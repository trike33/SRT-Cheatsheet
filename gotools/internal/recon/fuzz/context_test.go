package fuzz

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

func TestTitleWordsFiltersStopwordsAndShortTokens(t *testing.T) {
	got := titleWords("Welcome to the Acme Billing Portal - Home")
	want := []string{"acme", "billing", "portal"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestTitleWordsDedups(t *testing.T) {
	got := titleWords("Acme Acme ACME portal")
	if !slices.Equal(got, []string{"acme", "portal"}) {
		t.Errorf("got %v", got)
	}
}

func TestContextWordsTechBeforeTitleAndCapped(t *testing.T) {
	got := contextWords([]string{"WordPress"}, "Acme Billing Portal")
	if got[0] != "wp-admin" {
		t.Errorf("tech words must come first, got %v", got)
	}
	for _, w := range []string{"acme", "billing", "portal"} {
		if !slices.Contains(got, w) {
			t.Errorf("missing title word %q in %v", w, got)
		}
	}
}

func TestContextWordsCap(t *testing.T) {
	// A title with far more than maxContextWords unique tokens must still
	// cap the total (tech words + title words together).
	var sb strings.Builder
	for i := 0; i < maxContextWords+20; i++ {
		fmt.Fprintf(&sb, "word%d ", i)
	}
	got := contextWords([]string{"WordPress"}, sb.String())
	if len(got) != maxContextWords {
		t.Errorf("len = %d, want %d (capped)", len(got), maxContextWords)
	}
}

func TestContextWordsUnknownTechIsNoop(t *testing.T) {
	got := contextWords([]string{"nginx", "Cloudflare"}, "")
	if len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

func TestWordsForOffByDefault(t *testing.T) {
	e := &fuzzEngine{}
	if got := e.wordsFor("http://x/FUZZ"); got != nil {
		t.Errorf("got %v, want nil when -words-auto is off", got)
	}
}

// wordsTestServer serves a WordPress-flavored root page under a title, so
// probe's tech-detect and title extraction both have something real to find.
func wordsTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><head><title>Acme Billing Portal</title></head><body><link href="wp-content/style.css"></body></html>`)
		case "/wp-admin", "/wp-admin/":
			fmt.Fprint(w, strings.Repeat("admin login ", 50))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestFuzzWordsAutoEndToEnd(t *testing.T) {
	srv := wordsTestServer()
	defer srv.Close()
	dir := t.TempDir()
	wl, out := filepath.Join(dir, "w.txt"), filepath.Join(dir, "o.json")
	os.WriteFile(wl, []byte("robots\n"), 0o644) // the base wordlist alone would never find wp-admin

	if err := Run([]string{"-u", srv.URL + "/FUZZ", "-w", wl, "-mc", "200", "-words-auto", "-json", "-o", out, "-c", "1"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), "/wp-admin") {
		t.Errorf("expected -words-auto to find /wp-admin from the PHP/WordPress-style page, got:\n%s", b)
	}
}

func TestWordsForCachesPerOriginAndSharesProbeWithExtAuto(t *testing.T) {
	srv := wordsTestServer()
	defer srv.Close()
	e := &fuzzEngine{client: netx.NewClient(5e9, true), wordsAuto: true, extAuto: true}
	origin := srv.URL
	w1 := e.wordsFor(origin + "/FUZZ")
	w2 := e.wordsFor(origin + "/sub/FUZZ") // same origin -- cached, not re-probed
	if len(w1) == 0 || !slices.Equal(w1, w2) {
		t.Errorf("w1=%v w2=%v, want equal non-empty (per-origin cache)", w1, w2)
	}
	if len(e.sitec.done) != 1 {
		t.Errorf("siteProbe cache = %d entries, want 1 (shared with -ext-auto)", len(e.sitec.done))
	}
	// -ext-auto's own resolution must reuse the same cached probe, not send
	// a second one.
	e.extsFor(origin + "/FUZZ")
	if len(e.sitec.done) != 1 {
		t.Errorf("siteProbe cache = %d entries after extsFor, want still 1", len(e.sitec.done))
	}
}

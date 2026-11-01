package fuzz

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

// outputTestServer answers a few distinct statuses so -summary has more
// than one bucket to report and -mc's default lets through more than one
// of them.
func outputTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(403)
			fmt.Fprint(w, "forbidden")
		case "/login":
			fmt.Fprint(w, "login page")
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
}

func TestFuzzNdjsonStreamsIndependentlyOfDisplayMode(t *testing.T) {
	srv := outputTestServer()
	defer srv.Close()

	dir := t.TempDir()
	wl := filepath.Join(dir, "w.txt")
	ndjsonPath := filepath.Join(dir, "hits.ndjson")
	os.WriteFile(wl, []byte("admin\nlogin\nmissing\n"), 0o644)

	// Default (colored table) display mode, not -json -- ndjson must still
	// get written, proving it's independent of the console format.
	if err := Run([]string{"-u", srv.URL + "/FUZZ", "-w", wl, "-mc", "200,403", "-ndjson", ndjsonPath, "-c", "1"}); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(ndjsonPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 ndjson lines (admin=403, login=200), got %d:\n%s", len(lines), b)
	}
	for _, l := range lines {
		var r fuzzResult
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Errorf("line %q did not decode as JSON: %v", l, err)
		}
		if r.Status != 403 && r.Status != 200 {
			t.Errorf("unexpected status %d in ndjson line %q", r.Status, l)
		}
	}
}

func TestFuzzSummaryReportsEveryStatusIndependentOfMC(t *testing.T) {
	srv := outputTestServer()
	defer srv.Close()

	dir := t.TempDir()
	wl := filepath.Join(dir, "w.txt")
	os.WriteFile(wl, []byte("admin\nlogin\nmissing\n"), 0o644)

	stop := ioutil.CaptureWarnings()
	// -mc 200 alone would normally hide the 403 and 404 entirely; -summary
	// must still report them since it counts every response, not just shown
	// matches.
	err := Run([]string{"-u", srv.URL + "/FUZZ", "-w", wl, "-mc", "200", "-summary", "-silent", "-c", "1"})
	warnings := stop()
	if err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "status summary") {
		t.Fatalf("expected a status summary header in warnings:\n%s", joined)
	}
	for _, want := range []string{"200", "403", "404"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected status %s counted in the summary, warnings:\n%s", want, joined)
		}
	}
}

func TestFuzzNoSummaryByDefault(t *testing.T) {
	srv := outputTestServer()
	defer srv.Close()

	dir := t.TempDir()
	wl := filepath.Join(dir, "w.txt")
	os.WriteFile(wl, []byte("admin\nlogin\nmissing\n"), 0o644)

	stop := ioutil.CaptureWarnings()
	err := Run([]string{"-u", srv.URL + "/FUZZ", "-w", wl, "-mc", "200", "-silent", "-c", "1"})
	warnings := stop()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "status summary") {
			t.Errorf("did not expect a status summary without -summary, got: %s", w)
		}
	}
}

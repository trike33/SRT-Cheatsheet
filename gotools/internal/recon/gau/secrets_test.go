package gau

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

func TestScanBodyFindsKnownPatterns(t *testing.T) {
	cases := map[string]string{
		"AWS Access Key ID":       "config: AKIAABCDEFGHIJKLMNOP end",
		"Google API Key":          "key=AIzaSyA1234567890abcdefghijklmnopqrstuv",
		"Private Key":             "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----",
		"Generic API Key":         `api_key: "sk_abcdefghij1234567890ABCD"`,
		"Generic Secret/Password": `password = "SuperSecretPass123"`,
		"Basic Auth in URL":       "see https://admin:hunter2@internal.example.com/config for details",
	}
	for pattern, body := range cases {
		hits := scanBody("https://x.test/f", []byte(body))
		found := false
		for _, h := range hits {
			if h.Pattern == pattern {
				found = true
				if h.Match == "" {
					t.Errorf("%s: empty match", pattern)
				}
			}
		}
		if !found {
			t.Errorf("%s: no hit for body %q (got %v)", pattern, body, hits)
		}
	}
}

func TestScanBodyNoFalsePositiveOnPlainText(t *testing.T) {
	hits := scanBody("https://x.test/f", []byte("just an ordinary welcome page with nothing secret in it at all"))
	if len(hits) != 0 {
		t.Errorf("expected no hits on plain text, got %v", hits)
	}
}

func TestScanBodyOneHitPerPatternPerURL(t *testing.T) {
	body := []byte("AKIAABCDEFGHIJKLMNOP and also AKIAZZZZZZZZZZZZZZZZ")
	hits := scanBody("https://x.test/f", body)
	n := 0
	for _, h := range hits {
		if h.Pattern == "AWS Access Key ID" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected exactly one AWS key hit per URL, got %d", n)
	}
}

func TestScanContentEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/leak.env":
			fmt.Fprint(w, "AWS_KEY=AKIAABCDEFGHIJKLMNOP\nOTHER=fine")
		case "/clean.txt":
			fmt.Fprint(w, "nothing to see here")
		case "/missing":
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	urls := []string{srv.URL + "/leak.env", srv.URL + "/clean.txt", srv.URL + "/missing"}
	client := netx.NewClient(5*time.Second, true)
	hits, fetched, failed := scanContent(urls, client, 4, 1<<20)

	if fetched != 2 {
		t.Errorf("fetched = %d, want 2 (missing's 404 should not count)", fetched)
	}
	if failed != 1 {
		t.Errorf("failed = %d, want 1", failed)
	}
	if len(hits) != 1 || hits[0].Pattern != "AWS Access Key ID" || !strings.HasSuffix(hits[0].URL, "/leak.env") {
		t.Errorf("hits = %v, want exactly one AWS key hit on /leak.env", hits)
	}
}

func TestSnippetAroundNeverOutOfBounds(t *testing.T) {
	body := []byte("short")
	// A match spanning the whole tiny body must not panic or produce garbage.
	got := snippetAround(body, 0, len(body))
	if got != "short" {
		t.Errorf("got %q, want %q", got, "short")
	}
}

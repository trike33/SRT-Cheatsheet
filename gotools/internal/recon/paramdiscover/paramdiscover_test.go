package paramdiscover

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

func newD(t *testing.T) *Discoverer {
	return New(netx.NewClientOpts(5*time.Second, true, "", false), "GET", 5, 10)
}

// hiddenParamServer answers /search normally unless a "debug" query
// parameter is set, in which case the response changes -- a hidden
// parameter with no trace of it anywhere in the page or a URL.
func hiddenParamServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("debug"); v != "" {
			fmt.Fprintf(w, "<html>DEBUG MODE: %s</html>", v)
			return
		}
		fmt.Fprint(w, "<html>normal search page, nothing special here at all</html>")
	}))
}

func TestDiscoverFindsHiddenParamAcrossManyBatches(t *testing.T) {
	srv := hiddenParamServer()
	defer srv.Close()

	d := newD(t)
	// "debug" is deliberately placed in the middle of a large candidate
	// list so the real exercise is bisecting the one batch it falls in,
	// not just trying it directly.
	candidates := make([]string, 0, 300)
	for i := 0; i < 150; i++ {
		candidates = append(candidates, fmt.Sprintf("cand%d", i))
	}
	candidates = append(candidates, "debug")
	for i := 150; i < 300; i++ {
		candidates = append(candidates, fmt.Sprintf("cand%d", i))
	}

	r := d.Discover(srv.URL+"/search", candidates)
	if !slices.Contains(r.Found, "debug") {
		t.Fatalf("Found = %v, want it to include %q", r.Found, "debug")
	}
	if !slices.Contains(r.Reflected, "debug") {
		t.Errorf("Reflected = %v, want it to include %q (its value is echoed in the body)", r.Reflected, "debug")
	}
	// The whole point of batch+bisect: far fewer requests than one per
	// candidate (301 candidates would be 301+ requests tried naively).
	if r.Requests >= len(candidates) {
		t.Errorf("Requests = %d, want well under %d (batching should have saved most of them)", r.Requests, len(candidates))
	}
}

func TestDiscoverNoHiddenParamsFindsNothing(t *testing.T) {
	srv := hiddenParamServer()
	defer srv.Close()
	d := newD(t)

	r := d.Discover(srv.URL+"/search", []string{"wontmatch1", "wontmatch2", "wontmatch3"})
	if len(r.Found) != 0 {
		t.Errorf("Found = %v, want none", r.Found)
	}
}

func TestDiscoverSkipsCandidateAlreadyInURL(t *testing.T) {
	srv := hiddenParamServer()
	defer srv.Close()
	d := newD(t)

	// "debug" is already a real query param on the target URL -- it's
	// visible, not hidden, so params (the classify command) already
	// covers it; Discover must not re-report it as newly "found."
	r := d.Discover(srv.URL+"/search?debug=1", []string{"debug", "other"})
	if slices.Contains(r.Found, "debug") {
		t.Errorf("Found = %v, want \"debug\" excluded (already present in the URL)", r.Found)
	}
}

func TestDiscoverSkipsBinaryContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("\x89PNG\r\n\x1a\nnotarealpngbutwhocares"))
	}))
	defer srv.Close()
	d := newD(t)

	r := d.Discover(srv.URL+"/logo.png", []string{"a", "b", "c"})
	if r.Skipped == "" {
		t.Error("expected a binary content-type response to be skipped")
	}
	if r.Requests != 1 {
		t.Errorf("Requests = %d, want exactly 1 (baseline only, no batches sent)", r.Requests)
	}
}

func TestDiscoverReportsFetchError(t *testing.T) {
	d := newD(t)
	r := d.Discover("http://127.0.0.1:1/unreachable", []string{"a"})
	if r.Skipped == "" {
		t.Error("expected a fetch error to be reported as skipped")
	}
}

func TestChangedDetectsStatusAndSizeAndReflection(t *testing.T) {
	d := newD(t)
	base := probeResult{status: 200, size: 100, words: 20, body: []byte("hello")}

	if d.changed(base, probeResult{status: 200, size: 101, words: 20, body: []byte("hello")}) {
		t.Error("a 1-byte size delta within tolerance should not count as changed")
	}
	if !d.changed(base, probeResult{status: 404, size: 100, words: 20, body: []byte("hello")}) {
		t.Error("a different status should count as changed")
	}
	if !d.changed(base, probeResult{status: 200, size: 300, words: 20, body: []byte("hello")}) {
		t.Error("a large size delta should count as changed")
	}
	if !d.changed(base, probeResult{status: 200, size: 100, words: 20, body: []byte("has " + d.marker + " in it")}) {
		t.Error("the marker value appearing in the body should count as changed, regardless of size/status")
	}
}

func TestExistingParamsLowercases(t *testing.T) {
	got := existingParams("https://x.test/path?Foo=1&BAR=2")
	if !got["foo"] || !got["bar"] {
		t.Errorf("got %v, want foo and bar present (case-insensitive)", got)
	}
}

func TestBuildRequestGETAddsQueryParams(t *testing.T) {
	d := newD(t)
	req, err := d.buildRequest("https://x.test/path?existing=1", []string{"new1", "new2"})
	if err != nil {
		t.Fatal(err)
	}
	q := req.URL.Query()
	if q.Get("existing") != "1" {
		t.Error("existing query param should be preserved")
	}
	if q.Get("new1") != d.marker || q.Get("new2") != d.marker {
		t.Errorf("candidate params should be set to the marker value, got %v", q)
	}
}

func TestBuildRequestPOSTUsesFormBody(t *testing.T) {
	d := New(netx.NewClientOpts(5*time.Second, true, "", false), "POST", 5, 10)
	req, err := d.buildRequest("https://x.test/path", []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" {
		t.Errorf("method = %q, want POST", req.Method)
	}
	body := make([]byte, req.ContentLength)
	req.Body.Read(body)
	form, _ := url.ParseQuery(string(body))
	if form.Get("a") != d.marker || form.Get("b") != d.marker {
		t.Errorf("form body = %q, want a/b set to the marker", body)
	}
}

func TestIsSkippableContentType(t *testing.T) {
	cases := map[string]bool{
		"image/png":                 true,
		"image/jpeg; charset=utf-8": true,
		"application/pdf":           true,
		"text/html":                 false,
		"application/json":          false,
		"":                          false,
	}
	for ct, want := range cases {
		if got := isSkippableContentType(ct); got != want {
			t.Errorf("isSkippableContentType(%q) = %v, want %v", ct, got, want)
		}
	}
}

func TestLoadCandidatesFromFile(t *testing.T) {
	f := t.TempDir() + "/words.txt"
	if err := os.WriteFile(f, []byte("alpha\nbeta\nalpha\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadCandidates(stringSlice{f})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"alpha", "beta"}) {
		t.Errorf("got %v, want deduped [alpha beta]", got)
	}
}

func TestLoadCandidatesDefaultsToEmbedded(t *testing.T) {
	got, err := loadCandidates(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 1000 {
		t.Errorf("embedded default candidate list = %d entries, want at least 1000", len(got))
	}
}

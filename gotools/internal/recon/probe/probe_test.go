package probe

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeOneExtractsTitleStatusServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head>\n<title>  Example   Site  </title>\n</head><body>wp-content/plugins/x</body></html>"))
	}))
	defer srv.Close()

	r := One(srv.Client(), srv.URL)
	if r.Status != 200 {
		t.Errorf("Status = %d, want 200", r.Status)
	}
	if r.Title != "Example Site" {
		t.Errorf("Title = %q, want whitespace-collapsed %q", r.Title, "Example Site")
	}
	if r.Server != "nginx/1.18.0" {
		t.Errorf("Server = %q", r.Server)
	}
	if !containsStr(r.Tech, "nginx") || !containsStr(r.Tech, "WordPress") {
		t.Errorf("Tech = %v, want it to include nginx and WordPress", r.Tech)
	}
	if r.Length != len("<html><head>\n<title>  Example   Site  </title>\n</head><body>wp-content/plugins/x</body></html>") {
		t.Errorf("Length = %d, want the body length", r.Length)
	}
}

func TestProbeOneUnreachable(t *testing.T) {
	r := One(http.DefaultClient, "http://127.0.0.1:1") // port 1: nothing ever listens there
	if r.Err == "" {
		t.Error("expected an error probing an unreachable target")
	}
	if r.Status != 0 {
		t.Errorf("Status = %d, want 0 on error", r.Status)
	}
}

func TestProbeOneKeepsExplicitScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	r := One(srv.Client(), srv.URL) // srv.URL already has http://
	if r.URL != srv.URL {
		t.Errorf("URL = %q, want %q (explicit scheme kept as-is)", r.URL, srv.URL)
	}
	if r.Status != http.StatusTeapot {
		t.Errorf("Status = %d, want %d", r.Status, http.StatusTeapot)
	}
}

func TestTechSignatureDjangoLaravel(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "sessionid=abc")
	h.Add("Set-Cookie", "csrftoken=def")
	if !techSignatureMatch(t, "Django", h, "") {
		t.Error("expected Django signature to match a csrftoken cookie")
	}

	h2 := http.Header{}
	h2.Set("Set-Cookie", "laravel_session=xyz")
	if !techSignatureMatch(t, "Laravel", h2, "") {
		t.Error("expected Laravel signature to match a laravel_session cookie")
	}
}

// techSignatureMatch looks a signature up by name rather than slice index,
// so this test doesn't silently break if techSignatures gets reordered.
func techSignatureMatch(t *testing.T, name string, h http.Header, body string) bool {
	t.Helper()
	for _, sig := range signatures {
		if sig.name == name {
			return sig.match(h, body)
		}
	}
	t.Fatalf("no tech signature named %q", name)
	return false
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

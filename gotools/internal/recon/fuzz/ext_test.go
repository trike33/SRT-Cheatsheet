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

func TestHintedExtensions(t *testing.T) {
	got := hintedExtensions([]string{"nginx", "PHP", "WordPress", "Express"})
	want := []string{".php", ".phtml", ".inc", ".js", ".json"}
	if !slices.Equal(got, want) {
		t.Errorf("hinted = %v, want %v", got, want)
	}
	if len(hintedExtensions([]string{"nginx", "Cloudflare"})) != 0 {
		t.Error("servers with no extension mapping should hint nothing")
	}
}

func TestOriginOf(t *testing.T) {
	if got := originOf("https://a.example:8443/app/FUZZ"); got != "https://a.example:8443" {
		t.Errorf("origin = %q", got)
	}
}

// app serves index.php and login.html for real; every other path is a jittery
// soft-404 200.
func extTestServer(headers map[string]string) *httptest.Server {
	n := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		switch r.URL.Path {
		case "/index.php":
			fmt.Fprint(w, strings.Repeat("welcome home ", 200))
		case "/login.html":
			fmt.Fprint(w, strings.Repeat("please sign in ", 90))
		case "/":
			fmt.Fprint(w, "<html>root</html>")
		default:
			n++
			fmt.Fprint(w, strings.Repeat("nothing here ", 120), strings.Repeat("z", n%9))
		}
	}))
}

func TestDiscoverExtensionsAgainstSoft404(t *testing.T) {
	srv := extTestServer(nil)
	defer srv.Close()
	e := &fuzzEngine{client: netx.NewClient(5e9, true), retries: 0}
	probeFn := func(word string) (RespMeta, bool) {
		m, _, err := e.doRequest(srv.URL+"/"+word, word)
		return m, err == nil
	}
	got := discoverExtensions(genericExtensions, probeFn)
	if !slices.Equal(got, []string{".php", ".html"}) {
		t.Errorf("discovered = %v, want [.php .html] (no false extensions from the soft-404)", got)
	}
}

func TestFuzzExtAutoEndToEnd(t *testing.T) {
	srv := extTestServer(map[string]string{"X-Powered-By": "PHP/8.2"})
	defer srv.Close()
	// a backup that only exists with the hinted extension
	dir := t.TempDir()
	wl, out := filepath.Join(dir, "w.txt"), filepath.Join(dir, "o.json")
	os.WriteFile(wl, []byte("index\nlogin\nconfig\n"), 0o644)

	if err := Run([]string{"-u", srv.URL + "/FUZZ", "-w", wl, "-mc", "200", "-ac", "-ext-auto", "-json", "-o", out, "-c", "1"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	s := string(b)
	for _, want := range []string{"/index.php", "/login.html"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "config.") || strings.Count(s, "\n") != 2 {
		t.Errorf("unexpected extra findings:\n%s", s)
	}
}

func TestExtAutoOffByDefault(t *testing.T) {
	e := &fuzzEngine{exts: []string{".bak"}}
	if got := e.extsFor("http://x/FUZZ"); !slices.Equal(got, []string{".bak"}) {
		t.Errorf("got %v", got)
	}
}

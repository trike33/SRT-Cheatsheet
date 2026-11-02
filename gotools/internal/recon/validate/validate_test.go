package validate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

func newV(t *testing.T) *Validator {
	return New(netx.NewClientOpts(5*time.Second, true, "", false), 5, 3)
}

// softSite answers 200 with the same catch-all page for every unknown path
// (echoing the path, so its size wobbles), 302s unknown /old/* to /login,
// and 403s unknown /waf/* -- while serving genuinely different pages for the
// real ones.
func softSite() *httptest.Server {
	catchAll := "<html><body>" + strings.Repeat("Welcome to the site. Nothing here. ", 40) + "</body></html>"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/real.html":
			fmt.Fprint(w, "<html>"+strings.Repeat("Secret admin panel content with many different words. ", 12)+"</html>")
		case p == "/backup.zip":
			fmt.Fprint(w, strings.Repeat("PK\x03\x04binary", 300))
		case strings.HasPrefix(p, "/old/"):
			if p == "/old/real" {
				fmt.Fprint(w, "old real page with its own distinct content words here")
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
		case strings.HasPrefix(p, "/waf/"):
			if p == "/waf/ok" {
				fmt.Fprint(w, "allowed resource body with plenty of distinct words in it today")
				return
			}
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "blocked by the firewall, request id 1234")
		default:
			fmt.Fprint(w, catchAll+" you asked for "+p)
		}
	}))
}

func TestSoft404SiteRejectsCatchAllKeepsRealPages(t *testing.T) {
	srv := softSite()
	defer srv.Close()
	v := newV(t)
	cases := []struct {
		path  string
		valid bool
	}{
		{"/real.html", true},
		{"/backup.zip", true},
		{"/definitely-not-here", false}, // 200 catch-all
		{"/admin.php", false},           // 200 catch-all, other extension
		{"/some/deep/path/", false},     // directory catch-all
		{"/old/real", true},
		{"/old/missing", false}, // redirect to /login for anything
		{"/waf/ok", true},
		{"/waf/missing", false}, // 403 for anything
	}
	for _, c := range cases {
		got, _ := v.Check(srv.URL + c.path)
		if got.Valid != c.valid {
			t.Errorf("%s: valid=%v (%s), want %v", c.path, got.Valid, got.Reason, c.valid)
		}
	}
}

func TestPlain404IsRejectedByStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/here" {
			fmt.Fprint(w, "hello")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	v := newV(t)
	if got, _ := v.Check(srv.URL + "/here"); !got.Valid {
		t.Errorf("/here should be valid: %+v", got)
	}
	got, _ := v.Check(srv.URL + "/gone")
	if got.Valid || !strings.Contains(got.Reason, "404") {
		t.Errorf("/gone should be rejected by status, got %+v", got)
	}
}

func TestErrorsAndNonHTTPRejected(t *testing.T) {
	v := newV(t)
	for _, u := range []string{"ftp://x/y", "not a url", "http://127.0.0.1:1/x"} {
		if got, _ := v.Check(u); got.Valid || got.Reason == "" {
			t.Errorf("%q should be rejected with a reason, got %+v", u, got)
		}
	}
}

func TestLearnRejectsNearIdenticalGroups(t *testing.T) {
	var vs []Verdict
	for i := 0; i < 12; i++ {
		vs = append(vs, Verdict{URL: fmt.Sprintf("http://a.test/p%d", i), Status: 200, Length: 3300 + i, Words: 400, Valid: true})
	}
	vs = append(vs, Verdict{URL: "http://a.test/real", Status: 200, Length: 90000, Words: 9000, Valid: true})
	vs = Learn(vs, 10)
	for _, v := range vs[:12] {
		if v.Valid {
			t.Errorf("%s should have been learned as soft-404", v.URL)
		}
	}
	if !vs[12].Valid {
		t.Errorf("distinct page must survive: %+v", vs[12])
	}
	if got := Learn([]Verdict{{URL: "http://a.test/x", Status: 200, Valid: true}}, 0); !got[0].Valid {
		t.Error("learn=0 must be a no-op")
	}
}

func TestClassify(t *testing.T) {
	for _, c := range []struct{ in, dir, ext string }{
		{"/", "", "/"}, {"/a.php", "", ".php"}, {"/api/v1/x", "/api", ""},
		{"/api/x.JSON", "/api", ".json"}, {"/dir/", "", "/"}, {"/a/b/", "/a", "/"},
	} {
		if d, e := classify(c.in); d != c.dir || e != c.ext {
			t.Errorf("classify(%q) = %q,%q want %q,%q", c.in, d, e, c.dir, c.ext)
		}
	}
}

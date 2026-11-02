package robots

import (
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

func TestParseRobotsSitemapDirective(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User-agent: *\nDisallow: /admin\nAllow: /pub\nsitemap: https://x.test/s.xml\nSitemap:/rel.xml\n"))
	}))
	defer srv.Close()
	a, d, sm, err := parseRobots(netx.NewClient(5*time.Second, true), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, []string{"/pub"}) || !reflect.DeepEqual(d, []string{"/admin"}) {
		t.Errorf("allow/disallow = %v / %v", a, d)
	}
	if !reflect.DeepEqual(sm, []string{"https://x.test/s.xml", "/rel.xml"}) {
		t.Errorf("sitemaps = %v", sm)
	}
}

func TestFetchSitemapURLs(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<sitemapindex><sitemap><loc>` + srv.URL + `/a.xml</loc></sitemap>
<sitemap><loc>` + srv.URL + `/b.xml.gz</loc></sitemap></sitemapindex>`))
	})
	mux.HandleFunc("/a.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<urlset><url><loc>` + srv.URL + `/one</loc></url>
<url><loc>http://evil.test/offsite</loc></url><url><loc>` + srv.URL + `/one</loc></url></urlset>`))
	})
	mux.HandleFunc("/b.xml.gz", func(w http.ResponseWriter, r *http.Request) {
		gz := gzip.NewWriter(w)
		gz.Write([]byte(`<urlset><url><loc>` + srv.URL + `/two</loc></url><url><loc>` + srv.URL + `/three</loc></url></urlset>`))
		gz.Close()
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()
	c := netx.NewClient(5*time.Second, true)

	got := fetchSitemapURLs(c, srv.URL, nil, 100)
	want := []string{srv.URL + "/one", srv.URL + "/two", srv.URL + "/three"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (index followed, gzip read, offsite + duplicate dropped)", got, want)
	}
	if got := fetchSitemapURLs(c, srv.URL, nil, 2); len(got) != 2 {
		t.Errorf("max=2 returned %d URLs", len(got))
	}
	if got := fetchSitemapURLs(c, srv.URL, nil, 0); got != nil {
		t.Errorf("max=0 should list none, got %v", got)
	}
	if got := fetchSitemapURLs(c, srv.URL, []string{"/missing.xml"}, 10); len(got) != 0 {
		t.Errorf("a 404 sitemap should yield nothing, got %v", got)
	}
}

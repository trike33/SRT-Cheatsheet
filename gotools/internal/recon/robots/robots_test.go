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
	want := []string{srv.URL + "/sitemap.xml", srv.URL + "/a.xml", srv.URL + "/one", srv.URL + "/b.xml.gz", srv.URL + "/two", srv.URL + "/three"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (sitemap files listed, index followed, gzip read, offsite + duplicate dropped)", got, want)
	}
	// max caps page URLs only; the sitemap files found are still reported.
	if got := fetchSitemapURLs(c, srv.URL, nil, 1); len(got) != 4 { // sitemap.xml, a.xml, one, b.xml.gz
		t.Errorf("max=1 returned %v", got)
	}
	if got := fetchSitemapURLs(c, srv.URL, nil, 0); got != nil {
		t.Errorf("max=0 should list none, got %v", got)
	}
	// A declared-but-missing sitemap doesn't stop the conventional
	// /sitemap.xml from being tried.
	if got := fetchSitemapURLs(c, srv.URL, []string{"/missing.xml"}, 10); len(got) != 6 {
		t.Errorf("declared 404 + default /sitemap.xml: got %v", got)
	}
}

func TestFetchSitemapNestedIndexes(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<sitemapindex><sitemap><loc>` + srv.URL + `/sitemap-main.xml</loc></sitemap></sitemapindex>`))
	})
	mux.HandleFunc("/sitemap-main.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<sitemapindex><sitemap><loc>` + srv.URL + `/sitemap-products.xml</loc></sitemap>
<sitemap><loc>` + srv.URL + `/sitemap-social.xml</loc></sitemap></sitemapindex>`))
	})
	mux.HandleFunc("/sitemap-products.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<urlset><url><loc>` + srv.URL + `/p1</loc></url></urlset>`))
	})
	mux.HandleFunc("/sitemap-social.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<urlset><url><loc>` + srv.URL + `/s1</loc></url></urlset>`))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()
	got := fetchSitemapURLs(netx.NewClient(5*time.Second, true), srv.URL, nil, 100)
	for _, w := range []string{"/sitemap.xml", "/sitemap-main.xml", "/sitemap-products.xml", "/sitemap-social.xml", "/p1", "/s1"} {
		found := false
		for _, g := range got {
			found = found || g == srv.URL+w
		}
		if !found {
			t.Errorf("missing %s in %v", w, got)
		}
	}
}

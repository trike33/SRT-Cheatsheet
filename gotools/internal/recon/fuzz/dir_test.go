package fuzz

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

// dirServer serves /admin with no redirect (just a 200, like an app that
// lists a directory inline), /file.txt as a flat file-shaped 200, and
// everything else a soft-404-ish 200 of its own.
func dirServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/admin/":
			fmt.Fprint(w, "<html>admin index</html>")
		case "/file.txt":
			fmt.Fprint(w, "just a file")
		default:
			fmt.Fprint(w, "nope")
		}
	}))
}

func TestLooksLikeDirClassicRedirect(t *testing.T) {
	if !dirRedirect("https://host/admin", "https://host/admin/") {
		t.Error("expected the classic redirect-to-trailing-slash case to be recognized")
	}
}

func TestLooksLikeDirNoRedirectButConfirmedOnSlash(t *testing.T) {
	srv := dirServer()
	defer srv.Close()

	e := &fuzzEngine{client: netx.NewClient(5*time.Second, true), matcher: mustMatcher(t, "200")}
	ok := e.looksLikeDir(srv.URL+"/admin", "", RespMeta{Status: 200}, "admin", srv.URL+"/FUZZ")
	if !ok {
		t.Error("an extensionless 200 whose +\"/\" form also resolves should be treated as a directory")
	}
}

func TestLooksLikeDirFileShapedWordNeverConfirmed(t *testing.T) {
	srv := dirServer()
	defer srv.Close()

	e := &fuzzEngine{client: netx.NewClient(5*time.Second, true), matcher: mustMatcher(t, "200")}
	ok := e.looksLikeDir(srv.URL+"/file.txt", "", RespMeta{Status: 200}, "file.txt", srv.URL+"/FUZZ")
	if ok {
		t.Error("a path with an extension should never be probed/treated as a directory")
	}
}

func TestLooksLikeDirNonSuccessStatusSkipsProbe(t *testing.T) {
	e := &fuzzEngine{client: netx.NewClient(5*time.Second, true), matcher: mustMatcher(t, "200")}
	if e.looksLikeDir("http://127.0.0.1:1/missing", "", RespMeta{Status: 403}, "missing", "http://127.0.0.1:1/FUZZ") {
		t.Error("a non-2xx response with no redirect must not be treated as a directory")
	}
}

package dork

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

func TestSearchParsesItems(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "k" || r.URL.Query().Get("cx") != "c" || r.URL.Query().Get("q") != "site:a.test admin" {
			t.Errorf("unexpected query params: %s", r.URL.RawQuery)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]string{
				{"title": "Admin Login", "link": "https://a.test/admin", "snippet": "sign in"},
				{"title": "No link", "snippet": "dropped, no link field"}, // link omitted -> must be dropped
			},
		})
	}))
	defer srv.Close()
	searchEndpoint = srv.URL
	defer func() { searchEndpoint = "https://www.googleapis.com/customsearch/v1" }()

	hits, err := search(netx.NewClient(5*time.Second, true), "k", "c", "site:a.test admin", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].URL != "https://a.test/admin" || hits[0].Title != "Admin Login" || hits[0].Snippet != "sign in" {
		t.Errorf("hits = %+v", hits)
	}
}

func TestSearchNoItemsIsEmptyNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"searchInformation": map[string]any{"totalResults": "0"}})
	}))
	defer srv.Close()
	searchEndpoint = srv.URL
	defer func() { searchEndpoint = "https://www.googleapis.com/customsearch/v1" }()

	hits, err := search(netx.NewClient(5*time.Second, true), "k", "c", "q", 10)
	if err != nil || len(hits) != 0 {
		t.Errorf("hits=%v err=%v, want (nil, nil)", hits, err)
	}
}

func TestSearchErrorResponseReturnsMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// This is the real response shape verified live against the actual
		// Google Custom Search API with a dummy key (see dork.go's doc
		// comment) -- not a guess.
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code": 400, "message": "API key not valid. Please pass a valid API key.", "status": "INVALID_ARGUMENT",
			},
		})
	}))
	defer srv.Close()
	searchEndpoint = srv.URL
	defer func() { searchEndpoint = "https://www.googleapis.com/customsearch/v1" }()

	_, err := search(netx.NewClient(5*time.Second, true), "bad", "c", "q", 10)
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := err.Error(); got != `google custom search API: API key not valid. Please pass a valid API key. (INVALID_ARGUMENT)` {
		t.Errorf("err = %q", got)
	}
}

func TestSearchNumClampedTo10(t *testing.T) {
	var gotNum string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotNum = r.URL.Query().Get("num")
		json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer srv.Close()
	searchEndpoint = srv.URL
	defer func() { searchEndpoint = "https://www.googleapis.com/customsearch/v1" }()

	search(netx.NewClient(5*time.Second, true), "k", "c", "q", 50)
	if gotNum != "10" {
		t.Errorf("num = %q, want clamped to 10", gotNum)
	}
	search(netx.NewClient(5*time.Second, true), "k", "c", "q", 0)
	if gotNum != "10" {
		t.Errorf("num = %q, want defaulted to 10 for <= 0", gotNum)
	}
}

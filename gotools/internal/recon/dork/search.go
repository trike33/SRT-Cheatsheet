package dork

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

// searchEndpoint is the Google Custom Search JSON API. Verified reachable
// (unlike google.com itself) and its error-response shape verified live
// against a real request with a dummy key -- see dork.go's doc comment and
// ROADMAP.md for what wasn't verifiable in this environment (an
// authenticated success response: no API key/engine was available to test
// one, so that parsing follows the API's long-stable documented schema
// instead of a live-checked example).
var searchEndpoint = "https://www.googleapis.com/customsearch/v1" // var (not const) so tests can point it at a fake server

// apiError mirrors the Custom Search API's JSON error envelope, e.g.
// {"error":{"code":400,"message":"API key not valid...","status":"INVALID_ARGUMENT"}}.
type apiError struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

// apiResponse is the Custom Search API's success envelope -- only the
// fields this package uses.
type apiResponse struct {
	Items []struct {
		Title   string `json:"title"`
		Link    string `json:"link"`
		Snippet string `json:"snippet"`
	} `json:"items"`
}

// Hit is one search result.
type Hit struct {
	Category string `json:"category"`
	Query    string `json:"query"`
	Title    string `json:"title"`
	URL      string `json:"url"`
	Snippet  string `json:"snippet,omitempty"`
}

// search runs one query against the Google Custom Search JSON API,
// returning up to num results (API max 10 per request -- this package
// never paginates beyond that, to keep one dork run well inside the free
// tier's 100 queries/day rather than silently spending it on one category).
// Hits come back with no Category/Query set; the caller fills those in.
func search(client *http.Client, apiKey, cx, query string, num int) ([]Hit, error) {
	if num <= 0 || num > 10 {
		num = 10
	}
	q := url.Values{}
	q.Set("key", apiKey)
	q.Set("cx", cx)
	q.Set("q", query)
	q.Set("num", fmt.Sprint(num))
	endpoint := searchEndpoint + "?" + q.Encode()

	resp, err := netx.Get(client, endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var ae apiError
		if json.Unmarshal(body, &ae) == nil && ae.Error.Message != "" {
			return nil, fmt.Errorf("google custom search API: %s (%s)", ae.Error.Message, ae.Error.Status)
		}
		return nil, fmt.Errorf("google custom search API: HTTP %d", resp.StatusCode)
	}

	var ar apiResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return nil, fmt.Errorf("google custom search API: parsing response: %w", err)
	}
	hits := make([]Hit, 0, len(ar.Items))
	for _, it := range ar.Items {
		if it.Link == "" {
			continue
		}
		hits = append(hits, Hit{Title: it.Title, URL: it.Link, Snippet: it.Snippet})
	}
	return hits, nil
}

package gau

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/payloads"
)

// ContentHit is one secret/credential pattern found inside a fetched body --
// `sensitive -content`'s answer to the "not just by extension" half of the
// methodology gap: filterSensitive only ever looks at the URL's path, this
// looks at what the server actually returned.
type ContentHit struct {
	URL     string `json:"url"`
	Pattern string `json:"pattern"`
	Match   string `json:"match"`
	Context string `json:"context,omitempty"`
}

// scanContent fetches every url (bounded by conc concurrent requests,
// capped at maxBytes each) and scans the body against payloads.SecretPatterns,
// returning every hit found plus how many URLs were actually fetched and how
// many failed. A fetch error or non-2xx response is skipped, not fatal --
// a dead link from an old Wayback crawl is routine, not a reason to abort
// the whole scan.
func scanContent(urls []string, client *http.Client, conc int, maxBytes int64) (hits []ContentHit, fetched, failed int) {
	if conc < 1 {
		conc = 1
	}
	var mu sync.Mutex
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for _, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			body, err := fetchBody(client, u, maxBytes)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				return
			}
			fetched++
			hits = append(hits, scanBody(u, body)...)
		}(u)
	}
	wg.Wait()

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].URL != hits[j].URL {
			return hits[i].URL < hits[j].URL
		}
		return hits[i].Pattern < hits[j].Pattern
	})
	return hits, fetched, failed
}

// fetchBody GETs url and returns up to maxBytes of its body; a non-2xx
// response is treated as a fetch failure (nothing to scan).
func fetchBody(client *http.Client, u string, maxBytes int64) ([]byte, error) {
	resp, err := netx.Get(client, u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

// scanBody returns one hit per secret pattern that matches body (first match
// only per pattern per URL, so one leaked key doesn't flood the output).
func scanBody(u string, body []byte) []ContentHit {
	var hits []ContentHit
	for _, p := range payloads.SecretPatterns {
		loc := p.Re.FindIndex(body)
		if loc == nil {
			continue
		}
		hits = append(hits, ContentHit{
			URL:     u,
			Pattern: p.Name,
			Match:   string(body[loc[0]:loc[1]]),
			Context: snippetAround(body, loc[0], loc[1]),
		})
	}
	return hits
}

// snippetAround returns a flattened, single-line window of body around
// [start,end), for a quick "is this a real hit" glance without downloading
// the whole file.
func snippetAround(body []byte, start, end int) string {
	s := start - 30
	if s < 0 {
		s = 0
	}
	e := end + 30
	if e > len(body) {
		e = len(body)
	}
	return strings.TrimSpace(strings.ReplaceAll(string(body[s:e]), "\n", " "))
}

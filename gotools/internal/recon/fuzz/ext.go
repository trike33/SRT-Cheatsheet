package fuzz

import (
	"net/url"
	"strings"
	"sync"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/probe"
)

// Automatic extension discovery for `fuzz -ext-auto`.
//
// Instead of guessing `-e .php -e .bak` by hand, the fuzzer works out which
// extensions this particular app serves, in two steps that feed each other:
//
//  1. Tech hints: the target's root page is fingerprinted with probe's
//     tech-detect (PHP -> .php, ASP.NET -> .aspx/.ashx/.asmx, Express ->
//     .js/.json, ...). Hinted extensions are trusted and added directly.
//  2. Discovery: every other candidate extension (.html .txt .bak .zip ...)
//     is verified against the live server -- common stems (index, default,
//     login) are requested with the extension, and the extension is kept only
//     if the response differs from what a random, non-existent name with the
//     same extension returns. That baseline reuses the soft-404 band logic,
//     so apps that answer every miss with a jittery 200 don't make every
//     extension look "valid".
//
// Extensions are per-host (resolved once per origin, shared across
// recursion), so a multi-host run gives each host its own list.

// techExtensions maps a detected technology to the extensions it serves.
var techExtensions = map[string][]string{
	"PHP":       {".php", ".phtml", ".inc"},
	"WordPress": {".php"},
	"Drupal":    {".php", ".inc"},
	"Joomla":    {".php"},
	"Laravel":   {".php"},
	"ASP.NET":   {".aspx", ".ashx", ".asmx", ".asp"},
	"IIS":       {".aspx", ".asp"},
	"Express":   {".js", ".json"},
	"Django":    {".json"},
}

// genericExtensions are verified against the server before use.
var genericExtensions = []string{
	".php", ".asp", ".aspx", ".jsp", ".html", ".htm", ".js", ".json", ".txt", ".xml", ".bak", ".old", ".zip",
}

// discoveryStems are filenames likely to exist on a live app, tried with each
// candidate extension.
var discoveryStems = []string{"index", "default", "login"}

// hintedExtensions returns the trusted extensions for the detected techs,
// de-duplicated, in detection order.
func hintedExtensions(techs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range techs {
		for _, x := range techExtensions[t] {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	return out
}

// extLive reports whether a response to stem+ext looks like a real hit rather
// than the server's miss behaviour.
func extLive(meta RespMeta, word string, baseline *calibData) bool {
	switch {
	case meta.Status >= 200 && meta.Status < 400, meta.Status == 401, meta.Status == 403, meta.Status == 405:
	default:
		return false
	}
	return !baseline.matches(meta, word)
}

// discoverExtensions verifies candidates against the server. probe sends a
// request for word under the directory being fuzzed.
func discoverExtensions(candidates []string, probeFn func(word string) (RespMeta, bool)) []string {
	var found []string
	for _, ext := range candidates {
		baseline := newCalibData(1.0, 0)
		for i := 0; i < 2; i++ {
			w := randToken(10+i*6) + ext
			if m, ok := probeFn(w); ok {
				baseline.addCalibrated(m, w)
			}
		}
		for _, stem := range discoveryStems {
			w := stem + ext
			if m, ok := probeFn(w); ok && extLive(m, w, baseline) {
				found = append(found, ext)
				break
			}
		}
	}
	return found
}

func originOf(base string) string {
	u, err := url.Parse(strings.ReplaceAll(base, fuzzKeyword, ""))
	if err != nil || u.Host == "" {
		return base
	}
	return u.Scheme + "://" + u.Host
}

type extCache struct {
	mu   sync.Mutex
	done map[string][]string // origin -> extensions (user -e first)
}

// extsFor returns the extensions to try under base: the user's -e list, plus
// -ext-auto's hinted and discovered ones (resolved once per origin).
func (e *fuzzEngine) extsFor(base string) []string {
	if !e.extAuto {
		return e.exts
	}
	origin := originOf(base)
	e.extc.mu.Lock()
	defer e.extc.mu.Unlock()
	if x, ok := e.extc.done[origin]; ok {
		return x
	}
	if e.extc.done == nil {
		e.extc.done = map[string][]string{}
	}
	x := e.resolveExts(base, origin)
	e.extc.done[origin] = x
	return x
}

func (e *fuzzEngine) resolveExts(base, origin string) []string {
	out := append([]string{}, e.exts...)
	seen := map[string]bool{}
	for _, x := range out {
		seen[x] = true
	}
	add := func(xs []string) []string {
		var added []string
		for _, x := range xs {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
				added = append(added, x)
			}
		}
		return added
	}

	pr := probe.One(e.client, origin+"/")
	hinted := add(hintedExtensions(pr.Tech))

	var cands []string
	for _, x := range genericExtensions {
		if !seen[x] {
			cands = append(cands, x)
		}
	}
	probeFn := func(word string) (RespMeta, bool) {
		target := strings.ReplaceAll(base, fuzzKeyword, word)
		if e.scope != nil && !e.scope.InScope(target) {
			return RespMeta{}, false
		}
		m, _, err := e.doRequest(target, word)
		return m, err == nil
	}
	discovered := add(discoverExtensions(cands, probeFn))

	ioutil.Warn("ext-auto %s: tech=%v hinted=%v discovered=%v", origin, pr.Tech, hinted, discovered)
	return out
}

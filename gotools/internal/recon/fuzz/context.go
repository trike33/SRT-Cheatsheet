package fuzz

import (
	"regexp"
	"strings"
	"sync"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

// Context-derived wordlist words for `fuzz -words-auto` (gap 7). Besides
// -ext-auto's extension guesses, the detected tech stack and the page
// title often name real paths a generic wordlist has no way to know about
// ("wp-admin" for a WordPress site, a product name from the title that
// turns out to be a directory too). Same philosophy as -ext-auto's
// hintedExtensions: a small, curated, trusted set of additions, not a
// generative word-guessing engine -- bounded by maxContextWords so a
// chatty title can't balloon a run.

// techWords maps a detected technology to directory/file names its apps
// commonly expose, beyond what the base wordlist already tries.
var techWords = map[string][]string{
	"WordPress": {"wp-admin", "wp-content", "wp-includes", "wp-login", "wp-json", "xmlrpc", "wp-config", "wp-cron"},
	"Drupal":    {"sites", "modules", "themes", "core", "node", "user"},
	"Joomla":    {"administrator", "components", "modules", "templates", "plugins"},
	"Laravel":   {"storage", "vendor", "artisan", "bootstrap", "resources"},
	"Django":    {"admin", "static", "media", "api"},
	"Express":   {"api", "node_modules", "public"},
	"ASP.NET":   {"bin", "app_data", "scripts"},
	"IIS":       {"iisstart"},
	"PHP":       {"config", "includes", "inc", "admin"},
}

// maxContextWords caps how many extra words -words-auto adds in total
// (tech + title), per host.
const maxContextWords = 40

// titleStopwords are generic English words a page title accumulates that
// are never real paths, dropped before the rest become candidates.
var titleStopwords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "this": true, "that": true,
	"from": true, "your": true, "you": true, "are": true, "was": true, "were": true,
	"has": true, "have": true, "will": true, "into": true, "home": true, "page": true,
	"welcome": true, "official": true, "site": true, "website": true, "online": true,
	"all": true, "new": true, "our": true, "about": true,
}

var titleWordRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9_-]{2,}`)

// titleWords extracts plausible path-like words from a page title:
// lowercase alphanumeric-ish tokens of at least 3 characters, stopwords
// dropped, deduplicated, in first-seen order.
func titleWords(title string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range titleWordRe.FindAllString(title, -1) {
		w := strings.ToLower(m)
		if titleStopwords[w] || seen[w] {
			continue
		}
		seen[w] = true
		out = append(out, w)
	}
	return out
}

// contextWords combines techWords[techs] and titleWords(title), tech words
// first (curated, higher confidence), deduplicated and capped at
// maxContextWords.
func contextWords(techs []string, title string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(ws []string) {
		for _, w := range ws {
			if len(out) >= maxContextWords {
				return
			}
			if seen[w] {
				continue
			}
			seen[w] = true
			out = append(out, w)
		}
	}
	for _, t := range techs {
		add(techWords[t])
	}
	add(titleWords(title))
	return out
}

// wordsCache memoizes -words-auto's extra words per origin, the same shape
// as extCache.
type wordsCache struct {
	mu   sync.Mutex
	done map[string][]string
}

// wordsFor returns -words-auto's extra words for base's origin (nil if
// -words-auto is off), resolved once per origin and reusing -ext-auto's
// probe request via siteProbe when both are on.
func (e *fuzzEngine) wordsFor(base string) []string {
	if !e.wordsAuto {
		return nil
	}
	origin := originOf(base)
	e.wordc.mu.Lock()
	defer e.wordc.mu.Unlock()
	if x, ok := e.wordc.done[origin]; ok {
		return x
	}
	if e.wordc.done == nil {
		e.wordc.done = map[string][]string{}
	}
	pr := e.siteProbe(origin)
	x := contextWords(pr.Tech, pr.Title)
	ioutil.Warn("words-auto %s: tech=%v title=%q -> %d extra word(s): %v", origin, pr.Tech, pr.Title, len(x), x)
	e.wordc.done[origin] = x
	return x
}

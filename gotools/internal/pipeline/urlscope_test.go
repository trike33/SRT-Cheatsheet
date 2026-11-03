package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

const urlScopeBurp = `{"target":{"scope":{"include":[
{"enabled":true,"protocol":"any","host":"^nytco\\.com$","file":"^/.*$"},
{"enabled":true,"protocol":"any","host":"^.+\\.wild\\.org$","file":"^/.*$"},
{"enabled":true,"protocol":"any","host":"^wild\\.org$","file":"^/.*$"}
],"exclude":[{"enabled":true,"protocol":"any","host":"^wild\\.org$","file":"^/private/.*$"}]}}}`

func TestURLInScopeFilter(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scope.json")
	os.WriteFile(p, []byte(urlScopeBurp), 0o600)
	cfg := &pipelineConfig{
		Web: []targetEntry{
			{Target: "nytco.com", Scope: p, NoSubdomains: true}, // exact host only
			{Target: "wild.org", Scope: p},                      // subdomains allowed
		},
		Options: pipelineOptions{Scope: p},
	}
	in := urlInScopeFilter(cfg)
	for u, want := range map[string]bool{
		"https://nytco.com/a":             true,
		"https://stg.newsdev.nyt.net/x":   false, // unrelated domain from a shared cert / archive
		"https://blogs.nytco.com/post":    false, // subdomain of an exact-host rule
		"https://a.wild.org/x":            true,
		"https://wild.org/private/secret": false, // excluded path
		"https://wild.org/public":         true,
		"not a url":                       false,
	} {
		if got := in(u); got != want {
			t.Errorf("in(%q) = %v, want %v", u, got, want)
		}
	}
	// no scope information at all: admit everything with a host (old behavior)
	open := urlInScopeFilter(&pipelineConfig{Web: []targetEntry{{Target: "a.test"}}})
	if !open("https://anything.else/x") {
		t.Error("with no scope configured nothing should be filtered")
	}
}

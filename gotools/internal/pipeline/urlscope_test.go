package pipeline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/trike33/srt-cheatsheet/gotools/internal/scope"
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

// wildcardExcludeBurp includes *.example.com wholesale but carves one exact
// subdomain back out -- the shape runWebStage's discovery-time filtering
// (burpScopeAllows, via addDiscovered) exists for: admin.example.com must
// never reach probe/gau/fuzz even though the wildcard rule that admitted
// www/blog/etc. would otherwise cover it too.
const wildcardExcludeBurp = `{"target":{"scope":{"include":[
{"enabled":true,"protocol":"any","host":"^.+\\.example\\.com$","file":"^/.*$"},
{"enabled":true,"protocol":"any","host":"^example\\.com$","file":"^/.*$"}
],"exclude":[{"enabled":true,"protocol":"any","host":"^admin\\.example\\.com$","file":"^/.*$"}]}}}`

func TestBurpScopeAllowsDropsExcludedSubdomain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scope.json")
	os.WriteFile(p, []byte(wildcardExcludeBurp), 0o600)
	m, err := scope.LoadScopeMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"www.example.com":   true,
		"blog.example.com":  true,
		"admin.example.com": false, // carved out by the exclude rule
		"example.com":       true,
	} {
		if got := burpScopeAllows(m, name); got != want {
			t.Errorf("burpScopeAllows(%q) = %v, want %v", name, got, want)
		}
	}
	if !burpScopeAllows(nil, "anything.at.all") {
		t.Error("a nil matcher (no scope configured) should admit everything")
	}
}

package main

import (
	"os"
	"path/filepath"
	"testing"
)

const loanDepotScope = `{"target":{"scope":{"include":[
{"enabled":true,"protocol":"any","host":"^apply\\.myloandepot\\.com$","file":"^/.*$"},
{"enabled":true,"protocol":"any","host":"^.+\\.servicing\\.loandepot\\.com$","file":"^/.*$"},
{"enabled":true,"protocol":"any","host":"^www\\.loandepot\\.com$","file":"^/.*$"}
],"exclude":[
{"enabled":true,"protocol":"https","host":"^www\\.loandepot\\.com$","file":"^/branches/.*$"},
{"enabled":true,"protocol":"any","host":"^.+\\.secureconduit\\.net$","file":"^/.*$"}
]}}}`

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScopeMatcher(t *testing.T) {
	m, err := loadScopeMatcher(writeTemp(t, loanDepotScope))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		url  string
		want bool
	}{
		{"https://apply.myloandepot.com/anything", true},
		{"http://apply.myloandepot.com/", true},
		{"https://api.servicing.loandepot.com/x", true}, // wildcard include
		{"https://www.loandepot.com/about", true},
		{"https://www.loandepot.com/branches/ca", false}, // https exclude
		{"http://www.loandepot.com/branches/ca", true},   // exclude is https-only
		{"https://foo.secureconduit.net/x", false},       // excluded
		{"https://evil.com/", false},                     // not included
		{"https://loandepot.com/", false},                // apex not in include
	}
	for _, c := range cases {
		if got := m.inScope(c.url); got != c.want {
			t.Errorf("inScope(%q)=%v want %v", c.url, got, c.want)
		}
	}
}

func TestIncludeHosts(t *testing.T) {
	m, err := loadScopeMatcher(writeTemp(t, loanDepotScope))
	if err != nil {
		t.Fatal(err)
	}
	hosts := m.includeHosts()
	// wildcard "*.servicing..." must be dropped; concrete hosts kept.
	want := map[string]bool{"apply.myloandepot.com": true, "www.loandepot.com": true}
	for _, h := range hosts {
		if !want[h] {
			t.Errorf("unexpected seed host %q", h)
		}
		delete(want, h)
	}
	if len(want) != 0 {
		t.Errorf("missing seed hosts: %v", want)
	}
}

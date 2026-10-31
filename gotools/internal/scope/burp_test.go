package scope

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleBurpScope = `{"target":{"scope":{"include":[
{"enabled":true,"protocol":"any","host":"^apply\\.example\\.com$","file":"^/.*$"},
{"enabled":true,"protocol":"any","host":"^.+\\.api\\.example\\.com$","file":"^/v1/.*$"},
{"enabled":false,"protocol":"any","host":"^disabled\\.example\\.com$","file":""}
],"exclude":[]}}}`

func writeBurpScope(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(p, []byte(sampleBurpScope), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBurpHosts(t *testing.T) {
	bs, err := LoadBurpScope(writeBurpScope(t))
	if err != nil {
		t.Fatal(err)
	}
	got := BurpHosts(bs)
	want := map[string]bool{"apply.example.com": true, "api.example.com/v1": true}
	for _, h := range got {
		if !want[h] {
			t.Errorf("unexpected host %q (disabled rules must be excluded)", h)
		}
		delete(want, h)
	}
	if len(want) != 0 {
		t.Errorf("missing hosts: %v (got %v)", want, got)
	}
}

func TestLoadBurpScopeBadPath(t *testing.T) {
	if _, err := LoadBurpScope(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("a missing file should error")
	}
}

package wordlists

import (
	"os"
	"strings"
	"testing"
)

func TestEmbeddedLists(t *testing.T) {
	dir := t.TempDir()
	for name, fn := range map[string]func(string) (string, error){"subdomains": SubdomainsFile, "directories": DirectoriesFile, "paramNames": ParamNamesFile} {
		p, err := fn(dir)
		if err != nil {
			t.Fatal(name, err)
		}
		b, _ := os.ReadFile(p)
		if n := len(strings.Split(strings.TrimSpace(string(b)), "\n")); n < 4000 {
			t.Errorf("%s: only %d lines", name, n)
		}
	}
	if SubdomainsCount() < 19000 {
		t.Errorf("SubdomainsCount = %d", SubdomainsCount())
	}
}

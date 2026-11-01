package pipeline

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestWriteHostScopeFileEmptyWhenNoHostTargets(t *testing.T) {
	path, err := writeHostScopeFile(&pipelineConfig{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Errorf("path = %q, want empty (no host IP scope to cross-link against)", path)
	}
}

func TestWriteHostScopeFileIncludesExcludedHosts(t *testing.T) {
	dir := t.TempDir()
	cfg := &pipelineConfig{Host: []targetEntry{
		{Target: "10.0.0.0/24"},
		{Target: "10.0.1.5", Excluded: true}, // excluded-but-tracked is still in scope
	}}
	path, err := writeHostScopeFile(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	if path == "" {
		t.Fatal("expected a non-empty path")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{"10.0.0.0/24", "10.0.1.5"} {
		if !containsLine(got, want) {
			t.Errorf("host scope file missing %q, got:\n%s", want, got)
		}
	}
}

func containsLine(blob, line string) bool {
	for _, l := range splitLines(blob) {
		if l == line {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestFilterDomainsInScopeNoopWithoutScopeFile(t *testing.T) {
	names := []string{"a.example.com", "b.example.com"}
	got, steps := filterDomainsInScope(names, "", t.TempDir(), "domains", nil)
	if !slices.Equal(got, names) {
		t.Errorf("got %v, want unchanged %v", got, names)
	}
	if len(steps) != 0 {
		t.Errorf("expected no steps appended when there's no host scope, got %v", steps)
	}
}

func TestFilterDomainsInScopeNoopOnEmptyNames(t *testing.T) {
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope.txt")
	os.WriteFile(scopeFile, []byte("10.0.0.0/24\n"), 0o644)

	got, steps := filterDomainsInScope(nil, scopeFile, dir, "domains", nil)
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
	if len(steps) != 0 {
		t.Errorf("expected no steps for an empty input list, got %v", steps)
	}
}

// Literal IPs resolve through net.Resolver.LookupHost without any real DNS
// lookup (Go recognizes a literal address and short-circuits), so this stays
// fully offline while still exercising the real domains.RunScopeCheck path.
func TestFilterDomainsInScopeKeepsOnlyInScopeIPs(t *testing.T) {
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopeFile, []byte("10.0.0.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	names := []string{"10.0.0.5", "8.8.8.8"}
	kept, steps := filterDomainsInScope(names, scopeFile, dir, "domains", nil)

	if !slices.Equal(kept, []string{"10.0.0.5"}) {
		t.Errorf("kept = %v, want [10.0.0.5]", kept)
	}
	if len(steps) != 1 || steps[0].Name != "scopecheck" || steps[0].Status != "ok" {
		t.Errorf("steps = %+v, want one ok scopecheck step", steps)
	}
}

func TestFilterDomainsInScopeFailsOpenOnBrokenScopeFile(t *testing.T) {
	dir := t.TempDir()
	names := []string{"10.0.0.5", "8.8.8.8"}

	kept, steps := filterDomainsInScope(names, filepath.Join(dir, "does-not-exist.txt"), dir, "domains", nil)

	if !slices.Equal(kept, names) {
		t.Errorf("a broken scopecheck must fail open (keep everything), got %v", kept)
	}
	if len(steps) != 1 || steps[0].Status != "error" {
		t.Errorf("expected one error step, got %+v", steps)
	}
}

func TestFilterDomainsInScopeAppendsToExistingSteps(t *testing.T) {
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope.txt")
	os.WriteFile(scopeFile, []byte("10.0.0.0/24\n"), 0o644)

	prior := []stepResult{{Kind: "web", Name: "domains", Status: "ok"}}
	_, steps := filterDomainsInScope([]string{"10.0.0.5"}, scopeFile, dir, "domains", prior)

	if len(steps) != 2 {
		t.Fatalf("expected the prior step plus the new scopecheck step, got %+v", steps)
	}
	if steps[0].Name != "domains" || steps[1].Name != "scopecheck" {
		t.Errorf("steps = %+v, want [domains, scopecheck] in order", steps)
	}
}

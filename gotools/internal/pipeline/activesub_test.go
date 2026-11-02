package pipeline

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeProbeFile(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "probe.json")
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLiveProbedBaseURLsFiltersByWantAndErr(t *testing.T) {
	path := writeProbeFile(t, []string{
		`{"target":"live.example.com","url":"https://live.example.com","status":200}`,
		`{"target":"dead.example.com","url":"","error":"connection refused"}`,
		`{"target":"not-wanted.example.com","url":"https://not-wanted.example.com","status":200}`,
		`not json, a truncated last line`,
	})
	want := map[string]bool{"live.example.com": true, "dead.example.com": true}
	got := liveProbedBaseURLs(path, want)
	if !slices.Equal(got, []string{"https://live.example.com"}) {
		t.Errorf("got = %v, want just the live, wanted, successfully-probed one", got)
	}
}

func TestLiveProbedBaseURLsMissingFileIsEmpty(t *testing.T) {
	if got := liveProbedBaseURLs(filepath.Join(t.TempDir(), "missing.json"), map[string]bool{"a": true}); got != nil {
		t.Errorf("got = %v, want nil", got)
	}
}

func TestLiveProbedBaseURLsDedups(t *testing.T) {
	path := writeProbeFile(t, []string{
		`{"target":"a.example.com","url":"https://a.example.com","status":200}`,
		`{"target":"a.example.com","url":"https://a.example.com","status":200}`,
	})
	got := liveProbedBaseURLs(path, map[string]bool{"a.example.com": true})
	if !slices.Equal(got, []string{"https://a.example.com"}) {
		t.Errorf("got = %v, want one deduped entry", got)
	}
}

func TestActiveOnSubdomainsOrDefault(t *testing.T) {
	if (pipelineOptions{}).activeOnSubdomainsOrDefault(false) {
		t.Error("unset must fall back to the given default")
	}
	enabled := true
	if !(pipelineOptions{ActiveOnSubdomains: &enabled}).activeOnSubdomainsOrDefault(false) {
		t.Error("explicit true must win over the default")
	}
}

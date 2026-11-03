package pipeline

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseSelection(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want []int
	}{
		{"", 5, nil},
		{"none", 5, nil},
		{"  N  ", 5, nil},
		{"all", 3, []int{0, 1, 2}},
		{"*", 2, []int{0, 1}},
		{"1", 3, []int{0}},
		{"1,3", 3, []int{0, 2}},
		{"3,1,1", 3, []int{0, 2}}, // dedup, sorted
		{"2-4", 5, []int{1, 2, 3}},
		{"1,3-4", 5, []int{0, 2, 3}},
		{" 2 - 3 ", 5, []int{1, 2}},
	}
	for _, c := range cases {
		got, err := parseSelection(c.in, c.n)
		if err != nil {
			t.Errorf("parseSelection(%q, %d) unexpected error: %v", c.in, c.n, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseSelection(%q, %d) = %v, want %v", c.in, c.n, got, c.want)
		}
	}
}

func TestParseSelectionErrors(t *testing.T) {
	cases := []struct {
		in string
		n  int
	}{
		{"0", 3},
		{"4", 3},
		{"abc", 3},
		{"2-1", 5},
		{"1-10", 3},
	}
	for _, c := range cases {
		if _, err := parseSelection(c.in, c.n); err == nil {
			t.Errorf("parseSelection(%q, %d): expected an error, got none", c.in, c.n)
		}
	}
}

func TestSelectEntriesAndCandidates(t *testing.T) {
	cands := []fuzzCandidate{
		{entry: targetEntry{Target: "a.test"}, host: "a.test"},
		{entry: targetEntry{Target: "b.test"}, host: "b.test"},
		{entry: targetEntry{Target: "c.test"}, host: "c.test"},
	}
	entries := selectEntries(cands, []int{2, 0})
	if len(entries) != 2 || entries[0].Target != "c.test" || entries[1].Target != "a.test" {
		t.Errorf("selectEntries = %+v", entries)
	}
	picked := selectCandidates(cands, []int{1})
	if len(picked) != 1 || picked[0].host != "b.test" {
		t.Errorf("selectCandidates = %+v", picked)
	}
}

func TestCountFuzzHits(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "hits.json")
	writeLinesFile(f, []string{
		`{"url":"https://a.test/x","status":200}`,
		`{"url":"https://a.test/y","status":200}`,
		`{"url":"https://b.test/z","status":200}`,
		`not json`,
	})
	hits := countFuzzHits([]string{f})
	if hits["a.test"] != 2 || hits["b.test"] != 1 {
		t.Errorf("countFuzzHits = %v", hits)
	}
}

func TestFuzzWordlistDefaults(t *testing.T) {
	if got := fuzzDirsWordlistDefault(pipelineOptions{}); got != defaultFuzzDirsWordlist {
		t.Errorf("fuzzDirsWordlistDefault() = %q, want default", got)
	}
	if got := fuzzDirsWordlistDefault(pipelineOptions{FuzzDirsWordlist: "/tmp/custom.txt"}); got != "/tmp/custom.txt" {
		t.Errorf("fuzzDirsWordlistDefault() override = %q", got)
	}
	if got := fuzzFilesWordlistDefault(pipelineOptions{}); got != defaultFuzzFilesWordlist {
		t.Errorf("fuzzFilesWordlistDefault() = %q, want default", got)
	}
}

func TestResolveExistingWordlistFallsBackWhenMissing(t *testing.T) {
	dir := t.TempDir()
	got := resolveExistingWordlist(filepath.Join(dir, "does-not-exist.txt"), dir)
	if got != filepath.Join(dir, "common.txt") {
		t.Errorf("resolveExistingWordlist fallback = %q", got)
	}

	real := filepath.Join(dir, "real.txt")
	writeLinesFile(real, []string{"admin"})
	if got := resolveExistingWordlist(real, dir); got != real {
		t.Errorf("resolveExistingWordlist(existing) = %q, want %q", got, real)
	}
}

func TestRunFuzzStageDisabledSkipsEveryTarget(t *testing.T) {
	disabled := false
	cfg := &pipelineConfig{
		Web:     []targetEntry{{Target: "a.test"}, {Target: "b.test"}},
		Options: pipelineOptions{Fuzz: &disabled},
	}
	steps, files := runFuzzStage(cfg, t.TempDir(), cfg.Web, "")
	if len(files) != 0 {
		t.Errorf("expected no fuzz files when disabled, got %v", files)
	}
	if len(steps) != 2 {
		t.Fatalf("expected 2 skipped steps, got %d", len(steps))
	}
	for _, s := range steps {
		if s.Status != "skipped" {
			t.Errorf("step %+v: want skipped", s)
		}
	}
}

// TestRunManualFuzzPickFallsBackWithoutTerminal exercises the dispatcher's
// non-interactive path (activeSkip is nil in a test process -- no TTY) end
// to end: it must behave exactly like runSequentialFuzz, not block on a
// prompt.
func TestRunManualFuzzPickFallsBackWithoutTerminal(t *testing.T) {
	old := activeSkip
	activeSkip = nil
	defer func() { activeSkip = old }()

	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	writeLinesFile(wl, []string{"admin"})
	cfg := &pipelineConfig{Options: pipelineOptions{Wordlist: wl, Timeout: "1s"}}
	targets := []targetEntry{{Target: "https://nowhere.invalid"}}

	steps, files := runManualFuzzPick(cfg, dir, targets, "")
	if len(steps) != 1 {
		t.Fatalf("expected 1 step from the sequential fallback, got %d", len(steps))
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 fuzz file from the sequential fallback, got %d", len(files))
	}
}

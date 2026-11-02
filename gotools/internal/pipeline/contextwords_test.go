package pipeline

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestEngagementNameWordsSplitsAndFilters(t *testing.T) {
	got := engagementNameWords("Acme Billing Portal Inc.")
	want := []string{"acme", "billing", "portal"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestEngagementNameWordsSplitsCamelCase(t *testing.T) {
	got := engagementNameWords("AcmeBillingPortal")
	want := []string{"acme", "billing", "portal"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestEngagementNameWordsDropsShortAndDupes(t *testing.T) {
	got := engagementNameWords("Co Co ab Acme")
	if !slices.Equal(got, []string{"acme"}) {
		t.Errorf("got %v, want just [acme] (short tokens and stopwords dropped, dupes removed)", got)
	}
}

func TestEngagementNameWordsEmptyName(t *testing.T) {
	if got := engagementNameWords(""); len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

func TestContextWordsOrDefault(t *testing.T) {
	if !(pipelineOptions{}).contextWordsOrDefault(true) {
		t.Error("unset must fall back to the given default")
	}
	disabled := false
	if (pipelineOptions{ContextWords: &disabled}).contextWordsOrDefault(true) {
		t.Error("explicit false must win over the default")
	}
}

// runWebStage itself always makes real HTTP calls (see other tests' own
// comment on this), so it is intentionally not exercised here; this checks
// the one piece runWebStage adds on top of engagementNameWords -- writing
// its result to the file fuzz's -w picks up.
func TestEngagementNameWordsFileWrittenWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	nw := engagementNameWords("Acme Billing")
	path := filepath.Join(dir, "00_name_words.txt")
	if err := writeLinesFile(path, nw); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(b))
	if got != "acme\nbilling" {
		t.Errorf("name words file = %q", got)
	}
}

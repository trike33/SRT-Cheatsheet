package dork

import (
	"slices"
	"strings"
	"testing"
)

func TestGenerateDomainOnly(t *testing.T) {
	qs := Generate("example.com", "", nil)
	var names []string
	for _, q := range qs {
		names = append(names, q.Category)
		if !strings.Contains(q.Query, "example.com") {
			t.Errorf("%s query %q doesn't mention the domain", q.Category, q.Query)
		}
	}
	for _, want := range []string{"files", "backup", "admin", "listing", "errors", "confidential"} {
		if !slices.Contains(names, want) {
			t.Errorf("missing domain category %q in %v", want, names)
		}
	}
	for _, unwanted := range []string{"cloud", "pastes", "code"} {
		if slices.Contains(names, unwanted) {
			t.Errorf("name-only category %q must not appear without -name", unwanted)
		}
	}
}

func TestGenerateNameOnly(t *testing.T) {
	qs := Generate("", "Acme Corp", nil)
	var names []string
	for _, q := range qs {
		names = append(names, q.Category)
		if !strings.Contains(q.Query, "Acme Corp") {
			t.Errorf("%s query %q doesn't mention the name", q.Category, q.Query)
		}
	}
	want := []string{"cloud", "pastes", "code"}
	slices.Sort(names)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Errorf("got %v, want exactly %v", names, want)
	}
}

func TestGenerateNeitherDomainNorNameIsEmpty(t *testing.T) {
	if qs := Generate("", "", nil); len(qs) != 0 {
		t.Errorf("got %v, want none", qs)
	}
}

func TestGenerateRestrictedByWant(t *testing.T) {
	qs := Generate("example.com", "Acme", []string{"admin"})
	if len(qs) != 1 || qs[0].Category != "admin" {
		t.Errorf("got %+v, want just the admin category", qs)
	}
}

func TestGenerateUnknownWantedCategoryIsIgnoredNotError(t *testing.T) {
	qs := Generate("example.com", "", []string{"bogus"})
	if len(qs) != 0 {
		t.Errorf("got %v, want none (unknown category name matches nothing)", qs)
	}
}

func TestCategoryNamesMatchesCategories(t *testing.T) {
	got := CategoryNames()
	if len(got) != len(categories) {
		t.Fatalf("len = %d, want %d", len(got), len(categories))
	}
	for i, c := range categories {
		if got[i] != c.Name {
			t.Errorf("CategoryNames()[%d] = %q, want %q", i, got[i], c.Name)
		}
	}
}

func TestSearchURLEscapesAndPrefixesGoogle(t *testing.T) {
	got := SearchURL(`site:example.com intitle:"index of"`)
	if !strings.HasPrefix(got, "https://www.google.com/search?q=") {
		t.Errorf("got %q", got)
	}
	if strings.Contains(got, " ") || strings.Contains(got, `"`) {
		t.Errorf("query not escaped: %q", got)
	}
}

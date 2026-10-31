package fuzz

import (
	"slices"
	"sort"
	"testing"
)

func TestMutateWordCase(t *testing.T) {
	e := &fuzzEngine{mutateCase: true}
	got := e.mutateWord("Admin")
	sort.Strings(got)
	want := []string{"ADMIN", "Admin", "admin"}
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Errorf("mutateWord(Admin) = %v, want %v", got, want)
	}
}

func TestMutateWordDedupesWhenAlreadyLower(t *testing.T) {
	e := &fuzzEngine{mutateCase: true}
	got := e.mutateWord("admin")
	// lower==original, so only original, UPPER and Title should remain.
	if len(got) != 3 {
		t.Errorf("got %v, want 3 distinct forms", got)
	}
}

func TestMutateWordOffByDefault(t *testing.T) {
	e := &fuzzEngine{}
	if got := e.mutateWord("Admin"); !slices.Equal(got, []string{"Admin"}) {
		t.Errorf("got %v, want unchanged", got)
	}
}

func TestExpandExtToken(t *testing.T) {
	cands, isTok := expandExtToken("backup.%ext%", []string{".php", ".bak"})
	if !isTok {
		t.Fatal("expected the token to be recognized")
	}
	want := []string{"backup.php", "backup.bak"}
	if !slices.Equal(cands, want) {
		t.Errorf("got %v, want %v", cands, want)
	}
}

func TestExpandExtTokenNoExtsDropsToken(t *testing.T) {
	cands, isTok := expandExtToken("backup.%ext%", nil)
	if !isTok {
		t.Fatal("expected the token to still be recognized")
	}
	if len(cands) != 0 {
		t.Errorf("got %v, want no candidates when nothing resolves the token", cands)
	}
}

func TestExpandExtTokenPlainWordUntouched(t *testing.T) {
	_, isTok := expandExtToken("admin", []string{".php"})
	if isTok {
		t.Error("a word without the ext token should not be treated as a token word")
	}
}

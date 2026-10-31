package colorout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTermWidthNonTerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "notty")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if w := TermWidth(f); w != 0 {
		t.Errorf("TermWidth(regular file) = %d, want 0", w)
	}
}

func TestOverwriteFallsBackToNewlineOffTerminal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.txt")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	Overwrite(f, "tick one")
	Overwrite(f, "tick two")
	f.Close()

	b, _ := os.ReadFile(p)
	got := string(b)
	if strings.Contains(got, "\r") || strings.Contains(got, "\033[K") {
		t.Errorf("non-terminal output should never carry overwrite escapes: %q", got)
	}
	if got != "tick one\ntick two\n" {
		t.Errorf("got %q, want two newline-terminated lines", got)
	}
}

func TestClearLineNoopOffTerminal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.txt")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	ClearLine(f)
	f.Close()
	b, _ := os.ReadFile(p)
	if len(b) != 0 {
		t.Errorf("ClearLine on a non-terminal should write nothing, got %q", b)
	}
}

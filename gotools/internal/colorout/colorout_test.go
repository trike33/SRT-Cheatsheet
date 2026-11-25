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

func TestEnvColorOverridesAutoRegardlessOfTerminal(t *testing.T) {
	// go test's own stdout generally isn't a terminal, so Auto would say
	// "no color" here without EnvColor -- the point of this test is that
	// EnvColor short-circuits that check either way.
	t.Setenv(EnvColor, "1")
	if !Auto.Enabled() {
		t.Error("Auto.Enabled() with SRT_COLOR=1 = false, want true")
	}
	t.Setenv(EnvColor, "0")
	if Auto.Enabled() {
		t.Error("Auto.Enabled() with SRT_COLOR=0 = true, want false")
	}
	// Always/Never are absolute: EnvColor must never override them (a
	// command's own explicit -color=always/never flag always wins).
	t.Setenv(EnvColor, "0")
	if !Always.Enabled() {
		t.Error("Always.Enabled() with SRT_COLOR=0 = false, want true")
	}
	t.Setenv(EnvColor, "1")
	if Never.Enabled() {
		t.Error("Never.Enabled() with SRT_COLOR=1 = true, want false")
	}
}

func TestProgressMarkModeOffTerminal(t *testing.T) {
	t.Setenv(EnvProgressMark, "1")
	p := filepath.Join(t.TempDir(), "out.txt")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	Overwrite(f, "tick one")
	ClearLine(f)
	f.Close()
	b, _ := os.ReadFile(p)
	if want := "tick one\x1e\x1e"; string(b) != want {
		t.Errorf("got %q, want %q", b, want)
	}
}

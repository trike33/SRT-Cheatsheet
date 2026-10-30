package main

import "testing"

func TestShellSplitArgs(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"version", []string{"version"}},
		{"fuzz -u https://x/FUZZ -w words.txt", []string{"fuzz", "-u", "https://x/FUZZ", "-w", "words.txt"}},
		{`fuzz -H "Name: Value"`, []string{"fuzz", "-H", "Name: Value"}},
		{`ipexpand -l 'a file with spaces.txt'`, []string{"ipexpand", "-l", "a file with spaces.txt"}},
		{"  spaced   out   ", []string{"spaced", "out"}},
	}
	for _, c := range cases {
		got, err := shellSplitArgs(c.in)
		if err != nil {
			t.Errorf("shellSplitArgs(%q): unexpected error: %v", c.in, err)
			continue
		}
		if !equalStrings(got, c.want) {
			t.Errorf("shellSplitArgs(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestShellSplitArgsUnterminatedQuote(t *testing.T) {
	if _, err := shellSplitArgs(`fuzz -H "unterminated`); err == nil {
		t.Error("expected an error for an unterminated quote")
	}
}

func TestShellAutoCompleteUnambiguous(t *testing.T) {
	newLine, newPos, ok := shellAutoComplete([]string{"fuzz", "resolve"}, "res", 3, '\t')
	if !ok || newLine != "resolve " || newPos != len("resolve ") {
		t.Errorf("unambiguous completion: newLine=%q newPos=%d ok=%v", newLine, newPos, ok)
	}
}

func TestShellAutoCompleteAmbiguousIsNoop(t *testing.T) {
	names := []string{"snyk", "subdomains", "sensitive"}
	newLine, _, ok := shellAutoComplete(names, "s", 1, '\t')
	if ok {
		t.Errorf("expected an ambiguous prefix to be a no-op, got newLine=%q ok=%v", newLine, ok)
	}
}

func TestShellAutoCompleteNoMatchIsNoop(t *testing.T) {
	names := []string{"fuzz", "resolve"}
	_, _, ok := shellAutoComplete(names, "zzz", 3, '\t')
	if ok {
		t.Error("expected no match to be a no-op")
	}
}

func TestShellAutoCompleteIgnoresNonTabKeys(t *testing.T) {
	names := []string{"fuzz"}
	_, _, ok := shellAutoComplete(names, "fuz", 3, 'x')
	if ok {
		t.Error("expected a non-Tab key to be a no-op")
	}
}

func TestShellAutoCompleteOnlyCompletesFirstWord(t *testing.T) {
	names := []string{"fuzz"}
	_, _, ok := shellAutoComplete(names, "fuzz -u fu", 10, '\t')
	if ok {
		t.Error("expected completion to be a no-op once a space has been typed (only the command name completes)")
	}
}

func TestShellCommandNamesIncludesPseudoCommands(t *testing.T) {
	names := shellCommandNames()
	for _, want := range []string{"help", "exit", "version", "fuzz"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("shellCommandNames() missing %q: %v", want, names)
		}
	}
}

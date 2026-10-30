package main

import "testing"

func newTestModel() shellModel {
	m := newShellModel("/fake/path/to/srt")
	m.colorOn = false // deterministic: no ANSI codes to strip in assertions
	return m
}

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

func TestInsertRuneAndCursor(t *testing.T) {
	m := newTestModel()
	m, _ = m.insertRune('f')
	m, _ = m.insertRune('u')
	m, _ = m.insertRune('z')
	if string(m.input) != "fuz" || m.cursor != 3 {
		t.Fatalf("after inserts: input=%q cursor=%d", string(m.input), m.cursor)
	}

	m.cursor = 1 // move cursor between 'f' and 'u'
	m, _ = m.insertRune('X')
	if string(m.input) != "fXuz" || m.cursor != 2 {
		t.Errorf("mid-line insert: input=%q cursor=%d, want \"fXuz\" cursor=2", string(m.input), m.cursor)
	}
}

func TestCompleteCommandNameUnambiguous(t *testing.T) {
	m := newTestModel()
	m.input = []rune("vers")
	m.cursor = len(m.input)
	m.completeCommandName()
	if string(m.input) != "version " || m.cursor != len("version ") {
		t.Errorf("completion = %q (cursor %d), want \"version \" (cursor %d)", string(m.input), m.cursor, len("version "))
	}
}

func TestCompleteCommandNameAmbiguousIsNoop(t *testing.T) {
	m := newTestModel()
	m.input = []rune("s") // several commands start with "s"
	m.cursor = 1
	m.completeCommandName()
	if string(m.input) != "s" {
		t.Errorf("ambiguous completion changed the line: %q", string(m.input))
	}
}

func TestCompleteCommandNameOnlyCompletesFirstWord(t *testing.T) {
	m := newTestModel()
	m.input = []rune("fuzz -u fu")
	m.cursor = len(m.input)
	m.completeCommandName()
	if string(m.input) != "fuzz -u fu" {
		t.Errorf("completion fired past the first word: %q", string(m.input))
	}
}

func TestHistoryNavigation(t *testing.T) {
	m := newTestModel()
	m.history = []string{"version", "fuzz -h"}
	m.histPos = len(m.history)
	m.input = []rune("unsent draft")
	m.cursor = len(m.input)

	m.historyBack()
	if string(m.input) != "fuzz -h" {
		t.Fatalf("historyBack 1: input=%q", string(m.input))
	}
	m.historyBack()
	if string(m.input) != "version" {
		t.Fatalf("historyBack 2: input=%q", string(m.input))
	}
	m.historyBack() // at the oldest entry; should stay put
	if string(m.input) != "version" {
		t.Fatalf("historyBack past oldest: input=%q", string(m.input))
	}

	m.historyForward()
	if string(m.input) != "fuzz -h" {
		t.Fatalf("historyForward 1: input=%q", string(m.input))
	}
	m.historyForward() // back to the unsent draft
	if string(m.input) != "unsent draft" {
		t.Fatalf("historyForward to draft: input=%q", string(m.input))
	}
}

func TestDeleteWordBefore(t *testing.T) {
	m := newTestModel()
	m.input = []rune("fuzz -u target")
	m.cursor = len(m.input)
	m.deleteWordBefore()
	if string(m.input) != "fuzz -u " {
		t.Errorf("deleteWordBefore = %q, want \"fuzz -u \"", string(m.input))
	}
}

func TestApplyColorCommand(t *testing.T) {
	m := newTestModel()
	m.colorOn = false

	m.applyColorCommand([]string{"on"})
	if !m.colorOn || m.lastErr != nil {
		t.Errorf("color on: colorOn=%v lastErr=%v", m.colorOn, m.lastErr)
	}
	m.applyColorCommand([]string{"off"})
	if m.colorOn || m.lastErr != nil {
		t.Errorf("color off: colorOn=%v lastErr=%v", m.colorOn, m.lastErr)
	}
	m.applyColorCommand([]string{"bogus"})
	if m.lastErr == nil {
		t.Error("color bogus: expected lastErr to be set")
	}
	m.lastErr = nil
	m.applyColorCommand(nil)
	if m.lastErr == nil {
		t.Error("color with no args: expected a usage error")
	}
}

func TestTokenizeLineWithSpans(t *testing.T) {
	toks := tokenizeLineWithSpans([]rune(`fuzz -H "Name: Value" plain`))
	want := []string{"fuzz", "-H", `"Name: Value"`, "plain"}
	if len(toks) != len(want) {
		t.Fatalf("tokens = %+v, want %d entries", toks, len(want))
	}
	for i, w := range want {
		if toks[i].text != w {
			t.Errorf("token[%d] = %q, want %q", i, toks[i].text, w)
		}
	}
}

func TestTokenizeLineWithSpansUnterminatedQuoteDoesNotPanic(t *testing.T) {
	// Mid-typing an unterminated quote must not crash the live highlighter.
	toks := tokenizeLineWithSpans([]rune(`fuzz -H "still typing`))
	if len(toks) != 3 {
		t.Errorf("tokens = %+v, want 3 (fuzz, -H, the open-quoted rest)", toks)
	}
}

func TestShellCommandNamesIncludesPseudoCommands(t *testing.T) {
	names := shellCommandNames()
	for _, want := range []string{"help", "exit", "quit", "clear", "color", "fuzz", "version"} {
		if !commandKnown(names, want) {
			t.Errorf("shellCommandNames() missing %q: %v", want, names)
		}
	}
}

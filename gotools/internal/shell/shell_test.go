package shell

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	// Blank-imported so the registry looks the way it does for the real
	// binary (main.go imports all of these too) -- shell.go itself never
	// imports a recon package, it only ever looks commands up by name.
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/pipeline"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/dirlist"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/domains"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/fuzz"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/gau"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/ipexpand"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/portscan"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/probe"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/relpaths"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/resolve"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/robots"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/snyk"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/subdomains"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/traceroute"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/results"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/version"
)

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
		if !slices.Equal(got, c.want) {
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

func typeLine(m shellModel, s string) shellModel {
	m.input = []rune(s)
	m.cursor = len(m.input)
	return m
}

func TestRunLineBlankIsNoop(t *testing.T) {
	m := typeLine(newTestModel(), "   ")
	got, cmd := m.runLine()
	if cmd != nil || len(got.(shellModel).history) != 0 {
		t.Errorf("blank line should do nothing: cmd=%v history=%v", cmd, got.(shellModel).history)
	}
}

func TestRunLineExitQuits(t *testing.T) {
	for _, w := range []string{"exit", "quit"} {
		got, cmd := typeLine(newTestModel(), w).runLine()
		if !got.(shellModel).quitting || cmd == nil {
			t.Errorf("%q should quit", w)
		}
	}
}

func TestRunLineUnknownCommand(t *testing.T) {
	got, cmd := typeLine(newTestModel(), "nosuchcmd -x").runLine()
	gm := got.(shellModel)
	if cmd != nil || gm.lastErr == nil {
		t.Errorf("unknown command: cmd=%v lastErr=%v", cmd, gm.lastErr)
	}
	if len(gm.history) != 1 || gm.input != nil || gm.cursor != 0 {
		t.Errorf("line should be recorded and input reset: %+v", gm)
	}
}

func TestRunLineUnterminatedQuote(t *testing.T) {
	got, cmd := typeLine(newTestModel(), `fuzz -H "oops`).runLine()
	if cmd != nil || got.(shellModel).lastErr == nil {
		t.Error("unterminated quote should set lastErr and run nothing")
	}
}

func TestRunLineKnownCommandSpawnsSubprocess(t *testing.T) {
	got, cmd := typeLine(newTestModel(), "version").runLine()
	if cmd == nil || got.(shellModel).lastErr != nil {
		t.Errorf("known command should return an exec cmd: cmd=%v err=%v", cmd, got.(shellModel).lastErr)
	}
	if _, cmd = typeLine(newTestModel(), "help fuzz").runLine(); cmd == nil {
		t.Error("help <command> should dispatch")
	}
}

func TestRunLineClear(t *testing.T) {
	if _, cmd := typeLine(newTestModel(), "clear").runLine(); cmd == nil {
		t.Error("clear should return a ClearScreen cmd")
	}
}

func TestExecDoneMsg(t *testing.T) {
	m := newTestModel()
	got, _ := m.Update(execDoneMsg{cmd: "x", err: errors.New("launch failed")})
	if got.(shellModel).lastErr == nil {
		t.Error("launch failure should surface")
	}
	got, _ = m.Update(execDoneMsg{cmd: "x", err: &exec.ExitError{}})
	if got.(shellModel).lastErr != nil {
		t.Error("clean non-zero exit should not surface")
	}
}

func TestHandleKeyEditing(t *testing.T) {
	m := newTestModel()
	send := func(k tea.KeyMsg) { got, _ := m.Update(k); m = got.(shellModel) }
	send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("abc")})
	send(tea.KeyMsg{Type: tea.KeySpace})
	send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if string(m.input) != "abc d" {
		t.Fatalf("input = %q", string(m.input))
	}
	send(tea.KeyMsg{Type: tea.KeyBackspace})
	send(tea.KeyMsg{Type: tea.KeyHome})
	send(tea.KeyMsg{Type: tea.KeyDelete})
	if string(m.input) != "bc " || m.cursor != 0 {
		t.Errorf("after backspace/home/delete: %q cursor=%d", string(m.input), m.cursor)
	}
	send(tea.KeyMsg{Type: tea.KeyEnd})
	send(tea.KeyMsg{Type: tea.KeyLeft})
	if m.cursor != 2 {
		t.Errorf("cursor = %d, want 2", m.cursor)
	}
	send(tea.KeyMsg{Type: tea.KeyCtrlU})
	if len(m.input) != 0 {
		t.Errorf("ctrl+u should clear: %q", string(m.input))
	}
}

func TestHandleKeyQuit(t *testing.T) {
	got, cmd := newTestModel().Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if !got.(shellModel).quitting || cmd == nil {
		t.Error("ctrl+c should quit")
	}
	got, cmd = newTestModel().Update(tea.KeyMsg{Type: tea.KeyCtrlD})
	if !got.(shellModel).quitting || cmd == nil {
		t.Error("ctrl+d on empty line should quit")
	}
	got, cmd = typeLine(newTestModel(), "ab").Update(tea.KeyMsg{Type: tea.KeyCtrlD})
	if !got.(shellModel).quitting || cmd == nil {
		t.Error("ctrl+d should quit even with text typed")
	}
}

func TestWindowSizeAndView(t *testing.T) {
	got, _ := newTestModel().Update(tea.WindowSizeMsg{Width: 120})
	m := got.(shellModel)
	if m.width != 120 {
		t.Errorf("width = %d", m.width)
	}
	if v := typeLine(m, "version").View(); !strings.Contains(v, "version") {
		t.Errorf("View() missing input: %q", v)
	}
}

func TestRunShellRequiresTTY(t *testing.T) {
	if stdinIsTerminal() {
		t.Skip("stdin is a TTY here")
	}
	if err := Run(nil); err == nil {
		t.Error("runShell without a TTY should error")
	}
}

func TestProjectName(t *testing.T) {
	for in, want := range map[string]string{"/home/user/project1": "project1", "/": "/", "/a/b/": "b"} {
		if got := projectName(in); got != want {
			t.Errorf("projectName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCdSwitchesProject(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "alpha"), filepath.Join(root, "beta")
	os.Mkdir(a, 0o755)
	os.Mkdir(b, 0o755)
	os.WriteFile(filepath.Join(b, "target_assets.json"), []byte("{}"), 0o644)
	t.Chdir(a)
	ra, _ := os.Getwd()

	got, _ := typeLine(newTestModel(), "cd "+b).runLine()
	m := got.(shellModel)
	if m.lastErr != nil {
		t.Fatal(m.lastErr)
	}
	if wd, _ := os.Getwd(); projectName(wd) != "beta" {
		t.Errorf("cwd = %s", wd)
	}
	if !strings.Contains(m.notice, "beta") || !strings.Contains(m.notice, "target_assets.json") {
		t.Errorf("notice = %q", m.notice)
	}

	got, _ = typeLine(m, "cd -").runLine()
	if wd, _ := os.Getwd(); wd != ra {
		t.Errorf("cd - went to %s, want %s", wd, ra)
	}
	_ = got
}

func TestCdErrors(t *testing.T) {
	t.Chdir(t.TempDir())
	got, _ := typeLine(newTestModel(), "cd /no/such/dir-xyz").runLine()
	if got.(shellModel).lastErr == nil {
		t.Error("missing dir should error")
	}
	got, _ = typeLine(newTestModel(), "cd -").runLine()
	if got.(shellModel).lastErr == nil {
		t.Error("cd - with no previous should error")
	}
	got, _ = typeLine(newTestModel(), "cd a b").runLine()
	if got.(shellModel).lastErr == nil {
		t.Error("too many args should error")
	}
}

func TestCompletePathArg(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"project1", "project2", "other", ".hidden"} {
		os.Mkdir(filepath.Join(root, d), 0o755)
	}
	os.WriteFile(filepath.Join(root, "projfile"), nil, 0o644)
	os.WriteFile(filepath.Join(root, "projfile2"), nil, 0o644)

	run := func(line string) string {
		m := typeLine(newTestModel(), line)
		m.completePathArg()
		return string(m.input)
	}
	if got := run("cd " + root + "/oth"); got != "cd "+root+"/other/" {
		t.Errorf("unique: %q", got)
	}
	if got := run("project " + root + "/pro"); got != "project "+root+"/project" {
		t.Errorf("common prefix: %q", got)
	}
	if got := run("cd " + root + "/projf"); got != "cd "+root+"/projf" {
		t.Errorf("files must not complete for cd/project: %q", got)
	}
	if got := run("cd " + root + "/."); got != "cd "+root+"/.hidden/" {
		t.Errorf("hidden: %q", got)
	}
	if got := run("fuzz " + root + "/oth"); got != "fuzz "+root+"/other/" {
		t.Errorf("non-cd/project commands also complete paths: %q", got)
	}
	if got := run("fuzz " + root + "/projfile"); got != "fuzz "+root+"/projfile" {
		t.Errorf("files complete for non-cd/project commands: %q", got)
	}
	if got := run("fuzz -w " + root + "/oth"); got != "fuzz -w "+root+"/other/" {
		t.Errorf("completion applies to a later word, not just the 2nd: %q", got)
	}
}

func TestCompletePathArgCommandNameUntouched(t *testing.T) {
	m := typeLine(newTestModel(), "fu")
	m.completePathArg()
	if string(m.input) != "fu" {
		t.Errorf("cursor still in the command word, completeCommandName owns that: %q", m.input)
	}
}

func TestExecDoneSetsLastRunNotNotice(t *testing.T) {
	m := newTestModel()
	m.trafficFile = filepath.Join(t.TempDir(), "t.json")
	os.WriteFile(m.trafficFile, []byte(`{"requests":5,"bytes_out":10,"bytes_in":20}`), 0o644)

	got, _ := m.Update(execDoneMsg{cmd: "probe"})
	gm := got.(shellModel)
	if !strings.Contains(gm.lastRun, "probe") {
		t.Errorf("lastRun = %q, want it to mention the command", gm.lastRun)
	}
	if gm.notice != "" {
		t.Errorf("notice = %q, traffic feedback should go to lastRun, not notice", gm.notice)
	}
}

func TestLastRunSurvivesAKeystroke(t *testing.T) {
	m := newTestModel()
	m.lastRun = "last: probe — 5 req"
	got, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	gm := got.(shellModel)
	if gm.lastRun != m.lastRun {
		t.Errorf("lastRun = %q after a keystroke, want it unchanged (unlike notice)", gm.lastRun)
	}
}

func TestRenderTrafficShowsSessionAndLastRun(t *testing.T) {
	m := newTestModel()
	if got := m.renderTraffic(); !strings.Contains(got, "no command run yet") {
		t.Errorf("renderTraffic with nothing run = %q", got)
	}
	m.lastRun = "last: fuzz — 100 req"
	m.rate = 50
	m.save = true
	got := m.renderTraffic()
	if !strings.Contains(got, "50 req/s") || !strings.Contains(got, "save on") || !strings.Contains(got, "last: fuzz") {
		t.Errorf("renderTraffic = %q", got)
	}
}

func TestViewIncludesTrafficBox(t *testing.T) {
	m := newTestModel()
	m.lastRun = "last: portscan — 9 req"
	if v := m.View(); !strings.Contains(v, "portscan") || !strings.Contains(v, "session:") {
		t.Errorf("View() missing the traffic box: %q", v)
	}
}

func TestParseFlagUsage(t *testing.T) {
	text := "Usage of fuzz:\n  -c int\n    \ttotal workers (default 40)\n  -ac\n    \tauto-calibrate\n  -v\tverbose\n  -u value\n    \ttarget URL\n    \tsecond line\n"
	got := parseFlagUsage(text)
	if len(got) != 4 {
		t.Fatalf("want 4 flags, got %+v", got)
	}
	if got[0].Name != "c" || got[0].Arg != "int" || got[0].Desc != "total workers (default 40)" {
		t.Errorf("flag c: %+v", got[0])
	}
	if got[1].Arg != "" || got[2].Desc != "verbose" || got[3].Desc != "target URL second line" {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestFlagHint(t *testing.T) {
	m := newTestModel()
	m.helpCache = map[string]*cmdHelp{"fuzz": {flags: parseFlagUsage("  -u value\n    \ttarget URL\n  -ua string\n    \tUser-Agent\n  -c int\n    \tworkers\n")}}

	if h := typeLine(m, "fuzz -c").flagHint(); len(h) != 1 || !strings.Contains(h[0], "workers") {
		t.Errorf("exact flag hint: %q", h)
	}
	if h := typeLine(m, "fuzz -u").flagHint(); len(h) != 2 || !strings.Contains(h[0], "target URL") {
		t.Errorf("prefix hint should list -u first then -ua: %q", h)
	}
	if h := typeLine(m, "fuzz -c ").flagHint(); len(h) != 1 {
		t.Errorf("value position should remind the flag: %q", h)
	}
	if h := typeLine(m, "fuzz").flagHint(); h != nil {
		t.Errorf("no hint before arguments: %q", h)
	}
}

func TestHelpPaneOpensAndCloses(t *testing.T) {
	m := typeLine(newTestModel(), "help fuzz")
	nm, cmd := m.runLine()
	m = nm.(shellModel)
	if !m.helpOpen || m.helpName != "fuzz" || cmd == nil {
		t.Fatalf("pane not opened: open=%v name=%q", m.helpOpen, m.helpName)
	}
	m.helpCache["fuzz"] = &cmdHelp{text: strings.Repeat("line\n", 100)}
	m.height = 30
	m.scrollHelp(10)
	if m.helpScroll != 10 {
		t.Errorf("scroll = %d", m.helpScroll)
	}
	nm, _ = m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if nm.(shellModel).helpOpen {
		t.Error("Esc should close the pane")
	}
}

func TestRunningACommandClosesHelpPane(t *testing.T) {
	m := newTestModel()
	m.helpOpen, m.helpName = true, "fuzz"
	nm, cmd := typeLine(m, "version").runLine()
	if nm.(shellModel).helpOpen {
		t.Error("launching a command must close the help pane first")
	}
	if cmd == nil {
		t.Error("expected the command to be launched")
	}
}

func TestCtrlLClearsScreenKeepingInput(t *testing.T) {
	got, cmd := typeLine(newTestModel(), "fuzz -u").Update(tea.KeyMsg{Type: tea.KeyCtrlL})
	if cmd == nil || string(got.(shellModel).input) != "fuzz -u" {
		t.Errorf("ctrl+l should clear the screen and keep the typed line (cmd=%v, input=%q)", cmd != nil, string(got.(shellModel).input))
	}
}

const groupedUsage = `Usage of probe:

INPUT:
   -l string          target list: URLs or bare hosts (default: stdin)

OUTPUT:
   -o string          output file (default: stdout)
   -json              emit JSON lines instead of a table
`

func TestParseFlagUsageGrouped(t *testing.T) {
	got := parseFlagUsage(groupedUsage)
	if len(got) != 3 || got[0].Name != "l" || got[0].Arg != "string" || got[2].Name != "json" || got[2].Arg != "" {
		t.Fatalf("parseFlagUsage(grouped) = %+v", got)
	}
	if got[1].Desc != "output file (default: stdout)" {
		t.Errorf("desc = %q", got[1].Desc)
	}
}

func TestTabCompletesFlagsAndKeywordsPastFirstWord(t *testing.T) {
	m := newShellModel("srt")
	m.helpCache = map[string]*cmdHelp{"probe": {flags: parseFlagUsage(groupedUsage)}}
	set := func(s string) { m.input, m.cursor = []rune(s), len([]rune(s)) }

	set("probe -j")
	if !m.completeArgWord() || string(m.input) != "probe -json " {
		t.Errorf("flag completion: %q", string(m.input))
	}
	set("probe -l x.txt -o")
	if !m.completeArgWord() || string(m.input) != "probe -l x.txt -o " {
		t.Errorf("flag completion mid-line: %q", string(m.input))
	}
	set("help pr")
	m.names = []string{"probe", "portscan"}
	if !m.completeArgWord() || string(m.input) != "help probe " {
		t.Errorf("help completion: %q", string(m.input))
	}
	set("color o")
	m.completeArgWord() // "on"/"off" -> common prefix "o": unchanged
	if string(m.input) != "color o" {
		t.Errorf("ambiguous keyword changed input: %q", string(m.input))
	}
	set("probe ./x")
	if m.completeArgWord() {
		t.Error("plain path word must fall through to path completion")
	}
}

func TestArgClassHighlightsFlags(t *testing.T) {
	m := newShellModel("srt")
	m.helpCache = map[string]*cmdHelp{"probe": {flags: parseFlagUsage(groupedUsage)}}
	toks := tokenizeLineWithSpans([]rune("probe -json -bogus -3 -o=x"))
	want := []tokClass{classCommand, classFlag, classUnknown, classPlain, classFlag}
	for i := 1; i < len(toks); i++ {
		if got := m.argClass(toks, i); got != want[i] {
			t.Errorf("token %q: class %v, want %v", toks[i].text, got, want[i])
		}
	}
}

func TestCommandOutputIsCapturedIntoScrollback(t *testing.T) {
	m := newTestModel()
	m.self, m.width, m.height = "/bin/echo", 100, 30
	m.names = append(m.names, "hello")
	nm, cmd := m.launch("hello", []string{"world"}, false)
	m = nm.(shellModel)
	if m.run == nil {
		t.Fatal("run state not set while the command is running")
	}
	for msg := cmd(); ; {
		if b, ok := msg.(tea.BatchMsg); ok {
			msg = b[0]() // begin(): first output batch
			continue
		}
		var next tea.Model
		next, cmd = m.Update(msg)
		m = next.(shellModel)
		if m.run == nil {
			break
		}
		msg = cmd()
	}
	if len(m.out) == 0 || m.out[0] != "hello world" {
		t.Errorf("scrollback = %q", m.out)
	}
	if got := strings.Count(m.View(), "\n") + 1; got != m.height {
		t.Errorf("view is %d rows, want exactly the terminal height %d", got, m.height)
	}
	lines := strings.Split(m.View(), "\n")
	if !strings.Contains(lines[len(lines)-1], "help") && !strings.Contains(lines[len(lines)-2], "srt>") {
		t.Errorf("prompt is not pinned to the bottom:\n%s", m.View())
	}
}

func TestScrollbackScrollsAndClamps(t *testing.T) {
	m := newTestModel()
	m.width, m.height = 80, 24
	for i := 0; i < 100; i++ {
		m.appendOut(fmt.Sprintf("line %d", i))
	}
	if !strings.Contains(m.renderOutput(80, 10), "line 99") {
		t.Error("following output should show the newest line")
	}
	m.scrollOut(15)
	out := m.renderOutput(80, 10)
	if strings.Contains(out, "line 99") || !strings.Contains(out, "line 84") {
		t.Errorf("scrolled view wrong:\n%s", out)
	}
	m.scrollOut(10000)
	if m.outScroll > 100 {
		t.Errorf("scroll not clamped: %d", m.outScroll)
	}
	m.scrollOut(-10000)
	if m.outScroll != 0 {
		t.Errorf("scroll below newest: %d", m.outScroll)
	}
}

func TestCleanLineStripsControlSequencesKeepsColour(t *testing.T) {
	got := cleanLine("\x1b[2J\x1b[Hpre\rprog 50%\x1b[31m red\x1b[0m\x1b]0;title\x07\t\n")
	if got != "prog 50%\x1b[31m red\x1b[0m" {
		t.Errorf("cleanLine = %q", got)
	}
}

func TestOutputIsKeptCleanAndCounted(t *testing.T) {
	m := newTestModel()
	m.colorOn = false
	m.appendCmdOut([]string{"", "", "a", "", "", "[!] slow host", "srt: boom", "srt: HALTED — limit", ""})
	want := []string{"a", "", "[!] slow host", "srt: boom", "srt: HALTED — limit", ""}
	if strings.Join(m.out, "|") != strings.Join(want, "|") {
		t.Errorf("out = %q, want %q", m.out, want)
	}
	if m.errCount != 1 || m.warnCount != 2 {
		t.Errorf("errors=%d warnings=%d, want 1 and 2", m.errCount, m.warnCount)
	}
	m.endBlock()
	if len(m.out) != len(want) {
		t.Error("endBlock must not add a second blank line")
	}
	if got := plainText(m.renderCounts()); got != "errors 1 · warnings 2" {
		t.Errorf("renderCounts = %q", got)
	}
}

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

func init() {
	register(&command{
		name:    "shell",
		group:   "misc",
		summary: "Interactive shell: history, Tab-completion, live syntax highlighting",
		run:     runShell,
	})
}

func stdinIsTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

func runShell(args []string) error {
	if !stdinIsTerminal() {
		return errMissing("shell needs an interactive terminal (stdin is not a TTY)")
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("determining srt's own binary path: %w", err)
	}

	// Printed once, directly, before the Bubble Tea program starts: it
	// becomes ordinary scrollback, not part of the live-redrawn view below
	// it -- matching a banner-once-then-a-persistent-input-box layout.
	fmt.Println(renderBanner())

	m := newShellModel(self)
	if _, err := tea.NewProgram(m).Run(); err != nil {
		return err
	}
	return nil
}

// shellModel is the Bubble Tea model for the whole session: current input
// line, cursor, history, and the one piece of session state a user can
// change at runtime (color).
type shellModel struct {
	self string

	input  []rune
	cursor int

	history []string
	histPos int // == len(history) while editing a fresh (non-history) line
	saved   []rune

	names []string // every registered command name + shell pseudo-commands, for completion/highlighting

	colorOn bool
	width   int

	lastErr  error
	quitting bool
}

type execDoneMsg struct {
	cmd string
	err error
}

func newShellModel(self string) shellModel {
	return shellModel{
		self:    self,
		names:   shellCommandNames(),
		colorOn: term.IsTerminal(int(os.Stdout.Fd())),
		width:   80,
	}
}

func (m shellModel) Init() tea.Cmd { return nil }

func (m shellModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case execDoneMsg:
		m.lastErr = nil
		if msg.err != nil {
			var exitErr *exec.ExitError
			if !errors.As(msg.err, &exitErr) {
				// A clean non-zero exit (bad flags, -h, a real command
				// error) already printed its own reason; only a launch
				// failure is worth surfacing here.
				m.lastErr = fmt.Errorf("%s: %w", msg.cmd, msg.err)
			}
		}
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m shellModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.lastErr = nil

	switch msg.Type {
	case tea.KeyCtrlC:
		m.quitting = true
		return m, tea.Quit

	case tea.KeyCtrlD:
		if len(m.input) == 0 {
			m.quitting = true
			return m, tea.Quit
		}
		if m.cursor < len(m.input) {
			m.input = append(m.input[:m.cursor], m.input[m.cursor+1:]...)
		}
		return m, nil

	case tea.KeyEnter:
		return m.runLine()

	case tea.KeyTab:
		m.completeCommandName()
		return m, nil

	case tea.KeyBackspace:
		if m.cursor > 0 {
			m.input = append(m.input[:m.cursor-1], m.input[m.cursor:]...)
			m.cursor--
		}
		return m, nil

	case tea.KeyDelete:
		if m.cursor < len(m.input) {
			m.input = append(m.input[:m.cursor], m.input[m.cursor+1:]...)
		}
		return m, nil

	case tea.KeyLeft:
		if m.cursor > 0 {
			m.cursor--
		}
		return m, nil

	case tea.KeyRight:
		if m.cursor < len(m.input) {
			m.cursor++
		}
		return m, nil

	case tea.KeyHome, tea.KeyCtrlA:
		m.cursor = 0
		return m, nil

	case tea.KeyEnd, tea.KeyCtrlE:
		m.cursor = len(m.input)
		return m, nil

	case tea.KeyUp:
		m.historyBack()
		return m, nil

	case tea.KeyDown:
		m.historyForward()
		return m, nil

	case tea.KeyCtrlU:
		m.input = nil
		m.cursor = 0
		return m, nil

	case tea.KeyCtrlW:
		m.deleteWordBefore()
		return m, nil

	case tea.KeySpace:
		return m.insertRune(' ')

	case tea.KeyRunes:
		for _, r := range msg.Runes {
			m, _ = m.insertRune(r)
		}
		return m, nil
	}
	return m, nil
}

func (m shellModel) insertRune(r rune) (shellModel, tea.Cmd) {
	line := make([]rune, 0, len(m.input)+1)
	line = append(line, m.input[:m.cursor]...)
	line = append(line, r)
	line = append(line, m.input[m.cursor:]...)
	m.input = line
	m.cursor++
	return m, nil
}

func (m *shellModel) historyBack() {
	if len(m.history) == 0 || m.histPos == 0 {
		return
	}
	if m.histPos == len(m.history) {
		m.saved = append([]rune(nil), m.input...)
	}
	m.histPos--
	m.input = []rune(m.history[m.histPos])
	m.cursor = len(m.input)
}

func (m *shellModel) historyForward() {
	if m.histPos >= len(m.history) {
		return
	}
	m.histPos++
	if m.histPos == len(m.history) {
		m.input = m.saved
	} else {
		m.input = []rune(m.history[m.histPos])
	}
	m.cursor = len(m.input)
}

func (m *shellModel) deleteWordBefore() {
	i := m.cursor
	for i > 0 && m.input[i-1] == ' ' {
		i--
	}
	for i > 0 && m.input[i-1] != ' ' {
		i--
	}
	m.input = append(m.input[:i], m.input[m.cursor:]...)
	m.cursor = i
}

// completeCommandName completes an unambiguous prefix of the first word in
// place. An ambiguous or empty match is a no-op -- a safe default, since
// anything fancier (printing a match list) means reasoning about redrawing
// around an in-progress edit, not worth the risk for this.
func (m *shellModel) completeCommandName() {
	// Only the first word (the command name) completes.
	for i := 0; i < m.cursor; i++ {
		if m.input[i] == ' ' {
			return
		}
	}
	prefix := string(m.input[:m.cursor])
	if prefix == "" {
		return
	}

	var match string
	count := 0
	for _, n := range m.names {
		if strings.HasPrefix(n, prefix) {
			match = n
			count++
			if count > 1 {
				return
			}
		}
	}
	if count != 1 {
		return
	}

	rest := m.input[m.cursor:]
	newLine := []rune(match + " ")
	newLine = append(newLine, rest...)
	m.input = newLine
	m.cursor = len([]rune(match + " "))
}

// runLine parses the current line and dispatches it. Real commands always
// run as a subprocess of srt itself (never in-process): every command's
// flag.FlagSet uses flag.ExitOnError, so a bad flag -- or -h -- calls
// os.Exit, which in-process would kill this whole shell session instead of
// just that one command. tea.ExecProcess suspends the TUI for the
// subprocess's duration and hands it the real terminal, then resumes.
func (m shellModel) runLine() (tea.Model, tea.Cmd) {
	line := strings.TrimSpace(string(m.input))
	m.input = nil
	m.cursor = 0
	m.histPos = len(m.history)

	if line == "" {
		return m, nil
	}
	m.history = append(m.history, line)
	m.histPos = len(m.history)

	fields, err := shellSplitArgs(line)
	if err != nil {
		m.lastErr = err
		return m, nil
	}
	if len(fields) == 0 {
		return m, nil
	}
	cmdName, cmdArgs := fields[0], fields[1:]

	switch cmdName {
	case "exit", "quit":
		m.quitting = true
		return m, tea.Quit
	case "clear":
		return m, tea.ClearScreen
	case "color":
		m.applyColorCommand(cmdArgs)
		return m, nil
	case "help":
		if len(cmdArgs) > 0 {
			cmdName, cmdArgs = cmdArgs[0], []string{"-h"}
		}
	}

	if cmdName != "help" {
		if _, ok := registry[cmdName]; !ok {
			m.lastErr = fmt.Errorf("unknown command %q (type \"help\" to list commands)", cmdName)
			return m, nil
		}
	}

	c := exec.Command(m.self, append([]string{cmdName}, cmdArgs...)...)
	return m, tea.ExecProcess(c, func(err error) tea.Msg {
		return execDoneMsg{cmd: cmdName, err: err}
	})
}

// applyColorCommand handles the shell-local "color on|off|auto" toggle.
func (m *shellModel) applyColorCommand(args []string) {
	if len(args) == 0 {
		m.lastErr = errMissing(`usage: color on|off|auto`)
		return
	}
	switch args[0] {
	case "on":
		m.colorOn = true
	case "off":
		m.colorOn = false
	case "auto":
		m.colorOn = term.IsTerminal(int(os.Stdout.Fd()))
	default:
		m.lastErr = fmt.Errorf("color: unknown mode %q (want on, off, or auto)", args[0])
	}
}

// shellCommandNames lists every registered command plus the shell's own
// pseudo-commands, for completion and syntax highlighting.
func shellCommandNames() []string {
	names := make([]string, 0, len(registry)+5)
	for n := range registry {
		names = append(names, n)
	}
	names = append(names, "help", "exit", "quit", "clear", "color")
	sort.Strings(names)
	return names
}

// shellSplitArgs splits a line into argv the way a shell would for simple
// cases: whitespace-separated, with "..."/'...' spans kept as one argument
// (no escapes, no nesting) -- enough for a header "Name: Value" or a path
// with a space, without pulling in a full shell-parsing dependency.
func shellSplitArgs(line string) ([]string, error) {
	var args []string
	var cur strings.Builder
	var quote rune
	inArg := false

	flush := func() {
		if inArg {
			args = append(args, cur.String())
			cur.Reset()
			inArg = false
		}
	}

	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
			inArg = true
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
			inArg = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c quote", quote)
	}
	flush()
	return args, nil
}

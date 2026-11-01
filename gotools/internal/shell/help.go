package shell

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
)

// Dynamic help: the shell learns each command's flags by running
// `srt <cmd> -h` once (a subprocess, for the same os.Exit reason every other
// command runs as one) and parsing Go's flag usage output. That gives an
// inline one-line hint while typing a flag, and the full text for a right-hand
// pane opened by `help <cmd>`.

type flagDoc struct {
	Name string // without the leading dashes
	Arg  string // "string", "int", "value" ... empty for a boolean flag
	Desc string
}

type cmdHelp struct {
	text  string // raw usage text
	flags []flagDoc
}

type helpLoadedMsg struct {
	name string
	help *cmdHelp
}

// helpPaneKey is the cache key for bare `help` (the command listing).
const helpPaneKey = ""

// shellHelp documents the shell's own pseudo-commands, which have no
// subprocess to ask.
var shellHelp = map[string]string{
	"help":     "help [command]\n\nWith a command, open its flag reference in a pane beside the prompt (Esc closes it).\nWithout one, list every command.",
	"exit":     "exit\n\nLeave the shell (also quit, or Ctrl+D on an empty line).",
	"quit":     "quit\n\nLeave the shell (same as exit).",
	"clear":    "clear\n\nClear the screen and redraw the banner.",
	"color":    "color on|off|auto\n\nToggle syntax highlighting and colored UI.",
	"cd":       "cd [<dir>|-]\n\nSwitch project directory; `cd -` returns to the previous one.",
	"project":  "project [<dir>|-]\n\nShow the current project, or switch to another (same as cd).",
	"traffic":  "traffic\n\nShow the total request/byte traffic of this session.",
	"limit":    "limit [rate <req/s>|off | bytes <size> | off]\n\nrate   throttle every command to N requests per second\nbytes  halt a command once it has moved this much traffic (e.g. 50MB)\noff    lift the limits",
	"sessions": "sessions\n\nList interrupted, resumable commands.",
	"resume":   "resume [<id>]\n\nContinue an interrupted command from where it stopped.",
	"save":     "save [on|off]\n\nWhether each command's results are recorded in the project database.",
}

// isFlagLine reports whether line is an indented "-name ..." flag header, in
// either flag.PrintDefaults or cli.PrintGroupedUsage layout.
func isFlagLine(line string) bool {
	t := strings.TrimLeft(line, " ")
	return len(t) > 1 && len(t) < len(line) && t[0] == '-' && t[1] != ' ' && t[1] != '\t'
}

// parseFlagUsage extracts flags from Go's flag.PrintDefaults output
// (cli.PrintGroupedUsage's "-name type  description" rows work too):
//
//	-name type
//	  \tusage text
//
// (single-letter booleans put the usage on the header line after a tab).
func parseFlagUsage(text string) []flagDoc {
	var flags []flagDoc
	cur := -1
	for _, line := range strings.Split(text, "\n") {
		switch {
		case isFlagLine(line):
			header, inline := strings.TrimLeft(line, " "), ""
			if i := strings.Index(header, "\t"); i >= 0 {
				header, inline = header[:i], strings.TrimSpace(header[i+1:])
			} else if i := strings.Index(header, "  "); i >= 0 {
				// cli.PrintGroupedUsage: "-name type<2+ spaces>description".
				header, inline = header[:i], strings.TrimSpace(header[i:])
			}
			parts := strings.Fields(header)
			if len(parts) == 0 {
				cur = -1
				continue
			}
			flags = append(flags, flagDoc{
				Name: strings.TrimLeft(parts[0], "-"),
				Arg:  strings.Join(parts[1:], " "),
				Desc: inline,
			})
			cur = len(flags) - 1
		case cur >= 0 && (strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t")):
			d := strings.TrimSpace(line)
			if flags[cur].Desc != "" {
				d = flags[cur].Desc + " " + d
			}
			flags[cur].Desc = d
		default:
			cur = -1
		}
	}
	return flags
}

// loadHelp fetches a command's usage text in the background.
func loadHelp(self, name string) tea.Cmd {
	return func() tea.Msg {
		if text, ok := shellHelp[name]; ok {
			return helpLoadedMsg{name, &cmdHelp{text: text}}
		}
		args := []string{name, "-h"}
		if name == helpPaneKey {
			args = []string{"help"}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, _ := exec.CommandContext(ctx, self, args...).CombinedOutput() // -h exits non-zero by design
		text := strings.TrimRight(string(out), "\n")
		return helpLoadedMsg{name, &cmdHelp{text: text, flags: parseFlagUsage(text)}}
	}
}

// ensureHelp starts loading name's help if it is neither cached nor in flight.
func (m *shellModel) ensureHelp(name string) tea.Cmd {
	if m.helpCache == nil {
		m.helpCache = map[string]*cmdHelp{}
	}
	if _, ok := m.helpCache[name]; ok {
		return nil
	}
	m.helpCache[name] = nil // in flight
	return loadHelp(m.self, name)
}

// ensureHint preloads help for the command whose arguments are being typed.
func (m *shellModel) ensureHint() tea.Cmd {
	toks := tokenizeLineWithSpans(m.input)
	if len(toks) == 0 || m.cursor <= toks[0].end || toks[0].text == "shell" {
		return nil
	}
	if _, ok := cli.Lookup(toks[0].text); !ok {
		return nil
	}
	return m.ensureHelp(toks[0].text)
}

// openHelp shows name's help in the side pane.
func (m *shellModel) openHelp(name string) tea.Cmd {
	if _, ok := cli.Lookup(name); !ok && name != helpPaneKey {
		if _, ok := shellHelp[name]; !ok {
			m.lastErr = fmt.Errorf("unknown command %q (type \"help\" to list commands)", name)
			return nil
		}
	}
	m.helpOpen, m.helpName, m.helpScroll = true, name, 0
	return m.ensureHelp(name)
}

func (m *shellModel) closeHelp() tea.Cmd {
	m.helpOpen = false
	return nil
}

// --- inline flag hint ---

const maxHintLines = 5

// flagHint returns the lines to show under the input box: the description of
// the flag being typed (or of the flag whose value is being typed).
func (m shellModel) flagHint() []string {
	toks := tokenizeLineWithSpans(m.input)
	if len(toks) < 2 || m.cursor <= toks[0].end {
		return nil
	}
	h := m.helpCache[toks[0].text]
	if h == nil || len(h.flags) == 0 {
		return nil
	}

	// Which token is the cursor in? idx == len(toks) means a fresh empty one.
	idx, cur := len(toks), ""
	for i := 1; i < len(toks); i++ {
		if m.cursor > toks[i].start && m.cursor <= toks[i].end {
			idx, cur = i, string(m.input[toks[i].start:m.cursor])
			break
		}
	}

	byName := func(n string) *flagDoc {
		for i := range h.flags {
			if h.flags[i].Name == n {
				return &h.flags[i]
			}
		}
		return nil
	}

	if strings.HasPrefix(cur, "-") {
		name := strings.TrimLeft(cur, "-")
		if eq := strings.Index(name, "="); eq >= 0 {
			if f := byName(name[:eq]); f != nil {
				return m.hintLines([]flagDoc{*f})
			}
			return nil
		}
		var matches []flagDoc
		for _, f := range h.flags {
			if strings.HasPrefix(f.Name, name) {
				matches = append(matches, f)
			}
		}
		sort.SliceStable(matches, func(i, j int) bool {
			return matches[i].Name == name && matches[j].Name != name
		})
		return m.hintLines(matches)
	}

	// A value is being typed: remind what the preceding flag wants.
	if idx >= 2 {
		prev := toks[idx-1].text
		if strings.HasPrefix(prev, "-") && !strings.Contains(prev, "=") {
			if f := byName(strings.TrimLeft(prev, "-")); f != nil && f.Arg != "" {
				return m.hintLines([]flagDoc{*f})
			}
		}
	}
	return nil
}

func (m shellModel) hintLines(fs []flagDoc) []string {
	if len(fs) == 0 {
		return nil
	}
	w := m.mainWidth() - 4
	flagStyle := lipgloss.NewStyle().Bold(true)
	if m.colorOn {
		flagStyle = flagStyle.Foreground(lipgloss.Color(colorYellow))
	}
	one := lipgloss.NewStyle().MaxWidth(w)

	line := func(f flagDoc, full bool) []string {
		head := "-" + f.Name
		if f.Arg != "" {
			head += " " + f.Arg
		}
		pad := lipgloss.Width(head) + 4
		if !full {
			return []string{one.Render("  " + flagStyle.Render(head) + "  " + dimStyle(m.colorOn).Render(f.Desc))}
		}
		wrapped := strings.Split(lipgloss.NewStyle().Width(max(w-pad, 10)).Render(strings.TrimSpace(f.Desc)), "\n")
		out := []string{"  " + flagStyle.Render(head) + "  " + dimStyle(m.colorOn).Render(strings.TrimRight(wrapped[0], " "))}
		for _, l := range wrapped[1:] {
			out = append(out, strings.Repeat(" ", pad)+dimStyle(m.colorOn).Render(strings.TrimRight(l, " ")))
		}
		return out
	}

	// A single match (exact or the only candidate) gets its whole description.
	if len(fs) == 1 {
		out := line(fs[0], true)
		if len(out) > maxHintLines {
			out = out[:maxHintLines]
		}
		return out
	}
	var out []string
	for i, f := range fs {
		if i == maxHintLines-1 && len(fs) > maxHintLines {
			out = append(out, dimStyle(m.colorOn).Render(fmt.Sprintf("  … %d more", len(fs)-i)))
			break
		}
		out = append(out, line(f, false)...)
	}
	return out
}

// --- side pane ---

// mainWidth is the width of the prompt column: the whole terminal, or the
// left share of it while the help pane is open.
func (m shellModel) mainWidth() int {
	if !m.helpOpen {
		return m.width
	}
	return max(m.width*45/100, 36)
}

func (m shellModel) paneWidth() int { return max(m.width-m.mainWidth()-1, 20) }

func (m shellModel) paneHeight() int {
	h := m.height
	if h == 0 {
		h = 24
	}
	return max(h, 8)
}

// helpLines is the pane's text wrapped to its inner width, flag headers
// highlighted.
func (m shellModel) helpLines() []string {
	h, loaded := m.helpCache[m.helpName]
	if h == nil {
		if loaded {
			return []string{"loading…"}
		}
		return []string{"(no help)"}
	}
	w := m.paneWidth() - 4
	flag := lipgloss.NewStyle()
	if m.colorOn {
		flag = flag.Foreground(lipgloss.Color(colorYellow))
	}
	var out []string
	for _, raw := range strings.Split(h.text, "\n") {
		isFlag := isFlagLine(raw)
		// Go indents usage text with spaces+tab; render that as a plain indent
		// and keep it on wrapped continuation lines.
		body := strings.TrimLeft(raw, " \t")
		indent := strings.Repeat(" ", len(raw)-len(body))
		if strings.HasPrefix(raw, "    \t") || strings.HasPrefix(raw, "\t") {
			indent = "      "
		}
		wrapped := strings.Split(lipgloss.NewStyle().Width(max(w-len(indent), 8)).Render(body), "\n")
		for i, l := range wrapped {
			l = indent + strings.TrimRight(l, " ")
			if i == 0 && isFlag {
				l = flag.Render(l)
			}
			out = append(out, l)
		}
	}
	return out
}

func (m shellModel) bodyHeight() int { return m.paneHeight() - 3 } // border (2) + title

func (m *shellModel) scrollHelp(delta int) {
	maxScroll := max(len(m.helpLines())-m.bodyHeight(), 0)
	m.helpScroll = min(max(m.helpScroll+delta, 0), maxScroll)
}

func (m shellModel) renderHelpPane() string {
	lines := m.helpLines()
	body := m.bodyHeight()
	scroll := min(max(m.helpScroll, 0), max(len(lines)-body, 0))
	end := min(scroll+body, len(lines))
	visible := append([]string(nil), lines[scroll:end]...)
	for len(visible) < body {
		visible = append(visible, "")
	}

	name := m.helpName
	if name == helpPaneKey {
		name = "commands"
	}
	pct := 100
	if len(lines) > body {
		pct = scroll * 100 / (len(lines) - body)
	}
	title := lipgloss.NewStyle().Bold(true).Render("help: "+name) +
		dimStyle(m.colorOn).Render(fmt.Sprintf("  Esc close · PgUp/PgDn scroll · %d%%", pct))

	box := lipgloss.NewStyle().Padding(0, 1).Width(m.paneWidth() - 2).MaxWidth(m.paneWidth())
	if m.colorOn {
		box = box.Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color(colorCyan))
	} else {
		box = box.Border(lipgloss.NormalBorder())
	}
	return box.Render(lipgloss.NewStyle().MaxWidth(m.paneWidth()-4).Render(title) + "\n" + strings.Join(visible, "\n"))
}

package shell

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/trike33/srt-cheatsheet/gotools/internal/scope"
	"github.com/trike33/srt-cheatsheet/gotools/internal/version"
)

// Palette taken from the project's animated glyph gradient
// (srt-animated-glyph.svg: #A78BFA -> #818CF8 -> #67E8F9).
const (
	colorPurple = "#A78BFA"
	colorIndigo = "#818CF8"
	colorCyan   = "#67E8F9"
	colorGray   = "243"
	colorRed    = "203"
	colorYellow = "221"
	colorGreen  = "114"
)

// renderHeader builds the live header: a small block-art mark in the glyph's
// own gradient with version/build/cwd, beside a project box (project, the
// scope files auto-detection recognized, and the session traffic). It is part
// of the redrawn view, so the traffic numbers stay current.
func (m shellModel) renderHeader() string {
	glyph := []string{
		"  ▄███▄  ",
		" ███████ ",
		" ███████ ",
		"  ▀███▀  ",
	}
	glyphColors := []string{colorPurple, colorIndigo, colorIndigo, colorCyan}
	glyphLines := make([]string, len(glyph))
	for i, row := range glyph {
		glyphLines[i] = lipgloss.NewStyle().Foreground(lipgloss.Color(glyphColors[i])).Render(row)
	}
	glyphBlock := strings.Join(glyphLines, "\n")

	info := lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.NewStyle().Bold(true).Render("srt "+versionLine()),
		lipgloss.NewStyle().Foreground(lipgloss.Color(colorGray)).Render(buildLine()),
		lipgloss.NewStyle().Foreground(lipgloss.Color(colorGray)).Render(cwdLine()),
	)

	row := lipgloss.JoinHorizontal(lipgloss.Center, glyphBlock, "  ", info)

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(colorIndigo)).
		Padding(0, 2)
	left := box.Render(row)

	// The project box takes the rest of the row; on a narrow terminal it
	// drops below the version box instead.
	avail := m.width - lipgloss.Width(left) - 1
	if avail < 50 {
		return lipgloss.JoinVertical(lipgloss.Left, left, box.Width(max(m.width-2, 20)).Render(m.renderProjectBox()))
	}
	return lipgloss.JoinHorizontal(lipgloss.Center, left, " ", box.Width(avail-2).Render(m.renderProjectBox()))
}

// renderProjectBox is the header's second box: the current project, which
// scope files auto-detection recognized in it (the same detection `pipeline`
// uses when given no explicit scope), and the permanent traffic summary.
func (m shellModel) renderProjectBox() string {
	wd, _ := os.Getwd()
	host, web := scope.DetectScopeFiles(wd)
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color(colorGray))
	found := func(label, path string) string {
		if path == "" {
			return dim.Render(label + " (none detected)")
		}
		return dim.Render(label+" ") + lipgloss.NewStyle().Foreground(lipgloss.Color(colorGreen)).Render(filepath.Base(path))
	}
	return lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(colorPurple)).Render("project: "+projectName(wd)),
		found("host scope:", host),
		found("web scope: ", web),
		dim.Render(m.renderTraffic()),
	)
}

// versionLine mirrors the version package's own format, so the banner and
// `srt version` never disagree.
func versionLine() string {
	return version.Display()
}

func buildLine() string {
	return fmt.Sprintf("%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func cwdLine() string {
	wd, err := os.Getwd()
	if err != nil {
		return "?"
	}
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(wd, home) {
		wd = "~" + strings.TrimPrefix(wd, home)
	}
	return wd
}

// --- live input line: tokenize + classify + render with a cursor overlay ---

type tokClass int

const (
	classPlain tokClass = iota
	classCommand
	classUnknown
	classFlag
	classString
)

type lineToken struct {
	start, end int // rune indices [start, end) in the line
	text       string
}

// tokenizeLineWithSpans is a quick word/quote scanner for live highlighting
// as the user types -- not the same parser runLine uses to actually dispatch
// (shellSplitArgs); this one just needs each token's position in the line,
// and tolerates an unterminated quote gracefully instead of erroring, since
// the user may still be mid-way through typing one.
func tokenizeLineWithSpans(line []rune) []lineToken {
	var toks []lineToken
	i := 0
	for i < len(line) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			break
		}
		start := i
		if line[i] == '"' || line[i] == '\'' {
			q := line[i]
			i++
			for i < len(line) && line[i] != q {
				i++
			}
			if i < len(line) {
				i++ // consume the closing quote
			}
		} else {
			for i < len(line) && line[i] != ' ' && line[i] != '\t' {
				i++
			}
		}
		toks = append(toks, lineToken{start: start, end: i, text: string(line[start:i])})
	}
	return toks
}

// renderHighlightedLine classifies each token (command name, flag, quoted
// string, plain) and renders the line rune by rune so the cursor can be
// overlaid on the exact rune it's on, without having to split an
// already-ANSI-styled string back apart.
func (m shellModel) renderHighlightedLine() string {
	runes := m.input
	classes := make([]tokClass, len(runes))

	toks := tokenizeLineWithSpans(runes)
	for i, tok := range toks {
		c := classPlain
		switch {
		case i == 0:
			if commandKnown(m.names, tok.text) {
				c = classCommand
			} else {
				c = classUnknown
			}
		default:
			c = m.argClass(toks, i)
		}
		for j := tok.start; j < tok.end; j++ {
			classes[j] = c
		}
	}

	var b strings.Builder
	for i, r := range runes {
		s := classStyle(classes[i], m.colorOn)
		if i == m.cursor {
			s = cursorStyle()
		}
		b.WriteString(s.Render(string(r)))
	}
	if m.cursor == len(runes) {
		b.WriteString(cursorStyle().Render(" "))
	}
	return b.String()
}

func commandKnown(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// --- styles ---

func classStyle(c tokClass, colorOn bool) lipgloss.Style {
	s := lipgloss.NewStyle()
	if !colorOn {
		return s
	}
	switch c {
	case classCommand:
		return s.Foreground(lipgloss.Color(colorCyan)).Bold(true)
	case classUnknown:
		return s.Foreground(lipgloss.Color(colorRed))
	case classFlag:
		return s.Foreground(lipgloss.Color(colorYellow))
	case classString:
		return s.Foreground(lipgloss.Color(colorGreen))
	default:
		return s
	}
}

// cursorStyle (reverse video) is a terminal attribute, not a color, so the
// cursor stays visible even with "color off" -- without it there'd be no
// indicator of cursor position at all.
func cursorStyle() lipgloss.Style {
	return lipgloss.NewStyle().Reverse(true)
}

func promptStyle(colorOn bool) lipgloss.Style {
	s := lipgloss.NewStyle().Bold(true)
	if colorOn {
		s = s.Foreground(lipgloss.Color(colorPurple))
	}
	return s
}

func inputBoxStyle(colorOn bool, width int) lipgloss.Style {
	s := lipgloss.NewStyle().Padding(0, 1).Width(width)
	if colorOn {
		return s.Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color(colorIndigo))
	}
	return s.Border(lipgloss.NormalBorder())
}

func dimStyle(colorOn bool) lipgloss.Style {
	s := lipgloss.NewStyle()
	if colorOn {
		s = s.Foreground(lipgloss.Color(colorGray))
	}
	return s
}

// --- top-level View ---

func (m shellModel) View() string {
	if m.quitting {
		return ""
	}

	prompt := promptStyle(m.colorOn).Render("srt> ")
	highlighted := m.renderHighlightedLine()

	boxWidth := m.mainWidth() - 4
	if boxWidth < 20 {
		boxWidth = 20
	}
	inputBox := inputBoxStyle(m.colorOn, boxWidth).Render(prompt + highlighted)

	main := inputBox + "\n"
	if hint := m.flagHint(); len(hint) > 0 {
		main += strings.Join(hint, "\n") + "\n"
	}
	main += m.renderStatus()

	if !m.helpOpen {
		return m.renderHeader() + "\n" + main
	}
	return lipgloss.JoinHorizontal(lipgloss.Bottom, main, " ", m.renderHelpPane())
}

// renderTraffic is the header's traffic summary: the session total
// (every command run so far) and the last command's own numbers, always
// visible -- unlike the status line's notice, this never clears on the next
// keystroke, so you don't have to catch it before you start typing again.
func (m shellModel) renderTraffic() string {
	rate := "unlimited"
	if m.rate > 0 {
		rate = fmt.Sprintf("%g req/s", m.rate)
	}
	save := "off"
	if m.save {
		save = "on"
	}
	session := fmt.Sprintf("session: %s · rate %s · save %s", m.traffic.String(), rate, save)
	last := m.lastRun
	if last == "" {
		last = "last: (no command run yet)"
	}
	return session + "\n" + last
}

func (m shellModel) renderStatus() string {
	colorState := "off"
	if m.colorOn {
		colorState = "on"
	}
	left := fmt.Sprintf("color: %s · history: %d", colorState, len(m.history))
	if m.notice != "" {
		left = m.notice
	}
	if m.lastErr != nil {
		left = classStyle(classUnknown, m.colorOn).Render("! " + m.lastErr.Error())
	}
	right := `"help" for commands · "exit" or Ctrl+D to quit`
	if m.helpOpen {
		right = "" // the pane's own title says how to close it
	}

	w := m.mainWidth()
	gap := w - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		gap = 1
	}
	return dimStyle(m.colorOn).MaxWidth(w).Render(left + strings.Repeat(" ", gap) + right)
}

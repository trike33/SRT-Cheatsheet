package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/charmbracelet/lipgloss"
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

// renderBanner builds the once-only startup banner: a small block-art mark
// in the glyph's own gradient, plus version/build/cwd, in a bordered box.
// Printed directly (not through the Bubble Tea program), so it's ordinary
// scrollback, not part of the view that redraws on every keystroke below it.
func renderBanner() string {
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

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(colorIndigo)).
		Padding(0, 2).
		Render(row)
}

// versionLine mirrors cmd_version.go's own format, so the banner and
// `srt version` never disagree.
func versionLine() string {
	vcs := ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		var rev, dirty string
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if len(s.Value) >= 12 {
					rev = s.Value[:12]
				} else {
					rev = s.Value
				}
			case "vcs.modified":
				if s.Value == "true" {
					dirty = "-dirty"
				}
			}
		}
		if rev != "" {
			vcs = " (" + rev + dirty + ")"
		}
	}
	return version + vcs
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

	for i, tok := range tokenizeLineWithSpans(runes) {
		c := classPlain
		switch {
		case i == 0:
			if commandKnown(m.names, tok.text) {
				c = classCommand
			} else {
				c = classUnknown
			}
		case strings.HasPrefix(tok.text, "-"):
			c = classFlag
		case strings.HasPrefix(tok.text, `"`) || strings.HasPrefix(tok.text, "'"):
			c = classString
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

	boxWidth := m.width - 4
	if boxWidth < 20 {
		boxWidth = 20
	}
	inputBox := inputBoxStyle(m.colorOn, boxWidth).Render(prompt + highlighted)

	return inputBox + "\n" + m.renderStatus()
}

func (m shellModel) renderStatus() string {
	colorState := "off"
	if m.colorOn {
		colorState = "on"
	}
	wd, _ := os.Getwd()
	left := fmt.Sprintf("project: %s · color: %s · history: %d", projectName(wd), colorState, len(m.history))
	if m.notice != "" {
		left = m.notice
	}
	if m.lastErr != nil {
		left = classStyle(classUnknown, m.colorOn).Render("! " + m.lastErr.Error())
	}
	right := `"help" for commands · "exit" or Ctrl+D to quit`

	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		gap = 1
	}
	return dimStyle(m.colorOn).Render(left + strings.Repeat(" ", gap) + right)
}

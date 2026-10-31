// Package colorout holds the handful of terminal-presentation primitives
// shared by commands that colorize or animate their output: an ANSI palette,
// a --color auto|always|never mode, and a liveness spinner.
package colorout

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// ANSI colors used by the robots and burpscope commands.
const (
	Reset  = "\033[0m"
	Red    = "\033[91m"
	Green  = "\033[92m"
	Yellow = "\033[93m"
	Cyan   = "\033[36m"
)

// Mode decides whether to emit ANSI escapes.
type Mode int

const (
	Auto Mode = iota
	Always
	Never
)

// ParseMode parses a -color flag value ("always", "never", anything else ->
// Auto).
func ParseMode(s string) Mode {
	switch s {
	case "always":
		return Always
	case "never":
		return Never
	default:
		return Auto
	}
}

// Enabled reports whether color should be written. In Auto mode, color is
// only written when stdout is a terminal, so redirected/piped output stays
// clean.
func (m Mode) Enabled() bool {
	switch m {
	case Always:
		return true
	case Never:
		return false
	default:
		return IsTerminal(os.Stdout)
	}
}

// Wrap colorizes s with code when enabled, else returns it unchanged.
func (m Mode) Wrap(code, s string) string {
	if !m.Enabled() {
		return s
	}
	return code + s + Reset
}

// Frames animates a live-progress glyph, the same braille cycle Claude's own
// CLI spinner uses: a tick every 500ms proves the process is still alive
// even on a quiet run where the counters next to it don't move.
var Frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner returns the frame for tick n, cycling through Frames.
func Spinner(n int) string {
	return Frames[n%len(Frames)]
}

// IsTerminal is a dependency-free TTY check: it uses the file mode, which is
// enough to tell a pipe/file from a character device on Linux.
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// TermWidth returns f's terminal width in columns, or 0 if f isn't a
// terminal or its size can't be determined.
func TermWidth(f *os.File) int {
	if !IsTerminal(f) {
		return 0
	}
	w, _, err := term.GetSize(int(f.Fd()))
	if err != nil || w <= 0 {
		return 0
	}
	return w
}

// Overwrite prints s to f as a single self-updating line: a leading \r
// returns the cursor to the start of the line and a trailing "erase to end
// of line" wipes anything left over from a longer previous tick -- the
// standard trick behind every live progress counter in srt (fuzz's,
// portscan's, the heartbeat, the shell's per-command traffic line).
//
// The part that trick depends on, and that's easy to get wrong: s must
// never wrap to a second terminal row, or \r only returns to the start of
// that *last* row, not back to the top of the previous print, and every
// earlier wrapped row is left stuck on screen as new ticks pile up below it
// instead of replacing it. So Overwrite truncates s to f's width first,
// using TermWidth, which makes wrapping impossible by construction.
//
// When f isn't a terminal (redirected to a file/pipe) -- or its width can't
// be read -- there is no line to overwrite, so s is left untouched and
// printed as an ordinary newline-terminated line instead: redirected output
// stays one entry per tick, which is what you want in a log file.
func Overwrite(f *os.File, s string) {
	width := TermWidth(f)
	if width <= 0 {
		fmt.Fprintln(f, s)
		return
	}
	if r := []rune(s); len(r) > width-1 {
		s = string(r[:width-1])
	}
	fmt.Fprintf(f, "\r\033[K%s", s)
}

// ClearLine erases the current line in place, for the moment a live counter
// is done updating and should leave the terminal clean (e.g. right before
// printing a final summary on that same row). A no-op when f isn't a
// terminal, since there's no line to erase.
func ClearLine(f *os.File) {
	if TermWidth(f) > 0 {
		fmt.Fprint(f, "\r\033[K")
	}
}

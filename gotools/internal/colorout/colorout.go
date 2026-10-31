// Package colorout holds the handful of terminal-presentation primitives
// shared by commands that colorize or animate their output: an ANSI palette,
// a --color auto|always|never mode, and a liveness spinner.
package colorout

import "os"

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

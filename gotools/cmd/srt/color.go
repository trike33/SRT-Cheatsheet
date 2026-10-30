package main

import "os"

// ANSI colors used by the robots and burpscope commands.
const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[91m"
	ansiGreen  = "\033[92m"
	ansiYellow = "\033[93m"
	ansiCyan   = "\033[36m"
)

// colorMode decides whether to emit ANSI escapes.
type colorMode int

const (
	colorAuto colorMode = iota
	colorAlways
	colorNever
)

func parseColorMode(s string) colorMode {
	switch s {
	case "always":
		return colorAlways
	case "never":
		return colorNever
	default:
		return colorAuto
	}
}

// enabled reports whether color should be written. In auto mode we only
// colorize when stdout is a terminal, so redirected/piped output stays clean.
func (m colorMode) enabled() bool {
	switch m {
	case colorAlways:
		return true
	case colorNever:
		return false
	default:
		return isTerminal(os.Stdout)
	}
}

func (m colorMode) wrap(code, s string) string {
	if !m.enabled() {
		return s
	}
	return code + s + ansiReset
}

// spinnerFrames animates a live-progress glyph, the same braille cycle
// Claude's own CLI spinner uses: a tick every 500ms proves the process is
// still alive even on a quiet run where the counters next to it don't move.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// spinner returns the frame for tick n, cycling through spinnerFrames.
func spinner(n int) string {
	return spinnerFrames[n%len(spinnerFrames)]
}

// isTerminal is a dependency-free TTY check: it uses the file mode, which is
// enough to tell a pipe/file from a character device on Linux.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

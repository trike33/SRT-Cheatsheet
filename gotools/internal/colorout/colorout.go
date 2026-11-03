// Package colorout holds the handful of terminal-presentation primitives
// shared by commands that colorize or animate their output: an ANSI palette,
// a --color auto|always|never mode, and a liveness spinner.
package colorout

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// ANSI colors used by the robots and burpscope commands, and by any other
// command's hand-built, column-aligned table (see PadWrap: it pads a cell to
// its column width *before* adding a color's escape bytes, so a table never
// has to care how long any given color code is, or whether every cell in a
// column is colored the same way).
const (
	Reset   = "\033[0m"
	Red     = "\033[91m"
	Green   = "\033[92m"
	Yellow  = "\033[93m"
	Blue    = "\033[94m"
	Magenta = "\033[95m"
	Cyan    = "\033[36m"
	Gray    = "\033[90m"
)

// Palette is a small set of visually distinct colors for tagging an
// arbitrary category string (e.g. results' "kind" column) consistently,
// without hand-maintaining a fixed mapping for every value that might show
// up. See PaletteColor.
var Palette = []string{Cyan, Magenta, Blue, Yellow, Green}

// PaletteColor deterministically maps s to one of Palette's colors: the same
// s always gets the same color (in this run and the next), and different
// values are spread across the palette so a table with several different
// kinds/categories in one column reads as visually grouped at a glance.
func PaletteColor(s string) string {
	var h uint32
	for i := 0; i < len(s); i++ {
		h = h*31 + uint32(s[i])
	}
	return Palette[h%uint32(len(Palette))]
}

// StatusColor returns the color an HTTP status code should be shown in,
// loosely matching the convention curl/httpx-style tools already use: 2xx
// green (success), 3xx cyan (redirect), 4xx yellow (client error), 5xx red
// (server error). Anything else (0, or an out-of-range code) returns "" --
// Wrap and PadWrap both treat an empty code as "leave it uncolored".
func StatusColor(status int) string {
	switch {
	case status >= 200 && status < 300:
		return Green
	case status >= 300 && status < 400:
		return Cyan
	case status >= 400 && status < 500:
		return Yellow
	case status >= 500 && status < 600:
		return Red
	default:
		return ""
	}
}

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

// Wrap colorizes s with code when enabled, else returns it unchanged. An
// empty code is always left unwrapped, color enabled or not.
func (m Mode) Wrap(code, s string) string {
	if code == "" || !m.Enabled() {
		return s
	}
	return code + s + Reset
}

// PadWrap left-pads/truncates s to width (plain, uncolored -- just like
// fmt.Sprintf("%-*s", width, s)) and *then* wraps the padded result in code.
// Padding before coloring, rather than after, is what matters here: it's
// what a hand-built table (or any fixed-width column) needs to stay aligned
// once some of its cells are colored and others aren't -- pad first so the
// visible width is already correct, then color never has to touch the
// column math again.
func (m Mode) PadWrap(code, s string, width int) string {
	padded := s
	if w := len([]rune(s)); w < width {
		padded = s + strings.Repeat(" ", width-w)
	}
	return m.Wrap(code, padded)
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

// EnvProgressMark is set to "1" by the interactive shell on the commands it
// runs. Their output is a pipe, so Overwrite can't use \r tricks, but the
// shell wants live counters to replace themselves in its output pane instead
// of piling up one line per tick. With it set, a live line off a terminal is
// terminated with ProgressMark instead of a newline ("this line is transient,
// the next one replaces it"), and ClearLine sends a bare ProgressMark ("drop
// the transient line"). The shell's output reader is the only consumer.
const EnvProgressMark = "SRT_PROGRESS_MARK"

// ProgressMark (ASCII record separator) ends a transient progress line.
const ProgressMark = '\x1e'

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
		if os.Getenv(EnvProgressMark) == "1" {
			fmt.Fprintf(f, "%s%c", s, ProgressMark)
			return
		}
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
		return
	}
	if os.Getenv(EnvProgressMark) == "1" {
		fmt.Fprintf(f, "%c", ProgressMark)
	}
}

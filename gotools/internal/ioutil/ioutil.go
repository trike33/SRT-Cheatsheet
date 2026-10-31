// Package ioutil holds the small, generic plumbing every srt command is
// built on: reading a list from a file or stdin, writing to a file or
// stdout, a stderr-only warning logger (so stdout stays clean for piping),
// a "still running" heartbeat for commands with no richer progress output,
// and the couple of one-line helpers (a required-flag error, a timeout
// context) that would otherwise be copy-pasted into every command.
package ioutil

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
)

// InputLines reads non-empty, whitespace-trimmed lines from path. If path is
// "" or "-", it reads from stdin. This is what makes every command accept a
// pipe as well as a file.
func InputLines(path string) ([]string, error) {
	var r io.Reader
	if path == "" || path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	var lines []string
	sc := bufio.NewScanner(r)
	// Recon lists can carry very long URLs; give the scanner room.
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

// ReadAll reads the full contents of path (or stdin when path is "" or "-").
func ReadAll(path string) (string, error) {
	if path == "" || path == "-" {
		b, err := io.ReadAll(os.Stdin)
		return string(b), err
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

// nopWriteCloser lets Output return os.Stdout without closing it.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// Output returns a writer for path, or stdout when path is "" or "-". The
// caller must Close it (closing stdout is a no-op).
func Output(path string) (io.WriteCloser, error) {
	if path == "" || path == "-" {
		return nopWriteCloser{os.Stdout}, nil
	}
	return os.Create(path)
}

// WriteLines writes each line followed by a newline.
func WriteLines(w io.Writer, lines []string) error {
	bw := bufio.NewWriter(w)
	for _, l := range lines {
		if _, err := bw.WriteString(l); err != nil {
			return err
		}
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// Stdout returns os.Stdout as an io.Writer, for the handful of commands that
// print sections directly rather than through Output().
func Stdout() io.Writer { return os.Stdout }

// Warn prints a formatted message to stderr so stdout stays clean for piping.
func Warn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", a...)
}

// HeartbeatInterval is how often StartHeartbeat reassures the user a command
// is still working. Chosen so a fast command (the overwhelming majority of
// runs) never prints one at all.
const HeartbeatInterval = 5 * time.Second

// StartHeartbeat starts logging a "still running" line to stderr every
// HeartbeatInterval. This is the generic "didn't hang" signal for commands
// without their own richer progress output; call the returned stop function
// (defer it right after calling this) once the work finishes. Commands with
// their own live progress ticker (fuzz, portscan) don't need this -- they
// already report liveness in more detail.
func StartHeartbeat(label string) (stop func()) {
	return StartHeartbeatEvery(label, HeartbeatInterval)
}

// StartHeartbeatEvery is StartHeartbeat with an explicit interval, split out
// so tests don't have to wait out the real HeartbeatInterval. On a terminal
// it overwrites the same line in place every tick (colorout.Overwrite), so a
// long quiet command leaves one line ticking rather than a scroll of
// identical "still running" lines; stop() clears that line so whatever
// prints next (the command's real result) starts clean. Redirected to a
// file or pipe, each tick is its own newline-terminated line instead, same
// as a plain Warn call, so a backgrounded run's log still shows every tick.
// stop blocks until the background goroutine has actually exited, so a
// caller that reassigns os.Stderr right after stopping (as a test capturing
// it would) can't race the last tick's write.
func StartHeartbeatEvery(label string, interval time.Duration) (stop func()) {
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		start := time.Now()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				colorout.Overwrite(os.Stderr, fmt.Sprintf("[!] %s: still running (%s elapsed)...", label, time.Since(start).Round(time.Second)))
			}
		}
	}()
	return func() {
		close(done)
		<-exited
		colorout.ClearLine(os.Stderr)
	}
}

// ResolveInput returns the input path, preferring an explicit -l flag, then a
// single positional argument, otherwise "" (meaning stdin).
func ResolveInput(flagValue string, positional []string) string {
	if flagValue != "" {
		return flagValue
	}
	if len(positional) > 0 {
		return positional[0]
	}
	return ""
}

// ---- numeric range sets (for fuzz's -mc/-fc/-ms/-fs/-mw/-fw/-ml/-fl, and
// portscan's -p) ----

// RangeSet is a parsed set of numbers and ranges, tested with Contains.
type RangeSet struct {
	all    bool
	ranges [][2]int
}

// ParseRangeSet parses "200-299,301,302" or "all" into a RangeSet.
func ParseRangeSet(s string) (RangeSet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return RangeSet{}, nil
	}
	if s == "all" || s == "*" {
		return RangeSet{all: true}, nil
	}
	var rs RangeSet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil {
				return rs, fmt.Errorf("invalid range %q", part)
			}
			rs.ranges = append(rs.ranges, [2]int{a, b})
		} else {
			n, err := strconv.Atoi(part)
			if err != nil {
				return rs, fmt.Errorf("invalid number %q", part)
			}
			rs.ranges = append(rs.ranges, [2]int{n, n})
		}
	}
	return rs, nil
}

// Empty reports whether the set matches nothing (as opposed to "all" or a
// real range list).
func (rs RangeSet) Empty() bool { return !rs.all && len(rs.ranges) == 0 }

// Contains reports whether n falls in the set.
func (rs RangeSet) Contains(n int) bool {
	if rs.all {
		return true
	}
	for _, r := range rs.ranges {
		if n >= r[0] && n <= r[1] {
			return true
		}
	}
	return false
}

// DedupStrings returns in with duplicates removed, keeping first-seen order.
func DedupStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ErrMissing is a small helper for required-flag errors.
func ErrMissing(msg string) error { return errors.New(msg) }

// ContextTimeout is a thin wrapper so command code stays terse.
func ContextTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

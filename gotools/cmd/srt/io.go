package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// inputLines reads non-empty, whitespace-trimmed lines from path. If path is
// "" or "-", it reads from stdin. This is what makes every command accept a
// pipe as well as a file.
func inputLines(path string) ([]string, error) {
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

// readAll reads the full contents of path (or stdin when path is "" or "-").
func readAll(path string) (string, error) {
	if path == "" || path == "-" {
		b, err := io.ReadAll(os.Stdin)
		return string(b), err
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

// nopWriteCloser lets us return os.Stdout from output() without closing it.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// output returns a writer for path, or stdout when path is "" or "-".
// The caller must Close it (closing stdout is a no-op).
func output(path string) (io.WriteCloser, error) {
	if path == "" || path == "-" {
		return nopWriteCloser{os.Stdout}, nil
	}
	return os.Create(path)
}

// writeLines writes each line followed by a newline.
func writeLines(w io.Writer, lines []string) error {
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

// stdout returns os.Stdout as an io.Writer, for the handful of commands that
// print sections directly rather than through output().
func stdout() io.Writer { return os.Stdout }

// warn prints a formatted message to stderr so stdout stays clean for piping.
func warn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", a...)
}

// resolveInput returns the input path, preferring an explicit -l flag, then a
// single positional argument, otherwise "" (meaning stdin).
func resolveInput(flagValue string, positional []string) string {
	if flagValue != "" {
		return flagValue
	}
	if len(positional) > 0 {
		return positional[0]
	}
	return ""
}

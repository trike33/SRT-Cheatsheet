package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"golang.org/x/term"
)

func init() {
	register(&command{
		name:    "shell",
		group:   "misc",
		summary: "Interactive REPL: run commands by name with history and tab-completion",
		run:     runShell,
	})
}

func runShell(args []string) error {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return errMissing("shell needs an interactive terminal (stdin is not a TTY)")
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("determining srt's own binary path: %w", err)
	}

	names := shellCommandNames()

	t := term.NewTerminal(struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}, "srt> ")
	t.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		return shellAutoComplete(names, line, pos, key)
	}

	fmt.Fprintln(t, `srt interactive shell — tab-complete a command name, "help [command]" for its flags, "exit" or Ctrl+D to quit.`)

	for {
		// Raw mode is only needed while ReadLine is editing the current
		// line; restore normal (cooked) mode before running a command, or
		// its ordinary fmt.Println-style output would render staircased
		// (bare \n doesn't return the cursor to column 0 in raw mode).
		oldState, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}
		line, err := t.ReadLine()
		if restoreErr := term.Restore(fd, oldState); restoreErr != nil && err == nil {
			err = restoreErr
		}

		if err != nil {
			if err == io.EOF {
				fmt.Println()
				return nil
			}
			return fmt.Errorf("reading input: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			return nil
		}
		runShellLine(self, line)
	}
}

// runShellLine parses one line and, for a real command, runs it as a
// subprocess of srt itself — never in-process. Every command's flag.FlagSet
// uses flag.ExitOnError, so a bad flag (or -h) calls os.Exit; in-process
// that would silently kill the whole shell session instead of just that one
// command. A subprocess also makes "-h" work as the flag reference for
// free, with zero duplicated help text.
func runShellLine(self, line string) {
	fields, err := shellSplitArgs(line)
	if err != nil {
		warn("shell: %v", err)
		return
	}
	if len(fields) == 0 {
		return
	}

	cmdName := fields[0]
	cmdArgs := fields[1:]
	if cmdName == "help" {
		if len(cmdArgs) == 0 {
			usage()
			return
		}
		cmdName = cmdArgs[0]
		cmdArgs = []string{"-h"}
	}

	if _, ok := registry[cmdName]; !ok {
		warn("shell: unknown command %q (type \"help\" to list commands)", cmdName)
		return
	}

	cmd := exec.Command(self, append([]string{cmdName}, cmdArgs...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// A clean non-zero exit (bad flags, -h, a real command error) isn't
		// a shell-side problem -- the subprocess already printed why. Only
		// a launch failure (binary missing, permissions, ...) is worth a
		// shell-side warning here.
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			warn("shell: %s: %v", cmdName, err)
		}
	}
}

// shellCommandNames lists every registered command plus the shell's own
// pseudo-commands, for tab-completion.
func shellCommandNames() []string {
	names := make([]string, 0, len(registry)+2)
	for n := range registry {
		names = append(names, n)
	}
	names = append(names, "help", "exit")
	sort.Strings(names)
	return names
}

// shellAutoComplete completes the first word of the line (the command name)
// on Tab. An unambiguous match completes in place; an ambiguous or empty
// match is a no-op (no match list -- safe default given term.Terminal
// tracks its own cursor/line-length bookkeeping, and writing extra output
// mid-edit risks desyncing that).
func shellAutoComplete(names []string, line string, pos int, key rune) (string, int, bool) {
	if key != '\t' {
		return "", 0, false
	}
	prefix := line[:pos]
	if strings.ContainsAny(prefix, " \t") {
		return "", 0, false
	}

	var matches []string
	for _, n := range names {
		if strings.HasPrefix(n, prefix) {
			matches = append(matches, n)
		}
	}
	if len(matches) != 1 {
		return "", 0, false
	}
	newLine := matches[0] + " "
	return newLine, len(newLine), true
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

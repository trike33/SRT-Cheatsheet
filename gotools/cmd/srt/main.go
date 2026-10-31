// Command srt is a collection of bug-bounty recon helpers, ported from the
// Python glue scripts in the SRT-Cheatsheet repo.
//
// Design goals:
//   - One static, dependency-free binary you can scp onto any VPS.
//   - Every subcommand is pipe-friendly: it reads from a file (-l / positional)
//     or from stdin, and writes to stdout (or -o file), so the tools chain
//     straight into httpx / katana / nuclei / ffuf the way the methodology does.
//
// This file is deliberately thin: it only parses the leading global flags,
// dispatches argv to a registered command, and wires in the cross-cutting
// concerns (traffic metering, halt handling, saving to the results database)
// that apply to every command uniformly. All the actual command logic lives
// in internal/ -- see docs/ARCHITECTURE.md for the package layout and the
// convention for adding a new command.
package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/halt"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"

	// Every command package registers itself via an init() that calls
	// cli.Register; main never calls into one directly, so this blank-import
	// block is the only place that needs to list them. Adding a new command
	// package means adding one line here (and nowhere else in this file).
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/pipeline"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/dirlist"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/domains"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/fuzz"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/gau"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/ipexpand"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/portscan"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/probe"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/relpaths"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/resolve"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/robots"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/snyk"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/subdomains"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/recon/traceroute"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/results"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/scope" // burphosts, burpscope
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/shell"
	_ "github.com/trike33/srt-cheatsheet/gotools/internal/version"
)

// applyGlobalFlags consumes the leading global flags -- `-rate N`, `-save`,
// `-db <path>`, in any order, before the command name -- and strips them from
// os.Args. -rate arms the process-wide request cap (also $SRT_RATE); -save
// stores the command's results in the project database (also $SRT_SAVE=1);
// -db points at a different database file (also $SRT_DB). Each is mirrored
// into the environment so the shell and anything it spawns inherit it.
func applyGlobalFlags() {
	for len(os.Args) > 1 {
		a := os.Args[1]
		name, val, hasVal := strings.Cut(a, "=")
		name = strings.TrimLeft(name, "-")
		if !strings.HasPrefix(a, "-") || (name != "rate" && name != "save" && name != "db") {
			break
		}
		consumed := 1
		if name != "save" && !hasVal {
			if len(os.Args) < 3 {
				fmt.Fprintf(os.Stderr, "srt: -%s needs a value\n", name)
				os.Exit(2)
			}
			val, consumed = os.Args[2], 2
		}
		os.Args = append(os.Args[:1], os.Args[1+consumed:]...)
		switch name {
		case "rate":
			os.Setenv(netx.EnvRate, val)
		case "save":
			os.Setenv(store.EnvSave, "1")
		case "db":
			os.Setenv("SRT_DB", val)
		}
	}
	if raw := os.Getenv(netx.EnvRate); raw != "" {
		v, err := netx.ParseRate(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "srt: %v\n", err)
			os.Exit(2)
		}
		netx.SetRate(v)
	}
}

// structuredSaveCommands record rich results themselves (see each recon
// package's own store.CurrentSink().Add call sites); every other command is
// saved by teeing its stdout line by line.
var structuredSaveCommands = map[string]bool{"portscan": true, "fuzz": true, "probe": true, "pipeline": true}

// dbCommands read the database, so they are never run "with -save".
var dbCommands = map[string]bool{"runs": true, "results": true, "export": true, "db": true, "shell": true}

// teeStdoutToSink mirrors the command's stdout to the real stdout and stores
// each line as a record of the given kind. The returned func restores stdout
// and waits for the copy to finish.
func teeStdoutToSink(kind string) func() {
	r, w, err := os.Pipe()
	if err != nil {
		return func() {}
	}
	real := os.Stdout
	os.Stdout = w
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
		for sc.Scan() {
			line := sc.Text()
			fmt.Fprintln(real, line)
			if strings.TrimSpace(line) != "" {
				store.CurrentSink().Add(store.TextRecord(kind, line))
			}
		}
	}()
	return func() {
		os.Stdout = real
		w.Close()
		<-done
	}
}

// stdinIsTerminal decides whether bare `srt` should open the shell. It's a
// one-line duplicate of internal/shell's own check (which main.go can't call
// without importing shell's command logic directly) -- cheap enough to keep
// local rather than promote to a shared package for one line.
func stdinIsTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

func main() {
	applyGlobalFlags()
	if len(os.Args) < 2 {
		// Bare `srt` opens the interactive shell; with no TTY (a script,
		// a pipe) there's nobody to type at it, so fall back to usage.
		if c, ok := cli.Lookup("shell"); ok && stdinIsTerminal() {
			if err := c.Run(nil); err != nil {
				fmt.Fprintf(os.Stderr, "srt shell: %v\n", err)
				os.Exit(1)
			}
			return
		}
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "-h", "--help", "help":
		usage()
		return
	}

	c, ok := cli.Lookup(os.Args[1])
	if !ok {
		fmt.Fprintf(os.Stderr, "srt: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	// -save / $SRT_SAVE: record this command's results in the project database.
	var untee func()
	if os.Getenv(store.EnvSave) != "" && !dbCommands[os.Args[1]] && store.CurrentSink() == nil {
		if _, err := store.StartSink(os.Args[1], os.Args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "srt: -save: %v\n", err)
			os.Exit(1)
		}
		if !structuredSaveCommands[os.Args[1]] {
			untee = teeStdoutToSink(os.Args[1])
		}
	}

	// Under the shell, meter traffic and enforce its limits (no-op otherwise).
	var finishTraffic func()
	if os.Args[1] != "shell" {
		finishTraffic = netx.StartMonitor()
		halt.InstallHandler(func() string {
			if t := netx.Snapshot(); t.Requests > 0 {
				return t.String()
			}
			return ""
		})
	}
	err := c.Run(os.Args[2:])
	if untee != nil {
		untee()
	}
	store.CurrentSink().Close()
	if finishTraffic != nil {
		finishTraffic()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "srt %s: %v\n", c.Name, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "srt - bug-bounty recon helpers (SRT-Cheatsheet)")
	fmt.Fprintln(os.Stderr, "\nUsage:")
	fmt.Fprintln(os.Stderr, "  srt [-rate <req/s>] [-save] [-db <path>] <command> [flags]")
	fmt.Fprintln(os.Stderr, "\n  -rate (or $SRT_RATE) caps the whole process's request rate, whatever the command or concurrency.")
	fmt.Fprintln(os.Stderr, "  -save (or $SRT_SAVE=1) stores the command's results in .srt/srt.db; see 'srt results', 'srt export'.")
	fmt.Fprintln(os.Stderr, "\nMost commands read a list from -l <file> or stdin and write to stdout or -o <file>.")
	fmt.Fprintln(os.Stderr, "\nCommands:")

	// Group commands for a tidier --help.
	groups := cli.Grouped()
	var order []string
	for g := range groups {
		order = append(order, g)
	}
	sort.Strings(order)

	tw := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
	for _, g := range order {
		fmt.Fprintf(os.Stderr, "\n  %s:\n", g)
		cmds := groups[g]
		sort.Slice(cmds, func(i, j int) bool { return cmds[i].Name < cmds[j].Name })
		for _, c := range cmds {
			fmt.Fprintf(tw, "    %s\t%s\n", c.Name, c.Summary)
		}
		tw.Flush()
	}
	fmt.Fprintln(os.Stderr, "\nRun 'srt <command> -h' for flags on a specific command.")
}

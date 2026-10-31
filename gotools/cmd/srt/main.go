// Command srt is a collection of bug-bounty recon helpers, ported from the
// Python glue scripts in the SRT-Cheatsheet repo.
//
// Design goals:
//   - One static, dependency-free binary you can scp onto any VPS.
//   - Every subcommand is pipe-friendly: it reads from a file (-l / positional)
//     or from stdin, and writes to stdout (or -o file), so the tools chain
//     straight into httpx / katana / nuclei / ffuf the way the methodology does.
package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

// command is a single subcommand in the srt CLI.
type command struct {
	name    string
	group   string // used only to group the help output
	summary string
	run     func(args []string) error
}

// registry holds every subcommand; subcommands register themselves in init().
var registry = map[string]*command{}

func register(c *command) {
	if _, dup := registry[c.name]; dup {
		panic("duplicate command registered: " + c.name)
	}
	registry[c.name] = c
}

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
			os.Setenv(envRate, val)
		case "save":
			os.Setenv(envSave, "1")
		case "db":
			os.Setenv("SRT_DB", val)
		}
	}
	if raw := os.Getenv(envRate); raw != "" {
		v, err := parseRate(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "srt: %v\n", err)
			os.Exit(2)
		}
		gate.set(v)
	}
}

const envSave = "SRT_SAVE"

// structuredSaveCommands record rich results themselves (see sink.add call
// sites); every other command is saved by teeing its stdout line by line.
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
				sink.add(textRecord(kind, line))
			}
		}
	}()
	return func() {
		os.Stdout = real
		w.Close()
		<-done
	}
}

func main() {
	applyGlobalFlags()
	if len(os.Args) < 2 {
		// Bare `srt` opens the interactive shell; with no TTY (a script,
		// a pipe) there's nobody to type at it, so fall back to usage.
		if stdinIsTerminal() {
			if err := registry["shell"].run(nil); err != nil {
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

	c, ok := registry[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "srt: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	// -save / $SRT_SAVE: record this command's results in the project database.
	var untee func()
	if os.Getenv(envSave) != "" && !dbCommands[os.Args[1]] && sink == nil {
		if _, err := startSink(os.Args[1], os.Args[1:]); err != nil {
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
		finishTraffic = startTrafficMonitor()
		installHaltHandler(func() string {
			if t := meter.snapshot(); t.Requests > 0 {
				return t.String()
			}
			return ""
		})
	}
	err := c.run(os.Args[2:])
	if untee != nil {
		untee()
	}
	sink.close()
	if finishTraffic != nil {
		finishTraffic()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "srt %s: %v\n", c.name, err)
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
	groups := map[string][]*command{}
	var order []string
	for _, c := range registry {
		if _, seen := groups[c.group]; !seen {
			order = append(order, c.group)
		}
		groups[c.group] = append(groups[c.group], c)
	}
	sort.Strings(order)

	tw := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
	for _, g := range order {
		fmt.Fprintf(os.Stderr, "\n  %s:\n", g)
		cmds := groups[g]
		sort.Slice(cmds, func(i, j int) bool { return cmds[i].name < cmds[j].name })
		for _, c := range cmds {
			fmt.Fprintf(tw, "    %s\t%s\n", c.name, c.summary)
		}
		tw.Flush()
	}
	fmt.Fprintln(os.Stderr, "\nRun 'srt <command> -h' for flags on a specific command.")
}

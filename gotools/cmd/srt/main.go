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
	"fmt"
	"os"
	"sort"
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

func main() {
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

	if err := c.run(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "srt %s: %v\n", c.name, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "srt - bug-bounty recon helpers (SRT-Cheatsheet)")
	fmt.Fprintln(os.Stderr, "\nUsage:")
	fmt.Fprintln(os.Stderr, "  srt <command> [flags]")
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

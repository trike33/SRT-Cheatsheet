// Package cli is srt's command registry: the one piece of framework every
// subcommand package depends on. A command package registers itself with
// Register from its own init(), and the entrypoint (cmd/srt) looks commands
// up by name to dispatch argv and to render --help -- it never needs to
// import a command package directly.
package cli

import "fmt"

// Command is a single subcommand in the srt CLI.
type Command struct {
	Name    string
	Group   string // used only to group the help output
	Summary string
	Run     func(args []string) error
}

var registry = map[string]*Command{}

// Register adds c to the registry. It panics on a duplicate name, which is a
// programming error (two packages claiming the same command), not something
// to handle at runtime.
func Register(c *Command) {
	if _, dup := registry[c.Name]; dup {
		panic(fmt.Sprintf("cli: duplicate command registered: %q", c.Name))
	}
	registry[c.Name] = c
}

// Lookup returns the registered command named name, if any.
func Lookup(name string) (*Command, bool) {
	c, ok := registry[name]
	return c, ok
}

// Names returns every registered command's name, unsorted.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	return out
}

// Grouped returns every registered command, grouped by its Group, for a
// formatted --help listing.
func Grouped() map[string][]*Command {
	groups := map[string][]*Command{}
	for _, c := range registry {
		groups[c.Group] = append(groups[c.Group], c)
	}
	return groups
}

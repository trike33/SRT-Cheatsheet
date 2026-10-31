package cli

import (
	"flag"
	"fmt"
	"sort"
)

// UsageSection is one named group of flags in a command's --help output
// (INPUT:, OUTPUT:, FILTERS:, ... in the style projectdiscovery's tools use),
// listed in the order the command cares about instead of flag.FlagSet's
// alphabetical default. Names are the same flag names already registered
// with the FlagSet -- grouping only changes how --help is laid out, never a
// flag's name, default, or parsing.
type UsageSection struct {
	Title string
	Names []string
}

// PrintGroupedUsage renders fs's flags grouped into sections instead of
// flag.FlagSet's default alphabetical PrintDefaults dump. Assign it to
// fs.Usage before fs.Parse:
//
//	fs.Usage = func() { cli.PrintGroupedUsage(fs, sections) }
//
// A flag that exists in fs but is missing from every section still prints,
// under a trailing OTHER: section, so a flag can never silently disappear
// from --help just because a section list drifted out of sync with the
// command's real flags (e.g. a new flag added without updating sections).
func PrintGroupedUsage(fs *flag.FlagSet, sections []UsageSection) {
	w := fs.Output()
	fmt.Fprintf(w, "Usage of %s:\n", fs.Name())

	width := 0
	fs.VisitAll(func(f *flag.Flag) {
		if n := len(flagColumn(f)); n > width {
			width = n
		}
	})

	seen := map[string]bool{}
	printOne := func(name string) {
		f := fs.Lookup(name)
		if f == nil || seen[name] {
			return
		}
		seen[name] = true
		fmt.Fprintf(w, "   %-*s  %s\n", width, flagColumn(f), flagDesc(f))
	}

	for _, sec := range sections {
		has := false
		for _, n := range sec.Names {
			if fs.Lookup(n) != nil {
				has = true
				break
			}
		}
		if !has {
			continue
		}
		fmt.Fprintf(w, "\n%s:\n", sec.Title)
		for _, n := range sec.Names {
			printOne(n)
		}
	}

	var leftover []string
	fs.VisitAll(func(f *flag.Flag) {
		if !seen[f.Name] {
			leftover = append(leftover, f.Name)
		}
	})
	if len(leftover) > 0 {
		sort.Strings(leftover)
		fmt.Fprintf(w, "\nOTHER:\n")
		for _, n := range leftover {
			printOne(n)
		}
	}
}

// flagColumn renders "-name" or "-name <type>" for a flag's left column. A
// bool flag (its presence alone is the value) gets no type annotation.
func flagColumn(f *flag.Flag) string {
	t := flagType(f)
	if t == "" {
		return "-" + f.Name
	}
	return "-" + f.Name + " " + t
}

// flagType returns a short type annotation for f's value, or "" for a bool
// flag.
func flagType(f *flag.Flag) string {
	if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
		return ""
	}
	switch fmt.Sprintf("%T", f.Value) {
	case "*flag.intValue", "*flag.int64Value", "*flag.uintValue", "*flag.uint64Value":
		return "int"
	case "*flag.float64Value":
		return "float"
	case "*flag.durationValue":
		return "duration"
	case "*flag.stringValue":
		return "string"
	default:
		// srt's only custom flag.Value today is a repeatable string list
		// (stringSlice, used e.g. by fuzz's -u/-w/-e/-H).
		return "string[]"
	}
}

// flagDesc returns f's usage text, with its default appended the same way
// flag.PrintDefaults does: only when that default isn't the type's zero
// value, so an unset bool/empty string/zero duration doesn't clutter every
// line with "(default false)".
func flagDesc(f *flag.Flag) string {
	switch f.DefValue {
	case "", "false", "0", "0s", "0B":
		return f.Usage
	}
	if flagType(f) == "string" {
		return fmt.Sprintf("%s (default %q)", f.Usage, f.DefValue)
	}
	return fmt.Sprintf("%s (default %s)", f.Usage, f.DefValue)
}

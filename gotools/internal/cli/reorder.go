package cli

import "flag"

// ReorderArgs permutes args so every flag fs recognizes (and, for a
// non-boolean flag, its separate value token) moves ahead of the plain
// positional arguments, preserving each group's own relative order. This
// lets flags appear anywhere on the command line -- `smb 10.0.0.5 -u bob -p
// pw` works the same as `smb -u bob -p pw 10.0.0.5` -- working around
// flag.FlagSet.Parse's own rule that it stops consuming flags at the first
// non-flag argument, which would otherwise leave a flag typed after a
// positional target sitting unparsed in fs.Args() (and, for a command that
// treats bare positionals as targets, silently misread as one).
//
// fs must already have every flag registered (call this right before
// fs.Parse, after all the fs.String/Bool/Int/Var calls). A token this can't
// resolve to one of fs's flags -- an unknown "-x", or anything from a bare
// "--" on -- is left exactly where it was, so flag.Parse still reports an
// unknown flag (or stops at "--") the same way it always has.
func ReorderArgs(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}
		name := a[1:]
		if name[0] == '-' {
			name = name[1:]
		}
		if name == "" { // bare "-" (the stdin marker) is a positional
			positional = append(positional, a)
			continue
		}
		lookupName := name
		hasInlineVal := false
		for j, c := range name {
			if c == '=' {
				lookupName, hasInlineVal = name[:j], true
				break
			}
		}
		f := fs.Lookup(lookupName)
		if f == nil {
			// Not one of fs's flags -- leave it (and don't guess at an
			// arity for it); flag.Parse will report it as unknown
			// wherever it ends up.
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		isBool := false
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok {
			isBool = bf.IsBoolFlag()
		}
		if !hasInlineVal && !isBool && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positional...)
}

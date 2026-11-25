// Shared output formatting for every protocol command: a netexec-style
// line -- "PROTO   target:port   [tag] message" -- colored by the result's
// nature (info/ok/fail), so srt ftp/telnet/smb/ldap read as one family in
// the terminal instead of each inventing its own table.
package auth

import (
	"fmt"

	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
)

// Tag marks what kind of line this is: Info for a fact being reported
// (a banner, "enumerating shares"), OK for a succeeded auth/check, Fail for
// a failed one or an error.
type Tag int

const (
	Info Tag = iota
	OK
	Fail
)

func (t Tag) bracket(cm colorout.Mode) string {
	switch t {
	case OK:
		return cm.Wrap(colorout.Green, "[+]")
	case Fail:
		return cm.Wrap(colorout.Red, "[-]")
	default:
		return cm.Wrap(colorout.Cyan, "[*]")
	}
}

// protoColor gives each protocol its own consistent tag color across a run
// (and across commands), the same deterministic-by-name idea as
// colorout.PaletteColor, so e.g. every SMB line reads the same color whether
// it's this run's first or its hundredth target.
func protoColor(proto string) string { return colorout.PaletteColor(proto) }

// Line formats one netexec-style output line for a target. msg should not
// itself start with the tag -- Line adds it.
func Line(cm colorout.Mode, proto, target string, port int, tag Tag, msg string) string {
	head := fmt.Sprintf("%-6s %-21s", proto, fmt.Sprintf("%s:%d", target, port))
	return cm.Wrap(protoColor(proto), head) + " " + tag.bracket(cm) + " " + msg
}

// Package wordlists embeds the wordlists srt ships so default behaviour
// works from the single static binary with nothing installed alongside it.
package wordlists

import (
	_ "embed"
	"os"
	"path/filepath"
)

// subdomains is danielmiessler/SecLists' Discovery/DNS/
// subdomains-top1million-20000.txt (MIT licensed, see NOTICE.md).
//
//go:embed subdomains-top1million-20000.txt
var subdomains []byte

// SubdomainsFile writes the embedded subdomain-label wordlist into dir and
// returns its path, for tools (dnsx) that need a file on disk.
func SubdomainsFile(dir string) (string, error) {
	p := filepath.Join(dir, "subdomains-top1million-20000.txt")
	if err := os.WriteFile(p, subdomains, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

// SubdomainsCount is the number of labels in the embedded list (for docs/tests).
func SubdomainsCount() int {
	n := 0
	for _, b := range subdomains {
		if b == '\n' {
			n++
		}
	}
	return n
}

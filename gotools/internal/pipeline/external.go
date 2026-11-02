package pipeline

import (
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

// This is the extension point for driving a third-party tool from the
// pipeline. srt's policy (see docs/methodology.md) is to implement recon
// steps natively rather than shell out to tools like naabu, httpx,
// subfinder, katana, nuclei, or dalfox — the one sanctioned exception is
// vulnx (github.com/projectdiscovery/vulnx), used below for CVE lookups
// from a grabbed service banner (pipeline_host.go's "scan" step). A future
// external-tool step follows the same shape: runExternal with a binary name
// and an argv.

// runExternal looks up bin on PATH and, if found, runs it with args, writing
// its stdout to outFile and logging its stderr via warn(). If bin isn't
// installed, it reports a "skipped" stepResult instead of failing the whole
// pipeline run — an uninstalled optional tool should never abort an
// engagement.
func runExternal(kind, name, target, bin string, args []string, outFile string) stepResult {
	if _, err := exec.LookPath(bin); err != nil {
		return skipStep(kind, name, target, "external tool \""+bin+"\" not found on PATH")
	}
	return runStep(kind, name, target, outFile, func() error {
		cmd := exec.Command(bin, args...)
		out, err := os.Create(outFile)
		if err != nil {
			return err
		}
		defer out.Close()
		cmd.Stdout = out
		var stderr bytes.Buffer
		cmd.Stderr = &stderr // surfaced via Warn so the step summary/log handles it
		runErr := cmd.Run()
		for _, l := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
			if l != "" {
				ioutil.Warn("%s: %s", bin, l)
			}
		}
		return runErr
	})
}

// vulnxProductPatterns recognizes a banner shape well enough to pull out a
// clean product name for vulnx search's -p/--product filter, which gives
// far more precise CVE matches than free-text searching the raw banner
// (version numbers, build comments, hostnames and all): `vulnx search -p
// arcgis` over `vulnx search "ArcGIS Server 10.8.1 build 1234"`. Order
// matters: first match wins. Deliberately a short, high-confidence list --
// srt's own commonPorts/uncommonPorts services plus BeanShell, not an
// attempt at full banner/version parsing.
var vulnxProductPatterns = []struct {
	re      *regexp.Regexp
	product string
}{
	{regexp.MustCompile(`(?i)^SSH-[\d.]+-OpenSSH`), "openssh"},
	{regexp.MustCompile(`(?i)^SSH-[\d.]+-dropbear`), "dropbear"},
	{regexp.MustCompile(`(?i)vsftpd`), "vsftpd"},
	{regexp.MustCompile(`(?i)proftpd`), "proftpd"},
	{regexp.MustCompile(`(?i)pure-?ftpd`), "pureftpd"},
	{regexp.MustCompile(`(?i)filezilla`), "filezilla"},
	{regexp.MustCompile(`(?i)postfix`), "postfix"},
	{regexp.MustCompile(`(?i)\bexim\b`), "exim"},
	{regexp.MustCompile(`(?i)sendmail`), "sendmail"},
	{regexp.MustCompile(`(?i)beanshell`), "beanshell"},
	{regexp.MustCompile(`(?i)\bredis\b`), "redis"},
	{regexp.MustCompile(`(?i)memcached`), "memcached"},
	{regexp.MustCompile(`(?i)mariadb`), "mariadb"},
	{regexp.MustCompile(`(?i)mysql`), "mysql"},
	{regexp.MustCompile(`(?i)postgres`), "postgresql"},
	{regexp.MustCompile(`(?i)mongodb`), "mongodb"},
	{regexp.MustCompile(`(?i)samba`), "samba"},
	{regexp.MustCompile(`(?i)\brsync\b`), "rsync"},
	{regexp.MustCompile(`(?i)\bvnc\b`), "vnc"},
}

// vulnxProduct returns the clean product name vulnxProductPatterns
// recognizes in banner, or "" when none of them match -- the banner is some
// other/unrecognized service, so the caller falls back to a free-text
// search instead of guessing a product name.
func vulnxProduct(banner string) string {
	for _, p := range vulnxProductPatterns {
		if p.re.MatchString(banner) {
			return p.product
		}
	}
	return ""
}

// vulnxQuery turns a grabbed service banner into a vulnx free-text search
// query, for when vulnxProduct doesn't recognize it. vulnx's search is a
// free-text + structured query engine; plain text (verified against the
// real tool, not just its docs) works fine as a query without needing
// product/version parsing -- this just trims it to a sane length so a
// pathological banner can't produce an absurd query.
func vulnxQuery(banner string) string {
	q := strings.TrimSpace(banner)
	const maxLen = 150
	if len(q) > maxLen {
		q = q[:maxLen]
	}
	return q
}

// vulnxSearchArgs builds the argv for `vulnx search` from a grabbed banner:
// `-p <product>` when vulnxProduct recognizes it (precise, structured --
// verified against the real CLI: `vulnx search -p arcgis` is valid with no
// positional query), otherwise a free-text query over the banner itself.
func vulnxSearchArgs(banner string) []string {
	args := []string{"search", "--json", "--silent", "--limit", "5"}
	if p := vulnxProduct(banner); p != "" {
		return append(args, "-p", p)
	}
	return append(args, vulnxQuery(banner))
}

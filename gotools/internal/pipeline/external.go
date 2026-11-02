package pipeline

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

// This is the extension point for driving a third-party tool from the
// pipeline. srt's policy (see docs/methodology.md) is to implement recon
// steps natively rather than shell out to tools like naabu, httpx,
// subfinder, katana, nuclei, or dalfox — the sanctioned exceptions are
// vulnx (github.com/projectdiscovery/vulnx), used below for CVE lookups
// from a grabbed service banner, and nuclei (github.com/projectdiscovery/
// nuclei), used for the HOST stage's "easy wins" pass (default creds,
// common misconfigs -- options.easyWins/-easy-wins, off by default since
// it sends real exploitation-adjacent probes, not just passive recon).
// A future external-tool step follows the same shape: runExternal with a
// binary name and an argv.

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

// nucleiEasyWinsArgs builds a deliberately conservative `nuclei` invocation
// for the HOST stage's "easy wins" pass against one non-web open port
// (methodology.md: "default credentials, common misconfigurations"). A
// generic, otherwise-unrestricted nuclei run can fire thousands of
// requests at a single target; every flag here exists to cap that for an
// automated, unattended pipeline step, not to tune for thoroughness:
//
//   - -tags default-login,exposure,misconfig restricts it to that one
//     methodology bullet -- never "cve" (vulnx already covers that from
//     the banner right above this step, no need to duplicate the traffic).
//   - -etags dos,fuzz,intrusive drops anything actively harmful or noisy
//     regardless of which tag let it in.
//   - -rl/-c/-bs/-timeout/-retries/-mt bound the worst case for one target
//     to a low-rate, short burst, well under nuclei's own (much higher)
//     defaults -- see docs/pipeline.md for the exact numbers and why.
//   - -ni skips OAST/interactsh-based templates entirely, so this never
//     depends on or calls out to a third-party interactsh server.
//   - -duc skips nuclei's own template-update network check on every run;
//     it does NOT fetch templates on its own first run -- see
//     docs/pipeline.md for the one-time `nuclei -ut` this still needs.
//   - -silent -j matches vulnxSearchArgs' own shape: structured JSON lines
//     on stdout, which runExternal already redirects to this step's file.
func nucleiEasyWinsArgs(host string, port int) []string {
	return []string{
		"-u", fmt.Sprintf("%s:%d", host, port),
		"-tags", "default-login,exposure,misconfig",
		"-etags", "dos,fuzz,intrusive",
		"-rl", "10",
		"-c", "3",
		"-bs", "1",
		"-timeout", "5",
		"-retries", "1",
		"-mt", "3m",
		"-ni",
		"-duc",
		"-silent",
		"-j",
	}
}

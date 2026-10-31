package pipeline

import (
	"os"
	"os/exec"
	"strings"
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
		cmd.Stderr = os.Stderr
		return cmd.Run()
	})
}

// vulnxQuery turns a grabbed service banner into a vulnx search query.
// vulnx's search is a free-text + structured query engine; plain text
// (verified against the real tool, not just its docs) works fine as a
// query without needing product/version parsing — this just trims it to a
// sane length so a pathological banner can't produce an absurd query.
func vulnxQuery(banner string) string {
	q := strings.TrimSpace(banner)
	const maxLen = 150
	if len(q) > maxLen {
		q = q[:maxLen]
	}
	return q
}

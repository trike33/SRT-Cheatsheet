package main

import (
	"os"
	"os/exec"
)

// externalStep is the extension point for driving a third-party tool from
// the pipeline. srt's policy (see docs/methodology.md) is to implement
// recon steps natively rather than shell out to tools like naabu, httpx,
// subfinder, katana, nuclei, or dalfox — the one sanctioned exception is
// vulnx, for CVE lookups from a grabbed service/software version (HOST
// stage, docs/methodology.md's "scan" step). No stage wires it up yet, but
// runExternal is ready to use once that step is built: it just needs a
// binary name and an argv builder.
//
// Example of how that step would plug in (not wired into any stage yet):
//
//	sr := runExternal("host", "vulnx", target,
//		"vulnx", []string{"-o", target, "-v", version},
//		filepath.Join(outDir, "vulnx_"+safeName(target)+".txt"))
type externalStep struct {
	bin       string
	buildArgs func() []string
}

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

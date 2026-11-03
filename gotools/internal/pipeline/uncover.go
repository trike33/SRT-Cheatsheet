package pipeline

import (
	"path/filepath"
	"strings"
)

// uncoverUsableEngines returns which of requested have a key available
// (uncoverEngineHasKey, external.go), in the same order, and the ones that
// don't (for a clear skip message naming them).
func uncoverUsableEngines(requested []string) (usable, missing []string) {
	for _, e := range requested {
		if uncoverEngineHasKey(e) {
			usable = append(usable, e)
		} else {
			missing = append(missing, e)
		}
	}
	return usable, missing
}

// runUncoverSeed seeds additional HOST-stage targets from a Shodan/Censys/
// etc. search (gap 11, scope-building) -- options.uncover/-uncover, off by
// default. Needs options.uncoverQuery and a key for at least one requested
// engine (checked via uncoverEngineHasKey, the same env vars `uncover`
// itself reads -- no srt-side key file to manage); cleanly skipped,
// naming what's missing, otherwise. Results are bare IPs (-f ip), the
// same shape a "host" config entry already is, so they flow through
// ipexpand/portscan exactly like an explicit target once appended to
// `included` by the caller.
func runUncoverSeed(cfg *pipelineConfig, outDir string) (found []string, steps []stepResult) {
	if cfg.Options.UncoverQuery == "" {
		return nil, []stepResult{skipStep("host", "uncover", "", "options.uncover is on but options.uncoverQuery/-uncover-query is empty")}
	}
	engines := cfg.Options.UncoverEngines
	if len(engines) == 0 {
		engines = []string{"shodan"}
	}
	usable, missing := uncoverUsableEngines(engines)
	if len(usable) == 0 {
		detail := "no API key configured for engine(s) " + strings.Join(missing, ",") + " -- see docs/ROADMAP.md gap 11 for the env var each needs"
		return nil, []stepResult{skipStep("host", "uncover", cfg.Options.UncoverQuery, detail)}
	}

	outFile := filepath.Join(outDir, "00b_uncover.txt")
	args := uncoverArgs(cfg.Options.UncoverQuery, usable, cfg.Options.UncoverLimit)
	sr := runExternal("host", "uncover", cfg.Options.UncoverQuery, "uncover", args, outFile)
	steps = append(steps, sr)
	if len(missing) > 0 {
		steps = append(steps, stepResult{Kind: "host", Name: "uncover-engines", Status: "ok",
			Detail: "used " + strings.Join(usable, ",") + "; skipped " + strings.Join(missing, ",") + " (no key configured)"})
	}
	if sr.Status == "ok" {
		found = mustLines(outFile)
	}
	return found, steps
}

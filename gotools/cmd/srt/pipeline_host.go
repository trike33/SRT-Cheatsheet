package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// runHostStage runs the HOST methodology (docs/methodology.md) against
// config.Host entries, writing output under outDir ("<outputDir>/host/"):
//
//	ipexpand -> resolve (reverse DNS, informational) -> portscan
//	  -> classify each open port:
//	       web service  -> handed off to the WEB stage (webHandoff)
//	       other service -> flagged if it's an uncommon/specialty port;
//	                        a grabbed banner gets a "vulnx" placeholder step
//	                        (not wired up yet, see ROADMAP.md)
//
// Entries are grouped by their effective "ports" value (entry.Ports ->
// options.Ports -> "common,uncommon") so each distinct port spec only scans
// once.
//
// Excluded hosts (reverse DNS + route trace only, never actively probed)
// aren't handled here yet — the config schema has no way to mark a host
// excluded-but-tracked today; see ROADMAP.md.
func runHostStage(cfg *pipelineConfig, outDir string, webHandoff bool) []stepResult {
	var steps []stepResult
	if len(cfg.Host) == 0 {
		return steps
	}

	defaultPorts := cfg.Options.Ports
	if defaultPorts == "" {
		defaultPorts = "common,uncommon"
	}

	groups := map[string][]string{}
	var order []string
	for _, e := range cfg.Host {
		if e.Target == "" {
			continue
		}
		ports := e.Ports
		if ports == "" {
			ports = defaultPorts
		}
		if _, ok := groups[ports]; !ok {
			order = append(order, ports)
		}
		groups[ports] = append(groups[ports], e.Target)
	}

	var webEntries []targetEntry
	for gi, ports := range order {
		raw := groups[ports]
		rawFile := filepath.Join(outDir, fmt.Sprintf("00_raw_%d.txt", gi))
		if err := writeLinesFile(rawFile, raw); err != nil {
			steps = append(steps, stepResult{Kind: "host", Name: "ipexpand", Target: ports, Status: "error", Detail: err.Error()})
			continue
		}

		expandFile := filepath.Join(outDir, fmt.Sprintf("01_ipexpand_%d.txt", gi))
		steps = append(steps, runStep("host", "ipexpand", ports, expandFile, func() error {
			return runIPExpand([]string{"-l", rawFile, "-o", expandFile})
		}))

		resolveFile := filepath.Join(outDir, fmt.Sprintf("02_resolve_%d.txt", gi))
		steps = append(steps, runStep("host", "resolve", ports, resolveFile, func() error {
			return runResolve([]string{"-l", expandFile, "-reverse", "-o", resolveFile})
		}))

		portscanFile := filepath.Join(outDir, fmt.Sprintf("03_portscan_%d.json", gi))
		steps = append(steps, runStep("host", "portscan", ports, portscanFile, func() error {
			return runPortscan([]string{"-l", expandFile, "-p", ports, "-json", "-o", portscanFile})
		}))

		results, err := readScanResults(portscanFile)
		if err != nil {
			steps = append(steps, stepResult{Kind: "host", Name: "classify-services", Target: ports, Status: "error", Detail: err.Error()})
			continue
		}
		for _, r := range results {
			switch {
			case isWebPort(r.Port):
				webEntries = append(webEntries, targetEntry{Target: webBaseURL(r.Host, r.Port)})
			case isUncommonPort(r.Port):
				detail := fmt.Sprintf("uncommon/specialty service on port %d — follow up manually", r.Port)
				if r.Banner != "" {
					detail += "; banner: " + r.Banner
				}
				steps = append(steps, stepResult{
					Kind: "host", Name: "flag-uncommon-service",
					Target: fmt.Sprintf("%s:%d", r.Host, r.Port), Status: "ok", Detail: detail,
				})
			}
			if r.Banner != "" && !isWebPort(r.Port) {
				steps = append(steps, skipStep("host", "vulnx", fmt.Sprintf("%s:%d", r.Host, r.Port),
					"version/CVE lookup not wired up yet (vulnx's CLI interface needs confirming, see ROADMAP.md); banner: "+r.Banner))
			}
		}
	}

	switch {
	case len(webEntries) == 0:
		// Nothing to hand off either way.
	case !webHandoff:
		steps = append(steps, skipStep("host", "web-handoff", "",
			fmt.Sprintf("%d web service(s) discovered but web hand-off was disabled (-no-web-handoff)", len(webEntries))))
	default:
		webDir := filepath.Join(outDir, "web")
		if err := os.MkdirAll(webDir, 0o755); err != nil {
			steps = append(steps, stepResult{Kind: "host", Name: "web-handoff", Status: "error", Detail: err.Error()})
			break
		}
		webCfg := &pipelineConfig{Name: cfg.Name, Web: dedupTargetEntries(webEntries), Options: cfg.Options}
		steps = append(steps, runWebStage(webCfg, webDir)...)
	}

	return steps
}

// readScanResults reads a portscan -json output file back into scanResults.
func readScanResults(path string) ([]scanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // the portscan step itself already recorded the error
		}
		return nil, err
	}
	defer f.Close()

	var results []scanResult
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r scanResult
		if err := json.Unmarshal(line, &r); err != nil {
			continue // skip a malformed line rather than fail the whole stage
		}
		results = append(results, r)
	}
	return results, sc.Err()
}

// dedupTargetEntries drops entries with a Target already seen, keeping the
// first occurrence's fields and preserving order.
func dedupTargetEntries(entries []targetEntry) []targetEntry {
	seen := map[string]struct{}{}
	var out []targetEntry
	for _, e := range entries {
		if _, dup := seen[e.Target]; dup {
			continue
		}
		seen[e.Target] = struct{}{}
		out = append(out, e)
	}
	return out
}

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
//	                        a grabbed banner gets looked up via vulnx
//	                        (github.com/projectdiscovery/vulnx), skipped
//	                        cleanly if it isn't installed
//
// Entries are grouped by their effective "ports" value (entry.Ports ->
// options.Ports -> "common,uncommon") so each distinct port spec only scans
// once.
//
// A host entry with "excluded": true skips all of that (see runExcludedHosts
// below): reverse DNS + a route trace only, same as the methodology's
// excluded-but-tracked hosts, never a portscan or a WEB hand-off.
func runHostStage(cfg *pipelineConfig, outDir string, webHandoff bool) []stepResult {
	var steps []stepResult
	if len(cfg.Host) == 0 {
		return steps
	}

	var included []targetEntry
	var excluded []targetEntry
	for _, e := range cfg.Host {
		if e.Excluded {
			excluded = append(excluded, e)
		} else {
			included = append(included, e)
		}
	}
	steps = append(steps, runExcludedHosts(excluded, outDir)...)
	if len(included) == 0 {
		return steps
	}

	defaultPorts := cfg.Options.Ports
	if defaultPorts == "" {
		defaultPorts = "common,uncommon"
	}

	groups := map[string][]string{}
	var order []string
	for _, e := range included {
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
			return runPortscan(append([]string{"-l", expandFile, "-p", ports, "-json", "-o", portscanFile}, resumeStateArgs(portscanFile)...))
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
				target := fmt.Sprintf("%s:%d", r.Host, r.Port)
				vulnxFile := filepath.Join(outDir, "vulnx_"+safeName(target)+".json")
				steps = append(steps, runExternal("host", "vulnx", target, "vulnx",
					[]string{"search", vulnxQuery(r.Banner), "--json", "--silent", "--limit", "5"},
					vulnxFile))
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

// runExcludedHosts handles "host" entries marked "excluded": true -- the
// methodology's excluded-but-tracked hosts. They're never actively probed:
// no portscan, no WEB hand-off, just ipexpand (to resolve any CIDR to
// concrete IPs) -> reverse DNS -> a best-effort route trace.
//
// traceroute needs a raw ICMP socket (CAP_NET_RAW or root); without one, that
// step is **skipped** rather than failing the run, the same shape `pipeline`
// already uses for an optional capability (vulnx).
func runExcludedHosts(entries []targetEntry, outDir string) []stepResult {
	var steps []stepResult
	var raw []string
	for _, e := range entries {
		if e.Target != "" {
			raw = append(raw, e.Target)
		}
	}
	if len(raw) == 0 {
		return steps
	}

	rawFile := filepath.Join(outDir, "00_excluded_raw.txt")
	if err := writeLinesFile(rawFile, raw); err != nil {
		return []stepResult{{Kind: "host", Name: "ipexpand-excluded", Status: "error", Detail: err.Error()}}
	}

	expandFile := filepath.Join(outDir, "01_excluded_ipexpand.txt")
	steps = append(steps, runStep("host", "ipexpand-excluded", "", expandFile, func() error {
		return runIPExpand([]string{"-l", rawFile, "-o", expandFile})
	}))

	resolveFile := filepath.Join(outDir, "02_excluded_resolve.txt")
	steps = append(steps, runStep("host", "resolve-excluded", "", resolveFile, func() error {
		return runResolve([]string{"-l", expandFile, "-reverse", "-o", resolveFile})
	}))

	if err := checkRawICMPAvailable(); err != nil {
		steps = append(steps, skipStep("host", "traceroute-excluded", "",
			fmt.Sprintf("no raw ICMP socket available (%v) -- needs CAP_NET_RAW or root", err)))
		return steps
	}
	traceFile := filepath.Join(outDir, "03_excluded_traceroute.json")
	steps = append(steps, runStep("host", "traceroute-excluded", "", traceFile, func() error {
		return runTraceroute([]string{"-l", expandFile, "-json", "-o", traceFile})
	}))
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

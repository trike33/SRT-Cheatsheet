package pipeline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/ipexpand"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/portscan"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/resolve"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/traceroute"
)

// runHostStage runs the HOST methodology (docs/methodology.md) against
// config.Host entries, writing output under outDir ("<outputDir>/host/"):
//
//	ipexpand -> resolve (reverse DNS, informational) -> portscan
//	  -> cdncheck (options.cdnCheck, on by default): flag IPs behind a
//	     known CDN/WAF/cloud provider -- informational, a local dataset
//	     lookup with no traffic to the target
//	  -> classify each open port:
//	       web service  -> handed off to the WEB stage (webHandoff)
//	       other service -> flagged if it's an uncommon/specialty port or
//	                        BeanShell by banner; a grabbed banner gets
//	                        looked up via vulnx (github.com/
//	                        projectdiscovery/vulnx); with options.easyWins
//	                        (off by default), also a conservative nuclei
//	                        default-login/misconfig/exposure pass. All
//	                        external tools skip cleanly if not installed.
//
// Entries are grouped by their effective "ports" value (entry.Ports ->
// options.Ports -> "common,uncommon") so each distinct port spec only scans
// once.
//
// A host entry with "excluded": true skips all of that (see runExcludedHosts
// below): reverse DNS + a route trace only, same as the methodology's
// excluded-but-tracked hosts, never a portscan or a WEB hand-off.
//
// hostScopeFile, when non-empty, is forwarded to the WEB stage it hands
// services off to -- see runWebStage's own doc comment for what it does.
func runHostStage(cfg *pipelineConfig, outDir string, webHandoff bool, hostScopeFile string) []stepResult {
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
			return ipexpand.Run([]string{"-l", rawFile, "-o", expandFile})
		}))

		resolveFile := filepath.Join(outDir, fmt.Sprintf("02_resolve_%d.txt", gi))
		steps = append(steps, runStep("host", "resolve", ports, resolveFile, func() error {
			return resolve.Run([]string{"-l", expandFile, "-reverse", "-o", resolveFile})
		}))

		portscanFile := filepath.Join(outDir, fmt.Sprintf("03_portscan_%d.json", gi))
		steps = append(steps, runStep("host", "portscan", ports, portscanFile, func() error {
			return portscan.Run(append([]string{"-l", expandFile, "-p", ports, "-json", "-o", portscanFile}, resumeStateArgs(portscanFile)...))
		}))

		// cdncheck: flag which of this group's IPs sit behind a known
		// CDN/WAF/cloud provider -- on by default (options.cdnCheck), since
		// it's a local dataset lookup with no traffic to the target at all,
		// unlike every opt-in step below. Informational only: it doesn't
		// change what gets scanned, just what the operator sees about it
		// (an "open" web port that's actually a CDN edge, not the origin,
		// is worth knowing before testing it). Skips cleanly if cdncheck
		// isn't installed.
		if cfg.Options.cdnCheckOrDefault(true) {
			cdnFile := filepath.Join(outDir, fmt.Sprintf("03b_cdncheck_%d.json", gi))
			sr := runExternal("host", "cdncheck", ports, "cdncheck", cdncheckArgs(expandFile), cdnFile)
			if sr.Status == "ok" {
				if n := len(mustLines(cdnFile)); n > 0 {
					ioutil.Warn("cdncheck %s: %d IP(s) behind a known CDN/WAF/cloud provider, see %s", ports, n, cdnFile)
				}
			}
			steps = append(steps, sr)
		}

		results, err := readScanResults(portscanFile)
		if err != nil {
			steps = append(steps, stepResult{Kind: "host", Name: "classify-services", Target: ports, Status: "error", Detail: err.Error()})
			continue
		}
		for _, r := range results {
			switch {
			case portscan.IsWebPort(r.Port):
				webEntries = append(webEntries, targetEntry{Target: portscan.WebBaseURL(r.Host, r.Port)})
			case portscan.IsUncommonPort(r.Port):
				detail := fmt.Sprintf("uncommon/specialty service on port %d — follow up manually", r.Port)
				if r.Banner != "" {
					detail += "; banner: " + r.Banner
				}
				steps = append(steps, stepResult{
					Kind: "host", Name: "flag-uncommon-service",
					Target: fmt.Sprintf("%s:%d", r.Host, r.Port), Status: "ok", Detail: detail,
				})
			case portscan.IsBeanShellBanner(r.Banner):
				// BeanShell has no fixed/assigned port (docs/methodology.md),
				// so it can't be caught by the uncommonPorts list above --
				// only the banner gives it away. An exposed one with no auth
				// is an immediate unauthenticated RCE: anything sent to it
				// runs as arbitrary Java/BeanShell.
				steps = append(steps, stepResult{
					Kind: "host", Name: "flag-beanshell",
					Target: fmt.Sprintf("%s:%d", r.Host, r.Port), Status: "ok",
					Detail: fmt.Sprintf("BeanShell interactive server exposed on port %d — unauthenticated remote code execution risk, follow up manually; banner: %s", r.Port, r.Banner),
				})
			}
			if r.Banner != "" && !portscan.IsWebPort(r.Port) {
				target := fmt.Sprintf("%s:%d", r.Host, r.Port)
				vulnxFile := filepath.Join(outDir, "vulnx_"+safeName(target)+".json")
				steps = append(steps, runExternal("host", "vulnx", target, "vulnx",
					vulnxSearchArgs(r.Banner), vulnxFile))
			}
			if cfg.Options.easyWinsOrDefault(false) && !portscan.IsWebPort(r.Port) {
				// methodology.md's "easy wins" pass: default creds, common
				// misconfigs. Off by default (options.easyWins/-easy-wins) --
				// unlike vulnx above, this sends real probes against the
				// service, not a lookup against a third-party API, so it's
				// opt-in and kept deliberately rate-limited regardless (see
				// nucleiEasyWinsArgs). Runs independent of whether a banner
				// was grabbed: nuclei's own templates identify the service.
				target := fmt.Sprintf("%s:%d", r.Host, r.Port)
				easyWinsFile := filepath.Join(outDir, "easywins_"+safeName(target)+".json")
				steps = append(steps, runExternal("host", "nuclei", target, "nuclei",
					nucleiEasyWinsArgs(r.Host, r.Port), easyWinsFile))
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
		steps = append(steps, runWebStage(webCfg, webDir, hostScopeFile)...)
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
		return ipexpand.Run([]string{"-l", rawFile, "-o", expandFile})
	}))

	resolveFile := filepath.Join(outDir, "02_excluded_resolve.txt")
	steps = append(steps, runStep("host", "resolve-excluded", "", resolveFile, func() error {
		return resolve.Run([]string{"-l", expandFile, "-reverse", "-o", resolveFile})
	}))

	if err := traceroute.CheckRawICMPAvailable(); err != nil {
		steps = append(steps, skipStep("host", "traceroute-excluded", "",
			fmt.Sprintf("no raw ICMP socket available (%v) -- needs CAP_NET_RAW or root", err)))
		return steps
	}
	traceFile := filepath.Join(outDir, "03_excluded_traceroute.json")
	steps = append(steps, runStep("host", "traceroute-excluded", "", traceFile, func() error {
		return traceroute.Run([]string{"-l", expandFile, "-json", "-o", traceFile})
	}))
	return steps
}

// readScanResults reads a portscan -json output file back into portscan.Results.
func readScanResults(path string) ([]portscan.Result, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // the portscan step itself already recorded the error
		}
		return nil, err
	}
	defer f.Close()

	var results []portscan.Result
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r portscan.Result
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

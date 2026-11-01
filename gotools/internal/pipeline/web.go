package pipeline

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/domains"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/fuzz"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/gau"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/probe"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/robots"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/snyk"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/subdomains"
)

// runWebStage drives domain/URL discovery and content/version checks against
// config.Web entries, writing output under outDir ("<outputDir>/web/").
// Steps run in the order the methodology playbook documents by hand:
// domains -> gau -> sensitive/params -> robots -> fuzz -> snyk (optional).
// A target missing something a later step needs (e.g. no wordlist for fuzz)
// is recorded as "skipped", never treated as a fatal error for the run.
//
// hostScopeFile, when non-empty, is a plain IP/CIDR file built from the same
// invocation's "host" targets (see pipeline.go). playbook.md's manual flow
// runs every domain and subdomain it discovers through `scopecheck` against
// that host IP scope before probing it ("keep only the ones that resolve
// back into scope") -- a domain that happens to resolve outside the
// engagement's IP range (a third-party CDN, a stale DNS record) is dropped
// from gau/probe/sensitive/params instead of silently getting the same
// traffic as an in-scope one. Empty when there's no host IP scope to check
// against (a web-only config/run), in which case every domain found is
// used exactly as before -- the two stages stay independent.
func runWebStage(cfg *pipelineConfig, outDir string, hostScopeFile string) []stepResult {
	var steps []stepResult
	if len(cfg.Web) == 0 {
		return steps
	}

	// --- 00: target list (bare entries normalized to a base URL each) ---
	var rawTargets []string
	for _, e := range cfg.Web {
		if e.Target == "" {
			continue
		}
		rawTargets = append(rawTargets, baseURL(e.Target))
	}
	targetsFile := filepath.Join(outDir, "00_targets.txt")
	if err := writeLinesFile(targetsFile, rawTargets); err != nil {
		return append(steps, stepResult{Kind: "web", Name: "targets", Status: "error", Detail: err.Error()})
	}

	// --- 01: domains ---
	domainsFile := filepath.Join(outDir, "01_domains.txt")
	steps = append(steps, runStep("web", "domains", "", domainsFile, func() error {
		return domains.Run([]string{"-l", targetsFile, "-o", domainsFile})
	}))
	ds, _ := ioutil.InputLines(domainsFile)
	ds, steps = filterDomainsInScope(ds, hostScopeFile, outDir, "domains", steps)

	// --- 01b: subdomains (passive always; active too if options.subdomainsWordlist
	// is set), per domain, merged. Widens the domain list gau (below) and probe
	// (next) operate on; robots/fuzz stay scoped to the explicit web targets, so
	// discovering 50 subdomains doesn't silently blow up active traffic.
	allDomains := append([]string(nil), ds...)
	if len(ds) == 0 {
		steps = append(steps, skipStep("web", "subdomains", "", "no domains extracted from targets"))
	} else {
		discovered := map[string]struct{}{}
		var discoveredAll []string
		for _, d := range ds {
			d := d
			subFile := filepath.Join(outDir, "01b_subdomains_"+safeName(d)+".txt")
			subArgs := []string{"-d", d, "-o", subFile}
			if cfg.Options.SubdomainsWordlist != "" {
				subArgs = append(subArgs, "-w", cfg.Options.SubdomainsWordlist)
			} else {
				subArgs = append(subArgs, "-active=false")
			}
			steps = append(steps, runStep("web", "subdomains", d, subFile, func() error {
				return subdomains.Run(subArgs)
			}))
			for _, s := range mustLines(subFile) {
				if _, dup := discovered[s]; dup {
					continue
				}
				discovered[s] = struct{}{}
				discoveredAll = append(discoveredAll, s)
			}
		}
		discoveredAll, steps = filterDomainsInScope(discoveredAll, hostScopeFile, outDir, "subdomains", steps)
		allDomains = append(allDomains, discoveredAll...)
	}
	allDomains = ioutil.DedupStrings(allDomains)

	// --- 01c: probe (recon on root) for every domain + discovered subdomain ---
	if len(allDomains) == 0 {
		steps = append(steps, skipStep("web", "probe", "", "no domains to probe"))
	} else {
		probeTargetsFile := filepath.Join(outDir, "01c_probe_targets.txt")
		probeFile := filepath.Join(outDir, "01c_probe.json")
		if err := writeLinesFile(probeTargetsFile, allDomains); err != nil {
			steps = append(steps, stepResult{Kind: "web", Name: "probe", Status: "error", Detail: err.Error()})
		} else {
			probeArgs := []string{"-l", probeTargetsFile, "-json", "-o", probeFile,
				"-timeout", cfg.Options.timeoutDuration(10 * time.Second).String(),
				"-insecure=" + strconv.FormatBool(cfg.Options.insecureOrDefault(true)),
			}
			steps = append(steps, runStep("web", "probe", "", probeFile, func() error {
				return probe.Run(probeArgs)
			}))
		}
	}

	// --- 02: gau, per domain AND discovered subdomain, merged into one file ---
	allURLsFile := filepath.Join(outDir, "02_all_urls.txt")
	var allURLs []string
	if len(allDomains) == 0 {
		steps = append(steps, skipStep("web", "gau", "", "no domains extracted from targets (bare-IP targets skip gau/sensitive/params, which key off a resolvable domain)"))
	} else {
		seen := map[string]struct{}{}
		for _, d := range allDomains {
			d := d
			gauFile := filepath.Join(outDir, "02_gau_"+safeName(d)+".txt")
			gauTimeout := cfg.Options.timeoutDuration(90 * time.Second).String()
			steps = append(steps, runStep("web", "gau", d, gauFile, func() error {
				return gau.Run([]string{"-d", d, "-sub", "-o", gauFile, "-timeout", gauTimeout})
			}))
			for _, l := range mustLines(gauFile) {
				if _, dup := seen[l]; dup {
					continue
				}
				seen[l] = struct{}{}
				allURLs = append(allURLs, l)
			}
		}
		if err := writeLinesFile(allURLsFile, allURLs); err != nil {
			steps = append(steps, stepResult{Kind: "web", Name: "merge-urls", Status: "error", Detail: err.Error()})
		}
	}

	// --- 03/04: sensitive + params, both over the merged URL list ---
	if len(allURLs) == 0 {
		steps = append(steps, skipStep("web", "sensitive", "", "no URLs collected"))
		steps = append(steps, skipStep("web", "params", "", "no URLs collected"))
	} else {
		sensitiveFile := filepath.Join(outDir, "03_sensitive.txt")
		steps = append(steps, runStep("web", "sensitive", "", sensitiveFile, func() error {
			return gau.RunSensitive([]string{"-l", allURLsFile, "-o", sensitiveFile})
		}))

		// params has no -o flag; it always prints via fmt.Println, so capture
		// the real stdout for the duration of the call.
		paramsFile := filepath.Join(outDir, "04_params.txt")
		steps = append(steps, runStep("web", "params", "", paramsFile, func() error {
			out, runErr := captureStdout(func() error {
				return gau.RunParams([]string{"-l", allURLsFile})
			})
			if werr := os.WriteFile(paramsFile, []byte(out), 0o644); werr != nil {
				return werr
			}
			return runErr
		}))
	}

	// --- 05: robots, all targets in one run (also stdout-only, same capture
	// trick). One invocation, not one per target, so robots can fetch the
	// targets' robots.txt files concurrently instead of waiting out each dead
	// host's timeout in turn.
	var robotsBases []string
	for _, e := range cfg.Web {
		if e.Target != "" {
			robotsBases = append(robotsBases, baseURL(e.Target))
		}
	}
	if len(robotsBases) > 0 {
		robotsArgs := []string{
			"-timeout", cfg.Options.timeoutDuration(15 * time.Second).String(),
			// bool flags need the "=value" form in one token: "-insecure value"
			// (two tokens) leaves "value" as a stray positional arg, which
			// robots would wrongly treat as an extra base URL to probe.
			"-insecure=" + strconv.FormatBool(cfg.Options.insecureOrDefault(true)),
		}
		robotsArgs = append(robotsArgs, ioutil.DedupStrings(robotsBases)...) // positional base URLs after all flags
		robotsFile := filepath.Join(outDir, "05_robots.txt")
		steps = append(steps, runStep("web", "robots", "", robotsFile, func() error {
			out, runErr := captureStdout(func() error {
				return robots.Run(robotsArgs)
			})
			if werr := os.WriteFile(robotsFile, []byte(out), 0o644); werr != nil {
				return werr
			}
			return runErr
		}))
	}

	// --- 06: fuzz, per target that resolves to a wordlist ---
	for _, e := range cfg.Web {
		if e.Target == "" {
			continue
		}
		wordlist := resolveWordlist(e, cfg.Options)
		if wordlist == "" {
			steps = append(steps, skipStep("web", "fuzz", e.Target,
				`no wordlist configured (set this target's "wordlist" or options.wordlist)`))
			continue
		}

		fuzzFile := filepath.Join(outDir, "06_fuzz_"+safeName(e.Target)+".json")
		args := []string{"-u", fuzzURL(e.Target), "-w", wordlist, "-json", "-o", fuzzFile}

		targetScope := e.Scope
		if targetScope == "" {
			targetScope = cfg.Options.Scope
		}
		if targetScope != "" {
			args = append(args, "-scope", targetScope)
		}
		for _, ext := range e.Extensions {
			args = append(args, "-e", ext)
		}
		if len(e.Extensions) == 0 && cfg.Options.autoExtensionsOrDefault(true) {
			args = append(args, "-ext-auto") // tech-detect hints + live verification
		}
		if cfg.Options.Concurrency > 0 {
			args = append(args, "-c", strconv.Itoa(cfg.Options.Concurrency))
		}
		if cfg.Options.Rate > 0 {
			args = append(args, "-rate", strconv.Itoa(cfg.Options.Rate))
		}
		if cfg.Options.RateGlobal > 0 {
			args = append(args, "-rate-global", strconv.Itoa(cfg.Options.RateGlobal))
		}
		args = append(args, "-timeout", cfg.Options.timeoutDuration(10*time.Second).String())
		args = append(args, "-insecure="+strconv.FormatBool(cfg.Options.insecureOrDefault(true)))
		if cfg.Options.Proxy != "" {
			args = append(args, "-proxy", cfg.Options.Proxy)
		}

		args = append(args, resumeStateArgs(fuzzFile)...)
		steps = append(steps, runStep("web", "fuzz", e.Target, fuzzFile, func() error {
			return fuzz.Run(args)
		}))
	}

	// --- 07: snyk, only for targets that supply advisory info ---
	for _, e := range cfg.Web {
		if e.Target == "" {
			continue
		}
		if e.SnykURL == "" || e.SnykVersion == "" {
			steps = append(steps, skipStep("web", "snyk", e.Target, `no "snykUrl"/"snykVersion" set for this target`))
			continue
		}
		snykFile := filepath.Join(outDir, "07_snyk_"+safeName(e.Target)+".txt")
		snykArgs := []string{
			"-url", e.SnykURL, "-version", e.SnykVersion,
			"-timeout", cfg.Options.timeoutDuration(30 * time.Second).String(),
			"-insecure=" + strconv.FormatBool(cfg.Options.insecureOrDefault(true)),
		}
		steps = append(steps, runStep("web", "snyk", e.Target, snykFile, func() error {
			out, runErr := captureStdout(func() error {
				return snyk.Run(snykArgs)
			})
			if werr := os.WriteFile(snykFile, []byte(out), 0o644); werr != nil {
				return werr
			}
			return runErr
		}))
	}

	return steps
}

// filterDomainsInScope is the host<->web scope cross-link: when
// hostScopeFile is set, it runs names through domains.RunScopeCheck against
// that host IP scope and returns only the ones that resolve into it (plus
// the steps slice with a "scopecheck" step result appended); with no scope
// file, or nothing to check, names is returned unchanged and steps
// untouched -- the two stages stay fully independent, same as before this
// existed.
//
// A scopecheck failure (e.g. a malformed scope file) fails open: names is
// returned unchanged rather than silently dropping every domain because the
// check itself couldn't run.
func filterDomainsInScope(names []string, hostScopeFile, outDir, label string, steps []stepResult) ([]string, []stepResult) {
	if hostScopeFile == "" || len(names) == 0 {
		return names, steps
	}

	inFile := filepath.Join(outDir, "scopecheck_"+label+"_in.txt")
	outFile := filepath.Join(outDir, "scopecheck_"+label+"_out.txt")
	if err := writeLinesFile(inFile, names); err != nil {
		return names, append(steps, stepResult{Kind: "web", Name: "scopecheck", Target: label, Status: "error", Detail: err.Error()})
	}

	sr := runStep("web", "scopecheck", label, outFile, func() error {
		return domains.RunScopeCheck([]string{"-l", inFile, "-scope", hostScopeFile, "-o", outFile})
	})
	steps = append(steps, sr)
	if sr.Status != "ok" {
		return names, steps // fail open: don't drop anything over a broken check
	}

	kept, err := ioutil.InputLines(outFile)
	if err != nil {
		return names, steps
	}
	return kept, steps
}

// resolveWordlist picks the wordlist for one fuzz call: the target's own
// override, else the pipeline-wide default, else "" (meaning: skip fuzz for
// this target rather than guess a wordlist).
func resolveWordlist(e targetEntry, opts pipelineOptions) string {
	if e.Wordlist != "" {
		return e.Wordlist
	}
	return opts.Wordlist
}

// baseURL normalizes a target entry into a full base URL: a target that
// already has a scheme is kept as-is (minus a trailing slash); a bare
// domain or IP defaults to https://, matching srt's insecure-by-default
// convention elsewhere (e.g. fuzz/robots/dirlist's -insecure=true default).
func baseURL(target string) string {
	if strings.Contains(target, "://") {
		return strings.TrimSuffix(target, "/")
	}
	return "https://" + target
}

// fuzzURL builds the FUZZ-templated URL fuzz -u expects.
func fuzzURL(target string) string {
	return baseURL(target) + "/FUZZ"
}

// safeName turns a target string into a filesystem-safe fragment for output
// filenames.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// mustLines reads a file's lines, treating a read error as "no lines" since
// callers use it right after a step that may have failed to write anything.
func mustLines(path string) []string {
	lines, err := ioutil.InputLines(path)
	if err != nil {
		return nil
	}
	return lines
}

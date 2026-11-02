package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/validate"
	"github.com/trike33/srt-cheatsheet/gotools/internal/wordlists"
)

// runWebStage drives domain/URL discovery and content/version checks against
// config.Web entries, writing output under outDir ("<outputDir>/web/").
// Steps run in the order the methodology playbook documents by hand:
// domains -> gau -> sensitive/params -> robots -> fuzz -> snyk (optional).
// A target missing something a later step needs (e.g. no wordlist for fuzz)
// is recorded as "skipped", never treated as a fatal error for the run.
//
// options.contentScan/-content-scan (off by default) switches the
// sensitive step from extension-based filtering to fetching every merged
// URL and scanning its body for secrets (sensitive -content) -- off by
// default since it turns one string-classification step into a request
// per URL in what can be a very large gau dump.
//
// options.tlsx/-no-tlsx (on by default) widens the discovered-domain pool
// with every explicit web target's certificate SAN/CN entries, alongside
// crt.sh/active brute force -- one TLS handshake per target, the same
// order of traffic as probe's own one request per target.
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
	// is set), per domain, merged with tlsx's cert SAN/CN extraction (01d,
	// below) into one discovered-names pool. Widens the domain list gau
	// (below) and probe (next) operate on; robots/fuzz stay scoped to the
	// explicit web targets, so discovering 50 subdomains doesn't silently
	// blow up active traffic.
	allDomains := append([]string(nil), ds...)
	discovered := map[string]struct{}{}
	var discoveredAll []string
	addDiscovered := func(s string) {
		if _, dup := discovered[s]; dup {
			return
		}
		discovered[s] = struct{}{}
		discoveredAll = append(discoveredAll, s)
	}

	if len(ds) == 0 {
		steps = append(steps, skipStep("web", "subdomains", "", "no domains extracted from targets"))
	} else {
		for _, d := range ds {
			d := d
			subFile := filepath.Join(outDir, "01b_subdomains_"+safeName(d)+".txt")
			subArgs := []string{"-d", d, "-o", subFile}
			// Active brute force is on by default. When dnsx is installed it
			// does that job (same wordlist, plus wildcard filtering -- see
			// dnsDiscoverDomains), so the native brute force steps aside
			// rather than sending the same queries twice.
			if wl := subdomainWordlist(cfg, outDir); wl != "" && !dnsxAvailable() {
				subArgs = append(subArgs, "-w", wl)
			} else {
				subArgs = append(subArgs, "-active=false")
			}
			steps = append(steps, runStep("web", "subdomains", d, subFile, func() error {
				return subdomains.Run(subArgs)
			}))
			for _, s := range mustLines(subFile) {
				addDiscovered(s)
			}
		}
	}

	// --- 01d: tlsx (another passive-ish discovery source: a certificate's
	// SAN/CN entries) over every explicit web target, on by default --
	// options.tlsx/-no-tlsx. One TLS handshake per target is the same
	// order of traffic as probe's own one HTTP request per target, not
	// the "sends real exploitation-adjacent probes" category -easy-wins/
	// -content-scan are opt-in for. A bare-IP web target still has a
	// host:port to connect to, so this runs regardless of whether any
	// domain was extracted above.
	tlsxNames, tlsxSteps := tlsxWidenDomains(cfg, outDir)
	steps = append(steps, tlsxSteps...)
	for _, s := range tlsxNames {
		addDiscovered(s)
	}

	// --- 01e: subfinder / dnsx / alterx: more subdomain sources, each an
	// optional external tool that skips cleanly when not installed.
	dnsNames, dnsSteps := dnsDiscoverDomains(cfg, ds, discoveredAll, outDir)
	steps = append(steps, dnsSteps...)
	for _, s := range dnsNames {
		addDiscovered(s)
	}

	discoveredAll, steps = filterDomainsInScope(discoveredAll, hostScopeFile, outDir, "subdomains", steps)
	allDomains = append(allDomains, discoveredAll...)
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
		if !cfg.Options.fuzzOrDefault(true) {
			steps = append(steps, skipStep("web", "fuzz", e.Target, "disabled (options.fuzz:false / -no-fuzz)"))
			continue
		}
		wordlist := resolveWordlist(e, cfg.Options)
		if wordlist == "" {
			// No wordlist configured: fall back to the common.txt embedded
			// in the binary rather than skipping the step.
			var werr error
			if wordlist, werr = wordlists.DirectoriesFile(outDir); werr != nil {
				steps = append(steps, skipStep("web", "fuzz", e.Target, "embedded wordlist: "+werr.Error()))
				continue
			}
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

	// --- 06b: merge every endpoint source into one list (gau's archived
	// URLs + robots/sitemap hits + fuzz hits), then 03/04: sensitive +
	// params over that merged list -- so they see what the active steps
	// found, not just what Wayback remembers.
	var fuzzFiles []string
	for _, e := range cfg.Web {
		if e.Target != "" {
			fuzzFiles = append(fuzzFiles, filepath.Join(outDir, "06_fuzz_"+safeName(e.Target)+".json"))
		}
	}
	endpoints := collectEndpoints(allURLs, filepath.Join(outDir, "05_robots.txt"), fuzzFiles)
	endpointsFile := filepath.Join(outDir, "06b_endpoints.txt")
	if len(endpoints) > 0 {
		if err := writeLinesFile(endpointsFile, endpoints); err != nil {
			steps = append(steps, stepResult{Kind: "web", Name: "merge-endpoints", Status: "error", Detail: err.Error()})
			endpoints = nil
		} else {
			steps = append(steps, stepResult{Kind: "web", Name: "merge-endpoints", Status: "ok",
				Detail: fmt.Sprintf("%d endpoints (gau %d + robots/sitemap/fuzz)", len(endpoints), len(allURLs))})
		}
	}
	allURLs, allURLsFile = endpoints, endpointsFile

	// --- 06c: validate -- re-probe every endpoint with native httpx-style
	// requests and keep only real ones. Archived and sitemap URLs may be
	// dead, and a soft-404 site answers 200 (or a redirect, or 403) for any
	// path, so a status code alone proves nothing; `validate` fingerprints
	// each host's not-found response and drops matches. sensitive/params
	// then run over the valid list only.
	if len(endpoints) > 0 && cfg.Options.validateOrDefault(true) {
		validFile := filepath.Join(outDir, "06c_valid_endpoints.txt")
		rejectedFile := filepath.Join(outDir, "06c_rejected.txt")
		maxN := cfg.Options.ValidateMax
		if maxN <= 0 {
			maxN = 10000
		}
		vArgs := []string{"-l", endpointsFile, "-o", validFile, "-silent", "-rejected", rejectedFile,
			"-max", strconv.Itoa(maxN),
			"-timeout", cfg.Options.timeoutDuration(10 * time.Second).String(),
			"-insecure=" + strconv.FormatBool(cfg.Options.insecureOrDefault(true)),
		}
		if cfg.Options.Concurrency > 0 {
			vArgs = append(vArgs, "-c", strconv.Itoa(cfg.Options.Concurrency))
		}
		vs := runStep("web", "validate", "", validFile, func() error { return validate.Run(vArgs) })
		steps = append(steps, vs)
		if vs.Status == "ok" {
			allURLs, allURLsFile = mustLines(validFile), validFile
		}
	}

	// --- 03/04: sensitive + params over the merged endpoint list ---
	if len(allURLs) == 0 {
		steps = append(steps, skipStep("web", "sensitive", "", "no endpoints collected"))
		steps = append(steps, skipStep("web", "params", "", "no endpoints collected"))
	} else {
		sensitiveFile, sensitiveArgs := sensitiveArgsFor(cfg, allURLsFile, outDir)
		steps = append(steps, runStep("web", "sensitive", "", sensitiveFile, func() error {
			return gau.RunSensitive(sensitiveArgs)
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

// tlsxWidenDomains runs tlsx over every explicit web target (when
// options.tlsx/-no-tlsx allows it) and returns the certificate SAN/CN
// names it found, plus the steps recording each call -- for the caller to
// merge into its own discovered-names pool alongside crt.sh/active brute
// force. Returns (nil, nil) when disabled, so the caller's merge loop is a
// no-op. Pulled out of runWebStage so it's testable without the real
// domains/subdomains/probe/gau network calls that function makes.
func tlsxWidenDomains(cfg *pipelineConfig, outDir string) (names []string, steps []stepResult) {
	if !cfg.Options.tlsxOrDefault(true) {
		return nil, nil
	}
	for _, e := range cfg.Web {
		if e.Target == "" {
			continue
		}
		target := baseURL(e.Target)
		tlsxFile := filepath.Join(outDir, "01d_tlsx_"+safeName(target)+".txt")
		steps = append(steps, runExternal("web", "tlsx", target, "tlsx", tlsxDiscoveryArgs(target), tlsxFile))
		names = append(names, mustLines(tlsxFile)...)
	}
	return names, steps
}

// subdomainWordlist returns the path of the label wordlist active subdomain
// brute force should use, or "" when active brute force is disabled
// (options.subdomainsActive:false/-no-active-subdomains). The user's own
// options.subdomainsWordlist wins; otherwise the SecLists top-20000 list
// embedded in the binary is written into outDir.
func subdomainWordlist(cfg *pipelineConfig, outDir string) string {
	if !cfg.Options.subdomainsActiveOrDefault(true) {
		return ""
	}
	if cfg.Options.SubdomainsWordlist != "" {
		return cfg.Options.SubdomainsWordlist
	}
	p, err := wordlists.SubdomainsFile(outDir)
	if err != nil {
		ioutil.Warn("embedded subdomain wordlist: %v (active brute force skipped)", err)
		return ""
	}
	return p
}

// dnsxAvailable reports whether dnsx is on PATH (and so owns brute force).
func dnsxAvailable() bool {
	_, err := exec.LookPath("dnsx")
	return err == nil
}

// dnsDiscoverDomains widens subdomain discovery with ProjectDiscovery's DNS
// tools, per domain in ds:
//
//   - subfinder (options.subfinder, on by default): passive third-party
//     sources only, no traffic to the target.
//   - dnsx brute force (on by default, options.subdomainsActive/
//     -no-active-subdomains; wordlist: options.subdomainsWordlist, else the
//     embedded SecLists top-20000 list): resolves wordlist.domain, then a
//     second dnsx pass with -wd drops names a wildcard record answered for,
//     which the native brute force can't tell apart from real hosts.
//   - alterx permutations (options.permutations, off by default): mutates
//     the names found so far for that domain, resolves them with dnsx and
//     wildcard-filters the result. Off by default because every
//     permutation is a DNS query.
//
// known is the pool discovered so far (native subdomains + tlsx), the
// permutation input. Returns the new names plus a step per call.
func dnsDiscoverDomains(cfg *pipelineConfig, ds, known []string, outDir string) (names []string, steps []stepResult) {
	wild := func(d, in, out string) []string {
		steps = append(steps, runExternal("web", "dnsx-wildcard", d, "dnsx", dnsxWildcardArgs(in, d), out))
		return mustLines(out)
	}
	for _, d := range ds {
		safe := safeName(d)
		var found []string
		if cfg.Options.subfinderOrDefault(true) {
			f := filepath.Join(outDir, "01e_subfinder_"+safe+".txt")
			steps = append(steps, runExternal("web", "subfinder", d, "subfinder", subfinderArgs(d), f))
			found = append(found, mustLines(f)...)
		}
		if wl := subdomainWordlist(cfg, outDir); wl != "" {
			brute := filepath.Join(outDir, "01e_dnsx_brute_"+safe+".txt")
			steps = append(steps, runExternal("web", "dnsx-brute", d, "dnsx", dnsxBruteArgs(d, wl), brute))
			if len(mustLines(brute)) > 0 {
				found = append(found, wild(d, brute, filepath.Join(outDir, "01e_dnsx_brute_"+safe+".filtered.txt"))...)
			}
		}
		if cfg.Options.permutationsOrDefault(false) {
			var seeds []string
			for _, k := range append(append([]string(nil), known...), found...) {
				if k == d || strings.HasSuffix(k, "."+d) {
					seeds = append(seeds, k)
				}
			}
			if len(seeds) > 0 {
				seedFile := filepath.Join(outDir, "01e_alterx_seeds_"+safe+".txt")
				altFile := filepath.Join(outDir, "01e_alterx_"+safe+".txt")
				resolved := filepath.Join(outDir, "01e_alterx_resolved_"+safe+".txt")
				if err := writeLinesFile(seedFile, ioutil.DedupStrings(seeds)); err == nil {
					steps = append(steps, runExternal("web", "alterx", d, "alterx", alterxArgs(seedFile), altFile))
					if len(mustLines(altFile)) > 0 {
						steps = append(steps, runExternal("web", "dnsx-resolve", d, "dnsx", dnsxResolveArgs(altFile), resolved))
						if len(mustLines(resolved)) > 0 {
							found = append(found, wild(d, resolved, filepath.Join(outDir, "01e_alterx_filtered_"+safe+".txt"))...)
						}
					}
				}
			}
		}
		names = append(names, found...)
	}
	return ioutil.DedupStrings(names), steps
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

// sensitiveArgsFor builds the `sensitive` command's argv for the merged-URL
// step: plain extension-based filtering by default (unchanged from before
// options.contentScan existed), or -- with options.contentScan/
// -content-scan -- the fetch-every-URL-and-scan-for-secrets mode instead
// (sensitive -content), writing JSON since content hits are structured
// rather than a plain URL list. -c reuses options.Concurrency the same way
// the fuzz step does, rather than adding a second concurrency knob just for
// this.
func sensitiveArgsFor(cfg *pipelineConfig, allURLsFile, outDir string) (outFile string, args []string) {
	outFile = filepath.Join(outDir, "03_sensitive.txt")
	args = []string{"-l", allURLsFile, "-o", outFile}
	if !cfg.Options.contentScanOrDefault(false) {
		return outFile, args
	}

	outFile = filepath.Join(outDir, "03_sensitive.json")
	args = []string{
		"-l", allURLsFile, "-o", outFile, "-content", "-json",
		"-timeout", cfg.Options.timeoutDuration(15 * time.Second).String(),
		"-insecure=" + strconv.FormatBool(cfg.Options.insecureOrDefault(true)),
	}
	if cfg.Options.Concurrency > 0 {
		args = append(args, "-c", strconv.Itoa(cfg.Options.Concurrency))
	}
	return outFile, args
}

// robotsHitRe matches a `robots` probe line: "<url> [status] [length]".
var robotsHitRe = regexp.MustCompile(`^(https?://\S+) \[(\d{3})\] \[\d+\]\s*$`)

// collectEndpoints merges every endpoint source into one deduplicated list:
// the URLs `robots` probed (robots.txt paths plus sitemap URLs) that
// answered 2xx/3xx/401/403, every `fuzz` hit, and gau's archived URLs.
// Active hits come first so a cap on how many get validated drops archived
// URLs first, never the ones an active step just saw.
//
// Nothing here proves a URL is real -- that is the `validate` step's job
// (soft-404 aware), which runs over this list next.
func collectEndpoints(gauURLs []string, robotsFile string, fuzzFiles []string) []string {
	var out []string
	for _, l := range mustLines(robotsFile) {
		m := robotsHitRe.FindStringSubmatch(strings.TrimSpace(ansiRe.ReplaceAllString(l, "")))
		if m == nil {
			continue
		}
		if st, _ := strconv.Atoi(m[2]); st < 400 || st == 401 || st == 403 {
			out = append(out, m[1])
		}
	}
	for _, f := range fuzzFiles {
		for _, l := range mustLines(f) {
			var r struct {
				URL string `json:"url"`
			}
			if json.Unmarshal([]byte(l), &r) == nil && r.URL != "" {
				out = append(out, r.URL)
			}
		}
	}
	out = append(out, gauURLs...)
	return ioutil.DedupStrings(out)
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

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

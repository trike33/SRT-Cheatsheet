package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

// targetEntry is one item in a pipelineConfig's "host" or "web" list. It can
// be written as a bare string ("1.2.3.4", "example.com") or as a JSON object
// carrying per-target overrides; UnmarshalJSON accepts both so a config file
// can mix plain entries with ones that need extra settings.
type targetEntry struct {
	Target      string   `json:"target"`
	Ports       string   `json:"ports,omitempty"`
	Wordlist    string   `json:"wordlist,omitempty"`
	Scope       string   `json:"scope,omitempty"`
	Extensions  []string `json:"extensions,omitempty"`
	SnykURL     string   `json:"snykUrl,omitempty"`
	SnykVersion string   `json:"snykVersion,omitempty"`
	// Excluded marks a "host" entry excluded-but-tracked, the way a
	// Burp/program scope does: never actively probed (no portscan, no WEB
	// hand-off), only reverse DNS + a route trace. See methodology.md.
	Excluded bool `json:"excluded,omitempty"`
}

func (t *targetEntry) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		t.Target = s
		return nil
	}
	// Local named type to dodge UnmarshalJSON's own infinite recursion.
	type raw targetEntry
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return fmt.Errorf("target entry must be a string or object: %w", err)
	}
	*t = targetEntry(r)
	return nil
}

// pipelineOptions carries pipeline-wide defaults. Any target entry field
// with the same name overrides these for that one target.
type pipelineOptions struct {
	OutputDir             string `json:"outputDir,omitempty"`
	Concurrency           int    `json:"concurrency,omitempty"`
	Rate                  int    `json:"rate,omitempty"`
	RateGlobal            int    `json:"rateGlobal,omitempty"`
	Timeout               string `json:"timeout,omitempty"`
	Insecure              *bool  `json:"insecure,omitempty"`
	Wordlist              string `json:"wordlist,omitempty"`
	Scope                 string `json:"scope,omitempty"`
	Ports                 string `json:"ports,omitempty"`
	Proxy                 string `json:"proxy,omitempty"`
	AutoExtensions        *bool  `json:"autoExtensions,omitempty"`        // fuzz -ext-auto for targets without explicit "extensions" (default true)
	SubdomainsWordlist    string `json:"subdomainsWordlist,omitempty"`    // subdomain-label wordlist (e.g. www, api, dev); default: the embedded SecLists top-20000 list
	Crawl                 *bool  `json:"crawl,omitempty"`                 // WEB stage: crawl the explicit web targets with katana (default true; skipped if katana isn't installed)
	CrawlDepth            int    `json:"crawlDepth,omitempty"`            // WEB stage: katana crawl depth (default 3)
	Validate              *bool  `json:"validate,omitempty"`              // WEB stage: re-probe the merged endpoint list and keep only real ones, dropping soft-404s, before sensitive/params (default true)
	ValidateMax           int    `json:"validateMax,omitempty"`           // WEB stage: check at most this many endpoints (default 10000; active-step hits come first, archived URLs last)
	Fuzz                  *bool  `json:"fuzz,omitempty"`                  // WEB stage: directory/file brute force of the explicit web targets (default true; wordlist: per-target/options.wordlist, else the embedded SecLists common.txt)
	SubdomainsActive      *bool  `json:"subdomainsActive,omitempty"`      // WEB stage: active DNS brute force of subdomains (default true; passive sources always run regardless)
	EasyWins              *bool  `json:"easyWins,omitempty"`              // HOST stage: run nuclei's default-login/misconfig/exposure pass on non-web ports (default true; rate-limited and bounded -- set false to avoid sending probes beyond recon)
	Subfinder             *bool  `json:"subfinder,omitempty"`             // WEB stage: passive subdomain discovery via subfinder (default true -- queries third-party sources, no traffic to the target)
	Permutations          *bool  `json:"permutations,omitempty"`          // WEB stage: alterx permutations of discovered names, resolved with dnsx (default false -- multiplies DNS queries)
	ContentScan           *bool  `json:"contentScan,omitempty"`           // WEB stage: fetch every merged URL and scan its body for secrets (sensitive -content) instead of just classifying by extension (default false -- fetches every URL, not just inspects a string)
	CDNCheck              *bool  `json:"cdnCheck,omitempty"`              // HOST stage: flag IPs behind a known CDN/WAF/cloud provider via cdncheck (default true -- a local dataset lookup, no traffic to the target at all)
	TLSX                  *bool  `json:"tlsx,omitempty"`                  // WEB stage: widen the discovered-domain pool with each target's cert SAN/CN entries via tlsx (default true -- one TLS handshake per target, same order of traffic as probe)
	ParamDiscover         *bool  `json:"paramDiscover,omitempty"`         // WEB stage: guess hidden GET parameters on the validated endpoint list via paramdiscover (default false -- a batch of extra requests per endpoint, capped by paramDiscoverMax/paramDiscoverTop)
	ParamDiscoverMax      int    `json:"paramDiscoverMax,omitempty"`      // WEB stage: probe at most this many validated endpoints (default 20)
	ParamDiscoverTop      int    `json:"paramDiscoverTop,omitempty"`      // WEB stage: try at most this many candidate names per endpoint (default 500, same "0/unset falls back to the default" convention as validateMax/crawlDepth)
	ActiveOnSubdomains    *bool  `json:"activeOnSubdomains,omitempty"`    // WEB stage: also run robots/fuzz/katana against probe-confirmed-live discovered subdomains, not just the explicit web targets (default false -- each one gets its own full active pass, capped by activeOnSubdomainsMax)
	ActiveOnSubdomainsMax int    `json:"activeOnSubdomainsMax,omitempty"` // WEB stage: with activeOnSubdomains, cap to this many live discovered subdomains, first-confirmed first (default 20)
	ContextWords          *bool  `json:"contextWords,omitempty"`          // WEB stage: fuzz -words-auto -- add curated per-host words from the detected tech stack/page title, plus words from the engagement name, to every fuzz wordlist (default true -- reuses probe's own request via -ext-auto's cache when that's also on, capped at 40 extra words/host)
	Dork                  *bool  `json:"dork,omitempty"`                  // WEB stage: Google dorking (gap 12) -- generate (and, with dorkAPIKey/dorkCX, actually run) a curated set of dork queries per explicit target's domain plus the engagement name (default false -- without credentials it sends no traffic and just writes search URLs to paste by hand, but it's still a new kind of step most runs don't want on unasked)
	DorkAPIKey            string `json:"dorkAPIKey,omitempty"`            // WEB stage: Google Custom Search API key for options.dork's -search (falls back to $SRT_GOOGLE_API_KEY)
	DorkCX                string `json:"dorkCX,omitempty"`                // WEB stage: Google Programmable Search Engine ID for options.dork's -search (falls back to $SRT_GOOGLE_CSE_ID)
}

// timeoutDuration parses Timeout, defaulting to def when unset or invalid.
func (o pipelineOptions) timeoutDuration(def time.Duration) time.Duration {
	if o.Timeout == "" {
		return def
	}
	d, err := time.ParseDuration(o.Timeout)
	if err != nil {
		ioutil.Warn("options.timeout %q invalid, using default %s: %v", o.Timeout, def, err)
		return def
	}
	return d
}

func (o pipelineOptions) autoExtensionsOrDefault(def bool) bool {
	if o.AutoExtensions == nil {
		return def
	}
	return *o.AutoExtensions
}

func (o pipelineOptions) easyWinsOrDefault(def bool) bool {
	if o.EasyWins == nil {
		return def
	}
	return *o.EasyWins
}

func (o pipelineOptions) crawlOrDefault(def bool) bool {
	if o.Crawl == nil {
		return def
	}
	return *o.Crawl
}

func (o pipelineOptions) validateOrDefault(def bool) bool {
	if o.Validate == nil {
		return def
	}
	return *o.Validate
}

func (o pipelineOptions) fuzzOrDefault(def bool) bool {
	if o.Fuzz == nil {
		return def
	}
	return *o.Fuzz
}

func (o pipelineOptions) subdomainsActiveOrDefault(def bool) bool {
	if o.SubdomainsActive == nil {
		return def
	}
	return *o.SubdomainsActive
}

func (o pipelineOptions) subfinderOrDefault(def bool) bool {
	if o.Subfinder == nil {
		return def
	}
	return *o.Subfinder
}

func (o pipelineOptions) permutationsOrDefault(def bool) bool {
	if o.Permutations == nil {
		return def
	}
	return *o.Permutations
}

func (o pipelineOptions) cdnCheckOrDefault(def bool) bool {
	if o.CDNCheck == nil {
		return def
	}
	return *o.CDNCheck
}

func (o pipelineOptions) tlsxOrDefault(def bool) bool {
	if o.TLSX == nil {
		return def
	}
	return *o.TLSX
}

func (o pipelineOptions) paramDiscoverOrDefault(def bool) bool {
	if o.ParamDiscover == nil {
		return def
	}
	return *o.ParamDiscover
}

func (o pipelineOptions) activeOnSubdomainsOrDefault(def bool) bool {
	if o.ActiveOnSubdomains == nil {
		return def
	}
	return *o.ActiveOnSubdomains
}

func (o pipelineOptions) contextWordsOrDefault(def bool) bool {
	if o.ContextWords == nil {
		return def
	}
	return *o.ContextWords
}

func (o pipelineOptions) dorkOrDefault(def bool) bool {
	if o.Dork == nil {
		return def
	}
	return *o.Dork
}

func (o pipelineOptions) contentScanOrDefault(def bool) bool {
	if o.ContentScan == nil {
		return def
	}
	return *o.ContentScan
}

func (o pipelineOptions) insecureOrDefault(def bool) bool {
	if o.Insecure == nil {
		return def
	}
	return *o.Insecure
}

// pipelineConfig is the top-level shape of a -c <file>.json pipeline input.
type pipelineConfig struct {
	Name    string          `json:"name"`
	Host    []targetEntry   `json:"host,omitempty"`
	Web     []targetEntry   `json:"web,omitempty"`
	Options pipelineOptions `json:"options,omitempty"`
}

// loadPipelineConfig reads and parses a pipeline JSON config file.
func loadPipelineConfig(path string) (*pipelineConfig, error) {
	if path == "" {
		return nil, ioutil.ErrMissing("-c <config.json> is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg pipelineConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &cfg, nil
}

// stepResult records what happened for one pipeline step, for the manifest.
type stepResult struct {
	Kind     string `json:"kind"` // "host" or "web"
	Name     string `json:"name"` // e.g. "ipexpand", "fuzz"
	Target   string `json:"target,omitempty"`
	Status   string `json:"status"` // "ok" | "error" | "skipped"
	Detail   string `json:"detail,omitempty"`
	Output   string `json:"output,omitempty"`
	Duration string `json:"duration"`
}

// manifest is the single JSON summary written at the end of a pipeline run.
type manifest struct {
	Name      string       `json:"name"`
	StartedAt time.Time    `json:"startedAt"`
	EndedAt   time.Time    `json:"endedAt"`
	Kinds     []string     `json:"kinds"`
	Steps     []stepResult `json:"steps"`
}

// runStep times fn, turns a returned error into a stepResult{Status:"error"},
// and otherwise reports "ok". Steps that need to report "skipped" return that
// stepResult directly instead of going through runStep.
func runStep(kind, name, target, output string, fn func() error) stepResult {
	key := stepKey(kind, name, target, output)
	if activeCheckpoint != nil && activeCheckpoint.has(key) {
		if _, statErr := os.Stat(output); output == "" || statErr == nil {
			reportStep(name, target, "resumed (already completed)", nil)
			return stepResult{Kind: kind, Name: name, Target: target, Output: output, Status: "ok", Detail: "resumed: already completed in a previous run", Duration: "0s"}
		}
	}
	start := time.Now()
	stopCapture := ioutil.CaptureWarnings()
	done := make(chan error, 1)
	go func() { done <- fn() }()

	var err error
	select {
	case err = <-done:
	case <-activeSkip.skipChan():
		// The step keeps running in a goroutine we no longer wait on --
		// any traffic/work it already started continues in the background
		// until it finishes on its own; we just stop blocking on it. Its
		// own Warn() output may land in a later step's captured warnings
		// instead of this one's, since the capture target has moved on by
		// then -- a cosmetic side effect of abandoning rather than killing it.
		warnings := stopCapture()
		reason := "user pressed '" + string(skipKey) + "' while it was running; abandoned, not killed -- it may still be finishing in the background"
		reportStep(name, target, "skipped: "+reason, warnings)
		recordUserSkip(key, kind, name, target, reason)
		return stepResult{
			Kind: kind, Name: name, Target: target, Output: output,
			Duration: time.Since(start).Round(time.Millisecond).String(),
			Status:   "skipped",
			Detail:   "skipped by user keypress while running; the step was abandoned, not killed, and may still be finishing in the background",
		}
	}
	warnings := stopCapture()
	sr := stepResult{
		Kind:     kind,
		Name:     name,
		Target:   target,
		Output:   output,
		Duration: time.Since(start).Round(time.Millisecond).String(),
		Status:   "ok",
	}
	if err != nil {
		sr.Status = "error"
		sr.Detail = err.Error()
		reportStep(name, target, "error: "+err.Error(), warnings)
	} else {
		summary := "ok"
		if n := len(warnings); n > 0 {
			summary = warnings[n-1] // commands end with their own result line ("found 3 subdomain(s)...")
		}
		reportStep(name, target, summary, warnings)
		if activeCheckpoint != nil {
			activeCheckpoint.mark(key)
		}
		ingestStepOutput(name, output)
	}
	return sr
}

func skipStep(kind, name, target, reason string) stepResult {
	return stepResult{Kind: kind, Name: name, Target: target, Status: "skipped", Detail: reason}
}

// stepKinds maps pipeline steps that write plain line files to the record
// kind they're stored under. portscan/fuzz/probe record structured results
// themselves as they run (see each package's own store.CurrentSink().Add
// call), so they're not listed.
var stepKinds = map[string]string{
	"ipexpand": "ip", "resolve": "resolve", "domains": "domain", "subdomains": "subdomain",
	"gau": "gau", "sensitive": "sensitive", "params": "params", "robots": "robots", "snyk": "snyk",
	"ipexpand-excluded": "ip", "resolve-excluded": "resolve",
	// traceroute-excluded isn't listed: traceroute already saves structured
	// "route" records itself, so ingesting its JSON output file line-by-line
	// here would duplicate it.
}

// recordUserSkip saves a keyboard-skipped step to the results database
// (kind "pipeline_skip"), so a run's skips survive past manifest.json and
// can be queried later (`srt results -kind pipeline_skip`). A nil sink
// (no -save / -no-db) makes this a no-op, same as every other store call
// in this package.
func recordUserSkip(key, stage, name, target, reason string) {
	store.CurrentSink().Add(store.Record{
		Kind: "pipeline_skip",
		Key:  key,
		Data: map[string]any{
			"stage":  stage,
			"step":   name,
			"target": target,
			"reason": reason,
			"at":     time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// ingestStepOutput stores a finished step's line output in the active run.
func ingestStepOutput(step, output string) {
	kind, ok := stepKinds[step]
	if store.CurrentSink() == nil || !ok || output == "" {
		return
	}
	for _, l := range mustLines(output) {
		if strings.TrimSpace(l) != "" {
			store.CurrentSink().Add(store.TextRecord(kind, l))
		}
	}
}

// pipelineLogPath, when set, receives every warning a step printed, so the
// terminal only needs the one-line summary reportStep gives.
var pipelineLogPath string

// reportStep prints a step's one-line result and logs its full warning
// output. The last warning is the step's own summary; the rest are counted
// and left in the log instead of scrolling past.
func reportStep(name, target, summary string, warnings []string) {
	colorout.ClearLine(os.Stderr) // erase any live progress line first
	label := name
	switch name { // their "target" is just the port spec, which says nothing here
	case "ipexpand", "resolve", "portscan":
		target = ""
	}
	if target != "" {
		label += " " + target
	}
	line := fmt.Sprintf("[%s] %s", label, summary)
	if n := len(warnings) - 1; n > 0 && pipelineLogPath != "" {
		line += fmt.Sprintf(" (+%d message(s) in %s)", n, filepath.Base(pipelineLogPath))
	}
	fmt.Fprintln(os.Stderr, line)

	if pipelineLogPath == "" || len(warnings) == 0 {
		return
	}
	f, err := os.OpenFile(pipelineLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	for _, w := range warnings {
		fmt.Fprintf(f, "[%s] %s\n", label, w)
	}
}

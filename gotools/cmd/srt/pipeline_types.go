package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
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
	OutputDir          string `json:"outputDir,omitempty"`
	Concurrency        int    `json:"concurrency,omitempty"`
	Rate               int    `json:"rate,omitempty"`
	RateGlobal         int    `json:"rateGlobal,omitempty"`
	Timeout            string `json:"timeout,omitempty"`
	Insecure           *bool  `json:"insecure,omitempty"`
	Wordlist           string `json:"wordlist,omitempty"`
	Scope              string `json:"scope,omitempty"`
	Ports              string `json:"ports,omitempty"`
	Proxy              string `json:"proxy,omitempty"`
	SubdomainsWordlist string `json:"subdomainsWordlist,omitempty"` // subdomain-label wordlist (e.g. www, api, dev); passive (crt.sh) always runs regardless
}

// timeoutDuration parses Timeout, defaulting to def when unset or invalid.
func (o pipelineOptions) timeoutDuration(def time.Duration) time.Duration {
	if o.Timeout == "" {
		return def
	}
	d, err := time.ParseDuration(o.Timeout)
	if err != nil {
		warn("options.timeout %q invalid, using default %s: %v", o.Timeout, def, err)
		return def
	}
	return d
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
		return nil, errMissing("-c <config.json> is required")
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
	start := time.Now()
	err := fn()
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
	}
	return sr
}

func skipStep(kind, name, target, reason string) stepResult {
	return stepResult{Kind: kind, Name: name, Target: target, Status: "skipped", Detail: reason}
}

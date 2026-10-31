// Package pipeline implements the pipeline command: running the HOST and/or
// WEB methodology end to end from a JSON target file (see docs/pipeline.md),
// by calling the other recon packages' Run functions directly in the order
// the methodology prescribes and writing everything -- including a
// manifest.json summary -- to one output directory.
package pipeline

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/scope"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "pipeline",
		Group:   "Pipeline",
		Summary: "Run an automated host/web assessment from a JSON target file (see docs/pipeline.md)",
		Run:     Run,
	})
}

func Run(args []string) error {
	fs := flag.NewFlagSet("pipeline", flag.ExitOnError)
	cfgPath := fs.String("c", "", "pipeline JSON config file (optional if -host-file and/or -web-scope are given)")
	hostFile := fs.String("host-file", "", "plain file of IPs/CIDRs, one per line -- merged into the config's \"host\" list")
	webScope := fs.String("web-scope", "", "Burp scope JSON export -- concrete web hosts (via burphosts) are merged into \"web\", each gated by this scope file, which also becomes the default options.scope")
	name := fs.String("name", "", "engagement name for the manifest (overrides the config's \"name\")")
	kindFlag := fs.String("kind", "", `stage(s) to run: "host", "web", or "host,web" (default: auto -- run whichever sections the config has)`)
	outDirFlag := fs.String("o", "", "output directory (overrides options.outputDir in the config)")
	dryRun := fs.Bool("dry-run", false, "print the planned steps without sending any traffic")
	noWebHandoff := fs.Bool("no-web-handoff", false, "don't automatically run the WEB stage against web services the HOST stage discovers")
	colorFlag := fs.String("color", "auto", "color output: auto|always|never")
	resume := fs.Bool("resume", false, "continue an interrupted run in -o: skip steps already completed and resume portscan/fuzz mid-way (without it, a fresh run starts over)")
	noDB := fs.Bool("no-db", false, "don't record this run's results in the project database (.srt/srt.db, see `srt results`)")
	noDetect := fs.Bool("no-detect", false, "don't auto-detect *-in-scope / target_assets*.json in the current directory when no -c/-host-file/-web-scope is given")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)

	if *cfgPath == "" && *hostFile == "" && *webScope == "" && !*noDetect {
		if cwd, err := os.Getwd(); err == nil {
			*hostFile, *webScope = scope.DetectScopeFiles(cwd)
			if *hostFile != "" {
				fmt.Fprintf(os.Stderr, "pipeline: auto-detected host scope %s\n", *hostFile)
			}
			if *webScope != "" {
				fmt.Fprintf(os.Stderr, "pipeline: auto-detected web scope %s\n", *webScope)
			}
		}
	}

	cfg, err := assemblePipelineConfig(*cfgPath, *hostFile, *webScope, *name)
	if err != nil {
		return err
	}

	kinds, err := resolveKinds(*kindFlag, cfg)
	if err != nil {
		return err
	}

	outDir := cfg.Options.OutputDir
	if *outDirFlag != "" {
		outDir = *outDirFlag
	}
	if outDir == "" {
		outDir = "srt-pipeline-out"
	}

	if *dryRun {
		printDryRun(cfg, kinds, outDir)
		return nil
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	if store.CurrentSink() == nil && !*noDB {
		name := "pipeline"
		if cfg.Name != "" {
			name += " " + cfg.Name
		}
		if s, err := store.StartSink(name, append([]string{"pipeline"}, args...)); err != nil {
			ioutil.Warn("results database unavailable, continuing without saving: %v", err)
		} else {
			defer s.Close()
		}
	}

	activeCheckpoint = loadCheckpoint(filepath.Join(outDir, "checkpoint.json"), *resume)
	if *resume {
		ioutil.Warn("resuming: completed steps in %s will be skipped", outDir)
	}

	m := manifest{Name: cfg.Name, StartedAt: time.Now(), Kinds: kinds}
	for _, k := range kinds {
		stageDir := filepath.Join(outDir, k)
		if err := os.MkdirAll(stageDir, 0o755); err != nil {
			return err
		}
		ioutil.Warn("=== %s stage ===", k)
		switch k {
		case "host":
			m.Steps = append(m.Steps, runHostStage(cfg, stageDir, !*noWebHandoff)...)
		case "web":
			m.Steps = append(m.Steps, runWebStage(cfg, stageDir)...)
		}
	}
	m.EndedAt = time.Now()

	manifestPath := filepath.Join(outDir, "manifest.json")
	if err := writeManifest(manifestPath, m); err != nil {
		return err
	}

	printSummary(m, manifestPath, cm)
	return nil
}

// resolveKinds decides which stage(s) to run: an explicit -kind flag, or
// "auto" (whichever of host/web the config actually populates).
func resolveKinds(flagVal string, cfg *pipelineConfig) ([]string, error) {
	if flagVal == "" {
		var kinds []string
		if len(cfg.Host) > 0 {
			kinds = append(kinds, "host")
		}
		if len(cfg.Web) > 0 {
			kinds = append(kinds, "web")
		}
		if len(kinds) == 0 {
			return nil, ioutil.ErrMissing(`config has no "host" or "web" targets`)
		}
		return kinds, nil
	}

	var kinds []string
	for _, k := range strings.Split(flagVal, ",") {
		k = strings.TrimSpace(k)
		switch k {
		case "host", "web":
			kinds = append(kinds, k)
		default:
			return nil, fmt.Errorf("-kind: unknown kind %q (want host, web, or host,web)", k)
		}
	}
	return kinds, nil
}

// assemblePipelineConfig builds the pipelineConfig the rest of the command
// runs on: starting from -c's JSON (if given), then merging in -host-file
// (a plain IP/CIDR list, one per line) and -web-scope (a Burp scope JSON
// export, turned into concrete web targets via scope.BurpHosts and gated by
// that same file). Either source alone is enough to run; at least one is
// required. This exists so a quick test doesn't require hand-writing JSON
// when a plain host list and/or a Burp scope export already describe the
// engagement.
func assemblePipelineConfig(cfgPath, hostFile, webScope, name string) (*pipelineConfig, error) {
	var cfg *pipelineConfig
	if cfgPath != "" {
		var err error
		cfg, err = loadPipelineConfig(cfgPath)
		if err != nil {
			return nil, err
		}
	} else {
		cfg = &pipelineConfig{}
	}

	if hostFile != "" {
		lines, err := ioutil.InputLines(hostFile)
		if err != nil {
			return nil, fmt.Errorf("-host-file: %w", err)
		}
		for _, l := range lines {
			cfg.Host = append(cfg.Host, targetEntry{Target: l})
		}
	}

	if webScope != "" {
		bs, err := scope.LoadBurpScope(webScope)
		if err != nil {
			return nil, fmt.Errorf("-web-scope: %w", err)
		}
		for _, h := range scope.BurpHosts(bs) {
			cfg.Web = append(cfg.Web, targetEntry{Target: h, Scope: webScope})
		}
		if cfg.Options.Scope == "" {
			cfg.Options.Scope = webScope
		}
	}

	if name != "" {
		cfg.Name = name
	}

	if len(cfg.Host) == 0 && len(cfg.Web) == 0 {
		return nil, ioutil.ErrMissing("no targets: pass -c <config.json>, -host-file <file>, and/or -web-scope <burp.json> (or run from a directory containing *-in-scope / target_assets.json)")
	}
	return cfg, nil
}

// writeLinesFile writes lines to a new file at path, reusing ioutil.WriteLines.
func writeLinesFile(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return ioutil.WriteLines(f, lines)
}

func writeManifest(path string, m manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// captureStdout runs fn with the process's real os.Stdout swapped for a pipe
// and returns everything fn wrote. This is only needed for the handful of
// subcommands (robots, params, snyk) that always print via fmt.Println
// straight to os.Stdout instead of accepting an -o flag. The pipeline runs
// stages sequentially, so two of these never overlap.
func captureStdout(fn func() error) (string, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	old := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()

	fnErr := fn()

	os.Stdout = old
	w.Close()
	return <-done, fnErr
}

var pipelineStageOrder = map[string][]string{
	"host": {"ipexpand", "resolve (reverse DNS)", "portscan", "classify services (web -> WEB stage handoff, uncommon -> flagged, bannered -> vulnx)"},
	"web":  {"domains", "subdomains", "probe", "gau", "sensitive", "params", "robots", "fuzz", "snyk (only targets with snykUrl/snykVersion)"},
}

func printDryRun(cfg *pipelineConfig, kinds []string, outDir string) {
	fmt.Printf("pipeline %q -> %s\n", cfg.Name, outDir)
	for _, k := range kinds {
		var targets []string
		if k == "host" {
			for _, e := range cfg.Host {
				targets = append(targets, e.Target)
			}
		} else {
			for _, e := range cfg.Web {
				targets = append(targets, e.Target)
			}
		}
		fmt.Printf("\n[%s] %d target(s): %s\n", k, len(targets), strings.Join(targets, ", "))
		fmt.Printf("[%s] steps: %s\n", k, strings.Join(pipelineStageOrder[k], " -> "))
	}
	fmt.Println("\n(dry run: no requests were sent)")
}

func printSummary(m manifest, manifestPath string, cm colorout.Mode) {
	var ok, failed, skipped int
	for _, s := range m.Steps {
		switch s.Status {
		case "ok":
			ok++
		case "skipped":
			skipped++
		default:
			failed++
		}
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", cm.Wrap(colorout.Cyan, "=== pipeline summary ==="))
	fmt.Fprintf(os.Stderr, "%d step(s): %s, %s, %s\n",
		len(m.Steps),
		cm.Wrap(colorout.Green, fmt.Sprintf("%d ok", ok)),
		cm.Wrap(colorout.Yellow, fmt.Sprintf("%d skipped", skipped)),
		cm.Wrap(colorout.Red, fmt.Sprintf("%d failed", failed)))
	fmt.Fprintf(os.Stderr, "took %s, manifest: %s\n", m.EndedAt.Sub(m.StartedAt).Round(time.Millisecond), manifestPath)
}

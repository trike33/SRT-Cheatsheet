package main

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
)

func init() {
	register(&command{
		name:    "pipeline",
		group:   "Pipeline",
		summary: "Run an automated host/web assessment from a JSON target file (see docs/pipeline.md)",
		run:     runPipeline,
	})
}

func runPipeline(args []string) error {
	fs := flag.NewFlagSet("pipeline", flag.ExitOnError)
	cfgPath := fs.String("c", "", "pipeline JSON config file (required)")
	kindFlag := fs.String("kind", "", `stage(s) to run: "host", "web", or "host,web" (default: auto -- run whichever sections the config has)`)
	outDirFlag := fs.String("o", "", "output directory (overrides options.outputDir in the config)")
	dryRun := fs.Bool("dry-run", false, "print the planned steps without sending any traffic")
	noWebHandoff := fs.Bool("no-web-handoff", false, "don't automatically run the WEB stage against web services the HOST stage discovers")
	colorFlag := fs.String("color", "auto", "color output: auto|always|never")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := parseColorMode(*colorFlag)

	cfg, err := loadPipelineConfig(*cfgPath)
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

	m := manifest{Name: cfg.Name, StartedAt: time.Now(), Kinds: kinds}
	for _, k := range kinds {
		stageDir := filepath.Join(outDir, k)
		if err := os.MkdirAll(stageDir, 0o755); err != nil {
			return err
		}
		warn("=== %s stage ===", k)
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
			return nil, errMissing(`config has no "host" or "web" targets`)
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

// writeLinesFile writes lines to a new file at path, reusing writeLines.
func writeLinesFile(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeLines(f, lines)
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
	"host": {"ipexpand", "resolve (reverse DNS)", "portscan", "classify services (web -> WEB stage handoff, uncommon -> flagged)"},
	"web":  {"domains", "gau", "sensitive", "params", "robots", "fuzz", "snyk (only targets with snykUrl/snykVersion)"},
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

func printSummary(m manifest, manifestPath string, cm colorMode) {
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
	fmt.Fprintf(os.Stderr, "\n%s\n", cm.wrap(ansiCyan, "=== pipeline summary ==="))
	fmt.Fprintf(os.Stderr, "%d step(s): %s, %s, %s\n",
		len(m.Steps),
		cm.wrap(ansiGreen, fmt.Sprintf("%d ok", ok)),
		cm.wrap(ansiYellow, fmt.Sprintf("%d skipped", skipped)),
		cm.wrap(ansiRed, fmt.Sprintf("%d failed", failed)))
	fmt.Fprintf(os.Stderr, "took %s, manifest: %s\n", m.EndedAt.Sub(m.StartedAt).Round(time.Millisecond), manifestPath)
}

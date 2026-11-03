// Manual-fuzz cherrypick: options.manualFuzz/-no-manual-fuzz (default true).
//
// Instead of brute-forcing every explicit web target (plus
// options.activeOnSubdomains hosts) back to back with whatever wordlist the
// config happens to name, the WEB stage's fuzz step becomes a two-round,
// user-driven pass over what probe already found:
//
//  1. every fuzz candidate is listed (with probe's status/title/server when
//     known) and the user picks which ones are worth brute-forcing at all,
//     plus a wordlist for that first, flat round -- SecLists'
//     raft-medium-directories.txt by default, raft-medium-files.txt or any
//     other path on request.
//  2. once round 1 finishes, the hosts it actually ran against are listed
//     again (with their hit counts) and the user picks which of those are
//     worth a second, -recursion pass -- and a (possibly different)
//     wordlist for that round.
//
// Falls back to the old automatic sequential behavior (runSequentialFuzz)
// whenever there's no terminal to prompt on at all -- a -dry-run, a config
// run from CI, or a pipeline driven by the srt shell, whose control-file
// skip mode has no terminal on this process's stdin to read lines from
// either. -no-manual-fuzz asks for that fallback unconditionally.
package pipeline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/fuzz"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/probe"
	"github.com/trike33/srt-cheatsheet/gotools/internal/wordlists"
)

// Default wordlists the cherrypick prompts offer as the two one-keystroke
// choices each round. options.fuzzDirsWordlist/fuzzFilesWordlist (or
// -fuzz-dirs-wordlist/-fuzz-files-wordlist) override either path; the
// prompt itself also always accepts an arbitrary path typed in directly.
const (
	defaultFuzzDirsWordlist  = "/usr/share/SecLists-master/Discovery/Web-Content/raft-medium-directories.txt"
	defaultFuzzFilesWordlist = "/usr/share/SecLists-master/Discovery/Web-Content/raft-medium-files.txt"
)

func fuzzDirsWordlistDefault(o pipelineOptions) string {
	if o.FuzzDirsWordlist != "" {
		return o.FuzzDirsWordlist
	}
	return defaultFuzzDirsWordlist
}

func fuzzFilesWordlistDefault(o pipelineOptions) string {
	if o.FuzzFilesWordlist != "" {
		return o.FuzzFilesWordlist
	}
	return defaultFuzzFilesWordlist
}

// runFuzzStage is the WEB stage's one entry point for the fuzz step: a
// disabled step (options.fuzz:false/-no-fuzz) short-circuits before any
// prompt; otherwise it's the interactive cherrypick flow or, when that
// can't run, the old automatic sequential one.
func runFuzzStage(cfg *pipelineConfig, outDir string, fuzzTargets []targetEntry, nameWordsFile string) (steps []stepResult, fuzzFiles []string) {
	if !cfg.Options.fuzzOrDefault(true) {
		for _, e := range fuzzTargets {
			if e.Target == "" {
				continue
			}
			steps = append(steps, skipStep("web", "fuzz", e.Target, "disabled (options.fuzz:false / -no-fuzz)"))
		}
		return steps, nil
	}
	if cfg.Options.manualFuzzOrDefault(true) {
		return runManualFuzzPick(cfg, outDir, fuzzTargets, nameWordsFile)
	}
	return runSequentialFuzz(cfg, outDir, fuzzTargets, nameWordsFile)
}

// runSequentialFuzz is the pre-cherrypick behavior: every target in
// fuzzTargets, back to back, no prompts -- used by -no-manual-fuzz and as
// the automatic fallback when manual mode has no terminal to prompt on.
func runSequentialFuzz(cfg *pipelineConfig, outDir string, fuzzTargets []targetEntry, nameWordsFile string) (steps []stepResult, fuzzFiles []string) {
	for _, e := range fuzzTargets {
		if e.Target == "" {
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
		args := fuzzArgsFor(cfg, e, wordlist, nameWordsFile, fuzzFile, false)
		fuzzFiles = append(fuzzFiles, fuzzFile)
		steps = append(steps, runStep("web", "fuzz", e.Target, fuzzFile, func() error {
			return fuzz.Run(args)
		}))
	}
	return steps, fuzzFiles
}

// fuzzArgsFor builds one `fuzz` call's argv, shared by the automatic
// sequential path and both rounds of the manual cherrypick flow, so every
// other fuzz flag (extensions, scope, rate, proxy, ...) behaves identically
// either way. wordlist is the resolved path to use; recursion switches on
// fuzz's own -recursion (manual flow's round 2 only).
func fuzzArgsFor(cfg *pipelineConfig, e targetEntry, wordlist, nameWordsFile, fuzzFile string, recursion bool) []string {
	args := []string{"-u", fuzzURL(e.Target), "-w", wordlist, "-json", "-o", fuzzFile}
	if nameWordsFile != "" {
		args = append(args, "-w", nameWordsFile)
	}

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
	if cfg.Options.contextWordsOrDefault(true) {
		args = append(args, "-words-auto") // per-host tech-stack/title words, gap 7
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
	if recursion {
		args = append(args, "-recursion")
	}
	args = append(args, resumeStateArgs(fuzzFile)...)
	return args
}

// runFuzzRound runs one cherrypick round: fuzz.Run for every entry, same
// wordlist and recursion setting for all of them (the manual flow's "one
// choice per round" design), writing each to filePrefix+safeName(target)+
// ".json" so round 1 (06_fuzz_) and round 2 (06r_fuzz_) never collide.
func runFuzzRound(cfg *pipelineConfig, outDir string, entries []targetEntry, nameWordsFile, wordlist string, recursion bool, filePrefix string) (steps []stepResult, fuzzFiles []string) {
	stepName := "fuzz"
	if recursion {
		stepName = "fuzz-recursion"
	}
	for _, e := range entries {
		if e.Target == "" {
			continue
		}
		fuzzFile := filepath.Join(outDir, filePrefix+safeName(e.Target)+".json")
		args := fuzzArgsFor(cfg, e, wordlist, nameWordsFile, fuzzFile, recursion)
		fuzzFiles = append(fuzzFiles, fuzzFile)
		steps = append(steps, runStep("web", stepName, e.Target, fuzzFile, func() error {
			return fuzz.Run(args)
		}))
	}
	return steps, fuzzFiles
}

// fuzzCandidate is one row of the cherrypick menu: the target entry it came
// from, plus whatever probe already learned about it (best-effort -- a
// hostname match against 01c_probe.json, zero value when probe never saw
// this exact host).
type fuzzCandidate struct {
	entry  targetEntry
	host   string
	status int
	title  string
	server string
}

// buildFuzzCandidates turns fuzzTargets into the menu rows, enriched with
// probe's own result for each host when probeFile has one.
func buildFuzzCandidates(fuzzTargets []targetEntry, probeFile string) []fuzzCandidate {
	info := probeInfoByHost(probeFile)
	var out []fuzzCandidate
	for _, e := range fuzzTargets {
		if e.Target == "" {
			continue
		}
		h := targetHost(e.Target)
		c := fuzzCandidate{entry: e, host: h}
		if r, ok := info[h]; ok {
			c.status, c.title, c.server = r.Status, r.Title, r.Server
		}
		out = append(out, c)
	}
	return out
}

// probeInfoByHost reads probe's -json output and indexes it by bare
// hostname, for the cherrypick menu's display only -- never a correctness
// dependency (a host probe never saw just shows with no extra detail).
func probeInfoByHost(probeFile string) map[string]probe.Result {
	out := map[string]probe.Result{}
	f, err := os.Open(probeFile)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		var r probe.Result
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		h := targetHost(r.Target)
		if h == "" {
			h = targetHost(r.URL)
		}
		if h != "" {
			out[h] = r
		}
	}
	return out
}

// printFuzzCandidates renders the numbered cherrypick menu to stderr. hits,
// when non-nil, adds each host's round-1 hit count (round 2's menu).
func printFuzzCandidates(label string, cands []fuzzCandidate, hits map[string]int) {
	fmt.Fprintf(os.Stderr, "\n%s\n", label)
	for i, c := range cands {
		line := fmt.Sprintf("  [%2d] %s", i+1, baseURL(c.entry.Target))
		var extra []string
		if c.status > 0 {
			extra = append(extra, strconv.Itoa(c.status))
		}
		if c.title != "" {
			extra = append(extra, c.title)
		}
		if c.server != "" {
			extra = append(extra, c.server)
		}
		if hits != nil {
			extra = append(extra, fmt.Sprintf("%d hit(s) in round 1", hits[c.host]))
		}
		if len(extra) > 0 {
			line += "  (" + strings.Join(extra, ", ") + ")"
		}
		fmt.Fprintln(os.Stderr, line)
	}
}

// countFuzzHits reads every result file from a round and counts hits per
// bare hostname, for round 2's menu.
func countFuzzHits(files []string) map[string]int {
	out := map[string]int{}
	for _, f := range files {
		for _, l := range mustLines(f) {
			var r struct {
				URL string `json:"url"`
			}
			if json.Unmarshal([]byte(l), &r) == nil && r.URL != "" {
				out[targetHost(r.URL)]++
			}
		}
	}
	return out
}

// selectEntries picks cands[i].entry for each index in idx, in idx's order.
func selectEntries(cands []fuzzCandidate, idx []int) []targetEntry {
	out := make([]targetEntry, 0, len(idx))
	for _, i := range idx {
		out = append(out, cands[i].entry)
	}
	return out
}

// selectCandidates is selectEntries's counterpart for round 2's menu, which
// needs the whole fuzzCandidate (for its host, to look up hit counts), not
// just the bare targetEntry.
func selectCandidates(cands []fuzzCandidate, idx []int) []fuzzCandidate {
	out := make([]fuzzCandidate, 0, len(idx))
	for _, i := range idx {
		out = append(out, cands[i])
	}
	return out
}

// readUserLine prints prompt and reads one line from the real terminal,
// pausing the skip-key listener for the duration (see skip.go's pause) so
// the two readers of stdin never race. Must only be called when
// activeSkip.interactive() is true.
func readUserLine(prompt string) string {
	resume := activeSkip.pause()
	defer resume()
	fmt.Fprint(os.Stderr, prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line)
}

// parseSelection parses a cherrypick answer against n menu rows (1-based in
// the prompt, 0-based in the result): "", "none" or "n" selects nothing;
// "all" or "a" selects every row; otherwise a comma-separated list of
// numbers and/or "lo-hi" ranges. Order of first appearance is preserved,
// duplicates dropped.
func parseSelection(input string, n int) ([]int, error) {
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" || input == "none" || input == "n" {
		return nil, nil
	}
	if input == "all" || input == "a" || input == "*" {
		all := make([]int, n)
		for i := range all {
			all[i] = i
		}
		return all, nil
	}

	seen := map[int]bool{}
	var out []int
	add := func(i int) error {
		if i < 1 || i > n {
			return fmt.Errorf("%d is out of range (want 1-%d)", i, n)
		}
		if !seen[i-1] {
			seen[i-1] = true
			out = append(out, i-1)
		}
		return nil
	}
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			loN, err1 := strconv.Atoi(strings.TrimSpace(lo))
			hiN, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || loN > hiN {
				return nil, fmt.Errorf("invalid range %q (want e.g. 2-5)", part)
			}
			for i := loN; i <= hiN; i++ {
				if err := add(i); err != nil {
					return nil, err
				}
			}
			continue
		}
		idx, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid selection %q (want a number, a range like 2-5, \"all\", or empty for none)", part)
		}
		if err := add(idx); err != nil {
			return nil, err
		}
	}
	sort.Ints(out)
	return out, nil
}

// promptSelection asks the question up to 3 times, falling back to "none"
// (with a warning) if the user never gives a valid answer -- this is
// cherrypicking, not a required field, so a confused/empty terminal
// shouldn't block the rest of the run.
func promptSelection(question string, n int) []int {
	for attempt := 0; attempt < 3; attempt++ {
		sel, err := parseSelection(readUserLine(question), n)
		if err == nil {
			return sel
		}
		fmt.Fprintln(os.Stderr, "  "+err.Error())
	}
	ioutil.Warn("fuzz: no valid selection after 3 tries, treating it as none")
	return nil
}

// chooseWordlist asks which of the two default wordlists (or a custom path)
// this round should use, up to 3 times before giving up to the directories
// default -- same "cherrypicking shouldn't block the run" reasoning as
// promptSelection.
func chooseWordlist(round string, opts pipelineOptions, outDir string) string {
	dirsDefault := fuzzDirsWordlistDefault(opts)
	filesDefault := fuzzFilesWordlistDefault(opts)
	prompt := fmt.Sprintf("Wordlist for %s -- [d]irectories (%s), [f]iles (%s), or a custom path [default: d]: ", round, dirsDefault, filesDefault)
	for attempt := 0; attempt < 3; attempt++ {
		in := readUserLine(prompt)
		switch strings.ToLower(in) {
		case "", "d", "dir", "dirs", "directories":
			return resolveExistingWordlist(dirsDefault, outDir)
		case "f", "file", "files":
			return resolveExistingWordlist(filesDefault, outDir)
		default:
			if _, err := os.Stat(in); err == nil {
				return in
			}
			fmt.Fprintf(os.Stderr, "  %q: no such file; try again, \"d\"/\"f\", or Enter for the default directories wordlist.\n", in)
		}
	}
	ioutil.Warn("fuzz: no valid wordlist choice after 3 tries, falling back to the default directories wordlist")
	return resolveExistingWordlist(dirsDefault, outDir)
}

// resolveExistingWordlist returns path unchanged if it exists, else falls
// back to the embedded common.txt with a warning -- same fallback
// resolveWordlist's automatic-sequential path uses when no wordlist at all
// is configured, just applied to a configured path that turned out missing
// (e.g. SecLists isn't installed at the default location).
func resolveExistingWordlist(path, outDir string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	ioutil.Warn("fuzz: wordlist %s not found, falling back to the embedded common.txt", path)
	if p, err := wordlists.DirectoriesFile(outDir); err == nil {
		return p
	}
	return path // let fuzz itself report the missing file
}

// runManualFuzzPick is the interactive cherrypick flow: see the package
// doc comment at the top of this file for the two rounds it runs.
func runManualFuzzPick(cfg *pipelineConfig, outDir string, fuzzTargets []targetEntry, nameWordsFile string) (steps []stepResult, fuzzFiles []string) {
	if len(fuzzTargets) == 0 {
		return nil, nil
	}
	if !activeSkip.interactive() {
		ioutil.Warn("fuzz: stdin isn't an interactive terminal, falling back to automatic sequential fuzz (manual cherrypick needs a TTY; -no-manual-fuzz silences this)")
		return runSequentialFuzz(cfg, outDir, fuzzTargets, nameWordsFile)
	}

	probeFile := filepath.Join(outDir, "01c_probe.json")
	cands := buildFuzzCandidates(fuzzTargets, probeFile)
	if len(cands) == 0 {
		return nil, nil
	}

	printFuzzCandidates("=== fuzz round 1: pick hosts to brute-force ===", cands, nil)
	picked := promptSelection(fmt.Sprintf("Select hosts 1-%d (comma/ranges, \"all\", or empty for none): ", len(cands)), len(cands))
	if len(picked) == 0 {
		return []stepResult{skipStep("web", "fuzz", "", "manual cherrypick: no hosts selected for round 1")}, nil
	}

	wl1 := chooseWordlist("round 1", cfg.Options, outDir)
	round1Entries := selectEntries(cands, picked)
	round1Steps, round1Files := runFuzzRound(cfg, outDir, round1Entries, nameWordsFile, wl1, false, "06_fuzz_")
	steps = append(steps, round1Steps...)
	fuzzFiles = append(fuzzFiles, round1Files...)

	// --- round 2: recursion, cherrypicked from what round 1 just fuzzed ---
	round1Cands := selectCandidates(cands, picked)
	hits := countFuzzHits(round1Files)
	printFuzzCandidates("=== fuzz round 2: pick hosts to recurse into ===", round1Cands, hits)
	recPicked := promptSelection(fmt.Sprintf("Recurse into which of these %d host(s) (comma/ranges, \"all\", or empty to stop here): ", len(round1Cands)), len(round1Cands))
	if len(recPicked) == 0 {
		return steps, fuzzFiles
	}

	wl2 := chooseWordlist("round 2 (recursion)", cfg.Options, outDir)
	round2Entries := selectEntries(round1Cands, recPicked)
	round2Steps, round2Files := runFuzzRound(cfg, outDir, round2Entries, nameWordsFile, wl2, true, "06r_fuzz_")
	steps = append(steps, round2Steps...)
	fuzzFiles = append(fuzzFiles, round2Files...)
	return steps, fuzzFiles
}

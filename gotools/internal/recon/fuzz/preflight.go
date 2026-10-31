package fuzz

import (
	"strings"
	"sync"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

// Preflight: before sending a single real candidate, fire a couple of
// guaranteed-nonexistent paths at each target host's root to see what this
// particular application does with a page that isn't there -- the same
// sanity check a human runs by hand before trusting -mc on a new target.
//
// It always runs, independent of -ac:
//
//   - every host gets its "what does a miss look like" fingerprint recorded
//     as a baseline, so later per-directory calibration (calibrate, in
//     engine.go) starts from it instead of from zero, same idea as the
//     parent-to-child seeding recursion uses;
//   - a host whose miss comes back looking like a hit under the configured
//     matchers (a 200, a soft redirect, anything -mc would show) gets
//     soft-404 filtering auto-enabled for it even if -ac was never passed,
//     because without it the whole run would otherwise "match" on nearly
//     every word. The operator is told this happened and why.

// preflightCheck probes every target host's root once, in parallel, before
// any feeder starts.
func (e *fuzzEngine) preflightCheck(bases []string) {
	origins := uniqueOrigins(bases)
	if len(origins) == 0 {
		return
	}
	e.baseline = map[string]*calibData{}

	var wg sync.WaitGroup
	for _, origin := range origins {
		wg.Add(1)
		go func(origin string) {
			defer wg.Done()
			e.preflightOrigin(origin)
		}(origin)
	}
	wg.Wait()
}

// preflightOrigin probes one host's root with two differently-sized random
// tokens and records what comes back.
func (e *fuzzEngine) preflightOrigin(origin string) {
	tolPct := e.acTol
	if tolPct <= 0 {
		tolPct = 1.0 // still want a little jitter tolerance to size up the baseline itself
	}
	cd := newCalibData(tolPct, 0)
	soft := false

	for _, n := range []int{14, 22} {
		rnd := randToken(n)
		target := strings.TrimRight(origin, "/") + "/" + rnd
		if e.scope != nil && !e.scope.InScope(target) {
			continue
		}
		meta, _, err := e.doRequest(target, rnd)
		if err != nil {
			continue
		}
		if e.matcher.show(meta) {
			cd.addCalibrated(meta, rnd)
			soft = true
		}
	}

	if len(cd.filter) == 0 {
		return
	}

	e.baselineMu.Lock()
	e.baseline[origin] = cd
	e.baselineMu.Unlock()

	if !soft || e.autocal {
		return
	}

	e.forcedMu.Lock()
	if e.forcedCal == nil {
		e.forcedCal = map[string]bool{}
	}
	e.forcedCal[origin] = true
	e.forcedMu.Unlock()
	ioutil.Warn("preflight %s: a non-existent path doesn't 404 (%s) -- auto-enabling soft-404 filtering for this host",
		origin, cd.describe())
}

// calibrationEnabled reports whether soft-404 filtering/calibration should
// run for origin: the operator's own -ac, or preflight's own auto-enable.
func (e *fuzzEngine) calibrationEnabled(origin string) bool {
	if e.autocal {
		return true
	}
	e.forcedMu.Lock()
	defer e.forcedMu.Unlock()
	return e.forcedCal[origin]
}

// baselineFor returns the preflight fingerprint for origin, if any.
func (e *fuzzEngine) baselineFor(origin string) *calibData {
	e.baselineMu.RLock()
	defer e.baselineMu.RUnlock()
	return e.baseline[origin]
}

// uniqueOrigins returns the distinct origins (scheme://host[:port]) across
// every base template, in first-seen order.
func uniqueOrigins(bases []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range bases {
		o := originOf(b)
		if !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	return out
}

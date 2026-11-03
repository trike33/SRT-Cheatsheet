package fuzz

import (
	"os"
	"sync"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/fuzzctl"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

// Live status + control for the interactive shell (see package fuzzctl).
// Everything here is inert unless the shell set fuzzctl.EnvStatus /
// fuzzctl.EnvControl in the environment.

const maxHostHits = 200

// finishedHosts keeps hosts from earlier fuzz runs in this process (the
// pipeline fuzzes one target at a time) so the shell's view of the step
// still shows them, marked done, after the next target starts.
var (
	finishedMu    sync.Mutex
	finishedHosts []fuzzctl.Host
)

func (hb *hostBucket) addHit(line string) {
	hb.hitMu.Lock()
	hb.hits = append(hb.hits, line)
	if len(hb.hits) > maxHostHits {
		hb.hits = append([]string(nil), hb.hits[len(hb.hits)-maxHostHits:]...)
	}
	hb.hitMu.Unlock()
}

// halted reports whether this host gets no more traffic this run: stopped by
// the user or given up on after a WAF block.
func (hb *hostBucket) halted() bool { return hb.stopped.Load() || hb.wafIsHalted() }

// userStopped is true when the shell asked for host to be skipped.
func (e *fuzzEngine) userStopped(host string) bool {
	e.stopMu.Lock()
	defer e.stopMu.Unlock()
	return e.userStops[host]
}

// loadControl reads the shell's control file and applies it: hosts already
// being fuzzed stop at once (queued work dropped), hosts not started yet are
// remembered and skipped when their turn comes.
func (e *fuzzEngine) loadControl() {
	if e.controlPath == "" {
		return
	}
	for _, h := range fuzzctlStops(e.controlPath) {
		e.stopMu.Lock()
		already := e.userStops[h]
		e.userStops[h] = true
		e.stopMu.Unlock()
		if already {
			continue
		}
		if e.sched != nil {
			if hb := e.sched.lookup(h); hb != nil && !hb.stopped.Swap(true) {
				e.sched.dropJobs(hb)
				ioutil.Warn("stopping fuzzing of %s (requested from the shell)", h)
			}
		}
	}
}

func fuzzctlStops(path string) []string { return fuzzctl.ReadControl(path).Stop }

// hostStatus snapshots one host bucket.
func (e *fuzzEngine) hostStatus(hb *hostBucket, rate float64, final bool) fuzzctl.Host {
	hs := fuzzctl.Host{
		Host: hb.name, Target: hb.base,
		Planned: hb.planned.Load(), Done: hb.reqs.Load(), Matches: hb.matches.Load(),
		Rate: rate, Wordlists: e.wordlistNames, Words: len(e.words),
	}
	e.sched.mu.Lock()
	hs.Queued, hs.InFlight = len(hb.jobs), hb.inflight
	e.sched.mu.Unlock()

	hb.hitMu.Lock()
	hs.Hits = append([]string(nil), hb.hits...)
	hb.hitMu.Unlock()

	// Extensions / per-host words are resolved lazily by the engine; only
	// read them when already cached (never trigger a probe from here).
	if hb.base != "" {
		origin := originOf(hb.base)
		if e.extc.mu.TryLock() {
			hs.Exts = append([]string(nil), e.extc.done[origin]...)
			e.extc.mu.Unlock()
		}
		if hs.Exts == nil {
			hs.Exts = e.exts
		}
		if e.wordc.mu.TryLock() {
			hs.Extra = append([]string(nil), e.wordc.done[origin]...)
			e.wordc.mu.Unlock()
		}
	}

	switch d := hb.wafPausedFor(); {
	case hb.stopped.Load():
		hs.State = fuzzctl.StateStopped
	case hb.wafIsHalted():
		hs.State = fuzzctl.StateWAF
	case d > 0:
		hs.State, hs.Cooldown = fuzzctl.StateCooldown, int(d.Seconds())
	case final:
		hs.State = fuzzctl.StateDone
	case hs.Done == 0:
		hs.State = fuzzctl.StateQueued
	default:
		hs.State = fuzzctl.StateRunning
	}
	return hs
}

func (e *fuzzEngine) writeStatus(rates map[string]float64, final bool) []fuzzctl.Host {
	var cur []fuzzctl.Host
	for _, hb := range e.sched.hostsSnapshot() {
		cur = append(cur, e.hostStatus(hb, rates[hb.name], final))
	}
	if e.statusPath != "" {
		finishedMu.Lock()
		all := append(append([]fuzzctl.Host(nil), finishedHosts...), cur...)
		finishedMu.Unlock()
		fuzzctl.WriteStatus(e.statusPath, fuzzctl.Status{Hosts: all})
	}
	return cur
}

// statusLoop publishes the status and polls the control file until stop is
// closed, then writes a final snapshot and files this run's hosts under
// finishedHosts.
func (e *fuzzEngine) statusLoop(stop <-chan struct{}) {
	if e.statusPath == "" && e.controlPath == "" {
		return
	}
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	prev := map[string]int64{}
	last := time.Now()
	for {
		select {
		case <-stop:
			e.loadControl()
			cur := e.writeStatus(nil, true)
			finishedMu.Lock()
			finishedHosts = append(finishedHosts, cur...)
			finishedMu.Unlock()
			return
		case now := <-t.C:
			e.loadControl()
			dt := now.Sub(last).Seconds()
			last = now
			rates := map[string]float64{}
			for _, hb := range e.sched.hostsSnapshot() {
				r := hb.reqs.Load()
				if dt > 0 {
					rates[hb.name] = float64(r-prev[hb.name]) / dt
				}
				prev[hb.name] = r
			}
			e.writeStatus(rates, false)
		}
	}
}

func envPath(name string) string { return os.Getenv(name) }

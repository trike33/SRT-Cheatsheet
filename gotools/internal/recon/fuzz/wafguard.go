package fuzz

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

// WAF-block guard. A WAF that decides we're fuzzing typically starts
// answering every request with 403. Hammering on only extends the block (and
// fills the results with junk 403 "hits"), so:
//
//   - first block of a host: stop sending it traffic for this run and move on
//     to the next step/target;
//   - the block shows up again (this host trips a second time, or a later
//     fuzz run's first probe of it is still 403): the host is put on a live
//     5-minute cooldown (visible in the progress line) before any more
//     requests are sent, then fuzzing resumes.
//
// Strikes live in the process, not the engine, so a later fuzz run in the
// same pipeline remembers an earlier one's block.

const (
	wafDefaultThreshold = 40 // consecutive 403s on one host that count as a block
	wafCooldown         = 5 * time.Minute
	wafMaxCooldowns     = 3 // after this many cooldowns still blocked, give the host up
)

var (
	wafMu      sync.Mutex
	wafStrikes = map[string]int{} // host -> blocks seen so far this process
)

func wafStrikeCount(host string) int {
	wafMu.Lock()
	defer wafMu.Unlock()
	return wafStrikes[host]
}

func wafAddStrike(host string) int {
	wafMu.Lock()
	defer wafMu.Unlock()
	wafStrikes[host]++
	return wafStrikes[host]
}

// wafObserve feeds one response's status into hb's consecutive-403 counter
// and reacts when it reaches the threshold.
func (e *fuzzEngine) wafObserve(hb *hostBucket, status int) {
	if e.wafThreshold <= 0 {
		return
	}
	hb.wafMu.Lock()
	if status != 403 {
		hb.consec403 = 0
		hb.wafMu.Unlock()
		return
	}
	hb.consec403++
	if hb.consec403 < e.wafThreshold || hb.wafHalted || time.Now().Before(hb.pausedUntil) {
		hb.wafMu.Unlock()
		return
	}
	hb.consec403 = 0
	hb.wafMu.Unlock()
	e.wafTrip(hb)
}

// wafTrip handles a detected block: strike 1 halts the host for this run,
// later strikes put it on cooldown (up to wafMaxCooldowns of them).
func (e *fuzzEngine) wafTrip(hb *hostBucket) {
	strikes := wafAddStrike(hb.name)
	switch {
	case strikes == 1:
		hb.wafMu.Lock()
		hb.wafHalted = true
		hb.wafMu.Unlock()
		e.sched.dropJobs(hb)
		ioutil.Warn("WAF block suspected on %s (%d consecutive 403s): halting fuzz traffic to it and moving on", hb.name, e.wafThreshold)
	case strikes > 1+wafMaxCooldowns:
		hb.wafMu.Lock()
		hb.wafHalted = true
		hb.wafMu.Unlock()
		e.sched.dropJobs(hb)
		ioutil.Warn("%s is still blocking us after %d cooldowns: giving it up", hb.name, wafMaxCooldowns)
	default:
		e.wafCooldownHost(hb, "blocked again")
	}
}

// wafCooldownHost pauses a host for wafCooldown. The scheduler skips a host
// while paused (other hosts keep running); the progress line shows the
// countdown.
func (e *fuzzEngine) wafCooldownHost(hb *hostBucket, why string) {
	hb.wafMu.Lock()
	hb.pausedUntil = time.Now().Add(wafCooldown)
	hb.consec403 = 0
	hb.wafMu.Unlock()
	ioutil.Warn("WAF: %s %s -- cooling down %s before sending it more traffic", hb.name, why, wafCooldown)
}

// wafHaltedHost reports whether hb has been given up on this run.
func (hb *hostBucket) wafIsHalted() bool {
	hb.wafMu.Lock()
	defer hb.wafMu.Unlock()
	return hb.wafHalted
}

// wafPausedFor returns how long hb is still on cooldown (0 = not paused).
func (hb *hostBucket) wafPausedFor() time.Duration {
	hb.wafMu.Lock()
	defer hb.wafMu.Unlock()
	if d := time.Until(hb.pausedUntil); d > 0 {
		return d
	}
	return 0
}

// wafPreflight runs before a host is fuzzed: if an earlier run in this
// process was blocked by it, send one probe to a random path; a 403 means
// the block is still on, so the host starts out on cooldown.
func (e *fuzzEngine) wafPreflight(hb *hostBucket, base string) {
	if e.wafThreshold <= 0 || wafStrikeCount(hb.name) == 0 {
		return
	}
	probe := fmt.Sprintf("%s/srt-waf-probe-%06d", originOf(base), rand.Intn(1000000))
	req, err := http.NewRequest("GET", probe, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", e.ua)
	resp, err := e.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
	if resp.StatusCode == 403 {
		e.wafCooldownHost(hb, "is still returning 403 after an earlier block")
	}
}

// wafStatusFragment is the cooldown countdown for the progress line, e.g.
// " ⏸ cooldown example.com 4:32". Empty when no host is paused.
func (e *fuzzEngine) wafStatusFragment() string {
	var b strings.Builder
	for _, hb := range e.sched.hostsSnapshot() {
		if d := hb.wafPausedFor(); d > 0 {
			d = d.Round(time.Second)
			fmt.Fprintf(&b, "  ⏸ cooldown %s %d:%02d", shortHost(hb.name), int(d.Minutes()), int(d.Seconds())%60)
		}
	}
	return b.String()
}

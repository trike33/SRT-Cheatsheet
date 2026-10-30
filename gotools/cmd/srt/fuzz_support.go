package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---- rate limiting -------------------------------------------------------

// rateLimiter is a global token bucket shared by all workers, so the TOTAL
// request rate across the whole fuzz run is capped regardless of concurrency.
// This is the core of "precise control over the traffic I'm sending": you set
// a ceiling in requests/second and the engine never exceeds it.
type rateLimiter struct {
	tokens chan struct{}
	stop   chan struct{}
}

func newRateLimiter(perSecond int) *rateLimiter {
	if perSecond <= 0 {
		return nil // unlimited
	}
	l := &rateLimiter{
		tokens: make(chan struct{}, perSecond), // burst == 1s worth
		stop:   make(chan struct{}),
	}
	interval := time.Second / time.Duration(perSecond)
	if interval <= 0 {
		interval = time.Microsecond
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-t.C:
				select {
				case l.tokens <- struct{}{}:
				default: // bucket full; drop the token
				}
			}
		}
	}()
	return l
}

func (l *rateLimiter) wait() {
	if l != nil {
		<-l.tokens
	}
}

func (l *rateLimiter) close() {
	if l != nil {
		close(l.stop)
	}
}

// ---- numeric range sets (for -mc/-fc/-ms/-fs/-mw/-fw/-ml/-fl) -------------

type rangeSet struct {
	all    bool
	ranges [][2]int
}

// parseRangeSet parses "200-299,301,302" or "all" into a rangeSet.
func parseRangeSet(s string) (rangeSet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return rangeSet{}, nil
	}
	if s == "all" || s == "*" {
		return rangeSet{all: true}, nil
	}
	var rs rangeSet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil {
				return rs, fmt.Errorf("invalid range %q", part)
			}
			rs.ranges = append(rs.ranges, [2]int{a, b})
		} else {
			n, err := strconv.Atoi(part)
			if err != nil {
				return rs, fmt.Errorf("invalid number %q", part)
			}
			rs.ranges = append(rs.ranges, [2]int{n, n})
		}
	}
	return rs, nil
}

func (rs rangeSet) empty() bool { return !rs.all && len(rs.ranges) == 0 }

func (rs rangeSet) contains(n int) bool {
	if rs.all {
		return true
	}
	for _, r := range rs.ranges {
		if n >= r[0] && n <= r[1] {
			return true
		}
	}
	return false
}

// ---- response metadata & matcher ----------------------------------------

// respMeta is everything the matcher needs about one response.
type respMeta struct {
	status int
	size   int
	words  int
	lines  int
	body   []byte
}

// matcher holds the compiled match/filter rules. A response is SHOWN when it
// passes every configured matcher AND trips no configured filter. Filters win.
// Auto-calibration (soft-404 filtering) is handled per-directory by the engine,
// not here, so it can differ from one directory to the next.
type matcher struct {
	mc, fc rangeSet
	ms, fs rangeSet
	mw, fw rangeSet
	ml, fl rangeSet
	mr, fr *regexp.Regexp
}

// show decides whether a response should be reported.
func (m *matcher) show(r respMeta) bool {
	// Matchers: each configured matcher must pass.
	if !m.mc.empty() && !m.mc.contains(r.status) {
		return false
	}
	if !m.ms.empty() && !m.ms.contains(r.size) {
		return false
	}
	if !m.mw.empty() && !m.mw.contains(r.words) {
		return false
	}
	if !m.ml.empty() && !m.ml.contains(r.lines) {
		return false
	}
	if m.mr != nil && !m.mr.Match(r.body) {
		return false
	}
	// Filters: any configured filter that trips hides the response.
	if !m.fc.empty() && m.fc.contains(r.status) {
		return false
	}
	if !m.fs.empty() && m.fs.contains(r.size) {
		return false
	}
	if !m.fw.empty() && m.fw.contains(r.words) {
		return false
	}
	if !m.fl.empty() && m.fl.contains(r.lines) {
		return false
	}
	if m.fr != nil && m.fr.Match(r.body) {
		return false
	}
	return true
}

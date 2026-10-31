package fuzz

import (
	"regexp"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
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

// ---- response metadata & matcher ----------------------------------------

// RespMeta is everything the matcher needs about one response. It's exported
// because the results database's JSON-sniffing (internal/results) builds one
// directly from a saved fuzz JSON line to reuse Record's shaping.
type RespMeta struct {
	Status int
	Size   int
	Words  int
	Lines  int
	Body   []byte
}

// matcher holds the compiled match/filter rules. A response is SHOWN when it
// passes every configured matcher AND trips no configured filter. Filters win.
// Auto-calibration (soft-404 filtering) is handled per-directory by the engine,
// not here, so it can differ from one directory to the next.
type matcher struct {
	mc, fc ioutil.RangeSet
	ms, fs ioutil.RangeSet
	mw, fw ioutil.RangeSet
	ml, fl ioutil.RangeSet
	mr, fr *regexp.Regexp
}

// show decides whether a response should be reported.
func (m *matcher) show(r RespMeta) bool {
	// Matchers: each configured matcher must pass.
	if !m.mc.Empty() && !m.mc.Contains(r.Status) {
		return false
	}
	if !m.ms.Empty() && !m.ms.Contains(r.Size) {
		return false
	}
	if !m.mw.Empty() && !m.mw.Contains(r.Words) {
		return false
	}
	if !m.ml.Empty() && !m.ml.Contains(r.Lines) {
		return false
	}
	if m.mr != nil && !m.mr.Match(r.Body) {
		return false
	}
	// Filters: any configured filter that trips hides the response.
	if !m.fc.Empty() && m.fc.Contains(r.Status) {
		return false
	}
	if !m.fs.Empty() && m.fs.Contains(r.Size) {
		return false
	}
	if !m.fw.Empty() && m.fw.Contains(r.Words) {
		return false
	}
	if !m.fl.Empty() && m.fl.Contains(r.Lines) {
		return false
	}
	if m.fr != nil && m.fr.Match(r.Body) {
		return false
	}
	return true
}

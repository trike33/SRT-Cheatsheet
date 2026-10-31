package fuzz

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
)

// Soft-404 fingerprinting for `fuzz -ac`.
//
// Many apps answer a missing path with a 200 whose length wobbles from
// request to request -- a CSRF token or timestamp, or the requested path
// echoed back in the page (so the size tracks the word's length). Exact-size
// matching misses those: 3302, 3305, 3310, 3312 are all "not found". So a
// fingerprint is a *band*, not a number:
//
//   - reflection-normalized size: size minus every echo of the word, so the
//     path's own length stops mattering;
//   - a tolerance (-ac-tol percent, floor of a few bytes) around the band;
//   - the word count must sit in a band too, so a genuinely different page
//     that merely has a similar byte length is still reported.
//
// Bands come from calibration probes, and are also learned at runtime: if
// -ac-learn hits in one directory share a status and near-identical shape,
// they are almost certainly an undetected soft-404 and get filtered.

const (
	minByteTol = 6 // absolute floor, so tiny pages still tolerate small jitter
	minWordTol = 2
)

type respBand struct {
	status     int
	minS, maxS int // normalized size
	minW, maxW int // word count
	hits       int
}

type calibData struct {
	mu       sync.Mutex
	tolPct   float64
	learnAt  int
	filter   []*respBand // always-filtered: calibrated + learned
	clusters []*respBand // candidate clusters still being counted
}

func newCalibData(tolPct float64, learnAt int) *calibData {
	return &calibData{tolPct: tolPct, learnAt: learnAt}
}

// normalizedSize is the body length with every echo of word removed.
func normalizedSize(meta RespMeta, word string) int {
	n := meta.Size
	if word != "" {
		n -= bytes.Count(meta.Body, []byte(word)) * len(word)
	}
	return n
}

func (c *calibData) tolerances(size, words int) (byteTol, wordTol int) {
	if c.tolPct <= 0 {
		return 0, 0
	}
	byteTol = max(minByteTol, int(math.Ceil(float64(size)*c.tolPct/100)))
	wordTol = max(minWordTol, int(math.Ceil(float64(words)*c.tolPct/100)))
	return
}

func (c *calibData) covers(b *respBand, status, ns, words int) bool {
	if b.status != status {
		return false
	}
	bt, wt := c.tolerances(max(b.maxS, ns), max(b.maxW, words))
	return ns >= b.minS-bt && ns <= b.maxS+bt && words >= b.minW-wt && words <= b.maxW+wt
}

// widen grows b to include the point, refusing if that would stretch the band
// beyond twice the tolerance (so a slow chain of near-misses can't snowball
// into a band that swallows real pages).
func (c *calibData) widen(b *respBand, ns, words int) bool {
	lo, hi := min(b.minS, ns), max(b.maxS, ns)
	wlo, whi := min(b.minW, words), max(b.maxW, words)
	bt, wt := c.tolerances(hi, whi)
	if c.tolPct > 0 && (hi-lo > 2*bt || whi-wlo > 2*wt) {
		return false
	}
	b.minS, b.maxS, b.minW, b.maxW = lo, hi, wlo, whi
	return true
}

func (c *calibData) addCalibrated(meta RespMeta, word string) {
	ns := normalizedSize(meta, word)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range c.filter {
		if c.covers(b, meta.Status, ns, meta.Words) && c.widen(b, ns, meta.Words) {
			return
		}
	}
	c.filter = append(c.filter, &respBand{status: meta.Status, minS: ns, maxS: ns, minW: meta.Words, maxW: meta.Words})
}

func (c *calibData) matches(meta RespMeta, word string) bool {
	ns := normalizedSize(meta, word)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range c.filter {
		if c.covers(b, meta.Status, ns, meta.Words) {
			return true
		}
	}
	return false
}

// observe feeds a response that was about to be reported into the runtime
// learner; it returns a message when this response tips a cluster over the
// threshold into the filter set.
func (c *calibData) observe(meta RespMeta, word string) string {
	if c.learnAt <= 0 {
		return ""
	}
	ns := normalizedSize(meta, word)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range c.clusters {
		if !c.covers(b, meta.Status, ns, meta.Words) || !c.widen(b, ns, meta.Words) {
			continue
		}
		b.hits++
		if b.hits >= c.learnAt {
			c.filter = append(c.filter, b)
			c.clusters = removeBand(c.clusters, b)
			return fmt.Sprintf("learned soft-404 after %d near-identical hits: %s (filtering the rest)", b.hits, b.String())
		}
		return ""
	}
	c.clusters = append(c.clusters, &respBand{status: meta.Status, minS: ns, maxS: ns, minW: meta.Words, maxW: meta.Words, hits: 1})
	return ""
}

func removeBand(s []*respBand, b *respBand) []*respBand {
	out := s[:0]
	for _, x := range s {
		if x != b {
			out = append(out, x)
		}
	}
	return out
}

func (b *respBand) String() string {
	sz := fmt.Sprintf("%d", b.minS)
	if b.maxS != b.minS {
		sz = fmt.Sprintf("%d-%d", b.minS, b.maxS)
	}
	return fmt.Sprintf("status=%d size=%s", b.status, sz)
}

func (c *calibData) describe() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var parts []string
	for _, b := range c.filter {
		parts = append(parts, b.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

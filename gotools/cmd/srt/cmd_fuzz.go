package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func init() {
	register(&command{
		name:    "fuzz",
		group:   "WEB recon",
		summary: "Scope-aware concurrent directory/file bruteforcer with precise traffic control",
		run:     runFuzz,
	})
}

// stringSlice collects repeated flags (-H, -w, -e).
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

const fuzzKeyword = "FUZZ"

// fuzzJob is one candidate to request. base is the template (still containing
// FUZZ) so recursion can re-expand it; word is the substituted value.
type fuzzJob struct {
	base  string
	word  string
	depth int
}

type fuzzResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Length int    `json:"length"`
	Words  int    `json:"words"`
	Lines  int    `json:"lines"`
}

func runFuzz(args []string) error {
	fs := flag.NewFlagSet("fuzz", flag.ExitOnError)

	// Targets & wordlists.
	var targets stringSlice
	fs.Var(&targets, "u", "target URL with FUZZ (repeatable for multi-host); FUZZ also works in -H/-d")
	tl := fs.String("tl", "", "file of target URLs, one per line (each may contain FUZZ)")
	var wordlists stringSlice
	fs.Var(&wordlists, "w", "wordlist file (repeatable). Omit to read the wordlist from stdin")
	var exts stringSlice
	fs.Var(&exts, "e", "extension to also try per word, e.g. -e .php -e .bak (repeatable)")
	scopeFile := fs.String("scope", "", "Burp scope JSON: only in-scope requests are sent (and seeds targets if no -u/-tl)")

	// Precise traffic control.
	method := fs.String("X", "GET", "HTTP method")
	var headers stringSlice
	fs.Var(&headers, "H", `extra header "Name: Value" (repeatable)`)
	body := fs.String("d", "", "request body")
	ua := fs.String("ua", defaultUA, "User-Agent")
	proxy := fs.String("proxy", "", "proxy URL, e.g. http://127.0.0.1:8080 to route through Burp")
	conc := fs.Int("c", 40, "total concurrent workers (global concurrency across all hosts)")
	rate := fs.Int("rate", 0, "max requests/second PER HOST (0 = unlimited) — keeps any single target from being flooded")
	rateGlobal := fs.Int("rate-global", 0, "max requests/second across ALL hosts combined (0 = unlimited) — protects your uplink")
	hostConc := fs.Int("hc", 0, "max concurrent requests PER HOST (0 = unlimited)")
	delay := fs.Duration("delay", 0, "fixed delay before each request")
	jitter := fs.Duration("jitter", 0, "random extra delay up to this much, added to -delay")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	retries := fs.Int("retries", 1, "retries on transport error/timeout")
	insecure := fs.Bool("insecure", true, "skip TLS verification")
	randomAgent := fs.Bool("random-agent", false, "rotate a random browser User-Agent per request")
	maxTime := fs.Duration("maxtime", 0, "overall deadline; stop the whole run after this long (0 = none)")
	maxErrors := fs.Int("maxerrors", 0, "abort a target after this many consecutive request errors (0 = never; good for dead hosts)")

	// Matchers / filters.
	mc := fs.String("mc", "200-299,301,302,307,308,401,403,405,500", "match HTTP codes (or 'all')")
	fc := fs.String("fc", "", "filter (hide) HTTP codes")
	ms := fs.String("ms", "", "match response sizes (bytes)")
	fsz := fs.String("fs", "", "filter response sizes (bytes)")
	mw := fs.String("mw", "", "match word counts")
	fw := fs.String("fw", "", "filter word counts")
	ml := fs.String("ml", "", "match line counts")
	fl := fs.String("fl", "", "filter line counts")
	mr := fs.String("mr", "", "match body regex")
	fr := fs.String("fr", "", "filter body regex")
	ac := fs.Bool("ac", false, "auto-calibrate: fingerprint soft-404s per directory and filter matching responses")
	hl := fs.String("hl", "", "highlight response bodies matching this regex (prints snippets under the hit)")
	autoThrottle := fs.Bool("auto-throttle", false, "automatically back off a host's rate when it returns 429/503")
	resume := fs.String("resume", "", "state file: skip already-done work and persist progress so a re-run continues")

	// Recursion & output.
	recursion := fs.Bool("recursion", false, "recurse into discovered directories")
	depth := fs.Int("depth", 0, "max recursion depth (0 = unlimited)")
	out := fs.String("o", "", "write matched results to this file")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of the table")
	silent := fs.Bool("silent", false, "print only matched URLs (pipe into httpx/nuclei)")
	colorFlag := fs.String("color", "auto", "color output: auto|always|never")

	if err := fs.Parse(args); err != nil {
		return err
	}

	cm := parseColorMode(*colorFlag)

	// Build the matcher.
	m, err := buildMatcher(*mc, *fc, *ms, *fsz, *mw, *fw, *ml, *fl, *mr, *fr)
	if err != nil {
		return err
	}

	var hlRe *regexp.Regexp
	if *hl != "" {
		hlRe, err = regexp.Compile(*hl)
		if err != nil {
			return fmt.Errorf("-hl: %w", err)
		}
	}

	// Load scope if given.
	var scope *scopeMatcher
	if *scopeFile != "" {
		scope, err = loadScopeMatcher(*scopeFile)
		if err != nil {
			return err
		}
	}

	// Determine base templates (possibly across many hosts).
	bases, err := fuzzBases(targets, *tl, scope)
	if err != nil {
		return err
	}
	if len(bases) == 0 {
		return errMissing("no targets: pass -u <url with FUZZ> (repeatable), -tl <file>, or -scope <file>")
	}

	// Load words (from -w files, else stdin).
	words, err := loadWords(wordlists)
	if err != nil {
		return err
	}
	if len(words) == 0 {
		return errMissing("empty wordlist (use -w <file> or pipe words on stdin)")
	}

	client := newHTTPClientOpts(*timeout, *insecure, *proxy, false)

	// Parse headers once.
	hdrs, err := parseHeaders(headers)
	if err != nil {
		return err
	}

	perHostIval := time.Duration(0)
	if *rate > 0 {
		perHostIval = time.Second / time.Duration(*rate)
	}
	globalLimiter := newRateLimiter(*rateGlobal)
	defer globalLimiter.close()

	eng := &fuzzEngine{
		client:       client,
		matcher:      m,
		scope:        scope,
		method:       *method,
		headers:      hdrs,
		body:         *body,
		ua:           *ua,
		delay:        *delay,
		jitter:       *jitter,
		retries:      *retries,
		recursion:    *recursion,
		maxDepth:     *depth,
		words:        words,
		exts:         exts,
		cm:           cm,
		jsonOut:      *jsonOut,
		silent:       *silent,
		visited:      map[string]struct{}{},
		workerCount:  max(1, *conc),
		randomAgent:  *randomAgent,
		maxTime:      *maxTime,
		maxErrors:    *maxErrors,
		baseErrors:   map[string]int{},
		deadBases:    map[string]struct{}{},
		perHostIval:  perHostIval,
		perHostConc:  *hostConc,
		gLimiter:     globalLimiter,
		autocal:      *ac,
		cal:          map[string]*calibData{},
		hlRe:         hlRe,
		autoThrottle: *autoThrottle,
	}

	// Resume state: load prior progress and open the file for appends.
	if *resume != "" {
		if err := eng.initResume(*resume); err != nil {
			return err
		}
		defer eng.closeResume()
	}

	if *out != "" {
		w, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer w.Close()
		eng.outFile = w
	}

	eng.run(bases)
	return nil
}

// fuzzEngine holds shared state for one fuzz run.
type fuzzEngine struct {
	client      *http.Client
	matcher     *matcher
	scope       *scopeMatcher
	method      string
	headers     [][2]string
	body        string
	ua          string
	delay       time.Duration
	jitter      time.Duration
	retries     int
	recursion   bool
	maxDepth    int
	words       []string
	exts        []string
	cm          colorMode
	jsonOut     bool
	silent      bool
	workerCount int
	randomAgent bool
	maxTime     time.Duration
	maxErrors   int

	// multi-host scheduling.
	perHostIval  time.Duration // 0 = unlimited
	perHostConc  int           // 0 = unlimited
	gLimiter     *rateLimiter  // global rate cap across all hosts
	sched        *scheduler
	autoThrottle bool // adaptive per-host backoff on 429/503

	// per-directory soft-404 calibration (-ac).
	autocal bool
	calMu   sync.RWMutex
	cal     map[string]*calibData // keyed by base template

	// response-body highlighting (-hl).
	hlRe *regexp.Regexp

	// resumable runs (-resume).
	resumePath       string
	resumeW          *bufio.Writer
	resumeCloser     io.Closer
	resumeMu         sync.Mutex
	resumeDone       map[string]struct{} // targets completed in a prior run
	resumeDiscovered []string            // dirs discovered in a prior run, re-seeded
	resumeSkip       atomic.Int64

	outFile io.Writer
	outMu   sync.Mutex

	stopF atomic.Bool // set when the global deadline fires

	visited   map[string]struct{} // recursion bases already queued
	visitedMu sync.Mutex

	// per-target consecutive-error tracking, for -maxerrors.
	errMu      sync.Mutex
	baseErrors map[string]int
	deadBases  map[string]struct{}

	reqCount   atomic.Int64
	matchCount atomic.Int64
	skipCount  atomic.Int64 // out of scope
	errCount   atomic.Int64
}

// calibData holds a directory's soft-404 fingerprint (response sizes seen for
// random, non-existent paths under that directory).
type calibData struct {
	sizes map[int]struct{}
}

func (e *fuzzEngine) stopped() bool { return e.stopF.Load() }

// baseDead reports whether a target has been abandoned after too many
// consecutive errors (a dead/unreachable host).
func (e *fuzzEngine) baseDead(base string) bool {
	if e.maxErrors <= 0 {
		return false
	}
	e.errMu.Lock()
	defer e.errMu.Unlock()
	_, dead := e.deadBases[base]
	return dead
}

// recordResult updates the consecutive-error counter for a base; ok resets it,
// an error increments it and may mark the base dead.
func (e *fuzzEngine) recordResult(base string, ok bool) {
	if e.maxErrors <= 0 {
		return
	}
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if ok {
		e.baseErrors[base] = 0
		return
	}
	e.baseErrors[base]++
	if e.baseErrors[base] >= e.maxErrors {
		if _, already := e.deadBases[base]; !already {
			e.deadBases[base] = struct{}{}
			warn("abandoning %s after %d consecutive errors", hostOf(base), e.maxErrors)
		}
	}
}

func (e *fuzzEngine) run(bases []string) {
	// Re-seed directories discovered in a prior run (resume).
	if len(e.resumeDiscovered) > 0 {
		bases = dedupStrings(append(append([]string{}, bases...), e.resumeDiscovered...))
	}

	e.sched = newScheduler(e.workerCount, e.perHostIval, e.perHostConc, e.gLimiter, &e.stopF)

	// Seed a feeder per base, grouped by host so the scheduler can interleave
	// them. This happens before dispatch starts, so feeders>0 keeps it alive.
	// Calibration now happens per-directory inside feed().
	hosts := map[string]struct{}{}
	for _, b := range bases {
		hb := e.sched.hostBucket(hostOf(b))
		hosts[hb.name] = struct{}{}
		e.startFeeder(hb, b, 0)
	}
	if len(hosts) > 1 {
		warn("fuzzing %d hosts, work interleaved fairly across them", len(hosts))
	}

	// Workers drain ready jobs from the scheduler.
	var workers sync.WaitGroup
	for i := 0; i < e.workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for hj := range e.sched.ready {
				e.process(hj)
				e.sched.finish(hj.hb)
			}
		}()
	}

	// Progress ticker on stderr.
	stopProg := make(chan struct{})
	go e.progress(stopProg)

	// Global deadline: flip the stop flag so feeders stop queuing and the run
	// winds down.
	if e.maxTime > 0 {
		timer := time.AfterFunc(e.maxTime, func() {
			if !e.stopF.Swap(true) {
				warn("reached -maxtime %s, stopping", e.maxTime)
			}
		})
		defer timer.Stop()
	}

	go e.sched.dispatch()
	workers.Wait()
	close(stopProg)

	e.summary()
}

// startFeeder dedupes a base, registers a feeder with the scheduler, and
// launches it. Call it BEFORE finishing the request that triggers recursion so
// the scheduler never sees zero outstanding work mid-flight.
func (e *fuzzEngine) startFeeder(hb *hostBucket, base string, depth int) {
	e.visitedMu.Lock()
	if _, done := e.visited[base]; done {
		e.visitedMu.Unlock()
		return
	}
	e.visited[base] = struct{}{}
	e.visitedMu.Unlock()

	e.sched.addFeeder()
	go e.feed(hb, base, depth)
}

// feed calibrates this directory (if -ac) and then streams one job per word
// (and extension) into the host's queue, applying backpressure, before
// releasing its feeder registration.
func (e *fuzzEngine) feed(hb *hostBucket, base string, depth int) {
	defer e.sched.feederDone()
	if e.autocal {
		e.calibrate(base) // per-directory soft-404 fingerprint
	}
	for _, w := range e.words {
		if e.stopped() || e.baseDead(base) {
			return
		}
		for _, cand := range expandWord(w, e.exts) {
			e.sched.pushJob(hb, fuzzJob{base: base, word: cand, depth: depth})
		}
	}
}

// Package fuzz implements the fuzz command: a scope-aware concurrent
// directory/file bruteforcer with precise traffic control (per-host and
// global rate limits, fair multi-host scheduling), soft-404 band filtering
// (-ac), automatic extension discovery (-ext-auto, via recon/probe's
// tech-detect), and a resumable run log.
package fuzz

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

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/scope"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "fuzz",
		Group:   "WEB recon",
		Summary: "Scope-aware concurrent directory/file bruteforcer with precise traffic control",
		Run:     Run,
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

func Run(args []string) error {
	fs := flag.NewFlagSet("fuzz", flag.ExitOnError)

	// Targets & wordlists.
	var targets stringSlice
	fs.Var(&targets, "u", "target URL with FUZZ (repeatable for multi-host); FUZZ also works in -H/-d")
	tl := fs.String("tl", "", "file of target URLs, one per line (each may contain FUZZ)")
	var wordlists stringSlice
	fs.Var(&wordlists, "w", "wordlist file (repeatable). Omit to read the wordlist from stdin")
	var exts stringSlice
	extAuto := fs.Bool("ext-auto", false, "work out which extensions each host serves: tech-detect hints (PHP -> .php ...) plus live verification of common extensions; combines with -e")
	fs.Var(&exts, "e", "extension to also try per word, e.g. -e .php -e .bak (repeatable)")
	scopeFile := fs.String("scope", "", "Burp scope JSON: only in-scope requests are sent (and seeds targets if no -u/-tl)")

	// Precise traffic control.
	method := fs.String("X", "GET", "HTTP method")
	var headers stringSlice
	fs.Var(&headers, "H", `extra header "Name: Value" (repeatable)`)
	body := fs.String("d", "", "request body")
	ua := fs.String("ua", netx.DefaultUA, "User-Agent")
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
	acTol := fs.Float64("ac-tol", 1.0, "with -ac: size/word tolerance in percent -- a soft-404 whose length jitters (dynamic tokens, reflected path) still matches; 0 = exact sizes only")
	acLearn := fs.Int("ac-learn", 12, "with -ac: if this many hits in one directory share a status and near-identical size, treat them as an undetected soft-404 and filter the rest (0 = off)")
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

	cm := colorout.ParseMode(*colorFlag)

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
	var sc *scope.Matcher
	if *scopeFile != "" {
		sc, err = scope.LoadScopeMatcher(*scopeFile)
		if err != nil {
			return err
		}
	}

	// Determine base templates (possibly across many hosts).
	bases, err := fuzzBases(targets, *tl, sc)
	if err != nil {
		return err
	}
	if len(bases) == 0 {
		return ioutil.ErrMissing("no targets: pass -u <url with FUZZ> (repeatable), -tl <file>, or -scope <file>")
	}

	// Load words (from -w files, else stdin).
	words, err := loadWords(wordlists)
	if err != nil {
		return err
	}
	if len(words) == 0 {
		return ioutil.ErrMissing("empty wordlist (use -w <file> or pipe words on stdin)")
	}

	client := netx.NewClientOpts(*timeout, *insecure, *proxy, false)

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
		scope:        sc,
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
		extAuto:      *extAuto,
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
		acTol:        *acTol,
		acLearn:      *acLearn,
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
	scope       *scope.Matcher
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
	extAuto     bool
	extc        extCache
	cm          colorout.Mode
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
	acTol   float64 // -ac-tol, percent
	acLearn int     // -ac-learn threshold
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
	planned    atomic.Int64 // jobs queued so far (grows as recursion finds directories)
	matchCount atomic.Int64
	skipCount  atomic.Int64 // out of scope
	errCount   atomic.Int64
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
			ioutil.Warn("abandoning %s after %d consecutive errors", hostOf(base), e.maxErrors)
		}
	}
}

func (e *fuzzEngine) run(bases []string) {
	// Re-seed directories discovered in a prior run (resume).
	if len(e.resumeDiscovered) > 0 {
		bases = ioutil.DedupStrings(append(append([]string{}, bases...), e.resumeDiscovered...))
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
		ioutil.Warn("fuzzing %d hosts, work interleaved fairly across them", len(hosts))
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
				ioutil.Warn("reached -maxtime %s, stopping", e.maxTime)
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
	exts := e.extsFor(base) // -e plus -ext-auto's per-host discoveries
	e.planned.Add(int64(len(e.words) * (1 + len(exts))))
	for _, w := range e.words {
		if e.stopped() || e.baseDead(base) {
			return
		}
		for _, cand := range expandWord(w, exts) {
			e.sched.pushJob(hb, fuzzJob{base: base, word: cand, depth: depth})
		}
	}
}

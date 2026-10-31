package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// buildMatcher compiles all the match/filter flags into a matcher.
func buildMatcher(mc, fc, ms, fsz, mw, fw, ml, fl, mr, fr string) (*matcher, error) {
	m := &matcher{}
	var err error
	parse := func(s string, dst *rangeSet, name string) error {
		rs, e := parseRangeSet(s)
		if e != nil {
			return fmt.Errorf("-%s: %w", name, e)
		}
		*dst = rs
		return nil
	}
	if err = parse(mc, &m.mc, "mc"); err != nil {
		return nil, err
	}
	if err = parse(fc, &m.fc, "fc"); err != nil {
		return nil, err
	}
	if err = parse(ms, &m.ms, "ms"); err != nil {
		return nil, err
	}
	if err = parse(fsz, &m.fs, "fs"); err != nil {
		return nil, err
	}
	if err = parse(mw, &m.mw, "mw"); err != nil {
		return nil, err
	}
	if err = parse(fw, &m.fw, "fw"); err != nil {
		return nil, err
	}
	if err = parse(ml, &m.ml, "ml"); err != nil {
		return nil, err
	}
	if err = parse(fl, &m.fl, "fl"); err != nil {
		return nil, err
	}
	if mr != "" {
		if m.mr, err = regexp.Compile(mr); err != nil {
			return nil, fmt.Errorf("-mr: %w", err)
		}
	}
	if fr != "" {
		if m.fr, err = regexp.Compile(fr); err != nil {
			return nil, fmt.Errorf("-fr: %w", err)
		}
	}
	return m, nil
}

// fuzzBases returns the base templates (each containing FUZZ) across all
// targets: explicit -u values (repeatable), a -tl target-list file, and/or the
// include hosts of a Burp scope file. Duplicates are collapsed.
func fuzzBases(targets stringSlice, tlFile string, scope *scopeMatcher) ([]string, error) {
	var raw []string
	raw = append(raw, targets...)
	if tlFile != "" {
		lines, err := inputLines(tlFile)
		if err != nil {
			return nil, err
		}
		raw = append(raw, lines...)
	}

	var bases []string
	for _, t := range raw {
		if !strings.Contains(t, fuzzKeyword) {
			// Dir-mode convenience: append FUZZ to the path.
			t = strings.TrimRight(t, "/") + "/" + fuzzKeyword
		}
		bases = append(bases, t)
	}

	// Seed from scope only when no explicit targets were given.
	if len(bases) == 0 && scope != nil {
		for _, h := range scope.includeHosts() {
			bases = append(bases, "https://"+h+"/"+fuzzKeyword)
		}
	}
	return dedupStrings(bases), nil
}

// loadWords reads every wordlist file (or stdin when none are given).
func loadWords(files stringSlice) ([]string, error) {
	if len(files) == 0 {
		return inputLines("")
	}
	seen := map[string]struct{}{}
	var words []string
	for _, f := range files {
		lines, err := inputLines(f)
		if err != nil {
			return nil, err
		}
		for _, w := range lines {
			if _, dup := seen[w]; dup {
				continue
			}
			seen[w] = struct{}{}
			words = append(words, w)
		}
	}
	return words, nil
}

func parseHeaders(raw stringSlice) ([][2]string, error) {
	var out [][2]string
	for _, h := range raw {
		name, val, ok := strings.Cut(h, ":")
		if !ok {
			return nil, fmt.Errorf("bad header %q (want 'Name: Value')", h)
		}
		out = append(out, [2]string{strings.TrimSpace(name), strings.TrimSpace(val)})
	}
	return out, nil
}

func expandWord(word string, exts []string) []string {
	out := make([]string, 0, 1+len(exts))
	out = append(out, word)
	for _, e := range exts {
		out = append(out, word+e)
	}
	return out
}

// process issues one request and handles matching, output, and recursion.
func (e *fuzzEngine) process(hj hostJob) {
	j := hj.job
	// Fast no-op once the deadline fired or the target was abandoned.
	if e.stopped() || e.baseDead(j.base) {
		return
	}

	target := strings.ReplaceAll(j.base, fuzzKeyword, j.word)

	// Resume: skip targets already completed in a prior run.
	if e.resumeSkipTarget(target) {
		e.resumeSkip.Add(1)
		return
	}

	// Scope gate: never send a request outside the configured scope.
	if e.scope != nil && !e.scope.inScope(target) {
		e.skipCount.Add(1)
		return
	}

	meta, loc, err := e.doRequest(target, j.word)
	if err != nil {
		e.errCount.Add(1)
		e.recordResult(j.base, false)
		return
	}
	e.reqCount.Add(1)
	hj.hb.reqs.Add(1)
	e.recordResult(j.base, true)

	// Adaptive per-host throttle on rate-limit / overload responses.
	if e.autoThrottle {
		if meta.status == 429 || meta.status == 503 {
			e.sched.throttle(hj.hb)
		} else {
			e.sched.relax(hj.hb)
		}
	}

	// Mark this target done for resume (regardless of match).
	e.resumeRecord('R', target)

	if e.matcher.show(meta) && !e.softFiltered(j.base, j.word, meta) {
		e.matchCount.Add(1)
		hj.hb.matches.Add(1)
		e.emit(target, meta)

		if e.recursion && (e.maxDepth == 0 || j.depth < e.maxDepth) && dirRedirect(target, loc) {
			newBase := strings.TrimRight(target, "/") + "/" + fuzzKeyword
			if e.scope == nil || e.scope.inScope(strings.ReplaceAll(newBase, fuzzKeyword, "")) {
				// Recursion stays on the SAME host bucket, so it inherits that
				// host's rate/concurrency limits.
				e.resumeRecord('D', newBase)
				e.startFeeder(hj.hb, newBase, j.depth+1)
			}
		}
	}
}

// doRequest performs the HTTP request with delay/jitter and retries, and
// returns the response metadata plus any Location header. Per-host and global
// rate limiting are enforced by the scheduler before the job reaches here.
func (e *fuzzEngine) doRequest(target, word string) (respMeta, string, error) {
	var lastErr error
	for attempt := 0; attempt <= e.retries; attempt++ {
		// Per-request pacing: fixed delay + optional random jitter.
		if e.delay > 0 || e.jitter > 0 {
			d := e.delay
			if e.jitter > 0 {
				d += time.Duration(rand.Int63n(int64(e.jitter) + 1))
			}
			time.Sleep(d)
		}

		var bodyReader io.Reader
		reqBody := strings.ReplaceAll(e.body, fuzzKeyword, word)
		if reqBody != "" {
			bodyReader = strings.NewReader(reqBody)
		}
		req, err := http.NewRequest(e.method, target, bodyReader)
		if err != nil {
			return respMeta{}, "", err // malformed URL won't improve on retry
		}
		ua := e.ua
		if e.randomAgent {
			ua = randomUA()
		}
		req.Header.Set("User-Agent", ua)
		for _, h := range e.headers {
			req.Header.Set(h[0], strings.ReplaceAll(h[1], fuzzKeyword, word))
		}

		resp, err := e.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		meta := respMeta{
			status: resp.StatusCode,
			size:   len(body),
			words:  len(bytes.Fields(body)),
			lines:  bytes.Count(body, []byte{'\n'}),
			body:   body,
		}
		return meta, resp.Header.Get("Location"), nil
	}
	return respMeta{}, "", lastErr
}

// calibrate probes random paths under a directory and records the response
// fingerprints that would otherwise be reported, so this directory's soft-404s
// get filtered. Probes vary in length (and carry an extension) so reflected
// paths and extension-specific error pages are all seen. Calibration is
// per-directory: a fingerprint that is a soft-404 under /admin won't hide a
// real finding elsewhere.
func (e *fuzzEngine) calibrate(base string) {
	cd := newCalibData(e.acTol, e.acLearn)
	for _, p := range []struct {
		n   int
		ext string
	}{{6, ""}, {12, ""}, {20, ""}, {6, ".txt"}, {12, ".html"}, {20, ".php"}} {
		rnd := randToken(p.n) + p.ext
		target := strings.ReplaceAll(base, fuzzKeyword, rnd)
		if e.scope != nil && !e.scope.inScope(target) {
			continue
		}
		meta, _, err := e.doRequest(target, rnd)
		if err != nil {
			continue
		}
		if e.matcher.show(meta) {
			cd.addCalibrated(meta, rnd)
		}
	}
	e.calMu.Lock()
	e.cal[base] = cd // kept even when empty: it still learns at runtime
	e.calMu.Unlock()

	if d := cd.describe(); d != "" {
		warn("calibrate %s: filtering soft-404 %s", strings.TrimSuffix(base, fuzzKeyword), d)
	}
}

// softFiltered reports whether a response matches this directory's soft-404
// fingerprint, calibrated up front or learned from the run so far.
func (e *fuzzEngine) softFiltered(base, word string, meta respMeta) bool {
	if !e.autocal {
		return false
	}
	e.calMu.RLock()
	cd := e.cal[base]
	e.calMu.RUnlock()
	if cd == nil {
		return false
	}
	if cd.matches(meta, word) {
		return true
	}
	if msg := cd.observe(meta, word); msg != "" {
		warn("calibrate %s: %s", strings.TrimSuffix(base, fuzzKeyword), msg)
	}
	return false
}

// emit writes a matched result to stdout (and the output file if configured).
func (e *fuzzEngine) emit(target string, meta respMeta) {
	sink.add(fuzzRecord(target, meta))
	var snippets, plain []string
	if e.hlRe != nil {
		snippets, plain = e.buildHighlights(meta.body)
	}

	e.outMu.Lock()
	defer e.outMu.Unlock()

	switch {
	case e.jsonOut:
		b, _ := json.Marshal(struct {
			fuzzResult
			Highlights []string `json:"highlights,omitempty"`
		}{fuzzResult{target, meta.status, meta.size, meta.words, meta.lines}, plain})
		fmt.Println(string(b))
		e.writeFile(string(b))
	case e.silent:
		fmt.Println(target)
		e.writeFile(target)
	default:
		line := fmt.Sprintf("%-3d  %7db  %5dw  %4dl  %s", meta.status, meta.size, meta.words, meta.lines, target)
		fmt.Println(e.cm.wrap(statusColor(meta.status), line))
		for _, s := range snippets {
			fmt.Println("        " + s)
		}
		e.writeFile(fmt.Sprintf("%d %s", meta.status, target))
	}
}

// buildHighlights returns colored context snippets (for the table) and the
// plain matched substrings (for JSON) for the -hl regex, capped to a few hits.
func (e *fuzzEngine) buildHighlights(body []byte) (snippets, plain []string) {
	locs := e.hlRe.FindAllIndex(body, 8)
	seen := map[string]struct{}{}
	for _, loc := range locs {
		match := string(body[loc[0]:loc[1]])
		if _, dup := seen[match]; dup {
			continue
		}
		seen[match] = struct{}{}
		plain = append(plain, match)

		start := loc[0] - 30
		if start < 0 {
			start = 0
		}
		end := loc[1] + 30
		if end > len(body) {
			end = len(body)
		}
		ctx := string(body[start:loc[0]]) + e.cm.wrap(ansiYellow, match) + string(body[loc[1]:end])
		ctx = strings.TrimSpace(strings.ReplaceAll(ctx, "\n", " "))
		snippets = append(snippets, "↳ "+ctx)
		if len(plain) >= 3 {
			break
		}
	}
	return snippets, plain
}

func (e *fuzzEngine) writeFile(line string) {
	if e.outFile != nil {
		fmt.Fprintln(e.outFile, line)
	}
}

// progress prints a compact live counter to stderr (only on a TTY, so pipes
// and files stay clean), broken out per host with each host's req/s.
func (e *fuzzEngine) progress(stop <-chan struct{}) {
	if e.silent || !isTerminal(os.Stderr) {
		return
	}
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	prev := map[string]int64{}
	last := time.Now()
	frame := 0
	for {
		select {
		case <-stop:
			e.flushResume()
			fmt.Fprint(os.Stderr, "\r\033[K")
			return
		case now := <-t.C:
			dt := now.Sub(last).Seconds()
			last = now
			e.flushResume()

			var b strings.Builder
			fmt.Fprintf(&b, "\r\033[K%s reqs=%d matches=%d skip=%d err=%d",
				spinner(frame), e.reqCount.Load(), e.matchCount.Load(), e.skipCount.Load(), e.errCount.Load())
			frame++

			hosts := e.sched.hostsSnapshot()
			shown := 0
			for _, hb := range hosts {
				reqs := hb.reqs.Load()
				if reqs == 0 && hb.matches.Load() == 0 {
					continue
				}
				if shown >= 6 {
					fmt.Fprintf(&b, " +%d more", len(hosts)-shown)
					break
				}
				rate := 0.0
				if dt > 0 {
					rate = float64(reqs-prev[hb.name]) / dt
				}
				prev[hb.name] = reqs
				fmt.Fprintf(&b, "  %s=%d/%d(%.0f/s)", shortHost(hb.name), hb.matches.Load(), reqs, rate)
				shown++
			}
			fmt.Fprint(os.Stderr, b.String())
		}
	}
}

// shortHost trims a host:port to something compact for the progress line.
func shortHost(h string) string {
	if i := strings.IndexByte(h, ':'); i > 0 {
		return h[:i]
	}
	return h
}

func (e *fuzzEngine) summary() {
	extra := ""
	if e.resumeSkip.Load() > 0 {
		extra = fmt.Sprintf(", %d resumed-skipped", e.resumeSkip.Load())
	}
	warn("done: %d requests, %d matches, %d out-of-scope skipped, %d errors%s",
		e.reqCount.Load(), e.matchCount.Load(), e.skipCount.Load(), e.errCount.Load(), extra)
}

// ---- small helpers -------------------------------------------------------

func statusColor(status int) string {
	switch {
	case status >= 200 && status < 300:
		return ansiGreen
	case status >= 300 && status < 400:
		return ansiCyan
	case status == 401 || status == 403:
		return ansiYellow
	case status >= 500:
		return ansiRed
	default:
		return ansiRed
	}
}

// dirRedirect reports whether loc is a redirect from target to target+"/",
// i.e. target is a directory.
func dirRedirect(target, loc string) bool {
	if loc == "" {
		return false
	}
	tu, err := url.Parse(target)
	if err != nil {
		return false
	}
	lu, err := url.Parse(loc)
	if err != nil {
		return false
	}
	resolved := tu.ResolveReference(lu)
	return strings.TrimRight(resolved.Path, "/") == strings.TrimRight(tu.Path, "/") &&
		strings.HasSuffix(resolved.Path, "/") &&
		(lu.Host == "" || lu.Host == tu.Host)
}

func hostOf(rawurl string) string {
	if u, err := url.Parse(rawurl); err == nil {
		return u.Host
	}
	return rawurl
}

// randomAgents is a small pool of realistic browser User-Agents for -random-agent.
var randomAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
}

func randomUA() string { return randomAgents[rand.Intn(len(randomAgents))] }

const tokenAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func randToken(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = tokenAlphabet[rand.Intn(len(tokenAlphabet))]
	}
	return string(b)
}

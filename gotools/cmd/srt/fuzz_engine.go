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

// fuzzBases returns the list of base templates (each containing FUZZ). It takes
// an explicit -u, or seeds https://host/FUZZ from a scope file's include hosts.
func fuzzBases(target string, scope *scopeMatcher) ([]string, error) {
	if target != "" {
		if !strings.Contains(target, fuzzKeyword) {
			// Dir-mode convenience: append FUZZ to the path.
			target = strings.TrimRight(target, "/") + "/" + fuzzKeyword
		}
		return []string{target}, nil
	}
	if scope != nil {
		var bases []string
		for _, h := range scope.includeHosts() {
			bases = append(bases, "https://"+h+"/"+fuzzKeyword)
		}
		return bases, nil
	}
	return nil, nil
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

// enqueueBase expands every word (and extension) against a base template and
// pushes the jobs. Jobs are sent from a goroutine so recursion never deadlocks
// a worker that is trying to enqueue while the channel is full.
func (e *fuzzEngine) enqueueBase(base string, depth int) {
	e.visitedMu.Lock()
	if _, done := e.visited[base]; done {
		e.visitedMu.Unlock()
		return
	}
	e.visited[base] = struct{}{}
	e.visitedMu.Unlock()

	for _, w := range e.words {
		for _, cand := range expandWord(w, e.exts) {
			e.pending.Add(1)
			job := fuzzJob{base: base, word: cand, depth: depth}
			go func(j fuzzJob) { e.jobs <- j }(job)
		}
	}
}

// process issues one request and handles matching, output, and recursion.
func (e *fuzzEngine) process(j fuzzJob) {
	target := strings.ReplaceAll(j.base, fuzzKeyword, j.word)

	// Scope gate: never send a request outside the configured scope.
	if e.scope != nil && !e.scope.inScope(target) {
		e.skipCount.Add(1)
		return
	}

	meta, loc, err := e.doRequest(target, j.word)
	if err != nil {
		e.errCount.Add(1)
		return
	}
	e.reqCount.Add(1)

	if e.matcher.show(meta) {
		e.matchCount.Add(1)
		e.emit(target, meta)

		if e.recursion && (e.maxDepth == 0 || j.depth < e.maxDepth) && dirRedirect(target, loc) {
			newBase := strings.TrimRight(target, "/") + "/" + fuzzKeyword
			if e.scope == nil || e.scope.inScope(strings.ReplaceAll(newBase, fuzzKeyword, "")) {
				e.enqueueBase(newBase, j.depth+1)
			}
		}
	}
}

// doRequest performs the HTTP request with delay/jitter, rate limiting, and
// retries, and returns the response metadata plus any Location header.
func (e *fuzzEngine) doRequest(target, word string) (respMeta, string, error) {
	var lastErr error
	for attempt := 0; attempt <= e.retries; attempt++ {
		// Precise pacing: fixed delay + optional random jitter, then a global
		// rate-limit token.
		if e.delay > 0 || e.jitter > 0 {
			d := e.delay
			if e.jitter > 0 {
				d += time.Duration(rand.Int63n(int64(e.jitter) + 1))
			}
			time.Sleep(d)
		}
		e.limiter.wait()

		var bodyReader io.Reader
		reqBody := strings.ReplaceAll(e.body, fuzzKeyword, word)
		if reqBody != "" {
			bodyReader = strings.NewReader(reqBody)
		}
		req, err := http.NewRequest(e.method, target, bodyReader)
		if err != nil {
			return respMeta{}, "", err // malformed URL won't improve on retry
		}
		req.Header.Set("User-Agent", e.ua)
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

// calibrate sends a few random paths under base and records the fingerprints of
// responses that would otherwise be reported, so soft-404s get auto-filtered.
func (e *fuzzEngine) calibrate(base string) {
	const probes = 4
	for i := 0; i < probes; i++ {
		rnd := randToken(16)
		target := strings.ReplaceAll(base, fuzzKeyword, rnd)
		if e.scope != nil && !e.scope.inScope(target) {
			continue
		}
		meta, _, err := e.doRequest(target, rnd)
		if err != nil {
			continue
		}
		if e.matcher.show(meta) {
			e.matcher.addAuto(meta.size, meta.words)
			warn("calibrate: filtering size=%d words=%d (soft-404 on %s)", meta.size, meta.words, hostOf(base))
		}
	}
}

// emit writes a matched result to stdout (and the output file if configured).
func (e *fuzzEngine) emit(target string, meta respMeta) {
	e.outMu.Lock()
	defer e.outMu.Unlock()

	switch {
	case e.jsonOut:
		b, _ := json.Marshal(fuzzResult{target, meta.status, meta.size, meta.words, meta.lines})
		fmt.Println(string(b))
		e.writeFile(string(b))
	case e.silent:
		fmt.Println(target)
		e.writeFile(target)
	default:
		line := fmt.Sprintf("%-3d  %7db  %5dw  %4dl  %s", meta.status, meta.size, meta.words, meta.lines, target)
		fmt.Println(e.cm.wrap(statusColor(meta.status), line))
		e.writeFile(fmt.Sprintf("%d %s", meta.status, target))
	}
}

func (e *fuzzEngine) writeFile(line string) {
	if e.outFile != nil {
		fmt.Fprintln(e.outFile, line)
	}
}

// progress prints a compact live counter to stderr (only on a TTY, so pipes
// and files stay clean).
func (e *fuzzEngine) progress(stop <-chan struct{}) {
	if e.silent || !isTerminal(os.Stderr) {
		return
	}
	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-stop:
			fmt.Fprint(os.Stderr, "\r\033[K")
			return
		case <-t.C:
			fmt.Fprintf(os.Stderr, "\r\033[K[*] reqs=%d matches=%d skipped=%d errors=%d",
				e.reqCount.Load(), e.matchCount.Load(), e.skipCount.Load(), e.errCount.Load())
		}
	}
}

func (e *fuzzEngine) summary() {
	warn("done: %d requests, %d matches, %d out-of-scope skipped, %d errors",
		e.reqCount.Load(), e.matchCount.Load(), e.skipCount.Load(), e.errCount.Load())
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

const tokenAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func randToken(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = tokenAlphabet[rand.Intn(len(tokenAlphabet))]
	}
	return string(b)
}

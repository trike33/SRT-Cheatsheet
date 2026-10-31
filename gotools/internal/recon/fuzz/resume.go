package fuzz

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

// Resume state is a simple append-only log next to the run:
//
//	R <target-url>   a request that completed (skip it on a re-run)
//	D <base-with-FUZZ>  a directory discovered by recursion (re-seed it)
//
// On restart srt loads the file, skips every completed target, and re-seeds the
// discovered directories so recursion continues even though the request that
// originally revealed each directory is now skipped.
//
// The file grows by one line per request for as long as the run lasts, which
// on a big multi-host job can mean millions of lines even though
// resumeDone/visited already hold the exact same facts deduped in memory.
// Every resumeCompactEvery lines, compactResume rewrites it down to one line
// per completed target and one per discovered directory -- the minimum that
// still reconstructs the run's state on a restart.
var resumeCompactEvery = 20000 // var (not const) so tests can lower it

// initResume loads any prior state and opens the file for appends.
func (e *fuzzEngine) initResume(path string) error {
	e.resumePath = path
	e.resumeDone = map[string]struct{}{}

	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if len(line) < 3 || line[1] != ' ' {
				continue
			}
			val := strings.TrimSpace(line[2:])
			switch line[0] {
			case 'R':
				e.resumeDone[val] = struct{}{}
			case 'D':
				e.resumeDiscovered = append(e.resumeDiscovered, val)
			}
		}
		f.Close()
		if len(e.resumeDone) > 0 || len(e.resumeDiscovered) > 0 {
			ioutil.Warn("resume: %d done, %d discovered dir(s) loaded from %s",
				len(e.resumeDone), len(e.resumeDiscovered), path)
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("resume file: %w", err)
	}
	e.resumeCloser = f
	e.resumeW = bufio.NewWriter(f)
	return nil
}

// resumeSkipTarget reports whether a target was completed in a prior run, or
// already this run (resumeRecord keeps resumeDone current as it writes, so
// compaction can rebuild the file from it at any point mid-run).
func (e *fuzzEngine) resumeSkipTarget(target string) bool {
	e.resumeDoneMu.RLock()
	defer e.resumeDoneMu.RUnlock()
	if e.resumeDone == nil {
		return false
	}
	_, ok := e.resumeDone[target]
	return ok
}

// resumeRecord appends a state line (buffered; flushed periodically + on
// close) and, for a completed request, records it in the in-memory set too
// -- otherwise compaction could only ever see what a prior run's file held
// at startup, not what this run has completed since.
func (e *fuzzEngine) resumeRecord(kind byte, val string) {
	if e.resumeW == nil {
		return
	}
	if kind == 'R' {
		e.resumeDoneMu.Lock()
		if e.resumeDone == nil {
			e.resumeDone = map[string]struct{}{}
		}
		e.resumeDone[val] = struct{}{}
		e.resumeDoneMu.Unlock()
	}

	e.resumeMu.Lock()
	e.resumeW.WriteByte(kind)
	e.resumeW.WriteByte(' ')
	e.resumeW.WriteString(val)
	e.resumeW.WriteByte('\n')
	e.resumeLines++
	due := e.resumeLines >= resumeCompactEvery
	e.resumeMu.Unlock()

	if due {
		e.compactResume()
	}
}

// compactResume rewrites the resume file from the current in-memory state
// (every completed target, every visited/discovered base) instead of its own
// accumulated history, then reopens it for append. A failure leaves the
// original file and writer untouched -- compaction is an optimization, never
// a condition the run depends on.
func (e *fuzzEngine) compactResume() {
	if e.resumePath == "" {
		return
	}
	e.resumeMu.Lock()
	if e.resumeW != nil {
		e.resumeW.Flush()
	}
	e.resumeMu.Unlock()

	tmp := e.resumePath + ".compact"
	f, err := os.Create(tmp)
	if err != nil {
		ioutil.Warn("resume compaction: %v", err)
		return
	}
	w := bufio.NewWriter(f)

	e.resumeDoneMu.RLock()
	for t := range e.resumeDone {
		w.WriteByte('R')
		w.WriteByte(' ')
		w.WriteString(t)
		w.WriteByte('\n')
	}
	e.resumeDoneMu.RUnlock()

	e.visitedMu.Lock()
	for b := range e.visited {
		w.WriteByte('D')
		w.WriteByte(' ')
		w.WriteString(b)
		w.WriteByte('\n')
	}
	e.visitedMu.Unlock()

	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		ioutil.Warn("resume compaction: %v", err)
		return
	}
	f.Close()

	e.resumeMu.Lock()
	defer e.resumeMu.Unlock()
	if e.resumeCloser != nil {
		e.resumeCloser.Close()
	}
	if err := os.Rename(tmp, e.resumePath); err != nil {
		ioutil.Warn("resume compaction: %v", err)
		os.Remove(tmp)
	}
	nf, err := os.OpenFile(e.resumePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		ioutil.Warn("resume compaction: reopening %s: %v", e.resumePath, err)
		e.resumeW = nil
		e.resumeCloser = nil
		return
	}
	e.resumeCloser = nf
	e.resumeW = bufio.NewWriter(nf)
	e.resumeLines = 0
}

func (e *fuzzEngine) flushResume() {
	if e.resumeW == nil {
		return
	}
	e.resumeMu.Lock()
	e.resumeW.Flush()
	e.resumeMu.Unlock()
}

func (e *fuzzEngine) closeResume() {
	if e.resumeW == nil {
		return
	}
	e.flushResume()
	if e.resumeCloser != nil {
		e.resumeCloser.Close()
	}
}

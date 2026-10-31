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

// resumeSkipTarget reports whether a target was completed in a prior run.
func (e *fuzzEngine) resumeSkipTarget(target string) bool {
	if e.resumeDone == nil {
		return false
	}
	_, ok := e.resumeDone[target] // read-only after init, no lock needed
	return ok
}

// resumeRecord appends a state line (buffered; flushed periodically + on close).
func (e *fuzzEngine) resumeRecord(kind byte, val string) {
	if e.resumeW == nil {
		return
	}
	e.resumeMu.Lock()
	e.resumeW.WriteByte(kind)
	e.resumeW.WriteByte(' ')
	e.resumeW.WriteString(val)
	e.resumeW.WriteByte('\n')
	e.resumeMu.Unlock()
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

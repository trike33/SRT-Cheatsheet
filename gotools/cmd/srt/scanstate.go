package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// scanState makes a portscan resumable. The scan walks a fixed sequence of
// (host, port) probes -- host-major, ports in order -- so progress is a single
// number: the watermark, the count of leading probes that have all finished.
// Probes complete out of order under concurrency, so completions are tracked
// in a bitmap and the watermark advances over the contiguous finished prefix.
// Probes finished beyond the watermark are simply redone on resume (cheap,
// and never wrong).
//
// State file (JSON lines, append-only):
//
//	{"fp":"<sha>","total":N}        header; fp fingerprints hosts+ports
//	{"open":{...scanResult...}}     an open port found (written immediately)
//	{"w":K}                         watermark checkpoint (latest wins)
type scanState struct {
	mu    sync.Mutex
	f     *os.File
	w     *bufio.Writer
	done  []uint64
	mark  int64 // watermark: probes [0,mark) are finished
	saved int64 // last watermark written

	Prior []scanResult // open results recovered from a previous run
	total int64
}

func scanFingerprint(hosts []string, ports []int) string {
	h := sha256.New()
	for _, x := range hosts {
		fmt.Fprintln(h, x)
	}
	fmt.Fprintln(h, "--")
	for _, p := range ports {
		fmt.Fprintln(h, p)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// openScanState loads path (if it exists and matches this scan) or starts a
// fresh state file. A state from a different scan is an error rather than
// silently ignored, so a stale -resume file never skips the wrong work.
func openScanState(path string, hosts []string, ports []int) (*scanState, error) {
	total := int64(len(hosts)) * int64(len(ports))
	fp := scanFingerprint(hosts, ports)
	s := &scanState{done: make([]uint64, (total+63)/64), total: total}

	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		first := true
		for sc.Scan() {
			var rec struct {
				FP    string      `json:"fp"`
				Total int64       `json:"total"`
				W     *int64      `json:"w"`
				Open  *scanResult `json:"open"`
			}
			if json.Unmarshal(sc.Bytes(), &rec) != nil {
				continue // a torn last line from a hard kill
			}
			switch {
			case first && rec.FP != "":
				if rec.FP != fp {
					f.Close()
					return nil, fmt.Errorf("-resume %s belongs to a different scan (hosts/ports changed); delete it to start over", path)
				}
			case rec.W != nil:
				s.mark = min(*rec.W, total)
			case rec.Open != nil:
				s.Prior = append(s.Prior, *rec.Open)
			}
			first = false
		}
		f.Close()
		s.saved = s.mark
		for i := int64(0); i < s.mark; i++ {
			s.done[i/64] |= 1 << (i % 64)
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	s.f, s.w = f, bufio.NewWriter(f)
	if st, _ := f.Stat(); st != nil && st.Size() == 0 {
		s.line(map[string]any{"fp": fp, "total": total})
	}
	s.flushLocked()
	return s, nil
}

func (s *scanState) line(v any) {
	b, _ := json.Marshal(v)
	s.w.Write(b)
	s.w.WriteByte('\n')
}

func (s *scanState) flushLocked() { s.w.Flush() }

// Skip reports whether probe index i already finished in a previous run.
func (s *scanState) Skip(i int64) bool { return i < s.mark }

// Done records probe i as finished and advances the watermark.
func (s *scanState) Done(i int64) {
	s.mu.Lock()
	s.done[i/64] |= 1 << (i % 64)
	for s.mark < s.total && s.done[s.mark/64]&(1<<(s.mark%64)) != 0 {
		s.mark++
	}
	s.mu.Unlock()
}

// Open persists an open port immediately so it survives a hard stop.
func (s *scanState) Open(r scanResult) {
	s.mu.Lock()
	s.line(map[string]any{"open": r})
	s.flushLocked()
	s.mu.Unlock()
}

// Checkpoint writes the watermark if it moved.
func (s *scanState) Checkpoint() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mark != s.saved {
		s.line(map[string]any{"w": s.mark})
		s.saved = s.mark
	}
	s.flushLocked()
}

func (s *scanState) Progress() (done, total int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mark, s.total
}

func (s *scanState) Close() {
	s.Checkpoint()
	s.f.Close()
}

// startCheckpointing flushes every interval until the returned stop is called.
func (s *scanState) startCheckpointing(interval time.Duration) (stop func()) {
	quit := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-quit:
				return
			case <-t.C:
				s.Checkpoint()
			}
		}
	}()
	return func() { close(quit) }
}

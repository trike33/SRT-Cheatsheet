// Package netx is srt's network access layer: every HTTP client it builds
// (NewClient/NewClientOpts) and every TCP connection that goes through
// CountConn is metered and rate-gated here, so request-rate throttling
// (-rate/$SRT_RATE), a byte-limit halt (the shell's `limit bytes`), and the
// live "[traffic] ..." line are all implemented in one place instead of
// scattered across every command that happens to make a network call.
package netx

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/halt"
)

// The shell talks to its command subprocesses through these env vars:
//
//	EnvTrafficFile  child writes its running totals here (JSON)
//	EnvMaxBytes     halt the command once total bytes exceed this
//
// EnvRate (also the leading global flag `srt -rate N <command>`) throttles
// instead of halting: every request waits for its slot so the process never
// sends more than N requests/second, whatever the command's concurrency.
const (
	EnvTrafficFile = "SRT_TRAFFIC_FILE"
	// EnvQuietTraffic set to "1" suppresses the child's own "[traffic]" line;
	// the shell shows live traffic in its pinned header instead.
	EnvQuietTraffic = "SRT_QUIET_TRAFFIC"
	EnvRate         = "SRT_RATE"
	EnvMaxBytes     = "SRT_MAX_BYTES"
)

// Totals is a traffic snapshot: how many requests, and how many bytes in
// each direction.
type Totals struct {
	Requests int64 `json:"requests"`
	BytesOut int64 `json:"bytes_out"`
	BytesIn  int64 `json:"bytes_in"`
}

// Bytes is the combined up+down total.
func (t Totals) Bytes() int64 { return t.BytesOut + t.BytesIn }

// Add accumulates o into t.
func (t *Totals) Add(o Totals) {
	t.Requests += o.Requests
	t.BytesOut += o.BytesOut
	t.BytesIn += o.BytesIn
}

func (t Totals) String() string {
	return fmt.Sprintf("%s req · %s (↑%s ↓%s)", HumanCount(t.Requests), HumanBytes(t.Bytes()), HumanBytes(t.BytesOut), HumanBytes(t.BytesIn))
}

type trafficMeter struct{ reqs, out, in atomic.Int64 }

// meter is the process-wide counter.
var meter trafficMeter

// Snapshot returns the process's traffic totals so far.
func Snapshot() Totals {
	return Totals{meter.reqs.Load(), meter.out.Load(), meter.in.Load()}
}

// Request counts one request (a TCP connect attempt, a DNS lookup -- an HTTP
// request counts itself via the Transport wrapper) after waiting for its
// slot under the global rate cap (a no-op wait when no cap is set).
func Request() {
	gate.wait(nil)
	meter.reqs.Add(1)
}

// rateGate spaces requests evenly: each caller reserves the next free slot
// 1/rate seconds after the previous one and sleeps until it. Strict spacing
// (no burst) means no one-second window can ever exceed the cap.
type rateGate struct {
	mu       sync.Mutex
	interval time.Duration // 0 = unlimited
	next     time.Time
}

var gate rateGate

func (g *rateGate) set(perSecond float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if perSecond <= 0 {
		g.interval = 0
		return
	}
	g.interval = time.Duration(float64(time.Second) / perSecond)
}

// wait blocks for the caller's slot; with a non-nil done channel it gives up
// early (returning false) when done closes, so cancelled requests don't sit
// in the queue.
func (g *rateGate) wait(done <-chan struct{}) bool {
	g.mu.Lock()
	if g.interval == 0 {
		g.mu.Unlock()
		return true
	}
	now := time.Now()
	slot := g.next
	if slot.Before(now) {
		slot = now
	}
	g.next = slot.Add(g.interval)
	g.mu.Unlock()

	d := time.Until(slot)
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-done:
		return false
	}
}

// SetRate arms (or, at 0, clears) the process-wide request-rate cap.
func SetRate(perSecond float64) { gate.set(perSecond) }

// ParseRate validates a requests/second value from a flag or env var.
func ParseRate(s string) (float64, error) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("invalid rate %q (want a positive requests/second number)", s)
	}
	return v, nil
}

// countingConn counts bytes on a net.Conn into meter.
type countingConn struct{ net.Conn }

func (c countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	meter.in.Add(int64(n))
	return n, err
}

func (c countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	meter.out.Add(int64(n))
	return n, err
}

// CountConn wraps a raw connection (e.g. portscan's TCP connect, traceroute's
// raw socket reads) so its bytes are metered like an HTTP client's.
func CountConn(c net.Conn) net.Conn { return countingConn{c} }

// countingDialContext is the Transport dialer: it counts bytes through each
// connection.
func countingDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return countingConn{c}, nil
}

// countingTransport counts one request per RoundTrip.
type countingTransport struct{ next http.RoundTripper }

func (t countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !gate.wait(r.Context().Done()) {
		return nil, r.Context().Err()
	}
	meter.reqs.Add(1)
	return t.next.RoundTrip(r)
}

// --- guard + live line + totals file, active only under the shell ---

// Limits are the per-command ceilings the shell can apply (see `limit
// bytes`); a rate cap is handled separately, by SetRate, since it throttles
// rather than halts.
type Limits struct {
	MaxBytes int64 // total bytes; 0 = unlimited
}

func limitsFromEnv() Limits {
	var l Limits
	if v, err := ParseSize(os.Getenv(EnvMaxBytes)); err == nil && v > 0 {
		l.MaxBytes = v
	}
	return l
}

// breach reports why the limits are exceeded, or "" if they aren't.
func (l Limits) breach(t Totals) string {
	if l.MaxBytes > 0 && t.Bytes() > l.MaxBytes {
		return fmt.Sprintf("traffic %s exceeds limit %s", HumanBytes(t.Bytes()), HumanBytes(l.MaxBytes))
	}
	return ""
}

func writeTrafficFile(path string, t Totals) {
	if path == "" {
		return
	}
	if b, err := json.Marshal(t); err == nil {
		_ = os.WriteFile(path, b, 0o600)
	}
}

// ReadTrafficFile reads back a child command's running totals, written by its
// own StartMonitor. ok is false if the file doesn't exist yet or is invalid.
func ReadTrafficFile(path string) (Totals, bool) {
	var t Totals
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &t) != nil {
		return t, false
	}
	return t, true
}

// StartMonitor runs for commands launched by the shell (it's a no-op
// otherwise, i.e. plain CLI use is untouched). Every 100ms it enforces the
// limits and persists totals; every 2s it logs a traffic line, overwriting
// the same line in place on a terminal (colorout.Overwrite) rather than
// scrolling a new one every tick. A breach or a halt.Run call stops the
// command immediately via os.Exit. The returned func writes the final
// totals and, if a traffic line was ever drawn, clears it so whatever the
// command prints next starts on a clean row.
func StartMonitor() (finish func()) {
	file := os.Getenv(EnvTrafficFile)
	if file == "" {
		return func() {}
	}
	limits := limitsFromEnv()
	quiet := os.Getenv(EnvQuietTraffic) == "1"
	var logged atomic.Bool // whether an overwrite-line tick has actually printed
	persist := func() { writeTrafficFile(file, Snapshot()) }
	finish = func() {
		persist()
		if logged.Load() {
			colorout.ClearLine(os.Stderr)
		}
	}

	halt.On(finish)

	go func() {
		const tick = 100 * time.Millisecond
		t := time.NewTicker(tick)
		defer t.Stop()
		var window [10]int64 // request counts, 1s sliding window
		var i, n int
		lastLog := time.Now()
		for range t.C {
			snap := Snapshot()
			window[i%len(window)] = snap.Requests
			i++
			if n < len(window) {
				n++
			}
			oldest := window[(i-n+len(window))%len(window)]
			rate := float64(snap.Requests-oldest) / (float64(max(n-1, 1)) * tick.Seconds())
			if why := limits.breach(snap); why != "" {
				halt.Run()
				fmt.Fprintf(os.Stderr, "\nsrt: HALTED — %s (%s)\n", why, snap)
				os.Exit(3)
			}
			persist()
			if !quiet && snap.Requests > 0 && time.Since(lastLog) >= 2*time.Second {
				lastLog = time.Now()
				logged.Store(true)
				colorout.Overwrite(os.Stderr, fmt.Sprintf("[traffic] %s · %.0f req/s", snap, rate))
			}
		}
	}()
	return finish
}

// --- formatting / parsing helpers ---

// HumanBytes renders a byte count as e.g. "512 B", "1.5 KiB", "5.0 MiB".
func HumanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGT"[exp])
}

// HumanCount renders a count as e.g. "999", "1.5k", "2.5M".
func HumanCount(n int64) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return strconv.FormatInt(n, 10)
}

// ParseSize parses "500", "50KB", "10MB", "1.5GB" (1024-based).
func ParseSize(s string) (int64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	// Longest suffixes first so "KB" isn't read as "B".
	for _, u := range []struct {
		suf string
		m   int64
	}{{"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30}, {"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"B", 1}} {
		if strings.HasSuffix(s, u.suf) {
			s, mult = strings.TrimSpace(strings.TrimSuffix(s, u.suf)), u.m
			break
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return int64(v * float64(mult)), nil
}

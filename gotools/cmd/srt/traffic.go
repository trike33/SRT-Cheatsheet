package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Traffic accounting. Every command that touches the network funnels through
// one of three chokepoints -- newHTTPClientOpts (HTTP), probePort (TCP
// connect) and the DNS resolvers -- so counting there covers the whole tool
// without per-command plumbing. A "request" is one HTTP request, TCP connect
// attempt or DNS lookup; bytes are measured on the wire for HTTP (post-TLS)
// and for portscan banner reads.
//
// The shell talks to its command subprocesses through three env vars:
//
//	SRT_TRAFFIC_FILE  child writes its running totals here (JSON)
//	SRT_MAX_RATE      halt the command if requests/second exceeds this
//	SRT_MAX_BYTES     halt the command once total bytes exceed this

const (
	envTrafficFile = "SRT_TRAFFIC_FILE"
	envMaxRate     = "SRT_MAX_RATE"
	envMaxBytes    = "SRT_MAX_BYTES"
)

type trafficTotals struct {
	Requests int64 `json:"requests"`
	BytesOut int64 `json:"bytes_out"`
	BytesIn  int64 `json:"bytes_in"`
}

func (t trafficTotals) Bytes() int64 { return t.BytesOut + t.BytesIn }

func (t *trafficTotals) add(o trafficTotals) {
	t.Requests += o.Requests
	t.BytesOut += o.BytesOut
	t.BytesIn += o.BytesIn
}

func (t trafficTotals) String() string {
	return fmt.Sprintf("%s req · %s (↑%s ↓%s)", humanCount(t.Requests), humanBytes(t.Bytes()), humanBytes(t.BytesOut), humanBytes(t.BytesIn))
}

type trafficMeter struct{ reqs, out, in atomic.Int64 }

// meter is the process-wide counter.
var meter trafficMeter

func (m *trafficMeter) snapshot() trafficTotals {
	return trafficTotals{m.reqs.Load(), m.out.Load(), m.in.Load()}
}

func (m *trafficMeter) request() { m.reqs.Add(1) }

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
	meter.request()
	return t.next.RoundTrip(r)
}

// --- guard + live line + totals file, active only under the shell ---

type trafficLimits struct {
	maxRate  float64 // requests/second; 0 = unlimited
	maxBytes int64   // total bytes; 0 = unlimited
}

func limitsFromEnv() trafficLimits {
	var l trafficLimits
	if v, err := strconv.ParseFloat(os.Getenv(envMaxRate), 64); err == nil && v > 0 {
		l.maxRate = v
	}
	if v, err := parseSize(os.Getenv(envMaxBytes)); err == nil && v > 0 {
		l.maxBytes = v
	}
	return l
}

// breach reports why the limits are exceeded, or "" if they aren't. rate is
// the request rate over the most recent window.
func (l trafficLimits) breach(t trafficTotals, rate float64) string {
	if l.maxRate > 0 && rate > l.maxRate {
		return fmt.Sprintf("request rate %.0f/s exceeds limit %.0f/s", rate, l.maxRate)
	}
	if l.maxBytes > 0 && t.Bytes() > l.maxBytes {
		return fmt.Sprintf("traffic %s exceeds limit %s", humanBytes(t.Bytes()), humanBytes(l.maxBytes))
	}
	return ""
}

func writeTrafficFile(path string, t trafficTotals) {
	if path == "" {
		return
	}
	if b, err := json.Marshal(t); err == nil {
		_ = os.WriteFile(path, b, 0o600)
	}
}

func readTrafficFile(path string) (trafficTotals, bool) {
	var t trafficTotals
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &t) != nil {
		return t, false
	}
	return t, true
}

// startTrafficMonitor runs for commands launched by the shell (it's a no-op
// otherwise, i.e. plain CLI use is untouched). Every 100ms it enforces the
// limits and persists totals; every 2s it logs a traffic line. A breach or a
// Ctrl+C halts the command immediately via os.Exit. The returned func writes
// the final totals.
func startTrafficMonitor() (finish func()) {
	file := os.Getenv(envTrafficFile)
	if file == "" {
		return func() {}
	}
	limits := limitsFromEnv()
	finish = func() { writeTrafficFile(file, meter.snapshot()) }

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		finish()
		fmt.Fprintf(os.Stderr, "\nsrt: halted by user — %s\n", meter.snapshot())
		os.Exit(130)
	}()

	go func() {
		const tick = 100 * time.Millisecond
		t := time.NewTicker(tick)
		defer t.Stop()
		var window [10]int64 // request counts, 1s sliding window
		var i, n int
		lastLog := time.Now()
		for range t.C {
			snap := meter.snapshot()
			window[i%len(window)] = snap.Requests
			i++
			if n < len(window) {
				n++
			}
			oldest := window[(i-n+len(window))%len(window)]
			rate := float64(snap.Requests-oldest) / (float64(n-1)*tick.Seconds() + tick.Seconds())
			if why := limits.breach(snap, rate); why != "" {
				finish()
				fmt.Fprintf(os.Stderr, "\nsrt: HALTED — %s (%s)\n", why, snap)
				os.Exit(3)
			}
			finish()
			if snap.Requests > 0 && time.Since(lastLog) >= 2*time.Second {
				lastLog = time.Now()
				fmt.Fprintf(os.Stderr, "[traffic] %s · %.0f req/s\n", snap, rate)
			}
		}
	}()
	return finish
}

// --- formatting / parsing helpers ---

func humanBytes(b int64) string {
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

func humanCount(n int64) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return strconv.FormatInt(n, 10)
}

// parseSize parses "500", "50KB", "10MB", "1.5GB" (1024-based).
func parseSize(s string) (int64, error) {
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

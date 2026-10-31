package traceroute

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

// requireRawICMP skips a test outright when this environment can't open a
// raw ICMP socket (no CAP_NET_RAW / not root) -- common in CI and most dev
// sandboxes -- rather than failing it.
func requireRawICMP(t *testing.T) {
	t.Helper()
	if err := CheckRawICMPAvailable(); err != nil {
		t.Skipf("raw ICMP socket unavailable (%v); skipping a test that needs CAP_NET_RAW/root", err)
	}
}

func TestTraceHostLoopbackReachesInOneHop(t *testing.T) {
	requireRawICMP(t)
	var seq uint16
	res := traceHost("127.0.0.1", 5, 2*time.Second, 0xBEEF, &seq)
	if res.Err != "" {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if !res.Reached {
		t.Fatalf("loopback should be reached: %+v", res)
	}
	if len(res.Hops) == 0 || res.Hops[len(res.Hops)-1].Addr != "127.0.0.1" {
		t.Errorf("last hop should be 127.0.0.1: %+v", res.Hops)
	}
	for _, h := range res.Hops {
		if h.Timeout {
			t.Errorf("loopback trace should not time out on any hop: %+v", res.Hops)
		}
	}
}

func TestTraceHostUnresolvableNameErrors(t *testing.T) {
	requireRawICMP(t)
	var seq uint16
	res := traceHost("this-name-should-not-resolve.invalid", 5, time.Second, 1, &seq)
	if res.Err == "" {
		t.Error("an unresolvable name should report an error, not attempt to trace")
	}
}

func TestTraceHostRejectsNonIPv4(t *testing.T) {
	var seq uint16
	res := traceHost("::1", 5, time.Second, 1, &seq)
	if res.Err == "" {
		t.Error("traceroute is IPv4-only for now; an IPv6 literal should error cleanly")
	}
}

// TestTraceHostTimesOutOnUnreachableHop exercises the no-response path
// against an address nothing answers (TEST-NET-1, RFC 5737), within a short
// timeout -- the loop must still terminate and report every hop as a
// timeout rather than reaching it or hanging.
func TestTraceHostTimesOutOnUnreachableHop(t *testing.T) {
	requireRawICMP(t)
	var seq uint16
	start := time.Now()
	res := traceHost("192.0.2.123", 2, 150*time.Millisecond, 2, &seq)
	if res.Err != "" {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if res.Reached {
		t.Error("an address nothing answers should not be marked reached")
	}
	if len(res.Hops) != 2 {
		t.Fatalf("want 2 hops attempted, got %+v", res.Hops)
	}
	for _, h := range res.Hops {
		if !h.Timeout {
			t.Errorf("expected every hop to time out: %+v", res.Hops)
		}
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("took %v for 2 hops at 150ms timeout -- loop isn't bounded", el)
	}
}

func TestRunTraceroutePlainAndJSONOutput(t *testing.T) {
	requireRawICMP(t)
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.txt")
	os.WriteFile(targets, []byte("127.0.0.1\n"), 0o644)
	out := filepath.Join(dir, "o.txt")
	if err := Run([]string{"-l", targets, "-max-hops", "3", "-timeout", "500ms", "-o", out}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), "traceroute 127.0.0.1") {
		t.Errorf("plain output = %q", b)
	}

	outJSON := filepath.Join(dir, "o.json")
	if err := Run([]string{"-l", targets, "-max-hops", "3", "-timeout", "500ms", "-json", "-o", outJSON}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(outJSON)
	if !strings.Contains(string(b), `"target":"127.0.0.1"`) || !strings.Contains(string(b), `"reached":true`) {
		t.Errorf("json output = %q", b)
	}
}

func TestRunTracerouteSavesToSink(t *testing.T) {
	requireRawICMP(t)
	t.Setenv("SRT_DB", filepath.Join(t.TempDir(), "srt.db"))
	s, err := store.StartSink("traceroute", []string{"traceroute"})
	if err != nil {
		t.Fatal(err)
	}
	targets := filepath.Join(t.TempDir(), "targets.txt")
	os.WriteFile(targets, []byte("127.0.0.1\n"), 0o644)
	if err := Run([]string{"-l", targets, "-max-hops", "2", "-timeout", "500ms", "-o", os.DevNull}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	db, err := store.OpenReadable()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var kind, key, data string
	if err := db.QueryRow(`SELECT kind, key, data FROM records WHERE kind='route'`).Scan(&kind, &key, &data); err != nil {
		t.Fatalf("no route record saved: %v", err)
	}
	if key != "127.0.0.1" || !strings.Contains(data, `"reached":true`) {
		t.Errorf("route record = key=%q data=%q", key, data)
	}
}

func TestTracerouteRecordDropsErrors(t *testing.T) {
	rec := tracerouteResult{Target: "x", Err: "boom"}.record()
	if rec.Key != "" {
		t.Errorf("an errored result must not be persisted: %+v", rec)
	}
}

func TestTracerouteRequiresTarget(t *testing.T) {
	if err := Run(nil); err == nil {
		t.Error("no targets should error")
	}
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.txt")
	os.WriteFile(targets, []byte("127.0.0.1\n"), 0o644)
	if err := Run([]string{"-l", targets, "-max-hops", "0"}); err == nil {
		t.Error("-max-hops 0 should error")
	}
}

func TestTracerouteRegisteredInCLI(t *testing.T) {
	if _, ok := cli.Lookup("traceroute"); !ok {
		t.Fatal("traceroute not registered")
	}
}

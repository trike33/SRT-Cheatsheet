package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"500": 500, "50KB": 50 << 10, "10mb": 10 << 20, "1.5GB": 3 << 29, "2 M": 2 << 20} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "-5MB"} {
		if _, err := parseSize(bad); err == nil {
			t.Errorf("parseSize(%q) should fail", bad)
		}
	}
}

func TestHumanFormatting(t *testing.T) {
	if humanBytes(512) != "512 B" || humanBytes(1536) != "1.5 KiB" || humanBytes(5<<20) != "5.0 MiB" {
		t.Errorf("humanBytes: %s %s %s", humanBytes(512), humanBytes(1536), humanBytes(5<<20))
	}
	if humanCount(999) != "999" || humanCount(1500) != "1.5k" || humanCount(2_500_000) != "2.5M" {
		t.Error("humanCount")
	}
}

func TestLimitsBreach(t *testing.T) {
	l := trafficLimits{maxBytes: 1000}
	if l.breach(trafficTotals{BytesOut: 5}) != "" {
		t.Error("under limit should not breach")
	}
	if l.breach(trafficTotals{BytesOut: 600, BytesIn: 600}) == "" {
		t.Error("bytes over limit should breach")
	}
	if (trafficLimits{}).breach(trafficTotals{Requests: 1 << 40, BytesIn: 1 << 40}) != "" {
		t.Error("zero limits mean unlimited")
	}
}

func TestLimitsFromEnv(t *testing.T) {
	t.Setenv(envMaxBytes, "10MB")
	l := limitsFromEnv()
	if l.maxBytes != 10<<20 {
		t.Errorf("%+v", l)
	}
}

func TestTrafficFileRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.json")
	writeTrafficFile(p, trafficTotals{Requests: 3, BytesOut: 10, BytesIn: 20})
	got, ok := readTrafficFile(p)
	if !ok || got.Requests != 3 || got.Bytes() != 30 {
		t.Errorf("%+v %v", got, ok)
	}
	if _, ok := readTrafficFile(filepath.Join(t.TempDir(), "missing")); ok {
		t.Error("missing file should report !ok")
	}
}

func TestApplyLimitCommand(t *testing.T) {
	m := newTestModel()
	m.applyLimitCommand([]string{"rate", "20"})
	m.applyLimitCommand([]string{"bytes", "20MB"})
	if m.rate != 20 || m.limits.maxBytes != 20<<20 || m.lastErr != nil {
		t.Fatalf("%v %+v %v", m.rate, m.limits, m.lastErr)
	}
	m.applyLimitCommand([]string{"rate", "off"})
	if m.rate != 0 || m.limits.maxBytes == 0 {
		t.Error("rate off should only lift the throttle")
	}
	m.applyLimitCommand([]string{"off"})
	if m.limits != (trafficLimits{}) || m.rate != 0 {
		t.Error("off should clear everything")
	}
	for _, bad := range [][]string{{"rate", "x"}, {"rate", "-1"}, {"bytes", "zz"}, {"bogus"}, {"rate"}} {
		m.lastErr = nil
		m.applyLimitCommand(bad)
		if m.lastErr == nil {
			t.Errorf("limit %v should error", bad)
		}
	}
}

func TestChildEnvCarriesLimits(t *testing.T) {
	m := newTestModel()
	m.rate = 10
	m.limits = trafficLimits{maxBytes: 2048}
	t.Setenv(envRate, "999") // inherited value must be replaced, not duplicated
	env := m.childEnv()
	defer func() { _ = removeIfExists(m.trafficFile) }()
	want := map[string]bool{envTrafficFile + "=" + m.trafficFile: false, envRate + "=10": false, envMaxBytes + "=2048": false}
	for _, e := range env {
		if _, ok := want[e]; ok {
			want[e] = true
		}
	}
	for k, ok := range want {
		if !ok {
			t.Errorf("env missing %s", k)
		}
	}
}

func TestExecDoneAccumulatesTraffic(t *testing.T) {
	m := newTestModel()
	m.trafficFile = filepath.Join(t.TempDir(), "t.json")
	writeTrafficFile(m.trafficFile, trafficTotals{Requests: 7, BytesIn: 100})
	got, _ := m.Update(execDoneMsg{cmd: "probe"})
	if gm := got.(shellModel); gm.traffic.Requests != 7 || gm.traffic.BytesIn != 100 {
		t.Errorf("session totals = %+v", gm.traffic)
	}
}

func TestTrafficAndLimitAreShellCommands(t *testing.T) {
	names := shellCommandNames()
	for _, w := range []string{"traffic", "limit"} {
		if !commandKnown(names, w) {
			t.Errorf("missing %q", w)
		}
	}
}

func removeIfExists(p string) error {
	if p == "" {
		return nil
	}
	return os.Remove(p)
}

func TestShellDefaultsTo50ReqPerSec(t *testing.T) {
	t.Setenv(envRate, "")
	if m := newShellModel("x"); m.rate != 50 {
		t.Errorf("default rate = %v", m.rate)
	}
	t.Setenv(envRate, "12")
	if m := newShellModel("x"); m.rate != 12 {
		t.Errorf("env rate = %v", m.rate)
	}
}

func TestRateGateSpacesRequests(t *testing.T) {
	var g rateGate
	g.set(100) // 10ms apart
	start := time.Now()
	for i := 0; i < 11; i++ {
		g.wait(nil)
	}
	if el := time.Since(start); el < 95*time.Millisecond {
		t.Errorf("11 requests at 100/s took %v, want >= ~100ms", el)
	}
	g.set(0)
	start = time.Now()
	for i := 0; i < 1000; i++ {
		g.wait(nil)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Error("unlimited gate should not block")
	}
}

func TestRateGateConcurrentNeverExceedsCap(t *testing.T) {
	var g rateGate
	g.set(200)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 41; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); g.wait(nil) }()
	}
	wg.Wait()
	if el := time.Since(start); el < 190*time.Millisecond {
		t.Errorf("41 concurrent requests at 200/s took %v", el)
	}
}

func TestRateGateCancel(t *testing.T) {
	var g rateGate
	g.set(1)
	g.wait(nil) // takes the immediate slot; the next is 1s out
	done := make(chan struct{})
	close(done)
	if g.wait(done) {
		t.Error("cancelled wait should return false")
	}
}

func TestParseRate(t *testing.T) {
	if v, err := parseRate("50"); err != nil || v != 50 {
		t.Errorf("%v %v", v, err)
	}
	for _, bad := range []string{"", "0", "-1", "fast"} {
		if _, err := parseRate(bad); err == nil {
			t.Errorf("parseRate(%q) should fail", bad)
		}
	}
}

func TestApplyGlobalRate(t *testing.T) {
	old := os.Args
	defer func() { os.Args = old; gate.set(0) }()
	t.Setenv(envRate, "")
	for _, args := range [][]string{{"srt", "-rate", "25", "version"}, {"srt", "--rate=25", "version"}} {
		os.Args = args
		applyGlobalRate()
		if len(os.Args) != 2 || os.Args[1] != "version" {
			t.Errorf("flag not stripped: %v", os.Args)
		}
		if gate.interval != 40*time.Millisecond {
			t.Errorf("interval = %v", gate.interval)
		}
		gate.set(0)
	}
}

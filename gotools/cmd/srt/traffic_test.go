package main

import (
	"os"
	"path/filepath"
	"testing"
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
	l := trafficLimits{maxRate: 100, maxBytes: 1000}
	if l.breach(trafficTotals{Requests: 5}, 50) != "" {
		t.Error("under limits should not breach")
	}
	if l.breach(trafficTotals{}, 150) == "" {
		t.Error("rate over limit should breach")
	}
	if l.breach(trafficTotals{BytesOut: 600, BytesIn: 600}, 1) == "" {
		t.Error("bytes over limit should breach")
	}
	if (trafficLimits{}).breach(trafficTotals{Requests: 1 << 40, BytesIn: 1 << 40}, 1e9) != "" {
		t.Error("zero limits mean unlimited")
	}
}

func TestLimitsFromEnv(t *testing.T) {
	t.Setenv(envMaxRate, "25")
	t.Setenv(envMaxBytes, "10MB")
	l := limitsFromEnv()
	if l.maxRate != 25 || l.maxBytes != 10<<20 {
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
	m.applyLimitCommand([]string{"rate", "50"})
	m.applyLimitCommand([]string{"bytes", "20MB"})
	if m.limits.maxRate != 50 || m.limits.maxBytes != 20<<20 || m.lastErr != nil {
		t.Fatalf("%+v %v", m.limits, m.lastErr)
	}
	m.applyLimitCommand([]string{"off"})
	if m.limits != (trafficLimits{}) {
		t.Error("off should clear")
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
	m.limits = trafficLimits{maxRate: 10, maxBytes: 2048}
	env := m.childEnv()
	defer func() { _ = removeIfExists(m.trafficFile) }()
	want := map[string]bool{envTrafficFile + "=" + m.trafficFile: false, envMaxRate + "=10": false, envMaxBytes + "=2048": false}
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

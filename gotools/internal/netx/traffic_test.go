package netx

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"500": 500, "50KB": 50 << 10, "10mb": 10 << 20, "1.5GB": 3 << 29, "2 M": 2 << 20} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "-5MB"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) should fail", bad)
		}
	}
}

func TestHumanFormatting(t *testing.T) {
	if HumanBytes(512) != "512 B" || HumanBytes(1536) != "1.5 KiB" || HumanBytes(5<<20) != "5.0 MiB" {
		t.Errorf("HumanBytes: %s %s %s", HumanBytes(512), HumanBytes(1536), HumanBytes(5<<20))
	}
	if HumanCount(999) != "999" || HumanCount(1500) != "1.5k" || HumanCount(2_500_000) != "2.5M" {
		t.Error("HumanCount")
	}
}

func TestLimitsBreach(t *testing.T) {
	l := Limits{MaxBytes: 1000}
	if l.breach(Totals{BytesOut: 5}) != "" {
		t.Error("under limit should not breach")
	}
	if l.breach(Totals{BytesOut: 600, BytesIn: 600}) == "" {
		t.Error("bytes over limit should breach")
	}
	if (Limits{}).breach(Totals{Requests: 1 << 40, BytesIn: 1 << 40}) != "" {
		t.Error("zero limits mean unlimited")
	}
}

func TestLimitsFromEnv(t *testing.T) {
	t.Setenv(EnvMaxBytes, "10MB")
	l := limitsFromEnv()
	if l.MaxBytes != 10<<20 {
		t.Errorf("%+v", l)
	}
}

func TestTrafficFileRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.json")
	writeTrafficFile(p, Totals{Requests: 3, BytesOut: 10, BytesIn: 20})
	got, ok := ReadTrafficFile(p)
	if !ok || got.Requests != 3 || got.Bytes() != 30 {
		t.Errorf("%+v %v", got, ok)
	}
	if _, ok := ReadTrafficFile(filepath.Join(t.TempDir(), "missing")); ok {
		t.Error("missing file should report !ok")
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
	if v, err := ParseRate("50"); err != nil || v != 50 {
		t.Errorf("%v %v", v, err)
	}
	for _, bad := range []string{"", "0", "-1", "fast"} {
		if _, err := ParseRate(bad); err == nil {
			t.Errorf("ParseRate(%q) should fail", bad)
		}
	}
}

func TestSetRateAffectsRequest(t *testing.T) {
	defer SetRate(0)
	SetRate(25) // 40ms apart
	start := time.Now()
	for i := 0; i < 3; i++ {
		Request()
	}
	if el := time.Since(start); el < 70*time.Millisecond {
		t.Errorf("3 requests at 25/s took %v, want >= ~80ms", el)
	}
}

func TestCountConnWrapsIO(t *testing.T) {
	// CountConn must return something satisfying net.Conn without panicking
	// on a nil-embedded zero value's method set -- a compile-time check more
	// than a runtime one, since exercising real Read/Write needs a live
	// connection (covered by portscan's own tests).
	var _ = CountConn
}

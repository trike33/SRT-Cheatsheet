package ioutil

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// captureStderrFor runs fn with os.Stderr redirected to a pipe, waits, then
// restores it and returns everything written.
func captureStderrFor(t *testing.T, d time.Duration, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	time.Sleep(d)

	os.Stderr = old
	w.Close()
	return <-done
}

func TestStartHeartbeatTicksAndStops(t *testing.T) {
	out := captureStderrFor(t, 90*time.Millisecond, func() {
		stop := StartHeartbeatEvery("test-op", 20*time.Millisecond)
		time.Sleep(70 * time.Millisecond)
		stop()
	})

	if !strings.Contains(out, "test-op: still running") {
		t.Fatalf("heartbeat output = %q, want it to mention %q", out, "test-op: still running")
	}
	// ~70ms at a 20ms interval should tick at least twice.
	if n := strings.Count(out, "test-op: still running"); n < 2 {
		t.Errorf("heartbeat ticked %d time(s) in 70ms at a 20ms interval, want >= 2; output: %q", n, out)
	}
}

func TestStartHeartbeatStopsPromptly(t *testing.T) {
	stop := StartHeartbeatEvery("never-seen", time.Hour) // long enough to never naturally tick
	out := captureStderrFor(t, 10*time.Millisecond, func() {
		stop()
	})
	if out != "" {
		t.Errorf("heartbeat printed after stop() with no tick due: %q", out)
	}
}

func TestRangeSet(t *testing.T) {
	rs, err := ParseRangeSet("200-299,301,302")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{200, 250, 299, 301, 302} {
		if !rs.Contains(n) {
			t.Errorf("Contains(%d) = false, want true", n)
		}
	}
	for _, n := range []int{199, 300, 303} {
		if rs.Contains(n) {
			t.Errorf("Contains(%d) = true, want false", n)
		}
	}
	all, _ := ParseRangeSet("all")
	if !all.Contains(999999) {
		t.Error(`"all" should contain anything`)
	}
	empty, _ := ParseRangeSet("")
	if !empty.Empty() || empty.Contains(1) {
		t.Error("empty spec should be Empty and match nothing")
	}
	if _, err := ParseRangeSet("not-a-number"); err == nil {
		t.Error("invalid spec should error")
	}
	if _, err := ParseRangeSet("5-x"); err == nil {
		t.Error("invalid range should error")
	}
}

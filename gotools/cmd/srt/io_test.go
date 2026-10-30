package main

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
		stop := startHeartbeatEvery("test-op", 20*time.Millisecond)
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
	stop := startHeartbeatEvery("never-seen", time.Hour) // long enough to never naturally tick
	out := captureStderrFor(t, 10*time.Millisecond, func() {
		stop()
	})
	if out != "" {
		t.Errorf("heartbeat printed after stop() with no tick due: %q", out)
	}
}

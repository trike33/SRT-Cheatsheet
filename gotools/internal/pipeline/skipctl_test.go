package pipeline

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/fuzzctl"
)

func TestControlSkipListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.json")
	fuzzctl.RequestSkip(path) // a stale request from before the run must not fire
	sl := startControlSkipListener(path)
	defer sl.stop()
	select {
	case <-sl.skipChan():
		t.Fatal("stale skip request fired")
	case <-time.After(600 * time.Millisecond):
	}
	fuzzctl.RequestSkip(path)
	select {
	case <-sl.skipChan():
	case <-time.After(2 * time.Second):
		t.Fatal("skip request not picked up")
	}
}

package main

import (
	"runtime/debug"
	"testing"
)

func TestDisplayVersion(t *testing.T) {
	mk := func(v string) *debug.BuildInfo { return &debug.BuildInfo{Main: debug.Module{Version: v}} }
	if got := displayVersion(mk("v1.2.3")); got != "v1.2.3" {
		t.Errorf("go install build: %q", got)
	}
	if got := displayVersion(mk("(devel)")); got != defaultVersion {
		t.Errorf("local build: %q", got)
	}
	if got := displayVersion(nil); got != defaultVersion {
		t.Errorf("no build info: %q", got)
	}
	old := version
	version = "v9.9.9" // set via -ldflags
	defer func() { version = old }()
	if got := displayVersion(mk("v1.2.3")); got != "v9.9.9" {
		t.Errorf("ldflags must win: %q", got)
	}
}

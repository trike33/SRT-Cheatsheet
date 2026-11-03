package fuzz

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

func wafTestEngine() *fuzzEngine {
	return &fuzzEngine{
		client:       netx.NewClient(5*time.Second, true),
		ua:           "t",
		wafThreshold: 3,
		sched:        newScheduler(1, 0, 0, nil, &atomic.Bool{}, false),
	}
}

func TestWafFirstBlockHaltsHostSecondCoolsDown(t *testing.T) {
	e := wafTestEngine()
	host := "waf-test-host-1"
	hb := e.sched.hostBucket(host)
	delete(wafStrikes, host)

	for i := 0; i < 3; i++ {
		e.wafObserve(hb, 403)
	}
	if !hb.wafIsHalted() {
		t.Fatal("3 consecutive 403s should halt the host on the first block")
	}
	if hb.wafPausedFor() != 0 {
		t.Fatal("first block must halt, not cool down")
	}

	// A fresh run's bucket for the same host: blocked again -> cooldown.
	hb2 := newScheduler(1, 0, 0, nil, &atomic.Bool{}, false).hostBucket(host)
	for i := 0; i < 3; i++ {
		e.wafObserve(hb2, 403)
	}
	if hb2.wafIsHalted() {
		t.Fatal("a repeat block should cool down, not halt")
	}
	if d := hb2.wafPausedFor(); d < 4*time.Minute+50*time.Second {
		t.Fatalf("cooldown = %v, want ~5m", d)
	}
}

func TestWafNon403ResetsCounter(t *testing.T) {
	e := wafTestEngine()
	hb := e.sched.hostBucket("waf-test-host-2")
	delete(wafStrikes, "waf-test-host-2")
	e.wafObserve(hb, 403)
	e.wafObserve(hb, 403)
	e.wafObserve(hb, 200)
	e.wafObserve(hb, 403)
	e.wafObserve(hb, 403)
	if hb.wafIsHalted() {
		t.Fatal("a non-403 in between must reset the run")
	}
}

func TestWafPreflightStillBlockedStartsCooledDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer srv.Close()
	e := wafTestEngine()
	hb := e.sched.hostBucket(hostOf(srv.URL))
	wafStrikes[hb.name] = 1
	e.wafPreflight(hb, srv.URL+"/FUZZ")
	if hb.wafPausedFor() == 0 {
		t.Fatal("still-403 host with a prior strike should start on cooldown")
	}
	// No prior strike -> no probe, no cooldown.
	hb3 := e.sched.hostBucket("waf-test-host-3")
	delete(wafStrikes, "waf-test-host-3")
	e.wafPreflight(hb3, srv.URL+"/FUZZ")
	if hb3.wafPausedFor() != 0 {
		t.Fatal("no prior strike must not cool down")
	}
}

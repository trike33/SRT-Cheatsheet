package fuzz

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

// softServer answers every path with a 200 whose size jitters with the
// requested word's length (a classic soft-404), except /real which is a
// genuinely different, much shorter page.
func softServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real" {
			fmt.Fprint(w, "ok")
			return
		}
		fmt.Fprint(w, "nothing here: "+r.URL.Path+" "+strings.Repeat("x", 200))
	}))
}

func TestPreflightAutoEnablesCalibration(t *testing.T) {
	srv := softServer()
	defer srv.Close()

	dir := t.TempDir()
	wl, out := filepath.Join(dir, "w.txt"), filepath.Join(dir, "o.json")
	os.WriteFile(wl, []byte("aaa\nbbb\nreal\n"), 0o644)

	// No -ac passed: without preflight, every word would "match" under the
	// default -mc (all 200s), flooding the output with false positives.
	if err := Run([]string{"-u", srv.URL + "/FUZZ", "-w", wl, "-json", "-o", out, "-c", "1"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	s := string(b)
	if !strings.Contains(s, "/real") {
		t.Errorf("the genuine hit should still show up:\n%s", s)
	}
	if strings.Contains(s, "/aaa") || strings.Contains(s, "/bbb") {
		t.Errorf("preflight should have auto-enabled soft-404 filtering and hidden the jittery misses:\n%s", s)
	}
}

func TestPreflightNoOpOnHardAndCleanHost(t *testing.T) {
	srv := extTestServer(nil) // index.php/login.html real, everything else a soft 200 -- reuse ext_test's fixture
	defer srv.Close()

	e := &fuzzEngine{client: clientForTest(), matcher: mustMatcher(t, "200")}
	e.preflightCheck([]string{srv.URL + "/FUZZ"})

	if !e.calibrationEnabled(originOf(srv.URL + "/FUZZ")) {
		t.Error("a host whose root misses come back 200 should get calibration auto-enabled")
	}
	if e.baselineFor(originOf(srv.URL+"/FUZZ")) == nil {
		t.Error("expected a baseline fingerprint to be recorded")
	}
}

func TestPreflightRespectsExistingAC(t *testing.T) {
	srv := softServer()
	defer srv.Close()

	e := &fuzzEngine{client: clientForTest(), matcher: mustMatcher(t, "200"), autocal: true}
	e.preflightCheck([]string{srv.URL + "/FUZZ"})

	// forcedCal should stay empty: the operator already asked for -ac, so
	// there's nothing for preflight to force.
	e.forcedMu.Lock()
	n := len(e.forcedCal)
	e.forcedMu.Unlock()
	if n != 0 {
		t.Errorf("forcedCal should stay empty when -ac is already on, got %d entries", n)
	}
	if e.baselineFor(originOf(srv.URL+"/FUZZ")) == nil {
		t.Error("baseline should still be recorded even with -ac already on")
	}
}

func TestCalibrateInheritsBaseline(t *testing.T) {
	e := &fuzzEngine{client: clientForTest(), matcher: mustMatcher(t, "200"), acTol: 1.0, acLearn: 0, cal: map[string]*calibData{}}
	bl := newCalibData(1.0, 0)
	bl.addCalibrated(RespMeta{Status: 200, Size: 500, Words: 50}, "")
	e.baseline = map[string]*calibData{"http://example.test": bl}

	// calibrate() will try real network probes against a bogus origin and
	// get errors for all of them, so cd should end up with exactly the
	// inherited band and nothing else.
	e.calibrate("http://example.test/FUZZ", "")

	if !e.cal["http://example.test/FUZZ"].matches(RespMeta{Status: 200, Size: 503, Words: 50}, "") {
		t.Error("calibrate should have seeded from the preflight baseline")
	}
}

func clientForTest() *http.Client {
	return netx.NewClient(2*time.Second, true)
}

func mustMatcher(t *testing.T, mc string) *matcher {
	t.Helper()
	m, err := buildMatcher(mc, "", "", "", "", "", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

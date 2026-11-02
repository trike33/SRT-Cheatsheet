package pipeline

import (
	"net"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestNucleiEasyWinsArgsShape(t *testing.T) {
	got := nucleiEasyWinsArgs("10.0.0.5", 6379)
	want := []string{
		"-u", "10.0.0.5:6379",
		"-tags", "default-login,exposure,misconfig",
		"-etags", "dos,fuzz,intrusive",
		"-rl", "10",
		"-c", "3",
		"-bs", "1",
		"-timeout", "5",
		"-retries", "1",
		"-mt", "3m",
		"-ni",
		"-duc",
		"-silent",
		"-j",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// openListener opens a loopback TCP listener that accepts and closes every
// connection with no banner, and returns its port. Used to give portscan a
// real open port to classify without depending on any banner text -- the
// easy-wins pass must fire on an open non-web port regardless of whether a
// banner was grabbed (that's nuclei's own templates' job), unlike vulnx
// which needs one.
func openListener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parsing port %q: %v", portStr, err)
	}
	time.Sleep(10 * time.Millisecond) // give the accept loop a beat to be ready
	return port
}

func TestHostStageEasyWinsOnByDefault(t *testing.T) {
	port := openListener(t)
	dir := t.TempDir()
	cfg := &pipelineConfig{Host: []targetEntry{{Target: "127.0.0.1", Ports: strconv.Itoa(port)}}}

	steps := runHostStage(cfg, dir, true, "")
	for _, s := range steps {
		if s.Name == "nuclei" {
			return
		}
	}
	t.Fatalf("easyWins defaults to on, expected a nuclei step, got %+v", steps)
}

func TestHostStageEasyWinsOffByOption(t *testing.T) {
	port := openListener(t)
	dir := t.TempDir()
	disabled := false
	cfg := &pipelineConfig{
		Host:    []targetEntry{{Target: "127.0.0.1", Ports: strconv.Itoa(port)}},
		Options: pipelineOptions{EasyWins: &disabled},
	}
	for _, s := range runHostStage(cfg, dir, true, "") {
		if s.Name == "nuclei" {
			t.Fatalf("options.easyWins=false, expected no nuclei step, got %+v", s)
		}
	}
}

func TestHostStageEasyWinsRunsWhenEnabled(t *testing.T) {
	port := openListener(t)
	dir := t.TempDir()
	enabled := true
	cfg := &pipelineConfig{
		Host:    []targetEntry{{Target: "127.0.0.1", Ports: strconv.Itoa(port)}},
		Options: pipelineOptions{EasyWins: &enabled},
	}

	steps := runHostStage(cfg, dir, true, "")
	var found *stepResult
	for i := range steps {
		if steps[i].Name == "nuclei" {
			found = &steps[i]
		}
	}
	if found == nil {
		var names []string
		for _, s := range steps {
			names = append(names, s.Name)
		}
		t.Fatalf("options.easyWins=true, expected a nuclei step, got steps: %v", names)
	}
	// Whether nuclei is actually installed on the machine running this test
	// varies; either outcome is fine here -- this test is about the wiring
	// (is the step attempted at all), not nuclei's own behavior, which
	// nucleiEasyWinsArgs/TestNucleiEasyWinsArgsShape already covers.
	if found.Status != "ok" && found.Status != "skipped" && found.Status != "error" {
		t.Errorf("unexpected step status %q", found.Status)
	}
}

// TestHostStageEasyWinsNeverRunsForWebPorts binds the real loopback listener
// to a port portscan.IsWebPort actually recognizes (8080), so the HOST stage
// classifies it as a web service and hands it off instead of running
// easy-wins against it -- easy-wins is the "other services" bucket's tool,
// never the web one's. Skips if 8080 is already taken on the test machine
// rather than risk a flaky bind.
func TestHostStageEasyWinsNeverRunsForWebPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Skipf("127.0.0.1:8080 unavailable on this machine: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	dir := t.TempDir()
	enabled := true
	cfg := &pipelineConfig{
		Host:    []targetEntry{{Target: "127.0.0.1", Ports: "8080"}},
		Options: pipelineOptions{EasyWins: &enabled},
	}
	steps := runHostStage(cfg, dir, true, "")
	for _, s := range steps {
		if s.Name == "nuclei" {
			t.Errorf("did not expect a nuclei step from a web-port scan, got %+v", s)
		}
	}
}

package portscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanStateRoundTrip(t *testing.T) {
	hosts, ports := []string{"a", "b"}, []int{1, 2, 3}
	path := filepath.Join(t.TempDir(), "s.state")
	s, err := openScanState(path, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}
	// finish probes 0,1,2 and 4 (out of order); 3 is outstanding
	for _, i := range []int64{2, 0, 1, 4} {
		s.Done(i)
	}
	s.Open(Result{Host: "a", Port: 2})
	s.Close()

	r, err := openScanState(path, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.mark != 3 || !r.Skip(2) || r.Skip(3) {
		t.Errorf("watermark = %d (want 3: probe 3 unfinished)", r.mark)
	}
	if len(r.Prior) != 1 || r.Prior[0].Port != 2 {
		t.Errorf("prior = %+v", r.Prior)
	}
}

func TestScanStateRejectsDifferentScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.state")
	s, _ := openScanState(path, []string{"a"}, []int{1})
	s.Close()
	if _, err := openScanState(path, []string{"b"}, []int{1}); err == nil {
		t.Error("state for a different scan must be rejected")
	}
}

func TestScanStateToleratesTornLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.state")
	s, _ := openScanState(path, []string{"a"}, []int{1, 2})
	s.Done(0)
	s.Close()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(`{"w":`) // hard-kill mid-write
	f.Close()
	r, err := openScanState(path, []string{"a"}, []int{1, 2})
	if err != nil || r.mark != 1 {
		t.Fatalf("mark=%v err=%v", r, err)
	}
	r.Close()
}

func TestPortscanResumeEndToEnd(t *testing.T) {
	dir := t.TempDir()
	hostFile := filepath.Join(dir, "h.txt")
	os.WriteFile(hostFile, []byte("127.0.0.1\n"), 0o644)
	state, out := filepath.Join(dir, "st"), filepath.Join(dir, "o.txt")
	args := []string{"-l", hostFile, "-p", "1-40", "-timeout", "50ms", "-resume", state, "-o", out}
	if err := Run(args); err != nil {
		t.Fatal(err)
	}
	// Re-running a finished scan skips everything yet reproduces the output.
	first, _ := os.ReadFile(out)
	if err := Run(args); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(out)
	if string(first) != string(second) {
		t.Errorf("resumed output differs:\n%q\n%q", first, second)
	}
	if r, _ := openScanState(state, []string{"127.0.0.1"}, mustPorts(t, "1-40")); r.mark != 40 {
		t.Errorf("watermark = %d, want 40", r.mark)
	}
}

func mustPorts(t *testing.T, spec string) []int {
	p, err := resolvePorts(spec)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	s.Open(scanResult{Host: "a", Port: 2})
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
	if err := runPortscan(args); err != nil {
		t.Fatal(err)
	}
	// Re-running a finished scan skips everything yet reproduces the output.
	first, _ := os.ReadFile(out)
	if err := runPortscan(args); err != nil {
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

func TestPipelineCheckpointSkipsDoneSteps(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "step.txt")
	os.WriteFile(out, []byte("x"), 0o644)
	defer func() { activeCheckpoint = nil }()

	activeCheckpoint = loadCheckpoint(filepath.Join(dir, "cp.json"), false)
	ran := 0
	step := func() stepResult { return runStep("web", "probe", "t", out, func() error { ran++; return nil }) }
	step()
	if ran != 1 {
		t.Fatal("first run should execute")
	}
	activeCheckpoint = loadCheckpoint(filepath.Join(dir, "cp.json"), true)
	if sr := step(); ran != 1 || !strings.Contains(sr.Detail, "resumed") {
		t.Errorf("resumed run should skip: ran=%d %+v", ran, sr)
	}
	os.Remove(out) // output gone -> must rerun
	step()
	if ran != 2 {
		t.Error("missing output must force a rerun")
	}
	activeCheckpoint = loadCheckpoint(filepath.Join(dir, "cp.json"), false) // fresh run forgets
	step()
	if ran != 3 {
		t.Error("a fresh (non -resume) run must not skip")
	}
}

func TestFailedStepIsNotCheckpointed(t *testing.T) {
	dir := t.TempDir()
	defer func() { activeCheckpoint = nil }()
	activeCheckpoint = loadCheckpoint(filepath.Join(dir, "cp.json"), false)
	runStep("web", "x", "t", "", func() error { return errors.New("boom") })
	if activeCheckpoint.has(stepKey("web", "x", "t", "")) {
		t.Error("failed step must rerun on resume")
	}
}

func TestSessionStoreAndShellFlow(t *testing.T) {
	t.Chdir(t.TempDir())
	cwd, _ := os.Getwd()

	rec := sessionRec{ID: sessionID([]string{"portscan", "-l", "h"}), Args: []string{"portscan", "-l", "h"}}
	exit130 := execDoneMsg{cmd: "portscan", err: errors.New("x"), sess: &rec, dir: cwd}
	// an ExitError with code 130 can't be forged portably; use the real thing
	exit130.err = exitErrorWithCode(t, 130)
	recordSession(exit130)
	if s := loadSessions(cwd); len(s) != 1 || s[0].ID != rec.ID {
		t.Fatalf("interrupted session not recorded: %+v", s)
	}

	m := newTestModel()
	m.listSessions()
	if !strings.Contains(m.notice, rec.ID) {
		t.Errorf("sessions notice = %q", m.notice)
	}
	if _, cmd := m.resumeSession(nil); cmd == nil {
		t.Error("resume should launch the interrupted command")
	}
	if got, _ := newTestModel().resumeSession([]string{"zzzz"}); got.(shellModel).lastErr == nil {
		t.Error("unknown id should error")
	}

	recordSession(execDoneMsg{cmd: "portscan", sess: &rec, dir: cwd}) // clean exit
	if s := loadSessions(cwd); len(s) != 0 {
		t.Errorf("finished session should be dropped: %+v", s)
	}
	if got, _ := newTestModel().resumeSession(nil); got.(shellModel).lastErr == nil {
		t.Error("resume with nothing interrupted should error")
	}
}

func exitErrorWithCode(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit "+string(rune('0'+code/100))+string(rune('0'+code/10%10))+string(rune('0'+code%10))).Run()
	if err == nil {
		t.Fatal("expected a non-zero exit")
	}
	return err
}

func TestLaunchInjectsResumeState(t *testing.T) {
	t.Chdir(t.TempDir())
	stale := filepath.Join(stateDir("."), sessionID([]string{"portscan", "-l", "h"})+".state")
	os.MkdirAll(filepath.Dir(stale), 0o755)
	os.WriteFile(stale, []byte("old"), 0o644)

	_, cmd := newTestModel().launch("portscan", []string{"-l", "h"}, false)
	if cmd == nil {
		t.Fatal("no cmd")
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("a fresh run must discard stale state")
	}
	os.WriteFile(stale, []byte("keep"), 0o644)
	newTestModel().launch("portscan", []string{"-l", "h"}, true)
	if _, err := os.Stat(stale); err != nil {
		t.Error("resuming must keep state")
	}
}

func TestSessionCommandsRegistered(t *testing.T) {
	for _, w := range []string{"sessions", "resume"} {
		if !commandKnown(shellCommandNames(), w) {
			t.Errorf("missing %q", w)
		}
	}
}

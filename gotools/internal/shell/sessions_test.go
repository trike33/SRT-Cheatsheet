package shell

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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

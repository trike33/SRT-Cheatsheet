package shell

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

// Resumable sessions. Long-running commands (portscan, fuzz, pipeline) can be
// stopped -- Ctrl+C, a `limit bytes` halt -- and continued later with
// `resume`. Sessions live per project, in <project>/.srt/, so they survive
// closing the shell and `cd`-ing between projects:
//
//	.srt/sessions.json   interrupted sessions (command line + when)
//	.srt/state/<id>.state  per-session progress for portscan/fuzz
//
// Every portscan/fuzz run from the shell silently gets `-resume <state>`, so
// it is always resumable; pipeline resumes from its own checkpoint file.

var resumableCommands = map[string]bool{"portscan": true, "fuzz": true, "pipeline": true}

type sessionRec struct {
	ID      string    `json:"id"`
	Args    []string  `json:"args"` // command name first, as typed (no injected flags)
	Updated time.Time `json:"updated"`
}

func sessionsPath(dir string) string { return filepath.Join(dir, ".srt", "sessions.json") }
func stateDir(dir string) string     { return filepath.Join(dir, ".srt", "state") }

func sessionID(args []string) string {
	sum := sha256.Sum256([]byte(strings.Join(args, "\x00")))
	return hex.EncodeToString(sum[:])[:8]
}

func loadSessions(dir string) []sessionRec {
	var s []sessionRec
	if b, err := os.ReadFile(sessionsPath(dir)); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func saveSessions(dir string, s []sessionRec) error {
	if len(s) == 0 {
		if err := os.Remove(sessionsPath(dir)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(sessionsPath(dir)), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(sessionsPath(dir), b, 0o644)
}

func upsertSession(dir string, rec sessionRec) error {
	s := slices.DeleteFunc(loadSessions(dir), func(r sessionRec) bool { return r.ID == rec.ID })
	return saveSessions(dir, append(s, rec))
}

func dropSession(dir, id string) error {
	return saveSessions(dir, slices.DeleteFunc(loadSessions(dir), func(r sessionRec) bool { return r.ID == id }))
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

// launch starts cmdName/cmdArgs as a subprocess. For resumable commands it
// wires up session tracking: a fresh run clears any stale state; resuming keeps
// it. The user's own -resume flag is respected and not tracked.
func (m shellModel) launch(cmdName string, cmdArgs []string, resuming bool) (tea.Model, tea.Cmd) {
	runArgs := cmdArgs
	var sess *sessionRec
	var stateFile string
	cwd, _ := os.Getwd()

	if resumableCommands[cmdName] && !hasFlag(cmdArgs, "-resume") {
		rec := sessionRec{ID: sessionID(append([]string{cmdName}, cmdArgs...)), Args: append([]string{cmdName}, cmdArgs...), Updated: time.Now()}
		sess = &rec
		if cmdName == "pipeline" {
			if resuming {
				runArgs = append([]string{"-resume"}, cmdArgs...)
			}
		} else {
			if err := os.MkdirAll(stateDir(cwd), 0o755); err == nil {
				stateFile = filepath.Join(stateDir(cwd), rec.ID+".state")
				if !resuming {
					os.Remove(stateFile)
				}
				runArgs = append([]string{"-resume", stateFile}, cmdArgs...)
			}
		}
	}

	// A command takes over the screen, so close the help pane (and its mouse
	// capture) first; otherwise its output would be drawn around the pane.
	var closePane tea.Cmd
	if m.helpOpen {
		closePane = m.closeHelp()
	}

	c := m.cmdFor(cmdName, runArgs)
	base, snap := m.traffic, m
	pinned := &pinnedExec{
		cmd:         c,
		trafficFile: m.trafficFile,
		header: func(live netx.Totals, rate float64) string {
			hm := snap
			hm.traffic = base
			hm.traffic.Add(live)
			hm.lastRun = fmt.Sprintf("running: %s — %s · %.0f req/s", cmdName, live, rate)
			hm.width = max(hm.width, 80)
			return hm.renderHeader()
		},
	}
	run := tea.Exec(pinned, func(err error) tea.Msg {
		return execDoneMsg{cmd: cmdName, err: err, sess: sess, stateFile: stateFile, dir: cwd}
	})
	if closePane != nil {
		return m, tea.Sequence(closePane, run)
	}
	return m, run
}

// recordSession updates the on-disk session list from a finished command:
// halted (Ctrl+C / limit) -> interrupted and resumable; clean exit -> done.
func recordSession(msg execDoneMsg) {
	if msg.sess == nil {
		return
	}
	switch code := execExitCode(msg.err); {
	case msg.err == nil:
		dropSession(msg.dir, msg.sess.ID)
		if msg.stateFile != "" {
			os.Remove(msg.stateFile)
		}
	case code == 130 || code == 3:
		msg.sess.Updated = time.Now()
		upsertSession(msg.dir, *msg.sess)
	}
}

func (m *shellModel) listSessions() {
	cwd, _ := os.Getwd()
	s := loadSessions(cwd)
	if len(s) == 0 {
		m.notice = "no interrupted sessions in " + projectName(cwd)
		return
	}
	var parts []string
	for _, r := range s {
		parts = append(parts, fmt.Sprintf("%s: %s (%s ago)", r.ID, strings.Join(r.Args, " "), time.Since(r.Updated).Round(time.Second)))
	}
	m.notice = "interrupted — " + strings.Join(parts, " | ") + " — `resume [id]` continues"
}

// resumeSession re-launches an interrupted session: the given id, or the most
// recent one.
func (m shellModel) resumeSession(args []string) (tea.Model, tea.Cmd) {
	cwd, _ := os.Getwd()
	s := loadSessions(cwd)
	if len(s) == 0 {
		m.lastErr = fmt.Errorf("resume: no interrupted sessions in %s", projectName(cwd))
		return m, nil
	}
	pick := s[len(s)-1]
	if len(args) > 0 {
		i := slices.IndexFunc(s, func(r sessionRec) bool { return strings.HasPrefix(r.ID, args[0]) })
		if i < 0 {
			m.lastErr = fmt.Errorf("resume: no interrupted session %q (see `sessions`)", args[0])
			return m, nil
		}
		pick = s[i]
	}
	m.notice = "resuming " + strings.Join(pick.Args, " ")
	return m.launch(pick.Args[0], pick.Args[1:], true)
}

package shell

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/trike33/srt-cheatsheet/gotools/internal/fuzzctl"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

// Backgrounding (Ctrl+Z): the running command keeps going and the prompt is
// free again. Its output is buffered for `fg`; `jobs` lists what's running,
// and Ctrl+R still shows its live results.

func (m *shellModel) sendToBackground() {
	rs := m.run
	m.jobSeq++
	rs.id, rs.bg = m.jobSeq, true
	rs.traffic, m.trafficFile = m.trafficFile, ""
	m.bgRuns = append(m.bgRuns, rs)
	m.run, m.live, m.liveAt, m.liveRate = nil, netx.Totals{}, time.Time{}, 0
	m.progress = false
	m.appendOut(dimStyle(m.colorOn).Render(fmt.Sprintf("[%d] %s sent to the background — `jobs` lists, `fg %d` brings it back, Ctrl+R shows live results", rs.id, rs.name, rs.id)))
}

// finishBackground settles a background command that exited on its own.
func (m *shellModel) finishBackground(msg execDoneMsg) {
	rs := msg.rs
	for i, b := range m.bgRuns {
		if b == rs {
			m.bgRuns = append(m.bgRuns[:i], m.bgRuns[i+1:]...)
			break
		}
	}
	recordSession(msg)
	m.dropFuzzDir(rs)
	if t, ok := netx.ReadTrafficFile(rs.traffic); ok {
		m.traffic.Add(t)
		m.lastRun = fmt.Sprintf("last: %s (job %d) — %s", rs.name, rs.id, t)
	}
	if rs.traffic != "" {
		os.Remove(rs.traffic)
	}
	status := "done"
	if c := execExitCode(msg.err); c > 0 {
		status = fmt.Sprintf("exited with status %d", c)
		if c != 130 && c != 3 {
			m.errCount++
		}
	}
	m.appendOut(dimStyle(m.colorOn).Render(fmt.Sprintf("[%d] %s %s (background) — `fg %d` no longer applies; results are in the database / output dir", rs.id, rs.name, status, rs.id)))
	m.notice = fmt.Sprintf("job %d (%s) %s", rs.id, rs.name, status)
}

func (m *shellModel) listJobs() {
	if len(m.bgRuns) == 0 {
		m.notice = "no background jobs"
		return
	}
	var parts []string
	for _, r := range m.bgRuns {
		parts = append(parts, fmt.Sprintf("[%d] %s %s", r.id, r.name, strings.Join(r.args, " ")))
	}
	m.notice = "jobs — " + strings.Join(parts, " | ")
}

// foreground brings a background job (the newest, or the given number) back:
// its buffered output is replayed and it owns the prompt again.
func (m shellModel) foreground(args []string) (tea.Model, tea.Cmd) {
	if len(m.bgRuns) == 0 {
		m.lastErr = fmt.Errorf("fg: no background jobs")
		return m, nil
	}
	pick := len(m.bgRuns) - 1
	if len(args) > 0 {
		n, err := strconv.Atoi(strings.TrimPrefix(args[0], "%"))
		pick = -1
		for i, r := range m.bgRuns {
			if err == nil && r.id == n {
				pick = i
			}
		}
		if pick < 0 {
			m.lastErr = fmt.Errorf("fg: no such job %q (see `jobs`)", args[0])
			return m, nil
		}
	}
	rs := m.bgRuns[pick]
	m.bgRuns = append(m.bgRuns[:pick], m.bgRuns[pick+1:]...)
	rs.bg = false
	m.run = rs
	m.trafficFile, rs.traffic = rs.traffic, ""
	m.peekName, m.peekFuzz = rs.name, rs.fuzzDir
	m.appendCmdOut(rs.buf)
	rs.buf = nil
	return m, tick() // its output reader is already waiting; just resume the ticker
}

// dropFuzzDir removes a finished command's fuzz status/control files.
func (m *shellModel) dropFuzzDir(rs *runState) {
	if rs == nil || rs.fuzzDir == "" {
		return
	}
	os.RemoveAll(rs.fuzzDir)
	if m.peekFuzz == rs.fuzzDir {
		m.peekFuzz = ""
	}
	if m.peek != nil && m.peek.fuzzDir == rs.fuzzDir {
		m.peek.fuzzDir = ""
	}
	rs.fuzzDir = ""
}

// runControlsHint is the bottom-bar legend of what the keys do while a
// command runs. Skip only exists for a pipeline (it skips one of its steps).
func (m shellModel) runControlsHint() string {
	skip := ""
	if m.run.name == "pipeline" {
		skip = " · Ctrl+S to skip step"
	}
	if m.width > 0 && m.width < 115 {
		short := ""
		if skip != "" {
			short = " · Ctrl+S skip"
		}
		return "running " + m.run.name + " — Ctrl+C stop" + short + " · Ctrl+Z bg · Ctrl+R live results"
	}
	return "running " + m.run.name + " — Ctrl+C to stop" + skip + " · Ctrl+Z to bg · Ctrl+R to check live results"
}

// requestSkip asks the running pipeline to abandon its current step.
func (m *shellModel) requestSkip() {
	switch {
	case m.run.name != "pipeline":
		m.notice = "Ctrl+S skips a pipeline step; " + m.run.name + " isn't a pipeline (Ctrl+C stops it)"
	case m.run.fuzzDir == "":
		m.notice = "can't skip: no control channel to the pipeline"
	default:
		if err := fuzzctl.RequestSkip(filepath.Join(m.run.fuzzDir, "control.json")); err != nil {
			m.lastErr = fmt.Errorf("skip: %w", err)
			return
		}
		m.notice = "skipping the current pipeline step (it keeps running in the background; Ctrl+C halts the whole pipeline)"
	}
}

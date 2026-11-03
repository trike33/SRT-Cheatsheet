package shell

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/trike33/srt-cheatsheet/gotools/internal/fuzzctl"
)

func TestPipelineOutDir(t *testing.T) {
	cwd := t.TempDir()
	if got := pipelineOutDir(cwd, nil); got != filepath.Join(cwd, "srt-pipeline-out") {
		t.Errorf("default = %s", got)
	}
	if got := pipelineOutDir(cwd, []string{"-o", "out"}); got != filepath.Join(cwd, "out") {
		t.Errorf("-o = %s", got)
	}
	os.WriteFile(filepath.Join(cwd, "c.json"), []byte(`{"options":{"outputDir":"/abs/dir"}}`), 0o644)
	if got := pipelineOutDir(cwd, []string{"-c", "c.json"}); got != "/abs/dir" {
		t.Errorf("config outputDir = %s", got)
	}
}

func TestPeekListsStepFilesAndTailsLive(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "02_gau_a.txt"), []byte("u1\nu2\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "pipeline.log"), []byte("step ok\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "checkpoint.json"), []byte("{}"), 0o644)
	t.Setenv("SRT_DB", filepath.Join(dir, "none.db")) // no database yet

	p := &peekView{dir: dir, name: "pipeline"}
	p.refresh()
	var titles []string
	for _, e := range p.entries {
		titles = append(titles, e.title)
	}
	if strings.Join(titles, ",") != "results database,pipeline.log,02_gau_a.txt" {
		t.Fatalf("entries = %v", titles)
	}
	p.sel = 2
	p.refresh()
	if strings.Join(p.content, "|") != "u1|u2" {
		t.Errorf("content = %v", p.content)
	}
	// the file grows while the window is open: the next refresh sees it
	f, _ := os.OpenFile(filepath.Join(dir, "02_gau_a.txt"), os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("u3\n")
	f.Close()
	p.refresh()
	if last := p.content[len(p.content)-1]; last != "u3" {
		t.Errorf("did not pick up appended line: %v", p.content)
	}
}

func TestCtrlRopensAndEscCloses(t *testing.T) {
	t.Setenv("SRT_DB", filepath.Join(t.TempDir(), "none.db"))
	m := newTestModel()
	send := func(k tea.KeyMsg) { got, _ := m.Update(k); m = got.(shellModel) }
	send(tea.KeyMsg{Type: tea.KeyCtrlR})
	if m.peek == nil {
		t.Fatal("Ctrl+R should open the live-results window")
	}
	_ = m.View() // renders without panicking
	send(tea.KeyMsg{Type: tea.KeyEsc})
	if m.peek != nil {
		t.Fatal("Esc should close the window")
	}
}

func TestCtrlZSendsRunToBackground(t *testing.T) {
	m := newTestModel()
	rs := newRun(exec.Command("true"))
	rs.name = "pipeline"
	m.run = rs
	got, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlZ})
	m = got.(shellModel)
	if m.run != nil || len(m.bgRuns) != 1 || !rs.bg {
		t.Fatalf("run=%v bg=%d", m.run, len(m.bgRuns))
	}
	// its output is buffered, not printed
	got, _ = m.Update(outMsg{lines: []string{"hello"}, rs: rs})
	m = got.(shellModel)
	if len(rs.buf) != 1 {
		t.Errorf("buf = %v", rs.buf)
	}
	// fg brings it back and replays the buffer
	got, _ = m.foreground(nil)
	m = got.(shellModel)
	if m.run != rs || rs.bg || len(m.bgRuns) != 0 {
		t.Fatal("fg should restore the run")
	}
	if !strings.Contains(strings.Join(m.out, "\n"), "hello") {
		t.Errorf("buffered output not replayed: %v", m.out)
	}
}

func TestPeekFuzzHostsAndStopKey(t *testing.T) {
	t.Setenv("SRT_DB", filepath.Join(t.TempDir(), "none.db"))
	dir := t.TempDir()
	fuzzctl.WriteStatus(filepath.Join(dir, "status.json"), fuzzctl.Status{Hosts: []fuzzctl.Host{
		{Host: "a.test", State: fuzzctl.StateRunning, Planned: 100, Done: 40, Matches: 2, Wordlists: []string{"common.txt"}, Words: 50, Hits: []string{"200 12b http://a.test/admin"}},
		{Host: "b.test", State: fuzzctl.StateQueued, Planned: 100},
	}})
	m := newTestModel()
	m.peekFuzz = dir
	m.openPeek()
	if m.peek == nil || len(m.peek.entries) != 4 { // database, all hosts, a.test, b.test
		t.Fatalf("entries = %+v", m.peek)
	}
	// overview lists both hosts and the wordlist
	m.peek.sel = 1
	m.peek.refresh()
	joined := strings.Join(m.peek.content, "\n")
	if !strings.Contains(joined, "common.txt") || !strings.Contains(joined, "a.test") || !strings.Contains(joined, "b.test") {
		t.Errorf("overview = %s", joined)
	}
	// host detail shows live hits; x writes a stop request for that host
	m.peek.sel = 2
	m.peek.refresh()
	if !strings.Contains(strings.Join(m.peek.content, "\n"), "http://a.test/admin") {
		t.Errorf("host detail lacks hits: %v", m.peek.content)
	}
	m.peekKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")}, 30)
	if got := fuzzctl.ReadControl(filepath.Join(dir, "control.json")).Stop; len(got) != 1 || got[0] != "a.test" {
		t.Errorf("stop list = %v", got)
	}
	_ = m.View()
}

func TestCtrlSWritesSkipRequestForPipeline(t *testing.T) {
	dir := t.TempDir()
	m := newTestModel()
	rs := newRun(exec.Command("true"))
	rs.name, rs.fuzzDir = "pipeline", dir
	m.run = rs
	m.width = 140
	if !strings.Contains(m.runControlsHint(), "Ctrl+S to skip step") {
		t.Errorf("hint lacks Ctrl+S: %s", m.runControlsHint())
	}
	got, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	if n := fuzzctl.ReadControl(filepath.Join(dir, "control.json")).Skip; n != 1 {
		t.Errorf("skip counter = %d", n)
	}
	// a non-pipeline command has no skip
	m2 := got.(shellModel)
	m2.run = newRun(exec.Command("true"))
	m2.run.name = "fuzz"
	m2.width = 140
	if strings.Contains(m2.runControlsHint(), "Ctrl+S") {
		t.Error("only pipelines advertise Ctrl+S")
	}
}

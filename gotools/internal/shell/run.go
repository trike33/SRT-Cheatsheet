package shell

import (
	"bufio"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

// The shell keeps a fixed layout (header on top, prompt at the bottom) and
// shows a command's output in the scrollable area between them. So commands
// run with stdout+stderr captured through a pipe instead of owning the
// terminal; their lines stream into the model as messages.

// maxOutLines caps the scrollback; the oldest lines are dropped past it.
const maxOutLines = 5000

type runState struct {
	cmd   *exec.Cmd
	lines chan []string // batches of output lines; closed when the output ends
	done  chan error    // the command's exit status, sent after lines closes
	sigs  int           // Ctrl+C presses so far: first interrupts, then kills
	errs  int           // error lines seen in its output

	name      string
	sess      *sessionRec
	stateFile string
	dir       string
}

type outMsg struct{ lines []string }

type tickMsg struct{}

// newRun prepares c to run with its output captured; begin starts it. Its
// stdin is empty (a command that reads a list from stdin sees EOF instead of
// hanging the prompt).
func newRun(c *exec.Cmd) *runState {
	return &runState{cmd: c, lines: make(chan []string, 64), done: make(chan error, 1)}
}

// begin starts the process and returns its first output batch (or its end).
func (rs *runState) begin() tea.Cmd {
	return func() tea.Msg {
		pr, pw := io.Pipe()
		c := rs.cmd
		c.Stdin, c.Stdout, c.Stderr = nil, pw, pw
		setProcGroup(c)
		if err := c.Start(); err != nil {
			return execDoneMsg{cmd: rs.name, err: err, sess: rs.sess, stateFile: rs.stateFile, dir: rs.dir}
		}
		go func() {
			err := c.Wait()
			pw.Close()
			rs.done <- err
		}()
		go func() {
			br := bufio.NewReaderSize(pr, 64<<10)
			var batch []string
			flush := func() {
				if len(batch) > 0 {
					rs.lines <- batch
					batch = nil
				}
			}
			for {
				s, err := br.ReadString('\n')
				if s != "" {
					batch = append(batch, cleanLine(s))
					if len(batch) >= 256 || br.Buffered() == 0 {
						flush()
					}
				}
				if err != nil {
					break
				}
			}
			flush()
			close(rs.lines)
		}()
		return waitOutput(rs)()
	}
}

// escapeSeq matches terminal escape sequences; keepSGR leaves colours alone
// and drops everything else (cursor movement, screen clears, titles, ...) that
// would corrupt the fixed layout around the output area.
var escapeSeq = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\x1b[=>78cDEHMZ]`)

func keepSGR(seq string) string {
	if strings.HasPrefix(seq, "\x1b[") && strings.HasSuffix(seq, "m") {
		return seq
	}
	return ""
}

// cleanLine drops the newline, resolves carriage-return rewrites (progress
// lines keep only their last state), expands tabs (which the width math of
// wrapping can't handle) and strips control sequences other than colours.
func cleanLine(s string) string {
	s = strings.TrimRight(s, "\r\n")
	if i := strings.LastIndex(s, "\r"); i >= 0 {
		s = s[i+1:]
	}
	s = escapeSeq.ReplaceAllStringFunc(s, keepSGR)
	s = strings.ReplaceAll(s, "\t", "    ")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != 0x1b || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return strings.TrimRight(s, " ")
}

// plainText is s without colour codes, for classifying a line.
func plainText(s string) string { return escapeSeq.ReplaceAllString(s, "") }

type lineKind int

const (
	kindPlain lineKind = iota
	kindWarning
	kindError
)

// classifyLine recognises srt's own conventions: warnings print as "[!] msg"
// (ioutil.Warn) and command failures as "srt: msg" (a limit halt, "srt:
// HALTED", is a deliberate stop and only a warning).
func classifyLine(line string) lineKind {
	t := strings.TrimSpace(plainText(line))
	switch {
	case strings.HasPrefix(t, "[!]"):
		return kindWarning
	case strings.HasPrefix(t, "srt: HALTED"):
		return kindWarning
	case strings.HasPrefix(t, "srt: "):
		return kindError
	}
	return kindPlain
}

// appendCmdOut adds a command's output lines: blank runs collapse to one,
// there is never a leading blank, errors and warnings are counted for the
// header and coloured.
func (m *shellModel) appendCmdOut(lines []string) {
	var keep []string
	last := len(m.out) == 0 || m.out[len(m.out)-1] == ""
	for _, l := range lines {
		if l == "" {
			if last {
				continue
			}
			last = true
			keep = append(keep, l)
			continue
		}
		last = false
		switch classifyLine(l) {
		case kindError:
			m.errCount++
			if m.run != nil {
				m.run.errs++
			}
			l = classStyle(classUnknown, m.colorOn).Render(l)
		case kindWarning:
			m.warnCount++
			l = classStyle(classFlag, m.colorOn).Render(l)
		}
		keep = append(keep, l)
	}
	m.appendOut(keep...)
}

// endBlock closes a command's output with one blank line (never two).
func (m *shellModel) endBlock() {
	if len(m.out) > 0 && m.out[len(m.out)-1] != "" {
		m.appendOut("")
	}
}

// waitOutput delivers the next batch of output, or the final execDoneMsg.
func waitOutput(rs *runState) tea.Cmd {
	return func() tea.Msg {
		batch, ok := <-rs.lines
		if !ok {
			return execDoneMsg{cmd: rs.name, err: <-rs.done, sess: rs.sess, stateFile: rs.stateFile, dir: rs.dir}
		}
		return outMsg{batch}
	}
}

func tick() tea.Cmd {
	return tea.Tick(400*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

// interrupt stops the running command: the first call asks it to halt (so
// resumable commands save their state), later calls kill it.
func (rs *runState) interrupt() {
	rs.sigs++
	if rs.cmd.Process == nil {
		return // not started yet
	}
	signalGroup(rs.cmd.Process, rs.sigs > 1)
}

// appendOut adds lines to the scrollback, keeping the view anchored on
// whatever the user scrolled to.
func (m *shellModel) appendOut(lines ...string) {
	m.out = append(m.out, lines...)
	if len(m.out) > maxOutLines {
		m.out = append([]string(nil), m.out[len(m.out)-maxOutLines+maxOutLines/5:]...)
	}
	if m.outScroll > 0 {
		m.outScroll += len(lines)
	}
}

// tickTraffic refreshes the live totals shown in the header while a command
// runs, from the handoff file the child keeps writing.
func (m *shellModel) tickTraffic() {
	live, ok := netx.ReadTrafficFile(m.trafficFile)
	if !ok {
		return
	}
	now := time.Now()
	if !m.liveAt.IsZero() {
		if dt := now.Sub(m.liveAt).Seconds(); dt > 0 && live.Requests >= m.live.Requests {
			m.liveRate = float64(live.Requests-m.live.Requests) / dt
		}
	}
	m.live, m.liveAt = live, now
	m.lastRun = "running: " + m.run.name + " — " + live.String() + " · " + fmtRate(m.liveRate)
}

func fmtRate(r float64) string { return sprintf("%.0f req/s", r) }

// --- scrollback rendering ---

// wrapRows splits one output line into display rows of at most w cells.
func wrapRows(line string, w int) []string {
	if lipgloss.Width(line) <= w {
		return []string{line}
	}
	return strings.Split(lipgloss.NewStyle().Width(w).Render(line), "\n")
}

func (m shellModel) totalRows(w int) int {
	n := 0
	for _, l := range m.out {
		n += len(wrapRows(l, w))
	}
	return n
}

// outHeight is the number of rows the output area gets: everything between
// the header and the prompt.
func (m shellModel) outHeight() int {
	return max(m.height-m.chromeHeight(), 3)
}

// chromeHeight is the height of everything but the output area.
func (m shellModel) chromeHeight() int {
	return lipgloss.Height(m.renderBottom()) + lipgloss.Height(m.renderHeader())
}

// scrollOut moves the output view by delta rows (positive = toward older
// output), clamped to the available scrollback.
func (m *shellModel) scrollOut(delta int) {
	maxScroll := max(m.totalRows(m.width)-m.outHeight(), 0)
	m.outScroll = min(max(m.outScroll+delta, 0), maxScroll)
}

// renderOutput draws the output area: newest output at the bottom once it
// fills the area, top-aligned until then. scroll rows are hidden at the
// bottom.
func (m shellModel) renderOutput(w, h int) string {
	var rows []string // collected newest-first
	seen := 0
	for i := len(m.out) - 1; i >= 0 && seen < m.outScroll+h; i-- {
		wr := wrapRows(m.out[i], w)
		for k := len(wr) - 1; k >= 0 && seen < m.outScroll+h; k-- {
			if seen >= m.outScroll {
				rows = append(rows, wr[k])
			}
			seen++
		}
	}
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	for len(rows) < h {
		rows = append(rows, "")
	}
	return strings.Join(rows, "\n")
}

package shell

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/trike33/srt-cheatsheet/gotools/internal/fuzzctl"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

// The live-results window (Ctrl+R). It is a read-only overlay over the
// output area: it never touches the running command, it just re-reads where
// results land -- the project database (flushed about once a second while a
// command runs) and, for a pipeline, its output directory (one file per
// step, plus pipeline.log) -- every peekInterval. Esc closes it.

const (
	peekInterval = 500 * time.Millisecond
	peekTailMax  = 256 << 10 // bytes read from the end of a file
	peekListRows = 8
	peekDBRows   = 200
)

type peekTickMsg struct{}

func peekTick() tea.Cmd {
	return tea.Tick(peekInterval, func(time.Time) tea.Msg { return peekTickMsg{} })
}

const (
	entryFile = iota
	entryDB
	entryFuzzAll
	entryFuzzHost
)

type peekEntry struct {
	kind  int
	host  string // entryFuzzHost
	title string // list label
	path  string // file to tail; "" for the database entry
	size  int64
	fresh bool // modified in the last few seconds (still being written)
}

type peekView struct {
	dir   string // pipeline output dir ("" for a non-pipeline command)
	name  string // command being watched
	db    *sql.DB
	dbErr string

	fuzzDir string         // fuzz status/control dir of the watched command
	fuzz    fuzzctl.Status // latest snapshot
	notice  string         // one-line feedback (e.g. a stop request)

	entries []peekEntry
	sel     int
	scroll  int // rows up from the newest content (0 = following)
	content []string
}

// pipelineOutDir works out where a pipeline run writes its step files: -o,
// else options.outputDir from its -c config, else the default.
func pipelineOutDir(cwd string, args []string) string {
	val := func(name string) string {
		for i, a := range args {
			for _, p := range []string{"-" + name, "--" + name} {
				if a == p && i+1 < len(args) {
					return args[i+1]
				}
				if v, ok := strings.CutPrefix(a, p+"="); ok {
					return v
				}
			}
		}
		return ""
	}
	dir := val("o")
	if dir == "" {
		if cfg := val("c"); cfg != "" {
			if !filepath.IsAbs(cfg) {
				cfg = filepath.Join(cwd, cfg)
			}
			if b, err := os.ReadFile(cfg); err == nil {
				var c struct {
					Options struct {
						OutputDir string `json:"outputDir"`
					} `json:"options"`
				}
				if json.Unmarshal(b, &c) == nil {
					dir = c.Options.OutputDir
				}
			}
		}
	}
	if dir == "" {
		dir = "srt-pipeline-out"
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(cwd, dir)
	}
	return dir
}

// openPeek builds the window for the command the user cares about: the
// foreground one, else the newest background one, else the last one run.
func (m *shellModel) openPeek() {
	p := &peekView{dir: m.peekDir, name: m.peekName, fuzzDir: m.peekFuzz}
	if p.name == "" {
		p.name = "last command"
	}
	if db, err := store.OpenReadable(); err != nil {
		p.dbErr = err.Error()
	} else {
		p.db = db
	}
	m.peek = p
	p.refresh()
}

func (m *shellModel) closePeek() {
	if m.peek != nil && m.peek.db != nil {
		m.peek.db.Close()
	}
	m.peek = nil
}

func (p *peekView) refresh() {
	var keep string
	if p.sel < len(p.entries) {
		keep = p.entries[p.sel].title
	}
	p.entries = []peekEntry{{kind: entryDB, title: "results database"}}
	p.fuzz = fuzzctl.Status{}
	if p.fuzzDir != "" {
		if st, ok := fuzzctl.ReadStatus(filepath.Join(p.fuzzDir, "status.json")); ok && len(st.Hosts) > 0 {
			p.fuzz = st
			p.entries = append(p.entries, peekEntry{kind: entryFuzzAll, title: fmt.Sprintf("fuzz · all hosts (%d)", len(st.Hosts))})
			for _, h := range st.Hosts {
				p.entries = append(p.entries, peekEntry{kind: entryFuzzHost, host: h.Host,
					title: fmt.Sprintf("fuzz · %s  %s", h.Host, h.State), fresh: h.State == fuzzctl.StateRunning})
			}
		}
	}
	if p.dir != "" {
		files, _ := os.ReadDir(p.dir)
		var named []peekEntry
		for _, f := range files {
			if f.IsDir() || strings.HasPrefix(f.Name(), ".") || f.Name() == "checkpoint.json" {
				continue
			}
			info, err := f.Info()
			if err != nil {
				continue
			}
			named = append(named, peekEntry{
				title: f.Name(), path: filepath.Join(p.dir, f.Name()), size: info.Size(),
				fresh: time.Since(info.ModTime()) < 3*time.Second,
			})
		}
		sort.Slice(named, func(i, j int) bool {
			// pipeline.log first (the step-by-step status), then step files in name order.
			a, b := named[i].title == "pipeline.log", named[j].title == "pipeline.log"
			if a != b {
				return a
			}
			return named[i].title < named[j].title
		})
		p.entries = append(p.entries, named...)
	}
	for i, e := range p.entries {
		// keep the selection on the same entry across refreshes (a fuzz
		// host's title carries its state, which changes -- match its host)
		if e.title == keep || (e.kind == entryFuzzHost && strings.HasPrefix(keep, "fuzz · "+e.host+" ")) {
			p.sel = i
		}
	}
	p.sel = min(max(p.sel, 0), len(p.entries)-1)
	p.content = p.load(p.entries[p.sel])
}

func (p *peekView) load(e peekEntry) []string {
	switch e.kind {
	case entryDB:
		return p.dbLines()
	case entryFuzzAll:
		return p.fuzzOverview()
	case entryFuzzHost:
		return p.fuzzHostLines(e.host)
	}
	f, err := os.Open(e.path)
	if err != nil {
		return []string{"(" + err.Error() + ")"}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	off := int64(0)
	if info.Size() > peekTailMax {
		off = info.Size() - peekTailMax
	}
	buf := make([]byte, info.Size()-off)
	n, _ := f.ReadAt(buf, off)
	lines := strings.Split(strings.TrimRight(string(buf[:n]), "\n"), "\n")
	if off > 0 && len(lines) > 0 {
		lines = lines[1:] // first line is cut mid-way
		lines = append([]string{fmt.Sprintf("… (showing the last %d KiB of %s)", peekTailMax>>10, humanBytes(info.Size()))}, lines...)
	}
	for i, l := range lines {
		lines[i] = cleanLine(l)
	}
	if len(lines) == 1 && lines[0] == "" {
		return []string{"(empty so far)"}
	}
	return lines
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// dbLines summarizes the newest run in the project database: per-kind
// counts, then the most recent records.
func (p *peekView) dbLines() []string {
	if p.db == nil {
		return []string{p.dbErr, "", "nothing has been saved yet -- run with `save on` or a pipeline."}
	}
	var id int64
	var name, started string
	var ended sql.NullString
	err := p.db.QueryRow(`SELECT id,name,started_at,ended_at FROM runs ORDER BY id DESC LIMIT 1`).Scan(&id, &name, &started, &ended)
	if err != nil {
		return []string{"no runs saved yet"}
	}
	state := "running"
	if ended.Valid {
		state = "finished " + ended.String
	}
	out := []string{fmt.Sprintf("run %d · %s · started %s · %s", id, name, started, state), ""}
	rows, err := p.db.Query(`SELECT kind,COUNT(*) FROM records WHERE run_id=? GROUP BY kind ORDER BY kind`, id)
	if err == nil {
		total := 0
		var parts []string
		for rows.Next() {
			var k string
			var c int
			rows.Scan(&k, &c)
			total += c
			parts = append(parts, fmt.Sprintf("%s %d", k, c))
		}
		rows.Close()
		out = append(out, fmt.Sprintf("%d record(s): %s", total, strings.Join(parts, " · ")), "")
	}
	recs, err := p.db.Query(`SELECT kind,key,status FROM records WHERE run_id=? ORDER BY id DESC LIMIT ?`, id, peekDBRows)
	if err == nil {
		var latest []string
		for recs.Next() {
			var k, key string
			var st int
			recs.Scan(&k, &key, &st)
			l := fmt.Sprintf("[%s] %s", k, key)
			if st > 0 {
				l += fmt.Sprintf(" (%d)", st)
			}
			latest = append(latest, l)
		}
		recs.Close()
		// newest last, so the window follows the bottom like a log
		for i := len(latest) - 1; i >= 0; i-- {
			out = append(out, latest[i])
		}
	}
	return out
}

// peekKey handles a key while the window is open; it returns true when the
// key was consumed (Ctrl+C is not, so it still stops the running command).
func (m *shellModel) peekKey(msg tea.KeyMsg, h int) bool {
	p := m.peek
	switch msg.Type {
	case tea.KeyEsc, tea.KeyCtrlR:
		m.closePeek()
	case tea.KeyUp:
		p.sel = max(p.sel-1, 0)
		p.scroll = 0
		p.content = p.load(p.entries[p.sel])
	case tea.KeyDown, tea.KeyTab:
		p.sel = min(p.sel+1, len(p.entries)-1)
		p.scroll = 0
		p.content = p.load(p.entries[p.sel])
	case tea.KeyPgUp:
		p.scroll += max(h-peekListRows-4, 1)
	case tea.KeyPgDown:
		p.scroll = max(p.scroll-max(h-peekListRows-4, 1), 0)
	case tea.KeyCtrlUp:
		p.scroll++
	case tea.KeyCtrlDown:
		p.scroll = max(p.scroll-1, 0)
	case tea.KeyEnd:
		p.scroll = 0
	case tea.KeyRunes:
		if string(msg.Runes) == "x" && p.sel < len(p.entries) && p.entries[p.sel].kind == entryFuzzHost {
			host := p.entries[p.sel].host
			if err := fuzzctl.AddStop(filepath.Join(p.fuzzDir, "control.json"), host); err != nil {
				p.notice = "stop failed: " + err.Error()
			} else {
				p.notice = "stop requested for " + host + " — takes effect within a second; its queued work is dropped"
			}
		}
	default:
		return msg.Type != tea.KeyCtrlC // Ctrl+C still reaches the run
	}
	return true
}

func (m shellModel) renderPeek(w, h int) string {
	p := m.peek
	inner := max(w-4, 10)
	title := fmt.Sprintf("Live results · %s · refreshes every %s", p.name, peekInterval)
	if p.notice != "" {
		title = p.notice
	}

	// entry list, windowed around the selection
	listH := min(len(p.entries), peekListRows)
	start := min(max(p.sel-listH/2, 0), len(p.entries)-listH)
	var list []string
	for i := start; i < start+listH; i++ {
		e := p.entries[i]
		mark := "  "
		if i == p.sel {
			mark = "▶ "
		}
		label := e.title
		if e.path != "" {
			label += "  " + dimStyle(m.colorOn).Render(humanBytes(e.size))
			if e.fresh {
				label += classStyle(classFlag, m.colorOn).Render(" ● writing")
			}
		}
		list = append(list, ansi.Truncate(mark+label, inner, "…"))
	}

	contentH := max(h-2-1-len(list)-1, 1) // border rows, title, list, divider
	lines := p.content
	maxScroll := max(len(lines)-contentH, 0)
	scroll := min(p.scroll, maxScroll)
	end := len(lines) - scroll
	from := max(end-contentH, 0)
	body := make([]string, 0, contentH)
	for _, l := range lines[from:end] {
		body = append(body, ansi.Truncate(l, inner, "…"))
	}
	for len(body) < contentH {
		body = append(body, "")
	}
	pos := "following"
	if scroll > 0 {
		pos = fmt.Sprintf("scrolled up %d (End = follow)", scroll)
	}
	divider := dimStyle(m.colorOn).Render(strings.Repeat("─", max(inner-len(pos)-1, 1)) + " " + pos)

	content := classStyle(classCommand, m.colorOn).Render(ansi.Truncate(title, inner, "…")) + "\n" + strings.Join(list, "\n") + "\n" + divider + "\n" + strings.Join(body, "\n")
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).Width(max(w-2, 12)).Height(h - 2)
	if m.colorOn {
		box = box.BorderForeground(lipgloss.Color(colorIndigo))
	}
	return box.Render(content)
}

func pct(done, planned int64) string {
	if planned <= 0 {
		return "  -"
	}
	return fmt.Sprintf("%3d%%", min(done*100/planned, 100))
}

// fuzzOverview is the per-host workload table: which wordlists are in play,
// how the work is spread across hosts, and each host's progress and state.
func (p *peekView) fuzzOverview() []string {
	hosts := p.fuzz.Hosts
	if len(hosts) == 0 {
		return []string{"no fuzz data yet"}
	}
	h0 := hosts[0]
	var out []string
	wl := strings.Join(h0.Wordlists, ", ")
	if wl == "" {
		wl = "(stdin)"
	}
	out = append(out, fmt.Sprintf("wordlists: %s — %d distinct word(s)", wl, h0.Words), "")
	var planned, done, matches int64
	var rate float64
	for _, h := range hosts {
		planned += h.Planned
		done += h.Done
		matches += h.Matches
		rate += h.Rate
	}
	out = append(out, fmt.Sprintf("total: %d/%d requests (%s) · %d hit(s) · %.0f req/s", done, planned, strings.TrimSpace(pct(done, planned)), matches, rate), "")
	out = append(out, fmt.Sprintf("%-32s %-20s %6s %14s %5s %7s %6s", "HOST", "STATE", "DONE", "REQS", "HITS", "REQ/S", "QUEUE"))
	for _, h := range hosts {
		state := h.State
		if h.Cooldown > 0 {
			state = fmt.Sprintf("cooldown %d:%02d", h.Cooldown/60, h.Cooldown%60)
		}
		out = append(out, fmt.Sprintf("%-32.32s %-20.20s %6s %14s %5d %7.1f %6d",
			h.Host, state, pct(h.Done, h.Planned), fmt.Sprintf("%d/%d", h.Done, h.Planned), h.Matches, h.Rate, h.Queued))
	}
	out = append(out, "", "Select a host in the list for its wordlist details and live hits; press x on it to stop fuzzing that host.")
	return out
}

func (p *peekView) fuzzHostLines(host string) []string {
	for _, h := range p.fuzz.Hosts {
		if h.Host != host {
			continue
		}
		state := h.State
		if h.Cooldown > 0 {
			state = fmt.Sprintf("%s — %d:%02d left", state, h.Cooldown/60, h.Cooldown%60)
		}
		wl := strings.Join(h.Wordlists, ", ")
		if wl == "" {
			wl = "(stdin)"
		}
		exts := "none"
		if len(h.Exts) > 0 {
			exts = strings.Join(h.Exts, ", ")
		}
		extra := "none"
		if len(h.Extra) > 0 {
			extra = fmt.Sprintf("%d: %s", len(h.Extra), strings.Join(h.Extra, ", "))
		}
		out := []string{
			fmt.Sprintf("%s — %s", h.Host, state),
			"target:     " + h.Target,
			fmt.Sprintf("wordlists:  %s (%d distinct word(s))", wl, h.Words),
			"extensions: " + exts,
			"extra words (from this host's tech/title): " + extra,
			fmt.Sprintf("progress:   %d/%d (%s) · %d in flight · %d queued · %.1f req/s", h.Done, h.Planned, strings.TrimSpace(pct(h.Done, h.Planned)), h.InFlight, h.Queued, h.Rate),
			fmt.Sprintf("hits:       %d  (newest last; x stops this host)", h.Matches),
			"",
		}
		return append(out, h.Hits...)
	}
	return []string{"no data for " + host}
}

// Package store is srt's results database: a per-project SQLite file (see
// DBPath) that scan results persist to -- instead of living only in flat
// files -- so they can be queried, listed by run, and exported later (see
// the internal/results package for that CLI). It is deliberately generic:
// one wide "records" table (kind, key, host, port, url, status, length,
// and anything else as JSON), grouped into "runs" that are never
// overwritten, so re-running a scan keeps history instead of replacing it.
//
// Each recon package builds its own Record from its own result type (see
// e.g. recon/portscan's Result.Record) and calls CurrentSink().Add -- this
// package knows nothing about what a port scan or an HTTP probe looks like,
// only how to store and query the generic shape they reduce to.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/halt"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"

	_ "modernc.org/sqlite" // pure-Go driver: keeps srt a single static binary
)

const schema = `
CREATE TABLE IF NOT EXISTS runs (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	command    TEXT NOT NULL,
	cwd        TEXT NOT NULL,
	started_at TEXT NOT NULL,
	ended_at   TEXT
);
CREATE TABLE IF NOT EXISTS records (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id     INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
	kind       TEXT NOT NULL,
	key        TEXT NOT NULL,
	host       TEXT NOT NULL DEFAULT '',
	port       INTEGER NOT NULL DEFAULT 0,
	url        TEXT NOT NULL DEFAULT '',
	status     INTEGER NOT NULL DEFAULT 0,
	length     INTEGER NOT NULL DEFAULT 0,
	data       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	UNIQUE(run_id, kind, key)
);
CREATE INDEX IF NOT EXISTS idx_records_kind ON records(kind);
CREATE INDEX IF NOT EXISTS idx_records_host ON records(host);
CREATE INDEX IF NOT EXISTS idx_records_key  ON records(kind, key);
`

// Record is one saved result, in the generic shape every recon package
// reduces its own result type to.
type Record struct {
	Kind   string         `json:"kind"`
	Key    string         `json:"key"`
	Host   string         `json:"host,omitempty"`
	Port   int            `json:"port,omitempty"`
	URL    string         `json:"url,omitempty"`
	Status int            `json:"status,omitempty"`
	Length int            `json:"length,omitempty"`
	Data   map[string]any `json:"data,omitempty"`
	RunID  int64          `json:"run,omitempty"`
}

// EnvSave is the env var that mirrors the global -save flag: set to "1", it
// tells a subprocess (or itself, re-entrantly) to record its results.
const EnvSave = "SRT_SAVE"

// DBPath resolves the database location: $SRT_DB, else ./.srt/srt.db.
func DBPath() string {
	if p := os.Getenv("SRT_DB"); p != "" {
		return p
	}
	return filepath.Join(".srt", "srt.db")
}

// Open opens (creating if needed) the database at path and ensures its
// schema exists.
func Open(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// One connection: SQLite serializes writers anyway, and it makes the
	// per-connection pragmas apply to every statement.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing %s: %w", path, err)
	}
	return db, nil
}

// OpenReadable opens the existing database at DBPath() for queries, with a
// friendly error (and no stray file created) when there's nothing saved yet.
func OpenReadable() (*sql.DB, error) {
	p := DBPath()
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("no results database at %s -- run a command with -save (or a pipeline) first, or set SRT_DB", p)
	}
	return Open(p)
}

// --- run sink: buffered, flushed on exit/halt ---

// Sink is one active run's buffered writer.
type Sink struct {
	mu    sync.Mutex
	db    *sql.DB
	runID int64
	buf   []Record
	count int
	stop  chan struct{} // ends the periodic flusher
}

// current is the process-wide active run, nil when not saving. currentMu
// guards it: a recon package's own goroutine can call store.CurrentSink()
// at any time, including after the pipeline step that started it considers
// itself done (a skipped/abandoned pipeline step keeps running in the
// background -- see pipeline.runStep -- and most recon packages save
// results as they go, not just at the end).
var (
	currentMu sync.Mutex
	current   *Sink
)

// CurrentSink returns the active sink, or nil if nothing is being saved.
// Sink's methods are nil-safe, so `store.CurrentSink().Add(rec)` is always
// a valid call, saving every call site a nil check.
func CurrentSink() *Sink {
	currentMu.Lock()
	defer currentMu.Unlock()
	return current
}

const flushAt = 200

// StartSink opens (or creates) the results database, starts a new run named
// name (command/args recorded for `srt runs`), and makes it the current
// sink. It registers a halt.On hook so Ctrl+C or a traffic-limit halt
// flushes whatever was buffered before the process exits.
func StartSink(name string, args []string) (*Sink, error) {
	db, err := Open(DBPath())
	if err != nil {
		return nil, err
	}
	cwd, _ := os.Getwd()
	res, err := db.Exec(`INSERT INTO runs(name, command, cwd, started_at) VALUES (?,?,?,?)`,
		name, strings.Join(args, " "), cwd, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		db.Close()
		return nil, err
	}
	id, _ := res.LastInsertId()
	s := &Sink{db: db, runID: id, stop: make(chan struct{})}
	currentMu.Lock()
	current = s
	currentMu.Unlock()
	// Flush on a timer too, not only every flushAt records, so another
	// reader (the shell's live-results window) sees results as they come.
	// stopCh is captured once, by value, rather than read as s.stop on
	// every loop iteration -- Close() reassigns s.stop (to nil, under
	// s.mu) once it's done with it, and reading that field directly here
	// would race with that write.
	stopCh := s.stop
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.flush()
			case <-stopCh:
				return
			}
		}
	}()
	halt.On(s.Close) // Ctrl+C / limit halt: flush what we have first
	return s, nil
}

// Add buffers a record; a nil Sink (not saving) is a no-op, so call sites
// never need their own nil check.
func (s *Sink) Add(r Record) {
	if s == nil || r.Key == "" {
		return
	}
	s.mu.Lock()
	s.buf = append(s.buf, r)
	full := len(s.buf) >= flushAt
	s.mu.Unlock()
	if full {
		s.flush()
	}
}

func (s *Sink) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushLocked()
}

func (s *Sink) flushLocked() {
	if len(s.buf) == 0 {
		return
	}
	if s.db == nil {
		// Closed already (see Close()): a recon package's own goroutine --
		// still finishing a real request after its pipeline step was
		// skipped/abandoned -- added these after the fact. Nothing to
		// flush them to any more; drop them rather than panic on a nil DB.
		s.buf = s.buf[:0]
		return
	}
	if err := insertRecords(s.db, s.runID, s.buf); err != nil {
		ioutil.Warn("saving results: %v", err)
	} else {
		s.count += len(s.buf)
	}
	s.buf = s.buf[:0]
}

// Close flushes, stamps the run's end time and closes the database. Nil-safe
// and safe to call more than once (the halt hook and the normal path both
// do).
func (s *Sink) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	if s.stop != nil {
		close(s.stop)
		s.stop = nil
	}
	s.flushLocked()
	s.db.Exec(`UPDATE runs SET ended_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), s.runID)
	s.db.Close()
	s.db = nil
	currentMu.Lock()
	if current == s {
		current = nil
	}
	currentMu.Unlock()
	ioutil.Warn("saved %d record(s) to %s (run %d)", s.count, DBPath(), s.runID)
}

func insertRecords(db *sql.DB, runID int64, recs []Record) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO records(run_id,kind,key,host,port,url,status,length,data,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, r := range recs {
		data := ""
		if len(r.Data) > 0 {
			b, _ := json.Marshal(r.Data)
			data = string(b)
		}
		if _, err := stmt.Exec(runID, r.Kind, r.Key, r.Host, r.Port, r.URL, r.Status, r.Length, data, now); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// --- generic record helpers shared by every recon package ---

// HostPortOf pulls hostname and port out of a URL ("" / 0 if it isn't one).
func HostPortOf(raw string) (string, int) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", 0
	}
	port := 0
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	} else if u.Scheme == "https" {
		port = 443
	} else if u.Scheme == "http" {
		port = 80
	}
	return u.Hostname(), port
}

// TextRecord stores one line of a plain-text result file under kind. Lines
// that are URLs or host:port get their host/port columns filled so they
// stay filterable. Used for every command that isn't one of the few with
// its own richer Record constructor (portscan, fuzz, probe, traceroute).
func TextRecord(kind, line string) Record {
	line = strings.TrimSpace(line)
	rec := Record{Kind: kind, Key: line}
	if strings.Contains(line, "://") {
		rec.URL = line
		rec.Host, rec.Port = HostPortOf(line)
	} else if h, p, ok := splitHostPort(line); ok {
		rec.Host, rec.Port = h, p
	} else if !strings.ContainsAny(line, " \t") {
		rec.Host = line
	}
	return rec
}

func splitHostPort(s string) (string, int, bool) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || strings.ContainsAny(s, " /") {
		return "", 0, false
	}
	p, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0, false
	}
	return s[:i], p, true
}

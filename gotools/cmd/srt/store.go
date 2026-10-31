package main

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

	_ "modernc.org/sqlite" // pure-Go driver: keeps srt a single static binary
)

// Results store. Scan results persist to a SQLite file -- per project, in
// <cwd>/.srt/srt.db, or wherever $SRT_DB / `-db` points -- so they can be
// queried (`srt results`), listed by run (`srt runs`) and exported as a
// directory tree (`srt export`) instead of living only in flat files.
//
// Every record is one row of a deliberately generic table: a kind (port, url,
// probe, subdomain, ...), a natural key, and the common columns most queries
// filter on (host, port, url, status, length), with anything else as JSON in
// `data`. A run groups what one command or pipeline produced; re-running
// never overwrites old runs, so history is kept.

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

type dbRecord struct {
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

// dbPath resolves the database location: $SRT_DB, else ./.srt/srt.db.
func dbPath() string {
	if p := os.Getenv("SRT_DB"); p != "" {
		return p
	}
	return filepath.Join(".srt", "srt.db")
}

func openStore(path string) (*sql.DB, error) {
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

// openStoreReadable opens an existing database for queries, with a friendly
// error (and no stray file created) when there's nothing saved yet.
func openStoreReadable() (*sql.DB, error) {
	p := dbPath()
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("no results database at %s -- run a command with -save (or a pipeline) first, or set SRT_DB", p)
	}
	return openStore(p)
}

// --- run sink: buffered, flushed on exit/halt ---

type runSink struct {
	mu    sync.Mutex
	db    *sql.DB
	runID int64
	buf   []dbRecord
	count int
}

// sink is the process-wide active run, nil when not saving.
var sink *runSink

const sinkFlushAt = 200

func startSink(name string, args []string) (*runSink, error) {
	db, err := openStore(dbPath())
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
	s := &runSink{db: db, runID: id}
	sink = s
	onHalt(s.close) // Ctrl+C / limit halt: flush what we have first
	return s, nil
}

// add buffers a record; a nil sink (not saving) is a no-op, so call sites
// don't need a guard.
func (s *runSink) add(r dbRecord) {
	if s == nil || r.Key == "" {
		return
	}
	s.mu.Lock()
	s.buf = append(s.buf, r)
	full := len(s.buf) >= sinkFlushAt
	s.mu.Unlock()
	if full {
		s.flush()
	}
}

func (s *runSink) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushLocked()
}

func (s *runSink) flushLocked() {
	if len(s.buf) == 0 {
		return
	}
	if err := insertRecords(s.db, s.runID, s.buf); err != nil {
		warn("saving results: %v", err)
	} else {
		s.count += len(s.buf)
	}
	s.buf = s.buf[:0]
}

// close flushes, stamps the run's end time and closes the database. Safe to
// call more than once (the halt hook and the normal path both do).
func (s *runSink) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	s.flushLocked()
	s.db.Exec(`UPDATE runs SET ended_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), s.runID)
	s.db.Close()
	s.db = nil
	warn("saved %d record(s) to %s (run %d)", s.count, dbPath(), s.runID)
}

func insertRecords(db *sql.DB, runID int64, recs []dbRecord) error {
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

// --- record constructors / parsers shared by the commands, pipeline and import ---

// hostPortOf pulls hostname and port out of a URL ("" / 0 if it isn't one).
func hostPortOf(raw string) (string, int) {
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

func portRecord(r scanResult) dbRecord {
	rec := dbRecord{Kind: "port", Key: fmt.Sprintf("%s:%d", r.Host, r.Port), Host: r.Host, Port: r.Port}
	if r.Banner != "" {
		rec.Data = map[string]any{"banner": r.Banner}
	}
	return rec
}

func fuzzRecord(target string, m respMeta) dbRecord {
	h, p := hostPortOf(target)
	return dbRecord{Kind: "url", Key: target, Host: h, Port: p, URL: target, Status: m.status, Length: m.size,
		Data: map[string]any{"words": m.words, "lines": m.lines}}
}

func probeRecord(r probeResult) dbRecord {
	key := r.URL
	if key == "" {
		key = r.Target
	}
	h, p := hostPortOf(key)
	if h == "" {
		h = r.Target
	}
	d := map[string]any{}
	if r.Title != "" {
		d["title"] = r.Title
	}
	if r.Server != "" {
		d["server"] = r.Server
	}
	if len(r.Tech) > 0 {
		d["tech"] = r.Tech
	}
	if r.Err != "" {
		d["error"] = r.Err
	}
	return dbRecord{Kind: "probe", Key: key, Host: h, Port: p, URL: r.URL, Status: r.Status, Length: r.Length, Data: d}
}

// textRecord stores one line of a plain-text result file under kind. Lines
// that are URLs or host:port get their host/port columns filled so they stay
// filterable.
func textRecord(kind, line string) dbRecord {
	line = strings.TrimSpace(line)
	rec := dbRecord{Kind: kind, Key: line}
	if strings.Contains(line, "://") {
		rec.URL = line
		rec.Host, rec.Port = hostPortOf(line)
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

// sniffJSONRecord recognizes the JSON-lines output of portscan, fuzz and
// probe, so `db import` and the pipeline can ingest them without a -kind.
func sniffJSONRecord(line []byte) (dbRecord, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(line, &m) != nil {
		return dbRecord{}, false
	}
	str := func(k string) string {
		var s string
		json.Unmarshal(m[k], &s)
		return s
	}
	num := func(k string) int {
		var n int
		json.Unmarshal(m[k], &n)
		return n
	}
	switch {
	case m["port"] != nil && m["host"] != nil:
		return portRecord(scanResult{Host: str("host"), Port: num("port"), Banner: str("banner")}), true
	case m["url"] != nil && m["status"] != nil && m["length"] != nil && m["target"] == nil:
		return fuzzRecord(str("url"), respMeta{status: num("status"), size: num("length"), words: num("words"), lines: num("lines")}), true
	case m["target"] != nil:
		var p probeResult
		if json.Unmarshal(line, &p) != nil {
			return dbRecord{}, false
		}
		return probeRecord(p), true
	}
	return dbRecord{}, false
}

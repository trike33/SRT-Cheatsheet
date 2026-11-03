// Package fuzzctl is the small file-based channel between a running fuzz
// step and the interactive shell that launched it. They are separate
// processes (the shell runs `srt pipeline` as a child), so:
//
//   - the fuzz engine periodically writes a Status snapshot (per-host
//     workload, wordlists, live hits) to the file named by EnvStatus;
//   - the shell writes a Control file (hosts to stop) at EnvControl, which
//     the engine polls.
//
// Both are plain JSON, written atomically, so either side can read at any
// time without coordination.
package fuzzctl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	EnvStatus  = "SRT_FUZZ_STATUS"  // path the engine writes its Status to
	EnvControl = "SRT_FUZZ_CONTROL" // path the shell writes Control to
)

// Host states shown in the status.
const (
	StateQueued   = "queued"
	StateRunning  = "running"
	StateDone     = "done"
	StateStopped  = "stopped by you"
	StateWAF      = "halted (WAF block)"
	StateCooldown = "cooling down (WAF)"
)

// Host is one host's slice of the fuzz run.
type Host struct {
	Host      string   `json:"host"`
	Target    string   `json:"target"`   // the first base URL template being fuzzed
	State     string   `json:"state"`    // one of the State* values
	Planned   int64    `json:"planned"`  // requests queued so far (grows with recursion)
	Done      int64    `json:"done"`     // requests completed
	Queued    int      `json:"queued"`   // jobs waiting for a worker slot
	InFlight  int      `json:"inFlight"` // requests on the wire right now
	Matches   int64    `json:"matches"`  // hits shown
	Rate      float64  `json:"rate"`     // req/s over the last interval
	Cooldown  int      `json:"cooldownSec,omitempty"`
	Wordlists []string `json:"wordlists"`       // -w files
	Words     int      `json:"words"`           // distinct words across them
	Exts      []string `json:"exts,omitempty"`  // extensions in use (-e plus -ext-auto), once resolved
	Extra     []string `json:"extra,omitempty"` // -words-auto words for this host, once resolved
	Hits      []string `json:"hits,omitempty"`  // newest last
}

// Status is one snapshot of every host this process has fuzzed (finished
// ones from earlier targets included).
type Status struct {
	Updated time.Time `json:"updated"`
	Hosts   []Host    `json:"hosts"`
}

var writeMu sync.Mutex

// WriteStatus replaces the file atomically.
func WriteStatus(path string, s Status) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	s.Updated = time.Now()
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return atomicWrite(path, b)
}

// ReadStatus returns the latest snapshot; ok is false when there is none yet.
func ReadStatus(path string) (Status, bool) {
	var s Status
	if path == "" {
		return s, false
	}
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &s) != nil {
		return s, false
	}
	return s, true
}

// Control is what the shell asks the engine to do.
type Control struct {
	Stop []string `json:"stop"` // hosts to stop fuzzing, cumulative
	Skip int      `json:"skip"` // times the user asked to skip the running pipeline step (a counter)
}

// ReadControl returns the current requests (empty when none).
func ReadControl(path string) Control {
	var c Control
	if path == "" {
		return c
	}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &c)
	}
	return c
}

// AddStop records that host should stop being fuzzed (idempotent).
func AddStop(path, host string) error {
	c := ReadControl(path)
	for _, h := range c.Stop {
		if h == host {
			return nil
		}
	}
	c.Stop = append(c.Stop, host)
	b, _ := json.Marshal(c)
	return atomicWrite(path, b)
}

// RequestSkip asks the running pipeline to abandon its current step.
func RequestSkip(path string) error {
	c := ReadControl(path)
	c.Skip++
	b, _ := json.Marshal(c)
	return atomicWrite(path, b)
}

func atomicWrite(path string, b []byte) error {
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

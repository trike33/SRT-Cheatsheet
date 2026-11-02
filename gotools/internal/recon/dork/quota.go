package dork

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// dailyFreeQuota is the Google Custom Search JSON API's free-tier daily
// limit. Past it, every query is billed -- this package enforces it itself
// by default (DefaultMaxDaily) rather than relying on the operator to
// remember a number, since the cost of forgetting is a surprise bill.
//
// This is a LOCAL safety net, not authoritative: it's tracked in a file on
// this machine, keyed by a fingerprint of the API key, reset on UTC day
// rollover (a conservative approximation of Google's own reset, which is
// not independently documented here -- see commands.md). It does nothing
// to stop a *different* machine, or this one with its state file deleted,
// from using the same key past the real quota. The one authoritative way
// to guarantee no charge is in the Google Cloud Console itself: either
// don't attach a billing account to the project at all (requests just
// start failing with quotaExceeded once the free 100/day is used, which
// this package treats as an ordinary per-query error -- see search.go), or
// set a hard daily quota override there. commands.md says so; this is
// still worth having as a second layer.
const dailyFreeQuota = 100

// DefaultMaxDaily is -max-daily's default: the free tier's own limit, so a
// default run can never bill anything even if the key does have billing
// enabled.
const DefaultMaxDaily = dailyFreeQuota

// quotaFile is where quotaState is persisted. A var so tests don't touch a
// real user's home directory.
var quotaFile = func() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, ".srt", "dork_quota.json")
}()

type quotaState struct {
	Date  string         `json:"date"`  // YYYY-MM-DD, UTC
	Count map[string]int `json:"count"` // API key fingerprint -> queries sent today
}

// keyFingerprint identifies an API key in the quota file without storing it
// in plaintext.
func keyFingerprint(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])[:16]
}

func todayUTC() string { return time.Now().UTC().Format("2006-01-02") }

func loadQuotaState() (quotaState, error) {
	b, err := os.ReadFile(quotaFile)
	if os.IsNotExist(err) {
		return quotaState{Date: todayUTC(), Count: map[string]int{}}, nil
	}
	if err != nil {
		return quotaState{}, err
	}
	var s quotaState
	if err := json.Unmarshal(b, &s); err != nil {
		return quotaState{}, fmt.Errorf("parsing %s: %w", quotaFile, err)
	}
	if s.Date != todayUTC() {
		s = quotaState{Date: todayUTC(), Count: map[string]int{}}
	}
	if s.Count == nil {
		s.Count = map[string]int{}
	}
	return s, nil
}

func saveQuotaState(s quotaState) error {
	if err := os.MkdirAll(filepath.Dir(quotaFile), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := quotaFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, quotaFile)
}

// withQuotaLock serializes read-modify-write access to the quota file
// across concurrent `srt dork`/`srt pipeline -dork` processes (a plain
// read-then-write without this could let two processes both read "50
// used" and both write back "51", silently losing one increment and
// undercounting -- the one direction that must never happen here). A
// crude but portable mutex: an exclusive-create lock file, spin-waited.
func withQuotaLock(fn func() error) error {
	lockPath := quotaFile + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			break
		}
		if !os.IsExist(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("dork: could not acquire the daily-quota lock (%s) -- a stale lock from a crashed run? delete it and retry", lockPath)
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer os.Remove(lockPath)
	return fn()
}

// reserveQuota atomically checks and, if allowed, consumes one query
// against apiKey's daily budget (max). Returns the new used count and
// whether the query is allowed to proceed.
func reserveQuota(apiKey string, max int) (used int, allowed bool, err error) {
	err = withQuotaLock(func() error {
		s, lerr := loadQuotaState()
		if lerr != nil {
			return lerr
		}
		fp := keyFingerprint(apiKey)
		used = s.Count[fp]
		if used >= max {
			allowed = false
			return nil
		}
		used++
		allowed = true
		s.Count[fp] = used
		return saveQuotaState(s)
	})
	return used, allowed, err
}

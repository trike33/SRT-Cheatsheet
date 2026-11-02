package dork

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func withTempQuotaFile(t *testing.T) {
	t.Helper()
	old := quotaFile
	quotaFile = filepath.Join(t.TempDir(), "dork_quota.json")
	t.Cleanup(func() { quotaFile = old })
}

func TestReserveQuotaAllowsUpToMax(t *testing.T) {
	withTempQuotaFile(t)
	for i := 1; i <= 3; i++ {
		used, allowed, err := reserveQuota("key", 3)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed || used != i {
			t.Errorf("call %d: used=%d allowed=%v, want used=%d allowed=true", i, used, allowed, i)
		}
	}
}

func TestReserveQuotaRejectsPastMax(t *testing.T) {
	withTempQuotaFile(t)
	for i := 0; i < 2; i++ {
		if _, allowed, err := reserveQuota("key", 2); err != nil || !allowed {
			t.Fatalf("setup call %d: allowed=%v err=%v", i, allowed, err)
		}
	}
	used, allowed, err := reserveQuota("key", 2)
	if err != nil {
		t.Fatal(err)
	}
	if allowed || used != 2 {
		t.Errorf("used=%d allowed=%v, want used=2 allowed=false (quota already spent)", used, allowed)
	}
}

func TestReserveQuotaPerKeyIndependent(t *testing.T) {
	withTempQuotaFile(t)
	for i := 0; i < 2; i++ {
		reserveQuota("key-a", 2)
	}
	_, allowedA, _ := reserveQuota("key-a", 2)
	_, allowedB, _ := reserveQuota("key-b", 2)
	if allowedA {
		t.Error("key-a should be exhausted")
	}
	if !allowedB {
		t.Error("key-b has its own independent budget and should still be allowed")
	}
}

func TestReserveQuotaResetsOnDateRollover(t *testing.T) {
	withTempQuotaFile(t)
	for i := 0; i < 2; i++ {
		reserveQuota("key", 2)
	}
	if _, allowed, _ := reserveQuota("key", 2); allowed {
		t.Fatal("expected quota exhausted before simulating rollover")
	}

	// Simulate yesterday's state still on disk.
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	s := quotaState{Date: yesterday, Count: map[string]int{keyFingerprint("key"): 2}}
	b, _ := json.Marshal(s)
	if err := os.WriteFile(quotaFile, b, 0o600); err != nil {
		t.Fatal(err)
	}

	used, allowed, err := reserveQuota("key", 2)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed || used != 1 {
		t.Errorf("used=%d allowed=%v, want a fresh budget after the UTC day rolled over", used, allowed)
	}
}

func TestReserveQuotaConcurrentCallsNeverExceedMax(t *testing.T) {
	withTempQuotaFile(t)
	const max = 10
	var wg sync.WaitGroup
	allowedCount := make(chan bool, 30)
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, allowed, err := reserveQuota("key", max)
			if err != nil {
				t.Error(err)
			}
			allowedCount <- allowed
		}()
	}
	wg.Wait()
	close(allowedCount)
	n := 0
	for a := range allowedCount {
		if a {
			n++
		}
	}
	if n != max {
		t.Errorf("allowed %d calls concurrently, want exactly %d (the lock must serialize check+increment)", n, max)
	}
}

func TestKeyFingerprintDoesNotStoreRawKey(t *testing.T) {
	fp := keyFingerprint("super-secret-key")
	if fp == "super-secret-key" || len(fp) == 0 {
		t.Errorf("fingerprint = %q, must not be the raw key", fp)
	}
}

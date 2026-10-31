package fuzz

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func countLines(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		n++
	}
	return n
}

func TestResumeCompactsAndStillLoads(t *testing.T) {
	old := resumeCompactEvery
	resumeCompactEvery = 50
	defer func() { resumeCompactEvery = old }()

	dir := t.TempDir()
	path := filepath.Join(dir, "run.state")

	e := &fuzzEngine{visited: map[string]struct{}{}}
	if err := e.initResume(path); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 500; i++ {
		e.resumeRecord('R', "http://host/target"+string(rune('a'+i%26)))
	}
	e.visitedMu.Lock()
	e.visited["http://host/admin/FUZZ"] = struct{}{}
	e.visitedMu.Unlock()
	e.resumeRecord('D', "http://host/admin/FUZZ")
	e.closeResume()

	lines := countLines(t, path)
	// 500 R-records collapse to 26 distinct targets (i%26 repeats) + 1 D
	// record; without compaction the file would hold 501 lines.
	if lines > 100 {
		t.Errorf("expected compaction to shrink the file well below 501 lines, got %d", lines)
	}

	// A fresh engine loading the compacted file should still know every
	// target is done and still re-seed the discovered directory.
	e2 := &fuzzEngine{visited: map[string]struct{}{}}
	if err := e2.initResume(path); err != nil {
		t.Fatal(err)
	}
	defer e2.closeResume()
	if !e2.resumeSkipTarget("http://host/targeta") {
		t.Error("expected targeta to be marked done after reloading the compacted file")
	}
	if len(e2.resumeDiscovered) != 1 || e2.resumeDiscovered[0] != "http://host/admin/FUZZ" {
		t.Errorf("expected the discovered dir to survive compaction, got %v", e2.resumeDiscovered)
	}
}

func TestResumeRecordKeepsInMemorySetCurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run.state")
	e := &fuzzEngine{visited: map[string]struct{}{}}
	if err := e.initResume(path); err != nil {
		t.Fatal(err)
	}
	defer e.closeResume()

	if e.resumeSkipTarget("http://host/x") {
		t.Fatal("should not be marked done before it's recorded")
	}
	e.resumeRecord('R', "http://host/x")
	if !e.resumeSkipTarget("http://host/x") {
		t.Error("resumeRecord should make the target visible to resumeSkipTarget immediately, not just on reload")
	}
}

func TestCompactionFailureLeavesFileUsable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run.state")
	e := &fuzzEngine{visited: map[string]struct{}{}}
	if err := e.initResume(path); err != nil {
		t.Fatal(err)
	}
	e.resumeRecord('R', "http://host/a")

	// Make the directory read-only so the .compact temp file can't be
	// created; compactResume must fail soft and leave the writer usable.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skip("cannot drop write perms in this environment")
	}
	defer os.Chmod(dir, 0o700)

	e.compactResume()
	e.resumeRecord('R', "http://host/b")
	e.flushResume()

	os.Chmod(dir, 0o700)
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "http://host/a") || !strings.Contains(string(b), "http://host/b") {
		t.Errorf("expected both records to survive a failed compaction attempt:\n%s", b)
	}
}

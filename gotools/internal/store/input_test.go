package store

import (
	"os"
	"testing"
)

func seedRecords(t *testing.T, recs ...Record) {
	t.Helper()
	s, err := StartSink("seed", []string{"seed"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		s.Add(r)
	}
	s.Close()
	current = nil
}

func TestResolveUsesFlagValueEvenOnTerminal(t *testing.T) {
	withTempDB(t)
	ib := &InputFallback{kinds: []string{"domain"}, isTerminal: func() bool { return true }}
	path := t.TempDir() + "/in.txt"
	writeFile(t, path, "example.com\n")
	lines, source, err := ib.Resolve(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if source != "" {
		t.Errorf("source = %q, want \"\" (explicit -l must never touch the db)", source)
	}
	if len(lines) != 1 || lines[0] != "example.com" {
		t.Errorf("lines = %v", lines)
	}
}

func TestResolveUsesPositionalEvenOnTerminal(t *testing.T) {
	withTempDB(t)
	ib := &InputFallback{kinds: []string{"domain"}, isTerminal: func() bool { return true }}
	path := t.TempDir() + "/in.txt"
	writeFile(t, path, "example.com\n")
	lines, source, err := ib.Resolve("", []string{path})
	if err != nil {
		t.Fatal(err)
	}
	if source != "" || len(lines) != 1 || lines[0] != "example.com" {
		t.Errorf("lines=%v source=%q", lines, source)
	}
}

func TestResolveFallsBackToDBOnlyOnInteractiveTerminal(t *testing.T) {
	withTempDB(t)
	seedRecords(t, Record{Kind: "domain", Key: "a.example.com"}, Record{Kind: "subdomain", Key: "b.example.com"})

	// Not a terminal (piped/redirected stdin): must behave like before --
	// no db fallback, even with nothing else given. InputLines("") reads
	// real stdin, which os/exec gives this test process as /dev/null-ish
	// (empty), so lines come back empty rather than touching the db.
	notTTY := &InputFallback{kinds: []string{"domain", "subdomain"}, isTerminal: func() bool { return false }}
	lines, source, err := notTTY.Resolve("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if source != "" {
		t.Errorf("non-terminal stdin must not fall back to the db, got source=%q lines=%v", source, lines)
	}

	// An interactive terminal with nothing else given: falls back to the db.
	tty := &InputFallback{cmd: "test", kinds: []string{"domain", "subdomain"}, isTerminal: func() bool { return true }}
	lines, source, err = tty.Resolve("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if source == "" {
		t.Fatal("expected a db fallback source, got none")
	}
	want := map[string]bool{"a.example.com": true, "b.example.com": true}
	if len(lines) != 2 || !want[lines[0]] || !want[lines[1]] {
		t.Errorf("lines = %v, want a.example.com and b.example.com", lines)
	}
}

func TestResolveFromOverridesDefaultKinds(t *testing.T) {
	withTempDB(t)
	seedRecords(t, Record{Kind: "ip", Key: "10.0.0.1"}, Record{Kind: "domain", Key: "example.com"})

	from := "ip"
	ib := &InputFallback{kinds: []string{"domain"}, from: &from, isTerminal: func() bool { return true }}
	lines, _, err := ib.Resolve("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "10.0.0.1" {
		t.Errorf("lines = %v, want just 10.0.0.1 (-from=ip must override the domain default)", lines)
	}
}

func TestResolveWhereFiltersByStatus(t *testing.T) {
	withTempDB(t)
	seedRecords(t,
		Record{Kind: "probe", Key: "https://a.example.com", Status: 200},
		Record{Kind: "probe", Key: "https://b.example.com", Status: 404},
	)

	where := "status=200"
	ib := &InputFallback{kinds: []string{"probe"}, where: &where, isTerminal: func() bool { return true }}
	lines, _, err := ib.Resolve("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "https://a.example.com" {
		t.Errorf("lines = %v, want only the status=200 record", lines)
	}
}

func TestResolveWhereRejectsNonStatusField(t *testing.T) {
	withTempDB(t)
	where := "host=example.com"
	ib := &InputFallback{kinds: []string{"domain"}, where: &where, isTerminal: func() bool { return true }}
	if _, _, err := ib.Resolve("", nil); err == nil {
		t.Error("expected an error for an unsupported -where field")
	}
}

func TestResolveNoKindsIsNoFallback(t *testing.T) {
	withTempDB(t)
	seedRecords(t, Record{Kind: "domain", Key: "example.com"})
	ib := &InputFallback{isTerminal: func() bool { return true }} // no default kinds, no -from
	lines, source, err := ib.Resolve("", nil)
	if err != nil || source != "" || len(lines) != 0 {
		t.Errorf("lines=%v source=%q err=%v, want nothing (no kinds configured)", lines, source, err)
	}
}

func TestQueryRecordsNoDBIsNotAnError(t *testing.T) {
	withTempDB(t) // points SRT_DB at a path with nothing written yet
	recs, err := QueryRecords([]string{"domain"})
	if err != nil || recs != nil {
		t.Errorf("recs=%v err=%v, want (nil, nil) when there's no db file yet", recs, err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withTempDB(t *testing.T) {
	t.Helper()
	t.Setenv("SRT_DB", filepath.Join(t.TempDir(), "srt.db"))
	current = nil
}

func TestSinkRoundTrip(t *testing.T) {
	withTempDB(t)
	s, err := StartSink("r1", []string{"r1"})
	if err != nil {
		t.Fatal(err)
	}
	s.Add(Record{Kind: "port", Key: "10.0.0.1:22", Host: "10.0.0.1", Port: 22, Data: map[string]any{"banner": "SSH"}})
	s.Add(Record{Kind: "port", Key: "10.0.0.1:22"}) // duplicate key within the run: ignored, not an error
	s.Close()
	current = nil

	db, err := OpenReadable()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM records`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("records = %d, want 1 (duplicate key must be ignored)", n)
	}
	var host string
	var port int
	if err := db.QueryRow(`SELECT host, port FROM records WHERE kind='port'`).Scan(&host, &port); err != nil {
		t.Fatal(err)
	}
	if host != "10.0.0.1" || port != 22 {
		t.Errorf("host=%q port=%d", host, port)
	}
}

func TestSinkNilIsNoop(t *testing.T) {
	var s *Sink
	s.Add(Record{Kind: "x", Key: "y"}) // must not panic
	s.Close()                          // must not panic
}

func TestSinkDropsRecordsWithNoKey(t *testing.T) {
	withTempDB(t)
	s, err := StartSink("r", []string{"r"})
	if err != nil {
		t.Fatal(err)
	}
	s.Add(Record{Kind: "x"}) // empty Key
	s.Close()
	current = nil

	db, _ := OpenReadable()
	defer db.Close()
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM records`).Scan(&n)
	if n != 0 {
		t.Errorf("a keyless record should never be stored, got %d rows", n)
	}
}

func TestOpenReadableWithoutDBGivesFriendlyError(t *testing.T) {
	t.Setenv("SRT_DB", filepath.Join(t.TempDir(), "none", "srt.db"))
	_, err := OpenReadable()
	if err == nil || !strings.Contains(err.Error(), "-save") {
		t.Errorf("err = %v", err)
	}
	if _, statErr := os.Stat(DBPath()); statErr == nil {
		t.Error("reading must not create the database")
	}
}

func TestCurrentSinkTracksStartAndClose(t *testing.T) {
	withTempDB(t)
	if CurrentSink() != nil {
		t.Fatal("no sink should be active yet")
	}
	s, err := StartSink("r", []string{"r"})
	if err != nil {
		t.Fatal(err)
	}
	if CurrentSink() != s {
		t.Error("CurrentSink should return the just-started sink")
	}
	s.Close()
	current = nil
}

func TestHostPortOf(t *testing.T) {
	cases := map[string][2]any{
		"https://a.example:8443/p": {"a.example", 8443},
		"https://a.example/p":      {"a.example", 443},
		"http://a.example/p":       {"a.example", 80},
		"not a url":                {"", 0},
	}
	for in, want := range cases {
		h, p := HostPortOf(in)
		if h != want[0] || p != want[1] {
			t.Errorf("HostPortOf(%q) = %q,%d want %v", in, h, p, want)
		}
	}
}

func TestTextRecordFillsHostAndPort(t *testing.T) {
	if r := TextRecord("gau", "https://a.example:8443/p?q=1"); r.Host != "a.example" || r.Port != 8443 {
		t.Errorf("%+v", r)
	}
	if r := TextRecord("x", "10.0.0.5:22"); r.Host != "10.0.0.5" || r.Port != 22 {
		t.Errorf("%+v", r)
	}
	if r := TextRecord("subdomain", "dev.a.example"); r.Host != "dev.a.example" {
		t.Errorf("%+v", r)
	}
	if r := TextRecord("params", "id  sqli  xss"); r.Host != "" {
		t.Errorf("%+v", r)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withTempDB(t *testing.T) {
	t.Helper()
	t.Setenv("SRT_DB", filepath.Join(t.TempDir(), "srt.db"))
	sink = nil
}

func saveRun(t *testing.T, name string, recs ...dbRecord) int64 {
	t.Helper()
	s, err := startSink(name, []string{name})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		s.add(r)
	}
	id := s.runID
	s.close()
	sink = nil
	return id
}

func queryAll(t *testing.T, f queryFilter) []dbRecord {
	t.Helper()
	db, err := openStoreReadable()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	recs, err := f.query(db)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestSaveAndQuery(t *testing.T) {
	withTempDB(t)
	saveRun(t, "r1",
		portRecord(scanResult{Host: "10.0.0.1", Port: 22, Banner: "SSH-2.0-OpenSSH"}),
		portRecord(scanResult{Host: "10.0.0.1", Port: 80}),
		fuzzRecord("https://a.example/admin", respMeta{status: 200, size: 1234, words: 50, lines: 9}),
		fuzzRecord("https://a.example/old", respMeta{status: 404, size: 10}),
		probeRecord(probeResult{Target: "a.example", URL: "https://a.example", Status: 200, Title: "Home", Tech: []string{"PHP"}}),
		textRecord("subdomain", "dev.a.example"),
	)

	if got := queryAll(t, queryFilter{kinds: []string{"port"}}); len(got) != 2 {
		t.Errorf("ports = %d", len(got))
	}
	if got := queryAll(t, queryFilter{host: "a.example", status: []int{200}}); len(got) != 2 { // url + probe
		t.Errorf("host+status = %+v", got)
	}
	got := queryAll(t, queryFilter{q: "openssh"})
	if len(got) != 1 || got[0].Data["banner"] == nil {
		t.Errorf("data search = %+v", got)
	}
	if got := queryAll(t, queryFilter{port: 443}); len(got) != 3 { // two fuzz urls + the probe, all https
		t.Errorf("port filter = %d, want 3", len(got))
	}
	if got := queryAll(t, queryFilter{limit: 2}); len(got) != 2 {
		t.Errorf("limit = %d", len(got))
	}
}

func TestRunsKeepHistoryAndMergedViewShowsNewest(t *testing.T) {
	withTempDB(t)
	r1 := saveRun(t, "first", fuzzRecord("https://a/x", respMeta{status: 404, size: 5}), textRecord("subdomain", "only-first.a"))
	r2 := saveRun(t, "second", fuzzRecord("https://a/x", respMeta{status: 200, size: 99}))

	merged := queryAll(t, queryFilter{})
	if len(merged) != 2 {
		t.Fatalf("merged view = %+v", merged)
	}
	for _, r := range merged {
		if r.Key == "https://a/x" && r.Status != 200 {
			t.Errorf("merged view must show the newest observation, got status %d", r.Status)
		}
	}
	if got := queryAll(t, queryFilter{history: true}); len(got) != 3 {
		t.Errorf("history = %d, want 3 (old runs are kept)", len(got))
	}
	if got := queryAll(t, queryFilter{run: r1}); len(got) != 2 {
		t.Errorf("run %d = %d", r1, len(got))
	}
	if got := queryAll(t, queryFilter{run: r2, status: []int{200}}); len(got) != 1 {
		t.Errorf("run %d status = %d", r2, len(got))
	}
}

func TestDuplicateKeysInARunAreIgnored(t *testing.T) {
	withTempDB(t)
	saveRun(t, "dup", textRecord("subdomain", "x.a"), textRecord("subdomain", "x.a"))
	if got := queryAll(t, queryFilter{}); len(got) != 1 {
		t.Errorf("got %d, want 1", len(got))
	}
}

func TestSinkNilIsNoop(t *testing.T) {
	var s *runSink
	s.add(dbRecord{Kind: "x", Key: "y"})
	s.close() // must not panic
}

func TestQueryWithoutDBGivesFriendlyError(t *testing.T) {
	t.Setenv("SRT_DB", filepath.Join(t.TempDir(), "none", "srt.db"))
	_, err := openStoreReadable()
	if err == nil || !strings.Contains(err.Error(), "-save") {
		t.Errorf("err = %v", err)
	}
	if _, statErr := os.Stat(dbPath()); statErr == nil {
		t.Error("reading must not create the database")
	}
}

func TestParseStatusSet(t *testing.T) {
	got, err := parseStatusSet("200,301,400-402")
	if err != nil || len(got) != 5 || got[4] != 402 {
		t.Errorf("%v %v", got, err)
	}
	for _, bad := range []string{"x", "5-1", "200-x"} {
		if _, err := parseStatusSet(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestSniffJSONRecord(t *testing.T) {
	cases := map[string]string{
		`{"host":"1.2.3.4","port":80,"banner":"x"}`:                        "port",
		`{"url":"http://a/b","status":200,"length":5,"words":1,"lines":0}`: "url",
		`{"target":"a.example","url":"https://a.example","status":200}`:    "probe",
	}
	for in, want := range cases {
		r, ok := sniffJSONRecord([]byte(in))
		if !ok || r.Kind != want {
			t.Errorf("%s -> %+v ok=%v, want %s", in, r, ok, want)
		}
	}
	if _, ok := sniffJSONRecord([]byte("plain text")); ok {
		t.Error("plain text is not JSON")
	}
}

func TestTextRecordFillsHostAndPort(t *testing.T) {
	if r := textRecord("gau", "https://a.example:8443/p?q=1"); r.Host != "a.example" || r.Port != 8443 {
		t.Errorf("%+v", r)
	}
	if r := textRecord("x", "10.0.0.5:22"); r.Host != "10.0.0.5" || r.Port != 22 {
		t.Errorf("%+v", r)
	}
	if r := textRecord("subdomain", "dev.a.example"); r.Host != "dev.a.example" {
		t.Errorf("%+v", r)
	}
	if r := textRecord("params", "id  sqli  xss"); r.Host != "" {
		t.Errorf("%+v", r)
	}
}

func TestExportTree(t *testing.T) {
	withTempDB(t)
	saveRun(t, "r",
		portRecord(scanResult{Host: "10.0.0.1", Port: 22, Banner: "SSH"}),
		fuzzRecord("https://a.example/admin", respMeta{status: 200, size: 10}),
		fuzzRecord("https://a.example/x", respMeta{status: 301, size: 0}),
		probeRecord(probeResult{Target: "a.example", URL: "https://a.example", Status: 200, Title: "T"}),
		textRecord("subdomain", "dev.a.example"),
	)
	dir := filepath.Join(t.TempDir(), "out")
	if _, err := exportTree(queryAll(t, queryFilter{}), dir, 0); err != nil {
		t.Fatal(err)
	}
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
		return string(b)
	}
	if !strings.Contains(read("10.0.0.1/ports.txt"), "22  SSH") {
		t.Error("ports.txt")
	}
	if strings.TrimSpace(read("a.example/urls-200.txt")) != "https://a.example/admin" {
		t.Error("urls-200.txt")
	}
	if !strings.Contains(read("a.example/urls.txt"), "301  0  https://a.example/x") {
		t.Error("urls.txt")
	}
	if !strings.Contains(read("a.example/probe.txt"), "T") {
		t.Error("probe.txt")
	}
	if strings.TrimSpace(read("dev.a.example/subdomain.txt")) != "dev.a.example" {
		t.Error("subdomain.txt")
	}
	if !strings.Contains(read("hosts.txt"), "dev.a.example") || !strings.Contains(read("by-kind/port.txt"), "10.0.0.1:22") {
		t.Error("hosts/by-kind")
	}
	var sum map[string]any
	if json.Unmarshal([]byte(read("summary.json")), &sum) != nil || sum["total"].(float64) != 5 {
		t.Errorf("summary = %v", sum)
	}
}

func TestExportCSVAndJSON(t *testing.T) {
	withTempDB(t)
	saveRun(t, "r", fuzzRecord("https://a/x", respMeta{status: 200, size: 3}))
	recs := queryAll(t, queryFilter{})
	p := filepath.Join(t.TempDir(), "o.csv")
	if err := exportCSV(recs, p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !bytes.HasPrefix(b, []byte("run,kind,key")) || !strings.Contains(string(b), "https://a/x") {
		t.Errorf("csv = %s", b)
	}
	p = filepath.Join(t.TempDir(), "o.json")
	if err := exportJSON(recs, p); err != nil {
		t.Fatal(err)
	}
	var back []dbRecord
	b, _ = os.ReadFile(p)
	if json.Unmarshal(b, &back) != nil || len(back) != 1 {
		t.Errorf("json = %s", b)
	}
}

func TestDBImport(t *testing.T) {
	withTempDB(t)
	dir := t.TempDir()
	js := filepath.Join(dir, "scan.json")
	os.WriteFile(js, []byte(`{"host":"1.1.1.1","port":53}`+"\n"+`{"host":"1.1.1.1","port":443,"banner":"b"}`+"\n"), 0o644)
	if err := dbImport([]string{js}); err != nil {
		t.Fatal(err)
	}
	sink = nil
	txt := filepath.Join(dir, "subs.txt")
	os.WriteFile(txt, []byte("a.example\nb.example\n"), 0o644)
	if err := dbImport([]string{txt}); err == nil {
		t.Error("plain lines without -kind must error")
	}
	sink = nil
	if err := dbImport([]string{"-kind", "subdomain", txt}); err != nil {
		t.Fatal(err)
	}
	sink = nil
	if n := len(queryAll(t, queryFilter{kinds: []string{"port"}})); n != 2 {
		t.Errorf("ports = %d", n)
	}
	if n := len(queryAll(t, queryFilter{kinds: []string{"subdomain"}})); n != 2 {
		t.Errorf("subdomains = %d", n)
	}
}

func TestFuzzSavesToSink(t *testing.T) {
	withTempDB(t)
	if _, err := startSink("fuzz", []string{"fuzz"}); err != nil {
		t.Fatal(err)
	}
	e := &fuzzEngine{silent: true}
	e.emit("https://a/found", respMeta{status: 200, size: 7})
	sink.close()
	sink = nil
	if got := queryAll(t, queryFilter{kinds: []string{"url"}}); len(got) != 1 || got[0].Length != 7 {
		t.Errorf("%+v", got)
	}
}

func TestSaveShellCommandAndEnv(t *testing.T) {
	m := newTestModel()
	if env := strings.Join(m.childEnv(), "\n"); !strings.Contains(env, envSave+"=1") {
		t.Error("shell saves by default")
	}
	got, _ := typeLine(m, "save off").runLine()
	if env := strings.Join((func() []string { g := got.(shellModel); return g.childEnv() })(), "\n"); strings.Contains(env, envSave+"=1") {
		t.Error("save off should drop SRT_SAVE")
	}
}

func TestApplyGlobalFlagsSaveAndDB(t *testing.T) {
	old := os.Args
	defer func() { os.Args = old; os.Unsetenv(envSave) }()
	t.Setenv(envSave, "")
	t.Setenv("SRT_DB", "")
	os.Args = []string{"srt", "-save", "-db", "/tmp/x.db", "-rate=30", "portscan", "-l", "h"}
	applyGlobalFlags()
	defer gate.set(0)
	if os.Getenv(envSave) != "1" || os.Getenv("SRT_DB") != "/tmp/x.db" {
		t.Errorf("env save=%q db=%q", os.Getenv(envSave), os.Getenv("SRT_DB"))
	}
	if strings.Join(os.Args, " ") != "srt portscan -l h" {
		t.Errorf("args = %v", os.Args)
	}
}

package results

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/fuzz"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/portscan"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/probe"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func withTempDB(t *testing.T) {
	t.Helper()
	t.Setenv("SRT_DB", filepath.Join(t.TempDir(), "srt.db"))
}

func saveRun(t *testing.T, name string, recs ...store.Record) int64 {
	t.Helper()
	s, err := store.StartSink(name, []string{name})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		s.Add(r)
	}
	id := runIDOf(t, s)
	s.Close()
	return id
}

// runIDOf reads back the just-started run's id via the database itself,
// since Sink doesn't export its id directly.
func runIDOf(t *testing.T, _ *store.Sink) int64 {
	t.Helper()
	db, err := store.Open(store.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var id int64
	if err := db.QueryRow(`SELECT MAX(id) FROM runs`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func queryAll(t *testing.T, f queryFilter) []store.Record {
	t.Helper()
	db, err := store.OpenReadable()
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
		portscan.Result{Host: "10.0.0.1", Port: 22, Banner: "SSH-2.0-OpenSSH"}.Record(),
		portscan.Result{Host: "10.0.0.1", Port: 80}.Record(),
		fuzz.Record("https://a.example/admin", fuzz.RespMeta{Status: 200, Size: 1234, Words: 50, Lines: 9}),
		fuzz.Record("https://a.example/old", fuzz.RespMeta{Status: 404, Size: 10}),
		probe.Result{Target: "a.example", URL: "https://a.example", Status: 200, Title: "Home", Tech: []string{"PHP"}}.Record(),
		store.TextRecord("subdomain", "dev.a.example"),
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
	r1 := saveRun(t, "first", fuzz.Record("https://a/x", fuzz.RespMeta{Status: 404, Size: 5}), store.TextRecord("subdomain", "only-first.a"))
	r2 := saveRun(t, "second", fuzz.Record("https://a/x", fuzz.RespMeta{Status: 200, Size: 99}))

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
	saveRun(t, "dup", store.TextRecord("subdomain", "x.a"), store.TextRecord("subdomain", "x.a"))
	if got := queryAll(t, queryFilter{}); len(got) != 1 {
		t.Errorf("got %d, want 1", len(got))
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

func TestExportTree(t *testing.T) {
	withTempDB(t)
	saveRun(t, "r",
		portscan.Result{Host: "10.0.0.1", Port: 22, Banner: "SSH"}.Record(),
		fuzz.Record("https://a.example/admin", fuzz.RespMeta{Status: 200, Size: 10}),
		fuzz.Record("https://a.example/x", fuzz.RespMeta{Status: 301, Size: 0}),
		probe.Result{Target: "a.example", URL: "https://a.example", Status: 200, Title: "T"}.Record(),
		store.TextRecord("subdomain", "dev.a.example"),
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
	saveRun(t, "r", fuzz.Record("https://a/x", fuzz.RespMeta{Status: 200, Size: 3}))
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
	var back []store.Record
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
	txt := filepath.Join(dir, "subs.txt")
	os.WriteFile(txt, []byte("a.example\nb.example\n"), 0o644)
	if err := dbImport([]string{txt}); err == nil {
		t.Error("plain lines without -kind must error")
	}
	if err := dbImport([]string{"-kind", "subdomain", txt}); err != nil {
		t.Fatal(err)
	}
	if n := len(queryAll(t, queryFilter{kinds: []string{"port"}})); n != 2 {
		t.Errorf("ports = %d", n)
	}
	if n := len(queryAll(t, queryFilter{kinds: []string{"subdomain"}})); n != 2 {
		t.Errorf("subdomains = %d", n)
	}
}

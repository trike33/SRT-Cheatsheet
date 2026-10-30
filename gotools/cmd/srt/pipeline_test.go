package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTargetEntryUnmarshalString(t *testing.T) {
	var e targetEntry
	if err := json.Unmarshal([]byte(`"1.2.3.4"`), &e); err != nil {
		t.Fatalf("unmarshal string form: %v", err)
	}
	if e.Target != "1.2.3.4" {
		t.Errorf("Target = %q, want %q", e.Target, "1.2.3.4")
	}
	if e.Wordlist != "" || e.Scope != "" {
		t.Errorf("expected zero-value overrides for a bare-string entry, got %+v", e)
	}
}

func TestTargetEntryUnmarshalObject(t *testing.T) {
	var e targetEntry
	raw := `{"target":"https://example.com","wordlist":"w.txt","scope":"s.json","extensions":[".php",".bak"]}`
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatalf("unmarshal object form: %v", err)
	}
	if e.Target != "https://example.com" || e.Wordlist != "w.txt" || e.Scope != "s.json" {
		t.Errorf("unexpected fields: %+v", e)
	}
	if len(e.Extensions) != 2 || e.Extensions[0] != ".php" {
		t.Errorf("Extensions = %v", e.Extensions)
	}
}

func TestTargetEntryUnmarshalInvalid(t *testing.T) {
	var e targetEntry
	if err := json.Unmarshal([]byte(`42`), &e); err == nil {
		t.Error("expected an error unmarshaling a bare number into targetEntry")
	}
}

func TestPipelineConfigMixedEntries(t *testing.T) {
	raw := `{
		"name": "t",
		"host": ["10.0.0.1", {"target": "10.0.0.2", "ports": "22"}],
		"web": ["example.com", {"target": "https://admin.example.com", "wordlist": "w.txt"}]
	}`
	var cfg pipelineConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if len(cfg.Host) != 2 || len(cfg.Web) != 2 {
		t.Fatalf("got %d host, %d web entries", len(cfg.Host), len(cfg.Web))
	}
	if cfg.Host[0].Target != "10.0.0.1" || cfg.Host[1].Ports != "22" {
		t.Errorf("host entries = %+v", cfg.Host)
	}
	if cfg.Web[1].Wordlist != "w.txt" {
		t.Errorf("web entries = %+v", cfg.Web)
	}
}

func TestLoadPipelineConfigMissingPath(t *testing.T) {
	if _, err := loadPipelineConfig(""); err == nil {
		t.Error("expected an error for an empty -c path")
	}
}

func TestResolveKindsAuto(t *testing.T) {
	cases := []struct {
		name string
		cfg  pipelineConfig
		want []string
	}{
		{"host only", pipelineConfig{Host: []targetEntry{{Target: "1.2.3.4"}}}, []string{"host"}},
		{"web only", pipelineConfig{Web: []targetEntry{{Target: "example.com"}}}, []string{"web"}},
		{"both", pipelineConfig{Host: []targetEntry{{Target: "1.2.3.4"}}, Web: []targetEntry{{Target: "example.com"}}}, []string{"host", "web"}},
	}
	for _, c := range cases {
		got, err := resolveKinds("", &c.cfg)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", c.name, err)
		}
		if !equalStrings(got, c.want) {
			t.Errorf("%s: resolveKinds = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestResolveKindsEmptyConfigErrors(t *testing.T) {
	if _, err := resolveKinds("", &pipelineConfig{}); err == nil {
		t.Error("expected an error when the config has neither host nor web targets")
	}
}

func TestResolveKindsExplicit(t *testing.T) {
	cfg := &pipelineConfig{Host: []targetEntry{{Target: "1.2.3.4"}}, Web: []targetEntry{{Target: "example.com"}}}

	got, err := resolveKinds("host", cfg)
	if err != nil || !equalStrings(got, []string{"host"}) {
		t.Errorf("-kind host: got %v, err %v", got, err)
	}

	got, err = resolveKinds("host,web", cfg)
	if err != nil || !equalStrings(got, []string{"host", "web"}) {
		t.Errorf("-kind host,web: got %v, err %v", got, err)
	}

	if _, err := resolveKinds("bogus", cfg); err == nil {
		t.Error("expected an error for an unknown -kind value")
	}
}

func TestRunStepRecordsOkAndError(t *testing.T) {
	ok := runStep("web", "noop", "t1", "", func() error { return nil })
	if ok.Status != "ok" {
		t.Errorf("Status = %q, want ok", ok.Status)
	}

	failed := runStep("web", "noop", "t1", "", func() error { return errMissing("boom") })
	if failed.Status != "error" || failed.Detail != "boom" {
		t.Errorf("failed = %+v", failed)
	}
}

func TestSkipStep(t *testing.T) {
	s := skipStep("web", "fuzz", "t1", "no wordlist")
	if s.Status != "skipped" || s.Detail != "no wordlist" {
		t.Errorf("skipStep = %+v", s)
	}
}

func TestManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	m := manifest{
		Name:  "engagement",
		Kinds: []string{"host", "web"},
		Steps: []stepResult{
			{Kind: "host", Name: "ipexpand", Status: "ok", Output: "out.txt", Duration: "1ms"},
			{Kind: "web", Name: "fuzz", Target: "example.com", Status: "skipped", Detail: "no wordlist"},
		},
	}
	if err := writeManifest(path, m); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var got manifest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if got.Name != m.Name || len(got.Steps) != 2 {
		t.Errorf("round-tripped manifest = %+v", got)
	}
	if got.Steps[1].Status != "skipped" || got.Steps[1].Detail != "no wordlist" {
		t.Errorf("round-tripped skip step = %+v", got.Steps[1])
	}
}

func TestCaptureStdout(t *testing.T) {
	out, err := captureStdout(func() error {
		println("to stderr, not stdout") // sanity: unrelated to the capture
		_, werr := os.Stdout.WriteString("hello from captured stdout\n")
		return werr
	})
	if err != nil {
		t.Fatalf("captureStdout returned an error: %v", err)
	}
	if out != "hello from captured stdout\n" {
		t.Errorf("captured output = %q", out)
	}
}

func TestBaseURLAndFuzzURL(t *testing.T) {
	if got := baseURL("example.com"); got != "https://example.com" {
		t.Errorf("baseURL(bare domain) = %q", got)
	}
	if got := baseURL("http://example.com/"); got != "http://example.com" {
		t.Errorf("baseURL(trailing slash) = %q", got)
	}
	if got := fuzzURL("example.com"); got != "https://example.com/FUZZ" {
		t.Errorf("fuzzURL = %q", got)
	}
}

func TestSafeName(t *testing.T) {
	if got := safeName("https://a.b.com/x?y=1"); got != "https___a.b.com_x_y_1" {
		t.Errorf("safeName = %q", got)
	}
}

// TestHostStageGroupsByPorts exercises the real runHostStage, including its
// live resolve/portscan steps — kept fast and offline-safe by scanning only
// loopback addresses over a tiny, almost-certainly-closed port range.
func TestHostStageGroupsByPorts(t *testing.T) {
	dir := t.TempDir()
	cfg := &pipelineConfig{
		Host: []targetEntry{
			{Target: "127.0.0.1", Ports: "65530-65531"},
			{Target: "127.0.0.2", Ports: "65532-65533"}, // distinct group
			{Target: "invalid-not-an-ip-or-cidr", Ports: "65530-65531"},
		},
	}
	steps := runHostStage(cfg, dir, true)

	var names []string
	for _, s := range steps {
		names = append(names, s.Name)
		if s.Status == "error" {
			t.Errorf("unexpected error step: %+v", s)
		}
	}
	// One ipexpand+resolve+portscan triple per distinct ports group.
	if countName(names, "ipexpand") != 2 || countName(names, "resolve") != 2 || countName(names, "portscan") != 2 {
		t.Fatalf("steps = %v", names)
	}
}

func TestHostStageSkipsWebHandoffWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	// Port 0 is never a real open port, so webEntries stays empty either way;
	// this just checks the flag plumbing doesn't panic and produces no
	// unexpected error steps when handoff is turned off.
	cfg := &pipelineConfig{Host: []targetEntry{{Target: "127.0.0.1", Ports: "65534"}}}
	steps := runHostStage(cfg, dir, false)
	for _, s := range steps {
		if s.Status == "error" {
			t.Errorf("unexpected error step: %+v", s)
		}
	}
}

// Note: runWebStage itself always makes real HTTP calls (robots, and gau for
// any discovered domain), so it is intentionally not exercised in these unit
// tests. resolveWordlist is the pure decision runWebStage's fuzz step relies
// on to decide whether to skip a target, so that's what's tested here.
func TestResolveWordlist(t *testing.T) {
	opts := pipelineOptions{Wordlist: "default.txt"}

	if got := resolveWordlist(targetEntry{Target: "a"}, opts); got != "default.txt" {
		t.Errorf("no per-target override: got %q, want options default", got)
	}
	if got := resolveWordlist(targetEntry{Target: "a", Wordlist: "custom.txt"}, opts); got != "custom.txt" {
		t.Errorf("per-target override: got %q, want %q", got, "custom.txt")
	}
	if got := resolveWordlist(targetEntry{Target: "a"}, pipelineOptions{}); got != "" {
		t.Errorf("no wordlist anywhere: got %q, want \"\" (skip)", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func countName(names []string, want string) int {
	n := 0
	for _, s := range names {
		if s == want {
			n++
		}
	}
	return n
}

func TestReadScanResults(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/scan.json"
	content := `{"host":"1.2.3.4","port":80}` + "\n" +
		`{"host":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH"}` + "\n" +
		"\n" + // blank line must be skipped, not error
		`not json` + "\n" // malformed line must be skipped, not error
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	results, err := readScanResults(path)
	if err != nil {
		t.Fatalf("readScanResults: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %+v, want 2 entries", results)
	}
	if results[1].Banner != "SSH-2.0-OpenSSH" {
		t.Errorf("results[1].Banner = %q", results[1].Banner)
	}
}

func TestReadScanResultsMissingFile(t *testing.T) {
	// The portscan step itself already records a missing-file error; a
	// classify step reading a file that doesn't exist should get an empty
	// result, not a second error.
	results, err := readScanResults("/no/such/file.json")
	if err != nil || results != nil {
		t.Errorf("readScanResults(missing) = %v, %v, want nil, nil", results, err)
	}
}

func TestDedupTargetEntries(t *testing.T) {
	in := []targetEntry{
		{Target: "http://a"},
		{Target: "http://b"},
		{Target: "http://a"}, // duplicate, should be dropped
	}
	got := dedupTargetEntries(in)
	if len(got) != 2 {
		t.Fatalf("dedupTargetEntries = %+v, want 2 entries", got)
	}
	if got[0].Target != "http://a" || got[1].Target != "http://b" {
		t.Errorf("dedupTargetEntries order/content = %+v", got)
	}
}

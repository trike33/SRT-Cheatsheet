package pipeline

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeKatana prints katana-shaped JSON lines, plus a truncated last line like
// a killed katana can leave.
const fakeKatana = `printf '%s\n' \
'{"request":{"method":"GET","endpoint":"https://a.test"},"response":{"status_code":200,"forms":[{"method":"post","action":"https://a.test/search","parameters":["q","token"]}]}}' \
'{"request":{"method":"GET","endpoint":"https://a.test/about"},"response":{"status_code":200}}' \
'{"request":{"method":"GET","endpoint":"https://a.test/api/v1/users?limit=5"},"response":{"status_code":200}}' \
'{"request":{"meth'
`

func TestKatanaArgsShape(t *testing.T) {
	got := strings.Join(katanaArgs("https://a.test", 0, 0, 0, ""), " ")
	for _, want := range []string{"-u https://a.test", "-d 3", "-ct 3m", "-jc", "-kf all", "-fs fqdn", "-duc", "-silent", "-j", "-fx", "-rl 50", "-c 5"} {
		if !strings.Contains(got, want) {
			t.Errorf("katanaArgs missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "-proxy") {
		t.Errorf("no proxy configured, got %q", got)
	}
	if got := strings.Join(katanaArgs("https://a.test", 5, 20, 2, "http://127.0.0.1:8080"), " "); !strings.Contains(got, "-d 5") || !strings.Contains(got, "-rl 20") || !strings.Contains(got, "-proxy http://127.0.0.1:8080") {
		t.Errorf("overrides not applied: %q", got)
	}
}

func TestParseKatanaSkipsGarbageAndReadsForms(t *testing.T) {
	withFakeBinary(t, "katana", fakeKatana)
	f := filepath.Join(t.TempDir(), "k.jsonl")
	if r := runExternal("web", "katana", "x", "katana", nil, f); r.Status != "ok" {
		t.Fatalf("fake katana step: %+v", r)
	}
	eps, forms := parseKatana(f)
	if !slices.Equal(eps, []string{"https://a.test", "https://a.test/about", "https://a.test/api/v1/users?limit=5"}) {
		t.Errorf("endpoints = %v", eps)
	}
	if len(forms) != 1 || forms[0].Method != "POST" || forms[0].Action != "https://a.test/search" || !slices.Equal(forms[0].Params, []string{"q", "token"}) {
		t.Errorf("forms = %+v", forms)
	}
}

func TestCrawlTargetsEndToEndWithFakeKatana(t *testing.T) {
	withFakeBinary(t, "katana", fakeKatana)
	dir := t.TempDir()
	cfg := &pipelineConfig{Web: []targetEntry{{Target: "https://a.test"}}}
	urls, forms, steps := crawlTargets(cfg, dir, nil)
	if len(steps) != 1 || steps[0].Name != "katana" || steps[0].Status != "ok" {
		t.Fatalf("steps = %+v", steps)
	}
	if !slices.Contains(urls, "https://a.test/api/v1/users?limit=5") || !slices.Contains(urls, "https://a.test/search") {
		t.Errorf("urls = %v (want crawled endpoints plus the form action)", urls)
	}
	if err := writeForms(filepath.Join(dir, "05c_forms.txt"), forms); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "05c_forms.txt"))
	if got := strings.TrimSpace(string(b)); got != "POST https://a.test/search  q,token" {
		t.Errorf("forms file = %q", got)
	}
}

func TestCrawlTargetsCrawlsExtraBasesToo(t *testing.T) {
	withFakeBinary(t, "katana", fakeKatana)
	dir := t.TempDir()
	cfg := &pipelineConfig{Web: []targetEntry{{Target: "https://a.test"}}}
	_, _, steps := crawlTargets(cfg, dir, []string{"https://sub.a.test"})
	if len(steps) != 2 {
		t.Fatalf("steps = %+v, want one for the explicit target and one for the extra base", steps)
	}
	for _, s := range steps {
		if s.Name != "katana" || s.Status != "ok" {
			t.Errorf("step = %+v", s)
		}
	}
	if steps[0].Target == steps[1].Target {
		t.Errorf("both steps crawled %q, want the explicit target and the extra base crawled separately", steps[0].Target)
	}
}

func TestCrawlTargetsOffAndMissingTool(t *testing.T) {
	off := false
	if u, f, s := crawlTargets(&pipelineConfig{Web: []targetEntry{{Target: "a.test"}}, Options: pipelineOptions{Crawl: &off}}, t.TempDir(), nil); u != nil || f != nil || s != nil {
		t.Errorf("options.crawl=false must be a no-op, got %v %v %v", u, f, s)
	}
	t.Setenv("PATH", t.TempDir()) // no katana anywhere
	_, _, steps := crawlTargets(&pipelineConfig{Web: []targetEntry{{Target: "a.test"}}}, t.TempDir(), nil)
	if len(steps) != 1 || steps[0].Status != "skipped" {
		t.Errorf("missing katana must skip cleanly, got %+v", steps)
	}
}

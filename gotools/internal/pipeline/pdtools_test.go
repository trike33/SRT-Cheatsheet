package pipeline

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCdncheckArgsShape(t *testing.T) {
	got := cdncheckArgs("/tmp/ips.txt")
	want := []string{"-i", "/tmp/ips.txt", "-jsonl", "-silent", "-duc"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestTLSXDiscoveryArgsShape(t *testing.T) {
	got := tlsxDiscoveryArgs("https://example.com")
	want := []string{"-u", "https://example.com", "-san", "-cn", "-resp-only", "-silent", "-duc"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestHostStageCDNCheckOffByOption(t *testing.T) {
	port := openListener(t)
	dir := t.TempDir()
	disabled := false
	cfg := &pipelineConfig{
		Host:    []targetEntry{{Target: "127.0.0.1", Ports: strconv.Itoa(port)}},
		Options: pipelineOptions{CDNCheck: &disabled},
	}
	steps := runHostStage(cfg, dir, true, "")
	for _, s := range steps {
		if s.Name == "cdncheck" {
			t.Fatalf("options.cdnCheck=false, expected no cdncheck step, got %+v", s)
		}
	}
}

func TestHostStageCDNCheckOnByDefault(t *testing.T) {
	port := openListener(t)
	dir := t.TempDir()
	cfg := &pipelineConfig{Host: []targetEntry{{Target: "127.0.0.1", Ports: strconv.Itoa(port)}}}
	steps := runHostStage(cfg, dir, true, "")

	var found *stepResult
	for i := range steps {
		if steps[i].Name == "cdncheck" {
			found = &steps[i]
		}
	}
	if found == nil {
		var names []string
		for _, s := range steps {
			names = append(names, s.Name)
		}
		t.Fatalf("cdncheck defaults to on, expected a cdncheck step, got steps: %v", names)
	}
}

// runExternal's hard safety timeout is what protects the pipeline from a
// hung external tool (observed for real with katana in this environment --
// see external.go's doc comment). Exercise it directly against a tiny
// shell script that just sleeps, with a short timeout override, rather
// than waiting out the real 5-minute default.
func TestRunExternalKillsHungProcess(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("no `sleep` binary on this machine")
	}
	old := externalToolTimeout
	externalToolTimeout = 200 * time.Millisecond
	defer func() { externalToolTimeout = old }()

	dir := t.TempDir()
	outFile := filepath.Join(dir, "out.txt")
	start := time.Now()
	sr := runExternal("host", "sleep-test", "x", "sleep", []string{"30"}, outFile)
	elapsed := time.Since(start)

	if sr.Status != "error" {
		t.Errorf("status = %q, want error (killed by the safety timeout)", sr.Status)
	}
	if elapsed > 5*time.Second {
		t.Errorf("runExternal took %s, expected it to be killed within ~%s", elapsed, externalToolTimeout)
	}
}

func TestRunExternalSkipsCleanlyWhenNotInstalled(t *testing.T) {
	dir := t.TempDir()
	sr := runExternal("host", "nope", "x", "definitely-not-a-real-binary-xyz", nil, filepath.Join(dir, "out.txt"))
	if sr.Status != "skipped" {
		t.Errorf("status = %q, want skipped", sr.Status)
	}
}

// TestTLSXWidenDomainsUsesFakeBinary exercises tlsxWidenDomains end to end
// with a tiny fake "tlsx" script on PATH standing in for the real binary --
// hermetic and fast, and deliberately NOT routed through runWebStage
// (which always makes real domains/subdomains/probe/gau network calls, so
// it's intentionally not exercised in this package's unit tests). This
// covers the wiring (does a tlsx hit reach the caller's names list and get
// a step recorded), not tlsx's own behavior, which
// TestTLSXDiscoveryArgsShape already covers.
func TestTLSXWidenDomainsUsesFakeBinary(t *testing.T) {
	withFakeBinary(t, "tlsx", "echo widened-by-tlsx.example.test\n")

	cfg := &pipelineConfig{Web: []targetEntry{{Target: "https://example.com"}}}
	names, steps := tlsxWidenDomains(cfg, t.TempDir())

	if !slices.Contains(names, "widened-by-tlsx.example.test") {
		t.Errorf("names = %v, want the fake tlsx's discovered name", names)
	}
	if len(steps) != 1 || steps[0].Name != "tlsx" {
		t.Errorf("steps = %+v, want one tlsx step", steps)
	}
}

func TestTLSXWidenDomainsOffByOption(t *testing.T) {
	withFakeBinary(t, "tlsx", "echo should-not-appear.example.test\n")

	disabled := false
	cfg := &pipelineConfig{
		Web:     []targetEntry{{Target: "https://example.com"}},
		Options: pipelineOptions{TLSX: &disabled},
	}
	names, steps := tlsxWidenDomains(cfg, t.TempDir())
	if names != nil || steps != nil {
		t.Errorf("options.tlsx=false, expected (nil, nil), got (%v, %v)", names, steps)
	}
}

// withFakeBinary puts a tiny shell script named name on PATH for the
// duration of the test, standing in for a real external tool so tests
// stay hermetic (no dependency on the real tool being installed) and fast
// (no real network/process behavior to wait on).
func withFakeBinary(t *testing.T, name, script string) {
	t.Helper()
	binDir := t.TempDir()
	path := filepath.Join(binDir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)
	t.Cleanup(func() { os.Setenv("PATH", oldPath) })
}

func TestDNSToolArgsShape(t *testing.T) {
	if got := strings.Join(dnsxBruteArgs("a.test", "w.txt"), " "); !strings.Contains(got, "-d a.test") || !strings.Contains(got, "-w w.txt") || !strings.Contains(got, "-silent") {
		t.Errorf("dnsxBruteArgs = %q", got)
	}
	if got := strings.Join(dnsxWildcardArgs("in.txt", "a.test"), " "); !strings.Contains(got, "-l in.txt") || !strings.Contains(got, "-wd a.test") {
		t.Errorf("dnsxWildcardArgs = %q", got)
	}
	if got := strings.Join(alterxArgs("in.txt"), " "); !strings.Contains(got, "-limit") {
		t.Errorf("alterx must cap its output, got %q", got)
	}
}

// fakeDnsxFilter: a brute-force call (-w) answers two names, one a wildcard
// hit; the -wd pass drops it, like the real tool's filtering.
func fakeDnsxFilter() string {
	return `case "$*" in
  *" -wd "*) while [ $# -gt 0 ]; do [ "$1" = "-l" ] && f="$2"; shift; done; grep -v wild "$f" ;;
  *" -w "*) printf 'real.a.test\nwild.a.test\n' ;;
  *) printf 'perm-real.a.test\nwild2.a.test\n' ;;
esac
`
}

func TestDNSDiscoverDomainsBruteForceIsWildcardFiltered(t *testing.T) {
	withFakeBinary(t, "subfinder", "echo passive.a.test\n")
	withFakeBinary(t, "dnsx", fakeDnsxFilter())

	cfg := &pipelineConfig{Options: pipelineOptions{SubdomainsWordlist: "w.txt"}}
	names, steps := dnsDiscoverDomains(cfg, []string{"a.test"}, nil, t.TempDir())

	for _, want := range []string{"passive.a.test", "real.a.test"} {
		if !slices.Contains(names, want) {
			t.Errorf("names = %v, missing %q", names, want)
		}
	}
	if slices.Contains(names, "wild.a.test") {
		t.Errorf("wildcard hit survived the -wd pass: %v", names)
	}
	var got []string
	for _, s := range steps {
		got = append(got, s.Name)
	}
	if want := []string{"subfinder", "dnsx-brute", "dnsx-wildcard"}; !slices.Equal(got, want) {
		t.Errorf("steps = %v, want %v", got, want)
	}
}

func TestDNSDiscoverDomainsPermutationsOptIn(t *testing.T) {
	withFakeBinary(t, "subfinder", "echo passive.a.test\n")
	withFakeBinary(t, "alterx", "echo dev-passive.a.test\n")
	withFakeBinary(t, "dnsx", fakeDnsxFilter())

	// default: no alterx step
	_, steps := dnsDiscoverDomains(&pipelineConfig{}, []string{"a.test"}, nil, t.TempDir())
	for _, s := range steps {
		if s.Name == "alterx" {
			t.Fatalf("permutations must be off by default, got %+v", s)
		}
	}

	on := true
	cfg := &pipelineConfig{Options: pipelineOptions{Permutations: &on}}
	names, steps := dnsDiscoverDomains(cfg, []string{"a.test"}, []string{"seed.a.test", "other.example"}, t.TempDir())
	var got []string
	for _, s := range steps {
		got = append(got, s.Name)
	}
	if want := []string{"subfinder", "alterx", "dnsx-resolve", "dnsx-wildcard"}; !slices.Equal(got, want) {
		t.Errorf("steps = %v, want %v", got, want)
	}
	if !slices.Contains(names, "perm-real.a.test") || slices.Contains(names, "wild2.a.test") {
		t.Errorf("names = %v, want the resolved permutation without the wildcard hit", names)
	}
}

func TestDNSDiscoverDomainsSubfinderOffByOption(t *testing.T) {
	withFakeBinary(t, "subfinder", "echo should-not-appear.a.test\n")
	off := false
	cfg := &pipelineConfig{Options: pipelineOptions{Subfinder: &off}}
	names, steps := dnsDiscoverDomains(cfg, []string{"a.test"}, nil, t.TempDir())
	if len(names) != 0 || len(steps) != 0 {
		t.Errorf("options.subfinder=false: got names %v steps %v", names, steps)
	}
}

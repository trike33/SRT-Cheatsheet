package pipeline

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestUncoverArgsShape(t *testing.T) {
	got := uncoverArgs(`org:"Acme Corp"`, []string{"shodan", "censys"}, 50)
	want := []string{"-q", `org:"Acme Corp"`, "-e", "shodan,censys", "-f", "ip", "-silent", "-duc", "-l", "50"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestUncoverArgsNoLimitOmitsFlag(t *testing.T) {
	got := uncoverArgs("q", []string{"shodan"}, 0)
	if slices.Contains(got, "-l") {
		t.Errorf("got %v, -l must be omitted when limit <= 0", got)
	}
}

func TestUncoverEngineHasKey(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "")
	t.Setenv("FOFA_EMAIL", "")
	t.Setenv("FOFA_KEY", "")
	if uncoverEngineHasKey("shodan") {
		t.Error("shodan should need SHODAN_API_KEY")
	}
	t.Setenv("SHODAN_API_KEY", "k")
	if !uncoverEngineHasKey("shodan") {
		t.Error("shodan should be usable once SHODAN_API_KEY is set")
	}
	if uncoverEngineHasKey("fofa") {
		t.Error("fofa needs both FOFA_EMAIL and FOFA_KEY")
	}
	t.Setenv("FOFA_EMAIL", "e@x.test")
	t.Setenv("FOFA_KEY", "k")
	if !uncoverEngineHasKey("fofa") {
		t.Error("fofa should be usable once both env vars are set")
	}
}

func TestUncoverEngineHasKeyShodanIDBNeedsNoKey(t *testing.T) {
	if !uncoverEngineHasKey("shodan-idb") {
		t.Error("shodan-idb is free and should never need a key")
	}
}

func TestUncoverEngineHasKeyUnknownEngineIsFalse(t *testing.T) {
	if uncoverEngineHasKey("not-a-real-engine") {
		t.Error("an unrecognized engine must not be treated as usable")
	}
}

func TestUncoverUsableEngines(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "k")
	t.Setenv("HUNTER_API_KEY", "")
	usable, missing := uncoverUsableEngines([]string{"shodan", "hunter"})
	if !slices.Equal(usable, []string{"shodan"}) || !slices.Equal(missing, []string{"hunter"}) {
		t.Errorf("usable=%v missing=%v", usable, missing)
	}
}

func TestRunUncoverSeedSkipsWithoutQuery(t *testing.T) {
	cfg := &pipelineConfig{Options: pipelineOptions{}}
	found, steps := runUncoverSeed(cfg, t.TempDir())
	if found != nil {
		t.Errorf("found = %v, want nil", found)
	}
	if len(steps) != 1 || steps[0].Status != "skipped" {
		t.Errorf("steps = %+v", steps)
	}
}

func TestRunUncoverSeedSkipsWithoutAnyKey(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "")
	cfg := &pipelineConfig{Options: pipelineOptions{UncoverQuery: "org:test"}}
	found, steps := runUncoverSeed(cfg, t.TempDir())
	if found != nil {
		t.Errorf("found = %v, want nil", found)
	}
	if len(steps) != 1 || steps[0].Status != "skipped" || !strings.Contains(steps[0].Detail, "shodan") {
		t.Errorf("steps = %+v", steps)
	}
}

// fakeUncover prints two IPs regardless of args, standing in for a real
// `uncover -f ip` call.
const fakeUncover = `printf '%s\n' '198.51.100.1' '198.51.100.2'
`

func TestRunUncoverSeedEndToEndWithFakeBinary(t *testing.T) {
	withFakeBinary(t, "uncover", fakeUncover)
	t.Setenv("SHODAN_API_KEY", "k")
	dir := t.TempDir()
	cfg := &pipelineConfig{Options: pipelineOptions{UncoverQuery: "org:test"}}
	found, steps := runUncoverSeed(cfg, dir)
	if !slices.Equal(found, []string{"198.51.100.1", "198.51.100.2"}) {
		t.Errorf("found = %v", found)
	}
	if len(steps) != 1 || steps[0].Name != "uncover" || steps[0].Status != "ok" {
		t.Errorf("steps = %+v", steps)
	}
}

func TestRunUncoverSeedMissingToolSkipsCleanly(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no uncover anywhere
	t.Setenv("SHODAN_API_KEY", "k")
	cfg := &pipelineConfig{Options: pipelineOptions{UncoverQuery: "org:test"}}
	found, steps := runUncoverSeed(cfg, t.TempDir())
	if found != nil {
		t.Errorf("found = %v, want nil", found)
	}
	if len(steps) != 1 || steps[0].Status != "skipped" {
		t.Errorf("steps = %+v, want a clean skip when the uncover binary isn't installed", steps)
	}
}

func TestHostStageUncoverSeedsIncludedTargets(t *testing.T) {
	withFakeBinary(t, "uncover", fakeUncover)
	t.Setenv("SHODAN_API_KEY", "k")
	enabled := true
	cfg := &pipelineConfig{
		Options: pipelineOptions{Uncover: &enabled, UncoverQuery: "org:test", Ports: strconv.Itoa(openListener(t))},
	}
	steps := runHostStage(cfg, t.TempDir(), true, "")
	var sawUncover, sawIpexpand bool
	var ipexpandDetail string
	for _, s := range steps {
		if s.Name == "uncover" {
			sawUncover = true
		}
		if s.Name == "ipexpand" {
			sawIpexpand = true
			ipexpandDetail = s.Output
		}
	}
	if !sawUncover {
		t.Error("expected an uncover step")
	}
	if !sawIpexpand {
		t.Fatal("expected an ipexpand step even though cfg.Host was empty -- uncover-seeded hosts must still flow through it")
	}
	b, err := os.ReadFile(ipexpandDetail)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{"198.51.100.1", "198.51.100.2"} {
		if !strings.Contains(got, want) {
			t.Errorf("ipexpand output missing uncover-seeded host %q:\n%s", want, got)
		}
	}
}

func TestHostStageUncoverOffDoesNotRunWhenHostEmpty(t *testing.T) {
	cfg := &pipelineConfig{}
	steps := runHostStage(cfg, t.TempDir(), true, "")
	if len(steps) != 0 {
		t.Errorf("steps = %+v, want none (no host targets, uncover off)", steps)
	}
}

func TestSubfinderArgsNoProviderConfig(t *testing.T) {
	got := subfinderArgs("example.com", "")
	if slices.Contains(got, "-pc") {
		t.Errorf("got %v, -pc must be omitted with no provider config", got)
	}
}

func TestSubfinderArgsWithProviderConfig(t *testing.T) {
	got := subfinderArgs("example.com", "/tmp/pc.yaml")
	i := slices.Index(got, "-pc")
	if i == -1 || got[i+1] != "/tmp/pc.yaml" {
		t.Errorf("got %v", got)
	}
}

func TestChaosProviderConfigEmptyKeyIsNoop(t *testing.T) {
	path, err := chaosProviderConfig("", t.TempDir())
	if err != nil || path != "" {
		t.Errorf("path=%q err=%v, want (\"\", nil)", path, err)
	}
}

func TestChaosProviderConfigWritesYAML(t *testing.T) {
	dir := t.TempDir()
	path, err := chaosProviderConfig("my-chaos-key", dir)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "chaos_provider_config.yaml") {
		t.Errorf("path = %q", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, "chaos:") || !strings.Contains(got, `"my-chaos-key"`) {
		t.Errorf("provider config = %q", got)
	}
}

func TestChaosProviderConfigEscapesQuotes(t *testing.T) {
	dir := t.TempDir()
	path, err := chaosProviderConfig(`weird"key`, dir)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `weird\"key`) {
		t.Errorf("provider config = %q, want the embedded quote escaped", b)
	}
}

func TestChaosAPIKeyPrefersConfigOverEnv(t *testing.T) {
	t.Setenv(EnvChaosAPIKey, "env-key")
	if got := chaosAPIKey(pipelineOptions{ChaosAPIKey: "cfg-key"}); got != "cfg-key" {
		t.Errorf("got %q, want cfg-key", got)
	}
}

func TestChaosAPIKeyFallsBackToEnv(t *testing.T) {
	t.Setenv(EnvChaosAPIKey, "env-key")
	if got := chaosAPIKey(pipelineOptions{}); got != "env-key" {
		t.Errorf("got %q, want env-key", got)
	}
}

func TestUncoverOrDefault(t *testing.T) {
	if (pipelineOptions{}).uncoverOrDefault(false) {
		t.Error("unset must fall back to the given default")
	}
	enabled := true
	if !(pipelineOptions{Uncover: &enabled}).uncoverOrDefault(false) {
		t.Error("explicit true must win over the default")
	}
}

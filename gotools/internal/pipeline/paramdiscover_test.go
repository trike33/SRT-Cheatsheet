package pipeline

import (
	"slices"
	"testing"
)

func TestParamDiscoverTargetsCapsToDefault(t *testing.T) {
	var urls []string
	for i := 0; i < 50; i++ {
		urls = append(urls, "http://x.test/"+string(rune('a'+i%26)))
	}
	got := paramDiscoverTargets(&pipelineConfig{}, urls)
	if len(got) != 20 {
		t.Errorf("len = %d, want the default cap of 20", len(got))
	}
	if !slices.Equal(got, urls[:20]) {
		t.Error("expected the first 20, in order")
	}
}

func TestParamDiscoverTargetsRespectsConfiguredMax(t *testing.T) {
	urls := []string{"a", "b", "c", "d", "e"}
	cfg := &pipelineConfig{Options: pipelineOptions{ParamDiscoverMax: 2}}
	got := paramDiscoverTargets(cfg, urls)
	if !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("got %v, want [a b]", got)
	}
}

func TestParamDiscoverTargetsNeverExceedsInput(t *testing.T) {
	urls := []string{"a", "b"}
	got := paramDiscoverTargets(&pipelineConfig{}, urls)
	if !slices.Equal(got, urls) {
		t.Errorf("got %v, want the input unchanged (fewer than the cap)", got)
	}
}

func TestParamDiscoverArgsForDefaults(t *testing.T) {
	args := paramDiscoverArgsFor(&pipelineConfig{}, "/tmp/targets.txt", "/tmp/out.json")
	want := []string{
		"-l", "/tmp/targets.txt", "-o", "/tmp/out.json", "-json", "-top", "500",
		"-timeout", "10s", "-insecure=true",
	}
	if !slices.Equal(args, want) {
		t.Errorf("got %v, want %v", args, want)
	}
}

func TestParamDiscoverArgsForRespectsOverrides(t *testing.T) {
	insecure := false
	cfg := &pipelineConfig{Options: pipelineOptions{
		ParamDiscoverTop: 100,
		Concurrency:      5,
		Insecure:         &insecure,
		Timeout:          "30s",
	}}
	args := paramDiscoverArgsFor(cfg, "/tmp/t.txt", "/tmp/o.json")
	want := []string{
		"-l", "/tmp/t.txt", "-o", "/tmp/o.json", "-json", "-top", "100",
		"-timeout", "30s", "-insecure=false", "-c", "5",
	}
	if !slices.Equal(args, want) {
		t.Errorf("got %v, want %v", args, want)
	}
}

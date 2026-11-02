package pipeline

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestSensitiveArgsForDefaultUnchanged(t *testing.T) {
	cfg := &pipelineConfig{}
	outFile, args := sensitiveArgsFor(cfg, "/tmp/urls.txt", "/tmp/out")

	wantFile := filepath.Join("/tmp/out", "03_sensitive.txt")
	if outFile != wantFile {
		t.Errorf("outFile = %q, want %q", outFile, wantFile)
	}
	want := []string{"-l", "/tmp/urls.txt", "-o", wantFile}
	if !slices.Equal(args, want) {
		t.Errorf("args = %v, want %v (plain extension filtering, unchanged)", args, want)
	}
}

func TestSensitiveArgsForContentScanEnabled(t *testing.T) {
	enabled := true
	cfg := &pipelineConfig{Options: pipelineOptions{ContentScan: &enabled}}
	outFile, args := sensitiveArgsFor(cfg, "/tmp/urls.txt", "/tmp/out")

	wantFile := filepath.Join("/tmp/out", "03_sensitive.json")
	if outFile != wantFile {
		t.Errorf("outFile = %q, want %q (content hits are structured JSON)", outFile, wantFile)
	}
	want := []string{
		"-l", "/tmp/urls.txt", "-o", wantFile, "-content", "-json",
		"-timeout", "15s", "-insecure=true",
	}
	if !slices.Equal(args, want) {
		t.Errorf("args = %v, want %v", args, want)
	}
}

func TestSensitiveArgsForContentScanReusesConcurrency(t *testing.T) {
	enabled := true
	cfg := &pipelineConfig{Options: pipelineOptions{ContentScan: &enabled, Concurrency: 7}}
	_, args := sensitiveArgsFor(cfg, "/tmp/urls.txt", "/tmp/out")

	if !slices.Contains(args, "-c") {
		t.Fatalf("expected -c to be passed through from options.concurrency, got %v", args)
	}
	idx := slices.Index(args, "-c")
	if args[idx+1] != "7" {
		t.Errorf("-c value = %q, want %q", args[idx+1], "7")
	}
}

func TestSensitiveArgsForContentScanRespectsInsecureAndTimeoutOverrides(t *testing.T) {
	enabled, insecure := true, false
	cfg := &pipelineConfig{Options: pipelineOptions{ContentScan: &enabled, Insecure: &insecure, Timeout: "30s"}}
	_, args := sensitiveArgsFor(cfg, "/tmp/urls.txt", "/tmp/out")

	if !slices.Contains(args, "-insecure=false") {
		t.Errorf("expected -insecure=false, got %v", args)
	}
	if !slices.Contains(args, "30s") {
		t.Errorf("expected the 30s timeout override to be passed through, got %v", args)
	}
}

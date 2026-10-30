package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func touch(t *testing.T, dir, name string, age time.Duration) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(-age)
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatal(err)
	}
}

func TestDetectScopeFiles(t *testing.T) {
	d := t.TempDir()
	touch(t, d, "acme-in-scope", time.Hour)
	touch(t, d, "acme-in-scope-v2.txt", time.Minute)
	touch(t, d, "target_assets.json", 2*time.Hour)
	touch(t, d, "target_assets(1).json", time.Minute)
	touch(t, d, "notes.txt", 0)
	if err := os.Mkdir(filepath.Join(d, "x-in-scope"), 0o755); err != nil {
		t.Fatal(err)
	}
	host, web := detectScopeFiles(d)
	if filepath.Base(host) != "acme-in-scope-v2.txt" {
		t.Errorf("host = %q", host)
	}
	if filepath.Base(web) != "target_assets(1).json" {
		t.Errorf("web = %q", web)
	}
}

func TestDetectScopeFilesNone(t *testing.T) {
	host, web := detectScopeFiles(t.TempDir())
	if host != "" || web != "" {
		t.Errorf("got %q %q", host, web)
	}
	if h, w := detectScopeFiles("/nonexistent-dir-xyz"); h != "" || w != "" {
		t.Error("missing dir should yield nothing")
	}
}

func TestDetectScopeFilesVariants(t *testing.T) {
	d := t.TempDir()
	touch(t, d, "Target Assets (2).JSON", 0)
	touch(t, d, "ACME_InScope.TXT", 0)
	host, web := detectScopeFiles(d)
	if host == "" || web == "" {
		t.Errorf("variants not detected: %q %q", host, web)
	}
}

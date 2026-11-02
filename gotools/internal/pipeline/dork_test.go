package pipeline

import (
	"testing"

	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/dork"
)

func TestDorkCredentialsPrefersConfigOverEnv(t *testing.T) {
	t.Setenv(dork.EnvAPIKey, "env-key")
	t.Setenv(dork.EnvCX, "env-cx")
	key, cx := dorkCredentials(pipelineOptions{DorkAPIKey: "cfg-key", DorkCX: "cfg-cx"})
	if key != "cfg-key" || cx != "cfg-cx" {
		t.Errorf("key=%q cx=%q, want config values", key, cx)
	}
}

func TestDorkCredentialsFallsBackToEnv(t *testing.T) {
	t.Setenv(dork.EnvAPIKey, "env-key")
	t.Setenv(dork.EnvCX, "env-cx")
	key, cx := dorkCredentials(pipelineOptions{})
	if key != "env-key" || cx != "env-cx" {
		t.Errorf("key=%q cx=%q, want env fallback", key, cx)
	}
}

func TestDorkCredentialsEmptyWhenNeitherSet(t *testing.T) {
	t.Setenv(dork.EnvAPIKey, "")
	t.Setenv(dork.EnvCX, "")
	key, cx := dorkCredentials(pipelineOptions{})
	if key != "" || cx != "" {
		t.Errorf("key=%q cx=%q, want both empty", key, cx)
	}
}

func TestDorkOrDefault(t *testing.T) {
	if (pipelineOptions{}).dorkOrDefault(false) {
		t.Error("unset must fall back to the given default")
	}
	enabled := true
	if !(pipelineOptions{Dork: &enabled}).dorkOrDefault(false) {
		t.Error("explicit true must win over the default")
	}
}

package pipeline

import (
	"os"
	"path/filepath"
	"strings"
)

// EnvChaosAPIKey is the env var options.chaosAPIKey/-chaos-key falls back
// to, matching dork's SRT_-prefixed env var convention.
const EnvChaosAPIKey = "SRT_CHAOS_API_KEY"

// EnvPDCPAPIKey is ProjectDiscovery's single Cloud Platform key, shared by
// all PD tools (chaos included); used when EnvChaosAPIKey is unset.
const EnvPDCPAPIKey = "PDCP_API_KEY"

// chaosAPIKey resolves options.chaosAPIKey, falling back to EnvChaosAPIKey.
func chaosAPIKey(opts pipelineOptions) string {
	if opts.ChaosAPIKey != "" {
		return opts.ChaosAPIKey
	}
	if k := os.Getenv(EnvChaosAPIKey); k != "" {
		return k
	}
	if k := os.Getenv(EnvPDCPAPIKey); k != "" {
		return k
	}
	return pdcpCredentialsKey()
}

// pdcpCredentialsKey reads the api-key vulnx/pdtm store in
// ~/.pdcp/credentials.yaml (same PDCP key); "" if absent or unparseable.
func pdcpCredentialsKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(home, ".pdcp", "credentials.yaml"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimLeft(strings.TrimSpace(line), "- ")
		if v, ok := strings.CutPrefix(line, "api-key:"); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// chaosProviderConfig writes a subfinder provider-config.yaml containing
// just a "chaos" key, for subfinder's -pc flag to pick up -- gap 11's
// chaos half. subfinder already supports chaos as a passive source once a
// key is in its provider config (verified against a real subfinder
// binary: `subfinder -ls` lists "chaos *", and subfinder/pkg/runner/
// config.go loads a plain "sourceName: [keys...]" YAML map); this writes
// a dedicated file for the run rather than touching the operator's own
// default config (~/.config/subfinder/provider-config.yaml), so a key
// that exists there for OTHER sources is untouched, but it also means
// this invocation of subfinder sees ONLY the chaos key, not whatever else
// that default file might hold -- documented in commands.md/pipeline.md
// rather than attempting to merge the two (subfinder's own config format
// has no stable Go library here to parse/merge against; see ROADMAP.md).
// Returns "" (no -pc passed, subfinder's own default behavior) when key
// is empty.
func chaosProviderConfig(key, outDir string) (string, error) {
	if key == "" {
		return "", nil
	}
	path := filepath.Join(outDir, "chaos_provider_config.yaml")
	// Double-quoted YAML scalar: safe for a key containing ':', '#', etc.
	content := "chaos:\n  - \"" + strings.ReplaceAll(key, `"`, `\"`) + "\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

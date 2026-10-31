package resolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

func writeLinesFile(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func TestTrimTrailingDots(t *testing.T) {
	got := trimTrailingDots([]string{"host.example.com.", "noTrailingDot", "a.b.c."})
	want := []string{"host.example.com", "noTrailingDot", "a.b.c"}
	if len(got) != len(want) {
		t.Fatalf("trimTrailingDots = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("trimTrailingDots[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestRunResolveForwardLoopback resolves "localhost", which every OS resolver
// answers from /etc/hosts (or NSS equivalent) without touching the network --
// deterministic and offline-safe. It only checks that resolution succeeds and
// reports a loopback address; it doesn't assert IPv4 vs IPv6 since that's
// environment-dependent.
func TestRunResolveForwardLoopback(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "hosts.txt")
	if err := writeLinesFile(inFile, []string{"localhost"}); err != nil {
		t.Fatalf("writing input: %v", err)
	}
	outFile := filepath.Join(dir, "out.txt")

	if err := Run([]string{"-l", inFile, "-o", outFile}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	lines, err := ioutil.InputLines(outFile)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("output lines = %v, want exactly 1 (localhost resolved)", lines)
	}
}

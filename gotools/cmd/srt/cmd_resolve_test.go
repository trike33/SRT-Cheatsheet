package main

import "testing"

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
// answers from /etc/hosts (or NSS equivalent) without touching the network —
// deterministic and offline-safe. It only checks that resolution succeeds and
// reports a loopback address; it doesn't assert IPv4 vs IPv6 since that's
// environment-dependent.
func TestRunResolveForwardLoopback(t *testing.T) {
	dir := t.TempDir()
	inFile := dir + "/hosts.txt"
	if err := writeLinesFile(inFile, []string{"localhost"}); err != nil {
		t.Fatalf("writing input: %v", err)
	}
	outFile := dir + "/out.txt"

	if err := runResolve([]string{"-l", inFile, "-o", outFile}); err != nil {
		t.Fatalf("runResolve: %v", err)
	}

	lines, err := inputLines(outFile)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("output lines = %v, want exactly 1 (localhost resolved)", lines)
	}
}

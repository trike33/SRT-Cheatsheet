package cli

import (
	"bytes"
	"flag"
	"strings"
	"testing"
	"time"
)

func TestPrintGroupedUsageOrdersAndLabels(t *testing.T) {
	fs := flag.NewFlagSet("widget", flag.ContinueOnError)
	var buf bytes.Buffer
	fs.SetOutput(&buf)

	fs.String("l", "", "input file")
	fs.Bool("json", false, "emit JSON")
	fs.Int("c", 40, "concurrency")
	fs.Duration("timeout", 5*time.Second, "per-request timeout")

	fs.Usage = func() {
		PrintGroupedUsage(fs, []UsageSection{
			{Title: "INPUT", Names: []string{"l"}},
			{Title: "PERFORMANCE", Names: []string{"c", "timeout"}},
			{Title: "OUTPUT", Names: []string{"json"}},
		})
	}
	fs.Usage()

	out := buf.String()
	for _, want := range []string{
		"INPUT:", "-l string", "input file",
		"PERFORMANCE:", "-c int", "concurrency (default 40)",
		"-timeout duration", "per-request timeout (default 5s)",
		"OUTPUT:", "-json", "emit JSON",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// INPUT must come before PERFORMANCE must come before OUTPUT.
	iIdx := strings.Index(out, "INPUT:")
	pIdx := strings.Index(out, "PERFORMANCE:")
	oIdx := strings.Index(out, "OUTPUT:")
	if !(iIdx < pIdx && pIdx < oIdx) {
		t.Errorf("sections out of order:\n%s", out)
	}
	// A bool flag gets no type annotation.
	if strings.Contains(out, "-json bool") {
		t.Error("bool flags should have no type annotation")
	}
}

func TestPrintGroupedUsageNeverDropsAnUnlistedFlag(t *testing.T) {
	fs := flag.NewFlagSet("widget", flag.ContinueOnError)
	var buf bytes.Buffer
	fs.SetOutput(&buf)

	fs.String("l", "", "input file")
	fs.String("secret", "", "forgotten flag") // not in any section below

	PrintGroupedUsage(fs, []UsageSection{
		{Title: "INPUT", Names: []string{"l"}},
	})

	out := buf.String()
	if !strings.Contains(out, "OTHER:") || !strings.Contains(out, "-secret") {
		t.Errorf("a flag missing from every section must still appear under OTHER:\n%s", out)
	}
}

func TestFlagDescOmitsZeroDefaults(t *testing.T) {
	fs := flag.NewFlagSet("widget", flag.ContinueOnError)
	fs.Bool("x", false, "do x")
	fs.String("y", "", "set y")
	f := fs.Lookup("x")
	if got := flagDesc(f); got != "do x" {
		t.Errorf("flagDesc(false bool) = %q, want no default suffix", got)
	}
	f2 := fs.Lookup("y")
	if got := flagDesc(f2); got != "set y" {
		t.Errorf("flagDesc(empty string) = %q, want no default suffix", got)
	}
}

func TestFlagDescQuotesStringDefaults(t *testing.T) {
	fs := flag.NewFlagSet("widget", flag.ContinueOnError)
	fs.String("mode", "auto", "pick a mode")
	got := flagDesc(fs.Lookup("mode"))
	want := `pick a mode (default "auto")`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

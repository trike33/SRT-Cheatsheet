package resolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testZone() fakeZone {
	return fakeZone{
		// A real CNAME name can't also carry its own A record (RFC 1034 --
		// a CNAME owner has no other RRs at that name), so full.test's A
		// lookup resolves via the CNAME chain to target.test's own address.
		a:     map[string][]string{"target.test": {"10.0.0.1"}},
		cname: map[string]string{"full.test": "target.test"},
		mx:    map[string][]fakeMX{"full.test": {{Pref: 10, Host: "mail1.test"}, {Pref: 20, Host: "mail2.test"}}},
		ns:    map[string][]string{"full.test": {"ns1.test", "ns2.test"}},
		txt:   map[string][]string{"full.test": {"v=spf1 include:_spf.test ~all"}},
	}
}

func TestResolveTypeCNAMEMXNSTXTEndToEnd(t *testing.T) {
	withFakeDNS(t, testZone())
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	writeLinesFile(in, []string{"full.test"})
	out := filepath.Join(dir, "out.txt")

	if err := Run([]string{"-l", in, "-type", "cname,mx,ns,txt", "-o", out}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		"full.test -> 10.0.0.1",
		"full.test CNAME -> target.test",
		"full.test MX -> 10 mail1.test,20 mail2.test",
		"full.test NS -> ns1.test,ns2.test",
		"full.test TXT -> v=spf1 include:_spf.test ~all",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in output:\n%s", want, got)
		}
	}
}

func TestResolveTypeJSONIncludesExtra(t *testing.T) {
	withFakeDNS(t, testZone())
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	writeLinesFile(in, []string{"full.test"})
	out := filepath.Join(dir, "out.txt")

	if err := Run([]string{"-l", in, "-type", "txt", "-json", "-o", out}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	got := string(b)
	if !strings.Contains(got, `"extra":{"TXT":["v=spf1 include:_spf.test ~all"]}`) {
		t.Errorf("json output = %s", got)
	}
}

func TestResolveTypeOnlyRequestedTypesAreLookedUp(t *testing.T) {
	withFakeDNS(t, testZone())
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	writeLinesFile(in, []string{"full.test"})
	out := filepath.Join(dir, "out.txt")

	// Only -type txt requested: MX/NS/CNAME lines must not appear even
	// though the fake zone has records for them.
	if err := Run([]string{"-l", in, "-type", "txt", "-o", out}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	for _, unwanted := range []string{"MX ->", "NS ->", "CNAME ->"} {
		if strings.Contains(string(got), unwanted) {
			t.Errorf("unexpected %q in output (only -type txt was requested):\n%s", unwanted, got)
		}
	}
	if !strings.Contains(string(got), "TXT ->") {
		t.Errorf("missing TXT in output:\n%s", got)
	}
}

func TestResolveTypeNoRecordsForDomainIsSilentlyOmitted(t *testing.T) {
	withFakeDNS(t, fakeZone{a: map[string][]string{"bare.test": {"10.0.0.2"}}})
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	writeLinesFile(in, []string{"bare.test"})
	out := filepath.Join(dir, "out.txt")

	if err := Run([]string{"-l", in, "-type", "mx,txt", "-o", out}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if strings.TrimSpace(string(got)) != "bare.test -> 10.0.0.2" {
		t.Errorf("got %q, want just the A record line (no MX/TXT exist for this domain)", got)
	}
}

func TestResolveTypeRejectsUnknownType(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	writeLinesFile(in, []string{"example.test"})
	if err := Run([]string{"-l", in, "-type", "soa"}); err == nil {
		t.Error("expected an error for -type soa (not supported -- no stdlib primitive)")
	}
}

func TestResolveTypeRejectsWithReverse(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	writeLinesFile(in, []string{"1.2.3.4"})
	if err := Run([]string{"-l", in, "-type", "txt", "-reverse"}); err == nil {
		t.Error("expected an error combining -type with -reverse")
	}
}

func TestIsExtraRecordType(t *testing.T) {
	for _, valid := range []string{"cname", "mx", "ns", "txt"} {
		if !isExtraRecordType(valid) {
			t.Errorf("%q should be valid", valid)
		}
	}
	for _, invalid := range []string{"soa", "a", "aaaa", "ptr", ""} {
		if isExtraRecordType(invalid) {
			t.Errorf("%q should not be valid", invalid)
		}
	}
}

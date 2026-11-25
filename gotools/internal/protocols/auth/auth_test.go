package auth

import (
	"flag"
	"testing"
	"time"
)

func TestBindResolveDefaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := Bind(fs, 445)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	creds, opts := f.Resolve()
	if !creds.Anonymous() {
		t.Errorf("expected Anonymous() true with no flags, got creds=%+v", creds)
	}
	if opts.Port != 445 {
		t.Errorf("Port = %d, want 445 (the default passed to Bind)", opts.Port)
	}
	if opts.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s default", opts.Timeout)
	}
}

func TestBindResolveCreds(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := Bind(fs, 445)
	if err := fs.Parse([]string{"-u", "alice", "-p", "s3cret", "-d", "CORP", "-port", "139"}); err != nil {
		t.Fatal(err)
	}
	creds, opts := f.Resolve()
	if creds.Anonymous() {
		t.Error("Anonymous() true with -u/-p set")
	}
	if creds.User != "alice" || creds.Password != "s3cret" || creds.Domain != "CORP" {
		t.Errorf("creds = %+v, want alice/s3cret/CORP", creds)
	}
	if opts.Port != 139 {
		t.Errorf("Port = %d, want 139 (overridden)", opts.Port)
	}
}

func TestBindHashOnlyIsNotAnonymous(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := Bind(fs, 445)
	if err := fs.Parse([]string{"-H", "aabbccddeeff00112233445566778899"}); err != nil {
		t.Fatal(err)
	}
	creds, _ := f.Resolve()
	if creds.Anonymous() {
		t.Error("Anonymous() true with only -H set; pass-the-hash should count as credentialed")
	}
}

func TestModuleOptsRepeated(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := Bind(fs, 21)
	if err := fs.Parse([]string{"-M", "spider", "-o", "depth=2", "-o", "ext=.txt"}); err != nil {
		t.Fatal(err)
	}
	_, opts := f.Resolve()
	if opts.Module != "spider" {
		t.Errorf("Module = %q, want spider", opts.Module)
	}
	want := map[string]string{"depth": "2", "ext": ".txt"}
	if len(opts.ModOpts) != len(want) {
		t.Fatalf("ModOpts = %v, want %v", opts.ModOpts, want)
	}
	for k, v := range want {
		if opts.ModOpts[k] != v {
			t.Errorf("ModOpts[%q] = %q, want %q", k, opts.ModOpts[k], v)
		}
	}
}

func TestModuleOptMissingEquals(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	Bind(fs, 21)
	if err := fs.Parse([]string{"-o", "no-equals-sign"}); err == nil {
		t.Error("expected an error for -o with no key=val separator")
	}
}

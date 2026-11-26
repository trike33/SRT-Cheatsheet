package protocols

import (
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		line        string
		defaultPort int
		wantHost    string
		wantPort    int
		wantErr     bool
	}{
		{"10.0.0.1", 445, "10.0.0.1", 445, false},
		{"dc01.corp.local", 389, "dc01.corp.local", 389, false},
		{"10.0.0.1:139", 445, "10.0.0.1", 139, false},
		{"[::1]:445", 445, "::1", 445, false},
		{"10.0.0.1:", 445, "10.0.0.1", 445, false},
		{"10.0.0.1:abc", 445, "", 0, true},
		{"", 445, "", 0, true},
		{"  ", 445, "", 0, true},
	}
	for _, c := range cases {
		got, err := ParseTarget(c.line, c.defaultPort)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseTarget(%q): want error, got %+v", c.line, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTarget(%q): unexpected error: %v", c.line, err)
			continue
		}
		if got.Host != c.wantHost || got.Port != c.wantPort {
			t.Errorf("ParseTarget(%q) = %+v, want {%s %d}", c.line, got, c.wantHost, c.wantPort)
		}
	}
}

func TestTargetString(t *testing.T) {
	if s := (Target{Host: "10.0.0.1", Port: 445}).String(); s != "10.0.0.1:445" {
		t.Errorf("Target.String() = %q, want %q", s, "10.0.0.1:445")
	}
}

func TestCredentialString(t *testing.T) {
	cases := []struct {
		c    Credential
		want string
	}{
		{Anonymous, "(anonymous)"},
		{Credential{User: "alice"}, "alice"},
		{Credential{User: "alice", Domain: "CORP"}, `CORP\alice`},
		{Credential{User: "alice", Hash: "aad3b435b51404eeaad3b435b51404ee"}, "alice (pass-the-hash)"},
		{Credential{User: "alice", Kerberos: true}, "alice (kerberos)"},
	}
	for _, c := range cases {
		if got := c.c.String(); got != c.want {
			t.Errorf("Credential.String() = %q, want %q", got, c.want)
		}
	}
	if !Anonymous.IsAnonymous() {
		t.Error("Anonymous.IsAnonymous() = false, want true")
	}
	if (Credential{User: "alice"}).IsAnonymous() {
		t.Error("Credential{User: alice}.IsAnonymous() = true, want false")
	}
}

func TestFindingRecord(t *testing.T) {
	f := Finding{
		Target:   Target{Host: "10.0.0.1", Port: 445},
		Cred:     Credential{User: "alice", Domain: "CORP"},
		Kind:     "share",
		Detail:   "C$ (readable)",
		Severity: High,
	}
	rec := f.Record("smb")
	if rec.Kind != "smb" {
		t.Errorf("rec.Kind = %q, want %q", rec.Kind, "smb")
	}
	if rec.Host != "10.0.0.1" || rec.Port != 445 {
		t.Errorf("rec host/port = %s/%d, want 10.0.0.1/445", rec.Host, rec.Port)
	}
	if rec.Data["detail"] != "C$ (readable)" {
		t.Errorf("rec.Data[detail] = %v, want %q", rec.Data["detail"], "C$ (readable)")
	}
	if rec.Data["severity"] != "high" {
		t.Errorf("rec.Data[severity] = %v, want %q", rec.Data["severity"], "high")
	}
	if rec.Data["cred"] != `CORP\alice` {
		t.Errorf(`rec.Data[cred] = %v, want %q`, rec.Data["cred"], `CORP\alice`)
	}

	anon := Finding{Target: Target{Host: "10.0.0.1", Port: 445}, Kind: "null-session", Detail: "accepted"}
	rec2 := anon.Record("smb")
	if _, ok := rec2.Data["cred"]; ok {
		t.Errorf("anonymous finding's record carries a cred field: %v", rec2.Data)
	}
	if _, ok := rec2.Data["ok"]; ok {
		t.Errorf("a Finding with Accepted left at its zero value (false) carries an ok field: %v", rec2.Data)
	}

	accepted := Finding{Target: Target{Host: "10.0.0.1", Port: 445}, Kind: "login-ok", Detail: "accepted", Accepted: true}
	rec4 := accepted.Record("smb")
	if rec4.Data["ok"] != true {
		t.Errorf("rec4.Data[ok] = %v, want true", rec4.Data["ok"])
	}

	// A Record's Kind is always the protocol ("smb"), same convention as
	// every other recon package (probe.Result.Record uses "probe", not
	// its own status/title) -- an error attempt is still a "smb" record,
	// distinguished by its Data["error"] field and its Key ending in
	// "/error/...".
	errFinding := Finding{Target: Target{Host: "10.0.0.1", Port: 445}, Err: "connection refused"}
	rec3 := errFinding.Record("smb")
	if rec3.Kind != "smb" {
		t.Errorf("rec3.Kind = %q, want %q", rec3.Kind, "smb")
	}
	if rec3.Data["error"] != "connection refused" {
		t.Errorf("rec3.Data[error] = %v, want %q", rec3.Data["error"], "connection refused")
	}
	if !strings.Contains(rec3.Key, "/error/") {
		t.Errorf("rec3.Key = %q, want it to contain %q", rec3.Key, "/error/")
	}
}

func TestCredsAttempts(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	c := BindCreds(fs)
	// -p and -H each pair with -u by POSITION (i-th -p/-H with the i-th
	// -u), not by where they fall on the command line -- so a -u with no
	// -p/-H at its own index (bob, below) gets an empty password, and a
	// trailing -H with no matching -u is a Dangling() case (its own
	// test), not silently attached to the nearest user.
	if err := fs.Parse([]string{"-u", "alice", "-p", "pw1", "-u", "bob", "-d", "CORP"}); err != nil {
		t.Fatal(err)
	}
	attempts := c.Attempts()
	if len(attempts) != 3 {
		t.Fatalf("len(attempts) = %d, want 3 (anonymous + alice + bob)", len(attempts))
	}
	if !attempts[0].IsAnonymous() {
		t.Errorf("attempts[0] = %#v, want anonymous first", attempts[0])
	}
	if attempts[1].User != "alice" || attempts[1].Password != "pw1" || attempts[1].Domain != "CORP" || attempts[1].Hash != "" {
		t.Errorf("attempts[1] = %#v, want alice/pw1/CORP, no hash", attempts[1])
	}
	// -d applies to every credential in the invocation, netexec-style --
	// one domain per command, not per -u. bob has no -p at index 1, so
	// his password is empty (tried with a blank password, not skipped).
	if attempts[2].User != "bob" || attempts[2].Password != "" || attempts[2].Hash != "" || attempts[2].Domain != "CORP" {
		t.Errorf("attempts[2] = %#v, want bob/CORP, no password or hash", attempts[2])
	}
	if !c.HasCreds() {
		t.Error("HasCreds() = false, want true")
	}
}

func TestCredsAttemptsHash(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	c := BindCreds(fs)
	if err := fs.Parse([]string{"-u", "administrator", "-H", "aad3b435b51404eeaad3b435b51404ee:deadbeefdeadbeefdeadbeefdeadbeef"}); err != nil {
		t.Fatal(err)
	}
	attempts := c.Attempts()
	if len(attempts) != 2 {
		t.Fatalf("len(attempts) = %d, want 2 (anonymous + administrator)", len(attempts))
	}
	if attempts[1].User != "administrator" || attempts[1].Password != "" ||
		attempts[1].Hash != "aad3b435b51404eeaad3b435b51404ee:deadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("attempts[1] = %#v, want administrator with the hash, no password", attempts[1])
	}
}

func TestCredsAnonymousOnly(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	c := BindCreds(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	attempts := c.Attempts()
	if len(attempts) != 1 || !attempts[0].IsAnonymous() {
		t.Errorf("attempts = %+v, want exactly [anonymous]", attempts)
	}
	if c.HasCreds() {
		t.Error("HasCreds() = true, want false")
	}
}

func TestCredsDangling(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	c := BindCreds(fs)
	if err := fs.Parse([]string{"-u", "alice", "-p", "pw1", "-p", "pw2"}); err != nil {
		t.Fatal(err)
	}
	c.Attempts()
	extraP, extraH := c.Dangling()
	if extraP != 1 {
		t.Errorf("Dangling() extraPasswords = %d, want 1", extraP)
	}
	if extraH != 0 {
		t.Errorf("Dangling() extraHashes = %d, want 0", extraH)
	}
}

func TestBindConn(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	c := BindConn(fs, 445, 5*time.Second)
	if err := fs.Parse([]string{"-port", "1445", "-timeout", "2s"}); err != nil {
		t.Fatal(err)
	}
	if *c.Port != 1445 {
		t.Errorf("Port = %d, want 1445", *c.Port)
	}
	if *c.Timeout != 2*time.Second {
		t.Errorf("Timeout = %s, want 2s", *c.Timeout)
	}
}

func TestCredentialUserPass(t *testing.T) {
	cases := []struct {
		c    Credential
		want string
	}{
		{Anonymous, ""},
		{Credential{User: "alice", Password: "s3cret"}, "alice:s3cret"},
		{Credential{User: "alice", Password: "s3cret", Domain: "CORP"}, `CORP\alice:s3cret`},
		{Credential{User: "administrator", Hash: "aad3b435b51404eeaad3b435b51404ee"}, "administrator:aad3b435b51404eeaad3b435b51404ee"},
		// Hash wins over Password when both are somehow set (shouldn't
		// normally happen, but Hash is the more specific secret).
		{Credential{User: "a", Password: "pw", Hash: "ha"}, "a:ha"},
	}
	for _, c := range cases {
		if got := c.c.UserPass(); got != c.want {
			t.Errorf("UserPass() = %q, want %q (cred=%+v)", got, c.want, c.c)
		}
	}
}

func TestFindingLine(t *testing.T) {
	cm := colorout.ParseMode("never") // deterministic, uncolored output to assert on
	f := Finding{Target: Target{Host: "10.0.0.5", Port: 445}}

	got := f.Line("smb", cm, SymInfo, "Windows 10.0 Build 17763 x64", false)
	want := "SMB       10.0.0.5          445     10.0.0.5          [*] Windows 10.0 Build 17763 x64"
	if got != want {
		t.Errorf("Line (no hostname, info) =\n  %q\nwant\n  %q", got, want)
	}

	f.Hostname = "DC01"
	got = f.Line("smb", cm, SymSuccess, "CORP\\administrator:Password1", true)
	want = "SMB       10.0.0.5          445     DC01              [+] CORP\\administrator:Password1 (Pwn3d!)"
	if got != want {
		t.Errorf("Line (hostname, success, pwned) =\n  %q\nwant\n  %q", got, want)
	}

	got = f.Line("ldap", cm, SymFailure, "every bind attempt was rejected", false)
	want = "LDAP      10.0.0.5          445     DC01              [-] every bind attempt was rejected"
	if got != want {
		t.Errorf("Line (failure) =\n  %q\nwant\n  %q", got, want)
	}
}

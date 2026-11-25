package smb

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/spnego"

	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
)

var testTarget = protocols.Target{Host: "dc01.corp.local", Port: DefaultPort}

func TestParseHash(t *testing.T) {
	cases := []struct {
		in      string
		wantLen int
		wantErr bool
	}{
		{"aad3b435b51404eeaad3b435b51404ee", 16, false},
		{"aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef", 16, false},
		{"not-hex", 0, true},
		{"deadbeef", 0, true}, // valid hex, wrong length
		{"", 0, true},
	}
	for _, c := range cases {
		got, err := parseHash(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseHash(%q): want error, got %x", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseHash(%q): unexpected error: %v", c.in, err)
			continue
		}
		if len(got) != c.wantLen {
			t.Errorf("parseHash(%q) = %x (len %d), want len %d", c.in, got, len(got), c.wantLen)
		}
	}
}

func TestParseHashTakesNTHalfOfLMNT(t *testing.T) {
	lm := "aad3b435b51404eeaad3b435b51404ee"
	nt := "0123456789abcdef0123456789abcdef"
	got, err := parseHash(lm + ":" + nt)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := parseHash(nt)
	if string(got) != string(want) {
		t.Errorf("parseHash(LM:NT) = %x, want the NT half %x", got, want)
	}
}

// ntlmOf asserts gm is the *spnego.NTLMInitiator buildInitiator should have
// returned for every non-Kerberos case below, failing the test (not just
// returning ok=false) if it's some other gss.Mechanism instead.
func ntlmOf(t *testing.T, gm interface{}) *spnego.NTLMInitiator {
	t.Helper()
	init, ok := gm.(*spnego.NTLMInitiator)
	if !ok {
		t.Fatalf("buildInitiator returned %T, want *spnego.NTLMInitiator", gm)
	}
	return init
}

func TestBuildInitiator(t *testing.T) {
	gm, err := buildInitiator(protocols.Anonymous, testTarget)
	if err != nil {
		t.Fatalf("anonymous: %v", err)
	}
	init := ntlmOf(t, gm)
	if init.User != "" || init.Password != "" {
		t.Errorf("anonymous initiator = %+v, want empty user/password", init)
	}
	if init.AuthMode != spnego.NTLMAuthAnonymous {
		t.Errorf("anonymous initiator.AuthMode = %v, want NTLMAuthAnonymous (a true null session)", init.AuthMode)
	}

	gm, err = buildInitiator(protocols.Credential{User: "alice", Password: "pw", Domain: "CORP"}, testTarget)
	if err != nil {
		t.Fatal(err)
	}
	init = ntlmOf(t, gm)
	if init.User != "alice" || init.Password != "pw" || init.Domain != "CORP" {
		t.Errorf("initiator = %+v, want alice/pw/CORP", init)
	}

	// --local-auth drops the domain even if -d was also given (SAM, not AD),
	// and sets LocalUser so the library authenticates against the SAM.
	gm, err = buildInitiator(protocols.Credential{User: "admin", Password: "pw", Domain: "CORP", LocalAuth: true}, testTarget)
	if err != nil {
		t.Fatal(err)
	}
	init = ntlmOf(t, gm)
	if init.Domain != "" {
		t.Errorf("--local-auth initiator.Domain = %q, want empty", init.Domain)
	}
	if !init.LocalUser {
		t.Error("--local-auth initiator.LocalUser = false, want true")
	}

	gm, err = buildInitiator(protocols.Credential{User: "administrator", Hash: "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"}, testTarget)
	if err != nil {
		t.Fatal(err)
	}
	init = ntlmOf(t, gm)
	if len(init.Hash) != 16 {
		t.Errorf("pass-the-hash initiator.Hash len = %d, want 16", len(init.Hash))
	}

	if _, err := buildInitiator(protocols.Credential{User: "x", Hash: "not-hex"}, testTarget); err == nil {
		t.Error("buildInitiator with a malformed -H: want error, got nil")
	}
}

func TestBuildInitiatorKerberos(t *testing.T) {
	// -k with neither -p nor -H is rejected before ever touching the KDC.
	if _, err := buildInitiator(protocols.Credential{User: "alice", Domain: "CORP.LOCAL", Kerberos: true}, testTarget); err == nil {
		t.Error("-k with no -p/-H: want error, got nil")
	}
	// -k with no -d (no realm to authenticate against) is rejected the same way.
	if _, err := buildInitiator(protocols.Credential{User: "alice", Password: "pw", Kerberos: true}, testTarget); err == nil {
		t.Error("-k with no -d: want error, got nil")
	}

	gm, err := buildInitiator(protocols.Credential{User: "alice", Password: "pw", Domain: "CORP.LOCAL", Kerberos: true}, testTarget)
	if err != nil {
		t.Fatal(err)
	}
	krb, ok := gm.(*spnego.KRB5Initiator)
	if !ok {
		t.Fatalf("buildInitiator(..., Kerberos: true) returned %T, want *spnego.KRB5Initiator", gm)
	}
	if krb.User != "alice" || krb.Password != "pw" || krb.Domain != "CORP.LOCAL" {
		t.Errorf("KRB5Initiator = %+v, want alice/pw/CORP.LOCAL", krb)
	}
	if krb.DCIP != testTarget.Host || krb.Host != testTarget.Host {
		t.Errorf("KRB5Initiator.DCIP/Host = %q/%q, want the target's own host %q (the common case: hitting a DC directly)", krb.DCIP, krb.Host, testTarget.Host)
	}
	if krb.SPN != "cifs/"+testTarget.Host {
		t.Errorf("KRB5Initiator.SPN = %q, want %q", krb.SPN, "cifs/"+testTarget.Host)
	}

	// -H works for Kerberos too (an RC4/NT-hash pass-the-key), unlike srt's
	// ldap package, where gokrb5's keytab API forced -p-only.
	gm, err = buildInitiator(protocols.Credential{User: "alice", Hash: "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef", Domain: "CORP.LOCAL", Kerberos: true}, testTarget)
	if err != nil {
		t.Fatal(err)
	}
	krb = gm.(*spnego.KRB5Initiator)
	if len(krb.Hash) != 16 {
		t.Errorf("Kerberos pass-the-hash initiator.Hash len = %d, want 16", len(krb.Hash))
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	tg := protocols.Target{Host: "127.0.0.1", Port: 1}
	findings, _ := probe(tg, []protocols.Credential{protocols.Anonymous}, 300*time.Millisecond, true)
	if len(findings) != 1 || findings[0].Err == "" {
		t.Fatalf("expected a single connection-error Finding, got %+v", findings)
	}
}

// TestProbeAgainstNonSMBServer exercises the real github.com/jfjallid/go-smb
// NewConnection path against a TCP listener that accepts the connection
// but speaks nothing SMB -- as far as this package can offline-test the
// real wire negotiate without a genuine SMB2 server fixture (building
// one would mean re-implementing SMB2 negotiate/session-setup on the
// server side, which is out of scope for a unit test; see
// docs/ARCHITECTURE.md's note on preferring t.Skip over mocking for a
// capability the environment doesn't have). It only checks that a
// garbage response is reported as a login failure, never a panic or a
// hang past the dial timeout.
func TestProbeAgainstNonSMBServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Write([]byte("not an SMB server\r\n"))
				buf := make([]byte, 512)
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				c.Read(buf)
			}()
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	tg, err := protocols.ParseTarget(host+":"+portStr, DefaultPort)
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := probe(tg, []protocols.Credential{protocols.Anonymous}, 2*time.Second, true)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", findings)
	}
	f := findings[0]
	if f.Kind != KindLoginFailed {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginFailed, f.Detail, f.Err)
	}
	if !strings.Contains(f.Detail, "rejected") {
		t.Errorf("Detail = %q, want it to explain the rejection", f.Detail)
	}
}

func TestIsInterestingFile(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"vault.kdbx", true},
		{"server.pem", true},
		{"id_rsa", true},
		{"id_rsa.pub", true}, // substring match, not just suffix
		{"backup-passwords.xlsx", true},
		{"Unattend.xml", true}, // case-insensitive
		{"web.config", true},
		{".npmrc", true},
		{"readme.txt", false},
		{"invoice.pdf", false},
		{"photo.jpg", false},
	}
	for _, c := range cases {
		if got := isInterestingFile(c.name); got != c.want {
			t.Errorf("isInterestingFile(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestJoinHits(t *testing.T) {
	// Paths here are already backslash-joined, the form gosmb.SharedFile's
	// own FullPath produces (unlike the old go-smb2-backed code, which used
	// io/fs-style forward slashes and converted them in joinHits).
	hits := []shareHit{
		{share: "Users", path: `alice\id_rsa`},
		{share: "IT", path: `scripts\unattend.xml`},
	}
	got := joinHits(hits)
	want := `Users\alice\id_rsa, IT\scripts\unattend.xml`
	if got != want {
		t.Errorf("joinHits = %q, want %q", got, want)
	}
}

func TestShareReportString(t *testing.T) {
	r := shareReport{
		names:  []string{"IPC$", "C$", "Users"},
		access: map[string]string{"IPC$": "IPC", "C$": "no-access", "Users": "readable"},
	}
	got := r.String()
	for _, want := range []string{"3 share(s)", "IPC$ (IPC)", "C$ (no-access)", "Users (readable)"} {
		if !strings.Contains(got, want) {
			t.Errorf("shareReport.String() = %q, want it to contain %q", got, want)
		}
	}

	empty := shareReport{}
	if got := empty.String(); got != "session accepted; no shares enumerated" {
		t.Errorf("empty shareReport.String() = %q", got)
	}

	failed := shareReport{listErr: errors.New("access denied")}
	if got := failed.String(); !strings.Contains(got, "share enumeration failed") {
		t.Errorf("failed shareReport.String() = %q", got)
	}
}

func TestPrintShareTable(t *testing.T) {
	r := shareReport{
		names:  []string{"ADMIN$", "IPC$", "NETLOGON", "Users"},
		access: map[string]string{"ADMIN$": "no-access", "IPC$": "IPC", "NETLOGON": "readable", "Users": "listed, not readable"},
		remark: map[string]string{"ADMIN$": "Remote Admin", "IPC$": "Remote IPC", "NETLOGON": "Logon server share"},
	}
	var buf strings.Builder
	printShareTable(&buf, protocols.Target{Host: "10.0.0.5", Port: DefaultPort}, r, colorout.Never)
	got := buf.String()

	for _, want := range []string{
		"10.0.0.5:445 shares", "Share", "Permissions", "Remark",
		"ADMIN$", "Remote Admin", "IPC$", "READ", "Remote IPC",
		"NETLOGON", "Logon server share", "Users",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("printShareTable output missing %q; got:\n%s", want, got)
		}
	}
	// ADMIN$ and Users (readable but share enumeration denied/not
	// readable) show no permission -- only an actually readable share
	// (or IPC$, whose own RPC bind already proved access) says READ.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ADMIN$") && strings.Contains(line, "READ") {
			t.Errorf("ADMIN$ row shows READ, want blank permission: %q", line)
		}
	}

	var empty strings.Builder
	printShareTable(&empty, protocols.Target{Host: "10.0.0.5", Port: DefaultPort}, shareReport{}, colorout.Never)
	if empty.Len() != 0 {
		t.Errorf("printShareTable with no shares wrote %q, want nothing", empty.String())
	}
}

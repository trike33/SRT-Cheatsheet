package mssql

import (
	"net"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
)

// startGarbageServer starts a loopback listener that accepts
// connections and sends a line of non-TDS garbage, then stays open
// briefly before closing -- enough for the driver's PRELOGIN read to
// fail cleanly rather than hang.
func startGarbageServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Write([]byte("not a TDS server\r\n"))
				buf := make([]byte, 512)
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				c.Read(buf)
			}()
		}
	}()
	return ln
}

func splitAddr(t *testing.T, ln net.Listener) (host, port string) {
	t.Helper()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split %q: %v", ln.Addr().String(), err)
	}
	return host, port
}

func TestBuildUsername(t *testing.T) {
	tg := protocols.Target{Host: "10.0.0.5", Port: DefaultPort}

	if got := buildUsername(protocols.Credential{User: "sa"}, tg); got != "sa" {
		t.Errorf("plain SQL login: buildUsername = %q, want %q", got, "sa")
	}

	cr := protocols.Credential{User: "administrator", Domain: "CORP"}
	if got := buildUsername(cr, tg); got != `CORP\administrator` {
		t.Errorf("domain login: buildUsername = %q, want %q", got, `CORP\administrator`)
	}

	// -local-auth authenticates against the target's own hostname, not
	// the domain, even when -d was also given.
	cr = protocols.Credential{User: "admin", Domain: "CORP", LocalAuth: true}
	if got := buildUsername(cr, tg); got != `10.0.0.5\admin` {
		t.Errorf("local-auth login: buildUsername = %q, want %q", got, `10.0.0.5\admin`)
	}

	if got := buildUsername(protocols.Anonymous, tg); got != "" {
		t.Errorf("anonymous: buildUsername = %q, want empty", got)
	}
}

func TestFirstLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Microsoft SQL Server 2019\n\tDeveloper Edition", "Microsoft SQL Server 2019"},
		{"single line, no newline", "single line, no newline"},
		{"  padded line  \nmore", "padded line"},
		{"", ""},
	}
	for _, c := range cases {
		if got := firstLine(c.in); got != c.want {
			t.Errorf("firstLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	tg := protocols.Target{Host: "127.0.0.1", Port: 1}
	f := probe(tg, []protocols.Credential{protocols.Anonymous}, 300*time.Millisecond)
	if f.Err == "" {
		t.Fatalf("expected a connection error, got Finding %+v", f)
	}
}

// TestProbeAgainstNonTDSServer exercises the real
// github.com/microsoft/go-mssqldb connect path against a TCP listener
// that accepts the connection but speaks nothing TDS -- as far as this
// package can offline-test the real wire PRELOGIN/LOGIN7 exchange
// without a genuine SQL Server fixture (there is no widely available
// open-source TDS *server* implementation to stand one up with, unlike
// FTP/LDAP/SSH; see docs/ARCHITECTURE.md's note on preferring a
// graceful skip over mocking a capability the environment doesn't have).
// It only checks that a garbage response is reported as a login
// rejection, never a panic or a hang past the dial timeout.
func TestProbeAgainstNonTDSServer(t *testing.T) {
	ln := startGarbageServer(t)
	host, portStr := splitAddr(t, ln)
	tg, err := protocols.ParseTarget(host+":"+portStr, DefaultPort)
	if err != nil {
		t.Fatal(err)
	}
	creds := []protocols.Credential{{User: "sa", Password: "wrong"}}
	f := probe(tg, creds, 2*time.Second)
	if f.Kind != KindLoginFailed {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginFailed, f.Detail, f.Err)
	}
}

func TestProbeSkipsHashAndKerberosAttempts(t *testing.T) {
	// Neither is supported here (see probe's doc comment); both must be
	// skipped without ever dialing, falling straight through to
	// login-failed with no attempts actually made.
	ln := startGarbageServer(t)
	host, portStr := splitAddr(t, ln)
	tg, err := protocols.ParseTarget(host+":"+portStr, DefaultPort)
	if err != nil {
		t.Fatal(err)
	}
	creds := []protocols.Credential{
		{User: "administrator", Hash: "aad3b435b51404eeaad3b435b51404ee"},
		{User: "administrator", Kerberos: true, Domain: "CORP", Password: "pw"},
	}
	f := probe(tg, creds, 2*time.Second)
	if f.Kind != KindLoginFailed {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginFailed, f.Detail, f.Err)
	}
	if f.Detail != "every login attempt was rejected" {
		t.Errorf("Detail = %q, want the no-attempts-made message (both credentials should have been skipped)", f.Detail)
	}
}

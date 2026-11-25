package smb

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
)

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

func TestBuildInitiator(t *testing.T) {
	init, err := buildInitiator(protocols.Anonymous)
	if err != nil {
		t.Fatalf("anonymous: %v", err)
	}
	if init.User != "" || init.Password != "" {
		t.Errorf("anonymous initiator = %+v, want empty user/password", init)
	}

	init, err = buildInitiator(protocols.Credential{User: "alice", Password: "pw", Domain: "CORP"})
	if err != nil {
		t.Fatal(err)
	}
	if init.User != "alice" || init.Password != "pw" || init.Domain != "CORP" {
		t.Errorf("initiator = %+v, want alice/pw/CORP", init)
	}

	// --local-auth drops the domain even if -d was also given (SAM, not AD).
	init, err = buildInitiator(protocols.Credential{User: "admin", Password: "pw", Domain: "CORP", LocalAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	if init.Domain != "" {
		t.Errorf("--local-auth initiator.Domain = %q, want empty", init.Domain)
	}

	init, err = buildInitiator(protocols.Credential{User: "administrator", Hash: "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if len(init.Hash) != 16 {
		t.Errorf("pass-the-hash initiator.Hash len = %d, want 16", len(init.Hash))
	}

	if _, err := buildInitiator(protocols.Credential{User: "x", Hash: "not-hex"}); err == nil {
		t.Error("buildInitiator with a malformed -H: want error, got nil")
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	tg := protocols.Target{Host: "127.0.0.1", Port: 1}
	f := probe(tg, []protocols.Credential{protocols.Anonymous}, 300*time.Millisecond)
	if f.Err == "" {
		t.Fatalf("expected a connection error, got Finding %+v", f)
	}
}

// TestProbeAgainstNonSMBServer exercises the real github.com/hirochachacha/go-smb2
// Dial path against a TCP listener that accepts the connection but
// speaks nothing SMB -- as far as this package can offline-test the
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
	f := probe(tg, []protocols.Credential{protocols.Anonymous}, 2*time.Second)
	if f.Kind != KindLoginFailed {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginFailed, f.Detail, f.Err)
	}
	if !strings.Contains(f.Detail, "rejected") {
		t.Errorf("Detail = %q, want it to explain the rejection", f.Detail)
	}
}

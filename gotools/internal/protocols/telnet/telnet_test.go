package telnet

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
)

// fakeServer starts a loopback TCP listener that runs handle for each
// connection, and returns its address. The listener and every accepted
// connection are closed when the test ends.
func fakeServer(t *testing.T, handle func(net.Conn)) string {
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
			go handle(c)
		}
	}()
	return ln.Addr().String()
}

func target(t *testing.T, addr string) protocols.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	tg, err := protocols.ParseTarget(host+":"+portStr, 23)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	return tg
}

func TestProbeLoginPrompt(t *testing.T) {
	addr := fakeServer(t, func(c net.Conn) {
		defer c.Close()
		c.Write([]byte("Ubuntu 22.04 LTS\r\nlogin: "))
		time.Sleep(50 * time.Millisecond)
	})
	fs := probe(target(t, addr), []protocols.Credential{protocols.Anonymous}, 2*time.Second)
	if len(fs) != 1 {
		t.Fatalf("len(fs) = %d, want 1 (banner only), got %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Kind != KindBanner {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindBanner, f.Detail, f.Err)
	}
	if !strings.Contains(f.Detail, "login:") {
		t.Errorf("Detail = %q, want it to contain the login prompt", f.Detail)
	}
}

func TestProbeNoAuthShell(t *testing.T) {
	addr := fakeServer(t, func(c net.Conn) {
		defer c.Close()
		// No login at all: straight to a root shell prompt.
		c.Write([]byte("# "))
		time.Sleep(50 * time.Millisecond)
	})
	fs := probe(target(t, addr), []protocols.Credential{protocols.Anonymous}, 2*time.Second)
	if len(fs) != 2 {
		t.Fatalf("len(fs) = %d, want 2 (banner + no-auth), got %+v", len(fs), fs)
	}
	f := fs[1]
	if f.Kind != KindNoAuth {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindNoAuth, f.Detail, f.Err)
	}
	if f.Severity != protocols.High {
		t.Errorf("Severity = %q, want %q", f.Severity, protocols.High)
	}
}

func TestProbeLoginSuccess(t *testing.T) {
	addr := fakeServer(t, func(c net.Conn) {
		defer c.Close()
		br := bufio.NewReader(c)
		c.Write([]byte("login: "))
		user, _ := br.ReadString('\n')
		if strings.TrimSpace(user) != "admin" {
			c.Write([]byte("login incorrect\r\nlogin: "))
			return
		}
		c.Write([]byte("Password: "))
		pass, _ := br.ReadString('\n')
		if strings.TrimSpace(pass) == "hunter2" {
			c.Write([]byte("Last login...\r\n$ "))
		} else {
			c.Write([]byte("Login incorrect\r\nlogin: "))
		}
	})
	creds := []protocols.Credential{protocols.Anonymous, {User: "admin", Password: "hunter2"}}
	fs := probe(target(t, addr), creds, 2*time.Second)
	f := fs[len(fs)-1]
	if f.Kind != KindLoginOK {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginOK, f.Detail, f.Err)
	}
	if f.Cred.User != "admin" {
		t.Errorf("Cred.User = %q, want %q", f.Cred.User, "admin")
	}
}

func TestProbeLoginFailed(t *testing.T) {
	addr := fakeServer(t, func(c net.Conn) {
		defer c.Close()
		br := bufio.NewReader(c)
		c.Write([]byte("login: "))
		br.ReadString('\n')
		c.Write([]byte("Password: "))
		br.ReadString('\n')
		c.Write([]byte("Login incorrect\r\nlogin: "))
	})
	creds := []protocols.Credential{protocols.Anonymous, {User: "admin", Password: "wrong"}}
	fs := probe(target(t, addr), creds, 2*time.Second)
	f := fs[len(fs)-1]
	if f.Kind != KindLoginFailed {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginFailed, f.Detail, f.Err)
	}
	if f.Severity != protocols.Low {
		t.Errorf("Severity = %q, want %q", f.Severity, protocols.Low)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	// Nothing listening on this port.
	tg := protocols.Target{Host: "127.0.0.1", Port: 1}
	fs := probe(tg, []protocols.Credential{protocols.Anonymous}, 300*time.Millisecond)
	if len(fs) != 1 || fs[0].Err == "" {
		t.Fatalf("expected a single Finding with a connection error, got %+v", fs)
	}
}

func TestClassifyPrompt(t *testing.T) {
	cases := []struct {
		banner string
		want   promptKind
	}{
		{"Ubuntu 22.04\r\nlogin: ", promptLogin},
		{"Username: ", promptLogin},
		{"root@host:~# ", promptShell},
		{"user@host:~$ ", promptShell},
		{"C:\\> ", promptShell},
		{"", promptNone},
		{"some random banner with no prompt", promptNone},
	}
	for _, c := range cases {
		if got := classifyPrompt(c.banner); got != c.want {
			t.Errorf("classifyPrompt(%q) = %v, want %v", c.banner, got, c.want)
		}
	}
}

func TestStripIACAnswersNegotiation(t *testing.T) {
	addr := fakeServer(t, func(c net.Conn) {
		defer c.Close()
		// IAC DO ECHO, IAC WILL SUPPRESS-GO-AHEAD, then plain text.
		c.Write([]byte{iac, do, 1, iac, will, 3})
		c.Write([]byte("login: "))
		buf := make([]byte, 64)
		c.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _ := c.Read(buf) // expect our DONT/WONT replies
		if n > 0 {
			got := buf[:n]
			want := []byte{iac, dont, 1, iac, wont, 3}
			if string(got) != string(want) {
				t.Errorf("negotiation reply = %v, want %v", got, want)
			}
		}
	})
	fs := probe(target(t, addr), []protocols.Credential{protocols.Anonymous}, 2*time.Second)
	if len(fs) != 1 || fs[0].Kind != KindBanner || !strings.Contains(fs[0].Detail, "login:") {
		t.Errorf("Findings = %+v, want a single banner finding containing the login prompt with IAC bytes stripped", fs)
	}
}

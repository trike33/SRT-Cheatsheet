package ftp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
)

// fakeFTPServer starts a minimal, loopback-only FTP server that
// understands exactly the command sequence github.com/jlaffaye/ftp's
// Dial+Login+NameList sends: USER/PASS, FEAT (reports none, so no
// OPTS follows), TYPE, EPSV (always, the library's first choice) +
// NLST over the resulting data connection, and QUIT. loginOK decides
// whether a USER/PASS pair succeeds; entries is what NLST returns on a
// successful login.
func fakeFTPServer(t *testing.T, loginOK func(user, pass string) bool, entries []string) string {
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
			go handleFTPConn(t, c, loginOK, entries)
		}
	}()
	return ln.Addr().String()
}

func handleFTPConn(t *testing.T, c net.Conn, loginOK func(string, string) bool, entries []string) {
	defer c.Close()
	dataConnCh := make(chan net.Conn, 1)

	br := bufio.NewReader(c)
	fmt.Fprint(c, "220 fake ftpd ready\r\n")
	var user string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "USER "):
			user = line[5:]
			fmt.Fprint(c, "331 need password\r\n")
		case strings.HasPrefix(upper, "PASS "):
			pass := line[5:]
			if loginOK(user, pass) {
				fmt.Fprint(c, "230 logged in\r\n")
			} else {
				fmt.Fprint(c, "530 login incorrect\r\n")
			}
		case upper == "FEAT":
			fmt.Fprint(c, "500 no features\r\n")
		case strings.HasPrefix(upper, "TYPE"):
			fmt.Fprint(c, "200 type set\r\n")
		case upper == "EPSV":
			dataLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				fmt.Fprint(c, "425 can't open data connection\r\n")
				continue
			}
			_, portStr, _ := net.SplitHostPort(dataLn.Addr().String())
			fmt.Fprintf(c, "229 Entering Extended Passive Mode (|||%s|)\r\n", portStr)
			go func() {
				dc, err := dataLn.Accept()
				dataLn.Close()
				if err != nil {
					return
				}
				dataConnCh <- dc
			}()
		case strings.HasPrefix(upper, "NLST"):
			select {
			case dc := <-dataConnCh:
				fmt.Fprint(c, "150 here comes the listing\r\n")
				for _, e := range entries {
					fmt.Fprintf(dc, "%s\r\n", e)
				}
				dc.Close()
				fmt.Fprint(c, "226 transfer complete\r\n")
			case <-time.After(2 * time.Second):
				fmt.Fprint(c, "425 no data connection\r\n")
			}
		case upper == "QUIT":
			return
		default:
			fmt.Fprint(c, "500 unknown command\r\n")
		}
	}
}

func target(t *testing.T, addr string) protocols.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	tg, err := protocols.ParseTarget(host+":"+portStr, DefaultPort)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	return tg
}

func TestProbeAnonymousLoginWithListing(t *testing.T) {
	addr := fakeFTPServer(t, func(user, pass string) bool {
		return user == "anonymous"
	}, []string{"readme.txt", "pub", "incoming"})

	f := probe(target(t, addr), []protocols.Credential{protocols.Anonymous}, 3*time.Second)
	if f.Err != "" {
		t.Fatalf("unexpected error: %s", f.Err)
	}
	if f.Kind != KindAnonymousLogin {
		t.Fatalf("Kind = %q, want %q (detail=%q)", f.Kind, KindAnonymousLogin, f.Detail)
	}
	if f.Severity != protocols.High {
		t.Errorf("Severity = %q, want %q", f.Severity, protocols.High)
	}
	for _, name := range []string{"readme.txt", "pub", "incoming"} {
		if !strings.Contains(f.Detail, name) {
			t.Errorf("Detail = %q, want it to mention %q", f.Detail, name)
		}
	}
}

func TestProbeAnonymousRejectedThenCredsAccepted(t *testing.T) {
	addr := fakeFTPServer(t, func(user, pass string) bool {
		return user == "alice" && pass == "s3cret"
	}, []string{"home"})

	creds := []protocols.Credential{protocols.Anonymous, {User: "alice", Password: "s3cret"}}
	f := probe(target(t, addr), creds, 3*time.Second)
	if f.Kind != KindLoginOK {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginOK, f.Detail, f.Err)
	}
	if f.Cred.User != "alice" {
		t.Errorf("Cred.User = %q, want %q", f.Cred.User, "alice")
	}
}

func TestProbeEveryLoginRejected(t *testing.T) {
	addr := fakeFTPServer(t, func(user, pass string) bool { return false }, nil)

	creds := []protocols.Credential{protocols.Anonymous, {User: "alice", Password: "wrong"}}
	f := probe(target(t, addr), creds, 3*time.Second)
	if f.Kind != KindLoginFailed {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginFailed, f.Detail, f.Err)
	}
	if f.Severity != protocols.Info {
		t.Errorf("Severity = %q, want %q", f.Severity, protocols.Info)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	tg := protocols.Target{Host: "127.0.0.1", Port: 1}
	f := probe(tg, []protocols.Credential{protocols.Anonymous}, 300*time.Millisecond)
	if f.Err == "" {
		t.Fatalf("expected a connection error, got Finding %+v", f)
	}
}

func TestSummarizeNames(t *testing.T) {
	if got := summarizeNames(nil); got != "(empty)" {
		t.Errorf("summarizeNames(nil) = %q, want %q", got, "(empty)")
	}
	got := summarizeNames([]string{"a", "b", "c"})
	if got != "3 entries: a, b, c" {
		t.Errorf("summarizeNames = %q", got)
	}
	many := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	got = summarizeNames(many)
	if !strings.HasPrefix(got, "10 entries: a, b, c, d, e, f, g, h") || !strings.HasSuffix(got, "+2 more") {
		t.Errorf("summarizeNames(10 entries) = %q", got)
	}
}

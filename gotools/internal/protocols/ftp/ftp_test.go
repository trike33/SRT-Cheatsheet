package ftp

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols/auth"
)

// fakeFTPServer drives one net.Pipe end as a minimal FTP control channel,
// scripted by expect/reply pairs: it reads one line and, when it contains
// the expect substring, writes the matching reply.
func fakeFTPServer(t *testing.T, srv net.Conn, banner string, steps [][2]string) {
	t.Helper()
	go func() {
		defer srv.Close()
		if banner != "" {
			srv.Write([]byte(banner + "\r\n"))
		}
		r := bufio.NewReader(srv)
		for _, step := range steps {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if !strings.Contains(strings.ToUpper(line), strings.ToUpper(step[0])) {
				t.Errorf("fake server: expected a line containing %q, got %q", step[0], line)
			}
			srv.Write([]byte(step[1] + "\r\n"))
		}
	}()
}

func oneOverPipe(t *testing.T, banner string, steps [][2]string, creds auth.Creds) Result {
	t.Helper()
	client, srv := net.Pipe()
	fakeFTPServer(t, srv, banner, steps)
	c := &conn{nc: client, r: bufio.NewReader(client)}
	defer c.nc.Close()

	// Mirror One()'s control flow directly against the piped conn, since
	// One() itself owns the net.Dial -- this is the same state machine,
	// exercised without a real socket.
	deadline := time.Now().Add(2 * time.Second)
	res := Result{Target: "pipe", Port: 0}
	if _, b, err := c.readReply(deadline); err != nil {
		res.Err = err.Error()
		return res
	} else {
		res.Banner = b
	}
	user, pass := "anonymous", "anonymous@srt-cheatsheet.local"
	res.LoginAttempted = "anonymous"
	if !creds.Anonymous() {
		user, pass = creds.User, creds.Password
		res.LoginAttempted = user
	}
	c.send(deadline, "USER "+user)
	code, _, err := c.readReply(deadline)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	if code == 331 {
		c.send(deadline, "PASS "+pass)
		code, _, err = c.readReply(deadline)
		if err != nil {
			res.Err = err.Error()
			return res
		}
	}
	res.LoginOK = code == 230
	if res.LoginOK {
		c.send(deadline, "SYST")
		if _, sys, err := c.readReply(deadline); err == nil {
			res.System = sys
		}
	}
	return res
}

func TestAnonymousLoginSucceeds(t *testing.T) {
	res := oneOverPipe(t, "220 fake ready", [][2]string{
		{"USER anonymous", "331 need password"},
		{"PASS", "230 logged in"},
		{"SYST", "215 UNIX Type: L8"},
	}, auth.Creds{})
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if !res.LoginOK {
		t.Error("LoginOK = false, want true")
	}
	if res.System != "UNIX Type: L8" {
		t.Errorf("System = %q, want %q", res.System, "UNIX Type: L8")
	}
	if res.Banner != "fake ready" {
		t.Errorf("Banner = %q, want %q", res.Banner, "fake ready")
	}
}

func TestLoginFails(t *testing.T) {
	res := oneOverPipe(t, "220 fake ready", [][2]string{
		{"USER anonymous", "331 need password"},
		{"PASS", "530 login incorrect"},
	}, auth.Creds{})
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if res.LoginOK {
		t.Error("LoginOK = true, want false on a 530 reply")
	}
}

func TestCredentialedLoginUsesGivenUser(t *testing.T) {
	res := oneOverPipe(t, "220 fake ready", [][2]string{
		{"USER bob", "331 need password"},
		{"PASS", "230 logged in"},
	}, auth.Creds{User: "bob", Password: "s3cret"})
	if res.LoginAttempted != "bob" {
		t.Errorf("LoginAttempted = %q, want bob", res.LoginAttempted)
	}
	if !res.LoginOK {
		t.Error("LoginOK = false, want true")
	}
}

func TestMultilineReply(t *testing.T) {
	client, srv := net.Pipe()
	go func() {
		defer srv.Close()
		srv.Write([]byte("220-Welcome\r\n220-Second line\r\n220 Ready\r\n"))
	}()
	c := &conn{nc: client, r: bufio.NewReader(client)}
	defer c.nc.Close()
	code, text, err := c.readReply(time.Now().Add(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if code != 220 {
		t.Errorf("code = %d, want 220", code)
	}
	if text != "Ready" {
		t.Errorf("text = %q, want the final line's text only", text)
	}
}

func TestOneConnectionRefusedReportsError(t *testing.T) {
	res := One(context.Background(), "127.0.0.1", auth.Creds{}, auth.Options{Port: 1, Timeout: time.Second})
	if res.Err == "" {
		t.Error("expected an error dialing a closed/privileged port")
	}
}

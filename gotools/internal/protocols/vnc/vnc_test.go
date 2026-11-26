package vnc

import (
	"bytes"
	"crypto/des"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
)

// xtigervncPath finds the real Xtigervnc server this file drives for a
// genuine protocol-level test, skipping gracefully (not failing) when
// it isn't installed -- the same convention recon/traceroute uses for a
// capability (there, a raw socket) the test environment may not have.
func xtigervncPath(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("Xtigervnc")
	if err != nil {
		t.Skip("Xtigervnc not installed -- skipping real-server VNC tests (apt install tigervnc-standalone-server)")
	}
	return path
}

// freePort asks the OS for an unused TCP port by briefly binding to
// port 0, the same trick every other fake-server test in this repo
// uses -- Xtigervnc itself needs a concrete port number up front
// (-rfbport), unlike a net.Listener this package can just ask to pick
// one.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// startXtigervnc runs a real VNC server on a free port with the given
// extra arguments, waits for it to start accepting connections, and
// registers it to be killed when the test ends. displayNum must be
// unique per test (Xtigervnc locks it under /tmp).
func startXtigervnc(t *testing.T, displayNum, port int, extraArgs ...string) {
	t.Helper()
	xtigervnc := xtigervncPath(t)
	dir := t.TempDir()
	args := append([]string{
		":" + strconv.Itoa(displayNum),
		"-rfbport", strconv.Itoa(port),
		"-geometry", "800x600",
		"-ac", "-nolock", "-noreset", "-SecurityTypes",
	}, extraArgs...)
	_ = dir
	cmd := exec.Command(xtigervnc, args...)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting Xtigervnc: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Xtigervnc on port %d never started listening", port)
}

func writeVncPasswdFile(t *testing.T, password string) string {
	t.Helper()
	xtigervncPath(t) // vncpasswd ships alongside it; same skip condition
	path := filepath.Join(t.TempDir(), "passwd")
	cmd := exec.Command("vncpasswd", "-f")
	cmd.Stdin = bytes.NewBufferString(password + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("vncpasswd: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func target(t *testing.T, port int) protocols.Target {
	return protocols.Target{Host: "127.0.0.1", Port: port}
}

func TestProbeNoAuthRealServer(t *testing.T) {
	port := freePort(t)
	startXtigervnc(t, 51, port, "None", "-desktop", "no-auth-test")

	fs := probe(target(t, port), nil, 5*time.Second)
	if len(fs) != 2 {
		t.Fatalf("len(fs) = %d, want 2 (banner + no-auth), got %+v", len(fs), fs)
	}
	banner, f := fs[0], fs[1]
	if want := `desktop "no-auth-test"`; !containsStr(t, banner.Detail, want) {
		t.Errorf("banner.Detail = %q, want it to contain %q", banner.Detail, want)
	}
	if !containsStr(t, banner.Detail, "800x600") {
		t.Errorf("banner.Detail = %q, want it to contain the resolution", banner.Detail)
	}
	if f.Err != "" {
		t.Fatalf("unexpected error: %s", f.Err)
	}
	if f.Kind != KindNoAuth {
		t.Fatalf("Kind = %q, want %q (detail=%q)", f.Kind, KindNoAuth, f.Detail)
	}
	if f.Severity != protocols.High {
		t.Errorf("Severity = %q, want %q", f.Severity, protocols.High)
	}
}

// TestProbeVNCAuthRealServer is split into one subtest per server
// instance, deliberately NOT sharing one server across the
// wrong-password and right-password cases: TigerVNC (like most VNC
// servers) throttles a client IP after a failed auth attempt, closing
// the next connection before it can even finish the handshake -- caught
// by this test itself failing intermittently with "broken pipe" when a
// right-password probe followed a wrong-password one against the same
// server in quick succession. A fresh server per case sidesteps that
// throttle rather than papering over it with a sleep, and is also just
// the more realistic shape for what probe (a fresh connection per
// attempt) is actually meant to tolerate: one target, one real
// password to try.
func TestProbeVNCAuthRealServerWrongPassword(t *testing.T) {
	port := freePort(t)
	passwdFile := writeVncPasswdFile(t, "s3cret12")
	startXtigervnc(t, 52, port, "VncAuth", "-PasswordFile", passwdFile, "-desktop", "pwauth-test")

	fs := probe(target(t, port), []string{"wrongpass"}, 5*time.Second)
	f := fs[len(fs)-1]
	if f.Kind != KindLoginFailed {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginFailed, f.Detail, f.Err)
	}
}

func TestProbeVNCAuthRealServerNoPasswordGiven(t *testing.T) {
	port := freePort(t)
	passwdFile := writeVncPasswdFile(t, "s3cret12")
	startXtigervnc(t, 53, port, "VncAuth", "-PasswordFile", passwdFile, "-desktop", "pwauth-test")

	// No password given at all: a banner Finding naming what's required,
	// not a failure -- there was nothing to try, and this never attempts
	// an actual auth (so it's lockout-safe to run before another case
	// against the same server, unlike the wrong/right-password ones).
	fs := probe(target(t, port), nil, 5*time.Second)
	f := fs[len(fs)-1]
	if f.Kind != KindBanner {
		t.Fatalf("Kind = %q, want %q (detail=%q)", f.Kind, KindBanner, f.Detail)
	}
}

func TestProbeVNCAuthRealServerRightPassword(t *testing.T) {
	port := freePort(t)
	passwdFile := writeVncPasswdFile(t, "s3cret12")
	startXtigervnc(t, 54, port, "VncAuth", "-PasswordFile", passwdFile, "-desktop", "pwauth-test")

	fs := probe(target(t, port), []string{"s3cret12"}, 5*time.Second)
	if len(fs) != 2 {
		t.Fatalf("len(fs) = %d, want 2 (banner + login-ok), got %+v", len(fs), fs)
	}
	banner, f := fs[0], fs[1]
	if f.Kind != KindLoginOK {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginOK, f.Detail, f.Err)
	}
	if f.Cred.Password != "s3cret12" {
		t.Errorf("Cred.Password = %q, want %q", f.Cred.Password, "s3cret12")
	}
	if !containsStr(t, banner.Detail, `desktop "pwauth-test"`) {
		t.Errorf("banner.Detail = %q, want it to contain the desktop name", banner.Detail)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	fs := probe(protocols.Target{Host: "127.0.0.1", Port: 1}, nil, 300*time.Millisecond)
	if len(fs) != 1 || fs[0].Err == "" {
		t.Fatalf("expected a single Finding with a connection error, got %+v", fs)
	}
}

func containsStr(t *testing.T, s, substr string) bool {
	t.Helper()
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// --- pure-logic tests, no server needed ---

func TestVncEncryptChallenge(t *testing.T) {
	challenge := make([]byte, 16)
	for i := range challenge {
		challenge[i] = byte(i)
	}
	resp, err := vncEncryptChallenge(challenge, "s3cret12")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != 16 {
		t.Fatalf("len(resp) = %d, want 16", len(resp))
	}

	// Reproduce the expected bytes independently (bit-reversed key, ECB
	// DES over each 8-byte half) and compare, rather than trusting the
	// same code path twice.
	key := []byte("s3cret12")
	for i, b := range key {
		key[i] = reverseBits(b)
	}
	block, err := des.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 16)
	block.Encrypt(want[0:8], challenge[0:8])
	block.Encrypt(want[8:16], challenge[8:16])
	if string(resp) != string(want) {
		t.Errorf("vncEncryptChallenge = %x, want %x", resp, want)
	}

	if _, err := vncEncryptChallenge(challenge[:10], "x"); err == nil {
		t.Error("vncEncryptChallenge with a short challenge: want error, got nil")
	}
}

func TestReverseBits(t *testing.T) {
	cases := []struct{ in, want byte }{
		{0x00, 0x00},
		{0xFF, 0xFF},
		{0x01, 0x80},
		{0x80, 0x01},
		{0x0F, 0xF0},
	}
	for _, c := range cases {
		if got := reverseBits(c.in); got != c.want {
			t.Errorf("reverseBits(%#02x) = %#02x, want %#02x", c.in, got, c.want)
		}
	}
}

func TestMinorVersion(t *testing.T) {
	cases := []struct {
		version string
		want    int
	}{
		{"RFB 003.008", 8},
		{"RFB 003.003", 3},
		{"RFB 003.889", 889},
		{"garbage", 3},
		{"", 3},
	}
	for _, c := range cases {
		if got := minorVersion(c.version); got != c.want {
			t.Errorf("minorVersion(%q) = %d, want %d", c.version, got, c.want)
		}
	}
}

func TestContains(t *testing.T) {
	if !contains([]byte{1, 2, 3}, 2) {
		t.Error("contains should find 2")
	}
	if contains([]byte{1, 2, 3}, 9) {
		t.Error("contains should not find 9")
	}
}

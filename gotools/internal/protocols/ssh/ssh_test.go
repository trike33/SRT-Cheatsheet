package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
)

func pemEncode(block *pem.Block) []byte {
	return pem.EncodeToMemory(block)
}

func emptyCreds(t *testing.T) *protocols.Creds {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	c := protocols.BindCreds(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	return c
}

func credsWithPassword(t *testing.T, password string) *protocols.Creds {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	c := protocols.BindCreds(fs)
	if err := fs.Parse([]string{"-u", "x", "-p", password}); err != nil {
		t.Fatal(err)
	}
	return c
}

// testHostKey is one host key, generated once and reused by every
// fakeSSHServer in this file (the client's HostKeyCallback is
// InsecureIgnoreHostKey, so what the key actually is never matters).
var testHostKey = func() cryptossh.Signer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		panic(err)
	}
	return signer
}()

// fakeSSHServer starts a loopback-only SSH server driven by
// golang.org/x/crypto/ssh's OWN server side -- a real implementation of
// the protocol this package's client half talks, not a hand-rolled
// stand-in, so these tests exercise the real wire handshake end to end.
// It never opens a shell: every accepted connection is closed right
// after authentication completes, since probe never asks for one
// either.
func fakeSSHServer(t *testing.T, cfg *cryptossh.ServerConfig) string {
	t.Helper()
	cfg.AddHostKey(testHostKey)
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
				sc, chans, reqs, err := cryptossh.NewServerConn(c, cfg)
				if err != nil {
					c.Close()
					return
				}
				go cryptossh.DiscardRequests(reqs)
				go func() {
					for ch := range chans {
						ch.Reject(cryptossh.Prohibited, "this test server opens no channels")
					}
				}()
				sc.Close()
			}()
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
	tg, err := protocols.ParseTarget(host+":"+portStr, DefaultPort)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	return tg
}

func TestProbeNoAuthAccepted(t *testing.T) {
	addr := fakeSSHServer(t, &cryptossh.ServerConfig{NoClientAuth: true})
	f := probe(target(t, addr), []protocols.Credential{protocols.Anonymous}, nil, 3*time.Second)
	if f.Err != "" {
		t.Fatalf("unexpected error: %s", f.Err)
	}
	if f.Kind != KindNoAuth {
		t.Fatalf("Kind = %q, want %q (detail=%q)", f.Kind, KindNoAuth, f.Detail)
	}
	if f.Severity != protocols.High {
		t.Errorf("Severity = %q, want %q", f.Severity, protocols.High)
	}
	if !strings.Contains(f.Detail, "SSH-2.0-") {
		t.Errorf("Detail = %q, want it to mention the server's SSH banner", f.Detail)
	}
}

func TestProbeBannerOnlyWithNoCredentials(t *testing.T) {
	// The ordinary case: the server rejects "none" (no -u was given, so
	// Anonymous is the only attempt) -- a banner Finding, not a failure,
	// since there was nothing else to try.
	addr := fakeSSHServer(t, &cryptossh.ServerConfig{
		PasswordCallback: func(cryptossh.ConnMetadata, []byte) (*cryptossh.Permissions, error) {
			return nil, cryptossh.ErrNoAuth // never actually offered as a method; present so NoClientAuth defaults to false
		},
	})
	f := probe(target(t, addr), []protocols.Credential{protocols.Anonymous}, nil, 3*time.Second)
	if f.Kind != KindBanner {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindBanner, f.Detail, f.Err)
	}
	if !strings.HasPrefix(f.Detail, "SSH-2.0-") {
		t.Errorf("Detail = %q, want it to be the raw banner", f.Detail)
	}
}

func TestProbePasswordAccepted(t *testing.T) {
	addr := fakeSSHServer(t, &cryptossh.ServerConfig{
		PasswordCallback: func(conn cryptossh.ConnMetadata, password []byte) (*cryptossh.Permissions, error) {
			if conn.User() == "alice" && string(password) == "s3cret" {
				return nil, nil
			}
			return nil, cryptossh.ErrNoAuth
		},
	})
	creds := []protocols.Credential{protocols.Anonymous, {User: "alice", Password: "s3cret"}}
	f := probe(target(t, addr), creds, nil, 3*time.Second)
	if f.Kind != KindLoginOK {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginOK, f.Detail, f.Err)
	}
	if f.Cred.User != "alice" {
		t.Errorf("Cred.User = %q, want %q", f.Cred.User, "alice")
	}
}

func TestProbeEveryAttemptRejected(t *testing.T) {
	addr := fakeSSHServer(t, &cryptossh.ServerConfig{
		PasswordCallback: func(cryptossh.ConnMetadata, []byte) (*cryptossh.Permissions, error) {
			return nil, cryptossh.ErrNoAuth
		},
	})
	creds := []protocols.Credential{protocols.Anonymous, {User: "alice", Password: "wrong"}}
	f := probe(target(t, addr), creds, nil, 3*time.Second)
	if f.Kind != KindLoginFailed {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginFailed, f.Detail, f.Err)
	}
	if f.Severity != protocols.Info {
		t.Errorf("Severity = %q, want %q", f.Severity, protocols.Info)
	}
}

func TestProbePublicKeyAccepted(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	wantKey := clientSigner.PublicKey().Marshal()

	addr := fakeSSHServer(t, &cryptossh.ServerConfig{
		PublicKeyCallback: func(conn cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
			if conn.User() == "deploy" && bytes.Equal(key.Marshal(), wantKey) {
				return nil, nil
			}
			return nil, cryptossh.ErrNoAuth
		},
	})
	creds := []protocols.Credential{protocols.Anonymous, {User: "deploy"}}
	f := probe(target(t, addr), creds, clientSigner, 3*time.Second)
	if f.Kind != KindLoginOK {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginOK, f.Detail, f.Err)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	tg := protocols.Target{Host: "127.0.0.1", Port: 1}
	f := probe(tg, []protocols.Credential{protocols.Anonymous}, nil, 300*time.Millisecond)
	if f.Err == "" {
		t.Fatalf("expected a connection error, got Finding %+v", f)
	}
}

func TestLoadSigner(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	plain := pemEncode(block)

	dir := t.TempDir()
	plainPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(plainPath, plain, 0o600); err != nil {
		t.Fatal(err)
	}

	fs := emptyCreds(t)
	got, err := loadSigner(plainPath, fs)
	if err != nil {
		t.Fatalf("loadSigner(unencrypted): %v", err)
	}
	if !bytes.Equal(got.PublicKey().Marshal(), signer.PublicKey().Marshal()) {
		t.Errorf("loaded signer's public key doesn't match the original")
	}

	encBlock, err := cryptossh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	encPath := filepath.Join(dir, "id_ed25519_enc")
	if err := os.WriteFile(encPath, pemEncode(encBlock), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadSigner(encPath, emptyCreds(t)); err == nil {
		t.Error("loadSigner(encrypted, no passphrase): want error, got nil")
	}
	withPass := credsWithPassword(t, "hunter2")
	got, err = loadSigner(encPath, withPass)
	if err != nil {
		t.Fatalf("loadSigner(encrypted, right passphrase): %v", err)
	}
	if !bytes.Equal(got.PublicKey().Marshal(), signer.PublicKey().Marshal()) {
		t.Errorf("loaded (decrypted) signer's public key doesn't match the original")
	}
}

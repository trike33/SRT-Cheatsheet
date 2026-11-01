package portscan

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func TestResolvePortsNamedPresets(t *testing.T) {
	common, err := resolvePorts("common")
	if err != nil {
		t.Fatalf("common: %v", err)
	}
	if len(common) != len(commonPorts) {
		t.Errorf("len(common) = %d, want %d", len(common), len(commonPorts))
	}

	uncommon, err := resolvePorts("uncommon")
	if err != nil {
		t.Fatalf("uncommon: %v", err)
	}
	if len(uncommon) != len(uncommonPorts) {
		t.Errorf("len(uncommon) = %d, want %d", len(uncommon), len(uncommonPorts))
	}

	all, err := resolvePorts("all")
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if len(all) != 65535 {
		t.Errorf("len(all) = %d, want 65535", len(all))
	}
}

func TestResolvePortsCombined(t *testing.T) {
	got, err := resolvePorts("common,uncommon")
	if err != nil {
		t.Fatalf("combined: %v", err)
	}
	if len(got) != len(commonPorts)+len(uncommonPorts) {
		t.Errorf("len(combined) = %d, want %d", len(got), len(commonPorts)+len(uncommonPorts))
	}

	// common + an explicit numeric extra, deduped and sorted.
	got, err = resolvePorts("80,443,8000-8002")
	if err != nil {
		t.Fatalf("explicit: %v", err)
	}
	want := []int{80, 443, 8000, 8001, 8002}
	if len(got) != len(want) {
		t.Fatalf("explicit = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("explicit[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestResolvePortsDedup(t *testing.T) {
	// 80 appears in both the explicit list and (already via "common").
	got, err := resolvePorts("common,80,80")
	if err != nil {
		t.Fatalf("dedup: %v", err)
	}
	seen := map[int]int{}
	for _, p := range got {
		seen[p]++
	}
	for p, n := range seen {
		if n > 1 {
			t.Errorf("port %d appeared %d times, want deduped", p, n)
		}
	}
}

func TestResolvePortsEmptyFallsBackToCommon(t *testing.T) {
	got, err := resolvePorts("")
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if len(got) != len(commonPorts) {
		t.Errorf("empty spec: len = %d, want %d (common)", len(got), len(commonPorts))
	}
}

func TestResolvePortsInvalid(t *testing.T) {
	if _, err := resolvePorts("not-a-port"); err == nil {
		t.Error("expected an error for an unparseable -p spec")
	}
}

func TestSanitizeBanner(t *testing.T) {
	got := sanitizeBanner([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
	if got != "SSH-2.0-OpenSSH_8.9" {
		t.Errorf("sanitizeBanner = %q", got)
	}

	got = sanitizeBanner([]byte("line one\nline  two\ttabbed"))
	if got != "line one line two tabbed" {
		t.Errorf("sanitizeBanner (whitespace collapse) = %q", got)
	}

	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	got = sanitizeBanner(long)
	if len(got) != 123 { // 120 + "..."
		t.Errorf("sanitizeBanner truncation: len = %d, want 123", len(got))
	}
}

// TestProbePortLoopback exercises the real TCP-connect + banner-read path
// against a listener on 127.0.0.1, so it's fast, deterministic, and makes no
// outbound network call.
func TestProbePortLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("hello-banner\r\n"))
	}()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parsing port %q: %v", portStr, err)
	}

	res, ok := probePort(host, port, 2*time.Second, true)
	if !ok {
		t.Fatal("probePort: expected the loopback listener to be reported open")
	}
	if res.Host != host || res.Port != port {
		t.Errorf("probePort result = %+v, want host=%s port=%d", res, host, port)
	}
	if res.Banner != "hello-banner" {
		t.Errorf("probePort banner = %q, want %q", res.Banner, "hello-banner")
	}
}

func TestIsWebPort(t *testing.T) {
	for _, p := range []int{80, 443, 8080, 8443} {
		if !IsWebPort(p) {
			t.Errorf("IsWebPort(%d) = false, want true", p)
		}
	}
	if IsWebPort(22) {
		t.Error("IsWebPort(22) = true, want false")
	}
}

func TestIsUncommonPort(t *testing.T) {
	if !IsUncommonPort(873) { // rsync, explicitly called out in methodology.md
		t.Error("IsUncommonPort(873) [rsync] = false, want true")
	}
	if !IsUncommonPort(1099) { // java rmi, explicitly called out in methodology.md
		t.Error("IsUncommonPort(1099) [java rmi] = false, want true")
	}
	if IsUncommonPort(80) {
		t.Error("IsUncommonPort(80) = true, want false")
	}
}

func TestIsBeanShellBanner(t *testing.T) {
	cases := []struct {
		banner string
		want   bool
	}{
		{"BeanShell 2.0b4 - by Pat Niemeyer (pat@pat.net)", true},
		{"beanshell 2.0b6", true}, // case-insensitive
		{"", false},
		{"SSH-2.0-OpenSSH_8.9", false},
		{"220 ProFTPD Server ready", false},
	}
	for _, c := range cases {
		if got := IsBeanShellBanner(c.banner); got != c.want {
			t.Errorf("IsBeanShellBanner(%q) = %v, want %v", c.banner, got, c.want)
		}
	}
}

func TestWebBaseURL(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"example.com", 80, "http://example.com"},
		{"example.com", 443, "https://example.com"},
		{"example.com", 8080, "http://example.com:8080"},
		{"example.com", 8443, "https://example.com:8443"},
	}
	for _, c := range cases {
		if got := WebBaseURL(c.host, c.port); got != c.want {
			t.Errorf("WebBaseURL(%q, %d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

func TestCommonAndUncommonPortsDoNotOverlap(t *testing.T) {
	for _, p := range commonPorts {
		if uncommonPortSet[p] {
			t.Errorf("port %d is listed in both commonPorts and uncommonPorts", p)
		}
	}
}

func TestProbePortClosed(t *testing.T) {
	// Bind and immediately close to get a port nothing is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()

	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parsing port %q: %v", portStr, err)
	}

	if _, ok := probePort(host, port, 200*time.Millisecond, false); ok {
		t.Error("probePort: expected a closed port to be reported not-open")
	}
}

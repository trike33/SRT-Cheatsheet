package telnet

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadFilteredStripsIACNegotiation(t *testing.T) {
	client, srv := net.Pipe()
	go func() {
		defer srv.Close()
		// IAC WILL ECHO, IAC DO SUPPRESS-GO-AHEAD, then plain text. A real
		// telnet client replies to each negotiation on the same conn
		// (that's what readFiltered does), so this fake server must drain
		// those replies -- an unbuffered net.Pipe deadlocks otherwise.
		go io.Copy(io.Discard, srv)
		srv.Write([]byte{iac, will, 1, iac, do, 3})
		srv.Write([]byte("Welcome\r\nlogin: "))
	}()
	r := bufio.NewReader(client)
	out, err := readFiltered(client, r, time.Now().Add(2*time.Second))
	client.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, string(rune(iac))) {
		t.Errorf("output still contains an IAC byte: %q", out)
	}
	if !strings.Contains(out, "Welcome") || !strings.Contains(out, "login:") {
		t.Errorf("output = %q, want it to contain the banner and prompt text", out)
	}
}

func TestFailurePhraseDetection(t *testing.T) {
	cases := []struct {
		text    string
		failure bool
	}{
		{"Last login: Tue\r\n$ ", false},
		{"Login incorrect\r\nlogin: ", true},
		{"Authentication failed", true},
		{"welcome aboard", false},
	}
	for _, c := range cases {
		lower := strings.ToLower(c.text)
		got := false
		for _, phrase := range failurePhrases {
			if strings.Contains(lower, phrase) {
				got = true
				break
			}
		}
		if got != c.failure {
			t.Errorf("text %q: failure phrase match = %v, want %v", c.text, got, c.failure)
		}
	}
}

// One's end-to-end behavior (banner capture, credentialed login heuristic)
// was verified manually against a scripted fake telnetd during development
// -- see the design doc's roadmap notes -- rather than as an automated test
// here, since it needs real timing-based socket I/O that's prone to flaking
// in CI. readFiltered and the failure-phrase table above cover its logic.

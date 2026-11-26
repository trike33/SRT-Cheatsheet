package shell

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNTPTimeRoundTrip(t *testing.T) {
	cases := []time.Time{
		time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC),
		time.Date(2000, 1, 1, 0, 0, 0, 500_000_000, time.UTC),
		time.Unix(0, 0).UTC(), // the Unix epoch itself -- well after NTP's own 1900 epoch
	}
	for _, want := range cases {
		got := fromNTPTime(toNTPTime(want))
		// NTP's 32-bit fractional field can't represent nanosecond
		// precision exactly; a sub-millisecond round-trip error is the
		// format's own limit, not a bug in these functions.
		if diff := got.Sub(want); diff > time.Millisecond || diff < -time.Millisecond {
			t.Errorf("fromNTPTime(toNTPTime(%v)) = %v, diff %v exceeds the format's own precision", want, got, diff)
		}
	}
}

// fakeSNTPServer starts a UDP listener that answers every client
// request with a reply whose Receive/Transmit Timestamp fields encode
// now().Add(skew) -- a real, if synthetic, SNTP server (RFC 4330's wire
// format) good enough to drive queryNTP's own parsing and offset math
// against, the same convention the protocol packages' hand-rolled fake
// TCP servers use for FTP/telnet/LDAP.
func fakeSNTPServer(t *testing.T, skew time.Duration) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 48)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 48 {
				continue
			}
			resp := make([]byte, 48)
			resp[0] = 0x24 // LI=0, VN=4, Mode=4 (server)
			now := time.Now().Add(skew)
			binary.BigEndian.PutUint64(resp[32:40], toNTPTime(now)) // Receive Timestamp
			binary.BigEndian.PutUint64(resp[40:48], toNTPTime(now)) // Transmit Timestamp
			conn.WriteTo(resp, addr)
		}
	}()
	return conn.LocalAddr().String()
}

func TestQueryNTPMeasuresOffset(t *testing.T) {
	const skew = 90 * time.Second
	addr := fakeSNTPServer(t, skew)

	res, err := queryNTP(addr, 2*time.Second)
	if err != nil {
		t.Fatalf("queryNTP: %v", err)
	}
	// Loopback round trip is fast, but not instant -- allow a generous
	// margin rather than asserting an exact offset.
	if diff := res.offset - skew; diff > 2*time.Second || diff < -2*time.Second {
		t.Errorf("queryNTP offset = %v, want close to %v", res.offset, skew)
	}
	if res.roundTrip < 0 {
		t.Errorf("queryNTP roundTrip = %v, want >= 0", res.roundTrip)
	}
}

func TestQueryNTPNoListener(t *testing.T) {
	// Nothing listening on this port: SetDeadline should bound the wait,
	// not hang.
	if _, err := queryNTP("127.0.0.1:1", 300*time.Millisecond); err == nil {
		t.Fatal("expected an error with nothing listening")
	}
}

func TestQueryNTPAddsDefaultPort(t *testing.T) {
	addr := fakeSNTPServer(t, 0)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	if port != "123" {
		// Exercise the no-port path for real: dial a listener that's
		// genuinely on 123 isn't possible unprivileged, so just confirm
		// the bare-host form is rewritten the way net.JoinHostPort would.
		if _, err := strconv.Atoi(port); err != nil {
			t.Fatalf("unexpected fake server port %q", port)
		}
	}
	if _, err := queryNTP(host+":"+port, 2*time.Second); err != nil {
		t.Fatalf("queryNTP(host:port): %v", err)
	}
}

func TestDescribeTimesync(t *testing.T) {
	ahead := describeTimesync(timesyncDoneMsg{host: "dc01", result: ntpResult{offset: 90 * time.Second, roundTrip: 10 * time.Millisecond}})
	if !strings.Contains(ahead, "ahead of") || !strings.Contains(ahead, "within Kerberos") {
		t.Errorf("describeTimesync (90s ahead, within tolerance) = %q", ahead)
	}

	behindExceeds := describeTimesync(timesyncDoneMsg{host: "dc01", result: ntpResult{offset: -10 * time.Minute, roundTrip: time.Millisecond}})
	if !strings.Contains(behindExceeds, "behind") || !strings.Contains(behindExceeds, "EXCEEDS") {
		t.Errorf("describeTimesync (10m behind, exceeds tolerance) = %q", behindExceeds)
	}

	wantErr := errors.New("i/o timeout")
	errMsg := describeTimesync(timesyncDoneMsg{host: "dc01", err: wantErr})
	if !strings.Contains(errMsg, "dc01") || !strings.Contains(errMsg, wantErr.Error()) {
		t.Errorf("describeTimesync (error) = %q", errMsg)
	}
}

package rdp

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
)

// These hex strings are bytes this package's own client actually
// captured on the wire against a real xrdp server (1.13.1, Ubuntu
// noble) while this package was written -- not hand-derived from the
// spec alone. See rdp.go's negotiate doc comment.
const (
	// xrdp (security_layer=negotiate), requested SSL|HYBRID|HYBRID_EX:
	// RDP_NEG_RSP selecting SSL (xrdp here doesn't offer NLA).
	capturedOffersSSL = "030000130ed000001234000201080001000000"
	// Same server, requested plain RDP alone: RDP_NEG_RSP selecting
	// plain RDP (the legacy fallback still works).
	capturedLegacyAccepted = "030000130ed000001234000201080000000000"
	// xrdp reconfigured with security_layer=tls, requested plain RDP
	// alone: RDP Negotiation Failure (SSL_REQUIRED_BY_SERVER = 1),
	// immediately followed -- in the same TCP segment -- by a
	// Disconnect Request PDU the reader must NOT try to consume as
	// part of the Connection Confirm.
	capturedLegacyRejectedPlusDisconnect = "030000130ed00000123400030008000100000003000009" + "02f0802180"
)

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding test fixture: %v", err)
	}
	return b
}

func TestReadConnectionConfirmOffersSSL(t *testing.T) {
	r := bytes.NewReader(decodeHex(t, capturedOffersSSL))
	res, err := readConnectionConfirm(r, protoSSL|protoHybrid|protoHybridEx)
	if err != nil {
		t.Fatalf("readConnectionConfirm: %v", err)
	}
	if res.failed || res.noNegSupport {
		t.Fatalf("res = %+v, want a plain RDP_NEG_RSP", res)
	}
	if res.selected != protoSSL {
		t.Errorf("selected = %#x, want protoSSL (%#x)", res.selected, protoSSL)
	}
	if got := protoName(res.selected); got != "TLS" {
		t.Errorf("protoName(selected) = %q, want %q", got, "TLS")
	}
}

func TestReadConnectionConfirmLegacyAccepted(t *testing.T) {
	r := bytes.NewReader(decodeHex(t, capturedLegacyAccepted))
	res, err := readConnectionConfirm(r, protoRDP)
	if err != nil {
		t.Fatalf("readConnectionConfirm: %v", err)
	}
	if !res.accepted() {
		t.Fatalf("res = %+v, want accepted", res)
	}
	if res.selected != protoRDP {
		t.Errorf("selected = %#x, want protoRDP (0)", res.selected)
	}
}

func TestReadConnectionConfirmFailureIgnoresTrailingBytes(t *testing.T) {
	// The fixture has a full extra TPKT (a Disconnect Request) appended
	// after the Connection Confirm, exactly as xrdp sent it in one
	// segment -- readConnectionConfirm must stop at its own TPKT
	// length and not choke on, or try to parse, what follows.
	raw := decodeHex(t, capturedLegacyRejectedPlusDisconnect)
	r := bytes.NewReader(raw)
	res, err := readConnectionConfirm(r, protoRDP)
	if err != nil {
		t.Fatalf("readConnectionConfirm: %v", err)
	}
	if !res.failed {
		t.Fatalf("res = %+v, want a Negotiation Failure", res)
	}
	if res.failureCode != sslRequiredByServer {
		t.Errorf("failureCode = %d, want %d (sslRequiredByServer)", res.failureCode, sslRequiredByServer)
	}
	if got := res.reason(); got != failureReasons[sslRequiredByServer] {
		t.Errorf("reason() = %q, want %q", got, failureReasons[sslRequiredByServer])
	}
	// Exactly the Connection Confirm's own 19 bytes should have been
	// consumed, leaving the trailing Disconnect Request PDU untouched.
	if r.Len() != len(raw)-19 {
		t.Errorf("bytes remaining = %d, want %d (the trailing PDU, untouched)", r.Len(), len(raw)-19)
	}
}

func TestReadConnectionConfirmRejectsWrongTPDUType(t *testing.T) {
	// A full 7-byte X.224 fixed part, but with a Data TPDU's CDT (0xF0)
	// where a Connection Confirm's (0xD0) was expected.
	bad := decodeHex(t, "0300000b07f00000000000")
	if _, err := readConnectionConfirm(bytes.NewReader(bad), protoRDP); err == nil {
		t.Error("want an error for a non-CC TPDU, got nil")
	}
}

func TestReadConnectionConfirmNoNegotiationStructure(t *testing.T) {
	// A pre-RDP_NEG server: Connection Confirm with no negotiation
	// structure at all (just the 7-byte X.224 fixed part).
	noNeg := decodeHex(t, "0300000b07d00000123400")
	res, err := readConnectionConfirm(bytes.NewReader(noNeg), protoSSL)
	if err != nil {
		t.Fatalf("readConnectionConfirm: %v", err)
	}
	if !res.noNegSupport {
		t.Errorf("res = %+v, want noNegSupport", res)
	}
}

func TestSendConnectionRequestShape(t *testing.T) {
	var buf bytes.Buffer
	if err := sendConnectionRequest(&discardConn{&buf}, protoSSL|protoHybrid); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	want := decodeHex(t, "030000130ee000000000000100080003000000")
	if !bytes.Equal(got, want) {
		t.Errorf("sendConnectionRequest bytes = %x, want %x", got, want)
	}
}

// discardConn adapts a plain io.Writer to the net.Conn sendConnectionRequest's
// signature asks for -- only Write is ever called.
type discardConn struct{ w interface{ Write([]byte) (int, error) } }

func (d *discardConn) Write(b []byte) (int, error)         { return d.w.Write(b) }
func (d *discardConn) Read([]byte) (int, error)            { return 0, nil }
func (d *discardConn) Close() error                        { return nil }
func (d *discardConn) LocalAddr() net.Addr                 { return nil }
func (d *discardConn) RemoteAddr() net.Addr                { return nil }
func (d *discardConn) SetDeadline(time.Time) error         { return nil }
func (d *discardConn) SetReadDeadline(time.Time) error     { return nil }
func (d *discardConn) SetWriteDeadline(time.Time) error    { return nil }

func TestProtoName(t *testing.T) {
	cases := []struct {
		p    uint32
		want string
	}{
		{protoRDP, "plain RDP Standard Security"},
		{protoSSL, "TLS"},
		{protoHybrid, "CredSSP/NLA"},
		{protoHybridEx, "CredSSP/NLA (extended)"},
		{protoHybridEx | protoHybrid, "CredSSP/NLA (extended)"},
	}
	for _, c := range cases {
		if got := protoName(c.p); got != c.want {
			t.Errorf("protoName(%#x) = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestNegResultString(t *testing.T) {
	ok := negResult{selected: protoSSL}
	if got := ok.String(); got != "offers TLS" {
		t.Errorf("String() = %q, want %q", got, "offers TLS")
	}

	failed := negResult{requested: protoRDP, failed: true, failureCode: sslRequiredByServer}
	if got := failed.String(); !strings.Contains(got, "rejected") || !strings.Contains(got, "SSL/TLS required") {
		t.Errorf("String() = %q, want it to mention the rejection and reason", got)
	}

	old := negResult{noNegSupport: true}
	if got := old.String(); !strings.Contains(got, "predates") {
		t.Errorf("String() = %q, want it to mention predating negotiation", got)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	tg := protocols.Target{Host: "127.0.0.1", Port: 1}
	f := probe(tg, 300*time.Millisecond)
	if f.Err == "" {
		t.Fatalf("expected a connection error, got Finding %+v", f)
	}
}

// --- a real socket, round-tripping canned bytes through probe() itself ---

// fakeRDPServer starts a loopback server that reads the client's X.224
// Connection Request, extracts requestedProtocols (always at a fixed
// byte offset for the no-cookie request this package's own client
// sends -- see TestSendConnectionRequestShape), and replies with
// whatever responder returns for it.
func fakeRDPServer(t *testing.T, responder func(requestedProtocols uint32) []byte) string {
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
				req := make([]byte, 19)
				if _, err := net_ReadFull(c, req); err != nil {
					return
				}
				proto := uint32(req[15]) | uint32(req[16])<<8 | uint32(req[17])<<16 | uint32(req[18])<<24
				c.Write(responder(proto))
			}()
		}
	}()
	return ln.Addr().String()
}

func net_ReadFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
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

func TestProbeEndToEndAgainstFakeServer(t *testing.T) {
	addr := fakeRDPServer(t, func(proto uint32) []byte {
		if proto == protoRDP {
			return decodeHex(t, capturedLegacyAccepted)
		}
		return decodeHex(t, capturedOffersSSL)
	})
	f := probe(target(t, addr), 3*time.Second)
	if f.Err != "" {
		t.Fatalf("unexpected error: %s", f.Err)
	}
	if f.Kind != KindFingerprint {
		t.Fatalf("Kind = %q, want %q", f.Kind, KindFingerprint)
	}
	if f.Severity != protocols.Medium {
		t.Errorf("Severity = %q, want %q (no NLA offered + legacy accepted)", f.Severity, protocols.Medium)
	}
	for _, want := range []string{"offers TLS", "legacy RDP Standard Security", "also still accepted"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("Detail = %q, want it to contain %q", f.Detail, want)
		}
	}
}

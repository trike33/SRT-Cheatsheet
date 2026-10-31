package main

import (
	"encoding/binary"
	"testing"
)

// fakeIPHeader builds a minimal 20-byte IPv4 header (no options) around
// payload, enough for ipPayload/parseICMPReply to strip.
func fakeIPHeader(payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45 // version 4, IHL 5 (20 bytes) -- matches every real packet seen
	return append(h, payload...)
}

func fakeEchoReply(id, seq uint16) []byte {
	b := make([]byte, 8)
	b[0] = icmpEchoReply
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	return fakeIPHeader(b)
}

// fakeTimeExceeded builds the packet a router sends back: outer IP + ICMP
// Time Exceeded (type 11) + 4 unused bytes + the embedded original IP header
// + the embedded original echo request -- the exact shape confirmed against
// a real router's reply in testing.
func fakeTimeExceeded(id, seq uint16) []byte {
	inner := fakeIPHeader(buildICMPEcho(id, seq))
	te := make([]byte, 8)
	te[0] = icmpTimeExceeded
	return fakeIPHeader(append(te, inner...))
}

func TestICMPChecksumZeroesOut(t *testing.T) {
	pkt := buildICMPEcho(0x1234, 7)
	// Re-checksumming a packet that already carries its correct checksum
	// (the checksum field included) must land back on zero -- the standard
	// ones'-complement self-check.
	if icmpChecksum(pkt) != 0 {
		t.Errorf("checksum over an already-checksummed packet = %#x, want 0", icmpChecksum(pkt))
	}
}

func TestBuildICMPEchoFields(t *testing.T) {
	pkt := buildICMPEcho(0xabcd, 42)
	if pkt[0] != icmpEchoRequest || pkt[1] != 0 {
		t.Fatalf("type/code = %d/%d", pkt[0], pkt[1])
	}
	if binary.BigEndian.Uint16(pkt[4:6]) != 0xabcd || binary.BigEndian.Uint16(pkt[6:8]) != 42 {
		t.Errorf("id/seq not round-tripped: %x", pkt)
	}
}

func TestParseICMPReplyEchoReply(t *testing.T) {
	isReply, isFinal := parseICMPReply(fakeEchoReply(0x1234, 7), 0x1234, 7)
	if !isReply || !isFinal {
		t.Errorf("echo reply: isReply=%v isFinal=%v, want true,true", isReply, isFinal)
	}
}

func TestParseICMPReplyTimeExceeded(t *testing.T) {
	isReply, isFinal := parseICMPReply(fakeTimeExceeded(0x1234, 7), 0x1234, 7)
	if !isReply || isFinal {
		t.Errorf("time exceeded: isReply=%v isFinal=%v, want true,false", isReply, isFinal)
	}
}

func TestParseICMPReplyRejectsMismatchedIDOrSeq(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"wrong id, echo reply", fakeEchoReply(0x9999, 7)},
		{"wrong seq, echo reply", fakeEchoReply(0x1234, 8)},
		{"wrong id, time exceeded", fakeTimeExceeded(0x9999, 7)},
		{"wrong seq, time exceeded", fakeTimeExceeded(0x1234, 8)},
	}
	for _, c := range cases {
		if isReply, _ := parseICMPReply(c.pkt, 0x1234, 7); isReply {
			t.Errorf("%s: should not match", c.name)
		}
	}
}

func TestParseICMPReplyIgnoresOtherTypesAndJunk(t *testing.T) {
	destUnreach := fakeIPHeader([]byte{3, 0, 0, 0, 0, 0, 0, 0}) // type 3
	if isReply, _ := parseICMPReply(destUnreach, 1, 1); isReply {
		t.Error("an unrelated ICMP type must not match")
	}
	if isReply, _ := parseICMPReply(nil, 1, 1); isReply {
		t.Error("empty packet must not match")
	}
	if isReply, _ := parseICMPReply([]byte{0x45, 0, 0}, 1, 1); isReply {
		t.Error("truncated packet must not match")
	}
	// A Time Exceeded whose embedded packet isn't an echo request at all.
	notEcho := fakeIPHeader(append([]byte{0, 0, 0, 0}, fakeIPHeader([]byte{0, 0, 0, 0, 0, 1, 0, 7})...))
	notEcho[(0x45&0x0f)*4] = icmpTimeExceeded
	if isReply, _ := parseICMPReply(notEcho, 1, 7); isReply {
		t.Error("a Time Exceeded not embedding our echo request must not match")
	}
}

func TestIPPayloadStripsHeader(t *testing.T) {
	payload := []byte{0xAA, 0xBB}
	got, ok := ipPayload(fakeIPHeader(payload))
	if !ok || len(got) != 2 || got[0] != 0xAA {
		t.Errorf("got %v, ok=%v", got, ok)
	}
	if _, ok := ipPayload([]byte{1, 2, 3}); ok {
		t.Error("too-short packet should report !ok")
	}
}

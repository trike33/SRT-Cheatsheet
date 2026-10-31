package traceroute

import "encoding/binary"

// Minimal ICMPv4 echo request/reply construction and parsing — just enough
// for traceroute's probe-and-match loop, not a general ICMP library. These
// are pure byte-slice functions, independently testable without a raw
// socket (which the platform-specific traceroute_*.go needs CAP_NET_RAW or
// root to open).

const (
	icmpEchoRequest  = 8
	icmpEchoReply    = 0
	icmpTimeExceeded = 11
)

// icmpChecksum computes the standard Internet checksum (RFC 1071).
func icmpChecksum(b []byte) uint16 {
	var sum uint32
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// buildICMPEcho builds an 8-byte ICMPv4 echo request (type 8, code 0). id and
// seq identify this one probe, so the reply -- or an intermediate hop's Time
// Exceeded, which echoes it back -- can be matched to it.
func buildICMPEcho(id, seq uint16) []byte {
	b := make([]byte, 8)
	b[0], b[1] = icmpEchoRequest, 0
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	binary.BigEndian.PutUint16(b[2:4], icmpChecksum(b))
	return b
}

// parseICMPReply inspects a raw IPv4 packet -- IP header + ICMP, exactly what
// a raw ICMP socket hands back on read -- and reports whether it answers the
// echo probe id/seq identifies:
//
//   - an intermediate router's Time Exceeded (type 11), which embeds the
//     original packet -- our echo request -- after its own 4-byte unused
//     field and the inner IP header: a hop, not the destination.
//   - an Echo Reply (type 0) carrying our id/seq directly: the target itself
//     answered, so the trace is done.
//
// Anything else (wrong id/seq, a different ICMP type, a short/malformed
// packet) is reported as not a reply, so an unrelated packet arriving on the
// socket -- another process's ping, a stale reply from a previous probe --
// is ignored rather than misread as this hop's answer.
func parseICMPReply(pkt []byte, id, seq uint16) (isReply, isFinal bool) {
	icmp, ok := ipPayload(pkt)
	if !ok || len(icmp) < 8 {
		return false, false
	}
	switch icmp[0] {
	case icmpEchoReply:
		return matchesEcho(icmp, id, seq), true
	case icmpTimeExceeded:
		if len(icmp) < 16 { // 8-byte ICMP header + at least an embedded IP header
			return false, false
		}
		inner, ok := ipPayload(icmp[8:])
		if !ok || len(inner) < 8 || inner[0] != icmpEchoRequest {
			return false, false
		}
		return matchesEcho(inner, id, seq), false
	default:
		return false, false
	}
}

func matchesEcho(icmp []byte, id, seq uint16) bool {
	return binary.BigEndian.Uint16(icmp[4:6]) == id && binary.BigEndian.Uint16(icmp[6:8]) == seq
}

// ipPayload strips an IPv4 header (variable length, from its IHL field) off
// pkt and returns what follows.
func ipPayload(pkt []byte) ([]byte, bool) {
	if len(pkt) < 20 {
		return nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return nil, false
	}
	return pkt[ihl:], true
}

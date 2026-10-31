//go:build !windows

package main

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// Real traceroute: a raw ICMP socket, reused across targets. Linux and
// macOS both hand back the full IP packet (header included) on a raw ICMP
// socket read, which is what icmp.go's parsing assumes.

// checkRawICMPAvailable opens and immediately closes a raw ICMP socket, to
// fail once with one clear message up front rather than once per target.
func checkRawICMPAvailable() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// traceHost traces one target, sending one ICMP echo per TTL from 1 up to
// maxHops and waiting up to timeout for a matching reply before giving up on
// that hop and moving to the next TTL. id is this process's probe identifier;
// seq is shared and incremented across every probe of every target in the
// run, so a stale reply arriving late for an earlier target's probe is never
// mistaken for the current one's (parseICMPReply checks id+seq, not just
// source address).
func traceHost(target string, maxHops int, timeout time.Duration, id uint16, seq *uint16) tracerouteResult {
	res := tracerouteResult{Target: target}
	ip, err := resolveToIP4(target)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.Addr = ip.String()

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer unix.Close(fd)

	var dst [4]byte
	copy(dst[:], ip)
	sa := &unix.SockaddrInet4{Addr: dst}

	for ttl := 1; ttl <= maxHops; ttl++ {
		*seq++
		hop, final := probeHop(fd, sa, ttl, timeout, id, *seq)
		res.Hops = append(res.Hops, hop)
		if final {
			res.Reached = true
			break
		}
	}
	return res
}

// probeHop sends one echo at ttl and waits for its match, meant for metering
// consistency with the rest of srt (each probe is a "request").
func probeHop(fd int, sa *unix.SockaddrInet4, ttl int, timeout time.Duration, id, seq uint16) (tracerouteHop, bool) {
	meter.request()
	hop := tracerouteHop{TTL: ttl}

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl); err != nil {
		hop.Timeout = true
		return hop, false
	}
	sent := time.Now()
	if err := unix.Sendto(fd, buildICMPEcho(id, seq), 0, sa); err != nil {
		hop.Timeout = true
		return hop, false
	}

	addr, final, ok := recvMatch(fd, time.Now().Add(timeout), id, seq)
	if !ok {
		hop.Timeout = true
		return hop, false
	}
	hop.Addr = addr
	hop.RTTMs = time.Since(sent).Milliseconds()
	return hop, final
}

// recvMatch reads packets off fd until one matches id/seq (a hop's Time
// Exceeded or the target's Echo Reply) or deadline passes, discarding any
// unrelated ICMP traffic in between.
func recvMatch(fd int, deadline time.Time, id, seq uint16) (addr string, final, ok bool) {
	buf := make([]byte, 1500)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return "", false, false
		}
		tv := durationToTimeval(remaining)
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return "", false, false
		}
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return "", false, false // timed out, or the socket's gone
		}
		isReply, isFinal := parseICMPReply(buf[:n], id, seq)
		if !isReply {
			continue
		}
		if sa, ok := from.(*unix.SockaddrInet4); ok {
			addr = net.IP(sa.Addr[:]).String()
		}
		return addr, isFinal, true
	}
}

func durationToTimeval(d time.Duration) unix.Timeval {
	if d < 0 {
		d = 0
	}
	return unix.NsecToTimeval(d.Nanoseconds())
}

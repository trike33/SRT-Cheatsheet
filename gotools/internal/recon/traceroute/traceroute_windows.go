//go:build windows

package traceroute

import (
	"errors"
	"time"
)

// Windows needs a different raw-socket path (WSASocket + IP_HDRINCL,
// privileged in a different way than CAP_NET_RAW) that nobody's wired up
// yet -- see ROADMAP.md. Kept as a clean, typed failure rather than a build
// failure, so `srt` still cross-compiles for Windows and every other
// command is unaffected; `traceroute` itself just reports it can't run here.

func CheckRawICMPAvailable() error {
	return errors.New("not implemented on Windows yet")
}

func traceHost(target string, maxHops int, timeout time.Duration, id uint16, seq *uint16) tracerouteResult {
	return tracerouteResult{Target: target, Err: "traceroute is not implemented on Windows yet"}
}

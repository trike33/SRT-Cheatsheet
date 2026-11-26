package shell

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

// kerberosSkewTolerance is the default this compares a measured offset
// against: RFC 4120 doesn't mandate a number, but Microsoft's AD and
// MIT krb5 both default their KDC's own "clockskew" setting to 5
// minutes. A real KDC's setting can differ (and might be tighter); this
// is a sane assumption to flag against, not something read off the
// target itself.
const kerberosSkewTolerance = 5 * time.Minute

// ntpEpochOffset is the number of seconds between NTP's epoch
// (1900-01-01) and Unix's (1970-01-01) -- RFC 5905 Appendix A.
const ntpEpochOffset = 2208988800

// toNTPTime encodes t as NTP's 64-bit fixed-point timestamp: 32-bit
// whole seconds since 1900, 32-bit fractional seconds.
func toNTPTime(t time.Time) uint64 {
	secs := uint64(t.Unix() + ntpEpochOffset)
	frac := uint64(float64(t.Nanosecond()) / 1e9 * (1 << 32))
	return secs<<32 | frac
}

// fromNTPTime decodes an NTP 64-bit timestamp back into a time.Time.
func fromNTPTime(v uint64) time.Time {
	secs := int64(v>>32) - ntpEpochOffset
	frac := float64(v&0xFFFFFFFF) / (1 << 32)
	return time.Unix(secs, int64(frac*1e9))
}

// ntpResult is what queryNTP measures.
type ntpResult struct {
	offset    time.Duration // positive: the target's clock is ahead of this machine's
	roundTrip time.Duration
}

// queryNTP sends a single SNTP (RFC 4330) client request to host's UDP
// port 123 -- the same port Active Directory's own w32time service
// answers on by default, so a domain controller needs no extra setup
// for this to work -- and computes the clock offset the standard
// four-timestamp NTP formula gives: ((T2-T1)+(T3-T4))/2, where T1/T4
// are this process's own send/receive times and T2/T3 come from the
// server's reply (its Receive/Transmit Timestamp fields). It only ever
// reads the target's clock: nothing here writes to, or even touches,
// the local system clock.
func queryNTP(host string, timeout time.Duration) (ntpResult, error) {
	addr := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		addr = net.JoinHostPort(host, "123")
	}
	netx.Request()
	raw, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return ntpResult{}, err
	}
	defer raw.Close()
	c := netx.CountConn(raw)
	c.SetDeadline(time.Now().Add(timeout))

	req := make([]byte, 48)
	req[0] = 0x23 // LI=0 (no warning), VN=4, Mode=3 (client request) -- RFC 4330 4
	t1 := time.Now()
	binary.BigEndian.PutUint64(req[40:48], toNTPTime(t1))
	if _, err := c.Write(req); err != nil {
		return ntpResult{}, err
	}

	resp := make([]byte, 48)
	n, err := c.Read(resp)
	t4 := time.Now()
	if err != nil {
		return ntpResult{}, err
	}
	if n < 48 {
		return ntpResult{}, fmt.Errorf("short NTP reply (%d bytes)", n)
	}

	t2 := fromNTPTime(binary.BigEndian.Uint64(resp[32:40])) // server's own Receive Timestamp
	t3 := fromNTPTime(binary.BigEndian.Uint64(resp[40:48])) // server's own Transmit Timestamp

	offset := (t2.Sub(t1) + t3.Sub(t4)) / 2
	roundTrip := t4.Sub(t1) - t3.Sub(t2)
	return ntpResult{offset: offset, roundTrip: roundTrip}, nil
}

// timesyncDoneMsg carries queryNTP's result back into Update, the same
// async pattern helpLoadedMsg uses for a command's -h text -- a real
// network round trip has no business blocking the UI thread the way
// every other built-in's synchronous, in-memory work can.
type timesyncDoneMsg struct {
	host   string
	result ntpResult
	err    error
}

// runTimesync starts an SNTP query against args[0] in the background.
func (m shellModel) runTimesync(args []string) (tea.Model, tea.Cmd) {
	if len(args) != 1 {
		m.lastErr = ioutil.ErrMissing("usage: timesync <host>")
		return m, nil
	}
	host := args[0]
	return m, func() tea.Msg {
		res, err := queryNTP(host, 5*time.Second)
		return timesyncDoneMsg{host: host, result: res, err: err}
	}
}

// describeTimesync renders msg as the one-line notice its Update case
// shows -- the same "collapse a short report into one notice line"
// convention `jobs`/`sessions` already use, rather than a multi-line
// block.
func describeTimesync(msg timesyncDoneMsg) string {
	if msg.err != nil {
		return fmt.Sprintf("timesync %s: %v", msg.host, msg.err)
	}
	direction := "ahead of"
	abs := msg.result.offset
	if abs < 0 {
		abs = -abs
		direction = "behind"
	}
	verdict := "within Kerberos's ~5min default skew tolerance"
	if abs > kerberosSkewTolerance {
		verdict = "EXCEEDS Kerberos's ~5min default skew tolerance -- -k will likely fail with a clock-skew error until this is corrected"
	}
	return fmt.Sprintf("timesync %s: clock is %s %s local time (round-trip %s) -- %s",
		msg.host, abs.Round(time.Millisecond), direction, msg.result.roundTrip.Round(time.Millisecond), verdict)
}

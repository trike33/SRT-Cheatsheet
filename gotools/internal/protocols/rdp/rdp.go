// Package rdp implements the rdp command, continuing the "SRT
// internal-pentest direction" doc's protocol-client roadmap beyond its
// original four -- scoped down deliberately from what that doc's
// research originally hoped for.
//
// A real RDP login needs NLA (CredSSP wrapping SPNEGO wrapping NTLM or
// Kerberos, all inside TLS) or, for the older path, a full MCS/GCC
// connect sequence before any credential is even exchanged -- protocol
// layers this repo's other credential-check commands don't have an
// equivalent of, and the Go ecosystem has no library for RDP's NLA that
// is both maintained and verified against real Windows servers (every
// option found is either abandoned or explicitly describes itself as
// unfinished). Rather than hand-roll CredSSP with no live Windows RDP
// server to verify it against -- the kind of binary-protocol work this
// repo's own testing conventions treat very differently from something
// a loopback fake server can stand in for -- this package stops at the
// one layer that's small, well-defined, and empirically verified here
// against a real server (xrdp): the X.224 Connection
// Request/Confirm security-protocol negotiation (MS-RDPBCGR 2.2.1.1/
// 2.2.1.2), which happens before any authentication at all. It reports
// what the server offers (plain RDP Standard Security, TLS, or
// NLA/CredSSP) and whether legacy, unencrypted RDP Standard Security is
// still accepted as a fallback -- real, actionable recon on its own --
// and never attempts a login.
package rdp

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "rdp",
		Group:   "PROTOCOL recon",
		Summary: "RDP X.224 security-protocol negotiation: what the server offers, and whether legacy RDP security still works (no login attempted)",
		Run:     Run,
	})
}

// DefaultPort is RDP's well-known port.
const DefaultPort = 3389

// requestedProtocols bits -- MS-RDPBCGR 2.2.1.1.1.
const (
	protoRDP      uint32 = 0x00000000 // plain RDP Standard Security -- no negotiation structure needed to ask for this alone
	protoSSL      uint32 = 0x00000001 // TLS
	protoHybrid   uint32 = 0x00000002 // CredSSP (NLA)
	protoHybridEx uint32 = 0x00000008 // CredSSP with an early user-auth-result message (NLA, extended)
)

// RDP Negotiation Failure codes this package names in a Finding's
// Detail -- MS-RDPBCGR 2.2.1.2.2. Empirically confirmed against a real
// xrdp server configured to require TLS: requesting protoRDP alone
// against it returns failureCode 1 (sslRequiredByServer).
const (
	sslRequiredByServer             = 1
	sslNotAllowedByServer           = 2
	sslCertNotOnServer              = 3
	inconsistentFlags               = 4
	hybridRequiredByServer          = 5
	sslWithUserAuthRequiredByServer = 6
)

var failureReasons = map[uint32]string{
	sslRequiredByServer:             "SSL/TLS required by server",
	sslNotAllowedByServer:           "SSL/TLS not allowed by server",
	sslCertNotOnServer:              "server has no certificate configured for SSL/TLS",
	inconsistentFlags:               "inconsistent negotiation flags",
	hybridRequiredByServer:          "CredSSP (NLA) required by server",
	sslWithUserAuthRequiredByServer: "SSL/TLS with early user authentication required by server",
}

// Finding kinds this package reports.
const KindFingerprint = "fingerprint"

func Run(args []string) error {
	fs := flag.NewFlagSet("rdp", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "CONNECTION", Names: []string{"port", "timeout", "c"}},
			{Title: "OUTPUT", Names: []string{"o", "json", "color"}},
		})
	}
	// No -u/-p/-H/-d/-k/-local-auth here: this package never attempts a
	// login at all (see the package doc for why), so registering those
	// flags would only invite the belief that giving a credential does
	// something.
	in := fs.String("l", "", "target list: host or host:port (default: stdin, else the project db's port records -- see -from)")
	fb := store.BindInputFallback(fs, "rdp", "port")
	conn := protocols.BindConn(fs, DefaultPort, 8*time.Second)
	concurrency := fs.Int("c", 20, "concurrent connections")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of a table")
	colorFlag := fs.String("color", "auto", "color the table output: auto|always|never (ignored with -json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	defer ioutil.StartHeartbeat("rdp")()

	lines, _, err := fb.Resolve(*in, fs.Args())
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return ioutil.ErrMissing("no targets: pass -l <file>, pipe targets on stdin, or save some into the project db first (see `srt results`)")
	}

	var targets []protocols.Target
	for _, line := range lines {
		t, err := protocols.ParseTarget(line, *conn.Port)
		if err != nil {
			ioutil.Warn("rdp: %v", err)
			continue
		}
		targets = append(targets, t)
	}

	results := make([]protocols.Finding, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *concurrency))
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t protocols.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = probe(t, *conn.Timeout)
		}(i, t)
	}
	wg.Wait()

	for _, f := range results {
		store.CurrentSink().Add(f.Record("rdp"))
	}

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()

	if *jsonOut {
		for _, f := range results {
			fmt.Fprintf(w, `{"target":%q,"kind":%q,"detail":%q,"severity":%q,"error":%q}`+"\n",
				f.Target.String(), f.Kind, f.Detail, f.Severity, f.Err)
		}
		return nil
	}
	printTable(w, results, cm)
	return nil
}

// probe runs the negotiation twice, each on its own fresh connection:
// once asking for everything (SSL, CredSSP, extended CredSSP) to learn
// the best security the server offers, once asking for plain RDP
// Standard Security alone to learn whether that legacy fallback still
// works even when a client doesn't ask for anything better. A
// connection-level failure on the first attempt aborts the whole
// target (the second would fail identically); a negotiation-level
// response or failure on either is not an error -- both are themselves
// the finding.
func probe(t protocols.Target, timeout time.Duration) protocols.Finding {
	best, err := negotiate(t, timeout, protoSSL|protoHybrid|protoHybridEx)
	if err != nil {
		return protocols.Finding{Target: t, Err: err.Error()}
	}
	legacy, err := negotiate(t, timeout, protoRDP)
	if err != nil {
		// The connection itself worked a moment ago (best succeeded);
		// treat a failure here as a detail, not a whole-target abort.
		return protocols.Finding{Target: t, Kind: KindFingerprint, Severity: protocols.Info,
			Detail: fmt.Sprintf("%s; legacy RDP Standard Security check failed: %v", best.String(), err)}
	}

	sev := protocols.Info
	if legacy.accepted() {
		sev = protocols.Medium // a real, actionable finding: unencrypted/legacy RDP Standard Security is still reachable
	}
	if best.selected == protoSSL || (!best.failed && best.selected == protoRDP) {
		sev = protocols.Medium // the server's best offer doesn't include NLA/CredSSP at all
	}

	detail := best.String()
	if legacy.accepted() {
		detail += "; legacy RDP Standard Security (unencrypted/weak-cipher-capable) also still accepted"
	} else if legacy.failed {
		detail += fmt.Sprintf("; legacy RDP Standard Security rejected (%s)", legacy.reason())
	}
	return protocols.Finding{Target: t, Kind: KindFingerprint, Severity: sev, Detail: detail}
}

// negResult is what one negotiate call learns.
type negResult struct {
	requested    uint32
	selected     uint32
	failed       bool
	failureCode  uint32
	noNegSupport bool // the server's Connection Confirm carried no negotiation structure at all -- an RDP server old enough to predate RDP_NEG entirely (MS-RDPBCGR's own fallback: treat as plain RDP Standard Security)
}

func (r negResult) accepted() bool { return !r.failed }

func (r negResult) reason() string {
	if s, ok := failureReasons[r.failureCode]; ok {
		return s
	}
	return fmt.Sprintf("failure code %d", r.failureCode)
}

func (r negResult) String() string {
	if r.failed {
		return fmt.Sprintf("requested %s, rejected: %s", protoName(r.requested), r.reason())
	}
	if r.noNegSupport {
		return "server predates RDP security-protocol negotiation (plain RDP Standard Security only)"
	}
	return fmt.Sprintf("offers %s", protoName(r.selected))
}

func protoName(p uint32) string {
	switch {
	case p&protoHybridEx != 0:
		return "CredSSP/NLA (extended)"
	case p&protoHybrid != 0:
		return "CredSSP/NLA"
	case p&protoSSL != 0:
		return "TLS"
	default:
		return "plain RDP Standard Security"
	}
}

// negotiate dials t fresh, sends an X.224 Connection Request carrying
// an RDP Negotiation Request for requestedProtocols, and parses the
// Connection Confirm that comes back -- MS-RDPBCGR 2.2.1.1/2.2.1.2.
// Byte layout confirmed empirically against a real xrdp server while
// writing this (see docs/ROADMAP.md): a 4-byte TPKT header (version,
// reserved, big-endian total length), then the X.224 CC TPDU (length
// indicator, 0xD0 CC code, 2-byte dst-ref, 2-byte src-ref, 1-byte class
// option), then -- if present -- the negotiation structure itself
// (1-byte type, 1-byte flags, little-endian 2-byte length, then either
// a little-endian 4-byte selectedProtocol for RDP_NEG_RSP (type 2) or a
// little-endian 4-byte failureCode for RDP Negotiation Failure (type
// 3)). Only the Connection Confirm PDU itself is read, even if the
// server's reply (observed with xrdp configured to require TLS, on
// rejecting a plain-RDP-only request) is immediately followed by a
// Disconnect Request PDU in the same TCP segment.
func negotiate(t protocols.Target, timeout time.Duration, requestedProtocols uint32) (negResult, error) {
	netx.Request()
	raw, err := net.DialTimeout("tcp", t.String(), timeout)
	if err != nil {
		return negResult{}, err
	}
	defer raw.Close()
	c := netx.CountConn(raw)
	c.SetDeadline(time.Now().Add(timeout))

	if err := sendConnectionRequest(c, requestedProtocols); err != nil {
		return negResult{}, err
	}
	return readConnectionConfirm(c, requestedProtocols)
}

func sendConnectionRequest(c net.Conn, requestedProtocols uint32) error {
	negReq := make([]byte, 8)
	negReq[0] = 1 // TYPE_RDP_NEG_REQ
	negReq[1] = 0 // flags
	binary.LittleEndian.PutUint16(negReq[2:4], 8)
	binary.LittleEndian.PutUint32(negReq[4:8], requestedProtocols)

	x224Fixed := []byte{0xE0, 0, 0, 0, 0, 0} // CDT (CR, class 0), dst-ref, src-ref, class option
	li := byte(len(x224Fixed) + len(negReq))
	x224 := append([]byte{li}, x224Fixed...)
	x224 = append(x224, negReq...)

	tpkt := make([]byte, 4)
	tpkt[0] = 3 // version
	tpkt[1] = 0 // reserved
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(4+len(x224)))

	_, err := c.Write(append(tpkt, x224...))
	return err
}

// readConnectionConfirm takes a plain io.Reader (not net.Conn) so its
// parsing can be unit-tested directly against canned bytes, with no
// socket involved.
func readConnectionConfirm(c io.Reader, requested uint32) (negResult, error) {
	tpktHeader, err := readExact(c, 4)
	if err != nil {
		return negResult{}, fmt.Errorf("reading TPKT header: %w", err)
	}
	if tpktHeader[0] != 3 {
		return negResult{}, fmt.Errorf("not a TPKT response (version byte %#x)", tpktHeader[0])
	}
	total := int(binary.BigEndian.Uint16(tpktHeader[2:4]))
	if total < 4+7 {
		return negResult{}, fmt.Errorf("TPKT length %d too short for an X.224 CC TPDU", total)
	}
	body, err := readExact(c, total-4)
	if err != nil {
		return negResult{}, fmt.Errorf("reading X.224 Connection Confirm: %w", err)
	}

	// body[0] = LI, body[1] = CDT, body[2:4] = dst-ref, body[4:6] = src-ref,
	// body[6] = class option -- 7 bytes total, so whatever follows (the
	// negotiation structure, if any) starts at body[7].
	if len(body) < 7 {
		return negResult{}, fmt.Errorf("X.224 TPDU shorter than its fixed part (%d bytes)", len(body))
	}
	if body[1]&0xF0 != 0xD0 {
		return negResult{}, fmt.Errorf("expected an X.224 Connection Confirm (CDT 0xD0), got %#x", body[1])
	}

	rest := body[7:]
	if len(rest) == 0 {
		return negResult{requested: requested, noNegSupport: true}, nil
	}
	if len(rest) < 8 {
		return negResult{}, fmt.Errorf("negotiation structure shorter than 8 bytes (%d)", len(rest))
	}
	negType := rest[0]
	value := binary.LittleEndian.Uint32(rest[4:8])
	switch negType {
	case 2: // RDP_NEG_RSP
		return negResult{requested: requested, selected: value}, nil
	case 3: // RDP Negotiation Failure
		return negResult{requested: requested, failed: true, failureCode: value}, nil
	default:
		return negResult{}, fmt.Errorf("unrecognized negotiation structure type %#x", negType)
	}
}

func readExact(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func printTable(w io.Writer, results []protocols.Finding, cm colorout.Mode) {
	type row struct{ target, kind, detail string }
	rows := make([]row, len(results))
	for i, f := range results {
		kind := f.Kind
		detail := f.Detail
		if f.Err != "" {
			kind, detail = "error", f.Err
		}
		rows[i] = row{target: f.Target.String(), kind: kind, detail: detail}
	}
	widths := [2]int{len("TARGET"), len("KIND")}
	for _, r := range rows {
		if n := len(r.target); n > widths[0] {
			widths[0] = n
		}
		if n := len(r.kind); n > widths[1] {
			widths[1] = n
		}
	}
	fmt.Fprintf(w, "%-*s  %-*s  %s\n", widths[0], "TARGET", widths[1], "KIND", "DETAIL")
	for i, r := range rows {
		color := colorout.Cyan
		switch results[i].Severity {
		case protocols.Medium, protocols.High:
			color = colorout.Yellow
		}
		if results[i].Kind == "error" {
			color = colorout.Gray
		}
		fmt.Fprintf(w, "%s  %s  %s\n",
			cm.PadWrap("", r.target, widths[0]),
			cm.PadWrap(color, r.kind, widths[1]),
			cm.Wrap("", r.detail))
	}
}

// Package vnc implements the vnc command, continuing the "SRT
// internal-pentest direction" doc's protocol-client roadmap beyond its
// original four: an RFB (RFC 6143) handshake/credential check. No
// maintained, widely-used Go VNC library exists (the ecosystem is
// abandoned forks of mitchellh/go-vnc), so this is a small, deliberately
// narrow hand-rolled client: version negotiation, security-type
// selection, and the two security types every real VNC deployment
// actually uses -- "None" (RFC 6143 7.2.1: no password at all, a real
// and not-uncommon misconfiguration) and "VNC Authentication" (7.2.2:
// the classic DES challenge-response) -- plus, on success, ClientInit/
// ServerInit far enough to read the desktop name and resolution. It
// never requests a framebuffer update or sends an input event: the
// remote desktop itself is never touched, only the login.
//
// Tight/RA2ne/VeNCrypt/TLS and the vendor security-type extensions
// aren't implemented: a server offering only those is reported as a
// banner Finding naming what it offered, not a failure -- there's
// nothing this client can do about a type it doesn't speak.
package vnc

import (
	"crypto/des" //nolint:staticcheck -- VNC Authentication is specified as DES; this is a protocol client, not a design choice
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
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
		Name:    "vnc",
		Group:   "PROTOCOL recon",
		Summary: "VNC (RFB) no-auth/password check (None and VNC Authentication security types only)",
		Run:     Run,
	})
}

// DefaultPort is VNC's conventional first display port (display :0).
const DefaultPort = 5900

// RFB security type IDs this package understands -- RFC 6143 7.2.
const (
	secInvalid = 0
	secNone    = 1
	secVNCAuth = 2
)

// Finding kinds this package reports.
const (
	KindNoAuth      = "no-auth"      // the server's only (or chosen) security type is None
	KindLoginOK     = "login-ok"     // a given -p password was accepted under VNC Authentication
	KindLoginFailed = "login-failed" // every password attempt was rejected
	KindBanner      = "banner"       // connected, but the server offers no security type this client speaks
)

func Run(args []string) error {
	fs := flag.NewFlagSet("vnc", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "CREDENTIALS", Names: []string{"p"}},
			{Title: "CONNECTION", Names: []string{"port", "timeout", "c"}},
			{Title: "OUTPUT", Names: []string{"o", "json", "color"}},
		})
	}
	in := fs.String("l", "", "target list: host or host:port (default: stdin, else the project db's port records -- see -from)")
	fb := store.BindInputFallback(fs, "vnc", "port")
	creds := protocols.BindCreds(fs)
	conn := protocols.BindConn(fs, DefaultPort, 8*time.Second)
	concurrency := fs.Int("c", 20, "concurrent connections")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of a table")
	colorFlag := fs.String("color", "auto", "color the output: auto|always|never (ignored with -json)")
	args = cli.ReorderArgs(fs, args)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	defer ioutil.StartHeartbeat("vnc")()

	lines, _, err := protocols.ResolveTargets(fb, *in, fs.Args())
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
			ioutil.Warn("vnc: %v", err)
			continue
		}
		targets = append(targets, t)
	}

	// -u/-H/-d/-k/-local-auth carry no meaning for VNC's classic security
	// types (RFC 6143 has no concept of a username, only a password) --
	// RawPasswords reads the raw -p list directly rather than Attempts,
	// which would require a -u to pair each one with and so would drop
	// every password a VNC-style invocation gives (srt vnc -p mypassword,
	// no -u at all). An empty password is never meaningfully "anonymous"
	// under VNC Authentication the way it is for other protocols -- that
	// case is what the None security type itself already covers.
	passwords := creds.RawPasswords()

	perTarget := make([][]protocols.Finding, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *concurrency))
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t protocols.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			perTarget[i] = probe(t, passwords, *conn.Timeout)
		}(i, t)
	}
	wg.Wait()

	var results []protocols.Finding
	for _, fs := range perTarget {
		results = append(results, fs...)
	}

	for _, f := range results {
		store.CurrentSink().Add(f.Record("vnc"))
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

// probe connects once to learn the server's offered security types. If
// None is among them, that is itself the finding -- an unauthenticated
// VNC session needs no password attempt. If VNC Authentication is
// offered instead, each password is tried in turn, dialing a fresh
// connection per attempt (the server closes the connection after a
// failed auth, per protocol). A server offering neither is reported as
// a banner Finding naming what it did offer.
//
// It always returns a [*] KindBanner Finding first (the server's
// version, plus the desktop name/size once a session actually gets in),
// followed by a separate, bare success/failure Finding -- no server
// detail folded into the "[+] (anonymous)"/"[+] <password>" line itself.
func probe(t protocols.Target, passwords []string, timeout time.Duration) []protocols.Finding {
	types, serverVersion, err := negotiate(t, timeout)
	if err != nil {
		return []protocols.Finding{{Target: t, Err: err.Error()}}
	}
	if !contains(types, secNone) && !contains(types, secVNCAuth) {
		return []protocols.Finding{{Target: t, Kind: KindBanner, Severity: protocols.Info,
			Detail: fmt.Sprintf("%s; no supported security type offered (got %v)", serverVersion, types)}}
	}
	if contains(types, secNone) {
		detail, err := finishLoginNoAuth(t, timeout)
		if err != nil {
			return []protocols.Finding{{Target: t, Err: err.Error()}}
		}
		return []protocols.Finding{
			{Target: t, Kind: KindBanner, Severity: protocols.Info, Detail: strings.TrimSpace(serverVersion + "; " + detail)},
			{Target: t, Kind: KindNoAuth, Severity: protocols.High, Accepted: true},
		}
	}

	var lastErr error
	for _, pw := range passwords {
		ok, detail, err := tryVNCAuth(t, pw, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		if ok {
			return []protocols.Finding{
				{Target: t, Kind: KindBanner, Severity: protocols.Info, Detail: strings.TrimSpace(serverVersion + "; " + detail)},
				{Target: t, Cred: protocols.Credential{Password: pw}, Kind: KindLoginOK, Severity: protocols.High, Accepted: true},
			}
		}
		lastErr = fmt.Errorf("authentication failed")
	}

	if len(passwords) == 0 {
		return []protocols.Finding{{Target: t, Kind: KindBanner, Severity: protocols.Info,
			Detail: serverVersion + "; VNC Authentication required, no -p password given to try"}}
	}
	detail := "every password was rejected"
	if lastErr != nil {
		detail = "rejected: " + lastErr.Error()
	}
	return []protocols.Finding{{Target: t, Kind: KindLoginFailed, Severity: protocols.Info, Detail: detail}}
}

// negotiate dials t, exchanges ProtocolVersion lines, and returns the
// security types the server offers -- RFC 6143 7.1.1/7.1.2.
func negotiate(t protocols.Target, timeout time.Duration) (types []byte, serverVersion string, err error) {
	netx.Request()
	raw, err := net.DialTimeout("tcp", t.String(), timeout)
	if err != nil {
		return nil, "", err
	}
	defer raw.Close()
	c := netx.CountConn(raw)
	c.SetDeadline(time.Now().Add(timeout))

	line, err := readExact(c, 12) // "RFB 003.008\n", always exactly 12 bytes
	if err != nil {
		return nil, "", fmt.Errorf("reading ProtocolVersion: %w", err)
	}
	serverVersion = strings.TrimSpace(string(line))
	if !strings.HasPrefix(serverVersion, "RFB ") {
		return nil, "", fmt.Errorf("not an RFB server (got %q)", serverVersion)
	}
	minor := minorVersion(serverVersion)

	if _, err := c.Write(line); err != nil { // echo the server's own version back: always a version it accepts
		return nil, "", fmt.Errorf("sending ProtocolVersion: %w", err)
	}

	if minor < 7 {
		// RFC 6143 7.1.2, pre-3.7: the server sends exactly one 4-byte
		// security type, no negotiation.
		b, err := readExact(c, 4)
		if err != nil {
			return nil, "", fmt.Errorf("reading security-type: %w", err)
		}
		sec := binary.BigEndian.Uint32(b)
		if sec == secInvalid {
			reason, _ := readReasonString(c)
			return nil, "", fmt.Errorf("connection failed: %s", reason)
		}
		return []byte{byte(sec)}, serverVersion, nil
	}

	n, err := readExact(c, 1)
	if err != nil {
		return nil, "", fmt.Errorf("reading security-type count: %w", err)
	}
	if n[0] == 0 {
		reason, _ := readReasonString(c)
		return nil, "", fmt.Errorf("connection failed: %s", reason)
	}
	types, err = readExact(c, int(n[0]))
	if err != nil {
		return nil, "", fmt.Errorf("reading security types: %w", err)
	}
	return types, serverVersion, nil
}

// finishLoginNoAuth completes the handshake for the None security type
// on a fresh connection: select it, read SecurityResult (3.8+ sends one
// even for None; 3.3-3.7 don't, so a short read here is tolerated, not
// fatal), then ClientInit/ServerInit for a desktop-name/resolution bonus.
func finishLoginNoAuth(t protocols.Target, timeout time.Duration) (string, error) {
	c, minor, err := dialAndSelect(t, timeout, secNone)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if minor >= 8 {
		if _, err := readSecurityResult(c); err != nil {
			return "", err
		}
	}
	return clientServerInit(c)
}

// tryVNCAuth completes the handshake for the VNC Authentication
// security type on a fresh connection with password pw: select it, DES-
// encrypt the 16-byte challenge (RFC 6143 7.2.2), and read whether the
// server accepted it. A false, nil-error return means the password was
// cleanly rejected (not a protocol/connection error) -- probe's lastErr
// path still gets a reason via the second case below either way.
//
// Real-world note, confirmed against a real TigerVNC server while
// testing this package: after enough recent failed attempts from the
// same client address, the server starts closing the NEXT connection
// before the handshake can finish at all (surfacing here as a write or
// read error, not a clean SecurityResult rejection) -- a built-in
// brute-force throttle, not a bug in this client. A long -p list
// against one target can therefore see later attempts fail for that
// reason rather than a genuinely wrong password; this package does not
// add its own inter-attempt delay to work around it, since one target
// throttling itself is a result worth seeing, not hiding.
func tryVNCAuth(t protocols.Target, pw string, timeout time.Duration) (ok bool, detail string, err error) {
	c, _, err := dialAndSelect(t, timeout, secVNCAuth)
	if err != nil {
		return false, "", err
	}
	defer c.Close()

	challenge, err := readExact(c, 16)
	if err != nil {
		return false, "", fmt.Errorf("reading VNC auth challenge: %w", err)
	}
	response, err := vncEncryptChallenge(challenge, pw)
	if err != nil {
		return false, "", err
	}
	if _, err := c.Write(response); err != nil {
		return false, "", fmt.Errorf("sending VNC auth response: %w", err)
	}

	accepted, err := readSecurityResult(c)
	if err != nil {
		return false, "", err
	}
	if !accepted {
		return false, "", nil
	}
	detail, err = clientServerInit(c)
	return true, detail, err
}

// dialAndSelect runs negotiate again on a fresh connection (VNC Auth's
// challenge is tied to the connection it was issued on, and a server is
// free to close the connection after a rejected attempt, so each try
// gets its own socket, same convention smb/ldap use for a credential
// retry) and sends the one-byte chosen security type.
func dialAndSelect(t protocols.Target, timeout time.Duration, want byte) (net.Conn, int, error) {
	netx.Request()
	raw, err := net.DialTimeout("tcp", t.String(), timeout)
	if err != nil {
		return nil, 0, err
	}
	c := netx.CountConn(raw)
	c.SetDeadline(time.Now().Add(timeout))

	line, err := readExact(c, 12)
	if err != nil {
		c.Close()
		return nil, 0, fmt.Errorf("reading ProtocolVersion: %w", err)
	}
	serverVersion := strings.TrimSpace(string(line))
	minor := minorVersion(serverVersion)
	if _, err := c.Write(line); err != nil {
		c.Close()
		return nil, 0, fmt.Errorf("sending ProtocolVersion: %w", err)
	}

	if minor < 7 {
		if _, err := readExact(c, 4); err != nil { // the single security type, already known from the first negotiate call
			c.Close()
			return nil, 0, err
		}
		return c, minor, nil // pre-3.7 never sends a chosen-type byte -- the server's one offer is implicitly selected
	}

	n, err := readExact(c, 1)
	if err != nil {
		c.Close()
		return nil, 0, err
	}
	if _, err := readExact(c, int(n[0])); err != nil { // the types list, already known
		c.Close()
		return nil, 0, err
	}
	if _, err := c.Write([]byte{want}); err != nil {
		c.Close()
		return nil, 0, fmt.Errorf("selecting security type: %w", err)
	}
	return c, minor, nil
}

// clientServerInit sends ClientInit (shared session) and reads enough
// of ServerInit to report the framebuffer resolution and desktop name --
// RFC 6143 7.3.1/7.3.2. It never requests a framebuffer update or sends
// an input event afterward.
func clientServerInit(c net.Conn) (string, error) {
	if _, err := c.Write([]byte{1}); err != nil { // shared-flag = 1 (don't disconnect other viewers)
		return "", fmt.Errorf("sending ClientInit: %w", err)
	}
	head, err := readExact(c, 24) // width(2) height(2) pixel-format(16) name-length(4)
	if err != nil {
		return "", fmt.Errorf("reading ServerInit: %w", err)
	}
	width := binary.BigEndian.Uint16(head[0:2])
	height := binary.BigEndian.Uint16(head[2:4])
	nameLen := binary.BigEndian.Uint32(head[20:24])
	if nameLen > 1<<16 { // generous but bounded -- never trust a length field this directly
		nameLen = 1 << 16
	}
	name, err := readExact(c, int(nameLen))
	if err != nil {
		return "", fmt.Errorf("reading ServerInit name: %w", err)
	}
	return fmt.Sprintf("%dx%d, desktop %q", width, height, string(name)), nil
}

func readSecurityResult(c net.Conn) (bool, error) {
	b, err := readExact(c, 4)
	if err != nil {
		return false, fmt.Errorf("reading SecurityResult: %w", err)
	}
	if binary.BigEndian.Uint32(b) == 0 {
		return true, nil
	}
	return false, nil
}

func readReasonString(c net.Conn) (string, error) {
	lb, err := readExact(c, 4)
	if err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint32(lb)
	if n > 4096 {
		n = 4096
	}
	reason, err := readExact(c, int(n))
	return string(reason), err
}

func readExact(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

// minorVersion parses "RFB 003.00X" -> X; a malformed or unrecognized
// string is treated as 3 (the pre-negotiation form), the conservative
// choice since that path reads less and expects less structure.
func minorVersion(version string) int {
	var major, minor int
	if _, err := fmt.Sscanf(version, "RFB %d.%d", &major, &minor); err != nil {
		return 3
	}
	return minor
}

func contains(types []byte, want byte) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
}

// vncEncryptChallenge implements RFC 6143 7.2.2's VNC Authentication:
// the password, truncated/zero-padded to 8 bytes, becomes a DES key
// with each byte's BITS reversed (a historical quirk of the original
// RealVNC implementation every since-then server and client has had to
// match), used to ECB-encrypt the 16-byte challenge as two independent
// 8-byte blocks.
func vncEncryptChallenge(challenge []byte, password string) ([]byte, error) {
	if len(challenge) != 16 {
		return nil, fmt.Errorf("challenge must be 16 bytes, got %d", len(challenge))
	}
	key := make([]byte, 8)
	copy(key, password) // password longer than 8 bytes is truncated, per RFC 6143
	for i, b := range key {
		key[i] = reverseBits(b)
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	response := make([]byte, 16)
	block.Encrypt(response[0:8], challenge[0:8])
	block.Encrypt(response[8:16], challenge[8:16])
	return response, nil
}

func reverseBits(b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		r <<= 1
		r |= (b >> i) & 1
	}
	return r
}

// printTable renders results in netexec's own one-line-per-result style
// (see protocols.Finding.Line), not a table: "VNC  host  port  hostname
// [symbol] message". VNC has no username concept at all (RFB
// Authentication is a bare password), so a successful login's message is
// just the password, not Credential.UserPass's generic "user:secret"
// form. Full remote-desktop control, authenticated or not, is the same
// access-level claim ssh/telnet make for a shell -- so both KindNoAuth
// and KindLoginOK are marked "(Pwn3d!)".
func printTable(w io.Writer, results []protocols.Finding, cm colorout.Mode) {
	for _, f := range results {
		if f.Err != "" {
			fmt.Fprintln(w, f.Line("vnc", cm, protocols.SymFailure, f.Err, false))
			continue
		}
		switch f.Kind {
		case KindNoAuth:
			fmt.Fprintln(w, f.Line("vnc", cm, protocols.SymSuccess, "(anonymous)", true))
		case KindLoginOK:
			// VNC's classic security types have no username (RFC 6143)
			// -- Cred.CredText's anonymous check would misfire on a
			// User-less-but-real password, so this shows the password
			// directly, same as before.
			fmt.Fprintln(w, f.Line("vnc", cm, protocols.SymSuccess, f.Cred.Password, true))
		case KindLoginFailed:
			fmt.Fprintln(w, f.Line("vnc", cm, protocols.SymFailure, f.Detail, false))
		default: // KindBanner
			fmt.Fprintln(w, f.Line("vnc", cm, protocols.SymInfo, f.Detail, false))
		}
	}
}

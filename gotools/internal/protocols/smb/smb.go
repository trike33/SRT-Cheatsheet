// Package smb implements the smb command: Phase 1 of the "SRT
// internal-pentest direction" doc's protocol-client roadmap. It wraps
// github.com/hirochachacha/go-smb2, the doc's chosen base SMB 2/3
// library, with SRT's own connection metering (netx), credential
// attempts (protocols.Creds) and results-database wiring (store).
//
// Phase 1's default behavior is the anonymous/null-session check:
// every target is tried with an anonymous session first (no flags
// needed at all), then with each -u/-p/-H attempt in turn if any were
// given -- NTLM only (go-smb2 doesn't speak Kerberos; -k is accepted
// for CLI-schema consistency across every protocol command but not yet
// implemented here, see docs/ROADMAP.md). A session that's accepted is
// followed by a read-only share listing and a shallow per-share
// read-access check (ReadDir on the share root); this package never
// writes, deletes or creates anything on the target.
package smb

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	smb2 "github.com/hirochachacha/go-smb2"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "smb",
		Group:   "PROTOCOL recon",
		Summary: "SMB 2/3 anonymous/NTLM session + share listing and read-access check",
		Run:     Run,
	})
}

// DefaultPort is SMB's well-known port (SMB over TCP, no NetBIOS session service).
const DefaultPort = 445

// Finding kinds this package reports.
const (
	KindAnonymousLogin = "anonymous-login" // an anonymous/null session was accepted
	KindLoginOK        = "login-ok"        // a given -u/-p/-H credential was accepted
	KindLoginFailed    = "login-failed"    // every given credential (and anonymous) was rejected
)

// sharesToProbe caps how many non-admin shares get an actual ReadDir
// check per target, so a server with hundreds of shares doesn't turn
// one target into hundreds of extra round trips.
const sharesToProbe = 20

func Run(args []string) error {
	fs := flag.NewFlagSet("smb", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "CREDENTIALS", Names: []string{"u", "p", "H", "d", "local-auth", "k"}},
			{Title: "CONNECTION", Names: []string{"port", "timeout", "c"}},
			{Title: "OUTPUT", Names: []string{"o", "json", "color"}},
		})
	}
	in := fs.String("l", "", "target list: host or host:port (default: stdin, else the project db's port records -- see -from)")
	fb := store.BindInputFallback(fs, "smb", "port")
	creds := protocols.BindCreds(fs)
	conn := protocols.BindConn(fs, DefaultPort, 10*time.Second)
	concurrency := fs.Int("c", 10, "concurrent sessions")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of a table")
	colorFlag := fs.String("color", "auto", "color the table output: auto|always|never (ignored with -json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	if extraP, extraH := creds.Dangling(); extraP > 0 || extraH > 0 {
		ioutil.Warn("smb: %d -p and %d -H value(s) have no matching -u and will be ignored", extraP, extraH)
	}
	defer ioutil.StartHeartbeat("smb")()

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
			ioutil.Warn("smb: %v", err)
			continue
		}
		targets = append(targets, t)
	}

	attempts := creds.Attempts()
	results := make([]protocols.Finding, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *concurrency))
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t protocols.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = probe(t, attempts, *conn.Timeout)
		}(i, t)
	}
	wg.Wait()

	for _, f := range results {
		store.CurrentSink().Add(f.Record("smb"))
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

// probe tries each credential attempt against t in turn, dialing a
// fresh TCP connection per attempt (an SMB session that fails NTLM
// authentication isn't a safe connection to reuse for a retry -- a
// server is free to tear it down, and SRT would rather redial than
// guess at its state). The first attempt a session accepts wins; a
// successful session is followed by a read-only share listing.
func probe(t protocols.Target, attempts []protocols.Credential, timeout time.Duration) protocols.Finding {
	var lastErr error
	for _, cr := range attempts {
		if cr.Kerberos {
			continue // go-smb2 speaks NTLM only; Kerberos is Phase 2+ (see docs/ROADMAP.md)
		}
		init, err := buildInitiator(cr)
		if err != nil {
			lastErr = err
			continue
		}

		netx.Request()
		raw, err := net.DialTimeout("tcp", t.String(), timeout)
		if err != nil {
			return protocols.Finding{Target: t, Err: err.Error()}
		}
		c := netx.CountConn(raw)
		c.SetDeadline(time.Now().Add(timeout))

		d := &smb2.Dialer{Initiator: init}
		sess, err := d.Dial(c)
		if err != nil {
			c.Close()
			lastErr = err
			continue
		}

		detail := summarizeShares(sess)
		sess.Logoff()
		c.Close()

		kind := KindLoginOK
		if cr.IsAnonymous() {
			kind = KindAnonymousLogin
		}
		sev := protocols.High
		if !strings.Contains(detail, "readable") {
			sev = protocols.Medium // session accepted, but nothing beyond IPC$ was actually readable
		}
		return protocols.Finding{Target: t, Cred: cr, Kind: kind, Severity: sev, Detail: detail}
	}

	detail := "every login attempt was rejected"
	if lastErr != nil {
		detail = "rejected: " + lastErr.Error()
	}
	return protocols.Finding{Target: t, Kind: KindLoginFailed, Severity: protocols.Info, Detail: detail}
}

// buildInitiator turns a Credential into the NTLMInitiator go-smb2
// expects: an empty user/password for Anonymous (a null session), a
// plain password, or -- go-smb2 supports this directly -- pass-the-hash
// when cr.Hash is set (accepted either as a bare NT hash or netexec's
// "LM:NT" form, the LM half ignored).
func buildInitiator(cr protocols.Credential) (*smb2.NTLMInitiator, error) {
	domain := cr.Domain
	if cr.LocalAuth {
		domain = "" // authenticate against the target's local SAM, not the domain
	}
	init := &smb2.NTLMInitiator{User: cr.User, Password: cr.Password, Domain: domain}
	if cr.Hash != "" {
		h, err := parseHash(cr.Hash)
		if err != nil {
			return nil, fmt.Errorf("-H %q: %w", cr.Hash, err)
		}
		init.Hash = h
	}
	return init, nil
}

// parseHash accepts a bare 32-hex-digit NT hash, or netexec's
// "LM:NT" form (the LM half is ignored -- NTLMv2, which go-smb2 speaks,
// never uses it).
func parseHash(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[i+1:]
	}
	h, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not valid hex: %w", err)
	}
	if len(h) != 16 {
		return nil, fmt.Errorf("want a 16-byte (32 hex digit) NT hash, got %d bytes", len(h))
	}
	return h, nil
}

// summarizeShares lists sess's shares and, for up to sharesToProbe of
// them (skipping IPC$, which isn't a filesystem), checks whether its
// root directory can actually be read -- the distinction netexec's own
// output draws between "share exists" and "share is actually open".
func summarizeShares(sess *smb2.Session) string {
	names, err := sess.ListSharenames()
	if err != nil {
		return "session accepted, but share enumeration failed: " + err.Error()
	}
	if len(names) == 0 {
		return "session accepted; no shares enumerated"
	}

	checked := 0
	var parts []string
	for _, name := range names {
		if strings.EqualFold(name, "IPC$") {
			parts = append(parts, name+" (IPC)")
			continue
		}
		if checked >= sharesToProbe {
			parts = append(parts, name)
			continue
		}
		checked++
		parts = append(parts, name+" ("+shareAccess(sess, name)+")")
	}
	return fmt.Sprintf("%d share(s): %s", len(names), strings.Join(parts, ", "))
}

// shareAccess reports whether share's root directory can be listed
// ("readable") or the tree connect/listing was denied ("no-access"),
// without ever writing to or through the share.
func shareAccess(sess *smb2.Session, share string) string {
	fs, err := sess.Mount(share)
	if err != nil {
		return "no-access"
	}
	defer fs.Umount()
	if _, err := fs.ReadDir("."); err != nil {
		return "listed, not readable"
	}
	return "readable"
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
		if !f.Cred.IsAnonymous() {
			detail = f.Cred.String() + ": " + detail
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
		switch results[i].Kind {
		case KindAnonymousLogin, KindLoginOK:
			color = colorout.Red
		case "error":
			color = colorout.Gray
		case KindLoginFailed:
			color = colorout.Green
		}
		fmt.Fprintf(w, "%s  %s  %s\n",
			cm.PadWrap("", r.target, widths[0]),
			cm.PadWrap(color, r.kind, widths[1]),
			cm.Wrap("", r.detail))
	}
}

// Package ftp implements the ftp command: Phase 1 of the "SRT
// internal-pentest direction" doc's protocol-client roadmap. It wraps
// github.com/jlaffaye/ftp, the doc's chosen FTP library -- "FTP is
// simple enough that impacket adds little beyond what any client
// gives you" -- with SRT's own connection metering (netx), credential
// attempts (protocols.Creds) and results-database wiring (store).
//
// Phase 1's default behavior, per the doc's CLI flag schema, is the
// anonymous-access check: every target is tried with an anonymous
// login first (no flags needed at all), then with each -u/-p/-H
// attempt in turn if any were given. A successful login -- anonymous
// or not -- is followed by a read-only listing of the server's root
// directory; this package never writes, deletes or renames anything
// on the target, even when a login grants write access, since proving
// that would mean leaving a file behind.
package ftp

import (
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	ftplib "github.com/jlaffaye/ftp"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "ftp",
		Group:   "PROTOCOL recon",
		Summary: "FTP anonymous-login check (+ root listing) -- optionally tries -u/-p/-H credentials",
		Run:     Run,
	})
}

// DefaultPort is FTP's well-known control-channel port.
const DefaultPort = 21

// anonymousPassword is the conventional placeholder RFC 1635 suggests
// for an anonymous FTP login's "email address" field -- a generic,
// non-identifying string, never anything naming the person or
// engagement running srt.
const anonymousPassword = "anonymous@srt.local"

// Finding kinds this package reports.
const (
	KindAnonymousLogin = "anonymous-login" // anonymous login accepted
	KindLoginOK        = "login-ok"        // a given -u/-p/-H credential was accepted
	KindLoginFailed    = "login-failed"    // every given credential (and anonymous) was rejected
)

func Run(args []string) error {
	fs := flag.NewFlagSet("ftp", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "CREDENTIALS", Names: []string{"u", "p", "H", "d", "local-auth", "k"}},
			{Title: "CONNECTION", Names: []string{"port", "timeout", "c"}},
			{Title: "OUTPUT", Names: []string{"o", "json", "color"}},
		})
	}
	in := fs.String("l", "", "target list: host or host:port (default: stdin, else the project db's port records -- see -from)")
	fb := store.BindInputFallback(fs, "ftp", "port")
	creds := protocols.BindCreds(fs)
	conn := protocols.BindConn(fs, DefaultPort, 10*time.Second)
	concurrency := fs.Int("c", 20, "concurrent connections")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of a table")
	colorFlag := fs.String("color", "auto", "color the table output: auto|always|never (ignored with -json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	if extraP, extraH := creds.Dangling(); extraP > 0 || extraH > 0 {
		ioutil.Warn("ftp: %d -p and %d -H value(s) have no matching -u and will be ignored", extraP, extraH)
	}
	defer ioutil.StartHeartbeat("ftp")()

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
			ioutil.Warn("ftp: %v", err)
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
		store.CurrentSink().Add(f.Record("ftp"))
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

// probe dials t once and tries each credential attempt against that one
// connection in order (anonymous first, unless -u was given -- see
// protocols.Creds.Attempts), stopping at the first that logs in. A
// successful login is followed by a read-only root-directory listing;
// nothing is ever written, deleted or renamed.
func probe(t protocols.Target, attempts []protocols.Credential, timeout time.Duration) protocols.Finding {
	// A custom DialFunc, not DialWithNetConn: the control connection is
	// only the first of possibly several the library opens -- NameList
	// (and List, were Phase 2 to add it) opens a second, separate data
	// connection to whatever port EPSV/PASV hands back. DialWithNetConn
	// hands back the SAME pre-dialed conn for every address asked for,
	// which breaks the data connection; a DialFunc dials each address it
	// is actually given, so both the control and data connections get
	// netx's metering/rate-gating (the same convention portscan/traceroute
	// use for a raw net.Conn) without SRT re-implementing EPSV/PASV itself.
	dial := func(network, address string) (net.Conn, error) {
		netx.Request()
		c, err := net.DialTimeout(network, address, timeout)
		if err != nil {
			return nil, err
		}
		return netx.CountConn(c), nil
	}
	c, err := ftplib.Dial(t.String(),
		ftplib.DialWithDialFunc(dial),
		ftplib.DialWithTimeout(timeout),
		ftplib.DialWithShutTimeout(timeout))
	if err != nil {
		return protocols.Finding{Target: t, Err: err.Error()}
	}
	defer c.Quit()

	var lastErr error
	for _, cr := range attempts {
		user, pass := cr.User, cr.Password
		if cr.IsAnonymous() {
			user, pass = "anonymous", anonymousPassword
		}
		if err := c.Login(user, pass); err != nil {
			lastErr = err
			continue
		}
		detail := "login accepted"
		if names, lerr := c.NameList(""); lerr == nil {
			detail = fmt.Sprintf("login accepted; root listing: %s", summarizeNames(names))
		}
		kind := KindLoginOK
		if cr.IsAnonymous() {
			kind = KindAnonymousLogin
		}
		return protocols.Finding{Target: t, Cred: cr, Kind: kind, Severity: protocols.High, Detail: detail}
	}

	detail := "every login attempt was rejected"
	if lastErr != nil {
		detail = "rejected: " + lastErr.Error()
	}
	return protocols.Finding{Target: t, Kind: KindLoginFailed, Severity: protocols.Info, Detail: detail}
}

// summarizeNames renders a root listing compactly for a Finding's
// Detail: the count plus up to 8 names, so a server with thousands of
// files doesn't blow out the table/record.
func summarizeNames(names []string) string {
	if len(names) == 0 {
		return "(empty)"
	}
	shown := names
	more := 0
	if len(shown) > 8 {
		more = len(shown) - 8
		shown = shown[:8]
	}
	s := fmt.Sprintf("%d entries: %s", len(names), strings.Join(shown, ", "))
	if more > 0 {
		s += fmt.Sprintf(", +%d more", more)
	}
	return s
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

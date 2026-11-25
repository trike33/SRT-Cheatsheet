// Package telnet implements the telnet command: Phase 1 of the "SRT
// internal-pentest direction" doc's protocol-client roadmap. Telnet is a
// thin text protocol over net.Dial -- no library needed, a raw-socket
// client is enough (per the doc's protocol table) -- so this package
// only does the minimum IAC option negotiation (decline everything) to
// keep a server from hanging on a negotiation srt doesn't care about,
// then reads whatever text follows: a login prompt (the common,
// unremarkable case) or, more interestingly, a shell prompt with no
// login at all -- an unauthenticated-access finding worth flagging on
// any internal engagement.
//
// Per the doc's CLI flag schema, srt telnet needs no protocol-specific
// flags for Phase 1 beyond the global ones every protocol command
// shares (protocols.BindCreds/BindConn): the default behavior is the
// anonymous-access check; -u/-p, when given, are used to attempt an
// actual login over the same connection.
package telnet

import (
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
		Name:    "telnet",
		Group:   "PROTOCOL recon",
		Summary: "Telnet banner grab + unauthenticated-shell / login check (optionally attempts -u/-p login)",
		Run:     Run,
	})
}

// DefaultPort is telnet's well-known port.
const DefaultPort = 23

// Telnet IAC (Interpret As Command) protocol bytes -- RFC 854/855. This
// package negotiates nothing it actually wants; it only needs to answer
// every DO/WILL with a DONT/WONT so a server waiting on option
// negotiation doesn't stall the read, then treat everything else as
// plain text.
const (
	iac  = 255
	dont = 254
	do   = 253
	wont = 252
	will = 251
	sb   = 250
	se   = 240
)

// Finding kinds this package reports.
const (
	KindBanner      = "banner"       // a login prompt was shown -- the ordinary, unremarkable case
	KindNoAuth      = "no-auth"      // a shell-like prompt appeared with no login at all
	KindLoginOK     = "login-ok"     // -u/-p was given and a login attempt succeeded
	KindLoginFailed = "login-failed" // -u/-p was given and the login attempt was rejected
)

func Run(args []string) error {
	fs := flag.NewFlagSet("telnet", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "CREDENTIALS", Names: []string{"u", "p", "H", "d", "local-auth", "k"}},
			{Title: "CONNECTION", Names: []string{"port", "timeout", "c"}},
			{Title: "OUTPUT", Names: []string{"o", "json", "color"}},
		})
	}
	in := fs.String("l", "", "target list: host or host:port (default: stdin, else the project db's port records -- see -from)")
	fb := store.BindInputFallback(fs, "telnet", "port")
	creds := protocols.BindCreds(fs)
	conn := protocols.BindConn(fs, DefaultPort, 8*time.Second)
	concurrency := fs.Int("c", 20, "concurrent connections")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of a table")
	colorFlag := fs.String("color", "auto", "color the table output: auto|always|never (ignored with -json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	if extraP, extraH := creds.Dangling(); extraP > 0 || extraH > 0 {
		ioutil.Warn("telnet: %d -p and %d -H value(s) have no matching -u and will be ignored", extraP, extraH)
	}
	defer ioutil.StartHeartbeat("telnet")()

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
			ioutil.Warn("telnet: %v", err)
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
		store.CurrentSink().Add(f.Record("telnet"))
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

// probe tries each credential attempt against t in order, stopping at
// the first one worth reporting: an anonymous probe that finds a shell
// with no login at all is the headline finding (KindNoAuth, High) and
// nothing else needs trying; otherwise it reports the banner/prompt it
// saw, then -- if any real credentials were given -- attempts a login
// with each in turn until one succeeds or all are exhausted.
func probe(t protocols.Target, attempts []protocols.Credential, timeout time.Duration) protocols.Finding {
	netx.Request()
	raw, err := net.DialTimeout("tcp", t.String(), timeout)
	if err != nil {
		return protocols.Finding{Target: t, Err: err.Error()}
	}
	defer raw.Close()
	c := netx.CountConn(raw)
	c.SetDeadline(time.Now().Add(timeout))

	banner := readText(c, 1500*time.Millisecond)
	prompt := classifyPrompt(banner)

	if prompt == promptShell {
		return protocols.Finding{Target: t, Kind: KindNoAuth, Severity: protocols.High,
			Detail: "unauthenticated shell prompt on connect: " + trimForDetail(banner)}
	}
	if prompt != promptLogin {
		// Neither a recognized login prompt nor a shell -- still worth a
		// record (an unusual banner, or the server closed early), just
		// not something to attempt a login against.
		return protocols.Finding{Target: t, Kind: KindBanner, Severity: protocols.Info, Detail: trimForDetail(banner)}
	}

	for _, cr := range attempts {
		if cr.IsAnonymous() {
			continue // no username to answer the login prompt with
		}
		ok, transcript := attemptLogin(c, cr, timeout)
		kind, sev := KindLoginFailed, protocols.Low
		if ok {
			kind, sev = KindLoginOK, protocols.High
		}
		return protocols.Finding{Target: t, Cred: cr, Kind: kind, Severity: sev, Detail: trimForDetail(transcript)}
	}
	return protocols.Finding{Target: t, Kind: KindBanner, Severity: protocols.Info, Detail: trimForDetail(banner)}
}

type promptKind int

const (
	promptNone promptKind = iota
	promptLogin
	promptShell
)

// classifyPrompt reads the heuristics every telnet client has to use:
// no formal protocol marks a login prompt or a shell prompt, so this
// looks for the conventional wording ("login:", "username:") versus a
// trailing shell-style prompt character with no login wording at all.
func classifyPrompt(banner string) promptKind {
	lower := strings.ToLower(banner)
	if strings.Contains(lower, "login:") || strings.Contains(lower, "username:") || strings.Contains(lower, "user name:") {
		return promptLogin
	}
	trimmed := strings.TrimRight(banner, "\r\n \t")
	if trimmed == "" {
		return promptNone
	}
	last := trimmed[len(trimmed)-1]
	if last == '$' || last == '#' || last == '>' || last == '%' {
		return promptShell
	}
	return promptNone
}

// attemptLogin answers a "login:"/"Password:" sequence with cr's
// username/password and reports whether the transcript that followed
// looks like a successful login (a new shell prompt) rather than a
// rejection ("incorrect", "failed", or another login prompt).
func attemptLogin(c net.Conn, cr protocols.Credential, timeout time.Duration) (ok bool, transcript string) {
	c.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(c, "%s\r\n", cr.User)
	afterUser := readText(c, 1200*time.Millisecond)
	transcript = afterUser

	lower := strings.ToLower(afterUser)
	if strings.Contains(lower, "password:") {
		c.SetDeadline(time.Now().Add(timeout))
		fmt.Fprintf(c, "%s\r\n", cr.Password)
		afterPass := readText(c, 1500*time.Millisecond)
		transcript += afterPass
		return classifyPrompt(afterPass) == promptShell, transcript
	}
	// No password prompt at all (password-less local account, or the
	// server echoed straight to a shell) -- judge directly on what
	// followed the username.
	return classifyPrompt(afterUser) == promptShell, transcript
}

// readText reads from c until it goes quiet for a short idle gap or the
// deadline window elapses, stripping Telnet IAC negotiation sequences
// (answered minimally below) and returning the remaining text.
func readText(c net.Conn, window time.Duration) string {
	deadline := time.Now().Add(window)
	var out []byte
	buf := make([]byte, 4096)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		c.SetReadDeadline(time.Now().Add(min(remaining, 300*time.Millisecond)))
		n, err := c.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			break // timeout (idle gap reached) or the connection closed
		}
	}
	return stripIAC(c, out)
}

// stripIAC removes Telnet IAC option-negotiation sequences from b,
// answering every DO/WILL request it finds with DONT/WONT (so a server
// waiting on a reply doesn't stall the next read) and returning the
// plain text that's left.
func stripIAC(c net.Conn, b []byte) string {
	var text []byte
	for i := 0; i < len(b); i++ {
		if b[i] != iac || i+1 >= len(b) {
			text = append(text, b[i])
			continue
		}
		cmd := b[i+1]
		switch cmd {
		case do, will:
			if i+2 < len(b) {
				opt := b[i+2]
				reply := wont
				if cmd == do {
					reply = dont
				}
				c.Write([]byte{iac, byte(reply), opt})
				i += 2
			} else {
				i++
			}
		case dont, wont:
			if i+2 < len(b) {
				i += 2
			} else {
				i++
			}
		case sb:
			// Subnegotiation: skip to IAC SE, or to the end if it never
			// arrives in this read (rare with the options we decline).
			j := i + 2
			for j+1 < len(b) && !(b[j] == iac && b[j+1] == se) {
				j++
			}
			i = j + 1
		default:
			i++
		}
	}
	return string(text)
}

func trimForDetail(s string) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\r' {
			return -1
		}
		return r
	}, s))
	if len(s) > 300 {
		s = s[:300] + "..."
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
		case KindNoAuth, KindLoginOK:
			color = colorout.Red
		case "error":
			color = colorout.Gray
		case KindLoginFailed:
			color = colorout.Yellow
		}
		fmt.Fprintf(w, "%s  %s  %s\n",
			cm.PadWrap("", r.target, widths[0]),
			cm.PadWrap(color, r.kind, widths[1]),
			cm.Wrap("", r.detail))
	}
}

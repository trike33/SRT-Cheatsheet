// Package ssh implements the ssh command, continuing the "SRT
// internal-pentest direction" doc's protocol-client roadmap beyond its
// original four: an SSH banner/credential check wrapping
// golang.org/x/crypto/ssh, Go's own standard-grade SSH implementation
// (both client and server sides -- this package's own tests drive the
// client against that same library's server side, a materially higher
// confidence level than the hand-rolled fake servers ftp/ldap/telnet
// rely on).
//
// The default behavior is the anonymous/no-auth check: every target is
// tried with no credentials at all first (RFC 4252's "none" method,
// which the client always sends first regardless of what's configured
// -- a server that accepts it outright needs no password, a real and
// not-uncommon misconfiguration), then each -u/-p attempt, and -key
// (a private key file, paired with -u the same way -p is) if given.
// This package never opens a shell or runs a command: it only
// completes the SSH handshake and authentication, then disconnects --
// the same boundary ftp/smb/ldap draw around "never writes, deletes or
// executes anything on the target".
package ssh

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "ssh",
		Group:   "PROTOCOL recon",
		Summary: "SSH banner + no-auth/-u/-p/-key credential check (never opens a shell or runs a command)",
		Run:     Run,
	})
}

// DefaultPort is SSH's well-known port.
const DefaultPort = 22

// Finding kinds this package reports.
const (
	KindBanner      = "banner"       // connected and exchanged versions; no credential was accepted (or none was tried)
	KindNoAuth      = "no-auth"      // the server accepted a connection with no authentication at all
	KindLoginOK     = "login-ok"     // a given -u/-p or -key credential was accepted
	KindLoginFailed = "login-failed" // every attempt (no-auth included) was rejected
)

func Run(args []string) error {
	fs := flag.NewFlagSet("ssh", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "CREDENTIALS", Names: []string{"u", "p", "key"}},
			{Title: "CONNECTION", Names: []string{"port", "timeout", "c"}},
			{Title: "OUTPUT", Names: []string{"o", "json", "color"}},
		})
	}
	in := fs.String("l", "", "target list: host or host:port (default: stdin, else the project db's port records -- see -from)")
	fb := store.BindInputFallback(fs, "ssh", "port")
	creds := protocols.BindCreds(fs)
	keyPath := fs.String("key", "", "private key file for public-key auth, tried alongside -p for every -u (the key's own passphrase, if it has one, is the first -p value)")
	conn := protocols.BindConn(fs, DefaultPort, 8*time.Second)
	concurrency := fs.Int("c", 20, "concurrent connections")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of a table")
	colorFlag := fs.String("color", "auto", "color the output: auto|always|never (ignored with -json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	if extraP, extraH := creds.Dangling(); extraP > 0 || extraH > 0 {
		ioutil.Warn("ssh: %d -p and %d -H value(s) have no matching -u and will be ignored", extraP, extraH)
	}
	defer ioutil.StartHeartbeat("ssh")()

	var signer cryptossh.Signer
	if *keyPath != "" {
		s, err := loadSigner(*keyPath, creds)
		if err != nil {
			return fmt.Errorf("-key %q: %w", *keyPath, err)
		}
		signer = s
	}

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
			ioutil.Warn("ssh: %v", err)
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
			results[i] = probe(t, attempts, signer, *conn.Timeout)
		}(i, t)
	}
	wg.Wait()

	for _, f := range results {
		store.CurrentSink().Add(f.Record("ssh"))
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

// loadSigner reads and parses -key's private key file. A passphrase
// comes from the first -p value, if any (keys and passwords share that
// one flag by design -- see protocols.BindCreds -- so this is the only
// reasonable place a key's own passphrase can come from).
func loadSigner(path string, creds *protocols.Creds) (cryptossh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if signer, err := cryptossh.ParsePrivateKey(data); err == nil {
		return signer, nil
	}
	for _, cr := range creds.Attempts() {
		if cr.Password != "" {
			return cryptossh.ParsePrivateKeyWithPassphrase(data, []byte(cr.Password))
		}
	}
	return nil, fmt.Errorf("key is encrypted and no -p passphrase was given")
}

// probe tries each credential attempt against t in turn, dialing a
// fresh TCP connection per attempt. The first attempt the server
// accepts wins. A connection-level failure (refused, timed out,
// unreachable) aborts the whole target immediately; an authentication
// rejection just moves on to the next attempt.
func probe(t protocols.Target, attempts []protocols.Credential, signer cryptossh.Signer, timeout time.Duration) protocols.Finding {
	banner, err := grabBanner(t, timeout)
	if err != nil {
		return protocols.Finding{Target: t, Err: err.Error()}
	}

	var lastErr error
	for _, cr := range attempts {
		netx.Request()
		raw, err := net.DialTimeout("tcp", t.String(), timeout)
		if err != nil {
			return protocols.Finding{Target: t, Err: err.Error()}
		}
		c := netx.CountConn(raw)
		c.SetDeadline(time.Now().Add(timeout))

		cfg := &cryptossh.ClientConfig{
			User:            cr.User,
			HostKeyCallback: cryptossh.InsecureIgnoreHostKey(), // fingerprinting a login, not pinning a known host
			Timeout:         timeout,
		}
		if cr.Password != "" {
			cfg.Auth = append(cfg.Auth, cryptossh.Password(cr.Password))
		}
		if signer != nil && !cr.IsAnonymous() {
			cfg.Auth = append(cfg.Auth, cryptossh.PublicKeys(signer))
		}

		sc, chans, reqs, err := cryptossh.NewClientConn(c, t.String(), cfg)
		if err != nil {
			c.Close() // NewClientConn always closes c itself too on error, but doing it here as well is harmless and keeps the call sites symmetric
			lastErr = err
			continue
		}

		client := cryptossh.NewClient(sc, chans, reqs)
		client.Close()

		if cr.IsAnonymous() {
			return protocols.Finding{Target: t, Kind: KindNoAuth, Severity: protocols.High,
				Detail: "server accepted a connection with no authentication at all" + bannerSuffix(banner), Accepted: true}
		}
		return protocols.Finding{Target: t, Cred: cr, Kind: KindLoginOK, Severity: protocols.High,
			Detail: "login accepted" + bannerSuffix(banner), Accepted: true}
	}

	if len(attempts) == 1 {
		// Anonymous only, no -u given at all: rejecting "none" is the
		// overwhelmingly normal case, so this is a banner Finding, not a
		// failure -- there was nothing else to try.
		return protocols.Finding{Target: t, Kind: KindBanner, Severity: protocols.Info, Detail: trimBanner(banner)}
	}
	detail := "every attempt was rejected"
	if lastErr != nil {
		detail = "rejected: " + lastErr.Error()
	}
	detail += bannerSuffix(banner)
	return protocols.Finding{Target: t, Kind: KindLoginFailed, Severity: protocols.Info, Detail: detail}
}

// grabBanner reads the server's SSH identification line (RFC 4253
// 4.2 -- sent in the clear, before any encryption or authentication)
// over its own short-lived connection, independently of the handshake
// attempts in probe: x/crypto/ssh's NewClientConn always closes its
// connection and returns a nil Conn on any handshake failure (including
// a rejected "none" attempt, the overwhelmingly common case for the
// very first attempt below), with no public way to recover the version
// strings it already read. A dial failure here is fatal to the whole
// probe (nothing is listening); a read failure after connecting is not
// -- it just means no banner to show, and the real attempts below still
// run.
func grabBanner(t protocols.Target, timeout time.Duration) (string, error) {
	netx.Request()
	raw, err := net.DialTimeout("tcp", t.String(), timeout)
	if err != nil {
		return "", err
	}
	defer raw.Close()
	c := netx.CountConn(raw)
	c.SetReadDeadline(time.Now().Add(timeout))
	line, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimRight(line, "\r\n"), nil
}

func trimBanner(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

func bannerSuffix(banner string) string {
	if banner == "" {
		return ""
	}
	return "; banner: " + trimBanner(banner)
}

// printTable renders results in netexec's own one-line-per-result style
// (see protocols.Finding.Line), not a table: "SSH  host  port  hostname
// [symbol] message". An SSH session, with or without a credential, is an
// interactive shell by definition -- so both KindNoAuth (no login at
// all) and KindLoginOK (a real credential worked) are marked "(Pwn3d!)".
func printTable(w io.Writer, results []protocols.Finding, cm colorout.Mode) {
	for _, f := range results {
		if f.Err != "" {
			fmt.Fprintln(w, f.Line("ssh", cm, protocols.SymFailure, f.Err, false))
			continue
		}
		switch f.Kind {
		case KindNoAuth:
			fmt.Fprintln(w, f.Line("ssh", cm, protocols.SymSuccess, f.Detail, true))
		case KindLoginOK:
			msg := f.Cred.UserPass() + " " + f.Detail
			fmt.Fprintln(w, f.Line("ssh", cm, protocols.SymSuccess, msg, true))
		case KindLoginFailed:
			fmt.Fprintln(w, f.Line("ssh", cm, protocols.SymFailure, f.Detail, false))
		default: // KindBanner
			fmt.Fprintln(w, f.Line("ssh", cm, protocols.SymInfo, f.Detail, false))
		}
	}
}

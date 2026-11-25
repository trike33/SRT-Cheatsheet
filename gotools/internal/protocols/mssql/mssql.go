// Package mssql implements the mssql command, continuing the "SRT
// internal-pentest direction" doc's protocol-client roadmap beyond its
// original four: a TDS login check wrapping
// github.com/microsoft/go-mssqldb, Microsoft's own official SQL Server
// driver.
//
// The default behavior tries an (almost certainly rejected, SQL Server
// has no real anonymous login) empty credential first, then each
// -u/-p attempt as SQL Server authentication -- or, when -d is also
// given, as NTLM/Windows authentication instead: the driver's own
// built-in NTLM provider activates for ANY backslash-qualified username
// ("DOMAIN\user"), which this package builds automatically from -u/-d,
// no extra flag needed. -H (pass-the-hash) isn't supported: the
// driver's NTLM provider takes a plain password field only, with no
// way to plug a raw hash in. A successful login is followed by
// `SELECT @@VERSION` and a bounded list of databases (`sys.databases`)
// -- read-only; this package never runs anything beyond those two
// queries, in particular never `xp_cmdshell` or any other
// execution-capable stored procedure.
package mssql

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	mssqllib "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "mssql",
		Group:   "PROTOCOL recon",
		Summary: "MSSQL (TDS) SQL-auth/NTLM login check + version and database enumeration",
		Run:     Run,
	})
}

// DefaultPort is SQL Server's well-known TCP port.
const DefaultPort = 1433

// Finding kinds this package reports.
const (
	KindLoginOK         = "login-ok"          // a given credential (SQL or NTLM auth) was accepted
	KindLoginOKSysadmin = "login-ok-sysadmin" // accepted AND confirmed a member of the sysadmin fixed server role
	KindLoginFailed     = "login-failed"      // every attempt was rejected
)

// databasesToList caps how many database names summarize prints, so an
// instance hosting hundreds of databases doesn't blow out the Finding.
const databasesToList = 50

func Run(args []string) error {
	fs := flag.NewFlagSet("mssql", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "CREDENTIALS", Names: []string{"u", "p", "H", "d", "local-auth", "k"}},
			{Title: "CONNECTION", Names: []string{"port", "timeout", "c"}},
			{Title: "OUTPUT", Names: []string{"o", "json", "color"}},
		})
	}
	in := fs.String("l", "", "target list: host or host:port (default: stdin, else the project db's port records -- see -from)")
	fb := store.BindInputFallback(fs, "mssql", "port")
	creds := protocols.BindCreds(fs)
	conn := protocols.BindConn(fs, DefaultPort, 10*time.Second)
	concurrency := fs.Int("c", 20, "concurrent connections")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of a table")
	colorFlag := fs.String("color", "auto", "color the output: auto|always|never (ignored with -json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	if extraP, extraH := creds.Dangling(); extraP > 0 || extraH > 0 {
		ioutil.Warn("mssql: %d -p and %d -H value(s) have no matching -u and will be ignored", extraP, extraH)
	}
	defer ioutil.StartHeartbeat("mssql")()

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
			ioutil.Warn("mssql: %v", err)
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
		store.CurrentSink().Add(f.Record("mssql"))
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

// probe tries each credential attempt against t in turn, opening a
// fresh *sql.DB (and so a fresh TCP connection) per attempt. The first
// attempt the server accepts wins, followed by summarize's read-only
// queries. A connection-level failure aborts the whole target
// immediately, same as the other protocol commands; a login rejection
// just moves on to the next attempt.
func probe(t protocols.Target, attempts []protocols.Credential, timeout time.Duration) protocols.Finding {
	var lastErr error
	for _, cr := range attempts {
		if cr.Hash != "" {
			continue // pass-the-hash isn't supported here -- the driver's NTLM provider takes a password only, see docs/ROADMAP.md
		}
		if cr.Kerberos {
			continue // not implemented -- see docs/ROADMAP.md
		}

		db, err := connect(t, cr, timeout)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) {
				// The TCP dial itself failed (refused, no route, timed
				// out) -- every other credential would fail the same
				// way, so there's nothing to gain from trying them.
				return protocols.Finding{Target: t, Err: err.Error()}
			}
			lastErr = err
			continue
		}

		detail := summarize(db, timeout)
		sysadmin := isSysadmin(db, timeout)
		db.Close()
		kind := KindLoginOK
		if sysadmin {
			kind = KindLoginOKSysadmin
		}
		return protocols.Finding{Target: t, Cred: cr, Kind: kind, Severity: protocols.High, Detail: detail}
	}

	detail := "every login attempt was rejected"
	if lastErr != nil {
		detail = "rejected: " + lastErr.Error()
	}
	return protocols.Finding{Target: t, Kind: KindLoginFailed, Severity: protocols.Info, Detail: detail}
}

// connect opens a *sql.DB for cr against t and verifies the login with
// Ping (which, unlike sql.OpenDB alone, actually dials and authenticates
// -- OpenDB itself never touches the network). TLS verification is
// skipped: an internal SQL Server's certificate is routinely self-signed,
// the same tolerant posture probe/ftp/ldap already take.
func connect(t protocols.Target, cr protocols.Credential, timeout time.Duration) (*sql.DB, error) {
	cfg := msdsn.Config{
		Host: t.Host,
		Port: uint64(t.Port),
		// dialConnection loops over exactly this list to pick a dialer
		// ("tcp" -> msdsn's own tcpParser/tcpDialer); built from a DSN
		// string, msdsn.Parse always populates it, but a Config built by
		// hand -- as here -- does not, and dialConnection silently
		// returns (nil, nil) on an empty list rather than an error,
		// which then panics deeper in the driver on a nil net.Conn.
		// Confirmed by a test that caught exactly this before this line
		// was added.
		Protocols:   []string{"tcp"},
		User:        buildUsername(cr, t),
		Password:    cr.Password,
		DialTimeout: timeout,
		ConnTimeout: timeout,
		TLSConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec -- fingerprinting a login, not pinning a known server
	}
	connector := mssqllib.NewConnectorConfig(cfg)
	connector.Dialer = meteredDialer{timeout: timeout}
	db := sql.OpenDB(connector)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	netx.Request()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// meteredDialer is the mssql.Dialer hook NewConnectorConfig's Connector
// takes: like smb's and ftp's own dial hooks, it routes every TCP
// connection the driver opens through netx's request-rate gate and
// traffic counter.
type meteredDialer struct{ timeout time.Duration }

func (d meteredDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	netx.Request()
	nd := net.Dialer{Timeout: d.timeout}
	raw, err := nd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return netx.CountConn(raw), nil
}

var _ mssqllib.Dialer = meteredDialer{}

// buildUsername turns cr into the username connect sends: a plain
// username for SQL Server authentication, or a "DOMAIN\user" form when
// cr.Domain is set (or, with -local-auth, the target's own hostname in
// its place) -- any backslash-qualified username activates the driver's
// built-in NTLM provider automatically, with no "authenticator" DSN
// parameter needed (see auth_unix.go in microsoft/go-mssqldb).
func buildUsername(cr protocols.Credential, t protocols.Target) string {
	domain := cr.Domain
	if cr.LocalAuth {
		domain = t.Host // authenticate against the target's own local accounts, not the domain
	}
	if domain == "" {
		return cr.User
	}
	return domain + `\` + cr.User
}

// summarize runs the two read-only queries a successful login unlocks:
// the server's own version string and a bounded list of databases. A
// query that fails (insufficient permission, an unusual edition) just
// leaves that part out rather than failing the whole login Finding over
// it -- the login itself already succeeded.
func summarize(db *sql.DB, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	version := "version unknown"
	var raw string
	if err := db.QueryRowContext(ctx, "SELECT @@VERSION").Scan(&raw); err == nil {
		version = firstLine(raw)
	}

	var dbs []string
	rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT TOP %d name FROM sys.databases ORDER BY name", databasesToList))
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			if rows.Scan(&name) == nil {
				dbs = append(dbs, name)
			}
		}
	}

	detail := version
	if len(dbs) > 0 {
		detail += fmt.Sprintf("; %d database(s): %s", len(dbs), strings.Join(dbs, ", "))
	}
	return detail
}

// isSysadmin runs a single read-only scalar check -- SELECT
// IS_SRVROLEMEMBER('sysadmin') -- the same scalar netexec's own mssql
// module reads to decide whether a login gets its "(Pwn3d!)" marker: 1
// means the current login is a member of the sysadmin fixed server role
// (full instance control, the SQL Server equivalent of local
// Administrator), 0 means it isn't. An error (an edition quirk, or a
// login lacking even that much visibility) is treated as "not
// confirmed" rather than failing the login Finding itself over it.
func isSysadmin(db *sql.DB, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var v int
	if err := db.QueryRowContext(ctx, "SELECT IS_SRVROLEMEMBER('sysadmin')").Scan(&v); err != nil {
		return false
	}
	return v == 1
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// printTable renders results in netexec's own one-line-per-result style
// (see protocols.Finding.Line), not a table: "MSSQL  host  port
// hostname  [symbol] message". KindLoginOKSysadmin -- a login confirmed
// a member of the sysadmin fixed server role via isSysadmin -- gets
// "(Pwn3d!)": the SQL Server equivalent of local Administrator, full
// instance control. A plain accepted login that isn't sysadmin does not.
func printTable(w io.Writer, results []protocols.Finding, cm colorout.Mode) {
	for _, f := range results {
		if f.Err != "" {
			fmt.Fprintln(w, f.Line("mssql", cm, protocols.SymFailure, f.Err, false))
			continue
		}
		switch f.Kind {
		case KindLoginOK, KindLoginOKSysadmin:
			msg := f.Detail
			if up := f.Cred.UserPass(); up != "" {
				msg = up + " " + msg
			}
			fmt.Fprintln(w, f.Line("mssql", cm, protocols.SymSuccess, msg, f.Kind == KindLoginOKSysadmin))
		case KindLoginFailed:
			fmt.Fprintln(w, f.Line("mssql", cm, protocols.SymFailure, f.Detail, false))
		default:
			fmt.Fprintln(w, f.Line("mssql", cm, protocols.SymInfo, f.Detail, false))
		}
	}
}

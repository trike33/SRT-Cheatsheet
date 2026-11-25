// Package ldap implements the ldap command: Phase 1 of the "SRT
// internal-pentest direction" doc's protocol-client roadmap. It wraps
// github.com/go-ldap/ldap/v3, the doc's chosen LDAP library, with
// SRT's own connection metering (netx), credential attempts
// (protocols.Creds) and results-database wiring (store).
//
// Phase 1's default behavior is the anonymous-bind check (RFC 4513
// 5.1.2: an empty DN and empty password is treated as anonymous), then
// each -u/-p attempt as a simple bind (-d builds a UPN, "user@domain",
// the form Active Directory's LDAP accepts for simple bind) and each
// -H attempt as an NTLM pass-the-hash bind, which go-ldap supports
// directly against servers that enable the NTLM SASL mechanism (most
// notably Active Directory). -k (Kerberos/GSSAPI bind) is accepted for
// CLI-schema consistency across every protocol command but not yet
// implemented here -- see docs/ROADMAP.md. A successful bind is
// followed by a RootDSE search (namingContexts, dnsHostName, the
// supported LDAP version): a read-only "(objectClass=*)" base-object
// search every LDAP server answers, authenticated or not.
package ldap

import (
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	ldaplib "github.com/go-ldap/ldap/v3"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "ldap",
		Group:   "PROTOCOL recon",
		Summary: "LDAP anonymous/simple-bind check + RootDSE discovery (optionally tries -u/-p/-H)",
		Run:     Run,
	})
}

// DefaultPort is plaintext LDAP's well-known port (not LDAPS).
const DefaultPort = 389

// rootDSEAttrs are requested on the anonymous base-object search every
// LDAP server answers, authenticated or not -- RFC 4512 5.1.
var rootDSEAttrs = []string{"namingContexts", "defaultNamingContext", "dnsHostName", "supportedLDAPVersion"}

// Finding kinds this package reports.
const (
	KindAnonymousBind = "anonymous-bind" // an anonymous bind (empty DN + empty password) was accepted
	KindLoginOK       = "login-ok"       // a given -u/-p or -H credential was accepted
	KindLoginFailed   = "login-failed"   // every given credential (and anonymous) was rejected
)

func Run(args []string) error {
	fs := flag.NewFlagSet("ldap", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "CREDENTIALS", Names: []string{"u", "p", "H", "d", "local-auth", "k"}},
			{Title: "CONNECTION", Names: []string{"port", "timeout", "c"}},
			{Title: "OUTPUT", Names: []string{"o", "json", "color"}},
		})
	}
	in := fs.String("l", "", "target list: host or host:port (default: stdin, else the project db's port records -- see -from)")
	fb := store.BindInputFallback(fs, "ldap", "port")
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
		ioutil.Warn("ldap: %d -p and %d -H value(s) have no matching -u and will be ignored", extraP, extraH)
	}
	defer ioutil.StartHeartbeat("ldap")()

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
			ioutil.Warn("ldap: %v", err)
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
		store.CurrentSink().Add(f.Record("ldap"))
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
// fresh TCP connection per attempt (a rejected bind can leave a server
// free to tear the connection down, same reasoning as smb.probe). The
// first attempt a bind accepts wins, followed by a RootDSE search.
func probe(t protocols.Target, attempts []protocols.Credential, timeout time.Duration) protocols.Finding {
	var lastErr error
	for _, cr := range attempts {
		if cr.Kerberos {
			continue // GSSAPI/Kerberos bind is Phase 2+ (see docs/ROADMAP.md)
		}

		netx.Request()
		raw, err := net.DialTimeout("tcp", t.String(), timeout)
		if err != nil {
			return protocols.Finding{Target: t, Err: err.Error()}
		}
		c := netx.CountConn(raw)

		l := ldaplib.NewConn(c, false)
		l.Start()
		l.SetTimeout(timeout)

		if err := bind(l, cr); err != nil {
			l.Close()
			lastErr = err
			continue
		}

		detail := summarizeRootDSE(l)
		l.Close()

		kind := KindLoginOK
		sev := protocols.Medium
		switch {
		case cr.IsAnonymous():
			kind, sev = KindAnonymousBind, protocols.High
		case cr.Hash != "":
			sev = protocols.High // a pass-the-hash bind succeeding confirms a usable compromised hash
		}
		return protocols.Finding{Target: t, Cred: cr, Kind: kind, Severity: sev, Detail: detail}
	}

	detail := "every bind attempt was rejected"
	if lastErr != nil {
		detail = "rejected: " + lastErr.Error()
	}
	return protocols.Finding{Target: t, Kind: KindLoginFailed, Severity: protocols.Info, Detail: detail}
}

// bind performs the right kind of bind for cr: a true anonymous bind
// (empty DN + empty password) for protocols.Anonymous, an NTLM
// pass-the-hash bind when cr.Hash is set, otherwise a simple bind --
// against a UPN ("user@domain") when cr.Domain is set, matching how
// Active Directory's LDAP expects a simple-bind DN, else the bare
// username as given. Every simple bind goes through SimpleBind with
// AllowEmptyPassword, not the plain Bind method: Bind refuses an empty
// password client-side (RFC 4513's unauthenticated-bind warning), which
// would make an anonymous attempt error out before a single byte
// reaches the wire.
func bind(l *ldaplib.Conn, cr protocols.Credential) error {
	if cr.Hash != "" {
		return l.NTLMBindWithHash(cr.Domain, cr.User, cr.Hash)
	}
	dn := cr.User
	if cr.Domain != "" {
		dn = cr.User + "@" + cr.Domain
	}
	_, err := l.SimpleBind(&ldaplib.SimpleBindRequest{Username: dn, Password: cr.Password, AllowEmptyPassword: true})
	return err
}

// summarizeRootDSE runs the anonymous RootDSE search every LDAP server
// answers and renders it compactly for a Finding's Detail.
func summarizeRootDSE(l *ldaplib.Conn) string {
	req := ldaplib.NewSearchRequest("", ldaplib.ScopeBaseObject, ldaplib.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", rootDSEAttrs, nil)
	res, err := l.Search(req)
	if err != nil {
		return "bind accepted, but the RootDSE search failed: " + err.Error()
	}
	if len(res.Entries) == 0 {
		return "bind accepted; RootDSE search returned no entry"
	}
	e := res.Entries[0]
	var parts []string
	if v := e.GetAttributeValue("dnsHostName"); v != "" {
		parts = append(parts, "dnsHostName="+v)
	}
	if nc := e.GetAttributeValues("namingContexts"); len(nc) > 0 {
		parts = append(parts, "namingContexts=["+strings.Join(nc, ", ")+"]")
	}
	if v := e.GetAttributeValue("supportedLDAPVersion"); v != "" {
		parts = append(parts, "LDAPv"+v)
	}
	if len(parts) == 0 {
		return "bind accepted; RootDSE had none of the requested attributes"
	}
	return strings.Join(parts, "; ")
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
		case KindAnonymousBind, KindLoginOK:
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

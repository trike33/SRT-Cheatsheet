// Package smb implements the smb command: Phase 1, Phase 2's Kerberos/
// fingerprint item, and part of Phase 2's secrets-spider work from the
// "SRT internal-pentest direction" doc's protocol-client roadmap.
//
// It wraps github.com/jfjallid/go-smb rather than the doc's originally
// picked hirochachacha/go-smb2: go-smb2's Initiator is an unexported
// interface (no way to plug Kerberos in from outside its own package)
// and it exposes no negotiated-dialect/signing/hostname/OS information,
// so a netexec-style fingerprint line was never reachable through it.
// jfjallid/go-smb is a maintained fork lineage related to both go-smb2
// and stacktitan/smb that exposes all of this publicly -- see the
// feasibility doc's research update for the exact APIs and the two
// caveats that remain (a Kerberos login still can't populate hostname/
// domain/OS, since that data comes from the NTLM challenge specifically;
// and no library anywhere maps a build number to a marketing name like
// "Server 2022", so the fingerprint shows "Windows X.Y Build Z").
//
// The default behavior is the anonymous/null-session check: every
// target is tried with an anonymous session first (no flags needed at
// all), then with each -u/-p/-H/-k attempt in turn. A session that's
// accepted is followed by the fingerprint line, a real share listing
// (MS-SRVS NetShareEnumAll over IPC$, with the server's own remark per
// share -- not a guessed one), and a shallow per-share read-access
// check. With -spider (off by default -- it's a real recursive crawl of
// every readable share, opt in rather than something every run does), a
// bounded recursive walk of every readable share (see spiderShare) also
// flags filenames that commonly carry secrets -- netexec's spider_plus
// module, read-only. This package never writes, deletes or creates
// anything on the target.
package smb

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/jfjallid/golog"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/gss"
	gosmb "github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"

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
		Summary: "SMB 2/3 anonymous/NTLM/Kerberos session, fingerprint, share listing, read-access check and a bounded secrets spider",
		Run:     Run,
	})
	// go-smb's own loggers default to printing protocol-level warnings
	// (a malformed NetBIOS header, a failed negotiate) straight to
	// stderr -- noisy and redundant for a tool whose own Finding.Err
	// already reports exactly that, and inconsistent with srt's own
	// stdout-stays-clean-for-piping convention (see internal/ioutil's
	// package doc). Silencing them here, once, covers every command
	// that imports this package.
	golog.SetAll(golog.LevelNone, 0, io.Discard, io.Discard)
}

// DefaultPort is SMB's well-known port (SMB over TCP, no NetBIOS session service).
const DefaultPort = 445

// Finding kinds this package reports.
const (
	KindAnonymousLogin  = "anonymous-login"  // an anonymous/null session was accepted
	KindLoginOK         = "login-ok"         // a given -u/-p/-H/-k credential was accepted
	KindLoginFailed     = "login-failed"     // every given credential (and anonymous) was rejected
	KindInterestingFile = "interesting-file" // the spider found a filename that commonly carries secrets
)

// sharesToProbe caps how many non-admin shares get an actual read-access
// check per target, so a server with hundreds of shares doesn't turn one
// target into hundreds of extra round trips.
const sharesToProbe = 20

// Spider bounds: deep and wide enough to catch what a person would
// actually find browsing a share by hand, bounded so one huge share
// never turns into an unbounded walk. spiderMaxEntries is a budget
// shared across every share and every directory within it (checked
// before each directory listing), not a per-directory cap.
const (
	spiderMaxDepth      = 3
	spiderMaxEntries    = 1000
	spiderMaxHitsPerRun = 50
)

func Run(args []string) error {
	fs := flag.NewFlagSet("smb", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "CREDENTIALS", Names: []string{"u", "p", "H", "d", "local-auth", "k"}},
			{Title: "CONNECTION", Names: []string{"port", "timeout", "c"}},
			{Title: "SPIDER", Names: []string{"spider"}},
			{Title: "OUTPUT", Names: []string{"o", "json", "color"}},
		})
	}
	in := fs.String("l", "", "target list: host or host:port (default: stdin, else the project db's port records -- see -from)")
	fb := store.BindInputFallback(fs, "smb", "port")
	creds := protocols.BindCreds(fs)
	conn := protocols.BindConn(fs, DefaultPort, 10*time.Second)
	concurrency := fs.Int("c", 10, "concurrent sessions")
	spider := fs.Bool("spider", false, "after a successful session, recursively walk every readable share (bounded depth/entries) flagging filenames that commonly carry secrets -- off by default: it's a real recursive crawl of every readable share, opt in rather than something every run does")
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
	findingsPerTarget := make([][]protocols.Finding, len(targets))
	sharesPerTarget := make([]shareReport, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *concurrency))
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t protocols.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			findingsPerTarget[i], sharesPerTarget[i] = probe(t, attempts, *conn.Timeout, *spider)
		}(i, t)
	}
	wg.Wait()

	var results []protocols.Finding
	for _, fs := range findingsPerTarget {
		results = append(results, fs...)
	}

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
	// The one-line Detail above already has the share summary (and it's
	// what's stored to the DB/JSON); this is the netexec-style expanded
	// view -- bold, colored, indented -- for a target where a session
	// actually got in and found something to enumerate.
	for i, t := range targets {
		printShareTable(w, t, sharesPerTarget[i], cm)
	}
	return nil
}

// probe tries each credential attempt against t in turn, dialing a fresh
// TCP connection per attempt (a session that fails authentication isn't
// safe to reuse for a retry -- a server is free to tear it down, and SRT
// would rather redial than guess at its state). The first attempt a
// session accepts wins: it's followed by the fingerprint line, a
// read-only share listing and, if spider is set, a bounded walk of every
// readable share -- so a target can report several Findings, not just
// one. A connection-level failure (refused, timed out, unreachable)
// aborts the whole target immediately, same as before; an
// authentication failure just moves on to the next credential.
//
// Its second return value -- a shareReport, zero-valued unless a session
// was actually accepted -- is for Run's netexec-style expanded share
// table: everything that table needs beyond what belongs in a stored
// Finding (the per-share access/remark detail, not just the one-line
// summary already in Finding.Detail).
func probe(t protocols.Target, attempts []protocols.Credential, timeout time.Duration, spider bool) ([]protocols.Finding, shareReport) {
	var lastErr error
	for _, cr := range attempts {
		init, err := buildInitiator(cr, t)
		if err != nil {
			lastErr = err
			continue
		}

		conn, err := gosmb.NewConnection(gosmb.Options{
			Host:        t.Host,
			Port:        t.Port,
			Initiator:   init,
			DialTimeout: timeout,
			// NewConnection dials its own socket (there's no pre-dialed
			// net.Conn hook the way go-smb2's Dialer.Dial(net.Conn) gave
			// the old code path) -- ProxyDialer is the injection point it
			// does expose, so meteredDialer routes that dial through the
			// same netx.Request()/-rate gate and traffic counter every
			// other connection in srt gets, rather than silently losing
			// metering in the library swap.
			ProxyDialer: meteredDialer{timeout: timeout},
		})
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) {
				// The TCP dial/handshake itself failed (refused, no
				// route, timed out) -- every other credential would fail
				// the same way, so there's nothing to gain from trying
				// them.
				return []protocols.Finding{{Target: t, Err: err.Error()}}, shareReport{}
			}
			lastErr = err
			continue
		}

		report := inspectShares(conn, t.Host)
		detail := fingerprint(conn) + "; " + report.String()
		var hits []shareHit
		if spider {
			budget := spiderMaxEntries
			for _, share := range report.readable {
				if len(hits) >= spiderMaxHitsPerRun {
					break
				}
				hits = append(hits, spiderShare(conn, share, &budget)...)
			}
		}
		conn.Close()

		kind := KindLoginOK
		if cr.IsAnonymous() {
			kind = KindAnonymousLogin
		}
		sev := protocols.High
		if len(report.readable) == 0 {
			sev = protocols.Medium // session accepted, but nothing beyond IPC$ was actually readable
		}
		findings := []protocols.Finding{{Target: t, Cred: cr, Kind: kind, Severity: sev, Detail: detail}}
		if len(hits) > 0 {
			if len(hits) > spiderMaxHitsPerRun {
				hits = hits[:spiderMaxHitsPerRun]
			}
			findings = append(findings, protocols.Finding{
				Target: t, Cred: cr, Kind: KindInterestingFile, Severity: protocols.High,
				Detail: fmt.Sprintf("%d file(s) matching known secret/credential patterns: %s", len(hits), joinHits(hits)),
			})
		}
		return findings, report
	}

	detail := "every login attempt was rejected"
	if lastErr != nil {
		detail = "rejected: " + lastErr.Error()
	}
	return []protocols.Finding{{Target: t, Kind: KindLoginFailed, Severity: protocols.Info, Detail: detail}}, shareReport{}
}

// meteredDialer is the ProxyDialer gosmb.Options takes: NewConnection
// dials its own socket, so this is srt's one hook to route that dial
// through netx's request-rate gate and traffic counter, the same
// accounting every other connection in srt gets. It implements
// proxy.ContextDialer (what NewConnection actually calls) and
// proxy.Dialer (the field's static type), not because a proxy is
// involved -- the library reuses that interface purely as a dial hook.
type meteredDialer struct{ timeout time.Duration }

func (d meteredDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d meteredDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	netx.Request()
	nd := net.Dialer{Timeout: d.timeout}
	raw, err := nd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return netx.CountConn(raw), nil
}

var _ proxy.ContextDialer = meteredDialer{}
var _ proxy.Dialer = meteredDialer{}

// fingerprint renders the netexec-style line this library's public API
// makes possible: negotiated dialect, whether signing is required, and
// -- from the NTLM challenge's target info, so empty on a Kerberos login,
// per the package doc -- the server's hostname, domain and OS build.
// There's no "Server 2022"-style marketing name here: no library,
// impacket included, maps a build number to one, so this reports the raw
// "Windows X.Y Build Z" form instead of guessing.
func fingerprint(conn *gosmb.Connection) string {
	parts := make([]string, 0, 5)
	if ti := conn.GetTargetInfo(); ti != nil {
		os := ti.GuessedOSVersion
		if os == "" {
			os = "unknown OS"
		}
		name := ti.DnsComputerName
		if name == "" {
			name = ti.NBComputerName
		}
		domain := ti.DnsDomainName
		if domain == "" {
			domain = ti.NBDomainName
		}
		parts = append(parts, fmt.Sprintf("%s (name:%s) (domain:%s)", os, name, domain))
	}
	parts = append(parts,
		fmt.Sprintf("(dialect:%s)", gosmb.DialectString(conn.Dialect())),
		fmt.Sprintf("(signing:%v)", conn.IsSigningRequired()),
	)
	if conn.IsGuestSession() {
		parts = append(parts, "(guest)")
	}
	if conn.IsNullSession() {
		parts = append(parts, "(null session)")
	}
	return strings.Join(parts, " ")
}

// buildInitiator turns a Credential into the gss.Mechanism gosmb.Options
// expects: an anonymous NTLM session (a true null session, via
// spnego.NTLMAuthAnonymous, not just an empty username) for Anonymous, a
// plain NTLM password or pass-the-hash login, or -- when cr.Kerberos is
// set -- a Kerberos login via buildKerberosInitiator.
func buildInitiator(cr protocols.Credential, t protocols.Target) (gss.Mechanism, error) {
	if cr.Kerberos {
		return buildKerberosInitiator(cr, t)
	}
	domain := cr.Domain
	if cr.LocalAuth {
		domain = "" // authenticate against the target's local SAM, not the domain
	}
	init := &spnego.NTLMInitiator{User: cr.User, Password: cr.Password, Domain: domain, LocalUser: cr.LocalAuth}
	if cr.IsAnonymous() {
		init.AuthMode = spnego.NTLMAuthAnonymous
	}
	if cr.Hash != "" {
		h, err := parseHash(cr.Hash)
		if err != nil {
			return nil, fmt.Errorf("-H %q: %w", cr.Hash, err)
		}
		init.Hash = h
	}
	return init, nil
}

// buildKerberosInitiator builds a spnego.KRB5Initiator for -k: unlike
// srt's ldap package (which hand-rolls a disposable krb5.conf for
// go-ldap's gssapi client), this library's Kerberos client dials the KDC
// itself given DCIP, so no config file is needed. The same caveat ldap's
// own Kerberos support documents applies here too: it needs the target's
// actual hostname, not its bare IP, since that's what the "cifs/<host>"
// SPN is keyed to.
func buildKerberosInitiator(cr protocols.Credential, t protocols.Target) (gss.Mechanism, error) {
	if cr.Domain == "" {
		return nil, fmt.Errorf("-k needs -d <domain> (the Kerberos realm)")
	}
	if cr.Password == "" && cr.Hash == "" {
		return nil, fmt.Errorf("-k needs -p <password> or -H <hash>")
	}
	init := &spnego.KRB5Initiator{
		User:   cr.User,
		Domain: cr.Domain,
		DCIP:   t.Host,
		Host:   t.Host,
		SPN:    "cifs/" + t.Host,
	}
	if cr.Hash != "" {
		h, err := parseHash(cr.Hash)
		if err != nil {
			return nil, fmt.Errorf("-H %q: %w", cr.Hash, err)
		}
		init.Hash = h
	} else {
		init.Password = cr.Password
	}
	return init, nil
}

// parseHash accepts a bare 32-hex-digit NT hash, or netexec's "LM:NT"
// form (the LM half is ignored -- NTLMv2, which this library speaks,
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

// shareReport is what inspectShares finds: every share name, the
// server's own remark for each (not a guessed one), which of them turned
// out readable (candidates for spiderShare), and a precomputed access
// label per share for String()'s Detail line.
type shareReport struct {
	names    []string
	readable []string
	access   map[string]string // share name -> "IPC" | "readable" | "listed, not readable" | "no-access"
	remark   map[string]string // share name -> the server's own comment, via MS-SRVS NetShareEnumAll
	listErr  error
}

// inspectShares enumerates host's shares over MS-SRVS (NetShareEnumAll,
// via a DCE/RPC bind to \PIPE\srvsvc on IPC$ -- the same wire call
// impacket/netexec make, not a workaround) and, for up to sharesToProbe
// of them (skipping IPC$, which isn't a filesystem), checks whether its
// root directory can actually be read -- the distinction netexec's own
// output draws between "share exists" and "share is actually open".
func inspectShares(conn *gosmb.Connection, host string) shareReport {
	shares, err := listShares(conn, host)
	if err != nil {
		return shareReport{listErr: err}
	}
	r := shareReport{access: map[string]string{}, remark: map[string]string{}}
	checked := 0
	for _, sh := range shares {
		r.names = append(r.names, sh.Name)
		r.remark[sh.Name] = sh.Comment
		switch {
		case strings.EqualFold(sh.Name, "IPC$"):
			r.access[sh.Name] = "IPC"
		case checked >= sharesToProbe:
			r.access[sh.Name] = "not checked (share limit)"
		default:
			checked++
			access := shareAccess(conn, sh.Name)
			r.access[sh.Name] = access
			if access == "readable" {
				r.readable = append(r.readable, sh.Name)
			}
		}
	}
	return r
}

// listShares runs MS-SRVS's NetShareEnumAll over a DCE/RPC bind to
// \PIPE\srvsvc on IPC$: TreeConnect, open the named pipe, wrap it in a
// DCE/RPC transport, bind the srvsvc interface, then make the call. This
// is the real share list, with the server's own per-share comment --
// unlike go-smb2 (the previous library here), which had no RPC layer at
// all and only gave a bare list of names.
func listShares(conn *gosmb.Connection, host string) ([]mssrvs.NetShare, error) {
	const ipc = "IPC$"
	if err := conn.TreeConnect(ipc); err != nil {
		return nil, err
	}
	defer conn.TreeDisconnect(ipc)

	f, err := conn.OpenFile(ipc, mssrvs.MSRPCSrvSvcPipe)
	if err != nil {
		return nil, err
	}
	defer f.CloseFile()

	transport, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		return nil, err
	}
	bind, err := dcerpc.Bind(transport, mssrvs.MSRPCUuidSrvSvc, mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, err
	}
	return mssrvs.NewRPCCon(bind).NetShareEnumAll(host)
}

func (r shareReport) String() string {
	if r.listErr != nil {
		return "session accepted, but share enumeration failed: " + r.listErr.Error()
	}
	if len(r.names) == 0 {
		return "session accepted; no shares enumerated"
	}
	parts := make([]string, len(r.names))
	for i, name := range r.names {
		if remark := r.remark[name]; remark != "" {
			parts[i] = fmt.Sprintf("%s [%s] (%s)", name, remark, r.access[name])
		} else {
			parts[i] = fmt.Sprintf("%s (%s)", name, r.access[name])
		}
	}
	return fmt.Sprintf("%d share(s): %s", len(r.names), strings.Join(parts, ", "))
}

// ansiBold is the plain SGR bold code; colorout only defines colors, not
// weight, so this is combined with one of its color constants (or used
// bare) the same way colorout.Mode.Wrap expects a single "code" string.
const ansiBold = "\033[1m"

// printShareTable renders r as a netexec-style expanded view: a bold
// header row, bold share names, "READ" highlighted in green, the whole
// block indented so it reads as nested under its target rather than
// starting at the left margin -- the visual netexec itself uses (see the
// design doc's screenshots). It prints nothing for a target with no
// shares to show (a failed login, a listing error, or an empty list).
func printShareTable(w io.Writer, t protocols.Target, r shareReport, cm colorout.Mode) {
	if len(r.names) == 0 {
		return
	}
	const indent = "    "
	nameW, permW := len("Share"), len("Permissions")
	for _, name := range r.names {
		if n := len(name); n > nameW {
			nameW = n
		}
	}
	row := func(nameCell, permCell, remark string) {
		fmt.Fprintf(w, "%s%s  %s  %s\n", indent, nameCell, permCell, remark)
	}

	fmt.Fprintf(w, "\n%s%s\n", indent, cm.Wrap(ansiBold, t.String()+" shares"))
	row(cm.PadWrap(ansiBold, "Share", nameW), cm.PadWrap(ansiBold, "Permissions", permW), cm.Wrap(ansiBold, "Remark"))
	row(dashes(nameW), dashes(permW), dashes(len("Remark")))
	for _, name := range r.names {
		// A plain "readable"/"no-access"/... phrase (shareReport's own,
		// kept as-is for the stored Detail summary) becomes netexec's
		// bare "READ" or blank here. IPC$ reads as accessible too: the
		// MS-SRVS RPC bind that enumerated these shares in the first
		// place already opened it, the same thing netexec's own
		// (IPC$, READ) line reports.
		perm := ""
		permColor := ""
		if access := r.access[name]; access == "readable" || access == "IPC" {
			perm, permColor = "READ", colorout.Green
		}
		row(cm.PadWrap(ansiBold, name, nameW), cm.PadWrap(permColor, perm, permW), r.remark[name])
	}
}

func dashes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '-'
	}
	return string(b)
}

// shareAccess reports whether share's root directory can be listed
// ("readable"), the tree connect itself was denied ("no-access"), or the
// tree connect succeeded but the listing was denied ("listed, not
// readable") -- without ever writing to or through the share.
func shareAccess(conn *gosmb.Connection, share string) string {
	if err := conn.TreeConnect(share); err != nil {
		return "no-access"
	}
	defer conn.TreeDisconnect(share)
	if _, err := conn.ListDirectory(share, "", "*"); err != nil {
		return "listed, not readable"
	}
	return "readable"
}

// shareHit is one spiderShare match.
type shareHit struct {
	share string
	path  string
}

// spiderShare walks share's directory tree (bounded by spiderMaxDepth
// and *budget, a shared entry-visit budget across every share this probe
// call spiders) looking for filenames that commonly carry credentials or
// secrets -- netexec's spider_plus module, read-only: it never opens a
// file's contents, only lists directories and checks names.
func spiderShare(conn *gosmb.Connection, share string, budget *int) []shareHit {
	if err := conn.TreeConnect(share); err != nil {
		return nil
	}
	defer conn.TreeDisconnect(share)
	var hits []shareHit
	walkDir(conn, share, "", 0, budget, &hits)
	return hits
}

func walkDir(conn *gosmb.Connection, share, dir string, depth int, budget *int, hits *[]shareHit) {
	if depth > spiderMaxDepth || *budget <= 0 || len(*hits) >= spiderMaxHitsPerRun {
		return
	}
	entries, err := conn.ListDirectory(share, dir, "*")
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Name == "." || e.Name == ".." {
			continue
		}
		if *budget <= 0 || len(*hits) >= spiderMaxHitsPerRun {
			return
		}
		*budget--
		if e.IsDir {
			walkDir(conn, share, e.FullPath, depth+1, budget, hits)
			continue
		}
		if isInterestingFile(e.Name) {
			*hits = append(*hits, shareHit{share: share, path: e.FullPath})
		}
	}
}

// interestingExtensions are file extensions that are themselves
// credential/secret material (a password-manager database, a private
// key, a PKCS#12 bundle, ...), checked case-insensitively.
var interestingExtensions = []string{
	".kdbx", ".kdb", ".ppk", ".pem", ".key", ".pfx", ".p12", ".ovpn",
}

// interestingNameSubstrings are lowercase substrings in a filename (not
// its extension) that commonly show up in files holding credentials,
// config secrets, or deployment artifacts worth a closer look --
// deliberately curated, not every word that could ever precede
// "password", to keep the spider's output signal-heavy.
var interestingNameSubstrings = []string{
	"password", "passwd", "credential", "secret", "unattend", "sysprep",
	"web.config", "id_rsa", "id_dsa", ".git-credentials", ".npmrc",
}

// isInterestingFile reports whether name's extension or filename itself
// commonly carries credentials or secrets.
func isInterestingFile(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range interestingExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	for _, sub := range interestingNameSubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

func joinHits(hits []shareHit) string {
	parts := make([]string, len(hits))
	for i, h := range hits {
		parts[i] = h.share + `\` + h.path
	}
	return strings.Join(parts, ", ")
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
		case KindAnonymousLogin, KindLoginOK, KindInterestingFile:
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

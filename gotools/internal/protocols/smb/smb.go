// Package smb implements the smb command: Phase 1, plus part of Phase 2,
// of the "SRT internal-pentest direction" doc's protocol-client
// roadmap. It wraps github.com/hirochachacha/go-smb2, the doc's chosen
// base SMB 2/3 library, with SRT's own connection metering (netx),
// credential attempts (protocols.Creds) and results-database wiring
// (store).
//
// The default behavior is the anonymous/null-session check: every
// target is tried with an anonymous session first (no flags needed at
// all), then with each -u/-p/-H attempt in turn if any were given --
// NTLM only (go-smb2 doesn't speak Kerberos; -k is accepted for
// CLI-schema consistency across every protocol command but not yet
// implemented here, see docs/ROADMAP.md). A session that's accepted is
// followed by a read-only share listing, a shallow per-share
// read-access check (ReadDir on the share root), and, unless
// -spider=false, a bounded recursive walk of every readable share
// (see spiderShare) flagging filenames that commonly carry secrets --
// netexec's spider_plus module, read-only. This package never writes,
// deletes or creates anything on the target.
package smb

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"path"
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
		Summary: "SMB 2/3 anonymous/NTLM session + share listing, read-access check and a bounded secrets spider",
		Run:     Run,
	})
}

// DefaultPort is SMB's well-known port (SMB over TCP, no NetBIOS session service).
const DefaultPort = 445

// Finding kinds this package reports.
const (
	KindAnonymousLogin  = "anonymous-login"  // an anonymous/null session was accepted
	KindLoginOK         = "login-ok"         // a given -u/-p/-H credential was accepted
	KindLoginFailed     = "login-failed"     // every given credential (and anonymous) was rejected
	KindInterestingFile = "interesting-file" // the spider found a filename that commonly carries secrets
)

// sharesToProbe caps how many non-admin shares get an actual ReadDir
// check per target, so a server with hundreds of shares doesn't turn
// one target into hundreds of extra round trips.
const sharesToProbe = 20

// Spider bounds: deep and wide enough to catch what a person would
// actually find browsing a share by hand, bounded so one huge share
// never turns into an unbounded walk. spiderMaxEntries is a budget
// shared across every share and every directory within it (checked
// before each ReadDir), not a per-directory cap.
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
	spider := fs.Bool("spider", true, "after a successful session, recursively walk every readable share (bounded depth/entries) flagging filenames that commonly carry secrets")
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
	perTarget := make([][]protocols.Finding, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *concurrency))
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t protocols.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			perTarget[i] = probe(t, attempts, *conn.Timeout, *spider)
		}(i, t)
	}
	wg.Wait()

	var results []protocols.Finding
	for _, fs := range perTarget {
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
	return nil
}

// probe tries each credential attempt against t in turn, dialing a
// fresh TCP connection per attempt (an SMB session that fails NTLM
// authentication isn't a safe connection to reuse for a retry -- a
// server is free to tear it down, and SRT would rather redial than
// guess at its state). The first attempt a session accepts wins: it's
// followed by a read-only share listing and, if spider is set, a
// bounded walk of every readable share -- so a target can report
// several Findings, not just one.
func probe(t protocols.Target, attempts []protocols.Credential, timeout time.Duration, spider bool) []protocols.Finding {
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
			return []protocols.Finding{{Target: t, Err: err.Error()}}
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

		report := inspectShares(sess)
		var hits []shareHit
		if spider {
			budget := spiderMaxEntries
			for _, share := range report.readable {
				if len(hits) >= spiderMaxHitsPerRun {
					break
				}
				hits = append(hits, spiderShare(sess, share, &budget)...)
			}
		}
		sess.Logoff()
		c.Close()

		kind := KindLoginOK
		if cr.IsAnonymous() {
			kind = KindAnonymousLogin
		}
		sev := protocols.High
		if len(report.readable) == 0 {
			sev = protocols.Medium // session accepted, but nothing beyond IPC$ was actually readable
		}
		findings := []protocols.Finding{{Target: t, Cred: cr, Kind: kind, Severity: sev, Detail: report.String()}}
		if len(hits) > 0 {
			if len(hits) > spiderMaxHitsPerRun {
				hits = hits[:spiderMaxHitsPerRun]
			}
			findings = append(findings, protocols.Finding{
				Target: t, Cred: cr, Kind: KindInterestingFile, Severity: protocols.High,
				Detail: fmt.Sprintf("%d file(s) matching known secret/credential patterns: %s", len(hits), joinHits(hits)),
			})
		}
		return findings
	}

	detail := "every login attempt was rejected"
	if lastErr != nil {
		detail = "rejected: " + lastErr.Error()
	}
	return []protocols.Finding{{Target: t, Kind: KindLoginFailed, Severity: protocols.Info, Detail: detail}}
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

// shareReport is what inspectShares finds: every share name, which of
// them turned out readable (candidates for spiderShare), and a
// precomputed access label per share for String()'s Detail line.
type shareReport struct {
	names    []string
	readable []string
	access   map[string]string // share name -> "IPC" | "readable" | "listed, not readable" | "no-access"
	listErr  error
}

// inspectShares lists sess's shares and, for up to sharesToProbe of
// them (skipping IPC$, which isn't a filesystem), checks whether its
// root directory can actually be read -- the distinction netexec's own
// output draws between "share exists" and "share is actually open".
func inspectShares(sess *smb2.Session) shareReport {
	names, err := sess.ListSharenames()
	if err != nil {
		return shareReport{listErr: err}
	}
	r := shareReport{names: names, access: map[string]string{}}
	checked := 0
	for _, name := range names {
		switch {
		case strings.EqualFold(name, "IPC$"):
			r.access[name] = "IPC"
		case checked >= sharesToProbe:
			r.access[name] = "not checked (share limit)"
		default:
			checked++
			access := shareAccess(sess, name)
			r.access[name] = access
			if access == "readable" {
				r.readable = append(r.readable, name)
			}
		}
	}
	return r
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
		parts[i] = fmt.Sprintf("%s (%s)", name, r.access[name])
	}
	return fmt.Sprintf("%d share(s): %s", len(r.names), strings.Join(parts, ", "))
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

// shareHit is one spiderShare match.
type shareHit struct {
	share string
	path  string
}

// spiderShare walks share's directory tree (bounded by spiderMaxDepth
// and *budget, a shared entry-visit budget across every share this
// probe call spiders) looking for filenames that commonly carry
// credentials or secrets -- netexec's spider_plus module, read-only:
// it never opens a file's contents, only lists directories and checks
// names.
func spiderShare(sess *smb2.Session, share string, budget *int) []shareHit {
	fsys, err := sess.Mount(share)
	if err != nil {
		return nil
	}
	defer fsys.Umount()
	var hits []shareHit
	walkDir(fsys, share, ".", 0, budget, &hits)
	return hits
}

func walkDir(fsys *smb2.Share, share, dir string, depth int, budget *int, hits *[]shareHit) {
	if depth > spiderMaxDepth || *budget <= 0 || len(*hits) >= spiderMaxHitsPerRun {
		return
	}
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if *budget <= 0 || len(*hits) >= spiderMaxHitsPerRun {
			return
		}
		*budget--
		rel := e.Name()
		if dir != "." {
			rel = path.Join(dir, e.Name())
		}
		if e.IsDir() {
			walkDir(fsys, share, rel, depth+1, budget, hits)
			continue
		}
		if isInterestingFile(e.Name()) {
			*hits = append(*hits, shareHit{share: share, path: rel})
		}
	}
}

// interestingExtensions are file extensions that are themselves
// credential/secret material (a password-manager database, a private
// key, a PKCS#12 bundle, ...), checked case-insensitively.
var interestingExtensions = []string{
	".kdbx", ".kdb", ".ppk", ".pem", ".key", ".pfx", ".p12", ".ovpn",
}

// interestingNameSubstrings are lowercase substrings in a filename
// (not its extension) that commonly show up in files holding
// credentials, config secrets, or deployment artifacts worth a closer
// look -- deliberately curated, not every word that could ever precede
// "password", to keep the spider's output signal-heavy.
var interestingNameSubstrings = []string{
	"password", "passwd", "credential", "secret", "unattend", "sysprep",
	"web.config", "id_rsa", "id_dsa", ".git-credentials", ".npmrc",
}

// isInterestingFile reports whether name's extension or filename
// itself commonly carries credentials or secrets.
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
		parts[i] = h.share + `\` + strings.ReplaceAll(h.path, "/", `\`)
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

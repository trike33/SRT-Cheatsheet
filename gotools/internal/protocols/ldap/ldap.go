// Package ldap implements the ldap command: Phase 1 and part of Phase 2
// of the "SRT internal-pentest direction" doc's protocol-client
// roadmap. It wraps github.com/go-ldap/ldap/v3, the doc's chosen LDAP
// library, with SRT's own connection metering (netx), credential
// attempts (protocols.Creds) and results-database wiring (store).
//
// The default behavior is the anonymous-bind check (RFC 4513 5.1.2: an
// empty DN and empty password is treated as anonymous), then each
// -u/-p attempt as a simple bind (-d builds a UPN, "user@domain", the
// form Active Directory's LDAP accepts), each -H attempt as an NTLM
// pass-the-hash bind, and each -k attempt as a Kerberos/GSSAPI bind
// (see kerberosBind). A successful bind is followed by a RootDSE
// search (namingContexts, dnsHostName, the supported LDAP version) --
// a read-only "(objectClass=*)" base-object search every LDAP server
// answers, authenticated or not -- and then, unless -enum=false,
// authenticated AD enumeration (see enumerate): AS-REP roastable
// accounts, privileged-group membership, and the domain password
// policy, all read-only LDAP searches.
package ldap

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	ldaplib "github.com/go-ldap/ldap/v3"
	krb5gssapi "github.com/go-ldap/ldap/v3/gssapi"

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
		Summary: "LDAP anonymous/simple/Kerberos bind + RootDSE and authenticated AD enumeration",
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
	KindAnonymousBind      = "anonymous-bind"          // an anonymous bind (empty DN + empty password) was accepted
	KindLoginOK            = "login-ok"                // a given -u/-p, -H or -k credential was accepted
	KindLoginFailed        = "login-failed"            // every given credential (and anonymous) was rejected
	KindDomainUsers        = "domain-users"             // a bulk user search succeeded
	KindASREPRoastable     = "asrep-roastable"          // account(s) with Kerberos pre-authentication disabled
	KindPrivilegedMembers  = "privileged-group-members" // member(s) of a well-known high-value AD group
	KindPasswordPolicy     = "password-policy"
	KindWeakPasswordPolicy = "weak-password-policy"
)

// userAccountControl bits this package cares about (MS-ADA3 2.247 /
// MS-SAMR 2.2.1.13).
const (
	uacAccountDisabled = 0x0002
	uacDontReqPreauth  = 0x400000 // AS-REP roastable: no Kerberos pre-authentication required
)

// privilegedGroups are the well-known AD groups worth calling out by
// name in enumerateUsers: compromising a member of any one of them is
// close to full domain compromise.
var privilegedGroups = []string{"Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins"}

// enumSizeLimit bounds the bulk user search enumerate runs, so a very
// large domain doesn't turn one target into an unbounded search.
const enumSizeLimit = 2000

func Run(args []string) error {
	fs := flag.NewFlagSet("ldap", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "CREDENTIALS", Names: []string{"u", "p", "H", "d", "local-auth", "k"}},
			{Title: "CONNECTION", Names: []string{"port", "timeout", "c"}},
			{Title: "ENUMERATION", Names: []string{"enum"}},
			{Title: "OUTPUT", Names: []string{"o", "json", "color"}},
		})
	}
	in := fs.String("l", "", "target list: host or host:port (default: stdin, else the project db's port records -- see -from)")
	fb := store.BindInputFallback(fs, "ldap", "port")
	creds := protocols.BindCreds(fs)
	conn := protocols.BindConn(fs, DefaultPort, 10*time.Second)
	concurrency := fs.Int("c", 20, "concurrent connections")
	enum := fs.Bool("enum", true, "after a successful bind, also run authenticated AD enumeration (AS-REP roastable accounts, privileged-group members, password policy) -- read-only LDAP searches")
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
	perTarget := make([][]protocols.Finding, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *concurrency))
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t protocols.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			perTarget[i] = probe(t, attempts, *conn.Timeout, *enum)
		}(i, t)
	}
	wg.Wait()

	var results []protocols.Finding
	for _, fs := range perTarget {
		results = append(results, fs...)
	}

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
// first attempt a bind accepts wins: it's followed by a RootDSE search
// and, if enum is set and a base DN is known, authenticated
// enumeration -- so a target can report several Findings, not just one.
func probe(t protocols.Target, attempts []protocols.Credential, timeout time.Duration, enum bool) []protocols.Finding {
	var lastErr error
	for _, cr := range attempts {
		netx.Request()
		raw, err := net.DialTimeout("tcp", t.String(), timeout)
		if err != nil {
			return []protocols.Finding{{Target: t, Err: err.Error()}}
		}
		c := netx.CountConn(raw)

		l := ldaplib.NewConn(c, false)
		l.Start()
		l.SetTimeout(timeout)

		if err := bind(l, t, cr); err != nil {
			l.Close()
			lastErr = err
			continue
		}

		dse := readRootDSE(l)
		kind := KindLoginOK
		sev := protocols.Medium
		switch {
		case cr.IsAnonymous():
			kind, sev = KindAnonymousBind, protocols.High
		case cr.Hash != "":
			sev = protocols.High // a pass-the-hash bind succeeding confirms a usable compromised hash
		case cr.Kerberos:
			sev = protocols.High // confirms a usable cleartext credential over Kerberos specifically
		}
		findings := []protocols.Finding{{Target: t, Cred: cr, Kind: kind, Severity: sev, Detail: dse.String()}}

		if enum {
			if base := dse.baseDN(); base != "" {
				findings = append(findings, enumerate(l, t, cr, base)...)
			}
		}
		l.Close()
		return findings
	}

	detail := "every bind attempt was rejected"
	if lastErr != nil {
		detail = "rejected: " + lastErr.Error()
	}
	return []protocols.Finding{{Target: t, Kind: KindLoginFailed, Severity: protocols.Info, Detail: detail}}
}

// bind performs the right kind of bind for cr: a true anonymous bind
// (empty DN + empty password) for protocols.Anonymous, an NTLM
// pass-the-hash bind when cr.Hash is set, a Kerberos/GSSAPI bind when
// cr.Kerberos is set, otherwise a simple bind -- against a UPN
// ("user@domain") when cr.Domain is set, matching how Active
// Directory's LDAP expects a simple-bind DN, else the bare username as
// given. Every simple bind goes through SimpleBind with
// AllowEmptyPassword, not the plain Bind method: Bind refuses an empty
// password client-side (RFC 4513's unauthenticated-bind warning), which
// would make an anonymous attempt error out before a single byte
// reaches the wire.
func bind(l *ldaplib.Conn, t protocols.Target, cr protocols.Credential) error {
	switch {
	case cr.Kerberos:
		return kerberosBind(l, t, cr)
	case cr.Hash != "":
		return l.NTLMBindWithHash(cr.Domain, cr.User, cr.Hash)
	default:
		dn := cr.User
		if cr.Domain != "" {
			dn = cr.User + "@" + cr.Domain
		}
		_, err := l.SimpleBind(&ldaplib.SimpleBindRequest{Username: dn, Password: cr.Password, AllowEmptyPassword: true})
		return err
	}
}

// kerberosBind authenticates with a TGT obtained over a connection
// gokrb5 opens itself straight to t.Host's port 88 (the KDC) -- a
// separate connection from l's, which does NOT go through netx's
// metering (gokrb5 exposes no dialer hook to route it through) -- using
// go-ldap's own gssapi.Client (merged as go-ldap PR #402, built on
// gokrb5), not a hand-rolled GSSAPI wrapper: that client's
// InitSecContext/NegotiateSaslAuth implement RFC 4752 3.1 and are
// exercised by go-ldap's own test suite, which is a meaningfully
// different confidence level than code written here with no live KDC
// to verify against (see docs/ROADMAP.md).
//
// Pass-the-key (a raw NT/AES key instead of a password) is NOT
// supported: gokrb5's public keytab.Keytab API only derives keys from a
// password (AddEntry), never accepts a raw key directly, so cr.Hash has
// no way in here -- see docs/ROADMAP.md.
//
// -d names the realm; since Active Directory's registered LDAP SPN is
// keyed to the DC's real hostname, not its IP, -k only works when the
// target was given as that hostname.
func kerberosBind(l *ldaplib.Conn, t protocols.Target, cr protocols.Credential) error {
	if cr.Domain == "" {
		return fmt.Errorf("-k needs -d <domain> (the Kerberos realm)")
	}
	if cr.Password == "" {
		return fmt.Errorf("-k needs -p <password>: pass-the-key isn't supported by srt's Kerberos library -- see docs/ROADMAP.md")
	}
	realm := strings.ToUpper(cr.Domain)
	confPath, cleanup, err := writeKrb5Conf(realm, t.Host)
	if err != nil {
		return fmt.Errorf("writing a temporary krb5.conf: %w", err)
	}
	defer cleanup()

	kc, err := krb5gssapi.NewClientWithPassword(cr.User, realm, cr.Password, confPath)
	if err != nil {
		return fmt.Errorf("kerberos client: %w", err)
	}
	defer kc.Close()

	return l.GSSAPIBind(kc, "ldap/"+t.Host, "")
}

// writeKrb5Conf writes the minimal krb5.conf gokrb5 needs to a fresh
// temp file: realm's KDC is kdcHost -- the common case for an internal
// pentest hitting a domain controller directly, which doubles as its
// own realm's KDC. DNS-based KDC/realm lookups are disabled so this
// never depends on the tester's resolver or a Kerberos install already
// being configured for an unrelated realm.
func writeKrb5Conf(realm, kdcHost string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "srt-krb5-*.conf")
	if err != nil {
		return "", func() {}, err
	}
	cleanup = func() { os.Remove(f.Name()) }
	_, werr := fmt.Fprintf(f, "[libdefaults]\ndefault_realm = %s\ndns_lookup_kdc = false\ndns_lookup_realm = false\nrdns = false\n\n[realms]\n%s = {\n\tkdc = %s\n}\n",
		realm, realm, kdcHost)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		cleanup()
		return "", func() {}, werr
	}
	return f.Name(), cleanup, nil
}

// rootDSE is what readRootDSE pulls out of the anonymous base-object
// search every LDAP server answers.
type rootDSE struct {
	dnsHostName    string
	namingContexts []string
	defaultNC      string
	ldapVersion    string
	err            error
}

func readRootDSE(l *ldaplib.Conn) rootDSE {
	req := ldaplib.NewSearchRequest("", ldaplib.ScopeBaseObject, ldaplib.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", rootDSEAttrs, nil)
	res, err := l.Search(req)
	if err != nil {
		return rootDSE{err: err}
	}
	if len(res.Entries) == 0 {
		return rootDSE{}
	}
	e := res.Entries[0]
	return rootDSE{
		dnsHostName:    e.GetAttributeValue("dnsHostName"),
		namingContexts: e.GetAttributeValues("namingContexts"),
		defaultNC:      e.GetAttributeValue("defaultNamingContext"),
		ldapVersion:    e.GetAttributeValue("supportedLDAPVersion"),
	}
}

// baseDN is where enumerate starts its subtree searches: the domain's
// own naming context, preferring defaultNamingContext (AD's own hint)
// over the first plain namingContexts entry (which, on AD, can also
// list the schema/configuration partitions).
func (d rootDSE) baseDN() string {
	if d.defaultNC != "" {
		return d.defaultNC
	}
	if len(d.namingContexts) > 0 {
		return d.namingContexts[0]
	}
	return ""
}

func (d rootDSE) String() string {
	if d.err != nil {
		return "bind accepted, but the RootDSE search failed: " + d.err.Error()
	}
	var parts []string
	if d.dnsHostName != "" {
		parts = append(parts, "dnsHostName="+d.dnsHostName)
	}
	if len(d.namingContexts) > 0 {
		parts = append(parts, "namingContexts=["+strings.Join(d.namingContexts, ", ")+"]")
	}
	if d.ldapVersion != "" {
		parts = append(parts, "LDAPv"+d.ldapVersion)
	}
	if len(parts) == 0 {
		return "bind accepted; RootDSE had none of the requested attributes"
	}
	return strings.Join(parts, "; ")
}

// enumerate runs the authenticated-enumeration searches -enum enables:
// a bulk user search (AS-REP roastable accounts, privileged-group
// membership) and the domain password policy. Every search here is
// read-only and bounded (enumSizeLimit, or none needed for the
// base-object password-policy read); a search this account can't run
// (insufficient access, usually) is just dropped, not reported as an
// error -- enumeration is a bonus on top of a successful bind, not
// something the bind itself should be judged to have failed over.
func enumerate(l *ldaplib.Conn, t protocols.Target, cr protocols.Credential, baseDN string) []protocols.Finding {
	var out []protocols.Finding
	out = append(out, enumerateUsers(l, t, cr, baseDN)...)
	if f, ok := enumeratePasswordPolicy(l, t, cr, baseDN); ok {
		out = append(out, f)
	}
	return out
}

// enumerateUsers runs the bulk person/user search and reduces it to a
// headline count plus two higher-value findings when they apply:
// AS-REP roastable accounts (userAccountControl's
// DONT_REQ_PREAUTH bit -- MS-SAMR 2.2.1.13) and membership in one of
// privilegedGroups (via each user's memberOf).
func enumerateUsers(l *ldaplib.Conn, t protocols.Target, cr protocols.Credential, baseDN string) []protocols.Finding {
	req := ldaplib.NewSearchRequest(baseDN, ldaplib.ScopeWholeSubtree, ldaplib.NeverDerefAliases, enumSizeLimit, 0, false,
		"(&(objectCategory=person)(objectClass=user))", []string{"sAMAccountName", "userAccountControl", "memberOf"}, nil)
	res, err := l.Search(req)
	if res == nil || len(res.Entries) == 0 {
		_ = err
		return nil
	}

	var asrep []string
	enabled, disabled := 0, 0
	privileged := map[string][]string{} // group display name -> usernames
	for _, e := range res.Entries {
		name := e.GetAttributeValue("sAMAccountName")
		uac, _ := strconv.ParseInt(e.GetAttributeValue("userAccountControl"), 10, 64)
		if uac&uacAccountDisabled != 0 {
			disabled++
		} else {
			enabled++
		}
		if uac&uacDontReqPreauth != 0 && name != "" {
			asrep = append(asrep, name)
		}
		for _, dn := range e.GetAttributeValues("memberOf") {
			upperDN := strings.ToUpper(dn)
			for _, g := range privilegedGroups {
				if strings.HasPrefix(upperDN, "CN="+strings.ToUpper(g)+",") {
					privileged[g] = append(privileged[g], name)
				}
			}
		}
	}

	findings := []protocols.Finding{{
		Target: t, Cred: cr, Kind: KindDomainUsers, Severity: protocols.Info,
		Detail: fmt.Sprintf("%d user(s) enumerated (%d enabled, %d disabled)", len(res.Entries), enabled, disabled),
	}}
	if len(asrep) > 0 {
		findings = append(findings, protocols.Finding{
			Target: t, Cred: cr, Kind: KindASREPRoastable, Severity: protocols.High,
			Detail: fmt.Sprintf("%d account(s) with Kerberos pre-authentication disabled: %s", len(asrep), joinCapped(asrep, 20)),
		})
	}
	for _, g := range privilegedGroups {
		if members := privileged[g]; len(members) > 0 {
			findings = append(findings, protocols.Finding{
				Target: t, Cred: cr, Kind: KindPrivilegedMembers, Severity: protocols.Medium,
				Detail: fmt.Sprintf("%s: %s", g, joinCapped(members, 20)),
			})
		}
	}
	return findings
}

// enumeratePasswordPolicy reads the domain password policy off the
// base DN object itself (every one of these attributes lives directly
// on the domain object in Active Directory, not a separate policy
// object) and flags it weak when the minimum length is under 8,
// complexity isn't required, or accounts never lock out.
func enumeratePasswordPolicy(l *ldaplib.Conn, t protocols.Target, cr protocols.Credential, baseDN string) (protocols.Finding, bool) {
	req := ldaplib.NewSearchRequest(baseDN, ldaplib.ScopeBaseObject, ldaplib.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"minPwdLength", "lockoutThreshold", "maxPwdAge", "pwdProperties"}, nil)
	res, err := l.Search(req)
	if err != nil || len(res.Entries) == 0 {
		return protocols.Finding{}, false
	}
	e := res.Entries[0]
	minLen := e.GetAttributeValue("minPwdLength")
	lockoutThreshold := e.GetAttributeValue("lockoutThreshold")

	complexity := "unknown"
	if v, err := strconv.ParseInt(e.GetAttributeValue("pwdProperties"), 10, 64); err == nil {
		if v&0x1 != 0 {
			complexity = "required"
		} else {
			complexity = "not required"
		}
	}

	maxAge := "unknown"
	if raw := e.GetAttributeValue("maxPwdAge"); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			if v == 0 {
				maxAge = "never expires"
			} else {
				maxAge = fmt.Sprintf("%d day(s)", adInterval100nsToDays(v))
			}
		}
	}

	weak := false
	if n, err := strconv.Atoi(minLen); err == nil && n < 8 {
		weak = true
	}
	if lockoutThreshold == "0" {
		weak = true
	}
	if complexity == "not required" {
		weak = true
	}

	kind, sev := KindPasswordPolicy, protocols.Info
	if weak {
		kind, sev = KindWeakPasswordPolicy, protocols.Medium
	}
	detail := fmt.Sprintf("minLength=%s, complexity=%s, maxAge=%s, lockoutThreshold=%s",
		orDash(minLen), complexity, maxAge, orDash(lockoutThreshold))
	return protocols.Finding{Target: t, Cred: cr, Kind: kind, Severity: sev, Detail: detail}, true
}

// adInterval100nsToDays converts an Active Directory "Interval"
// attribute (a count of 100-nanosecond ticks, negative because it
// counts back from now) to whole days.
func adInterval100nsToDays(v int64) int64 {
	if v < 0 {
		v = -v
	}
	const ticksPerDay = 24 * 60 * 60 * 10000000
	return v / ticksPerDay
}

func joinCapped(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(", +%d more", len(items)-n)
}

func orDash(s string) string {
	if s == "" {
		return "-"
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
		case KindAnonymousBind, KindLoginOK, KindASREPRoastable:
			color = colorout.Red
		case "error":
			color = colorout.Gray
		case KindLoginFailed:
			color = colorout.Green
		case KindPrivilegedMembers, KindWeakPasswordPolicy:
			color = colorout.Yellow
		}
		fmt.Fprintf(w, "%s  %s  %s\n",
			cm.PadWrap("", r.target, widths[0]),
			cm.PadWrap(color, r.kind, widths[1]),
			cm.Wrap("", r.detail))
	}
}

// Package protocols is the shared foundation every SRT protocol-client
// command (ftp, telnet, smb, ldap, and the ones that follow in later
// phases) builds on: the Target/Credential/Finding shapes a future
// pipeline step can consume uniformly, and the netexec-style
// credential/connection flags every protocol command accepts the same
// way (-u/-p/-H/-d/--local-auth/-k/--port/--timeout) -- see the "SRT
// internal-pentest direction" doc's CLI flag schema and proposed
// architecture.
//
// Phase 1 (ftp, telnet, smb, ldap) ships no -M/-o module flags yet --
// each protocol package below is the default anonymous/credentialed
// enumeration path only -- but BindCreds' shape is the one later phases'
// modules will also read credentials through, so adding -M/-o later
// doesn't change how a protocol command reads -u/-p/-H/-d.
package protocols

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

// EnvKRB5CCName is the standard MIT krb5 ticket-cache environment
// variable -- a path to a ccache file holding a TGT (and, maybe, service
// tickets) obtained elsewhere (kinit, Rubeus, impacket's getTGT.py, ...),
// letting -k authenticate from an existing ticket instead of needing
// -p/-H at all ("pass-the-ticket"). smb's go-smb checks it transparently
// inside its own Kerberos client construction (krb5ssp.InitKerberosClient
// tries it before ever falling back to a password/hash), so smb's own
// buildKerberosInitiator needs no extra code to use it; ldap's
// go-ldap/gssapi does not check it on its own, so ldap.go's kerberosBind
// reads it explicitly to choose between gssapi.NewClientFromCCache and
// NewClientWithPassword. The srt shell's own "krb5" built-in sets this
// for every command it launches -- see internal/shell.
const EnvKRB5CCName = "KRB5CCNAME"

// Target is one host:port a protocol command probes.
type Target struct {
	Host string
	Port int
}

func (t Target) String() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// ParseTarget splits a "host", "host:port" or "[ipv6]:port" line into a
// Target, falling back to defaultPort when the line names no port.
func ParseTarget(line string, defaultPort int) (Target, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	// A bare host (no colon at all, e.g. "10.0.0.1" or "dc01.corp.local")
	// never carries a port; everything else goes through
	// net.SplitHostPort so IPv6 ("[::1]:445") and a bad port
	// ("host:abc") are both rejected the same way net/http itself would,
	// rather than half-parsed.
	if !strings.Contains(line, ":") {
		return Target{Host: line, Port: defaultPort}, nil
	}
	host, portStr, err := net.SplitHostPort(line)
	if err != nil {
		return Target{}, fmt.Errorf("invalid target %q: %w", line, err)
	}
	if portStr == "" {
		return Target{Host: host, Port: defaultPort}, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return Target{}, fmt.Errorf("invalid target %q: bad port %q", line, portStr)
	}
	return Target{Host: host, Port: port}, nil
}

// Credential is one login attempt. The zero value is Anonymous: no
// username, no secret -- a null session / anonymous bind / anonymous FTP
// login, tried first by every protocol command with no flags at all.
type Credential struct {
	User      string
	Password  string
	Hash      string // NTLM/NT hash, for pass-the-hash (Phase 2+; see docs/ROADMAP.md)
	Domain    string
	LocalAuth bool // authenticate against the target's local SAM, not the domain
	Kerberos  bool // use Kerberos auth instead of NTLM (Phase 2+; see docs/ROADMAP.md)
}

// Anonymous is the credential a protocol command tries when no -u is
// given, or always first when one is.
var Anonymous = Credential{}

// IsAnonymous reports whether c carries no username at all.
func (c Credential) IsAnonymous() bool { return c.User == "" }

// String renders c for a Finding's "cred" detail and for log lines --
// never the password or hash itself.
func (c Credential) String() string {
	if c.IsAnonymous() {
		return "(anonymous)"
	}
	who := c.User
	if c.Domain != "" {
		who = c.Domain + "\\" + c.User
	}
	switch {
	case c.Hash != "":
		return who + " (pass-the-hash)"
	case c.Kerberos:
		return who + " (kerberos)"
	default:
		return who
	}
}

// UserPass renders c as netexec's own output does on a success line --
// "domain\user:password" (or "user:password" with no domain, or
// "user:hash" for pass-the-hash) -- the one place a protocol command
// deliberately shows the secret itself, unlike String above. Confirming
// exactly which credential worked, in cleartext, right there in the
// line that says so, is the point of that output style: the person
// running the command already supplied it. Anonymous renders as "".
func (c Credential) UserPass() string {
	if c.IsAnonymous() {
		return ""
	}
	who := c.User
	if c.Domain != "" {
		who = c.Domain + `\` + c.User
	}
	secret := c.Password
	if c.Hash != "" {
		secret = c.Hash
	}
	return who + ":" + secret
}

// Severity is how serious a Finding is -- the same four-level scale every
// protocol command uses, for consistent coloring/sorting with the rest of
// srt's results (see colorout.StatusColor for the HTTP-status equivalent).
type Severity string

const (
	Info   Severity = "info"
	Low    Severity = "low"
	Medium Severity = "medium"
	High   Severity = "high"
)

// Finding is one discrete result a protocol probe reports against a
// Target: the doc-proposed roadmap's Finding{Kind, Detail, Severity}
// shape, plus the target and credential it came from so Record can
// reduce it to the generic store shape every recon package shares.
type Finding struct {
	Target   Target
	Cred     Credential
	Kind     string // short, stable tag: "anonymous-login", "null-session", "share", "weak-auth", "banner", ...
	Detail   string
	Severity Severity
	Err      string // set instead of Kind/Detail when the attempt itself failed (refused, timed out, auth rejected)
	// Hostname is the target's own resolved name, when the protocol
	// happened to hand one over for free (SMB's NTLM challenge, LDAP's
	// RootDSE dnsHostName, ...) -- left empty for a protocol with no
	// such concept (ssh, mssql, vnc, ftp, telnet, rdp), in which case
	// Line falls back to the bare host, the same way netexec's own
	// hostname column does.
	Hostname string
	// Accepted marks f as the one Finding per probe call that reports a
	// session/login actually being let in -- an anonymous/null session,
	// a no-auth shell, or a real credential (set by each package's own
	// probe on exactly that Finding, never on a banner, a rejected
	// attempt, or a follow-up enumeration Finding tied to the same
	// already-accepted credential). It's what `srt creds` filters the
	// results database on: a plain severity/Kind check alone can't tell
	// "got in" apart from "every attempt was rejected", since both can
	// otherwise look alike (no Err, no Cred, a similar Severity).
	Accepted bool
}

// Record reduces f to the generic shape the results database stores,
// under protoKind ("ftp", "telnet", "smb", "ldap", ...) -- the new result
// kind the doc's "Fit with SRT's current architecture" section describes
// sitting alongside the existing portscan/probe/fuzz kinds.
func (f Finding) Record(protoKind string) store.Record {
	kind := f.Kind
	if kind == "" {
		kind = "error"
	}
	key := fmt.Sprintf("%s/%s/%s", f.Target, kind, f.Cred)
	d := map[string]any{}
	if f.Detail != "" {
		d["detail"] = f.Detail
	}
	if f.Severity != "" {
		d["severity"] = string(f.Severity)
	}
	if !f.Cred.IsAnonymous() {
		d["cred"] = f.Cred.String()
	}
	if f.Hostname != "" {
		d["hostname"] = f.Hostname
	}
	if f.Err != "" {
		d["error"] = f.Err
	}
	if f.Accepted {
		d["ok"] = true
	}
	return store.Record{Kind: protoKind, Key: key, Host: f.Target.Host, Port: f.Target.Port, Data: d}
}

// CredText renders c for a success line exactly the way UserPass does
// for a real credential (the secret itself, "domain\user:password"),
// but falls back to String's "(anonymous)" marker when there's no
// username to show a secret for -- the one line each protocol command
// prints for a login/session that was accepted, kept clean of any
// banner or enumeration text (those get their own Info lines).
func (c Credential) CredText() string {
	if up := c.UserPass(); up != "" {
		return up
	}
	return c.String()
}

// Symbol is netexec's own bracketed per-line outcome marker.
type Symbol string

const (
	SymInfo    Symbol = "*" // a banner/fingerprint/enumeration line -- no success/failure judgment
	SymSuccess Symbol = "+" // a credential, or a no-auth/anonymous check, was accepted
	SymFailure Symbol = "-" // every attempt was rejected, or a connection-level error
)

// Line renders f in netexec's own one-line output style -- what every
// protocol command in this family prints instead of a table:
//
//	PROTO     host             port   hostname         [symbol] message (Pwn3d!)
//
// proto is upper-cased and column-padded the way netexec's own module
// names are. hostname falls back to the bare host when f.Hostname is
// unknown. pwned appends " (Pwn3d!)" -- never decided by Line itself;
// each protocol package's own printTable decides when its access level
// earns it (see each command's doc comment on printTable for exactly
// which Kind/credential combination that is, and why).
func (f Finding) Line(proto string, cm colorout.Mode, symbol Symbol, message string, pwned bool) string {
	hostname := f.Hostname
	if hostname == "" {
		hostname = f.Target.Host
	}
	color := colorout.Cyan
	switch symbol {
	case SymSuccess:
		color = colorout.Green
	case SymFailure:
		color = colorout.Red
	}
	line := fmt.Sprintf("%s  %s  %s  %s  %s",
		cm.PadWrap("", strings.ToUpper(proto), 8),
		cm.PadWrap("", f.Target.Host, 16),
		cm.PadWrap("", strconv.Itoa(f.Target.Port), 6),
		cm.PadWrap("", hostname, 16),
		cm.Wrap(color, "["+string(symbol)+"] "+message))
	if pwned {
		line += cm.Wrap(colorout.Red, " (Pwn3d!)")
	}
	return line
}

// --- shared CLI flags (netexec-style global flags, see the doc's CLI flag schema) ---

// stringList is a repeatable string flag ("-u a -u b" -> ["a","b"]).
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// Creds is the parsed form of the shared credential flags (-u/-p/-H/-d/
// --local-auth/-k), bound once per command via BindCreds.
type Creds struct {
	users     stringList
	passwords stringList
	hashes    stringList
	domain    *string
	localAuth *bool
	kerberos  *bool
}

// BindCreds registers the credential/connection flags every protocol
// command accepts the same way, following netexec's convention (see the
// doc's "CLI flag schema" section). Call before fs.Parse.
func BindCreds(fs *flag.FlagSet) *Creds {
	c := &Creds{}
	fs.Var(&c.users, "u", "username (repeatable for multiple users; default: anonymous/unauthenticated only)")
	fs.Var(&c.passwords, "p", "password (repeatable, paired with -u in listed order; -p '' forces an empty password)")
	fs.Var(&c.hashes, "H", "NTLM/NT hash, for pass-the-hash (repeatable, paired with -u in listed order; not yet used by every protocol -- see docs/ROADMAP.md)")
	c.domain = fs.String("d", "", "AD domain")
	c.localAuth = fs.Bool("local-auth", false, "authenticate against the target's local SAM, not the domain")
	c.kerberos = fs.Bool("k", false, "use Kerberos auth instead of NTLM/simple bind, where this command supports it (smb and ldap do; see docs/ROADMAP.md for the rest)")
	return c
}

// Attempts resolves the bound flags into the credential attempts a probe
// should try, in order: one Credential per -u first, paired positionally
// with -p/-H (a -u with neither is tried with an empty password, not
// skipped -- "-u alone" means "this account, blank password", matching
// -p ''), then Anonymous last. Dangling -p/-H entries past the last -u
// are ignored with a warning from the caller (see WarnDangling).
//
// Anonymous goes last, not first, because every probe stops at the first
// attempt a session accepts (see e.g. smb's probe): many targets allow a
// null/anonymous session, and trying it before an explicit -u/-p would
// let that lesser session win and silently pre-empt the real credential
// the person actually asked to test. A pure-anonymous run (no -u at all)
// still gets exactly one attempt, [Anonymous], same as before.
func (c *Creds) Attempts() []Credential {
	var out []Credential
	for i, u := range c.users {
		cr := Credential{User: u, Domain: *c.domain, LocalAuth: *c.localAuth, Kerberos: *c.kerberos}
		if i < len(c.passwords) {
			cr.Password = c.passwords[i]
		}
		if i < len(c.hashes) {
			cr.Hash = c.hashes[i]
		}
		out = append(out, cr)
	}
	out = append(out, Anonymous)
	return out
}

// HasCreds reports whether any -u was given (a pure-anonymous run has
// none), so a command can skip printing "trying anonymous..." noise when
// the person clearly wants a credentialed check.
func (c *Creds) HasCreds() bool { return len(c.users) > 0 }

// RawPasswords returns every -p value given, regardless of whether any
// -u was given to pair it with. Attempts requires a -u to produce any
// non-anonymous Credential at all (so a lone -p with no -u is a
// Dangling entry, silently dropped there) -- which is right for every
// protocol with a real username, but wrong for one that has no
// username concept at all (vnc's classic security types: RFC 6143 has
// no login name, only a password). A command for such a protocol reads
// its passwords from here instead of Attempts, and should not also
// call Dangling for -p (there's nothing dangling about a username-less
// password).
func (c *Creds) RawPasswords() []string { return append([]string(nil), c.passwords...) }

// Dangling reports -p/-H entries with no matching -u, a near-certain
// command-line mistake (netexec itself requires -u before -p) worth
// warning about rather than silently dropping.
func (c *Creds) Dangling() (extraPasswords, extraHashes int) {
	if n := len(c.passwords) - len(c.users); n > 0 {
		extraPasswords = n
	}
	if n := len(c.hashes) - len(c.users); n > 0 {
		extraHashes = n
	}
	return
}

// Conn is the parsed form of the shared connection flags (-port/-timeout),
// bound once per command via BindConn alongside BindCreds.
type Conn struct {
	Port    *int
	Timeout *time.Duration
}

// BindConn registers the connection flags every protocol command accepts
// the same way: -port (override the protocol's default port) and
// -timeout (per-connection timeout). Call before fs.Parse.
func BindConn(fs *flag.FlagSet, defaultPort int, defaultTimeout time.Duration) *Conn {
	return &Conn{
		Port:    fs.Int("port", defaultPort, "override the protocol's default port"),
		Timeout: fs.Duration("timeout", defaultTimeout, "per-connection timeout"),
	}
}

// ResolveTargets is fb.Resolve with one addition: when -l isn't given and
// the positional args aren't an existing file, they're taken as targets
// themselves (`srt smb 10.0.0.5 10.0.0.6:4455`), the way netexec takes
// them. A single arg that names a file still reads as a target list.
func ResolveTargets(fb *store.InputFallback, flagValue string, positional []string) ([]string, string, error) {
	if flagValue == "" && len(positional) > 0 {
		if _, err := os.Stat(positional[0]); err != nil && os.IsNotExist(err) {
			var lines []string
			for _, p := range positional {
				if p = strings.TrimSpace(p); p != "" {
					lines = append(lines, p)
				}
			}
			return lines, "", nil
		}
	}
	return fb.Resolve(flagValue, positional)
}

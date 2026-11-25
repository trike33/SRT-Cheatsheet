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
	"strconv"
	"strings"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

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
	if f.Err != "" {
		d["error"] = f.Err
	}
	return store.Record{Kind: protoKind, Key: key, Host: f.Target.Host, Port: f.Target.Port, Data: d}
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
	c.kerberos = fs.Bool("k", false, "use Kerberos auth instead of NTLM (not yet implemented -- see docs/ROADMAP.md)")
	return c
}

// Attempts resolves the bound flags into the credential attempts a probe
// should try, in order: always Anonymous first (so a pure anonymous run
// needs no flags at all), then one Credential per -u, paired
// positionally with -p/-H (a -u with neither is tried with an empty
// password, not skipped -- "-u alone" means "this account, blank
// password", matching -p ''). Dangling -p/-H entries past the last -u are
// ignored with a warning from the caller (see WarnDangling).
func (c *Creds) Attempts() []Credential {
	out := []Credential{Anonymous}
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
	return out
}

// HasCreds reports whether any -u was given (a pure-anonymous run has
// none), so a command can skip printing "trying anonymous..." noise when
// the person clearly wants a credentialed check.
func (c *Creds) HasCreds() bool { return len(c.users) > 0 }

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

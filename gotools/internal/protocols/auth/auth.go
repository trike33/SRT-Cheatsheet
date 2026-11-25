// Package auth holds the credential/connection flags every protocol command
// under internal/protocols shares -- the netexec-style global flag schema
// (-u/-p/-H/-d/--local-auth/-k/--port/--timeout/-M/-o) -- so adding a new
// protocol command never means re-inventing flag names or parsing. See
// docs/internal-pentest-feasibility (the design doc) for the schema.
package auth

import (
	"errors"
	"flag"
	"time"
)

// Creds is one set of credentials to try against a target. Anonymous is the
// zero value: no user, no password, no hash -- every protocol package treats
// that as "attempt anonymous/guest access" rather than an error.
type Creds struct {
	User     string
	Password string
	Hash     string // NTLM/NT hash, hex, for pass-the-hash
	Domain   string
	Local    bool // --local-auth: authenticate against the target's local SAM, not the domain
	Kerberos bool // -k: use Kerberos instead of NTLM where the protocol supports both
}

// Anonymous reports whether c carries no credential material at all, so a
// protocol package knows to attempt an anonymous/guest connection instead of
// a bind/login.
func (c Creds) Anonymous() bool {
	return c.User == "" && c.Password == "" && c.Hash == ""
}

// Options is the common connection/behavior flags every protocol command
// binds the same way, plus the module hook (-M/-o) later phases plug into.
type Options struct {
	Port    int // 0 means "use the protocol's default"
	Timeout time.Duration
	Module  string
	ModOpts map[string]string
}

// modOptsValue implements flag.Value for repeated `-o key=val` options.
type modOptsValue struct{ m *map[string]string }

func (v modOptsValue) String() string { return "" }
func (v modOptsValue) Set(s string) error {
	k, val, ok := cut(s)
	if !ok {
		return errors.New("expected -o key=val")
	}
	if *v.m == nil {
		*v.m = map[string]string{}
	}
	(*v.m)[k] = val
	return nil
}

func cut(s string) (before, after string, found bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// Flags holds the pointers Bind registers on a flag.FlagSet; call Resolve
// after fs.Parse to get the Creds/Options a protocol package's Run uses.
type Flags struct {
	user, password, hash, domain *string
	local, kerberos              *bool
	port                         *int
	timeout                      *time.Duration
	module                       *string
	modOpts                      map[string]string
}

// Bind registers the shared global flags on fs (call before fs.Parse),
// defaultPort being the protocol's well-known port (e.g. 21 for FTP, 445 for
// SMB) shown in -port's usage text and used by Resolve when -port is left at
// its zero value.
func Bind(fs *flag.FlagSet, defaultPort int) *Flags {
	f := &Flags{}
	f.user = fs.String("u", "", "username (repeatable in a future phase; single value for now)")
	f.password = fs.String("p", "", "password")
	f.hash = fs.String("H", "", "NTLM/NT hash, for pass-the-hash")
	f.domain = fs.String("d", "", "AD domain")
	f.local = fs.Bool("local-auth", false, "authenticate against the target's local SAM, not the domain")
	f.kerberos = fs.Bool("k", false, "use Kerberos auth instead of NTLM where supported")
	f.port = fs.Int("port", defaultPort, "target port")
	f.timeout = fs.Duration("timeout", 10*time.Second, "per-connection timeout")
	f.module = fs.String("M", "", "run a named module instead of the default enumeration (phase 2+)")
	fs.Var(modOptsValue{&f.modOpts}, "o", "module option as key=val (repeatable)")
	return f
}

// Resolve reads the parsed flag values into a Creds and an Options. Call it
// after fs.Parse.
func (f *Flags) Resolve() (Creds, Options) {
	return Creds{
			User:     *f.user,
			Password: *f.password,
			Hash:     *f.hash,
			Domain:   *f.domain,
			Local:    *f.local,
			Kerberos: *f.kerberos,
		}, Options{
			Port:    *f.port,
			Timeout: *f.timeout,
			Module:  *f.module,
			ModOpts: f.modOpts,
		}
}

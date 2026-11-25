// Package auth holds the credential/connection flags every protocol command
// under internal/protocols shares -- the netexec-style global flag schema
// (-u/-p/-H/-d/--local-auth/-k/--port/--timeout/-M/-o) -- so adding a new
// protocol command never means re-inventing flag names or parsing. See
// docs/internal-pentest-feasibility (the design doc) for the schema.
package auth

import (
	"errors"
	"flag"
	"strings"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
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

// Reorder lets a protocol command accept its target anywhere on the command
// line -- netexec-style `srt smb 10.0.0.5 -u alice -p pass`, not just
// `srt smb -u alice -p pass 10.0.0.5` -- despite Go's flag.FlagSet.Parse
// stopping at the first non-flag token (after which everything, flags
// included, lands unparsed in fs.Args()). Call it on the raw args, after
// every flag is registered on fs but before fs.Parse: it moves every flag
// (and, for a non-boolean flag, the value token right after it) to the
// front, in order, and every other token to the back, also in order, so
// fs.Parse(Reorder(fs, args)) parses every flag regardless of where the
// target appeared, and fs.Args() after that call holds just the targets.
//
// A bare "--" stops reordering: everything after it is taken as positional,
// matching flag.FlagSet's own "--" convention.
func Reorder(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' || a == "-" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			continue // "-name=value" already carries its value
		}
		fl := fs.Lookup(name)
		isBool := false
		if fl != nil {
			if b, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok {
				isBool = b.IsBoolFlag()
			}
		}
		if !isBool && i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return append(flags, positional...)
}

// ResolveTargets returns the targets a protocol command should probe.
// Unlike most srt commands -- where internal/ioutil's ResolveInput treats a
// single positional argument as a *file path* to read lines from, the same
// as -l -- a protocol command's positional arguments are taken as literal
// hosts: netexec-style `srt smb 10.0.0.5 10.0.0.6`, not a target-list file.
// That fits how these commands actually get used (pointed at one host, or a
// handful typed inline) better than the file convention recon's bulk-list
// commands need. -l (an explicit file), stdin, or the project db fallback
// via fb still work exactly as ResolveInput/InputFallback always have --
// positional only short-circuits those when it's non-empty.
func ResolveTargets(l string, positional []string, fb *store.InputFallback) ([]string, string, error) {
	if len(positional) > 0 {
		return positional, "", nil
	}
	return fb.Resolve(l, nil)
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

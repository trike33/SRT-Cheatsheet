// Package smb implements the smb command: Phase 1 of SRT's internal-pentest
// protocol family (see docs/internal-pentest-feasibility). It wraps
// hirochachacha/go-smb2 rather than re-implementing SMB2/3 -- the design
// doc's call to integrate existing Go libraries instead of porting
// impacket's SMB client from scratch.
//
// Default behavior: attempt a null session (empty user/password) or, with
// -u/-p/-H, that credential, then list the target's shares with a
// best-effort READ-access probe on each (no write probe: this never writes
// to a target without being asked to). go-smb2 doesn't expose OS
// version/signing/dialect through its public API, so unlike netexec this
// can't print a full host fingerprint line -- Phase 3's DCE/RPC work
// (srvsvc/wkssvc, see the design doc) is where that becomes possible.
// Phase 2 adds authenticated file access and the -M module hook already
// wired in internal/protocols/auth.
package smb

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	smb2 "github.com/hirochachacha/go-smb2"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols/auth"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "smb",
		Group:   "PROTOCOLS",
		Summary: "SMB null-session/credentialed share enumeration (Phase 1 of the internal-pentest protocol family)",
		Run:     Run,
	})
}

// ShareInfo is one enumerated share, with a best-effort READ-access result
// and, for Windows' well-known default shares, the remark netexec/Windows
// itself shows for them (go-smb2 has no API for a server-supplied remark on
// a custom share, so those come back blank rather than guessed).
type ShareInfo struct {
	Name   string `json:"name"`
	Read   bool   `json:"read"`
	Remark string `json:"remark,omitempty"`
}

// defaultRemarks are the comments Windows itself assigns its built-in
// shares -- the same strings `net share` and netexec show for them.
var defaultRemarks = map[string]string{
	"ADMIN$":   "Remote Admin",
	"IPC$":     "Remote IPC",
	"NETLOGON": "Logon server share",
	"SYSVOL":   "Logon server share",
	"PRINT$":   "Printer Drivers",
}

func remarkFor(share string) string {
	if r, ok := defaultRemarks[share]; ok {
		return r
	}
	if len(share) == 2 && share[1] == '$' { // C$, D$, E$, ...
		return "Default share"
	}
	return ""
}

// Result is one target's SMB probe outcome.
type Result struct {
	Target         string      `json:"target"`
	Port           int         `json:"port"`
	LoginAttempted string      `json:"login_attempted,omitempty"` // "" (null session), or domain\user
	Secret         string      `json:"-"`                         // the password or "<hash> (pass-the-hash)" shown alongside LoginAttempted in terminal output, deliberately left out of JSON/the results DB
	LoginOK        bool        `json:"login_ok"`
	Shares         []ShareInfo `json:"shares,omitempty"`
	Err            string      `json:"error,omitempty"`
}

// Record reduces r to the generic shape the results database stores.
func (r Result) Record() store.Record {
	d := map[string]any{"login_ok": r.LoginOK}
	if r.LoginAttempted != "" {
		d["login_attempted"] = r.LoginAttempted
	} else {
		d["login_attempted"] = "null session"
	}
	if len(r.Shares) > 0 {
		shares := make([]map[string]any, len(r.Shares))
		for i, s := range r.Shares {
			shares[i] = map[string]any{"name": s.Name, "read": s.Read, "remark": s.Remark}
		}
		d["shares"] = shares
	}
	if r.Err != "" {
		d["error"] = r.Err
	}
	key := fmt.Sprintf("%s:%d", r.Target, r.Port)
	return store.Record{Kind: "smb", Key: key, Host: r.Target, Port: r.Port, Data: d}
}

// canRead attempts a READ-only check on share: mount it and list its root.
// It never writes anything. A failure of any kind (access denied, timeout,
// the share not existing) just means "not readable", not an error worth
// surfacing on its own.
func canRead(sess *smb2.Session, share string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	fs, err := sess.Mount(share)
	if err != nil {
		return false
	}
	fs = fs.WithContext(ctx)
	defer fs.Umount()
	_, err = fs.ReadDir(".")
	return err == nil
}

// One probes a single target: connect, authenticate (null session by
// default), list shares, and READ-probe each one.
func One(ctx context.Context, target string, creds auth.Creds, opts auth.Options) Result {
	port := opts.Port
	if port == 0 {
		port = 445
	}
	res := Result{Target: target, Port: port}

	d := net.Dialer{Timeout: opts.Timeout}
	nc, err := d.DialContext(ctx, "tcp", net.JoinHostPort(target, strconv.Itoa(port)))
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer nc.Close()

	init := &smb2.NTLMInitiator{
		User:     creds.User,
		Password: creds.Password,
		Domain:   creds.Domain,
	}
	if creds.Hash != "" {
		h, herr := hex.DecodeString(creds.Hash)
		if herr != nil {
			res.Err = fmt.Sprintf("bad -H hash: %v", herr)
			return res
		}
		init.Hash = h
	}
	if creds.User != "" {
		res.LoginAttempted = creds.User
		if creds.Domain != "" {
			res.LoginAttempted = creds.Domain + "\\" + creds.User
		}
		res.Secret = creds.Password
		if creds.Hash != "" {
			res.Secret = creds.Hash + " (pass-the-hash)"
		}
	}

	dialer := &smb2.Dialer{Initiator: init}
	dctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	sess, err := dialer.DialContext(dctx, nc)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer sess.Logoff()
	res.LoginOK = true

	names, err := sess.ListSharenames()
	if err != nil {
		res.Err = fmt.Sprintf("logged in but couldn't list shares: %v", err)
		return res
	}
	res.Shares = make([]ShareInfo, len(names))
	for i, name := range names {
		res.Shares[i] = ShareInfo{Name: name, Remark: remarkFor(name), Read: canRead(sess, name, opts.Timeout)}
	}
	return res
}

// Run implements the smb command: see internal/protocols/auth for the
// shared global flags (-u/-p/-H/-d/--port/--timeout/-M/-o) every protocol
// command binds the same way. The target can go anywhere on the command
// line, e.g. `srt smb 10.0.0.5 -u alice -p pass` (see auth.Reorder).
func Run(args []string) error {
	fs := flag.NewFlagSet("smb", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "AUTH", Names: []string{"u", "p", "H", "d", "local-auth", "k"}},
			{Title: "CONNECTION", Names: []string{"port", "timeout"}},
			{Title: "MODULES", Names: []string{"M", "o"}},
			{Title: "PERFORMANCE", Names: []string{"c"}},
			{Title: "OUTPUT", Names: []string{"out", "json", "color"}},
		})
	}
	in := fs.String("l", "", "target list: hosts (default: stdin, else the project db's port records -- see -from)")
	fb := store.BindInputFallback(fs, "smb", "port")
	af := auth.Bind(fs, 445)
	conc := fs.Int("c", 10, "concurrent connections")
	out := fs.String("out", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of netexec-style lines")
	colorFlag := fs.String("color", "auto", "color the output: auto|always|never (ignored with -json)")
	if err := fs.Parse(auth.Reorder(fs, args)); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	creds, opts := af.Resolve()

	targets, _, err := auth.ResolveTargets(*in, fs.Args(), fb)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return ioutil.ErrMissing("no targets: pass -l <file>, pipe hosts on stdin, give one as an argument (srt smb <host>), or save some into the project db first (see `srt results`)")
	}
	defer ioutil.StartHeartbeat("smb")()

	results := make([]Result, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *conc))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = One(ctx, target, creds, opts)
		}(i, t)
	}
	wg.Wait()
	for _, r := range results {
		store.CurrentSink().Add(r.Record())
	}

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()

	if *jsonOut {
		for _, r := range results {
			b, _ := json.Marshal(r)
			fmt.Fprintln(w, string(b))
		}
		return nil
	}

	for _, r := range results {
		login := r.LoginAttempted
		if login == "" {
			login = "(null)"
		}
		if r.Err != "" {
			fmt.Fprintln(w, auth.Line(cm, "SMB", r.Target, r.Port, auth.Fail, "ERROR: "+r.Err))
			continue
		}
		if !r.LoginOK {
			fmt.Fprintln(w, auth.Line(cm, "SMB", r.Target, r.Port, auth.Fail, login+" (login failed)"))
			continue
		}
		who := login
		if r.Secret != "" {
			who = login + ":" + r.Secret
		}
		fmt.Fprintln(w, auth.Line(cm, "SMB", r.Target, r.Port, auth.OK, who))
		fmt.Fprintln(w, auth.Line(cm, "SMB", r.Target, r.Port, auth.Info, "Enumerated shares"))
		if len(r.Shares) > 0 {
			printShares(w, r.Shares)
		}
	}
	return nil
}

// printShares renders a netexec-style share table: Share / Permissions /
// Remark, columns sized to the widest cell in this result's own shares.
func printShares(w interface{ Write([]byte) (int, error) }, shares []ShareInfo) {
	nameW, permW := len("Share"), len("Permissions")
	for _, s := range shares {
		if n := len(s.Name); n > nameW {
			nameW = n
		}
	}
	row := func(name, perm, remark string) {
		fmt.Fprintf(w, "%-*s  %-*s  %s\n", nameW, name, permW, perm, remark)
	}
	row("Share", "Permissions", "Remark")
	row(dashes(nameW), dashes(permW), dashes(len("Remark")))
	for _, s := range shares {
		perm := ""
		if s.Read {
			perm = "READ"
		}
		row(s.Name, perm, s.Remark)
	}
}

func dashes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '-'
	}
	return string(b)
}

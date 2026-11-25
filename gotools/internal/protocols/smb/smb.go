// Package smb implements the smb command: Phase 1 of SRT's internal-pentest
// protocol family (see docs/internal-pentest-feasibility). It wraps
// hirochachacha/go-smb2 rather than re-implementing SMB2/3 -- the design
// doc's call to integrate existing Go libraries instead of porting
// impacket's SMB client from scratch.
//
// Default behavior: attempt a null session (empty user/password) or, with
// -u/-p/-H, that credential, then list the target's shares. Phase 2 adds
// authenticated file/share access and the -M module hook already wired in
// internal/protocols/auth.
package smb

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"

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

// Result is one target's SMB probe outcome.
type Result struct {
	Target         string   `json:"target"`
	Port           int      `json:"port"`
	LoginAttempted string   `json:"login_attempted,omitempty"` // "" (null session), or user[@domain]
	LoginOK        bool     `json:"login_ok"`
	Shares         []string `json:"shares,omitempty"`
	Err            string   `json:"error,omitempty"`
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
		d["shares"] = r.Shares
	}
	if r.Err != "" {
		d["error"] = r.Err
	}
	key := fmt.Sprintf("%s:%d", r.Target, r.Port)
	return store.Record{Kind: "smb", Key: key, Host: r.Target, Port: r.Port, Data: d}
}

// One probes a single target: connect, authenticate (null session by
// default), and list shares.
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

	shares, err := sess.ListSharenames()
	if err != nil {
		res.Err = fmt.Sprintf("logged in but couldn't list shares: %v", err)
		return res
	}
	res.Shares = shares
	return res
}

// Run implements the smb command: see internal/protocols/auth for the
// shared global flags (-u/-p/-H/-d/--port/--timeout/-M/-o) every protocol
// command binds the same way.
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
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of a table")
	colorFlag := fs.String("color", "auto", "color the table output: auto|always|never (ignored with -json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	creds, opts := af.Resolve()

	targets, _, err := fb.Resolve(*in, fs.Args())
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return ioutil.ErrMissing("no targets: pass -l <file>, pipe hosts on stdin, or save some into the project db first (see `srt results`)")
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

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tLOGIN\tRESULT\tSHARES/ERROR")
	for _, r := range results {
		target := fmt.Sprintf("%s:%d", r.Target, r.Port)
		login := r.LoginAttempted
		if login == "" {
			login = "null session"
		}
		if r.Err != "" {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", target, login, cm.Wrap(colorout.Red, "ERROR"), r.Err)
			continue
		}
		result, color := "fail", colorout.Red
		if r.LoginOK {
			result, color = "OK", colorout.Green
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", target, login, cm.Wrap(color, result), strings.Join(r.Shares, ","))
	}
	return tw.Flush()
}

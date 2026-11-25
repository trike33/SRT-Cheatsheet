// Package ldap implements the ldap command: Phase 1 of SRT's internal-
// pentest protocol family (see docs/internal-pentest-feasibility). It wraps
// go-ldap/v3 rather than re-implementing the LDAP wire protocol.
//
// Default behavior: attempt an anonymous (unauthenticated) bind, then read
// the rootDSE to report naming contexts and the server's AD/LDAP flavor.
// With -u/-p: simple bind with that credential. With -H (a hash) and -d: an
// NTLM bind using the hash, the LDAP-side pass-the-hash go-ldap exposes
// directly. Phase 2 adds authenticated directory search and the -M module
// hook already wired in internal/protocols/auth.
package ldap

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"sync"
	"text/tabwriter"

	"github.com/go-ldap/ldap/v3"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols/auth"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "ldap",
		Group:   "PROTOCOLS",
		Summary: "LDAP anonymous/credentialed bind + rootDSE enumeration (Phase 1 of the internal-pentest protocol family)",
		Run:     Run,
	})
}

// Result is one target's LDAP probe outcome.
type Result struct {
	Target         string   `json:"target"`
	Port           int      `json:"port"`
	BindAttempted  string   `json:"bind_attempted"` // "anonymous" or user[@domain]
	BindOK         bool     `json:"bind_ok"`
	NamingContexts []string `json:"naming_contexts,omitempty"`
	DefaultContext string   `json:"default_naming_context,omitempty"`
	Err            string   `json:"error,omitempty"`
}

// Record reduces r to the generic shape the results database stores.
func (r Result) Record() store.Record {
	d := map[string]any{"bind_attempted": r.BindAttempted, "bind_ok": r.BindOK}
	if len(r.NamingContexts) > 0 {
		d["naming_contexts"] = r.NamingContexts
	}
	if r.DefaultContext != "" {
		d["default_naming_context"] = r.DefaultContext
	}
	if r.Err != "" {
		d["error"] = r.Err
	}
	key := fmt.Sprintf("%s:%d", r.Target, r.Port)
	return store.Record{Kind: "ldap", Key: key, Host: r.Target, Port: r.Port, Data: d}
}

// One probes a single target: connect, bind (anonymous by default), and read
// the rootDSE.
func One(ctx context.Context, target string, creds auth.Creds, opts auth.Options) Result {
	port := opts.Port
	if port == 0 {
		port = 389
	}
	res := Result{Target: target, Port: port, BindAttempted: "anonymous"}

	l, err := ldap.DialURL(
		fmt.Sprintf("ldap://%s:%d", target, port),
		ldap.DialWithDialer(&net.Dialer{Timeout: opts.Timeout}),
	)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer l.Close()
	l.SetTimeout(opts.Timeout)

	switch {
	case creds.Anonymous():
		err = l.UnauthenticatedBind("")
	case creds.Hash != "":
		res.BindAttempted = bindLabel(creds)
		err = l.NTLMBindWithHash(creds.Domain, creds.User, creds.Hash)
	default:
		res.BindAttempted = bindLabel(creds)
		user := creds.User
		if creds.Domain != "" {
			user = creds.Domain + "\\" + creds.User
		}
		err = l.Bind(user, creds.Password)
	}
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.BindOK = true

	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"namingContexts", "defaultNamingContext", "rootDomainNamingContext"}, nil)
	sr, err := l.Search(req)
	if err != nil {
		res.Err = fmt.Sprintf("bound but couldn't read rootDSE: %v", err)
		return res
	}
	for _, e := range sr.Entries {
		res.NamingContexts = e.GetAttributeValues("namingContexts")
		if dc := e.GetAttributeValue("defaultNamingContext"); dc != "" {
			res.DefaultContext = dc
		} else if dc := e.GetAttributeValue("rootDomainNamingContext"); dc != "" {
			res.DefaultContext = dc
		}
	}
	return res
}

func bindLabel(c auth.Creds) string {
	if c.Domain != "" {
		return c.Domain + "\\" + c.User
	}
	return c.User
}

// Run implements the ldap command: see internal/protocols/auth for the
// shared global flags (-u/-p/-H/-d/--port/--timeout/-M/-o) every protocol
// command binds the same way.
func Run(args []string) error {
	fs := flag.NewFlagSet("ldap", flag.ExitOnError)
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
	fb := store.BindInputFallback(fs, "ldap", "port")
	af := auth.Bind(fs, 389)
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
	defer ioutil.StartHeartbeat("ldap")()

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
	fmt.Fprintln(tw, "TARGET\tBIND\tRESULT\tDEFAULT NAMING CONTEXT/ERROR")
	for _, r := range results {
		target := fmt.Sprintf("%s:%d", r.Target, r.Port)
		if r.Err != "" {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", target, r.BindAttempted, cm.Wrap(colorout.Red, "ERROR"), r.Err)
			continue
		}
		result, color := "fail", colorout.Red
		if r.BindOK {
			result, color = "OK", colorout.Green
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", target, r.BindAttempted, cm.Wrap(color, result), r.DefaultContext)
	}
	return tw.Flush()
}

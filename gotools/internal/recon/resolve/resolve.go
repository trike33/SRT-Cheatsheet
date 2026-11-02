// Package resolve implements the resolve command: concurrent forward
// (A/AAAA) or reverse (PTR) DNS lookups.
package resolve

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "resolve",
		Group:   "HOST recon",
		Summary: "Forward (A/AAAA) or reverse (-reverse, PTR) DNS lookup, concurrent",
		Run:     Run,
	})
}

// Result is one query's outcome; Err is set instead of Results when the
// lookup failed, so -json output always has one line per query. Extra holds
// -type's additional record types (CNAME/MX/NS/TXT), keyed by uppercase
// type name; empty/absent unless -type was given. A type with no records
// (or a failed lookup for it) is simply missing from the map -- DNS doesn't
// distinguish "no records" from most lookup failures at this level, and a
// domain with no MX/TXT/etc. is the common case, not worth warning about.
type Result struct {
	Query   string              `json:"query"`
	Results []string            `json:"results,omitempty"`
	Extra   map[string][]string `json:"extra,omitempty"`
	Err     string              `json:"error,omitempty"`
}

// extraRecordTypes are the record types -type can request in addition to
// the normal forward (A/AAAA) or reverse (PTR, via -reverse) lookup.
// Deliberately not including SOA: Go's net package has no LookupSOA (no
// public primitive for it at all), and pulling in a DNS library just for
// one record type isn't a good trade for this command, which is native by
// policy -- see methodology.md's External-tool policy and ROADMAP.md.
var extraRecordTypes = []string{"cname", "mx", "ns", "txt"}

func isExtraRecordType(t string) bool {
	for _, x := range extraRecordTypes {
		if x == t {
			return true
		}
	}
	return false
}

// lookupExtra resolves one of extraRecordTypes for q, formatted the way
// resolve prints every other record: trailing dots trimmed, an MX entry as
// "<preference> <host>". A failed/empty lookup returns (nil, nil) -- see
// Result.Extra's doc comment on why that's not surfaced as an error.
func lookupExtra(ctx context.Context, resolver *net.Resolver, recordType, q string) []string {
	switch recordType {
	case "cname":
		if v, err := resolver.LookupCNAME(ctx, q); err == nil && v != "" {
			return []string{strings.TrimSuffix(v, ".")}
		}
	case "mx":
		if vs, err := resolver.LookupMX(ctx, q); err == nil {
			out := make([]string, len(vs))
			for i, m := range vs {
				out[i] = fmt.Sprintf("%d %s", m.Pref, strings.TrimSuffix(m.Host, "."))
			}
			return out
		}
	case "ns":
		if vs, err := resolver.LookupNS(ctx, q); err == nil {
			out := make([]string, len(vs))
			for i, n := range vs {
				out[i] = strings.TrimSuffix(n.Host, ".")
			}
			return out
		}
	case "txt":
		if vs, err := resolver.LookupTXT(ctx, q); err == nil {
			return vs
		}
	}
	return nil
}

func Run(args []string) error {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where", "reverse", "type"}},
			{Title: "PERFORMANCE", Names: []string{"c", "timeout"}},
			{Title: "OUTPUT", Names: []string{"o", "json"}},
		})
	}
	in := fs.String("l", "", "input file: hostnames, or IPs with -reverse (default: stdin, else the project db -- see -from)")
	fb := store.BindInputFallback(fs, "resolve", "domain", "subdomain")
	reverse := fs.Bool("reverse", false, "treat input as IPs and do a reverse (PTR) lookup instead of forward A/AAAA")
	typeFlag := fs.String("type", "", "forward lookups only: also collect these record types per query, comma list of cname,mx,ns,txt (not SOA -- no stdlib primitive for it)")
	conc := fs.Int("c", 40, "concurrent DNS lookups")
	timeout := fs.Duration("timeout", 5*time.Second, "per-lookup timeout")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines (one per query, including failures) instead of \"query -> result1,result2\"")
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer ioutil.StartHeartbeat("resolve")()
	if *reverse {
		fb.SetDefaultKinds("ip")
	}

	var extraTypes []string
	if *typeFlag != "" {
		if *reverse {
			return fmt.Errorf("-type only applies to forward lookups; remove -reverse or -type")
		}
		for _, t := range strings.Split(*typeFlag, ",") {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" {
				continue
			}
			if !isExtraRecordType(t) {
				return fmt.Errorf("-type: unknown record type %q (want cname, mx, ns, and/or txt)", t)
			}
			extraTypes = append(extraTypes, t)
		}
	}

	queries, _, err := fb.Resolve(*in, fs.Args())
	if err != nil {
		return err
	}
	if len(queries) == 0 {
		return ioutil.ErrMissing("no input: pass -l <file>, pipe hosts/IPs on stdin, or save some into the project db first (see `srt results`)")
	}

	resolver := newResolver()
	results := make([]Result, len(queries))

	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *conc))
	for i, q := range queries {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, q string) {
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := ioutil.ContextTimeout(*timeout)
			defer cancel()

			r := Result{Query: q}
			if *reverse {
				netx.Request()
				names, lookupErr := resolver.LookupAddr(ctx, q)
				if lookupErr != nil {
					r.Err = lookupErr.Error()
				} else {
					r.Results = trimTrailingDots(names)
				}
			} else {
				netx.Request()
				addrs, lookupErr := resolver.LookupHost(ctx, q)
				if lookupErr != nil {
					r.Err = lookupErr.Error()
				} else {
					r.Results = addrs
				}
				for _, t := range extraTypes {
					netx.Request()
					if vs := lookupExtra(ctx, resolver, t, q); len(vs) > 0 {
						if r.Extra == nil {
							r.Extra = map[string][]string{}
						}
						r.Extra[strings.ToUpper(t)] = vs
					}
				}
			}
			results[i] = r
		}(i, q)
	}
	wg.Wait()

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()

	var resolved int
	for _, r := range results {
		if len(r.Results) > 0 {
			resolved++
		}
		if *jsonOut {
			b, _ := json.Marshal(r)
			fmt.Fprintln(w, string(b))
			continue
		}
		switch {
		case len(r.Results) > 0:
			fmt.Fprintf(w, "%s -> %s\n", r.Query, strings.Join(r.Results, ","))
		case r.Err != "":
			ioutil.Warn("%s: %s", r.Query, r.Err)
		}
		for _, t := range extraRecordTypes { // stable order regardless of map iteration
			if vs := r.Extra[strings.ToUpper(t)]; len(vs) > 0 {
				fmt.Fprintf(w, "%s %s -> %s\n", r.Query, strings.ToUpper(t), strings.Join(vs, ","))
			}
		}
	}
	ioutil.Warn("%d/%d resolved", resolved, len(queries))
	return nil
}

// trimTrailingDots strips the trailing "." LookupAddr's PTR names carry.
// newResolver is a var (not a plain &net.Resolver{} literal inline) so
// tests can override it to point at a fake DNS server instead of the real
// system resolver.
var newResolver = func() *net.Resolver { return &net.Resolver{} }

func trimTrailingDots(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.TrimSuffix(n, ".")
	}
	return out
}

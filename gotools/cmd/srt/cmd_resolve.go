package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func init() {
	register(&command{
		name:    "resolve",
		group:   "HOST recon",
		summary: "Forward (A/AAAA) or reverse (-reverse, PTR) DNS lookup, concurrent",
		run:     runResolve,
	})
}

// resolveResult is one query's outcome; Err is set instead of Results when
// the lookup failed, so -json output always has one line per query.
type resolveResult struct {
	Query   string   `json:"query"`
	Results []string `json:"results,omitempty"`
	Err     string   `json:"error,omitempty"`
}

func runResolve(args []string) error {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	in := fs.String("l", "", "input file: hostnames, or IPs with -reverse (default: stdin)")
	reverse := fs.Bool("reverse", false, "treat input as IPs and do a reverse (PTR) lookup instead of forward A/AAAA")
	conc := fs.Int("c", 40, "concurrent DNS lookups")
	timeout := fs.Duration("timeout", 5*time.Second, "per-lookup timeout")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines (one per query, including failures) instead of \"query -> result1,result2\"")
	if err := fs.Parse(args); err != nil {
		return err
	}

	queries, err := inputLines(resolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}
	if len(queries) == 0 {
		return errMissing("no input: pass -l <file> or pipe hosts/IPs on stdin")
	}

	resolver := &net.Resolver{}
	results := make([]resolveResult, len(queries))

	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *conc))
	for i, q := range queries {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, q string) {
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := contextTimeout(*timeout)
			defer cancel()

			r := resolveResult{Query: q}
			if *reverse {
				names, lookupErr := resolver.LookupAddr(ctx, q)
				if lookupErr != nil {
					r.Err = lookupErr.Error()
				} else {
					r.Results = trimTrailingDots(names)
				}
			} else {
				addrs, lookupErr := resolver.LookupHost(ctx, q)
				if lookupErr != nil {
					r.Err = lookupErr.Error()
				} else {
					r.Results = addrs
				}
			}
			results[i] = r
		}(i, q)
	}
	wg.Wait()

	w, err := output(*out)
	if err != nil {
		return err
	}
	defer w.Close()

	var resolved int
	for _, r := range results {
		if len(r.Results) > 0 {
			resolved++
		}
		switch {
		case *jsonOut:
			b, _ := json.Marshal(r)
			fmt.Fprintln(w, string(b))
		case len(r.Results) > 0:
			fmt.Fprintf(w, "%s -> %s\n", r.Query, strings.Join(r.Results, ","))
		default:
			warn("%s: %s", r.Query, r.Err)
		}
	}
	warn("%d/%d resolved", resolved, len(queries))
	return nil
}

// trimTrailingDots strips the trailing "." LookupAddr's PTR names carry.
func trimTrailingDots(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.TrimSuffix(n, ".")
	}
	return out
}

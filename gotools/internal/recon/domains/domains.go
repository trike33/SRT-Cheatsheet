// Package domains implements the domains and scopecheck commands: pulling
// unique domains out of arbitrary text, and keeping only the hosts that
// resolve into a plain IP/CIDR scope.
package domains

import (
	"flag"
	"net"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/scope"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "domains",
		Group:   "HOST recon",
		Summary: "Extract unique domains from httpx output / any text (domain-extracter.py)",
		Run:     Run,
	})
	cli.Register(&cli.Command{
		Name:    "scopecheck",
		Group:   "HOST recon",
		Summary: "Keep only hosts whose resolved IP falls inside a scope file (domain_enum.py)",
		Run:     RunScopeCheck,
	})
}

// domainRe mirrors the regex in domain-extracter.py: grab the host of any
// http(s) URL while ignoring bare IPs (requires a trailing alpha TLD).
var domainRe = regexp.MustCompile(`https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)

func Run(args []string) error {
	fs := flag.NewFlagSet("domains", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l"}},
			{Title: "OUTPUT", Names: []string{"o"}},
		})
	}
	in := fs.String("l", "", "input file (default: stdin)")
	out := fs.String("o", "", "output file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer ioutil.StartHeartbeat("domains")()

	content, err := ioutil.ReadAll(ioutil.ResolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}

	seen := map[string]struct{}{}
	for _, m := range domainRe.FindAllStringSubmatch(content, -1) {
		seen[m[1]] = struct{}{}
	}

	ds := make([]string, 0, len(seen))
	for d := range seen {
		ds = append(ds, d)
	}
	sort.Strings(ds)

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	return ioutil.WriteLines(w, ds)
}

// RunScopeCheck ports HOST/domain_enum.py but swaps the O(N) membership list
// for IPNet.Contains and resolves hostnames concurrently -- the slow part on
// large subdomain lists.
func RunScopeCheck(args []string) error {
	fs := flag.NewFlagSet("scopecheck", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "scope"}},
			{Title: "PERFORMANCE", Names: []string{"c", "timeout"}},
			{Title: "OUTPUT", Names: []string{"o"}},
		})
	}
	in := fs.String("l", "", "hosts/subdomains file (default: stdin)")
	scopeFile := fs.String("scope", "", "scope file of IPs/CIDRs (required)")
	out := fs.String("o", "", "output file (default: stdout)")
	conc := fs.Int("c", 40, "concurrent DNS resolutions")
	timeout := fs.Duration("timeout", 5*time.Second, "per-host DNS timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scopeFile == "" {
		return ioutil.ErrMissing("-scope is required (the scope file of IPs/CIDRs)")
	}
	defer ioutil.StartHeartbeat("scopecheck")()

	sc, err := scope.Load(*scopeFile)
	if err != nil {
		return err
	}

	hosts, err := ioutil.InputLines(ioutil.ResolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}

	resolver := &net.Resolver{}
	inScope := make([]bool, len(hosts))

	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *conc))
	for i, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, host string) {
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := ioutil.ContextTimeout(*timeout)
			defer cancel()
			netx.Request()
			addrs, err := resolver.LookupHost(ctx, host)
			if err != nil {
				return
			}
			for _, a := range addrs {
				ip := net.ParseIP(a)
				if ip != nil && sc.Contains(ip) {
					inScope[i] = true
					return
				}
			}
		}(i, h)
	}
	wg.Wait()

	var result []string
	for i, h := range hosts {
		if inScope[i] {
			result = append(result, h)
		}
	}

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	if err := ioutil.WriteLines(w, result); err != nil {
		return err
	}
	ioutil.Warn("%d/%d host(s) resolved into scope", len(result), len(hosts))
	return nil
}

package main

import (
	"flag"
	"net"
	"regexp"
	"sort"
	"sync"
	"time"
)

func init() {
	register(&command{
		name:    "domains",
		group:   "HOST recon",
		summary: "Extract unique domains from httpx output / any text (domain-extracter.py)",
		run:     runDomains,
	})
	register(&command{
		name:    "scopecheck",
		group:   "HOST recon",
		summary: "Keep only hosts whose resolved IP falls inside a scope file (domain_enum.py)",
		run:     runScopeCheck,
	})
}

// domainRe mirrors the regex in domain-extracter.py: grab the host of any
// http(s) URL while ignoring bare IPs (requires a trailing alpha TLD).
var domainRe = regexp.MustCompile(`https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)

func runDomains(args []string) error {
	fs := flag.NewFlagSet("domains", flag.ExitOnError)
	in := fs.String("l", "", "input file (default: stdin)")
	out := fs.String("o", "", "output file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer startHeartbeat("domains")()

	content, err := readAll(resolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}

	seen := map[string]struct{}{}
	for _, m := range domainRe.FindAllStringSubmatch(content, -1) {
		seen[m[1]] = struct{}{}
	}

	domains := make([]string, 0, len(seen))
	for d := range seen {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	w, err := output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	return writeLines(w, domains)
}

// runScopeCheck ports HOST/domain_enum.py but swaps the O(N) membership list for
// IPNet.Contains and resolves hostnames concurrently — the slow part on large
// subdomain lists.
func runScopeCheck(args []string) error {
	fs := flag.NewFlagSet("scopecheck", flag.ExitOnError)
	in := fs.String("l", "", "hosts/subdomains file (default: stdin)")
	scopeFile := fs.String("scope", "", "scope file of IPs/CIDRs (required)")
	out := fs.String("o", "", "output file (default: stdout)")
	conc := fs.Int("c", 40, "concurrent DNS resolutions")
	timeout := fs.Duration("timeout", 5*time.Second, "per-host DNS timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scopeFile == "" {
		return errMissing("-scope is required (the scope file of IPs/CIDRs)")
	}
	defer startHeartbeat("scopecheck")()

	scope, err := loadScope(*scopeFile)
	if err != nil {
		return err
	}

	hosts, err := inputLines(resolveInput(*in, fs.Args()))
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

			ctx, cancel := contextTimeout(*timeout)
			defer cancel()
			meter.request()
			addrs, err := resolver.LookupHost(ctx, host)
			if err != nil {
				return
			}
			for _, a := range addrs {
				ip := net.ParseIP(a)
				if ip != nil && scope.contains(ip) {
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

	w, err := output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	if err := writeLines(w, result); err != nil {
		return err
	}
	warn("%d/%d host(s) resolved into scope", len(result), len(hosts))
	return nil
}

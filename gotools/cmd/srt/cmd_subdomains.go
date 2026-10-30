package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

func init() {
	register(&command{
		name:    "subdomains",
		group:   "WEB recon",
		summary: "Find subdomains: passive (crt.sh certificate transparency) + optional active DNS brute force",
		run:     runSubdomains,
	})
}

func runSubdomains(args []string) error {
	fs := flag.NewFlagSet("subdomains", flag.ExitOnError)
	domain := fs.String("d", "", "single target domain")
	list := fs.String("l", "", "file of target domains (or stdin)")
	wordlist := fs.String("w", "", "wordlist for active DNS brute force (e.g. www, api, mail, ...); omit to skip active enum")
	passive := fs.Bool("passive", true, "passive enumeration via crt.sh certificate transparency logs")
	active := fs.Bool("active", true, "active DNS brute force (needs -w)")
	conc := fs.Int("c", 100, "concurrent DNS resolutions for active brute force")
	httpTimeout := fs.Duration("timeout", 30*time.Second, "HTTP timeout for crt.sh")
	resolveTimeout := fs.Duration("resolve-timeout", 5*time.Second, "per-lookup DNS timeout for active brute force")
	out := fs.String("o", "", "output file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer startHeartbeat("subdomains")()

	// Gather target domains from -d, -l, positional, or stdin (same pattern as gau).
	var domains []string
	if *domain != "" {
		domains = append(domains, *domain)
	}
	if *domain == "" || *list != "" || fs.NArg() > 0 {
		if lines, err := inputLines(resolveInput(*list, fs.Args())); err == nil {
			domains = append(domains, lines...)
		} else if *domain == "" {
			return err
		}
	}
	domains = dedupStrings(domains)
	if len(domains) == 0 {
		return errMissing("provide -d <domain>, -l <file>, or pipe domains on stdin")
	}

	seen := map[string]struct{}{}
	var found []string
	addFound := func(s string) {
		s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
		s = strings.TrimPrefix(s, "*.")
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		found = append(found, s)
	}

	if *passive {
		for _, d := range domains {
			subs, err := passiveSubdomains(*httpTimeout, d)
			if err != nil {
				warn("passive enum for %s: %v", d, err)
				continue
			}
			for _, s := range subs {
				addFound(s)
			}
		}
	}

	switch {
	case *active && *wordlist != "":
		words, err := inputLines(*wordlist)
		if err != nil {
			return err
		}
		var candidates []string
		for _, d := range domains {
			for _, w := range words {
				w = strings.TrimSpace(w)
				if w == "" {
					continue
				}
				candidates = append(candidates, w+"."+d)
			}
		}
		live := activeBruteForce(candidates, *resolveTimeout, *conc)
		for _, s := range live {
			addFound(s)
		}
	case *active:
		warn("active brute force requested but no -w wordlist given, skipping")
	}

	sort.Strings(found)
	w, err := output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	if err := writeLines(w, found); err != nil {
		return err
	}
	warn("found %d subdomain(s) across %d domain(s)", len(found), len(domains))
	return nil
}

// crtshEntry is the slice of crt.sh's JSON response we care about.
type crtshEntry struct {
	NameValue string `json:"name_value"`
}

// passiveSubdomains queries crt.sh's certificate-transparency-log API for
// every hostname seen on a cert covering domain (including subdomains).
func passiveSubdomains(timeout time.Duration, domain string) ([]string, error) {
	api := "https://crt.sh/?q=%25." + url.QueryEscape(domain) + "&output=json"
	return passiveSubdomainsFrom(api, timeout)
}

// passiveSubdomainsFrom does the actual fetch + parse against an API URL,
// split out from passiveSubdomains so tests can point it at a local fixture
// server instead of the real crt.sh.
func passiveSubdomainsFrom(api string, timeout time.Duration) ([]string, error) {
	client := newHTTPClient(timeout, true)
	resp, err := httpGet(client, api)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, nil // no certs on record for this domain
	}
	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("decoding crt.sh response: %w", err)
	}

	seen := map[string]struct{}{}
	var names []string
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			line = strings.ToLower(strings.TrimSpace(line))
			if line == "" {
				continue
			}
			if _, dup := seen[line]; dup {
				continue
			}
			seen[line] = struct{}{}
			names = append(names, line)
		}
	}
	return names, nil
}

// activeBruteForce resolves every candidate concurrently and returns the
// ones that answer (DNS existence only — not liveness over HTTP).
func activeBruteForce(candidates []string, timeout time.Duration, conc int) []string {
	resolver := &net.Resolver{}
	live := make([]bool, len(candidates))

	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, conc))
	for i, host := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, host string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := contextTimeout(timeout)
			defer cancel()
			if _, err := resolver.LookupHost(ctx, host); err == nil {
				live[i] = true
			}
		}(i, host)
	}
	wg.Wait()

	var out []string
	for i, ok := range live {
		if ok {
			out = append(out, candidates[i])
		}
	}
	return out
}

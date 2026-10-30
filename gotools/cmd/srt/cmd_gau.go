package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"
)

func init() {
	register(&command{
		name:    "gau",
		group:   "WEB recon",
		summary: "Collect archived URLs from the Wayback Machine CDX API (gau_recon.py)",
		run:     runGau,
	})
	register(&command{
		name:    "sensitive",
		group:   "WEB recon",
		summary: "Filter a URL list to ones with sensitive file extensions (gau_recon.py)",
		run:     runSensitive,
	})
	register(&command{
		name:    "params",
		group:   "WEB recon",
		summary: "Classify URLs by likely vuln class from their parameters (gau_recon.py)",
		run:     runParams,
	})
}

// collectWayback queries the Wayback CDX API for every archived URL of host.
// withSubs broadens the query to *.host. HTTPS is used so it rides the proxy.
func collectWayback(timeout time.Duration, host string, withSubs bool) ([]string, error) {
	pattern := host + "/*"
	if withSubs {
		pattern = "*." + host + "/*"
	}
	q := url.Values{}
	q.Set("url", pattern)
	q.Set("output", "json")
	q.Set("fl", "original")
	q.Set("collapse", "urlkey")
	api := "https://web.archive.org/cdx/search/cdx?" + q.Encode()

	client := newHTTPClient(timeout, true)
	resp, err := httpGet(client, api)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// CDX JSON is an array of arrays; row 0 is the header.
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("decoding CDX response: %w", err)
	}
	var urls []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue
		}
		urls = append(urls, row[0])
	}
	return urls, nil
}

func runGau(args []string) error {
	fs := flag.NewFlagSet("gau", flag.ExitOnError)
	domain := fs.String("d", "", "single target domain")
	list := fs.String("l", "", "file of target domains (or stdin)")
	subs := fs.Bool("sub", false, "include subdomains (*.domain)")
	out := fs.String("o", "", "write collected URLs to this file")
	verbose := fs.Bool("v", false, "also print URLs to stdout when -o is set")
	checkExt := fs.Bool("ce", false, "report URLs with sensitive extensions")
	checkParams := fs.Bool("cp", false, "report URLs grouped by vuln param class")
	timeout := fs.Duration("timeout", 90*time.Second, "per-host HTTP timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Gather target hosts from -d, -l, positional, or stdin.
	var hosts []string
	if *domain != "" {
		hosts = append(hosts, *domain)
	}
	if *domain == "" || *list != "" || fs.NArg() > 0 {
		if *list != "" || fs.NArg() > 0 || *domain == "" {
			if lines, err := inputLines(resolveInput(*list, fs.Args())); err == nil {
				hosts = append(hosts, lines...)
			} else if *domain == "" {
				return err
			}
		}
	}
	hosts = dedupStrings(hosts)
	if len(hosts) == 0 {
		return errMissing("provide -d <domain>, -l <file>, or pipe domains on stdin")
	}

	seen := map[string]struct{}{}
	var all []string
	for _, h := range hosts {
		warn("collecting URLs for %s ...", h)
		urls, err := collectWayback(*timeout, h, *subs)
		if err != nil {
			warn("  %s: %v", h, err)
			continue
		}
		warn("  got %d URL(s)", len(urls))
		for _, u := range urls {
			if _, dup := seen[u]; dup {
				continue
			}
			seen[u] = struct{}{}
			all = append(all, u)
		}
	}

	if *out != "" {
		w, err := output(*out)
		if err != nil {
			return err
		}
		if err := writeLines(w, all); err != nil {
			w.Close()
			return err
		}
		w.Close()
		warn("saved %d URL(s) to %s", len(all), *out)
	}

	// Print the raw list when there is no file target, or on explicit -v.
	if *out == "" && !*checkExt && !*checkParams {
		writeLines(stdout(), all)
	} else if *verbose {
		writeLines(stdout(), all)
	}

	if *checkExt {
		fmt.Println("\n=== Sensitive extensions ===")
		writeLines(stdout(), filterSensitive(all))
	}
	if *checkParams {
		printParamGroups(classifyParams(all))
	}
	return nil
}

func runSensitive(args []string) error {
	fs := flag.NewFlagSet("sensitive", flag.ExitOnError)
	in := fs.String("l", "", "URL list file (default: stdin)")
	out := fs.String("o", "", "output file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	urls, err := inputLines(resolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}
	w, err := output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	return writeLines(w, filterSensitive(urls))
}

func runParams(args []string) error {
	fs := flag.NewFlagSet("params", flag.ExitOnError)
	in := fs.String("l", "", "URL list file (default: stdin)")
	only := fs.String("class", "", "only show one class (e.g. ssrf, sqli, xss, lfi, rce, open-redirect)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	urls, err := inputLines(resolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}
	groups := classifyParams(urls)
	if *only != "" {
		writeLines(stdout(), sortedSet(groups[*only]))
		return nil
	}
	printParamGroups(groups)
	return nil
}

// filterSensitive returns URLs whose path ends with a sensitive extension.
func filterSensitive(urls []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, u := range urls {
		p := u
		if parsed, err := url.Parse(u); err == nil && parsed.Path != "" {
			p = parsed.Path
		}
		low := strings.ToLower(p)
		for _, ext := range sensitiveExtensions {
			if strings.HasSuffix(low, ext) {
				if _, dup := seen[u]; !dup {
					seen[u] = struct{}{}
					out = append(out, u)
				}
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// classifyParams buckets URLs by vuln class based on parameter markers.
func classifyParams(urls []string) map[string]map[string]struct{} {
	groups := map[string]map[string]struct{}{}
	for _, cat := range paramCategories {
		groups[cat.name] = map[string]struct{}{}
	}
	for _, u := range urls {
		for _, cat := range paramCategories {
			for _, marker := range cat.markers {
				if strings.Contains(u, marker) {
					groups[cat.name][u] = struct{}{}
					break
				}
			}
		}
	}
	return groups
}

func printParamGroups(groups map[string]map[string]struct{}) {
	for _, cat := range paramCategories {
		hits := sortedSet(groups[cat.name])
		fmt.Printf("\n=== %s (%d) ===\n", cat.name, len(hits))
		writeLines(stdout(), hits)
	}
}

func sortedSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func dedupStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

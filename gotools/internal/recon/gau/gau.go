// Package gau implements the gau, sensitive and params commands: collecting
// archived URLs from the Wayback Machine, then classifying them by
// sensitive file extension or by vulnerability-class parameter markers.
package gau

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/payloads"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "gau",
		Group:   "WEB recon",
		Summary: "Collect archived URLs from the Wayback Machine CDX API (gau_recon.py)",
		Run:     Run,
	})
	cli.Register(&cli.Command{
		Name:    "sensitive",
		Group:   "WEB recon",
		Summary: "Filter a URL list to ones with sensitive file extensions (gau_recon.py)",
		Run:     RunSensitive,
	})
	cli.Register(&cli.Command{
		Name:    "params",
		Group:   "WEB recon",
		Summary: "Classify URLs by likely vuln class from their parameters (gau_recon.py)",
		Run:     RunParams,
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

	client := netx.NewClient(timeout, true)
	resp, err := netx.Get(client, api)
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

func Run(args []string) error {
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
	defer ioutil.StartHeartbeat("gau")()

	// Gather target hosts from -d, -l, positional, or stdin.
	var hosts []string
	if *domain != "" {
		hosts = append(hosts, *domain)
	}
	if *domain == "" || *list != "" || fs.NArg() > 0 {
		if *list != "" || fs.NArg() > 0 || *domain == "" {
			if lines, err := ioutil.InputLines(ioutil.ResolveInput(*list, fs.Args())); err == nil {
				hosts = append(hosts, lines...)
			} else if *domain == "" {
				return err
			}
		}
	}
	hosts = ioutil.DedupStrings(hosts)
	if len(hosts) == 0 {
		return ioutil.ErrMissing("provide -d <domain>, -l <file>, or pipe domains on stdin")
	}

	seen := map[string]struct{}{}
	var all []string
	for _, h := range hosts {
		ioutil.Warn("collecting URLs for %s ...", h)
		urls, err := collectWayback(*timeout, h, *subs)
		if err != nil {
			ioutil.Warn("  %s: %v", h, err)
			continue
		}
		ioutil.Warn("  got %d URL(s)", len(urls))
		for _, u := range urls {
			if _, dup := seen[u]; dup {
				continue
			}
			seen[u] = struct{}{}
			all = append(all, u)
		}
	}

	if *out != "" {
		w, err := ioutil.Output(*out)
		if err != nil {
			return err
		}
		if err := ioutil.WriteLines(w, all); err != nil {
			w.Close()
			return err
		}
		w.Close()
		ioutil.Warn("saved %d URL(s) to %s", len(all), *out)
	}

	// Print the raw list when there is no file target, or on explicit -v.
	if *out == "" && !*checkExt && !*checkParams {
		ioutil.WriteLines(ioutil.Stdout(), all)
	} else if *verbose {
		ioutil.WriteLines(ioutil.Stdout(), all)
	}

	if *checkExt {
		fmt.Println("\n=== Sensitive extensions ===")
		ioutil.WriteLines(ioutil.Stdout(), filterSensitive(all))
	}
	if *checkParams {
		printParamGroups(classifyParams(all))
	}
	return nil
}

func RunSensitive(args []string) error {
	fs := flag.NewFlagSet("sensitive", flag.ExitOnError)
	in := fs.String("l", "", "URL list file (default: stdin)")
	out := fs.String("o", "", "output file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer ioutil.StartHeartbeat("sensitive")()
	urls, err := ioutil.InputLines(ioutil.ResolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}
	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	return ioutil.WriteLines(w, filterSensitive(urls))
}

func RunParams(args []string) error {
	fs := flag.NewFlagSet("params", flag.ExitOnError)
	in := fs.String("l", "", "URL list file (default: stdin)")
	only := fs.String("class", "", "only show one class (e.g. ssrf, sqli, xss, lfi, rce, open-redirect)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer ioutil.StartHeartbeat("params")()
	urls, err := ioutil.InputLines(ioutil.ResolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}
	groups := classifyParams(urls)
	if *only != "" {
		ioutil.WriteLines(ioutil.Stdout(), sortedSet(groups[*only]))
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
		for _, ext := range payloads.SensitiveExtensions {
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
	for _, cat := range payloads.Categories {
		groups[cat.Name] = map[string]struct{}{}
	}
	for _, u := range urls {
		for _, cat := range payloads.Categories {
			for _, marker := range cat.Markers {
				if strings.Contains(u, marker) {
					groups[cat.Name][u] = struct{}{}
					break
				}
			}
		}
	}
	return groups
}

func printParamGroups(groups map[string]map[string]struct{}) {
	for _, cat := range payloads.Categories {
		hits := sortedSet(groups[cat.Name])
		fmt.Printf("\n=== %s (%d) ===\n", cat.Name, len(hits))
		ioutil.WriteLines(ioutil.Stdout(), hits)
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

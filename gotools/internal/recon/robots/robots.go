// Package robots implements the robots command: fetching robots.txt and
// probing each Allow/Disallow path it lists, plus the same-host URLs of the
// sitemap(s) it declares (or the conventional /sitemap.xml).
package robots

import (
	"bufio"
	"compress/gzip"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "robots",
		Group:   "WEB recon",
		Summary: "Fetch robots.txt and sitemap(s), probe each Allow/Disallow path and sitemap URL",
		Run:     Run,
	})
}

func Run(args []string) error {
	fs := flag.NewFlagSet("robots", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "SITEMAP", Names: []string{"no-sitemap", "sitemap-max"}},
			{Title: "PERFORMANCE", Names: []string{"timeout", "insecure", "c", "hc"}},
			{Title: "OUTPUT", Names: []string{"color"}},
		})
	}
	in := fs.String("l", "", "file of base URLs (optional; args/stdin also accepted, else the project db's url/probe/gau/robots records -- see -from)")
	fb := store.BindInputFallback(fs, "robots", "url", "probe", "gau", "robots")
	colorFlag := fs.String("color", "auto", "color output: auto|always|never")
	timeout := fs.Duration("timeout", 15*time.Second, "per-request timeout")
	insecure := fs.Bool("insecure", true, "skip TLS verification")
	conc := fs.Int("c", 20, "concurrent path probes per host")
	hostConc := fs.Int("hc", 32, "base URLs whose robots.txt is fetched concurrently")
	noSitemap := fs.Bool("no-sitemap", false, "don't fetch/probe sitemaps")
	sitemapMax := fs.Int("sitemap-max", 100, "max sitemap URLs probed per base URL (0 = list none)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	defer ioutil.StartHeartbeat("robots")()

	// Base URLs may come from args, -l, and/or stdin.
	var bases []string
	bases = append(bases, fs.Args()...)
	if *in != "" {
		lines, err := ioutil.InputLines(*in)
		if err != nil {
			return err
		}
		bases = append(bases, lines...)
	}
	if len(bases) == 0 {
		lines, _, err := fb.Resolve("", nil)
		if err != nil {
			return err
		}
		bases = append(bases, lines...)
	}
	if len(bases) == 0 {
		return ioutil.ErrMissing("provide a base URL as an argument, via -l, on stdin, or save some into the project db first (see `srt results`)")
	}

	client := netx.NewClient(*timeout, *insecure)

	// Fetch every robots.txt up front, concurrently: with hundreds of
	// bases, most of them dead or non-HTTP ports that sit out the full
	// timeout, doing this one base at a time is what made big runs crawl.
	type fetched struct {
		allow, disallow []string
		sitemap         []string
		err             error
	}
	fetchedAll := make([]fetched, len(bases))
	var wg sync.WaitGroup
	var doneFetch atomic.Int64
	sem := make(chan struct{}, max(1, *hostConc))
	start := time.Now()
	for i, base := range bases {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, base string) {
			defer wg.Done()
			defer func() { <-sem }()
			a, d, declared, err := parseRobots(client, base)
			var sm []string
			if err == nil && !*noSitemap {
				sm = fetchSitemapURLs(client, base, declared, *sitemapMax)
			}
			fetchedAll[i] = fetched{a, d, sm, err}
			if n := doneFetch.Add(1); len(bases) > 1 {
				ioutil.Progress("robots: fetched %d/%d · %s", n, len(bases), ioutil.ElapsedETA(n, int64(len(bases)), time.Since(start)))
			}
		}(i, base)
	}
	wg.Wait()
	if len(bases) > 1 {
		colorout.ClearLine(os.Stderr)
	}

	unreachable := 0
	defer func() {
		ioutil.Warn("checked %d site(s), %d without a robots.txt", len(bases), unreachable)
	}()
	for i, base := range bases {
		f := fetchedAll[i]
		if f.err != nil {
			ioutil.Warn("%s: %v", base, f.err)
			unreachable++
			continue
		}
		fmt.Println(cm.Wrap(colorout.Cyan, "--- "+base+" ---"))
		fmt.Println(cm.Wrap(colorout.Cyan, "[Allow]"))
		probePaths(client, base, filterWildcards(f.allow), cm, *conc)
		fmt.Println(cm.Wrap(colorout.Cyan, "[Disallow]"))
		probePaths(client, base, filterWildcards(f.disallow), cm, *conc)
		if !*noSitemap {
			fmt.Println(cm.Wrap(colorout.Cyan, "[Sitemap]"))
			probePaths(client, base, f.sitemap, cm, *conc)
		}
	}
	return nil
}

// parseRobots fetches /robots.txt and returns its Allow and Disallow paths
// and any Sitemap: URLs it declares.
func parseRobots(client *http.Client, base string) (allow, disallow, sitemaps []string, err error) {
	robotsURL, err := joinURL(base, "/robots.txt")
	if err != nil {
		return nil, nil, nil, err
	}
	resp, err := netx.Get(client, robotsURL)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case len(line) > len("Sitemap:") && strings.EqualFold(line[:len("Sitemap:")], "Sitemap:"):
			sitemaps = append(sitemaps, strings.TrimSpace(line[len("Sitemap:"):]))
		case strings.HasPrefix(line, "Disallow:"):
			disallow = append(disallow, strings.TrimSpace(line[len("Disallow:"):]))
		case strings.HasPrefix(line, "Allow:"):
			allow = append(allow, strings.TrimSpace(line[len("Allow:"):]))
		}
	}
	return allow, disallow, sitemaps, nil
}

const (
	maxSitemapFiles = 25       // sitemap files fetched per base (index recursion included)
	maxSitemapDepth = 2        // sitemap index -> sitemap -> (no deeper)
	maxSitemapBytes = 10 << 20 // per file, after decompression
)

// sitemapDoc covers both <urlset> and <sitemapindex> documents.
type sitemapDoc struct {
	URLs []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

// fetchSitemapURLs collects page URLs from the sitemaps robots.txt declared
// (or /sitemap.xml when it declared none), following sitemap indexes a
// couple of levels deep. Only URLs on base's own host are kept -- a sitemap
// can list anything, and this must not probe hosts outside the target.
// Returns at most max URLs, deduplicated, in discovery order.
func fetchSitemapURLs(client *http.Client, base string, declared []string, max int) []string {
	if max <= 0 {
		return nil
	}
	b, err := url.Parse(base)
	if err != nil {
		return nil
	}
	queue := declared
	if len(queue) == 0 {
		queue = []string{"/sitemap.xml"}
	}
	type item struct {
		u     string
		depth int
	}
	var work []item
	for _, q := range queue {
		if abs, err := joinURL(base, q); err == nil {
			work = append(work, item{abs, 0})
		}
	}
	seenMaps := map[string]bool{}
	seenURLs := map[string]bool{}
	var out []string
	for fetched := 0; len(work) > 0 && fetched < maxSitemapFiles && len(out) < max; {
		it := work[0]
		work = work[1:]
		if seenMaps[it.u] {
			continue
		}
		seenMaps[it.u] = true
		fetched++
		doc, ok := getSitemap(client, it.u)
		if !ok {
			continue
		}
		if it.depth < maxSitemapDepth {
			for _, sm := range doc.Sitemaps {
				if abs, err := joinURL(it.u, strings.TrimSpace(sm.Loc)); err == nil && sameHost(abs, b) {
					work = append(work, item{abs, it.depth + 1})
				}
			}
		}
		for _, u := range doc.URLs {
			loc := strings.TrimSpace(u.Loc)
			if loc == "" || seenURLs[loc] || !sameHost(loc, b) {
				continue
			}
			seenURLs[loc] = true
			out = append(out, loc)
			if len(out) >= max {
				break
			}
		}
	}
	return out
}

// getSitemap fetches and parses one sitemap file (plain or gzipped). ok is
// false for a non-200 response or anything that isn't sitemap XML.
func getSitemap(client *http.Client, u string) (sitemapDoc, bool) {
	var doc sitemapDoc
	resp, err := netx.Get(client, u)
	if err != nil {
		return doc, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return doc, false
	}
	var r io.Reader = io.LimitReader(resp.Body, maxSitemapBytes)
	br := bufio.NewReader(r)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return doc, false
		}
		r = io.LimitReader(gz, maxSitemapBytes)
	} else {
		r = br
	}
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return doc, false
	}
	return doc, len(doc.URLs)+len(doc.Sitemaps) > 0
}

// sameHost reports whether raw is an http(s) URL on base's host.
func sameHost(raw string, base *url.URL) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return strings.EqualFold(u.Host, base.Host)
}

// filterWildcards drops entries containing '*' (robots-checker.py does the same)
// and blank entries.
func filterWildcards(entries []string) []string {
	var out []string
	for _, e := range entries {
		if e != "" && !strings.Contains(e, "*") {
			out = append(out, e)
		}
	}
	return out
}

// probePaths GETs every path under base concurrently and prints status + length.
func probePaths(client *http.Client, base string, paths []string, cm colorout.Mode, conc int) {
	type result struct {
		line string
		ok   bool
	}
	results := make([]result, len(paths))

	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, conc))
	for i, p := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p string) {
			defer wg.Done()
			defer func() { <-sem }()

			full, err := joinURL(base, p)
			if err != nil {
				results[i] = result{line: fmt.Sprintf("failed to build URL for %s: %v", p, err)}
				return
			}
			resp, err := netx.Get(client, full)
			if err != nil {
				results[i] = result{line: fmt.Sprintf("%s [ERR] %v", full, err)}
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			results[i] = result{
				line: fmt.Sprintf("%s [%d] [%d]", full, resp.StatusCode, len(body)),
				ok:   resp.StatusCode == http.StatusOK,
			}
		}(i, p)
	}
	wg.Wait()

	for _, r := range results {
		if r.ok {
			fmt.Println(cm.Wrap(colorout.Green, r.line))
		} else {
			fmt.Println(cm.Wrap(colorout.Red, r.line))
		}
	}
}

// joinURL resolves ref against base, like Python's urljoin.
func joinURL(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(r).String(), nil
}

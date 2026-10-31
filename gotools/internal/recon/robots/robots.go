// Package robots implements the robots command: fetching robots.txt and
// probing each Allow/Disallow path it lists.
package robots

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "robots",
		Group:   "WEB recon",
		Summary: "Fetch robots.txt and probe each Allow/Disallow path (robots-checker.py)",
		Run:     Run,
	})
}

func Run(args []string) error {
	fs := flag.NewFlagSet("robots", flag.ExitOnError)
	in := fs.String("l", "", "file of base URLs (optional; args/stdin also accepted)")
	colorFlag := fs.String("color", "auto", "color output: auto|always|never")
	timeout := fs.Duration("timeout", 15*time.Second, "per-request timeout")
	insecure := fs.Bool("insecure", true, "skip TLS verification")
	conc := fs.Int("c", 20, "concurrent path probes per host")
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
		if lines, err := ioutil.InputLines(""); err == nil {
			bases = append(bases, lines...)
		}
	}
	if len(bases) == 0 {
		return ioutil.ErrMissing("provide a base URL as an argument, via -l, or on stdin")
	}

	client := netx.NewClient(*timeout, *insecure)
	unreachable := 0
	defer func() {
		ioutil.Warn("checked %d site(s), %d without a robots.txt", len(bases), unreachable)
	}()
	for _, base := range bases {
		allow, disallow, err := parseRobots(client, base)
		if err != nil {
			ioutil.Warn("%s: %v", base, err)
			unreachable++
			continue
		}
		fmt.Println(cm.Wrap(colorout.Cyan, "--- "+base+" ---"))
		fmt.Println(cm.Wrap(colorout.Cyan, "[Allow]"))
		probePaths(client, base, filterWildcards(allow), cm, *conc)
		fmt.Println(cm.Wrap(colorout.Cyan, "[Disallow]"))
		probePaths(client, base, filterWildcards(disallow), cm, *conc)
	}
	return nil
}

// parseRobots fetches /robots.txt and returns Allow and Disallow paths.
func parseRobots(client *http.Client, base string) (allow, disallow []string, err error) {
	robotsURL, err := joinURL(base, "/robots.txt")
	if err != nil {
		return nil, nil, err
	}
	resp, err := netx.Get(client, robotsURL)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Disallow:"):
			disallow = append(disallow, strings.TrimSpace(line[len("Disallow:"):]))
		case strings.HasPrefix(line, "Allow:"):
			allow = append(allow, strings.TrimSpace(line[len("Allow:"):]))
		}
	}
	return allow, disallow, nil
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

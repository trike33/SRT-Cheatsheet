package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

func init() {
	register(&command{
		name:    "probe",
		group:   "WEB recon",
		summary: "Native httpx-lite: title/status/content-length/server + basic tech-detect per target",
		run:     runProbe,
	})
}

type probeResult struct {
	Target string   `json:"target"`
	URL    string   `json:"url,omitempty"`
	Status int      `json:"status,omitempty"`
	Length int      `json:"length,omitempty"`
	Title  string   `json:"title,omitempty"`
	Server string   `json:"server,omitempty"`
	Tech   []string `json:"tech,omitempty"`
	Err    string   `json:"error,omitempty"`
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// techSignature is one best-effort fingerprint. This is intentionally a
// small, conservative set — not a wappalyzer-equivalent — covering the
// servers/frameworks/CMSs common enough to be worth flagging by default;
// see docs/ROADMAP.md.
type techSignature struct {
	name  string
	match func(headers http.Header, body string) bool
}

var techSignatures = []techSignature{
	{"WordPress", func(h http.Header, b string) bool {
		return strings.Contains(b, "wp-content") || strings.Contains(b, "wp-includes")
	}},
	{"Drupal", func(h http.Header, b string) bool {
		return strings.Contains(b, "Drupal.settings") || strings.Contains(h.Get("X-Generator"), "Drupal") ||
			strings.Contains(b, "/sites/default/files")
	}},
	{"Joomla", func(h http.Header, b string) bool {
		return strings.Contains(b, "/media/jui/") || strings.Contains(b, "Joomla!")
	}},
	{"Laravel", func(h http.Header, b string) bool {
		return strings.Contains(strings.Join(h.Values("Set-Cookie"), ";"), "laravel_session")
	}},
	{"Django", func(h http.Header, b string) bool {
		return strings.Contains(strings.Join(h.Values("Set-Cookie"), ";"), "csrftoken")
	}},
	{"Express", func(h http.Header, b string) bool { return strings.Contains(h.Get("X-Powered-By"), "Express") }},
	{"PHP", func(h http.Header, b string) bool {
		return strings.Contains(h.Get("X-Powered-By"), "PHP") ||
			strings.Contains(strings.Join(h.Values("Set-Cookie"), ";"), "PHPSESSID")
	}},
	{"ASP.NET", func(h http.Header, b string) bool {
		return strings.Contains(h.Get("X-Powered-By"), "ASP.NET") || h.Get("X-AspNet-Version") != ""
	}},
	{"nginx", func(h http.Header, b string) bool { return strings.Contains(strings.ToLower(h.Get("Server")), "nginx") }},
	{"Apache", func(h http.Header, b string) bool {
		return strings.Contains(strings.ToLower(h.Get("Server")), "apache")
	}},
	{"IIS", func(h http.Header, b string) bool { return strings.Contains(strings.ToLower(h.Get("Server")), "iis") }},
	{"Cloudflare", func(h http.Header, b string) bool {
		return strings.Contains(strings.ToLower(h.Get("Server")), "cloudflare")
	}},
}

func runProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	in := fs.String("l", "", "target list: URLs or bare hosts (default: stdin)")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	insecure := fs.Bool("insecure", true, "skip TLS verification")
	conc := fs.Int("c", 40, "concurrent probes")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of a table")
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer startHeartbeat("probe")()

	targets, err := inputLines(resolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errMissing("no targets: pass -l <file> or pipe targets on stdin")
	}

	client := newHTTPClient(*timeout, *insecure)
	results := make([]probeResult, len(targets))

	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *conc))
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = probeOne(client, target)
		}(i, t)
	}
	wg.Wait()
	for _, r := range results {
		sink.add(probeRecord(r))
	}

	w, err := output(*out)
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
	fmt.Fprintln(tw, "TARGET\tSTATUS\tLENGTH\tSERVER\tTECH\tTITLE")
	for _, r := range results {
		if r.Err != "" {
			fmt.Fprintf(tw, "%s\t-\t-\t-\t-\t[ERR] %s\n", r.Target, r.Err)
			continue
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\t%s\n",
			r.URL, r.Status, r.Length, r.Server, strings.Join(r.Tech, ","), r.Title)
	}
	return tw.Flush()
}

// probeOne tries https:// then http:// for a bare host (matching srt's
// insecure-by-default convention elsewhere), or uses target as-is if it
// already has a scheme.
func probeOne(client *http.Client, target string) probeResult {
	r := probeResult{Target: target}

	tries := []string{target}
	if !strings.Contains(target, "://") {
		tries = []string{"https://" + target, "http://" + target}
	}

	var lastErr error
	for _, u := range tries {
		resp, err := httpGet(client, u)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		r.URL = u
		r.Status = resp.StatusCode
		r.Length = len(body)
		if m := titleRe.FindSubmatch(body); m != nil {
			r.Title = strings.TrimSpace(strings.Join(strings.Fields(string(m[1])), " "))
		}
		r.Server = resp.Header.Get("Server")
		bodyStr := string(body)
		for _, sig := range techSignatures {
			if sig.match(resp.Header, bodyStr) {
				r.Tech = append(r.Tech, sig.name)
			}
		}
		return r
	}

	if lastErr != nil {
		r.Err = lastErr.Error()
	}
	return r
}

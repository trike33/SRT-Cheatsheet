// Package probe implements the probe command: a native httpx-lite that
// reports title/status/content-length/server plus a best-effort tech-detect
// per target. recon/fuzz also calls One directly, to fingerprint a host's
// stack for -ext-auto.
package probe

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "probe",
		Group:   "WEB recon",
		Summary: "Native httpx-lite: title/status/content-length/server + basic tech-detect per target",
		Run:     Run,
	})
}

// Result is one target's probe outcome.
type Result struct {
	Target string   `json:"target"`
	URL    string   `json:"url,omitempty"`
	Status int      `json:"status,omitempty"`
	Length int      `json:"length,omitempty"`
	Title  string   `json:"title,omitempty"`
	Server string   `json:"server,omitempty"`
	Tech   []string `json:"tech,omitempty"`
	Err    string   `json:"error,omitempty"`
}

// Record reduces a Result to the generic shape the results database stores.
func (r Result) Record() store.Record {
	key := r.URL
	if key == "" {
		key = r.Target
	}
	h, p := store.HostPortOf(key)
	if h == "" {
		h = r.Target
	}
	d := map[string]any{}
	if r.Title != "" {
		d["title"] = r.Title
	}
	if r.Server != "" {
		d["server"] = r.Server
	}
	if len(r.Tech) > 0 {
		d["tech"] = r.Tech
	}
	if r.Err != "" {
		d["error"] = r.Err
	}
	return store.Record{Kind: "probe", Key: key, Host: h, Port: p, URL: r.URL, Status: r.Status, Length: r.Length, Data: d}
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// signature is one best-effort fingerprint. This is intentionally a small,
// conservative set -- not a wappalyzer-equivalent -- covering the
// servers/frameworks/CMSs common enough to be worth flagging by default;
// see docs/ROADMAP.md.
type signature struct {
	name  string
	match func(headers http.Header, body string) bool
}

var signatures = []signature{
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

func Run(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "PERFORMANCE", Names: []string{"timeout", "insecure", "c"}},
			{Title: "OUTPUT", Names: []string{"o", "json", "color"}},
		})
	}
	in := fs.String("l", "", "target list: URLs or bare hosts (default: stdin, else the project db's domain/subdomain records -- see -from)")
	fb := store.BindInputFallback(fs, "probe", "domain", "subdomain")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	insecure := fs.Bool("insecure", true, "skip TLS verification")
	conc := fs.Int("c", 40, "concurrent probes")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of a table")
	colorFlag := fs.String("color", "auto", "color the table output: auto|always|never (ignored with -json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	defer ioutil.StartHeartbeat("probe")()

	targets, _, err := fb.Resolve(*in, fs.Args())
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return ioutil.ErrMissing("no targets: pass -l <file>, pipe targets on stdin, or save some into the project db first (see `srt results`)")
	}

	client := netx.NewClient(*timeout, *insecure)
	results := make([]Result, len(targets))

	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *conc))
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = One(client, target)
		}(i, t)
	}
	wg.Wait()
	for _, r := range results {
		store.CurrentSink().Add(r.Record())
	}

	w, err := ioutil.Output(*out)
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

	printTable(w, results, cm)
	return nil
}

// printTable renders results as a column-aligned, optionally colorized
// table: status 2xx/3xx/4xx/5xx in green/cyan/yellow/red, detected tech in
// magenta, and a failed probe's whole row in red so it stands out from the
// successes around it. Column widths are computed from the plain
// (uncolored) text first, then colored via Mode.PadWrap -- padding before
// coloring is what keeps every column aligned regardless of which cells
// end up colored (see colorout.PadWrap).
func printTable(w io.Writer, results []Result, cm colorout.Mode) {
	type row struct {
		target, status, length, server, tech, title string
		err                                         bool
		code                                        int
	}
	rows := make([]row, len(results))
	for i, r := range results {
		if r.Err != "" {
			rows[i] = row{target: r.Target, status: "-", length: "-", server: "-", tech: "-", title: "[ERR] " + r.Err, err: true}
			continue
		}
		rows[i] = row{
			target: r.URL, status: strconv.Itoa(r.Status), length: strconv.Itoa(r.Length),
			server: r.Server, tech: strings.Join(r.Tech, ","), title: r.Title, code: r.Status,
		}
	}

	headers := []string{"TARGET", "STATUS", "LENGTH", "SERVER", "TECH"}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len([]rune(h))
	}
	for _, r := range rows {
		cells := []string{r.target, r.status, r.length, r.server, r.tech}
		for i, c := range cells {
			if n := len([]rune(c)); n > widths[i] {
				widths[i] = n
			}
		}
	}

	fmt.Fprintln(w, strings.Join([]string{
		pad(headers[0], widths[0]), pad(headers[1], widths[1]), pad(headers[2], widths[2]),
		pad(headers[3], widths[3]), pad(headers[4], widths[4]), "TITLE",
	}, "  "))

	for _, r := range rows {
		statusColor := colorout.StatusColor(r.code)
		techColor := colorout.Magenta
		titleColor := ""
		if r.err {
			statusColor, techColor, titleColor = colorout.Red, colorout.Red, colorout.Red
		} else if r.tech == "" {
			techColor = ""
		}
		fmt.Fprintln(w, strings.Join([]string{
			cm.PadWrap("", r.target, widths[0]),
			cm.PadWrap(statusColor, r.status, widths[1]),
			cm.PadWrap("", r.length, widths[2]),
			cm.PadWrap("", r.server, widths[3]),
			cm.PadWrap(techColor, r.tech, widths[4]),
			cm.Wrap(titleColor, r.title),
		}, "  "))
	}
}

// pad is the plain (never colored) left-pad used for header cells, which
// are never wrapped in a color code so they need no PadWrap.
func pad(s string, width int) string {
	if n := len([]rune(s)); n < width {
		return s + strings.Repeat(" ", width-n)
	}
	return s
}

// One tries https:// then http:// for a bare host (matching srt's
// insecure-by-default convention elsewhere), or uses target as-is if it
// already has a scheme.
func One(client *http.Client, target string) Result {
	r := Result{Target: target}

	tries := []string{target}
	if !strings.Contains(target, "://") {
		tries = []string{"https://" + target, "http://" + target}
	}

	var lastErr error
	for _, u := range tries {
		resp, err := netx.Get(client, u)
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
		for _, sig := range signatures {
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

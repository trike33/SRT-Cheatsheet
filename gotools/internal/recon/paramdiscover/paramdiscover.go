// Package paramdiscover implements the paramdiscover command: Arjun-style
// parameter guessing. Given an endpoint, `params` only ever classifies
// parameter names already sitting in its URL -- this instead finds names
// the endpoint reads but doesn't expose in any URL at all (a hidden
// `?debug=1`, a form field a crawler never submitted), by comparing a
// baseline response against batches of candidate names and bisecting any
// batch that changes something down to the specific name(s) responsible.
// That bisection is the whole point: trying 6000+ candidate names one
// request each would be 6000+ requests per endpoint; batching them and only
// descending into a batch that actually changed something cuts that by
// roughly the batch size whenever (as is typical) almost none of a batch's
// names apply.
package paramdiscover

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
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
	"github.com/trike33/srt-cheatsheet/gotools/internal/wordlists"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "paramdiscover",
		Group:   "WEB recon",
		Summary: "Guess hidden GET parameters an endpoint reads but never exposes in a URL (Arjun-style batch+bisect)",
		Run:     Run,
	})
}

const maxBody = 1 << 20 // read at most 1 MiB per response, same cap as validate

// skippedContentTypes are response types not worth probing for parameters --
// a candidate param added to an image/video/binary request can't change
// anything meaningful, so baseline alone decides to skip rather than
// spending a batch of requests finding that out.
var skippedContentTypes = []string{
	"image/", "video/", "audio/", "font/",
	"application/octet-stream", "application/pdf", "application/zip",
	"application/x-7z-compressed", "application/gzip",
}

// Result is one endpoint's discovery outcome.
type Result struct {
	URL       string   `json:"url"`
	Found     []string `json:"found,omitempty"`
	Reflected []string `json:"reflected,omitempty"` // subset of Found whose value came back in the body
	Requests  int      `json:"requests"`
	Skipped   string   `json:"skipped,omitempty"`
}

// probeResult is one request's response reduced to what changed() compares.
type probeResult struct {
	status      int
	size        int
	words       int
	body        []byte
	contentType string
}

// Discoverer holds one run's shared config: the HTTP client, the marker
// value every candidate's probe value is set to (so a reflected value is
// unambiguous), and the diff tolerance.
type Discoverer struct {
	client    *http.Client
	marker    string
	method    string
	tolPct    float64
	batchSize int
	delay     time.Duration
}

// New builds a Discoverer. method is the HTTP method to probe with ("GET"
// adds candidates to the query string; any other value sends them
// form-encoded in the body instead).
func New(client *http.Client, method string, tolPct float64, batchSize int) *Discoverer {
	return &Discoverer{
		client:    client,
		marker:    "zz" + randHex(6),
		method:    strings.ToUpper(method),
		tolPct:    tolPct,
		batchSize: max(1, batchSize),
	}
}

// Discover runs the batch+bisect pass against targetURL over candidates,
// skipping any candidate already present in targetURL's own query (already
// known, not hidden) and any binary content type (baseline decides, one
// request). requests counts every HTTP request this call made, for the
// caller's own traffic accounting.
func (d *Discoverer) Discover(targetURL string, candidates []string) Result {
	r := Result{URL: targetURL}
	base, _, err := d.probe(targetURL, nil)
	r.Requests++
	if err != nil {
		r.Skipped = "error: " + err.Error()
		return r
	}
	if isSkippableContentType(base.contentType) {
		r.Skipped = "non-text content (" + base.contentType + ")"
		return r
	}

	existing := existingParams(targetURL)
	var toTry []string
	for _, c := range candidates {
		if !existing[strings.ToLower(c)] {
			toTry = append(toTry, c)
		}
	}

	var found []string
	for i := 0; i < len(toTry); i += d.batchSize {
		end := min(i+d.batchSize, len(toTry))
		batch := toTry[i:end]
		resp, _, err := d.probe(targetURL, batch)
		r.Requests++
		if err != nil {
			continue
		}
		if d.changed(base, resp) {
			hits, n := d.bisect(targetURL, base, batch)
			r.Requests += n
			found = append(found, hits...)
		}
	}
	r.Found = ioutil.DedupStrings(found)

	for _, name := range r.Found {
		_, body, err := d.probe(targetURL, []string{name})
		r.Requests++
		if err == nil && bytes.Contains(body, []byte(d.marker)) {
			r.Reflected = append(r.Reflected, name)
		}
	}
	return r
}

// bisect narrows a batch that changed something down to the individual
// name(s) responsible, confirming each candidate alone against the
// baseline before accepting it (cuts false positives from one flaky
// request). Returns the confirmed names and how many requests it took.
func (d *Discoverer) bisect(targetURL string, base probeResult, batch []string) (found []string, requests int) {
	if len(batch) == 1 {
		resp, _, err := d.probe(targetURL, batch)
		requests++
		if err == nil && d.changed(base, resp) {
			return batch, requests
		}
		return nil, requests
	}
	mid := len(batch) / 2
	for _, half := range [][]string{batch[:mid], batch[mid:]} {
		resp, _, err := d.probe(targetURL, half)
		requests++
		if err != nil {
			continue
		}
		if d.changed(base, resp) {
			hits, n := d.bisect(targetURL, base, half)
			requests += n
			found = append(found, hits...)
		}
	}
	return found, requests
}

// changed reports whether resp looks meaningfully different from base:
// a different status, the marker value reflected in the body, a body size
// delta beyond tolerance, or a word-count delta beyond tolerance.
func (d *Discoverer) changed(base, resp probeResult) bool {
	if resp.status != base.status {
		return true
	}
	if bytes.Contains(resp.body, []byte(d.marker)) {
		return true
	}
	sizeTol := max(10, int(float64(base.size)*d.tolPct/100))
	if abs(resp.size-base.size) > sizeTol {
		return true
	}
	wordTol := max(2, base.words/20)
	return abs(resp.words-base.words) > wordTol
}

// probe issues one request with names added as candidate parameters (each
// set to the shared marker value) and returns the reduced result plus the
// raw body (callers that need to grep the body, like Discover's reflection
// check, read it from here instead of re-fetching).
func (d *Discoverer) probe(targetURL string, names []string) (probeResult, []byte, error) {
	if d.delay > 0 {
		time.Sleep(d.delay)
	}
	req, err := d.buildRequest(targetURL, names)
	if err != nil {
		return probeResult{}, nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return probeResult{}, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return probeResult{
		status:      resp.StatusCode,
		size:        len(body),
		words:       len(bytes.Fields(body)),
		body:        body,
		contentType: resp.Header.Get("Content-Type"),
	}, body, nil
}

func (d *Discoverer) buildRequest(targetURL string, names []string) (*http.Request, error) {
	if d.method != "GET" {
		form := url.Values{}
		for _, n := range names {
			form.Set(n, d.marker)
		}
		req, err := http.NewRequest(d.method, targetURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", netx.DefaultUA)
		return req, nil
	}

	pu, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	q := pu.Query()
	for _, n := range names {
		q.Set(n, d.marker)
	}
	pu.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, pu.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", netx.DefaultUA)
	return req, nil
}

// existingParams returns the lowercased set of query parameter names
// targetURL already has -- candidates matching one are skipped, since
// params already visible in the URL aren't hidden and classifyParams
// (the `params` command) already covers them.
func existingParams(targetURL string) map[string]bool {
	out := map[string]bool{}
	pu, err := url.Parse(targetURL)
	if err != nil {
		return out
	}
	for k := range pu.Query() {
		out[strings.ToLower(k)] = true
	}
	return out
}

// isSkippableContentType reports whether ct is a type worth skipping
// parameter discovery for -- a candidate added to an image/video/binary
// request can't change anything meaningful, so the baseline's own
// Content-Type header decides in one request rather than spending a whole
// batch finding that out.
func isSkippableContentType(ct string) bool {
	ct = strings.ToLower(ct)
	for _, sig := range skippedContentTypes {
		if strings.HasPrefix(ct, sig) {
			return true
		}
	}
	return false
}

func randHex(n int) string {
	const alphabet = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func Run(args []string) error {
	fs := flag.NewFlagSet("paramdiscover", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "w", "top"}},
			{Title: "DISCOVERY", Names: []string{"X", "bs", "tol"}},
			{Title: "PERFORMANCE", Names: []string{"timeout", "insecure", "c", "delay"}},
			{Title: "OUTPUT", Names: []string{"o", "json", "silent", "color"}},
		})
	}
	in := fs.String("l", "", "endpoint URL list (default: stdin / args)")
	var wordlistFiles stringSlice
	fs.Var(&wordlistFiles, "w", "candidate parameter name wordlist (repeatable). Omit to use the embedded SecLists burp-parameter-names.txt (~6.4k names)")
	top := fs.Int("top", 0, "try at most the first N candidate names (0 = all)")
	method := fs.String("X", "GET", "HTTP method: GET adds candidates to the query string, anything else sends them form-encoded in the body")
	batchSize := fs.Int("bs", 25, "candidate names tried per request before bisecting a batch that changed something")
	tol := fs.Float64("tol", 5, "body size/word-count tolerance around the baseline, in percent")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	insecure := fs.Bool("insecure", true, "skip TLS verification")
	conc := fs.Int("c", 10, "endpoints probed concurrently (each endpoint's own batches run sequentially)")
	delay := fs.Duration("delay", 0, "fixed delay before each request")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit a JSON line per endpoint instead of a table")
	silent := fs.Bool("silent", false, "print only endpoints with at least one discovered parameter")
	colorFlag := fs.String("color", "auto", "color output: auto|always|never")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	defer ioutil.StartHeartbeat("paramdiscover")()

	urls, err := ioutil.InputLines(ioutil.ResolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}
	urls = ioutil.DedupStrings(urls)
	if len(urls) == 0 {
		return ioutil.ErrMissing("no endpoints: pass -l <file> or pipe URLs on stdin")
	}

	candidates, err := loadCandidates(wordlistFiles)
	if err != nil {
		return err
	}
	if *top > 0 && len(candidates) > *top {
		candidates = candidates[:*top]
	}
	if len(candidates) == 0 {
		return ioutil.ErrMissing("empty candidate wordlist")
	}

	d := New(netx.NewClientOpts(*timeout, *insecure, "", false), *method, *tol, *batchSize)
	d.delay = *delay

	results := make([]Result, len(urls))
	var wg sync.WaitGroup
	var done atomic.Int64
	sem := make(chan struct{}, max(1, *conc))
	start := time.Now()
	for i, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, u string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = d.Discover(u, candidates)
			if n := done.Add(1); len(urls) > 1 {
				ioutil.Progress("paramdiscover: %d/%d · %s", n, len(urls), ioutil.ElapsedETA(n, int64(len(urls)), time.Since(start)))
			}
		}(i, u)
	}
	wg.Wait()
	if len(urls) > 1 {
		colorout.ClearLine(os.Stderr)
	}

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()

	totalFound, totalReq := 0, 0
	for _, r := range results {
		totalFound += len(r.Found)
		totalReq += r.Requests
		switch {
		case *jsonOut:
			b, _ := json.Marshal(r)
			fmt.Fprintln(w, string(b))
		case len(r.Found) == 0:
			if !*silent && r.Skipped == "" {
				fmt.Fprintln(w, cm.Wrap(colorout.Yellow, r.URL+"  (no hidden parameters found)"))
			}
		default:
			reflected := map[string]bool{}
			for _, n := range r.Reflected {
				reflected[n] = true
			}
			var parts []string
			for _, n := range r.Found {
				if reflected[n] {
					parts = append(parts, n+"*")
				} else {
					parts = append(parts, n)
				}
			}
			fmt.Fprintln(w, cm.Wrap(colorout.Green, r.URL+"  "+strings.Join(parts, ",")))
		}
	}
	ioutil.Warn("paramdiscover: %d parameter(s) found across %d endpoint(s), %d request(s) total (* = value reflected in the response)",
		totalFound, len(results), totalReq)
	return nil
}

// loadCandidates reads every wordlist file, or the embedded default when
// none are given, deduplicated and order-preserved.
func loadCandidates(files stringSlice) ([]string, error) {
	if len(files) == 0 {
		dir, err := os.MkdirTemp("", "srt-paramdiscover")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		p, err := wordlists.ParamNamesFile(dir)
		if err != nil {
			return nil, err
		}
		return ioutil.InputLines(p)
	}
	seen := map[string]struct{}{}
	var out []string
	for _, f := range files {
		lines, err := ioutil.InputLines(f)
		if err != nil {
			return nil, err
		}
		for _, l := range lines {
			if _, dup := seen[l]; dup {
				continue
			}
			seen[l] = struct{}{}
			out = append(out, l)
		}
	}
	return out, nil
}

// stringSlice collects a repeatable -w flag.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// Package validate implements the validate command: given a list of
// candidate URLs (archived, robots/sitemap, brute-forced), keep only the ones
// that really exist -- by fingerprinting each host's "not found" response and
// dropping everything that looks like it. Many sites answer 200 (or a
// redirect, or 403) for any path, so a status code alone proves nothing.
package validate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
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
		Name:    "validate",
		Group:   "WEB recon",
		Summary: "Re-probe candidate URLs and keep the real ones, dropping soft-404s (200/redirect/403 for anything)",
		Run:     Run,
	})
}

const maxBody = 1 << 20 // read at most 1 MiB per response

// Verdict is the outcome for one candidate URL.
type Verdict struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Length int    `json:"length,omitempty"`
	Words  int    `json:"words,omitempty"`
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"` // why it was rejected
}

// print is one response reduced to what the fingerprints compare.
type print struct {
	status int
	size   int // body bytes with echoes of the requested name removed
	words  int
	loc    string // normalized Location for 3xx
}

// band is a tolerance range around one or more not-found responses.
type band struct {
	status     int
	minS, maxS int
	minW, maxW int
	loc        string
}

// Validator fingerprints each host's not-found behaviour lazily and judges
// URLs against it.
type Validator struct {
	client *http.Client
	tolPct float64
	probes int
	accept func(int) bool
	mu     sync.Mutex
	calibs map[string]*calib
}

type calib struct {
	once  sync.Once
	bands []band
}

// New builds a Validator. tolPct is the size tolerance in percent; probes is
// how many random not-found paths are requested per calibration.
func New(client *http.Client, tolPct float64, probes int) *Validator {
	return &Validator{
		client: client, tolPct: tolPct, probes: max(1, probes),
		accept: func(s int) bool { return (s >= 200 && s < 400) || s == 401 || s == 403 },
		calibs: map[string]*calib{},
	}
}

// Check requests u and decides whether it is a real resource.
func (v *Validator) Check(u string) (Verdict, print) {
	vd := Verdict{URL: u}
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
		vd.Reason = "not an http(s) URL"
		return vd, print{}
	}
	p, err := v.fetch(u, lastSegment(pu.Path))
	if err != nil {
		vd.Reason = "error: " + err.Error()
		return vd, print{}
	}
	vd.Status, vd.Length, vd.Words = p.status, p.size, p.words
	if !v.accept(p.status) {
		vd.Reason = fmt.Sprintf("status %d", p.status)
		return vd, p
	}
	for _, b := range v.calibration(pu) {
		if v.matches(b, p) {
			vd.Reason = "soft-404: matches the host's not-found response"
			return vd, p
		}
	}
	vd.Valid = true
	return vd, p
}

// fetch GETs u without following redirects (a redirect IS the fingerprint
// for many soft-404s) and reduces the response to a print; echo is the
// requested name, removed from the size so a reflected path doesn't matter.
func (v *Validator) fetch(u, echo string) (print, error) {
	resp, err := netx.Get(v.client, u)
	if err != nil {
		return print{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	resp.Body.Close()
	p := print{status: resp.StatusCode, size: len(body), words: len(strings.Fields(string(body)))}
	if echo != "" {
		p.size -= bytes.Count(body, []byte(echo)) * len(echo)
		p.loc = strings.ReplaceAll(resp.Header.Get("Location"), echo, "")
	} else {
		p.loc = resp.Header.Get("Location")
	}
	return p, nil
}

func (v *Validator) tol(n int) int { return max(6, int(float64(n)*v.tolPct/100)) }

func (v *Validator) matches(b band, p print) bool {
	if p.status != b.status {
		return false
	}
	if p.status >= 300 && p.status < 400 {
		return p.loc == b.loc
	}
	ts, tw := v.tol(b.maxS), max(2, b.maxW/20)
	return p.size >= b.minS-ts && p.size <= b.maxS+ts && p.words >= b.minW-tw && p.words <= b.maxW+tw
}

// calibration returns (computing once) the not-found bands for pu's class:
// same origin, same first directory, same extension -- apps routinely treat
// /api/*, /*.php and the site root differently.
func (v *Validator) calibration(pu *url.URL) []band {
	dir, ext := classify(pu.Path)
	key := pu.Scheme + "://" + pu.Host + "|" + dir + "|" + ext
	v.mu.Lock()
	c := v.calibs[key]
	if c == nil {
		c = &calib{}
		v.calibs[key] = c
	}
	v.mu.Unlock()
	c.once.Do(func() {
		for i := 0; i < v.probes; i++ {
			tok := randToken()
			probe := pu.Scheme + "://" + pu.Host + dir + "/" + tok
			if ext == "/" {
				probe += "/"
			} else {
				probe += ext
			}
			p, err := v.fetch(probe, tok)
			if err != nil {
				continue
			}
			c.bands = merge(c.bands, p, v)
		}
	})
	return c.bands
}

func merge(bands []band, p print, v *Validator) []band {
	for i := range bands {
		b := &bands[i]
		if v.matches(*b, p) {
			b.minS, b.maxS = min(b.minS, p.size), max(b.maxS, p.size)
			b.minW, b.maxW = min(b.minW, p.words), max(b.maxW, p.words)
			return bands
		}
	}
	return append(bands, band{status: p.status, minS: p.size, maxS: p.size, minW: p.words, maxW: p.words, loc: p.loc})
}

// classify returns the first directory ("" for root-level) and the
// extension class ("/" for a directory URL, ".php" etc., or "" for none).
func classify(p string) (dir, ext string) {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) > 1 {
		dir = "/" + segs[0]
	}
	if strings.HasSuffix(p, "/") && p != "" {
		return dir, "/"
	}
	if e := path.Ext(lastSegment(p)); len(e) > 0 && len(e) <= 6 {
		ext = strings.ToLower(e)
	}
	return dir, ext
}

func lastSegment(p string) string { return path.Base(strings.TrimSuffix(p, "/")) }

func randToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "srt" + hex.EncodeToString(b)
}

// Learn rejects groups of >= learnAt valid URLs on one origin whose
// responses are near-identical: a not-found page the calibration missed.
// It returns the (possibly downgraded) verdicts.
func Learn(vs []Verdict, learnAt int) []Verdict {
	if learnAt <= 0 {
		return vs
	}
	type key struct {
		origin      string
		status      int
		size, words int
	}
	counts := map[key]int{}
	keyOf := func(v Verdict) key {
		o := v.URL
		if pu, err := url.Parse(v.URL); err == nil {
			o = pu.Scheme + "://" + pu.Host
		}
		return key{o, v.Status, v.Length / 32, v.Words / 4}
	}
	for _, v := range vs {
		if v.Valid {
			counts[keyOf(v)]++
		}
	}
	for i, v := range vs {
		if v.Valid {
			if n := counts[keyOf(v)]; n >= learnAt {
				vs[i].Valid = false
				vs[i].Reason = fmt.Sprintf("soft-404: learned from %d near-identical responses", n)
			}
		}
	}
	return vs
}

func Run(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "SOFT-404 DETECTION", Names: []string{"probes", "tol", "learn"}},
			{Title: "PERFORMANCE", Names: []string{"timeout", "insecure", "c", "max"}},
			{Title: "OUTPUT", Names: []string{"o", "silent", "json", "rejected", "color"}},
		})
	}
	in := fs.String("l", "", "URL list (default: stdin / args, else the project db's url/probe/gau/robots records -- see -from)")
	fb := store.BindInputFallback(fs, "validate", "url", "probe", "gau", "robots")
	probes := fs.Int("probes", 3, "random not-found paths requested per host/directory/extension class")
	tol := fs.Float64("tol", 5, "size tolerance around a not-found response, in percent")
	learn := fs.Int("learn", 10, "reject groups of this many near-identical 'valid' responses on one host (0 = off)")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	insecure := fs.Bool("insecure", true, "skip TLS verification")
	conc := fs.Int("c", 40, "concurrent requests")
	maxURLs := fs.Int("max", 0, "check at most this many URLs, first ones first (0 = all)")
	out := fs.String("o", "", "write valid URLs to this file (default: stdout)")
	silent := fs.Bool("silent", false, "print only the valid URLs")
	jsonOut := fs.Bool("json", false, "emit a JSON line per URL (valid and rejected)")
	rejected := fs.String("rejected", "", "also write rejected URLs with the reason to this file")
	colorFlag := fs.String("color", "auto", "color output: auto|always|never")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	defer ioutil.StartHeartbeat("validate")()

	urls, _, err := fb.Resolve(*in, fs.Args())
	if err != nil {
		return err
	}
	urls = ioutil.DedupStrings(urls)
	if *maxURLs > 0 && len(urls) > *maxURLs {
		ioutil.Warn("checking the first %d of %d URLs (-max)", *maxURLs, len(urls))
		urls = urls[:*maxURLs]
	}
	if len(urls) == 0 {
		return ioutil.ErrMissing("no URLs: pass -l <file>, pipe URLs on stdin, or save some into the project db first (see `srt results`)")
	}

	v := New(netx.NewClientOpts(*timeout, *insecure, "", false), *tol, *probes)
	verdicts := make([]Verdict, len(urls))
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
			verdicts[i], _ = v.Check(u)
			if n := done.Add(1); len(urls) > 1 {
				ioutil.Progress("validate: %d/%d · %s", n, len(urls), ioutil.ElapsedETA(n, int64(len(urls)), time.Since(start)))
			}
		}(i, u)
	}
	wg.Wait()
	if len(urls) > 1 {
		colorout.ClearLine(os.Stderr)
	}
	verdicts = Learn(verdicts, *learn)

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	var rw io.WriteCloser
	if *rejected != "" {
		if rw, err = ioutil.Output(*rejected); err != nil {
			return err
		}
		defer rw.Close()
	}
	valid := 0
	for _, vd := range verdicts {
		if vd.Valid {
			valid++
		}
		switch {
		case *jsonOut:
			b, _ := json.Marshal(vd)
			fmt.Fprintln(w, string(b))
		case vd.Valid && *silent:
			fmt.Fprintln(w, vd.URL)
		case vd.Valid:
			fmt.Fprintln(w, cm.Wrap(colorout.Green, fmt.Sprintf("%-3d  %7db  %5dw  %s", vd.Status, vd.Length, vd.Words, vd.URL)))
		}
		if !vd.Valid && rw != nil && !*jsonOut {
			fmt.Fprintf(rw, "%s\t%s\n", vd.Reason, vd.URL)
		}
	}
	ioutil.Warn("validate: %d of %d URL(s) are real; %d rejected (dead, errors, or soft-404)", valid, len(verdicts), len(verdicts)-valid)
	return nil
}

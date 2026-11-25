// Package telnet implements the telnet command: Phase 1 of SRT's
// internal-pentest protocol family (see docs/internal-pentest-feasibility).
// Like ftp, this needs no external library -- just a raw net.Dial client
// that declines every telnet option negotiation (IAC DO/WILL) so a server
// waiting on option agreement doesn't hang the probe, then reads whatever
// banner/login-prompt text it sends.
//
// Unlike FTP, telnet has no standard success/failure reply code for a login
// attempt: this is a best-effort heuristic (looking for common failure
// phrases in the post-login text), documented as such below -- treat a
// reported "login likely ok" as a lead to confirm interactively, not a
// certainty.
package telnet

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols/auth"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "telnet",
		Group:   "PROTOCOLS",
		Summary: "Telnet banner grab + best-effort credentialed login check (Phase 1 of the internal-pentest protocol family)",
		Run:     Run,
	})
}

const (
	iac  = 255
	will = 251
	wont = 252
	do   = 253
	dont = 254
)

// Result is one target's telnet probe outcome.
type Result struct {
	Target         string `json:"target"`
	Port           int    `json:"port"`
	Banner         string `json:"banner,omitempty"`
	LoginAttempted string `json:"login_attempted,omitempty"`
	LoginLikelyOK  bool   `json:"login_likely_ok"`
	Err            string `json:"error,omitempty"`
}

// Record reduces r to the generic shape the results database stores.
func (r Result) Record() store.Record {
	d := map[string]any{}
	if r.Banner != "" {
		d["banner"] = r.Banner
	}
	if r.LoginAttempted != "" {
		d["login_attempted"] = r.LoginAttempted
		d["login_likely_ok"] = r.LoginLikelyOK
	}
	if r.Err != "" {
		d["error"] = r.Err
	}
	key := fmt.Sprintf("%s:%d", r.Target, r.Port)
	return store.Record{Kind: "telnet", Key: key, Host: r.Target, Port: r.Port, Data: d}
}

// failurePhrases are checked case-insensitively against text received after
// a login attempt; any match means the login is reported as failed. Their
// absence is not proof of success -- see the package doc.
var failurePhrases = []string{
	"login incorrect", "authentication failed", "access denied",
	"invalid", "permission denied", "incorrect",
}

// readFiltered reads from r for up to deadline, stripping telnet IAC
// sequences and answering every option negotiation with a refusal (WONT/
// DONT), so a server waiting on agreement doesn't block the read.
func readFiltered(nc net.Conn, r *bufio.Reader, deadline time.Time) (string, error) {
	nc.SetReadDeadline(deadline)
	var out strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			i := 0
			for i < n {
				if buf[i] == iac && i+2 < n {
					cmd, opt := buf[i+1], buf[i+2]
					if cmd == do || cmd == will {
						reply := []byte{iac, wont, opt}
						if cmd == do {
							reply[1] = wont
						} else {
							reply[1] = dont
						}
						nc.Write(reply)
					}
					i += 3
					continue
				}
				if buf[i] >= 32 && buf[i] < 127 || buf[i] == '\n' || buf[i] == '\r' {
					out.WriteByte(buf[i])
				}
				i++
			}
		}
		if err != nil {
			// Timeout here just means "no more data arrived" -- the normal
			// way this ends, since telnet has no reply framing to wait for.
			return strings.TrimSpace(out.String()), nil
		}
	}
}

// One probes a single target. With no credentials, it only captures the
// banner/login prompt. With -u/-p, it also attempts that login and reports
// the heuristic result above.
func One(ctx context.Context, target string, creds auth.Creds, opts auth.Options) Result {
	port := opts.Port
	if port == 0 {
		port = 23
	}
	res := Result{Target: target, Port: port}

	d := net.Dialer{Timeout: opts.Timeout}
	nc, err := d.DialContext(ctx, "tcp", net.JoinHostPort(target, strconv.Itoa(port)))
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer nc.Close()
	r := bufio.NewReader(nc)

	settle := 2 * time.Second
	if settle > opts.Timeout {
		settle = opts.Timeout
	}
	banner, err := readFiltered(nc, r, time.Now().Add(settle))
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.Banner = banner

	if creds.Anonymous() {
		return res
	}
	res.LoginAttempted = creds.User

	deadline := time.Now().Add(opts.Timeout)
	nc.SetWriteDeadline(deadline)
	if _, err := nc.Write([]byte(creds.User + "\r\n")); err != nil {
		res.Err = err.Error()
		return res
	}
	readFiltered(nc, r, time.Now().Add(settle)) // discard the "Password:" prompt echo

	nc.SetWriteDeadline(deadline)
	if _, err := nc.Write([]byte(creds.Password + "\r\n")); err != nil {
		res.Err = err.Error()
		return res
	}
	after, err := readFiltered(nc, r, deadline)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	lower := strings.ToLower(after)
	res.LoginLikelyOK = true
	for _, phrase := range failurePhrases {
		if strings.Contains(lower, phrase) {
			res.LoginLikelyOK = false
			break
		}
	}
	return res
}

// Run implements the telnet command: see internal/protocols/auth for the
// shared global flags (-u/-p/-H/-d/--port/--timeout/-M/-o) every protocol
// command binds the same way. -H/-d/--local-auth/-k are accepted for
// schema consistency but unused here -- telnet has no NTLM/Kerberos auth.
func Run(args []string) error {
	fs := flag.NewFlagSet("telnet", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "AUTH", Names: []string{"u", "p"}},
			{Title: "CONNECTION", Names: []string{"port", "timeout"}},
			{Title: "MODULES", Names: []string{"M", "o"}},
			{Title: "PERFORMANCE", Names: []string{"c"}},
			{Title: "OUTPUT", Names: []string{"out", "json", "color"}},
		})
	}
	in := fs.String("l", "", "target list: hosts (default: stdin, else the project db's port records -- see -from)")
	fb := store.BindInputFallback(fs, "telnet", "port")
	af := auth.Bind(fs, 23)
	conc := fs.Int("c", 20, "concurrent connections")
	out := fs.String("out", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of a table")
	colorFlag := fs.String("color", "auto", "color the table output: auto|always|never (ignored with -json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
	creds, opts := af.Resolve()

	targets, _, err := fb.Resolve(*in, fs.Args())
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return ioutil.ErrMissing("no targets: pass -l <file>, pipe hosts on stdin, or save some into the project db first (see `srt results`)")
	}
	defer ioutil.StartHeartbeat("telnet")()

	results := make([]Result, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *conc))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = One(ctx, target, creds, opts)
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

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tLOGIN\tRESULT\tBANNER/ERROR")
	for _, r := range results {
		target := fmt.Sprintf("%s:%d", r.Target, r.Port)
		if r.Err != "" {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", target, r.LoginAttempted, cm.Wrap(colorout.Red, "ERROR"), r.Err)
			continue
		}
		result, color := "-", ""
		if r.LoginAttempted != "" {
			result, color = "fail?", colorout.Yellow
			if r.LoginLikelyOK {
				result, color = "likely OK", colorout.Green
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", target, r.LoginAttempted, cm.Wrap(color, result), firstLine(r.Banner))
	}
	return tw.Flush()
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

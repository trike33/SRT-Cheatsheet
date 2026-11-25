// Package ftp implements the ftp command: Phase 1 of SRT's internal-pentest
// protocol family (see docs/internal-pentest-feasibility). FTP's control
// channel is a simple line-oriented text protocol, so this is a direct
// net.Dial client -- no library needed, matching the design doc's call that
// FTP/Telnet need none.
//
// Default behavior (no -u/-p/-H given): attempt anonymous login and report
// whether it succeeds. With -u/-p: attempt that login instead. Either way,
// grab the banner and SYST response as recon detail.
package ftp

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
		Name:    "ftp",
		Group:   "PROTOCOLS",
		Summary: "FTP anonymous/credentialed login check (Phase 1 of the internal-pentest protocol family)",
		Run:     Run,
	})
}

// Result is one target's FTP probe outcome.
type Result struct {
	Target         string `json:"target"`
	Port           int    `json:"port"`
	Banner         string `json:"banner,omitempty"`
	System         string `json:"system,omitempty"`
	LoginAttempted string `json:"login_attempted,omitempty"` // "anonymous" or the given username
	LoginOK        bool   `json:"login_ok"`
	Err            string `json:"error,omitempty"`
}

// Record reduces r to the generic shape the results database stores.
func (r Result) Record() store.Record {
	d := map[string]any{}
	if r.Banner != "" {
		d["banner"] = r.Banner
	}
	if r.System != "" {
		d["system"] = r.System
	}
	if r.LoginAttempted != "" {
		d["login_attempted"] = r.LoginAttempted
		d["login_ok"] = r.LoginOK
	}
	if r.Err != "" {
		d["error"] = r.Err
	}
	key := fmt.Sprintf("%s:%d", r.Target, r.Port)
	return store.Record{Kind: "ftp", Key: key, Host: r.Target, Port: r.Port, Data: d}
}

// conn wraps the control-channel socket with line read/write helpers; FTP
// replies are "CODE text\r\n", possibly multi-line ("CODE-text\r\n" ... until
// a final "CODE text\r\n" with a space). It holds a net.Conn, not a
// *net.TCPConn, so tests can drive it over net.Pipe without a real socket.
type conn struct {
	nc net.Conn
	r  *bufio.Reader
}

func dial(ctx context.Context, host string, port int, timeout time.Duration) (*conn, error) {
	d := net.Dialer{Timeout: timeout}
	nc, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	return &conn{nc: nc, r: bufio.NewReader(nc)}, nil
}

func (c *conn) readReply(deadline time.Time) (code int, text string, err error) {
	c.nc.SetReadDeadline(deadline)
	var lastLine string
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return 0, lastLine, err
		}
		line = strings.TrimRight(line, "\r\n")
		lastLine = line
		if len(line) < 4 {
			continue
		}
		code, cerr := strconv.Atoi(line[:3])
		if cerr != nil {
			continue
		}
		if line[3] == ' ' { // final line of a (possibly multi-line) reply
			return code, line[4:], nil
		}
		// line[3] == '-': continuation, keep reading
	}
}

func (c *conn) send(deadline time.Time, cmd string) error {
	c.nc.SetWriteDeadline(deadline)
	_, err := c.nc.Write([]byte(cmd + "\r\n"))
	return err
}

// One probes a single target. ctx bounds the whole exchange; opts.Timeout is
// also used per read/write as a floor.
func One(ctx context.Context, target string, creds auth.Creds, opts auth.Options) Result {
	port := opts.Port
	if port == 0 {
		port = 21
	}
	res := Result{Target: target, Port: port}

	c, err := dial(ctx, target, port, opts.Timeout)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer c.nc.Close()

	deadline := time.Now().Add(opts.Timeout)
	if _, banner, err := c.readReply(deadline); err == nil {
		res.Banner = banner
	} else {
		res.Err = fmt.Sprintf("reading banner: %v", err)
		return res
	}

	user, pass := "anonymous", "anonymous@srt-cheatsheet.local"
	res.LoginAttempted = "anonymous"
	if !creds.Anonymous() {
		user, pass = creds.User, creds.Password
		res.LoginAttempted = user
	}

	if err := c.send(deadline, "USER "+user); err != nil {
		res.Err = err.Error()
		return res
	}
	code, _, err := c.readReply(deadline)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	if code == 331 { // need password
		if err := c.send(deadline, "PASS "+pass); err != nil {
			res.Err = err.Error()
			return res
		}
		code, _, err = c.readReply(deadline)
		if err != nil {
			res.Err = err.Error()
			return res
		}
	}
	res.LoginOK = code == 230

	if res.LoginOK {
		if err := c.send(deadline, "SYST"); err == nil {
			if _, sys, err := c.readReply(deadline); err == nil {
				res.System = sys
			}
		}
	}
	c.send(deadline, "QUIT")
	return res
}

// Run implements the ftp command: see internal/protocols/auth for the
// shared global flags (-u/-p/-H/-d/--port/--timeout/-M/-o) every protocol
// command binds the same way.
func Run(args []string) error {
	fs := flag.NewFlagSet("ftp", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l", "from", "where"}},
			{Title: "AUTH", Names: []string{"u", "p", "H", "d", "local-auth", "k"}},
			{Title: "CONNECTION", Names: []string{"port", "timeout"}},
			{Title: "MODULES", Names: []string{"M", "o"}},
			{Title: "PERFORMANCE", Names: []string{"c"}},
			{Title: "OUTPUT", Names: []string{"out", "json", "color"}},
		})
	}
	in := fs.String("l", "", "target list: hosts (default: stdin, else the project db's port records -- see -from)")
	fb := store.BindInputFallback(fs, "ftp", "port")
	af := auth.Bind(fs, 21)
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
	defer ioutil.StartHeartbeat("ftp")()

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
	fmt.Fprintln(tw, "TARGET\tLOGIN\tRESULT\tSYSTEM/ERROR")
	for _, r := range results {
		target := fmt.Sprintf("%s:%d", r.Target, r.Port)
		if r.Err != "" {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", target, r.LoginAttempted, cm.Wrap(colorout.Red, "ERROR"), r.Err)
			continue
		}
		result, color := "fail", colorout.Red
		if r.LoginOK {
			result, color = "OK", colorout.Green
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", target, r.LoginAttempted, cm.Wrap(color, result), r.System)
	}
	return tw.Flush()
}

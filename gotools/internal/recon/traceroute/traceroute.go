// Package traceroute implements the traceroute command: a native ICMPv4
// route tracer. pipeline calls Run and CheckRawICMPAvailable directly for
// excluded-but-tracked hosts.
package traceroute

import (
	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "traceroute",
		Group:   "host",
		Summary: "Native ICMP route trace to each target (best-effort; needs CAP_NET_RAW/root for the raw socket)",
		Run:     Run,
	})
}

// tracerouteHop is one TTL step of a trace: either a router that answered
// (Addr set) or an unanswered probe (Timeout set).
type tracerouteHop struct {
	TTL     int    `json:"ttl"`
	Addr    string `json:"addr,omitempty"`
	RTTMs   int64  `json:"rttMs,omitempty"`
	Timeout bool   `json:"timeout,omitempty"`
}

type tracerouteResult struct {
	Target  string          `json:"target"`
	Addr    string          `json:"addr,omitempty"`
	Reached bool            `json:"reached"`
	Hops    []tracerouteHop `json:"hops,omitempty"`
	Err     string          `json:"error,omitempty"`
}

func Run(args []string) error {
	fs := flag.NewFlagSet("traceroute", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l"}},
			{Title: "OPTIONS", Names: []string{"max-hops", "timeout"}},
			{Title: "OUTPUT", Names: []string{"o", "json"}},
		})
	}
	in := fs.String("l", "", "target list: hosts or IPs (default: stdin)")
	maxHops := fs.Int("max-hops", 30, "maximum TTL to probe")
	timeout := fs.Duration("timeout", time.Second, "per-hop wait for a response")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of a plain per-hop listing")
	if err := fs.Parse(args); err != nil {
		return err
	}

	targets, err := ioutil.InputLines(ioutil.ResolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return ioutil.ErrMissing("no targets: pass -l <file> or pipe hosts/IPs on stdin")
	}
	if *maxHops < 1 {
		return ioutil.ErrMissing("-max-hops must be at least 1")
	}

	// Checked once, up front: every target would fail the exact same way
	// without a raw socket, so one clear error beats repeating it per target
	// (and matches the "skip cleanly, don't abort the run" shape `pipeline`
	// already uses for an optional capability like vulnx).
	if err := CheckRawICMPAvailable(); err != nil {
		return fmt.Errorf("traceroute needs a raw ICMP socket (CAP_NET_RAW, or root): %w", err)
	}

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	defer ioutil.StartHeartbeat("traceroute")()

	id := uint16(os.Getpid())
	var seq uint16
	for _, t := range targets {
		res := traceHost(t, *maxHops, *timeout, id, &seq)
		store.CurrentSink().Add(res.record())
		if *jsonOut {
			b, _ := json.Marshal(res)
			fmt.Fprintln(w, string(b))
		} else {
			printTraceroutePlain(w, res)
		}
	}
	return nil
}

func printTraceroutePlain(w io.Writer, res tracerouteResult) {
	if res.Err != "" {
		fmt.Fprintf(w, "traceroute %s: %s\n", res.Target, res.Err)
		return
	}
	fmt.Fprintf(w, "traceroute %s (%s), %d hop(s) max\n", res.Target, res.Addr, len(res.Hops))
	for _, h := range res.Hops {
		if h.Timeout {
			fmt.Fprintf(w, " %2d  *\n", h.TTL)
			continue
		}
		fmt.Fprintf(w, " %2d  %s  %dms\n", h.TTL, h.Addr, h.RTTMs)
	}
	if !res.Reached {
		fmt.Fprintln(w, " (destination not reached within -max-hops)")
	}
}

// resolveToIP4 resolves target to an IPv4 address; traceroute is IPv4-only
// for now (see ROADMAP.md -- IPv6 needs its own ICMPv6 message types).
func resolveToIP4(target string) (net.IP, error) {
	if ip := net.ParseIP(target); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
		return nil, fmt.Errorf("%s is not an IPv4 address (traceroute is IPv4-only for now)", target)
	}
	netx.Request()
	addrs, err := net.LookupIP(target)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if ip4 := a.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("%s has no IPv4 address", target)
}

// tracerouteRecord stores a trace as one "route" record per target, the hop
// list folded into its data (there's no natural one-row-per-hop key, and the
// whole path is what's useful to query/export together).
// record reduces a trace to the generic shape the results database stores.
func (res tracerouteResult) record() store.Record {
	if res.Err != "" {
		return store.Record{} // empty Key -> Sink.Add is a no-op; nothing useful to persist
	}
	data := map[string]any{"reached": res.Reached, "hops": res.Hops}
	if res.Addr != "" {
		data["addr"] = res.Addr
	}
	return store.Record{Kind: "route", Key: res.Target, Host: res.Target, Data: data}
}

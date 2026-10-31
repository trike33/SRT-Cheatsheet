package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func init() {
	register(&command{
		name:    "portscan",
		group:   "HOST recon",
		summary: "Native concurrent TCP connect port scanner (common/uncommon/all/custom ports)",
		run:     runPortscan,
	})
}

// commonPorts are the ordinary, frequently-exposed services a quick scan
// should always check: web, mail, DNS, databases, remote admin, and the
// usual cloud/container-platform ports.
var commonPorts = []int{
	21, 22, 23, 25, 53, 67, 68, 80, 81, 88, 110, 111, 119, 123, 135, 137, 138,
	139, 143, 161, 162, 179, 194, 389, 443, 444, 445, 464, 465, 500, 514, 515,
	520, 523, 540, 548, 554, 587, 593, 631, 636, 646, 691, 860, 902, 989, 990,
	993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1194, 1433, 1434, 1521,
	1701, 1723, 1755, 1812, 1813, 1900, 2000, 2049, 2082, 2083, 2086, 2087,
	2095, 2096, 2181, 3000, 3128, 3260, 3268, 3269, 3306, 3389, 3478, 3690,
	4000, 4443, 4444, 4567, 4848, 5000, 5001, 5060, 5061, 5222, 5223, 5432,
	5555, 5601, 5672, 5900, 5984, 5985, 5986, 6000, 6379, 6443, 6660, 6667,
	6881, 7000, 7001, 7077, 7199, 7396, 7474, 7547, 8000, 8008, 8009, 8080,
	8081, 8086, 8088, 8090, 8091, 8181, 8200, 8291, 8333, 8443, 8500, 8834,
	8880, 8888, 8983, 9000, 9001, 9042, 9043, 9090, 9091, 9092, 9100, 9160,
	9200, 9300, 9418, 9999, 10000, 10250, 11211, 15672, 20000, 27017, 27018,
	28017, 32400, 50000, 50070,
}

// uncommonPorts are specialty/legacy services worth flagging for manual
// follow-up rather than routine automated checks — rsync and Java RMI are
// the two examples called out explicitly in docs/methodology.md. BeanShell
// (also mentioned there) has no fixed/IANA-assigned port, so it isn't
// listed here; it needs banner-based detection instead (see ROADMAP.md).
var uncommonPorts = []int{
	79, 512, 513, 873, 1098, 1099, 2375, 2376, 3310, 4505, 4506, 6001, 7777,
	10809, 44818, 47808, 50050, 61616,
}

// webPorts are the open ports that count as a web service for the HOST
// stage's "hand off to WEB" split (docs/methodology.md). httpsPorts is the
// subset of those that speak TLS, used to pick the right scheme.
var webPorts = map[int]bool{
	80: true, 443: true, 3000: true, 4443: true, 5000: true, 5601: true,
	7001: true, 8000: true, 8008: true, 8009: true, 8080: true, 8081: true,
	8088: true, 8090: true, 8091: true, 8181: true, 8333: true, 8443: true,
	8500: true, 8834: true, 8888: true, 8983: true, 9000: true, 9043: true,
	9090: true,
}

var httpsPorts = map[int]bool{
	443: true, 4443: true, 8443: true, 8834: true, 9043: true,
}

func isWebPort(port int) bool { return webPorts[port] }

// uncommonPortSet is uncommonPorts as a set, for O(1) flagging lookups.
var uncommonPortSet = func() map[int]bool {
	m := make(map[int]bool, len(uncommonPorts))
	for _, p := range uncommonPorts {
		m[p] = true
	}
	return m
}()

func isUncommonPort(port int) bool { return uncommonPortSet[port] }

// webBaseURL builds the base URL a web-classified open port hands off to
// the WEB stage, omitting the port when it's the scheme's default.
func webBaseURL(host string, port int) string {
	scheme := "http"
	if httpsPorts[port] {
		scheme = "https"
	}
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return scheme + "://" + host
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

type scanResult struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Banner string `json:"banner,omitempty"`
}

func statePrior(s *scanState) []scanResult {
	if s == nil {
		return nil
	}
	return s.Prior
}

func runPortscan(args []string) error {
	fs := flag.NewFlagSet("portscan", flag.ExitOnError)
	in := fs.String("l", "", "input IP/host list (default: stdin)")
	portsFlag := fs.String("p", "common", `ports: "common", "uncommon", "all", or explicit e.g. "80,443,8000-9000" (comma-combinable, e.g. "common,uncommon")`)
	conc := fs.Int("c", 200, "concurrent connection attempts")
	timeout := fs.Duration("timeout", time.Second, "per-port connect timeout")
	banner := fs.Bool("banner", true, "best-effort read of a service's greeting banner on connect")
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of \"host:port [banner]\"")
	resume := fs.String("resume", "", "state file: persist progress so an interrupted scan (Ctrl+C, crash) continues where it stopped when re-run with the same hosts/ports")
	if err := fs.Parse(args); err != nil {
		return err
	}

	hosts, err := inputLines(resolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return errMissing("no hosts: pass -l <file> or pipe hosts on stdin")
	}

	ports, err := resolvePorts(*portsFlag)
	if err != nil {
		return err
	}

	w, err := output(*out)
	if err != nil {
		return err
	}
	defer w.Close()

	total := int64(len(hosts)) * int64(len(ports))
	var scanned, open int64

	var state *scanState
	if *resume != "" {
		state, err = openScanState(*resume, hosts, ports)
		if err != nil {
			return err
		}
		stopCP := state.startCheckpointing(500 * time.Millisecond)
		cancelHook := onHalt(func() { state.Checkpoint(); state.Close() })
		defer func() { cancelHook(); stopCP(); state.Close() }()
		if len(state.Prior) > 0 || state.mark > 0 {
			warn("resuming: %d/%d probes already done, %d open port(s) recovered", state.mark, total, len(state.Prior))
		}
		open = int64(len(state.Prior))
		scanned = state.mark
	}

	stopProg := make(chan struct{})
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopProg:
				return
			case <-t.C:
				warn("scanned %d/%d, %d open", atomic.LoadInt64(&scanned), total, atomic.LoadInt64(&open))
			}
		}
	}()

	results := make(chan scanResult, 256+len(statePrior(state)))
	priorOpen := map[string]bool{}
	for _, r := range statePrior(state) {
		priorOpen[fmt.Sprintf("%s:%d", r.Host, r.Port)] = true
		results <- r
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *conc))
	go func() {
		var idx int64 = -1
		for _, host := range hosts {
			for _, port := range ports {
				idx++
				if state != nil && state.Skip(idx) {
					continue
				}
				wg.Add(1)
				sem <- struct{}{}
				go func(host string, port int, idx int64) {
					defer wg.Done()
					defer func() { <-sem }()
					res, ok := probePort(host, port, *timeout, *banner)
					atomic.AddInt64(&scanned, 1)
					// An open port found just past the watermark last run is
					// re-found now; it's already in the output, so don't repeat it.
					if ok && !priorOpen[fmt.Sprintf("%s:%d", host, port)] {
						atomic.AddInt64(&open, 1)
						if state != nil {
							state.Open(res)
						}
						results <- res
					}
					if state != nil {
						state.Done(idx)
					}
				}(host, port, idx)
			}
		}
		wg.Wait()
		close(results)
	}()

	var outMu sync.Mutex
	for r := range results {
		sink.add(portRecord(r))
		outMu.Lock()
		if *jsonOut {
			b, _ := json.Marshal(r)
			fmt.Fprintln(w, string(b))
		} else if r.Banner != "" {
			fmt.Fprintf(w, "%s:%d [%s]\n", r.Host, r.Port, r.Banner)
		} else {
			fmt.Fprintf(w, "%s:%d\n", r.Host, r.Port)
		}
		outMu.Unlock()
	}

	close(stopProg)
	warn("done: %d open port(s) across %d host(s), %d port(s) each", open, len(hosts), len(ports))
	return nil
}

// probePort attempts a TCP connect to host:port, and — if grabBanner is set
// — a short, best-effort read of whatever the service sends unprompted
// (SSH/FTP/SMTP-style greetings; services that speak only on request, like
// plain HTTP, will just time out with no banner, which is fine).
func probePort(host string, port int, timeout time.Duration, grabBanner bool) (scanResult, bool) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	meter.request()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return scanResult{}, false
	}
	defer conn.Close()
	conn = countingConn{conn}

	res := scanResult{Host: host, Port: port}
	if grabBanner {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 256)
		if n, _ := conn.Read(buf); n > 0 {
			res.Banner = sanitizeBanner(buf[:n])
		}
	}
	return res, true
}

// sanitizeBanner collapses a raw banner read into a clean single line.
func sanitizeBanner(b []byte) string {
	s := strings.Map(func(r rune) rune {
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1 // drop other control bytes
		default:
			return r
		}
	}, string(b))
	s = strings.Join(strings.Fields(s), " ") // collapse whitespace runs
	const maxLen = 120
	if len(s) > maxLen {
		s = s[:maxLen] + "..."
	}
	return s
}

// resolvePorts expands a -p spec into a sorted, deduped port list. The spec
// is a comma-separated mix of the named presets "common"/"uncommon"/"all"
// and explicit numbers/ranges (reusing fuzz's rangeSet parser), e.g.
// "common,uncommon" or "common,8000-8100".
func resolvePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		spec = "common"
	}

	seen := map[int]struct{}{}
	var ports []int
	add := func(ns []int) {
		for _, n := range ns {
			if _, dup := seen[n]; !dup {
				seen[n] = struct{}{}
				ports = append(ports, n)
			}
		}
	}

	var numeric []string
	for _, tok := range strings.Split(spec, ",") {
		switch tok = strings.TrimSpace(tok); tok {
		case "":
		case "common":
			add(commonPorts)
		case "uncommon":
			add(uncommonPorts)
		default:
			numeric = append(numeric, tok)
		}
	}

	if len(numeric) > 0 {
		rs, err := parseRangeSet(strings.Join(numeric, ","))
		if err != nil {
			return nil, fmt.Errorf("-p: %w", err)
		}
		for n := 1; n <= 65535; n++ {
			if rs.contains(n) {
				add([]int{n})
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("-p: no ports resolved from %q", spec)
	}
	sort.Ints(ports)
	return ports, nil
}

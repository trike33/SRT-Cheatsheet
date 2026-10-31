// Package ipexpand implements the ipexpand and ipports commands: expanding
// a scope file's CIDRs/IPs into a flat IP list, and appending ports to each
// IP for httpx-style input.
package ipexpand

import (
	"bytes"
	"flag"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "ipexpand",
		Group:   "HOST recon",
		Summary: "Expand CIDRs + IPs from a scope file into a unique, sorted IP list (ipparser.py)",
		Run:     Run,
	})
	cli.Register(&cli.Command{
		Name:    "ipports",
		Group:   "HOST recon",
		Summary: "Append ports to each IP, one host:port per line, for httpx (format-ips.py)",
		Run:     RunPorts,
	})
}

// Run ports HOST/ipparser.py: read a scope file of IPs/CIDRs and emit a
// de-duplicated, numerically sorted list of individual IP addresses.
func Run(args []string) error {
	fs := flag.NewFlagSet("ipexpand", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l"}},
			{Title: "OUTPUT", Names: []string{"o"}},
		})
	}
	in := fs.String("l", "", "input scope file (default: stdin)")
	out := fs.String("o", "", "output file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer ioutil.StartHeartbeat("ipexpand")()

	lines, err := ioutil.InputLines(ioutil.ResolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}

	seen := map[string]net.IP{}
	for _, entry := range lines {
		if strings.Contains(entry, "/") {
			_, ipnet, err := net.ParseCIDR(entry)
			if err != nil {
				ioutil.Warn("skipping invalid entry: %s", entry)
				continue
			}
			for ip := cloneIP(ipnet.IP.Mask(ipnet.Mask)); ipnet.Contains(ip); incIP(ip) {
				seen[ip.String()] = cloneIP(ip)
			}
		} else {
			ip := net.ParseIP(entry)
			if ip == nil {
				ioutil.Warn("skipping invalid entry: %s", entry)
				continue
			}
			seen[ip.String()] = ip
		}
	}

	ips := make([]net.IP, 0, len(seen))
	for _, ip := range seen {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return bytes.Compare(ips[i].To16(), ips[j].To16()) < 0 })

	strs := make([]string, len(ips))
	for i, ip := range ips {
		strs[i] = ip.String()
	}

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	if err := ioutil.WriteLines(w, strs); err != nil {
		return err
	}
	ioutil.Warn("expanded to %d unique IP(s)", len(strs))
	return nil
}

// RunPorts ports HOST/format-ips.py: append ports (default 8080,8443) to each
// IP so the output feeds straight into `httpx -l -`.
func RunPorts(args []string) error {
	fs := flag.NewFlagSet("ipports", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l"}},
			{Title: "OPTIONS", Names: []string{"ports"}},
			{Title: "OUTPUT", Names: []string{"o"}},
		})
	}
	in := fs.String("l", "", "input IP file (default: stdin)")
	out := fs.String("o", "", "output file (default: stdout)")
	portsFlag := fs.String("ports", "8080,8443", "comma-separated ports to append")
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer ioutil.StartHeartbeat("ipports")()

	var ports []string
	for _, p := range strings.Split(*portsFlag, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := strconv.Atoi(p); err != nil {
			ioutil.Warn("skipping invalid port: %s", p)
			continue
		}
		ports = append(ports, p)
	}

	lines, err := ioutil.InputLines(ioutil.ResolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}

	var result []string
	for _, ip := range lines {
		for _, p := range ports {
			result = append(result, ip+":"+p)
		}
	}

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	return ioutil.WriteLines(w, result)
}

// incIP increments an IP address in place (big-endian add 1).
func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

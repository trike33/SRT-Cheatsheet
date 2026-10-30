package main

import (
	"bytes"
	"flag"
	"net"
	"sort"
	"strconv"
	"strings"
)

func init() {
	register(&command{
		name:    "ipexpand",
		group:   "HOST recon",
		summary: "Expand CIDRs + IPs from a scope file into a unique, sorted IP list (ipparser.py)",
		run:     runIPExpand,
	})
	register(&command{
		name:    "ipports",
		group:   "HOST recon",
		summary: "Append ports to each IP, one host:port per line, for httpx (format-ips.py)",
		run:     runIPPorts,
	})
}

// runIPExpand ports HOST/ipparser.py: read a scope file of IPs/CIDRs and emit a
// de-duplicated, numerically sorted list of individual IP addresses.
func runIPExpand(args []string) error {
	fs := flag.NewFlagSet("ipexpand", flag.ExitOnError)
	in := fs.String("l", "", "input scope file (default: stdin)")
	out := fs.String("o", "", "output file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer startHeartbeat("ipexpand")()

	lines, err := inputLines(resolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}

	seen := map[string]net.IP{}
	for _, entry := range lines {
		if strings.Contains(entry, "/") {
			_, ipnet, err := net.ParseCIDR(entry)
			if err != nil {
				warn("skipping invalid entry: %s", entry)
				continue
			}
			for ip := cloneIP(ipnet.IP.Mask(ipnet.Mask)); ipnet.Contains(ip); incIP(ip) {
				seen[ip.String()] = cloneIP(ip)
			}
		} else {
			ip := net.ParseIP(entry)
			if ip == nil {
				warn("skipping invalid entry: %s", entry)
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

	w, err := output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	if err := writeLines(w, strs); err != nil {
		return err
	}
	warn("expanded to %d unique IP(s)", len(strs))
	return nil
}

// runIPPorts ports HOST/format-ips.py: append ports (default 8080,8443) to each
// IP so the output feeds straight into `httpx -l -`.
func runIPPorts(args []string) error {
	fs := flag.NewFlagSet("ipports", flag.ExitOnError)
	in := fs.String("l", "", "input IP file (default: stdin)")
	out := fs.String("o", "", "output file (default: stdout)")
	portsFlag := fs.String("ports", "8080,8443", "comma-separated ports to append")
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer startHeartbeat("ipports")()

	var ports []string
	for _, p := range strings.Split(*portsFlag, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := strconv.Atoi(p); err != nil {
			warn("skipping invalid port: %s", p)
			continue
		}
		ports = append(ports, p)
	}

	lines, err := inputLines(resolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}

	var result []string
	for _, ip := range lines {
		for _, p := range ports {
			result = append(result, ip+":"+p)
		}
	}

	w, err := output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	return writeLines(w, result)
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

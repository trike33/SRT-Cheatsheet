// Package scope is every shape of "is this in scope" srt uses: a plain
// IP/CIDR list (ScopeSet, for `domains -scopecheck`), a Burp scope export's
// own include/exclude regexes (ScopeMatcher, for `fuzz -scope`, pipeline's
// web scope gating, and this package's own burphosts/burpscope commands),
// and auto-detecting the conventional scope files a project directory tends
// to have (DetectScopeFiles, for `pipeline` and the shell's `cd`).
package scope

import (
	"net"
	"strings"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

// Set holds a parsed scope: individual IPs plus CIDR networks. Membership is
// tested with Contains instead of expanding every CIDR into a set, so a /8
// in scope costs nothing.
type Set struct {
	ips  map[string]struct{}
	nets []*net.IPNet
}

// Contains reports whether ip is in the scope.
func (s *Set) Contains(ip net.IP) bool {
	if _, ok := s.ips[ip.String()]; ok {
		return true
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Load reads a file of IPs and/or CIDRs into a Set.
func Load(path string) (*Set, error) {
	lines, err := ioutil.InputLines(path)
	if err != nil {
		return nil, err
	}
	s := &Set{ips: map[string]struct{}{}}
	for _, entry := range lines {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, n, err := net.ParseCIDR(entry)
			if err != nil {
				ioutil.Warn("skipping invalid scope entry: %s", entry)
				continue
			}
			s.nets = append(s.nets, n)
		} else {
			ip := net.ParseIP(entry)
			if ip == nil {
				ioutil.Warn("skipping invalid scope entry: %s", entry)
				continue
			}
			s.ips[ip.String()] = struct{}{}
		}
	}
	return s, nil
}

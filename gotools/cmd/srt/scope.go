package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// errMissing is a small helper for required-flag errors.
func errMissing(msg string) error { return errors.New(msg) }

// contextTimeout is a thin wrapper so command code stays terse.
func contextTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// scopeSet holds a parsed scope: individual IPs plus CIDR networks. Membership
// is tested with Contains instead of expanding every CIDR into a set, so a /8
// in scope costs nothing.
type scopeSet struct {
	ips  map[string]struct{}
	nets []*net.IPNet
}

func (s *scopeSet) contains(ip net.IP) bool {
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

// loadScope reads a file of IPs and/or CIDRs into a scopeSet.
func loadScope(path string) (*scopeSet, error) {
	lines, err := inputLines(path)
	if err != nil {
		return nil, err
	}
	s := &scopeSet{ips: map[string]struct{}{}}
	for _, entry := range lines {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, n, err := net.ParseCIDR(entry)
			if err != nil {
				warn("skipping invalid scope entry: %s", entry)
				continue
			}
			s.nets = append(s.nets, n)
		} else {
			ip := net.ParseIP(entry)
			if ip == nil {
				warn("skipping invalid scope entry: %s", entry)
				continue
			}
			s.ips[ip.String()] = struct{}{}
		}
	}
	return s, nil
}

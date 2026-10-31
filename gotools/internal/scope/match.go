package scope

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

// Matcher evaluates whether a URL is in scope using Burp's OWN regexes. The
// `host` and `file` fields of a Burp scope export are already regular
// expressions (e.g. "^.+\\.servicing\\.loandepot\\.com$", "^/branches/.*$"),
// so they're compiled verbatim. That is what gives the fuzzer "extreme
// precision" over what it is allowed to touch: it defers to the exact scope
// definition the tester configured in Burp, include AND exclude.
type Matcher struct {
	include []rule
	exclude []rule
}

type rule struct {
	proto   string // "any", "http", or "https"
	rawHost string // the original host regex, for host extraction
	host    *regexp.Regexp
	file    *regexp.Regexp
}

func compileRule(e burpEntry, proto string) (rule, error) {
	hostRe, err := regexp.Compile(e.Host)
	if err != nil {
		return rule{}, fmt.Errorf("host regex %q: %w", e.Host, err)
	}
	fileExpr := e.File
	if fileExpr == "" {
		fileExpr = "^/.*$" // Burp treats an empty file as "any path"
	}
	fileRe, err := regexp.Compile(fileExpr)
	if err != nil {
		return rule{}, fmt.Errorf("file regex %q: %w", e.File, err)
	}
	if proto == "" {
		proto = "any"
	}
	return rule{proto: proto, rawHost: e.Host, host: hostRe, file: fileRe}, nil
}

// LoadScopeMatcher reads a Burp scope JSON file into a Matcher.
func LoadScopeMatcher(path string) (*Matcher, error) {
	bs, err := LoadBurpScope(path)
	if err != nil {
		return nil, err
	}
	m := &Matcher{}
	for _, e := range bs.Target.Scope.Include {
		if !e.Enabled {
			continue
		}
		r, err := compileRule(e, e.Protocol)
		if err != nil {
			ioutil.Warn("skipping include rule: %v", err)
			continue
		}
		m.include = append(m.include, r)
	}
	for _, e := range bs.Target.Scope.Exclude {
		if !e.Enabled {
			continue
		}
		r, err := compileRule(e, e.Protocol)
		if err != nil {
			ioutil.Warn("skipping exclude rule: %v", err)
			continue
		}
		m.exclude = append(m.exclude, r)
	}
	if len(m.include) == 0 {
		return nil, fmt.Errorf("scope file %q has no enabled include rules", path)
	}
	return m, nil
}

// protoMatches implements Burp's "any" wildcard for the protocol.
func protoMatches(ruleProto, scheme string) bool {
	return ruleProto == "any" || ruleProto == scheme
}

func (r rule) matches(scheme, host, path string) bool {
	return protoMatches(r.proto, scheme) && r.host.MatchString(host) && r.file.MatchString(path)
}

// InScope reports whether rawURL is allowed: it must match at least one
// include rule and no exclude rule -- exactly Burp's semantics.
func (m *Matcher) InScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	scheme := u.Scheme
	host := u.Hostname() // strips any :port, which Burp's host regex never includes
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	matchedInclude := false
	for _, r := range m.include {
		if r.matches(scheme, host, path) {
			matchedInclude = true
			break
		}
	}
	if !matchedInclude {
		return false
	}
	for _, r := range m.exclude {
		if r.matches(scheme, host, path) {
			return false
		}
	}
	return true
}

// IncludeHosts returns the concrete (non-wildcard) hostnames from the
// include rules, so the fuzzer can auto-seed targets straight from a scope
// file.
func (m *Matcher) IncludeHosts() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range m.include {
		host := stripRegexChars(r.rawHost)
		// Drop wildcard hosts like ".+.servicing.loandepot.com" -- we can't
		// resolve a wildcard, that's subfinder's job.
		if host == "" || strings.HasPrefix(host, ".+") || strings.ContainsAny(host, "+*") {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

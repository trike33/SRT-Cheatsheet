package main

import (
	"encoding/json"
	"flag"
	"regexp"
	"sort"
	"strings"
)

func init() {
	register(&command{
		name:    "burphosts",
		group:   "WEB recon",
		summary: "Burp scope JSON -> host[/dir] list for httpx/katana (domains-to-httpx.py)",
		run:     runBurpHosts,
	})
	register(&command{
		name:    "burpscope",
		group:   "WEB recon",
		summary: "Burp scope JSON -> colored include/exclude path list (domains-parser.py)",
		run:     runBurpScope,
	})
}

// burpScope models the slice of Burp's exported project/scope JSON we care about.
type burpScope struct {
	Target struct {
		Scope struct {
			Include []burpEntry `json:"include"`
			Exclude []burpEntry `json:"exclude"`
		} `json:"scope"`
	} `json:"target"`
}

type burpEntry struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	File    string `json:"file"`
}

func loadBurpScope(path string) (*burpScope, error) {
	content, err := readAll(path)
	if err != nil {
		return nil, err
	}
	var s burpScope
	if err := json.Unmarshal([]byte(content), &s); err != nil {
		return nil, err
	}
	return &s, nil
}

var multiSlashRe = regexp.MustCompile(`/{2,}`)

// stripRegexChars removes the regex escaping Burp stores in host/file fields.
func stripRegexChars(s string) string {
	s = strings.ReplaceAll(s, `\`, "")
	s = strings.ReplaceAll(s, "^", "")
	s = strings.ReplaceAll(s, "$", "")
	return s
}

// runBurpHosts ports WEB/domains-to-httpx.py: emit host+dir entries (no scheme)
// ready to pipe into httpx or katana.
func runBurpHosts(args []string) error {
	fs := flag.NewFlagSet("burphosts", flag.ExitOnError)
	in := fs.String("l", "", "Burp scope JSON file (default: stdin)")
	out := fs.String("o", "", "output file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	scope, err := loadBurpScope(resolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}

	seen := map[string]struct{}{}
	for _, item := range scope.Target.Scope.Include {
		if !item.Enabled {
			continue
		}
		host := stripRegexChars(item.Host)
		// Bug-bounty tweak over the literal Python: a wildcard host arrives as
		// ".+.example.com"; collapse it to the apex so httpx/katana can resolve
		// it (they can't take a wildcard) instead of emitting a dead ".+." host.
		host = strings.TrimPrefix(host, ".+")
		host = strings.TrimPrefix(host, ".")
		file := strings.ReplaceAll(stripRegexChars(item.File), ".*", "")
		full := strings.TrimRight(host+file, "/")
		if full != "" {
			seen[full] = struct{}{}
		}
	}

	result := make([]string, 0, len(seen))
	for s := range seen {
		result = append(result, s)
	}
	sort.Strings(result)

	w, err := output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	return writeLines(w, result)
}

// runBurpScope ports WEB/domains-parser.py: pretty, colored include (green) and
// exclude (red) path listing with wildcard-host collapsing.
func runBurpScope(args []string) error {
	fs := flag.NewFlagSet("burpscope", flag.ExitOnError)
	in := fs.String("l", "", "Burp scope JSON file (default: stdin)")
	out := fs.String("o", "", "output file (default: stdout)")
	colorFlag := fs.String("color", "auto", "color output: auto|always|never")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := parseColorMode(*colorFlag)

	scope, err := loadBurpScope(resolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}

	include := map[string][]string{}
	exclude := map[string][]string{}
	for _, item := range scope.Target.Scope.Include {
		if item.Enabled {
			host, file := cleanHostFile(item)
			include[host] = append(include[host], file)
		}
	}
	for _, item := range scope.Target.Scope.Exclude {
		if item.Enabled {
			host, file := cleanHostFile(item)
			exclude[host] = append(exclude[host], file)
		}
	}

	var lines []string
	seenPaths := map[string]struct{}{}
	wildcardDomains := map[string]struct{}{}

	add := func(domain, path, code string) {
		full := domain + normalizePath(path)
		cleaned := multiSlashRe.ReplaceAllString(full, "/")
		if _, dup := seenPaths[cleaned]; dup {
			return
		}
		seenPaths[cleaned] = struct{}{}
		lines = append(lines, cm.wrap(code, cleaned))
	}

	for _, domain := range sortedKeys(include) {
		if strings.HasPrefix(domain, "*.") {
			wildcardDomains[domainWithoutWildcard(domain)] = struct{}{}
		}
		paths := append([]string(nil), include[domain]...)
		sort.Strings(paths)
		for _, path := range paths {
			base := domainWithoutWildcard(domain)
			if _, hasWild := wildcardDomains[base]; hasWild && !strings.HasPrefix(domain, "*.") {
				continue // prefer the wildcard entry over the bare host
			}
			add(domain, path, ansiGreen)
		}
	}

	for _, domain := range sortedKeys(exclude) {
		paths := append([]string(nil), exclude[domain]...)
		sort.Strings(paths)
		for _, path := range paths {
			normEx := normalizePath(path)
			if incPaths, ok := include[domain]; ok {
				if containsNormalized(incPaths, normEx) {
					continue
				}
			}
			add(domain, path, ansiRed)
		}
	}

	w, err := output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	return writeLines(w, lines)
}

// cleanHostFile mirrors the clean_host_file() helper in domains-parser.py.
func cleanHostFile(item burpEntry) (host, file string) {
	host = stripRegexChars(item.Host)
	file = strings.ReplaceAll(stripRegexChars(item.File), ".*", "/*")
	if strings.HasPrefix(host, ".+") {
		host = "*." + host[3:]
	}
	return host, file
}

func normalizePath(path string) string {
	if !strings.HasSuffix(path, "/*") {
		return strings.TrimRight(path, "/") + "/*"
	}
	return path
}

func domainWithoutWildcard(domain string) string {
	return strings.TrimPrefix(domain, "*.")
}

func containsNormalized(paths []string, normalized string) bool {
	for _, p := range paths {
		if normalizePath(p) == normalized {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

package scope

import (
	"encoding/json"
	"flag"
	"regexp"
	"sort"
	"strings"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "burphosts",
		Group:   "WEB recon",
		Summary: "Burp scope JSON -> host[/dir] list for httpx/katana (domains-to-httpx.py)",
		Run:     runBurpHosts,
	})
	cli.Register(&cli.Command{
		Name:    "burpscope",
		Group:   "WEB recon",
		Summary: "Burp scope JSON -> colored include/exclude path list (domains-parser.py)",
		Run:     runBurpScope,
	})
}

// BurpScope models the slice of Burp's exported project/scope JSON this
// package cares about.
type BurpScope struct {
	Target struct {
		Scope struct {
			Include []burpEntry `json:"include"`
			Exclude []burpEntry `json:"exclude"`
		} `json:"scope"`
	} `json:"target"`
}

type burpEntry struct {
	Enabled  bool   `json:"enabled"`
	Protocol string `json:"protocol"` // "any", "http", or "https"
	Host     string `json:"host"`
	File     string `json:"file"`
}

// LoadBurpScope reads and parses a Burp scope JSON export.
func LoadBurpScope(path string) (*BurpScope, error) {
	content, err := ioutil.ReadAll(path)
	if err != nil {
		return nil, err
	}
	var s BurpScope
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
	defer ioutil.StartHeartbeat("burphosts")()

	scope, err := LoadBurpScope(ioutil.ResolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	return ioutil.WriteLines(w, BurpHosts(scope))
}

// BurpHosts extracts the unique host[/dir] entries (no scheme) from a Burp
// scope's enabled include rules. Shared by runBurpHosts and pipeline's
// -web-scope flag.
func BurpHosts(scope *BurpScope) []string {
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
	return result
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
	cm := colorout.ParseMode(*colorFlag)
	defer ioutil.StartHeartbeat("burpscope")()

	scope, err := LoadBurpScope(ioutil.ResolveInput(*in, fs.Args()))
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
		lines = append(lines, cm.Wrap(code, cleaned))
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
			add(domain, path, colorout.Green)
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
			add(domain, path, colorout.Red)
		}
	}

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	return ioutil.WriteLines(w, lines)
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

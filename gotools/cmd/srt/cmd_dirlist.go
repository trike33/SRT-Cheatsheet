package main

import (
	"flag"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

func init() {
	register(&command{
		name:    "dirlist",
		group:   "WEB recon",
		summary: "Recursively harvest file URLs from open directory listings (dir_listing.py)",
		run:     runDirList,
	})
}

// excludedDirListExt are the noise extensions dir_listing.py skips.
var excludedDirListExt = []string{
	".jpg", ".ttf", ".tif", ".jpeg", ".png", ".gif", ".css", ".webp",
	".svg", ".woff", ".woff2", ".jpe", ".bmp",
}

var hrefRe = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)

func runDirList(args []string) error {
	fs := flag.NewFlagSet("dirlist", flag.ExitOnError)
	in := fs.String("l", "", "file of directory-listing URLs (default: stdin)")
	out := fs.String("o", "", "output file (default: stdout)")
	timeout := fs.Duration("timeout", 15*time.Second, "per-request timeout")
	insecure := fs.Bool("insecure", true, "skip TLS verification")
	maxDepth := fs.Int("depth", 0, "max recursion depth (0 = unlimited)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	seeds, err := inputLines(resolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}

	client := newHTTPClient(*timeout, *insecure)
	visited := map[string]struct{}{}
	files := map[string]struct{}{}

	for _, seed := range seeds {
		u, err := url.Parse(seed)
		if err != nil {
			warn("bad seed URL %q: %v", seed, err)
			continue
		}
		base := u.Scheme + "://" + u.Host + "/"
		crawlDir(client, seed, base, visited, files, 1, *maxDepth)
	}

	result := make([]string, 0, len(files))
	for f := range files {
		result = append(result, f)
	}
	sort.Strings(result)

	w, err := output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	if err := writeLines(w, result); err != nil {
		return err
	}
	warn("found %d file URL(s)", len(result))
	return nil
}

// crawlDir fetches one directory URL, records in-scope files, and recurses into
// subdirectories, staying within base (same scheme+host, rooted at /).
func crawlDir(client *http.Client, dirURL, base string, visited, files map[string]struct{}, depth, maxDepth int) {
	if _, seen := visited[dirURL]; seen {
		return
	}
	visited[dirURL] = struct{}{}
	if maxDepth > 0 && depth > maxDepth {
		return
	}

	resp, err := httpGet(client, dirURL)
	if err != nil {
		warn("fetch %s: %v", dirURL, err)
		return
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(bodyBytes)

	pageURL, err := url.Parse(dirURL)
	if err != nil {
		return
	}

	for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
		href := m[1]
		if href == "" || href == "/" || strings.HasPrefix(href, "?") || strings.HasPrefix(href, "..") {
			continue
		}
		ref, err := url.Parse(href)
		if err != nil {
			continue
		}
		full := pageURL.ResolveReference(ref).String()
		if !strings.HasPrefix(full, base) {
			continue
		}
		if strings.HasSuffix(full, "/") {
			crawlDir(client, full, base, visited, files, depth+1, maxDepth)
		} else if !isExcludedExt(full) {
			files[full] = struct{}{}
		}
	}
}

func isExcludedExt(u string) bool {
	low := strings.ToLower(u)
	for _, ext := range excludedDirListExt {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	return false
}

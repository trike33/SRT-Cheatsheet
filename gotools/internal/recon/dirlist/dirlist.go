// Package dirlist implements the dirlist command: recursively harvesting
// file URLs from open directory listings.
package dirlist

import (
	"flag"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "dirlist",
		Group:   "WEB recon",
		Summary: "Recursively harvest file URLs from open directory listings (dir_listing.py)",
		Run:     Run,
	})
}

// excludedExt are the noise extensions dir_listing.py skips.
var excludedExt = []string{
	".jpg", ".ttf", ".tif", ".jpeg", ".png", ".gif", ".css", ".webp",
	".svg", ".woff", ".woff2", ".jpe", ".bmp",
}

var hrefRe = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)

func Run(args []string) error {
	fs := flag.NewFlagSet("dirlist", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"l"}},
			{Title: "OPTIONS", Names: []string{"timeout", "insecure", "depth"}},
			{Title: "OUTPUT", Names: []string{"o"}},
		})
	}
	in := fs.String("l", "", "file of directory-listing URLs (default: stdin)")
	out := fs.String("o", "", "output file (default: stdout)")
	timeout := fs.Duration("timeout", 15*time.Second, "per-request timeout")
	insecure := fs.Bool("insecure", true, "skip TLS verification")
	maxDepth := fs.Int("depth", 0, "max recursion depth (0 = unlimited)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer ioutil.StartHeartbeat("dirlist")()

	seeds, err := ioutil.InputLines(ioutil.ResolveInput(*in, fs.Args()))
	if err != nil {
		return err
	}

	client := netx.NewClient(*timeout, *insecure)
	visited := map[string]struct{}{}
	files := map[string]struct{}{}

	for _, seed := range seeds {
		u, err := url.Parse(seed)
		if err != nil {
			ioutil.Warn("bad seed URL %q: %v", seed, err)
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

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	if err := ioutil.WriteLines(w, result); err != nil {
		return err
	}
	ioutil.Warn("found %d file URL(s)", len(result))
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

	resp, err := netx.Get(client, dirURL)
	if err != nil {
		ioutil.Warn("fetch %s: %v", dirURL, err)
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
	for _, ext := range excludedExt {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	return false
}

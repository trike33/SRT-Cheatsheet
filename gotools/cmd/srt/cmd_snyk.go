package main

import (
	"flag"
	"fmt"
	"html"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

func init() {
	register(&command{
		name:    "snyk",
		group:   "WEB recon",
		summary: "Check a version against a Snyk package's advisory ranges (synk_parser.py)",
		run:     runSnyk,
	})
}

var (
	tableRe    = regexp.MustCompile(`(?s)<table[^>]*>(.*?)</table>`)
	trRe       = regexp.MustCompile(`(?s)<tr[^>]*>(.*?)</tr>`)
	tdRe       = regexp.MustCompile(`(?s)<td[^>]*>(.*?)</td>`)
	vulnHref   = regexp.MustCompile(`href="([^"]*vuln[^"]*)"`)
	tagStrip   = regexp.MustCompile(`(?s)<[^>]+>`)
	wsCollapse = regexp.MustCompile(`\s+`)
	// constraintTok matches a comparator (optional) followed by a version.
	constraintTok = regexp.MustCompile(`(>=|<=|>|<|=)?\s*v?([0-9]+(?:\.[0-9A-Za-z\-]+)*)`)
)

func runSnyk(args []string) error {
	fs := flag.NewFlagSet("snyk", flag.ExitOnError)
	snykURL := fs.String("url", "", "Snyk package advisory URL (required)")
	version := fs.String("version", "", "installed version to test, e.g. 3.7 or 3.7.2 (required)")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP timeout")
	insecure := fs.Bool("insecure", true, "skip TLS verification")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *snykURL == "" || *version == "" {
		return errMissing("both -url and -version are required")
	}
	defer startHeartbeat("snyk")()

	client := newHTTPClient(*timeout, *insecure)
	resp, err := httpGet(client, *snykURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("URL returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	tableMatch := tableRe.FindStringSubmatch(string(body))
	if tableMatch == nil {
		return fmt.Errorf("no advisory table found at %s (page layout may have changed)", *snykURL)
	}

	target := *version
	fmt.Fprintf(os.Stderr, "URL      >>> %s\n", *snykURL)
	fmt.Fprintf(os.Stderr, "Version  >>> %s\n", normalizeVersion(target))

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tVULNERABILITY\tLINK")
	count := 0
	for _, tr := range trRe.FindAllStringSubmatch(tableMatch[1], -1) {
		cells := tdRe.FindAllStringSubmatch(tr[1], -1)
		if len(cells) < 2 {
			continue
		}
		severity := cleanCell(cells[0][1])
		constraintStr := cleanCell(cells[1][1])
		if severity == "" && constraintStr == "" {
			continue
		}

		if !versionMatchesConstraints(target, constraintStr) {
			continue
		}

		link := "n/a"
		if m := vulnHref.FindStringSubmatch(tr[1]); m != nil {
			link = m[1]
			if strings.HasPrefix(link, "/") {
				link = "https://security.snyk.io" + link
			}
		}
		vuln := truncate(cleanCell(cells[0][1]), 60)
		if len(cells) >= 3 {
			vuln = truncate(cleanCell(cells[2][1]), 60)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", severity, vuln, link)
		count++
	}
	tw.Flush()
	fmt.Fprintf(os.Stderr, "\nVulnerabilities matching version %s >>> %d\n", normalizeVersion(target), count)
	return nil
}

// cleanCell strips HTML tags, unescapes entities, and collapses whitespace.
func cleanCell(s string) string {
	s = tagStrip.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	s = wsCollapse.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// versionMatchesConstraints reports whether target satisfies EVERY comparator in
// constraintStr — i.e. the version sits inside the affected range, so the row
// applies. An unparseable range is treated as non-matching to avoid noise.
func versionMatchesConstraints(target, constraintStr string) bool {
	matches := constraintTok.FindAllStringSubmatch(constraintStr, -1)
	if len(matches) == 0 {
		return false
	}
	parsedAny := false
	for _, m := range matches {
		op := m[1]
		ver := m[2]
		if ver == "" {
			continue
		}
		if op == "" {
			op = "=" // bare version means an exact affected version
		}
		parsedAny = true
		if !satisfies(target, op, ver) {
			return false
		}
	}
	return parsedAny
}

func satisfies(target, op, ver string) bool {
	c := compareVersions(target, ver)
	switch op {
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	case "=":
		return c == 0
	}
	return false
}

// normalizeVersion pads a shorthand version to X.Y.Z for display.
func normalizeVersion(v string) string {
	parts := strings.Split(v, ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	return strings.Join(parts[:3], ".")
}

// compareVersions does a numeric, segment-wise comparison (2.10 > 2.9), ignoring
// any non-numeric suffix on a segment (e.g. "1-beta" -> 1).
func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = leadingInt(as[i])
		}
		if i < len(bs) {
			bv = leadingInt(bs[i])
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

func leadingInt(s string) int {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0
	}
	n, _ := strconv.Atoi(s[:i])
	return n
}

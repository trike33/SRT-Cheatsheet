// Package dork implements the dork command: Google dorking -- generating
// (and, with a Google Programmable Search Engine key, actually running)
// a curated set of advanced search-operator queries against a target
// domain and/or engagement name, to surface exposed documents, admin/login
// panels, open directory listings, error pages, and third-party leaks
// (paste sites, cloud buckets, source hosting) a crawl or passive-URL
// source like gau would never see.
//
// Scraping google.com's own result pages is deliberately not how this
// works: it's against Google's terms of service, gets rate-limited/
// CAPTCHA'd within a handful of requests, and (in this project's sandbox,
// at least) google.com itself isn't even reachable -- only
// www.googleapis.com is. The Google Custom Search JSON API
// (customsearch.googleapis.com) is the one ToS-compliant, programmatic way
// to run these queries, so that's what -search uses; without an API
// key/engine ID it still prints the generated queries as ready-to-paste
// Google search URLs, which is useful on its own and sends no traffic at
// all.
package dork

import (
	"fmt"
	"net/url"
)

// Category is one dork query template.
type Category struct {
	Name        string
	Description string
	NeedsDomain bool // query references site:domain
	NeedsName   bool // query references the engagement/org name as a string
	Build       func(domain, name string) string
}

// categories is the curated set this package generates. Intentionally
// bounded and hand-picked -- like techWords/techExtensions in the fuzz
// package -- not an attempt at an exhaustive dork database (that's what
// the Google Hacking Database itself is for).
var categories = []Category{
	{
		Name: "files", Description: "office/document files", NeedsDomain: true,
		Build: func(d, _ string) string {
			return fmt.Sprintf(`site:%s (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:ppt OR filetype:pptx OR filetype:csv OR filetype:txt)`, d)
		},
	},
	{
		Name: "backup", Description: "backup/config/database file leaks", NeedsDomain: true,
		Build: func(d, _ string) string {
			return fmt.Sprintf(`site:%s (filetype:sql OR filetype:env OR filetype:bak OR filetype:old OR filetype:log OR filetype:conf OR filetype:config OR filetype:ini OR filetype:yml OR filetype:yaml)`, d)
		},
	},
	{
		Name: "admin", Description: "admin/login panels", NeedsDomain: true,
		Build: func(d, _ string) string {
			return fmt.Sprintf(`site:%s (inurl:admin OR inurl:login OR inurl:signin OR inurl:portal OR inurl:dashboard OR inurl:wp-admin OR inurl:cpanel)`, d)
		},
	},
	{
		Name: "listing", Description: `open directory listings ("index of")`, NeedsDomain: true,
		Build: func(d, _ string) string {
			return fmt.Sprintf(`site:%s intitle:"index of"`, d)
		},
	},
	{
		Name: "errors", Description: "error messages / stack traces", NeedsDomain: true,
		Build: func(d, _ string) string {
			return fmt.Sprintf(`site:%s (intext:"SQL syntax" OR intext:"stack trace" OR intext:"Fatal error" OR intext:"ORA-" OR intext:"Warning: mysql")`, d)
		},
	},
	{
		Name: "confidential", Description: "documents marked confidential/internal", NeedsDomain: true,
		Build: func(d, _ string) string {
			return fmt.Sprintf(`site:%s (intitle:confidential OR intitle:"internal use only" OR intext:"not for distribution")`, d)
		},
	},
	{
		Name: "cloud", Description: "third-party cloud storage buckets mentioning the org", NeedsName: true,
		Build: func(_, name string) string {
			return fmt.Sprintf(`(site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com) %q`, name)
		},
	},
	{
		Name: "pastes", Description: "paste-site leaks mentioning the org", NeedsName: true,
		Build: func(_, name string) string {
			return fmt.Sprintf(`(site:pastebin.com OR site:paste.ee OR site:ghostbin.com) %q`, name)
		},
	},
	{
		Name: "code", Description: "exposed secrets in public source hosting", NeedsName: true,
		Build: func(_, name string) string {
			return fmt.Sprintf(`site:github.com %q (password OR secret OR api_key OR apikey)`, name)
		},
	},
}

// CategoryNames returns every category's Name, in definition order.
func CategoryNames() []string {
	out := make([]string, len(categories))
	for i, c := range categories {
		out[i] = c.Name
	}
	return out
}

// Query is one generated dork: its category, the query string, and (when
// Build used it) which of domain/name it's scoped to.
type Query struct {
	Category string `json:"category"`
	Query    string `json:"query"`
}

// Generate builds every selected category's query for domain and/or name.
// want, when non-empty, restricts to those category names (unknown names
// are ignored, not an error -- a typo just finds nothing instead of
// failing a whole run); empty means every category domain/name actually
// support. A category whose required field (domain or name) wasn't given
// is skipped silently, so Generate("example.com", "", nil) returns only
// the domain-scoped categories.
func Generate(domain, name string, want []string) []Query {
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	var out []Query
	for _, c := range categories {
		if len(wantSet) > 0 && !wantSet[c.Name] {
			continue
		}
		if c.NeedsDomain && domain == "" {
			continue
		}
		if c.NeedsName && name == "" {
			continue
		}
		out = append(out, Query{Category: c.Name, Query: c.Build(domain, name)})
	}
	return out
}

// SearchURL returns a ready-to-paste google.com search URL for a query --
// useful whether or not -search (the Custom Search API) is configured,
// since nothing stops an operator from just clicking through these by hand.
func SearchURL(query string) string {
	return "https://www.google.com/search?q=" + url.QueryEscape(query)
}

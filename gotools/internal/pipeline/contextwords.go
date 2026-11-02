package pipeline

import (
	"regexp"
	"strings"
)

// engagementNameWords tokenizes the pipeline config's engagement name into
// lowercase words worth trying as directory/file names on the target's own
// site -- gap 7's third context-word source, alongside fuzz -words-auto's
// per-host tech/title words: a client's short name, product or codename is
// often also a path on their own site ("Acme Billing" -> /acme, /billing).
// Splits on non-alphanumerics and camelCase boundaries, drops short tokens
// and generic corporate-suffix noise, deduplicates, first-seen order.
var engagementNameSplitRe = regexp.MustCompile(`[A-Z]+[a-z0-9]*|[a-z0-9]+`)

var engagementNameStopwords = map[string]bool{
	"inc": true, "llc": true, "corp": true, "ltd": true, "co": true,
	"company": true, "group": true, "the": true, "and": true, "for": true,
}

func engagementNameWords(name string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range engagementNameSplitRe.FindAllString(name, -1) {
		w := strings.ToLower(m)
		if len(w) < 3 || engagementNameStopwords[w] || seen[w] {
			continue
		}
		seen[w] = true
		out = append(out, w)
	}
	return out
}

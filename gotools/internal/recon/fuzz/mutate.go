package fuzz

import "strings"

// extToken is a literal placeholder a wordlist line can carry (e.g.
// "backup.%ext%") to spell out exactly where a discovered/configured
// extension goes, instead of only ever appending it as a suffix the way -e
// does for a plain word.
const extToken = "%ext%"

// mutateWord returns w itself plus, with -mutate-case, its lower/UPPER/Title
// case variants -- catches the handful of apps/filesystems that are
// case-sensitive and where the "real" wordlist casing isn't the one in use
// (BACKUP.ZIP, Admin, login.PHP). Deduplicated and capped to the 4 forms.
func (e *fuzzEngine) mutateWord(w string) []string {
	if !e.mutateCase || w == "" {
		return []string{w}
	}
	out := []string{w}
	seen := map[string]bool{w: true}
	add := func(v string) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	add(strings.ToLower(w))
	add(strings.ToUpper(w))
	add(titleCase(w))
	return out
}

// titleCase upper-cases the first rune and lower-cases the rest.
func titleCase(w string) string {
	r := []rune(w)
	if len(r) == 0 {
		return w
	}
	return strings.ToUpper(string(r[0])) + strings.ToLower(string(r[1:]))
}

// expandExtToken reports whether word carries the %ext% token and, if so,
// returns one candidate per extension in exts with the token replaced
// (isToken is true either way, so the caller knows not to also run the
// normal suffix-append expansion for this word). With no extensions resolved
// yet, the token is dropped rather than sent as a literal "%ext%" in a URL.
func expandExtToken(word string, exts []string) (candidates []string, isToken bool) {
	if !strings.Contains(word, extToken) {
		return nil, false
	}
	for _, ext := range exts {
		candidates = append(candidates, strings.ReplaceAll(word, extToken, strings.TrimPrefix(ext, ".")))
	}
	return candidates, true
}

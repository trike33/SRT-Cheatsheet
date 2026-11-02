package store

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

// QueryRecords returns the newest-observation record for every (kind, key)
// pair under any of kinds, across every run in the project database --
// "newest observation" matching `srt results`' own default (no -history).
// Returns (nil, nil), not an error, when there's no database yet: a command
// falling back to it on empty input should treat "nothing to fall back to"
// as ordinary, not fatal.
func QueryRecords(kinds []string) ([]Record, error) {
	if len(kinds) == 0 {
		return nil, nil
	}
	if _, statErr := os.Stat(DBPath()); statErr != nil {
		return nil, nil
	}
	db, err := OpenReadable()
	if err != nil {
		return nil, nil
	}
	defer db.Close()

	ph := strings.TrimSuffix(strings.Repeat("?,", len(kinds)), ",")
	args := make([]any, len(kinds))
	for i, k := range kinds {
		args[i] = k
	}
	rows, err := db.Query(`SELECT kind, key, host, port, url, status, length FROM records
		WHERE id IN (SELECT MAX(id) FROM records GROUP BY kind, key) AND kind IN (`+ph+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.Kind, &r.Key, &r.Host, &r.Port, &r.URL, &r.Status, &r.Length); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// InputFallback binds the -from/-where flags a command offers alongside its
// own -l, so the project database -- when a command falls back to it -- can
// be aimed at a different kind, or narrowed by HTTP status, than the
// command's own default. See BindInputFallback.
type InputFallback struct {
	cmd        string
	kinds      []string
	from       *string
	where      *string
	isTerminal func() bool // overridden by tests; nil means ioutil.StdinIsTerminal
}

func (ib *InputFallback) stdinIsTerminal() bool {
	if ib.isTerminal != nil {
		return ib.isTerminal()
	}
	return ioutil.StdinIsTerminal()
}

// BindInputFallback registers -from/-where on fs (call before fs.Parse) and
// returns an InputFallback whose Resolve replaces the usual
// ioutil.InputLines(ioutil.ResolveInput(...)) call. cmd names the command,
// for Resolve's log line; defaultKinds are the record kind(s) read when
// -from isn't given, e.g. "domain", "subdomain" for a command that targets
// hostnames.
func BindInputFallback(fs *flag.FlagSet, cmd string, defaultKinds ...string) *InputFallback {
	ib := &InputFallback{cmd: cmd, kinds: defaultKinds}
	ib.from = fs.String("from", "", fmt.Sprintf("with no -l/args/piped stdin and an interactive terminal: comma list of result kinds to read from the project db instead of waiting on input (default: %s; see `srt results -kind`)", strings.Join(defaultKinds, ",")))
	ib.where = fs.String("where", "", `with -from (or its default): "status=<list/ranges>" to filter db records by HTTP status, e.g. "status=200,301-399"`)
	return ib
}

// SetDefaultKinds overrides the kinds BindInputFallback was given, for a
// command whose right default depends on another flag only known after
// fs.Parse (e.g. resolve's -reverse switching between hostnames and IPs).
// Call it after fs.Parse and before Resolve; a plain -from on the command
// line still wins over it, same as over BindInputFallback's own default.
func (ib *InputFallback) SetDefaultKinds(kinds ...string) { ib.kinds = kinds }

// Resolve returns the lines flagValue/positional/piped stdin would give, same
// as ioutil.InputLines(ioutil.ResolveInput(flagValue, positional)) always
// has. Only when none of those apply -- no flag, no positional arg, and
// stdin is an interactive terminal, so reading it would just hang waiting
// on a human -- does it fall back to the project database instead,
// returning the matching records' keys. source describes what was read
// from the database (for the caller to log); it's "" whenever the lines
// came from -l/args/stdin as before, so a command that never hits the
// fallback behaves exactly as it did before this existed.
func (ib *InputFallback) Resolve(flagValue string, positional []string) (lines []string, source string, err error) {
	path := ioutil.ResolveInput(flagValue, positional)
	if path != "" || !ib.stdinIsTerminal() {
		lines, err = ioutil.InputLines(path)
		return lines, "", err
	}

	kinds := ib.kinds
	if ib.from != nil && *ib.from != "" {
		kinds = nil
		for _, k := range strings.Split(*ib.from, ",") {
			if k = strings.TrimSpace(k); k != "" {
				kinds = append(kinds, k)
			}
		}
	}
	if len(kinds) == 0 {
		return nil, "", nil
	}

	var statusFilter ioutil.RangeSet
	if ib.where != nil && *ib.where != "" {
		field, val, ok := strings.Cut(*ib.where, "=")
		if !ok || strings.TrimSpace(field) != "status" {
			return nil, "", fmt.Errorf(`-where: only "status=<list/ranges>" is supported, got %q`, *ib.where)
		}
		if statusFilter, err = ioutil.ParseRangeSet(strings.TrimSpace(val)); err != nil {
			return nil, "", fmt.Errorf("-where: %w", err)
		}
	}

	recs, err := QueryRecords(kinds)
	if err != nil || len(recs) == 0 {
		return nil, "", err
	}
	seen := map[string]bool{}
	for _, r := range recs {
		if !statusFilter.Empty() && !statusFilter.Contains(r.Status) {
			continue
		}
		if r.Key == "" || seen[r.Key] {
			continue
		}
		seen[r.Key] = true
		lines = append(lines, r.Key)
	}
	if len(lines) == 0 {
		return nil, "", nil
	}
	sort.Strings(lines)
	source = fmt.Sprintf("%d %s record(s) from %s", len(lines), strings.Join(kinds, "/"), DBPath())
	if ib.cmd != "" {
		ioutil.Warn("%s: using %s (no -l/args/piped input given)", ib.cmd, source)
	}
	return lines, source, nil
}

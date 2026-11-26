// Package results implements the results, runs, export and db commands: the
// CLI layer over the generic internal/store results database. It is the one
// place that needs to know the JSON shape of portscan/fuzz/probe output (to
// auto-detect it on `db import`), so those three recon packages are its only
// recon dependency -- no recon package depends back on results.
package results

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{Name: "results", Group: "results", Summary: "Query saved scan results (filter by kind/host/status, output table, JSON or bare keys)", Run: RunResults})
	cli.Register(&cli.Command{Name: "runs", Group: "results", Summary: "List saved runs (each command/pipeline execution); old runs are never overwritten", Run: RunRuns})
	cli.Register(&cli.Command{Name: "export", Group: "results", Summary: "Export saved results as a directory tree (per host), JSON or CSV", Run: RunExport})
	cli.Register(&cli.Command{Name: "db", Group: "results", Summary: "Results database housekeeping: path, stats, import <file>, rm <run>", Run: RunDB})
}

// --- query ---

type queryFilter struct {
	run     int64
	history bool
	kinds   []string
	host    string
	port    int
	status  []int
	q       string
	limit   int
}

func (f *queryFilter) bind(fs *flag.FlagSet) (kind, status *string) {
	fs.Int64Var(&f.run, "run", 0, "only this run id (default: newest observation of every result across all runs)")
	fs.BoolVar(&f.history, "history", false, "every observation from every run, not just the newest")
	kind = fs.String("kind", "", "comma list: port, url, probe, subdomain, domain, ip, resolve, gau, params, sensitive, robots, ...")
	fs.StringVar(&f.host, "host", "", "host substring")
	fs.IntVar(&f.port, "port", 0, "exact port")
	status = fs.String("status", "", "HTTP status list/ranges, e.g. 200,301,400-499")
	fs.StringVar(&f.q, "q", "", "substring to find in the key or data")
	fs.IntVar(&f.limit, "limit", 0, "max rows (0 = all)")
	return
}

func (f *queryFilter) finish(kind, status string) error {
	for _, k := range strings.Split(kind, ",") {
		if k = strings.TrimSpace(k); k != "" {
			f.kinds = append(f.kinds, k)
		}
	}
	if status != "" {
		var err error
		if f.status, err = parseStatusSet(status); err != nil {
			return err
		}
	}
	return nil
}

func parseStatusSet(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("bad status %q", part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a {
				return nil, fmt.Errorf("bad status range %q", part)
			}
		}
		for c := a; c <= b && c-a < 1000; c++ {
			out = append(out, c)
		}
	}
	return out, nil
}

func placeholders(n int) string { return strings.TrimSuffix(strings.Repeat("?,", n), ",") }

func (f *queryFilter) query(db *sql.DB) ([]store.Record, error) {
	var where []string
	var args []any
	switch {
	case f.run > 0:
		where, args = append(where, "r.run_id = ?"), append(args, f.run)
	case !f.history:
		where = append(where, "r.id IN (SELECT MAX(id) FROM records GROUP BY kind, key)")
	}
	if len(f.kinds) > 0 {
		where = append(where, "r.kind IN ("+placeholders(len(f.kinds))+")")
		for _, k := range f.kinds {
			args = append(args, k)
		}
	}
	if f.host != "" {
		where, args = append(where, "r.host LIKE ?"), append(args, "%"+f.host+"%")
	}
	if f.port > 0 {
		where, args = append(where, "r.port = ?"), append(args, f.port)
	}
	if len(f.status) > 0 {
		where = append(where, "r.status IN ("+placeholders(len(f.status))+")")
		for _, s := range f.status {
			args = append(args, s)
		}
	}
	if f.q != "" {
		where, args = append(where, "(r.key LIKE ? OR r.data LIKE ?)"), append(args, "%"+f.q+"%", "%"+f.q+"%")
	}
	sqlq := `SELECT r.run_id, r.kind, r.key, r.host, r.port, r.url, r.status, r.length, r.data FROM records r`
	if len(where) > 0 {
		sqlq += " WHERE " + strings.Join(where, " AND ")
	}
	sqlq += " ORDER BY r.kind, r.host, r.port, r.key"
	if f.limit > 0 {
		sqlq += " LIMIT " + strconv.Itoa(f.limit)
	}
	rows, err := db.Query(sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Record
	for rows.Next() {
		var r store.Record
		var data string
		if err := rows.Scan(&r.RunID, &r.Kind, &r.Key, &r.Host, &r.Port, &r.URL, &r.Status, &r.Length, &data); err != nil {
			return nil, err
		}
		if data != "" {
			json.Unmarshal([]byte(data), &r.Data)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// protocolKinds are the eight kinds internal/protocols.Finding.Record
// stores -- the only kinds whose data holds "detail"/"severity"/"cred"/
// "hostname" rather than a recon command's "banner"/"title"/"server"/
// "tech".
var protocolKinds = map[string]bool{
	"ftp": true, "telnet": true, "smb": true, "ldap": true,
	"ssh": true, "mssql": true, "vnc": true, "rdp": true,
}

// summarize renders a record's extra data as one short column: a recon
// command's own fields, or -- for the eight protocol-client kinds --
// Finding.Record's own shape (cred, hostname, then detail; a Finding.Err
// always means no other field was set, so it's checked first and wins
// outright, same priority Line gives a connection error over a login
// outcome). Credential.String() never shows a password/hash itself (see
// its own doc comment) -- unlike the live command's one-line output,
// which deliberately does via UserPass(), a saved record is read back
// later by anyone who can run `srt results`, not just the person who
// just typed the credential in.
func summarize(r store.Record) string {
	if v, ok := r.Data["error"]; ok {
		return fmt.Sprint(v)
	}
	var parts []string
	for _, k := range []string{"banner", "title", "server", "tech"} {
		if v, ok := r.Data[k]; ok {
			if list, ok := v.([]any); ok {
				var s []string
				for _, x := range list {
					s = append(s, fmt.Sprint(x))
				}
				parts = append(parts, strings.Join(s, ","))
			} else {
				parts = append(parts, fmt.Sprint(v))
			}
		}
	}
	if protocolKinds[r.Kind] {
		if v, ok := r.Data["cred"]; ok {
			parts = append(parts, fmt.Sprint(v))
		}
		if v, ok := r.Data["hostname"]; ok {
			parts = append(parts, fmt.Sprintf("host:%s", v))
		}
		if v, ok := r.Data["detail"]; ok {
			parts = append(parts, fmt.Sprint(v))
		}
	}
	return strings.Join(parts, " | ")
}

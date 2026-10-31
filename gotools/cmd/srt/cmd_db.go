package main

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

func init() {
	register(&command{name: "results", group: "results", summary: "Query saved scan results (filter by kind/host/status, output table, JSON or bare keys)", run: runResults})
	register(&command{name: "runs", group: "results", summary: "List saved runs (each command/pipeline execution); old runs are never overwritten", run: runRuns})
	register(&command{name: "export", group: "results", summary: "Export saved results as a directory tree (per host), JSON or CSV", run: runExport})
	register(&command{name: "db", group: "results", summary: "Results database housekeeping: path, stats, import <file>, rm <run>", run: runDB})
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

func (f *queryFilter) query(db *sql.DB) ([]dbRecord, error) {
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
	var out []dbRecord
	for rows.Next() {
		var r dbRecord
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

// summarize renders a record's extra data as one short column.
func summarize(r dbRecord) string {
	var parts []string
	for _, k := range []string{"banner", "title", "server", "tech", "error"} {
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
	return strings.Join(parts, " | ")
}

func runResults(args []string) error {
	fs := flag.NewFlagSet("results", flag.ExitOnError)
	var f queryFilter
	kind, status := f.bind(fs)
	jsonOut := fs.Bool("json", false, "JSON lines")
	keys := fs.Bool("keys", false, "print only each result's key (URL, host:port, name) -- pipe-friendly")
	count := fs.Bool("count", false, "print the number of matching results")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := f.finish(*kind, *status); err != nil {
		return err
	}
	db, err := openStoreReadable()
	if err != nil {
		return err
	}
	defer db.Close()
	recs, err := f.query(db)
	if err != nil {
		return err
	}

	switch {
	case *count:
		fmt.Println(len(recs))
	case *keys:
		for _, r := range recs {
			fmt.Println(r.Key)
		}
	case *jsonOut:
		for _, r := range recs {
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
		}
	default:
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "RUN\tKIND\tSTATUS\tLENGTH\tKEY\tINFO")
		for _, r := range recs {
			st, ln := "-", "-"
			if r.Status > 0 {
				st, ln = strconv.Itoa(r.Status), strconv.Itoa(r.Length)
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", r.RunID, r.Kind, st, ln, r.Key, summarize(r))
		}
		tw.Flush()
		fmt.Fprintf(os.Stderr, "%d result(s)\n", len(recs))
	}
	return nil
}

// --- runs ---

type runInfo struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Command string `json:"command"`
	Cwd     string `json:"cwd"`
	Started string `json:"started_at"`
	Ended   string `json:"ended_at,omitempty"`
	Records int    `json:"records"`
}

func listRuns(db *sql.DB, limit int) ([]runInfo, error) {
	q := `SELECT r.id, r.name, r.command, r.cwd, r.started_at, COALESCE(r.ended_at,''), COUNT(x.id)
	      FROM runs r LEFT JOIN records x ON x.run_id = r.id GROUP BY r.id ORDER BY r.id DESC`
	if limit > 0 {
		q += " LIMIT " + strconv.Itoa(limit)
	}
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runInfo
	for rows.Next() {
		var r runInfo
		if err := rows.Scan(&r.ID, &r.Name, &r.Command, &r.Cwd, &r.Started, &r.Ended, &r.Records); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func runRuns(args []string) error {
	fs := flag.NewFlagSet("runs", flag.ExitOnError)
	n := fs.Int("n", 20, "most recent runs to show (0 = all)")
	jsonOut := fs.Bool("json", false, "JSON lines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := openStoreReadable()
	if err != nil {
		return err
	}
	defer db.Close()
	runs, err := listRuns(db, *n)
	if err != nil {
		return err
	}
	if *jsonOut {
		for _, r := range runs {
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
		}
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RUN\tSTARTED\tRECORDS\tCOMMAND")
	for _, r := range runs {
		state := ""
		if r.Ended == "" {
			state = "  (unfinished)"
		}
		fmt.Fprintf(tw, "%d\t%s\t%d\t%s%s\n", r.ID, localTime(r.Started), r.Records, r.Command, state)
	}
	return tw.Flush()
}

func localTime(rfc string) string {
	if t, err := time.Parse(time.RFC3339, rfc); err == nil {
		return t.Local().Format("2006-01-02 15:04")
	}
	return rfc
}

// --- export ---

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeDir(host string) string {
	if host == "" {
		return "_global"
	}
	return unsafeName.ReplaceAllString(host, "_")
}

func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	var f queryFilter
	kind, status := f.bind(fs)
	out := fs.String("o", "", "output directory (tree) or file (json/csv; - for stdout)")
	format := fs.String("format", "tree", "tree (a directory per host), json, or csv")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := f.finish(*kind, *status); err != nil {
		return err
	}
	if *out == "" {
		return errMissing("export needs -o <dir> (tree) or -o <file> (json/csv)")
	}
	db, err := openStoreReadable()
	if err != nil {
		return err
	}
	defer db.Close()
	recs, err := f.query(db)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		return errors.New("nothing to export (no results match)")
	}

	switch *format {
	case "json":
		return exportJSON(recs, *out)
	case "csv":
		return exportCSV(recs, *out)
	case "tree":
		n, err := exportTree(recs, *out, f.run)
		if err != nil {
			return err
		}
		warn("exported %d result(s) into %s (%d file(s))", len(recs), *out, n)
		return nil
	}
	return fmt.Errorf("unknown -format %q (want tree, json or csv)", *format)
}

func openOut(path string) (io.WriteCloser, error) { return output(path) }

func exportJSON(recs []dbRecord, path string) error {
	w, err := openOut(path)
	if err != nil {
		return err
	}
	defer w.Close()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(recs)
}

func exportCSV(recs []dbRecord, path string) error {
	w, err := openOut(path)
	if err != nil {
		return err
	}
	defer w.Close()
	cw := csv.NewWriter(w)
	cw.Write([]string{"run", "kind", "key", "host", "port", "url", "status", "length", "info"})
	for _, r := range recs {
		cw.Write([]string{strconv.FormatInt(r.RunID, 10), r.Kind, r.Key, r.Host, strconv.Itoa(r.Port), r.URL, strconv.Itoa(r.Status), strconv.Itoa(r.Length), summarize(r)})
	}
	cw.Flush()
	return cw.Error()
}

// exportTree lays results out as a directory per host:
//
//	<dir>/summary.json         counts per kind, hosts, when/which run
//	<dir>/hosts.txt            every host seen
//	<dir>/by-kind/<kind>.txt   all keys of a kind, across hosts
//	<dir>/<host>/ports.txt     "port  banner"
//	<dir>/<host>/probe.txt     "status  url  [tech]  title"
//	<dir>/<host>/urls.txt      "status  length  url" (+ urls-<status>.txt, bare URLs)
//	<dir>/<host>/<kind>.txt    keys of any other kind (subdomain, gau, ...)
//
// It returns the number of files written.
func exportTree(recs []dbRecord, dir string, run int64) (int, error) {
	files := map[string][]string{} // relative path -> lines
	add := func(path, line string) { files[path] = append(files[path], line) }

	counts := map[string]int{}
	hosts := map[string]bool{}
	for _, r := range recs {
		counts[r.Kind]++
		add(filepath.Join("by-kind", safeDir(r.Kind)+".txt"), r.Key)
		hd := safeDir(r.Host)
		if r.Host != "" {
			hosts[r.Host] = true
		}
		switch r.Kind {
		case "port":
			line := strconv.Itoa(r.Port)
			if b, ok := r.Data["banner"]; ok {
				line += "  " + fmt.Sprint(b)
			}
			add(filepath.Join(hd, "ports.txt"), line)
		case "probe":
			add(filepath.Join(hd, "probe.txt"), strings.TrimSpace(fmt.Sprintf("%d  %s  %s", r.Status, r.Key, summarize(r))))
		case "url":
			add(filepath.Join(hd, "urls.txt"), fmt.Sprintf("%d  %d  %s", r.Status, r.Length, r.Key))
			add(filepath.Join(hd, fmt.Sprintf("urls-%d.txt", r.Status)), r.Key)
		default:
			add(filepath.Join(hd, safeDir(r.Kind)+".txt"), r.Key)
		}
	}

	hostList := make([]string, 0, len(hosts))
	for h := range hosts {
		hostList = append(hostList, h)
	}
	sort.Strings(hostList)
	files["hosts.txt"] = hostList

	sum, _ := json.MarshalIndent(map[string]any{
		"generated": time.Now().UTC().Format(time.RFC3339),
		"run":       run, // 0 = merged view across runs
		"total":     len(recs),
		"kinds":     counts,
		"hosts":     len(hostList),
	}, "", "  ")

	n := 0
	for rel, lines := range files {
		if err := writeExportFile(filepath.Join(dir, rel), lines); err != nil {
			return n, err
		}
		n++
	}
	if err := os.WriteFile(filepath.Join(dir, "summary.json"), append(sum, '\n'), 0o644); err != nil {
		return n, err
	}
	return n + 1, nil
}

func writeExportFile(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// --- db housekeeping ---

func runDB(args []string) error {
	if len(args) == 0 {
		return errMissing("usage: srt db path | stats | import [-kind K] [-name N] <file> | rm <run-id>")
	}
	switch args[0] {
	case "path":
		fmt.Println(dbPath())
		return nil
	case "stats":
		return dbStats()
	case "import":
		return dbImport(args[1:])
	case "rm":
		return dbRemove(args[1:])
	}
	return fmt.Errorf("unknown db subcommand %q (want path, stats, import, rm)", args[0])
}

func dbStats() error {
	db, err := openStoreReadable()
	if err != nil {
		return err
	}
	defer db.Close()
	var runs, recs int
	db.QueryRow(`SELECT COUNT(*) FROM runs`).Scan(&runs)
	db.QueryRow(`SELECT COUNT(*) FROM records`).Scan(&recs)
	size := int64(0)
	if st, err := os.Stat(dbPath()); err == nil {
		size = st.Size()
	}
	fmt.Printf("%s\n%d run(s), %d record(s), %s\n", dbPath(), runs, recs, humanBytes(size))
	rows, err := db.Query(`SELECT kind, COUNT(*) FROM records GROUP BY kind ORDER BY COUNT(*) DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		rows.Scan(&k, &n)
		fmt.Printf("  %-12s %d\n", k, n)
	}
	return rows.Err()
}

func dbRemove(args []string) error {
	if len(args) != 1 {
		return errMissing("usage: srt db rm <run-id>")
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("bad run id %q", args[0])
	}
	db, err := openStoreReadable()
	if err != nil {
		return err
	}
	defer db.Close()
	db.Exec(`DELETE FROM records WHERE run_id=?`, id)
	res, err := db.Exec(`DELETE FROM runs WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no run %d", id)
	}
	warn("removed run %d", id)
	return nil
}

// dbImport loads a result file into a new run: JSON lines from portscan, fuzz
// or probe are recognized automatically; any other file is stored line by line
// under -kind.
func dbImport(args []string) error {
	fs := flag.NewFlagSet("db import", flag.ExitOnError)
	kind := fs.String("kind", "", "record kind for plain-text lines (e.g. subdomain); not needed for portscan/fuzz/probe JSON")
	name := fs.String("name", "", "run name (default: import <file>)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errMissing("usage: srt db import [-kind K] [-name N] <file>")
	}
	lines, err := inputLines(fs.Arg(0))
	if err != nil {
		return err
	}
	if *name == "" {
		*name = "import " + filepath.Base(fs.Arg(0))
	}
	s, err := startSink(*name, append([]string{"db", "import"}, args...))
	if err != nil {
		return err
	}
	var unparsed int
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if rec, ok := sniffJSONRecord([]byte(l)); ok {
			s.add(rec)
		} else if *kind != "" {
			s.add(textRecord(*kind, l))
		} else {
			unparsed++
		}
	}
	s.close()
	if unparsed > 0 {
		return fmt.Errorf("%d line(s) weren't recognized portscan/fuzz/probe JSON; pass -kind <name> to store plain lines", unparsed)
	}
	return nil
}

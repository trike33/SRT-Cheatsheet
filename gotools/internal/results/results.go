package results

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func RunResults(args []string) error {
	fs := flag.NewFlagSet("results", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "FILTERS", Names: []string{"kind", "status", "host", "port", "q", "run", "history"}},
			{Title: "OUTPUT", Names: []string{"limit", "json", "keys", "count"}},
		})
	}
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
	db, err := store.OpenReadable()
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

func RunRuns(args []string) error {
	fs := flag.NewFlagSet("runs", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "OUTPUT", Names: []string{"n", "json"}},
		})
	}
	n := fs.Int("n", 20, "most recent runs to show (0 = all)")
	jsonOut := fs.Bool("json", false, "JSON lines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := store.OpenReadable()
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

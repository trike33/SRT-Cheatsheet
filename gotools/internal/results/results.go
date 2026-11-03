package results

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func RunResults(args []string) error {
	fs := flag.NewFlagSet("results", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "FILTERS", Names: []string{"kind", "status", "host", "port", "q", "run", "history"}},
			{Title: "OUTPUT", Names: []string{"limit", "json", "keys", "count", "color"}},
		})
	}
	var f queryFilter
	kind, status := f.bind(fs)
	jsonOut := fs.Bool("json", false, "JSON lines")
	keys := fs.Bool("keys", false, "print only each result's key (URL, host:port, name) -- pipe-friendly")
	count := fs.Bool("count", false, "print the number of matching results")
	colorFlag := fs.String("color", "auto", "color the table output: auto|always|never (ignored with -json/-keys/-count)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
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
		printResultsTable(os.Stdout, recs, cm)
		summary := fmt.Sprintf("%d result(s)", len(recs))
		if len(recs) == 0 {
			summary = cm.Wrap(colorout.Yellow, summary)
		} else {
			summary = cm.Wrap(colorout.Green, summary)
		}
		fmt.Fprintln(os.Stderr, summary)
	}
	return nil
}

// printResultsTable renders recs as a column-aligned, optionally colorized
// table: a distinct color per "kind" (so scrolling past a mixed-kind result
// set still reads as visually grouped, see colorout.PaletteColor), status
// 2xx/3xx/4xx/5xx in green/cyan/yellow/red, and the summarized extra-data
// column dimmed, since it's secondary to KEY. As in probe's own table,
// column widths come from the plain (uncolored) text first, then colored
// cells are padded to that width before their color code is added (see
// colorout.Mode.PadWrap) -- so coloring some cells and not others never
// misaligns a column.
func printResultsTable(w io.Writer, recs []store.Record, cm colorout.Mode) {
	type row struct {
		run, kind, status, length, key, info string
		code                                 int
	}
	rows := make([]row, len(recs))
	for i, r := range recs {
		st, ln := "-", "-"
		if r.Status > 0 {
			st, ln = strconv.Itoa(r.Status), strconv.Itoa(r.Length)
		}
		rows[i] = row{run: strconv.FormatInt(r.RunID, 10), kind: r.Kind, status: st, length: ln, key: r.Key, info: summarize(r), code: r.Status}
	}

	headers := []string{"RUN", "KIND", "STATUS", "LENGTH", "KEY"}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len([]rune(h))
	}
	for _, r := range rows {
		cells := []string{r.run, r.kind, r.status, r.length, r.key}
		for i, c := range cells {
			if n := len([]rune(c)); n > widths[i] {
				widths[i] = n
			}
		}
	}

	fmt.Fprintln(w, strings.Join([]string{
		padLeft(headers[0], widths[0]), pad(headers[1], widths[1]), padLeft(headers[2], widths[2]),
		padLeft(headers[3], widths[3]), pad(headers[4], widths[4]), "INFO",
	}, "  "))

	for _, r := range rows {
		infoColor := ""
		if r.info != "" {
			infoColor = colorout.Gray
		}
		fmt.Fprintln(w, strings.Join([]string{
			cm.PadWrap("", padLeft(r.run, widths[0]), widths[0]),
			cm.PadWrap(colorout.PaletteColor(r.kind), r.kind, widths[1]),
			cm.PadWrap(colorout.StatusColor(r.code), padLeft(r.status, widths[2]), widths[2]),
			cm.PadWrap("", padLeft(r.length, widths[3]), widths[3]),
			cm.PadWrap("", r.key, widths[4]),
			cm.Wrap(infoColor, r.info),
		}, "  "))
	}
}

// pad left-aligns (right-pads) a plain, never-colored cell -- headers, and
// the KEY/KIND text columns' intrinsic width before PadWrap adds a color.
func pad(s string, width int) string {
	if n := len([]rune(s)); n < width {
		return s + strings.Repeat(" ", width-n)
	}
	return s
}

// padLeft right-aligns (left-pads) a numeric-looking column (RUN, STATUS,
// LENGTH) so a table of results reads like a column of numbers, not a
// ragged left edge.
func padLeft(s string, width int) string {
	if n := len([]rune(s)); n < width {
		return strings.Repeat(" ", width-n) + s
	}
	return s
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
			{Title: "OUTPUT", Names: []string{"n", "json", "color"}},
		})
	}
	n := fs.Int("n", 20, "most recent runs to show (0 = all)")
	jsonOut := fs.Bool("json", false, "JSON lines")
	colorFlag := fs.String("color", "auto", "color the table output: auto|always|never (ignored with -json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)
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
		// state is appended inside COMMAND, the table's last column -- safe
		// to color even under tabwriter, since there's no column after it
		// whose alignment a few extra escape bytes could throw off.
		state := ""
		if r.Ended == "" {
			state = "  " + cm.Wrap(colorout.Yellow, "(unfinished)")
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

package results

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/fuzz"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/portscan"
	"github.com/trike33/srt-cheatsheet/gotools/internal/recon/probe"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func RunDB(args []string) error {
	if len(args) == 0 {
		return ioutil.ErrMissing("usage: srt db path | stats | import [-kind K] [-name N] <file> | rm <run-id>")
	}
	switch args[0] {
	case "path":
		fmt.Println(store.DBPath())
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
	db, err := store.OpenReadable()
	if err != nil {
		return err
	}
	defer db.Close()
	var runs, recs int
	db.QueryRow(`SELECT COUNT(*) FROM runs`).Scan(&runs)
	db.QueryRow(`SELECT COUNT(*) FROM records`).Scan(&recs)
	size := int64(0)
	if st, err := os.Stat(store.DBPath()); err == nil {
		size = st.Size()
	}
	fmt.Printf("%s\n%d run(s), %d record(s), %s\n", store.DBPath(), runs, recs, netx.HumanBytes(size))
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
		return ioutil.ErrMissing("usage: srt db rm <run-id>")
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("bad run id %q", args[0])
	}
	db, err := store.OpenReadable()
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
	ioutil.Warn("removed run %d", id)
	return nil
}

// dbImport loads a result file into a new run: JSON lines from portscan, fuzz
// or probe are recognized automatically; any other file is stored line by line
// under -kind.
func dbImport(args []string) error {
	fs := flag.NewFlagSet("db import", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "OPTIONS", Names: []string{"kind", "name"}},
		})
	}
	kind := fs.String("kind", "", "record kind for plain-text lines (e.g. subdomain); not needed for portscan/fuzz/probe JSON")
	name := fs.String("name", "", "run name (default: import <file>)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return ioutil.ErrMissing("usage: srt db import [-kind K] [-name N] <file>")
	}
	lines, err := ioutil.InputLines(fs.Arg(0))
	if err != nil {
		return err
	}
	if *name == "" {
		*name = "import " + filepath.Base(fs.Arg(0))
	}
	s, err := store.StartSink(*name, append([]string{"db", "import"}, args...))
	if err != nil {
		return err
	}
	var unparsed int
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if rec, ok := sniffJSONRecord([]byte(l)); ok {
			s.Add(rec)
		} else if *kind != "" {
			s.Add(store.TextRecord(*kind, l))
		} else {
			unparsed++
		}
	}
	s.Close()
	if unparsed > 0 {
		return fmt.Errorf("%d line(s) weren't recognized portscan/fuzz/probe JSON; pass -kind <name> to store plain lines", unparsed)
	}
	return nil
}

// sniffJSONRecord recognizes the JSON-lines output of portscan, fuzz and
// probe, so `db import` and the pipeline can ingest them without a -kind.
func sniffJSONRecord(line []byte) (store.Record, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(line, &m) != nil {
		return store.Record{}, false
	}
	str := func(k string) string {
		var s string
		json.Unmarshal(m[k], &s)
		return s
	}
	num := func(k string) int {
		var n int
		json.Unmarshal(m[k], &n)
		return n
	}
	switch {
	case m["port"] != nil && m["host"] != nil:
		return portscan.Result{Host: str("host"), Port: num("port"), Banner: str("banner")}.Record(), true
	case m["url"] != nil && m["status"] != nil && m["length"] != nil && m["target"] == nil:
		return fuzz.Record(str("url"), fuzz.RespMeta{Status: num("status"), Size: num("length"), Words: num("words"), Lines: num("lines")}), true
	case m["target"] != nil:
		var p probe.Result
		if json.Unmarshal(line, &p) != nil {
			return store.Record{}, false
		}
		return p.Record(), true
	}
	return store.Record{}, false
}

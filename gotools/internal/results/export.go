package results

import (
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
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeDir(host string) string {
	if host == "" {
		return "_global"
	}
	return unsafeName.ReplaceAllString(host, "_")
}

func RunExport(args []string) error {
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
		return ioutil.ErrMissing("export needs -o <dir> (tree) or -o <file> (json/csv)")
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
		ioutil.Warn("exported %d result(s) into %s (%d file(s))", len(recs), *out, n)
		return nil
	}
	return fmt.Errorf("unknown -format %q (want tree, json or csv)", *format)
}

func openOut(path string) (io.WriteCloser, error) { return ioutil.Output(path) }

func exportJSON(recs []store.Record, path string) error {
	w, err := openOut(path)
	if err != nil {
		return err
	}
	defer w.Close()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(recs)
}

func exportCSV(recs []store.Record, path string) error {
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
func exportTree(recs []store.Record, dir string, run int64) (int, error) {
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

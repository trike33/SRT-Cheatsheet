// Package relpaths implements the relpaths command: listing every file
// under a directory as a path relative to it.
package relpaths

import (
	"flag"
	"io/fs"
	"path/filepath"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "relpaths",
		Group:   "misc",
		Summary: "List every file under a directory as a relative path (relative_paths.py)",
		Run:     Run,
	})
}

// Run ports relative_paths.py: walk a directory and print each file's path
// relative to the root. Handy for turning an unpacked CMS/plugin source
// tree into an ffuf wordlist.
func Run(args []string) error {
	fsFlags := flag.NewFlagSet("relpaths", flag.ExitOnError)
	fsFlags.Usage = func() {
		cli.PrintGroupedUsage(fsFlags, []cli.UsageSection{
			{Title: "OUTPUT", Names: []string{"o"}},
		})
	}
	out := fsFlags.String("o", "", "output file (default: stdout)")
	if err := fsFlags.Parse(args); err != nil {
		return err
	}
	if fsFlags.NArg() < 1 {
		return ioutil.ErrMissing("usage: srt relpaths <directory>")
	}
	root := fsFlags.Arg(0)
	defer ioutil.StartHeartbeat("relpaths")()

	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		paths = append(paths, rel)
		return nil
	})
	if err != nil {
		return err
	}

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	return ioutil.WriteLines(w, paths)
}

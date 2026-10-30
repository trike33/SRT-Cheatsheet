package main

import (
	"flag"
	"io/fs"
	"path/filepath"
)

func init() {
	register(&command{
		name:    "relpaths",
		group:   "misc",
		summary: "List every file under a directory as a relative path (relative_paths.py)",
		run:     runRelPaths,
	})
}

// runRelPaths ports relative_paths.py: walk a directory and print each file's
// path relative to the root. Handy for turning an unpacked CMS/plugin source
// tree into an ffuf wordlist.
func runRelPaths(args []string) error {
	fsFlags := flag.NewFlagSet("relpaths", flag.ExitOnError)
	out := fsFlags.String("o", "", "output file (default: stdout)")
	if err := fsFlags.Parse(args); err != nil {
		return err
	}
	if fsFlags.NArg() < 1 {
		return errMissing("usage: srt relpaths <directory>")
	}
	root := fsFlags.Arg(0)
	defer startHeartbeat("relpaths")()

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

	w, err := output(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	return writeLines(w, paths)
}

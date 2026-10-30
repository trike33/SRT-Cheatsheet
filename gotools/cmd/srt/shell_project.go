package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// A "project" in the shell is just the current working directory: its name is
// the directory's base name (/home/user/project1 -> project1). Switching
// projects is os.Chdir, so every command the shell spawns inherits the new
// CWD and its relative paths (wordlists, scope files, srt-pipeline-out/)
// resolve inside the project.

func projectName(dir string) string {
	if b := filepath.Base(dir); b != "." && b != string(filepath.Separator) {
		return b
	}
	return dir
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// switchProject changes into target ("-" = the previous project, "" = home)
// and returns the notice to show. prev is the directory left behind.
func (m *shellModel) switchProject(target string) error {
	cur, _ := os.Getwd()
	switch target {
	case "":
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		target = home
	case "-":
		if m.prevDir == "" {
			return fmt.Errorf("no previous project")
		}
		target = m.prevDir
	}
	if err := os.Chdir(expandHome(target)); err != nil {
		return fmt.Errorf("project: %v", err)
	}
	m.prevDir = cur
	now, _ := os.Getwd()
	m.notice = "project: " + projectName(now)
	host, web := detectScopeFiles(now)
	var found []string
	if host != "" {
		found = append(found, filepath.Base(host))
	}
	if web != "" {
		found = append(found, filepath.Base(web))
	}
	if len(found) > 0 {
		m.notice += " (scope: " + strings.Join(found, ", ") + ")"
	}
	return nil
}

// completeDirArg completes the directory being typed as the 2nd word of
// cd/project: a unique match completes fully (with a trailing /), several
// matches extend to their longest common prefix.
func (m *shellModel) completeDirArg() {
	line := string(m.input[:m.cursor])
	sp := strings.IndexByte(line, ' ')
	if sp < 0 {
		return
	}
	cmd, arg := line[:sp], strings.TrimLeft(line[sp:], " ")
	if (cmd != "cd" && cmd != "project") || strings.ContainsAny(arg, " \"'") {
		return
	}

	dirPart, base := filepath.Split(arg)
	listDir := expandHome(dirPart)
	if listDir == "" {
		listDir = "."
	}
	entries, err := os.ReadDir(listDir)
	if err != nil {
		return
	}
	var matches []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), base) || (strings.HasPrefix(e.Name(), ".") && !strings.HasPrefix(base, ".")) {
			continue
		}
		if e.IsDir() || isDirLink(filepath.Join(listDir, e.Name())) {
			matches = append(matches, e.Name())
		}
	}
	if len(matches) == 0 {
		return
	}
	sort.Strings(matches)
	comp := commonPrefix(matches)
	if len(matches) == 1 {
		comp += "/"
	}
	if comp == base {
		return
	}
	newArg := dirPart + comp
	m.input = append([]rune(cmd+" "+newArg), m.input[m.cursor:]...)
	m.cursor = len([]rune(cmd + " " + newArg))
}

func isDirLink(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func commonPrefix(ss []string) string {
	p := ss[0]
	for _, s := range ss[1:] {
		for !strings.HasPrefix(s, p) {
			p = p[:len(p)-1]
		}
	}
	return p
}

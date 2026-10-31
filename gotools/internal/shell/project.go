package shell

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/trike33/srt-cheatsheet/gotools/internal/scope"
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
	host, web := scope.DetectScopeFiles(now)
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

// completePathArg completes a file or directory path for whichever word the
// cursor is in, bash-style: cd/project still restrict matches to directories
// only (their sole argument is always a path to switch into), every other
// command completes both files and directories, so wordlists, scope files
// and other path arguments at any position get the same tab-completion a
// shell gives them. A unique match completes fully (directories get a
// trailing /), several matches extend to their longest common prefix.
func (m *shellModel) completePathArg() {
	line := m.input[:m.cursor]
	wordStart := len(line)
	for wordStart > 0 && line[wordStart-1] != ' ' && line[wordStart-1] != '\t' {
		wordStart--
	}
	if wordStart == 0 {
		// Cursor is still in the first word (the command name itself);
		// completeCommandName owns that case.
		return
	}

	cmdEnd := 0
	for cmdEnd < len(m.input) && m.input[cmdEnd] != ' ' && m.input[cmdEnd] != '\t' {
		cmdEnd++
	}
	cmdName := string(m.input[:cmdEnd])
	dirsOnly := cmdName == "cd" || cmdName == "project"

	arg := string(line[wordStart:])
	if strings.ContainsAny(arg, " \"'") {
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
		isDir := e.IsDir() || isDirLink(filepath.Join(listDir, e.Name()))
		if dirsOnly && !isDir {
			continue
		}
		name := e.Name()
		if isDir {
			name += "/"
		}
		matches = append(matches, name)
	}
	if len(matches) == 0 {
		return
	}
	sort.Strings(matches)
	comp := commonPrefix(matches)
	if comp == base {
		return
	}
	newArg := dirPart + comp
	prefix := string(m.input[:wordStart])
	rest := m.input[m.cursor:]
	m.input = append([]rune(prefix+newArg), rest...)
	m.cursor = len([]rune(prefix + newArg))
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

package scope

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// "target_assets.json", "target_assets(1).json", "target_assets (2).json",
	// "target-assets_copy.json" ...
	webScopeNameRe = regexp.MustCompile(`(?i)^target[-_ ]?assets.*\.json$`)
	// "acme-in-scope", "in_scope.txt", "Acme-InScope-ips.txt" ...
	hostScopeNameRe = regexp.MustCompile(`(?i)in[-_ ]?scope`)
)

// DetectScopeFiles looks in dir (non-recursively) for the conventional scope
// files: a host scope list (*-in-scope*) and a Burp web scope export
// (target_assets*.json, tolerating browser-download suffixes like "(1)").
// When several match, the most recently modified wins, since a re-downloaded
// export is the one the user means. Missing kinds come back empty.
func DetectScopeFiles(dir string) (hostFile, webScope string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", ""
	}
	var hostMod, webMod int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		name, mod := e.Name(), info.ModTime().UnixNano()
		switch {
		case webScopeNameRe.MatchString(name):
			if webScope == "" || mod > webMod {
				webScope, webMod = filepath.Join(dir, name), mod
			}
		case hostScopeNameRe.MatchString(name) && !strings.HasSuffix(strings.ToLower(name), ".json"):
			if hostFile == "" || mod > hostMod {
				hostFile, hostMod = filepath.Join(dir, name), mod
			}
		}
	}
	return hostFile, webScope
}

package pipeline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/scope"
)

// crawlForm is one HTML form katana extracted: where it submits and the
// field names it carries -- parameter names the site declares itself.
type crawlForm struct {
	Method string
	Action string
	Params []string
}

// parseKatana reads katana's JSON-lines output: every crawled endpoint, and
// the forms found on those pages. Lines that aren't JSON are ignored (a
// killed katana can leave a truncated last line).
func parseKatana(file string) (endpoints []string, forms []crawlForm) {
	f, err := os.Open(file)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		var r struct {
			Request struct {
				Endpoint string `json:"endpoint"`
			} `json:"request"`
			Response struct {
				Forms []struct {
					Method     string   `json:"method"`
					Action     string   `json:"action"`
					Parameters []string `json:"parameters"`
				} `json:"forms"`
			} `json:"response"`
		}
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		if r.Request.Endpoint != "" {
			endpoints = append(endpoints, r.Request.Endpoint)
		}
		for _, fm := range r.Response.Forms {
			if fm.Action == "" {
				continue
			}
			forms = append(forms, crawlForm{strings.ToUpper(fm.Method), fm.Action, fm.Parameters})
		}
	}
	return endpoints, forms
}

// crawlTargets runs katana against every explicit web target (when
// options.crawl/-no-crawl allows it) and returns the endpoints it found,
// the forms it extracted, and a step per call. When a Burp scope file is
// configured for a target, crawled URLs outside it are dropped. Skips
// cleanly when katana isn't installed. Pulled out of runWebStage so it's
// testable with a fake katana on PATH.
func crawlTargets(cfg *pipelineConfig, outDir string) (urls []string, forms []crawlForm, steps []stepResult) {
	if !cfg.Options.crawlOrDefault(true) {
		return nil, nil, nil
	}
	for _, e := range cfg.Web {
		if e.Target == "" {
			continue
		}
		target := baseURL(e.Target)
		file := filepath.Join(outDir, "05b_katana_"+safeName(target)+".jsonl")
		steps = append(steps, runExternal("web", "katana", target, "katana",
			katanaArgs(target, cfg.Options.CrawlDepth, cfg.Options.Rate, cfg.Options.Concurrency, cfg.Options.Proxy), file))

		eps, fms := parseKatana(file)
		scopeFile := e.Scope
		if scopeFile == "" {
			scopeFile = cfg.Options.Scope
		}
		if scopeFile != "" {
			if m, err := scope.LoadScopeMatcher(scopeFile); err == nil {
				keep := func(u string) bool { return m.InScope(u) }
				eps = filterStrings(eps, keep)
				var kept []crawlForm
				for _, f := range fms {
					if keep(f.Action) {
						kept = append(kept, f)
					}
				}
				fms = kept
			} else {
				ioutil.Warn("katana %s: scope %s: %v (crawl results kept unfiltered)", target, scopeFile, err)
			}
		}
		urls = append(urls, eps...)
		for _, f := range fms {
			urls = append(urls, f.Action)
		}
		forms = append(forms, fms...)
	}
	return ioutil.DedupStrings(urls), forms, steps
}

func filterStrings(in []string, keep func(string) bool) []string {
	var out []string
	for _, s := range in {
		if keep(s) {
			out = append(out, s)
		}
	}
	return out
}

// writeForms writes the extracted forms, one per line:
// "METHOD action  param,param,..." deduplicated and sorted -- the
// parameter names the site's own forms declare.
func writeForms(path string, forms []crawlForm) error {
	seen := map[string]bool{}
	var lines []string
	for _, f := range forms {
		p := append([]string(nil), f.Params...)
		sort.Strings(p)
		l := fmt.Sprintf("%s %s  %s", f.Method, f.Action, strings.Join(p, ","))
		if !seen[l] {
			seen[l] = true
			lines = append(lines, l)
		}
	}
	sort.Strings(lines)
	return writeLinesFile(path, lines)
}

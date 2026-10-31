package pipeline

import (
	"encoding/json"
	"os"
	"sync"
)

// pipelineCheckpoint records which pipeline steps finished OK so an
// interrupted run (`pipeline -resume`) skips straight past them. A step is
// identified by kind|name|target|output; the output file must still exist for
// the skip to apply. Steps interrupted mid-way aren't recorded, so they rerun
// -- and the long ones (portscan, fuzz) carry their own -resume state files so
// even those continue rather than restart.
type pipelineCheckpoint struct {
	mu   sync.Mutex
	path string
	done map[string]bool
	// resumed: this run continues an earlier one (-resume). A fresh run must
	// also discard stale per-step state files, or a leftover would be
	// mistaken for progress.
	resumed bool
}

// activeCheckpoint is nil unless the run was started with -resume.
var activeCheckpoint *pipelineCheckpoint

func stepKey(kind, name, target, output string) string {
	return kind + "|" + name + "|" + target + "|" + output
}

// loadCheckpoint opens path; keep=false starts fresh, discarding any old one.
func loadCheckpoint(path string, keep bool) *pipelineCheckpoint {
	c := &pipelineCheckpoint{path: path, done: map[string]bool{}, resumed: keep}
	if keep {
		if b, err := os.ReadFile(path); err == nil {
			var keys []string
			if json.Unmarshal(b, &keys) == nil {
				for _, k := range keys {
					c.done[k] = true
				}
			}
		}
	}
	c.save()
	return c
}

func (c *pipelineCheckpoint) has(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.done[key]
}

func (c *pipelineCheckpoint) mark(key string) {
	c.mu.Lock()
	c.done[key] = true
	c.mu.Unlock()
	c.save()
}

func (c *pipelineCheckpoint) save() {
	c.mu.Lock()
	keys := make([]string, 0, len(c.done))
	for k := range c.done {
		keys = append(keys, k)
	}
	c.mu.Unlock()
	if b, err := json.Marshal(keys); err == nil {
		_ = os.WriteFile(c.path, b, 0o644)
	}
}

// resumeStateArgs returns the extra "-resume <file>" args for a long-running
// step when the pipeline itself is resumable, else nothing.
func resumeStateArgs(outputFile string) []string {
	if activeCheckpoint == nil || outputFile == "" {
		return nil
	}
	state := outputFile + ".state"
	if !activeCheckpoint.resumed {
		os.Remove(state)
	}
	return []string{"-resume", state}
}

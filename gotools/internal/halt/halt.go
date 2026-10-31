// Package halt centralizes how srt reacts to being stopped early -- Ctrl+C,
// SIGTERM, or a traffic-limit breach -- so every way a command can end
// abruptly runs the same cleanup (flush resume state, write traffic totals)
// before the process exits. That is what makes an interrupted scan
// resumable: its state is on disk and current by the time the process dies.
package halt

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var (
	mu    sync.Mutex
	hooks []func()
)

// On registers fn to run (once, in registration order) before the process
// exits because of a halt. The returned cancel func unregisters it for the
// normal path, where the command finishes and flushes on its own.
func On(fn func()) (cancel func()) {
	mu.Lock()
	defer mu.Unlock()
	hooks = append(hooks, fn)
	idx := len(hooks) - 1
	return func() {
		mu.Lock()
		defer mu.Unlock()
		hooks[idx] = nil
	}
}

// Run runs every registered hook once and clears the list.
func Run() {
	mu.Lock()
	run := hooks
	hooks = nil
	mu.Unlock()
	for _, h := range run {
		if h != nil {
			h()
		}
	}
}

// InstallHandler turns SIGINT/SIGTERM into: run every hook, report, exit 130.
// report, if non-nil, supplies one extra line of context (e.g. traffic
// totals) appended to the halt message.
func InstallHandler(report func() string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		Run()
		msg := "srt: halted by user"
		if report != nil {
			if r := report(); r != "" {
				msg += " — " + r
			}
		}
		fmt.Fprintf(os.Stderr, "\n%s\n", msg)
		os.Exit(130)
	}()
}

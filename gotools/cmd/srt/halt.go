package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// Halt handling is central so every way a command can be stopped early --
// Ctrl+C, SIGTERM, or a traffic-limit breach -- first runs the registered
// hooks (flush resume state, write traffic totals) and then exits. That is
// what makes an interrupted scan resumable: its state is on disk and current.

var (
	haltMu    sync.Mutex
	haltHooks []func()
)

// onHalt registers fn to run (once, in registration order) before the process
// exits because of a halt. The returned func unregisters it for the normal
// path, where the command finishes and flushes on its own.
func onHalt(fn func()) (cancel func()) {
	haltMu.Lock()
	defer haltMu.Unlock()
	haltHooks = append(haltHooks, fn)
	idx := len(haltHooks) - 1
	return func() {
		haltMu.Lock()
		defer haltMu.Unlock()
		haltHooks[idx] = nil
	}
}

func runHaltHooks() {
	haltMu.Lock()
	hooks := haltHooks
	haltHooks = nil
	haltMu.Unlock()
	for _, h := range hooks {
		if h != nil {
			h()
		}
	}
}

// installHaltHandler turns SIGINT/SIGTERM into: run hooks, report, exit 130.
func installHaltHandler(report func() string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		runHaltHooks()
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

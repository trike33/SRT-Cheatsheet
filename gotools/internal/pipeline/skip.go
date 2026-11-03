package pipeline

import (
	"os"
	"syscall"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/fuzzctl"
	"github.com/trike33/srt-cheatsheet/gotools/internal/halt"
	"golang.org/x/term"
)

// skipKey is the key that abandons the step currently running.
const skipKey = 's'

// activeSkip is the skip-key listener for the run in progress. It's nil for
// a non-interactive run (stdin isn't a terminal, e.g. piped input or CI),
// in which case every runStep call just waits for its step like before --
// skipChan on a nil *skipListener returns nil, and a nil channel in a
// select is never ready, so it adds no behavior there.
var activeSkip *skipListener

// skipListener reads raw keypresses from stdin for the lifetime of a
// pipeline run and reports when the user presses skipKey, so runStep can
// abandon the step in progress instead of waiting on it. It's one key, not
// a line: no step in the pipeline itself reads stdin, so holding it in raw
// mode for the run's duration doesn't take anything away from a command.
type skipListener struct {
	requests chan struct{}
	fd       int
	oldState *term.State
	done     chan struct{} // ends the control-file poller (shell mode)
	// rfile is a dup of fd that read()'s loop actually reads from (nil in
	// shell/control-file mode, fd < 0). Reading from a dup rather than
	// os.Stdin directly lets pause() force that blocked read to return (by
	// closing the dup) without touching the real stdin fd, so a second
	// reader -- the manual-fuzz cherrypick prompts -- can safely take over
	// os.Stdin right after, with no race between the two for the next byte
	// typed. A bare os.Stdin.Read, once blocked, can't be cancelled at all.
	rfile *os.File
}

// startControlSkipListener is the skip listener for a pipeline run by the
// srt shell: there is no terminal on its stdin, so the shell asks for a skip
// (Ctrl+S) through the fuzzctl control file, which is polled here.
func startControlSkipListener(path string) *skipListener {
	sl := &skipListener{requests: make(chan struct{}, 1), fd: -1, done: make(chan struct{})}
	seen := fuzzctl.ReadControl(path).Skip
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-sl.done:
				return
			case <-t.C:
				if n := fuzzctl.ReadControl(path).Skip; n > seen {
					seen = n
					select {
					case sl.requests <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	return sl
}

// startSkipListener installs the listener for one pipeline run, or returns
// nil if stdin isn't a terminal. Callers must defer its stop method to
// restore the terminal, however the run ends.
func startSkipListener() *skipListener {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		if p := os.Getenv(fuzzctl.EnvControl); p != "" {
			return startControlSkipListener(p)
		}
		return nil
	}
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil
	}
	sl := &skipListener{requests: make(chan struct{}, 1), fd: fd, oldState: oldState}
	sl.dupAndRead()
	return sl
}

// dupAndRead duplicates sl.fd into sl.rfile and starts read() reading from
// it, so a later pause() can retire that exact fd without disturbing the
// real stdin fd. Falls back to reading os.Stdin directly (the old,
// un-pausable behavior) if the dup fails, which should never happen in
// practice.
func (sl *skipListener) dupAndRead() {
	dfd, err := syscall.Dup(sl.fd)
	if err != nil {
		sl.rfile = nil
	} else {
		sl.rfile = os.NewFile(uintptr(dfd), "stdin-skip")
	}
	go sl.read()
}

// read is the raw-mode stdin loop. Raw mode disables the terminal's own
// Ctrl+C-to-SIGINT translation, so Ctrl+C would otherwise arrive here as an
// ordinary byte (0x03) and do nothing; this loop watches for it directly
// and replicates halt.InstallHandler's usual SIGINT behavior so Ctrl+C
// keeps halting the whole run exactly as before.
func (sl *skipListener) read() {
	rf := sl.rfile
	if rf == nil {
		rf = os.Stdin
	}
	buf := make([]byte, 1)
	for {
		n, err := rf.Read(buf)
		if err != nil || n == 0 {
			return
		}
		switch buf[0] {
		case skipKey, skipKey - 'a' + 'A':
			select {
			case sl.requests <- struct{}{}:
			default: // a skip is already pending; the keypress is redundant
			}
		case 3: // Ctrl+C
			sl.restore()
			halt.Run()
			os.Exit(130)
		}
	}
}

func (sl *skipListener) restore() {
	if sl.oldState != nil {
		term.Restore(sl.fd, sl.oldState)
	}
	if sl.rfile != nil {
		sl.rfile.Close() // unblocks read()'s pending Read so that goroutine exits
		sl.rfile = nil
	}
}

// stop restores the terminal's normal mode. Safe to call on a nil listener.
func (sl *skipListener) stop() {
	if sl == nil {
		return
	}
	if sl.done != nil {
		close(sl.done)
	}
	sl.restore()
}

// pause temporarily restores normal (cooked, echoing) stdin mode and retires
// the skip-key listener's own reader, so pipeline code can safely read
// line-based input from the user -- the manual-fuzz cherrypick prompts are
// the only caller. It returns a resume func that re-enters raw mode and
// restarts skip-key detection; callers must call it exactly once, after
// they're done reading, even on an error path (defer it).
//
// A nil listener, or one with no real terminal to pause (fd < 0: the srt
// shell's control-file mode, which has no terminal on this process's stdin
// at all), is a no-op in both directions -- callers in that situation must
// not attempt interactive prompts in the first place.
func (sl *skipListener) pause() func() {
	if sl == nil || sl.fd < 0 {
		return func() {}
	}
	sl.restore()
	return func() {
		oldState, err := term.MakeRaw(sl.fd)
		if err != nil {
			return
		}
		sl.oldState = oldState
		sl.dupAndRead()
	}
}

// interactive reports whether sl has a real terminal a caller could pause()
// to read line-based prompts from (nil or shell/control-file mode: no).
func (sl *skipListener) interactive() bool {
	return sl != nil && sl.fd >= 0
}

// skipChan returns the channel a select waits on to abandon the current
// step, or nil on a nil listener -- a nil channel blocks forever in a
// select, which is exactly "there's nothing to skip to" for that case.
func (sl *skipListener) skipChan() <-chan struct{} {
	if sl == nil {
		return nil
	}
	return sl.requests
}

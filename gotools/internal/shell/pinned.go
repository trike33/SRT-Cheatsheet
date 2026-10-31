package shell

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
)

// pinnedExec runs a command with the shell's header pinned at the top of the
// screen and kept live. While a command runs, Bubble Tea has handed the
// terminal over, so the view can't redraw; instead the header rows are
// reserved with a scroll region (the command's output scrolls below them) and
// redrawn from here every tick using the traffic totals the child persists to
// its handoff file. When the command ends the pinned header is removed again,
// so the redrawn view's own header isn't duplicated.
type pinnedExec struct {
	cmd         *exec.Cmd
	trafficFile string
	header      func(live netx.Totals, rate float64) string // full header, including live totals and req/s

	out io.Writer
}

func (p *pinnedExec) SetStdin(r io.Reader)  { p.cmd.Stdin = r }
func (p *pinnedExec) SetStdout(w io.Writer) { p.cmd.Stdout = w; p.out = w }
func (p *pinnedExec) SetStderr(w io.Writer) { p.cmd.Stderr = w }

func (p *pinnedExec) Run() error {
	f, ok := p.out.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return p.cmd.Run()
	}
	_, rows, err := term.GetSize(int(f.Fd()))
	// Reserve for the header at its widest (largest plausible totals), so it
	// never grows into the command's output as numbers get longer.
	big := netx.Totals{Requests: 999_999_999, BytesOut: 1 << 40, BytesIn: 1 << 40}
	hRows := max(strings.Count(p.header(netx.Totals{}, 0), "\n"), strings.Count(p.header(big, 999), "\n")) + 1
	if err != nil || rows < hRows+6 {
		return p.cmd.Run() // too short a terminal to spare the rows
	}

	var mu sync.Mutex // one escape sequence at a time from this side
	draw := func(live netx.Totals, rate float64, restoreCursor bool) {
		mu.Lock()
		defer mu.Unlock()
		var b strings.Builder
		if restoreCursor {
			b.WriteString("\x1b7")
		}
		lines := strings.Split(p.header(live, rate), "\n")
		for i := 0; i < hRows; i++ { // exactly the reserved rows, even if the header's height shifts
			line := ""
			if i < len(lines) {
				line = lines[i]
			}
			fmt.Fprintf(&b, "\x1b[%d;1H%s\x1b[K", i+1, line)
		}
		if restoreCursor {
			b.WriteString("\x1b8")
		}
		io.WriteString(f, b.String())
	}

	// Clear, draw the header, confine scrolling to the rows below it.
	io.WriteString(f, "\x1b[2J")
	draw(netx.Totals{}, 0, false)
	fmt.Fprintf(f, "\x1b[%d;%dr\x1b[%d;1H", hRows+1, rows, hRows+1)

	if err := p.cmd.Start(); err != nil {
		p.unpin(f, hRows)
		return err
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(400 * time.Millisecond)
		defer t.Stop()
		var last netx.Totals
		lastAt := time.Now()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if live, ok := netx.ReadTrafficFile(p.trafficFile); ok && live != last {
					now := time.Now()
					rate := float64(live.Requests-last.Requests) / now.Sub(lastAt).Seconds()
					last, lastAt = live, now
					draw(live, rate, true)
				}
			}
		}
	}()

	runErr := p.cmd.Wait()
	close(stop)
	<-done
	p.unpin(f, hRows)
	return runErr
}

// unpin releases the scroll region and deletes the header rows, shifting the
// command's output up into their place and leaving the cursor where the
// output ended.
func (p *pinnedExec) unpin(f *os.File, hRows int) {
	fmt.Fprintf(f, "\x1b7\x1b[r\x1b[1;1H\x1b[%dM\x1b8\x1b[%dA", hRows, hRows)
}

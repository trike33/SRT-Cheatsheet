package pipeline

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// TestHostStageFlagsBeanShellByBanner exercises the real runHostStage
// against a loopback listener that sends BeanShell's real startup banner on
// connect, the same way TestHostStageGroupsByPorts exercises portscan
// itself -- offline-safe (loopback only), but a real classify-services pass
// end to end rather than a unit test of the predicate alone.
func TestHostStageFlagsBeanShellByBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("BeanShell 2.0b4 - by Pat Niemeyer (pat@pat.net)\r\n"))
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parsing port %q: %v", portStr, err)
	}
	// Give the listener goroutine a beat to be ready; portscan's own connect
	// timeout is generous enough that a slow scheduler won't flake this.
	time.Sleep(10 * time.Millisecond)

	dir := t.TempDir()
	cfg := &pipelineConfig{Host: []targetEntry{{Target: "127.0.0.1", Ports: strconv.Itoa(port)}}}
	steps := runHostStage(cfg, dir, true, "")

	var found *stepResult
	for i := range steps {
		if steps[i].Name == "flag-beanshell" {
			found = &steps[i]
		}
	}
	if found == nil {
		var names []string
		for _, s := range steps {
			names = append(names, s.Name+":"+s.Status)
		}
		t.Fatalf("no flag-beanshell step found, got steps: %v", names)
	}
	if found.Status != "ok" {
		t.Errorf("flag-beanshell step status = %q, want ok: %+v", found.Status, found)
	}
}

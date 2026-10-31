package scope

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSetContains(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.txt")
	os.WriteFile(p, []byte("10.0.0.5\n10.1.0.0/24\nnot-an-ip\n"), 0o644)
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Contains(net.ParseIP("10.0.0.5")) {
		t.Error("exact IP should be in scope")
	}
	if !s.Contains(net.ParseIP("10.1.0.42")) {
		t.Error("IP inside the CIDR should be in scope")
	}
	if s.Contains(net.ParseIP("10.2.0.1")) {
		t.Error("unrelated IP must not be in scope")
	}
}

func TestLoadSkipsInvalidEntriesWithoutFailing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.txt")
	os.WriteFile(p, []byte("bad-entry\n10.0.0.1\n"), 0o644)
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Contains(net.ParseIP("10.0.0.1")) {
		t.Error("the valid entry should still load")
	}
}

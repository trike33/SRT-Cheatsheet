package fuzz

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trike33/srt-cheatsheet/gotools/internal/fuzzctl"
)

func TestStatusPerHostAndUserStop(t *testing.T) {
	mk := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/admin" {
				w.Write([]byte("hello admin"))
				return
			}
			http.NotFound(w, r)
		}))
	}
	a, b := mk(), mk()
	defer a.Close()
	defer b.Close()

	dir := t.TempDir()
	wl := filepath.Join(dir, "words.txt")
	os.WriteFile(wl, []byte("admin\nlogin\nfoo\n"), 0o644)
	status := filepath.Join(dir, "status.json")
	control := filepath.Join(dir, "control.json")
	t.Setenv(fuzzctl.EnvStatus, status)
	t.Setenv(fuzzctl.EnvControl, control)

	hostB := strings.TrimPrefix(b.URL, "http://")
	if err := fuzzctl.AddStop(control, hostB); err != nil {
		t.Fatal(err)
	}

	if err := Run([]string{"-u", a.URL + "/FUZZ", "-u", b.URL + "/FUZZ", "-w", wl, "-mc", "200", "-silent", "-waf-403", "0"}); err != nil {
		t.Fatal(err)
	}

	st, ok := fuzzctl.ReadStatus(status)
	if !ok || len(st.Hosts) != 2 {
		t.Fatalf("status = %+v ok=%v", st, ok)
	}
	byHost := map[string]fuzzctl.Host{}
	for _, h := range st.Hosts {
		byHost[h.Host] = h
	}
	ha := byHost[strings.TrimPrefix(a.URL, "http://")]
	if ha.State != fuzzctl.StateDone || ha.Done != 3 || ha.Matches != 1 || ha.Words != 3 || len(ha.Wordlists) != 1 || len(ha.Hits) != 1 {
		t.Errorf("host A = %+v", ha)
	}
	if hb := byHost[hostB]; hb.State != fuzzctl.StateStopped || hb.Done != 0 {
		t.Errorf("host B should be stopped with no requests: %+v", hb)
	}
}

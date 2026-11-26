package results

import (
	"bytes"
	"strings"
	"testing"

	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func TestFilterAccepted(t *testing.T) {
	loginOK := protocols.Finding{
		Target: protocols.Target{Host: "10.0.0.5", Port: 445}, Cred: protocols.Credential{User: "administrator", Domain: "CORP"},
		Kind: "login-ok", Detail: "6 share(s)", Severity: protocols.High, Accepted: true,
	}.Record("smb")
	anonOK := protocols.Finding{
		Target: protocols.Target{Host: "10.0.0.6", Port: 21}, Kind: "anonymous-login", Detail: "listing ok", Severity: protocols.High, Accepted: true,
	}.Record("ftp")
	rejected := protocols.Finding{
		Target: protocols.Target{Host: "10.0.0.7", Port: 22}, Kind: "login-failed", Detail: "every attempt was rejected", Severity: protocols.Info,
	}.Record("ssh")
	connErr := protocols.Finding{Target: protocols.Target{Host: "10.0.0.8", Port: 23}, Err: "connection refused"}.Record("telnet")
	nonProtocol := store.Record{Kind: "port", Data: map[string]any{"ok": true}} // a different kind reusing the same field name must not matter here, but filterAccepted doesn't look at Kind at all

	got := filterAccepted([]store.Record{loginOK, anonOK, rejected, connErr, nonProtocol})
	if len(got) != 3 {
		t.Fatalf("filterAccepted returned %d records, want 3: %+v", len(got), got)
	}
	for _, r := range got {
		if ok, _ := r.Data["ok"].(bool); !ok {
			t.Errorf("filterAccepted kept a record without ok==true: %+v", r)
		}
	}
}

func TestCredTarget(t *testing.T) {
	if got := credTarget(store.Record{Host: "10.0.0.5", Port: 445}); got != "10.0.0.5:445" {
		t.Errorf("credTarget with a port = %q, want %q", got, "10.0.0.5:445")
	}
	if got := credTarget(store.Record{Host: "10.0.0.5"}); got != "10.0.0.5" {
		t.Errorf("credTarget with no port = %q, want %q", got, "10.0.0.5")
	}
}

func TestPrintCredsTable(t *testing.T) {
	recs := []store.Record{
		protocols.Finding{
			Target: protocols.Target{Host: "10.0.0.5", Port: 445}, Cred: protocols.Credential{User: "administrator", Domain: "CORP"},
			Kind: "login-ok", Detail: "6 share(s)", Severity: protocols.High, Hostname: "DC01", Accepted: true,
		}.Record("smb"),
		protocols.Finding{
			Target: protocols.Target{Host: "10.0.0.6", Port: 21}, Kind: "anonymous-login", Detail: "listing ok", Severity: protocols.High, Accepted: true,
		}.Record("ftp"),
	}
	var buf bytes.Buffer
	printCredsTable(&buf, recs, colorout.ParseMode("never"))
	out := buf.String()

	if !strings.Contains(out, "PROTO") || !strings.Contains(out, "HOSTNAME") {
		t.Fatalf("missing header: %q", out)
	}
	if !strings.Contains(out, "SMB") || !strings.Contains(out, "10.0.0.5:445") || !strings.Contains(out, "DC01") || !strings.Contains(out, `CORP\administrator`) {
		t.Errorf("smb row missing expected fields: %q", out)
	}
	if !strings.Contains(out, "FTP") || !strings.Contains(out, "10.0.0.6:21") || !strings.Contains(out, "(anonymous)") || !strings.Contains(out, "listing ok") {
		t.Errorf("ftp row missing expected fields (hostname should fall back to the bare host, cred to \"(anonymous)\"): %q", out)
	}
}

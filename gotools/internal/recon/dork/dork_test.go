package dork

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGeneratesURLsWithoutNetworkByDefault(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.txt")
	if err := Run([]string{"-d", "example.com", "-categories", "admin", "-o", out}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(b))
	if !strings.HasPrefix(got, "[admin] https://www.google.com/search?q=") {
		t.Errorf("got %q", got)
	}
}

func TestRunMissingTargetErrors(t *testing.T) {
	if err := Run([]string{"-search"}); err == nil {
		t.Error("expected an error with no -d/-l/-name")
	}
}

func TestRunSearchMissingCredentialsErrors(t *testing.T) {
	t.Setenv(EnvAPIKey, "")
	t.Setenv(EnvCX, "")
	if err := Run([]string{"-d", "example.com", "-search"}); err == nil {
		t.Error("expected an error: -search with no key/cx configured")
	}
}

func TestRunSearchEndToEndAgainstFakeAPI(t *testing.T) {
	withTempQuotaFile(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]string{
				{"title": "Admin", "link": "https://a.test/admin"},
			},
		})
	}))
	defer srv.Close()
	searchEndpoint = srv.URL
	defer func() { searchEndpoint = "https://www.googleapis.com/customsearch/v1" }()

	dir := t.TempDir()
	out := filepath.Join(dir, "out.txt")
	err := Run([]string{"-d", "example.com", "-categories", "admin", "-search", "-api-key", "k", "-cx", "c", "-delay", "0", "-o", out})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if strings.TrimSpace(string(b)) != "https://a.test/admin" {
		t.Errorf("out = %q", b)
	}
}

func TestRunStopsSearchingOnceDailyQuotaReached(t *testing.T) {
	withTempQuotaFile(t)
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]string{{"title": "x", "link": "https://a.test/x" + r.URL.Query().Get("q")}},
		})
	}))
	defer srv.Close()
	searchEndpoint = srv.URL
	defer func() { searchEndpoint = "https://www.googleapis.com/customsearch/v1" }()

	dir := t.TempDir()
	out := filepath.Join(dir, "out.txt")
	// 6 domain categories generated for one domain, but -max-daily caps it
	// at 2: only 2 requests should ever reach the fake API, not 6.
	if err := Run([]string{"-d", "example.com", "-search", "-api-key", "k", "-cx", "c", "-delay", "0", "-max-daily", "2", "-o", out}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("fake API received %d call(s), want exactly 2 (the daily cap)", calls)
	}

	// A second Run (e.g. a later `srt dork`/`srt pipeline -dork` the same
	// day) must see the quota as already spent and send nothing at all.
	out2 := filepath.Join(dir, "out2.txt")
	if err := Run([]string{"-d", "example.com", "-search", "-api-key", "k", "-cx", "c", "-delay", "0", "-max-daily", "2", "-o", out2}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("fake API received %d call(s) total, want still 2 -- the quota must persist across separate Run() invocations the same day", calls)
	}
}

func TestRunMaxDailyMustBePositive(t *testing.T) {
	withTempQuotaFile(t)
	if err := Run([]string{"-d", "example.com", "-search", "-api-key", "k", "-cx", "c", "-max-daily", "0"}); err == nil {
		t.Error("expected an error for -max-daily 0")
	}
}

func TestRunListCategoriesExitsCleanly(t *testing.T) {
	if err := Run([]string{"-list-categories"}); err != nil {
		t.Fatal(err)
	}
}

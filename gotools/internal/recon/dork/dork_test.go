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

func TestRunListCategoriesExitsCleanly(t *testing.T) {
	if err := Run([]string{"-list-categories"}); err != nil {
		t.Fatal(err)
	}
}

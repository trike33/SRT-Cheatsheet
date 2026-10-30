package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestActiveBruteForceLoopback(t *testing.T) {
	// "localhost" always resolves via /etc/hosts; a nonsense label almost
	// certainly won't — deterministic and offline-safe.
	candidates := []string{"localhost", "this-label-should-not-resolve-srt-test"}
	live := activeBruteForce(candidates, 2*time.Second, 10)

	found := map[string]bool{}
	for _, l := range live {
		found[l] = true
	}
	if !found["localhost"] {
		t.Errorf("activeBruteForce = %v, want it to include \"localhost\"", live)
	}
	if found["this-label-should-not-resolve-srt-test"] {
		t.Errorf("activeBruteForce = %v, want it to exclude the non-resolving label", live)
	}
}

func TestPassiveSubdomainsParsing(t *testing.T) {
	// A local fixture server standing in for crt.sh, so this test never
	// touches the real network.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			{"name_value":"www.example.com\nexample.com"},
			{"name_value":"*.api.example.com\napi.example.com"},
			{"name_value":"www.example.com"}
		]`))
	}))
	defer srv.Close()

	names, err := passiveSubdomainsFrom(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("passiveSubdomainsFrom: %v", err)
	}

	want := map[string]bool{"www.example.com": true, "example.com": true, "*.api.example.com": true, "api.example.com": true}
	if len(names) != len(want) {
		t.Fatalf("names = %v, want %d deduped entries matching %v", names, len(want), want)
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected name %q in result %v", n, names)
		}
	}
}

func TestPassiveSubdomainsEmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// crt.sh returns a literally empty body for a domain with no certs on record.
	}))
	defer srv.Close()

	names, err := passiveSubdomainsFrom(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("passiveSubdomainsFrom(empty): %v", err)
	}
	if names != nil {
		t.Errorf("names = %v, want nil for an empty response", names)
	}
}

func TestPassiveSubdomainsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := passiveSubdomainsFrom(srv.URL, 5*time.Second); err == nil {
		t.Error("expected an error for a non-200 response")
	}
}

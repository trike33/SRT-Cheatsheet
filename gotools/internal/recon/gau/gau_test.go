package gau

import "testing"

func TestClassifyAndSensitive(t *testing.T) {
	urls := []string{
		"https://x.com/a?id=1",        // sqli + xss
		"https://x.com/go?redirect=x", // open-redirect + ssrf
		"https://x.com/dump.sql",      // sensitive
		"https://x.com/i/logo.png",    // neither
	}
	groups := classifyParams(urls)
	if len(groups["sqli"]) != 1 {
		t.Errorf("sqli group = %d want 1", len(groups["sqli"]))
	}
	if len(groups["open-redirect"]) != 1 {
		t.Errorf("open-redirect group = %d want 1", len(groups["open-redirect"]))
	}
	sens := filterSensitive(urls)
	if len(sens) != 1 || sens[0] != "https://x.com/dump.sql" {
		t.Errorf("filterSensitive = %v want [.../dump.sql]", sens)
	}
}

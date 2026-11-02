package pipeline

import (
	"slices"
	"testing"
)

func TestVulnxProductRecognizesCommonBanners(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6":            "openssh",
		"SSH-2.0-dropbear_2020.81":                           "dropbear",
		"220 (vsFTPd 3.0.3)":                                 "vsftpd",
		"220 ProFTPD 1.3.5e Server ready.":                   "proftpd",
		"220 mail.example.com ESMTP Postfix (Ubuntu)":        "postfix",
		"BeanShell 2.0b4 - by Pat Niemeyer (pat@pat.net)":    "beanshell",
		"-NOAUTH Authentication required for redis.":         "redis",
		"5.7.32-0ubuntu0.18.04.1-log MySQL Community Server": "mysql",
	}
	for banner, want := range cases {
		if got := vulnxProduct(banner); got != want {
			t.Errorf("vulnxProduct(%q) = %q, want %q", banner, got, want)
		}
	}
}

func TestVulnxProductUnrecognizedReturnsEmpty(t *testing.T) {
	if got := vulnxProduct("some random unidentified service banner xyz123"); got != "" {
		t.Errorf("vulnxProduct(unrecognized) = %q, want empty", got)
	}
	if got := vulnxProduct(""); got != "" {
		t.Errorf("vulnxProduct(\"\") = %q, want empty", got)
	}
}

// TestVulnxSearchArgsUsesProductFlag locks in the real CLI usage the
// operator reported: `vulnx search -p <product>` (verified against the
// actual built binary, not just vulnx's docs) -- no positional query
// alongside -p, since the product filter alone is the precise form.
func TestVulnxSearchArgsUsesProductFlag(t *testing.T) {
	got := vulnxSearchArgs("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
	want := []string{"search", "--json", "--silent", "--limit", "5", "-p", "openssh"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestVulnxSearchArgsFallsBackToFreeText covers a banner vulnxProduct
// doesn't recognize: the old free-text-query behavior, not a guessed -p.
func TestVulnxSearchArgsFallsBackToFreeText(t *testing.T) {
	got := vulnxSearchArgs("Some Unidentified Service 1.2.3")
	want := []string{"search", "--json", "--silent", "--limit", "5", "Some Unidentified Service 1.2.3"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestVulnxQueryTruncatesPathologicalBanner(t *testing.T) {
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'a'
	}
	got := vulnxQuery(string(long))
	if len(got) != 150 {
		t.Errorf("len(vulnxQuery(500 chars)) = %d, want 150", len(got))
	}
}

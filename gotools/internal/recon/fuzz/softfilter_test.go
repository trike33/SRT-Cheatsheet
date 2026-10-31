package fuzz

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func meta(status, size, words int, body string) RespMeta {
	return RespMeta{Status: status, Size: size, Words: words, Body: []byte(body)}
}

func TestSoftFilterToleratesJitter(t *testing.T) {
	c := newCalibData(1.0, 0)
	for _, sz := range []int{3302, 3305} {
		c.addCalibrated(meta(200, sz, 400, ""), "")
	}
	for _, sz := range []int{3302, 3305, 3310, 3312} {
		if !c.matches(meta(200, sz, 400, ""), "") {
			t.Errorf("size %d should match the soft-404 band", sz)
		}
	}
	if c.matches(meta(200, 5000, 400, ""), "") {
		t.Error("a clearly different size must not match")
	}
	if c.matches(meta(200, 3305, 900, ""), "") {
		t.Error("same size but very different word count is a different page")
	}
	if c.matches(meta(403, 3305, 400, ""), "") {
		t.Error("status must match")
	}
}

func TestSoftFilterExactWhenTolZero(t *testing.T) {
	c := newCalibData(0, 0)
	c.addCalibrated(meta(200, 3305, 400, ""), "")
	if !c.matches(meta(200, 3305, 400, ""), "") || c.matches(meta(200, 3306, 400, ""), "") {
		t.Error("tol=0 must be exact")
	}
}

func TestNormalizedSizeRemovesReflection(t *testing.T) {
	// "<p>nope: WORD</p>" echoed twice; size depends on the word's length.
	body := func(w string) RespMeta {
		b := "x nope " + w + " y " + w
		return meta(200, len(b), 5, b)
	}
	a, b := body("ab"), body("abcdefghijklmnop")
	if normalizedSize(a, "ab") != normalizedSize(b, "abcdefghijklmnop") {
		t.Errorf("normalized sizes differ: %d vs %d", normalizedSize(a, "ab"), normalizedSize(b, "abcdefghijklmnop"))
	}
}

func TestBandDoesNotSnowball(t *testing.T) {
	c := newCalibData(1.0, 0) // tol ~ 33 bytes at 3300
	for sz := 3300; sz < 3300+400; sz += 20 {
		c.addCalibrated(meta(200, sz, 400, ""), "")
	}
	if c.matches(meta(200, 3300+380, 400, ""), "") && c.matches(meta(200, 3300, 400, ""), "") && len(c.filter) == 1 {
		t.Error("chained near-misses must not merge into one huge band")
	}
}

func TestLearnsUncalibratedSoftNotFound(t *testing.T) {
	c := newCalibData(1.0, 5)
	var learned string
	for i := 0; i < 5; i++ {
		if c.matches(meta(200, 1200+i*3, 150, ""), "") {
			t.Fatalf("hit %d filtered too early", i)
		}
		if m := c.observe(meta(200, 1200+i*3, 150, ""), ""); m != "" {
			learned = m
		}
	}
	if learned == "" {
		t.Fatal("expected a learned message after 5 clustered hits")
	}
	if !c.matches(meta(200, 1210, 150, ""), "") {
		t.Error("later hits in the cluster should now be filtered")
	}
	if c.matches(meta(200, 9000, 800, ""), "") {
		t.Error("an unrelated response must still be reported")
	}
}

func TestDistinctResponsesNeverLearned(t *testing.T) {
	c := newCalibData(1.0, 5)
	for i := 0; i < 50; i++ {
		c.observe(meta(200, 1000+i*500, 100+i*40, ""), "")
	}
	if len(c.filter) != 0 {
		t.Errorf("distinct pages were learned as soft-404: %s", c.describe())
	}
}

// End to end: an app answers every unknown path with a 200 whose length
// jitters 3302..3312, while /admin is a real, different page.
func TestFuzzFiltersJitteryWildcard(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			fmt.Fprint(w, strings.Repeat("secret admin panel content ", 120))
			return
		}
		n++
		fmt.Fprint(w, strings.Repeat("not found page ", 150), strings.Repeat("x", 3302-len("not found page ")*150+(n*7)%11))
	}))
	defer srv.Close()

	dir := t.TempDir()
	wl, out := filepath.Join(dir, "w.txt"), filepath.Join(dir, "o.json")
	var words []string
	for i := 0; i < 60; i++ {
		words = append(words, fmt.Sprintf("page%d", i))
	}
	words = append(words, "admin")
	os.WriteFile(wl, []byte(strings.Join(words, "\n")), 0o644)

	if err := Run([]string{"-u", srv.URL + "/FUZZ", "-w", wl, "-mc", "200", "-ac", "-json", "-o", out, "-c", "1"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "/admin") {
		t.Fatalf("want only /admin reported, got %d lines:\n%s", len(lines), b)
	}
}

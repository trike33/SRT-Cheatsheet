package snyk

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.10.0", "2.9.0", 1}, // numeric, not lexicographic
		{"2.9.0", "2.10.0", -1},
		{"3.7", "3.7.0", 0}, // shorthand == padded
		{"3.7.2", "3.7.2", 0},
		{"1.0.0", "1.0.1", -1},
		{"2.4.1-beta", "2.4.1", 0}, // suffix ignored
		{"3", "2.9.9", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionMatchesConstraints(t *testing.T) {
	cases := []struct {
		version    string
		constraint string
		want       bool
	}{
		{"3.7", ">=3.0.0, <3.7.2", true},    // inside range
		{"3.7.2", ">=3.0.0, <3.7.2", false}, // upper bound exclusive
		{"2.9", ">=3.0.0, <3.7.2", false},   // below range
		{"2.4.1", "<2.4.2", true},
		{"2.4.2", "<2.4.2", false},
		{"1.2.3", ">=1.0.0 <2.0.0", true}, // space-separated comparators
		{"2.4.1", "2.4.1", true},          // bare version = exact
		{"2.4.0", "2.4.1", false},
		{"1.0.0", "garbage", false}, // unparseable => no match
	}
	for _, c := range cases {
		if got := versionMatchesConstraints(c.version, c.constraint); got != c.want {
			t.Errorf("versionMatchesConstraints(%q,%q)=%v want %v", c.version, c.constraint, got, c.want)
		}
	}
}

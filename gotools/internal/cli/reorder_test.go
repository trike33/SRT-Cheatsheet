package cli

import (
	"flag"
	"reflect"
	"testing"
)

func newTestFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("u", "", "user")
	fs.String("p", "", "password")
	fs.Bool("local-enum", true, "local enum")
	return fs
}

func TestReorderArgsFlagsAfterPositional(t *testing.T) {
	fs := newTestFlagSet()
	got := ReorderArgs(fs, []string{"10.0.0.5", "-u", "bob", "-p", "secret"})
	want := []string{"-u", "bob", "-p", "secret", "10.0.0.5"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderArgsFlagsAlreadyFirst(t *testing.T) {
	fs := newTestFlagSet()
	args := []string{"-u", "bob", "-p", "secret", "10.0.0.5"}
	got := ReorderArgs(fs, args)
	if !reflect.DeepEqual(got, args) {
		t.Errorf("got %v, want %v (unchanged)", got, args)
	}
}

func TestReorderArgsBoolFlagAfterPositional(t *testing.T) {
	fs := newTestFlagSet()
	got := ReorderArgs(fs, []string{"10.0.0.5", "-local-enum=false", "10.0.0.6"})
	want := []string{"-local-enum=false", "10.0.0.5", "10.0.0.6"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderArgsPreservesPositionalOrder(t *testing.T) {
	fs := newTestFlagSet()
	got := ReorderArgs(fs, []string{"10.0.0.5", "-u", "bob", "10.0.0.6", "10.0.0.7"})
	want := []string{"-u", "bob", "10.0.0.5", "10.0.0.6", "10.0.0.7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderArgsUnknownFlagLeftInPlace(t *testing.T) {
	fs := newTestFlagSet()
	args := []string{"10.0.0.5", "-bogus", "x"}
	got := ReorderArgs(fs, args)
	if !reflect.DeepEqual(got, args) {
		t.Errorf("got %v, want %v (unchanged, flag.Parse reports it)", got, args)
	}
}

func TestReorderArgsStopsAtDoubleDash(t *testing.T) {
	fs := newTestFlagSet()
	got := ReorderArgs(fs, []string{"-u", "bob", "--", "-p", "notaflag"})
	want := []string{"-u", "bob", "--", "-p", "notaflag"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderArgsBareDashIsPositional(t *testing.T) {
	fs := newTestFlagSet()
	got := ReorderArgs(fs, []string{"-u", "bob", "-"})
	want := []string{"-u", "bob", "-"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

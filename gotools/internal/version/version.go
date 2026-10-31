// Package version implements the version command: printing srt's release
// version and build info.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
)

// version is the release version. Override at build time with:
//
//	go build -ldflags "-X github.com/trike33/srt-cheatsheet/gotools/internal/version.version=v0.2.0" ./cmd/srt
//
// A binary from `go install ...@vX.Y.Z` carries no ldflags, so displayVersion
// falls back to the module version the Go toolchain stamps into the binary.
var version = defaultVersion

const defaultVersion = "0.2.0-dev"

// displayVersion prefers the module version of a `go install ...@<version>`
// build over the in-source default; "(devel)" and empty mean a local build.
func displayVersion(bi *debug.BuildInfo) string {
	if bi != nil && version == defaultVersion {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return version
}

func init() {
	cli.Register(&cli.Command{
		Name:    "version",
		Group:   "misc",
		Summary: "Print srt version and build info",
		Run:     Run,
	})
}

func Run(args []string) error {
	bi, _ := debug.ReadBuildInfo()
	fmt.Printf("srt %s%s\n", displayVersion(bi), vcsSuffix(bi))
	fmt.Printf("%s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return nil
}

// vcsSuffix renders " (<12-char-revision>[-dirty])", or "" if bi carries no
// VCS info (e.g. a `go install` build outside a checkout).
func vcsSuffix(bi *debug.BuildInfo) string {
	if bi == nil {
		return ""
	}
	var rev, dirty string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) >= 12 {
				rev = s.Value[:12]
			} else {
				rev = s.Value
			}
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return ""
	}
	return " (" + rev + dirty + ")"
}

// Display returns the same version string `srt version` prints as its first
// word's suffix: the module version (overridden by -ldflags, see version
// above) plus a VCS suffix when available. The shell's startup banner uses
// this so it never disagrees with `srt version`.
func Display() string {
	bi, _ := debug.ReadBuildInfo()
	return displayVersion(bi) + vcsSuffix(bi)
}

package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// version is the release version. Override at build time with:
//
//	go build -ldflags "-X main.version=v0.2.0" ./cmd/srt
//
// A binary from `go install ...@vX.Y.Z` carries no ldflags, so displayVersion
// falls back to the module version the Go toolchain stamps into the binary.
var version = defaultVersion

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

const defaultVersion = "0.2.0-dev"

func init() {
	register(&command{
		name:    "version",
		group:   "misc",
		summary: "Print srt version and build info",
		run:     runVersion,
	})
}

func runVersion(args []string) error {
	vcs := ""
	bi, ok := debug.ReadBuildInfo()
	if ok {
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
		if rev != "" {
			vcs = " (" + rev + dirty + ")"
		}
	}
	fmt.Printf("srt %s%s\n", displayVersion(bi), vcs)
	fmt.Printf("%s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return nil
}

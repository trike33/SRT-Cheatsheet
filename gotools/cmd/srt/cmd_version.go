package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// version is the release version. Override at build time with:
//
//	go build -ldflags "-X main.version=v0.2.0" ./cmd/srt
var version = "0.2.0-dev"

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
	if bi, ok := debug.ReadBuildInfo(); ok {
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
	fmt.Printf("srt %s%s\n", version, vcs)
	fmt.Printf("%s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return nil
}

# Code layout

`srt` used to be one `package main` with ~60 files in `cmd/srt/`. As the
tool grew past the original Python-port scope — a results database, a
shell, pipeline orchestration, a traceroute implementation — that stopped
scaling: every file could reach into every other file's state (`sink`,
`meter`, `gate`, `registry`, `colorMode`...) by just naming it, so nothing
enforced a boundary between "this is plumbing every command relies on" and
"this is one command's own business". This document describes the layout
that replaced it, so new work lands in the right place instead of growing
`cmd/srt/` again.

## The shape

```
cmd/srt/            entrypoint only: ~200 lines, no command logic
internal/
  cli/              the command registry (Command, Register, Lookup, Names, Grouped)
  ioutil/           file/stdin I/O, Warn, heartbeat, RangeSet, the few generic one-liners
  colorout/         ANSI palette, --color mode, the spinner
  halt/             Ctrl+C / SIGTERM / limit-breach cleanup hooks
  netx/             HTTP client construction + traffic metering + rate gate
  store/            the results database engine (generic Record/Sink/schema)
  scope/            Burp scope parsing+matching, plain IP/CIDR scope, auto-detect
  payloads/         vuln-param markers & sensitive extensions (static data)
  recon/
    ipexpand/ resolve/ portscan/ domains/ subdomains/ probe/ gau/
    dirlist/ robots/ snyk/ relpaths/ traceroute/ fuzz/
                    one package per command (or tightly related command
                    group), each self-registering with cli in its own init()
  pipeline/         orchestrates the recon/* packages per docs/pipeline.md
  results/          the results/runs/export/db commands (the CLI over store)
  shell/            the interactive REPL
  version/          the version command
```

Dependencies only point inward/sideways, never back out:

```
recon/*, scope, store, netx, halt, ioutil, colorout, payloads, cli
        ^                                                        |
        |                                                        |
        +---- pipeline, results, shell, version --- cmd/srt -----+
```

A `recon/*` package never imports `pipeline`, `results`, or `shell`. The one
exception within `recon/` itself: `recon/fuzz` imports `recon/probe` (for
`-ext-auto`'s tech-detect), which is fine because the dependency still only
points "sideways" between two leaf packages, not back up toward anything
that depends on `fuzz`.

## Why this grain, not finer or coarser

**One package per command** (not one giant `recon` package) because that is
exactly where Go's exported/unexported split is useful: a command's flags,
its internal helpers, its result type's private fields all stay unexported
and invisible outside the package, and the moment something needs
`internal/recon/probe.Result` or `.One()` from another package, that is a
visible, deliberate decision in an import line — not a same-package
reach-around nobody chose. Grep `grep -rn "^func [A-Z]"` in any `recon/*`
package to see its real public surface; it's usually 1-3 functions.

**A handful of infra packages, not one `internal/util`** because `cli`,
`ioutil`, `colorout`, `halt`, `netx`, `store`, `scope`, `payloads` are each
a genuinely separate concern with its own tests and its own reason to
change. Dumping them in one `util` package is the same mistake as the old
`cmd/srt/` at a smaller scale — it just delays the next split.

**`pipeline`, `results`, and `shell` are not `recon/*`** because they are not
recon techniques; they are the three different *drivers* that sit on top of
the recon packages (and, for `results`, on top of `store`). Each depends on
several `recon/*` packages; none of `recon/*` depends on any of them.

## Adding a new recon command

1. `internal/recon/<name>/<name>.go`, `package <name>`.
2. In `init()`, call `cli.Register(&cli.Command{Name: "...", Group: "...",
   Summary: "...", Run: Run})`.
3. Build `Run(args []string) error` the way every other command does: its
   own `flag.FlagSet`, `ioutil.InputLines`/`ioutil.Output` for list I/O,
   `netx.NewClient`/`netx.Request()` for anything that touches the network
   (that's what makes `-rate`, the shell's traffic line, and `limit bytes`
   apply to it for free), `store.CurrentSink().Add(...)` if it has
   structured results worth a `Record()` (see `recon/portscan.Result.Record`
   for the pattern) — otherwise plain stdout/`-o` output is enough, and
   `-save` on the CLI tees it into the database line by line automatically.
4. Add one blank import to `cmd/srt/main.go`'s list. That's the only edit
   outside the new package itself.
5. If `pipeline` should call it as a stage, add the call in
   `internal/pipeline/host.go` or `web.go`, in the order
   [`methodology.md`](methodology.md) lays out, following the existing
   `runStep("host"|"web", "<name>", target, outputFile, func() error {...})`
   pattern (that's what wires in `-resume` checkpointing and saving the
   step's plain-text output to the database).
6. Tests live beside the package (`<name>_test.go`), same as every other
   package here. Prefer a real, offline-safe exercise of the command (a
   loopback listener, an `httptest.Server`) over mocking — see
   `recon/traceroute`'s tests for the pattern of skipping gracefully
   (`t.Skip`) when the test needs a capability the environment doesn't have
   (there, a raw socket) rather than failing.

## Adding a new infra concern

If it's a cross-cutting primitive (not recon-specific) that more than one
`recon/*` package — or `pipeline`/`shell`/`results` — would otherwise
duplicate, it's a new `internal/<name>` package, not an addition to
`ioutil`. `ioutil` is for things so generic and small (a line reader, a
warning logger) that inventing a package per helper would be worse than one
junk-drawer package for exactly that tier; anything with its own real state
or its own tests (the way `netx`, `store`, `halt`, `scope` each do) gets its
own package from the start.

## What main.go still does

`cmd/srt/main.go` is intentionally the only file that blank-imports every
command package — that's what makes `cli.Names()`/`cli.Grouped()` complete
for `--help` and the shell's completion. Beyond that, it only handles what
is genuinely global and can't live in any one command: the leading
`-rate`/`-save`/`-db` flags, starting the traffic monitor and halt handler
for a plain-CLI run (the shell manages its own, per child process), and
`-save`'s stdout-teeing for commands that don't save structured results
themselves.

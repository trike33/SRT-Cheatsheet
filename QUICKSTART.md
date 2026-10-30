# Quickstart

`srt` is a single, dependency-free Go binary for recon automation. This gets
you from clone to a first scan in under a minute.

## 1. Build

```bash
cd gotools
make build        # produces ./srt — uses your local Go toolchain (Go 1.24+)
./srt version
```

No `go.sum`, no `pip install`, nothing to fetch — it's stdlib-only, so this
is the whole setup.

## 2. Run one command

Every subcommand reads a list from `-l <file>` **or stdin**, and writes to
stdout **or `-o <file>`**; progress goes to stderr, so output stays pipeable.

```bash
# port-scan a host, common + uncommon ports, with a banner grab
echo 10.0.0.5 | ./srt portscan -p common,uncommon

# reverse-DNS a list of IPs
./srt ipexpand -l scope.txt | ./srt resolve -reverse

# scope-aware directory fuzzing
./srt fuzz -u https://target/FUZZ -w wordlist.txt -ac
```

Run `./srt help` for the full command list, or `./srt <command> -h` for a
command's flags.

## 3. Run a whole assessment

`srt pipeline` runs the HOST and/or WEB methodology end to end from one JSON
file of targets — see [`gotools/docs/examples/pipeline-example.json`](gotools/docs/examples/pipeline-example.json)
for a starting point:

```bash
./srt pipeline -c gotools/docs/examples/pipeline-example.json -dry-run   # preview, no traffic
./srt pipeline -c my-engagement.json -kind host,web -o ./out
```

Results land in `./out/`, including a `manifest.json` summarizing every step
that ran, was skipped, or failed.

## Next

- [`gotools/docs/methodology.md`](gotools/docs/methodology.md) — the HOST/WEB
  methodology this automates, and what's still backlog.
- [`gotools/docs/commands.md`](gotools/docs/commands.md) — every command,
  every flag.
- [`gotools/docs/pipeline.md`](gotools/docs/pipeline.md) — the orchestrator,
  in depth.
- [`gotools/docs/fuzz.md`](gotools/docs/fuzz.md) — the scope-aware fuzzer.

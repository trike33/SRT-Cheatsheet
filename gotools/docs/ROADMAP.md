# srt roadmap & changelog

Running log of what's shipped and what's queued, newest first.

## Shipped

### Fuzzer precision & scale
- **Per-directory soft-404 calibration** (`-ac`) — recalibrates on every
  directory recursion descends into, so a soft-404 size under one directory
  never hides a finding under another.
- **Response-body highlighting** (`-hl <regex>`) — prints context snippets of
  matching bodies (secrets, keys, versions); added to `-json` as `highlights`.
- **Per-host live progress line** — stderr shows total counters plus each
  host's `matches/reqs(req/s)`.
- **Auto-throttle** (`-auto-throttle`) — per-host exponential backoff on
  429/503, decaying back on success; one slow host doesn't stall the rest.
- **Resumable runs** (`-resume <file>`) — logs completed targets and discovered
  directories; a re-run skips done work and re-seeds discovered dirs.
- **Multi-host fair scheduling** — one wordlist across many hosts (repeat `-u`,
  `-tl` file, or `-scope` seeding), interleaved round-robin, with per-host
  `-rate`/`-hc`, a global `-rate-global`, and a shared `-c` worker pool.
- **Streaming engine** — one feeder goroutine per host instead of one per
  candidate; recursion stays race-free (verified with `-race`).
- **Safety/evasion** — `-random-agent`, `-maxtime`, `-maxerrors`.
- **Scope gating** — compiles a Burp scope export's host/file regexes
  (protocol-aware include/exclude); only in-scope requests are sent, and the
  scope file can seed targets directly.

### Toolkit
- Ported every Python helper to Go subcommands (`ipexpand`, `ipports`,
  `domains`, `scopecheck`, `burphosts`, `burpscope`, `gau`, `sensitive`,
  `params`, `dirlist`, `robots`, `snyk`, `relpaths`), all pipe-friendly.
- `version` command; GitHub Actions build/release workflow; usage docs.

## Ideas / backlog

- **Recursion content-length auto-filter inheritance** — optionally seed a
  child directory's calibration from its parent to save probe requests.
- **Smarter directory detection** — treat a `200` on a trailing-slash request
  as a directory even without a redirect.
- **Per-host adaptive concurrency** — raise/lower `-hc` based on latency.
- **Resume compaction** — periodically rewrite the state file to dedupe.
- **Output formats** — ndjson streaming to a file, and a `-mc`-less "show all"
  summary table grouped by status.
- **Wordlist mutations** — case/extension permutations, `%ext%` style tokens.
- **Integrate into the `integrated/` PyQt GUI** — drive `srt fuzz` from the UI.
- **Release automation** once workflow scope is available (tag → binaries).

Suggestions welcome — open an issue.

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
- **`pipeline` command** — JSON-driven orchestrator that runs the right
  subcommands against `host`/`web` targets automatically. See
  [pipeline.md](pipeline.md).
- **"Still running" heartbeat** — any command still working 5 seconds in
  logs `<command>: still running (Ns elapsed)...` to stderr every 5 seconds
  until it finishes, so a long run on a big input never looks hung. `fuzz`
  and `portscan` keep their own richer live counters instead.
- **`install.sh`/`update.sh`** — one-liner install/update: fetches the
  right platform binary from this repo's latest GitHub Release and `sudo
  install`s it to `/usr/local/bin` (`$PREFIX/bin` if set), no Go toolchain
  needed. Linux/macOS; Windows grabs the `.exe` release asset directly.
- **`pipeline -host-file`/`-web-scope`** — build a config straight from a
  plain IP/CIDR list and/or a Burp scope export, no hand-written JSON
  required; combines with `-c` when one is also given.
- **`shell`** — interactive REPL with command history and Tab-completion on
  command names (`golang.org/x/term`, pinned to v0.40.0 for Go 1.24
  compatibility — `srt`'s first Go module dependency; everything else stays
  stdlib-only). Every line dispatches as a real subprocess of `srt` itself
  rather than in-process, since every command's `flag.FlagSet` uses
  `flag.ExitOnError` — in-process, a typo'd flag would `os.Exit` the whole
  shell session instead of just that command. The subprocess design also
  makes `help <command>` free: it's literally `<command> -h`, so there's no
  separate help text to maintain or drift out of sync.
- **Scope-file auto-detection** — `pipeline` with no `-c`/`-host-file`/
  `-web-scope` scans the current directory for `*-in-scope*` (host list) and
  `target_assets*.json` (Burp export; tolerates `(1)`-style download
  suffixes), newest match wins, and says what it picked on stderr.
  `-no-detect` opts out.
- **Project switching in `shell`** — `cd <dir>` / `project <dir>` changes the
  shell's CWD (every spawned command inherits it); the project name is the
  directory's base name and sits in the status bar. `cd -` returns to the
  previous project, bare `cd` goes home, bare `project` shows where you are.
  Tab completes directories (unique match, or longest common prefix), and a
  switch reports any scope files auto-detected in the new project.
- **Go-binary install, run from anywhere** — `go install
  github.com/trike33/srt-cheatsheet/gotools/cmd/srt@latest` (or `make
  go-install`) gives a self-contained `srt` on `PATH`; nothing is read from
  the source tree and relative paths resolve against the CWD. `srt version`
  reports the module version for `go install` builds (ldflags still win),
  and the shell re-execs itself via `os.Executable`, so it works from any
  directory.
- **Live traffic counter + halt** — every network touch (HTTP requests and
  wire bytes, TCP connect attempts, DNS lookups) is metered at three
  chokepoints (`http.go`, `probePort`, the resolvers). Commands run from the
  `shell` log a `[traffic] ...` line every 2s, the status bar keeps a session
  total (`traffic` prints it), and Ctrl+C halts a command instantly with its
  totals. `limit bytes <size>` sets a per-command byte ceiling; a breach kills
  the command immediately (exit 3, "HALTED"). Plain CLI runs aren't metered.
  Counts are per process, so a `pipeline` run is metered as a whole; external
  tools it shells out to (`vulnx`) aren't counted.
- **Global request-rate cap** — `srt -rate 50 <command>` (or `$SRT_RATE`)
  throttles the whole process to N requests/second, whatever the command or
  its concurrency: every HTTP request, TCP connect and DNS lookup takes a
  strictly spaced slot (no bursts), and cancelled/timed-out requests leave
  the queue. Works on every subcommand; `fuzz`'s own `-rate`/`-rate-global`
  still apply on top (the lower wins). The shell applies **50 req/s by
  default** to every command; `limit rate <n>` changes it, `limit rate off`
  lifts it, and `srt -rate N` starts a shell with a different default. Under
  a tight cap, high `-c` concurrency queues behind the gate, so waiting time
  counts toward a request's timeout — lower `-c` or raise `-timeout` if you
  see spurious timeouts.
- **Shell is the default mode** — bare `srt` on an interactive terminal
  drops straight into the shell; `srt <command> ...` (e.g. `srt pipeline`)
  stays plain CLI. With no TTY on stdin (scripts, pipes) bare `srt` still
  prints usage and exits 2 rather than hanging. Shell test coverage now
  includes line dispatch, key handling, exec-result handling and the TTY
  guard.

### HOST methodology (see [methodology.md](methodology.md))
- **`resolve`** — forward (A/AAAA) and reverse (PTR) DNS lookup, concurrent.
  Covers the methodology's "DNS check" step.
- **`portscan`** — native concurrent TCP connect scanner: `common`/
  `uncommon`/`all`/explicit port specs (comma-combinable), a best-effort
  banner grab, JSON or plain output. `srt`'s replacement for naabu.
- **Service classification + WEB hand-off in `pipeline`** — the HOST stage
  now scans, classifies each open port as a web service or not, and
  automatically runs the WEB stage against the web ones (`-no-web-handoff`
  opts out). Non-web uncommon/specialty ports (rsync, Java RMI, and the rest
  of `portscan`'s `uncommon` list) get flagged in the manifest for manual
  follow-up.
- **vulnx integration** — `pipeline`'s HOST stage runs `vulnx search
  "<banner>"` (github.com/projectdiscovery/vulnx) for every non-web open
  port with a grabbed banner, via the `runExternal` helper in
  `pipeline_external.go` (skips cleanly if `vulnx` isn't installed). Works
  unauthenticated, just rate-limited without `vulnx auth` configured.

### WEB methodology (see [methodology.md](methodology.md))
- **`subdomains`** — passive enumeration via crt.sh certificate transparency
  logs (always runs) plus optional active DNS brute force with a label
  wordlist. `srt`'s replacement for subfinder.
- **`probe`** — native httpx-lite: title/status/content-length/`Server` +
  a best-effort tech-detect (WordPress, Drupal, Joomla, Laravel, Django,
  Express, PHP, ASP.NET, nginx, Apache, IIS, Cloudflare — a small,
  conservative signature set, not a wappalyzer-equivalent). Covers
  "recon on root."
- **Wired into `pipeline`'s WEB stage** — `subdomains` (passive always,
  active if `options.subdomainsWordlist` is set) and `probe` run right
  after `domains`, widening the domain list `gau` also runs against.
  `robots`/`fuzz` stay scoped to the explicit `web` targets, so discovering
  N subdomains doesn't silently multiply active traffic — that stays opt-in.

## Ideas / backlog

### Methodology gaps (see [methodology.md](methodology.md))

Native implementations, not external-tool integrations — `srt`'s policy is
to reimplement what naabu/httpx/subfinder/katana/nuclei/dalfox would give
us rather than shell out to them (vulnx is the one exception, now wired up
— see Shipped above).

- **HOST**: excluded-but-tracked hosts (reverse DNS + route trace, never
  actively probed) — the `pipeline` schema has no way to mark a `host` entry
  excluded today, and there's no traceroute helper yet either; a native
  "easy wins" pass (default creds/common misconfigs); BeanShell detection
  (no fixed port to match on, needs banner-based detection).
- **WEB**: Google dorking; context-aware wordlist generation for `fuzz`
  (candidates derived from the detected tech stack/app context — `probe`'s
  tech-detect output is the natural input for this now, not just static
  wordlists); a re-validation step for URLs pulled from `gau`/dorking;
  parameter fuzzing/guessing beyond `params`' URL-based classification,
  plus reading parameters from a webset/API spec when one exists;
  content-based sensitive-info classification (creds/keys found inside a
  file, not just by extension); optionally also running `robots`/`fuzz`
  against `pipeline`-discovered subdomains, opt-in given the traffic-volume
  implications (today only `gau`/`probe` auto-widen to them).
- **`pipeline` integration** — as each of the above lands, extend
  `pipeline_host.go`/`pipeline_web.go` to call it in the order
  `methodology.md` lays out.
- **Host↔web scope cross-link in `pipeline`** — `playbook.md` filters
  domains discovered on the web side through `scopecheck` against the host
  stage's IP scope; the pipeline's two stages are independent today.

### Active testing & UX (from engagement notes, not started)

Noted for later — none of these are scoped or designed yet, just captured
so they aren't lost:

- **Parameters → vulnerability-class correlation** — go beyond `params`'
  current static marker-matching to a richer mapping from a discovered
  parameter to the vulnerability classes worth testing it for.
- **A payload library**, sourced from PayloadsAllTheThings, for active
  testing modules to draw on (ties into auto-detect-and-send below).
- **Persist scan results to a local SQLite db**, fetchable via native `srt`
  commands, instead of only flat files/JSON.
- **Re-run the full methodology without overwriting old scans** — versioned
  or timestamped runs (likely the same db as above).
- **Detect error-based and time-based behaviors** — blind SQLi/command
  injection style signals during active testing.
- **Screenshot discovered websites** (gowitness/aquatone-style).
- **Auto-detect and send payloads** — close the loop from recon
  (parameters, tech-detect) to actually firing payloads at likely-vulnerable
  targets.
- **A guided flag-builder in `shell`** (the basic REPL itself shipped — see
  Shipped above) — interactively prompting for each flag instead of still
  typing them. Needs either a shared declarative flag schema across every
  command (a real refactor) or per-command duplicate prompt flows that
  would drift from the real flags over time.

### Fuzzer / pipeline

- **Recursion content-length auto-filter inheritance** — optionally seed a
  child directory's calibration from its parent to save probe requests.
- **Smarter directory detection** — treat a `200` on a trailing-slash request
  as a directory even without a redirect.
- **Per-host adaptive concurrency** — raise/lower `-hc` based on latency.
- **Resume compaction** — periodically rewrite the state file to dedupe.
- **Output formats** — ndjson streaming to a file, and a `-mc`-less "show all"
  summary table grouped by status.
- **Wordlist mutations** — case/extension permutations, `%ext%` style tokens.
- **Release automation** once workflow scope is available (tag → binaries).

Suggestions welcome — open an issue.

# JOAN Suggestions

- Ability to stop and resume sessions(eg. stop a network scan and resume it later with a command)
- ~~Project switching in the shell~~ — done, see Shipped.
- ~~Auto-detect known scope files~~ — done, see Shipped.
- ~~Live traffic counter and halt in the shell~~ — done, see Shipped.
- ~~Finish the shell tests and make shell the default mode~~ — done, see Shipped.
- ~~Install as a Go binary, run from anywhere~~ — done, see Shipped.


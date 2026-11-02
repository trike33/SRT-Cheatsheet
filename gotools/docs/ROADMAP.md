# srt roadmap & changelog

Running log of what's shipped and what's queued, newest first.

## Shipped

### `validate`: soft-404-aware endpoint validation (gaps 3, 4, 10)
- New native command `srt validate` and a pipeline step (`06c`, on by
  default, `-no-validate`): re-probes the merged endpoint list and keeps only
  real resources. Fingerprints each host's not-found response with random
  paths per (host, first directory, extension) — status, echo-normalized
  size band, word count, and `Location` for redirects — and drops matches;
  a second pass learns groups of 10+ near-identical hits calibration
  missed. `sensitive`/`params` now run on the validated list, so extension
  matches and `-content-scan` no longer waste requests on dead or soft-404
  URLs. Endpoints are capped (`options.validateMax`, default 10000) with
  archived URLs checked last.
- Known limits: calibration is per first directory, not per every
  directory; and the fingerprint is size/words based, so a soft-404 page
  that embeds large random content could slip through to the learn pass.

### WEB pipeline: endpoint merge, reordered sensitive/params, default directory wordlist
- `robots`/sitemap hits and `fuzz` hits now merge with gau's URLs into
  `06b_endpoints.txt`, and `sensitive`/`params` run over that list *after*
  `robots`/`fuzz` instead of before them (they used to see only gau's URLs).
- `fuzz` is on by default with SecLists' `common.txt` embedded in the
  binary when no wordlist is configured (`options.fuzz:false`/`-no-fuzz` to
  disable). Gaps 1, 2 and 6 below.

### Active subdomain brute force on by default, with an embedded wordlist
- The WEB stage now brute-forces subdomains by default using SecLists'
  `subdomains-top1million-20000.txt`, **embedded in the binary**
  (`internal/wordlists`, MIT, see its NOTICE.md) so there's no path to
  configure or install. `options.subdomainsWordlist` overrides it;
  `options.subdomainsActive:false`/`-no-active-subdomains` makes the run
  passive-only. When dnsx is installed it performs the brute force (plus
  wildcard filtering) and the native one steps aside, so queries aren't
  duplicated.

### Easy wins on by default; subfinder/dnsx/alterx DNS discovery
- **The nuclei "easy wins" pass is now on by default** (`options.easyWins:false`
  or `-no-easy-wins` to disable; `-easy-wins` stays as a deprecated no-op).
  Its flags are unchanged: rate-limited, `-etags dos,fuzz,intrusive`, no
  OAST, 3-minute cap per target.
- **WEB-stage subdomain discovery now chains ProjectDiscovery's DNS tools**,
  each skipped cleanly if not installed: **subfinder** (passive, on by
  default, `-no-subfinder`); **dnsx** brute force when
  `options.subdomainsWordlist` is set (now the default, see above), followed by a `-wd` wildcard-filter
  pass; **alterx** permutations resolved by dnsx (opt-in,
  `-permutations`, capped at 2000 per domain). This is the methodology's
  HOST "DNS brute force" gap, delivered through the host↔web cross-link:
  names found are scope-checked against the host IP scope before use.
  `install.sh`/`update.sh`/`uninstall.sh --with-pd` manage all seven tools.

### `robots`: sitemap handling
- `srt robots` (and the pipeline's WEB `robots` step) now also reads
  `Sitemap:` directives from robots.txt, falling back to `/sitemap.xml`,
  follows sitemap indexes (2 levels, 25 files max) and gzipped sitemaps, and
  probes the listed URLs under a `[Sitemap]` section. Same-host only (a
  sitemap can list anything; it must not widen what gets probed), capped at
  `-sitemap-max` (default 100) per base, `-no-sitemap` to disable.

### Chaining more ProjectDiscovery tools: `cdncheck`, `tlsx`; `katana` investigated, not shipped
- **`cdncheck`** (on by default, `options.cdnCheck`/`-no-cdn-check`) — the
  HOST stage now flags which of a ports group's IPs sit behind a known
  CDN/WAF/cloud provider, informational only. A local dataset lookup with
  no traffic to the target at all, unlike every other external-tool step
  here, so there's nothing to opt into.
- **`tlsx`** (on by default, `options.tlsx`/`-no-tlsx`) — the WEB stage
  now extracts each explicit target's certificate SAN/CN entries and
  merges them into the same discovered-domain pool `subdomains` widens,
  through the same host↔web scopecheck cross-link. One TLS handshake per
  target, the same order of traffic as `probe`'s own one request per
  target.
- **`katana` (active crawling) was investigated and deliberately NOT
  shipped.** It would have been the highest-value addition on this list —
  `gau`'s passive Wayback lookups miss everything that was never archived
  — but in the sandbox this was built in, a trivial local crawl hung
  indefinitely: it opened several parallel HTTPS connections through the
  egress proxy to something unrelated to the crawl target before ever
  reaching it, and no flag (including `-duc`) was found to prevent it.
  Shipping an automated, unattended pipeline step on a tool observed
  hanging, with no way to know whether a given deployment's own network
  hits the same thing, wasn't worth the risk. **Still a real, open gap —
  see Ideas/backlog below** for what adding it properly would need.
- **`runExternal` now enforces a hard 5-minute wall-clock timeout on every
  external-tool call** (`vulnx`, `nuclei`, `cdncheck`, `tlsx`, and any
  future addition) — directly because of the `katana` finding above. Set
  comfortably above `nucleiEasyWinsArgs`' own `-mt 3m` cap so a tool
  winding down cleanly on its own schedule is never cut off first; only
  matters for a tool that's hung or unexpectedly slow, which previously
  had no backstop at all.
- All four tools' exact flags (`vulnx`, `nuclei` from before, plus
  `cdncheck`/`tlsx` here, and `katana`'s investigation) were verified
  against binaries built with `go install .../cmd/<tool>@latest` and run
  directly (`-h`, and live against local test listeners/a self-signed TLS
  cert with SAN entries for `tlsx`), not just READMEs —
  `docs.projectdiscovery.io` itself is blocked in this session's network
  policy, so each tool's own GitHub README (via
  `raw.githubusercontent.com`, which is reachable) was the source instead.
  Install any of them with [pdtm](https://github.com/projectdiscovery/pdtm):
  `pdtm -i vulnx,nuclei,cdncheck,tlsx`.

### WEB stage wiring for `sensitive -content` (`-content-scan`)
- **`pipeline`'s WEB stage can now run `sensitive -content` over the
  merged `gau` URL list** instead of only ever filtering by extension —
  closes the "pipeline integration" gap that was still open after
  `sensitive -content` itself shipped. `options.contentScan` in a JSON
  config, or `-content-scan` on the CLI, switches the `sensitive` step
  from `03_sensitive.txt` (plain extension-filtered URLs, the unchanged
  default) to `03_sensitive.json` (structured secret hits: `url`,
  `pattern`, `match`, `context`). **Off by default** — a large `gau` dump
  can be thousands of URLs, and this turns a string classification into a
  real fetch per URL; `options.concurrency`, if set, caps it the same way
  it already does for `fuzz`, instead of adding a second concurrency knob
  just for this step. The argv-building logic
  (`sensitiveArgsFor` in `internal/pipeline/web.go`) was pulled out as its
  own function so it's unit-testable without live HTTP calls, the same
  shape `vulnxSearchArgs`/`nucleiEasyWinsArgs` already use.

### HOST "easy wins" pass: a conservative `nuclei` call (`-easy-wins`)
- **`pipeline`'s HOST stage can now run nuclei's default-login/misconfig/
  exposure templates against every non-web open port** — the last entry
  in methodology.md's HOST "scan" step. By explicit decision this is a
  direct `nuclei` call rather than a native reimplementation (the usual
  policy): reimplementing nuclei's own default-credential/misconfiguration
  template library wasn't worth it for one step, so `nuclei` joins `vulnx`
  as a second named exception in methodology.md's External-tool policy.
  **Off by default** (`options.easyWins` in a JSON config, or `-easy-wins`
  on the CLI) — unlike `vulnx`'s lookup against a third-party database,
  this sends real probes at the service, so it needs an explicit opt-in.
  Traffic is bounded regardless of that opt-in: `-tags
  default-login,exposure,misconfig` (never `cve` — `vulnx` already covers
  that from the banner right above this step in the same loop), `-etags
  dos,fuzz,intrusive` to drop anything actively harmful, and `-rl 10 -c 3
  -bs 1 -timeout 5 -retries 1 -mt 3m` to keep one target's worst case to a
  low-rate, short burst well under nuclei's own (much higher) defaults.
  `-ni` skips OAST/interactsh templates so this never depends on a
  third-party interactsh server; `-duc` skips nuclei's own per-run
  update-check call but does **not** fetch nuclei-templates from nothing
  — that's still a one-time `nuclei -ut` the operator runs themselves.
  Skips cleanly (same `runExternal` shape as `vulnx`) if `nuclei` isn't
  installed. The exact flags were verified against a built `nuclei`
  v3.11.1 binary (`-h`/`-help`), not just its docs, same rigor as `vulnx`'s
  `-p/--product` fix.

### BeanShell detection by banner (`portscan.IsBeanShellBanner`)
- **`pipeline`'s HOST stage now flags an exposed BeanShell interactive
  server** regardless of what port it's listening on. BeanShell has no
  fixed/assigned port, so it was the one entry in methodology.md's "flag
  uncommon services for manual follow-up" step that `uncommonPorts`'
  port-number list could never catch; `IsBeanShellBanner` instead matches
  its real startup line ("BeanShell &lt;version&gt; - by Pat Niemeyer
  (pat@pat.net)", the same signature nmap's service-probes database
  fingerprints it by) against any open port's grabbed banner. A match is
  recorded as its own `flag-beanshell` step — a distinct, more specific
  label than the generic `flag-uncommon-service`, since an exposed
  BeanShell with no auth is an immediate unauthenticated remote code
  execution risk (anything sent to it runs as arbitrary Java/BeanShell), not
  just "worth a manual look." `vulnx` still also runs against it, same as
  any other bannered non-web port.

### Fuzzer output formats: `-ndjson`, `-summary`
- **`-ndjson <file>`** — streams every matched hit as a JSON line to that
  file continuously, independent of the console display mode (table/
  `-silent`/`-json`) and of `-o`. Before this, getting structured output
  meant giving up the colored table (`-json` replaces it); now you can keep
  the table on screen and have another tool `tail -f` structured data from
  the file at the same time.
- **`-summary`** — counts every response this run saw (matched or not) and
  prints a per-status-code table at the end, independent of `-mc`/`-fc` --
  the "-mc-less show-all" view: a quick look at what's actually out there
  (how many 403s, how many soft-404 200s slipped past calibration, ...)
  before deciding what to filter, instead of re-running with `-mc all` and
  wading through every line.

### Host↔web scope cross-link in `pipeline`
- **`pipeline`'s WEB stage filters discovered domains/subdomains through
  the HOST stage's IP scope** — closes the gap `playbook.md`'s manual flow
  always had and `pipeline` didn't: a domain/subdomain that resolves
  outside the engagement's IP range (a third-party CDN, a stale DNS record)
  is dropped before it reaches `subdomains`/`gau`/`probe`, the same way
  `srt domains -l ... | srt scopecheck -scope scopeips` does by hand.
  The cross-link runs twice, matching the playbook's order: once on the
  domains `domains` extracts from `web` targets (before `subdomains` runs),
  and once on the subdomains that step discovers (before they're merged
  into the list `gau`/`probe` operate on). `robots`/`fuzz` are unaffected —
  they already only ever touch the explicit `web` targets, never the
  discovered list.
  The "host IP scope" is built from the same invocation's config `host`
  list (both included and excluded-but-tracked entries — excluded just
  means never actively probed, not out of scope), written once to
  `<outputDir>/host_scope.txt`. With no `host` targets in the config (a
  web-only run), the cross-link is skipped entirely and both stages stay as
  independent as before this existed. A `scopecheck` failure (e.g. a
  malformed host entry) fails open rather than silently dropping every
  domain over a broken check.

### Content-based sensitive-info classification (`sensitive -content`)
- **`sensitive -content`** — fetches every input URL and scans the response
  body against a small, high-precision set of secret/credential signatures
  (AWS/Google/Slack/GitHub/Stripe tokens, private key blocks, JWTs,
  basic-auth and database connection strings in a URL, generic
  `key=`/`secret=`/`password=` assignments — `internal/payloads.SecretPatterns`)
  instead of filtering by extension. Closes the "not just by extension" half
  of the WEB methodology gap: a leaked key in a `.js` bundle or a plain
  `config` endpoint is invisible to extension matching but not to this.
  `-c`/`-timeout`/`-insecure`/`-max-size` control the fetch; a fetch error or
  non-2xx is skipped, not fatal, since a dead link from an old Wayback crawl
  is routine on a large `gau` dump. `-json` emits structured hits
  (`url`, `pattern`, `match`, `context`); the default mode (no `-content`)
  is unchanged.

### Fuzzer: preflight baseline, parent-seeded calibration, smarter recursion, adaptive concurrency, mutations
- **Preflight baseline probe** — every `fuzz` run, with or without `-ac`,
  fires two guaranteed-nonexistent paths at each target host's root before
  any real fuzzing starts (the "what does a 404 look like here" check a
  human runs by hand). A host whose miss comes back looking like a *hit*
  under the configured matchers gets soft-404 filtering auto-enabled for it
  on its own, with a stderr line saying so; a host that 404s cleanly is left
  alone. Either way the fingerprint is recorded as that host's baseline.
- **Parent-to-child (and baseline-to-directory) calibration inheritance** —
  `-ac`'s per-directory calibration now seeds from the nearest already-known
  fingerprint — the preflight baseline at the top level, or the parent
  directory's own calibration once `-recursion` descends — before running
  its own probes on top. Saves probe requests on deep trees without masking
  a directory with a genuinely different soft-404 of its own.
- **Smarter directory detection for `-recursion`** — besides the classic
  redirect-to-trailing-slash signal, a direct `2xx` on an extensionless word
  is now also recursed into once its `<word>/` form is confirmed to resolve
  to a real (non-soft-404) page too — for apps that serve a directory
  listing inline with no redirect. Narrowed to words with no dot, so a flat
  file is never probed this way.
- **Adaptive per-host concurrency (`-adaptive-conc`)** — an AIMD controller
  per host: starts conservative, climbs one slot at a time after a run of
  clean, on-pace responses, and backs off immediately on a transport error,
  `429`/`503`, or a response much slower than that host's own recent
  average. `-hc`, if also set, still caps how high it can climb.
- **Wordlist mutations** — `-mutate-case` also tries lower/UPPER/Title-case
  variants of every word; a literal `%ext%` token in a wordlist line (e.g.
  `backup.%ext%`) expands against the resolved extensions instead of only
  ever having one appended as a suffix.
- **Resume-log compaction** — a `-resume` state file is now rewritten down
  to one line per completed target and one per discovered directory every
  20k appended lines, instead of growing by one line per request for the
  life of a long run; a failed compaction (e.g. a read-only output dir)
  leaves the original file and writer untouched.

### Excluded-but-tracked hosts + native traceroute
- **`host` entries can be marked `"excluded": true`** in a `pipeline`
  config: never portscanned, never handed off to WEB — only `ipexpand` ->
  `resolve -reverse` -> `srt traceroute`, matching the methodology's
  excluded-but-tracked hosts exactly.
- **`srt traceroute`** — a native ICMPv4 route tracer (one echo per TTL,
  matched to its reply by id/sequence so unrelated ICMP traffic on the host
  can't be mistaken for it). Needs a raw socket (`CAP_NET_RAW` on Linux, or
  root); checked once up front and **skipped cleanly** without one — in
  `traceroute` itself and in `pipeline`'s excluded-host step — the same
  shape already used for `vulnx` when it's not installed. Not implemented
  on Windows yet (needs a different raw-socket API — WSASocket/IP_HDRINCL —
  that nobody's wired up); the binary still cross-compiles there, the
  command just reports it can't run. IPv4 only for now; `golang.org/x/sys`
  (already pulled in transitively) is now a direct dependency for the raw
  socket calls, no new dependency tree.

### Fuzzer precision & scale
- **Automatic extension discovery** — `fuzz -ext-auto` combines tech-detect
  with the soft-404 logic: the root page's detected stack (PHP, ASP.NET,
  Express…) trusts its extensions outright, and the generic candidates
  (`.html .txt .bak .zip`…) are verified live against a per-extension
  baseline, so jittery-200 apps don't yield false extensions. Per host, shared
  across recursion. `pipeline` enables it for web targets with no explicit
  `extensions` (`options.autoExtensions: false` opts out).
- **Jitter-tolerant soft-404 filtering** — `-ac` fingerprints are bands:
  reflection-normalized size, `-ac-tol` percent tolerance, a word-count band
  (so a different page with a similar byte length still shows), and
  `-ac-learn` runtime learning of clusters calibration missed. Handles apps
  whose "not found" 200 varies in length (3302/3305/3310/3312).
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
  chokepoints (`netx`'s client, `portscan.probePort`, the resolvers).
  Commands run from the `shell` log a `[traffic] ...` line every 2s, the
  shell keeps a session total in its own permanent traffic box (see below),
  and Ctrl+C halts a command instantly with its totals. `limit bytes <size>`
  sets a per-command byte ceiling; a breach kills the command immediately
  (exit 3, "HALTED"). Plain CLI runs aren't metered. Counts are per process,
  so a `pipeline` run is metered as a whole; external tools it shells out to
  (`vulnx`) aren't counted.
- **Self-overwriting live counters, width-safe** — the heartbeat
  (`ioutil.StartHeartbeatEvery`), `fuzz`'s per-host progress ticker, and the
  shell's `[traffic] ...` line all update the same terminal row in place
  (`colorout.Overwrite`) instead of scrolling a new line per tick, and the
  line is truncated to the terminal's actual width first
  (`colorout.TermWidth`) — printing something longer than the terminal and
  letting it wrap breaks the whole trick, since `\r` only returns to the
  start of the *last* wrapped row, not back to the top of the previous
  print, so every earlier row is left stuck on screen as new ticks pile up
  below it (this is what a multi-host `fuzz` run on a narrow terminal used
  to look like). Redirected to a file/pipe, each tick still gets its own
  newline-terminated line, so a backgrounded run's log keeps every tick.
- **Permanent traffic box in the shell** — session traffic (and the last
  finished command's own traffic) now live in a dedicated bordered box that
  is always visible and never clears on the next keystroke, instead of a
  few seconds in the transient status-line notice that disappeared the
  moment you started typing the next command.
- **Bash-style Tab completion over paths** — Tab in the shell completes
  files and directories for whichever word the cursor is in, not just a
  2nd-word `cd`/`project` argument: any command's path argument (a
  wordlist, a scope file, an output path) completes the same way a real
  shell's does. `cd`/`project` still restrict matches to directories only,
  since their one argument is always a place to switch into; every other
  command completes both. A unique match completes fully (directories get
  a trailing `/`), several matches extend to their longest common prefix.
- **`clear` redraws the startup banner** — the shell's `clear` command
  still clears the terminal, then reprints the banner (version, build,
  cwd) that was otherwise only ever shown once at startup and lost for
  good the moment the screen was cleared.
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
- **Results database** — `pipeline`, the `shell`, and `-save` on any command
  persist results to a per-project SQLite file (`.srt/srt.db`; pure-Go driver
  `modernc.org/sqlite`, so `srt` stays one static binary, ~+8 MB). Generic
  `records` table (kind, key, host, port, url, status, length, JSON data)
  grouped into `runs`; **runs are never overwritten**, so re-running the
  methodology keeps history (that backlog item is done too). `srt results`
  (filters + table/JSON/keys/count; default view = newest observation of each
  result), `srt runs`, `srt export` (per-host directory tree, CSV, JSON) and
  `srt db path|stats|import|rm`. Global flags `-save` and `-db <path>`
  (`$SRT_SAVE`, `$SRT_DB`). Structured for portscan/fuzz/probe; other
  commands are saved from stdout line by line. Flushed on Ctrl+C/halts.
- **Stop & resume** — an interrupted scan continues instead of restarting.
  - `portscan -resume <file>`: progress is one watermark over the fixed
    host-major probe sequence (plus every open port, written the moment it's
    found), checkpointed every 500ms and flushed on Ctrl+C/limit halts. A
    re-run with the same hosts/ports skips finished probes and re-emits the
    recovered results, so the output file always reflects the whole scan; a
    state file from a different scan is refused. `fuzz -resume` already
    existed.
  - `pipeline -resume`: `checkpoint.json` in the output dir records finished
    steps; a resumed run skips them (if their output file still exists) and
    continues the interrupted `portscan`/`fuzz` mid-way via per-step state
    files. Without `-resume` a run starts fresh.
  - Central halt handling (`halt.go`): SIGINT/SIGTERM and limit breaches run
    flush hooks before exiting 130/3 — so state on disk is current.
  - In the `shell`, `portscan`/`fuzz`/`pipeline` are tracked automatically in
    `<project>/.srt/` (so they survive closing the shell and are per
    project). Stop one with Ctrl+C or a `limit bytes` halt, then `sessions`
    lists what's interrupted and `resume [id]` (default: the latest) carries
    on. A clean finish discards the session. Passing your own `-resume` opts
    out of tracking.
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
- **vulnx integration** — `pipeline`'s HOST stage runs `vulnx search` for
  every non-web open port with a grabbed banner, via the `runExternal`
  helper in `internal/pipeline/external.go` (skips cleanly if `vulnx` isn't
  installed). Works unauthenticated, just rate-limited without `vulnx auth`
  configured. `vulnxSearchArgs`/`vulnxProduct` use `-p <product>` (e.g. `-p
  openssh`, `-p arcgis`) when the banner matches a recognized service --
  the precise, structured form of the real CLI (verified against the built
  binary, not just its docs/help text) -- falling back to a free-text
  search over the banner for anything `vulnxProduct` doesn't recognize.

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
  active by default, see Shipped) and `probe` run right
  after `domains`, widening the domain list `gau` also runs against.
  `robots`/`fuzz` stay scoped to the explicit `web` targets, so discovering
  N subdomains doesn't silently multiply active traffic — that stays opt-in.

## Ideas / backlog

### Methodology gaps (see [methodology.md](methodology.md))

Native implementations, not external-tool integrations — `srt`'s policy is
to reimplement what naabu/httpx/subfinder/dalfox would give us rather than
shell out to them. `vulnx`, `nuclei`, `cdncheck`, and `tlsx` are the four
named exceptions, each wired up for its own reason — see Shipped above and
methodology.md's External-tool policy.

- **HOST**: ~~excluded-but-tracked hosts~~ — done, see Shipped.
  ~~BeanShell detection~~ — done, see Shipped (`portscan.IsBeanShellBanner`).
  ~~"Easy wins" pass~~ — done, see Shipped (`-easy-wins`; a direct `nuclei`
  call rather than a native reimplementation, by design — see
  methodology.md's External-tool policy).
- **WEB**: Google dorking; context-aware wordlist generation for `fuzz`
  (extensions now are, via `-ext-auto`; candidate *words* derived from the detected tech stack/app context — `probe`'s
  tech-detect output is the natural input for this now, not just static
  wordlists); a re-validation step for URLs pulled from `gau`/dorking;
  parameter fuzzing/guessing beyond `params`' URL-based classification,
  plus reading parameters from a webset/API spec when one exists;
  ~~content-based sensitive-info classification~~ — done, see Shipped
  (`sensitive -content`); optionally also running `robots`/`fuzz`
  against `pipeline`-discovered subdomains, opt-in given the traffic-volume
  implications (today only `gau`/`probe` auto-widen to them).
- **`pipeline` integration** — as each of the above lands, extend
  `internal/pipeline/host.go`/`internal/pipeline/web.go` to call it in the
  order `methodology.md` lays out. ~~`sensitive -content` wiring~~ — done,
  see Shipped (`options.contentScan`/`-content-scan`).
- ~~Host↔web scope cross-link in `pipeline`~~ — done, see Shipped.

### More ProjectDiscovery tool chaining (see Shipped above for `cdncheck`/`tlsx`)

- **`katana` (active crawling)** — investigated, not shipped (see Shipped
  above for why). Would widen `02_all_urls.txt` with URLs an active crawl
  finds that were never archived to Wayback, which `gau` alone can't see.
  Revisit if: a flag is found that actually prevents whatever background
  fetch was hanging (worth re-testing against a newer release, or asking
  upstream), or it's wired in with its own hard per-call timeout from the
  start rather than relying only on `runExternal`'s backstop, and proven
  not to hang across a few different real environments first.
- **`dnsx` (more record types)** — brute force, resolution and wildcard
  filtering are now wired (see Shipped); still open: TXT/CNAME/NS/MX/SOA
  record collection, which `srt resolve` doesn't do.
- **`shuffledns`** — massDNS-based brute force for very large wordlists;
  needs massdns and a resolver list, so it wasn't chosen over dnsx.
- **`mapcidr`** — CIDR aggregation (merge many ranges into the smallest
  covering set) and filtering. Overlaps with `srt ipexpand`'s existing CIDR
  expansion; aggregation specifically could help build/shrink a host scope
  file, but isn't a gap `ipexpand` leaves open today.
- **`asnmap`** — maps an ASN/org/domain to its CIDR ranges, which could
  seed a HOST scope from just a company name. Requires a ProjectDiscovery
  Cloud Platform API key for the CLI to work at all (not just
  rate-limited-without-one like `vulnx`), which is real adoption friction
  for a default-on or even default-off pipeline step — would need its own
  config field for the key and a clear skip when it's absent.
- **`uncover`** — aggregates Shodan/Censys/etc. searches for exposed
  assets matching a query. Needs per-engine API keys to do anything useful,
  same friction as `asnmap`; lower priority than the above.

### WEB pipeline: target flow and gaps (investigated, not started)

Target flow: **endpoints** (active: robots + sitemap, crawl, dir/file brute
force with generic *and* guessed wordlists; passive: gau, optionally
chaos/uncover) -> one merged endpoint list -> **re-probe with native httpx**
-> **valid endpoints** (careful: soft-404 sites answer 200 for anything) ->
**parameters** (fuzz/guess, or read from what the site declares) and
**sensitive info** (sensitive extensions, creds/API keys).

What the pipeline does today, in order: domains -> subdomains (+subfinder/
dnsx/alterx) -> tlsx -> `probe` (roots only) -> `gau` -> `sensitive` +
`params` (over gau URLs only) -> `robots` -> `fuzz` -> `snyk`. Gaps:

1. ~~**No endpoint merge.**~~ *(done — `06b_endpoints.txt`)* `robots`/sitemap output (`05_robots.txt`) and
   `fuzz` results (`06_fuzz_*.json`) never join `02_all_urls.txt`; there is
   no single "endpoints/directories/files" list to carry forward.
2. ~~**Wrong order.**~~ *(done)* `sensitive`/`params` run *before* `robots`/`fuzz`, so
   they only ever see gau's archived URLs, never what the active steps found.
3. ~~**No re-probe of endpoints.**~~ *(done — `validate`)*  
   *(original note:)* `probe` runs once on domains (recon on
   root). gau/robots/sitemap/fuzz URLs are never validated as a distinct
   step (`probe` already accepts URLs, so the plumbing exists).
4. ~~**No soft-404 handling outside `fuzz`.**~~ *(done — `validate`; `robots`' own green-on-200 output is unchanged)*  
   *(original note:)* `fuzz -ac` calibrates per
   directory, but `probe` has none, and `robots` prints green for any 200
   (so the new sitemap URLs on a soft-404 site all look valid). The
   validation step needs a per-host random-path fingerprint (status, size,
   words, body hash) and to drop matches — `fuzz`'s `calibData` is the
   reusable piece.
5. **No crawler.** katana is still out (hung in the dev sandbox); nothing
   else follows links, extracts JS/form URLs or reads `<a>`/`<script>`.
6. ~~**Directory brute force is off unless you configure a wordlist.**~~ *(done — embedded `common.txt`, on by default)* `fuzz`
   is skipped per target when no `wordlist`/`options.wordlist` resolves —
   the same problem subdomains had before the embedded list. Needs an
   embedded generic list (raft/common-style) and a `-no-fuzz`-style switch.
7. **No guessed/context wordlists.** Only extensions are auto-detected
   (`-ext-auto`); words derived from the target's tech stack, titles, JS
   identifiers or the engagement name are not generated.
8. **Active steps only cover explicit targets.** `robots`/`fuzz` never run
   against discovered live subdomains (deliberate, to bound traffic, but
   then "recon on every subdomain" never reaches endpoint discovery). Needs
   an opt-in that feeds `probe`-confirmed live hosts forward.
9. **Parameters are only classified, not discovered.** `params` buckets
   parameters already present in URLs by vuln class. Missing: parameter
   fuzzing/guessing against valid endpoints, and automatic extraction of
   what the site declares itself (HTML forms/inputs, JS, OpenAPI/Swagger/
   GraphQL introspection).
10. ~~**Sensitive-info checks the wrong population.**~~ *(done — runs on the validated list)*  
    *(original note:)* The extension list is
    identical to your regex (and matches on the URL *path*, so a query
    string can't hide or fake a hit), but it runs on archived URLs without
    checking the file still exists, and `-content-scan` (off by default)
    fetches every URL including dead ones and soft-404 pages. Both should
    run over the validated list only.
11. **chaos / uncover not wired.** Both need a ProjectDiscovery/engine API
    key. chaos is a subdomain source (subfinder can use it once a chaos key
    is in its provider config — worth documenting before adding a tool);
    uncover (Shodan/Censys/...) seeds hosts/IPs from a query and belongs at
    scope-building, with a config field for keys and a clean skip when
    absent.
12. **Google dorking** is still unimplemented.

Suggested build order: (1)+(2) merge and reorder, (4) soft-404-aware
validation, (3) re-probe, then (10) rerun sensitive/params on the valid
list, then (6)/(7) default wordlists, (9) parameter discovery, (5) crawler.

### Active testing & UX (from engagement notes, not started)

Noted for later — none of these are scoped or designed yet, just captured
so they aren't lost:

- **Parameters → vulnerability-class correlation** — go beyond `params`'
  current static marker-matching to a richer mapping from a discovered
  parameter to the vulnerability classes worth testing it for.
- **A payload library**, sourced from PayloadsAllTheThings, for active
  testing modules to draw on (ties into auto-detect-and-send below).
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

- ~~Recursion content-length auto-filter inheritance~~ — done, see Shipped
  (preflight-to-directory and parent-to-child calibration seeding).
- ~~Smarter directory detection~~ — done, see Shipped.
- ~~Per-host adaptive concurrency~~ — done, see Shipped (`-adaptive-conc`).
- ~~Resume compaction~~ — done, see Shipped.
- ~~Wordlist mutations~~ — done, see Shipped (`-mutate-case`, `%ext%`).
- ~~Output formats~~ — done, see Shipped (`-ndjson`, `-summary`).
- **Release automation** once workflow scope is available (tag → binaries).

Suggestions welcome — open an issue.

# JOAN Suggestions

- ~~Stop and resume sessions~~ — done, see Shipped.
- ~~Project switching in the shell~~ — done, see Shipped.
- ~~Auto-detect known scope files~~ — done, see Shipped.
- ~~Live traffic counter and halt in the shell~~ — done, see Shipped.
- ~~Finish the shell tests and make shell the default mode~~ — done, see Shipped.
- ~~Install as a Go binary, run from anywhere~~ — done, see Shipped.


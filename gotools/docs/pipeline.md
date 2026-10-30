# pipeline

Run the HOST and/or WEB methodology ([methodology.md](methodology.md)) from
one JSON target file instead of hand-chaining commands per
[playbook.md](playbook.md). `pipeline` orchestrates `srt`'s own subcommands
end to end and writes everything — including a `manifest.json` summary — to
one output directory.

It's still a subset of the full methodology — a few steps (subdomain
enumeration, a local tech-detect/title prober, content-based sensitive-info
classification, vulnx integration, ...) aren't implemented yet. See [The
methodology this is meant to drive](#the-methodology-this-is-meant-to-drive)
below.

## Quick start

```bash
srt pipeline -c engagement.json -kind host,web -o ./out
```

| Flag | Default | Meaning |
|---|---|---|
| `-c` | — (required) | pipeline JSON config file |
| `-kind` | auto | `host`, `web`, or `host,web` — which section(s) of the config to run. Auto runs whichever of `host`/`web` the config actually has. |
| `-o` | `options.outputDir`, else `srt-pipeline-out` | output directory |
| `-dry-run` | off | print the planned targets/steps and exit — sends no traffic |
| `-no-web-handoff` | off | don't auto-run the WEB stage against web services the HOST stage discovers |
| `-color` | `auto` | `auto` \| `always` \| `never` |

## Config file

```json
{
  "name": "example-engagement",
  "host": [
    "10.0.0.0/24",
    "192.168.1.5",
    { "target": "192.168.1.10", "ports": "22,80,443,8000-8100" }
  ],
  "web": [
    "example.com",
    "https://app.example.com/",
    "1.2.3.4",
    {
      "target": "https://admin.example.com",
      "wordlist": "custom.txt",
      "scope": "burp-scope.json",
      "extensions": [".php", ".bak"]
    }
  ],
  "options": {
    "outputDir": "./srt-pipeline-out",
    "concurrency": 40,
    "rate": 0,
    "rateGlobal": 0,
    "timeout": "10s",
    "insecure": true,
    "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "scope": "burp-scope.json",
    "ports": "common,uncommon",
    "proxy": ""
  }
}
```

- **`host`** and **`web`** are each a list of target entries. An entry is
  either a bare string (`"1.2.3.4"`, `"example.com"`) or an object with a
  required `target` field plus optional overrides — mix both freely in the
  same list.
- **`options`** sets pipeline-wide defaults. A per-target field of the same
  name always wins over `options`.
- A `web` entry can be a raw IP too (e.g. `"1.2.3.4"`) — it just won't have a
  domain to run `domains`/`gau`/`sensitive`/`params` against, so those steps
  are skipped for it (see [Steps](#steps) below); `robots` and `fuzz` still
  run against it directly.

### Per-target fields (object form)

| Field | Applies to | Meaning |
|---|---|---|
| `target` | host, web | the IP/CIDR/domain/URL (required) |
| `ports` | host | ports to scan (`portscan -p`), overrides `options.ports` (default `common,uncommon`) |
| `wordlist` | web | wordlist for `fuzz -w`, overrides `options.wordlist`. No wordlist resolved → `fuzz` is **skipped** for that target, not an error. |
| `scope` | web | Burp scope JSON for `fuzz -scope`, overrides `options.scope` |
| `extensions` | web | extra extensions for `fuzz -e` (repeatable) |
| `snykUrl` + `snykVersion` | web | both set → also runs `snyk -url -version` for that target |

## Steps

### `host` stage → `<outputDir>/host/`

Targets are grouped by their effective `ports` value so each distinct port
spec only runs once:

1. `ipexpand` — expand CIDRs/IPs into a unique IP list.
2. `resolve -reverse` — reverse DNS lookup per IP, informational (the
   methodology's "DNS check" for included hosts).
3. `portscan` — scan that group's port spec (see [`portscan`'s
   docs](commands.md#portscan) for what `-p` accepts).
4. Classify each open port:
   - **Web service** (a recognized HTTP(S) port) → added to the targets the
     `web` stage below runs against, automatically — this is the "hand off
     to WEB" step in methodology.md. Disable with `-no-web-handoff`.
   - **Uncommon/specialty port** (e.g. rsync, Java RMI) → recorded as a
     `flag-uncommon-service` step for manual follow-up.
   - Any open port with a grabbed banner, that isn't a web service → a
     `vulnx` step recorded as **skipped** (CVE lookups aren't wired up yet —
     see [ROADMAP.md](ROADMAP.md)).

Hosts marked excluded-but-tracked (reverse DNS + route trace only, never
actively probed) aren't supported yet — there's no way to mark a `host`
entry excluded in the schema today; see [ROADMAP.md](ROADMAP.md).

### `web` stage → `<outputDir>/web/`

Runs over all explicit `web` entries, **plus** any web services the `host`
stage discovered and handed off (written to a `web/` subfolder of that
`host`-stage run rather than a separate top-level one):

1. `domains` — extract domains from any URL-shaped targets.
2. `gau` — per discovered domain, archived URLs from the Wayback Machine
   (merged into one deduped list). **Skipped** if no domain was extracted
   (e.g. the `web` list is all bare IPs).
3. `sensitive` + `params` — classify the merged URL list. **Skipped** if step
   2 produced no URLs.
4. `robots` — per target, fetch `robots.txt` and probe its paths.
5. `fuzz` — per target with a resolved wordlist (see the field table above).
   **Skipped** per-target if no wordlist resolves.
6. `snyk` — per target that sets both `snykUrl` and `snykVersion`.
   **Skipped** otherwise.

A skipped step is recorded in the manifest with a `detail` explaining why —
it never aborts the run.

`scopecheck` isn't part of either stage yet: in `playbook.md` it filters
*domains discovered during the web stage* against the *host stage's* IP
scope, which is a cross-stage link left for later (see ROADMAP.md) rather
than folded into v1.

## Output layout

```
<outputDir>/
  manifest.json
  host/
    00_raw_<n>.txt          # raw CIDR/IP entries for that ports group
    01_ipexpand_<n>.txt
    02_resolve_<n>.txt       # reverse DNS
    03_portscan_<n>.json
    web/                      # web services the host stage discovered,
      ...                     #   same layout as the top-level web/ below
  web/
    00_targets.txt
    01_domains.txt
    02_gau_<domain>.txt      # one per domain
    02_all_urls.txt          # merged, deduped
    03_sensitive.txt
    04_params.txt
    05_robots_<target>.txt
    06_fuzz_<target>.json
    07_snyk_<target>.txt
```

## manifest.json

Written once, at the end of the run, even if some steps failed or were
skipped:

```json
{
  "name": "example-engagement",
  "startedAt": "2026-10-30T12:00:00Z",
  "endedAt": "2026-10-30T12:00:06Z",
  "kinds": ["host", "web"],
  "steps": [
    {
      "kind": "web",
      "name": "fuzz",
      "target": "https://app.example.com",
      "status": "ok",
      "output": "out/web/06_fuzz_https___app.example.com.json",
      "duration": "4.2s"
    },
    {
      "kind": "web",
      "name": "fuzz",
      "target": "1.2.3.4",
      "status": "skipped",
      "detail": "no wordlist configured (set this target's \"wordlist\" or options.wordlist)"
    }
  ]
}
```

`status` is one of `"ok"`, `"error"`, or `"skipped"`.

## The methodology this is meant to drive

Today's `host`/`web` stages implement most of the flow described in
[methodology.md](methodology.md) — port scanning, reverse DNS, service
classification, and the web hand-off are all there. A few pieces aren't
implemented yet: subdomain enumeration, a local tech-detect/title prober
("recon on root"), context-aware wordlist generation, Google dorking,
content-based sensitive-info classification, and the "easy wins"
misconfiguration pass. As each lands it gets added to
`pipeline_host.go`/`pipeline_web.go` in the order `methodology.md` lays out.
See [ROADMAP.md](ROADMAP.md) for what's queued.

`srt`'s policy is to implement that gap natively rather than shell out to
third-party tools (naabu, httpx, subfinder, katana, nuclei, dalfox). The one
exception is **vulnx**, for CVE lookups from a grabbed service/software
version. `gotools/cmd/srt/pipeline_external.go` ships the plumbing for that
(`runExternal`: look up a binary on `PATH`, run it, capture its output, and
report a clean `"skipped"` step instead of failing the run when it isn't
installed) — not wired into a stage yet, but ready for when the vulnx step
lands: a step calls `runExternal(kind, name, target, "vulnx", args,
outFile)` the same way existing steps call `runStep(...)`.

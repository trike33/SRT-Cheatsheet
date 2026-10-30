# `srt fuzz` — scope-aware bruteforcer guide

A concurrent directory/file bruteforcer built around two ideas: **precise
control over the traffic you send**, and a hard guarantee that nothing leaves
your defined scope.

## The FUZZ keyword

`FUZZ` marks where each wordlist entry is substituted. It works in the URL, in
any header value, and in the body:

```bash
srt fuzz -u https://host/FUZZ            -w words.txt   # path fuzzing
srt fuzz -u https://host/ -H "Host: FUZZ.host" -w subs.txt -mc all -fs 0   # vhost
srt fuzz -u https://host/api -X POST -d '{"user":"FUZZ"}' -w users.txt -mc all
```

If `-u` has no `FUZZ`, it's appended to the path (`https://host` → `https://host/FUZZ`),
so the common case is just `-u https://host`.

## Scope gating (the precision guarantee)

Point `-scope` at a **Burp Suite scope JSON export**. The `host` and `file`
fields in that file are regexes, and srt compiles and evaluates them exactly as
Burp does:

- a request is sent only if it matches an **include** rule **and no exclude** rule;
- the `protocol` field is honored — an `https`-only exclude won't block `http`;
- out-of-scope candidates are counted and dropped *before* any packet is sent.

With `-scope` and **no** `-u`, srt seeds `https://<host>/FUZZ` for every concrete
(non-wildcard) include host — point it at the scope file and go:

```bash
srt fuzz -scope target_scope.json -w raft-medium-directories.txt -ac -recursion
```

Wildcard include hosts (`*.example.com`) can't be resolved, so they aren't
seeded automatically — feed those through `subfinder` → `scopecheck` first and
pass concrete hosts with `-u`, still gated by `-scope`.

## Killing false positives: `-ac`

Many sites return `200` for everything (soft-404s). `-ac` probes a few random
paths first, fingerprints the response (size + word count), and auto-filters
anything that matches. Turn it on whenever results look too good:

```bash
srt fuzz -u https://host/FUZZ -w words.txt -ac
# stderr: [!] calibrate: filtering size=29 words=3 (soft-404 on host)
```

You can also filter manually: `-fs 1337` (hide that size), `-fw 12`, `-fc 404`,
`-fr 'Not Found'`, etc. Matchers (`-mc/-ms/-mw/-ml/-mr`) and filters combine —
a response is shown only if it passes every matcher and trips no filter.

## Precise pacing

- `-rate N` — a **global** token bucket: total requests/second across all
  workers, independent of `-c`. The way to be gentle on a target.
- `-delay` / `-jitter` — fixed + random delay before each request.
- `-c` — worker concurrency; `-timeout`, `-retries`.
- `-random-agent` — rotate a realistic browser User-Agent per request.
- `-proxy http://127.0.0.1:8080` — send everything through Burp for inspection.
- `-maxtime 30m` — hard stop for the whole run.
- `-maxerrors 15` — abandon a target after N consecutive errors (dead host), so
  you don't hammer something that's down.

```bash
# quiet, realistic, inspectable, time-boxed
srt fuzz -scope scope.json -w big.txt \
  -rate 15 -jitter 200ms -random-agent \
  -proxy http://127.0.0.1:8080 -maxtime 1h -maxerrors 20 -ac
```

## Recursion

`-recursion` descends into discovered directories (detected via a redirect to
the same path with a trailing slash). `-depth` caps how deep; scope still
applies at every level.

```bash
srt fuzz -u https://host/FUZZ -w words.txt -e .php -recursion -depth 3 -ac
```

## Output

- default: aligned table `status size words lines url`, colored by status;
- `-silent`: only matched URLs — pipe straight on: `… -silent | httpx -silent | nuclei`;
- `-json`: one JSON object per hit (`url,status,length,words,lines`);
- `-o file`: save hits (plain `status url`, or JSON with `-json`).

Progress (`reqs/matches/skipped/errors`) and the summary print to stderr, so
redirected/piped stdout stays clean.

## Recipes

```bash
# content discovery with extensions, hide the boilerplate 404 page by size
srt fuzz -u https://host/FUZZ -w raft-medium-files.txt \
  -e .php -e .bak -e .old -fs 0,1337 -ac -silent -o hits.txt

# only interesting codes, feed to nuclei
srt fuzz -u https://host/FUZZ -w common.txt -mc 200,401,403 -silent | nuclei -silent

# whole scope, through Burp, rate-limited, recursive
srt fuzz -scope scope.json -w directory-list-2.3-medium.txt \
  -proxy http://127.0.0.1:8080 -rate 20 -recursion -depth 2 -ac
```

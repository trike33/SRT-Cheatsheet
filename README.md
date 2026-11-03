<img src="srt-animated-glyph.svg" width="72" height="72" align="right" alt="">

# SRT-Cheatsheet

A bug-bounty / pentest recon toolkit built around **`srt`**, a single Go CLI
(stdlib-only except for one small dependency, used just by the interactive
`shell`) — that's the whole point of this repo now.

**New here? Start with [QUICKSTART.md](QUICKSTART.md).**

See [`gotools/`](gotools/) for the tool itself:

- [`gotools/docs/methodology.md`](gotools/docs/methodology.md) — the HOST and
  WEB assessment methodology `srt` is built to automate.
- [`gotools/docs/commands.md`](gotools/docs/commands.md) — every subcommand's
  flags.
- [`gotools/docs/pipeline.md`](gotools/docs/pipeline.md) — `srt pipeline`,
  the JSON-driven orchestrator that runs a whole assessment in one command.
- [`gotools/docs/ROADMAP.md`](gotools/docs/ROADMAP.md) — shipped features and
  backlog.

```bash
# install the latest release (Linux/macOS, no Go toolchain needed)
curl -fsSL https://raw.githubusercontent.com/trike33/SRT-Cheatsheet/main/install.sh | sudo bash

# or build from source
cd gotools && make build && ./srt help
```

`install.sh` won't reinstall over an existing `srt` — it just prints the
current version and points here. Update an existing install this way instead:

```bash
curl -fsSL https://raw.githubusercontent.com/trike33/SRT-Cheatsheet/main/update.sh | sudo bash
```

Want `srt dork -search` to actually run queries, or `pipeline`'s
`options.uncover`/chaos subdomain source to have something to query with? Run
`./config.sh` for a guided wizard through getting and setting those API keys —
everything it configures is optional, `srt` works fully without any of it.

[`legacy/`](legacy/) holds the original Python scripts the project started
as, kept for reference only — unmaintained, fully superseded by `srt`.

### Reminders worth keeping in mind on an engagement

- Most CMS/LMS platforms have plugins installed — find them.
- The application surface is rarely limited to the upstream CMS code on
  GitHub, so fuzz the whole app with recursion, not just the known codebase.

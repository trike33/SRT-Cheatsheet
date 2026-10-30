# SRT-Cheatsheet

A bug-bounty / pentest recon toolkit built around **`srt`**, a single
dependency-free Go CLI — that's the whole point of this repo now. See
[`gotools/`](gotools/) for the tool itself:

- [`gotools/docs/methodology.md`](gotools/docs/methodology.md) — the HOST and
  WEB assessment methodology `srt` is built to automate.
- [`gotools/docs/commands.md`](gotools/docs/commands.md) — every subcommand's
  flags.
- [`gotools/docs/pipeline.md`](gotools/docs/pipeline.md) — `srt pipeline`,
  the JSON-driven orchestrator that runs a whole assessment in one command.
- [`gotools/docs/ROADMAP.md`](gotools/docs/ROADMAP.md) — shipped features and
  backlog.

```bash
cd gotools && make build && ./srt help
```

[`legacy/`](legacy/) holds the original Python scripts the project started
as, kept for reference only — unmaintained, fully superseded by `srt`.

### Reminders worth keeping in mind on an engagement

- Most CMS/LMS platforms have plugins installed — find them.
- The application surface is rarely limited to the upstream CMS code on
  GitHub, so fuzz the whole app with recursion, not just the known codebase.

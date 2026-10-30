# Legacy scripts

This directory holds the original Python glue scripts the project started as,
kept for reference only. They are **not maintained** and are **not part of
the current tool** — that's [`gotools/`](../gotools/), a single Go CLI (`srt`)
that ports and extends everything here. See
[`gotools/docs/methodology.md`](../gotools/docs/methodology.md) for the
current HOST/WEB methodology these scripts originally implemented piecemeal.

| Path | Ported to |
|---|---|
| `HOST/ipparser.py` | `srt ipexpand` |
| `HOST/format-ips.py` | `srt ipports` |
| `HOST/domain-extracter.py` | `srt domains` |
| `HOST/domain_enum.py` | `srt scopecheck` |
| `WEB/domains-to-httpx.py` | `srt burphosts` |
| `WEB/domains-parser.py` | `srt burpscope` |
| `WEB/gau_recon.py` | `srt gau` / `srt sensitive` / `srt params` |
| `dir_listing.py` | `srt dirlist` |
| `robots-checker.py` | `srt robots` |
| `relative_paths.py` | `srt relpaths` |
| `synk_parser.py` | `srt snyk` |
| `Automated methodology.md` | superseded by `gotools/docs/methodology.md` |

If you're starting a new engagement, use `srt` — run `srt help` or see
[`gotools/docs/commands.md`](../gotools/docs/commands.md).

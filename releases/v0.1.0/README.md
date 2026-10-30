# srt v0.1.0 — prebuilt binaries

Static, stdlib-only builds of the `srt` recon toolkit (source in [`gotools/`](../../gotools)).

> These live in the repo because this project's automated session can't create
> GitHub Releases, push tags, or add a `.github/workflows/` file (all blocked by
> policy — see `gotools/README.md`). Binaries are gzipped; verify with
> `SHA256SUMS` (hashes are of the **uncompressed** binary).

| Platform | File |
|---|---|
| Linux x86-64 | `srt-linux-amd64.gz` |
| Linux arm64 | `srt-linux-arm64.gz` |
| macOS Intel | `srt-darwin-amd64.gz` |
| macOS Apple Silicon | `srt-darwin-arm64.gz` |
| Windows x86-64 | `srt-windows-amd64.exe.gz` |

## Install (Linux/macOS)

Pick your file; this is the Linux x86-64 example:

```bash
curl -fsSL https://github.com/trike33/SRT-Cheatsheet/raw/main/releases/v0.1.0/srt-linux-amd64.gz | gunzip > srt
chmod +x srt
./srt help
# optional: sudo mv srt /usr/local/bin/srt
```

## Verify

```bash
# after gunzip, compare against SHA256SUMS
sha256sum srt            # compare to the srt-linux-amd64 line in SHA256SUMS
```

## Promote to a real GitHub Release (when you have `workflow`/release creds)

From a clone authenticated with your own account:

```bash
# option A: let CI do it — activate the workflow, then tag
mkdir -p .github/workflows && git mv gotools/ci/build.yml .github/workflows/build.yml
git commit -m "Enable build workflow" && git push
git tag -a v0.1.0 -m "srt v0.1.0" && git push origin v0.1.0

# option B: upload these binaries straight to a release
cd releases/v0.1.0 && for f in *.gz; do gunzip -k "$f"; done
gh release create v0.1.0 --title "srt v0.1.0" --generate-notes \
  srt-linux-amd64 srt-linux-arm64 srt-darwin-amd64 srt-darwin-arm64 srt-windows-amd64.exe
```

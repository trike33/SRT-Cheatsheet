#!/usr/bin/env bash
# Installs the latest srt release binary to $PREFIX/bin (default /usr/local).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/trike33/SRT-Cheatsheet/main/install.sh | sudo bash
#   sudo ./install.sh
#
# Source of truth is this repo's GitHub Releases -- a prebuilt binary, not a
# source build (see gotools/Makefile's "make build"/"make install" for that).
set -euo pipefail

REPO="trike33/SRT-Cheatsheet"
PREFIX="${PREFIX:-/usr/local}"
BIN_NAME="srt"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64 | amd64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *)
    echo "error: unsupported architecture: $arch" >&2
    exit 1
    ;;
esac
case "$os" in
  linux | darwin) ;;
  *)
    echo "error: this script supports linux and darwin only." >&2
    echo "Windows: grab srt-windows-amd64.exe from https://github.com/${REPO}/releases/latest" >&2
    exit 1
    ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "error: this installs to ${PREFIX}/bin and needs root -- run with sudo." >&2
  exit 1
fi

asset="srt-${os}-${arch}"
url="https://github.com/${REPO}/releases/latest/download/${asset}"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

echo "Downloading ${asset} from the latest release..." >&2
curl -fsSL -o "$tmp" "$url"
chmod +x "$tmp"

install -d "${PREFIX}/bin"
install -m 0755 "$tmp" "${PREFIX}/bin/${BIN_NAME}"

echo "Installed to ${PREFIX}/bin/${BIN_NAME}" >&2
"${PREFIX}/bin/${BIN_NAME}" version

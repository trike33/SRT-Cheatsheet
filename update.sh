#!/usr/bin/env bash
# Updates an existing srt install to the latest release, from this repo's
# GitHub Releases -- re-runs install.sh fresh each time (no local version
# cache), so this is always "whatever's latest right now."
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/trike33/SRT-Cheatsheet/main/update.sh | sudo bash
#   sudo ./update.sh
set -euo pipefail

REPO="trike33/SRT-Cheatsheet"
PREFIX="${PREFIX:-/usr/local}"
BIN_PATH="${PREFIX}/bin/srt"

if [ "$(id -u)" -ne 0 ]; then
  echo "error: this updates ${BIN_PATH} and needs root -- run with sudo." >&2
  exit 1
fi

old_version="not installed"
if [ -x "$BIN_PATH" ]; then
  old_version="$("$BIN_PATH" version 2>/dev/null | head -1)"
  old_version="${old_version:-unknown}"
fi
echo "Current: ${old_version}" >&2

curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/install.sh" | bash

new_version="$("$BIN_PATH" version 2>/dev/null | head -1)"
echo "Updated: ${old_version} -> ${new_version:-unknown}" >&2

#!/usr/bin/env bash
# Updates an existing srt install -- re-runs install.sh fresh each time (no
# local version cache), so this is always "whatever's latest right now."
# By default that is the latest GitHub Release binary; with --local-build it
# pulls the repo clone and recompiles instead (see install.sh for details,
# including SRT_SRC_DIR and PREFIX).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/trike33/SRT-Cheatsheet/main/update.sh | sudo bash
#   sudo ./update.sh
#   ./update.sh --local-build
#   curl -fsSL .../update.sh | bash -s -- --local-build
set -euo pipefail

REPO="trike33/SRT-Cheatsheet"
PREFIX="${PREFIX:-/usr/local}"
BIN_PATH="${PREFIX}/bin/srt"

local_build=0
for arg in "$@"; do
  [ "$arg" = "--local-build" ] && local_build=1
done

# A local build only needs root if the destination isn't writable, which
# install.sh checks itself; the release path always needs it.
if [ "$local_build" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  echo "error: this updates ${BIN_PATH} and needs root -- run with sudo." >&2
  exit 1
fi

old_version="not installed"
if [ -x "$BIN_PATH" ]; then
  old_version="$("$BIN_PATH" version 2>/dev/null | head -1)"
  old_version="${old_version:-unknown}"
fi
echo "Current: ${old_version}" >&2

curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/install.sh" | bash -s -- "$@"

new_version="$("$BIN_PATH" version 2>/dev/null | head -1)"
echo "Updated: ${old_version} -> ${new_version:-unknown}" >&2

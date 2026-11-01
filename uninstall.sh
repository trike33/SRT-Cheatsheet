#!/usr/bin/env bash
# Removes the srt binary installed by install.sh / update.sh.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/trike33/SRT-Cheatsheet/main/uninstall.sh | sudo bash
#   sudo ./uninstall.sh
#   ./uninstall.sh --purge                # also delete the --local-build clone
#
# Honors the same PREFIX (default /usr/local) and SRT_SRC_DIR (default
# ~/.local/src/SRT-Cheatsheet) as install.sh. Engagement output such as
# srt-pipeline-out/ lives wherever you ran srt and is never touched.
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BIN_PATH="${PREFIX}/bin/srt"
SRC_DIR="${SRT_SRC_DIR:-$HOME/.local/src/SRT-Cheatsheet}"
PURGE=0

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    -h | --help)
      sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "error: unknown option: $arg (see --help)" >&2
      exit 1
      ;;
  esac
done

if [ -e "$BIN_PATH" ] || [ -L "$BIN_PATH" ]; then
  if [ ! -w "$(dirname "$BIN_PATH")" ]; then
    echo "error: cannot remove ${BIN_PATH} -- run with sudo or set PREFIX." >&2
    exit 1
  fi
  rm -f "$BIN_PATH"
  echo "Removed ${BIN_PATH}" >&2
else
  echo "Nothing to remove: ${BIN_PATH} not found." >&2
fi

if [ "$PURGE" -eq 1 ]; then
  # Only delete a directory that is actually a git clone of this repo.
  if [ -d "${SRC_DIR}/.git" ] && [ -d "${SRC_DIR}/gotools/cmd/srt" ]; then
    rm -rf "$SRC_DIR"
    echo "Removed clone ${SRC_DIR}" >&2
  else
    echo "No srt clone at ${SRC_DIR}; skipping --purge." >&2
  fi
fi

#!/usr/bin/env bash
# Removes the srt binary installed by install.sh / update.sh.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/trike33/SRT-Cheatsheet/main/uninstall.sh | sudo bash
#   sudo ./uninstall.sh
#   ./uninstall.sh --purge                # also delete the --local-build clone
#   sudo ./uninstall.sh --purge-pd        # also `pdtm -r` vulnx/nuclei/cdncheck/tlsx
#
# Honors the same PREFIX (default /usr/local) and SRT_SRC_DIR (default
# ~/.local/src/SRT-Cheatsheet) as install.sh. Engagement output such as
# srt-pipeline-out/ lives wherever you ran srt and is never touched.
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BIN_PATH="${PREFIX}/bin/srt"
SRC_DIR="${SRT_SRC_DIR:-$HOME/.local/src/SRT-Cheatsheet}"
PURGE=0
PURGE_PD=0


# --- ProjectDiscovery tools (opt-in), managed through pdtm -------------------
# Duplicated in install.sh / update.sh / uninstall.sh on purpose: each one has
# to work standalone via `curl | bash`. Runs as the invoking user (SUDO_USER
# when under sudo) so the tools land in *their* ~/.pdtm, not root's.
PD_TOOLS="vulnx,nuclei,cdncheck,tlsx"

# pd_run <-i|-u|-r> <bootstrap 0|1>
pd_run() {
  local runner=(bash -lc)
  if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    runner=(sudo -H -u "$SUDO_USER" bash -lc)
  fi
  "${runner[@]}" '
    flag=$1; tools=$2; bootstrap=$3
    pdtm="$(command -v pdtm || true)"
    for p in "$HOME/.pdtm/go/bin/pdtm" "$HOME/go/bin/pdtm"; do
      if [ -z "$pdtm" ] && [ -x "$p" ]; then pdtm="$p"; fi
    done
    if [ -z "$pdtm" ]; then
      if [ "$bootstrap" != 1 ]; then
        echo "pdtm not found; skipping ProjectDiscovery tools (install.sh --with-pd sets it up)." >&2
        exit 0
      fi
      # sudo resets PATH and a login shell skips ~/.bashrc, so also try the
      # usual Go install locations before giving up.
      for d in /usr/local/go/bin /usr/lib/go/bin /usr/local/bin "$HOME/go/bin"; do
        if ! command -v go >/dev/null 2>&1 && [ -x "$d/go" ]; then PATH="$PATH:$d"; fi
      done
      command -v go >/dev/null 2>&1 || { echo "error: pdtm is not installed and Go was not found (PATH or /usr/local/go/bin) to build it." >&2; exit 1; }
      echo "Installing pdtm..." >&2
      go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
      pdtm="$(go env GOPATH)/bin/pdtm"
    fi
    "$pdtm" "$flag" "$tools"
    if [ "$flag" = "-i" ]; then
      case ":$PATH:" in
        *":$HOME/.pdtm/go/bin:"*) ;;
        *) echo "note: add to your shell profile: export PATH=\"\$HOME/.pdtm/go/bin:\$PATH\"" >&2 ;;
      esac
    fi
  ' _ "$1" "$PD_TOOLS" "$2"
}

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    --purge-pd) PURGE_PD=1 ;;
    -h | --help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
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

if [ "$PURGE_PD" -eq 1 ]; then
  # Removes only the tools; pdtm itself and ~/.pdtm are left in place.
  pd_run -r 0
fi

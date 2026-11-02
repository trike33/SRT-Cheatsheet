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
#   sudo ./update.sh --with-pd            # also `pdtm -u` vulnx/nuclei/cdncheck/tlsx/subfinder/dnsx/alterx
set -euo pipefail

# --- ProjectDiscovery tools (opt-in), managed through pdtm -------------------
# Duplicated in install.sh / update.sh / uninstall.sh on purpose: each one has
# to work standalone via `curl | bash`. Runs as the invoking user (SUDO_USER
# when under sudo) so the tools land in *their* ~/.pdtm, not root's.
PD_TOOLS="vulnx,nuclei,cdncheck,tlsx,subfinder,dnsx,alterx"

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

REPO="trike33/SRT-Cheatsheet"
PREFIX="${PREFIX:-/usr/local}"
BIN_PATH="${PREFIX}/bin/srt"

local_build=0
with_pd=0
args=()
for arg in "$@"; do
  case "$arg" in
    --local-build) local_build=1; args+=("$arg") ;;
    --with-pd) with_pd=1 ;; # handled here, not by install.sh
    *) args+=("$arg") ;;
  esac
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

curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/install.sh" | bash -s -- "${args[@]}"

new_version="$("$BIN_PATH" version 2>/dev/null | head -1)"
echo "Updated: ${old_version} -> ${new_version:-unknown}" >&2

if [ "$with_pd" -eq 1 ]; then
  pd_run -u 0
fi

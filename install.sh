#!/usr/bin/env bash
# Installs srt to $PREFIX/bin (default /usr/local).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/trike33/SRT-Cheatsheet/main/install.sh | sudo bash
#   sudo ./install.sh
#   ./install.sh --local-build            # clone + compile instead (needs git, Go 1.24+)
#   curl -fsSL .../install.sh | bash -s -- --local-build
#   sudo ./install.sh --with-pd           # also install vulnx/nuclei/cdncheck/tlsx via pdtm
#
# --with-pd installs (building pdtm with Go if missing) the ProjectDiscovery
# tools the pipeline can use, as the invoking user (SUDO_USER), not root.
#
# By default this fetches the prebuilt binary from this repo's GitHub
# Releases. With --local-build it clones the repo (or fast-forwards an
# existing clone) into $SRT_SRC_DIR (default ~/.local/src/SRT-Cheatsheet),
# compiles gotools/cmd/srt with the local Go toolchain, and installs it to
# $PREFIX/bin. Use PREFIX=$HOME/.local to avoid needing root.
set -euo pipefail

REPO="trike33/SRT-Cheatsheet"
PREFIX="${PREFIX:-/usr/local}"
BIN_NAME="srt"
SRC_DIR="${SRT_SRC_DIR:-$HOME/.local/src/SRT-Cheatsheet}"
LOCAL_BUILD=0
WITH_PD=0

for arg in "$@"; do
  case "$arg" in
    --local-build) LOCAL_BUILD=1 ;;
    --with-pd) WITH_PD=1 ;;
    -h | --help)
      sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "error: unknown option: $arg (see --help)" >&2
      exit 1
      ;;
  esac
done

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

# Installs $1 to ${PREFIX}/bin/srt and reports the version.
install_bin() {
  install -d "${PREFIX}/bin"
  install -m 0755 "$1" "${PREFIX}/bin/${BIN_NAME}"
  echo "Installed to ${PREFIX}/bin/${BIN_NAME}" >&2
  "${PREFIX}/bin/${BIN_NAME}" version
  case ":${PATH}:" in
    *":${PREFIX}/bin:"*) ;;
    *) echo "note: ${PREFIX}/bin is not on your PATH -- add: export PATH=\"${PREFIX}/bin:\$PATH\"" >&2 ;;
  esac
  if [ "$WITH_PD" -eq 1 ]; then
    pd_run -i 1
  fi
}

if [ "$LOCAL_BUILD" -eq 1 ]; then
  for tool in git go; do
    command -v "$tool" >/dev/null 2>&1 || {
      echo "error: --local-build needs '$tool' on PATH." >&2
      exit 1
    }
  done

  if [ -d "${SRC_DIR}/.git" ]; then
    echo "Updating clone in ${SRC_DIR}..." >&2
    git -C "$SRC_DIR" pull --ff-only
  else
    echo "Cloning https://github.com/${REPO} into ${SRC_DIR}..." >&2
    mkdir -p "$(dirname "$SRC_DIR")"
    git clone "https://github.com/${REPO}.git" "$SRC_DIR"
  fi

  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  echo "Building srt..." >&2
  (cd "${SRC_DIR}/gotools" && GOTOOLCHAIN=local go build -trimpath -ldflags="-s -w" -o "$tmp" ./cmd/srt)

  # Only demand root when the destination isn't writable by this user.
  dest="${PREFIX}/bin"
  while [ ! -e "$dest" ]; do dest="$(dirname "$dest")"; done
  if [ ! -w "$dest" ]; then
    echo "error: ${PREFIX}/bin is not writable -- run with sudo or set PREFIX=\$HOME/.local." >&2
    exit 1
  fi
  install_bin "$tmp"
  exit 0
fi

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

install_bin "$tmp"

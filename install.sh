#!/usr/bin/env bash
# Installs srt to $PREFIX/bin (default /usr/local).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/trike33/SRT-Cheatsheet/main/install.sh | sudo bash
#   sudo ./install.sh
#   ./install.sh --local-build            # clone + compile instead (needs git, Go 1.24+)
#   curl -fsSL .../install.sh | bash -s -- --local-build
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

for arg in "$@"; do
  case "$arg" in
    --local-build) LOCAL_BUILD=1 ;;
    -h | --help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "error: unknown option: $arg (see --help)" >&2
      exit 1
      ;;
  esac
done

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

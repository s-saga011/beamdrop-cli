#!/bin/sh
# beamdrop CLI installer (macOS/Linux).
#
# Usage:
#   curl -fsSL .../install.sh | sh                       # install only
#   curl -fsSL .../install.sh | sh -s -- recv ROOM       # install if needed, then receive
#   curl -fsSL .../install.sh | sh -s -- send <file>     # install if needed, then send
#
# Already-installed binaries are reused unless BEAMDROP_FORCE_INSTALL=1.
set -e

REPO="s-saga011/beamdrop-cli"
INSTALL_DIR="${BEAMDROP_INSTALL_DIR:-$HOME/.local/bin}"
BIN_NAME="beamdrop"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac
case "$OS" in
  darwin|linux) ;;
  msys*|mingw*|cygwin*) OS=windows; BIN_NAME="beamdrop.exe" ;;
  *) echo "unsupported os: $OS" >&2; exit 1 ;;
esac

# 1. Locate existing install
EXISTING=""
if command -v "$BIN_NAME" >/dev/null 2>&1; then
  EXISTING=$(command -v "$BIN_NAME")
elif [ -x "$INSTALL_DIR/$BIN_NAME" ]; then
  EXISTING="$INSTALL_DIR/$BIN_NAME"
fi

TARGET="$INSTALL_DIR/$BIN_NAME"

if [ -n "$EXISTING" ] && [ "${BEAMDROP_FORCE_INSTALL:-0}" != "1" ]; then
  echo "beamdrop already installed: $EXISTING"
  TARGET="$EXISTING"
else
  ASSET="beamdrop-${OS}-${ARCH}"
  [ "$OS" = "windows" ] && ASSET="${ASSET}.exe"
  URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
  mkdir -p "$INSTALL_DIR"
  echo "Downloading ${ASSET}..."
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$TARGET"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$URL" -O "$TARGET"
  else
    echo "neither curl nor wget found" >&2
    exit 1
  fi
  chmod +x "$TARGET"
  echo "Installed: $TARGET"

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
      echo
      echo "Note: $INSTALL_DIR is not on your PATH yet. Add this to your shell rc:"
      echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
      ;;
  esac
fi

# 2. If subcommand args were supplied via `sh -s -- ...`, run them.
if [ "$#" -gt 0 ]; then
  echo
  exec "$TARGET" "$@"
fi

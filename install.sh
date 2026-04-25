#!/bin/sh
# beamdrop CLI installer + auto-updater (macOS/Linux).
#
# Usage:
#   curl -fsSL .../install.sh | sh                       # install or update only
#   curl -fsSL .../install.sh | sh -s -- recv ROOM       # update if needed, then receive
#   curl -fsSL .../install.sh | sh -s -- send <file>     # update if needed, then send
#
# BEAMDROP_FORCE_INSTALL=1   forces re-download regardless of version.
# BEAMDROP_INSTALL_DIR=...   override install location (default: ~/.local/bin).
set -e

REPO="s-saga011/beamdrop-cli"
INSTALL_DIR="${BEAMDROP_INSTALL_DIR:-$HOME/.local/bin}"
BIN_NAME="beamdrop"

# OS / arch detection
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

# Locate existing install (PATH first, then $INSTALL_DIR)
EXISTING=""
if command -v "$BIN_NAME" >/dev/null 2>&1; then
  EXISTING=$(command -v "$BIN_NAME")
elif [ -x "$INSTALL_DIR/$BIN_NAME" ]; then
  EXISTING="$INSTALL_DIR/$BIN_NAME"
fi

INSTALLED_VER=""
if [ -n "$EXISTING" ]; then
  INSTALLED_VER=$("$EXISTING" --version 2>/dev/null || true)
fi

# Determine latest release tag (retry transient 5xx)
LATEST_VER=""
if command -v curl >/dev/null 2>&1; then
  LATEST_VER=$(curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused \
      "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
elif command -v wget >/dev/null 2>&1; then
  LATEST_VER=$(wget -qO- --tries=3 --waitretry=2 \
      "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
fi

NEED_INSTALL=1
if [ -n "$EXISTING" ] && [ "${BEAMDROP_FORCE_INSTALL:-0}" != "1" ]; then
  if [ -n "$INSTALLED_VER" ] && [ -n "$LATEST_VER" ] && [ "$INSTALLED_VER" = "$LATEST_VER" ]; then
    echo "beamdrop $INSTALLED_VER already at latest ($EXISTING)"
    NEED_INSTALL=0
  elif [ -z "$LATEST_VER" ]; then
    echo "beamdrop installed ($EXISTING); skipping (could not check latest version)"
    NEED_INSTALL=0
  else
    echo "beamdrop ${INSTALLED_VER:-<unknown>} → ${LATEST_VER} (updating)"
  fi
fi

TARGET="$INSTALL_DIR/$BIN_NAME"

if [ "$NEED_INSTALL" = "1" ]; then
  ASSET="beamdrop-${OS}-${ARCH}"
  [ "$OS" = "windows" ] && ASSET="${ASSET}.exe"
  URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
  mkdir -p "$INSTALL_DIR"
  echo "Downloading ${ASSET}..."
  # curl --retry: transient errors include HTTP 408/429/5xx and network issues.
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 5 --retry-delay 2 --retry-connrefused "$URL" -o "$TARGET"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --tries=5 --waitretry=2 "$URL" -O "$TARGET"
  else
    echo "neither curl nor wget found" >&2
    exit 1
  fi
  chmod +x "$TARGET"
  echo "Installed: $TARGET ($($TARGET --version 2>/dev/null || echo "?"))"

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
      echo
      echo "Note: $INSTALL_DIR is not on your PATH yet. Add this to your shell rc:"
      echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
      ;;
  esac
else
  TARGET="$EXISTING"
fi

# If subcommand args were supplied via `sh -s -- ...`, run them.
if [ "$#" -gt 0 ]; then
  echo
  exec "$TARGET" "$@"
fi

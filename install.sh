#!/bin/sh
# beamdrop CLI installer (macOS/Linux).
# Pulls the latest release binary for the current platform and drops it in
# ~/.local/bin (override with BEAMDROP_INSTALL_DIR).
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

ASSET="beamdrop-${OS}-${ARCH}"
[ "$OS" = "windows" ] && ASSET="${ASSET}.exe"
URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"

mkdir -p "$INSTALL_DIR"
TARGET="${INSTALL_DIR}/${BIN_NAME}"

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
    echo "$INSTALL_DIR is not on your PATH. Add it with:"
    case "${SHELL##*/}" in
      zsh)  echo "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.zshrc && source ~/.zshrc" ;;
      bash) echo "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.bashrc && source ~/.bashrc" ;;
      fish) echo "  fish_add_path '$INSTALL_DIR'" ;;
      *)    echo "  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
    esac
    ;;
esac

echo
echo "Try:"
echo "  beamdrop send /path/to/file"
echo "  beamdrop recv <share-url-or-room-id>"

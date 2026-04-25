#!/bin/sh
# Build release binaries for major platforms into dist/.
# Version: pass on command line (./build-release.sh v0.1.2) or read from
# the most recent git tag (default: "dev" if no tags).
set -e

VERSION="${1:-$(git describe --tags --abbrev=0 2>/dev/null || echo dev)}"
echo "Building $VERSION"

mkdir -p dist
LDFLAGS="-s -w -X main.Version=${VERSION}"

build() {
  goos=$1; goarch=$2; ext=$3
  out="dist/beamdrop-${goos}-${goarch}${ext}"
  echo "→ $out"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "$LDFLAGS" -o "$out" .
}

build darwin  arm64 ""
build darwin  amd64 ""
build linux   amd64 ""
build linux   arm64 ""
build windows amd64 ".exe"

ls -la dist/

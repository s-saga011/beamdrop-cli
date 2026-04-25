#!/bin/sh
# Build release binaries for major platforms into dist/.
set -e

mkdir -p dist
LDFLAGS="-s -w"

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

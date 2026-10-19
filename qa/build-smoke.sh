#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'This gate requires a real macOS runner.' >&2
  exit 1
fi
smoke_dir="$(mktemp -d "${TMPDIR:-/tmp}/route-monitor-build.XXXXXX")"
trap 'rm -rf "$smoke_dir"' EXIT
for arch in arm64 amd64; do
  CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "$smoke_dir/monitor-$arch" .
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "$smoke_dir/bridge-$arch" ./cmd/route-bridge
done
lipo -create "$smoke_dir/monitor-arm64" "$smoke_dir/monitor-amd64" -output "$smoke_dir/route-monitor"
lipo "$smoke_dir/route-monitor" -verify_arch arm64 x86_64
plutil -lint Info.plist
echo 'Unsigned universal app binary and both Linux bridge builds passed.'

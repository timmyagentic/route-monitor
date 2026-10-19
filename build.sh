#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build/RouteMonitor
: "${CODESIGN_IDENTITY:?Set CODESIGN_IDENTITY to an Apple-issued signing identity}"
APP='build/RouteMonitor/Route Monitor.app'
mkdir -p "$APP/Contents/MacOS"
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o build/route-monitor-arm64 .
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o build/route-monitor-amd64 .
lipo -create -output "$APP/Contents/MacOS/route-monitor" build/route-monitor-arm64 build/route-monitor-amd64
cp Info.plist "$APP/Contents/Info.plist"
VERSION="$(sed -n 's/^var version = "\(.*\)"$/\1/p' main.go)"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" "$APP/Contents/Info.plist"
codesign --force --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$APP"
codesign --verify --strict "$APP"
mkdir -p build/RouteMonitor/router
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o build/RouteMonitor/router/route-bridge-linux-arm64 ./cmd/route-bridge
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o build/RouteMonitor/router/route-bridge-linux-amd64 ./cmd/route-bridge
(cd build/RouteMonitor/router && shasum -a 256 route-bridge-linux-*) > build/RouteMonitor/router/SHA256SUMS
cp install.command 'build/RouteMonitor/安装.command'
cp README.md 'build/RouteMonitor/使用说明.md'
{
  echo 'Third-party licenses (Go modules and Go runtime)'
  while IFS='|' read -r module directory; do
    [ -n "$directory" ] || continue
    for license in "$directory"/LICENSE "$directory"/LICENSE.txt "$directory"/LICENSE.md "$directory"/COPYING; do
      [ -f "$license" ] || continue
      printf '\nModule: %s\n\n' "$module"
      cat "$license"
    done
  done < <(go list -m -f '{{.Path}}|{{.Dir}}' all)
  printf '\nGo runtime license\n\n'
  runtime_license="$(go env GOROOT)/LICENSE"
  [ -f "$runtime_license" ] || runtime_license="$(go env GOROOT)/../LICENSE"
  cat "$runtime_license"
} > build/RouteMonitor/THIRD_PARTY_NOTICES.txt
chmod 755 'build/RouteMonitor/安装.command' "$APP/Contents/MacOS/route-monitor"
(cd build && /usr/bin/ditto --norsrc --noextattr -c -k --keepParent RouteMonitor RouteMonitor-macOS.zip)
shasum -a 256 build/RouteMonitor-macOS.zip

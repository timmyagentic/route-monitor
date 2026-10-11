#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build/RouteMonitor
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o build/route-monitor-arm64 .
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o build/route-monitor-amd64 .
lipo -create -output build/RouteMonitor/route-monitor build/route-monitor-arm64 build/route-monitor-amd64
codesign --force --sign - build/RouteMonitor/route-monitor
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
chmod 755 'build/RouteMonitor/安装.command' build/RouteMonitor/route-monitor
(cd build && /usr/bin/ditto --norsrc --noextattr -c -k --keepParent RouteMonitor RouteMonitor-macOS.zip)
shasum -a 256 build/RouteMonitor-macOS.zip

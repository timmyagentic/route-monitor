#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
TARGET="$HOME/Library/Application Support/RouteMonitor"
PLIST="$HOME/Library/LaunchAgents/local.route-monitor.plist"
BIN="$(pwd)/route-monitor"
mkdir -p "$TARGET" "$HOME/Library/LaunchAgents"
chmod 700 "$TARGET"
if [ ! -f "$TARGET/config.json" ]; then
  "$BIN" -data "$TARGET" -setup
else
  echo '保留已有配置与历史，验证路由器连接。'
  "$BIN" -data "$TARGET" -check
fi
if [ -f "$PLIST" ]; then
  launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
fi
cp "$BIN" "$TARGET/route-monitor.new"
chmod 700 "$TARGET/route-monitor.new"
mv "$TARGET/route-monitor.new" "$TARGET/route-monitor"
# Paths are generated on this Mac. plist values are XML-escaped by the binary helper.
"$TARGET/route-monitor" -data "$TARGET" -install-agent
launchctl bootstrap "gui/$(id -u)" "$PLIST"
open 'http://localhost:9780/'
echo '安装完成。登录此 Mac 后会自动启动；Mac 睡眠或退出登录时采集会暂停。'
echo '在其他设备上使用此 Mac 的局域网 IP 加 :9780 访问。'
echo '按回车退出。'
read -r

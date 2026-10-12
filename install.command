#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
TARGET="$HOME/Library/Application Support/RouteMonitor"
PLIST="$HOME/Library/LaunchAgents/local.route-monitor.plist"
SOURCE_APP="$(pwd)/Route Monitor.app"
APP="$HOME/Applications/Route Monitor.app"
BIN="$SOURCE_APP/Contents/MacOS/route-monitor"
mkdir -p "$TARGET" "$HOME/Library/LaunchAgents" "$HOME/Applications"
chmod 700 "$TARGET"
codesign --verify --strict "$SOURCE_APP"
if [ ! -f "$TARGET/config.json" ]; then
  "$BIN" -data "$TARGET" -setup
else
  echo '保留已有配置与历史，验证路由器连接。'
  "$BIN" -data "$TARGET" -check
fi
STAGED_APP="$(mktemp -d "$HOME/Applications/.route-monitor-install.XXXXXX")/Route Monitor.app"
ditto "$SOURCE_APP" "$STAGED_APP"
codesign --verify --strict "$STAGED_APP"
if [ -f "$PLIST" ]; then
  launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
fi
if [ -d "$APP" ]; then
  BACKUP="$(mktemp -d "$TARGET/app-backup.XXXXXX")"
  mv "$APP" "$BACKUP/Route Monitor.app"
fi
mv "$STAGED_APP" "$APP"
rmdir "$(dirname "$STAGED_APP")"
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$APP"
# Paths are generated on this Mac. plist values are XML-escaped by the binary helper.
"$APP/Contents/MacOS/route-monitor" -data "$TARGET" -install-agent
launchctl enable "gui/$(id -u)/local.route-monitor"
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo '后台正在连接路由器；系统询问本地网络权限时，请允许 Route Monitor。'
READY=0
for attempt in {1..60}; do
  if curl --noproxy '*' --fail --silent --max-time 2 'http://127.0.0.1:9780/healthz' >/dev/null; then
    READY=1
    break
  fi
  sleep 2
done
if [ "$READY" != 1 ]; then
  echo "后台尚未恢复采集。请检查系统设置中的 Route Monitor 本地网络权限，以及 $TARGET/logs/service.log。" >&2
  exit 1
fi
if [ "${ROUTE_MONITOR_NONINTERACTIVE:-0}" != 1 ]; then
  open 'http://localhost:9780/'
fi
echo '安装完成。登录此 Mac 后会自动启动；Mac 睡眠或退出登录时采集会暂停。'
echo '在其他设备上使用此 Mac 的局域网 IP 加 :9780 访问。'
if [ "${ROUTE_MONITOR_NONINTERACTIVE:-0}" != 1 ]; then
  echo '按回车退出。'
  read -r
fi

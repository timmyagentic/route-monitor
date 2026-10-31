# 交给 Agent 安装 Route Monitor

用户已要求安装时，请执行可自动完成的本机步骤，直到后台采集和页面可用。
首次密钥、页面密码及系统权限由用户在目标 Mac 上完成。安装目标是基础观察；
持续纠偏保持关闭，SSH、路由桥接、规则服务和自动发布不属于默认安装范围。

## 1. 核对环境和已有安装

- 使用 macOS；公开 ZIP 包含 Apple Silicon/Intel 通用应用，不需要 Go、Python、Node 或 SSH。
- 只在目标 Mac 确认用户实际的 Mihomo API 地址和访问方式，不套用 README 示例 IP 或其他机器的配置。
- 检查 `~/Applications/Route Monitor.app`、`~/Library/Application Support/RouteMonitor/` 和 `~/Library/LaunchAgents/local.route-monitor.plist`。已有安装保留配置、页面密码、历史和纠偏模式；先报告当前模式，不擅自把已有模式改成 off 或 auto。
- 用户仅要求检查时保持只读；已授权安装或升级时再执行安装器。它会重启本应用服务，不应操作其他服务。

## 2. 下载并验证同一正式版

从 https://github.com/timmyagentic/route-monitor/releases/latest 一次确定正式 tag，
下载同版 ZIP、`.zip.sha256` 和 provenance JSON 到新临时目录，检查 SHA-256 后
再安全解压。当前正式包为 `RouteMonitor-0.1.1-macOS.zip`；不得把未发布 main
编译包当成正式发行版，也不要覆盖用户已有源码目录。

```sh
shasum -a 256 -c RouteMonitor-0.1.1-macOS.zip.sha256
codesign --verify --deep --strict "/absolute/extracted/Route Monitor.app"
```

核对 provenance 中的版本、来源提交和包哈希。当前包已做 Apple Developer ID
签名，尚未公证；系统要求确认时交给用户处理。不得关闭 Gatekeeper、删除
quarantine 或更改系统安全设置。签名/哈希不匹配时停止并报告。

## 3. 执行安装

阅读包内 `安装.command` 后，在目标 Mac 的交互终端运行它。
新安装会询问路由器 API 地址、已有管理密钥和单独的页面访问密码（至少 12 字符）。
用户直接在不回显输入的终端填写，不把密钥或密码发送到聊天、日志或脚本参数。
已有配置时安装器会验证连接并保留配置与数据库。

已有持续纠偏配置时，Mac 安装器不会替换路由器上的桥接程序。0.1.1 的 DNS
负答案解析修复需要另行更新路由器上相应架构的 `route-bridge`；先取得设备修改
授权，备份旧程序，核对新程序哈希并验证。未更新时应报告该修复尚未生效。

系统提示本地网络或防火墙权限时，让用户为 Route Monitor 完成对应授权。
不要把终端中的连接成功当作后台 App 权限成功。安装器会等待后台连接、错误订阅
和存储恢复；非零退出或超时均为未完成，保留实际错误，不反复覆盖配置重试。

## 4. 首次使用和后台验收

1. 确认安装路径、版本和 `local.route-monitor` 的实际运行进程与 plist。
2. 访问本机 `http://127.0.0.1:9780/healthz`，必须返回 HTTP 200；连接断开或采样陈旧返回 503。
3. 打开 `http://localhost:9780/`，由用户输入刚设置的页面密码，检查连接状态、采集时间和一条真实新连接。空闲时明确报告暂无流量，不制造历史或把探测当业务成功。
4. 关闭安装终端后再检查 healthz 和后台进程；登录自启是当前用户 LaunchAgent。未实际测试的重启、退出登录和休眠唤醒标为 UNVERIFIED。
5. 升级时核对原配置和历史仍保留。不要删除数据库、重置密码、启用纠偏或更改路由器。

完成时报告版本、App/数据/plist 路径、健康状态、页面和后台验证结果，以及仍需
用户完成的权限或连接步骤。基础安装不需要发布规则。按 README 的明确步骤另行
配置纠偏前，不安装路由器桥接，也不更改网络或设备策略。

隔离验收应使用独立 macOS 用户，或明确独立的数据、端口和测试服务身份。
安装器使用固定 `local.route-monitor` 标签和 9780 健康检查端口；仅改变目录不代表
服务已隔离，不得直接拿现有服务做新用户安装试验。

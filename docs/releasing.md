# 发布流程

发布准备不等于发布。只有用户明确要求发布时才执行 tag/Release 步骤。已授权后完成下载验证，无需再次确认。

1. 从最新、已通过两个必需 CI 检查的远端 main 创建独立 release worktree。核对版本、双语发布记录及源提交；`python3 tools/check-release.py` 必须成功。不要混入其他分支的未发布改动。
2. 在授权的本机 Mac 用 `CODESIGN_IDENTITY` 指定本项目现有 Apple 签名身份，运行 `./build.sh`。不得把签名私钥、用户配置或其他项目的凭据上传到仓库或 CI。默认构建不会安装或启动生产服务。
3. 检查 ZIP 完整性、包内文件清单、app 的 `codesign --verify --strict`、arm64/x86_64 架构及版本；确认不含配置、数据库、日志或凭据。记录包 SHA-256 和完整源提交。普通 CI 的 unsigned build smoke 不能替代此步骤。
4. 将最终包命名为 `RouteMonitor-VERSION-macOS.zip`，生成同名 `.sha256`。先用 `gh release view vVERSION` 和 `git ls-remote origin refs/tags/vVERSION` 确认没有已有发布/标签。发现已有项时先核对，不覆盖或自动删除。
5. 用经过核对的源提交作为 `--target`，创建 GitHub Release 并上传包、checksum 和构建来源 JSON。Release 说明包含功能、版本、验证范围、签名与公证状态。未公证就明确说明，不声称 Gatekeeper/公证通过。
6. 通过 `gh release download vVERSION --pattern 'RouteMonitor-*' --dir <新临时目录>` 下载远端产物，核对 SHA-256、文件大小、包内版本与签名，读取 tag 的目标 SHA 和 Release URL。只有远端字节一致才算分发完成。

手工发布只使用当前仓库的 GitHub 权限，不自动部署服务、修改路由器、推送其他订阅或更改已安装客户端。若上传失败，检查同一个 Release 的现有资产后补齐，不盲目重建版本或覆盖已下载的包。

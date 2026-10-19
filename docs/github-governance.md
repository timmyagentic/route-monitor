# GitHub 协作规则

本仓库参考 QuotaMonitor 的 main ruleset 与 AGENTS.md：通过 PR 合并，禁止删除与强推，要求解决所有审查对话，没有绕过名单。保留单维护者的 0 个强制 approval；实质性审查问题仍须判断和处理。

Route Monitor 的 CI 与 Swift 项目不同，使用 Go/静态检查及真实 macOS 测试与通用二进制构建。两个检查在每个 PR 和 main push 上运行，没有 Draft 或路径过滤产生的“跳过即成功”。私有仓库需要支持 rulesets 的 GitHub 套餐；当前配置应以仓库 Settings → Rules → Rulesets 的实时读回为准。

## main 规则

- Pull request required，所有审查对话已解决。
- 必需检查：`Go and static checks`、`macOS build and tests`，来源为 GitHub Actions。
- 分支必须与 main 同步；禁止强推和删除；没有 bypass actor。
- 只允许 squash merge，合并后删除远端功能分支。

首次空仓库以已交付源码初始化 main，此后治理变更和产品改动均通过 PR。不要把首次初始化当作后续直推的例外。

## 每次交付

使用独立 worktree 和 `codex/` 分支，更新双语 changelog，运行项目门禁，再提交和创建 Ready PR。界面改动附真实截图。合并前检查差异与 review，使用完整 SHA 执行：

```sh
python3 tools/verify-pr.py PR_NUMBER FULL_HEAD_SHA
gh pr merge PR_NUMBER --squash --match-head-commit FULL_HEAD_SHA
```

验证器检查当前 head、Ready/Open、base main、分支同步、两个检查的成功状态和 GitHub Actions 来源，以及所有分页中的未解决审查对话。GitHub ruleset 在最终合并时再执行强制约束。不得使用 `--admin` 或临时关闭规则。合并后读取远端 main 与对应 CI；发布遵循 [发布流程](releasing.md)。

不照搬 QuotaMonitor 的 Swift、Sparkle、私有 Beta、品牌同步或签名密钥配置。源码托管、包分发和当前生产运行是独立证据层。

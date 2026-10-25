# Route Monitor repository rules

## Scope and safety

Route Monitor is a Go service with embedded HTML/CSS/JavaScript, a macOS app bundle, and an on-demand Linux router bridge. Application code and tests live at the repository root; bridge code lives in `internal/routebridge/` and `cmd/route-bridge/`; local gates live in `qa/` and `tools/`.

Never commit user configuration, history databases, logs, credentials, signing keys, or private QA exports. Tests use temporary directories and fictional configuration. Do not install, restart the real service, change router rules, publish a release, or alter production configuration unless the user has authorized that action. A request to publish includes the necessary release steps; do not ask twice.

## Worktree and verification

Fetch current `origin/main`, create an independent worktree and a `codex/` branch, and keep the primary checkout read-only. When working under Tingjun Workspace, its Task, Session, Context and writer-claim rules also apply.

Run focused tests while iterating. Once the candidate is stable, run `./qa/check.sh` once before commit/push. It owns formatting, shell/JavaScript/Python checks, changelog/version validation, whitespace, Go race tests and vet. Repeat only for new changes, a failure, or an unresolved risk. macOS contributors also run `./qa/build-smoke.sh`; Linux contributors may open a ready PR after the local gate, but must wait for the exact PR head's real macOS CI job before merge.

Tests and CI must not access the installed application's data, signing keychain, or a real router. CI build smoke checks compile unsigned binaries; they do not prove signing, installation, production routing, or App business success. Validate visible UI changes in an isolated instance, capture the exact candidate, and embed a verified screenshot in the PR and final handoff. State unavailable checks as `UNVERIFIED`.

## Pull requests and merge

Use concise imperative commit subjects. Push the branch and open a ready PR; use Draft only when requested or concretely blocked. Write the PR description in Chinese with the problem, resulting behavior, verification and relevant limitations. Every PR updates both `CHANGELOG.md` and `CHANGELOG.zh-Hans.md` under Unreleased; release preparation moves those entries into the numbered release. Do not manufacture product changes just to bump a version.

`main` requires a PR, successful current-head `Go and static checks` and `macOS build and tests`, an up-to-date branch, and resolved review conversations. No actor may bypass the rules, force-push, or delete main. Squash is the supported merge method. Zero mandatory approvals follows QuotaMonitor's single-maintainer setup; this is not permission to ignore a substantive review finding.

Before an authorized merge, inspect the diff and current reviews, fix material issues, and run `python3 tools/verify-pr.py <PR> <full-head-SHA>`. Merge with `gh pr merge <PR> --squash --match-head-commit <full-head-SHA>` without `--admin`. If main advances, update the branch and verify the new head. After merging, verify the remote main SHA and its CI. Never equate local tests, a draft skip, an old green SHA, a merge, a Release, and an installed client.

## Versions and releases

Keep `main.go`, both version fields in `Info.plist`, and both release changelog headings consistent. Use a patch increment for maintenance releases; a feature or breaking version change should reflect the actual scope. Release preparation is separate from publication. Follow `docs/releasing.md`; publish only a signed, inspected package with its SHA-256, and download the GitHub asset to verify the delivered bytes. Do not overwrite an existing tag or asset. Signing stays on an authorized local Mac; never copy another project's secrets into CI.

## Repository workflow and branch protection

- Confirm the current GitHub default branch before starting; it is currently `main`. Fetch it, use a separate `codex/` branch in an isolated worktree, and keep the primary checkout read-only. Under Tingjun Workspace, activate the Task and Session, acknowledge the current Context revision and hold the worktree's unique writer claim.
- All changes to the GitHub default branch must go through a PR. Direct pushes, force pushes and deletion of that branch are prohibited. Administrators and apps have no bypass. Never use `--admin`, disable protection or add a bypass actor to land a change.
- Only squash merging is allowed. Inspect the final diff, current head, review threads and actual verification results before an authorized merge. Resolve all review conversations and address substantive findings; zero mandatory approvals supports the single-maintainer workflow. Merge with `gh pr merge <PR> --squash --match-head-commit <verified-full-head-SHA>` and verify the merged state afterward.
- Keep `delete_branch_on_merge = true` and verify that GitHub automatically removes the merged PR's remote task branch when eligible. Do not use `--delete-branch`, which also removes the local branch. Under Tingjun Workspace, completion only releases the writer claim; local branches and worktrees remain for the existing archive workflow.
- The default-branch ruleset declaration is [`.github/rulesets/default-branch.json`](.github/rulesets/default-branch.json); repository merge and deletion settings are declared in [`.github/repository-settings.json`](.github/repository-settings.json). These files do not apply themselves. After an authorized configuration update, read back the GitHub repository settings, effective rules and any classic branch protection. Protect the actual default branch rather than assuming it is named `main`.
- Preserve the existing CI workflows, trigger conditions, required checks, app bindings and strictness. Existing stronger protections and immutable release tags remain in force. An empty or legitimately path-filtered checks list does not prove application tests passed; report the checks actually run and mark unavailable verification `UNVERIFIED`. Follow this repository's existing verification requirements and use proportionate document/configuration checks for documentation changes.

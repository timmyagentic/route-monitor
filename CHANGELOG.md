# Changelog

## [Unreleased]

- Add GitHub pull request protection, Linux and macOS CI, release checks, and contributor rules adapted from QuotaMonitor.

## [0.6.0] - 2026-10-19

- Add evidence-driven correction in both directions between direct and proxy routes, with two separated probe rounds and protected manual/device policy.
- Track cloud publication, router loading, path verification and new real-connection evidence separately; support scoped rollback.
- Limit automatic probing to 24 rounds and new rule additions to 20 per Beijing calendar day. Preserve paused legacy batches on upgrade.
- Distribute a signed universal macOS application and Linux arm64/amd64 bridge helpers. This package is not Apple-notarized.

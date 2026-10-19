#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

unformatted="$(gofmt -l $(git ls-files '*.go'))"
if [[ -n "$unformatted" ]]; then
  echo "Go files need gofmt:" >&2
  echo "$unformatted" >&2
  exit 1
fi
while IFS= read -r script; do bash -n "$script"; done < <(git ls-files '*.sh' '*.command')
node --check web/app.js
python3 -m unittest discover -s tools -p 'test_*.py'
if [[ -n "${PR_BASE_SHA:-}" ]]; then
  python3 tools/check-release.py --base "$PR_BASE_SHA"
else
  python3 tools/check-release.py
fi
git diff --check "${PR_BASE_SHA:-HEAD}"
go test -race ./...
go vet ./...

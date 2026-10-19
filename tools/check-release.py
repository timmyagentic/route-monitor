#!/usr/bin/env python3
"""Validate repository version metadata and the bilingual PR changelog."""
import argparse
import pathlib
import plistlib
import re
import subprocess


def validate(root, changed=None):
    errors = []
    match = re.search(r'^var version = "(\d+\.\d+\.\d+)"$', (root / 'main.go').read_text(), re.M)
    if not match:
        return ['main.go must declare a numeric three-part version']
    version = match.group(1)
    info = plistlib.loads((root / 'Info.plist').read_bytes())
    for key in ['CFBundleShortVersionString', 'CFBundleVersion']:
        if info.get(key) != version:
            errors.append(f'{key} does not match main.go')
    for name in ['CHANGELOG.md', 'CHANGELOG.zh-Hans.md']:
        content = (root / name).read_text()
        if not re.search(r'^## \[Unreleased\]\s*$', content, re.M):
            errors.append(f'{name}: missing Unreleased heading')
        if not re.search(r'^## \[' + re.escape(version) + r'\] - \d{4}-\d{2}-\d{2}\s*\n\s*\S', content, re.M):
            errors.append(f'{name}: missing release notes for {version}')
        if changed is not None and name not in changed:
            errors.append(f'PR must update {name}')
    return errors


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', help='PR base commit, when validating a PR')
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    changed = None
    if args.base:
        changed = set(subprocess.check_output(['git', 'diff', '--name-only', args.base, 'HEAD'], cwd=root, text=True).splitlines())
    failures = validate(root, changed)
    if failures:
        raise SystemExit('\n'.join(failures))
    print('Version metadata and bilingual changelogs passed.')

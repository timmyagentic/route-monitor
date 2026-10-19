#!/usr/bin/env python3
"""Check a specific GitHub PR head immediately before an authorized merge."""
import argparse
import json
import re
import subprocess

REQUIRED = ('Go and static checks', 'macOS build and tests')


def gh(*args):
    return json.loads(subprocess.check_output(['gh', *args], text=True))


def validate(pr, head, runs, behind, unresolved):
    errors = []
    if pr['head']['sha'] != head:
        errors.append('PR head changed')
    if pr['state'] != 'open' or pr['draft'] or pr['base']['ref'] != 'main':
        errors.append('PR must be open, ready, and target main')
    if pr['mergeable'] is not True or pr['mergeable_state'] != 'clean' or behind != 0:
        errors.append('PR must be clean, mergeable, and up to date')
    for name in REQUIRED:
        candidates = [r for r in runs if r['name'] == name and r['head_sha'] == head and r.get('app', {}).get('slug') == 'github-actions']
        latest = max(candidates, key=lambda r: r['id'], default={})
        if latest.get('status') != 'completed' or latest.get('conclusion') != 'success':
            errors.append(f'{name}: current-head GitHub Actions success required')
    if unresolved:
        errors.append(f'{unresolved} unresolved review conversation(s)')
    return errors


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pr', type=int)
    parser.add_argument('head')
    parser.add_argument('--repo', help='owner/repository; defaults to current Git remote')
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.head):
        parser.error('provide the full 40-character head SHA')
    repo = args.repo or gh('repo', 'view', '--json', 'nameWithOwner')['nameWithOwner']
    owner, name = repo.split('/')
    base = f'repos/{repo}'
    pr = gh('api', f'{base}/pulls/{args.pr}')
    pages = gh('api', f'{base}/commits/{args.head}/check-runs?per_page=100', '--paginate', '--slurp')
    runs = [run for page in pages for run in page['check_runs']]
    comparison = gh('api', f'{base}/compare/main...{args.head}')
    unresolved = 0
    cursor = None
    query = '''query($owner:String!,$name:String!,$number:Int!,$cursor:String) {
      repository(owner:$owner,name:$name) { pullRequest(number:$number) {
        reviewDecision
        reviewThreads(first:100,after:$cursor) { nodes { isResolved } pageInfo { hasNextPage endCursor } }
      } }
    }'''
    while True:
        params = ['api', 'graphql', '-f', 'query=' + query, '-f', 'owner=' + owner, '-f', 'name=' + name, '-F', f'number={args.pr}']
        if cursor:
            params += ['-f', 'cursor=' + cursor]
        review = gh(*params)['data']['repository']['pullRequest']
        if review['reviewDecision'] == 'CHANGES_REQUESTED':
            raise SystemExit('A current review requests changes; inspect and address it before merging.')
        threads = review['reviewThreads']
        unresolved += sum(not t['isResolved'] for t in threads['nodes'])
        if not threads['pageInfo']['hasNextPage']:
            break
        cursor = threads['pageInfo']['endCursor']
    failures = validate(pr, args.head, runs, comparison['behind_by'], unresolved)
    current = gh('api', f'{base}/pulls/{args.pr}')
    if current['head']['sha'] != args.head or current['base']['sha'] != pr['base']['sha']:
        failures.append('PR head or base changed while checking; rerun verification')
    if failures:
        raise SystemExit('\n'.join(failures))
    print(json.dumps({'repository': repo, 'pr': args.pr, 'head': args.head, 'checks': list(REQUIRED), 'unresolvedThreads': 0, 'verified': True}))

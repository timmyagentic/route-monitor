import copy
import importlib.util
import pathlib
import plistlib
import tempfile
import unittest


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, pathlib.Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load('release', 'check-release.py')
merge = load('merge', 'verify-pr.py')


class GovernanceTests(unittest.TestCase):
    def test_release_rejects_drift_and_missing_translation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'main.go').write_text('var version = "0.6.0"\n')
            (root / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleVersion': '0.6.0', 'CFBundleShortVersionString': '0.6.0'}))
            for name in ['CHANGELOG.md', 'CHANGELOG.zh-Hans.md']:
                (root / name).write_text('## [Unreleased]\n\n- Change\n\n## [0.6.0] - 2026-10-19\n\n- Release\n')
            self.assertEqual(release.validate(root, {'CHANGELOG.md', 'CHANGELOG.zh-Hans.md'}), [])
            self.assertIn('PR must update CHANGELOG.zh-Hans.md', release.validate(root, {'CHANGELOG.md'}))
            (root / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleVersion': '0.5.0', 'CFBundleShortVersionString': '0.6.0'}))
            self.assertIn('CFBundleVersion does not match main.go', release.validate(root))

    def test_merge_gate_rejects_stale_skipped_and_unresolved_states(self):
        head = 'a' * 40
        pr = {'head': {'sha': head}, 'state': 'open', 'draft': False, 'base': {'ref': 'main'}, 'mergeable': True, 'mergeable_state': 'clean'}
        runs = [{'id': i, 'name': name, 'head_sha': head, 'app': {'slug': 'github-actions'}, 'status': 'completed', 'conclusion': 'success'} for i, name in enumerate(merge.REQUIRED)]
        self.assertEqual(merge.validate(pr, head, runs, 0, 0), [])
        for field, value in [('head_sha', 'b' * 40), ('conclusion', 'skipped'), ('conclusion', 'failure'), ('app', {'slug': 'untrusted-app'})]:
            changed = copy.deepcopy(runs)
            changed[0][field] = value
            self.assertTrue(merge.validate(pr, head, changed, 0, 0), field)
        latest = {**runs[0], 'id': 100, 'conclusion': 'failure'}
        self.assertTrue(merge.validate(pr, head, runs + [latest], 0, 0))
        self.assertTrue(merge.validate(pr, 'b' * 40, runs, 0, 0))
        self.assertTrue(merge.validate({**pr, 'draft': True}, head, runs, 0, 0))
        self.assertTrue(merge.validate(pr, head, runs, 1, 0))
        self.assertTrue(merge.validate(pr, head, runs, 0, 1))


if __name__ == '__main__':
    unittest.main()

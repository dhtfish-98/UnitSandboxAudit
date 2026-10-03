# Author: dhtfish98
# Copyright (c) 2026 dhtfish98
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unit_sandbox_audit import analyze

PROJECT = Path(__file__).resolve().parents[1]


class WritablePathLexicalTests(unittest.TestCase):
    def snapshot(self, value):
        snapshot = json.loads((PROJECT / 'examples/good.json').read_text())
        snapshot['fragments'][0]['text'] += '\nReadWritePaths=' + value + '\n'
        return snapshot

    def cli(self, snapshot):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'snapshot.json'
            raw = json.dumps(snapshot).encode()
            path.write_bytes(raw)
            result = subprocess.run([sys.executable, '-m', 'unit_sandbox_audit', str(path)], capture_output=True, text=True, timeout=10)
            self.assertEqual(path.read_bytes(), raw)
            self.assertNotIn('Traceback', result.stderr)
            return result.returncode, json.loads(result.stdout)

    def test_original_quoted_backslash_root_never_passes(self):
        for value in (r"'/\../'", r'"/\../"'):
            snapshot = self.snapshot(value)
            result = analyze(snapshot)
            self.assertEqual(result['status'], 'OPEN')
            self.assertTrue(any(f['check'] == 'writable_path_syntax' and f['status'] == 'OPEN' for f in result['findings']))
            self.assertEqual(self.cli(snapshot)[0], 3)

    def test_other_quoted_or_escaped_declarations_stay_open(self):
        for value in (r'/\../', r'/\x2e\x2e', r'/\056\056', "'/var/lib/example'", '"/var/lib/example"'):
            snapshot = self.snapshot(value)
            self.assertEqual(analyze(snapshot)['status'], 'OPEN')
            self.assertEqual(self.cli(snapshot)[0], 3)

    def test_plain_safe_absolute_paths_still_pass(self):
        for value in ('/var/lib/example', '-/var/lib/example', '+/var/lib/example', '/var/../var/lib/example'):
            snapshot = self.snapshot(value)
            self.assertEqual(analyze(snapshot)['status'], 'PASS')
            self.assertEqual(self.cli(snapshot)[0], 0)

    def test_plain_roots_still_fail(self):
        for value in ('/', '/../', '-/', '+/', '/var/../'):
            snapshot = self.snapshot(value)
            self.assertEqual(analyze(snapshot)['status'], 'FAIL')
            self.assertEqual(self.cli(snapshot)[0], 1)

    def test_unsupported_assignment_is_not_hidden_by_later_reset(self):
        snapshot = self.snapshot(r"'/\../'")
        snapshot['fragments'][0]['text'] += '\nReadWritePaths=\nReadWritePaths=/var/lib/example\n'
        self.assertEqual(analyze(snapshot)['status'], 'OPEN')
        self.assertEqual(self.cli(snapshot)[0], 3)

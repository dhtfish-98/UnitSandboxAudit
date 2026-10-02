import unittest,json,tempfile,subprocess,sys
from pathlib import Path
from unit_sandbox_audit import analyze
from unit_sandbox_audit.common import InputError
PROJECT=Path(__file__).resolve().parents[1]
class ReauditTests(unittest.TestCase):
    def good(self):return json.loads((PROJECT/'examples/good.json').read_text())
    def cli(self,snapshot,expected):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'case.json';p.write_text(json.dumps(snapshot))
            r=subprocess.run([sys.executable,'-m','unit_sandbox_audit',str(p)],capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,expected,r.stderr)
            self.assertNotIn('Traceback',r.stderr)
            return json.loads(r.stdout)
    def test_systemd_quoted_escaped_and_multicommand_privilege_vectors(self):
        for command in ('"+/usr/sbin/helper"',r'\x2b/usr/sbin/helper','/usr/sbin/helper ; +/usr/sbin/helper',"'+/usr/sbin/helper'"):
            with self.subTest(command=command):
                s=self.good();s['fragments'][0]['text']=s['fragments'][0]['text'].replace('ExecStart=/usr/sbin/helper','ExecStart='+command)
                self.assertEqual(analyze(s)['status'],'OPEN');self.assertEqual(self.cli(s,3)['status'],'OPEN')
    def test_unquoted_privileged_and_safe_commands_remain_distinct(self):
        s=self.good();self.assertEqual(self.cli(s,0)['status'],'PASS')
        s['fragments'][0]['text']+='\nExecStartPre=+/usr/sbin/helper'
        self.assertEqual(analyze(s)['status'],'FAIL');self.assertEqual(self.cli(s,1)['status'],'FAIL')

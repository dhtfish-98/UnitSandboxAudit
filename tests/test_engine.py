import unittest
from unit_sandbox_audit import analyze
from unit_sandbox_audit.engine import BOOLEAN
from unit_sandbox_audit.common import InputError

class UnitTests(unittest.TestCase):
    def good(self):return {'fragments':[{'name':'app.service','text':'[Service]\n'+'\n'.join(k+'=yes' for k in BOOLEAN)+'\nUser=service-account\nProtectSystem=strict\nProtectHome=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nUMask=0077\nExecStart=/usr/sbin/helper'}]}
    def test_positive(self):self.assertEqual(analyze(self.good())['status'],'PASS')
    def test_scalar_override(self):
        s=self.good();s['fragments'].append({'name':'10.conf','text':'[Service]\nNoNewPrivileges=no'});self.assertEqual(analyze(s)['status'],'FAIL')
    def test_list_reset(self):
        s=self.good();s['fragments'][0]['text']+='\nAmbientCapabilities=CAP_SYS_ADMIN';s['fragments'].append({'name':'20.conf','text':'[Service]\nAmbientCapabilities='});self.assertEqual(analyze(s)['status'],'PASS')
    def test_inversion_open(self):
        s=self.good();s['fragments'][0]['text']+='\nCapabilityBoundingSet=~CAP_SYS_ADMIN';self.assertEqual(analyze(s)['status'],'OPEN')
    def test_root_and_privilege_prefix(self):
        s=self.good();s['fragments'][0]['text']+='\nUser=root\nExecStart=+/usr/sbin/helper';self.assertEqual(analyze(s)['status'],'FAIL')
    def test_empty(self):self.assertEqual(analyze({'fragments':[]})['status'],'OPEN')
    def test_unknown(self):
        s=self.good();s['fragments'][0]['text']+='\nFutureSandbox=yes';self.assertEqual(analyze(s)['status'],'OPEN')
    def test_umask_symbolic_open(self):
        s=self.good();s['fragments'][0]['text']+='\nUMask=u=rwx';self.assertEqual(analyze(s)['status'],'OPEN')
    def test_duplicate_name(self):
        s=self.good();s['fragments']*=2
        with self.assertRaises(InputError):analyze(s)
    def test_wrong_type(self):
        with self.assertRaises(InputError):analyze({'fragments':{}})
    def test_zero_uid_spellings(self):
        for uid in ('0','00','0000'):
            s=self.good();s['fragments'][0]['text']+='\nUser='+uid
            self.assertEqual(analyze(s)['status'],'FAIL')
    def test_invalid_uid_and_dynamic_specifier_open(self):
        for user in ('4294967295','9'*100,'%u'):
            s=self.good();s['fragments'][0]['text']+='\nDynamicUser=yes\nUser='+user
            self.assertEqual(analyze(s)['status'],'OPEN')
    def test_normalized_writable_root(self):
        for path in ('/./','-/./','+/a/..','//','-+/../../'):
            s=self.good();s['fragments'][0]['text']+='\nReadWritePaths='+path
            self.assertEqual(analyze(s)['status'],'FAIL')
    def test_unknown_address_family_open(self):
        s=self.good();s['fragments'][0]['text']+='\nRestrictAddressFamilies=AF_IMAGINARY'
        self.assertEqual(analyze(s)['status'],'OPEN')
    def test_relative_and_specifier_paths_open(self):
        for path in ('relative','%h/data'):
            s=self.good();s['fragments'][0]['text']+='\nReadWritePaths='+path
            self.assertEqual(analyze(s)['status'],'OPEN')

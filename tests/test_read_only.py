import unittest
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parents[1] / 'src/Invoke-ADHealthAudit.ps1').read_text(encoding='utf8')


class ScriptContractTests(unittest.TestCase):
    def test_query_only_ad_cmdlets(self):
        for forbidden in ('Set-AD', 'New-AD', 'Remove-AD', 'Enable-AD', 'Disable-AD', 'Unlock-AD', 'Reset-AD'):
            self.assertNotIn(forbidden, SCRIPT)

    def test_sensitive_names_opt_in(self):
        self.assertIn('[switch]$IncludeAccountNames', SCRIPT)
        self.assertIn('if ($IncludeAccountNames)', SCRIPT)
        self.assertIn('indicators_are_not_confirmed_vulnerabilities', SCRIPT)

    def test_unknown_lastlogon_is_tracked_separately(self):
        self.assertIn('enabled_last_logon_unknown', SCRIPT)
        self.assertIn('LastLogonDate', SCRIPT)


if __name__ == '__main__':
    unittest.main()

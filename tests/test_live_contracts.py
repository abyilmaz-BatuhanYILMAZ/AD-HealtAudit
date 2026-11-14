import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'src/Invoke-ADHealthAudit.ps1').read_text(encoding='utf-8')


class LiveAuditContractTests(unittest.TestCase):
    def test_live_domain_selection_and_directory_queries(self):
        for name in ('[string]$Server', 'Get-ADDomain @common', 'Get-ADUser -Filter *',
                     'Get-ADComputer -Filter *', 'Get-ADGroupMember -Identity',
                     'Get-ADDefaultDomainPasswordPolicy @common'):
            self.assertIn(name, SOURCE)

    def test_declared_findings_and_error_integrity(self):
        for token in ('AD001', 'AD002', 'AD007', 'AD008', 'AD009', 'AD012', 'AD013',
                      "complete = ($warnings.Count -eq 0)", 'throw',
                      'confirmed_vulnerability = $false'):
            self.assertIn(token, SOURCE)

    def test_read_only_and_redacted_default(self):
        for forbidden in ('Set-AD', 'New-AD', 'Remove-AD', 'Enable-AD', 'Disable-AD',
                          'Unlock-AD', 'Reset-AD'):
            self.assertNotIn(forbidden, SOURCE)
        self.assertIn('if ($IncludeAccountNames)', SOURCE)
        self.assertIn("[ValidateSet('Json', 'Html')]", SOURCE)
        self.assertIn('Refusing to overwrite an existing report', SOURCE)

    def test_mock_powershell_test_and_ci(self):
        mock = (ROOT / 'tests/Mock-ADIntegration.ps1').read_text(encoding='utf-8')
        workflow = (ROOT / '.github/workflows/check.yml').read_text(encoding='utf-8')
        self.assertIn('Export-ModuleMember', mock)
        self.assertIn("'lab-account-1'", mock)
        self.assertIn('Mock-ADIntegration.ps1', workflow)
        self.assertIn('shell: powershell', workflow)


if __name__ == '__main__':
    unittest.main()

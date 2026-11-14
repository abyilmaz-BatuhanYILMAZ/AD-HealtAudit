# AD-HealthAudit — Live, read-only AD security indicators

A Windows PowerShell 5.1+ utility that **connects to an authorized live Active Directory Domain Services domain** and reports security-relevant user, computer, delegation, Kerberos encryption and default password-policy indicators. No LDAP modifications or other domain state changes are made.

## Prerequisites

- Windows management workstation with RSAT **ActiveDirectory** PowerShell module, network connectivity to an authorized Domain Controller, and directory read access.
- Windows PowerShell 5.1; the included Windows CI executes tests in this PowerShell edition using a **mocked** AD module, not a real domain.
- An approved test domain for the first real run. This does not target Microsoft Entra ID.

## Run directly against a domain

```powershell
Import-Module ActiveDirectory
Get-ADDomain -Server dc01.training.invalid

# Aggregate summary + risk indicators (account names redacted by default).
.\src\Invoke-ADHealthAudit.ps1 -Server dc01.training.invalid -StaleDays 90 -OutputPath .\audit.json

# Explicitly include account names, and generate a local HTML report.
.\src\Invoke-ADHealthAudit.ps1 -Server dc01.training.invalid -StaleDays 90 -IncludeAccountNames -Format Html -OutputPath .\audit.html

# Narrow user and computer scope to an OU, where appropriate.
.\src\Invoke-ADHealthAudit.ps1 -Server dc01.training.invalid -SearchBase 'OU=Lab,DC=training,DC=invalid' -OutputPath .\lab-audit.json
```

The `-Server` parameter selects the controller rather than relying on automatic discovery; omit it to discover a default. Use `-Credential (Get-Credential)` only if your authorized account requires it. Credentials are passed to RSAT and are not recorded in reports. The tool refuses to overwrite existing local reports.

## What it checks

- Enabled users with PasswordNeverExpires, disabled Kerberos preauthentication, AdminCount=1 and SPNs.
- User or computer `TrustedForDelegation` indicators, approximate stale logons and unknown last logon.
- Explicit DES/RC4 Kerberos encryption flags for user accounts (not proof of negotiated encryption).
- Domain Admins group membership count (RID 512).
- Default domain password policy (complexity and lockout indicators).
- Per-indicator severity, count, evidence attribute and corrective guidance. Account names are **opt-in**.
- Local JSON or HTML reports with `complete` and `warnings` fields when optional queries fail.

## Test coverage and safety

```bash
python -m unittest discover -s tests -v
```

GitHub Actions also contains a **Windows PowerShell 5.1 syntax check and end-to-end mocked ActiveDirectory module test**. A real Domain Controller is *not* provided by CI. The code is built to run against a live domain but **an end-to-end test with a real DC has not yet been performed**; that requires an authorized Windows AD DS test environment and RSAT.

All remote directory commands are **Get-AD*** queries. No Set-AD, New-AD, Remove-AD or other domain modifications are used. All output files are local. For risk interpretation and missing checks see [INTERPRETATION.md](docs/INTERPRETATION.md).

**License:** MIT. Use only on AD DS environments you are authorized to audit.


## Extended v0.3 live posture checks

The optional parameters CheckDcRegistry, CheckLapsMetadata and CheckAdcsTemplates add five further review indicators AD014–AD018.

~~~powershell
.\src\Invoke-ADHealthAudit.ps1 -Server dc01.training.invalid -CheckDcRegistry -CheckLapsMetadata -CheckAdcsTemplates -IncludeAccountNames -Format Html -OutputPath .\posture.html
~~~

- CheckDcRegistry: uses opt-in read-only WinRM to inspect LDAPServerIntegrity and LdapEnforceChannelBinding on the **selected** DC. An absent registry value, missing WinRM privilege or failed connection means **unknown**, not compliant. It does not actively test LDAP binds or every Domain Controller in a forest.
- CheckLapsMetadata: retrieves Windows/legacy LAPS expiration **timestamps**, never password values. Overdue values prompt investigation, not a breach finding.
- CheckAdcsTemplates: reads certificate template enrollee-supplied-subject flags. Actual AD CS exploitation requires other checks including EKUs, effective enrolment ACLs, CA publication and issuance requirements.

Extended checks are optional to preserve least-privilege basic inventory. Optional failures appear in warnings and make complete=false. The Windows CI verifies code with **mocked AD records**, not a real DC.

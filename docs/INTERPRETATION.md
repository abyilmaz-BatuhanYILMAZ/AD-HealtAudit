# Interpretation and limitations

AD-HealthAudit v0.3 is a **read-only live Active Directory Domain Services inventory**. It queries authorized directory objects via the Microsoft RSAT ActiveDirectory PowerShell module and produces report files only on the auditor's machine. A finding is an **indicator for human review**, not a confirmed exploit, breach, or CVE.

## Indicator catalogue

| ID | Signal | How to interpret |
| --- | --- | --- |
| AD001 | Enabled user PasswordNeverExpires | Legitimate service identities exist; review ownership and compensating controls |
| AD002 | DoesNotRequirePreAuth | Increased exposure to offline password guessing against AS-REP responses; investigate exception |
| AD003 | AdminCount=1 | May persist after privilege removal; not a complete effective privilege assessment |
| AD004 | User SPN present | Inventory signal, *not* a vulnerability on its own |
| AD005 | LastLogonDate older than threshold | Replicated, approximate timestamp; confirm against other sources |
| AD006 | LastLogonDate missing | Unknown status, not proof of dormancy |
| AD007 | User TrustedForDelegation | Unconstrained delegation risk; verify role and need |
| AD008 | msDS-SupportedEncryptionTypes DES flags | Explicitly configured legacy DES encryption bits; check environment and exceptions |
| AD009 | msDS-SupportedEncryptionTypes RC4 bit | Explicit legacy RC4 support, not proof that RC4 was used in a session |
| AD010 | Default lockout threshold 0 | Default policy signal; FGPPs and other controls could supersede it |
| AD011 | Default password complexity disabled | Default policy signal; not proof that effective passwords are weak |
| AD012 | Computer TrustedForDelegation | May be legitimate for carefully reviewed infrastructure; assess |
| AD013 | Computer stale LastLogonDate | Approximate device inactivity only |

The report has `complete=false` and warnings when **optional** inventory such as computers, Domain Admins group or default policy cannot be read. Required user/domain queries fail loudly. It intentionally does *not* invent safe defaults in place of missing information. The explicit encryption bits are checked only when the account advertises the attribute; an absent/zero setting must not be counted as confirmed RC4/DES usage.

**Out of scope in the main indicator report:** effective permissions, privilege relationships, domain-root DCSync ACLs and GPO permissions. A separate **read-only preliminary graph analyzer** now examines directly collected group memberships and selected group/domain/GPO ACL candidates (see [PRIVILEGE-PATHS.md](PRIVILEGE-PATHS.md)). The graph is not a complete effective-permission evaluator. LDAP signing/channel binding enforcement testing, Kerberos network captures, Microsoft Entra ID, password cracking, password exposure and domain exploitation remain out of scope. None of the scripts changes domain settings.

**Privacy:** Account names are excluded by default; `-IncludeAccountNames` adds potentially sensitive names to findings. Do not publish real inventory reports or commit them to GitHub. Output files are not overwritten automatically.


## Extended v0.3 indicators

| ID | Severity | Interpretation |
| --- | --- | --- |
| AD014 | HIGH | Selected DC LDAPServerIntegrity explicitly not 2 (Require Signing) |
| AD015 | HIGH | Selected DC LdapEnforceChannelBinding=0 (Never) |
| AD016 | MEDIUM | Selected DC LdapEnforceChannelBinding=1 (When supported, not Always) |
| AD017 | MEDIUM | Windows/legacy LAPS password expiration metadata overdue; no passwords read |
| AD018 | MEDIUM | Certificate template enrollee-supplied-subject flag; not an ESC vulnerability finding without ACL/EKU/publication assessment |

Unknown or absent registry values do not establish secure defaults; DC OS and applied policy can affect defaults. The optional registry read uses WinRM against only the explicit DC. This does not prove whether unsigned LDAP binds are accepted.

Official sources: https://support.microsoft.com/en-gb/servicing/os/windows/2020/02/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412 ; https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding ; https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference .

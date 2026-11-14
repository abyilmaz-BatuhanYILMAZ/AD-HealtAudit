# Interpretation and limitations

AD-HealthAudit v0.2 is a **read-only live Active Directory Domain Services inventory**. It queries authorized directory objects via the Microsoft RSAT ActiveDirectory PowerShell module and produces report files only on the auditor's machine. A finding is an **indicator for human review**, not a confirmed exploit, breach, or CVE.

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

**Out of scope:** full effective permissions and group graph, DCSync ACL audits, GPO analysis, LDAP signing/channel binding enforcement, live Kerberos network captures, Azure AD / Microsoft Entra ID, password cracking, password exposure, and domain exploitation. None of the scripts changes domain settings.

**Privacy:** Account names are excluded by default; `-IncludeAccountNames` adds potentially sensitive names to findings. Do not publish real inventory reports or commit them to GitHub. Output files are not overwritten automatically.

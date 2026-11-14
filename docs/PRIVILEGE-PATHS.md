# Active Directory privilege relationship paths (read-only)

This capability answers a **narrow, defensive** question: *Can an ordinary
domain identity reach membership in Domain Admins through collected direct
group memberships and candidate ACL-based membership changes?*

It also lists domain-root replication-right and GPO ACL indicators as
**separate high-impact exposures**, not as proven paths to Domain Admins.

## Setup and test-domain run

Prerequisites: Windows PowerShell 5.1, RSAT `ActiveDirectory` PowerShell
module, authorized read access to the chosen Domain Controller, Python 3.11+
for local report rendering. Run on a **disposable, authorized AD DS test
domain first**. No DA login is inherently required; sufficient directory
read-control rights are required to read security descriptors.

From the repository root:

```powershell
# Collect only one domain, starting with one selected account.
.\src\Export-ADPrivilegeGraph.ps1 `
  -Server dc01.lab.local `
  -StartSamAccountName ordinary.user `
  -MaxGroups 1500 `
  -IncludeIdentityNames `
  -OutputPath .\graph.json

# Generate local report; never copies data to any cloud service.
python .\src\ad_privilege_paths.py .\graph.json --format html --output .\privilege-paths.html

# Or inspect JSON with explicit evidence and completeness flags.
python .\src\ad_privilege_paths.py .\graph.json --format json --output .\privilege-paths.json
```

The selected `-Server` consistently selects a Domain Controller for
AD cmdlets. The collector uses `Get-ADUser`, `Get-ADGroup`,
`Get-ADDomain` and `Get-ADObject`; **no** password/credential
replication, directory modification, GPO change, Kerberos request or
administrator impersonation is performed.

`-IncludeIdentityNames` is opt-in: by default, nodes are identified by
their SID. Even SID-only exports and ACL evidence are sensitive internal
data. Do **not** commit graph or result files to public GitHub.

## Example (entirely synthetic)

```text
User/alice
  --[member_of]--> Group/Helpdesk
  --[member_of]--> Group/Delegated-Operators
  --[can_modify_group; candidate WriteDacl ACE]--> Group/Domain Admins
```

The output status is `potential_acl_path`, **not** `confirmed_exploit`.
The last edge means the delegated group appears to hold ACL rights that
*may* let it alter Domain Admins membership or ACLs. A human must
validate the actual effective permission before calling it exploitable.

Alternative statuses:

- `membership_path_found`: collected direct/nested group membership
  already reaches Domain Admins. It is not an escalation exploit.
- `potential_acl_path`: at least one ACL-derived candidate step is
  needed to reach Domain Admins; it has **not** been executed or proven.
- `no_path_in_collected_scope`: no route found in available relationships;
  **this does not prove the environment is safe**.

The graph search respects `--max-depth` (default 10). It finds a shortest
collected route; not all possible paths or the probability of exploitation.

## Evidence collection

The export is deliberately bounded by `-MaxGroups` and `-MaxAces`.
It reads group `memberOf` links (including the selected user's
`primaryGroupID` where present), ACLs on the collected groups,
the domain-root ACL and GPO container ACLs.

Potential Domain Admins membership changes are considered when a
collected Allow ACE grants WriteDacl, WriteOwner, or WriteProperty on
the specific `member` attribute (or all attributes). The exact ACE
and rights mask are retained as **evidence**. Other rights can create
paths that this prototype does not model.

A DCSync-rights **candidate** is reported only where the same trustee
has collected Allow ControlAccess rights for both
`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`
on the domain root. Other prerequisite access and Deny rules are
not evaluated, so this is **not evidence that a DCSync operation
could succeed**. Domain root ACL control and GPO control are
reported independently. GPO editing alone is **not** interpreted
as Domain Admin access, because `gPLink`, scope, security filtering,
SYSVOL permissions, policy application and protected account
behavior are not collected.

## Limitations and safe interpretation

- Collected Allow ACEs are **candidates**, not validated effective rights.
  Deny ACEs, inheritance/scope, ownership, principal token memberships
  and AdminSDHolder/SDProp effects are not fully evaluated.
- Only **one domain** is scanned. Foreign security principals,
  trusts and nested forest relationships may be absent.
- Sessions, local administrator rights, AD CS exploitation, RBCD,
  delegation and interactive Kerberos attacks are **not** graphed.
- Larger environments might exceed default group/ACE bounds. An
  incomplete audit is marked `complete=false` or fails explicitly;
  never interpret a missing path as proof of absence.
- `Get-ADObject -Properties nTSecurityDescriptor` needs rights to
  read DACLs, and not every domain grants all readers those permissions.
  Unreadable ACLs are warnings, **not** empty ACLs.
- AD CS and LDAP policy findings in the main audit are independent of
  this graph; do not infer paths from an unrelated low-confidence signal.
- Existing reports are **never overwritten**.
- Real Domain Controller execution is not yet validated; CI uses
  **synthetic PowerShell AD module responses** and offline Python tests.

## Authoritative references

- [Microsoft: AD access rights and effective evaluation considerations](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584)
- [Microsoft: Group member attribute schema GUID](https://learn.microsoft.com/en-us/windows/win32/adschema/a-member)
- [Microsoft: Replication Get Changes](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes)
- [Microsoft: Replication Get Changes All](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all)
- [Microsoft: Get-ADObject](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adobject)

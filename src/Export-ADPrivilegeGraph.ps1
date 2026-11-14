#requires -Version 5.1
<#
.SYNOPSIS
  Read-only, bounded AD DS graph collection for possible privilege relationships.
.DESCRIPTION
  Uses Get-AD* cmdlets only. No passwords, hashes, tickets, remote execution,
  domain changes or exploitation. Outputs local JSON for ad_privilege_paths.py.
  Graph candidates require review of effective ACLs, deny rules and live policy.
.EXAMPLE
  .\Export-ADPrivilegeGraph.ps1 -Server dc01.lab.invalid -StartSamAccountName alice -OutputPath .\graph.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$StartSamAccountName,
    [string]$Server,
    [System.Management.Automation.PSCredential]$Credential,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputPath,
    [ValidateRange(1,5000)][int]$MaxGroups = 1500,
    [ValidateRange(100,100000)][int]$MaxAces = 30000,
    [switch]$IncludeIdentityNames
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { Import-Module ActiveDirectory -ErrorAction Stop }
catch { throw 'RSAT ActiveDirectory module is required.' }

$common = @{}
if ($Server) { $common['Server'] = $Server }
if ($null -ne $Credential) { $common['Credential'] = $Credential }
if (Test-Path -LiteralPath $OutputPath) { throw 'Refusing to overwrite existing graph JSON.' }
$parentFolder = Split-Path -Parent $OutputPath
if ($parentFolder -and -not (Test-Path -LiteralPath $parentFolder)) { throw 'Output directory does not exist.' }

$domain = Get-ADDomain @common -ErrorAction Stop
$domainSid = [string]$domain.DomainSID
$domainDn = [string]$domain.DistinguishedName
$targetSid = $domainSid + '-512'
$start = Get-ADUser -Identity $StartSamAccountName -Properties SID,MemberOf,PrimaryGroupID @common -ErrorAction Stop
if ($null -eq $start.SID) { throw 'Start account SID missing; cannot construct privilege graph.' }
$startSid = [string]$start.SID
if ($start.SID -is [System.Security.Principal.SecurityIdentifier]) { $startSid = $start.SID.Value }

$nodes = [System.Collections.Generic.List[object]]::new()
$edges = [System.Collections.Generic.List[object]]::new()
$indicators = [System.Collections.Generic.List[object]]::new()
$warnings = [System.Collections.Generic.List[string]]::new()
$nodeKeys = @{}
$edgeKeys = @{}
$groupByDn = @{}
$aceTotal = 0
$aclCount = 0
$gpoRead = 0

function Add-GraphNode([string]$Id, [string]$Kind, [string]$Display) {
    if (-not $Id -or $nodeKeys.ContainsKey($Id)) { return }
    $nodeKeys[$Id] = $true
    $label = if ($IncludeIdentityNames -and $Display) { $Display } else { $Id }
    $nodes.Add([ordered]@{id=$Id; kind=$Kind; label=$label})
}
function Add-GraphEdge([string]$From, [string]$To, [string]$Relation, [string]$Evidence) {
    if (-not $From -or -not $To -or $From -eq $To) { return }
    $k = $From + '|' + $To + '|' + $Relation
    if ($edgeKeys.ContainsKey($k)) { return }
    $edgeKeys[$k] = $true
    $edges.Add([ordered]@{from=$From; to=$To; relation=$Relation; evidence=$Evidence})
}
function Get-SidText($Identity) {
    if ($null -eq $Identity) { return $null }
    if ($Identity -is [System.Security.Principal.SecurityIdentifier]) { return $Identity.Value }
    $value = [string]$Identity
    if ($value -match '^S-\d(-\d+)+$') { return $value }
    try {
        return $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        $warnings.Add('An ACL trustee SID could not be resolved. Graph coverage is incomplete.')
        return $null
    }
}
function Get-Rules($DirectoryObject, [string]$ObjectKind) {
    $sd = $DirectoryObject.'nTSecurityDescriptor'
    if ($null -eq $sd -or $null -eq $sd.Access) {
        $warnings.Add("Security descriptor unavailable for $ObjectKind; effective rights unknown.")
        return @()
    }
    return @($sd.Access)
}
function Inspect-Access($DirectoryObject, [string]$ObjectKind, [string]$ObjectSid, [string]$ObjectLabel) {
    $rules = @(Get-Rules $DirectoryObject $ObjectKind)
    $script:aclCount++
    $replication = @{}
    $denySids = @{}
    foreach ($ace in $rules) {
        $script:aceTotal++
        if ($script:aceTotal -gt $MaxAces) { throw 'ACE collection exceeds MaxAces; raise the audit limit explicitly.' }
        $sid = Get-SidText $ace.IdentityReference
        if (-not $sid) { continue }
        Add-GraphNode $sid 'SecurityPrincipal' $sid
        $type = [string]$ace.AccessControlType
        $rights = [int64]$ace.ActiveDirectoryRights
        $guid = [string]$ace.ObjectType
        if (-not $guid) { $guid = [guid]::Empty.ToString() }
        $guid = $guid.ToLowerInvariant()
        $unrestricted = ($guid -eq [guid]::Empty.ToString())
        if ($type -eq 'Deny') {
            $denySids[$sid] = $true
            continue
        }
        if ($type -ne 'Allow') { continue }
        $sourceEvidence = "Allow ACE: rights=$rights; objectType=$guid; object=$ObjectKind"
        # DirectoryServices.ActiveDirectoryRights flags (not raw GENERIC_* masks).
        $writeDacl = (($rights -band 262144) -ne 0)
        $writeOwner = (($rights -band 524288) -ne 0)
        $writeProperty = (($rights -band 32) -ne 0)
        $canEdit = ($writeDacl -or $writeOwner -or $writeProperty)
        if ($ObjectKind -eq 'group' -and $canEdit -and
            ($writeDacl -or $writeOwner -or ($writeProperty -and
            ($unrestricted -or $guid -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2')))) {
            Add-GraphEdge $sid $ObjectSid 'can_modify_group' ($sourceEvidence + '; group membership change is a candidate, not verified effective access')
        }
        if ($ObjectKind -eq 'domain') {
            if ($writeDacl -or $writeOwner) {
                $indicators.Add([ordered]@{
                    principal_sid=$sid; kind='domain_root_acl_control_candidate'; object='domain_root'
                    evidence=$sourceEvidence + '; could potentially change domain ACL, not direct DCSync'
                })
            }
            if (($rights -band 256) -ne 0) {
                if (-not $replication.ContainsKey($sid)) { $replication[$sid] = @{} }
                if ($unrestricted -or $guid -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') {
                    $replication[$sid]['get_changes'] = $true
                }
                if ($unrestricted -or $guid -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') {
                    $replication[$sid]['get_changes_all'] = $true
                }
            }
        }
        if ($ObjectKind -eq 'gpo' -and $canEdit) {
            $indicators.Add([ordered]@{
                principal_sid=$sid; kind='gpo_acl_control_candidate'
                object=$ObjectLabel
                evidence=$sourceEvidence + '; gPLink scope, ACL denies and SYSVOL rights unverified'
            })
        }
    }
    if ($denySids.Count -gt 0) {
        $warnings.Add("Deny ACLs were found on $ObjectKind; candidate Allow rights may not be effective.")
    }
    if ($ObjectKind -eq 'domain') {
        foreach ($entry in $replication.GetEnumerator()) {
            if ($entry.Value.ContainsKey('get_changes') -and $entry.Value.ContainsKey('get_changes_all')) {
                $indicators.Add([ordered]@{
                    principal_sid=$entry.Key; kind='dcsync_rights_candidate'; object='domain_root'
                    evidence='Allow ControlAccess ACEs for Get-Changes + Get-Changes-All detected. Not a DCSync operation or proven effective permission.'
                })
            }
        }
    }
}

# Group inventory intentionally bounded to one selected domain.
$groups = @(Get-ADGroup -Filter * -SearchBase $domainDn -ResultPageSize 500 -Properties MemberOf,SID @common -ErrorAction Stop)
if ($groups.Count -gt $MaxGroups) {
    throw "Found $($groups.Count) groups, more than MaxGroups=$MaxGroups; do not issue an incomplete clean graph."
}
foreach ($g in $groups) {
    if ($null -eq $g.SID) { $warnings.Add('A group lacked its SID; membership scope incomplete.'); continue }
    $sid = Get-SidText $g.SID
    if (-not $sid) { continue }
    $dn = [string]$g.DistinguishedName
    $groupByDn[$dn.ToLowerInvariant()] = $sid
    Add-GraphNode $sid 'Group' ([string]$g.Name)
}
Add-GraphNode $startSid 'User' ([string]$start.SamAccountName)
Add-GraphNode $targetSid 'Group' 'Domain Admins'

foreach ($g in $groups) {
    $groupSid = Get-SidText $g.SID
    if (-not $groupSid) { continue }
    foreach ($parentDn in @($g.MemberOf)) {
        if (-not $parentDn) { continue }
        $key = ([string]$parentDn).ToLowerInvariant()
        if ($groupByDn.ContainsKey($key)) {
            Add-GraphEdge $groupSid $groupByDn[$key] 'member_of' 'AD memberOf group attribute'
        } else {
            $warnings.Add('Group membership references an out-of-scope or unreadable parent group.')
        }
    }
}
foreach ($parentDn in @($start.MemberOf)) {
    if (-not $parentDn) { continue }
    $key = ([string]$parentDn).ToLowerInvariant()
    if ($groupByDn.ContainsKey($key)) {
        Add-GraphEdge $startSid $groupByDn[$key] 'member_of' 'AD user memberOf attribute'
    } else {
        $warnings.Add('User group membership references an out-of-scope group.')
    }
}
if ($null -ne $start.PrimaryGroupID) {
    $primaryGroupSid = $domainSid + '-' + [string]$start.PrimaryGroupID
    if ($nodeKeys.ContainsKey($primaryGroupSid)) {
        Add-GraphEdge $startSid $primaryGroupSid 'member_of' 'AD primaryGroupID'
    } else {
        $warnings.Add('PrimaryGroupID not present in collected groups.')
    }
}

# Read every collected group DACL to identify candidate multi-hop links. No writes.
foreach ($g in $groups) {
    try {
        $dn = [string]$g.DistinguishedName
        $sid = Get-SidText $g.SID
        if (-not $sid) { continue }
        $obj = Get-ADObject -Identity $dn -Properties nTSecurityDescriptor @common -ErrorAction Stop
        Inspect-Access $obj 'group' $sid $dn
    } catch {
        $warnings.Add('Could not read or analyze one group ACL; results are incomplete.')
    }
}
try {
    $root = Get-ADObject -Identity $domainDn -Properties nTSecurityDescriptor @common -ErrorAction Stop
    Inspect-Access $root 'domain' $null 'domain_root'
} catch {
    $warnings.Add('Domain-root ACL unavailable; DCSync and domain ACL indicators incomplete.')
}
$gpoObjects = @()
try {
    $gpoBase = 'CN=Policies,CN=System,' + $domainDn
    $gpoObjects = @(Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' -SearchBase $gpoBase -Properties nTSecurityDescriptor,displayName -ResultPageSize 500 @common -ErrorAction Stop)
    foreach ($gpo in $gpoObjects) {
        try {
            $name = if ($IncludeIdentityNames) { [string]$gpo.Name } else { '[GPO name withheld]' }
            Inspect-Access $gpo 'gpo' $null $name
            $gpoRead++
        } catch {
            $warnings.Add('GPO ACL could not be analyzed; GPO scope is incomplete.')
        }
    }
} catch {
    $warnings.Add('GPO ACL inventory failed; GPO privilege indicators are unknown.')
}
$report = [ordered]@{
    schema_version = '1.0'
    generated_utc = (Get-Date).ToUniversalTime().ToString('o')
    source = 'read_only_live_AD_DS'
    domain = if ($IncludeIdentityNames) { [string]$domain.DNSRoot } else { '[domain withheld]' }
    start_sid = $startSid
    target_sid = $targetSid
    nodes = @($nodes.ToArray())
    edges = @($edges.ToArray())
    indicators = @($indicators.ToArray())
    complete = ($warnings.Count -eq 0)
    coverage = [ordered]@{
        selected_domain_only=$true
        groups_enumerated=$groups.Count
        group_and_domain_acl_reads=$aclCount
        aces_inspected=$aceTotal
        gpos_found=$gpoObjects.Count
        gpo_acls_read=$gpoRead
        all_forests_trusts_and_sessions_checked=$false
        effective_acl_deny_evaluation_checked=$false
        gpo_link_and_sysvol_checked=$false
    }
    warnings = @($warnings.ToArray())
}
$json = ConvertTo-Json -InputObject $report -Depth 16
$json | Out-File -LiteralPath $OutputPath -Encoding utf8
Write-Host "Read-only graph saved: $OutputPath (complete=$($report.complete), groups=$($groups.Count), edges=$($edges.Count), indicators=$($indicators.Count))"

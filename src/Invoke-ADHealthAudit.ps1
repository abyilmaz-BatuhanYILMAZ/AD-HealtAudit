#requires -Version 5.1
<#
.SYNOPSIS
    Read-only live AD DS security indicator inventory.
.DESCRIPTION
    Uses RSAT ActiveDirectory read cmdlets against a selected DC/domain.
    No domain settings, users, groups, GPOs or ACLs are modified.
    Findings are indicators requiring investigation, not proven exploits.
.EXAMPLE
    .\Invoke-ADHealthAudit.ps1 -Server dc01.lab.example -OutputPath .\audit.json
.EXAMPLE
    .\Invoke-ADHealthAudit.ps1 -Server dc01.lab.example -IncludeAccountNames -Format Html -OutputPath .\audit.html
#>
[CmdletBinding()]
param(
    [ValidateRange(30, 730)][int]$StaleDays = 90,
    [string]$Server,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$SearchBase,
    [ValidateSet('Json', 'Html')][string]$Format = 'Json',
    [string]$OutputPath,
    [switch]$IncludeAccountNames
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    throw 'The ActiveDirectory PowerShell module (RSAT) is required on an authorized management workstation.'
}

$common = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) { $common['Server'] = $Server }
if ($null -ne $Credential) { $common['Credential'] = $Credential }

# Domain and user inventory are required: fail rather than producing a "clean"
# report if they are unavailable. The Server option selects a DC explicitly.
$domain = Get-ADDomain @common -ErrorAction Stop
$userParams = @{}
if ($SearchBase) { $userParams['SearchBase'] = $SearchBase }
$properties = @('Enabled', 'PasswordNeverExpires', 'DoesNotRequirePreAuth',
                'LastLogonDate', 'AdminCount', 'ServicePrincipalName',
                'TrustedForDelegation', 'msDS-SupportedEncryptionTypes')
$users = @(Get-ADUser -Filter * -Properties $properties -ResultPageSize 500 @common @userParams -ErrorAction Stop)
$enabled = @($users | Where-Object { $_.Enabled -eq $true })
$cutoff = (Get-Date).AddDays(-$StaleDays)

$warnings = [System.Collections.Generic.List[string]]::new()
$findings = [System.Collections.Generic.List[object]]::new()

function Add-Indicator {
    param(
        [string]$Id, [string]$Severity, [string]$Title, [string]$Evidence,
        [string]$Recommendation, [object[]]$Objects, [string]$Type = 'user'
    )
    if ($Objects.Count -eq 0) { return }
    $item = [ordered]@{
        rule_id = $Id
        severity = $Severity
        title = $Title
        object_type = $Type
        affected_count = $Objects.Count
        evidence_attribute = $Evidence
        recommendation = $Recommendation
        confirmed_vulnerability = $false
    }
    if ($IncludeAccountNames) {
        # Account metadata is sensitive: names are emitted only with opt-in.
        $item['affected_objects'] = @($Objects | ForEach-Object { [string]$_.SamAccountName })
    }
    $findings.Add($item)
}

$neverExpires = @($enabled | Where-Object { $_.PasswordNeverExpires -eq $true })
$noPreauth = @($enabled | Where-Object { $_.DoesNotRequirePreAuth -eq $true })
$adminCount = @($enabled | Where-Object { $_.AdminCount -eq 1 })
$withSpn = @($enabled | Where-Object { @($_.ServicePrincipalName).Count -gt 0 -and $null -ne $_.ServicePrincipalName })
$stale = @($enabled | Where-Object { $null -ne $_.LastLogonDate -and $_.LastLogonDate -lt $cutoff })
$unknownLogon = @($enabled | Where-Object { $null -eq $_.LastLogonDate })
$unconstrained = @($enabled | Where-Object { $_.TrustedForDelegation -eq $true })
$des = @($enabled | Where-Object {
    $v = $_.'msDS-SupportedEncryptionTypes'
    $null -ne $v -and (([int]$v -band 3) -ne 0)
})
$rc4Explicit = @($enabled | Where-Object {
    $v = $_.'msDS-SupportedEncryptionTypes'
    $null -ne $v -and (([int]$v -band 4) -ne 0)
})

Add-Indicator 'AD001' 'MEDIUM' 'Enabled account password never expires' 'PasswordNeverExpires=True' 'Review ownership, service-account justification and rotation controls.' $neverExpires
Add-Indicator 'AD002' 'HIGH' 'Kerberos preauthentication disabled' 'DoesNotRequirePreAuth=True' 'Enable preauthentication unless an exception is documented.' $noPreauth
Add-Indicator 'AD003' 'MEDIUM' 'AdminCount=1 indicator' 'AdminCount=1' 'Review current protected-group membership; AdminCount may be stale.' $adminCount
Add-Indicator 'AD004' 'INFO' 'Accounts with SPNs' 'ServicePrincipalName populated' 'Inventory service identities and their authentication protections.' $withSpn
Add-Indicator 'AD005' 'LOW' 'Stale replicated logon estimate' 'LastLogonDate older than threshold' 'Correlate with accurate activity sources before disabling.' $stale
Add-Indicator 'AD006' 'INFO' 'Unknown replicated last logon' 'LastLogonDate is null' 'Treat absent timestamps as unknown, not as evidence of compromise.' $unknownLogon
Add-Indicator 'AD007' 'HIGH' 'Unconstrained delegation configured' 'TrustedForDelegation=True' 'Replace unconstrained delegation with narrowly scoped alternatives where practical.' $unconstrained
Add-Indicator 'AD008' 'HIGH' 'Explicit DES Kerberos encryption' 'msDS-SupportedEncryptionTypes DES bits' 'Review Kerberos encryption settings and remove DES support.' $des
Add-Indicator 'AD009' 'MEDIUM' 'Explicit RC4 Kerberos encryption' 'msDS-SupportedEncryptionTypes RC4 bit' 'Review compatibility, key rotation, and AES migration.' $rc4Explicit

$adminMembers = $null
try {
    $sid = "$($domain.DomainSID)-512"
    $adminMembers = @(Get-ADGroupMember -Identity $sid -Recursive @common -ErrorAction Stop).Count
} catch {
    $warnings.Add('Domain Admins membership unavailable; do not interpret null as zero.')
}

$policy = $null
try {
    $p = Get-ADDefaultDomainPasswordPolicy @common -ErrorAction Stop
    $policy = [ordered]@{
        minimum_length = [int]$p.MinPasswordLength
        lockout_threshold = [int]$p.LockoutThreshold
        complexity_enabled = [bool]$p.ComplexityEnabled
        maximum_age_days = [double]$p.MaxPasswordAge.TotalDays
    }
    if ($policy.lockout_threshold -eq 0) {
        Add-Indicator 'AD010' 'MEDIUM' 'Default policy has no account lockout threshold' 'LockoutThreshold=0' 'Review organizational lockout and smart-lockout strategy.' @([pscustomobject]@{SamAccountName='DefaultDomainPasswordPolicy'}) 'domain_policy'
    }
    if (-not $policy.complexity_enabled) {
        Add-Indicator 'AD011' 'MEDIUM' 'Default password policy complexity disabled' 'ComplexityEnabled=False' 'Evaluate password standards and fine-grained policy exceptions.' @([pscustomobject]@{SamAccountName='DefaultDomainPasswordPolicy'}) 'domain_policy'
    }
} catch {
    $warnings.Add('Default domain password policy unavailable; policy assessment incomplete.')
}

$computerCounts = $null
try {
    $computerParams = @{}
    if ($SearchBase) { $computerParams['SearchBase'] = $SearchBase }
    $computers = @(Get-ADComputer -Filter * -Properties Enabled,LastLogonDate,TrustedForDelegation -ResultPageSize 500 @common @computerParams -ErrorAction Stop)
    $activeComputers = @($computers | Where-Object { $_.Enabled -eq $true })
    $unconstrainedComputers = @($activeComputers | Where-Object { $_.TrustedForDelegation -eq $true })
    $staleComputers = @($activeComputers | Where-Object { $null -ne $_.LastLogonDate -and $_.LastLogonDate -lt $cutoff })
    $computerCounts = [ordered]@{
        total = $computers.Count
        enabled = $activeComputers.Count
        enabled_unconstrained_delegation = $unconstrainedComputers.Count
        enabled_stale_last_logon_estimates = $staleComputers.Count
    }
    Add-Indicator 'AD012' 'HIGH' 'Computer unconstrained delegation' 'TrustedForDelegation=True' 'Identify trusted infrastructure roles; remove unnecessary delegation.' $unconstrainedComputers 'computer'
    Add-Indicator 'AD013' 'LOW' 'Stale computer logon estimate' 'LastLogonDate older than threshold' 'Confirm device status before disabling or removal.' $staleComputers 'computer'
} catch {
    $warnings.Add('Computer inventory unavailable; computer findings are incomplete.')
}

$summary = [ordered]@{
    users_total = $users.Count
    users_enabled = $enabled.Count
    enabled_password_never_expires = $neverExpires.Count
    enabled_pre_auth_not_required = $noPreauth.Count
    enabled_admin_count_one = $adminCount.Count
    enabled_users_with_spn = $withSpn.Count
    enabled_last_logon_older_than_cutoff = $stale.Count
    enabled_last_logon_unknown = $unknownLogon.Count
    enabled_unconstrained_delegation = $unconstrained.Count
    enabled_des_encryption = $des.Count
    enabled_explicit_rc4_encryption = $rc4Explicit.Count
    effective_domain_admin_members = $adminMembers
}
$requestedDc = if ($Server) { $Server } else { 'discovered_default' }
$baseDn = if ($SearchBase) { $SearchBase } else { [string]$domain.DistinguishedName }
$report = [ordered]@{
    schema_version = '2.0'
    generated_utc = (Get-Date).ToUniversalTime().ToString('o')
    domain_dns_name = [string]$domain.DNSRoot
    domain_controller_requested = $requestedDc
    search_base = $baseDn
    stale_threshold_days = $StaleDays
    read_only = $true
    indicators_are_not_confirmed_vulnerabilities = $true
    complete = ($warnings.Count -eq 0)
    summary = $summary
    computer_summary = $computerCounts
    default_password_policy = $policy
    findings = @($findings.ToArray())
    warnings = @($warnings.ToArray())
}

if ($Format -eq 'Json') {
    $output = ConvertTo-Json -InputObject $report -Depth 12
} else {
    function Escape-Html([object]$Value) {
        return [System.Net.WebUtility]::HtmlEncode([string]$Value)
    }
    $rows = foreach ($finding in $findings) {
        $affected = if ($IncludeAccountNames -and $finding.Contains('affected_objects')) {
            ($finding['affected_objects'] -join ', ')
        } else { 'Account names redacted' }
        $cells = @((Escape-Html $finding.rule_id), (Escape-Html $finding.severity),
                   (Escape-Html $finding.title), (Escape-Html $finding.affected_count),
                   (Escape-Html $affected))
        '<tr><td>' + ($cells -join '</td><td>') + '</td></tr>'
    }
    $output = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>AD-HealthAudit Report</title>
<style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:3rem auto;padding:1rem;color:#202634}table{border-collapse:collapse;width:100%}th,td{padding:.7rem;border-bottom:1px solid #dde2e8;text-align:left}th{background:#f3f5f8}h1{margin-bottom:.2rem}p{line-height:1.55}</style></head><body>
<h1>AD-HealthAudit: Live Security Indicators</h1>
<p><b>Domain:</b> $(Escape-Html $domain.DNSRoot) | <b>Generated UTC:</b> $(Escape-Html $report.generated_utc)</p>
<p><b>Completeness:</b> $(Escape-Html $report.complete) | <b>Read only:</b> True</p>
<p><b>Interpretation:</b> Indicators require manual review; none is proof of exploitation.</p>
<table><thead><tr><th>Rule</th><th>Severity</th><th>Indicator</th><th>Affected</th><th>Objects</th></tr></thead><tbody>
$($rows -join "`n")
</tbody></table><p>Warnings: $(Escape-Html ($warnings -join '; '))</p></body></html>
"@
}

if ($OutputPath) {
    $parent = Split-Path -Parent $OutputPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        throw 'Output directory does not exist; create it explicitly.'
    }
    if (Test-Path -LiteralPath $OutputPath) {
        throw 'Refusing to overwrite an existing report. Use a new filename.'
    }
    $output | Out-File -LiteralPath $OutputPath -Encoding utf8
    Write-Host "Report saved: $OutputPath (complete=$($report.complete), indicators=$($findings.Count))"
} else {
    Write-Output $output
}

#requires -Version 5.1
<# Real PowerShell execution, synthetic ActiveDirectory cmdlet responses.
   Does not contact a domain and does not alter any AD state. #>
$ErrorActionPreference = 'Stop'
$moduleRoot = Join-Path $env:TEMP ('ad-audit-mock-' + [guid]::NewGuid().ToString('N'))
$moduleDir = Join-Path $moduleRoot 'ActiveDirectory'
New-Item -Path $moduleDir -ItemType Directory -Force | Out-Null
$moduleFile = Join-Path $moduleDir 'ActiveDirectory.psm1'
$moduleSource = @'
function Get-ADDomain {
  param([string]$Server, [System.Management.Automation.PSCredential]$Credential)
  [pscustomobject]@{ DNSRoot='training.invalid'; DomainSID='S-1-5-21-10-20-30'; DistinguishedName='DC=training,DC=invalid' }
}
function Get-ADUser {
  param([string]$Filter,[string[]]$Properties,[int]$ResultPageSize,[string]$Server,[string]$SearchBase,[System.Management.Automation.PSCredential]$Credential)
  [pscustomobject]@{
    SamAccountName='lab-account-1'; Enabled=$true; PasswordNeverExpires=$true
    DoesNotRequirePreAuth=$true; LastLogonDate=(Get-Date).AddDays(-200)
    AdminCount=1; ServicePrincipalName=@('HTTP/lab.invalid')
    TrustedForDelegation=$true; 'msDS-SupportedEncryptionTypes'=7
  }
  [pscustomobject]@{
    SamAccountName='normal-user'; Enabled=$true; PasswordNeverExpires=$false
    DoesNotRequirePreAuth=$false; LastLogonDate=(Get-Date)
    AdminCount=0; ServicePrincipalName=@(); TrustedForDelegation=$false
    'msDS-SupportedEncryptionTypes'=24
  }
}
function Get-ADGroupMember {
  param([string]$Identity,[switch]$Recursive,[string]$Server,[System.Management.Automation.PSCredential]$Credential)
  [pscustomobject]@{ DistinguishedName='CN=Administrator,CN=Users,DC=training,DC=invalid' }
}
function Get-ADDefaultDomainPasswordPolicy {
  param([string]$Server,[System.Management.Automation.PSCredential]$Credential)
  [pscustomobject]@{ MinPasswordLength=10; LockoutThreshold=0; ComplexityEnabled=$false; MaxPasswordAge=([TimeSpan]::FromDays(30)) }
}
function Get-ADComputer {
  param([string]$Filter,[string[]]$Properties,[int]$ResultPageSize,[string]$Server,[string]$SearchBase,[System.Management.Automation.PSCredential]$Credential)
  [pscustomobject]@{ SamAccountName='LAB-DC$'; Enabled=$true; LastLogonDate=(Get-Date); TrustedForDelegation=$true; 'msLAPS-PasswordExpirationTime'=([DateTime]::UtcNow.AddDays(-2).ToFileTimeUtc()); 'ms-Mcs-AdmPwdExpirationTime'=$null }
}
function Get-ADRootDSE {
  param([string]$Server,[System.Management.Automation.PSCredential]$Credential)
  [pscustomobject]@{ configurationNamingContext='CN=Configuration,DC=training,DC=invalid' }
}
function Get-ADObject {
  param([string]$LDAPFilter,[string]$SearchBase,[int]$ResultPageSize,[string[]]$Properties,[string]$Server,[System.Management.Automation.PSCredential]$Credential)
  [pscustomobject]@{Name='DemoTemplate'; 'msPKI-Certificate-Name-Flag'=1; pKIExtendedKeyUsage=@('1.3.6.1.5.5.7.3.2')}
}
Export-ModuleMember -Function Get-ADDomain,Get-ADUser,Get-ADGroupMember,Get-ADDefaultDomainPasswordPolicy,Get-ADComputer,Get-ADRootDSE,Get-ADObject
'@
$moduleSource | Set-Content -Path $moduleFile -Encoding UTF8
$oldPath = $env:PSModulePath
try {
    $env:PSModulePath = "$moduleRoot$([System.IO.Path]::PathSeparator)$oldPath"
    Remove-Module ActiveDirectory -ErrorAction SilentlyContinue
    $root = Split-Path -Parent $PSScriptRoot
    $script = Join-Path $root 'src/Invoke-ADHealthAudit.ps1'
    $jsonFile = Join-Path $moduleRoot 'audit.json'
    & $script -Server 'dc01.training.invalid' -OutputPath $jsonFile -Format Json
    $json = Get-Content -Path $jsonFile -Raw | ConvertFrom-Json
    if ($json.schema_version -ne '3.0' -or $json.summary.users_enabled -ne 2) { throw 'Wrong summary' }
    if ($json.findings.Count -lt 7) { throw 'Expected multiple live-indicator findings' }
    if ($json.findings | Where-Object { $_.PSObject.Properties.Name -contains 'affected_objects' }) {
        throw 'Account names were included without consent'
    }
    if ($json.complete -ne $true) { throw 'Mock AD inventory should be complete' }
    if ($json.summary.enabled_pre_auth_not_required -ne 1) { throw 'Kerberos preauth signal missing' }
    if ($json.summary.enabled_unconstrained_delegation -ne 1) { throw 'Delegation signal missing' }
    if ($json.summary.enabled_des_encryption -ne 1) { throw 'DES signal missing' }

    $htmlFile = Join-Path $moduleRoot 'audit.html'
    & $script -Server 'dc01.training.invalid' -OutputPath $htmlFile -Format Html -IncludeAccountNames
    $html = Get-Content -Path $htmlFile -Raw
    if ($html -notlike '*Evidence attribute*' -or $html -notlike '*Recommended review*' -or $html -notlike '*DoesNotRequirePreAuth=True*') {
        throw 'HTML report must contain escaped evidence and remediation details'
    }
    if ($html -notlike '*lab-account-1*' -or $html -notlike '*AD002*') {
        throw 'Expected opt-in account-level HTML evidence was absent'
    }
    $extended = Join-Path $moduleRoot 'extended.json'
    & $script -Server 'dc01.training.invalid' -CheckLapsMetadata -CheckAdcsTemplates -OutputPath $extended
    $ext = Get-Content -Path $extended -Raw | ConvertFrom-Json
    if ($ext.schema_version -ne '3.0') { throw 'Schema not upgraded' }
    if ($ext.laps_metadata_summary.enabled_overdue_expiration_metadata -ne 1) { throw 'LAPS timestamp finding missing' }
    if ($ext.adcs_template_summary.enrollee_supplies_subject_templates -ne 1) { throw 'AD CS template finding missing' }
    if (-not ($ext.findings | Where-Object { $_.rule_id -eq 'AD017' })) { throw 'Missing AD017' }
    if (-not ($ext.findings | Where-Object { $_.rule_id -eq 'AD018' })) { throw 'Missing AD018' }
    # Mock only the remote policy response; no remote machine is contacted.
    function Invoke-Command {
        [CmdletBinding()]
        param([string]$ComputerName,[scriptblock]$ScriptBlock,[System.Management.Automation.PSCredential]$Credential)
        [pscustomobject]@{ signing = 1; channel_binding = 0 }
    }
    $registryFile = Join-Path $moduleRoot 'dc-posture.json'
    & $script -Server 'dc01.training.invalid' -CheckDcRegistry -OutputPath $registryFile
    $registryReport = Get-Content -Path $registryFile -Raw | ConvertFrom-Json
    if (-not ($registryReport.findings | Where-Object { $_.rule_id -eq 'AD014' })) { throw 'LDAP signing indicator missing' }
    if (-not ($registryReport.findings | Where-Object { $_.rule_id -eq 'AD015' })) { throw 'LDAP channel binding indicator missing' }
    Remove-Item Function:\Invoke-Command -ErrorAction SilentlyContinue
    Write-Host 'PASS: PowerShell 5.1 mock AD query, LAPS, AD CS, and LDAP DC policy indicators'
} finally {
    Remove-Module ActiveDirectory -ErrorAction SilentlyContinue
    $env:PSModulePath = $oldPath
    Remove-Item -LiteralPath $moduleRoot -Recurse -Force -ErrorAction SilentlyContinue
}

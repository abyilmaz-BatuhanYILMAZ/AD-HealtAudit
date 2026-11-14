#requires -Version 5.1
# Synthetic domain objects only; no real Domain Controller or privileged changes.
$ErrorActionPreference = 'Stop'
$testFolder = Join-Path $env:TEMP ('ad-graph-mock-' + [guid]::NewGuid().ToString('N'))
$moduleDir = Join-Path $testFolder 'ActiveDirectory'
New-Item -ItemType Directory -Path $moduleDir -Force | Out-Null

$moduleSource = @'
function New-Ace([string]$sid,[long]$rights,[string]$guid='00000000-0000-0000-0000-000000000000') {
    [pscustomobject]@{ IdentityReference=$sid; ActiveDirectoryRights=$rights; ObjectType=$guid; AccessControlType='Allow' }
}
function Get-ADDomain {
    param([string]$Server,[System.Management.Automation.PSCredential]$Credential)
    [pscustomobject]@{
        DomainSID='S-1-5-21-10-20-30'
        DistinguishedName='DC=training,DC=invalid'
        DNSRoot='training.invalid'
    }
}
function Get-ADUser {
    param([string]$Identity,[string[]]$Properties,[string]$Server,[System.Management.Automation.PSCredential]$Credential)
    [pscustomobject]@{
        SID='S-1-5-21-10-20-30-1100'
        SamAccountName='lab-alice'
        MemberOf=@('CN=Helpdesk,CN=Users,DC=training,DC=invalid')
        PrimaryGroupID=513
    }
}
function Get-ADGroup {
    param([string]$Filter,[string]$SearchBase,[int]$ResultPageSize,[string[]]$Properties,[string]$Server,[System.Management.Automation.PSCredential]$Credential)
    @(
        [pscustomobject]@{
            SID='S-1-5-21-10-20-30-513'; Name='Domain Users'
            DistinguishedName='CN=Domain Users,CN=Users,DC=training,DC=invalid'; MemberOf=@()
        },
        [pscustomobject]@{
            SID='S-1-5-21-10-20-30-2001'; Name='Helpdesk'
            DistinguishedName='CN=Helpdesk,CN=Users,DC=training,DC=invalid'
            MemberOf=@('CN=Delegated,CN=Users,DC=training,DC=invalid')
        },
        [pscustomobject]@{
            SID='S-1-5-21-10-20-30-2002'; Name='Delegated'
            DistinguishedName='CN=Delegated,CN=Users,DC=training,DC=invalid'; MemberOf=@()
        },
        [pscustomobject]@{
            SID='S-1-5-21-10-20-30-512'; Name='Domain Admins'
            DistinguishedName='CN=Domain Admins,CN=Users,DC=training,DC=invalid'; MemberOf=@()
        }
    )
}
function Get-ADObject {
    param([string]$Identity,[string]$LDAPFilter,[string]$SearchBase,
          [string[]]$Properties,[int]$ResultPageSize,[string]$Server,
          [System.Management.Automation.PSCredential]$Credential)
    if ($LDAPFilter -eq '(objectClass=groupPolicyContainer)') {
        [pscustomobject]@{
            Name='{AABBCCDD-0011-2233-4455-66778899AABB}'
            nTSecurityDescriptor=[pscustomobject]@{
                Access=@(New-Ace 'S-1-5-21-10-20-30-2001' 262144)
            }
        }
        return
    }
    if ($Identity -eq 'DC=training,DC=invalid') {
        [pscustomobject]@{
            nTSecurityDescriptor=[pscustomobject]@{
                Access=@(
                    (New-Ace 'S-1-5-21-10-20-30-2001' 256 '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'),
                    (New-Ace 'S-1-5-21-10-20-30-2001' 256 '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                )
            }
        }
        return
    }
    if ($Identity -like '*CN=Domain Admins,*') {
        [pscustomobject]@{
            nTSecurityDescriptor=[pscustomobject]@{
                Access=@(New-Ace 'S-1-5-21-10-20-30-2002' 262144)
            }
        }
        return
    }
    [pscustomobject]@{ nTSecurityDescriptor=[pscustomobject]@{Access=@()} }
}
Export-ModuleMember -Function Get-ADDomain,Get-ADUser,Get-ADGroup,Get-ADObject
'@
$moduleSource | Set-Content -Path (Join-Path $moduleDir 'ActiveDirectory.psm1') -Encoding UTF8
$oldPath = $env:PSModulePath
try {
    $env:PSModulePath = "$testFolder$([System.IO.Path]::PathSeparator)$oldPath"
    Remove-Module ActiveDirectory -ErrorAction SilentlyContinue
    $root = Split-Path -Parent $PSScriptRoot
    $exporter = Join-Path $root 'src/Export-ADPrivilegeGraph.ps1'
    $graphFile = Join-Path $testFolder 'graph.json'
    & $exporter -Server 'dc01.training.invalid' -StartSamAccountName 'lab-alice' -OutputPath $graphFile -IncludeIdentityNames
    $graph = Get-Content -Raw -LiteralPath $graphFile | ConvertFrom-Json
    if ($graph.schema_version -ne '1.0' -or $graph.complete -ne $true) {
        throw "Expected complete synthetic graph; warnings: $($graph.warnings -join ', ')"
    }
    if (-not (@($graph.edges | Where-Object { $_.relation -eq 'can_modify_group' -and $_.to -eq 'S-1-5-21-10-20-30-512' }).Count -eq 1)) {
        throw 'Missing dangerous group ACL candidate'
    }
    if (-not (@($graph.indicators | Where-Object { $_.kind -eq 'dcsync_rights_candidate' }).Count -eq 1)) {
        throw 'Missing DCSync candidate'
    }
    if (-not (@($graph.indicators | Where-Object { $_.kind -eq 'gpo_acl_control_candidate' }).Count -eq 1)) {
        throw 'Missing GPO ACL indicator'
    }
    # Evaluate the PowerShell-generated JSON using the shipped Python graph engine.
    $report = Join-Path $testFolder 'report.json'
    & python (Join-Path $root 'src/ad_privilege_paths.py') $graphFile --output $report
    if ($LASTEXITCODE -ne 0) { throw 'Python candidate path evaluator failed' }
    $analysis = Get-Content -Raw -LiteralPath $report | ConvertFrom-Json
    if ($analysis.status -ne 'potential_acl_path' -or @($analysis.steps).Count -ne 3) {
        throw 'Expected three-edge candidate path to Domain Admins'
    }
    if (@($analysis.high_impact_exposures | Where-Object { $_.kind -eq 'dcsync_rights_candidate' }).Count -ne 1) {
        throw 'DCSync is an independent high-impact exposure, not an automatic DA membership'
    }
    # Verify that the one-command user entrypoint produces local evidence and HTML.
    $outputDirectory = Join-Path $testFolder 'reports'
    & (Join-Path $root 'scripts/Invoke-ADPrivilegePathAudit.ps1') -Server 'dc01.training.invalid' -StartSamAccountName 'lab-alice' -OutputDirectory $outputDirectory -Format Html -IncludeIdentityNames
    $graphOutputs = @(Get-ChildItem -LiteralPath $outputDirectory -Filter 'privilege-graph-*.json')
    $htmlOutputs = @(Get-ChildItem -LiteralPath $outputDirectory -Filter 'privilege-paths-*.html')
    if ($graphOutputs.Count -ne 1 -or $htmlOutputs.Count -ne 1) {
        throw 'The one-command AD audit runner did not produce graph evidence and HTML.'
    }
    if ((Get-Content -LiteralPath $htmlOutputs[0].FullName -Raw) -notlike '*potential_acl_path*') {
        throw 'The HTML report failed to display a potential ACL path.'
    }
    Write-Host 'PASS: mocked AD export, one-command HTML and Python path assessment'
} finally {
    Remove-Module ActiveDirectory -ErrorAction SilentlyContinue
    $env:PSModulePath = $oldPath
    Remove-Item -LiteralPath $testFolder -Recurse -Force -ErrorAction SilentlyContinue
}

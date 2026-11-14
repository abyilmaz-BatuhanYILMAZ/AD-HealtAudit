#requires -Version 5.1
<#
.SYNOPSIS
  Read-only, one-command AD privilege relationship report.
.DESCRIPTION
  Collects graph via RSAT and locally evaluates its explicit membership and
  ACL candidate relationships. No domain state is modified.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Server,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$StartSamAccountName,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputDirectory,
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateSet('Json','Html')][string]$Format = 'Html',
    [switch]$IncludeIdentityNames,
    [ValidateRange(1,5000)][int]$MaxGroups = 1500
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$collector = Join-Path $projectRoot 'src/Export-ADPrivilegeGraph.ps1'
$analyzer = Join-Path $projectRoot 'src/ad_privilege_paths.py'
if (-not (Test-Path -LiteralPath $collector) -or -not (Test-Path -LiteralPath $analyzer)) {
    throw 'The collector or analyzer file is missing from this repository.'
}
$python = Get-Command python -ErrorAction Stop
if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    [void](New-Item -Path $OutputDirectory -ItemType Directory -Force)
}
$runId = [guid]::NewGuid().ToString('N')
$evidencePath = Join-Path $OutputDirectory ("privilege-graph-" + $runId + ".json")
$extension = if ($Format -eq 'Html') { '.html' } else { '.json' }
$reportPath = Join-Path $OutputDirectory ("privilege-paths-" + $runId + $extension)
$params = @{
    Server = $Server
    StartSamAccountName = $StartSamAccountName
    OutputPath = $evidencePath
    MaxGroups = $MaxGroups
    IncludeIdentityNames = [bool]$IncludeIdentityNames
}
if ($null -ne $Credential) { $params['Credential'] = $Credential }
& $collector @params
if (-not (Test-Path -LiteralPath $evidencePath)) {
    throw 'Privilege graph collector did not write the expected local evidence file.'
}
& $python.Source $analyzer $evidencePath '--format' $Format.ToLowerInvariant() '--output' $reportPath
$analysisCode = $LASTEXITCODE
Write-Host "Graph evidence: $evidencePath"
Write-Host "Privilege relationship report: $reportPath"
if ($analysisCode -eq 3) {
    Write-Warning 'Graph is incomplete; missing paths must not be read as evidence of safety.'
    exit 3
}
if ($analysisCode -ne 0) {
    throw "Offline graph evaluator failed (exit=$analysisCode). Evidence retained locally."
}

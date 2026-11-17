#Requires -Version 5.1
<#
.SYNOPSIS
    Microsoft 365 breach investigation: reconstructs every PowerShell / administrative command
    executed across the tenant, who ran it, when, from where, and what access the attacker gained.

.DESCRIPTION
    READ-ONLY. This script makes NO changes to the tenant.

    Command-line wrapper around M365PowerShellForensics.psm1. The WinForms GUI is
    M365PowerShellForensics-GUI.ps1 in this folder.

    Use -Interactive for a console wizard (dates, suspects, phases, output folder).
    Use -ReportOnly to rebuild the interactive HTML report from an existing evidence folder.

    Output (in -OutputPath):
        * Investigation-Report.html   - fully interactive analyst workbench
        * Timeline-Master.csv         - every normalized event, correlated, sorted
        * Events-*.csv / SignIns-*.csv / Findings-*.csv
        * raw\*.jsonl                 - untouched original audit records
        * Evidence-Manifest.csv       - SHA-256 hash of every output file
        * Collection-Log.txt / Coverage.csv

.PARAMETER Interactive
    Prompt for investigation options, then run. Ignored when other investigation
    switches are already supplied alongside it; the prompts still run.

.EXAMPLE
    .\Invoke-M365PowerShellForensics.ps1 -Interactive

.EXAMPLE
    .\Invoke-M365PowerShellForensics.ps1 -StartDate '2026-09-01' -SuspectUsers 'jdoe@contoso.com' -SuspectIPs '203.0.113.50'

    Scope collection to those accounts (default when -SuspectUsers is set).
    Add -TenantWide to hunt the whole tenant and only highlight the suspects.

.EXAMPLE
    .\Invoke-M365PowerShellForensics.ps1 -OutputPath C:\IR\Case01 -SuspectUsers jdoe@contoso.com -SkipGraph
    .\Invoke-M365PowerShellForensics.ps1 -OutputPath C:\IR\Case01 -SuspectUsers jdoe@contoso.com -SkipExchange
    .\Invoke-M365PowerShellForensics.ps1 -OutputPath C:\IR\Case01 -ReportOnly -OpenReport
#>
[CmdletBinding()]
param(
    [datetime]$StartDate = (Get-Date).AddDays(-90),
    [datetime]$EndDate = (Get-Date),
    [string[]]$SuspectUsers = @(),
    [string[]]$SuspectIPs = @(),
    [string]$OutputPath = '',
    [string]$AdminUPN = '',
    [string]$TenantId = '',
    [ValidateRange(1, 168)][int]$ChunkHours = 24,
    [string[]]$AdditionalRecordTypes = @(),
    [int]$MaxSignInsPerQuery = 50000,
    [int]$MaxDirectoryAuditRecords = 250000,
    [int]$CorrelationWindowHours = 12,
    [int]$MaxMailboxesToInspect = 200,
    [int]$MaxReportEvents = 12000,
    [switch]$IncludeServicePrincipalSignIns,
    [switch]$SkipSuspectDataAccess,
    [switch]$SkipExchange,
    [switch]$SkipGraph,
    [switch]$SkipCurrentState,
    [switch]$ReportOnly,
    [switch]$InstallModules,
    [switch]$NoDisconnect,
    [switch]$OpenReport,
    [bool]$Fast = $true,
    [switch]$IncludeDiscovery,
    [switch]$TenantWide,
    [switch]$Interactive
)

$modulePath = Join-Path $PSScriptRoot 'M365PowerShellForensics.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    Write-Host "Investigation engine not found: $modulePath" -ForegroundColor Red
    exit 1
}
Import-Module $modulePath -Force -DisableNameChecking

if ($Interactive) {
    $result = Start-M365PsForensicsWizard
    exit $result.ExitCode
}

$pass = @{}
foreach ($k in @($PSBoundParameters.Keys)) {
    if ($k -eq 'Interactive') { continue }
    $pass[$k] = $PSBoundParameters[$k]
}
# Keep defaults for parameters the caller did not bind.
if (-not $PSBoundParameters.ContainsKey('StartDate')) { $pass['StartDate'] = $StartDate }
if (-not $PSBoundParameters.ContainsKey('EndDate')) { $pass['EndDate'] = $EndDate }
$result = Invoke-M365PowerShellForensics @pass
exit $result.ExitCode

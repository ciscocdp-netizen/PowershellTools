<#
.SYNOPSIS
    Runs every regression suite for the mailbox copy tool.

.EXAMPLE
    pwsh -File ./Invoke-AllTests.ps1

.NOTES
    Exits 1 if any suite fails, so it can be used as a build check.
#>

[CmdletBinding()]
param(
    [string]$ToolPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'M365-Mailbox-Copy-Tool.ps1')
)

$suites = @(
    'Invoke-FolderStructureTests.ps1',
    'Invoke-ProgressTests.ps1',
    'Invoke-CopyEmailsTests.ps1'
)

$failed = @()
foreach ($suite in $suites) {
    Write-Host ''
    Write-Host ('=' * 60)
    Write-Host "RUNNING $suite" -ForegroundColor Cyan
    Write-Host ('=' * 60)

    & (Join-Path $PSScriptRoot $suite) -ToolPath $ToolPath
    if ($LASTEXITCODE -ne 0) { $failed += $suite }
}

Write-Host ''
Write-Host ('=' * 60)
if ($failed.Count -gt 0) {
    Write-Host ("FAILED suites: " + ($failed -join ', ')) -ForegroundColor Red
    exit 1
}
Write-Host "All suites passed." -ForegroundColor Green
exit 0

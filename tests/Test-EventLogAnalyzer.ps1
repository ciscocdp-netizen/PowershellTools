<#
.SYNOPSIS
    Runs the Event Log XML Analyzer self-test suite.
.EXAMPLE
    pwsh -File ./tests/Test-EventLogAnalyzer.ps1
#>
[CmdletBinding()]
param()

$scriptPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../EventLogAnalyzer.ps1'))
if (-not (Test-Path -LiteralPath $scriptPath)) {
    throw "Cannot find EventLogAnalyzer.ps1 at $scriptPath"
}

& $scriptPath -SelfTest
exit $LASTEXITCODE

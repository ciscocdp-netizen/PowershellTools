#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive alias for Get-DeviceLapsPassword.ps1.

.DESCRIPTION
    Run this file with no parameters to check out a Windows LAPS password
    from Entra ID. Forwards every argument to Get-DeviceLapsPassword.ps1
    in the same folder.
#>
$target = Join-Path $PSScriptRoot 'Get-DeviceLapsPassword.ps1'
if (-not (Test-Path -LiteralPath $target)) {
    throw "Get-DeviceLapsPassword.ps1 was not found next to LAPsPassAzure.ps1."
}
& $target @args

#Requires -Version 5.1
<#
.SYNOPSIS
    Opens the Exchange Online Quota Manager.

.DESCRIPTION
    Use this file in place of the January 2026 MailboxQuotaChange.ps1 script.
    That script connected inside a background runspace, then a WinForms timer
    tick called Stop and Dispose. The timer variable is not visible inside
    the Tick handler, so sign-in ended with "You cannot call a method on a
    null-valued expression" at the Stop call on line 519.

    Keep these three files in the same folder and run this one:
      MailboxQuotaChange.ps1
      Exchange-Online-Quota-Manager.ps1
      QuotaManager.Core.ps1
#>

$here = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($here)) {
    $here = (Get-Location).Path
}

$manager = Join-Path $here 'Exchange-Online-Quota-Manager.ps1'
$core = Join-Path $here 'QuotaManager.Core.ps1'
if ((Test-Path -LiteralPath $manager) -and (Test-Path -LiteralPath $core)) {
    & $manager @args
    return
}

Add-Type -AssemblyName System.Windows.Forms
[void][System.Windows.Forms.MessageBox]::Show(
    "The quota manager files were not found next to this script.`r`n`r`nCopy all three files into the same folder, then run MailboxQuotaChange.ps1 again:`r`n`r`nMailboxQuotaChange.ps1`r`nExchange-Online-Quota-Manager.ps1`r`nQuotaManager.Core.ps1`r`n`r`nThe older MailboxQuotaChange.ps1 crashes after sign-in because its timer calls Stop() on a null timer.",
    'Exchange Online Quota Manager',
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Error
)

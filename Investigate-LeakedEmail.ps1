#Requires -Version 5.1
<#
.SYNOPSIS
  Investigates an accidentally sent email in Exchange Online.

.DESCRIPTION
  Reports original recipients, forwards, same-subject redirects, forwarders,
  mailbox auto-forward rules, and MailItemsAccessed opens. Requires
  ExchangeOnlineManagement 3.7 or newer, plus Exchange admin or Global Reader
  and View-Only Audit Logs. Opens require unified audit logging and
  MailItemsAccessed (Audit Premium, or tenants where that event is enabled).

  A date-only end date includes that whole calendar day. The GUI is
  Investigate-LeakedEmail-GUI.ps1.

.EXAMPLE
  .\Investigate-LeakedEmail.ps1 -Subject "Q3 Salary Review - Confidential" `
     -OriginalSender "hr@contoso.com" -StartDate "2026-09-25" -CheckAutoForwarding
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Subject,
    [Parameter(Mandatory = $true)][string]$OriginalSender,
    [datetime]$StartDate = (Get-Date).AddDays(-7),
    [datetime]$EndDate = (Get-Date),
    [string]$OutputFolder = (Join-Path $PWD ("EmailInvestigation_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [string]$MessageId,
    [string[]]$InternalDomains,
    [string[]]$AdditionalAuditUsers,
    [string]$SignInUpn,
    [switch]$CheckAutoForwarding,
    [switch]$IncludeDisabledRules,
    [switch]$CheckTransportPolicy,
    [switch]$AuditAllUsers,
    [switch]$SkipOpenAudit,
    [switch]$FastAudit,
    [switch]$IncludeTraceDetail,
    [switch]$SkipSenderAliasLookup,
    [switch]$LimitAuditToEndDate,
    [switch]$LooseSubjectMatch,
    [switch]$PassThru
)

$corePath = Join-Path $PSScriptRoot 'LeakedEmailInvestigation.Core.ps1'
if (-not (Test-Path -LiteralPath $corePath)) {
    throw "Missing investigation engine: $corePath"
}
. $corePath

$log = {
    param($Level, $Message)
    $color = 'Gray'
    switch ($Level) {
        'ERROR' { $color = 'Red' }
        'WARN' { $color = 'Yellow' }
        'INFO' { $color = 'Cyan' }
    }
    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor $color
}

try {
    $result = Invoke-LeakedEmailInvestigation `
        -Subject $Subject `
        -OriginalSender $OriginalSender `
        -StartDate $StartDate `
        -EndDate $EndDate `
        -OutputFolder $OutputFolder `
        -MessageId $MessageId `
        -InternalDomains $InternalDomains `
        -AdditionalAuditUsers $AdditionalAuditUsers `
        -SignInUpn $SignInUpn `
        -CheckAutoForwarding:([bool]$CheckAutoForwarding) `
        -IncludeDisabledRules:([bool]$IncludeDisabledRules) `
        -CheckTransportPolicy:([bool]$CheckTransportPolicy) `
        -AuditAllUsers:([bool]$AuditAllUsers) `
        -SkipOpenAudit:([bool]$SkipOpenAudit) `
        -FastAudit:([bool]$FastAudit) `
        -IncludeTraceDetail:([bool]$IncludeTraceDetail) `
        -ResolveSenderAliases:(-not [bool]$SkipSenderAliasLookup) `
        -AuditThroughNow:(-not [bool]$LimitAuditToEndDate) `
        -LooseSubjectMatch:([bool]$LooseSubjectMatch) `
        -LogHandler $log

    Write-Host ""
    Write-Host (Format-InvestigationSummaryText -Report $result) -ForegroundColor Green
    if ($result.ExportError) {
        Write-Host ("Export problem: {0}" -f $result.ExportError) -ForegroundColor Red
    }
    if ($PassThru) { $result }
    if ($result.Cancelled) { exit 2 }
}
catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

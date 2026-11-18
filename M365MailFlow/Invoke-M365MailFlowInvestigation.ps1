#Requires -Version 5.1
<#
.SYNOPSIS
    Deep-dive Exchange Online / Microsoft 365 mail flow investigation with root cause analysis.

.DESCRIPTION
    Goes well beyond the Message Trace UI by combining several data sources and running a
    rule-based root cause engine over the results.

      1. Message Trace summary   Get-MessageTraceV2 (falls back to legacy Get-MessageTrace)
                                 - automatic 10-day windowing and StartingRecipientAddress paging
      2. Message Trace detail    Get-MessageTraceDetailV2 (falls back to Get-MessageTraceDetail)
                                 - every event of the journey, ordered, with hop-to-hop latency
                                 - the hidden "Data" XML (MEP elements) decoded
                                 - agent custom data decoded (S:SFA spam filter, S:AMA anti-malware,
                                   S:TRA transport rules, DeliveryPriority, etc.)
      3. Tenant enrichment       Quarantine records, mail flow rule names/actions, connectors,
                                 recipient existence, mailbox quota/forwarding, group delivery
                                 restrictions, restricted (blocked) outbound senders, and optionally
                                 inbox rules + junk mail (Safe/Blocked senders) configuration
      4. DNS checks              MX / SPF / DMARC for the domains involved in failures/auth issues
      5. Header analysis         (-HeaderFile) Received chain hop latency, TLS per hop,
                                 SPF/DKIM/DMARC/compauth, X-Forefront-Antispam-Report verdicts
      6. Extended report         (-ExtendedReportCsv) analyse a downloaded "Extended" historical
                                 search CSV (custom_data, source_context, connector_id ...)
                                 (-SubmitHistoricalSearch) submit that search for you
      7. Root cause engine       NDR / enhanced status code decoding (4.x.x / 5.x.x), anti-spam
                                 verdict decoding (SFV/CAT/SCL/BCL/compauth), deferral patterns,
                                 latency gaps, rule actions, text heuristics (TLS, DNS, loops,
                                 reputation, forwarding, quota, moderation ...)

    Multiple senders, recipients, message IDs, and statuses are queried one value at a time.
    Quarantine and restricted-sender lookups use a Security & Compliance session.
    -Offline analyses a header file or extended report without contacting Exchange.
    -UseDeviceCode and -DisableWAM are passed through when the installed module supports them.
    Leave account, app id, thumbprint, and organization blank to sign in with the Microsoft window.
    When -MessageId or -MessageTraceId is set and the selected dates return nothing, the search
    continues through the 90-day message trace history. -StrictDateRange keeps the selected dates only.

    The WinForms GUI is M365MailFlowInvestigation-GUI.ps1 in this folder.

    Output (in -OutputPath):
      Report.html          Per-message journey timeline, findings, root cause, enrichment
      Messages.csv         One row per message/recipient with the primary root cause
      Events.csv           Every journey event with decoded data
      Findings.csv         Every finding with severity, evidence and recommendation
      Investigation.json   Full decoded data set
      Investigation.log    Run log

.NOTES
    Requirements
      - Windows PowerShell 5.1
      - ExchangeOnlineManagement module 3.x
            Install-Module ExchangeOnlineManagement -Scope CurrentUser
      - Read access to message trace (e.g. Global Reader, Security Reader, Exchange Administrator).
        Quarantine lookups need Security Reader / Security Administrator.
        Mailbox checks (-IncludeMailboxChecks) need Exchange Recipient Administrator or higher.

    Limits (Microsoft)
      - Message trace data: last 90 days, max 10 days per query (the script windows for you).
      - 100 trace queries per 5 minutes (the script self-throttles and retries).
      - Historical searches: 250 per tenant per 24h.

    All timestamps in the output are UTC unless labelled otherwise.

.EXAMPLE
    .\Invoke-M365MailFlowInvestigation.ps1 -RecipientAddress user@contoso.com -StartDate (Get-Date).AddDays(-3)

.EXAMPLE
    .\Invoke-M365MailFlowInvestigation.ps1 -MessageId '<abc123@mail.fabrikam.com>' -StartDate (Get-Date).AddDays(-20) -IncludeMailboxChecks -OpenReport

.EXAMPLE
    .\Invoke-M365MailFlowInvestigation.ps1 -SenderAddress app@contoso.com -Status Failed,Pending,Quarantined -StartDate (Get-Date).AddDays(-7)

.EXAMPLE
    # Paste the full internet headers of a message into headers.txt first
    .\Invoke-M365MailFlowInvestigation.ps1 -HeaderFile .\headers.txt -IncludeMailboxChecks

.EXAMPLE
    # Offline analysis of an Extended historical search report downloaded from the portal
    .\Invoke-M365MailFlowInvestigation.ps1 -ExtendedReportCsv .\MTDetail_Report.csv -SkipEnrichment -Offline

.EXAMPLE
    # App-only (certificate) authentication for automation
    .\Invoke-M365MailFlowInvestigation.ps1 -AppId <guid> -CertificateThumbprint <thumb> -Organization contoso.onmicrosoft.com -RecipientAddress user@contoso.com
#>
[CmdletBinding()]
param(
    [string[]]$SenderAddress,
    [string[]]$RecipientAddress,
    [string[]]$MessageId,
    [guid]$MessageTraceId,
    [string]$Subject,
    [ValidateSet('Contains', 'StartsWith', 'EndsWith')]
    [string]$SubjectFilterType = 'Contains',
    [ValidateSet('Delivered', 'Expanded', 'Failed', 'FilteredAsSpam', 'GettingStatus', 'Pending', 'Quarantined')]
    [string[]]$Status,
    [string]$FromIP,
    [string]$ToIP,
    [datetime]$StartDate = (Get-Date).AddDays(-2),
    [datetime]$EndDate = (Get-Date),
    [ValidateRange(1, 50000)]
    [int]$MaxResults = 5000,
    [ValidateRange(0, 5000)]
    [int]$MaxDetailLookups = 250,
    [switch]$ProblemsOnly,
    [switch]$SkipDetail,
    [switch]$SkipEnrichment,
    [switch]$IncludeMailboxChecks,
    [switch]$SkipDnsChecks,
    [ValidateRange(1, 1440)]
    [int]$LatencyWarningMinutes = 10,
    [string]$HeaderFile,
    [string]$ExtendedReportCsv,
    [switch]$SubmitHistoricalSearch,
    [string[]]$NotifyAddress,
    [string]$OutputPath = (Join-Path -Path (Get-Location).Path -ChildPath ('MailInvestigation_{0}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [switch]$OpenReport,
    [string]$UserPrincipalName,
    [string]$AppId,
    [string]$CertificateThumbprint,
    [string]$Organization,
    [switch]$DisconnectWhenDone,
    [switch]$Offline,
    [switch]$UseDeviceCode,
    [switch]$DisableWAM,
    [switch]$StrictDateRange
)

$modulePath = Join-Path $PSScriptRoot 'M365MailFlowInvestigation.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    Write-Host "Investigation engine not found: $modulePath" -ForegroundColor Red
    exit 1
}
Import-Module $modulePath -Force -DisableNameChecking
$result = Invoke-M365MailFlowInvestigation @PSBoundParameters
exit $result.ExitCode

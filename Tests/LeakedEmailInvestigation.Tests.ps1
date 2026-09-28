#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\LeakedEmailInvestigation.Core.ps1')

$script:Passed = 0
$script:Failed = 0

function Assert-True {
    param([string]$Name, $Condition)
    if ($Condition) {
        $script:Passed++
        Write-Host "PASS  $Name"
    }
    else {
        $script:Failed++
        Write-Host "FAIL  $Name"
    }
}

function Assert-Equal {
    param([string]$Name, $Actual, $Expected)
    if ($Actual -eq $Expected) {
        $script:Passed++
        Write-Host "PASS  $Name"
    }
    else {
        $script:Failed++
        Write-Host "FAIL  $Name"
        Write-Host "      actual:   $Actual"
        Write-Host "      expected: $Expected"
    }
}

function Assert-Finding {
    param($Report, [string]$Code)
    $hit = $false
    foreach ($finding in (ConvertTo-ItemArray $Report.Findings)) {
        if ($finding.Code -eq $Code) { $hit = $true }
    }
    Assert-True "finding $Code" $hit
}

function Assert-NoFinding {
    param($Report, [string]$Code)
    $hit = $false
    foreach ($finding in (ConvertTo-ItemArray $Report.Findings)) {
        if ($finding.Code -eq $Code) { $hit = $true }
    }
    Assert-True "no finding $Code" (-not $hit)
}

function New-Trace {
    param($Received, $Sender, $Recipient, $Subject, $MessageId, $Status = 'Delivered')
    [pscustomobject]@{
        Received         = [datetime]::SpecifyKind([datetime]$Received, [DateTimeKind]::Utc)
        SenderAddress    = $Sender
        RecipientAddress = $Recipient
        Subject          = $Subject
        Status           = $Status
        MessageId        = $MessageId
        MessageTraceId   = [guid]::NewGuid().ToString()
        FromIP           = '203.0.113.10'
        Size             = 2048
    }
}

$cleanSubject = 'Q3 Salary Review - Confidential'
$domains = @('contoso.com')

Assert-Equal 'normalized id' (Get-NormalizedId '  <ABC@Contoso.com> ') 'abc@contoso.com'
Assert-Equal 'blank id' (Get-NormalizedId '   ') $null
Assert-Equal 'csv formula' (ConvertTo-CsvSafeString '=cmd|calc') "'=cmd|calc"
Assert-Equal 'csv plus' (ConvertTo-CsvSafeString '+1') "'+1"
Assert-Equal 'csv safe mail' (ConvertTo-CsvSafeString 'a@contoso.com') 'a@contoso.com'
Assert-True 'internal exact' (Test-InternalAddress 'a@contoso.com' $domains)
Assert-True 'internal subdomain' (Test-InternalAddress 'a@eu.contoso.com' $domains)
Assert-True 'external domain' (-not (Test-InternalAddress 'a@gmail.com' $domains))
Assert-True 'smtp ok' (Test-SmtpAddress 'hr@contoso.com')
Assert-True 'smtp bad' (-not (Test-SmtpAddress 'not an email'))

$empty = ConvertTo-ItemArray $null
Assert-Equal 'null array count' @($empty).Count 0
$one = ConvertTo-ItemArray @([pscustomobject]@{ A = 1 })
Assert-Equal 'one item count' @($one).Count 1
Assert-Equal 'one item value' $one[0].A 1

$info = Get-NormalizedSubjectInfo "  [EXTERNAL] FWD: RE: $cleanSubject  "
Assert-Equal 'fwd prefix kind' $info.Kind 'Forward'
Assert-Equal 'fwd prefix subject' $info.Subject $cleanSubject
$info = Get-NormalizedSubjectInfo "RE: FW: $cleanSubject"
Assert-Equal 'reply outer kind' $info.Kind 'Reply'
Assert-Equal 'reply outer subject' $info.Subject $cleanSubject
$info = Get-NormalizedSubjectInfo "VS: $cleanSubject"
Assert-Equal 'finnish reply' $info.Kind 'Reply'
$info = Get-NormalizedSubjectInfo "VB: $cleanSubject"
Assert-Equal 'swedish forward' $info.Kind 'Forward'
$info = Get-NormalizedSubjectInfo "Doorsturen: $cleanSubject"
Assert-Equal 'dutch forward subject' $info.Subject $cleanSubject
$info = Get-NormalizedSubjectInfo "Automatic reply: $cleanSubject"
Assert-Equal 'auto reply' $info.Kind 'AutoReply'
$info = Get-NormalizedSubjectInfo "Undeliverable: $cleanSubject"
Assert-Equal 'ndr kind' $info.Kind 'Ndr'
Assert-Equal 'ndr subject' $info.Subject $cleanSubject
$info = Get-NormalizedSubjectInfo "I: $cleanSubject"
Assert-Equal 'italian forward' $info.Kind 'Forward'

$range = Resolve-InvestigationDateRange -StartDate ([datetime]'2026-09-25') -EndDate ([datetime]'2026-09-25')
Assert-Equal 'same midnight end hour' $range.End.Hour 23
Assert-Equal 'same midnight end minute' $range.End.Minute 59
$range = Resolve-InvestigationDateRange -StartDate ([datetime]'2026-09-25 10:00') -EndDate ([datetime]'2026-09-25 15:00')
Assert-Equal 'timed end preserved' $range.End.ToString('HH:mm') '15:00'
$threw = $false
try { Resolve-InvestigationDateRange -StartDate ([datetime]'2026-09-26 10:00') -EndDate ([datetime]'2026-09-25 09:00') | Out-Null }
catch { $threw = $true }
Assert-True 'end before start throws' $threw

$plan = Split-IntoBatches -Items @('only@contoso.com') -Size 50
Assert-Equal 'single batch count' $plan.Batches.Length 1
Assert-Equal 'single batch size' $plan.Batches[0].Length 1
Assert-Equal 'single batch user' $plan.Batches[0][0] 'only@contoso.com'
$many = 1..51 | ForEach-Object { "u$_@contoso.com" }
$plan = Split-IntoBatches -Items $many -Size 50
Assert-Equal '51 users batch count' $plan.Batches.Length 2
Assert-Equal 'first batch 50' $plan.Batches[0].Length 50
Assert-Equal 'second batch 1' $plan.Batches[1].Length 1
$plan = Split-IntoBatches -Items @() -Size 50
Assert-Equal 'empty batches' $plan.Batches.Length 0

$rows = @(
    (New-Trace '2026-09-25T12:00:00Z' 'hr@contoso.com' 'alice@contoso.com' $cleanSubject '<orig@contoso.com>')
    (New-Trace '2026-09-25T12:00:00Z' 'hr@contoso.com' 'bob@contoso.com' $cleanSubject '<orig@contoso.com>')
    (New-Trace '2026-09-25T12:00:00Z' 'hr@contoso.com' 'vendor@external.com' $cleanSubject '<orig@contoso.com>')
    (New-Trace '2026-09-25T13:00:00Z' 'alice@contoso.com' 'partner@external.com' "FW: $cleanSubject" '<fwd1@contoso.com>')
    (New-Trace '2026-09-25T13:30:00Z' 'bob@contoso.com' 'carol@contoso.com' $cleanSubject '<redir@contoso.com>')
    (New-Trace '2026-09-25T14:00:00Z' 'carol@contoso.com' 'dave@contoso.com' "FW: RE: $cleanSubject" '<fwd2@contoso.com>')
    (New-Trace '2026-09-25T15:00:00Z' 'dave@contoso.com' 'hr@contoso.com' "RE: $cleanSubject" '<reply@contoso.com>')
    (New-Trace '2026-09-25T15:10:00Z' 'alice@contoso.com' 'hr@contoso.com' "Automatic reply: $cleanSubject" '<ooo@contoso.com>')
    (New-Trace '2026-09-25T15:20:00Z' 'postmaster@contoso.com' 'hr@contoso.com' "Undeliverable: $cleanSubject" '<ndr@contoso.com>')
    (New-Trace '2026-09-25T16:00:00Z' 'someone@contoso.com' 'archive@contoso.com' "Notes about $cleanSubject tomorrow" '<other@contoso.com>')
    (New-Trace '2026-09-25T16:30:00Z' 'frank@contoso.com' 'spy@external.com' "FWD: $cleanSubject" '<bcc@contoso.com>')
)
$report = New-LeakedEmailReport -TraceRows $rows -Subject $cleanSubject -OriginalSender 'HR@contoso.com' -InternalDomains $domains -StartDate ([datetime]'2026-09-25') -EndDate ([datetime]'2026-09-26')
Assert-Equal 'original unique' $report.Summary.OriginalRecipients 3
Assert-Equal 'original external' $report.Summary.OriginalExternal 1
Assert-Equal 'propagation recipients' $report.Summary.PropagationRecipients 4
Assert-Equal 'propagation external' $report.Summary.PropagationExternal 2
Assert-Equal 'forwarders' $report.Summary.Forwarders 4
Assert-Equal 'redirect rows' $report.Summary.RedirectEvents 1
Assert-Equal 'replies' $report.Summary.Replies 1
Assert-Equal 'auto replies' $report.Summary.AutoReplies 1
Assert-Equal 'ndrs' $report.Summary.Ndrs 1
Assert-Equal 'excluded' $report.Summary.ExcludedRows 1
Assert-Equal 'zero is not one' (@($report.Journals).Count) 0

$alice = $null
foreach ($row in (ConvertTo-ItemArray $report.Propagation)) {
    if ($row.ForwardedTo -eq 'partner@external.com') { $alice = $row }
}
Assert-True 'alice forward found' ($null -ne $alice)
Assert-Equal 'alice via' $alice.ForwarderGotItVia 'Original from hr@contoso.com'

$dave = $null
foreach ($row in (ConvertTo-ItemArray $report.Propagation)) {
    if ($row.ForwardedTo -eq 'dave@contoso.com') { $dave = $row }
}
Assert-Equal 'dave chain' $dave.Chain 'Redirect from bob@contoso.com <- Original from hr@contoso.com'

$frank = $null
foreach ($row in (ConvertTo-ItemArray $report.Propagation)) {
    if ($row.ForwardedBy -eq 'frank@contoso.com') { $frank = $row }
}
Assert-True 'unknown chain' ($frank.Chain -like 'Unknown*')
Assert-Finding $report 'ExternalOriginal'
Assert-Finding $report 'ExternalForward'
Assert-Finding $report 'Redirects'
$summary = Format-InvestigationSummaryText $report
Assert-True 'summary external original' ($summary -match 'vendor@external.com')
Assert-True 'summary forwarder count' ($summary -match 'C\. Forwarders: 4')

$loose = New-LeakedEmailReport -TraceRows @(
    (New-Trace '2026-09-25T12:00:00Z' 'hr@contoso.com' 'alice@contoso.com' $cleanSubject '<orig@contoso.com>')
    (New-Trace '2026-09-25T16:00:00Z' 'someone@contoso.com' 'archive@contoso.com' "Notes about $cleanSubject tomorrow" '<other@contoso.com>')
) -Subject $cleanSubject -OriginalSender 'hr@contoso.com' -InternalDomains $domains -LooseSubjectMatch $true -StartDate ([datetime]'2026-09-25') -EndDate ([datetime]'2026-09-26')
Assert-Equal 'loose includes near match' $loose.Summary.ExcludedRows 0
Assert-True 'loose related' ($loose.Summary.RelatedRows -ge 2)

$idReport = New-LeakedEmailReport -TraceRows @(
    (New-Trace '2026-09-25T12:00:00Z' 'hr@contoso.com' 'alice@contoso.com' 'Gateway rewritten subject' '<Orig@contoso.com>')
) -Subject $cleanSubject -OriginalSender 'hr@contoso.com' -InternalDomains $domains -MessageId '<orig@contoso.com>' -StartDate ([datetime]'2026-09-25') -EndDate ([datetime]'2026-09-26')
Assert-Equal 'message id original' $idReport.Summary.OriginalRecipients 1
Assert-Finding $idReport 'MessageIdSubjectMismatch'

$aliasReport = New-LeakedEmailReport -TraceRows @(
    (New-Trace '2026-09-25T12:00:00Z' 'hr.alias@contoso.com' 'alice@contoso.com' $cleanSubject '<orig@contoso.com>')
) -Subject $cleanSubject -OriginalSender 'hr@contoso.com' -SenderAddresses @('hr@contoso.com', 'hr.alias@contoso.com') -InternalDomains $domains -StartDate ([datetime]'2026-09-25') -EndDate ([datetime]'2026-09-26')
Assert-Equal 'alias sender counts as original' $aliasReport.Summary.OriginalRecipients 1

$none = New-LeakedEmailReport -TraceRows @() -Subject $cleanSubject -OriginalSender 'hr@contoso.com' -InternalDomains $domains -StartDate ([datetime]'2026-09-25') -EndDate ([datetime]'2026-09-26')
Assert-Equal 'no forwarders' $none.Summary.Forwarders 0
Assert-Finding $none 'NoOriginalMatch'
Assert-True 'summary zero forwarders' ((Format-InvestigationSummaryText $none) -match 'C\. Forwarders: 0')

$state = @{ Index = 0; Calls = (New-Object System.Collections.Generic.List[object]) }
$pageSize = 2
$r1 = New-Trace '2026-09-25T12:00:00Z' 'hr@contoso.com' 'a@contoso.com' $cleanSubject '<1@contoso.com>'
$r2 = New-Trace '2026-09-25T11:00:00Z' 'hr@contoso.com' 'b@contoso.com' $cleanSubject '<1@contoso.com>'
$r3 = New-Trace '2026-09-25T10:00:00Z' 'hr@contoso.com' 'c@contoso.com' $cleanSubject '<1@contoso.com>'
$pages = @(@($r1, $r2), @($r2, $r3))
$fetch = {
    param($Query)
    $state.Calls.Add($Query)
    $i = $state.Index
    if ($i -ge $pages.Count) { return @() }
    $state.Index++
    return $pages[$i]
}
$traced = Get-MessageTracePages -StartUtc ([datetime]::SpecifyKind([datetime]'2026-09-20T00:00:00Z', 'Utc')) -EndUtc ([datetime]::SpecifyKind([datetime]'2026-09-26T00:00:00Z', 'Utc')) -SubjectText $cleanSubject -PageSize $pageSize -FetchPage $fetch
Assert-Equal 'deduped trace rows' @($traced.Rows).Count 3
Assert-True 'paging moved cursor' ($state.Calls.Count -ge 2)
Assert-True 'first page has no cursor' ([string]::IsNullOrEmpty([string]$state.Calls[0].StartingRecipient))
Assert-Equal 'default subject filter' $state.Calls[0].SubjectFilterType 'EndsWith'
Assert-Equal 'fast filter' (Get-SubjectTraceFilterType -FastSubjectSearch $true -LooseSubjectMatch $false) 'EndsWith'
Assert-Equal 'broad filter' (Get-SubjectTraceFilterType -FastSubjectSearch $false -LooseSubjectMatch $false) 'Contains'
Assert-Equal 'loose filter' (Get-SubjectTraceFilterType -FastSubjectSearch $true -LooseSubjectMatch $true) 'Contains'

$windows = @{ Calls = (New-Object System.Collections.Generic.List[object]) }
$windowFetch = {
    param($Query)
    $windows.Calls.Add($Query)
    return @()
}
$start = [datetime]::SpecifyKind([datetime]'2026-09-01T00:00:00Z', 'Utc')
$end = [datetime]::SpecifyKind([datetime]'2026-09-20T00:00:00Z', 'Utc')
Get-MessageTracePages -StartUtc $start -EndUtc $end -SubjectText $cleanSubject -PageSize 2 -FetchPage $windowFetch | Out-Null
Assert-True 'split into windows' ($windows.Calls.Count -ge 2)
$maxSpan = [TimeSpan]::FromDays(10)
foreach ($call in $windows.Calls) {
    $span = $call.PageEnd - $call.WindowStart
    Assert-True 'window under 10 days' ($span -lt $maxSpan -and $span -gt [TimeSpan]::Zero)
}

$stall = @{ N = 0 }
$stuckRow = New-Trace '2026-09-25T12:00:00Z' 'hr@contoso.com' 'a@contoso.com' $cleanSubject '<1@contoso.com>'
$stuck2 = New-Trace '2026-09-25T12:00:00Z' 'hr@contoso.com' 'b@contoso.com' $cleanSubject '<1@contoso.com>'
$stallFetch = {
    param($Query)
    $stall.N++
    return @($stuckRow, $stuck2)
}
$stalled = Get-MessageTracePages -StartUtc ([datetime]::SpecifyKind([datetime]'2026-09-25T00:00:00Z', 'Utc')) -EndUtc ([datetime]::SpecifyKind([datetime]'2026-09-25T18:00:00Z', 'Utc')) -SubjectText $cleanSubject -PageSize 2 -FetchPage $stallFetch
Assert-True 'stall stops' ($stall.N -lt 8)
Assert-Equal 'stall keeps unique' @($stalled.Rows).Count 2
Assert-True 'stall flagged' $stalled.Stalled

$cancelState = @{ N = 0 }
$script:InvCtx = [pscustomobject]@{ Log = $null; Progress = $null; Cancel = { $cancelState.N -ge 1 }; Warnings = (New-Object System.Collections.Generic.List[string]) }
$cancelFetch = {
    param($Query)
    $cancelState.N++
    return @($stuckRow, $stuck2)
}
$cancelledPages = Get-MessageTracePages -StartUtc ([datetime]::SpecifyKind([datetime]'2026-09-01T00:00:00Z', 'Utc')) -EndUtc ([datetime]::SpecifyKind([datetime]'2026-09-20T00:00:00Z', 'Utc')) -SubjectText $cleanSubject -PageSize 2 -FetchPage $cancelFetch
Assert-True 'cancel stops paging' $cancelledPages.Cancelled
$script:InvCtx = $null

$auditState = @{ N = 0 }
$auditFetch = {
    param($Query)
    $auditState.N++
    if ($auditState.N -eq 1) {
        return @(
            [pscustomobject]@{ Identity = 'a'; ResultIndex = 2; ResultCount = 3; AuditData = '{"n":1}' }
            [pscustomobject]@{ Identity = 'b'; ResultIndex = 2; ResultCount = 3; AuditData = '{"n":2}' }
        )
    }
    return @(
        [pscustomobject]@{ Identity = 'c'; ResultIndex = 3; ResultCount = 3; AuditData = '{"n":3}' }
    )
}
$audited = Invoke-PagedAuditSearch -Fetch $auditFetch -StartUtc ([datetime]::SpecifyKind([datetime]'2026-09-25Z', 'Utc')) -EndUtc ([datetime]::SpecifyKind([datetime]'2026-09-26Z', 'Utc')) -UserIds @('alice@contoso.com') -HighCompleteness $true -PageSize 2
Assert-Equal 'audit pages combine' @($audited.Records).Count 3

$repeat = @{ N = 0 }
$repeatFetch = {
    param($Query)
    $repeat.N++
    return @(
        [pscustomobject]@{ Identity = 'same'; ResultIndex = $null; ResultCount = $null; AuditData = '{"n":1}' }
        [pscustomobject]@{ Identity = 'same'; ResultIndex = -1; ResultCount = -1; AuditData = '{"n":1}' }
    )
}
$repeated = Invoke-PagedAuditSearch -Fetch $repeatFetch -StartUtc ([datetime]::SpecifyKind([datetime]'2026-09-25Z', 'Utc')) -EndUtc ([datetime]::SpecifyKind([datetime]'2026-09-26Z', 'Utc')) -UserIds $null -HighCompleteness $false -PageSize 2
Assert-True 'duplicate audit page stops' ($repeat.N -le 3)
Assert-Equal 'duplicate audit collapsed' @($repeated.Records).Count 1

$base = New-LeakedEmailReport -TraceRows @(
    (New-Trace '2026-09-25T12:00:00Z' 'hr@contoso.com' 'alice@contoso.com' $cleanSubject '<orig@contoso.com>')
    (New-Trace '2026-09-25T12:00:00Z' 'hr@contoso.com' 'bob@contoso.com' $cleanSubject '<orig@contoso.com>')
) -Subject $cleanSubject -OriginalSender 'hr@contoso.com' -InternalDomains $domains -StartDate ([datetime]'2026-09-25') -EndDate ([datetime]'2026-09-26')
$base.Mailboxes = @(
    [pscustomobject]@{
        Requested = 'alice@contoso.com'; PrimarySmtp = 'alice@contoso.com'; UserPrincipalName = 'alice.upn@contoso.com'
        Addresses = @('alice@contoso.com'); Error = ''
    }
    [pscustomobject]@{
        Requested = 'bob@contoso.com'; PrimarySmtp = 'bob@contoso.com'; UserPrincipalName = 'bob.upn@contoso.com'
        Addresses = @('bob@contoso.com'); Error = ''
    }
)
$auditJson = '{"UserId":"assistant@contoso.com","MailboxOwnerUPN":"alice.upn@contoso.com","ClientInfoString":"Client=OWA","ClientIPAddress":"198.51.100.8","OperationProperties":[{"Name":"MailAccessType","Value":"Bind"},{"Name":"IsThrottled","Value":"True"}],"Folders":[{"Path":"\\Inbox","FolderItems":[{"InternetMessageId":"<ORIG@contoso.com>"}]}]}'
$syncJson = '{"UserId":"bob.upn@contoso.com","MailboxOwnerUPN":"bob.upn@contoso.com","ClientInfoString":"Client=ActiveSync","ClientIPAddress":"198.51.100.9","OperationProperties":[{"Name":"MailAccessType","Value":"Sync"}],"Folders":[{"Path":"\\Inbox","FolderItems":[null]}]}'
$noiseJson = '{"UserId":"other@contoso.com","MailboxOwnerUPN":"other@contoso.com","OperationProperties":[{"Name":"MailAccessType","Value":"Sync"}],"Folders":[{"Path":"\\Inbox"}]}'
$emptyFolderJson = '{"UserId":"alice.upn@contoso.com","MailboxOwnerUPN":"alice.upn@contoso.com","OperationProperties":[{"Name":"MailAccessType","Value":"Bind"}],"Folders":null}'
$records = @(
    [pscustomobject]@{ Identity = '1'; CreationDate = [datetime]::SpecifyKind([datetime]'2026-09-25T18:00:00Z', 'Utc'); AuditData = $auditJson }
    [pscustomobject]@{ Identity = '2'; CreationDate = [datetime]::SpecifyKind([datetime]'2026-09-25T18:05:00Z', 'Utc'); AuditData = $syncJson }
    [pscustomobject]@{ Identity = '3'; CreationDate = [datetime]::SpecifyKind([datetime]'2026-09-25T18:06:00Z', 'Utc'); AuditData = $noiseJson }
    [pscustomobject]@{ Identity = '4'; CreationDate = [datetime]::SpecifyKind([datetime]'2026-09-25T18:07:00Z', 'Utc'); AuditData = $emptyFolderJson }
    [pscustomobject]@{ Identity = '5'; CreationDate = [datetime]::SpecifyKind([datetime]'2026-09-25T18:08:00Z', 'Utc'); AuditData = '{not json' }
)
$opens = Get-OpenEventsFromAudit -Records $records -TargetIds (Get-TargetMessageIds $base) -Report $base
Assert-Equal 'one real open' @($opens.Opened).Count 1
Assert-Equal 'delegate flagged' $opens.Opened[0].DelegateAccess 'Yes'
Assert-Equal 'upn maps to original' $opens.Opened[0].ReceivedVia 'Original'
Assert-Equal 'sync kept for recipient' @($opens.Syncs).Count 1
Assert-True 'sync note' ($opens.Syncs[0].Note -match 'not proof')
Assert-True 'throttled captured' $opens.Throttled
Assert-Equal 'bad json counted' $opens.ParseErrors 1
$base.Opened = $opens.Opened
$base.Syncs = $opens.Syncs
$base.AuditStatus = 'Completed'
$base.AuditThrottled = $true
$base.AuditAllUsers = $false
Complete-LeakedEmailReport -Report $base
Assert-Equal 'bob has no open' $base.Summary.NoOpenRecipients 1
Assert-Equal 'opened mailboxes' $base.Summary.OpenedMailboxes 1
Assert-Finding $base 'DelegateOpen'
Assert-Finding $base 'NoOpenEvents'
Assert-Finding $base 'AuditThrottled'
Assert-Finding $base 'DelegateSearchLimited'

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('leaktest_' + [guid]::NewGuid().ToString('N'))
$base.OutputFolder = $temp
Export-InvestigationReport -Report $base | Out-Null
$originalCsv = Get-Content -LiteralPath (Join-Path $temp 'A_OriginalRecipients.csv') -Raw
Assert-True 'original csv has recipient' ($originalCsv -match 'alice@contoso.com')
$emptyReport = New-LeakedEmailReport -TraceRows @() -Subject $cleanSubject -OriginalSender 'hr@contoso.com' -InternalDomains $domains -StartDate ([datetime]'2026-09-25') -EndDate ([datetime]'2026-09-26')
$emptyReport.OutputFolder = Join-Path $temp 'empty'
Export-InvestigationReport -Report $emptyReport | Out-Null
$header = Get-Content -LiteralPath (Join-Path $emptyReport.OutputFolder 'C_Forwarders.csv') -TotalCount 1
Assert-True 'empty forwarders header' ($header -match 'Forwarder')
$formula = New-LeakedEmailReport -TraceRows @(
    (New-Trace '2026-09-25T12:00:00Z' 'hr@contoso.com' 'alice@contoso.com' "=cmd|' /C calc'!A0 $cleanSubject" '<orig@contoso.com>')
) -Subject $cleanSubject -OriginalSender 'hr@contoso.com' -InternalDomains $domains -LooseSubjectMatch $true -StartDate ([datetime]'2026-09-25') -EndDate ([datetime]'2026-09-26')
$formula.OutputFolder = Join-Path $temp 'formula'
Export-InvestigationReport -Report $formula | Out-Null
$formulaCsv = Get-Content -LiteralPath (Join-Path $formula.OutputFolder 'A_OriginalRecipients.csv') -Raw
Assert-True 'formula neutralized' ($formulaCsv -match "'=cmd")

$calls = @{ Trace = 0; Mail = (New-Object System.Collections.Generic.List[string]); Rules = 0; AuditUsers = (New-Object System.Collections.Generic.List[object]); High = $false; Filters = (New-Object System.Collections.Generic.List[string]) }
$deps = [pscustomobject]@{
    GetAcceptedDomains = { @('contoso.com') }
    FetchTracePage = {
        param($Query)
        $calls.Filters.Add([string]$Query.SubjectFilterType)
        $calls.Trace++
        if ($calls.Trace -gt 1) { return @() }
        @(
            (New-Trace '2026-09-25T12:00:00Z' 'hr.alias@contoso.com' 'alice@contoso.com' $cleanSubject '<orig@contoso.com>')
            (New-Trace '2026-09-25T13:00:00Z' 'alice@contoso.com' 'vendor@external.com' "FW: $cleanSubject" '<fwd@contoso.com>')
        )
    }
    GetMailbox = {
        param($Identity)
        $calls.Mail.Add([string]$Identity)
        if ($Identity -eq 'hr@contoso.com') {
            return [pscustomobject]@{
                PrimarySmtpAddress = 'hr@contoso.com'
                UserPrincipalName = 'hr@contoso.com'
                EmailAddresses = @('SMTP:hr@contoso.com', 'smtp:hr.alias@contoso.com')
                ForwardingAddress = $null
                ForwardingSmtpAddress = $null
                DeliverToMailboxAndForward = $false
            }
        }
        return [pscustomobject]@{
            PrimarySmtpAddress = 'alice@contoso.com'
            UserPrincipalName = 'alice.upn@contoso.com'
            EmailAddresses = @('SMTP:alice@contoso.com')
            ForwardingAddress = $null
            ForwardingSmtpAddress = 'smtp:outsider@gmail.com'
            DeliverToMailboxAndForward = $false
        }
    }
    GetInboxRules = {
        param($Identity)
        $calls.Rules++
        @(
            [pscustomobject]@{ Name = 'Send out'; Enabled = $true; ForwardTo = @('boss@contoso.com'); RedirectTo = $null; ForwardAsAttachmentTo = $null }
            [pscustomobject]@{ Name = 'Old'; Enabled = $false; ForwardTo = 'old@contoso.com'; RedirectTo = $null; ForwardAsAttachmentTo = $null }
        )
    }
    SearchAudit = {
        param($Query)
        $calls.High = [bool]$Query.HighCompleteness
        $calls.AuditUsers.Add($Query.UserIds)
        $json = '{"UserId":"alice.upn@contoso.com","MailboxOwnerUPN":"alice.upn@contoso.com","ClientInfoString":"Client=OWA","ClientIPAddress":"203.0.113.5","OperationProperties":[{"Name":"MailAccessType","Value":"Bind"}],"Folders":[{"Path":"\\Inbox","FolderItems":[{"InternetMessageId":"<orig@contoso.com>"}]}]}'
        @(
            [pscustomobject]@{ Identity = 'open1'; ResultIndex = 1; ResultCount = 1; CreationDate = [datetime]::SpecifyKind([datetime]'2026-09-25T20:00:00Z', 'Utc'); AuditData = $json }
        )
    }
    GetTransportRules = {
        @(
            [pscustomobject]@{ Name = 'Copy payroll'; State = 'Enabled'; RedirectMessageTo = $null; BlindCopyTo = 'leak@external.com'; AddToRecipients = $null; CopyTo = $null }
        )
    }
    GetRemoteDomains = {
        @([pscustomobject]@{ DomainName = '*'; AutoForwardEnabled = $false })
    }
    GetOutboundPolicy = {
        @([pscustomobject]@{ Name = 'Default'; AutoForwardingMode = 'Off' })
    }
    GetAdminAuditLogConfig = {
        [pscustomobject]@{ UnifiedAuditLogIngestionEnabled = $true }
    }
}
$out = Join-Path $temp 'invoke'
$inv = Invoke-LeakedEmailInvestigation -Subject "FW: $cleanSubject" -OriginalSender 'hr@contoso.com' -StartDate ([datetime]'2026-09-25') -EndDate ([datetime]'2026-09-25') -OutputFolder $out -CheckAutoForwarding $true -CheckTransportPolicy $true -SkipConnectionCheck $true -ResolveSenderAliases $true -AuditThroughNow $false -FastAudit $false -Dependencies $deps -AdditionalAuditUsers @('delegate@contoso.com') -AuditBatchSize 50
Assert-Equal 'invoke uses endswith' $calls.Filters[0] 'EndsWith'
Assert-Equal 'invoke original' $inv.Summary.OriginalRecipients 1
Assert-Equal 'invoke external forward' $inv.Summary.PropagationExternal 1
Assert-True 'alias lookup happened' ($calls.Mail -contains 'hr@contoso.com')
Assert-True 'autoforward external' ($inv.Summary.AutoForwardExternal -ge 1)
$disabledKept = $false
foreach ($row in (ConvertTo-ItemArray $inv.AutoForwarding)) {
    if ($row.Name -eq 'Old') { $disabledKept = $true }
}
Assert-True 'disabled rule omitted' (-not $disabledKept)
Assert-Finding $inv 'ExternalAutoForward'
Assert-Finding $inv 'TransportRuleExternal'
Assert-Finding $inv 'OutboundAutoForwardOff'
Assert-True 'audit used upn' ($calls.AuditUsers[0] -contains 'alice.upn@contoso.com')
Assert-True 'extra audit upn included' ($calls.AuditUsers[0] -contains 'delegate@contoso.com')
Assert-True 'high completeness requested' $calls.High
Assert-Equal 'invoke open via upn' $inv.Opened[0].ReceivedVia 'Original'
Assert-True 'summary file exists' (Test-Path -LiteralPath (Join-Path $out 'Summary.txt'))
Assert-Equal 'end date includes day' $inv.EndDate.Hour 23

$fallbackCalls = New-Object System.Collections.Generic.List[string]
$fallbackDeps = [pscustomobject]@{
    GetAcceptedDomains = { @('contoso.com') }
    FetchTracePage = {
        param($Query)
        $fallbackCalls.Add([string]$Query.SubjectFilterType)
        if ($Query.SubjectFilterType -eq 'Contains') {
            return @(New-Trace '2026-09-25T12:00:00Z' 'hr@contoso.com' 'alice@contoso.com' $cleanSubject '<orig@contoso.com>')
        }
        return @()
    }
}
$fallback = Invoke-LeakedEmailInvestigation -Subject $cleanSubject -OriginalSender 'hr@contoso.com' -StartDate ([datetime]'2026-09-25') -EndDate ([datetime]'2026-09-25') -OutputFolder (Join-Path $temp 'fallback') -SkipConnectionCheck $true -SkipOpenAudit $true -ResolveSenderAliases $false -FastSubjectSearch $true -Dependencies $fallbackDeps
Assert-Equal 'endswith tried first' $fallbackCalls[0] 'EndsWith'
Assert-Equal 'contains fallback' $fallbackCalls[1] 'Contains'
Assert-Equal 'fallback found original' $fallback.Summary.OriginalRecipients 1

Remove-Item -LiteralPath $temp -Recurse -Force

$removalReport = New-LeakedEmailReport -TraceRows @(
    (New-Trace '2026-09-25T12:00:00Z' 'hr@contoso.com' 'alice@contoso.com' $cleanSubject '<Orig@contoso.com>')
    (New-Trace '2026-09-25T12:05:00Z' 'hr@contoso.com' 'vendor@external.com' $cleanSubject '<Orig@contoso.com>')
    (New-Trace '2026-09-25T13:00:00Z' 'alice@contoso.com' 'dave@contoso.com' "FW: $cleanSubject" '<Fwd@contoso.com>')
    (New-Trace '2026-09-25T14:00:00Z' 'dave@contoso.com' 'hr@contoso.com' "RE: $cleanSubject" '<Reply@contoso.com>')
) -Subject $cleanSubject -OriginalSender 'hr@contoso.com' -InternalDomains $domains -StartDate ([datetime]'2026-09-25') -EndDate ([datetime]'2026-09-26')
$removalReport.Mailboxes = @(
    [pscustomobject]@{ Requested = 'alice@contoso.com'; PrimarySmtp = 'alice.primary@contoso.com'; Addresses = @('alice@contoso.com'); UserPrincipalName = 'alice@contoso.com' }
)
$removalPlan = Get-InternalRemovalPlan -Report $removalReport
Assert-True 'removal includes alice primary' ($removalPlan.Mailboxes -contains 'alice.primary@contoso.com')
Assert-True 'removal includes sender' ($removalPlan.Mailboxes -contains 'hr@contoso.com')
Assert-True 'removal includes forward recipient' ($removalPlan.Mailboxes -contains 'dave@contoso.com')
Assert-True 'removal skips external' (-not ($removalPlan.Mailboxes -contains 'vendor@external.com'))
Assert-True 'removal keeps original id' ($removalPlan.MessageIds -contains 'orig@contoso.com')
Assert-True 'removal keeps forward id' ($removalPlan.MessageIds -contains 'fwd@contoso.com')
Assert-True 'removal skips reply id' (-not ($removalPlan.MessageIds -contains 'reply@contoso.com'))
Assert-True 'removal query uses message id' ([string]$removalPlan.Queries[0] -match 'InternetMessageId:"<orig@contoso.com>"')

$purgeState = @{ Searches = 0; Purges = 0; Type = ''; Mailboxes = $null }
$removalDeps = [pscustomobject]@{
    NewSearch = { param($Name, $Mailboxes, $Query) $purgeState.Mailboxes = @($Mailboxes) }
    StartSearch = { param($Name) }
    GetSearch = {
        param($Name)
        $purgeState.Searches++
        $items = 2
        if ($purgeState.Searches -gt 1) { $items = 0 }
        [pscustomobject]@{ Status = 'Completed'; Items = $items }
    }
    NewPurge = { param($Name, $PurgeType) $purgeState.Purges++; $purgeState.Type = $PurgeType }
    GetAction = { param($Name) [pscustomobject]@{ Status = 'Completed'; Results = 'Item count: 2' } }
}
$removed = Invoke-InternalMessageRemoval -Report $removalReport -PurgeType 'HardDelete' -PollSeconds 0 -OutputFolder (Join-Path $temp 'removal') -Dependencies $removalDeps
Assert-Equal 'one purge action' $purgeState.Purges 1
Assert-Equal 'hard delete requested' $purgeState.Type 'HardDelete'
Assert-True 'purge skipped external mailbox' (-not ($purgeState.Mailboxes -contains 'vendor@external.com'))
Assert-Equal 'removal completed' $removed.Status 'Completed'
Assert-Equal 'removal remaining none' $removed.RemainingItems 0
Assert-True 'removal csv written' (Test-Path -LiteralPath $removed.ExportPath)
Remove-Item -LiteralPath (Join-Path $temp 'removal') -Recurse -Force -ErrorAction SilentlyContinue

$cancelRemoval = Invoke-InternalMessageRemoval -Report $removalReport -PurgeType 'SoftDelete' -PollSeconds 0 -Dependencies $removalDeps -CancelHandler { $true }
Assert-Equal 'removal cancelled' $cancelRemoval.Status 'Cancelled'

$externalOnly = New-LeakedEmailReport -TraceRows @(
    (New-Trace '2026-09-25T12:00:00Z' 'vendor@external.com' 'other@external.com' $cleanSubject '<Out@external.com>')
) -Subject $cleanSubject -OriginalSender 'vendor@external.com' -InternalDomains $domains -StartDate ([datetime]'2026-09-25') -EndDate ([datetime]'2026-09-26')
$externalPlan = Get-InternalRemovalPlan -Report $externalOnly
Assert-Equal 'external plan has no mailbox' @($externalPlan.Mailboxes).Count 0

$remoteCommands = @(Get-InvestigationRemoteCommandNames)
Assert-True 'remote command list includes trace' ($remoteCommands -contains 'Get-MessageTraceV2')
Assert-True 'remote command list includes detail' ($remoteCommands -contains 'Get-MessageTraceDetailV2')
Assert-True 'remote command list includes domains' ($remoteCommands -contains 'Get-AcceptedDomain')

$views = @(Get-InvestigationViews)
Assert-True 'report views exist' ($views.Count -ge 12)
$viewNames = @{}
foreach ($view in $views) {
    Assert-True "unique file $($view.FileName)" (-not $viewNames.ContainsKey($view.FileName))
    $viewNames[$view.FileName] = $true
    Assert-True "columns $($view.Key)" (@($view.Columns).Count -ge 2)
}

$parseRoot = Split-Path $PSScriptRoot -Parent
foreach ($name in @('LeakedEmailInvestigation.Core.ps1', 'Investigate-LeakedEmail.ps1', 'Investigate-LeakedEmail-GUI.ps1')) {
    $path = Join-Path $parseRoot $name
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors -and @($parseErrors).Count -gt 0) {
        $script:Failed++
        Write-Host "FAIL  $name parses"
        foreach ($parseError in @($parseErrors)) { Write-Host ("      " + $parseError.ToString()) }
    }
    else {
        $script:Passed++
        Write-Host "PASS  $name parses"
    }
}

if ($script:Failed -gt 0) {
    Write-Host ""
    Write-Host ("{0} passed, {1} failed" -f $script:Passed, $script:Failed)
    exit 1
}
Write-Host ""
Write-Host ("{0} passed, 0 failed" -f $script:Passed)
exit 0

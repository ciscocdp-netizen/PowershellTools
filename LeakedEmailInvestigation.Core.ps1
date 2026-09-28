#Requires -Version 5.1
<#
.SYNOPSIS
  Shared engine for leaked-email investigation in Exchange Online.

.DESCRIPTION
  Classifies message-trace rows, mailbox forwarding, and MailItemsAccessed audit
  events, then writes the CSV report set used by Investigate-LeakedEmail.ps1 and
  the GUI. Exchange cmdlets are called only from Invoke-LeakedEmailInvestigation.
  The classification functions are pure and can be tested without a tenant.

  Fixes in this engine:
  - Message-trace paging stops when the cursor does not move, and each query
    stays under the 10-day service limit.
  - Same-subject redirects and resends join the forward chain. Previously only
    FW:/WG:-style subjects were treated as propagation.
  - Subject matching ignores repeated reply/forward prefixes and external tags,
    and drops trace hits whose remaining subject is a different message.
  - Audit paging stops when ResultCount is missing or the same page repeats.
  - Recipient audit batches stay intact. A single batch is not expanded into
    one query per person.
  - Opens are matched by Internet message ID, and mailbox UPNs are linked back
    to SMTP addresses so original recipients are not labeled as forwards.
  - Null audit folders and blank message IDs are ignored.
  - Empty reports still get CSV headers. Counts are never taken from a null
    array (Windows PowerShell reports @($null).Count as 1).
  - Date-only end dates include that calendar day. External original recipients
    are called out separately from external forwards.
  - Folder-sync rows are limited to investigated mailboxes and are not treated
    as proof the message was downloaded.
  - Get-MessageTraceV2 is a remote command created by Connect-ExchangeOnline.
    Importing ExchangeOnlineManagement does not add it, so sign-in is not
    rejected just because the command is absent before the session exists.
#>

$script:InvCtx = $null
$script:SubjectPatterns = $null

function Write-InvLog {
    param(
        [Parameter(Mandatory = $true)][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if ($script:InvCtx -and $script:InvCtx.Log) {
        & $script:InvCtx.Log $Level $Message
    }
    else {
        Write-Verbose ("[{0}] {1}" -f $Level, $Message)
    }
    if ($script:InvCtx -and ($Level -eq 'WARN' -or $Level -eq 'ERROR')) {
        [void]$script:InvCtx.Warnings.Add($Message)
    }
}

function Update-InvProgress {
    param(
        [int]$Percent,
        [string]$Phase,
        [string]$Message
    )
    if ($Message) { Write-InvLog -Level 'INFO' -Message $Message }
    if ($script:InvCtx -and $script:InvCtx.Progress) {
        & $script:InvCtx.Progress $Percent $Phase $Message
    }
}

function Test-InvCancel {
    if ($script:InvCtx -and $script:InvCtx.Cancel) {
        return [bool](& $script:InvCtx.Cancel)
    }
    return $false
}

function Get-ObjectProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function ConvertTo-ItemArray {
    param($Value)
    $list = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Value) {
        foreach ($item in @($Value)) {
            if ($null -ne $item) { $list.Add($item) }
        }
    }
    Write-Output -NoEnumerate -InputObject $list.ToArray()
}

function New-AddressSet {
    # NoEnumerate keeps PowerShell from turning an empty set into "no result".
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    Write-Output -NoEnumerate -InputObject $set
}

function Add-AddressToSet {
    param($Set, $Address)
    if ($null -eq $Set -or $null -eq $Address) { return }
    $text = ([string]$Address).Trim()
    if ($text) { [void]$Set.Add($text) }
}

function ConvertTo-CsvSafeString {
    param($Value)
    if ($null -eq $Value) { return '' }
    $text = [string]$Value
    if ($text.Length -gt 0) {
        $lead = $text.Substring(0, 1)
        if ($lead -eq '=' -or $lead -eq '+' -or $lead -eq '-' -or $lead -eq '@' -or $lead -eq "`t" -or $lead -eq "`r") {
            return "'" + $text
        }
    }
    return $text
}

function ConvertTo-FieldText {
    param([string]$Name, $Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) {
        $stamp = $Value
        if ($Name -eq 'ReceivedUtc' -or $Name -eq 'TimeUtc') {
            if ($stamp.Kind -eq [DateTimeKind]::Local) { $stamp = $stamp.ToUniversalTime() }
            elseif ($stamp.Kind -ne [DateTimeKind]::Utc) { $stamp = [datetime]::SpecifyKind($stamp, [DateTimeKind]::Utc) }
            return $stamp.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
        }
        return $stamp.ToString('yyyy-MM-dd HH:mm:ss')
    }
    if ($Value -is [bool]) {
        if ($Value) { return 'Yes' }
        return 'No'
    }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return [string]$Value
    }
    return (ConvertTo-CsvSafeString $Value)
}

function ConvertTo-UtcFromApi {
    param([datetime]$Value)
    switch ($Value.Kind.ToString()) {
        'Utc' { return $Value }
        'Local' { return $Value.ToUniversalTime() }
        default { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
    }
}

function ConvertTo-UtcFromLocal {
    param([datetime]$Value)
    switch ($Value.Kind.ToString()) {
        'Utc' { return $Value }
        'Local' { return $Value.ToUniversalTime() }
        default { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Local).ToUniversalTime() }
    }
}

function ConvertTo-LocalFromUtc {
    param([datetime]$Value)
    $utc = $Value
    if ($utc.Kind -eq [DateTimeKind]::Local) { return $utc }
    if ($utc.Kind -ne [DateTimeKind]::Utc) { $utc = [datetime]::SpecifyKind($utc, [DateTimeKind]::Utc) }
    return $utc.ToLocalTime()
}

function Get-NormalizedId {
    param($Id)
    if ($null -eq $Id) { return $null }
    $text = ([string]$Id).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $text = $text -replace '^(?i)message-id:\s*', ''
    $text = $text.Trim().Trim('<', '>').Trim()
    $text = $text.Trim('<', '>').Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text.ToLowerInvariant()
}

function Test-SmtpAddress {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    return $Address.Trim() -match '^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$'
}

function Test-InternalAddress {
    param([string]$Address, [string[]]$InternalDomains)
    if ([string]::IsNullOrWhiteSpace($Address) -or $Address -notmatch '@') { return $false }
    $parts = $Address.Trim().Trim('<', '>').Split('@')
    $domainPart = $parts[$parts.Length - 1].Trim().TrimEnd('.').ToLowerInvariant()
    if (-not $domainPart -or $domainPart -eq '*') { return $false }
    foreach ($candidate in @( $InternalDomains )) {
        if ($null -eq $candidate) { continue }
        $dom = ([string]$candidate).Trim().TrimEnd('.').ToLowerInvariant()
        if (-not $dom -or $dom -eq '*') { continue }
        if ($domainPart -eq $dom) { return $true }
        if ($domainPart.EndsWith('.' + $dom)) { return $true }
    }
    return $false
}

function Resolve-InvestigationDateRange {
    param(
        [datetime]$StartDate,
        [datetime]$EndDate
    )
    $start = $StartDate
    $end = $EndDate
    # A midnight end is how -EndDate "2026-09-25" binds. Include that calendar day.
    if ($end.TimeOfDay.Ticks -eq 0 -and $start -le $end) {
        $end = $end.Date.AddDays(1).AddSeconds(-1)
    }
    if ($end -le $start) {
        throw ("End date must be later than the start date. Start was {0:yyyy-MM-dd HH:mm:ss} and end was {1:yyyy-MM-dd HH:mm:ss}." -f $StartDate, $EndDate)
    }
    return [pscustomobject]@{ Start = $start; End = $end }
}

function ConvertTo-AddressList {
    param([string[]]$Values)
    $set = New-AddressSet
    foreach ($value in @( $Values )) {
        if ($null -eq $value) { continue }
        $chunks = ([string]$value) -split '[,\r\n;]+'
        foreach ($chunk in $chunks) {
            $text = $chunk.Trim()
            if ($text) { [void]$set.Add($text) }
        }
    }
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($item in $set) { $list.Add($item) }
    $list.Sort([System.StringComparer]::OrdinalIgnoreCase)
    Write-Output -NoEnumerate -InputObject $list.ToArray()
}

function New-PrefixRegex {
    param([string[]]$Prefixes)
    $ordered = @($Prefixes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object { $_.Length } -Descending)
    $escaped = foreach ($prefix in $ordered) { [regex]::Escape($prefix.Trim()) }
    $alternation = $escaped -join '|'
    return [regex]::new('^\s*(?:(?:' + $alternation + ')\s*:\s*)+', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Get-SubjectPatterns {
    if ($script:SubjectPatterns) { return $script:SubjectPatterns }
    $auto = New-PrefixRegex -Prefixes @(
        'Automatic reply', 'Automatische Antwort', 'Automatisch antwoord',
        'Respuesta automatica', 'Reponse automatique', 'Out of Office',
        'Out-of-Office', 'Autosvar', 'Abwesenheitsnotiz'
    )
    $forward = New-PrefixRegex -Prefixes @(
        'Doorgestuurd', 'Doorsturen', 'Weitergeleitet', 'Encaminhada', 'Encaminhado',
        'Iletildi', 'Doorst', 'FWD', 'ENC', 'ILT', 'WG', 'RV', 'VB', 'VL', 'TR', 'PD', 'FW', 'I'
    )
    $reply = New-PrefixRegex -Prefixes @('ANTW', 'RIF', 'YNT', 'RES', 'REF', 'AW', 'SV', 'VS', 'RE')
    $external = [regex]::new('^(?:\s*\[[^\]]*(?:EXT|EXTERNAL|CAUTION)[^\]]*\]\s*|\s*(?:EXTERNAL|CAUTION)\s*:\s*)+', 'IgnoreCase')
    $ndr = [regex]::new('^\s*(?:undeliverable|delivery status notification|delivery has failed|failure notice|returned mail|mail delivery failed)\s*:?\s*', 'IgnoreCase')
    $journal = [regex]::new('^\s*journal(?:\s+report)?\s*[:\(]\s*', 'IgnoreCase')
    $script:SubjectPatterns = [pscustomobject]@{
        AutoReply = $auto
        Forward   = $forward
        Reply     = $reply
        External  = $external
        Ndr       = $ndr
        Journal   = $journal
    }
    return $script:SubjectPatterns
}

function Get-NormalizedSubjectInfo {
    param([string]$Subject)
    $patterns = Get-SubjectPatterns
    $text = if ($null -eq $Subject) { '' } else { [string]$Subject }
    $text = $text.Replace([char]0x00A0, ' ')
    $text = [regex]::Replace($text, '[\u200B\u200C\u200D\uFEFF]', '')
    $text = $text.Trim()
    $kind = 'None'
    if ($patterns.Ndr.IsMatch($text)) {
        $kind = 'Ndr'
        $text = $patterns.Ndr.Replace($text, '', 1).Trim()
    }
    elseif ($patterns.Journal.IsMatch($text)) {
        $kind = 'Journal'
        $text = $patterns.Journal.Replace($text, '', 1).Trim()
    }

    $guard = 0
    $changed = $true
    while ($changed -and $guard -lt 20) {
        $guard++
        $changed = $false
        $next = $patterns.External.Replace($text, '')
        if ($next -ne $text) {
            $text = $next.Trim()
            $changed = $true
        }
        $next = $patterns.AutoReply.Replace($text, '')
        if ($next -ne $text) {
            $text = $next.Trim()
            $changed = $true
            if ($kind -eq 'None') { $kind = 'AutoReply' }
            continue
        }
        $next = $patterns.Forward.Replace($text, '')
        if ($next -ne $text) {
            $text = $next.Trim()
            $changed = $true
            if ($kind -eq 'None') { $kind = 'Forward' }
            continue
        }
        $next = $patterns.Reply.Replace($text, '')
        if ($next -ne $text) {
            $text = $next.Trim()
            $changed = $true
            if ($kind -eq 'None') { $kind = 'Reply' }
        }
    }
    $normalized = ([regex]::Replace($text, '\s+', ' ')).Trim()
    return [pscustomobject]@{
        Raw     = $Subject
        Subject = $normalized
        Kind    = $kind
    }
}

function Test-SameSubject {
    param(
        [string]$Left,
        [string]$Right,
        [bool]$Loose = $false
    )
    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) { return $false }
    if ($Loose) {
        $cmp = [System.StringComparison]::OrdinalIgnoreCase
        return ($Left.IndexOf($Right, $cmp) -ge 0) -or ($Right.IndexOf($Left, $cmp) -ge 0)
    }
    return [string]::Equals($Left, $Right, [System.StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-TraceRow {
    param($Raw)
    if ($null -eq $Raw) { return $null }
    $receivedRaw = Get-ObjectProperty $Raw 'Received'
    $receivedUtc = $null
    if ($receivedRaw -is [datetime]) {
        $receivedUtc = ConvertTo-UtcFromApi -Value $receivedRaw
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$receivedRaw)) {
        $receivedUtc = ConvertTo-UtcFromApi -Value ([datetime]$receivedRaw)
    }
    else {
        $existing = Get-ObjectProperty $Raw 'ReceivedUtc'
        if ($existing -is [datetime]) { $receivedUtc = ConvertTo-UtcFromApi -Value $existing }
        else { $receivedUtc = [datetime]::SpecifyKind([datetime]'1970-01-01Z', [DateTimeKind]::Utc) }
    }
    $size = Get-ObjectProperty $Raw 'Size'
    return [pscustomobject]@{
        ReceivedUtc      = $receivedUtc
        Received         = (ConvertTo-LocalFromUtc -Value $receivedUtc)
        SenderAddress    = ([string](Get-ObjectProperty $Raw 'SenderAddress')).Trim()
        RecipientAddress = ([string](Get-ObjectProperty $Raw 'RecipientAddress')).Trim()
        Subject          = [string](Get-ObjectProperty $Raw 'Subject')
        Status           = [string](Get-ObjectProperty $Raw 'Status')
        MessageId        = [string](Get-ObjectProperty $Raw 'MessageId')
        MessageTraceId   = [string](Get-ObjectProperty $Raw 'MessageTraceId')
        FromIP           = [string](Get-ObjectProperty $Raw 'FromIP')
        ToIP             = [string](Get-ObjectProperty $Raw 'ToIP')
        Size             = if ($null -eq $size) { '' } else { [string]$size }
    }
}

function Get-MessageTracePages {
    param(
        [datetime]$StartUtc,
        [datetime]$EndUtc,
        [string]$SubjectText,
        [int]$PageSize = 5000,
        [scriptblock]$FetchPage,
        [int]$MaxRows = 200000
    )
    $results = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $capped = $false
    $stalled = $false
    $cancelled = $false
    $windowStart = $StartUtc

    while ($windowStart -lt $EndUtc) {
        if (Test-InvCancel) { $cancelled = $true; break }
        $windowEnd = $windowStart.AddDays(10).AddMinutes(-1)
        if ($windowEnd -gt $EndUtc) { $windowEnd = $EndUtc }
        if ($windowEnd -le $windowStart) { break }

        $pageEnd = $windowEnd
        $startingRecipient = $null
        $stalls = 0
        $guardPages = 0
        while ($true) {
            if (Test-InvCancel) { $cancelled = $true; break }
            $guardPages++
            if ($guardPages -gt 10000) {
                $stalled = $true
                Write-InvLog -Level 'WARN' -Message 'Message trace pagination exceeded the page guard. Results may be incomplete.'
                break
            }
            Update-InvProgress -Percent 25 -Phase 'Trace' -Message ("Message trace {0:u} -> {1:u}" -f $windowStart, $pageEnd)
            $query = [pscustomobject]@{
                WindowStart         = $windowStart
                WindowEnd           = $windowEnd
                PageEnd             = $pageEnd
                StartingRecipient   = $startingRecipient
                PageSize            = $PageSize
                Subject             = $SubjectText
            }
            $page = ConvertTo-ItemArray (& $FetchPage $query)
            $added = 0
            $lastRow = $null
            foreach ($raw in $page) {
                $row = ConvertTo-TraceRow $raw
                if ($null -eq $row) { continue }
                $lastRow = $row
                $recipientKey = ''
                if ($row.RecipientAddress) { $recipientKey = $row.RecipientAddress.ToLowerInvariant() }
                $messageKey = ''
                if ($row.MessageId) { $messageKey = $row.MessageId.ToLowerInvariant() }
                $statusKey = ''
                if ($row.Status) { $statusKey = $row.Status.ToLowerInvariant() }
                $key = '{0}|{1}|{2}|{3}|{4}' -f $row.MessageTraceId, $recipientKey, $messageKey, $row.ReceivedUtc.Ticks, $statusKey
                if (-not $seen.ContainsKey($key)) {
                    $seen[$key] = $true
                    $results.Add($row)
                    $added++
                    if ($results.Count -ge $MaxRows) { $capped = $true; break }
                }
            }
            if ($capped -or $cancelled) { break }
            if ($page.Count -lt $PageSize) { break }
            if ($null -eq $lastRow -or $null -eq $lastRow.ReceivedUtc) { break }

            $newEnd = $lastRow.ReceivedUtc
            $newRecipient = $lastRow.RecipientAddress
            $sameCursor = ($newEnd -eq $pageEnd -and [string]$newRecipient -eq [string]$startingRecipient)
            if ($sameCursor -or $newEnd -le $windowStart) {
                $stalled = $true
                Write-InvLog -Level 'WARN' -Message 'Message trace pagination cursor did not advance. This window may be incomplete.'
                break
            }
            if ($added -eq 0) {
                $stalls++
                if ($stalls -ge 2) {
                    $stalled = $true
                    Write-InvLog -Level 'WARN' -Message 'Message trace returned the same page twice. Stopping this window.'
                    break
                }
            }
            else { $stalls = 0 }
            $pageEnd = $newEnd
            $startingRecipient = $newRecipient
        }
        if ($capped -or $cancelled) { break }
        $windowStart = $windowEnd
    }

    return [pscustomobject]@{
        Rows      = (ConvertTo-ItemArray $results.ToArray())
        Capped    = $capped
        Stalled   = $stalled
        Cancelled = $cancelled
    }
}

function Split-IntoBatches {
    param(
        [string[]]$Items,
        [int]$Size = 50
    )
    if ($Size -lt 1) { $Size = 50 }
    $clean = New-Object System.Collections.Generic.List[string]
    $seen = New-AddressSet
    foreach ($item in @( $Items )) {
        if ($null -eq $item) { continue }
        foreach ($chunk in (([string]$item) -split '[,\r\n;]+')) {
            $text = $chunk.Trim()
            if ($text -and $seen.Add($text)) { $clean.Add($text) }
        }
    }
    $batches = New-Object System.Collections.Generic.List[object]
    for ($offset = 0; $offset -lt $clean.Count; $offset += $Size) {
        $take = [Math]::Min($Size, $clean.Count - $offset)
        $slice = New-Object string[] $take
        for ($index = 0; $index -lt $take; $index++) {
            $slice[$index] = $clean[$offset + $index]
        }
        $batches.Add($slice)
    }
    return [pscustomobject]@{ Batches = $batches.ToArray() }
}

function Invoke-PagedAuditSearch {
    param(
        [scriptblock]$Fetch,
        [datetime]$StartUtc,
        [datetime]$EndUtc,
        [string[]]$UserIds,
        [bool]$HighCompleteness,
        [int]$PageSize = 5000,
        [int]$MaxRecords = 100000,
        [string]$Operation = 'MailItemsAccessed'
    )
    $all = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $session = [guid]::NewGuid().ToString()
    $stalls = 0
    $pages = 0
    $capped = $false
    $cancelled = $false
    while ($true) {
        if (Test-InvCancel) { $cancelled = $true; break }
        $pages++
        if ($pages -gt 10000) {
            Write-InvLog -Level 'WARN' -Message 'Audit pagination exceeded the page guard.'
            break
        }
        $query = [pscustomobject]@{
            Start             = $StartUtc
            End               = $EndUtc
            Operations        = $Operation
            UserIds           = $UserIds
            SessionId         = $session
            HighCompleteness  = $HighCompleteness
            ResultSize        = $PageSize
        }
        $batch = ConvertTo-ItemArray (& $Fetch $query)
        if ($batch.Count -eq 0) { break }
        $added = 0
        $last = $null
        foreach ($record in $batch) {
            $last = $record
            $key = [string](Get-ObjectProperty $record 'Identity')
            if ([string]::IsNullOrWhiteSpace($key)) {
                $key = [string](Get-ObjectProperty $record 'AuditData')
            }
            if ([string]::IsNullOrWhiteSpace($key)) {
                $all.Add($record)
                $added++
            }
            elseif (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $all.Add($record)
                $added++
            }
            if ($all.Count -ge $MaxRecords) { $capped = $true; break }
        }
        if ($capped) {
            Write-InvLog -Level 'WARN' -Message "Audit search stopped after $MaxRecords records."
            break
        }
        $resultCount = Get-ObjectProperty $last 'ResultCount'
        $resultIndex = Get-ObjectProperty $last 'ResultIndex'
        $done = $false
        if ($batch.Count -lt $PageSize) { $done = $true }
        if ($null -ne $resultCount -and $null -ne $resultIndex -and "$resultCount" -ne '') {
            $countNumber = 0
            $indexNumber = 0
            if ([int]::TryParse([string]$resultCount, [ref]$countNumber) -and [int]::TryParse([string]$resultIndex, [ref]$indexNumber)) {
                if ($countNumber -ge 0 -and $indexNumber -ge $countNumber) { $done = $true }
            }
        }
        if ($added -eq 0) {
            $stalls++
            if ($stalls -ge 2) {
                Write-InvLog -Level 'WARN' -Message 'Audit search repeated the same page. Stopping this batch.'
                $done = $true
            }
        }
        else { $stalls = 0 }
        if ($done) { break }
    }
    return [pscustomobject]@{
        Records   = (ConvertTo-ItemArray $all.ToArray())
        Capped    = $capped
        Cancelled = $cancelled
    }
}

function Get-SmtpFromForwardingValue {
    param($Value)
    $text = ([string]$Value).Trim()
    if (-not $text) { return '' }
    return ($text -replace '^(?i)smtp:', '').Trim()
}

function ConvertTo-MailboxRecord {
    param($Raw, [string]$RequestedAddress)
    if ($null -eq $Raw) { throw "No mailbox object was returned for $RequestedAddress." }
    $primary = [string](Get-ObjectProperty $Raw 'PrimarySmtpAddress')
    if (-not $primary) { $primary = $RequestedAddress }
    $upn = [string](Get-ObjectProperty $Raw 'UserPrincipalName')
    if (-not $upn) { $upn = $primary }
    $addresses = New-AddressSet
    Add-AddressToSet $addresses $RequestedAddress
    Add-AddressToSet $addresses $primary
    Add-AddressToSet $addresses $upn
    foreach ($proxy in (ConvertTo-ItemArray (Get-ObjectProperty $Raw 'EmailAddresses'))) {
        $smtp = Get-SmtpFromForwardingValue $proxy
        Add-AddressToSet $addresses $smtp
    }
    $addressList = New-Object System.Collections.Generic.List[string]
    foreach ($item in $addresses) { $addressList.Add($item.ToLowerInvariant()) }
    $forwardSmtp = Get-SmtpFromForwardingValue (Get-ObjectProperty $Raw 'ForwardingSmtpAddress')
    $forwardAddress = Get-SmtpFromForwardingValue (Get-ObjectProperty $Raw 'ForwardingAddress')
    $deliver = Get-ObjectProperty $Raw 'DeliverToMailboxAndForward'
    $deliverText = ''
    if ($null -ne $deliver) { $deliverText = [string]$deliver }
    return [pscustomobject]@{
        Requested                  = $RequestedAddress
        PrimarySmtp                = $primary.Trim()
        UserPrincipalName          = $upn.Trim()
        Addresses                  = $addressList.ToArray()
        ForwardingAddress          = $forwardAddress
        ForwardingSmtpAddress      = $forwardSmtp
        DeliverToMailboxAndForward = $deliverText
        Error                      = ''
    }
}

function Get-RuleTargets {
    param($Rule)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('ForwardTo', 'RedirectTo', 'ForwardAsAttachmentTo')) {
        foreach ($item in (ConvertTo-ItemArray (Get-ObjectProperty $Rule $name))) {
            $text = ([string]$item).Trim()
            if ($text) { $parts.Add($text) }
        }
    }
    Write-Output -NoEnumerate -InputObject $parts.ToArray()
}

function New-AutoForwardRow {
    param(
        [string]$Mailbox,
        [string]$Type,
        [string]$Name,
        $Enabled,
        [string]$Target,
        [string]$Deliver,
        [string]$Detail,
        [string[]]$InternalDomains
    )
    $smtp = Get-SmtpFromForwardingValue $Target
    $external = 'Unknown'
    if ($smtp -match '@') {
        if (Test-InternalAddress -Address $smtp -InternalDomains $InternalDomains) { $external = 'No' }
        else { $external = 'Yes' }
    }
    $enabledText = ''
    if ($Enabled -is [bool]) { $enabledText = $(if ($Enabled) { 'Yes' } else { 'No' }) }
    elseif ($null -ne $Enabled) { $enabledText = [string]$Enabled }
    return [pscustomobject]@{
        Mailbox                    = $Mailbox
        Type                       = $Type
        Name                       = $Name
        Enabled                    = $enabledText
        Target                     = $(if ($smtp) { $smtp } else { $Target })
        TargetExternal             = $external
        DeliverToMailboxAndForward = $Deliver
        Detail                     = $Detail
    }
}

function Get-AcquisitionText {
    param(
        [string]$Address,
        $FirstDelivery,
        $SenderSet
    )
    $lines = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Address)) {
        return 'Unknown (blank address)'
    }
    $current = $Address.Trim().ToLowerInvariant()
    if ($SenderSet.Contains($current)) { return 'Original sender' }
    $seen = @{}
    $guard = 0
    while ($guard -lt 30) {
        $guard++
        if ($seen.ContainsKey($current)) {
            $lines.Add('Cycle detected')
            break
        }
        $seen[$current] = $true
        if (-not $FirstDelivery.ContainsKey($current)) {
            $lines.Add('Unknown (not in trace: BCC, group expansion, or edited subject)')
            break
        }
        $event = $FirstDelivery[$current]
        $lines.Add(('{0} from {1}' -f $event.Method, $event.Sender))
        if ($event.Method -eq 'Original') { break }
        $current = ([string]$event.Sender).Trim().ToLowerInvariant()
        if ($SenderSet.Contains($current)) { break }
    }
    if ($lines.Count -eq 0) { return 'Unknown (not in trace: BCC, group expansion, or edited subject)' }
    return ($lines -join ' <- ')
}

function New-FlowRow {
    param(
        $Trace,
        [string]$Category,
        [string]$Method,
        [string]$NormalizedSubject,
        [bool]$External,
        [string]$Via,
        [string]$Chain
    )
    $externalText = $(if ($External) { 'Yes' } else { 'No' })
    return [pscustomobject]@{
        Category           = $Category
        Method             = $Method
        Received           = $Trace.Received
        ReceivedUtc        = $Trace.ReceivedUtc
        SenderAddress      = $Trace.SenderAddress
        RecipientAddress   = $Trace.RecipientAddress
        External           = $externalText
        Status             = $Trace.Status
        Subject            = $Trace.Subject
        NormalizedSubject  = $NormalizedSubject
        MessageId          = $Trace.MessageId
        MessageTraceId     = $Trace.MessageTraceId
        FromIP             = $Trace.FromIP
        ToIP               = $Trace.ToIP
        Size               = $Trace.Size
        ForwardedBy        = $Trace.SenderAddress
        ForwardedTo        = $Trace.RecipientAddress
        ForwarderGotItVia  = $Via
        Chain              = $Chain
        TraceEvents        = ''
        Reason             = ''
    }
}

function New-LeakedEmailReport {
    param(
        $TraceRows,
        [Parameter(Mandatory = $true)][string]$Subject,
        [Parameter(Mandatory = $true)][string]$OriginalSender,
        [string[]]$SenderAddresses,
        [string[]]$InternalDomains,
        [string]$MessageId,
        [bool]$LooseSubjectMatch = $false,
        [datetime]$StartDate = ([datetime]::MinValue),
        [datetime]$EndDate = ([datetime]::MinValue),
        [string]$OutputFolder = ''
    )
    $searchInfo = Get-NormalizedSubjectInfo -Subject $Subject
    if ([string]::IsNullOrWhiteSpace($searchInfo.Subject)) {
        throw 'The subject is empty after removing reply and forward prefixes.'
    }
    $senderSet = New-AddressSet
    Add-AddressToSet $senderSet $OriginalSender
    foreach ($alias in @( $SenderAddresses )) { Add-AddressToSet $senderSet $alias }
    $targetMessageId = Get-NormalizedId $MessageId
    $domains = @()
    foreach ($domain in @( $InternalDomains )) {
        if (-not [string]::IsNullOrWhiteSpace([string]$domain)) { $domains += ([string]$domain).Trim() }
    }

    $normalizedRows = New-Object System.Collections.Generic.List[object]
    foreach ($raw in (ConvertTo-ItemArray $TraceRows)) {
        $row = ConvertTo-TraceRow $raw
        if ($null -ne $row) { $normalizedRows.Add($row) }
    }

    $pending = New-Object System.Collections.Generic.List[object]
    $excluded = New-Object System.Collections.Generic.List[object]
    foreach ($trace in $normalizedRows) {
        $info = Get-NormalizedSubjectInfo -Subject $trace.Subject
        $idMatch = $false
        if ($targetMessageId) {
            $rowId = Get-NormalizedId $trace.MessageId
            if ($rowId -and $rowId -eq $targetMessageId) { $idMatch = $true }
        }
        $same = Test-SameSubject -Left $info.Subject -Right $searchInfo.Subject -Loose $LooseSubjectMatch
        $senderMatch = $false
        if ($trace.SenderAddress -and $senderSet.Contains($trace.SenderAddress)) { $senderMatch = $true }
        if (-not $same -and -not $idMatch) {
            $excluded.Add((New-FlowRow -Trace $trace -Category 'Excluded' -Method 'Excluded' -NormalizedSubject $info.Subject -External $false -Via '' -Chain ''))
            $excluded[$excluded.Count - 1].Reason = 'Subject does not match after prefix removal'
            $excluded[$excluded.Count - 1].External = $(if (Test-InternalAddress -Address $trace.RecipientAddress -InternalDomains $domains) { 'No' } else { 'Yes' })
            continue
        }
        $pending.Add([pscustomobject]@{
            Trace         = $trace
            Info          = $info
            IdMatch       = $idMatch
            Same          = $same
            SenderMatch   = $senderMatch
        })
    }

    $events = New-Object System.Collections.Generic.List[object]
    foreach ($item in $pending) {
        $method = 'Redirect'
        if ($item.Info.Kind -eq 'None' -and ($item.SenderMatch -or $item.IdMatch)) { $method = 'Original' }
        elseif ($item.Info.Kind -eq 'Forward') { $method = 'Forward' }
        elseif ($item.Info.Kind -eq 'Reply') { $method = 'Reply' }
        elseif ($item.Info.Kind -eq 'AutoReply') { $method = 'AutoReply' }
        elseif ($item.Info.Kind -eq 'Ndr') { $method = 'Ndr' }
        elseif ($item.Info.Kind -eq 'Journal') { $method = 'Journal' }
        elseif ($item.Info.Kind -eq 'None' -and -not $item.SenderMatch) { $method = 'Redirect' }
        $events.Add([pscustomobject]@{
            Received = $item.Trace.ReceivedUtc
            Sender   = $item.Trace.SenderAddress
            Recipient = $item.Trace.RecipientAddress
            Method   = $method
            Item     = $item
        })
    }
    $orderedEvents = @($events | Sort-Object Received, @{ Expression = {
        switch ($_.Method) {
            'Original' { 0 }
            'Redirect' { 1 }
            'Forward' { 2 }
            default { 3 }
        }
    } })

    $firstDelivery = @{}
    foreach ($event in $orderedEvents) {
        if ([string]::IsNullOrWhiteSpace($event.Recipient)) { continue }
        $key = $event.Recipient.Trim().ToLowerInvariant()
        if (-not $firstDelivery.ContainsKey($key)) { $firstDelivery[$key] = $event }
    }

    $original = New-Object System.Collections.Generic.List[object]
    $propagation = New-Object System.Collections.Generic.List[object]
    $replies = New-Object System.Collections.Generic.List[object]
    $autoReplies = New-Object System.Collections.Generic.List[object]
    $ndrs = New-Object System.Collections.Generic.List[object]
    $journals = New-Object System.Collections.Generic.List[object]
    $subjectMismatch = 0

    foreach ($event in $orderedEvents) {
        $item = $event.Item
        $trace = $item.Trace
        $external = -not (Test-InternalAddress -Address $trace.RecipientAddress -InternalDomains $domains)
        $via = ''
        $chain = ''
        $category = $event.Method
        switch ($event.Method) {
            'Original' {
                $via = 'Original sender'
                $chain = 'Original send'
                if ($item.IdMatch -and -not $item.Same) { $subjectMismatch++ }
            }
            'Forward' {
                $via = Get-AcquisitionText -Address $trace.SenderAddress -FirstDelivery $firstDelivery -SenderSet $senderSet
                $chain = $via
                $category = 'Forward'
            }
            'Redirect' {
                $via = Get-AcquisitionText -Address $trace.SenderAddress -FirstDelivery $firstDelivery -SenderSet $senderSet
                $chain = $via
                $category = 'Redirect'
            }
            default {
                $via = ''
                $chain = ''
            }
        }
        $flow = New-FlowRow -Trace $trace -Category $category -Method $event.Method -NormalizedSubject $item.Info.Subject -External $external -Via $via -Chain $chain
        switch ($event.Method) {
            'Original' { $original.Add($flow) }
            'Forward' { $propagation.Add($flow) }
            'Redirect' { $propagation.Add($flow) }
            'Reply' { $replies.Add($flow) }
            'AutoReply' { $autoReplies.Add($flow) }
            'Ndr' { $ndrs.Add($flow) }
            'Journal' { $journals.Add($flow) }
        }
    }

    $redirects = New-Object System.Collections.Generic.List[object]
    foreach ($row in $propagation) {
        if ($row.Method -eq 'Redirect') { $redirects.Add($row) }
    }

    $forwarderMap = @{}
    foreach ($row in $propagation) {
        $key = if ($row.ForwardedBy) { $row.ForwardedBy.ToLowerInvariant() } else { '' }
        if (-not $forwarderMap.ContainsKey($key)) {
            $forwarderMap[$key] = New-Object System.Collections.Generic.List[object]
        }
        $forwarderMap[$key].Add($row)
    }
    $forwarders = New-Object System.Collections.Generic.List[object]
    foreach ($key in $forwarderMap.Keys) {
        $group = $forwarderMap[$key]
        $display = $group[0].ForwardedBy
        $messages = New-AddressSet
        $recipients = New-AddressSet
        $externalRecipients = New-AddressSet
        $methods = New-AddressSet
        $first = $group[0].ReceivedUtc
        $last = $group[0].ReceivedUtc
        foreach ($row in $group) {
            [void]$methods.Add($row.Method)
            $id = Get-NormalizedId $row.MessageId
            if ($id) { [void]$messages.Add($id) } else { [void]$messages.Add([guid]::NewGuid().ToString()) }
            Add-AddressToSet $recipients $row.RecipientAddress
            if ($row.External -eq 'Yes') { Add-AddressToSet $externalRecipients $row.RecipientAddress }
            if ($row.ReceivedUtc -lt $first) { $first = $row.ReceivedUtc }
            if ($row.ReceivedUtc -gt $last) { $last = $row.ReceivedUtc }
        }
        $externalList = New-Object System.Collections.Generic.List[string]
        foreach ($addr in $externalRecipients) { $externalList.Add($addr) }
        $externalList.Sort([System.StringComparer]::OrdinalIgnoreCase)
        $methodList = New-Object System.Collections.Generic.List[string]
        foreach ($method in $methods) { $methodList.Add($method) }
        $methodList.Sort()
        $forwarders.Add([pscustomobject]@{
            Forwarder              = $display
            Methods                = ($methodList -join '; ')
            EventCount             = $group.Count
            MessageCount           = $messages.Count
            RecipientCount         = $recipients.Count
            ExternalRecipientCount = $externalRecipients.Count
            ExternalRecipients     = ($externalList -join '; ')
            External               = $(if ($externalRecipients.Count -gt 0) { 'Yes' } else { 'No' })
            FirstForward           = (ConvertTo-LocalFromUtc -Value $first)
            LastForward            = (ConvertTo-LocalFromUtc -Value $last)
        })
    }

    $related = New-Object System.Collections.Generic.List[object]
    foreach ($row in $original) { $related.Add($row) }
    foreach ($row in $propagation) { $related.Add($row) }
    foreach ($row in $replies) { $related.Add($row) }
    foreach ($row in $autoReplies) { $related.Add($row) }
    foreach ($row in $ndrs) { $related.Add($row) }
    foreach ($row in $journals) { $related.Add($row) }

    $senderList = New-Object System.Collections.Generic.List[string]
    foreach ($item in $senderSet) { $senderList.Add($item) }

    $report = [pscustomobject]@{
        Subject              = $Subject
        SearchedSubject      = $searchInfo.Subject
        OriginalSender       = $OriginalSender
        SenderAddresses      = $senderList.ToArray()
        MessageId            = $MessageId
        LooseSubjectMatch    = $LooseSubjectMatch
        StartDate            = $StartDate
        EndDate              = $EndDate
        OutputFolder         = $OutputFolder
        InternalDomains      = $domains
        GeneratedOn          = (Get-Date)
        Cancelled            = $false
        Capped               = $false
        Warnings             = @()
        Options              = $null
        AuditStatus          = ''
        AuditError           = ''
        AuditThrottled       = $false
        AuditAllUsers        = $false
        AuditIngestionEnabled = $null
        SubjectMismatchCount = $subjectMismatch
        Mailboxes            = @()
        Original             = (ConvertTo-ItemArray $original.ToArray())
        Propagation          = (ConvertTo-ItemArray $propagation.ToArray())
        Redirects            = (ConvertTo-ItemArray $redirects.ToArray())
        Forwarders           = (ConvertTo-ItemArray $forwarders.ToArray())
        Replies              = (ConvertTo-ItemArray $replies.ToArray())
        AutoReplies          = (ConvertTo-ItemArray $autoReplies.ToArray())
        Ndrs                 = (ConvertTo-ItemArray $ndrs.ToArray())
        Journals             = (ConvertTo-ItemArray $journals.ToArray())
        Noise                = @()
        Excluded             = (ConvertTo-ItemArray $excluded.ToArray())
        RelatedTrace         = (ConvertTo-ItemArray $related.ToArray())
        AutoForwarding       = @()
        Policy               = @()
        Opened               = @()
        Syncs                = @()
        NoOpen               = @()
        Timeline             = @()
        Findings             = @()
        Summary              = $null
        ExportError          = ''
    }
    Complete-LeakedEmailReport -Report $report
    return $report
}

function Get-UniqueFieldValues {
    param($Rows, [string]$PropertyName)
    $set = New-AddressSet
    foreach ($row in (ConvertTo-ItemArray $Rows)) {
        Add-AddressToSet $set (Get-ObjectProperty $row $PropertyName)
    }
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($item in $set) { $list.Add($item) }
    $list.Sort([System.StringComparer]::OrdinalIgnoreCase)
    Write-Output -NoEnumerate -InputObject $list.ToArray()
}

function Get-RecipientRoster {
    param($Report)
    $roles = @{}
    function Add-Role([string]$Address, [string]$Role) {
        if ([string]::IsNullOrWhiteSpace($Address)) { return }
        $key = $Address.Trim().ToLowerInvariant()
        if (-not $roles.ContainsKey($key)) { $roles[$key] = New-Object System.Collections.Generic.List[string] }
        if (-not $roles[$key].Contains($Role)) { $roles[$key].Add($Role) }
    }
    foreach ($row in (ConvertTo-ItemArray $Report.Original)) {
        if ($row.External -eq 'No') { Add-Role $row.RecipientAddress 'Original' }
    }
    foreach ($row in (ConvertTo-ItemArray $Report.Propagation)) {
        if ($row.External -eq 'No') {
            $role = $(if ($row.Method -eq 'Redirect') { 'Redirect' } else { 'Forward' })
            Add-Role $row.RecipientAddress $role
        }
    }
    foreach ($row in (ConvertTo-ItemArray $Report.Replies)) {
        if ($row.External -eq 'No') { Add-Role $row.RecipientAddress 'Reply' }
    }

    $byAddress = @{}
    foreach ($box in (ConvertTo-ItemArray $Report.Mailboxes)) {
        foreach ($addr in (ConvertTo-ItemArray $box.Addresses)) {
            $byAddress[$addr.ToLowerInvariant()] = $box
        }
        if ($box.Requested) { $byAddress[$box.Requested.ToLowerInvariant()] = $box }
    }

    $roster = New-Object System.Collections.Generic.List[object]
    $consumed = @{}
    foreach ($address in @($roles.Keys)) {
        if ($consumed.ContainsKey($address)) { continue }
        $box = $null
        if ($byAddress.ContainsKey($address)) { $box = $byAddress[$address] }
        $identities = New-AddressSet
        Add-AddressToSet $identities $address
        $primary = $address
        $upn = ''
        $requested = $address
        if ($box) {
            $primary = $box.PrimarySmtp
            $upn = $box.UserPrincipalName
            $requested = $box.Requested
            foreach ($alias in (ConvertTo-ItemArray $box.Addresses)) { Add-AddressToSet $identities $alias }
            Add-AddressToSet $identities $box.UserPrincipalName
            Add-AddressToSet $identities $box.PrimarySmtp
            Add-AddressToSet $identities $box.Requested
        }
        $roleList = New-Object System.Collections.Generic.List[string]
        foreach ($id in @($identities)) {
            $idKey = $id.ToLowerInvariant()
            if ($roles.ContainsKey($idKey)) {
                foreach ($role in $roles[$idKey]) {
                    if (-not $roleList.Contains($role)) { $roleList.Add($role) }
                }
                $consumed[$idKey] = $true
            }
        }
        $consumed[$address] = $true
        $receivedAs = 'Other'
        if ($roleList.Contains('Original')) { $receivedAs = 'Original' }
        elseif ($roleList.Contains('Forward') -and $roleList.Contains('Redirect')) { $receivedAs = 'Forward and redirect' }
        elseif ($roleList.Contains('Forward')) { $receivedAs = 'Forward' }
        elseif ($roleList.Contains('Redirect')) { $receivedAs = 'Redirect' }
        elseif ($roleList.Contains('Reply')) { $receivedAs = 'Reply' }
        $roster.Add([pscustomobject]@{
            Address     = $requested
            PrimarySmtp = $primary
            UserPrincipalName = $upn
            Identities  = @($identities)
            ReceivedAs  = $receivedAs
            LookupError = $(if ($box) { [string]$box.Error } else { '' })
        })
    }
    Write-Output -NoEnumerate -InputObject $roster.ToArray()
}

function Complete-LeakedEmailReport {
    param($Report)
    $domains = @( $Report.InternalDomains )
    $originalRecipients = Get-UniqueFieldValues -Rows $Report.Original -PropertyName 'RecipientAddress'
    $originalExternalSet = New-AddressSet
    foreach ($row in (ConvertTo-ItemArray $Report.Original)) {
        if ($row.External -eq 'Yes') { Add-AddressToSet $originalExternalSet $row.RecipientAddress }
    }
    $originalExternal = New-Object System.Collections.Generic.List[string]
    foreach ($item in $originalExternalSet) { $originalExternal.Add($item) }
    $originalExternal.Sort([System.StringComparer]::OrdinalIgnoreCase)
    $propagationRecipients = Get-UniqueFieldValues -Rows $Report.Propagation -PropertyName 'RecipientAddress'
    $propagationExternalSet = New-AddressSet
    foreach ($row in (ConvertTo-ItemArray $Report.Propagation)) {
        if ($row.External -eq 'Yes') { Add-AddressToSet $propagationExternalSet $row.RecipientAddress }
    }
    $propagationExternal = New-Object System.Collections.Generic.List[string]
    foreach ($item in $propagationExternalSet) { $propagationExternal.Add($item) }
    $propagationExternal.Sort([System.StringComparer]::OrdinalIgnoreCase)

    $noise = New-Object System.Collections.Generic.List[object]
    foreach ($row in (ConvertTo-ItemArray $Report.Ndrs)) { $noise.Add($row) }
    foreach ($row in (ConvertTo-ItemArray $Report.Journals)) { $noise.Add($row) }
    $Report.Noise = ConvertTo-ItemArray $noise.ToArray()

    $autoExternal = 0
    foreach ($row in (ConvertTo-ItemArray $Report.AutoForwarding)) {
        $enabled = [string]$row.Enabled
        if ($row.TargetExternal -eq 'Yes' -and $enabled -ne 'No' -and $row.Type -ne 'LookupFailed') { $autoExternal++ }
    }

    $openedMailboxes = Get-UniqueFieldValues -Rows $Report.Opened -PropertyName 'MailboxOwner'
    $delegateOpens = 0
    foreach ($row in (ConvertTo-ItemArray $Report.Opened)) {
        if ($row.DelegateAccess -eq 'Yes') { $delegateOpens++ }
    }

    $openedKeys = New-AddressSet
    foreach ($row in (ConvertTo-ItemArray $Report.Opened)) {
        Add-AddressToSet $openedKeys $row.OpenedBy
        Add-AddressToSet $openedKeys $row.MailboxOwner
    }
    foreach ($box in (ConvertTo-ItemArray $Report.Mailboxes)) {
        $hit = $false
        foreach ($alias in (ConvertTo-ItemArray $box.Addresses)) {
            if ($openedKeys.Contains($alias)) { $hit = $true }
        }
        if ($box.UserPrincipalName -and $openedKeys.Contains($box.UserPrincipalName)) { $hit = $true }
        if ($hit) {
            foreach ($alias in (ConvertTo-ItemArray $box.Addresses)) { Add-AddressToSet $openedKeys $alias }
            Add-AddressToSet $openedKeys $box.UserPrincipalName
            Add-AddressToSet $openedKeys $box.PrimarySmtp
            Add-AddressToSet $openedKeys $box.Requested
        }
    }

    $noOpen = New-Object System.Collections.Generic.List[object]
    if ($Report.AuditStatus) {
        $roster = Get-RecipientRoster -Report $Report
        foreach ($person in $roster) {
            if ($person.ReceivedAs -eq 'Reply') { continue }
            $seenOpen = $false
            foreach ($id in @( $person.Identities )) {
                if ($openedKeys.Contains($id)) { $seenOpen = $true; break }
            }
            if ($seenOpen) { continue }
            $reason = 'No MailItemsAccessed bind event matched this message for this mailbox.'
            switch ($Report.AuditStatus) {
                'Skipped' { $reason = 'Open audit was not run.' }
                'Failed' { $reason = "Open audit failed. $($Report.AuditError)" }
                'Cancelled' { $reason = 'Open audit was cancelled before this mailbox could be confirmed.' }
                default {
                    $reason = 'No MailItemsAccessed bind event matched this message. Sync clients, auditing gaps, and licenses without Audit Premium can omit opens. This is not proof the message was unread.'
                    if ($Report.AuditAllUsers -eq $false) {
                        $reason += ' The search was limited to recipient accounts, so a delegate open is not included.'
                    }
                    if ($person.LookupError) { $reason += ' Mailbox UPN lookup failed, so an open under a different alias may have been missed.' }
                }
            }
            $noOpen.Add([pscustomobject]@{
                Recipient           = $person.Address
                UserPrincipalName   = $person.UserPrincipalName
                ReceivedAs          = $person.ReceivedAs
                Reason              = $reason.Trim()
            })
        }
    }
    $Report.NoOpen = ConvertTo-ItemArray $noOpen.ToArray()

    $timeline = New-Object System.Collections.Generic.List[object]
    foreach ($row in (ConvertTo-ItemArray $Report.RelatedTrace)) {
        if ($row.Category -eq 'Excluded') { continue }
        $eventType = $row.Category
        $detail = $row.Subject
        if ($row.Chain -and $row.Category -in @('Forward', 'Redirect')) { $detail = $row.Chain }
        $timeline.Add([pscustomobject]@{
            Time       = $row.Received
            TimeUtc    = $row.ReceivedUtc
            EventType  = $eventType
            Actor      = $row.SenderAddress
            Target     = $row.RecipientAddress
            Detail     = $detail
            External   = $row.External
        })
    }
    foreach ($row in (ConvertTo-ItemArray $Report.Opened)) {
        $timeline.Add([pscustomobject]@{
            Time       = $row.Time
            TimeUtc    = $row.TimeUtc
            EventType  = 'Opened'
            Actor      = $row.OpenedBy
            Target     = $row.MailboxOwner
            Detail     = ('{0} {1} {2}' -f $row.AccessType, $row.Folder, $row.Client).Trim()
            External   = 'No'
        })
    }
    $timelineRows = @($timeline | Sort-Object TimeUtc, EventType)
    $Report.Timeline = ConvertTo-ItemArray $timelineRows

    $failed = 0
    foreach ($row in (ConvertTo-ItemArray $Report.RelatedTrace)) {
        if ($row.Status -match 'Fail|Quarantine|Spam|Reject') { $failed++ }
    }
    $originalIds = Get-UniqueFieldValues -Rows $Report.Original -PropertyName 'MessageId'

    $findings = New-Object System.Collections.Generic.List[object]
    function Add-Finding([string]$Severity, [string]$Code, [string]$Message) {
        $findings.Add([pscustomobject]@{ Severity = $Severity; Code = $Code; Message = $Message })
    }
    if ($Report.Cancelled) {
        Add-Finding 'Medium' 'Cancelled' 'The investigation was cancelled. Rows collected before the stop are included.'
    }
    if (@($originalRecipients).Count -eq 0) {
        Add-Finding 'High' 'NoOriginalMatch' 'No trace row matched the original sender and subject. Check the sender address, aliases, message ID, and date range.'
    }
    if ($originalExternal.Count -gt 0) {
        Add-Finding 'High' 'ExternalOriginal' ("{0} external address(es) received the original message: {1}" -f $originalExternal.Count, ($originalExternal -join '; '))
    }
    if ($propagationExternal.Count -gt 0) {
        Add-Finding 'High' 'ExternalForward' ("{0} external address(es) received a forward or same-subject redirect: {1}" -f $propagationExternal.Count, ($propagationExternal -join '; '))
    }
    if ($originalExternal.Count -eq 0 -and $propagationExternal.Count -eq 0 -and @($originalRecipients).Count -gt 0) {
        Add-Finding 'Info' 'NoExternalExposure' 'Message trace did not show an external original recipient or an external forward/redirect recipient.'
    }
    if (@($Report.Forwarders).Count -gt 0) {
        Add-Finding 'Medium' 'Forwarders' ("{0} mailbox(es) forwarded or redirected the message." -f @($Report.Forwarders).Count)
    }
    if (@($Report.Redirects).Count -gt 0) {
        Add-Finding 'Medium' 'Redirects' ("{0} same-subject redirect or resend row(s) were found. Inbox redirect rules often keep the original subject." -f @($Report.Redirects).Count)
    }
    if ($autoExternal -gt 0) {
        Add-Finding 'High' 'ExternalAutoForward' ("{0} enabled mailbox forward or inbox rule points at an external address. This is a standing path and may or may not have carried this message." -f $autoExternal)
    }
    $lookupFailures = 0
    foreach ($row in (ConvertTo-ItemArray $Report.AutoForwarding)) {
        if ($row.Type -eq 'LookupFailed') { $lookupFailures++ }
    }
    if ($lookupFailures -gt 0) {
        Add-Finding 'Medium' 'MailboxLookupFailed' ("Mailbox settings could not be read for {0} recipient(s). Their forwarding rules were not checked." -f $lookupFailures)
    }
    if ($Report.Options -and $Report.Options.CheckAutoForwarding -eq $false) {
        Add-Finding 'Info' 'AutoForwardNotChecked' 'Inbox rules and mailbox forwarding were not checked.'
    }
    if ($failed -gt 0) {
        Add-Finding 'Medium' 'QuarantineOrFail' ("{0} related trace row(s) have a failed, quarantined, spam, or rejected status." -f $failed)
    }
    if ($Report.SubjectMismatchCount -gt 0) {
        Add-Finding 'Info' 'MessageIdSubjectMismatch' ("{0} original row(s) matched the message ID with a different subject. A gateway may have rewritten it." -f $Report.SubjectMismatchCount)
    }
    if (@($originalIds).Count -gt 1) {
        Add-Finding 'Info' 'MultipleOriginalMessages' ("The original sender delivered {0} distinct message IDs with this subject in the window." -f @($originalIds).Count)
    }
    if ($Report.LooseSubjectMatch) {
        Add-Finding 'Info' 'LooseSubject' 'Loose subject matching is on, so related subjects that only contain the search text are included.'
    }
    if ($Report.SearchedSubject -and $Report.SearchedSubject.Length -lt 12) {
        Add-Finding 'Medium' 'ShortSubject' 'The searched subject is very short. Trace results can include unrelated mail that happens to contain it.'
    }
    if (@($Report.Excluded).Count -gt 0) {
        Add-Finding 'Info' 'ExcludedSubjects' ("{0} trace row(s) contained the subject text but did not match after prefix removal. They are in the excluded view." -f @($Report.Excluded).Count)
    }
    if ($Report.Capped) {
        Add-Finding 'High' 'ResultCap' 'A result cap was reached. This report is incomplete.'
    }
    if ($Report.AuditStatus -eq 'Skipped') {
        Add-Finding 'Info' 'AuditSkipped' 'MailItemsAccessed audit was not run, so opens are unknown.'
    }
    elseif ($Report.AuditStatus -eq 'Failed') {
        Add-Finding 'High' 'AuditFailed' ("The open audit failed. {0}" -f $Report.AuditError)
    }
    elseif ($Report.AuditStatus -eq 'Completed') {
        if ($Report.AuditThrottled) {
            Add-Finding 'High' 'AuditThrottled' 'The audit service throttled MailItemsAccessed results. Some opens can be missing. Narrow the date range or the user list and run again.'
        }
        if ($Report.AuditIngestionEnabled -eq $false) {
            Add-Finding 'High' 'AuditIngestionDisabled' 'Unified audit log ingestion is disabled for this organization. Open events will be missing.'
        }
        if (-not $Report.AuditAllUsers) {
            Add-Finding 'Info' 'DelegateSearchLimited' 'Open search was limited to recipient accounts plus any extra UPNs you added. Delegate opens by other people require those UPNs or Audit all users.'
        }
        if ($delegateOpens -gt 0) {
            Add-Finding 'High' 'DelegateOpen' ("{0} open event(s) were performed by someone other than the mailbox owner." -f $delegateOpens)
        }
        if (@($Report.NoOpen).Count -gt 0) {
            Add-Finding 'Medium' 'NoOpenEvents' ("{0} internal recipient mailbox(es) have no matching open event. That is not proof the message was unread." -f @($Report.NoOpen).Count)
        }
    }
    foreach ($row in (ConvertTo-ItemArray $Report.Policy)) {
        if ($row.Kind -eq 'RemoteDomain' -and $row.Enabled -eq 'Yes' -and $row.External -eq 'Yes') {
            Add-Finding 'Medium' 'PolicyAutoForward' ("Remote domain '{0}' allows automatic forwarding. {1}" -f $row.Name, $row.Detail)
        }
        if ($row.Kind -eq 'TransportRule' -and $row.External -eq 'Yes') {
            Add-Finding 'High' 'TransportRuleExternal' ("Transport rule '{0}' copies or redirects mail externally. {1}" -f $row.Name, $row.Detail)
        }
        if ($row.Kind -eq 'OutboundSpamPolicy' -and $row.Detail -match 'AutoForwardingMode=Off') {
            Add-Finding 'Info' 'OutboundAutoForwardOff' ("Outbound spam policy '{0}' blocks automatic external forwarding. A configured forward may not have left the tenant." -f $row.Name)
        }
    }

    $ranked = @($findings | Sort-Object @{ Expression = {
        switch ($_.Severity) { 'High' { 0 } 'Medium' { 1 } default { 2 } }
    } }, Code, Message)
    $Report.Findings = ConvertTo-ItemArray $ranked
    $Report.Summary = [pscustomobject]@{
        TraceRows              = (@(ConvertTo-ItemArray $Report.RelatedTrace).Count + @(ConvertTo-ItemArray $Report.Excluded).Count)
        RelatedRows            = @($Report.RelatedTrace).Count
        ExcludedRows           = @($Report.Excluded).Count
        OriginalRecipients     = @($originalRecipients).Count
        OriginalExternal       = $originalExternal.Count
        PropagationRecipients  = @($propagationRecipients).Count
        PropagationExternal    = $propagationExternal.Count
        Forwarders             = @($Report.Forwarders).Count
        RedirectEvents         = @($Report.Redirects).Count
        Replies                = @($Report.Replies).Count
        AutoReplies            = @($Report.AutoReplies).Count
        Ndrs                   = @($Report.Ndrs).Count
        AutoForwardRules       = @($Report.AutoForwarding).Count
        AutoForwardExternal    = $autoExternal
        OpenEvents             = @($Report.Opened).Count
        OpenedMailboxes        = @($openedMailboxes).Count
        DelegateOpens          = $delegateOpens
        NoOpenRecipients       = @($Report.NoOpen).Count
        ExternalOriginalList   = ($originalExternal -join '; ')
        ExternalForwardList    = ($propagationExternal -join '; ')
    }
}

function Format-InvestigationSummaryText {
    param($Report)
    $s = $Report.Summary
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('Leaked email investigation')
    $lines.Add('Subject: ' + $Report.Subject)
    $lines.Add('Searched subject: ' + $Report.SearchedSubject)
    $lines.Add('Original sender: ' + $Report.OriginalSender)
    if ($Report.MessageId) { $lines.Add('Message ID: ' + $Report.MessageId) }
    $lines.Add(('Window: {0:yyyy-MM-dd HH:mm:ss} -> {1:yyyy-MM-dd HH:mm:ss}' -f $Report.StartDate, $Report.EndDate))
    if ($Report.OutputFolder) { $lines.Add('Output: ' + $Report.OutputFolder) }
    $lines.Add('')
    $lines.Add(("A. Original recipients: {0} (external: {1})" -f $s.OriginalRecipients, $s.OriginalExternal))
    if ($s.ExternalOriginalList) { $lines.Add('   External original: ' + $s.ExternalOriginalList) }
    $lines.Add(("B. Forward and redirect recipients: {0} (external: {1})" -f $s.PropagationRecipients, $s.PropagationExternal))
    if ($s.ExternalForwardList) { $lines.Add('   External forwards: ' + $s.ExternalForwardList) }
    $lines.Add(("C. Forwarders: {0}" -f $s.Forwarders))
    $lines.Add(("   Redirect or resend rows: {0}" -f $s.RedirectEvents))
    $lines.Add(("   Auto-forward rows: {0} (external targets: {1})" -f $s.AutoForwardRules, $s.AutoForwardExternal))
    $lines.Add(("D. Open events: {0} across {1} mailbox(es)" -f $s.OpenEvents, $s.OpenedMailboxes))
    $lines.Add(("   Delegate opens: {0}" -f $s.DelegateOpens))
    $lines.Add(("   Internal recipients with no open event: {0}" -f $s.NoOpenRecipients))
    $lines.Add(("Replies: {0}; automatic replies: {1}; NDRs: {2}; excluded subjects: {3}" -f $s.Replies, $s.AutoReplies, $s.Ndrs, $s.ExcludedRows))
    $lines.Add('')
    $lines.Add('Findings:')
    $findingRows = ConvertTo-ItemArray $Report.Findings
    if ($findingRows.Count -eq 0) { $lines.Add('  None') }
    foreach ($finding in $findingRows) {
        $lines.Add(('  [{0}] {1}' -f $finding.Severity, $finding.Message))
    }
    $warningRows = ConvertTo-ItemArray $Report.Warnings
    if ($warningRows.Count -gt 0) {
        $lines.Add('')
        $lines.Add('Warnings:')
        foreach ($warning in $warningRows) { $lines.Add('  ' + $warning) }
    }
    return ($lines -join [Environment]::NewLine)
}

function New-Column {
    param([string]$Property, [string]$Header)
    if (-not $Header) { $Header = $Property }
    return [pscustomobject]@{ Property = $Property; Header = $Header }
}

function Get-InvestigationViews {
    $flow = @(
        (New-Column 'Received'),
        (New-Column 'Method'),
        (New-Column 'ForwardedBy' 'Forwarded by'),
        (New-Column 'ForwarderGotItVia' 'Forwarder got it via'),
        (New-Column 'Chain'),
        (New-Column 'ForwardedTo' 'Forwarded to'),
        (New-Column 'External'),
        (New-Column 'Status'),
        (New-Column 'Subject'),
        (New-Column 'MessageId' 'Message ID'),
        (New-Column 'TraceEvents' 'Trace events')
    )
    $mail = @(
        (New-Column 'Received'),
        (New-Column 'SenderAddress' 'Sender'),
        (New-Column 'RecipientAddress' 'Recipient'),
        (New-Column 'External'),
        (New-Column 'Status'),
        (New-Column 'Subject'),
        (New-Column 'MessageId' 'Message ID')
    )
    return @(
        [pscustomobject]@{
            Key = 'Findings'; Title = 'Findings'; FileName = 'Findings.csv'; Collection = 'Findings'
            Description = 'Highest severity first. External delivery and external auto-forward are high.'
            Columns = @((New-Column 'Severity'), (New-Column 'Code'), (New-Column 'Message'))
        }
        [pscustomobject]@{
            Key = 'Timeline'; Title = 'Timeline'; FileName = 'Timeline.csv'; Collection = 'Timeline'
            Description = 'Deliveries, forwards, redirects, replies, and opens in time order.'
            Columns = @((New-Column 'Time'), (New-Column 'TimeUtc' 'Time UTC'), (New-Column 'EventType' 'Event'), (New-Column 'Actor'), (New-Column 'Target'), (New-Column 'Detail'), (New-Column 'External'))
        }
        [pscustomobject]@{
            Key = 'Original'; Title = 'Original recipients'; FileName = 'A_OriginalRecipients.csv'; Collection = 'Original'
            Description = 'People and addresses that received the message from the original sender before anyone forwarded it.'
            Columns = @(
                (New-Column 'Received'), (New-Column 'ReceivedUtc' 'Received UTC'), (New-Column 'SenderAddress' 'Sender'),
                (New-Column 'RecipientAddress' 'Recipient'), (New-Column 'External'), (New-Column 'Status'),
                (New-Column 'Subject'), (New-Column 'MessageId' 'Message ID'), (New-Column 'MessageTraceId' 'Trace ID'),
                (New-Column 'FromIP' 'From IP'), (New-Column 'Size'), (New-Column 'TraceEvents' 'Trace events')
            )
        }
        [pscustomobject]@{
            Key = 'Propagation'; Title = 'Forwards and redirects'; FileName = 'B_ForwardRecipients.csv'; Collection = 'Propagation'
            Description = 'FW/WG-style forwards and same-subject redirects or resends. Redirect rules often keep the original subject.'
            Columns = $flow
        }
        [pscustomobject]@{
            Key = 'Redirects'; Title = 'Redirects and resends'; FileName = 'B_RedirectsAndResends.csv'; Collection = 'Redirects'
            Description = 'Same subject, different sender, no forward prefix. Typical of inbox redirect and some resends.'
            Columns = $flow
        }
        [pscustomobject]@{
            Key = 'Forwarders'; Title = 'Forwarders'; FileName = 'C_Forwarders.csv'; Collection = 'Forwarders'
            Description = 'Mailboxes that sent a forward or same-subject redirect, with any external targets.'
            Columns = @(
                (New-Column 'Forwarder'), (New-Column 'Methods'), (New-Column 'EventCount' 'Events'),
                (New-Column 'MessageCount' 'Messages'), (New-Column 'RecipientCount' 'Recipients'),
                (New-Column 'ExternalRecipientCount' 'External recipients'), (New-Column 'ExternalRecipients' 'External addresses'),
                (New-Column 'External'), (New-Column 'FirstForward' 'First'), (New-Column 'LastForward' 'Last')
            )
        }
        [pscustomobject]@{
            Key = 'AutoForwarding'; Title = 'Auto-forwarding'; FileName = 'C_AutoForwarding.csv'; Collection = 'AutoForwarding'
            Description = 'Mailbox forwarding and inbox rules on internal recipients. A rule existing is not proof it fired for this message.'
            Columns = @(
                (New-Column 'Mailbox'), (New-Column 'Type'), (New-Column 'Name'), (New-Column 'Enabled'),
                (New-Column 'Target'), (New-Column 'TargetExternal' 'Target external'),
                (New-Column 'DeliverToMailboxAndForward' 'Keep a copy'), (New-Column 'Detail')
            )
        }
        [pscustomobject]@{
            Key = 'Policy'; Title = 'Tenant policy'; FileName = 'C_TenantPolicy.csv'; Collection = 'Policy'
            Description = 'Transport rules, remote-domain auto-forward settings, and the outbound spam policy.'
            Columns = @((New-Column 'Kind'), (New-Column 'Name'), (New-Column 'Enabled'), (New-Column 'External'), (New-Column 'Detail'))
        }
        [pscustomobject]@{
            Key = 'Replies'; Title = 'Replies'; FileName = 'Replies.csv'; Collection = 'Replies'
            Description = 'Human replies whose subject reduces to the investigated subject.'
            Columns = $mail
        }
        [pscustomobject]@{
            Key = 'AutoReplies'; Title = 'Automatic replies'; FileName = 'AutoReplies.csv'; Collection = 'AutoReplies'
            Description = 'Out-of-office and automatic replies. These are not counted as forwarders.'
            Columns = $mail
        }
        [pscustomobject]@{
            Key = 'Noise'; Title = 'NDRs and journal'; FileName = 'NdrAndJournal.csv'; Collection = 'Noise'
            Description = 'Non-delivery reports and journal wrappers related to the subject.'
            Columns = @((New-Column 'Category'), (New-Column 'Received'), (New-Column 'SenderAddress' 'Sender'), (New-Column 'RecipientAddress' 'Recipient'), (New-Column 'Subject'), (New-Column 'MessageId' 'Message ID'))
        }
        [pscustomobject]@{
            Key = 'Opened'; Title = 'Opened by'; FileName = 'D_OpenedBy.csv'; Collection = 'Opened'
            Description = 'MailItemsAccessed bind events whose Internet message ID matches the original or a forwarded copy.'
            Columns = @(
                (New-Column 'Time'), (New-Column 'TimeUtc' 'Time UTC'), (New-Column 'OpenedBy' 'Opened by'),
                (New-Column 'MailboxOwner' 'Mailbox owner'), (New-Column 'DelegateAccess' 'Delegate'),
                (New-Column 'ReceivedVia' 'Received as'), (New-Column 'AccessType' 'Access'),
                (New-Column 'Folder'), (New-Column 'Client'), (New-Column 'ClientIP' 'Client IP'),
                (New-Column 'InternetMessageId' 'Message ID')
            )
        }
        [pscustomobject]@{
            Key = 'Syncs'; Title = 'Folder syncs'; FileName = 'D_FolderSyncs_PossibleDownload.csv'; Collection = 'Syncs'
            Description = 'Folder syncs for investigated mailboxes. A sync is not proof this message was downloaded.'
            Columns = @((New-Column 'Time'), (New-Column 'User'), (New-Column 'MailboxOwner' 'Mailbox owner'), (New-Column 'Folders'), (New-Column 'Client'), (New-Column 'ClientIP' 'Client IP'), (New-Column 'Note'))
        }
        [pscustomobject]@{
            Key = 'NoOpen'; Title = 'No open event'; FileName = 'D_NoOpenEventFound.csv'; Collection = 'NoOpen'
            Description = 'Internal recipients with no matching bind event. Absence is not proof the message was unread.'
            Columns = @((New-Column 'Recipient'), (New-Column 'UserPrincipalName' 'UPN'), (New-Column 'ReceivedAs' 'Received as'), (New-Column 'Reason'))
        }
        [pscustomobject]@{
            Key = 'Related'; Title = 'Related trace'; FileName = 'RelatedTrace.csv'; Collection = 'RelatedTrace'
            Description = 'Every classified trace row except subject hits that were excluded.'
            Columns = @(
                (New-Column 'Category'), (New-Column 'Received'), (New-Column 'ReceivedUtc' 'Received UTC'),
                (New-Column 'SenderAddress' 'Sender'), (New-Column 'RecipientAddress' 'Recipient'),
                (New-Column 'External'), (New-Column 'Status'), (New-Column 'Subject'),
                (New-Column 'MessageId' 'Message ID'), (New-Column 'MessageTraceId' 'Trace ID'),
                (New-Column 'TraceEvents' 'Trace events')
            )
        }
        [pscustomobject]@{
            Key = 'Excluded'; Title = 'Excluded subjects'; FileName = 'ExcludedSubjects.csv'; Collection = 'Excluded'
            Description = 'Trace hits whose subject contains the search text but is a different message after prefixes are removed.'
            Columns = @((New-Column 'Received'), (New-Column 'SenderAddress' 'Sender'), (New-Column 'RecipientAddress' 'Recipient'), (New-Column 'Subject'), (New-Column 'NormalizedSubject' 'Normalized subject'), (New-Column 'Reason'))
        }
    )
}

function Export-ObjectCsv {
    param(
        [object[]]$Rows,
        [string]$Path,
        [object[]]$Columns
    )
    $items = ConvertTo-ItemArray $Rows
    $headers = @()
    foreach ($column in $Columns) { $headers += $column.Header }
    if ($items.Count -eq 0) {
        $headerLine = ($headers | ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }) -join ','
        $encoding = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($Path, $headerLine + "`r`n", $encoding)
        return
    }
    $export = foreach ($row in $items) {
        $obj = New-Object PSObject
        foreach ($column in $Columns) {
            $value = ConvertTo-FieldText -Name $column.Property -Value (Get-ObjectProperty $row $column.Property)
            $obj | Add-Member -NotePropertyName $column.Header -NotePropertyValue $value
        }
        $obj
    }
    $export | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

function Export-InvestigationReport {
    param($Report)
    if ([string]::IsNullOrWhiteSpace($Report.OutputFolder)) {
        throw 'OutputFolder is required to export the report.'
    }
    New-Item -ItemType Directory -Path $Report.OutputFolder -Force | Out-Null
    foreach ($view in (Get-InvestigationViews)) {
        $rows = Get-ObjectProperty $Report $view.Collection
        $path = Join-Path $Report.OutputFolder $view.FileName
        Export-ObjectCsv -Rows $rows -Path $path -Columns $view.Columns
    }
    $summaryPath = Join-Path $Report.OutputFolder 'Summary.txt'
    $encoding = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($summaryPath, (Format-InvestigationSummaryText -Report $Report), $encoding)
    return $Report.OutputFolder
}

function ConvertTo-AuditPayload {
    param($Record)
    $raw = Get-ObjectProperty $Record 'AuditData'
    if ($null -eq $raw) { return $null }
    if ($raw -is [string]) {
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        try { return ($raw | ConvertFrom-Json) }
        catch { return $null }
    }
    return $raw
}

function Get-OperationPropertyValue {
    param($Data, [string]$Name)
    foreach ($property in (ConvertTo-ItemArray (Get-ObjectProperty $Data 'OperationProperties'))) {
        $propertyName = [string](Get-ObjectProperty $property 'Name')
        if ($propertyName -eq $Name) { return Get-ObjectProperty $property 'Value' }
    }
    return $null
}

function ConvertTo-AuditAccess {
    param($Record)
    $data = ConvertTo-AuditPayload $Record
    if ($null -eq $data) { return $null }
    $timeRaw = Get-ObjectProperty $Record 'CreationDate'
    if ($null -eq $timeRaw) { $timeRaw = Get-ObjectProperty $data 'CreationTime' }
    $timeUtc = [datetime]::SpecifyKind([datetime]'1970-01-01Z', [DateTimeKind]::Utc)
    if ($timeRaw -is [datetime]) { $timeUtc = ConvertTo-UtcFromApi -Value $timeRaw }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$timeRaw)) {
        try { $timeUtc = ConvertTo-UtcFromApi -Value ([datetime]$timeRaw) } catch { }
    }
    $folders = New-Object System.Collections.Generic.List[object]
    foreach ($folder in (ConvertTo-ItemArray (Get-ObjectProperty $data 'Folders'))) {
        $ids = New-Object System.Collections.Generic.List[string]
        foreach ($item in (ConvertTo-ItemArray (Get-ObjectProperty $folder 'FolderItems'))) {
            $id = [string](Get-ObjectProperty $item 'InternetMessageId')
            if ($id) { $ids.Add($id) }
        }
        $folders.Add([pscustomobject]@{
            Path       = [string](Get-ObjectProperty $folder 'Path')
            MessageIds = $ids.ToArray()
        })
    }
    $throttled = [string](Get-OperationPropertyValue -Data $data -Name 'IsThrottled')
    return [pscustomobject]@{
        Time            = (ConvertTo-LocalFromUtc -Value $timeUtc)
        TimeUtc         = $timeUtc
        UserId          = [string](Get-ObjectProperty $data 'UserId')
        MailboxOwnerUpn = [string](Get-ObjectProperty $data 'MailboxOwnerUPN')
        AccessType      = [string](Get-OperationPropertyValue -Data $data -Name 'MailAccessType')
        Client          = [string](Get-ObjectProperty $data 'ClientInfoString')
        ClientIP        = [string](Get-ObjectProperty $data 'ClientIPAddress')
        Throttled       = ($throttled -eq 'True' -or $throttled -eq 'true')
        Folders         = $folders.ToArray()
    }
}

function Get-OpenEventsFromAudit {
    param(
        [object[]]$Records,
        [hashtable]$TargetIds,
        $Report
    )
    $opened = New-Object System.Collections.Generic.List[object]
    $syncs = New-Object System.Collections.Generic.List[object]
    $throttled = $false
    $parseErrors = 0
    $index = @{}
    foreach ($row in (ConvertTo-ItemArray $Report.Original)) {
        if ($row.RecipientAddress) { $index[$row.RecipientAddress.ToLowerInvariant()] = 'Original' }
    }
    foreach ($row in (ConvertTo-ItemArray $Report.Propagation)) {
        if (-not $row.RecipientAddress) { continue }
        $key = $row.RecipientAddress.ToLowerInvariant()
        if (-not $index.ContainsKey($key)) { $index[$key] = $row.Method }
    }
    foreach ($box in (ConvertTo-ItemArray $Report.Mailboxes)) {
        $role = $null
        foreach ($alias in (ConvertTo-ItemArray $box.Addresses)) {
            $aliasKey = $alias.ToLowerInvariant()
            if ($index.ContainsKey($aliasKey)) { $role = $index[$aliasKey]; break }
        }
        if (-not $role) { continue }
        foreach ($alias in (ConvertTo-ItemArray $box.Addresses)) { $index[$alias.ToLowerInvariant()] = $role }
        if ($box.UserPrincipalName) { $index[$box.UserPrincipalName.ToLowerInvariant()] = $role }
    }

    $syncCap = 20000
    foreach ($record in (ConvertTo-ItemArray $Records)) {
        $access = ConvertTo-AuditAccess $record
        if ($null -eq $access) { $parseErrors++; continue }
        if ($access.Throttled) { $throttled = $true }
        $ownerKey = ''
        if ($access.MailboxOwnerUpn) { $ownerKey = $access.MailboxOwnerUpn.ToLowerInvariant() }
        $knownMailbox = $ownerKey -and $index.ContainsKey($ownerKey)
        if ($access.AccessType -eq 'Sync') {
            if ($knownMailbox -and $syncs.Count -lt $syncCap) {
                $paths = New-Object System.Collections.Generic.List[string]
                foreach ($folder in (ConvertTo-ItemArray $access.Folders)) {
                    if ($folder.Path) { $paths.Add($folder.Path) }
                }
                $syncs.Add([pscustomobject]@{
                    Time          = $access.Time
                    TimeUtc       = $access.TimeUtc
                    User          = $access.UserId
                    MailboxOwner  = $access.MailboxOwnerUpn
                    Folders       = ($paths -join '; ')
                    Client        = $access.Client
                    ClientIP      = $access.ClientIP
                    Note          = 'Folder sync is not proof that this message was downloaded.'
                })
            }
            continue
        }
        foreach ($folder in (ConvertTo-ItemArray $access.Folders)) {
            foreach ($messageId in (ConvertTo-ItemArray $folder.MessageIds)) {
                $normalized = Get-NormalizedId $messageId
                if (-not $normalized) { continue }
                if (-not $TargetIds.ContainsKey($normalized)) { continue }
                $delegate = 'Unknown'
                if ($access.UserId -and $access.MailboxOwnerUpn) {
                    if ([string]::Equals($access.UserId, $access.MailboxOwnerUpn, [System.StringComparison]::OrdinalIgnoreCase)) { $delegate = 'No' }
                    else { $delegate = 'Yes' }
                }
                $via = 'Other mailbox'
                if ($ownerKey -and $index.ContainsKey($ownerKey)) {
                    $role = $index[$ownerKey]
                    if ($role -eq 'Original') { $via = 'Original' }
                    elseif ($role -eq 'Redirect') { $via = 'Redirect' }
                    else { $via = 'Forward' }
                }
                $opened.Add([pscustomobject]@{
                    Time              = $access.Time
                    TimeUtc           = $access.TimeUtc
                    OpenedBy          = $access.UserId
                    MailboxOwner      = $access.MailboxOwnerUpn
                    DelegateAccess    = $delegate
                    ReceivedVia       = $via
                    AccessType        = $(if ($access.AccessType) { $access.AccessType } else { 'Bind' })
                    Folder            = [string]$folder.Path
                    Client            = $access.Client
                    ClientIP          = $access.ClientIP
                    InternetMessageId = [string]$messageId
                })
            }
        }
    }
    $openedRows = @($opened.ToArray() | Sort-Object TimeUtc, OpenedBy)
    $syncRows = @($syncs.ToArray() | Sort-Object TimeUtc, User)
    return [pscustomobject]@{
        Opened      = (ConvertTo-ItemArray $openedRows)
        Syncs       = (ConvertTo-ItemArray $syncRows)
        Throttled   = $throttled
        ParseErrors = $parseErrors
        SyncCapped  = ($syncs.Count -ge $syncCap)
    }
}

function Get-TargetMessageIds {
    param($Report)
    $ids = @{}
    foreach ($row in (ConvertTo-ItemArray $Report.Original) + (ConvertTo-ItemArray $Report.Propagation)) {
        $id = Get-NormalizedId $row.MessageId
        if ($id) { $ids[$id] = $true }
    }
    return $ids
}

function Get-TenantPolicyRows {
    param($Dependencies, [string[]]$InternalDomains)
    $rows = New-Object System.Collections.Generic.List[object]
    $readTransportRules = Get-ObjectProperty $Dependencies 'GetTransportRules'
    if ($readTransportRules) {
        try {
            foreach ($rule in (ConvertTo-ItemArray (& $readTransportRules))) {
                $state = [string](Get-ObjectProperty $rule 'State')
                if ($state -and $state -ne 'Enabled') { continue }
                $details = New-Object System.Collections.Generic.List[string]
                foreach ($name in @('RedirectMessageTo', 'BlindCopyTo', 'AddToRecipients', 'CopyTo')) {
                    $value = Get-ObjectProperty $rule $name
                    $text = (@(ConvertTo-ItemArray $value | ForEach-Object { [string]$_ })) -join '; '
                    if ($text) { $details.Add("$name=$text") }
                }
                if ($details.Count -eq 0) { continue }
                $detail = $details -join ' | '
                $external = 'No'
                foreach ($token in ($detail -split '[;\s|]+')) {
                    $smtp = Get-SmtpFromForwardingValue $token
                    if ($smtp -match '@' -and -not (Test-InternalAddress -Address $smtp -InternalDomains $InternalDomains)) {
                        $external = 'Yes'
                    }
                }
                $rows.Add([pscustomobject]@{
                    Kind = 'TransportRule'; Name = [string](Get-ObjectProperty $rule 'Name'); Enabled = 'Yes'; External = $external; Detail = $detail
                })
            }
        }
        catch {
            Write-InvLog -Level 'WARN' -Message ("Transport rules were not read: {0}" -f $_.Exception.Message)
        }
    }
    $readRemoteDomains = Get-ObjectProperty $Dependencies 'GetRemoteDomains'
    if ($readRemoteDomains) {
        try {
            foreach ($remote in (ConvertTo-ItemArray (& $readRemoteDomains))) {
                $name = [string](Get-ObjectProperty $remote 'DomainName')
                $auto = Get-ObjectProperty $remote 'AutoForwardEnabled'
                $enabled = $(if ($auto) { 'Yes' } else { 'No' })
                $external = 'No'
                if ($name -eq '*' -or ($name -match '@' -and -not (Test-InternalAddress "user@$name" $InternalDomains)) -or ($name -and $name -ne '*' -and -not (Test-InternalAddress "user@$name" $InternalDomains))) {
                    if ($auto) { $external = 'Yes' }
                }
                $rows.Add([pscustomobject]@{
                    Kind = 'RemoteDomain'; Name = $name; Enabled = $enabled; External = $external
                    Detail = ("AutoForwardEnabled={0}" -f $enabled)
                })
            }
        }
        catch {
            Write-InvLog -Level 'WARN' -Message ("Remote domains were not read: {0}" -f $_.Exception.Message)
        }
    }
    $readOutboundPolicy = Get-ObjectProperty $Dependencies 'GetOutboundPolicy'
    if ($readOutboundPolicy) {
        try {
            foreach ($policy in (ConvertTo-ItemArray (& $readOutboundPolicy))) {
                $mode = [string](Get-ObjectProperty $policy 'AutoForwardingMode')
                $rows.Add([pscustomobject]@{
                    Kind = 'OutboundSpamPolicy'
                    Name = [string](Get-ObjectProperty $policy 'Name')
                    Enabled = $(if ($mode -eq 'Off') { 'No' } else { 'Yes' })
                    External = $(if ($mode -eq 'Off') { 'No' } else { 'Yes' })
                    Detail = ("AutoForwardingMode={0}" -f $mode)
                })
            }
        }
        catch {
            Write-InvLog -Level 'WARN' -Message ("Outbound spam policy was not read: {0}" -f $_.Exception.Message)
        }
    }
    $policyRows = ConvertTo-ItemArray $rows.ToArray()
    Write-Output -NoEnumerate -InputObject $policyRows
}

function Get-InvestigationRemoteCommandNames {
    # These are remote Exchange commands. They appear in the temporary session
    # module after Connect-ExchangeOnline, not when the gallery module is imported.
    return @(
        'Get-MessageTraceV2'
        'Get-MessageTraceDetailV2'
        'Get-AcceptedDomain'
        'Get-InboxRule'
        'Get-TransportRule'
        'Get-RemoteDomain'
        'Get-HostedOutboundSpamFilterPolicy'
        'Get-AdminAuditLogConfig'
        'Search-UnifiedAuditLog'
    )
}

function Assert-InvestigationModule {
    $modules = @(Get-Module -ListAvailable -Name ExchangeOnlineManagement | Sort-Object Version -Descending)
    if ($modules.Count -eq 0) {
        throw 'ExchangeOnlineManagement is not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }
    $best = $modules[0]
    if ([version]$best.Version -lt [version]'3.7.0') {
        throw "ExchangeOnlineManagement $($best.Version) is installed. Get-MessageTraceV2 requires 3.7.0 or newer. Run: Update-Module ExchangeOnlineManagement -Force"
    }
    $stale = @(Get-Module -Name ExchangeOnlineManagement | Where-Object { [version]$_.Version -lt [version]'3.7.0' })
    if ($stale.Count -gt 0) {
        Remove-Module -Name ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue
    }
    $current = @(Get-Module -Name ExchangeOnlineManagement | Where-Object { [version]$_.Version -ge [version]'3.7.0' })
    if ($current.Count -eq 0) {
        Import-Module ExchangeOnlineManagement -RequiredVersion $best.Version -ErrorAction Stop
    }
    return $best.Version
}

function Connect-ExchangeOnlineForInvestigation {
    param(
        [string]$UserPrincipalName,
        [string[]]$CommandName
    )
    # -ShowBanner:$false must be passed directly. Splatting a switch as $false
    # still turns the switch on.
    $names = @($CommandName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($names.Count -gt 0) {
        if ($UserPrincipalName) {
            Connect-ExchangeOnline -ShowBanner:$false -ShowProgress:$false -SkipLoadingFormatData -UserPrincipalName $UserPrincipalName -CommandName $names
        }
        else {
            Connect-ExchangeOnline -ShowBanner:$false -ShowProgress:$false -SkipLoadingFormatData -CommandName $names
        }
        return
    }
    if ($UserPrincipalName) {
        Connect-ExchangeOnline -ShowBanner:$false -ShowProgress:$false -UserPrincipalName $UserPrincipalName
    }
    else {
        Connect-ExchangeOnline -ShowBanner:$false -ShowProgress:$false
    }
}

function Get-InvestigationConnectionStatus {
    $command = Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue
    if (-not $command) { return $null }
    $infos = @(Get-ConnectionInformation -ErrorAction SilentlyContinue)
    foreach ($info in $infos) {
        $state = [string](Get-ObjectProperty $info 'State')
        $token = [string](Get-ObjectProperty $info 'TokenStatus')
        if ($state -eq 'Connected' -or $token -eq 'Active') { return $info }
    }
    return $null
}

function Connect-InvestigationService {
    param([string]$UserPrincipalName)
    $version = Assert-InvestigationModule
    $existing = Get-InvestigationConnectionStatus
    if (-not $existing) {
        Connect-ExchangeOnlineForInvestigation -UserPrincipalName $UserPrincipalName
        $existing = Get-InvestigationConnectionStatus
    }
    if (-not (Get-Command Get-MessageTraceV2 -ErrorAction SilentlyContinue)) {
        # A normal REST session does not always import this remote command.
        # Ask for it explicitly. That signs the user in again.
        Disconnect-InvestigationService
        Connect-ExchangeOnlineForInvestigation -UserPrincipalName $UserPrincipalName -CommandName (Get-InvestigationRemoteCommandNames)
        $existing = Get-InvestigationConnectionStatus
    }
    if (-not (Get-Command Get-MessageTraceV2 -ErrorAction SilentlyContinue)) {
        throw "Signed in with ExchangeOnlineManagement $version, but Exchange Online did not load Get-MessageTraceV2. That command is created by Connect-ExchangeOnline, not by Import-Module. Run: Update-Module ExchangeOnlineManagement -Force. Then connect with an account that can run message trace."
    }
    $user = ''
    $organization = ''
    if ($existing) {
        $user = [string](Get-ObjectProperty $existing 'UserPrincipalName')
        $organization = [string](Get-ObjectProperty $existing 'Organization')
        if (-not $organization) { $organization = [string](Get-ObjectProperty $existing 'Name') }
    }
    return [pscustomobject]@{
        Connected    = ($null -ne $existing)
        Version      = [string]$version
        User         = $user
        Organization = $organization
    }
}

function Disconnect-InvestigationService {
    $command = Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue
    if ($command) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
}

function New-DefaultInvestigationDependencies {
    return [pscustomobject]@{
        GetAcceptedDomains = {
            @(Get-AcceptedDomain -ErrorAction Stop | ForEach-Object { [string]$_.DomainName })
        }
        FetchTracePage = {
            param($Query)
            $params = @{
                StartDate         = $Query.WindowStart
                EndDate           = $Query.PageEnd
                Subject           = $Query.Subject
                SubjectFilterType = 'Contains'
                ResultSize        = $Query.PageSize
            }
            if ($Query.StartingRecipient) { $params.StartingRecipientAddress = $Query.StartingRecipient }
            @(Get-MessageTraceV2 @params)
        }
        FetchTraceDetail = {
            param($Query)
            $details = @(Get-MessageTraceDetailV2 -MessageTraceId $Query.MessageTraceId -RecipientAddress $Query.RecipientAddress -ErrorAction Stop)
            foreach ($detail in $details) {
                $eventName = [string](Get-ObjectProperty $detail 'Event')
                if (-not $eventName) { $eventName = [string](Get-ObjectProperty $detail 'EventType') }
                if ($eventName) { $eventName }
            }
        }
        GetMailbox = {
            param($Identity)
            Get-EXOMailbox -Identity $Identity -Properties ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward, EmailAddresses -ErrorAction Stop
        }
        GetInboxRules = {
            param($Identity)
            $command = Get-Command Get-InboxRule -ErrorAction Stop
            if ($command.Parameters.ContainsKey('IncludeHidden')) {
                @(Get-InboxRule -Mailbox $Identity -IncludeHidden -ErrorAction Stop)
            }
            else {
                @(Get-InboxRule -Mailbox $Identity -ErrorAction Stop)
            }
        }
        SearchAudit = {
            param($Query)
            $params = @{
                StartDate      = $Query.Start
                EndDate        = $Query.End
                Operations     = $Query.Operations
                SessionId      = $Query.SessionId
                SessionCommand = 'ReturnLargeSet'
                ResultSize     = $Query.ResultSize
            }
            if ($Query.UserIds) { $params.UserIds = @($Query.UserIds) }
            $command = Get-Command Search-UnifiedAuditLog -ErrorAction Stop
            if ($Query.HighCompleteness -and $command.Parameters.ContainsKey('HighCompleteness')) {
                $params.HighCompleteness = $true
            }
            try {
                @(Search-UnifiedAuditLog @params)
            }
            catch {
                if ($params.ContainsKey('HighCompleteness')) {
                    $null = $params.Remove('HighCompleteness')
                    Write-InvLog -Level 'WARN' -Message 'High-completeness audit search was rejected. Retrying without it.'
                    @(Search-UnifiedAuditLog @params)
                }
                else { throw }
            }
        }
        GetTransportRules = { @(Get-TransportRule -ErrorAction Stop) }
        GetRemoteDomains = { @(Get-RemoteDomain -ErrorAction Stop) }
        GetOutboundPolicy = { @(Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop) }
        GetAdminAuditLogConfig = { Get-AdminAuditLogConfig -ErrorAction Stop }
    }
}

function Get-DefaultOutputFolder {
    $root = [Environment]::GetFolderPath('MyDocuments')
    if ([string]::IsNullOrWhiteSpace($root)) { $root = (Get-Location).Path }
    return (Join-Path $root ('EmailInvestigation_' + (Get-Date -Format 'yyyyMMdd_HHmmss')))
}

function Invoke-LeakedEmailInvestigation {
    <#
    .SYNOPSIS
      Runs the leaked-email investigation and writes the report folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Subject,
        [Parameter(Mandatory = $true)][string]$OriginalSender,
        [datetime]$StartDate = (Get-Date).AddDays(-7),
        [datetime]$EndDate = (Get-Date),
        [string]$OutputFolder,
        [string]$MessageId,
        [string[]]$InternalDomains,
        [string[]]$AdditionalAuditUsers,
        [string]$SignInUpn,
        [bool]$CheckAutoForwarding = $false,
        [bool]$IncludeDisabledRules = $false,
        [bool]$CheckTransportPolicy = $false,
        [bool]$AuditAllUsers = $false,
        [bool]$SkipOpenAudit = $false,
        [bool]$FastAudit = $false,
        [bool]$IncludeTraceDetail = $false,
        [bool]$ResolveSenderAliases = $true,
        [bool]$AuditThroughNow = $true,
        [bool]$LooseSubjectMatch = $false,
        [bool]$SkipConnectionCheck = $false,
        [int]$TracePageSize = 5000,
        [int]$AuditPageSize = 5000,
        [int]$AuditBatchSize = 50,
        [int]$MaxTraceRows = 200000,
        [int]$MaxAuditRecords = 100000,
        [int]$MaxDetailRows = 300,
        $Dependencies,
        [scriptblock]$ProgressHandler,
        [scriptblock]$LogHandler,
        [scriptblock]$CancelHandler
    )

    $previous = $script:InvCtx
    $script:InvCtx = [pscustomobject]@{
        Log       = $LogHandler
        Progress  = $ProgressHandler
        Cancel    = $CancelHandler
        Warnings  = (New-Object System.Collections.Generic.List[string])
    }
    try {
        if (-not (Test-SmtpAddress $OriginalSender)) {
            throw "Original sender '$OriginalSender' is not an email address."
        }
        $range = Resolve-InvestigationDateRange -StartDate $StartDate -EndDate $EndDate
        $now = Get-Date
        $queryEnd = $range.End
        if ($range.Start -gt $now.AddMinutes(2)) {
            throw 'The start date is in the future, so message trace has nothing to search.'
        }
        if ($queryEnd -gt $now.AddMinutes(2)) {
            Write-InvLog -Level 'WARN' -Message 'The end date is in the future. Message trace will be queried through the current time.'
            $queryEnd = $now
        }
        if ($range.Start -lt $now.AddDays(-90)) {
            Write-InvLog -Level 'WARN' -Message 'Message trace normally retains about 90 days. Older days in this window may return nothing.'
        }
        if ([string]::IsNullOrWhiteSpace($OutputFolder)) { $OutputFolder = Get-DefaultOutputFolder }
        $searchInfo = Get-NormalizedSubjectInfo -Subject $Subject
        if ($searchInfo.Subject.Length -lt 12) {
            Write-InvLog -Level 'WARN' -Message 'The subject is very short. Expect unrelated messages in the trace, then review the excluded view.'
        }

        Update-InvProgress -Percent 5 -Phase 'Connect' -Message 'Checking Exchange Online connection'
        if (-not $SkipConnectionCheck -and -not $Dependencies) {
            $connection = Connect-InvestigationService -UserPrincipalName $SignInUpn
            if (-not $connection.Connected) {
                throw 'Exchange Online did not report a connected session after sign-in.'
            }
            Write-InvLog -Level 'INFO' -Message ("Connected as {0} (module {1})" -f $connection.User, $connection.Version)
        }
        if (-not $Dependencies) { $Dependencies = New-DefaultInvestigationDependencies }

        $domains = New-Object System.Collections.Generic.List[string]
        foreach ($domain in @( $InternalDomains )) {
            if (-not [string]::IsNullOrWhiteSpace([string]$domain)) { $domains.Add(([string]$domain).Trim()) }
        }
        if ($domains.Count -eq 0) {
            Update-InvProgress -Percent 8 -Phase 'Domains' -Message 'Reading accepted domains'
            $loaded = ConvertTo-ItemArray (& $Dependencies.GetAcceptedDomains)
            foreach ($domain in $loaded) {
                if (-not [string]::IsNullOrWhiteSpace([string]$domain)) { $domains.Add(([string]$domain).Trim()) }
            }
        }
        if ($domains.Count -eq 0) {
            throw 'No accepted domains were returned. Pass -InternalDomains or sign in with a role that can read them.'
        }

        $senderAddresses = @($OriginalSender)
        if ($ResolveSenderAliases -and $Dependencies.GetMailbox) {
            Update-InvProgress -Percent 12 -Phase 'Sender' -Message 'Resolving sender aliases'
            try {
                $senderRaw = & $Dependencies.GetMailbox $OriginalSender
                $senderBox = ConvertTo-MailboxRecord -Raw $senderRaw -RequestedAddress $OriginalSender
                $senderAddresses = @($senderBox.Addresses)
                if ($senderBox.UserPrincipalName) { $senderAddresses += $senderBox.UserPrincipalName }
            }
            catch {
                Write-InvLog -Level 'WARN' -Message ("Sender aliases were not resolved: {0}" -f $_.Exception.Message)
            }
        }

        if (Test-InvCancel) {
            $cancelledReport = New-LeakedEmailReport -TraceRows @() -Subject $Subject -OriginalSender $OriginalSender -SenderAddresses $senderAddresses -InternalDomains $domains -MessageId $MessageId -LooseSubjectMatch $LooseSubjectMatch -StartDate $range.Start -EndDate $range.End -OutputFolder $OutputFolder
            $cancelledReport.Cancelled = $true
            $cancelledReport.Warnings = ConvertTo-ItemArray $script:InvCtx.Warnings
            Complete-LeakedEmailReport -Report $cancelledReport
            return $cancelledReport
        }

        $utcStart = ConvertTo-UtcFromLocal -Value $range.Start
        $utcEnd = ConvertTo-UtcFromLocal -Value $queryEnd
        Update-InvProgress -Percent 15 -Phase 'Trace' -Message ("Tracing '{0}'" -f $searchInfo.Subject)
        $pages = Get-MessageTracePages -StartUtc $utcStart -EndUtc $utcEnd -SubjectText $searchInfo.Subject -PageSize $TracePageSize -FetchPage $Dependencies.FetchTracePage -MaxRows $MaxTraceRows
        Write-InvLog -Level 'INFO' -Message ("{0} unique trace rows collected" -f @($pages.Rows).Count)

        $report = New-LeakedEmailReport -TraceRows $pages.Rows -Subject $Subject -OriginalSender $OriginalSender -SenderAddresses $senderAddresses -InternalDomains $domains -MessageId $MessageId -LooseSubjectMatch $LooseSubjectMatch -StartDate $range.Start -EndDate $range.End -OutputFolder $OutputFolder
        $report.Capped = [bool]$pages.Capped
        $report.Cancelled = [bool]$pages.Cancelled -or (Test-InvCancel)
        $report.Options = [pscustomobject]@{
            CheckAutoForwarding = $CheckAutoForwarding
            IncludeDisabledRules = $IncludeDisabledRules
            CheckTransportPolicy = $CheckTransportPolicy
            SkipOpenAudit = $SkipOpenAudit
            AuditAllUsers = $AuditAllUsers
            IncludeTraceDetail = $IncludeTraceDetail
        }
        if ($report.Cancelled) {
            $report.Warnings = ConvertTo-ItemArray $script:InvCtx.Warnings
            Complete-LeakedEmailReport -Report $report
            try { Export-InvestigationReport -Report $report | Out-Null } catch { $report.ExportError = $_.Exception.Message }
            return $report
        }

        if ($IncludeTraceDetail -and $Dependencies.FetchTraceDetail) {
            $detailTargets = @(ConvertTo-ItemArray $report.RelatedTrace | Sort-Object @{ Expression = { if ($_.External -eq 'Yes') { 0 } else { 1 } } }, ReceivedUtc)
            $limit = [Math]::Min($MaxDetailRows, $detailTargets.Count)
            if ($detailTargets.Count -gt $MaxDetailRows) {
                Write-InvLog -Level 'WARN' -Message ("Trace detail is limited to {0} of {1} related rows. External rows are first." -f $MaxDetailRows, $detailTargets.Count)
            }
            $detailFailures = 0
            for ($index = 0; $index -lt $limit; $index++) {
                if (Test-InvCancel) { $report.Cancelled = $true; break }
                $row = $detailTargets[$index]
                if ([string]::IsNullOrWhiteSpace($row.MessageTraceId) -or [string]::IsNullOrWhiteSpace($row.RecipientAddress)) { continue }
                Update-InvProgress -Percent 50 -Phase 'Detail' -Message ("Trace detail {0} of {1}" -f ($index + 1), $limit)
                try {
                    $events = @( & $Dependencies.FetchTraceDetail ([pscustomobject]@{
                        MessageTraceId   = $row.MessageTraceId
                        RecipientAddress = $row.RecipientAddress
                    }) )
                    $names = New-Object System.Collections.Generic.List[string]
                    foreach ($eventName in $events) {
                        if ($eventName) { $names.Add([string]$eventName) }
                    }
                    $row.TraceEvents = ($names -join '; ')
                }
                catch { $detailFailures++ }
            }
            if ($detailFailures -gt 0) {
                Write-InvLog -Level 'WARN' -Message ("Message trace detail failed for {0} row(s)." -f $detailFailures)
            }
        }
        if ($report.Cancelled) {
            $report.Warnings = ConvertTo-ItemArray $script:InvCtx.Warnings
            Complete-LeakedEmailReport -Report $report
            try { Export-InvestigationReport -Report $report | Out-Null } catch { $report.ExportError = $_.Exception.Message }
            return $report
        }

        $internalRecipients = New-Object System.Collections.Generic.List[string]
        $seenRecipients = New-AddressSet
        foreach ($row in (ConvertTo-ItemArray $report.Original) + (ConvertTo-ItemArray $report.Propagation) + (ConvertTo-ItemArray $report.Replies)) {
            if ($row.External -eq 'Yes') { continue }
            if ($row.RecipientAddress -and $seenRecipients.Add($row.RecipientAddress)) {
                $internalRecipients.Add($row.RecipientAddress)
            }
        }

        $mailboxRecords = New-Object System.Collections.Generic.List[object]
        $needMailbox = $CheckAutoForwarding -or (-not $SkipOpenAudit)
        if ($needMailbox -and $Dependencies.GetMailbox) {
            $mailboxIndex = 0
            foreach ($address in $internalRecipients) {
                if (Test-InvCancel) { $report.Cancelled = $true; break }
                $mailboxIndex++
                Update-InvProgress -Percent 60 -Phase 'Mailbox' -Message ("Reading mailbox {0} of {1}: {2}" -f $mailboxIndex, $internalRecipients.Count, $address)
                try {
                    $rawBox = & $Dependencies.GetMailbox $address
                    $record = ConvertTo-MailboxRecord -Raw $rawBox -RequestedAddress $address
                    $mailboxRecords.Add($record)
                }
                catch {
                    Write-InvLog -Level 'WARN' -Message ("{0}: {1}" -f $address, $_.Exception.Message)
                    $mailboxRecords.Add([pscustomobject]@{
                        Requested = $address; PrimarySmtp = $address; UserPrincipalName = $address
                        Addresses = @($address); ForwardingAddress = ''; ForwardingSmtpAddress = ''
                        DeliverToMailboxAndForward = ''; Error = $_.Exception.Message
                    })
                }
            }
        }
        $report.Mailboxes = ConvertTo-ItemArray $mailboxRecords.ToArray()

        if ($CheckAutoForwarding -and -not $report.Cancelled) {
            $autoRows = New-Object System.Collections.Generic.List[object]
            foreach ($record in $mailboxRecords) {
                if ($record.Error) {
                    $autoRows.Add((New-AutoForwardRow -Mailbox $record.Requested -Type 'LookupFailed' -Name '' -Enabled '' -Target '' -Deliver '' -Detail $record.Error -InternalDomains $domains))
                    continue
                }
                $chosen = $(if ($record.ForwardingSmtpAddress) { $record.ForwardingSmtpAddress } else { $record.ForwardingAddress })
                if ($chosen) {
                    $autoRows.Add((New-AutoForwardRow -Mailbox $record.Requested -Type 'MailboxForwarding' -Name '' -Enabled $true -Target $chosen -Deliver $record.DeliverToMailboxAndForward -Detail '' -InternalDomains $domains))
                }
                if (-not $Dependencies.GetInboxRules) { continue }
                try {
                    $rules = ConvertTo-ItemArray (& $Dependencies.GetInboxRules $record.Requested)
                    foreach ($rule in $rules) {
                        $targets = Get-RuleTargets $rule
                        if ($targets.Count -eq 0) { continue }
                        $enabled = Get-ObjectProperty $rule 'Enabled'
                        $isEnabled = $true
                        if ($enabled -is [bool]) { $isEnabled = $enabled }
                        if (-not $isEnabled -and -not $IncludeDisabledRules) { continue }
                        $autoRows.Add((New-AutoForwardRow -Mailbox $record.Requested -Type 'InboxRule' -Name ([string](Get-ObjectProperty $rule 'Name')) -Enabled $isEnabled -Target ($targets -join '; ') -Deliver '' -Detail '' -InternalDomains $domains))
                    }
                }
                catch {
                    Write-InvLog -Level 'WARN' -Message ("Inbox rules for {0}: {1}" -f $record.Requested, $_.Exception.Message)
                    $autoRows.Add((New-AutoForwardRow -Mailbox $record.Requested -Type 'LookupFailed' -Name 'Inbox rules' -Enabled '' -Target '' -Deliver '' -Detail $_.Exception.Message -InternalDomains $domains))
                }
            }
            $report.AutoForwarding = ConvertTo-ItemArray $autoRows.ToArray()
        }

        if ($CheckTransportPolicy -and -not $report.Cancelled) {
            Update-InvProgress -Percent 72 -Phase 'Policy' -Message 'Reading transport and remote-domain policy'
            $report.Policy = Get-TenantPolicyRows -Dependencies $Dependencies -InternalDomains $domains
        }

        if (-not $SkipOpenAudit -and -not $report.Cancelled) {
            Update-InvProgress -Percent 78 -Phase 'Audit' -Message 'Searching MailItemsAccessed'
            if ($Dependencies.GetAdminAuditLogConfig) {
                try {
                    $config = & $Dependencies.GetAdminAuditLogConfig
                    $ingestion = Get-ObjectProperty $config 'UnifiedAuditLogIngestionEnabled'
                    if ($null -ne $ingestion) { $report.AuditIngestionEnabled = [bool]$ingestion }
                }
                catch {
                    Write-InvLog -Level 'WARN' -Message ("Audit configuration was not read: {0}" -f $_.Exception.Message)
                }
            }
            $auditEndLocal = $queryEnd
            if ($AuditThroughNow -and $now -gt $auditEndLocal) { $auditEndLocal = $now }
            $auditStartUtc = $utcStart
            $auditEndUtc = ConvertTo-UtcFromLocal -Value $auditEndLocal
            $userBatches = New-Object System.Collections.Generic.List[object]
            if ($AuditAllUsers) {
                $userBatches.Add($null)
            }
            else {
                $upns = New-Object System.Collections.Generic.List[string]
                foreach ($record in $mailboxRecords) {
                    if ($record.UserPrincipalName -and -not $record.Error) { $upns.Add($record.UserPrincipalName) }
                    elseif ($record.Requested) { $upns.Add($record.Requested) }
                }
                foreach ($extra in (ConvertTo-AddressList $AdditionalAuditUsers)) { $upns.Add($extra) }
                $plan = Split-IntoBatches -Items $upns.ToArray() -Size $AuditBatchSize
                $batchArray = $plan.Batches
                if ($batchArray -is [System.Array]) {
                    for ($batchIndex = 0; $batchIndex -lt $batchArray.Length; $batchIndex++) {
                        $userBatches.Add($batchArray[$batchIndex])
                    }
                }
                if ($userBatches.Count -eq 0) {
                    Write-InvLog -Level 'WARN' -Message 'No internal recipients were available for the open audit. Add delegate UPNs or turn on Audit all users.'
                }
            }
            $records = New-Object System.Collections.Generic.List[object]
            $auditErrors = New-Object System.Collections.Generic.List[string]
            $batchNumber = 0
            foreach ($batch in $userBatches) {
                if (Test-InvCancel) { $report.Cancelled = $true; break }
                $batchNumber++
                $label = 'all users'
                $batchIds = $null
                if ($null -ne $batch) {
                    if ($batch -is [System.Array]) {
                        $batchIds = $batch
                        $label = ("{0} users" -f $batch.Length)
                    }
                    else {
                        $batchIds = @([string]$batch)
                        $label = '1 user'
                    }
                }
                Update-InvProgress -Percent 85 -Phase 'Audit' -Message ("Audit batch {0} of {1} ({2})" -f $batchNumber, $userBatches.Count, $label)
                try {
                    $page = Invoke-PagedAuditSearch -Fetch $Dependencies.SearchAudit -StartUtc $auditStartUtc -EndUtc $auditEndUtc -UserIds $batchIds -HighCompleteness:(-not $FastAudit) -PageSize $AuditPageSize -MaxRecords $MaxAuditRecords
                    foreach ($record in (ConvertTo-ItemArray $page.Records)) { $records.Add($record) }
                    if ($page.Capped) { $report.Capped = $true }
                    if ($page.Cancelled) { $report.Cancelled = $true; break }
                }
                catch {
                    $auditErrors.Add($_.Exception.Message)
                    Write-InvLog -Level 'WARN' -Message ("Audit batch failed: {0}" -f $_.Exception.Message)
                }
            }
            $targetIds = Get-TargetMessageIds -Report $report
            $openResult = Get-OpenEventsFromAudit -Records $records.ToArray() -TargetIds $targetIds -Report $report
            $report.Opened = $openResult.Opened
            $report.Syncs = $openResult.Syncs
            $report.AuditThrottled = $openResult.Throttled
            $report.AuditAllUsers = $AuditAllUsers
            if ($openResult.ParseErrors -gt 0) {
                Write-InvLog -Level 'WARN' -Message ("{0} audit record(s) could not be parsed." -f $openResult.ParseErrors)
            }
            if ($openResult.SyncCapped) {
                Write-InvLog -Level 'WARN' -Message 'Folder sync export was capped. Sync rows are weak evidence and were limited to investigated mailboxes.'
            }
            if ($auditErrors.Count -gt 0 -and $records.Count -eq 0) {
                $report.AuditStatus = 'Failed'
                $report.AuditError = $auditErrors[0]
            }
            elseif ($report.Cancelled) {
                $report.AuditStatus = 'Cancelled'
                if ($auditErrors.Count -gt 0) { $report.AuditError = $auditErrors[0] }
            }
            else {
                $report.AuditStatus = 'Completed'
                if ($auditErrors.Count -gt 0) { $report.AuditError = $auditErrors[0] }
            }
        }
        elseif ($SkipOpenAudit) {
            $report.AuditStatus = 'Skipped'
        }

        $report.Warnings = ConvertTo-ItemArray $script:InvCtx.Warnings
        Complete-LeakedEmailReport -Report $report
        Update-InvProgress -Percent 96 -Phase 'Export' -Message ("Writing reports to {0}" -f $report.OutputFolder)
        try { Export-InvestigationReport -Report $report | Out-Null }
        catch {
            $report.ExportError = $_.Exception.Message
            Write-InvLog -Level 'ERROR' -Message ("Reports could not be written: {0}" -f $_.Exception.Message)
        }
        Update-InvProgress -Percent 100 -Phase 'Done' -Message 'Investigation finished'
        return $report
    }
    finally {
        $script:InvCtx = $previous
    }
}

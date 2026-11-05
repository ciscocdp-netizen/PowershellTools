#Requires -Version 5.1
<#
.SYNOPSIS
    Unit tests for the mail flow investigation engine. No Exchange connection required.
#>
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot '..\M365MailFlowInvestigation.psm1'
Import-Module $modulePath -Force -DisableNameChecking

$script:Passed = 0
$script:Failed = 0

function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        $script:Passed++
        Write-Host "  PASS  $Name" -ForegroundColor Green
    } else {
        $script:Failed++
        Write-Host "  FAIL  $Name" -ForegroundColor Red
    }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Name)
    if ($Actual -eq $Expected) {
        $script:Passed++
        Write-Host "  PASS  $Name" -ForegroundColor Green
    } else {
        $script:Failed++
        Write-Host "  FAIL  $Name" -ForegroundColor Red
        Write-Host "        expected: [$Expected]" -ForegroundColor DarkRed
        Write-Host "        actual  : [$Actual]" -ForegroundColor DarkRed
    }
}

function Assert-Contains {
    param([string]$Haystack, [string]$Needle, [string]$Name)
    Assert-True ($Haystack -like "*$Needle*") $Name
}

function Assert-NotContains {
    param([string]$Haystack, [string]$Needle, [string]$Name)
    Assert-True ($Haystack -notlike "*$Needle*") $Name
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Name)
    $threw = $false
    try { & $Action } catch { $threw = $true }
    Assert-True $threw $Name
}

Write-Host 'DSN and status codes'
$info = Get-DsnInfo '5.1.1'
Assert-True ($info.Exact -and $info.Meaning -match 'mailbox') '5.1.1 is an exact mailbox code'
$banned = Get-DsnInfo '5.7.620'
Assert-True ((-not $banned.Exact) -and $banned.Meaning -match 'banned') '5.7.620 falls into the banned-IP range'
$tenant = Get-DsnInfo '5.7.720'
Assert-True ($tenant.Meaning -match 'tenant') '5.7.720 falls into the tenant-restricted range'
$throttle = Get-DsnInfo '4.7.600'
Assert-True ($throttle.Meaning -match 'throttl') '4.7.600 falls into the throttling range'
Assert-True ((Get-DsnInfo '4.7.650').Exact) '4.7.650 stays on the exact knowledge-base entry'
$codes = Get-StatusCodes 'remote said 5.1.10 and also 4.4.7 plus TLS 1.2 and build 2.0.0 and not 4.4.77'
Assert-True (($codes -contains '5.1.10') -and ($codes -contains '4.4.7')) '5.1.10 and 4.4.7 are both found'
Assert-True (($codes -contains '4.4.77') -and ($codes -notcontains '5.1.1')) '4.4.77 is not truncated and 5.1.10 is not 5.1.1'
Assert-True (-not ($codes -contains '1.2')) 'TLS 1.2 is not a status code'

Write-Host 'Agent, XML, and verdict decoders'
$agents = ConvertFrom-AgentData 'S:SFA=SUM|SFV=SPM|SFV=SKS|SCL=5;S:AMA=SUM|v=1|action=Delete;S:TRA=ETR|ruleId=abc|action=SetSCL'
Assert-Equal $agents.Count 3 'three agents are decoded'
Assert-Equal $agents[0].Agent 'SFA' 'first agent is SFA'
Assert-Equal $agents[0].Values['SFV'] 'SPM,SKS' 'duplicate agent keys are joined'
Assert-Equal $agents[1].Values['action'] 'Delete' 'AMA action is decoded'
Assert-Equal (ConvertFrom-AgentData 'no agent data').Count 0 'plain text yields no agents'
$xml = ConvertFrom-TraceDataXml '<root><MEP Name="Foo" String="Bar"/><MEP Name="Foo" String="Baz"/></root>'
Assert-Equal $xml['Foo'] 'Bar; Baz' 'duplicate MEP names are concatenated'
$bad = ConvertFrom-TraceDataXml 'not xml & <'
Assert-True ($bad.Contains('RawData')) 'malformed trace XML is kept as raw data'
$xxe = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><MEP Name="X" String="&xxe;"/></root>'
$xxeResult = ConvertFrom-TraceDataXml $xxe
$xxeText = ($xxeResult.Values | ForEach-Object { [string]$_ }) -join ' '
Assert-True ($xxeText -notmatch '(?m)^root:') 'trace XML does not expand external entities'
$verdicts = Get-AntiSpamVerdicts 'SFV=SPM SCL=6 CAT=PHSH BCL=7 compauth=fail reason=001 spf=fail'
Assert-Equal $verdicts['SFV'] 'SPM' 'SFV decoded'
Assert-Equal $verdicts['reason'] '001' 'compauth reason decoded'
Assert-Equal (Get-AuthReasonText '001') (Get-AuthReasonText '001') 'reason 001 resolves'
Assert-True ((Get-AuthReasonText '001') -match 'Implicit') 'reason 001 text is the implicit-failure entry'
Assert-True ((Get-AuthReasonText '601') -match 'Implicit fail') 'unknown 6xx reason uses the class prefix'
Assert-Equal (Get-AuthReasonText '10') '' 'a two-digit unknown reason is not guessed from its first digit'

Write-Host 'Dates, subjects, addresses, and query fan-out'
$utc = ConvertFrom-RfcDate 'Tue, 4 Nov 2025 10:00:00 +0000'
Assert-Equal $utc.Hour 10 'numeric offset +0000 is 10:00 UTC'
$colon = ConvertFrom-RfcDate '4 Nov 2025 10:00:00 +00:00'
Assert-Equal $colon.Hour 10 'offset written as +00:00 is accepted'
$shifted = ConvertFrom-RfcDate '4 Nov 2025 10:00:00 -0500'
Assert-Equal $shifted.Hour 15 '-0500 converts to 15:00 UTC'
Assert-Equal (ConvertFrom-RfcDate '4 Nov 2025 10:00:00 PST') $null 'PST is not reported as UTC'
Assert-Equal (ConvertFrom-RfcDate 'not a date') $null 'garbage dates return null'
Assert-True (Test-SubjectFilterMatch -SubjectText '100% off *sale*' -Filter '*sale*' -Mode 'Contains') 'subject filter treats asterisks as literal text'
Assert-True (Test-SubjectFilterMatch -SubjectText 'Quarterly sale*' -Filter 'sale*' -Mode 'EndsWith') 'EndsWith is literal'
Assert-True (-not (Test-SubjectFilterMatch -SubjectText 'sale starts here' -Filter 'sale' -Mode 'EndsWith')) 'EndsWith does not match a prefix'
$addrs = Get-NormalizedAddressList @('Doe, Jane <Jane@Contoso.com>; bob@contoso.com', 'jane@contoso.com')
Assert-Equal $addrs.Count 2 'display names and duplicates collapse to two addresses'
Assert-Equal $addrs[0] 'Jane@Contoso.com' 'address inside angle brackets is kept'
Assert-Equal (ConvertTo-NormalizedMessageId 'abc@mail.example.com') '<abc@mail.example.com>' 'bare message IDs gain brackets'
Assert-Equal (ConvertTo-NormalizedMessageId '<abc@mail.example.com>') '<abc@mail.example.com>' 'bracketed message IDs stay bracketed'
$foldedId = Get-NormalizedMessageIdList "<E1682@BY5PR03MB5141.namprd03.prod`r`n .outlook.com>"
Assert-Equal $foldedId.Count 1 'a folded message ID stays one value'
Assert-Equal $foldedId[0] '<E1682@BY5PR03MB5141.namprd03.prod.outlook.com>' 'folding inside the ID is removed'
$wrappedId = Get-NormalizedMessageIdList "<E1682@BY5PR03MB5141.namprd03.prod`r`n.outlook.com>"
Assert-Equal $wrappedId[0] '<E1682@BY5PR03MB5141.namprd03.prod.outlook.com>' 'a hard line break inside angle brackets is joined'
$headerBlob = "From: Jane <jane@contoso.com>`r`nMessage-ID: <abc123@mail.example.com>`r`nTo: Bob <bob@fabrikam.com>"
$headerIds = Get-NormalizedMessageIdList $headerBlob
Assert-Equal $headerIds.Count 1 'a Message-ID header is used and From/To addresses are not'
Assert-Equal $headerIds[0] '<abc123@mail.example.com>' 'the header message ID is kept'
$twoIds = Get-NormalizedMessageIdList "<one@contoso.com>`r`n<two@fabrikam.com>"
Assert-Equal $twoIds.Count 2 'two pasted message IDs stay separate'
$forms = Get-MessageIdQueryForms '<abc@x>'
Assert-Equal $forms.Count 2 'a bracketed ID is also queried without brackets'
Assert-Equal $forms[0] '<abc@x>' 'the bracketed form is tried first'
Assert-Equal $forms[1] 'abc@x' 'the bare form is the retry'
$locator = Get-MessageLocatorFromText "Message-ID: <abc123@mail.example.com>`r`nX-MS-Exchange-Organization-Network-Message-Id: 22222222-2222-2222-2222-222222222222"
Assert-Equal $locator.MessageIds[0] '<abc123@mail.example.com>' 'locator keeps the message ID'
Assert-Equal ([string]$locator.MessageTraceId) '22222222-2222-2222-2222-222222222222' 'locator keeps the network message id'
$onlyGuid = Get-MessageLocatorFromText '33333333-3333-3333-3333-333333333333'
Assert-Equal $onlyGuid.MessageIds.Count 0 'a bare GUID is not treated as a message ID'
Assert-Equal ([string]$onlyGuid.MessageTraceId) '33333333-3333-3333-3333-333333333333' 'a bare GUID is a trace id'
$backNow = Get-Date '2026-11-05T10:30:00'
$backStart = $backNow.AddDays(-2)
$backOld = $backNow.AddDays(-90)
$back = Get-SearchBackWindows -RequestedStart $backStart -RequestedEnd $backNow -Now $backNow -Oldest $backOld
Assert-True ($back.Count -ge 8) 'a two-day miss continues back through the 90-day history'
Assert-Equal $back[0].End $backStart 'the first extra window starts where the selected range ended'
Assert-Equal $back[-1].Start $backOld 'the search reaches the 90-day floor'
$noTrace = Get-MessageTraceCommandAvailability
Assert-True (-not $noTrace.HasTrace) 'this test host has no message trace cmdlets'
Assert-True (Test-ExoSessionNeedsRefresh -ExistingConnection ([pscustomobject]@{ State = 'Connected' }) -HasTraceCmdlet $false) 'a signed-in session with no trace cmdlets is signed in again'
Assert-True (-not (Test-ExoSessionNeedsRefresh -ExistingConnection $null -HasTraceCmdlet $false)) 'no session yet does not count as a stale session'
$access = Get-MessageTraceAccessError -Identity 'admin@contoso.com'
Assert-Contains $access 'admin@contoso.com' 'the missing-cmdlet error names the signed-in account'
Assert-Contains $access 'Message Tracking' 'the missing-cmdlet error names the Exchange role'
Set-M365MailFlowConfig @{
    SenderAddress = @('a@c.com','b@c.com')
    RecipientAddress = @('c@d.com','e@d.com')
    MessageId = @('<1@x>','<2@x>')
    Status = @('Failed','Pending')
}
$fan = Get-TraceQueryCombinations -FanOutStatus
Assert-Equal $fan.Count 16 'two of each filter fans out to 16 queries'
Assert-Throws { Set-M365MailFlowConfig @{ SenderAddress=@('a@x.com','b@x.com','c@x.com'); RecipientAddress=@('d@x.com','e@x.com','f@x.com'); MessageId=@('<1@x.com>','<2@x.com>','<3@x.com>'); Status=@() }; Get-TraceQueryCombinations -FanOutStatus } 'more than 25 combinations is rejected'
Set-M365MailFlowConfig @{ SenderAddress=@('a@x.com','b@x.com'); RecipientAddress=@(); MessageId=@(); Status=@('Failed','Pending') }
$packed = Get-TraceQueryCombinations
Assert-Equal $packed.Count 2 'legacy status packing does not multiply the status list'

Write-Host 'Root cause ranking'
Set-M365MailFlowConfig @{ AcceptedDomains = @('contoso.com'); LatencyWarningMinutes = 10; LogFile = $null }
$summary = [pscustomobject]@{
    Received = [datetime]::SpecifyKind((Get-Date).ToUniversalTime().AddHours(-2), 'Utc')
    SenderAddress = 'sender@contoso.com'; RecipientAddress = 'user@fabrikam.com'
    Subject = 'Invoice'; Status = 'Failed'; FromIP = '1.2.3.4'; ToIP = '5.6.7.8'
    Size = 100; MessageId = '<m@contoso.com>'; MessageTraceId = '11111111-1111-1111-1111-111111111111'
}
$msg = New-MessageRecord -Summary $summary
Assert-Equal $msg.Direction 'Outbound' 'accepted recipient domain marks the message outbound'
$msg.DetailRetrieved = $true
$msg.Events.Add((New-JourneyEvent -DateUtc ([datetime]::SpecifyKind((Get-Date).ToUniversalTime().AddHours(-2), 'Utc')) `
    -EventName 'Fail' -Action '' -Detail '550 5.1.1 User unknown' -DataRaw '' -Data ([ordered]@{}) -Source 'Test'))
Invoke-RootCauseAnalysis -Msg $msg
Set-PrimaryCause -Msg $msg
Assert-Equal $msg.PrimaryCause.Category 'Status code' 'primary cause is the enhanced status code'
Assert-True ($msg.PrimaryCause.Finding -match '5\.1\.1') 'primary cause names 5.1.1'
Assert-True (@($msg.Findings | Where-Object { $_.Finding -match '^Delivery FAILED' }).Count -ge 1) 'generic failure banner is still recorded'

$defer = New-MessageRecord -Summary $summary
$defer.Status = 'Pending'
$defer.DetailRetrieved = $true
$t0 = [datetime]::SpecifyKind((Get-Date).ToUniversalTime().AddMinutes(-30), 'Utc')
$defer.Events.Add((New-JourneyEvent -DateUtc $t0 -EventName 'Defer' -Action '' -Detail '450 4.4.1 connection timed out LED=connection timed out' -DataRaw '' -Data ([ordered]@{}) -Source 'Test'))
$defer.Events.Add((New-JourneyEvent -DateUtc $t0.AddMinutes(10) -EventName 'Defer' -Action '' -Detail '450 4.4.1 connection timed out' -DataRaw '' -Data ([ordered]@{}) -Source 'Test'))
Invoke-RootCauseAnalysis -Msg $defer
Assert-True (@($defer.Findings | Where-Object Category -eq 'Deferral').Count -ge 1) 'repeated deferrals produce a deferral finding'

Assert-True (Test-TextContainsToken -Text 'routed via Contoso Outbound connector' -Token 'Contoso Outbound') 'connector names match as a whole token'
Assert-True (-not (Test-TextContainsToken -Text 'Contoso Outbound' -Token 'to')) 'short connector names do not match inside other words'
Assert-True (Test-RuleMatchesSender -RuleFrom 'Other <a@b.com>, Jane Doe <jane@contoso.com>' -SenderAddress 'jane@contoso.com') 'inbox rule sender match is exact'
Assert-True (-not (Test-RuleMatchesSender -RuleFrom 'notjane@contoso.com' -SenderAddress 'jane@contoso.com')) 'inbox rule sender match is not a substring'
$bytes = ConvertTo-Bytes '1.5 GB (1500000 bytes)'
Assert-Equal $bytes 1500000 'byte size is read from the parenthetical'
Assert-True ([double]::IsInfinity((ConvertTo-Bytes 'Unlimited'))) 'Unlimited quota is infinite'
Assert-Equal (ConvertTo-Bytes $null) $null 'missing size stays null'
Assert-Equal (ConvertTo-CsvSafe "=cmd|' /C calc") "'=cmd|' /C calc" 'formula-like CSV text is prefixed'
Assert-Equal (ConvertTo-CsvSafe 'normal subject') 'normal subject' 'ordinary CSV text is unchanged'

Write-Host 'Header analysis'
$headerPath = Join-Path ([System.IO.Path]::GetTempPath()) ('m365mf-headers-' + [guid]::NewGuid().ToString('n') + '.txt')
@'
Received: from mail.contoso.com (1.2.3.4) by EXCH.contoso.com with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.1; Tue, 4 Nov 2025 10:20:00 +0000
Received: from sender.example.com (5.6.7.8) by mail.contoso.com with ESMTPS id abc; Tue, 4 Nov 2025 10:00:00 +0000
From: Someone <user@example.com>
To: recip@contoso.com
Subject: Invoice <img src=x onerror=alert(1)>
Message-ID: <abc123@mail.example.com>
Return-Path: bounce@bounce.example.net
Authentication-Results: spf=fail dkim=none dmarc=fail compauth=fail reason=001 smtp.mailfrom=bounce.example.net header.from=example.com
X-Forefront-Antispam-Report: CIP:1.2.3.4;CTRY:US;LANG:en;SCL:spam;SRV:;IPV:NLI;SFV:SPM;H:example.com;PTR:example.com;CAT:PHSH;SFS:;DIR:INB;
X-Microsoft-Antispam: BCL:7
X-MS-Exchange-Organization-Network-Message-Id: 22222222-2222-2222-2222-222222222222
Date: Tue, 4 Nov 2025 10:00:00 +0000
MIME-Version: 1.0

Body
'@ | Set-Content -LiteralPath $headerPath -Encoding UTF8
$header = Get-HeaderAnalysis -Path $headerPath
Assert-Equal @($header.Hops).Count 2 'two Received hops are parsed'
Assert-Equal $header.Summary.MessageId '<abc123@mail.example.com>' 'Message-ID is taken from the headers'
Assert-Equal $header.Summary.NetworkMessageId '22222222-2222-2222-2222-222222222222' 'network message id is taken from the headers'
Assert-True (@($header.Findings | Where-Object { $_.Severity -eq 'Critical' -and $_.Finding -match 'Composite authentication FAILED' }).Count -ge 1) 'compauth failure is critical'
Assert-True (@($header.Findings | Where-Object { $_.Finding -match 'SCL=' }).Count -eq 0) 'non-numeric SCL does not become a numeric finding and does not throw'
Assert-True (@($header.Findings | Where-Object { $_.Finding -match 'BCL=7' }).Count -ge 1) 'numeric BCL is still reported'
Assert-True (@($header.Findings | Where-Object { $_.Finding -match 'Return-Path domain' }).Count -ge 1) 'mismatched Return-Path is reported'
Assert-True (@($header.Findings | Where-Object Category -eq 'Latency').Count -ge 1) 'a 20 minute hop is over the 10 minute warning'

$future = [pscustomobject]@{ ReceivedUtc = [datetime]::SpecifyKind((Get-Date).ToUniversalTime().AddDays(3), 'Utc'); MessageTraceId = [guid]::NewGuid().ToString() }
$window = Get-TraceDetailWindow -Msg $future
Assert-True ($window.End -gt $window.Start) 'a future received time still produces a usable detail window'
$normal = [pscustomobject]@{ ReceivedUtc = [datetime]::SpecifyKind((Get-Date).ToUniversalTime().AddDays(-3), 'Utc') }
$normalWindow = Get-TraceDetailWindow -Msg $normal
Assert-True (($normalWindow.End - $normalWindow.Start).TotalHours -le 239) 'detail windows stay inside the 10 day query limit'

Write-Host 'Extended report, HTML report, log encoding, and cancellation'
$csvPath = Join-Path ([System.IO.Path]::GetTempPath()) ('m365mf-report-' + [guid]::NewGuid().ToString('n') + '.csv')
$csv = @"
Message trace report
date_time_utc,sender_address,recipient_address,message_subject,event_id,recipient_status,network_message_id,message_id,custom_data
2025-11-01T10:00:00Z,a@contoso.com,b@fabrikam.com,"Hello, world",RECEIVE,250 OK,11111111-1111-1111-1111-111111111111,<m@x>,
2025-11-01T10:05:00Z,a@contoso.com,b@fabrikam.com,"Hello
world",FAIL,550 5.1.1 User unknown,11111111-1111-1111-1111-111111111111,<m@x>,"S:SFA=SUM|SFV=SPM"
"@
[System.IO.File]::WriteAllText($csvPath, $csv, (New-Object System.Text.UTF8Encoding $false))
Set-M365MailFlowConfig @{ AcceptedDomains = @('contoso.com'); LogFile = $null }
$imported = Import-ExtendedReport -Path $csvPath
Assert-Equal $imported.Count 1 'extended report groups one message'
Assert-Equal $imported[0].Status 'Failed' 'FAIL event derives Failed'
Assert-Equal $imported[0].Subject 'Hello, world' 'a quoted comma stays in the subject and the following quoted newline does not split the file'
Assert-True $imported[0].DetailRetrieved 'extended rows are already detailed'
Assert-Equal @($imported[0].Events).Count 2 'both extended events are kept'
Assert-Equal @($imported[0].Events[1].Agents).Count 1 'custom_data agents are decoded'
Assert-Equal @($imported[0].Events[1].Agents)[0].Values['SFV'] 'SPM' 'extended SFV is SPM'

$utf16 = Join-Path ([System.IO.Path]::GetTempPath()) ('m365mf-utf16-' + [guid]::NewGuid().ToString('n') + '.csv')
$utf16Text = "date_time_utc,sender_address,recipient_address,message_subject,event_id,network_message_id,message_id`r`n2025-11-01T10:00:00Z,a@contoso.com,b@fabrikam.com,Hi,DELIVER,33333333-3333-3333-3333-333333333333,<z@x>`r`n"
[System.IO.File]::WriteAllText($utf16, $utf16Text, [System.Text.Encoding]::Unicode)
$utf16Rows = Import-ExtendedReport -Path $utf16
Assert-Equal $utf16Rows.Count 1 'UTF-16 extended reports import'
Assert-Equal $utf16Rows[0].Status 'Delivered' 'DELIVER derives Delivered'

$out = Join-Path ([System.IO.Path]::GetTempPath()) ('m365mf-out-' + [guid]::NewGuid().ToString('n'))
$result = Invoke-M365MailFlowInvestigation -Offline -HeaderFile $headerPath -OutputPath $out -Subject 'ignored'
Assert-Equal $result.ExitCode 0 'offline header investigation succeeds'
Assert-True (Test-Path -LiteralPath $result.ReportPath) 'HTML report is written'
$html = [System.IO.File]::ReadAllText($result.ReportPath)
Assert-Contains $html '&lt;img' 'HTML report encodes the subject'
Assert-NotContains $html '<img src=x' 'HTML report does not emit the raw image tag'
Assert-Contains $html 'Composite authentication FAILED' 'HTML report includes the header finding'
$logBytes = [System.IO.File]::ReadAllBytes((Join-Path $out 'Investigation.log'))
$bomAt = @()
for ($i = 1; $i -lt $logBytes.Length - 2; $i++) {
    if ($logBytes[$i] -eq 0xEF -and $logBytes[$i+1] -eq 0xBB -and $logBytes[$i+2] -eq 0xBF) { $bomAt += $i }
}
Assert-Equal $bomAt.Count 0 'log appends do not insert a UTF-8 BOM'
Assert-Equal $logBytes[0] 91 'log starts with the timestamp bracket'

$cancelOut = Join-Path ([System.IO.Path]::GetTempPath()) ('m365mf-cancel-' + [guid]::NewGuid().ToString('n'))
Set-M365MailFlowConfig @{ UiSync = @{ Cancel = $true; Queue = $null } }
$cancelled = Invoke-M365MailFlowInvestigation -Offline -HeaderFile $headerPath -OutputPath $cancelOut
Assert-Equal $cancelled.ExitCode 2 'a cancel flag stops the run'
Set-M365MailFlowConfig @{ UiSync = $null; LogFile = $null }

$start = (Get-Date '2025-11-01T00:00:00')
$end = $start.AddDays(15)
$windows = Get-DateWindows -Start $start -End $end
Assert-True ($windows.Count -ge 2) 'a 15 day range uses more than one window'
$maxHours = ($windows | ForEach-Object { ($_.End - $_.Start).TotalHours } | Measure-Object -Maximum).Maximum
Assert-True ($maxHours -le 239) 'no window exceeds 239 hours'
$coveredStart = ($windows | Measure-Object Start -Minimum).Minimum
$coveredEnd = ($windows | Measure-Object End -Maximum).Maximum
Assert-Equal $coveredStart $start 'windows cover the start'
Assert-Equal $coveredEnd $end 'windows cover the end'

Remove-Item -LiteralPath $headerPath, $csvPath, $utf16 -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $out, $cancelOut -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:Passed, $script:Failed)
if ($script:Failed -gt 0) { exit 1 }
exit 0

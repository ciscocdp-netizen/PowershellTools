#requires -Version 5.1
<#
.SYNOPSIS
  Read-only Kerberos RC4 investigation and live monitoring for Windows Domain Controllers.

.DESCRIPTION
  Reads Security events 4768 (AS/TGT) and 4769 (TGS) from one or more DCs, exported EVTX
  files, or the local Security log. Classifies actual RC4 ticket and session-key encryption
  separately from merely advertised RC4, enriches hostnames and (optionally) AD identities,
  and writes CSV plus a self-contained searchable HTML report.

  Does NOT modify AD, auditing settings, tickets, or encryption policies.

  Actual RC4 uses etype 0x17 (23, RC4-HMAC) or 0x18 (24, RC4-HMAC-EXP).
  "RC4 Offered Only" is NOT evidence of RC4 ticket issuance. Almost every modern Windows
  client still advertises RC4 even when the issued ticket is AES.

.EXAMPLE
  .\Watch-KerberosRC4-Enhanced.ps1 -DomainControllers LAP-MSASDC03.mclaren.org -Mode Both -HoursBack 24

.EXAMPLE
  .\Watch-KerberosRC4-Enhanced.ps1 -DiscoverDCs -Mode Live -IncludeOffered -ResolveHostnames -EnrichAD

.EXAMPLE
  .\Watch-KerberosRC4-Enhanced.ps1 -DomainControllers DC01,DC02 -Mode Historical -HoursBack 48 -OutputFolder C:\Temp\RC4

.EXAMPLE
  .\Watch-KerberosRC4-Enhanced.ps1 -EvtxPath C:\Temp\Security.evtx -Mode Historical

.EXAMPLE
  .\Watch-KerberosRC4-Enhanced.ps1 -SelfTest

.NOTES
  Requires permissions to remotely read DC Security event logs (Event Log Readers / Domain
  Admins) and firewall/Event Log RPC access.
  EnrichAD / DiscoverDCs require the ActiveDirectory RSAT PowerShell module.

  Event 4769 ServiceName is frequently a service account name, not the full SPN.
  Session-key and advertised-etype fields exist only on the updated 4768/4769 schema
  (Windows Server 2019+ and Server 2016 with the January 2025 cumulative update).

  Bugs fixed versus the original collector:
  - Windows PowerShell 5.1 XmlElement.Name is the tag "Data", not the Name attribute.
    Using $item.Name therefore stored every field under the key "Data" and Convert-Event
    dropped every record. Field names are now read with GetAttribute("Name").
  - CSV header was written with Set-Content -Encoding UTF8 (BOM) then appended with
    Export-Csv. On 5.1 the BOM made the first column name not match, so the first finding
    threw and $ErrorActionPreference=Stop killed the script. CSV is now UTF-8 (no BOM)
    with columns in ReportColumns order.
  - Live Get-WinEvent -MaxEvents without -Oldest returns the newest N matches. On a busy
    DC that skipped the middle of a burst and advanced the RecordId cursor past them.
    Live catch-up now uses EventRecordID > cursor with -Oldest and pages until caught up.
  - Security log clear/wrap left a high RecordId watermark that hid every new event.
  - Dns.GetHostEntry had no timeout and could stall historical scans for seconds per IP.
  - Live loop had no per-DC catch; one locked CSV or parse error stopped monitoring.
  - HTML replace used Move-Item, which fails when a browser has the report open.
  - AD lookup did not split HOST/service SPNs, so service enrichment usually missed.
#>
[CmdletBinding()]
param(
    [string[]]$DomainControllers,
    [switch]$DiscoverDCs,
    [switch]$IncludeRODCs,
    [string[]]$EvtxPath,
    [ValidateSet('Historical','Live','Both')][string]$Mode = 'Both',
    [ValidateRange(1,720)][int]$HoursBack = 24,
    [ValidateRange(2,3600)][int]$PollSeconds = 5,
    [switch]$IncludeOffered,
    [switch]$IncludeFailures,
    [switch]$ResolveHostnames,
    [switch]$EnrichAD,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputFolder = (Join-Path (Get-Location).Path 'RC4-Reports'),
    [ValidateRange(10,1000000)][int]$MaxHistoryEventsPerDC = 100000,
    [ValidateRange(100,100000)][int]$LivePageSize = 20000,
    [ValidateRange(250,15000)][int]$DnsTimeoutMs = 750,
    [switch]$SelfTest
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function ConvertTo-HtmlEncoded([object]$Value) {
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-CsvField([object]$Value) {
    $text = [string]$Value
    return '"' + $text.Replace('"','""') + '"'
}

function Get-NamedField {
    param($Table, [string[]]$Names)
    if ($null -eq $Table) { return '' }
    foreach ($n in $Names) {
        if ($Table.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace([string]$Table[$n])) {
            return [string]$Table[$n]
        }
    }
    return ''
}

function Get-EtypeCode {
    param([string]$Etype)
    if ([string]::IsNullOrWhiteSpace($Etype)) { return $null }
    $value = $Etype.Trim()
    if ($value -eq '-' -or $value -eq 'N/A') { return $null }

    if ($value -match '^(?i)0x([0-9a-f]+)$') {
        try { return [Convert]::ToInt32($Matches[1], 16) } catch { return $null }
    }

    $parsed = 0
    if ([int]::TryParse($value, [ref]$parsed)) { return $parsed }

    # Names from ClientAdvertizedEncryptionTypes / ticket fields. Check EXP first.
    switch -Regex ($value) {
        '(?i)RC4-HMAC-NT-EXP|RC4-HMAC-EXP|RC4-HMAC-OLD-EXP' { return 0x18 }
        '(?i)RC4|ARCFOUR' { return 0x17 }
        '(?i)AES256-SHA384|AES256-CTS-HMAC-SHA384' { return 0x14 }
        '(?i)AES128-SHA256|AES128-CTS-HMAC-SHA256' { return 0x13 }
        '(?i)AES256' { return 0x12 }
        '(?i)AES128' { return 0x11 }
        '(?i)DES-CBC-MD5|DES_CBC_MD5' { return 0x3 }
        '(?i)DES' { return 0x1 }
        default { return $null }
    }
}

function Test-IsRC4Etype {
    param([string]$Etype)
    $code = Get-EtypeCode $Etype
    if ($null -eq $code) { return $false }
    return ($code -eq 0x17 -or $code -eq 0x18)
}

function Get-EncryptionName {
    param([string]$Etype)
    if ([string]::IsNullOrWhiteSpace($Etype) -or $Etype.Trim() -eq '-' ) { return 'Not logged' }
    $code = Get-EtypeCode $Etype
    if ($null -eq $code) { return 'Other / unknown' }
    switch ($code) {
        0x1  { return 'DES-CBC-CRC' }
        0x3  { return 'DES-CBC-MD5' }
        0x11 { return 'AES128-SHA96' }
        0x12 { return 'AES256-SHA96' }
        0x13 { return 'AES128-SHA256' }
        0x14 { return 'AES256-SHA384' }
        0x17 { return 'RC4-HMAC' }
        0x18 { return 'RC4-HMAC-EXP' }
        default { return 'Other / unknown' }
    }
}

function Test-IsOfferedRC4 {
    param([string]$Advertised)
    if ([string]::IsNullOrWhiteSpace($Advertised) -or $Advertised.Trim() -eq '-') { return $false }
    if ($Advertised -match '(?i)RC4|ARCFOUR') { return $true }
    foreach ($token in ($Advertised -split '[,;|\s]+')) {
        if ([string]::IsNullOrWhiteSpace($token)) { continue }
        if (Test-IsRC4Etype $token) { return $true }
    }
    return $false
}

function Test-IsKerberosSuccess {
    param([string]$Status)
    if ([string]::IsNullOrWhiteSpace($Status) -or $Status.Trim() -eq '-') { return $true }
    $value = $Status.Trim()
    if ($value -match '^(?i)0x0+$') { return $true }
    $code = 0
    if ([int]::TryParse($value, [ref]$code)) { return ($code -eq 0) }
    return $false
}

function ConvertTo-NormalizedIp {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address) -or $Address.Trim() -eq '-') { return '' }
    $ip = $Address.Trim() -replace '^::ffff:','' -replace '^\[|\]$','' -replace '%\d+$',''
    return $ip
}

function Test-IsLocalComputerName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $n = $Name.Trim()
    if ($n -in @('.', 'localhost', '127.0.0.1', '::1')) { return $true }
    if ($n -eq $env:COMPUTERNAME) { return $true }
    if (-not [string]::IsNullOrWhiteSpace($env:USERDNSDOMAIN) -and
        $n -eq ($env:COMPUTERNAME + '.' + $env:USERDNSDOMAIN)) { return $true }
    return $false
}

function Test-IsNoMatchingEventsError {
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return $false }
    $fqid = [string]$ErrorRecord.FullyQualifiedErrorId
    $message = [string]$ErrorRecord.Exception.Message
    return (
        $fqid -match 'NoMatchingEventsFound' -or
        $message -match 'No events were found' -or
        $message -match 'No matching events found'
    )
}

function Get-EventXmlText {
    param($Event)
    if ($null -eq $Event) { return '' }
    if ($Event -is [string]) { return $Event }
    $xmlProp = $Event.PSObject.Properties['XmlText']
    if ($null -ne $xmlProp -and -not [string]::IsNullOrWhiteSpace([string]$xmlProp.Value)) {
        return [string]$xmlProp.Value
    }
    return [string]$Event.ToXml()
}

function Get-EventFields {
    param($Event)
    $result = @{}
    $xmlText = Get-EventXmlText $Event
    if ([string]::IsNullOrWhiteSpace($xmlText)) { return $result }

    $doc = New-Object System.Xml.XmlDocument
    $doc.XmlResolver = $null
    try { $doc.LoadXml($xmlText) } catch { return $result }

    # local-name() is required because Security events use a default xmlns.
    # GetAttribute('Name') is required on Windows PowerShell 5.1: XmlElement.Name is
    # the tag ("Data"), not the Name attribute ("TicketEncryptionType").
    $nodes = $doc.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")
    if ($null -eq $nodes) { return $result }
    foreach ($node in $nodes) {
        $name = $node.GetAttribute('Name')
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $result[$name] = [string]$node.InnerText
    }
    return $result
}

function Resolve-ClientHostname {
    param([string]$Address)
    if (-not $script:DoResolveHostnames -or [string]::IsNullOrWhiteSpace($Address)) { return '' }
    $ip = ConvertTo-NormalizedIp $Address
    if ([string]::IsNullOrWhiteSpace($ip)) { return '' }
    if ($ip -in @('127.0.0.1', '::1', '0.0.0.0')) { return '' }
    if ($script:DnsCache.ContainsKey($ip)) { return $script:DnsCache[$ip] }

    $name = ''
    try {
        $parsed = [System.Net.IPAddress]::Parse($ip)
        $async = [System.Net.Dns]::GetHostEntryAsync($parsed)
        if ($async.Wait($script:DnsTimeoutMs)) {
            if ($async.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion -and $null -ne $async.Result) {
                $name = [string]$async.Result.HostName
            }
        }
    } catch { }
    $script:DnsCache[$ip] = $name
    return $name
}

function ConvertTo-LdapEscaped {
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    return $Value.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29').Replace([string][char]0,'\00')
}

function Get-SamAccountCandidate {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Trim() -eq '-') { return '' }
    $short = ($Name -split '@')[0]
    $short = ($short -split '\\')[-1]
    $short = ($short -split '/')[-1]
    return $short.Trim()
}

function Find-ADIdentity {
    param([string]$Name)
    if (-not $script:DoEnrichAD -or [string]::IsNullOrWhiteSpace($Name) -or $Name.Trim() -eq '-') { return '' }
    if ($script:AdCache.ContainsKey($Name)) { return $script:AdCache[$Name] }

    $result = ''
    try {
        $short = Get-SamAccountCandidate $Name
        if ([string]::IsNullOrWhiteSpace($short)) {
            $script:AdCache[$Name] = ''
            return ''
        }
        $escaped = ConvertTo-LdapEscaped $short
        $filter = "(|(sAMAccountName=$escaped)(sAMAccountName=$escaped$)(servicePrincipalName=$escaped))"
        $adSplat = @{
            LDAPFilter  = $filter
            Properties  = @('distinguishedName','objectClass')
            ErrorAction = 'Stop'
        }
        if ($script:Credential) { $adSplat['Credential'] = $script:Credential }
        $match = Get-ADObject @adSplat | Select-Object -First 1
        if ($match) { $result = [string]$match.DistinguishedName }
    } catch { }
    $script:AdCache[$Name] = $result
    return $result
}

function New-EmptyFinding {
    $row = [ordered]@{}
    foreach ($column in $script:ReportColumns) { $row[$column] = '' }
    return [pscustomobject]$row
}

function Convert-KerberosEvent {
    param($Event, [string]$SourceName)
    try { $data = Get-EventFields $Event } catch {
        Write-Warning "Unable to parse event on ${SourceName}: $($_.Exception.Message)"
        return $null
    }

    $ticket  = Get-NamedField $data @('TicketEncryptionType')
    $session = Get-NamedField $data @('SessionKeyEncryptionType','SessionEncryptionType')
    $offered = Get-NamedField $data @('ClientAdvertizedEncryptionTypes','ClientAdvertisedEncryptionTypes','AdvertizedEtypes','AdvertisedEtypes')
    $status  = Get-NamedField $data @('Status')
    $success = Test-IsKerberosSuccess $status
    $ticketRc4  = Test-IsRC4Etype $ticket
    $sessionRc4 = Test-IsRC4Etype $session
    $offeredRc4 = Test-IsOfferedRC4 $offered

    $category = ''
    if ($success -and $ticketRc4 -and $sessionRc4) { $category = 'RC4 Ticket + Session' }
    elseif ($success -and $ticketRc4) { $category = 'RC4 Ticket' }
    elseif ($success -and $sessionRc4) { $category = 'RC4 Session' }
    elseif ($script:DoIncludeFailures -and -not $success -and ($ticketRc4 -or $sessionRc4 -or $offeredRc4)) { $category = 'Failed / RC4 Observed' }
    elseif ($success -and $script:DoIncludeOffered -and $offeredRc4) { $category = 'RC4 Offered Only' }
    else { return $null }

    $account = Get-NamedField $data @('TargetUserName','AccountName')
    $domain  = Get-NamedField $data @('TargetDomainName','AccountDomain')
    $service = Get-NamedField $data @('ServiceName')
    $spn     = Get-NamedField $data @('ServicePrincipalName')
    $ip      = ConvertTo-NormalizedIp (Get-NamedField $data @('IpAddress','ClientAddress'))
    $eventId = 0
    try { $eventId = [int]$Event.Id } catch { $eventId = 0 }
    $requestType = if ($eventId -eq 4768) { 'AS' } elseif ($eventId -eq 4769) { 'TGS' } else { '' }

    $when = Get-Date
    try { $when = [datetime]$Event.TimeCreated } catch { }

    $row = New-EmptyFinding
    $row.WhenLocal = $when.ToString('yyyy-MM-dd HH:mm:ss')
    $row.WhenUtc = $when.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $row.DomainController = $SourceName
    $row.EventId = $eventId
    $row.RequestType = $requestType
    $row.RecordId = $Event.RecordId
    $row.Category = $category
    $row.Account = $account
    $row.AccountDomain = $domain
    $row.AccountADObject = (Find-ADIdentity $account)
    $row.ClientIP = $ip
    $row.ClientPort = (Get-NamedField $data @('IpPort','ClientPort'))
    $row.ClientHostname = (Resolve-ClientHostname $ip)
    $row.ServiceName = $service
    $row.ServiceSPNIfLogged = $spn
    $row.ServiceADObject = (Find-ADIdentity $service)
    $row.TicketEtype = $ticket
    $row.TicketCipher = (Get-EncryptionName $ticket)
    $row.SessionEtype = $session
    $row.SessionCipher = (Get-EncryptionName $session)
    $row.AdvertisedEtypes = ($offered -replace '[\r\n]+','; ')
    $row.AccountSupportedEtypes = (Get-NamedField $data @('AccountSupportedEncryptionTypes'))
    $row.ServiceSupportedEtypes = (Get-NamedField $data @('ServiceSupportedEncryptionTypes'))
    $row.DCSupportedEtypes = (Get-NamedField $data @('DCSupportedEncryptionTypes'))
    $row.AccountAvailableKeys = (Get-NamedField $data @('AccountAvailableKeys'))
    $row.ServiceAvailableKeys = (Get-NamedField $data @('ServiceAvailableKeys'))
    $row.DCAvailableKeys = (Get-NamedField $data @('DCAvailableKeys'))
    $row.Status = $status
    return $row
}

function Initialize-CsvFile {
    $header = ($script:ReportColumns | ForEach-Object { ConvertTo-CsvField $_ }) -join ','
    [System.IO.File]::WriteAllText($script:CsvPath, $header + [Environment]::NewLine, $script:Utf8NoBom)
}

function Save-Finding {
    param($Row)
    if ($null -eq $Row) { return }
    [void]$script:Records.Add($Row)
    $line = ($script:ReportColumns | ForEach-Object {
        $prop = $Row.PSObject.Properties[$_]
        $val = if ($null -ne $prop) { $prop.Value } else { '' }
        ConvertTo-CsvField $val
    }) -join ','
    [System.IO.File]::AppendAllText($script:CsvPath, $line + [Environment]::NewLine, $script:Utf8NoBom)

    $color = 'Cyan'
    if ($Row.Category -like 'RC4 Ticket*') { $color = 'Red' }
    elseif ($Row.Category -like 'RC4 Session*') { $color = 'Yellow' }
    Write-Host ('[{0}] {1} {2} | {3} {4} | Account={5} | Client={6} {7} | Service={8} | Ticket={9} | Session={10}' -f `
        $Row.WhenLocal, $Row.DomainController, $Row.Category, $Row.RequestType, $Row.EventId, `
        $Row.Account, $Row.ClientIP, $Row.ClientHostname, $Row.ServiceName, $Row.TicketEtype, $Row.SessionEtype) `
        -ForegroundColor $color
}

function Write-HtmlReport {
    $total = $script:Records.Count
    $ticketCount = 0
    $sessionCount = 0
    $offeredCount = 0
    $escRows = New-Object System.Text.StringBuilder
    foreach ($r in $script:Records) {
        if ($r.Category -like '*Ticket*') { $ticketCount++ }
        if ($r.Category -like '*Session*') { $sessionCount++ }
        if ($r.Category -eq 'RC4 Offered Only') { $offeredCount++ }
        [void]$escRows.Append('<tr>')
        foreach ($field in $script:ReportColumns) {
            $prop = $r.PSObject.Properties[$field]
            $val = if ($null -ne $prop) { $prop.Value } else { '' }
            [void]$escRows.Append('<td>' + (ConvertTo-HtmlEncoded $val) + '</td>')
        }
        [void]$escRows.AppendLine('</tr>')
    }
    $heads = ($script:ReportColumns | ForEach-Object { '<th>' + (ConvertTo-HtmlEncoded $_) + '</th>' }) -join ''
    $generated = ConvertTo-HtmlEncoded ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
    $html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Kerberos RC4 Investigation</title>
<style>body{font:14px Segoe UI,Arial,sans-serif;background:#f4f6fa;color:#172338;margin:24px}h1{margin-bottom:4px}.muted{color:#5c6677}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}.card{background:white;border:1px solid #dbe1eb;border-radius:9px;padding:15px;min-width:150px}.num{font-size:28px;font-weight:700}.pane{overflow:auto;max-height:70vh;background:white;border:1px solid #dbe1eb;border-radius:8px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{padding:9px 10px;border-bottom:1px solid #e8edf2;text-align:left;white-space:nowrap}th{position:sticky;top:0;background:#eaf0f6}tr:hover{background:#f2f8fe}input{width:min(550px,90%);padding:10px;border:1px solid #abb8c8;border-radius:6px;margin:12px 0}.note{max-width:1100px;line-height:1.5}</style></head><body>
<h1>Kerberos RC4 Investigation</h1><div class="muted">Updated $generated | Event IDs 4768, 4769 | read-only collection</div>
<div class="cards"><div class="card">Records<div class="num">$total</div></div><div class="card">RC4 ticket categories<div class="num">$ticketCount</div></div><div class="card">RC4 session categories<div class="num">$sessionCount</div></div><div class="card">Offered only<div class="num">$offeredCount</div></div></div>
<p class="note"><b>Interpretation:</b> RC4 Ticket / RC4 Session categories require a successful event and a matching encryption field (0x17 / 23 or 0x18 / 24). "RC4 Offered Only" is not proof of RC4 ticket issuance — Windows clients commonly still advertise RC4 while receiving AES tickets. Older or unpatched DCs omit session and advertised fields. Event 4769 ServiceName often names the service account, not the complete SPN. DNS and AD enrichment are best effort.</p>
<input id="q" placeholder="Search accounts, clients, ciphers, services, DCs..." oninput="filterRows()" aria-label="Search records"><span id="shown"></span>
<div class="pane"><table id="events"><thead><tr>$heads</tr></thead><tbody>$($escRows.ToString())</tbody></table></div>
<script>function filterRows(){var q=document.getElementById('q').value.toLowerCase();var rows=document.querySelectorAll('#events tbody tr');var n=0;rows.forEach(function(r){var yes=r.textContent.toLowerCase().includes(q);r.style.display=yes?'':'none';if(yes)n++});document.getElementById('shown').textContent=' Showing '+n+' of '+rows.length;}filterRows();</script></body></html>
"@
    try {
        [System.IO.File]::WriteAllText($script:HtmlPath, $html, $script:Utf8NoBom)
    } catch {
        $tmp = $script:HtmlPath + '.tmp'
        [System.IO.File]::WriteAllText($tmp, $html, $script:Utf8NoBom)
        try {
            Copy-Item -LiteralPath $tmp -Destination $script:HtmlPath -Force
        } catch {
            Write-Warning "Unable to refresh HTML report (file may be open): $($_.Exception.Message)"
        }
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function New-KerberosQueryXml {
    param(
        [datetime]$Since,
        [int64]$AfterRecordId = -1,
        [switch]$RecordIdOnly
    )
    $utc = $Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $conditions = '(EventID=4768 or EventID=4769)'
    if ($AfterRecordId -ge 0) {
        $conditions += " and EventRecordID&gt;$AfterRecordId"
    }
    if (-not $RecordIdOnly) {
        $conditions += " and TimeCreated[@SystemTime&gt;='$utc']"
    }
    return @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[$conditions]]</Select>
  </Query>
</QueryList>
"@
}

function Get-WinEventSplat {
    param(
        [string]$ComputerName,
        [string]$Path,
        [xml]$FilterXml,
        [string]$FilterXPath,
        [int]$MaxEvents,
        [switch]$Oldest
    )
    $splat = @{ ErrorAction = 'Stop' }
    if ($MaxEvents -gt 0) { $splat['MaxEvents'] = $MaxEvents }
    if ($Oldest) { $splat['Oldest'] = $true }
    if ($script:Credential) { $splat['Credential'] = $script:Credential }

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $splat['Path'] = $Path
        if ($FilterXPath) { $splat['FilterXPath'] = $FilterXPath }
        return $splat
    }

    if ($FilterXml) { $splat['FilterXml'] = $FilterXml }
    elseif ($FilterXPath) {
        $splat['LogName'] = 'Security'
        $splat['FilterXPath'] = $FilterXPath
    }
    else {
        $splat['LogName'] = 'Security'
    }

    if (-not [string]::IsNullOrWhiteSpace($ComputerName) -and -not (Test-IsLocalComputerName $ComputerName)) {
        $splat['ComputerName'] = $ComputerName
    }
    return $splat
}

function Read-KerberosEvents {
    param(
        [string]$ComputerName,
        [string]$Path,
        [datetime]$Since,
        [int]$Max,
        [int64]$AfterRecordId = -1,
        [switch]$Oldest,
        [switch]$RecordIdOnly
    )
    try {
        if ($Path) {
            $xpath = "*[System[(EventID=4768 or EventID=4769) and TimeCreated[@SystemTime>='$($Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))']]]"
            $splat = Get-WinEventSplat -Path $Path -FilterXPath $xpath -MaxEvents $Max -Oldest:$Oldest
            return @(Get-WinEvent @splat)
        }
        $query = New-KerberosQueryXml -Since $Since -AfterRecordId $AfterRecordId -RecordIdOnly:$RecordIdOnly
        $splat = Get-WinEventSplat -ComputerName $ComputerName -FilterXml ([xml]$query) -MaxEvents $Max -Oldest:$Oldest
        return @(Get-WinEvent @splat)
    } catch {
        if (Test-IsNoMatchingEventsError $_) { return @() }
        $target = if ($Path) { $Path } else { $ComputerName }
        Write-Warning "Cannot read Security events from ${target}: $($_.Exception.Message)"
        return @()
    }
}

function Get-NewestSecurityRecordId {
    param([string]$ComputerName)
    try {
        $splat = Get-WinEventSplat -ComputerName $ComputerName -MaxEvents 1
        $newest = @(Get-WinEvent @splat)
        if ($newest.Count -gt 0) { return [int64]$newest[0].RecordId }
    } catch {
        Write-Warning "Unable to read newest Security record on ${ComputerName}: $($_.Exception.Message)"
    }
    return [int64]0
}

function Test-SecurityLogWrapped {
    param([string]$ComputerName, [int64]$Cursor)
    if ($Cursor -le 0) { return $false }
    $newest = Get-NewestSecurityRecordId $ComputerName
    return ($newest -gt 0 -and $newest -lt $Cursor)
}

function Import-ActiveDirectoryModule {
    param([string]$Reason)
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        return $true
    } catch {
        if ($Reason -eq 'required') {
            throw "ActiveDirectory module is required. Install RSAT ActiveDirectory tools and verify domain connectivity: $_"
        }
        Write-Warning "ActiveDirectory module unavailable; $Reason disabled. $_"
        return $false
    }
}

# ---------------------------------------------------------------------------
# Self-test (no DC / event log required)
# ---------------------------------------------------------------------------

function New-MockKerberosEvent {
    param(
        [int]$Id = 4769,
        [long]$RecordId = 1,
        [datetime]$TimeCreated = ([datetime]'2026-10-28T12:00:00'),
        [string]$Ticket = '0x17',
        [string]$Session = '0x12',
        [string]$Offered = 'AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96 RC4-HMAC-NT',
        [string]$Status = '0x0',
        [string]$Account = 'jsmith@CONTOSO.LOCAL',
        [string]$Domain = 'CONTOSO.LOCAL',
        [string]$Service = 'HOST/dc01.contoso.local',
        [string]$Ip = '::ffff:10.10.10.25',
        [string]$AccountSet = '0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)',
        [string]$ServiceSet = '0x18 (AES128-SHA96, AES256-SHA96)'
    )
    $xml = @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>$Id</EventID>
    <EventRecordID>$RecordId</EventRecordID>
    <TimeCreated SystemTime="$($TimeCreated.ToUniversalTime().ToString('o'))" />
  </System>
  <EventData>
    <Data Name="TargetUserName">$Account</Data>
    <Data Name="TargetDomainName">$Domain</Data>
    <Data Name="ServiceName">$Service</Data>
    <Data Name="TicketEncryptionType">$Ticket</Data>
    <Data Name="IpAddress">$Ip</Data>
    <Data Name="IpPort">54321</Data>
    <Data Name="Status">$Status</Data>
    <Data Name="AccountSupportedEncryptionTypes">$AccountSet</Data>
    <Data Name="ServiceSupportedEncryptionTypes">$ServiceSet</Data>
    <Data Name="DCSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data>
    <Data Name="ClientAdvertizedEncryptionTypes">$Offered</Data>
    <Data Name="SessionKeyEncryptionType">$Session</Data>
  </EventData>
</Event>
"@
    return [pscustomobject]@{
        Id          = $Id
        RecordId    = $RecordId
        TimeCreated = $TimeCreated
        XmlText     = $xml
    }
}

function Invoke-KerberosRc4SelfTest {
    $script:SelfTestPassed = 0
    $script:SelfTestFailed = 0
    $script:DoResolveHostnames = $false
    $script:DoEnrichAD = $false
    $script:DoIncludeOffered = $false
    $script:DoIncludeFailures = $false
    $script:Credential = $null
    $script:DnsTimeoutMs = 750
    $script:DnsCache = @{}
    $script:AdCache = @{}
    $script:ReportColumns = @(
        'WhenLocal','DomainController','EventId','RequestType','Category','Account','AccountDomain',
        'ClientIP','ClientHostname','ServiceName','ServiceSPNIfLogged','TicketEtype','TicketCipher',
        'SessionEtype','SessionCipher','AdvertisedEtypes','Status','AccountADObject','ServiceADObject',
        'AccountSupportedEtypes','ServiceSupportedEtypes','DCSupportedEtypes','AccountAvailableKeys',
        'ServiceAvailableKeys','DCAvailableKeys','WhenUtc','ClientPort','RecordId'
    )
    $script:Utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $script:Records = New-Object 'System.Collections.Generic.List[object]'

    function Assert-True {
        param([bool]$Condition, [string]$Name)
        if ($Condition) {
            $script:SelfTestPassed++
            Write-Host "  PASS  $Name" -ForegroundColor Green
        } else {
            $script:SelfTestFailed++
            Write-Host "  FAIL  $Name" -ForegroundColor Red
        }
    }

    Write-Host 'Watch-KerberosRC4-Enhanced self-test' -ForegroundColor Cyan
    Write-Host ''

    Assert-True -Condition (Test-IsRC4Etype '0x17') -Name '0x17 is RC4-HMAC'
    Assert-True -Condition (Test-IsRC4Etype '0x00000017') -Name '0x00000017 is RC4-HMAC'
    Assert-True -Condition (Test-IsRC4Etype '23') -Name 'Decimal 23 is RC4-HMAC'
    Assert-True -Condition (Test-IsRC4Etype '0x18') -Name '0x18 is RC4-HMAC-EXP'
    Assert-True -Condition (Test-IsRC4Etype '24') -Name 'Decimal 24 is RC4-HMAC-EXP'
    Assert-True -Condition (-not (Test-IsRC4Etype '0x12')) -Name '0x12 AES256 is not RC4'
    Assert-True -Condition (-not (Test-IsRC4Etype '18')) -Name 'Decimal 18 (AES256) is not RC4'
    Assert-True -Condition (-not (Test-IsRC4Etype '0x11')) -Name '0x11 AES128 is not RC4'
    Assert-True -Condition (-not (Test-IsRC4Etype '17')) -Name 'Decimal 17 (AES128) is not RC4'
    Assert-True -Condition (-not (Test-IsRC4Etype '0x1F')) -Name 'msDS-SET bitmask 0x1F is not a ticket etype RC4 hit'
    Assert-True -Condition ((Get-EncryptionName '0x17') -eq 'RC4-HMAC') -Name 'Get-EncryptionName maps 0x17'
    Assert-True -Condition ((Get-EncryptionName '0x12') -eq 'AES256-SHA96') -Name 'Get-EncryptionName maps 0x12'
    Assert-True -Condition ((Get-EncryptionName '') -eq 'Not logged') -Name 'Missing etype is Not logged'

    $offeredModern = 'AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96 RC4-HMAC-NT RC4-HMAC-NT-EXP RC4-HMAC-OLD-EXP'
    $offeredAesOnly = 'AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96'
    Assert-True -Condition (Test-IsOfferedRC4 $offeredModern) -Name 'Advertised RC4-HMAC-NT counts as offered'
    Assert-True -Condition (-not (Test-IsOfferedRC4 $offeredAesOnly)) -Name 'AES-only advertised list is not offered RC4'
    Assert-True -Condition (Test-IsOfferedRC4 '0x17 0x12') -Name 'Numeric advertised 0x17 counts as offered'
    Assert-True -Condition (-not (Test-IsOfferedRC4 '0x11 0x12')) -Name 'Numeric AES advertised list is not offered RC4'

    Assert-True -Condition (Test-IsKerberosSuccess '0x0') -Name 'Status 0x0 is success'
    Assert-True -Condition (Test-IsKerberosSuccess '0x00000000') -Name 'Status 0x00000000 is success'
    Assert-True -Condition (Test-IsKerberosSuccess '0') -Name 'Status 0 is success'
    Assert-True -Condition (-not (Test-IsKerberosSuccess '0x12')) -Name 'Status 0x12 is failure'
    Assert-True -Condition ((ConvertTo-NormalizedIp '::ffff:10.1.2.3') -eq '10.1.2.3') -Name 'Strips IPv4-mapped IPv6 prefix'
    Assert-True -Condition ((Get-SamAccountCandidate 'HOST/dc01.contoso.local') -eq 'dc01.contoso.local') -Name 'SPN splits on slash'
    Assert-True -Condition ((Get-SamAccountCandidate 'CONTOSO\sqlsvc') -eq 'sqlsvc') -Name 'DOMAIN\user splits to SAM'
    Assert-True -Condition ((Get-SamAccountCandidate 'jsmith@CONTOSO.LOCAL') -eq 'jsmith') -Name 'UPN splits to SAM'
    Assert-True -Condition ((ConvertTo-LdapEscaped 'a*b(c)') -eq 'a\2ab\28c\29') -Name 'LDAP special characters are escaped'

    $namespaced = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="SessionKeyEncryptionType">0x12</Data>
    <Data Name="TargetUserName">alice@CONTOSO.LOCAL</Data>
  </EventData>
</Event>
'@
    $doc = New-Object System.Xml.XmlDocument
    $doc.XmlResolver = $null
    $doc.LoadXml($namespaced)
    $dataNode = $doc.SelectSingleNode("//*[local-name()='Data']")
    $nameProp = [string]$dataNode.Name
    Assert-True -Condition ($nameProp -eq 'Data' -or $nameProp -eq 'TicketEncryptionType') `
        -Name 'XmlElement.Name is version-dependent; parser does not rely on it'
    Assert-True -Condition ($dataNode.GetAttribute('Name') -eq 'TicketEncryptionType') `
        -Name 'GetAttribute(Name) returns TicketEncryptionType on namespaced Data nodes'
    $fields = Get-EventFields $namespaced
    Assert-True -Condition ($fields['TicketEncryptionType'] -eq '0x17') `
        -Name 'Get-EventFields reads TicketEncryptionType via Name attribute, not the Data tag'
    Assert-True -Condition ($fields['TargetUserName'] -eq 'alice@CONTOSO.LOCAL') `
        -Name 'Get-EventFields keeps distinct field names (does not collapse onto Data)'

    $script:DoIncludeOffered = $false
    $rc4Ticket = Convert-KerberosEvent (New-MockKerberosEvent -Ticket '0x17' -Session '0x12') 'DC01'
    Assert-True -Condition ($null -ne $rc4Ticket -and $rc4Ticket.Category -eq 'RC4 Ticket') `
        -Name 'Successful 0x17 ticket / AES session classifies as RC4 Ticket'
    Assert-True -Condition ($rc4Ticket.ClientIP -eq '10.10.10.25') -Name 'Client IP strips ::ffff:'
    Assert-True -Condition ($rc4Ticket.RequestType -eq 'TGS') -Name 'Event 4769 is RequestType TGS'
    Assert-True -Condition ($rc4Ticket.TicketCipher -eq 'RC4-HMAC') -Name 'Ticket cipher name is RC4-HMAC'
    Assert-True -Condition ($rc4Ticket.SessionCipher -eq 'AES256-SHA96') -Name 'Session cipher name is AES256-SHA96'

    $both = Convert-KerberosEvent (New-MockKerberosEvent -Ticket '23' -Session '0x18') 'DC01'
    Assert-True -Condition ($null -ne $both -and $both.Category -eq 'RC4 Ticket + Session') `
        -Name 'Decimal 23 ticket + 0x18 session classifies as RC4 Ticket + Session'

    $sessionOnly = Convert-KerberosEvent (New-MockKerberosEvent -Ticket '0x12' -Session '0x17' -Id 4768) 'DC01'
    Assert-True -Condition ($null -ne $sessionOnly -and $sessionOnly.Category -eq 'RC4 Session') `
        -Name 'AES ticket + RC4 session classifies as RC4 Session'
    Assert-True -Condition ($sessionOnly.RequestType -eq 'AS') -Name 'Event 4768 is RequestType AS'

    $aesOnly = Convert-KerberosEvent (New-MockKerberosEvent -Ticket '0x12' -Session '0x12') 'DC01'
    Assert-True -Condition ($null -eq $aesOnly) -Name 'AES ticket + AES session is ignored by default'

    $script:DoIncludeOffered = $true
    $offeredOnly = Convert-KerberosEvent (New-MockKerberosEvent -Ticket '0x12' -Session '0x12') 'DC01'
    Assert-True -Condition ($null -ne $offeredOnly -and $offeredOnly.Category -eq 'RC4 Offered Only') `
        -Name '-IncludeOffered keeps AES tickets that advertised RC4'
    $script:DoIncludeOffered = $false

    $script:DoIncludeFailures = $true
    $failed = Convert-KerberosEvent (New-MockKerberosEvent -Ticket '0x17' -Status '0x12') 'DC01'
    Assert-True -Condition ($null -ne $failed -and $failed.Category -eq 'Failed / RC4 Observed') `
        -Name '-IncludeFailures keeps failed events that show RC4'
    $script:DoIncludeFailures = $false
    $failedHidden = Convert-KerberosEvent (New-MockKerberosEvent -Ticket '0x17' -Status '0x12') 'DC01'
    Assert-True -Condition ($null -eq $failedHidden) -Name 'Failed RC4 events are ignored without -IncludeFailures'

    $oldSchema = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">legacy@CONTOSO.LOCAL</Data>
    <Data Name="TargetDomainName">CONTOSO.LOCAL</Data>
    <Data Name="ServiceName">krbtgt</Data>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="IpAddress">::ffff:10.0.0.9</Data>
    <Data Name="IpPort">1</Data>
    <Data Name="Status">0x0</Data>
  </EventData>
</Event>
'@
    $legacyEvent = [pscustomobject]@{ Id = 4769; RecordId = 50; TimeCreated = Get-Date; XmlText = $oldSchema }
    $legacyRow = Convert-KerberosEvent $legacyEvent 'DC01'
    Assert-True -Condition ($null -ne $legacyRow -and $legacyRow.Category -eq 'RC4 Ticket') `
        -Name 'Pre-2025 4769 schema (no session field) still detects RC4 tickets'
    Assert-True -Condition ($legacyRow.SessionCipher -eq 'Not logged') `
        -Name 'Missing SessionKeyEncryptionType is reported as Not logged'

    $tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('RC4SelfTest_' + [guid]::NewGuid().ToString('N'))
    New-Item -Path $tmpRoot -ItemType Directory -Force | Out-Null
    $script:CsvPath = Join-Path $tmpRoot 'test.csv'
    $script:HtmlPath = Join-Path $tmpRoot 'test.html'
    Initialize-CsvFile
    Save-Finding $rc4Ticket
    Save-Finding $both
    Write-HtmlReport
    $csvLines = @(Get-Content -LiteralPath $script:CsvPath)
    Assert-True -Condition ($csvLines.Count -eq 3) -Name 'CSV has header plus two data rows'
    Assert-True -Condition ($csvLines[0].StartsWith('"WhenLocal"')) -Name 'CSV header starts with WhenLocal (no UTF-8 BOM on first column)'
    $headerCols = ($csvLines[0] -split '","').Count
    $dataCols = ($csvLines[1] -split '","').Count
    Assert-True -Condition ($headerCols -eq $dataCols -and $headerCols -eq $script:ReportColumns.Count) `
        -Name 'CSV header and data row have the same column count as ReportColumns'
    $html = Get-Content -LiteralPath $script:HtmlPath -Raw
    Assert-True -Condition ($html -match 'RC4 Ticket') -Name 'HTML report contains the RC4 Ticket finding'
    Assert-True -Condition ($html -match 'jsmith@CONTOSO.LOCAL') -Name 'HTML report contains the account name'
    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue

    $noMatchErr = [pscustomobject]@{
        FullyQualifiedErrorId = 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand'
        Exception = [pscustomobject]@{ Message = 'No events were found that match the specified selection criteria.' }
    }
    Assert-True -Condition (Test-IsNoMatchingEventsError $noMatchErr) -Name 'Empty event-log results are treated as no matches, not a fatal error'
    Assert-True -Condition (Test-IsLocalComputerName '.') -Name 'Dot is treated as the local computer'
    Assert-True -Condition (Test-IsLocalComputerName 'localhost') -Name 'localhost is treated as the local computer'

    $qTime = New-KerberosQueryXml -Since ([datetime]'2026-10-28T00:00:00Z')
    $timeXPath = ([xml]$qTime).QueryList.Query.Select.InnerText
    Assert-True -Condition ($timeXPath -match 'EventID=4768' -and $timeXPath -match 'TimeCreated' -and $timeXPath -match "SystemTime>='2026-10-28T00:00:00.000Z'") `
        -Name 'Historical query XML includes event IDs and a quoted UTC TimeCreated filter'
    $qLive = New-KerberosQueryXml -Since ([datetime]'2026-10-28T00:00:00Z') -AfterRecordId 12345 -RecordIdOnly
    $liveXPath = ([xml]$qLive).QueryList.Query.Select.InnerText
    Assert-True -Condition ($liveXPath -match 'EventRecordID>12345' -and $liveXPath -notmatch 'TimeCreated') `
        -Name 'Live catch-up query uses EventRecordID and omits TimeCreated to avoid clock-skew gaps'

    Write-Host ''
    Write-Host ('  {0} passed, {1} failed' -f $script:SelfTestPassed, $script:SelfTestFailed) `
        -ForegroundColor $(if ($script:SelfTestFailed) { 'Red' } else { 'Green' })
    return ($script:SelfTestFailed -eq 0)
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if ($SelfTest) {
    $ok = Invoke-KerberosRc4SelfTest
    if ($ok) { exit 0 } else { exit 1 }
}

$script:DoResolveHostnames = [bool]$ResolveHostnames
$script:DoEnrichAD = [bool]$EnrichAD
$script:DoIncludeOffered = [bool]$IncludeOffered
$script:DoIncludeFailures = [bool]$IncludeFailures
$script:Credential = $Credential
$script:DnsTimeoutMs = $DnsTimeoutMs
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding $false
$script:DnsCache = @{}
$script:AdCache = @{}
$script:Records = New-Object 'System.Collections.Generic.List[object]'
$script:ReportColumns = @(
    'WhenLocal','DomainController','EventId','RequestType','Category','Account','AccountDomain',
    'ClientIP','ClientHostname','ServiceName','ServiceSPNIfLogged','TicketEtype','TicketCipher',
    'SessionEtype','SessionCipher','AdvertisedEtypes','Status','AccountADObject','ServiceADObject',
    'AccountSupportedEtypes','ServiceSupportedEtypes','DCSupportedEtypes','AccountAvailableKeys',
    'ServiceAvailableKeys','DCAvailableKeys','WhenUtc','ClientPort','RecordId'
)

$evtxFiles = @()
if ($EvtxPath) {
    foreach ($p in $EvtxPath) {
        if (-not (Test-Path -LiteralPath $p)) { throw "EVTX file not found: $p" }
        $evtxFiles += (Resolve-Path -LiteralPath $p).Path
    }
}

if ($DiscoverDCs) {
    [void](Import-ActiveDirectoryModule -Reason 'required')
    $dcSplat = @{ Filter = '*'; ErrorAction = 'Stop' }
    if ($Credential) { $dcSplat['Credential'] = $Credential }
    $found = @(Get-ADDomainController @dcSplat)
    if (-not $IncludeRODCs) {
        $found = @($found | Where-Object { -not $_.IsReadOnly })
    }
    $DomainControllers = @($found | Select-Object -ExpandProperty HostName)
    if ($DomainControllers.Count -lt 1) {
        throw 'DC discovery returned no domain controllers. Specify -DomainControllers or add -IncludeRODCs.'
    }
}

if ($script:DoEnrichAD) {
    if (-not (Import-ActiveDirectoryModule -Reason 'AD enrichment')) { $script:DoEnrichAD = $false }
}

$controllers = @()
if ($DomainControllers) {
    $controllers = @($DomainControllers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

if ($evtxFiles.Count -lt 1 -and $controllers.Count -lt 1) {
    throw 'Specify -DomainControllers DC01,DC02, -DiscoverDCs, or -EvtxPath.'
}

if ($evtxFiles.Count -gt 0 -and $Mode -eq 'Live') {
    Write-Warning 'EVTX files are static. Live polling is skipped for -EvtxPath; running a one-shot historical scan.'
}

New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:CsvPath = Join-Path $OutputFolder "KerberosRC4_$stamp.csv"
$script:HtmlPath = Join-Path $OutputFolder "KerberosRC4_$stamp.html"
Initialize-CsvFile

$lastId = @{}
$lastScan = @{}
$targets = @()
foreach ($dc in $controllers) {
    $targets += [pscustomobject]@{ Kind = 'dc'; Name = $dc; Path = '' }
    $lastId[$dc] = [int64]0
    $lastScan[$dc] = Get-Date
}
foreach ($file in $evtxFiles) {
    $targets += [pscustomobject]@{ Kind = 'evtx'; Name = [System.IO.Path]::GetFileName($file); Path = $file }
    $lastId[$file] = [int64]0
    $lastScan[$file] = Get-Date
}

$targetNames = @($targets | ForEach-Object { if ($_.Kind -eq 'evtx') { $_.Path } else { $_.Name } })
Write-Host "Monitoring $($targetNames -join ', ') | Mode=$Mode | CSV=$script:CsvPath" -ForegroundColor Green

$runHistorical = ($Mode -eq 'Historical' -or $Mode -eq 'Both' -or $evtxFiles.Count -gt 0)
$runLive = ($Mode -eq 'Live' -or $Mode -eq 'Both') -and ($controllers.Count -gt 0) -and ($evtxFiles.Count -lt 1 -or $Mode -ne 'Historical')
if ($evtxFiles.Count -gt 0 -and $controllers.Count -lt 1) { $runLive = $false }

if ($runHistorical) {
    $since = (Get-Date).AddHours(-$HoursBack)
    foreach ($target in $targets) {
        Write-Host "Historical query $($target.Name) since $since" -ForegroundColor Gray
        if ($target.Kind -eq 'evtx') {
            $events = Read-KerberosEvents -Path $target.Path -Since $since -Max $MaxHistoryEventsPerDC
        } else {
            $events = Read-KerberosEvents -ComputerName $target.Name -Since $since -Max $MaxHistoryEventsPerDC
        }
        if ($events.Count -ge $MaxHistoryEventsPerDC) {
            Write-Warning "Hit -MaxHistoryEventsPerDC ($MaxHistoryEventsPerDC) on $($target.Name). Older matching events in the window were not read (Get-WinEvent returns the newest N). Increase the limit if needed."
        }
        foreach ($ev in ($events | Sort-Object RecordId)) {
            $key = if ($target.Kind -eq 'evtx') { $target.Path } else { $target.Name }
            if ([int64]$ev.RecordId -gt $lastId[$key]) { $lastId[$key] = [int64]$ev.RecordId }
            $row = Convert-KerberosEvent $ev $target.Name
            if ($null -ne $row) { Save-Finding $row }
        }
    }
} elseif ($runLive) {
    foreach ($dc in $controllers) {
        $lastId[$dc] = Get-NewestSecurityRecordId $dc
        $lastScan[$dc] = Get-Date
    }
}

Write-HtmlReport
Write-Host "HTML report: $script:HtmlPath" -ForegroundColor Green

if (-not $runLive) {
    Write-Host "Completed: $($script:Records.Count) findings."
    return
}

Write-Host 'Live monitoring. Press Ctrl+C to stop. HTML refreshes after each polling cycle.' -ForegroundColor Green
try {
    while ($true) {
        Start-Sleep -Seconds $PollSeconds
        foreach ($dc in $controllers) {
            try {
                if (Test-SecurityLogWrapped -ComputerName $dc -Cursor $lastId[$dc]) {
                    Write-Warning "Security log on $dc was cleared or wrapped. Resetting RecordId cursor."
                    $lastId[$dc] = [int64]0
                }
                $since = $lastScan[$dc].AddSeconds(-30)
                $useRecordIdOnly = ($lastId[$dc] -gt 0)
                $caughtUp = $false
                while (-not $caughtUp) {
                    $page = Read-KerberosEvents -ComputerName $dc -Since $since -Max $LivePageSize -AfterRecordId $lastId[$dc] -Oldest -RecordIdOnly:$useRecordIdOnly
                    if ($page.Count -lt 1) { $caughtUp = $true; break }
                    foreach ($ev in $page) {
                        $rid = [int64]$ev.RecordId
                        if ($rid -le $lastId[$dc]) { continue }
                        $lastId[$dc] = $rid
                        $row = Convert-KerberosEvent $ev $dc
                        if ($null -ne $row) { Save-Finding $row }
                    }
                    if ($page.Count -lt $LivePageSize) { $caughtUp = $true }
                    $useRecordIdOnly = ($lastId[$dc] -gt 0)
                }
                $lastScan[$dc] = Get-Date
            } catch {
                Write-Warning "Live poll failed for ${dc}: $($_.Exception.Message)"
            }
        }
        try { Write-HtmlReport } catch {
            Write-Warning "HTML refresh failed: $($_.Exception.Message)"
        }
    }
} finally {
    try { Write-HtmlReport } catch { }
    Write-Host "Stopped. Findings: $($script:Records.Count). CSV=$script:CsvPath" -ForegroundColor Green
}

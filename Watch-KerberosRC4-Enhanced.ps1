#requires -Version 5.1
<#
.SYNOPSIS
  Read-only Kerberos RC4 investigation and live monitoring for Windows Domain Controllers.

.DESCRIPTION
  Reads Security events 4768 (AS/TGT) and 4769 (TGS) from one or more DCs, exported EVTX
  files, or the local Security log. Classifies actual RC4 ticket and session-key encryption
  separately from merely advertised RC4, enriches hostnames and (optionally) AD identities,
  and writes CSV plus a self-contained searchable HTML report.

  Running the script with no targeting arguments opens a WinForms UI: pick DCs or EVTX
  files, toggle options, Start/Stop collection (including live monitoring), search and
  filter findings, and open the HTML/CSV reports. Pass -DomainControllers / -DiscoverDCs /
  -EvtxPath for the original non-interactive CLI. Use -Gui to open the UI with those
  values pre-filled.

  Before reading logs, the collector checks whether Kerberos auditing is enabled on each
  DC (Audit Kerberos Authentication Service for 4768, Audit Kerberos Service Ticket
  Operations for 4769). That check is read-only. Use -RequireAuditing to abort when a DC
  is not logging those events, or -SkipAuditCheck to bypass the preflight.

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
  .\Watch-KerberosRC4-Enhanced.ps1 -DomainControllers DC01 -Mode Live -LiveMinutes 30 -OutputFolder C:\Temp\RC4

  Watch live for 30 minutes, then stop and leave CSV/HTML in C:\Temp\RC4. 0 minutes (the default) runs until Ctrl+C or Stop.

.EXAMPLE
  .\Watch-KerberosRC4-Enhanced.ps1 -DomainControllers DC01 -Mode Both -RequireAuditing

  Abort instead of watching if 4768/4769 auditing is not enabled on DC01.

.EXAMPLE
  .\Watch-KerberosRC4-Enhanced.ps1 -EvtxPath C:\Temp\Security.evtx -Mode Historical

.EXAMPLE
  .\Watch-KerberosRC4-Enhanced.ps1

  Opens the interactive WinForms UI (default when no DC / EVTX arguments are given).

.EXAMPLE
  .\Watch-KerberosRC4-Enhanced.ps1 -Gui -DomainControllers DC01,DC02 -HoursBack 24

  Opens the UI with DC01 and DC02 already selected.

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
    [ValidateRange(0,10080)][int]$LiveMinutes = 0,
    [switch]$IncludeOffered,
    [switch]$IncludeFailures,
    [switch]$ResolveHostnames,
    [switch]$EnrichAD,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputFolder = (Join-Path (Get-Location).Path 'RC4-Reports'),
    [ValidateRange(10,1000000)][int]$MaxHistoryEventsPerDC = 100000,
    [ValidateRange(100,100000)][int]$LivePageSize = 20000,
    [ValidateRange(250,15000)][int]$DnsTimeoutMs = 750,
    [switch]$SkipAuditCheck,
    [switch]$RequireAuditing,
    [switch]$Gui,
    [switch]$NonInteractive,
    [switch]$SkipMain,
    [switch]$SelfTest
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:QuietHost = $false
$script:UiSync = $null
$script:CsvPath = ''
$script:HtmlPath = ''
$script:CancelRequested = $false
$script:DnsTimeoutMs = 750
$script:DoIncludeFailures = $false
$script:Ui = $null

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
    if (-not [string]::IsNullOrWhiteSpace($script:CsvPath)) {
        $line = ($script:ReportColumns | ForEach-Object {
            $prop = $Row.PSObject.Properties[$_]
            $val = if ($null -ne $prop) { $prop.Value } else { '' }
            ConvertTo-CsvField $val
        }) -join ','
        [System.IO.File]::AppendAllText($script:CsvPath, $line + [Environment]::NewLine, $script:Utf8NoBom)
    }

    if (-not $script:QuietHost) {
        $color = 'Cyan'
        if ($Row.Category -like 'RC4 Ticket*') { $color = 'Red' }
        elseif ($Row.Category -like 'RC4 Session*') { $color = 'Yellow' }
        Write-Host ('[{0}] {1} {2} | {3} {4} | Account={5} | Client={6} {7} | Service={8} | Ticket={9} | Session={10}' -f `
            $Row.WhenLocal, $Row.DomainController, $Row.Category, $Row.RequestType, $Row.EventId, `
            $Row.Account, $Row.ClientIP, $Row.ClientHostname, $Row.ServiceName, $Row.TicketEtype, $Row.SessionEtype) `
            -ForegroundColor $color
    }

    if ($null -ne $script:UiSync) {
        [void]$script:UiSync.Queue.Add($Row)
        $script:UiSync.FindingCount = $script:Records.Count
        $script:UiSync.CsvPath = $script:CsvPath
        $script:UiSync.HtmlPath = $script:HtmlPath
    }
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

function Get-ReportColumnList {
    return @(
        'WhenLocal','DomainController','EventId','RequestType','Category','Account','AccountDomain',
        'ClientIP','ClientHostname','ServiceName','ServiceSPNIfLogged','TicketEtype','TicketCipher',
        'SessionEtype','SessionCipher','AdvertisedEtypes','Status','AccountADObject','ServiceADObject',
        'AccountSupportedEtypes','ServiceSupportedEtypes','DCSupportedEtypes','AccountAvailableKeys',
        'ServiceAvailableKeys','DCAvailableKeys','WhenUtc','ClientPort','RecordId'
    )
}

function Get-GridColumnList {
    return @(
        'WhenLocal','Category','Account','AccountDomain','ClientIP','ClientHostname',
        'ServiceName','TicketCipher','SessionCipher','DomainController','RequestType',
        'EventId','Status','AdvertisedEtypes'
    )
}

function Test-ShouldStartInteractiveUi {
    param(
        [switch]$SelfTestPresent,
        [switch]$SkipMainPresent,
        [switch]$GuiPresent,
        [switch]$NonInteractivePresent,
        [string[]]$DomainControllerList,
        [switch]$DiscoverDCsPresent,
        [string[]]$EvtxPathList
    )
    if ($SelfTestPresent -or $SkipMainPresent -or $NonInteractivePresent) { return $false }
    if ($GuiPresent) { return $true }
    $hasDc = $false
    if ($DomainControllerList) {
        $hasDc = (@($DomainControllerList | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0)
    }
    $hasEvtx = $false
    if ($EvtxPathList) {
        $hasEvtx = (@($EvtxPathList | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0)
    }
    return -not ($hasDc -or [bool]$DiscoverDCsPresent -or $hasEvtx)
}

function ConvertTo-LikeLiteral {
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    return $Value.Replace("'","''").Replace('[','[[]').Replace('%','[%]').Replace('*','[*]')
}

function ConvertTo-DataViewFilter {
    param(
        [string]$Query,
        [string]$CategoryFilter = 'All'
    )
    $parts = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($CategoryFilter) -and $CategoryFilter -ne 'All') {
        $cat = ConvertTo-LikeLiteral $CategoryFilter
        if ($CategoryFilter -eq 'RC4 Ticket') {
            [void]$parts.Add("Category LIKE '%RC4 Ticket%'")
        } elseif ($CategoryFilter -eq 'RC4 Session') {
            [void]$parts.Add("Category LIKE '%Session%'")
        } else {
            [void]$parts.Add("Category = '$cat'")
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($Query)) {
        $like = "'%" + (ConvertTo-LikeLiteral $Query.Trim()) + "%'"
        $or = @()
        foreach ($col in (Get-GridColumnList)) {
            $or += "$col LIKE $like"
        }
        [void]$parts.Add('(' + ($or -join ' OR ') + ')')
    }
    if ($parts.Count -lt 1) { return '' }
    return ($parts -join ' AND ')
}

function Get-CategoryHighlightArgb {
    param([string]$Category)
    if ($Category -like 'RC4 Ticket*') { return [int[]](255, 228, 225) }
    if ($Category -like 'RC4 Session*') { return [int[]](255, 249, 196) }
    if ($Category -eq 'RC4 Offered Only') { return [int[]](220, 245, 255) }
    if ($Category -like 'Failed*') { return [int[]](232, 232, 232) }
    return [int[]](255, 255, 255)
}

function Test-IsStaApartment {
    return ([System.Threading.Thread]::CurrentThread.GetApartmentState().ToString() -eq 'STA')
}

function Get-LiveWatchDeadline {
    param(
        [int]$LiveMinutes,
        [datetime]$From = (Get-Date)
    )
    if ($LiveMinutes -le 0) { return $null }
    return $From.AddMinutes($LiveMinutes)
}

function Test-IsLiveWatchExpired {
    param(
        $Deadline,
        [datetime]$Now = (Get-Date)
    )
    if ($null -eq $Deadline) { return $false }
    return ($Now -ge [datetime]$Deadline)
}

function Get-LiveWatchStatusText {
    param(
        $Deadline,
        [int]$FindingCount = 0,
        [int]$LiveMinutes = 0,
        [datetime]$Now = (Get-Date)
    )
    if ($null -eq $Deadline) {
        return "Live monitoring until stopped | findings $FindingCount"
    }
    $remaining = [datetime]$Deadline - $Now
    if ($remaining.TotalSeconds -le 0) {
        return "Live watch of $LiveMinutes minute(s) finished | findings $FindingCount"
    }
    $mins = [int][Math]::Floor($remaining.TotalMinutes)
    $secs = [int][Math]::Floor($remaining.TotalSeconds % 60)
    return ('Live watch {0}m {1:D2}s remaining | findings {2}' -f $mins, $secs, $FindingCount)
}

function Test-IsCollectorCancelRequested {
    if ($script:CancelRequested) { return $true }
    if ($null -ne $script:UiSync) {
        try { return [bool]$script:UiSync.Cancel } catch { return $false }
    }
    return $false
}

function Write-CollectorStatus {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )
    if (-not $script:QuietHost) {
        $color = 'Gray'
        switch ($Level) {
            'WARN' { $color = 'Yellow' }
            'ERROR' { $color = 'Red' }
            'SUCCESS' { $color = 'Green' }
        }
        Write-Host $Message -ForegroundColor $color
    }
    if ($null -ne $script:UiSync) {
        $script:UiSync.Status = $Message
        if ($null -ne $script:UiSync.Log) {
            [void]$script:UiSync.Log.Add(('[{0}] [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message))
        }
    }
}

function Initialize-CollectorSession {
    param(
        [string]$OutputFolderPath,
        [bool]$ResolveHostnamesFlag,
        [bool]$EnrichADFlag,
        [bool]$IncludeOfferedFlag,
        [bool]$IncludeFailuresFlag,
        [int]$DnsTimeout,
        $CredentialObject,
        [bool]$Quiet = $false,
        [string]$ExistingCsvPath = '',
        [string]$ExistingHtmlPath = ''
    )
    $script:DoResolveHostnames = $ResolveHostnamesFlag
    $script:DoEnrichAD = $EnrichADFlag
    $script:DoIncludeOffered = $IncludeOfferedFlag
    $script:DoIncludeFailures = $IncludeFailuresFlag
    $script:Credential = $CredentialObject
    $script:DnsTimeoutMs = $DnsTimeout
    $script:QuietHost = $Quiet
    $script:CancelRequested = $false
    $script:Utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $script:DnsCache = @{}
    $script:AdCache = @{}
    $script:Records = New-Object 'System.Collections.Generic.List[object]'
    $script:ReportColumns = Get-ReportColumnList
    if ($script:DoEnrichAD) {
        if (-not (Import-ActiveDirectoryModule -Reason 'AD enrichment')) { $script:DoEnrichAD = $false }
    }
    if (-not [string]::IsNullOrWhiteSpace($ExistingCsvPath)) {
        $script:CsvPath = $ExistingCsvPath
        $script:HtmlPath = $ExistingHtmlPath
        if (-not (Test-Path -LiteralPath $script:CsvPath)) { Initialize-CsvFile }
        return
    }
    New-Item -Path $OutputFolderPath -ItemType Directory -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:CsvPath = Join-Path $OutputFolderPath "KerberosRC4_$stamp.csv"
    $script:HtmlPath = Join-Path $OutputFolderPath "KerberosRC4_$stamp.html"
    Initialize-CsvFile
}

function Get-CollectorTargetList {
    param(
        [string[]]$DomainControllerList,
        [string[]]$EvtxPathList,
        [switch]$Discover,
        [switch]$IncludeRODC
    )
    $controllers = @()
    $evtxFiles = @()
    if ($EvtxPathList) {
        foreach ($p in $EvtxPathList) {
            if ([string]::IsNullOrWhiteSpace($p)) { continue }
            if (-not (Test-Path -LiteralPath $p)) { throw "EVTX file not found: $p" }
            $evtxFiles += (Resolve-Path -LiteralPath $p).Path
        }
    }
    if ($Discover) {
        [void](Import-ActiveDirectoryModule -Reason 'required')
        $dcSplat = @{ Filter = '*'; ErrorAction = 'Stop' }
        if ($script:Credential) { $dcSplat['Credential'] = $script:Credential }
        $found = @(Get-ADDomainController @dcSplat)
        if (-not $IncludeRODC) {
            $found = @($found | Where-Object { -not $_.IsReadOnly })
        }
        $controllers = @($found | Select-Object -ExpandProperty HostName)
        if ($controllers.Count -lt 1) {
            throw 'DC discovery returned no domain controllers. Specify domain controllers or include RODCs.'
        }
    }
    if ($DomainControllerList) {
        $controllers = @($controllers + @($DomainControllerList | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }))
    }
    $controllers = @($controllers | Select-Object -Unique)
    $targets = @()
    foreach ($dc in $controllers) {
        $targets += [pscustomobject]@{ Kind = 'dc'; Name = $dc; Path = ''; Key = $dc }
    }
    foreach ($file in $evtxFiles) {
        $targets += [pscustomobject]@{ Kind = 'evtx'; Name = [System.IO.Path]::GetFileName($file); Path = $file; Key = $file }
    }
    return $targets
}

function Get-KerberosAuditGuidMap {
    return [ordered]@{
        'Kerberos Authentication Service'   = [guid]'0cce9242-69ae-11d9-bed3-505054503030'
        'Kerberos Service Ticket Operations' = [guid]'0cce9240-69ae-11d9-bed3-505054503030'
    }
}

function ConvertTo-AuditFlagPair {
    param(
        [string]$Inclusion,
        $SettingValue
    )
    $success = $false
    $failure = $false
    $n = 0
    if ($null -ne $SettingValue -and [int]::TryParse([string]$SettingValue, [ref]$n) -and $n -ge 0 -and $n -le 3) {
        if ($n -band 1) { $success = $true }
        if ($n -band 2) { $failure = $true }
        return @{ Success = $success; Failure = $failure; Value = $n }
    }
    $text = [string]$Inclusion
    if ($text -match '(?i)success') { $success = $true }
    if ($text -match '(?i)failure') { $failure = $true }
    $value = 0
    if ($success) { $value = $value -bor 1 }
    if ($failure) { $value = $value -bor 2 }
    return @{ Success = $success; Failure = $failure; Value = $value }
}

function ConvertFrom-AuditPolRaw {
    param(
        [string[]]$Lines,
        [guid]$Guid
    )
    if ($null -eq $Lines) { return $null }
    $bare = $Guid.ToString('D')
    foreach ($line in $Lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '(?i)^Machine Name,') { continue }
        if ($line -notmatch [regex]::Escape($bare)) { continue }
        $fields = $line.Split(',')
        $guidIndex = -1
        for ($i = 0; $i -lt $fields.Length; $i++) {
            if ($fields[$i] -match [regex]::Escape($bare)) { $guidIndex = $i; break }
        }
        if ($guidIndex -lt 0) { continue }
        $inclusion = ''
        $settingValue = $null
        if ($fields.Length -gt ($guidIndex + 1)) { $inclusion = $fields[$guidIndex + 1].Trim() }
        for ($j = $fields.Length - 1; $j -gt $guidIndex; $j--) {
            $parsed = 0
            $cell = $fields[$j].Trim()
            if ($cell -match '^\d+$' -and [int]::TryParse($cell, [ref]$parsed) -and $parsed -ge 0 -and $parsed -le 3) {
                $settingValue = $parsed
                break
            }
        }
        $flags = ConvertTo-AuditFlagPair -Inclusion $inclusion -SettingValue $settingValue
        $flags['Inclusion'] = $inclusion
        $flags['Found'] = $true
        return $flags
    }
    return $null
}

function Get-AuditPolSettingLabel {
    param($Flags)
    if ($null -eq $Flags) { return 'Unknown' }
    if ($Flags.Success -and $Flags.Failure) { return 'Success and Failure' }
    if ($Flags.Success) { return 'Success' }
    if ($Flags.Failure) { return 'Failure' }
    return 'No Auditing'
}

function Invoke-AuditPolRaw {
    param(
        [string]$ComputerName,
        [guid[]]$Guids
    )
    $guidArgs = ($Guids | ForEach-Object { $_.ToString('B') }) -join ','
    $scriptBlock = {
        param($SubcategoryArg)
        $exe = Join-Path $env:SystemRoot 'System32\auditpol.exe'
        if (-not (Test-Path -LiteralPath $exe)) { return @() }
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = & $exe @('/get', "/subcategory:$SubcategoryArg", '/r') 2>&1 | ForEach-Object { [string]$_ }
            if (-not $output -or ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne $null)) {
                $output = & $exe @('/get', "/subcategory:$SubcategoryArg") 2>&1 | ForEach-Object { [string]$_ }
            }
            return @($output)
        } finally {
            $ErrorActionPreference = $prev
        }
    }

    if ([string]::IsNullOrWhiteSpace($ComputerName) -or (Test-IsLocalComputerName $ComputerName)) {
        return @(& $scriptBlock $guidArgs)
    }

    try {
        $option = New-PSSessionOption -OpenTimeout 8000 -OperationTimeout 20000
        $sessSplat = @{
            ComputerName  = $ComputerName
            SessionOption = $option
            ErrorAction   = 'Stop'
        }
        if ($script:Credential) { $sessSplat['Credential'] = $script:Credential }
        $session = New-PSSession @sessSplat
        try {
            return @(Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $guidArgs -ErrorAction Stop)
        } finally {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
    } catch {
        return $null
    }
}

function Test-SecurityEventIdPresent {
    param(
        [string]$ComputerName,
        [int]$EventId
    )
    try {
        $splat = @{
            FilterHashtable = @{ LogName = 'Security'; Id = $EventId }
            MaxEvents       = 1
            ErrorAction     = 'Stop'
        }
        if ($script:Credential) { $splat['Credential'] = $script:Credential }
        if (-not [string]::IsNullOrWhiteSpace($ComputerName) -and -not (Test-IsLocalComputerName $ComputerName)) {
            $splat['ComputerName'] = $ComputerName
        }
        $events = @(Get-WinEvent @splat)
        return ($events.Count -gt 0)
    } catch {
        if (Test-IsNoMatchingEventsError $_) { return $false }
        throw
    }
}

function Get-KerberosAuditStatus {
    param(
        [string]$ComputerName,
        [switch]$NeedFailures
    )
    $name = $ComputerName
    if ([string]::IsNullOrWhiteSpace($name)) { $name = '.' }
    $asGuid = [guid]'0cce9242-69ae-11d9-bed3-505054503030'
    $tgsGuid = [guid]'0cce9240-69ae-11d9-bed3-505054503030'
    $asFlags = $null
    $tgsFlags = $null
    $source = 'unavailable'
    $errorText = ''
    $event4768 = $null
    $event4769 = $null

    try {
        $raw = Invoke-AuditPolRaw -ComputerName $name -Guids @($asGuid, $tgsGuid)
        if ($null -ne $raw) {
            $asFlags = ConvertFrom-AuditPolRaw -Lines $raw -Guid $asGuid
            $tgsFlags = ConvertFrom-AuditPolRaw -Lines $raw -Guid $tgsGuid
            if ($asFlags -or $tgsFlags) { $source = 'auditpol' }
        }
    } catch {
        $errorText = $_.Exception.Message
    }

    if ($source -ne 'auditpol') {
        try {
            $event4768 = Test-SecurityEventIdPresent -ComputerName $name -EventId 4768
            $event4769 = Test-SecurityEventIdPresent -ComputerName $name -EventId 4769
            $source = 'events'
        } catch {
            if ([string]::IsNullOrWhiteSpace($errorText)) { $errorText = $_.Exception.Message }
            $source = 'unavailable'
        }
    }

    $asSuccess = $false
    $asFailure = $false
    $tgsSuccess = $false
    $tgsFailure = $false
    if ($asFlags) { $asSuccess = [bool]$asFlags.Success; $asFailure = [bool]$asFlags.Failure }
    if ($tgsFlags) { $tgsSuccess = [bool]$tgsFlags.Success; $tgsFailure = [bool]$tgsFlags.Failure }
    if ($source -eq 'events') {
        $asSuccess = [bool]$event4768
        $tgsSuccess = [bool]$event4769
    }

    $fullyReady = ($asSuccess -and $tgsSuccess)
    if ($NeedFailures) { $fullyReady = $fullyReady -and $asFailure -and $tgsFailure }
    $partialReady = ($asSuccess -or $tgsSuccess -or [bool]$event4768 -or [bool]$event4769)

    $asLabel = if ($asFlags) { Get-AuditPolSettingLabel $asFlags } elseif ($source -eq 'events') { if ($event4768) { 'Events present' } else { 'No 4768 events found' } } else { 'Unknown' }
    $tgsLabel = if ($tgsFlags) { Get-AuditPolSettingLabel $tgsFlags } elseif ($source -eq 'events') { if ($event4769) { 'Events present' } else { 'No 4769 events found' } } else { 'Unknown' }

    $summary = if ($fullyReady) {
        "Kerberos auditing is ON on $name (4768=$asLabel, 4769=$tgsLabel) [$source]"
    } elseif ($partialReady) {
        "Kerberos auditing is PARTIAL on $name (4768=$asLabel, 4769=$tgsLabel) [$source]"
    } elseif ($source -eq 'unavailable') {
        "Could not determine Kerberos auditing on ${name}: $errorText"
    } else {
        "Kerberos auditing appears OFF on $name (4768=$asLabel, 4769=$tgsLabel) [$source]"
    }

    return [pscustomobject]@{
        Computer     = $name
        Source       = $source
        AsSuccess    = $asSuccess
        AsFailure    = $asFailure
        TgsSuccess   = $tgsSuccess
        TgsFailure   = $tgsFailure
        Event4768Seen = $event4768
        Event4769Seen = $event4769
        FullyReady   = $fullyReady
        PartialReady = $partialReady
        AsLabel      = $asLabel
        TgsLabel     = $tgsLabel
        Summary      = $summary
        Error        = $errorText
    }
}

function Invoke-KerberosAuditPreflight {
    param(
        [object[]]$Targets,
        [switch]$NeedFailures,
        [switch]$RequireAuditing,
        [switch]$SkipAuditCheck
    )
    if ($SkipAuditCheck) { return $true }
    $dcs = @($Targets | Where-Object { $_.Kind -eq 'dc' })
    if ($dcs.Count -lt 1) { return $true }

    $blocked = New-Object System.Collections.Generic.List[string]
    $partial = New-Object System.Collections.Generic.List[string]
    foreach ($dc in $dcs) {
        if (Test-IsCollectorCancelRequested) { return $false }
        Write-CollectorStatus "Checking Kerberos auditing on $($dc.Name)..."
        $status = Get-KerberosAuditStatus -ComputerName $dc.Name -NeedFailures:$NeedFailures
        if ($status.FullyReady) {
            Write-CollectorStatus $status.Summary 'SUCCESS'
        } elseif ($status.PartialReady) {
            Write-CollectorStatus $status.Summary 'WARN'
            [void]$partial.Add($status.Summary)
        } else {
            Write-CollectorStatus $status.Summary 'WARN'
            [void]$blocked.Add($status.Summary)
        }
    }

    if ($blocked.Count -lt 1 -and $partial.Count -lt 1) { return $true }

    $detail = @($blocked + $partial) -join [Environment]::NewLine
    if ($RequireAuditing) {
        throw "Kerberos auditing is not fully enabled. Refusing to watch logs.`nEnable 'Audit Kerberos Authentication Service' and 'Audit Kerberos Service Ticket Operations' (Success) on the DCs, or omit -RequireAuditing.`n$detail"
    }
    Write-CollectorStatus 'Continuing even though Kerberos auditing may be incomplete. Use -RequireAuditing to abort. Enable the Account Logon Kerberos subcategories if you expected events.' 'WARN'
    return $true
}

function Invoke-KerberosCollection {
    param(
        [object[]]$Targets,
        [ValidateSet('Historical','Live','Both')][string]$Mode = 'Both',
        [int]$HoursBack = 24,
        [int]$PollSeconds = 5,
        [int]$LiveMinutes = 0,
        [int]$MaxHistoryEventsPerDC = 100000,
        [int]$LivePageSize = 20000,
        [switch]$SkipAuditCheck,
        [switch]$RequireAuditing
    )
    if ($null -eq $Targets -or $Targets.Count -lt 1) {
        throw 'Specify at least one domain controller or EVTX file.'
    }
    $controllers = @($Targets | Where-Object { $_.Kind -eq 'dc' } | ForEach-Object { $_.Name })
    $evtxFiles = @($Targets | Where-Object { $_.Kind -eq 'evtx' } | ForEach-Object { $_.Path })
    $lastId = @{}
    $lastScan = @{}
    foreach ($target in $Targets) {
        $lastId[$target.Key] = [int64]0
        $lastScan[$target.Key] = Get-Date
    }

    if (-not (Invoke-KerberosAuditPreflight -Targets $Targets -NeedFailures:$script:DoIncludeFailures -RequireAuditing:$RequireAuditing -SkipAuditCheck:$SkipAuditCheck)) {
        return
    }

    $targetNames = @($Targets | ForEach-Object { if ($_.Kind -eq 'evtx') { $_.Path } else { $_.Name } })
    Write-CollectorStatus "Monitoring $($targetNames -join ', ') | Mode=$Mode | CSV=$script:CsvPath" 'SUCCESS'
    if ($null -ne $script:UiSync) {
        $script:UiSync.CsvPath = $script:CsvPath
        $script:UiSync.HtmlPath = $script:HtmlPath
    }

    $runHistorical = ($Mode -eq 'Historical' -or $Mode -eq 'Both' -or $evtxFiles.Count -gt 0)
    $runLive = ($Mode -eq 'Live' -or $Mode -eq 'Both') -and ($controllers.Count -gt 0)
    if ($evtxFiles.Count -gt 0 -and $controllers.Count -lt 1) { $runLive = $false }
    if ($evtxFiles.Count -gt 0 -and $Mode -eq 'Live') {
        Write-CollectorStatus 'EVTX files are static. Live polling is skipped for EVTX; running a one-shot historical scan.' 'WARN'
    }

    if ($runHistorical) {
        $since = (Get-Date).AddHours(-$HoursBack)
        foreach ($target in $Targets) {
            if (Test-IsCollectorCancelRequested) { break }
            Write-CollectorStatus "Historical query $($target.Name) since $since"
            if ($target.Kind -eq 'evtx') {
                $events = Read-KerberosEvents -Path $target.Path -Since $since -Max $MaxHistoryEventsPerDC
            } else {
                $events = Read-KerberosEvents -ComputerName $target.Name -Since $since -Max $MaxHistoryEventsPerDC
            }
            if ($events.Count -ge $MaxHistoryEventsPerDC) {
                Write-CollectorStatus "Hit MaxHistoryEventsPerDC ($MaxHistoryEventsPerDC) on $($target.Name). Older matching events in the window were not read." 'WARN'
            }
            $n = 0
            foreach ($ev in ($events | Sort-Object RecordId)) {
                if (Test-IsCollectorCancelRequested) { break }
                if ([int64]$ev.RecordId -gt $lastId[$target.Key]) { $lastId[$target.Key] = [int64]$ev.RecordId }
                $row = Convert-KerberosEvent $ev $target.Name
                if ($null -ne $row) { Save-Finding $row }
                $n++
                if (($n % 200) -eq 0) {
                    Write-CollectorStatus "Parsed $n events from $($target.Name)..."
                }
            }
        }
        try { Write-HtmlReport } catch {
            Write-CollectorStatus "HTML refresh failed: $($_.Exception.Message)" 'WARN'
        }
    } elseif ($runLive) {
        foreach ($dc in $controllers) {
            $lastId[$dc] = Get-NewestSecurityRecordId $dc
            $lastScan[$dc] = Get-Date
        }
    }

    Write-CollectorStatus "HTML report: $script:HtmlPath" 'SUCCESS'
    if (-not $runLive -or (Test-IsCollectorCancelRequested)) {
        Write-CollectorStatus "Completed: $($script:Records.Count) findings." 'SUCCESS'
        return
    }

    $liveDeadline = Get-LiveWatchDeadline -LiveMinutes $LiveMinutes
    if ($LiveMinutes -gt 0) {
        Write-CollectorStatus "Live monitoring for $LiveMinutes minute(s), then reports save to $(Split-Path -Parent $script:CsvPath). Stop early from the UI or with Ctrl+C." 'SUCCESS'
    } else {
        Write-CollectorStatus 'Live monitoring until stopped. Reports save continuously; Stop / Ctrl+C writes a final HTML snapshot.' 'SUCCESS'
    }
    try {
        while (-not (Test-IsCollectorCancelRequested) -and -not (Test-IsLiveWatchExpired $liveDeadline)) {
            Write-CollectorStatus (Get-LiveWatchStatusText -Deadline $liveDeadline -FindingCount $script:Records.Count -LiveMinutes $LiveMinutes)
            $waitMs = [Math]::Max(500, $PollSeconds * 1000)
            $slept = 0
            while ($slept -lt $waitMs -and -not (Test-IsCollectorCancelRequested) -and -not (Test-IsLiveWatchExpired $liveDeadline)) {
                $slice = [Math]::Min(500, $waitMs - $slept)
                Start-Sleep -Milliseconds $slice
                $slept += $slice
            }
            if (Test-IsCollectorCancelRequested -or (Test-IsLiveWatchExpired $liveDeadline)) { break }
            foreach ($dc in $controllers) {
                if (Test-IsCollectorCancelRequested) { break }
                try {
                    if (Test-SecurityLogWrapped -ComputerName $dc -Cursor $lastId[$dc]) {
                        Write-CollectorStatus "Security log on $dc was cleared or wrapped. Resetting RecordId cursor." 'WARN'
                        $lastId[$dc] = [int64]0
                    }
                    $since = $lastScan[$dc].AddSeconds(-30)
                    $useRecordIdOnly = ($lastId[$dc] -gt 0)
                    $caughtUp = $false
                    while (-not $caughtUp -and -not (Test-IsCollectorCancelRequested)) {
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
                    Write-CollectorStatus "Live poll failed for ${dc}: $($_.Exception.Message)" 'WARN'
                }
            }
            try { Write-HtmlReport } catch {
                Write-CollectorStatus "HTML refresh failed: $($_.Exception.Message)" 'WARN'
            }
        }
    } finally {
        try { Write-HtmlReport } catch { }
        if (Test-IsLiveWatchExpired $liveDeadline) {
            Write-CollectorStatus "Live watch of $LiveMinutes minute(s) finished. Saved $($script:Records.Count) finding(s) to $script:CsvPath and $script:HtmlPath" 'SUCCESS'
        } else {
            Write-CollectorStatus "Stopped. Findings: $($script:Records.Count). CSV=$script:CsvPath" 'SUCCESS'
        }
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
# Interactive WinForms UI
# ---------------------------------------------------------------------------

function Read-UiTextInput {
    param([string]$Title, [string]$Prompt, [string]$Default = '')
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.Size = New-Object System.Drawing.Size(460, 160)
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false
    $dlg.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Prompt
    $lbl.Location = New-Object System.Drawing.Point(12, 12)
    $lbl.AutoSize = $true
    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Text = $Default
    $txt.Location = New-Object System.Drawing.Point(12, 40)
    $txt.Width = 418
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'OK'
    $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $ok.Location = New-Object System.Drawing.Point(250, 78)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cancel.Location = New-Object System.Drawing.Point(340, 78)
    $dlg.Controls.AddRange(@($lbl, $txt, $ok, $cancel))
    $dlg.AcceptButton = $ok
    $dlg.CancelButton = $cancel
    $result = $dlg.ShowDialog()
    $value = $txt.Text
    $dlg.Dispose()
    if ($result -eq 'OK') { return $value }
    return ''
}

function New-UiButton {
    param([string]$Text, [int]$Width = 118, [int]$Height = 28)
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Width = $Width
    $button.Height = $Height
    $button.FlatStyle = [System.Windows.Forms.FlatStyle]::System
    $button.UseVisualStyleBackColor = $true
    return $button
}

function Add-UiLogLine {
    param([string]$Text)
    if ($null -eq $script:Ui -or $null -eq $script:Ui.LogBox) { return }
    $box = $script:Ui.LogBox
    if ($box.IsDisposed) { return }
    if ($box.Text.Length -gt 120000) { $box.Text = $box.Text.Substring($box.Text.Length - 80000) }
    $box.AppendText($Text.TrimEnd() + [Environment]::NewLine)
}

function Update-UiFilter {
    if ($null -eq $script:Ui) { return }
    $query = ''
    $category = 'All'
    if ($script:Ui.SearchBox) { $query = $script:Ui.SearchBox.Text }
    if ($script:Ui.FilterBox -and $null -ne $script:Ui.FilterBox.SelectedItem) {
        $category = [string]$script:Ui.FilterBox.SelectedItem
    }
    $script:Ui.Table.DefaultView.RowFilter = ConvertTo-DataViewFilter -Query $query -CategoryFilter $category
    Update-UiCountLabels
}

function Update-UiCountLabels {
    if ($null -eq $script:Ui) { return }
    $ticket = $script:Ui.TicketCount
    $session = $script:Ui.SessionCount
    $offered = $script:Ui.OfferedCount
    $total = $script:Ui.Table.Rows.Count
    $shown = $script:Ui.Table.DefaultView.Count
    $script:Ui.CountLabel.Text = "Records $total  |  Shown $shown  |  RC4 tickets $ticket  |  RC4 sessions $session  |  Offered $offered"
}

function Add-FindingToUi {
    param($Row)
    if ($null -eq $script:Ui) { return }
    $dataRow = $script:Ui.Table.NewRow()
    foreach ($col in (Get-GridColumnList)) {
        $prop = $Row.PSObject.Properties[$col]
        $dataRow[$col] = if ($null -ne $prop) { [string]$prop.Value } else { '' }
    }
    $script:Ui.Table.Rows.Add($dataRow)
    if ($Row.Category -like '*Ticket*') { $script:Ui.TicketCount++ }
    if ($Row.Category -like '*Session*') { $script:Ui.SessionCount++ }
    if ($Row.Category -eq 'RC4 Offered Only') { $script:Ui.OfferedCount++ }
}

function Drain-UiCollectorQueue {
    if ($null -eq $script:UiSync) { return }
    $batch = @()
    $lockObj = $script:UiSync.Queue.SyncRoot
    [System.Threading.Monitor]::Enter($lockObj)
    try {
        if ($script:UiSync.Queue.Count -gt 0) {
            $batch = @($script:UiSync.Queue.ToArray())
            $script:UiSync.Queue.Clear()
        }
    } finally {
        [System.Threading.Monitor]::Exit($lockObj)
    }
    foreach ($row in $batch) { Add-FindingToUi $row }
    if ($batch.Count -gt 0) { Update-UiFilter }

    $logLock = $script:UiSync.Log.SyncRoot
    $logLines = @()
    [System.Threading.Monitor]::Enter($logLock)
    try {
        if ($script:UiSync.Log.Count -gt 0) {
            $logLines = @($script:UiSync.Log.ToArray())
            $script:UiSync.Log.Clear()
        }
    } finally {
        [System.Threading.Monitor]::Exit($logLock)
    }
    foreach ($line in $logLines) { Add-UiLogLine $line }

    if (-not [string]::IsNullOrWhiteSpace([string]$script:UiSync.Status)) {
        $script:Ui.StatusLabel.Text = [string]$script:UiSync.Status
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$script:UiSync.CsvPath)) {
        $script:Ui.CsvPath = [string]$script:UiSync.CsvPath
        $script:Ui.HtmlPath = [string]$script:UiSync.HtmlPath
    }
}

function Set-UiRunningState {
    param([bool]$Running)
    $script:Ui.Running = $Running
    $script:Ui.StartButton.Enabled = -not $Running
    $script:Ui.StopButton.Enabled = $Running
    $script:Ui.TargetList.Enabled = -not $Running
    $script:Ui.DiscoverButton.Enabled = -not $Running
    $script:Ui.AddDcButton.Enabled = -not $Running
    $script:Ui.AddEvtxButton.Enabled = -not $Running
    $script:Ui.RemoveButton.Enabled = -not $Running
    $script:Ui.ModeBox.Enabled = -not $Running
}

function Add-UiTarget {
    param([string]$Kind, [string]$Name, [string]$Path = '')
    if ($null -eq $script:Ui) { return }
    $key = if ($Kind -eq 'evtx') { $Path } else { $Name }
    if ([string]::IsNullOrWhiteSpace($key)) { return }
    foreach ($existing in $script:Ui.Targets) {
        if ($existing.Key -eq $key) { return }
    }
    $display = if ($Kind -eq 'evtx') { "EVTX  $Name" } else { $Name }
    $item = [pscustomobject]@{ Kind = $Kind; Name = $Name; Path = $Path; Key = $key; Display = $display }
    [void]$script:Ui.Targets.Add($item)
    [void]$script:Ui.TargetList.Items.Add($display, $true)
}

function Get-UiCheckedTargets {
    $result = @()
    if ($null -eq $script:Ui) { return $result }
    for ($i = 0; $i -lt $script:Ui.TargetList.Items.Count; $i++) {
        if (-not $script:Ui.TargetList.GetItemChecked($i)) { continue }
        $result += $script:Ui.Targets[$i]
    }
    return $result
}

function Show-FindingDetail {
    param($GridRow)
    if ($null -eq $GridRow) { return }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($col in (Get-GridColumnList)) {
        [void]$lines.Add(('{0,-22} {1}' -f ($col + ':'), [string]$GridRow.Cells[$col].Value))
    }
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Finding detail'
    $dlg.Size = New-Object System.Drawing.Size(720, 520)
    $dlg.StartPosition = 'CenterParent'
    $dlg.MinimizeBox = $false
    $dlg.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $box = New-Object System.Windows.Forms.TextBox
    $box.Multiline = $true
    $box.ReadOnly = $true
    $box.ScrollBars = 'Both'
    $box.WordWrap = $false
    $box.Dock = 'Fill'
    $box.Font = New-Object System.Drawing.Font('Consolas', 9)
    $box.Text = ($lines -join [Environment]::NewLine)
    $dlg.Controls.Add($box)
    [void]$dlg.ShowDialog($script:Ui.Form)
    $dlg.Dispose()
}

function Stop-UiCollector {
    if ($null -ne $script:UiSync) { $script:UiSync.Cancel = $true }
    $script:CancelRequested = $true
    if ($null -ne $script:Ui -and $null -ne $script:Ui.CollectorPS) {
        try { $script:Ui.CollectorPS.BeginStop($null, $null) | Out-Null } catch { }
    }
    if ($null -ne $script:Ui) { $script:Ui.StatusLabel.Text = 'Stop requested...' }
}

function Complete-UiCollector {
    Drain-UiCollectorQueue
    Set-UiRunningState $false
    if ($null -ne $script:Ui.CollectorPS) {
        try {
            if ($null -ne $script:Ui.CollectorHandle) {
                $script:Ui.CollectorPS.EndInvoke($script:Ui.CollectorHandle) | Out-Null
            }
        } catch {
            Add-UiLogLine ('[ERROR] ' + $_.Exception.Message)
            $script:Ui.StatusLabel.Text = $_.Exception.Message
        }
        try { $script:Ui.CollectorPS.Runspace.Dispose() } catch { }
        try { $script:Ui.CollectorPS.Dispose() } catch { }
        $script:Ui.CollectorPS = $null
        $script:Ui.CollectorHandle = $null
    }
    if ($null -ne $script:UiSync -and -not [string]::IsNullOrWhiteSpace([string]$script:UiSync.Error)) {
        $script:Ui.StatusLabel.Text = [string]$script:UiSync.Error
    } elseif ($script:Ui.StatusLabel.Text -like 'Stop requested*') {
        $script:Ui.StatusLabel.Text = 'Stopped.'
    }
    $script:Ui.Timer.Stop()
}

function Get-UiKerberosAuditStatuses {
    $dcs = @(Get-UiCheckedTargets | Where-Object { $_.Kind -eq 'dc' })
    $statuses = @()
    if ($dcs.Count -lt 1) { return $statuses }
    $script:Credential = $script:Ui.Credential
    $needFail = $false
    if ($script:Ui.ChkFailures) { $needFail = [bool]$script:Ui.ChkFailures.Checked }
    if ($script:Ui.Form) { $script:Ui.Form.UseWaitCursor = $true }
    try {
        foreach ($t in $dcs) {
            Add-UiLogLine "[INFO] Checking Kerberos auditing on $($t.Name)..."
            try { [System.Windows.Forms.Application]::DoEvents() } catch { }
            $status = Get-KerberosAuditStatus -ComputerName $t.Name -NeedFailures:$needFail
            $level = if ($status.FullyReady) { 'INFO' } else { 'WARN' }
            Add-UiLogLine "[$level] $($status.Summary)"
            $statuses += $status
        }
    } finally {
        if ($script:Ui.Form) { $script:Ui.Form.UseWaitCursor = $false }
    }
    return $statuses
}

function Confirm-UiKerberosAuditing {
    $dcs = @(Get-UiCheckedTargets | Where-Object { $_.Kind -eq 'dc' })
    if ($dcs.Count -lt 1) { return $true }
    $statuses = @(Get-UiKerberosAuditStatuses)
    $notFully = @($statuses | Where-Object { -not $_.FullyReady })
    if ($notFully.Count -lt 1) { return $true }
    $msg = (($notFully | ForEach-Object { $_.Summary }) -join [Environment]::NewLine)
    $msg += [Environment]::NewLine + [Environment]::NewLine + "Enable Account Logon > Kerberos Authentication Service (event 4768) and Kerberos Service Ticket Operations (event 4769) with Success. This tool does not change audit policy."
    $require = $false
    if ($script:Ui.ChkRequireAudit) { $require = [bool]$script:Ui.ChkRequireAudit.Checked }
    if ($require) {
        [System.Windows.Forms.MessageBox]::Show($msg, 'Kerberos auditing not enabled', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return $false
    }
    $msg += [Environment]::NewLine + [Environment]::NewLine + 'Continue watching logs anyway?'
    $result = [System.Windows.Forms.MessageBox]::Show($msg, 'Kerberos auditing check', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    return ($result -eq [System.Windows.Forms.DialogResult]::Yes)
}

function Start-UiCollector {
    $targets = @(Get-UiCheckedTargets)
    if ($targets.Count -lt 1) {
        [System.Windows.Forms.MessageBox]::Show(
            'Check at least one domain controller or EVTX file.',
            'No targets',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        return
    }

    if (-not (Confirm-UiKerberosAuditing)) { return }

    $hours = 24
    $poll = 5
    $liveMins = 0
    [void][int]::TryParse($script:Ui.HoursBox.Text, [ref]$hours)
    [void][int]::TryParse($script:Ui.PollBox.Text, [ref]$poll)
    [void][int]::TryParse($script:Ui.LiveBox.Text, [ref]$liveMins)
    if ($hours -lt 1) { $hours = 1 }
    if ($hours -gt 720) { $hours = 720 }
    if ($poll -lt 2) { $poll = 2 }
    if ($poll -gt 3600) { $poll = 3600 }
    if ($liveMins -lt 0) { $liveMins = 0 }
    if ($liveMins -gt 10080) { $liveMins = 10080 }

    $mode = [string]$script:Ui.ModeBox.SelectedItem
    if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'Both' }
    $outputFolder = $script:Ui.OutputBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($outputFolder)) {
        $outputFolder = Join-Path (Get-Location).Path 'RC4-Reports'
        $script:Ui.OutputBox.Text = $outputFolder
    }

    $script:Ui.Table.Rows.Clear()
    $script:Ui.TicketCount = 0
    $script:Ui.SessionCount = 0
    $script:Ui.OfferedCount = 0
    Update-UiCountLabels

    $sync = [hashtable]::Synchronized(@{
        Cancel       = $false
        Status       = 'Starting...'
        Queue        = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        Log          = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        FindingCount = 0
        CsvPath      = ''
        HtmlPath     = ''
        Error        = ''
        Done         = $false
    })
    $script:UiSync = $sync
    $script:CancelRequested = $false

    $settings = @{
        ScriptPath            = $PSCommandPath
        OutputFolder          = $outputFolder
        ResolveHostnames      = [bool]$script:Ui.ChkDns.Checked
        EnrichAD              = [bool]$script:Ui.ChkAd.Checked
        IncludeOffered        = [bool]$script:Ui.ChkOffered.Checked
        IncludeFailures       = [bool]$script:Ui.ChkFailures.Checked
        DnsTimeoutMs          = $script:DnsTimeoutMs
        Mode                  = $mode
        HoursBack             = $hours
        PollSeconds           = $poll
        LiveMinutes           = $liveMins
        MaxHistoryEventsPerDC = $MaxHistoryEventsPerDC
        LivePageSize          = $LivePageSize
        SkipAuditCheck        = $true
        RequireAuditing       = $false
        Targets               = @($targets | ForEach-Object {
            [pscustomobject]@{ Kind = $_.Kind; Name = $_.Name; Path = $_.Path; Key = $_.Key }
        })
    }
    if ($script:Ui.Credential) { $settings['Credential'] = $script:Ui.Credential }

    $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $runspace.ApartmentState = 'MTA'
    $runspace.ThreadOptions = 'ReuseThread'
    $runspace.Open()
    $ps = [PowerShell]::Create()
    $ps.Runspace = $runspace
    $null = $ps.AddScript({
        param($Sync, $Settings)
        $script:UiSync = $Sync
        try {
            . $Settings.ScriptPath -SkipMain
            $script:UiSync = $Sync
            $cred = $null
            if ($Settings.ContainsKey('Credential')) { $cred = $Settings.Credential }
            Initialize-CollectorSession -OutputFolderPath $Settings.OutputFolder `
                -ResolveHostnamesFlag $Settings.ResolveHostnames `
                -EnrichADFlag $Settings.EnrichAD `
                -IncludeOfferedFlag $Settings.IncludeOffered `
                -IncludeFailuresFlag $Settings.IncludeFailures `
                -DnsTimeout $Settings.DnsTimeoutMs `
                -CredentialObject $cred `
                -Quiet $true
            $Sync.CsvPath = $script:CsvPath
            $Sync.HtmlPath = $script:HtmlPath
            Invoke-KerberosCollection -Targets $Settings.Targets -Mode $Settings.Mode `
                -HoursBack $Settings.HoursBack -PollSeconds $Settings.PollSeconds `
                -LiveMinutes $Settings.LiveMinutes `
                -MaxHistoryEventsPerDC $Settings.MaxHistoryEventsPerDC -LivePageSize $Settings.LivePageSize `
                -SkipAuditCheck:$Settings.SkipAuditCheck -RequireAuditing:$Settings.RequireAuditing
        } catch {
            $Sync.Error = $_.Exception.Message
            $Sync.Status = $_.Exception.Message
            if ($null -ne $Sync.Log) { [void]$Sync.Log.Add(('[{0}] [ERROR] {1}' -f (Get-Date -Format 'HH:mm:ss'), $_.Exception.Message)) }
        } finally {
            $Sync.Done = $true
        }
    }).AddArgument($sync).AddArgument($settings)

    $script:Ui.CollectorPS = $ps
    $script:Ui.CollectorHandle = $ps.BeginInvoke()
    Set-UiRunningState $true
    $script:Ui.StatusLabel.Text = 'Starting collector...'
    Add-UiLogLine '[INFO] Collector started.'
    $script:Ui.Timer.Start()
}

function Show-KerberosRc4Gui {
    param(
        [string[]]$PreselectedDCs,
        [string[]]$PreselectedEvtx,
        [string]$InitialMode = 'Both',
        [int]$InitialHours = 24,
        [int]$InitialPoll = 5,
        [int]$InitialLiveMinutes = 0,
        [string]$InitialOutput = '',
        [bool]$InitialOffered = $false,
        [bool]$InitialFailures = $false,
        [bool]$InitialDns = $false,
        [bool]$InitialAd = $false,
        [bool]$InitialRequireAuditing = $false
    )

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    } catch {
        throw "Interactive UI requires System.Windows.Forms (Windows PowerShell / Windows). $($_.Exception.Message)"
    }
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Kerberos RC4 Investigator'
    $form.Size = New-Object System.Drawing.Size(1280, 820)
    $form.StartPosition = 'CenterScreen'
    $form.MinimumSize = New-Object System.Drawing.Size(1000, 640)
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)

    $header = New-Object System.Windows.Forms.Panel
    $header.Dock = 'Top'
    $header.Height = 58
    $header.BackColor = [System.Drawing.Color]::FromArgb(23, 35, 56)
    $title = New-Object System.Windows.Forms.Label
    $title.Text = 'Kerberos RC4 Investigator'
    $title.ForeColor = [System.Drawing.Color]::White
    $title.Font = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
    $title.AutoSize = $true
    $title.Location = New-Object System.Drawing.Point(16, 8)
    $subtitle = New-Object System.Windows.Forms.Label
    $subtitle.Text = 'Read-only 4768 / 4769 collector   |   actual RC4 tickets vs advertised RC4   |   F5 start   Esc stop'
    $subtitle.ForeColor = [System.Drawing.Color]::FromArgb(180, 196, 214)
    $subtitle.AutoSize = $true
    $subtitle.Location = New-Object System.Drawing.Point(18, 34)
    $header.Controls.AddRange(@($title, $subtitle))

    $footer = New-Object System.Windows.Forms.Panel
    $footer.Dock = 'Bottom'
    $footer.Height = 150
    $status = New-Object System.Windows.Forms.Label
    $status.Text = 'Ready. Add domain controllers or an EVTX file, then Start.'
    $status.Dock = 'Top'
    $status.Height = 24
    $status.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 0)
    $counts = New-Object System.Windows.Forms.Label
    $counts.Text = 'Records 0  |  Shown 0  |  RC4 tickets 0  |  RC4 sessions 0  |  Offered 0'
    $counts.Dock = 'Top'
    $counts.Height = 22
    $counts.Padding = New-Object System.Windows.Forms.Padding(8, 0, 8, 0)
    $logBox = New-Object System.Windows.Forms.TextBox
    $logBox.Multiline = $true
    $logBox.ReadOnly = $true
    $logBox.ScrollBars = 'Vertical'
    $logBox.Dock = 'Fill'
    $logBox.Font = New-Object System.Drawing.Font('Consolas', 8.5)
    $logBox.BackColor = [System.Drawing.Color]::FromArgb(248, 250, 252)
    $footer.Controls.Add($logBox)
    $footer.Controls.Add($counts)
    $footer.Controls.Add($status)

    $left = New-Object System.Windows.Forms.Panel
    $left.Dock = 'Left'
    $left.Width = 360
    $left.Padding = New-Object System.Windows.Forms.Padding(12, 10, 12, 10)

    $y = 8
    $lblTargets = New-Object System.Windows.Forms.Label
    $lblTargets.Text = 'Targets'
    $lblTargets.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $lblTargets.Location = New-Object System.Drawing.Point(12, $y)
    $lblTargets.AutoSize = $true
    $y += 22
    $targetList = New-Object System.Windows.Forms.CheckedListBox
    $targetList.Location = New-Object System.Drawing.Point(12, $y)
    $targetList.Size = New-Object System.Drawing.Size(332, 128)
    $targetList.CheckOnClick = $true
    $y += 136
    $btnDiscover = New-UiButton 'Discover DCs' 100
    $btnDiscover.Location = New-Object System.Drawing.Point(12, $y)
    $btnAddDc = New-UiButton 'Add DC' 72 28
    $btnAddDc.Location = New-Object System.Drawing.Point(116, $y)
    $btnAddEvtx = New-UiButton 'Add EVTX' 76 28
    $btnAddEvtx.Location = New-Object System.Drawing.Point(192, $y)
    $btnRemove = New-UiButton 'Remove' 72 28
    $btnRemove.Location = New-Object System.Drawing.Point(272, $y)
    $y += 40

    $lblMode = New-Object System.Windows.Forms.Label
    $lblMode.Text = 'Mode'
    $lblMode.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $lblMode.Location = New-Object System.Drawing.Point(12, $y)
    $lblMode.AutoSize = $true
    $y += 22
    $modeBox = New-Object System.Windows.Forms.ComboBox
    $modeBox.DropDownStyle = 'DropDownList'
    $modeBox.Location = New-Object System.Drawing.Point(12, $y)
    $modeBox.Width = 160
    [void]$modeBox.Items.AddRange(@('Historical','Live','Both'))
    $modeBox.SelectedItem = $InitialMode
    $lblHours = New-Object System.Windows.Forms.Label
    $lblHours.Text = 'Hours'
    $lblHours.Location = New-Object System.Drawing.Point(182, ($y - 18))
    $lblHours.AutoSize = $true
    $hoursBox = New-Object System.Windows.Forms.TextBox
    $hoursBox.Text = [string]$InitialHours
    $hoursBox.Location = New-Object System.Drawing.Point(182, $y)
    $hoursBox.Width = 50
    $lblPoll = New-Object System.Windows.Forms.Label
    $lblPoll.Text = 'Poll sec'
    $lblPoll.Location = New-Object System.Drawing.Point(244, ($y - 18))
    $lblPoll.AutoSize = $true
    $pollBox = New-Object System.Windows.Forms.TextBox
    $pollBox.Text = [string]$InitialPoll
    $pollBox.Location = New-Object System.Drawing.Point(244, $y)
    $pollBox.Width = 50
    $y += 32
    $lblLive = New-Object System.Windows.Forms.Label
    $lblLive.Text = 'Live minutes (0 = until Stop)'
    $lblLive.Location = New-Object System.Drawing.Point(12, $y)
    $lblLive.AutoSize = $true
    $y += 18
    $liveBox = New-Object System.Windows.Forms.TextBox
    $liveBox.Text = [string]$InitialLiveMinutes
    $liveBox.Location = New-Object System.Drawing.Point(12, $y)
    $liveBox.Width = 50
    $lblLiveHint = New-Object System.Windows.Forms.Label
    $lblLiveHint.Text = 'Then save CSV/HTML to the output folder'
    $lblLiveHint.ForeColor = [System.Drawing.Color]::FromArgb(92, 102, 119)
    $lblLiveHint.Location = New-Object System.Drawing.Point(70, ($y + 3))
    $lblLiveHint.AutoSize = $true
    $y += 32

    $chkOffered = New-Object System.Windows.Forms.CheckBox
    $chkOffered.Text = 'Include offered RC4 (not proof of use)'
    $chkOffered.Location = New-Object System.Drawing.Point(12, $y)
    $chkOffered.AutoSize = $true
    $chkOffered.Checked = $InitialOffered
    $y += 24
    $chkFailures = New-Object System.Windows.Forms.CheckBox
    $chkFailures.Text = 'Include failed tickets that mention RC4'
    $chkFailures.Location = New-Object System.Drawing.Point(12, $y)
    $chkFailures.AutoSize = $true
    $chkFailures.Checked = $InitialFailures
    $y += 24
    $chkDns = New-Object System.Windows.Forms.CheckBox
    $chkDns.Text = 'Resolve client hostnames'
    $chkDns.Location = New-Object System.Drawing.Point(12, $y)
    $chkDns.AutoSize = $true
    $chkDns.Checked = $InitialDns
    $y += 24
    $chkAd = New-Object System.Windows.Forms.CheckBox
    $chkAd.Text = 'Enrich accounts in Active Directory'
    $chkAd.Location = New-Object System.Drawing.Point(12, $y)
    $chkAd.AutoSize = $true
    $chkAd.Checked = $InitialAd
    $y += 24
    $chkRodc = New-Object System.Windows.Forms.CheckBox
    $chkRodc.Text = 'Include RODCs when discovering'
    $chkRodc.Location = New-Object System.Drawing.Point(12, $y)
    $chkRodc.AutoSize = $true
    $y += 24
    $chkRequireAudit = New-Object System.Windows.Forms.CheckBox
    $chkRequireAudit.Text = 'Abort if Kerberos auditing is off'
    $chkRequireAudit.Location = New-Object System.Drawing.Point(12, $y)
    $chkRequireAudit.AutoSize = $true
    $chkRequireAudit.Checked = $InitialRequireAuditing
    $y += 32

    $lblOut = New-Object System.Windows.Forms.Label
    $lblOut.Text = 'Output folder'
    $lblOut.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $lblOut.Location = New-Object System.Drawing.Point(12, $y)
    $lblOut.AutoSize = $true
    $y += 20
    $outputBox = New-Object System.Windows.Forms.TextBox
    $outputBox.Location = New-Object System.Drawing.Point(12, $y)
    $outputBox.Width = 248
    if ([string]::IsNullOrWhiteSpace($InitialOutput)) {
        $outputBox.Text = Join-Path (Get-Location).Path 'RC4-Reports'
    } else {
        $outputBox.Text = $InitialOutput
    }
    $btnBrowse = New-UiButton 'Browse' 76 24
    $btnBrowse.Location = New-Object System.Drawing.Point(266, $y)
    $y += 40

    $btnStart = New-UiButton 'Start' 100 34
    $btnStart.Location = New-Object System.Drawing.Point(12, $y)
    $btnStop = New-UiButton 'Stop' 90 34
    $btnStop.Location = New-Object System.Drawing.Point(118, $y)
    $btnStop.Enabled = $false
    $btnCred = New-UiButton 'Credential...' 118 34
    $btnCred.Location = New-Object System.Drawing.Point(214, $y)
    $y += 44
    $btnHtml = New-UiButton 'Open HTML' 108 28
    $btnHtml.Location = New-Object System.Drawing.Point(12, $y)
    $btnCsv = New-UiButton 'Open CSV' 100 28
    $btnCsv.Location = New-Object System.Drawing.Point(124, $y)
    $btnFolder = New-UiButton 'Open folder' 108 28
    $btnFolder.Location = New-Object System.Drawing.Point(228, $y)
    $y += 34
    $btnAudit = New-UiButton 'Check auditing' 332 28
    $btnAudit.Location = New-Object System.Drawing.Point(12, $y)

    $left.Controls.AddRange(@(
        $lblTargets, $targetList, $btnDiscover, $btnAddDc, $btnAddEvtx, $btnRemove,
        $lblMode, $modeBox, $lblHours, $hoursBox, $lblPoll, $pollBox,
        $lblLive, $liveBox, $lblLiveHint,
        $chkOffered, $chkFailures, $chkDns, $chkAd, $chkRodc, $chkRequireAudit,
        $lblOut, $outputBox, $btnBrowse, $btnStart, $btnStop, $btnCred,
        $btnHtml, $btnCsv, $btnFolder, $btnAudit
    ))

    $right = New-Object System.Windows.Forms.Panel
    $right.Dock = 'Fill'
    $searchRow = New-Object System.Windows.Forms.Panel
    $searchRow.Dock = 'Top'
    $searchRow.Height = 42
    $lblSearch = New-Object System.Windows.Forms.Label
    $lblSearch.Text = 'Search'
    $lblSearch.Location = New-Object System.Drawing.Point(8, 12)
    $lblSearch.AutoSize = $true
    $searchBox = New-Object System.Windows.Forms.TextBox
    $searchBox.Location = New-Object System.Drawing.Point(64, 8)
    $searchBox.Width = 360
    $filterBox = New-Object System.Windows.Forms.ComboBox
    $filterBox.DropDownStyle = 'DropDownList'
    $filterBox.Location = New-Object System.Drawing.Point(434, 8)
    $filterBox.Width = 180
    [void]$filterBox.Items.AddRange(@('All','RC4 Ticket','RC4 Session','RC4 Offered Only','Failed / RC4 Observed'))
    $filterBox.SelectedIndex = 0
    $hint = New-Object System.Windows.Forms.Label
    $hint.Text = 'Double-click a row for details'
    $hint.AutoSize = $true
    $hint.Location = New-Object System.Drawing.Point(628, 12)
    $hint.ForeColor = [System.Drawing.Color]::FromArgb(92, 102, 119)
    $searchRow.Controls.AddRange(@($lblSearch, $searchBox, $filterBox, $hint))

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.SelectionMode = 'FullRowSelect'
    $grid.MultiSelect = $false
    $grid.AutoSizeColumnsMode = 'DisplayedCells'
    $grid.RowHeadersVisible = $false
    $grid.BackgroundColor = [System.Drawing.Color]::White
    $grid.BorderStyle = 'None'

    $table = New-Object System.Data.DataTable 'Findings'
    foreach ($col in (Get-GridColumnList)) { [void]$table.Columns.Add($col, [string]) }
    $grid.DataSource = $table

    $right.Controls.Add($grid)
    $right.Controls.Add($searchRow)

    $form.Controls.Add($right)
    $form.Controls.Add($left)
    $form.Controls.Add($footer)
    $form.Controls.Add($header)

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 400

    $script:Ui = @{
        Form            = $form
        TargetList      = $targetList
        Targets         = New-Object 'System.Collections.Generic.List[object]'
        DiscoverButton  = $btnDiscover
        AddDcButton     = $btnAddDc
        AddEvtxButton   = $btnAddEvtx
        RemoveButton    = $btnRemove
        ModeBox         = $modeBox
        HoursBox        = $hoursBox
        PollBox         = $pollBox
        LiveBox         = $liveBox
        ChkOffered      = $chkOffered
        ChkFailures     = $chkFailures
        ChkDns          = $chkDns
        ChkAd           = $chkAd
        ChkRodc         = $chkRodc
        ChkRequireAudit = $chkRequireAudit
        OutputBox       = $outputBox
        StartButton     = $btnStart
        StopButton      = $btnStop
        SearchBox       = $searchBox
        FilterBox       = $filterBox
        Grid            = $grid
        Table           = $table
        LogBox          = $logBox
        StatusLabel     = $status
        CountLabel      = $counts
        Timer           = $timer
        Running         = $false
        TicketCount     = 0
        SessionCount    = 0
        OfferedCount    = 0
        CollectorPS     = $null
        CollectorHandle = $null
        Credential      = $Credential
        CsvPath         = ''
        HtmlPath        = ''
    }

    $grid.add_CellFormatting({
        param($sender, $e)
        if ($e.RowIndex -lt 0) { return }
        try {
            $cat = [string]$grid.Rows[$e.RowIndex].Cells['Category'].Value
            $rgb = Get-CategoryHighlightArgb $cat
            $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb($rgb[0], $rgb[1], $rgb[2])
        } catch { }
    })
    $grid.add_CellDoubleClick({
        param($sender, $e)
        if ($e.RowIndex -lt 0) { return }
        Show-FindingDetail $grid.Rows[$e.RowIndex]
    })
    $searchBox.add_TextChanged({ Update-UiFilter })
    $filterBox.add_SelectedIndexChanged({ Update-UiFilter })

    $btnDiscover.add_Click({
        try {
            $form.UseWaitCursor = $true
            [System.Windows.Forms.Application]::DoEvents()
            $script:Credential = $script:Ui.Credential
            $found = Get-CollectorTargetList -Discover -IncludeRODC:$script:Ui.ChkRodc.Checked
            foreach ($t in $found) { Add-UiTarget -Kind $t.Kind -Name $t.Name -Path $t.Path }
            Add-UiLogLine ("[INFO] Discovered {0} domain controller(s)." -f @($found).Count)
        } catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'DC discovery failed', 'OK', 'Error') | Out-Null
            Add-UiLogLine ('[ERROR] ' + $_.Exception.Message)
        } finally {
            $form.UseWaitCursor = $false
        }
    })
    $btnAddDc.add_Click({
        $entered = Read-UiTextInput -Title 'Add domain controller' -Prompt 'Hostname or FQDN:' -Default $env:COMPUTERNAME
        if (-not [string]::IsNullOrWhiteSpace($entered)) { Add-UiTarget -Kind 'dc' -Name $entered.Trim() }
    })
    $btnAddEvtx.add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = 'Event logs (*.evtx)|*.evtx|All files (*.*)|*.*'
        $dlg.Multiselect = $true
        $dlg.Title = 'Select exported Security EVTX files'
        if ($dlg.ShowDialog() -eq 'OK') {
            foreach ($file in $dlg.FileNames) {
                Add-UiTarget -Kind 'evtx' -Name ([System.IO.Path]::GetFileName($file)) -Path $file
            }
        }
    })
    $btnRemove.add_Click({
        $idx = $targetList.SelectedIndex
        if ($idx -lt 0) { return }
        $script:Ui.Targets.RemoveAt($idx)
        $targetList.Items.RemoveAt($idx)
    })
    $btnBrowse.add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Folder for CSV and HTML reports'
        if ($dlg.ShowDialog() -eq 'OK') { $outputBox.Text = $dlg.SelectedPath }
    })
    $btnCred.add_Click({
        try {
            $script:Ui.Credential = Get-Credential -Message 'Credential for remote event logs / AD'
            Add-UiLogLine '[INFO] Alternate credential stored for this session.'
        } catch {
            Add-UiLogLine '[WARN] Credential prompt cancelled.'
        }
    })
    $btnStart.add_Click({ Start-UiCollector })
    $btnStop.add_Click({ Stop-UiCollector })
    $btnHtml.add_Click({
        if ($script:Ui.HtmlPath -and (Test-Path -LiteralPath $script:Ui.HtmlPath)) {
            Start-Process $script:Ui.HtmlPath
        } else {
            [System.Windows.Forms.MessageBox]::Show('No HTML report yet. Run a collection first.', 'Open HTML', 'OK', 'Information') | Out-Null
        }
    })
    $btnCsv.add_Click({
        if ($script:Ui.CsvPath -and (Test-Path -LiteralPath $script:Ui.CsvPath)) {
            Start-Process $script:Ui.CsvPath
        } else {
            [System.Windows.Forms.MessageBox]::Show('No CSV yet. Run a collection first.', 'Open CSV', 'OK', 'Information') | Out-Null
        }
    })
    $btnAudit.add_Click({
        $dcs = @(Get-UiCheckedTargets | Where-Object { $_.Kind -eq 'dc' })
        if ($dcs.Count -lt 1) {
            [System.Windows.Forms.MessageBox]::Show('Check at least one domain controller first.', 'Check auditing', 'OK', 'Information') | Out-Null
            return
        }
        $statuses = @(Get-UiKerberosAuditStatuses)
        $notFully = @($statuses | Where-Object { -not $_.FullyReady })
        if ($notFully.Count -lt 1) {
            [System.Windows.Forms.MessageBox]::Show('Kerberos 4768/4769 auditing looks enabled on the selected DCs.', 'Check auditing', 'OK', 'Information') | Out-Null
        } else {
            $msg = (($notFully | ForEach-Object { $_.Summary }) -join [Environment]::NewLine)
            [System.Windows.Forms.MessageBox]::Show($msg, 'Kerberos auditing check', 'OK', 'Warning') | Out-Null
        }
    })
    $btnFolder.add_Click({
        $path = $outputBox.Text.Trim()
        if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -ItemType Directory -Force | Out-Null }
        Start-Process $path
    })
    $timer.add_Tick({
        try {
            Drain-UiCollectorQueue
            if ($null -ne $script:UiSync -and [bool]$script:UiSync.Done) {
                Complete-UiCollector
            }
        } catch {
            Add-UiLogLine ('[ERROR] ' + $_.Exception.Message)
        }
    })
    $form.add_FormClosing({
        param($sender, $e)
        if ($script:Ui.Running) {
            Stop-UiCollector
            Start-Sleep -Milliseconds 200
            Complete-UiCollector
        }
    })
    $form.add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq 'F5') { Start-UiCollector }
        elseif ($e.KeyCode -eq 'Escape') { Stop-UiCollector }
    })
    $form.KeyPreview = $true

    if ($PreselectedDCs) {
        foreach ($dc in $PreselectedDCs) { Add-UiTarget -Kind 'dc' -Name $dc }
    }
    if ($PreselectedEvtx) {
        foreach ($p in $PreselectedEvtx) {
            if (Test-Path -LiteralPath $p) {
                Add-UiTarget -Kind 'evtx' -Name ([System.IO.Path]::GetFileName($p)) -Path ((Resolve-Path -LiteralPath $p).Path)
            }
        }
    }
    if ($script:Ui.Targets.Count -lt 1) {
        Add-UiLogLine 'Add a DC (Discover, Add DC, or Add EVTX) then click Start. Collection is read-only.'
    } else {
        Add-UiLogLine 'Targets loaded. Review options and click Start.'
    }

    [void]$form.ShowDialog()
    try { $timer.Stop(); $timer.Dispose() } catch { }
    try { $form.Dispose() } catch { }
}

function Start-InteractiveUi {
    if (-not (Test-IsStaApartment)) {
        $procPath = (Get-Process -Id $PID).Path
        $argList = New-Object System.Collections.Generic.List[string]
        $exeName = [IO.Path]::GetFileNameWithoutExtension($procPath)
        if ($exeName -eq 'powershell') { [void]$argList.Add('-STA') }
        [void]$argList.Add('-NoProfile')
        [void]$argList.Add('-ExecutionPolicy'); [void]$argList.Add('Bypass')
        [void]$argList.Add('-File'); [void]$argList.Add($PSCommandPath)
        [void]$argList.Add('-Gui')
        if ($DomainControllers) { [void]$argList.Add('-DomainControllers'); foreach ($d in $DomainControllers) { [void]$argList.Add($d) } }
        if ($EvtxPath) { [void]$argList.Add('-EvtxPath'); foreach ($p in $EvtxPath) { [void]$argList.Add($p) } }
        [void]$argList.Add('-Mode'); [void]$argList.Add($Mode)
        [void]$argList.Add('-HoursBack'); [void]$argList.Add([string]$HoursBack)
        [void]$argList.Add('-PollSeconds'); [void]$argList.Add([string]$PollSeconds)
        [void]$argList.Add('-LiveMinutes'); [void]$argList.Add([string]$LiveMinutes)
        if ($IncludeOffered) { [void]$argList.Add('-IncludeOffered') }
        if ($IncludeFailures) { [void]$argList.Add('-IncludeFailures') }
        if ($ResolveHostnames) { [void]$argList.Add('-ResolveHostnames') }
        if ($EnrichAD) { [void]$argList.Add('-EnrichAD') }
        if ($SkipAuditCheck) { [void]$argList.Add('-SkipAuditCheck') }
        if ($RequireAuditing) { [void]$argList.Add('-RequireAuditing') }
        if ($OutputFolder) { [void]$argList.Add('-OutputFolder'); [void]$argList.Add($OutputFolder) }
        Write-Host 'Relaunching in STA apartment for the interactive UI...' -ForegroundColor Gray
        Start-Process -FilePath $procPath -ArgumentList $argList.ToArray()
        return
    }
    Show-KerberosRc4Gui -PreselectedDCs $DomainControllers -PreselectedEvtx $EvtxPath `
        -InitialMode $Mode -InitialHours $HoursBack -InitialPoll $PollSeconds `
        -InitialLiveMinutes $LiveMinutes `
        -InitialOutput $OutputFolder -InitialOffered ([bool]$IncludeOffered) `
        -InitialFailures ([bool]$IncludeFailures) -InitialDns ([bool]$ResolveHostnames) `
        -InitialAd ([bool]$EnrichAD) -InitialRequireAuditing ([bool]$RequireAuditing)
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

    Assert-True -Condition (Test-ShouldStartInteractiveUi) `
        -Name 'No targeting arguments start the interactive UI'
    Assert-True -Condition (Test-ShouldStartInteractiveUi -GuiPresent) `
        -Name '-Gui starts the interactive UI even when other switches are absent'
    Assert-True -Condition (-not (Test-ShouldStartInteractiveUi -DomainControllerList @('DC01'))) `
        -Name 'Passing -DomainControllers keeps the non-interactive CLI path'
    Assert-True -Condition (-not (Test-ShouldStartInteractiveUi -SelfTestPresent)) `
        -Name '-SelfTest does not open the UI'
    Assert-True -Condition (-not (Test-ShouldStartInteractiveUi -SkipMainPresent -GuiPresent)) `
        -Name '-SkipMain suppresses the UI so a collector runspace can load functions'
    Assert-True -Condition (-not (Test-ShouldStartInteractiveUi -NonInteractivePresent)) `
        -Name '-NonInteractive forces the CLI/error path instead of the UI'
    Assert-True -Condition ((ConvertTo-DataViewFilter -Query '' -CategoryFilter 'All') -eq '') `
        -Name 'Empty search and All category produce no DataView filter'
    $ticketFilter = ConvertTo-DataViewFilter -Query '' -CategoryFilter 'RC4 Ticket'
    Assert-True -Condition ($ticketFilter -eq "Category LIKE '%RC4 Ticket%'") `
        -Name 'Ticket category filter matches RC4 Ticket and RC4 Ticket + Session'
    $searchFilter = ConvertTo-DataViewFilter -Query "O'Brien" -CategoryFilter 'All'
    Assert-True -Condition ($searchFilter -match "O''Brien" -and $searchFilter -match 'Account LIKE') `
        -Name 'Search filter ORs across grid columns and escapes quotes'
    $rgbTicket = Get-CategoryHighlightArgb 'RC4 Ticket + Session'
    Assert-True -Condition ($rgbTicket[0] -eq 255 -and $rgbTicket[1] -eq 228) `
        -Name 'RC4 ticket rows use the red highlight'
    $rgbAes = Get-CategoryHighlightArgb 'Other'
    Assert-True -Condition ($rgbAes[0] -eq 255 -and $rgbAes[2] -eq 255) `
        -Name 'Unknown categories stay white'
    $sta = Test-IsStaApartment
    Assert-True -Condition ($sta -eq $true -or $sta -eq $false) `
        -Name 'STA apartment probe returns a boolean without throwing'

    $listRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('RC4Tgt_' + [guid]::NewGuid().ToString('N'))
    New-Item -Path $listRoot -ItemType Directory -Force | Out-Null
    $fakeEvtx = Join-Path $listRoot 'Security.evtx'
    Set-Content -LiteralPath $fakeEvtx -Value 'fake'
    $targetList = @(Get-CollectorTargetList -DomainControllerList @('DC01','DC01','DC02') -EvtxPathList @($fakeEvtx))
    Assert-True -Condition ($targetList.Count -eq 3) -Name 'Target list de-duplicates DCs and includes EVTX files'
    Assert-True -Condition ((@($targetList | Where-Object { $_.Kind -eq 'evtx' }).Count) -eq 1) `
        -Name 'EVTX entries are tagged separately from domain controllers'
    Remove-Item -LiteralPath $listRoot -Recurse -Force -ErrorAction SilentlyContinue

    $from = [datetime]'2026-10-28T12:00:00'
    Assert-True -Condition ($null -eq (Get-LiveWatchDeadline -LiveMinutes 0 -From $from)) `
        -Name 'LiveMinutes 0 means no deadline (run until stopped)'
    $deadline = Get-LiveWatchDeadline -LiveMinutes 30 -From $from
    Assert-True -Condition ($deadline -eq $from.AddMinutes(30)) `
        -Name 'LiveMinutes 30 sets a deadline 30 minutes after start'
    Assert-True -Condition (-not (Test-IsLiveWatchExpired -Deadline $deadline -Now $from.AddMinutes(29))) `
        -Name 'Watch is not expired before the deadline'
    Assert-True -Condition (Test-IsLiveWatchExpired -Deadline $deadline -Now $from.AddMinutes(30)) `
        -Name 'Watch expires at the deadline'
    Assert-True -Condition (-not (Test-IsLiveWatchExpired -Deadline $null -Now $from)) `
        -Name 'A null deadline never expires'
    $statusText = Get-LiveWatchStatusText -Deadline $deadline -FindingCount 4 -LiveMinutes 30 -Now $from.AddMinutes(10)
    Assert-True -Condition ($statusText -match '20m 00s remaining' -and $statusText -match 'findings 4') `
        -Name 'Status text shows remaining live-watch time and finding count'

    $asGuid = [guid]'0cce9242-69ae-11d9-bed3-505054503030'
    $tgsGuid = [guid]'0cce9240-69ae-11d9-bed3-505054503030'
    $guidMap = Get-KerberosAuditGuidMap
    Assert-True -Condition ($guidMap['Kerberos Authentication Service'] -eq $asGuid) `
        -Name '4768 maps to Kerberos Authentication Service GUID 0cce9242'
    Assert-True -Condition ($guidMap['Kerberos Service Ticket Operations'] -eq $tgsGuid) `
        -Name '4769 maps to Kerberos Service Ticket Operations GUID 0cce9240'
    $both = ConvertTo-AuditFlagPair -Inclusion 'Success and Failure' -SettingValue 3
    Assert-True -Condition ($both.Success -and $both.Failure) -Name 'Setting value 3 is Success and Failure'
    $succ = ConvertTo-AuditFlagPair -Inclusion 'Success' -SettingValue 1
    Assert-True -Condition ($succ.Success -and -not $succ.Failure) -Name 'Setting value 1 is Success only'
    $none = ConvertTo-AuditFlagPair -Inclusion 'No Auditing' -SettingValue 0
    Assert-True -Condition (-not $none.Success -and -not $none.Failure) -Name 'Setting value 0 is No Auditing'
    $rawLines = @(
        'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value',
        'DC01,System,Kerberos Authentication Service,{0CCE9242-69AE-11D9-BED3-505054503030},Success and Failure,,3',
        'DC01,System,Kerberos Service Ticket Operations,{0CCE9240-69AE-11D9-BED3-505054503030},No Auditing,,0'
    )
    $parsedAs = ConvertFrom-AuditPolRaw -Lines $rawLines -Guid $asGuid
    $parsedTgs = ConvertFrom-AuditPolRaw -Lines $rawLines -Guid $tgsGuid
    Assert-True -Condition ($parsedAs.Success -and $parsedAs.Failure) `
        -Name 'auditpol /r parser reads Success and Failure for the AS subcategory'
    Assert-True -Condition (-not $parsedTgs.Success -and -not $parsedTgs.Failure) `
        -Name 'auditpol /r parser reads No Auditing for the TGS subcategory'
    Assert-True -Condition ($null -eq (ConvertFrom-AuditPolRaw -Lines $rawLines -Guid ([guid]'0cce9243-69ae-11d9-bed3-505054503030'))) `
        -Name 'Parser ignores unrelated audit subcategories such as NPS'
    Assert-True -Condition ((Get-AuditPolSettingLabel $none) -eq 'No Auditing') `
        -Name 'No-auditing flags render as No Auditing'
    $skipOk = Invoke-KerberosAuditPreflight -Targets @([pscustomobject]@{ Kind = 'evtx'; Name = 'x.evtx' }) -SkipAuditCheck
    Assert-True -Condition ($skipOk -eq $true) -Name 'EVTX-only / -SkipAuditCheck preflight does not block collection'

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

if ($SkipMain) { return }

$script:DnsTimeoutMs = $DnsTimeoutMs
$script:Credential = $Credential

$startGui = Test-ShouldStartInteractiveUi -SelfTestPresent:$false -SkipMainPresent:$false `
    -GuiPresent:$Gui -NonInteractivePresent:$NonInteractive `
    -DomainControllerList $DomainControllers -DiscoverDCsPresent:$DiscoverDCs `
    -EvtxPathList $EvtxPath

if ($startGui) {
    Start-InteractiveUi
    return
}

Initialize-CollectorSession -OutputFolderPath $OutputFolder `
    -ResolveHostnamesFlag ([bool]$ResolveHostnames) `
    -EnrichADFlag ([bool]$EnrichAD) `
    -IncludeOfferedFlag ([bool]$IncludeOffered) `
    -IncludeFailuresFlag ([bool]$IncludeFailures) `
    -DnsTimeout $DnsTimeoutMs `
    -CredentialObject $Credential `
    -Quiet $false

$targets = @(Get-CollectorTargetList -DomainControllerList $DomainControllers -EvtxPathList $EvtxPath -Discover:$DiscoverDCs -IncludeRODC:$IncludeRODCs)
if ($targets.Count -lt 1) {
    throw 'Specify -DomainControllers DC01,DC02, -DiscoverDCs, or -EvtxPath. Or run without arguments for the interactive UI.'
}

Invoke-KerberosCollection -Targets $targets -Mode $Mode -HoursBack $HoursBack -PollSeconds $PollSeconds `
    -LiveMinutes $LiveMinutes `
    -MaxHistoryEventsPerDC $MaxHistoryEventsPerDC -LivePageSize $LivePageSize `
    -SkipAuditCheck:$SkipAuditCheck -RequireAuditing:$RequireAuditing


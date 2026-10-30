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
  client still advertises RC4 even when the issued ticket is AES. Historical reads
  pull every 4768/4769 in the Hours window (paged), then keep RC4 ticket/session rows.
  Use -IncludeAes (or Include AES tickets) to list AES tickets too — that is how you
  confirm the Security log is being read. The log prints Hours, IncludeAes, and a
  ticket-etype histogram. A tiny RC4-only result (for example 14 session rows) with
  Include AES off is not the full Kerberos volume on the DC.

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
  On that schema (23+ EventData properties) session-key etype is property index 20
  (4769) or 22 (4768), matching Microsoft's Watch-KerbEncryptionUsage, but only
  when that slot is an etype scalar (0x17, 23, AES256, ...). Some DCs store
  AvailableKeys blobs there; those are not session etypes.

  Live mode subscribes with EventLogWatcher (push, same idea as Watch-KerbEncryptionUsage)
  for 4768/4769 as they are written. If the watcher cannot attach (some remote DCs),
  it falls back to Get-WinEvent polling. This tool never changes audit policy.

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
  - StrictMode 2.0 crashed on .Count after an empty Get-WinEvent result unwrapped to $null.
    Empty and single-event results are comma-wrapped and counted with Get-CollectionCount.
  - Access-denied Security-log / WinRM failures used Write-Warning, so the GUI only showed
    "Attempted to perform an unauthorized operation." Collector and audit-check paths now
    log Event Log Readers / WinRM guidance once per target.
  - Historical DC queries used Get-WinEvent -FilterXml QueryList, which often returns
    zero events on Windows PowerShell 5.1. Historical reads now use FilterHashtable
    (StartTime + event IDs) with an XPath fallback, and the log reports events-read vs
    RC4-saved vs AES-skipped so a modern AES-only DC is not mistaken for a query miss.
  - FilterHashtable Id as a typed int[] matches nothing on 5.1 and "No events were found"
    was treated as final, so XPath never ran and the empty-window probe repeated the same
    miss — then claimed Kerberos auditing was off. Id is now Object[], empty hashtable
    results always fall through to XPath and per-ID queries, and the probe distinguishes
    a readable Security log with no 4768/4769 from an access-denied or wrapped window.
  - Historical collection issued one Get-WinEvent for up to 100,000 events, so the GUI
    looked hung on a busy DC. It now pages newest-first until a page is empty (a short
    Get-WinEvent page is not treated as end-of-log). The log reports Hours vs the
    actual 4768/4769 time span so a wrapped Security log is not mistaken for an Hours bug.
  - Session etype used an unanchored (?i)RC4 name match. AvailableKeys blobs such as
    gW8sCt4e...RC4H...= and advertised group strings "AES-SHA1, RC4" were classified
    as RC4 Session even when TicketEncryptionType was 18 (AES256). Etype parsing now
    accepts only scalars (0xNN, 0-255, short cipher names). Microsoft's 4769[20] /
    4768[22] overlay is used only when that slot is a scalar; otherwise the classic
    session field is kept. Live and Historical exports of the same RecordId then match,
    and AES tickets stop appearing as RC4 Session.
  - Historical parse walked every 4768/4769 (mostly AES) and ran ToXml/XmlDocument on
    each. EventData is read from EventLogRecord.Properties (classic 4768/4769 layout)
    and ToXml is only a fallback. AES confirmation rows skip DNS/AD. CSV is buffered
    per page. The collector pages 4768/4769 by EventID and time only.
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
    [switch]$IncludeAes,
    [switch]$IncludeFailures,
    [switch]$ResolveHostnames,
    [switch]$EnrichAD,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputFolder = (Join-Path (Get-Location).Path 'RC4-Reports'),
    [ValidateRange(10,1000000)][int]$MaxHistoryEventsPerDC = 100000,
    [ValidateRange(50,20000)][int]$HistoryPageSize = 2000,
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
$script:ReportedAccessDenied = @{}
$script:LoggedRc4Filter = $false
$script:TicketEtypeTally = @{}
$script:EventDataRegex = $null
$script:CsvBuffer = $null
$script:DnsTimeoutMs = 750
$script:DoIncludeFailures = $false
$script:DoIncludeAes = $false
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

function ConvertTo-IntOrDefault {
    param(
        [string]$Text,
        [int]$Default,
        [int]$Min,
        [int]$Max
    )
    [int]$parsed = $Default
    if (-not [string]::IsNullOrWhiteSpace($Text)) {
        [void][int]::TryParse($Text.Trim(), [ref]$parsed)
    }
    if ($parsed -lt $Min) { $parsed = $Min }
    if ($parsed -gt $Max) { $parsed = $Max }
    return $parsed
}

function Test-UiCheckboxChecked {
    param($Box)
    if ($null -eq $Box) { return $false }
    try { return [bool]$Box.Checked } catch { return $false }
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

function Test-IsEtypeScalar {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $text = $Value.Trim()
    if ($text -eq '-' -or $text -eq 'N/A') { return $false }
    # Lists, SET captions, and key material are not a single ticket/session etype.
    if ($text.IndexOf(',') -ge 0) { return $false }
    if ($text.IndexOf(' ') -ge 0) { return $false }
    if ($text.IndexOf('(') -ge 0) { return $false }
    if ($text.Length -gt 48) { return $false }
    # 32-byte AvailableKeys encode as 44-char base64 and often contain the letters RC4.
    if ($text.Length -ge 24 -and $text -match '^[A-Za-z0-9+/]+=*$') { return $false }

    if ($text -match '^(?i)0x[0-9a-f]{1,8}$') { return $true }

    [int]$parsed = 0
    if ([int]::TryParse($text, [ref]$parsed)) {
        return ($parsed -ge 0 -and $parsed -le 255)
    }

    return [bool]($text -match '^(?i)(RC4|ARCFOUR|AES256|AES128|DES)([-_A-Za-z0-9]*)$')
}

function Get-EtypeScalarOrEmpty {
    param([string]$Value)
    if (Test-IsEtypeScalar $Value) { return $Value.Trim() }
    return ''
}

function Get-EtypeCode {
    param([string]$Etype)
    if (-not (Test-IsEtypeScalar $Etype)) { return $null }
    $value = $Etype.Trim()

    switch ($value) {
        '0x17' { return 0x17 }
        '0x12' { return 0x12 }
        '0x11' { return 0x11 }
        '0x18' { return 0x18 }
        '0x13' { return 0x13 }
        '0x14' { return 0x14 }
        '23'   { return 23 }
        '24'   { return 24 }
        '18'   { return 18 }
        '17'   { return 17 }
        '0x00000017' { return 0x17 }
        '0x00000018' { return 0x18 }
        '0x00000012' { return 0x12 }
        '0x00000011' { return 0x11 }
    }

    if ($value -match '^(?i)0x([0-9a-f]+)$') {
        try { return [Convert]::ToInt32($Matches[1], 16) } catch { return $null }
    }

    [int]$parsed = 0
    if ([int]::TryParse($value, [ref]$parsed)) { return $parsed }

    # Names from ticket/session fields. Anchored so "rc4" inside a key blob cannot match.
    switch -Regex ($value) {
        '^(?i)(RC4-HMAC-NT-EXP|RC4-HMAC-EXP|RC4-HMAC-OLD-EXP)$' { return 0x18 }
        '^(?i)(RC4(-HMAC(-NT)?)?|ARCFOUR([-_]HMAC)?)$' { return 0x17 }
        '^(?i)(AES256-SHA384|AES256-CTS-HMAC-SHA384([-_]192)?)$' { return 0x14 }
        '^(?i)(AES128-SHA256|AES128-CTS-HMAC-SHA256([-_]128)?)$' { return 0x13 }
        '^(?i)(AES256(-SHA96)?|AES256-CTS-HMAC-SHA1-96)$' { return 0x12 }
        '^(?i)(AES128(-SHA96)?|AES128-CTS-HMAC-SHA1-96)$' { return 0x11 }
        '^(?i)(DES-CBC-MD5|DES_CBC_MD5)$' { return 0x3 }
        '^(?i)(DES-CBC-CRC|DES)$' { return 0x1 }
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
    if (-not (Test-IsEtypeScalar $Etype)) { return 'Not logged' }
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
    $n = $n.TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($n)) { return $true }
    $short = ($n -split '\.')[0]
    $candidates = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
        [void]$candidates.Add($env:COMPUTERNAME)
        if (-not [string]::IsNullOrWhiteSpace($env:USERDNSDOMAIN)) {
            [void]$candidates.Add($env:COMPUTERNAME + '.' + $env:USERDNSDOMAIN)
        }
        if (-not [string]::IsNullOrWhiteSpace($env:USERDOMAIN)) {
            [void]$candidates.Add($env:COMPUTERNAME + '.' + $env:USERDOMAIN)
        }
    }
    try {
        $hostName = [System.Net.Dns]::GetHostName()
        if (-not [string]::IsNullOrWhiteSpace($hostName)) {
            [void]$candidates.Add($hostName)
            [void]$candidates.Add(($hostName -split '\.')[0])
        }
    } catch { }
    foreach ($c in $candidates) {
        if ($n -eq $c -or $short -eq $c) { return $true }
        if (($c -split '\.')[0] -eq $n -or ($c -split '\.')[0] -eq $short) { return $true }
    }
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

function Test-IsAccessDeniedError {
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return $false }
    $ex = $null
    $message = ''
    $fqid = ''
    try { $ex = $ErrorRecord.Exception } catch { }
    try { $fqid = [string]$ErrorRecord.FullyQualifiedErrorId } catch { }
    if ($null -ne $ex) {
        if ($ex -is [System.UnauthorizedAccessException]) { return $true }
        try {
            if ($ex.InnerException -is [System.UnauthorizedAccessException]) { return $true }
        } catch { }
        try { $message = [string]$ex.Message } catch { }
    }
    if ([string]::IsNullOrWhiteSpace($message)) {
        try { $message = [string]$ErrorRecord } catch { }
    }
    return (
        $fqid -match 'UnauthorizedAccess' -or
        $message -match '(?i)unauthorized operation' -or
        $message -match '(?i)access is denied' -or
        $message -match '(?i)access denied' -or
        $message -match '(?i)not authorized'
    )
}

function Get-AccessDeniedGuidance {
    param(
        [string]$Target,
        [string]$Message,
        [string]$Action = 'read the Security log'
    )
    $suffix = ''
    if (-not [string]::IsNullOrWhiteSpace($Message)) { $suffix = " $Message" }
    return "Access denied while trying to $Action on ${Target}. Use an account in Event Log Readers (or Domain Admins). Security-log reads use Event Log RPC; remote auditpol uses WinRM.$suffix"
}

function Write-AccessDeniedOnce {
    param(
        [string]$Target,
        [string]$Message
    )
    if ($null -eq $script:ReportedAccessDenied) { $script:ReportedAccessDenied = @{} }
    $key = [string]$Target
    if ([string]::IsNullOrWhiteSpace($key)) { $key = '.' }
    if ($script:ReportedAccessDenied.ContainsKey($key)) { return }
    $script:ReportedAccessDenied[$key] = $true
    Write-CollectorStatus $Message 'ERROR'
}

function Get-CollectionCount {
    param($Value)
    if ($null -eq $Value) { return 0 }
    if ($Value -is [string]) { return 1 }
    if ($Value -is [System.Collections.ICollection]) { return [int]$Value.Count }
    return 1
}

function ConvertTo-EventArray {
    param($Value)
    if ($null -eq $Value) { return ,([object[]]@()) }
    if ($Value -is [object[]]) { return ,$Value }
    if ($Value -is [System.Array]) { return ,([object[]]$Value) }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $list = New-Object 'System.Collections.Generic.List[object]'
        foreach ($item in $Value) {
            if ($null -ne $item) { [void]$list.Add($item) }
        }
        return ,$list.ToArray()
    }
    return ,([object[]]@($Value))
}

function Get-KerberosLayoutIndices {
    param([int]$EventId, [int]$PropertyCount)
    # Watch-KerbEncryptionUsage (Microsoft) requires 23+ properties and reads
    # SessionKeyEncryptionType at 4769[20] / 4768[22]. Older events have fewer fields.
    # Callers must still Test-IsEtypeScalar before trusting those slots: some DCs
    # put AvailableKeys blobs at the Microsoft indexes.
    $newSchema = ($PropertyCount -ge 23)
    if ($EventId -eq 4769) {
        $session = 11
        if ($newSchema) { $session = 20 }
        return @{
            Ticket  = 5
            Session = $session
            Status  = 8
            Ip      = 6
            Port    = 7
            Account = 0
            Domain  = 1
            Service = 2
        }
    }
    if ($EventId -eq 4768) {
        $session = 14
        if ($newSchema) { $session = 22 }
        return @{
            Ticket  = 7
            Session = $session
            Status  = 6
            Ip      = 9
            Port    = 10
            Account = 0
            Domain  = 1
            Service = 3
        }
    }
    return $null
}

function Get-KerberosPropertyNames {
    param([int]$EventId)
    if ($EventId -eq 4768) {
        return @(
            'TargetUserName','TargetDomainName','TargetSid','ServiceName','ServiceSid',
            'TicketOptions','Status','TicketEncryptionType','PreAuthType','IpAddress','IpPort',
            'CertIssuerName','CertSerialNumber','CertThumbprint',
            'SessionKeyEncryptionType','PreAuthEncryptionType',
            'AccountSupportedEncryptionTypes','AccountAvailableKeys',
            'ServiceSupportedEncryptionTypes','ServiceAvailableKeys',
            'DCSupportedEncryptionTypes','DCAvailableKeys',
            'ClientAdvertizedEncryptionTypes'
        )
    }
    if ($EventId -eq 4769) {
        return @(
            'TargetUserName','TargetDomainName','ServiceName','ServiceSid','TicketOptions',
            'TicketEncryptionType','IpAddress','IpPort','Status','LogonGuid','TransmittedServices',
            'SessionKeyEncryptionType',
            'AccountSupportedEncryptionTypes','AccountAvailableKeys',
            'ServiceSupportedEncryptionTypes','ServiceAvailableKeys',
            'DCSupportedEncryptionTypes','DCAvailableKeys',
            'ClientAdvertizedEncryptionTypes'
        )
    }
    return @()
}

function Get-EventPropertyValue {
    param($Properties, [int]$Index)
    if ($null -eq $Properties -or $Index -lt 0) { return '' }
    try {
        if ($Index -ge [int]$Properties.Count) { return '' }
        return [string]$Properties[$Index].Value
    } catch {
        return ''
    }
}

function Get-EventFieldsFromProperties {
    param($Event)
    if ($null -eq $Event) { return $null }
    $props = $null
    try { $props = $Event.Properties } catch { return $null }
    if ($null -eq $props) { return $null }
    $count = 0
    try { $count = [int]$props.Count } catch { return $null }
    if ($count -lt 1) { return $null }

    $eventId = 0
    try { $eventId = [int]$Event.Id } catch { return $null }
    $names = Get-KerberosPropertyNames $eventId
    if ($names.Count -lt 1) { return $null }

    $layout = Get-KerberosLayoutIndices -EventId $eventId -PropertyCount $count
    if ($null -eq $layout) { return $null }
    if ([int]$layout['Ticket'] -ge $count) { return $null }

    $result = @{}
    $limit = $count
    if ($limit -gt $names.Count) { $limit = $names.Count }
    for ($i = 0; $i -lt $limit; $i++) {
        $result[$names[$i]] = Get-EventPropertyValue $props $i
    }
    $result['TargetUserName'] = Get-EventPropertyValue $props ([int]$layout['Account'])
    $result['TargetDomainName'] = Get-EventPropertyValue $props ([int]$layout['Domain'])
    $result['ServiceName'] = Get-EventPropertyValue $props ([int]$layout['Service'])
    $result['TicketEncryptionType'] = Get-EventPropertyValue $props ([int]$layout['Ticket'])
    $namedRaw = ''
    if ($result.ContainsKey('SessionKeyEncryptionType')) {
        $namedRaw = [string]$result['SessionKeyEncryptionType']
    }
    $namedSession = Get-EtypeScalarOrEmpty $namedRaw
    $layoutSession = Get-EtypeScalarOrEmpty (Get-EventPropertyValue $props ([int]$layout['Session']))
    if (-not [string]::IsNullOrWhiteSpace($layoutSession)) {
        $result['SessionKeyEncryptionType'] = $layoutSession
    } else {
        $result['SessionKeyEncryptionType'] = $namedSession
    }
    $result['Status'] = Get-EventPropertyValue $props ([int]$layout['Status'])
    $result['IpAddress'] = Get-EventPropertyValue $props ([int]$layout['Ip'])
    $result['IpPort'] = Get-EventPropertyValue $props ([int]$layout['Port'])
    if ([string]::IsNullOrWhiteSpace([string]$result['TicketEncryptionType'])) {
        return $null
    }
    return $result
}

function Get-EventXmlText {
    param($Event)
    if ($null -eq $Event) { return '' }
    if ($Event -is [string]) { return $Event }
    $xmlProp = $Event.PSObject.Properties['XmlText']
    if ($null -ne $xmlProp -and -not [string]::IsNullOrWhiteSpace([string]$xmlProp.Value)) {
        return [string]$xmlProp.Value
    }
    try {
        return [string]$Event.ToXml()
    } catch {
        return ''
    }
}

function Get-EventFieldsFromXml {
    param($Event)
    $result = @{}
    $xmlText = Get-EventXmlText $Event
    if ([string]::IsNullOrWhiteSpace($xmlText)) { return $result }

    if ($null -eq $script:EventDataRegex) {
        $regexOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled
        $script:EventDataRegex = New-Object System.Text.RegularExpressions.Regex -ArgumentList @('<Data Name="([^"]+)">([^<]*)</Data>', $regexOpts)
    }
    $matchList = $script:EventDataRegex.Matches($xmlText)
    if ($matchList.Count -gt 0) {
        foreach ($m in $matchList) {
            $result[$m.Groups[1].Value] = $m.Groups[2].Value
        }
        return $result
    }

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

function Get-EventFields {
    param($Event)
    $xmlProp = $null
    try { $xmlProp = $Event.PSObject.Properties['XmlText'] } catch { }
    if ($null -ne $xmlProp -and -not [string]::IsNullOrWhiteSpace([string]$xmlProp.Value)) {
        return (Get-EventFieldsFromXml $Event)
    }
    $fromProps = Get-EventFieldsFromProperties $Event
    if ($null -ne $fromProps -and $fromProps.Count -gt 0) {
        return $fromProps
    }
    return (Get-EventFieldsFromXml $Event)
}

function Test-EventMayBeInteresting {
    param($Event)
    if ($script:DoIncludeAes) { return $true }
    if ($null -eq $Event) { return $false }

    $props = $null
    try { $props = $Event.Properties } catch { return $true }
    if ($null -eq $props) { return $true }
    $count = 0
    try { $count = [int]$props.Count } catch { return $true }
    if ($count -lt 1) { return $true }

    $eventId = 0
    try { $eventId = [int]$Event.Id } catch { }
    $layout = Get-KerberosLayoutIndices -EventId $eventId -PropertyCount $count
    $ticketIndex = -1
    $portIndex = -1
    if ($null -ne $layout) {
        $ticketIndex = [int]$layout['Ticket']
        $portIndex = [int]$layout['Port']
        if (Test-IsRC4Etype (Get-EventPropertyValue $props ([int]$layout['Session']))) { return $true }
    }

    if ($ticketIndex -ge 0 -and $ticketIndex -lt $count) {
        if (Test-IsRC4Etype (Get-EventPropertyValue $props $ticketIndex)) { return $true }
    }

    for ($i = 0; $i -lt $count; $i++) {
        if ($i -eq $portIndex) { continue }
        $value = Get-EventPropertyValue $props $i
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        if (Test-IsRC4Etype $value) { return $true }
        if ($script:DoIncludeOffered -and $value -match '(?i)RC4') { return $true }
    }
    return $false
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

function Add-TicketEtypeTally {
    param([string]$Etype)
    if ($null -eq $script:TicketEtypeTally) { $script:TicketEtypeTally = @{} }
    $name = Get-EncryptionName $Etype
    if ($script:TicketEtypeTally.ContainsKey($name)) {
        $script:TicketEtypeTally[$name] = [int]$script:TicketEtypeTally[$name] + 1
    } else {
        $script:TicketEtypeTally[$name] = 1
    }
}

function Get-TicketEtypeTallyText {
    if ($null -eq $script:TicketEtypeTally -or $script:TicketEtypeTally.Count -lt 1) { return '' }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($entry in ($script:TicketEtypeTally.GetEnumerator() | Sort-Object Name)) {
        [void]$parts.Add(('{0}={1}' -f $entry.Name, $entry.Value))
    }
    return ($parts -join ', ')
}

function Convert-KerberosEvent {
    param($Event, [string]$SourceName)
    try {
        $data = Get-EventFields $Event
    } catch {
        Write-Warning "Unable to parse event on ${SourceName}: $($_.Exception.Message)"
        return $null
    }

    $ticket  = Get-NamedField $data @('TicketEncryptionType')
    Add-TicketEtypeTally $ticket
    $session = Get-EtypeScalarOrEmpty (Get-NamedField $data @('SessionKeyEncryptionType','SessionEncryptionType'))
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
    elseif ($success -and $script:DoIncludeAes) {
        $code = Get-EtypeCode $ticket
        if ($code -eq 0x11 -or $code -eq 0x12 -or $code -eq 0x13 -or $code -eq 0x14) { $category = 'AES Ticket' }
        else { $category = 'Other Kerberos' }
    }
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
    $row.ClientIP = $ip
    $row.ClientPort = (Get-NamedField $data @('IpPort','ClientPort'))
    $row.ServiceName = $service
    $row.ServiceSPNIfLogged = $spn
    $needEnrich = ($category -like 'RC4*') -or ($category -like 'Failed*')
    if ($needEnrich) {
        $row.ClientHostname = (Resolve-ClientHostname $ip)
        $row.AccountADObject = (Find-ADIdentity $account)
        $row.ServiceADObject = (Find-ADIdentity $service)
    } else {
        $row.ClientHostname = ''
        $row.AccountADObject = ''
        $row.ServiceADObject = ''
    }
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
    $script:CsvBuffer = New-Object System.Text.StringBuilder
}

function Flush-CsvBuffer {
    if ($null -eq $script:CsvBuffer -or $script:CsvBuffer.Length -lt 1) { return }
    if ([string]::IsNullOrWhiteSpace($script:CsvPath)) {
        [void]$script:CsvBuffer.Clear()
        return
    }
    [System.IO.File]::AppendAllText($script:CsvPath, $script:CsvBuffer.ToString(), $script:Utf8NoBom)
    [void]$script:CsvBuffer.Clear()
}

function Save-Finding {
    param($Row)
    if ($null -eq $Row) { return }
    [void]$script:Records.Add($Row)
    if (-not [string]::IsNullOrWhiteSpace($script:CsvPath)) {
        if ($null -eq $script:CsvBuffer) { $script:CsvBuffer = New-Object System.Text.StringBuilder }
        $line = ($script:ReportColumns | ForEach-Object {
            $prop = $Row.PSObject.Properties[$_]
            $val = if ($null -ne $prop) { $prop.Value } else { '' }
            ConvertTo-CsvField $val
        }) -join ','
        [void]$script:CsvBuffer.Append($line)
        [void]$script:CsvBuffer.Append([Environment]::NewLine)
        if ($script:CsvBuffer.Length -ge 65536) { Flush-CsvBuffer }
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
    Flush-CsvBuffer
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
    if ($Category -eq 'AES Ticket') { return [int[]](226, 245, 226) }
    if ($Category -eq 'Other Kerberos') { return [int[]](240, 240, 240) }
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
        [bool]$IncludeAesFlag = $false,
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
    $script:DoIncludeAes = $IncludeAesFlag
    $script:DoIncludeFailures = $IncludeFailuresFlag
    $script:Credential = $CredentialObject
    $script:DnsTimeoutMs = $DnsTimeout
    $script:QuietHost = $Quiet
    $script:CancelRequested = $false
    $script:ReportedAccessDenied = @{}
    $script:LoggedRc4Filter = $false
    $script:TicketEtypeTally = @{}
    $script:EventDataRegex = $null
    $script:CsvBuffer = New-Object System.Text.StringBuilder
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

    $session = $null
    try {
        $option = New-PSSessionOption -OpenTimeout 8000 -OperationTimeout 20000
        $sessSplat = @{
            ComputerName  = $ComputerName
            SessionOption = $option
            ErrorAction   = 'Stop'
        }
        if ($script:Credential) { $sessSplat['Credential'] = $script:Credential }
        $session = New-PSSession @sessSplat
        return @(Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $guidArgs -ErrorAction Stop)
    } finally {
        if ($null -ne $session) {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
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
        $events = ConvertTo-EventArray (Get-WinEvent @splat)
        return ((Get-CollectionCount $events) -gt 0)
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
        if (Test-IsAccessDeniedError $_) {
            $errorText = Get-AccessDeniedGuidance -Target $name -Message $_.Exception.Message -Action 'query audit policy'
        }
    }

    if ($source -ne 'auditpol') {
        try {
            $event4768 = Test-SecurityEventIdPresent -ComputerName $name -EventId 4768
            $event4769 = Test-SecurityEventIdPresent -ComputerName $name -EventId 4769
            $source = 'events'
        } catch {
            if (Test-IsAccessDeniedError $_) {
                $errorText = Get-AccessDeniedGuidance -Target $name -Message $_.Exception.Message -Action 'read Security events 4768/4769'
            } elseif ([string]::IsNullOrWhiteSpace($errorText)) {
                $errorText = $_.Exception.Message
            }
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
        [int]$HistoryPageSize = 2000,
        [int]$LivePageSize = 20000,
        [switch]$SkipAuditCheck,
        [switch]$RequireAuditing
    )
    if ((Get-CollectionCount $Targets) -lt 1) {
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
        if ($HistoryPageSize -lt 50) { $HistoryPageSize = 50 }
        foreach ($target in $Targets) {
            if (Test-IsCollectorCancelRequested) { break }
            Write-CollectorStatus "Historical query $($target.Name) since $since"
            if ($target.Kind -eq 'dc') {
                if (Test-IsLocalComputerName $target.Name) {
                    Write-CollectorStatus "Reading the local Security log ($($env:COMPUTERNAME)) for $($target.Name)."
                } else {
                    Write-CollectorStatus "Reading the Security log on $($target.Name) over Event Log RPC (not this computer)."
                }
            }
            Write-CollectorStatus "Options: Hours=$HoursBack IncludeAes=$($script:DoIncludeAes) IncludeOffered=$($script:DoIncludeOffered) IncludeFailures=$($script:DoIncludeFailures). Querying every 4768/4769 since $since (EventID + time only)."
            Write-CollectorStatus "Paging newest matching events first (page size $HistoryPageSize). EventData is read from event Properties (ToXml only if needed). The log updates after each page; Stop is checked between pages."
            if ($script:DoIncludeAes) {
                Write-CollectorStatus 'Include AES is on: AES tickets are listed as well as RC4. AES rows skip DNS/AD; uncheck Include AES for the fastest RC4-only grid.'
            } else {
                Write-CollectorStatus 'Include AES is off: every 4768/4769 in the window is still read, but AES tickets are counted and skipped. Check Include AES tickets to list them.'
            }

            $beforeId = [int64]-1
            $pageNum = 0
            $totalRead = 0
            $saved = 0
            $skipped = 0
            $oldestRead = $null
            $newestRead = $null
            $oldestSaved = $null
            $newestSaved = $null
            $script:TicketEtypeTally = @{}
            $logSummary = Get-SecurityLogSummary -ComputerName $target.Name -Path $target.Path
            if (-not [string]::IsNullOrWhiteSpace($logSummary)) {
                Write-CollectorStatus $logSummary
            }
            while ($totalRead -lt $MaxHistoryEventsPerDC -and -not (Test-IsCollectorCancelRequested)) {
                $pageNum++
                $take = $HistoryPageSize
                $remaining = $MaxHistoryEventsPerDC - $totalRead
                if ($take -gt $remaining) { $take = $remaining }
                Write-CollectorStatus "Fetching page $pageNum (up to $take events) from $($target.Name)..."
                if ($target.Kind -eq 'evtx') {
                    $page = ConvertTo-EventArray (Read-KerberosEvents -Path $target.Path -Since $since -Max $take -BeforeRecordId $beforeId)
                } else {
                    $page = ConvertTo-EventArray (Read-KerberosEvents -ComputerName $target.Name -Since $since -Max $take -BeforeRecordId $beforeId)
                }
                $pageCount = Get-CollectionCount $page
                if ($pageCount -lt 1) { break }

                $minId = [int64]::MaxValue
                $pageOldest = $null
                $pageNewest = $null
                foreach ($ev in $page) {
                    if (Test-IsCollectorCancelRequested) { break }
                    $rid = [int64]$ev.RecordId
                    if ($rid -lt $minId) { $minId = $rid }
                    if ($rid -gt $lastId[$target.Key]) { $lastId[$target.Key] = $rid }
                    $when = $null
                    try { $when = [datetime]$ev.TimeCreated } catch { }
                    if ($null -ne $when) {
                        if ($null -eq $oldestRead -or $when -lt $oldestRead) { $oldestRead = $when }
                        if ($null -eq $newestRead -or $when -gt $newestRead) { $newestRead = $when }
                        if ($null -eq $pageOldest -or $when -lt $pageOldest) { $pageOldest = $when }
                        if ($null -eq $pageNewest -or $when -gt $pageNewest) { $pageNewest = $when }
                    }
                    $row = Convert-KerberosEvent $ev $target.Name
                    if ($null -ne $row) {
                        Save-Finding $row
                        $saved++
                        if ($null -ne $when) {
                            if ($null -eq $oldestSaved -or $when -lt $oldestSaved) { $oldestSaved = $when }
                            if ($null -eq $newestSaved -or $when -gt $newestSaved) { $newestSaved = $when }
                        }
                    } else {
                        $skipped++
                    }
                }
                Flush-CsvBuffer
                if ($beforeId -gt 0 -and $minId -ge $beforeId) {
                    Write-CollectorStatus "Paging did not move older than RecordId $beforeId on $($target.Name); stopping so the same page is not repeated." 'WARN'
                    break
                }
                $beforeId = $minId
                $totalRead += $pageCount
                $span = ''
                if ($null -ne $pageOldest -and $null -ne $pageNewest) {
                    $span = " Times $($pageOldest.ToString('yyyy-MM-dd HH:mm:ss')) .. $($pageNewest.ToString('yyyy-MM-dd HH:mm:ss'))."
                }
                Write-CollectorStatus "Page $pageNum from $($target.Name): $pageCount event(s), $saved finding(s), $skipped AES/other skipped. Total read $totalRead.$span"
                # Do not stop just because this page is smaller than MaxEvents. Remote Get-WinEvent
                # often returns a short page while older 4768/4769 still exist (looks like only ~4 hours).
            }

            if ($totalRead -ge $MaxHistoryEventsPerDC) {
                Write-CollectorStatus "Hit MaxHistoryEventsPerDC ($MaxHistoryEventsPerDC) on $($target.Name). Older matching events in the window were not read." 'WARN'
            }
            $tallyText = Get-TicketEtypeTallyText
            if ($totalRead -lt 1) {
                Write-CollectorStatus (Get-HistoricalEmptyHint -ComputerName $target.Name -Path $target.Path -Since $since) 'WARN'
            } else {
                if (-not [string]::IsNullOrWhiteSpace($tallyText)) {
                    Write-CollectorStatus "Ticket etypes parsed on $($target.Name): $tallyText"
                }
                Write-CollectorStatus "Finished $($target.Name): $totalRead Kerberos event(s) read, $saved finding(s) saved, $skipped AES/other skipped."
                if ($null -ne $oldestRead -and $null -ne $newestRead) {
                    $coverage = @(Get-HistoryCoverageMessages -WindowStart $since -HoursBack $HoursBack -OldestRead $oldestRead -NewestRead $newestRead -OldestSaved $oldestSaved -NewestSaved $newestSaved -SavedCount $saved)
                    foreach ($msg in $coverage) {
                        Write-CollectorStatus $msg.Text $msg.Level
                    }
                }
                if ($saved -lt 1) {
                    $etypeNote = if ([string]::IsNullOrWhiteSpace($tallyText)) { '' } else { " Ticket etypes were $tallyText." }
                    Write-CollectorStatus "No RC4 tickets in this window.$etypeNote That is expected when the DC issues AES. Include AES tickets only if you want those rows listed." 'WARN'
                } elseif ($skipped -gt 0 -and -not $script:DoIncludeAes) {
                    Write-CollectorStatus "Listed RC4 ticket/session rows only. $skipped AES/other event(s) were read and skipped. Check Include AES tickets to list every 4768/4769 in this window." 'WARN'
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

    $liveSubs = @{}
    $pollDcs = New-Object System.Collections.Generic.List[string]
    foreach ($dc in $controllers) {
        try {
            $sub = New-KerberosLiveWatcher -ComputerName $dc
            $liveSubs[$dc] = $sub
            Write-CollectorStatus "Live EventLogWatcher subscribed on $dc (4768/4769 as they are written; RC4 ticket or session, same idea as Watch-KerbEncryptionUsage)." 'SUCCESS'
        } catch {
            Write-CollectorStatus "EventLogWatcher could not attach on $dc ($($_.Exception.Message)). Falling back to Get-WinEvent polling every $PollSeconds second(s)." 'WARN'
            [void]$pollDcs.Add($dc)
        }
    }

    $lastHtml = Get-Date
    $lastPoll = [datetime]'2000-01-01'
    try {
        while (-not (Test-IsCollectorCancelRequested) -and -not (Test-IsLiveWatchExpired $liveDeadline)) {
            Write-CollectorStatus (Get-LiveWatchStatusText -Deadline $liveDeadline -FindingCount $script:Records.Count -LiveMinutes $LiveMinutes)
            $drained = 0
            foreach ($dc in @($liveSubs.Keys)) {
                if (Test-IsCollectorCancelRequested) { break }
                $drained += [int](Read-KerberosLiveQueue -Queue $liveSubs[$dc].Queue -ComputerName $dc)
            }
            if ($drained -gt 0) { Flush-CsvBuffer }

            $now = Get-Date
            $needPoll = ($pollDcs.Count -gt 0) -and (($now - $lastPoll).TotalSeconds -ge [Math]::Max(2, $PollSeconds))
            if ($needPoll) {
                $lastPoll = $now
                foreach ($dc in $pollDcs) {
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
                            $page = ConvertTo-EventArray (Read-KerberosEvents -ComputerName $dc -Since $since -Max $LivePageSize -AfterRecordId $lastId[$dc] -Oldest -RecordIdOnly:$useRecordIdOnly)
                            $pageCount = Get-CollectionCount $page
                            if ($pageCount -lt 1) { $caughtUp = $true; break }
                            foreach ($ev in $page) {
                                $rid = [int64]$ev.RecordId
                                if ($rid -le $lastId[$dc]) { continue }
                                $lastId[$dc] = $rid
                                $row = Convert-KerberosEvent $ev $dc
                                if ($null -ne $row) { Save-Finding $row }
                            }
                            if ($pageCount -lt $LivePageSize) { $caughtUp = $true }
                            $useRecordIdOnly = ($lastId[$dc] -gt 0)
                        }
                        Flush-CsvBuffer
                        $lastScan[$dc] = Get-Date
                    } catch {
                        Write-CollectorStatus "Live poll failed for ${dc}: $($_.Exception.Message)" 'WARN'
                    }
                }
            }

            if (($now - $lastHtml).TotalSeconds -ge 5) {
                try { Write-HtmlReport } catch {
                    Write-CollectorStatus "HTML refresh failed: $($_.Exception.Message)" 'WARN'
                }
                $lastHtml = Get-Date
            }

            $slept = 0
            while ($slept -lt 250 -and -not (Test-IsCollectorCancelRequested) -and -not (Test-IsLiveWatchExpired $liveDeadline)) {
                Start-Sleep -Milliseconds 50
                $slept += 50
            }
        }
    } finally {
        foreach ($dc in @($liveSubs.Keys)) {
            Stop-KerberosLiveWatcher $liveSubs[$dc]
        }
        try { Write-HtmlReport } catch { }
        if (Test-IsLiveWatchExpired $liveDeadline) {
            Write-CollectorStatus "Live watch of $LiveMinutes minute(s) finished. Saved $($script:Records.Count) finding(s) to $script:CsvPath and $script:HtmlPath" 'SUCCESS'
        } else {
            Write-CollectorStatus "Stopped. Findings: $($script:Records.Count). CSV=$script:CsvPath" 'SUCCESS'
        }
    }
}

function Get-Rc4EventDataPredicate {
    # Hex only. Decimal 23/24 collides with IpPort and other EventData fields because
    # Event Log XPath Data[@Name='X']='Y' is not always same-node. AES tickets were
    # coming through the "RC4" filter, then skipped as AES, which looked like 0 findings.
    $hex = @('0x17','0x18','0x00000017','0x00000018')
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($field in @('TicketEncryptionType','SessionKeyEncryptionType')) {
        foreach ($value in $hex) {
            [void]$parts.Add("EventData[Data[@Name='$field']='$value']")
        }
    }
    return '(' + ($parts -join ' or ') + ')'
}

function New-KerberosFilterXPath {
    param(
        [datetime]$Since,
        [int64]$AfterRecordId = -1,
        [int64]$BeforeRecordId = -1,
        [switch]$RecordIdOnly,
        [switch]$NoTimeFilter,
        [switch]$Rc4Only
    )
    $conditions = '(EventID=4768 or EventID=4769)'
    if ($AfterRecordId -ge 0) {
        $conditions += " and EventRecordID>$AfterRecordId"
    }
    if ($BeforeRecordId -gt 0) {
        $conditions += " and EventRecordID<$BeforeRecordId"
    }
    if (-not $RecordIdOnly -and -not $NoTimeFilter) {
        $utc = $Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        $conditions += " and TimeCreated[@SystemTime>='$utc']"
    }
    $path = "*[System[$conditions]]"
    if ($Rc4Only) {
        $path = "*[System[$conditions] and $(Get-Rc4EventDataPredicate)]"
    }
    return $path
}

function New-KerberosQueryXml {
    param(
        [datetime]$Since,
        [int64]$AfterRecordId = -1,
        [switch]$RecordIdOnly
    )
    $xpath = New-KerberosFilterXPath -Since $Since -AfterRecordId $AfterRecordId -RecordIdOnly:$RecordIdOnly
    return @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">$xpath</Select>
  </Query>
</QueryList>
"@
}

function New-KerberosFilterHashtable {
    param(
        [datetime]$Since,
        [string]$Path,
        [switch]$NoTimeFilter
    )
    # Object[] (not int[]) — Get-WinEvent FilterHashtable on 5.1 ignores a typed int[] and returns no matches.
    $hash = @{ Id = @(4768, 4769) }
    if (-not $NoTimeFilter) { $hash['StartTime'] = $Since }
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $hash['Path'] = $Path
    } else {
        $hash['LogName'] = 'Security'
    }
    return $hash
}

function Get-WinEventSplat {
    param(
        [string]$ComputerName,
        [string]$Path,
        [xml]$FilterXml,
        [string]$FilterXPath,
        [hashtable]$FilterHashtable,
        [int]$MaxEvents,
        [switch]$Oldest
    )
    $splat = @{ ErrorAction = 'Stop' }
    if ($MaxEvents -gt 0) { $splat['MaxEvents'] = $MaxEvents }
    if ($Oldest) { $splat['Oldest'] = $true }
    if ($script:Credential) { $splat['Credential'] = $script:Credential }

    if ($FilterHashtable) {
        $splat['FilterHashtable'] = $FilterHashtable
        if (-not [string]::IsNullOrWhiteSpace($ComputerName) -and -not (Test-IsLocalComputerName $ComputerName) -and [string]::IsNullOrWhiteSpace($Path)) {
            $splat['ComputerName'] = $ComputerName
        }
        return $splat
    }

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

function ConvertFrom-WinEventResult {
    param($Raw)
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in @($Raw)) {
        if ($null -ne $item) { [void]$list.Add($item) }
    }
    return ,$list.ToArray()
}

function Invoke-KerberosWinEventAttempt {
    param(
        [hashtable]$Splat,
        [string]$Label
    )
    $result = [pscustomobject]@{
        Label   = $Label
        Events  = [object[]]@()
        Count   = 0
        Failed  = $false
        Message = ''
    }
    try {
        $raw = ConvertTo-EventArray (Get-WinEvent @Splat)
        $result.Events = $raw
        $result.Count = Get-CollectionCount $raw
    } catch {
        if (Test-IsAccessDeniedError $_) { throw }
        if (-not (Test-IsNoMatchingEventsError $_)) {
            $result.Failed = $true
            $result.Message = $_.Exception.Message
        }
    }
    return $result
}

function Read-KerberosEvents {
    param(
        [string]$ComputerName,
        [string]$Path,
        [datetime]$Since,
        [int]$Max,
        [int64]$AfterRecordId = -1,
        [int64]$BeforeRecordId = -1,
        [switch]$Oldest,
        [switch]$RecordIdOnly,
        [switch]$Rc4Only
    )
    $xpath = New-KerberosFilterXPath -Since $Since -AfterRecordId $AfterRecordId -BeforeRecordId $BeforeRecordId -RecordIdOnly:$RecordIdOnly -Rc4Only:$Rc4Only
    try {
        if ($Rc4Only -and -not $script:LoggedRc4Filter) {
            $script:LoggedRc4Filter = $true
            Write-CollectorStatus 'Using an EventData RC4 etype filter so AES tickets are skipped by the log engine. Uncheck Include AES / Include offered RC4 for this fast path.'
        }
        $splat = Get-WinEventSplat -ComputerName $ComputerName -Path $Path -FilterXPath $xpath -MaxEvents $Max -Oldest:$Oldest
        $hit = Invoke-KerberosWinEventAttempt -Splat $splat -Label 'XPath'
        if ($hit.Failed -and $Rc4Only) {
            Write-CollectorStatus "RC4 EventData filter was not accepted ($($hit.Message)); reading all 4768/4769 and skipping AES in memory." 'WARN'
            $xpath = New-KerberosFilterXPath -Since $Since -AfterRecordId $AfterRecordId -BeforeRecordId $BeforeRecordId -RecordIdOnly:$RecordIdOnly
            $splat = Get-WinEventSplat -ComputerName $ComputerName -Path $Path -FilterXPath $xpath -MaxEvents $Max -Oldest:$Oldest
            $hit = Invoke-KerberosWinEventAttempt -Splat $splat -Label 'XPath'
        }
        if ($hit.Failed) {
            Write-CollectorStatus "XPath query failed ($($hit.Message))" 'WARN'
        }
        return ,(ConvertTo-EventArray $hit.Events)
    } catch {
        if (Test-IsNoMatchingEventsError $_) { return ,([object[]]@()) }
        $target = if ($Path) { $Path } else { $ComputerName }
        $msg = $_.Exception.Message
        if (Test-IsAccessDeniedError $_) {
            Write-AccessDeniedOnce -Target $target -Message (Get-AccessDeniedGuidance -Target $target -Message $msg -Action 'read the Security log')
        } else {
            Write-CollectorStatus "Cannot read Security events from ${target}: $msg" 'WARN'
        }
        return ,([object[]]@())
    }
}

function Get-KerberosLiveXPath {
    return '*[System[(EventID=4768 or EventID=4769)]]'
}

function New-KerberosLiveWatcher {
    param([string]$ComputerName)
    $xpath = Get-KerberosLiveXPath
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
        'Security',
        [System.Diagnostics.Eventing.Reader.PathType]::LogName,
        $xpath
    )
    $session = $null
    if (-not [string]::IsNullOrWhiteSpace($ComputerName) -and -not (Test-IsLocalComputerName $ComputerName)) {
        if ($script:Credential) {
            $net = $script:Credential.GetNetworkCredential()
            $domain = $net.Domain
            if ([string]::IsNullOrWhiteSpace($domain)) { $domain = $ComputerName }
            $session = New-Object System.Diagnostics.Eventing.Reader.EventLogSession(
                $ComputerName,
                $domain,
                $net.UserName,
                $net.Password,
                [System.Diagnostics.Eventing.Reader.SessionAuthentication]::Default
            )
        } else {
            $session = New-Object System.Diagnostics.Eventing.Reader.EventLogSession($ComputerName)
        }
        $query.Session = $session
    }
    $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    $watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher $query
    $handler = [System.Diagnostics.Eventing.Reader.EventRecordWrittenEventHandler] {
        param($sender, $eventArgs)
        if ($null -ne $eventArgs -and $null -ne $eventArgs.EventRecord) {
            [void]$queue.Enqueue($eventArgs.EventRecord)
        }
    }
    $watcher.add_EventRecordWritten($handler)
    $watcher.Enabled = $true
    return [pscustomobject]@{
        ComputerName = $ComputerName
        Watcher      = $watcher
        Session      = $session
        Queue        = $queue
        Handler      = $handler
    }
}

function Stop-KerberosLiveWatcher {
    param($Subscription)
    if ($null -eq $Subscription) { return }
    try { $Subscription.Watcher.Enabled = $false } catch { }
    try {
        if ($null -ne $Subscription.Handler) {
            $Subscription.Watcher.remove_EventRecordWritten($Subscription.Handler)
        }
    } catch { }
    try { $Subscription.Watcher.Dispose() } catch { }
    try {
        if ($null -ne $Subscription.Session) { $Subscription.Session.Dispose() }
    } catch { }
}

function Read-KerberosLiveQueue {
    param($Queue, [string]$ComputerName, [int]$MaxDrain = 500)
    if ($null -eq $Queue) { return 0 }
    $n = 0
    $record = $null
    while ($n -lt $MaxDrain -and $Queue.TryDequeue([ref]$record)) {
        $n++
        if ($null -eq $record) { continue }
        $row = Convert-KerberosEvent $record $ComputerName
        if ($null -ne $row) { Save-Finding $row }
    }
    return $n
}

function Get-HistoricalEmptyHint {
    param(
        [string]$ComputerName,
        [string]$Path,
        [datetime]$Since,
        [switch]$Rc4OnlyQuery
    )
    $target = if ($Path) { $Path } else { $ComputerName }
    $newestSecurity = $null
    $newestKerb = $null

    try {
        $securitySplat = Get-WinEventSplat -ComputerName $ComputerName -Path $Path -MaxEvents 1
        $securityHit = Invoke-KerberosWinEventAttempt -Splat $securitySplat -Label 'Security newest'
        if ($securityHit.Count -gt 0) { $newestSecurity = $securityHit.Events[0] }
        elseif ($securityHit.Failed) {
            return "Could not read the Security log on ${target}: $($securityHit.Message)"
        }
    } catch {
        if (Test-IsAccessDeniedError $_) {
            return (Get-AccessDeniedGuidance -Target $target -Message $_.Exception.Message -Action 'read the Security log')
        }
        return "Could not read the Security log on ${target}: $($_.Exception.Message)"
    }

    $xpathAny = New-KerberosFilterXPath -Since $Since -NoTimeFilter
    try {
        $probeSplat = Get-WinEventSplat -ComputerName $ComputerName -Path $Path -FilterXPath $xpathAny -MaxEvents 1
        $probeHit = Invoke-KerberosWinEventAttempt -Splat $probeSplat -Label 'XPath untimed'
        if ($probeHit.Count -gt 0) { $newestKerb = $probeHit.Events[0] }
    } catch {
        if (Test-IsAccessDeniedError $_) {
            return (Get-AccessDeniedGuidance -Target $target -Message $_.Exception.Message -Action 'probe for 4768/4769 events')
        }
    }

    if ($null -eq $newestKerb) {
        foreach ($id in @(4768, 4769)) {
            try {
                $one = @{ Id = $id }
                if (-not [string]::IsNullOrWhiteSpace($Path)) { $one['Path'] = $Path } else { $one['LogName'] = 'Security' }
                $oneSplat = Get-WinEventSplat -ComputerName $ComputerName -Path $Path -FilterHashtable $one -MaxEvents 1
                $oneHit = Invoke-KerberosWinEventAttempt -Splat $oneSplat -Label "Id=$id untimed"
                if ($oneHit.Count -gt 0) { $newestKerb = $oneHit.Events[0]; break }
            } catch { }
        }
    }

    if ($null -ne $newestKerb) {
        $when = $newestKerb.TimeCreated
        if ($Rc4OnlyQuery) {
            return "No RC4 tickets (etype 0x17/0x18) in the window since $($Since.ToString('yyyy-MM-dd HH:mm:ss')) on $target. Newest 4768/4769 is $($when.ToString('yyyy-MM-dd HH:mm:ss')) (event $($newestKerb.Id)) and is not RC4. That is expected when the DC issues AES. Include AES tickets only if you want those rows listed."
        }
        return "No 4768/4769 events in the window since $($Since.ToString('yyyy-MM-dd HH:mm:ss')) on $target. Newest Kerberos ticket event in the log is $($when.ToString('yyyy-MM-dd HH:mm:ss')) (event $($newestKerb.Id)). Increase Hours, or the Security log may have wrapped."
    }

    $suffix = ''
    if ($null -ne $newestSecurity) {
        $suffix = " The Security log is readable (newest event Id=$($newestSecurity.Id) at $($newestSecurity.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))), so this is not an access-denied miss. Advanced Audit Policy can show Success while this DC is still not writing 4768/4769 — run ``auditpol /get /category:*`` on the DC and gpupdate if the Kerberos subcategories are No Auditing."
    }
    return "No 4768/4769 events are in the Security log on $target. Enable Account Logon > Kerberos Authentication Service (4768) and Kerberos Service Ticket Operations (4769) with Success. This tool does not change audit policy.$suffix"
}

function Get-SecurityLogSummary {
    param(
        [string]$ComputerName,
        [string]$Path
    )
    try {
        if (-not [string]::IsNullOrWhiteSpace($Path)) {
            if (-not (Test-Path -LiteralPath $Path)) { return '' }
            $item = Get-Item -LiteralPath $Path
            $mb = [Math]::Round($item.Length / 1MB, 1)
            return "EVTX $($item.Name): $mb MB."
        }
        $splat = @{ ListLog = 'Security'; ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($ComputerName) -and -not (Test-IsLocalComputerName $ComputerName)) {
            $splat['ComputerName'] = $ComputerName
        }
        if ($script:Credential) { $splat['Credential'] = $script:Credential }
        $log = Get-WinEvent @splat | Select-Object -First 1
        if ($null -eq $log) { return '' }
        $maxBytes = 0
        try { $maxBytes = [int64]$log.MaximumSizeInBytes } catch { }
        $records = 0
        try { $records = [int64]$log.RecordCount } catch { }
        $mode = ''
        try { $mode = [string]$log.LogMode } catch { }
        $maxMb = [Math]::Round($maxBytes / 1MB, 1)
        $parts = New-Object System.Collections.Generic.List[string]
        if (-not [string]::IsNullOrWhiteSpace($mode)) { [void]$parts.Add($mode) }
        if ($maxBytes -gt 0) { [void]$parts.Add("max $maxMb MB") }
        if ($records -gt 0) { [void]$parts.Add("$records records") }
        if ($parts.Count -lt 1) { return '' }
        $name = if ($ComputerName) { $ComputerName } else { 'local' }
        return "Security log on ${name}: $($parts -join ', ')."
    } catch {
        return ''
    }
}

function Get-HistoryCoverageMessages {
    param(
        [datetime]$WindowStart,
        [int]$HoursBack,
        [datetime]$OldestRead,
        [datetime]$NewestRead,
        $OldestSaved = $null,
        $NewestSaved = $null,
        [int]$SavedCount = 0
    )
    $messages = New-Object System.Collections.Generic.List[object]
    $readHours = [Math]::Round(($NewestRead - $OldestRead).TotalHours, 2)
    if ($readHours -lt 0) { $readHours = 0 }
    $gapHours = [Math]::Round(($OldestRead - $WindowStart).TotalHours, 2)
    [void]$messages.Add([pscustomobject]@{
        Text  = "Requested window: $HoursBack hour(s) since $($WindowStart.ToString('yyyy-MM-dd HH:mm:ss')). 4768/4769 actually in the log: $($OldestRead.ToString('yyyy-MM-dd HH:mm:ss')) through $($NewestRead.ToString('yyyy-MM-dd HH:mm:ss')) ($readHours hour(s))."
        Level = 'INFO'
    })
    if ($gapHours -gt 1) {
        [void]$messages.Add([pscustomobject]@{
            Text  = "Oldest Kerberos event is $gapHours hour(s) newer than the Hours start. The Security log has wrapped (circular size limit) and does not retain $HoursBack hours of 4768/4769. That is a log-retention limit, not an Hours-box bug. Increase the Security log maximum size on the DC (Event Viewer > Security > Properties) or collect more often."
            Level = 'WARN'
        })
    } else {
        [void]$messages.Add([pscustomobject]@{
            Text  = "Read coverage matches the requested Hours window."
            Level = 'INFO'
        })
    }
    if ($SavedCount -gt 0 -and $null -ne $OldestSaved -and $null -ne $NewestSaved) {
        $savedHours = [Math]::Round(([datetime]$NewestSaved - [datetime]$OldestSaved).TotalHours, 2)
        if ($savedHours -lt 0) { $savedHours = 0 }
        if ($gapHours -le 1 -and ($readHours - $savedHours) -gt 1) {
            [void]$messages.Add([pscustomobject]@{
                Text  = "RC4 findings only span $savedHours hour(s) ($(([datetime]$OldestSaved).ToString('yyyy-MM-dd HH:mm:ss')) through $(([datetime]$NewestSaved).ToString('yyyy-MM-dd HH:mm:ss'))). Older 4768/4769 in this window were AES or otherwise not RC4."
                Level = 'WARN'
            })
        }
    }
    return $messages.ToArray()
}

function Get-NewestSecurityRecordId {
    param([string]$ComputerName)
    try {
        $splat = Get-WinEventSplat -ComputerName $ComputerName -MaxEvents 1
        $newest = ConvertTo-EventArray (Get-WinEvent @splat)
        if ((Get-CollectionCount $newest) -gt 0) { return [int64]$newest[0].RecordId }
    } catch {
        if (Test-IsNoMatchingEventsError $_) { return [int64]0 }
        $msg = $_.Exception.Message
        if (Test-IsAccessDeniedError $_) {
            Write-AccessDeniedOnce -Target $ComputerName -Message (Get-AccessDeniedGuidance -Target $ComputerName -Message $msg -Action 'read the newest Security record')
        } else {
            Write-CollectorStatus "Unable to read newest Security record on ${ComputerName}: $msg" 'WARN'
        }
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
            try {
                $status = Get-KerberosAuditStatus -ComputerName $t.Name -NeedFailures:$needFail
                $level = if ($status.FullyReady) { 'INFO' } else { 'WARN' }
                Add-UiLogLine "[$level] $($status.Summary)"
                $statuses += $status
            } catch {
                $msg = $_.Exception.Message
                if (Test-IsAccessDeniedError $_) {
                    $msg = Get-AccessDeniedGuidance -Target $t.Name -Message $_.Exception.Message -Action 'check Kerberos auditing'
                }
                Add-UiLogLine "[ERROR] $msg"
                $statuses += [pscustomobject]@{
                    Computer     = $t.Name
                    Source       = 'unavailable'
                    FullyReady   = $false
                    PartialReady = $false
                    Summary      = $msg
                    Error        = $msg
                }
            }
        }
    } finally {
        if ($script:Ui.Form) { $script:Ui.Form.UseWaitCursor = $false }
    }
    return $statuses
}

function Confirm-UiKerberosAuditing {
    try {
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
    } catch {
        $msg = $_.Exception.Message
        if (Test-IsAccessDeniedError $_) {
            $msg = Get-AccessDeniedGuidance -Target 'selected DC(s)' -Message $_.Exception.Message -Action 'check Kerberos auditing'
        }
        Add-UiLogLine "[ERROR] $msg"
        $require = $false
        if ($script:Ui.ChkRequireAudit) { $require = [bool]$script:Ui.ChkRequireAudit.Checked }
        if ($require) {
            [System.Windows.Forms.MessageBox]::Show($msg, 'Kerberos auditing check failed', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            return $false
        }
        $msg += [Environment]::NewLine + [Environment]::NewLine + 'Continue watching logs anyway?'
        $result = [System.Windows.Forms.MessageBox]::Show($msg, 'Kerberos auditing check failed', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return ($result -eq [System.Windows.Forms.DialogResult]::Yes)
    }
}

function Start-UiCollector {
    $targets = @(Get-UiCheckedTargets)
    if ((Get-CollectionCount $targets) -lt 1) {
        [System.Windows.Forms.MessageBox]::Show(
            'Check at least one domain controller or EVTX file.',
            'No targets',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        return
    }

    try {
    if (-not (Confirm-UiKerberosAuditing)) { return }

    $hours = ConvertTo-IntOrDefault -Text $script:Ui.HoursBox.Text -Default 24 -Min 1 -Max 720
    $poll = ConvertTo-IntOrDefault -Text $script:Ui.PollBox.Text -Default 5 -Min 2 -Max 3600
    $liveMins = ConvertTo-IntOrDefault -Text $script:Ui.LiveBox.Text -Default 0 -Min 0 -Max 10080

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
        WantDns               = [int](Test-UiCheckboxChecked $script:Ui.ChkDns)
        WantAd                = [int](Test-UiCheckboxChecked $script:Ui.ChkAd)
        WantOffered           = [int](Test-UiCheckboxChecked $script:Ui.ChkOffered)
        WantAes               = [int](Test-UiCheckboxChecked $script:Ui.ChkAes)
        WantFailures          = [int](Test-UiCheckboxChecked $script:Ui.ChkFailures)
        DnsTimeoutMs          = $script:DnsTimeoutMs
        Mode                  = $mode
        HoursBack             = $hours
        PollSeconds           = $poll
        LiveMinutes           = $liveMins
        MaxHistoryEventsPerDC = $MaxHistoryEventsPerDC
        HistoryPageSize       = $HistoryPageSize
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
            . $Settings['ScriptPath'] -SkipMain
            $script:UiSync = $Sync
            $cred = $null
            if ($Settings.ContainsKey('Credential')) { $cred = $Settings['Credential'] }
            Initialize-CollectorSession -OutputFolderPath $Settings['OutputFolder'] `
                -ResolveHostnamesFlag ([bool]$Settings['WantDns']) `
                -EnrichADFlag ([bool]$Settings['WantAd']) `
                -IncludeOfferedFlag ([bool]$Settings['WantOffered']) `
                -IncludeAesFlag ([bool]$Settings['WantAes']) `
                -IncludeFailuresFlag ([bool]$Settings['WantFailures']) `
                -DnsTimeout $Settings['DnsTimeoutMs'] `
                -CredentialObject $cred `
                -Quiet $true
            $Sync.CsvPath = $script:CsvPath
            $Sync.HtmlPath = $script:HtmlPath
            Invoke-KerberosCollection -Targets $Settings['Targets'] -Mode $Settings['Mode'] `
                -HoursBack ([int]$Settings['HoursBack']) -PollSeconds ([int]$Settings['PollSeconds']) `
                -LiveMinutes ([int]$Settings['LiveMinutes']) `
                -MaxHistoryEventsPerDC ([int]$Settings['MaxHistoryEventsPerDC']) -HistoryPageSize ([int]$Settings['HistoryPageSize']) -LivePageSize ([int]$Settings['LivePageSize']) `
                -SkipAuditCheck:([bool]$Settings['SkipAuditCheck']) -RequireAuditing:([bool]$Settings['RequireAuditing'])
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
    Add-UiLogLine ('---- {0} ----' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    Add-UiLogLine ('[INFO] Collector started. Mode={0} Hours={1} IncludeAes={2} IncludeOffered={3} IncludeFailures={4}' -f $mode, $hours, $settings['WantAes'], $settings['WantOffered'], $settings['WantFailures'])
    $script:Ui.Timer.Start()
    } catch {
        $msg = $_.Exception.Message
        if (Test-IsAccessDeniedError $_) {
            $msg = Get-AccessDeniedGuidance -Target 'selected target(s)' -Message $_.Exception.Message -Action 'start collection'
        }
        Add-UiLogLine "[ERROR] $msg"
        if ($script:Ui -and $script:Ui.StatusLabel) { $script:Ui.StatusLabel.Text = $msg }
        try {
            [System.Windows.Forms.MessageBox]::Show($msg, 'Start failed', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        } catch { }
    }
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
        [bool]$InitialAes = $false,
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
    $targetList.Size = New-Object System.Drawing.Size(332, 108)
    $targetList.CheckOnClick = $true
    $y += 116
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
    $y += 22
    $chkAes = New-Object System.Windows.Forms.CheckBox
    $chkAes.Text = 'Include AES tickets (noisy; confirms log reads)'
    $chkAes.Location = New-Object System.Drawing.Point(12, $y)
    $chkAes.AutoSize = $true
    $chkAes.Checked = $InitialAes
    $y += 22
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
        $chkOffered, $chkAes, $chkFailures, $chkDns, $chkAd, $chkRodc, $chkRequireAudit,
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
    [void]$filterBox.Items.AddRange(@('All','RC4 Ticket','RC4 Session','RC4 Offered Only','AES Ticket','Other Kerberos','Failed / RC4 Observed'))
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
        ChkAes          = $chkAes
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
    $btnStart.add_Click({
        try {
            Start-UiCollector
        } catch {
            $msg = $_.Exception.Message
            if (Test-IsAccessDeniedError $_) {
                $msg = Get-AccessDeniedGuidance -Target 'selected target(s)' -Message $_.Exception.Message -Action 'start collection'
            }
            Add-UiLogLine "[ERROR] $msg"
            if ($script:Ui.StatusLabel) { $script:Ui.StatusLabel.Text = $msg }
            [System.Windows.Forms.MessageBox]::Show($msg, 'Start failed', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
    })
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
        try {
            $dcs = @(Get-UiCheckedTargets | Where-Object { $_.Kind -eq 'dc' })
            if ((Get-CollectionCount $dcs) -lt 1) {
                [System.Windows.Forms.MessageBox]::Show('Check at least one domain controller first.', 'Check auditing', 'OK', 'Information') | Out-Null
                return
            }
            $statuses = @(Get-UiKerberosAuditStatuses)
            $notFully = @($statuses | Where-Object { -not $_.FullyReady })
            if ((Get-CollectionCount $notFully) -lt 1) {
                [System.Windows.Forms.MessageBox]::Show('Kerberos 4768/4769 auditing looks enabled on the selected DCs.', 'Check auditing', 'OK', 'Information') | Out-Null
            } else {
                $msg = (($notFully | ForEach-Object { $_.Summary }) -join [Environment]::NewLine)
                [System.Windows.Forms.MessageBox]::Show($msg, 'Kerberos auditing check', 'OK', 'Warning') | Out-Null
            }
        } catch {
            $msg = $_.Exception.Message
            if (Test-IsAccessDeniedError $_) {
                $msg = Get-AccessDeniedGuidance -Target 'selected DC(s)' -Message $_.Exception.Message -Action 'check Kerberos auditing'
            }
            Add-UiLogLine "[ERROR] $msg"
            [System.Windows.Forms.MessageBox]::Show($msg, 'Kerberos auditing check failed', 'OK', 'Error') | Out-Null
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
        [void]$argList.Add('-HistoryPageSize'); [void]$argList.Add([string]$HistoryPageSize)
        if ($IncludeOffered) { [void]$argList.Add('-IncludeOffered') }
        if ($IncludeAes) { [void]$argList.Add('-IncludeAes') }
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
        -InitialAes ([bool]$IncludeAes) `
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

function New-MockPropertyEvent {
    param(
        [int]$Id = 4769,
        [string]$Ticket = '0x12',
        [string]$Session = '0x12',
        [string]$Status = '0x0',
        [string]$Account = 'jsmith@CONTOSO.LOCAL',
        [string]$Domain = 'CONTOSO.LOCAL',
        [string]$Service = 'HOST/dc01.contoso.local',
        [string]$Ip = '::ffff:10.10.10.25',
        [string]$KeyBlob = '',
        [switch]$NewMetadata
    )
    $classicSession = $Session
    if ($NewMetadata) { $classicSession = '0x12' }
    $values = @()
    if ($Id -eq 4768) {
        $values = @(
            $Account, $Domain, 'S-1-5-21-1-2-3-1001', $Service, 'S-1-5-21-1-2-3-502',
            '0x40810010', $Status, $Ticket, '15', $Ip, '54321',
            '-', '-', '-', $classicSession
        )
    } else {
        $values = @(
            $Account, $Domain, $Service, 'S-1-5-21-1-2-3-502', '0x40810010',
            $Ticket, $Ip, '54321', $Status, '{00000000-0000-0000-0000-000000000000}', '-',
            $classicSession
        )
    }
    $props = New-Object System.Collections.ArrayList
    foreach ($value in $values) {
        [void]$props.Add([pscustomobject]@{ Value = $value })
    }
    if ($NewMetadata) {
        $sessionIndex = 20
        if ($Id -eq 4768) { $sessionIndex = 22 }
        while ($props.Count -lt 23) {
            [void]$props.Add([pscustomobject]@{ Value = '' })
        }
        while ($props.Count -le $sessionIndex) {
            [void]$props.Add([pscustomobject]@{ Value = '' })
        }
        if (-not [string]::IsNullOrWhiteSpace($KeyBlob)) {
            $props[$sessionIndex] = [pscustomobject]@{ Value = $KeyBlob }
        } else {
            $props[$sessionIndex] = [pscustomobject]@{ Value = $Session }
        }
    }
    return [pscustomobject]@{
        Id          = $Id
        RecordId    = 9
        TimeCreated = [datetime]'2026-10-28T12:00:00'
        Properties  = $props
    }
}

function Invoke-KerberosRc4SelfTest {
    $script:SelfTestPassed = 0
    $script:SelfTestFailed = 0
    $script:DoResolveHostnames = $false
    $script:DoEnrichAD = $false
    $script:DoIncludeOffered = $false
    $script:DoIncludeAes = $false
    $script:DoIncludeFailures = $false
    $script:LoggedRc4Filter = $false
    $script:TicketEtypeTally = @{}
    $script:EventDataRegex = $null
    $script:CsvBuffer = New-Object System.Text.StringBuilder
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

    $blobRc4Letters = 'gW8sCt4eBg+v76puGQSRRC4Hrpe7aI26frnCahEJib4='
    $blobRc4Lower = '/5UYR6z9JHvBVzyFXSU0rc4ED69063cmzX/LNV6rVf8='
    Assert-True -Condition (-not (Test-IsEtypeScalar $blobRc4Letters)) -Name 'Base64 session-key blob is not an etype scalar'
    Assert-True -Condition (-not (Test-IsRC4Etype $blobRc4Letters)) -Name 'RC4 letters inside a key blob are not RC4-HMAC'
    Assert-True -Condition (-not (Test-IsRC4Etype $blobRc4Lower)) -Name 'Lowercase rc4 inside a key blob is not RC4-HMAC'
    Assert-True -Condition (-not (Test-IsRC4Etype '0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)')) `
        -Name 'msDS-SET caption containing RC4 is not a session etype'
    Assert-True -Condition (-not (Test-IsRC4Etype 'AES-SHA1, RC4')) `
        -Name 'Advertised-etype group string is not a ticket/session etype'
    Assert-True -Condition (Test-IsOfferedRC4 'AES-SHA1, RC4') `
        -Name 'AES-SHA1, RC4 still counts as offered RC4'
    Assert-True -Condition ((Get-EncryptionName $blobRc4Letters) -eq 'Not logged') `
        -Name 'Key blob session field is reported as Not logged'
    Assert-True -Condition (Test-IsEtypeScalar '18' -and (Get-EncryptionName '18') -eq 'AES256-SHA96') `
        -Name 'Decimal 18 ticket etype is AES256-SHA96'

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

    $script:TicketEtypeTally = @{}
    $aesOnly = Convert-KerberosEvent (New-MockKerberosEvent -Ticket '0x12' -Session '0x12') 'DC01'
    Assert-True -Condition ($null -eq $aesOnly) -Name 'AES ticket + AES session is ignored by default'
    Assert-True -Condition ((Get-TicketEtypeTallyText) -match 'AES256-SHA96=1') `
        -Name 'Skipped AES tickets are counted in the etype tally so 0 findings still shows what was read'

    $script:TicketEtypeTally = @{}
    $propAes = New-MockPropertyEvent -Ticket '0x12' -Session '0x12'
    $propAesFields = Get-EventFields $propAes
    Assert-True -Condition ($propAesFields['TicketEncryptionType'] -eq '0x12' -and $propAesFields['SessionKeyEncryptionType'] -eq '0x12') `
        -Name 'EventLogRecord.Properties maps 4769 TicketEncryptionType at index 5 without ToXml'
    Assert-True -Condition ($null -eq (Convert-KerberosEvent $propAes 'DC01')) `
        -Name 'AES 4769 from Properties is skipped without IncludeAes'
    $propRc4 = Convert-KerberosEvent (New-MockPropertyEvent -Ticket '0x17' -Session '0x12') 'DC01'
    Assert-True -Condition ($null -ne $propRc4 -and $propRc4.Category -eq 'RC4 Ticket' -and $propRc4.TicketCipher -eq 'RC4-HMAC') `
        -Name 'RC4 4769 from Properties classifies as RC4 Ticket'
    $propAs = Convert-KerberosEvent (New-MockPropertyEvent -Id 4768 -Ticket '0x17' -Session '0x12') 'DC01'
    Assert-True -Condition ($null -ne $propAs -and $propAs.RequestType -eq 'AS' -and $propAs.Category -eq 'RC4 Ticket') `
        -Name 'RC4 4768 from Properties uses TicketEncryptionType at index 7'
    Assert-True -Condition (-not (Test-EventMayBeInteresting $propAes)) `
        -Name 'AES Properties events are not interesting when IncludeAes is off'
    $newLayout = Get-KerberosLayoutIndices -EventId 4769 -PropertyCount 23
    $oldLayout = Get-KerberosLayoutIndices -EventId 4769 -PropertyCount 12
    Assert-True -Condition (([int]$newLayout['Session'] -eq 20) -and ([int]$newLayout['Ticket'] -eq 5)) `
        -Name 'New 4769 metadata (23+ properties) reads SessionKeyEncryptionType at index 20 like Watch-KerbEncryptionUsage'
    Assert-True -Condition (([int]$oldLayout['Session'] -eq 11) -and ([int]$oldLayout['Ticket'] -eq 5)) `
        -Name 'Classic 4769 layout keeps TicketEncryptionType at index 5'
    $asLayout = Get-KerberosLayoutIndices -EventId 4768 -PropertyCount 23
    Assert-True -Condition (([int]$asLayout['Session'] -eq 22) -and ([int]$asLayout['Ticket'] -eq 7)) `
        -Name 'New 4768 metadata reads SessionKeyEncryptionType at index 22 like Watch-KerbEncryptionUsage'
    $msRc4Session = Convert-KerberosEvent (New-MockPropertyEvent -Ticket '0x12' -Session '0x17' -NewMetadata) 'DC01'
    Assert-True -Condition ($null -ne $msRc4Session -and $msRc4Session.Category -eq 'RC4 Session' -and $msRc4Session.SessionCipher -eq 'RC4-HMAC') `
        -Name 'AES ticket + RC4 session at 4769 index 20 classifies as RC4 Session'
    $blobEvent = New-MockPropertyEvent -Ticket '18' -Session '0x12' -NewMetadata -KeyBlob $blobRc4Letters
    $blobFields = Get-EventFields $blobEvent
    Assert-True -Condition ($blobFields['SessionKeyEncryptionType'] -eq '0x12') `
        -Name 'When 4769[20] is a key blob, session etype keeps the classic scalar at index 11'
    Assert-True -Condition ($null -eq (Convert-KerberosEvent $blobEvent 'DC01')) `
        -Name 'AES256 ticket with key blob at 4769[20] is not classified as RC4 Session'
    Assert-True -Condition (-not (Test-EventMayBeInteresting $blobEvent)) `
        -Name 'AES256 ticket with RC4-looking key blob is not interesting when IncludeAes is off'
    $xmlBlob = New-MockKerberosEvent -Ticket '18' -Session $blobRc4Letters
    Assert-True -Condition ($null -eq (Convert-KerberosEvent $xmlBlob 'DC01')) `
        -Name 'XML SessionKeyEncryptionType key blob with AES256 ticket is not RC4 Session'
    Assert-True -Condition ((Get-KerberosLiveXPath) -eq '*[System[(EventID=4768 or EventID=4769)]]') `
        -Name 'Live EventLogWatcher XPath matches Watch-KerbEncryptionUsage (all 4768/4769)'
    $script:DoIncludeAes = $true
    $aesKept = Convert-KerberosEvent (New-MockKerberosEvent -Ticket '0x12' -Session '0x12') 'DC01'
    Assert-True -Condition ($null -ne $aesKept -and $aesKept.Category -eq 'AES Ticket') `
        -Name '-IncludeAes keeps successful AES tickets as AES Ticket'
    $aesFromBlob = Convert-KerberosEvent $blobEvent 'DC01'
    Assert-True -Condition ($null -ne $aesFromBlob -and $aesFromBlob.Category -eq 'AES Ticket' -and $aesFromBlob.TicketCipher -eq 'AES256-SHA96' -and $aesFromBlob.SessionCipher -eq 'AES256-SHA96' -and $aesFromBlob.SessionEtype -eq '0x12') `
        -Name 'IncludeAes keeps AES256 tickets whose Microsoft session index holds a key blob'
    $script:DoIncludeAes = $false

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
    Assert-True -Condition ((ConvertTo-IntOrDefault -Text '16' -Default 24 -Min 1 -Max 720) -eq 16) `
        -Name 'Hours text 16 parses to 16'
    Assert-True -Condition ((ConvertTo-IntOrDefault -Text '' -Default 24 -Min 1 -Max 720) -eq 24) `
        -Name 'Blank Hours text keeps the default'
    Assert-True -Condition ((ConvertTo-IntOrDefault -Text '9999' -Default 24 -Min 1 -Max 720) -eq 720) `
        -Name 'Hours above the max is clamped'
    $HoursBack = 24
    $IncludeAes = [System.Management.Automation.SwitchParameter]::new($false)
    $flagBag = @{ WantAes = 1; HoursBack = 48; IncludeAes = $true }
    Assert-True -Condition (([bool]$flagBag['WantAes'] -eq $true) -and ([int]$flagBag['HoursBack'] -eq 48)) `
        -Name 'GUI collector flags are read by indexer so script params HoursBack/IncludeAes cannot shadow them'
    $wrapMsgs = @(Get-HistoryCoverageMessages -WindowStart ([datetime]'2026-10-29 07:00:00') -HoursBack 24 -OldestRead ([datetime]'2026-10-30 03:15:00') -NewestRead ([datetime]'2026-10-30 07:14:00'))
    Assert-True -Condition (@($wrapMsgs | Where-Object { $_.Level -eq 'WARN' -and $_.Text -match 'wrapped' }).Count -eq 1) `
        -Name 'Oldest Kerberos event 20 hours newer than Hours start is reported as Security log wrap'
    $subsetMsgs = @(Get-HistoryCoverageMessages -WindowStart ([datetime]'2026-10-29 07:00:00') -HoursBack 24 -OldestRead ([datetime]'2026-10-29 07:05:00') -NewestRead ([datetime]'2026-10-30 07:00:00') -OldestSaved ([datetime]'2026-10-30 03:00:00') -NewestSaved ([datetime]'2026-10-30 07:00:00') -SavedCount 14)
    Assert-True -Condition (@($subsetMsgs | Where-Object { $_.Text -match 'RC4 findings only span' }).Count -eq 1) `
        -Name 'Full window of 4768/4769 with RC4 only in the last 4 hours is distinguished from log wrap'

    $xpathTime = New-KerberosFilterXPath -Since ([datetime]'2026-10-28T00:00:00Z')
    Assert-True -Condition ($xpathTime -match 'EventID=4768' -and $xpathTime -match "SystemTime>='2026-10-28T00:00:00.000Z'" -and $xpathTime -notmatch '&gt;') `
        -Name 'FilterXPath uses a real greater-than for TimeCreated (not an XML entity)'
    Assert-True -Condition ($xpathTime -notmatch 'TicketEncryptionType') `
        -Name 'Default historical XPath is every 4768/4769 (no EventData RC4 etype filter)'
    $qLive = New-KerberosQueryXml -Since ([datetime]'2026-10-28T00:00:00Z') -AfterRecordId 12345 -RecordIdOnly
    $liveXPath = ([xml]$qLive).QueryList.Query.Select.InnerText
    Assert-True -Condition ($liveXPath -match 'EventRecordID>12345' -and $liveXPath -notmatch 'TimeCreated') `
        -Name 'Live catch-up query uses EventRecordID and omits TimeCreated to avoid clock-skew gaps'
    $xpathBefore = New-KerberosFilterXPath -Since ([datetime]'2026-10-28T00:00:00Z') -BeforeRecordId 99999
    Assert-True -Condition ($xpathBefore -match 'EventRecordID<99999' -and $xpathBefore -match 'TimeCreated') `
        -Name 'Historical pages walk backward with EventRecordID less than the previous page'
    $xpathRc4 = New-KerberosFilterXPath -Since ([datetime]'2026-10-28T00:00:00Z') -Rc4Only
    Assert-True -Condition ($xpathRc4 -match 'TicketEncryptionType' -and $xpathRc4 -match '0x17' -and $xpathRc4 -match 'SessionKeyEncryptionType' -and $xpathRc4 -match 'EventData') `
        -Name 'RC4-only XPath filters TicketEncryptionType/SessionKeyEncryptionType in EventData'
    Assert-True -Condition ($xpathRc4 -match "EventData\[Data\[@Name='TicketEncryptionType'\]='0x17'\]" -and $xpathRc4 -notmatch "='23'" -and $xpathRc4 -notmatch "='24'") `
        -Name 'RC4-only XPath uses hex 0x17/0x18 only (decimal 23/24 would match IpPort and leak AES tickets)'
    $script:DoIncludeAes = $false
    $script:DoIncludeOffered = $false
    $plainMock = New-MockKerberosEvent -Ticket '0x12' -Session '0x12'
    Assert-True -Condition (Test-EventMayBeInteresting $plainMock) `
        -Name 'Events without a Properties collection still go through full field parsing'
    $script:DoIncludeAes = $true
    Assert-True -Condition (Test-EventMayBeInteresting $plainMock) `
        -Name 'IncludeAes keeps every Kerberos event eligible for full parsing'
    $script:DoIncludeAes = $false
    $hash = New-KerberosFilterHashtable -Since ([datetime]'2026-10-28T00:00:00')
    $hashIds = @($hash.Id)
    Assert-True -Condition ($hash.LogName -eq 'Security' -and ($hashIds -contains 4768) -and ($hashIds -contains 4769) -and $hash.ContainsKey('StartTime')) `
        -Name 'Historical FilterHashtable uses Security log, 4768/4769, and StartTime'
    Assert-True -Condition ($hash.Id -isnot [int[]]) `
        -Name 'FilterHashtable Id is not a typed int[] (Get-WinEvent 5.1 ignores that and returns no matches)'
    $xpathUntimed = New-KerberosFilterXPath -Since ([datetime]'2026-10-28T00:00:00Z') -NoTimeFilter
    Assert-True -Condition ($xpathUntimed -match 'EventID=4768' -and $xpathUntimed -match 'EventID=4769' -and $xpathUntimed -notmatch 'TimeCreated') `
        -Name 'Untimed XPath probe matches 4768/4769 without a TimeCreated filter'
    $hashEvtx = New-KerberosFilterHashtable -Since ([datetime]'2026-10-28T00:00:00') -Path 'C:\Temp\Security.evtx'
    Assert-True -Condition ($hashEvtx.ContainsKey('Path') -and -not $hashEvtx.ContainsKey('LogName')) `
        -Name 'EVTX FilterHashtable uses Path instead of LogName'
    $hashProbe = New-KerberosFilterHashtable -Since ([datetime]'2026-10-28T00:00:00') -NoTimeFilter
    Assert-True -Condition (-not $hashProbe.ContainsKey('StartTime')) `
        -Name 'Empty-window probe FilterHashtable omits StartTime'
    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
        Assert-True -Condition (Test-IsLocalComputerName ($env:COMPUTERNAME + '.contoso.local')) `
            -Name 'FQDN of this computer is treated as local so the DC query does not go out over RPC'
    }

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

    Assert-True -Condition ((Get-CollectionCount $null) -eq 0) `
        -Name 'Get-CollectionCount treats $null as 0 (empty Get-WinEvent unwrap)'
    Assert-True -Condition ((Get-CollectionCount @()) -eq 0) `
        -Name 'Get-CollectionCount of an empty array is 0'
    Assert-True -Condition ((Get-CollectionCount 'abc') -eq 1) `
        -Name 'Get-CollectionCount does not enumerate strings as characters'
    Assert-True -Condition ((Get-CollectionCount 42) -eq 1) `
        -Name 'Get-CollectionCount of a scalar is 1'
    Assert-True -Condition ((Get-CollectionCount @(1, 2, 3)) -eq 3) `
        -Name 'Get-CollectionCount of a three-item array is 3'
    function script:Invoke-EmptyArrayReturn { return @() }
    $unwrappedEmpty = script:Invoke-EmptyArrayReturn
    Assert-True -Condition ($null -eq $unwrappedEmpty) `
        -Name 'Bare return @() unwraps to $null in PowerShell'
    Assert-True -Condition ((Get-CollectionCount $unwrappedEmpty) -eq 0) `
        -Name 'Get-CollectionCount of an unwrapped empty return is 0'
    function script:Invoke-SingleItemReturn { return ,@(Get-Date) }
    Assert-True -Condition ((Get-CollectionCount (script:Invoke-SingleItemReturn)) -eq 1) `
        -Name 'Get-CollectionCount of a comma-wrapped single item is 1'
    Assert-True -Condition ((Get-CollectionCount (ConvertTo-EventArray $null)) -eq 0) `
        -Name 'ConvertTo-EventArray of $null counts as 0'
    Assert-True -Condition ((Get-CollectionCount (ConvertTo-EventArray 'only-one')) -eq 1) `
        -Name 'ConvertTo-EventArray wraps a scalar as one event'
    Assert-True -Condition ((Get-CollectionCount (ConvertTo-EventArray @(1, 2))) -eq 2) `
        -Name 'ConvertTo-EventArray preserves a two-item array'
    $deniedCaught = $false
    try {
        throw (New-Object System.UnauthorizedAccessException 'Attempted to perform an unauthorized operation.')
    } catch {
        $deniedCaught = Test-IsAccessDeniedError $_
    }
    Assert-True -Condition $deniedCaught `
        -Name 'UnauthorizedAccessException is treated as access denied'
    $otherErr = [pscustomobject]@{
        FullyQualifiedErrorId = 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand'
        Exception = [pscustomobject]@{ Message = 'No events were found that match the specified selection criteria.' }
    }
    Assert-True -Condition (-not (Test-IsAccessDeniedError $otherErr)) `
        -Name 'Empty event-log results are not classified as access denied'
    $hint = Get-AccessDeniedGuidance -Target 'DC01' -Message 'Attempted to perform an unauthorized operation.' -Action 'read the Security log'
    Assert-True -Condition ($hint -match 'Event Log Readers' -and $hint -match 'DC01' -and $hint -match 'WinRM') `
        -Name 'Access-denied guidance names Event Log Readers and WinRM'

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
    -IncludeAesFlag ([bool]$IncludeAes) `
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
    -MaxHistoryEventsPerDC $MaxHistoryEventsPerDC -HistoryPageSize $HistoryPageSize -LivePageSize $LivePageSize `
    -SkipAuditCheck:$SkipAuditCheck -RequireAuditing:$RequireAuditing


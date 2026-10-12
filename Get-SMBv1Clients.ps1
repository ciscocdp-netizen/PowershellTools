<#
.SYNOPSIS
    Interactive, menu-driven tool to find clients connecting to servers (typically
    Domain Controllers) via SMBv1. Compatible with Windows PowerShell 5.1.

.DESCRIPTION
    Reads Event ID 3000 from the Microsoft-Windows-SMBServer/Audit log. Those events
    are written only after SMB1 access auditing is enabled (menu option 3, or
    -EnableAuditing). This does not enable the SMBv1 protocol itself.

    Also reports SMB1 feature / server configuration, live SMBv1 sessions, and
    optional reverse-DNS / Active Directory enrichment of client addresses.

    Run from an elevated PowerShell prompt:
        powershell.exe -ExecutionPolicy Bypass -File .\Get-SMBv1Clients.ps1

.PARAMETER ComputerName
    Target servers. Defaults to this computer. Used by the menu and by
    non-interactive switches.

.PARAMETER Days
    How many days of audit events to search. Default: 7.

.PARAMETER MaxEvents
    Maximum Event ID 3000 records to read per server. 0 means unlimited.

.PARAMETER Scan
    Skip the menu and scan audit logs immediately.

.PARAMETER EnableAuditing
    Skip the menu and enable SMB1 access auditing on the targets.

.PARAMETER DisableAuditing
    Skip the menu and disable SMB1 access auditing on the targets.

.PARAMETER Status
    Skip the menu and print SMB1 / auditing status.

.PARAMETER ExportCsv
    After a scan, write the summary to this CSV path.

.PARAMETER ExportHtml
    After a scan, write an HTML report to this path.

.PARAMETER SkipDns
    Do not reverse-resolve client IP addresses.

.PARAMETER LookupAD
    After DNS (or when the client is already a hostname), look up the computer
    in Active Directory for OS / OU details.

.PARAMETER Credential
    Credential for remote Get-WinEvent / Invoke-Command / CIM.

.PARAMETER SelfTest
    Run built-in parser and summary tests (no SMB or event log required) and exit.

.PARAMETER SkipMain
    Load functions only; do not start the menu. Used when dot-sourcing.

.EXAMPLE
    .\Get-SMBv1Clients.ps1

    Starts the interactive menu.

.EXAMPLE
    .\Get-SMBv1Clients.ps1 -ComputerName DC01,DC02 -Scan -Days 14 -ExportCsv .\smb1.csv

    Non-interactive scan of two DCs for the last 14 days.

.EXAMPLE
    .\Get-SMBv1Clients.ps1 -SelfTest

    Runs parser/unit tests and exits 0 on success.

.NOTES
    Version: 2.0
    Compatible: Windows PowerShell 5.1 and PowerShell 7+ on Windows
    Requires: Elevation for enabling auditing and (typically) for reading the Audit log

    Bugs fixed versus the original script:
      - Event XML parsing never matched ClientName: XmlElement.Name is the tag
        ("Data"), not the Name attribute. Real events also use a default xmlns,
        which breaks naive XPath. Parser now uses Properties[0], then
        local-name() XPath, then the message text.
      - Format-Table output was buffered and often appeared after "Press Enter".
      - Client addresses with a :port suffix were treated as distinct clients and
        reverse DNS failed on them.
      - IPv6-mapped IPv4 (::ffff:x.x.x.x) and [IPv6]:port were not normalized.
      - Reverse DNS ran on "Unknown" / hostnames and could hang with no timeout.
      - "No events" detection only matched one English exception string and could
        hide a missing/disabled log behind "is auditing enabled?".
      - Analytic/debug channels require Get-WinEvent -Oldest; the Audit log type
        is detected and the switch is retried when Windows demands it.
      - Get-ADDomainController | Select -Expand HostName can enumerate a single
        hostname as characters; DC names are collected via ForEach-Object.
      - Remote event collection had no WinRM fallback when RPC Get-WinEvent failed.
      - Enabling AuditSmb1Access did not ensure the Audit channel itself is on.
      - CSV UTF-8 encoding differed between Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [int]$Days = 7,
    [int]$MaxEvents = 0,
    [switch]$Scan,
    [switch]$EnableAuditing,
    [switch]$DisableAuditing,
    [switch]$Status,
    [string]$ExportCsv,
    [string]$ExportHtml,
    [switch]$SkipDns,
    [switch]$LookupAD,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$SelfTest,
    [switch]$SkipMain
)

#Requires -Version 5.1

Set-StrictMode -Off

$script:Version      = '2.0'
$script:AuditLogName = 'Microsoft-Windows-SMBServer/Audit'
$script:AuditEventId = 3000
$script:Targets      = @()
$script:Summary      = New-Object System.Collections.Generic.List[object]
$script:ClientRollup = New-Object System.Collections.Generic.List[object]
$script:DnsCache     = @{}
$script:Credential   = $Credential
$script:NonInteractive = $false

if ($ComputerName -and @($ComputerName).Count -gt 0) {
    $script:Targets = @($ComputerName | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
else {
    $localName = $env:COMPUTERNAME
    if ([string]::IsNullOrWhiteSpace($localName)) {
        try { $localName = [System.Net.Dns]::GetHostName() } catch { $localName = 'localhost' }
    }
    $script:Targets = @($localName)
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Write-Info    { param([string]$Message) Write-Host $Message -ForegroundColor Cyan }
function Write-Ok      { param([string]$Message) Write-Host $Message -ForegroundColor Green }
function Write-WarnLine { param([string]$Message) Write-Host $Message -ForegroundColor Yellow }
function Write-ErrLine { param([string]$Message) Write-Host $Message -ForegroundColor Red }

function Write-Banner {
    try { Clear-Host } catch { }
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ("        SMBv1 Client Audit Tool v{0}         " -f $script:Version) -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ("Targets : {0}" -f ($script:Targets -join ', ')) -ForegroundColor Gray
    Write-Host ("Results : {0} unique client(s) in memory" -f $script:Summary.Count) -ForegroundColor Gray
    if ($script:Credential) {
        Write-Host ("Creds   : {0}" -f $script:Credential.UserName) -ForegroundColor Gray
    }
    Write-Host ""
}

function Pause-Menu {
    if ($script:NonInteractive) { return }
    Write-Host ""
    [void](Read-Host "Press Enter to return to the menu")
}

function Show-Table {
    param($InputObject)
    $rows = @($InputObject)
    if ($rows.Count -eq 0) { return }
    $rows | Format-Table -AutoSize -Wrap | Out-Host
}

function Test-IsElevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal $id
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $true)
    if ($script:NonInteractive) { return $Default }
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = (Read-Host "$Prompt $hint").Trim()
        if ([string]::IsNullOrEmpty($answer)) { return $Default }
        switch -Regex ($answer) {
            '^(y|yes)$' { return $true }
            '^(n|no)$'  { return $false }
            default     { Write-WarnLine "Please enter Y or N." }
        }
    }
}

function Read-Int32Value {
    param(
        [string]$Prompt,
        [int]$Default,
        [int]$Minimum = 1
    )
    if ($script:NonInteractive) { return $Default }
    while ($true) {
        $answer = (Read-Host "$Prompt [default: $Default]").Trim()
        if ([string]::IsNullOrEmpty($answer)) { return $Default }
        $value = 0
        if ([int]::TryParse($answer, [ref]$value) -and $value -ge $Minimum) { return $value }
        Write-WarnLine ("Please enter a whole number greater than or equal to {0}." -f $Minimum)
    }
}

function Get-CsvUtf8Encoding {
    if ($PSVersionTable.PSVersion.Major -ge 6) { return 'utf8BOM' }
    return 'UTF8'
}

# ---------------------------------------------------------------------------
# Address / event parsing (locale-independent)
# ---------------------------------------------------------------------------
function ConvertTo-NormalizedClientAddress {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return 'Unknown' }

    $a = $Address.Trim().Trim('"').Trim("'")
    if ($a.StartsWith('\\')) { $a = $a.TrimStart('\') }

    # [IPv6]:port
    if ($a -match '^\[([^\]]+)\]:(\d+)$') {
        $a = $Matches[1]
    }
    # dotted IPv4:port (do not treat IPv6 as IPv4:port)
    elseif ($a -match '^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$') {
        $a = $Matches[1]
    }

    # IPv6 zone id (fe80::1%12) — strip for grouping / DNS
    if ($a -match '^([^%]+)%\d+$') {
        $withoutZone = $Matches[1]
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse($withoutZone, [ref]$parsed)) {
            $a = $withoutZone
        }
    }

    # IPv4-mapped IPv6
    if ($a -match '^(?i)::ffff:((?:\d{1,3}\.){3}\d{1,3})$') {
        $a = $Matches[1]
    }

    if ([string]::IsNullOrWhiteSpace($a)) { return 'Unknown' }
    return $a
}

function Test-IsIpAddress {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $parsed = $null
    return [System.Net.IPAddress]::TryParse($Value, [ref]$parsed)
}

function Get-Smbv1ClientAddressFromXml {
    param([string]$XmlText)

    if ([string]::IsNullOrWhiteSpace($XmlText)) { return $null }

    try {
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.LoadXml($XmlText)
    }
    catch {
        return $null
    }

    $nodes = $doc.SelectNodes("//*[local-name()='Data']")
    if ($null -eq $nodes) { return $null }

    foreach ($node in $nodes) {
        $attr = $node.GetAttribute('Name')
        if ($attr -eq 'ClientName' -or $attr -eq 'ClientAddress') {
            $text = $node.InnerText
            if (-not [string]::IsNullOrWhiteSpace($text)) { return $text.Trim() }
        }
    }

    if ($nodes.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace($nodes[0].InnerText)) {
        return $nodes[0].InnerText.Trim()
    }
    return $null
}

function Get-EventPropertyValue {
    param($Event, [int]$Index = 0)

    if ($null -eq $Event) { return $null }
    $propsMember = $Event.PSObject.Properties['Properties']
    if ($null -eq $propsMember -or $null -eq $propsMember.Value) { return $null }

    $items = @($propsMember.Value)
    if ($items.Count -le $Index) { return $null }

    $item = $items[$Index]
    if ($null -eq $item) { return $null }

    $valueMember = $item.PSObject.Properties['Value']
    if ($null -eq $valueMember -or $null -eq $valueMember.Value) { return $null }
    $text = [string]$valueMember.Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text
}

function Get-EventXmlText {
    param($Event)

    if ($null -eq $Event) { return $null }

    $method = $Event.PSObject.Methods['ToXml']
    if ($method) {
        try { return [string]$Event.ToXml() } catch { }
    }

    foreach ($name in @('ToXml', 'Xml')) {
        $prop = $Event.PSObject.Properties[$name]
        if ($prop -and $prop.Value) { return [string]$prop.Value }
    }
    return $null
}

function Get-Smbv1ClientAddressFromEvent {
    param($Event)

    $raw = Get-EventPropertyValue -Event $Event -Index 0
    if ($raw) { return ConvertTo-NormalizedClientAddress -Address $raw }

    $xmlText = Get-EventXmlText -Event $Event
    $fromXml = Get-Smbv1ClientAddressFromXml -XmlText $xmlText
    if ($fromXml) { return ConvertTo-NormalizedClientAddress -Address $fromXml }

    $msgMember = $Event.PSObject.Properties['Message']
    if ($msgMember -and $msgMember.Value) {
        $msg = [string]$msgMember.Value
        if ($msg -match 'Client Address:\s*(\S+)') {
            return ConvertTo-NormalizedClientAddress -Address $Matches[1]
        }
        if ($msg -match 'ClientName:\s*(\S+)') {
            return ConvertTo-NormalizedClientAddress -Address $Matches[1]
        }
        if ($msg -match '((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?') {
            return ConvertTo-NormalizedClientAddress -Address $Matches[1]
        }
    }

    return 'Unknown'
}

function Test-IsNoEventsError {
    param($ErrorRecord)

    if ($null -eq $ErrorRecord) { return $false }

    $fqid = [string]$ErrorRecord.FullyQualifiedErrorId
    if ($fqid -match 'NoMatchingEventsFound') { return $true }

    $msg = ''
    if ($ErrorRecord.PSObject.Properties['Exception'] -and $ErrorRecord.Exception) {
        $msg = [string]$ErrorRecord.Exception.Message
    }
    if ([string]::IsNullOrWhiteSpace($msg)) { $msg = [string]$ErrorRecord }

    # Do NOT treat "log does not exist" / access denied as "no events".
    return ($msg -match 'No events were found|No matching events found')
}

function New-Smbv1EventFilter {
    param([datetime]$StartTime)
    return @{
        LogName   = $script:AuditLogName
        Id        = $script:AuditEventId
        StartTime = $StartTime
    }
}

# ---------------------------------------------------------------------------
# Remoting / targets
# ---------------------------------------------------------------------------
function Test-IsLocalComputer {
    param([string]$Computer)

    if ([string]::IsNullOrWhiteSpace($Computer)) { return $true }

    $n = $Computer.Trim()
    if ($n -eq '.' -or $n -eq 'localhost' -or $n -eq '127.0.0.1' -or $n -eq '::1' -or $n -eq '[::1]') {
        return $true
    }

    $short = ($n -split '\.')[0]
    $local = $env:COMPUTERNAME
    if ($local -and ($short -eq $local -or $n -eq $local)) { return $true }

    try {
        $hostName = [System.Net.Dns]::GetHostName()
        if ($n -eq $hostName) { return $true }
        if ($short -eq ($hostName -split '\.')[0]) { return $true }
    }
    catch { }

    return $false
}

function Invoke-OnTarget {
    param(
        [string]$Computer,
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )

    if (Test-IsLocalComputer $Computer) {
        return & $ScriptBlock @ArgumentList
    }

    $ic = @{
        ComputerName = $Computer
        ScriptBlock  = $ScriptBlock
        ErrorAction  = 'Stop'
    }
    if ($ArgumentList -and @($ArgumentList).Count -gt 0) {
        $ic.ArgumentList = $ArgumentList
    }
    if ($script:Credential) { $ic.Credential = $script:Credential }
    return Invoke-Command @ic
}

function Get-DomainControllerNames {
    $names = New-Object System.Collections.Generic.List[string]

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop)
        foreach ($dc in $dcs) {
            # ForEach-Object / property access — never pipe a single string to
            # Select-Object -ExpandProperty (that enumerates characters).
            $hostName = $null
            if ($dc.PSObject.Properties['HostName'] -and $dc.HostName) {
                $hostName = [string]$dc.HostName
            }
            elseif ($dc.PSObject.Properties['Name'] -and $dc.Name) {
                $hostName = [string]$dc.Name
            }
            if ($hostName) { [void]$names.Add($hostName) }
        }
        if ($names.Count -gt 0) { return @($names) }
    }
    catch { }

    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        foreach ($dc in @($domain.DomainControllers)) {
            if ($dc.Name) { [void]$names.Add([string]$dc.Name) }
        }
        if ($names.Count -gt 0) { return @($names) }
    }
    catch { }

    throw "Could not enumerate domain controllers. Install the RSAT ActiveDirectory module or run this on a domain-joined computer."
}

# ---------------------------------------------------------------------------
# Name resolution
# ---------------------------------------------------------------------------
function Resolve-ClientName {
    param(
        [string]$Address,
        [int]$TimeoutMs = 2000
    )

    if (-not $script:DnsCache.ContainsKey($Address)) {
        if (-not (Test-IsIpAddress -Value $Address) -or $Address -eq 'Unknown') {
            $script:DnsCache[$Address] = if ($Address -eq 'Unknown') { 'N/A' } else { $Address }
            return $script:DnsCache[$Address]
        }

        try {
            $task = [System.Net.Dns]::GetHostEntryAsync($Address)
            if ($task.Wait($TimeoutMs)) {
                if ($task.IsFaulted -or $null -eq $task.Result) {
                    $script:DnsCache[$Address] = 'Unresolved'
                }
                else {
                    $script:DnsCache[$Address] = $task.Result.HostName
                }
            }
            else {
                $script:DnsCache[$Address] = 'Unresolved (timeout)'
            }
        }
        catch {
            $script:DnsCache[$Address] = 'Unresolved'
        }
    }
    return $script:DnsCache[$Address]
}

function Get-AdComputerDetails {
    param([string]$HostName)

    if ([string]::IsNullOrWhiteSpace($HostName) -or $HostName -match '^(N/A|Unresolved|Unknown)') {
        return $null
    }

    $short = ($HostName -split '\.')[0]
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        return Get-ADComputer -Identity $short -Properties OperatingSystem, OperatingSystemVersion, DistinguishedName, Description, LastLogonDate -ErrorAction Stop
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# SMB configuration / event collection
# ---------------------------------------------------------------------------
function Get-Smbv1AuditEvents {
    param(
        [string]$Computer,
        [datetime]$StartTime,
        [int]$MaxEventsPerServer = 0
    )

    $filter = New-Smbv1EventFilter -StartTime $StartTime

    $gwe = @{
        FilterHashtable = $filter
        ErrorAction     = 'Stop'
    }
    if ($MaxEventsPerServer -gt 0) { $gwe.MaxEvents = $MaxEventsPerServer }

    $isLocal = Test-IsLocalComputer $Computer
    if (-not $isLocal) {
        $gwe.ComputerName = $Computer
        if ($script:Credential) { $gwe.Credential = $script:Credential }
    }

    $useOldest = $false
    try {
        $list = @{ ListLog = $script:AuditLogName; ErrorAction = 'Stop' }
        if (-not $isLocal) {
            $list.ComputerName = $Computer
            if ($script:Credential) { $list.Credential = $script:Credential }
        }
        $logInfo = Get-WinEvent @list
        if (-not $logInfo.IsEnabled) {
            throw "The $script:AuditLogName log is disabled on $Computer. Enable SMB1 access auditing first (option 3)."
        }
        if ([string]$logInfo.LogType -match 'Analytic|Debug') { $useOldest = $true }
    }
    catch {
        if ($_.Exception.Message -match 'disabled') { throw }
        # Log list can fail on some hosts; still try the query.
    }

    $invokeQuery = {
        param([hashtable]$Params, [bool]$Oldest)
        $p = @{}
        foreach ($key in $Params.Keys) { $p[$key] = $Params[$key] }
        if ($Oldest) { $p['Oldest'] = $true }
        Get-WinEvent @p
    }

    try {
        return @(& $invokeQuery $gwe $useOldest)
    }
    catch {
        if (Test-IsNoEventsError $_) { return @() }

        if (-not $useOldest -and $_.Exception.Message -match 'Oldest') {
            try {
                return @(& $invokeQuery $gwe $true)
            }
            catch {
                if (Test-IsNoEventsError $_) { return @() }
                throw
            }
        }

        if ($isLocal) { throw }

        Write-WarnLine "    RPC/Get-WinEvent failed on $Computer; retrying via PowerShell remoting..."
        $remote = Invoke-OnTarget -Computer $Computer -ArgumentList $StartTime, $MaxEventsPerServer, $script:AuditLogName, $script:AuditEventId -ScriptBlock {
            param($start, $max, $logName, $eventId)
            $filter = @{ LogName = $logName; Id = $eventId; StartTime = $start }
            $p = @{ FilterHashtable = $filter; ErrorAction = 'Stop' }
            if ($max -gt 0) { $p.MaxEvents = $max }
            try {
                $evts = @(Get-WinEvent @p)
            }
            catch {
                $fq = [string]$_.FullyQualifiedErrorId
                $msg = [string]$_.Exception.Message
                if ($fq -match 'NoMatchingEventsFound' -or $msg -match 'No events were found|No matching events found') {
                    if ($msg -match 'Oldest') {
                        $p['Oldest'] = $true
                        try { $evts = @(Get-WinEvent @p) }
                        catch { return @() }
                    }
                    else { return @() }
                }
                elseif ($msg -match 'Oldest') {
                    $p['Oldest'] = $true
                    $evts = @(Get-WinEvent @p)
                }
                else { throw }
            }
            foreach ($e in $evts) {
                $addr = $null
                if ($e.Properties -and $e.Properties.Count -gt 0) {
                    $addr = [string]$e.Properties[0].Value
                }
                [pscustomobject]@{
                    TimeCreated   = $e.TimeCreated
                    ClientAddress = $addr
                    Message       = $e.Message
                    Id            = $e.Id
                }
            }
        }
        return @($remote)
    }
}

function ConvertTo-Smbv1Summary {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Events,
        [bool]$ResolveDns = $false,
        [bool]$LookupAD = $false,
        [scriptblock]$NameResolver = $null
    )

    $list = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Events -or @($Events).Count -eq 0) { return $list }

    $groups = @($Events | Group-Object DomainController, ClientAddress)
    foreach ($g in $groups) {
        $first = @($g.Group)[0]
        $times = @($g.Group | Sort-Object TimeCreated)
        $address = [string]$first.ClientAddress
        $hostName = 'N/A'

        if ($ResolveDns) {
            if ($NameResolver) {
                $hostName = [string](& $NameResolver $address)
            }
            else {
                $hostName = Resolve-ClientName -Address $address
            }
        }
        elseif (-not (Test-IsIpAddress -Value $address) -and $address -ne 'Unknown') {
            $hostName = $address
        }

        $os = ''
        $ou = ''
        if ($LookupAD -and $hostName -and $hostName -notmatch '^(N/A|Unresolved|Unknown)') {
            $ad = Get-AdComputerDetails -HostName $hostName
            if ($ad) {
                $os = [string]$ad.OperatingSystem
                $ou = [string]$ad.DistinguishedName
            }
        }

        [void]$list.Add([pscustomobject]@{
            DomainController = $first.DomainController
            ClientAddress    = $address
            HostName         = $hostName
            OperatingSystem  = $os
            DistinguishedName = $ou
            ConnectionCount  = [int]$g.Count
            FirstSeen        = $times[0].TimeCreated
            LastSeen         = $times[-1].TimeCreated
        })
    }

    $sorted = @($list | Sort-Object @{ Expression = 'ConnectionCount'; Descending = $true }, @{ Expression = 'ClientAddress'; Descending = $false })
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($row in $sorted) { [void]$out.Add($row) }
    return $out
}

function ConvertTo-Smbv1ClientRollup {
    param(
        [AllowEmptyCollection()]
        [object[]]$SummaryRows
    )

    $list = New-Object System.Collections.Generic.List[object]
    if ($null -eq $SummaryRows -or @($SummaryRows).Count -eq 0) { return $list }

    $groups = @($SummaryRows | Group-Object ClientAddress)
    foreach ($g in $groups) {
        $rows = @($g.Group)
        $dcs = @($rows | Select-Object -ExpandProperty DomainController -Unique)
        $hostName = @($rows | Where-Object { $_.HostName -and $_.HostName -ne 'N/A' } | Select-Object -First 1 -ExpandProperty HostName)
        if (-not $hostName) { $hostName = 'N/A' }
        $firsts = @($rows | Sort-Object FirstSeen)
        $lasts  = @($rows | Sort-Object LastSeen)
        [void]$list.Add([pscustomobject]@{
            ClientAddress      = $g.Name
            HostName           = $hostName
            DomainControllers  = ($dcs -join ', ')
            ConnectionCount    = [int](($rows | Measure-Object -Property ConnectionCount -Sum).Sum)
            FirstSeen          = $firsts[0].FirstSeen
            LastSeen           = $lasts[-1].LastSeen
        })
    }

    $sorted = @($list | Sort-Object @{ Expression = 'ConnectionCount'; Descending = $true }, @{ Expression = 'ClientAddress'; Descending = $false })
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($row in $sorted) { [void]$out.Add($row) }
    return $out
}

function ConvertTo-Smbv1Html {
    param(
        [object[]]$SummaryRows,
        [object[]]$RollupRows,
        [string[]]$Targets,
        [int]$Days
    )

    function ConvertTo-HtmlCell([string]$Value) {
        if ($null -eq $Value) { return '' }
        return ($Value -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;')
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"/>')
    [void]$sb.AppendLine('<title>SMBv1 Client Audit</title>')
    [void]$sb.AppendLine('<style>body{font-family:Segoe UI,Tahoma,sans-serif;margin:24px;color:#222}')
    [void]$sb.AppendLine('h1{color:#0b6aa2}table{border-collapse:collapse;margin:12px 0 28px;width:100%}')
    [void]$sb.AppendLine('th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;font-size:13px}')
    [void]$sb.AppendLine('th{background:#0b6aa2;color:#fff}tr:nth-child(even){background:#f4f8fb}')
    [void]$sb.AppendLine('.meta{color:#555;margin-bottom:16px}</style></head><body>')
    [void]$sb.AppendLine('<h1>SMBv1 Client Audit</h1>')
    [void]$sb.AppendLine(('<p class="meta">Generated {0:yyyy-MM-dd HH:mm:ss} | Days: {1} | Targets: {2}</p>' -f (Get-Date), $Days, ((@($Targets) -join ', '))))

    [void]$sb.AppendLine('<h2>Unique clients by server</h2><table><tr>')
    foreach ($h in @('DomainController','ClientAddress','HostName','OperatingSystem','ConnectionCount','FirstSeen','LastSeen')) {
        [void]$sb.Append("<th>$h</th>")
    }
    [void]$sb.AppendLine('</tr>')
    foreach ($row in @($SummaryRows)) {
        [void]$sb.Append('<tr>')
        foreach ($h in @('DomainController','ClientAddress','HostName','OperatingSystem','ConnectionCount','FirstSeen','LastSeen')) {
            [void]$sb.Append('<td>' + (ConvertTo-HtmlCell ([string]$row.$h)) + '</td>')
        }
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h2>Unique clients across all servers</h2><table><tr>')
    foreach ($h in @('ClientAddress','HostName','DomainControllers','ConnectionCount','FirstSeen','LastSeen')) {
        [void]$sb.Append("<th>$h</th>")
    }
    [void]$sb.AppendLine('</tr>')
    foreach ($row in @($RollupRows)) {
        [void]$sb.Append('<tr>')
        foreach ($h in @('ClientAddress','HostName','DomainControllers','ConnectionCount','FirstSeen','LastSeen')) {
            [void]$sb.Append('<td>' + (ConvertTo-HtmlCell ([string]$row.$h)) + '</td>')
        }
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</table></body></html>')
    return $sb.ToString()
}

function Save-Smbv1Results {
    param(
        [string]$Path,
        [ValidateSet('Csv','Html')]
        [string]$Format = 'Csv'
    )

    if ($script:Summary.Count -eq 0) {
        Write-WarnLine "No results in memory. Run a scan first (option 5)."
        Pause-Menu
        return
    }

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    try {
        if ($Format -eq 'Html') {
            $html = ConvertTo-Smbv1Html -SummaryRows @($script:Summary) -RollupRows @($script:ClientRollup) -Targets @($script:Targets) -Days $Days
            [System.IO.File]::WriteAllText($Path, $html, [System.Text.UTF8Encoding]::new($true))
        }
        else {
            $script:Summary | Export-Csv -Path $Path -NoTypeInformation -Encoding (Get-CsvUtf8Encoding) -ErrorAction Stop
        }
        Write-Ok ("[+] Exported {0} row(s) to {1}" -f $script:Summary.Count, $Path)
    }
    catch {
        Write-ErrLine "[!] Export failed: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------
function Select-Targets {
    Write-Banner
    Write-Host "Select target servers:" -ForegroundColor White
        $localLabel = $env:COMPUTERNAME
        if ([string]::IsNullOrWhiteSpace($localLabel)) {
            try { $localLabel = [System.Net.Dns]::GetHostName() } catch { $localLabel = 'localhost' }
        }
        Write-Host "  1) This computer ($localLabel)"
    Write-Host "  2) All Domain Controllers in the domain (RSAT AD module or .NET AD)"
    Write-Host "  3) Enter server names manually"
    Write-Host "  B) Back"
    $choice = (Read-Host "Choice").Trim().ToUpper()

    switch ($choice) {
        '1' {
            $localName = $env:COMPUTERNAME
            if ([string]::IsNullOrWhiteSpace($localName)) { $localName = [System.Net.Dns]::GetHostName() }
            $script:Targets = @($localName)
        }
        '2' {
            try {
                $dcs = @(Get-DomainControllerNames)
                if ($dcs.Count -eq 0) { throw "No domain controllers returned." }
                $script:Targets = $dcs
                Write-Ok "[+] Found $($dcs.Count) DC(s): $($dcs -join ', ')"
            }
            catch {
                Write-ErrLine "[!] Could not enumerate DCs: $($_.Exception.Message)"
            }
            Pause-Menu
        }
        '3' {
            $raw = Read-Host "Enter server names separated by commas (e.g. DC01,DC02)"
            $names = @($raw -split '[,;\s]+' | Where-Object { $_ -ne '' })
            if ($names.Count -gt 0) {
                $script:Targets = $names
                Write-Ok "[+] Targets set to: $($names -join ', ')"
            }
            else {
                Write-WarnLine "[!] No names entered; targets unchanged."
            }
            Pause-Menu
        }
        default { }
    }
}

function Show-AuditStatus {
    param([switch]$NoPause)

    Write-Banner
    Write-Host "Checking SMB1 configuration..." -ForegroundColor White
    $statusScript = {
        $feature = 'Unknown'
        try {
            $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
            $feature = [string]$feat.State
        }
        catch {
            try {
                $feat = Get-WindowsFeature -Name FS-SMB1 -ErrorAction Stop
                if ($feat.PSObject.Properties['InstallState'] -and $null -ne $feat.InstallState) {
                    $feature = [string]$feat.InstallState
                }
                elseif ($feat.PSObject.Properties['Installed']) {
                    $feature = $(if ($feat.Installed) { 'Installed' } else { 'Available' })
                }
            }
            catch { }
        }

        $cfg = Get-SmbServerConfiguration -ErrorAction Stop
        $logEnabled = $null
        $logType    = $null
        $logCount   = $null
        try {
            $log = Get-WinEvent -ListLog 'Microsoft-Windows-SMBServer/Audit' -ErrorAction Stop
            $logEnabled = $log.IsEnabled
            $logType    = [string]$log.LogType
            $logCount   = $log.RecordCount
        }
        catch {
            $logEnabled = $false
            $logType    = 'Missing'
            $logCount   = 0
        }

        [pscustomobject]@{
            SMB1Enabled      = $cfg.EnableSMB1Protocol
            SMB1Auditing     = $cfg.AuditSmb1Access
            SMB1Feature      = $feature
            AuditLogEnabled  = $logEnabled
            AuditLogType     = $logType
            AuditRecordCount = $logCount
        }
    }

    $rows = foreach ($dc in @($script:Targets)) {
        try {
            $cfg = $null
            try {
                $cfg = Invoke-OnTarget -Computer $dc -ScriptBlock $statusScript
            }
            catch {
                if (Test-IsLocalComputer $dc) { throw }
                $cim = Get-SmbServerConfiguration -CimSession $dc -ErrorAction Stop
                $cfg = [pscustomobject]@{
                    SMB1Enabled      = $cim.EnableSMB1Protocol
                    SMB1Auditing     = $cim.AuditSmb1Access
                    SMB1Feature      = 'N/A'
                    AuditLogEnabled  = 'N/A'
                    AuditLogType     = 'N/A'
                    AuditRecordCount = 'N/A'
                }
            }
            [pscustomobject]@{
                Server           = $dc
                SMB1Enabled      = $cfg.SMB1Enabled
                SMB1Auditing     = $cfg.SMB1Auditing
                SMB1Feature      = $cfg.SMB1Feature
                AuditLogEnabled  = $cfg.AuditLogEnabled
                AuditLogType     = $cfg.AuditLogType
                AuditRecordCount = $cfg.AuditRecordCount
                Status           = 'OK'
            }
        }
        catch {
            [pscustomobject]@{
                Server           = $dc
                SMB1Enabled      = 'N/A'
                SMB1Auditing     = 'N/A'
                SMB1Feature      = 'N/A'
                AuditLogEnabled  = 'N/A'
                AuditLogType     = 'N/A'
                AuditRecordCount = 'N/A'
                Status           = "Error: $($_.Exception.Message)"
            }
        }
    }
    Show-Table $rows
    Write-Host ""
    Write-Host "SMB1Enabled = the SMBv1 server protocol (keep this False / disabled)." -ForegroundColor Gray
    Write-Host "SMB1Auditing = AuditSmb1Access (this is what option 3 turns on)." -ForegroundColor Gray
    if (-not $NoPause) { Pause-Menu }
}

function Set-AuditState {
    param(
        [bool]$Enable,
        [switch]$Force
    )

    Write-Banner
    $verb = if ($Enable) { 'ENABLE' } else { 'DISABLE' }
    Write-Host "This will $verb SMB1 access AUDITING (not the SMBv1 protocol) on:" -ForegroundColor White
    Write-Host ("  {0}" -f ($script:Targets -join ', ')) -ForegroundColor Gray
    if (-not $Force) {
        if (-not (Read-YesNo -Prompt "Continue?" -Default $true)) { return }
    }

    foreach ($dc in @($script:Targets)) {
        try {
            Invoke-OnTarget -Computer $dc -ArgumentList $Enable -ScriptBlock {
                param($state)
                Set-SmbServerConfiguration -AuditSmb1Access $state -Force -Confirm:$false -ErrorAction Stop
                if ($state) {
                    try {
                        $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration 'Microsoft-Windows-SMBServer/Audit'
                        if (-not $cfg.IsEnabled) {
                            $cfg.IsEnabled = $true
                            $cfg.SaveChanges()
                        }
                    }
                    catch {
                        # Channel enable is best-effort; AuditSmb1Access is the supported switch.
                    }
                }
            } | Out-Null
            Write-Ok "[+] Auditing set to $Enable on $dc"
        }
        catch {
            Write-ErrLine "[!] Failed on ${dc}: $($_.Exception.Message)"
            if ($_.Exception.Message -match 'WinRM|cannot be found|Access is denied') {
                Write-WarnLine "    Hint: run elevated, enable WinRM (Enable-PSRemoting), or set credentials (option 9)."
            }
        }
    }
    if ($Enable) {
        Write-Host ""
        Write-Info "Auditing is on. Give clients time to connect (hours/days), then run a scan."
        Write-Info "This does not turn SMBv1 on. It only logs clients that attempt to use it."
    }
    Pause-Menu
}

function Start-Smbv1Scan {
    param(
        [int]$DaysBack = 7,
        [bool]$DoDns = $true,
        [bool]$DoAd = $false,
        [int]$MaxEventsPerServer = 0,
        [switch]$Quiet
    )

    if (-not $Quiet) {
        Write-Banner
        $DaysBack = Read-Int32Value -Prompt "How many days back to search?" -Default $DaysBack -Minimum 1
        $DoDns = Read-YesNo -Prompt "Resolve client IPs to hostnames (reverse DNS, 2s timeout)?" -Default $DoDns
        $DoAd  = Read-YesNo -Prompt "Look up resolved names in Active Directory (OS / OU)?" -Default $DoAd
        $MaxEventsPerServer = Read-Int32Value -Prompt "Maximum events per server (0 = unlimited)?" -Default $MaxEventsPerServer -Minimum 0
    }

    $startTime = (Get-Date).AddDays(-$DaysBack)
    $results   = New-Object System.Collections.Generic.List[object]

    Write-Host ""
    foreach ($dc in @($script:Targets)) {
        Write-Info "[*] Querying $dc ..."
        try {
            $events = @(Get-Smbv1AuditEvents -Computer $dc -StartTime $startTime -MaxEventsPerServer $MaxEventsPerServer)
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -match 'disabled|does not exist|There is not an event log') {
                Write-WarnLine "    Audit log missing or disabled (enable auditing with option 3)."
                Write-WarnLine "    $($msg)"
            }
            elseif ($msg -match 'Access is denied|UnauthorizedAccess') {
                Write-ErrLine "    Access denied. Run elevated or add this account to Event Log Readers."
            }
            else {
                Write-ErrLine "    Failed: $msg"
            }
            continue
        }

        if ($events.Count -eq 0) {
            Write-WarnLine "    No SMBv1 events found in the last $DaysBack day(s) (is auditing enabled?)."
            continue
        }

        $i = 0
        foreach ($evt in $events) {
            $i++
            if ($i % 200 -eq 0 -and $events.Count -gt 0) {
                Write-Progress -Activity "Parsing events on $dc" -Status "$i of $($events.Count)" `
                    -PercentComplete (($i / $events.Count) * 100)
            }

            $clientAddress = Get-Smbv1ClientAddressFromEvent -Event $evt
            $timeCreated = $evt.TimeCreated
            [void]$results.Add([pscustomobject]@{
                DomainController = $dc
                TimeCreated      = $timeCreated
                ClientAddress    = $clientAddress
            })
        }
        Write-Progress -Activity "Parsing events on $dc" -Completed
        Write-Ok "    Found $($events.Count) event(s)"
    }

    if ($results.Count -eq 0) {
        $script:Summary      = New-Object System.Collections.Generic.List[object]
        $script:ClientRollup = New-Object System.Collections.Generic.List[object]
        Write-Host ""
        Write-Ok "No SMBv1 client connections found."
        if (-not $Quiet) { Pause-Menu }
        return
    }

    $script:Summary = ConvertTo-Smbv1Summary -Events @($results) -ResolveDns $DoDns -LookupAD $DoAd
    $script:ClientRollup = ConvertTo-Smbv1ClientRollup -SummaryRows @($script:Summary)

    Write-Host ""
    Write-Ok "[+] $($script:Summary.Count) unique SMBv1 client/server pair(s) found."
    Show-Table $script:Summary

    if ($script:ClientRollup.Count -gt 0 -and $script:Targets.Count -gt 1) {
        Write-Host ""
        Write-Host "Unique clients across all targets:" -ForegroundColor White
        Show-Table $script:ClientRollup
    }

    if ($Quiet) { return }

    if (Read-YesNo -Prompt "Export these results to CSV now?" -Default $true) {
        Export-Results
        return
    }
    Pause-Menu
}

function Show-Results {
    Write-Banner
    if ($script:Summary.Count -eq 0) {
        Write-WarnLine "No results in memory. Run a scan first (option 5)."
        Pause-Menu
        return
    }
    if ((Get-Command Out-GridView -ErrorAction SilentlyContinue) -and
        -not $script:NonInteractive -and
        (Read-YesNo -Prompt "Open in a sortable grid window (Out-GridView)?" -Default $true)) {
        $script:Summary | Out-GridView -Title "SMBv1 Clients" -Wait
        return
    }
    Show-Table $script:Summary
    if ($script:ClientRollup.Count -gt 0) {
        Write-Host ""
        Write-Host "Unique clients across all targets:" -ForegroundColor White
        Show-Table $script:ClientRollup
    }
    Pause-Menu
}

function Export-Results {
    if ($script:Summary.Count -eq 0) {
        Write-WarnLine "No results in memory. Run a scan first (option 5)."
        Pause-Menu
        return
    }
    $default = Join-Path (Get-Location) ("SMBv1_Clients_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $path = $default
    if (-not $script:NonInteractive) {
        $entered = (Read-Host "CSV path [default: $default]").Trim().Trim('"')
        if (-not [string]::IsNullOrEmpty($entered)) { $path = $entered }
    }
    Save-Smbv1Results -Path $path -Format Csv
    Pause-Menu
}

function Export-HtmlResults {
    if ($script:Summary.Count -eq 0) {
        Write-WarnLine "No results in memory. Run a scan first (option 5)."
        Pause-Menu
        return
    }
    $default = Join-Path (Get-Location) ("SMBv1_Clients_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $path = $default
    if (-not $script:NonInteractive) {
        $entered = (Read-Host "HTML path [default: $default]").Trim().Trim('"')
        if (-not [string]::IsNullOrEmpty($entered)) { $path = $entered }
    }
    Save-Smbv1Results -Path $path -Format Html
    Pause-Menu
}

function Show-LiveSmbv1Sessions {
    Write-Banner
    Write-Host "Live SMB sessions using dialect 1.x (Get-SmbSession)..." -ForegroundColor White
    $rows = foreach ($dc in @($script:Targets)) {
        try {
            $sessions = @(Invoke-OnTarget -Computer $dc -ScriptBlock {
                Get-SmbSession -ErrorAction Stop | Where-Object {
                    $d = [string]$_.Dialect
                    if ([string]::IsNullOrWhiteSpace($d)) { return $false }
                    $major = 99
                    $first = ($d -split '\.')[0]
                    [void][int]::TryParse($first, [ref]$major)
                    return ($major -lt 2)
                } | Select-Object ClientComputerName, ClientUserName, Dialect, NumOpens, SecondsExists, SessionId
            })
            if ($sessions.Count -eq 0) {
                [pscustomobject]@{
                    Server             = $dc
                    ClientComputerName = '(none)'
                    ClientUserName     = ''
                    Dialect            = ''
                    NumOpens           = ''
                    SecondsExists      = ''
                    Status             = 'No live SMBv1 sessions'
                }
            }
            else {
                foreach ($s in $sessions) {
                    [pscustomobject]@{
                        Server             = $dc
                        ClientComputerName = $s.ClientComputerName
                        ClientUserName     = $s.ClientUserName
                        Dialect            = $s.Dialect
                        NumOpens           = $s.NumOpens
                        SecondsExists      = $s.SecondsExists
                        Status             = 'SMBv1'
                    }
                }
            }
        }
        catch {
            [pscustomobject]@{
                Server             = $dc
                ClientComputerName = 'N/A'
                ClientUserName     = 'N/A'
                Dialect            = 'N/A'
                NumOpens           = 'N/A'
                SecondsExists      = 'N/A'
                Status             = "Error: $($_.Exception.Message)"
            }
        }
    }
    Show-Table $rows
    Pause-Menu
}

function Set-RemoteCredential {
    Write-Banner
    Write-Host "Remote credential for Get-WinEvent / Invoke-Command / CIM." -ForegroundColor White
    Write-Host "  1) Prompt for a credential"
    Write-Host "  2) Clear stored credential (use current logon)"
    Write-Host "  B) Back"
    $choice = (Read-Host "Choice").Trim().ToUpper()
    switch ($choice) {
        '1' {
            try {
                $script:Credential = Get-Credential -Message "Credential for remote SMBv1 audit targets"
                if ($script:Credential) {
                    Write-Ok ("[+] Using {0}" -f $script:Credential.UserName)
                }
            }
            catch {
                Write-ErrLine "[!] $($_.Exception.Message)"
            }
            Pause-Menu
        }
        '2' {
            $script:Credential = $null
            Write-Ok "[+] Credential cleared."
            Pause-Menu
        }
        default { }
    }
}

function Show-MainMenu {
    $isAdmin = Test-IsElevated
    while ($true) {
        Write-Banner
        if (-not $isAdmin) {
            Write-WarnLine "WARNING: Not running elevated. Enabling auditing and reading the Audit log may fail."
            Write-Host ""
        }
        Write-Host "  1) Select target servers"
        Write-Host "  2) Check SMB1 / auditing status"
        Write-Host "  3) Enable SMB1 access auditing"
        Write-Host "  4) Disable SMB1 access auditing"
        Write-Host "  5) Scan audit logs for SMBv1 clients"
        Write-Host "  6) View last results"
        Write-Host "  7) Export last results to CSV"
        Write-Host "  8) Export last results to HTML"
        Write-Host "  9) Set / clear remote credentials"
        Write-Host "  L) Show live SMBv1 sessions"
        Write-Host "  Q) Quit"
        Write-Host ""
        $choice = (Read-Host "Select an option").Trim().ToUpper()

        switch ($choice) {
            '1' { Select-Targets }
            '2' { Show-AuditStatus }
            '3' { Set-AuditState -Enable $true }
            '4' { Set-AuditState -Enable $false }
            '5' { Start-Smbv1Scan -DaysBack $Days -DoDns (-not $SkipDns) -DoAd $LookupAD -MaxEventsPerServer $MaxEvents }
            '6' { Show-Results }
            '7' { Write-Banner; Export-Results }
            '8' { Write-Banner; Export-HtmlResults }
            '9' { Set-RemoteCredential }
            'L' { Show-LiveSmbv1Sessions }
            'Q' { Write-Host "Goodbye." -ForegroundColor Cyan; return }
            default {
                Write-WarnLine "Invalid option."
                Start-Sleep -Seconds 1
            }
        }
    }
}

function Invoke-NonInteractive {
    $script:NonInteractive = $true
    if ($Status) { Show-AuditStatus -NoPause }
    if ($EnableAuditing) { Set-AuditState -Enable $true -Force }
    if ($DisableAuditing) { Set-AuditState -Enable $false -Force }
    if ($Scan) {
        Start-Smbv1Scan -DaysBack $Days -DoDns (-not $SkipDns) -DoAd $LookupAD -MaxEventsPerServer $MaxEvents -Quiet
        if ($ExportCsv)  { Save-Smbv1Results -Path $ExportCsv  -Format Csv }
        if ($ExportHtml) { Save-Smbv1Results -Path $ExportHtml -Format Html }
        if (-not $ExportCsv -and -not $ExportHtml -and $script:Summary.Count -gt 0) {
            Show-Table $script:Summary
        }
    }
}

# ---------------------------------------------------------------------------
# Self-test (no Windows SMB / event log required)
# ---------------------------------------------------------------------------
function Invoke-Smbv1SelfTest {
    function Assert-True {
        param([bool]$Condition, [string]$Name)
        if ($Condition) {
            $script:SelfTestPassed++
            Write-Host "  PASS  $Name" -ForegroundColor Green
        }
        else {
            $script:SelfTestFailed++
            Write-Host "  FAIL  $Name" -ForegroundColor Red
        }
    }

    $script:SelfTestPassed = 0
    $script:SelfTestFailed = 0
    $script:DnsCache = @{}

    Write-Host "Get-SMBv1Clients self-test" -ForegroundColor Cyan
    Write-Host ""

    Assert-True -Condition ((ConvertTo-NormalizedClientAddress -Address '10.1.2.3:445') -eq '10.1.2.3') `
        -Name 'Strips :port from IPv4 client addresses'
    Assert-True -Condition ((ConvertTo-NormalizedClientAddress -Address '[fe80::1]:1234') -eq 'fe80::1') `
        -Name 'Strips port from [IPv6]:port'
    Assert-True -Condition ((ConvertTo-NormalizedClientAddress -Address '::ffff:192.168.8.8') -eq '192.168.8.8') `
        -Name 'Maps IPv4-mapped IPv6 to dotted IPv4'
    Assert-True -Condition ((ConvertTo-NormalizedClientAddress -Address 'fe80::1%12') -eq 'fe80::1') `
        -Name 'Strips IPv6 zone id'
    Assert-True -Condition ((ConvertTo-NormalizedClientAddress -Address '\\PC01') -eq 'PC01') `
        -Name 'Trims UNC slashes from a client name'
    Assert-True -Condition ((ConvertTo-NormalizedClientAddress -Address '') -eq 'Unknown') `
        -Name 'Blank addresses become Unknown'
    Assert-True -Condition ((ConvertTo-NormalizedClientAddress -Address '2001:db8::1') -eq '2001:db8::1') `
        -Name 'Leaves a bare IPv6 address unchanged'

    Assert-True -Condition (Test-IsIpAddress -Value '10.0.0.1') -Name 'Test-IsIpAddress accepts IPv4'
    Assert-True -Condition (Test-IsIpAddress -Value 'fe80::1') -Name 'Test-IsIpAddress accepts IPv6'
    Assert-True -Condition (-not (Test-IsIpAddress -Value 'PC01.contoso.com')) -Name 'Test-IsIpAddress rejects a hostname'
    Assert-True -Condition (-not (Test-IsIpAddress -Value 'Unknown')) -Name 'Test-IsIpAddress rejects Unknown'

    $namespacedXml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>3000</EventID></System>
  <EventData>
    <Data Name="ClientName">10.9.8.7:4444</Data>
  </EventData>
</Event>
'@
    $fromXml = Get-Smbv1ClientAddressFromXml -XmlText $namespacedXml
    Assert-True -Condition ($fromXml -eq '10.9.8.7:4444') `
        -Name 'XML parser reads Name=ClientName under the default event xmlns'

    $xmlDoc = New-Object System.Xml.XmlDocument
    $xmlDoc.XmlResolver = $null
    $xmlDoc.LoadXml($namespacedXml)
    $dataNode = $xmlDoc.SelectSingleNode("//*[local-name()='Data']")
    Assert-True -Condition ($null -ne $dataNode -and $dataNode.LocalName -eq 'Data' -and $dataNode.GetAttribute('Name') -eq 'ClientName') `
        -Name 'Event Data tag is Data; the client field is the Name attribute'
    # XmlElement.Name is the tag in Windows PowerShell 5.1 ("Data") and may be the
    # attribute in PowerShell 7 ("ClientName"). The original Where-Object { $_.Name
    # -eq 'ClientName' } therefore silently matches nothing on PS 5.1.
    $nameProp = [string]$dataNode.Name
    Assert-True -Condition ($nameProp -eq 'Data' -or $nameProp -eq 'ClientName') `
        -Name 'XmlElement.Name is version-dependent; parser does not rely on it'

    $propEvent = [pscustomobject]@{
        Properties   = @([pscustomobject]@{ Value = '172.16.4.5:5555' })
        Message      = 'SMB1 access'
        TimeCreated  = [datetime]'2026-01-02 08:00:00'
    }
    Assert-True -Condition ((Get-Smbv1ClientAddressFromEvent -Event $propEvent) -eq '172.16.4.5') `
        -Name 'Event parser prefers Properties[0] and normalizes the port'

    $xmlOnly = [pscustomobject]@{
        Properties  = @()
        Message     = 'truncated'
        TimeCreated = Get-Date
        Xml         = $namespacedXml
    }
    Assert-True -Condition ((Get-Smbv1ClientAddressFromEvent -Event $xmlOnly) -eq '10.9.8.7') `
        -Name 'Event parser falls back to event XML when Properties is empty'

    $msgOnly = [pscustomobject]@{
        Properties  = $null
        Message     = "SMB1 access`r`nClient Address: 8.8.4.4"
        TimeCreated = Get-Date
    }
    Assert-True -Condition ((Get-Smbv1ClientAddressFromEvent -Event $msgOnly) -eq '8.8.4.4') `
        -Name 'Event parser falls back to English "Client Address:" message text'

    $noEvents = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.Exception 'No events were found that match the specified selection criteria.'),
        'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand',
        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
        $null
    )
    $missingLog = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.Exception 'There is not an event log on the localhost computer that matches "Microsoft-Windows-SMBServer/Audit".'),
        'NoMatchingLogsFound,Microsoft.PowerShell.Commands.GetWinEventCommand',
        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
        $null
    )
    Assert-True -Condition (Test-IsNoEventsError -ErrorRecord $noEvents) `
        -Name 'Test-IsNoEventsError recognises NoMatchingEventsFound'
    Assert-True -Condition (-not (Test-IsNoEventsError -ErrorRecord $missingLog)) `
        -Name 'Test-IsNoEventsError does not treat a missing log as "no events"'

    $filter = New-Smbv1EventFilter -StartTime ([datetime]'2026-01-01')
    Assert-True -Condition ($filter.LogName -eq 'Microsoft-Windows-SMBServer/Audit' -and $filter.Id -eq 3000) `
        -Name 'Event filter targets Microsoft-Windows-SMBServer/Audit id 3000'

    Assert-True -Condition (Test-IsLocalComputer -Computer 'localhost') -Name 'localhost is treated as local'
    Assert-True -Condition (Test-IsLocalComputer -Computer '.') -Name 'dot is treated as local'
    Assert-True -Condition (Test-IsLocalComputer -Computer '127.0.0.1') -Name 'loopback IPv4 is treated as local'
    $thisHost = [System.Net.Dns]::GetHostName()
    Assert-True -Condition (Test-IsLocalComputer -Computer $thisHost) -Name 'GetHostName() is treated as local'
    Assert-True -Condition (-not (Test-IsLocalComputer -Computer 'DC99.contoso.com')) -Name 'A different FQDN is not local'

    $sampleEvents = @(
        [pscustomobject]@{ DomainController = 'DC1'; TimeCreated = [datetime]'2026-03-01 10:00:00'; ClientAddress = '10.0.0.1' }
        [pscustomobject]@{ DomainController = 'DC1'; TimeCreated = [datetime]'2026-03-02 11:00:00'; ClientAddress = '10.0.0.1' }
        [pscustomobject]@{ DomainController = 'DC1'; TimeCreated = [datetime]'2026-03-03 12:00:00'; ClientAddress = '10.0.0.2' }
        [pscustomobject]@{ DomainController = 'DC2'; TimeCreated = [datetime]'2026-03-04 13:00:00'; ClientAddress = '10.0.0.1' }
    )
    $summary = @(ConvertTo-Smbv1Summary -Events $sampleEvents -ResolveDns $false)
    $dc1c1 = @($summary | Where-Object { $_.DomainController -eq 'DC1' -and $_.ClientAddress -eq '10.0.0.1' })[0]
    Assert-True -Condition ($summary.Count -eq 3) -Name 'Summary groups by DomainController + ClientAddress'
    Assert-True -Condition ($dc1c1.ConnectionCount -eq 2) -Name 'Summary counts repeat connections'
    Assert-True -Condition ($dc1c1.FirstSeen -eq [datetime]'2026-03-01 10:00:00' -and $dc1c1.LastSeen -eq [datetime]'2026-03-02 11:00:00') `
        -Name 'Summary FirstSeen / LastSeen follow TimeCreated'

    $withDns = @(ConvertTo-Smbv1Summary -Events $sampleEvents -ResolveDns $true -NameResolver { param($addr) "host-$addr" })
    $resolved = @($withDns | Where-Object { $_.ClientAddress -eq '10.0.0.2' })[0]
    Assert-True -Condition ($resolved.HostName -eq 'host-10.0.0.2') -Name 'Summary uses the injected DNS resolver'

    $rollup = @(ConvertTo-Smbv1ClientRollup -SummaryRows $summary)
    $r1 = @($rollup | Where-Object { $_.ClientAddress -eq '10.0.0.1' })[0]
    Assert-True -Condition ($rollup.Count -eq 2) -Name 'Rollup collapses the same client across DCs'
    Assert-True -Condition ($r1.ConnectionCount -eq 3 -and $r1.DomainControllers -match 'DC1' -and $r1.DomainControllers -match 'DC2') `
        -Name 'Rollup sums counts and lists every DC'

    $single = @(ConvertTo-Smbv1Summary -Events @($sampleEvents[2]) -ResolveDns $false)
    Assert-True -Condition ($single.Count -eq 1 -and $single[0].ClientAddress -eq '10.0.0.2') `
        -Name 'Summary keeps a single-row result as a one-element collection'

    $html = ConvertTo-Smbv1Html -SummaryRows $summary -RollupRows $rollup -Targets @('DC1','DC2') -Days 7
    Assert-True -Condition ($html -match '10.0.0.1' -and $html -match '<table>' -and $html -notmatch '<script') `
        -Name 'HTML report includes client rows and no script tags'
    Assert-True -Condition ((ConvertTo-Smbv1Html -SummaryRows @([pscustomobject]@{ ClientAddress = '<xss>'; DomainController='DC1'; HostName='n'; OperatingSystem=''; ConnectionCount=1; FirstSeen='t'; LastSeen='t' }) -RollupRows @() -Targets @('DC1') -Days 1) -match '&lt;xss&gt;') `
        -Name 'HTML report encodes angle brackets in client fields'

    $emptySummary = ConvertTo-Smbv1Summary -Events @() -ResolveDns $false
    Assert-True -Condition ($emptySummary.Count -eq 0) -Name 'Empty event list yields an empty summary'

    Assert-True -Condition ((Get-CsvUtf8Encoding) -match 'UTF8|utf8BOM') -Name 'CSV encoding is UTF-8 (with BOM on PS 7+)'

    Write-Host ""
    Write-Host ("  {0} passed, {1} failed" -f $script:SelfTestPassed, $script:SelfTestFailed) -ForegroundColor $(if ($script:SelfTestFailed) { 'Red' } else { 'Green' })
    return ($script:SelfTestFailed -eq 0)
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
$script:IsDotSourced = ($MyInvocation.InvocationName -eq '.')

if ($SelfTest) {
    $ok = Invoke-Smbv1SelfTest
    if ($ok) { exit 0 } else { exit 1 }
}

if ($SkipMain -or $script:IsDotSourced) { return }

if ($Scan -or $EnableAuditing -or $DisableAuditing -or $Status) {
    Invoke-NonInteractive
    return
}

Show-MainMenu

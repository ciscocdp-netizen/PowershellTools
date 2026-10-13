<#
.SYNOPSIS
    Interactive, menu-driven tool to find clients connecting to servers (typically
    Domain Controllers) via SMBv1. Compatible with Windows PowerShell 5.1.

.DESCRIPTION
    Finds SMBv1 clients connecting to the targets (typically Domain Controllers).
    Prefers Event ID 3000 from Microsoft-Windows-SMBServer/Audit after SMB1 access
    auditing is enabled (menu option 3, or -EnableAuditing). This does not enable
    the SMBv1 protocol itself.

    On Windows Server 2016 / Windows 10 and later, auditing uses
    Set-SmbServerConfiguration -AuditSmb1Access. On Server 2012 R2 / Windows 8.1
    and older that parameter does not exist (the cmdlet throws "A parameter cannot
    be found that matches parameter name 'AuditSmb1Access'"), so the script sets
    the DWORD
    HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\AuditSmb1Access
    to 1 (or 0 to disable). After a short delay the script restarts the Server
    service (LanmanServer) on those hosts so Event ID 3000 can be logged.

    A scan tries to enable the SMBServer Audit channel with wevtutil /q:true when
    that channel is present but disabled (Analytic on 2012 R2). On Server 2012 the
    channel is often not registered at all ("specified channel could not be
    found"); the scan does not treat wevtutil stderr as a hard failure. It then
    uses Microsoft-Windows-SMBServer/Operational (SMB1-related messages) and live
    Get-SmbSession dialect 1.x rows.

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
    Skip the menu and enable SMB1 access auditing on the targets. Server 2012 R2
    and older get the LanmanServer AuditSmb1Access registry DWORD, then a short
    wait and a LanmanServer restart. This does not enable the SMBv1 protocol.

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
    Version: 2.5
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
      - Wrapping a List[object] of PSCustomObject with @() (or binding it to [object[]])
        throws "Argument types do not match" in Windows PowerShell 5.1, so a successful
        event query produced 0 summary rows. Collections are ArrayList and copied by index.
      - Server 2012 R2 / Windows 8.1 and older have no -AuditSmb1Access parameter
        (it was added in Server 2016 / Windows 10). Enable/disable set the
        LanmanServer AuditSmb1Access registry DWORD, skip the missing cmdlet
        parameter, wait a few seconds, then restart LanmanServer automatically.
      - On Server 2012 the Microsoft-Windows-SMBServer/Audit channel is often not
        registered. wevtutil / EventLogConfiguration then fail with "specified
        channel could not be found". The scan classifies that as unregistered
        (without dumping NativeCommandError), inventories existing SMBServer logs,
        and falls back to Operational SMB1 messages plus live Get-SmbSession rows.
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

$script:Version      = '2.5'
$script:AuditLogName = 'Microsoft-Windows-SMBServer/Audit'
$script:AuditEventId = 3000
$script:SmbServerLogNames = @(
    'Microsoft-Windows-SMBServer/Audit',
    'Microsoft-Windows-SMBServer/Operational',
    'Microsoft-Windows-SMBServer/Analytic',
    'Microsoft-Windows-SMBServer/Diagnostic',
    'Microsoft-Windows-SMBServer/Security'
)
$script:LanmanParamsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$script:AuditSmb1ValueName = 'AuditSmb1Access'
$script:LanmanRestartDelaySeconds = 5
$script:Targets      = @()
$script:Summary      = New-Object System.Collections.ArrayList
$script:ClientRollup = New-Object System.Collections.ArrayList
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
    $rows = ConvertTo-ArrayList $InputObject
    if ($rows.Count -eq 0) { return }
    $rows | Format-Table -AutoSize -Wrap | Out-Host
}

# Windows PowerShell 5.1 throws "Argument types do not match" when @() or an
# [object[]] parameter conversion is applied to List[object] containing
# PSCustomObject rows. Copy by index into ArrayList instead (ArrayList is not
# unrolled on function return, so 0- and 1-row results keep a real .Count).
function ConvertTo-ArrayList {
    param($Value)

    $acc = New-Object System.Collections.ArrayList
    if ($null -eq $Value) { return $acc }

    if ($Value -is [string]) {
        [void]$acc.Add($Value)
        return $acc
    }

    if ($Value -is [System.Collections.IList]) {
        $count = [int]$Value.Count
        for ($i = 0; $i -lt $count; $i++) {
            [void]$acc.Add($Value[$i])
        }
        return $acc
    }

    if ($Value -is [System.Collections.IEnumerable] -and
        -not ($Value -is [System.Management.Automation.PSObject])) {
        foreach ($item in $Value) {
            [void]$acc.Add($item)
        }
        return $acc
    }

    [void]$acc.Add($Value)
    return $acc
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

function Test-IsMissingEventLogError {
    param($ErrorRecord)

    if ($null -eq $ErrorRecord) { return $false }
    $msg = ''
    if ($ErrorRecord.PSObject.Properties['Exception'] -and $ErrorRecord.Exception) {
        $msg = [string]$ErrorRecord.Exception.Message
    }
    if ([string]::IsNullOrWhiteSpace($msg)) { $msg = [string]$ErrorRecord }

    # Do not treat "A parameter cannot be found" as a missing event log.
    if ($msg -match 'parameter cannot be found') { return $false }
    return ($msg -match 'There is not an event log|specified channel could not be found|does not exist that matches')
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

function Test-IsChannelNotRegisteredText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return ($Text -match 'specified channel could not be found|Failed to read configuration for log')
}

function Test-IsSmbv1Dialect {
    param($Dialect)

    $d = [string]$Dialect
    if ([string]::IsNullOrWhiteSpace($d)) { return $false }

    $major = 99
    $first = ($d -split '\.')[0]
    if ([int]::TryParse($first, [ref]$major)) {
        return ($major -ge 1 -and $major -lt 2)
    }
    return ($d -match '(?i)^(SMB)?v?1(\.|$)')
}

function Test-IsSmbv1EventMessage {
    param($Event)

    if ($null -eq $Event) { return $false }

    $id = 0
    if ($Event.PSObject.Properties['Id'] -and $null -ne $Event.Id) {
        try { $id = [int]$Event.Id } catch { $id = 0 }
    }
    if ($id -eq 3000) { return $true }

    $msg = ''
    if ($Event.PSObject.Properties['Message'] -and $Event.Message) {
        $msg = [string]$Event.Message
    }
    if ([string]::IsNullOrWhiteSpace($msg)) { return $false }
    return ($msg -match '(?i)\bSMB\s*v?1(\.0)?\b|\bSMB1\b|\bSMB 1\.0\b')
}

function New-Smbv1EventFilter {
    param(
        [datetime]$StartTime,
        [string]$LogName = 'Microsoft-Windows-SMBServer/Audit',
        [int]$EventId = 3000
    )
    if ([string]::IsNullOrWhiteSpace($LogName)) { $LogName = 'Microsoft-Windows-SMBServer/Audit' }
    $filter = @{
        LogName   = $LogName
        StartTime = $StartTime
    }
    if ($EventId -gt 0) { $filter.Id = $EventId }
    return $filter
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
# The Audit channel is often Analytic/disabled on 2012 R2. Get-WinEvent then
# reports "There is not an event log ... that matches". Enabling requires
# wevtutil /q:true (quiet) for analytic/debug logs. On Server 2012 the channel
# is frequently not registered at all; wevtutil then writes "specified channel
# could not be found" to stderr, which PowerShell surfaces as NativeCommandError.
function Enable-SmbServerAuditChannel {
    param([string]$Computer)

    $sb = {
        $logName = 'Microsoft-Windows-SMBServer/Audit'
        $enabled = $false
        $justEnabled = $false
        $registered = $false
        $noteParts = New-Object System.Collections.ArrayList
        $found = New-Object System.Collections.ArrayList

        function Get-WevtutilResult {
            param([string]$ArgLine)
            $prev = $ErrorActionPreference
            $ErrorActionPreference = 'SilentlyContinue'
            $raw = $null
            try {
                $raw = cmd.exe /c "wevtutil.exe $ArgLine 2>&1"
            }
            catch {
                $raw = $_.Exception.Message
            }
            $code = 1
            if ($null -ne $LASTEXITCODE) { $code = [int]$LASTEXITCODE }
            $ErrorActionPreference = $prev
            $text = ''
            if ($null -ne $raw) {
                $text = ((@($raw) | ForEach-Object { [string]$_ } | Where-Object { $_ }) -join ' ')
            }
            New-Object psobject -Property @{ ExitCode = $code; Text = $text }
        }

        try {
            $logs = @(Get-WinEvent -ListLog 'Microsoft-Windows-SMBServer*' -Force -ErrorAction SilentlyContinue)
            foreach ($l in $logs) {
                if (-not $l.LogName) { continue }
                [void]$found.Add([string]$l.LogName)
                if ([string]$l.LogName -eq $logName) {
                    $registered = $true
                    if ($l.IsEnabled) {
                        $enabled = $true
                        [void]$noteParts.Add('Audit channel already enabled')
                    }
                }
            }
        }
        catch { }

        if ($found.Count -eq 0) {
            $el = Get-WevtutilResult -ArgLine 'el'
            if ($el.Text) {
                foreach ($line in @($el.Text -split '\s+')) {
                    $t = [string]$line
                    if ($t -like 'Microsoft-Windows-SMBServer/*') {
                        [void]$found.Add($t)
                        if ($t -eq $logName) { $registered = $true }
                    }
                }
            }
        }

        if (-not $registered) {
            if ($found.Count -eq 0) {
                # ListLog found nothing; try a quiet enable in case the channel exists.
                $probe = Get-WevtutilResult -ArgLine ("sl `"{0}`" /e:true /q:true" -f $logName)
                if ($probe.ExitCode -eq 0) {
                    $registered = $true
                    $enabled = $true
                    $justEnabled = $true
                    [void]$noteParts.Add('Enabled via wevtutil /q:true')
                }
                else {
                    [void]$noteParts.Add('Microsoft-Windows-SMBServer/Audit is not registered on this OS (typical of Server 2012).')
                }
            }
            else {
                [void]$noteParts.Add('Microsoft-Windows-SMBServer/Audit is not registered on this OS (typical of Server 2012).')
            }
        }
        elseif (-not $enabled) {
            $out = Get-WevtutilResult -ArgLine ("sl `"{0}`" /e:true /q:true" -f $logName)
            if ($out.ExitCode -eq 0) {
                $enabled = $true
                $justEnabled = $true
                [void]$noteParts.Add('Enabled via wevtutil /q:true')
            }
            else {
                try {
                    $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
                    if (-not $cfg.IsEnabled) {
                        $cfg.IsEnabled = $true
                        $cfg.SaveChanges()
                        $justEnabled = $true
                        [void]$noteParts.Add('Enabled via EventLogConfiguration')
                    }
                    else {
                        [void]$noteParts.Add('Audit channel already enabled')
                    }
                    $enabled = $true
                    $registered = $true
                }
                catch {
                    $em = [string]$_.Exception.Message
                    if ($em -match 'specified channel could not be found|Failed to read configuration') {
                        $registered = $false
                        $enabled = $false
                        [void]$noteParts.Add('Microsoft-Windows-SMBServer/Audit is not registered on this OS (typical of Server 2012).')
                    }
                    else {
                        [void]$noteParts.Add(('Could not enable Audit channel: {0}' -f $em))
                    }
                }
            }
        }

        New-Object psobject -Property @{
            Enabled           = $enabled
            JustEnabled       = $justEnabled
            ChannelRegistered = $registered
            Notes             = ($noteParts -join '; ')
            ExistingLogs      = ($found -join ', ')
        }
    }

    return (Invoke-OnTarget -Computer $Computer -ScriptBlock $sb)
}

function Get-Smbv1EventsFromLog {
    param(
        [string]$Computer,
        [string]$LogName,
        [datetime]$StartTime,
        [int]$MaxEventsPerServer = 0,
        [int]$EventId = 3000
    )

    $filter = New-Smbv1EventFilter -StartTime $StartTime -LogName $LogName -EventId $EventId
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
        $list = @{ ListLog = $LogName; ErrorAction = 'Stop'; Force = $true }
        if (-not $isLocal) {
            $list.ComputerName = $Computer
            if ($script:Credential) { $list.Credential = $script:Credential }
        }
        $logInfo = Get-WinEvent @list
        if ($logInfo -and -not $logInfo.IsEnabled) {
            return @{ Status = 'Disabled'; Events = @() }
        }
        if ($logInfo -and [string]$logInfo.LogType -match 'Analytic|Debug') {
            $useOldest = $true
        }
    }
    catch {
        if (Test-IsMissingEventLogError $_) {
            return @{ Status = 'Missing'; Events = @() }
        }
    }

    $invokeQuery = {
        param([hashtable]$Params, [bool]$Oldest)
        $p = @{}
        foreach ($key in $Params.Keys) { $p[$key] = $Params[$key] }
        if ($Oldest) { $p['Oldest'] = $true }
        Get-WinEvent @p
    }

    try {
        return @{ Status = 'OK'; Events = @(& $invokeQuery $gwe $useOldest) }
    }
    catch {
        if (Test-IsNoEventsError $_) {
            return @{ Status = 'OK'; Events = @() }
        }
        if (Test-IsMissingEventLogError $_) {
            return @{ Status = 'Missing'; Events = @() }
        }
        if (-not $useOldest -and $_.Exception.Message -match 'Oldest') {
            try {
                return @{ Status = 'OK'; Events = @(& $invokeQuery $gwe $true) }
            }
            catch {
                if (Test-IsNoEventsError $_) { return @{ Status = 'OK'; Events = @() } }
                if (Test-IsMissingEventLogError $_) { return @{ Status = 'Missing'; Events = @() } }
                throw
            }
        }
        throw
    }
}

function Get-Smbv1OperationalSmb1Events {
    param(
        [string]$Computer,
        [datetime]$StartTime,
        [int]$MaxEventsPerServer = 0
    )

    $matched = New-Object System.Collections.ArrayList
    $logName = 'Microsoft-Windows-SMBServer/Operational'

    $incoming = $null
    try {
        $batch = Get-Smbv1EventsFromLog -Computer $Computer -LogName $logName -StartTime $StartTime -MaxEventsPerServer $MaxEventsPerServer -EventId 0
        if ($batch.Status -eq 'OK') {
            $incoming = $batch.Events
        }
    }
    catch {
        if (Test-IsMissingEventLogError $_ -or Test-IsNoEventsError $_) {
            return $matched
        }
        if (-not (Test-IsLocalComputer $Computer)) {
            try {
                $incoming = Invoke-OnTarget -Computer $Computer -ArgumentList $StartTime, $MaxEventsPerServer, $logName -ScriptBlock {
                    param($start, $max, $logName)
                    $filter = @{ LogName = $logName; StartTime = $start }
                    $p = @{ FilterHashtable = $filter; ErrorAction = 'Stop' }
                    if ($max -gt 0) { $p.MaxEvents = $max }
                    try {
                        return @(Get-WinEvent @p)
                    }
                    catch {
                        $msg = [string]$_.Exception.Message
                        if ($msg -match 'No events were found|No matching events found') { return @() }
                        throw
                    }
                }
            }
            catch { }
        }
    }

    foreach ($e in @(ConvertTo-ArrayList $incoming)) {
        if (Test-IsSmbv1EventMessage -Event $e) { [void]$matched.Add($e) }
    }

    return $matched
}

function Get-Smbv1LiveSessionRows {
    param([string]$Computer)

    $rows = New-Object System.Collections.ArrayList
    try {
        $sessions = @(Invoke-OnTarget -Computer $Computer -ScriptBlock {
            Get-SmbSession -ErrorAction Stop |
                Select-Object ClientComputerName, ClientUserName, Dialect, NumOpens, SecondsExists, SessionId
        })
    }
    catch {
        return $rows
    }

    $now = Get-Date
    foreach ($s in @($sessions)) {
        if ($null -eq $s) { continue }
        $dialect = ''
        if ($s.PSObject.Properties['Dialect']) { $dialect = [string]$s.Dialect }
        if (-not (Test-IsSmbv1Dialect -Dialect $dialect)) { continue }

        $client = ''
        if ($s.PSObject.Properties['ClientComputerName']) { $client = [string]$s.ClientComputerName }
        $secs = 0
        if ($s.PSObject.Properties['SecondsExists'] -and $null -ne $s.SecondsExists) {
            [void][int]::TryParse([string]$s.SecondsExists, [ref]$secs)
        }
        $when = $now
        if ($secs -gt 0) { $when = $now.AddSeconds(-$secs) }

        [void]$rows.Add([pscustomobject]@{
            DomainController = $Computer
            TimeCreated      = $when
            ClientAddress    = (ConvertTo-NormalizedClientAddress -Address $client)
            Source           = 'LiveSession'
            Dialect          = $dialect
        })
    }
    return $rows
}

function Get-Smbv1AuditEvents {
    param(
        [string]$Computer,
        [datetime]$StartTime,
        [int]$MaxEventsPerServer = 0
    )

    $channel = $null
    try {
        $channel = Enable-SmbServerAuditChannel -Computer $Computer
        $registered = $true
        if ($channel -and $channel.PSObject.Properties['ChannelRegistered']) {
            $registered = [bool]$channel.ChannelRegistered
        }
        if ($channel -and $registered -eq $false) {
            Write-WarnLine "    Microsoft-Windows-SMBServer/Audit is not registered on this OS (typical of Server 2012). Using Operational log + live SMBv1 sessions."
            if ($channel.ExistingLogs) {
                Write-Info ("    SMBServer logs present: {0}" -f $channel.ExistingLogs)
            }
        }
        elseif ($channel -and $channel.JustEnabled) {
            Write-WarnLine "    Enabled the SMBServer Audit channel on $Computer (it was disabled or treated as missing)."
            Start-Sleep -Seconds 2
        }
        elseif ($channel -and -not $channel.Enabled -and $channel.Notes) {
            Write-WarnLine ("    Could not enable Audit channel: {0}" -f $channel.Notes)
        }
    }
    catch {
        Write-WarnLine ("    Could not enable the Audit channel: {0}" -f $_.Exception.Message)
    }

    $all = New-Object System.Collections.ArrayList
    $queried = New-Object System.Collections.ArrayList
    $missing = New-Object System.Collections.ArrayList
    $lastError = $null

    foreach ($logName in $script:SmbServerLogNames) {
        try {
            $batch = Get-Smbv1EventsFromLog -Computer $Computer -LogName $logName -StartTime $StartTime -MaxEventsPerServer $MaxEventsPerServer
        }
        catch {
            $lastError = $_
            if (Test-IsMissingEventLogError $_) {
                [void]$missing.Add($logName)
                continue
            }
            if (-not (Test-IsLocalComputer $Computer)) {
                Write-WarnLine "    RPC/Get-WinEvent failed for $logName on $Computer; retrying via PowerShell remoting..."
                try {
                    $remote = Invoke-OnTarget -Computer $Computer -ArgumentList $StartTime, $MaxEventsPerServer, $logName, $script:AuditEventId -ScriptBlock {
                        param($start, $max, $logName, $eventId)
                        $filter = @{ LogName = $logName; Id = $eventId; StartTime = $start }
                        $p = @{ FilterHashtable = $filter; ErrorAction = 'Stop' }
                        if ($max -gt 0) { $p.MaxEvents = $max }
                        try {
                            return @(Get-WinEvent @p)
                        }
                        catch {
                            $msg = [string]$_.Exception.Message
                            if ($msg -match 'Oldest') {
                                $p['Oldest'] = $true
                                try { return @(Get-WinEvent @p) } catch { return @() }
                            }
                            if ($msg -match 'No events were found|No matching events found') { return @() }
                            throw
                        }
                    }
                    foreach ($e in @($remote)) { [void]$all.Add($e) }
                    [void]$queried.Add($logName)
                    continue
                }
                catch {
                    $lastError = $_
                }
            }
            continue
        }

        if ($batch.Status -eq 'Missing' -or $batch.Status -eq 'Disabled') {
            [void]$missing.Add($logName)
            continue
        }
        [void]$queried.Add($logName)
        foreach ($e in @($batch.Events)) {
            [void]$all.Add($e)
        }
        if ($logName -eq $script:AuditLogName -and $all.Count -gt 0) {
            break
        }
    }

    if ($all.Count -gt 0) { return $all }

    $operational = Get-Smbv1OperationalSmb1Events -Computer $Computer -StartTime $StartTime -MaxEventsPerServer $MaxEventsPerServer
    if ($operational.Count -gt 0) {
        Write-Info ("    No Event ID 3000; using {0} Operational SMB1-related event(s)." -f $operational.Count)
        return $operational
    }

    if ($queried.Count -eq 0) {
        $existing = ''
        if ($channel -and $channel.ExistingLogs) { $existing = [string]$channel.ExistingLogs }
        $detail = "There is not a queryable Microsoft-Windows-SMBServer/Audit log on $Computer."
        if ($existing) {
            $detail = $detail + " SMBServer logs present: $existing."
        }
        else {
            $detail = $detail + " The Audit channel is often Analytic and reports as missing until it is enabled with wevtutil /q:true (this scan tries that automatically)."
        }
        $detail = $detail + " On Server 2012 the channel is often not registered at all. The scan will still check live SMBv1 sessions."
        if ($lastError) {
            $detail = $detail + ' ' + [string]$lastError.Exception.Message
        }
        throw $detail
    }

    if ($channel -and $channel.JustEnabled) {
        Write-WarnLine "    Audit log is now on, but it has no history. Leave auditing enabled, wait for clients to connect, then scan again."
    }
    return @()
}

function ConvertTo-Smbv1Summary {
    param(
        $Events,
        [bool]$ResolveDns = $false,
        [bool]$LookupAD = $false,
        [scriptblock]$NameResolver = $null
    )

    $out = New-Object System.Collections.ArrayList
    $eventRows = ConvertTo-ArrayList $Events
    if ($eventRows.Count -eq 0) { return $out }

    $groups = $eventRows | Group-Object DomainController, ClientAddress
    foreach ($g in $groups) {
        $groupRows = ConvertTo-ArrayList $g.Group
        $first = $groupRows[0]
        $times = $groupRows | Sort-Object TimeCreated
        $timeList = ConvertTo-ArrayList $times
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

        $sourceMap = @{}
        foreach ($row in $groupRows) {
            if ($row.PSObject.Properties['Source'] -and $row.Source) {
                $src = [string]$row.Source
                if ($src) { $sourceMap[$src] = $true }
            }
        }
        $sourceText = 'Event3000'
        if ($sourceMap.Count -gt 0) { $sourceText = (($sourceMap.Keys | Sort-Object) -join ', ') }

        [void]$out.Add([pscustomobject]@{
            DomainController  = $first.DomainController
            ClientAddress     = $address
            HostName          = $hostName
            OperatingSystem   = $os
            DistinguishedName = $ou
            ConnectionCount   = [int]$g.Count
            FirstSeen         = $timeList[0].TimeCreated
            LastSeen          = $timeList[$timeList.Count - 1].TimeCreated
            Source            = $sourceText
        })
    }

    $sorted = ConvertTo-ArrayList ($out | Sort-Object @{ Expression = 'ConnectionCount'; Descending = $true }, @{ Expression = 'ClientAddress'; Descending = $false })
    return $sorted
}

function ConvertTo-Smbv1ClientRollup {
    param($SummaryRows)

    $out = New-Object System.Collections.ArrayList
    $summaryList = ConvertTo-ArrayList $SummaryRows
    if ($summaryList.Count -eq 0) { return $out }

    $groups = $summaryList | Group-Object ClientAddress
    foreach ($g in $groups) {
        $rows = ConvertTo-ArrayList $g.Group
        $dcs = ConvertTo-ArrayList ($rows | Select-Object -ExpandProperty DomainController -Unique)
        $named = ConvertTo-ArrayList ($rows | Where-Object { $_.HostName -and $_.HostName -ne 'N/A' })
        $hostName = 'N/A'
        if ($named.Count -gt 0) { $hostName = [string]$named[0].HostName }
        $firsts = ConvertTo-ArrayList ($rows | Sort-Object FirstSeen)
        $lasts  = ConvertTo-ArrayList ($rows | Sort-Object LastSeen)
        [void]$out.Add([pscustomobject]@{
            ClientAddress     = $g.Name
            HostName          = $hostName
            DomainControllers = ($dcs -join ', ')
            ConnectionCount   = [int](($rows | Measure-Object -Property ConnectionCount -Sum).Sum)
            FirstSeen         = $firsts[0].FirstSeen
            LastSeen          = $lasts[$lasts.Count - 1].LastSeen
        })
    }

    return (ConvertTo-ArrayList ($out | Sort-Object @{ Expression = 'ConnectionCount'; Descending = $true }, @{ Expression = 'ClientAddress'; Descending = $false }))
}

function ConvertTo-Smbv1Html {
    param(
        $SummaryRows,
        $RollupRows,
        $Targets,
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
    $targetList  = ConvertTo-ArrayList $Targets
    $summaryList = ConvertTo-ArrayList $SummaryRows
    $rollupList  = ConvertTo-ArrayList $RollupRows
    [void]$sb.AppendLine(('<p class="meta">Generated {0:yyyy-MM-dd HH:mm:ss} | Days: {1} | Targets: {2}</p>' -f (Get-Date), $Days, ($targetList -join ', ')))

    [void]$sb.AppendLine('<h2>Unique clients by server</h2><table><tr>')
    foreach ($h in @('DomainController','ClientAddress','HostName','OperatingSystem','ConnectionCount','FirstSeen','LastSeen','Source')) {
        [void]$sb.Append("<th>$h</th>")
    }
    [void]$sb.AppendLine('</tr>')
    foreach ($row in $summaryList) {
        [void]$sb.Append('<tr>')
        foreach ($h in @('DomainController','ClientAddress','HostName','OperatingSystem','ConnectionCount','FirstSeen','LastSeen','Source')) {
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
    foreach ($row in $rollupList) {
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
            $html = ConvertTo-Smbv1Html -SummaryRows $script:Summary -RollupRows $script:ClientRollup -Targets $script:Targets -Days $Days
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

# -AuditSmb1Access exists on Windows 10 / Server 2016 (10.0) and later.
# Server 2012 R2 / Windows 8.1 (6.3) still throw "parameter cannot be found".
function Test-OsNeedsSmb1AuditRegistry {
    param(
        [version]$OsVersion,
        [bool]$CmdletHasAuditParameter = $false
    )
    if ($null -eq $OsVersion) { return $true }
    if ($OsVersion.Major -lt 10) { return $true }
    if (-not $CmdletHasAuditParameter) { return $true }
    return $false
}

function Get-Smb1AuditRegistryPath {
    return 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
}

# Self-contained: sent to remote hosts, including Server 2012 (PS 3) and 2008 R2 (PS 2).
function Invoke-Smb1AuditLocal {
    param(
        [string]$Action = 'Get',
        [bool]$Enable = $true
    )

    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $regName = 'AuditSmb1Access'
    $logName = 'Microsoft-Windows-SMBServer/Audit'

    function Get-LocalOsInfo {
        $caption = 'Unknown'
        $verStr = '0.0'
        try {
            $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
            $caption = [string]$os.Caption
            $verStr = [string]$os.Version
        }
        catch {
            try {
                $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
                $caption = [string]$os.Caption
                $verStr = [string]$os.Version
            }
            catch {
                $verStr = [Environment]::OSVersion.Version.ToString()
            }
        }
        $ver = $null
        try { $ver = [version]$verStr } catch { $ver = [version]'0.0' }
        New-Object psobject -Property @{ Caption = $caption; Version = $ver; VersionString = $verStr }
    }

    function Test-NeedsRegistryInner {
        param([version]$OsVersion, [bool]$HasCmdletParam)
        if ($null -eq $OsVersion) { return $true }
        if ($OsVersion.Major -lt 10) { return $true }
        if (-not $HasCmdletParam) { return $true }
        return $false
    }

    function Test-HasAuditCmdletParam {
        $cmd = Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($null -eq $cmd) { return $false }
        if ($null -eq $cmd.Parameters) { return $false }
        return [bool]$cmd.Parameters.ContainsKey('AuditSmb1Access')
    }

    function Get-RegDword {
        param([string]$Path, [string]$Name)
        try {
            $p = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            return [int]$p.$Name
        }
        catch {
            return $null
        }
    }

    function Set-RegDword {
        param([string]$Path, [string]$Name, [int]$Value)
        if (-not (Test-Path -Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
    }

    function Enable-AuditLogChannel {
        $present = $false
        try {
            $null = Get-WinEvent -ListLog $logName -Force -ErrorAction Stop
            $present = $true
        }
        catch { }
        if (-not $present) { return $false }

        try {
            $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
            if (-not $cfg.IsEnabled) {
                $cfg.IsEnabled = $true
                $cfg.SaveChanges()
            }
            return $true
        }
        catch { }

        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        try {
            cmd.exe /c "wevtutil.exe sl `"$logName`" /e:true /q:true" | Out-Null
        }
        catch { }
        $code = 1
        if ($null -ne $LASTEXITCODE) { $code = [int]$LASTEXITCODE }
        $ErrorActionPreference = $prev
        return ($code -eq 0)
    }

    function Get-LogInfo {
        $enabled = $null
        $logType = 'Unknown'
        $count = $null
        try {
            $log = Get-WinEvent -ListLog $logName -Force -ErrorAction Stop
            $enabled = $log.IsEnabled
            $logType = [string]$log.LogType
            $count = $log.RecordCount
        }
        catch {
            $enabled = $false
            $logType = 'NotRegistered'
            $count = 0
        }
        New-Object psobject -Property @{ Enabled = $enabled; LogType = $logType; RecordCount = $count }
    }

    $os = Get-LocalOsInfo
    $hasParam = Test-HasAuditCmdletParam
    $needsReg = Test-NeedsRegistryInner -OsVersion $os.Version -HasCmdletParam $hasParam

    if ($Action -eq 'Set') {
        $cmdletApplied = $false
        $cmdletError = ''
        $regApplied = $false
        $regError = ''
        $dword = 0
        if ($Enable) { $dword = 1 }

        # Do not call -AuditSmb1Access on 2012 R2 and older: the parameter is
        # absent and Set-SmbServerConfiguration throws "parameter cannot be found".
        if ($hasParam -and -not $needsReg) {
            try {
                Set-SmbServerConfiguration -AuditSmb1Access ([bool]$Enable) -Force -Confirm:$false -ErrorAction Stop
                $cmdletApplied = $true
            }
            catch {
                $cmdletError = [string]$_.Exception.Message
            }
        }

        if ($needsReg -or -not $cmdletApplied) {
            try {
                Set-RegDword -Path $regPath -Name $regName -Value $dword
                $regApplied = $true
            }
            catch {
                $regError = [string]$_.Exception.Message
            }
        }

        $logOk = $true
        if ($Enable) { $logOk = Enable-AuditLogChannel }

        $method = 'None'
        if ($cmdletApplied -and $regApplied) { $method = 'Cmdlet+Registry' }
        elseif ($cmdletApplied) { $method = 'Cmdlet' }
        elseif ($regApplied) { $method = 'Registry' }

        $ok = [bool]($cmdletApplied -or $regApplied)
        $restart = [bool]($needsReg -and $regApplied -and $Enable)
        $msg = ''
        if (-not $ok) {
            $msg = ($cmdletError + ' ' + $regError).Trim()
        }
        elseif ($restart) {
            $msg = 'Registry AuditSmb1Access written. LanmanServer will be restarted after a short delay so Event ID 3000 can be logged.'
        }
        else {
            $msg = 'SMB1 access auditing updated via Set-SmbServerConfiguration.'
        }
        if ($Enable -and -not $logOk) {
            $msg = ($msg + ' Microsoft-Windows-SMBServer/Audit is not registered on this OS (typical of Server 2012); Event ID 3000 will not be written. Scan uses Operational log + live SMBv1 sessions.').Trim()
        }

        New-Object psobject -Property @{
            Action           = 'Set'
            Ok               = $ok
            OsCaption        = $os.Caption
            OsVersion        = $os.VersionString
            NeedsRegistry    = $needsReg
            Method           = $method
            CmdletApplied    = $cmdletApplied
            RegistryApplied  = $regApplied
            RegistryValue    = (Get-RegDword -Path $regPath -Name $regName)
            LogEnabled       = $logOk
            RestartRequired  = $restart
            Message          = $msg
            Error            = $(if ($ok) { '' } else { $msg })
        }
        return
    }

    $cmdletAudit = $null
    $smb1Enabled = $null
    try {
        $cfg = Get-SmbServerConfiguration -ErrorAction Stop
        if ($cfg.PSObject.Properties['AuditSmb1Access']) {
            $cmdletAudit = $cfg.AuditSmb1Access
        }
        if ($cfg.PSObject.Properties['EnableSMB1Protocol']) {
            $smb1Enabled = $cfg.EnableSMB1Protocol
        }
    }
    catch { }

    $regAudit = Get-RegDword -Path $regPath -Name $regName
    $regSmb1  = Get-RegDword -Path $regPath -Name 'SMB1'
    if ($null -eq $smb1Enabled) {
        if ($null -eq $regSmb1) { $smb1Enabled = 'Default (on)' }
        elseif ($regSmb1 -eq 0) { $smb1Enabled = $false }
        else { $smb1Enabled = $true }
    }

    $effective = $false
    if ($cmdletAudit -eq $true) { $effective = $true }
    if ($regAudit -eq 1) { $effective = $true }

    $method = 'Not configured'
    if ($needsReg) { $method = 'Registry (2012 R2/older)' }
    else { $method = 'Cmdlet (2016+)' }

    $log = Get-LogInfo
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
                if ($feat.Installed) { $feature = 'Installed' } else { $feature = 'Available' }
            }
        }
        catch { }
    }

    New-Object psobject -Property @{
        Action           = 'Get'
        Ok               = $true
        OsCaption        = $os.Caption
        OsVersion        = $os.VersionString
        NeedsRegistry    = $needsReg
        Method           = $method
        SMB1Enabled      = $smb1Enabled
        SMB1Feature      = $feature
        SMB1Auditing     = $effective
        CmdletAudit      = $cmdletAudit
        RegistryAudit    = $(if ($null -eq $regAudit) { 'Missing' } else { $regAudit })
        AuditLogEnabled  = $log.Enabled
        AuditLogType     = $log.LogType
        AuditRecordCount = $log.RecordCount
        RestartRequired  = $false
        Message          = ''
        Error            = ''
    }
}

function Set-Smb1AuditViaRemoteRegistry {
    param(
        [string]$Computer,
        [bool]$Enable
    )

    $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
    $view = [Microsoft.Win32.RegistryView]::Registry64
    $sub  = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $base = $null
    $key  = $null
    try {
        if (Test-IsLocalComputer $Computer) {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
        }
        else {
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $Computer, $view)
            }
            catch {
                $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $Computer)
            }
        }
        $key = $base.OpenSubKey($sub, $true)
        if ($null -eq $key) {
            throw "Cannot open $sub on $Computer. Is the Remote Registry service running?"
        }
        $dword = 0
        if ($Enable) { $dword = 1 }
        $key.SetValue($script:AuditSmb1ValueName, $dword, [Microsoft.Win32.RegistryValueKind]::DWord)
    }
    finally {
        if ($key) { $key.Close() }
        if ($base) { $base.Close() }
    }

    if ($Enable) {
        try {
            $null = & wevtutil.exe sl $script:AuditLogName /r:$Computer /e:true /q:true 2>&1
        }
        catch { }
    }
}

function Get-Smb1AuditViaRemoteRegistry {
    param([string]$Computer)

    $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
    $view = [Microsoft.Win32.RegistryView]::Registry64
    $sub  = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $base = $null
    $key  = $null
    try {
        if (Test-IsLocalComputer $Computer) {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
        }
        else {
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $Computer, $view)
            }
            catch {
                $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $Computer)
            }
        }
        $key = $base.OpenSubKey($sub, $false)
        if ($null -eq $key) { return $null }
        return $key.GetValue($script:AuditSmb1ValueName, $null)
    }
    finally {
        if ($key) { $key.Close() }
        if ($base) { $base.Close() }
    }
}

function Show-AuditStatus {
    param([switch]$NoPause)

    Write-Banner
    Write-Host "Checking SMB1 configuration..." -ForegroundColor White
    Write-Host "Server 2012 R2 / older: auditing is the LanmanServer AuditSmb1Access registry DWORD." -ForegroundColor Gray
    Write-Host ""

    $rows = foreach ($dc in @($script:Targets)) {
        try {
            $cfg = $null
            try {
                $cfg = Invoke-OnTarget -Computer $dc -ArgumentList 'Get' -ScriptBlock ${function:Invoke-Smb1AuditLocal}
            }
            catch {
                if (Test-IsLocalComputer $dc) { throw }
                $regVal = $null
                try { $regVal = Get-Smb1AuditViaRemoteRegistry -Computer $dc } catch { }
                $cimAudit = $null
                $cimSmb1 = $null
                try {
                    $cim = Get-SmbServerConfiguration -CimSession $dc -ErrorAction Stop
                    if ($cim.PSObject.Properties['AuditSmb1Access']) { $cimAudit = $cim.AuditSmb1Access }
                    if ($cim.PSObject.Properties['EnableSMB1Protocol']) { $cimSmb1 = $cim.EnableSMB1Protocol }
                }
                catch { }
                $effective = $false
                if ($cimAudit -eq $true -or $regVal -eq 1) { $effective = $true }
                $cfg = New-Object psobject -Property @{
                    OsCaption        = 'N/A (WinRM failed)'
                    OsVersion        = ''
                    Method           = 'Registry fallback'
                    SMB1Enabled      = $(if ($null -ne $cimSmb1) { $cimSmb1 } else { 'N/A' })
                    SMB1Feature      = 'N/A'
                    SMB1Auditing     = $effective
                    RegistryAudit    = $(if ($null -eq $regVal) { 'N/A' } else { $regVal })
                    AuditLogEnabled  = 'N/A'
                    AuditLogType     = 'N/A'
                    AuditRecordCount = 'N/A'
                    NeedsRegistry    = $true
                }
            }

            $osLabel = [string]$cfg.OsCaption
            if ($cfg.OsVersion) { $osLabel = ($osLabel + ' ' + $cfg.OsVersion).Trim() }

            $logType = 'N/A'
            if ($cfg.PSObject.Properties['AuditLogType'] -and $cfg.AuditLogType) {
                $logType = [string]$cfg.AuditLogType
            }

            [pscustomobject]@{
                Server           = $dc
                OS               = $osLabel
                SMB1Enabled      = $cfg.SMB1Enabled
                SMB1Auditing     = $cfg.SMB1Auditing
                AuditMethod      = $cfg.Method
                RegistryDWORD    = $cfg.RegistryAudit
                AuditLogEnabled  = $cfg.AuditLogEnabled
                AuditLogType     = $logType
                AuditRecordCount = $cfg.AuditRecordCount
                Status           = 'OK'
            }
        }
        catch {
            [pscustomobject]@{
                Server           = $dc
                OS               = 'N/A'
                SMB1Enabled      = 'N/A'
                SMB1Auditing     = 'N/A'
                AuditMethod      = 'N/A'
                RegistryDWORD    = 'N/A'
                AuditLogEnabled  = 'N/A'
                AuditLogType     = 'N/A'
                AuditRecordCount = 'N/A'
                Status           = "Error: $($_.Exception.Message)"
            }
        }
    }
    Show-Table $rows
    Write-Host ""
    Write-Host "SMB1Enabled  = SMBv1 server protocol (keep False / disabled). Not changed by this tool." -ForegroundColor Gray
    Write-Host "SMB1Auditing = effective AuditSmb1Access (cmdlet and/or registry DWORD)." -ForegroundColor Gray
    Write-Host "RegistryDWORD = HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\AuditSmb1Access" -ForegroundColor Gray
    Write-Host "AuditLogType = NotRegistered means Microsoft-Windows-SMBServer/Audit is absent (typical of Server 2012)." -ForegroundColor Gray
    if (-not $NoPause) { Pause-Menu }
}

function Restart-LanmanServerOnTargets {
    param($Computers)

    $names = ConvertTo-ArrayList $Computers
    if ($names.Count -eq 0) { return }

    $delay = [int]$script:LanmanRestartDelaySeconds
    if ($delay -lt 1) { $delay = 5 }

    Write-Host ""
    Write-WarnLine ("Waiting {0} second(s), then restarting LanmanServer on: {1}" -f $delay, ($names -join ', '))
    Write-WarnLine "SMB file sharing / SYSVOL will interrupt briefly on those hosts."
    Start-Sleep -Seconds $delay

    foreach ($name in $names) {
        Write-Info ("[*] Restarting LanmanServer on {0} ..." -f $name)
        $restarted = $false
        try {
            Invoke-OnTarget -Computer $name -ScriptBlock {
                Restart-Service -Name LanmanServer -Force -ErrorAction Stop
            } | Out-Null
            $restarted = $true
        }
        catch {
            try {
                Get-Service -Name LanmanServer -ComputerName $name -ErrorAction Stop |
                    Restart-Service -Force -ErrorAction Stop
                $restarted = $true
            }
            catch {
                Write-ErrLine "[!] Could not restart LanmanServer on ${name}: $($_.Exception.Message)"
                Write-WarnLine "    Reboot $name during a maintenance window, then scan."
            }
        }
        if ($restarted) {
            Write-Ok "[+] Restarted LanmanServer on $name"
        }
    }
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
    Write-Host ""
    Write-Host "Server 2016 / Windows 10 and later : Set-SmbServerConfiguration -AuditSmb1Access" -ForegroundColor Gray
    Write-Host "Server 2012 R2 / 8.1 and older     : registry DWORD, then restart LanmanServer after $($script:LanmanRestartDelaySeconds)s" -ForegroundColor Gray
    if (-not $Force) {
        if (-not (Read-YesNo -Prompt "Continue?" -Default $true)) { return }
    }

    $needRestart = New-Object System.Collections.ArrayList
    $anyOk = $false

    foreach ($dc in @($script:Targets)) {
        $result = $null
        try {
            $result = Invoke-OnTarget -Computer $dc -ArgumentList 'Set', $Enable -ScriptBlock ${function:Invoke-Smb1AuditLocal}
        }
        catch {
            $winrmError = $_.Exception.Message
            try {
                Set-Smb1AuditViaRemoteRegistry -Computer $dc -Enable $Enable
                $result = New-Object psobject -Property @{
                    Ok              = $true
                    OsCaption       = 'Unknown (remote registry)'
                    OsVersion       = ''
                    Method          = 'Registry'
                    RestartRequired = $Enable
                    Message         = 'WinRM failed; set AuditSmb1Access via Remote Registry. LanmanServer will be restarted after a short delay.'
                    Error           = ''
                }
                Write-WarnLine "    WinRM/CIM failed on $dc ($winrmError). Used Remote Registry instead."
            }
            catch {
                Write-ErrLine "[!] Failed on ${dc}: $winrmError"
                Write-ErrLine "    Remote Registry fallback: $($_.Exception.Message)"
                if ($winrmError -match 'WinRM|WSMan|Access is denied|RPC') {
                    Write-WarnLine "    Hint: run elevated, enable WinRM, start Remote Registry, or set credentials (option 9)."
                }
                continue
            }
        }

        if ($result -and $result.Ok) {
            $anyOk = $true
            $osBit = ([string]$result.OsCaption).Trim()
            if ($result.OsVersion) { $osBit = ($osBit + ' ' + $result.OsVersion).Trim() }
            Write-Ok ("[+] {0} on {1} via {2}{3}" -f $(if ($Enable) { 'Enabled' } else { 'Disabled' }), $dc, $result.Method, $(if ($osBit) { " ($osBit)" } else { '' }))
            if ($result.Message) {
                Write-Host ("    {0}" -f $result.Message) -ForegroundColor Gray
            }
            if ($result.RestartRequired) {
                [void]$needRestart.Add($dc)
            }
        }
        else {
            $err = ''
            if ($result) { $err = [string]$result.Error }
            if (-not $err) { $err = 'Unknown error' }
            Write-ErrLine "[!] Failed on ${dc}: $err"
        }
    }

    if ($Enable -and $anyOk) {
        Write-Host ""
        Write-Info "This does not turn SMBv1 on. It only logs clients that attempt to use it."
        if ($needRestart.Count -gt 0) {
            Restart-LanmanServerOnTargets -Computers $needRestart
        }
        else {
            Write-Info "Auditing is on. Give clients time to connect (hours/days), then run a scan."
        }
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
    $results   = New-Object System.Collections.ArrayList

    Write-Host ""
    foreach ($dc in @($script:Targets)) {
        Write-Info "[*] Querying $dc ..."
        $events = @()
        try {
            $events = @(Get-Smbv1AuditEvents -Computer $dc -StartTime $startTime -MaxEventsPerServer $MaxEventsPerServer)
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -match 'disabled|does not exist|There is not an event log|not a queryable|not registered') {
                Write-WarnLine "    Audit log missing, disabled, or not registered on this OS."
                Write-WarnLine "    $($msg)"
            }
            elseif ($msg -match 'Access is denied|UnauthorizedAccess') {
                Write-ErrLine "    Access denied. Run elevated or add this account to Event Log Readers."
            }
            else {
                Write-ErrLine "    Failed: $msg"
            }
        }

        $i = 0
        foreach ($evt in $events) {
            $i++
            if ($i % 200 -eq 0 -and $events.Count -gt 0) {
                Write-Progress -Activity "Parsing events on $dc" -Status "$i of $($events.Count)" `
                    -PercentComplete (($i / $events.Count) * 100)
            }

            $source = 'Event3000'
            if ($evt.PSObject.Properties['Source'] -and $evt.Source) {
                $source = [string]$evt.Source
            }
            elseif ($evt.PSObject.Properties['Id'] -and $null -ne $evt.Id) {
                $evtId = 0
                try { $evtId = [int]$evt.Id } catch { $evtId = 0 }
                if ($evtId -ne 3000) { $source = 'Operational' }
            }

            $clientAddress = $null
            if ($evt.PSObject.Properties['ClientAddress'] -and $evt.ClientAddress) {
                $clientAddress = ConvertTo-NormalizedClientAddress -Address ([string]$evt.ClientAddress)
            }
            else {
                $clientAddress = Get-Smbv1ClientAddressFromEvent -Event $evt
            }
            $timeCreated = Get-Date
            if ($evt.PSObject.Properties['TimeCreated'] -and $evt.TimeCreated) {
                $timeCreated = $evt.TimeCreated
            }
            [void]$results.Add([pscustomobject]@{
                DomainController = $dc
                TimeCreated      = $timeCreated
                ClientAddress    = $clientAddress
                Source           = $source
            })
        }
        Write-Progress -Activity "Parsing events on $dc" -Completed
        if ($events.Count -gt 0) {
            Write-Ok "    Found $($events.Count) event(s)"
        }
        else {
            Write-WarnLine "    No Event ID 3000 / Operational SMB1 records in the last $DaysBack day(s)."
        }

        $live = Get-Smbv1LiveSessionRows -Computer $dc
        if ($live.Count -gt 0) {
            foreach ($row in $live) { [void]$results.Add($row) }
            Write-Ok ("    Found {0} live SMBv1 session(s)" -f $live.Count)
        }
        elseif ($events.Count -eq 0) {
            Write-WarnLine "    No live SMBv1 sessions either."
        }
    }

    if ($results.Count -eq 0) {
        $script:Summary      = New-Object System.Collections.ArrayList
        $script:ClientRollup = New-Object System.Collections.ArrayList
        Write-Host ""
        Write-Ok "No SMBv1 client connections found."
        Write-WarnLine "On Server 2012 the Audit channel is often not registered; live sessions only catch clients connected right now."
        if (-not $Quiet) { Pause-Menu }
        return
    }

    $script:Summary = ConvertTo-Smbv1Summary -Events $results -ResolveDns $DoDns -LookupAD $DoAd
    $script:ClientRollup = ConvertTo-Smbv1ClientRollup -SummaryRows $script:Summary

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
                Get-SmbSession -ErrorAction Stop |
                    Select-Object ClientComputerName, ClientUserName, Dialect, NumOpens, SecondsExists, SessionId
            })
            $sessions = @($sessions | Where-Object { Test-IsSmbv1Dialect -Dialect $_.Dialect })
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
        Write-Host "  3) Enable SMB1 access auditing (registry on Server 2012 R2 / older)"
        Write-Host "  4) Disable SMB1 access auditing"
        Write-Host "  5) Scan for SMBv1 clients (events + live sessions)"
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
    $paramMissing = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.Exception "A parameter cannot be found that matches parameter name 'AuditSmb1Access'."),
        'NamedParameterNotFound',
        [System.Management.Automation.ErrorCategory]::InvalidArgument,
        $null
    )
    Assert-True -Condition (Test-IsNoEventsError -ErrorRecord $noEvents) `
        -Name 'Test-IsNoEventsError recognises NoMatchingEventsFound'
    Assert-True -Condition (-not (Test-IsNoEventsError -ErrorRecord $missingLog)) `
        -Name 'Test-IsNoEventsError does not treat a missing log as "no events"'
    Assert-True -Condition (Test-IsMissingEventLogError -ErrorRecord $missingLog) `
        -Name 'Test-IsMissingEventLogError recognises the 2012 R2 disabled-channel message'
    Assert-True -Condition (-not (Test-IsMissingEventLogError -ErrorRecord $paramMissing)) `
        -Name 'Test-IsMissingEventLogError does not treat a missing cmdlet parameter as a missing log'

    $channelMissing = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.Exception 'Failed to read configuration for log Microsoft-Windows-SMBServer/Audit. The specified channel could not be found. Check channel configuration.'),
        'NativeCommandError',
        [System.Management.Automation.ErrorCategory]::NotSpecified,
        $null
    )
    Assert-True -Condition (Test-IsMissingEventLogError -ErrorRecord $channelMissing) `
        -Name 'Test-IsMissingEventLogError recognises wevtutil unregistered-channel text'
    Assert-True -Condition (Test-IsChannelNotRegisteredText -Text 'The specified channel could not be found. Check channel configuration.') `
        -Name 'Test-IsChannelNotRegisteredText matches wevtutil channel-not-found'
    Assert-True -Condition (Test-IsChannelNotRegisteredText -Text 'Failed to read configuration for log Microsoft-Windows-SMBServer/Audit') `
        -Name 'Test-IsChannelNotRegisteredText matches wevtutil failed-to-read-configuration'
    Assert-True -Condition (-not (Test-IsChannelNotRegisteredText -Text 'Audit channel already enabled')) `
        -Name 'Test-IsChannelNotRegisteredText ignores a successful enable note'

    Assert-True -Condition (Test-IsSmbv1Dialect -Dialect '1.5') -Name 'Test-IsSmbv1Dialect accepts dialect 1.5'
    Assert-True -Condition (Test-IsSmbv1Dialect -Dialect '1.0') -Name 'Test-IsSmbv1Dialect accepts dialect 1.0'
    Assert-True -Condition (-not (Test-IsSmbv1Dialect -Dialect '2.0.2')) -Name 'Test-IsSmbv1Dialect rejects dialect 2.0.2'
    Assert-True -Condition (-not (Test-IsSmbv1Dialect -Dialect '3.1.1')) -Name 'Test-IsSmbv1Dialect rejects dialect 3.1.1'
    Assert-True -Condition (-not (Test-IsSmbv1Dialect -Dialect '')) -Name 'Test-IsSmbv1Dialect rejects a blank dialect'

    Assert-True -Condition (Test-IsSmbv1EventMessage -Event ([pscustomobject]@{ Id = 3000; Message = '' })) `
        -Name 'Test-IsSmbv1EventMessage treats Event ID 3000 as SMBv1'
    Assert-True -Condition (Test-IsSmbv1EventMessage -Event ([pscustomobject]@{ Id = 1006; Message = 'SMB1 access is requested from client 10.0.0.9' })) `
        -Name 'Test-IsSmbv1EventMessage matches Operational SMB1 message text'
    Assert-True -Condition (Test-IsSmbv1EventMessage -Event ([pscustomobject]@{ Id = 4; Message = 'SMBv1 client connected' })) `
        -Name 'Test-IsSmbv1EventMessage matches SMBv1 in an Operational message'
    Assert-True -Condition (-not (Test-IsSmbv1EventMessage -Event ([pscustomobject]@{ Id = 1001; Message = 'SMB2 negotiate completed' }))) `
        -Name 'Test-IsSmbv1EventMessage ignores SMB2 Operational messages'

    $filter = New-Smbv1EventFilter -StartTime ([datetime]'2026-01-01')
    Assert-True -Condition ($filter.LogName -eq 'Microsoft-Windows-SMBServer/Audit' -and $filter.Id -eq 3000) `
        -Name 'Event filter targets Microsoft-Windows-SMBServer/Audit id 3000'
    $opFilter = New-Smbv1EventFilter -StartTime ([datetime]'2026-01-01') -LogName 'Microsoft-Windows-SMBServer/Operational'
    Assert-True -Condition ($opFilter.LogName -eq 'Microsoft-Windows-SMBServer/Operational') `
        -Name 'Event filter can target Microsoft-Windows-SMBServer/Operational as a fallback'
    $anyFilter = New-Smbv1EventFilter -StartTime ([datetime]'2026-01-01') -LogName 'Microsoft-Windows-SMBServer/Operational' -EventId 0
    Assert-True -Condition (-not $anyFilter.ContainsKey('Id')) `
        -Name 'Event filter omits Id when EventId is 0 (Operational message scan)'

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

    $genericBag = New-Object System.Collections.Generic.List[object]
    foreach ($evt in $sampleEvents) { [void]$genericBag.Add($evt) }
    $copiedBag = ConvertTo-ArrayList $genericBag
    Assert-True -Condition ($copiedBag.Count -eq 4) `
        -Name 'ConvertTo-ArrayList copies List[object] of PSCustomObject by index (PS 5.1 @() workaround)'

    $fromGeneric = ConvertTo-Smbv1Summary -Events $genericBag -ResolveDns $false
    Assert-True -Condition ($fromGeneric.Count -eq 3) `
        -Name 'Summary accepts List[object] without @() or [object[]] conversion'
    Assert-True -Condition ($fromGeneric[0].ConnectionCount -ge 1 -and $fromGeneric[0].ClientAddress) `
        -Name 'Summary rows from List[object] are indexable PSCustomObjects'

    $rollupFromGeneric = ConvertTo-Smbv1ClientRollup -SummaryRows $fromGeneric
    Assert-True -Condition ($rollupFromGeneric.Count -eq 2) `
        -Name 'Rollup accepts ArrayList summary rows without @() conversion'

    $showThrew = $false
    try {
        $null = (ConvertTo-ArrayList $fromGeneric | Format-Table | Out-String)
    }
    catch { $showThrew = $true }
    Assert-True -Condition (-not $showThrew) -Name 'Formatting ArrayList of PSCustomObject does not throw'

    $oneRow = ConvertTo-ArrayList ([pscustomobject]@{ A = 1 })
    Assert-True -Condition ($oneRow.Count -eq 1) -Name 'ConvertTo-ArrayList wraps a single PSCustomObject (does not unroll)'
    $nullList = ConvertTo-ArrayList $null
    Assert-True -Condition ($nullList.Count -eq 0) -Name 'ConvertTo-ArrayList of null is empty (not one $null)'

    Assert-True -Condition ((Get-CsvUtf8Encoding) -match 'UTF8|utf8BOM') -Name 'CSV encoding is UTF-8 (with BOM on PS 7+)'

    Assert-True -Condition ($script:LanmanRestartDelaySeconds -ge 1) `
        -Name 'LanmanServer restart delay is a positive number of seconds'
    Assert-True -Condition ((Get-Smb1AuditRegistryPath) -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters') `
        -Name 'SMB1 audit registry path is LanmanServer\Parameters'
    Assert-True -Condition (Test-OsNeedsSmb1AuditRegistry -OsVersion ([version]'6.1.7601') -CmdletHasAuditParameter $false) `
        -Name 'Server 2008 R2 (6.1) uses the AuditSmb1Access registry DWORD'
    Assert-True -Condition (Test-OsNeedsSmb1AuditRegistry -OsVersion ([version]'6.2.9200') -CmdletHasAuditParameter $false) `
        -Name 'Server 2012 / Windows 8 (6.2) uses the AuditSmb1Access registry DWORD'
    Assert-True -Condition (Test-OsNeedsSmb1AuditRegistry -OsVersion ([version]'6.2.9200') -CmdletHasAuditParameter $true) `
        -Name 'Server 2012 still uses registry even if a later cmdlet parameter exists'
    Assert-True -Condition (Test-OsNeedsSmb1AuditRegistry -OsVersion ([version]'6.3.9600') -CmdletHasAuditParameter $true) `
        -Name 'Server 2012 R2 (6.3) uses the AuditSmb1Access registry DWORD (no cmdlet parameter)'
    Assert-True -Condition (Test-OsNeedsSmb1AuditRegistry -OsVersion ([version]'6.3.9600') -CmdletHasAuditParameter $false) `
        -Name 'Server 2012 R2 uses registry when the cmdlet parameter is missing'
    Assert-True -Condition (-not (Test-OsNeedsSmb1AuditRegistry -OsVersion ([version]'10.0.14393') -CmdletHasAuditParameter $true)) `
        -Name 'Server 2016 (10.0) uses the cmdlet, not a forced registry write'
    Assert-True -Condition (-not (Test-OsNeedsSmb1AuditRegistry -OsVersion ([version]'10.0.17763') -CmdletHasAuditParameter $true)) `
        -Name 'Server 2019 (10.0) uses the cmdlet, not a forced registry write'

    Assert-True -Condition ($dc1c1.Source -eq 'Event3000') `
        -Name 'Summary defaults Source to Event3000 when the row has none'

    $mixedSource = @(
        [pscustomobject]@{ DomainController = 'DC1'; TimeCreated = [datetime]'2026-03-01 10:00:00'; ClientAddress = '10.9.9.9'; Source = 'Operational' }
        [pscustomobject]@{ DomainController = 'DC1'; TimeCreated = [datetime]'2026-03-01 10:05:00'; ClientAddress = '10.9.9.9'; Source = 'LiveSession' }
    )
    $mixedSummary = @(ConvertTo-Smbv1Summary -Events $mixedSource -ResolveDns $false)
    Assert-True -Condition ($mixedSummary.Count -eq 1 -and $mixedSummary[0].ConnectionCount -eq 2) `
        -Name 'Summary groups Operational and live-session rows for the same client'
    Assert-True -Condition ($mixedSummary[0].Source -match 'LiveSession' -and $mixedSummary[0].Source -match 'Operational') `
        -Name 'Summary joins Source values from mixed event and live-session rows'

    $liveOnly = @(
        [pscustomobject]@{ DomainController = 'DC1'; TimeCreated = [datetime]'2026-03-01 10:00:00'; ClientAddress = '10.8.8.8'; Source = 'LiveSession' }
    )
    $liveSummary = @(ConvertTo-Smbv1Summary -Events $liveOnly -ResolveDns $false)
    Assert-True -Condition ($liveSummary.Count -eq 1 -and $liveSummary[0].Source -eq 'LiveSession') `
        -Name 'Summary keeps Source=LiveSession for a live Get-SmbSession row'

    $htmlWithSource = ConvertTo-Smbv1Html -SummaryRows $mixedSummary -RollupRows @() -Targets @('DC1') -Days 7
    Assert-True -Condition ($htmlWithSource -match 'LiveSession' -and $htmlWithSource -match '<th>Source</th>') `
        -Name 'HTML report includes the Source column for fallback rows'

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

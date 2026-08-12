<#
.SYNOPSIS
    Comprehensive Windows Server Health & Performance Analysis.

.DESCRIPTION
    Collects CPU, memory, disk, network, SQL Server, Active Directory, Hyper-V,
    certificate, and security metrics, then writes a self-contained HTML report
    and a CSV export.

    Designed for Windows PowerShell 5.1 (also runs on PowerShell 7 on Windows).
    Run elevated. Individual sections are isolated so one failure cannot abort
    the rest of the run.

.PARAMETER OutputPath
    Directory for the HTML and CSV files. Created if missing.
    Defaults to the current user's Desktop, then TEMP if Desktop is unavailable.

.PARAMETER SampleIntervalSeconds
    Seconds between performance-counter samples. Default: 5.

.PARAMETER SampleCount
    Number of performance-counter samples per counter group. Default: 3.

.PARAMETER EventLogHours
    How far back to scan Application/System (and optional Security) logs. Default: 24.

.PARAMETER EventLogMaxPerLog
    Maximum events retrieved per log before grouping. Default: 80.

.PARAMETER BpaTimeoutSeconds
    Per-model timeout for Best Practices Analyzer jobs. Default: 45.

.PARAMETER Sections
    Subset of sections to run. Default: All.

.PARAMETER SkipBpa
    Skip Windows Best Practices Analyzer (recommended on most servers; BPA can hang).

.PARAMETER SkipSoftware
    Skip installed-software inventory (faster on servers with large Add/Remove lists).

.PARAMETER IncludeRootCertificates
    Include LocalMachine\Root and CA stores. Default is Personal + WebHosting only.

.PARAMETER IncludeSecurityLog
    Include targeted Security-log event IDs (failed logons, group changes, log cleared).

.PARAMETER NoBrowser
    Do not open the HTML report when the run finishes.

.EXAMPLE
    .\Invoke-SystemAnalysis.ps1

.EXAMPLE
    .\Invoke-SystemAnalysis.ps1 -OutputPath D:\Reports -SkipBpa -NoBrowser

.NOTES
    Author: Anthony Blake (Anthony.Blake@cdw.com)
    Requires: Windows PowerShell 5.1+ and an elevated session.
#>
#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath,
    [ValidateRange(1, 60)]
    [int]$SampleIntervalSeconds = 5,
    [ValidateRange(1, 30)]
    [int]$SampleCount = 3,
    [ValidateRange(1, 168)]
    [int]$EventLogHours = 24,
    [ValidateRange(10, 500)]
    [int]$EventLogMaxPerLog = 80,
    [ValidateRange(10, 300)]
    [int]$BpaTimeoutSeconds = 45,
    [ValidateSet(
        'All', 'CPU', 'Memory', 'Disk', 'Network', 'Software', 'Events',
        'Health', 'Security', 'SQL', 'Hardware', 'MemoryDeep', 'StorageDeep',
        'NetworkDeep', 'AD', 'HyperV', 'Certificates'
    )]
    [string[]]$Sections = @('All'),
    [switch]$SkipBpa,
    [switch]$SkipSoftware,
    [switch]$IncludeRootCertificates,
    [switch]$IncludeSecurityLog,
    [switch]$NoBrowser
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$WarningPreference     = 'Continue'
$ProgressPreference    = 'Continue'

#region ── Helpers ────────────────────────────────────────────────────────────

function Get-TimeStamp { Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }

function ConvertTo-HtmlEncoded {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
}

function Get-Truncated {
    param(
        [AllowNull()]
        [string]$Text,
        [int]$Max = 200
    )
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $clean = ($Text -replace '\s+', ' ').Trim()
    if ($clean.Length -le $Max) { return $clean }
    return $clean.Substring(0, $Max) + '...'
}

function Convert-CimTime {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return $null }
    if ($Value -is [datetime]) { return [datetime]$Value }
    try {
        return [System.Management.ManagementDateTimeConverter]::ToDateTime($Value)
    } catch {
        try { return [datetime]$Value } catch { return $null }
    }
}

function Get-CimOrWmi {
    param(
        [Parameter(Mandatory)]
        [string]$Class,
        [string]$Filter
    )
    try {
        if ($Filter) {
            return @(Get-CimInstance -ClassName $Class -Filter $Filter -ErrorAction Stop)
        }
        return @(Get-CimInstance -ClassName $Class -ErrorAction Stop)
    } catch {
        try {
            if ($Filter) {
                return @(Get-WmiObject -Class $Class -Filter $Filter -ErrorAction Stop)
            }
            return @(Get-WmiObject -Class $Class -ErrorAction Stop)
        } catch {
            return @()
        }
    }
}

function Test-SectionEnabled {
    param([string]$Name)
    if (-not $Sections -or $Sections -contains 'All') { return $true }
    return $Sections -contains $Name
}

function Write-Step {
    param([string]$Message, [string]$Detail)
    Write-Host "[*] $Message" -ForegroundColor Cyan
    if ($Detail) { Write-Host "    $Detail" -ForegroundColor DarkGray }
}

function Write-StepWarn {
    param([string]$Message)
    Write-Host "    [!] $Message" -ForegroundColor Yellow
}

function New-RowList {
    return New-Object 'System.Collections.Generic.List[PSObject]'
}

function Add-CsvRow {
    param(
        [string]$Section,
        [string]$Check,
        [string]$Value,
        [string]$Status,
        [string]$Recommendation = ''
    )
    $script:csvRows.Add([PSCustomObject]@{
        Section        = $Section
        Check          = $Check
        Value          = $Value
        Status         = $Status
        Recommendation = $Recommendation
    })
}

function Register-Status {
    param(
        [string]$Status,
        [string]$Section,
        [string]$Check,
        [string]$Value,
        [string]$Recommendation = ''
    )
    if ($Status -eq 'Critical' -or $Status -eq 'Warning' -or $Status -eq 'OK') {
        [void]$script:statuses.Add($Status)
    }
    if ($Status -eq 'Critical' -or $Status -eq 'Warning') {
        $script:attentionRows.Add([PSCustomObject]@{
            Section        = $Section
            Check          = $Check
            Value          = $Value
            Status         = $Status
            Recommendation = $Recommendation
        })
    }
}

function Add-CheckRow {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[PSObject]]$List,
        [Parameter(Mandatory)]
        [string]$Section,
        [Parameter(Mandatory)]
        [hashtable]$Properties,
        [string]$Status = 'Info',
        [string]$Recommendation = '',
        [string]$Check,
        [string]$Value,
        [switch]$NoScore
    )
    $obj = New-Object PSObject
    foreach ($key in $Properties.Keys) {
        $obj | Add-Member -NotePropertyName $key -NotePropertyValue $Properties[$key]
    }
    if (-not ($obj.PSObject.Properties.Name -contains 'Status')) {
        $obj | Add-Member -NotePropertyName Status -NotePropertyValue $Status
    } else {
        $Status = [string]$obj.Status
    }
    if (-not ($obj.PSObject.Properties.Name -contains 'Recommendation')) {
        $obj | Add-Member -NotePropertyName Recommendation -NotePropertyValue $Recommendation
    } else {
        $Recommendation = [string]$obj.Recommendation
    }
    $List.Add($obj)

    $checkName = $Check
    if (-not $checkName) {
        foreach ($candidate in @('Check', 'Counter', 'Name', 'Item', 'Drive', 'Subject', 'TaskName')) {
            if ($obj.PSObject.Properties.Name -contains $candidate -and $obj.$candidate) {
                $checkName = [string]$obj.$candidate
                break
            }
        }
        if (-not $checkName) { $checkName = $Section }
    }
    $checkValue = $Value
    if ($null -eq $checkValue -or $checkValue -eq '') {
        foreach ($candidate in @('Value', 'Average', 'State', 'PctFree')) {
            if ($obj.PSObject.Properties.Name -contains $candidate -and $null -ne $obj.$candidate) {
                $checkValue = [string]$obj.$candidate
                break
            }
        }
    }

    Add-CsvRow -Section $Section -Check $checkName -Value $checkValue -Status $Status -Recommendation $Recommendation
    if (-not $NoScore) {
        Register-Status -Status $Status -Section $Section -Check $checkName -Value $checkValue -Recommendation $Recommendation
    }
}

function Get-WorstStatus {
    param($Rows)
    if ($null -eq $Rows) { return 'Info' }
    $list = @($Rows | Where-Object { $_ })
    if ($list.Count -eq 0) { return 'Info' }
    if ($list | Where-Object { $_.Status -eq 'Critical' }) { return 'Critical' }
    if ($list | Where-Object { $_.Status -eq 'Warning'  }) { return 'Warning'  }
    if ($list | Where-Object { $_.Status -eq 'OK'       }) { return 'OK'       }
    return 'Info'
}

function Get-CounterAverages {
    param([string[]]$Counters)
    $result = New-RowList
    $wanted = @($Counters | Where-Object { $_ })
    if ($wanted.Count -eq 0) { return $result }

    $samples = $null
    try {
        $samples = Get-Counter -Counter $wanted -SampleInterval $SampleIntervalSeconds -MaxSamples $SampleCount -ErrorAction Stop
    } catch {
        $valid = New-Object 'System.Collections.Generic.List[string]'
        foreach ($c in $wanted) {
            try {
                $null = Get-Counter -Counter $c -MaxSamples 1 -ErrorAction Stop
                $valid.Add($c)
            } catch { }
        }
        if ($valid.Count -eq 0) { return $result }
        try {
            $samples = Get-Counter -Counter $valid.ToArray() -SampleInterval $SampleIntervalSeconds -MaxSamples $SampleCount -ErrorAction Stop
        } catch {
            return $result
        }
    }

    $bucket = @{}
    foreach ($set in @($samples)) {
        if ($null -eq $set) { continue }
        foreach ($s in @($set.CounterSamples)) {
            if ($null -eq $s) { continue }
            $path = [string]$s.Path
            $slash = $path.LastIndexOf('\')
            $counterName = if ($slash -ge 0 -and $slash -lt ($path.Length - 1)) { $path.Substring($slash + 1) } else { $path }
            $instance = [string]$s.InstanceName
            if ([string]::IsNullOrWhiteSpace($instance)) { $instance = '_Total' }
            $key = "$instance|$counterName"
            if (-not $bucket.ContainsKey($key)) {
                $bucket[$key] = @{ Name = $counterName; Instance = $instance; Values = New-Object 'System.Collections.Generic.List[double]' }
            }
            try { [void]$bucket[$key].Values.Add([double]$s.CookedValue) } catch { }
        }
    }

    foreach ($key in ($bucket.Keys | Sort-Object)) {
        $avg = ($bucket[$key].Values | Measure-Object -Average).Average
        $result.Add([PSCustomObject]@{
            Counter  = $bucket[$key].Name
            Instance = $bucket[$key].Instance
            Average  = $avg
        })
    }
    return $result
}

function Format-Number {
    param($Value, [int]$Decimals = 2)
    if ($null -eq $Value) { return '' }
    try { return ([math]::Round([double]$Value, $Decimals)).ToString() } catch { return [string]$Value }
}

function Test-PendingReboot {
    $reasons = New-Object 'System.Collections.Generic.List[string]'

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        [void]$reasons.Add('Component Based Servicing')
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        [void]$reasons.Add('Windows Update')
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting') {
        [void]$reasons.Add('Post-reboot reporting')
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttempts') {
        [void]$reasons.Add('Server Manager')
    }

    try {
        $sm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop
        $pfro = $sm.PendingFileRenameOperations
        if ($pfro -and @($pfro | Where-Object { $_ -and $_.ToString().Trim() }).Count -gt 0) {
            [void]$reasons.Add('Pending file rename')
        }
    } catch { }

    try {
        $cd = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -Name JoinDomain, AvoidSpnSet -ErrorAction SilentlyContinue
        if ($cd -and ($cd.JoinDomain -or $cd.AvoidSpnSet)) {
            [void]$reasons.Add('Domain join')
        }
    } catch { }

    return $reasons
}

function Get-HtmlTable {
    param(
        [string]$SectionName,
        $Rows,
        [string[]]$Headers,
        [string]$BarColumn
    )
    if ($null -eq $Rows) { return '<p class="no-data">No data collected.</p>' }
    $list = @($Rows | Where-Object { $_ })
    if ($list.Count -eq 0) { return '<p class="no-data">No data collected.</p>' }

    $script:tableSeq++
    $tableId = "tbl-$SectionName-$($script:tableSeq)"
    $sb2 = New-Object System.Text.StringBuilder

    $hasStatuses = @{}
    foreach ($row in $list) {
        if ($null -ne $row.Status) { $hasStatuses[[string]$row.Status] = $true }
    }

    [void]$sb2.AppendLine("<div class=`"table-controls`" data-for=`"$tableId`">")
    [void]$sb2.AppendLine('<div class="filter-pills" role="group" aria-label="Filter by status">')
    [void]$sb2.AppendLine('<button type="button" class="pill pill-all active" data-filter="all">All</button>')
    if ($hasStatuses['Critical']) { [void]$sb2.AppendLine('<button type="button" class="pill pill-crit" data-filter="Critical">Critical</button>') }
    if ($hasStatuses['Warning'])  { [void]$sb2.AppendLine('<button type="button" class="pill pill-warn" data-filter="Warning">Warning</button>') }
    if ($hasStatuses['OK'])       { [void]$sb2.AppendLine('<button type="button" class="pill pill-ok" data-filter="OK">OK</button>') }
    if ($hasStatuses['Info'])     { [void]$sb2.AppendLine('<button type="button" class="pill pill-info" data-filter="Info">Info</button>') }
    [void]$sb2.AppendLine('</div>')
    [void]$sb2.AppendLine("<input type=`"search`" class=`"tbl-search`" placeholder=`"Filter rows...`" aria-label=`"Filter $SectionName table`" autocomplete=`"off`">")
    [void]$sb2.AppendLine("<span class=`"tbl-count`" data-total=`"$($list.Count)`">$($list.Count)</span>")
    [void]$sb2.AppendLine('</div>')

    [void]$sb2.AppendLine("<div class=`"table-wrapper`"><table id=`"$tableId`">")
    [void]$sb2.AppendLine('<thead><tr>')
    $colIdx = 0
    foreach ($h in $Headers) {
        [void]$sb2.AppendLine("<th scope=`"col`" data-col=`"$colIdx`">$(ConvertTo-HtmlEncoded $h) <span class=`"sort-icon`" aria-hidden=`"true`">&#9650;</span></th>")
        $colIdx++
    }
    [void]$sb2.AppendLine('</tr></thead><tbody>')

    foreach ($row in $list) {
        $statusVal = if ($null -ne $row.Status) { [string]$row.Status } else { '' }
        $rowClass = switch ($statusVal) {
            'Critical' { 'row-crit' }
            'Warning'  { 'row-warn' }
            'OK'       { 'row-ok' }
            default    { 'row-info' }
        }
        [void]$sb2.AppendLine("<tr class=`"$rowClass`" data-status=`"$statusVal`">")
        foreach ($h in $Headers) {
            $val = $null
            if ($row.PSObject.Properties.Name -contains $h) { $val = $row.$h }
            if ($null -eq $val) { $val = '' }
            if ($val -is [datetime]) { $val = $val.ToString('yyyy-MM-dd HH:mm:ss') }
            $encoded = ConvertTo-HtmlEncoded $val

            if ($h -eq 'Status') {
                $pillClass = switch ($statusVal) {
                    'Critical' { 'sp-crit' }
                    'Warning'  { 'sp-warn' }
                    'OK'       { 'sp-ok' }
                    default    { 'sp-info' }
                }
                [void]$sb2.AppendLine("<td class=`"status-cell`"><span class=`"status-pill $pillClass`">$encoded</span></td>")
            } elseif ($h -eq 'Recommendation' -or $h -eq 'Resolution' -or $h -eq 'Problem' -or $h -eq 'Message') {
                [void]$sb2.AppendLine("<td class=`"rec-cell`">$encoded</td>")
            } elseif ($BarColumn -and $h -eq $BarColumn) {
                $pct = $null
                $raw = $val.ToString()
                if ($raw -match '([\d.]+)') { try { $pct = [double]$Matches[1] } catch { $pct = $null } }
                if ($null -ne $pct) {
                    if ($pct -gt 100) { $pct = 100 }
                    if ($pct -lt 0) { $pct = 0 }
                    $fill = if ($pct -lt 10) { 'var(--crit)' } elseif ($pct -lt 15) { 'var(--warn)' } else { 'var(--ok)' }
                    [void]$sb2.AppendLine("<td><div class=`"meter`" title=`"$encoded`"><span class=`"meter-fill`" style=`"width:$pct%;background:$fill`"></span></div><span class=`"meter-label`">$encoded</span></td>")
                } else {
                    [void]$sb2.AppendLine("<td>$encoded</td>")
                }
            } else {
                [void]$sb2.AppendLine("<td>$encoded</td>")
            }
        }
        [void]$sb2.AppendLine('</tr>')
    }
    [void]$sb2.AppendLine('</tbody></table></div>')
    return $sb2.ToString()
}

function New-SubTitle {
    param([string]$T)
    return "<div class=`"subsection-title`">$(ConvertTo-HtmlEncoded $T)</div>"
}

function New-SectionPanel {
    param(
        [string]$Id,
        [string]$Title,
        [string]$WorstStatus,
        [int]$CheckCount,
        [string]$BodyHtml,
        [bool]$StartOpen = $false
    )
    $badgeClass = switch ($WorstStatus) {
        'Critical' { 'badge-crit' }
        'Warning'  { 'badge-warn' }
        'OK'       { 'badge-ok' }
        default    { 'badge-info' }
    }
    $openClass = ''
    $expanded  = 'false'
    if ($StartOpen) { $openClass = ' open'; $expanded = 'true' }
    $sb3 = New-Object System.Text.StringBuilder
    [void]$sb3.AppendLine("<section class=`"section-panel$openClass`" id=`"$Id`" data-status=`"$WorstStatus`">")
    [void]$sb3.AppendLine("<div class=`"section-header`" role=`"button`" tabindex=`"0`" aria-expanded=`"$expanded`" aria-controls=`"$Id-body`">")
    [void]$sb3.AppendLine('<span class="section-chevron" aria-hidden="true">&#9658;</span>')
    [void]$sb3.AppendLine("<span class=`"section-title`">$(ConvertTo-HtmlEncoded $Title)</span>")
    [void]$sb3.AppendLine("<span class=`"section-badge $badgeClass`">$(ConvertTo-HtmlEncoded $WorstStatus)</span>")
    [void]$sb3.AppendLine("<span class=`"section-count`">$CheckCount checks</span>")
    [void]$sb3.AppendLine('</div>')
    [void]$sb3.AppendLine("<div class=`"section-body`" id=`"$Id-body`">$BodyHtml</div>")
    [void]$sb3.AppendLine('</section>')
    return $sb3.ToString()
}

function Invoke-Section {
    param(
        [string]$Name,
        [int]$Percent,
        [scriptblock]$Script
    )
    Write-Progress -Activity "System Analysis ($hostname)" -Status $Name -PercentComplete $Percent
    try {
        . $Script
    } catch {
        Write-StepWarn "$Name failed: $($_.Exception.Message)"
        Add-CsvRow -Section $Name -Check 'Section error' -Value $_.Exception.Message -Status 'Warning' -Recommendation 'This section failed. Re-run elevated and review the console output.'
        Register-Status -Status 'Warning' -Section $Name -Check 'Section error' -Value $_.Exception.Message -Recommendation 'This section failed. Re-run elevated and review the console output.'
    }
}

#endregion

#region ── Init ───────────────────────────────────────────────────────────────

$hostname  = $env:COMPUTERNAME
$startTime = Get-Date
$script:tableSeq = 0
$script:statuses = New-Object 'System.Collections.Generic.List[string]'
$script:csvRows = New-RowList
$script:attentionRows = New-RowList

if (-not $OutputPath) {
    $desktop = Join-Path $env:USERPROFILE 'Desktop'
    if (Test-Path -LiteralPath $desktop) { $OutputPath = $desktop } else { $OutputPath = $env:TEMP }
}
try {
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
} catch {
    Write-Host "[!] Cannot write to '$OutputPath' ($($_.Exception.Message)). Using TEMP." -ForegroundColor Yellow
    $OutputPath = $env:TEMP
}

Write-Host ""
Write-Host "  System Analysis  |  $hostname  |  $(Get-TimeStamp)" -ForegroundColor White
Write-Host "  Sampling $($SampleCount)x $($SampleIntervalSeconds)s performance counters" -ForegroundColor DarkGray
Write-Host ""

$cpuRows = New-RowList; $cpuInfoRows = New-RowList
$memRows = New-RowList
$diskRows = New-RowList; $volRows = New-RowList
$netRows = New-RowList
$swRows = New-RowList; $featureRows = New-RowList; $svcRows = New-RowList; $taskRows = New-RowList
$eventRows = New-RowList
$winHealthRows = New-RowList; $wuRows = New-RowList
$secRows = New-RowList; $iisRows = New-RowList; $w32tmRows = New-RowList
$sqlInstRows = New-RowList; $sqlCounterRows = New-RowList
$script:sqlInstances = @()
$hwRows = New-RowList; $physDiskRows = New-RowList; $nicRows = New-RowList; $nicLinkRows = New-RowList
$memDeepRows = New-RowList; $pfRows = New-RowList
$storDeepRows = New-RowList; $vssRows = New-RowList; $fsHealthRows = New-RowList
$netDeepRows = New-RowList; $dnsRows = New-RowList; $listenRows = New-RowList
$adKerbBpaHtml = '<p class="no-data">AD / Kerberos / BPA section was skipped.</p>'
$adWorst = 'Info'; $adCheckCount = 0
$hvRows = New-RowList
$certRows = New-RowList
$osInfo = $null
$logicalProcs = 1

$osInfoArr = Get-CimOrWmi -Class Win32_OperatingSystem
if ($osInfoArr.Count -gt 0) { $osInfo = $osInfoArr[0] }

#endregion

#region ── Section 1: CPU ─────────────────────────────────────────────────────

if (Test-SectionEnabled 'CPU') {
    Write-Step 'CPU analysis' 'Sampling processor counters...'
    Invoke-Section -Name 'CPU' -Percent 6 -Script {
        $cpuCounters = @(
            '\Processor(_Total)\% Processor Time',
            '\Processor(_Total)\% Privileged Time',
            '\Processor(_Total)\% User Time',
            '\Processor(_Total)\% Interrupt Time',
            '\System\Processor Queue Length',
            '\System\Context Switches/sec'
        )
        $averages = Get-CounterAverages -Counters $cpuCounters
        $procInfo = Get-CimOrWmi -Class Win32_Processor
        $logicalProcs = 0
        foreach ($p in $procInfo) {
            try { $logicalProcs += [int]$p.NumberOfLogicalProcessors } catch { }
            $cpuInfoRows.Add([PSCustomObject]@{
                Name         = $p.Name
                Cores        = $p.NumberOfCores
                LogicalProcs = $p.NumberOfLogicalProcessors
                MaxClockMHz  = $p.MaxClockSpeed
                CurrentMHz   = $p.CurrentClockSpeed
                L2CacheKB    = $p.L2CacheSize
                L3CacheKB    = $p.L3CacheSize
                Status       = 'Info'
            })
        }
        if ($logicalProcs -lt 1) { $logicalProcs = 1 }
        $script:logicalProcs = $logicalProcs

        foreach ($item in $averages) {
            $status = 'OK'
            $rec    = ''
            $name   = $item.Counter
            $avg    = $item.Average
            if ($name -eq '% Processor Time') {
                if ($avg -gt 90) { $status = 'Critical'; $rec = 'CPU consistently above 90%. Identify high-CPU processes and right-size the VM or service.' }
                elseif ($avg -gt 75) { $status = 'Warning'; $rec = 'CPU above 75%. Monitor for sustained spikes before they become saturation.' }
            }
            if ($name -eq 'Processor Queue Length' -and $avg -gt [Math]::Max(2, $logicalProcs)) {
                $status = 'Warning'
                $rec = "Queue length ($([math]::Round($avg,1))) exceeds logical processors ($logicalProcs). The CPU scheduler is backing up."
            }
            if ($name -eq '% Interrupt Time' -and $avg -gt 15) {
                $status = 'Warning'
                $rec = 'High interrupt time. Check NIC offload, storage drivers, or excessive hardware interrupts.'
            }
            Add-CheckRow -List $cpuRows -Section 'CPU' -Status $status -Recommendation $rec -Check $name -Value (Format-Number $avg) -Properties @{
                Counter        = $name
                Average        = Format-Number $avg
                Status         = $status
                Recommendation = $rec
            }
        }
    }
}

#endregion

#region ── Section 2: Memory ──────────────────────────────────────────────────

if (Test-SectionEnabled 'Memory') {
    Write-Step 'Memory analysis' 'Sampling memory counters...'
    Invoke-Section -Name 'Memory' -Percent 12 -Script {
        $memCounters = @(
            '\Memory\Available MBytes',
            '\Memory\% Committed Bytes In Use',
            '\Memory\Pages/sec',
            '\Memory\Page Faults/sec',
            '\Memory\Pool Nonpaged Bytes',
            '\Memory\Pool Paged Bytes',
            '\Memory\Cache Bytes',
            '\Memory\Committed Bytes'
        )
        $totalMB = 0
        if ($osInfo) {
            try { $totalMB = [math]::Round($osInfo.TotalVisibleMemorySize / 1KB, 0) } catch { $totalMB = 0 }
        }
        $averages = Get-CounterAverages -Counters $memCounters
        foreach ($item in $averages) {
            $status  = 'OK'
            $rec     = ''
            $name    = $item.Counter
            $avg     = $item.Average
            $display = Format-Number $avg

            if ($name -eq 'Available MBytes') {
                $pctFree = if ($totalMB -gt 0) { [math]::Round(($avg / $totalMB) * 100, 1) } else { 100 }
                if ($pctFree -lt 8) { $status = 'Critical'; $rec = 'Less than 8% RAM free. Paging and allocation failures are likely.' }
                elseif ($pctFree -lt 15) { $status = 'Warning'; $rec = 'Less than 15% RAM free. Watch working sets and consider adding memory.' }
                $display = "$([math]::Round($avg, 0)) MB ($pctFree% free)"
            }
            if ($name -eq 'Pages/sec' -and $avg -gt 100) {
                $status = 'Warning'; $rec = 'High paging. Confirm this is hard page faults (not just cache activity) and check RAM pressure.'
            }
            if ($name -eq '% Committed Bytes In Use' -and $avg -gt 85) {
                $status = 'Warning'; $rec = 'Committed memory above 85%. The commit limit (RAM + page file) is getting tight.'
            }
            if ($name -eq 'Pool Nonpaged Bytes' -and $avg -gt 1GB) {
                $status = 'Warning'; $rec = 'Nonpaged pool is large. Investigate pool leaks with poolmon or a similar tool.'
            }

            Add-CheckRow -List $memRows -Section 'Memory' -Status $status -Recommendation $rec -Check $name -Value $display -Properties @{
                Counter        = $name
                Average        = $display
                Status         = $status
                Recommendation = $rec
            }
        }
    }
}

#endregion

#region ── Section 3: Disk ────────────────────────────────────────────────────

if (Test-SectionEnabled 'Disk') {
    Write-Step 'Disk analysis' 'Sampling disk counters and volume free space...'
    Invoke-Section -Name 'Disk' -Percent 18 -Script {
        $diskCounters = @(
            '\PhysicalDisk(_Total)\Avg. Disk sec/Read',
            '\PhysicalDisk(_Total)\Avg. Disk sec/Write',
            '\PhysicalDisk(_Total)\Disk Reads/sec',
            '\PhysicalDisk(_Total)\Disk Writes/sec',
            '\PhysicalDisk(_Total)\% Disk Time',
            '\PhysicalDisk(_Total)\Current Disk Queue Length',
            '\LogicalDisk(_Total)\Free Megabytes'
        )
        $averages = Get-CounterAverages -Counters $diskCounters
        foreach ($item in $averages) {
            $status  = 'OK'
            $rec     = ''
            $name    = $item.Counter
            $avg     = $item.Average
            $display = Format-Number $avg 4

            if ($name -eq '% Disk Time' -and $avg -gt 85) {
                $status = 'Warning'; $rec = 'Disk busy time above 85%. Check for an IO bottleneck (this counter is less meaningful on RAID/SSDs).'
            }
            if ($name -eq 'Avg. Disk sec/Read' -and $avg -gt 0.025) {
                $status = 'Warning'; $rec = 'Read latency above 25ms. Investigate storage performance, queue depth, and competing workloads.'
            }
            if ($name -eq 'Avg. Disk sec/Write' -and $avg -gt 0.025) {
                $status = 'Warning'; $rec = 'Write latency above 25ms. Investigate storage performance and cache/battery health on the array.'
            }
            if ($name -eq 'Current Disk Queue Length' -and $avg -gt 4) {
                $status = 'Warning'; $rec = 'Disk queue is elevated. The IO subsystem may be overloaded.'
            }

            Add-CheckRow -List $diskRows -Section 'Disk' -Status $status -Recommendation $rec -Check $name -Value $display -Properties @{
                Counter        = $name
                Average        = $display
                Status         = $status
                Recommendation = $rec
            }
        }

        $volumes = Get-CimOrWmi -Class Win32_LogicalDisk -Filter 'DriveType=3'
        foreach ($v in $volumes) {
            if (-not $v.Size -or $v.Size -le 0) { continue }
            $totalGB = [math]::Round($v.Size / 1GB, 2)
            $freeGB  = [math]::Round($v.FreeSpace / 1GB, 2)
            $pctFree = [math]::Round(($v.FreeSpace / $v.Size) * 100, 1)
            $status  = if ($pctFree -lt 8) { 'Critical' } elseif ($pctFree -lt 15) { 'Warning' } else { 'OK' }
            $rec     = ''
            if ($pctFree -lt 8) { $rec = "Critical: $($v.DeviceID) has less than 8% free ($freeGB GB of $totalGB GB)." }
            elseif ($pctFree -lt 15) { $rec = "Warning: $($v.DeviceID) has less than 15% free. Plan cleanup or expansion." }
            Add-CheckRow -List $volRows -Section 'Disk-Volume' -Status $status -Recommendation $rec -Check $v.DeviceID -Value "$freeGB GB free ($pctFree%)" -Properties @{
                Drive          = $v.DeviceID
                Label          = $v.VolumeName
                TotalGB        = $totalGB
                FreeGB         = $freeGB
                PctFree        = "$pctFree%"
                FileSystem     = $v.FileSystem
                Status         = $status
                Recommendation = $rec
            }
        }
    }
}

#endregion

#region ── Section 4: Network ─────────────────────────────────────────────────

if (Test-SectionEnabled 'Network') {
    Write-Step 'Network analysis' 'Sampling NIC counters...'
    Invoke-Section -Name 'Network' -Percent 24 -Script {
        $skipPattern = 'isatap|Teredo|Loopback|6TO4|VPN|Pseudo'
        $nicNames = @()
        try {
            $probe = Get-Counter '\Network Interface(*)\Bytes Total/sec' -ErrorAction Stop
            $nicNames = @(
                @($probe.CounterSamples) |
                    ForEach-Object { $_.InstanceName } |
                    Where-Object { $_ -and $_ -ne '_Total' -and $_ -notmatch $skipPattern } |
                    Select-Object -Unique
            )
        } catch { }

        $netCounterList = New-Object 'System.Collections.Generic.List[string]'
        foreach ($nic in $nicNames) {
            $netCounterList.Add("\Network Interface($nic)\Bytes Total/sec")
            $netCounterList.Add("\Network Interface($nic)\Packets Received Errors")
            $netCounterList.Add("\Network Interface($nic)\Packets Outbound Errors")
            $netCounterList.Add("\Network Interface($nic)\Output Queue Length")
            $netCounterList.Add("\Network Interface($nic)\Packets Received Discarded")
        }
        if ($netCounterList.Count -eq 0) {
            [void]$netCounterList.Add('\Network Interface(*)\Bytes Total/sec')
            [void]$netCounterList.Add('\Network Interface(*)\Packets Received Errors')
            [void]$netCounterList.Add('\Network Interface(*)\Output Queue Length')
        }

        $averages = Get-CounterAverages -Counters $netCounterList.ToArray()
        foreach ($item in $averages) {
            if ($item.Instance -match $skipPattern) { continue }
            $status = 'OK'
            $rec    = ''
            $name   = $item.Counter
            $avg    = $item.Average
            if ($name -match 'Error|Discarded' -and $avg -gt 0) {
                $status = 'Warning'
                $rec = 'NIC errors or discards detected. Check cabling, driver, offload settings, and the switch port.'
            }
            if ($name -eq 'Output Queue Length' -and $avg -gt 2) {
                $status = 'Warning'
                $rec = 'Output queue elevated. Possible bandwidth saturation or a paused adapter.'
            }
            Add-CheckRow -List $netRows -Section 'Network' -Status $status -Recommendation $rec -Check "$($item.Instance) - $name" -Value (Format-Number $avg 4) -Properties @{
                NIC            = $item.Instance
                Counter        = $name
                Average        = Format-Number $avg 4
                Status         = $status
                Recommendation = $rec
            }
        }
    }
}

#endregion

#region ── Section 5: Software, Roles, Features, Services, Tasks ──────────────

if (Test-SectionEnabled 'Software') {
    Write-Step 'Software, roles, services, scheduled tasks'
    Invoke-Section -Name 'Software' -Percent 32 -Script {
        if (-not $SkipSoftware) {
            $seen = @{}
            $regPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )
            foreach ($rp in $regPaths) {
                $items = Get-ItemProperty $rp -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }
                foreach ($item in @($items)) {
                    $key = "$($item.DisplayName)|$($item.DisplayVersion)"
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $true
                    $installDate = $item.InstallDate
                    if ($installDate -match '^\d{8}$') {
                        try { $installDate = [datetime]::ParseExact($installDate, 'yyyyMMdd', $null).ToString('yyyy-MM-dd') } catch { }
                    }
                    $swRows.Add([PSCustomObject]@{
                        Name        = $item.DisplayName
                        Version     = $item.DisplayVersion
                        Publisher   = $item.Publisher
                        InstallDate = $installDate
                        Status      = 'Info'
                    })
                }
            }
            $sorted = @($swRows | Where-Object { $_ } | Sort-Object Name)
            $swRows.Clear()
            foreach ($s in $sorted) { $swRows.Add($s) }
        }

        $features = $null
        try { $features = Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed } } catch { }
        if ($features) {
            foreach ($f in $features) {
                $featureRows.Add([PSCustomObject]@{
                    Name        = $f.Name
                    DisplayName = $f.DisplayName
                    FeatureType = $f.FeatureType
                    Status      = 'Info'
                })
            }
        }

        $services = Get-CimOrWmi -Class Win32_Service
        foreach ($svc in $services) {
            if ($svc.StartMode -ne 'Auto') { continue }
            if ($svc.State -eq 'Running') { continue }
            # Ignore clean trigger-start / already-completed Automatic services (ExitCode 0 + Stopped is often expected).
            $exit = 0
            try { $exit = [int]$svc.ExitCode } catch { }
            if ($svc.State -eq 'Stopped' -and $exit -eq 0) { continue }
            $status = 'Warning'
            $rec = "Service '$($svc.Name)' is Automatic but $($svc.State) (exit $exit). Confirm whether this is expected."
            Add-CheckRow -List $svcRows -Section 'Services' -Status $status -Recommendation $rec -Check $svc.Name -Value $svc.State -Properties @{
                Name           = $svc.Name
                DisplayName    = $svc.DisplayName
                State          = $svc.State
                StartMode      = $svc.StartMode
                ExitCode       = $exit
                Status         = $status
                Recommendation = $rec
            }
        }

        $okTaskResults = @(0, 267008, 267009, 267011, 267014)
        try {
            $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object {
                $_.State -ne 'Disabled' -and $_.TaskPath -notmatch '^\\Microsoft\\'
            }
            foreach ($t in @($tasks)) {
                $taskInfo = $null
                try { $taskInfo = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch { }
                $lastResult = $null
                $lastRun = $null
                $nextRun = $null
                if ($taskInfo) {
                    $lastResult = $taskInfo.LastTaskResult
                    $lastRun = $taskInfo.LastRunTime
                    $nextRun = $taskInfo.NextRunTime
                }
                $lastResultInt = $null
                if ($null -ne $lastResult) {
                    try { $lastResultInt = [int]$lastResult } catch { $lastResultInt = $null }
                }
                $status = 'Info'
                $rec = ''
                if ($null -ne $lastResultInt -and $okTaskResults -notcontains $lastResultInt) {
                    $status = 'Warning'
                    $rec = "Task '$($t.TaskName)' last result was $lastResult. Review the task history."
                    Register-Status -Status $status -Section 'ScheduledTasks' -Check $t.TaskName -Value $lastResult -Recommendation $rec
                    Add-CsvRow -Section 'ScheduledTasks' -Check $t.TaskName -Value "$lastResult" -Status $status -Recommendation $rec
                }
                $taskRows.Add([PSCustomObject]@{
                    TaskName       = $t.TaskName
                    TaskPath       = $t.TaskPath
                    State          = $t.State
                    LastRunTime    = $lastRun
                    LastResult     = $lastResult
                    NextRunTime    = $nextRun
                    Status         = $status
                    Recommendation = $rec
                })
            }
        } catch {
            Write-StepWarn "Scheduled tasks: $($_.Exception.Message)"
        }
    }
}

#endregion

#region ── Section 6: Event logs ──────────────────────────────────────────────

if (Test-SectionEnabled 'Events') {
    Write-Step 'Event log analysis' "Last $EventLogHours hour(s), grouped by provider + ID..."
    Invoke-Section -Name 'Events' -Percent 40 -Script {
        $since = (Get-Date).AddHours(-$EventLogHours)
        $logs  = @('System', 'Application')
        if ($IncludeSecurityLog) { $logs += 'Security' }

        foreach ($log in $logs) {
            $events = @()
            try {
                if ($log -eq 'Security') {
                    $secIds = 1102, 4625, 4648, 4697, 4698, 4720, 4728, 4732, 4740, 4756
                    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $secIds; StartTime = $since } -MaxEvents $EventLogMaxPerLog -ErrorAction Stop)
                } else {
                    $events = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Level = 2, 3; StartTime = $since } -MaxEvents $EventLogMaxPerLog -ErrorAction Stop)
                }
            } catch {
                Write-StepWarn "Could not read $log log: $($_.Exception.Message)"
                continue
            }

            $groups = $events | Group-Object ProviderName, Id | Sort-Object Count -Descending
            foreach ($g in $groups) {
                $sample = $g.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
                $level  = [string]$sample.LevelDisplayName
                $status = if ($level -eq 'Error' -or $level -eq 'Critical') { 'Critical' } else { 'Warning' }
                $msg    = Get-Truncated -Text $sample.Message -Max 220
                $latest = if ($sample.TimeCreated) { $sample.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                Add-CheckRow -List $eventRows -Section "EventLog-$log" -Status $status -Check "$($sample.ProviderName) / $($sample.Id)" -Value "$($g.Count)x $msg" -Properties @{
                    Log            = $log
                    Count          = $g.Count
                    Latest         = $latest
                    Source         = $sample.ProviderName
                    EventID        = $sample.Id
                    Level          = $level
                    Message        = $msg
                    Status         = $status
                    Recommendation = 'Review the grouped events. Recurring IDs usually matter more than one-off noise.'
                }
            }
        }
    }
}

#endregion

#region ── Section 7: Windows Health ──────────────────────────────────────────

if (Test-SectionEnabled 'Health') {
    Write-Step 'Windows health' 'Uptime, patches, pending reboot...'
    Invoke-Section -Name 'Health' -Percent 46 -Script {
        if ($osInfo) {
            $boot = Convert-CimTime $osInfo.LastBootUpTime
            if ($boot) {
                $uptime    = (Get-Date) - $boot
                $uptimeStr = "{0}d {1}h {2}m" -f [int]$uptime.TotalDays, $uptime.Hours, $uptime.Minutes
                $status    = if ($uptime.TotalDays -gt 60) { 'Warning' } else { 'OK' }
                $rec       = if ($uptime.TotalDays -gt 60) { 'Uptime exceeds 60 days. Schedule a maintenance reboot so patches can finish applying.' } else { '' }
                Add-CheckRow -List $winHealthRows -Section 'WindowsHealth' -Status $status -Recommendation $rec -Check 'Uptime' -Value $uptimeStr -Properties @{
                    Check = 'Uptime'; Value = $uptimeStr; Status = $status; Recommendation = $rec
                }
            }
            $caption = "$($osInfo.Caption) Build $($osInfo.BuildNumber)"
            Add-CheckRow -List $winHealthRows -Section 'WindowsHealth' -Status 'Info' -Check 'OS' -Value $caption -NoScore -Properties @{
                Check = 'OS'; Value = $caption; Status = 'Info'; Recommendation = ''
            }
            $ramGB = [math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 2)
            $freeGB = [math]::Round($osInfo.FreePhysicalMemory / 1MB, 2)
            Add-CheckRow -List $winHealthRows -Section 'WindowsHealth' -Status 'Info' -Check 'Total RAM (GB)' -Value $ramGB -NoScore -Properties @{
                Check = 'Total RAM (GB)'; Value = $ramGB; Status = 'Info'; Recommendation = ''
            }
            Add-CheckRow -List $winHealthRows -Section 'WindowsHealth' -Status 'Info' -Check 'Free RAM (GB)' -Value $freeGB -NoScore -Properties @{
                Check = 'Free RAM (GB)'; Value = $freeGB; Status = 'Info'; Recommendation = ''
            }
        }

        $hotfixes = @()
        try { $hotfixes = @(Get-HotFix -ErrorAction Stop) } catch { }
        $dated = @($hotfixes | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
        foreach ($hf in ($dated | Select-Object -First 10)) {
            $wuRows.Add([PSCustomObject]@{
                HotFixID    = $hf.HotFixID
                Description = $hf.Description
                InstalledOn = $hf.InstalledOn.ToString('yyyy-MM-dd')
                Status      = 'Info'
            })
        }
        if ($dated.Count -gt 0) {
            $lastPatch = [datetime]$dated[0].InstalledOn
            $ageDays   = [int]((Get-Date) - $lastPatch).TotalDays
            $status    = if ($ageDays -gt 60) { 'Warning' } else { 'OK' }
            $rec       = if ($ageDays -gt 60) { "Last recorded hotfix is $ageDays days old ($($lastPatch.ToString('yyyy-MM-dd'))). Confirm patching is current." } else { '' }
            Add-CheckRow -List $winHealthRows -Section 'WindowsHealth' -Status $status -Recommendation $rec -Check 'Last hotfix age (days)' -Value $ageDays -Properties @{
                Check = 'Last hotfix age (days)'; Value = $ageDays; Status = $status; Recommendation = $rec
            }
        } elseif ($hotfixes.Count -eq 0) {
            Add-CheckRow -List $winHealthRows -Section 'WindowsHealth' -Status 'Warning' -Recommendation 'Get-HotFix returned no results. Confirm the servicing stack and WMI repository.' -Check 'Hotfixes' -Value 'None found' -Properties @{
                Check = 'Hotfixes'; Value = 'None found'; Status = 'Warning'; Recommendation = 'Get-HotFix returned no results. Confirm the servicing stack and WMI repository.'
            }
        }

        $rebootReasons = Test-PendingReboot
        $pending = $rebootReasons.Count -gt 0
        $rbStatus = if ($pending) { 'Warning' } else { 'OK' }
        $rbValue  = if ($pending) { ($rebootReasons -join ', ') } else { 'False' }
        $rbRec    = if ($pending) { "Pending reboot: $rbValue. Schedule a maintenance window." } else { '' }
        Add-CheckRow -List $winHealthRows -Section 'WindowsHealth' -Status $rbStatus -Recommendation $rbRec -Check 'Pending Reboot' -Value $rbValue -Properties @{
            Check = 'Pending Reboot'; Value = $rbValue; Status = $rbStatus; Recommendation = $rbRec
        }

        try {
            $plan = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -Filter 'IsActive=true' -ErrorAction Stop
            if ($plan) {
                $planName = $plan.ElementName
                $status = 'Info'
                $rec = ''
                if ($planName -match 'Balanced|Power saver') {
                    $status = 'Warning'
                    $rec = "Active power plan is '$planName'. Servers typically should use High Performance or an OEM equivalent."
                }
                Add-CheckRow -List $winHealthRows -Section 'WindowsHealth' -Status $status -Recommendation $rec -Check 'Power plan' -Value $planName -Properties @{
                    Check = 'Power plan'; Value = $planName; Status = $status; Recommendation = $rec
                }
            }
        } catch { }
    }
}

#endregion

#region ── Section 8: Security, IIS, Time ─────────────────────────────────────

if (Test-SectionEnabled 'Security') {
    Write-Step 'Security, IIS, Windows Time'
    Invoke-Section -Name 'Security' -Percent 52 -Script {
        $adminNames = @()
        try {
            $adminNames = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { $_.Name })
        } catch {
            try {
                $group = [ADSI]'WinNT://./Administrators,group'
                foreach ($m in @($group.Invoke('Members'))) {
                    $adminNames += $m.GetType().InvokeMember('Name', 'GetProperty', $null, $m, $null)
                }
            } catch {
                $raw = net localgroup Administrators 2>$null
                $capture = $false
                foreach ($line in @($raw)) {
                    if ($line -match '^-+$') { $capture = $true; continue }
                    if ($capture -and $line -match 'The command completed') { break }
                    if ($capture -and $line.Trim()) { $adminNames += $line.Trim() }
                }
            }
        }
        $adminValue = if ($adminNames.Count -gt 0) { ($adminNames | Select-Object -Unique) -join '; ' } else { 'Unable to enumerate' }
        Add-CheckRow -List $secRows -Section 'Security' -Status 'Info' -Recommendation 'Review local Administrators membership on a regular cadence.' -Check 'Local Admins' -Value $adminValue -NoScore -Properties @{
            Check = 'Local Admins'; Value = $adminValue; Status = 'Info'; Recommendation = 'Review local Administrators membership on a regular cadence.'
        }

        foreach ($prof in @('Domain', 'Private', 'Public')) {
            $fw = $null
            try { $fw = Get-NetFirewallProfile -Name $prof -ErrorAction Stop } catch { }
            $enabled = $false
            if ($fw) { $enabled = [bool]$fw.Enabled }
            $fwStatus = if ($fw -and $enabled) { 'OK' } else { 'Warning' }
            $fwValue  = if (-not $fw) { 'Unknown' } elseif ($enabled) { 'Enabled' } else { 'Disabled' }
            $fwRec    = if ($fwStatus -ne 'OK') { "Firewall $prof profile is $fwValue. Confirm this matches the security baseline." } else { '' }
            Add-CheckRow -List $secRows -Section 'Security' -Status $fwStatus -Recommendation $fwRec -Check "Firewall ($prof)" -Value $fwValue -Properties @{
                Check = "Firewall ($prof)"; Value = $fwValue; Status = $fwStatus; Recommendation = $fwRec
            }
        }

        $defenderStatus = $null
        try { $defenderStatus = Get-MpComputerStatus -ErrorAction Stop } catch { }
        if ($defenderStatus) {
            $avOn = [bool]$defenderStatus.AntivirusEnabled
            $avStatus = if ($avOn) { 'OK' } else { 'Critical' }
            $avRec = if (-not $avOn) { 'Windows Defender antivirus is disabled. Enable it or confirm a supported replacement AV is active.' } else { '' }
            Add-CheckRow -List $secRows -Section 'Security' -Status $avStatus -Recommendation $avRec -Check 'Defender AV Enabled' -Value $avOn -Properties @{
                Check = 'Defender AV Enabled'; Value = $avOn; Status = $avStatus; Recommendation = $avRec
            }

            $rtp = [bool]$defenderStatus.RealTimeProtectionEnabled
            $rtpStatus = if ($rtp) { 'OK' } else { 'Warning' }
            $rtpRec = if (-not $rtp) { 'Real-time protection is off. Confirm this is intentional (for example another AV owns the filter).' } else { '' }
            Add-CheckRow -List $secRows -Section 'Security' -Status $rtpStatus -Recommendation $rtpRec -Check 'Defender Real-Time' -Value $rtp -Properties @{
                Check = 'Defender Real-Time'; Value = $rtp; Status = $rtpStatus; Recommendation = $rtpRec
            }

            $sigAge = $null
            if ($defenderStatus.AntivirusSignatureLastUpdated) {
                $sigAge = [int]((Get-Date) - [datetime]$defenderStatus.AntivirusSignatureLastUpdated).TotalDays
            }
            if ($null -ne $sigAge) {
                $sigStatus = if ($sigAge -gt 7) { 'Critical' } elseif ($sigAge -gt 3) { 'Warning' } else { 'OK' }
                $sigRec = if ($sigAge -gt 3) { "Defender signatures are $sigAge day(s) old. Update immediately." } else { '' }
                Add-CheckRow -List $secRows -Section 'Security' -Status $sigStatus -Recommendation $sigRec -Check 'Defender Signature Age (days)' -Value $sigAge -Properties @{
                    Check = 'Defender Signature Age (days)'; Value = $sigAge; Status = $sigStatus; Recommendation = $sigRec
                }
            }
        }

        try {
            $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
            if ($smb1 -and $smb1.State -eq 'Enabled') {
                Add-CheckRow -List $secRows -Section 'Security' -Status 'Warning' -Recommendation 'SMBv1 is enabled. Disable it unless a legacy dependency still requires it.' -Check 'SMBv1' -Value 'Enabled' -Properties @{
                    Check = 'SMBv1'; Value = 'Enabled'; Status = 'Warning'; Recommendation = 'SMBv1 is enabled. Disable it unless a legacy dependency still requires it.'
                }
            } elseif ($smb1) {
                Add-CheckRow -List $secRows -Section 'Security' -Status 'OK' -Check 'SMBv1' -Value $smb1.State -Properties @{
                    Check = 'SMBv1'; Value = $smb1.State; Status = 'OK'; Recommendation = ''
                }
            }
        } catch { }

        $iisPresent = $false
        try {
            $w3 = Get-Service -Name W3SVC -ErrorAction Stop
            $iisPresent = $true
            Add-CheckRow -List $secRows -Section 'Security' -Status $(if ($w3.Status -eq 'Running') { 'OK' } else { 'Warning' }) -Check 'IIS (W3SVC)' -Value $w3.Status -Properties @{
                Check = 'IIS (W3SVC)'; Value = $w3.Status; Status = $(if ($w3.Status -eq 'Running') { 'OK' } else { 'Warning' }); Recommendation = $(if ($w3.Status -ne 'Running') { 'World Wide Web Publishing Service is not running.' } else { '' })
            }
        } catch { }
        if ($iisPresent) {
            try {
                Import-Module WebAdministration -ErrorAction Stop
                foreach ($site in @(Get-WebSite -ErrorAction Stop)) {
                    $bindings = ''
                    try {
                        $bindings = @(
                            $site.bindings.Collection | ForEach-Object { "$($_.protocol)/$($_.bindingInformation)" }
                        ) -join ', '
                    } catch { }
                    $st = if ($site.state -eq 'Started') { 'OK' } else { 'Warning' }
                    $rec = if ($st -ne 'OK') { "IIS site '$($site.name)' is $($site.state)." } else { '' }
                    Add-CheckRow -List $iisRows -Section 'IIS' -Status $st -Recommendation $rec -Check $site.name -Value $site.state -Properties @{
                        SiteName       = $site.name
                        State          = $site.state
                        PhysicalPath   = $site.physicalPath
                        Bindings       = $bindings
                        Status         = $st
                        Recommendation = $rec
                    }
                }
            } catch {
                Write-StepWarn "IIS sites: $($_.Exception.Message)"
            }
        }

        $w32Text = ''
        try { $w32Text = ((w32tm /query /status 2>&1) | Out-String).Trim() } catch { $w32Text = $_.Exception.Message }
        $offsetStatus = 'Info'
        $offsetRec = ''
        $offsetVal = Get-Truncated -Text $w32Text -Max 320
        if ($w32Text -match 'Last Successful Sync Time:\s*(.+)') {
            $syncLine = $Matches[1].Trim()
            Add-CheckRow -List $w32tmRows -Section 'Time' -Status 'Info' -Check 'Last Successful Sync' -Value $syncLine -NoScore -Properties @{
                Check = 'Last Successful Sync'; Value = $syncLine; Status = 'Info'
            }
        }
        if ($w32Text -match 'Phase Offset:\s*([+-]?[\d\.]+s)') {
            $offsetVal = $Matches[1]
            $seconds = $null
            if ($offsetVal -match '([+-]?[\d\.]+)') { $seconds = [double]$Matches[1] }
            if ($null -ne $seconds) {
                $abs = [math]::Abs($seconds)
                if ($abs -gt 5) { $offsetStatus = 'Critical'; $offsetRec = 'Clock skew exceeds 5 seconds. Kerberos and AD replication will suffer. Fix NTP.' }
                elseif ($abs -gt 1) { $offsetStatus = 'Warning'; $offsetRec = 'Clock skew exceeds 1 second. Investigate the time source.' }
                else { $offsetStatus = 'OK' }
            }
        } elseif ($w32Text -match 'The service has not been started|0x80070426') {
            $offsetStatus = 'Warning'
            $offsetRec = 'Windows Time service does not appear to be running.'
        }
        Add-CheckRow -List $w32tmRows -Section 'Time' -Status $offsetStatus -Recommendation $offsetRec -Check 'W32TM Status' -Value $offsetVal -Properties @{
            Check = 'W32TM Status'; Value = $offsetVal; Status = $offsetStatus; Recommendation = $offsetRec
        }
    }
}

#endregion

#region ── Section 9: SQL Server ──────────────────────────────────────────────

if (Test-SectionEnabled 'SQL') {
    Write-Step 'SQL Server' 'Auto-detect instances and sample counters...'
    Invoke-Section -Name 'SQL' -Percent 58 -Script {
        $regSql = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
        if (Test-Path $regSql) {
            $props = Get-ItemProperty $regSql -ErrorAction SilentlyContinue
            if ($props) {
                $script:sqlInstances = @(
                    $props.PSObject.Properties |
                        Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notmatch '^PS' } |
                        Select-Object -ExpandProperty Name
                )
            }
        }

        foreach ($inst in @($script:sqlInstances)) {
            $svcName = if ($inst -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { "MSSQL`$$inst" }
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            $svcStatus = if ($svc) { $svc.Status.ToString() } else { 'Not Found' }
            $st = if ($svcStatus -eq 'Running') { 'OK' } else { 'Critical' }
            $rec = if ($st -ne 'OK') { "SQL Server instance $inst is not running." } else { '' }
            Add-CheckRow -List $sqlInstRows -Section 'SQLServer' -Status $st -Recommendation $rec -Check "Instance $inst" -Value $svcStatus -Properties @{
                Instance = $inst; Service = $svcName; State = $svcStatus; Status = $st; Recommendation = $rec
            }

            $agentSvc = if ($inst -eq 'MSSQLSERVER') { 'SQLSERVERAGENT' } else { "SQLAgent`$$inst" }
            $agent = Get-Service -Name $agentSvc -ErrorAction SilentlyContinue
            if ($agent) {
                $agSt = if ($agent.Status -eq 'Running') { 'OK' } else { 'Warning' }
                $agRec = if ($agSt -ne 'OK') { "SQL Agent for $inst is not running. Scheduled jobs will not execute." } else { '' }
                Add-CheckRow -List $sqlInstRows -Section 'SQLServer' -Status $agSt -Recommendation $agRec -Check "Agent $inst" -Value $agent.Status -Properties @{
                    Instance = "$inst (Agent)"; Service = $agentSvc; State = $agent.Status.ToString(); Status = $agSt; Recommendation = $agRec
                }
            }
        }

        foreach ($inst in @($script:sqlInstances)) {
            $prefix = if ($inst -eq 'MSSQLSERVER') { 'SQLServer' } else { "MSSQL`$$inst" }
            $sqlPerfCounters = @(
                "\${prefix}:Buffer Manager\Buffer cache hit ratio",
                "\${prefix}:Buffer Manager\Page life expectancy",
                "\${prefix}:General Statistics\User Connections",
                "\${prefix}:SQL Statistics\Batch Requests/sec",
                "\${prefix}:SQL Statistics\SQL Compilations/sec",
                "\${prefix}:SQL Statistics\SQL Re-Compilations/sec",
                "\${prefix}:Memory Manager\Memory Grants Pending",
                "\${prefix}:Access Methods\Full Scans/sec",
                "\${prefix}:Locks(_Total)\Lock Waits/sec",
                "\${prefix}:Locks(_Total)\Average Wait Time (ms)"
            )
            $averages = Get-CounterAverages -Counters $sqlPerfCounters
            foreach ($item in $averages) {
                $status = 'OK'
                $rec    = ''
                $name   = $item.Counter
                $avg    = $item.Average
                if ($name -eq 'Buffer cache hit ratio' -and $avg -lt 90) {
                    $status = 'Warning'; $rec = 'Buffer cache hit ratio below 90%. The instance may need more memory or have a scanning workload.'
                }
                if ($name -eq 'Page life expectancy' -and $avg -lt 300) {
                    $status = 'Warning'; $rec = 'PLE below 300 seconds. Memory pressure is likely.'
                }
                if ($name -eq 'Memory Grants Pending' -and $avg -gt 0) {
                    $status = 'Warning'; $rec = 'Queries are waiting on memory grants.'
                }
                if ($name -eq 'SQL Re-Compilations/sec' -and $avg -gt 10) {
                    $status = 'Warning'; $rec = 'High recompile rate. Review ad-hoc SQL, sniffed parameters, and plan cache hygiene.'
                }
                Add-CheckRow -List $sqlCounterRows -Section 'SQLServer-Perf' -Status $status -Recommendation $rec -Check "$inst - $name" -Value (Format-Number $avg 4) -Properties @{
                    Instance       = $inst
                    Counter        = $name
                    Average        = Format-Number $avg 4
                    Status         = $status
                    Recommendation = $rec
                }
            }
        }
    }
}

#endregion

#region ── Section 10: Hardware ───────────────────────────────────────────────

if (Test-SectionEnabled 'Hardware') {
    Write-Step 'Hardware / firmware'
    Invoke-Section -Name 'Hardware' -Percent 64 -Script {
        $csArr = Get-CimOrWmi -Class Win32_ComputerSystem
        if ($csArr.Count -gt 0) {
            $cs = $csArr[0]
            foreach ($pair in @(
                @{ Item = 'Manufacturer'; Value = $cs.Manufacturer },
                @{ Item = 'Model'; Value = $cs.Model },
                @{ Item = 'Total RAM (GB)'; Value = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) },
                @{ Item = 'Domain'; Value = $cs.Domain },
                @{ Item = 'PartOfDomain'; Value = $cs.PartOfDomain }
            )) {
                $hwRows.Add([PSCustomObject]@{ Item = $pair.Item; Value = $pair.Value; Status = 'Info' })
            }
        }
        $biosArr = Get-CimOrWmi -Class Win32_BIOS
        if ($biosArr.Count -gt 0) {
            $bios = $biosArr[0]
            $release = $bios.ReleaseDate
            $releaseDt = Convert-CimTime $release
            if ($releaseDt) { $release = $releaseDt.ToString('yyyy-MM-dd') }
            $hwRows.Add([PSCustomObject]@{ Item = 'BIOS Version'; Value = $bios.SMBIOSBIOSVersion; Status = 'Info' })
            $hwRows.Add([PSCustomObject]@{ Item = 'BIOS Release'; Value = $release; Status = 'Info' })
            $hwRows.Add([PSCustomObject]@{ Item = 'Serial Number'; Value = $bios.SerialNumber; Status = 'Info' })
        }

        foreach ($d in (Get-CimOrWmi -Class Win32_DiskDrive)) {
            $physDiskRows.Add([PSCustomObject]@{
                DeviceID    = $d.DeviceID
                Model       = $d.Model
                SizeGB      = if ($d.Size) { [math]::Round($d.Size / 1GB, 2) } else { 0 }
                Interface   = $d.InterfaceType
                MediaType   = $d.MediaType
                FirmwareRev = $d.FirmwareRevision
                Partitions  = $d.Partitions
                Status      = 'Info'
            })
        }

        foreach ($n in (Get-CimOrWmi -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')) {
            $nicRows.Add([PSCustomObject]@{
                Description = $n.Description
                IPAddress   = (@($n.IPAddress) -join ', ')
                SubnetMask  = (@($n.IPSubnet) -join ', ')
                Gateway     = (@($n.DefaultIPGateway) -join ', ')
                DNS         = (@($n.DNSServerSearchOrder) -join ', ')
                DHCP        = $n.DHCPEnabled
                MACAddress  = $n.MACAddress
                Status      = 'Info'
            })
        }

        try {
            foreach ($a in @(Get-NetAdapter -Physical -ErrorAction Stop)) {
                $linkStatus = 'OK'
                $rec = ''
                if ($a.Status -ne 'Up') {
                    $linkStatus = 'Warning'
                    $rec = "Adapter '$($a.Name)' is $($a.Status)."
                }
                Add-CheckRow -List $nicLinkRows -Section 'NetworkAdapters' -Status $linkStatus -Recommendation $rec -Check $a.Name -Value "$($a.LinkSpeed) / $($a.Status)" -Properties @{
                    Name           = $a.Name
                    Interface      = $a.InterfaceDescription
                    StatusText     = $a.Status
                    LinkSpeed      = $a.LinkSpeed
                    MacAddress     = $a.MacAddress
                    Driver         = $a.DriverVersion
                    Status         = $linkStatus
                    Recommendation = $rec
                }
            }
        } catch { }
    }
}

#endregion

#region ── Section 11: Memory deep dive ───────────────────────────────────────

if (Test-SectionEnabled 'MemoryDeep') {
    Write-Step 'Memory deep dive' 'Top processes and page file...'
    Invoke-Section -Name 'MemoryDeep' -Percent 70 -Script {
        $topProcs = Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 20
        foreach ($p in $topProcs) {
            $wsMB = 0
            try { $wsMB = [math]::Round($p.WorkingSet64 / 1MB, 1) } catch { }
            $cpuSec = $null
            try { if ($null -ne $p.CPU) { $cpuSec = [math]::Round($p.CPU, 2) } } catch { }
            $status = if ($wsMB -gt 4000) { 'Warning' } else { 'OK' }
            $rec = if ($wsMB -gt 4000) { "Process '$($p.Name)' (PID $($p.Id)) is using ${wsMB} MB working set." } else { '' }
            Add-CheckRow -List $memDeepRows -Section 'MemoryProcesses' -Status $status -Recommendation $rec -Check "$($p.Name) ($($p.Id))" -Value "$wsMB MB" -NoScore:($status -eq 'OK') -Properties @{
                PID            = $p.Id
                Name           = $p.Name
                WorkingSetMB   = $wsMB
                CPU            = $cpuSec
                Threads        = $p.Threads.Count
                Handles        = $p.HandleCount
                Status         = $status
                Recommendation = $rec
            }
        }

        $pagefiles = Get-CimOrWmi -Class Win32_PageFileSetting
        if ($pagefiles.Count -eq 0) {
            $usage = Get-CimOrWmi -Class Win32_PageFileUsage
            foreach ($pf in $usage) {
                $pfRows.Add([PSCustomObject]@{
                    Name          = $pf.Name
                    InitialSizeMB = $pf.AllocatedBaseSize
                    MaxSizeMB     = $pf.AllocatedBaseSize
                    Status        = 'Info'
                })
            }
        } else {
            foreach ($pf in $pagefiles) {
                $pfRows.Add([PSCustomObject]@{
                    Name          = $pf.Name
                    InitialSizeMB = $pf.InitialSize
                    MaxSizeMB     = $pf.MaximumSize
                    Status        = 'Info'
                })
            }
        }
        if ($pfRows.Count -eq 0) {
            $pfRows.Add([PSCustomObject]@{
                Name = 'System managed or none found'
                InitialSizeMB = ''
                MaxSizeMB = ''
                Status = 'Info'
            })
        }
    }
}

#endregion

#region ── Section 12: Storage deep dive ──────────────────────────────────────

if (Test-SectionEnabled 'StorageDeep') {
    Write-Step 'Storage deep dive'
    Invoke-Section -Name 'StorageDeep' -Percent 76 -Script {
        foreach ($pt in (Get-CimOrWmi -Class Win32_DiskPartition)) {
            $storDeepRows.Add([PSCustomObject]@{
                Disk             = $pt.DiskIndex
                Partition        = $pt.Index
                Name             = $pt.Name
                Type             = $pt.Type
                SizeGB           = if ($pt.Size) { [math]::Round($pt.Size / 1GB, 2) } else { 0 }
                Bootable         = $pt.Bootable
                PrimaryPartition = $pt.PrimaryPartition
                Status           = 'Info'
            })
        }

        $shadows = Get-CimOrWmi -Class Win32_ShadowCopy
        if ($shadows.Count -gt 0) {
            foreach ($s in $shadows) {
                $when = Convert-CimTime $s.InstallDate
                $vssRows.Add([PSCustomObject]@{
                    ID          = $s.ID
                    VolumeName  = $s.VolumeName
                    InstallDate = if ($when) { $when.ToString('yyyy-MM-dd HH:mm') } else { $s.InstallDate }
                    ProviderID  = $s.ProviderID
                    Status      = 'Info'
                })
            }
        } else {
            $vssRows.Add([PSCustomObject]@{ ID = 'N/A'; VolumeName = 'No shadow copies found'; InstallDate = ''; ProviderID = ''; Status = 'Info' })
        }

        try {
            $vols = Get-Volume -ErrorAction Stop | Where-Object { $_.DriveType -eq 'Fixed' }
            foreach ($v in @($vols)) {
                $hStatus = if ($v.HealthStatus -eq 'Healthy') { 'OK' } else { 'Critical' }
                $rec = if ($hStatus -ne 'OK') { "Volume $($v.DriveLetter) health is $($v.HealthStatus)." } else { '' }
                Add-CheckRow -List $fsHealthRows -Section 'VolumeHealth' -Status $hStatus -Recommendation $rec -Check "Drive $($v.DriveLetter)" -Value $v.HealthStatus -Properties @{
                    DriveLetter    = $v.DriveLetter
                    FriendlyName   = $v.FileSystemLabel
                    FileSystem     = $v.FileSystem
                    SizeGB         = if ($v.Size) { [math]::Round($v.Size / 1GB, 2) } else { 0 }
                    FreeGB         = if ($v.SizeRemaining) { [math]::Round($v.SizeRemaining / 1GB, 2) } else { 0 }
                    HealthStatus   = $v.HealthStatus
                    Status         = $hStatus
                    Recommendation = $rec
                }
            }
        } catch {
            Write-StepWarn "Get-Volume: $($_.Exception.Message)"
        }
    }
}

#endregion

#region ── Section 13: Network deep dive ──────────────────────────────────────

if (Test-SectionEnabled 'NetworkDeep') {
    Write-Step 'Network deep dive' 'TCP states, DNS, listeners...'
    Invoke-Section -Name 'NetworkDeep' -Percent 82 -Script {
        $tcpConns = @()
        try { $tcpConns = @(Get-NetTCPConnection -ErrorAction Stop) } catch { Write-StepWarn "TCP connections: $($_.Exception.Message)" }
        if ($tcpConns.Count -gt 0) {
            $tcpStats = $tcpConns | Group-Object State | Sort-Object Count -Descending
            foreach ($t in $tcpStats) {
                $status = 'OK'
                $rec = ''
                if ($t.Name -eq 'TimeWait' -and $t.Count -gt 500) {
                    $status = 'Warning'
                    $rec = 'High TIME_WAIT count. Possible port exhaustion or a chatty client that is not pooling connections.'
                }
                if ($t.Name -eq 'SynSent' -and $t.Count -gt 50) {
                    $status = 'Warning'
                    $rec = 'Many SYN_SENT sockets. Outbound connections may be failing or hanging.'
                }
                Add-CheckRow -List $netDeepRows -Section 'TCPConnections' -Status $status -Recommendation $rec -Check $t.Name -Value $t.Count -Properties @{
                    State = $t.Name; Count = $t.Count; Status = $status; Recommendation = $rec
                }
            }

            $procMap = @{}
            foreach ($p in Get-Process -ErrorAction SilentlyContinue) { $procMap[$p.Id] = $p.Name }
            $listening = $tcpConns | Where-Object { $_.State -eq 'Listen' } | Sort-Object LocalPort
            $seenListen = @{}
            foreach ($l in $listening) {
                $key = "$($l.LocalAddress):$($l.LocalPort):$($l.OwningProcess)"
                if ($seenListen.ContainsKey($key)) { continue }
                $seenListen[$key] = $true
                $procName = 'Unknown'
                if ($procMap.ContainsKey([int]$l.OwningProcess)) { $procName = $procMap[[int]$l.OwningProcess] }
                $listenRows.Add([PSCustomObject]@{
                    LocalAddress = $l.LocalAddress
                    LocalPort    = $l.LocalPort
                    PID          = $l.OwningProcess
                    ProcessName  = $procName
                    Status       = 'Info'
                })
            }
        }

        $dnsOk = $false
        try {
            $dnsTest = @(Resolve-DnsName -Name $hostname -ErrorAction Stop)
            foreach ($d in $dnsTest) {
                $dnsOk = $true
                $dnsRows.Add([PSCustomObject]@{
                    Name      = $d.Name
                    Type      = $d.Type
                    IPAddress = $d.IPAddress
                    TTL       = $d.TTL
                    Status    = 'OK'
                })
            }
        } catch { }
        if (-not $dnsOk) {
            Add-CheckRow -List $dnsRows -Section 'DNS' -Status 'Warning' -Recommendation 'This server could not resolve its own hostname. Check the primary DNS suffix and DNS servers.' -Check 'Self-Resolution' -Value 'Failed' -Properties @{
                Name = $hostname; Type = 'N/A'; IPAddress = 'Resolution failed'; TTL = 0; Status = 'Warning'; Recommendation = 'This server could not resolve its own hostname. Check the primary DNS suffix and DNS servers.'
            }
        } else {
            foreach ($d in $dnsRows) {
                Register-Status -Status 'OK' -Section 'DNS' -Check $d.Name -Value $d.IPAddress
            }
        }
    }
}

#endregion

#region ── Section 14: AD / Kerberos / BPA ────────────────────────────────────

if (Test-SectionEnabled 'AD') {
    Write-Step 'Active Directory, Kerberos, BPA'
    Invoke-Section -Name 'AD' -Percent 88 -Script {
        $htmlOut = New-Object System.Text.StringBuilder
        $adRows  = New-RowList
        $kerbRows = New-RowList
        $bpaRows = New-RowList

        $adModule = Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue
        if ($adModule) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue

            $dcdiagText = ''
            try { $dcdiagText = ((dcdiag /test:replications /test:netlogons /test:services /test:fsmocheck 2>&1) | Out-String) } catch { }
            $dcHits = 0
            foreach ($line in ($dcdiagText -split "`r?`n")) {
                $trim = $line.Trim()
                if ($trim -match 'passed test|failed test|warning') {
                    $dcHits++
                    $status = if ($trim -match 'failed test') { 'Critical' } elseif ($trim -match 'warning') { 'Warning' } else { 'OK' }
                    $rec = if ($status -ne 'OK') { 'Review DCDiag output and remediate the failing test.' } else { '' }
                    Add-CheckRow -List $adRows -Section 'AD-DCDiag' -Status $status -Recommendation $rec -Check 'DCDiag' -Value (Get-Truncated $trim 200) -Properties @{
                        Check = 'DCDiag'; Value = (Get-Truncated $trim 200); Status = $status; Recommendation = $rec
                    }
                }
            }
            if ($dcHits -eq 0 -and $dcdiagText) {
                $adRows.Add([PSCustomObject]@{
                    Check = 'DCDiag'; Value = 'DCDiag ran but no pass/fail lines were parsed. The host may not be a domain controller.'; Status = 'Info'; Recommendation = ''
                })
            }

            try {
                $replText = ((repadmin /replsummary 2>&1) | Out-String)
                foreach ($line in ($replText -split "`r?`n")) {
                    $trim = $line.Trim()
                    if ($trim -and $trim -match '(?i)\berror\b|\bfail') {
                        Add-CheckRow -List $adRows -Section 'AD-Replication' -Status 'Critical' -Recommendation 'AD replication errors detected. Run repadmin /showrepl for details.' -Check 'Replication' -Value (Get-Truncated $trim 200) -Properties @{
                            Check = 'Replication'; Value = (Get-Truncated $trim 200); Status = 'Critical'; Recommendation = 'AD replication errors detected. Run repadmin /showrepl for details.'
                        }
                    }
                }
            } catch { }

            try {
                $domain = Get-ADDomain -ErrorAction Stop
                $forest = Get-ADForest -ErrorAction Stop
                $fsmoRoles = @{
                    'PDC Emulator'          = $domain.PDCEmulator
                    'RID Master'            = $domain.RIDMaster
                    'Infrastructure Master' = $domain.InfrastructureMaster
                    'Schema Master'         = $forest.SchemaMaster
                    'Domain Naming Master'  = $forest.DomainNamingMaster
                }
                foreach ($role in $fsmoRoles.GetEnumerator()) {
                    $adRows.Add([PSCustomObject]@{
                        Check = "FSMO: $($role.Key)"; Value = $role.Value; Status = 'Info'; Recommendation = ''
                    })
                }
                $adRows.Add([PSCustomObject]@{ Check = 'Domain Functional Level'; Value = $domain.DomainMode; Status = 'Info'; Recommendation = '' })
                $adRows.Add([PSCustomObject]@{ Check = 'Forest Functional Level'; Value = $forest.ForestMode; Status = 'Info'; Recommendation = '' })
            } catch { }

            try {
                foreach ($dc in @(Get-ADDomainController -Filter * -ErrorAction Stop)) {
                    $roles = @($dc.OperationMasterRoles) -join ', '
                    $adRows.Add([PSCustomObject]@{
                        Check = 'Domain Controller'
                        Value = "$($dc.HostName) | Site: $($dc.Site) | OS: $($dc.OperatingSystem) | FSMO: $roles"
                        Status = 'Info'
                        Recommendation = ''
                    })
                }
            } catch { }
        } else {
            $adRows.Add([PSCustomObject]@{
                Check = 'AD Module'
                Value = 'ActiveDirectory module not installed. Skipping DC/FSMO checks.'
                Status = 'Info'
                Recommendation = 'Install RSAT AD tools for full AD analysis.'
            })
        }

        [void]$htmlOut.AppendLine((New-SubTitle 'Active Directory Health'))
        [void]$htmlOut.AppendLine((Get-HtmlTable -SectionName 'AD' -Rows $adRows -Headers @('Check', 'Value', 'Status', 'Recommendation')))

        $klistText = ''
        try { $klistText = ((klist tickets 2>&1) | Out-String) } catch { $klistText = $_.Exception.Message }
        if ($klistText -match '(?i)cached tickets' -and $klistText -notmatch '(?i)no tickets') {
            $kerbRows.Add([PSCustomObject]@{ Check = 'Kerberos Tickets'; Value = 'Tickets present in the current session.'; Status = 'OK'; Recommendation = '' })
            Register-Status -Status 'OK' -Section 'Kerberos' -Check 'Kerberos Tickets' -Value 'Present'
        } else {
            $kerbRows.Add([PSCustomObject]@{ Check = 'Kerberos Tickets'; Value = 'No Kerberos tickets found in the current session.'; Status = 'Info'; Recommendation = '' })
        }

        try {
            $kerbEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Security-Kerberos'; Level = 2, 3 } -MaxEvents 20 -ErrorAction Stop)
            foreach ($ke in $kerbEvents) {
                $kst = if ($ke.LevelDisplayName -eq 'Error' -or $ke.LevelDisplayName -eq 'Critical') { 'Critical' } else { 'Warning' }
                $msg = Get-Truncated -Text $ke.Message -Max 200
                Add-CheckRow -List $kerbRows -Section 'Kerberos' -Status $kst -Recommendation 'Investigate Kerberos errors. Check time sync, SPNs, and KDC availability.' -Check "Kerberos EventID $($ke.Id)" -Value $msg -Properties @{
                    Check = "Kerberos EventID $($ke.Id)"; Value = $msg; Status = $kst; Recommendation = 'Investigate Kerberos errors. Check time sync, SPNs, and KDC availability.'
                }
            }
        } catch {
            $kerbRows.Add([PSCustomObject]@{ Check = 'Kerberos Events'; Value = 'No Kerberos errors/warnings retrieved from the System log.'; Status = 'OK'; Recommendation = '' })
            Register-Status -Status 'OK' -Section 'Kerberos' -Check 'Kerberos Events' -Value 'None'
        }

        [void]$htmlOut.AppendLine((New-SubTitle 'Kerberos'))
        [void]$htmlOut.AppendLine((Get-HtmlTable -SectionName 'Kerberos' -Rows $kerbRows -Headers @('Check', 'Value', 'Status', 'Recommendation')))

        [void]$htmlOut.AppendLine((New-SubTitle 'Windows Best Practices Analyzer'))
        if ($SkipBpa) {
            [void]$htmlOut.AppendLine('<p class="no-data">BPA skipped (-SkipBpa). BPA is optional because some models hang on EngineReport.xml generation.</p>')
        } else {
            $bpaModels = $null
            try { $bpaModels = @(Get-BpaModel -ErrorAction Stop) } catch { }
            if ($bpaModels) {
                foreach ($model in $bpaModels) {
                    $job = $null
                    try {
                        $job = Start-Job -ScriptBlock {
                            param($modelId)
                            Invoke-BpaModel -ModelId $modelId -ErrorAction Stop 2>&1
                        } -ArgumentList $model.Id
                        $completed = Wait-Job -Job $job -Timeout $BpaTimeoutSeconds
                        if (-not $completed) {
                            Stop-Job -Job $job -ErrorAction SilentlyContinue
                            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                            $bpaRows.Add([PSCustomObject]@{
                                Model = $model.Name; Title = 'Timed out'; Problem = "BPA model $($model.Id) exceeded $BpaTimeoutSeconds seconds."; Resolution = 'Re-run this model manually or increase -BpaTimeoutSeconds.'; Status = 'Info'
                            })
                            continue
                        }
                        $jobOut = Receive-Job -Job $job 2>&1 | Out-String
                        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                        if ($jobOut -match 'EngineReport\.xml|Result\.xml') { continue }

                        $bpaResults = Get-BpaResult -ModelId $model.Id -ErrorAction Stop |
                            Where-Object { $_.Severity -ne 'Information' -and $null -ne $_.Problem }
                        foreach ($r in @($bpaResults)) {
                            $bpaStatus = switch ($r.Severity) {
                                'Error'   { 'Critical' }
                                'Warning' { 'Warning' }
                                default   { 'Info' }
                            }
                            Add-CheckRow -List $bpaRows -Section "BPA - $($model.Name)" -Status $bpaStatus -Recommendation $r.Resolution -Check $r.Title -Value $r.Problem -Properties @{
                                Model      = $model.Name
                                Title      = $r.Title
                                Problem    = $r.Problem
                                Resolution = $r.Resolution
                                Status     = $bpaStatus
                            }
                        }
                    } catch {
                        if ($job) { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
                    }
                }
            }
            if ($bpaRows.Count -gt 0) {
                [void]$htmlOut.AppendLine((Get-HtmlTable -SectionName 'BPA' -Rows $bpaRows -Headers @('Model', 'Title', 'Problem', 'Resolution', 'Status')))
            } else {
                [void]$htmlOut.AppendLine('<p class="no-data">No BPA models found, or all models passed without warnings/errors.</p>')
            }
        }

        $script:adKerbBpaHtml = $htmlOut.ToString()
        $script:adWorst = Get-WorstStatus (@($adRows) + @($kerbRows) + @($bpaRows))
        $script:adCheckCount = $adRows.Count + $kerbRows.Count + $bpaRows.Count
    }
}

#endregion

#region ── Section 15: Hyper-V ────────────────────────────────────────────────

if (Test-SectionEnabled 'HyperV') {
    Write-Step 'Hyper-V'
    Invoke-Section -Name 'HyperV' -Percent 94 -Script {
        $hvInstalled = $false
        try {
            $vmms = Get-Service -Name vmms -ErrorAction Stop
            $hvInstalled = $true
            if ($vmms.Status -ne 'Running') {
                Add-CheckRow -List $hvRows -Section 'HyperV' -Status 'Warning' -Recommendation 'Hyper-V Virtual Machine Management service is not running.' -Check 'vmms' -Value $vmms.Status -Properties @{
                    Name = 'vmms'; State = $vmms.Status; CPUs = ''; AssignedMemGB = ''; Uptime = ''; Generation = ''; Version = ''; Status = 'Warning'; Recommendation = 'Hyper-V Virtual Machine Management service is not running.'
                }
            }
        } catch { }

        if ($hvInstalled) {
            try {
                foreach ($vm in @(Get-VM -ErrorAction Stop)) {
                    $stateName = [string]$vm.State
                    $vmStatus = 'Info'
                    $rec = ''
                    switch ($stateName) {
                        'Running' { $vmStatus = 'OK' }
                        'Off'     { $vmStatus = 'Info'; $rec = "VM '$($vm.Name)' is off (not treated as a fault)." }
                        'Paused'  { $vmStatus = 'Warning'; $rec = "VM '$($vm.Name)' is paused." }
                        'Saved'   { $vmStatus = 'Warning'; $rec = "VM '$($vm.Name)' is saved. Resume it if it should be online." }
                        default   { $vmStatus = 'Warning'; $rec = "VM '$($vm.Name)' is $stateName." }
                    }
                    $memGB = $null
                    try { $memGB = [math]::Round($vm.MemoryAssigned / 1GB, 2) } catch { }
                    Add-CheckRow -List $hvRows -Section 'HyperV' -Status $vmStatus -Recommendation $rec -Check $vm.Name -Value $stateName -Properties @{
                        Name           = $vm.Name
                        State          = $stateName
                        CPUs           = $vm.ProcessorCount
                        AssignedMemGB  = $memGB
                        Uptime         = $vm.Uptime
                        Generation     = $vm.Generation
                        Version        = $vm.Version
                        Status         = $vmStatus
                        Recommendation = $rec
                    }
                }
            } catch {
                $hvRows.Add([PSCustomObject]@{
                    Name = 'Error'; State = $_.Exception.Message; CPUs = ''; AssignedMemGB = ''; Uptime = ''; Generation = ''; Version = ''; Status = 'Info'; Recommendation = ''
                })
            }
        } else {
            $hvRows.Add([PSCustomObject]@{
                Name = 'N/A'; State = 'Hyper-V not installed'; CPUs = ''; AssignedMemGB = ''; Uptime = ''; Generation = ''; Version = ''; Status = 'Info'; Recommendation = ''
            })
        }
    }
}

#endregion

#region ── Section 16: Certificates ───────────────────────────────────────────

if (Test-SectionEnabled 'Certificates') {
    Write-Step 'Certificates' 'Personal / WebHosting stores (Root/CA optional)...'
    Invoke-Section -Name 'Certificates' -Percent 97 -Script {
        $stores = New-Object 'System.Collections.Generic.List[string]'
        [void]$stores.Add('LocalMachine\My')
        if (Test-Path 'Cert:\LocalMachine\WebHosting') { [void]$stores.Add('LocalMachine\WebHosting') }
        if ($IncludeRootCertificates) {
            [void]$stores.Add('LocalMachine\Root')
            [void]$stores.Add('LocalMachine\CA')
        }
        $today = Get-Date
        foreach ($store in $stores) {
            $parts = $store -split '\\', 2
            $certs = @()
            try { $certs = @(Get-ChildItem "Cert:\$store" -ErrorAction Stop) } catch { continue }
            foreach ($cert in $certs) {
                $daysLeft = ([datetime]$cert.NotAfter - $today).Days
                $expStatus = if ($daysLeft -lt 0) { 'Critical' } elseif ($daysLeft -lt 30) { 'Critical' } elseif ($daysLeft -lt 90) { 'Warning' } else { 'OK' }
                $rec = ''
                if ($daysLeft -lt 0) { $rec = "Certificate expired on $($cert.NotAfter.ToString('yyyy-MM-dd')). Replace it." }
                elseif ($expStatus -ne 'OK') { $rec = "Renew before $($cert.NotAfter.ToString('yyyy-MM-dd')) ($daysLeft days remaining)." }
                $subject = $cert.Subject
                if ([string]::IsNullOrWhiteSpace($subject)) { $subject = $cert.Thumbprint }
                Add-CheckRow -List $certRows -Section 'Certificates' -Status $expStatus -Recommendation $rec -Check $subject -Value "Expires $($cert.NotAfter.ToString('yyyy-MM-dd')) ($daysLeft d)" -Properties @{
                    Store          = $store
                    Subject        = $subject
                    Thumbprint     = $cert.Thumbprint
                    NotAfter       = $cert.NotAfter.ToString('yyyy-MM-dd')
                    DaysRemaining  = $daysLeft
                    Issuer         = $cert.Issuer
                    Status         = $expStatus
                    Recommendation = $rec
                }
            }
        }
        if ($certRows.Count -eq 0) {
            $certRows.Add([PSCustomObject]@{
                Store = 'LocalMachine\My'; Subject = 'No certificates found'; Thumbprint = ''; NotAfter = ''; DaysRemaining = ''; Issuer = ''; Status = 'Info'; Recommendation = ''
            })
        }
    }
}

#endregion

Write-Progress -Activity "System Analysis ($hostname)" -Status 'Building HTML report' -PercentComplete 99

#region ── Summary ────────────────────────────────────────────────────────────

$totalCritical = @($script:statuses | Where-Object { $_ -eq 'Critical' }).Count
$totalWarning  = @($script:statuses | Where-Object { $_ -eq 'Warning' }).Count
$totalOK       = @($script:statuses | Where-Object { $_ -eq 'OK' }).Count
$overallStatus = if ($totalCritical -gt 0) { 'Critical' } elseif ($totalWarning -gt 0) { 'Warning' } else { 'OK' }
$healthScore   = [math]::Max(0, [math]::Min(100, 100 - ($totalCritical * 12) - ($totalWarning * 4)))
$uptimeStr = ''
if ($osInfo) {
    $boot2 = Convert-CimTime $osInfo.LastBootUpTime
    if ($boot2) {
        $uptime2 = (Get-Date) - $boot2
        $uptimeStr = "{0}d {1}h {2}m" -f [int]$uptime2.TotalDays, $uptime2.Hours, $uptime2.Minutes
    }
}
$runtimeSec = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
$genTime    = Get-TimeStamp
$scoreBarColor = if ($totalCritical -gt 0) { '#fb7185' } elseif ($totalWarning -gt 0) { '#fbbf24' } else { '#34d399' }

$osCaption = ''
if ($osInfo) { $osCaption = [string]$osInfo.Caption }

#endregion
#region ── HTML report ────────────────────────────────────────────────────────

$sb = New-Object System.Text.StringBuilder

[void]$sb.AppendLine(@'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="color-scheme" content="dark light"/>
<title>System Analysis Report</title>
<style>
:root{
  --bg:#070b14;--bg-2:#0c1220;--sidebar:#0a101c;--card:#121a2b;--card-2:#182234;
  --border:rgba(148,163,184,.14);--glow:rgba(45,212,191,.16);
  --accent:#2dd4bf;--accent-2:#38bdf8;--accent-hover:#5eead4;--accent-dim:rgba(45,212,191,.14);
  --ok:#34d399;--ok-bg:rgba(52,211,153,.14);
  --warn:#fbbf24;--warn-bg:rgba(251,191,36,.14);
  --crit:#fb7185;--crit-bg:rgba(251,113,133,.14);
  --info:#7b8ba3;--info-bg:rgba(123,139,163,.12);
  --text:#e8eef7;--muted:#8b9cb3;--muted2:#a8b6c8;
  --font:"Segoe UI",system-ui,-apple-system,sans-serif;
  --mono:"Cascadia Code","Consolas",ui-monospace,monospace;
  --radius:12px;--sidebar-w:280px;--shadow:0 18px 50px rgba(0,0,0,.35);
  --topbar-h:64px;
}
html[data-theme="light"]{
  --bg:#eef2f6;--bg-2:#e6ebf2;--sidebar:#ffffff;--card:#ffffff;--card-2:#f5f7fb;
  --border:rgba(15,23,42,.1);--glow:rgba(15,118,110,.08);
  --accent:#0f766e;--accent-2:#0369a1;--accent-hover:#0d9488;--accent-dim:rgba(15,118,110,.1);
  --ok:#047857;--ok-bg:rgba(4,120,87,.1);
  --warn:#b45309;--warn-bg:rgba(180,83,9,.1);
  --crit:#be123c;--crit-bg:rgba(190,18,60,.1);
  --info:#64748b;--info-bg:rgba(100,116,139,.1);
  --text:#0f172a;--muted:#64748b;--muted2:#475569;
  --shadow:0 12px 32px rgba(15,23,42,.08);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{min-height:100%}
body{
  font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;
  display:flex;line-height:1.45;
  background-image:
    radial-gradient(1200px 500px at 90% -10%, var(--glow), transparent 55%),
    linear-gradient(180deg, var(--bg) 0%, var(--bg-2) 100%);
}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.skip-link{
  position:absolute;left:-999px;top:8px;background:var(--accent);color:#042f2e;
  padding:8px 12px;border-radius:8px;z-index:400;font-weight:700;
}
.skip-link:focus{left:12px}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0}

#sidebar{
  width:var(--sidebar-w);flex-shrink:0;background:var(--sidebar);
  border-right:1px solid var(--border);position:fixed;top:0;left:0;
  height:100vh;overflow-y:auto;display:flex;flex-direction:column;z-index:100;
  transition:transform .25s ease;
}
#sidebar::-webkit-scrollbar{width:6px}
#sidebar::-webkit-scrollbar-thumb{background:var(--border);border-radius:8px}
.sidebar-header{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.sidebar-logo{display:flex;align-items:center;gap:12px}
.sidebar-title{font-size:14px;font-weight:750;letter-spacing:.01em}
.sidebar-sub{font-size:11px;color:var(--muted);margin-top:2px;font-family:var(--mono)}
.sidebar-score{margin:16px 16px 8px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center}
.score-ring-wrap{position:relative;width:118px;height:118px;margin:0 auto 10px}
.score-ring-wrap svg{transform:rotate(-90deg)}
.score-ring-bg{fill:none;stroke:var(--border);stroke-width:3.2}
.score-ring-fg{fill:none;stroke-width:3.2;stroke-linecap:round;transition:stroke-dasharray .8s ease}
.score-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.score-num{font-size:28px;font-weight:800;letter-spacing:-.04em;line-height:1}
.score-lbl{font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);margin-top:4px}
.score-counts{display:flex;justify-content:center;gap:12px;font-size:11px;color:var(--muted2)}
.score-counts span{display:flex;align-items:center;gap:5px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.dot-crit{background:var(--crit)} .dot-warn{background:var(--warn)} .dot-ok{background:var(--ok)}
.sidebar-nav{padding:8px 10px 18px;flex:1}
.nav-item{
  display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:8px;
  cursor:pointer;font-size:12.5px;color:var(--muted2);margin-bottom:2px;
  transition:background .15s,color .15s;border:0;background:none;width:100%;text-align:left;
}
.nav-item:hover{background:var(--card);color:var(--text)}
.nav-item.active{background:var(--accent-dim);color:var(--accent)}
.nav-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.nav-num{font-size:10px;color:var(--muted);margin-left:auto;font-variant-numeric:tabular-nums}
.sidebar-foot{padding:12px 16px 18px;border-top:1px solid var(--border);display:flex;gap:8px}
.sidebar-toggle{
  display:none;position:fixed;top:14px;left:14px;z-index:200;
  background:var(--card);border:1px solid var(--border);border-radius:8px;
  padding:7px 10px;cursor:pointer;color:var(--text);font-size:18px;line-height:1;
}
.sidebar-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:90}
.sidebar-backdrop.show{display:block}

#main{margin-left:var(--sidebar-w);flex:1;min-width:0;display:flex;flex-direction:column}
#topbar{
  position:sticky;top:0;z-index:80;min-height:var(--topbar-h);
  background:var(--bg);
  background:color-mix(in srgb, var(--bg) 84%, transparent);
  backdrop-filter:blur(14px);border-bottom:1px solid var(--border);
  padding:12px 28px;display:flex;align-items:center;gap:14px;flex-wrap:wrap;
}
.topbar-title{font-size:16px;font-weight:750;flex:1;min-width:180px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.topbar-meta{font-size:11px;color:var(--muted);width:100%;order:5}
.topbar-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.btn{
  padding:7px 12px;border-radius:8px;border:1px solid var(--border);
  background:var(--card-2);color:var(--text);font-size:12px;cursor:pointer;
  transition:background .15s,border-color .15s,transform .1s;white-space:nowrap;
}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn-primary{background:var(--accent);border-color:var(--accent);color:#042f2e;font-weight:700}
.btn-primary:hover{background:var(--accent-hover);color:#042f2e}
#search-global{
  background:var(--card-2);border:1px solid var(--border);border-radius:8px;
  color:var(--text);padding:7px 12px;font-size:12px;width:220px;
}
#search-global:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim)}
.content{padding:24px 28px 48px}

.summary-strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
.stat-card{
  background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
  padding:16px 16px 14px;display:flex;flex-direction:column;gap:6px;box-shadow:var(--shadow);
}
.stat-card .sc-label{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}
.stat-card .sc-value{font-size:26px;font-weight:800;letter-spacing:-.03em;line-height:1;font-variant-numeric:tabular-nums}
.stat-card .sc-sub{font-size:11px;color:var(--muted2)}
.stat-crit .sc-value{color:var(--crit)} .stat-warn .sc-value{color:var(--warn)}
.stat-ok .sc-value{color:var(--ok)} .stat-info .sc-value{color:var(--muted2)}

.alert-banner{
  display:flex;align-items:center;gap:12px;padding:12px 16px;border-radius:var(--radius);
  margin-bottom:18px;font-size:13px;border:1px solid var(--border);border-left:4px solid;
}
.alert-crit{background:var(--crit-bg);border-left-color:var(--crit)}
.alert-warn{background:var(--warn-bg);border-left-color:var(--warn)}
.alert-ok{background:var(--ok-bg);border-left-color:var(--ok)}
.alert-icon{font-size:18px}
.alert-text{flex:1}
.alert-text strong{color:inherit}

.attention-panel{
  background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
  margin-bottom:18px;overflow:hidden;box-shadow:var(--shadow);
}
.attention-head{
  display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--border);
}
.attention-head h2{font-size:14px;font-weight:750;flex:1}
.attention-head .count{font-size:11px;color:var(--muted)}
.attention-body{padding:12px 16px 16px}

.section-panel{
  background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
  margin-bottom:12px;overflow:hidden;
}
.section-header{
  display:flex;align-items:center;gap:10px;padding:13px 16px;cursor:pointer;user-select:none;
}
.section-header:hover{background:var(--card-2)}
.section-chevron{color:var(--muted);font-size:11px;transition:transform .2s;width:16px;text-align:center}
.section-panel.open .section-chevron{transform:rotate(90deg)}
.section-title{font-size:13px;font-weight:700;flex:1}
.section-badge{font-size:10px;font-weight:700;padding:3px 8px;border-radius:999px;text-transform:uppercase;letter-spacing:.04em}
.badge-crit{background:var(--crit-bg);color:var(--crit)} .badge-warn{background:var(--warn-bg);color:var(--warn)}
.badge-ok{background:var(--ok-bg);color:var(--ok)} .badge-info{background:var(--info-bg);color:var(--muted2)}
.section-count{font-size:11px;color:var(--muted)}
.section-body{padding:0 16px 16px;display:none}
.section-panel.open .section-body{display:block}
.subsection-title{
  font-size:11px;font-weight:750;color:var(--muted2);text-transform:uppercase;
  letter-spacing:.08em;padding:16px 0 8px;border-bottom:1px solid var(--border);margin-bottom:10px;
}
.table-controls{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:10px 0}
.filter-pills{display:flex;gap:4px;flex-wrap:wrap}
.pill{
  padding:4px 10px;border-radius:999px;font-size:11px;font-weight:650;cursor:pointer;
  border:1px solid var(--border);background:transparent;color:var(--muted2);
}
.pill:hover,.pill.active{color:#fff;border-color:transparent}
.pill-all.active{background:var(--accent);color:#042f2e}
.pill-crit.active{background:var(--crit)} .pill-warn.active{background:var(--warn);color:#1c1403}
.pill-ok.active{background:var(--ok);color:#042f2e} .pill-info.active{background:var(--info)}
.tbl-search{
  background:var(--card-2);border:1px solid var(--border);border-radius:8px;color:var(--text);
  padding:5px 8px;font-size:11px;margin-left:auto;width:170px;
}
.tbl-count{font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums}
.table-wrapper{overflow-x:auto;border-radius:10px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
thead tr{background:var(--card-2)}
th{
  padding:9px 10px;text-align:left;border-bottom:1px solid var(--border);font-weight:700;
  white-space:nowrap;color:var(--muted2);font-size:11px;text-transform:uppercase;letter-spacing:.04em;
  cursor:pointer;user-select:none;
}
th:hover{color:var(--text)}
th .sort-icon{margin-left:4px;opacity:.35;font-size:9px}
th.sort-asc .sort-icon,th.sort-desc .sort-icon{opacity:1;color:var(--accent)}
th.sort-desc .sort-icon{transform:scaleY(-1);display:inline-block}
td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top;color:var(--muted2)}
td:first-child{color:var(--text);font-weight:600}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:var(--accent-dim)}
.row-crit td{background:var(--crit-bg)}
.row-warn td{background:var(--warn-bg)}
.status-pill{display:inline-flex;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:750;text-transform:uppercase;letter-spacing:.03em}
.sp-crit{background:var(--crit-bg);color:var(--crit)} .sp-warn{background:var(--warn-bg);color:var(--warn)}
.sp-ok{background:var(--ok-bg);color:var(--ok)} .sp-info{background:var(--info-bg);color:var(--muted2)}
tr.hidden-row{display:none}
.no-data{color:var(--muted);font-style:italic;padding:12px 0;font-size:13px}
.rec-cell{font-size:12px;max-width:340px}
.meter{height:7px;background:var(--border);border-radius:99px;overflow:hidden;width:88px;display:inline-block;vertical-align:middle;margin-right:8px}
.meter-fill{display:block;height:100%;border-radius:99px}
.meter-label{font-variant-numeric:tabular-nums}
footer{text-align:center;padding:18px;font-size:11px;color:var(--muted);border-top:1px solid var(--border)}
.back-top{
  position:fixed;right:22px;bottom:22px;z-index:70;display:none;
  background:var(--accent);color:#042f2e;border:0;border-radius:999px;padding:10px 14px;
  font-size:12px;font-weight:750;cursor:pointer;box-shadow:var(--shadow);
}
.back-top.show{display:block}
.kbd{font-family:var(--mono);font-size:10px;border:1px solid var(--border);padding:1px 5px;border-radius:4px;color:var(--muted)}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:8px}

@media(max-width:960px){
  #sidebar{transform:translateX(-100%)}
  #sidebar.mob-open{transform:translateX(0)}
  #main{margin-left:0}
  #topbar{padding:12px 16px 12px 56px}
  .sidebar-toggle{display:block}
  .content{padding:16px 14px 40px}
  #search-global{width:140px}
}
@media(prefers-reduced-motion:reduce){
  *{transition:none!important;scroll-behavior:auto!important}
}
@media print{
  #sidebar,.sidebar-toggle,#topbar,.table-controls,.back-top,.sidebar-backdrop{display:none!important}
  #main{margin-left:0}
  .section-body{display:block!important}
  .section-panel{break-inside:avoid;box-shadow:none}
  body{background:#fff;color:#111}
  .stat-card,.section-panel,.attention-panel{border-color:#d0d5dd}
}
</style>
</head>
<body>
<a class="skip-link" href="#content">Skip to report</a>
<button class="sidebar-toggle" id="mob-toggle" type="button" aria-label="Open section menu">&#9776;</button>
<div class="sidebar-backdrop" id="sidebar-backdrop"></div>
'@)

# Sidebar
$navDefs = @(
    @{ T = 'CPU Analysis';        I = 'CPU-Analysis';        W = (Get-WorstStatus $cpuRows) }
    @{ T = 'Memory Analysis';     I = 'Memory-Analysis';     W = (Get-WorstStatus $memRows) }
    @{ T = 'Disk Analysis';       I = 'Disk-Analysis';       W = (Get-WorstStatus (@($diskRows) + @($volRows))) }
    @{ T = 'Network Analysis';    I = 'Network-Analysis';    W = (Get-WorstStatus $netRows) }
    @{ T = 'Software & Services'; I = 'Software-Services';   W = (Get-WorstStatus (@($svcRows) + @($taskRows))) }
    @{ T = 'Event Logs';          I = 'Event-Logs';          W = (Get-WorstStatus $eventRows) }
    @{ T = 'Windows Health';      I = 'Windows-Health';      W = (Get-WorstStatus $winHealthRows) }
    @{ T = 'Security & IIS';      I = 'Security-IIS';        W = (Get-WorstStatus (@($secRows) + @($iisRows) + @($w32tmRows))) }
    @{ T = 'SQL Server';          I = 'SQL-Server';          W = (Get-WorstStatus (@($sqlInstRows) + @($sqlCounterRows))) }
    @{ T = 'Hardware';            I = 'Hardware';            W = (Get-WorstStatus (@($hwRows) + @($nicLinkRows))) }
    @{ T = 'Memory Deep Dive';    I = 'Memory-Deep-Dive';    W = (Get-WorstStatus $memDeepRows) }
    @{ T = 'Storage Deep Dive';   I = 'Storage-Deep-Dive';   W = (Get-WorstStatus $fsHealthRows) }
    @{ T = 'Network Deep Dive';   I = 'Network-Deep-Dive';   W = (Get-WorstStatus (@($netDeepRows) + @($dnsRows))) }
    @{ T = 'AD / Kerberos / BPA'; I = 'AD-Kerberos-BPA';     W = $adWorst }
    @{ T = 'Hyper-V';             I = 'Hyper-V';             W = (Get-WorstStatus $hvRows) }
    @{ T = 'Certificates';        I = 'Certificates';        W = (Get-WorstStatus $certRows) }
)

[void]$sb.AppendLine('<nav id="sidebar" aria-label="Report sections">')
[void]$sb.AppendLine('<div class="sidebar-header"><div class="sidebar-logo">')
[void]$sb.AppendLine('<svg width="32" height="32" viewBox="0 0 32 32" fill="none" aria-hidden="true"><rect width="32" height="32" rx="8" fill="#2dd4bf"/><path d="M8 20.5V11.5L16 8l8 3.5v9L16 24l-8-3.5z" stroke="#042f2e" stroke-width="1.6" fill="none"/><path d="M16 12v8M12.5 14.2l7 3.6" stroke="#042f2e" stroke-width="1.6" stroke-linecap="round"/></svg>')
[void]$sb.AppendLine("<div><div class=`"sidebar-title`">System Analysis</div><div class=`"sidebar-sub`">$(ConvertTo-HtmlEncoded $hostname)</div></div>")
[void]$sb.AppendLine('</div></div>')

[void]$sb.AppendLine('<div class="sidebar-score">')
[void]$sb.AppendLine('<div class="score-ring-wrap">')
[void]$sb.AppendLine("<svg viewBox=`"0 0 36 36`" role=`"img`" aria-label=`"Health score $healthScore out of 100`">")
[void]$sb.AppendLine('<path class="score-ring-bg" d="M18 2.2 a 15.8 15.8 0 1 1 0 31.6 a 15.8 15.8 0 1 1 0 -31.6"/>')
[void]$sb.AppendLine("<path class=`"score-ring-fg`" stroke=`"$scoreBarColor`" stroke-dasharray=`"$healthScore, 100`" d=`"M18 2.2 a 15.8 15.8 0 1 1 0 31.6 a 15.8 15.8 0 1 1 0 -31.6`"/>")
[void]$sb.AppendLine('</svg>')
[void]$sb.AppendLine("<div class=`"score-center`"><div class=`"score-num`" style=`"color:$scoreBarColor`">$healthScore</div><div class=`"score-lbl`">Score</div></div>")
[void]$sb.AppendLine('</div>')
[void]$sb.AppendLine('<div class="score-counts">')
[void]$sb.AppendLine("<span><span class=`"dot dot-crit`"></span>$totalCritical Crit</span>")
[void]$sb.AppendLine("<span><span class=`"dot dot-warn`"></span>$totalWarning Warn</span>")
[void]$sb.AppendLine("<span><span class=`"dot dot-ok`"></span>$totalOK OK</span>")
[void]$sb.AppendLine('</div></div>')

[void]$sb.AppendLine('<div class="sidebar-nav">')
$navIdx = 1
foreach ($nav in $navDefs) {
    $dotColor = switch ($nav.W) {
        'Critical' { 'var(--crit)' }
        'Warning'  { 'var(--warn)' }
        'OK'       { 'var(--ok)' }
        default    { 'var(--info)' }
    }
    $title = ConvertTo-HtmlEncoded $nav.T
    [void]$sb.AppendLine("<button type=`"button`" class=`"nav-item`" data-target=`"$($nav.I)`" aria-label=`"Jump to $title`">")
    [void]$sb.AppendLine("<span class=`"nav-dot`" style=`"background:$dotColor`"></span>")
    [void]$sb.AppendLine("<span>$title</span><span class=`"nav-num`">$navIdx</span></button>")
    $navIdx++
}
[void]$sb.AppendLine('</div>')
[void]$sb.AppendLine('<div class="sidebar-foot">')
[void]$sb.AppendLine('<button type="button" class="btn" id="btn-theme" style="flex:1">Light mode</button>')
[void]$sb.AppendLine('</div></nav>')

# Section bodies
$body1 = New-Object System.Text.StringBuilder
[void]$body1.AppendLine((New-SubTitle 'Performance counters'))
[void]$body1.AppendLine((Get-HtmlTable -SectionName 'CPU' -Rows $cpuRows -Headers @('Counter','Average','Status','Recommendation')))
[void]$body1.AppendLine((New-SubTitle 'Processor information'))
[void]$body1.AppendLine((Get-HtmlTable -SectionName 'CPUInfo' -Rows $cpuInfoRows -Headers @('Name','Cores','LogicalProcs','MaxClockMHz','CurrentMHz','L2CacheKB','L3CacheKB','Status')))

$body2 = New-Object System.Text.StringBuilder
[void]$body2.AppendLine((Get-HtmlTable -SectionName 'Memory' -Rows $memRows -Headers @('Counter','Average','Status','Recommendation')))

$body3 = New-Object System.Text.StringBuilder
[void]$body3.AppendLine((New-SubTitle 'Performance counters'))
[void]$body3.AppendLine((Get-HtmlTable -SectionName 'Disk' -Rows $diskRows -Headers @('Counter','Average','Status','Recommendation')))
[void]$body3.AppendLine((New-SubTitle 'Volume free space'))
[void]$body3.AppendLine((Get-HtmlTable -SectionName 'DiskVol' -Rows $volRows -Headers @('Drive','Label','TotalGB','FreeGB','PctFree','FileSystem','Status','Recommendation') -BarColumn 'PctFree'))

$body4 = New-Object System.Text.StringBuilder
[void]$body4.AppendLine((Get-HtmlTable -SectionName 'Network' -Rows $netRows -Headers @('NIC','Counter','Average','Status','Recommendation')))

$body5 = New-Object System.Text.StringBuilder
[void]$body5.AppendLine((New-SubTitle 'Installed software'))
[void]$body5.AppendLine((Get-HtmlTable -SectionName 'SW' -Rows $swRows -Headers @('Name','Version','Publisher','InstallDate','Status')))
[void]$body5.AppendLine((New-SubTitle 'Windows roles and features (installed)'))
[void]$body5.AppendLine((Get-HtmlTable -SectionName 'Features' -Rows $featureRows -Headers @('Name','DisplayName','FeatureType','Status')))
[void]$body5.AppendLine((New-SubTitle 'Automatic services not running'))
if ($svcRows.Count -eq 0) {
    [void]$body5.AppendLine('<p class="no-data">No failed Automatic services were found.</p>')
} else {
    [void]$body5.AppendLine((Get-HtmlTable -SectionName 'Svc' -Rows $svcRows -Headers @('Name','DisplayName','State','StartMode','ExitCode','Status','Recommendation')))
}
[void]$body5.AppendLine((New-SubTitle 'Scheduled tasks (non-Microsoft, enabled)'))
[void]$body5.AppendLine((Get-HtmlTable -SectionName 'Tasks' -Rows $taskRows -Headers @('TaskName','TaskPath','State','LastRunTime','LastResult','NextRunTime','Status','Recommendation')))

$body6 = New-Object System.Text.StringBuilder
[void]$body6.AppendLine("<p class=`"no-data`" style=`"font-style:normal`">Errors and warnings from the last $EventLogHours hour(s), grouped by provider and event ID (max $EventLogMaxPerLog events read per log).</p>")
if ($eventRows.Count -eq 0) {
    [void]$body6.AppendLine('<p class="no-data">No errors or warnings found in the selected window.</p>')
} else {
    [void]$body6.AppendLine((Get-HtmlTable -SectionName 'Events' -Rows $eventRows -Headers @('Log','Count','Latest','Source','EventID','Level','Message','Status','Recommendation')))
}

$body7 = New-Object System.Text.StringBuilder
[void]$body7.AppendLine((Get-HtmlTable -SectionName 'WinHealth' -Rows $winHealthRows -Headers @('Check','Value','Status','Recommendation')))
[void]$body7.AppendLine((New-SubTitle 'Recent Windows updates (last 10 with install dates)'))
[void]$body7.AppendLine((Get-HtmlTable -SectionName 'WU' -Rows $wuRows -Headers @('HotFixID','Description','InstalledOn','Status')))

$body8 = New-Object System.Text.StringBuilder
[void]$body8.AppendLine((New-SubTitle 'Security checks'))
[void]$body8.AppendLine((Get-HtmlTable -SectionName 'Sec' -Rows $secRows -Headers @('Check','Value','Status','Recommendation')))
if ($iisRows.Count -gt 0) {
    [void]$body8.AppendLine((New-SubTitle 'IIS sites'))
    [void]$body8.AppendLine((Get-HtmlTable -SectionName 'IIS' -Rows $iisRows -Headers @('SiteName','State','PhysicalPath','Bindings','Status','Recommendation')))
}
[void]$body8.AppendLine((New-SubTitle 'Windows Time (W32TM)'))
[void]$body8.AppendLine((Get-HtmlTable -SectionName 'W32TM' -Rows $w32tmRows -Headers @('Check','Value','Status','Recommendation')))

$body9 = New-Object System.Text.StringBuilder
if ($sqlInstRows.Count -gt 0 -or @($script:sqlInstances).Count -gt 0) {
    [void]$body9.AppendLine((New-SubTitle 'SQL Server instances and agents'))
    [void]$body9.AppendLine((Get-HtmlTable -SectionName 'SQLInst' -Rows $sqlInstRows -Headers @('Instance','Service','State','Status','Recommendation')))
    if ($sqlCounterRows.Count -gt 0) {
        [void]$body9.AppendLine((New-SubTitle 'SQL Server performance counters'))
        [void]$body9.AppendLine((Get-HtmlTable -SectionName 'SQLPerf' -Rows $sqlCounterRows -Headers @('Instance','Counter','Average','Status','Recommendation')))
    }
} else {
    [void]$body9.AppendLine('<p class="no-data">No SQL Server instances detected on this server.</p>')
}

$body10 = New-Object System.Text.StringBuilder
[void]$body10.AppendLine((New-SubTitle 'System and BIOS'))
[void]$body10.AppendLine((Get-HtmlTable -SectionName 'HW' -Rows $hwRows -Headers @('Item','Value','Status')))
[void]$body10.AppendLine((New-SubTitle 'Physical disks'))
[void]$body10.AppendLine((Get-HtmlTable -SectionName 'PhysDisk' -Rows $physDiskRows -Headers @('DeviceID','Model','SizeGB','Interface','MediaType','FirmwareRev','Partitions','Status')))
[void]$body10.AppendLine((New-SubTitle 'Network adapters (IP enabled)'))
[void]$body10.AppendLine((Get-HtmlTable -SectionName 'NICs' -Rows $nicRows -Headers @('Description','IPAddress','SubnetMask','Gateway','DNS','DHCP','MACAddress','Status')))
if ($nicLinkRows.Count -gt 0) {
    [void]$body10.AppendLine((New-SubTitle 'Physical adapter link status'))
    [void]$body10.AppendLine((Get-HtmlTable -SectionName 'NICLink' -Rows $nicLinkRows -Headers @('Name','Interface','StatusText','LinkSpeed','MacAddress','Driver','Status','Recommendation')))
}

$body11 = New-Object System.Text.StringBuilder
[void]$body11.AppendLine((New-SubTitle 'Top 20 processes by working set'))
[void]$body11.AppendLine((Get-HtmlTable -SectionName 'MemProc' -Rows $memDeepRows -Headers @('PID','Name','WorkingSetMB','CPU','Threads','Handles','Status','Recommendation')))
[void]$body11.AppendLine((New-SubTitle 'Page file configuration'))
[void]$body11.AppendLine((Get-HtmlTable -SectionName 'PageFile' -Rows $pfRows -Headers @('Name','InitialSizeMB','MaxSizeMB','Status')))

$body12 = New-Object System.Text.StringBuilder
[void]$body12.AppendLine((New-SubTitle 'Disk partitions'))
[void]$body12.AppendLine((Get-HtmlTable -SectionName 'Partitions' -Rows $storDeepRows -Headers @('Disk','Partition','Name','Type','SizeGB','Bootable','PrimaryPartition','Status')))
[void]$body12.AppendLine((New-SubTitle 'Volume health'))
[void]$body12.AppendLine((Get-HtmlTable -SectionName 'VolHealth' -Rows $fsHealthRows -Headers @('DriveLetter','FriendlyName','FileSystem','SizeGB','FreeGB','HealthStatus','Status','Recommendation')))
[void]$body12.AppendLine((New-SubTitle 'Volume shadow copies (VSS)'))
[void]$body12.AppendLine((Get-HtmlTable -SectionName 'VSS' -Rows $vssRows -Headers @('ID','VolumeName','InstallDate','ProviderID','Status')))

$body13 = New-Object System.Text.StringBuilder
[void]$body13.AppendLine((New-SubTitle 'TCP connection states'))
[void]$body13.AppendLine((Get-HtmlTable -SectionName 'TCP' -Rows $netDeepRows -Headers @('State','Count','Status','Recommendation')))
[void]$body13.AppendLine((New-SubTitle 'DNS self-resolution'))
[void]$body13.AppendLine((Get-HtmlTable -SectionName 'DNS' -Rows $dnsRows -Headers @('Name','Type','IPAddress','TTL','Status','Recommendation')))
[void]$body13.AppendLine((New-SubTitle 'Listening TCP ports'))
[void]$body13.AppendLine((Get-HtmlTable -SectionName 'Listen' -Rows $listenRows -Headers @('LocalAddress','LocalPort','PID','ProcessName','Status')))

$body15 = New-Object System.Text.StringBuilder
[void]$body15.AppendLine((Get-HtmlTable -SectionName 'HV' -Rows $hvRows -Headers @('Name','State','CPUs','AssignedMemGB','Uptime','Generation','Version','Status','Recommendation')))

$body16 = New-Object System.Text.StringBuilder
[void]$body16.AppendLine((Get-HtmlTable -SectionName 'Certs' -Rows $certRows -Headers @('Store','Subject','Thumbprint','NotAfter','DaysRemaining','Issuer','Status','Recommendation')))

$attentionSorted = @($script:attentionRows | Sort-Object @{ Expression = { if ($_.Status -eq 'Critical') { 0 } else { 1 } } }, Section, Check)
$attentionHtml = Get-HtmlTable -SectionName 'Attention' -Rows $attentionSorted -Headers @('Section','Check','Value','Status','Recommendation')

$alertClass = if ($totalCritical -gt 0) { 'alert-crit' } elseif ($totalWarning -gt 0) { 'alert-warn' } else { 'alert-ok' }
$alertIcon  = if ($totalCritical -gt 0) { '&#9888;' } elseif ($totalWarning -gt 0) { '&#9888;' } else { '&#10003;' }
$alertMsg   = if ($totalCritical -gt 0) {
    "<strong>$totalCritical critical issue(s)</strong> need attention, plus $totalWarning warning(s)."
} elseif ($totalWarning -gt 0) {
    "<strong>$totalWarning warning(s)</strong> detected — review recommended."
} else {
    'All scored checks passed. No critical issues or warnings were recorded.'
}
$overallStatClass = if ($totalCritical -gt 0) { 'stat-crit' } elseif ($totalWarning -gt 0) { 'stat-warn' } else { 'stat-ok' }
$hostEnc = ConvertTo-HtmlEncoded $hostname
$osEnc   = ConvertTo-HtmlEncoded $osCaption
$genEnc  = ConvertTo-HtmlEncoded $genTime

[void]$sb.AppendLine('<div id="main">')
[void]$sb.AppendLine('<div id="topbar">')
[void]$sb.AppendLine("<div class=`"topbar-title`">System Analysis — $hostEnc</div>")
[void]$sb.AppendLine('<div class="topbar-actions">')
[void]$sb.AppendLine('<input type="search" id="search-global" placeholder="Search report  /" aria-label="Search the whole report" autocomplete="off">')
[void]$sb.AppendLine('<button type="button" class="btn" id="btn-issues">Issues only</button>')
[void]$sb.AppendLine('<button type="button" class="btn" id="btn-expand-all">Expand all</button>')
[void]$sb.AppendLine('<button type="button" class="btn" id="btn-collapse-all">Collapse all</button>')
[void]$sb.AppendLine('<button type="button" class="btn" id="btn-csv">Download CSV</button>')
[void]$sb.AppendLine('<button type="button" class="btn btn-primary" onclick="window.print()">Print / PDF</button>')
[void]$sb.AppendLine('</div>')
[void]$sb.AppendLine("<div class=`"topbar-meta`">Generated $genEnc &bull; Runtime ${runtimeSec}s")
if ($uptimeStr) { [void]$sb.AppendLine(" &bull; Uptime $uptimeStr") }
if ($osEnc) { [void]$sb.AppendLine(" &bull; $osEnc") }
[void]$sb.AppendLine(' &bull; <span class="kbd">/</span> search</div></div>')

[void]$sb.AppendLine('<div class="content" id="content">')
[void]$sb.AppendLine('<div class="summary-strip">')
[void]$sb.AppendLine("<div class=`"stat-card`"><div class=`"sc-label`">Hostname</div><div class=`"sc-value`" style=`"font-size:18px`">$hostEnc</div><div class=`"sc-sub`">$osEnc</div></div>")
[void]$sb.AppendLine("<div class=`"stat-card $overallStatClass`"><div class=`"sc-label`">Overall</div><div class=`"sc-value`" style=`"font-size:22px`">$overallStatus</div><div class=`"sc-sub`">score $healthScore / 100</div></div>")
[void]$sb.AppendLine("<div class=`"stat-card stat-crit`"><div class=`"sc-label`">Critical</div><div class=`"sc-value`">$totalCritical</div><div class=`"sc-sub`">unique checks</div></div>")
[void]$sb.AppendLine("<div class=`"stat-card stat-warn`"><div class=`"sc-label`">Warnings</div><div class=`"sc-value`">$totalWarning</div><div class=`"sc-sub`">unique checks</div></div>")
[void]$sb.AppendLine("<div class=`"stat-card stat-ok`"><div class=`"sc-label`">OK</div><div class=`"sc-value`">$totalOK</div><div class=`"sc-sub`">checks passed</div></div>")
if ($uptimeStr) {
    [void]$sb.AppendLine("<div class=`"stat-card stat-info`"><div class=`"sc-label`">Uptime</div><div class=`"sc-value`" style=`"font-size:18px`">$uptimeStr</div><div class=`"sc-sub`">since last boot</div></div>")
}
[void]$sb.AppendLine('</div>')
[void]$sb.AppendLine("<div class=`"alert-banner $alertClass`"><span class=`"alert-icon`">$alertIcon</span><span class=`"alert-text`">$alertMsg</span></div>")

[void]$sb.AppendLine('<div class="attention-panel" id="attention">')
[void]$sb.AppendLine("<div class=`"attention-head`"><h2>Action required</h2><span class=`"count`">$($attentionSorted.Count) item(s)</span></div>")
[void]$sb.AppendLine('<div class="attention-body">')
if ($attentionSorted.Count -eq 0) {
    [void]$sb.AppendLine('<p class="no-data">Nothing to action — no critical or warning checks were recorded.</p>')
} else {
    [void]$sb.AppendLine($attentionHtml)
}
[void]$sb.AppendLine('</div></div>')

function Open-IfIssue {
    param($Rows)
    $w = Get-WorstStatus $Rows
    return ($w -eq 'Critical' -or $w -eq 'Warning')
}

[void]$sb.AppendLine((New-SectionPanel -Id 'CPU-Analysis' -Title 'CPU Analysis' -WorstStatus (Get-WorstStatus $cpuRows) -CheckCount ($cpuRows.Count + $cpuInfoRows.Count) -BodyHtml $body1.ToString() -StartOpen $true))
[void]$sb.AppendLine((New-SectionPanel -Id 'Memory-Analysis' -Title 'Memory Analysis' -WorstStatus (Get-WorstStatus $memRows) -CheckCount $memRows.Count -BodyHtml $body2.ToString() -StartOpen (Open-IfIssue $memRows)))
[void]$sb.AppendLine((New-SectionPanel -Id 'Disk-Analysis' -Title 'Disk Analysis' -WorstStatus (Get-WorstStatus (@($diskRows)+@($volRows))) -CheckCount ($diskRows.Count + $volRows.Count) -BodyHtml $body3.ToString() -StartOpen (Open-IfIssue (@($diskRows)+@($volRows)))))
[void]$sb.AppendLine((New-SectionPanel -Id 'Network-Analysis' -Title 'Network Analysis' -WorstStatus (Get-WorstStatus $netRows) -CheckCount $netRows.Count -BodyHtml $body4.ToString() -StartOpen (Open-IfIssue $netRows)))
[void]$sb.AppendLine((New-SectionPanel -Id 'Software-Services' -Title 'Software & Services' -WorstStatus (Get-WorstStatus (@($svcRows)+@($taskRows))) -CheckCount ($swRows.Count + $featureRows.Count + $svcRows.Count + $taskRows.Count) -BodyHtml $body5.ToString() -StartOpen (Open-IfIssue (@($svcRows)+@($taskRows)))))
[void]$sb.AppendLine((New-SectionPanel -Id 'Event-Logs' -Title 'Event Logs' -WorstStatus (Get-WorstStatus $eventRows) -CheckCount $eventRows.Count -BodyHtml $body6.ToString() -StartOpen (Open-IfIssue $eventRows)))
[void]$sb.AppendLine((New-SectionPanel -Id 'Windows-Health' -Title 'Windows Health' -WorstStatus (Get-WorstStatus $winHealthRows) -CheckCount ($winHealthRows.Count + $wuRows.Count) -BodyHtml $body7.ToString() -StartOpen (Open-IfIssue $winHealthRows)))
[void]$sb.AppendLine((New-SectionPanel -Id 'Security-IIS' -Title 'Security & IIS' -WorstStatus (Get-WorstStatus (@($secRows)+@($iisRows)+@($w32tmRows))) -CheckCount ($secRows.Count + $iisRows.Count + $w32tmRows.Count) -BodyHtml $body8.ToString() -StartOpen (Open-IfIssue (@($secRows)+@($iisRows)+@($w32tmRows)))))
[void]$sb.AppendLine((New-SectionPanel -Id 'SQL-Server' -Title 'SQL Server' -WorstStatus (Get-WorstStatus (@($sqlInstRows)+@($sqlCounterRows))) -CheckCount ($sqlInstRows.Count + $sqlCounterRows.Count) -BodyHtml $body9.ToString() -StartOpen (Open-IfIssue (@($sqlInstRows)+@($sqlCounterRows)))))
[void]$sb.AppendLine((New-SectionPanel -Id 'Hardware' -Title 'Hardware' -WorstStatus (Get-WorstStatus (@($hwRows)+@($nicLinkRows))) -CheckCount ($hwRows.Count + $physDiskRows.Count + $nicRows.Count + $nicLinkRows.Count) -BodyHtml $body10.ToString() -StartOpen (Open-IfIssue $nicLinkRows)))
[void]$sb.AppendLine((New-SectionPanel -Id 'Memory-Deep-Dive' -Title 'Memory Deep Dive' -WorstStatus (Get-WorstStatus $memDeepRows) -CheckCount ($memDeepRows.Count + $pfRows.Count) -BodyHtml $body11.ToString() -StartOpen (Open-IfIssue $memDeepRows)))
[void]$sb.AppendLine((New-SectionPanel -Id 'Storage-Deep-Dive' -Title 'Storage Deep Dive' -WorstStatus (Get-WorstStatus $fsHealthRows) -CheckCount ($storDeepRows.Count + $fsHealthRows.Count + $vssRows.Count) -BodyHtml $body12.ToString() -StartOpen (Open-IfIssue $fsHealthRows)))
[void]$sb.AppendLine((New-SectionPanel -Id 'Network-Deep-Dive' -Title 'Network Deep Dive' -WorstStatus (Get-WorstStatus (@($netDeepRows)+@($dnsRows))) -CheckCount ($netDeepRows.Count + $dnsRows.Count + $listenRows.Count) -BodyHtml $body13.ToString() -StartOpen (Open-IfIssue (@($netDeepRows)+@($dnsRows)))))
[void]$sb.AppendLine((New-SectionPanel -Id 'AD-Kerberos-BPA' -Title 'AD / Kerberos / BPA' -WorstStatus $adWorst -CheckCount $adCheckCount -BodyHtml $adKerbBpaHtml -StartOpen ($adWorst -eq 'Critical' -or $adWorst -eq 'Warning')))
[void]$sb.AppendLine((New-SectionPanel -Id 'Hyper-V' -Title 'Hyper-V' -WorstStatus (Get-WorstStatus $hvRows) -CheckCount $hvRows.Count -BodyHtml $body15.ToString() -StartOpen (Open-IfIssue $hvRows)))
[void]$sb.AppendLine((New-SectionPanel -Id 'Certificates' -Title 'Certificates' -WorstStatus (Get-WorstStatus $certRows) -CheckCount $certRows.Count -BodyHtml $body16.ToString() -StartOpen (Open-IfIssue $certRows)))

[void]$sb.AppendLine('</div>')
[void]$sb.AppendLine("<footer>System Analysis Report &bull; $hostEnc &bull; $genEnc &bull; Score $healthScore/100</footer>")
[void]$sb.AppendLine('</div>')
[void]$sb.AppendLine('<button type="button" class="back-top" id="back-top">Back to top</button>')

$csvName = "SystemAnalysis_${hostname}.csv"
[void]$sb.AppendLine("<script>window.REPORT_CSV_NAME = '$(ConvertTo-HtmlEncoded $csvName)';</script>")

[void]$sb.AppendLine(@'
<script>
(function(){
  function togglePanel(panel, force) {
    if (!panel) return;
    var isOpen = panel.classList.contains('open');
    var open = (force !== undefined) ? force : !isOpen;
    var header = panel.querySelector('.section-header');
    var body = panel.querySelector('.section-body');
    if (open) {
      panel.classList.add('open');
      if (header) header.setAttribute('aria-expanded', 'true');
      if (body) body.style.display = 'block';
    } else {
      panel.classList.remove('open');
      if (header) header.setAttribute('aria-expanded', 'false');
      if (body) body.style.display = 'none';
    }
  }

  document.querySelectorAll('.section-header').forEach(function(h) {
    h.addEventListener('click', function() { togglePanel(h.closest('.section-panel')); });
    h.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        togglePanel(h.closest('.section-panel'));
      }
    });
  });

  document.querySelectorAll('.section-panel').forEach(function(p) {
    var body = p.querySelector('.section-body');
    if (body && !p.classList.contains('open')) body.style.display = 'none';
  });

  var expandBtn = document.getElementById('btn-expand-all');
  var collapseBtn = document.getElementById('btn-collapse-all');
  if (expandBtn) expandBtn.addEventListener('click', function() {
    document.querySelectorAll('.section-panel').forEach(function(p) { togglePanel(p, true); });
  });
  if (collapseBtn) collapseBtn.addEventListener('click', function() {
    document.querySelectorAll('.section-panel').forEach(function(p) { togglePanel(p, false); });
  });

  function closeMobileNav() {
    var side = document.getElementById('sidebar');
    var back = document.getElementById('sidebar-backdrop');
    if (side) side.classList.remove('mob-open');
    if (back) back.classList.remove('show');
  }

  document.querySelectorAll('.nav-item').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var id = btn.getAttribute('data-target');
      var el = document.getElementById(id);
      if (!el) return;
      if (!el.classList.contains('open')) togglePanel(el, true);
      setTimeout(function() { el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }, 40);
      document.querySelectorAll('.nav-item').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      closeMobileNav();
    });
  });

  var mobToggle = document.getElementById('mob-toggle');
  var backdrop = document.getElementById('sidebar-backdrop');
  if (mobToggle) {
    mobToggle.addEventListener('click', function() {
      var side = document.getElementById('sidebar');
      side.classList.toggle('mob-open');
      if (backdrop) backdrop.classList.toggle('show', side.classList.contains('mob-open'));
    });
  }
  if (backdrop) backdrop.addEventListener('click', closeMobileNav);

  function applyTableFilter(controls) {
    var tableId = controls.getAttribute('data-for');
    var table = document.getElementById(tableId);
    if (!table) return;
    var activeFilter = 'all';
    var searchVal = '';
    var pill = controls.querySelector('.pill.active');
    if (pill) activeFilter = pill.getAttribute('data-filter');
    var searchEl = controls.querySelector('.tbl-search');
    if (searchEl) searchVal = searchEl.value.toLowerCase().trim();
    var visible = 0;
    table.querySelectorAll('tbody tr').forEach(function(row) {
      var statusMatch = (activeFilter === 'all') || (row.getAttribute('data-status') === activeFilter);
      var searchMatch = true;
      if (searchVal) searchMatch = row.textContent.toLowerCase().indexOf(searchVal) !== -1;
      var hide = !(statusMatch && searchMatch);
      row.classList.toggle('hidden-filter', hide);
      syncRowVisibility(row);
      if (!row.classList.contains('hidden-row')) visible++;
    });
    var count = controls.querySelector('.tbl-count');
    if (count) {
      var total = count.getAttribute('data-total') || '';
      count.textContent = visible + (total ? '/' + total : '');
    }
  }

  function syncRowVisibility(row) {
    var hide = row.classList.contains('hidden-filter') ||
               row.classList.contains('hidden-global') ||
               row.classList.contains('hidden-issues');
    row.classList.toggle('hidden-row', hide);
  }

  document.querySelectorAll('.table-controls').forEach(function(controls) {
    controls.querySelectorAll('.pill').forEach(function(pill) {
      pill.addEventListener('click', function() {
        controls.querySelectorAll('.pill').forEach(function(p) { p.classList.remove('active'); });
        pill.classList.add('active');
        applyTableFilter(controls);
      });
    });
    var search = controls.querySelector('.tbl-search');
    if (search) search.addEventListener('input', function() { applyTableFilter(controls); });
  });

  document.querySelectorAll('th[data-col]').forEach(function(th) {
    th.addEventListener('click', function() {
      var table = th.closest('table');
      var colIdx = parseInt(th.getAttribute('data-col'), 10);
      var asc = !th.classList.contains('sort-asc');
      table.querySelectorAll('th').forEach(function(t) { t.classList.remove('sort-asc', 'sort-desc'); });
      th.classList.add(asc ? 'sort-asc' : 'sort-desc');
      var tbody = table.querySelector('tbody');
      var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
      rows.sort(function(a, b) {
        var aText = (a.cells[colIdx] ? a.cells[colIdx].textContent.trim() : '');
        var bText = (b.cells[colIdx] ? b.cells[colIdx].textContent.trim() : '');
        var aNum = parseFloat(aText.replace(/,/g, ''));
        var bNum = parseFloat(bText.replace(/,/g, ''));
        if (!isNaN(aNum) && !isNaN(bNum) && /^-?[\d.,]+/.test(aText) && /^-?[\d.,]+/.test(bText)) {
          return asc ? aNum - bNum : bNum - aNum;
        }
        return asc ? aText.localeCompare(bText) : bText.localeCompare(aText);
      });
      rows.forEach(function(r) { tbody.appendChild(r); });
    });
  });

  var globalSearch = document.getElementById('search-global');
  function applyGlobalSearch() {
    var val = globalSearch ? globalSearch.value.toLowerCase().trim() : '';
    document.querySelectorAll('tbody tr').forEach(function(row) {
      if (!val) {
        row.classList.remove('hidden-global');
      } else {
        row.classList.toggle('hidden-global', row.textContent.toLowerCase().indexOf(val) === -1);
      }
      syncRowVisibility(row);
    });
    if (val) {
      document.querySelectorAll('.section-panel').forEach(function(p) { togglePanel(p, true); });
    }
  }
  if (globalSearch) globalSearch.addEventListener('input', applyGlobalSearch);

  var issuesOnly = false;
  var issuesBtn = document.getElementById('btn-issues');
  if (issuesBtn) {
    issuesBtn.addEventListener('click', function() {
      issuesOnly = !issuesOnly;
      issuesBtn.classList.toggle('btn-primary', issuesOnly);
      document.querySelectorAll('.section-panel').forEach(function(p) {
        var st = p.getAttribute('data-status');
        var keep = !issuesOnly || st === 'Critical' || st === 'Warning';
        p.style.display = keep ? '' : 'none';
        if (keep && issuesOnly) togglePanel(p, true);
      });
      document.querySelectorAll('tbody tr').forEach(function(row) {
        var st = row.getAttribute('data-status');
        row.classList.toggle('hidden-issues', issuesOnly && st !== 'Critical' && st !== 'Warning');
        syncRowVisibility(row);
      });
    });
  }

  var themeBtn = document.getElementById('btn-theme');
  function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('sysanalysis-theme', theme); } catch (e) {}
    if (themeBtn) themeBtn.textContent = (theme === 'dark') ? 'Light mode' : 'Dark mode';
  }
  var saved = null;
  try { saved = localStorage.getItem('sysanalysis-theme'); } catch (e) {}
  if (saved === 'light' || saved === 'dark') setTheme(saved);
  else setTheme('dark');
  if (themeBtn) themeBtn.addEventListener('click', function() {
    var cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    setTheme(cur);
  });

  var csvBtn = document.getElementById('btn-csv');
  if (csvBtn) {
    csvBtn.addEventListener('click', function() {
      var lines = [];
      document.querySelectorAll('table').forEach(function(table) {
        var headers = Array.prototype.map.call(table.querySelectorAll('thead th'), function(th) {
          return '"' + th.textContent.replace(/▲|▼/g, '').trim().replace(/"/g, '""') + '"';
        });
        if (!headers.length) return;
        table.querySelectorAll('tbody tr').forEach(function(row) {
          if (row.classList.contains('hidden-row')) return;
          var cells = Array.prototype.map.call(row.cells, function(td) {
            return '"' + td.textContent.trim().replace(/"/g, '""') + '"';
          });
          lines.push(cells.join(','));
        });
      });
      if (!lines.length) return;
      var blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = window.REPORT_CSV_NAME || 'SystemAnalysis.csv';
      a.click();
      URL.revokeObjectURL(a.href);
    });
  }

  var backTop = document.getElementById('back-top');
  window.addEventListener('scroll', function() {
    if (backTop) backTop.classList.toggle('show', window.scrollY > 600);
  });
  if (backTop) backTop.addEventListener('click', function() {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  document.addEventListener('keydown', function(e) {
    var tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : '';
    if (tag === 'input' || tag === 'textarea') return;
    if (e.key === '/') {
      e.preventDefault();
      if (globalSearch) globalSearch.focus();
    }
  });

  if ('IntersectionObserver' in window) {
    var obs = new IntersectionObserver(function(entries) {
      var vis = entries.filter(function(en) { return en.isIntersecting; });
      if (!vis.length) return;
      vis.sort(function(a, b) { return b.intersectionRatio - a.intersectionRatio; });
      var id = vis[0].target.id;
      document.querySelectorAll('.nav-item').forEach(function(btn) {
        btn.classList.toggle('active', btn.getAttribute('data-target') === id);
      });
    }, { rootMargin: '-20% 0px -55% 0px', threshold: [0.1, 0.25] });
    document.querySelectorAll('.section-panel').forEach(function(p) { obs.observe(p); });
  }
})();
</script>
</body></html>
'@)

#endregion

#region ── Output ─────────────────────────────────────────────────────────────

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$htmlFile  = Join-Path $OutputPath "SystemAnalysis_${hostname}_${timestamp}.html"
$csvFile   = Join-Path $OutputPath "SystemAnalysis_${hostname}_${timestamp}.csv"

try {
    $sb.ToString() | Out-File -FilePath $htmlFile -Encoding UTF8 -Force
} catch {
    throw "Failed to write HTML report to '$htmlFile': $($_.Exception.Message)"
}

try {
    $script:csvRows | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8 -Force
} catch {
    Write-Host "[!] CSV export failed: $($_.Exception.Message)" -ForegroundColor Yellow
    $csvFile = $null
}

Write-Progress -Activity "System Analysis ($hostname)" -Completed
Write-Host ""
Write-Host "  Analysis complete" -ForegroundColor Green
Write-Host "  HTML report     : $htmlFile"
if ($csvFile) { Write-Host "  CSV export      : $csvFile" }
Write-Host "  Overall status  : $overallStatus  (Critical: $totalCritical | Warning: $totalWarning | OK: $totalOK | Score: $healthScore)"
Write-Host "  Runtime         : $([math]::Round(((Get-Date) - $startTime).TotalSeconds, 1))s"
Write-Host ""

if (-not $NoBrowser) {
    try { Start-Process $htmlFile } catch { }
}

#endregion

<#
.SYNOPSIS
    Active Directory Log Viewer - Modern GUI

.DESCRIPTION
    Fast, resizable WinForms viewer for AD account-management log files.
    Streams files instead of loading them all at once, reports ingest
    progress in real time, and parses common AD log fields for filtering
    and export.

.NOTES
    Version:      2.0
    Compatible:   Windows PowerShell 5.1+ and PowerShell 7+ (Windows)
    UI:           System.Windows.Forms (STA)

    Changes in v2.0:
    - Modern layout aligned with AD Object Manager (header, cards, flat buttons)
    - Sizable / maximizable window with anchored, docking controls
    - Streaming ingest with byte-level progress, throughput, and cancel
    - Live status updates while the file is being read
    - Data grid with parsed Timestamp, Event, Account, Actor, Host columns
    - Instant filter of already-loaded results
    - Literal search by default (regex optional)
    - Export, copy, detail pane, drag-and-drop, encoding selection
#>

#Requires -Version 5.1

param(
    [switch]$SkipGui
)

$script:AppVersion = '2.0'
$script:TimestampFormat = 'MM/dd/yyyy HH:mm:ss'
$script:AccountCalledRegex = [regex]::new('AD user called:\s*([^,\s]+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$script:AccountWasRegex    = [regex]::new('(?i)Account\s+(\S+)\s+was', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$script:AccountOfUserRegex = [regex]::new('(?i)of user(?:\s+called:)?\s+([^\s(]+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$script:ActorByRegex       = [regex]::new('(?i)\sby\s+(\S+)\s+in\s+', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$script:ActorModifiedRegex = [regex]::new('(?i)^.{19}\s*==\s*The user\s+(\S+)\s+modified', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$script:HostRegex          = [regex]::new('(?i)\sin\s+([A-Za-z0-9._-]+)\s*$', [System.Text.RegularExpressions.RegexOptions]::Compiled)

# ============================================================
# DATA TYPES
# ============================================================
class AdLogEntry {
    [datetime]$SortKey
    [bool]$HasTimestamp
    [string]$TimestampText
    [string]$Event
    [string]$Account
    [string]$Actor
    [string]$HostName
    [string]$FileName
    [int]$LineNumber
    [string]$Text
}

# ============================================================
# PARSE / SEARCH ENGINE  (no UI dependency)
# ============================================================
function Get-AdLogTimestamp {
    param([string]$Line)

    if ([string]::IsNullOrEmpty($Line) -or $Line.Length -lt 19) {
        return $null
    }

    try {
        return [datetime]::ParseExact(
            $Line.Substring(0, 19),
            $script:TimestampFormat,
            [System.Globalization.CultureInfo]::InvariantCulture
        )
    } catch {
        return $null
    }
}

function Get-AdLogEventKind {
    param([string]$Line)

    if ([string]::IsNullOrEmpty($Line)) { return 'Other' }

    $upper = $Line.ToUpperInvariant()
    if ($upper.Contains('ADDED TO'))          { return 'Added' }
    if ($upper.Contains('REMOVED FROM'))      { return 'Removed' }
    if ($upper.Contains('DISABLED'))          { return 'Disabled' }
    if ($upper.Contains('UNLOCKED'))          { return 'Unlocked' }
    if ($upper.Contains('LOCKED'))            { return 'Locked' }
    if ($upper.Contains('ENABLED'))           { return 'Enabled' }
    if ($upper.Contains('CREATED'))           { return 'Created' }
    if ($upper.Contains('DELETED'))           { return 'Deleted' }
    if ($upper.Contains('PASSWORD'))          { return 'Password' }
    if ($upper.Contains('MODIFIED') -or $upper.Contains(' MODIFIED')) { return 'Modified' }
    return 'Other'
}

function Get-AdLogAccount {
    param([string]$Line)

    if ([string]::IsNullOrEmpty($Line)) { return '' }

    $m = $script:AccountCalledRegex.Match($Line)
    if ($m.Success) { return $m.Groups[1].Value }

    $m = $script:AccountWasRegex.Match($Line)
    if ($m.Success) { return $m.Groups[1].Value }

    $m = $script:AccountOfUserRegex.Match($Line)
    if ($m.Success) { return $m.Groups[1].Value }

    return ''
}

function Get-AdLogActor {
    param([string]$Line)

    if ([string]::IsNullOrEmpty($Line)) { return '' }

    $m = $script:ActorByRegex.Match($Line)
    if ($m.Success) { return $m.Groups[1].Value }

    $m = $script:ActorModifiedRegex.Match($Line)
    if ($m.Success) { return $m.Groups[1].Value }

    return ''
}

function Get-AdLogHostName {
    param([string]$Line)

    if ([string]::IsNullOrEmpty($Line)) { return '' }

    $m = $script:HostRegex.Match($Line)
    if ($m.Success) { return $m.Groups[1].Value }

    return ''
}

function New-AdLogEntry {
    param(
        [string]$Line,
        [string]$FileName,
        [int]$LineNumber
    )

    $entry = [AdLogEntry]::new()
    $entry.Text = $Line
    $entry.FileName = $FileName
    $entry.LineNumber = $LineNumber
    $ts = Get-AdLogTimestamp -Line $Line
    if ($ts) {
        $entry.SortKey = $ts
        $entry.HasTimestamp = $true
        $entry.TimestampText = $ts.ToString($script:TimestampFormat)
    } else {
        $entry.SortKey = [datetime]::MaxValue
        $entry.HasTimestamp = $false
        $entry.TimestampText = ''
    }
    $entry.Event = Get-AdLogEventKind -Line $Line
    $entry.Account = Get-AdLogAccount -Line $Line
    $entry.Actor = Get-AdLogActor -Line $Line
    $entry.HostName = Get-AdLogHostName -Line $Line
    return $entry
}

function Get-AdLogEncoding {
    param(
        [string]$Name,
        [string]$FilePath
    )

    switch ($Name) {
        'Unicode (UTF-16)' { return [System.Text.Encoding]::Unicode }
        'UTF-8'            { return [System.Text.Encoding]::UTF8 }
        'ANSI (Default)'   { return [System.Text.Encoding]::Default }
        default {
            $fs = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $bom = New-Object byte[] 4
                $read = $fs.Read($bom, 0, 4)
                if ($read -ge 2 -and $bom[0] -eq 0xFF -and $bom[1] -eq 0xFE) { return [System.Text.Encoding]::Unicode }
                if ($read -ge 2 -and $bom[0] -eq 0xFE -and $bom[1] -eq 0xFF) { return [System.Text.Encoding]::BigEndianUnicode }
                if ($read -ge 3 -and $bom[0] -eq 0xEF -and $bom[1] -eq 0xBB -and $bom[2] -eq 0xBF) { return [System.Text.Encoding]::UTF8 }
            } finally {
                $fs.Dispose()
            }
            return [System.Text.Encoding]::UTF8
        }
    }
}

function Test-AdLogLineMatch {
    param(
        [string]$Line,
        [string]$SearchTerm,
        [bool]$CaseInsensitive,
        [bool]$UseRegex,
        [System.Text.RegularExpressions.Regex]$CompiledRegex
    )

    if ([string]::IsNullOrEmpty($SearchTerm)) { return $true }

    if ($UseRegex) {
        if ($null -eq $CompiledRegex) { return $false }
        return $CompiledRegex.IsMatch($Line)
    }

    if ($CaseInsensitive) {
        return $Line.IndexOf($SearchTerm, [StringComparison]::OrdinalIgnoreCase) -ge 0
    }
    return $Line.IndexOf($SearchTerm, [StringComparison]::Ordinal) -ge 0
}

function Get-AdLogTargetFiles {
    param(
        [string]$Path,
        [bool]$IsFolder,
        [bool]$Recursive
    )

    if ($IsFolder) {
        $gci = @{
            Path    = $Path
            Filter  = '*.txt'
            File    = $true
            ErrorAction = 'Stop'
        }
        if ($Recursive) { $gci['Recurse'] = $true }
        return @(Get-ChildItem @gci | Sort-Object FullName)
    }

    return @([System.IO.FileInfo]::new($Path))
}

function ConvertTo-AdLogList {
    param($InputObject)

    if ($InputObject -is [System.Collections.Generic.List[AdLogEntry]]) {
        return , $InputObject
    }

    $list = New-Object 'System.Collections.Generic.List[AdLogEntry]'
    if ($null -eq $InputObject) {
        return , $list
    }

    foreach ($item in @($InputObject)) {
        if ($item -is [AdLogEntry]) {
            [void]$list.Add($item)
        }
    }
    return , $list
}

function Get-AdLogEntryCount {
    param($Entries)

    if ($null -eq $Entries) { return 0 }
    if ($Entries -is [System.Collections.ICollection]) { return [int]$Entries.Count }
    return @($Entries).Count
}

function Search-AdLogFiles {
    <#
    .SYNOPSIS
        Stream-search one file or a folder of AD log files.
        Calls -ProgressCallback with a hashtable of ingest stats.
    #>
    param(
        [string]$Path,
        [string]$SearchTerm,
        [bool]$IsFolder,
        [bool]$Recursive,
        [bool]$CaseInsensitive,
        [bool]$UseRegex,
        [string]$EncodingName = 'Auto (BOM)',
        [scriptblock]$ProgressCallback,
        [scriptblock]$ShouldCancel,
        [System.Collections.IList]$ErrorLog
    )

    $results = New-Object 'System.Collections.Generic.List[AdLogEntry]'
    $compiled = $null

    if ($UseRegex -and -not [string]::IsNullOrEmpty($SearchTerm)) {
        $options = [System.Text.RegularExpressions.RegexOptions]::Compiled
        if ($CaseInsensitive) {
            $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        }
        $compiled = [regex]::new($SearchTerm, $options)
    }

    $files = Get-AdLogTargetFiles -Path $Path -IsFolder $IsFolder -Recursive $Recursive
    $fileCount = $files.Count
    $fileIndex = 0
    $grandLines = 0
    $started = [datetime]::UtcNow
    $lastReport = [datetime]::MinValue
    $cancelled = $false

    function Send-AdLogProgress {
        param(
            [string]$FileName,
            [int]$Index,
            [int]$Count,
            [int]$FileLines,
            [long]$BytesRead,
            [long]$TotalBytes
        )

        if (-not $ProgressCallback) { return }
        $now = [datetime]::UtcNow
        $elapsed = [math]::Max(0.001, ($now - $started).TotalSeconds)
        $portion = 0.0
        if ($Count -gt 0) {
            $portion = (($Index - 1) + ([double]$BytesRead / [math]::Max(1L, $TotalBytes))) / $Count
        }
        & $ProgressCallback @{
            FileName    = $FileName
            FileIndex   = $Index
            FileCount   = $Count
            FileLines   = $FileLines
            TotalLines  = $grandLines
            Matches     = $results.Count
            Results     = $results
            Percent     = [int]([math]::Min(100, $portion * 100))
            BytesRead   = $BytesRead
            TotalBytes  = $TotalBytes
            LinesPerSec = [int]($grandLines / $elapsed)
            Elapsed     = $elapsed
        }
    }

    foreach ($file in $files) {
        $fileIndex++
        if (-not (Test-Path -LiteralPath $file.FullName)) { continue }

        if ($ShouldCancel -and (& $ShouldCancel)) { break }

        $encoding = Get-AdLogEncoding -Name $EncodingName -FilePath $file.FullName
        $totalBytes = [math]::Max(1L, $file.Length)
        $lineNumber = 0

        $stream = $null
        $reader = $null
        try {
            $stream = [System.IO.FileStream]::new(
                $file.FullName,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite,
                65536,
                [System.IO.FileOptions]::SequentialScan
            )
            $reader = New-Object System.IO.StreamReader($stream, $encoding, $true, 65536)
            Send-AdLogProgress -FileName $file.Name -Index $fileIndex -Count $fileCount -FileLines 0 -BytesRead 0 -TotalBytes $totalBytes

            while ($null -ne ($line = $reader.ReadLine())) {
                $lineNumber++
                $grandLines++

                if (Test-AdLogLineMatch -Line $line -SearchTerm $SearchTerm -CaseInsensitive $CaseInsensitive -UseRegex $UseRegex -CompiledRegex $compiled) {
                    $results.Add((New-AdLogEntry -Line $line -FileName $file.Name -LineNumber $lineNumber))
                }

                $now = [datetime]::UtcNow
                $due = ($lineNumber % 8192 -eq 0) -or (($now - $lastReport).TotalMilliseconds -ge 120)
                if ($due) {
                    if ($ShouldCancel -and (& $ShouldCancel)) {
                        $cancelled = $true
                        break
                    }
                    Send-AdLogProgress -FileName $file.Name -Index $fileIndex -Count $fileCount -FileLines $lineNumber -BytesRead $stream.Position -TotalBytes $totalBytes
                    $lastReport = $now
                }
            }

            if ($cancelled) { break }
            Send-AdLogProgress -FileName $file.Name -Index $fileIndex -Count $fileCount -FileLines $lineNumber -BytesRead $totalBytes -TotalBytes $totalBytes
        } catch {
            if ($ErrorLog) {
                [void]$ErrorLog.Add("[FileError] $($file.FullName) - $($_.Exception.Message)")
            }
        } finally {
            if ($reader) { $reader.Dispose() }
            elseif ($stream) { $stream.Dispose() }
        }
    }

    # Unary comma keeps the list intact. A bare `return $results` enumerates
    # the items, so the caller would receive $null / a single object / an array
    # and the GUI would think the search found nothing.
    return , $results
}

function Sort-AdLogEntries {
    param(
        [System.Collections.IList]$Entries,
        [bool]$Descending
    )

    $dated = New-Object 'System.Collections.Generic.List[AdLogEntry]'
    $undated = New-Object 'System.Collections.Generic.List[AdLogEntry]'
    foreach ($entry in $Entries) {
        if ($entry.HasTimestamp) { $dated.Add($entry) } else { $undated.Add($entry) }
    }

    $sortedDated = if ($Descending) {
        $dated | Sort-Object SortKey -Descending
    } else {
        $dated | Sort-Object SortKey
    }

    $output = New-Object 'System.Collections.Generic.List[AdLogEntry]'
    foreach ($entry in $sortedDated) { $output.Add($entry) }
    foreach ($entry in $undated) { $output.Add($entry) }
    return , $output
}

function Select-AdLogEntries {
    param(
        [System.Collections.IList]$Entries,
        [string]$FilterText,
        [string]$EventKind
    )

    $hasFilter = -not [string]::IsNullOrWhiteSpace($FilterText)
    $hasEvent = -not [string]::IsNullOrWhiteSpace($EventKind) -and $EventKind -ne 'All events'
    $output = New-Object 'System.Collections.Generic.List[AdLogEntry]'

    foreach ($entry in $Entries) {
        if ($hasEvent -and $entry.Event -ne $EventKind) { continue }
        if ($hasFilter) {
            $hit = ($entry.Text.IndexOf($FilterText, [StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                   ($entry.Account.IndexOf($FilterText, [StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                   ($entry.Actor.IndexOf($FilterText, [StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                   ($entry.HostName.IndexOf($FilterText, [StringComparison]::OrdinalIgnoreCase) -ge 0)
            if (-not $hit) { continue }
        }
        $output.Add($entry)
    }
    return , $output
}

# ============================================================
# GUI
# ============================================================
function New-FlatButton {
    param(
        [string]$Text,
        [int]$Width,
        [int]$Height = 32,
        [System.Drawing.Color]$BackColor
    )

    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $Text
    $btn.Size = New-Object System.Drawing.Size($Width, $Height)
    $btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btn.BackColor = $BackColor
    $btn.ForeColor = [System.Drawing.Color]::White
    $btn.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $btn.FlatAppearance.BorderSize = 0
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
    return $btn
}

function Get-AdLogEventColor {
    param([string]$EventKind)

    switch ($EventKind) {
        'Added'    { return [System.Drawing.Color]::FromArgb(220, 245, 230) }
        'Removed'  { return [System.Drawing.Color]::FromArgb(255, 228, 228) }
        'Modified' { return [System.Drawing.Color]::FromArgb(255, 244, 214) }
        'Disabled' { return [System.Drawing.Color]::FromArgb(255, 236, 220) }
        'Enabled'  { return [System.Drawing.Color]::FromArgb(220, 240, 255) }
        'Deleted'  { return [System.Drawing.Color]::FromArgb(255, 214, 214) }
        'Created'  { return [System.Drawing.Color]::FromArgb(226, 240, 255) }
        'Locked'   { return [System.Drawing.Color]::FromArgb(255, 228, 200) }
        'Unlocked' { return [System.Drawing.Color]::FromArgb(230, 255, 246) }
        'Password' { return [System.Drawing.Color]::FromArgb(236, 228, 255) }
        default    { return [System.Drawing.Color]::White }
    }
}

function Start-AdLogViewer {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    try {
        Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;
public static class AdLogDpi {
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
}
"@ -ErrorAction Stop
        [AdLogDpi]::SetProcessDPIAware() | Out-Null
    } catch { }

    [System.Windows.Forms.Application]::EnableVisualStyles()
    [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

    $script:AllRows = New-Object 'System.Collections.Generic.List[AdLogEntry]'
    $script:VisibleRows = New-Object 'System.Collections.Generic.List[AdLogEntry]'
    $script:SortDescending = $false
    $script:IsSearching = $false
    $script:CancelRequested = $false
    $script:LastErrorLogPath = $null

    $navy       = [System.Drawing.Color]::FromArgb(24, 42, 68)
    $navyMid    = [System.Drawing.Color]::FromArgb(32, 52, 80)
    $pageBg     = [System.Drawing.Color]::FromArgb(245, 247, 250)
    $cardBorder = [System.Drawing.Color]::FromArgb(220, 225, 232)
    $textDark   = [System.Drawing.Color]::FromArgb(24, 42, 68)
    $muted      = [System.Drawing.Color]::FromArgb(120, 130, 140)
    $blue       = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $green      = [System.Drawing.Color]::FromArgb(16, 137, 62)
    $amber      = [System.Drawing.Color]::FromArgb(202, 131, 0)
    $red        = [System.Drawing.Color]::FromArgb(196, 43, 28)
    $slate      = [System.Drawing.Color]::FromArgb(55, 65, 81)
    $teal       = [System.Drawing.Color]::FromArgb(0, 150, 136)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Active Directory Log Viewer v$($script:AppVersion)"
    $form.Size = New-Object System.Drawing.Size(1280, 820)
    $form.MinimumSize = New-Object System.Drawing.Size(960, 640)
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.BackColor = $pageBg
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
    $form.MaximizeBox = $true
    $form.MinimizeBox = $true
    $form.KeyPreview = $true
    $form.AllowDrop = $true
    $form.Icon = [System.Drawing.SystemIcons]::Information

    # --- Header ---
    $header = New-Object System.Windows.Forms.Panel
    $header.Dock = [System.Windows.Forms.DockStyle]::Top
    $header.Height = 58
    $header.BackColor = $navy

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = 'Active Directory Log Viewer'
    $lblTitle.Font = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor = [System.Drawing.Color]::White
    $lblTitle.AutoSize = $true
    $lblTitle.Location = New-Object System.Drawing.Point(20, 13)
    $header.Controls.Add($lblTitle)

    $lblVersion = New-Object System.Windows.Forms.Label
    $lblVersion.Text = "v$($script:AppVersion)  |  Streaming ingest  |  PowerShell 5.1+"
    $lblVersion.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $lblVersion.ForeColor = [System.Drawing.Color]::FromArgb(160, 185, 215)
    $lblVersion.AutoSize = $true
    $lblVersion.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $lblVersion.Location = New-Object System.Drawing.Point(880, 20)
    $header.Controls.Add($lblVersion)

    # --- Search card ---
    $searchCard = New-Object System.Windows.Forms.Panel
    $searchCard.Dock = [System.Windows.Forms.DockStyle]::Top
    $searchCard.Height = 168
    $searchCard.BackColor = [System.Drawing.Color]::White
    $searchCard.Padding = New-Object System.Windows.Forms.Padding(16, 10, 16, 8)

    $tlp = New-Object System.Windows.Forms.TableLayoutPanel
    $tlp.Dock = [System.Windows.Forms.DockStyle]::Fill
    $tlp.ColumnCount = 7
    $tlp.RowCount = 3
    $tlp.BackColor = [System.Drawing.Color]::White
    [void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 96)))
    [void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 100)))
    [void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 128)))
    [void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 118)))
    [void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 150)))
    [void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 168)))
    [void]$tlp.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 36)))
    [void]$tlp.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 36)))
    [void]$tlp.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    function New-FieldLabel([string]$Text) {
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text = $Text
        $lbl.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $lbl.Dock = [System.Windows.Forms.DockStyle]::Fill
        $lbl.ForeColor = $textDark
        $lbl.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
        return $lbl
    }

    $lblPath = New-FieldLabel 'Path'
    $txtPath = New-Object System.Windows.Forms.TextBox
    $txtPath.Dock = [System.Windows.Forms.DockStyle]::Fill
    $txtPath.Font = New-Object System.Drawing.Font('Consolas', 10)
    $tlp.SetColumnSpan($txtPath, 3)

    $btnBrowse = New-FlatButton -Text 'Browse' -Width 92 -BackColor $slate
    $btnBrowse.Dock = [System.Windows.Forms.DockStyle]::Fill

    $chkFolder = New-Object System.Windows.Forms.CheckBox
    $chkFolder.Text = 'Search folder'
    $chkFolder.Dock = [System.Windows.Forms.DockStyle]::Fill
    $chkFolder.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft

    $chkRecursive = New-Object System.Windows.Forms.CheckBox
    $chkRecursive.Text = 'Include subfolders'
    $chkRecursive.Dock = [System.Windows.Forms.DockStyle]::Fill
    $chkRecursive.Enabled = $false

    $lblSearch = New-FieldLabel 'Search'
    $txtSearch = New-Object System.Windows.Forms.TextBox
    $txtSearch.Dock = [System.Windows.Forms.DockStyle]::Fill
    $txtSearch.Font = New-Object System.Drawing.Font('Consolas', 10)
    $tlp.SetColumnSpan($txtSearch, 2)

    $chkCase = New-Object System.Windows.Forms.CheckBox
    $chkCase.Text = 'Ignore case'
    $chkCase.Checked = $true
    $chkCase.Dock = [System.Windows.Forms.DockStyle]::Fill

    $chkRegex = New-Object System.Windows.Forms.CheckBox
    $chkRegex.Text = 'Use regex'
    $chkRegex.Dock = [System.Windows.Forms.DockStyle]::Fill

    $chkLog = New-Object System.Windows.Forms.CheckBox
    $chkLog.Text = 'Log errors to Desktop'
    $chkLog.Dock = [System.Windows.Forms.DockStyle]::Fill

    $cmbEncoding = New-Object System.Windows.Forms.ComboBox
    $cmbEncoding.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $cmbEncoding.Dock = [System.Windows.Forms.DockStyle]::Fill
    [void]$cmbEncoding.Items.AddRange(@('Auto (BOM)', 'UTF-8', 'Unicode (UTF-16)', 'ANSI (Default)'))
    $cmbEncoding.SelectedIndex = 0

    $buttonBar = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttonBar.Dock = [System.Windows.Forms.DockStyle]::Fill
    $buttonBar.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
    $buttonBar.WrapContents = $false
    $buttonBar.Padding = New-Object System.Windows.Forms.Padding(0, 8, 0, 0)
    $tlp.SetColumnSpan($buttonBar, 7)

    $btnSearch = New-FlatButton -Text 'Search' -Width 110 -BackColor $blue
    $btnCancel = New-FlatButton -Text 'Cancel' -Width 96 -BackColor $red
    $btnCancel.Enabled = $false
    $btnSort   = New-FlatButton -Text 'Sort by date' -Width 118 -BackColor $amber
    $btnExport = New-FlatButton -Text 'Export' -Width 96 -BackColor $teal
    $btnCopy   = New-FlatButton -Text 'Copy' -Width 86 -BackColor $slate
    $btnClear  = New-FlatButton -Text 'Clear' -Width 86 -BackColor ([System.Drawing.Color]::FromArgb(100, 110, 125))

    $lblHint = New-Object System.Windows.Forms.Label
    $lblHint.Text = 'Blank search loads every line. Drag a file or folder onto the window. Resize freely — the grid fills the space.'
    $lblHint.AutoSize = $true
    $lblHint.ForeColor = $muted
    $lblHint.Margin = New-Object System.Windows.Forms.Padding(12, 12, 0, 0)

    $buttonBar.Controls.AddRange(@($btnSearch, $btnCancel, $btnSort, $btnExport, $btnCopy, $btnClear, $lblHint))

    $tlp.Controls.Add($lblPath, 0, 0)
    $tlp.Controls.Add($txtPath, 1, 0)
    $tlp.Controls.Add($btnBrowse, 4, 0)
    $tlp.Controls.Add($chkFolder, 5, 0)
    $tlp.Controls.Add($chkRecursive, 6, 0)

    $tlp.Controls.Add($lblSearch, 0, 1)
    $tlp.Controls.Add($txtSearch, 1, 1)
    $tlp.Controls.Add($chkCase, 3, 1)
    $tlp.Controls.Add($chkRegex, 4, 1)
    $tlp.Controls.Add($chkLog, 5, 1)
    $tlp.Controls.Add($cmbEncoding, 6, 1)

    $tlp.Controls.Add($buttonBar, 0, 2)
    $searchCard.Controls.Add($tlp)

    $accent = New-Object System.Windows.Forms.Panel
    $accent.Dock = [System.Windows.Forms.DockStyle]::Top
    $accent.Height = 3
    $accent.BackColor = $blue

    # --- Filter bar ---
    $filterBar = New-Object System.Windows.Forms.Panel
    $filterBar.Dock = [System.Windows.Forms.DockStyle]::Top
    $filterBar.Height = 44
    $filterBar.BackColor = $pageBg
    $filterBar.Padding = New-Object System.Windows.Forms.Padding(16, 6, 16, 6)

    $filterTlp = New-Object System.Windows.Forms.TableLayoutPanel
    $filterTlp.Dock = [System.Windows.Forms.DockStyle]::Fill
    $filterTlp.ColumnCount = 6
    $filterTlp.RowCount = 1
    [void]$filterTlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 96)))
    [void]$filterTlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$filterTlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 150)))
    [void]$filterTlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 130)))
    [void]$filterTlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 220)))
    [void]$filterTlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 90)))

    $lblFilter = New-FieldLabel 'Filter results'
    $txtFilter = New-Object System.Windows.Forms.TextBox
    $txtFilter.Dock = [System.Windows.Forms.DockStyle]::Fill
    $txtFilter.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    $cmbEvent = New-Object System.Windows.Forms.ComboBox
    $cmbEvent.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $cmbEvent.Dock = [System.Windows.Forms.DockStyle]::Fill
    [void]$cmbEvent.Items.AddRange(@(
        'All events', 'Added', 'Removed', 'Modified', 'Created', 'Deleted',
        'Enabled', 'Disabled', 'Locked', 'Unlocked', 'Password', 'Other'
    ))
    $cmbEvent.SelectedIndex = 0

    $cmbFont = New-Object System.Windows.Forms.ComboBox
    $cmbFont.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $cmbFont.Dock = [System.Windows.Forms.DockStyle]::Fill
    [void]$cmbFont.Items.AddRange(@('Grid font 9', 'Grid font 10', 'Grid font 11', 'Grid font 12', 'Grid font 14'))
    $cmbFont.SelectedIndex = 1

    $lblCounts = New-Object System.Windows.Forms.Label
    $lblCounts.Text = 'Added 0   Removed 0   Modified 0'
    $lblCounts.Dock = [System.Windows.Forms.DockStyle]::Fill
    $lblCounts.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $lblCounts.ForeColor = $muted

    $lblShown = New-Object System.Windows.Forms.Label
    $lblShown.Text = '0 shown'
    $lblShown.Dock = [System.Windows.Forms.DockStyle]::Fill
    $lblShown.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
    $lblShown.ForeColor = $textDark
    $lblShown.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)

    $filterTlp.Controls.Add($lblFilter, 0, 0)
    $filterTlp.Controls.Add($txtFilter, 1, 0)
    $filterTlp.Controls.Add($cmbEvent, 2, 0)
    $filterTlp.Controls.Add($cmbFont, 3, 0)
    $filterTlp.Controls.Add($lblCounts, 4, 0)
    $filterTlp.Controls.Add($lblShown, 5, 0)
    $filterBar.Controls.Add($filterTlp)

    # --- Status ---
    $status = New-Object System.Windows.Forms.StatusStrip
    $status.SizingGrip = $true
    $status.BackColor = $navyMid
    $status.ForeColor = [System.Drawing.Color]::White
    $status.Padding = New-Object System.Windows.Forms.Padding(2, 2, 16, 2)

    $statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusLabel.Text = 'Ready — choose a log file or folder and search.'
    $statusLabel.Spring = $true
    $statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $statusLabel.ForeColor = [System.Drawing.Color]::White

    $progressBar = New-Object System.Windows.Forms.ToolStripProgressBar
    $progressBar.Minimum = 0
    $progressBar.Maximum = 100
    $progressBar.Value = 0
    $progressBar.Width = 220
    $progressBar.Visible = $false

    $statusMatches = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusMatches.Text = 'Matches: 0'
    $statusMatches.ForeColor = [System.Drawing.Color]::FromArgb(160, 220, 180)

    $statusRate = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusRate.Text = ''
    $statusRate.ForeColor = [System.Drawing.Color]::FromArgb(160, 185, 215)

    [void]$status.Items.AddRange(@($statusLabel, $progressBar, $statusMatches, $statusRate))

    # --- Split: grid / detail ---
    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = [System.Windows.Forms.DockStyle]::Fill
    $split.Orientation = [System.Windows.Forms.Orientation]::Horizontal
    $split.SplitterWidth = 6
    $split.BackColor = $cardBorder
    $split.Panel1.BackColor = $pageBg
    $split.Panel2.BackColor = [System.Drawing.Color]::White
    $split.Panel1MinSize = 160
    $split.Panel2MinSize = 80

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = [System.Windows.Forms.DockStyle]::Fill
    $grid.BackgroundColor = [System.Drawing.Color]::White
    $grid.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $grid.RowHeadersVisible = $false
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToResizeRows = $false
    $grid.ReadOnly = $true
    $grid.VirtualMode = $true
    $grid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $grid.MultiSelect = $true
    $grid.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
    $grid.AutoSizeRowsMode = [System.Windows.Forms.DataGridViewAutoSizeRowsMode]::None
    $grid.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::AutoSize
    $grid.EnableHeadersVisualStyles = $false
    $grid.ColumnHeadersDefaultCellStyle.BackColor = $navy
    $grid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $grid.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $grid.DefaultCellStyle.Font = New-Object System.Drawing.Font('Consolas', 10)
    $grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $grid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $grid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(248, 250, 252)
    $grid.RowTemplate.Height = 24
    $grid.GridColor = $cardBorder
    $grid.ClipboardCopyMode = [System.Windows.Forms.DataGridViewClipboardCopyMode]::EnableWithoutHeaderText

    $colMap = @(
        @{ Name = 'Timestamp'; Fill = 16 },
        @{ Name = 'Event';     Fill = 9 },
        @{ Name = 'Account';   Fill = 12 },
        @{ Name = 'Actor';     Fill = 12 },
        @{ Name = 'Host';      Fill = 12 },
        @{ Name = 'Line';      Fill = 39 }
    )
    foreach ($def in $colMap) {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $col.Name = $def.Name
        $col.HeaderText = $def.Name
        $col.FillWeight = [single]$def.Fill
        $col.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::NotSortable
        if ($def.Name -eq 'Line') { $col.MinimumWidth = 220 }
        [void]$grid.Columns.Add($col)
    }

    $detailPanel = New-Object System.Windows.Forms.Panel
    $detailPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $detailPanel.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 8)
    $detailPanel.BackColor = [System.Drawing.Color]::White

    $lblDetail = New-Object System.Windows.Forms.Label
    $lblDetail.Text = 'Selected line'
    $lblDetail.Dock = [System.Windows.Forms.DockStyle]::Top
    $lblDetail.Height = 20
    $lblDetail.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $lblDetail.ForeColor = $textDark

    $txtDetail = New-Object System.Windows.Forms.TextBox
    $txtDetail.Multiline = $true
    $txtDetail.ReadOnly = $true
    $txtDetail.ScrollBars = 'Vertical'
    $txtDetail.Dock = [System.Windows.Forms.DockStyle]::Fill
    $txtDetail.Font = New-Object System.Drawing.Font('Consolas', 10)
    $txtDetail.BackColor = [System.Drawing.Color]::FromArgb(248, 250, 252)
    $txtDetail.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $txtDetail.WordWrap = $true

    $detailPanel.Controls.Add($txtDetail)
    $detailPanel.Controls.Add($lblDetail)

    $split.Panel1.Controls.Add($grid)
    $split.Panel2.Controls.Add($detailPanel)

    $form.Controls.Add($split)
    $form.Controls.Add($status)
    $form.Controls.Add($filterBar)
    $form.Controls.Add($accent)
    $form.Controls.Add($searchCard)
    $form.Controls.Add($header)

    $form.Add_Shown({
        if ($split.Height -gt 240) {
            $split.SplitterDistance = [math]::Max(200, $split.Height - 140)
        }
        $lblVersion.Left = [math]::Max(420, $header.ClientSize.Width - $lblVersion.PreferredWidth - 20)
    })
    $header.Add_Resize({
        $lblVersion.Left = [math]::Max(420, $header.ClientSize.Width - $lblVersion.PreferredWidth - 20)
    })

    function Set-StatusText {
        param(
            [string]$Text,
            [System.Drawing.Color]$Color = [System.Drawing.Color]::White
        )
        $statusLabel.Text = $Text
        $statusLabel.ForeColor = $Color
    }

    function Update-VisibleRows {
        $script:AllRows = ConvertTo-AdLogList $script:AllRows
        $script:VisibleRows = ConvertTo-AdLogList (
            Select-AdLogEntries -Entries $script:AllRows -FilterText $txtFilter.Text -EventKind ([string]$cmbEvent.SelectedItem)
        )
        $shown = Get-AdLogEntryCount $script:VisibleRows
        $grid.RowCount = 0
        $grid.RowCount = $shown
        $grid.Refresh()

        $added = 0; $removed = 0; $modified = 0
        foreach ($row in $script:AllRows) {
            switch ($row.Event) {
                'Added'    { $added++ }
                'Removed'  { $removed++ }
                'Modified' { $modified++ }
            }
        }
        $lblCounts.Text = "Added $added   Removed $removed   Modified $modified"
        $lblShown.Text = "$shown shown"
        $statusMatches.Text = "Matches: $(Get-AdLogEntryCount $script:AllRows)"
    }

    function Show-SelectedDetail {
        if ($grid.CurrentCell -and $grid.CurrentCell.RowIndex -ge 0 -and $grid.CurrentCell.RowIndex -lt $script:VisibleRows.Count) {
            $entry = $script:VisibleRows[$grid.CurrentCell.RowIndex]
            $txtDetail.Text = "$( $entry.TimestampText )  [$($entry.Event)]  $($entry.FileName):$($entry.LineNumber)`r`n$($entry.Text)"
        } else {
            $txtDetail.Clear()
        }
    }

    function Write-ErrorLog([string]$Message) {
        if (-not $chkLog.Checked) { return }
        if (-not $script:LastErrorLogPath) {
            $desktop = [Environment]::GetFolderPath('Desktop')
            $script:LastErrorLogPath = Join-Path $desktop ("ADLogViewer_Errors_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date))
        }
        $Message | Out-File -FilePath $script:LastErrorLogPath -Append -Encoding UTF8
    }

    $grid.Add_CellValueNeeded({
        param($sender, $e)
        if ($e.RowIndex -lt 0 -or $e.RowIndex -ge $script:VisibleRows.Count) { return }
        $item = $script:VisibleRows[$e.RowIndex]
        switch ($e.ColumnIndex) {
            0 { $e.Value = $item.TimestampText }
            1 { $e.Value = $item.Event }
            2 { $e.Value = $item.Account }
            3 { $e.Value = $item.Actor }
            4 { $e.Value = $item.HostName }
            5 { $e.Value = $item.Text }
        }
    })

    $grid.Add_CellFormatting({
        param($sender, $e)
        if ($e.RowIndex -lt 0 -or $e.RowIndex -ge $script:VisibleRows.Count) { return }
        if ($e.ColumnIndex -eq 1) {
            $e.CellStyle.BackColor = Get-AdLogEventColor -EventKind $script:VisibleRows[$e.RowIndex].Event
            $e.CellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
        }
    })

    $grid.Add_SelectionChanged({ Show-SelectedDetail })
    $grid.Add_CellDoubleClick({ Show-SelectedDetail })

    $ctx = New-Object System.Windows.Forms.ContextMenuStrip
    $mCopy = $ctx.Items.Add('Copy selected lines')
    $mCopyAll = $ctx.Items.Add('Copy all visible lines')
    $mExport = $ctx.Items.Add('Export visible results...')
    $grid.ContextMenuStrip = $ctx

    $chkFolder.Add_CheckedChanged({
        $chkRecursive.Enabled = $chkFolder.Checked
    })

    $btnBrowse.Add_Click({
        if ($chkFolder.Checked) {
            $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
            $dialog.Description = 'Select the folder that contains AD log files'
            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $txtPath.Text = $dialog.SelectedPath
            }
        } else {
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.Filter = 'Text files (*.txt)|*.txt|Log files (*.log)|*.log|All files (*.*)|*.*'
            $dialog.Title = 'Open AD log file'
            $dialog.Multiselect = $false
            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $txtPath.Text = $dialog.FileName
            }
        }
    })

    $form.Add_DragEnter({
        param($sender, $e)
        if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
            $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
        }
    })

    $form.Add_DragDrop({
        param($sender, $e)
        $dropped = @($e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop))
        if ($dropped.Count -lt 1) { return }
        $txtPath.Text = $dropped[0]
        if (Test-Path -LiteralPath $dropped[0] -PathType Container) {
            $chkFolder.Checked = $true
        } else {
            $chkFolder.Checked = $false
        }
    })

    function Copy-VisibleSelection {
        param([bool]$AllVisible)

        $lines = New-Object System.Collections.Generic.List[string]
        if ($AllVisible) {
            foreach ($row in $script:VisibleRows) { $lines.Add($row.Text) }
        } else {
            $indexes = New-Object System.Collections.Generic.List[int]
            foreach ($row in $grid.SelectedRows) { $indexes.Add($row.Index) }
            foreach ($idx in ($indexes | Sort-Object)) {
                if ($idx -ge 0 -and $idx -lt $script:VisibleRows.Count) {
                    $lines.Add($script:VisibleRows[$idx].Text)
                }
            }
        }

        if ($lines.Count -eq 0) { return }
        [System.Windows.Forms.Clipboard]::SetText(($lines -join [Environment]::NewLine))
        Set-StatusText "Copied $($lines.Count) line(s) to the clipboard." ([System.Drawing.Color]::FromArgb(160, 220, 180))
    }

    function Export-VisibleResults {
        if ($script:VisibleRows.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show('There are no visible results to export.', 'Export', 'OK', 'Information') | Out-Null
            return
        }

        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Filter = 'CSV (*.csv)|*.csv|Text (*.txt)|*.txt|All files (*.*)|*.*'
        $dialog.FileName = "ADLogViewer_Results_{0:yyyyMMdd_HHmmss}" -f (Get-Date)
        $dialog.Title = 'Export visible results'
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

        try {
            if ($dialog.FileName -like '*.csv') {
                $script:VisibleRows |
                    Select-Object TimestampText, Event, Account, Actor, HostName, FileName, LineNumber, Text |
                    Export-Csv -Path $dialog.FileName -NoTypeInformation -Encoding UTF8
            } else {
                $script:VisibleRows | ForEach-Object { $_.Text } | Set-Content -Path $dialog.FileName -Encoding UTF8
            }
            Set-StatusText "Exported $($script:VisibleRows.Count) row(s) to $($dialog.FileName)." ([System.Drawing.Color]::FromArgb(160, 220, 180))
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed:`n$($_.Exception.Message)", 'Export error', 'OK', 'Error') | Out-Null
        }
    }

    $mCopy.Add_Click({ Copy-VisibleSelection -AllVisible:$false })
    $mCopyAll.Add_Click({ Copy-VisibleSelection -AllVisible:$true })
    $mExport.Add_Click({ Export-VisibleResults })
    $btnCopy.Add_Click({ Copy-VisibleSelection -AllVisible:$false })
    $btnExport.Add_Click({ Export-VisibleResults })

    $btnClear.Add_Click({
        if ($script:IsSearching) { return }
        $script:AllRows = New-Object 'System.Collections.Generic.List[AdLogEntry]'
        $txtFilter.Clear()
        $cmbEvent.SelectedIndex = 0
        $txtDetail.Clear()
        Update-VisibleRows
        $progressBar.Value = 0
        $progressBar.Visible = $false
        $statusRate.Text = ''
        Set-StatusText 'Results cleared.'
    })

    $btnSort.Add_Click({
        if ((Get-AdLogEntryCount $script:AllRows) -eq 0) { return }
        $script:SortDescending = -not $script:SortDescending
        $script:AllRows = ConvertTo-AdLogList (Sort-AdLogEntries -Entries $script:AllRows -Descending $script:SortDescending)
        Update-VisibleRows
        if ($script:SortDescending) {
            $btnSort.Text = 'Sort newest'
            Set-StatusText 'Sorted newest first. Undated lines stay at the bottom.' ([System.Drawing.Color]::FromArgb(160, 185, 215))
        } else {
            $btnSort.Text = 'Sort oldest'
            Set-StatusText 'Sorted oldest first. Undated lines stay at the bottom.' ([System.Drawing.Color]::FromArgb(160, 185, 215))
        }
    })

    $filterTimer = New-Object System.Windows.Forms.Timer
    $filterTimer.Interval = 180
    $filterTimer.Add_Tick({
        $filterTimer.Stop()
        Update-VisibleRows
    })
    $txtFilter.Add_TextChanged({ $filterTimer.Stop(); $filterTimer.Start() })
    $cmbEvent.Add_SelectedIndexChanged({ Update-VisibleRows })

    $cmbFont.Add_SelectedIndexChanged({
        $size = 10
        switch ($cmbFont.SelectedIndex) {
            0 { $size = 9 }
            1 { $size = 10 }
            2 { $size = 11 }
            3 { $size = 12 }
            4 { $size = 14 }
        }
        $grid.DefaultCellStyle.Font = New-Object System.Drawing.Font('Consolas', $size)
        $grid.RowTemplate.Height = [math]::Max(22, $size + 14)
        $grid.Refresh()
    })

    function Complete-LogSearchUi {
        $script:IsSearching = $false
        $btnSearch.Enabled = $true
        $btnCancel.Enabled = $false
        $btnSort.Enabled = $true
        $btnExport.Enabled = $true
        $btnClear.Enabled = $true
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        $progressBar.Visible = $false
        $statusRate.Text = ''
    }

    function Start-LogSearch {
        if ($script:IsSearching) { return }

        $path = $txtPath.Text.Trim()
        $term = $txtSearch.Text
        if ([string]::IsNullOrWhiteSpace($path)) {
            [System.Windows.Forms.MessageBox]::Show('Choose a log file or folder first.', 'Path required', 'OK', 'Warning') | Out-Null
            return
        }
        if (-not (Test-Path -LiteralPath $path)) {
            [System.Windows.Forms.MessageBox]::Show('The specified path does not exist.', 'Invalid path', 'OK', 'Error') | Out-Null
            return
        }
        if ($chkFolder.Checked -and -not (Test-Path -LiteralPath $path -PathType Container)) {
            [System.Windows.Forms.MessageBox]::Show('Search folder is checked, but the path is not a folder.', 'Invalid path', 'OK', 'Warning') | Out-Null
            return
        }
        if (-not $chkFolder.Checked -and (Test-Path -LiteralPath $path -PathType Container)) {
            [System.Windows.Forms.MessageBox]::Show('The path is a folder. Check "Search folder" or pick a file.', 'Invalid path', 'OK', 'Warning') | Out-Null
            return
        }

        if ($chkRegex.Checked -and -not [string]::IsNullOrEmpty($term)) {
            try {
                [void][regex]::new($term)
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Invalid regular expression:`n$($_.Exception.Message)", 'Regex error', 'OK', 'Error') | Out-Null
                return
            }
        }

        $script:LastErrorLogPath = $null
        $script:CancelRequested = $false
        $script:IsSearching = $true
        $script:AllRows = New-Object 'System.Collections.Generic.List[AdLogEntry]'
        $script:VisibleRows = $script:AllRows
        $grid.RowCount = 0
        $txtDetail.Clear()
        $lblShown.Text = '0 shown'
        $lblCounts.Text = 'Added 0   Removed 0   Modified 0'
        $statusMatches.Text = 'Matches: 0'

        $btnSearch.Enabled = $false
        $btnCancel.Enabled = $true
        $btnSort.Enabled = $false
        $btnExport.Enabled = $false
        $btnClear.Enabled = $false
        $progressBar.Visible = $true
        $progressBar.Value = 0
        $form.Cursor = [System.Windows.Forms.Cursors]::AppStarting
        Set-StatusText 'Starting ingest...'
        [System.Windows.Forms.Application]::DoEvents()

        $errorLog = New-Object System.Collections.Generic.List[string]
        try {
            $found = Search-AdLogFiles `
                -Path $path `
                -SearchTerm $term `
                -IsFolder ([bool]$chkFolder.Checked) `
                -Recursive ([bool]$chkRecursive.Checked) `
                -CaseInsensitive ([bool]$chkCase.Checked) `
                -UseRegex ([bool]$chkRegex.Checked) `
                -EncodingName ([string]$cmbEncoding.SelectedItem) `
                -ErrorLog $errorLog `
                -ShouldCancel { $script:CancelRequested } `
                -ProgressCallback {
                    param($info)
                    if ($info.Results) {
                        $script:AllRows = $info.Results
                        $script:VisibleRows = $info.Results
                    }
                    $progressBar.Visible = $true
                    $progressBar.Value = [math]::Min(100, [math]::Max(0, [int]$info.Percent))
                    $statusMatches.Text = "Matches: $($info.Matches)"
                    $statusRate.Text = "$($info.LinesPerSec) lines/s"
                    Set-StatusText ("Ingesting {0} ({1}/{2})  ·  {3:N0} lines  ·  {4:N0} matches  ·  {5:N0}%" -f `
                        $info.FileName, $info.FileIndex, $info.FileCount, $info.TotalLines, $info.Matches, $info.Percent)
                    $grid.RowCount = [int]$info.Matches
                    $lblShown.Text = "$($info.Matches) shown"
                    [System.Windows.Forms.Application]::DoEvents()
                }
            $script:AllRows = ConvertTo-AdLogList $found
        } catch {
            Complete-LogSearchUi
            Set-StatusText "Search failed: $($_.Exception.Message)" ([System.Drawing.Color]::FromArgb(255, 170, 170))
            Write-ErrorLog "[RuntimeError] $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Search error', 'OK', 'Error') | Out-Null
            return
        }

        foreach ($line in $errorLog) { Write-ErrorLog $line }

        $cancelled = $script:CancelRequested
        $script:AllRows = ConvertTo-AdLogList (Sort-AdLogEntries -Entries $script:AllRows -Descending $false)
        $script:SortDescending = $false
        $btnSort.Text = 'Sort by date'
        Update-VisibleRows
        Complete-LogSearchUi

        $matchCount = Get-AdLogEntryCount $script:AllRows
        if ($cancelled) {
            Set-StatusText "Cancelled. Loaded $matchCount match(es) so far." ([System.Drawing.Color]::FromArgb(255, 214, 150))
        } elseif ($matchCount -eq 0) {
            Set-StatusText 'Search complete. No matching entries.'
            [System.Windows.Forms.MessageBox]::Show('No matching entries found.', 'No results', 'OK', 'Information') | Out-Null
        } else {
            Set-StatusText "Search complete. $matchCount result(s) loaded." ([System.Drawing.Color]::FromArgb(160, 220, 180))
        }
    }

    $btnSearch.Add_Click({ Start-LogSearch })
    $btnCancel.Add_Click({
        if ($script:IsSearching) {
            $script:CancelRequested = $true
            Set-StatusText 'Cancelling...' ([System.Drawing.Color]::FromArgb(255, 214, 150))
        }
    })

    $txtSearch.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $e.SuppressKeyPress = $true
            Start-LogSearch
        }
    })
    $txtPath.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $e.SuppressKeyPress = $true
            Start-LogSearch
        }
    })

    $form.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape -and $script:IsSearching) {
            $btnCancel.PerformClick()
        } elseif ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::F) {
            $txtFilter.Focus()
        } elseif ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::E) {
            Export-VisibleResults
        }
    })

    $form.Add_FormClosing({
        $script:CancelRequested = $true
    })

    $settingsPath = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'ADLogViewer\settings.json'
    if (Test-Path -LiteralPath $settingsPath) {
        try {
            $saved = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($saved.Path) { $txtPath.Text = [string]$saved.Path }
            if ($saved.SearchTerm) { $txtSearch.Text = [string]$saved.SearchTerm }
            if ($null -ne $saved.SearchFolder) { $chkFolder.Checked = [bool]$saved.SearchFolder }
            if ($null -ne $saved.IgnoreCase) { $chkCase.Checked = [bool]$saved.IgnoreCase }
        } catch { }
    }

    $form.Add_FormClosed({
        try {
            $dir = Split-Path $settingsPath -Parent
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            @{
                Path         = $txtPath.Text
                SearchTerm   = $txtSearch.Text
                SearchFolder = [bool]$chkFolder.Checked
                IgnoreCase   = [bool]$chkCase.Checked
            } | ConvertTo-Json | Set-Content -LiteralPath $settingsPath -Encoding UTF8
        } catch { }
    })

    [void]$form.ShowDialog()
}

if (-not $SkipGui) {
    $isSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq [System.Threading.ApartmentState]::STA
    if ($isSta) {
        Start-AdLogViewer
    } elseif ($PSCommandPath) {
        $shell = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell' }
        $proc = Start-Process -FilePath $shell -ArgumentList @(
            '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath
        ) -Wait -PassThru
        exit $proc.ExitCode
    } else {
        Start-AdLogViewer
    }
}

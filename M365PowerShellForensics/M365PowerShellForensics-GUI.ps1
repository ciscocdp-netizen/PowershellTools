#Requires -Version 5.1
<#
.SYNOPSIS
    WinForms front end for Microsoft 365 PowerShell / admin-command forensics.

.DESCRIPTION
    Collects the investigation window, suspect accounts/IPs, and collection phases,
    then runs Invoke-M365PowerShellForensics on a background runspace. Cancel
    requests a stop; Force stop aborts the current call. F5 runs, Esc cancels.

    Settings are stored in %APPDATA%\PowershellTools\M365PsForensicsGui\settings.json.
    Suspect account lists are not stored.

.NOTES
    Requires Windows PowerShell 5.1 or PowerShell 7 on Windows, with an STA thread.
    The script relaunches itself with -STA when the current thread is MTA.
    Launch: powershell.exe -STA -File .\M365PowerShellForensics-GUI.ps1
#>
param(
    [switch]$StaReady
)

$script:GuiVersion = '2.1.0'

if (-not $StaReady -and [System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $hostPath = $null
    try { $hostPath = (Get-Process -Id $PID).Path } catch { $hostPath = $null }
    if (-not $hostPath -or $hostPath -notmatch 'powershell') {
        $cmd = Get-Command -Name 'powershell.exe' -ErrorAction SilentlyContinue
        if ($cmd) { $hostPath = $cmd.Source }
    }
    if (-not $hostPath) { $hostPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' }
    $quoted = '"' + ($PSCommandPath -replace '"', '`"') + '"'
    $argumentList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', $quoted, '-StaReady')
    try {
        Start-Process -FilePath $hostPath -ArgumentList $argumentList | Out-Null
    } catch {
        Write-Host "Could not relaunch on an STA thread: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host 'Start this script with: powershell.exe -STA -File M365PowerShellForensics-GUI.ps1'
        exit 1
    }
    exit 0
}

$script:ModulePath = Join-Path $PSScriptRoot 'M365PowerShellForensics.psm1'
if (-not (Test-Path -LiteralPath $script:ModulePath)) {
    Write-Host "Investigation engine not found: $script:ModulePath" -ForegroundColor Red
    exit 1
}

try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
} catch {
    Write-Host "WinForms is not available in this PowerShell host: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Run M365PowerShellForensics-GUI.ps1 on Windows with powershell.exe -STA.'
    exit 1
}

try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch { }
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }

Import-Module $script:ModulePath -Force -DisableNameChecking
$script:EngineVersion = Get-M365PsForensicsVersion
$script:Prereq = Get-M365PsForensicsPrerequisite

$script:Font = New-Object System.Drawing.Font('Segoe UI', 9)
$script:FontBold = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:FontMono = New-Object System.Drawing.Font('Consolas', 9)
$script:ColorBg = [System.Drawing.Color]::FromArgb(245, 247, 250)
$script:ColorHeader = [System.Drawing.Color]::FromArgb(24, 42, 68)
$script:ColorAccent = [System.Drawing.Color]::FromArgb(0, 122, 204)
$script:ColorDanger = [System.Drawing.Color]::FromArgb(180, 35, 24)
$script:ColorOk = [System.Drawing.Color]::FromArgb(6, 118, 71)
$script:ColorMuted = [System.Drawing.Color]::FromArgb(101, 109, 118)
$script:ColorLine = [System.Drawing.Color]::FromArgb(208, 215, 222)

$script:Busy = $false
$script:BusyAction = ''
$script:CancelRequested = $false
$script:AllowClose = $false
$script:CloseAfterStop = $false
$script:InTick = $false
$script:RunHandle = $null
$script:LastReport = $null
$script:LastFolder = $null
$script:SettingsPath = Join-Path (Join-Path $env:APPDATA 'PowershellTools\M365PsForensicsGui') 'settings.json'

function New-Button {
    param([string]$Text, [System.Drawing.Color]$Back, [System.Drawing.Color]$Fore)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Font = $script:Font
    $b.FlatStyle = 'Flat'
    $b.BackColor = $Back
    $b.ForeColor = $Fore
    $b.Height = 30
    $b.Cursor = [System.Windows.Forms.Cursors]::Hand
    return $b
}

function Add-Labeled {
    param($Parent, [int]$Top, [string]$Caption, $Control, [int]$ControlHeight = 24, [int]$LabelWidth = 118)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Caption
    $lbl.Font = $script:Font
    $lbl.ForeColor = [System.Drawing.Color]::FromArgb(31, 35, 40)
    $lbl.Location = New-Object System.Drawing.Point(10, ($Top + 3))
    $lbl.Size = New-Object System.Drawing.Size($LabelWidth, 20)
    $Control.Font = $script:Font
    $Control.Location = New-Object System.Drawing.Point((14 + $LabelWidth), $Top)
    $width = 392 - $LabelWidth - 24
    $Control.Size = New-Object System.Drawing.Size($width, $ControlHeight)
    $Parent.Controls.Add($lbl)
    $Parent.Controls.Add($Control)
    return ($Top + $ControlHeight + 8)
}

function New-TextBox {
    param([switch]$Multi)
    $t = New-Object System.Windows.Forms.TextBox
    $t.BorderStyle = 'FixedSingle'
    if ($Multi) {
        $t.Multiline = $true
        $t.ScrollBars = 'Vertical'
        $t.AcceptsReturn = $true
        $t.WordWrap = $true
    }
    return $t
}

function New-Check {
    param([string]$Text)
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text = $Text
    $c.Font = $script:Font
    $c.AutoSize = $true
    return $c
}

function Get-JsonProperty {
    param($Object, [string]$Name, $Default)
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if (-not $p -or $null -eq $p.Value) { return $Default }
    return $p.Value
}

function ConvertTo-BoolSetting {
    param($Value, [bool]$Default)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return $Value }
    $text = [string]$Value
    if ($text -eq 'True' -or $text -eq 'true') { return $true }
    if ($text -eq 'False' -or $text -eq 'false') { return $false }
    return $Default
}

function Get-DefaultOutputParent {
    $docs = $null
    try { $docs = [Environment]::GetFolderPath('Desktop') } catch { $docs = $null }
    if ([string]::IsNullOrWhiteSpace($docs)) {
        try { $docs = [Environment]::GetFolderPath('MyDocuments') } catch { $docs = $null }
    }
    if ([string]::IsNullOrWhiteSpace($docs)) { $docs = $env:USERPROFILE }
    if ([string]::IsNullOrWhiteSpace($docs)) { $docs = (Get-Location).Path }
    return (Join-Path $docs 'M365-PS-Forensics')
}

function Save-GuiSettings {
    try {
        $dir = Split-Path -Parent $script:SettingsPath
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $bag = [ordered]@{
            AdminUPN = $script:txtUpn.Text.Trim()
            TenantId = $script:txtTenant.Text.Trim()
            ChunkHours = [int]$script:numChunk.Value
            CorrelationWindowHours = [int]$script:numCorr.Value
            MaxMailboxesToInspect = [int]$script:numMbx.Value
            IncludeServicePrincipalSignIns = [bool]$script:chkSp.Checked
            SkipSuspectDataAccess = [bool]$script:chkSkipData.Checked
            SkipExchange = [bool]$script:chkSkipExo.Checked
            SkipGraph = [bool]$script:chkSkipGraph.Checked
            SkipCurrentState = [bool]$script:chkSkipState.Checked
            ReportOnly = [bool]$script:chkReportOnly.Checked
            NoDisconnect = [bool]$script:chkNoDisc.Checked
            OpenReport = [bool]$script:chkOpenReport.Checked
            AdvancedSignIn = [bool]$script:chkAdvanced.Checked
            AdditionalRecordTypes = $script:txtExtra.Text.Trim()
            OutputParent = $script:txtOutput.Text.Trim()
            NewTimestampedFolder = [bool]$script:chkStamp.Checked
            WindowWidth = [int]$script:form.Width
            WindowHeight = [int]$script:form.Height
        }
        $utf8 = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($script:SettingsPath, ($bag | ConvertTo-Json), $utf8)
    } catch { }
}

function Import-GuiSettings {
    if (-not (Test-Path -LiteralPath $script:SettingsPath)) { return $null }
    try {
        $raw = [System.IO.File]::ReadAllText($script:SettingsPath)
        return ($raw | ConvertFrom-Json)
    } catch { return $null }
}

function Append-Log {
    param([string]$Message, [string]$Level = 'INFO')
    if ($null -eq $Message) { return }
    $color = $script:ColorMuted
    if ($Level -eq 'ERROR') { $color = $script:ColorDanger }
    elseif ($Level -eq 'WARN') { $color = [System.Drawing.Color]::FromArgb(181, 71, 8) }
    elseif ($Level -eq 'OK') { $color = $script:ColorOk }
    elseif ($Level -eq 'INFO') { $color = [System.Drawing.Color]::FromArgb(31, 35, 40) }
    $script:txtLog.SelectionStart = $script:txtLog.TextLength
    $script:txtLog.SelectionLength = 0
    $script:txtLog.SelectionColor = $color
    $script:txtLog.AppendText($Message.TrimEnd() + "`r`n")
    $script:txtLog.ScrollToCaret()
}

function Get-FirstResult {
    param($Raw)
    if ($null -eq $Raw) { return $null }
    if ($Raw -is [System.Collections.IList] -and $Raw -isnot [string]) {
        if ($Raw.Count -eq 0) { return $null }
        return $Raw[$Raw.Count - 1]
    }
    return $Raw
}

function Split-GuiList {
    param([string]$Text)
    return @($Text -split '[,;\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Update-ActionButtons {
    $script:btnRun.Enabled = -not $script:Busy
    $script:btnConnectExo.Enabled = -not $script:Busy
    $script:btnConnectGraph.Enabled = -not $script:Busy
    $script:btnDisconnect.Enabled = -not $script:Busy
    $script:btnInstall.Enabled = -not $script:Busy
    $script:btnCancel.Enabled = $script:Busy
    if (-not $script:Busy) { $script:btnCancel.Text = 'Cancel (Esc)' }
}

function Show-ConnectionState {
    param($State)
    if ($null -eq $State) { return }
    $bits = New-Object System.Collections.Generic.List[string]
    if ($State.ExchangeConnected) { $bits.Add('Exchange: ' + $(if ($State.ExchangeUser) { $State.ExchangeUser } else { 'connected' })) }
    else { $bits.Add('Exchange: not connected') }
    if ($State.GraphConnected) { $bits.Add('Graph: ' + $(if ($State.GraphUser) { $State.GraphUser } else { 'connected' })) }
    else { $bits.Add('Graph: not connected') }
    $script:lblConn.Text = ($bits -join '  |  ')
    if ($State.Connected) { $script:lblConn.ForeColor = $script:ColorOk } else { $script:lblConn.ForeColor = $script:ColorMuted }
}

function Show-Prerequisite {
    param($Pre)
    if ($null -eq $Pre) { $Pre = Get-M365PsForensicsPrerequisite }
    $exo = if ($Pre.ExchangeInstalled) { "EXO $($Pre.ExchangeVersion)" } else { 'EXO missing' }
    $graph = if ($Pre.GraphInstalled) { "Graph $($Pre.GraphVersion)" } else { 'Graph missing' }
    $script:lblModule.Text = "$exo  |  $graph"
    if ($Pre.ExchangeInstalled -and $Pre.GraphInstalled) { $script:lblModule.ForeColor = $script:ColorOk }
    elseif ($Pre.ExchangeInstalled -or $Pre.GraphInstalled) { $script:lblModule.ForeColor = [System.Drawing.Color]::FromArgb(181, 71, 8) }
    else { $script:lblModule.ForeColor = $script:ColorDanger }
}

function Initialize-Worker {
    $script:Sync = [hashtable]::Synchronized(@{
        Cancel = $false
        Queue  = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    })
    $script:Runspace = [runspacefactory]::CreateRunspace()
    $script:Runspace.ApartmentState = 'STA'
    $script:Runspace.ThreadOptions = 'ReuseThread'
    $script:Runspace.Open()
    $script:Worker = [powershell]::Create()
    $script:Worker.Runspace = $script:Runspace
    $init = {
        param($ModulePath, $Bridge)
        $ErrorActionPreference = 'Stop'
        Import-Module -Name $ModulePath -Force -DisableNameChecking
        Set-M365PsForensicsUiBridge -Sync $Bridge
        'ready'
    }
    [void]$script:Worker.AddScript($init).AddArgument($script:ModulePath).AddArgument($script:Sync)
    $ready = $script:Worker.Invoke()
    $errors = @($script:Worker.Streams.Error)
    $script:Worker.Commands.Clear()
    $script:Worker.Streams.ClearStreams()
    if ($errors.Count -gt 0 -or @($ready) -notcontains 'ready') {
        $detail = ($errors | ForEach-Object { $_.ToString() }) -join "`r`n"
        throw "Could not load the investigation engine.`r`n$detail"
    }
}

function Reset-WorkerIfBroken {
    $opened = $false
    try { $opened = ($script:Runspace.RunspaceStateInfo.State -eq 'Opened') } catch { $opened = $false }
    $failed = $false
    try { $failed = ($script:Worker.InvocationStateInfo.State -eq 'Failed') } catch { $failed = $true }
    if ($opened -and -not $failed) { return }
    try { $script:Worker.Dispose() } catch { }
    try { $script:Runspace.Close() } catch { }
    try { $script:Runspace.Dispose() } catch { }
    Initialize-Worker
}

function Start-WorkerAction {
    param([string]$Action, [scriptblock]$Script, [object[]]$Arguments)
    if ($script:Busy) { return }
    Reset-WorkerIfBroken
    $script:Busy = $true
    $script:BusyAction = $Action
    $script:CancelRequested = $false
    $script:Sync.Cancel = $false
    $script:btnCancel.Text = 'Cancel (Esc)'
    Update-ActionButtons
    $script:Worker.Commands.Clear()
    $invocation = $script:Worker.AddScript($Script)
    foreach ($arg in @($Arguments)) { [void]$invocation.AddArgument($arg) }
    $script:RunHandle = $script:Worker.BeginInvoke()
}

function Test-InvestigationForm {
    $errors = New-Object System.Collections.Generic.List[string]
    $p = @{}
    if ($script:dtEnd.Value -le $script:dtStart.Value) { $errors.Add('End time must be after the start time.') }
    $p.StartDate = $script:dtStart.Value
    $p.EndDate = $script:dtEnd.Value
    $users = Split-GuiList $script:txtUsers.Text
    $ips = Split-GuiList $script:txtIps.Text
    if ($users.Count) { $p.SuspectUsers = $users }
    if ($ips.Count) { $p.SuspectIPs = $ips }
    $extra = Split-GuiList $script:txtExtra.Text
    if ($extra.Count) { $p.AdditionalRecordTypes = $extra }
    if ($script:chkAdvanced.Checked) {
        $upn = $script:txtUpn.Text.Trim()
        $tenant = $script:txtTenant.Text.Trim()
        if ($upn -and $upn -notmatch '@') { $errors.Add('Investigator account should be a UPN, or leave it blank.') }
        if ($upn) { $p.AdminUPN = $upn }
        if ($tenant) { $p.TenantId = $tenant }
    }
    $parent = $script:txtOutput.Text.Trim()
    if (-not $parent) { $parent = Get-DefaultOutputParent }
    if ($script:chkReportOnly.Checked) {
        if (-not (Test-Path -LiteralPath $parent)) { $errors.Add('Report only needs an existing evidence folder.') }
        $p.OutputPath = $parent
        $p.ReportOnly = $true
    }
    else {
        if ($script:chkStamp.Checked) {
            $p.OutputPath = Join-Path $parent ('M365-PS-Forensics-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
        }
        else { $p.OutputPath = $parent }
    }
    $p.ChunkHours = [int]$script:numChunk.Value
    $p.CorrelationWindowHours = [int]$script:numCorr.Value
    $p.MaxMailboxesToInspect = [int]$script:numMbx.Value
    $p.IncludeServicePrincipalSignIns = [bool]$script:chkSp.Checked
    $p.SkipSuspectDataAccess = [bool]$script:chkSkipData.Checked
    $p.SkipExchange = [bool]$script:chkSkipExo.Checked
    $p.SkipGraph = [bool]$script:chkSkipGraph.Checked
    $p.SkipCurrentState = [bool]$script:chkSkipState.Checked
    $p.NoDisconnect = [bool]$script:chkNoDisc.Checked
    $p.OpenReport = [bool]$script:chkOpenReport.Checked
    if ($p.SkipExchange -and $p.SkipGraph -and -not $p.ReportOnly) {
        $errors.Add('Skip Exchange and Skip Graph are both on. Turn one off, or use Report only.')
    }
    return [pscustomobject]@{ Ok = ($errors.Count -eq 0); Errors = @($errors); Parameters = $p }
}

function Import-ResultTable {
    param($Grid, [string]$Path, [string[]]$Preferred)
    $Grid.Rows.Clear()
    $Grid.Columns.Clear()
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $rows = @(Import-Csv -LiteralPath $Path)
    if ($rows.Count -eq 0) { return 0 }
    $cols = @($rows[0].PSObject.Properties.Name)
    if ($Preferred) { $cols = @($Preferred | Where-Object { $_ -in $cols }) + @($cols | Where-Object { $_ -notin $Preferred }) }
    foreach ($c in $cols) {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $col.Name = $c
        $col.HeaderText = $c
        $col.AutoSizeMode = 'DisplayedCells'
        [void]$Grid.Columns.Add($col)
    }
    $n = 0
    foreach ($r in $rows) {
        $vals = foreach ($c in $cols) { [string]$r.$c }
        [void]$Grid.Rows.Add($vals)
        $n++
        if ($n -ge 5000) { break }
    }
    return $rows.Count
}

function Load-ResultFolder {
    param([string]$Folder)
    if (-not $Folder -or -not (Test-Path -LiteralPath $Folder)) { return }
    $script:LastFolder = $Folder
    $report = Join-Path $Folder 'Investigation-Report.html'
    if (Test-Path -LiteralPath $report) { $script:LastReport = $report }
    $cmdPath = Join-Path $Folder 'Timeline-Master.csv'
    $nCmd = Import-ResultTable $script:gridCmd $cmdPath @('TimeUtc','Severity','Actor','CommandLine','Operation','ClientIP','InferredIP','ExecutionChannel','SuspectMatch')
    $si = Get-ChildItem -LiteralPath $Folder -Filter 'SignIns-*.csv' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    $nSi = 0
    if ($si) { $nSi = Import-ResultTable $script:gridSi $si.FullName @('TimeUtc','User','Result','AppName','PowerShellApp','IPAddress','Location','UserAgent') }
    $find = @(Get-ChildItem -LiteralPath $Folder -Filter 'Findings-*.csv' -File -ErrorAction SilentlyContinue)
    $script:gridFind.Rows.Clear(); $script:gridFind.Columns.Clear()
    $allFind = @()
    foreach ($f in $find) { $allFind += @(Import-Csv -LiteralPath $f.FullName) }
    if ($allFind.Count) {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('m365ps-find-' + [guid]::NewGuid().ToString('n') + '.csv')
        $allFind | Export-Csv -LiteralPath $tmp -NoTypeInformation -Encoding UTF8
        [void](Import-ResultTable $script:gridFind $tmp @('Severity','Area','Item','Detail','Reason','WhenUtc'))
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    $cov = Join-Path $Folder 'Coverage.csv'
    [void](Import-ResultTable $script:gridCov $cov @('Source','Status','Records','FromUtc','ToUtc','Notes'))
    $script:lblGrid.Text = ("Commands/timeline: {0:N0}  |  Sign-ins: {1:N0}  |  Findings: {2:N0}" -f $nCmd, $nSi, $allFind.Count)
}

function Show-RunResult {
    param($Result)
    if ($null -eq $Result) { return }
    if ($Result.OutputPath) { Load-ResultFolder $Result.OutputPath }
    if ($Result.ReportPath) { $script:LastReport = $Result.ReportPath }
    if ($Result.ExitCode -eq 0) {
        $script:lblStatus.Text = 'Finished. Open the HTML report for the interactive investigation.'
        Append-Log 'Investigation finished.' 'OK'
        $script:tabs.SelectedTab = $script:tabCmd
    }
    elseif ($Result.ExitCode -eq 2) {
        $script:lblStatus.Text = 'Cancelled.'
        Append-Log 'Cancelled.' 'WARN'
    }
    else {
        $script:lblStatus.Text = 'Finished with errors. See the log and Coverage tab.'
        Append-Log ('Finished with errors: ' + $Result.Error) 'ERROR'
        $script:tabs.SelectedTab = $script:tabLog
    }
}

function Drain-WorkerStreams {
    foreach ($i in @($script:Worker.Streams.Information)) { Append-Log ([string]$i) 'INFO' }
    foreach ($w in @($script:Worker.Streams.Warning)) { Append-Log ([string]$w) 'WARN' }
    foreach ($e in @($script:Worker.Streams.Error)) { Append-Log ([string]$e) 'ERROR' }
    try { $script:Worker.Streams.ClearStreams() } catch { }
}

function Drain-WorkerQueue {
    $item = $null
    while ($script:Sync.Queue.TryDequeue([ref]$item)) {
        if ($item.Type -eq 'Log') { Append-Log $item.Message $item.Level }
        elseif ($item.Type -eq 'Progress') {
            if ($item.Percent -ge 0) { $script:progress.Value = [Math]::Min(100, [Math]::Max(0, $item.Percent)) }
            if ($item.Message) { $script:lblStatus.Text = $item.Message }
        }
    }
}

function Complete-WorkerAction {
    param($Result, $Failure)
    $script:Busy = $false
    $script:RunHandle = $null
    Update-ActionButtons
    $script:progress.Value = 100
    if ($Failure) {
        Append-Log ([string]$Failure) 'ERROR'
        $script:lblStatus.Text = 'The background run failed. See the log.'
    }
    elseif ($script:BusyAction -eq 'Run') { Show-RunResult (Get-FirstResult $Result) }
    elseif ($script:BusyAction -eq 'ConnectExo' -or $script:BusyAction -eq 'ConnectGraph' -or $script:BusyAction -eq 'Disconnect' -or $script:BusyAction -eq 'State') {
        Show-ConnectionState (Get-FirstResult $Result)
        $script:lblStatus.Text = 'Ready.'
    }
    elseif ($script:BusyAction -eq 'Install') {
        Show-Prerequisite (Get-FirstResult $Result)
        $script:lblStatus.Text = 'Module install finished.'
    }
    if ($script:CloseAfterStop) {
        $script:AllowClose = $true
        $script:form.Close()
    }
}

function Update-WorkerUi {
    Drain-WorkerQueue
    if ($script:Busy) { Drain-WorkerStreams }
    if ($script:RunHandle -and $script:RunHandle.IsCompleted) {
        $handle = $script:RunHandle
        $script:RunHandle = $null
        try {
            $raw = $script:Worker.EndInvoke($handle)
            Complete-WorkerAction -Result (Get-FirstResult $raw) -Failure $null
        } catch {
            Complete-WorkerAction -Result $null -Failure $_
        }
    }
}

$script:RunWorkerScript = {
    param($Bridge, $Params)
    $ErrorActionPreference = 'Stop'
    $InformationPreference = 'Continue'
    Set-M365PsForensicsUiBridge -Sync $Bridge
    $Bridge.Cancel = $false
    Invoke-M365PowerShellForensics @Params
}

$script:ConnectExoScript = {
    param($Bridge, $Auth)
    $ErrorActionPreference = 'Stop'
    $InformationPreference = 'Continue'
    Set-M365PsForensicsUiBridge -Sync $Bridge
    $Bridge.Cancel = $false
    Connect-M365PsForensicsExchange -UserPrincipalName $Auth.UserPrincipalName
}

$script:ConnectGraphScript = {
    param($Bridge, $Auth)
    $ErrorActionPreference = 'Stop'
    $InformationPreference = 'Continue'
    Set-M365PsForensicsUiBridge -Sync $Bridge
    $Bridge.Cancel = $false
    Connect-M365PsForensicsGraph -TenantId $Auth.TenantId -UserPrincipalName $Auth.UserPrincipalName
}

$script:DisconnectWorkerScript = {
    param($Bridge)
    $ErrorActionPreference = 'Stop'
    Set-M365PsForensicsUiBridge -Sync $Bridge
    Disconnect-M365PsForensicsSessions -Force
}

$script:StateWorkerScript = {
    param($Bridge)
    $ErrorActionPreference = 'Stop'
    Set-M365PsForensicsUiBridge -Sync $Bridge
    Get-M365PsForensicsConnectionState
}

$script:InstallWorkerScript = {
    param($Bridge)
    $ErrorActionPreference = 'Stop'
    $InformationPreference = 'Continue'
    Set-M365PsForensicsUiBridge -Sync $Bridge
    Install-M365PsForensicsModules
}

function Start-Investigation {
    if ($script:Busy) { return }
    $check = Test-InvestigationForm
    if (-not $check.Ok) {
        [System.Windows.Forms.MessageBox]::Show(($check.Errors -join "`r`n"), 'Check the form', 'OK', 'Warning') | Out-Null
        return
    }
    Save-GuiSettings
    $script:progress.Value = 0
    $script:lblStatus.Text = 'Starting investigation...'
    $script:tabs.SelectedTab = $script:tabLog
    Append-Log '---- Run started ----' 'INFO'
    Start-WorkerAction -Action 'Run' -Script $script:RunWorkerScript -Arguments @($script:Sync, $check.Parameters)
}

function Get-AuthBag {
    $auth = @{ UserPrincipalName = ''; TenantId = '' }
    if ($script:chkAdvanced.Checked) {
        $auth.UserPrincipalName = $script:txtUpn.Text.Trim()
        $auth.TenantId = $script:txtTenant.Text.Trim()
    }
    return $auth
}

function Start-ConnectExo {
    if ($script:Busy) { return }
    $script:lblStatus.Text = 'Connecting to Exchange Online. Complete the Microsoft sign-in window.'
    $script:tabs.SelectedTab = $script:tabLog
    Append-Log '---- Connect Exchange ----' 'INFO'
    Start-WorkerAction -Action 'ConnectExo' -Script $script:ConnectExoScript -Arguments @($script:Sync, (Get-AuthBag))
}

function Start-ConnectGraph {
    if ($script:Busy) { return }
    $script:lblStatus.Text = 'Connecting to Microsoft Graph. Complete the Microsoft sign-in window.'
    $script:tabs.SelectedTab = $script:tabLog
    Append-Log '---- Connect Graph ----' 'INFO'
    Start-WorkerAction -Action 'ConnectGraph' -Script $script:ConnectGraphScript -Arguments @($script:Sync, (Get-AuthBag))
}

function Start-Disconnect {
    if ($script:Busy) { return }
    $script:lblStatus.Text = 'Disconnecting...'
    Start-WorkerAction -Action 'Disconnect' -Script $script:DisconnectWorkerScript -Arguments @($script:Sync)
}

function Start-Install {
    if ($script:Busy) { return }
    $answer = [System.Windows.Forms.MessageBox]::Show(
        'Install or update ExchangeOnlineManagement and Microsoft.Graph.Authentication for the current user from PSGallery?',
        'Install modules',
        'YesNo',
        'Question')
    if ($answer -ne 'Yes') { return }
    $script:lblStatus.Text = 'Installing modules...'
    $script:tabs.SelectedTab = $script:tabLog
    Start-WorkerAction -Action 'Install' -Script $script:InstallWorkerScript -Arguments @($script:Sync)
}

function Stop-Investigation {
    if (-not $script:Busy) { return }
    if (-not $script:CancelRequested) {
        $script:CancelRequested = $true
        $script:Sync.Cancel = $true
        $script:btnCancel.Text = 'Force stop'
        $script:lblStatus.Text = 'Cancel requested. Waiting for the current call to return. Click Force stop to abort it.'
        Append-Log 'Cancel requested.' 'WARN'
        return
    }
    $script:lblStatus.Text = 'Aborting the current call.'
    Append-Log 'Force stop.' 'WARN'
    try { $script:Worker.Stop() } catch { }
}

function Browse-Folder {
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Evidence folder'
    $dlg.ShowNewFolderButton = $true
    if ($script:txtOutput.Text -and (Test-Path -LiteralPath $script:txtOutput.Text)) {
        $dlg.SelectedPath = $script:txtOutput.Text
    }
    if ($dlg.ShowDialog() -eq 'OK') { $script:txtOutput.Text = $dlg.SelectedPath }
}

# ----- UI layout -----
$script:form = New-Object System.Windows.Forms.Form
$script:form.Text = "M365 PowerShell Forensics  v$script:GuiVersion / engine $script:EngineVersion"
$script:form.StartPosition = 'CenterScreen'
$script:form.Size = New-Object System.Drawing.Size(1280, 820)
$script:form.MinimumSize = New-Object System.Drawing.Size(1000, 640)
$script:form.BackColor = $script:ColorBg
$script:form.KeyPreview = $true
$script:form.Font = $script:Font

$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'
$header.Height = 64
$header.BackColor = $script:ColorHeader
$title = New-Object System.Windows.Forms.Label
$title.Text = 'Microsoft 365 PowerShell & admin-command investigation'
$title.Font = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = [System.Drawing.Color]::White
$title.Location = New-Object System.Drawing.Point(18, 8)
$title.AutoSize = $true
$subtitle = New-Object System.Windows.Forms.Label
$subtitle.Text = 'READ-ONLY. Reconstructs commands from Unified Audit Log, Entra sign-ins, and directory audit. F5 runs, Esc cancels.'
$subtitle.ForeColor = [System.Drawing.Color]::FromArgb(203, 213, 225)
$subtitle.Location = New-Object System.Drawing.Point(18, 36)
$subtitle.AutoSize = $true
$header.Controls.Add($title)
$header.Controls.Add($subtitle)

$footer = New-Object System.Windows.Forms.Panel
$footer.Dock = 'Bottom'
$footer.Height = 36
$footer.BackColor = [System.Drawing.Color]::White
$script:progress = New-Object System.Windows.Forms.ProgressBar
$script:progress.Location = New-Object System.Drawing.Point(12, 8)
$script:progress.Size = New-Object System.Drawing.Size(220, 18)
$script:progress.Minimum = 0
$script:progress.Maximum = 100
$script:lblStatus = New-Object System.Windows.Forms.Label
$script:lblStatus.Text = 'Ready.'
$script:lblStatus.Font = $script:Font
$script:lblStatus.Location = New-Object System.Drawing.Point(244, 8)
$script:lblStatus.Size = New-Object System.Drawing.Size(980, 20)
$script:lblStatus.Anchor = 'Top,Left,Right'
$footer.Controls.Add($script:progress)
$footer.Controls.Add($script:lblStatus)

$script:split = New-Object System.Windows.Forms.SplitContainer
$script:split.Dock = 'Fill'
$script:split.Orientation = 'Vertical'
$script:split.Panel1MinSize = 80
$script:split.Panel2MinSize = 80
$script:split.BackColor = $script:ColorLine
$script:split.Panel1.BackColor = $script:ColorBg
$script:split.Panel2.BackColor = $script:ColorBg

$left = New-Object System.Windows.Forms.Panel
$left.Dock = 'Fill'
$left.AutoScroll = $true
$left.BackColor = $script:ColorBg
$script:split.Panel1.Controls.Add($left)

$tips = New-Object System.Windows.Forms.ToolTip
$tips.AutoPopDelay = 14000
$tips.InitialDelay = 400

$script:grpConn = New-Object System.Windows.Forms.GroupBox
$script:grpConn.Text = 'Connection'
$script:grpConn.Font = $script:FontBold
$script:grpConn.Location = New-Object System.Drawing.Point(8, 8)
$script:grpConn.Size = New-Object System.Drawing.Size(400, 200)
$left.Controls.Add($script:grpConn)
$hint = New-Object System.Windows.Forms.Label
$hint.Text = 'Connect is optional. Run will sign in when a live collection needs it. Use a break-glass / IR account.'
$hint.Font = $script:Font
$hint.Location = New-Object System.Drawing.Point(14, 22)
$hint.Size = New-Object System.Drawing.Size(370, 36)
$script:grpConn.Controls.Add($hint)
$script:btnConnectExo = New-Button 'Connect Exchange' $script:ColorAccent ([System.Drawing.Color]::White)
$script:btnConnectExo.Location = New-Object System.Drawing.Point(14, 62)
$script:btnConnectExo.Size = New-Object System.Drawing.Size(130, 32)
$script:btnConnectGraph = New-Button 'Connect Graph' $script:ColorAccent ([System.Drawing.Color]::White)
$script:btnConnectGraph.Location = New-Object System.Drawing.Point(150, 62)
$script:btnConnectGraph.Size = New-Object System.Drawing.Size(120, 32)
$script:btnDisconnect = New-Button 'Disconnect' ([System.Drawing.Color]::White) $script:ColorDanger
$script:btnDisconnect.Location = New-Object System.Drawing.Point(276, 62)
$script:btnDisconnect.Size = New-Object System.Drawing.Size(100, 32)
$script:btnInstall = New-Button 'Install modules' ([System.Drawing.Color]::White) $script:ColorAccent
$script:btnInstall.Location = New-Object System.Drawing.Point(14, 100)
$script:btnInstall.Size = New-Object System.Drawing.Size(130, 28)
$script:grpConn.Controls.Add($script:btnConnectExo)
$script:grpConn.Controls.Add($script:btnConnectGraph)
$script:grpConn.Controls.Add($script:btnDisconnect)
$script:grpConn.Controls.Add($script:btnInstall)
$script:lblModule = New-Object System.Windows.Forms.Label
$script:lblModule.Font = $script:Font
$script:lblModule.Location = New-Object System.Drawing.Point(150, 104)
$script:lblModule.Size = New-Object System.Drawing.Size(230, 20)
$script:grpConn.Controls.Add($script:lblModule)
$script:lblConn = New-Object System.Windows.Forms.Label
$script:lblConn.Font = $script:Font
$script:lblConn.Location = New-Object System.Drawing.Point(14, 134)
$script:lblConn.Size = New-Object System.Drawing.Size(370, 32)
$script:grpConn.Controls.Add($script:lblConn)
$script:chkAdvanced = New-Check 'Advanced sign-in (optional UPN / tenant id)'
$script:chkAdvanced.Location = New-Object System.Drawing.Point(14, 168)
$script:grpConn.Controls.Add($script:chkAdvanced)

$script:grpCase = New-Object System.Windows.Forms.GroupBox
$script:grpCase.Text = 'Investigation'
$script:grpCase.Font = $script:FontBold
$script:grpCase.Location = New-Object System.Drawing.Point(8, 216)
$script:grpCase.Size = New-Object System.Drawing.Size(400, 430)
$left.Controls.Add($script:grpCase)
$y = 24
$script:dtStart = New-Object System.Windows.Forms.DateTimePicker
$script:dtStart.Format = 'Custom'
$script:dtStart.CustomFormat = 'yyyy-MM-dd HH:mm'
$script:dtStart.Value = (Get-Date).AddDays(-90)
$y = Add-Labeled $script:grpCase $y 'Start (local)' $script:dtStart
$script:dtEnd = New-Object System.Windows.Forms.DateTimePicker
$script:dtEnd.Format = 'Custom'
$script:dtEnd.CustomFormat = 'yyyy-MM-dd HH:mm'
$script:dtEnd.Value = Get-Date
$y = Add-Labeled $script:grpCase $y 'End (local)' $script:dtEnd
$script:txtUsers = New-TextBox -Multi
$y = Add-Labeled $script:grpCase $y 'Suspect users' $script:txtUsers 64
$script:txtIps = New-TextBox -Multi
$y = Add-Labeled $script:grpCase $y 'Suspect IPs' $script:txtIps 48
$script:txtExtra = New-TextBox
$y = Add-Labeled $script:grpCase $y 'Extra UAL types' $script:txtExtra
$script:txtUpn = New-TextBox
$y = Add-Labeled $script:grpCase $y 'Investigator' $script:txtUpn
$script:txtTenant = New-TextBox
$y = Add-Labeled $script:grpCase $y 'Tenant ID' $script:txtTenant
$script:txtOutput = New-TextBox
$y = Add-Labeled $script:grpCase $y 'Evidence folder' $script:txtOutput
$btnBrowse = New-Button 'Browse...' ([System.Drawing.Color]::White) ([System.Drawing.Color]::FromArgb(31, 35, 40))
$btnBrowse.Location = New-Object System.Drawing.Point(286, ($y - 32))
$btnBrowse.Size = New-Object System.Drawing.Size(90, 24)
$script:grpCase.Controls.Add($btnBrowse)
$script:chkStamp = New-Check 'Create a timestamped subfolder for each run'
$script:chkStamp.Checked = $true
$script:chkStamp.Location = New-Object System.Drawing.Point(14, $y)
$script:grpCase.Controls.Add($script:chkStamp)
$tips.SetToolTip($script:txtUsers, 'One UPN per line or comma-separated. Enables deep per-account UAL collection and highlighting.')
$tips.SetToolTip($script:txtExtra, 'Optional extra Unified Audit Log record types, e.g. MicrosoftTeams, PowerBIAudit.')

$script:grpScope = New-Object System.Windows.Forms.GroupBox
$script:grpScope.Text = 'Collection options'
$script:grpScope.Font = $script:FontBold
$script:grpScope.Location = New-Object System.Drawing.Point(8, 654)
$script:grpScope.Size = New-Object System.Drawing.Size(400, 280)
$left.Controls.Add($script:grpScope)
$y = 22
$script:numChunk = New-Object System.Windows.Forms.NumericUpDown
$script:numChunk.Minimum = 1; $script:numChunk.Maximum = 168; $script:numChunk.Value = 24
$y = Add-Labeled $script:grpScope $y 'UAL chunk (hours)' $script:numChunk
$script:numCorr = New-Object System.Windows.Forms.NumericUpDown
$script:numCorr.Minimum = 1; $script:numCorr.Maximum = 72; $script:numCorr.Value = 12
$y = Add-Labeled $script:grpScope $y 'IP correlate (hours)' $script:numCorr
$script:numMbx = New-Object System.Windows.Forms.NumericUpDown
$script:numMbx.Minimum = 1; $script:numMbx.Maximum = 5000; $script:numMbx.Value = 200
$y = Add-Labeled $script:grpScope $y 'Max mailboxes' $script:numMbx
foreach ($pair in @(
        @{ N = 'chkSkipExo'; T = 'Skip Exchange / Unified Audit Log' },
        @{ N = 'chkSkipGraph'; T = 'Skip Microsoft Graph' },
        @{ N = 'chkSkipState'; T = 'Skip current-state persistence sweep' },
        @{ N = 'chkSkipData'; T = 'Skip suspect mailbox/file/Teams activity' },
        @{ N = 'chkSp'; T = 'Include all service-principal sign-ins' },
        @{ N = 'chkReportOnly'; T = 'Report only (rebuild HTML from this folder)' },
        @{ N = 'chkNoDisc'; T = 'Keep Exchange/Graph sessions when the run finishes' },
        @{ N = 'chkOpenReport'; T = 'Open the HTML report when the run finishes' }
    )) {
    $c = New-Check $pair.T
    $c.Location = New-Object System.Drawing.Point(14, $y)
    $script:grpScope.Controls.Add($c)
    Set-Variable -Name $pair.N -Value $c -Scope Script
    $y += 22
}
$script:chkNoDisc.Checked = $true
$script:chkOpenReport.Checked = $true

$script:btnRun = New-Button 'Run investigation (F5)' $script:ColorAccent ([System.Drawing.Color]::White)
$script:btnRun.Location = New-Object System.Drawing.Point(8, 942)
$script:btnRun.Size = New-Object System.Drawing.Size(200, 36)
$script:btnCancel = New-Button 'Cancel (Esc)' ([System.Drawing.Color]::White) $script:ColorDanger
$script:btnCancel.Location = New-Object System.Drawing.Point(216, 942)
$script:btnCancel.Size = New-Object System.Drawing.Size(120, 36)
$script:btnOpenReport = New-Button 'Open report' ([System.Drawing.Color]::White) $script:ColorAccent
$script:btnOpenReport.Location = New-Object System.Drawing.Point(8, 986)
$script:btnOpenReport.Size = New-Object System.Drawing.Size(130, 32)
$script:btnOpenFolder = New-Button 'Open folder' ([System.Drawing.Color]::White) ([System.Drawing.Color]::FromArgb(31, 35, 40))
$script:btnOpenFolder.Location = New-Object System.Drawing.Point(146, 986)
$script:btnOpenFolder.Size = New-Object System.Drawing.Size(120, 32)
$left.Controls.Add($script:btnRun)
$left.Controls.Add($script:btnCancel)
$left.Controls.Add($script:btnOpenReport)
$left.Controls.Add($script:btnOpenFolder)
$pad = New-Object System.Windows.Forms.Panel
$pad.Location = New-Object System.Drawing.Point(8, 1030)
$pad.Size = New-Object System.Drawing.Size(10, 20)
$left.Controls.Add($pad)

$script:tabs = New-Object System.Windows.Forms.TabControl
$script:tabs.Dock = 'Fill'
$script:split.Panel2.Controls.Add($script:tabs)

function New-Grid {
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'
    $g.ReadOnly = $true
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.MultiSelect = $false
    $g.AutoSizeColumnsMode = 'DisplayedCells'
    $g.RowHeadersVisible = $false
    $g.BackgroundColor = [System.Drawing.Color]::White
    return $g
}

$script:tabLog = New-Object System.Windows.Forms.TabPage
$script:tabLog.Text = 'Log'
$script:txtLog = New-Object System.Windows.Forms.RichTextBox
$script:txtLog.Dock = 'Fill'
$script:txtLog.ReadOnly = $true
$script:txtLog.Font = $script:FontMono
$script:txtLog.BackColor = [System.Drawing.Color]::White
$script:tabLog.Controls.Add($script:txtLog)

$script:tabCmd = New-Object System.Windows.Forms.TabPage
$script:tabCmd.Text = 'Commands'
$script:gridCmd = New-Grid
$script:tabCmd.Controls.Add($script:gridCmd)
$script:tabSi = New-Object System.Windows.Forms.TabPage
$script:tabSi.Text = 'Sign-ins'
$script:gridSi = New-Grid
$script:tabSi.Controls.Add($script:gridSi)
$script:tabFind = New-Object System.Windows.Forms.TabPage
$script:tabFind.Text = 'Persistence'
$script:gridFind = New-Grid
$script:tabFind.Controls.Add($script:gridFind)
$script:tabCov = New-Object System.Windows.Forms.TabPage
$script:tabCov.Text = 'Coverage'
$script:gridCov = New-Grid
$script:tabCov.Controls.Add($script:gridCov)
[void]$script:tabs.TabPages.Add($script:tabLog)
[void]$script:tabs.TabPages.Add($script:tabCmd)
[void]$script:tabs.TabPages.Add($script:tabSi)
[void]$script:tabs.TabPages.Add($script:tabFind)
[void]$script:tabs.TabPages.Add($script:tabCov)

$script:lblGrid = New-Object System.Windows.Forms.Label
$script:lblGrid.Dock = 'Bottom'
$script:lblGrid.Height = 22
$script:lblGrid.Text = 'No results loaded yet.'
$script:split.Panel2.Controls.Add($script:lblGrid)

$script:form.Controls.Add($script:split)
$script:form.Controls.Add($footer)
$script:form.Controls.Add($header)

$saved = Import-GuiSettings
if ($saved) {
    $script:txtUpn.Text = [string](Get-JsonProperty $saved 'AdminUPN' '')
    $script:txtTenant.Text = [string](Get-JsonProperty $saved 'TenantId' '')
    $script:txtExtra.Text = [string](Get-JsonProperty $saved 'AdditionalRecordTypes' '')
    $script:txtOutput.Text = [string](Get-JsonProperty $saved 'OutputParent' (Get-DefaultOutputParent))
    try { $script:numChunk.Value = [decimal](Get-JsonProperty $saved 'ChunkHours' 24) } catch { }
    try { $script:numCorr.Value = [decimal](Get-JsonProperty $saved 'CorrelationWindowHours' 12) } catch { }
    try { $script:numMbx.Value = [decimal](Get-JsonProperty $saved 'MaxMailboxesToInspect' 200) } catch { }
    $script:chkSp.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'IncludeServicePrincipalSignIns' $false) $false
    $script:chkSkipData.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'SkipSuspectDataAccess' $false) $false
    $script:chkSkipExo.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'SkipExchange' $false) $false
    $script:chkSkipGraph.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'SkipGraph' $false) $false
    $script:chkSkipState.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'SkipCurrentState' $false) $false
    $script:chkReportOnly.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'ReportOnly' $false) $false
    $script:chkNoDisc.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'NoDisconnect' $true) $true
    $script:chkOpenReport.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'OpenReport' $true) $true
    $script:chkAdvanced.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'AdvancedSignIn' $false) $false
    $script:chkStamp.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'NewTimestampedFolder' $true) $true
    try {
        $w = [int](Get-JsonProperty $saved 'WindowWidth' 1280)
        $h = [int](Get-JsonProperty $saved 'WindowHeight' 820)
        if ($w -ge 900 -and $h -ge 600) { $script:form.Size = New-Object System.Drawing.Size($w, $h) }
    } catch { }
}
if (-not $script:txtOutput.Text) { $script:txtOutput.Text = Get-DefaultOutputParent }
Show-Prerequisite $script:Prereq
Show-ConnectionState ([pscustomobject]@{ Connected = $false; ExchangeConnected = $false; GraphConnected = $false })
Update-ActionButtons

$script:btnRun.Add_Click({ Start-Investigation })
$script:btnCancel.Add_Click({ Stop-Investigation })
$script:btnConnectExo.Add_Click({ Start-ConnectExo })
$script:btnConnectGraph.Add_Click({ Start-ConnectGraph })
$script:btnDisconnect.Add_Click({ Start-Disconnect })
$script:btnInstall.Add_Click({ Start-Install })
$btnBrowse.Add_Click({ Browse-Folder })
$script:btnOpenReport.Add_Click({
    if ($script:LastReport -and (Test-Path -LiteralPath $script:LastReport)) { Start-Process -FilePath $script:LastReport }
    else { [System.Windows.Forms.MessageBox]::Show('No report yet. Run an investigation first.', 'Open report', 'OK', 'Information') | Out-Null }
})
$script:btnOpenFolder.Add_Click({
    if ($script:LastFolder -and (Test-Path -LiteralPath $script:LastFolder)) { Start-Process -FilePath $script:LastFolder }
    elseif ($script:txtOutput.Text -and (Test-Path -LiteralPath $script:txtOutput.Text)) { Start-Process -FilePath $script:txtOutput.Text }
})
$script:gridCmd.Add_CellDoubleClick({
    param($sender, $e)
    if ($e.RowIndex -lt 0) { return }
    $row = $script:gridCmd.Rows[$e.RowIndex]
    $cmdCol = $script:gridCmd.Columns['CommandLine']
    if ($cmdCol) {
        $text = [string]$row.Cells[$cmdCol.Index].Value
        if ($text) {
            try { [System.Windows.Forms.Clipboard]::SetText($text) } catch { }
            $script:lblStatus.Text = 'Command line copied to the clipboard.'
        }
    }
})
$script:form.Add_KeyDown({
    param($sender, $e)
    if ($e.KeyCode -eq 'F5') { $e.SuppressKeyPress = $true; Start-Investigation }
    elseif ($e.KeyCode -eq 'Escape') { $e.SuppressKeyPress = $true; Stop-Investigation }
})
$script:form.Add_FormClosing({
    param($sender, $e)
    Save-GuiSettings
    if ($script:Busy -and -not $script:AllowClose) {
        $e.Cancel = $true
        $answer = [System.Windows.Forms.MessageBox]::Show(
            'An investigation is still running. Stop it and close?',
            'M365 PowerShell Forensics',
            'YesNo',
            'Question')
        if ($answer -eq 'Yes') {
            $script:CloseAfterStop = $true
            if (-not $script:CancelRequested) { Stop-Investigation }
            Stop-Investigation
        }
    }
})
$script:form.Add_Shown({
    try { $script:split.SplitterDistance = 430 } catch { }
    try { Start-WorkerAction -Action 'State' -Script $script:StateWorkerScript -Arguments @($script:Sync) } catch { Append-Log $_.Exception.Message 'ERROR' }
})

try { Initialize-Worker }
catch {
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'M365 PowerShell Forensics', 'OK', 'Error') | Out-Null
    exit 1
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 200
$timer.Add_Tick({
    if ($script:InTick) { return }
    $script:InTick = $true
    try { Update-WorkerUi } catch { Append-Log $_.Exception.Message 'ERROR' }
    $script:InTick = $false
})
$timer.Start()

try {
    [void][System.Windows.Forms.Application]::Run($script:form)
} finally {
    $timer.Stop()
    try { $script:Worker.Stop() } catch { }
    try { $script:Worker.Dispose() } catch { }
    try { $script:Runspace.Close() } catch { }
    try { $script:Runspace.Dispose() } catch { }
}

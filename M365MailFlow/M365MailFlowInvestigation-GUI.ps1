#Requires -Version 5.1
<#
.SYNOPSIS
    WinForms front end for the Microsoft 365 mail flow investigation engine.

.DESCRIPTION
    Collects trace filters, header/CSV sources, and connection settings, then runs
    Invoke-M365MailFlowInvestigation on a single background runspace. The Exchange
    session stays on that runspace across Connect and Run. Cancel requests a stop;
    Force stop aborts the current call. F5 runs, Esc cancels.

    Settings (account, certificate thumbprint, limits, output folder) are stored in
    %APPDATA%\PowershellTools\M365MailFlowGui\settings.json. Search addresses are not stored.

.NOTES
    Requires Windows PowerShell 5.1 or PowerShell 7 on Windows, with an STA thread.
    The script relaunches itself with -STA when the current thread is MTA.
    ExchangeOnlineManagement 3.x is required for a live trace. Offline header and
    extended-report analysis does not contact Exchange.
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
        Write-Host 'Start this script with: powershell.exe -STA -File M365MailFlowInvestigation-GUI.ps1'
        exit 1
    }
    exit 0
}

$script:ModulePath = Join-Path $PSScriptRoot 'M365MailFlowInvestigation.psm1'
if (-not (Test-Path -LiteralPath $script:ModulePath)) {
    Write-Host "Investigation engine not found: $script:ModulePath" -ForegroundColor Red
    exit 1
}

try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
} catch {
    Write-Host "WinForms is not available in this PowerShell host: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Run M365MailFlowInvestigation-GUI.ps1 on Windows with powershell.exe -STA.'
    exit 1
}

try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch { }
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }

Import-Module $script:ModulePath -Force -DisableNameChecking
$script:EngineVersion = Get-M365MailFlowVersion
$script:Prereq = Get-M365MailFlowPrerequisite

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
$script:LoadingGrid = $false
$script:RunHandle = $null
$script:LastReport = $null
$script:LastFolder = $null
$script:EventRows = @()
$script:FindingRows = @()
$script:SettingsPath = Join-Path (Join-Path $env:APPDATA 'PowershellTools\M365MailFlowGui') 'settings.json'

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
    param($Parent, [int]$Top, [string]$Caption, $Control, [int]$ControlHeight = 24, [int]$LabelWidth = 112)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Caption
    $lbl.Font = $script:Font
    $lbl.ForeColor = [System.Drawing.Color]::FromArgb(31, 35, 40)
    $lbl.Location = New-Object System.Drawing.Point(10, ($Top + 3))
    $lbl.Size = New-Object System.Drawing.Size($LabelWidth, 20)
    $Control.Font = $script:Font
    $Control.Location = New-Object System.Drawing.Point((14 + $LabelWidth), $Top)
    $width = 386 - $LabelWidth - 24
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
    try { $docs = [Environment]::GetFolderPath('MyDocuments') } catch { $docs = $null }
    if ([string]::IsNullOrWhiteSpace($docs)) { $docs = $env:USERPROFILE }
    if ([string]::IsNullOrWhiteSpace($docs)) { $docs = (Get-Location).Path }
    return (Join-Path $docs 'M365MailFlow')
}

function Save-GuiSettings {
    try {
        $dir = Split-Path -Parent $script:SettingsPath
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $bag = [ordered]@{
            UserPrincipalName = $script:txtUpn.Text.Trim()
            AppId = $script:txtAppId.Text.Trim()
            CertificateThumbprint = ($script:txtThumb.Text -replace '\s', '')
            Organization = $script:txtOrg.Text.Trim()
            UseDeviceCode = [bool]$script:chkDevice.Checked
            DisableWAM = [bool]$script:chkWam.Checked
            SubjectFilterType = [string]$script:cmbSubject.SelectedItem
            MaxResults = [int]$script:numMax.Value
            MaxDetailLookups = [int]$script:numDetail.Value
            LatencyWarningMinutes = [int]$script:numLatency.Value
            ProblemsOnly = [bool]$script:chkProblems.Checked
            SkipDetail = [bool]$script:chkSkipDetail.Checked
            SkipEnrichment = [bool]$script:chkSkipEnrich.Checked
            IncludeMailboxChecks = [bool]$script:chkMailbox.Checked
            SkipDnsChecks = [bool]$script:chkSkipDns.Checked
            DisconnectWhenDone = [bool]$script:chkDisconnect.Checked
            OpenReport = [bool]$script:chkOpenReport.Checked
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

function ConvertFrom-DisplayText {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($Text.Length -gt 1 -and $Text.StartsWith("'")) {
        $second = $Text.Substring(1, 1)
        if ($second -eq '=' -or $second -eq '+' -or $second -eq '-' -or $second -eq '@') {
            return $Text.Substring(1)
        }
    }
    return $Text
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

function Update-ActionButtons {
    $script:btnRun.Enabled = -not $script:Busy
    $script:btnConnect.Enabled = -not $script:Busy
    $script:btnDisconnect.Enabled = -not $script:Busy
    $script:btnInstall.Enabled = -not $script:Busy
    $script:btnCancel.Enabled = $script:Busy
    if (-not $script:Busy) { $script:btnCancel.Text = 'Cancel (Esc)' }
}

function Show-ConnectionState {
    param($State)
    if ($null -eq $State -or $null -eq $State.PSObject.Properties['Connected']) { return }
    if ($State.Connected) {
        $who = [string]$State.UserPrincipalName
        if ([string]::IsNullOrWhiteSpace($who)) { $who = [string]$State.TenantId }
        if ([string]::IsNullOrWhiteSpace($who)) { $who = 'session open' }
        $extra = ''
        if ($State.Ipps) { $extra = '  |  Security & Compliance cmdlets available' }
        $script:lblConn.Text = "Connected: $who$extra"
        $script:lblConn.ForeColor = $script:ColorOk
    } else {
        $script:lblConn.Text = 'Not connected. Run will sign in when a live trace is needed.'
        $script:lblConn.ForeColor = $script:ColorMuted
    }
}

function Show-Prerequisite {
    param($Pre)
    if ($null -eq $Pre) { $Pre = Get-M365MailFlowPrerequisite }
    if ($Pre.ModuleInstalled) {
        $script:lblModule.Text = "ExchangeOnlineManagement $($Pre.ModuleVersion)"
        $script:lblModule.ForeColor = $script:ColorOk
    } else {
        $script:lblModule.Text = 'ExchangeOnlineManagement is not installed'
        $script:lblModule.ForeColor = $script:ColorDanger
    }
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
        Set-M365MailFlowUiBridge -Sync $Bridge
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

function Get-CheckedStatuses {
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($key in @($script:StatusBoxes.Keys)) {
        if ($script:StatusBoxes[$key].Checked) { $names.Add($key) }
    }
    return ,$names.ToArray()
}

function Test-InvestigationForm {
    $errors = New-Object System.Collections.Generic.List[string]
    $p = @{}

    $upn = $script:txtUpn.Text.Trim()
    $app = $script:txtAppId.Text.Trim()
    $thumb = ($script:txtThumb.Text -replace '\s', '')
    $org = $script:txtOrg.Text.Trim()
    $anyApp = $app -or $thumb -or $org
    if ($anyApp) {
        $guid = [guid]::Empty
        if (-not $app -or -not [guid]::TryParse($app, [ref]$guid)) { $errors.Add('App id must be a GUID when certificate authentication is used.') }
        if ($thumb -notmatch '^[0-9A-Fa-f]{40}$') { $errors.Add('Certificate thumbprint must be 40 hexadecimal characters.') }
        if (-not $org) { $errors.Add('Organization (tenant .onmicrosoft.com name) is required for certificate authentication.') }
    }
    if ($upn -and $upn -notmatch '@') { $errors.Add('User principal name should be an email address.') }
    if ($upn) { $p.UserPrincipalName = $upn }
    if ($anyApp -and $errors.Count -eq 0) {
        $p.AppId = $app
        $p.CertificateThumbprint = $thumb
        $p.Organization = $org
    }
    $p.UseDeviceCode = [bool]$script:chkDevice.Checked
    $p.DisableWAM = [bool]$script:chkWam.Checked

    $sender = $script:txtSender.Text.Trim()
    $recip = $script:txtRecipient.Text.Trim()
    $mid = $script:txtMessageId.Text.Trim()
    $subject = $script:txtSubject.Text.Trim()
    $fromIp = $script:txtFromIp.Text.Trim()
    $toIp = $script:txtToIp.Text.Trim()
    if ($sender) { $p.SenderAddress = @($sender) }
    if ($recip) { $p.RecipientAddress = @($recip) }
    if ($mid) { $p.MessageId = @($mid) }
    if ($subject) { $p.Subject = $subject }
    $p.SubjectFilterType = [string]$script:cmbSubject.SelectedItem
    if ($fromIp) { $p.FromIP = $fromIp }
    if ($toIp) { $p.ToIP = $toIp }
    $trace = $script:txtTrace.Text.Trim()
    if ($trace) {
        $g = [guid]::Empty
        if (-not [guid]::TryParse($trace, [ref]$g)) { $errors.Add('Message trace id must be a GUID (the Network Message ID).') }
        else { $p.MessageTraceId = $g }
    }
    if ($script:dtEnd.Value -le $script:dtStart.Value) { $errors.Add('End time must be after the start time.') }
    $p.StartDate = $script:dtStart.Value
    $p.EndDate = $script:dtEnd.Value
    $statuses = Get-CheckedStatuses
    if (@($statuses).Count -gt 0) { $p.Status = $statuses }

    $p.MaxResults = [int]$script:numMax.Value
    $p.MaxDetailLookups = [int]$script:numDetail.Value
    $p.LatencyWarningMinutes = [int]$script:numLatency.Value
    $p.ProblemsOnly = [bool]$script:chkProblems.Checked
    $p.SkipDetail = [bool]$script:chkSkipDetail.Checked
    $p.SkipEnrichment = [bool]$script:chkSkipEnrich.Checked
    $p.IncludeMailboxChecks = [bool]$script:chkMailbox.Checked
    $p.SkipDnsChecks = [bool]$script:chkSkipDns.Checked
    $p.Offline = [bool]$script:chkOffline.Checked
    $p.DisconnectWhenDone = [bool]$script:chkDisconnect.Checked
    $p.OpenReport = [bool]$script:chkOpenReport.Checked
    $p.SubmitHistoricalSearch = [bool]$script:chkHist.Checked
    $notify = $script:txtNotify.Text.Trim()
    if ($p.SubmitHistoricalSearch) {
        if ($p.Offline) { $errors.Add('A historical search needs Exchange Online. Clear Offline mode.') }
        if ($notify -notmatch '@') { $errors.Add('Historical search needs the address that should receive the completion mail.') }
        $hasTarget = ($sender -match '@') -or ($recip -match '@') -or $mid
        if (-not $hasTarget) { $errors.Add('Historical search needs a sender, a recipient, or a message id.') }
        if ($notify) { $p.NotifyAddress = @($notify) }
    }

    $header = $script:txtHeader.Text.Trim()
    $csv = $script:txtCsv.Text.Trim()
    if ($header) {
        if (-not (Test-Path -LiteralPath $header -PathType Leaf)) { $errors.Add("Header file was not found: $header") }
        else { $p.HeaderFile = $header }
    }
    if ($csv) {
        if (-not (Test-Path -LiteralPath $csv -PathType Leaf)) { $errors.Add("Extended report was not found: $csv") }
        else { $p.ExtendedReportCsv = $csv }
    }

    $parent = $script:txtOutput.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($parent)) { $errors.Add('Choose an output folder.') }
    else {
        if ($script:chkStamp.Checked) {
            $p.OutputPath = Join-Path $parent ('MailInvestigation_{0}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        } else {
            $p.OutputPath = $parent
        }
    }

    [pscustomobject]@{
        Ok = ($errors.Count -eq 0)
        Errors = $errors.ToArray()
        Parameters = $p
    }
}

function Get-AuthParameters {
    $check = Test-InvestigationForm
    # Always send the current boxes, including blanks, so a cleared account does not
    # keep the previous sign-in on the worker.
    $auth = @{
        UserPrincipalName = $script:txtUpn.Text.Trim()
        AppId = $script:txtAppId.Text.Trim()
        CertificateThumbprint = ($script:txtThumb.Text -replace '\s', '')
        Organization = $script:txtOrg.Text.Trim()
        UseDeviceCode = [bool]$script:chkDevice.Checked
        DisableWAM = [bool]$script:chkWam.Checked
    }
    [pscustomobject]@{ Ok = $check.Ok; Errors = $check.Errors; Auth = $auth }
}

function Clear-ResultsView {
    $script:LoadingGrid = $true
    $script:grid.Rows.Clear()
    $script:LoadingGrid = $false
    $script:txtSummary.Text = ''
    $script:txtFindings.Text = ''
    $script:txtJourney.Text = ''
    $script:EventRows = @()
    $script:FindingRows = @()
    $script:btnOpenReport.Enabled = $false
    $script:btnOpenFolder.Enabled = $false
}

function Import-ResultTable {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $rows = @(Import-Csv -LiteralPath $Path)
    return $rows
}

function Show-RunResult {
    param($Result)
    if ($null -eq $Result) {
        $script:lblStatus.Text = 'The run returned no result.'
        return
    }
    $script:LastReport = [string]$Result.ReportPath
    $script:LastFolder = [string]$Result.OutputPath
    $script:btnOpenReport.Enabled = ($script:LastReport -and (Test-Path -LiteralPath $script:LastReport))
    $script:btnOpenFolder.Enabled = ($script:LastFolder -and (Test-Path -LiteralPath $script:LastFolder))
    $code = 0
    try { $code = [int]$Result.ExitCode } catch { $code = 1 }
    if ($code -eq 2) { $script:lblStatus.Text = 'Cancelled. Partial output was kept when any messages had already been read.' }
    elseif ($code -eq 0) { $script:lblStatus.Text = "Finished. $($Result.MessageCount) message row(s). Report: $($script:LastReport)" }
    else {
        $why = [string]$Result.FatalError
        if (-not $why) { $why = 'The investigation failed.' }
        $script:lblStatus.Text = $why
        Append-Log $why 'ERROR'
    }
    $script:progress.Value = 100
    Load-ResultFolder -Folder $script:LastFolder -Result $Result
    if ([int]$Result.MessageCount -gt 0) { $script:tabs.SelectedTab = $script:tabMessages }
    else { $script:tabs.SelectedTab = $script:tabSummary }
}

function Load-ResultFolder {
    param([string]$Folder, $Result)
    Clear-ResultsView
    $script:LastFolder = $Folder
    if ($Result -and $Result.ReportPath) { $script:LastReport = [string]$Result.ReportPath }
    elseif ($Folder) { $script:LastReport = Join-Path $Folder 'Report.html' }
    $script:btnOpenReport.Enabled = ($script:LastReport -and (Test-Path -LiteralPath $script:LastReport))
    $script:btnOpenFolder.Enabled = ($Folder -and (Test-Path -LiteralPath $Folder))
    if (-not $Folder -or -not (Test-Path -LiteralPath $Folder)) {
        $script:txtSummary.Text = 'No output folder was produced.'
        return
    }
    $messages = Import-ResultTable (Join-Path $Folder 'Messages.csv')
    $script:EventRows = Import-ResultTable (Join-Path $Folder 'Events.csv')
    $script:FindingRows = Import-ResultTable (Join-Path $Folder 'Findings.csv')

    $script:LoadingGrid = $true
    $script:grid.SuspendLayout()
    foreach ($row in $messages) {
        $crit = 0
        $warn = 0
        try { $crit = [int]$row.Critical } catch { $crit = 0 }
        try { $warn = [int]$row.Warning } catch { $warn = 0 }
        $idx = $script:grid.Rows.Add(
            [string]$row.ReceivedUtc,
            [string]$row.Status,
            [string]$row.Direction,
            (ConvertFrom-DisplayText ([string]$row.Sender)),
            (ConvertFrom-DisplayText ([string]$row.Recipient)),
            (ConvertFrom-DisplayText ([string]$row.Subject)),
            (ConvertFrom-DisplayText ([string]$row.PrimaryCause)),
            [string]$crit,
            [string]$warn
        )
        $gridRow = $script:grid.Rows[$idx]
        $gridRow.Tag = $row
        if ($crit -gt 0 -or [string]$row.Status -eq 'Failed') {
            $gridRow.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(254, 243, 242)
        } elseif ($warn -gt 0 -or [string]$row.Status -in @('Pending', 'Quarantined', 'FilteredAsSpam')) {
            $gridRow.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 250, 235)
        }
    }
    $script:grid.ResumeLayout()
    $script:LoadingGrid = $false

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("Engine $($script:EngineVersion)")
    [void]$sb.AppendLine("Folder  $Folder")
    if ($script:LastReport) { [void]$sb.AppendLine("Report  $($script:LastReport)") }
    if ($Result -and $Result.FatalError) { [void]$sb.AppendLine("Error   $($Result.FatalError)") }
    if ($Result -and $Result.HistoricalSearch) { [void]$sb.AppendLine([string]$Result.HistoricalSearch) }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(("Messages  {0}" -f $messages.Count))
    $messages | Group-Object Status | Sort-Object Count -Descending | ForEach-Object {
        [void]$sb.AppendLine(("  {0,-16} {1}" -f $_.Name, $_.Count))
    }
    $critCount = @($script:FindingRows | Where-Object { $_.Severity -eq 'Critical' }).Count
    $warnCount = @($script:FindingRows | Where-Object { $_.Severity -eq 'Warning' }).Count
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("Critical findings  $critCount")
    [void]$sb.AppendLine("Warning findings   $warnCount")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Top causes')
    $causes = @($messages | Where-Object { $_.PrimaryCategory } | Group-Object PrimaryCategory | Sort-Object Count -Descending | Select-Object -First 8)
    if ($causes.Count -eq 0) { [void]$sb.AppendLine('  None') }
    else {
        foreach ($c in $causes) { [void]$sb.AppendLine(("  {0}  x{1}" -f $c.Name, $c.Count)) }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Select a message to read its findings and journey. The HTML report has the full timeline and enrichment.')
    $script:txtSummary.Text = $sb.ToString()
    if ($script:grid.Rows.Count -gt 0) {
        $script:grid.ClearSelection()
        $script:grid.Rows[0].Selected = $true
    }
}

function Show-SelectedMessage {
    if ($script:LoadingGrid) { return }
    if ($script:grid.SelectedRows.Count -eq 0) { return }
    $row = $script:grid.SelectedRows[0].Tag
    if ($null -eq $row) { return }
    $trace = [string]$row.MessageTraceId
    $recip = [string]$row.Recipient
    $findings = @($script:FindingRows | Where-Object { [string]$_.MessageTraceId -eq $trace -and [string]$_.Recipient -eq $recip })
    $events = @($script:EventRows | Where-Object { [string]$_.MessageTraceId -eq $trace -and [string]$_.Recipient -eq $recip })
    $fb = New-Object System.Text.StringBuilder
    [void]$fb.AppendLine((ConvertFrom-DisplayText ([string]$row.Subject)))
    [void]$fb.AppendLine(("{0}  ->  {1}" -f (ConvertFrom-DisplayText ([string]$row.Sender)), (ConvertFrom-DisplayText $recip)))
    [void]$fb.AppendLine(("Status {0}   Direction {1}   Transit {2}" -f $row.Status, $row.Direction, $row.TotalTransit))
    [void]$fb.AppendLine(("Message-ID {0}" -f (ConvertFrom-DisplayText ([string]$row.MessageId))))
    [void]$fb.AppendLine(("Trace      {0}" -f $trace))
    [void]$fb.AppendLine('')
    if ($row.PrimaryCause) {
        [void]$fb.AppendLine('Most likely cause')
        [void]$fb.AppendLine((ConvertFrom-DisplayText ([string]$row.PrimaryCause)))
        if ($row.Recommendation) {
            [void]$fb.AppendLine('')
            [void]$fb.AppendLine('Action')
            [void]$fb.AppendLine((ConvertFrom-DisplayText ([string]$row.Recommendation)))
        }
        [void]$fb.AppendLine('')
    }
    if ($findings.Count -eq 0) { [void]$fb.AppendLine('No findings for this recipient.') }
    foreach ($f in $findings) {
        [void]$fb.AppendLine(("[{0}] {1}" -f $f.Severity, $f.Category))
        [void]$fb.AppendLine((ConvertFrom-DisplayText ([string]$f.Finding)))
        if ($f.Evidence) { [void]$fb.AppendLine(("Evidence: {0}" -f (ConvertFrom-DisplayText ([string]$f.Evidence)))) }
        if ($f.Recommendation) { [void]$fb.AppendLine(("Action: {0}" -f (ConvertFrom-DisplayText ([string]$f.Recommendation)))) }
        [void]$fb.AppendLine('')
    }
    $script:txtFindings.Text = $fb.ToString()

    $jb = New-Object System.Text.StringBuilder
    if ($events.Count -eq 0) { [void]$jb.AppendLine('No journey events were retrieved for this row.') }
    foreach ($e in $events) {
        $gap = ''
        if ($e.GapSeconds) { $gap = "   +$($e.GapSeconds)s" }
        [void]$jb.AppendLine(("{0}   T+{1}{2}   {3}" -f $e.DateUtc, $e.Elapsed, $gap, $e.Event))
        if ($e.Detail) { [void]$jb.AppendLine(("  {0}" -f (ConvertFrom-DisplayText ([string]$e.Detail)))) }
        if ($e.Codes) { [void]$jb.AppendLine(("  Codes: {0}" -f $e.Codes)) }
        if ($e.LastError) { [void]$jb.AppendLine(("  Last error: {0}" -f (ConvertFrom-DisplayText ([string]$e.LastError)))) }
        if ($e.Verdicts) { [void]$jb.AppendLine(("  Verdicts: {0}" -f (ConvertFrom-DisplayText ([string]$e.Verdicts)))) }
        [void]$jb.AppendLine('')
    }
    $script:txtJourney.Text = $jb.ToString()
}

function Drain-WorkerStreams {
    if (-not $script:Worker) { return }
    foreach ($info in @($script:Worker.Streams.Information)) {
        $text = ([string]$info).Trim()
        if (-not $text) { continue }
        if ($text -match '^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]') { continue }
        Append-Log $text 'INFO'
    }
    foreach ($warn in @($script:Worker.Streams.Warning)) {
        $text = ([string]$warn).Trim()
        if ($text) { Append-Log $text 'WARN' }
    }
    foreach ($err in @($script:Worker.Streams.Error)) {
        $text = ([string]$err).Trim()
        if ($text) { Append-Log $text 'ERROR' }
    }
    try { $script:Worker.Streams.ClearStreams() } catch { }
}

function Drain-WorkerQueue {
    if (-not $script:Sync -or -not $script:Sync.Queue) { return }
    $item = $null
    while ($script:Sync.Queue.TryDequeue([ref]$item)) {
        if ($null -eq $item) { continue }
        if ($item.Type -eq 'Progress') {
            $pct = 0
            try { $pct = [int]$item.Percent } catch { $pct = 0 }
            if ($pct -lt 0) { $pct = 0 }
            if ($pct -gt 100) { $pct = 100 }
            $script:progress.Value = $pct
            $activity = [string]$item.Activity
            $message = [string]$item.Message
            if ($activity -and $message) { $script:lblStatus.Text = "$activity - $message" }
            elseif ($message) { $script:lblStatus.Text = $message }
        } elseif ($item.Message) {
            Append-Log ([string]$item.Message) ([string]$item.Level)
        }
    }
}

function Complete-WorkerAction {
    param($Result, $Failure)
    $action = $script:BusyAction
    $script:Busy = $false
    $script:BusyAction = ''
    $script:RunHandle = $null
    $script:CancelRequested = $false
    $script:btnCancel.Text = 'Cancel (Esc)'
    Update-ActionButtons
    if ($Failure) {
        $msg = [string]$Failure.Exception.Message
        if (-not $msg) { $msg = [string]$Failure }
        $cancelled = $script:Sync.Cancel -or ($msg -match 'cancel|stopped')
        if ($cancelled) {
            $script:lblStatus.Text = 'Cancelled.'
            Append-Log 'The running call was stopped.' 'WARN'
        } else {
            $script:lblStatus.Text = $msg
            Append-Log $msg 'ERROR'
            [System.Windows.Forms.MessageBox]::Show($msg, 'Mail flow investigation', 'OK', 'Error') | Out-Null
        }
    } elseif ($action -eq 'Run') {
        Show-RunResult $Result
    } elseif ($action -eq 'Connect' -or $action -eq 'Disconnect' -or $action -eq 'State') {
        Show-ConnectionState $Result
        if ($action -eq 'Connect') { $script:lblStatus.Text = $script:lblConn.Text }
        if ($action -eq 'Disconnect') { $script:lblStatus.Text = 'Disconnected.' }
    } elseif ($action -eq 'Install') {
        Show-Prerequisite $Result
        $script:lblStatus.Text = $script:lblModule.Text
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
    Set-M365MailFlowUiBridge -Sync $Bridge
    $Bridge.Cancel = $false
    Invoke-M365MailFlowInvestigation @Params
}

$script:ConnectWorkerScript = {
    param($Bridge, $Auth)
    $ErrorActionPreference = 'Stop'
    $InformationPreference = 'Continue'
    Set-M365MailFlowUiBridge -Sync $Bridge
    $Bridge.Cancel = $false
    Connect-M365MailFlowSession @Auth
}

$script:DisconnectWorkerScript = {
    param($Bridge)
    $ErrorActionPreference = 'Stop'
    Set-M365MailFlowUiBridge -Sync $Bridge
    Disconnect-M365MailFlowSession -Force
    Get-M365MailFlowConnectionState
}

$script:StateWorkerScript = {
    param($Bridge)
    $ErrorActionPreference = 'Stop'
    Set-M365MailFlowUiBridge -Sync $Bridge
    Get-M365MailFlowConnectionState
}

$script:InstallWorkerScript = {
    param($Bridge)
    $ErrorActionPreference = 'Stop'
    $InformationPreference = 'Continue'
    Set-M365MailFlowUiBridge -Sync $Bridge
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    Write-Log 'Installing ExchangeOnlineManagement for the current user...'
    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $nuget) {
        Write-Log 'Installing the NuGet package provider...'
        Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
    }
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    $pre = Get-M365MailFlowPrerequisite
    Write-Log ("ExchangeOnlineManagement {0} is installed." -f $pre.ModuleVersion) 'OK'
    $pre
}

function Start-Investigation {
    if ($script:Busy) { return }
    $check = Test-InvestigationForm
    if (-not $check.Ok) {
        $text = ($check.Errors -join "`r`n")
        [System.Windows.Forms.MessageBox]::Show($text, 'Check the form', 'OK', 'Warning') | Out-Null
        return
    }
    if ($check.Parameters.Offline -and -not $check.Parameters.HeaderFile -and -not $check.Parameters.ExtendedReportCsv) {
        $answer = [System.Windows.Forms.MessageBox]::Show(
            'Offline mode is on and no header file or extended report is selected. The run will write an empty report. Continue?',
            'Offline investigation',
            'YesNo',
            'Question')
        if ($answer -ne 'Yes') { return }
    }
    Save-GuiSettings
    Clear-ResultsView
    $script:progress.Value = 0
    $script:lblStatus.Text = 'Starting investigation...'
    $script:tabs.SelectedTab = $script:tabLog
    Append-Log '---- Run started ----' 'INFO'
    Start-WorkerAction -Action 'Run' -Script $script:RunWorkerScript -Arguments @($script:Sync, $check.Parameters)
}

function Start-Connect {
    if ($script:Busy) { return }
    $authCheck = Get-AuthParameters
    $blocking = @($authCheck.Errors | Where-Object { $_ -match 'App id|thumbprint|Organization|principal' })
    if ($blocking.Count -gt 0) {
        [System.Windows.Forms.MessageBox]::Show(($blocking -join "`r`n"), 'Check the connection', 'OK', 'Warning') | Out-Null
        return
    }
    $script:lblStatus.Text = 'Connecting. Complete the Microsoft sign-in if a window opens. Device codes appear below and in the console.'
    $script:tabs.SelectedTab = $script:tabLog
    Append-Log '---- Connect ----' 'INFO'
    Start-WorkerAction -Action 'Connect' -Script $script:ConnectWorkerScript -Arguments @($script:Sync, $authCheck.Auth)
}

function Start-Disconnect {
    if ($script:Busy) { return }
    $script:lblStatus.Text = 'Disconnecting...'
    Start-WorkerAction -Action 'Disconnect' -Script $script:DisconnectWorkerScript -Arguments @($script:Sync)
}

function Start-Install {
    if ($script:Busy) { return }
    $answer = [System.Windows.Forms.MessageBox]::Show(
        "Install or update ExchangeOnlineManagement for the current user from PSGallery?",
        'Install module',
        'YesNo',
        'Question')
    if ($answer -ne 'Yes') { return }
    $script:lblStatus.Text = 'Installing ExchangeOnlineManagement...'
    $script:tabs.SelectedTab = $script:tabLog
    Start-WorkerAction -Action 'Install' -Script $script:InstallWorkerScript -Arguments @($script:Sync)
}

function Stop-Investigation {
    if (-not $script:Busy) { return }
    if (-not $script:CancelRequested) {
        $script:CancelRequested = $true
        $script:Sync.Cancel = $true
        $script:btnCancel.Text = 'Force stop'
        $script:lblStatus.Text = 'Cancel requested. Waiting for the current Exchange call to return. Click Force stop to abort it.'
        Append-Log 'Cancel requested.' 'WARN'
        return
    }
    $script:lblStatus.Text = 'Aborting the current call.'
    Append-Log 'Force stop.' 'WARN'
    try { $script:Worker.Stop() } catch { }
}

function Browse-File {
    param($Target, [string]$Filter, [string]$Title)
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = $Filter
    $dlg.Title = $Title
    $dlg.CheckFileExists = $true
    if ($dlg.ShowDialog() -eq 'OK') { $Target.Text = $dlg.FileName }
}

function Browse-Folder {
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Folder for investigation reports'
    $dlg.ShowNewFolderButton = $true
    if ($script:txtOutput.Text -and (Test-Path -LiteralPath $script:txtOutput.Text)) {
        $dlg.SelectedPath = $script:txtOutput.Text
    }
    if ($dlg.ShowDialog() -eq 'OK') { $script:txtOutput.Text = $dlg.SelectedPath }
}

function Use-HeaderClipboard {
    $text = $null
    try { $text = [System.Windows.Forms.Clipboard]::GetText() } catch { $text = $null }
    if ([string]::IsNullOrWhiteSpace($text)) {
        [System.Windows.Forms.MessageBox]::Show('The clipboard has no text. Copy the message headers first.', 'Paste headers', 'OK', 'Information') | Out-Null
        return
    }
    $name = 'headers-{0}.txt' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    $path = Join-Path ([System.IO.Path]::GetTempPath()) $name
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($path, $text, $utf8)
    $script:txtHeader.Text = $path
    Append-Log "Saved clipboard headers to $path" 'OK'
}

# ---------- Form ----------
$script:form = New-Object System.Windows.Forms.Form
$script:form.Text = "Microsoft 365 Mail Flow Investigation  $script:EngineVersion"
$script:form.StartPosition = 'CenterScreen'
$script:form.Size = New-Object System.Drawing.Size(1280, 860)
$script:form.MinimumSize = New-Object System.Drawing.Size(1100, 720)
$script:form.BackColor = $script:ColorBg
$script:form.Font = $script:Font
$script:form.KeyPreview = $true

$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'
$header.Height = 58
$header.BackColor = $script:ColorHeader
$title = New-Object System.Windows.Forms.Label
$title.Text = 'Mail flow investigation'
$title.ForeColor = [System.Drawing.Color]::White
$title.Font = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
$title.Location = New-Object System.Drawing.Point(16, 8)
$title.AutoSize = $true
$subtitle = New-Object System.Windows.Forms.Label
$subtitle.Text = 'Message trace, journey detail, quarantine, DNS, headers, and a root-cause report.  F5 runs.  Esc cancels.'
$subtitle.ForeColor = [System.Drawing.Color]::FromArgb(198, 210, 224)
$subtitle.Font = $script:Font
$subtitle.Location = New-Object System.Drawing.Point(18, 34)
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
$script:lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(31, 35, 40)
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
$tips.AutoPopDelay = 12000
$tips.InitialDelay = 400

# Connection
$grpConn = New-Object System.Windows.Forms.GroupBox
$grpConn.Text = 'Connection'
$grpConn.Font = $script:FontBold
$grpConn.Location = New-Object System.Drawing.Point(8, 8)
$grpConn.Size = New-Object System.Drawing.Size(400, 324)
$left.Controls.Add($grpConn)
$y = 24
$script:txtUpn = New-TextBox
$y = Add-Labeled $grpConn $y 'Account' $script:txtUpn
$script:txtAppId = New-TextBox
$y = Add-Labeled $grpConn $y 'App id' $script:txtAppId
$script:txtThumb = New-TextBox
$y = Add-Labeled $grpConn $y 'Thumbprint' $script:txtThumb
$script:txtOrg = New-TextBox
$y = Add-Labeled $grpConn $y 'Organization' $script:txtOrg
$script:chkDevice = New-Check 'Sign in with a device code'
$script:chkDevice.Location = New-Object System.Drawing.Point(14, $y)
$grpConn.Controls.Add($script:chkDevice)
$y += 24
$script:chkWam = New-Check 'Disable WAM and use a browser'
$script:chkWam.Location = New-Object System.Drawing.Point(14, $y)
$grpConn.Controls.Add($script:chkWam)
$y += 28
$script:btnConnect = New-Button 'Connect' $script:ColorAccent ([System.Drawing.Color]::White)
$script:btnConnect.Location = New-Object System.Drawing.Point(14, $y)
$script:btnConnect.Size = New-Object System.Drawing.Size(88, 30)
$script:btnDisconnect = New-Button 'Disconnect' ([System.Drawing.Color]::White) $script:ColorDanger
$script:btnDisconnect.Location = New-Object System.Drawing.Point(108, $y)
$script:btnDisconnect.Size = New-Object System.Drawing.Size(100, 30)
$script:btnInstall = New-Button 'Install module' ([System.Drawing.Color]::White) $script:ColorAccent
$script:btnInstall.Location = New-Object System.Drawing.Point(214, $y)
$script:btnInstall.Size = New-Object System.Drawing.Size(120, 30)
$grpConn.Controls.Add($script:btnConnect)
$grpConn.Controls.Add($script:btnDisconnect)
$grpConn.Controls.Add($script:btnInstall)
$y += 36
$script:lblModule = New-Object System.Windows.Forms.Label
$script:lblModule.Font = $script:Font
$script:lblModule.Location = New-Object System.Drawing.Point(14, $y)
$script:lblModule.Size = New-Object System.Drawing.Size(370, 18)
$grpConn.Controls.Add($script:lblModule)
$y += 18
$script:lblConn = New-Object System.Windows.Forms.Label
$script:lblConn.Font = $script:Font
$script:lblConn.Location = New-Object System.Drawing.Point(14, $y)
$script:lblConn.Size = New-Object System.Drawing.Size(370, 32)
$grpConn.Controls.Add($script:lblConn)
$tips.SetToolTip($script:txtUpn, 'Optional. Leave blank to use the account picker. Ignored when App id, thumbprint, and organization are all set.')
$tips.SetToolTip($script:txtThumb, 'Certificate thumbprint in the CurrentUser or LocalMachine certificate store. Stored in settings on this PC. The certificate itself is not copied.')
$tips.SetToolTip($script:chkDevice, 'Use this when the sign-in window does not appear. The code is written to the log and the PowerShell window.')
$tips.SetToolTip($script:chkWam, 'Passed only when this ExchangeOnlineManagement build has -DisableWAM.')

# Search
$grpSearch = New-Object System.Windows.Forms.GroupBox
$grpSearch.Text = 'Trace filters'
$grpSearch.Font = $script:FontBold
$grpSearch.Location = New-Object System.Drawing.Point(8, 340)
$grpSearch.Size = New-Object System.Drawing.Size(400, 548)
$left.Controls.Add($grpSearch)
$y = 24
$script:txtSender = New-TextBox -Multi
$y = Add-Labeled $grpSearch $y 'Senders' $script:txtSender 52
$script:txtRecipient = New-TextBox -Multi
$y = Add-Labeled $grpSearch $y 'Recipients' $script:txtRecipient 52
$script:txtMessageId = New-TextBox -Multi
$y = Add-Labeled $grpSearch $y 'Message IDs' $script:txtMessageId 44
$script:txtTrace = New-TextBox
$y = Add-Labeled $grpSearch $y 'Trace id' $script:txtTrace
$script:txtSubject = New-TextBox
$y = Add-Labeled $grpSearch $y 'Subject' $script:txtSubject
$script:cmbSubject = New-Object System.Windows.Forms.ComboBox
$script:cmbSubject.DropDownStyle = 'DropDownList'
[void]$script:cmbSubject.Items.Add('Contains')
[void]$script:cmbSubject.Items.Add('StartsWith')
[void]$script:cmbSubject.Items.Add('EndsWith')
$script:cmbSubject.SelectedIndex = 0
$y = Add-Labeled $grpSearch $y 'Subject match' $script:cmbSubject
$script:txtFromIp = New-TextBox
$y = Add-Labeled $grpSearch $y 'From IP' $script:txtFromIp
$script:txtToIp = New-TextBox
$y = Add-Labeled $grpSearch $y 'To IP' $script:txtToIp
$script:dtStart = New-Object System.Windows.Forms.DateTimePicker
$script:dtStart.Format = 'Custom'
$script:dtStart.CustomFormat = 'yyyy-MM-dd HH:mm'
$script:dtStart.Value = (Get-Date).AddDays(-2)
$y = Add-Labeled $grpSearch $y 'Start (local)' $script:dtStart
$script:dtEnd = New-Object System.Windows.Forms.DateTimePicker
$script:dtEnd.Format = 'Custom'
$script:dtEnd.CustomFormat = 'yyyy-MM-dd HH:mm'
$script:dtEnd.Value = Get-Date
$y = Add-Labeled $grpSearch $y 'End (local)' $script:dtEnd
$lblStatusFilter = New-Object System.Windows.Forms.Label
$lblStatusFilter.Text = 'Statuses (blank = all)'
$lblStatusFilter.Font = $script:Font
$lblStatusFilter.Location = New-Object System.Drawing.Point(10, ($y + 4))
$lblStatusFilter.Size = New-Object System.Drawing.Size(150, 18)
$grpSearch.Controls.Add($lblStatusFilter)
$flow = New-Object System.Windows.Forms.FlowLayoutPanel
$flow.Location = New-Object System.Drawing.Point(14, ($y + 24))
$flow.Size = New-Object System.Drawing.Size(370, 52)
$flow.WrapContents = $true
$grpSearch.Controls.Add($flow)
$script:StatusBoxes = @{}
foreach ($name in @('Failed', 'Pending', 'Quarantined', 'FilteredAsSpam', 'Delivered', 'Expanded', 'GettingStatus')) {
    $cb = New-Check $name
    $cb.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 2)
    $flow.Controls.Add($cb)
    $script:StatusBoxes[$name] = $cb
}
$y = $y + 82
$btnProblems = New-Button 'Problem statuses' ([System.Drawing.Color]::White) ([System.Drawing.Color]::FromArgb(31, 35, 40))
$btnProblems.Location = New-Object System.Drawing.Point(14, $y)
$btnProblems.Size = New-Object System.Drawing.Size(130, 28)
$btnClearStatus = New-Button 'All statuses' ([System.Drawing.Color]::White) ([System.Drawing.Color]::FromArgb(31, 35, 40))
$btnClearStatus.Location = New-Object System.Drawing.Point(150, $y)
$btnClearStatus.Size = New-Object System.Drawing.Size(110, 28)
$grpSearch.Controls.Add($btnProblems)
$grpSearch.Controls.Add($btnClearStatus)
$tips.SetToolTip($script:txtSender, 'One address per line, or separate with semicolons. Display names such as Doe, Jane <user@contoso.com> are accepted.')
$tips.SetToolTip($script:txtMessageId, 'Internet message ids. Angle brackets are optional. One per line.')
$tips.SetToolTip($script:txtTrace, 'Network message id / MessageTraceId GUID. A header file can supply this when the other filters are empty.')

# Scope
$grpScope = New-Object System.Windows.Forms.GroupBox
$grpScope.Text = 'Scope'
$grpScope.Font = $script:FontBold
$grpScope.Location = New-Object System.Drawing.Point(8, 896)
$grpScope.Size = New-Object System.Drawing.Size(400, 400)
$left.Controls.Add($grpScope)
$y = 24
$script:numMax = New-Object System.Windows.Forms.NumericUpDown
$script:numMax.Minimum = 1
$script:numMax.Maximum = 50000
$script:numMax.Value = 5000
$script:numMax.ThousandsSeparator = $true
$y = Add-Labeled $grpScope $y 'Max messages' $script:numMax
$script:numDetail = New-Object System.Windows.Forms.NumericUpDown
$script:numDetail.Minimum = 0
$script:numDetail.Maximum = 5000
$script:numDetail.Value = 250
$y = Add-Labeled $grpScope $y 'Max detail' $script:numDetail
$script:numLatency = New-Object System.Windows.Forms.NumericUpDown
$script:numLatency.Minimum = 1
$script:numLatency.Maximum = 1440
$script:numLatency.Value = 10
$y = Add-Labeled $grpScope $y 'Latency (min)' $script:numLatency
$script:chkProblems = New-Check 'Detail for problems only (skip Delivered and Expanded)'
$script:chkProblems.Location = New-Object System.Drawing.Point(14, $y)
$grpScope.Controls.Add($script:chkProblems)
$y += 24
$script:chkSkipDetail = New-Check 'Skip journey detail'
$script:chkSkipDetail.Location = New-Object System.Drawing.Point(14, $y)
$grpScope.Controls.Add($script:chkSkipDetail)
$y += 24
$script:chkSkipEnrich = New-Check 'Skip tenant enrichment'
$script:chkSkipEnrich.Location = New-Object System.Drawing.Point(14, $y)
$grpScope.Controls.Add($script:chkSkipEnrich)
$y += 24
$script:chkMailbox = New-Check 'Include mailbox checks (inbox rules and junk settings)'
$script:chkMailbox.Location = New-Object System.Drawing.Point(14, $y)
$grpScope.Controls.Add($script:chkMailbox)
$y += 24
$script:chkSkipDns = New-Check 'Skip DNS checks'
$script:chkSkipDns.Location = New-Object System.Drawing.Point(14, $y)
$grpScope.Controls.Add($script:chkSkipDns)
$y += 24
$script:chkOffline = New-Check 'Offline (headers or extended CSV only)'
$script:chkOffline.Location = New-Object System.Drawing.Point(14, $y)
$grpScope.Controls.Add($script:chkOffline)
$y += 24
$script:chkHist = New-Check 'Submit an extended historical search'
$script:chkHist.Location = New-Object System.Drawing.Point(14, $y)
$grpScope.Controls.Add($script:chkHist)
$y += 26
$script:txtNotify = New-TextBox
$y = Add-Labeled $grpScope $y 'Notify' $script:txtNotify
$script:chkDisconnect = New-Check 'Disconnect Exchange when the run finishes'
$script:chkDisconnect.Location = New-Object System.Drawing.Point(14, $y)
$grpScope.Controls.Add($script:chkDisconnect)
$y += 24
$script:chkOpenReport = New-Check 'Open the HTML report when the run finishes'
$script:chkOpenReport.Location = New-Object System.Drawing.Point(14, $y)
$grpScope.Controls.Add($script:chkOpenReport)
$tips.SetToolTip($script:numDetail, 'Journey detail calls are throttled. Problem messages are retrieved first.')
$tips.SetToolTip($script:chkMailbox, 'Needs Exchange Recipient Administrator or a higher role. Used when the user says a delivered message is missing.')
$tips.SetToolTip($script:chkDisconnect, 'Closes the Exchange session on the worker, including a session that was already open.')

# Sources
$grpSrc = New-Object System.Windows.Forms.GroupBox
$grpSrc.Text = 'Extra sources'
$grpSrc.Font = $script:FontBold
$grpSrc.Location = New-Object System.Drawing.Point(8, 1304)
$grpSrc.Size = New-Object System.Drawing.Size(400, 112)
$left.Controls.Add($grpSrc)
$y = 24
$script:txtHeader = New-TextBox
$yHdr = $y
$y = Add-Labeled $grpSrc $y 'Headers' $script:txtHeader
$script:txtHeader.Width = 130
$btnHeader = New-Button '...' ([System.Drawing.Color]::White) ([System.Drawing.Color]::FromArgb(31, 35, 40))
$btnHeader.Location = New-Object System.Drawing.Point(258, $yHdr)
$btnHeader.Size = New-Object System.Drawing.Size(32, 24)
$btnPaste = New-Button 'Paste' ([System.Drawing.Color]::White) $script:ColorAccent
$btnPaste.Location = New-Object System.Drawing.Point(294, $yHdr)
$btnPaste.Size = New-Object System.Drawing.Size(90, 24)
$grpSrc.Controls.Add($btnHeader)
$grpSrc.Controls.Add($btnPaste)
$script:txtCsv = New-TextBox
$yCsv = $y
$y = Add-Labeled $grpSrc $y 'Extended CSV' $script:txtCsv
$script:txtCsv.Width = 166
$btnCsv = New-Button '...' ([System.Drawing.Color]::White) ([System.Drawing.Color]::FromArgb(31, 35, 40))
$btnCsv.Location = New-Object System.Drawing.Point(294, $yCsv)
$btnCsv.Size = New-Object System.Drawing.Size(90, 24)
$grpSrc.Controls.Add($btnCsv)
$tips.SetToolTip($btnPaste, 'Save internet headers from the clipboard into a temp file and analyse them.')
$tips.SetToolTip($script:txtCsv, 'Extended message-trace detail report downloaded from the Exchange admin center. UTF-8 and UTF-16 are both accepted.')

# Output
$grpOut = New-Object System.Windows.Forms.GroupBox
$grpOut.Text = 'Output'
$grpOut.Font = $script:FontBold
$grpOut.Location = New-Object System.Drawing.Point(8, 1424)
$grpOut.Size = New-Object System.Drawing.Size(400, 96)
$left.Controls.Add($grpOut)
$script:txtOutput = New-TextBox
$script:txtOutput.Text = Get-DefaultOutputParent
Add-Labeled $grpOut 24 'Folder' $script:txtOutput | Out-Null
$script:txtOutput.Width = 168
$btnFolder = New-Button '...' ([System.Drawing.Color]::White) ([System.Drawing.Color]::FromArgb(31, 35, 40))
$btnFolder.Location = New-Object System.Drawing.Point(318, 24)
$btnFolder.Size = New-Object System.Drawing.Size(32, 24)
$grpOut.Controls.Add($btnFolder)
$script:chkStamp = New-Check 'Create a new timestamped folder for each run'
$script:chkStamp.Checked = $true
$script:chkStamp.Location = New-Object System.Drawing.Point(14, 58)
$grpOut.Controls.Add($script:chkStamp)

$script:btnRun = New-Button 'Run (F5)' $script:ColorAccent ([System.Drawing.Color]::White)
$script:btnRun.Location = New-Object System.Drawing.Point(22, 1532)
$script:btnRun.Size = New-Object System.Drawing.Size(180, 34)
$script:btnCancel = New-Button 'Cancel (Esc)' $script:ColorDanger ([System.Drawing.Color]::White)
$script:btnCancel.Location = New-Object System.Drawing.Point(214, 1532)
$script:btnCancel.Size = New-Object System.Drawing.Size(180, 34)
$script:btnCancel.Enabled = $false
$left.Controls.Add($script:btnRun)
$left.Controls.Add($script:btnCancel)
$scrollPad = New-Object System.Windows.Forms.Panel
$scrollPad.Location = New-Object System.Drawing.Point(0, 1580)
$scrollPad.Size = New-Object System.Drawing.Size(10, 20)
$left.Controls.Add($scrollPad)

# Right side
$script:tabs = New-Object System.Windows.Forms.TabControl
$script:tabs.Dock = 'Fill'
$script:tabs.Font = $script:Font
$script:split.Panel2.Controls.Add($script:tabs)

$script:tabSummary = New-Object System.Windows.Forms.TabPage
$script:tabSummary.Text = 'Summary'
$script:tabSummary.BackColor = $script:ColorBg
$script:tabSummary.Padding = New-Object System.Windows.Forms.Padding(8)
$script:tabs.TabPages.Add($script:tabSummary)
$sumBar = New-Object System.Windows.Forms.FlowLayoutPanel
$sumBar.Dock = 'Top'
$sumBar.Height = 42
$sumBar.Padding = New-Object System.Windows.Forms.Padding(4)
$script:btnOpenReport = New-Button 'Open HTML report' $script:ColorAccent ([System.Drawing.Color]::White)
$script:btnOpenReport.Width = 150
$script:btnOpenReport.Enabled = $false
$script:btnOpenFolder = New-Button 'Open folder' ([System.Drawing.Color]::White) $script:ColorAccent
$script:btnOpenFolder.Width = 110
$script:btnOpenFolder.Enabled = $false
$sumBar.Controls.Add($script:btnOpenReport)
$sumBar.Controls.Add($script:btnOpenFolder)
$script:txtSummary = New-Object System.Windows.Forms.TextBox
$script:txtSummary.Multiline = $true
$script:txtSummary.ReadOnly = $true
$script:txtSummary.ScrollBars = 'Vertical'
$script:txtSummary.Dock = 'Fill'
$script:txtSummary.Font = $script:FontMono
$script:txtSummary.BackColor = [System.Drawing.Color]::White
$script:txtSummary.BorderStyle = 'None'
$script:tabSummary.Controls.Add($script:txtSummary)
$script:tabSummary.Controls.Add($sumBar)

$script:tabMessages = New-Object System.Windows.Forms.TabPage
$script:tabMessages.Text = 'Messages'
$script:tabMessages.BackColor = [System.Drawing.Color]::White
$script:tabs.TabPages.Add($script:tabMessages)
$script:grid = New-Object System.Windows.Forms.DataGridView
$script:grid.Dock = 'Fill'
$script:grid.ReadOnly = $true
$script:grid.AllowUserToAddRows = $false
$script:grid.AllowUserToDeleteRows = $false
$script:grid.AllowUserToResizeRows = $false
$script:grid.RowHeadersVisible = $false
$script:grid.SelectionMode = 'FullRowSelect'
$script:grid.MultiSelect = $false
$script:grid.AutoSizeColumnsMode = 'Fill'
$script:grid.BackgroundColor = [System.Drawing.Color]::White
$script:grid.BorderStyle = 'None'
$script:grid.EnableHeadersVisualStyles = $false
$script:grid.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(238, 241, 244)
$script:grid.ColumnHeadersDefaultCellStyle.Font = $script:FontBold
$script:grid.ColumnHeadersHeight = 32
$script:grid.RowTemplate.Height = 24
$script:grid.Font = $script:Font
foreach ($col in @(
    @{ N = 'Received (UTC)'; W = 130 },
    @{ N = 'Status'; W = 90 },
    @{ N = 'Direction'; W = 80 },
    @{ N = 'Sender'; W = 160 },
    @{ N = 'Recipient'; W = 160 },
    @{ N = 'Subject'; W = 180 },
    @{ N = 'Cause'; W = 220 },
    @{ N = 'Critical'; W = 60 },
    @{ N = 'Warning'; W = 70 }
)) {
    $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $c.Name = $col.N
    $c.HeaderText = $col.N
    $c.FillWeight = $col.W
    $c.MinimumWidth = 50
    [void]$script:grid.Columns.Add($c)
}
$script:tabMessages.Controls.Add($script:grid)

$script:tabDetail = New-Object System.Windows.Forms.TabPage
$script:tabDetail.Text = 'Detail'
$script:tabDetail.BackColor = $script:ColorBg
$script:tabs.TabPages.Add($script:tabDetail)
$script:detailSplit = New-Object System.Windows.Forms.SplitContainer
$detailSplit = $script:detailSplit
$detailSplit.Dock = 'Fill'
$detailSplit.Orientation = 'Horizontal'
$detailSplit.Panel1MinSize = 40
$detailSplit.Panel2MinSize = 40
$script:txtFindings = New-Object System.Windows.Forms.TextBox
$script:txtFindings.Multiline = $true
$script:txtFindings.ReadOnly = $true
$script:txtFindings.ScrollBars = 'Vertical'
$script:txtFindings.Dock = 'Fill'
$script:txtFindings.Font = $script:Font
$script:txtFindings.BackColor = [System.Drawing.Color]::White
$script:txtJourney = New-Object System.Windows.Forms.TextBox
$script:txtJourney.Multiline = $true
$script:txtJourney.ReadOnly = $true
$script:txtJourney.ScrollBars = 'Both'
$script:txtJourney.WordWrap = $false
$script:txtJourney.Dock = 'Fill'
$script:txtJourney.Font = $script:FontMono
$script:txtJourney.BackColor = [System.Drawing.Color]::White
$detailSplit.Panel1.Controls.Add($script:txtFindings)
$detailSplit.Panel2.Controls.Add($script:txtJourney)
$script:tabDetail.Controls.Add($detailSplit)

$script:tabLog = New-Object System.Windows.Forms.TabPage
$script:tabLog.Text = 'Log'
$script:tabLog.BackColor = [System.Drawing.Color]::White
$script:tabs.TabPages.Add($script:tabLog)
$script:txtLog = New-Object System.Windows.Forms.RichTextBox
$script:txtLog.Dock = 'Fill'
$script:txtLog.ReadOnly = $true
$script:txtLog.Font = $script:FontMono
$script:txtLog.BackColor = [System.Drawing.Color]::White
$script:txtLog.BorderStyle = 'None'
$script:txtLog.DetectUrls = $false
$script:tabLog.Controls.Add($script:txtLog)

$script:form.Controls.Add($script:split)
$script:form.Controls.Add($footer)
$script:form.Controls.Add($header)

# Apply saved settings before events that read them.
$saved = Import-GuiSettings
if ($saved) {
    $script:txtUpn.Text = [string](Get-JsonProperty $saved 'UserPrincipalName' '')
    $script:txtAppId.Text = [string](Get-JsonProperty $saved 'AppId' '')
    $script:txtThumb.Text = [string](Get-JsonProperty $saved 'CertificateThumbprint' '')
    $script:txtOrg.Text = [string](Get-JsonProperty $saved 'Organization' '')
    $script:chkDevice.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'UseDeviceCode' $false) $false
    $script:chkWam.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'DisableWAM' $false) $false
    $matchType = [string](Get-JsonProperty $saved 'SubjectFilterType' 'Contains')
    $idx = $script:cmbSubject.Items.IndexOf($matchType)
    if ($idx -ge 0) { $script:cmbSubject.SelectedIndex = $idx }
    try { $script:numMax.Value = [decimal](Get-JsonProperty $saved 'MaxResults' 5000) } catch { }
    try { $script:numDetail.Value = [decimal](Get-JsonProperty $saved 'MaxDetailLookups' 250) } catch { }
    try { $script:numLatency.Value = [decimal](Get-JsonProperty $saved 'LatencyWarningMinutes' 10) } catch { }
    $script:chkProblems.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'ProblemsOnly' $false) $false
    $script:chkSkipDetail.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'SkipDetail' $false) $false
    $script:chkSkipEnrich.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'SkipEnrichment' $false) $false
    $script:chkMailbox.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'IncludeMailboxChecks' $false) $false
    $script:chkSkipDns.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'SkipDnsChecks' $false) $false
    $script:chkDisconnect.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'DisconnectWhenDone' $false) $false
    $script:chkOpenReport.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'OpenReport' $false) $false
    $script:chkStamp.Checked = ConvertTo-BoolSetting (Get-JsonProperty $saved 'NewTimestampedFolder' $true) $true
    $parent = [string](Get-JsonProperty $saved 'OutputParent' '')
    if ($parent) { $script:txtOutput.Text = $parent }
    $w = 0
    $h = 0
    try { $w = [int](Get-JsonProperty $saved 'WindowWidth' 0) } catch { $w = 0 }
    try { $h = [int](Get-JsonProperty $saved 'WindowHeight' 0) } catch { $h = 0 }
    if ($w -ge 1100 -and $h -ge 720) { $script:form.Size = New-Object System.Drawing.Size($w, $h) }
}
Show-Prerequisite $script:Prereq
$script:lblConn.Text = 'Not connected. Run will sign in when a live trace is needed.'
$script:lblConn.ForeColor = $script:ColorMuted
Append-Log "Mail flow investigation GUI $($script:GuiVersion), engine $($script:EngineVersion)." 'INFO'
if (-not $script:Prereq.ModuleInstalled) {
    Append-Log 'ExchangeOnlineManagement is not installed. Use Install module, or stay offline with a header file or extended CSV.' 'WARN'
} else {
    Append-Log "ExchangeOnlineManagement $($script:Prereq.ModuleVersion) is installed." 'OK'
}
Append-Log 'Search addresses are not saved. The certificate thumbprint is saved in your AppData settings file.' 'INFO'

$script:btnRun.Add_Click({ Start-Investigation })
$script:btnCancel.Add_Click({ Stop-Investigation })
$script:btnConnect.Add_Click({ Start-Connect })
$script:btnDisconnect.Add_Click({ Start-Disconnect })
$script:btnInstall.Add_Click({ Start-Install })
$btnHeader.Add_Click({ Browse-File $script:txtHeader 'Text and messages|*.txt;*.eml;*.log|All files|*.*' 'Message headers' })
$btnCsv.Add_Click({ Browse-File $script:txtCsv 'CSV files|*.csv|All files|*.*' 'Extended message trace report' })
$btnFolder.Add_Click({ Browse-Folder })
$btnPaste.Add_Click({ Use-HeaderClipboard })
$btnProblems.Add_Click({
    foreach ($key in @($script:StatusBoxes.Keys)) {
        $script:StatusBoxes[$key].Checked = ($key -in @('Failed', 'Pending', 'Quarantined', 'FilteredAsSpam'))
    }
})
$btnClearStatus.Add_Click({
    foreach ($key in @($script:StatusBoxes.Keys)) { $script:StatusBoxes[$key].Checked = $false }
})
$script:grid.Add_SelectionChanged({ Show-SelectedMessage })
$script:grid.Add_CellDoubleClick({
    param($sender, $e)
    if ($e.RowIndex -ge 0) { $script:tabs.SelectedTab = $script:tabDetail }
})
$script:btnOpenReport.Add_Click({
    if ($script:LastReport -and (Test-Path -LiteralPath $script:LastReport)) {
        Start-Process -FilePath $script:LastReport
    }
})
$script:btnOpenFolder.Add_Click({
    if ($script:LastFolder -and (Test-Path -LiteralPath $script:LastFolder)) {
        Start-Process -FilePath $script:LastFolder
    }
})
$script:form.Add_KeyDown({
    param($sender, $e)
    if ($e.KeyCode -eq 'F5') {
        $e.SuppressKeyPress = $true
        Start-Investigation
    } elseif ($e.KeyCode -eq 'Escape') {
        $e.SuppressKeyPress = $true
        Stop-Investigation
    }
})
$script:form.Add_FormClosing({
    param($sender, $e)
    Save-GuiSettings
    if ($script:Busy -and -not $script:AllowClose) {
        $e.Cancel = $true
        $answer = [System.Windows.Forms.MessageBox]::Show(
            'An investigation is still running. Stop it and close?',
            'Mail flow investigation',
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
    try { $script:detailSplit.SplitterDistance = 280 } catch { }
    try {
        Start-WorkerAction -Action 'State' -Script $script:StateWorkerScript -Arguments @($script:Sync)
    } catch {
        Append-Log $_.Exception.Message 'ERROR'
    }
})

try {
    Initialize-Worker
} catch {
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Mail flow investigation', 'OK', 'Error') | Out-Null
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

#Requires -Version 5.1
<#
.SYNOPSIS
    Desktop window for exporting Microsoft Teams call records.

.DESCRIPTION
    WinForms front end for TeamsCallReport.Core.ps1. Start it with
    Start-TeamsCallReport.cmd so Windows PowerShell is in STA mode.
    Secrets are kept in memory only and are not written to settings.json.
#>
[CmdletBinding()]
param(
    [switch] $StaReady
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

if ($env:OS -eq 'Windows_NT' -and -not $StaReady.IsPresent) {
    $apartment = [Threading.Thread]::CurrentThread.GetApartmentState()
    if ($apartment -ne 'STA') {
        $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (-not (Test-Path -LiteralPath $exe)) { $exe = 'powershell.exe' }
        $launchArgs = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA',
            '-File', $PSCommandPath, '-StaReady'
        )
        Start-Process -FilePath $exe -ArgumentList $launchArgs | Out-Null
        return
    }
}

if ($env:OS -ne 'Windows_NT') {
    Write-Error 'The Teams Call Report window needs Windows PowerShell and WinForms. On Windows, run Start-TeamsCallReport.cmd.'
    return
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

try {
    if (-not ('TeamsCallReportDpi' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class TeamsCallReportDpi {
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
}
'@
    }
    [void][TeamsCallReportDpi]::SetProcessDPIAware()
}
catch { }
try { [System.Windows.Forms.Application]::SetHighDpiMode([System.Windows.Forms.HighDpiMode]::PerMonitorV2) } catch { }
[System.Windows.Forms.Application]::EnableVisualStyles()
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }

$script:CorePath = Join-Path $PSScriptRoot 'TeamsCallReport.Core.ps1'
if (-not (Test-Path -LiteralPath $script:CorePath)) {
    $coreMessage = "Keep TeamsCallReport.Core.ps1 in the same folder as this script.`r`n`r`nExpected:`r`n$script:CorePath"
    [System.Windows.Forms.MessageBox]::Show($coreMessage, 'Teams Call Report') | Out-Null
    Write-Error $coreMessage
    return
}
$coreSource = [System.IO.File]::ReadAllText($script:CorePath)
if ($coreSource -notmatch 'function Connect-TeamsCallReportAccount') {
    $coreMessage = "TeamsCallReport.Core.ps1 next to this script is an older copy. Replace it with the core file from the same download as this window.`r`n`r`n$script:CorePath"
    [System.Windows.Forms.MessageBox]::Show($coreMessage, 'Teams Call Report') | Out-Null
    Write-Error $coreMessage
    return
}
$script:WorkerSource = @'
param($Sync, $CorePath, $Operation, $Payload)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
$script:Sync = $Sync
. $CorePath

function Add-WorkerLog {
    param($Level, $Message)
    $line = "{0:HH:mm:ss}  {1,-5} {2}" -f (Get-Date), $Level, $Message
    [void]$script:Sync.Log.Add($line)
}

function New-WorkerClient {
    param($Payload)
    if ($Payload.AuthMode -eq 'Sample') { return (New-TeamsSampleGraphClient) }
    $params = @{ Cloud = [string]$Payload.Cloud }
    if ($Payload.AuthMode -eq 'CertificateThumbprint') {
        $params.TenantId = [string]$Payload.TenantId
        $params.ClientId = [string]$Payload.ClientId
        $params.CertificateThumbprint = [string]$Payload.Thumbprint
    }
    elseif ($Payload.AuthMode -eq 'CertificateFile') {
        $params.TenantId = [string]$Payload.TenantId
        $params.ClientId = [string]$Payload.ClientId
        $params.CertificatePath = [string]$Payload.CertificatePath
        if ($Payload.CertificatePassword) { $params.CertificatePassword = $Payload.CertificatePassword }
    }
    elseif ($Payload.AuthMode -eq 'Secret') {
        $params.TenantId = [string]$Payload.TenantId
        $params.ClientId = [string]$Payload.ClientId
        $params.ClientSecret = $Payload.ClientSecret
    }
    elseif ($Payload.AuthMode -eq 'Existing') {
        $params.UseExistingConnection = $true
    }
    elseif ($Payload.AuthMode -eq 'Account') {
        $connected = Connect-TeamsCallReportAccount -Cloud ([string]$Payload.Cloud) -ShouldCancel { [bool]$script:Sync.Cancel } -Log {
            param($Level, $Message)
            Add-WorkerLog $Level $Message
        } -OnDeviceCode {
            param($Info)
            $script:Sync.DeviceCode = [string]$Info.UserCode
            $script:Sync.DeviceUrl = [string]$Info.VerificationUrl
            $script:Sync.StatusText = [string]$Info.Message
            Add-WorkerLog 'INFO' ([string]$Info.Message)
        }
        if ($connected.Reused) { Add-WorkerLog 'INFO' 'Reused the Teams Call Report application from the last sign-in.' }
        else { Add-WorkerLog 'INFO' ("Granted call-record access to application $($connected.ClientId).") }
        $script:Sync.StatusText = "Ready. Tenant $($connected.TenantId)."
        return $connected.Client
    }
    else {
        throw "Unknown sign-in mode."
    }
    return (New-TeamsGraphClient @params)
}

function Get-WorkerTokenText {
    param($Client)
    $info = $null
    if ($Client.ContainsKey('TokenInfo')) { $info = $Client.TokenInfo }
    if (-not $info) {
        if ($Client.Kind -eq 'Sample') { return 'Sample data is ready. No tenant is connected.' }
        return 'Connected.'
    }
    $roles = @($info.Roles) -join ', '
    if (-not $roles) { $roles = '(none)' }
    foreach ($warning in @($info.Warnings)) {
        if ($warning) { Add-WorkerLog 'WARN' $warning }
    }
    return ("Connected. Tenant {0}; auth {1}; roles: {2}" -f $info.TenantId, $info.AuthType, $roles)
}

try {
    Add-WorkerLog 'INFO' ("Starting {0}." -f $Operation)
    if ($Operation -eq 'Connect' -or $Operation -eq 'Resolve' -or $Operation -eq 'Export') {
        $client = $null
        $useSample = ($Payload.AuthMode -eq 'Sample') -or ($Operation -eq 'Export' -and $Payload.Sample)
        if ($useSample) {
            $client = New-TeamsSampleGraphClient
            if ($Operation -ne 'Resolve') { Add-WorkerLog 'INFO' 'Using built-in sample call records. No tenant connection.' }
        }
        else {
            $client = New-WorkerClient $Payload
            $tokenText = Get-WorkerTokenText $client
            Add-WorkerLog 'INFO' $tokenText
            $script:Sync.StatusText = $tokenText
        }
        if ($Operation -eq 'Connect') {
            if ($useSample) { $script:Sync.StatusText = 'Sample data is ready. No tenant is connected.' }
        }
        elseif ($Operation -eq 'Resolve') {
            $user = Resolve-TeamsUser -GraphClient $client -User ([string]$Payload.User)
            $script:Sync.ResolvedText = "{0} <{1}> [{2}]" -f $user.displayName, $user.userPrincipalName, $user.id
            $script:Sync.StatusText = "Resolved $($script:Sync.ResolvedText)"
            Add-WorkerLog 'INFO' $script:Sync.StatusText
        }
        else {
            $log = {
                param($Level, $Message)
                $line = "{0:HH:mm:ss}  {1,-5} {2}" -f (Get-Date), $Level, $Message
                [void]$script:Sync.Log.Add($line)
            }
            $progress = {
                param($Percent, $Status)
                $script:Sync.Progress = [int]$Percent
                $script:Sync.StatusText = [string]$Status
            }
            $cancel = { return [bool]$script:Sync.Cancel }
            $exportParams = @{
                User         = [string]$Payload.User
                StartDate    = $Payload.Start
                EndDate      = $Payload.End
                OutputPath   = [string]$Payload.OutputPath
                GraphClient  = $client
                MaxCalls     = [int]$Payload.MaxCalls
                Log          = $log
                Progress     = $progress
                ShouldCancel = $cancel
            }
            if ($Payload.SkipDirectory) { $exportParams.SkipDirectoryLookup = $true }
            if (-not $Payload.SaveRawJson) { $exportParams.SkipRawJson = $true }
            $result = Export-TeamsUserCallDetails @exportParams
            $script:Sync.Result = $result
            if ($result.ErrorMessage) {
                $script:Sync.ErrorText = [string]$result.ErrorMessage
                Add-WorkerLog 'ERROR' $result.ErrorMessage
            }
            elseif ($result.Cancelled) {
                $script:Sync.StatusText = 'Cancelled. Partial files were kept.'
                Add-WorkerLog 'WARN' $script:Sync.StatusText
            }
            else {
                $script:Sync.StatusText = "Export complete. $($result.CallCount) call(s)."
                Add-WorkerLog 'INFO' $script:Sync.StatusText
            }
            $script:Sync.Progress = 100
        }
    }
    else {
        throw "Unknown operation '$Operation'."
    }
}
catch {
    $script:Sync.ErrorText = [string]$_.Exception.Message
    Add-WorkerLog 'ERROR' $script:Sync.ErrorText
}
finally {
    $script:Sync.Done = $true
}
'@

$script:Ui = @{}
$logList = New-Object System.Collections.ArrayList
$script:Ui.Sync = [hashtable]::Synchronized(@{
        Cancel       = $false
        Done         = $false
        Progress     = 0
        StatusText   = 'Ready'
        ErrorText    = $null
        Result       = $null
        ResolvedText = $null
        Operation    = $null
        Log          = [System.Collections.ArrayList]::Synchronized($logList)
    })
$script:Ui.Busy = $false
$script:Ui.CallView = $null
$script:Ui.ParticipantView = $null
$script:Ui.EndpointView = $null
$script:Ui.SuppressSelection = $false

function Get-SettingsPath {
    $root = $env:APPDATA
    if ([string]::IsNullOrWhiteSpace($root)) { $root = (Join-Path $env:USERPROFILE 'AppData\Roaming') }
    $dir = Join-Path $root 'TeamsCallReport'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    return (Join-Path $dir 'settings.json')
}

function Get-DefaultOutputPath {
    $docs = ''
    try { $docs = [Environment]::GetFolderPath('MyDocuments') } catch { $docs = '' }
    if ([string]::IsNullOrWhiteSpace($docs)) { $docs = [IO.Path]::GetTempPath() }
    return (Join-Path $docs ("TeamsCallReport_{0:yyyyMMdd_HHmmss}" -f (Get-Date)))
}

function Resolve-TeamsWindowAuthMode {
    param(
        [string]$SavedMode,
        [string]$TenantId,
        [string]$ClientId
    )
    # The same function lives in TeamsCallReport.Core.ps1 for tests. The window
    # keeps this copy so an older core file cannot stop the form from opening.
    $mode = [string]$SavedMode
    if ([string]::IsNullOrWhiteSpace($mode)) { return 'Account' }
    $manualApp = @('CertificateThumbprint', 'CertificateFile', 'Secret') -contains $mode
    if ($manualApp) {
        if ([string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($ClientId)) {
            return 'Account'
        }
    }
    return $mode
}

function Get-AuthModeName {
    switch ($script:Ui.AuthMode.SelectedIndex) {
        0 { return 'Account' }
        1 { return 'CertificateThumbprint' }
        2 { return 'CertificateFile' }
        3 { return 'Secret' }
        4 { return 'Existing' }
        default { return 'Sample' }
    }
}

function ConvertTo-SecureText {
    param([string]$Plain)
    if ([string]::IsNullOrEmpty($Plain)) { return $null }
    $secure = New-Object System.Security.SecureString
    foreach ($ch in $Plain.ToCharArray()) { $secure.AppendChar($ch) }
    $secure.MakeReadOnly()
    return $secure
}

function Save-ReportSettings {
    try {
        $form = $script:Ui.Form
        $data = [ordered]@{
            Cloud            = [string]$script:Ui.Cloud.SelectedItem
            TenantId         = $script:Ui.TenantBox.Text.Trim()
            ClientId         = $script:Ui.ClientBox.Text.Trim()
            AuthMode         = (Get-AuthModeName)
            Thumbprint       = (($script:Ui.ThumbBox.Text -replace '\s', '').ToUpperInvariant())
            CertificatePath  = $script:Ui.PfxBox.Text.Trim()
            User             = $script:Ui.UserBox.Text.Trim()
            OutputPath       = $script:Ui.OutputBox.Text.Trim()
            MaxCalls         = [int]$script:Ui.MaxCalls.Value
            SkipDirectory    = [bool]$script:Ui.SkipDirectory.Checked
            SaveRawJson      = [bool]$script:Ui.SaveRaw.Checked
            LinkCall         = [bool]$script:Ui.LinkCheck.Checked
            Width            = 1180
            Height           = 820
        }
        if ($form -and $form.WindowState -eq 'Normal') {
            $data.Width = [int]$form.Width
            $data.Height = [int]$form.Height
        }
        $json = $data | ConvertTo-Json -Depth 4
        [IO.File]::WriteAllText((Get-SettingsPath), $json, (New-Object System.Text.UTF8Encoding $true))
    }
    catch { }
}

function Read-ReportSettings {
    $path = Get-SettingsPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json) }
    catch { return $null }
}

function Write-UiLog {
    param([string]$Message)
    if (-not $script:Ui.LogBox -or $script:Ui.LogBox.IsDisposed) { return }
    $script:Ui.LogBox.AppendText(("{0:HH:mm:ss}  {1}`r`n" -f (Get-Date), $Message))
}

function Receive-WorkerLog {
    $log = $script:Ui.Sync.Log
    $items = @()
    [System.Threading.Monitor]::Enter($log.SyncRoot)
    try {
        if ($log.Count -gt 0) {
            $items = @($log.ToArray())
            $log.Clear()
        }
    }
    finally { [System.Threading.Monitor]::Exit($log.SyncRoot) }
    foreach ($line in $items) {
        if ($script:Ui.LogBox -and -not $script:Ui.LogBox.IsDisposed) {
            $script:Ui.LogBox.AppendText(([string]$line) + "`r`n")
        }
    }
}

function Set-ReportBusy {
    param([bool]$Busy)
    $script:Ui.Busy = $Busy
    $sample = (Get-AuthModeName) -eq 'Sample'
    $script:Ui.ConnectButton.Enabled = (-not $Busy) -and (-not $sample)
    $script:Ui.ResolveButton.Enabled = -not $Busy
    $script:Ui.RunButton.Enabled = -not $Busy
    $script:Ui.PreviewButton.Enabled = -not $Busy
    $script:Ui.CancelButton.Enabled = $Busy
    if ($script:Ui.Form) { $script:Ui.Form.UseWaitCursor = $Busy }
}

function Update-AuthPanels {
    $mode = Get-AuthModeName
    $account = ($mode -eq 'Account')
    $script:Ui.TenantLabel.Visible = -not $account
    $script:Ui.TenantBox.Visible = -not $account
    $script:Ui.ClientLabel.Visible = -not $account
    $script:Ui.ClientBox.Visible = -not $account
    if ($account) {
        $script:Ui.ConnectButton.Text = 'Sign in'
        $script:Ui.AuthNote.Location = New-Object System.Drawing.Point(300, 6)
        $script:Ui.AuthNote.Size = New-Object System.Drawing.Size(840, 44)
    }
    else {
        $script:Ui.ConnectButton.Text = 'Test connection'
        $script:Ui.AuthNote.Location = New-Object System.Drawing.Point(500, 50)
        $script:Ui.AuthNote.Size = New-Object System.Drawing.Size(640, 40)
    }
    $script:Ui.ThumbLabel.Visible = ($mode -eq 'CertificateThumbprint')
    $script:Ui.ThumbBox.Visible = ($mode -eq 'CertificateThumbprint')
    $pfx = ($mode -eq 'CertificateFile')
    $script:Ui.PfxLabel.Visible = $pfx
    $script:Ui.PfxBox.Visible = $pfx
    $script:Ui.PfxBrowse.Visible = $pfx
    $script:Ui.PfxPasswordLabel.Visible = $pfx
    $script:Ui.PfxPassword.Visible = $pfx
    $secret = ($mode -eq 'Secret')
    $script:Ui.SecretLabel.Visible = $secret
    $script:Ui.SecretBox.Visible = $secret
    if ($account) {
        $script:Ui.AuthNote.Text = 'No tenant id or client id. An administrator sign-in grants CallRecords.Read.All and User.Read.All. Later runs reuse that grant.'
    }
    elseif ($mode -eq 'Existing') {
        $script:Ui.AuthNote.Text = 'Uses Connect-MgGraph from this Windows PowerShell process. Start-TeamsCallReport.cmd opens a new process, so sign in with your account instead.'
    }
    elseif ($mode -eq 'Sample') {
        $script:Ui.AuthNote.Text = 'Offline sample records. Leave the user blank to use alice@contoso.com. Nothing is sent to Microsoft.'
    }
    else {
        $script:Ui.AuthNote.Text = 'Tenant id and client id are only for an app registration you already created. Choose Sign in with my account to skip both.'
    }
    if (-not $script:Ui.Busy) { Set-ReportBusy $false }
}

function Set-GridTable {
    param($Grid, $Table)
    $view = $null
    $script:Ui.SuppressSelection = $true
    try {
        if ($Table) { $view = New-Object System.Data.DataView $Table }
        $Grid.DataSource = $view
        if ($Grid.Columns.Contains('SearchBlob')) { $Grid.Columns['SearchBlob'].Visible = $false }
    }
    finally { $script:Ui.SuppressSelection = $false }
    return $view
}

function Update-ReportFilters {
    if (-not $script:Ui.CallView) { return }
    $search = ''
    if ($script:Ui.FilterBox) { $search = $script:Ui.FilterBox.Text.Trim() }
    $like = ''
    if ($search) {
        $escaped = $search.Replace("'", "''").Replace('[', '[[]').Replace('%', '[%]').Replace('*', '[*]')
        $like = "SearchBlob LIKE '%$escaped%'"
    }
    $callId = ''
    $calls = $script:Ui.CallsGrid
    if ($script:Ui.LinkCheck.Checked -and $calls.SelectedRows.Count -gt 0 -and $calls.Columns.Contains('CallId')) {
        $callId = [string]$calls.SelectedRows[0].Cells['CallId'].Value
    }
    $parts = New-Object System.Collections.Generic.List[string]
    if ($callId) { $parts.Add(("CallId = '{0}'" -f $callId.Replace("'", "''"))) }
    if ($like) { $parts.Add($like) }
    $linked = ''
    if ($parts.Count -gt 0) { $linked = [string]::Join(' AND ', $parts.ToArray()) }
    foreach ($pair in @(
            @($script:Ui.CallView, $like),
            @($script:Ui.ParticipantView, $linked),
            @($script:Ui.EndpointView, $linked)
        )) {
        $view = $pair[0]
        $filter = [string]$pair[1]
        if (-not $view) { continue }
        try { $view.RowFilter = $filter }
        catch { try { $view.RowFilter = '' } catch { } }
    }
    if ($callId) { $script:Ui.LinkLabel.Text = "Participants and endpoints are limited to the selected call." }
    else { $script:Ui.LinkLabel.Text = "Participants and endpoints include every exported call." }
}

function Show-ExportResult {
    param($Result)
    if (-not $Result) { return }
    $script:Ui.CallView = Set-GridTable $script:Ui.CallsGrid $Result.CallsTable
    $script:Ui.ParticipantView = Set-GridTable $script:Ui.ParticipantsGrid $Result.ParticipantsTable
    $script:Ui.EndpointView = Set-GridTable $script:Ui.EndpointsGrid $Result.EndpointsTable
    $script:Ui.SummaryBox.Text = [string]$Result.SummaryText
    if ($Result.TargetUser) {
        $user = $Result.TargetUser
        $script:Ui.ResolvedLabel.Text = "{0}  <{1}>  [{2}]" -f $user.displayName, $user.userPrincipalName, $user.id
    }
    Update-ReportFilters
    if ($script:Ui.CallsGrid.Rows.Count -gt 0) {
        $script:Ui.SuppressSelection = $true
        try { $script:Ui.CallsGrid.Rows[0].Selected = $true }
        finally { $script:Ui.SuppressSelection = $false }
        Update-ReportFilters
    }
    $script:Ui.Tabs.SelectedIndex = 0
}

function New-ReportPayload {
    param([bool]$SampleExport)
    $mode = Get-AuthModeName
    if ($SampleExport) { $mode = 'Sample' }
    $user = $script:Ui.UserBox.Text.Trim()
    if ($mode -eq 'Sample' -and [string]::IsNullOrWhiteSpace($user)) { $user = 'alice@contoso.com' }
    $payload = @{
        AuthMode             = $mode
        Cloud                = [string]$script:Ui.Cloud.SelectedItem
        TenantId             = $script:Ui.TenantBox.Text.Trim()
        ClientId             = $script:Ui.ClientBox.Text.Trim()
        Thumbprint           = (($script:Ui.ThumbBox.Text -replace '\s', '').ToUpperInvariant())
        CertificatePath      = $script:Ui.PfxBox.Text.Trim()
        CertificatePassword  = (ConvertTo-SecureText $script:Ui.PfxPassword.Text)
        ClientSecret         = (ConvertTo-SecureText $script:Ui.SecretBox.Text)
        User                 = $user
        Start                = $script:Ui.StartPicker.Value
        End                  = $script:Ui.EndPicker.Value
        OutputPath           = $script:Ui.OutputBox.Text.Trim()
        MaxCalls             = [int]$script:Ui.MaxCalls.Value
        SkipDirectory        = [bool]$script:Ui.SkipDirectory.Checked
        SaveRawJson          = [bool]$script:Ui.SaveRaw.Checked
        Sample               = [bool]$SampleExport -or ($mode -eq 'Sample')
    }
    return $payload
}

function Test-ReportInput {
    param([bool]$NeedOutput, [bool]$SampleExport, [bool]$NeedUser = $true)
    $mode = Get-AuthModeName
    if ($SampleExport) { $mode = 'Sample' }
    $user = $script:Ui.UserBox.Text.Trim()
    if ($NeedUser -and $mode -ne 'Sample' -and [string]::IsNullOrWhiteSpace($user)) {
        throw 'Enter the user principal name, email address, or object id to export.'
    }
    if ($script:Ui.EndPicker.Value -le $script:Ui.StartPicker.Value) {
        throw 'The end of the window has to be later than the start.'
    }
    if ($NeedOutput -and [string]::IsNullOrWhiteSpace($script:Ui.OutputBox.Text)) {
        throw 'Choose an output folder.'
    }
    if ($mode -eq 'Sample' -or $mode -eq 'Existing' -or $mode -eq 'Account') { return }
    if ([string]::IsNullOrWhiteSpace($script:Ui.TenantBox.Text) -or [string]::IsNullOrWhiteSpace($script:Ui.ClientBox.Text)) {
        throw 'Tenant id and application (client) id are required.'
    }
    if ($mode -eq 'CertificateThumbprint') {
        $thumb = ($script:Ui.ThumbBox.Text -replace '\s', '')
        if ($thumb -notmatch '^[0-9A-Fa-f]{40}$') { throw 'Certificate thumbprint must be 40 hexadecimal characters.' }
    }
    elseif ($mode -eq 'CertificateFile') {
        if ([string]::IsNullOrWhiteSpace($script:Ui.PfxBox.Text)) { throw 'Choose a PFX file.' }
        if (-not (Test-Path -LiteralPath $script:Ui.PfxBox.Text.Trim())) { throw 'The PFX file was not found.' }
    }
    elseif ($mode -eq 'Secret') {
        if ([string]::IsNullOrWhiteSpace($script:Ui.SecretBox.Text)) { throw 'Enter the client secret.' }
    }
}

function Start-ReportOperation {
    param([string]$Operation, [bool]$SampleExport)
    if ($script:Ui.Busy) { return }
    $needOutput = ($Operation -eq 'Export')
    $needUser = ($Operation -ne 'Connect')
    try { Test-ReportInput -NeedOutput $needOutput -SampleExport $SampleExport -NeedUser $needUser }
    catch {
        [System.Windows.Forms.MessageBox]::Show($script:Ui.Form, $_.Exception.Message, 'Teams Call Report') | Out-Null
        return
    }
    $sync = $script:Ui.Sync
    $sync.Cancel = $false
    $sync.Done = $false
    $sync.ErrorText = $null
    $sync.Result = $null
    $sync.ResolvedText = $null
    $sync.DeviceCode = $null
    $sync.DeviceUrl = $null
    $script:Ui.ShownDeviceCode = $null
    $sync.Progress = 2
    $sync.StatusText = "Starting $Operation..."
    $sync.Operation = $Operation
    $script:Ui.Progress.Value = 2
    $script:Ui.StatusLabel.Text = [string]$sync.StatusText
    Set-ReportBusy $true
    $ps = [powershell]::Create()
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'MTA'
    $rs.Open()
    $ps.Runspace = $rs
    [void]$ps.AddScript($script:WorkerSource)
    [void]$ps.AddArgument($sync)
    [void]$ps.AddArgument($script:CorePath)
    [void]$ps.AddArgument($Operation)
    [void]$ps.AddArgument((New-ReportPayload -SampleExport $SampleExport))
    $script:Ui.PowerShell = $ps
    $script:Ui.Runspace = $rs
    $script:Ui.Handle = $ps.BeginInvoke()
}

function Complete-ReportOperation {
    $handle = $script:Ui.Handle
    if (-not $handle -or -not $handle.IsCompleted) { return }
    $workerError = $null
    try { $script:Ui.PowerShell.EndInvoke($handle) | Out-Null }
    catch { $workerError = $_.Exception.Message }
    try { $script:Ui.PowerShell.Dispose() } catch { }
    try { $script:Ui.Runspace.Close() } catch { }
    try { $script:Ui.Runspace.Dispose() } catch { }
    $script:Ui.PowerShell = $null
    $script:Ui.Runspace = $null
    $script:Ui.Handle = $null
    Receive-WorkerLog
    Set-ReportBusy $false
    $sync = $script:Ui.Sync
    if ($workerError -and -not $sync.ErrorText) { $sync.ErrorText = $workerError }
    $progress = 0
    try { $progress = [int]$sync.Progress } catch { $progress = 0 }
    if ($progress -lt 0) { $progress = 0 }
    if ($progress -gt 100) { $progress = 100 }
    $script:Ui.Progress.Value = $progress
    if ($sync.StatusText) { $script:Ui.StatusLabel.Text = [string]$sync.StatusText }
    if ($sync.Operation -eq 'Resolve' -and $sync.ResolvedText) {
        $script:Ui.ResolvedLabel.Text = [string]$sync.ResolvedText
    }
    if ($sync.Result) { Show-ExportResult $sync.Result }
    Save-ReportSettings
    if ($sync.ErrorText) {
        [System.Windows.Forms.MessageBox]::Show($script:Ui.Form, [string]$sync.ErrorText, 'Teams Call Report') | Out-Null
    }
}

function New-UiLabel {
    param([string]$Text, [int]$X, [int]$Y, [int]$W)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point($X, ($Y + 3))
    $label.Size = New-Object System.Drawing.Size($W, 20)
    return $label
}

function New-UiText {
    param([int]$X, [int]$Y, [int]$W, [switch]$Secret)
    $box = New-Object System.Windows.Forms.TextBox
    $box.Location = New-Object System.Drawing.Point($X, $Y)
    $box.Size = New-Object System.Drawing.Size($W, 23)
    if ($Secret) { $box.UseSystemPasswordChar = $true }
    return $box
}

function New-ReportGrid {
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToOrderColumns = $true
    $grid.SelectionMode = 'FullRowSelect'
    $grid.MultiSelect = $false
    $grid.RowHeadersVisible = $false
    $grid.AutoSizeColumnsMode = 'DisplayedCells'
    $grid.ClipboardCopyMode = 'EnableAlwaysIncludeHeaderText'
    $grid.BackgroundColor = [System.Drawing.Color]::White
    $grid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(245, 248, 252)
    $grid.AutoGenerateColumns = $true
    $grid.Add_DataBindingComplete({
            param($sender, $eventArgs)
            if ($sender.Columns.Contains('SearchBlob')) { $sender.Columns['SearchBlob'].Visible = $false }
        })
    return $grid
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Teams Call Report'
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$form.Size = New-Object System.Drawing.Size(1180, 820)
$form.MinimumSize = New-Object System.Drawing.Size(980, 700)
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
$script:Ui.Form = $form

$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'
$header.Height = 292

$script:Ui.Cloud = New-Object System.Windows.Forms.ComboBox
$script:Ui.Cloud.DropDownStyle = 'DropDownList'
[void]$script:Ui.Cloud.Items.AddRange(@('Public', 'USGov', 'USGovDoD'))
$script:Ui.Cloud.SelectedIndex = 0
$script:Ui.Cloud.Location = New-Object System.Drawing.Point(124, 12)
$script:Ui.Cloud.Size = New-Object System.Drawing.Size(160, 24)

$script:Ui.TenantBox = New-UiText 390 12 250
$script:Ui.ClientBox = New-UiText 760 12 280
$script:Ui.ClientBox.Anchor = 'Top, Left, Right'

$script:Ui.AuthMode = New-Object System.Windows.Forms.ComboBox
$script:Ui.AuthMode.DropDownStyle = 'DropDownList'
[void]$script:Ui.AuthMode.Items.AddRange(@(
        'Sign in with my account',
        'Certificate in the Windows store',
        'Certificate PFX file',
        'Client secret',
        'Existing Connect-MgGraph session',
        'Sample data (offline)'
    ))
$script:Ui.AuthMode.SelectedIndex = 0
$script:Ui.AuthMode.Location = New-Object System.Drawing.Point(124, 52)
$script:Ui.AuthMode.Size = New-Object System.Drawing.Size(360, 24)
$script:Ui.AuthMode.DropDownWidth = 360
$script:Ui.AuthMode.Add_SelectedIndexChanged({ Update-AuthPanels })

$script:Ui.AuthNote = New-Object System.Windows.Forms.Label
$script:Ui.AuthNote.Location = New-Object System.Drawing.Point(300, 6)
$script:Ui.AuthNote.Size = New-Object System.Drawing.Size(840, 44)
$script:Ui.AuthNote.Anchor = 'Top, Left, Right'

$script:Ui.ThumbLabel = New-UiLabel 'Thumbprint' 12 84 100
$script:Ui.ThumbBox = New-UiText 124 80 520
$script:Ui.PfxLabel = New-UiLabel 'PFX file' 12 84 100
$script:Ui.PfxBox = New-UiText 124 80 360
$script:Ui.PfxBrowse = New-Object System.Windows.Forms.Button
$script:Ui.PfxBrowse.Text = 'Browse...'
$script:Ui.PfxBrowse.Location = New-Object System.Drawing.Point(490, 79)
$script:Ui.PfxBrowse.Size = New-Object System.Drawing.Size(80, 25)
$script:Ui.PfxPasswordLabel = New-UiLabel 'PFX password' 580 84 90
$script:Ui.PfxPassword = New-UiText 676 80 180 -Secret
$script:Ui.SecretLabel = New-UiLabel 'Client secret' 12 84 100
$script:Ui.SecretBox = New-UiText 124 80 360 -Secret

$script:Ui.UserBox = New-UiText 124 116 280
$script:Ui.ResolveButton = New-Object System.Windows.Forms.Button
$script:Ui.ResolveButton.Text = 'Resolve'
$script:Ui.ResolveButton.Location = New-Object System.Drawing.Point(412, 115)
$script:Ui.ResolveButton.Size = New-Object System.Drawing.Size(80, 25)
$script:Ui.ResolvedLabel = New-Object System.Windows.Forms.Label
$script:Ui.ResolvedLabel.Text = 'Resolve checks the user in Entra ID before the export.'
$script:Ui.ResolvedLabel.Location = New-Object System.Drawing.Point(500, 119)
$script:Ui.ResolvedLabel.Size = New-Object System.Drawing.Size(640, 22)
$script:Ui.ResolvedLabel.Anchor = 'Top, Left, Right'
$script:Ui.ResolvedLabel.AutoEllipsis = $true

$script:Ui.StartPicker = New-Object System.Windows.Forms.DateTimePicker
$script:Ui.StartPicker.Format = 'Custom'
$script:Ui.StartPicker.CustomFormat = 'yyyy-MM-dd HH:mm'
$script:Ui.StartPicker.Value = (Get-Date).AddDays(-29)
$script:Ui.StartPicker.Location = New-Object System.Drawing.Point(124, 150)
$script:Ui.StartPicker.Size = New-Object System.Drawing.Size(170, 24)
$script:Ui.EndPicker = New-Object System.Windows.Forms.DateTimePicker
$script:Ui.EndPicker.Format = 'Custom'
$script:Ui.EndPicker.CustomFormat = 'yyyy-MM-dd HH:mm'
$script:Ui.EndPicker.Value = (Get-Date)
$script:Ui.EndPicker.Location = New-Object System.Drawing.Point(360, 150)
$script:Ui.EndPicker.Size = New-Object System.Drawing.Size(170, 24)
$script:Ui.MaxCalls = New-Object System.Windows.Forms.NumericUpDown
$script:Ui.MaxCalls.Minimum = 0
$script:Ui.MaxCalls.Maximum = 100000
$script:Ui.MaxCalls.Value = 0
$script:Ui.MaxCalls.Location = New-Object System.Drawing.Point(680, 150)
$script:Ui.MaxCalls.Size = New-Object System.Drawing.Size(80, 24)

$script:Ui.OutputBox = New-UiText 124 186 620
$script:Ui.OutputBox.Anchor = 'Top, Left, Right'
$script:Ui.OutputBox.Text = Get-DefaultOutputPath
$script:Ui.OutputBrowse = New-Object System.Windows.Forms.Button
$script:Ui.OutputBrowse.Text = 'Browse...'
$script:Ui.OutputBrowse.Location = New-Object System.Drawing.Point(752, 185)
$script:Ui.OutputBrowse.Size = New-Object System.Drawing.Size(80, 25)
$script:Ui.OutputBrowse.Anchor = 'Top, Right'
$script:Ui.NewFolder = New-Object System.Windows.Forms.Button
$script:Ui.NewFolder.Text = 'New folder name'
$script:Ui.NewFolder.Location = New-Object System.Drawing.Point(840, 185)
$script:Ui.NewFolder.Size = New-Object System.Drawing.Size(120, 25)
$script:Ui.NewFolder.Anchor = 'Top, Right'

$script:Ui.SkipDirectory = New-Object System.Windows.Forms.CheckBox
$script:Ui.SkipDirectory.Text = 'Skip Entra directory lookup'
$script:Ui.SkipDirectory.AutoSize = $true
$script:Ui.SkipDirectory.Margin = New-Object System.Windows.Forms.Padding(0, 4, 16, 0)
$script:Ui.SaveRaw = New-Object System.Windows.Forms.CheckBox
$script:Ui.SaveRaw.Text = 'Save raw Graph JSON'
$script:Ui.SaveRaw.Checked = $true
$script:Ui.SaveRaw.AutoSize = $true
$script:Ui.SaveRaw.Margin = New-Object System.Windows.Forms.Padding(0, 4, 16, 0)
$script:Ui.LinkCheck = New-Object System.Windows.Forms.CheckBox
$script:Ui.LinkCheck.Text = 'Filter other grids to the selected call'
$script:Ui.LinkCheck.Checked = $true
$script:Ui.LinkCheck.AutoSize = $true
$script:Ui.LinkCheck.Margin = New-Object System.Windows.Forms.Padding(0, 4, 16, 0)
$script:Ui.LinkCheck.Add_CheckedChanged({ Update-ReportFilters })
$script:Ui.OptionRow = New-Object System.Windows.Forms.FlowLayoutPanel
$script:Ui.OptionRow.FlowDirection = 'LeftToRight'
$script:Ui.OptionRow.WrapContents = $false
$script:Ui.OptionRow.AutoSize = $true
$script:Ui.OptionRow.AutoSizeMode = 'GrowAndShrink'
$script:Ui.OptionRow.Location = New-Object System.Drawing.Point(124, 214)
$script:Ui.OptionRow.Controls.Add($script:Ui.SkipDirectory)
$script:Ui.OptionRow.Controls.Add($script:Ui.SaveRaw)
$script:Ui.OptionRow.Controls.Add($script:Ui.LinkCheck)

$script:Ui.ConnectButton = New-Object System.Windows.Forms.Button
$script:Ui.ConnectButton.Text = 'Sign in'
$script:Ui.ConnectButton.AutoSize = $true
$script:Ui.ConnectButton.AutoSizeMode = 'GrowAndShrink'
$script:Ui.ConnectButton.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
$script:Ui.RunButton = New-Object System.Windows.Forms.Button
$script:Ui.RunButton.Text = 'Run export'
$script:Ui.RunButton.AutoSize = $true
$script:Ui.RunButton.AutoSizeMode = 'GrowAndShrink'
$script:Ui.RunButton.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
$script:Ui.CancelButton = New-Object System.Windows.Forms.Button
$script:Ui.CancelButton.Text = 'Cancel'
$script:Ui.CancelButton.Enabled = $false
$script:Ui.CancelButton.AutoSize = $true
$script:Ui.CancelButton.AutoSizeMode = 'GrowAndShrink'
$script:Ui.CancelButton.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
$script:Ui.PreviewButton = New-Object System.Windows.Forms.Button
$script:Ui.PreviewButton.Text = 'Preview sample data'
$script:Ui.PreviewButton.AutoSize = $true
$script:Ui.PreviewButton.AutoSizeMode = 'GrowAndShrink'
$script:Ui.PreviewButton.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
$script:Ui.OpenButton = New-Object System.Windows.Forms.Button
$script:Ui.OpenButton.Text = 'Open output folder'
$script:Ui.OpenButton.AutoSize = $true
$script:Ui.OpenButton.AutoSizeMode = 'GrowAndShrink'
$script:Ui.OpenButton.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
$script:Ui.ButtonRow = New-Object System.Windows.Forms.FlowLayoutPanel
$script:Ui.ButtonRow.FlowDirection = 'LeftToRight'
$script:Ui.ButtonRow.WrapContents = $false
$script:Ui.ButtonRow.AutoSize = $true
$script:Ui.ButtonRow.AutoSizeMode = 'GrowAndShrink'
$script:Ui.ButtonRow.Location = New-Object System.Drawing.Point(12, 248)
$script:Ui.ButtonRow.Controls.Add($script:Ui.ConnectButton)
$script:Ui.ButtonRow.Controls.Add($script:Ui.RunButton)
$script:Ui.ButtonRow.Controls.Add($script:Ui.CancelButton)
$script:Ui.ButtonRow.Controls.Add($script:Ui.PreviewButton)
$script:Ui.ButtonRow.Controls.Add($script:Ui.OpenButton)

$script:Ui.TenantLabel = New-UiLabel 'Tenant id' 300 12 84
$script:Ui.ClientLabel = New-UiLabel 'Client id' 660 12 90
foreach ($control in @(
        (New-UiLabel 'Cloud' 12 12 100),
        $script:Ui.Cloud,
        $script:Ui.TenantLabel,
        $script:Ui.TenantBox,
        $script:Ui.ClientLabel,
        $script:Ui.ClientBox,
        (New-UiLabel 'Sign-in' 12 52 100),
        $script:Ui.AuthMode,
        $script:Ui.AuthNote,
        $script:Ui.ThumbLabel,
        $script:Ui.ThumbBox,
        $script:Ui.PfxLabel,
        $script:Ui.PfxBox,
        $script:Ui.PfxBrowse,
        $script:Ui.PfxPasswordLabel,
        $script:Ui.PfxPassword,
        $script:Ui.SecretLabel,
        $script:Ui.SecretBox,
        (New-UiLabel 'User' 12 116 100),
        $script:Ui.UserBox,
        $script:Ui.ResolveButton,
        $script:Ui.ResolvedLabel,
        (New-UiLabel 'Start' 12 150 100),
        $script:Ui.StartPicker,
        (New-UiLabel 'End' 310 150 44),
        $script:Ui.EndPicker,
        (New-UiLabel 'Max calls (0 = all)' 546 150 130),
        $script:Ui.MaxCalls,
        (New-UiLabel 'Output folder' 12 186 100),
        $script:Ui.OutputBox,
        $script:Ui.OutputBrowse,
        $script:Ui.NewFolder,
        $script:Ui.OptionRow,
        $script:Ui.ButtonRow
    )) {
    $header.Controls.Add($control)
}

$filterPanel = New-Object System.Windows.Forms.Panel
$filterPanel.Dock = 'Top'
$filterPanel.Height = 36
$script:Ui.FilterBox = New-UiText 124 6 360
$script:Ui.FilterBox.Anchor = 'Top, Left, Right'
$script:Ui.LinkLabel = New-Object System.Windows.Forms.Label
$script:Ui.LinkLabel.Text = 'Participants and endpoints include every exported call.'
$script:Ui.LinkLabel.Location = New-Object System.Drawing.Point(500, 9)
$script:Ui.LinkLabel.Size = New-Object System.Drawing.Size(640, 20)
$script:Ui.LinkLabel.Anchor = 'Top, Left, Right'
$filterPanel.Controls.Add((New-UiLabel 'Filter grids' 12 6 100))
$filterPanel.Controls.Add($script:Ui.FilterBox)
$filterPanel.Controls.Add($script:Ui.LinkLabel)
$script:Ui.FilterBox.Add_TextChanged({ Update-ReportFilters })

$script:Ui.Tabs = New-Object System.Windows.Forms.TabControl
$script:Ui.Tabs.Dock = 'Fill'
$script:Ui.CallsGrid = New-ReportGrid
$script:Ui.ParticipantsGrid = New-ReportGrid
$script:Ui.EndpointsGrid = New-ReportGrid
$script:Ui.CallsGrid.Add_SelectionChanged({
        if (-not $script:Ui.SuppressSelection) { Update-ReportFilters }
    })

$script:Ui.SummaryBox = New-Object System.Windows.Forms.TextBox
$script:Ui.SummaryBox.Multiline = $true
$script:Ui.SummaryBox.ReadOnly = $true
$script:Ui.SummaryBox.ScrollBars = 'Vertical'
$script:Ui.SummaryBox.Dock = 'Fill'
$script:Ui.SummaryBox.Font = New-Object System.Drawing.Font('Segoe UI', 10)

$script:Ui.LogBox = New-Object System.Windows.Forms.TextBox
$script:Ui.LogBox.Multiline = $true
$script:Ui.LogBox.ReadOnly = $true
$script:Ui.LogBox.ScrollBars = 'Both'
$script:Ui.LogBox.Dock = 'Fill'
$script:Ui.LogBox.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:Ui.LogBox.WordWrap = $false

function Add-ReportTab {
    param([string]$Title, $Control)
    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = $Title
    $page.Padding = New-Object System.Windows.Forms.Padding(4)
    $Control.Dock = 'Fill'
    $page.Controls.Add($Control)
    [void]$script:Ui.Tabs.TabPages.Add($page)
}
Add-ReportTab 'Calls' $script:Ui.CallsGrid
Add-ReportTab 'Participants' $script:Ui.ParticipantsGrid
Add-ReportTab 'Endpoints' $script:Ui.EndpointsGrid
Add-ReportTab 'Summary' $script:Ui.SummaryBox
Add-ReportTab 'Log' $script:Ui.LogBox

$status = New-Object System.Windows.Forms.StatusStrip
$script:Ui.StatusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$script:Ui.StatusLabel.Spring = $true
$script:Ui.StatusLabel.TextAlign = 'MiddleLeft'
$script:Ui.StatusLabel.Text = 'Ready. Graph retains call records for 30 days, and only after the call ends.'
$script:Ui.Progress = New-Object System.Windows.Forms.ToolStripProgressBar
$script:Ui.Progress.Minimum = 0
$script:Ui.Progress.Maximum = 100
$script:Ui.Progress.Width = 180
[void]$status.Items.Add($script:Ui.StatusLabel)
[void]$status.Items.Add($script:Ui.Progress)

$form.Controls.Add($script:Ui.Tabs)
$form.Controls.Add($filterPanel)
$form.Controls.Add($header)
$form.Controls.Add($status)

$script:Ui.PfxBrowse.Add_Click({
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Filter = 'PFX files (*.pfx)|*.pfx|All files (*.*)|*.*'
        $dialog.Title = 'Application certificate'
        if ($dialog.ShowDialog($script:Ui.Form) -eq 'OK') { $script:Ui.PfxBox.Text = $dialog.FileName }
    })
$script:Ui.OutputBrowse.Add_Click({
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = 'Folder for Calls.csv, Participants.csv, Endpoints.csv, and RawJson'
        if ($dialog.ShowDialog($script:Ui.Form) -eq 'OK') { $script:Ui.OutputBox.Text = $dialog.SelectedPath }
    })
$script:Ui.NewFolder.Add_Click({ $script:Ui.OutputBox.Text = Get-DefaultOutputPath })
$script:Ui.ConnectButton.Add_Click({ Start-ReportOperation -Operation 'Connect' -SampleExport $false })
$script:Ui.ResolveButton.Add_Click({ Start-ReportOperation -Operation 'Resolve' -SampleExport $false })
$script:Ui.RunButton.Add_Click({ Start-ReportOperation -Operation 'Export' -SampleExport $false })
$script:Ui.PreviewButton.Add_Click({ Start-ReportOperation -Operation 'Export' -SampleExport $true })
$script:Ui.CancelButton.Add_Click({
        $script:Ui.Sync.Cancel = $true
        $script:Ui.StatusLabel.Text = 'Cancelling...'
        Write-UiLog 'Cancel requested. The current Graph call finishes, then the export stops.'
    })
$script:Ui.OpenButton.Add_Click({
        $path = $script:Ui.OutputBox.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($path)) { return }
        if (-not (Test-Path -LiteralPath $path)) {
            try { New-Item -ItemType Directory -Path $path -Force | Out-Null }
            catch {
                [System.Windows.Forms.MessageBox]::Show($script:Ui.Form, $_.Exception.Message, 'Teams Call Report') | Out-Null
                return
            }
        }
        Start-Process -FilePath 'explorer.exe' -ArgumentList ("`"{0}`"" -f $path) | Out-Null
    })
$form.Add_KeyDown({
        param($sender, $eventArgs)
        if ($eventArgs.KeyCode -eq 'Escape' -and $script:Ui.CancelButton.Enabled) {
            $script:Ui.Sync.Cancel = $true
            $script:Ui.StatusLabel.Text = 'Cancelling...'
        }
    })
$form.KeyPreview = $true
$form.Add_FormClosing({
        $script:Ui.Sync.Cancel = $true
        Save-ReportSettings
        if ($script:Ui.PowerShell) {
            try { $script:Ui.PowerShell.Stop() } catch { }
        }
    })

$saved = Read-ReportSettings
if ($saved) {
    $cloudIndex = $script:Ui.Cloud.Items.IndexOf([string]$saved.Cloud)
    if ($cloudIndex -ge 0) { $script:Ui.Cloud.SelectedIndex = $cloudIndex }
    if ($saved.TenantId) { $script:Ui.TenantBox.Text = [string]$saved.TenantId }
    if ($saved.ClientId) { $script:Ui.ClientBox.Text = [string]$saved.ClientId }
    $savedMode = Resolve-TeamsWindowAuthMode -SavedMode ([string]$saved.AuthMode) -TenantId ([string]$saved.TenantId) -ClientId ([string]$saved.ClientId)
    $authIndex = 0
    switch ($savedMode) {
        'Account' { $authIndex = 0 }
        'CertificateThumbprint' { $authIndex = 1 }
        'CertificateFile' { $authIndex = 2 }
        'Secret' { $authIndex = 3 }
        'Existing' { $authIndex = 4 }
        'Sample' { $authIndex = 5 }
    }
    $script:Ui.AuthMode.SelectedIndex = $authIndex
    if ($saved.Thumbprint) { $script:Ui.ThumbBox.Text = [string]$saved.Thumbprint }
    if ($saved.CertificatePath) { $script:Ui.PfxBox.Text = [string]$saved.CertificatePath }
    if ($saved.User) { $script:Ui.UserBox.Text = [string]$saved.User }
    if ($saved.OutputPath) { $script:Ui.OutputBox.Text = [string]$saved.OutputPath }
    if ($null -ne $saved.MaxCalls) { $script:Ui.MaxCalls.Value = [decimal]$saved.MaxCalls }
    if ($null -ne $saved.SkipDirectory) { $script:Ui.SkipDirectory.Checked = [bool]$saved.SkipDirectory }
    if ($null -ne $saved.SaveRawJson) { $script:Ui.SaveRaw.Checked = [bool]$saved.SaveRawJson }
    if ($null -ne $saved.LinkCall) { $script:Ui.LinkCheck.Checked = [bool]$saved.LinkCall }
    if ($saved.Width -ge 980 -and $saved.Height -ge 700) {
        $form.Size = New-Object System.Drawing.Size([int]$saved.Width, [int]$saved.Height)
    }
}

Update-AuthPanels
Write-UiLog 'Sign in with your administrator account. Microsoft does not allow a user token to read call records, so the first sign-in grants CallRecords.Read.All and User.Read.All to an app named Teams Call Report.'
Write-UiLog 'Preview sample data loads alice@contoso.com without contacting a tenant.'

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 200
$timer.Add_Tick({
        if ($script:Ui.Form.IsDisposed) { return }
        Receive-WorkerLog
        $sync = $script:Ui.Sync
        if ($script:Ui.Busy) {
            $progress = 0
            try { $progress = [int]$sync.Progress } catch { $progress = 0 }
            if ($progress -lt 0) { $progress = 0 }
            if ($progress -gt 100) { $progress = 100 }
            $script:Ui.Progress.Value = $progress
            if ($sync.StatusText) { $script:Ui.StatusLabel.Text = [string]$sync.StatusText }
            if ($sync.DeviceCode -and $script:Ui.ShownDeviceCode -ne $sync.DeviceCode) {
                $script:Ui.ShownDeviceCode = [string]$sync.DeviceCode
                $script:Ui.AuthNote.Text = [string]$sync.StatusText
                try { Set-Clipboard -Value ([string]$sync.DeviceCode) } catch { }
                if ($sync.DeviceUrl) {
                    try { Start-Process ([string]$sync.DeviceUrl) } catch { }
                }
                $script:Ui.Tabs.SelectedIndex = 4
            }
        }
        if ($sync.Done -and $script:Ui.Handle) { Complete-ReportOperation }
    })
$script:Ui.Timer = $timer
$timer.Start()
[void]$form.ShowDialog()
$timer.Stop()
$timer.Dispose()

#Requires -Version 5.1
<#
.SYNOPSIS
    .S account status in Entra — checks a list of UPNs from a CSV against Entra ID.

.DESCRIPTION
    - Prompts (GUI) for an input CSV containing UPNs.
    - Prompts (GUI) for where to save the results CSV.
    - Connects to Microsoft Graph and looks up each UPN.
    - Shows a live progress status bar while the CSV is processed.
    - Writes a results file showing Found / Found (Disabled) / Not Found
      (plus useful attributes).

.PARAMETER InputCsv
    Optional path to the input CSV. When omitted, an Open File dialog is shown.

.PARAMETER OutputCsv
    Optional path for the results CSV. When omitted, a Save File dialog is shown.

.PARAMETER DeviceCode
    Use device-code sign-in instead of interactive browser login.

.PARAMETER SelfTest
    Runs built-in unit tests for helper logic and exits (no Graph / no dialogs).

.EXAMPLE
    .\.S account status in Entra.ps1

.EXAMPLE
    .\.S account status in Entra.ps1 -InputCsv .\upns.csv -OutputCsv .\results.csv

.NOTES
    Requires the Microsoft.Graph.Users module and delegated permission "User.Read.All".
    File dialogs and the progress window require Windows PowerShell in STA mode;
    the script relaunches itself in STA automatically when needed.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$InputCsv,

    [Parameter()]
    [string]$OutputCsv,

    [switch]$DeviceCode,

    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Avoid MSAL WAM "A window handle must be configured" in console hosts.
$env:AZURE_IDENTITY_DISABLE_CP1 = 'true'
$env:MSAL_DESKTOP_APP_USE_WAM = '0'

$script:WinFormsLoaded = $false
$script:UseGui = -not $SelfTest
$script:ProgressForm = $null
$script:ProgressBar = $null
$script:ProgressLabel = $null
$script:ProgressDetail = $null

#region STA -------------------------------------------------------------------

if ($script:UseGui -and [System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        Write-Host "File dialogs require STA. Restart with: powershell.exe -STA -File <script>" -ForegroundColor Red
        exit 1
    }

    $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $argParts = New-Object System.Collections.Generic.List[string]
    [void]$argParts.Add('-NoProfile')
    [void]$argParts.Add('-STA')
    [void]$argParts.Add('-ExecutionPolicy')
    [void]$argParts.Add('Bypass')
    [void]$argParts.Add('-File')
    [void]$argParts.Add(('"{0}"' -f $PSCommandPath))
    if (-not [string]::IsNullOrWhiteSpace($InputCsv)) {
        [void]$argParts.Add('-InputCsv')
        [void]$argParts.Add(('"{0}"' -f $InputCsv))
    }
    if (-not [string]::IsNullOrWhiteSpace($OutputCsv)) {
        [void]$argParts.Add('-OutputCsv')
        [void]$argParts.Add(('"{0}"' -f $OutputCsv))
    }
    if ($DeviceCode) {
        [void]$argParts.Add('-DeviceCode')
    }

    Write-Host "Relaunching in STA mode so file dialogs and the progress bar work..." -ForegroundColor Yellow
    $proc = Start-Process -FilePath $exe -ArgumentList ($argParts -join ' ') -Wait -PassThru -NoNewWindow
    if ($null -eq $proc.ExitCode) { exit 1 }
    exit $proc.ExitCode
}

#endregion

#region Helpers ----------------------------------------------------------------

function Initialize-WinForms {
    if ($script:WinFormsLoaded) { return }
    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    Add-Type -AssemblyName System.Drawing | Out-Null
    try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch { }
    $script:WinFormsLoaded = $true
}

function Get-DefaultPickerDirectory {
    foreach ($special in @('Desktop', 'MyDocuments')) {
        $path = [Environment]::GetFolderPath($special)
        if ($path -and (Test-Path -LiteralPath $path)) {
            return $path
        }
    }
    return [Environment]::GetFolderPath('UserProfile')
}

function Show-OwnedDialog {
    param(
        [Parameter(Mandatory)]
        [System.Windows.Forms.CommonDialog]$Dialog
    )

    $owner = New-Object System.Windows.Forms.Form
    $owner.ShowInTaskbar = $false
    $owner.WindowState = [System.Windows.Forms.FormWindowState]::Minimized
    $owner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
    $owner.Opacity = 0
    $owner.TopMost = $true
    try {
        [void]$owner.Show()
        $owner.Activate()
        return $Dialog.ShowDialog($owner)
    }
    finally {
        $owner.Close()
        $owner.Dispose()
    }
}

function Get-InputCsvPath {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title            = 'Select the CSV file containing the UPNs'
    $dialog.Filter           = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $dialog.InitialDirectory = Get-DefaultPickerDirectory
    $dialog.Multiselect      = $false
    $dialog.CheckFileExists  = $true
    $dialog.RestoreDirectory = $true

    try {
        if ((Show-OwnedDialog -Dialog $dialog) -eq [System.Windows.Forms.DialogResult]::OK) {
            return $dialog.FileName
        }
        return $null
    }
    finally {
        $dialog.Dispose()
    }
}

function Get-OutputCsvPath {
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Title            = 'Choose where to save the results'
    $dialog.Filter           = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $dialog.InitialDirectory = Get-DefaultPickerDirectory
    $dialog.FileName         = "UPN_Check_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $dialog.DefaultExt       = 'csv'
    $dialog.AddExtension     = $true
    $dialog.OverwritePrompt  = $true
    $dialog.RestoreDirectory = $true

    try {
        if ((Show-OwnedDialog -Dialog $dialog) -eq [System.Windows.Forms.DialogResult]::OK) {
            return $dialog.FileName
        }
        return $null
    }
    finally {
        $dialog.Dispose()
    }
}

function Escape-ODataString {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return '' }
    return ($Value -replace "'", "''")
}

function Get-UpnFromRow {
    param(
        $Row,
        [Parameter(Mandatory)]
        [string]$ColumnName
    )

    if ($null -eq $Row) { return '' }

    $raw = $null
    try {
        $raw = $Row.$ColumnName
    }
    catch {
        return ''
    }

    if ($null -eq $raw) { return '' }
    return ([string]$raw).Trim()
}

function Resolve-UpnColumn {
    param(
        [Parameter(Mandatory)]
        [object[]]$Rows
    )

    $columns = @($Rows[0].PSObject.Properties.Name)
    $match = $columns | Where-Object {
        $_ -match '^(userprincipalname|upn|email|mail|user)$'
    } | Select-Object -First 1

    if ($match) {
        return [pscustomobject]@{
            ColumnName = [string]$match
            AutoDetected = $true
        }
    }

    return [pscustomobject]@{
        ColumnName = [string]($columns | Select-Object -First 1)
        AutoDetected = $false
    }
}

function Get-ClampedPercent {
    param(
        [int]$Current,
        [int]$Total
    )

    if ($Total -le 0) { return 0 }
    $pct = [int][Math]::Floor(($Current / [double]$Total) * 100)
    if ($pct -lt 0) { return 0 }
    if ($pct -gt 100) { return 100 }
    return $pct
}

function Show-ProgressUi {
    param(
        [Parameter(Mandatory)]
        [int]$Total
    )

    if (-not $script:UseGui) { return }

    Initialize-WinForms

    $form = New-Object System.Windows.Forms.Form
    $form.Text = '.S account status in Entra'
    $form.Width = 560
    $form.Height = 160
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $true
    $form.TopMost = $true
    $form.ShowInTaskbar = $true

    $label = New-Object System.Windows.Forms.Label
    $label.Left = 16
    $label.Top = 16
    $label.Width = 510
    $label.Height = 22
    $label.Text = "Preparing to check $Total UPN(s)..."
    $form.Controls.Add($label)

    $bar = New-Object System.Windows.Forms.ProgressBar
    $bar.Left = 16
    $bar.Top = 48
    $bar.Width = 510
    $bar.Height = 24
    $bar.Minimum = 0
    $bar.Maximum = [Math]::Max($Total, 1)
    $bar.Value = 0
    $bar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
    $form.Controls.Add($bar)

    $detail = New-Object System.Windows.Forms.Label
    $detail.Left = 16
    $detail.Top = 84
    $detail.Width = 510
    $detail.Height = 22
    $detail.ForeColor = [System.Drawing.Color]::FromArgb(96, 94, 92)
    $detail.Text = '0%'
    $form.Controls.Add($detail)

    [void]$form.Show()
    $form.Activate()
    [void][System.Windows.Forms.Application]::DoEvents()

    $script:ProgressForm = $form
    $script:ProgressBar = $bar
    $script:ProgressLabel = $label
    $script:ProgressDetail = $detail
}

function Update-ProgressUi {
    param(
        [Parameter(Mandatory)]
        [int]$Current,

        [Parameter(Mandatory)]
        [int]$Total,

        [Parameter()]
        [string]$Upn = ''
    )

    $pct = Get-ClampedPercent -Current $Current -Total $Total
    $statusText = if ([string]::IsNullOrWhiteSpace($Upn)) {
        "$Current of $Total"
    }
    else {
        "$Current of $Total : $Upn"
    }

    Write-Progress -Activity 'Checking UPNs in Entra ID' `
                   -Status $statusText `
                   -PercentComplete $pct

    if ($null -eq $script:ProgressForm -or $script:ProgressForm.IsDisposed) {
        return
    }

    try {
        if ($script:ProgressBar.Maximum -ne [Math]::Max($Total, 1)) {
            $script:ProgressBar.Maximum = [Math]::Max($Total, 1)
        }
        $script:ProgressBar.Value = [Math]::Min($Current, $script:ProgressBar.Maximum)
        $script:ProgressLabel.Text = "Checking UPNs in Entra ID — $statusText"
        $script:ProgressDetail.Text = "$pct% complete"
        [void][System.Windows.Forms.Application]::DoEvents()
    }
    catch {
        # Progress UI is best-effort; never fail the lookup loop because of it.
    }
}

function Close-ProgressUi {
    Write-Progress -Activity 'Checking UPNs in Entra ID' -Completed

    if ($null -eq $script:ProgressForm) { return }
    try {
        if (-not $script:ProgressForm.IsDisposed) {
            $script:ProgressForm.Close()
            $script:ProgressForm.Dispose()
        }
    }
    catch { }
    finally {
        $script:ProgressForm = $null
        $script:ProgressBar = $null
        $script:ProgressLabel = $null
        $script:ProgressDetail = $null
    }
}

function New-ResultRow {
    param(
        [string]$UPN = '',
        [string]$Status = '',
        [string]$DisplayName = '',
        $AccountEnabled = '',
        [string]$Id = '',
        [string]$ErrorMessage = ''
    )

    return [PSCustomObject]@{
        UPN            = $UPN
        Status         = $Status
        DisplayName    = $DisplayName
        AccountEnabled = $AccountEnabled
        Id             = $Id
        Error          = $ErrorMessage
    }
}

function Get-UserStatusFromAccount {
    param($User)

    if ($null -eq $User) {
        return 'Not Found'
    }

    # Graph may return AccountEnabled as bool, or occasionally as string.
    $enabled = $User.AccountEnabled
    if ($enabled -is [string]) {
        if ($enabled -match '^(true|1|yes)$') { return 'Found' }
        if ($enabled -match '^(false|0|no)$') { return 'Found (Disabled)' }
    }

    if ($enabled -eq $true) { return 'Found' }
    if ($enabled -eq $false) { return 'Found (Disabled)' }

    # Unknown / missing AccountEnabled — still report as found.
    return 'Found'
}

function Invoke-SelfTest {
    $failures = New-Object System.Collections.Generic.List[string]

    function Assert-Equal {
        param($Expected, $Actual, [string]$Name)
        if ($Expected -ne $Actual) {
            [void]$failures.Add("$Name : expected '$Expected', got '$Actual'")
        }
    }

    Assert-Equal "o''brien@contoso.com" (Escape-ODataString "o'brien@contoso.com") 'odata escape apostrophe'
    Assert-Equal '' (Escape-ODataString $null) 'odata escape null'
    Assert-Equal 0 (Get-ClampedPercent -Current 0 -Total 0) 'percent empty total'
    Assert-Equal 50 (Get-ClampedPercent -Current 1 -Total 2) 'percent halfway'
    Assert-equal 100 (Get-ClampedPercent -Current 5 -Total 5) 'percent complete'
    Assert-equal 100 (Get-ClampedPercent -Current 6 -Total 5) 'percent over'

    $row = [PSCustomObject]@{ UserPrincipalName = '  a@b.com  '; Other = 1 }
    Assert-equal 'a@b.com' (Get-UpnFromRow -Row $row -ColumnName 'UserPrincipalName') 'trim upn'
    Assert-equal '' (Get-UpnFromRow -Row $row -ColumnName 'Missing') 'missing column'
    Assert-Equal '' (Get-UpnFromRow -Row ([PSCustomObject]@{ UserPrincipalName = $null }) -ColumnName 'UserPrincipalName') 'null upn'

    $csvRows = @(
        [PSCustomObject]@{ Email = 'one@contoso.com'; Name = 'One' }
    )
    $resolved = Resolve-UpnColumn -Rows $csvRows
    Assert-Equal 'Email' $resolved.ColumnName 'detect email column'
    Assert-equal $true $resolved.AutoDetected 'email auto-detected'

    $fallbackRows = @(
        [PSCustomObject]@{ WeirdCol = 'x@y.com' }
    )
    $fallback = Resolve-UpnColumn -Rows $fallbackRows
    Assert-equal 'WeirdCol' $fallback.ColumnName 'fallback first column'
    Assert-equal $false $fallback.AutoDetected 'fallback not auto-detected'

    $enabledUser = [PSCustomObject]@{ AccountEnabled = $true }
    $disabledUser = [PSCustomObject]@{ AccountEnabled = $false }
    Assert-equal 'Found' (Get-UserStatusFromAccount -User $enabledUser) 'enabled status'
    Assert-equal 'Found (Disabled)' (Get-UserStatusFromAccount -User $disabledUser) 'disabled status'
    Assert-equal 'Not Found' (Get-UserStatusFromAccount -User $null) 'null user status'

    if ($failures.Count -gt 0) {
        Write-Host 'Self-test FAILED:' -ForegroundColor Red
        foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
        exit 1
    }

    Write-Host 'All self-tests passed.' -ForegroundColor Green
    exit 0
}

#endregion

if ($SelfTest) {
    Invoke-SelfTest
}

#region Main -------------------------------------------------------------------

Write-Host '.S account status in Entra' -ForegroundColor Cyan
Write-Host ''

if ($script:UseGui) {
    Initialize-WinForms
}

# --- 1. Pick input CSV -----------------------------------------------------
if ([string]::IsNullOrWhiteSpace($InputCsv)) {
    Write-Host 'Please select the input CSV file...' -ForegroundColor Cyan
    $InputCsv = Get-InputCsvPath
    if (-not $InputCsv) {
        Write-Warning 'No input file selected. Exiting.'
        exit 0
    }
}
elseif (-not (Test-Path -LiteralPath $InputCsv)) {
    Write-Error "Input CSV not found: $InputCsv"
    exit 1
}
Write-Host "Input file:  $InputCsv" -ForegroundColor Green

# --- 2. Pick output location ----------------------------------------------
if ([string]::IsNullOrWhiteSpace($OutputCsv)) {
    Write-Host 'Please choose where to save the results...' -ForegroundColor Cyan
    $OutputCsv = Get-OutputCsvPath
    if (-not $OutputCsv) {
        Write-Warning 'No output file selected. Exiting.'
        exit 0
    }
}
Write-Host "Output file: $OutputCsv" -ForegroundColor Green

# --- 3. Import the CSV and locate the UPN column ---------------------------
try {
    # Force array so a single-row CSV does not break .Count / foreach logic.
    $rows = @(Import-Csv -Path $InputCsv -ErrorAction Stop)
}
catch {
    Write-Error "Failed to read the CSV: $($_.Exception.Message)"
    exit 1
}

if ($rows.Count -eq 0) {
    Write-Warning 'The selected CSV is empty.'
    exit 0
}

$columnInfo = Resolve-UpnColumn -Rows $rows
$upnColumn = $columnInfo.ColumnName
if ($columnInfo.AutoDetected) {
    Write-Host "Using column '$upnColumn' for UPNs." -ForegroundColor Green
}
else {
    Write-Warning "Could not auto-detect a UPN column. Using the first column: '$upnColumn'"
}

# --- 4. Ensure the Microsoft Graph module is available ---------------------
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
    Write-Warning 'The Microsoft.Graph.Users module is not installed.'
    $answer = Read-Host 'Install it now for the current user? (Y/N)'
    if ($answer -match '^(y|yes)$') {
        try {
            Install-Module Microsoft.Graph.Users -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        }
        catch {
            Write-Error "Module installation failed: $($_.Exception.Message)"
            exit 1
        }
    }
    else {
        Write-Error 'Cannot continue without the Microsoft.Graph.Users module.'
        exit 1
    }
}

Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue | Out-Null
Import-Module Microsoft.Graph.Users -ErrorAction Stop

# --- 5. Connect to Microsoft Graph -----------------------------------------
try {
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    $needsConnect = $true
    if ($ctx -and $ctx.Scopes -and ($ctx.Scopes -contains 'User.Read.All' -or $ctx.Scopes -contains 'Directory.Read.All')) {
        $needsConnect = $false
    }

    if ($needsConnect) {
        Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
        $connectParams = @{
            Scopes      = @('User.Read.All')
            ErrorAction = 'Stop'
        }
        if ($DeviceCode) {
            $connectParams['UseDeviceAuthentication'] = $true
        }
        # -NoWelcome exists on newer Graph SDK versions only.
        $cmd = Get-Command Connect-MgGraph -ErrorAction Stop
        if ($cmd.Parameters.ContainsKey('NoWelcome')) {
            $connectParams['NoWelcome'] = $true
        }
        Connect-MgGraph @connectParams | Out-Null
    }
    else {
        Write-Host "Already connected to Microsoft Graph as $($ctx.Account)." -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

# --- 6. Look up each UPN ---------------------------------------------------
$results = New-Object System.Collections.Generic.List[object]
$total   = $rows.Count
$i       = 0

Show-ProgressUi -Total $total
Write-Host "Processing $total UPN(s)..." -ForegroundColor Cyan

try {
    foreach ($row in $rows) {
        $i++
        $upn = Get-UpnFromRow -Row $row -ColumnName $upnColumn
        Update-ProgressUi -Current $i -Total $total -Upn $upn

        if ([string]::IsNullOrWhiteSpace($upn)) {
            [void]$results.Add((New-ResultRow -UPN $upn -Status 'Skipped (blank)' -ErrorMessage 'Empty UPN value'))
            continue
        }

        try {
            $escapedUpn = Escape-ODataString -Value $upn
            # Filter returns zero-or-more users via the pipeline; take the first match.
            # Do not index an empty array under StrictMode (throws on PS 7+).
            $user = Get-MgUser -Filter "userPrincipalName eq '$escapedUpn'" `
                               -Property 'Id,DisplayName,UserPrincipalName,AccountEnabled' `
                               -ErrorAction Stop |
                    Select-Object -First 1

            if ($null -ne $user) {
                $status = Get-UserStatusFromAccount -User $user
                [void]$results.Add((New-ResultRow `
                    -UPN $upn `
                    -Status $status `
                    -DisplayName ([string]$user.DisplayName) `
                    -AccountEnabled $user.AccountEnabled `
                    -Id ([string]$user.Id)))
            }
            else {
                [void]$results.Add((New-ResultRow -UPN $upn -Status 'Not Found'))
            }
        }
        catch {
            # Graph returns 404 Request_ResourceNotFound for some not-found paths;
            # filter with zero results usually returns empty, but treat 404 as Not Found.
            $msg = [string]$_.Exception.Message
            if ($msg -match 'Request_ResourceNotFound|does not exist|NotFound') {
                [void]$results.Add((New-ResultRow -UPN $upn -Status 'Not Found'))
            }
            else {
                [void]$results.Add((New-ResultRow -UPN $upn -Status 'Error' -ErrorMessage $msg))
            }
        }
    }
}
finally {
    Close-ProgressUi
}

# --- 7. Export results -----------------------------------------------------
try {
    $results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    Write-Host ''
    Write-Host 'Done. Results saved to:' -ForegroundColor Green
    Write-Host $OutputCsv -ForegroundColor Yellow
}
catch {
    Write-Error "Failed to write the output file: $($_.Exception.Message)"
    exit 1
}

# --- 8. Quick summary ------------------------------------------------------
$found    = @($results | Where-Object { $_.Status -eq 'Found' }).Count
$disabled = @($results | Where-Object { $_.Status -eq 'Found (Disabled)' }).Count
$notFound = @($results | Where-Object { $_.Status -eq 'Not Found' }).Count
$skipped  = @($results | Where-Object { $_.Status -eq 'Skipped (blank)' }).Count
$errors   = @($results | Where-Object { $_.Status -eq 'Error' }).Count

Write-Host ''
Write-Host 'Summary:' -ForegroundColor Cyan
Write-Host "  Found (Enabled):  $found"
Write-Host "  Found (Disabled): $disabled"
Write-Host "  Not Found:        $notFound"
Write-Host "  Skipped (blank):  $skipped"
Write-Host "  Errors:           $errors"

# Optional: disconnect when finished
# Disconnect-MgGraph | Out-Null

#endregion

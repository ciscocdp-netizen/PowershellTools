#Requires -Version 5.1
<#
.SYNOPSIS
    Exchange Online Mailbox Quota Manager.

.DESCRIPTION
    Windows Forms tool for reading and changing mailbox quota settings and for
    viewing the licenses assigned to each mailbox.

    Quota settings, in gigabytes:
      IssueWarningGB          - IssueWarningQuota
      ProhibitSendGB          - ProhibitSendQuota
      ProhibitSendReceiveGB   - ProhibitSendReceiveQuota

    A CSV import detects those headers automatically. The mapping dropdowns can
    be changed before the update runs. A QuotaInGB column is used only when the
    three quota columns are blank.

.NOTES
    Requires Windows PowerShell 5.1 or PowerShell 7 on Windows.
    Keep QuotaManager.Core.ps1 in the same folder as this script.

    Install-Module ExchangeOnlineManagement -Scope CurrentUser
    Install-Module Microsoft.Graph -Scope CurrentUser

    Bugs fixed from the January 2026 script:
      - Connect-ExchangeOnline ran in a runspace that was closed immediately,
        so Set-Mailbox could not see the session. Commands now run on the
        window's thread, which is also what the sign-in window requires.
      - The action bar was added after the grid and could be covered by it.
      - ProhibitSendReceiveQuota, ProhibitSendQuota, and IssueWarningQuota in
        the CSV were ignored. One QuotaInGB value was copied onto send and
        send/receive.
      - Quota values such as 50GB failed the integer cast.
      - A one-row CSV was not always treated as a collection.
      - The missing-module message used Windows Forms before the assembly loaded.
      - Headers had to match three exact names.
      - Test mode did not check that the mailbox existed.
      - Exchange progress output could stall a Windows Forms host.
      - The last grid edit could be left uncommitted.
#>

$ErrorActionPreference = 'Continue'
# Exchange cmdlets call Write-Progress. That can stall or throw under Windows Forms.
$ProgressPreference = 'SilentlyContinue'

if ($env:OS -ne 'Windows_NT') {
    Write-Error 'Exchange Online Quota Manager must be run on Windows.'
    return
}

if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        Write-Error 'This session is not STA. Run the script file with powershell.exe, or start PowerShell 7 with -STA.'
        return
    }
    $hostPath = (Get-Process -Id $PID).Path
    Start-Process -FilePath $hostPath -ArgumentList @('-NoProfile', '-STA', '-File', $PSCommandPath) | Out-Null
    return
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch {}

$script:CorePath = Join-Path $PSScriptRoot 'QuotaManager.Core.ps1'
if (-not (Test-Path -LiteralPath $script:CorePath)) {
    [System.Windows.Forms.MessageBox]::Show(
        "QuotaManager.Core.ps1 was not found next to this script.`r`n`r`nExpected:`r`n$($script:CorePath)",
        'Exchange Online Quota Manager',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    return
}
. $script:CorePath

$script:AppVersion = '2.0'
$script:busy = $false
$script:cancelRequested = $false
$script:exoConnected = $false
$script:licenseConnected = $false
$script:licenseSource = ''
$script:exoOrganization = ''
$script:exoAccount = ''
$script:licenseAccount = ''
$script:mailboxLoaded = $false
$script:loadedUpn = ''
$script:gridEdited = $false
$script:suppressMapEvents = $false
$script:suppressQuotaEvents = $false
$script:sourceRows = @()
$script:sourceHeaders = @()
$script:sourcePath = ''
$script:sourceDelimiter = ''
$script:detectedDisplayName = $null
$script:mapSnapshot = $null
$script:licenseSummary = ''
$script:form = $null

function Write-Activity {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    if ($script:txtLog) {
        $color = switch ($Level) {
            'ERROR'   { [System.Drawing.Color]::Firebrick }
            'WARN'    { [System.Drawing.Color]::DarkGoldenrod }
            'SUCCESS' { [System.Drawing.Color]::DarkGreen }
            default   { [System.Drawing.Color]::FromArgb(32, 32, 32) }
        }
        $script:txtLog.SelectionStart = $script:txtLog.TextLength
        $script:txtLog.SelectionLength = 0
        $script:txtLog.SelectionColor = $color
        $script:txtLog.AppendText("$line`r`n")
        $script:txtLog.ScrollToCaret()
    }
    if ($script:statusLabel) {
        $script:statusLabel.Text = $Message
    }
}

function Show-Info {
    param(
        [Parameter(Mandatory)][string]$Message,
        [string]$Title = 'Exchange Online Quota Manager',
        [System.Windows.Forms.MessageBoxIcon]$Icon = 'Information'
    )

    if ($script:form -and -not $script:form.IsDisposed) {
        [void][System.Windows.Forms.MessageBox]::Show($script:form, $Message, $Title, 'OK', $Icon)
    }
    else {
        [void][System.Windows.Forms.MessageBox]::Show($Message, $Title, 'OK', $Icon)
    }
}

function Show-Confirm {
    param(
        [Parameter(Mandatory)][string]$Message,
        [string]$Title = 'Exchange Online Quota Manager'
    )

    $owner = $null
    if ($script:form -and -not $script:form.IsDisposed) {
        $owner = $script:form
    }
    $result = if ($owner) {
        [System.Windows.Forms.MessageBox]::Show($owner, $Message, $Title, 'YesNo', 'Question')
    }
    else {
        [System.Windows.Forms.MessageBox]::Show($Message, $Title, 'YesNo', 'Question')
    }
    return ($result -eq [System.Windows.Forms.DialogResult]::Yes)
}

function Show-TextDialog {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Body
    )

    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = $Title
    $dialog.Size = New-Object System.Drawing.Size(780, 580)
    $dialog.StartPosition = 'CenterParent'
    $dialog.MinimizeBox = $false
    $dialog.Font = $script:form.Font

    $close = New-Object System.Windows.Forms.Button
    $close.Text = 'Close'
    $close.Dock = 'Bottom'
    $close.Height = 36
    $close.DialogResult = 'OK'
    $dialog.CancelButton = $close
    $dialog.Controls.Add($close)

    $box = New-Object System.Windows.Forms.TextBox
    $box.Multiline = $true
    $box.ReadOnly = $true
    $box.ScrollBars = 'Both'
    $box.Dock = 'Fill'
    $box.WordWrap = $true
    $box.Text = $Body
    $box.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $dialog.Controls.Add($box)

    [void]$dialog.ShowDialog($script:form)
    $dialog.Dispose()
}

function Set-UiBusy {
    param([bool]$Busy)

    $ready = -not $Busy
    $hasRows = $false
    if ($script:dataTable) {
        $hasRows = @($script:dataTable.DefaultView).Count -gt 0
    }

    if ($script:btnConnect) { $script:btnConnect.Enabled = $ready -and -not $script:exoConnected }
    if ($script:btnDisconnectExo) { $script:btnDisconnectExo.Enabled = $ready -and $script:exoConnected }
    if ($script:btnConnectLicense) { $script:btnConnectLicense.Enabled = $ready -and -not $script:licenseConnected }
    if ($script:btnDisconnectLicense) { $script:btnDisconnectLicense.Enabled = $ready -and $script:licenseConnected }
    if ($script:btnLookup) { $script:btnLookup.Enabled = $ready -and $script:exoConnected }
    if ($script:btnApplyOne) { $script:btnApplyOne.Enabled = $ready -and $script:exoConnected -and $script:mailboxLoaded }
    if ($script:btnImport) { $script:btnImport.Enabled = $ready }
    if ($script:btnExportTemplate) { $script:btnExportTemplate.Enabled = $ready }
    if ($script:btnExportGrid) { $script:btnExportGrid.Enabled = $ready }
    if ($script:btnRemoveRows) { $script:btnRemoveRows.Enabled = $ready }
    if ($script:btnOpenSelected) { $script:btnOpenSelected.Enabled = $ready -and $script:exoConnected -and $hasRows }
    if ($script:btnApplyBulk) { $script:btnApplyBulk.Enabled = $ready -and $script:exoConnected -and $hasRows }
    if ($script:btnLoadCurrent) { $script:btnLoadCurrent.Enabled = $ready -and $script:exoConnected -and $hasRows }
    if ($script:btnCancel) { $script:btnCancel.Enabled = $Busy }
    if ($script:cboIdentity) { $script:cboIdentity.Enabled = $ready }
    if ($script:cboReceive) { $script:cboReceive.Enabled = $ready }
    if ($script:cboSend) { $script:cboSend.Enabled = $ready }
    if ($script:cboWarning) { $script:cboWarning.Enabled = $ready }
    if ($script:cboQuota) { $script:cboQuota.Enabled = $ready }
    if ($script:progress) {
        $script:progress.Visible = $Busy
        if (-not $Busy) { $script:progress.Value = 0 }
    }
    Update-ConnectionLabels
}

function Invoke-WithBusyCursor {
    param([Parameter(Mandatory)][scriptblock]$Action)

    if ($script:busy) {
        return
    }

    $script:busy = $true
    $script:cancelRequested = $false
    Set-UiBusy $true
    $previous = $script:form.Cursor
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()
    try {
        & $Action
    }
    finally {
        $script:busy = $false
        $script:cancelRequested = $false
        if ($script:form -and -not $script:form.IsDisposed) {
            $script:form.Cursor = $previous
        }
        Set-UiBusy $false
    }
}

function Update-ConnectionLabels {
    if ($script:exoConnected) {
        $text = 'Connected'
        if ($script:exoAccount) { $text += " as $($script:exoAccount)" }
        if ($script:exoOrganization) { $text += " · $($script:exoOrganization)" }
        if ($script:lblExo) {
            $script:lblExo.Text = $text
            $script:lblExo.ForeColor = [System.Drawing.Color]::DarkGreen
        }
        if ($script:exoStatus) {
            $script:exoStatus.Text = 'Exchange: Connected'
            $script:exoStatus.ForeColor = [System.Drawing.Color]::DarkGreen
        }
    }
    else {
        if ($script:lblExo) {
            $script:lblExo.Text = 'Not connected'
            $script:lblExo.ForeColor = [System.Drawing.Color]::Firebrick
        }
        if ($script:exoStatus) {
            $script:exoStatus.Text = 'Exchange: Not connected'
            $script:exoStatus.ForeColor = [System.Drawing.Color]::Firebrick
        }
    }

    if ($script:licenseConnected) {
        $text = "Connected via $($script:licenseSource)"
        if ($script:licenseAccount) { $text += " as $($script:licenseAccount)" }
        if ($script:lblLicense) {
            $script:lblLicense.Text = $text
            $script:lblLicense.ForeColor = [System.Drawing.Color]::DarkGreen
        }
        if ($script:licenseStatus) {
            $script:licenseStatus.Text = "Licenses: $($script:licenseSource)"
            $script:licenseStatus.ForeColor = [System.Drawing.Color]::DarkGreen
        }
    }
    else {
        if ($script:lblLicense) {
            $script:lblLicense.Text = 'Not connected — user licenses are not loaded'
            $script:lblLicense.ForeColor = [System.Drawing.Color]::Firebrick
        }
        if ($script:licenseStatus) {
            $script:licenseStatus.Text = 'Licenses: Not connected'
            $script:licenseStatus.ForeColor = [System.Drawing.Color]::Firebrick
        }
    }
}

function Connect-GraphWithFallback {
    try {
        Connect-MgGraph -Scopes @('User.Read.All') -NoWelcome -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -match 'NoWelcome') {
            Connect-MgGraph -Scopes @('User.Read.All') -ErrorAction Stop
        }
        else {
            throw
        }
    }
}

function Connect-ExchangeSession {
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw "The ExchangeOnlineManagement module is not installed.`r`n`r`nInstall-Module ExchangeOnlineManagement -Scope CurrentUser"
    }
    if (-not (Get-Module -Name ExchangeOnlineManagement)) {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
    }

    $existing = @()
    try { $existing = @(Get-ConnectionInformation -ErrorAction SilentlyContinue) } catch {}
    if ($existing.Count -eq 0) {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    }

    try {
        $org = Get-OrganizationConfig -ErrorAction Stop
    }
    catch {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        throw
    }

    $account = ''
    try {
        $info = @(Get-ConnectionInformation -ErrorAction SilentlyContinue) | Select-Object -First 1
        if ($info -and $info.UserPrincipalName) {
            $account = [string]$info.UserPrincipalName
        }
    }
    catch {}

    $script:exoConnected = $true
    $script:exoOrganization = [string]$org.DisplayName
    $script:exoAccount = $account
}

function Disconnect-ExchangeSession {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
    $script:exoConnected = $false
    $script:exoOrganization = ''
    $script:exoAccount = ''
}

function Connect-LicenseSession {
    $graphModule = @(Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)
    $graphMeta = @(Get-Module -ListAvailable -Name Microsoft.Graph)
    if ($graphModule.Count -gt 0 -or $graphMeta.Count -gt 0) {
        if (-not (Get-Module -Name Microsoft.Graph.Authentication)) {
            if ($graphModule.Count -gt 0) {
                Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
            }
            else {
                Import-Module Microsoft.Graph -ErrorAction Stop
            }
        }
        if (-not (Get-Command Get-MgUserLicenseDetail -ErrorAction SilentlyContinue)) {
            if (@(Get-Module -ListAvailable -Name Microsoft.Graph.Users).Count -gt 0) {
                Import-Module Microsoft.Graph.Users -ErrorAction Stop
            }
            elseif (-not (Get-Module -Name Microsoft.Graph)) {
                Import-Module Microsoft.Graph -ErrorAction Stop
            }
        }

        $context = $null
        try { $context = Get-MgContext -ErrorAction SilentlyContinue } catch {}
        if (-not $context -or [string]::IsNullOrWhiteSpace([string]$context.Account)) {
            Connect-GraphWithFallback
            $context = Get-MgContext -ErrorAction Stop
        }

        $script:licenseConnected = $true
        $script:licenseSource = 'Graph'
        $script:licenseAccount = [string]$context.Account
        return
    }

    if (@(Get-Module -ListAvailable -Name AzureAD).Count -gt 0) {
        if (-not (Get-Module -Name AzureAD)) {
            Import-Module AzureAD -ErrorAction Stop
        }
        $connection = Connect-AzureAD -ErrorAction Stop
        $script:licenseConnected = $true
        $script:licenseSource = 'AzureAD'
        $script:licenseAccount = [string]$connection.Account.Id
        return
    }

    if (@(Get-Module -ListAvailable -Name MSOnline).Count -gt 0) {
        if (-not (Get-Module -Name MSOnline)) {
            Import-Module MSOnline -ErrorAction Stop
        }
        Connect-MsolService -ErrorAction Stop
        $script:licenseConnected = $true
        $script:licenseSource = 'MSOnline'
        $script:licenseAccount = ''
        return
    }

    throw "No license module is installed.`r`n`r`nInstall the Microsoft Graph module, then connect again:`r`n`r`nInstall-Module Microsoft.Graph -Scope CurrentUser`r`n`r`nThe sign-in needs permission to read users (User.Read.All)."
}

function Disconnect-LicenseSession {
    if ($script:licenseSource -eq 'Graph') {
        Disconnect-MgGraph -ErrorAction Stop | Out-Null
    }
    elseif ($script:licenseSource -eq 'AzureAD') {
        Disconnect-AzureAD -ErrorAction Stop
    }
    $script:licenseConnected = $false
    $script:licenseSource = ''
    $script:licenseAccount = ''
}

function ConvertTo-BooleanValue {
    param($Value)
    if ($Value -is [bool]) { return [bool]$Value }
    if ($null -eq $Value) { return $false }
    $text = [string]$Value
    return ($text -eq 'True' -or $text -eq '1' -or $text -eq '$true')
}

function Format-CurrentQuota {
    param($Gigabytes, [string]$Raw)
    if ($null -ne $Gigabytes -and -not [string]::IsNullOrWhiteSpace([string]$Gigabytes)) {
        return "$(Format-QuotaNumber $Gigabytes) GB"
    }
    if ([string]::IsNullOrWhiteSpace($Raw)) { return '-' }
    return $Raw
}

function Get-MailboxQuotaSnapshot {
    param([Parameter(Mandatory)][string]$Identity)

    $mailbox = Get-Mailbox -Identity $Identity -ErrorAction Stop
    $snapshot = [pscustomobject]@{
        DisplayName              = [string]$mailbox.DisplayName
        UserPrincipalName        = [string]$mailbox.UserPrincipalName
        PrimarySmtpAddress       = [string]$mailbox.PrimarySmtpAddress
        RecipientTypeDetails     = [string]$mailbox.RecipientTypeDetails
        ArchiveStatus            = [string]$mailbox.ArchiveStatus
        UseDatabaseQuotaDefaults = (ConvertTo-BooleanValue $mailbox.UseDatabaseQuotaDefaults)
        IssueWarningRaw          = [string]$mailbox.IssueWarningQuota
        ProhibitSendRaw          = [string]$mailbox.ProhibitSendQuota
        ProhibitSendReceiveRaw   = [string]$mailbox.ProhibitSendReceiveQuota
        IssueWarningGB           = $null
        ProhibitSendGB           = $null
        ProhibitSendReceiveGB    = $null
        ParseError               = $null
    }

    try {
        $snapshot.IssueWarningGB = ConvertFrom-ExchangeQuotaValue $mailbox.IssueWarningQuota
        $snapshot.ProhibitSendGB = ConvertFrom-ExchangeQuotaValue $mailbox.ProhibitSendQuota
        $snapshot.ProhibitSendReceiveGB = ConvertFrom-ExchangeQuotaValue $mailbox.ProhibitSendReceiveQuota
    }
    catch {
        $snapshot.ParseError = $_.Exception.Message
    }

    return $snapshot
}

function Get-AssignedLicenseDetails {
    param([Parameter(Mandatory)][string]$UserPrincipalName)

    if (-not $script:licenseConnected) {
        return [pscustomobject]@{
            Summary = 'License service not connected'
            Records = @()
            Error   = $null
        }
    }

    try {
        $raw = @()
        if ($script:licenseSource -eq 'Graph') {
            $raw = @(Get-MgUserLicenseDetail -UserId $UserPrincipalName -ErrorAction Stop)
        }
        elseif ($script:licenseSource -eq 'AzureAD') {
            $user = Get-AzureADUser -ObjectId $UserPrincipalName -ErrorAction Stop
            $raw = @(Get-AzureADUserLicenseDetail -ObjectId $user.ObjectId -ErrorAction Stop)
        }
        elseif ($script:licenseSource -eq 'MSOnline') {
            $user = Get-MsolUser -UserPrincipalName $UserPrincipalName -ErrorAction Stop
            $raw = @($user.Licenses)
        }

        $records = @(ConvertTo-NormalizedLicenses $raw)
        return [pscustomobject]@{
            Summary = (Format-LicenseSummary $records)
            Records = $records
            Error   = $null
        }
    }
    catch {
        $message = $_.Exception.Message
        if ($message -match 'Authorization|Forbidden|Insufficient|Access denied') {
            $message += ' The signed-in account needs permission to read other users (User.Read.All).'
        }
        return [pscustomobject]@{
            Summary = "License lookup failed: $message"
            Records = @()
            Error   = $message
        }
    }
}

function Get-QuotaTargetIdentity {
    param($Snapshot, [string]$RequestedIdentity)
    if ($Snapshot -and -not [string]::IsNullOrWhiteSpace($Snapshot.UserPrincipalName)) {
        return $Snapshot.UserPrincipalName
    }
    if ($Snapshot -and -not [string]::IsNullOrWhiteSpace($Snapshot.PrimarySmtpAddress)) {
        return $Snapshot.PrimarySmtpAddress
    }
    return $RequestedIdentity
}

function Format-SetMailboxCommand {
    param(
        [string]$Identity,
        $Step,
        [bool]$WhatIf,
        [bool]$RevertToDefaults
    )

    $safeIdentity = $Identity.Replace("'", "''")
    if ($RevertToDefaults) {
        $text = "Set-Mailbox -Identity '$safeIdentity' -UseDatabaseQuotaDefaults `$true -Confirm:`$false"
    }
    else {
        $parts = @("Set-Mailbox -Identity '$safeIdentity' -UseDatabaseQuotaDefaults `$false -Confirm:`$false")
        if ($Step.IssueWarningQuota) { $parts += "-IssueWarningQuota $($Step.IssueWarningQuota)" }
        if ($Step.ProhibitSendQuota) { $parts += "-ProhibitSendQuota $($Step.ProhibitSendQuota)" }
        if ($Step.ProhibitSendReceiveQuota) { $parts += "-ProhibitSendReceiveQuota $($Step.ProhibitSendReceiveQuota)" }
        $text = $parts -join ' '
    }
    if ($WhatIf) { $text += ' -WhatIf' }
    return $text
}

function Invoke-SetMailboxStep {
    param(
        [string]$Identity,
        $Step,
        [bool]$WhatIf,
        [bool]$RevertToDefaults
    )

    Write-Activity (Format-SetMailboxCommand -Identity $Identity -Step $Step -WhatIf:$WhatIf -RevertToDefaults:$RevertToDefaults)

    $params = @{
        Identity     = $Identity
        Confirm      = $false
        ErrorAction  = 'Stop'
        WarningVariable = 'quotaWarnings'
    }
    if ($WhatIf) {
        $params.WhatIf = $true
    }

    if ($RevertToDefaults) {
        $params.UseDatabaseQuotaDefaults = $true
    }
    else {
        $params.UseDatabaseQuotaDefaults = $false
        if ($Step.IssueWarningQuota) { $params.IssueWarningQuota = [string]$Step.IssueWarningQuota }
        if ($Step.ProhibitSendQuota) { $params.ProhibitSendQuota = [string]$Step.ProhibitSendQuota }
        if ($Step.ProhibitSendReceiveQuota) { $params.ProhibitSendReceiveQuota = [string]$Step.ProhibitSendReceiveQuota }
    }

    Set-Mailbox @params
    foreach ($warning in @($quotaWarnings)) {
        if ($warning) {
            Write-Activity "Exchange warning: $warning" 'WARN'
        }
    }
}

function New-QuotaResult {
    param(
        [string]$Status,
        [string]$Message,
        $Snapshot = $null,
        [string]$LicenseSummary = '',
        $LicenseRecords = @()
    )

    return [pscustomobject]@{
        Status          = $Status
        Message         = $Message
        Snapshot        = $Snapshot
        LicenseSummary  = $LicenseSummary
        LicenseRecords  = @($LicenseRecords)
    }
}

function Invoke-MailboxQuotaChange {
    param(
        [Parameter(Mandatory)][string]$Identity,
        $RequestedIssueWarningGB,
        $RequestedProhibitSendGB,
        $RequestedProhibitSendReceiveGB,
        [bool]$WhatIf,
        [bool]$RevertToDefaults,
        [bool]$LoadLicenses = $true,
        [switch]$PreviewOnly
    )

    if ([string]::IsNullOrWhiteSpace($Identity)) {
        return (New-QuotaResult -Status 'Skipped' -Message 'No user identity was provided.')
    }

    $hasRequest = ($null -ne $RequestedIssueWarningGB) -or ($null -ne $RequestedProhibitSendGB) -or ($null -ne $RequestedProhibitSendReceiveGB)
    if (-not $RevertToDefaults -and -not $hasRequest) {
        return (New-QuotaResult -Status 'Skipped' -Message 'No quota values were provided.')
    }

    if (-not $RevertToDefaults -and $hasRequest) {
        $local = Test-QuotaTargets -IssueWarningGB $RequestedIssueWarningGB -ProhibitSendGB $RequestedProhibitSendGB -ProhibitSendReceiveGB $RequestedProhibitSendReceiveGB
        if (-not $local.IsValid) {
            return (New-QuotaResult -Status 'Skipped' -Message ($local.Errors -join ' '))
        }
    }

    try {
        $snapshot = Get-MailboxQuotaSnapshot -Identity $Identity
    }
    catch {
        return (New-QuotaResult -Status 'Failed' -Message $_.Exception.Message)
    }

    $licenseSummary = ''
    $licenseRecords = @()
    if ($LoadLicenses) {
        $licenseIdentity = Get-QuotaTargetIdentity -Snapshot $snapshot -RequestedIdentity $Identity
        $licenses = Get-AssignedLicenseDetails -UserPrincipalName $licenseIdentity
        $licenseSummary = [string]$licenses.Summary
        $licenseRecords = @($licenses.Records)
        if ($licenses.Error) {
            Write-Activity "$licenseIdentity licenses: $($licenses.Error)" 'WARN'
        }
    }

    $target = Get-QuotaTargetIdentity -Snapshot $snapshot -RequestedIdentity $Identity

    if ($RevertToDefaults) {
        if ($snapshot.UseDatabaseQuotaDefaults) {
            return (New-QuotaResult -Status 'Unchanged' -Message 'The mailbox already uses license defaults.' -Snapshot $snapshot -LicenseSummary $licenseSummary -LicenseRecords $licenseRecords)
        }
        if ($PreviewOnly) {
            return (New-QuotaResult -Status 'Preview' -Message 'Ready to revert to license defaults.' -Snapshot $snapshot -LicenseSummary $licenseSummary -LicenseRecords $licenseRecords)
        }
        try {
            Invoke-SetMailboxStep -Identity $target -WhatIf:$WhatIf -RevertToDefaults:$true -Step $null
        }
        catch {
            return (New-QuotaResult -Status 'Failed' -Message $_.Exception.Message -Snapshot $snapshot -LicenseSummary $licenseSummary -LicenseRecords $licenseRecords)
        }
        $status = if ($WhatIf) { 'TestPassed' } else { 'Updated' }
        $message = if ($WhatIf) { 'Would revert to license defaults.' } else { 'Reverted to license defaults.' }
        return (New-QuotaResult -Status $status -Message $message -Snapshot $snapshot -LicenseSummary $licenseSummary -LicenseRecords $licenseRecords)
    }

    $merged = Merge-QuotaTargets `
        -CurrentIssueWarningGB $snapshot.IssueWarningGB `
        -CurrentProhibitSendGB $snapshot.ProhibitSendGB `
        -CurrentProhibitSendReceiveGB $snapshot.ProhibitSendReceiveGB `
        -RequestedIssueWarningGB $RequestedIssueWarningGB `
        -RequestedProhibitSendGB $RequestedProhibitSendGB `
        -RequestedProhibitSendReceiveGB $RequestedProhibitSendReceiveGB

    if (-not $merged.IsComplete) {
        $reason = "The quota set is incomplete. Missing: $($merged.Missing -join ', ')."
        if ($snapshot.ParseError) {
            $reason += " Current quota text could not be read ($($snapshot.ParseError))."
        }
        return (New-QuotaResult -Status 'Skipped' -Message $reason -Snapshot $snapshot -LicenseSummary $licenseSummary -LicenseRecords $licenseRecords)
    }

    $check = Test-QuotaTargets -IssueWarningGB $merged.IssueWarningGB -ProhibitSendGB $merged.ProhibitSendGB -ProhibitSendReceiveGB $merged.ProhibitSendReceiveGB
    $licenseWarnings = @(Get-LicenseQuotaWarnings -Licenses $licenseRecords -IssueWarningGB $merged.IssueWarningGB -ProhibitSendGB $merged.ProhibitSendGB -ProhibitSendReceiveGB $merged.ProhibitSendReceiveGB)
    $warnings = @($check.Warnings) + @($licenseWarnings | Where-Object { $_ })

    if (-not $check.IsValid) {
        return (New-QuotaResult -Status 'Skipped' -Message ($check.Errors -join ' ') -Snapshot $snapshot -LicenseSummary $licenseSummary -LicenseRecords $licenseRecords)
    }

    $summary = "IssueWarningGB $(Format-QuotaNumber $merged.IssueWarningGB), ProhibitSendGB $(Format-QuotaNumber $merged.ProhibitSendGB), ProhibitSendReceiveGB $(Format-QuotaNumber $merged.ProhibitSendReceiveGB)."
    if (-not $merged.Changed) {
        $unchanged = "Already $summary"
        if ($warnings.Count -gt 0) { $unchanged += ' ' + ($warnings -join ' ') }
        return (New-QuotaResult -Status 'Unchanged' -Message $unchanged -Snapshot $snapshot -LicenseSummary $licenseSummary -LicenseRecords $licenseRecords)
    }

    if ($PreviewOnly) {
        $preview = "Ready: $summary"
        if ($warnings.Count -gt 0) { $preview += ' ' + ($warnings -join ' ') }
        return (New-QuotaResult -Status 'Preview' -Message $preview -Snapshot $snapshot -LicenseSummary $licenseSummary -LicenseRecords $licenseRecords)
    }

    try {
        $steps = @(Get-MailboxQuotaWriteSteps `
            -CurrentIssueWarningGB $snapshot.IssueWarningGB `
            -CurrentProhibitSendGB $snapshot.ProhibitSendGB `
            -CurrentProhibitSendReceiveGB $snapshot.ProhibitSendReceiveGB `
            -TargetIssueWarningGB $merged.IssueWarningGB `
            -TargetProhibitSendGB $merged.ProhibitSendGB `
            -TargetProhibitSendReceiveGB $merged.ProhibitSendReceiveGB `
            -TestMode:$WhatIf)
        foreach ($step in $steps) {
            Invoke-SetMailboxStep -Identity $target -Step $step -WhatIf:$WhatIf
        }
    }
    catch {
        return (New-QuotaResult -Status 'Failed' -Message $_.Exception.Message -Snapshot $snapshot -LicenseSummary $licenseSummary -LicenseRecords $licenseRecords)
    }

    foreach ($warning in $warnings) {
        Write-Activity "$target $warning" 'WARN'
    }

    $status = if ($WhatIf) { 'TestPassed' } else { 'Updated' }
    $prefix = if ($WhatIf) { 'Would set' } else { 'Set' }
    $message = "$prefix $summary"
    if ($warnings.Count -gt 0) { $message += ' ' + ($warnings -join ' ') }
    return (New-QuotaResult -Status $status -Message $message -Snapshot $snapshot -LicenseSummary $licenseSummary -LicenseRecords $licenseRecords)
}

function Clear-MailboxDetails {
    $script:mailboxLoaded = $false
    $script:loadedUpn = ''
    foreach ($key in @($script:detailValues.Keys)) {
        $script:detailValues[$key].Text = '-'
    }
    $script:lblCurrentWarning.Text = 'Current: -'
    $script:lblCurrentSend.Text = 'Current: -'
    $script:lblCurrentReceive.Text = 'Current: -'
    $script:licenseList.Items.Clear()
    $script:lblLicenseCount.Text = 'Look up a mailbox to see every license assigned to it.'
    $script:licenseSummary = ''
    if (-not $script:busy) { Set-UiBusy $false }
}

function Show-LicenseRecords {
    param($Records, [string]$Summary)

    $script:licenseList.Items.Clear()
    $records = @(ConvertTo-NormalizedLicenses $Records)
    foreach ($record in $records) {
        $item = New-Object System.Windows.Forms.ListViewItem([string]$record.Product)
        [void]$item.SubItems.Add([string]$record.SkuPartNumber)
        [void]$item.SubItems.Add([string]$record.SkuId)
        $enabled = Format-ServicePlanList $record.EnabledPlans
        $disabled = Format-ServicePlanList $record.DisabledPlans
        [void]$item.SubItems.Add($enabled)
        [void]$item.SubItems.Add($disabled)
        $item.ToolTipText = "$($record.Product) ($($record.SkuPartNumber))`r`nEnabled: $enabled`r`nDisabled: $disabled"
        [void]$script:licenseList.Items.Add($item)
    }

    if ([string]::IsNullOrWhiteSpace($Summary)) {
        $Summary = Format-LicenseSummary $records
    }
    $script:licenseSummary = $Summary
    if ($records.Count -eq 0) {
        $script:lblLicenseCount.Text = $Summary
    }
    else {
        $script:lblLicenseCount.Text = "$($records.Count) license(s) assigned. $Summary"
    }
}

function Show-MailboxSnapshot {
    param($Snapshot, [bool]$FillEditors)

    $script:detailValues['DisplayName'].Text = $(if ($Snapshot.DisplayName) { $Snapshot.DisplayName } else { '-' })
    $script:detailValues['UserPrincipalName'].Text = $(if ($Snapshot.UserPrincipalName) { $Snapshot.UserPrincipalName } else { '-' })
    $script:detailValues['PrimarySmtpAddress'].Text = $(if ($Snapshot.PrimarySmtpAddress) { $Snapshot.PrimarySmtpAddress } else { '-' })
    $script:detailValues['RecipientType'].Text = $(if ($Snapshot.RecipientTypeDetails) { $Snapshot.RecipientTypeDetails } else { '-' })
    $script:detailValues['ArchiveStatus'].Text = $(if ($Snapshot.ArchiveStatus) { $Snapshot.ArchiveStatus } else { '-' })
    $script:detailValues['DatabaseDefaults'].Text = $(if ($Snapshot.UseDatabaseQuotaDefaults) { 'Using license defaults' } else { 'Custom quotas' })
    $script:detailValues['IssueWarning'].Text = Format-CurrentQuota $Snapshot.IssueWarningGB $Snapshot.IssueWarningRaw
    $script:detailValues['ProhibitSend'].Text = Format-CurrentQuota $Snapshot.ProhibitSendGB $Snapshot.ProhibitSendRaw
    $script:detailValues['ProhibitSendReceive'].Text = Format-CurrentQuota $Snapshot.ProhibitSendReceiveGB $Snapshot.ProhibitSendReceiveRaw

    $script:lblCurrentWarning.Text = "Current: $($script:detailValues['IssueWarning'].Text)"
    $script:lblCurrentSend.Text = "Current: $($script:detailValues['ProhibitSend'].Text)"
    $script:lblCurrentReceive.Text = "Current: $($script:detailValues['ProhibitSendReceive'].Text)"

    if ($FillEditors) {
        $script:suppressQuotaEvents = $true
        try {
            $script:txtWarning.Text = Format-QuotaNumber $Snapshot.IssueWarningGB
            $script:txtSend.Text = Format-QuotaNumber $Snapshot.ProhibitSendGB
            $script:txtReceive.Text = Format-QuotaNumber $Snapshot.ProhibitSendReceiveGB
            $script:chkRevert.Checked = $false
        }
        finally {
            $script:suppressQuotaEvents = $false
        }
        Update-SingleQuotaHint
    }

    $script:mailboxLoaded = $true
    $script:loadedUpn = Get-QuotaTargetIdentity -Snapshot $Snapshot -RequestedIdentity $script:txtUser.Text.Trim()
    if (-not $script:busy) { Set-UiBusy $false }
}

function Update-SingleQuotaHint {
    if ($script:chkRevert.Checked) {
        $script:txtWarning.Enabled = $false
        $script:txtSend.Enabled = $false
        $script:txtReceive.Enabled = $false
        $script:lblQuotaHint.Text = 'Apply will turn database quota defaults back on for this mailbox.'
        $script:lblQuotaHint.ForeColor = [System.Drawing.Color]::DarkGoldenrod
        return
    }

    $script:txtWarning.Enabled = $true
    $script:txtSend.Enabled = $true
    $script:txtReceive.Enabled = $true

    try {
        $warning = ConvertTo-QuotaGigabytes $script:txtWarning.Text
        $send = ConvertTo-QuotaGigabytes $script:txtSend.Text
        $receive = ConvertTo-QuotaGigabytes $script:txtReceive.Text
    }
    catch {
        $script:lblQuotaHint.Text = $_.Exception.Message
        $script:lblQuotaHint.ForeColor = [System.Drawing.Color]::Firebrick
        return
    }

    if ($null -eq $warning -and $null -eq $send -and $null -eq $receive) {
        $script:lblQuotaHint.Text = 'Enter gigabytes. Blank fields keep the current mailbox value. Issue warning ≤ prohibit send ≤ prohibit send/receive.'
        $script:lblQuotaHint.ForeColor = [System.Drawing.Color]::DimGray
        return
    }

    $check = Test-QuotaTargets -IssueWarningGB $warning -ProhibitSendGB $send -ProhibitSendReceiveGB $receive
    if (-not $check.IsValid) {
        $script:lblQuotaHint.Text = $check.Errors -join ' '
        $script:lblQuotaHint.ForeColor = [System.Drawing.Color]::Firebrick
    }
    elseif ($check.Warnings.Count -gt 0) {
        $script:lblQuotaHint.Text = $check.Warnings -join ' '
        $script:lblQuotaHint.ForeColor = [System.Drawing.Color]::DarkGoldenrod
    }
    else {
        $script:lblQuotaHint.Text = 'Ready. Issue warning ≤ prohibit send ≤ prohibit send/receive. Archive quota is not changed.'
        $script:lblQuotaHint.ForeColor = [System.Drawing.Color]::DarkGreen
    }
}

function Get-EditorQuota {
    param([string]$Text, [string]$Label)
    try {
        return ConvertTo-QuotaGigabytes $Text
    }
    catch {
        throw "$Label $($_.Exception.Message)"
    }
}

function Start-MailboxLookup {
    $identity = $script:txtUser.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($identity)) {
        Show-Info 'Enter a user principal name or email address.' -Icon Warning
        return
    }
    if (-not $script:exoConnected) {
        Show-Info 'Connect to Exchange Online first.' -Icon Warning
        return
    }

    Invoke-WithBusyCursor {
        try {
            Write-Activity "Looking up $identity..."
            $snapshot = Get-MailboxQuotaSnapshot -Identity $identity
            $canonical = Get-QuotaTargetIdentity -Snapshot $snapshot -RequestedIdentity $identity
            if ($canonical -and $canonical -ne $identity) {
                Write-Activity "Resolved $identity to $canonical."
            }
            $script:txtUser.Text = $canonical
            Show-MailboxSnapshot -Snapshot $snapshot -FillEditors $true
            $licenses = Get-AssignedLicenseDetails -UserPrincipalName $canonical
            Show-LicenseRecords -Records $licenses.Records -Summary $licenses.Summary
            if ($licenses.Error) {
                Write-Activity "$canonical licenses: $($licenses.Error)" 'WARN'
            }
            else {
                Write-Activity "$canonical licenses: $($licenses.Summary)" 'SUCCESS'
            }
            Write-Activity "Loaded $($snapshot.DisplayName) ($($snapshot.RecipientTypeDetails)). Warning $($script:detailValues['IssueWarning'].Text), send $($script:detailValues['ProhibitSend'].Text), send/receive $($script:detailValues['ProhibitSendReceive'].Text)." 'SUCCESS'
        }
        catch {
            Clear-MailboxDetails
            Write-Activity "Lookup failed for ${identity}: $($_.Exception.Message)" 'ERROR'
            Show-Info "Could not read that mailbox.`r`n`r`n$($_.Exception.Message)" -Icon Error
        }
    }
}

function Start-SingleApply {
    if (-not $script:exoConnected -or -not $script:mailboxLoaded) {
        Show-Info 'Look up a mailbox after connecting to Exchange Online.' -Icon Warning
        return
    }

    $whatIf = $script:chkWhatIfOne.Checked
    $revert = $script:chkRevert.Checked
    try {
        $warning = Get-EditorQuota $script:txtWarning.Text 'IssueWarningGB:'
        $send = Get-EditorQuota $script:txtSend.Text 'ProhibitSendGB:'
        $receive = Get-EditorQuota $script:txtReceive.Text 'ProhibitSendReceiveGB:'
    }
    catch {
        Show-Info $_.Exception.Message -Icon Warning
        return
    }

    if (-not $revert) {
        $check = Test-QuotaTargets -IssueWarningGB $warning -ProhibitSendGB $send -ProhibitSendReceiveGB $receive
        if (-not $check.IsValid) {
            Show-Info ($check.Errors -join "`r`n") -Icon Warning
            return
        }
    }

    $mode = if ($whatIf) { 'TEST MODE. No changes will be saved.' } else { 'LIVE MODE. This mailbox will be updated.' }
    $body = if ($revert) {
        "Revert $($script:loadedUpn) to license defaults?`r`n`r`n$mode"
    }
    else {
        "Update $($script:loadedUpn)?`r`n`r`nIssueWarningGB: $(Format-QuotaNumber $warning)`r`nProhibitSendGB: $(Format-QuotaNumber $send)`r`nProhibitSendReceiveGB: $(Format-QuotaNumber $receive)`r`n`r`n$mode"
    }
    if (-not (Show-Confirm $body)) { return }

    Invoke-WithBusyCursor {
        $result = Invoke-MailboxQuotaChange `
            -Identity $script:loadedUpn `
            -RequestedIssueWarningGB $warning `
            -RequestedProhibitSendGB $send `
            -RequestedProhibitSendReceiveGB $receive `
            -WhatIf:$whatIf `
            -RevertToDefaults:$revert `
            -LoadLicenses $true

        $level = if ($result.Status -eq 'Failed') { 'ERROR' } elseif ($result.Status -eq 'Updated' -or $result.Status -eq 'TestPassed') { 'SUCCESS' } else { 'WARN' }
        Write-Activity "$($script:loadedUpn) — $($result.Status): $($result.Message)" $level
        if ($result.LicenseSummary) {
            Show-LicenseRecords -Records $result.LicenseRecords -Summary $result.LicenseSummary
        }
        if ($result.Snapshot) {
            Show-MailboxSnapshot -Snapshot $result.Snapshot -FillEditors $false
        }
        if ($result.Status -eq 'Updated') {
            try {
                $fresh = Get-MailboxQuotaSnapshot -Identity $script:loadedUpn
                Show-MailboxSnapshot -Snapshot $fresh -FillEditors $true
            }
            catch {
                Write-Activity "The update finished, but the mailbox could not be read again: $($_.Exception.Message)" 'WARN'
            }
        }

        $icon = if ($result.Status -eq 'Failed') { 'Error' } elseif ($result.Status -eq 'Updated' -or $result.Status -eq 'TestPassed') { 'Information' } else { 'Warning' }
        Show-Info "$($result.Status): $($result.Message)" -Icon $icon
    }
}

function New-QuotaTable {
    $table = New-Object System.Data.DataTable
    foreach ($name in @(
        'DisplayName', 'UserPrincipalName', 'IssueWarningGB', 'ProhibitSendGB', 'ProhibitSendReceiveGB',
        'Validation', 'Result', 'Licenses', 'CurrentIssueWarningGB', 'CurrentProhibitSendGB',
        'CurrentProhibitSendReceiveGB', 'DatabaseDefaults'
    )) {
        [void]$table.Columns.Add($name, [string])
    }
    return $table
}

function Complete-GridEdit {
    if ($script:grid) {
        [void]$script:grid.EndEdit()
        if ($script:dataTable) {
            $manager = $script:grid.BindingContext[$script:dataTable]
            if ($manager) { $manager.EndCurrentEdit() }
        }
    }
}

function Get-VisibleDataRows {
    Complete-GridEdit
    $rows = foreach ($view in @($script:dataTable.DefaultView)) {
        $view.Row
    }
    return @($rows | Where-Object { $null -ne $_ })
}

function Update-RecordCount {
    if (-not $script:dataTable -or -not $script:lblRecords) { return }
    $total = $script:dataTable.Rows.Count
    $visible = @($script:dataTable.DefaultView).Count
    if ($visible -ne $total) {
        $script:lblRecords.Text = "Records: $visible of $total"
    }
    else {
        $script:lblRecords.Text = "Records: $total"
    }
}

function Update-GridRowValidation {
    param($DataRow)

    if ([string]::IsNullOrWhiteSpace([string]$DataRow['UserPrincipalName'])) {
        $DataRow['Validation'] = 'Error: No user identity in the mapped identity column.'
        return
    }

    try {
        $warning = ConvertTo-QuotaGigabytes ([string]$DataRow['IssueWarningGB'])
        $send = ConvertTo-QuotaGigabytes ([string]$DataRow['ProhibitSendGB'])
        $receive = ConvertTo-QuotaGigabytes ([string]$DataRow['ProhibitSendReceiveGB'])
    }
    catch {
        $DataRow['Validation'] = "Error: $($_.Exception.Message)"
        return
    }

    $hasValue = ($null -ne $warning) -or ($null -ne $send) -or ($null -ne $receive)
    $DataRow['Validation'] = Format-QuotaValidationMessage `
        -ParseErrors @() `
        -HasQuotaValue $hasValue `
        -UsedQuotaFallback $false `
        -IssueWarningGB $warning `
        -ProhibitSendGB $send `
        -ProhibitSendReceiveGB $receive
}

function Get-SelectedMapValue {
    param($Combo)
    if ($null -eq $Combo -or $Combo.SelectedIndex -le 0) { return $null }
    return [string]$Combo.SelectedItem
}

function Get-MapFromCombos {
    return [pscustomobject]@{
        Identity              = (Get-SelectedMapValue $script:cboIdentity)
        DisplayName           = $null
        ProhibitSendReceiveGB = (Get-SelectedMapValue $script:cboReceive)
        ProhibitSendGB        = (Get-SelectedMapValue $script:cboSend)
        IssueWarningGB        = (Get-SelectedMapValue $script:cboWarning)
        QuotaInGB             = (Get-SelectedMapValue $script:cboQuota)
    }
}

function Get-MapSnapshot {
    return [pscustomobject]@{
        Identity = $script:cboIdentity.SelectedIndex
        Receive  = $script:cboReceive.SelectedIndex
        Send     = $script:cboSend.SelectedIndex
        Warning  = $script:cboWarning.SelectedIndex
        Quota    = $script:cboQuota.SelectedIndex
    }
}

function Restore-MapSnapshot {
    param($Snapshot)
    if ($null -eq $Snapshot) { return }
    $script:suppressMapEvents = $true
    try {
        $script:cboIdentity.SelectedIndex = $Snapshot.Identity
        $script:cboReceive.SelectedIndex = $Snapshot.Receive
        $script:cboSend.SelectedIndex = $Snapshot.Send
        $script:cboWarning.SelectedIndex = $Snapshot.Warning
        $script:cboQuota.SelectedIndex = $Snapshot.Quota
    }
    finally {
        $script:suppressMapEvents = $false
    }
}

function Select-MapCombo {
    param($Combo, $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        $Combo.SelectedIndex = 0
        return
    }
    $index = $Combo.Items.IndexOf($Value)
    if ($index -ge 0) { $Combo.SelectedIndex = $index } else { $Combo.SelectedIndex = 0 }
}

function Set-MappingCombos {
    param([string[]]$Headers, $DetectedMap)

    $script:suppressMapEvents = $true
    try {
        foreach ($combo in @($script:cboIdentity, $script:cboReceive, $script:cboSend, $script:cboWarning, $script:cboQuota)) {
            $combo.Items.Clear()
            [void]$combo.Items.Add('(not mapped)')
            foreach ($header in $Headers) {
                [void]$combo.Items.Add($header)
            }
        }
        # Display name is detected for the grid, but it is not one of the quota dropdowns.
        Select-MapCombo $script:cboIdentity $DetectedMap.Identity
        Select-MapCombo $script:cboReceive $DetectedMap.ProhibitSendReceiveGB
        Select-MapCombo $script:cboSend $DetectedMap.ProhibitSendGB
        Select-MapCombo $script:cboWarning $DetectedMap.IssueWarningGB
        Select-MapCombo $script:cboQuota $DetectedMap.QuotaInGB
    }
    finally {
        $script:suppressMapEvents = $false
    }
}

function Update-MapStatus {
    $map = Get-MapFromCombos
    $show = {
        param($Value)
        if ([string]::IsNullOrWhiteSpace($Value)) { return '(not mapped)' }
        return $Value
    }
    $script:lblMap.Text = "Identity: $(& $show $map.Identity)    ProhibitSendReceiveGB: $(& $show $map.ProhibitSendReceiveGB)    ProhibitSendGB: $(& $show $map.ProhibitSendGB)    IssueWarningGB: $(& $show $map.IssueWarningGB)    QuotaInGB fallback: $(& $show $map.QuotaInGB)"
}

function Update-GridFromSource {
    if (-not $script:dataTable) { return }
    $map = Get-MapFromCombos
    # Keep a detected display-name column even though it has no dropdown.
    if ($script:detectedDisplayName) {
        $map = [pscustomobject]@{
            Identity              = $map.Identity
            DisplayName           = $script:detectedDisplayName
            ProhibitSendReceiveGB = $map.ProhibitSendReceiveGB
            ProhibitSendGB        = $map.ProhibitSendGB
            IssueWarningGB        = $map.IssueWarningGB
            QuotaInGB             = $map.QuotaInGB
        }
    }

    $script:dataTable.Rows.Clear()
    foreach ($source in @($script:sourceRows)) {
        $resolved = Resolve-MailboxQuotaRow -Row $source -ColumnMap $map
        $validation = Format-QuotaValidationMessage `
            -ParseErrors $resolved.Errors `
            -HasQuotaValue $resolved.HasQuotaValue `
            -UsedQuotaFallback $resolved.UsedQuotaFallback `
            -IssueWarningGB $resolved.IssueWarningGB `
            -ProhibitSendGB $resolved.ProhibitSendGB `
            -ProhibitSendReceiveGB $resolved.ProhibitSendReceiveGB
        $row = $script:dataTable.NewRow()
        $row['DisplayName'] = $resolved.DisplayName
        $row['UserPrincipalName'] = $resolved.Identity
        $row['IssueWarningGB'] = Format-QuotaNumber $resolved.IssueWarningGB
        $row['ProhibitSendGB'] = Format-QuotaNumber $resolved.ProhibitSendGB
        $row['ProhibitSendReceiveGB'] = Format-QuotaNumber $resolved.ProhibitSendReceiveGB
        $row['Validation'] = $validation
        $row['Result'] = ''
        $row['Licenses'] = ''
        $row['CurrentIssueWarningGB'] = ''
        $row['CurrentProhibitSendGB'] = ''
        $row['CurrentProhibitSendReceiveGB'] = ''
        $row['DatabaseDefaults'] = ''
        [void]$script:dataTable.Rows.Add($row)
    }
    Update-MapStatus
    Update-RecordCount
    $script:gridEdited = $false
    $script:mapSnapshot = Get-MapSnapshot
    if (-not $script:busy) { Set-UiBusy $false }
}

function Update-MappingFromUi {
    if ($script:suppressMapEvents) { return }
    if (@($script:sourceRows).Count -eq 0) {
        Update-MapStatus
        return
    }
    if ($script:gridEdited -and $script:mapSnapshot) {
        $ok = Show-Confirm 'Reapplying the column mapping replaces quota edits in the grid. Continue?'
        if (-not $ok) {
            Restore-MapSnapshot $script:mapSnapshot
            return
        }
    }
    Update-GridFromSource
}

function Import-CsvIntoGrid {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $dialog.Title = 'Select a mailbox quota CSV'
    if ($dialog.ShowDialog($script:form) -ne [System.Windows.Forms.DialogResult]::OK) { return }

    try {
        Write-Activity "Reading $($dialog.FileName)..."
        $imported = Import-QuotaCsv -Path $dialog.FileName
        $script:sourceRows = @($imported.Rows)
        $script:sourceHeaders = @($imported.Headers)
        $script:sourcePath = $imported.Path
        $script:sourceDelimiter = $imported.Delimiter
        $script:detectedDisplayName = $imported.ColumnMap.DisplayName
        Set-MappingCombos -Headers $script:sourceHeaders -DetectedMap $imported.ColumnMap
        Update-GridFromSource

        $map = $imported.ColumnMap
        Write-Activity "Loaded $($script:sourceRows.Count) records ($($imported.Delimiter)). Identity [$($map.Identity)]; ProhibitSendReceiveGB [$($map.ProhibitSendReceiveGB)]; ProhibitSendGB [$($map.ProhibitSendGB)]; IssueWarningGB [$($map.IssueWarningGB)]; QuotaInGB [$($map.QuotaInGB)]." 'SUCCESS'

        $warnings = @()
        if ([string]::IsNullOrWhiteSpace($map.Identity)) {
            $warnings += "No identity column was detected.`r`nChoose it in the Identity dropdown.`r`n`r`nHeaders found: $($script:sourceHeaders -join ', ')"
        }
        $hasQuota = $map.ProhibitSendReceiveGB -or $map.ProhibitSendGB -or $map.IssueWarningGB -or $map.QuotaInGB
        if (-not $hasQuota) {
            $warnings += "No quota column was detected.`r`nMap ProhibitSendReceiveGB, ProhibitSendGB, IssueWarningGB, or the QuotaInGB fallback."
        }
        if ($warnings.Count -gt 0) {
            Show-Info ($warnings -join "`r`n`r`n") -Icon Warning
        }
    }
    catch {
        Write-Activity "CSV import failed: $($_.Exception.Message)" 'ERROR'
        Show-Info "Could not import that CSV.`r`n`r`n$($_.Exception.Message)" -Icon Error
    }
}

function Export-QuotaRows {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Rows
    )
    $csv = @($Rows | ConvertTo-Csv -NoTypeInformation)
    $encoding = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllLines($Path, $csv, $encoding)
}

function Export-TemplateCsv {
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = 'CSV files (*.csv)|*.csv'
    $dialog.FileName = 'mailbox-quota-template.csv'
    $dialog.Title = 'Save template CSV'
    if ($dialog.ShowDialog($script:form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
    try {
        Export-QuotaRows -Path $dialog.FileName -Rows (Get-QuotaCsvTemplateRows)
        Write-Activity "Template saved to $($dialog.FileName)" 'SUCCESS'
        Show-Info "Template saved to:`r`n$($dialog.FileName)`r`n`r`nHeaders can also be names such as Email, Prohibit Send Receive (GB), Prohibit Send (GB), and Issue Warning (GB). A QuotaInGB column is optional."
    }
    catch {
        Write-Activity "Template export failed: $($_.Exception.Message)" 'ERROR'
        Show-Info $_.Exception.Message -Icon Error
    }
}

function Export-GridCsv {
    Complete-GridEdit
    if ($script:dataTable.Rows.Count -eq 0) {
        Show-Info 'There are no rows to export.' -Icon Warning
        return
    }
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = 'CSV files (*.csv)|*.csv'
    $dialog.FileName = 'mailbox-quota-results.csv'
    $dialog.Title = 'Export grid'
    if ($dialog.ShowDialog($script:form) -ne [System.Windows.Forms.DialogResult]::OK) { return }

    try {
        $rows = foreach ($row in $script:dataTable.Rows) {
            [pscustomobject]@{
                DisplayName                 = [string]$row['DisplayName']
                UserPrincipalName           = [string]$row['UserPrincipalName']
                IssueWarningGB              = [string]$row['IssueWarningGB']
                ProhibitSendGB              = [string]$row['ProhibitSendGB']
                ProhibitSendReceiveGB       = [string]$row['ProhibitSendReceiveGB']
                Licenses                    = [string]$row['Licenses']
                CurrentIssueWarningGB       = [string]$row['CurrentIssueWarningGB']
                CurrentProhibitSendGB       = [string]$row['CurrentProhibitSendGB']
                CurrentProhibitSendReceiveGB = [string]$row['CurrentProhibitSendReceiveGB']
                DatabaseDefaults            = [string]$row['DatabaseDefaults']
                Validation                  = [string]$row['Validation']
                Result                      = [string]$row['Result']
            }
        }
        Export-QuotaRows -Path $dialog.FileName -Rows $rows
        Write-Activity "Exported $($script:dataTable.Rows.Count) rows to $($dialog.FileName)" 'SUCCESS'
    }
    catch {
        Write-Activity "Grid export failed: $($_.Exception.Message)" 'ERROR'
        Show-Info $_.Exception.Message -Icon Error
    }
}

function Remove-SelectedRows {
    Complete-GridEdit
    $selected = @($script:grid.SelectedRows)
    if ($selected.Count -eq 0) {
        Show-Info 'Select one or more rows to remove.' -Icon Warning
        return
    }
    $dataRows = foreach ($gridRow in $selected) {
        if ($gridRow.DataBoundItem) { $gridRow.DataBoundItem.Row }
    }
    foreach ($dataRow in @($dataRows)) {
        if ($dataRow) { $script:dataTable.Rows.Remove($dataRow) }
    }
    Update-RecordCount
    Write-Activity "Removed $(@($dataRows).Count) row(s) from the grid."
    if (-not $script:busy) { Set-UiBusy $false }
}

function Open-SelectedMailbox {
    $selected = @($script:grid.SelectedRows | Where-Object { $_.DataBoundItem })
    if ($selected.Count -eq 0) {
        Show-Info 'Select a row first.' -Icon Warning
        return
    }
    $upn = [string]$selected[0].DataBoundItem.Row['UserPrincipalName']
    if ([string]::IsNullOrWhiteSpace($upn)) {
        Show-Info 'The selected row has no user identity.' -Icon Warning
        return
    }
    $script:tabs.SelectedIndex = 0
    $script:txtUser.Text = $upn
    Start-MailboxLookup
}

function Write-ChangeToRow {
    param($DataRow, $Result)

    if ($Result.Snapshot) {
        if ([string]::IsNullOrWhiteSpace([string]$DataRow['DisplayName']) -and $Result.Snapshot.DisplayName) {
            $DataRow['DisplayName'] = [string]$Result.Snapshot.DisplayName
        }
        $DataRow['CurrentIssueWarningGB'] = Format-QuotaNumber $Result.Snapshot.IssueWarningGB
        $DataRow['CurrentProhibitSendGB'] = Format-QuotaNumber $Result.Snapshot.ProhibitSendGB
        $DataRow['CurrentProhibitSendReceiveGB'] = Format-QuotaNumber $Result.Snapshot.ProhibitSendReceiveGB
        $DataRow['DatabaseDefaults'] = if ($Result.Snapshot.UseDatabaseQuotaDefaults) { 'License defaults' } else { 'Custom' }
    }
    if ($Result.LicenseSummary) {
        $DataRow['Licenses'] = [string]$Result.LicenseSummary
    }

    switch ($Result.Status) {
        'Preview'    { $DataRow['Validation'] = [string]$Result.Message; $DataRow['Result'] = '' }
        'Updated'    { $DataRow['Result'] = "Updated: $($Result.Message)" }
        'TestPassed' { $DataRow['Result'] = "Test passed: $($Result.Message)" }
        'Unchanged'  { $DataRow['Result'] = "Unchanged: $($Result.Message)" }
        'Failed'     { $DataRow['Result'] = "Failed: $($Result.Message)" }
        'Skipped'    { $DataRow['Result'] = "Skipped: $($Result.Message)" }
        default      { $DataRow['Result'] = "$($Result.Status): $($Result.Message)" }
    }
}

function Invoke-BulkQuotaRun {
    param([bool]$PreviewOnly)

    if (-not $script:exoConnected) {
        Show-Info 'Connect to Exchange Online first.' -Icon Warning
        return
    }

    foreach ($row in (Get-VisibleDataRows)) {
        Update-GridRowValidation $row
    }
    [System.Windows.Forms.Application]::DoEvents()

    $rows = @(Get-VisibleDataRows)
    if ($rows.Count -eq 0) {
        Show-Info 'There are no visible rows to process. Clear the filter or import a CSV.' -Icon Warning
        return
    }

    $whatIf = $script:chkWhatIfBulk.Checked
    if (-not $PreviewOnly) {
        $errorCount = @($rows | Where-Object { [string]$_['Validation'] -like 'Error*' }).Count
        $mode = if ($whatIf) { 'TEST MODE. No changes will be saved.' } else { 'LIVE MODE. Mailboxes will be updated.' }
        $filterNote = ''
        if ($script:dataTable.Rows.Count -ne $rows.Count) {
            $filterNote = "`r`nThe filter is on, so only visible rows are included ($($rows.Count) of $($script:dataTable.Rows.Count))."
        }
        $skipNote = ''
        if ($errorCount -gt 0) {
            $skipNote = "`r`n$errorCount row(s) already have validation errors and will be skipped."
        }
        $prompt = "Process $($rows.Count) mailbox row(s)?`r`n`r`n$mode$filterNote$skipNote"
        if (-not (Show-Confirm $prompt)) { return }
    }

    Invoke-WithBusyCursor {
        if (-not $script:licenseConnected) {
            Write-Activity 'License service is not connected. Quotas can still be changed. Connect for licenses to fill the User licenses column.' 'WARN'
        }
        $counts = @{
            Updated = 0; TestPassed = 0; Unchanged = 0; Failed = 0; Skipped = 0; Preview = 0
        }
        $script:progress.Value = 0
        $script:progress.Maximum = [Math]::Max($rows.Count, 1)
        $index = 0
        $actionName = if ($PreviewOnly) { 'Loading' } else { 'Updating' }

        foreach ($row in $rows) {
            if ($script:cancelRequested) {
                Write-Activity 'Stopped at your request.' 'WARN'
                break
            }

            $index++
            $identity = [string]$row['UserPrincipalName']
            $script:progress.Value = [Math]::Min($index, $script:progress.Maximum)
            Write-Activity "$actionName $identity ($index/$($rows.Count))"
            [System.Windows.Forms.Application]::DoEvents()

            if ([string]$row['Validation'] -like 'Error*') {
                $row['Result'] = "Skipped: $([string]$row['Validation'])"
                $counts.Skipped++
                continue
            }

            try {
                $warning = ConvertTo-QuotaGigabytes ([string]$row['IssueWarningGB'])
                $send = ConvertTo-QuotaGigabytes ([string]$row['ProhibitSendGB'])
                $receive = ConvertTo-QuotaGigabytes ([string]$row['ProhibitSendReceiveGB'])
            }
            catch {
                $row['Result'] = "Skipped: $($_.Exception.Message)"
                $counts.Skipped++
                Write-Activity "$identity skipped: $($_.Exception.Message)" 'WARN'
                continue
            }

            $result = Invoke-MailboxQuotaChange `
                -Identity $identity `
                -RequestedIssueWarningGB $warning `
                -RequestedProhibitSendGB $send `
                -RequestedProhibitSendReceiveGB $receive `
                -WhatIf:$whatIf `
                -RevertToDefaults:$false `
                -LoadLicenses:([bool]$script:licenseConnected) `
                -PreviewOnly:$PreviewOnly

            Write-ChangeToRow -DataRow $row -Result $result
            if ($counts.ContainsKey($result.Status)) { $counts[$result.Status]++ } else { $counts.Failed++ }
            $level = if ($result.Status -eq 'Failed') { 'ERROR' } elseif ($result.Status -eq 'Updated' -or $result.Status -eq 'TestPassed') { 'SUCCESS' } else { 'INFO' }
            Write-Activity "$identity — $($result.Status): $($result.Message)" $level
            if ($result.LicenseSummary -and $result.LicenseSummary -ne 'License service not connected') {
                Write-Activity "$identity licenses: $($result.LicenseSummary)"
            }
            $script:grid.Refresh()
            [System.Windows.Forms.Application]::DoEvents()
        }

        $summary = if ($PreviewOnly) {
            "Preview finished. Loaded: $($counts.Preview). Failed: $($counts.Failed). Skipped: $($counts.Skipped)."
        }
        else {
            $text = "Finished. Updated: $($counts.Updated). Test passed: $($counts.TestPassed). Unchanged: $($counts.Unchanged). Failed: $($counts.Failed). Skipped: $($counts.Skipped)."
            if ($whatIf) { $text += ' Test mode saved nothing.' }
            $text
        }
        Write-Activity $summary $(if ($counts.Failed -gt 0) { 'WARN' } else { 'SUCCESS' })
        Show-Info $summary -Icon $(if ($counts.Failed -gt 0) { 'Warning' } else { 'Information' })
    }
}

function Save-ActivityLog {
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = 'Text files (*.txt)|*.txt|Log files (*.log)|*.log'
    $dialog.FileName = "quota-manager-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    if ($dialog.ShowDialog($script:form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
    try {
        $encoding = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($dialog.FileName, $script:txtLog.Text, $encoding)
        Write-Activity "Log saved to $($dialog.FileName)" 'SUCCESS'
    }
    catch {
        Show-Info $_.Exception.Message -Icon Error
    }
}

function Get-HelpText {
    return @"
Exchange Online Quota Manager

Three mailbox settings, in gigabytes:

  IssueWarningGB
    When the mailbox warns the user. This is IssueWarningQuota.

  ProhibitSendGB
    The mailbox can still receive mail, but the user can no longer send.
    This is ProhibitSendQuota.

  ProhibitSendReceiveGB
    The mailbox can no longer send or receive. This is ProhibitSendReceiveQuota.

Exchange requires:
  Issue warning  <=  Prohibit send  <=  Prohibit send/receive

Saving custom values turns off database quota defaults for that mailbox.
Archive quotas are not changed. Primary mailbox quota is 50 GB on Exchange
Online Plan 1 and 100 GB on Plan 2. Larger numbers are sent only if you
confirm them, and Exchange may reject them.

Single mailbox
  Connect to Exchange Online, enter a user principal name or email address,
  and choose Look up. The current quotas and every assigned license are shown.
  Edit the three values and apply them. Blank fields keep the current value.
  Test mode checks the mailbox and does not save.

Bulk CSV
  The dropdowns choose which CSV header is used for each setting. Headers are
  detected automatically. Spaces, capitalization, and punctuation are ignored,
  so "Prohibit Send Receive (GB)" matches ProhibitSendReceiveGB. Change a
  dropdown if the wrong column was selected.

  Identity headers include UserPrincipalName, UPN, Email, PrimarySmtpAddress,
  and Mail.

  QuotaInGB is used only when the three quota columns are empty for that row.
  It sets prohibit send and prohibit send/receive to that size. When the size
  is above 1 GB, the warning is set 1 GB lower.

  You can edit the three quota cells in the grid before applying. The filter
  limits the rows that are processed. Export grid writes the licenses, current
  quotas, and results.

Licenses
  Connect for licenses to read every license on the account. Microsoft Graph
  is used when it is installed and requests User.Read.All. AzureAD or MSOnline
  is used when Graph is not installed.

  Each license shows the product name, SKU part number, SKU id, and service
  plans. Exchange Online Plan 1 or Plan 2 appears with the plans inside a
  suite such as Microsoft 365 E3. Disabled plans are listed separately.
  A shared mailbox often has no user license.

Install
  Install-Module ExchangeOnlineManagement -Scope CurrentUser
  Install-Module Microsoft.Graph -Scope CurrentUser
"@
}

function New-PrimaryButton {
    param([string]$Text, [int]$X, [int]$Y, [int]$Width, [int]$Height = 32)
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.Size = New-Object System.Drawing.Size($Width, $Height)
    $button.FlatStyle = 'Flat'
    $button.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $button.ForeColor = [System.Drawing.Color]::White
    $button.FlatAppearance.BorderSize = 0
    return $button
}

function New-StandardButton {
    param([string]$Text, [int]$X, [int]$Y, [int]$Width, [int]$Height = 32)
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.Size = New-Object System.Drawing.Size($Width, $Height)
    return $button
}

function Enable-ControlDoubleBuffer {
    param($Control)
    $property = $Control.GetType().GetProperty('DoubleBuffered', [System.Reflection.BindingFlags]'Instance, NonPublic')
    if ($property) { $property.SetValue($Control, $true, $null) }
}

function Build-MainForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Exchange Online Quota Manager $($script:AppVersion)"
    $form.Size = New-Object System.Drawing.Size(1280, 860)
    $form.MinimumSize = New-Object System.Drawing.Size(1100, 740)
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.BackColor = [System.Drawing.Color]::FromArgb(245, 246, 248)
    $script:form = $form

    $menu = New-Object System.Windows.Forms.MenuStrip
    $fileMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $fileMenu.Text = '&File'
    $importItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $importItem.Text = '&Import CSV...'
    $importItem.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::O
    $templateItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $templateItem.Text = 'Export &template CSV...'
    $exportItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $exportItem.Text = '&Export grid...'
    $exitItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $exitItem.Text = 'E&xit'
    [void]$fileMenu.DropDownItems.Add($importItem)
    [void]$fileMenu.DropDownItems.Add($templateItem)
    [void]$fileMenu.DropDownItems.Add($exportItem)
    [void]$fileMenu.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    [void]$fileMenu.DropDownItems.Add($exitItem)

    $connectionMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $connectionMenu.Text = '&Connection'
    $connectExoItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $connectExoItem.Text = 'Connect to &Exchange Online'
    $disconnectExoItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $disconnectExoItem.Text = '&Disconnect Exchange Online'
    $connectLicenseItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $connectLicenseItem.Text = 'Connect for &licenses'
    $disconnectLicenseItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $disconnectLicenseItem.Text = 'Disconnect licenses'
    [void]$connectionMenu.DropDownItems.Add($connectExoItem)
    [void]$connectionMenu.DropDownItems.Add($disconnectExoItem)
    [void]$connectionMenu.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    [void]$connectionMenu.DropDownItems.Add($connectLicenseItem)
    [void]$connectionMenu.DropDownItems.Add($disconnectLicenseItem)

    $helpMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $helpMenu.Text = '&Help'
    $helpItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $helpItem.Text = '&How quotas and licenses work'
    $aboutItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $aboutItem.Text = '&About'
    [void]$helpMenu.DropDownItems.Add($helpItem)
    [void]$helpMenu.DropDownItems.Add($aboutItem)
    [void]$menu.Items.Add($fileMenu)
    [void]$menu.Items.Add($connectionMenu)
    [void]$menu.Items.Add($helpMenu)
    $form.MainMenuStrip = $menu

    $status = New-Object System.Windows.Forms.StatusStrip
    $script:statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $script:statusLabel.Spring = $true
    $script:statusLabel.TextAlign = 'MiddleLeft'
    $script:statusLabel.Text = 'Ready'
    $script:exoStatus = New-Object System.Windows.Forms.ToolStripStatusLabel
    $script:exoStatus.Text = 'Exchange: Not connected'
    $script:exoStatus.ForeColor = [System.Drawing.Color]::Firebrick
    $script:exoStatus.BorderSides = 'Left'
    $script:licenseStatus = New-Object System.Windows.Forms.ToolStripStatusLabel
    $script:licenseStatus.Text = 'Licenses: Not connected'
    $script:licenseStatus.ForeColor = [System.Drawing.Color]::Firebrick
    $script:licenseStatus.BorderSides = 'Left'
    [void]$status.Items.Add($script:statusLabel)
    [void]$status.Items.Add($script:exoStatus)
    [void]$status.Items.Add($script:licenseStatus)

    $connectionPanel = New-Object System.Windows.Forms.Panel
    $connectionPanel.Dock = 'Top'
    $connectionPanel.Height = 118
    $connectionPanel.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 4)
    $connectionGroup = New-Object System.Windows.Forms.GroupBox
    $connectionGroup.Text = 'Connections'
    $connectionGroup.Dock = 'Fill'
    $connectionPanel.Controls.Add($connectionGroup)

    $script:btnConnect = New-PrimaryButton 'Connect to Exchange Online' 12 24 210
    $script:btnDisconnectExo = New-StandardButton 'Disconnect' 230 24 110
    $script:btnDisconnectExo.Enabled = $false
    $script:lblExo = New-Object System.Windows.Forms.Label
    $script:lblExo.Text = 'Not connected'
    $script:lblExo.Location = New-Object System.Drawing.Point(352, 30)
    $script:lblExo.Size = New-Object System.Drawing.Size(760, 22)
    $script:lblExo.ForeColor = [System.Drawing.Color]::Firebrick
    $script:lblExo.AutoEllipsis = $true

    $script:btnConnectLicense = New-StandardButton 'Connect for licenses' 12 64 210
    $script:btnDisconnectLicense = New-StandardButton 'Disconnect' 230 64 110
    $script:btnDisconnectLicense.Enabled = $false
    $script:lblLicense = New-Object System.Windows.Forms.Label
    $script:lblLicense.Text = 'Not connected — user licenses are not loaded'
    $script:lblLicense.Location = New-Object System.Drawing.Point(352, 70)
    $script:lblLicense.Size = New-Object System.Drawing.Size(760, 22)
    $script:lblLicense.ForeColor = [System.Drawing.Color]::Firebrick
    $script:lblLicense.AutoEllipsis = $true

    $connectionGroup.Controls.AddRange(@(
        $script:btnConnect, $script:btnDisconnectExo, $script:lblExo,
        $script:btnConnectLicense, $script:btnDisconnectLicense, $script:lblLicense
    ))

    $script:tabs = New-Object System.Windows.Forms.TabControl
    $script:tabs.Dock = 'Fill'

    # Single mailbox tab
    $mailboxTab = New-Object System.Windows.Forms.TabPage
    $mailboxTab.Text = 'Single mailbox'
    $mailboxTab.Padding = New-Object System.Windows.Forms.Padding(8)
    $mailboxTab.UseVisualStyleBackColor = $false
    $mailboxTab.BackColor = [System.Drawing.Color]::FromArgb(245, 246, 248)

    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'
    $split.SplitterWidth = 6
    $script:split = $split
    $mailboxTab.Controls.Add($split)

    $lookup = New-Object System.Windows.Forms.GroupBox
    $lookup.Text = 'Find mailbox'
    $lookup.Dock = 'Top'
    $lookup.Height = 84
    $userLabel = New-Object System.Windows.Forms.Label
    $userLabel.Text = 'User principal name or email'
    $userLabel.Location = New-Object System.Drawing.Point(12, 20)
    $userLabel.AutoSize = $true
    $script:txtUser = New-Object System.Windows.Forms.TextBox
    $script:txtUser.Location = New-Object System.Drawing.Point(12, 42)
    $script:txtUser.Size = New-Object System.Drawing.Size(360, 24)
    $script:txtUser.Anchor = 'Top, Left, Right'
    $script:btnLookup = New-PrimaryButton 'Look up' 382 38 110
    $script:btnLookup.Anchor = 'Top, Right'
    $script:btnLookup.Enabled = $false
    $lookup.Controls.AddRange(@($userLabel, $script:txtUser, $script:btnLookup))

    $quota = New-Object System.Windows.Forms.GroupBox
    $quota.Text = 'Quota settings (GB)'
    $quota.Dock = 'Top'
    $quota.Height = 292
    $script:lblQuotaHint = New-Object System.Windows.Forms.Label
    $script:lblQuotaHint.Text = 'Look up a mailbox, then edit IssueWarningGB, ProhibitSendGB, and ProhibitSendReceiveGB.'
    $script:lblQuotaHint.Location = New-Object System.Drawing.Point(12, 22)
    $script:lblQuotaHint.Size = New-Object System.Drawing.Size(470, 36)
    $script:lblQuotaHint.ForeColor = [System.Drawing.Color]::DimGray

    $script:txtWarning = New-Object System.Windows.Forms.TextBox
    $script:txtSend = New-Object System.Windows.Forms.TextBox
    $script:txtReceive = New-Object System.Windows.Forms.TextBox
    $script:lblCurrentWarning = New-Object System.Windows.Forms.Label
    $script:lblCurrentSend = New-Object System.Windows.Forms.Label
    $script:lblCurrentReceive = New-Object System.Windows.Forms.Label
    $quotaRows = @(
        @{ Label = 'IssueWarningGB'; Box = $script:txtWarning; Current = $script:lblCurrentWarning; Y = 66 }
        @{ Label = 'ProhibitSendGB'; Box = $script:txtSend; Current = $script:lblCurrentSend; Y = 100 }
        @{ Label = 'ProhibitSendReceiveGB'; Box = $script:txtReceive; Current = $script:lblCurrentReceive; Y = 134 }
    )
    foreach ($quotaRow in $quotaRows) {
        $caption = New-Object System.Windows.Forms.Label
        $caption.Text = $quotaRow.Label
        $caption.Location = New-Object System.Drawing.Point(12, ($quotaRow.Y + 4))
        $caption.Size = New-Object System.Drawing.Size(180, 22)
        $caption.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
        $quotaRow.Box.Location = New-Object System.Drawing.Point(196, $quotaRow.Y)
        $quotaRow.Box.Size = New-Object System.Drawing.Size(80, 24)
        $quotaRow.Current.Text = 'Current: -'
        $quotaRow.Current.Location = New-Object System.Drawing.Point(286, ($quotaRow.Y + 4))
        $quotaRow.Current.Size = New-Object System.Drawing.Size(190, 22)
        $quotaRow.Current.AutoEllipsis = $true
        $quota.Controls.Add($caption)
        $quota.Controls.Add($quotaRow.Box)
        $quota.Controls.Add($quotaRow.Current)
    }

    $script:chkRevert = New-Object System.Windows.Forms.CheckBox
    $script:chkRevert.Text = 'Revert this mailbox to license defaults'
    $script:chkRevert.Location = New-Object System.Drawing.Point(12, 172)
    $script:chkRevert.Size = New-Object System.Drawing.Size(320, 24)
    $script:chkWhatIfOne = New-Object System.Windows.Forms.CheckBox
    $script:chkWhatIfOne.Text = 'Test mode (no changes saved)'
    $script:chkWhatIfOne.Location = New-Object System.Drawing.Point(12, 248)
    $script:chkWhatIfOne.Size = New-Object System.Drawing.Size(220, 24)
    $script:chkWhatIfOne.Checked = $true
    $script:btnApplyOne = New-PrimaryButton 'Apply to this mailbox' 240 242 180
    $script:btnApplyOne.Enabled = $false
    $quota.Controls.AddRange(@($script:lblQuotaHint, $script:chkRevert, $script:chkWhatIfOne, $script:btnApplyOne))

    $licenseGroup = New-Object System.Windows.Forms.GroupBox
    $licenseGroup.Text = 'User licenses'
    $licenseGroup.Dock = 'Fill'
    $script:btnCopyLicenses = New-StandardButton 'Copy summary' 12 18 120 26
    $script:btnCopyLicenses.Dock = 'Bottom'
    $script:lblLicenseCount = New-Object System.Windows.Forms.Label
    $script:lblLicenseCount.Text = 'Look up a mailbox to see every license assigned to it.'
    $script:lblLicenseCount.Dock = 'Top'
    $script:lblLicenseCount.Height = 36
    $script:lblLicenseCount.Padding = New-Object System.Windows.Forms.Padding(8, 8, 8, 0)
    $script:licenseList = New-Object System.Windows.Forms.ListView
    $script:licenseList.Dock = 'Fill'
    $script:licenseList.View = 'Details'
    $script:licenseList.FullRowSelect = $true
    $script:licenseList.GridLines = $true
    $script:licenseList.HideSelection = $false
    $script:licenseList.ShowItemToolTips = $true
    [void]$script:licenseList.Columns.Add('Product', 210)
    [void]$script:licenseList.Columns.Add('SKU', 170)
    [void]$script:licenseList.Columns.Add('SKU id', 250)
    [void]$script:licenseList.Columns.Add('Enabled service plans', 360)
    [void]$script:licenseList.Columns.Add('Disabled service plans', 240)
    $licenseGroup.Controls.Add($script:btnCopyLicenses)
    $licenseGroup.Controls.Add($script:lblLicenseCount)
    $licenseGroup.Controls.Add($script:licenseList)

    $split.Panel1.Controls.Add($lookup)
    $split.Panel1.Controls.Add($quota)
    $split.Panel1.Controls.Add($licenseGroup)

    $detailGroup = New-Object System.Windows.Forms.GroupBox
    $detailGroup.Text = 'Current mailbox'
    $detailGroup.Dock = 'Fill'
    $detailTable = New-Object System.Windows.Forms.TableLayoutPanel
    $detailTable.Dock = 'Fill'
    $detailTable.ColumnCount = 2
    $detailTable.Padding = New-Object System.Windows.Forms.Padding(8)
    $detailTable.ColumnStyles.Clear()
    [void]$detailTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 180)))
    [void]$detailTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $script:detailValues = @{}
    $detailFields = @(
        @{ Key = 'DisplayName'; Caption = 'Display name' }
        @{ Key = 'UserPrincipalName'; Caption = 'User principal name' }
        @{ Key = 'PrimarySmtpAddress'; Caption = 'Primary SMTP' }
        @{ Key = 'RecipientType'; Caption = 'Recipient type' }
        @{ Key = 'ArchiveStatus'; Caption = 'Archive status' }
        @{ Key = 'DatabaseDefaults'; Caption = 'Quota source' }
        @{ Key = 'IssueWarning'; Caption = 'IssueWarningGB' }
        @{ Key = 'ProhibitSend'; Caption = 'ProhibitSendGB' }
        @{ Key = 'ProhibitSendReceive'; Caption = 'ProhibitSendReceiveGB' }
    )
    $detailTable.RowCount = $detailFields.Count
    $detailTable.RowStyles.Clear()
    for ($i = 0; $i -lt $detailFields.Count; $i++) {
        [void]$detailTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 32)))
        $caption = New-Object System.Windows.Forms.Label
        $caption.Text = $detailFields[$i].Caption
        $caption.Dock = 'Fill'
        $caption.TextAlign = 'MiddleLeft'
        $caption.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
        $value = New-Object System.Windows.Forms.Label
        $value.Text = '-'
        $value.Dock = 'Fill'
        $value.TextAlign = 'MiddleLeft'
        $value.AutoEllipsis = $true
        $detailTable.Controls.Add($caption, 0, $i)
        $detailTable.Controls.Add($value, 1, $i)
        $script:detailValues[$detailFields[$i].Key] = $value
    }
    $detailGroup.Controls.Add($detailTable)
    $split.Panel2.Controls.Add($detailGroup)

    # Bulk tab
    $bulkTab = New-Object System.Windows.Forms.TabPage
    $bulkTab.Text = 'Bulk CSV'
    $bulkTab.Padding = New-Object System.Windows.Forms.Padding(8)
    $bulkTab.UseVisualStyleBackColor = $false
    $bulkTab.BackColor = [System.Drawing.Color]::FromArgb(245, 246, 248)

    $csvPanel = New-Object System.Windows.Forms.Panel
    $csvPanel.Dock = 'Top'
    $csvPanel.Height = 230
    $csvGroup = New-Object System.Windows.Forms.GroupBox
    $csvGroup.Text = 'CSV column mapping'
    $csvGroup.Dock = 'Fill'
    $script:csvGroup = $csvGroup
    $csvPanel.Controls.Add($csvGroup)

    $script:btnImport = New-PrimaryButton 'Import CSV' 12 24 120
    $script:btnExportTemplate = New-StandardButton 'Export template' 140 24 130
    $script:btnExportGrid = New-StandardButton 'Export grid' 278 24 110
    $script:btnRemoveRows = New-StandardButton 'Remove selected' 396 24 130
    $script:btnOpenSelected = New-StandardButton 'Open selected mailbox' 534 24 170
    $script:btnOpenSelected.Enabled = $false
    $script:lblRecords = New-Object System.Windows.Forms.Label
    $script:lblRecords.Text = 'Records: 0'
    $script:lblRecords.Location = New-Object System.Drawing.Point(716, 30)
    $script:lblRecords.AutoSize = $true
    $filterLabel = New-Object System.Windows.Forms.Label
    $filterLabel.Text = 'Filter'
    $filterLabel.Location = New-Object System.Drawing.Point(820, 30)
    $filterLabel.AutoSize = $true
    $filterLabel.Anchor = 'Top, Right'
    $script:txtFilter = New-Object System.Windows.Forms.TextBox
    $script:txtFilter.Location = New-Object System.Drawing.Point(858, 26)
    $script:txtFilter.Size = New-Object System.Drawing.Size(220, 24)
    $script:txtFilter.Anchor = 'Top, Right'
    $csvGroup.Controls.AddRange(@(
        $script:btnImport, $script:btnExportTemplate, $script:btnExportGrid,
        $script:btnRemoveRows, $script:btnOpenSelected, $script:lblRecords,
        $filterLabel, $script:txtFilter
    ))

    $script:mapTable = New-Object System.Windows.Forms.TableLayoutPanel
    $script:mapTable.Location = New-Object System.Drawing.Point(12, 66)
    $script:mapTable.Size = New-Object System.Drawing.Size(1040, 78)
    $script:mapTable.ColumnCount = 5
    $script:mapTable.RowCount = 2
    $script:mapTable.ColumnStyles.Clear()
    $script:mapTable.RowStyles.Clear()
    for ($i = 0; $i -lt 5; $i++) {
        [void]$script:mapTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 20)))
    }
    [void]$script:mapTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 22)))
    [void]$script:mapTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $mapCaptions = @('Identity', 'ProhibitSendReceiveGB', 'ProhibitSendGB', 'IssueWarningGB', 'QuotaInGB fallback')
    $mapCombos = @()
    for ($i = 0; $i -lt $mapCaptions.Count; $i++) {
        $caption = New-Object System.Windows.Forms.Label
        $caption.Text = $mapCaptions[$i]
        $caption.Dock = 'Fill'
        $caption.TextAlign = 'BottomLeft'
        $caption.Font = New-Object System.Drawing.Font('Segoe UI', 8, [System.Drawing.FontStyle]::Bold)
        $combo = New-Object System.Windows.Forms.ComboBox
        $combo.Dock = 'Fill'
        $combo.DropDownStyle = 'DropDownList'
        $combo.Margin = New-Object System.Windows.Forms.Padding(0, 4, 12, 0)
        [void]$combo.Items.Add('(not mapped)')
        $combo.SelectedIndex = 0
        $script:mapTable.Controls.Add($caption, $i, 0)
        $script:mapTable.Controls.Add($combo, $i, 1)
        $mapCombos += $combo
    }
    $script:cboIdentity = $mapCombos[0]
    $script:cboReceive = $mapCombos[1]
    $script:cboSend = $mapCombos[2]
    $script:cboWarning = $mapCombos[3]
    $script:cboQuota = $mapCombos[4]
    $csvGroup.Controls.Add($script:mapTable)

    $script:lblMap = New-Object System.Windows.Forms.Label
    $script:lblMap.Text = 'Import a CSV to detect Identity, ProhibitSendReceiveGB, ProhibitSendGB, and IssueWarningGB.'
    $script:lblMap.Location = New-Object System.Drawing.Point(12, 152)
    $script:lblMap.Size = New-Object System.Drawing.Size(1040, 40)
    $script:lblMap.ForeColor = [System.Drawing.Color]::DimGray
    $csvGroup.Controls.Add($script:lblMap)

    $actionPanel = New-Object System.Windows.Forms.Panel
    $actionPanel.Dock = 'Bottom'
    $actionPanel.Height = 104
    $actionGroup = New-Object System.Windows.Forms.GroupBox
    $actionGroup.Text = 'Apply'
    $actionGroup.Dock = 'Fill'
    $actionPanel.Controls.Add($actionGroup)
    $script:chkWhatIfBulk = New-Object System.Windows.Forms.CheckBox
    $script:chkWhatIfBulk.Text = 'Test mode (no changes saved)'
    $script:chkWhatIfBulk.Location = New-Object System.Drawing.Point(12, 28)
    $script:chkWhatIfBulk.Size = New-Object System.Drawing.Size(210, 24)
    $script:chkWhatIfBulk.Checked = $true
    $script:btnApplyBulk = New-PrimaryButton 'Apply quota changes' 230 22 180
    $script:btnApplyBulk.Enabled = $false
    $script:btnLoadCurrent = New-StandardButton 'Load quotas and licenses' 418 22 190
    $script:btnLoadCurrent.Enabled = $false
    $script:btnCancel = New-StandardButton 'Cancel' 616 22 90
    $script:btnCancel.Enabled = $false
    $script:progress = New-Object System.Windows.Forms.ProgressBar
    $script:progress.Location = New-Object System.Drawing.Point(12, 64)
    $script:progress.Size = New-Object System.Drawing.Size(1040, 22)
    $script:progress.Anchor = 'Top, Left, Right'
    $script:progress.Visible = $false
    $actionGroup.Controls.AddRange(@(
        $script:chkWhatIfBulk, $script:btnApplyBulk, $script:btnLoadCurrent,
        $script:btnCancel, $script:progress
    ))

    $script:dataTable = New-QuotaTable
    $script:grid = New-Object System.Windows.Forms.DataGridView
    $script:grid.Dock = 'Fill'
    $script:grid.DataSource = $script:dataTable
    $script:grid.AllowUserToAddRows = $false
    $script:grid.AllowUserToDeleteRows = $false
    $script:grid.AllowUserToOrderColumns = $true
    $script:grid.AllowUserToResizeRows = $false
    $script:grid.SelectionMode = 'FullRowSelect'
    $script:grid.MultiSelect = $true
    $script:grid.RowHeadersVisible = $false
    $script:grid.AutoSizeColumnsMode = 'None'
    $script:grid.AutoGenerateColumns = $true
    $script:grid.BackgroundColor = [System.Drawing.Color]::White
    $script:grid.BorderStyle = 'Fixed3D'
    $script:grid.EditMode = 'EditOnKeystrokeOrF2'
    $script:grid.ClipboardCopyMode = 'EnableAlwaysIncludeHeaderText'
    $script:grid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(248, 250, 252)
    Enable-ControlDoubleBuffer $script:grid

    $columnPlan = @(
        @{ Name = 'DisplayName'; Header = 'Display name'; Width = 160; ReadOnly = $true; Tip = 'Display name from the CSV or the mailbox.' }
        @{ Name = 'UserPrincipalName'; Header = 'User principal name'; Width = 220; ReadOnly = $true; Tip = 'Mailbox identity used for the update.' }
        @{ Name = 'IssueWarningGB'; Header = 'IssueWarningGB'; Width = 130; ReadOnly = $false; Tip = 'IssueWarningQuota in gigabytes. Editable.' }
        @{ Name = 'ProhibitSendGB'; Header = 'ProhibitSendGB'; Width = 130; ReadOnly = $false; Tip = 'ProhibitSendQuota in gigabytes. Editable.' }
        @{ Name = 'ProhibitSendReceiveGB'; Header = 'ProhibitSendReceiveGB'; Width = 170; ReadOnly = $false; Tip = 'ProhibitSendReceiveQuota in gigabytes. Editable.' }
        @{ Name = 'Validation'; Header = 'Validation'; Width = 220; ReadOnly = $true; Tip = 'Whether this row is ready to apply.' }
        @{ Name = 'Result'; Header = 'Result'; Width = 260; ReadOnly = $true; Tip = 'Outcome of the last preview or update.' }
        @{ Name = 'Licenses'; Header = 'User licenses'; Width = 360; ReadOnly = $true; Tip = 'Every license assigned to the account.' }
        @{ Name = 'CurrentIssueWarningGB'; Header = 'Current warning'; Width = 120; ReadOnly = $true; Tip = 'Issue warning currently on the mailbox.' }
        @{ Name = 'CurrentProhibitSendGB'; Header = 'Current send'; Width = 110; ReadOnly = $true; Tip = 'Prohibit send quota currently on the mailbox.' }
        @{ Name = 'CurrentProhibitSendReceiveGB'; Header = 'Current send/receive'; Width = 140; ReadOnly = $true; Tip = 'Prohibit send/receive quota currently on the mailbox.' }
        @{ Name = 'DatabaseDefaults'; Header = 'Quota source'; Width = 120; ReadOnly = $true; Tip = 'License defaults, or custom quotas.' }
    )
    foreach ($plan in $columnPlan) {
        $column = $script:grid.Columns[$plan.Name]
        $column.HeaderText = $plan.Header
        $column.Width = $plan.Width
        $column.MinimumWidth = 70
        $column.ReadOnly = $plan.ReadOnly
        $column.ToolTipText = $plan.Tip
        $column.SortMode = 'Automatic'
    }
    $script:grid.Columns['DisplayName'].Frozen = $true
    $script:grid.Columns['UserPrincipalName'].Frozen = $true

    $bulkTab.Controls.Add($actionPanel)
    $bulkTab.Controls.Add($csvPanel)
    $bulkTab.Controls.Add($script:grid)

    # Log tab
    $logTab = New-Object System.Windows.Forms.TabPage
    $logTab.Text = 'Activity log'
    $logTab.Padding = New-Object System.Windows.Forms.Padding(8)
    $logButtons = New-Object System.Windows.Forms.Panel
    $logButtons.Dock = 'Bottom'
    $logButtons.Height = 48
    $btnSaveLog = New-StandardButton 'Save log' 0 8 110
    $btnClearLog = New-StandardButton 'Clear log' 118 8 110
    $logButtons.Controls.AddRange(@($btnSaveLog, $btnClearLog))
    $script:txtLog = New-Object System.Windows.Forms.RichTextBox
    $script:txtLog.Dock = 'Fill'
    $script:txtLog.ReadOnly = $true
    $script:txtLog.WordWrap = $false
    $script:txtLog.BackColor = [System.Drawing.Color]::White
    $script:txtLog.Font = $(try { New-Object System.Drawing.Font('Consolas', 9) } catch { New-Object System.Drawing.Font('Courier New', 9) })
    $script:txtLog.HideSelection = $false
    $logTab.Controls.Add($logButtons)
    $logTab.Controls.Add($script:txtLog)

    [void]$script:tabs.TabPages.Add($mailboxTab)
    [void]$script:tabs.TabPages.Add($bulkTab)
    [void]$script:tabs.TabPages.Add($logTab)

    $form.Controls.Add($menu)
    $form.Controls.Add($status)
    $form.Controls.Add($connectionPanel)
    $form.Controls.Add($script:tabs)

    $importItem.Add_Click({ Import-CsvIntoGrid })
    $templateItem.Add_Click({ Export-TemplateCsv })
    $exportItem.Add_Click({ Export-GridCsv })
    $exitItem.Add_Click({ $script:form.Close() })
    $connectExoItem.Add_Click({ $script:btnConnect.PerformClick() })
    $disconnectExoItem.Add_Click({ $script:btnDisconnectExo.PerformClick() })
    $connectLicenseItem.Add_Click({ $script:btnConnectLicense.PerformClick() })
    $disconnectLicenseItem.Add_Click({ $script:btnDisconnectLicense.PerformClick() })
    $helpItem.Add_Click({ Show-TextDialog -Title 'How quotas and licenses work' -Body (Get-HelpText) })
    $aboutItem.Add_Click({
        Show-Info "Exchange Online Quota Manager $($script:AppVersion)`r`n`r`nSets IssueWarningGB, ProhibitSendGB, and ProhibitSendReceiveGB for one mailbox or from a CSV. Lists every license assigned to the account."
    })

    $script:btnConnect.Add_Click({
        Invoke-WithBusyCursor {
            try {
                Write-Activity 'Connecting to Exchange Online...'
                [System.Windows.Forms.Application]::DoEvents()
                Connect-ExchangeSession
                $who = if ($script:exoAccount) { $script:exoAccount } else { 'the signed-in account' }
                Write-Activity "Connected to Exchange Online as $who ($($script:exoOrganization))." 'SUCCESS'
                Show-Info "Connected to $($script:exoOrganization) as $who."
            }
            catch {
                $script:exoConnected = $false
                Write-Activity "Exchange Online connection failed: $($_.Exception.Message)" 'ERROR'
                Show-Info "Could not connect to Exchange Online.`r`n`r`n$($_.Exception.Message)" -Icon Error
            }
        }
    })
    $script:btnDisconnectExo.Add_Click({
        try {
            Disconnect-ExchangeSession
            Write-Activity 'Disconnected from Exchange Online.' 'SUCCESS'
        }
        catch {
            $still = $false
            try { $still = @(Get-ConnectionInformation -ErrorAction SilentlyContinue).Count -gt 0 } catch {}
            if (-not $still) {
                $script:exoConnected = $false
                $script:exoOrganization = ''
                $script:exoAccount = ''
            }
            Write-Activity "Disconnect failed: $($_.Exception.Message)" 'WARN'
            Show-Info "Disconnect reported an error.`r`n`r`n$($_.Exception.Message)" -Icon Warning
        }
        Set-UiBusy $false
    })
    $script:btnConnectLicense.Add_Click({
        Invoke-WithBusyCursor {
            try {
                Write-Activity 'Connecting to read user licenses...'
                [System.Windows.Forms.Application]::DoEvents()
                Connect-LicenseSession
                $who = if ($script:licenseAccount) { " as $($script:licenseAccount)" } else { '' }
                Write-Activity "License connection ready via $($script:licenseSource)$who." 'SUCCESS'
                Show-Info "Connected via $($script:licenseSource)$who.`r`n`r`nLooking up a mailbox or loading the grid will list every license on the account."
            }
            catch {
                $script:licenseConnected = $false
                Write-Activity "License connection failed: $($_.Exception.Message)" 'ERROR'
                Show-Info "Could not connect for licenses.`r`n`r`n$($_.Exception.Message)" -Icon Error
            }
        }
    })
    $script:btnDisconnectLicense.Add_Click({
        try {
            Disconnect-LicenseSession
            Write-Activity 'Disconnected the license service.' 'SUCCESS'
        }
        catch {
            $script:licenseConnected = $false
            $script:licenseSource = ''
            $script:licenseAccount = ''
            Write-Activity "License disconnect failed: $($_.Exception.Message)" 'WARN'
            Show-Info $_.Exception.Message -Icon Warning
        }
        Set-UiBusy $false
    })

    $script:btnLookup.Add_Click({ Start-MailboxLookup })
    $script:txtUser.Add_KeyDown({
        if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $_.SuppressKeyPress = $true
            if ($script:btnLookup.Enabled) { Start-MailboxLookup }
        }
    })
    $script:btnApplyOne.Add_Click({ Start-SingleApply })
    $script:chkRevert.Add_CheckedChanged({ if (-not $script:suppressQuotaEvents) { Update-SingleQuotaHint } })
    foreach ($box in @($script:txtWarning, $script:txtSend, $script:txtReceive)) {
        $box.Add_TextChanged({ if (-not $script:suppressQuotaEvents) { Update-SingleQuotaHint } })
    }
    $script:btnCopyLicenses.Add_Click({
        if ([string]::IsNullOrWhiteSpace($script:licenseSummary)) {
            Show-Info 'There is no license summary to copy yet.' -Icon Warning
            return
        }
        [System.Windows.Forms.Clipboard]::SetText($script:licenseSummary)
        Write-Activity 'Copied the license summary.' 'SUCCESS'
    })

    $script:btnImport.Add_Click({ Import-CsvIntoGrid })
    $script:btnExportTemplate.Add_Click({ Export-TemplateCsv })
    $script:btnExportGrid.Add_Click({ Export-GridCsv })
    $script:btnRemoveRows.Add_Click({ Remove-SelectedRows })
    $script:btnOpenSelected.Add_Click({ Open-SelectedMailbox })
    $script:btnApplyBulk.Add_Click({ Invoke-BulkQuotaRun -PreviewOnly:$false })
    $script:btnLoadCurrent.Add_Click({ Invoke-BulkQuotaRun -PreviewOnly:$true })
    $script:btnCancel.Add_Click({
        if ($script:busy) {
            $script:cancelRequested = $true
            Write-Activity 'Cancel requested. The current mailbox will finish, then the run will stop.' 'WARN'
        }
    })
    foreach ($combo in @($script:cboIdentity, $script:cboReceive, $script:cboSend, $script:cboWarning, $script:cboQuota)) {
        $combo.Add_SelectedIndexChanged({ Update-MappingFromUi })
    }
    $script:txtFilter.Add_TextChanged({
        if (-not $script:dataTable) { return }
        try {
            $text = $script:txtFilter.Text
            if ([string]::IsNullOrWhiteSpace($text)) {
                $script:dataTable.DefaultView.RowFilter = ''
            }
            else {
                $safe = $text.Replace("'", "''").Replace('[', '[[]').Replace('%', '[%]').Replace('*', '[*]')
                $clauses = @(
                    "DisplayName LIKE '%$safe%'",
                    "UserPrincipalName LIKE '%$safe%'",
                    "Licenses LIKE '%$safe%'",
                    "Validation LIKE '%$safe%'",
                    "Result LIKE '%$safe%'"
                )
                $script:dataTable.DefaultView.RowFilter = $clauses -join ' OR '
            }
        }
        catch {
            Write-Activity "The filter could not be applied: $($_.Exception.Message)" 'WARN'
        }
        Update-RecordCount
        if (-not $script:busy) { Set-UiBusy $false }
    })
    $script:grid.Add_DataError({ $_.ThrowException = $false })
    $script:grid.Add_CellEndEdit({
        $rowIndex = $_.RowIndex
        if ($rowIndex -lt 0) { return }
        $bound = $script:grid.Rows[$rowIndex].DataBoundItem
        if ($bound) {
            $script:gridEdited = $true
            Update-GridRowValidation $bound.Row
        }
    })
    $script:grid.Add_CellFormatting({
        if ($_.RowIndex -lt 0 -or $_.RowIndex -ge $script:grid.Rows.Count) { return }
        $gridRow = $script:grid.Rows[$_.RowIndex]
        $result = [string]$gridRow.Cells['Result'].Value
        $validation = [string]$gridRow.Cells['Validation'].Value
        $color = $null
        if ($result.StartsWith('Failed') -or $validation.StartsWith('Error')) {
            $color = [System.Drawing.Color]::FromArgb(255, 236, 236)
        }
        elseif ($result.StartsWith('Updated') -or $result.StartsWith('Test passed')) {
            $color = [System.Drawing.Color]::FromArgb(232, 245, 233)
        }
        elseif ($result.StartsWith('Unchanged') -or $result.StartsWith('Skipped') -or $validation.StartsWith('Warning') -or $validation.StartsWith('Skipped')) {
            $color = [System.Drawing.Color]::FromArgb(255, 249, 230)
        }
        if ($color) { $_.CellStyle.BackColor = $color }
    })

    $btnSaveLog.Add_Click({ Save-ActivityLog })
    $btnClearLog.Add_Click({ $script:txtLog.Clear() })

    $form.Add_Shown({
        try {
            $script:split.Panel1MinSize = 420
            $script:split.Panel2MinSize = 280
            $script:split.SplitterDistance = 560
        }
        catch {}
        if ($script:csvGroup -and $script:mapTable) {
            $width = $script:csvGroup.ClientSize.Width - 24
            if ($width -gt 200) {
                $script:mapTable.Width = $width
                $script:lblMap.Width = $width
            }
        }
    })
    $script:csvGroup.Add_Resize({
        if (-not $script:mapTable -or -not $script:csvGroup) { return }
        $width = $script:csvGroup.ClientSize.Width - 24
        if ($width -gt 200) {
            $script:mapTable.Width = $width
            $script:lblMap.Width = $width
        }
    })
    $form.Add_FormClosing({
        if ($script:busy) {
            $_.Cancel = $true
            Show-Info 'A task is still running. Cancel it and wait for it to finish before closing.' -Icon Warning
            return
        }
        if ($script:exoConnected) {
            try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        }
        if ($script:licenseConnected -and $script:licenseSource -eq 'Graph') {
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
        if ($script:licenseConnected -and $script:licenseSource -eq 'AzureAD') {
            try { Disconnect-AzureAD -ErrorAction SilentlyContinue } catch {}
        }
    })

    $script:tip = New-Object System.Windows.Forms.ToolTip
    $script:tip.SetToolTip($script:cboReceive, 'CSV column for ProhibitSendReceiveQuota, in gigabytes.')
    $script:tip.SetToolTip($script:cboSend, 'CSV column for ProhibitSendQuota, in gigabytes.')
    $script:tip.SetToolTip($script:cboWarning, 'CSV column for IssueWarningQuota, in gigabytes.')
    $script:tip.SetToolTip($script:cboIdentity, 'CSV column that identifies the mailbox.')
    $script:tip.SetToolTip($script:cboQuota, 'Optional. Used only when the three quota columns are empty.')
    $script:tip.SetToolTip($script:btnLoadCurrent, 'Read current quotas and every assigned license. Does not change mailboxes.')

    return $form
}

$form = Build-MainForm
Set-UiBusy $false
Write-Activity "Exchange Online Quota Manager $($script:AppVersion) is ready."
Write-Activity 'Connect to Exchange Online, then look up one mailbox or import a CSV. Connect for licenses to see every license on the account.'

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Activity 'ExchangeOnlineManagement is not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser' 'ERROR'
}
$graphReady = @(Get-Module -ListAvailable -Name Microsoft.Graph.Authentication).Count -gt 0 -or @(Get-Module -ListAvailable -Name Microsoft.Graph).Count -gt 0
$legacyReady = @(Get-Module -ListAvailable -Name AzureAD).Count -gt 0 -or @(Get-Module -ListAvailable -Name MSOnline).Count -gt 0
if (-not $graphReady -and -not $legacyReady) {
    Write-Activity 'No license module is installed. Run: Install-Module Microsoft.Graph -Scope CurrentUser' 'WARN'
}

[void]$form.ShowDialog()
$form.Dispose()

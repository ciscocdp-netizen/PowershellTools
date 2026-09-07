#Requires -Version 5.1
<#
.SYNOPSIS
    Reports which users from an imported CSV do NOT have a strong authentication
    method registered in Entra ID (Azure AD) — only a password, or nothing at all.

.DESCRIPTION
    Fully interactive, PowerShell 5.1 and Windows PowerShell ISE compatible.
      * Prompts you (via a GUI file picker) to select the input CSV of users.
      * Prompts you (via a GUI save dialog) to choose where the report is saved.
      * Connects to Microsoft Graph and inspects each user's registered
        authentication methods.
      * A user is flagged as "missing" when they have NO authentication methods
        registered, or only a password (i.e. no Microsoft Authenticator, phone,
        FIDO2, Windows Hello, software OATH, email, TAP, passkey, or any other
        non-password method).

    Password methods are identified by Graph @odata.type AND by the well-known
    password method id (28c10230-6103-485e-b985-444c60001490), so users are not
    missed when the SDK omits @odata.type. Method payloads are read with
    Invoke-MgGraphRequest so hashtable / AdditionalProperties indexer bugs in
    Windows PowerShell 5.1 do not drop registered methods.

.PARAMETER InputCsv
    Optional path to the input CSV. When omitted, an Open File dialog is shown.

.PARAMETER OutputCsv
    Optional path for the report CSV. When omitted, a Save File dialog is shown.

.PARAMETER IncludeAll
    Also write users who DO have a non-password method. Default report contains
    only password-only / no-method users, plus not-found / error / skipped rows.

.PARAMETER DeviceCode
    Use device-code sign-in instead of Windows Web Account Manager (WAM).

.PARAMETER TenantId
    Optional Entra tenant (contoso.onmicrosoft.com or a Tenant ID GUID).

.PARAMETER ClientId
    Optional public-client app ID. Leave blank to use the Microsoft Graph
    PowerShell app (the default WAM client).

.PARAMETER SelfTest
    Runs built-in unit tests for classification helpers and exits
    (no Graph / no dialogs).

.EXAMPLE
    .\Get-EntraUsersWithoutAuthMethod.ps1

.EXAMPLE
    .\Get-EntraUsersWithoutAuthMethod.ps1 -InputCsv .\users.csv -OutputCsv .\report.csv

.EXAMPLE
    .\Get-EntraUsersWithoutAuthMethod.ps1 -IncludeAll

.EXAMPLE
    .\Get-EntraUsersWithoutAuthMethod.ps1 -SelfTest

.EXAMPLE
    .\Get-EntraUsersWithoutAuthMethod.ps1 -DeviceCode

.EXAMPLE
    # PowerShell ISE: open this script and press F5. File dialogs and browser sign-in are used automatically.

.NOTES
    Requires the Microsoft.Graph.Authentication module.
    Requires the UserAuthenticationMethod.Read.All and User.Read.All permissions
    (delegated). An admin may need to consent the first time you run it.

    Sign-in: Windows console uses Web Account Manager (WAM). PowerShell ISE
    cannot host WAM, so ISE automatically opens your web browser with a
    device-code sign-in instead. In ISE, open the script and press F5.

    Do not rely on WAM from an elevated Administrator window.

    CSV requirement: a header row containing a column with the user's UPN /
    email / object id. The script auto-detects common column names
    (UserPrincipalName, UPN, Email, Mail, User, Id, ObjectId) or will prompt
    you to pick one.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$InputCsv,

    [Parameter()]
    [string]$OutputCsv,

    [switch]$IncludeAll,

    [switch]$DeviceCode,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$ClientId,

    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:WinFormsLoaded = $false
$script:UseGui = -not $SelfTest
$script:ProgressForm = $null
$script:ProgressBar = $null
$script:ProgressLabel = $null
$script:ProgressDetail = $null
$script:GraphScopeList = @('UserAuthenticationMethod.Read.All', 'User.Read.All')
$script:GraphScopeString = 'UserAuthenticationMethod.Read.All User.Read.All offline_access openid profile'
$script:GraphPowerShellClientId = '14d82eec-204b-4c2f-b113-9d477e6ee18c'
$script:AzurePowerShellClientId = '1950a258-227b-4e31-a9cf-717495945fc2'
$script:AzureCliClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
$script:PasswordMethodId = '28c10230-6103-485e-b985-444c60001490'
$script:GraphBase = 'https://graph.microsoft.com/v1.0'
$script:AccessToken = $null
$script:RefreshToken = $null
$script:TokenClientId = $null
$script:TokenTenant = 'organizations'
$script:AuthSkipRequested = $false
$script:IsPowerShellIse = $false
try {
    if ($Host.Name -eq 'Windows PowerShell ISE Host') {
        $script:IsPowerShellIse = $true
    }
}
catch { }
try {
    if (Get-Variable -Name psISE -ErrorAction SilentlyContinue) {
        if ($null -ne $psISE) { $script:IsPowerShellIse = $true }
    }
}
catch { }

# ---------------------------------------------------------------------------
# STA relaunch (WinForms dialogs + WAM parent window)
# ISE is already STA — never relaunch out of ISE into powershell.exe.
# ---------------------------------------------------------------------------

if ($script:UseGui -and -not $script:IsPowerShellIse -and [System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
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
    if ($IncludeAll) {
        [void]$argParts.Add('-IncludeAll')
    }
    if ($DeviceCode) {
        [void]$argParts.Add('-DeviceCode')
    }
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        [void]$argParts.Add('-TenantId')
        [void]$argParts.Add(('"{0}"' -f $TenantId))
    }
    if (-not [string]::IsNullOrWhiteSpace($ClientId)) {
        [void]$argParts.Add('-ClientId')
        [void]$argParts.Add(('"{0}"' -f $ClientId))
    }

    Write-Host "Relaunching in STA mode so file dialogs and sign-in work..." -ForegroundColor Yellow
    $proc = Start-Process -FilePath $exe -ArgumentList ($argParts -join ' ') -Wait -PassThru -NoNewWindow
    if ($null -eq $proc.ExitCode) { exit 1 }
    exit $proc.ExitCode
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

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

function Select-InputFile {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title            = "Select the CSV file containing your list of users"
    $dialog.Filter           = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    $dialog.Multiselect      = $false
    $dialog.CheckFileExists  = $true
    $dialog.RestoreDirectory = $true
    $dialog.InitialDirectory = Get-DefaultPickerDirectory

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

function Select-OutputFile {
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Title            = "Choose where to save the report"
    $dialog.Filter           = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    $dialog.DefaultExt       = "csv"
    $dialog.AddExtension     = $true
    $dialog.OverwritePrompt  = $true
    $dialog.RestoreDirectory = $true
    $dialog.InitialDirectory = Get-DefaultPickerDirectory
    $dialog.FileName         = "EntraID_UsersWithoutAuthMethod_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date)

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

function Test-LooksLikeGuid {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $parsed = [guid]::Empty
    return [guid]::TryParse($Value, [ref]$parsed)
}

function Resolve-UpnColumn {
    param(
        [Parameter(Mandatory)]
        [object[]]$Rows,

        [switch]$PromptIfMissing
    )

    $columns = @($Rows[0].PSObject.Properties.Name)
    $preferred = @(
        'UserPrincipalName', 'UPN', 'Email', 'EmailAddress', 'Mail',
        'User', 'Username', 'UserName', 'ObjectId', 'Id'
    )

    foreach ($p in $preferred) {
        $match = $columns | Where-Object {
            $_ -and ([string]::Equals($_.Trim(), $p, [System.StringComparison]::OrdinalIgnoreCase))
        } | Select-Object -First 1
        if ($match) {
            return [pscustomobject]@{
                ColumnName   = [string]$match
                AutoDetected = $true
            }
        }
    }

    if ($PromptIfMissing -and $script:UseGui) {
        Write-Host ""
        Write-Host "Could not auto-detect the column that holds the user's UPN / email." -ForegroundColor Yellow
        Write-Host "Available columns:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $columns.Count; $i++) {
            Write-Host ("  [{0}] {1}" -f ($i + 1), $columns[$i])
        }
        do {
            $choice = Read-Host "Enter the number of the column to use"
            $valid  = ($choice -match '^\d+$') -and ([int]$choice -ge 1) -and ([int]$choice -le $columns.Count)
            if (-not $valid) { Write-Host "Invalid selection, try again." -ForegroundColor Red }
        } while (-not $valid)

        return [pscustomobject]@{
            ColumnName   = [string]$columns[[int]$choice - 1]
            AutoDetected = $false
        }
    }

    return [pscustomobject]@{
        ColumnName   = [string]($columns | Select-Object -First 1)
        AutoDetected = $false
    }
}

function Get-GraphResponseProperty {
    param(
        $Response,
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Response) {
        return $null
    }

    # Invoke-MgGraphRequest often returns Hashtable/OrderedDictionary/Dictionary.
    # Do NOT use $Response.PSObject.Properties[$Name] on dictionaries — under
    # StrictMode that throws "Argument types do not match".
    if ($Response -is [System.Collections.IDictionary]) {
        foreach ($key in @($Response.Keys)) {
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                try {
                    return $Response[$key]
                }
                catch {
                    # Generic Dictionary[string,object] indexer can throw
                    # "Argument types do not match" in Windows PowerShell 5.1.
                    if ($Response.PSObject.Methods['get_Item']) {
                        return $Response.get_Item([string]$key)
                    }
                    throw
                }
            }
        }
        return $null
    }

    foreach ($prop in @($Response.PSObject.Properties)) {
        if ([string]::Equals([string]$prop.Name, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $prop.Value
        }
    }
    return $null
}

function ConvertTo-ObjectList {
    param($Value)

    # Always return List[psobject]. Do NOT use @($genericList) — under Set-StrictMode
    # that throws "Argument types do not match" in Windows PowerShell 5.1 and PS 7.
    $out = New-Object System.Collections.Generic.List[psobject]
    if ($null -eq $Value) {
        return ,$out
    }

    if ($Value -is [string]) {
        [void]$out.Add($Value)
        return ,$out
    }

    $isDict = $false
    try {
        $isDict = $Value -is [System.Collections.IDictionary]
    }
    catch {
        $isDict = $false
    }
    if ($isDict) {
        [void]$out.Add($Value)
        return ,$out
    }

    foreach ($item in $Value) {
        [void]$out.Add($item)
    }

    # Unary comma keeps the List as one object (pipeline would otherwise enumerate it).
    return ,$out
}

function Get-AuthMethodOdataType {
    param($Method)

    if ($null -eq $Method) { return '' }

    foreach ($name in @('@odata.type', 'odata.type', 'OdataType')) {
        $value = Get-GraphResponseProperty -Response $Method -Name $name
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            return [string]$value
        }
    }

    $additional = Get-GraphResponseProperty -Response $Method -Name 'AdditionalProperties'
    if ($null -ne $additional) {
        $fromAdditional = Get-GraphResponseProperty -Response $additional -Name '@odata.type'
        if ([string]::IsNullOrWhiteSpace([string]$fromAdditional)) {
            $fromAdditional = Get-GraphResponseProperty -Response $additional -Name 'odata.type'
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$fromAdditional)) {
            return [string]$fromAdditional
        }
    }

    try {
        $typeName = $Method.GetType().Name
        if ($typeName -match '^(MicrosoftGraph)?(.+AuthenticationMethod)$') {
            $short = $Matches[2]
            if ($short -ne 'AuthenticationMethod') {
                $camel = $short.Substring(0, 1).ToLowerInvariant() + $short.Substring(1)
                return "#microsoft.graph.$camel"
            }
        }
    }
    catch { }

    return ''
}

function Get-NormalizedMethodType {
    param([AllowNull()][string]$OdataType)

    if ([string]::IsNullOrWhiteSpace($OdataType)) { return '' }
    $t = $OdataType.Trim()
    if ($t.StartsWith('#')) { $t = $t.Substring(1) }
    if ($t.StartsWith('microsoft.graph.')) { $t = $t.Substring(16) }
    if ($t.EndsWith('AuthenticationMethod')) {
        $t = $t.Substring(0, $t.Length - 'AuthenticationMethod'.Length)
    }
    return $t.ToLowerInvariant()
}

function Test-IsPasswordAuthenticationMethod {
    param($Method)

    if ($null -eq $Method) { return $false }

    $id = [string](Get-GraphResponseProperty -Response $Method -Name 'id')
    if (-not [string]::IsNullOrWhiteSpace($id) -and
        [string]::Equals($id.Trim(), $script:PasswordMethodId, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    $normalized = Get-NormalizedMethodType -OdataType (Get-AuthMethodOdataType -Method $Method)
    return ($normalized -eq 'password')
}

function ConvertTo-FriendlyMethodName {
    param([AllowNull()][string]$OdataType)

    $normalized = Get-NormalizedMethodType -OdataType $OdataType
    if ([string]::IsNullOrWhiteSpace($normalized)) { return 'Unknown' }

    $map = @{
        'password'                         = 'Password'
        'microsoftauthenticator'           = 'Microsoft Authenticator'
        'passwordlessmicrosoftauthenticator' = 'Passwordless Authenticator'
        'phone'                            = 'Phone'
        'fido2'                            = 'FIDO2'
        'windowshelloforbusiness'          = 'Windows Hello for Business'
        'softwareoath'                     = 'Software OATH'
        'hardwareoath'                     = 'Hardware OATH'
        'email'                            = 'Email'
        'temporaryaccesspass'              = 'Temporary Access Pass'
        'platformcredential'               = 'Platform Credential'
        'x509certificate'                  = 'Certificate'
        'qrcodespin'                       = 'QR code PIN'
        'qrcodepin'                        = 'QR code PIN'
        'external'                         = 'External'
        'passkeydevicebound'               = 'Passkey'
    }

    if ($map.ContainsKey($normalized)) {
        return $map[$normalized]
    }
    return $normalized
}

function Get-AuthenticationMethodInventory {
    param($Methods)

    # foreach / List — not @() — so empty and generic collections stay intact.
    $items = ConvertTo-ObjectList -Value $Methods
    $friendly = New-Object System.Collections.Generic.List[string]
    $hasNonPassword = $false
    $passwordCount = 0
    $unknownCount = 0

    foreach ($method in $items) {
        if ($null -eq $method) { continue }

        $isPassword = Test-IsPasswordAuthenticationMethod -Method $method
        $odataType = Get-AuthMethodOdataType -Method $method
        $label = ConvertTo-FriendlyMethodName -OdataType $odataType

        if ($isPassword) {
            $passwordCount++
            if ([string]::IsNullOrWhiteSpace($odataType)) { $label = 'Password' }
        }
        else {
            $hasNonPassword = $true
            if ([string]::IsNullOrWhiteSpace($odataType)) {
                $unknownCount++
                $id = [string](Get-GraphResponseProperty -Response $method -Name 'id')
                if (-not [string]::IsNullOrWhiteSpace($id)) {
                    $label = "Unknown (id $id)"
                }
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($label) -and -not $friendly.Contains($label)) {
            [void]$friendly.Add($label)
        }
    }

    $sorted = @($friendly | Sort-Object)
    $detail = 'Password only - no other method registered'
    if ($items.Count -eq 0) {
        $detail = 'No methods registered'
    }
    elseif ($hasNonPassword) {
        $detail = 'Has a non-password authentication method'
    }

    return [pscustomobject]@{
        HasNonPasswordMethod = [bool]$hasNonPassword
        RegisteredMethods    = ($sorted -join '; ')
        MethodCount          = [int]$items.Count
        PasswordCount        = [int]$passwordCount
        UnknownCount         = [int]$unknownCount
        Detail               = $detail
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
    $form.Text = 'Entra ID - Users Without Auth Method'
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
    $label.Text = "Preparing to check $Total user(s)..."
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

    Write-Progress -Activity "Checking Entra ID authentication methods" `
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
        $script:ProgressLabel.Text = "Checking authentication methods — $statusText"
        $script:ProgressDetail.Text = "$pct% complete"
        [void][System.Windows.Forms.Application]::DoEvents()
    }
    catch { }
}

function Close-ProgressUi {
    Write-Progress -Activity "Checking Entra ID authentication methods" -Completed
    if ($null -ne $script:ProgressForm) {
        try { $script:ProgressForm.Close() } catch { }
        try { $script:ProgressForm.Dispose() } catch { }
    }
    $script:ProgressForm = $null
    $script:ProgressBar = $null
    $script:ProgressLabel = $null
    $script:ProgressDetail = $null
}

function New-ReportRow {
    param(
        [string]$CsvIdentifier = '',
        [string]$UserPrincipalName = '',
        [string]$DisplayName = '',
        $AccountEnabled = '',
        [string]$Status = '',
        $HasNonPasswordMethod = '',
        [string]$RegisteredMethods = '',
        $MethodCount = '',
        [string]$Detail = ''
    )

    return [pscustomobject][ordered]@{
        CsvIdentifier        = $CsvIdentifier
        UserPrincipalName    = $UserPrincipalName
        DisplayName          = $DisplayName
        AccountEnabled       = $AccountEnabled
        Status               = $Status
        HasNonPasswordMethod = $HasNonPasswordMethod
        RegisteredMethods    = $RegisteredMethods
        MethodCount          = $MethodCount
        Detail               = $Detail
    }
}

function Ensure-GraphModule {
    $required = @('Microsoft.Graph.Authentication')

    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($m in $required) {
        if (-not (Get-Module -ListAvailable -Name $m)) { [void]$missing.Add($m) }
    }

    if ($missing.Count -gt 0) {
        Write-Host "The following required Microsoft Graph modules are not installed:" -ForegroundColor Yellow
        $missing | ForEach-Object { Write-Host "   - $_" -ForegroundColor Yellow }
        $answer = Read-Host "Install them now for the current user? (Y/N)"
        if ($answer -match '^(y|yes)$') {
            try {
                if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
                }
                foreach ($m in $missing) {
                    Write-Host "Installing $m ..." -ForegroundColor Gray
                    Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                }
            }
            catch {
                throw "Failed to install Microsoft Graph modules: $($_.Exception.Message)"
            }
        }
        else {
            throw "Required Microsoft Graph modules are missing. Cannot continue."
        }
    }

    foreach ($m in $required) {
        Import-Module $m -ErrorAction Stop
    }

    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw "Invoke-MgGraphRequest is not available. Please update the Microsoft.Graph.Authentication module."
    }
}

function New-AuthParentForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Entra ID sign-in (Windows WAM)'
    $form.Width = 520
    $form.Height = 160
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.TopMost = $true
    $form.ShowInTaskbar = $true
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    $label = New-Object System.Windows.Forms.Label
    $label.Dock = [System.Windows.Forms.DockStyle]::Fill
    $label.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $label.Text = "Complete sign-in in the Windows account picker / browser.`r`nLeave this window open until sign-in finishes."
    $form.Controls.Add($label)

    [void]$form.Show()
    $form.Activate()
    [void][System.Windows.Forms.Application]::DoEvents()
    return $form
}

function Get-PublicClientIdList {
    $ids = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($ClientId)) {
        [void]$ids.Add($ClientId.Trim())
    }
    # Azure CLI / Azure PowerShell first-party apps cannot request
    # UserAuthenticationMethod.Read.All (AADSTS65002). Only Graph PowerShell
    # or a custom public client in this tenant can.
    [void]$ids.Add($script:GraphPowerShellClientId)

    $seen = @{}
    $unique = New-Object System.Collections.Generic.List[string]
    foreach ($id in $ids) {
        $key = $id.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [void]$unique.Add($id)
    }
    return ,$unique
}

function Get-GraphAdminConsentUrl {
    $tenant = 'organizations'
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $tenant = $TenantId.Trim()
    }
    return "https://login.microsoftonline.com/$tenant/adminconsent?client_id=$($script:GraphPowerShellClientId)"
}

function Show-GraphConsentGuidance {
    $url = Get-GraphAdminConsentUrl
    Write-Host ""
    Write-Host "Azure CLI and Azure PowerShell cannot read authentication methods in this tenant (AADSTS65002)." -ForegroundColor Yellow
    Write-Host "Microsoft Graph PowerShell may also be missing from the tenant (AADSTS700016)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "An Entra admin must do ONE of these:" -ForegroundColor Cyan
    Write-Host "  A) Consent the Microsoft Graph PowerShell app:" -ForegroundColor Cyan
    Write-Host "     $url" -ForegroundColor White
    Write-Host "  B) Create an app registration in Entra:" -ForegroundColor Cyan
    Write-Host "     - Platform: Mobile and desktop / Public client" -ForegroundColor Gray
    Write-Host "     - Redirect URI: http://localhost" -ForegroundColor Gray
    Write-Host "     - Allow public client flows: Yes" -ForegroundColor Gray
    Write-Host "     - Delegated permissions: User.Read.All, UserAuthenticationMethod.Read.All" -ForegroundColor Gray
    Write-Host "     - Grant admin consent, then re-run:" -ForegroundColor Gray
    Write-Host "       .\Get-EntraUsersWithoutAuthMethod.ps1 -ClientId <app-id> -TenantId <tenant-id>" -ForegroundColor White
}

function Read-CustomPublicClientId {
    $prompt = 'Paste a custom App (client) ID from your tenant, or leave blank to skip'
    if ($script:WinFormsLoaded) {
        try {
            Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue | Out-Null
            $value = [Microsoft.VisualBasic.Interaction]::InputBox(
                "Your tenant blocked Azure CLI/Azure PowerShell from reading auth methods.`r`n`r`nPaste an App (client) ID from an Entra app registration in THIS tenant.`r`nRedirect URI must be http://localhost, with User.Read.All and UserAuthenticationMethod.Read.All.`r`n`r`nLeave blank to skip.",
                'Entra app Client ID',
                ''
            )
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                return $value.Trim()
            }
            return ''
        }
        catch { }
    }

    $entered = Read-Host $prompt
    if ([string]::IsNullOrWhiteSpace($entered)) { return '' }
    return $entered.Trim()
}

function Test-IsProcessElevated {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return [bool]$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Test-IsPowerShellIse {
    if ($script:IsPowerShellIse) { return $true }
    try {
        if ($Host.Name -eq 'Windows PowerShell ISE Host') { return $true }
    }
    catch { }
    return $false
}

function Test-ShouldSkipWam {
    param([switch]$ForceDeviceCode)
    if ($ForceDeviceCode) { return $true }
    if (Test-IsPowerShellIse) { return $true }
    if (Test-IsProcessElevated) { return $true }
    return $false
}

function Test-GraphContextHasRequiredScopes {
    $ctx = $null
    try { $ctx = Get-MgContext -ErrorAction SilentlyContinue } catch { }
    if (-not $ctx) { return $false }

    $scopeText = ''
    if ($ctx.Scopes) {
        $scopeText = @($ctx.Scopes) -join ' '
    }
    if ([string]::IsNullOrWhiteSpace($scopeText)) {
        $account = ''
        try {
            if ($ctx.Account) { $account = [string]$ctx.Account }
        }
        catch { }
        # Some SDK builds omit Scopes; treat an account as connected.
        return (-not [string]::IsNullOrWhiteSpace($account))
    }

    $hasUserRead = ($scopeText -match 'User\.Read\.All|Directory\.Read\.All')
    $hasAuthRead = ($scopeText -match 'UserAuthenticationMethod\.Read\.All|AuthenticationMethod\.Read\.All')
    return ($hasUserRead -and $hasAuthRead)
}

function ConvertTo-FormUrlEncoded {
    param([hashtable]$Data)

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($key in $Data.Keys) {
        $k = [uri]::EscapeDataString([string]$key)
        $v = [uri]::EscapeDataString([string]$Data[$key])
        [void]$parts.Add("$k=$v")
    }
    return ($parts -join '&')
}

function Get-ConnectMgGraphDeviceCodeParameter {
    $cmd = Get-Command Connect-MgGraph -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    foreach ($name in @('UseDeviceAuthentication', 'UseDeviceCode', 'DeviceCode')) {
        if ($cmd.Parameters.ContainsKey($name)) {
            return $name
        }
    }
    return $null
}

function ConvertTo-GraphAccessTokenArgument {
    param([Parameter(Mandatory)][string]$AccessToken)

    $cmd = Get-Command Connect-MgGraph -ErrorAction SilentlyContinue
    if (-not $cmd -or -not $cmd.Parameters.ContainsKey('AccessToken')) {
        return $null
    }

    $typeName = [string]$cmd.Parameters['AccessToken'].ParameterType.FullName
    if ($typeName -match 'SecureString') {
        return (ConvertTo-SecureString -String $AccessToken -AsPlainText -Force)
    }
    return $AccessToken
}

function Connect-WithAccessToken {
    param([Parameter(Mandatory)][string]$AccessToken)

    $script:AccessToken = $AccessToken
    $tokenArg = ConvertTo-GraphAccessTokenArgument -AccessToken $AccessToken
    if ($null -eq $tokenArg) {
        return $true
    }

    $cmd = Get-Command Connect-MgGraph -ErrorAction Stop
    $params = @{
        AccessToken = $tokenArg
        ErrorAction = 'Stop'
    }
    if ($cmd.Parameters.ContainsKey('NoWelcome')) {
        $params['NoWelcome'] = $true
    }
    Connect-MgGraph @params | Out-Null
    return $true
}

function ConvertTo-Base64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $b64 = [Convert]::ToBase64String($Bytes)
    return ($b64.TrimEnd('=') -replace '\+', '-' -replace '/', '_')
}

function New-PkcePair {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }

    $verifier = ConvertTo-Base64Url -Bytes $bytes
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($verifier))
    }
    finally {
        $sha.Dispose()
    }

    return [pscustomobject]@{
        Verifier  = $verifier
        Challenge = (ConvertTo-Base64Url -Bytes $hash)
    }
}

function Get-QueryValue {
    param(
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)][string]$Name
    )

    $query = [string]$Uri.Query
    if ([string]::IsNullOrWhiteSpace($query)) { return $null }
    if ($query.StartsWith('?')) { $query = $query.Substring(1) }

    foreach ($part in $query.Split('&')) {
        if ([string]::IsNullOrWhiteSpace($part)) { continue }
        $eq = $part.IndexOf('=')
        $key = $part
        $val = ''
        if ($eq -ge 0) {
            $key = $part.Substring(0, $eq)
            $val = $part.Substring($eq + 1)
        }
        $decodedKey = [uri]::UnescapeDataString($key)
        if ([string]::Equals($decodedKey, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
            return [uri]::UnescapeDataString($val.Replace('+', ' '))
        }
    }
    return $null
}

function Get-EntraAuthorizeUrl {
    param(
        [Parameter(Mandatory)][string]$Authority,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$RedirectUri,
        [Parameter(Mandatory)][string]$State,
        [Parameter(Mandatory)][string]$CodeChallenge
    )

    $pairs = @(
        "client_id=$([uri]::EscapeDataString($ClientId))",
        'response_type=code',
        "redirect_uri=$([uri]::EscapeDataString($RedirectUri))",
        'response_mode=query',
        "scope=$([uri]::EscapeDataString($script:GraphScopeString))",
        "state=$([uri]::EscapeDataString($State))",
        "code_challenge=$([uri]::EscapeDataString($CodeChallenge))",
        'code_challenge_method=S256',
        'prompt=select_account'
    )
    return "$Authority/oauth2/v2.0/authorize?$($pairs -join '&')"
}

function Start-SystemBrowser {
    param([Parameter(Mandatory)][string]$Url)

    Write-Host "Launching your web browser for Microsoft sign-in..." -ForegroundColor Cyan

    try {
        Start-Process $Url | Out-Null
        return $true
    }
    catch { }

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Url
        $psi.UseShellExecute = $true
        [void][System.Diagnostics.Process]::Start($psi)
        return $true
    }
    catch { }

    try {
        if ($env:OS -match 'Windows') {
            cmd.exe /c start "" "$Url" | Out-Null
            return $true
        }
    }
    catch { }

    return $false
}

function Get-AuthListener {
    $ports = @(8400, 8401, 8402, 18800, 18801, 5050, 5051)
    foreach ($port in $ports) {
        foreach ($hostName in @('localhost', '127.0.0.1')) {
            $listener = $null
            try {
                $listener = New-Object System.Net.HttpListener
                $prefix = "http://${hostName}:${port}/"
                $listener.Prefixes.Add($prefix)
                $listener.Start()
                return [pscustomobject]@{
                    Listener    = $listener
                    RedirectUri = $prefix
                    Port        = $port
                }
            }
            catch {
                if ($null -ne $listener) {
                    try { $listener.Close() } catch { }
                }
            }
        }
    }
    return $null
}

function Write-AuthBrowserResponse {
    param(
        $Context,
        [string]$Title,
        [string]$Body
    )

    $html = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>$Title</title></head>
<body style="font-family: Segoe UI, Tahoma, sans-serif; padding: 48px; max-width: 640px;">
  <h2>$Title</h2>
  <p>$Body</p>
  <p>You can close this tab and return to PowerShell.</p>
</body>
</html>
"@
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
    try {
        $Context.Response.StatusCode = 200
        $Context.Response.ContentType = 'text/html; charset=utf-8'
        $Context.Response.ContentLength64 = $buffer.Length
        $Context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $Context.Response.OutputStream.Close()
    }
    catch { }
}

function Complete-GraphTokenResponse {
    param(
        $Token,
        [Parameter(Mandatory)][string]$AppClientId,
        [Parameter(Mandatory)][string]$Tenant
    )

    $accessToken = [string](Get-GraphResponseProperty -Response $Token -Name 'access_token')
    if ([string]::IsNullOrWhiteSpace($accessToken)) {
        throw 'Sign-in succeeded but no access_token was returned.'
    }

    $script:TokenClientId = $AppClientId
    $script:TokenTenant = $Tenant
    $refresh = [string](Get-GraphResponseProperty -Response $Token -Name 'refresh_token')
    if (-not [string]::IsNullOrWhiteSpace($refresh)) {
        $script:RefreshToken = $refresh
    }

    return (Connect-WithAccessToken -AccessToken $accessToken)
}

function Connect-ViaSystemBrowser {
    param(
        [Parameter()]
        [string]$AppClientId
    )

    if ([string]::IsNullOrWhiteSpace($AppClientId)) {
        $AppClientId = $script:GraphPowerShellClientId
    }

    $tenant = 'organizations'
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $tenant = $TenantId.Trim()
    }
    $authority = "https://login.microsoftonline.com/$tenant"
    $pkce = New-PkcePair
    $state = [guid]::NewGuid().ToString('N')

    $listenerInfo = Get-AuthListener
    if ($null -eq $listenerInfo) {
        throw 'Could not start a local http://localhost listener for the browser redirect. Try -DeviceCode.'
    }

    $listener = $listenerInfo.Listener
    $redirect = [string]$listenerInfo.RedirectUri
    $parent = $null

    try {
        $script:AuthSkipRequested = $false
        $authUrl = Get-EntraAuthorizeUrl -Authority $authority -ClientId $AppClientId `
            -RedirectUri $redirect -State $state -CodeChallenge $pkce.Challenge

        Write-Host ""
        Write-Host "Opening your web browser to sign in to Microsoft Graph." -ForegroundColor Cyan
        Write-Host "Complete sign-in in the browser, then return here." -ForegroundColor Cyan

        if ($script:WinFormsLoaded) {
            $parent = New-AuthParentForm
        }

        $opened = Start-SystemBrowser -Url $authUrl
        if (-not $opened) {
            Write-Host "The browser could not be launched automatically. Open this URL:" -ForegroundColor Yellow
            Write-Host $authUrl -ForegroundColor White
        }

        $async = $null
        $deadline = [datetime]::UtcNow.AddMinutes(5)
        $code = $null
        $errorCode = $null
        $errorDesc = $null

        while ([datetime]::UtcNow -lt $deadline -and [string]::IsNullOrWhiteSpace($code)) {
            if ($script:AuthSkipRequested) {
                throw 'USER_SKIPPED_BROWSER'
            }

            $async = $listener.BeginGetContext($null, $null)
            $got = $false
            while ([datetime]::UtcNow -lt $deadline) {
                if ($script:AuthSkipRequested) {
                    throw 'USER_SKIPPED_BROWSER'
                }
                if ($async.AsyncWaitHandle.WaitOne(200)) {
                    $got = $true
                    break
                }
                try { [void][System.Windows.Forms.Application]::DoEvents() } catch { }
            }
            if (-not $got) {
                throw 'Timed out waiting for browser sign-in (5 minutes).'
            }

            $context = $listener.EndGetContext($async)
            $requestUri = $context.Request.Url
            $path = [string]$requestUri.AbsolutePath
            if ($path -match 'favicon') {
                try {
                    $context.Response.StatusCode = 404
                    $context.Response.Close()
                }
                catch { }
                continue
            }

            $returnedState = Get-QueryValue -Uri $requestUri -Name 'state'
            $thisCode = Get-QueryValue -Uri $requestUri -Name 'code'
            $thisError = Get-QueryValue -Uri $requestUri -Name 'error'
            $thisErrorDesc = Get-QueryValue -Uri $requestUri -Name 'error_description'
            $stateOk = [string]::Equals([string]$returnedState, $state, [System.StringComparison]::Ordinal)

            if (-not $stateOk) {
                Write-AuthBrowserResponse -Context $context -Title 'Waiting for sign-in' -Body 'This tab is from an older sign-in attempt. Use the newest browser window, or return to PowerShell.'
                continue
            }

            if (-not [string]::IsNullOrWhiteSpace($thisError)) {
                Write-AuthBrowserResponse -Context $context -Title 'Sign-in did not complete' -Body ([System.Net.WebUtility]::HtmlEncode("$thisError $thisErrorDesc"))
                throw "Browser sign-in failed: $thisError $thisErrorDesc"
            }

            if ([string]::IsNullOrWhiteSpace($thisCode)) {
                Write-AuthBrowserResponse -Context $context -Title 'Waiting for sign-in' -Body 'No authorization code was returned yet.'
                continue
            }

            Write-AuthBrowserResponse -Context $context -Title 'Sign-in complete' -Body 'You signed in successfully.'
            $code = $thisCode
        }

        if ([string]::IsNullOrWhiteSpace($code)) {
            throw 'Timed out waiting for browser sign-in (5 minutes).'
        }

        $tokBody = ConvertTo-FormUrlEncoded -Data @{
            client_id     = $AppClientId
            grant_type    = 'authorization_code'
            code          = $code
            redirect_uri  = $redirect
            code_verifier = $pkce.Verifier
            scope         = $script:GraphScopeString
        }
        $token = Invoke-RestMethod -Method Post -Uri "$authority/oauth2/v2.0/token" `
            -ContentType 'application/x-www-form-urlencoded' -Body $tokBody -ErrorAction Stop

        return (Complete-GraphTokenResponse -Token $token -AppClientId $AppClientId -Tenant $tenant)
    }
    finally {
        if ($null -ne $parent) {
            try { $parent.Close() } catch { }
            try { $parent.Dispose() } catch { }
        }
        try { $listener.Stop() } catch { }
        try { $listener.Close() } catch { }
    }
}

function Connect-ViaRestDeviceCode {
    param(
        [Parameter()]
        [string]$AppClientId
    )

    if ([string]::IsNullOrWhiteSpace($AppClientId)) {
        $AppClientId = $script:GraphPowerShellClientId
    }

    $tenant = 'organizations'
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $tenant = $TenantId.Trim()
    }
    $authority = "https://login.microsoftonline.com/$tenant"

    $dcBody = ConvertTo-FormUrlEncoded -Data @{
        client_id = $AppClientId
        scope     = $script:GraphScopeString
    }

    $dc = Invoke-RestMethod -Method Post -Uri "$authority/oauth2/v2.0/devicecode" `
        -ContentType 'application/x-www-form-urlencoded' -Body $dcBody -ErrorAction Stop

    $verifyUrl = [string](Get-GraphResponseProperty -Response $dc -Name 'verification_uri')
    $userCode  = [string](Get-GraphResponseProperty -Response $dc -Name 'user_code')
    $completeUrl = [string](Get-GraphResponseProperty -Response $dc -Name 'verification_uri_complete')
    $openUrl = $verifyUrl
    if (-not [string]::IsNullOrWhiteSpace($completeUrl)) {
        $openUrl = $completeUrl
    }

    Write-Host ""
    Write-Host "To sign in, a web browser will open." -ForegroundColor Cyan
    Write-Host "If asked for a code, enter: $userCode" -ForegroundColor Cyan
    Write-Host "Waiting for sign-in..." -ForegroundColor Yellow

    if ($script:WinFormsLoaded) {
        try { [System.Windows.Forms.Clipboard]::SetText($userCode) } catch { }
        try {
            [void][System.Windows.Forms.MessageBox]::Show(
                ("A web browser will open for Microsoft sign-in.`r`n`r`nIf asked for a code, enter:`r`n`r`n{0}`r`n`r`nThe code is copied to the clipboard.`r`nClick OK, then finish sign-in in the browser. Leave this window running." -f $userCode),
                'Entra ID sign-in',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
        catch { }
    }

    $opened = Start-SystemBrowser -Url $openUrl
    if (-not $opened) {
        Write-Host "Open this URL manually: $openUrl" -ForegroundColor Yellow
        Write-Host "Enter code: $userCode" -ForegroundColor Yellow
    }
    else {
        Write-Host "(If the browser did not show a code prompt, enter $userCode at $verifyUrl)" -ForegroundColor Gray
    }

    $deadline = [datetime]::UtcNow.AddSeconds([int](Get-GraphResponseProperty -Response $dc -Name 'expires_in'))
    $intervalRaw = Get-GraphResponseProperty -Response $dc -Name 'interval'
    $interval = 5
    if ($null -ne $intervalRaw) { $interval = [Math]::Max(5, [int]$intervalRaw) }
    $deviceCode = [string](Get-GraphResponseProperty -Response $dc -Name 'device_code')
    $token = $null

    while ([datetime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds $interval
        try { [void][System.Windows.Forms.Application]::DoEvents() } catch { }
        try {
            $tokBody = ConvertTo-FormUrlEncoded -Data @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $AppClientId
                device_code = $deviceCode
            }
            $token = Invoke-RestMethod -Method Post -Uri "$authority/oauth2/v2.0/token" `
                -ContentType 'application/x-www-form-urlencoded' -Body $tokBody -ErrorAction Stop
            break
        }
        catch {
            $errText = Get-RestErrorText -ErrorRecord $_
            if ($errText -match 'authorization_pending|slow_down') { continue }
            throw "Device code token exchange failed: $errText"
        }
    }

    if (-not $token) {
        throw 'Sign-in timed out or was cancelled.'
    }

    $accessToken = [string](Get-GraphResponseProperty -Response $token -Name 'access_token')
    if ([string]::IsNullOrWhiteSpace($accessToken)) {
        throw 'Device code sign-in succeeded but no access_token was returned.'
    }

    return (Complete-GraphTokenResponse -Token $token -AppClientId $AppClientId -Tenant $tenant)
}

function Invoke-ConnectMgGraph {
    param([switch]$UseDeviceCode)

    $cmd = Get-Command Connect-MgGraph -ErrorAction Stop
    $params = @{
        Scopes      = $script:GraphScopeList
        ErrorAction = 'Stop'
    }
    if ($cmd.Parameters.ContainsKey('NoWelcome')) {
        $params['NoWelcome'] = $true
    }
    if ($UseDeviceCode) {
        $deviceParam = Get-ConnectMgGraphDeviceCodeParameter
        if ([string]::IsNullOrWhiteSpace($deviceParam)) {
            throw 'SDK_NO_DEVICE_CODE'
        }
        $params[$deviceParam] = $true
    }
    if (-not [string]::IsNullOrWhiteSpace($TenantId) -and $cmd.Parameters.ContainsKey('TenantId')) {
        $params['TenantId'] = $TenantId
    }
    if (-not [string]::IsNullOrWhiteSpace($ClientId) -and $cmd.Parameters.ContainsKey('ClientId')) {
        $params['ClientId'] = $ClientId
    }

    $parent = $null
    try {
        if ($UseDeviceCode) {
            Write-Host ""
            Write-Host "Device-code sign-in: a URL and code will appear below." -ForegroundColor Cyan
            Write-Host "Open the URL, enter the code, and finish signing in. Leave this window open." -ForegroundColor Cyan
        }
        else {
            Write-Host "Opening Windows Web Account Manager (WAM) sign-in..." -ForegroundColor Cyan
            if ($script:WinFormsLoaded) {
                $parent = New-AuthParentForm
            }
        }
        Connect-MgGraph @params | Out-Null
    }
    finally {
        if ($null -ne $parent) {
            try { $parent.Close() } catch { }
            try { $parent.Dispose() } catch { }
        }
    }
}

function Connect-WithDeviceCodeFlow {
    $appId = $script:GraphPowerShellClientId
    if (-not [string]::IsNullOrWhiteSpace($ClientId)) {
        $appId = $ClientId
    }

    # ISE / elevated hosts cannot use WAM. Prefer SDK device-code, then REST + browser.
    $env:AZURE_IDENTITY_DISABLE_CP1 = 'true'
    $env:MSAL_DESKTOP_APP_USE_WAM = '0'

    try {
        Invoke-ConnectMgGraph -UseDeviceCode
        return
    }
    catch {
        $msg = Get-GraphErrorMessage -ErrorRecord $_
        Write-Host "SDK device-code sign-in was not available or failed: $msg" -ForegroundColor Yellow
        Write-Host "Opening a browser for device-code sign-in instead..." -ForegroundColor Yellow
    }

    [void](Connect-ViaRestDeviceCode -AppClientId $appId)
}

function Connect-EntraGraph {
    if (Test-GraphContextHasRequiredScopes) {
        $ctx = $null
        try { $ctx = Get-MgContext -ErrorAction SilentlyContinue } catch { }
        $account = ''
        if ($ctx -and $ctx.Account) { $account = [string]$ctx.Account }
        if ([string]::IsNullOrWhiteSpace($account)) {
            Write-Host "Already connected to Microsoft Graph." -ForegroundColor Green
        }
        else {
            Write-Host "Already connected to Microsoft Graph as $account." -ForegroundColor Green
        }
        return
    }

    Write-Host "Sign in with an account that can read authentication method details" -ForegroundColor Gray
    Write-Host "(for example Global Reader, Authentication Admin, or Privileged Auth Admin)." -ForegroundColor Gray

    $skipWam = Test-ShouldSkipWam -ForceDeviceCode:$DeviceCode
    if ($skipWam) {
        if (Test-IsPowerShellIse) {
            Write-Host "PowerShell ISE detected. WAM does not work in ISE, so a web browser will be used to sign in." -ForegroundColor Cyan
        }
        elseif (Test-IsProcessElevated) {
            Write-Host "Administrator session detected. Skipping WAM (it fails when elevated) and opening a browser to sign in." -ForegroundColor Cyan
        }
        Connect-WithDeviceCodeFlow
        return
    }

    try {
        Invoke-ConnectMgGraph
    }
    catch {
        $msg = Get-GraphErrorMessage -ErrorRecord $_
        Write-Host "Windows WAM sign-in failed: $msg" -ForegroundColor Yellow
        Write-Host "Falling back to browser device-code sign-in (ISE-safe)..." -ForegroundColor Yellow
        try {
            Connect-WithDeviceCodeFlow
        }
        catch {
            $msg2 = Get-GraphErrorMessage -ErrorRecord $_
            $hint = @(
                'Could not sign in to Microsoft Graph.',
                $msg,
                $msg2,
                '',
                'In PowerShell ISE, press F5 to run this script; a browser will open to sign in.',
                'If you are in an Administrator window, WAM cannot be used — the script will use the browser instead.'
            ) -join [Environment]::NewLine
            throw $hint
        }
    }
}

function Get-GraphErrorMessage {
    param($ErrorRecord)

    if ($null -eq $ErrorRecord) { return '' }

    $parts = New-Object System.Collections.Generic.List[string]
    $ex = $null

    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $ex = $ErrorRecord.Exception
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            [void]$parts.Add([string]$ErrorRecord.ErrorDetails.Message)
        }
    }
    elseif ($ErrorRecord -is [System.Exception]) {
        $ex = $ErrorRecord
    }
    else {
        return [string]$ErrorRecord
    }

    while ($null -ne $ex) {
        if (-not [string]::IsNullOrWhiteSpace([string]$ex.Message)) {
            [void]$parts.Add([string]$ex.Message)
        }
        $ex = $ex.InnerException
    }

    $seen = @{}
    $unique = New-Object System.Collections.Generic.List[string]
    foreach ($p in $parts) {
        if (-not $seen.ContainsKey($p)) {
            $seen[$p] = $true
            [void]$unique.Add($p)
        }
    }
    return ($unique -join ' | ')
}

function Get-RestErrorText {
    param($ErrorRecord)

    $chunks = New-Object System.Collections.Generic.List[string]
    $fromGraph = Get-GraphErrorMessage -ErrorRecord $ErrorRecord
    if (-not [string]::IsNullOrWhiteSpace($fromGraph)) {
        [void]$chunks.Add($fromGraph)
    }

    try {
        $ex = $null
        if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
            $ex = $ErrorRecord.Exception
        }
        elseif ($ErrorRecord -is [System.Exception]) {
            $ex = $ErrorRecord
        }

        $response = $null
        while ($null -ne $ex -and $null -eq $response) {
            try {
                if ($ex.Response) { $response = $ex.Response }
            }
            catch { }
            $ex = $ex.InnerException
        }

        if ($response) {
            $stream = $response.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                try {
                    $body = $reader.ReadToEnd()
                    if (-not [string]::IsNullOrWhiteSpace($body)) {
                        [void]$chunks.Add([string]$body)
                    }
                }
                finally {
                    $reader.Close()
                }
            }
        }
    }
    catch { }

    return ($chunks -join ' | ')
}

function Test-TransientGraphError {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
    return ($Message -match '429|Too Many Requests|503|Server Busy|temporarily unavailable|timeout|timed out')
}

function Update-GraphAccessToken {
    if ([string]::IsNullOrWhiteSpace($script:RefreshToken) -or [string]::IsNullOrWhiteSpace($script:TokenClientId)) {
        return $false
    }

    $tenant = $script:TokenTenant
    if ([string]::IsNullOrWhiteSpace($tenant)) { $tenant = 'organizations' }
    $authority = "https://login.microsoftonline.com/$tenant"

    try {
        $tokBody = ConvertTo-FormUrlEncoded -Data @{
            client_id     = $script:TokenClientId
            grant_type    = 'refresh_token'
            refresh_token = $script:RefreshToken
            scope         = $script:GraphScopeString
        }
        $token = Invoke-RestMethod -Method Post -Uri "$authority/oauth2/v2.0/token" `
            -ContentType 'application/x-www-form-urlencoded' -Body $tokBody -ErrorAction Stop
        $accessToken = [string](Get-GraphResponseProperty -Response $token -Name 'access_token')
        if ([string]::IsNullOrWhiteSpace($accessToken)) { return $false }

        $refresh = [string](Get-GraphResponseProperty -Response $token -Name 'refresh_token')
        if (-not [string]::IsNullOrWhiteSpace($refresh)) {
            $script:RefreshToken = $refresh
        }
        [void](Connect-WithAccessToken -AccessToken $accessToken)
        return $true
    }
    catch {
        return $false
    }
}

function Invoke-GraphRestGet {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    if ([string]::IsNullOrWhiteSpace($script:AccessToken)) {
        throw 'No Graph access token is available.'
    }

    $headers = @{
        Authorization    = "Bearer $($script:AccessToken)"
        ConsistencyLevel = 'eventual'
    }
    return Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers -ErrorAction Stop
}

function Invoke-GraphGetWithRetry {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [int]$MaxAttempts = 6
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            if (-not [string]::IsNullOrWhiteSpace($script:AccessToken)) {
                return (Invoke-GraphRestGet -Uri $Uri)
            }
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
        }
        catch {
            $msg = Get-GraphErrorMessage -ErrorRecord $_
            $unauthorized = ($msg -match '401|Unauthorized|InvalidAuthenticationToken|expired')
            if ($unauthorized -and (Update-GraphAccessToken)) {
                continue
            }

            $transient = Test-TransientGraphError -Message $msg
            if (-not $transient -or $attempt -eq $MaxAttempts) {
                throw
            }

            $waitSeconds = [Math]::Min([Math]::Pow(2, $attempt), 32)
            if ($msg -match 'Retry-After[:\s]+(\d+)') {
                $waitSeconds = [int]$Matches[1]
            }
            Write-Host "Graph throttled/unavailable. Retrying in $waitSeconds second(s) (attempt $attempt of $MaxAttempts)..." -ForegroundColor Yellow
            Start-Sleep -Seconds $waitSeconds
        }
    }
}

function ConvertTo-UserObject {
    param($Payload)

    if ($null -eq $Payload) { return $null }

    return [pscustomobject]@{
        Id                = [string](Get-GraphResponseProperty -Response $Payload -Name 'id')
        DisplayName       = [string](Get-GraphResponseProperty -Response $Payload -Name 'displayName')
        UserPrincipalName = [string](Get-GraphResponseProperty -Response $Payload -Name 'userPrincipalName')
        Mail              = [string](Get-GraphResponseProperty -Response $Payload -Name 'mail')
        AccountEnabled    = (Get-GraphResponseProperty -Response $Payload -Name 'accountEnabled')
    }
}

function Find-EntraUser {
    param(
        [Parameter(Mandatory)]
        [string]$Identifier
    )

    $select = 'id,displayName,userPrincipalName,mail,accountEnabled'

    if (Test-LooksLikeGuid -Value $Identifier) {
        $uri = "{0}/users/{1}?`$select={2}" -f $script:GraphBase, $Identifier, $select
        try {
            $byId = Invoke-GraphGetWithRetry -Uri $uri
            $user = ConvertTo-UserObject -Payload $byId
            if ($user -and -not [string]::IsNullOrWhiteSpace($user.Id)) {
                return $user
            }
        }
        catch {
            $msg = Get-GraphErrorMessage -ErrorRecord $_
            if ($msg -notmatch 'Request_ResourceNotFound|does not exist|NotFound|404') {
                throw
            }
        }
    }

    $escaped = Escape-ODataString -Value $Identifier
    $filters = @(
        "userPrincipalName eq '$escaped'",
        "mail eq '$escaped'"
    )

    foreach ($filter in $filters) {
        $uri = "{0}/users?`$filter={1}&`$select={2}&`$top=5" -f $script:GraphBase, [uri]::EscapeDataString($filter), $select
        $resp = Invoke-GraphGetWithRetry -Uri $uri
        $values = ConvertTo-ObjectList -Value (Get-GraphResponseProperty -Response $resp -Name 'value')
        if ($values.Count -gt 0) {
            return (ConvertTo-UserObject -Payload $values[0])
        }
    }

    # Last resort: UPN in the path (works for many cloud UPNs; guests with '#' often fail).
    $encoded = [uri]::EscapeDataString($Identifier)
    $uri = "{0}/users/{1}?`$select={2}" -f $script:GraphBase, $encoded, $select
    try {
        $byPath = Invoke-GraphGetWithRetry -Uri $uri
        $user = ConvertTo-UserObject -Payload $byPath
        if ($user -and -not [string]::IsNullOrWhiteSpace($user.Id)) {
            return $user
        }
    }
    catch {
        $msg = Get-GraphErrorMessage -ErrorRecord $_
        if ($msg -match 'Request_ResourceNotFound|does not exist|NotFound|404') {
            return $null
        }
        throw
    }

    return $null
}

function Get-EntraUserAuthMethods {
    param(
        [Parameter(Mandatory)]
        [string]$UserId
    )

    $methods = New-Object System.Collections.Generic.List[object]
    $uri = "{0}/users/{1}/authentication/methods" -f $script:GraphBase, [uri]::EscapeDataString($UserId)

    while (-not [string]::IsNullOrWhiteSpace($uri)) {
        $resp = Invoke-GraphGetWithRetry -Uri $uri
        $page = ConvertTo-ObjectList -Value (Get-GraphResponseProperty -Response $resp -Name 'value')
        foreach ($item in $page) {
            [void]$methods.Add($item)
        }
        $uri = [string](Get-GraphResponseProperty -Response $resp -Name '@odata.nextLink')
    }

    # Return the List as one object so 0/1 methods are not lost to pipeline unwrapping.
    return ,$methods
}

function Test-IsNotFoundMessage {
    param([string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
    return ($Message -match 'Request_ResourceNotFound|does not exist|not found|NotFound|404')
}

function Invoke-SelfTest {
    $failures = New-Object System.Collections.Generic.List[string]

    function Assert-Equal {
        param($Expected, $Actual, [string]$Name)
        if ($Expected -ne $Actual) {
            [void]$failures.Add("$Name : expected '$Expected', got '$Actual'")
        }
    }

    function Assert-True {
        param($Actual, [string]$Name)
        if (-not $Actual) {
            [void]$failures.Add("$Name : expected True, got '$Actual'")
        }
    }

    function Assert-False {
        param($Actual, [string]$Name)
        if ($Actual) {
            [void]$failures.Add("$Name : expected False, got '$Actual'")
        }
    }

    Assert-Equal "o''brien@contoso.com" (Escape-ODataString "o'brien@contoso.com") 'odata escape apostrophe'
    Assert-Equal '' (Escape-ODataString $null) 'odata escape null'
    Assert-Equal 0 (Get-ClampedPercent -Current 0 -Total 0) 'percent empty total'
    Assert-Equal 50 (Get-ClampedPercent -Current 1 -Total 2) 'percent halfway'
    Assert-Equal 100 (Get-ClampedPercent -Current 5 -Total 5) 'percent complete'
    Assert-Equal 100 (Get-ClampedPercent -Current 6 -Total 5) 'percent over'

    $row = [PSCustomObject]@{ UserPrincipalName = '  a@b.com  '; Other = 1 }
    Assert-Equal 'a@b.com' (Get-UpnFromRow -Row $row -ColumnName 'UserPrincipalName') 'trim upn'
    Assert-Equal '' (Get-UpnFromRow -Row $row -ColumnName 'Missing') 'missing column'
    Assert-Equal '' (Get-UpnFromRow -Row ([PSCustomObject]@{ UserPrincipalName = $null }) -ColumnName 'UserPrincipalName') 'null upn'

    $csvRows = @(
        [PSCustomObject]@{ Email = 'one@contoso.com'; Name = 'One' }
    )
    $resolved = Resolve-UpnColumn -Rows $csvRows
    Assert-Equal 'Email' $resolved.ColumnName 'detect email column'
    Assert-True $resolved.AutoDetected 'email auto-detected'

    $idRows = @(
        [PSCustomObject]@{ ObjectId = '11111111-1111-1111-1111-111111111111' }
    )
    $idResolved = Resolve-UpnColumn -Rows $idRows
    Assert-Equal 'ObjectId' $idResolved.ColumnName 'detect object id column'

    $fallbackRows = @(
        [PSCustomObject]@{ WeirdCol = 'x@y.com' }
    )
    $fallback = Resolve-UpnColumn -Rows $fallbackRows
    Assert-Equal 'WeirdCol' $fallback.ColumnName 'fallback first column'
    Assert-False $fallback.AutoDetected 'fallback not auto-detected'

    Assert-True (Test-LooksLikeGuid '28c10230-6103-485e-b985-444c60001490') 'guid parse'
    Assert-False (Test-LooksLikeGuid 'user@contoso.com') 'upn is not guid'

    $ht = @{ value = @(@{ id = '1' }, @{ id = '2' }); '@odata.nextLink' = $null }
    $extracted = Get-GraphResponseProperty -Response $ht -Name 'value'
    $extractedList = ConvertTo-ObjectList -Value $extracted
    Assert-Equal 2 $extractedList.Count 'dictionary value extraction count'
    Assert-Equal $null (Get-GraphResponseProperty -Response $ht -Name '@odata.nextLink') 'null nextLink'

    $generic = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    $generic.Add('@odata.type', '#microsoft.graph.passwordAuthenticationMethod')
    $generic.Add('id', $script:PasswordMethodId)
    Assert-Equal '#microsoft.graph.passwordAuthenticationMethod' (Get-GraphResponseProperty -Response $generic -Name '@odata.type') 'generic dictionary odata.type'
    Assert-True (Test-IsPasswordAuthenticationMethod -Method $generic) 'generic dict is password'

    $passwordOnly = @(
        @{
            '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod'
            id            = $script:PasswordMethodId
        }
    )
    $invPassword = Get-AuthenticationMethodInventory -Methods $passwordOnly
    Assert-False $invPassword.HasNonPasswordMethod 'password-only has no other method'
    Assert-Equal 'Password' $invPassword.RegisteredMethods 'password-only friendly name'
    Assert-Equal 'Password only - no other method registered' $invPassword.Detail 'password-only detail'

    $passwordNoType = @(
        @{ id = $script:PasswordMethodId }
    )
    $invById = Get-AuthenticationMethodInventory -Methods $passwordNoType
    Assert-False $invById.HasNonPasswordMethod 'password identified by well-known id without type'
    Assert-Equal 'Password' $invById.RegisteredMethods 'password by id friendly name'

    $emptyInv = Get-AuthenticationMethodInventory -Methods @()
    Assert-False $emptyInv.HasNonPasswordMethod 'empty methods is missing'
    Assert-Equal 'No methods registered' $emptyInv.Detail 'empty methods detail'
    Assert-Equal 0 $emptyInv.MethodCount 'empty methods count'

    $listPassword = New-Object System.Collections.Generic.List[object]
    [void]$listPassword.Add(@{
            '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod'
            id            = $script:PasswordMethodId
        })
    $invList = Get-AuthenticationMethodInventory -Methods $listPassword
    Assert-False $invList.HasNonPasswordMethod 'List[object] password-only is missing'
    Assert-Equal 1 $invList.MethodCount 'List[object] password-only count'

    $emptyList = New-Object System.Collections.Generic.List[object]
    $invEmptyList = Get-AuthenticationMethodInventory -Methods $emptyList
    Assert-False $invEmptyList.HasNonPasswordMethod 'empty List[object] is missing'
    Assert-Equal 0 $invEmptyList.MethodCount 'empty List[object] count'

    $nullInv = Get-AuthenticationMethodInventory -Methods $null
    Assert-False $nullInv.HasNonPasswordMethod 'null methods is missing'

    $withAuthenticator = @(
        @{
            '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod'
            id            = $script:PasswordMethodId
        },
        @{
            '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'
            id            = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            displayName   = 'iPhone'
        }
    )
    $invAuth = Get-AuthenticationMethodInventory -Methods $withAuthenticator
    Assert-True $invAuth.HasNonPasswordMethod 'authenticator counts as non-password'
    Assert-True ($invAuth.RegisteredMethods -match 'Microsoft Authenticator') 'authenticator friendly name present'
    Assert-Equal 2 $invAuth.MethodCount 'authenticator+password count'

    $phoneOnly = @(
        [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'
            id            = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        }
    )
    $invPhone = Get-AuthenticationMethodInventory -Methods $phoneOnly
    Assert-True $invPhone.HasNonPasswordMethod 'phone without password still counts'

    $typeNoHash = @{
        '@odata.type' = 'microsoft.graph.fido2AuthenticationMethod'
        id            = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    }
    Assert-False (Test-IsPasswordAuthenticationMethod -Method $typeNoHash) 'fido2 is not password'
    $invFido = Get-AuthenticationMethodInventory -Methods @($typeNoHash)
    Assert-True $invFido.HasNonPasswordMethod 'fido2 is a non-password method'
    Assert-Equal 'FIDO2' $invFido.RegisteredMethods 'fido2 friendly name'

    $sdkStyle = [pscustomobject]@{
        Id                   = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        AdditionalProperties = @{
            '@odata.type' = '#microsoft.graph.emailAuthenticationMethod'
            emailAddress  = 'alt@contoso.com'
        }
    }
    Assert-False (Test-IsPasswordAuthenticationMethod -Method $sdkStyle) 'sdk-style email is not password'
    $invEmail = Get-AuthenticationMethodInventory -Methods @($sdkStyle)
    Assert-True $invEmail.HasNonPasswordMethod 'sdk-style email is a non-password method'
    Assert-Equal 'Email' $invEmail.RegisteredMethods 'sdk-style email friendly name'

    $unknownNonPassword = @{ id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee' }
    $invUnknown = Get-AuthenticationMethodInventory -Methods @($unknownNonPassword)
    Assert-True $invUnknown.HasNonPasswordMethod 'unknown non-password id still counts as other method'

    $odataProp = [pscustomobject]@{
        OdataType = '#microsoft.graph.softwareOathAuthenticationMethod'
        Id        = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    }
    $invOath = Get-AuthenticationMethodInventory -Methods @($odataProp)
    Assert-True $invOath.HasNonPasswordMethod 'OdataType property is honored'
    Assert-Equal 'Software OATH' $invOath.RegisteredMethods 'software oath friendly name'

    Assert-Equal 'password' (Get-NormalizedMethodType '#microsoft.graph.passwordAuthenticationMethod') 'normalize password type'
    Assert-Equal 'microsoftauthenticator' (Get-NormalizedMethodType '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod') 'normalize authenticator type'

    $singleCsv = [PSCustomObject]@{ UserPrincipalName = 'only@contoso.com' }
    $wrapped = @($singleCsv)
    Assert-Equal 1 $wrapped.Count 'single-row csv wrapped as array has count 1'

    Assert-True (Test-IsNotFoundMessage 'Request_ResourceNotFound: User was not found') 'not found message'
    Assert-False (Test-IsNotFoundMessage 'Access denied') 'access denied is not not-found'
    Assert-True (Test-TransientGraphError '429 Too Many Requests') '429 is transient'
    Assert-False (Test-TransientGraphError 'Authorization_RequestDenied') 'auth denied is not transient'

    $form = ConvertTo-FormUrlEncoded -Data @{ client_id = 'abc'; scope = 'User.Read' }
    Assert-True ($form -match 'client_id=abc') 'form encode client_id'
    Assert-True ($form -match 'scope=User\.Read') 'form encode scope'

    $pkce = New-PkcePair
    Assert-True ($pkce.Verifier.Length -ge 43) 'pkce verifier length'
    Assert-True ($pkce.Challenge.Length -ge 43) 'pkce challenge length'
    Assert-True ($pkce.Verifier -notmatch '[+/=]') 'pkce verifier is base64url'

    $authUrl = Get-EntraAuthorizeUrl -Authority 'https://login.microsoftonline.com/organizations' `
        -ClientId 'abc' -RedirectUri 'http://localhost:8400/' -State 'st' -CodeChallenge 'ch'
    Assert-True ($authUrl -match 'response_type=code') 'authorize url response_type'
    Assert-True ($authUrl -match 'code_challenge_method=S256') 'authorize url pkce method'
    Assert-True ($authUrl -match 'prompt=select_account') 'authorize url prompt'
    Assert-True ($authUrl -match 'redirect_uri=http%3A%2F%2Flocalhost%3A8400%2F') 'authorize url redirect'

    $pubIds = Get-PublicClientIdList
    Assert-Equal $script:GraphPowerShellClientId $pubIds[0] 'graph powershell client is default'
    Assert-Equal 1 $pubIds.Count 'only graph powershell is used by default'

    $consent = Get-GraphAdminConsentUrl
    Assert-True ($consent -match 'adminconsent') 'admin consent url'
    Assert-True ($consent -match $script:GraphPowerShellClientId) 'admin consent uses graph powershell app'

    try { $null = Test-IsProcessElevated } catch {
        [void]$failures.Add('Test-IsProcessElevated threw')
    }
    try { $null = Test-IsPowerShellIse } catch {
        [void]$failures.Add('Test-IsPowerShellIse threw')
    }
    Assert-True (Test-ShouldSkipWam -ForceDeviceCode) 'device-code switch skips WAM'

    $callback = [uri]'http://localhost:8400/?code=abc%2Fde&state=xyz'
    Assert-Equal 'abc/de' (Get-QueryValue -Uri $callback -Name 'code') 'query code decode'
    Assert-Equal 'xyz' (Get-QueryValue -Uri $callback -Name 'state') 'query state'

    try { $null = Get-ConnectMgGraphDeviceCodeParameter } catch {
        [void]$failures.Add('Get-ConnectMgGraphDeviceCodeParameter threw')
    }

    try {
        $inner = New-Object System.Exception 'broker window handle missing'
        throw (New-Object System.Exception 'InteractiveBrowserCredential authentication failed: ', $inner)
    }
    catch {
        $msg = Get-GraphErrorMessage -ErrorRecord $_
        Assert-True ($msg -match 'broker window handle missing') 'inner exception is surfaced'
        Assert-True ($msg -match 'InteractiveBrowserCredential') 'outer exception is surfaced'
        $restText = Get-RestErrorText -ErrorRecord $_
        Assert-True ($restText -match 'InteractiveBrowserCredential') 'rest error text includes outer message'
    }

    if ($failures.Count -gt 0) {
        Write-Host 'Self-test FAILED:' -ForegroundColor Red
        foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
        exit 1
    }

    Write-Host 'All self-tests passed.' -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if ($SelfTest) {
    Invoke-SelfTest
}

Write-Section "Entra ID - Users Without a Registered Authentication Method"

if ($script:UseGui) {
    Initialize-WinForms
}

# 1. Ensure Graph SDK is available -------------------------------------------
try {
    Ensure-GraphModule
}
catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# 2. Pick the input CSV ------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($InputCsv)) {
    Write-Host ""
    Write-Host "Please select the CSV file containing the users to check..." -ForegroundColor Green
    $InputCsv = Select-InputFile
    if (-not $InputCsv) {
        Write-Host "No input file selected. Exiting." -ForegroundColor Red
        exit 0
    }
}
elseif (-not (Test-Path -LiteralPath $InputCsv)) {
    Write-Host "Input CSV not found: $InputCsv" -ForegroundColor Red
    exit 1
}
Write-Host "Selected input file: $InputCsv" -ForegroundColor Gray

# 3. Import the CSV & determine UPN column -----------------------------------
try {
    # Force array so a single-row CSV does not break .Count / foreach logic.
    $users = @(Import-Csv -Path $InputCsv -ErrorAction Stop)
}
catch {
    Write-Host "Failed to read the CSV: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ($users.Count -eq 0) {
    Write-Host "The selected CSV contains no rows. Exiting." -ForegroundColor Red
    exit 1
}

$columnInfo = Resolve-UpnColumn -Rows $users -PromptIfMissing
$upnColumn = $columnInfo.ColumnName
Write-Host "Using column '$upnColumn' as the user identifier." -ForegroundColor Gray
Write-Host "Loaded $($users.Count) row(s) from the CSV." -ForegroundColor Gray

# 4. Pick the output location ------------------------------------------------
if ([string]::IsNullOrWhiteSpace($OutputCsv)) {
    Write-Host ""
    Write-Host "Please choose where to save the report..." -ForegroundColor Green
    $OutputCsv = Select-OutputFile
    if (-not $OutputCsv) {
        Write-Host "No output location selected. Exiting." -ForegroundColor Red
        exit 0
    }
}
Write-Host "Report will be saved to: $OutputCsv" -ForegroundColor Gray

# 5. Connect to Microsoft Graph ----------------------------------------------
Write-Section "Connecting to Microsoft Graph"

try {
    Connect-EntraGraph
}
catch {
    Write-Host "Failed to connect to Microsoft Graph:" -ForegroundColor Red
    Write-Host (Get-GraphErrorMessage -ErrorRecord $_) -ForegroundColor Red
    exit 1
}

$context = $null
try { $context = Get-MgContext -ErrorAction SilentlyContinue } catch { }
$connectedAs = ''
try {
    if ($context -and $context.Account) { $connectedAs = [string]$context.Account }
} catch { }
if (-not [string]::IsNullOrWhiteSpace($connectedAs)) {
    Write-Host "Connected as: $connectedAs" -ForegroundColor Green
}
else {
    Write-Host "Connected to Microsoft Graph." -ForegroundColor Green
}

# 6. Process each user -------------------------------------------------------
Write-Section "Checking authentication methods"

$report  = New-Object System.Collections.Generic.List[object]
$total   = $users.Count
$counter = 0

Show-ProgressUi -Total $total

try {
    foreach ($row in $users) {
        $counter++
        $upn = Get-UpnFromRow -Row $row -ColumnName $upnColumn
        Update-ProgressUi -Current $counter -Total $total -Upn $upn

        if ([string]::IsNullOrWhiteSpace($upn)) {
            [void]$report.Add((New-ReportRow `
                -CsvIdentifier $upn `
                -Status 'Skipped' `
                -HasNonPasswordMethod $false `
                -Detail 'Empty/blank identifier in CSV row'))
            continue
        }

        try {
            $entraUser = Find-EntraUser -Identifier $upn
            if ($null -eq $entraUser -or [string]::IsNullOrWhiteSpace($entraUser.Id)) {
                [void]$report.Add((New-ReportRow `
                    -CsvIdentifier $upn `
                    -Status 'User not found' `
                    -HasNonPasswordMethod $false `
                    -Detail 'No Entra ID user matched this UPN, mail, or object id'))
                continue
            }

            $methods = Get-EntraUserAuthMethods -UserId $entraUser.Id
            $inventory = Get-AuthenticationMethodInventory -Methods $methods

            if (-not $inventory.HasNonPasswordMethod) {
                [void]$report.Add((New-ReportRow `
                    -CsvIdentifier $upn `
                    -UserPrincipalName $entraUser.UserPrincipalName `
                    -DisplayName $entraUser.DisplayName `
                    -AccountEnabled $entraUser.AccountEnabled `
                    -Status 'MISSING auth method' `
                    -HasNonPasswordMethod $false `
                    -RegisteredMethods $inventory.RegisteredMethods `
                    -MethodCount $inventory.MethodCount `
                    -Detail $inventory.Detail))
            }
            elseif ($IncludeAll) {
                [void]$report.Add((New-ReportRow `
                    -CsvIdentifier $upn `
                    -UserPrincipalName $entraUser.UserPrincipalName `
                    -DisplayName $entraUser.DisplayName `
                    -AccountEnabled $entraUser.AccountEnabled `
                    -Status 'Has other method' `
                    -HasNonPasswordMethod $true `
                    -RegisteredMethods $inventory.RegisteredMethods `
                    -MethodCount $inventory.MethodCount `
                    -Detail $inventory.Detail))
            }
        }
        catch {
            $msg = Get-GraphErrorMessage -ErrorRecord $_
            $status = if (Test-IsNotFoundMessage -Message $msg) { 'User not found' } else { 'Error' }
            [void]$report.Add((New-ReportRow `
                -CsvIdentifier $upn `
                -Status $status `
                -HasNonPasswordMethod $false `
                -Detail $msg))
        }
    }
}
finally {
    Close-ProgressUi
}

# 7. Export report -----------------------------------------------------------
Write-Section "Results"

try {
    if ($report.Count -eq 0) {
        # Header-only CSV so Excel / downstream jobs still open cleanly.
        $header = New-ReportRow
        $header | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        $csvLines = @(Get-Content -LiteralPath $OutputCsv)
        if ($csvLines.Count -gt 1) {
            Set-Content -LiteralPath $OutputCsv -Value $csvLines[0] -Encoding UTF8
        }
    }
    else {
        $report | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    }
}
catch {
    Write-Host "Failed to write the report: $($_.Exception.Message)" -ForegroundColor Red
    try { Disconnect-MgGraph | Out-Null } catch { }
    exit 1
}

$missingCount = @($report | Where-Object { $_.Status -eq 'MISSING auth method' }).Count
$notFound     = @($report | Where-Object { $_.Status -eq 'User not found' }).Count
$errors       = @($report | Where-Object { $_.Status -eq 'Error' }).Count
$skipped      = @($report | Where-Object { $_.Status -eq 'Skipped' }).Count
$hasOther     = @($report | Where-Object { $_.Status -eq 'Has other method' }).Count

Write-Host ""
Write-Host "Total users checked        : $total"
Write-Host "Missing an auth method     : $missingCount" -ForegroundColor Yellow
Write-Host "Users not found in Entra ID: $notFound"
Write-Host "Errors                     : $errors"
Write-Host "Skipped (blank CSV rows)   : $skipped"
if ($IncludeAll) {
    Write-Host "Has a non-password method  : $hasOther"
}
Write-Host ""
Write-Host "Report saved to: $OutputCsv" -ForegroundColor Green

# 8. Offer to open the report ------------------------------------------------
if ($script:UseGui) {
    $open = Read-Host "Open the report now? (Y/N)"
    if ($open -match '^(y|yes)$') {
        Invoke-Item -Path $OutputCsv
    }
}

try { Disconnect-MgGraph | Out-Null } catch { }
Write-Host "Done. Disconnected from Microsoft Graph." -ForegroundColor Cyan

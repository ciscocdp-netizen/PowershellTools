#Requires -Version 5.1
<#
.SYNOPSIS
    Finds enabled Entra ID users who have SMS or voice phone authentication methods
    registered, and exports a CSV report (with Email Address and Employee ID).

.DESCRIPTION
    Signs in to Microsoft Graph, reads authentication method registration details,
    and reports users who can authenticate with SMS and/or voice call MFA.

    Microsoft Graph's userRegistrationDetails API only returns enabled users, so
    disabled accounts are already excluded. The script still verifies accountEnabled
    when enriching each user and skips anyone who is disabled.

    A user is included when ANY of the following is true:
      - methodsRegistered contains mobilePhone, officePhone, or alternateMobilePhone
      - userPreferredMethodForSecondaryAuthentication is sms / voiceMobile /
        voiceAlternateMobile / voiceOffice
      - systemPreferredAuthenticationMethods contains sms or a voice* value

    Output columns include DisplayName, UserPrincipalName, EmailAddress, EmployeeID,
    AccountEnabled, registered phone methods, preferred MFA method, and an SMS/Voice
    classification.

    When -OutputCsv is omitted, a Save File dialog chooses where to place the report.

.PARAMETER OutputCsv
    Optional path for the CSV report. When omitted, a Save File dialog is shown.

.PARAMETER TenantId
    Optional Entra tenant (contoso.onmicrosoft.com or a Tenant ID GUID). Leave blank
    for interactive browser / account picker sign-in.

.PARAMETER ClientId
    Optional public-client app ID. Defaults to the Microsoft Graph PowerShell app.

.PARAMETER DeviceCode
    Use device-code sign-in instead of interactive browser login.

.PARAMETER SelfTest
    Runs built-in unit tests for SMS/voice classification helpers and exits.
    Does not contact Microsoft Graph or show dialogs.

.EXAMPLE
    .\Get-EntraSmsVoiceAuthUsers.ps1

.EXAMPLE
    .\Get-EntraSmsVoiceAuthUsers.ps1 -OutputCsv .\SmsVoiceUsers.csv

.EXAMPLE
    .\Get-EntraSmsVoiceAuthUsers.ps1 -TenantId contoso.onmicrosoft.com

.EXAMPLE
    .\Get-EntraSmsVoiceAuthUsers.ps1 -DeviceCode

.EXAMPLE
    .\Get-EntraSmsVoiceAuthUsers.ps1 -SelfTest

.NOTES
    Required Graph delegated permissions (admin consent typically needed):
      - AuditLog.Read.All   (authentication method registration report)
      - User.Read.All       (mail, employeeId, accountEnabled)

    Least-privileged Entra roles that can run the registration report:
      Reports Reader, Security Reader, Security Administrator, Global Reader

    Interactive browser sign-in is the default. The script relaunches in STA and
    shows a small parent window so Windows WAM / MSAL can attach a window handle.
    Azure PowerShell interactive login is used as a browser fallback. Pass
    -DeviceCode only if interactive login is blocked in your environment.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputCsv,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$ClientId = '14d82eec-204b-4c2f-b113-9d477e6ee18c', # Microsoft Graph PowerShell

    [switch]$DeviceCode,

    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Avoid MSAL WAM "A window handle must be configured" in console hosts.
$env:AZURE_IDENTITY_DISABLE_CP1 = 'true'
$env:MSAL_DESKTOP_APP_USE_WAM = '0'

$script:GraphScopeList = @('AuditLog.Read.All', 'User.Read.All')
$script:GraphScopes = 'AuditLog.Read.All User.Read.All offline_access openid profile'
$script:GraphPowerShellClientId = '14d82eec-204b-4c2f-b113-9d477e6ee18c'
$script:AzurePowerShellClientId = '1950a258-227b-4e31-a9cf-717495945fc2'
$script:AccessToken = $null
$script:TokenExpiresUtc = [datetime]::MinValue
$script:AuthMode = ''
$script:SignedInUpn = ''
$script:WinFormsLoaded = $false
# Interactive browser/WAM and Save dialogs need WinForms + STA (even with -OutputCsv).
$script:UseGui = -not $SelfTest

if ([string]::IsNullOrWhiteSpace($ClientId)) {
    $ClientId = $script:GraphPowerShellClientId
}

$script:PhoneMethodValues = @(
    'mobilePhone',
    'officePhone',
    'alternateMobilePhone'
)

$script:SmsPreferredValues = @('sms')
$script:VoicePreferredValues = @(
    'voiceMobile',
    'voiceAlternateMobile',
    'voiceOffice'
)

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
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        [void]$argParts.Add('-TenantId')
        [void]$argParts.Add(('"{0}"' -f $TenantId))
    }
    if (-not [string]::IsNullOrWhiteSpace($ClientId)) {
        [void]$argParts.Add('-ClientId')
        [void]$argParts.Add(('"{0}"' -f $ClientId))
    }
    if ($DeviceCode) {
        [void]$argParts.Add('-DeviceCode')
    }

    Write-Host "Relaunching in STA mode so interactive sign-in and file dialogs work..." -ForegroundColor Yellow
    $proc = Start-Process -FilePath $exe -ArgumentList ($argParts -join ' ') -Wait -PassThru -NoNewWindow
    if ($null -eq $proc.ExitCode) { exit 1 }
    exit $proc.ExitCode
}

#endregion

#region Helpers ----------------------------------------------------------------

function Show-UiMessage {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter(Mandatory)]
        [string]$Title,

        [ValidateSet('Information', 'Error', 'Warning')]
        [string]$Icon = 'Information'
    )

    if ($script:UseGui -and $script:WinFormsLoaded) {
        $boxIcon = [System.Windows.Forms.MessageBoxIcon]::$Icon
        [void][System.Windows.Forms.MessageBox]::Show(
            $Message,
            $Title,
            [System.Windows.Forms.MessageBoxButtons]::OK,
            $boxIcon
        )
        return
    }

    if ($Icon -eq 'Error') {
        Write-Host $Message -ForegroundColor Red
    }
    elseif ($Icon -eq 'Warning') {
        Write-Warning $Message
    }
    else {
        Write-Host $Message
    }
}

function Get-DefaultPickerDirectory {
    foreach ($special in @('Desktop', 'MyDocuments')) {
        $path = [Environment]::GetFolderPath($special)
        if ($path -and (Test-Path -LiteralPath $path)) {
            return $path
        }
    }
    return (Get-Location).Path
}

function Show-OwnedDialog {
    param($Dialog)

    $owner = New-Object System.Windows.Forms.Form
    $owner.TopMost = $true
    $owner.ShowInTaskbar = $false
    $owner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
    $owner.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $owner.Width = 1
    $owner.Height = 1
    $owner.Opacity = 0
    [void]$owner.Show()
    try {
        return $Dialog.ShowDialog($owner)
    }
    finally {
        $owner.Close()
        $owner.Dispose()
    }
}

function Select-OutputCsv {
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Title = 'Choose where to save the Entra SMS/Voice auth report'
    $dialog.Filter = 'CSV Files (*.csv)|*.csv|All Files (*.*)|*.*'
    $dialog.FileName = "EntraSmsVoiceAuthUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $dialog.DefaultExt = 'csv'
    $dialog.AddExtension = $true
    $dialog.OverwritePrompt = $true
    $dialog.CheckPathExists = $true
    $dialog.RestoreDirectory = $true
    $dialog.InitialDirectory = Get-DefaultPickerDirectory

    try {
        $result = Show-OwnedDialog -Dialog $dialog
        if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
            Write-Warning 'No output file selected. Exiting.'
            exit 0
        }
        return $dialog.FileName
    }
    finally {
        $dialog.Dispose()
    }
}

function Escape-ODataString {
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    return ($Value -replace "'", "''")
}

function ConvertTo-StringArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
        return @($Value)
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.Generic.List[string]
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            $text = [string]$item
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                [void]$list.Add($text.Trim())
            }
        }
        return @($list)
    }

    $single = [string]$Value
    if ([string]::IsNullOrWhiteSpace($single)) { return @() }
    return @($single.Trim())
}

function Test-StringInSet {
    param(
        [string]$Value,
        [string[]]$Set
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    foreach ($candidate in $Set) {
        if ([string]::Equals($Value, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
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
        if ($Response.Contains($Name)) {
            return $Response[$Name]
        }
        foreach ($key in @($Response.Keys)) {
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $Response[$key]
            }
        }
        return $null
    }

    $prop = $Response.PSObject.Properties[$Name]
    if ($null -ne $prop) {
        return $prop.Value
    }
    return $null
}

function Get-SmsVoiceClassification {
    param(
        [Parameter(Mandatory)]
        $Registration
    )

    $methods = ConvertTo-StringArray (Get-GraphResponseProperty -Response $Registration -Name 'methodsRegistered')
    $preferred = [string](Get-GraphResponseProperty -Response $Registration -Name 'userPreferredMethodForSecondaryAuthentication')
    if ([string]::IsNullOrWhiteSpace($preferred)) { $preferred = '' }
    $systemPreferred = ConvertTo-StringArray (Get-GraphResponseProperty -Response $Registration -Name 'systemPreferredAuthenticationMethods')

    $phoneMethods = @(
        $methods | Where-Object { Test-StringInSet -Value $_ -Set $script:PhoneMethodValues }
    )

    $hasMobilePhone = (Test-StringInSet -Value 'mobilePhone' -Set $phoneMethods) -or
        (Test-StringInSet -Value 'alternateMobilePhone' -Set $phoneMethods)
    $hasOfficePhone = Test-StringInSet -Value 'officePhone' -Set $phoneMethods
    $hasPhoneRegistered = $phoneMethods.Count -gt 0

    $hasSmsPreferred = (Test-StringInSet -Value $preferred -Set $script:SmsPreferredValues) -or
        ((@($systemPreferred | Where-Object { Test-StringInSet -Value $_ -Set $script:SmsPreferredValues })).Count -gt 0)

    $hasVoicePreferred = (Test-StringInSet -Value $preferred -Set $script:VoicePreferredValues) -or
        ((@($systemPreferred | Where-Object { Test-StringInSet -Value $_ -Set $script:VoicePreferredValues })).Count -gt 0)

    # Include anyone with a registered phone MFA method, or an SMS/voice preference.
    $isMatch = $hasPhoneRegistered -or $hasSmsPreferred -or $hasVoicePreferred

    # Capability model used by Entra:
    # - mobile / alternate mobile => SMS and voice
    # - office phone => voice
    # - explicit preferred method always counts
    $usesSms = $hasSmsPreferred -or $hasMobilePhone
    $usesVoice = $hasVoicePreferred -or $hasMobilePhone -or $hasOfficePhone

    $category = 'None'
    if ($usesSms -and $usesVoice) {
        $category = 'SMS and Voice'
    }
    elseif ($usesSms) {
        $category = 'SMS'
    }
    elseif ($usesVoice) {
        $category = 'Voice'
    }

    return [pscustomobject]@{
        IsMatch              = [bool]$isMatch
        UsesSms              = [bool]$usesSms
        UsesVoice            = [bool]$usesVoice
        Category             = $category
        PhoneMethods         = ($phoneMethods -join '; ')
        PreferredMethod      = $preferred
        SystemPreferred      = ($systemPreferred -join '; ')
        MethodsRegisteredAll = ($methods -join '; ')
    }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Name)

    $ok = $false
    if ($null -eq $Expected -and $null -eq $Actual) {
        $ok = $true
    }
    elseif ($null -ne $Expected -and $null -ne $Actual -and $Expected -eq $Actual) {
        $ok = $true
    }
    if (-not $ok) {
        throw "SelfTest failed: $Name. Expected '$Expected', got '$Actual'."
    }
}

function Invoke-SmsVoiceSelfTest {
    Write-Host 'Running Get-EntraSmsVoiceAuthUsers self-tests...' -ForegroundColor Cyan

    $smsOnly = Get-SmsVoiceClassification -Registration ([pscustomobject]@{
            methodsRegistered                             = @('microsoftAuthenticatorPush')
            userPreferredMethodForSecondaryAuthentication = 'sms'
            systemPreferredAuthenticationMethods          = @()
        })
    Assert-Equal $true $smsOnly.IsMatch 'sms preferred is match'
    Assert-Equal $true $smsOnly.UsesSms 'sms preferred uses SMS'
    Assert-Equal 'SMS' $smsOnly.Category 'sms preferred category'

    $voiceOnly = Get-SmsVoiceClassification -Registration ([pscustomobject]@{
            methodsRegistered                             = @('officePhone')
            userPreferredMethodForSecondaryAuthentication = 'voiceOffice'
            systemPreferredAuthenticationMethods          = @('voiceOffice')
        })
    Assert-Equal $true $voiceOnly.IsMatch 'voice preferred is match'
    Assert-Equal $true $voiceOnly.UsesVoice 'voice preferred uses voice'
    Assert-equal $false $voiceOnly.UsesSms 'office voice is not SMS'
    Assert-Equal 'Voice' $voiceOnly.Category 'voice preferred category'

    $mobilePhone = Get-SmsVoiceClassification -Registration ([pscustomobject]@{
            methodsRegistered                             = @('mobilePhone', 'microsoftAuthenticatorPush')
            userPreferredMethodForSecondaryAuthentication = 'push'
            systemPreferredAuthenticationMethods          = @('push')
        })
    Assert-Equal $true $mobilePhone.IsMatch 'mobilePhone registered is match'
    Assert-Equal $true $mobilePhone.UsesSms 'mobilePhone implies SMS capable'
    Assert-equal $true $mobilePhone.UsesVoice 'mobilePhone implies Voice capable'
    Assert-Equal 'SMS and Voice' $mobilePhone.Category 'mobilePhone category'

    $noPhone = Get-SmsVoiceClassification -Registration ([pscustomobject]@{
            methodsRegistered                             = @('microsoftAuthenticatorPush', 'softwareOneTimePasscode')
            userPreferredMethodForSecondaryAuthentication = 'push'
            systemPreferredAuthenticationMethods          = @('push')
        })
    Assert-Equal $false $noPhone.IsMatch 'authenticator-only is not a match'
    Assert-Equal 'None' $noPhone.Category 'authenticator-only category'

    $dictReg = [ordered]@{
        methodsRegistered = @('mobilePhone')
        userPreferredMethodForSecondaryAuthentication = 'push'
        systemPreferredAuthenticationMethods = @('push')
    }
    $fromDict = Get-SmsVoiceClassification -Registration $dictReg
    Assert-Equal $true $fromDict.IsMatch 'ordered dictionary registration is match'

    $ht = @{ value = @(@{ id = '1' }, @{ id = '2' }); '@odata.nextLink' = $null }
    $extracted = Get-GraphResponseProperty -Response $ht -Name 'value'
    Assert-Equal 2 @($extracted).Count 'dictionary value extraction count'

    Write-Host 'All self-tests passed.' -ForegroundColor Green
}

#endregion

if ($SelfTest) {
    Invoke-SmsVoiceSelfTest
    exit 0
}

#region Graph auth / HTTP ------------------------------------------------------

function Import-GraphAuthModule {
    if (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue) {
        return $true
    }
    try {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Set-TokenSession {
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [datetime]$ExpiresOnUtc = [datetime]::MinValue,

        [string]$AccountUpn = '',

        [string]$Mode = 'Token'
    )

    $script:AccessToken = $AccessToken
    $script:TokenExpiresUtc = if ($ExpiresOnUtc -gt [datetime]::MinValue) {
        $ExpiresOnUtc.ToUniversalTime()
    }
    else {
        [datetime]::UtcNow.AddMinutes(45)
    }
    $script:SignedInUpn = $AccountUpn
    $script:AuthMode = $Mode
    return $true
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

function Get-HttpErrorBody {
    param($ErrorRecord)

    try {
        $response = $ErrorRecord.Exception.Response
        if (-not $response) { return [string]$ErrorRecord.Exception.Message }

        $stream = $response.GetResponseStream()
        if (-not $stream) { return [string]$ErrorRecord.Exception.Message }

        $reader = New-Object System.IO.StreamReader($stream)
        try {
            $body = $reader.ReadToEnd()
            if (-not [string]::IsNullOrWhiteSpace($body)) {
                return $body
            }
        }
        finally {
            $reader.Close()
        }
    }
    catch { }

    return [string]$ErrorRecord.Exception.Message
}

function Complete-MgGraphSession {
    $ctx = Get-MgContext -ErrorAction Stop
    if (-not $ctx) { return $false }

    $token = $null
    try {
        if (Get-Command Get-MgAccessToken -ErrorAction SilentlyContinue) {
            $token = Get-MgAccessToken -ErrorAction Stop
        }
    }
    catch { }

    if ($token) {
        return (Set-TokenSession -AccessToken ([string]$token) -AccountUpn ([string]$ctx.Account) -Mode 'MgGraphToken')
    }

    $script:AuthMode = 'MgGraph'
    $script:SignedInUpn = [string]$ctx.Account
    return $true
}

function New-AuthParentForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Entra ID interactive sign-in'
    $form.Width = 480
    $form.Height = 140
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.TopMost = $true
    $form.ShowInTaskbar = $true
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ControlBox = $true

    $label = New-Object System.Windows.Forms.Label
    $label.Dock = [System.Windows.Forms.DockStyle]::Fill
    $label.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $label.Text = "Complete interactive sign-in in the browser / account picker.`r`nLeave this window open until sign-in finishes."
    $form.Controls.Add($label)

    [void]$form.Show()
    $form.Activate()
    [void][System.Windows.Forms.Application]::DoEvents()
    return $form
}

function Connect-ViaMgGraph {
    param(
        [switch]$UseDeviceCode
    )

    if (-not (Import-GraphAuthModule)) { return $false }

    # Custom apps can disable WAM and use classic interactive browser login.
    $isCustomApp = -not [string]::Equals(
        [string]$ClientId,
        $script:GraphPowerShellClientId,
        [System.StringComparison]::OrdinalIgnoreCase
    )
    if ($isCustomApp -and -not $UseDeviceCode -and -not $DeviceCode) {
        try {
            if (Get-Command Set-MgGraphOption -ErrorAction SilentlyContinue) {
                Set-MgGraphOption -DisableLoginByWAM $true -ErrorAction SilentlyContinue | Out-Null
            }
        }
        catch { }
    }

    $params = @{
        Scopes      = $script:GraphScopeList
        NoWelcome   = $true
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $params['TenantId'] = $TenantId
    }
    if (-not [string]::IsNullOrWhiteSpace($ClientId)) {
        $params['ClientId'] = $ClientId
    }
    if ($UseDeviceCode -or $DeviceCode) {
        $params['UseDeviceAuthentication'] = $true
    }

    $parent = $null
    try {
        if ($UseDeviceCode -or $DeviceCode) {
            Write-Host 'Opening Microsoft Graph device sign-in (enter the code in your browser)...' -ForegroundColor Cyan
        }
        else {
            Write-Host 'Opening interactive Microsoft Graph sign-in...' -ForegroundColor Cyan
            if ($script:WinFormsLoaded) {
                $parent = New-AuthParentForm
            }
        }

        Connect-MgGraph @params | Out-Null
        return (Complete-MgGraphSession)
    }
    finally {
        if ($null -ne $parent) {
            try { $parent.Close() } catch { }
            try { $parent.Dispose() } catch { }
        }
    }
}

function Import-AzAuthModule {
    if (Get-Command Connect-AzAccount -ErrorAction SilentlyContinue) {
        return $true
    }
    try {
        Import-Module Az.Accounts -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function ConvertFrom-AzAccessToken {
    param($TokenObject)

    if ($null -eq $TokenObject) { return $null }

    $raw = $null
    if ($TokenObject.PSObject.Properties['Token']) {
        $raw = $TokenObject.Token
    }
    elseif ($TokenObject -is [string]) {
        $raw = $TokenObject
    }

    if ($null -eq $raw) { return $null }

    if ($raw -is [securestring]) {
        return [System.Net.NetworkCredential]::new('', $raw).Password
    }

    return [string]$raw
}

function Connect-ViaAzAccount {
    if (-not (Import-AzAuthModule)) { return $false }

    Write-Host 'Opening interactive Azure PowerShell sign-in (browser)...' -ForegroundColor Cyan

    $parent = $null
    try {
        if ($script:WinFormsLoaded) {
            $parent = New-AuthParentForm
        }

        $azParams = @{
            ErrorAction = 'Stop'
        }
        if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
            $azParams['Tenant'] = $TenantId
        }

        Connect-AzAccount @azParams | Out-Null

        $tokObj = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -ErrorAction Stop
        $accessToken = ConvertFrom-AzAccessToken -TokenObject $tokObj
        if ([string]::IsNullOrWhiteSpace($accessToken)) {
            throw 'Get-AzAccessToken returned an empty Graph token.'
        }

        $expires = [datetime]::UtcNow.AddHours(1)
        if ($tokObj.PSObject.Properties['ExpiresOn'] -and $tokObj.ExpiresOn) {
            try {
                $expires = ([datetimeoffset]$tokObj.ExpiresOn).UtcDateTime
            }
            catch { }
        }

        $account = ''
        try {
            $ctx = Get-AzContext -ErrorAction SilentlyContinue
            if ($ctx -and $ctx.Account -and $ctx.Account.Id) {
                $account = [string]$ctx.Account.Id
            }
        }
        catch { }

        return (Set-TokenSession -AccessToken $accessToken -ExpiresOnUtc $expires -AccountUpn $account -Mode 'AzInteractive')
    }
    finally {
        if ($null -ne $parent) {
            try { $parent.Close() } catch { }
            try { $parent.Dispose() } catch { }
        }
    }
}

function Connect-ViaDeviceCode {
    param(
        [Parameter()]
        [string]$AppClientId = $script:AzurePowerShellClientId
    )

    if ([string]::IsNullOrWhiteSpace($AppClientId)) {
        $AppClientId = $script:AzurePowerShellClientId
    }

    $tenant = if (-not [string]::IsNullOrWhiteSpace($TenantId)) { $TenantId.Trim() } else { 'organizations' }
    $authority = "https://login.microsoftonline.com/$tenant"

    $dcBody = ConvertTo-FormUrlEncoded -Data @{
        client_id = $AppClientId
        scope     = $script:GraphScopes
    }

    try {
        $dc = Invoke-RestMethod -Method Post -Uri "$authority/oauth2/v2.0/devicecode" `
            -ContentType 'application/x-www-form-urlencoded' -Body $dcBody -ErrorAction Stop
    }
    catch {
        $detail = Get-HttpErrorBody -ErrorRecord $_
        throw "Device code start failed for client $AppClientId / tenant $tenant`: $detail"
    }

    Write-Host ""
    Write-Host "To sign in, open $($dc.verification_uri) and enter code: $($dc.user_code)" -ForegroundColor Cyan
    Write-Host "Waiting for sign-in..." -ForegroundColor Yellow

    if ($script:WinFormsLoaded) {
        try { [System.Windows.Forms.Clipboard]::SetText([string]$dc.user_code) } catch { }
        Show-UiMessage -Message "Complete sign-in in your browser:`r`n`r`n1. Open $($dc.verification_uri)`r`n2. Enter code $($dc.user_code) (copied to clipboard)`r`n`r`nClick OK, then finish sign-in in the browser while this window waits." -Title 'Sign in to Entra ID' -Icon Information
    }

    $deadline = [datetime]::UtcNow.AddSeconds([int]$dc.expires_in)
    $interval = [Math]::Max(5, [int]$dc.interval)
    $token = $null

    while ([datetime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            $tokBody = ConvertTo-FormUrlEncoded -Data @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $AppClientId
                device_code = [string]$dc.device_code
            }
            $token = Invoke-RestMethod -Method Post -Uri "$authority/oauth2/v2.0/token" `
                -ContentType 'application/x-www-form-urlencoded' -Body $tokBody -ErrorAction Stop
            break
        }
        catch {
            $errText = Get-HttpErrorBody -ErrorRecord $_
            if ($errText -match 'authorization_pending|slow_down') { continue }
            throw "Device code token exchange failed: $errText"
        }
    }

    if (-not $token -or -not $token.access_token) {
        throw 'Sign-in timed out or was cancelled.'
    }

    return (Set-TokenSession -AccessToken ([string]$token.access_token) `
            -ExpiresOnUtc ([datetime]::UtcNow.AddSeconds([int]$token.expires_in)) `
            -Mode 'DeviceCode')
}

function Connect-EntraGraph {
    Write-Host 'Signing in to Microsoft Graph...' -ForegroundColor Cyan
    $ok = $false
    $errors = New-Object System.Collections.Generic.List[string]

    if ($DeviceCode) {
        # Explicit device-code only
        try {
            if (Connect-ViaMgGraph -UseDeviceCode) { $ok = $true }
        }
        catch {
            [void]$errors.Add("Microsoft.Graph device-code: $($_.Exception.Message)")
        }
        if (-not $ok) {
            try {
                if (Connect-ViaDeviceCode -AppClientId $script:AzurePowerShellClientId) { $ok = $true }
            }
            catch {
                [void]$errors.Add("Device code (Azure PowerShell app): $($_.Exception.Message)")
            }
        }
        if (-not $ok) {
            try {
                if (Connect-ViaDeviceCode -AppClientId $ClientId) { $ok = $true }
            }
            catch {
                [void]$errors.Add("Device code (Graph app): $($_.Exception.Message)")
            }
        }
    }
    else {
        # 1) Interactive Microsoft Graph (browser / WAM with parent window)
        try {
            if (Connect-ViaMgGraph) { $ok = $true }
        }
        catch {
            [void]$errors.Add("Microsoft.Graph interactive: $($_.Exception.Message)")
        }

        # 2) Interactive Azure PowerShell browser login -> Graph token
        if (-not $ok) {
            try {
                if (Connect-ViaAzAccount) { $ok = $true }
            }
            catch {
                [void]$errors.Add("Azure PowerShell interactive: $($_.Exception.Message)")
            }
        }

        # 3) Last resort: device code
        if (-not $ok) {
            Write-Host 'Interactive sign-in failed; falling back to device code...' -ForegroundColor Yellow
            try {
                if (Connect-ViaMgGraph -UseDeviceCode) { $ok = $true }
            }
            catch {
                [void]$errors.Add("Microsoft.Graph device-code fallback: $($_.Exception.Message)")
            }
        }
        if (-not $ok) {
            try {
                if (Connect-ViaDeviceCode -AppClientId $script:AzurePowerShellClientId) { $ok = $true }
            }
            catch {
                [void]$errors.Add("Device code (Azure PowerShell app): $($_.Exception.Message)")
            }
        }
    }

    if (-not $ok) {
        $hint = @(
            'Could not sign in to Entra ID / Microsoft Graph.',
            '',
            'Interactive login tips:',
            '  1) Run Windows PowerShell or PowerShell 7 in a normal desktop session (not remoting).',
            '  2) Install-Module Microsoft.Graph.Authentication -Scope CurrentUser',
            '  3) Optional browser fallback: Install-Module Az.Accounts -Scope CurrentUser',
            '  4) Re-run: .\Get-EntraSmsVoiceAuthUsers.ps1',
            '  5) If interactive is blocked by policy, use: .\Get-EntraSmsVoiceAuthUsers.ps1 -DeviceCode',
            '',
            'Permissions needed: AuditLog.Read.All, User.Read.All (admin consent).',
            '',
            ($errors -join "`r`n")
        ) -join "`r`n"
        throw $hint
    }

    try {
        $me = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/me?$select=userPrincipalName,displayName'
        if ($me.userPrincipalName) {
            $script:SignedInUpn = [string]$me.userPrincipalName
        }
        elseif ($me.displayName -and -not $script:SignedInUpn) {
            $script:SignedInUpn = [string]$me.displayName
        }
    }
    catch { }

    Write-Host "Signed in as $($script:SignedInUpn) ($($script:AuthMode))" -ForegroundColor Green
}

function Invoke-GraphGet {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [int]$MaxPages = 0
    )

    $items = New-Object 'System.Collections.Generic.List[object]'
    $next = $Uri
    $pages = 0
    $last = $null

    while (-not [string]::IsNullOrWhiteSpace($next)) {
        $pages++
        if ($MaxPages -gt 0 -and $pages -gt $MaxPages) { break }

        $resp = $null
        $useMg = ($script:AuthMode -eq 'MgGraph') -and (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)

        if ($useMg) {
            try {
                # Prefer PSObject when supported; fall back to default hashtable/dictionary.
                $mgParams = @{
                    Method      = 'GET'
                    Uri         = $next
                    ErrorAction = 'Stop'
                }
                $cmd = Get-Command Invoke-MgGraphRequest -ErrorAction Stop
                if ($cmd.Parameters.ContainsKey('OutputType')) {
                    try {
                        $resp = Invoke-MgGraphRequest @mgParams -OutputType PSObject
                    }
                    catch {
                        $resp = Invoke-MgGraphRequest @mgParams
                    }
                }
                else {
                    $resp = Invoke-MgGraphRequest @mgParams
                }
            }
            catch {
                # Some Graph module builds reject Method as string; retry with enum-like casing / no OutputType.
                try {
                    $resp = Invoke-MgGraphRequest -Method Get -Uri $next -ErrorAction Stop
                }
                catch {
                    throw
                }
            }
        }
        else {
            if ([string]::IsNullOrWhiteSpace($script:AccessToken)) {
                throw 'No Graph access token is available.'
            }
            if ($script:TokenExpiresUtc -gt [datetime]::MinValue -and
                [datetime]::UtcNow -ge $script:TokenExpiresUtc.AddMinutes(-2)) {
                throw 'Graph access token expired. Re-run the script to sign in again.'
            }
            $headers = @{
                Authorization    = "Bearer $($script:AccessToken)"
                ConsistencyLevel = 'eventual'
            }
            $resp = Invoke-RestMethod -Method Get -Uri $next -Headers $headers -ErrorAction Stop
        }

        $last = $resp
        $valueList = Get-GraphResponseProperty -Response $resp -Name 'value'
        $nextLink = Get-GraphResponseProperty -Response $resp -Name '@odata.nextLink'

        if ($null -ne $valueList) {
            foreach ($v in @($valueList)) {
                if ($null -ne $v) {
                    [void]$items.Add($v)
                }
            }
            $next = if ($nextLink) { [string]$nextLink } else { $null }
        }
        else {
            # Single-object response (e.g. /users/{id})
            return $resp
        }
    }

    return @{
        value = @($items.ToArray())
        _raw  = $last
    }
}

function Get-GraphCollectionValue {
    param($Response)

    if ($null -eq $Response) { return @() }

    $value = Get-GraphResponseProperty -Response $Response -Name 'value'
    if ($null -ne $value) {
        return @($value)
    }

    return @($Response)
}

function Get-EntraUserProfile {
    param(
        [Parameter(Mandatory)]
        [string]$UserId
    )

    $select = 'id,displayName,userPrincipalName,mail,otherMails,employeeId,accountEnabled,userType'
    $uri = "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($UserId))?`$select=$select"
    try {
        return Invoke-GraphGet -Uri $uri -MaxPages 1
    }
    catch {
        return $null
    }
}

function Get-EmailFromProfile {
    param($Profile)

    if ($null -eq $Profile) { return $null }

    $mail = Get-GraphResponseProperty -Response $Profile -Name 'mail'
    if (-not [string]::IsNullOrWhiteSpace([string]$mail)) {
        return ([string]$mail).Trim()
    }

    $other = Get-GraphResponseProperty -Response $Profile -Name 'otherMails'
    if ($null -ne $other) {
        $first = @(ConvertTo-StringArray $other) | Select-Object -First 1
        if ($first) { return $first }
    }
    return $null
}

#endregion

#region Main -------------------------------------------------------------------

if ($script:UseGui) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $script:WinFormsLoaded = $true
    }
    catch {
        Write-Host "Failed to load System.Windows.Forms. Pass -OutputCsv to run without a GUI. $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

if ([string]::IsNullOrWhiteSpace($OutputCsv)) {
    $OutputCsv = Select-OutputCsv
}

try {
    Connect-EntraGraph
}
catch {
    Show-UiMessage -Message "$_" -Title 'Entra sign-in failed' -Icon Error
    exit 1
}

# Phone methods that enable SMS and/or voice MFA
$phoneFilters = @(
    "methodsRegistered/any(m:m eq 'mobilePhone')",
    "methodsRegistered/any(m:m eq 'officePhone')",
    "methodsRegistered/any(m:m eq 'alternateMobilePhone')"
) -join ' or '

# Explicit preferred SMS / voice defaults
$preferredFilters = @(
    "userPreferredMethodForSecondaryAuthentication eq 'sms'",
    "userPreferredMethodForSecondaryAuthentication eq 'voiceMobile'",
    "userPreferredMethodForSecondaryAuthentication eq 'voiceAlternateMobile'",
    "userPreferredMethodForSecondaryAuthentication eq 'voiceOffice'"
) -join ' or '

$filter = "($phoneFilters) or ($preferredFilters)"
$baseUri = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails'
$uri = "$baseUri`?`$filter=$([uri]::EscapeDataString($filter))&`$top=999"

Write-Host 'Querying Entra authentication method registration details (SMS / voice)...' -ForegroundColor Cyan
Write-Host 'Note: this Graph report only includes enabled users.' -ForegroundColor DarkGray

try {
    $regResponse = Invoke-GraphGet -Uri $uri
}
catch {
    $detail = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
        $detail = "$detail`r`n$($_.ErrorDetails.Message)"
    }
    Show-UiMessage -Message "Failed to query authentication method registration details:`r`n$detail`r`n`r`nEnsure your account has AuditLog.Read.All (Reports Reader or higher)." -Title 'Graph query failed' -Icon Error
    exit 1
}

$registrations = @(Get-GraphCollectionValue $regResponse)
Write-Host ("Registration rows returned: {0}" -f $registrations.Count) -ForegroundColor Yellow

$results = New-Object 'System.Collections.Generic.List[object]'
$skippedDisabled = 0
$skippedNoMatch = 0
$enrichFailures = 0
$counter = 0

foreach ($reg in $registrations) {
    $counter++
    if ($counter % 25 -eq 0 -or $counter -eq $registrations.Count) {
        Write-Progress -Activity 'Building SMS/Voice auth report' -Status "$counter of $($registrations.Count)" -PercentComplete (($counter / [Math]::Max($registrations.Count, 1)) * 100)
    }

    $classification = Get-SmsVoiceClassification -Registration $reg
    if (-not $classification.IsMatch) {
        $skippedNoMatch++
        continue
    }

    $userId = [string](Get-GraphResponseProperty -Response $reg -Name 'id')
    $profile = $null
    if (-not [string]::IsNullOrWhiteSpace($userId)) {
        $profile = Get-EntraUserProfile -UserId $userId
        if ($null -eq $profile) {
            $enrichFailures++
        }
    }

    $accountEnabled = $true
    if ($null -ne $profile) {
        $enabledRaw = Get-GraphResponseProperty -Response $profile -Name 'accountEnabled'
        if ($null -ne $enabledRaw) {
            $accountEnabled = [bool]$enabledRaw
        }
    }
    if (-not $accountEnabled) {
        $skippedDisabled++
        continue
    }

    $displayName = [string](Get-GraphResponseProperty -Response $reg -Name 'userDisplayName')
    $upn = [string](Get-GraphResponseProperty -Response $reg -Name 'userPrincipalName')
    $email = $null
    $employeeId = $null

    if ($null -ne $profile) {
        $profileDisplay = Get-GraphResponseProperty -Response $profile -Name 'displayName'
        $profileUpn = Get-GraphResponseProperty -Response $profile -Name 'userPrincipalName'
        if (-not [string]::IsNullOrWhiteSpace([string]$profileDisplay)) {
            $displayName = [string]$profileDisplay
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$profileUpn)) {
            $upn = [string]$profileUpn
        }
        $email = Get-EmailFromProfile -Profile $profile
        $employeeRaw = Get-GraphResponseProperty -Response $profile -Name 'employeeId'
        if (-not [string]::IsNullOrWhiteSpace([string]$employeeRaw)) {
            $employeeId = ([string]$employeeRaw).Trim()
        }
    }

    $userType = Get-GraphResponseProperty -Response $reg -Name 'userType'
    $isMfaRegistered = Get-GraphResponseProperty -Response $reg -Name 'isMfaRegistered'
    $isMfaCapable = Get-GraphResponseProperty -Response $reg -Name 'isMfaCapable'
    $lastUpdated = Get-GraphResponseProperty -Response $reg -Name 'lastUpdatedDateTime'

    [void]$results.Add([pscustomobject][ordered]@{
            DisplayName        = $displayName
            UserPrincipalName  = $upn
            EmailAddress       = $email
            EmployeeID         = $employeeId
            AccountEnabled     = $accountEnabled
            UserType           = [string]$userType
            AuthCategory       = $classification.Category
            UsesSms            = $classification.UsesSms
            UsesVoice          = $classification.UsesVoice
            PhoneMethods       = $classification.PhoneMethods
            PreferredMfaMethod = $classification.PreferredMethod
            SystemPreferred    = $classification.SystemPreferred
            MethodsRegistered  = $classification.MethodsRegisteredAll
            IsMfaRegistered    = $isMfaRegistered
            IsMfaCapable       = $isMfaCapable
            LastUpdated        = $lastUpdated
            UserId             = $userId
        })
}

Write-Progress -Activity 'Building SMS/Voice auth report' -Completed

$exportEncoding = 'UTF8'
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $exportEncoding = 'utf8BOM'
}

try {
    $results | Sort-Object DisplayName, UserPrincipalName |
        Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Encoding $exportEncoding
}
catch {
    Show-UiMessage -Message "Failed to write the output CSV:`r`n$($_.Exception.Message)" -Title 'Export Error' -Icon Error
    exit 1
}

$smsCount = @($results | Where-Object { $_.UsesSms }).Count
$voiceCount = @($results | Where-Object { $_.UsesVoice }).Count

$summary = @"
Enabled users with SMS and/or Voice auth methods: $($results.Count)
  Uses SMS:   $smsCount
  Uses Voice: $voiceCount
Skipped (disabled after enrich): $skippedDisabled
Enrichment failures: $enrichFailures
Saved to:
$OutputCsv
"@

Write-Host $summary -ForegroundColor Green
Show-UiMessage -Message $summary -Title 'Entra SMS/Voice Auth Report Complete' -Icon Information

#endregion

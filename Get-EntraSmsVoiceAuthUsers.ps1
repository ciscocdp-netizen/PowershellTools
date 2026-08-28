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
    Prefer device-code sign-in and skip browser sign-in. The script already tries
    device-code first (console-safe) to avoid WAM window-handle failures.

.PARAMETER SelfTest
    Runs built-in unit tests for SMS/voice classification helpers and exits.
    Does not contact Microsoft Graph or show dialogs.

.EXAMPLE
    .\Get-EntraSmsVoiceAuthUsers.ps1

.EXAMPLE
    .\Get-EntraSmsVoiceAuthUsers.ps1 -OutputCsv .\SmsVoiceUsers.csv

.EXAMPLE
    .\Get-EntraSmsVoiceAuthUsers.ps1 -TenantId contoso.onmicrosoft.com -DeviceCode

.NOTES
    Required Graph delegated permissions (admin consent typically needed):
      - AuditLog.Read.All   (authentication method registration report)
      - User.Read.All       (mail, employeeId, accountEnabled)

    Least-privileged Entra roles that can run the registration report:
      Reports Reader, Security Reader, Security Administrator, Global Reader
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
$script:UseGui = (-not $SelfTest) -and [string]::IsNullOrWhiteSpace($OutputCsv)

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

    Write-Host "Relaunching in STA mode so the save dialog works..." -ForegroundColor Yellow
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

function Get-SmsVoiceClassification {
    param(
        [Parameter(Mandatory)]
        $Registration
    )

    $methods = ConvertTo-StringArray $Registration.methodsRegistered
    $preferred = [string]$Registration.userPreferredMethodForSecondaryAuthentication
    if ($null -eq $preferred) { $preferred = '' }
    $systemPreferred = ConvertTo-StringArray $Registration.systemPreferredAuthenticationMethods

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

function Connect-ViaMgGraph {
    param(
        [switch]$UseDeviceCode
    )

    if (-not (Import-GraphAuthModule)) { return $false }

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

    if ($UseDeviceCode -or $DeviceCode) {
        Write-Host 'Opening Microsoft Graph device sign-in (enter the code in your browser)...' -ForegroundColor Cyan
    }
    else {
        Write-Host 'Opening Microsoft Graph browser sign-in...' -ForegroundColor Cyan
    }

    Connect-MgGraph @params | Out-Null
    return (Complete-MgGraphSession)
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

    # 1) Preferred for consoles: Microsoft.Graph device-code (avoids WAM window-handle failures)
    try {
        if (Connect-ViaMgGraph -UseDeviceCode) { $ok = $true }
    }
    catch {
        [void]$errors.Add("Microsoft.Graph device-code: $($_.Exception.Message)")
    }

    # 2) Optional browser sign-in when -DeviceCode was not forced and device-code path failed
    if (-not $ok -and -not $DeviceCode) {
        try {
            if (Connect-ViaMgGraph) { $ok = $true }
        }
        catch {
            [void]$errors.Add("Microsoft.Graph browser: $($_.Exception.Message)")
        }
    }

    # 3) Raw device-code with Azure PowerShell public client (most reliable fallback)
    if (-not $ok) {
        try {
            if (Connect-ViaDeviceCode -AppClientId $script:AzurePowerShellClientId) { $ok = $true }
        }
        catch {
            [void]$errors.Add("Device code (Azure PowerShell app): $($_.Exception.Message)")
        }
    }

    # 4) Raw device-code with Microsoft Graph PowerShell app / custom -ClientId
    if (-not $ok) {
        try {
            $fallbackClient = if (-not [string]::IsNullOrWhiteSpace($ClientId)) { $ClientId } else { $script:GraphPowerShellClientId }
            if (Connect-ViaDeviceCode -AppClientId $fallbackClient) { $ok = $true }
        }
        catch {
            [void]$errors.Add("Device code (Graph PowerShell app): $($_.Exception.Message)")
        }
    }

    if (-not $ok) {
        $hint = @(
            'Could not sign in to Entra ID / Microsoft Graph.',
            '',
            'Try:',
            '  1) Install-Module Microsoft.Graph.Authentication -Scope CurrentUser',
            '  2) Close PowerShell, reopen, then run:',
            '       .\Get-EntraSmsVoiceAuthUsers.ps1 -DeviceCode',
            '  3) If needed, pass your tenant:',
            '       .\Get-EntraSmsVoiceAuthUsers.ps1 -DeviceCode -TenantId contoso.onmicrosoft.com',
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

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $pages = 0
    $last = $null

    while ($next) {
        $pages++
        if ($MaxPages -gt 0 -and $pages -gt $MaxPages) { break }

        if ($script:AuthMode -eq 'MgGraph' -and (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        }
        else {
            if ([string]::IsNullOrWhiteSpace($script:AccessToken)) {
                throw 'No Graph access token is available.'
            }
            if ([datetime]::UtcNow -ge $script:TokenExpiresUtc.AddMinutes(-2)) {
                throw 'Graph access token expired. Re-run the script to sign in again.'
            }
            $headers = @{
                Authorization    = "Bearer $($script:AccessToken)"
                ConsistencyLevel = 'eventual'
            }
            $resp = Invoke-RestMethod -Method Get -Uri $next -Headers $headers -ErrorAction Stop
        }

        $last = $resp
        $hasValue = $false
        $valueList = $null
        $nextLink = $null

        if ($resp -is [hashtable]) {
            if ($resp.ContainsKey('value')) {
                $hasValue = $true
                $valueList = $resp['value']
            }
            if ($resp.ContainsKey('@odata.nextLink')) {
                $nextLink = $resp['@odata.nextLink']
            }
        }
        elseif ($resp.PSObject.Properties['value']) {
            $hasValue = $true
            $valueList = $resp.value
            if ($resp.PSObject.Properties['@odata.nextLink']) {
                $nextLink = $resp.'@odata.nextLink'
            }
        }

        if ($hasValue) {
            foreach ($v in @($valueList)) {
                if ($null -ne $v) { [void]$items.Add($v) }
            }
            $next = if ($nextLink) { [string]$nextLink } else { $null }
        }
        else {
            return $resp
        }
    }

    return @{ value = @($items); _raw = $last }
}

function Get-GraphCollectionValue {
    param($Response)

    if ($null -eq $Response) { return @() }
    if ($Response -is [hashtable] -and $Response.ContainsKey('value')) {
        return @($Response['value'])
    }
    if ($Response.PSObject.Properties['value']) {
        return @($Response.value)
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
    foreach ($name in @('mail')) {
        $prop = $Profile.PSObject.Properties[$name]
        if ($prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
            return ([string]$prop.Value).Trim()
        }
    }
    $other = $Profile.PSObject.Properties['otherMails']
    if ($other -and $other.Value) {
        $first = @(ConvertTo-StringArray $other.Value) | Select-Object -First 1
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
    Show-UiMessage -Message "Failed to query authentication method registration details:`r`n$($_.Exception.Message)`r`n`r`nEnsure your account has AuditLog.Read.All (Reports Reader or higher)." -Title 'Graph query failed' -Icon Error
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

    $userId = [string]$reg.id
    $profile = $null
    if (-not [string]::IsNullOrWhiteSpace($userId)) {
        $profile = Get-EntraUserProfile -UserId $userId
        if ($null -eq $profile) {
            $enrichFailures++
        }
    }

    $accountEnabled = $true
    if ($null -ne $profile -and $null -ne $profile.PSObject.Properties['accountEnabled']) {
        $accountEnabled = [bool]$profile.accountEnabled
    }
    if (-not $accountEnabled) {
        $skippedDisabled++
        continue
    }

    $displayName = [string]$reg.userDisplayName
    $upn = [string]$reg.userPrincipalName
    $email = $null
    $employeeId = $null

    if ($null -ne $profile) {
        if ($profile.displayName) { $displayName = [string]$profile.displayName }
        if ($profile.userPrincipalName) { $upn = [string]$profile.userPrincipalName }
        $email = Get-EmailFromProfile -Profile $profile
        if ($profile.PSObject.Properties['employeeId'] -and $profile.employeeId) {
            $employeeId = ([string]$profile.employeeId).Trim()
        }
    }

    [void]$results.Add([pscustomobject][ordered]@{
            DisplayName        = $displayName
            UserPrincipalName  = $upn
            EmailAddress       = $email
            EmployeeID         = $employeeId
            AccountEnabled     = $accountEnabled
            UserType           = [string]$reg.userType
            AuthCategory       = $classification.Category
            UsesSms            = $classification.UsesSms
            UsesVoice          = $classification.UsesVoice
            PhoneMethods       = $classification.PhoneMethods
            PreferredMfaMethod = $classification.PreferredMethod
            SystemPreferred    = $classification.SystemPreferred
            MethodsRegistered  = $classification.MethodsRegisteredAll
            IsMfaRegistered    = $reg.isMfaRegistered
            IsMfaCapable       = $reg.isMfaCapable
            LastUpdated        = $reg.lastUpdatedDateTime
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

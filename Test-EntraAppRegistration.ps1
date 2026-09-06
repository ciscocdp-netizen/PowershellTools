#Requires -Version 5.1
<#
.SYNOPSIS
    Interactively validates an Entra ID app registration OAuth client-credentials
    connection and reports the application roles present in the access token.

.DESCRIPTION
    Signs the operator into Microsoft Entra ID (browser or device code) to discover
    the tenant ID automatically, then requests an app-only token using the registered
    application's client ID, client secret, and Application ID URI.

    A formatted console report (and an optional Windows results window) shows:
      - Whether the OAuth client-credentials request succeeded
      - Tenant, app, audience, expiry, and token type
      - Every value in the token "roles" claim
      - Optional comparison against expected role names

    The original raw-token dump is off by default. Pass -ShowToken only when you
    need the JWT itself.

.PARAMETER ClientId
    Application (client) ID of the app registration to test.

.PARAMETER ClientSecret
    Client secret for the app registration. Prefer -ClientSecretSecure when calling
    from another script. If omitted, you are prompted.

.PARAMETER ClientSecretSecure
    Client secret as a SecureString.

.PARAMETER AppIdUri
    Application ID URI of the API app (the resource where app roles are defined).
    Example: api://xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    The script appends /.default unless it is already present.

.PARAMETER TenantId
    Optional tenant ID or domain (contoso.onmicrosoft.com). When omitted, the
    operator signs in to Entra ID and the tenant is read from the ID token.

.PARAMETER ExpectedRoles
    Optional list of role names that must appear in the token. Missing names are
    called out in the report.

.PARAMETER DeviceCode
    Force device-code sign-in instead of trying interactive browser login first.

.PARAMETER ConsoleOnly
    Skip Windows Forms dialogs. Prompts and the report stay in the console.

.PARAMETER ShowToken
    Include the raw access token in the report. The token is a credential; do not
    share the report if this switch is used.

.PARAMETER HtmlReport
    Optional path to write a stand-alone HTML report.

.PARAMETER SelfTest
    Runs built-in unit tests for JWT decoding, role extraction, scope building,
    and report generation. Does not contact Entra ID.

.EXAMPLE
    .\Test-EntraAppRegistration.ps1

.EXAMPLE
    .\Test-EntraAppRegistration.ps1 -ClientId '11111111-1111-1111-1111-111111111111' -AppIdUri 'api://my-api'

.EXAMPLE
    .\Test-EntraAppRegistration.ps1 -TenantId 'contoso.onmicrosoft.com' -ExpectedRoles 'Orders.Read','Orders.Write'

.EXAMPLE
    .\Test-EntraAppRegistration.ps1 -DeviceCode -ConsoleOnly

.EXAMPLE
    .\Test-EntraAppRegistration.ps1 -SelfTest

.NOTES
    No Microsoft Graph or Azure PowerShell modules are required. If Az.Accounts or
    Microsoft.Graph.Authentication is installed, interactive browser sign-in is
    attempted first; device code is always available as a fallback.

    The user sign-in is used only to discover the tenant. The OAuth test itself
    uses the client-credentials grant against the app registration you supply.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [Alias('ApplicationId')]
    [string]$ClientId,

    [Parameter()]
    [string]$ClientSecret,

    [Parameter()]
    [SecureString]$ClientSecretSecure,

    [Parameter()]
    [Alias('ApplicationIdUri')]
    [string]$AppIdUri,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string[]]$ExpectedRoles,

    [switch]$DeviceCode,

    [switch]$ConsoleOnly,

    [switch]$ShowToken,

    [Parameter()]
    [string]$HtmlReport,

    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$env:AZURE_IDENTITY_DISABLE_CP1 = 'true'
$env:MSAL_DESKTOP_APP_USE_WAM = '0'

$script:AzurePowerShellClientId = '1950a258-227b-4e31-a9cf-717495945fc2'
$script:GraphPowerShellClientId = '14d82eec-204b-4c2f-b113-9d477e6ee18c'
$script:AzureCliClientId        = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
$script:WinFormsLoaded          = $false
$script:IsWindowsHost           = $false
$script:UseGui                  = $false

try {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $script:IsWindowsHost = [bool]$IsWindows
    }
    else {
        $script:IsWindowsHost = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    }
}
catch {
    $script:IsWindowsHost = $false
}

$script:UseGui = $script:IsWindowsHost -and -not $ConsoleOnly -and -not $SelfTest

#region STA -------------------------------------------------------------------

if ($script:UseGui -and [System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        Write-Host 'Windows dialogs require STA. Restart with: powershell.exe -STA -File <script>' -ForegroundColor Red
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

    $named = @{
        ClientId   = $ClientId
        AppIdUri   = $AppIdUri
        TenantId   = $TenantId
        HtmlReport = $HtmlReport
    }
    foreach ($key in $named.Keys) {
        if (-not [string]::IsNullOrWhiteSpace($named[$key])) {
            [void]$argParts.Add("-$key")
            [void]$argParts.Add(('"{0}"' -f $named[$key]))
        }
    }
    if ($ExpectedRoles -and $ExpectedRoles.Count -gt 0) {
        [void]$argParts.Add('-ExpectedRoles')
        foreach ($role in $ExpectedRoles) {
            [void]$argParts.Add(('"{0}"' -f $role))
        }
    }
    if ($DeviceCode) { [void]$argParts.Add('-DeviceCode') }
    if ($ShowToken)  { [void]$argParts.Add('-ShowToken') }

    if (-not [string]::IsNullOrWhiteSpace($ClientSecret)) {
        $env:ENTRA_APP_VALIDATOR_SECRET = $ClientSecret
    }

    Write-Host 'Relaunching in STA mode so sign-in and result windows work...' -ForegroundColor Yellow
    $proc = Start-Process -FilePath $exe -ArgumentList ($argParts -join ' ') -Wait -PassThru -NoNewWindow
    if ($null -eq $proc.ExitCode) { exit 1 }
    exit $proc.ExitCode
}

#endregion

#region Helpers ----------------------------------------------------------------

function Initialize-WinForms {
    if ($script:WinFormsLoaded) { return $true }
    if (-not $script:UseGui) { return $false }

    try {
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        Add-Type -AssemblyName System.Drawing | Out-Null
        try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch { }
        $script:WinFormsLoaded = $true
        return $true
    }
    catch {
        $script:UseGui = $false
        return $false
    }
}

function ConvertTo-PlainText {
    param(
        [AllowNull()]
        [SecureString]$Secret
    )

    if ($null -eq $Secret) { return '' }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
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

    if ($null -eq $ErrorRecord) { return '' }

    try {
        if ($ErrorRecord.PSObject.Properties['ErrorDetails'] -and $ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            return [string]$ErrorRecord.ErrorDetails.Message
        }
    }
    catch { }

    try {
        $response = $ErrorRecord.Exception.Response
        if ($response) {
            if ($response.PSObject.Properties['Content'] -and $response.Content) {
                $content = $response.Content
                if ($content -is [string]) { return $content }
                try { return [string]$content.ReadAsStringAsync().Result } catch { }
            }

            $stream = $response.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                try {
                    $body = $reader.ReadToEnd()
                    if (-not [string]::IsNullOrWhiteSpace($body)) { return $body }
                }
                finally {
                    $reader.Close()
                }
            }
        }
    }
    catch { }

    return [string]$ErrorRecord.Exception.Message
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)

    $encoded = [Convert]::ToBase64String($Bytes)
    return ($encoded.TrimEnd('=') -replace '\+', '-' -replace '/', '_')
}

function ConvertFrom-Base64Url {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $padded = $Value.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) {
        2 { $padded += '==' }
        3 { $padded += '=' }
        1 { $padded += '===' }
    }
    return [Convert]::FromBase64String($padded)
}

function ConvertFrom-Jwt {
    param(
        [Parameter(Mandatory)]
        [string]$Token
    )

    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) {
        throw 'Not a valid JWT (expected header.payload.signature).'
    }

    $bytes = ConvertFrom-Base64Url -Value $parts[1]
    $json = [System.Text.Encoding]::UTF8.GetString($bytes)
    return $json | ConvertFrom-Json
}

function Get-JwtRoles {
    param($Payload)

    $list = New-Object System.Collections.Generic.List[string]

    if ($null -ne $Payload) {
        $names = @($Payload.PSObject.Properties.Name)
        if ($names -contains 'roles' -and $null -ne $Payload.roles) {
            foreach ($item in @($Payload.roles)) {
                if ($null -eq $item) { continue }
                $text = [string]$item
                if (-not [string]::IsNullOrWhiteSpace($text)) {
                    [void]$list.Add($text)
                }
            }
        }
    }

    # Unary comma prevents PowerShell from unrolling a 0- or 1-item array.
    return ,([string[]]$list.ToArray())
}

function Get-ClaimValue {
    param(
        $Payload,
        [string]$Name
    )

    if ($null -eq $Payload) { return $null }
    $prop = $Payload.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function ConvertFrom-UnixSeconds {
    param($Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try {
        $seconds = [int64]$Value
        return ([datetime]'1970-01-01Z').ToUniversalTime().AddSeconds($seconds)
    }
    catch {
        return $null
    }
}

function Get-OAuthScope {
    param(
        [Parameter(Mandatory)]
        [string]$AppIdUri
    )

    $trimmed = $AppIdUri.Trim().TrimEnd('/')
    if ($trimmed -match '/\.default$') {
        return $trimmed
    }
    return "$trimmed/.default"
}

function Get-FriendlyAadError {
    param(
        [Parameter(Mandatory)]
        [string]$Raw
    )

    $code = ''
    $description = $Raw
    $errorId = ''

    try {
        $json = $Raw | ConvertFrom-Json
        if ($json.PSObject.Properties['error']) { $errorId = [string]$json.error }
        if ($json.PSObject.Properties['error_description']) { $description = [string]$json.error_description }
        if ($json.PSObject.Properties['error_codes'] -and $json.error_codes) {
            $code = [string](@($json.error_codes)[0])
        }
    }
    catch { }

    if ($description -match 'AADSTS(\d+)') {
        $code = $Matches[1]
    }

    $hint = switch ($code) {
        '700016'  { 'The application was not found in this tenant. Confirm the client ID and that the app exists in the signed-in directory.' }
        '7000215' { 'The client secret is invalid or expired. Create a new secret on the app registration and try again.' }
        '7000222' { 'The client secret has expired. Create a new secret on the app registration.' }
        '70011'   { 'The requested scope is invalid. Check the Application ID URI and that it ends up as <uri>/.default.' }
        '500011'  { 'The resource principal was not found. The Application ID URI does not match an app in this tenant.' }
        '65001'   { 'Admin consent is required for this application in the tenant.' }
        '70001'   { 'The application is disabled or not found in this tenant.' }
        '90002'   { 'The tenant was not found. Sign in again or pass a tenant ID / domain name.' }
        '90102'   { 'The Application ID URI / resource identifier is malformed.' }
        default   { $null }
    }

    $summary = $description
    if ($summary.Length -gt 400) {
        $summary = $summary.Substring(0, 400).Trim() + '...'
    }

    $parts = New-Object System.Collections.Generic.List[string]
    if ($errorId) { [void]$parts.Add($errorId) }
    if ($code) { [void]$parts.Add("AADSTS$code") }
    $title = if ($parts.Count -gt 0) { $parts -join ' / ' } else { 'Token request failed' }

    return [pscustomobject]@{
        Title       = $title
        Description = $summary
        Hint        = $hint
        Raw         = $Raw
    }
}

function Get-PromptValue {
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [string]$Current,

        [switch]$Required,

        [switch]$Secret
    )

    if (-not [string]::IsNullOrWhiteSpace($Current)) {
        return $Current
    }

    while ($true) {
        if ($Secret) {
            $secure = Read-Host $Label -AsSecureString
            $plain = ConvertTo-PlainText -Secret $secure
        }
        else {
            $plain = Read-Host $Label
        }

        if (-not $Required -or -not [string]::IsNullOrWhiteSpace($plain)) {
            return $plain
        }
        Write-Host "  $Label is required." -ForegroundColor Yellow
    }
}

function Write-Banner {
    Write-Host ''
    Write-Host '  ================================================================' -ForegroundColor DarkCyan
    Write-Host '           Entra ID App Registration Validator' -ForegroundColor Cyan
    Write-Host '      OAuth client-credentials test  |  Token role inspector' -ForegroundColor Gray
    Write-Host '  ================================================================' -ForegroundColor DarkCyan
    Write-Host ''
}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host "  $Title" -ForegroundColor White
    Write-Host '  ----------------------------------------------------------------' -ForegroundColor DarkGray
}

function Write-KV {
    param(
        [string]$Label,
        [string]$Value,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { $Value = '-' }
    $pad = $Label.PadRight(22)
    Write-Host "  $pad" -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -ForegroundColor $Color
}

#endregion

#region Sign-in ----------------------------------------------------------------

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

function New-AuthParentForm {
    if (-not $script:WinFormsLoaded) { return $null }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Entra ID sign-in'
    $form.Width = 460
    $form.Height = 140
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.TopMost = $true
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    $label = New-Object System.Windows.Forms.Label
    $label.Dock = [System.Windows.Forms.DockStyle]::Fill
    $label.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $label.Text = "Complete sign-in in the browser / account picker.`r`nLeave this window open until sign-in finishes."
    $form.Controls.Add($label)

    [void]$form.Show()
    $form.Activate()
    [void][System.Windows.Forms.Application]::DoEvents()
    return $form
}

function Get-TenantFromJwt {
    param([string]$Token)

    if ([string]::IsNullOrWhiteSpace($Token)) { return $null }
    try {
        $payload = ConvertFrom-Jwt -Token $Token
        $tid = [string](Get-ClaimValue -Payload $payload -Name 'tid')
        if ([string]::IsNullOrWhiteSpace($tid)) { return $null }

        $upn = [string](Get-ClaimValue -Payload $payload -Name 'preferred_username')
        if ([string]::IsNullOrWhiteSpace($upn)) {
            $upn = [string](Get-ClaimValue -Payload $payload -Name 'upn')
        }
        $name = [string](Get-ClaimValue -Payload $payload -Name 'name')

        return [pscustomobject]@{
            TenantId = $tid
            Account  = $upn
            Name     = $name
            Issuer   = [string](Get-ClaimValue -Payload $payload -Name 'iss')
        }
    }
    catch {
        return $null
    }
}

function Connect-ViaAzAccountTenant {
    if (-not (Get-Command Connect-AzAccount -ErrorAction SilentlyContinue)) {
        try { Import-Module Az.Accounts -ErrorAction Stop | Out-Null } catch { return $null }
    }
    if (-not (Get-Command Connect-AzAccount -ErrorAction SilentlyContinue)) { return $null }

    Write-Host '  Opening interactive Azure PowerShell sign-in (browser)...' -ForegroundColor Cyan
    $parent = $null
    try {
        if ($script:WinFormsLoaded) { $parent = New-AuthParentForm }

        $azParams = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($TenantId)) { $azParams['Tenant'] = $TenantId }
        Connect-AzAccount @azParams | Out-Null

        $ctx = Get-AzContext -ErrorAction Stop
        $tid = [string]$ctx.Tenant.Id
        if ([string]::IsNullOrWhiteSpace($tid)) { return $null }

        $account = ''
        if ($ctx.Account -and $ctx.Account.Id) { $account = [string]$ctx.Account.Id }

        return [pscustomobject]@{
            TenantId = $tid
            Account  = $account
            Name     = $account
            Issuer   = "https://login.microsoftonline.com/$tid/v2.0"
            Mode     = 'AzInteractive'
        }
    }
    finally {
        if ($null -ne $parent) {
            try { $parent.Close() } catch { }
            try { $parent.Dispose() } catch { }
        }
    }
}

function Connect-ViaMgGraphTenant {
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        try { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null } catch { return $null }
    }
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) { return $null }

    Write-Host '  Opening interactive Microsoft Graph sign-in...' -ForegroundColor Cyan
    $parent = $null
    try {
        if ($script:WinFormsLoaded) { $parent = New-AuthParentForm }

        $params = @{
            Scopes      = @('openid', 'profile')
            NoWelcome   = $true
            ErrorAction = 'Stop'
        }
        if (-not [string]::IsNullOrWhiteSpace($TenantId)) { $params['TenantId'] = $TenantId }
        if ($DeviceCode) { $params['UseDeviceAuthentication'] = $true }

        Connect-MgGraph @params | Out-Null
        $ctx = Get-MgContext -ErrorAction Stop
        $tid = [string]$ctx.TenantId
        if ([string]::IsNullOrWhiteSpace($tid)) { return $null }

        return [pscustomobject]@{
            TenantId = $tid
            Account  = [string]$ctx.Account
            Name     = [string]$ctx.Account
            Issuer   = "https://login.microsoftonline.com/$tid/v2.0"
            Mode     = 'MgGraph'
        }
    }
    finally {
        if ($null -ne $parent) {
            try { $parent.Close() } catch { }
            try { $parent.Dispose() } catch { }
        }
    }
}

function Connect-ViaDeviceCodeTenant {
    param(
        [Parameter(Mandatory)]
        [string]$AppClientId
    )

    $tenantHint = if (-not [string]::IsNullOrWhiteSpace($TenantId)) { $TenantId.Trim() } else { 'organizations' }
    $authority = "https://login.microsoftonline.com/$tenantHint"

    $dcBody = ConvertTo-FormUrlEncoded -Data @{
        client_id = $AppClientId
        scope     = 'openid profile offline_access'
    }

    $dc = Invoke-RestMethod -Method Post -Uri "$authority/oauth2/v2.0/devicecode" `
        -ContentType 'application/x-www-form-urlencoded' -Body $dcBody -ErrorAction Stop

    Write-Host ''
    Write-Host "  To sign in, open  $($dc.verification_uri)" -ForegroundColor Cyan
    Write-Host "  Enter code:       $($dc.user_code)" -ForegroundColor Yellow
    Write-Host '  Waiting for sign-in...' -ForegroundColor DarkGray
    Write-Host ''

    try { Set-Clipboard -Value ([string]$dc.user_code) -ErrorAction SilentlyContinue } catch { }
    if ($script:WinFormsLoaded) {
        try { [System.Windows.Forms.Clipboard]::SetText([string]$dc.user_code) } catch { }
        $deviceMessage = @(
            'Complete sign-in in your browser:',
            '',
            "1. Open $($dc.verification_uri)",
            "2. Enter code $($dc.user_code)  (copied to clipboard)",
            '',
            'Click OK, then finish sign-in in the browser while this window waits.'
        ) -join [Environment]::NewLine
        Show-UiMessage -Title 'Sign in to Entra ID' -Icon Information -Message $deviceMessage
    }

    try { Start-Process ([string]$dc.verification_uri) | Out-Null } catch { }

    $deadline = [datetime]::UtcNow.AddSeconds([int]$dc.expires_in)
    $interval = [Math]::Max(5, [int]$dc.interval)
    $token = $null
    $lastPoll = [datetime]::MinValue

    while ([datetime]::UtcNow -lt $deadline) {
        if ($script:WinFormsLoaded) {
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Milliseconds 400
        }
        else {
            Start-Sleep -Seconds 1
        }

        if (([datetime]::UtcNow - $lastPoll).TotalSeconds -lt $interval) { continue }
        $lastPoll = [datetime]::UtcNow

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

    if (-not $token) {
        throw 'Sign-in timed out or was cancelled.'
    }

    $jwt = $null
    if ($token.PSObject.Properties['id_token'] -and $token.id_token) {
        $jwt = [string]$token.id_token
    }
    elseif ($token.PSObject.Properties['access_token'] -and $token.access_token) {
        $jwt = [string]$token.access_token
    }

    $discovered = Get-TenantFromJwt -Token $jwt
    if ($null -eq $discovered) {
        throw 'Sign-in succeeded but the token did not include a tenant ID (tid) claim.'
    }

    $discovered | Add-Member -NotePropertyName Mode -NotePropertyValue 'DeviceCode' -Force
    return $discovered
}

function Connect-EntraTenant {
    Write-Section 'Tenant discovery'
    Write-Host '  Sign in to Microsoft Entra ID. The tenant ID is read from your token.' -ForegroundColor Gray

    $errors = New-Object System.Collections.Generic.List[string]
    $result = $null

    if (-not $DeviceCode) {
        try { $result = Connect-ViaAzAccountTenant } catch { [void]$errors.Add("Azure PowerShell: $($_.Exception.Message)") }
        if ($null -eq $result) {
            try { $result = Connect-ViaMgGraphTenant } catch { [void]$errors.Add("Microsoft Graph: $($_.Exception.Message)") }
        }
        if ($null -eq $result -and $errors.Count -gt 0) {
            Write-Host '  Interactive browser sign-in was not available; using device code.' -ForegroundColor Yellow
        }
    }

    if ($null -eq $result) {
        $clientIds = @(
            $script:AzurePowerShellClientId,
            $script:GraphPowerShellClientId,
            $script:AzureCliClientId
        )
        foreach ($app in $clientIds) {
            try {
                $result = Connect-ViaDeviceCodeTenant -AppClientId $app
                if ($null -ne $result) { break }
            }
            catch {
                [void]$errors.Add("Device code ($app): $($_.Exception.Message)")
            }
        }
    }

    if ($null -eq $result) {
        $detail = ($errors | Select-Object -Unique) -join [Environment]::NewLine
        throw "Could not sign in to Entra ID to discover the tenant.`n$detail"
    }

    Write-KV 'Signed in as' $result.Account Cyan
    Write-KV 'Tenant ID'    $result.TenantId Green
    if ($result.Mode) { Write-KV 'Sign-in method' $result.Mode DarkGray }
    return $result
}

#endregion

#region Token test -------------------------------------------------------------

function Get-AppAccessToken {
    param(
        [Parameter(Mandatory)]
        [string]$TenantIdValue,

        [Parameter(Mandatory)]
        [string]$ClientIdValue,

        [Parameter(Mandatory)]
        [string]$ClientSecretValue,

        [Parameter(Mandatory)]
        [string]$Scope
    )

    $uri = "https://login.microsoftonline.com/$TenantIdValue/oauth2/v2.0/token"
    $body = ConvertTo-FormUrlEncoded -Data @{
        grant_type    = 'client_credentials'
        client_id     = $ClientIdValue
        client_secret = $ClientSecretValue
        scope         = $Scope
    }

    try {
        return Invoke-RestMethod -Uri $uri -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded'
    }
    catch {
        $raw = Get-HttpErrorBody -ErrorRecord $_
        $friendly = Get-FriendlyAadError -Raw $raw
        $message = $friendly.Title + ': ' + $friendly.Description
        if ($friendly.Hint) { $message += [Environment]::NewLine + $friendly.Hint }
        $ex = New-Object System.Exception $message
        throw $ex
    }
}

function New-ValidationReport {
    param(
        [Parameter(Mandatory)]
        [bool]$Success,

        [string]$TenantIdValue,
        [string]$SignedInAccount,
        [string]$SignInMode,
        [string]$ClientIdValue,
        [string]$AppIdUriValue,
        [string]$Scope,
        [object]$TokenResponse,
        [string]$ErrorMessage,
        [string[]]$ExpectedRoleList,
        [bool]$IncludeRawToken
    )

    $payload = $null
    $roles = [string[]]@()
    $expires = $null
    $issued = $null
    $rawToken = $null

    if ($Success -and $null -ne $TokenResponse -and $TokenResponse.PSObject.Properties['access_token']) {
        $rawToken = [string]$TokenResponse.access_token
        try { $payload = ConvertFrom-Jwt -Token $rawToken } catch { }
        $roles = Get-JwtRoles -Payload $payload
        $expires = ConvertFrom-UnixSeconds (Get-ClaimValue -Payload $payload -Name 'exp')
        $issued = ConvertFrom-UnixSeconds (Get-ClaimValue -Payload $payload -Name 'iat')
        if ($null -eq $expires -and $TokenResponse.PSObject.Properties['expires_in']) {
            try { $expires = [datetime]::UtcNow.AddSeconds([int]$TokenResponse.expires_in) } catch { }
        }
    }

    $expected = @()
    if ($ExpectedRoleList) {
        $expected = @($ExpectedRoleList | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Select-Object -Unique)
    }

    $missing = @()
    $matched = @()
    foreach ($role in $expected) {
        $found = $false
        foreach ($present in $roles) {
            if ([string]::Equals($present, $role, [System.StringComparison]::OrdinalIgnoreCase)) {
                $found = $true
                break
            }
        }
        if ($found) { $matched += $role } else { $missing += $role }
    }

    $hasRoles = $roles.Count -gt 0
    $rolesOk = $Success -and ($expected.Count -eq 0 -or $missing.Count -eq 0)

    $statusLabel = if (-not $Success) {
        'FAILED'
    }
    elseif ($expected.Count -gt 0 -and $missing.Count -gt 0) {
        'TOKEN ISSUED - MISSING ROLES'
    }
    elseif ($Success -and -not $hasRoles) {
        'TOKEN ISSUED - NO ROLES CLAIM'
    }
    else {
        'SUCCESS'
    }

    $audience = [string](Get-ClaimValue -Payload $payload -Name 'aud')
    $appId = [string](Get-ClaimValue -Payload $payload -Name 'appid')
    if ([string]::IsNullOrWhiteSpace($appId)) { $appId = [string](Get-ClaimValue -Payload $payload -Name 'azp') }
    $idtyp = [string](Get-ClaimValue -Payload $payload -Name 'idtyp')
    $tidClaim = [string](Get-ClaimValue -Payload $payload -Name 'tid')
    $tokenType = $null
    if ($null -ne $TokenResponse -and $TokenResponse.PSObject.Properties['token_type']) {
        $tokenType = [string]$TokenResponse.token_type
    }

    $remaining = $null
    if ($null -ne $expires) {
        $remaining = ($expires.ToUniversalTime() - [datetime]::UtcNow)
    }

    return [pscustomobject]@{
        GeneratedUtc      = [datetime]::UtcNow
        Success           = $Success
        StatusLabel       = $statusLabel
        RolesOk           = $rolesOk
        TenantId          = $TenantIdValue
        TokenTenantId     = $tidClaim
        SignedInAccount   = $SignedInAccount
        SignInMode        = $SignInMode
        ClientId          = $ClientIdValue
        AppIdUri          = $AppIdUriValue
        Scope             = $Scope
        TokenType         = $tokenType
        Audience          = $audience
        AppId             = $appId
        IdentityType      = $idtyp
        IssuedAtUtc       = $issued
        ExpiresOnUtc      = $expires
        TimeRemaining     = $remaining
        Roles             = [string[]]$roles
        HasRolesClaim     = ($roles.Count -gt 0)
        ExpectedRoles     = [string[]]$expected
        MatchedRoles      = [string[]]$matched
        MissingRoles      = [string[]]$missing
        ErrorMessage      = $ErrorMessage
        AccessToken       = $(if ($IncludeRawToken) { $rawToken } else { $null })
        Payload           = $payload
    }
}

function Format-Utc {
    param($Value)
    if ($null -eq $Value) { return '-' }
    try { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' } catch { return [string]$Value }
}

function Write-ValidationReport {
    param($Report)

    Write-Host ''
    Write-Host '  ================================================================' -ForegroundColor DarkCyan
    Write-Host '                     VALIDATION REPORT' -ForegroundColor Cyan
    Write-Host '  ================================================================' -ForegroundColor DarkCyan

    $statusColor = switch ($Report.StatusLabel) {
        'SUCCESS'                     { [ConsoleColor]::Green }
        'TOKEN ISSUED - NO ROLES CLAIM' { [ConsoleColor]::Yellow }
        'TOKEN ISSUED - MISSING ROLES'  { [ConsoleColor]::Yellow }
        default                       { [ConsoleColor]::Red }
    }

    Write-Section 'OAuth client credentials'
    Write-KV 'Result' $Report.StatusLabel $statusColor
    Write-KV 'Generated' (Format-Utc $Report.GeneratedUtc)

    Write-Section 'Tenant'
    Write-KV 'Tenant ID' $Report.TenantId Cyan
    if (-not [string]::IsNullOrWhiteSpace($Report.TokenTenantId) -and $Report.TokenTenantId -ne $Report.TenantId) {
        Write-KV 'Token tid' $Report.TokenTenantId Yellow
    }
    Write-KV 'Signed in as' $(if ($Report.SignedInAccount) { $Report.SignedInAccount } else { '(tenant supplied)' })
    if ($Report.SignInMode) { Write-KV 'Sign-in method' $Report.SignInMode }

    Write-Section 'App registration'
    Write-KV 'Client ID' $Report.ClientId
    Write-KV 'Application ID URI' $Report.AppIdUri
    Write-KV 'Scope' $Report.Scope DarkGray

    if ($Report.Success) {
        Write-Section 'Access token'
        Write-KV 'Token type' $(if ($Report.TokenType) { $Report.TokenType } else { 'Bearer' }) Green
        Write-KV 'Audience' $(if ($Report.Audience) { $Report.Audience } else { '-' })
        Write-KV 'App ID in token' $(if ($Report.AppId) { $Report.AppId } else { '-' })
        Write-KV 'Identity type' $(if ($Report.IdentityType) { $Report.IdentityType } else { 'app' })
        Write-KV 'Issued' (Format-Utc $Report.IssuedAtUtc)
        Write-KV 'Expires' (Format-Utc $Report.ExpiresOnUtc)
        if ($null -ne $Report.TimeRemaining) {
            $mins = [Math]::Max(0, [int]$Report.TimeRemaining.TotalMinutes)
            Write-KV 'Time remaining' "$mins minute(s)"
        }

        Write-Section 'Application roles in token'
        if ($Report.HasRolesClaim) {
            Write-Host "  The payload includes $($Report.Roles.Count) role(s):" -ForegroundColor Green
            foreach ($role in $Report.Roles) {
                Write-Host "    [+]  $role" -ForegroundColor Green
            }
        }
        else {
            Write-Host '  The payload does not include any ''roles'' in the token.' -ForegroundColor Yellow
            Write-Host '  Assign application roles to this app''s service principal, then wait' -ForegroundColor DarkGray
            Write-Host '  a few minutes and retry. Client-credentials tokens only carry app roles.' -ForegroundColor DarkGray
        }

        if ($Report.ExpectedRoles.Count -gt 0) {
            Write-Section 'Expected roles'
            foreach ($role in $Report.MatchedRoles) {
                Write-Host "    [+]  $role" -ForegroundColor Green
            }
            foreach ($role in $Report.MissingRoles) {
                Write-Host "    [!]  $role   (missing)" -ForegroundColor Red
            }
            if ($Report.MissingRoles.Count -eq 0) {
                Write-Host '  All expected roles are present.' -ForegroundColor Green
            }
        }

        if ($Report.AccessToken) {
            Write-Section 'Raw access token'
            Write-Host $Report.AccessToken -ForegroundColor DarkGray
        }
    }
    else {
        Write-Section 'Failure detail'
        Write-Host "  $($Report.ErrorMessage)" -ForegroundColor Red
        Write-Host ''
        Write-Host '  Typical fixes:' -ForegroundColor DarkGray
        Write-Host '    - Confirm the client ID belongs to this tenant' -ForegroundColor DarkGray
        Write-Host '    - Create a new client secret if the current one expired' -ForegroundColor DarkGray
        Write-Host '    - Set Application ID URI to the API app that defines the roles' -ForegroundColor DarkGray
        Write-Host '    - Grant admin consent and assign app roles to the client service principal' -ForegroundColor DarkGray
    }

    Write-Host ''
    Write-Host '  ================================================================' -ForegroundColor DarkCyan
    Write-Host ''
}

function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function New-HtmlReport {
    param($Report)

    $statusColor = switch ($Report.StatusLabel) {
        'SUCCESS'                       { '#0B6A0B' }
        'TOKEN ISSUED - NO ROLES CLAIM' { '#8A6D00' }
        'TOKEN ISSUED - MISSING ROLES'  { '#8A6D00' }
        default                         { '#A4262C' }
    }
    $statusBg = switch ($Report.StatusLabel) {
        'SUCCESS'                       { '#DFF6DD' }
        'TOKEN ISSUED - NO ROLES CLAIM' { '#FFF4CE' }
        'TOKEN ISSUED - MISSING ROLES'  { '#FFF4CE' }
        default                         { '#FDE7E9' }
    }

    $roleRows = ''
    if ($Report.HasRolesClaim) {
        foreach ($role in $Report.Roles) {
            $roleRows += "<li class='ok'>$(ConvertTo-HtmlEncoded $role)</li>"
        }
    }
    else {
        $roleRows = "<li class='warn'>No <code>roles</code> claim is present in the token.</li>"
    }

    $expectedBlock = ''
    if ($Report.ExpectedRoles.Count -gt 0) {
        $items = ''
        foreach ($role in $Report.MatchedRoles) {
            $items += "<li class='ok'>$(ConvertTo-HtmlEncoded $role)</li>"
        }
        foreach ($role in $Report.MissingRoles) {
            $items += "<li class='bad'>$(ConvertTo-HtmlEncoded $role) - missing</li>"
        }
        $expectedBlock = "<h2>Expected roles</h2><ul class='roles'>$items</ul>"
    }

    $errorBlock = ''
    if (-not $Report.Success -and $Report.ErrorMessage) {
        $errorBlock = "<h2>Failure detail</h2><pre class='error'>$(ConvertTo-HtmlEncoded $Report.ErrorMessage)</pre>"
    }

    $tokenBlock = ''
    if ($Report.AccessToken) {
        $tokenBlock = "<h2>Raw access token</h2><pre>$(ConvertTo-HtmlEncoded $Report.AccessToken)</pre>"
    }

    $remaining = '-'
    if ($null -ne $Report.TimeRemaining) {
        $remaining = '{0} minute(s)' -f [Math]::Max(0, [int]$Report.TimeRemaining.TotalMinutes)
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Entra ID App Registration Validator</title>
<style>
  body { font-family: 'Segoe UI', Calibri, Arial, sans-serif; background:#f3f2f1; color:#242424; margin:0; padding:32px; }
  .card { max-width: 880px; margin: 0 auto; background:#fff; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,.08); overflow:hidden; }
  header { background:#0078D4; color:#fff; padding:24px 32px; }
  header h1 { margin:0 0 6px 0; font-size:22px; font-weight:600; }
  header p { margin:0; opacity:.9; }
  .content { padding:28px 32px 36px; }
  .badge { display:inline-block; padding:8px 14px; border-radius:4px; font-weight:600; letter-spacing:.04em; background:$statusBg; color:$statusColor; }
  h2 { font-size:16px; margin:28px 0 10px; color:#0078D4; border-bottom:1px solid #edebe9; padding-bottom:6px; }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:8px 0; vertical-align:top; }
  th { width:220px; color:#605e5c; font-weight:600; }
  ul.roles { list-style:none; padding:0; margin:0; }
  ul.roles li { padding:8px 12px; margin:6px 0; border-radius:4px; font-family:Consolas, 'Courier New', monospace; }
  li.ok { background:#DFF6DD; color:#0B6A0B; }
  li.warn { background:#FFF4CE; color:#8A6D00; }
  li.bad { background:#FDE7E9; color:#A4262C; }
  pre { background:#f3f2f1; padding:12px; overflow:auto; border-radius:4px; }
  pre.error { background:#FDE7E9; color:#A4262C; white-space:pre-wrap; }
  footer { padding:0 32px 24px; color:#605e5c; font-size:12px; }
</style>
</head>
<body>
  <div class="card">
    <header>
      <h1>Entra ID App Registration Validator</h1>
      <p>OAuth client-credentials test and token role inspector</p>
    </header>
    <div class="content">
      <p><span class="badge">$(ConvertTo-HtmlEncoded $Report.StatusLabel)</span></p>
      <h2>OAuth client credentials</h2>
      <table>
        <tr><th>Generated</th><td>$(ConvertTo-HtmlEncoded (Format-Utc $Report.GeneratedUtc))</td></tr>
        <tr><th>Tenant ID</th><td>$(ConvertTo-HtmlEncoded $Report.TenantId)</td></tr>
        <tr><th>Signed in as</th><td>$(ConvertTo-HtmlEncoded $(if ($Report.SignedInAccount) { $Report.SignedInAccount } else { '(tenant supplied)' }))</td></tr>
        <tr><th>Client ID</th><td>$(ConvertTo-HtmlEncoded $Report.ClientId)</td></tr>
        <tr><th>Application ID URI</th><td>$(ConvertTo-HtmlEncoded $Report.AppIdUri)</td></tr>
        <tr><th>Scope</th><td>$(ConvertTo-HtmlEncoded $Report.Scope)</td></tr>
        <tr><th>Audience</th><td>$(ConvertTo-HtmlEncoded $Report.Audience)</td></tr>
        <tr><th>App ID in token</th><td>$(ConvertTo-HtmlEncoded $Report.AppId)</td></tr>
        <tr><th>Issued</th><td>$(ConvertTo-HtmlEncoded (Format-Utc $Report.IssuedAtUtc))</td></tr>
        <tr><th>Expires</th><td>$(ConvertTo-HtmlEncoded (Format-Utc $Report.ExpiresOnUtc))</td></tr>
        <tr><th>Time remaining</th><td>$(ConvertTo-HtmlEncoded $remaining)</td></tr>
      </table>
      $errorBlock
      <h2>Application roles in token</h2>
      <ul class="roles">$roleRows</ul>
      $expectedBlock
      $tokenBlock
    </div>
    <footer>Do not share this file if it contains a raw access token. Secrets are never written to the report.</footer>
  </div>
</body>
</html>
"@
}

function Show-ReportForm {
    param($Report)

    if (-not (Initialize-WinForms)) { return }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Entra ID App Registration Validator'
    $form.Width = 760
    $form.Height = 640
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $form.BackColor = [System.Drawing.Color]::White
    $form.MinimizeBox = $true
    $form.MaximizeBox = $false
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog

    $header = New-Object System.Windows.Forms.Panel
    $header.Dock = [System.Windows.Forms.DockStyle]::Top
    $header.Height = 72
    $header.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)

    $title = New-Object System.Windows.Forms.Label
    $title.Text = 'Entra ID App Registration Validator'
    $title.ForeColor = [System.Drawing.Color]::White
    $title.Font = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
    $title.AutoSize = $true
    $title.Location = New-Object System.Drawing.Point(20, 12)
    $header.Controls.Add($title)

    $subtitle = New-Object System.Windows.Forms.Label
    $subtitle.Text = 'OAuth client-credentials test  |  Token role inspector'
    $subtitle.ForeColor = [System.Drawing.Color]::FromArgb(220, 235, 250)
    $subtitle.Location = New-Object System.Drawing.Point(22, 42)
    $subtitle.AutoSize = $true
    $header.Controls.Add($subtitle)

    $status = New-Object System.Windows.Forms.Label
    $status.Text = "  $($Report.StatusLabel)  "
    $status.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
    $status.AutoSize = $true
    $status.Location = New-Object System.Drawing.Point(20, 88)
    if ($Report.StatusLabel -eq 'SUCCESS') {
        $status.ForeColor = [System.Drawing.Color]::FromArgb(11, 106, 11)
        $status.BackColor = [System.Drawing.Color]::FromArgb(223, 246, 221)
    }
    elseif ($Report.Success) {
        $status.ForeColor = [System.Drawing.Color]::FromArgb(138, 109, 0)
        $status.BackColor = [System.Drawing.Color]::FromArgb(255, 244, 206)
    }
    else {
        $status.ForeColor = [System.Drawing.Color]::FromArgb(164, 38, 44)
        $status.BackColor = [System.Drawing.Color]::FromArgb(253, 231, 233)
    }

    $box = New-Object System.Windows.Forms.TextBox
    $box.Multiline = $true
    $box.ReadOnly = $true
    $box.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
    $box.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $box.Location = New-Object System.Drawing.Point(20, 124)
    $box.Size = New-Object System.Drawing.Size(700, 420)
    $box.Font = New-Object System.Drawing.Font('Consolas', 10)
    $box.BackColor = [System.Drawing.Color]::FromArgb(250, 249, 248)

    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add("Tenant ID           $($Report.TenantId)")
    [void]$lines.Add("Signed in as        $(if ($Report.SignedInAccount) { $Report.SignedInAccount } else { '(tenant supplied)' })")
    [void]$lines.Add("Client ID           $($Report.ClientId)")
    [void]$lines.Add("Application ID URI  $($Report.AppIdUri)")
    [void]$lines.Add("Scope               $($Report.Scope)")
    if ($Report.Success) {
        [void]$lines.Add("Audience            $($Report.Audience)")
        [void]$lines.Add("Expires             $(Format-Utc $Report.ExpiresOnUtc)")
        [void]$lines.Add('')
        if ($Report.HasRolesClaim) {
            [void]$lines.Add('Application roles in token:')
            foreach ($role in $Report.Roles) { [void]$lines.Add("  + $role") }
        }
        else {
            [void]$lines.Add("The payload does not include any 'roles' in the token.")
        }
        if ($Report.ExpectedRoles.Count -gt 0) {
            [void]$lines.Add('')
            [void]$lines.Add('Expected roles:')
            foreach ($role in $Report.MatchedRoles) { [void]$lines.Add("  + $role") }
            foreach ($role in $Report.MissingRoles) { [void]$lines.Add("  ! $role  (missing)") }
        }
    }
    else {
        [void]$lines.Add('')
        [void]$lines.Add($Report.ErrorMessage)
    }
    $box.Text = $lines -join [Environment]::NewLine

    $close = New-Object System.Windows.Forms.Button
    $close.Text = 'Close'
    $close.Width = 110
    $close.Height = 32
    $close.Location = New-Object System.Drawing.Point(610, 556)
    $close.Add_Click({ $form.Close() })

    $copy = New-Object System.Windows.Forms.Button
    $copy.Text = 'Copy report'
    $copy.Width = 110
    $copy.Height = 32
    $copy.Location = New-Object System.Drawing.Point(490, 556)
    $copy.Tag = $box
    $copy.Add_Click({
        try {
            $textBox = [System.Windows.Forms.TextBox]$this.Tag
            [System.Windows.Forms.Clipboard]::SetText($textBox.Text)
        }
        catch { }
    })

    $form.Controls.Add($header)
    $form.Controls.Add($status)
    $form.Controls.Add($box)
    $form.Controls.Add($copy)
    $form.Controls.Add($close)
    $form.AcceptButton = $close
    [void]$form.ShowDialog()
    $form.Dispose()
}

#endregion

#region SelfTest ---------------------------------------------------------------

function New-TestJwt {
    param($PayloadObject)

    $headerJson = '{"alg":"none","typ":"JWT"}'
    $payloadJson = ConvertTo-Json -InputObject $PayloadObject -Compress -Depth 6
    $header = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes($headerJson))
    $payload = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes($payloadJson))
    return "$header.$payload.sig"
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Name)
    $a = [string]$Actual
    $e = [string]$Expected
    if ($a -ne $e) {
        throw "SelfTest failed: $Name. Expected '$e', got '$a'."
    }
}

function Invoke-SelfTest {
    function Invoke-Case {
        param([string]$Name, [scriptblock]$Body)
        try {
            & $Body
            Write-Host "  PASS  $Name" -ForegroundColor Green
            $script:SelfPassed++
        }
        catch {
            Write-Host "  FAIL  $Name" -ForegroundColor Red
            Write-Host "        $($_.Exception.Message)" -ForegroundColor DarkRed
            $script:SelfFailed++
        }
    }

    $script:SelfPassed = 0
    $script:SelfFailed = 0

    Write-Banner
    Write-Host '  Running built-in tests (no network)...' -ForegroundColor Cyan
    Write-Host ''

    Invoke-Case 'Scope appends /.default' {
        Assert-Equal (Get-OAuthScope -AppIdUri 'api://demo') 'api://demo/.default' 'scope'
        Assert-Equal (Get-OAuthScope -AppIdUri 'api://demo/') 'api://demo/.default' 'trim slash'
        Assert-Equal (Get-OAuthScope -AppIdUri 'api://demo/.default') 'api://demo/.default' 'already default'
    }

    Invoke-Case 'Base64url JWT decode with roles array' {
        $jwt = New-TestJwt @{
            aud   = 'api://demo'
            appid = '11111111-1111-1111-1111-111111111111'
            tid   = '22222222-2222-2222-2222-222222222222'
            roles = @('Orders.Read', 'Orders.Write')
            exp   = 2000000000
            idtyp = 'app'
        }
        $payload = ConvertFrom-Jwt -Token $jwt
        $roles = Get-JwtRoles -Payload $payload
        Assert-Equal $roles.Count 2 'role count'
        Assert-Equal $roles[0] 'Orders.Read' 'first role'
        Assert-Equal $roles[1] 'Orders.Write' 'second role'
        Assert-Equal (Get-ClaimValue -Payload $payload -Name 'tid') '22222222-2222-2222-2222-222222222222' 'tid'
    }

    Invoke-Case 'JWT decode handles missing padding and URL alphabet' {
        $json = '{"aud":"x","roles":["R1"]}'
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $b64 = ConvertTo-Base64Url $bytes
        if ($b64.Contains('=') -or $b64.Contains('+') -or $b64.Contains('/')) {
            throw 'Base64url helper still contains standard base64 alphabet.'
        }
        $jwt = "eyJhbGciOiJub25lIn0.$b64.sig"
        $payload = ConvertFrom-Jwt -Token $jwt
        $roles = Get-JwtRoles -Payload $payload
        Assert-Equal $roles[0] 'R1' 'url-safe role'
    }

    Invoke-Case 'Single string role is normalized' {
        $jwt = New-TestJwt @{ roles = 'Only.One' }
        $roles = Get-JwtRoles -Payload (ConvertFrom-Jwt -Token $jwt)
        Assert-Equal $roles.Count 1 'count'
        Assert-Equal $roles[0] 'Only.One' 'value'
    }

    Invoke-Case 'Missing roles claim returns empty' {
        $jwt = New-TestJwt @{ aud = 'api://demo'; appid = 'abc' }
        $roles = Get-JwtRoles -Payload (ConvertFrom-Jwt -Token $jwt)
        Assert-Equal $roles.Count 0 'empty'
    }

    Invoke-Case 'Friendly AADSTS secret error' {
        $raw = '{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.","error_codes":[7000215]}'
        $info = Get-FriendlyAadError -Raw $raw
        if ($info.Title -notmatch '7000215') { throw "Title missing code: $($info.Title)" }
        if ([string]::IsNullOrWhiteSpace($info.Hint)) { throw 'Expected a hint for 7000215.' }
    }

    Invoke-Case 'Report SUCCESS with expected roles' {
        $jwt = New-TestJwt @{
            aud   = 'api://demo'
            appid = 'app-1'
            tid   = 'tenant-1'
            roles = @('Orders.Read', 'Orders.Write')
            exp   = 2000000000
            iat   = 1700000000
            idtyp = 'app'
        }
        $tokenResponse = [pscustomobject]@{
            access_token = $jwt
            token_type   = 'Bearer'
            expires_in   = 3600
        }
        $report = New-ValidationReport -Success $true -TenantIdValue 'tenant-1' `
            -SignedInAccount 'admin@contoso.com' -SignInMode 'DeviceCode' `
            -ClientIdValue 'app-1' -AppIdUriValue 'api://demo' -Scope 'api://demo/.default' `
            -TokenResponse $tokenResponse -ErrorMessage $null `
            -ExpectedRoleList @('Orders.Read', 'Orders.Admin') -IncludeRawToken $false

        Assert-Equal $report.StatusLabel 'TOKEN ISSUED - MISSING ROLES' 'status'
        Assert-Equal $report.HasRolesClaim $true 'has roles'
        Assert-Equal $report.Roles.Count 2 'roles'
        Assert-Equal $report.MissingRoles[0] 'Orders.Admin' 'missing'
        Assert-Equal $report.MatchedRoles[0] 'Orders.Read' 'matched'
        if ($null -ne $report.AccessToken) { throw 'Raw token should be omitted by default.' }
    }

    Invoke-Case 'Report FAILED without token' {
        $report = New-ValidationReport -Success $false -TenantIdValue 'tenant-1' `
            -SignedInAccount 'admin@contoso.com' -SignInMode 'DeviceCode' `
            -ClientIdValue 'app-1' -AppIdUriValue 'api://demo' -Scope 'api://demo/.default' `
            -TokenResponse $null -ErrorMessage 'AADSTS7000215: Invalid client secret' `
            -ExpectedRoleList @() -IncludeRawToken $false
        Assert-Equal $report.StatusLabel 'FAILED' 'status'
        Assert-Equal $report.HasRolesClaim $false 'no roles'
        Assert-Equal $report.Roles.Count 0 'count'
    }

    Invoke-Case 'Report SUCCESS when all expected roles exist' {
        $jwt = New-TestJwt @{ aud = 'api://demo'; roles = @('A', 'B'); exp = 2000000000 }
        $tokenResponse = [pscustomobject]@{ access_token = $jwt; token_type = 'Bearer'; expires_in = 3600 }
        $report = New-ValidationReport -Success $true -TenantIdValue 't' -SignedInAccount 'u' `
            -SignInMode 'x' -ClientIdValue 'c' -AppIdUriValue 'api://demo' -Scope 'api://demo/.default' `
            -TokenResponse $tokenResponse -ErrorMessage $null -ExpectedRoleList @('A', 'B') -IncludeRawToken $true
        Assert-Equal $report.StatusLabel 'SUCCESS' 'status'
        Assert-Equal $report.RolesOk $true 'roles ok'
        if ([string]::IsNullOrWhiteSpace($report.AccessToken)) { throw 'Expected raw token when IncludeRawToken is set.' }

        $html = New-HtmlReport -Report $report
        if ($html -notmatch 'SUCCESS') { throw 'HTML missing SUCCESS badge.' }
        if ($html -notmatch 'Application roles in token') { throw 'HTML missing roles section.' }
    }

    Invoke-Case 'Tenant discovery helper reads tid from id token' {
        $jwt = New-TestJwt @{
            tid                 = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            preferred_username  = 'ada@contoso.com'
            name                = 'Ada Lovelace'
            iss                 = 'https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0'
        }
        $info = Get-TenantFromJwt -Token $jwt
        Assert-Equal $info.TenantId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' 'tid'
        Assert-Equal $info.Account 'ada@contoso.com' 'upn'
    }

    Invoke-Case 'Unix timestamp conversion' {
        $dt = ConvertFrom-UnixSeconds 0
        Assert-Equal $dt.Year 1970 'epoch year'
        Assert-Equal (ConvertFrom-UnixSeconds $null) $null 'null'
    }

    Write-Host ''
    Write-Host "  SelfTest complete: $($script:SelfPassed) passed, $($script:SelfFailed) failed." -ForegroundColor $(if ($script:SelfFailed -eq 0) { 'Green' } else { 'Red' })
    Write-Host ''
    if ($script:SelfFailed -gt 0) { exit 1 }
    exit 0
}

#endregion

#region Main -------------------------------------------------------------------

if ($SelfTest) {
    Invoke-SelfTest
}

[void](Initialize-WinForms)
Write-Banner

Write-Host '  This tool signs you in to discover the tenant, then tests the app' -ForegroundColor Gray
Write-Host '  registration with the OAuth client-credentials grant and lists token roles.' -ForegroundColor Gray
Write-Host ''

$tenantInfo = $null
$resolvedTenantId = $TenantId

if ([string]::IsNullOrWhiteSpace($resolvedTenantId)) {
    try {
        $tenantInfo = Connect-EntraTenant
        $resolvedTenantId = $tenantInfo.TenantId
    }
    catch {
        Write-Host ''
        Write-Host "  Tenant discovery failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host '  You can rerun with -TenantId <guid-or-domain> to skip sign-in.' -ForegroundColor Yellow
        exit 1
    }
}
else {
    Write-Section 'Tenant'
    Write-KV 'Tenant ID' $resolvedTenantId Cyan
    Write-Host '  (supplied; sign-in skipped)' -ForegroundColor DarkGray
}

Write-Section 'App registration to test'
$ClientId = Get-PromptValue -Label 'Application (client) ID' -Current $ClientId -Required

if ([string]::IsNullOrWhiteSpace($ClientSecret) -and $null -ne $ClientSecretSecure) {
    $ClientSecret = ConvertTo-PlainText -Secret $ClientSecretSecure
}
if ([string]::IsNullOrWhiteSpace($ClientSecret) -and -not [string]::IsNullOrWhiteSpace($env:ENTRA_APP_VALIDATOR_SECRET)) {
    $ClientSecret = [string]$env:ENTRA_APP_VALIDATOR_SECRET
}
Remove-Item Env:ENTRA_APP_VALIDATOR_SECRET -ErrorAction SilentlyContinue
$ClientSecret = Get-PromptValue -Label 'Client secret' -Current $ClientSecret -Required -Secret

$AppIdUri = Get-PromptValue -Label 'Application ID URI (resource where roles are defined)' -Current $AppIdUri -Required
$scope = Get-OAuthScope -AppIdUri $AppIdUri
Write-KV 'Scope' $scope DarkGray

Write-Section 'Requesting token'
Write-Host '  POST /oauth2/v2.0/token  (client_credentials)' -ForegroundColor DarkGray

$success = $false
$tokenResponse = $null
$errorMessage = $null

try {
    $tokenResponse = Get-AppAccessToken -TenantIdValue $resolvedTenantId -ClientIdValue $ClientId `
        -ClientSecretValue $ClientSecret -Scope $scope
    $success = $true
    Write-Host '  Token issued.' -ForegroundColor Green
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Host '  Token request failed.' -ForegroundColor Red
}

$account = $null
$mode = $null
if ($null -ne $tenantInfo) {
    $account = $tenantInfo.Account
    $mode = $tenantInfo.Mode
}

$report = New-ValidationReport -Success $success -TenantIdValue $resolvedTenantId `
    -SignedInAccount $account -SignInMode $mode `
    -ClientIdValue $ClientId -AppIdUriValue $AppIdUri -Scope $scope `
    -TokenResponse $tokenResponse -ErrorMessage $errorMessage `
    -ExpectedRoleList $ExpectedRoles -IncludeRawToken:$ShowToken

Write-ValidationReport -Report $report

if (-not [string]::IsNullOrWhiteSpace($HtmlReport)) {
    $html = New-HtmlReport -Report $report
    $dir = Split-Path -Parent $HtmlReport
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($HtmlReport, $html, [System.Text.Encoding]::UTF8)
    Write-Host "  HTML report saved: $HtmlReport" -ForegroundColor Cyan
}

if ($script:UseGui) {
    Show-ReportForm -Report $report
}

if ($success -and $report.RolesOk) { exit 0 }
if ($success) { exit 2 }
exit 1

#endregion

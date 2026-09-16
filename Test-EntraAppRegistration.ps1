#Requires -Version 5.1
<#
.SYNOPSIS
    Interactively validates an Entra ID app registration OAuth client-credentials
    connection and reports the application roles present in the access token.

.DESCRIPTION
    Signs the operator into Microsoft Entra ID with a device-code browser prompt
    to discover the tenant ID automatically, then requests an app-only token using
    the registered application's client ID, client secret, and Application ID URI.

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
    Use device-code sign-in. This is already the default because Connect-AzAccount
    hangs in Command Prompt / Windows Server (a "Not Responding" sign-in window).

.PARAMETER BrowserSignIn
    Try Azure PowerShell / Microsoft Graph interactive login first. Do not use this
    from cmd.exe; it commonly freezes on Windows Server 2016/2019.

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
    .\Test-EntraAppRegistration.ps1 -ConsoleOnly

.EXAMPLE
    .\Test-EntraAppRegistration.ps1 -SelfTest

.NOTES
    No Microsoft Graph or Azure PowerShell modules are required. Tenant discovery
    uses the OAuth device-code flow (open a browser, enter a code). Pass
    -BrowserSignIn only if you want Connect-AzAccount / Connect-MgGraph first;
    that path hangs in Command Prompt on Windows Server.

    The user sign-in is used only to discover the tenant. After sign-in the script
    lists directories the account can access and selects the Home (main) tenant,
    not a guest directory. The OAuth test itself uses the client-credentials grant
    against the app registration you supply.

    Compatible with Windows PowerShell 5.1 and PowerShell 7. On 5.1 the script
    enables TLS 1.2 (required by login.microsoftonline.com) and avoids PowerShell
    7-only syntax.
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

    [switch]$BrowserSignIn,

    [switch]$ConsoleOnly,

    [switch]$ShowToken,

    [Parameter()]
    [string]$HtmlReport,

    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 defaults to TLS 1.0; Entra ID requires TLS 1.2.
try {
    $tls12 = [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor $tls12
}
catch {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]3072
    }
    catch { }
}

$env:AZURE_IDENTITY_DISABLE_CP1 = 'true'
$env:MSAL_DESKTOP_APP_USE_WAM = '0'

$script:AzurePowerShellClientId = '1950a258-227b-4e31-a9cf-717495945fc2'
$script:GraphPowerShellClientId = '14d82eec-204b-4c2f-b113-9d477e6ee18c'
$script:AzureCliClientId        = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
$script:WinFormsLoaded          = $false
$script:IsWindowsHost           = $false
$script:UseGui                  = $false

try {
    # $IsWindows is PowerShell 6+ only; OS env/platform checks work on 5.1.
    if ([string]$env:OS -eq 'Windows_NT') {
        $script:IsWindowsHost = $true
    }
    elseif ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
        $script:IsWindowsHost = $true
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
    if ($BrowserSignIn) { [void]$argParts.Add('-BrowserSignIn') }
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
        $response = $null
        $ex = $ErrorRecord.Exception
        if ($null -ne $ex -and $ex.PSObject.Properties['Response'] -and $ex.Response) {
            $response = $ex.Response
        }
        elseif ($null -ne $ex -and $ex.PSObject.Properties['InnerException'] -and $ex.InnerException) {
            $inner = $ex.InnerException
            if ($inner.PSObject.Properties['Response'] -and $inner.Response) {
                $response = $inner.Response
            }
        }

        if ($response) {
            # PS 7 HttpResponseMessage.Content; skip on 5.1 HttpWebResponse.
            if ($response.PSObject.Properties['Content'] -and $response.Content) {
                $content = $response.Content
                if ($content -is [string]) { return $content }
                try { return [string]$content.ReadAsStringAsync().Result } catch { }
            }

            $stream = $null
            try { $stream = $response.GetResponseStream() } catch { }
            if ($stream) {
                try {
                    if ($stream.PSObject.Properties['CanSeek'] -and $stream.CanSeek) {
                        $stream.Position = 0
                    }
                }
                catch { }
                $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
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

    if ($null -ne $ErrorRecord.Exception) {
        return [string]$ErrorRecord.Exception.Message
    }
    return [string]$ErrorRecord
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
    # -InputObject avoids 5.1 pipeline quirks with ConvertFrom-Json.
    return ConvertFrom-Json -InputObject $json
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
        $epoch = New-Object System.DateTime 1970, 1, 1, 0, 0, 0, ([System.DateTimeKind]::Utc)
        return $epoch.AddSeconds($seconds)
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
        $json = ConvertFrom-Json -InputObject $Raw
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

function Get-GuidFromText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    if ($Text -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {
        return $Matches[1]
    }
    return $null
}

function Get-TenantFromJwt {
    param([string]$Token)

    if ([string]::IsNullOrWhiteSpace($Token)) { return $null }
    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) { return $null }

    try {
        $payload = ConvertFrom-Jwt -Token $Token
        $tid = [string](Get-ClaimValue -Payload $payload -Name 'tid')
        $iss = [string](Get-ClaimValue -Payload $payload -Name 'iss')
        if ([string]::IsNullOrWhiteSpace($tid)) {
            $tid = [string](Get-GuidFromText -Text $iss)
        }
        if ([string]::IsNullOrWhiteSpace($tid)) { return $null }

        $upn = [string](Get-ClaimValue -Payload $payload -Name 'preferred_username')
        if ([string]::IsNullOrWhiteSpace($upn)) {
            $upn = [string](Get-ClaimValue -Payload $payload -Name 'upn')
        }
        if ([string]::IsNullOrWhiteSpace($upn)) {
            $upn = [string](Get-ClaimValue -Payload $payload -Name 'unique_name')
        }
        $name = [string](Get-ClaimValue -Payload $payload -Name 'name')

        return [pscustomobject]@{
            TenantId = $tid
            Account  = $upn
            Name     = $name
            Issuer   = $iss
        }
    }
    catch {
        return $null
    }
}

function Get-DirectoryTenantId {
    param($Record)

    if ($null -eq $Record) { return '' }
    $id = [string](Get-ClaimValue -Payload $Record -Name 'tenantId')
    if ([string]::IsNullOrWhiteSpace($id)) {
        $id = [string](Get-ClaimValue -Payload $Record -Name 'TenantId')
    }
    if ([string]::IsNullOrWhiteSpace($id)) {
        $id = [string](Get-ClaimValue -Payload $Record -Name 'Id')
    }
    if ([string]::IsNullOrWhiteSpace($id)) {
        $id = [string](Get-GuidFromText -Text ([string](Get-ClaimValue -Payload $Record -Name 'id')))
    }
    return $id
}

function Select-MainEntraTenant {
    param(
        $Directories,
        [string]$LoginTenantId,
        [string]$Upn
    )

    $msa = '9188040d-6c67-4c5b-b112-36a304b66dad'
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($Directories)) {
        if ($null -eq $item) { continue }
        $tid = Get-DirectoryTenantId -Record $item
        if ([string]::IsNullOrWhiteSpace($tid)) { continue }
        if ([string]::Equals($tid, $msa, [System.StringComparison]::OrdinalIgnoreCase)) { continue }

        $display = [string](Get-ClaimValue -Payload $item -Name 'displayName')
        if ([string]::IsNullOrWhiteSpace($display)) {
            $display = [string](Get-ClaimValue -Payload $item -Name 'Name')
        }
        $category = [string](Get-ClaimValue -Payload $item -Name 'tenantCategory')
        $defaultDomain = [string](Get-ClaimValue -Payload $item -Name 'defaultDomain')
        if ([string]::IsNullOrWhiteSpace($defaultDomain)) {
            $defaultDomain = [string](Get-ClaimValue -Payload $item -Name 'DefaultDomain')
        }
        $domains = Get-ClaimValue -Payload $item -Name 'domains'
        if ($null -eq $domains) {
            $domains = Get-ClaimValue -Payload $item -Name 'Domains'
        }

        [void]$list.Add([pscustomobject]@{
            TenantId       = $tid
            DisplayName    = $display
            TenantCategory = $category
            DefaultDomain  = $defaultDomain
            Domains        = $domains
        })
    }

    $chosen = $null
    $reason = 'login-token'

    foreach ($row in $list) {
        if ([string]::Equals([string]$row.TenantCategory, 'Home', [System.StringComparison]::OrdinalIgnoreCase)) {
            $chosen = $row
            $reason = 'home'
            break
        }
    }

    if ($null -eq $chosen -and -not [string]::IsNullOrWhiteSpace($Upn) -and $Upn -match '@(.+)$') {
        $upnDomain = $Matches[1]
        foreach ($row in $list) {
            $hit = $false
            if (-not [string]::IsNullOrWhiteSpace($row.DefaultDomain) -and
                [string]::Equals($row.DefaultDomain, $upnDomain, [System.StringComparison]::OrdinalIgnoreCase)) {
                $hit = $true
            }
            foreach ($d in @($row.Domains)) {
                $text = [string]$d
                if ($text -match 'name=') {
                    # Graph verifiedDomains objects
                    $n = [string](Get-ClaimValue -Payload $d -Name 'name')
                    if ([string]::Equals($n, $upnDomain, [System.StringComparison]::OrdinalIgnoreCase)) { $hit = $true }
                }
                elseif ([string]::Equals($text, $upnDomain, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $hit = $true
                }
            }
            if ($hit) {
                $chosen = $row
                $reason = 'upn-domain'
                break
            }
        }
    }

    if ($null -eq $chosen -and -not [string]::IsNullOrWhiteSpace($LoginTenantId)) {
        foreach ($row in $list) {
            if ([string]::Equals($row.TenantId, $LoginTenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
                $chosen = $row
                $reason = 'login-match'
                break
            }
        }
    }

    if ($null -eq $chosen -and $list.Count -eq 1) {
        $chosen = $list[0]
        $reason = 'only-directory'
    }

    if ($null -eq $chosen) {
        return [pscustomobject]@{
            TenantId      = $LoginTenantId
            DisplayName   = ''
            DefaultDomain = ''
            IsHome        = $false
            Reason        = $reason
            Directories   = $list
        }
    }

    return [pscustomobject]@{
        TenantId      = [string]$chosen.TenantId
        DisplayName   = [string]$chosen.DisplayName
        DefaultDomain = [string]$chosen.DefaultDomain
        IsHome        = [string]::Equals([string]$chosen.TenantCategory, 'Home', [System.StringComparison]::OrdinalIgnoreCase)
        Reason        = $reason
        Directories   = $list
    }
}

function Get-ArmAccessToken {
    param(
        [string]$RefreshToken,
        [string]$ClientId,
        [string]$Authority,
        [string]$ExistingAccessToken
    )

    if (-not [string]::IsNullOrWhiteSpace($ExistingAccessToken)) {
        try {
            $payload = ConvertFrom-Jwt -Token $ExistingAccessToken
            $aud = Get-ClaimValue -Payload $payload -Name 'aud'
            foreach ($a in @($aud)) {
                if ([string]$a -like '*management.azure.com*') { return $ExistingAccessToken }
            }
        }
        catch { }
    }

    if ([string]::IsNullOrWhiteSpace($RefreshToken) -or [string]::IsNullOrWhiteSpace($ClientId)) {
        return $null
    }

    try {
        $body = ConvertTo-FormUrlEncoded -Data @{
            grant_type    = 'refresh_token'
            client_id     = $ClientId
            refresh_token = $RefreshToken
            scope         = 'https://management.azure.com/.default'
        }
        $tok = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/token" `
            -ContentType 'application/x-www-form-urlencoded' -Body $body -ErrorAction Stop
        return [string](Get-ClaimValue -Payload $tok -Name 'access_token')
    }
    catch {
        return $null
    }
}

function Get-GraphAccessToken {
    param(
        [string]$RefreshToken,
        [string]$ClientId,
        [string]$Authority,
        [string]$ExistingAccessToken
    )

    if (-not [string]::IsNullOrWhiteSpace($ExistingAccessToken)) {
        try {
            $payload = ConvertFrom-Jwt -Token $ExistingAccessToken
            $aud = Get-ClaimValue -Payload $payload -Name 'aud'
            foreach ($a in @($aud)) {
                if ([string]$a -like '*graph.microsoft.com*' -or [string]$a -eq '00000003-0000-0000-c000-000000000000') {
                    return $ExistingAccessToken
                }
            }
        }
        catch { }
    }

    if ([string]::IsNullOrWhiteSpace($RefreshToken) -or [string]::IsNullOrWhiteSpace($ClientId)) {
        return $null
    }

    try {
        $body = ConvertTo-FormUrlEncoded -Data @{
            grant_type    = 'refresh_token'
            client_id     = $ClientId
            refresh_token = $RefreshToken
            scope         = 'https://graph.microsoft.com/User.Read'
        }
        $tok = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/token" `
            -ContentType 'application/x-www-form-urlencoded' -Body $body -ErrorAction Stop
        return [string](Get-ClaimValue -Payload $tok -Name 'access_token')
    }
    catch {
        return $null
    }
}

function Get-DirectoryListFromArm {
    param([string]$AccessToken)

    if ([string]::IsNullOrWhiteSpace($AccessToken)) { return @() }
    try {
        $headers = @{ Authorization = "Bearer $AccessToken" }
        $resp = Invoke-RestMethod -Method Get -Uri 'https://management.azure.com/tenants?api-version=2020-01-01' `
            -Headers $headers -ErrorAction Stop
        $value = Get-ClaimValue -Payload $resp -Name 'value'
        return @($value)
    }
    catch {
        return @()
    }
}

function Get-DirectoryListFromGraph {
    param([string]$AccessToken)

    if ([string]::IsNullOrWhiteSpace($AccessToken)) { return @() }
    try {
        $headers = @{ Authorization = "Bearer $AccessToken" }
        $resp = Invoke-RestMethod -Method Get -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains' `
            -Headers $headers -ErrorAction Stop
        $value = Get-ClaimValue -Payload $resp -Name 'value'
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($org in @($value)) {
            $domains = New-Object System.Collections.Generic.List[string]
            $verified = Get-ClaimValue -Payload $org -Name 'verifiedDomains'
            $defaultDomain = ''
            foreach ($d in @($verified)) {
                $n = [string](Get-ClaimValue -Payload $d -Name 'name')
                if (-not [string]::IsNullOrWhiteSpace($n)) { [void]$domains.Add($n) }
                $isDefault = Get-ClaimValue -Payload $d -Name 'isDefault'
                if ($isDefault) { $defaultDomain = $n }
            }
            [void]$list.Add([pscustomobject]@{
                tenantId      = [string](Get-ClaimValue -Payload $org -Name 'id')
                displayName   = [string](Get-ClaimValue -Payload $org -Name 'displayName')
                defaultDomain = $defaultDomain
                tenantCategory = ''
                domains       = $domains.ToArray()
            })
        }
        return ,$list.ToArray()
    }
    catch {
        return @()
    }
}

function Resolve-MainEntraTenant {
    param(
        $TokenResponse,
        [string]$ClientId,
        [string]$Authority,
        [string]$LoginTenantId,
        [string]$Account
    )

    $access = [string](Get-ClaimValue -Payload $TokenResponse -Name 'access_token')
    $refresh = [string](Get-ClaimValue -Payload $TokenResponse -Name 'refresh_token')

    $directories = @()
    $armToken = Get-ArmAccessToken -RefreshToken $refresh -ClientId $ClientId -Authority $Authority -ExistingAccessToken $access
    if (-not [string]::IsNullOrWhiteSpace($armToken)) {
        $directories = Get-DirectoryListFromArm -AccessToken $armToken
    }

    if ($directories.Count -eq 0) {
        $graphToken = Get-GraphAccessToken -RefreshToken $refresh -ClientId $ClientId -Authority $Authority -ExistingAccessToken $access
        $directories = Get-DirectoryListFromGraph -AccessToken $graphToken
    }

    return (Select-MainEntraTenant -Directories $directories -LoginTenantId $LoginTenantId -Upn $Account)
}

function Connect-ViaAzAccountTenant {
    if (-not (Get-Command Connect-AzAccount -ErrorAction SilentlyContinue)) {
        try { Import-Module Az.Accounts -ErrorAction Stop | Out-Null } catch { return $null }
    }
    if (-not (Get-Command Connect-AzAccount -ErrorAction SilentlyContinue)) { return $null }

    Write-Host '  Opening interactive Azure PowerShell sign-in (browser)...' -ForegroundColor Cyan
    $azParams = @{ ErrorAction = 'Stop' }
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) { $azParams['Tenant'] = $TenantId }
    Connect-AzAccount @azParams | Out-Null

    $ctx = Get-AzContext -ErrorAction Stop
    $tenantObj = Get-ClaimValue -Payload $ctx -Name 'Tenant'
    $loginTid = [string](Get-ClaimValue -Payload $tenantObj -Name 'Id')
    if ([string]::IsNullOrWhiteSpace($loginTid)) {
        $loginTid = [string](Get-ClaimValue -Payload $tenantObj -Name 'TenantId')
    }
    if ([string]::IsNullOrWhiteSpace($loginTid)) { return $null }

    $accountObj = Get-ClaimValue -Payload $ctx -Name 'Account'
    $account = [string](Get-ClaimValue -Payload $accountObj -Name 'Id')

    $azTenants = @()
    try { $azTenants = @(Get-AzTenant -ErrorAction Stop) } catch { }

    $main = Select-MainEntraTenant -Directories $azTenants -LoginTenantId $loginTid -Upn $account
    $tid = [string]$main.TenantId
    if ([string]::IsNullOrWhiteSpace($tid)) { $tid = $loginTid }

    return [pscustomobject]@{
        TenantId        = $tid
        LoginTenantId   = $loginTid
        TenantName      = [string]$main.DisplayName
        TenantDomain    = [string]$main.DefaultDomain
        IsHomeTenant    = [bool]$main.IsHome
        TenantReason    = [string]$main.Reason
        DirectoryCount  = @($main.Directories).Count
        Account         = $account
        Name            = $account
        Issuer          = "https://login.microsoftonline.com/$tid/v2.0"
        Mode            = 'AzInteractive'
    }
}

function Connect-ViaMgGraphTenant {
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        try { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null } catch { return $null }
    }
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) { return $null }

    Write-Host '  Opening interactive Microsoft Graph sign-in...' -ForegroundColor Cyan

    $cmd = Get-Command Connect-MgGraph -ErrorAction Stop
    $params = @{
        Scopes      = @('openid', 'profile')
        ErrorAction = 'Stop'
    }
    # -NoWelcome / -UseDeviceAuthentication are not in every Graph 5.1 module build.
    if ($cmd.Parameters.ContainsKey('NoWelcome')) {
        $params['NoWelcome'] = $true
    }
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) { $params['TenantId'] = $TenantId }
    if ($DeviceCode) {
        if (-not $cmd.Parameters.ContainsKey('UseDeviceAuthentication')) { return $null }
        $params['UseDeviceAuthentication'] = $true
    }

    Connect-MgGraph @params | Out-Null
    $ctx = Get-MgContext -ErrorAction Stop
    $tid = [string](Get-ClaimValue -Payload $ctx -Name 'TenantId')
    if ([string]::IsNullOrWhiteSpace($tid)) { return $null }

    return [pscustomobject]@{
        TenantId = $tid
        Account  = [string](Get-ClaimValue -Payload $ctx -Name 'Account')
        Name     = [string](Get-ClaimValue -Payload $ctx -Name 'Account')
        Issuer   = "https://login.microsoftonline.com/$tid/v2.0"
        Mode     = 'MgGraph'
    }
}

function Connect-ViaDeviceCodeTenant {
    param(
        [Parameter(Mandatory)]
        [string]$AppClientId,

        [Parameter()]
        [string[]]$ScopeList
    )

    if (-not $ScopeList -or $ScopeList.Count -eq 0) {
        $ScopeList = @(
            'openid profile offline_access https://management.azure.com/.default',
            'openid profile offline_access'
        )
    }

    $tenantHint = if (-not [string]::IsNullOrWhiteSpace($TenantId)) { $TenantId.Trim() } else { 'organizations' }
    $authority = "https://login.microsoftonline.com/$tenantHint"

    $dc = $null
    $usedScope = $null
    foreach ($scope in $ScopeList) {
        try {
            $dcBody = ConvertTo-FormUrlEncoded -Data @{
                client_id = $AppClientId
                scope     = $scope
            }
            $dc = Invoke-RestMethod -Method Post -Uri "$authority/oauth2/v2.0/devicecode" `
                -ContentType 'application/x-www-form-urlencoded' -Body $dcBody -ErrorAction Stop
            $usedScope = $scope
            break
        }
        catch {
            $dc = $null
        }
    }

    if ($null -eq $dc) {
        throw "Device code start failed for client $AppClientId"
    }

    $verificationUri = [string](Get-ClaimValue -Payload $dc -Name 'verification_uri')
    $verificationUriComplete = [string](Get-ClaimValue -Payload $dc -Name 'verification_uri_complete')
    $userCode = [string](Get-ClaimValue -Payload $dc -Name 'user_code')
    $deviceCodeValue = [string](Get-ClaimValue -Payload $dc -Name 'device_code')
    $expiresIn = Get-ClaimValue -Payload $dc -Name 'expires_in'
    $pollInterval = Get-ClaimValue -Payload $dc -Name 'interval'
    if ($null -eq $expiresIn -or [string]::IsNullOrWhiteSpace([string]$expiresIn)) { $expiresIn = 900 }
    if ($null -eq $pollInterval -or [string]::IsNullOrWhiteSpace([string]$pollInterval)) { $pollInterval = 5 }

    Write-Host ''
    Write-Host '  Sign in with your work or school account:' -ForegroundColor White
    Write-Host "    1. Open  $verificationUri" -ForegroundColor Cyan
    Write-Host "    2. Enter code:  $userCode" -ForegroundColor Yellow
    Write-Host '    3. Come back here; this window waits until you finish.' -ForegroundColor Gray
    Write-Host '  Waiting for sign-in...' -ForegroundColor DarkGray
    Write-Host ''

    try { Set-Clipboard -Value $userCode -ErrorAction SilentlyContinue } catch { }

    $openUri = $verificationUri
    if (-not [string]::IsNullOrWhiteSpace($verificationUriComplete)) {
        $openUri = $verificationUriComplete
    }
    if (-not [string]::IsNullOrWhiteSpace($openUri)) {
        try { Start-Process $openUri | Out-Null } catch { }
    }

    $deadline = [datetime]::UtcNow.AddSeconds([int]$expiresIn)
    $interval = [Math]::Max(5, [int]$pollInterval)
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
                device_code = $deviceCodeValue
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

    $jwt = [string](Get-ClaimValue -Payload $token -Name 'id_token')
    if ([string]::IsNullOrWhiteSpace($jwt)) {
        $jwt = [string](Get-ClaimValue -Payload $token -Name 'access_token')
    }

    $discovered = Get-TenantFromJwt -Token $jwt
    if ($null -eq $discovered) {
        throw 'Sign-in succeeded but the token did not include a tenant ID (tid) claim.'
    }

    $refreshAuthority = $authority
    if (-not [string]::IsNullOrWhiteSpace($discovered.TenantId)) {
        $refreshAuthority = "https://login.microsoftonline.com/$($discovered.TenantId)"
    }

    $main = Resolve-MainEntraTenant -TokenResponse $token -ClientId $AppClientId `
        -Authority $refreshAuthority -LoginTenantId $discovered.TenantId -Account $discovered.Account

    $tid = [string]$main.TenantId
    if ([string]::IsNullOrWhiteSpace($tid)) { $tid = $discovered.TenantId }

    return [pscustomobject]@{
        TenantId       = $tid
        LoginTenantId  = $discovered.TenantId
        TenantName     = [string]$main.DisplayName
        TenantDomain   = [string]$main.DefaultDomain
        IsHomeTenant   = [bool]$main.IsHome
        TenantReason   = [string]$main.Reason
        DirectoryCount = @($main.Directories).Count
        Account        = $discovered.Account
        Name           = $discovered.Name
        Issuer         = $discovered.Issuer
        Mode           = 'DeviceCode'
        Scope          = $usedScope
    }
}

function Connect-EntraTenant {
    Write-Section 'Tenant discovery'
    Write-Host '  Sign in to Microsoft Entra ID. The tenant ID is read from your token.' -ForegroundColor Gray

    $errors = New-Object System.Collections.Generic.List[string]
    $result = $null

    # Device code is the default. Connect-AzAccount plus a WinForms parent window
    # freezes in cmd.exe on Windows Server ("Entra ID sign-in (Not Responding)").
    $useBrowser = $BrowserSignIn -and -not $DeviceCode
    if ($useBrowser) {
        try { $result = Connect-ViaAzAccountTenant } catch { [void]$errors.Add("Azure PowerShell: $($_.Exception.Message)") }
        if ($null -eq $result) {
            try { $result = Connect-ViaMgGraphTenant } catch { [void]$errors.Add("Microsoft Graph: $($_.Exception.Message)") }
        }
        if ($null -eq $result) {
            Write-Host '  Interactive browser sign-in was not available; using device code.' -ForegroundColor Yellow
        }
    }
    else {
        Write-Host '  A browser will open. Enter the code shown below to continue.' -ForegroundColor Gray
    }

    if ($null -eq $result) {
        $attempts = @(
            @{ ClientId = $script:AzureCliClientId;        Scopes = @('openid profile offline_access https://management.azure.com/.default', 'openid profile offline_access') }
            @{ ClientId = $script:AzurePowerShellClientId; Scopes = @('openid profile offline_access https://management.azure.com/.default', 'openid profile offline_access') }
            @{ ClientId = $script:GraphPowerShellClientId; Scopes = @('openid profile offline_access https://graph.microsoft.com/User.Read', 'openid profile offline_access') }
        )
        foreach ($attempt in $attempts) {
            try {
                $result = Connect-ViaDeviceCodeTenant -AppClientId ([string]$attempt.ClientId) -ScopeList $attempt.Scopes
                if ($null -ne $result) { break }
            }
            catch {
                [void]$errors.Add("Device code ($($attempt.ClientId)): $($_.Exception.Message)")
            }
        }
    }

    if ($null -eq $result) {
        $detail = ($errors | Select-Object -Unique) -join [Environment]::NewLine
        throw "Could not sign in to Entra ID to discover the tenant.`n$detail"
    }

    Write-KV 'Signed in as' $result.Account Cyan
    $tenantName = [string](Get-ClaimValue -Payload $result -Name 'TenantName')
    $tenantDomain = [string](Get-ClaimValue -Payload $result -Name 'TenantDomain')
    $loginTid = [string](Get-ClaimValue -Payload $result -Name 'LoginTenantId')
    if (-not [string]::IsNullOrWhiteSpace($tenantName)) {
        Write-KV 'Main tenant' $tenantName Green
    }
    Write-KV 'Main tenant ID' $result.TenantId Green
    if (-not [string]::IsNullOrWhiteSpace($tenantDomain)) {
        Write-KV 'Tenant domain' $tenantDomain
    }
    if (-not [string]::IsNullOrWhiteSpace($loginTid) -and
        -not [string]::Equals($loginTid, $result.TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-KV 'Sign-in directory' $loginTid Yellow
        Write-Host '  Using the Home (main) tenant, not the guest directory from sign-in.' -ForegroundColor Yellow
    }
    $dirCount = Get-ClaimValue -Payload $result -Name 'DirectoryCount'
    if ($null -eq $dirCount -or [int]$dirCount -lt 1) {
        Write-Host '  Could not list all directories; using the tenant ID from the sign-in token.' -ForegroundColor Yellow
        Write-Host '  If this is not the main (Home) tenant, rerun with -TenantId <guid>.' -ForegroundColor Yellow
    }
    elseif ([int]$dirCount -gt 1) {
        Write-KV 'Directories found' ([string]$dirCount)
        Write-Host '  To test an app in a different tenant, rerun with -TenantId <guid>.' -ForegroundColor DarkGray
    }
    $signInMode = [string](Get-ClaimValue -Payload $result -Name 'Mode')
    if (-not [string]::IsNullOrWhiteSpace($signInMode)) { Write-KV 'Sign-in method' $signInMode DarkGray }
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
        $ex = New-Object -TypeName System.Exception -ArgumentList $message
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

    Invoke-Case 'Tenant id falls back to issuer GUID when tid is missing' {
        $jwt = New-TestJwt @{
            preferred_username = 'ada@contoso.com'
            iss                = 'https://sts.windows.net/bbbbbbbb-cccc-dddd-eeee-ffffffffffff/'
        }
        $info = Get-TenantFromJwt -Token $jwt
        Assert-Equal $info.TenantId 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff' 'iss tid'
    }

    Invoke-Case 'Main tenant prefers Home directory over guest login tid' {
        $dirs = @(
            [pscustomobject]@{ tenantId = 'guest-id'; displayName = 'Fabrikam'; tenantCategory = 'Managed'; defaultDomain = 'fabrikam.com' },
            [pscustomobject]@{ tenantId = 'home-id'; displayName = 'Contoso'; tenantCategory = 'Home'; defaultDomain = 'contoso.com' }
        )
        $main = Select-MainEntraTenant -Directories $dirs -LoginTenantId 'guest-id' -Upn 'ada@contoso.com'
        Assert-Equal $main.TenantId 'home-id' 'home'
        Assert-Equal $main.Reason 'home' 'reason'
        Assert-Equal $main.DisplayName 'Contoso' 'name'
    }

    Invoke-Case 'Main tenant matches UPN domain when category is missing' {
        $dirs = @(
            [pscustomobject]@{ TenantId = 'other-id'; Name = 'Other'; Domains = @('other.onmicrosoft.com') },
            [pscustomobject]@{ TenantId = 'main-id'; Name = 'Contoso'; DefaultDomain = 'contoso.com'; Domains = @('contoso.com') }
        )
        $main = Select-MainEntraTenant -Directories $dirs -LoginTenantId 'other-id' -Upn 'ada@contoso.com'
        Assert-Equal $main.TenantId 'main-id' 'upn'
        Assert-Equal $main.Reason 'upn-domain' 'reason'
    }

    Invoke-Case 'Unix timestamp conversion' {
        $dt = ConvertFrom-UnixSeconds 0
        Assert-Equal $dt.Year 1970 'epoch year'
        Assert-Equal $dt.Hour 0 'epoch hour'
        Assert-Equal $dt.Kind 'Utc' 'epoch kind'
        Assert-Equal (ConvertFrom-UnixSeconds $null) $null 'null'
    }

    Invoke-Case 'Single-element JSON error_codes unwraps on 5.1' {
        $raw = '{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.","error_codes":[7000215]}'
        $info = Get-FriendlyAadError -Raw $raw
        if ($info.Title -notmatch '7000215') { throw "Title missing code: $($info.Title)" }
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

Write-Banner

Write-Host '  This tool signs you in to discover the tenant, then tests the app' -ForegroundColor Gray
Write-Host '  registration with the OAuth client-credentials grant and lists token roles.' -ForegroundColor Gray
Write-Host ''

$tenantInfo = $null
$resolvedTenantId = $TenantId

if ([string]::IsNullOrWhiteSpace($resolvedTenantId)) {
    try {
        $tenantInfo = Connect-EntraTenant
        $resolvedTenantId = [string](Get-ClaimValue -Payload $tenantInfo -Name 'TenantId')
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
    $account = [string](Get-ClaimValue -Payload $tenantInfo -Name 'Account')
    $mode = [string](Get-ClaimValue -Payload $tenantInfo -Name 'Mode')
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

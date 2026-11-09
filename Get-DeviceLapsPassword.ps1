#Requires -Version 5.1
<#
================================================================================
 SCRIPT : Get-DeviceLapsPassword.ps1
 PURPOSE: Return the local administrator account and current Windows LAPS
          password for an Intune-managed device from Microsoft Entra ID.
          Run with no parameters for an interactive console checkout.
 AUTHOR : Anthony Blake
 UPDATED: 2026-11-09
 COMPAT : Windows PowerShell 5.1 (Microsoft.Graph.Authentication, app-only cert)
================================================================================

.SYNOPSIS
    Retrieves the local administrator account name and current Windows LAPS password
    for an Intune-managed device from Microsoft Entra ID.

.DESCRIPTION
    Two ways to run it:

      Interactive (helpdesk / console)
        Double-click or run with no parameters. Prompts for a computer name,
        shows the local admin account and LAPS password, can copy the password
        to the clipboard, then asks whether to look up another device.

      Unattended (ServiceNow MID Server catalog item)
        Pass -ComputerName (and optional -RequestId / -RequesterUpn).
        Writes exactly ONE line of JSON to stdout and sets the process exit code.

    Flow: Intune managed device -> Entra device ID -> LAPS password backed up to Entra ID.
    Authenticates to Microsoft Graph app-only with a certificate (no browser sign-in).
    The password is never written to the log file.

    Credentials are resolved in this order:
        1. -TenantId / -ClientId / -CertificateThumbprint parameters
        2. ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_CERT_THUMBPRINT environment variables
        3. Values in the CONFIGURATION region below

.PARAMETER ComputerName
    Device name as entered in the catalog item or at the interactive prompt.
    An FQDN is reduced to the host name. Optional in interactive mode.

.PARAMETER Interactive
    Force the console prompts and formatted result, even if -ComputerName was supplied.

.PARAMETER NonInteractive
    Force the ServiceNow JSON contract (no prompts). Used by the MID Server.

.PARAMETER RequesterUpn
    Optional. If supplied, the request is refused unless this UPN is the device's Intune
    primary user (case-insensitive). Leave empty to keep the current catalog behaviour.

.PARAMETER RequestId
    Optional ServiceNow request/RITM number, used only to correlate log entries.

.PARAMETER LogPath
    Optional path to a log file. Passwords are never logged.

.PARAMETER SelfTest
    Run built-in decoder, name-validation, and JSON-contract tests. No Graph call is made.

.NOTES
    Microsoft Graph APPLICATION permissions (admin consent required):
      DeviceManagementManagedDevices.Read.All  - look up the device in Intune
      DeviceLocalCredential.Read.All           - read the LAPS password from Entra ID

    Exit codes:
      0  Success
      1  Invalid input
      2  Configuration or authentication error
      3  Device not found in Intune
      4  Device found, but no LAPS password is available
      5  Requester is not the device's primary user (only when -RequesterUpn is used)
      9  Unexpected error

.EXAMPLE
    .\Get-DeviceLapsPassword.ps1
    Interactive checkout: prompts for a computer name and prints the password.

.EXAMPLE
    .\Get-DeviceLapsPassword.ps1 -ComputerName LAPTOP-1234 -RequestId RITM0012345
    Unattended MID Server call. One JSON line on stdout.

.EXAMPLE
    .\Get-DeviceLapsPassword.ps1 -ComputerName LAPTOP-1234 -RequesterUpn jsmith@contoso.com

.EXAMPLE
    .\Get-DeviceLapsPassword.ps1 -SelfTest
#>
[CmdletBinding()]
param(
    [string]$ComputerName,

    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,

    [string]$RequesterUpn,
    [string]$RequestId,
    [string]$LogPath,
    [switch]$Interactive,
    [switch]$NonInteractive,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

#region ### 1. CONFIGURATION ###################################################

# MID Server / tenant app registration. Prefer env vars in production.
$DefaultTenantId              = 'e18c199f-7bc4-489e-b810-eddee385899b'
$DefaultClientId              = 'ea1351f4-ccb0-488d-8be6-a2be7b929894'
$DefaultCertificateThumbprint = 'CA226E648AE75DEFEE298111D8DC4A1E33E34A3B'

$GraphBase    = 'https://graph.microsoft.com/v1.0'
$EmptyGuid    = '00000000-0000-0000-0000-000000000000'
$ClientName   = 'ServiceNow-LAPS-Checkout'
$ClientVer    = '1.2'

$script:GraphConnected  = $false
$script:LogFile         = $LogPath
$script:NormalizedName  = $null
$script:TenantId        = $null
$script:ClientId        = $null
$script:CertificateThumbprint = $null
$script:InteractiveMode = $false

$Result = [ordered]@{
    success             = $false
    computerName        = $null
    account             = $null
    loginName           = $null
    password            = $null
    passwordLastUpdated = $null
    passwordExpires     = $null
    primaryUser         = $null
    warnings            = New-Object System.Collections.Generic.List[string]
    error               = $null
    exitCode            = 9
}

#endregion

#region ### 2. CORE HELPERS ####################################################

function Resolve-ConfigString {
    param(
        [string]$ParamValue,
        [string]$EnvironmentName,
        [string]$Fallback
    )
    if (-not [string]::IsNullOrWhiteSpace($ParamValue) -and $ParamValue -notmatch '^(#+$|<.*>)$') {
        return $ParamValue.Trim()
    }
    $envValue = [Environment]::GetEnvironmentVariable($EnvironmentName)
    if (-not [string]::IsNullOrWhiteSpace($envValue)) {
        return $envValue.Trim()
    }
    return $Fallback
}

function New-LapsError {
    param([string]$Message, [int]$Code)
    $ex = New-Object System.Exception $Message
    $ex.Data['ExitCode'] = $Code
    return $ex
}

function Get-ErrorExitCode {
    param($ErrorRecord, [int]$Default = 9)
    $ex = $null
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $ex = $ErrorRecord.Exception
    }
    elseif ($ErrorRecord -is [System.Exception]) {
        $ex = $ErrorRecord
    }
    while ($null -ne $ex) {
        if ($ex.Data -and $ex.Data.Contains('ExitCode')) {
            return [int]$ex.Data['ExitCode']
        }
        $ex = $ex.InnerException
    }
    return $Default
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')][string]$Level = 'INFO'
    )
    $reqTag  = if ([string]::IsNullOrWhiteSpace($RequestId)) { '-' } else { $RequestId }
    $devTag  = if ([string]::IsNullOrWhiteSpace($script:NormalizedName)) { $ComputerName } else { $script:NormalizedName }
    $line    = '{0} [{1}] [{2}] [{3}] {4}' -f (Get-Date).ToString('s'), $Level, $reqTag, $devTag, $Message
    if ($script:InteractiveMode) {
        $color = switch ($Level) {
            'ERROR' { 'Red' }
            'WARN'  { 'Yellow' }
            default { 'Gray' }
        }
        Write-Host ("  {0}" -f $Message) -ForegroundColor $color
    }
    else {
        Write-Verbose $line
    }
    if ([string]::IsNullOrWhiteSpace($script:LogFile)) { return }
    try {
        $logDir = Split-Path -Parent $script:LogFile
        if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
    } catch { }
}

function Add-Warning {
    param([string]$Message)
    [void]$Result.warnings.Add($Message)
    Write-Log $Message 'WARN'
}

function Get-NotePropertyValue {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string[]]$Name
    )
    if ($null -eq $Object) { return $null }

    foreach ($n in $Name) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($n)) { return $Object[$n] }
            foreach ($key in @($Object.Keys)) {
                if ([string]$key -eq $n) { return $Object[$key] }
            }
        }
        else {
            $prop = $Object.PSObject.Properties[$n]
            if ($null -ne $prop) { return $prop.Value }
            $prop = $Object.PSObject.Properties | Where-Object { $_.Name -eq $n } | Select-Object -First 1
            if ($null -ne $prop) { return $prop.Value }
        }
    }
    return $null
}

function ConvertTo-IsoString {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    try {
        $parsed = [datetime]$Value
        if ($parsed.Kind -eq [DateTimeKind]::Local) { $parsed = $parsed.ToUniversalTime() }
        elseif ($parsed.Kind -eq [DateTimeKind]::Unspecified) {
            $parsed = [datetime]::SpecifyKind($parsed, [DateTimeKind]::Utc)
        }
        return $parsed.ToUniversalTime().ToString('o')
    } catch {
        return "$Value"
    }
}

function Get-SortableDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return [datetime]::MinValue }
    try { return [datetime]$Value } catch { return [datetime]::MinValue }
}

function ConvertFrom-LapsPasswordBase64 {
    <#
        Graph samples and Get-LapsAADPassword encode the password as UTF-16LE (Unicode).
        A UTF-8 decode of those bytes injects NUL characters and the password cannot be typed.
        Fall back to UTF-8 when the payload is not UTF-16LE.
    #>
    param([Parameter(Mandatory = $true)][string]$PasswordBase64)

    $bytes = [System.Convert]::FromBase64String($PasswordBase64)
    if ($null -eq $bytes -or $bytes.Length -eq 0) { return $null }

    $looksUtf16 = ($bytes.Length -ge 2) -and (($bytes.Length % 2) -eq 0)
    if ($looksUtf16) {
        $nulCount = 0
        for ($i = 1; $i -lt $bytes.Length; $i += 2) {
            if ($bytes[$i] -eq 0) { $nulCount++ }
        }
        $pairs = [int]($bytes.Length / 2)
        if ($nulCount -ge [math]::Ceiling($pairs / 2.0)) {
            return [System.Text.Encoding]::Unicode.GetString($bytes).Trim([char]0)
        }
    }
    return [System.Text.Encoding]::UTF8.GetString($bytes).Trim([char]0)
}

function ConvertTo-SingleJsonLine {
    param($InputObject)

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return ($InputObject | ConvertTo-Json -Depth 6 -Compress)
    }

    # Windows PowerShell 5.1 unwraps a one-item array; JavaScriptSerializer does not.
    try {
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $serializer.MaxJsonLength = [int]::MaxValue
        $serializer.RecursionLimit = 32
        return $serializer.Serialize((ConvertTo-JsonSerializable $InputObject))
    } catch {
        return ($InputObject | ConvertTo-Json -Depth 6 -Compress)
    }
}

function ConvertTo-JsonSerializable {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [byte] -or
        $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return $Value
    }
    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString('o')
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $map = New-Object System.Collections.Generic.Dictionary[string, object]
        foreach ($key in $Value.Keys) {
            $map[$key.ToString()] = ConvertTo-JsonSerializable $Value[$key]
        }
        return $map
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Value) {
            $list.Add((ConvertTo-JsonSerializable $item))
        }
        return $list
    }
    if ($null -ne $Value.PSObject -and $null -ne $Value.PSObject.Properties) {
        $map = New-Object System.Collections.Generic.Dictionary[string, object]
        foreach ($prop in $Value.PSObject.Properties) {
            if ($prop.MemberType -eq 'ScriptProperty' -or $prop.MemberType -eq 'ScriptMethod') { continue }
            $map[$prop.Name] = ConvertTo-JsonSerializable $prop.Value
        }
        return $map
    }
    return "$Value"
}

function Get-NormalizedComputerName {
    param([string]$Name)

    $hostName = ("$Name".Trim()).Split('.')[0]
    if ($hostName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$') {
        throw (New-LapsError "'$Name' is not a valid computer name (1-15 letters, digits or hyphens)." 1)
    }
    return $hostName.ToUpperInvariant()
}

function Test-SameUpn {
    param([string]$Left, [string]$Right)
    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) { return $false }
    return (([string]$Left).Trim() -ieq ([string]$Right).Trim())
}

function Write-ResultAndExit {
    $Result.warnings = [string[]]@($Result.warnings)
    $json = ConvertTo-SingleJsonLine -InputObject $Result
    Write-Output $json
    exit $Result.exitCode
}

function Reset-LapsResult {
    $Result.success             = $false
    $Result.computerName        = $null
    $Result.account             = $null
    $Result.loginName           = $null
    $Result.password            = $null
    $Result.passwordLastUpdated = $null
    $Result.passwordExpires     = $null
    $Result.primaryUser         = $null
    $Result.warnings            = New-Object System.Collections.Generic.List[string]
    $Result.error               = $null
    $Result.exitCode            = 9
}

function Test-ShouldUseInteractiveUi {
    if ($NonInteractive -or $SelfTest) { return $false }
    if ($Interactive) { return $true }
    if (-not [string]::IsNullOrWhiteSpace($ComputerName)) { return $false }
    if (-not [Environment]::UserInteractive) { return $false }
    return $true
}

function Write-Banner {
    param([string[]]$Lines)
    $rule = ('=' * 78)
    Write-Host ''
    Write-Host $rule -ForegroundColor Cyan
    foreach ($line in $Lines) {
        Write-Host ("  {0}" -f $line) -ForegroundColor Cyan
    }
    Write-Host $rule -ForegroundColor Cyan
    Write-Host ''
}

function Read-RawInput {
    param([Parameter(Mandatory = $true)][string]$PromptText)
    try {
        return Read-Host $PromptText
    }
    catch {
        Write-Host "$PromptText " -NoNewline
        try { $line = [Console]::In.ReadLine() } catch { $line = '' }
        if ($null -eq $line) { return '' }
        return $line
    }
}

function Read-Prompt {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Default
    )
    $suffix = if ($PSBoundParameters.ContainsKey('Default') -and -not [string]::IsNullOrWhiteSpace($Default)) {
        " [$Default]"
    } else { '' }
    $raw = Read-RawInput -PromptText ($Message + $suffix)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        if ($PSBoundParameters.ContainsKey('Default')) { return $Default }
        return ''
    }
    return $raw.Trim()
}

function Read-YesNo {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [bool]$Default = $true
    )
    $hint = if ($Default) { 'Y/n' } else { 'y/N' }
    while ($true) {
        $raw = Read-RawInput -PromptText "$Message [$hint]"
        if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
        switch -Regex ($raw.Trim()) {
            '^(y|yes)$' { return $true }
            '^(n|no)$'  { return $false }
            default     { Write-Host '  Please enter Y or N.' -ForegroundColor Yellow }
        }
    }
}

function Copy-TextToClipboard {
    param([Parameter(Mandatory = $true)][string]$Text)
    try {
        Set-Clipboard -Value $Text -ErrorAction Stop
        return $true
    } catch { }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [System.Windows.Forms.Clipboard]::SetText($Text)
        return $true
    } catch { }
    return $false
}

function Format-DisplayTime {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return '(none)' }
    try {
        return ([datetime]$Value).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
    } catch {
        $iso = ConvertTo-IsoString $Value
        if ($iso) { return $iso }
        return '(none)'
    }
}

function Write-LabeledValue {
    param([string]$Label, [string]$Value, [ConsoleColor]$ValueColor = 'White')
    $text = if ([string]::IsNullOrWhiteSpace($Value)) { '(none)' } else { $Value }
    Write-Host ('  {0,-22}' -f "${Label}:") -NoNewline -ForegroundColor DarkGray
    Write-Host $text -ForegroundColor $ValueColor
}

function Show-LapsResult {
    Write-Host ''
    if ($Result.success) {
        Write-Host '  LAPS password retrieved' -ForegroundColor Green
        Write-LabeledValue 'Computer' $Result.computerName 'Cyan'
        Write-LabeledValue 'Account' $Result.account
        Write-LabeledValue 'Logon as' $Result.loginName 'Cyan'
        Write-LabeledValue 'Password' $Result.password 'Yellow'
        Write-LabeledValue 'Last updated' (Format-DisplayTime $Result.passwordLastUpdated)
        Write-LabeledValue 'Expires / refreshes' (Format-DisplayTime $Result.passwordExpires)
        Write-LabeledValue 'Intune primary user' $Result.primaryUser
    }
    else {
        Write-Host '  Lookup failed' -ForegroundColor Red
        if ($Result.computerName) { Write-LabeledValue 'Computer' $Result.computerName 'Cyan' }
        Write-LabeledValue 'Error' $Result.error 'Red'
        Write-LabeledValue 'Exit code' ([string]$Result.exitCode)
    }
    foreach ($warning in @($Result.warnings)) {
        if (-not [string]::IsNullOrWhiteSpace($warning)) {
            Write-Host ("  WARNING: {0}" -f $warning) -ForegroundColor Yellow
        }
    }
    Write-Host ''
}

function Invoke-LapsCheckout {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$Requester
    )

    Reset-LapsResult
    $normalized              = Get-NormalizedComputerName -Name $Name
    $script:NormalizedName   = $normalized
    $Result.computerName     = $normalized

    Write-Log "Request started. Requester=$Requester; RunAs=$env:USERDOMAIN\$env:USERNAME"

    if (-not $script:GraphConnected) {
        Connect-GraphAppOnly
    }

    $device = Get-IntuneDevice -Name $normalized
    if (-not $device) {
        throw (New-LapsError "$normalized was not found in Intune." 3)
    }

    $os            = [string](Get-NotePropertyValue $device 'operatingSystem')
    $entraDeviceId = [string](Get-NotePropertyValue $device 'azureADDeviceId')
    $Result.primaryUser = Get-NotePropertyValue $device 'userPrincipalName'
    Write-Log "Intune device found. IntuneId=$(Get-NotePropertyValue $device 'id'); EntraDeviceId=$entraDeviceId; OS=$os; PrimaryUser=$($Result.primaryUser)"

    if ($os -and $os -notmatch 'Windows') {
        throw (New-LapsError "$normalized is enrolled in Intune as '$os'. Windows LAPS is only available on Windows devices." 4)
    }

    if (-not [string]::IsNullOrWhiteSpace($Requester) -and -not (Test-SameUpn $Result.primaryUser $Requester)) {
        throw (New-LapsError "Requester '$Requester' is not the primary user of $normalized." 5)
    }

    if ([string]::IsNullOrWhiteSpace($entraDeviceId) -or $entraDeviceId -eq $EmptyGuid) {
        throw (New-LapsError "The Intune record for $normalized has no Entra device ID." 4)
    }

    $cred = Get-EntraLapsCredential -DeviceId $entraDeviceId
    if (-not $cred) {
        throw (New-LapsError "No LAPS password is backed up to Entra ID for $normalized. Confirm a Windows LAPS policy is assigned and the device has checked in." 4)
    }

    $Result.success             = $true
    $Result.account             = $cred.Account
    $Result.loginName           = ".\$($cred.Account)"
    $Result.password            = $cred.Password
    $Result.passwordLastUpdated = ConvertTo-IsoString $cred.PasswordUpdated
    $Result.passwordExpires     = ConvertTo-IsoString $cred.Expiration
    $Result.exitCode            = 0
    Write-Log "Password retrieved for account '$($cred.Account)'."
}

function Set-LapsFailure {
    param($ErrorRecord)
    $code = Get-ErrorExitCode -ErrorRecord $ErrorRecord -Default 9
    $Result.success  = $false
    $Result.password = $null
    $Result.error    = $ErrorRecord.Exception.Message
    $Result.exitCode = $code
    $lineNo = $null
    try { $lineNo = $ErrorRecord.InvocationInfo.ScriptLineNumber } catch { }
    Write-Log ("Failed (exit {0}) at line {1}: {2}" -f $code, $lineNo, $ErrorRecord.Exception.Message) 'ERROR'
}

function Invoke-InteractiveCheckout {
    Write-Banner @(
        'Windows LAPS checkout  (Entra ID / Intune)'
        'App-only certificate authentication  |  password is never written to the log'
        'Enter a computer name, or Q to quit'
    )

    try {
        Connect-GraphAppOnly
        Write-Host '  Connected to Microsoft Graph.' -ForegroundColor Green
        Write-Host ''
        $Result.exitCode = 0
    }
    catch {
        Set-LapsFailure $_
        Show-LapsResult
        [void](Read-RawInput -PromptText 'Press Enter to exit')
        return
    }

    $prefill = $ComputerName
    while ($true) {
        $nameInput = $prefill
        $prefill = $null
        if ([string]::IsNullOrWhiteSpace($nameInput)) {
            $nameInput = Read-Prompt -Message 'Computer name'
        }
        if ($nameInput -match '^(q|quit|exit)$') {
            Write-Host '  Done.' -ForegroundColor DarkGray
            break
        }
        if ([string]::IsNullOrWhiteSpace($nameInput)) {
            Write-Host '  Enter a computer name, or Q to quit.' -ForegroundColor Yellow
            continue
        }

        try {
            Invoke-LapsCheckout -Name $nameInput -Requester $RequesterUpn
        }
        catch {
            Set-LapsFailure $_
        }

        Show-LapsResult

        if ($Result.success -and -not [string]::IsNullOrWhiteSpace($Result.password)) {
            if (Read-YesNo -Message 'Copy password to clipboard?' -Default $true) {
                if (Copy-TextToClipboard -Text $Result.password) {
                    Write-Host '  Password copied to the clipboard.' -ForegroundColor Green
                }
                else {
                    Write-Host '  Could not copy to the clipboard. Copy it from the line above.' -ForegroundColor Yellow
                }
            }
        }

        if (-not (Read-YesNo -Message 'Look up another device?' -Default $true)) {
            Write-Host '  Done.' -ForegroundColor DarkGray
            break
        }
        Write-Host ''
    }
}

#endregion

#region ### 3. GRAPH HELPERS ###################################################

function Get-GraphStatusCode {
    param($ErrorRecord)

    if ($null -eq $ErrorRecord) { return 0 }

    $exceptions = New-Object System.Collections.Generic.List[object]
    $ex = $null
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $ex = $ErrorRecord.Exception
    }
    elseif ($ErrorRecord -is [System.Exception]) {
        $ex = $ErrorRecord
    }
    while ($null -ne $ex) {
        $exceptions.Add($ex)
        $ex = $ex.InnerException
    }

    foreach ($item in $exceptions) {
        foreach ($propName in @('Response', 'StatusCode', 'Status', 'ResponseStatusCode')) {
            try {
                $prop = $item.PSObject.Properties[$propName]
                if ($null -eq $prop -or $null -eq $prop.Value) { continue }
                $val = $prop.Value
                if ($propName -eq 'Response') {
                    $codeProp = $val.PSObject.Properties['StatusCode']
                    if ($null -ne $codeProp -and $null -ne $codeProp.Value) {
                        return [int]$codeProp.Value
                    }
                    continue
                }
                if ($val -is [enum] -or $val -is [int] -or $val -is [long]) {
                    $asInt = [int]$val
                    if ($asInt -ge 100 -and $asInt -le 599) { return $asInt }
                }
            } catch { }
        }
    }

    $chunks = New-Object System.Collections.Generic.List[string]
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        if ($ErrorRecord.Exception) { [void]$chunks.Add([string]$ErrorRecord.Exception.Message) }
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            [void]$chunks.Add([string]$ErrorRecord.ErrorDetails.Message)
        }
    }
    elseif ($ErrorRecord.Message) {
        [void]$chunks.Add([string]$ErrorRecord.Message)
    }
    $text = ($chunks -join ' ')

    if ($text -match 'status code does not indicate success:\s*(\d{3})') { return [int]$Matches[1] }
    if ($text -match '(?i)(?:HTTP|status(?:\s+code)?)\s*[:=]?\s*(\d{3})') { return [int]$Matches[1] }
    if ($text -match '\((\d{3})\)') { return [int]$Matches[1] }
    if ($text -match '(?i)"code"\s*:\s*"(ResourceNotFound|ErrorItemNotFound|Request_ResourceNotFound|NotFound)"') { return 404 }
    if ($text -match '(?i)"code"\s*:\s*"(Authorization_RequestDenied|accessDenied|Forbidden)"') { return 403 }
    if ($text -match '(?i)"code"\s*:\s*"(TooManyRequests)"') { return 429 }
    if ($text -match '(?i)ResourceNotFound|Request_ResourceNotFound|ErrorItemNotFound') { return 404 }
    if ($text -match '(?i)\bNotFound\b') { return 404 }
    if ($text -match '(?i)\bForbidden\b|Authorization_RequestDenied|accessDenied') { return 403 }
    if ($text -match '(?i)TooManyRequests|throttl') { return 429 }
    if ($text -match '(?i)\bUnauthorized\b') { return 401 }
    return 0
}

function Get-RetryAfterSeconds {
    param($ErrorRecord, [int]$Attempt)

    $fallback = [int][math]::Min(60, [math]::Pow(2, $Attempt))
    try {
        $resp = $ErrorRecord.Exception.Response
        if ($resp -and $resp.Headers) {
            $retry = $resp.Headers.RetryAfter
            if ($retry -and $retry.Delta) {
                return [int][math]::Max(1, [math]::Ceiling($retry.Delta.TotalSeconds))
            }
            $headerVal = $null
            try { $headerVal = $resp.Headers['Retry-After'] } catch { }
            if ($headerVal) { return [int][math]::Max(1, $headerVal) }
        }
    } catch { }
    return $fallback
}

function Get-GraphRequestHeaders {
    return @{
        'User-Agent'         = "$ClientName/$ClientVer"
        'ocp-client-name'    = $ClientName
        'ocp-client-version' = $ClientVer
        'client-request-id'  = [guid]::NewGuid().ToString()
    }
}

function Invoke-GraphGet {
    <# GET with retry on throttling/transient errors. Returns $null on 404. #>
    param([string]$Uri, [int]$MaxAttempts = 4)

    $graphCmd = Get-Command Invoke-MgGraphRequest -ErrorAction Stop

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $headers = Get-GraphRequestHeaders
        $irParams = @{
            Method      = 'GET'
            Uri         = $Uri
            ErrorAction = 'Stop'
        }
        if ($graphCmd.Parameters.ContainsKey('Headers')) {
            $irParams['Headers'] = $headers
        }
        if ($graphCmd.Parameters.ContainsKey('OutputType')) {
            $irParams['OutputType'] = 'PSObject'
        }

        try {
            return Invoke-MgGraphRequest @irParams
        }
        catch {
            $status = Get-GraphStatusCode -ErrorRecord $_

            if ($status -eq 404) { return $null }
            if ($status -eq 401) {
                throw (New-LapsError "Graph returned 401 Unauthorized for $Uri. Confirm the certificate is uploaded to the app registration and that the MID Server account can read the private key." 2)
            }
            if ($status -eq 403) {
                throw (New-LapsError "Graph returned 403 Forbidden for $Uri. Check that the app registration has DeviceManagementManagedDevices.Read.All and DeviceLocalCredential.Read.All with admin consent." 2)
            }

            $transient = $status -in 429, 500, 502, 503, 504
            if (-not $transient -or $attempt -eq $MaxAttempts) {
                if ($status -gt 0) {
                    throw (New-LapsError "Graph GET failed (HTTP $status) for $Uri : $($_.Exception.Message)" 9)
                }
                throw
            }

            $delay = Get-RetryAfterSeconds -ErrorRecord $_ -Attempt $attempt
            Write-Log "Graph returned $status; retrying in $delay s (attempt $attempt of $MaxAttempts)." 'WARN'
            Start-Sleep -Seconds $delay
        }
    }
}

function Get-GraphCollection {
    param([string]$Uri)

    $items = New-Object System.Collections.Generic.List[object]
    $next  = $Uri
    while ($next) {
        $resp = Invoke-GraphGet -Uri $next
        if ($null -eq $resp) { break }
        foreach ($item in @((Get-NotePropertyValue $resp 'value'))) {
            if ($null -ne $item) { [void]$items.Add($item) }
        }
        $next = Get-NotePropertyValue $resp '@odata.nextLink'
    }
    return $items
}

function Test-LapsResourceObject {
    param($Object)
    if ($null -eq $Object) { return $false }
    if ($null -ne (Get-NotePropertyValue $Object 'credentials')) { return $true }
    if ($null -ne (Get-NotePropertyValue $Object 'deviceName')) { return $true }
    if ($null -ne (Get-NotePropertyValue $Object 'refreshDateTime')) { return $true }
    if ($null -ne (Get-NotePropertyValue $Object 'lastBackupDateTime')) { return $true }
    return $false
}

function Unprotect-GraphResource {
    param($Response)
    if ($null -eq $Response) { return $null }
    if (Test-LapsResourceObject $Response) { return $Response }

    $wrapped = Get-NotePropertyValue $Response 'value'
    if ($null -eq $wrapped) { return $Response }
    if (Test-LapsResourceObject $wrapped) { return $wrapped }

    if ($wrapped -is [System.Collections.IEnumerable] -and -not ($wrapped -is [string])) {
        foreach ($item in @($wrapped)) {
            if (Test-LapsResourceObject $item) { return $item }
        }
    }
    return $Response
}

#endregion

#region ### 4. MICROSOFT GRAPH -------------------------------------------------

function Connect-GraphAppOnly {
    $script:TenantId              = Resolve-ConfigString $TenantId 'ENTRA_TENANT_ID' $DefaultTenantId
    $script:ClientId              = Resolve-ConfigString $ClientId 'ENTRA_CLIENT_ID' $DefaultClientId
    $script:CertificateThumbprint = Resolve-ConfigString $CertificateThumbprint 'ENTRA_CERT_THUMBPRINT' $DefaultCertificateThumbprint

    $config = [ordered]@{
        TenantId              = $script:TenantId
        ClientId              = $script:ClientId
        CertificateThumbprint = $script:CertificateThumbprint
    }
    foreach ($key in $config.Keys) {
        if ([string]::IsNullOrWhiteSpace($config[$key]) -or $config[$key] -match '^(#+$|<.*>)$') {
            throw (New-LapsError "Configuration value '$key' is not set." 2)
        }
    }

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw (New-LapsError 'PowerShell module Microsoft.Graph.Authentication is not installed on this server.' 2)
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null

    # Strip spaces and the invisible character that certlm.msc adds when copying a thumbprint
    $thumb = ($script:CertificateThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($thumb.Length -ne 40) {
        throw (New-LapsError "Certificate thumbprint '$thumb' is not a 40-character SHA-1 value." 2)
    }

    $cert  = $null
    $runAs = "$env:USERDOMAIN\$env:USERNAME"
    foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        if (-not (Test-Path -LiteralPath $store)) { continue }
        $cert = Get-ChildItem -Path $store | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
        if ($cert) { break }
    }

    if (-not $cert)               { throw (New-LapsError "Certificate $thumb not found in CurrentUser\My or LocalMachine\My (running as $runAs)." 2) }
    if (-not $cert.HasPrivateKey) { throw (New-LapsError "Certificate $thumb has no private key available to $runAs." 2) }

    $now = Get-Date
    if ($cert.NotAfter -lt $now) {
        throw (New-LapsError "Certificate $thumb expired on $($cert.NotAfter.ToString('yyyy-MM-dd'))." 2)
    }
    if ($cert.NotAfter -lt $now.AddDays(30)) {
        Add-Warning "Graph authentication certificate expires on $($cert.NotAfter.ToString('yyyy-MM-dd')). Renew it soon."
    }

    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

    $connectCmd    = Get-Command Connect-MgGraph -ErrorAction Stop
    $connectParams = @{
        TenantId    = $script:TenantId
        ClientId    = $script:ClientId
        ErrorAction = 'Stop'
    }
    if ($connectCmd.Parameters.ContainsKey('NoWelcome')) {
        $connectParams['NoWelcome'] = $true
    }

    try {
        if ($connectCmd.Parameters.ContainsKey('Certificate')) {
            $connectParams['Certificate'] = $cert
            Connect-MgGraph @connectParams | Out-Null
        }
        elseif ($connectCmd.Parameters.ContainsKey('CertificateThumbprint')) {
            $connectParams['CertificateThumbprint'] = $thumb
            Connect-MgGraph @connectParams | Out-Null
        }
        else {
            throw (New-LapsError 'This version of Microsoft.Graph.Authentication does not support certificate authentication.' 2)
        }
    }
    catch {
        if ($_.Exception.Data -and $_.Exception.Data.Contains('ExitCode')) { throw }
        $fallback = $null
        if ($connectParams.ContainsKey('Certificate') -and $connectCmd.Parameters.ContainsKey('CertificateThumbprint')) {
            try {
                $connectParams.Remove('Certificate')
                $connectParams['CertificateThumbprint'] = $thumb
                Connect-MgGraph @connectParams | Out-Null
                $fallback = $true
            } catch {
                $fallback = $false
            }
        }
        if (-not $fallback) {
            throw (New-LapsError ("Microsoft Graph authentication failed: {0} Confirm the certificate is uploaded to the app registration and that {1} can read its private key." -f $_.Exception.Message, $runAs) 2)
        }
    }

    $ctx = Get-MgContext
    if (-not $ctx -or (Get-NotePropertyValue $ctx 'AuthType') -ne 'AppOnly') {
        throw (New-LapsError 'Graph connection did not establish an app-only session.' 2)
    }
    $script:GraphConnected = $true

    $granted = @()
    foreach ($scope in @((Get-NotePropertyValue $ctx 'Scopes'))) {
        if ([string]::IsNullOrWhiteSpace($scope)) { continue }
        $granted += @($scope -split '[, ]+' | Where-Object { $_ })
    }
    foreach ($perm in @('DeviceManagementManagedDevices.Read.All', 'DeviceLocalCredential.Read.All')) {
        if ($granted.Count -gt 0 -and ($granted -notcontains $perm)) {
            Write-Log "Token does not list application permission '$perm'. Confirm admin consent." 'WARN'
        }
    }
    Write-Log "Connected to Graph as app $($script:ClientId) using certificate $thumb."
}

function Get-IntuneDevice {
    param([string]$Name)

    $escaped = $Name.Replace("'", "''")
    $select  = 'id,deviceName,azureADDeviceId,userPrincipalName,lastSyncDateTime,operatingSystem'
    $query   = {
        param([string]$Filter)
        $encoded = [uri]::EscapeDataString($Filter)
        Get-GraphCollection -Uri "$GraphBase/deviceManagement/managedDevices?`$filter=$encoded&`$select=$select"
    }

    # Intune's OData subset is picky about 'or'; try exact name first, then FQDN-style names.
    $devices = @(& $query "deviceName eq '$escaped'")
    if ($devices.Count -eq 0) {
        $devices = @(& $query "startswith(deviceName,'$escaped.')")
    }

    if ($devices.Count -eq 0) { return $null }

    if ($devices.Count -gt 1) {
        Add-Warning "$($devices.Count) Intune records match '$Name'; using the most recently synced Windows record with an Entra device ID."
    }

    return $devices | Sort-Object -Property `
        @{ Expression = {
                $os = [string](Get-NotePropertyValue $_ 'operatingSystem')
                [bool]($os -match 'Windows')
            }; Descending = $true },
        @{ Expression = {
                $aadId = [string](Get-NotePropertyValue $_ 'azureADDeviceId')
                [bool]($aadId -and $aadId -ne $EmptyGuid)
            }; Descending = $true },
        @{ Expression = { Get-SortableDate (Get-NotePropertyValue $_ 'lastSyncDateTime') }; Descending = $true } |
        Select-Object -First 1
}

function Get-EntraLapsCredential {
    param([string]$DeviceId)

    $select = [uri]::EscapeDataString('id,deviceName,lastBackupDateTime,refreshDateTime,credentials')
    $info   = Unprotect-GraphResource (Invoke-GraphGet -Uri "$GraphBase/directory/deviceLocalCredentials/${DeviceId}?`$select=$select")
    if ($null -eq $info) { return $null }

    $credentials = @((Get-NotePropertyValue $info 'credentials') | Where-Object { $_ })
    if ($credentials.Count -eq 0) { return $null }

    $latest = $credentials |
        Sort-Object -Property @{ Expression = { Get-SortableDate (Get-NotePropertyValue $_ 'backupDateTime') }; Descending = $true } |
        Select-Object -First 1

    $passwordB64 = [string](Get-NotePropertyValue $latest 'passwordBase64')
    if ([string]::IsNullOrWhiteSpace($passwordB64)) {
        throw (New-LapsError "Graph returned a LAPS credential for this device without passwordBase64. DeviceLocalCredential.Read.All (not ReadBasic.All) is required, with admin consent." 2)
    }

    $plain = ConvertFrom-LapsPasswordBase64 -PasswordBase64 $passwordB64
    if ([string]::IsNullOrWhiteSpace($plain)) { return $null }

    $account = Get-NotePropertyValue $latest 'accountName'
    return [pscustomobject]@{
        Account         = $account
        Password        = $plain
        PasswordUpdated = Get-NotePropertyValue $latest 'backupDateTime'
        Expiration      = Get-NotePropertyValue $info 'refreshDateTime'
    }
}

#endregion

#region ### 5. SELF-TEST -------------------------------------------------------

function Assert-Equal {
    param($Actual, $Expected, [string]$Name)
    if ("$Actual" -cne "$Expected") {
        throw "SelfTest failed: $Name. Expected '$Expected', got '$Actual'."
    }
}

function Invoke-SelfTest {
    $script:SelfPassed = 0
    $script:SelfFailed = 0
    $failures = New-Object System.Collections.Generic.List[string]

    function Invoke-Case {
        param([string]$Name, [scriptblock]$Body)
        try {
            & $Body
            Write-Log "PASS  $Name" 'INFO'
            $script:SelfPassed++
            [void]$Result.warnings.Add("PASS $Name")
        }
        catch {
            Write-Log "FAIL  $Name : $($_.Exception.Message)" 'ERROR'
            $script:SelfFailed++
            [void]$failures.Add("$Name : $($_.Exception.Message)")
            [void]$Result.warnings.Add("FAIL $Name")
        }
    }

    Write-Log 'Running built-in tests (no Graph call).'

    Invoke-Case 'FQDN is reduced to a 15-character NetBIOS host name' {
        Assert-Equal (Get-NormalizedComputerName 'laptop-1234.corp.com') 'LAPTOP-1234' 'normalized'
        Assert-Equal (Get-NormalizedComputerName 'LAPTOP-1234') 'LAPTOP-1234' 'already host'
    }

    Invoke-Case 'Invalid computer names are rejected with exit 1' {
        $caught = $null
        try { Get-NormalizedComputerName 'bad_name' } catch { $caught = $_ }
        if ($null -eq $caught) { throw 'Expected invalid name to throw.' }
        Assert-Equal (Get-ErrorExitCode $caught) 1 'exit code'
    }

    Invoke-Case 'Graph sample passwordBase64 decodes as UTF-16LE, not UTF-8' {
        $decoded = ConvertFrom-LapsPasswordBase64 -PasswordBase64 'UQBRAEAAZAA4AGYAOABnAFkA'
        Assert-Equal $decoded 'QQ@d8f8gY' 'ms sample 1'
        Assert-Equal (ConvertFrom-LapsPasswordBase64 -PasswordBase64 'KgBEADkAawBsAGsAZgAjADQA') '*D9klkf#4' 'ms sample 2'
        Assert-Equal (ConvertFrom-LapsPasswordBase64 -PasswordBase64 'TABwAGQAOQAqACgAKQAzADQA') 'Lpd9*()34' 'ms sample 3'
        if ($decoded.Contains([char]0)) { throw 'Decoder left embedded NUL characters in the password.' }
    }

    Invoke-Case 'UTF-8 passwordBase64 still decodes when it is not UTF-16LE' {
        $utf8 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('P@ssw0rd!'))
        Assert-Equal (ConvertFrom-LapsPasswordBase64 -PasswordBase64 $utf8) 'P@ssw0rd!' 'utf8'
    }

    Invoke-Case 'UPN ownership check is case-insensitive' {
        if (-not (Test-SameUpn 'JSmith@Contoso.com' 'jsmith@contoso.com')) {
            throw 'Expected UPN compare to be case-insensitive.'
        }
        if (Test-SameUpn 'jsmith@contoso.com' 'other@contoso.com') {
            throw 'Expected different UPNs to fail.'
        }
    }

    Invoke-Case 'Graph SDK 404 / 403 messages map to HTTP status codes' {
        $notFound = New-Object System.Exception 'Response status code does not indicate success: 404 (NotFound).'
        Assert-Equal (Get-GraphStatusCode $notFound) 404 '404 from message'
        $forbidden = New-Object System.Exception 'GET https://graph.microsoft.com/v1.0/directory/deviceLocalCredentials/x returned 403 (Forbidden)'
        Assert-Equal (Get-GraphStatusCode $forbidden) 403 '403 from message'
        $json404 = New-Object System.Exception '{"error":{"code":"ResourceNotFound","message":"Not found"}}'
        Assert-Equal (Get-GraphStatusCode $json404) 404 '404 from Graph JSON'
    }

    Invoke-Case 'PS 5.1 JSON contract keeps a single warning as an array' {
        $sample = [ordered]@{
            success  = $true
            warnings = [string[]]@('only-one')
            password = $null
            exitCode = 0
        }
        $json = ConvertTo-SingleJsonLine -InputObject $sample
        if ($json -notmatch '"warnings":\[') {
            throw "Expected warnings to serialize as a JSON array. Got: $json"
        }
        if ($json -notmatch '"password":null') {
            throw "Expected password null to remain JSON null. Got: $json"
        }
    }

    Invoke-Case 'LAPS error objects preserve ExitCode through throw/catch' {
        try { throw (New-LapsError 'not in Intune' 3) }
        catch { Assert-Equal (Get-ErrorExitCode $_) 3 'wrapped exit' }
    }

    Invoke-Case 'SelfTest and -ComputerName stay on the JSON path' {
        if (Test-ShouldUseInteractiveUi) {
            throw 'SelfTest must not open the interactive UI.'
        }
    }

    $Result.computerName = 'SELFTEST'
    $Result.account      = 'ContosoLocalAdminAccount'
    $Result.loginName    = '.\ContosoLocalAdminAccount'
    $Result.password     = $(if ($script:SelfFailed -eq 0) { 'QQ@d8f8gY' } else { $null })
    $Result.success      = ($script:SelfFailed -eq 0)
    $Result.error        = $(if ($script:SelfFailed -eq 0) { $null } else { ($failures -join '; ') })
    $Result.exitCode     = $(if ($script:SelfFailed -eq 0) { 0 } else { 9 })
    Write-Log ("SelfTest complete: {0} passed, {1} failed." -f $script:SelfPassed, $script:SelfFailed)
}

#endregion

#region ### 6. MAIN ------------------------------------------------------------

$script:InteractiveMode = Test-ShouldUseInteractiveUi

try {
    if ($SelfTest) {
        Invoke-SelfTest
    }
    elseif ($script:InteractiveMode) {
        Invoke-InteractiveCheckout
    }
    else {
        if ([string]::IsNullOrWhiteSpace($ComputerName)) {
            throw (New-LapsError '-ComputerName is required. Run without parameters for the interactive prompt, or pass -ComputerName for JSON output.' 1)
        }
        Invoke-LapsCheckout -Name $ComputerName -Requester $RequesterUpn
    }
}
catch {
    Set-LapsFailure $_
}
finally {
    if ($script:GraphConnected) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    }
}

if ($script:InteractiveMode -and -not $SelfTest) {
    exit $Result.exitCode
}

Write-ResultAndExit

#endregion

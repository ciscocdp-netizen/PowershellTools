#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive tool to add, modify or clear extensionAttribute1 on Windows devices
    that are Microsoft Entra registered, for use in a Conditional Access device filter.

.DESCRIPTION
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

    Menu driven:
      1. List Windows Entra registered devices and their current extensionAttribute1
      2. Update a single device (search by name, Device ID or Object ID)
      3. Bulk update many devices from a CSV, with a full preview before any change
      4. Find Windows devices by user and export a bulk-update CSV
      5. Export a CSV template
      6. Settings: default value, dry-run mode, audit log path, registered-only filter
      7. Connect or switch tenant
      8. Conditional Access filter help

    Every change (or dry-run) is written to a CSV audit log.

    Fixes versus the original draft:
      - Graph responses are read as hashtables or objects (SDK version differences)
      - Single-device GET results are not enumerated as hashtable keys
      - PATCH JSON sends a real JSON null when clearing (PS 5.1 ConvertTo-Json pitfalls)
      - HTTP 429/503 retries with backoff
      - Windows + Entra-registered filter is applied in Graph, not only after download
      - CSV headers, delimiters, {GUID} braces and aliases are normalised
      - Missing CSV devices are looked up so "not eligible" is distinct from "not found"
      - Graph error bodies, throttling and progress cleanup are handled
      - Settings persist next to the script; device-code sign-in is offered

.PARAMETER SkipMain
    Load functions without starting the menu. Used by tests.

.PARAMETER TenantId
    Optional tenant ID or domain passed to Connect-MgGraph.

.PARAMETER DeviceCode
    Use device-code sign-in instead of the interactive browser.

.PARAMETER SettingsPath
    Optional path to a JSON settings file. Defaults to CAExemption.settings.json
    next to this script.

.NOTES
    Requirements
      - Module: Microsoft.Graph.Authentication (the script offers to install it)
      - Delegated Graph permissions: Device.ReadWrite.All and User.Read.All (admin consent required)
      - Entra role: Cloud Device Administrator, Intune Administrator or Global Administrator
      - Windows PowerShell 5.1 needs .NET Framework 4.7.2 or later for the Graph SDK

    CSV format
      At least one identifier column per row: DeviceId, ObjectId or DisplayName
      (checked in that order). Optional columns: Value, Action (Set or Clear).

      Headers are matched case-insensitively and aliases are accepted
      (Device ID, Name, ComputerName, ExtensionAttribute1, Operation, ...).
      Comma, semicolon and tab delimited files are detected automatically.

        DeviceId,ObjectId,DisplayName,Value,Action
        1a2b3c4d-1111-2222-3333-444455556666,,,CAExempt,Set
        ,,KIOSK-02,CAExempt,Set
        ,,KIOSK-03,,Clear

    User-to-device CSV (menu option 4)
      Look up users by UPN, mail, display name or object ID, or import a user list
      with those columns (aliases such as UPN / Email are accepted). The export
      includes DeviceId, ObjectId, DisplayName, Value and Action so it can be
      applied immediately with menu option 3. Extra columns (user, relationship,
      join type) are for review and are ignored by bulk update.

    Conditional Access usage
      Conditions > Filter for devices > Exclude filtered devices:
        device.extensionAttribute1 -eq "CAExempt"

      The comparison is case-sensitive in Conditional Access, so the stored value
      must match the policy filter exactly.

.EXAMPLE
    .\Set-EntraDeviceCAExemption.ps1

.EXAMPLE
    .\Set-EntraDeviceCAExemption.ps1 -TenantId contoso.onmicrosoft.com -DeviceCode
#>
[CmdletBinding()]
param(
    [switch]$SkipMain,
    [string]$TenantId,
    [switch]$DeviceCode,
    [string]$SettingsPath
)

$script:ToolVersion    = '1.0.5'
$script:Root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:SettingsFile = if ($SettingsPath) { $SettingsPath } else { Join-Path $script:Root 'CAExemption.settings.json' }
$script:RequiredScope  = 'Device.ReadWrite.All'
$script:RequiredScopes = @('Device.ReadWrite.All', 'User.Read.All')
$script:GraphBase      = 'https://graph.microsoft.com/v1.0/devices'
$script:GraphUsersBase = 'https://graph.microsoft.com/v1.0/users'
$script:SelectFields     = 'id,deviceId,displayName,trustType,operatingSystem,operatingSystemVersion,accountEnabled,approximateLastSignInDateTime,extensionAttributes,isManagementRestricted'
$script:UserSelectFields = 'id,displayName,userPrincipalName,mail,accountEnabled'
$script:GuidPattern   = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
$script:MaxValueLength = 1024
$script:CsvColumnAliases = @{
    DeviceId    = @('DeviceId', 'Device ID', 'Device_Id', 'AzureDeviceId', 'azureADDeviceId', 'AzureAdDeviceId')
    ObjectId    = @('ObjectId', 'Object ID', 'Object_Id', 'ObjectID', 'EntraObjectId', 'id')
    DisplayName = @('DisplayName', 'Display Name', 'DeviceName', 'Device Name', 'Name', 'ComputerName', 'Computer')
    Value       = @('Value', 'ExtensionAttribute1', 'extensionAttribute1', 'Attribute', 'NewValue', 'EA1')
    Action      = @('Action', 'Operation')
}
$script:UserCsvColumnAliases = @{
    ObjectId          = @('ObjectId', 'Object ID', 'Object_Id', 'UserObjectId', 'UserId', 'id')
    UserPrincipalName = @('UserPrincipalName', 'UPN', 'User', 'UserName', 'SamAccountName')
    Mail              = @('Mail', 'Email', 'EmailAddress', 'E-mail')
    DisplayName       = @('DisplayName', 'Display Name', 'Name', 'FullName')
}

$script:Settings = @{
    DefaultValue    = 'CAExempt'
    DryRun          = $false
    LogPath         = Join-Path $script:Root ('CAExemption-Log_{0}.csv' -f (Get-Date -Format 'yyyyMMdd'))
    RegisteredOnly  = $true
}

#region Console helpers

function Write-Title {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkCyan
    Write-Host (' ' + $Text) -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor DarkCyan
}

function Wait-ForKey {
    Write-Host ''
    [void](Read-Host 'Press Enter to continue')
}

function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $false)
    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = ([string](Read-Host "$Prompt $suffix")).Trim()
        if ([string]::IsNullOrEmpty($answer)) { return $Default }
        if ($answer -match '^(y|yes)$') { return $true }
        if ($answer -match '^(n|no)$')  { return $false }
        Write-Host 'Please answer Y or N.' -ForegroundColor Yellow
    }
}

function Read-Choice {
    param([string]$Prompt = 'Choose an option')
    return ([string](Read-Host $Prompt)).Trim().ToUpperInvariant()
}

function Limit-Text {
    param($Text, [int]$Length = 30)
    if ($null -eq $Text) { return '' }
    $value = [string]$Text
    if ($Length -le 0) { return '' }
    if ($value.Length -le $Length) { return $value }
    if ($Length -le 3) { return $value.Substring(0, $Length) }
    return $value.Substring(0, $Length - 3) + '...'
}

function Format-Value {
    param($Value)
    if ([string]::IsNullOrEmpty($Value)) { return '<empty>' }
    return [string]$Value
}

function Format-DateTimeDisplay {
    param($Value)
    if ([string]::IsNullOrEmpty([string]$Value)) { return '' }
    try {
        $dt = [datetime]$Value
        return $dt.ToLocalTime().ToString('yyyy-MM-dd HH:mm')
    }
    catch {
        return [string]$Value
    }
}

function Test-SameValue {
    param($A, $B)
    if ([string]::IsNullOrEmpty($A) -and [string]::IsNullOrEmpty($B)) { return $true }
    return ([string]$A -ceq [string]$B)
}

function Get-ValueValidationError {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'Value cannot be empty. Use the Clear option to remove a value.'
    }
    if ($Value.Trim().Length -gt $script:MaxValueLength) {
        return "Value cannot be longer than $($script:MaxValueLength) characters."
    }
    return $null
}

function Test-ValidValue {
    param([string]$Value, [switch]$Quiet)
    $errorMessage = Get-ValueValidationError $Value
    if ($errorMessage) {
        if (-not $Quiet) { Write-Host $errorMessage -ForegroundColor Yellow }
        return $false
    }
    return $true
}

function Test-GridViewAvailable {
    return [bool](Get-Command -Name Out-GridView -ErrorAction SilentlyContinue)
}

function ConvertTo-CanonicalGuid {
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = [string](ConvertTo-PlainValue $Value)
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $trimmed = $text.Trim().Trim('"').Trim('{}')
    $guid = [guid]::Empty
    if ([guid]::TryParse($trimmed, [ref]$guid)) {
        return $guid.ToString()
    }
    return $null
}

function Test-LooksLikeGuid {
    param([string]$Value)
    return [bool](ConvertTo-CanonicalGuid $Value)
}

function ConvertTo-ObjectArray {
    param($Value)
    $list = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Value) { return ,$list.ToArray() }
    if ($Value -is [string] -or $Value -is [System.Collections.IDictionary]) {
        $list.Add($Value)
        return ,$list.ToArray()
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($item in $Value) { $list.Add($item) }
        return ,$list.ToArray()
    }
    $list.Add($Value)
    return ,$list.ToArray()
}

function ConvertTo-PlainValue {
    param($Value)
    if ($null -eq $Value) { return $null }

    $typeName = $Value.GetType().FullName
    if ($typeName -eq 'Newtonsoft.Json.Linq.JValue') {
        try { return ConvertTo-PlainValue $Value.Value } catch { }
        try { return [string]$Value } catch { return $null }
    }

    if ($typeName -eq 'System.Text.Json.JsonElement') {
        try {
            switch ($Value.ValueKind.ToString()) {
                'String' { return $Value.GetString() }
                'Number' {
                    try { return $Value.GetInt64() } catch { return $Value.GetDouble() }
                }
                'True' { return $true }
                'False' { return $false }
                'Null' { return $null }
                default { return $Value }
            }
        }
        catch {
            return [string]$Value
        }
    }

    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    if ($Value -is [bool] -or $Value -is [string] -or $Value -is [byte] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int] -or $Value -is [uint32] -or $Value -is [long] -or $Value -is [uint64] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [guid] -or $Value -is [datetime]) {
        return $Value
    }

    return $Value
}

function Add-ToolProperty {
    param($Object, [string]$Name, $Value)
    if ($null -eq $Object) { return $Object }
    if ($null -ne $Value -and $Value -is [System.Collections.IList] -and -not ($Value -is [System.Array]) -and -not ($Value -is [string])) {
        $Value = ConvertTo-ObjectArray $Value
        if ($null -eq $Value) { $Value = [object[]]::new(0) }
    }
    $existing = $Object.PSObject.Properties[$Name]
    if ($existing) {
        $existing.Value = $Value
    }
    else {
        Add-Member -InputObject $Object -NotePropertyName $Name -NotePropertyValue $Value
    }
    return $Object
}

function New-ToolObject {
    param([AllowEmptyCollection()][object[]]$Properties)
    # Windows PowerShell 5.1 throws "Argument types do not match" when a hashtable
    # or [pscustomobject]@{ } holds a Generic.List, PSCustomObject, or Graph JValue.
    # Building with Add-Member from a pair array avoids that.
    $object = New-Object PSObject
    if ($null -eq $Properties) { return $object }
    for ($i = 0; $i -lt $Properties.Count; $i += 2) {
        $name = [string]$Properties[$i]
        $value = $null
        if (($i + 1) -lt $Properties.Count) { $value = $Properties[$i + 1] }
        [void](Add-ToolProperty $object $name $value)
    }
    return $object
}

function New-PsObjectFromHashtable {
    param($Property)
    $pairs = New-Object System.Collections.Generic.List[object]
    foreach ($key in $Property.Keys) {
        $pairs.Add([string]$key)
        $pairs.Add($Property[$key])
    }
    return (New-ToolObject -Properties $pairs.ToArray())
}

#endregion

#region Settings

function Import-ToolSettings {
    param([string]$Path = $script:SettingsFile)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { return }
        $data = $raw | ConvertFrom-Json
        foreach ($name in @('DefaultValue', 'DryRun', 'LogPath', 'RegisteredOnly')) {
            $prop = $data.PSObject.Properties[$name]
            if ($null -eq $prop) { continue }
            if ($name -eq 'DefaultValue') {
                $candidate = [string]$prop.Value
                if (-not (Get-ValueValidationError $candidate)) {
                    $script:Settings.DefaultValue = $candidate.Trim()
                }
            }
            elseif ($name -in @('DryRun', 'RegisteredOnly')) {
                $script:Settings[$name] = [bool]$prop.Value
            }
            elseif ($name -eq 'LogPath' -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
                $script:Settings.LogPath = [string]$prop.Value
            }
        }
    }
    catch {
        Write-Host "Could not read settings file '$Path': $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Export-ToolSettings {
    param([string]$Path = $script:SettingsFile)
    if (-not $Path) { return }
    try {
        $payload = [pscustomobject]@{
            DefaultValue   = $script:Settings.DefaultValue
            DryRun         = [bool]$script:Settings.DryRun
            LogPath        = $script:Settings.LogPath
            RegisteredOnly = [bool]$script:Settings.RegisteredOnly
        }
        $json = $payload | ConvertTo-Json -Depth 4
        $folder = Split-Path -Parent $Path
        if ($folder -and -not (Test-Path -LiteralPath $folder)) {
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
        }
        Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
    }
    catch {
        Write-Host "Could not save settings: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

#endregion

#region Graph property / JSON helpers

function Get-GraphProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object -or [string]::IsNullOrEmpty($Name)) { return $null }

    $found = $null
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                $found = $Object[$key]
                break
            }
        }
    }
    else {
        $prop = $Object.PSObject.Properties[$Name]
        if ($prop) { $found = $prop.Value }
    }

    if ($null -eq $found) { return $null }
    $found = ConvertTo-PlainValue $found
    if ($null -eq $found) { return $null }
    if ($found -is [System.Collections.IDictionary]) { return $found }
    if ($found -is [System.Collections.IEnumerable] -and -not ($found -is [string])) { return $found }
    return $found
}

function Get-GraphCollection {
    param($Response)
    $list = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Response) { return ,$list.ToArray() }

    $value = Get-GraphProperty $Response 'value'
    if ($null -eq $value) {
        if ($null -ne (Get-GraphProperty $Response 'id') -or $null -ne (Get-GraphProperty $Response 'deviceId')) {
            $list.Add($Response)
        }
        return ,$list.ToArray()
    }

    # Hashtables are IEnumerable (keys). A Graph entity is a dictionary; a page of
    # entities is an array/list and must be enumerated as items, not as one object.
    if ($value -is [System.Collections.IDictionary]) {
        $list.Add($value)
        return ,$list.ToArray()
    }
    if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
        foreach ($item in $value) { $list.Add($item) }
        return ,$list.ToArray()
    }

    $list.Add($value)
    return ,$list.ToArray()
}

function ConvertTo-JsonStringLiteral {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return 'null' }
    $text = [string]$Value
    $builder = New-Object System.Text.StringBuilder ($text.Length + 8)
    [void]$builder.Append('"')
    foreach ($ch in $text.ToCharArray()) {
        $code = [int]$ch
        switch ($code) {
            34 { [void]$builder.Append('\"') }
            92 { [void]$builder.Append('\\') }
            8  { [void]$builder.Append('\b') }
            9  { [void]$builder.Append('\t') }
            10 { [void]$builder.Append('\n') }
            12 { [void]$builder.Append('\f') }
            13 { [void]$builder.Append('\r') }
            default {
                if ($code -lt 32) {
                    [void]$builder.AppendFormat('\u{0:x4}', $code)
                }
                else {
                    [void]$builder.Append($ch)
                }
            }
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function New-ExtensionAttributePatchJson {
    param([AllowNull()]$Value)
    $literal = if ([string]::IsNullOrEmpty($Value)) { 'null' } else { ConvertTo-JsonStringLiteral ([string]$Value) }
    return ('{{"extensionAttributes":{{"extensionAttribute1":{0}}}}}' -f $literal)
}

function Get-GraphExceptionStatusCode {
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return 0 }

    $ex = $ErrorRecord.Exception
    while ($null -ne $ex) {
        $response = $null
        if ($ex.PSObject.Properties['Response']) { $response = $ex.Response }
        if ($response) {
            try {
                if ($response.StatusCode) { return [int]$response.StatusCode }
            }
            catch { }
        }
        if ($ex.PSObject.Properties['StatusCode'] -and $ex.StatusCode) {
            try { return [int]$ex.StatusCode } catch { }
        }
        $ex = $ex.InnerException
    }

    $message = [string]$ErrorRecord.Exception.Message
    if ($message -match '\b(429|503|504|401|403|404)\b') { return [int]$Matches[1] }
    if ($message -match 'Too Many Requests|throttl') { return 429 }
    return 0
}

function Get-GraphErrorMessage {
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return 'Unknown error' }
    $message = [string]$ErrorRecord.Exception.Message
    if ($message -match '"message"\s*:\s*"(.*?)"') {
        return ($Matches[1] -replace '\\"', '"')
    }
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $details = [string]$ErrorRecord.ErrorDetails.Message
        if ($details -match '"message"\s*:\s*"(.*?)"') {
            return ($Matches[1] -replace '\\"', '"')
        }
        if ($details) { return $details }
    }
    return $message
}

function Format-CaughtError {
    param($ErrorRecord)
    $message = Get-GraphErrorMessage $ErrorRecord
    $line = 0
    try { $line = [int]$ErrorRecord.InvocationInfo.ScriptLineNumber } catch { }
    if ($line -gt 0) {
        return ('{0}  [line {1}]' -f $message, $line)
    }
    return $message
}

function Test-ArgumentTypesMismatch {
    param($ErrorRecord)
    $message = [string]$ErrorRecord.Exception.Message
    return ($message -like '*Argument types do not match*')
}

function Get-PreferredGraphOutputType {
    param([string[]]$ValidValues)
    $candidates = @('PSObject', 'Json')
    if ($null -eq $ValidValues -or $ValidValues.Count -eq 0) { return $candidates[0] }
    foreach ($candidate in $candidates) {
        foreach ($value in $ValidValues) {
            if ([string]::Equals([string]$value, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $candidate
            }
        }
    }
    return $null
}

function Get-RetryDelaySeconds {
    param($ErrorRecord, [int]$Attempt)
    $delay = [Math]::Min(60, [int][Math]::Pow(2, [Math]::Max(1, $Attempt)))
    $ex = if ($ErrorRecord) { $ErrorRecord.Exception } else { $null }
    while ($null -ne $ex) {
        $response = $null
        if ($ex.PSObject.Properties['Response']) { $response = $ex.Response }
        if ($response -and $response.Headers) {
            try {
                $values = $response.Headers['Retry-After']
                if ($values) {
                    $raw = [string]@($values)[0]
                    $seconds = 0
                    if ([int]::TryParse($raw, [ref]$seconds) -and $seconds -gt 0) { return $seconds }
                }
            }
            catch { }
        }
        $ex = $ex.InnerException
    }
    return $delay
}

function Test-HasGraphScope {
    param($Context, [string]$Scope = $script:RequiredScope)
    if ($null -eq $Context) { return $false }
    $scopes = @($Context.Scopes)
    foreach ($item in $scopes) {
        if ([string]$item -like "*$Scope*") { return $true }
    }
    return $false
}

#endregion

#region Microsoft Graph

function Initialize-GraphModule {
    if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
        try {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
            return $true
        }
        catch {
            Write-Host "Could not import Microsoft.Graph.Authentication: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }

    Write-Host 'The Microsoft.Graph.Authentication module is not installed.' -ForegroundColor Yellow
    if (-not (Read-YesNo 'Install it now for the current user from the PowerShell Gallery?' $true)) { return $false }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
        }
        $installParams = @{
            Name       = 'Microsoft.Graph.Authentication'
            Scope      = 'CurrentUser'
            Repository = 'PSGallery'
            Force      = $true
            AllowClobber = $true
        }
        if ((Get-Command Install-Module).Parameters.ContainsKey('AcceptLicense')) {
            $installParams['AcceptLicense'] = $true
        }
        if ((Get-Command Install-Module).Parameters.ContainsKey('SkipPublisherCheck')) {
            $installParams['SkipPublisherCheck'] = $true
        }
        Install-Module @installParams
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        return $true
    }
    catch {
        Write-Host "Module install failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-GraphConnection {
    $context = Get-MgContext
    if ($null -eq $context) { return $false }
    foreach ($scope in $script:RequiredScopes) {
        if (-not (Test-HasGraphScope $context $scope)) { return $false }
    }
    return $true
}

function Connect-Graph {
    param(
        [switch]$Reconnect,
        [string]$Tenant = $TenantId,
        [switch]$UseDeviceCode = $DeviceCode
    )

    if ((Test-GraphConnection) -and -not $Reconnect) { return $true }

    Write-Title 'Connect to Microsoft Graph'
    if (-not $Tenant) {
        $Tenant = ([string](Read-Host 'Tenant ID or domain (press Enter for your home tenant)')).Trim()
    }

    $connectCommand = Get-Command Connect-MgGraph -ErrorAction Stop
    $useDevice = [bool]$UseDeviceCode
    if (-not $useDevice -and -not $Reconnect) {
        Write-Host '  1) Interactive browser sign-in'
        Write-Host '  2) Device code (RDP, Server Core, no browser)'
        $method = Read-Choice 'Choose sign-in method [1]'
        if ($method -eq '2') { $useDevice = $true }
    }

    $params = @{ Scopes = @($script:RequiredScopes) }
    if ($Tenant) { $params['TenantId'] = $Tenant }
    if ($connectCommand.Parameters.ContainsKey('NoWelcome')) { $params['NoWelcome'] = $true }
    if ($useDevice -and $connectCommand.Parameters.ContainsKey('UseDeviceCode')) {
        $params['UseDeviceCode'] = $true
    }

    try {
        if (Get-MgContext) {
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        }
        Connect-MgGraph @params | Out-Null
    }
    catch {
        Write-Host "Sign-in failed: $(Get-GraphErrorMessage $_)" -ForegroundColor Red
        return $false
    }

    if (-not (Test-GraphConnection)) {
        Write-Host ("Signed in, but these permissions were not granted: {0}. An administrator may need to consent." -f ($script:RequiredScopes -join ', ')) -ForegroundColor Red
        return $false
    }

    $context = Get-MgContext
    Write-Host "Connected as $($context.Account) to tenant $($context.TenantId)" -ForegroundColor Green
    return $true
}

function Invoke-GraphRequestWithRetry {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        $Body,
        [string]$ContentType,
        [hashtable]$Headers,
        [int]$MaxAttempts = 6
    )

    $command = Get-Command Invoke-MgGraphRequest -ErrorAction Stop
    $params = @{
        Method = $Method
        Uri    = $Uri
    }
    if ($null -ne $Body) { $params['Body'] = $Body }
    if ($ContentType) { $params['ContentType'] = $ContentType }
    if ($Headers) { $params['Headers'] = $Headers }

    # Windows PowerShell 5.1 cannot put nested PSCustomObjects/arrays into a Hashtable.
    # Device payloads include extensionAttributes and physicalIds, so HashTable output throws
    # "Argument types do not match". Prefer PSObject (or JSON parsed to objects).
    $validOutputTypes = @()
    if ($command.Parameters.ContainsKey('OutputType')) {
        foreach ($attr in $command.Parameters['OutputType'].Attributes) {
            if ($attr -is [System.Management.Automation.ValidateSetAttribute]) {
                $validOutputTypes = @($attr.ValidValues)
            }
        }
        $outputType = Get-PreferredGraphOutputType $validOutputTypes
        if ($outputType) { $params['OutputType'] = $outputType }
    }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $result = Invoke-MgGraphRequest @params -ErrorAction Stop
            if ($result -is [string]) {
                $text = $result.Trim()
                if ($text.StartsWith('{') -or $text.StartsWith('[')) {
                    try { return ($result | ConvertFrom-Json) } catch { return $result }
                }
            }
            return $result
        }
        catch {
            if ($params.ContainsKey('OutputType') -and (Test-ArgumentTypesMismatch $_)) {
                $params.Remove('OutputType')
                continue
            }
            $status = Get-GraphExceptionStatusCode $_
            if ($status -in 429, 503, 504 -and $attempt -lt $MaxAttempts) {
                $wait = Get-RetryDelaySeconds $_ $attempt
                Write-Host "Microsoft Graph returned HTTP $status. Retrying in $wait second(s) (attempt $attempt of $MaxAttempts)..." -ForegroundColor Yellow
                Start-Sleep -Seconds $wait
                continue
            }
            throw
        }
    }
}

function Invoke-GraphGetAll {
    param(
        [string]$Uri,
        [string]$Activity = 'Retrieving devices from Entra ID',
        [hashtable]$Headers,
        [switch]$ShowHostProgress
    )

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $seenUris = @{}
    $page = 0
    try {
        while ($next) {
            $pageKey = [string]$next
            if ($seenUris.ContainsKey($pageKey)) {
                Write-Host '  Stopped pagination because Microsoft Graph repeated a page link.' -ForegroundColor Yellow
                break
            }
            $seenUris[$pageKey] = $true
            $page++
            if ($page -gt 500) {
                Write-Host '  Stopped pagination after 500 Graph pages.' -ForegroundColor Yellow
                break
            }

            $request = @{ Method = 'GET'; Uri = $next }
            if ($Headers) { $request['Headers'] = $Headers }
            $response = Invoke-GraphRequestWithRetry @request
            foreach ($item in (Get-GraphCollection $response)) {
                $items.Add($item)
            }
            Write-Progress -Activity $Activity -Status "$($items.Count) retrieved"
            if ($ShowHostProgress) {
                Write-Host ("  {0}: {1} retrieved (page {2})..." -f $Activity, $items.Count, $page)
            }
            $nextLink = Get-GraphProperty $response '@odata.nextLink'
            if ($null -eq $nextLink -or [string]::IsNullOrWhiteSpace([string]$nextLink)) {
                $next = $null
            }
            else {
                $next = [string]$nextLink
            }
        }
    }
    finally {
        Write-Progress -Activity $Activity -Completed
    }
    return (ConvertTo-ObjectArray $items)
}

function Get-JoinTypeLabel {
    param($TrustType)
    $TrustType = [string](ConvertTo-PlainValue $TrustType)
    switch ($TrustType) {
        'Workplace' { return 'Entra registered' }
        'AzureAd'   { return 'Entra joined' }
        'ServerAd'  { return 'Hybrid joined' }
        default {
            if ([string]::IsNullOrWhiteSpace($TrustType)) { return 'Unknown' }
            return $TrustType
        }
    }
}

function Test-DeviceEligible {
    param($Device)
    if ($null -eq $Device) { return $false }
    $os = [string]$Device.OperatingSystem
    $trust = [string]$Device.JoinType
    if ($os -notlike 'Windows*') { return $false }
    if ($script:Settings.RegisteredOnly) {
        return ($Device.TrustType -eq 'Workplace' -or $trust -eq 'Entra registered')
    }
    return $true
}

function ConvertTo-DeviceRecord {
    param($Item)

    $extensionAttribute1 = $null
    $extensionAttributes = Get-GraphProperty $Item 'extensionAttributes'
    if ($extensionAttributes) {
        $extensionAttribute1 = Get-GraphProperty $extensionAttributes 'extensionAttribute1'
    }

    $os    = [string](Get-GraphProperty $Item 'operatingSystem')
    $trust = [string](Get-GraphProperty $Item 'trustType')
    $deviceId = ConvertTo-CanonicalGuid (Get-GraphProperty $Item 'deviceId')
    if (-not $deviceId) { $deviceId = [string](Get-GraphProperty $Item 'deviceId') }
    $objectId = ConvertTo-CanonicalGuid (Get-GraphProperty $Item 'id')
    if (-not $objectId) { $objectId = [string](Get-GraphProperty $Item 'id') }

    $record = New-Object PSObject
    [void](Add-ToolProperty $record 'DisplayName' ([string](Get-GraphProperty $Item 'displayName')))
    [void](Add-ToolProperty $record 'DeviceId' ([string]$deviceId))
    [void](Add-ToolProperty $record 'ObjectId' ([string]$objectId))
    [void](Add-ToolProperty $record 'OperatingSystem' $os)
    [void](Add-ToolProperty $record 'OSVersion' ([string](Get-GraphProperty $Item 'operatingSystemVersion')))
    [void](Add-ToolProperty $record 'TrustType' $trust)
    [void](Add-ToolProperty $record 'JoinType' (Get-JoinTypeLabel $trust))
    [void](Add-ToolProperty $record 'Enabled' (ConvertTo-PlainValue (Get-GraphProperty $Item 'accountEnabled')))
    [void](Add-ToolProperty $record 'LastSignIn' (ConvertTo-PlainValue (Get-GraphProperty $Item 'approximateLastSignInDateTime')))
    [void](Add-ToolProperty $record 'LastSignInDisplay' (Format-DateTimeDisplay (Get-GraphProperty $Item 'approximateLastSignInDateTime')))
    [void](Add-ToolProperty $record 'ExtensionAttribute1' (ConvertTo-PlainValue $extensionAttribute1))
    [void](Add-ToolProperty $record 'IsManagementRestricted' (ConvertTo-PlainValue (Get-GraphProperty $Item 'isManagementRestricted')))
    [void](Add-ToolProperty $record 'Eligible' $false)
    $record.Eligible = Test-DeviceEligible $record
    return $record
}

function ConvertTo-DeviceRecords {
    param($Items)
    $records = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Items) { return ,$records.ToArray() }

    $list = New-Object System.Collections.Generic.List[object]
    # Hashtables are IEnumerable (keys). Treat a Graph entity as a single item.
    if ($Items -is [System.Collections.IDictionary]) {
        $list.Add($Items)
    }
    elseif ($Items -is [System.Collections.IEnumerable] -and -not ($Items -is [string])) {
        foreach ($item in $Items) { $list.Add($item) }
    }
    else {
        $list.Add($Items)
    }

    foreach ($item in $list) {
        if ($null -eq $item) { continue }
        $records.Add((ConvertTo-DeviceRecord $item))
    }
    return ,$records.ToArray()
}

function New-GraphDeviceListUri {
    param([string]$Filter, [hashtable]$ExtraQuery)
    $query = New-Object System.Collections.Generic.List[string]
    if ($Filter) {
        $query.Add(('$filter={0}' -f [uri]::EscapeDataString($Filter)))
    }
    $query.Add(('$select={0}' -f $script:SelectFields))
    $query.Add('$top=999')
    if ($ExtraQuery) {
        foreach ($key in $ExtraQuery.Keys) {
            $query.Add(('{0}={1}' -f $key, $ExtraQuery[$key]))
        }
    }
    return ('{0}?{1}' -f $script:GraphBase, ($query -join '&'))
}

function Get-WindowsRegisteredDevices {
    $filters = New-Object System.Collections.Generic.List[string]
    if ($script:Settings.RegisteredOnly) {
        $filters.Add("startswith(operatingSystem,'Windows') and trustType eq 'Workplace'")
        $filters.Add("operatingSystem eq 'Windows' and trustType eq 'Workplace'")
        $filters.Add("trustType eq 'Workplace'")
        $filters.Add("operatingSystem eq 'Windows'")
    }
    else {
        $filters.Add("startswith(operatingSystem,'Windows')")
        $filters.Add("operatingSystem eq 'Windows'")
    }

    $lastError = $null
    foreach ($filter in $filters) {
        try {
            $uri = New-GraphDeviceListUri -Filter $filter
            $raw = Invoke-GraphGetAll -Uri $uri -Activity 'Retrieving Windows devices from Entra ID' -ShowHostProgress
            $records = ConvertTo-ObjectArray (ConvertTo-DeviceRecords $raw | Where-Object { $_.Eligible } | Sort-Object DisplayName)
            return $records
        }
        catch {
            $lastError = $_
            $status = Get-GraphExceptionStatusCode $_
            if ($status -in 400, 0) { continue }
            throw
        }
    }

    if ($lastError) { throw $lastError.Exception }
    return @()
}

function Find-Devices {
    param([string]$Search)

    $search = if ($null -eq $Search) { '' } else { $Search.Trim() }
    if (-not $search) { return @() }

    $records = New-Object System.Collections.Generic.List[object]
    $guid = ConvertTo-CanonicalGuid $search

    if ($guid) {
        $filter = "deviceId eq '$guid'"
        $raw = @(Invoke-GraphGetAll -Uri (New-GraphDeviceListUri -Filter $filter))
        if ($raw.Count -eq 0) {
            try {
                $single = Invoke-GraphRequestWithRetry -Method GET -Uri ('{0}/{1}?$select={2}' -f $script:GraphBase, $guid, $script:SelectFields)
                if ($single) { $raw = @($single) }
            }
            catch {
                $status = Get-GraphExceptionStatusCode $_
                if ($status -ne 404 -and (Get-GraphErrorMessage $_) -notmatch 'NotFound|does not exist') { throw }
            }
        }
        foreach ($record in (ConvertTo-DeviceRecords $raw)) { $records.Add($record) }
        return @($records | Sort-Object DisplayName)
    }

    $escapedName = $search.Replace("'", "''")

    $filters = @(
        "displayName eq '$escapedName'",
        "startswith(displayName,'$escapedName')"
    )
    foreach ($filter in $filters) {
        $raw = @(Invoke-GraphGetAll -Uri (New-GraphDeviceListUri -Filter $filter))
        foreach ($record in (ConvertTo-DeviceRecords $raw)) { $records.Add($record) }
        if ($records.Count -gt 0) { break }
    }

    if ($records.Count -eq 0) {
        try {
            $searchUri = New-GraphDeviceListUri -Filter $null -ExtraQuery @{
                '$search' = [uri]::EscapeDataString(('"{0}"' -f ("displayName:$escapedName")))
                '$count'  = 'true'
            }
            $raw = @(Invoke-GraphGetAll -Uri $searchUri -Headers @{ ConsistencyLevel = 'eventual' })
            foreach ($record in (ConvertTo-DeviceRecords $raw)) { $records.Add($record) }
        }
        catch {
            $status = Get-GraphExceptionStatusCode $_
            if ($status -notin 400, 0) { throw }
        }
    }

    $unique = @{}
    $output = New-Object System.Collections.Generic.List[object]
    foreach ($record in $records) {
        if ($record.ObjectId -and $unique.ContainsKey($record.ObjectId)) { continue }
        if ($record.ObjectId) { $unique[$record.ObjectId] = $true }
        $output.Add($record)
    }
    return @($output | Sort-Object DisplayName)
}

function ConvertTo-UserRecord {
    param($Item)
    $objectId = ConvertTo-CanonicalGuid (Get-GraphProperty $Item 'id')
    if (-not $objectId) { $objectId = [string](Get-GraphProperty $Item 'id') }
    $record = New-Object PSObject
    [void](Add-ToolProperty $record 'ObjectId' ([string]$objectId))
    [void](Add-ToolProperty $record 'DisplayName' ([string](Get-GraphProperty $Item 'displayName')))
    [void](Add-ToolProperty $record 'UserPrincipalName' ([string](Get-GraphProperty $Item 'userPrincipalName')))
    [void](Add-ToolProperty $record 'Mail' ([string](Get-GraphProperty $Item 'mail')))
    [void](Add-ToolProperty $record 'Enabled' (ConvertTo-PlainValue (Get-GraphProperty $Item 'accountEnabled')))
    return $record
}

function Split-UserSearchTokens {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $tokens = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($part in @($Text -split '[,\r\n;\t]+')) {
        $token = $part.Trim().Trim('"').Trim("'")
        if (-not $token) { continue }
        $key = $token.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $tokens.Add($token)
    }
    return @($tokens)
}

function New-GraphUserListUri {
    param([string]$Filter, [hashtable]$ExtraQuery)
    $query = New-Object System.Collections.Generic.List[string]
    if ($Filter) {
        $query.Add(('$filter={0}' -f [uri]::EscapeDataString($Filter)))
    }
    $query.Add(('$select={0}' -f $script:UserSelectFields))
    $query.Add('$top=999')
    if ($ExtraQuery) {
        foreach ($key in $ExtraQuery.Keys) {
            $query.Add(('{0}={1}' -f $key, $ExtraQuery[$key]))
        }
    }
    return ('{0}?{1}' -f $script:GraphUsersBase, ($query -join '&'))
}

function Find-Users {
    param([string]$Search)

    $search = if ($null -eq $Search) { '' } else { $Search.Trim() }
    if (-not $search) { return @() }

    $guid = ConvertTo-CanonicalGuid $search
    if ($guid) {
        try {
            $single = Invoke-GraphRequestWithRetry -Method GET -Uri ('{0}/{1}?$select={2}' -f $script:GraphUsersBase, $guid, $script:UserSelectFields)
            if ($single) { return @(ConvertTo-UserRecord $single) }
        }
        catch {
            $status = Get-GraphExceptionStatusCode $_
            if ($status -ne 404 -and (Get-GraphErrorMessage $_) -notmatch 'NotFound|does not exist') { throw }
        }
        return @()
    }

    $escaped = $search.Replace("'", "''")
    if ($search -match '@') {
        $filter = "userPrincipalName eq '$escaped' or mail eq '$escaped'"
    }
    else {
        $filter = "startswith(displayName,'$escaped') or startswith(userPrincipalName,'$escaped') or startswith(mail,'$escaped')"
    }

    $raw = @()
    try {
        $raw = @(Invoke-GraphGetAll -Uri (New-GraphUserListUri -Filter $filter) -Activity 'Searching users in Entra ID')
    }
    catch {
        $status = Get-GraphExceptionStatusCode $_
        if ($status -notin 400, 0) { throw }
    }

    if ($raw.Count -eq 0) {
        try {
            $searchUri = New-GraphUserListUri -Filter $null -ExtraQuery @{
                '$search' = [uri]::EscapeDataString(('"{0}"' -f $escaped))
                '$count'  = 'true'
            }
            $raw = @(Invoke-GraphGetAll -Uri $searchUri -Headers @{ ConsistencyLevel = 'eventual' } -Activity 'Searching users in Entra ID')
        }
        catch {
            $status = Get-GraphExceptionStatusCode $_
            if ($status -notin 400, 0) { throw }
        }
    }

    $users = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($item in $raw) {
        $user = ConvertTo-UserRecord $item
        if ($user.ObjectId -and $seen.ContainsKey($user.ObjectId)) { continue }
        if ($user.ObjectId) { $seen[$user.ObjectId] = $true }
        $users.Add($user)
    }
    return @($users | Sort-Object DisplayName, UserPrincipalName)
}

function Get-UserRelatedWindowsDevices {
    param($User)

    $pairs = New-Object System.Collections.Generic.List[object]
    $endpoints = @(
        @{ Name = 'Registered'; Path = 'registeredDevices' }
        @{ Name = 'Owned';      Path = 'ownedDevices' }
    )

    foreach ($endpoint in $endpoints) {
        $uri = '{0}/{1}/{2}?$select={3}&$top=999' -f $script:GraphUsersBase, $User.ObjectId, $endpoint.Path, $script:SelectFields
        $raw = @()
        try {
            $raw = @(Invoke-GraphGetAll -Uri $uri -Activity ('Retrieving {0} devices for {1}' -f $endpoint.Name.ToLower(), $User.UserPrincipalName))
        }
        catch {
            $status = Get-GraphExceptionStatusCode $_
            if ($status -eq 400 -or (Test-ArgumentTypesMismatch $_)) {
                $fallback = '{0}/{1}/{2}?$top=999' -f $script:GraphUsersBase, $User.ObjectId, $endpoint.Path
                $raw = @(Invoke-GraphGetAll -Uri $fallback -Activity ('Retrieving {0} devices for {1}' -f $endpoint.Name.ToLower(), $User.UserPrincipalName))
            }
            elseif ($status -eq 404) {
                continue
            }
            else {
                throw
            }
        }

        foreach ($item in (ConvertTo-ObjectArray $raw)) {
            $record = $null
            try {
                $record = ConvertTo-DeviceRecord $item
            }
            catch {
                Write-Host ("  Skipping a {0} device for {1}: {2}" -f $endpoint.Name.ToLower(), $User.UserPrincipalName, (Format-CaughtError $_)) -ForegroundColor Yellow
                continue
            }
            if ([string]::IsNullOrWhiteSpace($record.OperatingSystem) -and $record.ObjectId) {
                try {
                    $full = Invoke-GraphRequestWithRetry -Method GET -Uri ('{0}/{1}?$select={2}' -f $script:GraphBase, $record.ObjectId, $script:SelectFields)
                    if ($full) { $record = ConvertTo-DeviceRecord $full }
                }
                catch { }
            }
            if ($record.OperatingSystem -notlike 'Windows*') { continue }
            $pair = New-Object PSObject
            [void](Add-ToolProperty $pair 'Device' $record)
            [void](Add-ToolProperty $pair 'User' $User)
            [void](Add-ToolProperty $pair 'Relationship' $endpoint.Name)
            $pairs.Add($pair)
        }
    }

    # Windows PowerShell 5.1 throws "Argument types do not match" for @($genericList)
    # when the list holds PSCustomObjects with nested objects (Device/User).
    return (ConvertTo-ObjectArray $pairs)
}

function Write-AuditLog {
    param($Entry)
    try {
        $folder = Split-Path -Parent $script:Settings.LogPath
        if ($folder -and -not (Test-Path -LiteralPath $folder)) {
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
        }
        $Entry | Export-Csv -Path $script:Settings.LogPath -Append -NoTypeInformation -Encoding UTF8
    }
    catch {
        Write-Host "Could not write audit log: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Set-DeviceExtensionAttribute {
    param(
        [Parameter(Mandatory = $true)] $Device,
        $NewValue,
        [string]$Source = 'Single'
    )

    if ([string]::IsNullOrEmpty($NewValue)) {
        $NewValue = $null
        $action = 'Clear'
    }
    elseif ([string]::IsNullOrEmpty($Device.ExtensionAttribute1)) {
        $action = 'Add'
    }
    else {
        $action = 'Modify'
    }

    $status  = 'Success'
    $message = ''

    if ($Device.IsManagementRestricted) {
        $message = 'Device is in a restricted management administrative unit; the update may be denied.'
    }

    if ($script:Settings.DryRun) {
        $status  = 'DryRun'
        $message = 'No change written (dry-run mode)'
    }
    else {
        $body = New-ExtensionAttributePatchJson $NewValue
        try {
            Invoke-GraphRequestWithRetry -Method PATCH -Uri "$($script:GraphBase)/$($Device.ObjectId)" -Body $body -ContentType 'application/json' | Out-Null
        }
        catch {
            $status  = 'Failed'
            $message = Get-GraphErrorMessage $_
        }
    }

    $context = $null
    try { $context = Get-MgContext } catch { }
    $entry = [pscustomobject]@{
        Timestamp     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Source        = $Source
        Status        = $status
        Action        = $action
        DisplayName   = $Device.DisplayName
        DeviceId      = $Device.DeviceId
        ObjectId      = $Device.ObjectId
        PreviousValue = $Device.ExtensionAttribute1
        NewValue      = $NewValue
        ChangedBy     = if ($context) { $context.Account } else { '' }
        Message       = $message
    }
    Write-AuditLog $entry
    return $entry
}

#endregion

#region CSV helpers

function Get-CsvDelimiter {
    param([string]$Path)
    $lines = @(Get-Content -LiteralPath $Path -TotalCount 8 -ErrorAction Stop)
    $normalised = @($lines | ForEach-Object { $_.Trim().Trim([char]0xFEFF) })
    if ($normalised.Count -gt 0 -and $normalised[0] -match '^sep=(.)$') { return $Matches[1] }
    $header = $null
    foreach ($line in $normalised) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^sep=') { continue }
        $header = $line
        break
    }
    if (-not $header) { return ',' }
    $comma = ([regex]::Matches($header, ',')).Count
    $semi  = ([regex]::Matches($header, ';')).Count
    $tab   = ([regex]::Matches($header, "`t")).Count
    if ($tab -ge $comma -and $tab -ge $semi -and $tab -gt 0) { return "`t" }
    if ($semi -gt $comma) { return ';' }
    return ','
}

function Import-DeviceCsv {
    param([string]$Path)
    $delimiter = Get-CsvDelimiter -Path $Path
    $lines = @(Get-Content -LiteralPath $Path -Encoding UTF8)
    if ($lines.Count -gt 0 -and $lines[0].Trim().Trim([char]0xFEFF) -match '^sep=') {
        $lines = @($lines | Select-Object -Skip 1)
    }
    if ($lines.Count -eq 0) { return @() }

    $temp = [IO.Path]::GetTempFileName()
    try {
        Set-Content -LiteralPath $temp -Value $lines -Encoding UTF8
        return @(Import-Csv -LiteralPath $temp -Delimiter $delimiter -Encoding UTF8)
    }
    finally {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    }
}

function Resolve-CsvColumnMap {
    param($Headers)
    $map = @{}
    $headerList = @(
        $Headers | ForEach-Object {
            if ($_ -is [System.Management.Automation.PSPropertyInfo]) { $_.Name }
            else { [string]$_ }
        } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    foreach ($canonical in @('DeviceId', 'ObjectId', 'DisplayName', 'Value', 'Action')) {
        foreach ($alias in $script:CsvColumnAliases[$canonical]) {
            $match = $headerList | Where-Object { [string]::Equals($_.Trim(), $alias.Trim(), [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
            if ($match) {
                $map[$canonical] = $match
                break
            }
        }
    }
    return $map
}

function Get-RowField {
    param($Row, [string]$Name)
    if ($null -eq $Row -or [string]::IsNullOrWhiteSpace($Name)) { return '' }
    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property) {
        $property = $Row.PSObject.Properties | Where-Object { [string]::Equals($_.Name.Trim(), $Name.Trim(), [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
    }
    if ($null -eq $property -or $null -eq $property.Value) { return '' }
    return ([string]$property.Value).Trim().Trim('"')
}

function Get-MappedRowField {
    param($Row, $ColumnMap, [string]$CanonicalName)
    if ($null -eq $ColumnMap -or -not $ColumnMap.ContainsKey($CanonicalName)) { return '' }
    return Get-RowField $Row $ColumnMap[$CanonicalName]
}

function Get-BulkCsvLookupTargets {
    param($Rows, $ColumnMap)
    $targets = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($row in (ConvertTo-ObjectArray $Rows)) {
        $deviceId = ConvertTo-CanonicalGuid (Get-MappedRowField $row $ColumnMap 'DeviceId')
        if (-not $deviceId) { $deviceId = '' }
        $objectId = ConvertTo-CanonicalGuid (Get-MappedRowField $row $ColumnMap 'ObjectId')
        if (-not $objectId) { $objectId = '' }
        $name = [string](Get-MappedRowField $row $ColumnMap 'DisplayName')
        $search = if ($deviceId) { $deviceId } elseif ($objectId) { $objectId } elseif ($name) { $name } else { $null }
        if (-not $search) { continue }
        $key = $search.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $target = New-Object PSObject
        [void](Add-ToolProperty $target 'Search' $search)
        [void](Add-ToolProperty $target 'DeviceId' $deviceId)
        [void](Add-ToolProperty $target 'ObjectId' $objectId)
        [void](Add-ToolProperty $target 'DisplayName' $name)
        $targets.Add($target)
    }
    return (ConvertTo-ObjectArray $targets)
}

function Get-DevicesForBulkRows {
    param($Rows, $ColumnMap)
    $devices = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $targets = Get-BulkCsvLookupTargets -Rows $Rows -ColumnMap $ColumnMap
    $total = @($targets).Count
    $n = 0
    foreach ($target in $targets) {
        $n++
        $label = $target.DisplayName
        if (-not $label) { $label = $target.Search }
        Write-Host ("  {0}/{1}  {2}" -f $n, $total, $label)
        try {
            $found = ConvertTo-ObjectArray (Find-Devices $target.Search)
        }
        catch {
            Write-Host ("    Lookup failed: {0}" -f (Format-CaughtError $_)) -ForegroundColor Yellow
            continue
        }
        foreach ($record in $found) {
            $id = [string]$record.ObjectId
            if (-not $id) { $id = [string]$record.DeviceId }
            if ($id -and $seen.ContainsKey($id)) { continue }
            if ($id) { $seen[$id] = $true }
            $devices.Add($record)
        }
    }
    return (ConvertTo-ObjectArray $devices)
}

function Get-RowAction {
    param($Row, $ColumnMap)
    $action = if ($ColumnMap) { Get-MappedRowField $Row $ColumnMap 'Action' } else { Get-RowField $Row 'Action' }
    if ($action -match '^(clear|remove|delete)$') { return 'Clear' }
    if ($action -eq '' -or $action -match '^(set|add|modify|update)$') { return 'Set' }
    return 'Invalid'
}

function Resolve-UserCsvColumnMap {
    param($Headers)
    $map = @{}
    $headerList = @(
        $Headers | ForEach-Object {
            if ($_ -is [System.Management.Automation.PSPropertyInfo]) { $_.Name }
            else { [string]$_ }
        } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    foreach ($canonical in @('ObjectId', 'UserPrincipalName', 'Mail', 'DisplayName')) {
        foreach ($alias in $script:UserCsvColumnAliases[$canonical]) {
            $match = $headerList | Where-Object { [string]::Equals($_.Trim(), $alias.Trim(), [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
            if ($match) {
                $map[$canonical] = $match
                break
            }
        }
    }
    return $map
}

function Get-UserRowSearchToken {
    param($Row, $ColumnMap)
    foreach ($name in @('ObjectId', 'UserPrincipalName', 'Mail', 'DisplayName')) {
        $value = Get-MappedRowField $Row $ColumnMap $name
        if ($value) { return $value }
    }
    return ''
}

function New-UserDeviceBulkRow {
    param(
        $Device,
        $User,
        [string]$Relationship = 'Registered',
        $Value,
        [string]$Action = 'Set'
    )
    if ($Action -eq 'Clear') { $Value = '' }
    elseif ($null -eq $Value) { $Value = '' }
    return (New-ToolObject @(
            'DeviceId', $Device.DeviceId
            'ObjectId', $Device.ObjectId
            'DisplayName', $Device.DisplayName
            'Value', [string]$Value
            'Action', $Action
            'UserPrincipalName', $(if ($User) { [string]$User.UserPrincipalName } else { '' })
            'UserDisplayName', $(if ($User) { [string]$User.DisplayName } else { '' })
            'UserObjectId', $(if ($User) { [string]$User.ObjectId } else { '' })
            'Relationship', $Relationship
            'JoinType', $Device.JoinType
            'OperatingSystem', $Device.OperatingSystem
            'CurrentExtensionAttribute1', $Device.ExtensionAttribute1
            'Eligible', [bool]$Device.Eligible
        ))
}

function Merge-UserDeviceBulkRows {
    param([object[]]$Rows)
    $byKey = [ordered]@{}
    foreach ($row in @($Rows)) {
        $key = if ($row.ObjectId) { [string]$row.ObjectId } elseif ($row.DeviceId) { [string]$row.DeviceId } else { [guid]::NewGuid().ToString() }
        if ($byKey.Contains($key)) {
            $existing = $byKey[$key]
            $relParts = New-Object System.Collections.Generic.List[string]
            foreach ($part in @(($existing.Relationship -split ',') + ($row.Relationship -split ','))) {
                $piece = ([string]$part).Trim()
                if ($piece -and -not $relParts.Contains($piece)) { $relParts.Add($piece) }
            }
            $existing.Relationship = ($relParts -join ', ')

            if ($row.UserPrincipalName -and $existing.UserPrincipalName -notlike ('*{0}*' -f $row.UserPrincipalName)) {
                $existing.UserPrincipalName = @($existing.UserPrincipalName, $row.UserPrincipalName) -join '; '
                $existing.UserDisplayName = @($existing.UserDisplayName, $row.UserDisplayName) -join '; '
                $existing.UserObjectId = @($existing.UserObjectId, $row.UserObjectId) -join '; '
            }
        }
        else {
            $byKey[$key] = $row
        }
    }
    return (ConvertTo-ObjectArray $byKey.Values)
}

function New-DeviceIndex {
    param([object[]]$Devices)
    $index = [pscustomobject]@{
        ByDeviceId = @{}
        ByObjectId = @{}
        ByName     = @{}
    }
    foreach ($device in @($Devices)) {
        if ($device.DeviceId) { $index.ByDeviceId[$device.DeviceId] = $device }
        if ($device.ObjectId) { $index.ByObjectId[$device.ObjectId] = $device }
        $name = [string]$device.DisplayName
        if ($name) {
            if (-not $index.ByName.ContainsKey($name)) {
                $index.ByName[$name] = New-Object System.Collections.Generic.List[object]
            }
            $index.ByName[$name].Add($device)
        }
    }
    return $index
}

function New-BulkUpdatePlan {
    param(
        [Parameter(Mandatory = $true)][object[]]$Rows,
        [Parameter(Mandatory = $true)]$DeviceIndex,
        $ColumnMap,
        $FallbackValue,
        [bool]$SkipMissing = $false,
        [int]$HeaderLineNumber = 1,
        [scriptblock]$LookupMissingDevice
    )

    if (-not $ColumnMap) {
        $headers = @($Rows[0].PSObject.Properties | ForEach-Object { $_.Name })
        $ColumnMap = Resolve-CsvColumnMap $headers
    }

    $plan = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $rowNumber = $HeaderLineNumber

    foreach ($row in $Rows) {
        $rowNumber++
        $deviceIdText = Get-MappedRowField $row $ColumnMap 'DeviceId'
        $objectIdText = Get-MappedRowField $row $ColumnMap 'ObjectId'
        $nameText     = Get-MappedRowField $row $ColumnMap 'DisplayName'

        $deviceId = ConvertTo-CanonicalGuid $deviceIdText
        if (-not $deviceId) { $deviceId = $deviceIdText }
        $objectId = ConvertTo-CanonicalGuid $objectIdText
        if (-not $objectId) { $objectId = $objectIdText }

        $identifier = ''
        $device     = $null
        $status     = 'Ready'
        $note       = ''
        $newValue   = $null

        if ($deviceId) {
            $identifier = $deviceId
            if ($DeviceIndex.ByDeviceId.ContainsKey($deviceId)) { $device = $DeviceIndex.ByDeviceId[$deviceId] }
        }
        elseif ($objectId) {
            $identifier = $objectId
            if ($DeviceIndex.ByObjectId.ContainsKey($objectId)) { $device = $DeviceIndex.ByObjectId[$objectId] }
        }
        elseif ($nameText) {
            $identifier = $nameText
            if ($DeviceIndex.ByName.ContainsKey($nameText)) {
                $nameMatches = $DeviceIndex.ByName[$nameText]
                if ($nameMatches.Count -eq 1) {
                    $device = $nameMatches[0]
                }
                else {
                    $status = 'Ambiguous'
                    $note   = "$($nameMatches.Count) devices share this name. Use DeviceId instead."
                }
            }
        }
        else {
            $status = 'Invalid'
            $note   = 'No DeviceId, ObjectId or DisplayName'
        }

        if ($status -eq 'Ready' -and $null -eq $device) {
            $lookedUp = $null
            if ($LookupMissingDevice) {
                $lookedUp = & $LookupMissingDevice $deviceId $objectId $nameText
            }
            if ($lookedUp) {
                $status = 'NotEligible'
                $note   = "Found as $($lookedUp.JoinType) ($($lookedUp.OperatingSystem)). Only eligible Windows devices can be changed."
                $device = $lookedUp
            }
            else {
                $status = 'NotFound'
                $note   = 'Not found as an eligible Windows device'
            }
        }

        if ($status -eq 'Ready') {
            $action = Get-RowAction $row $ColumnMap
            if ($action -eq 'Invalid') {
                $status = 'Invalid'
                $note   = "Unknown Action '$(Get-MappedRowField $row $ColumnMap 'Action')'. Use Set or Clear."
            }
            elseif ($action -eq 'Clear') {
                $newValue = $null
            }
            else {
                $rowValue = Get-MappedRowField $row $ColumnMap 'Value'
                if ($rowValue) {
                    $validation = Get-ValueValidationError $rowValue
                    if ($validation) {
                        $status = 'Invalid'
                        $note   = $validation
                    }
                    else {
                        $newValue = $rowValue
                    }
                }
                elseif ($SkipMissing) {
                    $status = 'Skipped'
                    $note   = 'No Value in CSV'
                }
                else {
                    $newValue = $FallbackValue
                }
            }
        }

        if ($status -eq 'Ready') {
            if ($seen.ContainsKey($device.ObjectId)) {
                $status = 'Duplicate'
                $note   = "Same device as row $($seen[$device.ObjectId])"
            }
            else {
                $seen[$device.ObjectId] = $rowNumber
                if (Test-SameValue $device.ExtensionAttribute1 $newValue) {
                    $status = 'NoChange'
                    $note   = 'Already has this value'
                }
            }
        }

        $displayName  = ''
        $currentValue = ''
        $newDisplay   = ''
        if ($device) {
            $displayName  = $device.DisplayName
            $currentValue = Format-Value $device.ExtensionAttribute1
        }
        if ($status -eq 'Ready' -or $status -eq 'NoChange') { $newDisplay = Format-Value $newValue }

        $plan.Add((New-ToolObject @(
                    'Row', $rowNumber
                    'Identifier', $identifier
                    'DisplayName', $displayName
                    'Current', $currentValue
                    'New', $newDisplay
                    'Status', $status
                    'Note', $note
                    'Device', $device
                    'NewValue', $newValue
                )))
    }

    return (ConvertTo-ObjectArray $plan)
}

#endregion

#region Shared prompts

function Read-ValueChoice {
    param([string]$Heading = 'What do you want to set extensionAttribute1 to?')

    Write-Host ''
    Write-Host $Heading -ForegroundColor Cyan
    Write-Host "  1) Default value '$($script:Settings.DefaultValue)'"
    Write-Host '  2) Enter a custom value'
    Write-Host '  3) Clear the value'
    Write-Host '  0) Cancel'

    while ($true) {
        switch (Read-Choice 'Choose') {
            '1' { return @{ Value = $script:Settings.DefaultValue } }
            '2' {
                $custom = [string](Read-Host 'Enter value')
                if (Test-ValidValue $custom) { return @{ Value = $custom.Trim() } }
            }
            '3' { return @{ Value = $null } }
            '0' { return $null }
            default { Write-Host 'Invalid choice.' -ForegroundColor Yellow }
        }
    }
}

function Show-DeviceDetail {
    param($Device)
    $Device |
        Select-Object DisplayName, DeviceId, ObjectId, JoinType, OperatingSystem, OSVersion,
            @{ Name = 'Enabled'; Expression = { $_.Enabled } },
            @{ Name = 'LastSignIn'; Expression = { $_.LastSignInDisplay } },
            @{ Name = 'Restricted AU'; Expression = { $_.IsManagementRestricted } },
            @{ Name = 'ExtensionAttribute1'; Expression = { Format-Value $_.ExtensionAttribute1 } } |
        Format-List | Out-Host
}

function Select-DeviceFromList {
    param([object[]]$Devices)

    $pageSize = 30
    $page = 0
    $total = $Devices.Count
    $pageCount = [Math]::Max(1, [int][Math]::Ceiling($total / $pageSize))

    while ($true) {
        $start = $page * $pageSize
        $shown = @($Devices | Select-Object -Skip $start -First $pageSize)

        Write-Host ''
        Write-Host ('{0,4}  {1,-30} {2,-17} {3,-12} {4}' -f '#', 'Name', 'Join type', 'OS', 'extensionAttribute1') -ForegroundColor Cyan
        for ($i = 0; $i -lt $shown.Count; $i++) {
            $d = $shown[$i]
            $color = if ($d.Eligible) { 'White' } else { 'DarkGray' }
            $line = '{0,4}) {1,-30} {2,-17} {3,-12} {4}' -f ($start + $i + 1), (Limit-Text $d.DisplayName 30), $d.JoinType, (Limit-Text $d.OperatingSystem 12), (Format-Value $d.ExtensionAttribute1)
            Write-Host $line -ForegroundColor $color
        }
        Write-Host '      Grey entries are not eligible and cannot be changed.' -ForegroundColor DarkGray
        if ($pageCount -gt 1) {
            Write-Host "      Page $($page + 1) of $pageCount. N=next, P=previous." -ForegroundColor Yellow
        }

        $pick = ([string](Read-Host 'Select a number (Enter to cancel)')).Trim()
        if (-not $pick) { return $null }
        if ($pick -match '^(N|NEXT)$') {
            if ($page -lt $pageCount - 1) { $page++ }
            continue
        }
        if ($pick -match '^(P|PREV|PREVIOUS)$') {
            if ($page -gt 0) { $page-- }
            continue
        }

        $number = 0
        if ([int]::TryParse($pick, [ref]$number) -and $number -ge 1 -and $number -le $total) {
            $choice = $Devices[$number - 1]
            if ($choice.Eligible) { return $choice }
            Write-Host "That device is $($choice.JoinType) ($($choice.OperatingSystem)). Only eligible Windows devices can be changed." -ForegroundColor Yellow
            continue
        }
        Write-Host 'Invalid selection.' -ForegroundColor Yellow
    }
}

function Select-UserFromList {
    param([object[]]$Users)

    $pageSize = 30
    $page = 0
    $total = $Users.Count
    $pageCount = [Math]::Max(1, [int][Math]::Ceiling($total / $pageSize))

    while ($true) {
        $start = $page * $pageSize
        $shown = @($Users | Select-Object -Skip $start -First $pageSize)

        Write-Host ''
        Write-Host ('{0,4}  {1,-32} {2,-36} {3}' -f '#', 'Name', 'UPN', 'Enabled') -ForegroundColor Cyan
        for ($i = 0; $i -lt $shown.Count; $i++) {
            $u = $shown[$i]
            $line = '{0,4}) {1,-32} {2,-36} {3}' -f ($start + $i + 1), (Limit-Text $u.DisplayName 32), (Limit-Text $u.UserPrincipalName 36), $u.Enabled
            Write-Host $line
        }
        if ($pageCount -gt 1) {
            Write-Host "      Page $($page + 1) of $pageCount. N=next, P=previous." -ForegroundColor Yellow
        }

        $pick = ([string](Read-Host 'Select a number (Enter to skip this user)')).Trim()
        if (-not $pick) { return $null }
        if ($pick -match '^(N|NEXT)$') {
            if ($page -lt $pageCount - 1) { $page++ }
            continue
        }
        if ($pick -match '^(P|PREV|PREVIOUS)$') {
            if ($page -gt 0) { $page-- }
            continue
        }

        $number = 0
        if ([int]::TryParse($pick, [ref]$number) -and $number -ge 1 -and $number -le $total) {
            return $Users[$number - 1]
        }
        Write-Host 'Invalid selection.' -ForegroundColor Yellow
    }
}

#endregion

#region Menu actions

function Show-DeviceList {
    Write-Title 'Windows Entra devices'

    try {
        Write-Host 'Large tenants can take a few minutes. A count is printed after each Graph page.' -ForegroundColor DarkGray
        $devices = ConvertTo-ObjectArray (Get-WindowsRegisteredDevices)
    }
    catch {
        Write-Host "Failed to retrieve devices: $(Get-GraphErrorMessage $_)" -ForegroundColor Red
        Wait-ForKey
        return
    }

    $view = $devices
    $columns = @(
        'DisplayName',
        'DeviceId',
        'JoinType',
        'OSVersion',
        'Enabled',
        @{ Name = 'LastSignIn'; Expression = { $_.LastSignInDisplay } },
        @{ Name = 'ExtensionAttribute1'; Expression = { Format-Value $_.ExtensionAttribute1 } }
    )

    while ($true) {
        $withValue   = @($view | Where-Object { -not [string]::IsNullOrEmpty($_.ExtensionAttribute1) })
        $withDefault = @($view | Where-Object { $_.ExtensionAttribute1 -ceq $script:Settings.DefaultValue })
        $scopeText   = if ($script:Settings.RegisteredOnly) { 'Windows Entra registered' } else { 'Windows' }

        Write-Host ''
        Write-Host "Found $($devices.Count) $scopeText devices." -ForegroundColor Green
        if ($view.Count -ne $devices.Count) {
            Write-Host "Showing $($view.Count) after name filter." -ForegroundColor Yellow
        }
        Write-Host "  $($withValue.Count) have extensionAttribute1 set, $($withDefault.Count) are set to '$($script:Settings.DefaultValue)'."
        Write-Host ''
        Write-Host '  1) Show listed devices'
        Write-Host '  2) Show devices with extensionAttribute1 set'
        Write-Host "  3) Show devices set to '$($script:Settings.DefaultValue)'"
        if (Test-GridViewAvailable) { Write-Host '  4) Open in grid view' } else { Write-Host '  4) Open in grid view (not available in this session)' }
        Write-Host '  5) Export list to CSV'
        Write-Host '  6) Filter listed devices by name'
        Write-Host '  7) Clear name filter'
        Write-Host '  0) Back'

        switch (Read-Choice) {
            '1' { $view | Format-Table -Property $columns -AutoSize | Out-Host }
            '2' { $withValue | Format-Table -Property $columns -AutoSize | Out-Host }
            '3' { $withDefault | Format-Table -Property $columns -AutoSize | Out-Host }
            '4' {
                if (Test-GridViewAvailable) {
                    $view | Select-Object DisplayName, DeviceId, ObjectId, JoinType, OperatingSystem, OSVersion, Enabled, LastSignInDisplay, ExtensionAttribute1 |
                        Out-GridView -Title 'Windows Entra devices'
                }
                else {
                    Write-Host 'Out-GridView is not available. Install Microsoft.PowerShell.GraphicalTools or use Windows PowerShell.' -ForegroundColor Yellow
                }
            }
            '5' {
                $defaultPath = Join-Path $script:Root ('EntraRegisteredDevices_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
                $path = ([string](Read-Host "Save to [$defaultPath]")).Trim().Trim('"')
                if (-not $path) { $path = $defaultPath }
                try {
                    $folder = Split-Path -Parent $path
                    if ($folder -and -not (Test-Path -LiteralPath $folder)) {
                        New-Item -ItemType Directory -Path $folder -Force | Out-Null
                    }
                    $view | Select-Object DisplayName, DeviceId, ObjectId, JoinType, OperatingSystem, OSVersion, Enabled, LastSignIn, ExtensionAttribute1 |
                        Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
                    Write-Host "Exported to $path" -ForegroundColor Green
                }
                catch {
                    Write-Host "Export failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            '6' {
                $filter = ([string](Read-Host 'Name contains')).Trim()
                if ($filter) {
                    $view = @($devices | Where-Object { $_.DisplayName -like "*$filter*" })
                }
            }
            '7' { $view = $devices }
            '0' { return }
            default { Write-Host 'Invalid choice.' -ForegroundColor Yellow }
        }
    }
}

function Invoke-SingleDeviceUpdate {
    Write-Title 'Update a single device'

    while ($true) {
        Write-Host ''
        $search = ([string](Read-Host 'Device name (or start of name), Device ID or Object ID (Enter to go back)')).Trim()
        if (-not $search) { return }

        try {
            $found = @(Find-Devices $search)
        }
        catch {
            Write-Host "Lookup failed: $(Get-GraphErrorMessage $_)" -ForegroundColor Red
            continue
        }

        if ($found.Count -eq 0) {
            Write-Host "No devices found matching '$search'." -ForegroundColor Yellow
            continue
        }

        $eligible = @($found | Where-Object { $_.Eligible })
        if ($eligible.Count -eq 0) {
            Write-Host 'Matching devices were found, but none are eligible to change:' -ForegroundColor Yellow
            $found | Format-Table DisplayName, JoinType, OperatingSystem, DeviceId -AutoSize | Out-Host
            if ($script:Settings.RegisteredOnly) {
                Write-Host "Only Windows Entra registered devices are eligible. Turn off 'Registered only' in Settings to include Entra joined / hybrid devices." -ForegroundColor DarkGray
            }
            continue
        }

        if ($found.Count -eq 1) { $device = $found[0] } else { $device = Select-DeviceFromList $found }
        if ($null -eq $device) { continue }

        Show-DeviceDetail $device
        if ($device.IsManagementRestricted) {
            Write-Host 'This device is in a restricted management administrative unit. The update may be denied unless your role is scoped to that unit.' -ForegroundColor Yellow
        }

        $choice = Read-ValueChoice
        if ($null -eq $choice) {
            Write-Host 'Cancelled.' -ForegroundColor Yellow
            continue
        }

        $newValue = $choice.Value
        if (Test-SameValue $device.ExtensionAttribute1 $newValue) {
            Write-Host 'The device already has that value. Nothing to change.' -ForegroundColor Yellow
            continue
        }

        Write-Host ''
        Write-Host "Device : $($device.DisplayName)"
        Write-Host "Current: $(Format-Value $device.ExtensionAttribute1)"
        Write-Host "New    : $(Format-Value $newValue)"
        if ($script:Settings.DryRun) { Write-Host 'Dry-run mode is ON. No change will be written.' -ForegroundColor Yellow }

        if (-not (Read-YesNo 'Apply this change?' $false)) {
            Write-Host 'Cancelled.' -ForegroundColor Yellow
            continue
        }

        $result = Set-DeviceExtensionAttribute -Device $device -NewValue $newValue -Source 'Single'
        switch ($result.Status) {
            'Success' { Write-Host "$($result.Action) completed for $($device.DisplayName)." -ForegroundColor Green }
            'DryRun'  { Write-Host "Dry-run: would $($result.Action.ToLower()) the value on $($device.DisplayName)." -ForegroundColor Yellow }
            default   { Write-Host "Failed: $($result.Message)" -ForegroundColor Red }
        }

        if (-not (Read-YesNo 'Update another device?' $true)) { return }
    }
}

function Show-OpenFileDialog {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $owner = New-Object System.Windows.Forms.Form
        $owner.TopMost = $true
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = 'Select device CSV'
        $dialog.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
        $dialog.InitialDirectory = $script:Root
        $result = $dialog.ShowDialog($owner)
        $owner.Dispose()
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.FileName }
    }
    catch {
        Write-Host 'The file browser is not available in this session. Type the path instead.' -ForegroundColor Yellow
    }
    return $null
}

function Select-CsvPath {
    Write-Host '  1) Browse for the CSV file'
    Write-Host '  2) Type the path'
    Write-Host '  0) Cancel'

    switch (Read-Choice 'Choose') {
        '1' {
            $path = Show-OpenFileDialog
            if ($path) { return $path }
            $typed = ([string](Read-Host 'Full path to CSV (Enter to cancel)')).Trim().Trim('"')
            if ($typed) { return $typed }
            return $null
        }
        '2' {
            $typed = ([string](Read-Host 'Full path to CSV')).Trim().Trim('"')
            if ($typed) { return $typed }
            return $null
        }
        default { return $null }
    }
}

function Invoke-BulkUpdate {
    param([string]$Path)

    Write-Title 'Bulk update from CSV'

    if (-not $Path) { $Path = Select-CsvPath }
    if (-not $Path) { return }

    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Write-Host "File not found: $path" -ForegroundColor Red
        Wait-ForKey
        return
    }

    try {
        $rows = @(Import-DeviceCsv -Path $path)
    }
    catch {
        Write-Host "Could not read CSV: $($_.Exception.Message)" -ForegroundColor Red
        Wait-ForKey
        return
    }

    if ($rows.Count -eq 0) {
        Write-Host 'The CSV has no data rows.' -ForegroundColor Yellow
        Wait-ForKey
        return
    }

    $headers   = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name })
    $columnMap = Resolve-CsvColumnMap $headers
    $idColumns = @('DeviceId', 'ObjectId', 'DisplayName' | Where-Object { $columnMap.ContainsKey($_) })
    if ($idColumns.Count -eq 0) {
        Write-Host 'The CSV needs at least one of these columns: DeviceId, ObjectId, DisplayName (or an alias such as Name / ComputerName).' -ForegroundColor Red
        Write-Host "Columns found: $($headers -join ', ')" -ForegroundColor Red
        Wait-ForKey
        return
    }

    Write-Host ''
    Write-Host "Loaded $($rows.Count) rows from $path" -ForegroundColor Green
    Write-Host "Identifier columns: $($idColumns -join ', ')"

    $missingValueCount = @($rows | Where-Object {
            (Get-RowAction $_ $columnMap) -eq 'Set' -and [string]::IsNullOrEmpty((Get-MappedRowField $_ $columnMap 'Value'))
        }).Count

    $fallbackValue = $null
    $skipMissing   = $false
    if ($missingValueCount -gt 0) {
        Write-Host ''
        Write-Host "$missingValueCount rows have no Value." -ForegroundColor Yellow
        Write-Host '  1) Use the default value'
        Write-Host '  2) Use a custom value'
        Write-Host '  3) Clear the value on those devices'
        Write-Host '  4) Skip those rows'
        Write-Host '  0) Cancel'

        $decided = $false
        while (-not $decided) {
            switch (Read-Choice 'Choose') {
                '1' { $fallbackValue = $script:Settings.DefaultValue; $decided = $true }
                '2' {
                    $custom = [string](Read-Host 'Enter value')
                    if (Test-ValidValue $custom) { $fallbackValue = $custom.Trim(); $decided = $true }
                }
                '3' { $fallbackValue = $null; $decided = $true }
                '4' { $skipMissing = $true; $decided = $true }
                '0' { return }
                default { Write-Host 'Invalid choice.' -ForegroundColor Yellow }
            }
        }
    }

    Write-Host ''
    Write-Host "Looking up $($rows.Count) CSV device(s) in Entra ID..."
    try {
        $devices = ConvertTo-ObjectArray (Get-DevicesForBulkRows -Rows $rows -ColumnMap $columnMap)
    }
    catch {
        Write-Host "Failed to retrieve devices: $(Format-CaughtError $_)" -ForegroundColor Red
        Wait-ForKey
        return
    }
    Write-Host ("Found {0} matching Entra device(s)." -f @($devices).Count) -ForegroundColor Green

    $index = New-DeviceIndex $devices
    $lookup = {
        param($DeviceId, $ObjectId, $DisplayName)
        $search = if ($DeviceId) { $DeviceId } elseif ($ObjectId) { $ObjectId } else { $DisplayName }
        if (-not $search) { return $null }
        try {
            $found = @(Find-Devices $search)
        }
        catch {
            return $null
        }
        if ($DeviceId) {
            return ($found | Where-Object { $_.DeviceId -eq $DeviceId } | Select-Object -First 1)
        }
        if ($ObjectId) {
            return ($found | Where-Object { $_.ObjectId -eq $ObjectId } | Select-Object -First 1)
        }
        $exact = @($found | Where-Object { $_.DisplayName -eq $DisplayName })
        if ($exact.Count -eq 1) { return $exact[0] }
        return $null
    }

    $plan = ConvertTo-ObjectArray (New-BulkUpdatePlan -Rows $rows -DeviceIndex $index -ColumnMap $columnMap -FallbackValue $fallbackValue -SkipMissing $skipMissing -LookupMissingDevice $lookup)
    $planColumns = 'Row', 'Identifier', 'DisplayName', 'Current', 'New', 'Status', 'Note'
    $ready = @($plan | Where-Object { $_.Status -eq 'Ready' })

    while ($true) {
        Write-Title 'Preview'
        $plan | Select-Object -Property $planColumns | Format-Table -AutoSize -Wrap | Out-Host

        Write-Host 'Summary:' -ForegroundColor Cyan
        $plan | Group-Object Status | Sort-Object Name | ForEach-Object {
            $color = if ($_.Name -eq 'Ready') { 'Green' } elseif ($_.Name -in @('NoChange', 'Skipped')) { 'Gray' } else { 'Yellow' }
            Write-Host ('  {0,-12} {1}' -f $_.Name, $_.Count) -ForegroundColor $color
        }
        if ($script:Settings.DryRun) { Write-Host 'Dry-run mode is ON. No changes will be written.' -ForegroundColor Yellow }

        Write-Host ''
        Write-Host "  1) Apply $($ready.Count) change(s)"
        if (Test-GridViewAvailable) { Write-Host '  2) View preview in grid view' }
        Write-Host '  3) Export preview to CSV'
        Write-Host '  0) Cancel'

        switch (Read-Choice) {
            '1' {
                if ($ready.Count -eq 0) {
                    Write-Host 'There are no changes to apply.' -ForegroundColor Yellow
                    Wait-ForKey
                    return
                }
                $confirmation = ([string](Read-Host "Type YES to update $($ready.Count) device(s)")).Trim()
                if ($confirmation -cne 'YES') {
                    Write-Host 'Not confirmed. Nothing was changed.' -ForegroundColor Yellow
                    continue
                }

                $source  = 'CSV:' + [IO.Path]::GetFileName($path)
                $results = New-Object System.Collections.Generic.List[object]
                $indexNo = 0
                try {
                    foreach ($item in $ready) {
                        $indexNo++
                        Write-Progress -Activity 'Updating extensionAttribute1' -Status "$indexNo of $($ready.Count): $($item.DisplayName)" -PercentComplete ([int](($indexNo / $ready.Count) * 100))
                        $results.Add((Set-DeviceExtensionAttribute -Device $item.Device -NewValue $item.NewValue -Source $source))
                    }
                }
                finally {
                    Write-Progress -Activity 'Updating extensionAttribute1' -Completed
                }

                $succeeded = @($results | Where-Object { $_.Status -eq 'Success' }).Count
                $dryRuns   = @($results | Where-Object { $_.Status -eq 'DryRun' }).Count
                $failed    = @($results | Where-Object { $_.Status -eq 'Failed' })

                Write-Host ''
                Write-Host "Succeeded: $succeeded" -ForegroundColor Green
                if ($dryRuns -gt 0) { Write-Host "Dry-run  : $dryRuns" -ForegroundColor Yellow }
                $failedColor = if ($failed.Count -gt 0) { 'Red' } else { 'Green' }
                Write-Host "Failed   : $($failed.Count)" -ForegroundColor $failedColor
                if ($failed.Count -gt 0) {
                    $failed | Format-Table DisplayName, DeviceId, Message -AutoSize -Wrap | Out-Host
                }
                Write-Host "Audit log: $($script:Settings.LogPath)"
                Wait-ForKey
                return
            }
            '2' {
                if (Test-GridViewAvailable) {
                    $plan | Select-Object -Property $planColumns | Out-GridView -Title 'Bulk update preview'
                }
                else {
                    Write-Host 'Out-GridView is not available in this session.' -ForegroundColor Yellow
                }
            }
            '3' {
                $defaultPath = Join-Path $script:Root ('CAExemption-Preview_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
                $previewPath = ([string](Read-Host "Save to [$defaultPath]")).Trim().Trim('"')
                if (-not $previewPath) { $previewPath = $defaultPath }
                try {
                    $folder = Split-Path -Parent $previewPath
                    if ($folder -and -not (Test-Path -LiteralPath $folder)) {
                        New-Item -ItemType Directory -Path $folder -Force | Out-Null
                    }
                    $plan | Select-Object -Property $planColumns | Export-Csv -Path $previewPath -NoTypeInformation -Encoding UTF8
                    Write-Host "Exported to $previewPath" -ForegroundColor Green
                }
                catch {
                    Write-Host "Export failed: $($_.Exception.Message)" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '0' {
                Write-Host 'Cancelled. Nothing was changed.' -ForegroundColor Yellow
                Wait-ForKey
                return
            }
            default { Write-Host 'Invalid choice.' -ForegroundColor Yellow }
        }
    }
}

function Read-UserSearchTokens {
    Write-Host 'Enter users as UPN, email, display name or object ID.'
    Write-Host 'Separate with commas or semicolons. Enter a blank line when finished.'
    $lines = New-Object System.Collections.Generic.List[string]
    while ($true) {
        $line = ([string](Read-Host '>')).Trim()
        if (-not $line) { break }
        $lines.Add($line)
    }
    return @(Split-UserSearchTokens ($lines -join ','))
}

function Resolve-UsersFromTokens {
    param([string[]]$Tokens)

    $resolved = New-Object System.Collections.Generic.List[object]
    $missing = New-Object System.Collections.Generic.List[string]
    $seen = @{}

    foreach ($token in @($Tokens)) {
        if ([string]::IsNullOrWhiteSpace($token)) { continue }
        try {
            $matches = @(Find-Users $token)
        }
        catch {
            Write-Host "Lookup failed for '$token': $(Get-GraphErrorMessage $_)" -ForegroundColor Red
            $missing.Add($token)
            continue
        }

        if ($matches.Count -eq 0) {
            Write-Host "No user found for '$token'." -ForegroundColor Yellow
            $missing.Add($token)
            continue
        }

        $user = $null
        if ($matches.Count -eq 1) {
            $user = $matches[0]
        }
        else {
            Write-Host "'$token' matched $($matches.Count) users. Choose one, or skip." -ForegroundColor Yellow
            $user = Select-UserFromList $matches
        }

        if ($null -eq $user) { continue }
        if ($user.ObjectId -and $seen.ContainsKey($user.ObjectId)) { continue }
        if ($user.ObjectId) { $seen[$user.ObjectId] = $true }
        $resolved.Add($user)
        Write-Host ("  {0} <{1}>" -f $user.DisplayName, $user.UserPrincipalName) -ForegroundColor Green
    }

    return (New-ToolObject @(
            'Users', $resolved.ToArray()
            'Missing', $missing.ToArray()
        ))
}

function Invoke-UserDeviceCsvExport {
    Write-Title 'Find Windows devices by user'

    Write-Host 'Look up users, collect their Windows registered/owned devices,'
    Write-Host 'and export a CSV that menu option 3 can apply directly.'
    Write-Host ''
    Write-Host '  1) Type users (UPN, email, name or object ID)'
    Write-Host '  2) Load users from a CSV'
    Write-Host '  3) Export a user-list CSV template'
    Write-Host '  0) Cancel'

    $tokens = @()
    switch (Read-Choice 'Choose') {
        '1' { $tokens = @(Read-UserSearchTokens) }
        '2' {
            $userCsvPath = Select-CsvPath
            if (-not $userCsvPath) { return }
            if (-not (Test-Path -LiteralPath $userCsvPath -PathType Leaf)) {
                Write-Host "File not found: $userCsvPath" -ForegroundColor Red
                Wait-ForKey
                return
            }
            try {
                $userRows = @(Import-DeviceCsv -Path $userCsvPath)
            }
            catch {
                Write-Host "Could not read CSV: $($_.Exception.Message)" -ForegroundColor Red
                Wait-ForKey
                return
            }
            if ($userRows.Count -eq 0) {
                Write-Host 'The CSV has no data rows.' -ForegroundColor Yellow
                Wait-ForKey
                return
            }
            $headers = @($userRows[0].PSObject.Properties | ForEach-Object { $_.Name })
            $userMap = Resolve-UserCsvColumnMap $headers
            if ($userMap.Count -eq 0) {
                Write-Host 'The CSV needs a UserPrincipalName, Mail, DisplayName or ObjectId column (or an alias such as UPN / Email).' -ForegroundColor Red
                Write-Host "Columns found: $($headers -join ', ')" -ForegroundColor Red
                Wait-ForKey
                return
            }
            foreach ($row in $userRows) {
                $token = Get-UserRowSearchToken $row $userMap
                if ($token) { $tokens += $token }
            }
            Write-Host "Loaded $($tokens.Count) user identifier(s) from $userCsvPath" -ForegroundColor Green
        }
        '3' {
            $defaultPath = Join-Path $script:Root 'CAExemption-Users-Template.csv'
            $path = ([string](Read-Host "Save template to [$defaultPath]")).Trim().Trim('"')
            if (-not $path) { $path = $defaultPath }
            $template = @(
                [pscustomobject]@{ UserPrincipalName = 'jane.doe@contoso.com'; DisplayName = ''; ObjectId = ''; Mail = '' }
                [pscustomobject]@{ UserPrincipalName = ''; DisplayName = 'Alex Smith'; ObjectId = ''; Mail = '' }
            )
            try {
                $folder = Split-Path -Parent $path
                if ($folder -and -not (Test-Path -LiteralPath $folder)) {
                    New-Item -ItemType Directory -Path $folder -Force | Out-Null
                }
                $template | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
                Write-Host "Template saved to $path" -ForegroundColor Green
            }
            catch {
                Write-Host "Could not save template: $($_.Exception.Message)" -ForegroundColor Red
            }
            Wait-ForKey
            return
        }
        default { return }
    }

    $tokens = @(Split-UserSearchTokens ($tokens -join ','))
    if ($tokens.Count -eq 0) {
        Write-Host 'No users were entered.' -ForegroundColor Yellow
        Wait-ForKey
        return
    }

    Write-Host ''
    Write-Host "Resolving $($tokens.Count) user identifier(s)..."
    $resolved = Resolve-UsersFromTokens -Tokens $tokens
    if ($resolved.Users.Count -eq 0) {
        Write-Host 'No users were resolved.' -ForegroundColor Yellow
        Wait-ForKey
        return
    }
    if ($resolved.Missing.Count -gt 0) {
        Write-Host ("Not found: {0}" -f ($resolved.Missing -join ', ')) -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host "Retrieving Windows devices registered to or owned by $($resolved.Users.Count) user(s)..."
    $pairs = New-Object System.Collections.Generic.List[object]
    foreach ($user in (ConvertTo-ObjectArray $resolved.Users)) {
        try {
            foreach ($pair in (ConvertTo-ObjectArray (Get-UserRelatedWindowsDevices $user))) {
                $pairs.Add($pair)
            }
        }
        catch {
            Write-Host "Failed to get devices for $($user.UserPrincipalName): $(Format-CaughtError $_)" -ForegroundColor Red
        }
    }

    if ($pairs.Count -eq 0) {
        Write-Host 'No Windows devices were found for those users.' -ForegroundColor Yellow
        Wait-ForKey
        return
    }

    $choice = Read-ValueChoice 'What should the exported CSV set extensionAttribute1 to?'
    if ($null -eq $choice) {
        Write-Host 'Cancelled.' -ForegroundColor Yellow
        Wait-ForKey
        return
    }
    $exportAction = if ([string]::IsNullOrEmpty($choice.Value)) { 'Clear' } else { 'Set' }

    $rawRows = New-Object System.Collections.Generic.List[object]
    foreach ($pair in (ConvertTo-ObjectArray $pairs)) {
        $rawRows.Add((New-UserDeviceBulkRow -Device $pair.Device -User $pair.User -Relationship $pair.Relationship -Value $choice.Value -Action $exportAction))
    }
    $rows = ConvertTo-ObjectArray (Merge-UserDeviceBulkRows (ConvertTo-ObjectArray $rawRows))
    $eligible = ConvertTo-ObjectArray ($rows | Where-Object { $_.Eligible })
    $ineligible = ConvertTo-ObjectArray ($rows | Where-Object { -not $_.Eligible })

    Write-Host ''
    Write-Host "Found $($rows.Count) Windows device(s) for $($resolved.Users.Count) user(s)." -ForegroundColor Green
    Write-Host "  $($eligible.Count) are eligible to change with the current device scope."
    if ($ineligible.Count -gt 0) {
        Write-Host "  $($ineligible.Count) are Windows but not eligible (join type / settings)." -ForegroundColor Yellow
    }

    $exportRows = $eligible
    if ($ineligible.Count -gt 0 -and (Read-YesNo 'Include ineligible Windows devices in the CSV as well?' $false)) {
        $exportRows = $rows
    }
    if ($exportRows.Count -eq 0) {
        Write-Host 'Nothing to export. Turn off "Registered only" in Settings if you want Entra joined / hybrid devices included.' -ForegroundColor Yellow
        Wait-ForKey
        return
    }

    $previewColumns = 'DisplayName', 'DeviceId', 'UserPrincipalName', 'Relationship', 'JoinType', 'CurrentExtensionAttribute1', 'Value', 'Action', 'Eligible'
    while ($true) {
        Write-Title 'User device CSV preview'
        $exportRows | Select-Object -Property $previewColumns | Format-Table -AutoSize -Wrap | Out-Host

        Write-Host "  1) Export $($exportRows.Count) row(s) for bulk update"
        if (Test-GridViewAvailable) { Write-Host '  2) Open preview in grid view' }
        Write-Host '  0) Cancel'

        switch (Read-Choice) {
            '1' {
                $defaultPath = Join-Path $script:Root ('CAExemption-UserDevices_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
                $path = ([string](Read-Host "Save to [$defaultPath]")).Trim().Trim('"')
                if (-not $path) { $path = $defaultPath }
                try {
                    $folder = Split-Path -Parent $path
                    if ($folder -and -not (Test-Path -LiteralPath $folder)) {
                        New-Item -ItemType Directory -Path $folder -Force | Out-Null
                    }
                    $exportRows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
                    Write-Host "Exported to $path" -ForegroundColor Green
                    Write-Host 'Columns DeviceId, ObjectId, DisplayName, Value and Action can be fed straight into bulk update.'
                }
                catch {
                    Write-Host "Export failed: $($_.Exception.Message)" -ForegroundColor Red
                    Wait-ForKey
                    return
                }
                if (Read-YesNo 'Run bulk update from this CSV now?' $true) {
                    Invoke-BulkUpdate -Path $path
                }
                else {
                    Wait-ForKey
                }
                return
            }
            '2' {
                if (Test-GridViewAvailable) {
                    $exportRows | Select-Object -Property $previewColumns | Out-GridView -Title 'Windows devices by user'
                }
                else {
                    Write-Host 'Out-GridView is not available in this session.' -ForegroundColor Yellow
                }
            }
            '0' { return }
            default { Write-Host 'Invalid choice.' -ForegroundColor Yellow }
        }
    }
}

function Export-CsvTemplate {
    Write-Title 'Export CSV template'

    $defaultPath = Join-Path $script:Root 'CAExemption-Template.csv'
    $path = ([string](Read-Host "Save template to [$defaultPath]")).Trim().Trim('"')
    if (-not $path) { $path = $defaultPath }

    $template = @(
        [pscustomobject]@{ DeviceId = '00000000-0000-0000-0000-000000000000'; ObjectId = ''; DisplayName = ''; Value = $script:Settings.DefaultValue; Action = 'Set' }
        [pscustomobject]@{ DeviceId = ''; ObjectId = ''; DisplayName = 'DEVICE-NAME-01'; Value = $script:Settings.DefaultValue; Action = 'Set' }
        [pscustomobject]@{ DeviceId = ''; ObjectId = ''; DisplayName = 'DEVICE-NAME-02'; Value = ''; Action = 'Clear' }
    )

    try {
        $folder = Split-Path -Parent $path
        if ($folder -and -not (Test-Path -LiteralPath $folder)) {
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
        }
        $template | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-Host "Template saved to $path" -ForegroundColor Green
        Write-Host 'Fill in one identifier per row (DeviceId is the most reliable). Replace the sample rows before use.'
        Write-Host 'Aliases such as Name, ComputerName, Device ID and Operation are also accepted.'
    }
    catch {
        Write-Host "Could not save template: $($_.Exception.Message)" -ForegroundColor Red
    }
    Wait-ForKey
}

function Show-ConditionalAccessHelp {
    Write-Title 'Conditional Access device filter'
    $value = $script:Settings.DefaultValue
    Write-Host 'Use this when you want a CA policy to skip (or include) devices that this tool tagged.'
    Write-Host ''
    Write-Host 'Azure portal: Conditional Access > policy > Conditions > Filter for devices'
    Write-Host ''
    Write-Host 'Exclude tagged Windows Entra registered devices:' -ForegroundColor Cyan
    Write-Host "  device.extensionAttribute1 -eq `"$value`""
    Write-Host '  AND device.trustType -eq "AzureADRegistered"'
    Write-Host ''
    Write-Host 'Notes:' -ForegroundColor Cyan
    Write-Host '  - The extensionAttribute1 comparison is case-sensitive in CA. Keep the stored value and the filter identical.'
    Write-Host '  - Graph trustType Workplace = CA trustType AzureADRegistered (Entra registered / workplace join).'
    Write-Host '  - Graph AzureAd = CA AzureADJoined. Graph ServerAd = CA ServerADJoined.'
    Write-Host '  - extensionAttribute1 lives in the cloud. It is not synced from on-premises Active Directory.'
    Write-Host ("  - Required Graph permissions: {0}" -f ($script:RequiredScopes -join ', '))
    Write-Host '  - Entra roles that can write device attributes: Cloud Device Administrator, Intune Administrator, Global Administrator.'
    Wait-ForKey
}

function Show-SettingsMenu {
    while ($true) {
        Write-Title 'Settings'
        $dryRunText = if ($script:Settings.DryRun) { 'ON' } else { 'Off' }
        $registeredText = if ($script:Settings.RegisteredOnly) { 'Windows Entra registered only' } else { 'All Windows devices' }
        Write-Host "  1) Default value : $($script:Settings.DefaultValue)"
        Write-Host "  2) Dry-run mode  : $dryRunText"
        Write-Host "  3) Audit log     : $($script:Settings.LogPath)"
        Write-Host "  4) Device scope  : $registeredText"
        Write-Host '  0) Back'

        switch (Read-Choice) {
            '1' {
                $value = [string](Read-Host 'New default value')
                if (Test-ValidValue $value) {
                    $script:Settings.DefaultValue = $value.Trim()
                    Export-ToolSettings
                    Write-Host "Default value set to '$($script:Settings.DefaultValue)'." -ForegroundColor Green
                }
            }
            '2' {
                $script:Settings.DryRun = -not $script:Settings.DryRun
                Export-ToolSettings
                $state = if ($script:Settings.DryRun) { 'ON. No changes will be written.' } else { 'Off. Changes will be written.' }
                Write-Host "Dry-run mode is $state" -ForegroundColor Yellow
            }
            '3' {
                $logPath = ([string](Read-Host 'New audit log path')).Trim().Trim('"')
                if ($logPath) {
                    try {
                        $folder = Split-Path -Parent $logPath
                        if ($folder -and -not (Test-Path -LiteralPath $folder)) {
                            New-Item -ItemType Directory -Path $folder -Force | Out-Null
                        }
                        $script:Settings.LogPath = $logPath
                        Export-ToolSettings
                        Write-Host "Audit log set to $logPath" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "Could not use that path: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
            '4' {
                $script:Settings.RegisteredOnly = -not $script:Settings.RegisteredOnly
                Export-ToolSettings
                $state = if ($script:Settings.RegisteredOnly) { 'Windows Entra registered devices only.' } else { 'all Windows devices (registered, Entra joined and hybrid).' }
                Write-Host "Device scope is now $state" -ForegroundColor Yellow
            }
            '0' { return }
            default { Write-Host 'Invalid choice.' -ForegroundColor Yellow }
        }
    }
}

function Show-MainMenu {
    while ($true) {
        Clear-Host
        Write-Title 'Entra ID device extensionAttribute1 - Conditional Access exemption tool'

        $context = $null
        try { $context = Get-MgContext } catch { }
        Write-Host "  Tool version  : $($script:ToolVersion)"
        if ($context) {
            Write-Host "  Signed in     : $($context.Account)"
            Write-Host "  Tenant        : $($context.TenantId)"
        }
        else {
            Write-Host '  Signed in     : Not connected' -ForegroundColor Yellow
        }
        Write-Host "  Default value : $($script:Settings.DefaultValue)"
        if ($script:Settings.DryRun) {
            Write-Host '  Dry-run mode  : ON (no changes will be written)' -ForegroundColor Yellow
        }
        else {
            Write-Host '  Dry-run mode  : Off'
        }
        $scopeText = if ($script:Settings.RegisteredOnly) { 'Windows Entra registered' } else { 'All Windows devices' }
        Write-Host "  Device scope  : $scopeText"
        Write-Host "  Audit log     : $($script:Settings.LogPath)"
        Write-Host ''
        Write-Host '  1) List Windows devices'
        Write-Host '  2) Add, modify or clear the value on one device'
        Write-Host '  3) Bulk update devices from a CSV'
        Write-Host '  4) Find Windows devices by user and export a bulk-update CSV'
        Write-Host '  5) Export a CSV template'
        Write-Host '  6) Settings (default value, dry-run, log path, device scope)'
        Write-Host '  7) Connect or switch tenant'
        Write-Host '  8) Conditional Access filter help'
        Write-Host '  Q) Quit'
        Write-Host ''

        switch (Read-Choice) {
            '1' { if (Connect-Graph) { Show-DeviceList } else { Wait-ForKey } }
            '2' { if (Connect-Graph) { Invoke-SingleDeviceUpdate } else { Wait-ForKey } }
            '3' { if (Connect-Graph) { Invoke-BulkUpdate } else { Wait-ForKey } }
            '4' { if (Connect-Graph) { Invoke-UserDeviceCsvExport } else { Wait-ForKey } }
            '5' { Export-CsvTemplate }
            '6' { Show-SettingsMenu }
            '7' { [void](Connect-Graph -Reconnect); Wait-ForKey }
            '8' { Show-ConditionalAccessHelp }
            'Q' { return }
            default { Write-Host 'Invalid choice.' -ForegroundColor Yellow; Start-Sleep -Milliseconds 600 }
        }
    }
}

function Start-CAExemptionTool {
    $savedEap = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try {
        Import-ToolSettings
        if (-not (Initialize-GraphModule)) {
            Write-Host 'Cannot continue without the Microsoft.Graph.Authentication module.' -ForegroundColor Red
            return
        }

        Show-MainMenu

        if (Get-MgContext) {
            if (Read-YesNo 'Disconnect from Microsoft Graph?' $true) {
                try { Disconnect-MgGraph | Out-Null } catch { }
                Write-Host 'Disconnected.'
            }
        }
    }
    finally {
        $ErrorActionPreference = $savedEap
    }
}

#endregion

if (-not $SkipMain) {
    Start-CAExemptionTool
}

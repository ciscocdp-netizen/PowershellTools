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
      4. Export a CSV template
      5. Settings: default value, dry-run mode, audit log path, registered-only filter
      6. Connect or switch tenant
      7. Conditional Access filter help

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
      - Delegated Graph permission: Device.ReadWrite.All (admin consent required)
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

$script:Root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:SettingsFile = if ($SettingsPath) { $SettingsPath } else { Join-Path $script:Root 'CAExemption.settings.json' }
$script:RequiredScope = 'Device.ReadWrite.All'
$script:GraphBase     = 'https://graph.microsoft.com/v1.0/devices'
$script:SelectFields  = 'id,deviceId,displayName,trustType,operatingSystem,operatingSystemVersion,accountEnabled,approximateLastSignInDateTime,extensionAttributes,isManagementRestricted'
$script:GuidPattern   = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
$script:MaxValueLength = 1024
$script:CsvColumnAliases = @{
    DeviceId    = @('DeviceId', 'Device ID', 'Device_Id', 'AzureDeviceId', 'azureADDeviceId', 'AzureAdDeviceId')
    ObjectId    = @('ObjectId', 'Object ID', 'Object_Id', 'ObjectID', 'EntraObjectId', 'id')
    DisplayName = @('DisplayName', 'Display Name', 'DeviceName', 'Device Name', 'Name', 'ComputerName', 'Computer')
    Value       = @('Value', 'ExtensionAttribute1', 'extensionAttribute1', 'Attribute', 'NewValue', 'EA1')
    Action      = @('Action', 'Operation')
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
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $trimmed = $Value.Trim().Trim('"').Trim('{}')
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

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $Object[$key]
            }
        }
        return $null
    }

    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
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
    return (Test-HasGraphScope $context)
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

    $params = @{ Scopes = @($script:RequiredScope) }
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
        Write-Host "Signed in, but $($script:RequiredScope) was not granted. An administrator may need to consent." -ForegroundColor Red
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
    if ($command.Parameters.ContainsKey('OutputType')) { $params['OutputType'] = 'HashTable' }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return Invoke-MgGraphRequest @params -ErrorAction Stop
        }
        catch {
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
        [hashtable]$Headers
    )

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    try {
        while ($next) {
            $request = @{ Method = 'GET'; Uri = $next }
            if ($Headers) { $request['Headers'] = $Headers }
            $response = Invoke-GraphRequestWithRetry @request
            foreach ($item in (Get-GraphCollection $response)) {
                $items.Add($item)
            }
            Write-Progress -Activity $Activity -Status "$($items.Count) retrieved"
            $next = Get-GraphProperty $response '@odata.nextLink'
        }
    }
    finally {
        Write-Progress -Activity $Activity -Completed
    }
    return $items.ToArray()
}

function Get-JoinTypeLabel {
    param([string]$TrustType)
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

    $record = [pscustomobject]@{
        DisplayName             = [string](Get-GraphProperty $Item 'displayName')
        DeviceId                = [string]$deviceId
        ObjectId                = [string]$objectId
        OperatingSystem         = $os
        OSVersion               = [string](Get-GraphProperty $Item 'operatingSystemVersion')
        TrustType               = $trust
        JoinType                = Get-JoinTypeLabel $trust
        Enabled                 = Get-GraphProperty $Item 'accountEnabled'
        LastSignIn              = Get-GraphProperty $Item 'approximateLastSignInDateTime'
        LastSignInDisplay       = Format-DateTimeDisplay (Get-GraphProperty $Item 'approximateLastSignInDateTime')
        ExtensionAttribute1     = $extensionAttribute1
        IsManagementRestricted  = Get-GraphProperty $Item 'isManagementRestricted'
        Eligible                = $false
    }
    $record.Eligible = Test-DeviceEligible $record
    return $record
}

function ConvertTo-DeviceRecords {
    param($Items)
    $records = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Items) { return $records.ToArray() }

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
        $records.Add((ConvertTo-DeviceRecord $item))
    }
    return $records.ToArray()
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
            $raw = Invoke-GraphGetAll -Uri $uri -Activity 'Retrieving Windows devices from Entra ID'
            $records = @(ConvertTo-DeviceRecords $raw | Where-Object { $_.Eligible } | Sort-Object DisplayName)
            return @($records)
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

function Get-RowAction {
    param($Row, $ColumnMap)
    $action = if ($ColumnMap) { Get-MappedRowField $Row $ColumnMap 'Action' } else { Get-RowField $Row 'Action' }
    if ($action -match '^(clear|remove|delete)$') { return 'Clear' }
    if ($action -eq '' -or $action -match '^(set|add|modify|update)$') { return 'Set' }
    return 'Invalid'
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

        $plan.Add([pscustomobject]@{
                Row         = $rowNumber
                Identifier  = $identifier
                DisplayName = $displayName
                Current     = $currentValue
                New         = $newDisplay
                Status      = $status
                Note        = $note
                Device      = $device
                NewValue    = $newValue
            })
    }

    return $plan.ToArray()
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

#endregion

#region Menu actions

function Show-DeviceList {
    Write-Title 'Windows Entra devices'

    try {
        $devices = @(Get-WindowsRegisteredDevices)
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
    Write-Title 'Bulk update from CSV'

    $path = Select-CsvPath
    if (-not $path) { return }

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
    $scopeText = if ($script:Settings.RegisteredOnly) { 'Windows Entra registered' } else { 'Windows' }
    Write-Host "Retrieving $scopeText devices from Entra ID..."
    try {
        $devices = @(Get-WindowsRegisteredDevices)
    }
    catch {
        Write-Host "Failed to retrieve devices: $(Get-GraphErrorMessage $_)" -ForegroundColor Red
        Wait-ForKey
        return
    }

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

    $plan = @(New-BulkUpdatePlan -Rows $rows -DeviceIndex $index -ColumnMap $columnMap -FallbackValue $fallbackValue -SkipMissing $skipMissing -LookupMissingDevice $lookup)
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
    Write-Host "  - Required Graph permission: $($script:RequiredScope)"
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
        Write-Host '  4) Export a CSV template'
        Write-Host '  5) Settings (default value, dry-run, log path, device scope)'
        Write-Host '  6) Connect or switch tenant'
        Write-Host '  7) Conditional Access filter help'
        Write-Host '  Q) Quit'
        Write-Host ''

        switch (Read-Choice) {
            '1' { if (Connect-Graph) { Show-DeviceList } else { Wait-ForKey } }
            '2' { if (Connect-Graph) { Invoke-SingleDeviceUpdate } else { Wait-ForKey } }
            '3' { if (Connect-Graph) { Invoke-BulkUpdate } else { Wait-ForKey } }
            '4' { Export-CsvTemplate }
            '5' { Show-SettingsMenu }
            '6' { [void](Connect-Graph -Reconnect); Wait-ForKey }
            '7' { Show-ConditionalAccessHelp }
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

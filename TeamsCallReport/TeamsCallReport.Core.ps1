# Teams call-record export engine.
# Dot-source this file. It has no top-level side effects.
#
# The original script failed in these ways:
#   * Participant endpoints identify the person on associatedIdentity. Reading only
#     .identity left DisplayName, UPN, and tenant blank on every media row.
#   * Casting a missing endDateTime with [datetime] throws on PowerShell 7 and
#     becomes year 0001 on Windows PowerShell 5.1, and that cast sat outside the
#     per-call try/catch so one bad record aborted the export.
#   * Invoke-MgGraphRequest hides HTTP status on failure, so 429/5xx retries never
#     ran and Retry-After was ignored. On Windows PowerShell 5.1 it also re-encodes
#     an already escaped $filter and @odata.nextLink, which drops later pages.
#   * ConvertTo-Json rewrote the saved payload, so RawJson was not the Graph body.
#   * Tenant comparison was case-sensitive, so the home tenant was treated as external.
#   * Lookup accepted only an object id or UPN, not mail or proxy addresses.
#   * Windows PowerShell 5.1 ConvertFrom-Json unwraps a one-element JSON array.
#   * App-only tokens often expose only ".default" on Get-MgContext, not the roles.

Set-StrictMode -Off

function ConvertTo-Base64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    return ([Convert]::ToBase64String($Bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url {
    param([Parameter(Mandatory)][string]$Text)
    $padded = $Text.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) {
        2 { $padded += '==' }
        3 { $padded += '=' }
        1 { throw 'The token fragment is not valid base64url.' }
    }
    return [Convert]::FromBase64String($padded)
}

function ConvertTo-NullableString {
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text
}

function ConvertTo-StringArray {
    param($Value)
    $list = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Value) { return ,@() }
    if ($Value -is [string]) {
        if (-not [string]::IsNullOrWhiteSpace($Value)) { $list.Add($Value) }
        return ,$list.ToArray()
    }
    foreach ($item in $Value) {
        $text = ConvertTo-NullableString $item
        if ($text) { $list.Add($text) }
    }
    return ,$list.ToArray()
}

function Get-ObjectList {
    param($Value)
    $list = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Value) {
        $isScalar = $Value -is [string] -or $Value -is [System.Collections.IDictionary] -or $Value -is [System.Management.Automation.PSCustomObject]
        if ($isScalar) {
            $list.Add($Value)
        }
        elseif ($Value -is [System.Collections.IEnumerable]) {
            foreach ($item in $Value) {
                if ($null -ne $item) { $list.Add($item) }
            }
        }
        else {
            $list.Add($Value)
        }
    }
    # A PSCustomObject survives function return. The list stays a list: an object[]
    # property unwraps when it has one element, and returning the list itself unrolls.
    return [pscustomobject]@{ Items = $list }
}

function ConvertTo-JsonSafe {
    param($Value, [int]$Depth = 20)
    if ($Depth -lt 0) { return 'null' }
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) {
        return (ConvertTo-Json -InputObject $Value -Compress -Depth 1)
    }
    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }
    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) {
        $utc = ConvertTo-UtcString $Value
        if ($null -eq $utc) { return 'null' }
        return (ConvertTo-Json -InputObject $utc -Compress -Depth 1)
    }
    if ($Value -is [enum]) {
        return (ConvertTo-Json -InputObject ([string]$Value) -Compress -Depth 1)
    }
    $isNumber = $Value -is [byte] -or $Value -is [int16] -or $Value -is [int] -or $Value -is [int64] -or $Value -is [long] -or
        $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64] -or
        $Value -is [decimal] -or $Value -is [single] -or $Value -is [double]
    if ($isNumber) {
        return [System.Convert]::ToString($Value, [cultureinfo]::InvariantCulture)
    }
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [System.Management.Automation.PSCustomObject]) {
        $props = New-Object System.Collections.Generic.List[string]
        if ($Value -is [System.Collections.IDictionary]) {
            foreach ($key in @($Value.Keys)) {
                $name = ConvertTo-Json -InputObject ([string]$key) -Compress -Depth 1
                $props.Add($name + ':' + (ConvertTo-JsonSafe -Value $Value[$key] -Depth ($Depth - 1)))
            }
        }
        else {
            foreach ($prop in $Value.PSObject.Properties) {
                $name = ConvertTo-Json -InputObject ([string]$prop.Name) -Compress -Depth 1
                $props.Add($name + ':' + (ConvertTo-JsonSafe -Value $prop.Value -Depth ($Depth - 1)))
            }
        }
        return '{' + [string]::Join(',', $props.ToArray()) + '}'
    }
    if (($Value -is [System.Collections.IEnumerable]) -and ($Value -isnot [string])) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($item in $Value) {
            $parts.Add((ConvertTo-JsonSafe -Value $item -Depth ($Depth - 1)))
        }
        return '[' + [string]::Join(',', $parts.ToArray()) + ']'
    }
    return (ConvertTo-Json -InputObject ([string]$Value) -Compress -Depth 1)
}

function ConvertTo-DateTimeOffset {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetimeoffset]) { return $Value }
    if ($Value -is [datetime]) {
        if ($Value.Year -lt 1900) { return $null }
        return [datetimeoffset]$Value
    }
    $text = ConvertTo-NullableString $Value
    if (-not $text) { return $null }
    try {
        return [datetimeoffset]::Parse(
            $text,
            [cultureinfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind)
    }
    catch {
        return $null
    }
}

function ConvertTo-UtcString {
    param($Value)
    $dto = ConvertTo-DateTimeOffset $Value
    if ($null -eq $dto) { return $null }
    return $dto.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Get-DurationSeconds {
    param($Start, $End)
    $startDto = ConvertTo-DateTimeOffset $Start
    $endDto = ConvertTo-DateTimeOffset $End
    if ($null -eq $startDto -or $null -eq $endDto) { return $null }
    $seconds = [math]::Round(($endDto - $startDto).TotalSeconds, 0)
    if ($seconds -lt 0) { return $null }
    return [int]$seconds
}

function Get-TeamsCallWindow {
    param(
        $StartDate,
        $EndDate,
        $Now = ([datetimeoffset]::UtcNow)
    )
    $start = ConvertTo-DateTimeOffset $StartDate
    $end = ConvertTo-DateTimeOffset $EndDate
    if ($null -eq $start -or $null -eq $end) { throw 'Start and end dates are required.' }
    $start = $start.ToUniversalTime()
    $end = $end.ToUniversalTime()
    if ($end -le $start) { throw 'End date must be after the start date.' }
    $floor = $Now.ToUniversalTime().AddDays(-30)
    $clamped = $false
    if ($start -lt $floor) {
        $start = $floor
        $clamped = $true
    }
    if ($start -ge $end) {
        throw 'That range is entirely older than the 30-day call record retention window.'
    }
    return [pscustomobject]@{
        Start   = $start
        End     = $end
        Floor   = $floor
        Clamped = [bool]$clamped
    }
}

function Test-SameId {
    param($Left, $Right)
    $a = ConvertTo-NullableString $Left
    $b = ConvertTo-NullableString $Right
    if (-not $a -or -not $b) { return $false }
    return $a.Trim().Equals($b.Trim(), [StringComparison]::OrdinalIgnoreCase)
}

function Test-TeamsGuid {
    param([string]$Value)
    $text = ConvertTo-NullableString $Value
    if (-not $text) { return $false }
    return $text -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
}

function Format-FlatScalar {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) { return ConvertTo-UtcString $Value }
    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }
    $isNumber = $Value -is [byte] -or $Value -is [int16] -or $Value -is [int] -or $Value -is [int64] -or $Value -is [long] -or
        $Value -is [decimal] -or $Value -is [single] -or $Value -is [double]
    if ($isNumber) {
        return [System.Convert]::ToString($Value, [cultureinfo]::InvariantCulture)
    }
    return [string]$Value
}

function Add-FlatObject {
    param($InputObject, [string]$Prefix, $Target)
    if ($null -eq $InputObject -or [string]::IsNullOrWhiteSpace($Prefix)) { return }
    if ($InputObject -is [string] -or ($InputObject -is [ValueType] -and $InputObject -isnot [enum])) {
        $scalar = Format-FlatScalar $InputObject
        if (-not [string]::IsNullOrWhiteSpace([string]$scalar)) { $Target[$Prefix] = $scalar }
        return
    }
    if ($InputObject -is [System.Collections.IDictionary] -or $InputObject -is [System.Management.Automation.PSCustomObject]) {
        $wrote = $false
        $props = @()
        if ($InputObject -is [System.Collections.IDictionary]) {
            foreach ($key in @($InputObject.Keys)) { $props += [pscustomobject]@{ Name = [string]$key; Value = $InputObject[$key] } }
        }
        else {
            $props = @($InputObject.PSObject.Properties)
        }
        foreach ($prop in $props) {
            if ($prop.Name -like '*@odata*') { continue }
            if ($null -eq $prop.Value) { continue }
            Add-FlatObject -InputObject $prop.Value -Prefix ("$Prefix.$($prop.Name)") -Target $Target
            $wrote = $true
        }
        if (-not $wrote) { return }
        return
    }
    if (($InputObject -is [System.Collections.IEnumerable]) -and ($InputObject -isnot [string])) {
        $json = ConvertTo-JsonSafe $InputObject
        if ($json -and $json -ne '[]' -and $json -ne 'null') { $Target[$Prefix] = $json }
    }
}

function Format-CsvField {
    param($Value)
    if ($null -eq $Value) { return '""' }
    if ($Value -is [bool]) {
        if ($Value) { $text = 'true' } else { $text = 'false' }
    }
    elseif ($Value -is [datetime] -or $Value -is [datetimeoffset]) {
        $text = ConvertTo-UtcString $Value
        if ($null -eq $text) { return '""' }
    }
    else {
        $isNumber = $Value -is [byte] -or $Value -is [int16] -or $Value -is [int] -or $Value -is [int64] -or $Value -is [long] -or
            $Value -is [decimal] -or $Value -is [single] -or $Value -is [double]
        if ($isNumber) { $text = [System.Convert]::ToString($Value, [cultureinfo]::InvariantCulture) }
        else { $text = [string]$Value }
    }
    if ($null -eq $text) { return '""' }
    if ($text -match '^[=@\t\r]') { $text = "'" + $text }
    elseif ($text -match '^[+-]' -and $text -notmatch '^[+-]?(\d+(\.\d+)?|\.\d+)([eE][+-]?\d+)?$') {
        $text = "'" + $text
    }
    return '"' + $text.Replace('"', '""') + '"'
}

function Get-UnionColumns {
    param($Rows)
    $columns = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($row in (Get-ObjectList $Rows).Items) {
        if ($null -eq $row) { continue }
        $keys = @()
        if ($row -is [System.Collections.IDictionary]) { $keys = @($row.Keys) }
        else { foreach ($prop in $row.PSObject.Properties) { $keys += $prop.Name } }
        foreach ($key in $keys) {
            $name = [string]$key
            if ($seen.Add($name)) { $columns.Add($name) }
        }
    }
    return ,$columns.ToArray()
}

function Export-UnionCsv {
    param($Rows, [Parameter(Mandatory)][string]$Path)
    $list = (Get-ObjectList $Rows).Items
    if ($list.Count -eq 0) { return }
    # Direct assignment keeps the comma-returned array. @(...) would nest it.
    $columns = Get-UnionColumns $list
    $sb = New-Object System.Text.StringBuilder
    $header = New-Object System.Collections.Generic.List[string]
    foreach ($col in $columns) { $header.Add((Format-CsvField $col)) }
    [void]$sb.AppendLine([string]::Join(',', $header.ToArray()))
    foreach ($row in $list) {
        $fields = New-Object System.Collections.Generic.List[string]
        foreach ($col in $columns) {
            $val = $null
            if ($row -is [System.Collections.IDictionary]) {
                if ($row.Contains($col)) { $val = $row[$col] }
            }
            elseif ($row.PSObject.Properties[$col]) {
                $val = $row.PSObject.Properties[$col].Value
            }
            $fields.Add((Format-CsvField $val))
        }
        [void]$sb.AppendLine([string]::Join(',', $fields.ToArray()))
    }
    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $encoding = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), $encoding)
}

function ConvertTo-ReportDataTable {
    param($Rows, [string]$Name = 'Report')
    $table = New-Object System.Data.DataTable $Name
    $list = (Get-ObjectList $Rows).Items
    # Direct assignment keeps the comma-returned array. @(...) would nest it.
    $columns = Get-UnionColumns $list
    $numeric = @{
        DurationSeconds  = [int]
        ParticipantCount = [int]
        SessionCount     = [int]
        SegmentCount     = [int]
    }
    [void]$table.Columns.Add('SearchBlob', [string])
    foreach ($col in $columns) {
        if ($col -eq 'SearchBlob') { continue }
        $type = [string]
        if ($numeric.ContainsKey($col)) { $type = $numeric[$col] }
        [void]$table.Columns.Add([string]$col, $type)
    }
    foreach ($row in $list) {
        $dataRow = $table.NewRow()
        $blob = New-Object System.Text.StringBuilder
        foreach ($col in $columns) {
            if (-not $table.Columns.Contains($col)) { continue }
            $val = $null
            if ($row -is [System.Collections.IDictionary]) {
                if ($row.Contains($col)) { $val = $row[$col] }
            }
            if ($null -eq $val -or [string]::IsNullOrWhiteSpace([string]$val)) {
                if ($numeric.ContainsKey($col)) { $dataRow[$col] = [DBNull]::Value }
                continue
            }
            if ($numeric.ContainsKey($col)) {
                $numberText = [string]$val
                if ($numberText -match '^-?\d+$') { $dataRow[$col] = [int]$numberText }
                else { $dataRow[$col] = [DBNull]::Value }
                [void]$blob.Append($numberText).Append(' ')
            }
            else {
                $text = Format-FlatScalar $val
                if ($null -eq $text) { $text = [string]$val }
                $dataRow[$col] = $text
                [void]$blob.Append($text).Append(' ')
            }
        }
        $dataRow['SearchBlob'] = $blob.ToString()
        [void]$table.Rows.Add($dataRow)
    }
    return ,$table
}

function Get-TeamsUserSelect {
    param([switch]$Core)
    if ($Core) {
        return @(
            'id', 'displayName', 'givenName', 'surname', 'userPrincipalName', 'mail',
            'jobTitle', 'department', 'companyName', 'officeLocation', 'employeeId',
            'accountEnabled', 'userType'
        ) -join ','
    }
    return @(
        'id', 'displayName', 'givenName', 'surname', 'userPrincipalName', 'mail', 'otherMails',
        'proxyAddresses', 'userType', 'accountEnabled', 'creationType', 'externalUserState',
        'createdDateTime', 'jobTitle', 'department', 'companyName', 'officeLocation', 'employeeId',
        'employeeType', 'streetAddress', 'city', 'state', 'postalCode', 'country', 'usageLocation',
        'preferredLanguage', 'businessPhones', 'mobilePhone', 'faxNumber', 'onPremisesSyncEnabled',
        'onPremisesSamAccountName', 'onPremisesUserPrincipalName', 'onPremisesDomainName',
        'onPremisesSecurityIdentifier', 'onPremisesImmutableId', 'onPremisesDistinguishedName'
    ) -join ','
}

function Get-TeamsUserFilter {
    param([Parameter(Mandatory)][string]$User, [switch]$NameOnly)
    $escaped = $User.Replace("'", "''")
    $basicFilter = "userPrincipalName eq '$escaped' or mail eq '$escaped' or displayName eq '$escaped'"
    if ($NameOnly) { return $basicFilter }
    $smtp = "smtp:$escaped"
    $smtpUpper = "SMTP:$escaped"
    return "$basicFilter or otherMails/any(m:m eq '$escaped') or proxyAddresses/any(p:p eq '$smtp') or proxyAddresses/any(p:p eq '$smtpUpper')"
}

function Format-GraphPath {
    param([Parameter(Mandatory)][string]$Path, [hashtable]$Query)
    $relative = $Path.TrimStart('/')
    if ($null -eq $Query -or $Query.Count -eq 0) { return $relative }
    $pairs = New-Object System.Collections.Generic.List[string]
    foreach ($key in @($Query.Keys)) {
        $pairs.Add(('{0}={1}' -f $key, [uri]::EscapeDataString([string]$Query[$key])))
    }
    return ($relative + '?' + [string]::Join('&', $pairs.ToArray()))
}

function Get-TeamsCloudConfig {
    param([string]$Cloud = 'Public')
    switch ($Cloud) {
        'USGov' {
            return [pscustomobject]@{
                Name      = 'USGov'
                LoginHost = 'login.microsoftonline.us'
                GraphHost = 'graph.microsoft.us'
                GraphBase = 'https://graph.microsoft.us/v1.0'
                Scope     = 'https://graph.microsoft.us/.default'
            }
        }
        'USGovDoD' {
            return [pscustomobject]@{
                Name      = 'USGovDoD'
                LoginHost = 'login.microsoftonline.us'
                GraphHost = 'dod-graph.microsoft.us'
                GraphBase = 'https://dod-graph.microsoft.us/v1.0'
                Scope     = 'https://dod-graph.microsoft.us/.default'
            }
        }
        default {
            return [pscustomobject]@{
                Name      = 'Public'
                LoginHost = 'login.microsoftonline.com'
                GraphHost = 'graph.microsoft.com'
                GraphBase = 'https://graph.microsoft.com/v1.0'
                Scope     = 'https://graph.microsoft.com/.default'
            }
        }
    }
}

function Initialize-TeamsTls {
    if ($script:TeamsCallReportTlsReady) { return }
    $script:TeamsCallReportTlsReady = $true
    try {
        $protocols = [Net.SecurityProtocolType]::Tls12
        if ([enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
            $protocols = $protocols -bor [Net.SecurityProtocolType]::Tls13
        }
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $protocols
    }
    catch { }
    try { [Net.ServicePointManager]::Expect100Continue = $false } catch { }
}

function Get-TeamsAbsoluteUri {
    param($Client, [string]$Uri)
    if ($Uri -match '^[a-zA-Z][a-zA-Z0-9+\.-]*://') { return $Uri }
    return ($Client.BaseUrl.TrimEnd('/') + '/' + $Uri.TrimStart('/'))
}

function Assert-TeamsAllowedHost {
    param($Client, [string]$AbsoluteUri, [string[]]$FallbackHosts)
    $hostName = ([Uri]$AbsoluteUri).IdnHost
    if ([string]::IsNullOrWhiteSpace($hostName)) { $hostName = ([Uri]$AbsoluteUri).Host }
    $allowed = @()
    if ($Client -and $Client.AllowedHosts) { $allowed = @($Client.AllowedHosts) }
    if ($allowed.Count -eq 0) { $allowed = @($FallbackHosts) }
    foreach ($candidate in $allowed) {
        if ($hostName.Equals([string]$candidate, [StringComparison]::OrdinalIgnoreCase)) { return }
    }
    throw "Refusing to send a token to unexpected host '$hostName'."
}

function Get-GraphErrorMessage {
    param($Raw, [int]$Status)
    if (-not [string]::IsNullOrWhiteSpace([string]$Raw)) {
        try {
            $parsed = $Raw | ConvertFrom-Json
            if ($parsed.error -and $parsed.error.message) { return [string]$parsed.error.message }
            if ($parsed.error_description) {
                return ([string]$parsed.error_description -split '\r?\n')[0]
            }
            if ($parsed.error -is [string]) { return [string]$parsed.error }
        }
        catch { }
        $text = [string]$Raw
        if ($text.Length -gt 500) { return $text.Substring(0, 500) }
        return $text
    }
    return "HTTP $Status"
}

function Get-TeamsRetryDelay {
    param($RetryAfter, [int]$Attempt)
    $seconds = $null
    $header = ConvertTo-NullableString $RetryAfter
    if ($header -match '^\d+$') {
        $seconds = [int]$header
    }
    elseif ($header) {
        try {
            $when = [datetimeoffset]::Parse($header, [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
            $seconds = [int][math]::Ceiling(($when.ToUniversalTime() - [datetimeoffset]::UtcNow).TotalSeconds)
        }
        catch { $seconds = $null }
    }
    if ($null -eq $seconds) { $seconds = [int][math]::Min(30, [math]::Pow(2, $Attempt)) }
    if ($seconds -lt 0) { $seconds = 0 }
    if ($seconds -gt 120) { $seconds = 120 }
    return $seconds
}

function Test-TeamsClientCancel {
    param($Client)
    if ($Client -and $Client.ShouldCancel) {
        $cancel = & $Client.ShouldCancel
        if ($cancel) { throw [System.OperationCanceledException]::new('Export cancelled.') }
    }
}

function Start-TeamsSleep {
    param($Client, [double]$Seconds)
    if ($Seconds -le 0) { return }
    $deadline = [datetime]::UtcNow.AddSeconds($Seconds)
    while ([datetime]::UtcNow -lt $deadline) {
        Test-TeamsClientCancel $Client
        Start-Sleep -Milliseconds 200
    }
}

function Write-TeamsClientLog {
    param($Client, [string]$Level, [string]$Message)
    if ($Client -and $Client.Log) {
        try { & $Client.Log $Level $Message } catch { }
    }
}

function Invoke-TeamsHttp {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET',
        [hashtable]$Headers,
        [string]$Body,
        [string]$ContentType = 'application/json',
        [int]$TimeoutSec = 100
    )
    Initialize-TeamsTls
    $request = [System.Net.HttpWebRequest]::Create($Uri)
    $request.Method = $Method
    $request.Accept = 'application/json'
    $request.UserAgent = 'TeamsCallReport/1.0'
    $request.AllowAutoRedirect = $false
    $request.Timeout = $TimeoutSec * 1000
    $request.ReadWriteTimeout = $TimeoutSec * 1000
    try {
        $request.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
    }
    catch { }
    if ($Headers) {
        foreach ($key in @($Headers.Keys)) {
            $name = [string]$key
            $headerValue = [string]$Headers[$key]
            if ($name -eq 'Accept') { $request.Accept = $headerValue; continue }
            if ($name -eq 'Content-Type') { $request.ContentType = $headerValue; continue }
            if ($name -eq 'User-Agent') { $request.UserAgent = $headerValue; continue }
            [void]$request.Headers.Set($name, $headerValue)
        }
    }
    if ($Body -and $Method -ne 'GET') {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
        $request.ContentType = $ContentType
        $request.ContentLength = $bytes.Length
        $stream = $request.GetRequestStream()
        try { $stream.Write($bytes, 0, $bytes.Length) }
        finally { $stream.Close() }
    }
    $response = $null
    try {
        try {
            $response = $request.GetResponse()
        }
        catch [System.Net.WebException] {
            if ($_.Exception.Response) { $response = $_.Exception.Response }
            else { throw }
        }
        $status = [int]$response.StatusCode
        $retry = $null
        try { $retry = $response.Headers['Retry-After'] } catch { $retry = $null }
        $reader = New-Object System.IO.StreamReader ($response.GetResponseStream())
        try { $raw = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
        return [pscustomobject]@{ StatusCode = $status; Raw = $raw; RetryAfter = $retry }
    }
    finally {
        if ($response) { $response.Close() }
    }
}

function ConvertFrom-SecureStringPlain {
    param([securestring]$Secure)
    if ($null -eq $Secure -or $Secure.Length -eq 0) { return $null }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-TeamsCertificatePrivateKey {
    param($Certificate)
    if ($null -eq $Certificate) { throw 'A certificate is required.' }
    # Reflection does not unwrap PowerShell's PSObject, so pass the raw certificate.
    $raw = $Certificate
    if ($raw -is [System.Management.Automation.PSObject]) { $raw = $raw.PSObject.BaseObject }
    $method = $raw.GetType().GetMethod('GetRSAPrivateKey')
    if ($method) {
        $key = $method.Invoke($raw, $null)
        if ($key) { return $key }
    }
    $extensionNames = @(
        'System.Security.Cryptography.X509Certificates.RSACertificateExtensions, System.Core',
        'System.Security.Cryptography.X509Certificates.RSACertificateExtensions'
    )
    $extensions = New-Object System.Collections.Generic.List[type]
    foreach ($typeName in $extensionNames) {
        $found = [Type]::GetType($typeName, $false)
        if ($found) { $extensions.Add($found) }
    }
    if ($extensions.Count -eq 0) {
        foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
            $found = $assembly.GetType('System.Security.Cryptography.X509Certificates.RSACertificateExtensions', $false)
            if ($found) { $extensions.Add($found); break }
        }
    }
    foreach ($extension in $extensions) {
        $getKey = $extension.GetMethod('GetRSAPrivateKey', [Type[]]@([System.Security.Cryptography.X509Certificates.X509Certificate2]))
        if (-not $getKey) { $getKey = $extension.GetMethod('GetRSAPrivateKey') }
        if (-not $getKey) { continue }
        $key = $getKey.Invoke($null, @($raw))
        if ($key) { return $key }
    }
    if ($raw.PrivateKey) { return $raw.PrivateKey }
    throw 'The certificate does not have an accessible RSA private key.'
}

function New-TeamsClientAssertion {
    param(
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$TokenEndpoint,
        [Parameter(Mandatory)]$Certificate
    )
    $now = [int64][math]::Floor(([datetimeoffset]::UtcNow.UtcDateTime - [datetime]'1970-01-01Z').TotalSeconds)
    $header = ConvertTo-JsonSafe ([ordered]@{
            alg = 'RS256'
            typ = 'JWT'
            x5t = (ConvertTo-Base64Url $Certificate.GetCertHash())
        })
    $payloadObject = [ordered]@{
        aud = $TokenEndpoint
        iss = $ClientId
        sub = $ClientId
        jti = ([guid]::NewGuid().ToString())
        nbf = ($now - 120)
        exp = ($now + 540)
    }
    $payload = ConvertTo-JsonSafe $payloadObject
    $headerPart = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($header))
    $payloadPart = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payload))
    $signingInput = $headerPart + '.' + $payloadPart
    $rsa = Get-TeamsCertificatePrivateKey $Certificate
    try {
        $data = [Text.Encoding]::ASCII.GetBytes($signingInput)
        $sign = $rsa.GetType().GetMethod('SignData', [Type[]]@(
                [byte[]],
                [System.Security.Cryptography.HashAlgorithmName],
                [System.Security.Cryptography.RSASignaturePadding]
            ))
        if ($sign) {
            $hashName = [System.Security.Cryptography.HashAlgorithmName]::SHA256
            $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            $signature = $sign.Invoke($rsa, @($data, $hashName, $padding))
        }
        else {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try { $signature = $rsa.SignData($data, $sha) }
            finally { $sha.Dispose() }
        }
    }
    finally {
        if ($rsa -is [IDisposable]) { $rsa.Dispose() }
    }
    return ($signingInput + '.' + (ConvertTo-Base64Url $signature))
}

function Get-TeamsJwtPayload {
    param([Parameter(Mandatory)][string]$Token)
    $parts = $Token.Split('.')
    if ($parts.Length -lt 2) { throw 'The access token is not a JWT.' }
    $json = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $parts[1]))
    return ($json | ConvertFrom-Json)
}

function ConvertTo-FormBody {
    param([hashtable]$Fields)
    $pairs = New-Object System.Collections.Generic.List[string]
    foreach ($key in @($Fields.Keys)) {
        $pairs.Add(('{0}={1}' -f [uri]::EscapeDataString([string]$key), [uri]::EscapeDataString([string]$Fields[$key])))
    }
    return [string]::Join('&', $pairs.ToArray())
}

function Get-TeamsCertificate {
    param([string]$Thumbprint, [string]$Path, [securestring]$Password)
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) { throw "Certificate file not found: $Path" }
        $flagType = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
        if ([enum]::GetNames($flagType) -contains 'EphemeralKeySet') {
            $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
        }
        $plain = ConvertFrom-SecureStringPlain $Password
        if ($null -eq $plain) { $plain = '' }
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Path, $plain, $flags)
    }
    $normalized = (($Thumbprint | ForEach-Object { $_ }) -replace '\s', '').ToUpperInvariant()
    if ($normalized -notmatch '^[0-9A-F]{40}$') {
        throw 'Certificate thumbprint must be 40 hexadecimal characters.'
    }
    $certDrive = $false
    try { $certDrive = [bool](Get-PSDrive -Name Cert -ErrorAction SilentlyContinue) } catch { $certDrive = $false }
    if (-not $certDrive) {
        throw 'The Windows certificate store is not available in this session. Use a PFX file instead.'
    }
    foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        $candidate = Join-Path $store $normalized
        if (Test-Path -LiteralPath $candidate) {
            $cert = Get-Item -LiteralPath $candidate
            if (-not $cert.HasPrivateKey) { throw "Certificate $normalized does not have a private key." }
            return $cert
        }
    }
    throw "Certificate $normalized was not found in CurrentUser\My or LocalMachine\My."
}

function Request-TeamsAccessToken {
    param($Client)
    $cloud = Get-TeamsCloudConfig $Client.Cloud
    $tokenEndpoint = "https://$($cloud.LoginHost)/$($Client.TenantId)/oauth2/v2.0/token"
    Assert-TeamsAllowedHost -Client $null -AbsoluteUri $tokenEndpoint -FallbackHosts @($cloud.LoginHost)
    $fields = @{
        client_id  = [string]$Client.ClientId
        scope      = [string]$cloud.Scope
        grant_type = 'client_credentials'
    }
    if ($Client.TokenMode -eq 'Secret') {
        $plain = ConvertFrom-SecureStringPlain $Client.ClientSecret
        if (-not $plain) { throw 'Client secret is empty.' }
        $fields['client_secret'] = $plain
    }
    elseif ($Client.TokenMode -eq 'Certificate') {
        $fields['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        $fields['client_assertion'] = New-TeamsClientAssertion -ClientId $Client.ClientId -TokenEndpoint $tokenEndpoint -Certificate $Client.Certificate
    }
    elseif ($Client.TokenMode -eq 'Existing') {
        $token = Get-TeamsExistingGraphAccessToken
        return @{ AccessToken = $token; ExpiresIn = 3000 }
    }
    else {
        throw "Unknown token mode '$($Client.TokenMode)'."
    }
    $response = Invoke-TeamsHttp -Uri $tokenEndpoint -Method 'POST' -Body (ConvertTo-FormBody $fields) -ContentType 'application/x-www-form-urlencoded'
    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
        throw ("Token request failed with HTTP {0}: {1}" -f $response.StatusCode, (Get-GraphErrorMessage $response.Raw $response.StatusCode))
    }
    $parsed = $response.Raw | ConvertFrom-Json
    if (-not $parsed.access_token) { throw 'Token response did not include an access token.' }
    $expires = 3600
    if ($parsed.expires_in) { $expires = [int]$parsed.expires_in }
    return @{ AccessToken = [string]$parsed.access_token; ExpiresIn = $expires }
}

function Get-TeamsExistingGraphAccessToken {
    $module = Get-Module -ListAvailable Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $module) {
        throw 'Microsoft.Graph.Authentication is not installed. Install it, or sign in with a certificate or client secret.'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null
    $context = Get-MgContext
    if (-not $context) {
        throw 'No Microsoft Graph connection exists in this process. Connect-MgGraph first, then start this tool with: powershell.exe -STA -File TeamsCallReport.ps1'
    }
    foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        $sessionType = $null
        try { $sessionType = $assembly.GetType('Microsoft.Graph.PowerShell.Authentication.GraphSession', $false) } catch { $sessionType = $null }
        if (-not $sessionType) { continue }
        $instanceProp = $sessionType.GetProperty('Instance', [Reflection.BindingFlags]'Public,Static')
        if (-not $instanceProp) { continue }
        $instance = $instanceProp.GetValue($null, $null)
        if (-not $instance) { continue }
        $auth = $null
        $authProp = $instance.GetType().GetProperty('AuthContext')
        if ($authProp) { $auth = $authProp.GetValue($instance, $null) }
        if (-not $auth) { continue }
        $methods = @($auth.GetType().GetMethods() | Where-Object { $_.Name -match 'GetAccessToken|AcquireToken|GetToken' })
        foreach ($method in $methods) {
            if ($method.GetParameters().Count -gt 1) { continue }
            try {
                $methodArgs = @()
                $parameters = @($method.GetParameters())
                if ($parameters.Count -eq 1) {
                    if ($parameters[0].ParameterType.FullName -eq 'System.Threading.CancellationToken') {
                        $methodArgs = @([System.Threading.CancellationToken]::None)
                    }
                    else { continue }
                }
                $result = $method.Invoke($auth, $methodArgs)
                if ($result -is [System.Threading.Tasks.Task]) {
                    $result = $result.GetAwaiter().GetResult()
                }
                if ($result -is [string] -and $result.Length -gt 20) { return [string]$result }
                if ($result -and $result.PSObject.Properties['AccessToken'] -and $result.AccessToken) {
                    return [string]$result.AccessToken
                }
                $tokenProp = $result.GetType().GetProperty('AccessToken')
                if ($tokenProp) {
                    $value = $tokenProp.GetValue($result, $null)
                    if ($value) { return [string]$value }
                }
            }
            catch { }
        }
    }
    throw 'Could not read an access token from the existing Graph session. Sign in with a certificate or client secret instead.'
}

function Update-TeamsGraphToken {
    param($Client, [switch]$Force)
    if ($Client.Kind -ne 'Http') { return }
    $expires = $Client.ExpiresOn
    $due = $Force.IsPresent -or ($null -eq $expires) -or ($expires -lt [datetimeoffset]::UtcNow.AddMinutes(5))
    if (-not $due) { return }
    if (-not $Client.TokenMode) {
        if (-not $Client.AccessToken) { throw 'Not signed in to Microsoft Graph.' }
        if ($Force) { throw 'The access token was rejected and this session cannot refresh it.' }
        return
    }
    $issued = Request-TeamsAccessToken $Client
    $Client.AccessToken = [string]$issued.AccessToken
    $Client.ExpiresOn = [datetimeoffset]::UtcNow.AddSeconds([int]$issued.ExpiresIn)
    $payload = Get-TeamsJwtPayload $Client.AccessToken
    if ($payload.tid) { $Client.TenantId = [string]$payload.tid }
    $Client.TokenInfo = New-TeamsTokenInfo -Payload $payload -ExpiresOn $Client.ExpiresOn -RequestedTenant $Client.RequestedTenantId
}

function New-TeamsTokenInfo {
    param($Payload, $ExpiresOn, [string]$RequestedTenant)
    $roles = ConvertTo-StringArray $Payload.roles
    $scopes = @()
    if ($Payload.scp) { $scopes = @(([string]$Payload.scp -split ' ' | Where-Object { $_ })) }
    $authType = 'Unknown'
    if ($roles.Count -gt 0 -and -not $Payload.scp) { $authType = 'Application' }
    elseif ($Payload.scp) { $authType = 'Delegated' }
    $warnings = New-Object System.Collections.Generic.List[string]
    if ($authType -eq 'Delegated') {
        $warnings.Add('This is a delegated user token. Call records require application permissions, so Graph will reject the query.')
    }
    $roleSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($role in $roles) { [void]$roleSet.Add($role) }
    if (-not $roleSet.Contains('CallRecords.Read.All')) {
        $warnings.Add('The token does not include application role CallRecords.Read.All.')
    }
    if (-not $roleSet.Contains('User.Read.All')) {
        $warnings.Add('The token does not include application role User.Read.All. Directory enrichment will fail.')
    }
    if ($Payload.tid -and $RequestedTenant -and -not (Test-SameId $Payload.tid $RequestedTenant)) {
        $warnings.Add("Token tenant $($Payload.tid) does not match requested tenant $RequestedTenant.")
    }
    return [pscustomobject]@{
        TenantId   = ConvertTo-NullableString $Payload.tid
        ClientId   = ConvertTo-NullableString $(if ($Payload.appid) { $Payload.appid } else { $Payload.azp })
        ExpiresOn  = $ExpiresOn
        Roles      = $roles
        Scopes     = $scopes
        AuthType   = $authType
        Warnings   = $warnings.ToArray()
    }
}

function Get-TeamsPublicClientId {
    # Microsoft Graph Command Line Tools, the public client Connect-MgGraph uses.
    # Call records have no delegated permission, so this sign-in is only used to
    # create an app and grant the application roles below.
    return '14d82eec-204b-4c2f-b7e8-296a70dab67e'
}

function Get-TeamsCallReportAppRoles {
    return @(
        [pscustomobject]@{ Name = 'CallRecords.Read.All'; Id = '45bbb07e-7321-4fd7-a8f6-3ff27e6a81c8' },
        [pscustomobject]@{ Name = 'User.Read.All'; Id = 'df021288-bdef-4463-88db-98f22de89214' }
    )
}

function Get-TeamsAccountGrantPath {
    param([string]$Path)
    if ($Path) { return $Path }
    $root = $env:APPDATA
    if ([string]::IsNullOrWhiteSpace($root)) { $root = (Join-Path $env:USERPROFILE 'AppData\Roaming') }
    $dir = Join-Path $root 'TeamsCallReport'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    return (Join-Path $dir 'account.json')
}

function Read-TeamsAccountGrant {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json) }
    catch { return $null }
}

function Save-TeamsAccountGrant {
    param([string]$Path, [string]$ClientId, [string]$Thumbprint, [string]$TenantId)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = ConvertTo-JsonSafe ([ordered]@{
            clientId   = $ClientId
            thumbprint = $Thumbprint
            tenantId   = $TenantId
        })
    $utf8 = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($Path, $json, $utf8)
}

function New-TeamsBootstrapCertificate {
    if (-not (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
        throw 'Signing in with your account needs Windows PowerShell so the certificate can be stored in Cert:\CurrentUser\My.'
    }
    $notAfter = (Get-Date).AddYears(2)
    try {
        return New-SelfSignedCertificate -Subject 'CN=Teams Call Report' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotAfter $notAfter -FriendlyName 'Teams Call Report' -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2')
    }
    catch {
        return New-SelfSignedCertificate -Subject 'CN=Teams Call Report' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotAfter $notAfter
    }
}

function Invoke-TeamsAccountRequest {
    param(
        $Send,
        [string[]]$AllowedHosts,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [string]$Body,
        [string]$ContentType = 'application/json',
        [hashtable]$Headers
    )
    Assert-TeamsAllowedHost -Client $null -AbsoluteUri $Uri -FallbackHosts $AllowedHosts
    if ($Send) { return (& $Send $Method $Uri $Body $ContentType $Headers) }
    return (Invoke-TeamsHttp -Method $Method -Uri $Uri -Body $Body -ContentType $ContentType -Headers $Headers)
}

function Get-TeamsOAuthErrorCode {
    param($Raw)
    if ([string]::IsNullOrWhiteSpace([string]$Raw)) { return $null }
    try {
        $parsed = $Raw | ConvertFrom-Json
        if ($parsed.error -is [string]) { return [string]$parsed.error }
        if ($parsed.error -and $parsed.error.code) { return [string]$parsed.error.code }
    }
    catch { }
    return $null
}

function Test-TeamsTokenHasCallRoles {
    param($TokenInfo)
    if (-not $TokenInfo -or $TokenInfo.AuthType -ne 'Application') { return $false }
    $have = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($role in (ConvertTo-StringArray $TokenInfo.Roles)) { [void]$have.Add([string]$role) }
    return ($have.Contains('CallRecords.Read.All') -and $have.Contains('User.Read.All'))
}

function New-TeamsAppOnlyClient {
    param(
        $Send,
        $CloudConfig,
        [string[]]$AllowedHosts,
        [string]$TenantId,
        [string]$ClientId,
        $Certificate,
        [scriptblock]$Log
    )
    $tokenEndpoint = "https://$($CloudConfig.LoginHost)/$TenantId/oauth2/v2.0/token"
    $fields = @{
        client_id             = $ClientId
        scope                 = [string]$CloudConfig.Scope
        grant_type            = 'client_credentials'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = (New-TeamsClientAssertion -ClientId $ClientId -TokenEndpoint $tokenEndpoint -Certificate $Certificate)
    }
    $response = Invoke-TeamsAccountRequest -Send $Send -AllowedHosts $AllowedHosts -Method 'POST' -Uri $tokenEndpoint -Body (ConvertTo-FormBody $fields) -ContentType 'application/x-www-form-urlencoded'
    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
        throw ("Saved app sign-in failed with HTTP {0}: {1}" -f $response.StatusCode, (Get-GraphErrorMessage $response.Raw $response.StatusCode))
    }
    $parsed = $response.Raw | ConvertFrom-Json
    if (-not $parsed.access_token) { throw 'Token response did not include an access token.' }
    $expires = 3600
    if ($parsed.expires_in) { $expires = [int]$parsed.expires_in }
    $payload = Get-TeamsJwtPayload ([string]$parsed.access_token)
    $expiresOn = [datetimeoffset]::UtcNow.AddSeconds($expires)
    $client = @{
        Kind              = 'Http'
        Cloud             = $CloudConfig.Name
        BaseUrl           = $CloudConfig.GraphBase
        AllowedHosts      = @($CloudConfig.GraphHost)
        TenantId          = $TenantId
        RequestedTenantId = $TenantId
        ClientId          = $ClientId
        AccessToken       = [string]$parsed.access_token
        ExpiresOn         = $expiresOn
        TokenMode         = 'Certificate'
        Certificate       = $Certificate
        TokenInfo         = (New-TeamsTokenInfo -Payload $payload -ExpiresOn $expiresOn -RequestedTenant $TenantId)
        Log               = $Log
        ShouldCancel      = $null
        Requests          = $null
    }
    if ($payload.tid) { $client.TenantId = [string]$payload.tid }
    return $client
}

function Get-TeamsGraphCollection {
    param($Raw)
    if ([string]::IsNullOrWhiteSpace([string]$Raw)) { return (Get-ObjectList $null).Items }
    $parsed = $Raw | ConvertFrom-Json
    $value = $null
    if ($parsed.PSObject.Properties['value']) { $value = $parsed.value }
    return (Get-ObjectList $value).Items
}

function New-TeamsCallReportAppBody {
    param([string]$DisplayName, [string]$Notes, $KeyCredential)
    $roles = New-Object System.Collections.Generic.List[object]
    foreach ($role in @(Get-TeamsCallReportAppRoles)) {
        $roles.Add([pscustomobject]@{ id = $role.Id; type = 'Role' })
    }
    $resources = New-Object System.Collections.Generic.List[object]
    $resources.Add([pscustomobject]@{
            resourceAppId  = '00000003-0000-0000-c000-000000000000'
            resourceAccess = $roles
        })
    $keys = New-Object System.Collections.Generic.List[object]
    $keys.Add([pscustomobject]$KeyCredential)
    return [pscustomobject]@{
        displayName            = $DisplayName
        signInAudience         = 'AzureADMyOrg'
        notes                  = $Notes
        requiredResourceAccess = $resources
        keyCredentials         = $keys
    }
}

function Invoke-TeamsUserGraph {
    param($Send, [string[]]$AllowedHosts, [string]$Method, [string]$Uri, [string]$Token, $BodyObject)
    $body = $null
    if ($null -ne $BodyObject) { $body = ConvertTo-JsonSafe $BodyObject }
    $headers = @{ Authorization = ("Bearer {0}" -f $Token); Accept = 'application/json' }
    $response = Invoke-TeamsAccountRequest -Send $Send -AllowedHosts $AllowedHosts -Method $Method -Uri $Uri -Body $body -ContentType 'application/json' -Headers $headers
    return $response
}

function Connect-TeamsCallReportAccount {
    param(
        [ValidateSet('Public', 'USGov', 'USGovDoD')]
        [string]$Cloud = 'Public',
        [string]$GrantPath,
        $Certificate,
        [scriptblock]$OnDeviceCode,
        [scriptblock]$ShouldCancel,
        [scriptblock]$Log,
        $Send
    )
    $cloudConfig = Get-TeamsCloudConfig $Cloud
    $allowed = @($cloudConfig.LoginHost, $cloudConfig.GraphHost)
    $grantFile = Get-TeamsAccountGrantPath $GrantPath
    $saved = Read-TeamsAccountGrant $grantFile
    $thumb = $null
    if ($Certificate -and $Certificate.Thumbprint) {
        $thumb = (($Certificate.Thumbprint -replace '\s', '').ToUpperInvariant())
    }
    if ($saved -and $saved.clientId -and $saved.thumbprint -and $saved.tenantId) {
        $savedThumb = (([string]$saved.thumbprint -replace '\s', '').ToUpperInvariant())
        $reuseCert = $null
        if ($Certificate -and $thumb -eq $savedThumb) { $reuseCert = $Certificate }
        elseif (-not $Certificate) {
            try { $reuseCert = Get-TeamsCertificate -Thumbprint $savedThumb } catch { $reuseCert = $null }
        }
        if ($reuseCert) {
            try {
                $existing = New-TeamsAppOnlyClient -Send $Send -CloudConfig $cloudConfig -AllowedHosts $allowed -TenantId ([string]$saved.tenantId) -ClientId ([string]$saved.clientId) -Certificate $reuseCert -Log $Log
                if (Test-TeamsTokenHasCallRoles $existing.TokenInfo) {
                    return [pscustomobject]@{
                        Client      = $existing
                        ClientId    = [string]$saved.clientId
                        Thumbprint  = $savedThumb
                        TenantId    = [string]$existing.TenantId
                        Reused      = $true
                        Account     = $null
                    }
                }
                if ($Log) { & $Log 'WARN' 'The saved Teams Call Report app is missing CallRecords.Read.All or User.Read.All. Signing in to grant them.' }
            }
            catch {
                if ($Log) { & $Log 'WARN' ("Saved sign-in could not be reused ({0}). Signing in again." -f $_.Exception.Message) }
            }
        }
    }

    $scopeHost = 'https://' + $cloudConfig.GraphHost
    $scopes = @(
        "$scopeHost/Application.ReadWrite.All",
        "$scopeHost/AppRoleAssignment.ReadWrite.All",
        "$scopeHost/Directory.Read.All",
        'offline_access',
        'openid',
        'profile'
    )
    $deviceEndpoint = "https://$($cloudConfig.LoginHost)/organizations/oauth2/v2.0/devicecode"
    $deviceResponse = Invoke-TeamsAccountRequest -Send $Send -AllowedHosts $allowed -Method 'POST' -Uri $deviceEndpoint -Body (ConvertTo-FormBody @{
            client_id = (Get-TeamsPublicClientId)
            scope     = ($scopes -join ' ')
        }) -ContentType 'application/x-www-form-urlencoded'
    if ($deviceResponse.StatusCode -lt 200 -or $deviceResponse.StatusCode -ge 300) {
        throw ("Could not start sign-in (HTTP {0}): {1}" -f $deviceResponse.StatusCode, (Get-GraphErrorMessage $deviceResponse.Raw $deviceResponse.StatusCode))
    }
    $device = $deviceResponse.Raw | ConvertFrom-Json
    $verifyUrl = $null
    if ($device.verification_uri) { $verifyUrl = [string]$device.verification_uri }
    elseif ($device.verification_url) { $verifyUrl = [string]$device.verification_url }
    else { $verifyUrl = 'https://microsoft.com/devicelogin' }
    $userCode = [string]$device.user_code
    $signInMessage = "Open $verifyUrl and enter code $userCode. Sign in as a Global Administrator or Privileged Role Administrator. This grants CallRecords.Read.All and User.Read.All to an app named Teams Call Report. The private key stays on this PC."
    if ($OnDeviceCode) {
        & $OnDeviceCode ([pscustomobject]@{
                UserCode        = $userCode
                VerificationUrl = $verifyUrl
                Message         = $signInMessage
                DeviceCode      = [string]$device.device_code
            })
    }
    $interval = 5
    if ($device.PSObject.Properties['interval'] -and $null -ne $device.interval) { $interval = [int]$device.interval }
    $lifetime = 900
    if ($device.expires_in) { $lifetime = [int]$device.expires_in }
    $deadline = [datetimeoffset]::UtcNow.AddSeconds($lifetime)
    $tokenEndpoint = "https://$($cloudConfig.LoginHost)/organizations/oauth2/v2.0/token"
    $userToken = $null
    $sleepClient = @{ ShouldCancel = $ShouldCancel }
    while ([datetimeoffset]::UtcNow -lt $deadline) {
        if ($ShouldCancel -and (& $ShouldCancel)) { throw 'Sign-in cancelled.' }
        $tokenResponse = Invoke-TeamsAccountRequest -Send $Send -AllowedHosts $allowed -Method 'POST' -Uri $tokenEndpoint -Body (ConvertTo-FormBody @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = (Get-TeamsPublicClientId)
                device_code = [string]$device.device_code
            }) -ContentType 'application/x-www-form-urlencoded'
        if ($tokenResponse.StatusCode -ge 200 -and $tokenResponse.StatusCode -lt 300) {
            $tokenJson = $tokenResponse.Raw | ConvertFrom-Json
            if ($tokenJson.access_token) { $userToken = [string]$tokenJson.access_token; break }
        }
        $oauthError = Get-TeamsOAuthErrorCode $tokenResponse.Raw
        if ($oauthError -eq 'authorization_pending') {
            if ($interval -gt 0) { Start-TeamsSleep -Client $sleepClient -Seconds $interval }
            continue
        }
        if ($oauthError -eq 'slow_down') {
            $interval = $interval + 5
            Start-TeamsSleep -Client $sleepClient -Seconds $interval
            continue
        }
        if ($oauthError -eq 'expired_token') { throw 'The sign-in code expired. Run sign-in again.' }
        if ($oauthError -eq 'access_denied' -or $oauthError -eq 'authorization_declined') {
            throw 'Sign-in was declined. Call records need an administrator to grant the application permission.'
        }
        throw ("Sign-in failed with HTTP {0}: {1}" -f $tokenResponse.StatusCode, (Get-GraphErrorMessage $tokenResponse.Raw $tokenResponse.StatusCode))
    }
    if (-not $userToken) { throw 'Sign-in timed out before the browser step finished.' }
    $userPayload = Get-TeamsJwtPayload $userToken
    $tenantId = ConvertTo-NullableString $userPayload.tid
    if (-not $tenantId) { throw 'The sign-in token did not include a tenant id.' }
    $account = ConvertTo-NullableString $userPayload.preferred_username
    if (-not $account) { $account = ConvertTo-NullableString $userPayload.upn }
    if ($Log -and $account) { & $Log 'INFO' ("Signed in as $account.") }

    if (-not $Certificate) { $Certificate = New-TeamsBootstrapCertificate }
    $thumb = (([string]$Certificate.Thumbprint -replace '\s', '').ToUpperInvariant())
    $certKey = [Convert]::ToBase64String($Certificate.RawData)
    $keyId = [Convert]::ToBase64String($Certificate.GetCertHash())
    $keyCredential = [ordered]@{
        type                = 'AsymmetricX509Cert'
        usage               = 'Verify'
        key                 = $certKey
        displayName         = 'Teams Call Report'
        customKeyIdentifier = $keyId
    }
    $graphBase = $cloudConfig.GraphBase.TrimEnd('/')
    $appFilter = Format-GraphPath 'applications' @{ '$filter' = "displayName eq 'Teams Call Report'"; '$select' = 'id,appId,displayName,keyCredentials' }
    $appResponse = Invoke-TeamsUserGraph -Send $Send -AllowedHosts $allowed -Method 'GET' -Uri ($graphBase + '/' + $appFilter) -Token $userToken
    if ($appResponse.StatusCode -eq 403) {
        throw 'This account cannot create applications. Sign in with a Global Administrator or Privileged Role Administrator.'
    }
    if ($appResponse.StatusCode -lt 200 -or $appResponse.StatusCode -ge 300) {
        throw ("Could not look for the Teams Call Report app (HTTP {0}): {1}" -f $appResponse.StatusCode, (Get-GraphErrorMessage $appResponse.Raw $appResponse.StatusCode))
    }
    $apps = @(Get-TeamsGraphCollection $appResponse.Raw)
    $application = $null
    foreach ($candidate in $apps) {
        if ($candidate.appId) { $application = $candidate; break }
    }
    $created = $false
    if (-not $application) {
        $createBody = New-TeamsCallReportAppBody -DisplayName 'Teams Call Report' -Notes 'Created by Teams Call Report. Call records only allow an application permission, so this app holds CallRecords.Read.All and User.Read.All.' -KeyCredential $keyCredential
        $createdResponse = Invoke-TeamsUserGraph -Send $Send -AllowedHosts $allowed -Method 'POST' -Uri ($graphBase + '/applications') -Token $userToken -BodyObject $createBody
        if ($createdResponse.StatusCode -eq 403) {
            throw 'This account cannot grant application permissions. Sign in with a Global Administrator or Privileged Role Administrator.'
        }
        if ($createdResponse.StatusCode -lt 200 -or $createdResponse.StatusCode -ge 300) {
            throw ("Could not create the Teams Call Report app (HTTP {0}): {1}" -f $createdResponse.StatusCode, (Get-GraphErrorMessage $createdResponse.Raw $createdResponse.StatusCode))
        }
        $application = $createdResponse.Raw | ConvertFrom-Json
        $created = $true
    }
    else {
        $hasKey = $false
        foreach ($existingKey in (Get-ObjectList $application.keyCredentials).Items) {
            $identifier = ConvertTo-NullableString $existingKey.customKeyIdentifier
            if ($identifier -and $identifier.Trim().Equals($keyId, [StringComparison]::Ordinal)) { $hasKey = $true }
        }
        if (-not $hasKey) {
            $addResponse = Invoke-TeamsUserGraph -Send $Send -AllowedHosts $allowed -Method 'POST' -Uri ($graphBase + "/applications/$($application.id)/addKey") -Token $userToken -BodyObject ([ordered]@{ keyCredential = $keyCredential })
            if ($addResponse.StatusCode -lt 200 -or $addResponse.StatusCode -ge 300) {
                $fallbackName = 'Teams Call Report ' + $env:COMPUTERNAME
                if ([string]::IsNullOrWhiteSpace($fallbackName)) { $fallbackName = 'Teams Call Report local' }
                $createBody = New-TeamsCallReportAppBody -DisplayName $fallbackName -Notes 'Created by Teams Call Report because the existing app certificate could not be updated.' -KeyCredential $keyCredential
                $createdResponse = Invoke-TeamsUserGraph -Send $Send -AllowedHosts $allowed -Method 'POST' -Uri ($graphBase + '/applications') -Token $userToken -BodyObject $createBody
                if ($createdResponse.StatusCode -lt 200 -or $createdResponse.StatusCode -ge 300) {
                    throw ("Could not add a certificate to the Teams Call Report app (HTTP {0}): {1}" -f $addResponse.StatusCode, (Get-GraphErrorMessage $addResponse.Raw $addResponse.StatusCode))
                }
                $application = $createdResponse.Raw | ConvertFrom-Json
                $created = $true
            }
        }
    }
    $appId = [string]$application.appId
    if (-not $appId) { throw 'The Teams Call Report app did not return an application id.' }

    $spFilter = Format-GraphPath 'servicePrincipals' @{ '$filter' = "appId eq '$appId'"; '$select' = 'id,appId' }
    $spResponse = Invoke-TeamsUserGraph -Send $Send -AllowedHosts $allowed -Method 'GET' -Uri ($graphBase + '/' + $spFilter) -Token $userToken
    if ($spResponse.StatusCode -lt 200 -or $spResponse.StatusCode -ge 300) {
        throw ("Could not find the app's service principal (HTTP {0}): {1}" -f $spResponse.StatusCode, (Get-GraphErrorMessage $spResponse.Raw $spResponse.StatusCode))
    }
    $servicePrincipals = @(Get-TeamsGraphCollection $spResponse.Raw)
    $servicePrincipal = $null
    foreach ($candidate in $servicePrincipals) { if ($candidate.id) { $servicePrincipal = $candidate; break } }
    if (-not $servicePrincipal) {
        $spCreate = Invoke-TeamsUserGraph -Send $Send -AllowedHosts $allowed -Method 'POST' -Uri ($graphBase + '/servicePrincipals') -Token $userToken -BodyObject ([ordered]@{ appId = $appId })
        if ($spCreate.StatusCode -lt 200 -or $spCreate.StatusCode -ge 300) {
            throw ("Could not enable the Teams Call Report app (HTTP {0}): {1}" -f $spCreate.StatusCode, (Get-GraphErrorMessage $spCreate.Raw $spCreate.StatusCode))
        }
        $servicePrincipal = $spCreate.Raw | ConvertFrom-Json
    }

    $graphFilter = Format-GraphPath 'servicePrincipals' @{ '$filter' = "appId eq '00000003-0000-0000-c000-000000000000'"; '$select' = 'id,appId,appRoles' }
    $graphResponse = Invoke-TeamsUserGraph -Send $Send -AllowedHosts $allowed -Method 'GET' -Uri ($graphBase + '/' + $graphFilter) -Token $userToken
    if ($graphResponse.StatusCode -lt 200 -or $graphResponse.StatusCode -ge 300) {
        throw ("Could not read Microsoft Graph roles (HTTP {0}): {1}" -f $graphResponse.StatusCode, (Get-GraphErrorMessage $graphResponse.Raw $graphResponse.StatusCode))
    }
    $graphPrincipals = @(Get-TeamsGraphCollection $graphResponse.Raw)
    $graphPrincipal = $null
    foreach ($candidate in $graphPrincipals) { if ($candidate.id) { $graphPrincipal = $candidate; break } }
    if (-not $graphPrincipal) { throw 'Microsoft Graph is not present as a service principal in this tenant.' }
    $roleIds = @{}
    foreach ($known in @(Get-TeamsCallReportAppRoles)) { $roleIds[$known.Name] = $known.Id }
    foreach ($appRole in (Get-ObjectList $graphPrincipal.appRoles).Items) {
        $roleName = ConvertTo-NullableString $appRole.value
        if ($roleName -and $roleIds.ContainsKey($roleName) -and $appRole.id) { $roleIds[$roleName] = [string]$appRole.id }
    }
    foreach ($roleName in @($roleIds.Keys)) {
        $assign = Invoke-TeamsUserGraph -Send $Send -AllowedHosts $allowed -Method 'POST' -Uri ($graphBase + "/servicePrincipals/$($graphPrincipal.id)/appRoleAssignedTo") -Token $userToken -BodyObject ([ordered]@{
                principalId = [string]$servicePrincipal.id
                resourceId  = [string]$graphPrincipal.id
                appRoleId   = [string]$roleIds[$roleName]
            })
        $assignError = Get-GraphErrorMessage $assign.Raw $assign.StatusCode
        $already = ($assign.StatusCode -eq 409) -or ($assignError -match 'already exists')
        if ($already) { continue }
        if ($assign.StatusCode -eq 403) {
            throw 'This account cannot grant CallRecords.Read.All. Sign in with a Global Administrator or Privileged Role Administrator.'
        }
        if ($assign.StatusCode -lt 200 -or $assign.StatusCode -ge 300) {
            throw ("Could not grant $roleName (HTTP $($assign.StatusCode)): $assignError")
        }
    }

    $client = New-TeamsAppOnlyClient -Send $Send -CloudConfig $cloudConfig -AllowedHosts $allowed -TenantId $tenantId -ClientId $appId -Certificate $Certificate -Log $Log
    Save-TeamsAccountGrant -Path $grantFile -ClientId $appId -Thumbprint $thumb -TenantId $client.TenantId
    if (-not (Test-TeamsTokenHasCallRoles $client.TokenInfo)) {
        $roleText = (@(ConvertTo-StringArray $client.TokenInfo.Roles) | ForEach-Object { [string]$_ }) -join ', '
        if (-not $roleText) { $roleText = '(none)' }
        throw "The app token does not include both call-record roles yet. Auth $($client.TokenInfo.AuthType). Token roles: $roleText. Wait a minute and run sign-in again if the grant was just created."
    }
    return [pscustomobject]@{
        Client     = $client
        ClientId   = $appId
        Thumbprint = $thumb
        TenantId   = [string]$client.TenantId
        Reused     = $false
        Account    = $account
        Created    = [bool]$created
    }
}

function New-TeamsGraphClient {
    [CmdletBinding(DefaultParameterSetName = 'CertificateStore')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'CertificateStore')]
        [Parameter(Mandatory, ParameterSetName = 'CertificateFile')]
        [Parameter(Mandatory, ParameterSetName = 'Secret')]
        [string]$TenantId,

        [Parameter(Mandatory, ParameterSetName = 'CertificateStore')]
        [Parameter(Mandatory, ParameterSetName = 'CertificateFile')]
        [Parameter(Mandatory, ParameterSetName = 'Secret')]
        [string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = 'CertificateStore')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory, ParameterSetName = 'CertificateFile')]
        [string]$CertificatePath,

        [Parameter(ParameterSetName = 'CertificateFile')]
        [securestring]$CertificatePassword,

        [Parameter(Mandatory, ParameterSetName = 'Secret')]
        [securestring]$ClientSecret,

        [Parameter(Mandatory, ParameterSetName = 'Existing')]
        [switch]$UseExistingConnection,

        [ValidateSet('Public', 'USGov', 'USGovDoD')]
        [string]$Cloud = 'Public'
    )
    $cloud = Get-TeamsCloudConfig $Cloud
    $client = @{
        Kind              = 'Http'
        Cloud             = $cloud.Name
        BaseUrl           = $cloud.GraphBase
        AllowedHosts      = @($cloud.GraphHost)
        TenantId          = $TenantId
        RequestedTenantId = $TenantId
        ClientId          = $ClientId
        AccessToken       = $null
        ExpiresOn         = $null
        TokenMode         = $null
        TokenInfo         = $null
        Log               = $null
        ShouldCancel      = $null
        Requests          = $null
    }
    switch ($PSCmdlet.ParameterSetName) {
        'CertificateStore' {
            $client.TokenMode = 'Certificate'
            $client.Certificate = Get-TeamsCertificate -Thumbprint $CertificateThumbprint
        }
        'CertificateFile' {
            $client.TokenMode = 'Certificate'
            $client.Certificate = Get-TeamsCertificate -Path $CertificatePath -Password $CertificatePassword
        }
        'Secret' {
            $client.TokenMode = 'Secret'
            $client.ClientSecret = $ClientSecret
        }
        'Existing' {
            $client.TokenMode = 'Existing'
        }
    }
    Update-TeamsGraphToken -Client $client -Force
    return $client
}

function Invoke-TeamsGraphRequest {
    param(
        [Parameter(Mandatory)]$Client,
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET',
        [string]$Body
    )
    $absolute = Get-TeamsAbsoluteUri -Client $Client -Uri $Uri
    Assert-TeamsAllowedHost -Client $Client -AbsoluteUri $absolute
    if ($null -ne $Client.Requests) {
        [void]$Client.Requests.Add(("{0} {1}" -f $Method.ToUpperInvariant(), $absolute))
        if ($Body) { [void]$Client.Requests.Add($Body) }
    }
    $attempt = 0
    $refreshed = $false
    while ($true) {
        Test-TeamsClientCancel $Client
        $attempt++
        if ($Client.Kind -eq 'Http') { Update-TeamsGraphToken -Client $Client }
        try {
            if ($Client.Kind -eq 'Sample') {
                $response = Invoke-TeamsSampleRequest -Client $Client -Uri $absolute -Method $Method -Body $Body
            }
            elseif ($Client.Send) {
                $response = & $Client.Send $Client $absolute $Method $Body
            }
            else {
                $headers = @{
                    Authorization = ("Bearer {0}" -f $Client.AccessToken)
                    Accept        = 'application/json'
                }
                $response = Invoke-TeamsHttp -Uri $absolute -Method $Method -Headers $headers -Body $Body -ContentType 'application/json'
            }
        }
        catch [System.OperationCanceledException] { throw }
        catch {
            if ($attempt -le 5) {
                $delay = [int][math]::Min(30, [math]::Pow(2, $attempt))
                Write-TeamsClientLog $Client 'WARN' "Graph request error: $($_.Exception.Message). Retrying in $delay s."
                Start-TeamsSleep -Client $Client -Seconds $delay
                continue
            }
            throw
        }
        $status = [int]$response.StatusCode
        if ($status -ge 200 -and $status -lt 300) {
            $parsed = $null
            if (-not [string]::IsNullOrWhiteSpace([string]$response.Raw)) {
                $parsed = $response.Raw | ConvertFrom-Json
            }
            return [pscustomobject]@{
                StatusCode = $status
                Raw        = [string]$response.Raw
                Object     = $parsed
            }
        }
        if ($status -eq 401 -and -not $refreshed -and $Client.Kind -eq 'Http') {
            $refreshed = $true
            Write-TeamsClientLog $Client 'WARN' 'Graph returned HTTP 401. Refreshing the access token.'
            Update-TeamsGraphToken -Client $Client -Force
            $attempt--
            continue
        }
        $retryable = ($status -eq 429 -or $status -eq 408 -or $status -ge 500)
        if ($retryable -and $attempt -le 5) {
            $delay = Get-TeamsRetryDelay -RetryAfter $response.RetryAfter -Attempt $attempt
            Write-TeamsClientLog $Client 'WARN' "Graph returned HTTP $status. Retrying in $delay s (attempt $attempt of 5)."
            Start-TeamsSleep -Client $Client -Seconds $delay
            continue
        }
        $message = Get-GraphErrorMessage -Raw $response.Raw -Status $status
        throw "Graph request failed with HTTP ${status}: $message"
    }
}

function Get-NextLink {
    param($Response, [string]$Name = '@odata.nextLink')
    if ($null -eq $Response) { return $null }
    $prop = $Response.PSObject.Properties[$Name]
    if ($prop -and $prop.Value) { return [string]$prop.Value }
    return $null
}

function Get-PageItems {
    param($Response)
    if ($null -eq $Response) { return (Get-ObjectList $null) }
    $names = @($Response.PSObject.Properties.Name)
    if ($names -contains 'value') { return (Get-ObjectList $Response.value) }
    return (Get-ObjectList $Response)
}

function Get-TeamsPagedItems {
    param($Client, [string]$Uri, [string]$FirstNextLinkProperty)
    $items = New-Object System.Collections.Generic.List[object]
    $raws = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $next = $Uri
    $nextProperty = $FirstNextLinkProperty
    $pages = 0
    while ($next) {
        if (-not $seen.Add($next)) {
            Write-TeamsClientLog $Client 'WARN' 'Stopped paging because the next link repeated.'
            break
        }
        $pages++
        if ($pages -gt 500) {
            Write-TeamsClientLog $Client 'WARN' 'Stopped paging after 500 pages.'
            break
        }
        $page = Invoke-TeamsGraphRequest -Client $Client -Uri $next
        if ($page.Raw) { $raws.Add($page.Raw) }
        foreach ($item in (Get-PageItems $page.Object).Items) {
            if ($null -ne $item) { $items.Add($item) }
        }
        if ($nextProperty) {
            $next = Get-NextLink -Response $page.Object -Name $nextProperty
            $nextProperty = $null
        }
        else {
            $next = Get-NextLink -Response $page.Object
        }
    }
    return [pscustomobject]@{
        Items    = $items.ToArray()
        RawPages = $raws.ToArray()
    }
}

function New-IdentitySummary {
    return [pscustomobject]@{
        IdentityType      = $null
        IdentityId        = $null
        DisplayName       = $null
        TenantId          = $null
        UserPrincipalName = $null
        EndpointType      = $null
    }
}

function Get-IdentitySummary {
    param($IdentitySet)
    $summary = New-IdentitySummary
    if ($null -eq $IdentitySet) { return $summary }
    $preference = @(
        'user', 'guest', 'phone', 'applicationInstance', 'application', 'device',
        'acsUser', 'spoolUser', 'encrypted', 'onPremises', 'assertedIdentity',
        'acsApplicationInstance', 'spoolApplicationInstance'
    )
    $kinds = New-Object System.Collections.Generic.List[string]
    foreach ($prop in @($IdentitySet.PSObject.Properties)) {
        if ($prop.Name -like '*@odata*') { continue }
        if ($null -eq $prop.Value) { continue }
        if ($prop.Value -is [System.Management.Automation.PSCustomObject]) { $kinds.Add($prop.Name) }
    }
    if ($kinds.Count -eq 0) {
        if ($IdentitySet.PSObject.Properties['id'] -or $IdentitySet.PSObject.Properties['displayName'] -or $IdentitySet.PSObject.Properties['userPrincipalName']) {
            $summary.IdentityType = 'identity'
            $summary.IdentityId = ConvertTo-NullableString $IdentitySet.id
            $summary.DisplayName = ConvertTo-NullableString $IdentitySet.displayName
            $summary.TenantId = ConvertTo-NullableString $IdentitySet.tenantId
            $summary.UserPrincipalName = ConvertTo-NullableString $IdentitySet.userPrincipalName
        }
        return $summary
    }
    $primary = $null
    foreach ($name in $preference) {
        if ($kinds -contains $name) { $primary = $name; break }
    }
    if (-not $primary) { $primary = $kinds[0] }
    $identity = $IdentitySet.$primary
    $summary.IdentityType = [string]::Join(';', $kinds.ToArray())
    $summary.IdentityId = ConvertTo-NullableString $identity.id
    $summary.DisplayName = ConvertTo-NullableString $identity.displayName
    $summary.TenantId = ConvertTo-NullableString $identity.tenantId
    $summary.UserPrincipalName = ConvertTo-NullableString $identity.userPrincipalName
    $summary.EndpointType = ConvertTo-NullableString $IdentitySet.endpointType
    return $summary
}

function Get-EndpointIdentitySummary {
    param($Endpoint)
    if ($null -eq $Endpoint) { return (New-IdentitySummary) }
    if ($Endpoint.PSObject.Properties['identity'] -and $Endpoint.identity) {
        $fromIdentity = Get-IdentitySummary $Endpoint.identity
        if ($fromIdentity.IdentityId -or $fromIdentity.DisplayName) { return $fromIdentity }
    }
    if ($Endpoint.PSObject.Properties['associatedIdentity'] -and $Endpoint.associatedIdentity) {
        return (Get-IdentitySummary $Endpoint.associatedIdentity)
    }
    return (New-IdentitySummary)
}

function Get-OrganizerSummary {
    param($Detail)
    if ($Detail -and $Detail.PSObject.Properties['organizer_v2'] -and $Detail.organizer_v2) {
        $summary = $null
        if ($Detail.organizer_v2.PSObject.Properties['identity'] -and $Detail.organizer_v2.identity) {
            $summary = Get-IdentitySummary $Detail.organizer_v2.identity
        }
        if ($null -eq $summary -or (-not $summary.IdentityId -and -not $summary.DisplayName)) {
            $summary = Get-IdentitySummary $Detail.organizer_v2
        }
        if ($summary.IdentityId -or $summary.DisplayName) { return $summary }
    }
    if ($Detail -and $Detail.PSObject.Properties['organizer'] -and $Detail.organizer) {
        return (Get-IdentitySummary $Detail.organizer)
    }
    return (New-IdentitySummary)
}

function Test-IsTargetIdentity {
    param($TargetUser, $Summary, $ParticipantId)
    if ($null -eq $TargetUser) { return $false }
    if (Test-SameId $ParticipantId $TargetUser.id) { return $true }
    if ($Summary -and (Test-SameId $Summary.IdentityId $TargetUser.id)) { return $true }
    $upn = $null
    if ($Summary) { $upn = ConvertTo-NullableString $Summary.UserPrincipalName }
    $targetUpn = ConvertTo-NullableString $TargetUser.userPrincipalName
    if ($upn -and $targetUpn -and $upn.Equals($targetUpn, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $false
}

function Get-StreamSummary {
    param($Streams)
    $items = (Get-ObjectList $Streams).Items
    if ($items.Count -eq 0) { return $null }
    $parts = New-Object System.Collections.Generic.List[string]
    $fields = @(
        @('streamDirection', 'dir'),
        @('averageJitter', 'avgJitter'),
        @('maxJitter', 'maxJitter'),
        @('averagePacketLossRate', 'avgLoss'),
        @('maxPacketLossRate', 'maxLoss'),
        @('averageRoundTripTime', 'avgRtt'),
        @('maxRoundTripTime', 'maxRtt'),
        @('audioCodec', 'audio'),
        @('videoCodec', 'video')
    )
    foreach ($stream in $items) {
        $bits = New-Object System.Collections.Generic.List[string]
        foreach ($pair in $fields) {
            $val = $null
            if ($stream.PSObject.Properties[$pair[0]]) { $val = ConvertTo-NullableString $stream.($pair[0]) }
            if ($val) { $bits.Add(("{0}={1}" -f $pair[1], $val)) }
        }
        if ($bits.Count -gt 0) { $parts.Add([string]::Join(' ', $bits.ToArray())) }
    }
    if ($parts.Count -eq 0) { return $null }
    return [string]::Join(' | ', $parts.ToArray())
}

function Join-Modalities {
    param($Value)
    $items = (Get-ObjectList $Value).Items
    if ($items.Count -eq 0) { return $null }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($item in $items) {
        $text = ConvertTo-NullableString $item
        if ($text) { $names.Add($text) }
    }
    if ($names.Count -eq 0) { return $null }
    return [string]::Join(';', $names.ToArray())
}

function Get-TeamsDirectoryUser {
    param($Client, [string]$User)
    $needle = $User.Trim()
    if (-not $needle) { throw 'Enter a user principal name, email address, or object id.' }
    $direct = $null
    $escaped = [uri]::EscapeDataString($needle)
    try {
        $direct = Invoke-TeamsUserRequest -Client $Client -Path "users/$escaped"
    }
    catch {
        if ($_.Exception.Message -notmatch 'HTTP 404') { throw }
    }
    if ($direct -and $direct.id) { return $direct }
    $filterResult = $null
    try {
        $filterResult = Invoke-TeamsUserRequest -Client $Client -Path 'users' -Filter (Get-TeamsUserFilter $needle)
    }
    catch {
        if ($_.Exception.Message -notmatch 'HTTP 400') { throw }
        Write-TeamsClientLog $Client 'WARN' 'The detailed user filter was rejected. Retrying with UPN, mail, and display name only.'
        $filterResult = Invoke-TeamsUserRequest -Client $Client -Path 'users' -Filter (Get-TeamsUserFilter $needle -NameOnly)
    }
    $matches = (Get-PageItems $filterResult).Items
    if ($matches.Count -eq 0) { throw "No Entra user matched '$needle'." }
    if ($matches.Count -eq 1) { return $matches[0] }
    $exact = @($matches | Where-Object {
            (Test-SameId $_.id $needle) -or
            ($(if ($_.userPrincipalName) { $_.userPrincipalName.Equals($needle, [StringComparison]::OrdinalIgnoreCase) } else { $false })) -or
            ($(if ($_.mail) { $_.mail.Equals($needle, [StringComparison]::OrdinalIgnoreCase) } else { $false }))
        })
    if ($exact.Count -eq 1) { return $exact[0] }
    throw "Matched $($matches.Count) Entra users for '$needle'. Use a user principal name or object id."
}

function Invoke-TeamsUserRequest {
    param($Client, [string]$Path, [string]$Filter)
    $selects = @((Get-TeamsUserSelect), (Get-TeamsUserSelect -Core))
    $lastError = $null
    foreach ($select in $selects) {
        $query = @{ '$select' = $select }
        if ($Filter) {
            $query['$filter'] = $Filter
            $query['$top'] = '10'
        }
        try {
            $response = Invoke-TeamsGraphRequest -Client $Client -Uri (Format-GraphPath $Path $query)
            if ($Filter) { return $response.Object }
            return $response.Object
        }
        catch {
            $lastError = $_
            if ($_.Exception.Message -notmatch 'HTTP 400') { throw }
        }
    }
    throw $lastError
}

function Import-DirectoryUsers {
    param($Client, $Cache, [string[]]$Ids)
    $pending = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($Ids)) {
        if (-not (Test-TeamsGuid $id)) { continue }
        $key = $id.ToLowerInvariant()
        if ($Cache.ContainsKey($key)) { continue }
        if ($seen.Add($key)) { $pending.Add($key) }
    }
    if ($pending.Count -eq 0) { return }
    $index = 0
    while ($index -lt $pending.Count) {
        $chunk = New-Object System.Collections.Generic.List[string]
        while ($index -lt $pending.Count -and $chunk.Count -lt 10) {
            $chunk.Add($pending[$index])
            $index++
        }
        try {
            Import-DirectoryUserChunk -Client $Client -Cache $Cache -Ids $chunk.ToArray()
        }
        catch {
            Write-TeamsClientLog $Client 'WARN' "Directory batch failed ($($_.Exception.Message)). Requesting those users one at a time."
            foreach ($id in @($chunk.ToArray())) {
                $key = $id.ToLowerInvariant()
                if ($Cache.ContainsKey($key)) { continue }
                Import-DirectoryUserSingle -Client $Client -Cache $Cache -Id $id
            }
        }
    }
}

function Import-DirectoryUserChunk {
    param($Client, $Cache, [string[]]$Ids)
    $select = [uri]::EscapeDataString((Get-TeamsUserSelect))
    $managerSelect = [uri]::EscapeDataString('id,displayName,userPrincipalName,mail')
    $requests = New-Object System.Collections.Generic.List[object]
    $ordinal = 0
    foreach ($id in @($Ids)) {
        # Batch request ids are ordinals. Putting the user id here would duplicate it in the log.
        $requests.Add([pscustomobject]@{
                id     = "u-$ordinal"
                method = 'GET'
                url    = "/users/${id}?`$select=$select"
            })
        $requests.Add([pscustomobject]@{
                id     = "m-$ordinal"
                method = 'GET'
                url    = "/users/${id}/manager?`$select=$managerSelect"
            })
        $ordinal++
    }
    $body = ConvertTo-JsonSafe ([pscustomobject]@{ requests = $requests.ToArray() })
    $batchUri = Format-GraphPath '$batch' @{}
    $response = Invoke-TeamsGraphRequest -Client $Client -Uri $batchUri -Method 'POST' -Body $body
    $responses = (Get-ObjectList $response.Object.responses).Items
    if ($responses.Count -eq 0) { throw 'Directory batch returned no responses.' }
    $byId = @{}
    foreach ($item in $responses) { $byId[[string]$item.id] = $item }
    $ordinal = 0
    foreach ($id in @($Ids)) {
        $userItem = $byId["u-$ordinal"]
        $managerItem = $byId["m-$ordinal"]
        $ordinal++
        if ($null -eq $userItem) { throw "Directory batch omitted user $id." }
        $userStatus = [int]$userItem.status
        if ($userStatus -eq 200) {
            $manager = $null
            $managerStatus = 'NotFound'
            if ($managerItem -and [int]$managerItem.status -eq 200) {
                $manager = $managerItem.body
                $managerStatus = 'Found'
            }
            $Cache[$id.ToLowerInvariant()] = [pscustomobject]@{
                User            = $userItem.body
                Manager         = $manager
                LookupStatus    = 'Found'
                ManagerStatus   = $managerStatus
            }
        }
        elseif ($userStatus -eq 404) {
            $Cache[$id.ToLowerInvariant()] = [pscustomobject]@{
                User          = $null
                Manager       = $null
                LookupStatus  = 'NotFound'
                ManagerStatus = 'NotApplicable'
            }
        }
        else {
            $message = Get-GraphErrorMessage -Raw (ConvertTo-JsonSafe $userItem.body) -Status $userStatus
            $Cache[$id.ToLowerInvariant()] = [pscustomobject]@{
                User          = $null
                Manager       = $null
                LookupStatus  = "Error: $message"
                ManagerStatus = 'NotApplicable'
            }
        }
    }
}

function Import-DirectoryUserSingle {
    param($Client, $Cache, [string]$Id)
    $key = $Id.ToLowerInvariant()
    try {
        $user = Invoke-TeamsUserRequest -Client $Client -Path "users/$Id"
        $manager = $null
        $managerStatus = 'NotFound'
        try {
            $managerResponse = Invoke-TeamsGraphRequest -Client $Client -Uri (Format-GraphPath "users/$Id/manager" @{ '$select' = 'id,displayName,userPrincipalName,mail' })
            $manager = $managerResponse.Object
            $managerStatus = 'Found'
        }
        catch {
            if ($_.Exception.Message -notmatch 'HTTP 404') {
                $managerStatus = 'Error'
            }
        }
        $Cache[$key] = [pscustomobject]@{
            User          = $user
            Manager       = $manager
            LookupStatus  = 'Found'
            ManagerStatus = $managerStatus
        }
    }
    catch {
        $status = 'NotFound'
        if ($_.Exception.Message -notmatch 'HTTP 404') { $status = "Error: $($_.Exception.Message)" }
        $Cache[$key] = [pscustomobject]@{
            User          = $null
            Manager       = $null
            LookupStatus  = $status
            ManagerStatus = 'NotApplicable'
        }
    }
}

function Complete-DirectoryColumns {
    param($Client, $Cache, $HomeTenantId, [bool]$SkipDirectory, $Row, $Summary)
    if ($SkipDirectory) {
        $Row['Entra.LookupStatus'] = 'Skipped'
        return
    }
    $type = [string]$Summary.IdentityType
    if ($type -notmatch '(^|;)(user|guest)(;|$)') {
        $Row['Entra.LookupStatus'] = 'NotApplicable'
        return
    }
    $tenant = ConvertTo-NullableString $Summary.TenantId
    if ($tenant -and -not (Test-SameId $tenant $HomeTenantId)) {
        $Row['Entra.LookupStatus'] = "ExternalTenant ($tenant)"
        return
    }
    if (-not (Test-TeamsGuid $Summary.IdentityId)) {
        $Row['Entra.LookupStatus'] = 'NotApplicable'
        return
    }
    $key = $Summary.IdentityId.ToLowerInvariant()
    if (-not $Cache.ContainsKey($key)) {
        $Row['Entra.LookupStatus'] = 'NotLoaded'
        return
    }
    $entry = $Cache[$key]
    $Row['Entra.LookupStatus'] = [string]$entry.LookupStatus
    if ($entry.User) { Add-FlatObject -InputObject $entry.User -Prefix 'Entra' -Target $Row }
    $Row['Entra.Manager.LookupStatus'] = [string]$entry.ManagerStatus
    if ($entry.Manager) { Add-FlatObject -InputObject $entry.Manager -Prefix 'Entra.Manager' -Target $Row }
}

function Get-PropertyText {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if (-not $Object.PSObject.Properties[$Name]) { return $null }
    return (ConvertTo-NullableString $Object.$Name)
}

function New-EndpointRow {
    param($Detail, $Session, $Segment, [string]$Source, [string]$Side, $Endpoint, $Media, $TargetUser, $HomeTenantId)
    $summary = Get-EndpointIdentitySummary $Endpoint
    $network = $null
    $device = $null
    $label = $null
    $streams = $null
    if ($Media) {
        $label = Get-PropertyText $Media 'label'
        $streams = $null
        if ($Media.PSObject.Properties['streams']) { $streams = $Media.streams }
        $deviceName = "${Side}Device"
        $networkName = "${Side}Network"
        if ($Media.PSObject.Properties[$deviceName]) { $device = $Media.$deviceName }
        if ($Media.PSObject.Properties[$networkName]) { $network = $Media.$networkName }
    }
    $agent = $null
    if ($Endpoint -and $Endpoint.PSObject.Properties['userAgent']) { $agent = $Endpoint.userAgent }
    $row = [ordered]@{
        CallId               = ConvertTo-NullableString $Detail.id
        SessionId            = ConvertTo-NullableString $Session.id
        SegmentId            = ConvertTo-NullableString $Segment.id
        SegmentSource        = $Source
        SegmentStartUtc      = ConvertTo-UtcString $Segment.startDateTime
        SegmentEndUtc        = ConvertTo-UtcString $Segment.endDateTime
        Role                 = $Side
        IsTargetUser         = (Test-IsTargetIdentity -TargetUser $TargetUser -Summary $summary)
        IdentityType         = $summary.IdentityType
        IdentityId           = $summary.IdentityId
        DisplayName          = $summary.DisplayName
        TenantId             = $summary.TenantId
        IsExternalTenant     = [bool]($summary.TenantId -and -not (Test-SameId $summary.TenantId $HomeTenantId))
        UserPrincipalName    = $summary.UserPrincipalName
        MachineName          = $(if ($Endpoint) { Get-PropertyText $Endpoint 'name' } else { $null })
        ClientPlatform       = Get-PropertyText $agent 'platform'
        ClientProductFamily  = Get-PropertyText $agent 'productFamily'
        ClientUserAgent      = Get-PropertyText $agent 'headerValue'
        ClientAppVersion     = Get-PropertyText $agent 'applicationVersion'
        CpuName              = $(if ($Endpoint) { Get-PropertyText $Endpoint 'cpuName' } else { $null })
        CpuCores             = $(if ($Endpoint) { Get-PropertyText $Endpoint 'cpuCoresCount' } else { $null })
        CpuMhz               = $(if ($Endpoint) { Get-PropertyText $Endpoint 'cpuProcessorSpeedInMhz' } else { $null })
        FeedbackRating       = $(if ($Endpoint -and $Endpoint.PSObject.Properties['feedback']) { Get-PropertyText $Endpoint.feedback 'rating' } else { $null })
        SessionModalities    = Join-Modalities $Session.modalities
        SessionIsTest        = $(if ($Session.PSObject.Properties['isTest'] -and $null -ne $Session.isTest) { [bool]$Session.isTest } else { $null })
        'Media.Label'        = $label
        CaptureDevice        = Get-PropertyText $device 'captureDeviceName'
        RenderDevice         = Get-PropertyText $device 'renderDeviceName'
        IpAddress            = Get-PropertyText $network 'ipAddress'
        Subnet               = Get-PropertyText $network 'subnet'
        ReflexiveIP          = Get-PropertyText $network 'reflexiveIPAddress'
        RelayIP              = Get-PropertyText $network 'relayIPAddress'
        MacAddress           = Get-PropertyText $network 'macAddress'
        ConnectionType       = Get-PropertyText $network 'connectionType'
        LinkSpeed            = Get-PropertyText $network 'linkSpeed'
        WifiDriver           = Get-PropertyText $network 'wifiVendorDriver'
        WifiSignal           = Get-PropertyText $network 'wifiSignalStrength'
        WifiChannel          = Get-PropertyText $network 'wifiChannel'
        Bssid                = Get-PropertyText $network 'basicServiceSetIdentifier'
        FailureReason        = $(if ($Segment.PSObject.Properties['failureInfo']) { Get-PropertyText $Segment.failureInfo 'reason' } else { $null })
        FailureStage         = $(if ($Segment.PSObject.Properties['failureInfo']) { Get-PropertyText $Segment.failureInfo 'stage' } else { $null })
        'Media.StreamSummary' = Get-StreamSummary $streams
        'Media.Streams'      = $(if ($streams) { ConvertTo-JsonSafe $streams } else { $null })
    }
    if ($Endpoint) { Add-FlatObject -InputObject $Endpoint -Prefix 'Endpoint' -Target $row }
    if ($device) { Add-FlatObject -InputObject $device -Prefix 'Device' -Target $row }
    if ($network) { Add-FlatObject -InputObject $network -Prefix 'Network' -Target $row }
    if ($Segment.PSObject.Properties['failureInfo'] -and $Segment.failureInfo) {
        Add-FlatObject -InputObject $Segment.failureInfo -Prefix 'FailureInfo' -Target $row
    }
    return $row
}

function Get-CallSessions {
    param($Client, $Detail, [string]$CallId)
    $sessions = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $raws = New-Object System.Collections.Generic.List[string]
    foreach ($session in (Get-ObjectList $Detail.sessions).Items) {
        $sid = ConvertTo-NullableString $session.id
        if ($sid) {
            if ($seen.Add($sid)) { $sessions.Add($session) }
        }
        else { $sessions.Add($session) }
    }
    $next = Get-NextLink -Response $Detail -Name 'sessions@odata.nextLink'
    if (-not $next -and (Get-ObjectList $Detail.sessions).Items.Count -eq 0) {
        $page = Get-TeamsPagedItems -Client $Client -Uri (Format-GraphPath "communications/callRecords/$CallId/sessions" @{ '$expand' = 'segments' })
        foreach ($raw in (Get-ObjectList $page.RawPages).Items) { $raws.Add([string]$raw) }
        foreach ($session in (Get-ObjectList $page.Items).Items) { $sessions.Add($session) }
        return [pscustomobject]@{ Sessions = $sessions.ToArray(); RawPages = $raws.ToArray() }
    }
    $seenLinks = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $guard = 0
    while ($next) {
        if (-not $seenLinks.Add($next)) { break }
        $guard++
        if ($guard -gt 500) { break }
        $page = Invoke-TeamsGraphRequest -Client $Client -Uri $next
        if ($page.Raw) { $raws.Add($page.Raw) }
        foreach ($session in (Get-PageItems $page.Object).Items) {
            $sid = ConvertTo-NullableString $session.id
            if ($sid) {
                if ($seen.Add($sid)) { $sessions.Add($session) }
            }
            else { $sessions.Add($session) }
        }
        $next = Get-NextLink -Response $page.Object
    }
    return [pscustomobject]@{ Sessions = $sessions.ToArray(); RawPages = $raws.ToArray() }
}

function Write-TeamsRawBundle {
    param([string]$Path, [string]$CallRaw, $SessionRaws, $ParticipantRaws)
    $sessionJson = [string]::Join(',', @((Get-ObjectList $SessionRaws).Items | Where-Object { $_ }))
    $participantJson = [string]::Join(',', @((Get-ObjectList $ParticipantRaws).Items | Where-Object { $_ }))
    if ([string]::IsNullOrWhiteSpace($CallRaw)) { $CallRaw = 'null' }
    $text = '{"callRecord":' + $CallRaw + ',"sessionPages":[' + $sessionJson + '],"participantPages":[' + $participantJson + ']}'
    $encoding = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $text, $encoding)
}

function Get-TeamsCallList {
    param($Client, [string]$UserId, $Window, [int]$MaxCalls)
    $participant = "participants_v2/any(p:p/id eq '{0}')" -f ($UserId.Replace("'", "''"))
    $start = $Window.Start.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $end = $Window.End.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $combined = "$participant and startDateTime ge $start and startDateTime lt $end"
    $usedFallback = $false
    try {
        $page = Get-TeamsPagedItems -Client $Client -Uri (Format-GraphPath 'communications/callRecords' @{ '$filter' = $combined })
    }
    catch {
        if ($_.Exception.Message -notmatch 'HTTP 400') { throw }
        $usedFallback = $true
        Write-TeamsClientLog $Client 'WARN' 'Graph rejected the combined participant and date filter. Falling back to the participant filter and applying the date window locally.'
        $page = Get-TeamsPagedItems -Client $Client -Uri (Format-GraphPath 'communications/callRecords' @{ '$filter' = $participant })
    }
    $filtered = New-Object System.Collections.Generic.List[object]
    foreach ($item in (Get-ObjectList $page.Items).Items) {
        $startDto = ConvertTo-DateTimeOffset $item.startDateTime
        if ($null -eq $startDto) { continue }
        if ($startDto -ge $Window.Start -and $startDto -lt $Window.End) { $filtered.Add($item) }
    }
    $sorted = @($filtered.ToArray() | Sort-Object { ConvertTo-DateTimeOffset $_.startDateTime } -Descending)
    if ($MaxCalls -gt 0) { $sorted = @($sorted | Select-Object -First $MaxCalls) }
    return [pscustomobject]@{ Items = $sorted; UsedFallback = [bool]$usedFallback }
}

function Add-CallRecord {
    param($Client, $Cache, $TargetUser, $HomeTenantId, [bool]$SkipDirectory, [bool]$SaveRaw, [string]$RawDirectory, $ListItem, $CallRows, $ParticipantRows, $EndpointRows)
    $callId = ConvertTo-NullableString $ListItem.id
    if (-not $callId) { throw 'Call record is missing an id.' }
    $escapedId = [uri]::EscapeDataString($callId)
    $detailPage = $null
    try {
        $detailPage = Invoke-TeamsGraphRequest -Client $Client -Uri (Format-GraphPath "communications/callRecords/$escapedId" @{ '$expand' = 'sessions($expand=segments)' })
    }
    catch {
        Write-TeamsClientLog $Client 'WARN' "Expanding sessions for call $callId failed ($($_.Exception.Message)). Requesting the call and sessions separately."
        $detailPage = Invoke-TeamsGraphRequest -Client $Client -Uri (Format-GraphPath "communications/callRecords/$escapedId" @{})
    }
    $detail = $detailPage.Object
    $sessionResult = Get-CallSessions -Client $Client -Detail $detail -CallId $escapedId
    $participants = Get-TeamsPagedItems -Client $Client -Uri (Format-GraphPath "communications/callRecords/$escapedId/participants_v2" @{})
    if ($SaveRaw) {
        $rawPath = Join-Path $RawDirectory ($callId + '.json')
        Write-TeamsRawBundle -Path $rawPath -CallRaw $detailPage.Raw -SessionRaws $sessionResult.RawPages -ParticipantRaws $participants.RawPages
    }
    $organizer = Get-OrganizerSummary $detail
    $participantItems = (Get-ObjectList $participants.Items).Items
    $sessions = (Get-ObjectList $sessionResult.Sessions).Items
    $segmentCount = 0
    foreach ($session in $sessions) { $segmentCount += (Get-ObjectList $session.segments).Items.Count }
    $CallRows.Add([ordered]@{
            CallId                = ConvertTo-NullableString $detail.id
            CallType              = Get-PropertyText $detail 'type'
            Modalities            = Join-Modalities $detail.modalities
            StartDateTimeUtc      = ConvertTo-UtcString $detail.startDateTime
            EndDateTimeUtc        = ConvertTo-UtcString $detail.endDateTime
            DurationSeconds       = Get-DurationSeconds $detail.startDateTime $detail.endDateTime
            Version               = Get-PropertyText $detail 'version'
            LastModifiedUtc       = ConvertTo-UtcString $detail.lastModifiedDateTime
            JoinWebUrl            = Get-PropertyText $detail 'joinWebUrl'
            OrganizerType         = $organizer.IdentityType
            OrganizerId           = $organizer.IdentityId
            OrganizerDisplayName  = $organizer.DisplayName
            OrganizerTenantId     = $organizer.TenantId
            OrganizerUpn          = $organizer.UserPrincipalName
            TargetUserIsOrganizer = (Test-SameId $organizer.IdentityId $TargetUser.id)
            ParticipantCount      = $participantItems.Count
            SessionCount          = $sessions.Count
            SegmentCount          = $segmentCount
        })
    $directoryIds = New-Object System.Collections.Generic.List[string]
    $newParticipantRows = New-Object System.Collections.Generic.List[object]
    foreach ($participant in $participantItems) {
        $summary = Get-IdentitySummary $participant.identity
        $units = New-Object System.Collections.Generic.List[string]
        foreach ($unit in (Get-ObjectList $participant.administrativeUnitInfos).Items) {
            $unitId = Get-PropertyText $unit 'id'
            if ($unitId) { $units.Add($unitId) }
        }
        $row = [ordered]@{
            CallId              = ConvertTo-NullableString $detail.id
            CallStartUtc        = ConvertTo-UtcString $detail.startDateTime
            ParticipantId       = Get-PropertyText $participant 'id'
            IsTargetUser        = (Test-IsTargetIdentity -TargetUser $TargetUser -Summary $summary -ParticipantId $participant.id)
            IsOrganizer         = (Test-SameId $summary.IdentityId $organizer.IdentityId)
            IdentityType        = $summary.IdentityType
            IdentityId          = $summary.IdentityId
            DisplayName         = $summary.DisplayName
            TenantId            = $summary.TenantId
            IsExternalTenant    = [bool]($summary.TenantId -and -not (Test-SameId $summary.TenantId $HomeTenantId))
            UserPrincipalName   = $summary.UserPrincipalName
            EndpointType        = $summary.EndpointType
            AdministrativeUnits = $(if ($units.Count) { [string]::Join(';', $units.ToArray()) } else { $null })
        }
        Add-FlatObject -InputObject $participant.identity -Prefix 'Identity' -Target $row
        if (-not $SkipDirectory -and $summary.IdentityType -match '(^|;)(user|guest)(;|$)' -and (Test-TeamsGuid $summary.IdentityId)) {
            $inHomeTenant = (-not $summary.TenantId) -or (Test-SameId $summary.TenantId $HomeTenantId)
            if ($inHomeTenant) { $directoryIds.Add($summary.IdentityId) }
        }
        $newParticipantRows.Add($row)
    }
    if (-not $SkipDirectory) {
        Import-DirectoryUsers -Client $Client -Cache $Cache -Ids $directoryIds.ToArray()
    }
    foreach ($row in @($newParticipantRows.ToArray())) {
        $summary = [pscustomobject]@{
            IdentityType = $row['IdentityType']
            IdentityId   = $row['IdentityId']
            TenantId     = $row['TenantId']
        }
        Complete-DirectoryColumns -Client $Client -Cache $Cache -HomeTenantId $HomeTenantId -SkipDirectory $SkipDirectory -Row $row -Summary $summary
        $ParticipantRows.Add($row)
    }
    foreach ($session in $sessions) {
        $segments = (Get-ObjectList $session.segments).Items
        $source = 'segment'
        if ($segments.Count -eq 0) {
            $source = 'session'
            $segments = @([pscustomobject]@{
                    id            = $session.id
                    startDateTime = $session.startDateTime
                    endDateTime   = $session.endDateTime
                    caller        = $session.caller
                    callee        = $session.callee
                    failureInfo   = $(if ($session.PSObject.Properties['failureInfo']) { $session.failureInfo } else { $null })
                    media         = $null
                })
        }
        foreach ($segment in $segments) {
            foreach ($side in @('caller', 'callee')) {
                $endpoint = $null
                if ($segment.PSObject.Properties[$side]) { $endpoint = $segment.$side }
                if ($null -eq $endpoint) { continue }
                $mediaList = (Get-ObjectList $segment.media).Items
                if ($mediaList.Count -eq 0) {
                    $EndpointRows.Add((New-EndpointRow -Detail $detail -Session $session -Segment $segment -Source $source -Side $side -Endpoint $endpoint -Media $null -TargetUser $TargetUser -HomeTenantId $HomeTenantId))
                    continue
                }
                foreach ($media in $mediaList) {
                    $EndpointRows.Add((New-EndpointRow -Detail $detail -Session $session -Segment $segment -Source $source -Side $side -Endpoint $endpoint -Media $media -TargetUser $TargetUser -HomeTenantId $HomeTenantId))
                }
            }
        }
    }
}

function New-TeamsSummaryText {
    param($Export)
    $warningText = 'None'
    $warnings = (Get-ObjectList $Export.Warnings).Items
    if ($warnings.Count -gt 0) { $warningText = [string]::Join([Environment]::NewLine, $warnings.ToArray()) }
    $user = $Export.TargetUser
    $name = ConvertTo-NullableString $user.displayName
    $upn = ConvertTo-NullableString $user.userPrincipalName
    $id = ConvertTo-NullableString $user.id
    $state = 'Completed'
    if ($Export.Cancelled) { $state = 'Cancelled' }
    if ($Export.ErrorMessage) { $state = 'Failed' }
    return @"
Teams call report
Status: $state
User: $name <$upn> [$id]
Window UTC: $($Export.WindowStart) to $($Export.WindowEnd)
Calls: $($Export.CallCount)
Participant rows: $($Export.ParticipantRowCount)
Endpoint rows: $($Export.EndpointRowCount)
Unique identities: $($Export.UniqueIdentityCount)
External identities: $($Export.ExternalIdentityCount)
Output: $($Export.OutputPath)
$(if ($Export.ErrorMessage) { "Error: $($Export.ErrorMessage)`r`n" } else { '' })Warnings:
$warningText
"@
}

function Export-TeamsUserCallDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$User,
        [datetime]$StartDate = ([datetime]::Now.AddDays(-30)),
        [datetime]$EndDate = ([datetime]::Now),
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$GraphClient,
        [switch]$SkipDirectoryLookup,
        [int]$MaxCalls = 0,
        [scriptblock]$Log,
        [scriptblock]$Progress,
        [scriptblock]$ShouldCancel,
        [switch]$SkipRawJson
    )
    if ($MaxCalls -lt 0) { throw 'MaxCalls cannot be negative.' }
    # Leave a cancel or log callback already stored on the client in place.
    if ($PSBoundParameters.ContainsKey('Log')) { $GraphClient.Log = $Log }
    if ($PSBoundParameters.ContainsKey('ShouldCancel')) { $GraphClient.ShouldCancel = $ShouldCancel }
    $warnings = New-Object System.Collections.Generic.List[string]
    $window = Get-TeamsCallWindow -StartDate $StartDate -EndDate $EndDate
    if ($window.Clamped) {
        $warnings.Add('Graph keeps call records for 30 days. The start of the window was moved to 30 days ago.')
        Write-TeamsClientLog $GraphClient 'WARN' $warnings[$warnings.Count - 1]
    }
    $callRows = New-Object System.Collections.Generic.List[object]
    $participantRows = New-Object System.Collections.Generic.List[object]
    $endpointRows = New-Object System.Collections.Generic.List[object]
    $cache = @{}
    $cancelled = $false
    $fatal = $null
    $target = $null
    $saveRaw = -not $SkipRawJson.IsPresent
    $rawDirectory = Join-Path $OutputPath 'RawJson'
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        if ($saveRaw) { New-Item -ItemType Directory -Path $rawDirectory -Force | Out-Null }
        if ($Progress) { & $Progress 2 'Resolving user' }
        $target = Get-TeamsDirectoryUser -Client $GraphClient -User $User
        if (-not $target.id) { throw 'The resolved user has no object id.' }
        Write-TeamsClientLog $GraphClient 'INFO' ("Resolved {0} <{1}> [{2}]" -f $target.displayName, $target.userPrincipalName, $target.id)
        if ($Progress) { & $Progress 8 'Searching call records' }
        $list = Get-TeamsCallList -Client $GraphClient -UserId ([string]$target.id) -Window $window -MaxCalls $MaxCalls
        if ($list.UsedFallback) {
            $warnings.Add('Graph rejected the combined participant and date filter. Falling back to the participant filter and applying the date window locally.')
        }
        $records = (Get-ObjectList $list.Items).Items
        Write-TeamsClientLog $GraphClient 'INFO' ("Found {0} call record(s) between {1} and {2}." -f $records.Count, (ConvertTo-UtcString $window.Start), (ConvertTo-UtcString $window.End))
        if ($records.Count -eq 0) {
            $warnings.Add('No call records matched. Records appear only after a call ends, and Graph keeps them for 30 days. The signed-in app needs CallRecords.Read.All.')
            Write-TeamsClientLog $GraphClient 'WARN' $warnings[$warnings.Count - 1]
        }
        $index = 0
        foreach ($record in $records) {
            Test-TeamsClientCancel $GraphClient
            $index++
            $percent = 10 + [int](($index / [math]::Max(1, $records.Count)) * 80)
            if ($Progress) { & $Progress $percent ("Reading call $index of $($records.Count)") }
            try {
                Add-CallRecord -Client $GraphClient -Cache $cache -TargetUser $target -HomeTenantId $GraphClient.TenantId -SkipDirectory:$SkipDirectoryLookup.IsPresent -SaveRaw $saveRaw -RawDirectory $rawDirectory -ListItem $record -CallRows $callRows -ParticipantRows $participantRows -EndpointRows $endpointRows
            }
            catch [System.OperationCanceledException] { throw }
            catch {
                $warnings.Add("Failed to retrieve call $($record.id): $($_.Exception.Message)")
                Write-TeamsClientLog $GraphClient 'WARN' $warnings[$warnings.Count - 1]
            }
        }
        if ($Progress) { & $Progress 94 'Writing CSV files' }
    }
    catch [System.OperationCanceledException] {
        $cancelled = $true
        $warnings.Add('Export cancelled. Files contain the calls retrieved before the cancel.')
        Write-TeamsClientLog $GraphClient 'WARN' $warnings[$warnings.Count - 1]
    }
    catch {
        $fatal = $_
        $warnings.Add($_.Exception.Message)
    }
    $unique = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $external = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($row in @($participantRows.ToArray())) {
        $identity = ConvertTo-NullableString $row['IdentityId']
        if ($identity) { [void]$unique.Add($identity) }
        if ($identity -and $row['IsExternalTenant'] -eq $true) { [void]$external.Add($identity) }
    }
    $result = [pscustomobject]@{
        OutputPath             = $OutputPath
        CallCount              = $callRows.Count
        ParticipantRowCount    = $participantRows.Count
        EndpointRowCount       = $endpointRows.Count
        UniqueIdentityCount    = $unique.Count
        ExternalIdentityCount  = $external.Count
        Cancelled              = [bool]$cancelled
        ErrorMessage           = $(if ($fatal) { [string]$fatal.Exception.Message } else { $null })
        Warnings               = $warnings.ToArray()
        TargetUser             = $target
        WindowStart            = ConvertTo-UtcString $window.Start
        WindowEnd              = ConvertTo-UtcString $window.End
        CallsTable             = $null
        ParticipantsTable      = $null
        EndpointsTable         = $null
        SummaryText            = $null
    }
    try {
        if ($callRows.Count -gt 0) {
            Export-UnionCsv -Rows $callRows.ToArray() -Path (Join-Path $OutputPath 'Calls.csv')
            Export-UnionCsv -Rows $participantRows.ToArray() -Path (Join-Path $OutputPath 'Participants.csv')
            Export-UnionCsv -Rows $endpointRows.ToArray() -Path (Join-Path $OutputPath 'Endpoints.csv')
        }
        if ($target) {
            $utf8 = New-Object System.Text.UTF8Encoding $true
            [System.IO.File]::WriteAllText((Join-Path $OutputPath 'TargetUser.json'), (ConvertTo-JsonSafe $target), $utf8)
        }
        $result.CallsTable = ConvertTo-ReportDataTable -Rows $callRows.ToArray() -Name 'Calls'
        $result.ParticipantsTable = ConvertTo-ReportDataTable -Rows $participantRows.ToArray() -Name 'Participants'
        $result.EndpointsTable = ConvertTo-ReportDataTable -Rows $endpointRows.ToArray() -Name 'Endpoints'
        $result.SummaryText = New-TeamsSummaryText $result
        $summaryEncoding = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText((Join-Path $OutputPath 'Summary.txt'), $result.SummaryText, $summaryEncoding)
    }
    catch {
        if (-not $result.ErrorMessage) { $result.ErrorMessage = $_.Exception.Message }
    }
    if ($Progress) {
        try { & $Progress 100 $(if ($cancelled) { 'Cancelled' } elseif ($result.ErrorMessage) { 'Failed' } else { 'Export complete' }) } catch { }
    }
    Write-TeamsClientLog $GraphClient 'INFO' ("Calls: {0}; participants: {1}; endpoints: {2}; folder: {3}" -f $result.CallCount, $result.ParticipantRowCount, $result.EndpointRowCount, $result.OutputPath)
    return $result
}

function Resolve-TeamsUser {
    param(
        [Parameter(Mandatory)]$GraphClient,
        [Parameter(Mandatory)][string]$User
    )
    return (Get-TeamsDirectoryUser -Client $GraphClient -User $User)
}

function New-SampleHttpResponse {
    param([int]$Status, [string]$Raw, [string]$RetryAfter = $null)
    return [pscustomobject]@{ StatusCode = $Status; Raw = $Raw; RetryAfter = $RetryAfter }
}

function New-SampleIdentity {
    param([string]$Kind, [string]$Id, [string]$Name, [string]$Tenant, [string]$Upn)
    $body = [ordered]@{
        id                = $Id
        displayName       = $Name
        tenantId          = $Tenant
        userPrincipalName = $Upn
    }
    $set = [ordered]@{}
    $set[$Kind] = [pscustomobject]$body
    return [pscustomobject]$set
}

function New-SampleParticipant {
    param([string]$Kind, [string]$Id, [string]$Name, [string]$Tenant, [string]$Upn, [string]$ParticipantId)
    if (-not $ParticipantId) { $ParticipantId = $Id }
    return [pscustomobject]@{
        id                      = $ParticipantId
        identity                = (New-SampleIdentity -Kind $Kind -Id $Id -Name $Name -Tenant $Tenant -Upn $Upn)
        administrativeUnitInfos = @()
    }
}

function New-SampleEndpoint {
    param($Identity, [string]$Machine, [string]$Platform, [string]$Product, [string]$UserAgent, [string]$AppVersion, [string]$Cpu, $Cores, $Mhz, [string]$Feedback)
    return [pscustomobject]@{
        '@odata.type'             = '#microsoft.graph.callRecords.participantEndpoint'
        name                      = $Machine
        cpuName                   = $Cpu
        cpuCoresCount             = $Cores
        cpuProcessorSpeedInMhz   = $Mhz
        userAgent                 = [pscustomobject]@{
            '@odata.type'        = '#microsoft.graph.callRecords.clientUserAgent'
            headerValue          = $UserAgent
            applicationVersion   = $AppVersion
            platform             = $Platform
            productFamily        = $Product
        }
        associatedIdentity        = $Identity
        feedback                  = [pscustomobject]@{ rating = $Feedback; text = $null }
    }
}

function New-TeamsSampleGraphClient {
    param([switch]$RejectCombinedFilter)
    $homeTenant = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    $external = '99999999-9999-9999-9999-999999999999'
    $alice = '11111111-1111-1111-1111-111111111111'
    $mary = '22222222-2222-2222-2222-222222222222'
    $bob = '33333333-3333-3333-3333-333333333333'
    $dave = '44444444-4444-4444-4444-444444444444'
    $erin = '66666666-6666-6666-6666-666666666666'
    $callA = 'aaaaaaaa-0000-0000-0000-00000000000a'
    $callB = 'bbbbbbbb-0000-0000-0000-00000000000b'
    $callC = 'cccccccc-0000-0000-0000-00000000000c'
    $now = [datetimeoffset]::UtcNow
    $now = $now.AddTicks(-($now.Ticks % [timespan]::TicksPerSecond))
    $startA = $now.AddDays(-2)
    $endA = $startA.AddMinutes(30)
    $startB = $now.AddDays(-5)
    $endB = $startB.AddMinutes(10)
    $startC = $now.AddDays(-40)
    $endC = $startC.AddMinutes(5)
    $fixture = [pscustomobject]@{
        HomeTenantId   = $homeTenant
        ExternalTenant = $external
        AliceId        = $alice
        MaryId         = $mary
        BobId          = $bob
        DaveId         = $dave
        ErinId         = $erin
        AliceUpn       = 'alice@contoso.com'
        AliceMail      = 'Alice.Adams@contoso.com'
        CallA          = $callA
        CallB          = $callB
        CallC          = $callC
        CallADuration  = 1800
        CallBDuration  = 600
        StartA         = ConvertTo-UtcString $startA
        EndA           = ConvertTo-UtcString $endA
        StartB         = ConvertTo-UtcString $startB
        EndB           = ConvertTo-UtcString $endB
        StartC         = ConvertTo-UtcString $startC
        EndC           = ConvertTo-UtcString $endC
    }
    $directory = @{}
    $directory[$alice] = [pscustomobject]@{
        id = $alice; displayName = 'Alice Adams'; userPrincipalName = 'alice@contoso.com'; mail = 'Alice.Adams@contoso.com'
        department = 'Voice Engineering'; jobTitle = 'Network Engineer'; employeeId = 'E100'
        onPremisesSamAccountName = 'alice'; userType = 'Member'; accountEnabled = $true
    }
    $directory[$mary] = [pscustomobject]@{
        id = $mary; displayName = 'Mary Manager'; userPrincipalName = 'mary@contoso.com'; mail = 'mary@contoso.com'
        department = 'IT'; jobTitle = 'Director'
    }
    $directory[$dave] = [pscustomobject]@{
        id = $dave; displayName = 'José Núñez'; userPrincipalName = 'jose@contoso.com'; mail = 'jose@contoso.com'
        department = 'Engineering'; userType = 'Guest'; accountEnabled = $true
    }
    $directory[$erin] = [pscustomobject]@{
        id = $erin; displayName = 'Erin Ellis'; userPrincipalName = 'erin@contoso.com'; mail = 'erin@contoso.com'
        department = 'Support'; userType = 'Member'; accountEnabled = $true
    }
    $managers = @{ $alice = $mary; $dave = $mary }
    $client = @{
        Kind                     = 'Sample'
        Cloud                    = 'Public'
        BaseUrl                  = 'https://graph.microsoft.com/v1.0'
        AllowedHosts             = @('graph.microsoft.com')
        TenantId                 = $homeTenant
        RequestedTenantId        = $homeTenant
        AccessToken              = $null
        ExpiresOn                = [datetimeoffset]::UtcNow.AddHours(1)
        TokenMode                = $null
        TokenInfo                = $null
        Log                      = $null
        ShouldCancel             = $null
        Requests                 = (New-Object System.Collections.Generic.List[string])
        Fixture                  = $fixture
        Directory                = $directory
        Managers                 = $managers
        RejectCombinedRemaining  = $(if ($RejectCombinedFilter) { 1 } else { 0 })
    }
    return $client
}

function New-SampleAudioNetwork {
    return [pscustomobject]@{
        ipAddress                    = '10.20.30.40'
        subnet                       = '10.20.30.0'
        linkSpeed                    = 1000000000
        connectionType               = 'wifi'
        port                         = 50018
        reflexiveIPAddress           = '203.0.113.25'
        relayIPAddress               = '52.114.1.10'
        macAddress                   = '00:11:22:33:44:55'
        wifiVendorDriver             = 'Intel Wireless Driver'
        wifiVendorDriverVersion      = '22.180.0.4'
        wifiMicrosoftDriver          = 'netwtw08.sys'
        wifiMicrosoftDriverVersion   = '22.180.0.4'
        basicServiceSetIdentifier    = 'AA:BB:CC:DD:EE:FF'
        wifiRadioType                = '802.11ac'
        wifiSignalStrength           = 78
        wifiChannel                  = 44
        wifiBatteryCharge            = 90
        dnsSuffix                    = 'contoso.com'
        networkTransportProtocol     = 'udp'
    }
}

function New-SampleStreams {
    param([string]$Codec = 'satin')
    return @(
        [pscustomobject]@{
            streamId               = '1001'
            streamDirection        = 'callerToCallee'
            averageJitter          = 'PT0.012S'
            maxJitter              = 'PT0.040S'
            averagePacketLossRate  = 0.005
            maxPacketLossRate      = 0.02
            averageRoundTripTime   = 'PT0.045S'
            maxRoundTripTime       = 'PT0.120S'
            averageBandwidthEstimate = 64000
            audioCodec             = $Codec
        },
        [pscustomobject]@{
            streamId              = '1002'
            streamDirection       = 'calleeToCaller'
            averageJitter         = 'PT0.015S'
            averagePacketLossRate = 0.001
            averageRoundTripTime  = 'PT0.048S'
        }
    )
}

function Invoke-TeamsSampleRequest {
    param($Client, [string]$Uri, [string]$Method = 'GET', [string]$Body)
    $methodName = $Method.ToUpperInvariant()
    $parsedUri = [Uri]$Uri
    $path = $parsedUri.AbsolutePath.TrimEnd('/')
    $query = [Uri]::UnescapeDataString($parsedUri.Query)
    $fixture = $Client.Fixture
    if ($methodName -eq 'POST' -and $path -match '\$batch$') {
        return New-SampleBatchResponse -Client $Client -Body $Body
    }
    if ($path -match '/communications/callRecords$') {
        return New-SampleCallListResponse -Client $Client -Query $query
    }
    if ($path -match '/communications/callRecords/([^/]+)$') {
        return New-SampleCallDetailResponse -Client $Client -CallId ([Uri]::UnescapeDataString($Matches[1])) -Query $query
    }
    if ($path -match '/communications/callRecords/([^/]+)/participants_v2$') {
        return New-SampleParticipantResponse -Client $Client -CallId ([Uri]::UnescapeDataString($Matches[1])) -Query $query
    }
    if ($path -match '/communications/callRecords/([^/]+)/sessions$') {
        return New-SampleSessionPageResponse -Client $Client -CallId ([Uri]::UnescapeDataString($Matches[1])) -Query $query
    }
    if ($path -match '/users/([^/]+)/manager$') {
        return New-SampleManagerResponse -Client $Client -UserId ([Uri]::UnescapeDataString($Matches[1]))
    }
    if ($path -match '/users/([^/]+)$') {
        return New-SampleUserResponse -Client $Client -Key ([Uri]::UnescapeDataString($Matches[1]))
    }
    if ($path -match '/users$') {
        return New-SampleUserSearchResponse -Client $Client -Query $query
    }
    return (New-SampleHttpResponse -Status 404 -Raw '{"error":{"code":"NotFound","message":"No sample handler for this URL."}}')
}

function New-SampleBatchResponse {
    param($Client, [string]$Body)
    $parsed = $Body | ConvertFrom-Json
    $responses = New-Object System.Collections.Generic.List[object]
    foreach ($request in (Get-ObjectList $parsed.requests).Items) {
        $url = [string]$request.url
        $id = [string]$request.id
        if ($url -match '/users/([^/]+)/manager') {
            $userId = $Matches[1]
            if ($Client.Managers.ContainsKey($userId)) {
                $responses.Add([pscustomobject]@{ id = $id; status = 200; body = $Client.Directory[$Client.Managers[$userId]] })
            }
            else {
                $responses.Add([pscustomobject]@{
                        id     = $id
                        status = 404
                        body   = [pscustomobject]@{ error = [pscustomobject]@{ code = 'Request_ResourceNotFound'; message = 'Manager not found' } }
                    })
            }
        }
        elseif ($url -match '/users/([^/?]+)') {
            $userId = $Matches[1]
            if ($Client.Directory.ContainsKey($userId)) {
                $responses.Add([pscustomobject]@{ id = $id; status = 200; body = $Client.Directory[$userId] })
            }
            else {
                $responses.Add([pscustomobject]@{
                        id     = $id
                        status = 404
                        body   = [pscustomobject]@{ error = [pscustomobject]@{ code = 'Request_ResourceNotFound'; message = 'User not found' } }
                    })
            }
        }
        else {
            $responses.Add([pscustomobject]@{ id = $id; status = 400; body = [pscustomobject]@{ error = [pscustomobject]@{ code = 'BadRequest'; message = 'Unsupported batch URL' } } })
        }
    }
    return (New-SampleHttpResponse -Status 200 -Raw (ConvertTo-JsonSafe ([pscustomobject]@{ responses = $responses.ToArray() })))
}

function New-SampleCallListResponse {
    param($Client, [string]$Query)
    $fixture = $Client.Fixture
    if ($Client.RejectCombinedRemaining -gt 0 -and $Query -match 'participants_v2' -and $Query -match 'startDateTime') {
        $Client.RejectCombinedRemaining = $Client.RejectCombinedRemaining - 1
        return (New-SampleHttpResponse -Status 400 -Raw '{"error":{"code":"BadRequest","message":"Combined filter is not supported."}}')
    }
    if ($Query -match 'participants_v2' -and $Query -notmatch [regex]::Escape($fixture.AliceId)) {
        return (New-SampleHttpResponse -Status 200 -Raw '{"value":[]}')
    }
    $calls = @(
        (New-SampleCallSummary -Client $Client -Id $fixture.CallA -Type 'groupCall' -Start $fixture.StartA -End $fixture.EndA -Modalities @('audio', 'video') -OrganizerId $fixture.AliceId -OrganizerName 'Alice Adams' -Join $true),
        (New-SampleCallSummary -Client $Client -Id $fixture.CallB -Type 'peerToPeer' -Start $fixture.StartB -End $fixture.EndB -Modalities @('audio', 'video') -OrganizerId $fixture.ErinId -OrganizerName 'Erin Ellis' -Join $false),
        (New-SampleCallSummary -Client $Client -Id $fixture.CallC -Type 'peerToPeer' -Start $fixture.StartC -End $fixture.EndC -Modalities @('audio') -OrganizerId $fixture.AliceId -OrganizerName 'Alice Adams' -Join $false)
    )
    $start = $null
    $end = $null
    if ($Query -match 'startDateTime ge (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)') { $start = ConvertTo-DateTimeOffset $Matches[1] }
    if ($Query -match 'startDateTime lt (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)') { $end = ConvertTo-DateTimeOffset $Matches[1] }
    if ($start -or $end) {
        $calls = @($calls | Where-Object {
                $callStart = ConvertTo-DateTimeOffset $_.startDateTime
                ((-not $start) -or $callStart -ge $start) -and ((-not $end) -or $callStart -lt $end)
            })
    }
    return (New-SampleHttpResponse -Status 200 -Raw (ConvertTo-JsonSafe ([pscustomobject]@{ value = @($calls) })))
}

function New-SampleCallSummary {
    param($Client, [string]$Id, [string]$Type, [string]$Start, [string]$End, [string[]]$Modalities, [string]$OrganizerId, [string]$OrganizerName, [bool]$Join)
    $fixture = $Client.Fixture
    $summary = [ordered]@{
        id                   = $Id
        version              = 2
        type                 = $Type
        modalities           = $Modalities
        lastModifiedDateTime = $End
        startDateTime        = $Start
        endDateTime          = $End
        joinWebUrl           = $(if ($Join) { 'https://teams.microsoft.com/l/meetup-join/sample' } else { $null })
        organizer_v2         = [pscustomobject]@{
            id       = $OrganizerId
            identity = (New-SampleIdentity -Kind 'user' -Id $OrganizerId -Name $OrganizerName -Tenant $fixture.HomeTenantId -Upn $null)
        }
    }
    return [pscustomobject]$summary
}

function New-SampleAliceEndpoint {
    param($Client)
    $fixture = $Client.Fixture
    $identity = [pscustomobject]@{
        id                = $fixture.AliceId
        displayName       = 'Alice Adams'
        tenantId          = $fixture.HomeTenantId
        userPrincipalName = $fixture.AliceUpn
    }
    return (New-SampleEndpoint -Identity $identity -Machine 'ALICE-PC' -Platform 'windows' -Product 'teams' -UserAgent 'CallSignalingAgent (Teams-Windows/1.0)' -AppVersion '1.0.0.1' -Cpu 'Intel(R) Core(TM) i7-8665U CPU @ 1.90GHz' -Cores 8 -Mhz 2112 -Feedback 'good')
}

function New-SampleErinEndpoint {
    param($Client)
    $fixture = $Client.Fixture
    $identity = [pscustomobject]@{
        id                = $fixture.ErinId
        displayName       = 'Erin Ellis'
        tenantId          = $fixture.HomeTenantId.ToUpperInvariant()
        userPrincipalName = 'erin@contoso.com'
    }
    return (New-SampleEndpoint -Identity $identity -Machine 'ERIN-MAC' -Platform 'macOS' -Product 'teams' -UserAgent 'CallSignalingAgent (Teams-Mac/1.0)' -AppVersion '1.0.0.2' -Cpu 'Apple M2' -Cores 8 -Mhz 2400 -Feedback 'notRated')
}

function New-SampleCallDetailResponse {
    param($Client, [string]$CallId, [string]$Query)
    $fixture = $Client.Fixture
    if ($CallId -eq $fixture.CallA) {
        $alice = New-SampleAliceEndpoint -Client $Client
        $bobIdentity = [pscustomobject]@{ id = $fixture.BobId; displayName = 'Bob External'; tenantId = $fixture.ExternalTenant; userPrincipalName = 'bob@fabrikam.com' }
        $bob = New-SampleEndpoint -Identity $bobIdentity -Machine 'BOB-PHONE' -Platform 'android' -Product 'teams' -UserAgent 'Teams-Android/1.0' -AppVersion '1.0.0.3' -Cpu $null -Cores $null -Mhz $null -Feedback 'poor'
        $audio = [pscustomobject]@{
            label          = 'main-audio'
            callerDevice   = [pscustomobject]@{ captureDeviceName = 'Headset Microphone (Poly V4320)'; captureDeviceDriver = 'poly.sys'; renderDeviceName = 'Headset Earphone (Poly V4320)'; renderDeviceDriver = 'poly.sys'; receivedSignalLevel = -18; sentSignalLevel = -12 }
            calleeDevice   = [pscustomobject]@{ captureDeviceName = 'Speakerphone'; renderDeviceName = 'Speakerphone' }
            callerNetwork  = (New-SampleAudioNetwork)
            calleeNetwork  = [pscustomobject]@{ ipAddress = '192.0.2.40'; subnet = '192.0.2.0'; connectionType = 'wired'; macAddress = '10:20:30:40:50:60' }
            streams        = (New-SampleStreams)
        }
        $segment = [pscustomobject]@{
            id            = 'segment-a-audio'
            startDateTime = $fixture.StartA
            endDateTime   = $null
            caller        = $alice
            callee        = $bob
            failureInfo   = [pscustomobject]@{ reason = 'MediaConnectivity'; stage = 'midcall' }
            media         = @($audio)
        }
        $session = [pscustomobject]@{
            id            = 'session-a'
            modalities    = @('audio', 'video')
            startDateTime = $fixture.StartA
            endDateTime   = $fixture.EndA
            isTest        = $false
            caller        = $alice
            callee        = $bob
            segments      = @($segment)
        }
        $detail = [ordered]@{
            id                   = $fixture.CallA
            version              = 2
            type                 = 'groupCall'
            modalities           = @('audio', 'video')
            lastModifiedDateTime = $fixture.EndA
            startDateTime        = $fixture.StartA
            endDateTime          = $fixture.EndA
            joinWebUrl           = 'https://teams.microsoft.com/l/meetup-join/sample'
            organizer_v2         = [pscustomobject]@{
                id       = $fixture.AliceId
                identity = (New-SampleIdentity -Kind 'user' -Id $fixture.AliceId -Name 'Alice Adams' -Tenant $fixture.HomeTenantId -Upn $fixture.AliceUpn)
            }
            sessions             = @($session)
        }
        return (New-SampleHttpResponse -Status 200 -Raw (ConvertTo-JsonSafe ([pscustomobject]$detail)))
    }
    if ($CallId -eq $fixture.CallB) {
        $alice = New-SampleAliceEndpoint -Client $Client
        $erin = New-SampleErinEndpoint -Client $Client
        $audio = [pscustomobject]@{
            label         = 'main-audio'
            callerDevice  = [pscustomobject]@{ captureDeviceName = 'Headset Microphone (Poly V4320)'; renderDeviceName = 'Headset Earphone (Poly V4320)'; receivedSignalLevel = -18 }
            calleeDevice  = [pscustomobject]@{ captureDeviceName = 'MacBook Microphone'; renderDeviceName = 'MacBook Speakers' }
            callerNetwork = (New-SampleAudioNetwork)
            calleeNetwork = [pscustomobject]@{ ipAddress = '10.9.8.7'; subnet = '10.9.8.0'; connectionType = 'wired'; reflexiveIPAddress = '198.51.100.20'; macAddress = '66:55:44:33:22:11' }
            streams       = (New-SampleStreams)
        }
        $session = [pscustomobject]@{
            id            = 'session-b-audio'
            modalities    = @('audio')
            startDateTime = $fixture.StartB
            endDateTime   = $fixture.EndB
            isTest        = $false
            caller        = $alice
            callee        = $erin
            segments      = @([pscustomobject]@{
                    id            = 'segment-b-audio'
                    startDateTime = $fixture.StartB
                    endDateTime   = $fixture.EndB
                    caller        = $alice
                    callee        = $erin
                    failureInfo   = $null
                    media         = @($audio)
                })
        }
        $detail = [ordered]@{
            id                   = $fixture.CallB
            version              = 2
            type                 = 'peerToPeer'
            modalities           = @('audio', 'video')
            lastModifiedDateTime = $fixture.EndB
            startDateTime        = $fixture.StartB
            endDateTime          = $fixture.EndB
            organizer_v2         = [pscustomobject]@{
                id       = $fixture.ErinId
                identity = (New-SampleIdentity -Kind 'user' -Id $fixture.ErinId -Name 'Erin Ellis' -Tenant $fixture.HomeTenantId -Upn 'erin@contoso.com')
            }
            sessions             = @($session)
            'sessions@odata.nextLink' = ("{0}/communications/callRecords/{1}/sessions?`$expand=segments&`$skiptoken=sessions2" -f $Client.BaseUrl, $fixture.CallB)
        }
        return (New-SampleHttpResponse -Status 200 -Raw (ConvertTo-JsonSafe ([pscustomobject]$detail)))
    }
    return (New-SampleHttpResponse -Status 404 -Raw '{"error":{"code":"NotFound","message":"Call record not found."}}')
}

function New-SampleSessionPageResponse {
    param($Client, [string]$CallId, [string]$Query)
    $fixture = $Client.Fixture
    if ($CallId -eq $fixture.CallB -and $Query -match 'sessions2') {
        $alice = New-SampleAliceEndpoint -Client $Client
        $erin = New-SampleErinEndpoint -Client $Client
        $video = [pscustomobject]@{
            label         = 'main-video'
            callerDevice  = [pscustomobject]@{ captureDeviceName = 'Integrated Camera'; renderDeviceName = 'Headset Earphone (Poly V4320)' }
            calleeDevice  = [pscustomobject]@{ captureDeviceName = 'FaceTime HD Camera'; renderDeviceName = 'MacBook Speakers' }
            callerNetwork = (New-SampleAudioNetwork)
            calleeNetwork = [pscustomobject]@{ ipAddress = '10.9.8.7'; connectionType = 'wired' }
            streams       = @([pscustomobject]@{ streamId = '2001'; streamDirection = 'callerToCallee'; videoCodec = 'H264'; averagePacketLossRate = 0.01; averageRoundTripTime = 'PT0.060S' })
        }
        $session = [pscustomobject]@{
            id            = 'session-b-video'
            modalities    = @('video')
            startDateTime = $fixture.StartB
            endDateTime   = $fixture.EndB
            isTest        = $false
            caller        = $alice
            callee        = $erin
            segments      = @([pscustomobject]@{
                    id            = 'segment-b-video'
                    startDateTime = $fixture.StartB
                    endDateTime   = $fixture.EndB
                    caller        = $alice
                    callee        = $erin
                    media         = @($video)
                })
        }
        return (New-SampleHttpResponse -Status 200 -Raw (ConvertTo-JsonSafe ([pscustomobject]@{ value = @($session) })))
    }
    return (New-SampleHttpResponse -Status 200 -Raw '{"value":[]}')
}

function New-SampleParticipantResponse {
    param($Client, [string]$CallId, [string]$Query)
    $fixture = $Client.Fixture
    $homeUpper = $fixture.HomeTenantId.ToUpperInvariant()
    if ($CallId -eq $fixture.CallA -and $Query -match 'participants2') {
        $erin = New-SampleParticipant -Kind 'user' -Id $fixture.ErinId -Name 'Erin Ellis' -Tenant $homeUpper -Upn 'erin@contoso.com'
        return (New-SampleHttpResponse -Status 200 -Raw (ConvertTo-JsonSafe ([pscustomobject]@{ value = @($erin) })))
    }
    if ($CallId -eq $fixture.CallA) {
        $alice = New-SampleParticipant -Kind 'user' -Id $fixture.AliceId -Name 'Alice Adams' -Tenant $fixture.HomeTenantId -Upn $fixture.AliceUpn
        $dave = New-SampleParticipant -Kind 'guest' -Id $fixture.DaveId -Name 'José Núñez' -Tenant $homeUpper -Upn 'jose@contoso.com'
        $bob = New-SampleParticipant -Kind 'user' -Id $fixture.BobId -Name 'Bob External' -Tenant $fixture.ExternalTenant -Upn 'bob@fabrikam.com'
        $phone = [pscustomobject]@{
            id       = 'phone-participant'
            identity = [pscustomobject]@{ phone = [pscustomobject]@{ id = '+14255550100'; displayName = '=2+2' } }
        }
        $next = "{0}/communications/callRecords/{1}/participants_v2?`$skiptoken=participants2" -f $Client.BaseUrl, $fixture.CallA
        $payload = [ordered]@{
            value              = @($alice, $dave, $bob, $phone)
            '@odata.nextLink'  = $next
        }
        return (New-SampleHttpResponse -Status 200 -Raw (ConvertTo-JsonSafe ([pscustomobject]$payload)))
    }
    if ($CallId -eq $fixture.CallB) {
        $alice = New-SampleParticipant -Kind 'user' -Id $fixture.AliceId -Name 'Alice Adams' -Tenant $fixture.HomeTenantId -Upn $fixture.AliceUpn
        $erin = New-SampleParticipant -Kind 'user' -Id $fixture.ErinId -Name 'Erin Ellis' -Tenant $homeUpper -Upn 'erin@contoso.com'
        return (New-SampleHttpResponse -Status 200 -Raw (ConvertTo-JsonSafe ([pscustomobject]@{ value = @($alice, $erin) })))
    }
    return (New-SampleHttpResponse -Status 200 -Raw '{"value":[]}')
}

function New-SampleManagerResponse {
    param($Client, [string]$UserId)
    if ($Client.Managers.ContainsKey($UserId)) {
        return (New-SampleHttpResponse -Status 200 -Raw (ConvertTo-JsonSafe $Client.Directory[$Client.Managers[$UserId]]))
    }
    return (New-SampleHttpResponse -Status 404 -Raw '{"error":{"code":"Request_ResourceNotFound","message":"Manager not found."}}')
}

function New-SampleUserResponse {
    param($Client, [string]$Key)
    $fixture = $Client.Fixture
    if ($Client.Directory.ContainsKey($Key)) {
        return (New-SampleHttpResponse -Status 200 -Raw (ConvertTo-JsonSafe $Client.Directory[$Key]))
    }
    if ($Key.Equals($fixture.AliceUpn, [StringComparison]::OrdinalIgnoreCase)) {
        return (New-SampleHttpResponse -Status 200 -Raw (ConvertTo-JsonSafe $Client.Directory[$fixture.AliceId]))
    }
    return (New-SampleHttpResponse -Status 404 -Raw '{"error":{"code":"Request_ResourceNotFound","message":"User not found."}}')
}

function New-SampleUserSearchResponse {
    param($Client, [string]$Query)
    $fixture = $Client.Fixture
    $alice = $Client.Directory[$fixture.AliceId]
    if ($Query -match [regex]::Escape($fixture.AliceMail) -or $Query -match [regex]::Escape($fixture.AliceUpn) -or $Query -match 'Alice Adams') {
        return (New-SampleHttpResponse -Status 200 -Raw (ConvertTo-JsonSafe ([pscustomobject]@{ value = @($alice) })))
    }
    return (New-SampleHttpResponse -Status 200 -Raw '{"value":[]}')
}

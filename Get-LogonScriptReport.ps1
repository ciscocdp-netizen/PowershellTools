#Requires -Version 5.1
<#
.SYNOPSIS
    Finds Active Directory users with a Logon Script and writes an HTML dashboard
    plus raw CSV/JSON exports whose counts match the dashboard.

.DESCRIPTION
    Queries AD for accounts that have ScriptPath set and builds:
      - A self-contained HTML dashboard (filter, sort, charts, CSV/JSON export)
      - Companion raw-data files next to the HTML so totals can be audited in Excel

    Numbering fixes versus the original report:
      - Script paths are JSON-escaped. Windows paths such as scripts\logon.bat
        were injected raw, so JavaScript treated \l as an escape and collapsed
        distinct scripts, which made KPI / chart / table counts disagree.
      - JSON no longer HTML-encodes values (&quot; / &amp;), which previously
        broke filters and made names look wrong.
      - Script grouping is case-insensitive and slash-normalized, matching AD.
        The original used a case-insensitive PowerShell hashtable but
        case-sensitive JavaScript comparisons, so "Logon.bat" and "logon.bat"
        counted as one script in KPIs and as two in the table filter.
      - Get-ADUser / Where-Object results are wrapped in @() so 0- and 1-row
        result sets do not throw under StrictMode or report a blank Count.
      - Empty / whitespace ScriptPath rows are excluded before totals are
        calculated, so console, HTML, JSON and CSV share one processed count.
      - Chart labels stay unique when two paths share a file name.
      - Runtime integrity check: sum(script counts) == user rows, and
        enabled + disabled == user rows. Mismatches fail the run.

.PARAMETER OutputPath
    HTML report path. Defaults to a timestamped file in the script directory
    (or a Save dialog on Windows).

.PARAMETER SearchBase
    Distinguished Name of the OU to search. Defaults to the domain root.

.PARAMETER IncludeDisabledUsers
    Include disabled accounts. They are excluded by default.

.PARAMETER Server
    Domain controller to query. Defaults to automatic DC discovery.

.PARAMETER SkipRawExport
    Do not write the companion CSV/JSON raw-data files.

.PARAMETER RawCsvPath
    Override path for the per-user raw CSV. Default: <html>_users.csv

.PARAMETER RawJsonPath
    Override path for the raw JSON package. Default: <html>_users.json

.PARAMETER ScriptCsvPath
    Override path for the script-inventory CSV. Default: <html>_scripts.csv

.PARAMETER SkipBrowser
    Do not open the HTML report after it is written.

.PARAMETER SelfTest
    Run built-in unit tests (no Active Directory required) and exit 0/1.

.EXAMPLE
    .\Get-LogonScriptReport.ps1

.EXAMPLE
    .\Get-LogonScriptReport.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -IncludeDisabledUsers

.EXAMPLE
    .\Get-LogonScriptReport.ps1 -OutputPath "C:\Reports\LogonScripts.html" -Server "DC01"

.EXAMPLE
    .\Get-LogonScriptReport.ps1 -SelfTest

.NOTES
    Author      : v0 / Vercel (debugged)
    Version     : 1.1
    Requires    : ActiveDirectory PowerShell Module (RSAT) unless -SelfTest
    PowerShell  : 5.1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$SearchBase,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabledUsers,

    [Parameter(Mandatory = $false)]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [switch]$SkipRawExport,

    [Parameter(Mandatory = $false)]
    [string]$RawCsvPath,

    [Parameter(Mandatory = $false)]
    [string]$RawJsonPath,

    [Parameter(Mandatory = $false)]
    [string]$ScriptCsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipBrowser,

    [Parameter(Mandatory = $false)]
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helper Functions ─────────────────────────────────────────────────────

function Write-Header {
    param([string]$Text)
    $line = [string]::new([char]0x2500, 70)
    Write-Host ""
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor DarkCyan
}

function Write-Step {
    param([string]$Text)
    Write-Host "  [>] $Text" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Text)
    Write-Host "  [OK] $Text" -ForegroundColor Green
}

function Write-Info {
    param([string]$Text)
    Write-Host "  [i] $Text" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Text)
    Write-Host "  [!] $Text" -ForegroundColor DarkYellow
}

function Get-PropertyValue {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    return $prop.Value
}

function Get-AsArray {
    <#
    .SYNOPSIS
        Normalize Get-ADUser / pipeline output so 0, 1 and N rows all have .Count
        and can be enumerated under StrictMode.

        Returns a List so PowerShell cannot unwrap a 0- or 1-item result to $null
        or a scalar (which has no Count under StrictMode).
    #>
    param($Value)
    $acc = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Value) { return , $acc }
    if ($Value -is [string]) {
        $acc.Add($Value)
        return , $acc
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $acc.Add($Value)
        return , $acc
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($item in $Value) { $acc.Add($item) }
        return , $acc
    }
    $acc.Add($Value)
    return , $acc
}

function Convert-ADDateToString {
    param(
        $DateValue,
        [string]$Format = 'yyyy-MM-dd HH:mm'
    )
    if ($null -eq $DateValue -or $DateValue -eq [DateTime]::MinValue) {
        return 'Never'
    }
    try {
        if ($DateValue -is [DateTime]) {
            if ($DateValue.Year -lt 1970) { return 'Never' }
            return $DateValue.ToString($Format)
        }
        $dt = [DateTime]::FromFileTime([int64]$DateValue)
        if ($dt.Year -lt 1970) { return 'Never' }
        return $dt.ToString($Format)
    } catch {
        return 'Unknown'
    }
}

function Get-OUFromDN {
    param([string]$DistinguishedName)
    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return 'N/A' }
    # Split on commas that are not escaped as \,
    $parts = [regex]::Split($DistinguishedName, '(?<!\\),')
    if ($parts.Count -gt 1) {
        return ($parts[1..($parts.Count - 1)] -join ',')
    }
    return $DistinguishedName
}

function Get-CanonicalScriptPath {
    <#
    .SYNOPSIS
        Trim, convert / to \, collapse duplicate slashes, preserve UNC \\ prefix.
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $p = $Path.Trim() -replace '/', '\'
    if ($p.StartsWith('\\')) {
        $rest = $p.Substring(2) -replace '\\{2,}', '\'
        return '\\' + $rest
    }
    return ($p -replace '\\{2,}', '\')
}

function Get-ScriptGroupKey {
    param([string]$CanonicalPath)
    if ([string]::IsNullOrWhiteSpace($CanonicalPath)) { return '' }
    return $CanonicalPath.ToLowerInvariant()
}

function Get-ScriptFileName {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $canonical = Get-CanonicalScriptPath -Path $Path
    if ($canonical -match '[\\/]') {
        $leaf = $canonical
        $idx = $leaf.LastIndexOf('\')
        if ($idx -ge 0 -and $idx -lt ($leaf.Length - 1)) {
            return $leaf.Substring($idx + 1)
        }
    }
    return $canonical
}

function Escape-HtmlString {
    param([string]$str)
    if ([string]::IsNullOrEmpty($str)) { return '' }
    $str = $str.Replace('&',  '&amp;')
    $str = $str.Replace('<',  '&lt;')
    $str = $str.Replace('>',  '&gt;')
    $str = $str.Replace('"',  '&quot;')
    $str = $str.Replace("'",  '&#39;')
    return $str
}

function Escape-JsonString {
    <#
    .SYNOPSIS
        RFC 8259 string escape. Required for Windows script paths (backslashes).
    #>
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    $sb = New-Object System.Text.StringBuilder ($Value.Length + 16)
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '"'  { [void]$sb.Append('\"') }
            '\'  { [void]$sb.Append('\\') }
            "`b" { [void]$sb.Append('\b') }
            "`f" { [void]$sb.Append('\f') }
            "`n" { [void]$sb.Append('\n') }
            "`r" { [void]$sb.Append('\r') }
            "`t" { [void]$sb.Append('\t') }
            default {
                $code = [int]$ch
                if ($code -lt 32 -or $code -eq 0x2028 -or $code -eq 0x2029) {
                    [void]$sb.AppendFormat('\u{0:x4}', $code)
                } else {
                    [void]$sb.Append($ch)
                }
            }
        }
    }
    return $sb.ToString()
}

function ConvertTo-EmbeddedJson {
    <#
    .SYNOPSIS
        JSON text safe to drop inside a <script> tag.
    #>
    param([string]$Json)
    if ([string]::IsNullOrEmpty($Json)) { return $Json }
    return $Json.Replace('</', '<\/')
}

function Get-LastLogonString {
    param($User)
    $lastLogonDate = Get-PropertyValue -Object $User -Name 'LastLogonDate'
    if ($null -ne $lastLogonDate -and $lastLogonDate -ne [DateTime]::MinValue) {
        return Convert-ADDateToString -DateValue $lastLogonDate
    }
    $ts = Get-PropertyValue -Object $User -Name 'LastLogonTimestamp'
    if ($null -ne $ts) {
        return Convert-ADDateToString -DateValue $ts
    }
    return 'Never'
}

#endregion

#region ── Analytics ────────────────────────────────────────────────────────────

function Build-LogonScriptAnalytics {
    <#
    .SYNOPSIS
        Build the single source of truth used by the HTML, CSV, JSON and console.
    #>
    param(
        [Parameter(Mandatory = $true)]
        $Users
    )

    $userRows = New-Object System.Collections.Generic.List[object]
    $scriptUsageMap = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)
    $scriptDisplayMap = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $scriptOriginalMap = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $scriptUsersMap = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]' ([System.StringComparer]::OrdinalIgnoreCase)
    $ouMap = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)
    $deptMap = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)

    $enabledCount = 0
    $disabledCount = 0
    $skippedEmptyScript = 0

    foreach ($u in (Get-AsArray $Users)) {
        $rawScript = Get-PropertyValue -Object $u -Name 'ScriptPath'
        if ($null -eq $rawScript) { $rawScript = '' }
        $rawScript = [string]$rawScript
        $trimmed = $rawScript.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            $skippedEmptyScript++
            continue
        }

        $canonical = Get-CanonicalScriptPath -Path $trimmed
        $groupKey = Get-ScriptGroupKey -CanonicalPath $canonical
        if (-not $scriptDisplayMap.ContainsKey($groupKey)) {
            $scriptDisplayMap[$groupKey] = $canonical
            $scriptOriginalMap[$groupKey] = $trimmed
            $scriptUsageMap[$groupKey] = 0
            $scriptUsersMap[$groupKey] = New-Object 'System.Collections.Generic.List[string]'
        }
        $groupedPath = $scriptDisplayMap[$groupKey]
        $scriptName = Get-ScriptFileName -Path $groupedPath

        $ou = Get-OUFromDN -DistinguishedName ([string](Get-PropertyValue -Object $u -Name 'DistinguishedName'))
        $lastLogon = Get-LastLogonString -User $u

        $createdVal = Get-PropertyValue -Object $u -Name 'Created'
        $created = 'Unknown'
        if ($null -ne $createdVal) {
            $created = Convert-ADDateToString -DateValue $createdVal -Format 'yyyy-MM-dd'
            if ($created -eq 'Never') { $created = 'Unknown' }
        }

        $deptRaw = Get-PropertyValue -Object $u -Name 'Department'
        $titleRaw = Get-PropertyValue -Object $u -Name 'Title'
        $dept = if ([string]::IsNullOrWhiteSpace([string]$deptRaw)) { 'Unspecified' } else { [string]$deptRaw }
        $title = if ([string]::IsNullOrWhiteSpace([string]$titleRaw)) { 'Unspecified' } else { [string]$titleRaw }

        $sam = [string](Get-PropertyValue -Object $u -Name 'SamAccountName')
        $displayRaw = Get-PropertyValue -Object $u -Name 'DisplayName'
        $display = if ([string]::IsNullOrWhiteSpace([string]$displayRaw)) { $sam } else { [string]$displayRaw }
        $upnRaw = Get-PropertyValue -Object $u -Name 'UserPrincipalName'
        $enabled = [bool](Get-PropertyValue -Object $u -Name 'Enabled' -Default $true)

        $pwdLastSet = Get-PropertyValue -Object $u -Name 'PasswordLastSet'
        $pwdLastSetText = if ($null -eq $pwdLastSet) { '' } else { Convert-ADDateToString -DateValue $pwdLastSet -Format 'yyyy-MM-dd HH:mm' }

        $row = [pscustomobject][ordered]@{
            SamAccountName      = $sam
            DisplayName         = $display
            GivenName           = [string](Get-PropertyValue -Object $u -Name 'GivenName' -Default '')
            Surname             = [string](Get-PropertyValue -Object $u -Name 'Surname' -Default '')
            UserPrincipalName   = if ([string]::IsNullOrWhiteSpace([string]$upnRaw)) { '' } else { [string]$upnRaw }
            EmailAddress        = [string](Get-PropertyValue -Object $u -Name 'EmailAddress' -Default '')
            ScriptPath          = $groupedPath
            ScriptPathOriginal  = $trimmed
            ScriptKey           = $groupKey
            ScriptName          = $scriptName
            OU                  = $ou
            DistinguishedName   = [string](Get-PropertyValue -Object $u -Name 'DistinguishedName' -Default '')
            Enabled             = $enabled
            LastLogon           = $lastLogon
            Created             = $created
            Department          = $dept
            Title               = $title
            Description         = [string](Get-PropertyValue -Object $u -Name 'Description' -Default '')
            PasswordLastSet     = $pwdLastSetText
            PasswordNeverExpires = [bool](Get-PropertyValue -Object $u -Name 'PasswordNeverExpires' -Default $false)
            LockedOut           = [bool](Get-PropertyValue -Object $u -Name 'LockedOut' -Default $false)
        }
        $userRows.Add($row)

        $scriptUsageMap[$groupKey]++
        $scriptUsersMap[$groupKey].Add($sam)

        if (-not $ouMap.ContainsKey($ou)) { $ouMap[$ou] = 0 }
        $ouMap[$ou]++

        if (-not $deptMap.ContainsKey($dept)) { $deptMap[$dept] = 0 }
        $deptMap[$dept]++

        if ($enabled) { $enabledCount++ } else { $disabledCount++ }
    }

    $scriptAnalytics = New-Object System.Collections.Generic.List[object]
    foreach ($kvp in ($scriptUsageMap.GetEnumerator() | Sort-Object @{ Expression = 'Value'; Descending = $true }, @{ Expression = 'Key' })) {
        $key = $kvp.Key
        $scriptAnalytics.Add([pscustomobject][ordered]@{
            Script     = $scriptDisplayMap[$key]
            ScriptKey  = $key
            Name       = Get-ScriptFileName -Path $scriptDisplayMap[$key]
            Original   = $scriptOriginalMap[$key]
            Count      = [int]$kvp.Value
            Users      = @($scriptUsersMap[$key])
        })
    }

    $ouAnalytics = @(
        $ouMap.GetEnumerator() |
            Sort-Object @{ Expression = 'Value'; Descending = $true }, @{ Expression = 'Key' } |
            Select-Object -First 10 |
            ForEach-Object {
                [pscustomobject][ordered]@{ OU = $_.Key; Count = [int]$_.Value }
            }
    )

    $deptAnalytics = @(
        $deptMap.GetEnumerator() |
            Sort-Object @{ Expression = 'Value'; Descending = $true }, @{ Expression = 'Key' } |
            Select-Object -First 12 |
            ForEach-Object {
                [pscustomobject][ordered]@{ Department = $_.Key; Count = [int]$_.Value }
            }
    )

    $totalUsers = $userRows.Count
    $uniqueScripts = $scriptUsageMap.Count
    $scriptSum = 0
    foreach ($c in $scriptUsageMap.Values) { $scriptSum += [int]$c }

    if ($scriptSum -ne $totalUsers) {
        throw "Integrity check failed: sum of per-script counts ($scriptSum) does not equal processed users ($totalUsers)."
    }
    if (($enabledCount + $disabledCount) -ne $totalUsers) {
        throw "Integrity check failed: enabled ($enabledCount) + disabled ($disabledCount) does not equal processed users ($totalUsers)."
    }
    if ($uniqueScripts -ne $scriptAnalytics.Count) {
        throw "Integrity check failed: unique script map ($uniqueScripts) does not equal analytics rows ($($scriptAnalytics.Count))."
    }

    return [pscustomobject]@{
        Users               = $userRows
        Scripts             = $scriptAnalytics
        TopOUs              = $ouAnalytics
        TopDepartments      = $deptAnalytics
        TotalUsers          = $totalUsers
        UniqueScripts       = $uniqueScripts
        EnabledCount        = $enabledCount
        DisabledCount       = $disabledCount
        SkippedEmptyScript  = $skippedEmptyScript
        ScriptCountSum      = $scriptSum
    }
}

function ConvertTo-UserDataJson {
    param($Users)
    $items = foreach ($row in (Get-AsArray $Users)) {
        $enabled = if ($row.Enabled) { 'true' } else { 'false' }
        '{' +
            '"sam":"' + (Escape-JsonString $row.SamAccountName) + '",' +
            '"display":"' + (Escape-JsonString $row.DisplayName) + '",' +
            '"upn":"' + (Escape-JsonString $row.UserPrincipalName) + '",' +
            '"ou":"' + (Escape-JsonString $row.OU) + '",' +
            '"script":"' + (Escape-JsonString $row.ScriptPath) + '",' +
            '"scriptKey":"' + (Escape-JsonString $row.ScriptKey) + '",' +
            '"scriptOriginal":"' + (Escape-JsonString $row.ScriptPathOriginal) + '",' +
            '"scriptName":"' + (Escape-JsonString $row.ScriptName) + '",' +
            '"enabled":' + $enabled + ',' +
            '"lastLogon":"' + (Escape-JsonString $row.LastLogon) + '",' +
            '"created":"' + (Escape-JsonString $row.Created) + '",' +
            '"dept":"' + (Escape-JsonString $row.Department) + '",' +
            '"title":"' + (Escape-JsonString $row.Title) + '"' +
        '}'
    }
    return '[' + (($items | ForEach-Object { $_ }) -join ',') + ']'
}

function ConvertTo-ScriptAnalyticsJson {
    param($Scripts)
    $items = foreach ($s in (Get-AsArray $Scripts)) {
        $uArr = (@($s.Users) | ForEach-Object { '"' + (Escape-JsonString $_) + '"' }) -join ','
        '{' +
            '"script":"' + (Escape-JsonString $s.Script) + '",' +
            '"scriptKey":"' + (Escape-JsonString $s.ScriptKey) + '",' +
            '"name":"' + (Escape-JsonString $s.Name) + '",' +
            '"count":' + [int]$s.Count + ',' +
            '"users":[' + $uArr + ']' +
        '}'
    }
    return '[' + (($items | ForEach-Object { $_ }) -join ',') + ']'
}

function ConvertTo-OuJson {
    param($OUs)
    $items = foreach ($o in (Get-AsArray $OUs)) {
        '{"ou":"' + (Escape-JsonString $o.OU) + '","count":' + [int]$o.Count + '}'
    }
    return '[' + (($items | ForEach-Object { $_ }) -join ',') + ']'
}

function ConvertTo-DeptJson {
    param($Depts)
    $items = foreach ($d in (Get-AsArray $Depts)) {
        '{"dept":"' + (Escape-JsonString $d.Department) + '","count":' + [int]$d.Count + '}'
    }
    return '[' + (($items | ForEach-Object { $_ }) -join ',') + ']'
}

function ConvertTo-JsonValue {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int] -or $Value -is [long] -or $Value -is [decimal] -or $Value -is [double] -or $Value -is [single]) {
        return ([string]$Value)
    }
    if ($Value -is [string]) { return '"' + (Escape-JsonString $Value) + '"' }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = foreach ($key in $Value.Keys) {
            '"' + (Escape-JsonString ([string]$key)) + '":' + (ConvertTo-JsonValue $Value[$key])
        }
        return '{' + (($parts | ForEach-Object { $_ }) -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = foreach ($item in $Value) { ConvertTo-JsonValue $item }
        return '[' + (($parts | ForEach-Object { $_ }) -join ',') + ']'
    }
    $props = @($Value.PSObject.Properties)
    if ($props.Count -gt 0) {
        $parts = foreach ($p in $props) {
            '"' + (Escape-JsonString $p.Name) + '":' + (ConvertTo-JsonValue $p.Value)
        }
        return '{' + (($parts | ForEach-Object { $_ }) -join ',') + '}'
    }
    return '"' + (Escape-JsonString ([string]$Value)) + '"'
}

function Test-JsonRoundTripCounts {
    param(
        [string]$UserJson,
        [string]$ScriptJson,
        [int]$ExpectedUsers,
        [int]$ExpectedScripts
    )
    $users = @(ConvertFrom-Json -InputObject $UserJson)
    $scripts = @(ConvertFrom-Json -InputObject $ScriptJson)
    if ($users.Count -ne $ExpectedUsers) {
        throw "JSON round-trip user count $($users.Count) != $ExpectedUsers"
    }
    if ($scripts.Count -ne $ExpectedScripts) {
        throw "JSON round-trip script count $($scripts.Count) != $ExpectedScripts"
    }
    $sum = 0
    foreach ($s in $scripts) { $sum += [int]$s.count }
    if ($sum -ne $ExpectedUsers) {
        throw "JSON script counts sum $sum != $ExpectedUsers"
    }
    foreach ($s in $scripts) {
        $listed = (Get-AsArray $s.users).Count
        if ($listed -ne [int]$s.count) {
            throw "Script '$($s.script)' lists $listed users but count is $($s.count)"
        }
    }
}

function Export-LogonScriptRawData {
    param(
        $Analytics,
        [string]$CsvPath,
        [string]$JsonPath,
        [string]$ScriptCsvPath,
        [hashtable]$Meta
    )

    $users = Get-AsArray $Analytics.Users

    if (-not [string]::IsNullOrWhiteSpace($CsvPath)) {
        $dir = Split-Path -Parent $CsvPath
        if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $users | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Success "Raw user CSV written: $CsvPath  ($($users.Count) rows)"
    }

    if (-not [string]::IsNullOrWhiteSpace($ScriptCsvPath)) {
        $dir = Split-Path -Parent $ScriptCsvPath
        if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $scriptRows = foreach ($s in (Get-AsArray $Analytics.Scripts)) {
            $pct = if ($Analytics.TotalUsers -gt 0) {
                [math]::Round(($s.Count / $Analytics.TotalUsers) * 100, 1)
            } else { 0 }
            [pscustomobject][ordered]@{
                ScriptName      = $s.Name
                ScriptPath      = $s.Script
                ScriptKey       = $s.ScriptKey
                UserCount       = $s.Count
                PercentOfUsers  = $pct
                Users           = (@($s.Users) -join '; ')
            }
        }
        $scriptRows | Export-Csv -Path $ScriptCsvPath -NoTypeInformation -Encoding UTF8
        Write-Success "Script inventory CSV written: $ScriptCsvPath  ($($Analytics.UniqueScripts) rows)"
    }

    if (-not [string]::IsNullOrWhiteSpace($JsonPath)) {
        $dir = Split-Path -Parent $JsonPath
        if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $json = '{' +
            '"meta":' + (ConvertTo-JsonValue $Meta) + ',' +
            '"users":' + (ConvertTo-JsonValue $Analytics.Users) + ',' +
            '"scripts":' + (ConvertTo-JsonValue $Analytics.Scripts) +
        '}'
        $utf8 = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($JsonPath, $json, $utf8)
        Write-Success "Raw JSON package written: $JsonPath"
    }
}

#endregion

#region ── HTML dashboard ───────────────────────────────────────────────────────

function Get-LogonScriptReportHtmlTemplate {
    return @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>AD Logon Script Report &mdash; ##REPORT_DOMAIN##</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0d1117; --bg-card: #161b22; --bg-card2: #1c2333; --bg-hover: #21262d;
    --border: #30363d; --border-light: #444c56; --text: #e6edf3; --text-muted: #8b949e;
    --text-dim: #6e7681; --accent: #58a6ff; --accent-glow: rgba(88,166,255,0.15);
    --green: #3fb950; --green-bg: rgba(63,185,80,0.12); --red: #f85149;
    --red-bg: rgba(248,81,73,0.12); --yellow: #d29922; --purple: #a371f7;
    --orange: #f0883e; --teal: #39d353; --radius: 8px; --radius-lg: 12px;
    --shadow: 0 4px 24px rgba(0,0,0,0.4);
    --font-mono: Consolas, "Cascadia Code", "Courier New", monospace;
  }
  html, body { height: 100%; }
  body {
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    font-size: 14px; line-height: 1.5; min-height: 100vh;
  }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .page-wrap { display: flex; flex-direction: column; min-height: 100vh; }
  header {
    background: var(--bg-card); border-bottom: 1px solid var(--border);
    padding: 0 24px; position: sticky; top: 0; z-index: 100;
  }
  .header-inner {
    max-width: 1600px; margin: 0 auto; display: flex; align-items: center;
    justify-content: space-between; gap: 16px; height: 60px;
  }
  .header-brand { display: flex; align-items: center; gap: 10px; }
  .brand-icon {
    width: 34px; height: 34px;
    background: linear-gradient(135deg, var(--accent) 0%, var(--purple) 100%);
    border-radius: 8px; display: flex; align-items: center; justify-content: center;
    font-size: 16px; flex-shrink: 0;
  }
  .brand-text h1 { font-size: 15px; font-weight: 600; line-height: 1.2; }
  .brand-text p { font-size: 11px; color: var(--text-muted); }
  .header-meta { display: flex; align-items: center; gap: 20px; font-size: 12px; color: var(--text-muted); }
  .header-meta span { display: flex; align-items: center; gap: 5px; }
  .live-dot {
    width: 7px; height: 7px; background: var(--green); border-radius: 50%;
    box-shadow: 0 0 6px var(--green); animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
  main { flex: 1; padding: 28px 24px; max-width: 1600px; margin: 0 auto; width: 100%; }
  footer {
    border-top: 1px solid var(--border); padding: 16px 24px; text-align: center;
    font-size: 12px; color: var(--text-dim); background: var(--bg-card);
  }
  .section-title {
    font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--text-muted); margin-bottom: 14px; display: flex; align-items: center; gap: 8px;
  }
  .section-title::after { content: ""; flex: 1; height: 1px; background: var(--border); }
  .section-sep { margin-bottom: 32px; }
  .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 32px; }
  .kpi-card {
    background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius-lg);
    padding: 20px; position: relative; overflow: hidden; transition: border-color .2s, transform .15s;
  }
  .kpi-card:hover { border-color: var(--border-light); transform: translateY(-2px); }
  .kpi-card::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px; }
  .kpi-card.blue::before { background: var(--accent); }
  .kpi-card.green::before { background: var(--green); }
  .kpi-card.red::before { background: var(--red); }
  .kpi-card.purple::before { background: var(--purple); }
  .kpi-card.orange::before { background: var(--orange); }
  .kpi-card.teal::before { background: var(--teal); }
  .kpi-label { font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: .06em; color: var(--text-muted); margin-bottom: 10px; }
  .kpi-value { font-size: 32px; font-weight: 700; line-height: 1; font-variant-numeric: tabular-nums; }
  .kpi-value.kpi-text { font-size: 18px; word-break: break-all; }
  .kpi-sub { font-size: 11px; color: var(--text-dim); margin-top: 6px; }
  .charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 32px; }
  .chart-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 20px; }
  .chart-card-wide { grid-column: 1 / -1; }
  .chart-title { font-size: 13px; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
  .chart-title .badge {
    font-size: 11px; background: var(--bg-card2); border: 1px solid var(--border);
    border-radius: 20px; padding: 2px 8px; color: var(--text-muted); font-weight: 400;
  }
  .chart-wrap { position: relative; height: 260px; }
  .chart-wrap-sm { height: 220px; }
  .script-analytics-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 32px; }
  .script-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden; }
  .script-card-header { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .script-card-header h3 { font-size: 13px; font-weight: 600; }
  .script-list { list-style: none; max-height: 340px; overflow-y: auto; }
  .script-item {
    display: flex; align-items: center; gap: 12px; padding: 12px 20px;
    border-bottom: 1px solid var(--border); cursor: pointer;
  }
  .script-item:hover { background: var(--bg-hover); }
  .script-item.active { background: var(--accent-glow); border-left: 3px solid var(--accent); }
  .script-rank { font-size: 11px; color: var(--text-dim); width: 20px; text-align: right; flex-shrink: 0; }
  .script-info { flex: 1; min-width: 0; }
  .script-name { font-size: 13px; font-weight: 500; color: var(--accent); font-family: var(--font-mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .script-path { font-size: 11px; color: var(--text-dim); font-family: var(--font-mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 2px; }
  .script-count-wrap { display: flex; flex-direction: column; align-items: flex-end; flex-shrink: 0; }
  .script-count { font-size: 18px; font-weight: 700; font-variant-numeric: tabular-nums; }
  .script-pct { font-size: 10px; color: var(--text-dim); }
  .bar-wrap { width: 80px; height: 4px; background: var(--border); border-radius: 2px; margin-top: 4px; overflow: hidden; }
  .bar-fill { height: 100%; background: var(--accent); border-radius: 2px; }
  .table-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden; margin-bottom: 32px; }
  .table-toolbar { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .table-toolbar h2 { font-size: 14px; font-weight: 600; margin-right: auto; }
  .search-wrap { position: relative; flex: 0 0 260px; }
  .search-wrap svg { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); color: var(--text-dim); pointer-events: none; }
  .search-input {
    width: 100%; padding: 7px 10px 7px 34px; background: var(--bg); border: 1px solid var(--border);
    border-radius: var(--radius); color: var(--text); font-size: 13px; outline: none;
  }
  .search-input:focus { border-color: var(--accent); }
  select.filter-select {
    padding: 7px 10px; background: var(--bg); border: 1px solid var(--border);
    border-radius: var(--radius); color: var(--text); font-size: 13px; outline: none; cursor: pointer;
  }
  .btn {
    display: inline-flex; align-items: center; gap: 6px; padding: 7px 14px;
    border-radius: var(--radius); font-size: 13px; font-weight: 500; cursor: pointer;
    border: 1px solid transparent; white-space: nowrap;
  }
  .btn-primary { background: var(--accent); color: #0d1117; border-color: var(--accent); }
  .btn-ghost { background: transparent; color: var(--text-muted); border-color: var(--border); }
  .btn-ghost:hover { background: var(--bg-hover); color: var(--text); }
  .btn-green { background: var(--green-bg); color: var(--green); border-color: rgba(63,185,80,0.3); }
  .result-count { font-size: 12px; color: var(--text-dim); white-space: nowrap; }
  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead tr { background: var(--bg-card2); border-bottom: 1px solid var(--border); }
  th {
    padding: 10px 14px; text-align: left; font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: .06em; color: var(--text-muted);
    white-space: nowrap; user-select: none; cursor: pointer; background: var(--bg-card2);
  }
  th.sorted { color: var(--accent); }
  tbody tr { border-bottom: 1px solid var(--border); }
  tbody tr:hover { background: var(--bg-hover); }
  td { padding: 10px 14px; vertical-align: middle; max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  td.mono { font-family: var(--font-mono); font-size: 12px; color: var(--accent); }
  td.muted { color: var(--text-muted); }
  td.dim { color: var(--text-dim); font-size: 12px; }
  .badge-pill { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: 500; }
  .badge-enabled { background: var(--green-bg); color: var(--green); }
  .badge-disabled { background: var(--red-bg); color: var(--red); }
  .table-footer {
    padding: 12px 20px; border-top: 1px solid var(--border); display: flex;
    align-items: center; justify-content: space-between; font-size: 12px;
    color: var(--text-muted); background: var(--bg-card2); flex-wrap: wrap; gap: 8px;
  }
  .pagination { display: flex; align-items: center; gap: 4px; }
  .page-btn { padding: 4px 10px; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); color: var(--text-muted); font-size: 12px; cursor: pointer; }
  .page-btn.active { background: var(--accent); border-color: var(--accent); color: #0d1117; font-weight: 600; }
  .page-btn:disabled { opacity: 0.35; cursor: not-allowed; }
  .modal-overlay {
    display: none; position: fixed; inset: 0; background: rgba(0,0,0,.65);
    z-index: 200; align-items: center; justify-content: center;
  }
  .modal-overlay.open { display: flex; }
  .modal {
    background: var(--bg-card); border: 1px solid var(--border-light); border-radius: var(--radius-lg);
    width: min(700px, 95vw); max-height: 80vh; overflow: hidden; display: flex; flex-direction: column;
    box-shadow: 0 24px 64px rgba(0,0,0,.6);
  }
  .modal-header { padding: 18px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
  .modal-close { width: 28px; height: 28px; background: transparent; border: 1px solid var(--border); border-radius: 6px; cursor: pointer; color: var(--text-muted); }
  .modal-body { padding: 20px; overflow-y: auto; flex: 1; }
  .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px; }
  .detail-item { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px; }
  .detail-item label { display: block; font-size: 10px; text-transform: uppercase; letter-spacing: .06em; color: var(--text-dim); margin-bottom: 4px; }
  .detail-item .val { font-size: 13px; word-break: break-all; }
  .detail-item .val.mono { font-family: var(--font-mono); color: var(--accent); }
  .toast {
    position: fixed; bottom: 24px; right: 24px; background: var(--bg-card2);
    border: 1px solid var(--border-light); border-radius: var(--radius); padding: 12px 18px;
    font-size: 13px; z-index: 300; transform: translateY(80px); opacity: 0; transition: all .3s ease;
    display: flex; align-items: center; gap: 8px;
  }
  .toast.show { transform: translateY(0); opacity: 1; }
  .integrity-ok { color: var(--green); }
  .integrity-bad { color: var(--red); }
  @media (max-width: 900px) {
    .charts-grid, .script-analytics-grid, .detail-grid { grid-template-columns: 1fr; }
    .chart-card-wide { grid-column: auto; }
    .header-meta { display: none; }
    .search-wrap { flex: 1 1 200px; }
  }
  @media (max-width: 600px) {
    main { padding: 16px 12px; }
    .kpi-grid { grid-template-columns: repeat(2, 1fr); }
  }
  .empty-state { padding: 48px 20px; text-align: center; color: var(--text-dim); }
</style>
</head>
<body>
<div class="page-wrap">
<header>
  <div class="header-inner">
    <div class="header-brand">
      <div class="brand-icon">&#128274;</div>
      <div class="brand-text">
        <h1>AD Logon Script Report</h1>
        <p id="hdr-domain">Domain: ##REPORT_DOMAIN##</p>
      </div>
    </div>
    <div class="header-meta">
      <span><div class="live-dot"></div> Report ready</span>
      <span>Generated: ##REPORT_GEN_TIME##</span>
      <span>Domain: ##REPORT_DOMAIN##</span>
    </div>
  </div>
</header>
<main>
  <div class="section-sep">
    <p class="section-title">Overview</p>
    <div class="kpi-grid" id="kpi-grid"></div>
  </div>
  <div class="section-sep">
    <p class="section-title">Analytics</p>
    <div class="charts-grid">
      <div class="chart-card">
        <p class="chart-title">Top Scripts by User Count <span class="badge" id="top-scripts-badge"></span></p>
        <div class="chart-wrap"><canvas id="chartTopScripts"></canvas></div>
      </div>
      <div class="chart-card">
        <p class="chart-title">Script Distribution</p>
        <div class="chart-wrap"><canvas id="chartPie"></canvas></div>
      </div>
      <div class="chart-card chart-card-wide">
        <p class="chart-title">Users per Script &mdash; full breakdown <span class="badge" id="all-scripts-badge"></span></p>
        <div class="chart-wrap"><canvas id="chartAll"></canvas></div>
      </div>
      <div class="chart-card">
        <p class="chart-title">Top OUs by User Count <span class="badge">Top 10</span></p>
        <div class="chart-wrap chart-wrap-sm"><canvas id="chartOU"></canvas></div>
      </div>
      <div class="chart-card">
        <p class="chart-title">Users by Department <span class="badge">Top 12</span></p>
        <div class="chart-wrap chart-wrap-sm"><canvas id="chartDept"></canvas></div>
      </div>
    </div>
  </div>
  <div class="section-sep">
    <p class="section-title">Script Inventory</p>
    <div class="script-analytics-grid">
      <div class="script-card">
        <div class="script-card-header">
          <h3>Scripts by Usage (click to filter)</h3>
          <span>
            <button class="btn btn-ghost" id="btn-export-scripts" style="font-size:11px;padding:4px 10px">CSV</button>
            <span class="result-count" id="script-list-count"></span>
          </span>
        </div>
        <ul class="script-list" id="script-list"></ul>
      </div>
      <div class="script-card">
        <div class="script-card-header">
          <h3>Users of selected script</h3>
          <span class="result-count" id="script-user-count"></span>
        </div>
        <ul class="script-list" id="script-user-list">
          <li class="empty-state"><p>Click a script on the left to view its users</p></li>
        </ul>
      </div>
    </div>
  </div>
  <div class="section-sep">
    <p class="section-title">User Details</p>
    <div class="table-card">
      <div class="table-toolbar">
        <h2>All Users with Logon Scripts</h2>
        <div class="search-wrap">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input type="text" class="search-input" id="search-input" placeholder="Search users, scripts, OUs..." aria-label="Search users" />
        </div>
        <select class="filter-select" id="filter-script" aria-label="Filter by script"><option value="">All Scripts</option></select>
        <select class="filter-select" id="filter-status" aria-label="Filter by status">
          <option value="">All Status</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </select>
        <select class="filter-select" id="filter-dept" aria-label="Filter by department"><option value="">All Depts</option></select>
        <span class="result-count" id="result-count"></span>
        <button class="btn btn-green" id="btn-export-csv" title="Export the filtered table to CSV">Export CSV</button>
        <button class="btn btn-primary" id="btn-export-raw" title="Export every processed user (unfiltered raw data)">Export Raw</button>
        <button class="btn btn-ghost" id="btn-export-json" title="Export the full raw JSON package">JSON</button>
        <button class="btn btn-ghost" id="btn-clear-filters">Clear</button>
      </div>
      <div class="table-wrap">
        <table id="user-table" aria-label="Active Directory users with logon scripts">
          <thead>
            <tr>
              <th data-col="sam" class="sorted">SAM Account <span class="sort-icon">&#9650;</span></th>
              <th data-col="display">Display Name <span class="sort-icon">&#8645;</span></th>
              <th data-col="scriptName">Script Name <span class="sort-icon">&#8645;</span></th>
              <th data-col="script">Full Path <span class="sort-icon">&#8645;</span></th>
              <th data-col="enabled">Status <span class="sort-icon">&#8645;</span></th>
              <th data-col="dept">Department <span class="sort-icon">&#8645;</span></th>
              <th data-col="lastLogon">Last Logon <span class="sort-icon">&#8645;</span></th>
              <th data-col="ou">OU <span class="sort-icon">&#8645;</span></th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody id="table-body"></tbody>
        </table>
      </div>
      <div class="table-footer">
        <span id="footer-info"></span>
        <div class="pagination" id="pagination"></div>
        <select class="filter-select" id="page-size" aria-label="Rows per page">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
          <option value="999999">All</option>
        </select>
      </div>
    </div>
  </div>
</main>
<footer>
  AD Logon Script Report &bull; Generated ##REPORT_GEN_TIME## &bull; Domain: ##REPORT_DOMAIN## &bull;
  Total users processed: ##TOTAL_USERS## &bull; Unique scripts: ##UNIQUE_SCRIPTS## &bull;
  Integrity: <span id="integrity-label">checking…</span><br>
  ##RAW_EXPORT_NOTE##<br>
  Last logon is AD LastLogonDate (replicated lastLogonTimestamp), not a per-DC lastLogon sweep.
</footer>
</div>
<div class="modal-overlay" id="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="modal-title">
  <div class="modal">
    <div class="modal-header">
      <h2 id="modal-title">User Detail</h2>
      <button class="modal-close" id="modal-close" aria-label="Close detail panel">&#10005;</button>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>
<div class="toast" id="toast" role="status" aria-live="polite">
  <span class="toast-icon">&#10003;</span>
  <span id="toast-msg">Done</span>
</div>
<script>
const RAW_USERS    = ##USER_DATA_JSON##;
const RAW_SCRIPTS  = ##SCRIPT_ANALYTICS_JSON##;
const RAW_OUS      = ##OU_JSON##;
const RAW_DEPTS    = ##DEPT_JSON##;
const META = {
  totalUsers    : ##TOTAL_USERS##,
  uniqueScripts : ##UNIQUE_SCRIPTS##,
  enabledCount  : ##ENABLED_COUNT##,
  disabledCount : ##DISABLED_COUNT##,
  skippedEmpty  : ##SKIPPED_EMPTY##,
  reportTime    : "##REPORT_GEN_TIME##",
  domain        : "##REPORT_DOMAIN##"
};

let filteredData   = RAW_USERS.slice();
let sortCol        = 'sam';
let sortDir        = 'asc';
let currentPage    = 1;
let pageSize       = 25;
let selectedScript = null;

const PALETTE = ['#58a6ff','#3fb950','#f0883e','#a371f7','#39d353','#f85149','#d29922','#56d364','#79c0ff','#ff7b72','#ffa657','#d2a8ff'];
const PALETTE_ALPHA = PALETTE.map(c => c + 'bb');

function esc(s){ const d=document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
function showToast(msg){
  const t=document.getElementById('toast');
  document.getElementById('toast-msg').textContent=msg;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2800);
}
function fmtNum(n){ return Number(n).toLocaleString(); }
function scriptKeyOf(u){ return (u.scriptKey || String(u.script||'').replace(/\//g,'\\').toLowerCase()); }
function scriptEq(a,b){
  return String(a||'').replace(/\//g,'\\').toLowerCase() === String(b||'').replace(/\//g,'\\').toLowerCase();
}
function uniqueChartLabels(items, nameFn, keyFn){
  const names = items.map(nameFn);
  const freq = {};
  names.forEach(n => { freq[n] = (freq[n]||0)+1; });
  return items.map((it,i) => freq[names[i]] > 1 ? names[i] + ' · ' + keyFn(it) : names[i]);
}
function verifyIntegrity(){
  const sum = RAW_SCRIPTS.reduce((a,s)=>a + Number(s.count||0), 0);
  const enabled = RAW_USERS.filter(u=>u.enabled).length;
  const disabled = RAW_USERS.filter(u=>!u.enabled).length;
  const ok = sum === META.totalUsers &&
             RAW_USERS.length === META.totalUsers &&
             RAW_SCRIPTS.length === META.uniqueScripts &&
             enabled === META.enabledCount &&
             disabled === META.disabledCount &&
             (enabled + disabled) === META.totalUsers;
  const el = document.getElementById('integrity-label');
  el.textContent = ok
    ? ('OK — ' + fmtNum(sum) + ' script assignments = ' + fmtNum(META.totalUsers) + ' users')
    : ('MISMATCH — script sum ' + sum + ' / users ' + RAW_USERS.length + ' / meta ' + META.totalUsers);
  el.className = ok ? 'integrity-ok' : 'integrity-bad';
  return ok;
}

function buildKPIs(){
  const topScript = RAW_SCRIPTS.length ? RAW_SCRIPTS[0] : null;
  const maxCount  = topScript ? topScript.count : 0;
  const topName   = topScript ? topScript.name : 'N/A';
  const cards = [
    { label:'Total Users', val: fmtNum(META.totalUsers), sub:'Users with a non-empty logon script', color:'blue', text:false },
    { label:'Unique Scripts', val: fmtNum(META.uniqueScripts), sub:'Distinct paths (case / slash normalized)', color:'purple', text:false },
    { label:'Enabled Accounts', val: fmtNum(META.enabledCount), sub:'Active user accounts in this report', color:'green', text:false },
    { label:'Disabled Accounts', val: fmtNum(META.disabledCount), sub: META.disabledCount===0 ? 'Disabled accounts excluded or none found' : 'Disabled user accounts in this report', color:'red', text:false },
    { label:'Most Used Script', val: topName, sub: fmtNum(maxCount) + ' users', color:'orange', text:true },
    { label:'Domain', val: (META.domain.split('.')[0]||META.domain), sub: META.domain, color:'teal', text:true }
  ];
  document.getElementById('kpi-grid').innerHTML = cards.map(c => `
    <div class="kpi-card ${c.color}">
      <p class="kpi-label">${c.label}</p>
      <p class="kpi-value${c.text?' kpi-text':''}">${esc(String(c.val))}</p>
      <p class="kpi-sub">${esc(c.sub)}</p>
    </div>`).join('');
}

const CHART_DEFAULTS = {
  plugins: {
    legend: { labels: { color:'#8b949e', font:{ size:11 } } },
    tooltip: { backgroundColor:'#161b22', borderColor:'#30363d', borderWidth:1, titleColor:'#e6edf3', bodyColor:'#8b949e' }
  },
  scales: {
    x: { ticks:{ color:'#8b949e', font:{ size:11 } }, grid:{ color:'#21262d' } },
    y: { ticks:{ color:'#8b949e', font:{ size:11 } }, grid:{ color:'#21262d' } }
  }
};

function buildCharts(){
  if (typeof Chart === 'undefined') { return; }
  const top10 = RAW_SCRIPTS.slice(0, 10);
  document.getElementById('top-scripts-badge').textContent = 'Top ' + top10.length;
  new Chart(document.getElementById('chartTopScripts'), {
    type: 'bar',
    data: {
      labels: uniqueChartLabels(top10, s=>s.name, s=>s.script),
      datasets: [{ label:'Users', data: top10.map(s=>s.count), backgroundColor: PALETTE_ALPHA, borderColor: PALETTE, borderWidth: 1, borderRadius: 4 }]
    },
    options: { ...CHART_DEFAULTS, indexAxis:'y', responsive:true, maintainAspectRatio:false, plugins:{ ...CHART_DEFAULTS.plugins, legend:{ display:false } } }
  });

  const pieTop = RAW_SCRIPTS.slice(0, 8);
  const pieOtherCount = RAW_SCRIPTS.slice(8).reduce((a,s)=>a+s.count, 0);
  const pieItems = pieTop.slice();
  if (pieOtherCount > 0) pieItems.push({ name:'Others', script:'Others', count: pieOtherCount });
  new Chart(document.getElementById('chartPie'), {
    type: 'doughnut',
    data: { labels: uniqueChartLabels(pieItems, s=>s.name, s=>s.script), datasets:[{ data: pieItems.map(s=>s.count), backgroundColor: PALETTE_ALPHA, borderColor: PALETTE, borderWidth:1 }] },
    options: { responsive:true, maintainAspectRatio:false, plugins:{ ...CHART_DEFAULTS.plugins, legend:{ position:'right', labels:{ color:'#8b949e', font:{size:10}, boxWidth:12 } } } }
  });

  document.getElementById('all-scripts-badge').textContent = RAW_SCRIPTS.length + ' scripts';
  new Chart(document.getElementById('chartAll'), {
    type: 'bar',
    data: {
      labels: uniqueChartLabels(RAW_SCRIPTS, s=>s.name, s=>s.script),
      datasets:[{ label:'Users', data: RAW_SCRIPTS.map(s=>s.count), backgroundColor:'#58a6ffbb', borderColor:'#58a6ff', borderWidth:1, borderRadius:3 }]
    },
    options:{ ...CHART_DEFAULTS, responsive:true, maintainAspectRatio:false, plugins:{ ...CHART_DEFAULTS.plugins, legend:{display:false} } }
  });

  new Chart(document.getElementById('chartOU'),{
    type:'bar',
    data:{
      labels: RAW_OUS.map(o=>{ const p=String(o.ou||'').split(','); return p[0].replace(/^OU=/i,'').replace(/^CN=/i,''); }),
      datasets:[{ label:'Users', data:RAW_OUS.map(o=>o.count), backgroundColor:'#a371f7bb', borderColor:'#a371f7', borderWidth:1, borderRadius:3 }]
    },
    options:{...CHART_DEFAULTS, responsive:true, maintainAspectRatio:false, indexAxis:'y', plugins:{...CHART_DEFAULTS.plugins, legend:{display:false}} }
  });

  new Chart(document.getElementById('chartDept'),{
    type:'bar',
    data:{
      labels: RAW_DEPTS.map(d=>d.dept),
      datasets:[{ label:'Users', data:RAW_DEPTS.map(d=>d.count), backgroundColor:'#f0883ebb', borderColor:'#f0883e', borderWidth:1, borderRadius:3 }]
    },
    options:{...CHART_DEFAULTS, responsive:true, maintainAspectRatio:false, indexAxis:'y', plugins:{...CHART_DEFAULTS.plugins, legend:{display:false}} }
  });
}

function buildScriptList(){
  const list = document.getElementById('script-list');
  document.getElementById('script-list-count').textContent = RAW_SCRIPTS.length + ' scripts';
  if (!RAW_SCRIPTS.length){
    list.innerHTML='<li class="empty-state"><p>No scripts found</p></li>';
    return;
  }
  const maxC = RAW_SCRIPTS[0].count;
  list.innerHTML = RAW_SCRIPTS.map((s,i)=>{
    const pct = META.totalUsers > 0 ? Math.round((s.count/META.totalUsers)*100) : 0;
    const barW = maxC > 0 ? Math.round((s.count/maxC)*100) : 0;
    return `<li class="script-item" data-scriptkey="${esc(s.scriptKey||s.script)}" tabindex="0" role="button">
      <span class="script-rank">${i+1}</span>
      <span class="script-info">
        <span class="script-name" title="${esc(s.script)}">${esc(s.name)}</span>
        <span class="script-path" title="${esc(s.script)}">${esc(s.script)}</span>
      </span>
      <span class="script-count-wrap">
        <span class="script-count">${fmtNum(s.count)}</span>
        <span class="script-pct">${pct}% of users</span>
        <span class="bar-wrap"><span class="bar-fill" style="width:${barW}%"></span></span>
      </span>
    </li>`;
  }).join('');
  list.querySelectorAll('.script-item').forEach(li=>{
    li.addEventListener('click', ()=>selectScript(li.dataset.scriptkey));
    li.addEventListener('keydown', e=>{ if(e.key==='Enter'||e.key===' '){ e.preventDefault(); selectScript(li.dataset.scriptkey); } });
  });
}

function selectScript(scriptKey){
  selectedScript = selectedScript === scriptKey ? null : scriptKey;
  document.querySelectorAll('#script-list .script-item').forEach(li=>{
    li.classList.toggle('active', li.dataset.scriptkey === selectedScript);
  });
  const sel = document.getElementById('filter-script');
  sel.value = selectedScript || '';
  buildScriptUserList(selectedScript);
  applyFilters();
}

function buildScriptUserList(scriptKey){
  const ul  = document.getElementById('script-user-list');
  const ctr = document.getElementById('script-user-count');
  if (!scriptKey){
    ctr.textContent='';
    ul.innerHTML='<li class="empty-state"><p>Click a script on the left to view its users</p></li>';
    return;
  }
  const entry = RAW_SCRIPTS.find(s => scriptEq(s.scriptKey||s.script, scriptKey));
  if (!entry){ ul.innerHTML='<li class="empty-state"><p>Not found</p></li>'; return; }
  ctr.textContent = entry.users.length + ' users';
  ul.innerHTML = entry.users.slice().sort().map(u=>`
    <li class="script-item">
      <span class="script-info"><span class="script-name">${esc(u)}</span></span>
    </li>`).join('');
}

function populateFilterDropdowns(){
  const ss = document.getElementById('filter-script');
  RAW_SCRIPTS.forEach(s=>{
    const o = document.createElement('option');
    o.value = s.scriptKey || s.script;
    o.textContent = s.name + ' (' + s.count + ')';
    ss.appendChild(o);
  });
  const ds = document.getElementById('filter-dept');
  const depts = [...new Set(RAW_USERS.map(u=>u.dept))].sort();
  depts.forEach(d=>{
    const o = document.createElement('option');
    o.value = d; o.textContent = d;
    ds.appendChild(o);
  });
}

function applyFilters(){
  const q      = document.getElementById('search-input').value.trim().toLowerCase();
  const script = document.getElementById('filter-script').value;
  const status = document.getElementById('filter-status').value;
  const dept   = document.getElementById('filter-dept').value;

  filteredData = RAW_USERS.filter(u=>{
    if (script && !scriptEq(scriptKeyOf(u), script)) return false;
    if (status === 'enabled'  && !u.enabled)  return false;
    if (status === 'disabled' && u.enabled)   return false;
    if (dept   && u.dept !== dept)            return false;
    if (q){
      const hay = [u.sam, u.display, u.script, u.scriptOriginal, u.scriptName, u.ou, u.dept, u.title, u.upn].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  filteredData.sort((a,b)=>{
    let av = a[sortCol] ?? '';
    let bv = b[sortCol] ?? '';
    if (typeof av === 'boolean') av = av ? 1 : 0;
    if (typeof bv === 'boolean') bv = bv ? 1 : 0;
    const cmp = String(av).localeCompare(String(bv), undefined, {numeric:true, sensitivity:'base'});
    return sortDir === 'asc' ? cmp : -cmp;
  });

  currentPage = 1;
  renderTable();
}

function renderTable(){
  const tbody = document.getElementById('table-body');
  const start = (currentPage - 1) * pageSize;
  const page  = filteredData.slice(start, start + pageSize);
  document.getElementById('result-count').textContent =
    filteredData.length + ' of ' + fmtNum(RAW_USERS.length) + ' users';

  if (!filteredData.length){
    tbody.innerHTML = `<tr><td colspan="9" class="empty-state"><p>No users match the current filters.</p></td></tr>`;
  } else {
    tbody.innerHTML = page.map((u,i)=>{
      const statusBadge = u.enabled
        ? '<span class="badge-pill badge-enabled">Enabled</span>'
        : '<span class="badge-pill badge-disabled">Disabled</span>';
      const ouShort = String(u.ou||'').split(',')[0].replace(/^OU=/i,'').replace(/^CN=/i,'');
      return `<tr>
        <td><strong>${esc(u.sam)}</strong></td>
        <td class="muted">${esc(u.display)}</td>
        <td class="mono">${esc(u.scriptName)}</td>
        <td class="mono" title="${esc(u.script)}">${esc(u.script)}</td>
        <td>${statusBadge}</td>
        <td class="muted">${esc(u.dept)}</td>
        <td class="dim">${esc(u.lastLogon)}</td>
        <td class="dim" title="${esc(u.ou)}">${esc(ouShort)}</td>
        <td><button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" data-idx="${start+i}">View</button></td>
      </tr>`;
    }).join('');
    tbody.querySelectorAll('button[data-idx]').forEach(btn=>{
      btn.addEventListener('click', ()=>showDetail(Number(btn.dataset.idx)));
    });
  }
  renderPagination();
  updateFooter();
}

function renderPagination(){
  const totalPages = Math.max(1, Math.ceil(filteredData.length / pageSize));
  const pg = document.getElementById('pagination');
  if (totalPages <= 1){ pg.innerHTML=''; return; }
  let html = `<button class="page-btn" data-page="${currentPage-1}" ${currentPage===1?'disabled':''}>&#8249;</button>`;
  const range = new Set([1, totalPages, currentPage, currentPage-1, currentPage+1, currentPage+2, currentPage-2].filter(p=>p>=1&&p<=totalPages));
  const sorted = [...range].sort((a,b)=>a-b);
  let prev = 0;
  sorted.forEach(p=>{
    if (prev && p - prev > 1) html += `<span style="color:var(--text-dim);padding:0 4px">…</span>`;
    html += `<button class="page-btn ${p===currentPage?'active':''}" data-page="${p}">${p}</button>`;
    prev = p;
  });
  html += `<button class="page-btn" data-page="${currentPage+1}" ${currentPage===totalPages?'disabled':''}>&#8250;</button>`;
  pg.innerHTML = html;
  pg.querySelectorAll('button[data-page]').forEach(b=>b.addEventListener('click', ()=>goPage(Number(b.dataset.page))));
}

function updateFooter(){
  const totalPages = Math.max(1, Math.ceil(filteredData.length / pageSize));
  const start = (currentPage-1)*pageSize + 1;
  const end   = Math.min(currentPage*pageSize, filteredData.length);
  document.getElementById('footer-info').textContent =
    filteredData.length > 0
      ? 'Showing ' + fmtNum(start) + '–' + fmtNum(end) + ' of ' + fmtNum(filteredData.length) + ' users (page ' + currentPage + ' of ' + totalPages + ')'
      : 'No results';
}

function goPage(p){
  const totalPages = Math.max(1, Math.ceil(filteredData.length / pageSize));
  currentPage = Math.max(1, Math.min(p, totalPages));
  renderTable();
}

document.querySelectorAll('th[data-col]').forEach(th=>{
  th.addEventListener('click', ()=>{
    const col = th.dataset.col;
    if (sortCol === col){ sortDir = sortDir==='asc' ? 'desc' : 'asc'; }
    else { sortCol = col; sortDir = 'asc'; }
    document.querySelectorAll('th[data-col]').forEach(t=>{
      t.classList.remove('sorted');
      const ic = t.querySelector('.sort-icon');
      if (ic) ic.innerHTML = '&#8645;';
    });
    th.classList.add('sorted');
    const icon = th.querySelector('.sort-icon');
    if (icon) icon.innerHTML = sortDir==='asc' ? '&#9650;' : '&#9660;';
    applyFilters();
  });
});

function showDetail(idx){
  const u = filteredData[idx];
  if (!u) return;
  document.getElementById('modal-title').textContent = u.sam + ' — User Detail';
  document.getElementById('modal-body').innerHTML = `
    <div class="detail-grid">
      <div class="detail-item"><label>SAM Account Name</label><div class="val mono">${esc(u.sam)}</div></div>
      <div class="detail-item"><label>Display Name</label><div class="val">${esc(u.display)}</div></div>
      <div class="detail-item"><label>User Principal Name</label><div class="val mono">${esc(u.upn||'N/A')}</div></div>
      <div class="detail-item"><label>Status</label><div class="val">${u.enabled?'<span class="badge-pill badge-enabled">Enabled</span>':'<span class="badge-pill badge-disabled">Disabled</span>'}</div></div>
      <div class="detail-item" style="grid-column:1/-1"><label>Logon Script (grouped path)</label><div class="val mono">${esc(u.script)}</div></div>
      <div class="detail-item" style="grid-column:1/-1"><label>Logon Script (value stored in AD)</label><div class="val mono">${esc(u.scriptOriginal||u.script)}</div></div>
      <div class="detail-item"><label>Script File Name</label><div class="val mono">${esc(u.scriptName)}</div></div>
      <div class="detail-item"><label>Department</label><div class="val">${esc(u.dept)}</div></div>
      <div class="detail-item"><label>Job Title</label><div class="val">${esc(u.title)}</div></div>
      <div class="detail-item"><label>Last Logon</label><div class="val">${esc(u.lastLogon)}</div></div>
      <div class="detail-item"><label>Account Created</label><div class="val">${esc(u.created)}</div></div>
      <div class="detail-item" style="grid-column:1/-1"><label>Organisational Unit</label><div class="val mono" style="font-size:12px">${esc(u.ou)}</div></div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn btn-primary" id="btn-filter-this-script">Filter to this script</button>
      <button class="btn btn-ghost" id="btn-close-modal">Close</button>
    </div>`;
  document.getElementById('btn-filter-this-script').addEventListener('click', ()=>{
    closeModal();
    document.getElementById('filter-script').value = scriptKeyOf(u);
    selectedScript = scriptKeyOf(u);
    document.querySelectorAll('#script-list .script-item').forEach(li=>{
      li.classList.toggle('active', li.dataset.scriptkey === selectedScript);
    });
    buildScriptUserList(selectedScript);
    applyFilters();
  });
  document.getElementById('btn-close-modal').addEventListener('click', closeModal);
  document.getElementById('modal-overlay').classList.add('open');
}
function closeModal(){ document.getElementById('modal-overlay').classList.remove('open'); }
document.getElementById('modal-close').addEventListener('click', closeModal);
document.getElementById('modal-overlay').addEventListener('click', e=>{
  if (e.target === document.getElementById('modal-overlay')) closeModal();
});
document.addEventListener('keydown', e=>{ if (e.key==='Escape') closeModal(); });

function csvEscape(v){ return '"'+String(v??'').replace(/"/g,'""')+'"'; }
function downloadBlob(filename, text, mime){
  const blob = new Blob([text], {type: mime});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
function usersToCsv(rows){
  const headers = ['SAM Account','Display Name','UPN','Script Name','Script Path','Script Path (AD)','Enabled','Department','Title','Last Logon','Created','OU'];
  const body = rows.map(u=>[
    u.sam, u.display, u.upn, u.scriptName, u.script, u.scriptOriginal||u.script,
    u.enabled ? 'Enabled' : 'Disabled', u.dept, u.title, u.lastLogon, u.created, u.ou
  ].map(csvEscape).join(','));
  return '\uFEFF' + [headers.join(','), ...body].join('\r\n');
}
function stamp(){ return new Date().toISOString().slice(0,10); }

document.getElementById('btn-export-csv').addEventListener('click', ()=>{
  downloadBlob('AD_LogonScripts_filtered_' + stamp() + '.csv', usersToCsv(filteredData), 'text/csv;charset=utf-8');
  showToast('Filtered CSV exported — ' + filteredData.length + ' users');
});
document.getElementById('btn-export-raw').addEventListener('click', ()=>{
  downloadBlob('AD_LogonScripts_raw_' + stamp() + '.csv', usersToCsv(RAW_USERS), 'text/csv;charset=utf-8');
  showToast('Raw CSV exported — ' + RAW_USERS.length + ' users (unfiltered)');
});
document.getElementById('btn-export-json').addEventListener('click', ()=>{
  const payload = { meta: META, users: RAW_USERS, scripts: RAW_SCRIPTS, ous: RAW_OUS, departments: RAW_DEPTS };
  downloadBlob('AD_LogonScripts_raw_' + stamp() + '.json', JSON.stringify(payload, null, 2), 'application/json');
  showToast('Raw JSON exported — ' + RAW_USERS.length + ' users');
});
document.getElementById('btn-export-scripts').addEventListener('click', ()=>{
  const headers = ['Script Name','Full Path','User Count','% of Users','Users (semicolon-sep)'];
  const rows = RAW_SCRIPTS.map(s=>[
    s.name, s.script, s.count,
    META.totalUsers > 0 ? ((s.count/META.totalUsers)*100).toFixed(1)+'%' : '0%',
    (s.users||[]).join('; ')
  ].map(csvEscape).join(','));
  downloadBlob('AD_ScriptSummary_' + stamp() + '.csv', '\uFEFF' + [headers.join(','),...rows].join('\r\n'), 'text/csv;charset=utf-8');
  showToast('Script summary CSV exported');
});

document.getElementById('search-input').addEventListener('input', applyFilters);
document.getElementById('filter-script').addEventListener('change', function(){
  selectedScript = this.value || null;
  document.querySelectorAll('#script-list .script-item').forEach(li=>{
    li.classList.toggle('active', li.dataset.scriptkey === selectedScript);
  });
  buildScriptUserList(selectedScript);
  applyFilters();
});
document.getElementById('filter-status').addEventListener('change', applyFilters);
document.getElementById('filter-dept').addEventListener('change', applyFilters);
document.getElementById('page-size').addEventListener('change', function(){ pageSize=+this.value; applyFilters(); });
document.getElementById('btn-clear-filters').addEventListener('click', ()=>{
  document.getElementById('search-input').value = '';
  document.getElementById('filter-script').value = '';
  document.getElementById('filter-status').value = '';
  document.getElementById('filter-dept').value   = '';
  selectedScript = null;
  document.querySelectorAll('#script-list .script-item').forEach(li=>li.classList.remove('active'));
  buildScriptUserList(null);
  applyFilters();
});

(function init(){
  verifyIntegrity();
  buildKPIs();
  buildCharts();
  buildScriptList();
  populateFilterDropdowns();
  applyFilters();
})();
</script>
</body>
</html>
'@
}

function New-LogonScriptReportHtml {
    param(
        $Analytics,
        [hashtable]$Meta,
        [string]$RawExportNote
    )

    $userJson   = ConvertTo-EmbeddedJson (ConvertTo-UserDataJson -Users $Analytics.Users)
    $scriptJson = ConvertTo-EmbeddedJson (ConvertTo-ScriptAnalyticsJson -Scripts $Analytics.Scripts)
    $ouJson     = ConvertTo-EmbeddedJson (ConvertTo-OuJson -OUs $Analytics.TopOUs)
    $deptJson   = ConvertTo-EmbeddedJson (ConvertTo-DeptJson -Depts $Analytics.TopDepartments)

    Test-JsonRoundTripCounts -UserJson $userJson -ScriptJson $scriptJson -ExpectedUsers $Analytics.TotalUsers -ExpectedScripts $Analytics.UniqueScripts

    $html = Get-LogonScriptReportHtmlTemplate
    $replacements = [ordered]@{
        '##USER_DATA_JSON##'        = $userJson
        '##SCRIPT_ANALYTICS_JSON##' = $scriptJson
        '##OU_JSON##'               = $ouJson
        '##DEPT_JSON##'             = $deptJson
        '##TOTAL_USERS##'           = [string]$Analytics.TotalUsers
        '##UNIQUE_SCRIPTS##'        = [string]$Analytics.UniqueScripts
        '##ENABLED_COUNT##'         = [string]$Analytics.EnabledCount
        '##DISABLED_COUNT##'        = [string]$Analytics.DisabledCount
        '##SKIPPED_EMPTY##'         = [string]$Analytics.SkippedEmptyScript
        '##REPORT_GEN_TIME##'       = [string]$Meta.reportTime
        '##REPORT_DOMAIN##'         = [string]$Meta.domain
        '##RAW_EXPORT_NOTE##'       = $(if ([string]::IsNullOrWhiteSpace($RawExportNote)) { 'Raw data was not exported on disk. Use Export Raw / JSON in this page.' } else { $RawExportNote })
    }
    foreach ($key in $replacements.Keys) {
        $html = $html.Replace($key, $replacements[$key])
    }
    return $html
}

function Resolve-CompanionPath {
    param(
        [string]$HtmlPath,
        [string]$Suffix,
        [string]$Override
    )
    if (-not [string]::IsNullOrWhiteSpace($Override)) { return $Override }
    $dir  = Split-Path -Parent $HtmlPath
    $base = [System.IO.Path]::GetFileNameWithoutExtension($HtmlPath)
    return (Join-Path $dir ($base + $Suffix))
}

#endregion

#region ── Self-test (no Active Directory) ──────────────────────────────────────

function New-MockAdUser {
    param(
        [string]$Sam,
        [string]$ScriptPath,
        [bool]$Enabled = $true,
        [string]$DisplayName,
        [string]$Ou = 'OU=Users,DC=contoso,DC=com',
        [string]$Dept = 'IT',
        [string]$Title = 'Engineer',
        [string]$Upn,
        $LastLogon,
        $Created
    )
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = $Sam }
    if ([string]::IsNullOrWhiteSpace($Upn)) { $Upn = "$Sam@contoso.com" }
    [pscustomobject]@{
        SamAccountName       = $Sam
        DisplayName          = $DisplayName
        GivenName            = ''
        Surname              = ''
        UserPrincipalName    = $Upn
        EmailAddress         = $Upn
        ScriptPath           = $ScriptPath
        Enabled              = $Enabled
        LastLogonDate        = $LastLogon
        LastLogonTimestamp   = $null
        Created              = $Created
        DistinguishedName    = "CN=$Sam,$Ou"
        Department           = $Dept
        Title                = $Title
        Description          = ''
        PasswordLastSet      = $null
        PasswordNeverExpires = $false
        LockedOut            = $false
    }
}

function Invoke-LogonScriptReportSelfTest {
    $script:SelfTestPassed = 0
    $script:SelfTestFailed = 0
    function Assert-True {
        param([bool]$Condition, [string]$Name)
        if ($Condition) {
            Write-Success $Name
            $script:SelfTestPassed++
        } else {
            Write-Host "  [FAIL] $Name" -ForegroundColor Red
            $script:SelfTestFailed++
        }
    }

    Write-Header "Get-LogonScriptReport self-test"

    # JSON escaping: backslash, quote, ampersand
    $escaped = Escape-JsonString 'scripts\logon.bat'
    Assert-True ($escaped -eq 'scripts\\logon.bat') 'JSON escapes backslashes in script paths'

    $q = Escape-JsonString 'O''Brien & "Sons"'
    Assert-True ($q -eq "O'Brien & \`"Sons\`"") 'JSON escapes quotes and leaves ampersand raw'

    Assert-True ((Escape-HtmlString 'A & B') -eq 'A &amp; B') 'HTML escape still encodes ampersand'

    # Canonical paths
    Assert-True ((Get-CanonicalScriptPath ' scripts/logon.bat ') -eq 'scripts\logon.bat') 'Slash and trim normalize to backslash'
    Assert-True ((Get-CanonicalScriptPath 'scripts\\logon.bat') -eq 'scripts\logon.bat') 'Duplicate backslashes collapse'
    Assert-True ((Get-CanonicalScriptPath '\\fs01\netlogon\\dept.vbs') -eq '\\fs01\netlogon\dept.vbs') 'UNC prefix is preserved'
    Assert-True ((Get-ScriptGroupKey 'Scripts\Logon.BAT') -eq 'scripts\logon.bat') 'Group key is case-insensitive'

    # Collection wrapping
    Assert-True ((Get-AsArray $null).Count -eq 0) 'Get-AsArray null -> 0'
    $one = Get-AsArray (New-MockAdUser -Sam 'only' -ScriptPath 'a.bat')
    Assert-True ($one.Count -eq 1) 'Get-AsArray scalar -> 1'

    $created = Get-Date '2020-01-15'
    $logon   = Get-Date '2026-03-01 09:15'
    $users = @(
        (New-MockAdUser -Sam 'alice'   -ScriptPath 'scripts\logon.bat'     -Dept 'IT'      -LastLogon $logon -Created $created),
        (New-MockAdUser -Sam 'bob'     -ScriptPath 'SCRIPTS/Logon.bat'     -Dept 'IT'      -LastLogon $logon -Created $created),
        (New-MockAdUser -Sam 'carol'   -ScriptPath 'scripts\\logon.bat'    -Dept 'Finance' -LastLogon $logon -Created $created),
        (New-MockAdUser -Sam 'dave'    -ScriptPath 'login.cmd'             -Dept 'Finance' -LastLogon $logon -Created $created),
        (New-MockAdUser -Sam 'erin'    -ScriptPath 'login.cmd'             -Dept 'HR'      -LastLogon $logon -Created $created),
        (New-MockAdUser -Sam 'frank'   -ScriptPath '\\fs01\netlogon\dept.vbs' -Dept 'HR'  -LastLogon $logon -Created $created),
        (New-MockAdUser -Sam 'gina'    -ScriptPath 'scripts\old.bat'       -Dept 'IT'      -Enabled $false -LastLogon $logon -Created $created),
        (New-MockAdUser -Sam 'empty1'  -ScriptPath ''                      -Dept 'IT'),
        (New-MockAdUser -Sam 'empty2'  -ScriptPath '   '                   -Dept 'IT'),
        (New-MockAdUser -Sam 'obrien'  -ScriptPath 'scripts\logon.bat'     -DisplayName 'O''Brien & "Sons"' -Dept 'IT' -LastLogon $logon -Created $created)
    )

    $all = Build-LogonScriptAnalytics -Users $users
    Assert-True ($all.TotalUsers -eq 8) 'Empty/whitespace ScriptPath rows are excluded (8 processed)'
    Assert-True ($all.SkippedEmptyScript -eq 2) 'Two empty script rows skipped'
    Assert-True ($all.UniqueScripts -eq 4) 'Case/slash variants count as one unique script (4 total)'
    Assert-True ($all.EnabledCount -eq 7) 'Enabled count is 7 when disabled are included'
    Assert-True ($all.DisabledCount -eq 1) 'Disabled count is 1'
    Assert-True ($all.ScriptCountSum -eq $all.TotalUsers) 'Per-script counts sum to processed users'

    $logonScript = @($all.Scripts | Where-Object { $_.ScriptKey -eq 'scripts\logon.bat' })[0]
    Assert-True ($null -ne $logonScript -and $logonScript.Count -eq 4) 'scripts\logon.bat usage is 4 (alice/bob/carol/obrien)'
    Assert-True (@($logonScript.Users) -contains 'bob') 'bob (SCRIPTS/Logon.bat) grouped with scripts\logon.bat'

    $enabledOnly = Build-LogonScriptAnalytics -Users ($users | Where-Object { $_.Enabled -eq $true })
    Assert-True ($enabledOnly.TotalUsers -eq 7) 'Enabled-only set has 7 users'
    Assert-True ($enabledOnly.UniqueScripts -eq 3) 'Enabled-only set drops old.bat (3 unique scripts)'
    Assert-True ($enabledOnly.DisabledCount -eq 0) 'Enabled-only set has 0 disabled'

    $userJson = ConvertTo-UserDataJson -Users $all.Users
    $scriptJson = ConvertTo-ScriptAnalyticsJson -Scripts $all.Scripts
    $roundTripOk = $true
    try {
        Test-JsonRoundTripCounts -UserJson $userJson -ScriptJson $scriptJson -ExpectedUsers 8 -ExpectedScripts 4
    } catch {
        $roundTripOk = $false
        Write-Host "  [FAIL] JSON round-trip: $($_.Exception.Message)" -ForegroundColor Red
        $script:SelfTestFailed++
    }
    if ($roundTripOk) {
        Write-Success 'JSON round-trip preserves user and script counts'
        $script:SelfTestPassed++
    }

    $parsedUsers = @(ConvertFrom-Json -InputObject $userJson)
    $alice = @($parsedUsers | Where-Object { $_.sam -eq 'alice' })[0]
    Assert-True ($alice.script -eq 'scripts\logon.bat') 'Parsed JSON keeps backslash in script path (not scriptslogon.bat)'
    $obrien = @($parsedUsers | Where-Object { $_.sam -eq 'obrien' })[0]
    Assert-True ($obrien.display -eq 'O''Brien & "Sons"') 'Parsed JSON keeps ampersand and quotes in display name'

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("LogonScriptReportSelfTest_" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $htmlPath = Join-Path $tmp 'report.html'
        $meta = @{
            reportTime = '2026-10-26 21:30:00'
            domain     = 'contoso.com'
        }
        $csvPath    = Join-Path $tmp 'report_users.csv'
        $jsonPath   = Join-Path $tmp 'report_users.json'
        $scriptPath = Join-Path $tmp 'report_scripts.csv'
        $note = "Raw data files written next to this report: report_users.csv, report_users.json, report_scripts.csv"
        $html = New-LogonScriptReportHtml -Analytics $all -Meta $meta -RawExportNote $note
        [System.IO.File]::WriteAllText($htmlPath, $html, [System.Text.UTF8Encoding]::new($false))
        Export-LogonScriptRawData -Analytics $all -CsvPath $csvPath -JsonPath $jsonPath -ScriptCsvPath $scriptPath -Meta $meta

        Assert-True (Test-Path -LiteralPath $htmlPath) 'Sample HTML was written'
        Assert-True (Test-Path -LiteralPath $csvPath) 'Raw user CSV was written'
        Assert-True (Test-Path -LiteralPath $jsonPath) 'Raw JSON package was written'
        Assert-True (Test-Path -LiteralPath $scriptPath) 'Script inventory CSV was written'

        $csvRows = @(Import-Csv -LiteralPath $csvPath)
        Assert-True ($csvRows.Count -eq 8) 'Raw user CSV has 8 data rows'
        Assert-True (@($csvRows[0].PSObject.Properties.Name) -contains 'ScriptPathOriginal') 'Raw CSV includes ScriptPathOriginal'

        $scriptCsv = @(Import-Csv -LiteralPath $scriptPath)
        Assert-True ($scriptCsv.Count -eq 4) 'Script inventory CSV has 4 rows'
        $scriptCsvSum = 0
        foreach ($r in $scriptCsv) { $scriptCsvSum += [int]$r.UserCount }
        Assert-True ($scriptCsvSum -eq 8) 'Script inventory CSV counts sum to 8'

        Assert-True ($html -match 'scripts\\\\logon\.bat') 'HTML embeds JSON-escaped backslashes'
        Assert-True ($html -notmatch '##USER_DATA_JSON##') 'HTML placeholders were replaced'
        Assert-True ($html -match 'totalUsers    : 8') 'HTML META.totalUsers is 8'
        Assert-True ($html -match 'uniqueScripts : 4') 'HTML META.uniqueScripts is 4'
        Assert-True ($html -match 'id="btn-export-raw"') 'HTML includes Export Raw control'
        Assert-True ($html -match 'id="btn-export-json"') 'HTML includes Export JSON control'

        $sampleDir = Join-Path $PSScriptRoot 'samples'
        if (-not (Test-Path -LiteralPath $sampleDir)) {
            New-Item -ItemType Directory -Path $sampleDir | Out-Null
        }
        $sampleHtml = Join-Path $sampleDir 'Get-LogonScriptReport.sample.html'
        $sampleCsv  = Join-Path $sampleDir 'Get-LogonScriptReport.sample_users.csv'
        $sampleJson = Join-Path $sampleDir 'Get-LogonScriptReport.sample_users.json'
        $sampleScsv = Join-Path $sampleDir 'Get-LogonScriptReport.sample_scripts.csv'
        Copy-Item -LiteralPath $htmlPath -Destination $sampleHtml -Force
        Copy-Item -LiteralPath $csvPath -Destination $sampleCsv -Force
        Copy-Item -LiteralPath $jsonPath -Destination $sampleJson -Force
        Copy-Item -LiteralPath $scriptPath -Destination $sampleScsv -Force
        Write-Info "Sample report copied to $sampleHtml"
    } catch {
        Write-Host "  [FAIL] Sample export: $($_.Exception.GetType().FullName): $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  $($_.InvocationInfo.PositionMessage)" -ForegroundColor DarkYellow
        Write-Host "  $($_.ScriptStackTrace)" -ForegroundColor DarkYellow
        $script:SelfTestFailed++
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    if ($script:SelfTestFailed -gt 0) {
        Write-Host "  Self-test FAILED: $($script:SelfTestFailed) failed, $($script:SelfTestPassed) passed." -ForegroundColor Red
        return 1
    }
    Write-Host "  Self-test PASSED: $($script:SelfTestPassed) checks." -ForegroundColor Green
    return 0
}

#endregion

#region ── Main ─────────────────────────────────────────────────────────────────

if ($SelfTest) {
    $code = Invoke-LogonScriptReportSelfTest
    exit $code
}

Write-Header "AD Logon Script Report Generator v1.1"
Write-Info "PowerShell Version : $($PSVersionTable.PSVersion)"
Write-Info "Script Start Time  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Info "Run As             : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

Write-Step "Checking for ActiveDirectory PowerShell module..."
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host ""
    Write-Host "  [ERROR] The ActiveDirectory module is not installed." -ForegroundColor Red
    Write-Host "  Install RSAT (Remote Server Administration Tools):" -ForegroundColor Red
    Write-Host "  - Windows 10/11: Settings > Optional Features > RSAT: Active Directory" -ForegroundColor DarkYellow
    Write-Host "  - Server: Add-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor DarkYellow
    Write-Host ""
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop
Write-Success "ActiveDirectory module loaded."

Write-Step "Building AD query parameters..."

$adParams = @{
    Filter        = { ScriptPath -like '*' }
    ResultSetSize = $null
    Properties    = @(
        'SamAccountName',
        'DisplayName',
        'UserPrincipalName',
        'GivenName',
        'Surname',
        'ScriptPath',
        'Enabled',
        'LastLogonDate',
        'LastLogonTimestamp',
        'Created',
        'DistinguishedName',
        'Department',
        'Title',
        'EmailAddress',
        'PasswordLastSet',
        'PasswordNeverExpires',
        'LockedOut',
        'Description'
    )
}

if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $adParams['Server'] = $Server
    Write-Info "Targeting DC: $Server"
}

if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
    $adParams['SearchBase'] = $SearchBase
    Write-Info "Search Base: $SearchBase"
} else {
    try {
        $domain = Get-ADDomain
        $adParams['SearchBase'] = $domain.DistinguishedName
        Write-Info "Domain: $($domain.DNSRoot)"
        Write-Info "Search Base: $($domain.DistinguishedName)"
    } catch {
        Write-Warn "Could not resolve domain automatically. Proceeding without SearchBase."
    }
}

Write-Step "Querying Active Directory for users with Logon Scripts..."
$startQuery = Get-Date

try {
    $allUsers = Get-AsArray (Get-ADUser @adParams)
} catch {
    Write-Host ""
    Write-Host "  [ERROR] Failed to query Active Directory: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$queryTime = (Get-Date) - $startQuery
Write-Success "Query completed in $([math]::Round($queryTime.TotalSeconds, 2)) seconds."
Write-Info "Raw AD rows returned: $($allUsers.Count)"

if (-not $IncludeDisabledUsers) {
    $users = Get-AsArray ($allUsers | Where-Object { $_.Enabled -eq $true })
    Write-Info "After excluding disabled accounts: $($users.Count) rows (empty ScriptPath still removed next)"
} else {
    $users = $allUsers
    Write-Info "Including disabled accounts: $($users.Count) rows"
}

if ($users.Count -eq 0) {
    Write-Warn "No users with logon scripts found. The report will be empty."
}

Write-Step "Processing user data and building analytics..."
$analytics = Build-LogonScriptAnalytics -Users $users

$reportGenTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$reportDomain  = try { (Get-ADDomain).DNSRoot } catch { 'Unknown' }
$meta = @{
    reportTime = $reportGenTime
    domain     = $reportDomain
}

Write-Success "Processed $($analytics.TotalUsers) user records."
Write-Info "Unique scripts found: $($analytics.UniqueScripts)"
if ($analytics.SkippedEmptyScript -gt 0) {
    Write-Warn "$($analytics.SkippedEmptyScript) AD row(s) had a blank ScriptPath after trim and were excluded from totals."
}

Write-Step "Serialising data and generating HTML report..."
# Output path (file picker on Windows, otherwise script directory)
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $pickerUsed = $false
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $saveDialog                  = New-Object System.Windows.Forms.SaveFileDialog
        $timestamp                   = Get-Date -Format 'yyyyMMdd_HHmmss'
        $saveDialog.Title            = 'Save AD Logon Script Report'
        $saveDialog.Filter           = 'HTML Report (*.html)|*.html|All Files (*.*)|*.*'
        $saveDialog.DefaultExt       = 'html'
        $saveDialog.FileName         = "Get-LogonScriptReport_$timestamp.html"
        $startDir = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } else { [System.Environment]::GetFolderPath('Desktop') }
        $saveDialog.InitialDirectory = $startDir
        $dialogResult = $saveDialog.ShowDialog()
        if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK -and
            -not [string]::IsNullOrWhiteSpace($saveDialog.FileName)) {
            $OutputPath = $saveDialog.FileName
            $pickerUsed = $true
            Write-Info "Output path selected via file picker."
        } else {
            Write-Warn "File picker was cancelled. Falling back to default output location."
        }
    } catch {
        Write-Warn "Windows Forms not available — skipping file picker. ($($_.Exception.Message))"
    }

    if (-not $pickerUsed) {
        $scriptDir  = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } else { $PWD.Path }
        $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
        $OutputPath = Join-Path $scriptDir "Get-LogonScriptReport_$timestamp.html"
    }
}

$outputDir = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($outputDir) -and -not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$resolvedCsv    = $null
$resolvedJson   = $null
$resolvedScript = $null
$rawNote        = 'Raw data was not written on disk. Use Export Raw / JSON in this page.'
if (-not $SkipRawExport) {
    $resolvedCsv    = Resolve-CompanionPath -HtmlPath $OutputPath -Suffix '_users.csv'    -Override $RawCsvPath
    $resolvedJson   = Resolve-CompanionPath -HtmlPath $OutputPath -Suffix '_users.json'   -Override $RawJsonPath
    $resolvedScript = Resolve-CompanionPath -HtmlPath $OutputPath -Suffix '_scripts.csv'  -Override $ScriptCsvPath
    $rawNote = "Raw data written next to this report: $(Split-Path -Leaf $resolvedCsv), $(Split-Path -Leaf $resolvedJson), $(Split-Path -Leaf $resolvedScript)"
}

$htmlContent = New-LogonScriptReportHtml -Analytics $analytics -Meta $meta -RawExportNote $rawNote

Write-Step "Writing HTML report to: $OutputPath"
try {
    [System.IO.File]::WriteAllText($OutputPath, $htmlContent, [System.Text.Encoding]::UTF8)
} catch {
    Write-Host "  [ERROR] Could not write file: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$fileSize = (Get-Item -LiteralPath $OutputPath).Length
Write-Success "HTML report written successfully."
Write-Info "File size : $([math]::Round($fileSize / 1KB, 1)) KB"
Write-Info "File path : $OutputPath"

if (-not $SkipRawExport) {
    Write-Step "Writing raw data exports..."
    Export-LogonScriptRawData -Analytics $analytics -CsvPath $resolvedCsv -JsonPath $resolvedJson -ScriptCsvPath $resolvedScript -Meta @{
        reportTime         = $reportGenTime
        domain             = $reportDomain
        totalUsers         = $analytics.TotalUsers
        uniqueScripts      = $analytics.UniqueScripts
        enabledCount       = $analytics.EnabledCount
        disabledCount      = $analytics.DisabledCount
        skippedEmptyScript = $analytics.SkippedEmptyScript
        includeDisabled    = [bool]$IncludeDisabledUsers
        searchBase         = $(if ($adParams.ContainsKey('SearchBase')) { [string]$adParams['SearchBase'] } else { '' })
        server             = $(if ($adParams.ContainsKey('Server')) { [string]$adParams['Server'] } else { '' })
    }
}

Write-Header "Report Summary"
Write-Host ""
Write-Host "  Domain Queried      : " -NoNewline -ForegroundColor White
Write-Host $reportDomain -ForegroundColor Cyan
Write-Host "  Total Users Found   : " -NoNewline -ForegroundColor White
Write-Host $analytics.TotalUsers -ForegroundColor Cyan
Write-Host "  Unique Scripts      : " -NoNewline -ForegroundColor White
Write-Host $analytics.UniqueScripts -ForegroundColor Cyan
Write-Host "  Enabled Users       : " -NoNewline -ForegroundColor White
Write-Host $analytics.EnabledCount -ForegroundColor Green
Write-Host "  Disabled Users      : " -NoNewline -ForegroundColor White
Write-Host $analytics.DisabledCount -ForegroundColor Red
if ($analytics.SkippedEmptyScript -gt 0) {
    Write-Host "  Skipped (blank path): " -NoNewline -ForegroundColor White
    Write-Host $analytics.SkippedEmptyScript -ForegroundColor DarkYellow
}
Write-Host ""
Write-Host "  -- Top 10 Scripts --------------------------------------------------" -ForegroundColor DarkCyan
$rank = 1
foreach ($item in @($analytics.Scripts | Select-Object -First 10)) {
    $pct  = if ($analytics.TotalUsers -gt 0) { [math]::Round(($item.Count / $analytics.TotalUsers) * 100, 1) } else { 0 }
    Write-Host ("  {0,2}. {1,-35} {2,4} users ({3}%)" -f $rank, $item.Name, $item.Count, $pct) -ForegroundColor White
    $rank++
}

Write-Host ""
Write-Host "  -- Output files ----------------------------------------------------" -ForegroundColor DarkCyan
Write-Host "  HTML : $OutputPath" -ForegroundColor Yellow
if (-not $SkipRawExport) {
    Write-Host "  Users CSV    : $resolvedCsv" -ForegroundColor Yellow
    Write-Host "  Users JSON   : $resolvedJson" -ForegroundColor Yellow
    Write-Host "  Scripts CSV  : $resolvedScript" -ForegroundColor Yellow
}
Write-Host ""

if (-not $SkipBrowser) {
    try {
        Write-Step "Opening report in default browser..."
        Start-Process $OutputPath
        Write-Success "Report opened in browser."
    } catch {
        Write-Warn "Could not auto-open browser. Open the file manually: $OutputPath"
    }
}

Write-Header "Completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

#endregion

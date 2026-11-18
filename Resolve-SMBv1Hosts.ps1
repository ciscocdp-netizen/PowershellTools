#Requires -Version 5.1
<#
.SYNOPSIS
    Enriches an SMBv1 host spreadsheet with DNS hostname, AD operating system,
    OU location, and enabled/disabled status.

.DESCRIPTION
    Fully interactive. Prompts for the input spreadsheet with a file picker
    (.xlsx, .xls, or .csv), auto-detects the header row and every column,
    shows a catalog of headers (Excel letter, sample values, IPv4 vs hostname
    hits), and lets you choose which column to key lookups on.

    The key column may contain IPv4 addresses, hostnames, or a mix (auto per
    row). IPs are resolved (DNS PTR, falling back to System.Net.Dns) and then
    looked up in Active Directory. Hostnames skip PTR and go to AD (with an
    optional DNS A lookup for the IP). You pick which AD domain to connect to
    (current forest domains and trusts are listed; you can also type a domain
    or DC). Results are saved via a Save dialog.

    Reading/writing .xlsx uses Excel (COM) if installed, otherwise the
    ImportExcel module if available, otherwise falls back to CSV.

.PARAMETER InputPath
    Spreadsheet to read. When omitted, an Open dialog is shown.

.PARAMETER OutputPath
    Destination .xlsx or .csv. When omitted, a Save dialog is shown.

.PARAMETER KeyColumn
    Header name to key lookups on. When omitted, headers are detected and
    you are prompted (the suggested column is the default).

.PARAMETER KeyKind
    How to interpret the key column: Auto, IPv4, or Hostname.

.PARAMETER DnsServer
    DNS server for PTR/A queries. Blank uses the system default.

.PARAMETER Domain
    AD domain DNS name or NetBIOS name to bind to. When omitted, discovered
    forest domains and trusts are listed and you choose one.

.PARAMETER Server
    Domain controller (or domain DNS name) for AD queries. When set, the
    domain picker is skipped and this DC is used.

.PARAMETER Ping
    Ping each host to record Online / No reply.

.PARAMETER NonInteractive
    Skip prompts; use detected defaults (requires -InputPath).

.PARAMETER SelfTest
    Run built-in parser / header-detection tests and exit (no Excel, DNS, or AD).

.PARAMETER SkipMain
    Load functions only; do not start the interactive flow.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Resolve-SMBv1Hosts.ps1

.EXAMPLE
    .\Resolve-SMBv1Hosts.ps1 -SelfTest

.NOTES
    Version      : 1.2
    Requirements : Windows PowerShell 5.1, RSAT ActiveDirectory module
                   (for OS / OU / Enabled lookups).
    Run with     : powershell.exe -ExecutionPolicy Bypass -File .\Resolve-SMBv1Hosts.ps1

    Bugs fixed versus the original script:
      - Header mapping only accepted a few exact names (IP, Address, Hostname).
        Qualys/Nessus/Defender columns such as "Asset IP Address" or "DNS Name"
        were missed, and the script then silently picked a column with zero IPs.
      - Detected headers were never listed; you could not choose the key column.
      - Excel UsedRange.Value2 is a scalar (1x1) or a 1-D array (single column
        or single row). Indexing with $values[$r, $c] threw and aborted import.
      - Excel UsedRange often covers an entire formatted column (million rows).
        Import now walks xlUp / xlToLeft when the range looks inflated.
      - Title/banner rows above the table were treated as headers. The header
        row is scored (unique labels + IP/host names + next-row data).
      - Duplicate or blank headers collided; now uniqued (ColumnN / Name_2).
      - CSV delimiter was always comma; semicolon / tab / pipe exports failed.
      - IPs with CIDR, :port, quotes, NBSP, or \\prefix failed TryParse.
      - $row.$column broke on odd header names; property lookup is by name.
      - Empty IP values all shared one cache entry; cache is now kind+value.
      - List[object] of PSCustomObject piped to [object[]] throws "Argument
        types do not match" in Windows PowerShell 5.1 on export.
      - AD lookup did not try IPv4Address when PTR failed.
      - File dialogs that fail (non-STA, no UI) had no path-typed fallback.
#>
[CmdletBinding()]
param(
    [string]$InputPath,
    [string]$OutputPath,
    [string]$KeyColumn,
    [ValidateSet('Auto', 'IPv4', 'Hostname')]
    [string]$KeyKind,
    [string]$DnsServer,
    [string]$Domain,
    [string]$Server,
    [switch]$Ping,
    [switch]$NonInteractive,
    [switch]$SelfTest,
    [switch]$SkipMain
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
$script:Version = '1.2'
$script:NonInteractive = [bool]$NonInteractive -or [bool]$SelfTest

#region ---------- Small utilities ----------

function ConvertTo-ArrayList {
    param($Value)

    $acc = New-Object System.Collections.ArrayList
    # Unary comma so a 0- or 1-item list is returned as one object (not unrolled
    # to $null / a scalar). ArrayList enumerates on the pipeline otherwise.
    if ($null -eq $Value) { return , $acc }

    if ($Value -is [string]) {
        [void]$acc.Add($Value)
        return , $acc
    }

    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        [void]$acc.Add($Value)
        return , $acc
    }

    if ($Value -is [System.Collections.IDictionary]) {
        [void]$acc.Add($Value)
        return , $acc
    }

    if ($Value -is [System.Collections.IList]) {
        $count = [int]$Value.Count
        for ($i = 0; $i -lt $count; $i++) {
            [void]$acc.Add($Value[$i])
        }
        return , $acc
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($item in $Value) {
            [void]$acc.Add($item)
        }
        return , $acc
    }

    [void]$acc.Add($Value)
    return , $acc
}

function ConvertTo-ObjectArray {
    param($Value)
    ConvertTo-ArrayList $Value
}

function ConvertTo-StringArray {
    param($Value)
    $list = ConvertTo-ArrayList $Value
    $acc = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $list.Count; $i++) {
        [void]$acc.Add([string]$list[$i])
    }
    , $acc
}

function ConvertTo-CellText {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { return $Value.ToString() }
    if ($Value -is [DateTime]) { return Get-Date $Value -Format 's' }
    ([string]$Value).Trim()
}

function Get-RowPropertyValue {
    param($Row, [string]$Name)
    if ($null -eq $Row -or [string]::IsNullOrEmpty($Name)) { return $null }
    $prop = $Row.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    $prop.Value
}

function Get-ExcelColumnLetter {
    param([int]$Index)
    if ($Index -lt 1) { return '' }
    $n = [int]$Index
    $s = ''
    while ($n -gt 0) {
        $n--
        $code = [int](65 + [int]($n % 26))
        $s = ([string][char]$code) + $s
        $n = [int][Math]::Floor($n / 26.0)
    }
    $s
}

function Get-CsvUtf8Encoding {
    if ($PSVersionTable.PSVersion.Major -ge 6) { return 'utf8BOM' }
    return 'UTF8'
}

function Get-TruncatedText {
    param([string]$Text, [int]$Max = 28)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = $Text -replace '\s+', ' '
    if ($t.Length -le $Max) { return $t }
    $t.Substring(0, $Max - 1) + [char]0x2026
}

#endregion

#region ---------- IP / hostname parsing ----------

function ConvertTo-NormalizedIPv4 {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $a = $Value.Trim().Trim([char]0x00A0, [char]0x2007, [char]0x202F, [char]0xFEFF)
    $a = $a.Trim('"').Trim("'").Trim()
    if ($a.StartsWith('=')) { $a = $a.TrimStart('=').Trim().Trim('"').Trim("'") }
    if ($a.StartsWith('\\')) { $a = $a.TrimStart('\') }

    if ($a -match '^(\d{1,3}(?:\.\d{1,3}){3})/\d{1,2}$') { $a = $Matches[1] }
    elseif ($a -match '^(\d{1,3}(?:\.\d{1,3}){3}):\d+$') { $a = $Matches[1] }
    elseif ($a -match '^(?i)::ffff:((?:\d{1,3}\.){3}\d{1,3})$') { $a = $Matches[1] }

    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($a, [ref]$parsed) -and
        $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $parsed.ToString()
    }
    $null
}

function Test-IPv4 {
    param([string]$Value)
    [bool](ConvertTo-NormalizedIPv4 $Value)
}

function Test-LikelyHostName {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if (ConvertTo-NormalizedIPv4 $Value) { return $false }

    $v = $Value.Trim().TrimEnd('.')
    if ($v.StartsWith('\\')) { $v = $v.TrimStart('\') }
    $slash = $v.LastIndexOf('\')
    if ($slash -ge 0 -and $slash -lt ($v.Length - 1)) { $v = $v.Substring($slash + 1) }
    if ($v.Length -lt 2 -or $v.Length -gt 253) { return $false }
    if ($v -match '\s') { return $false }
    if ($v -match '^(?i)(none|n/a|null|unknown|-)$') { return $false }
    # FQDN or single label (NetBIOS / DNS). Underscores allowed (Windows).
    return [bool]($v -match '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9])?)*$')
}

function ConvertTo-NormalizedHostName {
    param([string]$Value)
    if (-not (Test-LikelyHostName $Value)) { return $null }
    $v = $Value.Trim().Trim('"').Trim("'").TrimEnd('.')
    if ($v.StartsWith('\\')) { $v = $v.TrimStart('\') }
    $slash = $v.IndexOf('\')
    if ($slash -gt 0) { $v = $v.Substring($slash + 1) } # DOMAIN\PC
    $v
}

function Test-HeaderLooksLikeIp {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $n = $Name.Trim()
    if ($n -match '(?i)mac\s*address|email|e-?mail|guid|uuid|serial') { return $false }
    return [bool]($n -match '(?i)(ip\s*v?4|ipv4|ip[\s_\-]*address|host[\s_\-]*ip|source[\s_\-]*ip|client[\s_\-]*ip|dest(?:ination)?[\s_\-]*ip|remote[\s_\-]*ip|asset[\s_\-]*ip|target[\s_\-]*ip|scanned[\s_\-]*ip|endpoint[\s_\-]*ip|device[\s_\-]*ip|last[\s_\-]*ip|(^|[^a-z])ip([^a-z]|$)|^address$)')
}

function Test-HeaderLooksLikeHost {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if (Test-HeaderLooksLikeIp $Name) { return $false }
    $n = $Name.Trim()
    return [bool]($n -match '(?i)(host\s*name|hostname|computer\s*name|computername|dns[\s_\-]*name|dnsname|dns[\s_\-]*host|fqdn|netbios|device\s*name|asset\s*name|machine\s*name|system\s*name|^host$|^name$|^computer$|^device$|^dns$|^asset$)')
}

#endregion

#region ---------- CSV parsing / header-row scoring ----------

function Split-CsvRecord {
    param(
        [Parameter(Mandatory)][string]$Line,
        [string]$Delimiter = ','
    )
    if ([string]::IsNullOrEmpty($Delimiter)) { $Delimiter = ',' }
    $d = $Delimiter[0]
    $fields = New-Object System.Collections.Generic.List[string]
    $sb = New-Object System.Text.StringBuilder
    $inQuotes = $false
    $chars = $Line.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $ch = $chars[$i]
        if ($inQuotes) {
            if ($ch -eq [char]'"') {
                if (($i + 1) -lt $chars.Length -and $chars[$i + 1] -eq [char]'"') {
                    [void]$sb.Append('"')
                    $i++
                }
                else {
                    $inQuotes = $false
                }
            }
            else {
                [void]$sb.Append($ch)
            }
        }
        else {
            if ($ch -eq [char]'"') {
                $inQuotes = $true
            }
            elseif ($ch -eq $d) {
                $fields.Add($sb.ToString())
                [void]$sb.Clear()
            }
            else {
                [void]$sb.Append($ch)
            }
        }
    }
    $fields.Add($sb.ToString())
    ConvertTo-ArrayList $fields
}

function Get-CsvDelimiter {
    param($Lines)
    $lineList = ConvertTo-ArrayList $Lines
    $candidates = @(',', ';', "`t", '|')
    $best = ','
    $bestScore = -1
    foreach ($d in $candidates) {
        $counts = New-Object System.Collections.Generic.List[int]
        foreach ($line in $lineList) {
            $text = [string]$line
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            $fields = Split-CsvRecord -Line $text -Delimiter $d
            $counts.Add([int]$fields.Count)
        }
        if ($counts.Count -eq 0) { continue }
        $groups = $counts | Group-Object | Sort-Object Count -Descending
        $modalCount = [int]$groups[0].Name
        $modalFreq = [int]$groups[0].Count
        if ($modalCount -lt 2) { continue }
        $score = ($modalFreq * 10) + $modalCount
        if ($score -gt $bestScore) {
            $bestScore = $score
            $best = $d
        }
    }
    $best
}

function Get-UniqueHeaders {
    param($RawHeaders)
    $seen = @{}
    $result = New-Object System.Collections.Generic.List[string]
    $items = ConvertTo-ArrayList $RawHeaders
    for ($i = 0; $i -lt $items.Count; $i++) {
        $name = ConvertTo-CellText $items[$i]
        if ([string]::IsNullOrWhiteSpace($name)) { $name = "Column$($i + 1)" }
        $name = ($name -replace '[\u0000-\u001F]', '').Trim()
        $base = $name
        $n = 2
        while ($seen.ContainsKey($name)) {
            $name = "${base}_$n"
            $n++
        }
        $seen[$name] = $true
        $result.Add($name)
    }
    if ($result.Count -eq 0) { $result.Add('Column1') }
    ConvertTo-ArrayList $result
}

function Get-HeaderRowScore {
    param($Cells, $NextRowCells)
    $cellList = ConvertTo-ArrayList $Cells
    $nextList = ConvertTo-ArrayList $NextRowCells
    $names = New-Object System.Collections.Generic.List[string]
    $filled = 0
    $numeric = 0
    $nameHits = 0

    foreach ($c in $cellList) {
        $t = ConvertTo-CellText $c
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        $filled++
        $names.Add($t)
        $asDouble = 0.0
        if ((ConvertTo-NormalizedIPv4 $t) -or [double]::TryParse($t, [ref]$asDouble)) { $numeric++ }
        if ((Test-HeaderLooksLikeIp $t) -or (Test-HeaderLooksLikeHost $t)) { $nameHits++ }
    }

    if ($filled -eq 0) { return -1000 }

    $unique = @($names | Select-Object -Unique).Count
    $score = ($unique * 6) + ($nameHits * 28) + $filled
    if ($unique -le 1) { $score -= 40 }
    if ($filled -gt 0 -and ($numeric / [double]$filled) -gt 0.6) { $score -= 50 }
    $long = @($names | Where-Object { $_.Length -gt 80 }).Count
    if ($long -gt 0) { $score -= 25 }

    $nextIp = 0
    $nextHost = 0
    $nextFilled = 0
    foreach ($c in $nextList) {
        $t = ConvertTo-CellText $c
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        $nextFilled++
        if (ConvertTo-NormalizedIPv4 $t) { $nextIp++ }
        elseif (Test-LikelyHostName $t) { $nextHost++ }
    }
    if ($nextIp -ge 1) { $score += 40 }
    if ($nextHost -ge 1) { $score += 20 }
    if ($nextFilled -eq 0) { $score -= 15 }
    $score
}

function Find-BestHeaderRowIndex {
    param(
        $Matrix,
        [int]$MaxScan = 15
    )
    $rows = ConvertTo-ArrayList $Matrix
    if ($rows.Count -eq 0) { return 0 }
    $limit = [Math]::Min($rows.Count, $MaxScan)
    $bestIdx = 0
    $bestScore = [int]::MinValue
    for ($r = 0; $r -lt $limit; $r++) {
        $next = if (($r + 1) -lt $rows.Count) { $rows[$r + 1] } else { @() }
        $score = Get-HeaderRowScore -Cells $rows[$r] -NextRowCells $next
        if ($score -gt $bestScore) {
            $bestScore = $score
            $bestIdx = $r
        }
    }
    $bestIdx
}

function Get-ExcelRangeValue {
    param(
        $Value2,
        [int]$Row,
        [int]$Col,
        [int]$RowCount,
        [int]$ColCount
    )
    if ($null -eq $Value2) { return $null }
    if ($Row -lt 1 -or $Col -lt 1 -or $Row -gt $RowCount -or $Col -gt $ColCount) { return $null }

    $arr = $Value2 -as [Array]
    if ($null -eq $arr) {
        if ($RowCount -eq 1 -and $ColCount -eq 1) { return $Value2 }
        return $null
    }

    try {
        if ($arr.Rank -eq 2) {
            $r0 = $arr.GetLowerBound(0)
            $c0 = $arr.GetLowerBound(1)
            return $arr.GetValue(($r0 + $Row - 1), ($c0 + $Col - 1))
        }
        if ($arr.Rank -eq 1) {
            $b = $arr.GetLowerBound(0)
            if ($ColCount -eq 1) { return $arr.GetValue($b + $Row - 1) }
            if ($RowCount -eq 1) { return $arr.GetValue($b + $Col - 1) }
            return $arr.GetValue($b + (($Row - 1) * $ColCount) + ($Col - 1))
        }
    }
    catch { return $null }
    $null
}

function Convert-ExcelValue2ToMatrix {
    param($Value2, [int]$RowCount, [int]$ColCount)
    $matrix = New-Object System.Collections.Generic.List[object]
    for ($r = 1; $r -le $RowCount; $r++) {
        $row = New-Object object[] $ColCount
        for ($c = 1; $c -le $ColCount; $c++) {
            $row[$c - 1] = Get-ExcelRangeValue -Value2 $Value2 -Row $r -Col $c -RowCount $RowCount -ColCount $ColCount
        }
        $matrix.Add($row)
    }
    ConvertTo-ArrayList $matrix
}

function Get-TrimmedColumnCount {
    param($Matrix, [int]$HeaderRowIndex)
    $rows = ConvertTo-ArrayList $Matrix
    if ($rows.Count -eq 0) { return 0 }
    $header = @( $rows[$HeaderRowIndex] )
    $max = $header.Count
    foreach ($row in $rows) {
        $cells = @($row)
        if ($cells.Count -gt $max) { $max = $cells.Count }
    }
    $last = -1
    for ($c = 0; $c -lt $max; $c++) {
        $used = $false
        for ($r = $HeaderRowIndex; $r -lt $rows.Count; $r++) {
            $cells = @($rows[$r])
            if ($c -lt $cells.Count -and -not [string]::IsNullOrWhiteSpace((ConvertTo-CellText $cells[$c]))) {
                $used = $true
                break
            }
        }
        if ($used) { $last = $c }
    }
    $last + 1
}

function Convert-MatrixToSheetData {
    param(
        $Matrix,
        [int]$HeaderRowIndex,
        [string]$Sheet
    )
    $rowsIn = ConvertTo-ArrayList $Matrix
    if ($HeaderRowIndex -ge $rowsIn.Count) { $HeaderRowIndex = 0 }
    $colCount = Get-TrimmedColumnCount -Matrix $rowsIn -HeaderRowIndex $HeaderRowIndex
    if ($colCount -lt 1) { throw 'No columns with data were found.' }

    $headerCells = @($rowsIn[$HeaderRowIndex])
    $rawHeaders = New-Object object[] $colCount
    for ($c = 0; $c -lt $colCount; $c++) {
        $rawHeaders[$c] = if ($c -lt $headerCells.Count) { $headerCells[$c] } else { $null }
    }
    $headers = Get-UniqueHeaders -RawHeaders $rawHeaders

    $out = New-Object System.Collections.Generic.List[object]
    for ($r = $HeaderRowIndex + 1; $r -lt $rowsIn.Count; $r++) {
        $cells = @($rowsIn[$r])
        $record = [ordered]@{}
        $hasData = $false
        for ($c = 0; $c -lt $headers.Count; $c++) {
            $value = if ($c -lt $cells.Count) { $cells[$c] } else { $null }
            if (-not [string]::IsNullOrWhiteSpace((ConvertTo-CellText $value))) { $hasData = $true }
            $record[$headers[$c]] = $value
        }
        if ($hasData) { $out.Add([pscustomobject]$record) }
    }
    if ($out.Count -eq 0) { throw 'The spreadsheet has no data rows under the header row.' }

    [pscustomobject]@{
        Headers   = $headers
        Rows      = ConvertTo-ObjectArray $out
        Sheet     = $Sheet
        HeaderRow = $HeaderRowIndex + 1
    }
}

#endregion

#region ---------- Column catalog (detect + choose key) ----------

function Get-ColumnProfiles {
    param(
        $Headers,
        $Rows,
        [int]$SampleLimit = 6,
        [int]$ScanLimit = 250
    )
    $headerList = ConvertTo-StringArray $Headers
    $rowList = ConvertTo-ArrayList $Rows
    $scan = [Math]::Min($rowList.Count, $ScanLimit)
    $profiles = New-Object System.Collections.Generic.List[object]

    for ($i = 0; $i -lt $headerList.Count; $i++) {
        $name = $headerList[$i]
        $ipv4 = 0
        $hostn = 0
        $filled = 0
        $samples = New-Object System.Collections.Generic.List[string]
        $seenSample = @{}

        for ($r = 0; $r -lt $scan; $r++) {
            $text = ConvertTo-CellText (Get-RowPropertyValue -Row $rowList[$r] -Name $name)
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            $filled++
            if (ConvertTo-NormalizedIPv4 $text) { $ipv4++ }
            elseif (Test-LikelyHostName $text) { $hostn++ }
            if ($samples.Count -lt $SampleLimit -and -not $seenSample.ContainsKey($text)) {
                $seenSample[$text] = $true
                $samples.Add($text)
            }
        }

        $looksLike = 'Other'
        $thresholdIp = [Math]::Max(1, [int]([Math]::Ceiling($filled * 0.45)))
        $thresholdHost = [Math]::Max(1, [int]([Math]::Ceiling($filled * 0.40)))
        if ($ipv4 -ge $thresholdIp -and $ipv4 -ge $hostn) {
            $looksLike = 'IPv4 address'
        }
        elseif ($hostn -ge $thresholdHost) {
            $looksLike = 'Hostname'
        }
        elseif (Test-HeaderLooksLikeIp $name) {
            $looksLike = 'IPv4 address'
        }
        elseif (Test-HeaderLooksLikeHost $name) {
            $looksLike = 'Hostname'
        }

        $score = 0
        if (Test-HeaderLooksLikeIp $name) { $score += 90 }
        elseif (Test-HeaderLooksLikeHost $name) { $score += 55 }
        $score += [Math]::Min($ipv4, 250) * 2
        $score += [Math]::Min($hostn, 180)
        if ($looksLike -eq 'Other') { $score -= 10 }
        if ($filled -eq 0) { $score -= 50 }

        $kindHint = 'Auto'
        if ($looksLike -eq 'IPv4 address') { $kindHint = 'IPv4' }
        elseif ($looksLike -eq 'Hostname') { $kindHint = 'Hostname' }

        $profiles.Add([pscustomobject]@{
            Index       = $i
            Number      = $i + 1
            Letter      = Get-ExcelColumnLetter ($i + 1)
            Name        = $name
            LooksLike   = $looksLike
            KindHint    = $kindHint
            IPv4Count   = $ipv4
            HostCount   = $hostn
            FilledCount = $filled
            Score       = $score
            Samples     = ConvertTo-StringArray $samples
        })
    }

    ConvertTo-ArrayList $profiles
}

function Get-SuggestedKeyProfile {
    param($Profiles)
    $list = ConvertTo-ArrayList $Profiles
    if ($list.Count -eq 0) { return $null }
    $sorted = ConvertTo-ArrayList @($list.ToArray() | Sort-Object -Property Score -Descending)
    $best = $sorted[0]
    # Prefer a real IPv4 column when scores are close (typical SMBv1 sheets).
    $ipBest = $null
    foreach ($p in $sorted) {
        if ($p.LooksLike -eq 'IPv4 address') { $ipBest = $p; break }
    }
    if ($null -ne $ipBest -and $best.LooksLike -ne 'IPv4 address') {
        $bestScore = [int]$best.Score
        $ipScore = [int]$ipBest.Score
        if ($ipScore -ge ($bestScore - 25)) { return $ipBest }
    }
    $best
}

function Write-ColumnCatalog {
    param($Profiles, $SuggestedName)
    Write-Host ''
    Write-Host '  Detected headers (auto-scored from names + sample values):' -ForegroundColor White
    Write-Host ('    {0} {1,-4} {2,-4} {3,-28} {4,-14} {5,5} {6,5}  {7}' -f ' ', '#', 'Col', 'Header', 'Looks like', 'IPv4', 'Host', 'Samples') -ForegroundColor DarkGray
    Write-Host ('    {0} {1,-4} {2,-4} {3,-28} {4,-14} {5,5} {6,5}  {7}' -f ' ', '--', '---', '------', '----------', '----', '----', '-------') -ForegroundColor DarkGray
    foreach ($p in (ConvertTo-ArrayList $Profiles)) {
        $marker = if ($p.Name -eq $SuggestedName) { '*' } else { ' ' }
        $sampleParts = New-Object System.Collections.Generic.List[string]
        foreach ($s in (ConvertTo-ArrayList $p.Samples)) {
            if (-not [string]::IsNullOrWhiteSpace($s)) { $sampleParts.Add((Get-TruncatedText $s 22)) }
        }
        $sampleText = $sampleParts -join ', '
        Write-Host ('    {0}[{1,2}] {2,-4} {3,-28} {4,-14} {5,5} {6,5}  {7}' -f `
            $marker, $p.Number, $p.Letter, (Get-TruncatedText $p.Name 28), $p.LooksLike, $p.IPv4Count, $p.HostCount, $sampleText)
    }
    Write-Host '    * = suggested key column' -ForegroundColor DarkGray
}

#endregion

#region ---------- Self-test (no Excel / DNS / AD) ----------

function Assert-SelfTest {
    param([bool]$Condition, [string]$Name)
    if (-not $Condition) { throw "SelfTest FAILED: $Name" }
    Write-Host "  PASS  $Name" -ForegroundColor Green
}

function Invoke-SelfTest {
    Write-Host ''
    Write-Host "SMBv1 host enrichment self-test (v$script:Version)" -ForegroundColor Cyan
    Write-Host ''

    $al = ConvertTo-ArrayList 'Address'
    Assert-SelfTest ($al -is [System.Collections.ArrayList] -and $al.Count -eq 1 -and $al[0] -eq 'Address') 'ConvertTo-ArrayList keeps a single string intact'
    $al0 = ConvertTo-ArrayList @()
    Assert-SelfTest ($al0 -is [System.Collections.ArrayList] -and $al0.Count -eq 0) 'ConvertTo-ArrayList keeps an empty list'

    $h = Get-UniqueHeaders -RawHeaders @('IP', '', 'IP', $null, 'Host')
    Assert-SelfTest ($h.Count -eq 5 -and $h[0] -eq 'IP' -and $h[1] -eq 'Column2' -and $h[2] -eq 'IP_2' -and $h[4] -eq 'Host') 'Unique headers for blanks/duplicates'
    $one = Get-UniqueHeaders -RawHeaders 'Address'
    Assert-SelfTest ($one.Count -eq 1 -and $one[0] -eq 'Address') 'Single header string is not unrolled into characters'
    $oneColMatrix = @(
        , @('ComputerName')
        , @('WKS01')
        , @('WKS02')
    )
    $oneCol = Convert-MatrixToSheetData -Matrix $oneColMatrix -HeaderRowIndex 0 -Sheet $null
    Assert-SelfTest ($oneCol.Headers.Count -eq 1 -and $oneCol.Headers[0] -eq 'ComputerName' -and $oneCol.Rows.Count -eq 2) 'One-column sheet keeps the real header name'

    Assert-SelfTest ((ConvertTo-NormalizedIPv4 '  10.1.2.3  ') -eq '10.1.2.3') 'Trim IPv4'
    Assert-SelfTest ((ConvertTo-NormalizedIPv4 '10.1.2.3/24') -eq '10.1.2.3') 'CIDR IPv4'
    Assert-SelfTest ((ConvertTo-NormalizedIPv4 '10.1.2.3:445') -eq '10.1.2.3') 'IPv4:port'
    Assert-SelfTest ((ConvertTo-NormalizedIPv4 '"10.1.2.3"') -eq '10.1.2.3') 'Quoted IPv4'
    Assert-SelfTest ((ConvertTo-NormalizedIPv4 "'10.1.2.3'") -eq '10.1.2.3') 'Apostrophe IPv4'
    Assert-SelfTest ((ConvertTo-NormalizedIPv4 '\\10.1.2.3') -eq '10.1.2.3') 'UNC IPv4'
    Assert-SelfTest ((ConvertTo-NormalizedIPv4 '::ffff:10.1.2.3') -eq '10.1.2.3') 'IPv4-mapped IPv6'
    Assert-SelfTest ((ConvertTo-NormalizedIPv4 ("10.1.2.3" + [char]0x00A0)) -eq '10.1.2.3') 'NBSP IPv4'
    Assert-SelfTest (-not (Test-IPv4 'WKS-01')) 'Hostname is not IPv4'
    Assert-SelfTest (-not (Test-IPv4 '2001:db8::1')) 'IPv6 is not treated as IPv4'
    Assert-SelfTest (Test-LikelyHostName 'WKS-0421') 'NetBIOS hostname'
    Assert-SelfTest (Test-LikelyHostName 'wks0421.corp.example.com') 'FQDN hostname'
    Assert-SelfTest (Test-LikelyHostName 'CONTOSO\WKS-0421') 'DOMAIN\PC hostname'
    Assert-SelfTest (-not (Test-LikelyHostName 'Windows 10')) 'OS string is not a hostname'
    Assert-SelfTest (-not (Test-LikelyHostName '10.1.2.3')) 'IPv4 is not a hostname'
    Assert-SelfTest ((ConvertTo-NormalizedHostName 'CONTOSO\WKS-0421') -eq 'WKS-0421') 'Strip DOMAIN\ prefix'

    Assert-SelfTest (Test-HeaderLooksLikeIp 'Asset IP Address') 'Qualys-style IP header'
    Assert-SelfTest (Test-HeaderLooksLikeIp 'IPv4') 'IPv4 header'
    Assert-SelfTest (Test-HeaderLooksLikeIp 'Host IP') 'Host IP header'
    Assert-SelfTest (Test-HeaderLooksLikeIp 'SourceIP') 'SourceIP header'
    Assert-SelfTest (-not (Test-HeaderLooksLikeIp 'Email Address')) 'Email is not an IP header'
    Assert-SelfTest (Test-HeaderLooksLikeHost 'DNS Name') 'DNS Name header'
    Assert-SelfTest (Test-HeaderLooksLikeHost 'Computer Name') 'Computer Name header'
    Assert-SelfTest (Test-HeaderLooksLikeHost 'FQDN') 'FQDN header'
    Assert-SelfTest (-not (Test-HeaderLooksLikeHost 'IP Address')) 'IP Address is not a host header'

    Assert-SelfTest ((Get-ExcelColumnLetter 1) -eq 'A' -and (Get-ExcelColumnLetter 26) -eq 'Z' -and (Get-ExcelColumnLetter 27) -eq 'AA') 'Excel column letters'

    $scalar = Get-ExcelRangeValue -Value2 'IP Address' -Row 1 -Col 1 -RowCount 1 -ColCount 1
    Assert-SelfTest ($scalar -eq 'IP Address') 'Value2 scalar 1x1'
    $col = New-Object object[] 3
    $col[0] = 'IP'; $col[1] = '10.0.0.1'; $col[2] = '10.0.0.2'
    Assert-SelfTest ((Get-ExcelRangeValue -Value2 $col -Row 2 -Col 1 -RowCount 3 -ColCount 1) -eq '10.0.0.1') 'Value2 1-D column'
    $row = New-Object object[] 2
    $row[0] = 'IP'; $row[1] = 'Host'
    Assert-SelfTest ((Get-ExcelRangeValue -Value2 $row -Row 1 -Col 2 -RowCount 1 -ColCount 2) -eq 'Host') 'Value2 1-D row'
    $grid = New-Object 'object[,]' 2, 2
    $grid[0, 0] = 'IP'; $grid[0, 1] = 'Host'; $grid[1, 0] = '10.0.0.1'; $grid[1, 1] = 'WKS01'
    Assert-SelfTest ((Get-ExcelRangeValue -Value2 $grid -Row 2 -Col 1 -RowCount 2 -ColCount 2) -eq '10.0.0.1') 'Value2 0-based 2-D'
    $grid1 = [Array]::CreateInstance([object], [int[]]@(2, 2), [int[]]@(1, 1))
    $grid1.SetValue('IP', 1, 1)
    $grid1.SetValue('Host', 1, 2)
    $grid1.SetValue('10.0.0.1', 2, 1)
    $grid1.SetValue('WKS01', 2, 2)
    Assert-SelfTest ((Get-ExcelRangeValue -Value2 $grid1 -Row 2 -Col 2 -RowCount 2 -ColCount 2) -eq 'WKS01') 'Value2 1-based 2-D (Excel COM)'

    $fields = Split-CsvRecord -Line 'a,"b,c",d' -Delimiter ','
    Assert-SelfTest ($fields.Count -eq 3 -and $fields[1] -eq 'b,c') 'Quoted CSV comma'
    Assert-SelfTest ((Get-CsvDelimiter -Lines @('IP;Host;OS', '10.0.0.1;WKS01;Win10')) -eq ';') 'Detect semicolon delimiter'
    Assert-SelfTest ((Get-CsvDelimiter -Lines @("IP`tHost", "10.0.0.1`tWKS01")) -eq "`t") 'Detect tab delimiter'

    $matrix = @(
        , @('SMBv1 Host Inventory - week 42')
        , @('IP Address', 'DNS Name', 'OS')
        , @('10.1.1.8', 'WKS01.corp.local', 'Windows 10')
        , @('10.1.1.9', 'WKS02.corp.local', 'Windows 7')
    )
    $idx = Find-BestHeaderRowIndex -Matrix $matrix
    Assert-SelfTest ($idx -eq 1) 'Header row skips title banner'

    $sheet = Convert-MatrixToSheetData -Matrix $matrix -HeaderRowIndex $idx -Sheet 'Hosts'
    Assert-SelfTest ($sheet.Headers[0] -eq 'IP Address' -and $sheet.Rows.Count -eq 2) 'Matrix-to-rows uses detected header row'

    $dn = Get-OUFromDistinguishedName 'CN=WKS01,OU=Workstations,OU=Corp,DC=corp,DC=local'
    Assert-SelfTest ($dn -eq 'OU=Workstations,OU=Corp,DC=corp,DC=local') 'OU from DN'
    $escaped = Get-OUFromDistinguishedName 'CN=Smith\, John,OU=Labs,DC=corp,DC=local'
    Assert-SelfTest ($escaped -eq 'OU=Labs,DC=corp,DC=local') 'OU from DN with escaped comma'
    $path = Get-OUPathFromCanonicalName 'corp.local/Corp/Workstations/WKS01'
    Assert-SelfTest ($path -eq 'corp.local/Corp/Workstations') 'OU path from canonical name'

    $rows = @(
        [pscustomobject]@{ 'Asset IP Address' = '10.9.8.7'; 'DNS Name' = 'WKS01'; Notes = 'x' }
        [pscustomobject]@{ 'Asset IP Address' = '10.9.8.8'; 'DNS Name' = 'WKS02'; Notes = 'y' }
        [pscustomobject]@{ 'Asset IP Address' = '10.9.8.9'; 'DNS Name' = 'WKS03'; Notes = 'z' }
    )
    $profiles = Get-ColumnProfiles -Headers @('Asset IP Address', 'DNS Name', 'Notes') -Rows $rows
    $suggested = Get-SuggestedKeyProfile -Profiles $profiles
    Assert-SelfTest ($suggested.Name -eq 'Asset IP Address' -and $suggested.KindHint -eq 'IPv4') 'Suggest IP column from mixed Qualys-style headers'
    $hostProf = @($profiles | Where-Object { $_.Name -eq 'DNS Name' })[0]
    Assert-SelfTest ($hostProf.LooksLike -eq 'Hostname') 'DNS Name profiled as hostname'

    $hostRows = @(
        [pscustomobject]@{ ComputerName = 'WKS01'; Owner = 'A' }
        [pscustomobject]@{ ComputerName = 'WKS02'; Owner = 'B' }
    )
    $hp = Get-ColumnProfiles -Headers @('ComputerName', 'Owner') -Rows $hostRows
    $hs = Get-SuggestedKeyProfile -Profiles $hp
    Assert-SelfTest ($hs.Name -eq 'ComputerName' -and $hs.KindHint -eq 'Hostname') 'Suggest hostname when no IP column exists'

    $domList = New-Object System.Collections.ArrayList
    $domList = Add-AdDomainChoice -List $domList -DnsRoot 'corp.example.com' -NetBIOS 'CORP' -PDC 'dc01.corp.example.com' -Kind 'Current logon domain' -IsCurrent $true
    $domList = Add-AdDomainChoice -List $domList -DnsRoot 'CORP.EXAMPLE.COM' -Kind 'Forest root'
    Assert-SelfTest ($domList.Count -eq 1 -and $domList[0].Kind -eq 'Current logon domain' -and $domList[0].PDC -eq 'dc01.corp.example.com') 'Duplicate domain DNS names are merged'
    $domList = Add-AdDomainChoice -List $domList -DnsRoot 'child.corp.example.com' -NetBIOS 'CHILD' -Kind 'Forest domain'
    Assert-SelfTest ($domList.Count -eq 2) 'Second forest domain is added'
    Assert-SelfTest (Test-AdDomainChoiceMatch -Choice $domList[0] -Name 'CORP') 'Match domain by NetBIOS'
    Assert-SelfTest (Test-AdDomainChoiceMatch -Choice $domList[0] -Name 'dc01.corp.example.com') 'Match domain by PDC host'
    Assert-SelfTest (Test-AdDomainChoiceMatch -Choice $domList[0] -Name 'corp.example.com') 'Match domain by DNS root'
    Assert-SelfTest (-not (Test-AdDomainChoiceMatch -Choice $domList[0] -Name 'child.corp.example.com')) 'Do not match a different domain'
    $domLabel = Format-AdDomainChoiceLabel $domList[0]
    Assert-SelfTest ($domLabel -match 'corp.example.com' -and $domLabel -match 'CORP' -and $domLabel -match 'Current logon domain') 'Domain picker label includes DNS, NetBIOS, and kind'

    Write-Host ''
    Write-Host 'All self-tests passed.' -ForegroundColor Green
}

#endregion

#region ---------- UI helpers ----------

function Write-Banner {
    Clear-Host
    $line = '=' * 70
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  SMBv1 Host Enrichment v$script:Version  |  Key column -> DNS -> AD" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
}

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ">> $Text" -ForegroundColor Yellow
}

function Read-YesNo {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [bool]$Default = $true
    )
    if ($script:NonInteractive) { return $Default }
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = (Read-Host "$Prompt $hint").Trim()
        if ([string]::IsNullOrEmpty($answer)) { return $Default }
        switch -Regex ($answer) {
            '^(y|yes)$' { return $true }
            '^(n|no)$'  { return $false }
            default     { Write-Host '  Please answer Y or N.' -ForegroundColor DarkYellow }
        }
    }
}

function Read-ListIndex {
    param(
        [Parameter(Mandatory)][int]$Count,
        [int]$DefaultIndex = 0,
        [string]$Prompt = 'Enter number'
    )
    if ($Count -lt 1) { throw 'Nothing to select.' }
    if ($DefaultIndex -lt 0 -or $DefaultIndex -ge $Count) { $DefaultIndex = 0 }
    if ($script:NonInteractive) { return $DefaultIndex }
    while ($true) {
        $answer = (Read-Host "$Prompt (default $($DefaultIndex + 1))").Trim()
        if ([string]::IsNullOrEmpty($answer)) { return $DefaultIndex }
        $n = 0
        if ([int]::TryParse($answer, [ref]$n) -and $n -ge 1 -and $n -le $Count) {
            return ($n - 1)
        }
        Write-Host "  Invalid selection. Enter 1-$Count." -ForegroundColor DarkYellow
    }
}

function Select-FromList {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)]$Items,
        [int]$DefaultIndex = 0,
        [switch]$SkipPrint
    )
    $list = ConvertTo-StringArray $Items
    if ($list.Count -eq 0) { throw 'Select-FromList: no items.' }
    if ($DefaultIndex -lt 0 -or $DefaultIndex -ge $list.Count) { $DefaultIndex = 0 }
    if (-not $SkipPrint) {
        Write-Host $Title -ForegroundColor White
        for ($i = 0; $i -lt $list.Count; $i++) {
            $marker = if ($i -eq $DefaultIndex) { '*' } else { ' ' }
            Write-Host ("  {0}[{1,2}] {2}" -f $marker, ($i + 1), $list[$i])
        }
    }
    else {
        Write-Host $Title -ForegroundColor White
    }
    $idx = Read-ListIndex -Count $list.Count -DefaultIndex $DefaultIndex -Prompt 'Enter number'
    $list[$idx]
}

function New-TopMostOwner {
    $owner = New-Object System.Windows.Forms.Form
    $owner.TopMost = $true
    $owner.ShowInTaskbar = $false
    $owner.WindowState = 'Minimized'
    $owner
}

function Select-InputFile {
    try {
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = 'Select the SMBv1 host spreadsheet'
        $dialog.Filter = 'Spreadsheets (*.xlsx;*.xls;*.csv)|*.xlsx;*.xls;*.csv|Excel (*.xlsx;*.xls)|*.xlsx;*.xls|CSV (*.csv)|*.csv|All files (*.*)|*.*'
        $dialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')
        $dialog.Multiselect = $false
        $owner = New-TopMostOwner
        try {
            if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.FileName }
            return $null
        }
        finally { $owner.Dispose(); $dialog.Dispose() }
    }
    catch {
        Write-Host '  File picker unavailable (no UI / non-STA). Paste the full path instead.' -ForegroundColor DarkYellow
        $typed = (Read-Host '  Input file path').Trim('"')
        if ($typed -and (Test-Path -LiteralPath $typed)) { return $typed }
        return $null
    }
}

function Select-OutputFile {
    param([string]$SuggestedPath, [bool]$AllowXlsx)
    try {
        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Title = 'Save enriched results as'
        $dialog.Filter = if ($AllowXlsx) { 'Excel Workbook (*.xlsx)|*.xlsx|CSV (*.csv)|*.csv' } else { 'CSV (*.csv)|*.csv' }
        $parent = Split-Path -Path $SuggestedPath -Parent
        if ($parent -and (Test-Path -LiteralPath $parent)) { $dialog.InitialDirectory = $parent }
        $dialog.FileName = [System.IO.Path]::GetFileNameWithoutExtension($SuggestedPath)
        $dialog.OverwritePrompt = $true
        $owner = New-TopMostOwner
        try {
            if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.FileName }
            return $null
        }
        finally { $owner.Dispose(); $dialog.Dispose() }
    }
    catch {
        Write-Host '  Save picker unavailable. Paste the full output path instead (blank = default).' -ForegroundColor DarkYellow
        $typed = (Read-Host "  Output path [$SuggestedPath]").Trim('"')
        if ([string]::IsNullOrWhiteSpace($typed)) { return $SuggestedPath }
        return $typed
    }
}

function Select-KeyColumnInteractive {
    param(
        $Profiles,
        [string]$SuggestedName,
        [string]$PreselectedName
    )
    $list = ConvertTo-ArrayList $Profiles
    Write-ColumnCatalog -Profiles $list -SuggestedName $SuggestedName

    if ($PreselectedName) {
        $match = @($list | Where-Object { $_.Name -eq $PreselectedName })
        if ($match.Count -gt 0) {
            Write-Host "  Using -KeyColumn '$PreselectedName'." -ForegroundColor Green
            return $match[0]
        }
        Write-Host "  -KeyColumn '$PreselectedName' was not found in this sheet." -ForegroundColor DarkYellow
    }

    $defaultIndex = 0
    for ($i = 0; $i -lt $list.Count; $i++) {
        if ($list[$i].Name -eq $SuggestedName) { $defaultIndex = $i; break }
    }
    Write-Host ''
    Write-Host "  Suggested key column: [$($defaultIndex + 1)] $($list[$defaultIndex].Name) ($($list[$defaultIndex].LooksLike))" -ForegroundColor Green
    $idx = Read-ListIndex -Count $list.Count -DefaultIndex $defaultIndex -Prompt '  Which column should lookups key on?'
    $list[$idx]
}

function Select-KeyKindInteractive {
    param(
        [string]$SuggestedKind,
        [string]$ColumnName,
        [string]$PreselectedKind
    )
    if ($PreselectedKind) { return $PreselectedKind }
    $items = @(
        'Auto-detect per row (IPv4 vs hostname)',
        'IPv4 address — DNS PTR, then Active Directory',
        'Hostname / computer name — Active Directory (optional DNS A)'
    )
    $default = 0
    switch ($SuggestedKind) {
        'IPv4'     { $default = 1 }
        'Hostname' { $default = 2 }
    }
    Write-Host ''
    $choice = Select-FromList -Title "  How should values in '$ColumnName' be interpreted?" -Items $items -DefaultIndex $default
    if ($choice -like 'IPv4*') { return 'IPv4' }
    if ($choice -like 'Hostname*') { return 'Hostname' }
    'Auto'
}

function Select-OptionalColumnInteractive {
    param(
        [string]$Title,
        $Profiles,
        [string]$SuggestedName,
        [string]$ExcludeName
    )
    $candidates = New-Object System.Collections.ArrayList
    foreach ($p in (ConvertTo-ArrayList $Profiles)) {
        if ($p.Name -ne $ExcludeName) { [void]$candidates.Add($p) }
    }
    $labels = New-Object System.Collections.Generic.List[string]
    $labels.Add('(none)')
    foreach ($p in $candidates) { $labels.Add(('{0}  ({1})' -f $p.Name, $p.LooksLike)) }
    $default = 0
    if ($SuggestedName) {
        for ($i = 0; $i -lt $candidates.Count; $i++) {
            if ($candidates[$i].Name -eq $SuggestedName) { $default = $i + 1; break }
        }
    }
    $choice = Select-FromList -Title $Title -Items (ConvertTo-StringArray $labels) -DefaultIndex $default
    if ($choice -eq '(none)') { return $null }
    $idx = -1
    for ($i = 0; $i -lt $labels.Count; $i++) {
        if ($labels[$i] -eq $choice) { $idx = $i; break }
    }
    if ($idx -le 0) { return $null }
    $candidates[$idx - 1].Name
}

#endregion

#region ---------- Spreadsheet I/O ----------

function Release-ComObject {
    param($Object)
    if ($null -ne $Object) {
        try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($Object) } catch { }
    }
}

function Test-ExcelComAvailable {
    try {
        $type = [Type]::GetTypeFromProgID('Excel.Application')
        return ($null -ne $type)
    }
    catch { return $false }
}

function Get-TrueUsedDimensions {
    param($Sheet, $Used)
    $firstRow = [int]$Used.Row
    $firstCol = [int]$Used.Column
    $rowCount = [int]$Used.Rows.Count
    $colCount = [int]$Used.Columns.Count

    if ($rowCount -gt 5000 -or $colCount -gt 50) {
        Write-Host '  UsedRange looks inflated; shrinking with End(xlUp)/End(xlToLeft)...' -ForegroundColor DarkGray
        $lastRow = $firstRow
        $lastCol = $firstCol
        $scanCols = [Math]::Min($colCount, 25)
        for ($c = 0; $c -lt $scanCols; $c++) {
            $endCell = $Sheet.Cells.Item($Sheet.Rows.Count, $firstCol + $c).End(-4162) # xlUp
            if ($endCell.Row -gt $lastRow) { $lastRow = [int]$endCell.Row }
            Release-ComObject $endCell
        }
        $scanRows = [Math]::Min([Math]::Max($lastRow - $firstRow + 1, 1), 80)
        for ($r = 0; $r -lt $scanRows; $r++) {
            $endCell = $Sheet.Cells.Item($firstRow + $r, $Sheet.Columns.Count).End(-4159) # xlToLeft
            if ($endCell.Column -gt $lastCol) { $lastCol = [int]$endCell.Column }
            Release-ComObject $endCell
        }
        $rowCount = [Math]::Max(1, $lastRow - $firstRow + 1)
        $colCount = [Math]::Max(1, $lastCol - $firstCol + 1)
    }

    [pscustomobject]@{
        FirstRow = $firstRow
        FirstCol = $firstCol
        RowCount = $rowCount
        ColCount = $colCount
    }
}

function Import-ExcelViaCom {
    param([Parameter(Mandatory)][string]$Path)

    $excel = $null; $workbook = $null; $sheet = $null; $used = $null; $range = $null; $sheets = $null
    try {
        Write-Host '  Opening workbook with Excel (read-only)...' -ForegroundColor DarkGray
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $excel.DisplayAlerts = $false
        $full = [System.IO.Path]::GetFullPath($Path)
        $workbook = $excel.Workbooks.Open($full, 0, $true)

        $sheets = $workbook.Worksheets
        $sheetNames = New-Object System.Collections.Generic.List[string]
        for ($i = 1; $i -le $sheets.Count; $i++) {
            $ws = $sheets.Item($i)
            $sheetNames.Add([string]$ws.Name)
            Release-ComObject $ws
        }
        $nameArray = ConvertTo-StringArray $sheetNames
        $sheetName = if ($nameArray.Count -gt 1) {
            Select-FromList -Title 'The workbook has multiple worksheets. Which one contains the hosts?' -Items $nameArray
        } else { $nameArray[0] }

        $sheet = $workbook.Worksheets.Item($sheetName)
        $used = $sheet.UsedRange
        $dim = Get-TrueUsedDimensions -Sheet $sheet -Used $used
        if ($dim.RowCount -lt 2) { throw "Worksheet '$sheetName' has no data rows." }

        $range = $sheet.Range(
            $sheet.Cells.Item($dim.FirstRow, $dim.FirstCol),
            $sheet.Cells.Item($dim.FirstRow + $dim.RowCount - 1, $dim.FirstCol + $dim.ColCount - 1)
        )
        $values = $range.Value2
        $matrix = Convert-ExcelValue2ToMatrix -Value2 $values -RowCount $dim.RowCount -ColCount $dim.ColCount
        $headerIdx = Find-BestHeaderRowIndex -Matrix $matrix
        if ($headerIdx -gt 0) {
            Write-Host "  Header row auto-detected as row $($dim.FirstRow + $headerIdx) (row $($dim.FirstRow) looks like a title/banner)." -ForegroundColor Green
        }

        $isDateColumn = @{}
        $dataRowExcel = $dim.FirstRow + $headerIdx + 1
        for ($c = 1; $c -le $dim.ColCount; $c++) {
            $cell = $sheet.Cells.Item($dataRowExcel, $dim.FirstCol + $c - 1)
            $format = [string]$cell.NumberFormat
            Release-ComObject $cell
            $isDateColumn[$c - 1] = ($format -match '[dmyhDMYH]') -and ($format -ne 'General')
        }

        $sheetData = Convert-MatrixToSheetData -Matrix $matrix -HeaderRowIndex $headerIdx -Sheet $sheetName
        foreach ($row in @($sheetData.Rows)) {
            foreach ($name in @($sheetData.Headers)) {
                $idx = [array]::IndexOf(@($sheetData.Headers), $name)
                $value = $row.$name
                if ($idx -ge 0 -and $isDateColumn[$idx] -and $value -is [double]) {
                    try { $row.$name = [DateTime]::FromOADate($value) } catch { }
                }
            }
        }
        $sheetData
    }
    finally {
        if ($workbook) { try { $workbook.Close($false) } catch { } }
        if ($excel) { try { $excel.Quit() } catch { } }
        Release-ComObject $range; Release-ComObject $used; Release-ComObject $sheet
        Release-ComObject $sheets
        Release-ComObject $workbook; Release-ComObject $excel
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
}

function Import-CsvRobust {
    param([Parameter(Mandatory)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $encoding = New-Object System.Text.UTF8Encoding $false
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $text = $encoding.GetString($bytes, 3, $bytes.Length - 3)
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $text = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    else {
        $text = $encoding.GetString($bytes)
    }

    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($text -split '\r\n|\n|\r')) {
        $lines.Add($line)
    }
    if ($lines.Count -gt 0) { $lines[0] = $lines[0].TrimStart([char]0xFEFF) }

    $nonEmpty = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($nonEmpty.Count -eq 0) { throw 'The CSV file is empty.' }

    $delimiter = Get-CsvDelimiter -Lines ($nonEmpty | Select-Object -First 12)
    $matrix = New-Object System.Collections.Generic.List[object]
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $matrix.Add((Split-CsvRecord -Line $line -Delimiter $delimiter))
    }
    if ($matrix.Count -lt 2) { throw 'The CSV file has no data rows.' }

    $headerIdx = Find-BestHeaderRowIndex -Matrix $matrix.ToArray()
    if ($headerIdx -gt 0) {
        Write-Host "  Header row auto-detected as line $($headerIdx + 1) (earlier lines look like a title)." -ForegroundColor Green
    }
    $delimName = switch ($delimiter) {
        ';'  { 'semicolon' }
        "`t" { 'tab' }
        '|'  { 'pipe' }
        default { 'comma' }
    }
    Write-Host "  CSV delimiter: $delimName" -ForegroundColor DarkGray
    Convert-MatrixToSheetData -Matrix $matrix.ToArray() -HeaderRowIndex $headerIdx -Sheet $null
}

function Import-HostSpreadsheet {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
    $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()

    if ($extension -eq '.csv' -or $extension -eq '.txt') {
        return Import-CsvRobust -Path $Path
    }

    if (Test-ExcelComAvailable) {
        return Import-ExcelViaCom -Path $Path
    }

    if (Get-Module -ListAvailable -Name ImportExcel) {
        Import-Module ImportExcel
        $info = Get-ExcelSheetInfo -Path $Path
        $sheetNames = ConvertTo-StringArray @($info | ForEach-Object { $_.Name })
        $sheetName = if ($sheetNames.Count -gt 1) {
            Select-FromList -Title 'Which worksheet contains the hosts?' -Items $sheetNames
        } else { $sheetNames[0] }
        $raw = @(Import-Excel -Path $Path -WorksheetName $sheetName -NoHeader)
        if ($raw.Count -eq 0) { throw "Worksheet '$sheetName' has no rows." }
        $propNames = @($raw[0].PSObject.Properties.Name)
        $matrix = New-Object System.Collections.Generic.List[object]
        foreach ($row in $raw) {
            $cells = New-Object object[] $propNames.Count
            for ($c = 0; $c -lt $propNames.Count; $c++) {
                $cells[$c] = $row.($propNames[$c])
            }
            $matrix.Add($cells)
        }
        $headerIdx = Find-BestHeaderRowIndex -Matrix $matrix.ToArray()
        if ($headerIdx -gt 0) {
            Write-Host "  Header row auto-detected as row $($headerIdx + 1)." -ForegroundColor Green
        }
        return Convert-MatrixToSheetData -Matrix $matrix.ToArray() -HeaderRowIndex $headerIdx -Sheet $sheetName
    }

    throw 'Excel is not installed and the ImportExcel module was not found. Save the sheet as CSV and run again, or run: Install-Module ImportExcel -Scope CurrentUser'
}

function Export-ExcelViaCom {
    param(
        [Parameter(Mandatory)]$Rows,
        [Parameter(Mandatory)][string]$Path
    )

    $rowArray = ConvertTo-ObjectArray $Rows
    $excel = $null; $workbook = $null; $sheet = $null; $range = $null
    try {
        $headers = @($rowArray[0].PSObject.Properties.Name)
        $rowCount = $rowArray.Count
        $colCount = $headers.Count

        $data = New-Object 'object[,]' ($rowCount + 1), $colCount
        $dateColumns = @{}
        for ($c = 0; $c -lt $colCount; $c++) { $data[0, $c] = $headers[$c] }
        for ($r = 0; $r -lt $rowCount; $r++) {
            $row = $rowArray[$r]
            for ($c = 0; $c -lt $colCount; $c++) {
                $value = Get-RowPropertyValue -Row $row -Name $headers[$c]
                if ($value -is [DateTime]) {
                    $dateColumns[$c] = $true
                    $value = $value.ToOADate()
                }
                elseif ($value -is [bool]) { $value = $value.ToString() }
                $data[($r + 1), $c] = $value
            }
        }

        Write-Host '  Writing workbook with Excel...' -ForegroundColor DarkGray
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $excel.DisplayAlerts = $false
        $workbook = $excel.Workbooks.Add()
        $sheet = $workbook.Worksheets.Item(1)
        $sheet.Name = 'SMBv1 Hosts'

        $range = $sheet.Range($sheet.Cells.Item(1, 1), $sheet.Cells.Item($rowCount + 1, $colCount))
        $range.Value2 = $data

        foreach ($c in $dateColumns.Keys) {
            $col = $sheet.Columns.Item($c + 1)
            $col.NumberFormat = 'm/d/yyyy h:mm'
            Release-ComObject $col
        }

        $table = $sheet.ListObjects.Add(1, $range, $null, 1)
        $table.Name = 'SMBv1Hosts'
        $table.TableStyle = 'TableStyleMedium2'

        $lightRed    = 206 * 65536 + 199 * 256 + 255
        $lightYellow = 156 * 65536 + 235 * 256 + 255
        $enabledIdx = [array]::IndexOf($headers, 'AD_Enabled')
        $foundIdx   = [array]::IndexOf($headers, 'AD_Found')
        for ($r = 0; $r -lt $rowCount; $r++) {
            $color = $null
            if ($foundIdx -ge 0 -and "$($data[($r + 1), $foundIdx])" -eq 'False') { $color = $lightYellow }
            elseif ($enabledIdx -ge 0 -and "$($data[($r + 1), $enabledIdx])" -eq 'False') { $color = $lightRed }
            if ($color) {
                $rowRange = $sheet.Range($sheet.Cells.Item($r + 2, 1), $sheet.Cells.Item($r + 2, $colCount))
                $rowRange.Interior.Color = $color
                Release-ComObject $rowRange
            }
        }

        [void]$sheet.Columns.AutoFit()
        foreach ($c in 1..$colCount) {
            $col = $sheet.Columns.Item($c)
            if ($col.ColumnWidth -gt 60) { $col.ColumnWidth = 60 }
            Release-ComObject $col
        }

        $sheet.Activate()
        $excel.ActiveWindow.SplitRow = 1
        $excel.ActiveWindow.FreezePanes = $true

        $workbook.SaveAs($Path, 51)
        Release-ComObject $table
    }
    finally {
        if ($workbook) { try { $workbook.Close($false) } catch { } }
        if ($excel) { try { $excel.Quit() } catch { } }
        Release-ComObject $range; Release-ComObject $sheet
        Release-ComObject $workbook; Release-ComObject $excel
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
}

function Export-Results {
    param(
        [Parameter(Mandatory)]$Rows,
        [Parameter(Mandatory)][string]$Path
    )
    $rowArray = ConvertTo-ObjectArray $Rows
    if ($rowArray.Count -eq 0) { throw 'No rows to export.' }
    $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()

    if ($extension -eq '.xlsx') {
        if (Test-ExcelComAvailable) {
            Export-ExcelViaCom -Rows $rowArray -Path $Path
            return $Path
        }
        if (Get-Module -ListAvailable -Name ImportExcel) {
            Import-Module ImportExcel
            $rowArray | Export-Excel -Path $Path -WorksheetName 'SMBv1 Hosts' -TableName 'SMBv1Hosts' -AutoSize -FreezeTopRow -ClearSheet
            return $Path
        }
        Write-Warning 'Neither Excel nor ImportExcel is available. Saving as CSV instead.'
        $Path = [System.IO.Path]::ChangeExtension($Path, '.csv')
    }

    $rowArray | Export-Csv -Path $Path -NoTypeInformation -Encoding (Get-CsvUtf8Encoding)
    $Path
}

#endregion

#region ---------- Lookup logic ----------

function Resolve-IpToHostName {
    param(
        [Parameter(Mandatory)][string]$IP,
        [string]$DnsServer
    )
    $result = [pscustomobject]@{ FQDN = $null; Method = $null; Error = $null }

    if (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue) {
        try {
            $params = @{ Name = $IP; Type = 'PTR'; DnsOnly = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
            if ($DnsServer) { $params.Server = $DnsServer }
            $ptr = Resolve-DnsName @params | Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1
            if ($ptr -and $ptr.NameHost) {
                $result.FQDN = $ptr.NameHost.TrimEnd('.')
                $result.Method = 'DNS PTR'
                return $result
            }
        }
        catch { $result.Error = "PTR: $($_.Exception.Message)" }
    }

    try {
        $entry = [System.Net.Dns]::GetHostEntry($IP)
        if ($entry.HostName -and $entry.HostName -ne $IP) {
            $result.FQDN = $entry.HostName.TrimEnd('.')
            $result.Method = 'System.Net.Dns'
            $result.Error = $null
        }
    }
    catch {
        if (-not $result.Error) { $result.Error = "DNS: $($_.Exception.Message)" }
    }
    $result
}

function Resolve-HostToIp {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$DnsServer
    )
    if (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue) {
        try {
            $params = @{ Name = $Name; Type = 'A'; DnsOnly = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
            if ($DnsServer) { $params.Server = $DnsServer }
            $a = Resolve-DnsName @params | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1
            if ($a -and $a.IPAddress) { return [string]$a.IPAddress }
        }
        catch { }
    }
    try {
        $entry = [System.Net.Dns]::GetHostEntry($Name)
        $v4 = $entry.AddressList | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1
        if ($v4) { return $v4.ToString() }
    }
    catch { }
    $null
}

$script:AdProperties = @(
    'OperatingSystem', 'OperatingSystemVersion', 'OperatingSystemServicePack',
    'Enabled', 'DistinguishedName', 'CanonicalName', 'LastLogonDate',
    'PasswordLastSet', 'DNSHostName', 'Description', 'IPv4Address'
)

function Find-ADComputerRecord {
    param(
        [string]$FQDN,
        [string]$ShortName,
        [string]$IP,
        [hashtable]$AdParams
    )
    if ($null -eq $AdParams) { $AdParams = @{} }

    $attempts = New-Object System.Collections.Generic.List[hashtable]
    if ($FQDN) {
        $safe = $FQDN -replace "'", "''"
        $attempts.Add(@{ Filter = "DNSHostName -eq '$safe'" })
    }
    if ($ShortName) {
        $safe = $ShortName -replace "'", "''"
        $attempts.Add(@{ Filter = "Name -eq '$safe'" })
        $attempts.Add(@{ Filter = "SamAccountName -eq '$safe`$'" })
    }
    if ($IP) {
        $safe = $IP -replace "'", "''"
        $attempts.Add(@{ Filter = "IPv4Address -eq '$safe'" })
    }

    foreach ($attempt in $attempts) {
        try {
            $computer = Get-ADComputer @attempt -Properties $script:AdProperties @AdParams |
                Select-Object -First 1
            if ($computer) { return $computer }
        }
        catch { Write-Verbose "AD lookup failed ($($attempt.Filter)): $($_.Exception.Message)" }
    }

    if ($FQDN -and $FQDN.Contains('.') -and -not $AdParams.ContainsKey('Server')) {
        $domain = $FQDN.Substring($FQDN.IndexOf('.') + 1)
        $crossParams = @{} + $AdParams
        $crossParams.Server = $domain
        $safe = $FQDN -replace "'", "''"
        try {
            $computer = Get-ADComputer -Filter "DNSHostName -eq '$safe'" -Properties $script:AdProperties @crossParams |
                Select-Object -First 1
            if ($computer) { return $computer }
        }
        catch { Write-Verbose "Cross-domain lookup against $domain failed: $($_.Exception.Message)" }
    }
    $null
}

function Get-OUFromDistinguishedName {
    param([string]$DistinguishedName)
    if ([string]::IsNullOrEmpty($DistinguishedName)) { return $null }
    $DistinguishedName -replace '^CN=.*?(?<!\\),', ''
}

function Get-OUPathFromCanonicalName {
    param([string]$CanonicalName)
    if ([string]::IsNullOrEmpty($CanonicalName)) { return $null }
    $idx = $CanonicalName.LastIndexOf('/')
    if ($idx -gt 0) { return $CanonicalName.Substring(0, $idx) }
    $CanonicalName
}

function New-AdDomainChoice {
    param(
        [Parameter(Mandatory)][string]$DnsRoot,
        [string]$NetBIOS,
        [string]$PDC,
        [string]$Kind = 'Domain',
        [bool]$IsCurrent = $false
    )
    [pscustomobject]@{
        DnsRoot   = $DnsRoot.Trim()
        NetBIOS   = $NetBIOS
        PDC       = $PDC
        Kind      = $Kind
        IsCurrent = [bool]$IsCurrent
    }
}

function Add-AdDomainChoice {
    param(
        $List,
        [string]$DnsRoot,
        [string]$NetBIOS,
        [string]$PDC,
        [string]$Kind = 'Domain',
        [bool]$IsCurrent = $false
    )
    $acc = ConvertTo-ArrayList $List
    if ([string]::IsNullOrWhiteSpace($DnsRoot)) { return $acc }
    $key = $DnsRoot.Trim().ToLowerInvariant()
    foreach ($existing in $acc) {
        if ($existing.DnsRoot -and $existing.DnsRoot.ToLowerInvariant() -eq $key) {
            if ($IsCurrent) {
                $existing.IsCurrent = $true
                $existing.Kind = $Kind
            }
            if (-not $existing.PDC -and $PDC) { $existing.PDC = $PDC }
            if (-not $existing.NetBIOS -and $NetBIOS) { $existing.NetBIOS = $NetBIOS }
            return $acc
        }
    }
    [void]$acc.Add((New-AdDomainChoice -DnsRoot $DnsRoot -NetBIOS $NetBIOS -PDC $PDC -Kind $Kind -IsCurrent $IsCurrent))
    $acc
}

function Test-AdDomainChoiceMatch {
    param($Choice, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or $null -eq $Choice) { return $false }
    $n = $Name.Trim()
    foreach ($candidate in @($Choice.DnsRoot, $Choice.NetBIOS, $Choice.PDC)) {
        if ($candidate -and [string]::Equals([string]$candidate, $n, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    $false
}

function Format-AdDomainChoiceLabel {
    param($Choice)
    if ($null -eq $Choice) { return '' }
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add([string]$Choice.DnsRoot)
    if ($Choice.NetBIOS) { $parts.Add('[' + $Choice.NetBIOS + ']') }
    $parts.Add('-')
    $parts.Add([string]$Choice.Kind)
    if ($Choice.PDC) { $parts.Add('(PDC ' + $Choice.PDC + ')') }
    $parts -join ' '
}

function Get-AdDomainCatalog {
    param([hashtable]$DiscoverParams)
    if ($null -eq $DiscoverParams) { $DiscoverParams = @{} }
    $list = New-Object System.Collections.ArrayList

    $current = $null
    try {
        $current = Get-ADDomain @DiscoverParams -ErrorAction Stop
    }
    catch {
        Write-Host "  Current domain not detected: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }

    if ($current) {
        $list = Add-AdDomainChoice -List $list -DnsRoot $current.DNSRoot -NetBIOS $current.NetBIOSName `
            -PDC $current.PDCEmulator -Kind 'Current logon domain' -IsCurrent $true

        try {
            $forest = Get-ADForest @DiscoverParams -ErrorAction Stop
            $root = [string]$forest.RootDomain
            foreach ($name in (ConvertTo-ArrayList $forest.Domains)) {
                $dns = [string]$name
                if ([string]::IsNullOrWhiteSpace($dns)) { continue }
                if ([string]::Equals($dns, $current.DNSRoot, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                $kind = 'Forest domain'
                if ($root -and [string]::Equals($dns, $root, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $kind = 'Forest root'
                }
                $child = $null
                try {
                    $child = Get-ADDomain -Identity $dns @DiscoverParams -ErrorAction Stop
                }
                catch {
                    try {
                        $childParams = @{} + $DiscoverParams
                        $childParams.Server = $dns
                        $child = Get-ADDomain -Identity $dns @childParams -ErrorAction Stop
                    }
                    catch { }
                }
                if ($child) {
                    $list = Add-AdDomainChoice -List $list -DnsRoot $child.DNSRoot -NetBIOS $child.NetBIOSName `
                        -PDC $child.PDCEmulator -Kind $kind
                }
                else {
                    $list = Add-AdDomainChoice -List $list -DnsRoot $dns -Kind $kind
                }
            }
        }
        catch {
            Write-Host "  Forest domains could not be enumerated: $($_.Exception.Message)" -ForegroundColor DarkYellow
        }

        try {
            $rawTrusts = Get-ADTrust -Filter * @DiscoverParams -ErrorAction Stop
            $trustItems = New-Object System.Collections.ArrayList
            if ($null -eq $rawTrusts) { }
            elseif ($rawTrusts -is [System.Array] -or ($rawTrusts -is [System.Collections.IList] -and -not ($rawTrusts.PSObject.Properties['Target']))) {
                $count = [int]$rawTrusts.Count
                for ($i = 0; $i -lt $count; $i++) { [void]$trustItems.Add($rawTrusts[$i]) }
            }
            else {
                [void]$trustItems.Add($rawTrusts)
            }
            foreach ($t in $trustItems) {
                if ($null -eq $t) { continue }
                $target = [string]$t.Target
                if ([string]::IsNullOrWhiteSpace($target)) { continue }
                $kind = 'Trusted domain'
                if ($t.TrustType) { $kind = "Trust: $($t.TrustType)" }
                if ($t.Direction) { $kind = "$kind ($($t.Direction))" }
                $list = Add-AdDomainChoice -List $list -DnsRoot $target -Kind $kind
            }
        }
        catch {
            Write-Host "  Trusted domains could not be enumerated: $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }

    ConvertTo-ArrayList $list
}

function Select-AdDomainInteractive {
    param(
        $Catalog,
        [string]$Preselected
    )
    $list = ConvertTo-ArrayList $Catalog
    Write-Host ''
    if ($list.Count -eq 0) {
        Write-Host '  No domains were discovered automatically.' -ForegroundColor DarkYellow
    }
    else {
        Write-Host '  Discovered domains (current forest + trusts). Lookups use the one you pick.' -ForegroundColor White
        Write-Host '  Child domains are listed separately — pick the domain the computers live in.' -ForegroundColor DarkGray
        Write-Host ''
        Write-Host ('    {0} {1,-4} {2}' -f ' ', '#', 'Domain') -ForegroundColor DarkGray
        Write-Host ('    {0} {1,-4} {2}' -f ' ', '--', '------') -ForegroundColor DarkGray
        $starDefault = 0
        for ($i = 0; $i -lt $list.Count; $i++) {
            if ($list[$i].IsCurrent) { $starDefault = $i }
            if ($Preselected -and (Test-AdDomainChoiceMatch -Choice $list[$i] -Name $Preselected)) { $starDefault = $i }
        }
        for ($i = 0; $i -lt $list.Count; $i++) {
            $marker = if ($i -eq $starDefault) { '*' } else { ' ' }
            Write-Host ('    {0}[{1,2}] {2}' -f $marker, ($i + 1), (Format-AdDomainChoiceLabel $list[$i]))
        }
        Write-Host ('     [{0,2}] {1}' -f ($list.Count + 1), 'Type a domain DNS name or domain controller')
        Write-Host '    * = default' -ForegroundColor DarkGray
    }

    if ($Preselected) {
        foreach ($c in $list) {
            if (Test-AdDomainChoiceMatch -Choice $c -Name $Preselected) {
                Write-Host "  Using -Domain '$($c.DnsRoot)'." -ForegroundColor Green
                return $c
            }
        }
        Write-Host "  -Domain '$Preselected' was not in the discovered list; connecting to it directly." -ForegroundColor DarkYellow
        return (New-AdDomainChoice -DnsRoot $Preselected -Kind 'Specified')
    }

    if ($list.Count -eq 0) {
        $typed = (Read-Host '  Domain DNS name, NetBIOS name, or DC hostname').Trim()
        if (-not $typed) { return $null }
        return (New-AdDomainChoice -DnsRoot $typed -Kind 'Typed')
    }

    $default = 0
    for ($i = 0; $i -lt $list.Count; $i++) {
        if ($list[$i].IsCurrent) { $default = $i }
    }
    $idx = Read-ListIndex -Count ($list.Count + 1) -DefaultIndex $default -Prompt '  Which domain should AD lookups connect to?'
    if ($idx -eq $list.Count) {
        while ($true) {
            $typed = (Read-Host '  Domain DNS name, NetBIOS name, or DC hostname').Trim()
            if ($typed) { return (New-AdDomainChoice -DnsRoot $typed -Kind 'Typed') }
            Write-Host '  Please enter a domain or DC name.' -ForegroundColor DarkYellow
            if ($script:NonInteractive) { return $null }
        }
    }
    $list[$idx]
}

function Connect-ChosenAdDomain {
    param(
        [Parameter(Mandatory)][string]$Identity,
        [hashtable]$AdParams
    )
    if ($null -eq $AdParams) { $AdParams = @{} }

    $firstError = $null
    try {
        return Get-ADDomain -Identity $Identity @AdParams -ErrorAction Stop
    }
    catch {
        $firstError = $_.Exception.Message
    }
    try {
        $asServer = @{} + $AdParams
        $asServer.Server = $Identity
        return Get-ADDomain @asServer -ErrorAction Stop
    }
    catch {
        throw "Could not connect to '$Identity' as a domain or DC. $($firstError); $($_.Exception.Message)"
    }
}

function Get-HostEnrichment {
    param(
        [string]$KeyValue,
        [string]$KeyKind,
        [string]$FallbackHost,
        [string]$FallbackIp,
        [string]$DnsServer,
        [hashtable]$AdParams,
        [bool]$AdAvailable,
        [bool]$DoPing,
        [string]$AdDomain
    )

    $info = [ordered]@{
        Key_Value          = $KeyValue
        Key_Kind           = $null
        Resolved_IP        = $null
        Resolved_HostName  = $null
        Resolved_FQDN      = $null
        Resolve_Method     = $null
        Ping               = $null
        AD_Domain          = $AdDomain
        AD_Found           = $null
        AD_Enabled         = $null
        AD_OperatingSystem = $null
        AD_OSVersion       = $null
        AD_OU              = $null
        AD_OUPath          = $null
        AD_LastLogonDate   = $null
        AD_PasswordLastSet = $null
        AD_Description     = $null
        Lookup_Notes       = $null
    }
    $notes = New-Object System.Collections.Generic.List[string]

    $ip = ConvertTo-NormalizedIPv4 $KeyValue
    $hostName = ConvertTo-NormalizedHostName $KeyValue
    $kind = $KeyKind
    if ($kind -eq 'Auto' -or [string]::IsNullOrEmpty($kind)) {
        if ($ip) { $kind = 'IPv4' }
        elseif ($hostName) { $kind = 'Hostname' }
        else { $kind = 'Auto' }
    }
    $info.Key_Kind = $kind

    if ($kind -eq 'IPv4') {
        if (-not $ip) { $ip = ConvertTo-NormalizedIPv4 $KeyValue }
        if (-not $ip) {
            $notes.Add('Invalid or missing IP')
            $info.Lookup_Notes = ($notes -join '; ')
            return [pscustomobject]$info
        }
        $info.Resolved_IP = $ip

        $dns = Resolve-IpToHostName -IP $ip -DnsServer $DnsServer
        $fqdn = $dns.FQDN
        if (-not $fqdn -and $FallbackHost) {
            $existing = ConvertTo-NormalizedHostName $FallbackHost
            if (-not $existing -and $FallbackHost -and -not (Test-IPv4 $FallbackHost)) {
                $existing = $FallbackHost.Trim()
            }
            if ($existing) {
                $fqdn = $existing
                $dns.Method = 'Spreadsheet'
            }
        }
        if ($fqdn) {
            $info.Resolved_FQDN = $fqdn
            $info.Resolved_HostName = $fqdn.Split('.')[0].ToUpperInvariant()
            $info.Resolve_Method = $dns.Method
        }
        else {
            $notes.Add('No DNS/PTR record')
            if ($dns.Error) { $notes.Add($dns.Error) }
        }
    }
    elseif ($kind -eq 'Hostname') {
        if (-not $hostName) {
            $raw = if ($KeyValue) { $KeyValue.Trim() } else { '' }
            if ($raw -and -not (Test-IPv4 $raw)) { $hostName = $raw.TrimEnd('.') }
        }
        if (-not $hostName) {
            $notes.Add('Invalid or missing hostname')
            $info.Lookup_Notes = ($notes -join '; ')
            return [pscustomobject]$info
        }
        $info.Resolved_FQDN = $hostName
        $info.Resolved_HostName = $hostName.Split('.')[0].ToUpperInvariant()
        $info.Resolve_Method = 'Spreadsheet'

        $resolvedIp = ConvertTo-NormalizedIPv4 $FallbackIp
        if (-not $resolvedIp) {
            $resolvedIp = Resolve-HostToIp -Name $hostName -DnsServer $DnsServer
            if ($resolvedIp) { $info.Resolve_Method = 'DNS A + spreadsheet name' }
        }
        else {
            $info.Resolve_Method = 'Spreadsheet name + IP column'
        }
        $info.Resolved_IP = $resolvedIp
        $ip = $resolvedIp
    }
    else {
        $notes.Add('Could not interpret key value as IPv4 or hostname')
        $info.Lookup_Notes = ($notes -join '; ')
        return [pscustomobject]$info
    }

    if ($DoPing) {
        $pingTarget = if ($info.Resolved_IP) { $info.Resolved_IP } else { $KeyValue }
        $info.Ping = if (Test-Connection -ComputerName $pingTarget -Count 1 -Quiet -ErrorAction SilentlyContinue) { 'Online' } else { 'No reply' }
    }

    if ($AdAvailable -and ($info.Resolved_HostName -or $ip)) {
        $computer = Find-ADComputerRecord -FQDN $info.Resolved_FQDN -ShortName $info.Resolved_HostName -IP $ip -AdParams $AdParams
        if ($computer) {
            $info.AD_Found           = $true
            $info.AD_Enabled         = [bool]$computer.Enabled
            $info.AD_OperatingSystem = $computer.OperatingSystem
            $info.AD_OSVersion       = (@($computer.OperatingSystemVersion, $computer.OperatingSystemServicePack) | Where-Object { $_ }) -join ' '
            $info.AD_OU              = Get-OUFromDistinguishedName $computer.DistinguishedName
            $info.AD_OUPath          = Get-OUPathFromCanonicalName $computer.CanonicalName
            $info.AD_LastLogonDate   = $computer.LastLogonDate
            $info.AD_PasswordLastSet = $computer.PasswordLastSet
            $info.AD_Description     = $computer.Description
            if (-not $info.Resolved_FQDN -and $computer.DNSHostName) {
                $info.Resolved_FQDN = $computer.DNSHostName
                $info.Resolved_HostName = $computer.DNSHostName.Split('.')[0].ToUpperInvariant()
                if (-not $info.Resolve_Method) { $info.Resolve_Method = 'AD IPv4Address' }
            }
            if ($computer.IPv4Address) {
                if ($info.Resolved_IP -and $computer.IPv4Address -ne $info.Resolved_IP) {
                    $notes.Add("AD/DNS A record is $($computer.IPv4Address) (possible stale PTR)")
                }
                elseif (-not $info.Resolved_IP) {
                    $info.Resolved_IP = $computer.IPv4Address
                }
            }
        }
        else {
            $info.AD_Found = $false
            $notes.Add('Not found in AD (non-domain device, appliance, or stale DNS)')
        }
    }

    $info.Lookup_Notes = ($notes -join '; ')
    [pscustomobject]$info
}

#endregion

if ($SelfTest) {
    Invoke-SelfTest
    return
}

if ($SkipMain) { return }

try {
    Add-Type -AssemblyName System.Windows.Forms
}
catch {
    Write-Host "  Unable to load Windows.Forms (file dialogs unavailable): $($_.Exception.Message)" -ForegroundColor DarkYellow
}

#region ---------- Main ----------

Write-Banner

Write-Section 'Checking prerequisites'
$adAvailable = $false
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adAvailable = $true
    Write-Host '  ActiveDirectory module: found' -ForegroundColor Green
}
else {
    Write-Host '  ActiveDirectory module: NOT FOUND (install RSAT: AD DS Tools)' -ForegroundColor Red
    if (-not (Read-YesNo -Prompt '  Continue with DNS resolution only (no OS / OU / Enabled)?' -Default $false)) {
        Write-Host 'Exiting.'; return
    }
}
$excelText = if (Test-ExcelComAvailable) { 'found' } else { 'not found (CSV / ImportExcel will be used)' }
Write-Host "  Microsoft Excel       : $excelText" -ForegroundColor Gray

Write-Section 'Select the input spreadsheet'
$inputPath = $InputPath
if ($inputPath) {
    if (-not (Test-Path -LiteralPath $inputPath)) {
        Write-Host "  File not found: $inputPath" -ForegroundColor Red
        return
    }
    Write-Host "  Using -InputPath: $inputPath" -ForegroundColor Green
}
while (-not $inputPath) {
    Write-Host '  A file picker has opened (it may be behind other windows)...' -ForegroundColor Gray
    $inputPath = Select-InputFile
    if (-not $inputPath) {
        if (-not (Read-YesNo -Prompt '  No file selected. Try again?' -Default $true)) { Write-Host 'Exiting.'; return }
    }
}
Write-Host "  Selected: $inputPath" -ForegroundColor Green

try {
    $sheetData = Import-HostSpreadsheet -Path $inputPath
}
catch {
    Write-Host "  Failed to read spreadsheet: $($_.Exception.Message)" -ForegroundColor Red
    return
}
$rows = ConvertTo-ArrayList $sheetData.Rows
$headers = ConvertTo-StringArray $sheetData.Headers
Write-Host ("  Loaded {0} row(s), {1} column(s){2} (header row {3})" -f $rows.Count, $headers.Count,
    $(if ($sheetData.Sheet) { " from sheet '$($sheetData.Sheet)'" } else { '' }),
    $sheetData.HeaderRow) -ForegroundColor Green

Write-Section 'Column mapping'
$profiles = Get-ColumnProfiles -Headers $headers -Rows $rows
if ($null -eq $profiles -or $profiles.Count -eq 0) {
    Write-Host '  No headers were detected.' -ForegroundColor Red
    return
}
$suggested = Get-SuggestedKeyProfile -Profiles $profiles
$keyProfile = Select-KeyColumnInteractive -Profiles $profiles -SuggestedName $suggested.Name -PreselectedName $KeyColumn
$keyColumn = $keyProfile.Name
$effectiveKind = Select-KeyKindInteractive -SuggestedKind $keyProfile.KindHint -ColumnName $keyColumn -PreselectedKind $KeyKind

$hostColumn = $null
$ipCompanion = $null
$hostGuess = $null
$ipGuess = $null
foreach ($p in $profiles) {
    if ($p.Name -eq $keyColumn) { continue }
    if ($p.LooksLike -eq 'Hostname' -and ($null -eq $hostGuess -or [int]$p.Score -gt [int]$hostGuess.Score)) { $hostGuess = $p }
    if ($p.LooksLike -eq 'IPv4 address' -and ($null -eq $ipGuess -or [int]$p.Score -gt [int]$ipGuess.Score)) { $ipGuess = $p }
}
if ($effectiveKind -eq 'IPv4' -or $effectiveKind -eq 'Auto') {
    $hostColumn = Select-OptionalColumnInteractive -Title '  Optional hostname column (fallback when DNS PTR fails):' -Profiles $profiles -SuggestedName $(if ($null -ne $hostGuess) { $hostGuess.Name } else { $null }) -ExcludeName $keyColumn
}
if ($effectiveKind -eq 'Hostname' -or $effectiveKind -eq 'Auto') {
    $ipCompanion = Select-OptionalColumnInteractive -Title '  Optional IP column (used when the key is a hostname):' -Profiles $profiles -SuggestedName $(if ($null -ne $ipGuess) { $ipGuess.Name } else { $null }) -ExcludeName $keyColumn
}

Write-Host ''
Write-Host "  Key column : '$keyColumn' ($effectiveKind)" -ForegroundColor Green
if ($hostColumn) { Write-Host "  Hostname   : '$hostColumn' (fallback)" -ForegroundColor Green }
if ($ipCompanion) { Write-Host "  IP column  : '$ipCompanion' (companion)" -ForegroundColor Green }

Write-Host ''
Write-Host '  Preview of keyed values:' -ForegroundColor White
$previewN = [Math]::Min(5, $rows.Count)
for ($i = 0; $i -lt $previewN; $i++) {
    $pv = ConvertTo-CellText (Get-RowPropertyValue -Row $rows[$i] -Name $keyColumn)
    if ([string]::IsNullOrWhiteSpace($pv)) { $pv = '<blank>' }
    Write-Host ("    row {0,3}: {1}" -f ($i + 1 + [int]$sheetData.HeaderRow), $pv)
}
if (-not (Read-YesNo -Prompt '  Continue with this key column?' -Default $true)) {
    Write-Host 'Exiting.'; return
}

$adParams = @{}
$chosenAdDomain = $null
if ($adAvailable) {
    Write-Section 'Active Directory domain'
    if ($Server) {
        $adParams.Server = $Server
        Write-Host "  Using -Server '$Server'." -ForegroundColor Green
        if (Read-YesNo -Prompt '  Use alternate credentials for AD?' -Default $false) {
            $adParams.Credential = Get-Credential -Message "Enter credentials for $Server"
        }
        try {
            $identity = if ($Domain) { $Domain } else { $Server }
            $domainInfo = Connect-ChosenAdDomain -Identity $identity -AdParams $adParams
            $adParams.Server = $(if ($domainInfo.PDCEmulator) { $domainInfo.PDCEmulator } else { $Server })
            $chosenAdDomain = $domainInfo.DNSRoot
            Write-Host "  Connected to AD domain: $chosenAdDomain" -ForegroundColor Green
            Write-Host "  Domain controller    : $($adParams.Server)" -ForegroundColor Green
        }
        catch {
            Write-Host "  Could not contact AD via -Server: $($_.Exception.Message)" -ForegroundColor Red
            if (-not (Read-YesNo -Prompt '  Continue with DNS resolution only?' -Default $true)) { Write-Host 'Exiting.'; return }
            $adAvailable = $false
        }
    }
    else {
        Write-Host '  Discovering domains in the current forest and trusts...' -ForegroundColor DarkGray
        $catalog = Get-AdDomainCatalog
        $connected = $false
        while (-not $connected) {
            $choice = Select-AdDomainInteractive -Catalog $catalog -Preselected $Domain
            if ($null -eq $choice -or [string]::IsNullOrWhiteSpace($choice.DnsRoot)) {
                if (-not (Read-YesNo -Prompt '  No domain selected. Continue with DNS resolution only?' -Default $false)) {
                    Write-Host 'Exiting.'; return
                }
                $adAvailable = $false
                break
            }
            $adParams = @{}
            if (Read-YesNo -Prompt "  Use alternate credentials for '$($choice.DnsRoot)'?" -Default $false) {
                $adParams.Credential = Get-Credential -Message "Enter credentials for $($choice.DnsRoot)"
            }
            try {
                $domainInfo = Connect-ChosenAdDomain -Identity $choice.DnsRoot -AdParams $adParams
                $adParams.Server = $(if ($domainInfo.PDCEmulator) { $domainInfo.PDCEmulator } else { $domainInfo.DNSRoot })
                $chosenAdDomain = $domainInfo.DNSRoot
                Write-Host "  Connected to AD domain: $chosenAdDomain" -ForegroundColor Green
                if ($domainInfo.NetBIOSName) {
                    Write-Host "  NetBIOS name         : $($domainInfo.NetBIOSName)" -ForegroundColor Green
                }
                Write-Host "  Domain controller    : $($adParams.Server)" -ForegroundColor Green
                $connected = $true
            }
            catch {
                Write-Host "  Could not contact $($choice.DnsRoot): $($_.Exception.Message)" -ForegroundColor Red
                $Domain = $null
                if ($script:NonInteractive) {
                    if (-not (Read-YesNo -Prompt '  Continue with DNS resolution only?' -Default $true)) { Write-Host 'Exiting.'; return }
                    $adAvailable = $false
                    break
                }
                if (Read-YesNo -Prompt '  Pick a different domain?' -Default $true) { continue }
                if (-not (Read-YesNo -Prompt '  Continue with DNS resolution only?' -Default $true)) { Write-Host 'Exiting.'; return }
                $adAvailable = $false
                break
            }
        }
    }
}

Write-Section 'Lookup options'
if (-not $PSBoundParameters.ContainsKey('DnsServer')) {
    $DnsServer = (Read-Host '  DNS server to query (blank = system default)').Trim()
}

$doPing = if ($Ping) { $true } else { Read-YesNo -Prompt '  Ping each host to check if it is online? (slower)' -Default $false }
$fillHostColumn = $false
$fillIpColumn = $false
if ($hostColumn) {
    $fillHostColumn = Read-YesNo -Prompt "  Fill blank/IP-only values in '$hostColumn' with the resolved name?" -Default $true
}
if ($ipCompanion) {
    $fillIpColumn = Read-YesNo -Prompt "  Fill blank values in '$ipCompanion' with the resolved IP?" -Default $true
}

Write-Section 'Processing hosts'
$cache = @{}
$results = New-Object System.Collections.ArrayList
$total = $rows.Count
$index = 0

foreach ($row in $rows) {
    $index++
    $rawKey = ConvertTo-CellText (Get-RowPropertyValue -Row $row -Name $keyColumn)
    $fallbackHost = if ($hostColumn) { ConvertTo-CellText (Get-RowPropertyValue -Row $row -Name $hostColumn) } else { $null }
    $fallbackIp = if ($ipCompanion) { ConvertTo-CellText (Get-RowPropertyValue -Row $row -Name $ipCompanion) } else { $null }
    $cacheKey = '{0}|{1}|{2}|{3}' -f $effectiveKind, $rawKey.ToLowerInvariant(), [string]$fallbackHost, [string]$fallbackIp

    Write-Progress -Activity 'Resolving SMBv1 hosts' -Status "$index of $total : $rawKey" -PercentComplete (($index / [Math]::Max($total, 1)) * 100)

    if (-not $cache.ContainsKey($cacheKey)) {
        $cache[$cacheKey] = Get-HostEnrichment -KeyValue $rawKey -KeyKind $effectiveKind `
            -FallbackHost $fallbackHost -FallbackIp $fallbackIp -DnsServer $DnsServer `
            -AdParams $adParams -AdAvailable $adAvailable -DoPing $doPing -AdDomain $chosenAdDomain
    }

    $lookup = $cache[$cacheKey]

    $name = if ($lookup.Resolved_FQDN) { $lookup.Resolved_FQDN } else { '<unresolved>' }
    $status = if ($lookup.AD_Found -eq $true) {
        if ($lookup.AD_Enabled) { 'Enabled' } else { 'DISABLED' }
    } elseif ($lookup.AD_Found -eq $false) { 'Not in AD' } else { '-' }
    $color = switch ($status) { 'Enabled' { 'Green' } 'DISABLED' { 'Red' } 'Not in AD' { 'Yellow' } default { 'DarkGray' } }
    $displayKey = Get-TruncatedText $(if ($rawKey) { $rawKey } else { '<blank>' }) 20
    Write-Host ("  [{0,3}/{1}] {2,-22} {3,-40} {4,-30} {5}" -f $index, $total, $displayKey, (Get-TruncatedText $name 40), (Get-TruncatedText ([string]$lookup.AD_OperatingSystem) 30), $status) -ForegroundColor $color

    $merged = [ordered]@{}
    foreach ($h in $headers) { $merged[$h] = Get-RowPropertyValue -Row $row -Name $h }
    if ($fillHostColumn -and $hostColumn -and $lookup.Resolved_HostName) {
        $current = ConvertTo-CellText $merged[$hostColumn]
        if (-not $current -or (Test-IPv4 $current)) { $merged[$hostColumn] = $lookup.Resolved_HostName }
    }
    if ($fillIpColumn -and $ipCompanion -and $lookup.Resolved_IP) {
        $current = ConvertTo-CellText $merged[$ipCompanion]
        if (-not $current) { $merged[$ipCompanion] = $lookup.Resolved_IP }
    }
    $merged['Key_Column'] = $keyColumn
    foreach ($p in $lookup.PSObject.Properties) {
        if (-not $doPing -and $p.Name -eq 'Ping') { continue }
        if (-not $adAvailable -and $p.Name -like 'AD_*') { continue }
        $merged[$p.Name] = $p.Value
    }
    [void]$results.Add([pscustomobject]$merged)
}
Write-Progress -Activity 'Resolving SMBv1 hosts' -Completed

Write-Section 'Summary'
$resultArray = ConvertTo-ObjectArray $results
$resolved = @($resultArray | Where-Object { $_.Resolved_FQDN }).Count
Write-Host ("  Total rows        : {0}" -f $resultArray.Count)
Write-Host ("  Unique keys       : {0}" -f $cache.Count)
if ($chosenAdDomain) {
    Write-Host ("  AD domain         : {0}" -f $chosenAdDomain) -ForegroundColor Green
}
Write-Host ("  Resolved to name  : {0}" -f $resolved) -ForegroundColor Green
Write-Host ("  Unresolved        : {0}" -f ($resultArray.Count - $resolved)) -ForegroundColor Yellow
if ($adAvailable) {
    Write-Host ("  Found in AD       : {0}" -f @($resultArray | Where-Object { $_.AD_Found -eq $true }).Count) -ForegroundColor Green
    Write-Host ("  Enabled in AD     : {0}" -f @($resultArray | Where-Object { $_.AD_Enabled -eq $true }).Count) -ForegroundColor Green
    Write-Host ("  Disabled in AD    : {0}" -f @($resultArray | Where-Object { $_.AD_Found -eq $true -and $_.AD_Enabled -eq $false }).Count) -ForegroundColor Red
    Write-Host ("  Not in AD         : {0}" -f @($resultArray | Where-Object { $_.AD_Found -eq $false }).Count) -ForegroundColor Yellow

    Write-Host ''
    Write-Host '  By operating system:' -ForegroundColor White
    $resultArray | Where-Object { $_.AD_OperatingSystem } |
        Group-Object -Property AD_OperatingSystem | Sort-Object -Property Count -Descending |
        ForEach-Object { Write-Host ("    {0,4}  {1}" -f $_.Count, $_.Name) }

    Write-Host ''
    Write-Host '  By OU:' -ForegroundColor White
    $resultArray | Where-Object { $_.AD_OUPath } |
        Group-Object -Property AD_OUPath | Sort-Object -Property Count -Descending |
        ForEach-Object { Write-Host ("    {0,4}  {1}" -f $_.Count, $_.Name) }
}

Write-Section 'Save results'
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($inputPath)
$canWriteXlsx = (Test-ExcelComAvailable) -or [bool](Get-Module -ListAvailable -Name ImportExcel)
$defaultExt = if ($canWriteXlsx) { '.xlsx' } else { '.csv' }
$suggestedOut = Join-Path (Split-Path $inputPath -Parent) ("{0}_enriched_{1:yyyyMMdd_HHmm}{2}" -f $baseName, (Get-Date), $defaultExt)

$savedPath = $null
if ($OutputPath) {
    $outputPath = $OutputPath
}
else {
    $outputPath = Select-OutputFile -SuggestedPath $suggestedOut -AllowXlsx $canWriteXlsx
}
if (-not $outputPath) {
    Write-Host '  Save cancelled. Writing a CSV next to the input file instead.' -ForegroundColor Yellow
    $outputPath = [System.IO.Path]::ChangeExtension($suggestedOut, '.csv')
}

try {
    $savedPath = Export-Results -Rows $resultArray -Path $outputPath
    Write-Host "  Saved: $savedPath" -ForegroundColor Green
}
catch {
    $fallback = [System.IO.Path]::ChangeExtension($outputPath, '.csv')
    Write-Host "  Save failed ($($_.Exception.Message)). Writing CSV to $fallback" -ForegroundColor Red
    $resultArray | Export-Csv -Path $fallback -NoTypeInformation -Encoding (Get-CsvUtf8Encoding)
    $savedPath = $fallback
}

Write-Host ''
if (Read-YesNo -Prompt 'Open an interactive grid view of the results?' -Default $true) {
    $resultArray | Out-GridView -Title "SMBv1 host enrichment - $baseName"
}
if ($savedPath -and (Read-YesNo -Prompt 'Open the saved file now?' -Default $false)) {
    Invoke-Item -Path $savedPath
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Cyan

#endregion

#Requires -Version 5.1
<#
.SYNOPSIS
    Legacy Domain Retirement Assessment — comprehensive read-only inventory
    for collapsing / decommissioning an Active Directory domain.

.DESCRIPTION
    Collects the data needed to plan a graceful domain retirement and writes a
    self-contained HTML dashboard plus CSV extracts.

    Accuracy and robustness fixes versus earlier editions
    ----------------------------------------------------
    - Last logon: never-logged-on is no longer lumped in with stale; computer
      activity uses max(LastLogonTimestamp, PasswordLastSet) because machine
      passwords rotate while lastLogonTimestamp can lag ~9–14 days.
    - Optional -AccurateLastLogon queries lastLogon on every DC (non-replicated).
    - Privileged groups are resolved by well-known SID (works in non-English AD).
    - Group member counts use reverse memberOf + primaryGroupID — no per-group
      Get-ADGroupMember (avoids 1500-member truncation, FSP failures, timeouts
      on Domain Users / Domain Computers).
    - SYSVOL / DFSR state is read from AD (msDFSR-Flags), not the local registry.
    - NPS is taken from the RAS and IAS Servers group, not fictional nps/radius SPNs.
    - AD FS is detected via SCP, SPNs, and CN=ADFS,CN=Microsoft,CN=Program Data.
    - DNS searches DomainDnsZones, ForestDnsZones, AND CN=MicrosoftDNS,CN=System.
    - DHCP shows every authorised server; domain match is a column, not a filter.
    - GPO links include sites and parse enabled / enforced flags.
    - Collection-typed properties (FSMO roles, GCs, member lists) are joined
      instead of rendering as type names or "N/A".
    - Failed queries are distinguished from genuinely empty results.
    - Report is air-gapped: no CDN / Chart.js dependency.
    - Every dataset is also written as CSV for Excel / ticketing.

    Categories
    ----------
    Domain & forest, FSMO, DCs, sites/subnets/site links, users, computers,
    groups & privileged members, trusts, GPOs, DNS, DHCP, AD CS, AD FS,
    Entra Connect, NPS, replication, SYSVOL, SPN/delegation, OUs, password
    policy / FGPP, recycle bin, RID pool, schema, application partitions,
    Exchange / SCCM / DFS / print queues / SCPs, gMSA, BitLocker, LAPS,
    foreign security principals, logon scripts / profiles / home dirs.

.PARAMETER DomainController
    Target a specific DC for LDAP queries. Default: DC locator.

.PARAMETER DomainName
    FQDN of the domain (used as -Server when DomainController is omitted).

.PARAMETER Credential
    Alternate credentials. Example: -Credential (Get-Credential)

.PARAMETER StaleDays
    Days without evidence of activity before an object is stale. Default: 90.

.PARAMETER OutputPath
    Root folder for reports. Default: C:\Temp\LegacyDomainAssessment

.PARAMETER AccurateLastLogon
    Query the non-replicated lastLogon attribute on every DC. Slow on large
    domains; most accurate logon date.

.PARAMETER MaxHtmlRows
    Max rows per HTML table (full data is always in CSV). Default: 3000.

.PARAMETER DemoMode
    Generate a synthetic report without talking to Active Directory.

.PARAMETER NoLaunch
    Do not open the HTML report at the end.

.PARAMETER SkipCsv
    Do not write per-category CSV files.

.EXAMPLE
    .\Invoke-DomainRetirementAssessment.ps1

.EXAMPLE
    .\Invoke-DomainRetirementAssessment.ps1 -DomainController dc01.legacy.corp -Credential (Get-Credential)

.EXAMPLE
    .\Invoke-DomainRetirementAssessment.ps1 -AccurateLastLogon -StaleDays 60

.NOTES
    Requires RSAT ActiveDirectory module (not needed in -DemoMode).
    Group Policy / DnsServer / DhcpServer modules are NOT required.
    Read-only. Run as Domain Admin or an account that can read domain, config,
    schema, and application partitions.
    Windows PowerShell 5.1 or PowerShell 7+.
#>

[CmdletBinding()]
param(
    [string] $DomainController = '',
    [string] $DomainName       = '',
    [PSCredential] $Credential = $null,
    [int]    $StaleDays        = 90,
    [string] $OutputPath       = 'C:\Temp\LegacyDomainAssessment',
    [switch] $AccurateLastLogon,
    [int]    $MaxHtmlRows      = 3000,
    [switch] $DemoMode,
    [switch] $NoLaunch,
    [switch] $SkipCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$script:AssessmentVersion = '3.0.0'

# ═══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════════

function ConvertTo-HtmlEncoded {
    param([AllowNull()][object]$Text)
    if ($null -eq $Text) { return '' }
    $s = [string]$Text
    if ($s.Length -eq 0) { return '' }
    $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
}

function Get-Safe {
    param($Obj, [string]$Name, $Default = $null)
    if ($null -eq $Obj) { return $Default }
    try {
        $prop = $Obj.PSObject.Properties[$Name]
        if ($null -eq $prop) { return $Default }
        if ($null -eq $prop.Value) { return $Default }
        return $prop.Value
    }
    catch { return $Default }
}

function Format-DisplayValue {
    param($Value, [string]$DateFormat = 'yyyy-MM-dd HH:mm')
    if ($null -eq $Value) { return '' }
    if ($Value -is [DateTime]) {
        if ($Value.Year -lt 1980) { return 'Never' }
        return $Value.ToString($DateFormat)
    }
    if ($Value -is [bool]) { return $(if ($Value) { 'True' } else { 'False' }) }
    if ($Value -is [enum]) { return $Value.ToString() }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Security.Principal.SecurityIdentifier]) { return $Value.Value }
    if ($Value -is [byte[]]) { return ('[{0} bytes]' -f $Value.Length) }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            $rendered = Format-DisplayValue -Value $item -DateFormat $DateFormat
            if (-not [string]::IsNullOrWhiteSpace($rendered)) { [void]$parts.Add($rendered) }
        }
        return [string]::Join(', ', $parts.ToArray())
    }
    $s = $Value.ToString()
    if ($s -match 'Collection|Microsoft\.ActiveDirectory|System\.') {
        try {
            $alt = @($Value | ForEach-Object { if ($null -ne $_) { $_.ToString() } })
            if ($alt.Count -gt 0) { return [string]::Join(', ', $alt) }
        }
        catch { }
    }
    return $s
}

function Get-PropText {
    param($Obj, [string]$Name, [string]$Fallback = 'N/A')
    $v = Get-Safe -Obj $Obj -Name $Name
    if ($null -eq $v) { return $Fallback }
    $text = Format-DisplayValue -Value $v
    if ([string]::IsNullOrWhiteSpace($text)) { return $Fallback }
    return $text
}

function ConvertFrom-AdDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [DateTime]) {
            if ($Value.Year -lt 1980) { return $null }
            return $Value
        }
        $ft = [DateTime]::FromFileTime([int64]$Value)
        if ($ft.Year -lt 1980) { return $null }
        return $ft
    }
    catch { return $null }
}

function Get-EffectiveLogonDate {
    param($Account)
    $d = ConvertFrom-AdDate (Get-Safe $Account 'LastLogonDate')
    if ($null -ne $d) { return $d }
    foreach ($name in @('lastLogonTimestamp', 'LastLogonTimestamp', 'lastLogon', 'LastLogon', 'LastLogonAccurate')) {
        $d = ConvertFrom-AdDate (Get-Safe $Account $name)
        if ($null -ne $d) { return $d }
    }
    return $null
}

function Get-UacFlagNames {
    param($Uac)
    if ($null -eq $Uac) { return '' }
    try { $bits = [int]$Uac } catch { return '' }
    $names = New-Object System.Collections.Generic.List[string]
    $map = [ordered]@{
        0x0002     = 'Disabled'
        0x0008     = 'HomeDirRequired'
        0x0010     = 'Lockout'
        0x0020     = 'PasswordNotRequired'
        0x0080     = 'ReversibleEncryption'
        0x0100     = 'TempDuplicate'
        0x0800     = 'InterdomainTrust'
        0x10000    = 'PasswordNeverExpires'
        0x40000    = 'SmartcardRequired'
        0x80000    = 'UnconstrainedDelegation'
        0x100000   = 'NotDelegated'
        0x200000   = 'UseDesKeyOnly'
        0x400000   = 'DoNotRequirePreAuth'
        0x800000   = 'PasswordExpired'
        0x1000000  = 'TrustedToAuthForDelegation'
        0x4000000  = 'PartialSecrets(RODC)'
    }
    foreach ($entry in $map.GetEnumerator()) {
        if (($bits -band [int]$entry.Key) -ne 0) { [void]$names.Add([string]$entry.Value) }
    }
    if ($names.Count -eq 0) { return '' }
    return [string]::Join(', ', $names.ToArray())
}

function Test-UacBit {
    param($Uac, [int]$Bit)
    if ($null -eq $Uac) { return $false }
    try { return (([int]$Uac -band $Bit) -ne 0) } catch { return $false }
}

function Get-RidFromSid {
    param($Sid)
    if ($null -eq $Sid) { return $null }
    try {
        $text = if ($Sid -is [string]) { $Sid } else { $Sid.ToString() }
        $parts = $text -split '-'
        return [int]$parts[-1]
    }
    catch { return $null }
}

function Get-OuFromDn {
    param([string]$Dn)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return '' }
    $idx = $Dn.IndexOf(',')
    if ($idx -lt 0) { return $Dn }
    return $Dn.Substring($idx + 1)
}

function ConvertTo-StringList {
    param($Value)
    # Unary comma prevents PowerShell from enumerating the List on return
    # (empty -> $null, one item -> a string with no .Count under StrictMode).
    $out = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Value) { return , $out }
    if ($Value -is [string]) {
        if (-not [string]::IsNullOrWhiteSpace($Value)) { [void]$out.Add($Value) }
        return , $out
    }
    try {
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            $s = $item.ToString()
            if (-not [string]::IsNullOrWhiteSpace($s)) { [void]$out.Add($s) }
        }
    }
    catch { }
    return , $out
}

function ConvertTo-ObjectList {
    param($Value)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Value) { return , $out }
    if ($Value -is [string] -or $Value -is [ValueType]) {
        [void]$out.Add($Value)
        return , $out
    }
    try {
        foreach ($item in $Value) {
            if ($null -ne $item) { [void]$out.Add($item) }
        }
    }
    catch {
        [void]$out.Add($Value)
    }
    return , $out
}

function Join-StringList {
    param($Value, [string]$Separator = '; ')
    $list = ConvertTo-StringList $Value
    if ($list.Count -eq 0) { return '' }
    return [string]::Join($Separator, $list.ToArray())
}

$script:ErrorLog = New-Object 'System.Collections.Generic.List[PSCustomObject]'
$script:QueryNotes = New-Object 'System.Collections.Generic.List[PSCustomObject]'

function Write-ErrorEntry {
    param(
        [string]$Step,
        [string]$Category,
        [System.Management.Automation.ErrorRecord]$Err
    )
    $line = 'N/A'
    if ($null -ne $Err -and $null -ne $Err.InvocationInfo) {
        $src = ''
        try { $src = $Err.InvocationInfo.Line.Trim() } catch { $src = '' }
        $line = "Line $($Err.InvocationInfo.ScriptLineNumber): $src"
    }
    $msg = if ($null -ne $Err -and $null -ne $Err.Exception) { $Err.Exception.Message } else { 'Unknown error' }
    $typ = if ($null -ne $Err -and $null -ne $Err.Exception) { $Err.Exception.GetType().Name } else { 'Error' }
    $entry = [PSCustomObject]@{
        Timestamp     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Step          = $Step
        Category      = $Category
        Message       = $msg
        ExceptionType = $typ
        ScriptLine    = $line
    }
    $script:ErrorLog.Add($entry)
    Write-Warning "[$Step / $Category] $msg"
}

function Write-QueryNote {
    param([string]$Category, [string]$Message)
    $script:QueryNotes.Add([PSCustomObject]@{
        Category = $Category
        Message  = $Message
    })
}

function Invoke-AdCmd {
    param(
        [string]$Step,
        [string]$Category,
        [scriptblock]$Command,
        $DefaultValue = $null
    )
    try {
        $p = $script:AdServerParam
        $out = & $Command $p
        if ($null -eq $out) {
            if ($null -ne $DefaultValue) { return $DefaultValue }
            return @()
        }
        return $out
    }
    catch {
        Write-ErrorEntry -Step $Step -Category $Category -Err $_
        if ($null -ne $DefaultValue) { return $DefaultValue }
        return @()
    }
}

function New-EmptyTableNote {
    param([string]$Category)
    $errs = @($script:ErrorLog | Where-Object { $_.Category -like "*$Category*" -or $_.Step -like "*$Category*" })
    if ($errs.Count -gt 0) {
        $msg = ConvertTo-HtmlEncoded $errs[0].Message
        return "<p class='no-data'>Query failed for this category: $msg (see Error Log).</p>"
    }
    return '<p class="no-data">No objects found for this category.</p>'
}

function ConvertTo-HtmlTable {
    param(
        [Parameter(Mandatory)][string]$TableId,
        [object[]]$Data,
        [string[]]$Properties,
        [string]$CsvHint = '',
        [string]$EmptyCategory = ''
    )
    $rows = ConvertTo-ObjectList $Data
    if ($rows.Count -eq 0) {
        if ($EmptyCategory) { return (New-EmptyTableNote -Category $EmptyCategory) }
        return '<p class="no-data">No data collected for this category.</p>'
    }
    if (-not $Properties) {
        $Properties = @($rows[0].PSObject.Properties | Select-Object -ExpandProperty Name)
    }

    $total = $rows.Count
    $truncated = $false
    if ($MaxHtmlRows -gt 0 -and $total -gt $MaxHtmlRows) {
        $limited = New-Object System.Collections.Generic.List[object]
        $n = 0
        foreach ($r in $rows) {
            if ($n -ge $MaxHtmlRows) { break }
            [void]$limited.Add($r)
            $n++
        }
        $rows = $limited
        $truncated = $true
    }

    $sb = New-Object System.Text.StringBuilder
    if ($truncated) {
        $hint = if ($CsvHint) { " Full dataset: <code>$CsvHint</code>" } else { '' }
        [void]$sb.Append("<p class='truncate-note'>Showing $($rows.Count) of $total rows in the report.$hint</p>")
    }
    [void]$sb.Append("<div class='table-toolbar'><input class='table-search' type='search' placeholder='Filter...' oninput=""filterTable('$TableId',this.value)""><button class='btn-csv' type='button' onclick=""downloadTableCsv('$TableId')"">Download CSV</button><span class='row-count' id='cnt_$TableId'>$($rows.Count) rows</span></div>")
    [void]$sb.Append("<div class='table-wrapper'><table id='$TableId' class='data-table'>")
    [void]$sb.Append('<thead><tr>')
    foreach ($prop in $Properties) {
        [void]$sb.Append("<th onclick='sortTable(""$TableId"",this)'>$(ConvertTo-HtmlEncoded $prop) <span class='sort-arrow'>&#x21D5;</span></th>")
    }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $rows) {
        [void]$sb.Append('<tr>')
        foreach ($prop in $Properties) {
            $val = Get-Safe $row $prop
            $text = Format-DisplayValue $val
            $encoded = ConvertTo-HtmlEncoded $text
            [void]$sb.Append("<td title='$encoded'>$encoded</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function ConvertTo-InfoRows {
    param($Map)
    $sb = New-Object System.Text.StringBuilder
    if ($null -eq $Map) { return '' }
    foreach ($key in $Map.Keys) {
        $encK = ConvertTo-HtmlEncoded $key
        $encV = ConvertTo-HtmlEncoded (Format-DisplayValue $Map[$key])
        [void]$sb.Append("<tr><td>$encK</td><td>$encV</td></tr>")
    }
    return $sb.ToString()
}

function New-MetricCard {
    param([string]$Label, $Value, [string]$Sub = '', [string]$Level = '')
    $cls = if ($Level) { "metric-card metric-$Level" } else { 'metric-card' }
    $subHtml = if ($Sub) { "<div class='metric-sub'>$(ConvertTo-HtmlEncoded $Sub)</div>" } else { '' }
    return "<div class='$cls'><div class='metric-label'>$(ConvertTo-HtmlEncoded $Label)</div><div class='metric-value'>$(ConvertTo-HtmlEncoded ([string]$Value))</div>$subHtml</div>"
}

function New-NavItem {
    param([string]$Id, [string]$Icon, [string]$Label, [int]$Count = -1, [string]$CountClass = 'nav-badge-neutral')
    $badge = ''
    if ($Count -ge 0) {
        $cls = if ($Count -eq 0) { 'nav-badge nav-badge-ok' } else { "nav-badge $CountClass" }
        $badge = " <span class='$cls'>$Count</span>"
    }
    return "<li><a href='#$Id' class='nav-link' data-section='$Id'><span class='nav-icon'>$Icon</span>$Label$badge</a></li>"
}

function Format-SeverityBadge {
    param([string]$Severity)
    $cls = switch ($Severity) {
        'Critical' { 'badge-critical' }
        'High'     { 'badge-high' }
        'Medium'   { 'badge-medium' }
        'Low'      { 'badge-low' }
        default    { 'badge-info' }
    }
    return "<span class='badge $cls'>$(ConvertTo-HtmlEncoded $Severity)</span>"
}

function Get-SchemaVersionName {
    param($Version)
    $n = 0
    try { $n = [int]$Version } catch { return $(if ($Version) { [string]$Version } else { 'Unknown' }) }
    switch ($n) {
        13  { '13 — Windows 2000' }
        30  { '30 — Windows Server 2003' }
        31  { '31 — Windows Server 2003 R2' }
        44  { '44 — Windows Server 2008' }
        47  { '47 — Windows Server 2008 R2' }
        56  { '56 — Windows Server 2012' }
        69  { '69 — Windows Server 2012 R2' }
        87  { '87 — Windows Server 2016' }
        88  { '88 — Windows Server 2019 / 2022' }
        91  { '91 — Windows Server 2025' }
        default { "$n" }
    }
}

function Get-DfsrStateName {
    param($Flags)
    if ($null -eq $Flags) { return 'Unknown' }
    try { $n = [int]$Flags } catch { return "Raw: $Flags" }
    switch ($n) {
        0  { 'Start (NTFRS / FRS mode)' }
        16 { 'Prepared (FRS + DFSR)' }
        32 { 'Redirected (DFSR primary, FRS leftover)' }
        48 { 'Eliminated (DFSR only)' }
        default { "msDFSR-Flags=$n" }
    }
}

function Get-FunctionalLevelName {
    param($Value)
    if ($null -eq $Value) { return 'N/A' }
    $s = $Value.ToString()
    switch ($s) {
        '0' { 'Windows 2000' }
        '1' { 'Windows Server 2003 Interim' }
        '2' { 'Windows Server 2003' }
        '3' { 'Windows Server 2008' }
        '4' { 'Windows Server 2008 R2' }
        '5' { 'Windows Server 2012' }
        '6' { 'Windows Server 2012 R2' }
        '7' { 'Windows Server 2016' }
        '10' { 'Windows Server 2025' }
        default { $s }
    }
}

function Test-ServiceAccount {
    param($User)
    $sam  = ([string](Get-Safe $User 'SamAccountName' '')).ToLowerInvariant()
    $desc = ([string](Get-Safe $User 'Description' '')).ToLowerInvariant()
    $name = ([string](Get-Safe $User 'Name' '')).ToLowerInvariant()
    $spns = ConvertTo-StringList (Get-Safe $User 'ServicePrincipalNames')
    if ($spns.Count -eq 0) { $spns = ConvertTo-StringList (Get-Safe $User 'servicePrincipalName') }
    if ($spns.Count -gt 0) { return $true }
    if ($sam -match '^(svc[-_\.]|service[-_\.]|gmsa[-_]?|msa[-_]?|sql[-_\.]|iis[-_\.]|app[-_\.]|npa_|usr_svc|sa_)') { return $true }
    if ($sam -match '[-_](svc|service|gmsa)$') { return $true }
    if ($sam -eq 'krbtgt') { return $true }
    if ($sam -like 'msol_*' -or $sam -like 'aad_*' -or $sam -like 'sync_*') { return $true }
    if ($desc -match 'service account|gMSA|group managed|application identity|iis app pool|scheduled task|used by .+ service|sql server|ldap bind|ad connect|dirsync') { return $true }
    if ($name -match 'service account') { return $true }
    return $false
}

function Export-AssessmentCsv {
    param([string]$Name, $Data)
    if ($SkipCsv) { return }
    if ($null -eq $Data) { return }
    $arr = ConvertTo-ObjectList $Data
    if ($arr.Count -eq 0) { return }
    $path = Join-Path $script:CsvDir ($Name + '.csv')
    try {
        $flat = @(foreach ($row in $arr) {
            $h = [ordered]@{}
            foreach ($prop in $row.PSObject.Properties) {
                $h[$prop.Name] = Format-DisplayValue $prop.Value
            }
            [PSCustomObject]$h
        })
        $flat | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    }
    catch {
        Write-ErrorEntry -Step 'CSV Export' -Category $Name -Err $_
    }
}

function New-AlertBox {
    param([string]$Kind, [string]$Html)
    $cls = switch ($Kind) {
        'crit' { 'alert-crit' }
        'high' { 'alert-high' }
        'ok'   { 'alert-ok' }
        default { 'alert-ok' }
    }
    return "<div class='alert-box $cls'>$Html</div>"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Setup
# ═══════════════════════════════════════════════════════════════════════════════

$script:AdServerParam = @{}
if ($DomainController) { $script:AdServerParam['Server'] = $DomainController }
elseif ($DomainName)   { $script:AdServerParam['Server'] = $DomainName }
if ($Credential)       { $script:AdServerParam['Credential'] = $Credential }

$DateStamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$ReportRoot = Join-Path $OutputPath $DateStamp
New-Item -Path $ReportRoot -ItemType Directory -Force | Out-Null
$script:CsvDir = Join-Path $ReportRoot 'csv'
if (-not $SkipCsv) { New-Item -Path $script:CsvDir -ItemType Directory -Force | Out-Null }
$CutoffDate = (Get-Date).AddDays(-$StaleDays)
$AssessmentDate = Get-Date -Format 'dddd, MMMM dd, yyyy  HH:mm:ss'

Write-Host ''
Write-Host '╔══════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
Write-Host '║  Legacy Domain Retirement Assessment  v3.0               ║' -ForegroundColor Cyan
Write-Host '╚══════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
Write-Host "Report Path : $ReportRoot" -ForegroundColor Yellow
if ($DemoMode)         { Write-Host 'Mode        : DEMO (synthetic data, no AD queries)' -ForegroundColor Magenta }
if ($DomainController) { Write-Host "Target DC   : $DomainController" -ForegroundColor Yellow }
if ($DomainName)       { Write-Host "Domain      : $DomainName" -ForegroundColor Yellow }
if ($Credential)       { Write-Host "Credential  : $($Credential.UserName)" -ForegroundColor Yellow }
if ($AccurateLastLogon){ Write-Host 'LastLogon   : Per-DC lastLogon (accurate, slower)' -ForegroundColor Yellow }
Write-Host "StaleDays   : $StaleDays" -ForegroundColor Yellow
Write-Host ''

# ═══════════════════════════════════════════════════════════════════════════════
#  Demo data (lets the HTML/CSV pipeline be validated without a domain)
# ═══════════════════════════════════════════════════════════════════════════════

function Get-DemoData {
    $now = Get-Date
    $domainDn = 'DC=legacy,DC=corp'
    $sidPrefix = 'S-1-5-21-1000-2000-3000'

    $domain = [PSCustomObject]@{
        DNSRoot                = 'legacy.corp'
        NetBIOSName            = 'LEGACY'
        DomainMode             = 'Windows2016Domain'
        DistinguishedName      = $domainDn
        PDCEmulator            = 'dc01.legacy.corp'
        RIDMaster              = 'dc01.legacy.corp'
        InfrastructureMaster   = 'dc02.legacy.corp'
        DomainSID              = $sidPrefix
        ParentDomain           = 'corp.local'
        ChildDomains           = @()
        ReplicaDirectoryServers= @('dc01.legacy.corp', 'dc02.legacy.corp')
        ComputersContainer     = "CN=Computers,$domainDn"
        UsersContainer         = "CN=Users,$domainDn"
        DeletedObjectsContainer= "CN=Deleted Objects,$domainDn"
    }
    $forest = [PSCustomObject]@{
        Name                 = 'corp.local'
        ForestMode           = 'Windows2016Forest'
        SchemaMaster         = 'dc01.corp.local'
        DomainNamingMaster   = 'dc01.corp.local'
        GlobalCatalogs       = @('dc01.legacy.corp', 'dc01.corp.local')
        Domains              = @('corp.local', 'legacy.corp')
        UPNSuffixes          = @('legacy.corp', 'contoso.com')
        RootDomain           = 'corp.local'
    }

    $dcs = @(
        [PSCustomObject]@{ HostName='dc01.legacy.corp'; Site='HQ'; IPv4Address='10.10.10.11'; OperatingSystem='Windows Server 2019 Standard'; OperatingSystemVersion='10.0 (17763)'; IsGlobalCatalog=$true; IsReadOnly=$false; OperationMasterRoles=@('PDCEmulator','RIDMaster','InfrastructureMaster'); Enabled=$true }
        [PSCustomObject]@{ HostName='dc02.legacy.corp'; Site='DR'; IPv4Address='10.10.20.11'; OperatingSystem='Windows Server 2016 Standard'; OperatingSystemVersion='10.0 (14393)'; IsGlobalCatalog=$true; IsReadOnly=$false; OperationMasterRoles=@(); Enabled=$true }
    )

    $users = @(
        [PSCustomObject]@{ Name='Alice Smith'; SamAccountName='asmith'; Enabled=$true; LastLogonDate=$now.AddDays(-1); Mail='alice@legacy.corp'; PasswordLastSet=$now.AddDays(-40); DistinguishedName="CN=Alice Smith,OU=Users,$domainDn"; UserPrincipalName='alice@legacy.corp'; Description='Finance'; PasswordNeverExpires=$false; adminCount=0; ScriptPath='finance.bat'; HomeDirectory='\\fs01\users\asmith'; ProfilePath=''; SIDHistory=@("$sidPrefix-1111"); UserAccountControl=512; primaryGroupID=513; ServicePrincipalNames=@(); MemberOf=@("CN=Finance,OU=Groups,$domainDn"); AccountExpirationDate=$null; PasswordNotRequired=$false; AllowReversiblePasswordEncryption=$false; DoesNotRequirePreAuth=$false; LockedOut=$false; SmartcardLogonRequired=$false; logonCount=400; Department='Finance'; Title='Analyst'; ObjectClass='user'; WhenCreated=$now.AddYears(-6) }
        [PSCustomObject]@{ Name='Bob Admin'; SamAccountName='badmin'; Enabled=$true; LastLogonDate=$now.AddDays(-2); Mail='bob@legacy.corp'; PasswordLastSet=$now.AddDays(-10); DistinguishedName="CN=Bob Admin,OU=IT,$domainDn"; UserPrincipalName='bob@legacy.corp'; Description='Domain admin'; PasswordNeverExpires=$true; adminCount=1; ScriptPath=''; HomeDirectory=''; ProfilePath=''; SIDHistory=@(); UserAccountControl=66048; primaryGroupID=513; ServicePrincipalNames=@(); MemberOf=@("CN=Domain Admins,CN=Users,$domainDn"); AccountExpirationDate=$null; PasswordNotRequired=$false; AllowReversiblePasswordEncryption=$false; DoesNotRequirePreAuth=$false; LockedOut=$false; SmartcardLogonRequired=$false; logonCount=900; Department='IT'; Title='Admin'; ObjectClass='user'; WhenCreated=$now.AddYears(-8) }
        [PSCustomObject]@{ Name='SQL Service'; SamAccountName='svc-sql'; Enabled=$true; LastLogonDate=$now.AddDays(-5); Mail=''; PasswordLastSet=$now.AddDays(-300); DistinguishedName="CN=SQL Service,OU=Service Accounts,$domainDn"; UserPrincipalName='svc-sql@legacy.corp'; Description='SQL Server service account'; PasswordNeverExpires=$true; adminCount=0; ScriptPath=''; HomeDirectory=''; ProfilePath=''; SIDHistory=@(); UserAccountControl=66048; primaryGroupID=513; ServicePrincipalNames=@('MSSQLSvc/sql01.legacy.corp:1433'); MemberOf=@("CN=SQL Admins,OU=Groups,$domainDn"); AccountExpirationDate=$null; PasswordNotRequired=$false; AllowReversiblePasswordEncryption=$false; DoesNotRequirePreAuth=$false; LockedOut=$false; SmartcardLogonRequired=$false; logonCount=20; Department='IT'; Title='Service'; ObjectClass='user'; WhenCreated=$now.AddYears(-5) }
        [PSCustomObject]@{ Name='Old Vendor'; SamAccountName='jvendor'; Enabled=$true; LastLogonDate=$now.AddDays(-400); Mail=''; PasswordLastSet=$now.AddDays(-400); DistinguishedName="CN=Old Vendor,OU=Users,$domainDn"; UserPrincipalName='jvendor@legacy.corp'; Description='Former contractor'; PasswordNeverExpires=$false; adminCount=0; ScriptPath=''; HomeDirectory=''; ProfilePath=''; SIDHistory=@(); UserAccountControl=512; primaryGroupID=513; ServicePrincipalNames=@(); MemberOf=@(); AccountExpirationDate=$now.AddDays(-30); PasswordNotRequired=$false; AllowReversiblePasswordEncryption=$false; DoesNotRequirePreAuth=$true; LockedOut=$false; SmartcardLogonRequired=$false; logonCount=3; Department=''; Title=''; ObjectClass='user'; WhenCreated=$now.AddYears(-9) }
        [PSCustomObject]@{ Name='Never Logged On'; SamAccountName='newhire'; Enabled=$true; LastLogonDate=$null; Mail='new@legacy.corp'; PasswordLastSet=$null; DistinguishedName="CN=Never Logged On,OU=Users,$domainDn"; UserPrincipalName='new@legacy.corp'; Description='Created for onboarding'; PasswordNeverExpires=$false; adminCount=0; ScriptPath=''; HomeDirectory=''; ProfilePath=''; SIDHistory=@(); UserAccountControl=544; primaryGroupID=513; ServicePrincipalNames=@(); MemberOf=@(); AccountExpirationDate=$null; PasswordNotRequired=$true; AllowReversiblePasswordEncryption=$false; DoesNotRequirePreAuth=$false; LockedOut=$false; SmartcardLogonRequired=$false; logonCount=0; Department='HR'; Title=''; ObjectClass='user'; WhenCreated=$now.AddDays(-10) }
        [PSCustomObject]@{ Name='Disabled User'; SamAccountName='duser'; Enabled=$false; LastLogonDate=$now.AddDays(-800); Mail=''; PasswordLastSet=$now.AddDays(-800); DistinguishedName="CN=Disabled User,OU=Disabled,$domainDn"; UserPrincipalName='duser@legacy.corp'; Description='Left company'; PasswordNeverExpires=$false; adminCount=0; ScriptPath=''; HomeDirectory=''; ProfilePath=''; SIDHistory=@(); UserAccountControl=514; primaryGroupID=513; ServicePrincipalNames=@(); MemberOf=@(); AccountExpirationDate=$null; PasswordNotRequired=$false; AllowReversiblePasswordEncryption=$false; DoesNotRequirePreAuth=$false; LockedOut=$false; SmartcardLogonRequired=$false; logonCount=12; Department=''; Title=''; ObjectClass='user'; WhenCreated=$now.AddYears(-10) }
        [PSCustomObject]@{ Name='KRBTGT'; SamAccountName='krbtgt'; Enabled=$false; LastLogonDate=$null; Mail=''; PasswordLastSet=$now.AddDays(-900); DistinguishedName="CN=krbtgt,CN=Users,$domainDn"; UserPrincipalName=''; Description='Key Distribution Center Service Account'; PasswordNeverExpires=$true; adminCount=1; ScriptPath=''; HomeDirectory=''; ProfilePath=''; SIDHistory=@(); UserAccountControl=528; primaryGroupID=513; ServicePrincipalNames=@('kadmin/changepw'); MemberOf=@(); AccountExpirationDate=$null; PasswordNotRequired=$false; AllowReversiblePasswordEncryption=$false; DoesNotRequirePreAuth=$false; LockedOut=$false; SmartcardLogonRequired=$false; logonCount=0; Department=''; Title=''; ObjectClass='user'; WhenCreated=$now.AddYears(-12) }
    )

    $computers = @(
        [PSCustomObject]@{ Name='APP01'; DNSHostName='app01.legacy.corp'; Enabled=$true; LastLogonDate=$now.AddDays(-3); PasswordLastSet=$now.AddDays(-12); OperatingSystem='Windows Server 2019 Standard'; OperatingSystemVersion='10.0 (17763)'; IPv4Address='10.10.10.40'; DistinguishedName="CN=APP01,OU=Servers,$domainDn"; Description='Line of business app'; ServicePrincipalNames=@('HOST/APP01','TERMSRV/APP01'); MemberOf=@("CN=App Servers,OU=Groups,$domainDn"); primaryGroupID=515; UserAccountControl=4096; SIDHistory=@(); msDS_ExternalDirectoryObjectId=''; WhenCreated=$now.AddYears(-4) }
        [PSCustomObject]@{ Name='WKS-OLD'; DNSHostName='wks-old.legacy.corp'; Enabled=$true; LastLogonDate=$null; PasswordLastSet=$now.AddDays(-400); OperatingSystem='Windows 7 Professional'; OperatingSystemVersion='6.1 (7601)'; IPv4Address=''; DistinguishedName="CN=WKS-OLD,OU=Workstations,$domainDn"; Description='Stale workstation'; ServicePrincipalNames=@('HOST/WKS-OLD'); MemberOf=@(); primaryGroupID=515; UserAccountControl=4096; SIDHistory=@(); msDS_ExternalDirectoryObjectId=''; WhenCreated=$now.AddYears(-8) }
        [PSCustomObject]@{ Name='SQL01'; DNSHostName='sql01.legacy.corp'; Enabled=$true; LastLogonDate=$now.AddDays(-1); PasswordLastSet=$now.AddDays(-8); OperatingSystem='Windows Server 2016 Standard'; OperatingSystemVersion='10.0 (14393)'; IPv4Address='10.10.10.50'; DistinguishedName="CN=SQL01,OU=Servers,$domainDn"; Description='SQL Server'; ServicePrincipalNames=@('MSSQLSvc/sql01.legacy.corp:1433','HOST/SQL01'); MemberOf=@(); primaryGroupID=515; UserAccountControl=528384; SIDHistory=@(); msDS_ExternalDirectoryObjectId=''; WhenCreated=$now.AddYears(-5) }
        [PSCustomObject]@{ Name='NPS01'; DNSHostName='nps01.legacy.corp'; Enabled=$true; LastLogonDate=$now.AddDays(-2); PasswordLastSet=$now.AddDays(-15); OperatingSystem='Windows Server 2019 Standard'; OperatingSystemVersion='10.0 (17763)'; IPv4Address='10.10.10.60'; DistinguishedName="CN=NPS01,OU=Servers,$domainDn"; Description='Network Policy Server'; ServicePrincipalNames=@('HOST/NPS01'); MemberOf=@("CN=RAS and IAS Servers,CN=Users,$domainDn"); primaryGroupID=515; UserAccountControl=4096; SIDHistory=@(); msDS_ExternalDirectoryObjectId=''; WhenCreated=$now.AddYears(-3) }
        [PSCustomObject]@{ Name='ADFS01'; DNSHostName='adfs01.legacy.corp'; Enabled=$true; LastLogonDate=$now.AddDays(-1); PasswordLastSet=$now.AddDays(-9); OperatingSystem='Windows Server 2019 Standard'; OperatingSystemVersion='10.0 (17763)'; IPv4Address='10.10.10.70'; DistinguishedName="CN=ADFS01,OU=Servers,$domainDn"; Description='AD FS farm node'; ServicePrincipalNames=@('http/adfs.legacy.corp','HOST/ADFS01'); MemberOf=@(); primaryGroupID=515; UserAccountControl=4096; SIDHistory=@(); msDS_ExternalDirectoryObjectId=''; WhenCreated=$now.AddYears(-3) }
        [PSCustomObject]@{ Name='DC01'; DNSHostName='dc01.legacy.corp'; Enabled=$true; LastLogonDate=$now; PasswordLastSet=$now.AddDays(-5); OperatingSystem='Windows Server 2019 Standard'; OperatingSystemVersion='10.0 (17763)'; IPv4Address='10.10.10.11'; DistinguishedName="CN=DC01,OU=Domain Controllers,$domainDn"; Description=''; ServicePrincipalNames=@('HOST/DC01','ldap/DC01'); MemberOf=@(); primaryGroupID=516; UserAccountControl=532480; SIDHistory=@(); msDS_ExternalDirectoryObjectId=''; WhenCreated=$now.AddYears(-6) }
    )

    $groups = @(
        [PSCustomObject]@{ Name='Domain Admins'; SamAccountName='Domain Admins'; GroupCategory='Security'; GroupScope='Global'; DistinguishedName="CN=Domain Admins,CN=Users,$domainDn"; Description='Designated administrators of the domain'; MemberOf=@("CN=Administrators,CN=Builtin,$domainDn"); Members=@("CN=Bob Admin,OU=IT,$domainDn"); Mail=''; ManagedBy=''; WhenCreated=$now.AddYears(-12); SID="$sidPrefix-512"; ObjectSID="$sidPrefix-512" }
        [PSCustomObject]@{ Name='Finance'; SamAccountName='Finance'; GroupCategory='Security'; GroupScope='Global'; DistinguishedName="CN=Finance,OU=Groups,$domainDn"; Description='Finance department'; MemberOf=@("CN=File-Finance,OU=Groups,$domainDn"); Members=@("CN=Alice Smith,OU=Users,$domainDn"); Mail='finance@legacy.corp'; ManagedBy='CN=Alice Smith,OU=Users,$domainDn'; WhenCreated=$now.AddYears(-6); SID="$sidPrefix-1101"; ObjectSID="$sidPrefix-1101" }
        [PSCustomObject]@{ Name='File-Finance'; SamAccountName='File-Finance'; GroupCategory='Security'; GroupScope='DomainLocal'; DistinguishedName="CN=File-Finance,OU=Groups,$domainDn"; Description='ACL group for finance share'; MemberOf=@(); Members=@("CN=Finance,OU=Groups,$domainDn"); Mail=''; ManagedBy=''; WhenCreated=$now.AddYears(-6); SID="$sidPrefix-1102"; ObjectSID="$sidPrefix-1102" }
        [PSCustomObject]@{ Name='Empty-Old'; SamAccountName='Empty-Old'; GroupCategory='Security'; GroupScope='Global'; DistinguishedName="CN=Empty-Old,OU=Groups,$domainDn"; Description='Unused'; MemberOf=@(); Members=@(); Mail=''; ManagedBy=''; WhenCreated=$now.AddYears(-9); SID="$sidPrefix-1199"; ObjectSID="$sidPrefix-1199" }
        [PSCustomObject]@{ Name='RAS and IAS Servers'; SamAccountName='RAS and IAS Servers'; GroupCategory='Security'; GroupScope='DomainLocal'; DistinguishedName="CN=RAS and IAS Servers,CN=Users,$domainDn"; Description='Servers in this group can access remote access properties of users'; MemberOf=@(); Members=@("CN=NPS01,OU=Servers,$domainDn"); Mail=''; ManagedBy=''; WhenCreated=$now.AddYears(-12); SID="$sidPrefix-553"; ObjectSID="$sidPrefix-553" }
        [PSCustomObject]@{ Name='Domain Users'; SamAccountName='Domain Users'; GroupCategory='Security'; GroupScope='Global'; DistinguishedName="CN=Domain Users,CN=Users,$domainDn"; Description='All domain users'; MemberOf=@(); Members=@(); Mail=''; ManagedBy=''; WhenCreated=$now.AddYears(-12); SID="$sidPrefix-513"; ObjectSID="$sidPrefix-513" }
        [PSCustomObject]@{ Name='SQL Admins'; SamAccountName='SQL Admins'; GroupCategory='Security'; GroupScope='Global'; DistinguishedName="CN=SQL Admins,OU=Groups,$domainDn"; Description='SQL'; MemberOf=@(); Members=@("CN=SQL Service,OU=Service Accounts,$domainDn"); Mail=''; ManagedBy=''; WhenCreated=$now.AddYears(-5); SID="$sidPrefix-1200"; ObjectSID="$sidPrefix-1200" }
        [PSCustomObject]@{ Name='App Servers'; SamAccountName='App Servers'; GroupCategory='Security'; GroupScope='Global'; DistinguishedName="CN=App Servers,OU=Groups,$domainDn"; Description=''; MemberOf=@(); Members=@("CN=APP01,OU=Servers,$domainDn"); Mail=''; ManagedBy=''; WhenCreated=$now.AddYears(-4); SID="$sidPrefix-1201"; ObjectSID="$sidPrefix-1201" }
    )

    [PSCustomObject]@{
        Domain              = $domain
        Forest              = $forest
        RootDSE             = [PSCustomObject]@{ defaultNamingContext=$domainDn; rootDomainNamingContext='DC=corp,DC=local'; configurationNamingContext='CN=Configuration,DC=corp,DC=local'; schemaNamingContext='CN=Schema,CN=Configuration,DC=corp,DC=local'; namingContexts=@($domainDn,'CN=Configuration,DC=corp,DC=local','CN=Schema,CN=Configuration,DC=corp,DC=local',"DC=DomainDnsZones,$domainDn") }
        DCs                 = $dcs
        Sites               = @([PSCustomObject]@{ Name='HQ'; Description='Headquarters'; DistinguishedName='CN=HQ,CN=Sites,CN=Configuration,DC=corp,DC=local'; gpLink='' }, [PSCustomObject]@{ Name='DR'; Description='DR site'; DistinguishedName='CN=DR,CN=Sites,CN=Configuration,DC=corp,DC=local'; gpLink='' })
        Subnets             = @([PSCustomObject]@{ Name='10.10.10.0/24'; Site='HQ'; Description='HQ LAN'; Location='Building A'; DistinguishedName='CN=10.10.10.0/24,CN=Subnets,CN=Sites,CN=Configuration,DC=corp,DC=local' }, [PSCustomObject]@{ Name='10.10.20.0/24'; Site='DR'; Description='DR LAN'; Location='DR cage'; DistinguishedName='CN=10.10.20.0/24,CN=Subnets,CN=Sites,CN=Configuration,DC=corp,DC=local' })
        SiteLinks           = @([PSCustomObject]@{ Name='HQ-DR'; Cost=100; ReplicationFrequencyInMinutes=15; SitesIncluded=@('HQ','DR'); DistinguishedName='CN=HQ-DR,CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,DC=corp,DC=local' })
        Users               = $users
        Computers           = $computers
        Groups              = $groups
        Trusts              = @([PSCustomObject]@{ Name='corp.local'; Direction='Bidirectional'; TrustType='Forest'; ForestTransitive=$true; SelectiveAuthentication=$false; SIDFilteringForestAware=$true; SIDFilteringQuarantined=$false; DisallowTransivity=$false; TGTDelegation=$false; IntraForest=$false; UsesAESKeys=$true; UsesRC4Encryption=$false; UplevelOnly=$true; Created=$now.AddYears(-5); Modified=$now.AddDays(-90); DistinguishedName="CN=corp.local,CN=System,$domainDn" })
        GPOs                = @()
        RawGPOs             = @([PSCustomObject]@{ Name='{31B2F340-016D-11D2-945F-00C04FB984F9}'; displayName='Default Domain Policy'; whenCreated=$now.AddYears(-12); whenChanged=$now.AddDays(-20); gPCFileSysPath="\\legacy.corp\sysvol\legacy.corp\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}"; flags=0; gPCUserExtensionNames='Yes'; gPCMachineExtensionNames='Yes'; description='Default'; DistinguishedName="CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,$domainDn"; versionNumber=15; gPCWQLFilter='' }, [PSCustomObject]@{ Name='{6AC1786C-016F-11D2-945F-00C04FB984F9}'; displayName='Default Domain Controllers Policy'; whenCreated=$now.AddYears(-12); whenChanged=$now.AddDays(-40); gPCFileSysPath="\\legacy.corp\sysvol\legacy.corp\Policies\{6AC1786C-016F-11D2-945F-00C04FB984F9}"; flags=0; gPCUserExtensionNames=''; gPCMachineExtensionNames='Yes'; description=''; DistinguishedName="CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=Policies,CN=System,$domainDn"; versionNumber=8; gPCWQLFilter='' }, [PSCustomObject]@{ Name='{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}'; displayName='Unlinked Legacy App Policy'; whenCreated=$now.AddYears(-7); whenChanged=$now.AddYears(-3); gPCFileSysPath="\\legacy.corp\sysvol\legacy.corp\Policies\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"; flags=3; gPCUserExtensionNames=''; gPCMachineExtensionNames=''; description='Orphaned'; DistinguishedName="CN={AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE},CN=Policies,CN=System,$domainDn"; versionNumber=1; gPCWQLFilter='' })
        LinkedObjects       = @([PSCustomObject]@{ DistinguishedName=$domainDn; gpLink='[LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=legacy,DC=corp;0]' }, [PSCustomObject]@{ DistinguishedName="OU=Domain Controllers,$domainDn"; gpLink='[LDAP://CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=legacy,DC=corp;2]' })
        DnsZones            = @()
        DhcpServers         = @([PSCustomObject]@{ DnsName='dhcp01.legacy.corp'; IPAddress='10.10.10.20'; Created=$now.AddYears(-4); Description='Primary DHCP'; DistinguishedName='CN=10.10.10.20,CN=NetServices,CN=Services,CN=Configuration,DC=corp,DC=local'; InTargetDomain=$true })
        CAs                 = @([PSCustomObject]@{ Name='legacy-CA01-CA'; dNSHostName='ca01.legacy.corp'; cACertificateDN='CN=legacy-CA01-CA,DC=legacy,DC=corp'; whenCreated=$now.AddYears(-6); Description='Enterprise CA'; certificateTemplates=@('User','Computer','WebServer'); DistinguishedName='CN=legacy-CA01-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local' })
        CaTemplates         = @([PSCustomObject]@{ Name='User'; displayName='User'; DistinguishedName='CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local' }, [PSCustomObject]@{ Name='Computer'; displayName='Machine'; DistinguishedName='CN=Machine,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local' })
        AiaCdp              = @([PSCustomObject]@{ Name='legacy-CA01-CA'; ObjectClass='certificationAuthority'; DistinguishedName='CN=legacy-CA01-CA,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local' })
        AdfsObjects         = @([PSCustomObject]@{ Name='ADFS'; ObjectClass='container'; DistinguishedName="CN=ADFS,CN=Microsoft,CN=Program Data,$domainDn"; Description='AD FS configuration' })
        AdfsSpnComputers    = @('ADFS01')
        EntraConnect        = @([PSCustomObject]@{ Name='MSOL_a1b2c3'; SamAccountName='MSOL_a1b2c3'; Enabled=$true; Description='Account created by Microsoft Azure Active Directory Connect'; DistinguishedName="CN=MSOL_a1b2c3,CN=Users,$domainDn" })
        NpsMembers          = @([PSCustomObject]@{ Group='RAS and IAS Servers'; Name='NPS01'; SamAccountName='NPS01$'; ObjectClass='computer'; DistinguishedName="CN=NPS01,OU=Servers,$domainDn" })
        ReplPartners        = @([PSCustomObject]@{ Server='dc01.legacy.corp'; Partner='dc02.legacy.corp'; LastReplicationSuccess=$now.AddMinutes(-12); LastReplicationResult=0; ConsecutiveReplicationFailures=0; LastReplicationAttempt=$now.AddMinutes(-12); HealthStatus='OK'; Partition='DC=legacy,DC=corp' }, [PSCustomObject]@{ Server='dc02.legacy.corp'; Partner='dc01.legacy.corp'; LastReplicationSuccess=$now.AddHours(-6); LastReplicationResult=1722; ConsecutiveReplicationFailures=4; LastReplicationAttempt=$now.AddMinutes(-15); HealthStatus='ERROR'; Partition='DC=legacy,DC=corp' })
        ReplFailures        = @([PSCustomObject]@{ Server='dc02.legacy.corp'; Partner='dc01.legacy.corp'; FailureType='Link'; FirstFailureTime=$now.AddHours(-6); FailureCount=4; LastError='1722 RPC server unavailable' })
        SysvolState         = 'Start (NTFRS / FRS mode)'
        SysvolDetail        = 'msDFSR-Flags=0 on CN=DFSR-GlobalSettings (demo)'
        SysvolSource        = 'AD msDFSR-Flags'
        DelegationAccounts  = @([PSCustomObject]@{ SamAccountName='SQL01$'; ObjectClass='computer'; DelegationType='Unconstrained'; AllowedToDelegateTo=''; Description='SQL Server'; DistinguishedName="CN=SQL01,OU=Servers,$domainDn" })
        RbcdAccounts        = @()
        SPNDuplicates       = @([PSCustomObject]@{ SPN='HOST/legacy.corp'; Account='DC01$'; DN="CN=DC01,OU=Domain Controllers,$domainDn" }, [PSCustomObject]@{ SPN='HOST/legacy.corp'; Account='APP01$'; DN="CN=APP01,OU=Servers,$domainDn" })
        OUs                 = @([PSCustomObject]@{ Name='Users'; Description='User accounts'; ProtectedFromAccidentalDeletion=$true; LinkedGroupPolicyObjects=@(); ManagedBy=''; DistinguishedName="OU=Users,$domainDn" }, [PSCustomObject]@{ Name='Servers'; Description='Member servers'; ProtectedFromAccidentalDeletion=$true; LinkedGroupPolicyObjects=@(); ManagedBy=''; DistinguishedName="OU=Servers,$domainDn" }, [PSCustomObject]@{ Name='EmptyOU'; Description=''; ProtectedFromAccidentalDeletion=$false; LinkedGroupPolicyObjects=@(); ManagedBy=''; DistinguishedName="OU=EmptyOU,$domainDn" })
        PasswordPolicy      = [PSCustomObject]@{ MinPasswordLength=8; MaxPasswordAge='42.00:00:00'; MinPasswordAge='1.00:00:00'; PasswordHistoryCount=24; LockoutThreshold=0; LockoutDuration='00:30:00'; ComplexityEnabled=$true; ReversibleEncryptionEnabled=$false }
        Fgpp                = @([PSCustomObject]@{ Name='Admins PSO'; Precedence=10; MinPasswordLength=14; MaxPasswordAge='90.00:00:00'; AppliesTo='Domain Admins' })
        RecycleBinEnabled   = $false
        TombstoneDays       = 180
        RidPool             = [PSCustomObject]@{ NextRid=12500; PoolEnd=14000; Remaining=1500 }
        SchemaVersion       = 88
        SchemaVersionName   = '88 — Windows Server 2019 / 2022'
        AppPartitions       = @("DC=DomainDnsZones,$domainDn")
        ExchangeServers     = @()
        SccmContainers      = @()
        DfsNamespaces       = @([PSCustomObject]@{ Name='legacy.corp'; DistinguishedName="CN=legacy.corp,CN=Dfs-Configuration,CN=System,$domainDn" })
        PrintQueues         = @([PSCustomObject]@{ Name='Accounts-MFP'; DistinguishedName="CN=Accounts-MFP,CN=APP01,OU=Servers,$domainDn"; driverName='HP Universal' })
        ServiceConnections  = @([PSCustomObject]@{ Name='ADFS'; serviceClassName='ADFS'; serviceBindingInformation='https://adfs.legacy.corp/adfs/ls'; DistinguishedName="CN=ADFS,CN=Device Registration Services,CN=Services,CN=Configuration,DC=corp,DC=local"; keywords='https://schemas.microsoft.com/ws/2008/06/identity/offering/federation' })
        Gmsa                = @([PSCustomObject]@{ Name='gmsa-iis'; SamAccountName='gmsa-iis$'; DistinguishedName="CN=gmsa-iis,CN=Managed Service Accounts,$domainDn"; DNSHostName='gmsa-iis.legacy.corp'; Enabled=$true })
        KdsRootKeys         = @([PSCustomObject]@{ Name='{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}'; whenCreated=$now.AddYears(-3); DistinguishedName='CN={A1B2C3D4-E5F6-7890-ABCD-EF1234567890},CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=corp,DC=local' })
        BitLockerCount      = 2
        LapsCount           = 1
        HybridJoinCount     = 0
        FspCount            = 3
        ForeignPrincipals   = @([PSCustomObject]@{ Name='S-1-5-21-999-888-777-512'; DistinguishedName="CN=S-1-5-21-999-888-777-512,CN=ForeignSecurityPrincipals,$domainDn"; whenCreated=$now.AddYears(-4) })
        WmiFilters          = @()
        OptionalFeatures    = @([PSCustomObject]@{ Name='Recycle Bin Feature'; EnabledScopes=@() })
        AuthSilos           = @()
        KrbtgtPasswordAgeDays = 900
        LocatorRecords      = @([PSCustomObject]@{ Zone='_msdcs.legacy.corp'; HostName='_ldap._tcp.dc'; RecordType='SRV'; Tombstoned='No' }, [PSCustomObject]@{ Zone='_msdcs.legacy.corp'; HostName='_kerberos._tcp.dc'; RecordType='SRV'; Tombstoned='No' }, [PSCustomObject]@{ Zone='legacy.corp'; HostName='dc01'; RecordType='A'; Tombstoned='No' })
        DnsZoneRows         = @([PSCustomObject]@{ ZoneName='legacy.corp'; IsReverse=$false; ZoneType='AD-Integrated'; Partition='Domain'; Created=$now.AddYears(-12); Modified=$now.AddDays(-1); RecordCount=42 }, [PSCustomObject]@{ ZoneName='_msdcs.legacy.corp'; IsReverse=$false; ZoneType='AD-Integrated'; Partition='Forest'; Created=$now.AddYears(-12); Modified=$now.AddDays(-1); RecordCount=18 }, [PSCustomObject]@{ ZoneName='10.10.in-addr.arpa'; IsReverse=$true; ZoneType='AD-Integrated'; Partition='Domain'; Created=$now.AddYears(-12); Modified=$now.AddDays(-10); RecordCount=9 })
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Live collection
# ═══════════════════════════════════════════════════════════════════════════════

$Domain = $null
$Forest = $null
$RootDSE = $null
$DCs = @()
$Sites = @()
$Subnets = @()
$SiteLinks = @()
$AllUsers = @()
$AllComputers = @()
$AllGroups = @()
$Trusts = @()
$RawGPOs = @()
$LinkedObjects = @()
$WmiFilters = @()
$DnsZoneRows = @()
$LocatorRecords = @()
$DhcpServers = @()
$CAs = @()
$CaTemplates = @()
$AiaCdp = @()
$AdfsObjects = @()
$AdfsSpnComputers = @()
$EntraConnect = @()
$NpsMembers = @()
$ReplPartners = @()
$ReplFailures = @()
$SysvolState = 'Unknown'
$SysvolDetail = ''
$SysvolSource = ''
$DelegationAccounts = @()
$RbcdAccounts = @()
$OUs = @()
$PasswordPolicy = $null
$Fgpp = @()
$RecycleBinEnabled = $false
$TombstoneDays = $null
$RidPool = $null
$SchemaVersion = $null
$SchemaVersionName = 'Unknown'
$AppPartitions = @()
$ExchangeServers = @()
$SccmContainers = @()
$DfsNamespaces = @()
$PrintQueues = @()
$ServiceConnections = @()
$Gmsa = @()
$KdsRootKeys = @()
$BitLockerCount = 0
$LapsCount = 0
$HybridJoinCount = 0
$ForeignPrincipals = @()
$OptionalFeatures = @()
$AuthSilos = @()
$KrbtgtPasswordAgeDays = $null
$PerDcLogonMap = @{}

$UserProps = @(
    'Enabled','LastLogonDate','lastLogonTimestamp','Mail','EmployeeID','PasswordLastSet',
    'WhenCreated','WhenChanged','Description','DisplayName','PasswordNeverExpires',
    'SmartcardLogonRequired','LockedOut','BadLogonCount','MemberOf','ServicePrincipalNames',
    'SIDHistory','UserAccountControl','AccountExpirationDate','adminCount','ScriptPath',
    'HomeDirectory','ProfilePath','UserPrincipalName','primaryGroupID','logonCount',
    'PasswordNotRequired','CannotChangePassword','AllowReversiblePasswordEncryption',
    'TrustedForDelegation','TrustedToAuthForDelegation','AccountNotDelegated',
    'DoesNotRequirePreAuth','Title','Department','samAccountName','msDS-AllowedToDelegateTo'
)
$ComputerProps = @(
    'Enabled','LastLogonDate','lastLogonTimestamp','OperatingSystem','OperatingSystemVersion',
    'IPv4Address','WhenCreated','WhenChanged','Description','ServicePrincipalNames',
    'DNSHostName','Location','PasswordLastSet','MemberOf','primaryGroupID','UserAccountControl',
    'SIDHistory','TrustedForDelegation','TrustedToAuthForDelegation','msDS-AllowedToDelegateTo',
    'msDS-ExternalDirectoryObjectId','ms-Mcs-AdmPwdExpirationTime'
)

if ($DemoMode) {
    Write-Host '[demo] Loading synthetic assessment data...' -ForegroundColor Magenta
    $demo = Get-DemoData
    $Domain             = $demo.Domain
    $Forest             = $demo.Forest
    $RootDSE            = $demo.RootDSE
    $DCs                = @($demo.DCs)
    $Sites              = @($demo.Sites)
    $Subnets            = @($demo.Subnets)
    $SiteLinks          = @($demo.SiteLinks)
    $AllUsers           = @($demo.Users)
    $AllComputers       = @($demo.Computers)
    $AllGroups          = @($demo.Groups)
    $Trusts             = @($demo.Trusts)
    $RawGPOs            = @($demo.RawGPOs)
    $LinkedObjects      = @($demo.LinkedObjects)
    $DnsZoneRows        = @($demo.DnsZoneRows)
    $LocatorRecords     = @($demo.LocatorRecords)
    $DhcpServers        = @($demo.DhcpServers)
    $CAs                = @($demo.CAs)
    $CaTemplates        = @($demo.CaTemplates)
    $AiaCdp             = @($demo.AiaCdp)
    $AdfsObjects        = @($demo.AdfsObjects)
    $AdfsSpnComputers   = @($demo.AdfsSpnComputers)
    $EntraConnect       = @($demo.EntraConnect)
    $NpsMembers         = @($demo.NpsMembers)
    $ReplPartners       = @($demo.ReplPartners)
    $ReplFailures       = @($demo.ReplFailures)
    $SysvolState        = $demo.SysvolState
    $SysvolDetail       = $demo.SysvolDetail
    $SysvolSource       = $demo.SysvolSource
    $DelegationAccounts = @($demo.DelegationAccounts)
    $RbcdAccounts       = @($demo.RbcdAccounts)
    $OUs                = @($demo.OUs)
    $PasswordPolicy     = $demo.PasswordPolicy
    $Fgpp               = @($demo.Fgpp)
    $RecycleBinEnabled  = [bool]$demo.RecycleBinEnabled
    $TombstoneDays      = $demo.TombstoneDays
    $RidPool            = $demo.RidPool
    $SchemaVersion      = $demo.SchemaVersion
    $SchemaVersionName  = $demo.SchemaVersionName
    $AppPartitions      = @($demo.AppPartitions)
    $ExchangeServers    = @($demo.ExchangeServers)
    $SccmContainers     = @($demo.SccmContainers)
    $DfsNamespaces      = @($demo.DfsNamespaces)
    $PrintQueues        = @($demo.PrintQueues)
    $ServiceConnections = @($demo.ServiceConnections)
    $Gmsa               = @($demo.Gmsa)
    $KdsRootKeys        = @($demo.KdsRootKeys)
    $BitLockerCount     = [int]$demo.BitLockerCount
    $LapsCount          = [int]$demo.LapsCount
    $HybridJoinCount    = [int]$demo.HybridJoinCount
    $ForeignPrincipals  = @($demo.ForeignPrincipals)
    $WmiFilters         = @($demo.WmiFilters)
    $OptionalFeatures   = @($demo.OptionalFeatures)
    $AuthSilos          = @($demo.AuthSilos)
    $KrbtgtPasswordAgeDays = $demo.KrbtgtPasswordAgeDays
    Write-QueryNote 'Demo' 'Report built from synthetic data. Connect to a domain without -DemoMode for a live assessment.'
}
else {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "The ActiveDirectory module is not installed. Install RSAT (Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0) or run with -DemoMode."
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Host '[1/24] Domain, forest, RootDSE...' -ForegroundColor White
    $Domain = Invoke-AdCmd '1/24 Domain' 'Get-ADDomain' { param($p) Get-ADDomain @p -ErrorAction Stop } $null
    $Forest = Invoke-AdCmd '1/24 Forest' 'Get-ADForest' { param($p) Get-ADForest @p -ErrorAction Stop } $null
    $RootDSE = Invoke-AdCmd '1/24 RootDSE' 'Get-ADRootDSE' { param($p) Get-ADRootDSE @p -ErrorAction Stop } $null

    if ($Domain -is [System.Array]) { $Domain = $Domain | Select-Object -First 1 }
    if ($Forest -is [System.Array]) { $Forest = $Forest | Select-Object -First 1 }
    if ($RootDSE -is [System.Array]) { $RootDSE = $RootDSE | Select-Object -First 1 }

    $DomainNC = Get-PropText $Domain 'DistinguishedName' ''
    if ($DomainNC -eq 'N/A' -or [string]::IsNullOrWhiteSpace($DomainNC)) {
        $DomainNC = Get-PropText $RootDSE 'defaultNamingContext' ''
    }
    $ConfigNC = Get-PropText $RootDSE 'configurationNamingContext' ''
    $SchemaNC = Get-PropText $RootDSE 'schemaNamingContext' ''
    $ForestNC = Get-PropText $RootDSE 'rootDomainNamingContext' ''
    if ($ForestNC -eq 'N/A') { $ForestNC = $DomainNC }

    Write-Host '[2/24] Domain controllers...' -ForegroundColor White
    $DCs = @(Invoke-AdCmd '2/24 DCs' 'Get-ADDomainController' { param($p) Get-ADDomainController -Filter * @p -ErrorAction Stop })

    Write-Host '[3/24] FSMO / schema / partitions...' -ForegroundColor White
    $schemaObj = $null
    if ($SchemaNC -and $SchemaNC -ne 'N/A') {
        $schemaObj = try {
            $p = $script:AdServerParam
            Get-ADObject -Identity $SchemaNC -Properties objectVersion @p -ErrorAction Stop
        } catch { Write-ErrorEntry '3/24 Schema' 'Schema-objectVersion' $_; $null }
        $SchemaVersion = Get-Safe $schemaObj 'objectVersion'
        $SchemaVersionName = Get-SchemaVersionName $SchemaVersion
    }
    $ncs = ConvertTo-StringList (Get-Safe $RootDSE 'namingContexts')
    $wellKnownNc = @($DomainNC, $ConfigNC, $SchemaNC)
    $AppPartitions = @($ncs | Where-Object {
        $nc = $_
        if ([string]::IsNullOrWhiteSpace($nc)) { return $false }
        foreach ($w in $wellKnownNc) { if ($w -and $nc -eq $w) { return $false } }
        return $true
    })

    if ($DomainNC) {
        $ridObj = try {
            $p = $script:AdServerParam
            Get-ADObject -Identity "CN=RID Manager$,CN=System,$DomainNC" -Properties rIDAvailablePool @p -ErrorAction Stop
        } catch { Write-ErrorEntry '3/24 RID' 'RID-Manager' $_; $null }
        $pool = Get-Safe $ridObj 'rIDAvailablePool'
        if ($null -ne $pool) {
            try {
                $high = 0; $low = 0
                if ($null -ne (Get-Safe $pool 'HighPart')) {
                    $high = [uint32](Get-Safe $pool 'HighPart')
                    $low  = [uint32](Get-Safe $pool 'LowPart')
                }
                else {
                    $big = [uint64]$pool
                    $low = [uint32]($big -band 0xFFFFFFFF)
                    $high = [uint32]($big -shr 32)
                }
                $RidPool = [PSCustomObject]@{ NextRid = $low; PoolEnd = $high; Remaining = [int64]$high - [int64]$low }
            }
            catch { Write-QueryNote 'RID' "Could not decode rIDAvailablePool: $($_.Exception.Message)" }
        }
    }

    Write-Host '[4/24] Sites, subnets, site links...' -ForegroundColor White
    $Sites = @(Invoke-AdCmd '4/24 Sites' 'Get-ADReplicationSite' { param($p) Get-ADReplicationSite -Filter * @p -ErrorAction Stop })
    $Subnets = @(Invoke-AdCmd '4/24 Subnets' 'Get-ADReplicationSubnet' { param($p) Get-ADReplicationSubnet -Filter * @p -ErrorAction Stop })
    $SiteLinks = @(Invoke-AdCmd '4/24 SiteLinks' 'Get-ADReplicationSiteLink' { param($p) Get-ADReplicationSiteLink -Filter * @p -ErrorAction Stop })

    Write-Host '[5/24] Users...' -ForegroundColor White
    $AllUsers = @(Invoke-AdCmd '5/24 Users' 'Get-ADUser' { param($p) Get-ADUser -Filter * -Properties $UserProps @p -ErrorAction Stop })

    Write-Host '[6/24] Computers...' -ForegroundColor White
    $AllComputers = @(Invoke-AdCmd '6/24 Computers' 'Get-ADComputer' { param($p) Get-ADComputer -Filter * -Properties $ComputerProps @p -ErrorAction Stop })

    if ($AccurateLastLogon -and $DCs.Count -gt 0) {
        Write-Host '      Querying lastLogon on every DC (AccurateLastLogon)...' -ForegroundColor DarkGray
        foreach ($dc in $DCs) {
            $hostName = Get-PropText $dc 'HostName' ''
            if (-not $hostName -or $hostName -eq 'N/A') { continue }
            Write-Host "      lastLogon from $hostName" -ForegroundColor DarkGray
            try {
                $p = @{}
                foreach ($k in $script:AdServerParam.Keys) { $p[$k] = $script:AdServerParam[$k] }
                $p['Server'] = $hostName
                $batch = @(Get-ADObject -LDAPFilter '(|(objectClass=user)(objectClass=computer))' -Properties lastLogon @p -ErrorAction Stop)
                foreach ($o in $batch) {
                    $dn = Get-Safe $o 'DistinguishedName'
                    $ll = ConvertFrom-AdDate (Get-Safe $o 'lastLogon')
                    if (-not $dn -or $null -eq $ll) { continue }
                    if (-not $PerDcLogonMap.ContainsKey($dn) -or $ll -gt $PerDcLogonMap[$dn]) {
                        $PerDcLogonMap[$dn] = $ll
                    }
                }
            }
            catch { Write-ErrorEntry '5/24 LastLogon' "lastLogon:$hostName" $_ }
        }
        Write-QueryNote 'LastLogon' "Accurate lastLogon merged from $($DCs.Count) DC(s). lastLogonTimestamp alone can lag 9–14 days."
    }
    else {
        Write-QueryNote 'LastLogon' 'Using replicated lastLogonTimestamp (LastLogonDate). It can lag 9–14 days. Use -AccurateLastLogon for per-DC lastLogon.'
    }

    Write-Host '[7/24] Groups...' -ForegroundColor White
    $AllGroups = @(Invoke-AdCmd '7/24 Groups' 'Get-ADGroup' {
        param($p) Get-ADGroup -Filter * -Properties GroupCategory, GroupScope, Members, Mail, Description, ManagedBy, WhenCreated, memberOf, SID @p -ErrorAction Stop
    })

    Write-Host '[8/24] Trusts...' -ForegroundColor White
    $Trusts = @(Invoke-AdCmd '8/24 Trusts' 'Get-ADTrust' { param($p) Get-ADTrust -Filter * @p -ErrorAction Stop })

    Write-Host '[9/24] GPOs, links, WMI filters...' -ForegroundColor White
    if ($DomainNC) {
        $gpoBase = "CN=Policies,CN=System,$DomainNC"
        $RawGPOs = @()
        try {
            $p = $script:AdServerParam
            $RawGPOs = @(Get-ADObject -SearchBase $gpoBase -LDAPFilter '(objectClass=groupPolicyContainer)' `
                -Properties displayName, gPCFileSysPath, flags, whenCreated, whenChanged, versionNumber, `
                            gPCMachineExtensionNames, gPCUserExtensionNames, description, gPCWQLFilter `
                @p -ErrorAction Stop)
        }
        catch { Write-ErrorEntry '9/24 GPOs' 'GPO-ADObject' $_ }

        $LinkedObjects = @()
        try {
            $p = $script:AdServerParam
            $LinkedObjects += @(Get-ADObject -Identity $DomainNC -Properties gpLink @p -ErrorAction SilentlyContinue)
            $LinkedObjects += @(Get-ADOrganizationalUnit -Filter * -Properties gpLink @p -ErrorAction SilentlyContinue)
            if ($ConfigNC -and $ConfigNC -ne 'N/A') {
                $LinkedObjects += @(Get-ADObject -SearchBase $ConfigNC -LDAPFilter '(objectClass=site)' -Properties gpLink @p -ErrorAction SilentlyContinue)
            }
        }
        catch { Write-ErrorEntry '9/24 GPOs' 'GPO-Links' $_ }

        try {
            $p = $script:AdServerParam
            $wmiBase = "CN=SOM,CN=WMIPolicy,CN=System,$DomainNC"
            $WmiFilters = @(Get-ADObject -SearchBase $wmiBase -LDAPFilter '(objectClass=msWMI-Som)' `
                -Properties 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2', whenCreated @p -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name        = Get-Safe $_ 'msWMI-Name'
                        Description = Get-Safe $_ 'msWMI-Parm1'
                        WQL         = Get-Safe $_ 'msWMI-Parm2'
                        Created     = Get-Safe $_ 'whenCreated'
                        DistinguishedName = Get-Safe $_ 'DistinguishedName'
                    }
                })
        }
        catch { Write-QueryNote 'WMI Filters' 'No WMI filter container (or access denied).' }
    }

    Write-Host '[10/24] DNS zones (AD partitions)...' -ForegroundColor White
    $dnsBases = @()
    if ($DomainNC) {
        $dnsBases += [PSCustomObject]@{ Base = "CN=MicrosoftDNS,DC=DomainDnsZones,$DomainNC"; Partition = 'DomainDnsZones' }
        $dnsBases += [PSCustomObject]@{ Base = "CN=MicrosoftDNS,CN=System,$DomainNC"; Partition = 'DomainNC (legacy)' }
    }
    if ($ForestNC -and $ForestNC -ne 'N/A') {
        $dnsBases += [PSCustomObject]@{ Base = "CN=MicrosoftDNS,DC=ForestDnsZones,$ForestNC"; Partition = 'ForestDnsZones' }
    }
    $seenZones = @{}
    foreach ($dns in $dnsBases) {
        try {
            $p = $script:AdServerParam
            $zoneObjs = @(Get-ADObject -SearchBase $dns.Base -LDAPFilter '(objectClass=dnsZone)' -Properties name, whenCreated, whenChanged @p -ErrorAction Stop)
            foreach ($z in $zoneObjs) {
                $zName = [string](Get-Safe $z 'Name')
                if ([string]::IsNullOrWhiteSpace($zName)) { continue }
                $key = ($zName + '|' + $dns.Partition).ToLowerInvariant()
                if ($seenZones.ContainsKey($zName.ToLowerInvariant())) {
                    continue
                }
                $seenZones[$zName.ToLowerInvariant()] = $true
                $isReverse = $zName -match '\.in-addr\.arpa$|\.ip6\.arpa$'
                $recordCount = 0
                $nodeBase = "DC=$zName,$($dns.Base)"
                try {
                    $nodes = @(Get-ADObject -SearchBase $nodeBase -LDAPFilter '(objectClass=dnsNode)' -Properties name, dNSTombstoned, dnsRecord @p -ErrorAction Stop)
                    $recordCount = $nodes.Count
                    foreach ($node in $nodes) {
                        $nName = [string](Get-Safe $node 'Name')
                        $isLocator = $nName -match '^_|^dc$|^gc$|^pdc$|^domains$|^gc\._msdcs' -or $zName -match '^_msdcs'
                        if ($isLocator) {
                            $rType = ''
                            $blob = Get-Safe $node 'dnsRecord'
                            if ($blob) {
                                $first = @($blob)[0]
                                if ($first -is [byte[]] -and $first.Length -ge 4) {
                                    $t = [BitConverter]::ToUInt16($first, 2)
                                    $rType = switch ($t) { 1 {'A'} 2 {'NS'} 5 {'CNAME'} 6 {'SOA'} 12 {'PTR'} 15 {'MX'} 16 {'TXT'} 28 {'AAAA'} 33 {'SRV'} default {"TYPE$t"} }
                                }
                            }
                            $LocatorRecords += [PSCustomObject]@{
                                Zone       = $zName
                                HostName   = $nName
                                RecordType = $rType
                                Tombstoned = $(if (Get-Safe $node 'dNSTombstoned') { 'Yes' } else { 'No' })
                            }
                        }
                    }
                }
                catch {
                    Write-QueryNote 'DNS' "Could not enumerate records in zone $zName ($($dns.Partition))"
                }
                $DnsZoneRows += [PSCustomObject]@{
                    ZoneName   = $zName
                    IsReverse  = $isReverse
                    ZoneType   = 'AD-Integrated'
                    Partition  = $dns.Partition
                    Created    = Get-Safe $z 'whenCreated'
                    Modified   = Get-Safe $z 'whenChanged'
                    RecordCount= $recordCount
                }
            }
        }
        catch {
            Write-QueryNote 'DNS' "Search base $($dns.Base) not available ($($_.Exception.Message))"
        }
    }

    Write-Host '[11/24] DHCP (authorised servers in configuration NC)...' -ForegroundColor White
    if ($ConfigNC -and $ConfigNC -ne 'N/A') {
        try {
            $p = $script:AdServerParam
            $targetDomain = if ($DomainName) { $DomainName } else { Get-PropText $Domain 'DNSRoot' '' }
            if (-not $targetDomain -or $targetDomain -eq 'N/A') {
                $targetDomain = ($DomainNC -replace '^DC=', '' -replace ',DC=', '.')
            }
            $rawDhcp = @(Get-ADObject -SearchBase "CN=NetServices,CN=Services,$ConfigNC" -LDAPFilter '(objectClass=dhcpServer)' -Properties dnsHostName, whenCreated, description @p -ErrorAction Stop)
            $DhcpServers = @($rawDhcp | ForEach-Object {
                $fqdn = [string](Get-Safe $_ 'dnsHostName')
                $fqdnTrim = $fqdn.TrimEnd('.')
                $inDom = $false
                if ($targetDomain -and $fqdnTrim) {
                    $inDom = ($fqdnTrim -ieq $targetDomain) -or ($fqdnTrim -like "*.$targetDomain")
                }
                [PSCustomObject]@{
                    DnsName         = $fqdn
                    IPAddress       = Get-Safe $_ 'Name'
                    Created         = Get-Safe $_ 'whenCreated'
                    Description     = Get-Safe $_ 'description'
                    InTargetDomain  = $inDom
                    DistinguishedName = Get-Safe $_ 'DistinguishedName'
                }
            })
        }
        catch { Write-ErrorEntry '11/24 DHCP' 'DHCP-ADObject' $_ }
    }

    Write-Host '[12/24] AD CS, templates, AIA/CDP...' -ForegroundColor White
    if ($ConfigNC -and $ConfigNC -ne 'N/A') {
        $pki = "CN=Public Key Services,CN=Services,$ConfigNC"
        try {
            $p = $script:AdServerParam
            $CAs = @(Get-ADObject -SearchBase "CN=Enrollment Services,$pki" -LDAPFilter '(objectClass=pKIEnrollmentService)' `
                -Properties dNSHostName, cACertificateDN, whenCreated, Description, certificateTemplates @p -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name              = Get-Safe $_ 'Name'
                        dNSHostName       = Get-Safe $_ 'dNSHostName'
                        cACertificateDN   = Get-Safe $_ 'cACertificateDN'
                        whenCreated       = Get-Safe $_ 'whenCreated'
                        Description       = Get-Safe $_ 'Description'
                        certificateTemplates = (Format-DisplayValue (Get-Safe $_ 'certificateTemplates'))
                        DistinguishedName = Get-Safe $_ 'DistinguishedName'
                    }
                })
        }
        catch { Write-QueryNote 'AD CS' 'No enrollment services container (or access denied).' }
        try {
            $p = $script:AdServerParam
            $CaTemplates = @(Get-ADObject -SearchBase "CN=Certificate Templates,$pki" -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties displayName, 'msPKI-Enrollment-Flag' @p -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name        = Get-Safe $_ 'Name'
                        DisplayName = Get-Safe $_ 'displayName'
                        DistinguishedName = Get-Safe $_ 'DistinguishedName'
                    }
                })
        }
        catch { }
        try {
            $p = $script:AdServerParam
            $AiaCdp = @()
            foreach ($cn in @('AIA', 'CDP', 'Certification Authorities', 'KRA', 'OID')) {
                try {
                    $AiaCdp += @(Get-ADObject -SearchBase "CN=$cn,$pki" -LDAPFilter '(objectClass=*)' -Properties whenCreated @p -ErrorAction Stop |
                        Where-Object { (Get-Safe $_ 'ObjectClass') -ne 'container' } |
                        ForEach-Object {
                            [PSCustomObject]@{
                                Name              = Get-Safe $_ 'Name'
                                ObjectClass       = Get-Safe $_ 'ObjectClass'
                                Container         = $cn
                                DistinguishedName = Get-Safe $_ 'DistinguishedName'
                            }
                        })
                }
                catch { }
            }
        }
        catch { }
    }

    Write-Host '[13/24] AD FS, Entra Connect, NPS...' -ForegroundColor White
    if ($ConfigNC -and $ConfigNC -ne 'N/A') {
        try {
            $p = $script:AdServerParam
            $AdfsObjects += @(Get-ADObject -SearchBase $ConfigNC -LDAPFilter '(&(objectClass=serviceConnectionPoint)(|(keywords=*federation*)(serviceClassName=ADFS)(serviceClassName=*DeviceRegistration*)))' -Properties serviceClassName, serviceBindingInformation, keywords @p -ErrorAction SilentlyContinue)
        }
        catch { }
    }
    if ($DomainNC) {
        try {
            $p = $script:AdServerParam
            $adfsProg = "CN=ADFS,CN=Microsoft,CN=Program Data,$DomainNC"
            $AdfsObjects += @(Get-ADObject -SearchBase $adfsProg -LDAPFilter '(objectClass=*)' -Properties whenCreated, description @p -ErrorAction SilentlyContinue |
                Select-Object -First 50)
        }
        catch { Write-QueryNote 'AD FS' 'No CN=ADFS,CN=Microsoft,CN=Program Data container.' }
    }
    $AdfsSpnComputers = @($AllComputers | Where-Object {
        $spn = Join-StringList (Get-Safe $_ 'ServicePrincipalNames') ' '
        $spn -match '(?i)http/adfs|/adfs\.|enterpriseregistration'
    } | ForEach-Object { Get-Safe $_ 'Name' })

    $EntraConnect = @($AllUsers | Where-Object {
        $sam = [string](Get-Safe $_ 'SamAccountName')
        $desc = [string](Get-Safe $_ 'Description')
        $sam -like 'MSOL_*' -or $sam -like 'AAD_*' -or $sam -like 'Sync_*' -or $desc -match 'Azure Active Directory Connect|DirSync|Entra Connect'
    } | ForEach-Object {
        [PSCustomObject]@{
            Name              = Get-Safe $_ 'Name'
            SamAccountName    = Get-Safe $_ 'SamAccountName'
            Enabled           = Get-Safe $_ 'Enabled'
            Description       = Get-Safe $_ 'Description'
            DistinguishedName = Get-Safe $_ 'DistinguishedName'
        }
    })

    # NPS: RAS and IAS Servers is RID 553 — works in any locale
    $domainSidValue = Get-PropText $Domain 'DomainSID' ''
    if ($domainSidValue -eq 'N/A') { $domainSidValue = '' }
    if ($domainSidValue -match '^S-1-5-21-') {
        $rasSid = "$domainSidValue-553"
        try {
            $p = $script:AdServerParam
            $rasGrp = Get-ADGroup -Identity $rasSid @p -ErrorAction Stop
            $NpsMembers = @(Get-ADGroupMember -Identity $rasGrp.DistinguishedName @p -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{
                        Group             = 'RAS and IAS Servers'
                        Name              = Get-Safe $_ 'Name'
                        SamAccountName    = Get-Safe $_ 'SamAccountName'
                        ObjectClass       = Get-Safe $_ 'objectClass'
                        DistinguishedName = Get-Safe $_ 'DistinguishedName'
                    }
                })
        }
        catch {
            Write-QueryNote 'NPS' 'Could not enumerate RAS and IAS Servers (RID 553). Falling back to memberOf index later.'
        }
    }

    Write-Host '[14/24] Replication health...' -ForegroundColor White
    $replTargets = @($DCs | ForEach-Object { Get-PropText $_ 'HostName' '' } | Where-Object { $_ -and $_ -ne 'N/A' })
    if ($replTargets.Count -eq 0) { $replTargets = @('*') }
    foreach ($rt in $replTargets) {
        $got = $false
        try {
            $replSplat = @{ Target = $rt; AuthType = 'Negotiate'; ErrorAction = 'Stop' }
            if ($Credential) { $replSplat['Credential'] = $Credential }
            $ReplPartners += @(Get-ADReplicationPartnerMetadata @replSplat | ForEach-Object {
                $fail = 0
                try { $fail = [int](Get-Safe $_ 'ConsecutiveReplicationFailures' 0) } catch { $fail = 0 }
                $res = Get-Safe $_ 'LastReplicationResult' 0
                $status = if ($fail -gt 0) { 'ERROR' } elseif ("$res" -ne '0') { 'WARNING' } else { 'OK' }
                [PSCustomObject]@{
                    Server                         = Get-Safe $_ 'Server'
                    Partner                        = Get-Safe $_ 'Partner'
                    LastReplicationSuccess         = Get-Safe $_ 'LastReplicationSuccess'
                    LastReplicationResult          = $res
                    ConsecutiveReplicationFailures = $fail
                    LastReplicationAttempt         = Get-Safe $_ 'LastReplicationAttempt'
                    HealthStatus                   = $status
                    Partition                      = Get-Safe $_ 'Partition'
                }
            })
            $got = $true
        }
        catch { Write-ErrorEntry '14/24 Replication' "Replication:$rt" $_ }

        if ($rt -ne '*') {
            try {
                $failSplat = @{ Target = $rt; ErrorAction = 'Stop' }
                if ($Credential) { $failSplat['Credential'] = $Credential }
                $ReplFailures += @(Get-ADReplicationFailure @failSplat | ForEach-Object {
                    [PSCustomObject]@{
                        Server          = $rt
                        Partner         = Get-Safe $_ 'Partner'
                        FailureType     = Get-Safe $_ 'FailureType'
                        FirstFailureTime= Get-Safe $_ 'FirstFailureTime'
                        FailureCount    = Get-Safe $_ 'FailureCount'
                        LastError       = Get-Safe $_ 'LastError'
                    }
                })
            }
            catch { }
        }

        if (-not $got -and $rt -ne '*') {
            try {
                Write-Host "      Falling back to repadmin for $rt ..." -ForegroundColor DarkYellow
                $repadminOut = & repadmin.exe /showrepl $rt /csv 2>&1
                $csvLines = @($repadminOut | Where-Object { $_ -is [string] -and $_ -match ',' -and $_ -notmatch '^Repadmin' })
                if ($csvLines.Count -gt 1) {
                    $replCsv = $csvLines | ConvertFrom-Csv
                    foreach ($row in $replCsv) {
                        $failures = 0
                        $failRaw = Get-Safe $row 'Number of Failures'
                        if ($failRaw) { try { $failures = [int]$failRaw } catch { $failures = 0 } }
                        $lastResult = Get-Safe $row 'Last Failure Status'
                        if (-not $lastResult) { $lastResult = '0' }
                        $partner = Get-Safe $row 'Source DSA'
                        if (-not $partner) { $partner = Get-Safe $row 'Destination DSA' }
                        $ReplPartners += [PSCustomObject]@{
                            Server                         = $rt
                            Partner                        = $partner
                            LastReplicationSuccess         = Get-Safe $row 'Last Success Time'
                            LastReplicationResult          = $lastResult
                            ConsecutiveReplicationFailures = $failures
                            LastReplicationAttempt         = Get-Safe $row 'Last Attempt Time'
                            HealthStatus                   = $(if ($failures -gt 0) { 'ERROR' } elseif ("$lastResult" -ne '0') { 'WARNING' } else { 'OK' })
                            Partition                      = Get-Safe $row 'Naming Context'
                        }
                    }
                }
            }
            catch { Write-ErrorEntry '14/24 Replication' "repadmin-fallback:$rt" $_ }
        }
    }

    Write-Host '[15/24] SYSVOL / DFSR (from AD, not local registry)...' -ForegroundColor White
    $SysvolSource = 'AD'
    if ($DomainNC) {
        try {
            $p = $script:AdServerParam
            $dfsr = Get-ADObject -Identity "CN=DFSR-GlobalSettings,CN=System,$DomainNC" -Properties 'msDFSR-Flags' @p -ErrorAction Stop
            $flags = Get-Safe $dfsr 'msDFSR-Flags'
            $SysvolState = Get-DfsrStateName $flags
            $SysvolDetail = "msDFSR-Flags=$flags on CN=DFSR-GlobalSettings,CN=System"
            if ($null -eq $flags) {
                $SysvolState = 'DFSR-GlobalSettings present but msDFSR-Flags empty (typically DFSR / Eliminated)'
            }
        }
        catch {
            try {
                $p = $script:AdServerParam
                $frs = @(Get-ADObject -SearchBase "CN=File Replication Service,CN=System,$DomainNC" -LDAPFilter '(objectClass=nTFRSSettings)' @p -ErrorAction Stop)
                if ($frs.Count -gt 0) {
                    $SysvolState = 'NTFRS (legacy FRS objects present; DFSR-GlobalSettings missing)'
                    $SysvolDetail = 'File Replication Service container exists under CN=System'
                }
                else {
                    $SysvolState = 'Unknown (no DFSR-GlobalSettings, no FRS settings)'
                }
            }
            catch {
                $SysvolState = 'Unknown (could not read DFSR or FRS objects in AD)'
                Write-ErrorEntry '15/24 SYSVOL' 'DFSR-GlobalSettings' $_
            }
        }
    }

    Write-Host '[16/24] Kerberos delegation and RBCD...' -ForegroundColor White
    try {
        $p = $script:AdServerParam
        $Unconstrained = @(Get-ADObject -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            -Properties userAccountControl, 'msDS-AllowedToDelegateTo', SamAccountName, ObjectClass, Description, servicePrincipalName @p -ErrorAction Stop |
            ForEach-Object {
                [PSCustomObject]@{
                    SamAccountName    = Get-Safe $_ 'SamAccountName'
                    ObjectClass       = Get-Safe $_ 'ObjectClass'
                    DelegationType    = 'Unconstrained'
                    AllowedToDelegateTo = Format-DisplayValue (Get-Safe $_ 'msDS-AllowedToDelegateTo')
                    Description       = Get-Safe $_ 'Description'
                    DistinguishedName = Get-Safe $_ 'DistinguishedName'
                }
            })
        $Constrained = @(Get-ADObject -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=16777216)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            -Properties userAccountControl, 'msDS-AllowedToDelegateTo', SamAccountName, ObjectClass, Description, servicePrincipalName @p -ErrorAction Stop |
            ForEach-Object {
                [PSCustomObject]@{
                    SamAccountName    = Get-Safe $_ 'SamAccountName'
                    ObjectClass       = Get-Safe $_ 'ObjectClass'
                    DelegationType    = 'Constrained (protocol transition)'
                    AllowedToDelegateTo = Format-DisplayValue (Get-Safe $_ 'msDS-AllowedToDelegateTo')
                    Description       = Get-Safe $_ 'Description'
                    DistinguishedName = Get-Safe $_ 'DistinguishedName'
                }
            })
        $DelegationAccounts = @($Unconstrained) + @($Constrained)
    }
    catch { Write-ErrorEntry '16/24 Delegation' 'Delegation-ADObject' $_ }

    try {
        $p = $script:AdServerParam
        $RbcdAccounts = @(Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
            -Properties SamAccountName, ObjectClass, Description, 'msDS-AllowedToActOnBehalfOfOtherIdentity' @p -ErrorAction Stop |
            ForEach-Object {
                [PSCustomObject]@{
                    SamAccountName    = Get-Safe $_ 'SamAccountName'
                    ObjectClass       = Get-Safe $_ 'ObjectClass'
                    Description       = Get-Safe $_ 'Description'
                    DistinguishedName = Get-Safe $_ 'DistinguishedName'
                }
            })
    }
    catch { Write-QueryNote 'RBCD' 'msDS-AllowedToActOnBehalfOfOtherIdentity query failed (attribute may not exist at this FL).' }

    Write-Host '[17/24] Organizational units...' -ForegroundColor White
    $OUs = @(Invoke-AdCmd '17/24 OUs' 'Get-ADOrganizationalUnit' {
        param($p) Get-ADOrganizationalUnit -Filter * -Properties Description, ProtectedFromAccidentalDeletion, LinkedGroupPolicyObjects, ManagedBy, gpLink @p -ErrorAction Stop
    })

    Write-Host '[18/24] Password policy, FGPP, recycle bin, tombstone...' -ForegroundColor White
    try {
        $p = $script:AdServerParam
        $PasswordPolicy = Get-ADDefaultDomainPasswordPolicy @p -ErrorAction Stop
    }
    catch { Write-ErrorEntry '18/24 Policy' 'Get-ADDefaultDomainPasswordPolicy' $_ }

    try {
        $p = $script:AdServerParam
        $Fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * -Properties * @p -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Name              = Get-Safe $_ 'Name'
                Precedence        = Get-Safe $_ 'Precedence'
                MinPasswordLength = Get-Safe $_ 'MinPasswordLength'
                MaxPasswordAge    = Get-Safe $_ 'MaxPasswordAge'
                AppliesTo         = Format-DisplayValue (Get-Safe $_ 'AppliesTo')
                DistinguishedName = Get-Safe $_ 'DistinguishedName'
            }
        })
    }
    catch { Write-QueryNote 'FGPP' 'No fine-grained password policies (or cmdlet/access failed).' }

    try {
        $p = $script:AdServerParam
        $OptionalFeatures = @(Get-ADOptionalFeature -Filter * @p -ErrorAction Stop)
        foreach ($of in $OptionalFeatures) {
            $n = [string](Get-Safe $of 'Name')
            $scopes = ConvertTo-StringList (Get-Safe $of 'EnabledScopes')
            if ($n -match 'Recycle Bin' -and $scopes.Count -gt 0) { $RecycleBinEnabled = $true }
        }
    }
    catch { }

    if ($ConfigNC -and $ConfigNC -ne 'N/A') {
        try {
            $p = $script:AdServerParam
            $dsObj = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$ConfigNC" -Properties tombstoneLifetime @p -ErrorAction Stop
            $TombstoneDays = Get-Safe $dsObj 'tombstoneLifetime'
            if ($null -eq $TombstoneDays) { $TombstoneDays = 60 }
        }
        catch { }
    }

    Write-Host '[19/24] gMSA, KDS root key, BitLocker, LAPS, hybrid join...' -ForegroundColor White
    try {
        $p = $script:AdServerParam
        $Gmsa = @(Get-ADServiceAccount -Filter * -Properties DNSHostName, Enabled, 'msDS-ManagedPasswordInterval', PrincipalsAllowedToRetrieveManagedPassword @p -ErrorAction Stop |
            ForEach-Object {
                [PSCustomObject]@{
                    Name              = Get-Safe $_ 'Name'
                    SamAccountName    = Get-Safe $_ 'SamAccountName'
                    DNSHostName       = Get-Safe $_ 'DNSHostName'
                    Enabled           = Get-Safe $_ 'Enabled'
                    DistinguishedName = Get-Safe $_ 'DistinguishedName'
                    Principals        = Format-DisplayValue (Get-Safe $_ 'PrincipalsAllowedToRetrieveManagedPassword')
                }
            })
    }
    catch { Write-QueryNote 'gMSA' 'Get-ADServiceAccount failed (no MSA objects, or module/rights).' }

    if ($ConfigNC -and $ConfigNC -ne 'N/A') {
        try {
            $p = $script:AdServerParam
            $kdsBase = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$ConfigNC"
            $KdsRootKeys = @(Get-ADObject -SearchBase $kdsBase -LDAPFilter '(objectClass=msKds-ProvRootKey)' -Properties whenCreated, 'msKds-CreateTime' @p -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name              = Get-Safe $_ 'Name'
                        whenCreated       = Get-Safe $_ 'whenCreated'
                        DistinguishedName = Get-Safe $_ 'DistinguishedName'
                    }
                })
        }
        catch { Write-QueryNote 'KDS' 'No KDS root keys (gMSA will not work in a target domain until a key is created).' }
    }

    if ($DomainNC) {
        try {
            $p = $script:AdServerParam
            $BitLockerCount = @(Get-ADObject -SearchBase $DomainNC -LDAPFilter '(objectClass=msFVE-RecoveryInformation)' -Properties name @p -ErrorAction Stop).Count
        }
        catch { Write-QueryNote 'BitLocker' 'Could not count msFVE-RecoveryInformation objects.' }
        try {
            $p = $script:AdServerParam
            $LapsCount = @(Get-ADComputer -LDAPFilter '(ms-Mcs-AdmPwd=*)' @p -ErrorAction Stop).Count
        }
        catch { }
        try {
            $HybridJoinCount = @($AllComputers | Where-Object { Get-Safe $_ 'msDS-ExternalDirectoryObjectId' }).Count
        }
        catch { }
    }

    Write-Host '[20/24] Exchange, SCCM, DFS, printers, SCPs, FSPs...' -ForegroundColor White
    if ($ConfigNC -and $ConfigNC -ne 'N/A') {
        try {
            $p = $script:AdServerParam
            $ExchangeServers = @(Get-ADObject -SearchBase $ConfigNC -LDAPFilter '(objectClass=msExchExchangeServer)' -Properties networkAddress, serialNumber, whenCreated @p -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name              = Get-Safe $_ 'Name'
                        Created           = Get-Safe $_ 'whenCreated'
                        DistinguishedName = Get-Safe $_ 'DistinguishedName'
                    }
                })
        }
        catch { }
        try {
            $p = $script:AdServerParam
            $ServiceConnections = @(Get-ADObject -SearchBase $ConfigNC -LDAPFilter '(objectClass=serviceConnectionPoint)' -Properties serviceClassName, serviceBindingInformation, keywords @p -ErrorAction Stop |
                Select-Object -First 400 |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name              = Get-Safe $_ 'Name'
                        serviceClassName  = Get-Safe $_ 'serviceClassName'
                        serviceBindingInformation = Format-DisplayValue (Get-Safe $_ 'serviceBindingInformation')
                        keywords          = Format-DisplayValue (Get-Safe $_ 'keywords')
                        DistinguishedName = Get-Safe $_ 'DistinguishedName'
                    }
                })
        }
        catch { }
        try {
            $p = $script:AdServerParam
            $AuthSilos = @(Get-ADObject -SearchBase $ConfigNC -LDAPFilter '(objectClass=msDS-AuthNPolicySilo)' -Properties 'msDS-AuthNPolicySiloMembers' @p -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name    = Get-Safe $_ 'Name'
                        Members = Format-DisplayValue (Get-Safe $_ 'msDS-AuthNPolicySiloMembers')
                        DistinguishedName = Get-Safe $_ 'DistinguishedName'
                    }
                })
        }
        catch { }
    }
    if ($DomainNC) {
        try {
            $p = $script:AdServerParam
            $SccmContainers = @(Get-ADObject -SearchBase "CN=System Management,CN=System,$DomainNC" -LDAPFilter '(objectClass=container)' @p -ErrorAction Stop |
                Select-Object -First 20 | ForEach-Object { [PSCustomObject]@{ Name = Get-Safe $_ 'Name'; DistinguishedName = Get-Safe $_ 'DistinguishedName' } })
        }
        catch { }
        try {
            $p = $script:AdServerParam
            $DfsNamespaces = @(Get-ADObject -SearchBase "CN=Dfs-Configuration,CN=System,$DomainNC" -LDAPFilter '(objectClass=fTDfs)' -Properties remoteServerName @p -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name              = Get-Safe $_ 'Name'
                        Servers           = Format-DisplayValue (Get-Safe $_ 'remoteServerName')
                        DistinguishedName = Get-Safe $_ 'DistinguishedName'
                    }
                })
        }
        catch { }
        try {
            $p = $script:AdServerParam
            $PrintQueues = @(Get-ADObject -SearchBase $DomainNC -LDAPFilter '(objectClass=printQueue)' -Properties printerName, driverName, uNCName, serverName @p -ErrorAction Stop |
                Select-Object -First 500 |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name              = Get-Safe $_ 'Name'
                        Printer           = Get-Safe $_ 'printerName'
                        Server            = Get-Safe $_ 'serverName'
                        Driver            = Get-Safe $_ 'driverName'
                        UNC               = Get-Safe $_ 'uNCName'
                        DistinguishedName = Get-Safe $_ 'DistinguishedName'
                    }
                })
        }
        catch { }
        try {
            $p = $script:AdServerParam
            $ForeignPrincipals = @(Get-ADObject -SearchBase "CN=ForeignSecurityPrincipals,$DomainNC" -LDAPFilter '(objectClass=foreignSecurityPrincipal)' -Properties whenCreated, memberOf, name @p -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name              = Get-Safe $_ 'Name'
                        Created           = Get-Safe $_ 'whenCreated'
                        MemberOfCount     = (ConvertTo-StringList (Get-Safe $_ 'memberOf')).Count
                        DistinguishedName = Get-Safe $_ 'DistinguishedName'
                    }
                })
        }
        catch { }
    }

    Write-Host '[21/24] KRBTGT password age...' -ForegroundColor White
    $krbtgt = @($AllUsers | Where-Object { ([string](Get-Safe $_ 'SamAccountName')) -eq 'krbtgt' } | Select-Object -First 1)
    if ($krbtgt) {
        $kPwd = ConvertFrom-AdDate (Get-Safe $krbtgt 'PasswordLastSet')
        if ($kPwd) { $KrbtgtPasswordAgeDays = [int]((Get-Date) - $kPwd).TotalDays }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Projection / classification (shared by live + demo)
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host '[22/24] Classifying users, computers, groups...' -ForegroundColor White

function Get-BestLogon {
    param($Obj)
    $dn = Get-Safe $Obj 'DistinguishedName'
    if ($dn -and $PerDcLogonMap.ContainsKey($dn)) { return $PerDcLogonMap[$dn] }
    return (Get-EffectiveLogonDate $Obj)
}

$UserRows = @($AllUsers | ForEach-Object {
    $logon = Get-BestLogon $_
    $uac = Get-Safe $_ 'UserAccountControl'
    $sidHist = ConvertTo-StringList (Get-Safe $_ 'SIDHistory')
    $memberOf = ConvertTo-StringList (Get-Safe $_ 'MemberOf')
    $spns = ConvertTo-StringList (Get-Safe $_ 'ServicePrincipalNames')
    if ($spns.Count -eq 0) { $spns = ConvertTo-StringList (Get-Safe $_ 'servicePrincipalName') }
    $enabled = $true
    $enRaw = Get-Safe $_ 'Enabled'
    if ($null -ne $enRaw) { $enabled = [bool]$enRaw }
    elseif (Test-UacBit $uac 0x2) { $enabled = $false }
    $acctExp = ConvertFrom-AdDate (Get-Safe $_ 'AccountExpirationDate')
    $expired = $false
    if ($acctExp -and $acctExp -lt (Get-Date) -and $acctExp.Year -gt 1980) { $expired = $true }
    $never = ($null -eq $logon)
    $stale = $enabled -and (-not $never) -and ($logon -lt $CutoffDate)
    $active = $enabled -and (-not $never) -and ($logon -ge $CutoffDate)
    [PSCustomObject]@{
        Name                 = Get-Safe $_ 'Name'
        SamAccountName       = Get-Safe $_ 'SamAccountName'
        Enabled              = $enabled
        LastLogon            = $logon
        LastLogonDisplay     = $(if ($logon) { $logon.ToString('yyyy-MM-dd HH:mm') } else { 'Never' })
        Activity             = $(if (-not $enabled) { 'Disabled' } elseif ($never) { 'Never logged on' } elseif ($stale) { 'Stale' } else { 'Active' })
        Mail                 = Get-Safe $_ 'Mail'
        UPN                  = Get-Safe $_ 'UserPrincipalName'
        PasswordLastSet      = ConvertFrom-AdDate (Get-Safe $_ 'PasswordLastSet')
        PasswordNeverExpires = [bool](Get-Safe $_ 'PasswordNeverExpires' $false)
        PasswordNotRequired  = [bool](Get-Safe $_ 'PasswordNotRequired' $false) -or (Test-UacBit $uac 0x20)
        ReversibleEncryption = [bool](Get-Safe $_ 'AllowReversiblePasswordEncryption' $false) -or (Test-UacBit $uac 0x80)
        DoNotRequirePreAuth  = [bool](Get-Safe $_ 'DoesNotRequirePreAuth' $false) -or (Test-UacBit $uac 0x400000)
        SmartcardRequired    = [bool](Get-Safe $_ 'SmartcardLogonRequired' $false)
        LockedOut            = [bool](Get-Safe $_ 'LockedOut' $false)
        AdminCount           = Get-Safe $_ 'adminCount'
        ScriptPath           = Get-Safe $_ 'ScriptPath'
        HomeDirectory        = Get-Safe $_ 'HomeDirectory'
        ProfilePath          = Get-Safe $_ 'ProfilePath'
        SIDHistory           = (Join-StringList $sidHist)
        SIDHistoryCount      = $sidHist.Count
        MemberOfCount        = $memberOf.Count
        SPNCount             = $spns.Count
        SPNs                 = (Join-StringList $spns)
        Description          = Get-Safe $_ 'Description'
        Department           = Get-Safe $_ 'Department'
        Title                = Get-Safe $_ 'Title'
        UacFlags             = Get-UacFlagNames $uac
        AccountExpired       = $expired
        AccountExpires       = $acctExp
        WhenCreated          = ConvertFrom-AdDate (Get-Safe $_ 'WhenCreated')
        PrimaryGroupID       = Get-Safe $_ 'primaryGroupID'
        DistinguishedName    = Get-Safe $_ 'DistinguishedName'
        OU                   = Get-OuFromDn (Get-Safe $_ 'DistinguishedName')
        IsServiceAccount     = Test-ServiceAccount $_
        LogonCount           = Get-Safe $_ 'logonCount'
        MemberOf             = $memberOf
        ObjectClass          = Get-Safe $_ 'ObjectClass' 'user'
    }
})

$ComputerRows = @($AllComputers | ForEach-Object {
    $logon = Get-BestLogon $_
    $pwd = ConvertFrom-AdDate (Get-Safe $_ 'PasswordLastSet')
    $activity = $logon
    if ($pwd -and ($null -eq $activity -or $pwd -gt $activity)) { $activity = $pwd }
    $uac = Get-Safe $_ 'UserAccountControl'
    $enabled = $true
    $enRaw = Get-Safe $_ 'Enabled'
    if ($null -ne $enRaw) { $enabled = [bool]$enRaw }
    elseif (Test-UacBit $uac 0x2) { $enabled = $false }
    $never = ($null -eq $activity)
    $stale = $enabled -and (-not $never) -and ($activity -lt $CutoffDate)
    $active = $enabled -and (-not $never) -and ($activity -ge $CutoffDate)
    $os = [string](Get-Safe $_ 'OperatingSystem')
    $spns = ConvertTo-StringList (Get-Safe $_ 'ServicePrincipalNames')
    $sidHist = ConvertTo-StringList (Get-Safe $_ 'SIDHistory')
    $memberOf = ConvertTo-StringList (Get-Safe $_ 'MemberOf')
    [PSCustomObject]@{
        Name              = Get-Safe $_ 'Name'
        DNSHostName       = Get-Safe $_ 'DNSHostName'
        Enabled           = $enabled
        LastLogon         = $logon
        PasswordLastSet   = $pwd
        ActivityDate      = $activity
        ActivitySource    = $(if ($pwd -and $activity -eq $pwd -and $activity -ne $logon) { 'PasswordLastSet' } elseif ($logon) { 'LastLogon' } else { 'None' })
        Activity          = $(if (-not $enabled) { 'Disabled' } elseif ($never) { 'Never' } elseif ($stale) { 'Stale' } else { 'Active' })
        LastLogonDisplay  = $(if ($activity) { $activity.ToString('yyyy-MM-dd HH:mm') } else { 'Never' })
        OperatingSystem   = $os
        OSVersion         = Get-Safe $_ 'OperatingSystemVersion'
        IPv4Address       = Get-Safe $_ 'IPv4Address'
        Description       = Get-Safe $_ 'Description'
        IsServer          = [bool]($os -match 'Server')
        IsDC              = (Test-UacBit $uac 0x2000) -or ((Get-Safe $_ 'primaryGroupID') -eq 516)
        UnconstrainedDel  = Test-UacBit $uac 0x80000
        SIDHistoryCount   = $sidHist.Count
        SPNs              = (Join-StringList $spns)
        MemberOfCount     = $memberOf.Count
        MemberOf          = $memberOf
        PrimaryGroupID    = Get-Safe $_ 'primaryGroupID'
        HybridJoin        = [bool](Get-Safe $_ 'msDS-ExternalDirectoryObjectId')
        HasLaps           = $null -ne (Get-Safe $_ 'ms-Mcs-AdmPwdExpirationTime')
        UacFlags          = Get-UacFlagNames $uac
        WhenCreated       = ConvertFrom-AdDate (Get-Safe $_ 'WhenCreated')
        DistinguishedName = Get-Safe $_ 'DistinguishedName'
        OU                = Get-OuFromDn (Get-Safe $_ 'DistinguishedName')
        ObjectClass       = 'computer'
    }
})

$ActiveUsers      = @($UserRows | Where-Object { $_.Activity -eq 'Active' })
$StaleUsers       = @($UserRows | Where-Object { $_.Activity -eq 'Stale' })
$NeverUsers       = @($UserRows | Where-Object { $_.Activity -eq 'Never logged on' })
$DisabledUsers    = @($UserRows | Where-Object { -not $_.Enabled })
$SvcAccounts      = @($UserRows | Where-Object { $_.IsServiceAccount })
$UsersWithSIDHistory = @($UserRows | Where-Object { $_.SIDHistoryCount -gt 0 })
$AdminCountUsers  = @($UserRows | Where-Object { $_.AdminCount -ge 1 -and $_.SamAccountName -ne 'krbtgt' })
$PwdNeverUsers    = @($UserRows | Where-Object { $_.Enabled -and $_.PasswordNeverExpires })
$NoPreauthUsers   = @($UserRows | Where-Object { $_.DoNotRequirePreAuth })
$PwdNotReqUsers   = @($UserRows | Where-Object { $_.PasswordNotRequired })
$LogonScriptUsers = @($UserRows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.ScriptPath) })
$HomeDirUsers     = @($UserRows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.HomeDirectory) })
$ProfileUsers     = @($UserRows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.ProfilePath) })
$MailUsers        = @($UserRows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Mail) })
$TokenBloatUsers  = @($UserRows | Where-Object { $_.MemberOfCount -ge 70 })
$ExpiredEnabled   = @($UserRows | Where-Object { $_.Enabled -and $_.AccountExpired })

$ActiveComputers   = @($ComputerRows | Where-Object { $_.Activity -eq 'Active' })
$StaleComputers    = @($ComputerRows | Where-Object { $_.Activity -eq 'Stale' })
$NeverComputers    = @($ComputerRows | Where-Object { $_.Activity -eq 'Never' })
$DisabledComputers = @($ComputerRows | Where-Object { -not $_.Enabled })
$ServerComputers   = @($ComputerRows | Where-Object { $_.IsServer -and -not $_.IsDC })
$OsSummary = @($ComputerRows | Where-Object { $_.OperatingSystem } | Group-Object OperatingSystem | ForEach-Object {
    [PSCustomObject]@{ Name = $_.Name; Count = $_.Count }
} | Sort-Object Count -Descending)

# Group membership index (reverse memberOf + primaryGroupID) — no Get-ADGroupMember per group
$GroupRidMap = @{}
$GroupByDn = @{}
foreach ($g in $AllGroups) {
    $dn = Get-Safe $g 'DistinguishedName'
    if (-not $dn) { continue }
    $GroupByDn[$dn] = $g
    $sid = Get-Safe $g 'SID'
    if (-not $sid) { $sid = Get-Safe $g 'ObjectSID' }
    $rid = Get-RidFromSid $sid
    if ($null -ne $rid) { $GroupRidMap[$rid] = $dn }
}

$GroupMemberCount = @{}
$GroupMemberTypeHint = @{}
foreach ($dn in $GroupByDn.Keys) { $GroupMemberCount[$dn] = 0 }

function Add-IndexedMembership {
    param($ObjRow)
    $mof = Get-Safe $ObjRow 'MemberOf'
    foreach ($dn in (ConvertTo-StringList $mof)) {
        if ($GroupMemberCount.ContainsKey($dn)) { $GroupMemberCount[$dn]++ }
    }
    $rid = Get-Safe $ObjRow 'PrimaryGroupID'
    if ($null -eq $rid) { $rid = Get-Safe $ObjRow 'primaryGroupID' }
    if ($null -ne $rid) {
        try { $rid = [int]$rid } catch { $rid = $null }
        if ($null -ne $rid -and $GroupRidMap.ContainsKey($rid)) {
            $pdn = $GroupRidMap[$rid]
            if ($GroupMemberCount.ContainsKey($pdn)) { $GroupMemberCount[$pdn]++ }
        }
    }
}
foreach ($u in $UserRows) { Add-IndexedMembership $u }
foreach ($c in $ComputerRows) { Add-IndexedMembership $c }
foreach ($g in $AllGroups) {
    $mof = ConvertTo-StringList (Get-Safe $g 'memberOf')
    if ($mof.Count -eq 0) { $mof = ConvertTo-StringList (Get-Safe $g 'MemberOf') }
    foreach ($dn in $mof) {
        if ($GroupMemberCount.ContainsKey($dn)) { $GroupMemberCount[$dn]++ }
    }
}

$GroupRows = @($AllGroups | ForEach-Object {
    $dn = Get-Safe $_ 'DistinguishedName'
    $mof = ConvertTo-StringList (Get-Safe $_ 'memberOf')
    if ($mof.Count -eq 0) { $mof = ConvertTo-StringList (Get-Safe $_ 'MemberOf') }
    $count = 0
    if ($dn -and $GroupMemberCount.ContainsKey($dn)) { $count = $GroupMemberCount[$dn] }
    [PSCustomObject]@{
        Name              = Get-Safe $_ 'Name'
        SamAccountName    = Get-Safe $_ 'SamAccountName'
        GroupCategory     = Get-Safe $_ 'GroupCategory'
        GroupScope        = Get-Safe $_ 'GroupScope'
        MemberCount       = $count
        NestedIn          = $mof.Count
        Mail              = Get-Safe $_ 'Mail'
        Description       = Get-Safe $_ 'Description'
        ManagedBy         = Get-Safe $_ 'ManagedBy'
        WhenCreated       = ConvertFrom-AdDate (Get-Safe $_ 'WhenCreated')
        SID               = Format-DisplayValue (Get-Safe $_ 'SID')
        DistinguishedName = $dn
        MemberOf          = $mof
    }
})

$GroupsWithMembers = @($GroupRows | Where-Object { $_.MemberCount -gt 0 })
$EmptyGroups       = @($GroupRows | Where-Object { $_.MemberCount -eq 0 })

$NestedGroups = New-Object System.Collections.Generic.List[object]
foreach ($g in $GroupRows) {
    foreach ($parentDn in @(Get-Safe $g 'MemberOf')) {
        $parentName = $parentDn
        if ($GroupByDn.ContainsKey($parentDn)) { $parentName = Get-Safe $GroupByDn[$parentDn] 'Name' }
        $NestedGroups.Add([PSCustomObject]@{
            NestedGroup   = $g.Name
            ChildScope    = $g.GroupScope
            ChildCategory = $g.GroupCategory
            ParentGroup   = $parentName
            NestedDN      = $g.DistinguishedName
            ParentDN      = $parentDn
        }) | Out-Null
    }
}
# Keep as List — wrapping Generic.List with @() throws "Argument types do not match" on PS 7.

# Privileged groups by SID (locale-independent) plus a few CN lookups
$PrivSidRids = @(
    @{ Rid = 512; Label = 'Domain Admins'; Scope = 'domain' },
    @{ Rid = 519; Label = 'Enterprise Admins'; Scope = 'domain' },
    @{ Rid = 518; Label = 'Schema Admins'; Scope = 'domain' },
    @{ Rid = 517; Label = 'Cert Publishers'; Scope = 'domain' },
    @{ Rid = 520; Label = 'Group Policy Creator Owners'; Scope = 'domain' },
    @{ Rid = 521; Label = 'Read-only Domain Controllers'; Scope = 'domain' },
    @{ Rid = 525; Label = 'Protected Users'; Scope = 'domain' },
    @{ Rid = 526; Label = 'Key Admins'; Scope = 'domain' },
    @{ Rid = 527; Label = 'Enterprise Key Admins'; Scope = 'domain' },
    @{ Rid = 553; Label = 'RAS and IAS Servers'; Scope = 'domain' }
)
$BuiltinSids = @(
    @{ Sid = 'S-1-5-32-544'; Label = 'Administrators' },
    @{ Sid = 'S-1-5-32-548'; Label = 'Account Operators' },
    @{ Sid = 'S-1-5-32-549'; Label = 'Server Operators' },
    @{ Sid = 'S-1-5-32-550'; Label = 'Print Operators' },
    @{ Sid = 'S-1-5-32-551'; Label = 'Backup Operators' },
    @{ Sid = 'S-1-5-32-555'; Label = 'Remote Desktop Users' },
    @{ Sid = 'S-1-5-32-556'; Label = 'Network Configuration Operators' }
)

$domainSidValue = Get-PropText $Domain 'DomainSID' ''
if ($domainSidValue -eq 'N/A') { $domainSidValue = '' }

$PrivGroupDns = New-Object System.Collections.Generic.List[object]
if ($domainSidValue -match '^S-1-5-21-') {
    foreach ($item in $PrivSidRids) {
        $sid = "$domainSidValue-$($item.Rid)"
        $dn = $null
        foreach ($g in $AllGroups) {
            $gsid = Format-DisplayValue (Get-Safe $g 'SID')
            if (-not $gsid) { $gsid = Format-DisplayValue (Get-Safe $g 'ObjectSID') }
            if ($gsid -eq $sid) { $dn = Get-Safe $g 'DistinguishedName'; break }
        }
        $PrivGroupDns.Add([PSCustomObject]@{ Label = $item.Label; Sid = $sid; DN = $dn }) | Out-Null
    }
}
foreach ($item in $BuiltinSids) {
    $dn = $null
    foreach ($g in $AllGroups) {
        $gsid = Format-DisplayValue (Get-Safe $g 'SID')
        if ($gsid -eq $item.Sid) { $dn = Get-Safe $g 'DistinguishedName'; break }
    }
    $PrivGroupDns.Add([PSCustomObject]@{ Label = $item.Label; Sid = $item.Sid; DN = $dn }) | Out-Null
}
foreach ($extraName in @('DnsAdmins', 'Hyper-V Administrators', 'Access Control Assistance Operators')) {
    $hit = @($AllGroups | Where-Object { (Get-Safe $_ 'SamAccountName') -eq $extraName -or (Get-Safe $_ 'Name') -eq $extraName } | Select-Object -First 1)
    if ($hit) {
        $PrivGroupDns.Add([PSCustomObject]@{ Label = $extraName; Sid = Format-DisplayValue (Get-Safe $hit 'SID'); DN = Get-Safe $hit 'DistinguishedName' }) | Out-Null
    }
}

function Get-MembersRecursive {
    param([string]$GroupDn, [int]$MaxDepth = 8)
    $results = New-Object System.Collections.Generic.List[object]
    $visited = @{}
    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue(@{ Dn = $GroupDn; Depth = 0 })
    $userByDn = @{}
    foreach ($u in $UserRows) { if ($u.DistinguishedName) { $userByDn[$u.DistinguishedName] = $u } }
    $compByDn = @{}
    foreach ($c in $ComputerRows) { if ($c.DistinguishedName) { $compByDn[$c.DistinguishedName] = $c } }

    $childIndex = @{}
    foreach ($u in $UserRows) {
        foreach ($p in (ConvertTo-StringList $u.MemberOf)) {
            if (-not $childIndex.ContainsKey($p)) { $childIndex[$p] = New-Object System.Collections.Generic.List[string] }
            [void]$childIndex[$p].Add($u.DistinguishedName)
        }
        $rid = $u.PrimaryGroupID
        if ($null -ne $rid) {
            try { $rid = [int]$rid } catch { $rid = $null }
            if ($null -ne $rid -and $GroupRidMap.ContainsKey($rid)) {
                $pdn = $GroupRidMap[$rid]
                if (-not $childIndex.ContainsKey($pdn)) { $childIndex[$pdn] = New-Object System.Collections.Generic.List[string] }
                [void]$childIndex[$pdn].Add($u.DistinguishedName)
            }
        }
    }
    foreach ($c in $ComputerRows) {
        foreach ($p in (ConvertTo-StringList $c.MemberOf)) {
            if (-not $childIndex.ContainsKey($p)) { $childIndex[$p] = New-Object System.Collections.Generic.List[string] }
            [void]$childIndex[$p].Add($c.DistinguishedName)
        }
        $rid = $c.PrimaryGroupID
        if ($null -ne $rid) {
            try { $rid = [int]$rid } catch { $rid = $null }
            if ($null -ne $rid -and $GroupRidMap.ContainsKey($rid)) {
                $pdn = $GroupRidMap[$rid]
                if (-not $childIndex.ContainsKey($pdn)) { $childIndex[$pdn] = New-Object System.Collections.Generic.List[string] }
                [void]$childIndex[$pdn].Add($c.DistinguishedName)
            }
        }
    }
    foreach ($g in $GroupRows) {
        foreach ($p in (ConvertTo-StringList $g.MemberOf)) {
            if (-not $childIndex.ContainsKey($p)) { $childIndex[$p] = New-Object System.Collections.Generic.List[string] }
            [void]$childIndex[$p].Add($g.DistinguishedName)
        }
    }

    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        $dn = $item.Dn
        $depth = [int]$item.Depth
        if ($visited.ContainsKey($dn)) { continue }
        $visited[$dn] = $true
        if (-not $childIndex.ContainsKey($dn)) { continue }
        foreach ($child in @($childIndex[$dn])) {
            if ($userByDn.ContainsKey($child)) {
                $u = $userByDn[$child]
                $results.Add([PSCustomObject]@{ Name=$u.Name; SamAccountName=$u.SamAccountName; ObjectClass='user'; DistinguishedName=$child; Depth=$depth }) | Out-Null
            }
            elseif ($compByDn.ContainsKey($child)) {
                $c = $compByDn[$child]
                $results.Add([PSCustomObject]@{ Name=$c.Name; SamAccountName=$c.Name; ObjectClass='computer'; DistinguishedName=$child; Depth=$depth }) | Out-Null
            }
            elseif ($GroupByDn.ContainsKey($child) -and $depth -lt $MaxDepth) {
                $queue.Enqueue(@{ Dn = $child; Depth = $depth + 1 })
            }
        }
    }
    return $results
}

$PrivilegedMembers = New-Object System.Collections.Generic.List[object]
foreach ($pg in $PrivGroupDns) {
    if (-not $pg.DN) { continue }
    $members = Get-MembersRecursive -GroupDn $pg.DN
    foreach ($m in $members) {
        $PrivilegedMembers.Add([PSCustomObject]@{
            Group             = $pg.Label
            Name              = $m.Name
            SamAccountName    = $m.SamAccountName
            ObjectClass       = $m.ObjectClass
            NestedDepth       = $m.Depth
            DistinguishedName = $m.DistinguishedName
        }) | Out-Null
    }
}
# Keep as List so PS 7 does not throw on @() wrapping.

if ($NpsMembers.Count -eq 0) {
    $ras = @($PrivGroupDns | Where-Object { $_.Label -eq 'RAS and IAS Servers' } | Select-Object -First 1)
    if ($ras -and $ras.DN) {
        $NpsMembers = @($PrivilegedMembers | Where-Object { $_.Group -eq 'RAS and IAS Servers' } |
            Select-Object Group, Name, SamAccountName, ObjectClass, DistinguishedName)
    }
}

# Duplicate SPNs
$spnFlat = New-Object System.Collections.Generic.List[object]
foreach ($u in $UserRows) {
    foreach ($spn in @(($u.SPNs -split '; ') | Where-Object { $_ })) {
        $spnFlat.Add([PSCustomObject]@{ SPN = $spn; Account = $u.SamAccountName; DN = $u.DistinguishedName }) | Out-Null
    }
}
foreach ($c in $ComputerRows) {
    foreach ($spn in @(($c.SPNs -split '; ') | Where-Object { $_ })) {
        $acct = if ($c.Name) { $c.Name + '$' } else { $c.DNSHostName }
        $spnFlat.Add([PSCustomObject]@{ SPN = $spn; Account = $acct; DN = $c.DistinguishedName }) | Out-Null
    }
}
$SPNDuplicates = @($spnFlat | Group-Object SPN | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Group })
$SpnPrefixSummary = @($spnFlat | ForEach-Object {
    $prefix = $_.SPN
    $slash = $prefix.IndexOf('/')
    if ($slash -gt 0) { $prefix = $prefix.Substring(0, $slash) }
    $prefix
} | Group-Object | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object {
    [PSCustomObject]@{ Prefix = $_.Name; Count = $_.Count }
})

# GPO projection with site + OU links and flags
$GpoLinkMap = @{}
$GpoLinkDetail = New-Object System.Collections.Generic.List[object]
foreach ($lo in @($LinkedObjects)) {
    $gpLink = [string](Get-Safe $lo 'gpLink')
    if ([string]::IsNullOrWhiteSpace($gpLink)) { continue }
    $target = Get-Safe $lo 'DistinguishedName'
    $matchesLink = [regex]::Matches($gpLink, '\[LDAP://([^;\]]+);(\d+)\]')
    if ($matchesLink.Count -eq 0) {
        $matchesLink = [regex]::Matches($gpLink, '\{([A-Fa-f0-9\-]{36})\}')
        foreach ($m in $matchesLink) {
            $gid = '{' + $m.Groups[1].Value.ToUpperInvariant() + '}'
            if (-not $GpoLinkMap.ContainsKey($gid)) { $GpoLinkMap[$gid] = New-Object 'System.Collections.Generic.List[string]' }
            $GpoLinkMap[$gid].Add($target)
            $GpoLinkDetail.Add([PSCustomObject]@{ GpoId = $gid; Target = $target; Enabled = $true; Enforced = $false }) | Out-Null
        }
        continue
    }
    foreach ($m in $matchesLink) {
        $path = $m.Groups[1].Value
        $flag = 0
        try { $flag = [int]$m.Groups[2].Value } catch { $flag = 0 }
        $gm = [regex]::Match($path, '\{[A-Fa-f0-9\-]{36}\}')
        if (-not $gm.Success) { continue }
        $gid = $gm.Value.ToUpperInvariant()
        $enabled = (($flag -band 1) -eq 0)
        $enforced = (($flag -band 2) -ne 0)
        if (-not $GpoLinkMap.ContainsKey($gid)) { $GpoLinkMap[$gid] = New-Object 'System.Collections.Generic.List[string]' }
        $GpoLinkMap[$gid].Add($target)
        $GpoLinkDetail.Add([PSCustomObject]@{
            GpoId    = $gid
            Target   = $target
            Enabled  = $enabled
            Enforced = $enforced
            Flags    = $flag
        }) | Out-Null
    }
}

$GPOs = @($RawGPOs | ForEach-Object {
    $id = ([string](Get-Safe $_ 'Name')).ToUpperInvariant()
    $flags = 0
    try { $flags = [int](Get-Safe $_ 'flags' 0) } catch { $flags = 0 }
    $status = switch ($flags) {
        0 { 'Enabled' }
        1 { 'User Settings Disabled' }
        2 { 'Computer Settings Disabled' }
        3 { 'All Settings Disabled' }
        default { "flags=$flags" }
    }
    $linkCount = 0
    $linkTargets = ''
    if ($GpoLinkMap.ContainsKey($id)) {
        $linkCount = $GpoLinkMap[$id].Count
        $linkTargets = Join-StringList $GpoLinkMap[$id] ' | '
    }
    $ver = 0
    try { $ver = [int](Get-Safe $_ 'versionNumber' 0) } catch { $ver = 0 }
    $userVer = [math]::Floor($ver / 65536)
    $compVer = $ver -band 65535
    [PSCustomObject]@{
        DisplayName   = $(if (Get-Safe $_ 'displayName') { Get-Safe $_ 'displayName' } else { Get-Safe $_ 'Name' })
        GPOId         = Get-Safe $_ 'Name'
        Status        = $status
        LinkedTo      = $linkCount
        LinkTargets   = $linkTargets
        UserExts      = $(if (Get-Safe $_ 'gPCUserExtensionNames') { 'Yes' } else { 'None' })
        ComputerExts  = $(if (Get-Safe $_ 'gPCMachineExtensionNames') { 'Yes' } else { 'None' })
        UserVersion   = $userVer
        ComputerVersion = $compVer
        WmiFilter     = Get-Safe $_ 'gPCWQLFilter'
        Created       = ConvertFrom-AdDate (Get-Safe $_ 'whenCreated')
        Modified      = ConvertFrom-AdDate (Get-Safe $_ 'whenChanged')
        SysvolPath    = Get-Safe $_ 'gPCFileSysPath'
        Description   = Get-Safe $_ 'description'
        DistinguishedName = Get-Safe $_ 'DistinguishedName'
    }
})
$UnlinkedGpos = @($GPOs | Where-Object { $_.LinkedTo -eq 0 })
$DisabledGpos = @($GPOs | Where-Object { $_.Status -eq 'All Settings Disabled' })

# FSMO table
$FsmoRows = @()
$FsmoRows += [PSCustomObject]@{ Role = 'PDC Emulator'; Scope = 'Domain'; Holder = Get-PropText $Domain 'PDCEmulator'; Notes = 'Time source, password changes, GPO processing, account lockout. Transfer before demoting the holder.' }
$FsmoRows += [PSCustomObject]@{ Role = 'RID Master'; Scope = 'Domain'; Holder = Get-PropText $Domain 'RIDMaster'; Notes = 'RID pool allocation. Transfer before demoting the holder.' }
$FsmoRows += [PSCustomObject]@{ Role = 'Infrastructure Master'; Scope = 'Domain'; Holder = Get-PropText $Domain 'InfrastructureMaster'; Notes = 'Phantom/FSP updates. Should not be a GC in multi-domain forests unless all DCs are GCs.' }
$FsmoRows += [PSCustomObject]@{ Role = 'Schema Master'; Scope = 'Forest'; Holder = Get-PropText $Forest 'SchemaMaster'; Notes = 'Forest-wide. Do not retire the forest root until this has moved.' }
$FsmoRows += [PSCustomObject]@{ Role = 'Domain Naming Master'; Scope = 'Forest'; Holder = Get-PropText $Forest 'DomainNamingMaster'; Notes = 'Required to add/remove domains. Must live until this domain is removed from the forest.' }

$DcRows = @($DCs | ForEach-Object {
    [PSCustomObject]@{
        HostName              = Get-PropText $_ 'HostName' ''
        Site                  = Get-PropText $_ 'Site' ''
        IPv4Address           = Get-PropText $_ 'IPv4Address' ''
        OperatingSystem       = Get-PropText $_ 'OperatingSystem' ''
        OSVersion             = Get-PropText $_ 'OperatingSystemVersion' ''
        IsGlobalCatalog       = Get-PropText $_ 'IsGlobalCatalog' ''
        IsReadOnly            = Get-PropText $_ 'IsReadOnly' 'False'
        OperationMasterRoles  = Format-DisplayValue (Get-Safe $_ 'OperationMasterRoles')
        Enabled               = Get-PropText $_ 'Enabled' ''
        NTDSSettings          = Get-PropText $_ 'NTDSSettingsObjectDN' ''
    }
})

$TrustRows = @($Trusts | ForEach-Object {
    [PSCustomObject]@{
        Name                     = Get-PropText $_ 'Name' ''
        Direction                = Get-PropText $_ 'Direction' ''
        TrustType                = Get-PropText $_ 'TrustType' ''
        ForestTransitive         = Get-PropText $_ 'ForestTransitive' ''
        IntraForest              = Get-PropText $_ 'IntraForest' ''
        SelectiveAuthentication  = Get-PropText $_ 'SelectiveAuthentication' ''
        SIDFilteringForestAware  = Get-PropText $_ 'SIDFilteringForestAware' ''
        SIDFilteringQuarantined  = Get-PropText $_ 'SIDFilteringQuarantined' ''
        DisallowTransivity       = Get-PropText $_ 'DisallowTransivity' ''
        TGTDelegation            = Get-PropText $_ 'TGTDelegation' ''
        UsesAESKeys              = Get-PropText $_ 'UsesAESKeys' ''
        UsesRC4Encryption        = Get-PropText $_ 'UsesRC4Encryption' ''
        UplevelOnly              = Get-PropText $_ 'UplevelOnly' ''
        Created                  = Format-DisplayValue (Get-Safe $_ 'Created')
        Modified                 = Format-DisplayValue (Get-Safe $_ 'Modified')
        DistinguishedName        = Get-PropText $_ 'DistinguishedName' ''
    }
})

$SiteRows = @($Sites | ForEach-Object {
    $siteName = Get-PropText $_ 'Name' ''
    $dcHere = @($DcRows | Where-Object { $_.Site -eq $siteName }).Count
    [PSCustomObject]@{
        Name              = $siteName
        Description       = Get-PropText $_ 'Description' ''
        DCCount           = $dcHere
        DistinguishedName = Get-PropText $_ 'DistinguishedName' ''
    }
})
$SitesWithoutDCs = @($SiteRows | Where-Object { $_.DCCount -eq 0 })
$SubnetRows = @($Subnets | ForEach-Object {
    [PSCustomObject]@{
        Name              = Get-PropText $_ 'Name' ''
        Site              = Format-DisplayValue (Get-Safe $_ 'Site')
        Location          = Get-PropText $_ 'Location' ''
        Description       = Get-PropText $_ 'Description' ''
        DistinguishedName = Get-PropText $_ 'DistinguishedName' ''
    }
})
$SubnetsWithoutSite = @($SubnetRows | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.Site) -or $_.Site -eq 'N/A' })
$SiteLinkRows = @($SiteLinks | ForEach-Object {
    [PSCustomObject]@{
        Name          = Get-PropText $_ 'Name' ''
        Cost          = Get-PropText $_ 'Cost' ''
        IntervalMin   = Get-PropText $_ 'ReplicationFrequencyInMinutes' ''
        SitesIncluded = Format-DisplayValue (Get-Safe $_ 'SitesIncluded')
        DistinguishedName = Get-PropText $_ 'DistinguishedName' ''
    }
})

$OuRows = @($OUs | ForEach-Object {
    $dn = Get-PropText $_ 'DistinguishedName' ''
    $childHint = @($UserRows + $ComputerRows | Where-Object { $_.OU -eq $dn }).Count
    [PSCustomObject]@{
        Name              = Get-PropText $_ 'Name' ''
        Description       = Get-PropText $_ 'Description' ''
        ProtectedFromAccidentalDeletion = Get-PropText $_ 'ProtectedFromAccidentalDeletion' ''
        DirectUserOrComputerCount = $childHint
        GpoLinks          = (ConvertTo-StringList (Get-Safe $_ 'LinkedGroupPolicyObjects')).Count
        ManagedBy         = Get-PropText $_ 'ManagedBy' ''
        DistinguishedName = $dn
    }
})
$ProtectedOus = @($OuRows | Where-Object { $_.ProtectedFromAccidentalDeletion -eq 'True' -or $_.ProtectedFromAccidentalDeletion -eq $true })

$DnsZones = $DnsZoneRows
$FspCount = @($ForeignPrincipals).Count

if ($null -eq $PasswordPolicy) {
    $PasswordPolicy = [PSCustomObject]@{
        MinPasswordLength = 'N/A'; MaxPasswordAge = 'N/A'; MinPasswordAge = 'N/A'
        PasswordHistoryCount = 'N/A'; LockoutThreshold = 'N/A'; LockoutDuration = 'N/A'
        ComplexityEnabled = 'N/A'; ReversibleEncryptionEnabled = 'N/A'
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Risk scoring
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host '[23/24] Computing retirement readiness...' -ForegroundColor White

$Blockers = New-Object 'System.Collections.Generic.List[PSCustomObject]'
function Add-Blocker {
    param($Category, $Severity, $Count, $Detail, $Recommendation)
    $Blockers.Add([PSCustomObject]@{
        Category       = $Category
        Severity       = $Severity
        Count          = $Count
        Detail         = $Detail
        Recommendation = $Recommendation
    }) | Out-Null
}

if ($ActiveUsers.Count -gt 0) {
    Add-Blocker 'Active Users' 'Critical' $ActiveUsers.Count "$($ActiveUsers.Count) user(s) authenticated (or lastLogonTimestamp) within $StaleDays days. lastLogonTimestamp can lag ~14 days; never-logged-on accounts are listed separately." 'Migrate identities (ADMT / Entra Connect / cloud-native) then disable. Coordinate HR, IAM, and app owners. Preserve SID history until resource ACLs are rewritten.'
}
if ($SvcAccounts.Count -gt 0) {
    Add-Blocker 'Service Accounts' 'Critical' $SvcAccounts.Count "$($SvcAccounts.Count) likely service/application account(s) (SPN on a user, gMSA-style name, MSOL/AAD sync, or service description). Human 'admin' accounts are no longer auto-classified as service accounts." 'Trace every LDAP/Kerberos bind. Replace with gMSA or target-domain accounts. Check IIS app pools, Windows services, scheduled tasks, SQL, backup, monitoring, printers.'
}
if ($Gmsa.Count -gt 0) {
    Add-Blocker 'Group Managed Service Accounts' 'Critical' $Gmsa.Count "$($Gmsa.Count) gMSA/sMSA object(s) plus $($KdsRootKeys.Count) KDS root key(s)." 'Recreate KDS root key in the target domain (wait 10 hours, or use effective time now in a lab), then recreate gMSAs and update host principals.'
}
if ($ActiveComputers.Count -gt 0) {
    Add-Blocker 'Active Computers' 'Critical' $ActiveComputers.Count "$($ActiveComputers.Count) computer(s) with lastLogonTimestamp or PasswordLastSet within $StaleDays days (machine passwords rotate ~30 days, which is a better 'online' signal than LastLogonDate alone)." 'Re-join servers first, then workstations. Validate third-party NAS / Linux / macOS binds. Update WSUS/SCCM/Intune and backup agents.'
}
if ($ServerComputers.Count -gt 0) {
    Add-Blocker 'Member Servers' 'Critical' $ServerComputers.Count "$($ServerComputers.Count) non-DC server-class computer object(s) in this domain." 'Inventory workloads (SQL, file, print, IIS, app). These are usually the last objects that still need the domain.'
}
if ($Trusts.Count -gt 0) {
    Add-Blocker 'Domain Trusts' 'Critical' $Trusts.Count "$($Trusts.Count) trust(s) remain. Inbound trusts mean others still consume this domain; outbound means this domain still consumes others. FSPs: $FspCount." 'Map every cross-domain group, SQL linked server, file-share ACL, and LDAP bind that uses the trust. Remove from both sides only after cutover.'
}
if ($CAs.Count -gt 0) {
    Add-Blocker 'AD Certificate Services' 'Critical' $CAs.Count "$($CAs.Count) enterprise enrollment service(s); $($CaTemplates.Count) template(s); $($AiaCdp.Count) AIA/CDP/KRA object(s)." 'Stand up a CA in the surviving forest. Publish new AIA/CDP (keep old HTTP CDP online for remaining cert lifetimes). Export CA database + keys. Remove Enrollment Services objects only after no autoenrollment remains.'
}
if ($AdfsObjects.Count -gt 0 -or $AdfsSpnComputers.Count -gt 0) {
    $n = [Math]::Max($AdfsObjects.Count, $AdfsSpnComputers.Count)
    Add-Blocker 'AD FS / Device Registration' 'Critical' $n "AD FS artifacts: $($AdfsObjects.Count) directory object(s), computers with ADFS SPNs: $($AdfsSpnComputers.Count)." 'Migrate relying parties to Entra ID or a new STS. Keep the farm until token lifetime + certificate lifetime expire. Update Azure AD Connect federation settings.'
}
if ($EntraConnect.Count -gt 0) {
    Add-Blocker 'Entra Connect / DirSync' 'Critical' $EntraConnect.Count "$($EntraConnect.Count) Azure AD Connect / MSOL / AAD sync account(s) live in this domain." 'If this domain still feeds Entra ID, re-point or rebuild the sync engine against the surviving source of authority before DC demotion.'
}
if ($ExchangeServers.Count -gt 0) {
    Add-Blocker 'Exchange' 'Critical' $ExchangeServers.Count "$($ExchangeServers.Count) msExchExchangeServer object(s) in configuration." 'Exchange cannot be left behind in a retired domain. Migrate mailboxes / decommission with /Hosting or official uninstall so the forest config NC is cleaned.'
}

if ($PrivilegedMembers.Count -gt 0) {
    Add-Blocker 'Privileged Group Members' 'High' $PrivilegedMembers.Count "$($PrivilegedMembers.Count) nested member(s) across SID-resolved privileged groups (Domain/Enterprise/Schema Admins, builtin operators, Protected Users, Key Admins, DnsAdmins, …)." 'Recreate break-glass and admin workstations in the target domain. Nested membership is expanded from memberOf (works when Get-ADGroupMember fails on FSPs).'
}
if ($GPOs.Count -gt 0) {
    Add-Blocker 'Group Policies' 'High' $GPOs.Count "$($GPOs.Count) GPO(s); $($UnlinkedGpos.Count) unlinked; $($DisabledGpos.Count) fully disabled; $($WmiFilters.Count) WMI filter(s). Links include OUs, domain root, and sites." 'Backup with GPMC. Recreate only what is still required. Watch security filtering, WMI filters, and GPP credentials (cpassword).'
}
if ($GroupsWithMembers.Count -gt 0) {
    Add-Blocker 'Groups with Members' 'High' $GroupsWithMembers.Count "$($GroupsWithMembers.Count) of $($GroupRows.Count) group(s) have members (explicit memberOf + primaryGroupID, so Domain Users is no longer stuck at 0)." "Rebuild resource groups in the target domain and rewrite ACLs. Empty groups ($($EmptyGroups.Count)) can usually be skipped."
}
if ($UsersWithSIDHistory.Count -gt 0) {
    Add-Blocker 'SID History' 'High' $UsersWithSIDHistory.Count "$($UsersWithSIDHistory.Count) user(s) carry SID history from a previous migration." 'Do not strip SID history until file/SQL/application ACLs have been rewritten to target-domain SIDs.'
}
if ($DhcpServers.Count -gt 0) {
    Add-Blocker 'DHCP Servers' 'High' $DhcpServers.Count "$($DhcpServers.Count) authorised DHCP server(s) in the forest configuration (not filtered out just because the FQDN suffix differs)." 'Export scopes, authorise the new server, migrate reservations/options (especially 006 DNS / 015 domain), then de-authorise.'
}
if ($NpsMembers.Count -gt 0) {
    Add-Blocker 'NPS / RADIUS' 'High' $NpsMembers.Count "$($NpsMembers.Count) member(s) of RAS and IAS Servers (the supported way to find NPS). SPN matching for 'radius' is not reliable." 'Export NPS config (netsh nps export), migrate RADIUS clients (switches, VPN, WAP), re-register in the target domain.'
}
if ($DfsNamespaces.Count -gt 0) {
    Add-Blocker 'DFS Namespaces' 'High' $DfsNamespaces.Count "$($DfsNamespaces.Count) domain-based DFS namespace(s) published in AD." 'Recreate namespaces in the target domain or convert to stand-alone. Update GPO drive maps and logon scripts.'
}
if ($PrintQueues.Count -gt 0) {
    Add-Blocker 'Published Printers' 'High' $PrintQueues.Count "$($PrintQueues.Count) printQueue object(s) published in AD." 'Migrate print servers / Universal Print. AD publication is removed when the domain goes away.'
}

if ($DelegationAccounts.Count -gt 0) {
    Add-Blocker 'Kerberos Delegation' 'Medium' $DelegationAccounts.Count "$($DelegationAccounts.Count) unconstrained or protocol-transition delegation account(s). RBCD objects: $($RbcdAccounts.Count)." 'Rebuild SPNs and delegation (prefer RBCD) in the target domain. Unconstrained delegation on SQL/IIS is a common break during domain moves.'
}
if ($SPNDuplicates.Count -gt 0) {
    Add-Blocker 'Duplicate SPNs' 'Medium' $SPNDuplicates.Count "$($SPNDuplicates.Count) duplicate SPN assignment(s)." 'Fix now with setspn -X / setspn -D. Duplicates cause Kerberos to fail in both the old and new domains.'
}
if ($DnsZones.Count -gt 0) {
    Add-Blocker 'DNS Zones' 'Medium' $DnsZones.Count "$($DnsZones.Count) AD-integrated zone(s) across DomainDnsZones / ForestDnsZones / domain NC. Locator SRV nodes captured: $($LocatorRecords.Count)." 'Move zones to the surviving DNS. Keep _msdcs/legacy locator records only until the last DC is demoted, then delete them so clients stop locating this domain.'
}
if ($SysvolState -match 'NTFRS|FRS|Start|Prepared|Redirected') {
    Add-Blocker 'SYSVOL Replication' 'Medium' 1 "SYSVOL state: $SysvolState ($SysvolSource). $SysvolDetail" 'Complete DFSR migration (dfsrmig /setGlobalState 3) and confirm every DC is Eliminated before demotion. FRS + Server 2022+ is unsupported.'
}
$ReplErrors = @($ReplPartners | Where-Object { $_.HealthStatus -eq 'ERROR' })
if ($ReplErrors.Count -gt 0) {
    Add-Blocker 'Replication Errors' 'Medium' $ReplErrors.Count "$($ReplErrors.Count) replication partnership(s) in ERROR. Failure objects: $($ReplFailures.Count)." 'Do not demote DCs with lingering replication errors. Use repadmin /replsummary, dcdiag /test:replications, and resolve USN rollback / RPC 1722 first.'
}
if ($BitLockerCount -gt 0) {
    Add-Blocker 'BitLocker Recovery Passwords' 'Medium' $BitLockerCount "$BitLockerCount msFVE-RecoveryInformation object(s) stored under computer accounts." 'Export recovery passwords (Get-ADObject msFVE-RecoveryInformation or MBAM/Intune). Once the domain is gone those passwords are gone with it.'
}
if ($LapsCount -gt 0) {
    Add-Blocker 'LAPS Passwords' 'Medium' $LapsCount "$LapsCount computer(s) have ms-Mcs-AdmPwd populated." 'Rotate local admin passwords into Windows LAPS in the target domain / Intune before this directory is destroyed.'
}
if ($SccmContainers.Count -gt 0) {
    Add-Blocker 'ConfigMgr / SCCM' 'Medium' $SccmContainers.Count 'System Management container is present — ConfigMgr (or a similar product) published management points in this domain.' 'Reassign clients, remove the System Management container only after site decommission per ConfigMgr docs.'
}
if ($AppPartitions.Count -gt 0) {
    Add-Blocker 'Application Partitions' 'Medium' $AppPartitions.Count "Extra naming contexts: $([string]::Join(', ', $AppPartitions)). DomainDnsZones/ForestDnsZones are expected; anything else is a custom app partition that must be removed or migrated." 'Use ntdsutil / domain.msc to delete custom app partitions after the application is migrated. DNS partitions disappear with the last DC that hosts them.'
}

if ($StaleUsers.Count -gt 0) {
    Add-Blocker 'Stale Enabled Users' 'Low' $StaleUsers.Count "$($StaleUsers.Count) enabled user(s) with a logon older than $StaleDays days (separate from $($NeverUsers.Count) never-logged-on)." 'Disable after owner sign-off. Do not treat Never as Stale — those may be newly provisioned or break-glass.'
}
if ($StaleComputers.Count -gt 0) {
    Add-Blocker 'Stale Computers' 'Low' $StaleComputers.Count "$($StaleComputers.Count) enabled computer(s) with no LastLogon or PasswordLastSet in $StaleDays days." 'Confirm they are powered off, then disable. PasswordLastSet is used because LastLogonDate on computers is often empty even when the machine is healthy.'
}
if ($NeverUsers.Count -gt 0) {
    Add-Blocker 'Never-Logged-On Users' 'Low' $NeverUsers.Count "$($NeverUsers.Count) enabled user(s) have no lastLogonTimestamp at all." 'Often unused provisioned accounts, or accounts that only authenticate against a DC this script did not query. Use -AccurateLastLogon to be sure.'
}
if ($NoPreauthUsers.Count -gt 0) {
    Add-Blocker 'Kerberos Pre-auth Disabled' 'Low' $NoPreauthUsers.Count "$($NoPreauthUsers.Count) account(s) have DONT_REQ_PREAUTH (AS-REP roastable)." 'Fix before any lingering trust period; these are high-value attack paths while the domain still exists.'
}
if ($LogonScriptUsers.Count -gt 0 -or $HomeDirUsers.Count -gt 0) {
    Add-Blocker 'Logon Scripts / Home Folders' 'Low' ($LogonScriptUsers.Count + $HomeDirUsers.Count) "$($LogonScriptUsers.Count) logon script(s), $($HomeDirUsers.Count) homeDirectory, $($ProfileUsers.Count) profilePath." 'Rewrite GPO logon scripts / Folder Redirection / home shares in the target domain. UNC paths to this domain DFS namespace will break at cutover.'
}
if ($FspCount -gt 0) {
    Add-Blocker 'Foreign Security Principals' 'Low' $FspCount "$FspCount FSP object(s) — other domains still appear in groups here." 'Each FSP is a cross-domain ACL/group dependency. Resolve before the trust is deleted.'
}
if ($SitesWithoutDCs.Count -gt 0) {
    Add-Blocker 'Sites Without DCs' 'Low' $SitesWithoutDCs.Count "$($SitesWithoutDCs.Count) site(s) have no DC in this domain. Clients there may be using remote DCs or another domain." 'Update subnet-to-site mapping in the surviving forest so logons still work after demotion.'
}

$CritCount = @($Blockers | Where-Object { $_.Severity -eq 'Critical' }).Count
$HighCount = @($Blockers | Where-Object { $_.Severity -eq 'High' }).Count
$MedCount  = @($Blockers | Where-Object { $_.Severity -eq 'Medium' }).Count
$LowCount  = @($Blockers | Where-Object { $_.Severity -eq 'Low' }).Count
$TotalWeight = ($CritCount * 25) + ($HighCount * 10) + ($MedCount * 4) + ($LowCount * 1)
$ReadyPct = [math]::Max(0, [math]::Min(100, (100 - $TotalWeight)))
$ReadyLabel = if ($ReadyPct -ge 80) { 'Near Ready' } elseif ($ReadyPct -ge 50) { 'In Progress' } elseif ($ReadyPct -ge 20) { 'Early Stage' } else { 'Not Ready' }
$ReadyColor = if ($ReadyPct -ge 80) { '#22c55e' } elseif ($ReadyPct -ge 50) { '#f59e0b' } elseif ($ReadyPct -ge 20) { '#f97316' } else { '#ef4444' }

$Phase1 = @($Blockers | Where-Object { $_.Severity -eq 'Critical' })
$Phase2 = @($Blockers | Where-Object { $_.Severity -eq 'High' })
$Phase3 = @($Blockers | Where-Object { $_.Severity -in @('Medium', 'Low') })

function Get-BlockerRows {
    param([object[]]$Items, [string]$Phase)
    if ($null -eq $Items -or $Items.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $Items) {
        $sev = Format-SeverityBadge $b.Severity
        $safeDetail = ConvertTo-HtmlEncoded $b.Detail
        $safeRec    = ConvertTo-HtmlEncoded $b.Recommendation
        $safeTitle  = ConvertTo-HtmlEncoded $b.Category
        $plural = if ($b.Count -ne 1) { 's' } else { '' }
        [void]$sb.Append(@"
<div class="blocker-card">
  <div class="blocker-header">
    <span class="blocker-phase">$Phase</span>
    $sev
    <span class="blocker-title">$safeTitle</span>
    <span class="blocker-count">$($b.Count) item$plural</span>
  </div>
  <p class="blocker-detail">$safeDetail</p>
  <div class="blocker-rec"><span class="rec-icon">&#x1F4CB;</span> $safeRec</div>
</div>
"@)
    }
    return $sb.ToString()
}

# ═══════════════════════════════════════════════════════════════════════════════
#  CSV / JSON exports
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host '[24/24] Writing CSV extracts and HTML report...' -ForegroundColor White

$DomainDisplayName = Get-PropText $Domain 'DNSRoot' ''
$ForestDisplayName = Get-PropText $Forest 'Name' ''
if ($DomainDisplayName -eq 'N/A' -or [string]::IsNullOrWhiteSpace($DomainDisplayName)) {
    if ($DomainName) { $DomainDisplayName = $DomainName }
    elseif ($DomainController) { $DomainDisplayName = $DomainController }
    elseif ($DemoMode) { $DomainDisplayName = 'legacy.corp (demo)' }
    else { $DomainDisplayName = '(unknown domain)' }
}

Export-AssessmentCsv 'Users' $UserRows
Export-AssessmentCsv 'Users-Active' $ActiveUsers
Export-AssessmentCsv 'Users-Stale' $StaleUsers
Export-AssessmentCsv 'Users-NeverLoggedOn' $NeverUsers
Export-AssessmentCsv 'Users-ServiceAccounts' $SvcAccounts
Export-AssessmentCsv 'Users-SIDHistory' $UsersWithSIDHistory
Export-AssessmentCsv 'Users-AdminCount' $AdminCountUsers
Export-AssessmentCsv 'Users-LogonScripts' $LogonScriptUsers
Export-AssessmentCsv 'Computers' $ComputerRows
Export-AssessmentCsv 'Computers-Active' $ActiveComputers
Export-AssessmentCsv 'Computers-Stale' $StaleComputers
Export-AssessmentCsv 'Groups' $GroupRows
Export-AssessmentCsv 'Groups-Nested' $NestedGroups
Export-AssessmentCsv 'Groups-PrivilegedMembers' $PrivilegedMembers
Export-AssessmentCsv 'Trusts' $TrustRows
Export-AssessmentCsv 'GPOs' $GPOs
Export-AssessmentCsv 'GPO-Links' $GpoLinkDetail
Export-AssessmentCsv 'DNS-Zones' $DnsZones
Export-AssessmentCsv 'DNS-LocatorRecords' $LocatorRecords
Export-AssessmentCsv 'DHCP' $DhcpServers
Export-AssessmentCsv 'CAs' $CAs
Export-AssessmentCsv 'DomainControllers' $DcRows
Export-AssessmentCsv 'FSMO' $FsmoRows
Export-AssessmentCsv 'Replication' $ReplPartners
Export-AssessmentCsv 'Delegation' $DelegationAccounts
Export-AssessmentCsv 'SPN-Duplicates' $SPNDuplicates
Export-AssessmentCsv 'Sites' $SiteRows
Export-AssessmentCsv 'Subnets' $SubnetRows
Export-AssessmentCsv 'OUs' $OuRows
Export-AssessmentCsv 'Blockers' $Blockers
Export-AssessmentCsv 'ErrorLog' $script:ErrorLog
Export-AssessmentCsv 'ForeignPrincipals' $ForeignPrincipals
Export-AssessmentCsv 'ServiceConnectionPoints' $ServiceConnections
Export-AssessmentCsv 'gMSA' $Gmsa

$summary = [PSCustomObject]@{
    Version            = $script:AssessmentVersion
    Domain             = $DomainDisplayName
    Forest             = $ForestDisplayName
    Generated          = (Get-Date).ToString('o')
    StaleDays          = $StaleDays
    DemoMode           = [bool]$DemoMode
    AccurateLastLogon  = [bool]$AccurateLastLogon
    ReadinessPercent   = $ReadyPct
    ReadinessLabel     = $ReadyLabel
    CriticalBlockers   = $CritCount
    HighBlockers       = $HighCount
    MediumBlockers     = $MedCount
    LowBlockers        = $LowCount
    Users              = $UserRows.Count
    ActiveUsers        = $ActiveUsers.Count
    StaleUsers         = $StaleUsers.Count
    NeverLoggedOnUsers = $NeverUsers.Count
    ServiceAccounts    = $SvcAccounts.Count
    Computers          = $ComputerRows.Count
    ActiveComputers    = $ActiveComputers.Count
    Groups             = $GroupRows.Count
    Trusts             = $TrustRows.Count
    GPOs               = $GPOs.Count
    DCs                = $DcRows.Count
    CAs                = $CAs.Count
    DnsZones           = $DnsZones.Count
    Errors             = $script:ErrorLog.Count
    SysvolState        = $SysvolState
    RecycleBinEnabled  = $RecycleBinEnabled
    SchemaVersion      = $SchemaVersionName
}
if (-not $SkipCsv) {
    $summary | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $ReportRoot 'Summary.json') -Encoding UTF8
}

# ═══════════════════════════════════════════════════════════════════════════════
#  HTML
# ═══════════════════════════════════════════════════════════════════════════════

$Css = @'
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0c10;--bg-s:#111318;--bg-c:#161b22;--bg-h:#1c2330;
  --b:#21262d;--ba:#30363d;
  --tp:#e6edf3;--ts:#8b949e;--tm:#484f58;
  --blue:#58a6ff;--teal:#39d0d0;
  --crit:#ff4d4f;--high:#ff7a00;--med:#f0c040;--low:#52c41a;--ok:#22c55e;
  --sw:250px;--sh:56px;
}
html,body{height:100%;background:var(--bg);color:var(--tp);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.5}
a{color:inherit;text-decoration:none}
.app{display:flex;flex-direction:column;height:100%}
.topbar{position:fixed;top:0;left:0;right:0;height:var(--sh);background:var(--bg-s);border-bottom:1px solid var(--b);display:flex;align-items:center;gap:12px;padding:0 20px;z-index:100;overflow:hidden}
.topbar-logo{display:flex;align-items:center;gap:8px;font-weight:700;font-size:15px;flex-shrink:0}
.topbar-domain{padding:3px 10px;background:var(--bg-c);border:1px solid var(--ba);border-radius:5px;font-family:monospace;font-size:12px;color:var(--blue);flex-shrink:0;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.topbar-date{margin-left:auto;color:var(--tm);font-size:11px;white-space:nowrap}
.topbar-score{display:flex;align-items:center;gap:8px;padding:4px 12px;border-radius:5px;border:1px solid var(--ba);background:var(--bg-c);flex-shrink:0}
.score-lbl{font-size:11px;color:var(--ts)}
.score-val{font-weight:700;font-size:13px}
.body-wrap{display:flex;padding-top:var(--sh);flex:1;overflow:hidden}
.sidebar{width:var(--sw);flex-shrink:0;background:var(--bg-s);border-right:1px solid var(--b);overflow-y:auto;padding:12px 0;position:fixed;top:var(--sh);bottom:0;left:0}
.sidebar-section{padding:8px 16px 4px;font-size:10px;font-weight:600;color:var(--tm);text-transform:uppercase;letter-spacing:.08em}
.sidebar ul{list-style:none}
.nav-link{display:flex;align-items:center;gap:8px;padding:7px 16px;color:var(--ts);transition:all .12s;cursor:pointer;font-size:13px}
.nav-link:hover{color:var(--tp);background:var(--bg-h)}
.nav-link.active{color:var(--blue);background:rgba(88,166,255,.08);border-right:2px solid var(--blue)}
.nav-icon{width:18px;text-align:center;font-size:13px;flex-shrink:0}
.nav-badge{margin-left:auto;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:600}
.nav-badge-neutral{background:var(--bg-h);color:var(--ts)}
.nav-badge-ok{background:rgba(34,197,94,.12);color:#22c55e}
.nav-badge-warn{background:rgba(255,122,0,.12);color:#ff7a00}
.nav-badge-crit{background:rgba(255,77,79,.12);color:#ff4d4f}
.main{margin-left:var(--sw);flex:1;overflow-y:auto;padding:24px}
.section{display:none}
.section.active{display:block}
.page-title{font-size:20px;font-weight:700;margin-bottom:4px}
.page-sub{font-size:13px;color:var(--ts);margin-bottom:20px}
.card{background:var(--bg-c);border:1px solid var(--b);border-radius:8px;padding:16px;margin-bottom:16px}
.card-title{font-size:12px;font-weight:600;color:var(--ts);text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px;display:flex;align-items:center;gap:6px}
.metric-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:12px;margin-bottom:20px}
.metric-card{background:var(--bg-c);border:1px solid var(--b);border-radius:8px;padding:14px;position:relative;overflow:hidden}
.metric-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:var(--ba)}
.metric-crit::before{background:var(--crit)}
.metric-high::before{background:var(--high)}
.metric-med::before{background:var(--med)}
.metric-ok::before{background:var(--ok)}
.metric-label{font-size:11px;color:var(--tm);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
.metric-value{font-size:28px;font-weight:700;line-height:1;color:var(--tp)}
.metric-sub{font-size:11px;color:var(--ts);margin-top:4px}
.metric-crit .metric-value{color:var(--crit)}
.metric-high .metric-value{color:var(--high)}
.metric-med  .metric-value{color:var(--med)}
.metric-ok   .metric-value{color:var(--ok)}
.readiness-section{background:var(--bg-c);border:1px solid var(--b);border-radius:8px;padding:20px;margin-bottom:20px}
.readiness-row{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.readiness-big{font-size:48px;font-weight:800;line-height:1}
.readiness-info{flex:1;min-width:200px}
.readiness-title{font-size:16px;font-weight:600;margin-bottom:4px}
.readiness-desc{font-size:12px;color:var(--ts)}
.progress-bar-wrap{flex:1;min-width:200px}
.progress-track{background:var(--bg-h);border-radius:8px;height:10px;overflow:hidden;margin-bottom:6px}
.progress-fill{height:100%;border-radius:8px}
.progress-labels{display:flex;justify-content:space-between;font-size:10px;color:var(--tm)}
.phase-header{font-size:14px;font-weight:700;padding:12px 0 8px;border-bottom:1px solid var(--b);margin-bottom:12px;display:flex;align-items:center;gap:8px}
.blocker-card{background:var(--bg-s);border:1px solid var(--b);border-radius:6px;padding:14px;margin-bottom:10px}
.blocker-header{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap}
.blocker-phase{font-size:10px;font-weight:600;color:var(--tm);text-transform:uppercase;letter-spacing:.06em}
.blocker-title{font-weight:600;font-size:13px}
.blocker-count{margin-left:auto;font-size:11px;color:var(--tm);background:var(--bg-h);padding:2px 8px;border-radius:10px}
.blocker-detail{font-size:12px;color:var(--ts);margin-bottom:8px}
.blocker-rec{font-size:12px;color:var(--teal);background:rgba(57,208,208,.05);border:1px solid rgba(57,208,208,.12);border-radius:4px;padding:8px 10px;display:flex;gap:6px;align-items:flex-start}
.phase-empty{color:var(--tm);font-style:italic;font-size:13px;padding:12px 0}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.badge-critical{background:rgba(255,77,79,.12);color:#ff4d4f;border:1px solid rgba(255,77,79,.25)}
.badge-high    {background:rgba(255,122,0,.12);color:#ff7a00;border:1px solid rgba(255,122,0,.25)}
.badge-medium  {background:rgba(240,192,64,.12);color:#f0c040;border:1px solid rgba(240,192,64,.25)}
.badge-low     {background:rgba(82,196,26,.12); color:#52c41a;border:1px solid rgba(82,196,26,.25)}
.badge-info    {background:rgba(88,166,255,.12);color:#58a6ff;border:1px solid rgba(88,166,255,.25)}
.table-toolbar{display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap}
.table-search{background:var(--bg-s);border:1px solid var(--ba);border-radius:5px;padding:6px 12px;color:var(--tp);font-size:13px;width:240px;outline:none}
.table-search:focus{border-color:var(--blue)}
.row-count{font-size:11px;color:var(--tm);margin-left:auto}
.btn-csv{background:var(--bg-s);border:1px solid var(--ba);color:var(--ts);border-radius:5px;padding:6px 10px;cursor:pointer;font-size:12px}
.btn-csv:hover{color:var(--tp);border-color:var(--blue)}
.table-wrapper{overflow-x:auto;border-radius:6px;border:1px solid var(--b)}
.data-table{width:100%;border-collapse:collapse;font-size:12px}
.data-table thead{background:var(--bg-s)}
.data-table th{padding:8px 12px;text-align:left;font-size:11px;font-weight:600;color:var(--ts);text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--b);white-space:nowrap;cursor:pointer;user-select:none}
.data-table th:hover{color:var(--tp)}
.sort-arrow{opacity:.4;font-size:9px}
.data-table tbody tr:hover{background:var(--bg-h)}
.data-table td{padding:7px 12px;border-bottom:1px solid var(--b);color:var(--ts);vertical-align:top;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.no-data{color:var(--tm);font-style:italic;font-size:13px;padding:16px 0}
.truncate-note{font-size:12px;color:var(--med);margin-bottom:8px}
.info-table{width:100%;border-collapse:collapse}
.info-table td{padding:8px 12px;border-bottom:1px solid var(--b);font-size:13px;color:var(--ts)}
.info-table td:first-child{color:var(--tm);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;width:240px;white-space:nowrap}
.info-table td:last-child{color:var(--tp);font-family:monospace;font-size:12px}
.tab-bar{display:flex;gap:2px;border-bottom:1px solid var(--b);margin-bottom:16px;flex-wrap:wrap}
.tab-btn{padding:7px 14px;background:none;border:none;border-bottom:2px solid transparent;color:var(--ts);cursor:pointer;font-size:13px;margin-bottom:-1px}
.tab-btn:hover{color:var(--tp)}
.tab-btn.active{color:var(--blue);border-bottom-color:var(--blue)}
.tab-panel{display:none}
.tab-panel.active{display:block}
.check-item{display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--b)}
.check-item:last-child{border-bottom:none}
.check-box{width:18px;height:18px;border-radius:3px;border:1px solid var(--ba);flex-shrink:0;cursor:pointer;display:flex;align-items:center;justify-content:center;margin-top:2px;background:var(--bg)}
.check-box:hover{border-color:var(--blue)}
.check-box.done{background:var(--ok);border-color:var(--ok)}
.check-box.done::after{content:"\2713";color:#000;font-size:11px;font-weight:700}
.check-title{font-size:13px;color:var(--tp);font-weight:500}
.check-desc{font-size:12px;color:var(--tm);margin-top:2px;line-height:1.5}
.chart-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
@media(max-width:900px){.chart-row{grid-template-columns:1fr}}
.bar-row{display:flex;align-items:center;gap:8px;margin:6px 0}
.bar-label{width:140px;font-size:11px;color:var(--ts);flex-shrink:0}
.bar-track{flex:1;background:var(--bg-h);height:10px;border-radius:6px;overflow:hidden}
.bar-fill{height:100%;border-radius:6px}
.bar-val{width:48px;text-align:right;font-size:11px;color:var(--tp);font-variant-numeric:tabular-nums}
.os-legend{display:flex;flex-direction:column;gap:6px;font-size:12px;color:var(--ts)}
.os-swatch{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px}
.alert-box{padding:10px 14px;border-radius:5px;font-size:13px;margin-bottom:12px;border-left:3px solid;line-height:1.6}
.alert-crit{background:rgba(255,77,79,.06);border-color:var(--crit);color:var(--tp)}
.alert-high{background:rgba(255,122,0,.06);border-color:var(--high);color:var(--tp)}
.alert-ok  {background:rgba(34,197,94,.06); border-color:var(--ok);  color:var(--tp)}
code{background:var(--bg-h);padding:1px 5px;border-radius:3px;font-family:monospace;font-size:12px;color:var(--blue)}
.sysvol-status{padding:10px 14px;border-radius:5px;font-family:monospace;font-size:13px;background:var(--bg-s);border:1px solid var(--ba);display:inline-block}
.guidance-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:900px){.guidance-grid{grid-template-columns:1fr}}
.guidance-item{background:var(--bg-s);border:1px solid var(--b);border-radius:6px;padding:12px}
.guidance-label{font-weight:600;color:var(--tp);margin-bottom:6px;font-size:12px}
.guidance-body{font-size:12px;color:var(--ts);line-height:1.5}
.demo-banner{background:rgba(139,92,246,.12);border:1px solid rgba(139,92,246,.35);color:#c4b5fd;padding:10px 14px;border-radius:6px;margin-bottom:16px;font-size:13px}
.note-list{font-size:12px;color:var(--ts);padding-left:18px;margin:8px 0}
.note-list li{margin:4px 0}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-thumb{background:var(--ba);border-radius:3px}
'@

function New-BarChartHtml {
    param($Values, $Colors)
    $max = 1
    foreach ($k in $Values.Keys) { if ([int]$Values[$k] -gt $max) { $max = [int]$Values[$k] } }
    $sb = New-Object System.Text.StringBuilder
    foreach ($k in $Values.Keys) {
        $v = [int]$Values[$k]
        $pct = [math]::Round(($v / $max) * 100, 1)
        $col = '#58a6ff'
        if ($null -ne $Colors) {
            try {
                $c = $Colors[$k]
                if ($c) { $col = [string]$c }
            } catch { }
        }
        [void]$sb.Append("<div class='bar-row'><div class='bar-label'>$(ConvertTo-HtmlEncoded $k)</div><div class='bar-track'><div class='bar-fill' style='width:$pct%;background:$col'></div></div><div class='bar-val'>$v</div></div>")
    }
    return $sb.ToString()
}

$barValues = [ordered]@{
    'Active Users'      = $ActiveUsers.Count
    'Stale Users'       = $StaleUsers.Count
    'Never logged on'   = $NeverUsers.Count
    'Disabled Users'    = $DisabledUsers.Count
    'Active Computers'  = $ActiveComputers.Count
    'Stale Computers'   = $StaleComputers.Count
    'Service Accounts'  = $SvcAccounts.Count
    'Groups w/ members' = $GroupsWithMembers.Count
    'Trusts'            = $TrustRows.Count
}
$barColors = @{
    'Active Users'      = '#ef4444'
    'Stale Users'       = '#f97316'
    'Never logged on'   = '#a78bfa'
    'Disabled Users'    = '#64748b'
    'Active Computers'  = '#22c55e'
    'Stale Computers'   = '#3b82f6'
    'Service Accounts'  = '#ec4899'
    'Groups w/ members' = '#8b5cf6'
    'Trusts'            = '#14b8a6'
}
$BarChartHtml = New-BarChartHtml -Values $barValues -Colors $barColors

$osPalette = @('#58a6ff','#39d0d0','#f59e0b','#ef4444','#8b5cf6','#22c55e','#ec4899','#14b8a6','#f97316','#64748b')
$osTotal = 0
foreach ($o in $OsSummary) { $osTotal += [int]$o.Count }
if ($osTotal -le 0) { $osTotal = 1 }
$OsLegendHtml = ''
$iOs = 0
$stops = @()
$cursorPct = 0.0
foreach ($o in $OsSummary) {
    $col = $osPalette[$iOs % $osPalette.Count]
    $share = [math]::Round((([int]$o.Count) / $osTotal) * 100, 2)
    $next = $cursorPct + $share
    $stops += "$col ${cursorPct}% ${next}%"
    $OsLegendHtml += "<div><span class='os-swatch' style='background:$col'></span>$(ConvertTo-HtmlEncoded $o.Name) — $($o.Count)</div>"
    $cursorPct = $next
    $iOs++
}
if ($stops.Count -eq 0) { $stops = @('#21262d 0% 100%'); $OsLegendHtml = '<div>No OS data</div>' }
$OsDonutCss = [string]::Join(',', $stops)

$UsersTable     = ConvertTo-HtmlTable 'tblUsers'    $UserRows @('Name','SamAccountName','Enabled','Activity','LastLogonDisplay','Mail','PasswordNeverExpires','AdminCount','MemberOfCount','DistinguishedName') 'csv/Users.csv' 'Users'
$ActiveUTable   = ConvertTo-HtmlTable 'tblActUsr'   $ActiveUsers @('Name','SamAccountName','LastLogonDisplay','Mail','Department','DistinguishedName') 'csv/Users-Active.csv'
$StaleUTable    = ConvertTo-HtmlTable 'tblStaleUsr' $StaleUsers @('Name','SamAccountName','Enabled','LastLogonDisplay','DistinguishedName') 'csv/Users-Stale.csv'
$NeverUTable    = ConvertTo-HtmlTable 'tblNeverUsr' $NeverUsers @('Name','SamAccountName','Enabled','WhenCreated','PasswordNotRequired','DistinguishedName') 'csv/Users-NeverLoggedOn.csv'
$SvcTable       = ConvertTo-HtmlTable 'tblSvc'      $SvcAccounts @('Name','SamAccountName','Enabled','LastLogonDisplay','Description','SPNs','PasswordLastSet','DistinguishedName') 'csv/Users-ServiceAccounts.csv'
$SIDHTable      = ConvertTo-HtmlTable 'tblSIDH'     $UsersWithSIDHistory @('Name','SamAccountName','Enabled','SIDHistory','DistinguishedName') 'csv/Users-SIDHistory.csv'
$AdminTable     = ConvertTo-HtmlTable 'tblAdmin'    $AdminCountUsers @('Name','SamAccountName','Enabled','AdminCount','UacFlags','DistinguishedName') 'csv/Users-AdminCount.csv'
$ScriptTable    = ConvertTo-HtmlTable 'tblScripts'  $LogonScriptUsers @('Name','SamAccountName','ScriptPath','HomeDirectory','ProfilePath','DistinguishedName') 'csv/Users-LogonScripts.csv'
$KerberosTable  = ConvertTo-HtmlTable 'tblKerb'     (@($NoPreauthUsers + $PwdNotReqUsers) | Select-Object -Unique) @('Name','SamAccountName','DoNotRequirePreAuth','PasswordNotRequired','ReversibleEncryption','UacFlags','DistinguishedName') ''
$CompsTable     = ConvertTo-HtmlTable 'tblComps'    $ComputerRows @('Name','DNSHostName','Enabled','Activity','LastLogonDisplay','ActivitySource','OperatingSystem','IPv4Address','DistinguishedName') 'csv/Computers.csv' 'Computers'
$ActCmpTable    = ConvertTo-HtmlTable 'tblActCmp'   $ActiveComputers @('Name','DNSHostName','LastLogonDisplay','OperatingSystem','IPv4Address','DistinguishedName') 'csv/Computers-Active.csv'
$StaleCmpTable  = ConvertTo-HtmlTable 'tblStaleCmp' $StaleComputers @('Name','DNSHostName','Enabled','LastLogonDisplay','OperatingSystem','DistinguishedName') 'csv/Computers-Stale.csv'
$OsTable        = ConvertTo-HtmlTable 'tblOS'       $OsSummary @('Name','Count')
$SrvTable       = ConvertTo-HtmlTable 'tblSrv'      $ServerComputers @('Name','DNSHostName','OperatingSystem','LastLogonDisplay','Description','DistinguishedName')
$GroupsTable    = ConvertTo-HtmlTable 'tblGroups'   $GroupRows @('Name','SamAccountName','GroupCategory','GroupScope','MemberCount','NestedIn','Description','DistinguishedName') 'csv/Groups.csv' 'Groups'
$NestedTable    = ConvertTo-HtmlTable 'tblNested'   $NestedGroups @('NestedGroup','ChildScope','ChildCategory','ParentGroup','NestedDN','ParentDN') 'csv/Groups-Nested.csv'
$PrivTable      = ConvertTo-HtmlTable 'tblPriv'     $PrivilegedMembers @('Group','Name','SamAccountName','ObjectClass','NestedDepth','DistinguishedName') 'csv/Groups-PrivilegedMembers.csv'
$EmptyGrpTable  = ConvertTo-HtmlTable 'tblEmptyGrp' $EmptyGroups @('Name','SamAccountName','GroupCategory','GroupScope','Description','DistinguishedName')
$TrustsTable    = ConvertTo-HtmlTable 'tblTrusts'   $TrustRows @('Name','Direction','TrustType','ForestTransitive','IntraForest','SelectiveAuthentication','SIDFilteringQuarantined','UsesAESKeys','UsesRC4Encryption','DistinguishedName') 'csv/Trusts.csv' 'Trusts'
$GpoTable       = ConvertTo-HtmlTable 'tblGPO'      $GPOs @('DisplayName','Status','LinkedTo','UserExts','ComputerExts','UserVersion','ComputerVersion','Modified','Description') 'csv/GPOs.csv' 'GPO'
$GpoLinkTable   = ConvertTo-HtmlTable 'tblGpoLink'  $GpoLinkDetail @('GpoId','Target','Enabled','Enforced','Flags') 'csv/GPO-Links.csv'
$DnsTable       = ConvertTo-HtmlTable 'tblDNS'      $DnsZones @('ZoneName','ZoneType','Partition','IsReverse','RecordCount','Created','Modified') 'csv/DNS-Zones.csv' 'DNS'
$LocTable       = ConvertTo-HtmlTable 'tblLoc'      $LocatorRecords @('Zone','HostName','RecordType','Tombstoned') 'csv/DNS-LocatorRecords.csv'
$DhcpTable      = ConvertTo-HtmlTable 'tblDHCP'     $DhcpServers @('DnsName','IPAddress','InTargetDomain','Created','Description') 'csv/DHCP.csv' 'DHCP'
$CaTable        = ConvertTo-HtmlTable 'tblCA'       $CAs @('Name','dNSHostName','whenCreated','certificateTemplates','Description') 'csv/CAs.csv' 'AD CS'
$TmplTable      = ConvertTo-HtmlTable 'tblTmpl'     $CaTemplates @('Name','DisplayName','DistinguishedName')
$AiaTable       = ConvertTo-HtmlTable 'tblAia'      $AiaCdp @('Name','ObjectClass','Container','DistinguishedName')
$OuTable        = ConvertTo-HtmlTable 'tblOU'       $OuRows @('Name','Description','ProtectedFromAccidentalDeletion','DirectUserOrComputerCount','GpoLinks','DistinguishedName') 'csv/OUs.csv' 'OU'
$DCTable        = ConvertTo-HtmlTable 'tblDC'       $DcRows @('HostName','Site','IPv4Address','OperatingSystem','IsGlobalCatalog','IsReadOnly','OperationMasterRoles') 'csv/DomainControllers.csv' 'Domain Controller'
$FsmoTable      = ConvertTo-HtmlTable 'tblFSMO'     $FsmoRows @('Role','Scope','Holder','Notes') 'csv/FSMO.csv'
$ReplTable      = ConvertTo-HtmlTable 'tblRepl'     $ReplPartners @('Server','Partner','HealthStatus','LastReplicationSuccess','ConsecutiveReplicationFailures','LastReplicationResult','Partition') 'csv/Replication.csv' 'Replication'
$FailTable      = ConvertTo-HtmlTable 'tblReplFail' $ReplFailures @('Server','Partner','FailureType','FirstFailureTime','FailureCount','LastError')
$DelgTable      = ConvertTo-HtmlTable 'tblDelg'     $DelegationAccounts @('SamAccountName','ObjectClass','DelegationType','AllowedToDelegateTo','Description','DistinguishedName') 'csv/Delegation.csv'
$RbcdTable      = ConvertTo-HtmlTable 'tblRbcd'     $RbcdAccounts @('SamAccountName','ObjectClass','Description','DistinguishedName')
$SpnTable       = ConvertTo-HtmlTable 'tblSPN'      $SPNDuplicates @('SPN','Account','DN') 'csv/SPN-Duplicates.csv'
$SpnPreTable    = ConvertTo-HtmlTable 'tblSpnPre'   $SpnPrefixSummary @('Prefix','Count')
$SiteTable      = ConvertTo-HtmlTable 'tblSites'    $SiteRows @('Name','Description','DCCount','DistinguishedName') 'csv/Sites.csv' 'Sites'
$SubnetTable    = ConvertTo-HtmlTable 'tblSubnets'  $SubnetRows @('Name','Site','Description','Location','DistinguishedName') 'csv/Subnets.csv'
$LinkTable      = ConvertTo-HtmlTable 'tblSiteLink' $SiteLinkRows @('Name','Cost','IntervalMin','SitesIncluded')
$ErrorLogTable  = ConvertTo-HtmlTable 'tblErrLog'   $script:ErrorLog @('Timestamp','Step','Category','Message','ExceptionType','ScriptLine') 'csv/ErrorLog.csv'
$NoteTable      = ConvertTo-HtmlTable 'tblNotes'    $script:QueryNotes @('Category','Message')
$FspTable       = ConvertTo-HtmlTable 'tblFsp'      $ForeignPrincipals @('Name','Created','MemberOfCount','DistinguishedName') 'csv/ForeignPrincipals.csv'
$GmsaTable      = ConvertTo-HtmlTable 'tblGmsa'     $Gmsa @('Name','SamAccountName','DNSHostName','Enabled','Principals','DistinguishedName') 'csv/gMSA.csv'
$KdsTable       = ConvertTo-HtmlTable 'tblKds'      $KdsRootKeys @('Name','whenCreated','DistinguishedName')
$FgppTable      = ConvertTo-HtmlTable 'tblFgpp'     $Fgpp @('Name','Precedence','MinPasswordLength','MaxPasswordAge','AppliesTo')
$ExchTable      = ConvertTo-HtmlTable 'tblExch'     $ExchangeServers @('Name','Created','DistinguishedName')
$DfsTable       = ConvertTo-HtmlTable 'tblDfs'      $DfsNamespaces @('Name','Servers','DistinguishedName')
$PrnTable       = ConvertTo-HtmlTable 'tblPrn'      $PrintQueues @('Name','Printer','Server','Driver','UNC')
$ScpTable       = ConvertTo-HtmlTable 'tblScp'      $ServiceConnections @('Name','serviceClassName','serviceBindingInformation','keywords','DistinguishedName') 'csv/ServiceConnectionPoints.csv'
$AdfsTable      = ConvertTo-HtmlTable 'tblAdfs'     $AdfsObjects @('Name','ObjectClass','DistinguishedName','Description')
$NpsTable       = ConvertTo-HtmlTable 'tblNps'      $NpsMembers @('Group','Name','SamAccountName','ObjectClass','DistinguishedName')
$EntraTable     = ConvertTo-HtmlTable 'tblEntra'    $EntraConnect @('Name','SamAccountName','Enabled','Description','DistinguishedName')
$SccmTable      = ConvertTo-HtmlTable 'tblSccm'     $SccmContainers @('Name','DistinguishedName')

$DomainSafe = ConvertTo-HtmlEncoded $DomainDisplayName
$ForestSafe = ConvertTo-HtmlEncoded $ForestDisplayName
$StorageKey = 'drAssessment_' + ($DomainDisplayName -replace '[^a-zA-Z0-9]', '_') + '_checklist'

$pp = $PasswordPolicy
$DomainInfoMap = [ordered]@{
    'DNS Root'              = Get-PropText $Domain 'DNSRoot'
    'NetBIOS Name'          = Get-PropText $Domain 'NetBIOSName'
    'Domain SID'            = Get-PropText $Domain 'DomainSID'
    'Domain Mode'           = Get-FunctionalLevelName (Get-Safe $Domain 'DomainMode')
    'Distinguished Name'    = Get-PropText $Domain 'DistinguishedName'
    'Parent Domain'         = Get-PropText $Domain 'ParentDomain'
    'Child Domains'         = Get-PropText $Domain 'ChildDomains'
    'Replica DCs'           = Get-PropText $Domain 'ReplicaDirectoryServers'
    'Users Container'       = Get-PropText $Domain 'UsersContainer'
    'Computers Container'   = Get-PropText $Domain 'ComputersContainer'
    'Deleted Objects'       = Get-PropText $Domain 'DeletedObjectsContainer'
    'Min Password Length'   = Get-PropText $pp 'MinPasswordLength'
    'Max Password Age'      = Get-PropText $pp 'MaxPasswordAge'
    'Password History'      = Get-PropText $pp 'PasswordHistoryCount'
    'Complexity Enabled'    = Get-PropText $pp 'ComplexityEnabled'
    'Lockout Threshold'     = Get-PropText $pp 'LockoutThreshold'
    'Lockout Duration'      = Get-PropText $pp 'LockoutDuration'
    'Reversible Encryption' = Get-PropText $pp 'ReversibleEncryptionEnabled'
    'Tombstone Lifetime'    = $(if ($null -ne $TombstoneDays) { "$TombstoneDays days" } else { 'N/A (assume 60 or 180)' })
    'Recycle Bin'           = $(if ($RecycleBinEnabled) { 'Enabled' } else { 'Not enabled' })
    'RID Next / Remaining'  = $(if ($RidPool) { "$($RidPool.NextRid) / $($RidPool.Remaining) remaining (end $($RidPool.PoolEnd))" } else { 'N/A' })
    'Schema Version'        = $SchemaVersionName
    'Application NCs'       = $(if ($AppPartitions.Count -gt 0) { [string]::Join(', ', $AppPartitions) } else { '(none beyond domain/config/schema)' })
    'KRBTGT Password Age'   = $(if ($null -ne $KrbtgtPasswordAgeDays) { "$KrbtgtPasswordAgeDays days" } else { 'N/A' })
    'UPN Suffixes'          = Get-PropText $Forest 'UPNSuffixes'
    'BitLocker Passwords'   = $BitLockerCount
    'LAPS Computers'        = $LapsCount
    'Hybrid Azure AD Join'  = $HybridJoinCount
}
$ForestInfoMap = [ordered]@{
    'Forest Name'          = Get-PropText $Forest 'Name'
    'Forest Mode'          = Get-FunctionalLevelName (Get-Safe $Forest 'ForestMode')
    'Root Domain'          = Get-PropText $Forest 'RootDomain'
    'Schema Master'        = Get-PropText $Forest 'SchemaMaster'
    'Domain Naming Master' = Get-PropText $Forest 'DomainNamingMaster'
    'Global Catalogs'      = Get-PropText $Forest 'GlobalCatalogs'
    'All Domains'          = Get-PropText $Forest 'Domains'
    'UPN Suffixes'         = Get-PropText $Forest 'UPNSuffixes'
}
$DomainInfoRows = ConvertTo-InfoRows $DomainInfoMap
$ForestInfoRows = ConvertTo-InfoRows $ForestInfoMap

$levelActiveU = if ($ActiveUsers.Count -gt 0) { 'crit' } else { 'ok' }
$levelActiveC = if ($ActiveComputers.Count -gt 0) { 'crit' } else { 'ok' }
$levelSvc     = if ($SvcAccounts.Count -gt 0) { 'crit' } else { 'ok' }
$levelTrust   = if ($TrustRows.Count -gt 0) { 'crit' } else { 'ok' }
$levelCa      = if ($CAs.Count -gt 0) { 'high' } else { 'ok' }
$levelGpo     = if ($GPOs.Count -gt 0) { 'high' } else { 'ok' }
$levelStaleU  = if ($StaleUsers.Count -gt 0) { 'med' } else { 'ok' }
$levelStaleC  = if ($StaleComputers.Count -gt 0) { 'med' } else { 'ok' }

$MetricsHtml = @(
    (New-MetricCard 'Active Users' $ActiveUsers.Count "Last $StaleDays days" $levelActiveU)
    (New-MetricCard 'Active Computers' $ActiveComputers.Count "Logon or machine password" $levelActiveC)
    (New-MetricCard 'Service Accounts' $SvcAccounts.Count 'SPN / svc naming / sync' $levelSvc)
    (New-MetricCard 'Trusts' $TrustRows.Count 'Must be removed' $levelTrust)
    (New-MetricCard 'Certificate Authorities' $CAs.Count 'Requires migration' $levelCa)
    (New-MetricCard 'GPOs' $GPOs.Count "$($UnlinkedGpos.Count) unlinked" $levelGpo)
    (New-MetricCard 'All Users' $UserRows.Count "$($DisabledUsers.Count) disabled")
    (New-MetricCard 'All Computers' $ComputerRows.Count "$($DisabledComputers.Count) disabled")
    (New-MetricCard 'Domain Controllers' $DcRows.Count 'All must be demoted')
    (New-MetricCard 'Groups w/ Members' $GroupsWithMembers.Count "of $($GroupRows.Count) total")
    (New-MetricCard 'Stale Enabled Users' $StaleUsers.Count "No login $StaleDays+ days" $levelStaleU)
    (New-MetricCard 'Never Logged On' $NeverUsers.Count 'Enabled, no timestamp')
    (New-MetricCard 'Stale Computers' $StaleComputers.Count "No auth/password $StaleDays+" $levelStaleC)
    (New-MetricCard 'gMSA / sMSA' $Gmsa.Count "$($KdsRootKeys.Count) KDS key(s)")
    (New-MetricCard 'SID History Users' $UsersWithSIDHistory.Count 'Previous migration leftover')
    (New-MetricCard 'AD FS Objects' ([Math]::Max($AdfsObjects.Count, $AdfsSpnComputers.Count)) 'Federation / DRS')
) -join "`n"

$NavHtml = @"
$(New-NavItem 'dashboard' '&#x2302;' 'Dashboard')
$(New-NavItem 'roadmap' '&#x1F5FA;' 'Retirement Roadmap' ([int]$Blockers.Count) 'nav-badge-warn')
$(New-NavItem 'domain' '&#x1F3E2;' 'Domain &amp; Forest')
$(New-NavItem 'fsmo' '&#x265B;' 'FSMO Roles' ([int]$FsmoRows.Count))
$(New-NavItem 'dcs' '&#x1F5A5;' 'Domain Controllers' ([int]$DcRows.Count))
$(New-NavItem 'users' '&#x1F464;' 'Users' ([int]$UserRows.Count))
$(New-NavItem 'computers' '&#x1F4BB;' 'Computers' ([int]$ComputerRows.Count))
$(New-NavItem 'groups' '&#x1F465;' 'Groups' ([int]$GroupRows.Count))
$(New-NavItem 'trusts' '&#x1F517;' 'Trusts' ([int]$TrustRows.Count) 'nav-badge-warn')
$(New-NavItem 'gpos' '&#x1F4CB;' 'Group Policies' ([int]$GPOs.Count))
$(New-NavItem 'dns' '&#x1F310;' 'DNS Zones' ([int]$DnsZones.Count))
$(New-NavItem 'dhcp' '&#x1F4E1;' 'DHCP' ([int]$DhcpServers.Count))
$(New-NavItem 'certs' '&#x1F510;' 'Certificates / CA' ([int]$CAs.Count) 'nav-badge-warn')
$(New-NavItem 'identity' '&#x1F511;' 'AD FS / Entra / NPS')
$(New-NavItem 'apps' '&#x1F4E6;' 'Apps &amp; Directory Footprint')
$(New-NavItem 'repl' '&#x1F504;' 'Replication' ([int]$ReplPartners.Count))
$(New-NavItem 'spns' '&#x1F3AB;' 'SPNs &amp; Delegation' ([int]$DelegationAccounts.Count) 'nav-badge-warn')
$(New-NavItem 'sites' '&#x1F4CD;' 'Sites &amp; Subnets')
$(New-NavItem 'ous' '&#x1F4C1;' 'Org Units' ([int]$OuRows.Count))
$(New-NavItem 'errorlog' '&#x26A0;' 'Error Log' ([int]$script:ErrorLog.Count) $(if ($script:ErrorLog.Count -gt 0) { 'nav-badge-crit' } else { 'nav-badge-ok' }))
"@

$BlockerRows1 = Get-BlockerRows $Phase1 'Phase 1'
$BlockerRows2 = Get-BlockerRows $Phase2 'Phase 2'
$BlockerRows3 = Get-BlockerRows $Phase3 'Phase 3'

$SysvolAlertHtml = if ($SysvolState -match 'NTFRS|FRS|Start|Prepared|Redirected') {
    New-AlertBox 'crit' "<strong>Action Required:</strong> SYSVOL is not fully on DFSR (<code>$SysvolState</code>, source: $SysvolSource). Complete <code>dfsrmig /setGlobalState 3</code> and confirm Eliminated on every DC before demotion."
} else {
    New-AlertBox 'ok' "SYSVOL state: $(ConvertTo-HtmlEncoded $SysvolState). Source: $(ConvertTo-HtmlEncoded $SysvolSource)."
}
$TrustAlertHtml = if ($TrustRows.Count -gt 0) {
    New-AlertBox 'crit' "<strong>Action Required:</strong> $($TrustRows.Count) trust(s) and $FspCount foreign security principal(s). Identify every cross-domain ACL and LDAP bind before removal."
} else {
    New-AlertBox 'ok' 'No domain trusts detected.'
}
$CaAlertHtml = if ($CAs.Count -gt 0) {
    New-AlertBox 'crit' "<strong>Action Required:</strong> Back up CA database and private keys. Keep HTTP CDP/AIA reachable for remaining certificate lifetimes. $($CaTemplates.Count) template(s), $($AiaCdp.Count) AIA/CDP/KRA object(s)."
} else {
    New-AlertBox 'ok' 'No AD CS enrollment services detected.'
}
$ReplAlertHtml = if ($ReplErrors.Count -gt 0) {
    New-AlertBox 'crit' "Replication errors detected — resolve before any DC demotion."
} else { '' }
$DupSpnAlertHtml = if ($SPNDuplicates.Count -gt 0) {
    New-AlertBox 'crit' "Duplicate SPNs detected. Resolve with <code>setspn -X</code> / <code>setspn -D &lt;spn&gt; &lt;account&gt;</code>."
} else {
    New-AlertBox 'ok' 'No duplicate SPNs detected among user and computer objects loaded in this run.'
}
$DelgAlertHtml = if ($DelegationAccounts.Count -gt 0) {
    New-AlertBox 'crit' 'Migrate SPN and delegation configuration to the target domain for each account below. Unconstrained delegation is the highest risk.'
} else { '' }
$DemoBanner = if ($DemoMode) { '<div class="demo-banner"><strong>Demo mode.</strong> This report is built from synthetic data so the dashboard can be reviewed without a domain. Re-run without <code>-DemoMode</code> against the legacy domain for real numbers.</div>' } else { '' }

$notesHtml = ''
if ($script:QueryNotes.Count -gt 0) {
    $items = ($script:QueryNotes | ForEach-Object { "<li><strong>$(ConvertTo-HtmlEncoded $_.Category):</strong> $(ConvertTo-HtmlEncoded $_.Message)</li>" }) -join ''
    $notesHtml = "<div class='card'><div class='card-title'>Collection notes</div><ul class='note-list'>$items</ul></div>"
}

$checkItems = @(
    @('Confirm AD health', 'Run dcdiag /c /v and repadmin /replsummary. Fix USN rollback, DNS, and RPC errors before any demotion.'),
    @('Inventory LDAP / Kerberos / NTLM applications', 'Packet capture on DCs, IIS app-pool identities, SQL SPNs, Linux SSSD, printers, scanners, PACs, backup software, monitoring.'),
    @('Decide surviving source of authority', 'If this is a child domain, collapsing into the forest root is different from a full forest retirement. Confirm Entra Connect / HR source of authority.'),
    @('Migrate or replace service accounts and gMSA', 'Recreate KDS root key in the target, then gMSAs. Update Windows services, scheduled tasks, IIS, and secret stores.'),
    @('Migrate users (and mailboxes / profiles first)', 'ADMT, cloud sync, or native recreate. Keep SID history until resource ACLs are rewritten, then strip it.'),
    @('Re-join servers, then workstations', 'Validate file servers, SQL, print, RADIUS, and jump hosts first. Update MDM/SCCM last.'),
    @('Recreate required GPOs + WMI filters', 'GPMC backup/restore. Re-check security filtering, GPP credentials, Restricted Groups, and Folder Redirection.'),
    @('Migrate AD CS', 'New CA, new templates, keep old CDP online, export keys, then remove Enrollment Services / AIA / CDP objects via ADSI Edit.'),
    @('Migrate AD FS / Device Registration', 'Move relying parties. Monitor Entra Connect Health for a week after cutover.'),
    @('Rebuild Entra Connect against the surviving directory', 'Do not demote the last DC that the current sync server still uses.'),
    @('Migrate DHCP + DNS', 'Export scopes, update option 006/015, move AD-integrated zones, configure conditional forwarders during overlap.'),
    @('Point RADIUS clients at new NPS', 'Switches, VPN, Wi-Fi. Members of RAS and IAS Servers in this report are the current NPS servers.'),
    @('Migrate DFS namespaces, published printers, BitLocker and LAPS secrets', 'Export recovery passwords and local-admin passwords before computer objects are deleted.'),
    @('Remove trusts only after FSP / SID history is gone', 'Delete from both sides. Confirm name-suffix routing and selective authentication apps.'),
    @('Enable NTLM auditing and fix leftovers', 'Advanced Audit Policy > Account Logon / Logon. Residual NTLM often belongs to scanners and NAS.'),
    @('Finish SYSVOL DFSR migration if needed', 'dfsrmig /getGlobalState must be Eliminated (3) on every DC.'),
    @('Transfer FSMO roles, then demote DCs one at a time', 'PDC emulator last among domain roles. Use Uninstall-ADDSDomainController (graceful), not metadata cleanup unless a DC is dead.'),
    @('Metadata cleanup + DNS scavenger pass', 'Remove NTDS Settings, server objects, FRS/DFSR subscriptions, _msdcs SRV, GC records, and nameserver records.'),
    @('Empty Recycle Bin / wait tombstone lifetime if objects were force-deleted', "Tombstone lifetime is $(if ($TombstoneDays) { $TombstoneDays } else { 180 }) days. Lingering objects appear if another DC is introduced too soon."),
    @('Remove accidental-deletion protection on OUs before bulk cleanup', "$($ProtectedOus.Count) OU(s) are protected in this domain."),
    @('Decommission CA / AD FS / NPS hardware and reclaim IPs', 'Update CMDB, certificates, load balancers, and firewall objects.'),
    @('Archive this report, GPMC backups, CA backups, and change records', 'Keep for audit through certificate and SID-history overlap.')
)
$checkHtml = ''
foreach ($c in $checkItems) {
    $checkHtml += @"
<div class="check-item"><div class="check-box" onclick="toggleCheck(this)"></div><div class="check-text"><div class="check-title">$(ConvertTo-HtmlEncoded $c[0])</div><div class="check-desc">$(ConvertTo-HtmlEncoded $c[1])</div></div></div>
"@
}

$Js = @'
function showSection(id) {
  document.querySelectorAll(".section").forEach(function(s){ s.classList.toggle("active", s.id === id); });
  document.querySelectorAll(".nav-link").forEach(function(l){ l.classList.toggle("active", l.getAttribute("data-section") === id); });
}
document.querySelectorAll(".nav-link").forEach(function(l){
  l.addEventListener("click", function(e){ e.preventDefault(); showSection(l.getAttribute("data-section")); });
});
function sortTable(tableId, th) {
  var table = document.getElementById(tableId);
  if (!table) return;
  var ths = Array.prototype.slice.call(th.parentElement.cells);
  var col = ths.indexOf(th);
  var asc = th.getAttribute("data-asc") !== "true";
  th.setAttribute("data-asc", asc ? "true" : "false");
  ths.forEach(function(t){ var s = t.querySelector(".sort-arrow"); if (s) s.textContent = "\u21D5"; });
  var sa = th.querySelector(".sort-arrow");
  if (sa) sa.textContent = asc ? "\u2191" : "\u2193";
  var rows = Array.prototype.slice.call(table.tBodies[0].rows);
  rows.sort(function(a, b){
    var va = (a.cells[col] && a.cells[col].textContent || "").trim();
    var vb = (b.cells[col] && b.cells[col].textContent || "").trim();
    var na = parseFloat(va), nb = parseFloat(vb);
    if (!isNaN(na) && !isNaN(nb) && va !== "" && vb !== "") return asc ? na - nb : nb - na;
    if (va < vb) return asc ? -1 : 1;
    if (va > vb) return asc ? 1 : -1;
    return 0;
  });
  rows.forEach(function(r){ table.tBodies[0].appendChild(r); });
}
function filterTable(tableId, query) {
  var table = document.getElementById(tableId);
  if (!table) return;
  var q = (query || "").toLowerCase();
  var visible = 0;
  Array.prototype.slice.call(table.tBodies[0].rows).forEach(function(r){
    var match = Array.prototype.slice.call(r.cells).some(function(c){ return c.textContent.toLowerCase().indexOf(q) !== -1; });
    r.style.display = match ? "" : "none";
    if (match) visible++;
  });
  var cnt = document.getElementById("cnt_" + tableId);
  if (cnt) cnt.textContent = visible + " rows";
}
function showTab(btn, panelId) {
  var section = btn.closest(".section");
  section.querySelectorAll(".tab-btn").forEach(function(b){ b.classList.remove("active"); });
  section.querySelectorAll(".tab-panel").forEach(function(p){ p.classList.remove("active"); });
  btn.classList.add("active");
  var panel = document.getElementById(panelId);
  if (panel) panel.classList.add("active");
}
function downloadTableCsv(tableId) {
  var table = document.getElementById(tableId);
  if (!table) return;
  var rows = [];
  function cell(c){ return '"' + String(c.textContent || "").replace(/"/g, '""').trim() + '"'; }
  rows.push(Array.prototype.slice.call(table.tHead.rows[0].cells).map(cell).join(","));
  Array.prototype.slice.call(table.tBodies[0].rows).forEach(function(r){
    if (r.style.display === "none") return;
    rows.push(Array.prototype.slice.call(r.cells).map(cell).join(","));
  });
  var blob = new Blob([rows.join("\r\n")], { type: "text/csv" });
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = tableId + ".csv";
  a.click();
}
var STORAGE_KEY = "__STORAGE_KEY__";
function saveChecklist() {
  var boxes = Array.prototype.slice.call(document.querySelectorAll("#checklistContainer .check-box"));
  localStorage.setItem(STORAGE_KEY, JSON.stringify(boxes.map(function(b){ return b.classList.contains("done"); })));
}
function loadChecklist() {
  try {
    var data = localStorage.getItem(STORAGE_KEY);
    if (!data) return;
    var states = JSON.parse(data);
    var boxes = document.querySelectorAll("#checklistContainer .check-box");
    states.forEach(function(done, i){ if (boxes[i] && done) boxes[i].classList.add("done"); });
  } catch (e) {}
}
function toggleCheck(el) { el.classList.toggle("done"); saveChecklist(); }
loadChecklist();
'@
$Js = $Js.Replace('__STORAGE_KEY__', $StorageKey)

$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Domain Retirement Assessment — $DomainSafe</title>
<style>
$Css
</style>
</head>
<body>
<div class="app">
<header class="topbar">
  <div class="topbar-logo">
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#58a6ff" fill-opacity=".12"/>
      <path d="M12 4L4 8v8l8 4 8-4V8L12 4z" stroke="#58a6ff" stroke-width="1.5" stroke-linejoin="round"/>
    </svg>
    Domain Retirement Assessment
  </div>
  <span class="topbar-domain">$DomainSafe</span>
  <span class="topbar-date">$AssessmentDate &middot; v$($script:AssessmentVersion)</span>
  <div class="topbar-score">
    <span class="score-lbl">Readiness</span>
    <span class="score-val" style="color:$ReadyColor">$ReadyPct% &mdash; $ReadyLabel</span>
  </div>
</header>
<div class="body-wrap">
<nav class="sidebar">
  <div class="sidebar-section">Navigation</div>
  <ul>$NavHtml</ul>
</nav>
<main class="main" id="mainContent">

<section id="dashboard" class="section active">
  <div class="page-title">Executive Dashboard</div>
  <div class="page-sub">Retirement readiness &mdash; <strong>$DomainSafe</strong> &nbsp;&bull;&nbsp; Forest: <strong>$ForestSafe</strong></div>
  $DemoBanner
  <div class="readiness-section">
    <div class="readiness-row">
      <div class="readiness-big" style="color:$ReadyColor">$ReadyPct%</div>
      <div class="readiness-info">
        <div class="readiness-title">Retirement Readiness &mdash; $ReadyLabel</div>
        <div class="readiness-desc">$CritCount critical &nbsp;&bull;&nbsp; $HighCount high &nbsp;&bull;&nbsp; $MedCount medium &nbsp;&bull;&nbsp; $LowCount low blocker(s). This is a work-remaining score, not a health score: a full production domain should be Near Ready only after identities, trusts, CAs, and member servers have actually moved.</div>
      </div>
      <div class="progress-bar-wrap">
        <div class="progress-track"><div class="progress-fill" style="width:$ReadyPct%;background:$ReadyColor"></div></div>
        <div class="progress-labels"><span>0% &mdash; Not Ready</span><span>100% &mdash; Ready</span></div>
      </div>
    </div>
  </div>
  <div class="metric-grid">$MetricsHtml</div>
  <div class="chart-row">
    <div class="card"><div class="card-title">Object summary</div>$BarChartHtml</div>
    <div class="card"><div class="card-title">Operating systems</div>
      <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap">
        <div style="width:140px;height:140px;border-radius:50%;background:conic-gradient($OsDonutCss);flex-shrink:0"></div>
        <div class="os-legend">$OsLegendHtml</div>
      </div>
    </div>
  </div>
  <div class="card">
    <div class="card-title">SYSVOL replication state</div>
    <div class="sysvol-status">$(ConvertTo-HtmlEncoded $SysvolState)$(if ($SysvolDetail) { ' &mdash; ' + (ConvertTo-HtmlEncoded $SysvolDetail) })</div>
    $SysvolAlertHtml
  </div>
  $notesHtml
</section>

<section id="roadmap" class="section">
  <div class="page-title">Retirement Roadmap</div>
  <div class="page-sub">Resolve Phase 1 before Phase 2. Check-list progress is stored in this browser only.</div>
  <div class="card">
    <div class="phase-header"><span style="color:var(--crit)">&#x1F6A8;</span> Phase 1 &mdash; Critical Blockers <span class="badge badge-critical">$($Phase1.Count)</span></div>
    $(if ($BlockerRows1) { $BlockerRows1 } else { '<p class="phase-empty">No critical blockers detected.</p>' })
    <div class="phase-header" style="margin-top:20px"><span style="color:var(--high)">&#x26A0;</span> Phase 2 &mdash; High Priority <span class="badge badge-high">$($Phase2.Count)</span></div>
    $(if ($BlockerRows2) { $BlockerRows2 } else { '<p class="phase-empty">No high-priority blockers detected.</p>' })
    <div class="phase-header" style="margin-top:20px"><span style="color:var(--med)">&#x1F4CC;</span> Phase 3 &mdash; Medium / Low <span class="badge badge-medium">$($Phase3.Count)</span></div>
    $(if ($BlockerRows3) { $BlockerRows3 } else { '<p class="phase-empty">No medium/low blockers detected.</p>' })
  </div>
  <div class="card">
    <div class="card-title">Domain retirement checklist</div>
    <p style="font-size:12px;color:var(--tm);margin-bottom:14px">Click an item to mark it complete. Full datasets for every table are in the <code>csv</code> folder next to this report.</p>
    <div id="checklistContainer">$checkHtml</div>
  </div>
</section>

<section id="domain" class="section">
  <div class="page-title">Domain &amp; Forest</div>
  <div class="page-sub">Functional levels, password policy, RID pool, schema, recycle bin, tombstone lifetime — all required before the last DC is demoted.</div>
  <div class="card"><div class="card-title">Domain details</div><table class="info-table">$DomainInfoRows</table></div>
  <div class="card"><div class="card-title">Forest details</div><table class="info-table">$ForestInfoRows</table></div>
  <div class="card"><div class="card-title">Fine-grained password policies ($($Fgpp.Count))</div>$FgppTable</div>
</section>

<section id="fsmo" class="section">
  <div class="page-title">FSMO Roles</div>
  <div class="page-sub">Transfer every role off this domain&rsquo;s DCs (and off the forest root if you are retiring the forest) before demotion.</div>
  <div class="card"><div class="card-title">Role holders</div>$FsmoTable</div>
</section>

<section id="dcs" class="section">
  <div class="page-title">Domain Controllers</div>
  <div class="page-sub">$($DcRows.Count) DC(s). Demote gracefully. RODCs have a separate PRP that must be cleared.</div>
  <div class="card"><div class="card-title">Domain controllers</div>$DCTable</div>
  <div class="card"><div class="card-title">Replication partnerships ($($ReplPartners.Count))</div>$ReplAlertHtml$ReplTable</div>
  <div class="card"><div class="card-title">Replication failures ($($ReplFailures.Count))</div>$FailTable</div>
</section>

<section id="users" class="section">
  <div class="page-title">User Accounts</div>
  <div class="page-sub">$($UserRows.Count) total &mdash; $($ActiveUsers.Count) active, $($StaleUsers.Count) stale, $($NeverUsers.Count) never logged on, $($SvcAccounts.Count) service-like. LastLogonDate is lastLogonTimestamp (replicated, &plusmn;14 days) unless -AccurateLastLogon was used.</div>
  <div class="tab-bar">
    <button class="tab-btn active" onclick="showTab(this,'tabAllUsers')">All ($($UserRows.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabActiveUsers')">Active ($($ActiveUsers.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabStaleUsers')">Stale ($($StaleUsers.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabNeverUsers')">Never ($($NeverUsers.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabSvcAccts')">Service ($($SvcAccounts.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabSIDH')">SID History ($($UsersWithSIDHistory.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabAdmin')">adminCount ($($AdminCountUsers.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabScripts')">Scripts / Homes ($($LogonScriptUsers.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabKerb')">Kerberos flags</button>
  </div>
  <div id="tabAllUsers" class="tab-panel active">$UsersTable</div>
  <div id="tabActiveUsers" class="tab-panel">$(New-AlertBox 'crit' 'These users have recent logon evidence. Migrate or disable before domain retirement.')$ActiveUTable</div>
  <div id="tabStaleUsers" class="tab-panel">$StaleUTable</div>
  <div id="tabNeverUsers" class="tab-panel">$(New-AlertBox 'high' 'Never-logged-on is not the same as stale. These may be unused, newly created, or authenticating only on a DC that was not queried.')$NeverUTable</div>
  <div id="tabSvcAccts" class="tab-panel">$(New-AlertBox 'crit' 'Classified by SPNs on user objects, gMSA/MSOL/AAD naming, and service descriptions — not a blunt match on the word admin.')$SvcTable</div>
  <div id="tabSIDH" class="tab-panel">$SIDHTable</div>
  <div id="tabAdmin" class="tab-panel">$(New-AlertBox 'high' 'adminCount=1 is stamped by AdminSDHolder/SDProp. Includes current and former privileged users.')$AdminTable</div>
  <div id="tabScripts" class="tab-panel">$(New-AlertBox 'high' 'Logon scripts, home directories, and roaming profiles are UNC dependencies that break when DFS/file servers leave this domain.')$ScriptTable</div>
  <div id="tabKerb" class="tab-panel">$(New-AlertBox 'high' 'DONT_REQ_PREAUTH (AS-REP roast), PASSWD_NOTREQD, and reversible encryption should be cleaned up while the domain still exists.')$KerberosTable</div>
</section>

<section id="computers" class="section">
  <div class="page-title">Computer Accounts</div>
  <div class="page-sub">$($ComputerRows.Count) total &mdash; $($ActiveComputers.Count) active. Activity = the later of LastLogonTimestamp and PasswordLastSet (machine passwords rotate ~30 days on healthy PCs).</div>
  <div class="tab-bar">
    <button class="tab-btn active" onclick="showTab(this,'tabAllComps')">All ($($ComputerRows.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabActiveComps')">Active ($($ActiveComputers.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabStaleComps')">Stale ($($StaleComputers.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabServers')">Servers ($($ServerComputers.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabOS')">By OS</button>
  </div>
  <div id="tabAllComps" class="tab-panel active">$CompsTable</div>
  <div id="tabActiveComps" class="tab-panel">$(New-AlertBox 'crit' 'Re-join these computers to the target domain. ActivitySource tells you whether the signal was a logon or a machine-password rotation.')$ActCmpTable</div>
  <div id="tabStaleComps" class="tab-panel">$StaleCmpTable</div>
  <div id="tabServers" class="tab-panel">$(New-AlertBox 'crit' 'Member servers usually host the workloads that still need this domain.')$SrvTable</div>
  <div id="tabOS" class="tab-panel">$OsTable</div>
</section>

<section id="groups" class="section">
  <div class="page-title">Groups &amp; Privileged Membership</div>
  <div class="page-sub">$($GroupRows.Count) groups &mdash; $($GroupsWithMembers.Count) with members &mdash; $($NestedGroups.Count) nested relationship(s). Counts use reverse memberOf + primaryGroupID (Domain Users is no longer stuck at zero). Privileged groups are resolved by SID so non-English AD still works.</div>
  <div class="tab-bar">
    <button class="tab-btn active" onclick="showTab(this,'tabAllGrp')">All ($($GroupRows.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabPrivGrp')">Privileged ($($PrivilegedMembers.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabNestedGrp')">Nested ($($NestedGroups.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabEmptyGrp')">Empty ($($EmptyGroups.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabFsp')">FSPs ($FspCount)</button>
  </div>
  <div id="tabAllGrp" class="tab-panel active">$(New-AlertBox 'ok' 'Member counts include primary-group members (RID 513/515/516) and nested groups that list this group in memberOf. Foreign members only appear if the FSP object itself has memberOf.')$GroupsTable</div>
  <div id="tabPrivGrp" class="tab-panel">$(New-AlertBox 'crit' 'Nested expansion walks memberOf (depth 8). Get-ADGroupMember is not used here, so FSP/cross-domain failures no longer blank this table.')$PrivTable</div>
  <div id="tabNestedGrp" class="tab-panel">$NestedTable</div>
  <div id="tabEmptyGrp" class="tab-panel">$EmptyGrpTable</div>
  <div id="tabFsp" class="tab-panel">$(New-AlertBox 'high' 'Foreign security principals are users/groups from other domains. They are why trusts cannot be deleted yet.')$FspTable</div>
</section>

<section id="trusts" class="section">
  <div class="page-title">Domain Trusts</div>
  <div class="page-sub">Every trust is a hard blocker. Direction, SID filtering, AES vs RC4, and selective authentication all affect cutover risk.</div>
  $TrustAlertHtml
  <div class="card"><div class="card-title">Trust relationships ($($TrustRows.Count))</div>$TrustsTable</div>
</section>

<section id="gpos" class="section">
  <div class="page-title">Group Policy Objects</div>
  <div class="page-sub">$($GPOs.Count) GPO(s), $($UnlinkedGpos.Count) unlinked, $($WmiFilters.Count) WMI filter(s). Links include domain, OUs, <strong>and sites</strong>. Enabled/enforced parsed from gpLink flags.</div>
  <div class="card"><div class="card-title">GPOs</div>$GpoTable</div>
  <div class="card"><div class="card-title">GPO links</div>$GpoLinkTable</div>
  <div class="card"><div class="card-title">WMI filters ($($WmiFilters.Count))</div>$(ConvertTo-HtmlTable 'tblWmi' $WmiFilters @('Name','Description','WQL','Created','DistinguishedName'))</div>
</section>

<section id="dns" class="section">
  <div class="page-title">DNS Zones</div>
  <div class="page-sub">AD-integrated zones from DomainDnsZones, ForestDnsZones, and CN=MicrosoftDNS,CN=System. File-backed (non-AD) zones on a DNS server will not appear — check those hosts separately. Locator / _msdcs records must be removed after the last DC is demoted or clients keep finding this domain.</div>
  <div class="card"><div class="card-title">Zones ($($DnsZones.Count))</div>$DnsTable</div>
  <div class="card"><div class="card-title">Locator / SRV-like nodes ($($LocatorRecords.Count))</div>$LocTable</div>
</section>

<section id="dhcp" class="section">
  <div class="page-title">DHCP Servers</div>
  <div class="page-sub">Every authorised DHCP server in the forest configuration NC. InTargetDomain is a hint, not a filter — a server in another domain can still hand out leases to this one.</div>
  <div class="card"><div class="card-title">Authorised DHCP ($($DhcpServers.Count))</div>$DhcpTable</div>
</section>

<section id="certs" class="section">
  <div class="page-title">Certificate Authorities / AD CS</div>
  <div class="page-sub">Keep CDP/AIA reachable for as long as issued certificates remain valid.</div>
  $CaAlertHtml
  <div class="card"><div class="card-title">Enrollment services ($($CAs.Count))</div>$CaTable</div>
  <div class="card"><div class="card-title">Certificate templates ($($CaTemplates.Count))</div>$TmplTable</div>
  <div class="card"><div class="card-title">AIA / CDP / KRA / OID objects ($($AiaCdp.Count))</div>$AiaTable</div>
</section>

<section id="identity" class="section">
  <div class="page-title">AD FS, Entra Connect, NPS</div>
  <div class="page-sub">Federation, directory sync, and RADIUS are the identity services that most often survive &ldquo;we already moved the users.&rdquo;</div>
  <div class="card"><div class="card-title">AD FS directory objects ($($AdfsObjects.Count)) &middot; computers with ADFS SPNs: $($AdfsSpnComputers.Count)</div>$AdfsTable</div>
  <div class="card"><div class="card-title">Entra Connect / MSOL / AAD accounts ($($EntraConnect.Count))</div>$EntraTable</div>
  <div class="card"><div class="card-title">RAS and IAS Servers / NPS ($($NpsMembers.Count))</div>$NpsTable</div>
  <div class="card"><div class="card-title">gMSA / sMSA ($($Gmsa.Count))</div>$GmsaTable</div>
  <div class="card"><div class="card-title">KDS root keys ($($KdsRootKeys.Count))</div>$KdsTable</div>
</section>

<section id="apps" class="section">
  <div class="page-title">Application footprint</div>
  <div class="page-sub">Directory objects that mean an application still depends on this domain. BitLocker $BitLockerCount &middot; LAPS $LapsCount &middot; Hybrid join $HybridJoinCount.</div>
  <div class="card"><div class="card-title">Exchange servers ($($ExchangeServers.Count))</div>$ExchTable</div>
  <div class="card"><div class="card-title">ConfigMgr System Management ($($SccmContainers.Count))</div>$SccmTable</div>
  <div class="card"><div class="card-title">DFS namespaces ($($DfsNamespaces.Count))</div>$DfsTable</div>
  <div class="card"><div class="card-title">Published printers ($($PrintQueues.Count))</div>$PrnTable</div>
  <div class="card"><div class="card-title">Service connection points (sample) ($($ServiceConnections.Count))</div>$ScpTable</div>
</section>

<section id="repl" class="section">
  <div class="page-title">Replication &amp; SYSVOL</div>
  <div class="page-sub">Replication must be clean before demotion. SYSVOL state is read from AD (<code>msDFSR-Flags</code>), not from the workstation you happened to run the script on.</div>
  <div class="card"><div class="card-title">Partnerships ($($ReplPartners.Count))</div>$ReplAlertHtml$ReplTable</div>
  <div class="card"><div class="card-title">Failures ($($ReplFailures.Count))</div>$FailTable</div>
  <div class="card"><div class="card-title">SYSVOL</div>
    <div class="sysvol-status">$(ConvertTo-HtmlEncoded $SysvolState)</div>
    $SysvolAlertHtml
  </div>
</section>

<section id="spns" class="section">
  <div class="page-title">SPNs &amp; Kerberos Delegation</div>
  <div class="page-sub">Unconstrained delegation, protocol transition, RBCD, and duplicate SPNs all break or become attack paths during a move.</div>
  <div class="tab-bar">
    <button class="tab-btn active" onclick="showTab(this,'tabDelg')">Delegation ($($DelegationAccounts.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabRbcd')">RBCD ($($RbcdAccounts.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabDupSpn')">Duplicate SPNs ($($SPNDuplicates.Count))</button>
    <button class="tab-btn" onclick="showTab(this,'tabSpnPre')">SPN prefixes</button>
  </div>
  <div id="tabDelg" class="tab-panel active">$DelgAlertHtml$DelgTable</div>
  <div id="tabRbcd" class="tab-panel">$RbcdTable</div>
  <div id="tabDupSpn" class="tab-panel">$DupSpnAlertHtml$SpnTable</div>
  <div id="tabSpnPre" class="tab-panel">$(New-AlertBox 'ok' 'HOST/RestrictedKrbHost/TERMSRV are normal. HTTP, MSSQLSvc, CIFS, DNS, and custom prefixes are application dependencies to migrate.')$SpnPreTable</div>
</section>

<section id="sites" class="section">
  <div class="page-title">AD Sites &amp; Subnets</div>
  <div class="page-sub">$($SiteRows.Count) site(s), $($SitesWithoutDCs.Count) with no DC, $($SubnetsWithoutSite.Count) subnet(s) not assigned to a site. Clients in those subnets will fail over unpredictably once this domain&rsquo;s DCs are gone.</div>
  <div class="card"><div class="card-title">Sites</div>$SiteTable</div>
  <div class="card"><div class="card-title">Subnets</div>$SubnetTable</div>
  <div class="card"><div class="card-title">Site links</div>$LinkTable</div>
</section>

<section id="ous" class="section">
  <div class="page-title">Organizational Units</div>
  <div class="page-sub">$($OuRows.Count) OU(s), $($ProtectedOus.Count) protected from accidental deletion (must be turned off before bulk delete).</div>
  <div class="card"><div class="card-title">OUs</div>$OuTable</div>
</section>

<section id="errorlog" class="section">
  <div class="page-title">Error Log &amp; Collection Notes</div>
  <div class="page-sub">$($script:ErrorLog.Count) error(s), $($script:QueryNotes.Count) note(s). Failed queries now show as failures instead of looking like empty inventory.</div>
  $(if ($script:ErrorLog.Count -eq 0) { New-AlertBox 'ok' '<strong>Clean run.</strong> No terminating query errors were recorded.' } else { New-AlertBox 'high' "<strong>$($script:ErrorLog.Count) error(s)</strong> — tables for those categories may be incomplete." })
  <div class="card"><div class="card-title">Query errors</div>$ErrorLogTable</div>
  <div class="card"><div class="card-title">Collection notes</div>$NoteTable</div>
  <div class="card">
    <div class="card-title">Common causes</div>
    <div class="guidance-grid">
      <div class="guidance-item"><div class="guidance-label">Access denied</div><div class="guidance-body">Use a Domain Admin or pass <code>-Credential (Get-Credential)</code>. Configuration and schema NCs need read access too.</div></div>
      <div class="guidance-item"><div class="guidance-label">DC unreachable</div><div class="guidance-body"><code>Test-NetConnection &lt;DC&gt; -Port 389</code>. LDAP 389, LDAPS 636, RPC 135, and ADWS 9389.</div></div>
      <div class="guidance-item"><div class="guidance-label">RSAT missing</div><div class="guidance-body"><code>Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0</code></div></div>
      <div class="guidance-item"><div class="guidance-label">Stale vs never vs active</div><div class="guidance-body">LastLogonDate is lastLogonTimestamp (replicated, 9–14 day lag). Computers also use PasswordLastSet. Use <code>-AccurateLastLogon</code> to query lastLogon on every DC.</div></div>
      <div class="guidance-item"><div class="guidance-label">Empty privileged groups</div><div class="guidance-body">Earlier builds looked up &quot;Domain Admins&quot; by English name. This build uses well-known SIDs so localized AD still populates the table.</div></div>
      <div class="guidance-item"><div class="guidance-label">Group counts stuck at 0</div><div class="guidance-body">The member attribute omits primary-group members and truncates at 1500. Counts now come from memberOf + primaryGroupID.</div></div>
    </div>
  </div>
</section>

</main>
</div>
</div>
<script>
$Js
</script>
</body>
</html>
"@

$HtmlPath = Join-Path $ReportRoot 'DomainRetirementAssessment.html'
$ErrLogPath = Join-Path $ReportRoot 'ErrorLog.txt'
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($HtmlPath, $HTML, $utf8Bom)

if ($script:ErrorLog.Count -gt 0) {
    $errLines = New-Object System.Collections.Generic.List[string]
    [void]$errLines.Add('Domain Retirement Assessment — Error Log')
    [void]$errLines.Add("Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$errLines.Add("Target    : $(if ($DomainController) { $DomainController } elseif ($DomainName) { $DomainName } elseif ($DemoMode) { 'DEMO' } else { '(default discovery)' })")
    [void]$errLines.Add("Errors    : $($script:ErrorLog.Count)")
    [void]$errLines.Add(('=' * 80))
    foreach ($e in $script:ErrorLog) {
        [void]$errLines.Add('')
        [void]$errLines.Add("Timestamp  : $($e.Timestamp)")
        [void]$errLines.Add("Step       : $($e.Step)")
        [void]$errLines.Add("Category   : $($e.Category)")
        [void]$errLines.Add("Type       : $($e.ExceptionType)")
        [void]$errLines.Add("Message    : $($e.Message)")
        [void]$errLines.Add("Script     : $($e.ScriptLine)")
        [void]$errLines.Add(('-' * 80))
    }
    [System.IO.File]::WriteAllLines($ErrLogPath, $errLines.ToArray(), $utf8Bom)
}

Write-Host ''
Write-Host '╔══════════════════════════════════════════════════════════╗' -ForegroundColor Green
Write-Host '║              Assessment complete                         ║' -ForegroundColor Green
Write-Host '╚══════════════════════════════════════════════════════════╝' -ForegroundColor Green
Write-Host ''
Write-Host "Report : $HtmlPath" -ForegroundColor Cyan
if (-not $SkipCsv) { Write-Host "CSVs   : $script:CsvDir" -ForegroundColor Cyan }
Write-Host "Readiness : $ReadyPct% — $ReadyLabel" -ForegroundColor White
Write-Host "  Critical : $CritCount" -ForegroundColor $(if ($CritCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "  High     : $HighCount" -ForegroundColor $(if ($HighCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  Medium   : $MedCount" -ForegroundColor $(if ($MedCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  Low      : $LowCount" -ForegroundColor $(if ($LowCount -gt 0) { 'White' } else { 'Green' })
if ($script:ErrorLog.Count -gt 0) {
    Write-Host "Errors    : $($script:ErrorLog.Count) — $ErrLogPath" -ForegroundColor Red
} else {
    Write-Host 'Errors    : None' -ForegroundColor Green
}
Write-Host ''
Write-Host 'Open:  Start-Process' $HtmlPath -ForegroundColor White

if (-not $NoLaunch -and -not $DemoMode) {
    try { Invoke-Item -Path $HtmlPath -ErrorAction SilentlyContinue } catch { }
}

if ($DemoMode) {
    Write-Host 'DemoMode: HTML generated; not launching a browser from this host by default.' -ForegroundColor DarkGray
}

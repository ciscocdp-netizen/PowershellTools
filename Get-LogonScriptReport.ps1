#Requires -Version 5.1
<#
.SYNOPSIS
    Finds all Active Directory users with a Logon Script defined in their user profile
    and generates a self-contained HTML dashboard report with analytics.

.DESCRIPTION
    This script queries Active Directory for all user accounts that have a ScriptPath
    (logon script) configured. It generates analytics including:
      - Total users with logon scripts
      - Unique scripts in use (paths are normalised so casing / slash differences merge)
      - Script usage distribution
      - Per-user details (username, display name, OU, last logon, enabled status, script path)

    Output is a single self-contained HTML file with embedded CSS, JavaScript, and Chart.js.
    The dashboard supports live filtering, sorting, and CSV export.

    Filtering (v2.0) is designed to return accurate results:
      - Script paths are JSON-escaped (not HTML-escaped) so Windows backslashes stay intact
      - Path comparison is case-insensitive and treats \ and / as equivalent
      - Search supports AND tokens, quoted phrases, -exclusions, and field prefixes
        (sam:, display:, script:, dept:, ou:, title:, status:, logon:)
      - Dropdowns can filter by specific path, file name (any path), OU, department,
        account status, and last-logon age
      - The match banner, chips, table, and "users of selected script" list all share
        the same filter engine so the counts cannot drift apart

.PARAMETER OutputPath
    Path where the HTML report will be saved.
    Defaults to a file-picker (interactive) or Get-LogonScriptReport_<timestamp>.html

.PARAMETER SearchBase
    The Distinguished Name of the OU to search. Defaults to the entire domain.

.PARAMETER IncludeDisabledUsers
    Switch to include disabled user accounts in the results (excluded by default).

.PARAMETER Server
    Specify a domain controller to query. Defaults to automatic DC discovery.

.PARAMETER DemoMode
    Generate a synthetic report without querying Active Directory. Useful for testing
    the dashboard filters (covers paths with \users, \temp, mixed slashes, etc.).

.PARAMETER NoLaunch
    Do not open the generated HTML file in the default browser.

.EXAMPLE
    .\Get-LogonScriptReport.ps1
    Searches entire domain, exports enabled users only, saves HTML to script directory.

.EXAMPLE
    .\Get-LogonScriptReport.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -IncludeDisabledUsers
    Searches a specific OU including disabled users.

.EXAMPLE
    .\Get-LogonScriptReport.ps1 -OutputPath "C:\Reports\LogonScripts.html" -Server "DC01"
    Saves to a custom path and queries a specific domain controller.

.EXAMPLE
    .\Get-LogonScriptReport.ps1 -DemoMode -OutputPath ".\LogonScripts-Demo.html"
    Builds a demo dashboard with synthetic users so filters can be verified offline.

.NOTES
    Author      : v0 / Vercel
    Version     : 2.0
    Requires    : ActiveDirectory PowerShell Module (RSAT) — not required in -DemoMode
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
    [switch]$DemoMode,

    [Parameter(Mandatory = $false)]
    [switch]$NoLaunch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helper Functions ─────────────────────────────────────────────────────

function Write-Header {
    param([string]$Text)
    $line = '-' * 70
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

function Convert-ADDateToString {
    param($DateValue)
    if ($null -eq $DateValue) { return 'Never' }
    try {
        $dt = $null
        if ($DateValue -is [DateTime]) {
            $dt = $DateValue
        }
        else {
            $dt = [DateTime]::FromFileTime([int64]$DateValue)
        }
        if ($dt -eq [DateTime]::MinValue -or $dt.Year -lt 1970) { return 'Never' }
        return $dt.ToString('yyyy-MM-dd HH:mm')
    }
    catch {
        return 'Unknown'
    }
}

function Convert-DateToUnixMs {
    param($DateValue)
    if ($null -eq $DateValue) { return [int64]0 }
    try {
        $dt = $null
        if ($DateValue -is [DateTime]) {
            $dt = $DateValue
        }
        else {
            $dt = [DateTime]::FromFileTime([int64]$DateValue)
        }
        if ($dt -eq [DateTime]::MinValue -or $dt.Year -lt 1970) { return [int64]0 }
        $utc = if ($dt.Kind -eq [DateTimeKind]::Utc) { $dt } else { $dt.ToUniversalTime() }
        $epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
        return [int64]($utc - $epoch).TotalMilliseconds
    }
    catch {
        return [int64]0
    }
}

function Get-OUFromDN {
    param([string]$DistinguishedName)
    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return 'N/A' }
    $parts = $DistinguishedName -split ',', 2
    if ($parts.Count -gt 1) { return $parts[1] }
    return $DistinguishedName
}

function Get-OuShortName {
    param([string]$OuDn)
    if ([string]::IsNullOrWhiteSpace($OuDn)) { return 'N/A' }
    $first = ($OuDn -split ',', 2)[0]
    return ($first -replace '^(OU|CN|DC)=', '')
}

function Get-NormalizedScriptPath {
    <#
    .SYNOPSIS
        Canonical form used for grouping and filtering.
        Case-insensitive, slash-normalised, UNC-safe.
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $p = $Path.Trim().Replace('/', '\')
    $prefix = ''
    if ($p.StartsWith('\\')) {
        $prefix = '\\'
        $p = $p.Substring(2)
    }
    while ($p.Contains('\\')) {
        $p = $p.Replace('\\', '\')
    }
    $p = $p.TrimEnd('\')
    return ($prefix + $p).ToLowerInvariant()
}

function Get-ScriptFileName {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $normalized = $Path.Trim().Replace('/', '\')
    $leaf = $normalized
    $idx = $normalized.LastIndexOf('\')
    if ($idx -ge 0 -and $idx -lt ($normalized.Length - 1)) {
        $leaf = $normalized.Substring($idx + 1)
    }
    return $leaf
}

function Escape-JsonString {
    <#
    .SYNOPSIS
        RFC-compliant JSON string escaping for injection into a <script> tag.
        Unlike HTML escaping, this preserves Windows path backslashes as \\ so
        JS does not treat \n, \t, \u, \b, \r, \f as control characters.
    #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    $sb = New-Object System.Text.StringBuilder ($s.Length * 2)
    foreach ($ch in $s.ToCharArray()) {
        $code = [int]$ch
        if ($code -eq 34) {
            [void]$sb.Append('\"')
        }
        elseif ($code -eq 92) {
            [void]$sb.Append('\\')
        }
        elseif ($code -eq 8) {
            [void]$sb.Append('\b')
        }
        elseif ($code -eq 9) {
            [void]$sb.Append('\t')
        }
        elseif ($code -eq 10) {
            [void]$sb.Append('\n')
        }
        elseif ($code -eq 12) {
            [void]$sb.Append('\f')
        }
        elseif ($code -eq 13) {
            [void]$sb.Append('\r')
        }
        elseif ($code -lt 32 -or $code -eq 0x2028 -or $code -eq 0x2029 -or $code -eq 60 -or $code -eq 62 -or $code -eq 38) {
            # < > & are \u-escaped so a value can never close the <script> tag
            [void]$sb.Append('\u')
            [void]$sb.Append($code.ToString('x4'))
        }
        else {
            [void]$sb.Append($ch)
        }
    }
    return $sb.ToString()
}

function ConvertTo-UserDataJson {
    param([System.Collections.Generic.List[hashtable]]$Data)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('[')
    $first = $true
    foreach ($row in $Data) {
        if (-not $first) { [void]$sb.Append(',') } else { $first = $false }
        $enabled = if ($row.Enabled) { 'true' } else { 'false' }
        $locked  = if ($row.LockedOut) { 'true' } else { 'false' }
        $pne     = if ($row.PasswordNeverExpires) { 'true' } else { 'false' }
        $ts      = if ($null -eq $row.LastLogonTs) { '0' } else { [string][int64]$row.LastLogonTs }
        [void]$sb.Append('{"sam":"')
        [void]$sb.Append((Escape-JsonString $row.SamAccountName))
        [void]$sb.Append('","display":"')
        [void]$sb.Append((Escape-JsonString $row.DisplayName))
        [void]$sb.Append('","upn":"')
        [void]$sb.Append((Escape-JsonString $row.UserPrincipalName))
        [void]$sb.Append('","email":"')
        [void]$sb.Append((Escape-JsonString $row.EmailAddress))
        [void]$sb.Append('","ou":"')
        [void]$sb.Append((Escape-JsonString $row.OU))
        [void]$sb.Append('","ouShort":"')
        [void]$sb.Append((Escape-JsonString $row.OuShort))
        [void]$sb.Append('","script":"')
        [void]$sb.Append((Escape-JsonString $row.ScriptPath))
        [void]$sb.Append('","scriptName":"')
        [void]$sb.Append((Escape-JsonString $row.ScriptName))
        [void]$sb.Append('","scriptNorm":"')
        [void]$sb.Append((Escape-JsonString $row.ScriptNorm))
        [void]$sb.Append('","enabled":')
        [void]$sb.Append($enabled)
        [void]$sb.Append(',"lastLogon":"')
        [void]$sb.Append((Escape-JsonString $row.LastLogon))
        [void]$sb.Append('","lastLogonTs":')
        [void]$sb.Append($ts)
        [void]$sb.Append(',"created":"')
        [void]$sb.Append((Escape-JsonString $row.Created))
        [void]$sb.Append('","dept":"')
        [void]$sb.Append((Escape-JsonString $row.Department))
        [void]$sb.Append('","title":"')
        [void]$sb.Append((Escape-JsonString $row.Title))
        [void]$sb.Append('","description":"')
        [void]$sb.Append((Escape-JsonString $row.Description))
        [void]$sb.Append('","lockedOut":')
        [void]$sb.Append($locked)
        [void]$sb.Append(',"pwdNeverExpires":')
        [void]$sb.Append($pne)
        [void]$sb.Append('}')
    }
    [void]$sb.Append(']')
    return $sb.ToString()
}

function Get-PropertyString {
    param($Object, [string]$Name, [string]$Default = '')
    if ($null -eq $Object) { return $Default }
    try {
        $val = $Object.$Name
        if ($null -eq $val -or [string]::IsNullOrWhiteSpace([string]$val)) { return $Default }
        return ([string]$val).Trim()
    }
    catch {
        return $Default
    }
}

function Get-DemoUserObjects {
    $now = Get-Date
    $mk = {
        param($Sam, $Display, $Script, $Enabled, $Dept, $Title, $Ou, $DaysAgo, $CreatedDays, $Email, $Desc, $Locked)
        $logon = $null
        if ($DaysAgo -ge 0) { $logon = $now.AddDays(-1 * $DaysAgo) }
        [PSCustomObject]@{
            SamAccountName         = $Sam
            DisplayName            = $Display
            UserPrincipalName      = "$Sam@demo.local"
            ScriptPath             = $Script
            Enabled                = [bool]$Enabled
            LastLogonDate          = $logon
            LastLogonTimestamp     = $logon
            Created                = $now.AddDays(-1 * $CreatedDays)
            DistinguishedName      = "CN=$Display,OU=$Ou,OU=Users,DC=demo,DC=local"
            Department             = $Dept
            Title                  = $Title
            EmailAddress           = $Email
            Description            = $Desc
            LockedOut              = [bool]$Locked
            PasswordNeverExpires   = $false
        }
    }

    return @(
        & $mk 'jsmith'     'Jane Smith'              'netlogon\users\logon.bat'     $true  'Sales'              'Account Exec'     'Sales'     3   800 'jsmith@demo.local'     'Standard sales logon'              $false
        & $mk 'ajones'     'Aaron Jones'             'netlogon\users\logon.bat'     $true  'Sales'              'Account Exec'     'Sales'     12  400 'ajones@demo.local'     ''                                  $false
        & $mk 'obrien'     "Una O'Brien"             'scripts\logon.bat'            $true  'Sales'              'Manager'          'Sales'     1   1200 "obrien@demo.local"     'Apostrophe in name'                $false
        & $mk 'mchen'      'Mei Chen'                'scripts/logon.bat'            $true  'Sales'              'Specialist'       'Sales'     20  200 'mchen@demo.local'      'Forward-slash path (same script)'  $false
        & $mk 'kpatel'     'Kiran Patel'             'SCRIPTS\Logon.BAT'            $true  'Marketing'          'Coordinator'      'Marketing' 5   90  'kpatel@demo.local'     'Different casing of scripts\logon' $false
        & $mk 'rdavis'     'Riley Davis'             'temp\run.vbs'                 $true  'IT'                 'Technician'       'IT'        2   300 'rdavis@demo.local'     'Path contains \t (tab escape bug)' $false
        & $mk 'tnguyen'    'Thu Nguyen'              'finance\mapdrive.bat'         $true  'Finance'            'Analyst'          'Finance'   8   500 'tnguyen@demo.local'    ''                                  $false
        & $mk 'lwilson'    'Lee Wilson'              'finance\mapdrive.bat'         $false 'Finance'            'Analyst'          'Finance'   95  700 'lwilson@demo.local'    'Disabled account'                  $false
        & $mk 'admin.svc'  'Admin Service'           'scripts\admin.cmd'            $true  'IT'                 'Service Account'  'IT'        -1  1500 'admin.svc@demo.local'  'Never logged on'                   $false
        & $mk 'bmurphy'    'Blair Murphy'            'logon.bat'                    $true  'Operations'         'Lead'             'Ops'       15  220 'bmurphy@demo.local'    'Filename only, no folder'          $false
        & $mk 'sgarcia'    'Sofia Garcia'            'scripts\sales_on.bat'         $true  'Sales & Marketing'  'Director'         'Sales'     4   1100 'sgarcia@demo.local'    'Ampersand in department'           $false
        & $mk 'hbrook'     'Harper Brook'            'netlogon\users\logon.bat'     $true  'Sales'              'Rep'              'Sales'     40  60  'hbrook@demo.local'     '</script> in description'          $false
        & $mk 'cokada'     'Chris Okada'             'scripts\logon.bat'            $true  'R&D'                'Engineer'         'Engineering' 0  30 'cokada@demo.local'     'Locked out user'                   $true
        & $mk 'nvest'      'Nora Vest'               'finance\mapdrive.bat'         $false 'Finance'            'Controller'       'Finance'   400 2000 'nvest@demo.local'      'Stale and disabled'                $false
        & $mk 'pwong'      'Priya Wong'              'temp\run.vbs'                 $true  'IT'                 'Sysadmin'         'IT'        120 800 'pwong@demo.local'      'Stale > 90 days'                   $false
        & $mk 'dross'      'Devon Ross'              'logon.bat'                    $true  'Operations'         'Coordinator'      'Ops'       6   45  'dross@demo.local'      ''                                  $false
        & $mk 'ifernandez' 'Isabel Fernandez'        'netlogon\backup\logon.bat'    $true  'Sales'              'Rep'              'Sales'     9   310 'ifernandez@demo.local' 'Same filename, different path'     $false
        & $mk 'gstone'     'Gemma Stone'             'scripts\admin.cmd'            $false 'IT'                 'Contractor'       'IT'        200 100 'gstone@demo.local'     'Disabled contractor'               $false
        & $mk 'yali'       'Yasmin Ali'              'finance\mapdrive.bat'         $true  'Finance'            'AP Clerk'         'Finance'   18  15  'yali@demo.local'       ''                                  $false
        & $mk 'unspec'     'Unspecified Person'      'logon.bat'                    $true  ''                   ''                 'Users'     25  10  'unspec@demo.local'     'Missing dept/title'                $false
    )
}

#endregion

#region ── Preflight Checks ──────────────────────────────────────────────────────

Write-Header "AD Logon Script Report Generator v2.0"
Write-Info "PowerShell Version : $($PSVersionTable.PSVersion)"
Write-Info "Script Start Time  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Info "Run As             : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

$reportDomain = 'Unknown'
$allUsers = @()

if ($DemoMode) {
    Write-Warn "DEMO MODE - synthetic data only; Active Directory is not queried."
    $allUsers = @(Get-DemoUserObjects)
    $reportDomain = 'demo.local'
    Write-Success "Loaded $($allUsers.Count) demo users."
}
else {
    Write-Step "Checking for ActiveDirectory PowerShell module..."
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Host ""
        Write-Host "  [ERROR] The ActiveDirectory module is not installed." -ForegroundColor Red
        Write-Host "  Install RSAT (Remote Server Administration Tools):" -ForegroundColor Red
        Write-Host "  - Windows 10/11: Settings > Optional Features > RSAT: Active Directory" -ForegroundColor DarkYellow
        Write-Host "  - Server: Add-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor DarkYellow
        Write-Host "  - Or run with -DemoMode to preview the dashboard offline." -ForegroundColor DarkYellow
        Write-Host ""
        exit 1
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Success "ActiveDirectory module loaded."

    Write-Step "Building AD query parameters..."

    $filter = if ($IncludeDisabledUsers) {
        "ScriptPath -like '*'"
    }
    else {
        "ScriptPath -like '*' -and Enabled -eq `$true"
    }

    $adParams = @{
        Filter          = $filter
        ResultPageSize  = 1000
        Properties      = @(
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

    $domainParams = @{}
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $adParams['Server'] = $Server
        $domainParams['Server'] = $Server
        Write-Info "Targeting DC: $Server"
    }

    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
        $adParams['SearchBase'] = $SearchBase
        Write-Info "Search Base: $SearchBase"
    }
    else {
        try {
            $domain = Get-ADDomain @domainParams
            $adParams['SearchBase'] = $domain.DistinguishedName
            $reportDomain = [string]$domain.DNSRoot
            Write-Info "Domain: $reportDomain"
            Write-Info "Search Base: $($domain.DistinguishedName)"
        }
        catch {
            Write-Warn "Could not resolve domain automatically. Proceeding without SearchBase."
        }
    }

    if ([string]::IsNullOrWhiteSpace($reportDomain) -or $reportDomain -eq 'Unknown') {
        try {
            $reportDomain = [string](Get-ADDomain @domainParams).DNSRoot
        }
        catch {
            $reportDomain = 'Unknown'
        }
    }

    Write-Step "Querying Active Directory for users with Logon Scripts..."
    $startQuery = Get-Date
    try {
        $allUsers = @(Get-ADUser @adParams)
    }
    catch {
        Write-Host ""
        Write-Host "  [ERROR] Failed to query Active Directory: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    $queryTime = (Get-Date) - $startQuery
    Write-Success "Query completed in $([math]::Round($queryTime.TotalSeconds, 2)) seconds."
    Write-Info "Raw results returned: $($allUsers.Count)"
}

# Client-side safety net. Demo mode always keeps disabled accounts so the
# status filter can be exercised without an extra switch.
if ($DemoMode) {
    $users = @($allUsers)
    Write-Info "Demo data (enabled + disabled): $($users.Count) users"
}
elseif (-not $IncludeDisabledUsers) {
    $users = @($allUsers | Where-Object { $_.Enabled -eq $true })
    Write-Info "After filtering disabled accounts: $($users.Count) users"
}
else {
    $users = @($allUsers)
    Write-Info "Including disabled accounts: $($users.Count) users"
}

if ($users.Count -eq 0) {
    Write-Warn "No users with logon scripts found. The report will be empty."
}

#endregion

#region ── Build Data Structures ─────────────────────────────────────────────────

Write-Step "Processing user data and building analytics..."

$userDataList   = [System.Collections.Generic.List[hashtable]]::new()
$scriptUsageMap = @{}   # scriptNorm -> count
$scriptUsersMap = @{}   # scriptNorm -> list of SAM
$scriptDisplay  = @{}   # scriptNorm -> original path (most common spelling)
$scriptDisplayN = @{}   # scriptNorm -> hashtable of original path -> count
$ouMap          = @{}
$deptMap        = @{}
$enabledCount   = 0
$disabledCount  = 0

foreach ($u in $users) {
    $rawScript = Get-PropertyString $u 'ScriptPath'
    if ([string]::IsNullOrWhiteSpace($rawScript)) { continue }

    $scriptName = Get-ScriptFileName $rawScript
    $scriptNorm = Get-NormalizedScriptPath $rawScript
    $ou         = Get-OUFromDN -DistinguishedName (Get-PropertyString $u 'DistinguishedName' 'N/A')
    $ouShort    = Get-OuShortName $ou

    $lastLogonDt = $null
    try {
        if ($null -ne $u.LastLogonDate -and $u.LastLogonDate -ne [DateTime]::MinValue) {
            $lastLogonDt = $u.LastLogonDate
        }
        elseif ($null -ne $u.LastLogonTimestamp) {
            $tsVal = $u.LastLogonTimestamp
            if ($tsVal -is [DateTime]) { $lastLogonDt = $tsVal }
            else {
                try { $lastLogonDt = [DateTime]::FromFileTime([int64]$tsVal) } catch { $lastLogonDt = $null }
            }
        }
    }
    catch {
        $lastLogonDt = $null
    }

    $lastLogon   = Convert-ADDateToString -DateValue $lastLogonDt
    $lastLogonTs = Convert-DateToUnixMs -DateValue $lastLogonDt

    $created = 'Unknown'
    try {
        if ($null -ne $u.Created) { $created = $u.Created.ToString('yyyy-MM-dd') }
    }
    catch { }

    $dept  = Get-PropertyString $u 'Department' 'Unspecified'
    $title = Get-PropertyString $u 'Title' 'Unspecified'
    $sam   = Get-PropertyString $u 'SamAccountName'
    if ([string]::IsNullOrWhiteSpace($sam)) { continue }

    $isEnabled = $false
    try { $isEnabled = [bool]$u.Enabled } catch { $isEnabled = $false }

    $isLocked = $false
    try { $isLocked = [bool]$u.LockedOut } catch { $isLocked = $false }

    $pwdNever = $false
    try { $pwdNever = [bool]$u.PasswordNeverExpires } catch { $pwdNever = $false }

    $row = @{
        SamAccountName        = $sam
        DisplayName           = Get-PropertyString $u 'DisplayName' $sam
        UserPrincipalName     = Get-PropertyString $u 'UserPrincipalName'
        EmailAddress          = Get-PropertyString $u 'EmailAddress'
        ScriptPath            = $rawScript
        ScriptName            = $scriptName
        ScriptNorm            = $scriptNorm
        OU                    = $ou
        OuShort               = $ouShort
        Enabled               = $isEnabled
        LastLogon             = $lastLogon
        LastLogonTs           = $lastLogonTs
        Created               = $created
        Department            = $dept
        Title                 = $title
        Description           = Get-PropertyString $u 'Description'
        LockedOut             = $isLocked
        PasswordNeverExpires  = $pwdNever
    }
    $userDataList.Add($row)

    if (-not $scriptUsageMap.ContainsKey($scriptNorm)) {
        $scriptUsageMap[$scriptNorm]  = 0
        $scriptUsersMap[$scriptNorm]  = [System.Collections.Generic.List[string]]::new()
        $scriptDisplayN[$scriptNorm]  = @{}
    }
    $scriptUsageMap[$scriptNorm]++
    $scriptUsersMap[$scriptNorm].Add($sam)
    if (-not $scriptDisplayN[$scriptNorm].ContainsKey($rawScript)) {
        $scriptDisplayN[$scriptNorm][$rawScript] = 0
    }
    $scriptDisplayN[$scriptNorm][$rawScript]++

    if (-not $ouMap.ContainsKey($ouShort)) { $ouMap[$ouShort] = 0 }
    $ouMap[$ouShort]++

    if (-not $deptMap.ContainsKey($dept)) { $deptMap[$dept] = 0 }
    $deptMap[$dept]++

    if ($isEnabled) { $enabledCount++ } else { $disabledCount++ }
}

foreach ($normKey in @($scriptDisplayN.Keys)) {
    $best = $scriptDisplayN[$normKey].GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
    $scriptDisplay[$normKey] = $best.Key
}

$totalUsers    = $userDataList.Count
$uniqueScripts = $scriptUsageMap.Count
$reportGenTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

Write-Success "Processed $totalUsers user records."
Write-Info "Unique scripts found (normalised): $uniqueScripts"

#endregion

#region ── Build JSON Payloads ───────────────────────────────────────────────────

Write-Step "Serialising data for HTML report..."

$userDataJson = ConvertTo-UserDataJson -Data $userDataList

$scriptAnalyticsSb = New-Object System.Text.StringBuilder
[void]$scriptAnalyticsSb.Append('[')
$saFirst = $true
foreach ($kvp in ($scriptUsageMap.GetEnumerator() | Sort-Object Value -Descending)) {
    if (-not $saFirst) { [void]$scriptAnalyticsSb.Append(',') } else { $saFirst = $false }
    $displayPath = if ($scriptDisplay.ContainsKey($kvp.Key)) { $scriptDisplay[$kvp.Key] } else { $kvp.Key }
    $rawName     = Get-ScriptFileName $displayPath
    [void]$scriptAnalyticsSb.Append('{"script":"')
    [void]$scriptAnalyticsSb.Append((Escape-JsonString $displayPath))
    [void]$scriptAnalyticsSb.Append('","scriptNorm":"')
    [void]$scriptAnalyticsSb.Append((Escape-JsonString $kvp.Key))
    [void]$scriptAnalyticsSb.Append('","name":"')
    [void]$scriptAnalyticsSb.Append((Escape-JsonString $rawName))
    [void]$scriptAnalyticsSb.Append('","count":')
    [void]$scriptAnalyticsSb.Append([string]$kvp.Value)
    [void]$scriptAnalyticsSb.Append(',"users":[')
    $uFirst = $true
    foreach ($samName in $scriptUsersMap[$kvp.Key]) {
        if (-not $uFirst) { [void]$scriptAnalyticsSb.Append(',') } else { $uFirst = $false }
        [void]$scriptAnalyticsSb.Append('"')
        [void]$scriptAnalyticsSb.Append((Escape-JsonString $samName))
        [void]$scriptAnalyticsSb.Append('"')
    }
    [void]$scriptAnalyticsSb.Append(']}')
}
[void]$scriptAnalyticsSb.Append(']')
$scriptAnalyticsJson = $scriptAnalyticsSb.ToString()

$ouItems = foreach ($item in ($ouMap.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10)) {
    '{"ou":"' + (Escape-JsonString $item.Key) + '","count":' + $item.Value + '}'
}
$ouJson = '[' + (@($ouItems) -join ',') + ']'

$deptItems = foreach ($item in ($deptMap.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 12)) {
    '{"dept":"' + (Escape-JsonString $item.Key) + '","count":' + $item.Value + '}'
}
$deptJson = '[' + (@($deptItems) -join ',') + ']'

#endregion

#region ── Generate HTML ─────────────────────────────────────────────────────────

Write-Step "Generating self-contained HTML report..."

$htmlContent = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>AD Logon Script Report — @@REPORT_DOMAIN@@</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:          #0d1117;
    --bg-card:     #161b22;
    --bg-card2:    #1c2333;
    --bg-hover:    #21262d;
    --border:      #30363d;
    --border-light:#444c56;
    --text:        #e6edf3;
    --text-muted:  #8b949e;
    --text-dim:    #6e7681;
    --accent:      #58a6ff;
    --accent-glow: rgba(88,166,255,0.15);
    --green:       #3fb950;
    --green-bg:    rgba(63,185,80,0.12);
    --red:         #f85149;
    --red-bg:      rgba(248,81,73,0.12);
    --yellow:      #d29922;
    --yellow-bg:   rgba(210,153,34,0.12);
    --purple:      #a371f7;
    --orange:      #f0883e;
    --teal:        #39d353;
    --radius:      8px;
    --radius-lg:   12px;
    --shadow:      0 4px 24px rgba(0,0,0,0.4);
    --font-mono:   Consolas,'Cascadia Code','Courier New',monospace;
  }
  html, body { height: 100%; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.5;
    min-height: 100vh;
  }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }

  .page-wrap { display: flex; flex-direction: column; min-height: 100vh; }
  header {
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
    padding: 0 24px;
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .header-inner {
    max-width: 1600px;
    margin: 0 auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    height: 60px;
  }
  .header-brand { display: flex; align-items: center; gap: 10px; }
  .brand-icon {
    width: 34px; height: 34px;
    background: linear-gradient(135deg, var(--accent) 0%, var(--purple) 100%);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 16px; flex-shrink: 0;
  }
  .brand-text h1 { font-size: 15px; font-weight: 600; line-height: 1.2; }
  .brand-text p { font-size: 11px; color: var(--text-muted); }
  .header-meta {
    display: flex; align-items: center; gap: 20px;
    font-size: 12px; color: var(--text-muted);
  }
  .header-meta span { display: flex; align-items: center; gap: 5px; }
  .live-dot {
    width: 7px; height: 7px;
    background: var(--green); border-radius: 50%;
    box-shadow: 0 0 6px var(--green);
    animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }

  main {
    flex: 1; padding: 28px 24px;
    max-width: 1600px; margin: 0 auto; width: 100%;
  }
  footer {
    border-top: 1px solid var(--border);
    padding: 16px 24px; text-align: center;
    font-size: 12px; color: var(--text-dim);
    background: var(--bg-card);
  }

  .section-title {
    font-size: 13px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--text-muted); margin-bottom: 14px;
    display: flex; align-items: center; gap: 8px;
  }
  .section-title::after { content: ''; flex: 1; height: 1px; background: var(--border); }
  .section-sep { margin-bottom: 32px; }

  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px; margin-bottom: 12px;
  }
  .kpi-note { font-size: 11px; color: var(--text-dim); margin-bottom: 20px; }
  .kpi-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 20px; position: relative; overflow: hidden;
    transition: border-color .2s, transform .15s;
  }
  .kpi-card:hover { border-color: var(--border-light); transform: translateY(-2px); }
  .kpi-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
    border-radius: var(--radius-lg) var(--radius-lg) 0 0;
  }
  .kpi-card.blue::before   { background: var(--accent); }
  .kpi-card.green::before  { background: var(--green); }
  .kpi-card.red::before    { background: var(--red); }
  .kpi-card.purple::before { background: var(--purple); }
  .kpi-card.orange::before { background: var(--orange); }
  .kpi-card.teal::before   { background: var(--teal); }
  .kpi-label {
    font-size: 11px; font-weight: 500; text-transform: uppercase;
    letter-spacing: .06em; color: var(--text-muted); margin-bottom: 10px;
  }
  .kpi-value {
    font-size: 32px; font-weight: 700; line-height: 1;
    font-variant-numeric: tabular-nums;
  }
  .kpi-sub { font-size: 11px; color: var(--text-dim); margin-top: 6px; }

  .charts-grid {
    display: grid; grid-template-columns: 1fr 1fr;
    gap: 16px; margin-bottom: 32px;
  }
  .chart-card {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius-lg); padding: 20px;
  }
  .chart-card-wide { grid-column: 1 / -1; }
  .chart-title {
    font-size: 13px; font-weight: 600; margin-bottom: 16px;
    display: flex; align-items: center; gap: 8px;
  }
  .chart-title .badge {
    font-size: 11px; background: var(--bg-card2);
    border: 1px solid var(--border); border-radius: 20px;
    padding: 2px 8px; color: var(--text-muted); font-weight: 400;
  }
  .chart-wrap { position: relative; height: 260px; }
  .chart-wrap-sm { height: 220px; }

  .script-analytics-grid {
    display: grid; grid-template-columns: 1fr 1fr;
    gap: 16px; margin-bottom: 32px;
  }
  .script-card {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius-lg); overflow: hidden;
  }
  .script-card-header {
    padding: 16px 20px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
  }
  .script-card-header h3 { font-size: 13px; font-weight: 600; }
  .script-list { list-style: none; max-height: 340px; overflow-y: auto; }
  .script-list::-webkit-scrollbar { width: 5px; }
  .script-list::-webkit-scrollbar-track { background: var(--bg-card); }
  .script-list::-webkit-scrollbar-thumb { background: var(--border-light); border-radius: 3px; }
  .script-item {
    display: flex; align-items: center; gap: 12px;
    padding: 12px 20px; border-bottom: 1px solid var(--border);
    transition: background .15s; cursor: pointer;
  }
  .script-item:last-child { border-bottom: none; }
  .script-item:hover { background: var(--bg-hover); }
  .script-item.active { background: var(--accent-glow); border-left: 3px solid var(--accent); }
  .script-item.static { cursor: default; }
  .script-rank {
    font-size: 11px; color: var(--text-dim);
    font-variant-numeric: tabular-nums; width: 20px; text-align: right; flex-shrink: 0;
  }
  .script-info { flex: 1; min-width: 0; }
  .script-name {
    font-size: 13px; font-weight: 500; color: var(--accent);
    font-family: var(--font-mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .script-path {
    font-size: 11px; color: var(--text-dim); font-family: var(--font-mono);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 2px;
  }
  .script-count-wrap { display: flex; flex-direction: column; align-items: flex-end; flex-shrink: 0; }
  .script-count { font-size: 18px; font-weight: 700; font-variant-numeric: tabular-nums; }
  .script-pct { font-size: 10px; color: var(--text-dim); }
  .bar-wrap { width: 80px; height: 4px; background: var(--border); border-radius: 2px; margin-top: 4px; overflow: hidden; }
  .bar-fill { height: 100%; background: var(--accent); border-radius: 2px; }

  .table-card {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius-lg); overflow: hidden; margin-bottom: 32px;
  }
  .table-toolbar {
    padding: 16px 20px 10px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  }
  .table-toolbar h2 { font-size: 14px; font-weight: 600; margin-right: auto; }
  .search-wrap { position: relative; flex: 1 1 280px; min-width: 200px; max-width: 420px; }
  .search-wrap svg {
    position: absolute; left: 10px; top: 50%; transform: translateY(-50%);
    color: var(--text-dim); pointer-events: none;
  }
  .search-input {
    width: 100%; padding: 7px 10px 7px 34px;
    background: var(--bg); border: 1px solid var(--border);
    border-radius: var(--radius); color: var(--text); font-size: 13px; outline: none;
  }
  .search-input:focus { border-color: var(--accent); }
  .search-input::placeholder { color: var(--text-dim); }
  .search-hint { font-size: 11px; color: var(--text-dim); padding: 0 20px 8px; }

  select.filter-select {
    padding: 7px 10px; background: var(--bg);
    border: 1px solid var(--border); border-radius: var(--radius);
    color: var(--text); font-size: 13px; outline: none; cursor: pointer;
    max-width: 220px;
  }
  select.filter-select:focus { border-color: var(--accent); }

  .btn {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 7px 14px; border-radius: var(--radius);
    font-size: 13px; font-weight: 500; cursor: pointer;
    border: 1px solid transparent; white-space: nowrap;
  }
  .btn-primary { background: var(--accent); color: #0d1117; border-color: var(--accent); }
  .btn-primary:hover { background: #79c0ff; }
  .btn-ghost { background: transparent; color: var(--text-muted); border-color: var(--border); }
  .btn-ghost:hover { background: var(--bg-hover); color: var(--text); }
  .btn-green { background: var(--green-bg); color: var(--green); border-color: rgba(63,185,80,0.3); }
  .btn-green:hover { background: rgba(63,185,80,0.2); }

  .result-count { font-size: 12px; color: var(--text-dim); white-space: nowrap; }

  .match-banner {
    display: none; margin: 0 20px 12px; padding: 10px 14px;
    background: var(--accent-glow); border: 1px solid rgba(88,166,255,0.35);
    border-radius: var(--radius); font-size: 12px; color: var(--text);
  }
  .match-banner.active { display: block; }
  .match-banner strong { color: var(--accent); }

  .filter-chips {
    display: flex; flex-wrap: wrap; gap: 6px; padding: 0 20px 12px;
  }
  .chip {
    display: inline-flex; align-items: center; gap: 6px;
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 20px; padding: 3px 8px 3px 10px;
    font-size: 11px; color: var(--text-muted);
  }
  .chip b { color: var(--text); font-weight: 600; }
  .chip button {
    border: 0; background: transparent; color: var(--text-dim);
    cursor: pointer; font-size: 13px; line-height: 1; padding: 0 2px;
  }
  .chip button:hover { color: var(--red); }

  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead tr { background: var(--bg-card2); border-bottom: 1px solid var(--border); }
  th {
    padding: 10px 14px; text-align: left; font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: .06em; color: var(--text-muted);
    white-space: nowrap; user-select: none; cursor: pointer;
    position: sticky; top: 0; background: var(--bg-card2);
  }
  th:hover { color: var(--text); }
  th .sort-icon { color: var(--text-dim); font-size: 10px; margin-left: 4px; }
  th.sorted { color: var(--accent); }
  th.sorted .sort-icon { color: var(--accent); }
  th.nosort { cursor: default; }
  tbody tr { border-bottom: 1px solid var(--border); }
  tbody tr:hover { background: var(--bg-hover); }
  td {
    padding: 10px 14px; vertical-align: middle; max-width: 240px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  td.mono { font-family: var(--font-mono); font-size: 12px; color: var(--accent); }
  td.muted { color: var(--text-muted); }
  td.dim { color: var(--text-dim); font-size: 12px; }

  .badge-pill {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: 500;
  }
  .badge-enabled  { background: var(--green-bg); color: var(--green); }
  .badge-disabled { background: var(--red-bg); color: var(--red); }
  .badge-locked   { background: var(--yellow-bg); color: var(--yellow); margin-left: 4px; }

  .table-footer {
    padding: 12px 20px; border-top: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    font-size: 12px; color: var(--text-muted); background: var(--bg-card2);
    flex-wrap: wrap; gap: 8px;
  }
  .pagination { display: flex; align-items: center; gap: 4px; }
  .page-btn {
    padding: 4px 10px; background: var(--bg); border: 1px solid var(--border);
    border-radius: var(--radius); color: var(--text-muted); font-size: 12px; cursor: pointer;
  }
  .page-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
  .page-btn:disabled { opacity: 0.35; cursor: not-allowed; }
  .page-btn.active { background: var(--accent); border-color: var(--accent); color: #0d1117; font-weight: 600; }

  .modal-overlay {
    display: none; position: fixed; inset: 0;
    background: rgba(0,0,0,.65); z-index: 200;
    align-items: center; justify-content: center;
    backdrop-filter: blur(4px);
  }
  .modal-overlay.open { display: flex; }
  .modal {
    background: var(--bg-card); border: 1px solid var(--border-light);
    border-radius: var(--radius-lg); width: min(700px, 95vw); max-height: 80vh;
    overflow: hidden; display: flex; flex-direction: column;
    box-shadow: 0 24px 64px rgba(0,0,0,.6);
  }
  .modal-header {
    padding: 18px 20px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
  }
  .modal-header h2 { font-size: 15px; font-weight: 600; }
  .modal-close {
    width: 28px; height: 28px; background: transparent;
    border: 1px solid var(--border); border-radius: 6px; cursor: pointer;
    color: var(--text-muted); font-size: 16px;
  }
  .modal-close:hover { background: var(--red-bg); border-color: var(--red); color: var(--red); }
  .modal-body { padding: 20px; overflow-y: auto; flex: 1; }
  .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px; }
  .detail-item { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px; }
  .detail-item label {
    display: block; font-size: 10px; text-transform: uppercase;
    letter-spacing: .06em; color: var(--text-dim); margin-bottom: 4px;
  }
  .detail-item .val { font-size: 13px; word-break: break-all; }
  .detail-item .val.mono { font-family: var(--font-mono); color: var(--accent); }

  .toast {
    position: fixed; bottom: 24px; right: 24px;
    background: var(--bg-card2); border: 1px solid var(--border-light);
    border-radius: var(--radius); padding: 12px 18px; font-size: 13px;
    box-shadow: var(--shadow); z-index: 300;
    transform: translateY(80px); opacity: 0; transition: all .3s ease;
    display: flex; align-items: center; gap: 8px;
  }
  .toast.show { transform: translateY(0); opacity: 1; }

  @media (max-width: 900px) {
    .charts-grid, .script-analytics-grid, .detail-grid { grid-template-columns: 1fr; }
    .chart-card-wide { grid-column: auto; }
    .header-meta { display: none; }
  }
  @media (max-width: 600px) {
    main { padding: 16px 12px; }
    .kpi-grid { grid-template-columns: repeat(2, 1fr); }
  }
  .empty-state { padding: 48px 20px; text-align: center; color: var(--text-dim); }
  .empty-state .empty-icon { font-size: 40px; margin-bottom: 12px; }
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
        <p id="hdr-domain">Domain: @@REPORT_DOMAIN@@</p>
      </div>
    </div>
    <div class="header-meta">
      <span><div class="live-dot"></div> Report ready</span>
      <span>Generated: @@REPORT_GEN_TIME@@</span>
      <span>Domain: @@REPORT_DOMAIN@@</span>
    </div>
  </div>
</header>

<main>
  <div class="section-sep">
    <p class="section-title">Overview</p>
    <div class="kpi-grid" id="kpi-grid"></div>
    <p class="kpi-note">Domain-wide totals (not affected by table filters). Matching-filter counts appear above the user table.</p>
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
        <p class="chart-title">Users per Script — full breakdown <span class="badge" id="all-scripts-badge"></span></p>
        <div class="chart-wrap"><canvas id="chartAll"></canvas></div>
      </div>
      <div class="chart-card">
        <p class="chart-title">Top OUs by User Count</p>
        <div class="chart-wrap chart-wrap-sm"><canvas id="chartOU"></canvas></div>
      </div>
      <div class="chart-card">
        <p class="chart-title">Users by Department</p>
        <div class="chart-wrap chart-wrap-sm"><canvas id="chartDept"></canvas></div>
      </div>
    </div>
  </div>

  <div class="section-sep">
    <p class="section-title">Script Inventory</p>
    <div class="script-analytics-grid">
      <div class="script-card">
        <div class="script-card-header">
          <h3>Scripts by usage (click to filter)</h3>
          <span class="result-count" id="script-list-count"></span>
        </div>
        <ul class="script-list" id="script-list"></ul>
      </div>
      <div class="script-card">
        <div class="script-card-header">
          <h3>Matching users of selected script</h3>
          <span class="result-count" id="script-user-count"></span>
        </div>
        <ul class="script-list" id="script-user-list">
          <li class="empty-state"><div class="empty-icon">&#128204;</div><p>Click a script on the left<br>to view its users</p></li>
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
          <input type="search" class="search-input" id="search-input" placeholder="Search users, scripts, OUs…" aria-label="Search users" />
        </div>
        <select class="filter-select" id="filter-script" aria-label="Filter by script path"></select>
        <select class="filter-select" id="filter-scriptname" aria-label="Filter by script file name"></select>
        <select class="filter-select" id="filter-status" aria-label="Filter by status">
          <option value="">All Status</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </select>
        <select class="filter-select" id="filter-dept" aria-label="Filter by department"></select>
        <select class="filter-select" id="filter-ou" aria-label="Filter by OU"></select>
        <select class="filter-select" id="filter-logon" aria-label="Filter by last logon">
          <option value="">All last logon</option>
          <option value="never">Never logged on</option>
          <option value="30">Active (last 30 days)</option>
          <option value="90">Active (last 90 days)</option>
          <option value="365">Active (last 365 days)</option>
          <option value="stale90">Stale (over 90 days / never)</option>
          <option value="stale365">Stale (over 365 days / never)</option>
        </select>
        <span class="result-count" id="result-count"></span>
        <button class="btn btn-green" id="btn-export-csv" title="Export filtered results to CSV">Export CSV</button>
        <button class="btn btn-ghost" id="btn-clear-filters" title="Clear all filters">Clear</button>
      </div>
      <p class="search-hint">
        Search is AND across words. Use quotes for a phrase, <code>-term</code> to exclude,
        and prefixes like <code>script:logon.bat</code>, <code>dept:IT</code>, <code>ou:Sales</code>,
        <code>sam:jsmith</code>, <code>status:enabled</code>. Paths match with <code>\</code> or <code>/</code>, case-insensitive.
      </p>
      <div class="match-banner" id="match-banner"></div>
      <div class="filter-chips" id="filter-chips"></div>
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
              <th data-col="ouShort">OU <span class="sort-icon">&#8645;</span></th>
              <th class="nosort">Detail</th>
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
          <option value="all">All</option>
        </select>
      </div>
    </div>
  </div>
</main>

<footer>
  AD Logon Script Report &bull; Generated @@REPORT_GEN_TIME@@ &bull; Domain: @@REPORT_DOMAIN@@ &bull;
  Total users processed: @@TOTAL_USERS@@ &bull; Unique scripts: @@UNIQUE_SCRIPTS@@
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
const RAW_USERS    = @@USER_DATA_JSON@@;
const RAW_SCRIPTS  = @@SCRIPT_ANALYTICS_JSON@@;
const RAW_OUS      = @@OU_JSON@@;
const RAW_DEPTS    = @@DEPT_JSON@@;
const META = {
  totalUsers    : @@TOTAL_USERS@@,
  uniqueScripts : @@UNIQUE_SCRIPTS@@,
  enabledCount  : @@ENABLED_COUNT@@,
  disabledCount : @@DISABLED_COUNT@@,
  reportTime    : "@@REPORT_GEN_TIME@@",
  domain        : "@@REPORT_DOMAIN@@"
};

let filteredData = [];
let sortCol = 'sam';
let sortDir = 'asc';
let currentPage = 1;
let pageSize = 25;
let searchTimer = null;

const PALETTE = [
  '#58a6ff','#3fb950','#f0883e','#a371f7','#39d353','#f85149',
  '#d29922','#56d364','#79c0ff','#ff7b72','#ffa657','#d2a8ff'
];
const PALETTE_ALPHA = PALETTE.map(c => c + 'bb');

const FIELD_ALIASES = {
  sam: ['sam','user','username','account'],
  display: ['display','name','displayname'],
  upn: ['upn','email','mail'],
  script: ['script','path','scriptpath'],
  scriptname: ['scriptname','file','filename'],
  ou: ['ou','org','orgunit'],
  dept: ['dept','department'],
  title: ['title','job','role'],
  status: ['status','state'],
  logon: ['logon','lastlogon']
};

function esc(s){
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}
function showToast(msg, icon){
  const t = document.getElementById('toast');
  document.getElementById('toast-msg').textContent = msg;
  t.querySelector('.toast-icon').innerHTML = icon || '&#10003;';
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2800);
}
function fmtNum(n){ return Number(n || 0).toLocaleString(); }

function normText(s){
  return String(s == null ? '' : s)
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .trim();
}
function canonPath(s){
  let p = String(s == null ? '' : s).trim().replace(/\//g, '\\');
  let prefix = '';
  if (p.startsWith('\\\\')) { prefix = '\\\\'; p = p.slice(2); }
  while (p.indexOf('\\\\') !== -1) p = p.replace(/\\\\/g, '\\');
  p = p.replace(/\\+$/, '');
  return (prefix + p).toLowerCase();
}
function pathVariants(s){
  const raw = String(s == null ? '' : s);
  return [raw, raw.replace(/\\/g, '/'), raw.replace(/\//g, '\\'), canonPath(raw)].join(' ');
}

function resolveField(name){
  const n = String(name || '').toLowerCase();
  for (const key of Object.keys(FIELD_ALIASES)) {
    if (FIELD_ALIASES[key].indexOf(n) !== -1) return key;
  }
  return n;
}

function parseSearchQuery(raw){
  const q = String(raw == null ? '' : raw).trim();
  const tokens = [];
  const re = /(-)?(?:([a-zA-Z]+):)?(?:"([^"]*)"|(\S+))/g;
  let m;
  while ((m = re.exec(q))) {
    const value = m[3] != null ? m[3] : m[4];
    if (!value) continue;
    tokens.push({
      neg: m[1] === '-',
      field: m[2] ? resolveField(m[2]) : null,
      value: value
    });
  }
  return tokens;
}

function fieldHaystack(u, field){
  switch (field) {
    case 'sam': return String(u.sam || '');
    case 'display': return String(u.display || '');
    case 'upn': return [u.upn, u.email].filter(Boolean).join(' ');
    case 'script': return pathVariants(u.script) + ' ' + pathVariants(u.scriptNorm);
    case 'scriptname': return String(u.scriptName || '');
    case 'ou': return [u.ou, u.ouShort].filter(Boolean).join(' ');
    case 'dept': return String(u.dept || '');
    case 'title': return String(u.title || '');
    case 'status': return u.enabled ? 'enabled active' : 'disabled inactive';
    case 'logon': return String(u.lastLogon || '');
    default: return '';
  }
}

function fullHaystack(u){
  return [
    u.sam, u.display, u.upn, u.email, u.script, u.scriptName, u.scriptNorm,
    u.ou, u.ouShort, u.dept, u.title, u.lastLogon, u.created, u.description,
    u.enabled ? 'enabled active' : 'disabled inactive',
    u.lockedOut ? 'locked lockedout' : '',
    pathVariants(u.script)
  ].join(' ');
}

function textContains(hay, needle){
  return normText(hay).indexOf(normText(needle)) !== -1;
}

function tokenMatches(u, token){
  const hay = token.field ? fieldHaystack(u, token.field) : fullHaystack(u);
  if (token.field === 'script' || token.field === 'scriptname') {
    const ok = textContains(hay, token.value) || canonPath(hay).indexOf(canonPath(token.value)) !== -1;
    return token.neg ? !ok : ok;
  }
  const ok = textContains(hay, token.value);
  return token.neg ? !ok : ok;
}

function daysSinceLogon(u){
  const ts = Number(u.lastLogonTs || 0);
  if (!ts) return Infinity;
  return (Date.now() - ts) / 86400000;
}

function getFilters(){
  return {
    query: document.getElementById('search-input').value,
    script: document.getElementById('filter-script').value,
    scriptName: document.getElementById('filter-scriptname').value,
    status: document.getElementById('filter-status').value,
    dept: document.getElementById('filter-dept').value,
    ou: document.getElementById('filter-ou').value,
    logon: document.getElementById('filter-logon').value
  };
}

function hasActiveFilters(f){
  return !!(f.query.trim() || f.script || f.scriptName || f.status || f.dept || f.ou || f.logon);
}

function userMatches(u, f){
  if (f.script) {
    const want = f.script;
    if (u.scriptNorm !== want && canonPath(u.script) !== canonPath(want) && canonPath(u.scriptNorm) !== canonPath(want)) {
      return false;
    }
  }
  if (f.scriptName && normText(u.scriptName) !== normText(f.scriptName)) return false;
  if (f.status === 'enabled' && !u.enabled) return false;
  if (f.status === 'disabled' && u.enabled) return false;
  if (f.dept && normText(u.dept) !== normText(f.dept)) return false;
  if (f.ou && normText(u.ouShort) !== normText(f.ou) && !textContains(u.ou, f.ou)) return false;
  if (f.logon) {
    const days = daysSinceLogon(u);
    if (f.logon === 'never' && days !== Infinity) return false;
    if (f.logon === '30' && !(days <= 30)) return false;
    if (f.logon === '90' && !(days <= 90)) return false;
    if (f.logon === '365' && !(days <= 365)) return false;
    if (f.logon === 'stale90' && !(days > 90)) return false;
    if (f.logon === 'stale365' && !(days > 365)) return false;
  }
  const tokens = parseSearchQuery(f.query);
  for (let i = 0; i < tokens.length; i++) {
    if (!tokenMatches(u, tokens[i])) return false;
  }
  return true;
}

function sortValue(u, col){
  if (col === 'lastLogon') return Number(u.lastLogonTs || 0);
  if (col === 'enabled') return u.enabled ? 1 : 0;
  return u[col] == null ? '' : u[col];
}

function sortData(){
  filteredData.sort((a, b) => {
    const av = sortValue(a, sortCol);
    const bv = sortValue(b, sortCol);
    let cmp;
    if (typeof av === 'number' && typeof bv === 'number') cmp = av - bv;
    else cmp = String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: 'base' });
    return sortDir === 'asc' ? cmp : -cmp;
  });
}

function applyFilters(resetPage){
  const f = getFilters();
  filteredData = RAW_USERS.filter(u => userMatches(u, f));
  sortData();
  if (resetPage !== false) currentPage = 1;
  const totalPages = Math.max(1, Math.ceil(filteredData.length / pageSize) || 1);
  if (currentPage > totalPages) currentPage = totalPages;
  renderTable();
  renderChips(f);
  renderMatchBanner(f);
  syncScriptHighlight(f);
  updateScriptUserList(f);
}

function buildKPIs(){
  const topScript = RAW_SCRIPTS.length ? RAW_SCRIPTS[0] : null;
  const maxCount  = topScript ? topScript.count : 0;
  const domainShort = String(META.domain || '').split('.')[0] || META.domain;
  const cards = [
    { label:'Total Users',      val: fmtNum(META.totalUsers),    sub:'Users with logon scripts',            color:'blue' },
    { label:'Unique Scripts',    val: fmtNum(META.uniqueScripts), sub:'Distinct script paths (normalised)', color:'purple' },
    { label:'Enabled Accounts',  val: fmtNum(META.enabledCount),  sub:'Active user accounts',               color:'green' },
    { label:'Disabled Accounts', val: fmtNum(META.disabledCount), sub:'Disabled user accounts',             color:'red' },
    { label:'Most Used Script',  val: fmtNum(maxCount),           sub: topScript ? topScript.name : 'N/A',  color:'orange' },
    { label:'Domain',            val: domainShort,                sub: META.domain,                         color:'teal' }
  ];
  document.getElementById('kpi-grid').innerHTML = cards.map(c =>
    '<div class="kpi-card ' + c.color + '">' +
      '<p class="kpi-label">' + esc(c.label) + '</p>' +
      '<p class="kpi-value">' + esc(String(c.val)) + '</p>' +
      '<p class="kpi-sub">' + esc(c.sub) + '</p>' +
    '</div>'
  ).join('');
}

const CHART_DEFAULTS = {
  plugins: {
    legend: { labels: { color:'#8b949e', font:{ size:11 } } },
    tooltip: {
      backgroundColor:'#161b22', borderColor:'#30363d', borderWidth:1,
      titleColor:'#e6edf3', bodyColor:'#8b949e'
    }
  },
  scales: {
    x: { ticks:{ color:'#8b949e', font:{ size:11 } }, grid:{ color:'#21262d' } },
    y: { ticks:{ color:'#8b949e', font:{ size:11 } }, grid:{ color:'#21262d' } }
  }
};

function setScriptFilter(scriptNorm, scriptName){
  const ss = document.getElementById('filter-script');
  const sn = document.getElementById('filter-scriptname');
  ss.value = scriptNorm || '';
  if (scriptName !== undefined) sn.value = scriptName || '';
  if (ss.value !== (scriptNorm || '') && scriptNorm) {
    // option missing — still filter via a temporary option
    const o = document.createElement('option');
    o.value = scriptNorm;
    o.textContent = scriptNorm;
    ss.appendChild(o);
    ss.value = scriptNorm;
  }
}

function applyChartScript(index, source){
  if (index == null || index < 0) return;
  const s = source[index];
  if (!s || !s.scriptNorm) return;
  setScriptFilter(s.scriptNorm, '');
  applyFilters(true);
  document.querySelector('.table-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function buildCharts(){
  const top10 = RAW_SCRIPTS.slice(0, 10);
  document.getElementById('top-scripts-badge').textContent = 'Top ' + top10.length + ' · click a bar to filter';
  new Chart(document.getElementById('chartTopScripts'), {
    type: 'bar',
    data: {
      labels: top10.map(s => s.name),
      datasets: [{ label:'Users', data: top10.map(s => s.count),
        backgroundColor: PALETTE_ALPHA, borderColor: PALETTE, borderWidth: 1, borderRadius: 4 }]
    },
    options: {
      ...CHART_DEFAULTS, indexAxis:'y', responsive:true, maintainAspectRatio:false,
      plugins:{ ...CHART_DEFAULTS.plugins, legend:{ display:false } },
      onClick: (e, els) => { if (els.length) applyChartScript(els[0].index, top10); }
    }
  });

  const pieTop = RAW_SCRIPTS.slice(0, 8);
  const pieOtherCount = RAW_SCRIPTS.slice(8).reduce((a,s) => a + s.count, 0);
  const pieLabels = pieTop.map(s => s.name);
  const pieData = pieTop.map(s => s.count);
  if (pieOtherCount > 0) { pieLabels.push('Others'); pieData.push(pieOtherCount); }
  new Chart(document.getElementById('chartPie'), {
    type: 'doughnut',
    data: { labels: pieLabels, datasets:[{ data: pieData, backgroundColor: PALETTE_ALPHA, borderColor: PALETTE, borderWidth:1 }] },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{ ...CHART_DEFAULTS.plugins, legend:{ position:'right', labels:{ color:'#8b949e', font:{size:10}, boxWidth:12 } } },
      onClick: (e, els) => {
        if (!els.length) return;
        const i = els[0].index;
        if (i < pieTop.length) applyChartScript(i, pieTop);
      }
    }
  });

  document.getElementById('all-scripts-badge').textContent = RAW_SCRIPTS.length + ' scripts · click to filter';
  new Chart(document.getElementById('chartAll'), {
    type: 'bar',
    data: {
      labels: RAW_SCRIPTS.map(s => s.name),
      datasets:[{ label:'Users', data: RAW_SCRIPTS.map(s => s.count),
        backgroundColor:'#58a6ffbb', borderColor:'#58a6ff', borderWidth:1, borderRadius:3 }]
    },
    options:{
      ...CHART_DEFAULTS, responsive:true, maintainAspectRatio:false,
      plugins:{ ...CHART_DEFAULTS.plugins, legend:{display:false} },
      onClick: (e, els) => { if (els.length) applyChartScript(els[0].index, RAW_SCRIPTS); }
    }
  });

  new Chart(document.getElementById('chartOU'), {
    type:'bar',
    data:{
      labels: RAW_OUS.map(o => o.ou),
      datasets:[{ label:'Users', data: RAW_OUS.map(o => o.count),
        backgroundColor:'#a371f7bb', borderColor:'#a371f7', borderWidth:1, borderRadius:3 }]
    },
    options:{
      ...CHART_DEFAULTS, responsive:true, maintainAspectRatio:false, indexAxis:'y',
      plugins:{...CHART_DEFAULTS.plugins, legend:{display:false}},
      onClick: (e, els) => {
        if (!els.length) return;
        const ou = RAW_OUS[els[0].index] && RAW_OUS[els[0].index].ou;
        if (!ou) return;
        document.getElementById('filter-ou').value = ou;
        applyFilters(true);
        document.querySelector('.table-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }
  });

  new Chart(document.getElementById('chartDept'), {
    type:'bar',
    data:{
      labels: RAW_DEPTS.map(d => d.dept),
      datasets:[{ label:'Users', data: RAW_DEPTS.map(d => d.count),
        backgroundColor:'#f0883ebb', borderColor:'#f0883e', borderWidth:1, borderRadius:3 }]
    },
    options:{
      ...CHART_DEFAULTS, responsive:true, maintainAspectRatio:false, indexAxis:'y',
      plugins:{...CHART_DEFAULTS.plugins, legend:{display:false}},
      onClick: (e, els) => {
        if (!els.length) return;
        const dept = RAW_DEPTS[els[0].index] && RAW_DEPTS[els[0].index].dept;
        if (!dept) return;
        document.getElementById('filter-dept').value = dept;
        applyFilters(true);
        document.querySelector('.table-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }
  });
}

function buildScriptList(){
  const list = document.getElementById('script-list');
  document.getElementById('script-list-count').textContent = RAW_SCRIPTS.length + ' scripts';
  if (!RAW_SCRIPTS.length) {
    list.innerHTML = '<li class="empty-state"><div class="empty-icon">&#128204;</div><p>No scripts found</p></li>';
    return;
  }
  const maxC = RAW_SCRIPTS[0].count;
  list.innerHTML = RAW_SCRIPTS.map((s, i) => {
    const pct = META.totalUsers > 0 ? Math.round((s.count / META.totalUsers) * 100) : 0;
    const barW = maxC > 0 ? Math.round((s.count / maxC) * 100) : 0;
    return '<li class="script-item" data-idx="' + i + '" tabindex="0" role="button" aria-label="Filter by ' + esc(s.name) + '">' +
      '<span class="script-rank">' + (i + 1) + '</span>' +
      '<span class="script-info">' +
        '<span class="script-name" title="' + esc(s.script) + '">' + esc(s.name) + '</span>' +
        '<span class="script-path" title="' + esc(s.script) + '">' + esc(s.script) + '</span>' +
      '</span>' +
      '<span class="script-count-wrap">' +
        '<span class="script-count">' + fmtNum(s.count) + '</span>' +
        '<span class="script-pct">' + pct + '% of users</span>' +
        '<span class="bar-wrap"><span class="bar-fill" style="width:' + barW + '%"></span></span>' +
      '</span></li>';
  }).join('');

  list.querySelectorAll('.script-item').forEach(li => {
    const activate = () => {
      const idx = Number(li.getAttribute('data-idx'));
      const s = RAW_SCRIPTS[idx];
      if (!s) return;
      const cur = document.getElementById('filter-script').value;
      if (cur === s.scriptNorm) setScriptFilter('', '');
      else setScriptFilter(s.scriptNorm, '');
      applyFilters(true);
    };
    li.addEventListener('click', activate);
    li.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(); }
    });
  });
}

function syncScriptHighlight(f){
  document.querySelectorAll('#script-list .script-item').forEach(li => {
    const idx = Number(li.getAttribute('data-idx'));
    const s = RAW_SCRIPTS[idx];
    li.classList.toggle('active', !!(s && f.script && s.scriptNorm === f.script));
  });
}

function updateScriptUserList(f){
  const ul = document.getElementById('script-user-list');
  const ctr = document.getElementById('script-user-count');
  if (!f.script) {
    ctr.textContent = '';
    ul.innerHTML = '<li class="empty-state"><div class="empty-icon">&#128204;</div><p>Click a script on the left<br>to view its users</p></li>';
    return;
  }
  const matches = filteredData;
  ctr.textContent = matches.length + ' matching';
  if (!matches.length) {
    ul.innerHTML = '<li class="empty-state"><p>No matching users for this script with the current filters.</p></li>';
    return;
  }
  ul.innerHTML = matches.map(u =>
    '<li class="script-item static" data-sam="' + esc(u.sam) + '">' +
      '<span style="font-size:16px">&#128100;</span>' +
      '<span class="script-info">' +
        '<span class="script-name">' + esc(u.sam) + '</span>' +
        '<span class="script-path">' + esc(u.display) + (u.enabled ? '' : ' · disabled') + '</span>' +
      '</span></li>'
  ).join('');
  ul.querySelectorAll('[data-sam]').forEach(li => {
    li.style.cursor = 'pointer';
    li.addEventListener('click', () => showDetailBySam(li.getAttribute('data-sam')));
  });
}

function populateFilterDropdowns(){
  const ss = document.getElementById('filter-script');
  ss.innerHTML = '';
  const allScript = document.createElement('option');
  allScript.value = '';
  allScript.textContent = 'All script paths';
  ss.appendChild(allScript);

  const nameCount = {};
  RAW_SCRIPTS.forEach(s => {
    const n = (s.name || '').toLowerCase();
    nameCount[n] = (nameCount[n] || 0) + 1;
  });
  RAW_SCRIPTS.forEach(s => {
    const o = document.createElement('option');
    o.value = s.scriptNorm;
    const ambiguous = nameCount[(s.name || '').toLowerCase()] > 1;
    o.textContent = ambiguous
      ? s.name + ' — ' + s.script + ' (' + s.count + ')'
      : s.name + ' (' + s.count + ')';
    ss.appendChild(o);
  });

  const sn = document.getElementById('filter-scriptname');
  sn.innerHTML = '';
  const allName = document.createElement('option');
  allName.value = '';
  allName.textContent = 'All script names';
  sn.appendChild(allName);
  const byName = {};
  RAW_USERS.forEach(u => {
    const n = u.scriptName || '';
    if (!n) return;
    const key = n.toLowerCase();
    if (!byName[key]) byName[key] = { name: n, count: 0 };
    byName[key].count++;
  });
  Object.keys(byName).sort().forEach(k => {
    const o = document.createElement('option');
    o.value = byName[k].name;
    o.textContent = byName[k].name + ' (' + byName[k].count + ')';
    sn.appendChild(o);
  });

  const ds = document.getElementById('filter-dept');
  ds.innerHTML = '';
  const allDept = document.createElement('option');
  allDept.value = '';
  allDept.textContent = 'All departments';
  ds.appendChild(allDept);
  const depts = [...new Set(RAW_USERS.map(u => u.dept || 'Unspecified'))].sort((a,b) => a.localeCompare(b, undefined, {sensitivity:'base'}));
  depts.forEach(d => {
    const o = document.createElement('option');
    o.value = d;
    o.textContent = d;
    ds.appendChild(o);
  });

  const os = document.getElementById('filter-ou');
  os.innerHTML = '';
  const allOu = document.createElement('option');
  allOu.value = '';
  allOu.textContent = 'All OUs';
  os.appendChild(allOu);
  const ous = [...new Set(RAW_USERS.map(u => u.ouShort || 'N/A'))].sort((a,b) => a.localeCompare(b, undefined, {sensitivity:'base'}));
  ous.forEach(v => {
    const o = document.createElement('option');
    o.value = v;
    o.textContent = v;
    os.appendChild(o);
  });
}

function renderChips(f){
  const box = document.getElementById('filter-chips');
  const chips = [];
  const add = (key, label, value) => {
    chips.push({ key, label, value });
  };
  if (f.query.trim()) add('query', 'Search', f.query.trim());
  if (f.script) {
    const s = RAW_SCRIPTS.find(x => x.scriptNorm === f.script);
    add('script', 'Path', s ? s.script : f.script);
  }
  if (f.scriptName) add('scriptName', 'File', f.scriptName);
  if (f.status) add('status', 'Status', f.status);
  if (f.dept) add('dept', 'Dept', f.dept);
  if (f.ou) add('ou', 'OU', f.ou);
  if (f.logon) {
    const labels = {
      never:'Never logged on', '30':'Last 30 days', '90':'Last 90 days',
      '365':'Last 365 days', stale90:'Stale > 90 days', stale365:'Stale > 365 days'
    };
    add('logon', 'Logon', labels[f.logon] || f.logon);
  }
  if (!chips.length) { box.innerHTML = ''; return; }
  box.innerHTML = chips.map(c =>
    '<span class="chip"><span>' + esc(c.label) + ': <b>' + esc(c.value) + '</b></span>' +
    '<button type="button" data-clear="' + esc(c.key) + '" aria-label="Remove ' + esc(c.label) + ' filter">×</button></span>'
  ).join('');
  box.querySelectorAll('button[data-clear]').forEach(btn => {
    btn.addEventListener('click', () => {
      const k = btn.getAttribute('data-clear');
      if (k === 'query') document.getElementById('search-input').value = '';
      if (k === 'script') document.getElementById('filter-script').value = '';
      if (k === 'scriptName') document.getElementById('filter-scriptname').value = '';
      if (k === 'status') document.getElementById('filter-status').value = '';
      if (k === 'dept') document.getElementById('filter-dept').value = '';
      if (k === 'ou') document.getElementById('filter-ou').value = '';
      if (k === 'logon') document.getElementById('filter-logon').value = '';
      applyFilters(true);
    });
  });
}

function renderMatchBanner(f){
  const el = document.getElementById('match-banner');
  if (!hasActiveFilters(f)) { el.classList.remove('active'); el.textContent = ''; return; }
  const unique = new Set(filteredData.map(u => u.scriptNorm || canonPath(u.script)));
  const en = filteredData.filter(u => u.enabled).length;
  const dis = filteredData.length - en;
  el.classList.add('active');
  el.innerHTML = 'Filters matched <strong>' + fmtNum(filteredData.length) + '</strong> of ' +
    fmtNum(RAW_USERS.length) + ' users · <strong>' + unique.size + '</strong> unique script' +
    (unique.size === 1 ? '' : 's') + ' · ' + en + ' enabled / ' + dis + ' disabled';
}

function renderTable(){
  const tbody = document.getElementById('table-body');
  const start = (currentPage - 1) * pageSize;
  const page = filteredData.slice(start, start + pageSize);

  document.getElementById('result-count').textContent =
    fmtNum(filteredData.length) + ' of ' + fmtNum(RAW_USERS.length) + ' users';

  if (!filteredData.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-state"><div class="empty-icon">&#128269;</div><p>No users match the current filters.</p></td></tr>';
  } else {
    tbody.innerHTML = page.map(u => {
      const statusBadge = u.enabled
        ? '<span class="badge-pill badge-enabled">Enabled</span>'
        : '<span class="badge-pill badge-disabled">Disabled</span>';
      const locked = u.lockedOut ? '<span class="badge-pill badge-locked">Locked</span>' : '';
      return '<tr>' +
        '<td><strong>' + esc(u.sam) + '</strong></td>' +
        '<td class="muted">' + esc(u.display) + '</td>' +
        '<td class="mono">' + esc(u.scriptName) + '</td>' +
        '<td class="mono" title="' + esc(u.script) + '">' + esc(u.script) + '</td>' +
        '<td>' + statusBadge + locked + '</td>' +
        '<td class="muted">' + esc(u.dept) + '</td>' +
        '<td class="dim">' + esc(u.lastLogon) + '</td>' +
        '<td class="dim" title="' + esc(u.ou) + '">' + esc(u.ouShort || u.ou) + '</td>' +
        '<td><button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" data-sam="' + esc(u.sam) + '" aria-label="View detail for ' + esc(u.sam) + '">View</button></td>' +
      '</tr>';
    }).join('');
  }
  renderPagination();
  updateFooter();
}

function renderPagination(){
  const totalPages = Math.max(1, Math.ceil(filteredData.length / pageSize) || 1);
  const pg = document.getElementById('pagination');
  if (totalPages <= 1) { pg.innerHTML = ''; return; }
  let html = '<button class="page-btn" data-page="' + (currentPage - 1) + '" ' + (currentPage === 1 ? 'disabled' : '') + ' aria-label="Previous page">&#8249;</button>';
  const range = new Set([1, totalPages, currentPage, currentPage - 1, currentPage + 1, currentPage + 2, currentPage - 2].filter(p => p >= 1 && p <= totalPages));
  const sorted = [...range].sort((a,b) => a - b);
  let prev = 0;
  sorted.forEach(p => {
    if (prev && p - prev > 1) html += '<span style="color:var(--text-dim);padding:0 4px">…</span>';
    html += '<button class="page-btn ' + (p === currentPage ? 'active' : '') + '" data-page="' + p + '" aria-label="Page ' + p + '">' + p + '</button>';
    prev = p;
  });
  html += '<button class="page-btn" data-page="' + (currentPage + 1) + '" ' + (currentPage === totalPages ? 'disabled' : '') + ' aria-label="Next page">&#8250;</button>';
  pg.innerHTML = html;
}

function updateFooter(){
  const totalPages = Math.max(1, Math.ceil(filteredData.length / pageSize) || 1);
  const start = filteredData.length ? (currentPage - 1) * pageSize + 1 : 0;
  const end = Math.min(currentPage * pageSize, filteredData.length);
  document.getElementById('footer-info').textContent = filteredData.length
    ? 'Showing ' + fmtNum(start) + '–' + fmtNum(end) + ' of ' + fmtNum(filteredData.length) + ' matching users (page ' + currentPage + ' of ' + totalPages + ')'
    : 'No results';
}

function goPage(p){
  const totalPages = Math.max(1, Math.ceil(filteredData.length / pageSize) || 1);
  currentPage = Math.max(1, Math.min(Number(p) || 1, totalPages));
  renderTable();
  document.querySelector('.table-card').scrollIntoView({ behavior:'smooth', block:'nearest' });
}

document.getElementById('pagination').addEventListener('click', e => {
  const btn = e.target.closest('[data-page]');
  if (!btn || btn.disabled) return;
  goPage(btn.getAttribute('data-page'));
});

document.querySelectorAll('th[data-col]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.col;
    if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    else { sortCol = col; sortDir = 'asc'; }
    document.querySelectorAll('th[data-col]').forEach(t => {
      t.classList.remove('sorted');
      t.querySelector('.sort-icon').innerHTML = '&#8645;';
    });
    th.classList.add('sorted');
    th.querySelector('.sort-icon').innerHTML = sortDir === 'asc' ? '&#9650;' : '&#9660;';
    applyFilters(false);
  });
});

document.getElementById('table-body').addEventListener('click', e => {
  const btn = e.target.closest('[data-sam]');
  if (btn) showDetailBySam(btn.getAttribute('data-sam'));
});

function findUser(sam){
  const want = String(sam || '').toLowerCase();
  return RAW_USERS.find(u => String(u.sam || '').toLowerCase() === want) ||
         filteredData.find(u => String(u.sam || '').toLowerCase() === want);
}

function showDetailBySam(sam){
  const u = findUser(sam);
  if (!u) return;
  document.getElementById('modal-title').textContent = u.sam + ' — User Detail';
  document.getElementById('modal-body').innerHTML =
    '<div class="detail-grid">' +
      '<div class="detail-item"><label>SAM Account Name</label><div class="val mono">' + esc(u.sam) + '</div></div>' +
      '<div class="detail-item"><label>Display Name</label><div class="val">' + esc(u.display) + '</div></div>' +
      '<div class="detail-item"><label>User Principal Name</label><div class="val mono">' + esc(u.upn || 'N/A') + '</div></div>' +
      '<div class="detail-item"><label>Email</label><div class="val">' + esc(u.email || 'N/A') + '</div></div>' +
      '<div class="detail-item"><label>Status</label><div class="val">' +
        (u.enabled ? '<span class="badge-pill badge-enabled">Enabled</span>' : '<span class="badge-pill badge-disabled">Disabled</span>') +
        (u.lockedOut ? ' <span class="badge-pill badge-locked">Locked</span>' : '') +
      '</div></div>' +
      '<div class="detail-item"><label>Password never expires</label><div class="val">' + (u.pwdNeverExpires ? 'Yes' : 'No') + '</div></div>' +
      '<div class="detail-item" style="grid-column:1/-1"><label>Logon Script (Full Path)</label><div class="val mono">' + esc(u.script) + '</div></div>' +
      '<div class="detail-item"><label>Script File Name</label><div class="val mono">' + esc(u.scriptName) + '</div></div>' +
      '<div class="detail-item"><label>Normalised Path</label><div class="val mono">' + esc(u.scriptNorm) + '</div></div>' +
      '<div class="detail-item"><label>Department</label><div class="val">' + esc(u.dept) + '</div></div>' +
      '<div class="detail-item"><label>Job Title</label><div class="val">' + esc(u.title) + '</div></div>' +
      '<div class="detail-item"><label>Last Logon</label><div class="val">' + esc(u.lastLogon) + '</div></div>' +
      '<div class="detail-item"><label>Account Created</label><div class="val">' + esc(u.created) + '</div></div>' +
      '<div class="detail-item" style="grid-column:1/-1"><label>Organisational Unit</label><div class="val mono" style="font-size:12px">' + esc(u.ou) + '</div></div>' +
      '<div class="detail-item" style="grid-column:1/-1"><label>Description</label><div class="val">' + esc(u.description || '—') + '</div></div>' +
    '</div>' +
    '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
      '<button class="btn btn-primary" id="btn-filter-this-script">Filter to this script path</button>' +
      '<button class="btn btn-ghost" id="btn-filter-this-name">Filter by file name (any path)</button>' +
      '<button class="btn btn-ghost" id="btn-close-modal-2">Close</button>' +
    '</div>';
  document.getElementById('btn-filter-this-script').addEventListener('click', () => {
    closeModal();
    setScriptFilter(u.scriptNorm, '');
    applyFilters(true);
  });
  document.getElementById('btn-filter-this-name').addEventListener('click', () => {
    closeModal();
    setScriptFilter('', u.scriptName);
    applyFilters(true);
  });
  document.getElementById('btn-close-modal-2').addEventListener('click', closeModal);
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal(){ document.getElementById('modal-overlay').classList.remove('open'); }
document.getElementById('modal-close').addEventListener('click', closeModal);
document.getElementById('modal-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('modal-overlay')) closeModal();
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
  if (e.key === '/' && e.target.tagName !== 'INPUT' && e.target.tagName !== 'SELECT' && e.target.tagName !== 'TEXTAREA') {
    e.preventDefault();
    document.getElementById('search-input').focus();
  }
});

function csvCell(v){ return '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"'; }

document.getElementById('btn-export-csv').addEventListener('click', () => {
  const headers = ['SAM Account','Display Name','UPN','Email','Script Name','Script Path','Enabled','Locked Out','Department','Title','Last Logon','Created','OU'];
  const rows = filteredData.map(u => [
    u.sam, u.display, u.upn, u.email, u.scriptName, u.script,
    u.enabled ? 'Enabled' : 'Disabled',
    u.lockedOut ? 'Yes' : 'No',
    u.dept, u.title, u.lastLogon, u.created, u.ou
  ].map(csvCell).join(','));
  const csv = [headers.join(','), ...rows].join('\r\n');
  const blob = new Blob(['\uFEFF' + csv], { type:'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'AD_LogonScripts_' + new Date().toISOString().slice(0,10) + '.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('CSV exported — ' + filteredData.length + ' users', '&#128196;');
});

function exportScriptSummaryCSV(){
  const headers = ['Script Name','Full Path','Normalised Path','User Count','% of Users','Users (semicolon-sep)'];
  const rows = RAW_SCRIPTS.map(s => [
    s.name, s.script, s.scriptNorm, s.count,
    META.totalUsers > 0 ? ((s.count / META.totalUsers) * 100).toFixed(1) + '%' : '0%',
    (s.users || []).join('; ')
  ].map(csvCell).join(','));
  const csv = [headers.join(','), ...rows].join('\r\n');
  const blob = new Blob(['\uFEFF' + csv], { type:'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'AD_ScriptSummary_' + new Date().toISOString().slice(0,10) + '.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('Script summary CSV exported', '&#128196;');
}

document.querySelector('.script-card .script-card-header h3').insertAdjacentHTML(
  'afterend',
  '<button class="btn btn-ghost" style="font-size:11px;padding:4px 10px" id="btn-export-scripts" title="Export script summary CSV">CSV</button>'
);
document.getElementById('btn-export-scripts').addEventListener('click', exportScriptSummaryCSV);

document.getElementById('search-input').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => applyFilters(true), 120);
});
document.getElementById('filter-script').addEventListener('change', function(){
  if (this.value) document.getElementById('filter-scriptname').value = '';
  applyFilters(true);
});
document.getElementById('filter-scriptname').addEventListener('change', function(){
  if (this.value) document.getElementById('filter-script').value = '';
  applyFilters(true);
});
document.getElementById('filter-status').addEventListener('change', () => applyFilters(true));
document.getElementById('filter-dept').addEventListener('change', () => applyFilters(true));
document.getElementById('filter-ou').addEventListener('change', () => applyFilters(true));
document.getElementById('filter-logon').addEventListener('change', () => applyFilters(true));
document.getElementById('page-size').addEventListener('change', function(){
  pageSize = this.value === 'all' ? Number.MAX_SAFE_INTEGER : (parseInt(this.value, 10) || 25);
  applyFilters(true);
});
document.getElementById('btn-clear-filters').addEventListener('click', () => {
  document.getElementById('search-input').value = '';
  document.getElementById('filter-script').value = '';
  document.getElementById('filter-scriptname').value = '';
  document.getElementById('filter-status').value = '';
  document.getElementById('filter-dept').value = '';
  document.getElementById('filter-ou').value = '';
  document.getElementById('filter-logon').value = '';
  applyFilters(true);
});

(function init(){
  if (!Array.isArray(RAW_USERS)) { console.error('User payload is not an array'); return; }
  buildKPIs();
  buildCharts();
  buildScriptList();
  populateFilterDropdowns();
  applyFilters(true);
})();
</script>
</body>
</html>
'@

$htmlContent = $htmlContent.Replace('@@USER_DATA_JSON@@',        $userDataJson)
$htmlContent = $htmlContent.Replace('@@SCRIPT_ANALYTICS_JSON@@', $scriptAnalyticsJson)
$htmlContent = $htmlContent.Replace('@@OU_JSON@@',               $ouJson)
$htmlContent = $htmlContent.Replace('@@DEPT_JSON@@',             $deptJson)
$htmlContent = $htmlContent.Replace('@@TOTAL_USERS@@',           [string]$totalUsers)
$htmlContent = $htmlContent.Replace('@@UNIQUE_SCRIPTS@@',        [string]$uniqueScripts)
$htmlContent = $htmlContent.Replace('@@ENABLED_COUNT@@',         [string]$enabledCount)
$htmlContent = $htmlContent.Replace('@@DISABLED_COUNT@@',        [string]$disabledCount)
$htmlContent = $htmlContent.Replace('@@REPORT_GEN_TIME@@',       $reportGenTime)
$htmlContent = $htmlContent.Replace('@@REPORT_DOMAIN@@',         $reportDomain)

#endregion

#region ── Write HTML File ───────────────────────────────────────────────────────

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $pickerUsed = $false
    $interactive = $false
    try {
        $interactive = [Environment]::UserInteractive -and $Host.Name -ne 'ServerRemoteHost'
    }
    catch { $interactive = $false }

    if ($interactive) {
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
            $saveDialog                  = New-Object System.Windows.Forms.SaveFileDialog
            $timestamp                   = Get-Date -Format 'yyyyMMdd_HHmmss'
            $saveDialog.Title            = 'Save AD Logon Script Report'
            $saveDialog.Filter           = 'HTML Report (*.html)|*.html|All Files (*.*)|*.*'
            $saveDialog.DefaultExt       = 'html'
            $saveDialog.FileName         = "Get-LogonScriptReport_$timestamp.html"
            $startDir = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
                $PSScriptRoot
            }
            else {
                [System.Environment]::GetFolderPath('Desktop')
            }
            $saveDialog.InitialDirectory = $startDir
            $dialogResult = $saveDialog.ShowDialog()
            if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK -and
                -not [string]::IsNullOrWhiteSpace($saveDialog.FileName)) {
                $OutputPath = $saveDialog.FileName
                $pickerUsed = $true
                Write-Info "Output path selected via file picker."
            }
            else {
                Write-Warn "File picker was cancelled. Falling back to default output location."
            }
        }
        catch {
            Write-Warn "Windows Forms not available — skipping file picker. ($_)"
        }
    }

    if (-not $pickerUsed) {
        $scriptDir = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } else { $PWD.Path }
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $OutputPath = Join-Path $scriptDir "Get-LogonScriptReport_$timestamp.html"
    }
}

$outputDir = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($outputDir) -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

Write-Step "Writing HTML report to: $OutputPath"
try {
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($OutputPath, $htmlContent, $utf8NoBom)
}
catch {
    Write-Host "  [ERROR] Could not write file: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$fileSize = (Get-Item $OutputPath).Length
Write-Success "HTML report written successfully."
Write-Info "File size : $([math]::Round($fileSize / 1KB, 1)) KB"
Write-Info "File path : $OutputPath"

#endregion

#region ── Console Summary ──────────────────────────────────────────────────────

Write-Header "Report Summary"
Write-Host ""
Write-Host "  Domain Queried      : " -NoNewline -ForegroundColor White
Write-Host $reportDomain -ForegroundColor Cyan
Write-Host "  Total Users Found   : " -NoNewline -ForegroundColor White
Write-Host $totalUsers -ForegroundColor Cyan
Write-Host "  Unique Scripts      : " -NoNewline -ForegroundColor White
Write-Host $uniqueScripts -ForegroundColor Cyan
Write-Host "  Enabled Users       : " -NoNewline -ForegroundColor White
Write-Host $enabledCount -ForegroundColor Green
Write-Host "  Disabled Users      : " -NoNewline -ForegroundColor White
Write-Host $disabledCount -ForegroundColor Red
Write-Host ""
Write-Host "  -- Top 10 Scripts ------------------------------------------------" -ForegroundColor DarkCyan
$top10 = $scriptUsageMap.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
$rank = 1
foreach ($item in $top10) {
    $pct  = if ($totalUsers -gt 0) { [math]::Round(($item.Value / $totalUsers) * 100, 1) } else { 0 }
    $name = Get-ScriptFileName $(if ($scriptDisplay.ContainsKey($item.Key)) { $scriptDisplay[$item.Key] } else { $item.Key })
    Write-Host ("  {0,2}. {1,-35} {2,4} users ({3}%)" -f $rank, $name, $item.Value, $pct) -ForegroundColor White
    $rank++
}

Write-Host ""
Write-Host "  -- Output File ---------------------------------------------------" -ForegroundColor DarkCyan
Write-Host "  $OutputPath" -ForegroundColor Yellow
Write-Host ""

if (-not $NoLaunch) {
    try {
        Write-Step "Opening report in default browser..."
        Start-Process $OutputPath
        Write-Success "Report opened in browser."
    }
    catch {
        Write-Warn "Could not auto-open browser. Open the file manually: $OutputPath"
    }
}

Write-Header "Completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

#endregion

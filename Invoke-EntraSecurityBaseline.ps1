#Requires -Version 5.1
<#
.SYNOPSIS
    Runs an interactive Microsoft Entra ID security baseline assessment and produces a
    modern, self-contained interactive HTML report with charts and detailed findings.

.DESCRIPTION
    This single script recreates four Maester test suites as standalone, live Microsoft
    Graph checks (no dependency on the Maester module):

        * Authentication Method Baseline   (MT.1067)
        * Conditional Access Baseline      (MT.1001 - MT.1184, licensing, security defaults)
        * Conditional Access WhatIf        (MT.1033 / MT.1034 legacy-auth evaluation)
        * Entra Recommendations            (MT.1024 directory recommendations)

    Each check queries Microsoft Graph directly. Complex Maester behaviours that cannot be
    faithfully reproduced with a single Graph query (e.g. Restricted Management Admin Units,
    exclusion fallback gap analysis, live CA WhatIf evaluation) are implemented as documented
    best-effort approximations and are clearly flagged in the report.

    The resulting HTML report is completely self-contained: all CSS and JavaScript (including
    the charting engine, which is hand-written with inline SVG) are embedded, so the report
    works fully offline with no internet connection and no external CDN.

    Bugs fixed vs. the original script:
    - Windows PowerShell 5.1 ConvertTo-Json unwraps single-element arrays, so a 1-test run
      produced `results: { ... }` instead of `results: [ ... ]` and the report JS crashed.
    - JSON was spliced into a <script> tag without escaping `<`, so a finding containing
      `</script>` terminated the page.
    - Conditional Access policies were loaded from v1.0, which omits authenticationFlows
      (MT.1052 device-code) and some guest/location fields. Policies are now fetched from beta.
    - $org.value[0] threw under StrictMode when Graph returned a single organization object.
    - $outcome.ContainsKey('__Expand') threw when a check returned $null or a non-hashtable.
    - MT.1024 treated dismissed / postponed recommendations as Fail (Maester skips dismissed).
    - P1 license utilization picked the first SKU that contained AAD_PREMIUM, often a P2/E5
      SKU, and compared the wrong prepaid/consumed counts.
    - Plan detection counted disabled service plans, so a tenant could be labelled P2
      incorrectly and Identity Protection checks would run.
    - Context load (CA policies / SKUs / organization) had no error handling, so one Graph
      failure aborted the whole assessment with no report.
    - Connect-Graph discarded Get-MgContext, leaving TenantId as Unknown if /organization failed.
    - Group/user existence checks issued one GET per object (throttling). They now use
      directoryObjects/getByIds with a GET fallback.
    - TLS 1.2 was never enabled; Graph and Install-Module fail on stock Windows PowerShell 5.1.
    - Graph sessions were left open on error paths. Disconnect-MgGraph runs in finally.
    - -WhatIfUserCount was accepted but never used.
    - MT.1011 passed if a locations object existed even when includeLocations was empty.
    - MT.1017 passed if persistent-browser was enabled, including mode=always (the opposite
      of non-persistent sessions).

.PARAMETER TenantId
    Optional tenant id or domain to connect to.

.PARAMETER OutputPath
    Path to write the HTML report. Defaults to EntraSecurityBaseline_<timestamp>.html in the
    current directory.

.PARAMETER Scopes
    Microsoft Graph delegated scopes to request. Sensible read-only defaults are provided.

.PARAMETER IncludeSuite
    One or more suites to run. Defaults to all. Valid: Authentication, ConditionalAccess,
    WhatIf, Recommendations.

.PARAMETER WhatIfUserCount
    Number of sample member users to evaluate for the WhatIf legacy-auth suite.

.PARAMETER DemoMode
    Generate the report from bundled realistic sample data with no tenant / Graph connection.
    Useful for previewing the report design.

.PARAMETER DeviceCode
    Use device-code authentication instead of the WAM / broker popup. Recommended in an
    elevated console, PowerShell ISE, or when the sign-in window never appears.

.PARAMETER NoLaunch
    Do not open the HTML report in the default browser when finished.

.PARAMETER SkipDisconnect
    Leave the Microsoft Graph session connected when the script ends.

.PARAMETER SelfTest
    Run built-in unit tests (JSON encoding, StrictMode helpers, demo report generation)
    and exit. Does not connect to Microsoft Graph.

.EXAMPLE
    .\Invoke-EntraSecurityBaseline.ps1

.EXAMPLE
    .\Invoke-EntraSecurityBaseline.ps1 -TenantId contoso.onmicrosoft.com -OutputPath C:\Reports\entra.html

.EXAMPLE
    .\Invoke-EntraSecurityBaseline.ps1 -DemoMode

.EXAMPLE
    .\Invoke-EntraSecurityBaseline.ps1 -SelfTest
#>
[CmdletBinding()]
param(
    [string] $TenantId,

    [string] $OutputPath,

    [string[]] $Scopes = @(
        'Policy.Read.All',
        'Directory.Read.All',
        'DirectoryRecommendations.Read.All',
        'Application.Read.All',
        'Group.Read.All',
        'User.Read.All'
    ),

    [ValidateSet('Authentication', 'ConditionalAccess', 'WhatIf', 'Recommendations')]
    [string[]] $IncludeSuite = @('Authentication', 'ConditionalAccess', 'WhatIf', 'Recommendations'),

    [int] $WhatIfUserCount = 5,

    [switch] $DemoMode,

    [switch] $DeviceCode,

    [switch] $NoLaunch,

    [switch] $SkipDisconnect,

    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:BuildStamp = '2026-09-11-a'
$script:WeConnected = $false
$script:IncludeSuite = @($IncludeSuite)
$script:WhatIfUserCount = [Math]::Max(1, $WhatIfUserCount)

# ----------------------------------------------------------------------------------------------
# Well-known identifiers
# ----------------------------------------------------------------------------------------------
$script:AppIds = @{
    AzureManagement = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
    AzureDevOps     = '499b84ac-1321-427f-aa17-267ca6975798'
    ExchangeOnline  = '00000002-0000-0ff1-ce00-000000000000'
}

# ----------------------------------------------------------------------------------------------
# Result collection
# ----------------------------------------------------------------------------------------------
$script:Results = New-Object System.Collections.ArrayList

function Add-Result {
    [CmdletBinding()]
    param(
        [string] $Id,
        [string] $Title,
        [string] $Category,
        [ValidateSet('High', 'Medium', 'Low', 'Info')]
        [string] $Severity = 'Medium',
        [ValidateSet('Pass', 'Fail', 'Skipped', 'Error')]
        [string] $Status,
        [string] $Result,
        [string] $Details,
        [string] $DocsUrl,
        [switch] $Approximation
    )
    $null = $script:Results.Add([pscustomobject]@{
            Id            = $Id
            Title         = $Title
            Category      = $Category
            Severity      = $Severity
            Status        = $Status
            Result        = $Result
            Details       = $Details
            DocsUrl       = $DocsUrl
            Approximation = [bool]$Approximation
        })
}

function Write-Section {
    param([string] $Message)
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
}

function Enable-Tls12 {
    # Windows PowerShell 5.1 / .NET 4.x still defaults to TLS 1.0/1.1.
    $tls12 = [Net.SecurityProtocolType]::Tls12
    try {
        $current = [Net.ServicePointManager]::SecurityProtocol
        if (($current -band $tls12) -ne $tls12) {
            [Net.ServicePointManager]::SecurityProtocol = $current -bor $tls12
        }
    }
    catch {
        try { [Net.ServicePointManager]::SecurityProtocol = $tls12 } catch { }
    }
}

function ConvertTo-InvariantNumber([object] $Value) {
    return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-ReportJson {
    <#
        Portable JSON serializer that:
          * Never unwraps single-element arrays (Windows PowerShell 5.1 ConvertTo-Json does)
          * Escapes < > / so payload can be embedded inside a <script> tag
    #>
    param($InputObject, [int] $Depth = 0)

    if ($Depth -gt 40) { return 'null' }
    if ($null -eq $InputObject) { return 'null' }

    if ($InputObject -is [bool]) {
        if ($InputObject) { return 'true' } else { return 'false' }
    }
    if ($InputObject -is [string] -or $InputObject -is [char]) {
        return '"' + (Escape-ReportJsonString ([string]$InputObject)) + '"'
    }
    if ($InputObject -is [datetime]) {
        return '"' + (Escape-ReportJsonString ($InputObject.ToString('o'))) + '"'
    }
    if ($InputObject -is [guid]) {
        return '"' + (Escape-ReportJsonString ($InputObject.ToString())) + '"'
    }
    if ($InputObject -is [enum]) {
        return '"' + (Escape-ReportJsonString ($InputObject.ToString())) + '"'
    }
    if ($InputObject -is [decimal] -or $InputObject -is [double] -or $InputObject -is [float] -or
        $InputObject -is [byte] -or $InputObject -is [int16] -or $InputObject -is [uint16] -or
        $InputObject -is [int] -or $InputObject -is [uint32] -or $InputObject -is [int64] -or
        $InputObject -is [uint64]) {
        if ($InputObject -is [double] -or $InputObject -is [float]) {
            if ([double]::IsNaN([double]$InputObject) -or [double]::IsInfinity([double]$InputObject)) { return 'null' }
        }
        return (ConvertTo-InvariantNumber $InputObject)
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $parts = New-Object System.Collections.ArrayList
        foreach ($key in $InputObject.Keys) {
            $null = $parts.Add(('"{0}":{1}' -f (Escape-ReportJsonString ([string]$key)), (ConvertTo-ReportJson $InputObject[$key] ($Depth + 1))))
        }
        return '{' + ($parts -join ',') + '}'
    }

    if ($InputObject -is [System.Collections.IEnumerable]) {
        $parts = New-Object System.Collections.ArrayList
        foreach ($item in $InputObject) {
            $null = $parts.Add((ConvertTo-ReportJson $item ($Depth + 1)))
        }
        return '[' + ($parts -join ',') + ']'
    }

    $props = @($InputObject.PSObject.Properties | Where-Object { $_.MemberType -match 'NoteProperty|Property' })
    if ($props.Count -gt 0) {
        $parts = New-Object System.Collections.ArrayList
        foreach ($p in $props) {
            $null = $parts.Add(('"{0}":{1}' -f (Escape-ReportJsonString ([string]$p.Name)), (ConvertTo-ReportJson $p.Value ($Depth + 1))))
        }
        return '{' + ($parts -join ',') + '}'
    }

    return '"' + (Escape-ReportJsonString ([string]$InputObject)) + '"'
}

function Escape-ReportJsonString {
    param([string] $Value)
    if ($null -eq $Value) { return '' }
    $sb = New-Object System.Text.StringBuilder ($Value.Length + 16)
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int]$ch
        switch ($code) {
            34 { [void]$sb.Append('\'); [void]$sb.Append('"') }
            92 { [void]$sb.Append('\\') }
            8  { [void]$sb.Append('\b') }
            12 { [void]$sb.Append('\f') }
            10 { [void]$sb.Append('\n') }
            13 { [void]$sb.Append('\r') }
            9  { [void]$sb.Append('\t') }
            47 { [void]$sb.Append('\u002f') }
            60 { [void]$sb.Append('\u003c') }
            62 { [void]$sb.Append('\u003e') }
            default {
                if ($code -lt 32) {
                    [void]$sb.Append(('\u{0:x4}' -f $code))
                }
                else {
                    [void]$sb.Append($ch)
                }
            }
        }
    }
    return $sb.ToString()
}

function Get-OutcomeValue {
    param($Outcome, [string] $Name)
    if ($null -eq $Outcome) { return $null }
    if ($Outcome -is [System.Collections.IDictionary]) {
        if ($Outcome.Contains($Name)) { return $Outcome[$Name] }
        return $null
    }
    return (Get-Prop $Outcome $Name)
}

function Test-OutcomeHasExpand {
    param($Outcome)
    if ($null -eq $Outcome) { return $false }
    if ($Outcome -is [System.Collections.IDictionary]) { return $Outcome.Contains('__Expand') }
    return $null -ne (Get-Prop $Outcome '__Expand')
}

# ----------------------------------------------------------------------------------------------
# Graph helpers
# ----------------------------------------------------------------------------------------------
function Connect-Graph {
    param([string] $TenantId, [string[]] $Scopes, [switch] $DeviceCode)

    Enable-Tls12

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host "The Microsoft.Graph.Authentication module is required." -ForegroundColor Yellow
        $answer = Read-Host "Install it now from the PSGallery for the current user? (Y/N)"
        if ($answer -match '^(y|yes)$') {
            try {
                $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
                if (-not $nuget -or $nuget.Version -lt [version]'2.8.5.201') {
                    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
                }
            }
            catch { }
            Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
        }
        else {
            throw "Microsoft.Graph.Authentication is required to run live checks. Re-run with -DemoMode to preview the report."
        }
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $connectParams = @{ Scopes = $Scopes }
    $cmd = Get-Command Connect-MgGraph -ErrorAction Stop
    if ($cmd.Parameters.ContainsKey('NoWelcome')) { $connectParams['NoWelcome'] = $true }
    if ($TenantId) { $connectParams['TenantId'] = $TenantId }
    if ($DeviceCode -and $cmd.Parameters.ContainsKey('UseDeviceAuthentication')) {
        $connectParams['UseDeviceAuthentication'] = $true
    }

    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Gray
    Connect-MgGraph @connectParams | Out-Null

    $ctx = Get-MgContext
    if (-not $ctx) { throw "Failed to establish a Microsoft Graph context." }
    Write-Host ("Connected to tenant: {0}" -f $ctx.TenantId) -ForegroundColor Green
    return $ctx
}

function Invoke-GraphRequest {
    <#
        Wrapper around Invoke-MgGraphRequest that returns a single response object (PSObject).
    #>
    param(
        [string] $Uri,
        [ValidateSet('v1.0', 'beta')]
        [string] $ApiVersion = 'v1.0',
        [ValidateSet('GET', 'POST')]
        [string] $Method = 'GET',
        $Body
    )
    if ($Uri -match '^https?://') { $full = $Uri }
    else { $full = "https://graph.microsoft.com/$ApiVersion/$Uri" }

    $params = @{ Method = $Method; Uri = $full }
    $cmd = Get-Command Invoke-MgGraphRequest -ErrorAction Stop
    if ($cmd.Parameters.ContainsKey('OutputType')) { $params['OutputType'] = 'PSObject' }
    if ($null -ne $Body) {
        $params['Body'] = $Body
        if ($cmd.Parameters.ContainsKey('ContentType')) { $params['ContentType'] = 'application/json' }
    }
    return Invoke-MgGraphRequest @params
}

function Invoke-GraphCollection {
    <#
        Returns all items of a collection endpoint, following @odata.nextLink paging.
    #>
    param(
        [string] $Uri,
        [ValidateSet('v1.0', 'beta')]
        [string] $ApiVersion = 'v1.0',
        [int] $MaxPages = 200
    )
    $items = New-Object System.Collections.ArrayList
    $next = "https://graph.microsoft.com/$ApiVersion/$Uri"
    $pages = 0
    while ($next) {
        $pages++
        if ($pages -gt $MaxPages) {
            Write-Warning "Stopped paging $Uri after $MaxPages pages."
            break
        }
        $resp = Invoke-GraphRequest -Uri $next
        $value = Get-Prop $resp 'value'
        if ($null -ne $value) {
            foreach ($v in @($value)) { $null = $items.Add($v) }
        }
        $next = Get-Prop $resp '@odata.nextLink'
        if (-not $next) { $next = Get-Prop $resp 'odata.nextLink' }
    }
    return @($items)
}

function Get-Prop {
    <#
        Safely walk a dotted property path on a PSObject/Hashtable, returning $null if any
        segment is missing. Works under StrictMode.
    #>
    param($InputObject, [string] $Path)
    if ($null -eq $InputObject -or [string]::IsNullOrWhiteSpace($Path)) { return $null }
    $current = $InputObject
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Collections.IDictionary]) {
            if ($current.Contains($segment)) {
                $current = $current[$segment]
                continue
            }
            $matched = $false
            foreach ($k in @($current.Keys)) {
                if ([string]$k -eq $segment) {
                    $current = $current[$k]
                    $matched = $true
                    break
                }
            }
            if ($matched) { continue }
            return $null
        }
        $prop = $null
        try { $prop = $current.PSObject.Properties[$segment] } catch { $prop = $null }
        if ($null -eq $prop) { return $null }
        $current = $prop.Value
    }
    return $current
}

function Get-FirstItem {
    param($Value)
    # Use @() wrapping, not pipeline enumeration — a string piped to Where-Object yields chars.
    if ($null -eq $Value) { return $null }
    $arr = @($Value)
    if ($arr.Count -eq 0) { return $null }
    return $arr[0]
}

function Test-ArrayContains {
    param($Array, [string] $Value)
    if ($null -eq $Array) { return $false }
    foreach ($item in @($Array)) {
        if ("$item".ToLowerInvariant() -eq $Value.ToLowerInvariant()) { return $true }
    }
    return $false
}

function Get-MissingDirectoryObjects {
    param([string[]] $Ids)
    $special = '^(All|None|GuestsOrExternalUsers|all_users)$'
    $unique = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($Ids)) {
        if ($id -and ($id -notmatch $special)) { $null = $unique.Add([string]$id) }
    }
    if ($unique.Count -eq 0) { return @() }

    $missing = New-Object System.Collections.ArrayList
    $all = @($unique)
    for ($i = 0; $i -lt $all.Count; $i += 900) {
        $end = [Math]::Min($i + 899, $all.Count - 1)
        $chunk = [System.Collections.Generic.List[string]]::new()
        foreach ($id in @($all[$i..$end])) { $chunk.Add([string]$id) }

        $found = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
        $batched = $false
        try {
            $types = [System.Collections.Generic.List[string]]::new()
            foreach ($t in @('user', 'group', 'directoryRole')) { $types.Add($t) }
            $body = @{ ids = $chunk; types = $types }
            $resp = Invoke-GraphRequest -Uri 'directoryObjects/getByIds' -Method POST -Body $body
            foreach ($obj in @(Get-Prop $resp 'value')) {
                $oid = Get-Prop $obj 'id'
                if ($oid) { $null = $found.Add([string]$oid) }
            }
            $batched = $true
        }
        catch { $batched = $false }

        if (-not $batched) {
            foreach ($id in $chunk) {
                try {
                    $null = Invoke-GraphRequest -Uri ("directoryObjects/{0}?`$select=id" -f $id)
                    $null = $found.Add([string]$id)
                }
                catch { }
            }
        }

        foreach ($id in $chunk) {
            if (-not $found.Contains([string]$id)) { $null = $missing.Add([string]$id) }
        }
    }
    return @($missing)
}

function Get-SkuUtilization {
    param([string] $ServicePlanName)
    $entitled = 0
    $consumed = 0
    $found = $false
    foreach ($sku in @($script:Ctx.Skus)) {
        $hasPlan = $false
        foreach ($sp in @(Get-Prop $sku 'servicePlans')) {
            if ((Get-Prop $sp 'servicePlanName') -eq $ServicePlanName) {
                $prov = Get-Prop $sp 'provisioningStatus'
                if (-not $prov -or $prov -eq 'Success') { $hasPlan = $true }
            }
        }
        if ($hasPlan) {
            $found = $true
            $enabled = Get-Prop $sku 'prepaidUnits.enabled'
            $used = Get-Prop $sku 'consumedUnits'
            if ($null -ne $enabled) { $entitled += [int]$enabled }
            if ($null -ne $used) { $consumed += [int]$used }
        }
    }
    return @{ Found = $found; Entitled = $entitled; Consumed = $consumed }
}

function Resolve-RecommendationStatus {
    param([string] $GraphStatus)
    $s = "$GraphStatus".ToLowerInvariant()
    switch ($s) {
        'completedbysystem' { return 'Pass' }
        'dismissed' { return 'Skipped' }
        default { return 'Fail' }
    }
}

# ----------------------------------------------------------------------------------------------
# Tenant context gathering (fetched once, reused by many checks)
# ----------------------------------------------------------------------------------------------
$script:Ctx = @{
    CaPolicies      = @()
    EnabledPolicies = @()
    Skus            = @()
    Plan            = 'Unknown'
    TenantId        = 'Unknown'
    TenantName      = 'Unknown'
}

function Initialize-TenantContext {
    param($GraphContext)

    if ($GraphContext) {
        $tid = Get-Prop $GraphContext 'TenantId'
        if ($tid) { $script:Ctx.TenantId = [string]$tid }
    }

    try {
        Write-Host "Loading Conditional Access policies (Graph beta)..." -ForegroundColor Gray
        # beta includes authenticationFlows, guest conditions, and other fields missing from v1.0
        $script:Ctx.CaPolicies = @(Invoke-GraphCollection -Uri 'identity/conditionalAccess/policies' -ApiVersion 'beta')
    }
    catch {
        Write-Warning ("Failed to load Conditional Access policies: {0}" -f $_.Exception.Message)
        $script:Ctx.CaPolicies = @()
    }
    $script:Ctx.EnabledPolicies = @($script:Ctx.CaPolicies | Where-Object { (Get-Prop $_ 'state') -eq 'enabled' })

    try {
        Write-Host "Loading subscribed SKUs (licensing)..." -ForegroundColor Gray
        $script:Ctx.Skus = @(Invoke-GraphCollection -Uri 'subscribedSkus')
    }
    catch {
        Write-Warning ("Failed to load subscribed SKUs: {0}" -f $_.Exception.Message)
        $script:Ctx.Skus = @()
    }

    $planNames = New-Object System.Collections.Generic.HashSet[string]
    foreach ($sku in @($script:Ctx.Skus)) {
        foreach ($sp in @(Get-Prop $sku 'servicePlans')) {
            $name = Get-Prop $sp 'servicePlanName'
            $prov = Get-Prop $sp 'provisioningStatus'
            if ($name -and (-not $prov -or $prov -eq 'Success')) { $null = $planNames.Add([string]$name) }
        }
    }
    if ($planNames.Contains('AAD_PREMIUM_P2')) { $script:Ctx.Plan = 'P2' }
    elseif ($planNames.Contains('AAD_PREMIUM')) { $script:Ctx.Plan = 'P1' }
    elseif (@($script:Ctx.Skus).Count -gt 0) { $script:Ctx.Plan = 'Free' }
    else { $script:Ctx.Plan = 'Unknown' }

    try {
        $org = Invoke-GraphRequest -Uri 'organization?$select=id,displayName'
        $first = Get-FirstItem (Get-Prop $org 'value')
        if ($first) {
            $oid = Get-Prop $first 'id'
            $oname = Get-Prop $first 'displayName'
            if ($oid) { $script:Ctx.TenantId = [string]$oid }
            if ($oname) { $script:Ctx.TenantName = [string]$oname }
        }
    }
    catch {
        Write-Warning ("Failed to load organization: {0}" -f $_.Exception.Message)
    }

    Write-Host ("Entra ID plan detected: {0}  |  Policies: {1} ({2} enabled)" -f `
            $script:Ctx.Plan, @($script:Ctx.CaPolicies).Count, @($script:Ctx.EnabledPolicies).Count) -ForegroundColor Green
}

# ----------------------------------------------------------------------------------------------
# Predicate helpers over a single CA policy
# ----------------------------------------------------------------------------------------------
function Test-PolicyHasMfa {
    param($Policy)
    $controls = Get-Prop $Policy 'grantControls.builtInControls'
    if (Test-ArrayContains $controls 'mfa') { return $true }
    if (Get-Prop $Policy 'grantControls.authenticationStrength') { return $true }
    return $false
}
function Test-PolicyHasControl {
    param($Policy, [string] $Control)
    return (Test-ArrayContains (Get-Prop $Policy 'grantControls.builtInControls') $Control)
}
function Test-PolicyAllUsers {
    param($Policy)
    return (Test-ArrayContains (Get-Prop $Policy 'conditions.users.includeUsers') 'All')
}
function Test-PolicyAllApps {
    param($Policy)
    return (Test-ArrayContains (Get-Prop $Policy 'conditions.applications.includeApplications') 'All')
}
function Test-PolicyTargetsAdmins {
    param($Policy)
    $roles = Get-Prop $Policy 'conditions.users.includeRoles'
    return ($null -ne $roles -and @($roles).Count -gt 0)
}
function Test-PolicyTargetsGuests {
    param($Policy)
    if (Test-ArrayContains (Get-Prop $Policy 'conditions.users.includeUsers') 'GuestsOrExternalUsers') { return $true }
    if (Get-Prop $Policy 'conditions.users.includeGuestsOrExternalUsers') { return $true }
    return $false
}
function Test-PolicyHasLocations {
    param($Policy)
    $include = @(Get-Prop $Policy 'conditions.locations.includeLocations' | Where-Object { $_ })
    return ($include.Count -gt 0)
}
function Format-PolicyList {
    param($Policies)
    $arr = @($Policies)
    if ($arr.Count -eq 0) { return "" }
    $names = @($arr | ForEach-Object { "- " + (Get-Prop $_ 'displayName') })
    return "`n`nMatching policies:`n" + ($names -join "`n")
}

# ----------------------------------------------------------------------------------------------
# CHECK DEFINITIONS
# Each returns a hashtable: @{ Status; Result; Details }
# ----------------------------------------------------------------------------------------------
function Get-CheckDefinitions {
    $defs = New-Object System.Collections.ArrayList

    function Add-Def {
        param($Id, $Title, $Category, $Severity, $DocsUrl, [scriptblock] $Test, [switch] $Approximation)
        $null = $defs.Add(@{
                Id            = $Id
                Title         = $Title
                Category      = $Category
                Severity      = $Severity
                DocsUrl       = $DocsUrl
                Test          = $Test
                Approximation = [bool]$Approximation
            })
    }

    # ---------------- Authentication method baseline ----------------
    if ($script:IncludeSuite -contains 'Authentication') {
        Add-Def 'MT.1067' 'Authentication method policies should not reference non-existent groups' `
            'Authentication' 'High' 'https://maester.dev/docs/tests/MT.1067' {
            $policy = Invoke-GraphRequest -Uri 'policies/authenticationMethodsPolicy' -ApiVersion 'v1.0'
            $configs = @(Get-Prop $policy 'authenticationMethodConfigurations')
            $groupIds = New-Object System.Collections.ArrayList
            $refs = New-Object System.Collections.ArrayList
            foreach ($cfg in $configs) {
                $cfgId = Get-Prop $cfg 'id'
                $targets = @()
                $targets += @(Get-Prop $cfg 'includeTargets')
                $targets += @(Get-Prop $cfg 'excludeTargets')
                foreach ($t in $targets) {
                    if (-not $t) { continue }
                    if ((Get-Prop $t 'targetType') -eq 'group') {
                        $gid = Get-Prop $t 'id'
                        if ($gid -and $gid -ne 'all_users') {
                            $null = $groupIds.Add($gid)
                            $null = $refs.Add("$cfgId -> $gid")
                        }
                    }
                }
            }
            $missingIds = @(Get-MissingDirectoryObjects -Ids @($groupIds))
            if ($missingIds.Count -eq 0) {
                return @{ Status = 'Pass'; Result = "All groups referenced by authentication method policies exist." ; Details = "No remediation required." }
            }
            $missingRefs = @($refs | Where-Object {
                    $line = $_
                    @($missingIds | Where-Object { $line -like "*$_" }).Count -gt 0
                })
            return @{ Status = 'Fail'
                Result  = "Authentication method policies reference deleted or non-existent groups:`n- " + ($missingRefs -join "`n- ")
                Details = "Remove references to deleted groups from the affected authentication method configurations."
            }
        }
    }

    # ---------------- Conditional Access baseline ----------------
    if ($script:IncludeSuite -contains 'ConditionalAccess') {

        Add-Def 'MT.1001' 'A CA policy requires device compliance' 'Conditional Access' 'Medium' 'https://maester.dev/docs/tests/MT.1001' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object { Test-PolicyHasControl $_ 'compliantDevice' })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "At least one enabled policy requires device compliance." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy requires device compliance."; Details = 'Create a policy that requires a compliant device.' }
        }

        Add-Def 'MT.1003' 'A CA policy is scoped to All Apps' 'Conditional Access' 'Low' 'https://maester.dev/docs/tests/MT.1003' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object { Test-PolicyAllApps $_ })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "At least one enabled policy targets All Apps." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy targets All Apps."; Details = 'Scope a baseline policy to All cloud apps.' }
        }

        Add-Def 'MT.1004' 'A CA policy is scoped to All Apps and All Users' 'Conditional Access' 'Medium' 'https://maester.dev/docs/tests/MT.1004' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object { (Test-PolicyAllApps $_) -and (Test-PolicyAllUsers $_) })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "At least one enabled policy targets All Apps and All Users." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy targets both All Apps and All Users."; Details = 'Create a broad baseline policy for All apps + All users.' }
        }

        Add-Def 'MT.1005' 'All CA policies exclude an emergency / break-glass account or group' 'Conditional Access' 'High' 'https://maester.dev/docs/tests/MT.1005' {
            $offenders = New-Object System.Collections.ArrayList
            foreach ($p in $script:Ctx.EnabledPolicies) {
                $exUsers = @(Get-Prop $p 'conditions.users.excludeUsers' | Where-Object { $_ })
                $exGroups = @(Get-Prop $p 'conditions.users.excludeGroups' | Where-Object { $_ })
                if (($exUsers.Count + $exGroups.Count) -eq 0) { $null = $offenders.Add((Get-Prop $p 'displayName')) }
            }
            if ($offenders.Count -eq 0) { return @{ Status = 'Pass'; Result = "Every enabled policy excludes at least one user or group (candidate break-glass exclusion)."; Details = 'Approximation: verify the excluded objects are your emergency access accounts.' } }
            return @{ Status = 'Fail'; Result = "Policies with no user/group exclusion (no break-glass safety):`n- " + ($offenders -join "`n- "); Details = 'Exclude your emergency access account/group from every enabled policy.' }
        } -Approximation

        Add-Def 'MT.1006' 'A CA policy requires MFA for admins' 'Conditional Access' 'High' 'https://maester.dev/docs/tests/MT.1006' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object { (Test-PolicyTargetsAdmins $_) -and (Test-PolicyHasMfa $_) })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "MFA is required for admin roles." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy requires MFA for admins."; Details = 'Require MFA for all privileged directory roles.' }
        }

        Add-Def 'MT.1007' 'A CA policy requires MFA for all users' 'Conditional Access' 'High' 'https://maester.dev/docs/tests/MT.1007' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object { (Test-PolicyAllUsers $_) -and (Test-PolicyHasMfa $_) })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "MFA is required for all users." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy requires MFA for all users."; Details = 'Require MFA for All users (excluding break-glass).' }
        }

        Add-Def 'MT.1008' 'A CA policy requires MFA for Azure management' 'Conditional Access' 'High' 'https://maester.dev/docs/tests/MT.1008' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object {
                    (
                        (Test-ArrayContains (Get-Prop $_ 'conditions.applications.includeApplications') $script:AppIds.AzureManagement) -or
                        (Test-PolicyAllApps $_)
                    ) -and (Test-PolicyHasMfa $_)
                })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "MFA is required for Azure management." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy requires MFA for the Microsoft Azure Management app."; Details = 'Require MFA for the Windows Azure Service Management API app.' }
        }

        Add-Def 'MT.1009' 'A CA policy blocks other legacy authentication' 'Conditional Access' 'High' 'https://maester.dev/docs/tests/MT.1009' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object { (Test-ArrayContains (Get-Prop $_ 'conditions.clientAppTypes') 'other') -and (Test-PolicyHasControl $_ 'block') })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "Legacy 'other clients' authentication is blocked." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy blocks 'other clients' legacy authentication."; Details = 'Create a policy that blocks legacy authentication clients.' }
        }

        Add-Def 'MT.1010' 'A CA policy blocks legacy Exchange ActiveSync' 'Conditional Access' 'High' 'https://maester.dev/docs/tests/MT.1010' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object { (Test-ArrayContains (Get-Prop $_ 'conditions.clientAppTypes') 'exchangeActiveSync') -and (Test-PolicyHasControl $_ 'block') })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "Legacy Exchange ActiveSync is blocked." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy blocks legacy Exchange ActiveSync."; Details = 'Block the exchangeActiveSync legacy client app type.' }
        }

        Add-Def 'MT.1011' 'A CA policy secures security info registration to trusted locations' 'Conditional Access' 'Medium' 'https://maester.dev/docs/tests/MT.1011' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object {
                    (Test-ArrayContains (Get-Prop $_ 'conditions.applications.includeUserActions') 'urn:user:registersecurityinfo') -and
                    (Test-PolicyHasLocations $_)
                })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "Security info registration is protected by a location condition." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy secures security info registration from a trusted location."; Details = 'Restrict the Register security info user action to trusted locations.' }
        }

        Add-Def 'MT.1012' 'A CA policy requires MFA for risky sign-ins' 'Conditional Access' 'High' 'https://maester.dev/docs/tests/MT.1012' {
            if ($script:Ctx.Plan -ne 'P2') { return @{ Status = 'Skipped'; Result = "Requires Entra ID P2 (Identity Protection). Detected plan: $($script:Ctx.Plan)."; Details = 'Skipped due to licensing.' } }
            $m = @($script:Ctx.EnabledPolicies | Where-Object { ((@(Get-Prop $_ 'conditions.signInRiskLevels') | Where-Object { $_ }).Count -gt 0) -and (Test-PolicyHasMfa $_) })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "MFA is required for risky sign-ins." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy requires MFA for risky sign-ins."; Details = 'Require MFA when sign-in risk is medium or high.' }
        }

        Add-Def 'MT.1013' 'A CA policy requires password change for high user risk' 'Conditional Access' 'High' 'https://maester.dev/docs/tests/MT.1013' {
            if ($script:Ctx.Plan -ne 'P2') { return @{ Status = 'Skipped'; Result = "Requires Entra ID P2 (Identity Protection). Detected plan: $($script:Ctx.Plan)."; Details = 'Skipped due to licensing.' } }
            $m = @($script:Ctx.EnabledPolicies | Where-Object { ((@(Get-Prop $_ 'conditions.userRiskLevels') | Where-Object { $_ }).Count -gt 0) -and (Test-PolicyHasControl $_ 'passwordChange') })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "Password change is required for high user risk." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy requires a password change for high user risk."; Details = 'Require secure password change when user risk is high.' }
        }

        Add-Def 'MT.1014' 'A CA policy requires compliant/hybrid device for admins' 'Conditional Access' 'Medium' 'https://maester.dev/docs/tests/MT.1014' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object { (Test-PolicyTargetsAdmins $_) -and ((Test-PolicyHasControl $_ 'compliantDevice') -or (Test-PolicyHasControl $_ 'domainJoinedDevice')) })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "Admins require a compliant or hybrid-joined device." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy requires compliant/hybrid device for admins."; Details = 'Require a managed device for privileged roles.' }
        }

        Add-Def 'MT.1015' 'A CA policy blocks unknown / unsupported device platforms' 'Conditional Access' 'Low' 'https://maester.dev/docs/tests/MT.1015' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object { ($null -ne (Get-Prop $_ 'conditions.platforms.includePlatforms') -or $null -ne (Get-Prop $_ 'conditions.platforms.excludePlatforms')) -and (Test-PolicyHasControl $_ 'block') })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "A platform-scoped block policy exists." + (Format-PolicyList $m); Details = 'Approximation: verify it excludes known platforms and blocks the rest.' } }
            return @{ Status = 'Fail'; Result = "No enabled policy blocks unknown/unsupported device platforms."; Details = 'Block access from platforms other than your supported set.' }
        } -Approximation

        Add-Def 'MT.1016' 'A CA policy requires MFA for guest access' 'Conditional Access' 'Medium' 'https://maester.dev/docs/tests/MT.1016' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object { (Test-PolicyTargetsGuests $_) -and (Test-PolicyHasMfa $_) })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "MFA is required for guest / external users." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy requires MFA for guest access."; Details = 'Require MFA for guests and external users.' }
        }

        Add-Def 'MT.1017' 'A CA policy enforces non-persistent browser sessions for non-corporate devices' 'Conditional Access' 'Low' 'https://maester.dev/docs/tests/MT.1017' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object {
                    $enabled = (Get-Prop $_ 'sessionControls.persistentBrowser.isEnabled')
                    $mode = "$(Get-Prop $_ 'sessionControls.persistentBrowser.mode')"
                    ($enabled -eq $true -or "$enabled" -eq 'True') -and ($mode.ToLowerInvariant() -eq 'never')
                })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "Non-persistent browser session control is configured (mode = never)." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy enforces non-persistent browser sessions."; Details = 'Set persistent browser session to Never for unmanaged devices.' }
        }

        Add-Def 'MT.1018' 'A CA policy enforces sign-in frequency for non-corporate devices' 'Conditional Access' 'Low' 'https://maester.dev/docs/tests/MT.1018' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object { (Get-Prop $_ 'sessionControls.signInFrequency.isEnabled') -eq $true })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "Sign-in frequency control is configured." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy enforces sign-in frequency."; Details = 'Enforce a sign-in frequency for unmanaged devices.' }
        }

        Add-Def 'MT.1019' 'A CA policy enables application enforced restrictions' 'Conditional Access' 'Low' 'https://maester.dev/docs/tests/MT.1019' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object { (Get-Prop $_ 'sessionControls.applicationEnforcedRestrictions.isEnabled') -eq $true })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "Application enforced restrictions are enabled." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy enables application enforced restrictions."; Details = 'Enable app-enforced restrictions for Office apps.' }
        }

        Add-Def 'MT.1020' 'All CA policies exclude directory synchronization accounts' 'Conditional Access' 'Medium' 'https://maester.dev/docs/tests/MT.1020' {
            $syncUsers = @()
            try { $syncUsers = @(Invoke-GraphCollection -Uri "users?`$filter=onPremisesSyncEnabled eq true and userType eq 'Member'&`$select=id,displayName&`$top=999" | Where-Object { (Get-Prop $_ 'displayName') -match 'On-Premises Directory Synchronization' }) } catch {}
            $syncIds = @($syncUsers | ForEach-Object { Get-Prop $_ 'id' } | Where-Object { $_ })
            if ($syncIds.Count -eq 0) { return @{ Status = 'Skipped'; Result = "No on-premises directory synchronization service account was found."; Details = 'Nothing to exclude.' } }
            $offenders = New-Object System.Collections.ArrayList
            foreach ($p in $script:Ctx.EnabledPolicies) {
                $ex = @(Get-Prop $p 'conditions.users.excludeUsers')
                $scoped = (Test-PolicyAllUsers $p)
                $excluded = $false
                foreach ($s in $syncIds) { if ($ex -contains $s) { $excluded = $true } }
                if ($scoped -and -not $excluded) { $null = $offenders.Add((Get-Prop $p 'displayName')) }
            }
            if ($offenders.Count -eq 0) { return @{ Status = 'Pass'; Result = "Directory sync accounts are excluded or not scoped."; Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "Policies scoping the sync account without excluding it:`n- " + ($offenders -join "`n- "); Details = 'Exclude the directory sync service account from these policies.' }
        }

        Add-Def 'MT.1021' 'Security Defaults status' 'Conditional Access' 'Medium' 'https://maester.dev/docs/tests/MT.1021' {
            if ($script:Ctx.Plan -ne 'Free') { return @{ Status = 'Skipped'; Result = "Tenant is licensed for Entra ID Premium ($($script:Ctx.Plan)); Conditional Access is used instead of Security Defaults."; Details = 'Skipped: premium licensed.' } }
            $sd = Invoke-GraphRequest -Uri 'policies/identitySecurityDefaultsEnforcementPolicy' -ApiVersion 'v1.0'
            $enabled = (Get-Prop $sd 'isEnabled') -eq $true
            if ($enabled) { return @{ Status = 'Pass'; Result = "Security Defaults are enabled."; Details = 'OK for tenants without Conditional Access.' } }
            return @{ Status = 'Fail'; Result = "Security Defaults are disabled and no premium CA licensing was detected."; Details = 'Enable Security Defaults or configure Conditional Access.' }
        }

        Add-Def 'MT.1022' 'Entra ID P1 license utilization is within entitlement' 'License' 'Low' 'https://maester.dev/docs/tests/MT.1022' {
            $util = Get-SkuUtilization -ServicePlanName 'AAD_PREMIUM'
            if (-not $util.Found) { return @{ Status = 'Skipped'; Result = "No P1 (AAD_PREMIUM) SKU present in this tenant."; Details = 'Skipped: not licensed.' } }
            if ($util.Consumed -le $util.Entitled) { return @{ Status = 'Pass'; Result = "P1 usage $($util.Consumed) / $($util.Entitled) entitled."; Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "P1 usage $($util.Consumed) exceeds $($util.Entitled) entitled licenses."; Details = 'Acquire more licenses or reduce assignments.' }
        }

        Add-Def 'MT.1023' 'Entra ID P2 license utilization is within entitlement' 'License' 'Low' 'https://maester.dev/docs/tests/MT.1023' {
            $util = Get-SkuUtilization -ServicePlanName 'AAD_PREMIUM_P2'
            if (-not $util.Found) { return @{ Status = 'Skipped'; Result = "No P2 (AAD_PREMIUM_P2) SKU present in this tenant."; Details = 'Skipped: not licensed.' } }
            if ($util.Consumed -le $util.Entitled) { return @{ Status = 'Pass'; Result = "P2 usage $($util.Consumed) / $($util.Entitled) entitled."; Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "P2 usage $($util.Consumed) exceeds $($util.Entitled) entitled licenses."; Details = 'Acquire more licenses or reduce assignments.' }
        }

        Add-Def 'MT.1038' 'CA policies do not reference deleted groups' 'Conditional Access' 'Medium' 'https://maester.dev/docs/tests/MT.1038' {
            $groupIds = New-Object System.Collections.ArrayList
            foreach ($p in $script:Ctx.CaPolicies) {
                foreach ($g in @(Get-Prop $p 'conditions.users.includeGroups') + @(Get-Prop $p 'conditions.users.excludeGroups')) {
                    if ($g) { $null = $groupIds.Add($g) }
                }
            }
            $missing = @(Get-MissingDirectoryObjects -Ids @($groupIds))
            $uniqueCount = @($groupIds | Select-Object -Unique).Count
            if ($missing.Count -eq 0) { return @{ Status = 'Pass'; Result = "All $uniqueCount referenced groups exist."; Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "CA policies reference deleted groups:`n- " + ($missing -join "`n- "); Details = 'Remove references to deleted groups.' }
        }

        Add-Def 'MT.1049' 'User risk and sign-in risk are configured in separate policies' 'Conditional Access' 'Medium' 'https://maester.dev/docs/tests/MT.1049' {
            $bad = @($script:Ctx.EnabledPolicies | Where-Object { ((@(Get-Prop $_ 'conditions.userRiskLevels') | Where-Object { $_ }).Count -gt 0) -and ((@(Get-Prop $_ 'conditions.signInRiskLevels') | Where-Object { $_ }).Count -gt 0) })
            if ($bad.Count -eq 0) { return @{ Status = 'Pass'; Result = "No policy mixes user risk and sign-in risk conditions."; Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "Policies combining user risk and sign-in risk (misconfiguration):" + (Format-PolicyList $bad); Details = 'Split user-risk and sign-in-risk into separate policies.' }
        }

        Add-Def 'MT.1052' 'A CA policy targets the device code authentication flow' 'Conditional Access' 'Medium' 'https://maester.dev/docs/tests/MT.1052' {
            $m = @($script:Ctx.EnabledPolicies | Where-Object {
                    $methods = Get-Prop $_ 'conditions.authenticationFlows.transferMethods'
                    (Test-ArrayContains $methods 'deviceCodeFlow') -or ("$methods" -match 'deviceCodeFlow')
                })
            if ($m.Count -gt 0) { return @{ Status = 'Pass'; Result = "Device code flow is targeted by a policy." + (Format-PolicyList $m); Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "No enabled policy targets the device code authentication flow."; Details = 'Block or restrict the device code flow.' }
        }

        Add-Def 'MT.1066' 'CA policies do not reference non-existent users, groups, or roles' 'Conditional Access' 'Medium' 'https://maester.dev/docs/tests/MT.1066' {
            $users = New-Object System.Collections.ArrayList
            $groups = New-Object System.Collections.ArrayList
            foreach ($p in $script:Ctx.CaPolicies) {
                foreach ($u in @(Get-Prop $p 'conditions.users.includeUsers') + @(Get-Prop $p 'conditions.users.excludeUsers')) {
                    if ($u -and $u -notmatch '^(All|None|GuestsOrExternalUsers)$') { $null = $users.Add($u) }
                }
                foreach ($g in @(Get-Prop $p 'conditions.users.includeGroups') + @(Get-Prop $p 'conditions.users.excludeGroups')) {
                    if ($g) { $null = $groups.Add($g) }
                }
            }
            $missing = New-Object System.Collections.ArrayList
            foreach ($u in @(Get-MissingDirectoryObjects -Ids @($users))) { $null = $missing.Add("user:$u") }
            foreach ($g in @(Get-MissingDirectoryObjects -Ids @($groups))) { $null = $missing.Add("group:$g") }
            if ($missing.Count -eq 0) { return @{ Status = 'Pass'; Result = "All referenced users and groups exist."; Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "CA policies reference non-existent objects:`n- " + ($missing -join "`n- "); Details = 'Clean up stale object references.' }
        }

        Add-Def 'MT.1071' 'A CA policy explicitly includes Azure DevOps' 'Conditional Access' 'Info' 'https://maester.dev/docs/tests/MT.1071' {
            $referenced = @($script:Ctx.CaPolicies | Where-Object { Test-ArrayContains (Get-Prop $_ 'conditions.applications.includeApplications') $script:AppIds.AzureDevOps })
            $anyRef = @($script:Ctx.CaPolicies | Where-Object { (@(Get-Prop $_ 'conditions.applications.includeApplications') | Where-Object { $_ }).Count -gt 0 -and -not (Test-PolicyAllApps $_) })
            if ($referenced.Count -gt 0) { return @{ Status = 'Pass'; Result = "Azure DevOps is explicitly targeted." + (Format-PolicyList $referenced); Details = 'OK' } }
            if ($anyRef.Count -eq 0) { return @{ Status = 'Skipped'; Result = "No app-scoped policies to evaluate for Azure DevOps."; Details = 'Not applicable.' } }
            return @{ Status = 'Fail'; Result = "App-scoped policies exist but none target Azure DevOps."; Details = 'Include Azure DevOps in an appropriate policy.' }
        }

        Add-Def 'MT.1072' 'CA policies do not use the deprecated Approved Client App grant' 'Conditional Access' 'Medium' 'https://maester.dev/docs/tests/MT.1072' {
            $bad = @($script:Ctx.EnabledPolicies | Where-Object { Test-PolicyHasControl $_ 'approvedApplication' })
            if ($bad.Count -eq 0) { return @{ Status = 'Pass'; Result = "No policy uses the deprecated Approved Client App grant."; Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "Policies using the deprecated Approved Client App grant:" + (Format-PolicyList $bad); Details = 'Migrate to app protection policy (compliantApplication).' }
        }

        Add-Def 'MT.1184' 'No CA policy is missing target resources' 'Conditional Access' 'Low' 'https://maester.dev/docs/tests/MT.1184' {
            $bad = New-Object System.Collections.ArrayList
            foreach ($p in $script:Ctx.CaPolicies) {
                $apps = @(Get-Prop $p 'conditions.applications.includeApplications' | Where-Object { $_ })
                $actions = @(Get-Prop $p 'conditions.applications.includeUserActions' | Where-Object { $_ })
                $auth = @(Get-Prop $p 'conditions.applications.includeAuthenticationContextClassReferences' | Where-Object { $_ })
                if (($apps.Count + $actions.Count + $auth.Count) -eq 0) { $null = $bad.Add((Get-Prop $p 'displayName')) }
            }
            if ($bad.Count -eq 0) { return @{ Status = 'Pass'; Result = "Every policy targets at least one resource."; Details = 'OK' } }
            return @{ Status = 'Fail'; Result = "Policies with no target resource:`n- " + ($bad -join "`n- "); Details = 'Target apps, user actions, or auth context in each policy.' }
        }

        Add-Def 'MT.1035' 'CA-assigned security groups are protected by RMAU' 'Conditional Access' 'Low' 'https://maester.dev/docs/tests/MT.1035' {
            return @{ Status = 'Skipped'; Result = "Requires evaluating Restricted Management Administrative Unit membership for every CA-assigned group. Review manually in the Entra portal."; Details = 'Manual review recommended.' }
        } -Approximation

        Add-Def 'MT.1036' 'Excluded objects have a fallback include in another policy' 'Conditional Access' 'Low' 'https://maester.dev/docs/tests/MT.1036' {
            return @{ Status = 'Skipped'; Result = "Requires full exclusion/inclusion gap analysis across all policies and transitive group membership. Review manually."; Details = 'Manual review recommended.' }
        } -Approximation

        Add-Def 'MT.1061' 'Device registration MFA control does not conflict with CA' 'Conditional Access' 'Low' 'https://maester.dev/docs/tests/MT.1061' {
            $conflict = @($script:Ctx.EnabledPolicies | Where-Object { Test-ArrayContains (Get-Prop $_ 'conditions.applications.includeUserActions') 'urn:user:registerdevice' })
            $drp = $null
            try { $drp = Invoke-GraphRequest -Uri 'policies/deviceRegistrationPolicy' -ApiVersion 'beta' } catch {}
            $regMfa = (Get-Prop $drp 'multiFactorAuthConfiguration')
            if ($conflict.Count -gt 0 -and $regMfa -and "$regMfa" -ne 'notRequired') {
                return @{ Status = 'Fail'; Result = "Device registration requires MFA in Entra settings AND a CA policy targets the register-device action, which conflicts." + (Format-PolicyList $conflict); Details = 'Use only one MFA-during-registration control.' }
            }
            return @{ Status = 'Pass'; Result = "No conflict detected between device registration MFA and Conditional Access."; Details = 'OK' }
        } -Approximation
    }

    # ---------------- CA WhatIf (approximated legacy-auth evaluation) ----------------
    if ($script:IncludeSuite -contains 'WhatIf') {
        Add-Def 'MT.1033' 'Regular users are blocked from legacy authentication' 'WhatIf' 'High' 'https://maester.dev/docs/tests/MT.1033' {
            if ($script:Ctx.Plan -eq 'Free') { return @{ Status = 'Skipped'; Result = "Requires Entra ID Premium for Conditional Access."; Details = 'Skipped due to licensing.' } }
            $blockPolicies = @($script:Ctx.EnabledPolicies | Where-Object {
                    (Test-PolicyHasControl $_ 'block') -and
                    ((Test-ArrayContains (Get-Prop $_ 'conditions.clientAppTypes') 'other') -or (Test-ArrayContains (Get-Prop $_ 'conditions.clientAppTypes') 'exchangeActiveSync')) -and
                    (Test-PolicyAllUsers $_)
                })
            $sampleNote = ""
            $top = $script:WhatIfUserCount
            try {
                $sample = @(Invoke-GraphCollection -Uri "users?`$filter=userType eq 'Member' and accountEnabled eq true&`$select=id,displayName,userPrincipalName&`$top=$top")
                if ($sample.Count -gt 0) {
                    $names = @($sample | ForEach-Object { Get-Prop $_ 'userPrincipalName' } | Where-Object { $_ } | Select-Object -First $top)
                    $sampleNote = "`n`nSampled $($names.Count) member user(s) (WhatIfUserCount=$top): " + ($names -join ', ')
                }
            }
            catch { }

            if ($blockPolicies.Count -gt 0) { return @{ Status = 'Pass'; Result = "A block-legacy-auth policy applies to all users, so regular users are blocked from legacy authentication." + (Format-PolicyList $blockPolicies) + $sampleNote; Details = 'Approximation of Test-MtCaWIFBlockLegacyAuthentication based on policy scope.' } }
            return @{ Status = 'Fail'; Result = "No all-users policy blocks legacy authentication; regular users may still authenticate with legacy protocols." + $sampleNote; Details = 'Add an all-users legacy-auth block policy.' }
        } -Approximation

        Add-Def 'MT.1034' 'Emergency access users are not blocked by legacy-auth policies' 'WhatIf' 'High' 'https://maester.dev/docs/tests/MT.1034' {
            if ($script:Ctx.Plan -eq 'Free') { return @{ Status = 'Skipped'; Result = "Requires Entra ID Premium for Conditional Access."; Details = 'Skipped due to licensing.' } }
            $noExclusion = @($script:Ctx.EnabledPolicies | Where-Object {
                    (Test-PolicyHasControl $_ 'block') -and (Test-PolicyAllUsers $_) -and
                    ((@(Get-Prop $_ 'conditions.users.excludeUsers') | Where-Object { $_ }).Count + (@(Get-Prop $_ 'conditions.users.excludeGroups') | Where-Object { $_ }).Count) -eq 0
                })
            if ($noExclusion.Count -eq 0) { return @{ Status = 'Pass'; Result = "Break-glass exclusions exist on all-users block policies; emergency access accounts are unlikely to be locked out."; Details = 'Approximation of Test-MtConditionalAccessWhatIf. Verify excluded objects are your emergency accounts.' } }
            return @{ Status = 'Fail'; Result = "All-users block policies without any exclusion could lock out emergency access accounts:" + (Format-PolicyList $noExclusion); Details = 'Exclude emergency access accounts from block policies.' }
        } -Approximation
    }

    # ---------------- Entra recommendations ----------------
    if ($script:IncludeSuite -contains 'Recommendations') {
        Add-Def 'MT.1024' 'Entra recommendations are completed' 'Recommendation' 'Medium' 'https://maester.dev/docs/tests/MT.1024' {
            $recs = @()
            try { $recs = @(Invoke-GraphCollection -Uri 'directory/recommendations?$expand=impactedResources' -ApiVersion 'beta') }
            catch { return @{ Status = 'Skipped'; Result = "Directory recommendations are unavailable (requires Entra ID P1/P2 and DirectoryRecommendations.Read.All)."; Details = 'Skipped: unavailable.' } }
            if ($recs.Count -eq 0) { return @{ Status = 'Skipped'; Result = "No Entra recommendations were returned for this tenant."; Details = 'Nothing to evaluate.' } }
            return @{ __Expand = $recs }
        }
    }

    return @($defs)
}

# ----------------------------------------------------------------------------------------------
# Runner
# ----------------------------------------------------------------------------------------------
function Invoke-AllChecks {
    $defs = @(Get-CheckDefinitions)
    $total = $defs.Count
    $i = 0
    foreach ($def in $defs) {
        $i++
        Write-Progress -Activity "Running Entra security baseline" -Status "$($def.Id): $($def.Title)" -PercentComplete (($i / [math]::Max($total, 1)) * 100)
        try {
            $outcome = & $def.Test

            if (Test-OutcomeHasExpand $outcome) {
                foreach ($rec in @(Get-OutcomeValue $outcome '__Expand')) {
                    $graphStatus = "$(Get-Prop $rec 'status')"
                    $status = Resolve-RecommendationStatus $graphStatus
                    $prio = "$(Get-Prop $rec 'priority')"
                    $sev = switch ($prio.ToLowerInvariant()) { 'high' { 'High' } 'medium' { 'Medium' } 'low' { 'Low' } default { 'Info' } }
                    $impacted = @(Get-Prop $rec 'impactedResources')
                    $impactText = ""
                    if (@($impacted | Where-Object { $_ }).Count -gt 0) {
                        $impactText = "`n`nImpacted resources:`n" + (($impacted | ForEach-Object { "- " + (Get-Prop $_ 'displayName') + " [" + (Get-Prop $_ 'status') + "]" }) -join "`n")
                    }
                    $recType = Get-Prop $rec 'recommendationType'
                    if (-not $recType) { $recType = Get-Prop $rec 'id' }
                    $skipReason = ""
                    if ($status -eq 'Skipped') { $skipReason = " Recommendation status is '$graphStatus' (treated as skipped, matching Maester dismissed handling)." }
                    Add-Result -Id ("MT.1024:" + $recType) `
                        -Title (Get-Prop $rec 'displayName') `
                        -Category 'Recommendation' -Severity $sev -Status $status `
                        -Result ("" + (Get-Prop $rec 'insights') + $impactText + $skipReason) `
                        -Details ("" + (Get-Prop $rec 'benefits')) `
                        -DocsUrl $def.DocsUrl
                }
                continue
            }

            $sev = $def.Severity
            $approx = $false
            if ($def.Contains('Approximation')) { $approx = [bool]$def.Approximation }
            Add-Result -Id $def.Id -Title $def.Title -Category $def.Category -Severity $sev `
                -Status (Get-OutcomeValue $outcome 'Status') -Result (Get-OutcomeValue $outcome 'Result') -Details (Get-OutcomeValue $outcome 'Details') `
                -DocsUrl $def.DocsUrl -Approximation:$approx
        }
        catch {
            $approx = $false
            if ($def -is [System.Collections.IDictionary] -and $def.Contains('Approximation')) { $approx = [bool]$def.Approximation }
            Add-Result -Id $def.Id -Title $def.Title -Category $def.Category -Severity $def.Severity `
                -Status 'Error' -Result ("Check failed: " + $_.Exception.Message) `
                -Details 'Review Graph permissions and connectivity.' -DocsUrl $def.DocsUrl -Approximation:$approx
        }
    }
    Write-Progress -Activity "Running Entra security baseline" -Completed
}

# ----------------------------------------------------------------------------------------------
# Demo data
# ----------------------------------------------------------------------------------------------
function Set-DemoData {
    $script:Ctx.TenantId = '11111111-2222-3333-4444-555555555555'
    $script:Ctx.TenantName = 'Contoso (Demo)'
    $script:Ctx.Plan = 'P2'
    $demo = @(
        @('MT.1067', 'Authentication method policies should not reference non-existent groups', 'Authentication', 'High', 'Pass', 'All groups referenced by authentication method policies exist.', 'No remediation required.', $false),
        @('MT.1001', 'A CA policy requires device compliance', 'Conditional Access', 'Medium', 'Pass', 'At least one enabled policy requires device compliance.', 'OK', $false),
        @('MT.1004', 'A CA policy is scoped to All Apps and All Users', 'Conditional Access', 'Medium', 'Pass', 'Baseline policy covers All Apps + All Users.', 'OK', $false),
        @('MT.1005', 'All CA policies exclude an emergency / break-glass account or group', 'Conditional Access', 'High', 'Fail', 'Policy "Legacy Block" has no user/group exclusion (no break-glass safety).', 'Exclude your emergency access account from every enabled policy.', $true),
        @('MT.1006', 'A CA policy requires MFA for admins', 'Conditional Access', 'High', 'Pass', 'MFA is required for admin roles.', 'OK', $false),
        @('MT.1007', 'A CA policy requires MFA for all users', 'Conditional Access', 'High', 'Pass', 'MFA is required for all users.', 'OK', $false),
        @('MT.1009', 'A CA policy blocks other legacy authentication', 'Conditional Access', 'High', 'Pass', 'Legacy other-client authentication is blocked.', 'OK', $false),
        @('MT.1012', 'A CA policy requires MFA for risky sign-ins', 'Conditional Access', 'High', 'Fail', 'No enabled policy requires MFA for risky sign-ins.', 'Require MFA when sign-in risk is medium or high.', $false),
        @('MT.1013', 'A CA policy requires password change for high user risk', 'Conditional Access', 'High', 'Fail', 'No enabled policy requires a password change for high user risk.', 'Require secure password change when user risk is high.', $false),
        @('MT.1016', 'A CA policy requires MFA for guest access', 'Conditional Access', 'Medium', 'Pass', 'MFA is required for guests.', 'OK', $false),
        @('MT.1021', 'Security Defaults status', 'Conditional Access', 'Medium', 'Skipped', 'Tenant is licensed for Entra ID Premium (P2); Conditional Access is used instead.', 'Skipped: premium licensed.', $false),
        @('MT.1022', 'Entra ID P1 license utilization is within entitlement', 'License', 'Low', 'Pass', 'P1 usage 420 / 500 entitled.', 'OK', $false),
        @('MT.1023', 'Entra ID P2 license utilization is within entitlement', 'License', 'Low', 'Fail', 'P2 usage 260 exceeds 250 entitled licenses.', 'Acquire more licenses or reduce assignments.', $false),
        @('MT.1049', 'User risk and sign-in risk are configured separately', 'Conditional Access', 'Medium', 'Pass', 'No policy mixes user risk and sign-in risk conditions.', 'OK', $false),
        @('MT.1052', 'A CA policy targets the device code authentication flow', 'Conditional Access', 'Medium', 'Fail', 'No enabled policy targets the device code authentication flow.', 'Block or restrict the device code flow.', $false),
        @('MT.1072', 'CA policies do not use the deprecated Approved Client App grant', 'Conditional Access', 'Medium', 'Pass', 'No policy uses the deprecated Approved Client App grant.', 'OK', $false),
        @('MT.1035', 'CA-assigned security groups are protected by RMAU', 'Conditional Access', 'Low', 'Skipped', 'Requires evaluating RMAU membership. Review manually.', 'Manual review recommended.', $true),
        @('MT.1033', 'Regular users are blocked from legacy authentication', 'WhatIf', 'High', 'Pass', 'A block-legacy-auth policy applies to all users.', 'Approximation based on policy scope.', $true),
        @('MT.1034', 'Emergency access users are not blocked by legacy-auth policies', 'WhatIf', 'High', 'Fail', 'An all-users block policy has no exclusion and could lock out emergency accounts.', 'Exclude emergency access accounts from block policies.', $true),
        @('MT.1024:passwordHashSync', 'Enable password hash synchronization', 'Recommendation', 'Medium', 'Fail', 'Password hash sync improves resiliency and leaked-credential detection.', 'Turn on password hash sync in Entra Connect.', $false),
        @('MT.1024:staleApps', 'Remove unused applications', 'Recommendation', 'Low', 'Pass', 'No stale application credentials detected.', 'Keep reviewing app registrations.', $false),
        @('MT.1024:mfaRegistration', 'Ensure all users can complete MFA', 'Recommendation', 'High', 'Fail', '37 users have not registered a strong authentication method.', 'Drive an MFA registration campaign.', $false),
        @('MT.1024:blockLegacyAuth', 'Block legacy authentication', 'Recommendation', 'Medium', 'Skipped', 'Recommendation status is dismissed (treated as skipped, matching Maester).', 'No action; dismissed by an administrator.', $false)
    )
    foreach ($d in $demo) {
        Add-Result -Id $d[0] -Title $d[1] -Category $d[2] -Severity $d[3] -Status $d[4] -Result $d[5] -Details $d[6] -DocsUrl ('https://maester.dev/docs/tests/' + ($d[0] -replace ':.*$', '')) -Approximation:$d[7]
    }
}

# ----------------------------------------------------------------------------------------------
# HTML report
# ----------------------------------------------------------------------------------------------
function ConvertTo-HtmlReport {
    param([string] $OutputPath)

    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    $payload = @{
        generated  = $generated
        tenantId   = [string]$script:Ctx.TenantId
        tenantName = [string]$script:Ctx.TenantName
        plan       = [string]$script:Ctx.Plan
        build      = $script:BuildStamp
        results    = @($script:Results | ForEach-Object {
                @{
                    id            = [string]$_.Id
                    title         = [string]$_.Title
                    category      = [string]$_.Category
                    severity      = [string]$_.Severity
                    status        = [string]$_.Status
                    result        = [string]$_.Result
                    details       = [string]$_.Details
                    docsUrl       = [string]$_.DocsUrl
                    approximation = [bool]$_.Approximation
                }
            })
    }
    $json = ConvertTo-ReportJson $payload

    $template = Get-HtmlTemplate
    $html = $template.Replace('/*__REPORT_DATA__*/null', $json)
    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($OutputPath, $html, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-HtmlTemplate {
    # Single-quoted here-string: no PowerShell interpolation, JS template literals stay intact.
    return @'
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Entra ID Security Baseline Report</title>
<style>
  :root{
    --bg:#0b1220; --panel:#111a2e; --panel-2:#0e1626; --border:#1e2b47;
    --fg:#e8edf7; --muted:#93a1c0; --accent:#3b82f6; --accent-2:#60a5fa;
    --pass:#22c55e; --fail:#ef4444; --skip:#f59e0b; --error:#a855f7;
    --high:#ef4444; --medium:#f59e0b; --low:#38bdf8; --info:#94a3b8;
    --radius:14px;
  }
  *{box-sizing:border-box}
  body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#152140 0,var(--bg) 55%);
    color:var(--fg);font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.5;}
  a{color:var(--accent-2);text-decoration:none} a:hover{text-decoration:underline}
  .wrap{max-width:1200px;margin:0 auto;padding:32px 20px 80px}
  header.top{display:flex;flex-wrap:wrap;gap:20px;align-items:center;justify-content:space-between;margin-bottom:28px}
  .brand{display:flex;align-items:center;gap:14px}
  .logo{width:46px;height:46px;border-radius:12px;background:linear-gradient(135deg,var(--accent),#8b5cf6);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:20px;color:#fff}
  h1{font-size:22px;margin:0;letter-spacing:-.2px}
  .sub{color:var(--muted);font-size:13px;margin-top:2px}
  .meta{display:flex;gap:22px;flex-wrap:wrap;font-size:13px;color:var(--muted)}
  .meta b{color:var(--fg);font-weight:600}
  .grid{display:grid;gap:18px}
  .cards{grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:22px}
  .card{background:linear-gradient(180deg,var(--panel),var(--panel-2));border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px}
  .card .n{font-size:30px;font-weight:800;letter-spacing:-1px}
  .card .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
  .card.pass .n{color:var(--pass)} .card.fail .n{color:var(--fail)}
  .card.skip .n{color:var(--skip)} .card.error .n{color:var(--error)}
  .panels{grid-template-columns:1.1fr 1.4fr;margin-bottom:22px}
  @media(max-width:860px){.panels{grid-template-columns:1fr}}
  .panel{background:linear-gradient(180deg,var(--panel),var(--panel-2));border:1px solid var(--border);border-radius:var(--radius);padding:20px}
  .panel h2{margin:0 0 14px;font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
  .score-wrap{display:flex;align-items:center;gap:22px}
  .legend{display:flex;flex-direction:column;gap:8px;font-size:13px}
  .legend .row{display:flex;align-items:center;gap:8px}
  .dot{width:11px;height:11px;border-radius:3px;display:inline-block}
  .controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:8px 0 18px}
  .controls input,.controls select{background:var(--panel-2);border:1px solid var(--border);color:var(--fg);
    border-radius:10px;padding:9px 12px;font-size:13px;outline:none}
  .controls input{min-width:230px;flex:1}
  .chips{display:flex;gap:8px;flex-wrap:wrap}
  .chip{cursor:pointer;border:1px solid var(--border);background:var(--panel-2);color:var(--muted);
    padding:7px 13px;border-radius:999px;font-size:12px;font-weight:600;user-select:none}
  .chip.active{color:#fff;border-color:transparent}
  .chip.active[data-s="all"]{background:var(--accent)}
  .chip.active[data-s="Pass"]{background:var(--pass)}
  .chip.active[data-s="Fail"]{background:var(--fail)}
  .chip.active[data-s="Skipped"]{background:var(--skip)}
  .chip.active[data-s="Error"]{background:var(--error)}
  .results{display:flex;flex-direction:column;gap:10px}
  .item{border:1px solid var(--border);border-radius:12px;background:var(--panel);overflow:hidden}
  .item .head{display:flex;align-items:center;gap:14px;padding:14px 16px;cursor:pointer}
  .item .head:hover{background:rgba(255,255,255,.02)}
  .badge{font-size:11px;font-weight:700;padding:3px 9px;border-radius:999px;white-space:nowrap}
  .b-Pass{background:rgba(34,197,94,.15);color:var(--pass)}
  .b-Fail{background:rgba(239,68,68,.15);color:var(--fail)}
  .b-Skipped{background:rgba(245,158,11,.15);color:var(--skip)}
  .b-Error{background:rgba(168,85,247,.15);color:var(--error)}
  .sev{font-size:10px;font-weight:700;padding:2px 7px;border-radius:6px;text-transform:uppercase;letter-spacing:.05em}
  .sev-High{background:rgba(239,68,68,.15);color:var(--high)}
  .sev-Medium{background:rgba(245,158,11,.15);color:var(--medium)}
  .sev-Low{background:rgba(56,189,248,.15);color:var(--low)}
  .sev-Info{background:rgba(148,163,184,.15);color:var(--info)}
  .id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--accent-2);min-width:96px}
  .title{flex:1;font-size:14px;font-weight:600}
  .approx{font-size:10px;color:var(--skip);border:1px dashed var(--skip);border-radius:6px;padding:1px 6px}
  .chev{color:var(--muted);transition:transform .15s}
  .item.open .chev{transform:rotate(90deg)}
  .body{display:none;padding:0 16px 16px;border-top:1px solid var(--border)}
  .item.open .body{display:block}
  .body h4{margin:14px 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
  .body pre{white-space:pre-wrap;word-break:break-word;background:var(--panel-2);border:1px solid var(--border);
    border-radius:10px;padding:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:var(--fg);margin:0}
  .cat-panel .bar-row{display:flex;align-items:center;gap:10px;margin-bottom:10px;font-size:12.5px}
  .cat-panel .bar-row .name{width:150px;color:var(--muted)}
  .track{flex:1;height:16px;background:var(--panel-2);border-radius:8px;overflow:hidden;display:flex}
  .track > span{display:block;height:100%}
  .empty{text-align:center;color:var(--muted);padding:40px;border:1px dashed var(--border);border-radius:12px}
  footer{margin-top:36px;color:var(--muted);font-size:12px;text-align:center}
  .svg-donut text{fill:var(--fg)}
  .render-error{color:var(--fail);padding:16px;margin:16px 20px;border:1px solid var(--fail);border-radius:12px;background:rgba(239,68,68,.08)}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">
      <div class="logo">E</div>
      <div>
        <h1>Entra ID Security Baseline</h1>
        <div class="sub">Maester-style assessment &middot; interactive report</div>
      </div>
    </div>
    <div class="meta" id="meta"></div>
  </header>

  <div class="grid cards" id="cards"></div>

  <div class="grid panels">
    <div class="panel">
      <h2>Compliance overview</h2>
      <div class="score-wrap">
        <div id="donut"></div>
        <div class="legend" id="legend"></div>
      </div>
    </div>
    <div class="panel cat-panel">
      <h2>Results by category</h2>
      <div id="catbars"></div>
      <h2 style="margin-top:22px">Findings by severity</h2>
      <div id="sevbars"></div>
    </div>
  </div>

  <div class="panel">
    <h2>Test results</h2>
    <div class="controls">
      <input id="search" type="search" placeholder="Search by id, title, or finding..." />
      <select id="catFilter"></select>
      <select id="sevFilter">
        <option value="all">All severities</option>
        <option>High</option><option>Medium</option><option>Low</option><option>Info</option>
      </select>
    </div>
    <div class="chips" id="statusChips">
      <span class="chip active" data-s="all">All</span>
      <span class="chip" data-s="Pass">Pass</span>
      <span class="chip" data-s="Fail">Fail</span>
      <span class="chip" data-s="Skipped">Skipped</span>
      <span class="chip" data-s="Error">Error</span>
    </div>
    <div class="results" id="results"></div>
  </div>

  <footer>
    Generated by Invoke-EntraSecurityBaseline.ps1 &middot; live Microsoft Graph checks &middot;
    approximated checks are marked <span class="approx">approx</span>.
  </footer>
</div>

<script>
let REPORT = /*__REPORT_DATA__*/null;
if (!REPORT) REPORT = {generated:'', tenantId:'Unknown', tenantName:'Unknown', plan:'Unknown', results:[]};
if (!Array.isArray(REPORT.results)) REPORT.results = (REPORT.results == null) ? [] : [REPORT.results];

const COLORS = { Pass:'#22c55e', Fail:'#ef4444', Skipped:'#f59e0b', Error:'#a855f7' };
const SEVCOLORS = { High:'#ef4444', Medium:'#f59e0b', Low:'#38bdf8', Info:'#94a3b8' };
const state = { status:'all', cat:'all', sev:'all', q:'' };

function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function count(pred){ return REPORT.results.filter(pred).length; }

function renderMeta(){
  document.getElementById('meta').innerHTML =
    `<div>Tenant <b>${esc(REPORT.tenantName)}</b></div>`+
    `<div>ID <b>${esc(REPORT.tenantId)}</b></div>`+
    `<div>Plan <b>${esc(REPORT.plan)}</b></div>`+
    `<div>Generated <b>${esc(REPORT.generated)}</b></div>`;
}

function renderCards(){
  const total = REPORT.results.length;
  const pass = count(r=>r.status==='Pass');
  const fail = count(r=>r.status==='Fail');
  const skip = count(r=>r.status==='Skipped');
  const err  = count(r=>r.status==='Error');
  const scored = pass + fail;
  const score = scored ? Math.round(pass/scored*100) : 0;
  const cards = [
    ['',''+total,'Total tests'],
    ['pass',''+pass,'Passed'],
    ['fail',''+fail,'Failed'],
    ['skip',''+skip,'Skipped'],
    ['error',''+err,'Errors'],
    ['',score+'%','Compliance'],
  ];
  document.getElementById('cards').innerHTML = cards.map(c=>
    `<div class="card ${c[0]}"><div class="n">${c[1]}</div><div class="l">${c[2]}</div></div>`).join('');
  return {pass,fail,skip,err,score};
}

function polar(cx,cy,r,a){ const rad=(a-90)*Math.PI/180; return [cx+r*Math.cos(rad), cy+r*Math.sin(rad)]; }
function arc(cx,cy,r,a0,a1){
  const [x0,y0]=polar(cx,cy,r,a0), [x1,y1]=polar(cx,cy,r,a1);
  const large = (a1-a0)>180?1:0;
  return `M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1}`;
}
function renderDonut(s){
  const data=[['Pass',s.pass],['Fail',s.fail],['Skipped',s.skip],['Error',s.err]].filter(d=>d[1]>0);
  const total=data.reduce((a,d)=>a+d[1],0)||1;
  const cx=90,cy=90,r=68; let ang=0; let paths='';
  data.forEach(d=>{
    const sweep=d[1]/total*360; const a1=ang+sweep;
    const seg = sweep>=359.999 ? `M ${cx-r} ${cy} A ${r} ${r} 0 1 1 ${cx+r} ${cy} A ${r} ${r} 0 1 1 ${cx-r} ${cy}` : arc(cx,cy,r,ang,a1);
    paths += `<path d="${seg}" fill="none" stroke="${COLORS[d[0]]}" stroke-width="24" stroke-linecap="butt"/>`;
    ang=a1;
  });
  document.getElementById('donut').innerHTML =
    `<svg class="svg-donut" width="180" height="180" viewBox="0 0 180 180">
      ${paths}
      <text x="90" y="84" text-anchor="middle" font-size="34" font-weight="800">${s.score}%</text>
      <text x="90" y="106" text-anchor="middle" font-size="12" fill="#93a1c0">compliant</text>
    </svg>`;
  const legend=[['Pass',s.pass],['Fail',s.fail],['Skipped',s.skip],['Error',s.err]];
  document.getElementById('legend').innerHTML = legend.map(l=>
    `<div class="row"><span class="dot" style="background:${COLORS[l[0]]}"></span>${l[0]} <b style="margin-left:auto;color:#fff">${l[1]}</b></div>`).join('');
}

function stackedBar(map, colors){
  const total=Object.values(map).reduce((a,b)=>a+b,0)||1;
  return Object.keys(map).filter(k=>map[k]>0).map(k=>
    `<span title="${k}: ${map[k]}" style="width:${map[k]/total*100}%;background:${colors[k]}"></span>`).join('');
}
function renderCatBars(){
  const cats=[...new Set(REPORT.results.map(r=>r.category))].sort();
  document.getElementById('catbars').innerHTML = cats.map(cat=>{
    const rows=REPORT.results.filter(r=>r.category===cat);
    const map={Pass:0,Fail:0,Skipped:0,Error:0};
    rows.forEach(r=>map[r.status]++);
    return `<div class="bar-row"><div class="name">${esc(cat)}</div>
      <div class="track">${stackedBar(map,COLORS)}</div><b>${rows.length}</b></div>`;
  }).join('');
}
function renderSevBars(){
  const sevs=['High','Medium','Low','Info'];
  document.getElementById('sevbars').innerHTML = sevs.map(sev=>{
    const rows=REPORT.results.filter(r=>r.severity===sev);
    const map={Pass:0,Fail:0,Skipped:0,Error:0};
    rows.forEach(r=>map[r.status]++);
    if(rows.length===0) return '';
    return `<div class="bar-row"><div class="name"><span class="sev sev-${sev}">${sev}</span></div>
      <div class="track">${stackedBar(map,COLORS)}</div><b>${rows.length}</b></div>`;
  }).join('');
}

function renderCatFilter(){
  const cats=[...new Set(REPORT.results.map(r=>r.category))].sort();
  document.getElementById('catFilter').innerHTML =
    `<option value="all">All categories</option>`+cats.map(c=>`<option>${esc(c)}</option>`).join('');
}

function passesFilter(r){
  if(state.status!=='all' && r.status!==state.status) return false;
  if(state.cat!=='all' && r.category!==state.cat) return false;
  if(state.sev!=='all' && r.severity!==state.sev) return false;
  if(state.q){
    const hay=(r.id+' '+r.title+' '+r.result+' '+r.details).toLowerCase();
    if(!hay.includes(state.q.toLowerCase())) return false;
  }
  return true;
}
function renderResults(){
  const rows=REPORT.results.filter(passesFilter);
  const el=document.getElementById('results');
  if(rows.length===0){ el.innerHTML=`<div class="empty">No tests match the current filters.</div>`; return; }
  el.innerHTML = rows.map((r,i)=>`
    <div class="item" data-i="${i}">
      <div class="head">
        <span class="badge b-${esc(r.status)}">${esc(r.status)}</span>
        <span class="sev sev-${esc(r.severity)}">${esc(r.severity)}</span>
        <span class="id">${esc(r.id)}</span>
        <span class="title">${esc(r.title)}</span>
        ${r.approximation?'<span class="approx">approx</span>':''}
        <span class="chev">&#9654;</span>
      </div>
      <div class="body">
        <h4>Finding</h4><pre>${esc(r.result)||'(no details)'}</pre>
        <h4>Recommendation</h4><pre>${esc(r.details)||'(none)'}</pre>
        ${r.docsUrl?`<h4>Reference</h4><a href="${esc(r.docsUrl)}" target="_blank" rel="noopener">${esc(r.docsUrl)}</a>`:''}
      </div>
    </div>`).join('');
  el.querySelectorAll('.item .head').forEach(h=>{
    h.addEventListener('click',()=>h.parentElement.classList.toggle('open'));
  });
}

function wire(){
  document.getElementById('search').addEventListener('input',e=>{state.q=e.target.value;renderResults();});
  document.getElementById('catFilter').addEventListener('change',e=>{state.cat=e.target.value;renderResults();});
  document.getElementById('sevFilter').addEventListener('change',e=>{state.sev=e.target.value;renderResults();});
  document.querySelectorAll('#statusChips .chip').forEach(c=>{
    c.addEventListener('click',()=>{
      document.querySelectorAll('#statusChips .chip').forEach(x=>x.classList.remove('active'));
      c.classList.add('active'); state.status=c.dataset.s; renderResults();
    });
  });
}

try {
  renderMeta();
  const summary=renderCards();
  renderDonut(summary);
  renderCatBars();
  renderSevBars();
  renderCatFilter();
  wire();
  renderResults();
} catch (e) {
  document.body.insertAdjacentHTML('afterbegin', '<div class="render-error">Report failed to render: '+esc(e && e.message)+'</div>');
}
</script>
</body>
</html>
'@
}

function Assert-Equal {
    param($Actual, $Expected, [string] $Name)
    if ("$Actual" -ne "$Expected") {
        throw "SelfTest failed: $Name. Expected '$Expected', got '$Actual'."
    }
}

function Invoke-BaselineSelfTest {
    Write-Section "SelfTest"
    Enable-Tls12
    $tls12 = [Net.SecurityProtocolType]::Tls12
    Assert-Equal (([Net.ServicePointManager]::SecurityProtocol -band $tls12) -eq $tls12) $true 'TLS 1.2 enabled'

    Set-StrictMode -Version Latest

    $obj = [pscustomobject]@{ grantControls = [pscustomobject]@{ builtInControls = @('mfa', 'block') } }
    Assert-Equal (Test-ArrayContains (Get-Prop $obj 'grantControls.builtInControls') 'mfa') $true 'Get-Prop nested array'
    Assert-Equal (Get-Prop $obj 'grantControls.missing') $null 'Get-Prop missing returns null'
    Assert-Equal (Get-Prop $null 'a.b') $null 'Get-Prop null input'

    $ht = @{ conditions = @{ users = @{ includeUsers = @('All') } } }
    Assert-Equal (Test-PolicyAllUsers $ht) $true 'Test-PolicyAllUsers hashtable'

    $single = Get-FirstItem 'only-one'
    Assert-Equal $single 'only-one' 'Get-FirstItem scalar'

    $jsonOne = ConvertTo-ReportJson @{ results = @(@{ id = 'MT.1'; title = 'One' }) }
    if ($jsonOne -notmatch '"results":\[') { throw "SelfTest failed: single-element results array was flattened." }

    $jsonXss = ConvertTo-ReportJson @{ results = @(@{ result = '</script><script>alert(1)' }) }
    if ($jsonXss -match '</script>') { throw "SelfTest failed: JSON payload still contains </script>." }

    Assert-Equal (Resolve-RecommendationStatus 'completedBySystem') 'Pass' 'rec completedBySystem'
    Assert-Equal (Resolve-RecommendationStatus 'dismissed') 'Skipped' 'rec dismissed'
    Assert-Equal (Resolve-RecommendationStatus 'active') 'Fail' 'rec active'

    $script:Results = New-Object System.Collections.ArrayList
    Set-DemoData
    $out = Join-Path ([IO.Path]::GetTempPath()) ("EntraSecurityBaseline_SelfTest_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    ConvertTo-HtmlReport -OutputPath $out
    if (-not (Test-Path -LiteralPath $out)) { throw "SelfTest failed: report was not written." }
    $html = [IO.File]::ReadAllText($out)
    if ($html -notmatch 'Entra ID Security Baseline') { throw "SelfTest failed: report missing title." }
    if ($html -notmatch '"results":\[') { throw "SelfTest failed: report JSON results is not an array." }
    if ($html -match '</script><script>') { throw "SelfTest failed: report HTML contains script-break sequence from data." }
    $count = @($script:Results).Count
    if ($count -lt 10) { throw "SelfTest failed: demo data too small ($count)." }

    Write-Host ("SelfTest passed ({0} demo results). Report: {1}" -f $count, $out) -ForegroundColor Green
    Write-Host ("Script build: {0}" -f $script:BuildStamp) -ForegroundColor Gray
}

# ----------------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------------
Write-Host ("Invoke-EntraSecurityBaseline  |  build {0}" -f $script:BuildStamp) -ForegroundColor Gray
Enable-Tls12

if ($SelfTest) {
    Invoke-BaselineSelfTest
    return
}

Write-Section "Entra ID Security Baseline Assessment"

if (-not $OutputPath) {
    $OutputPath = Join-Path (Get-Location).Path ("EntraSecurityBaseline_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

try {
    if ($DemoMode) {
        Write-Host "Running in DEMO mode with bundled sample data (no Graph connection)." -ForegroundColor Yellow
        Set-DemoData
    }
    else {
        $graphCtx = Connect-Graph -TenantId $TenantId -Scopes $Scopes -DeviceCode:$DeviceCode
        $script:WeConnected = $true
        Initialize-TenantContext -GraphContext $graphCtx
        Write-Section "Running checks"
        Invoke-AllChecks
    }

    Write-Section "Building report"
    ConvertTo-HtmlReport -OutputPath $OutputPath

    $pass = @($script:Results | Where-Object { $_.Status -eq 'Pass' }).Count
    $fail = @($script:Results | Where-Object { $_.Status -eq 'Fail' }).Count
    $skip = @($script:Results | Where-Object { $_.Status -eq 'Skipped' }).Count
    $err = @($script:Results | Where-Object { $_.Status -eq 'Error' }).Count
    $scored = $pass + $fail
    $score = if ($scored -gt 0) { [math]::Round(($pass / $scored) * 100) } else { 0 }

    Write-Host ""
    Write-Host ("Results:  Pass {0}  |  Fail {1}  |  Skipped {2}  |  Error {3}  |  Compliance {4}%" -f $pass, $fail, $skip, $err, $score) -ForegroundColor Cyan
    Write-Host ("Report written to: {0}" -f $OutputPath) -ForegroundColor Green

    if (-not $NoLaunch) {
        try { Start-Process $OutputPath } catch { Write-Host "Open the report manually: $OutputPath" -ForegroundColor Yellow }
    }
}
finally {
    if ($script:WeConnected -and -not $SkipDisconnect) {
        try {
            Disconnect-MgGraph | Out-Null
            Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Gray
        }
        catch { }
    }
}

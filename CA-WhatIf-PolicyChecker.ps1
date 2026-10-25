#Requires -Version 5.1
<#
.SYNOPSIS
    Entra ID Conditional Access What If Policy Checker

.DESCRIPTION
    WinForms "What If" simulator for Microsoft Entra Conditional Access.
    Uses the same Microsoft Graph evaluate API that powers the Entra admin
    center What If tool, then falls back to a local evaluator when the API
    is unavailable.

    The original UPN-only checker treated cloud-app, platform, and client-app
    assignments as reasons a policy applied to a user. That is incorrect and
    can hide gaps. This tool evaluates a full sign-in the way Entra does:

      Users AND cloud apps/user actions/auth context AND every configured
      condition (platform, client app, location, device, risk, flow).
      Exclusions always win. Disabled policies never apply. Report-only
      policies are shown but not treated as enforced.

.NOTES
    Version:     2.0
    Compatible:  Windows PowerShell 5.1+ / PowerShell 7+ (Windows)
    Requires:    Microsoft.Graph PowerShell SDK
    Scopes:      Policy.Read.All, User.Read.All, GroupMember.Read.All,
                 Directory.Read.All, Application.Read.All

    Known Entra What If limits (also apply here):
      - Service dependencies are not expanded (Teams does not auto-include
        Exchange Online, and so on).
      - Classic Conditional Access policies are not evaluated.
      - Missing optional conditions may return notEnoughInformation.

.PARAMETER SelfTest
    Run the local evaluation engine against mock policies and exit.
    Does not connect to Graph or open the GUI.
#>

[CmdletBinding()]
param(
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:AppVersion = '2.0'

# ------------------------------------------------------------
# STA host (WinForms). Skip when running automated tests.
# ------------------------------------------------------------
if (-not $SelfTest) {
    $apartment = [System.Threading.Thread]::CurrentThread.GetApartmentState()
    if ($apartment -ne [System.Threading.ApartmentState]::STA) {
        $exe = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell' }
        $argList = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        if ($PSBoundParameters.ContainsKey('SelfTest')) { $argList += '-SelfTest' }
        Start-Process -FilePath $exe -ArgumentList $argList -Wait -NoNewWindow
        exit $LASTEXITCODE
    }

    # Load WinForms before any window exists. SetCompatibleTextRenderingDefault
    # throws if ISE, VS Code, or a previous run already created an IWin32Window.
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Data
    [System.Windows.Forms.Application]::EnableVisualStyles()
    try {
        [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)
    } catch [System.InvalidOperationException] {
        # Host already created a window; visual styles still apply.
    }
}

# ============================================================
# CONSTANTS
# ============================================================
$script:GraphScopes = @(
    'Policy.Read.All',
    'User.Read.All',
    'GroupMember.Read.All',
    'Directory.Read.All',
    'Application.Read.All'
)

# First-party / bundle identifiers used by Conditional Access.
$script:WellKnownApps = [ordered]@{
    'All cloud apps'                         = 'All'
    'Office 365'                             = 'Office365'
    'Microsoft Admin Portals'                = 'MicrosoftAdminPortals'
    'Office 365 Exchange Online'             = '00000002-0000-0ff1-ce00-000000000000'
    'Office 365 SharePoint Online'           = '00000003-0000-0ff1-ce00-000000000000'
    'Office 365 Portal'                      = '00000006-0000-0ff1-ce00-000000000000'
    'Microsoft Teams'                        = '1fec8e78-bce4-4aaf-ab1b-5451cc387264'
    'Microsoft Teams Web Client'             = '5e3ce6c0-2b1f-4285-8d4b-75ee78787346'
    'Microsoft Office'                       = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
    'Microsoft Graph'                        = '00000003-0000-0000-c000-000000000000'
    'Azure Portal'                           = 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c'
    'Azure Service Management'               = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
    'Windows Azure Active Directory'         = '00000002-0000-0000-c000-000000000000'
    'Microsoft Intune'                       = '0000000a-0000-0000-c000-000000000000'
    'Microsoft Intune Enrollment'            = 'd4ebce55-015a-49b5-a083-c84d1797ae8c'
    'Microsoft Azure Management'             = 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c'
}

# Apps treated as members of the Office 365 bundle for local matching.
$script:Office365AppIds = @(
    '00000002-0000-0ff1-ce00-000000000000',
    '00000003-0000-0ff1-ce00-000000000000',
    '00000006-0000-0ff1-ce00-000000000000',
    '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
    '5e3ce6c0-2b1f-4285-8d4b-75ee78787346',
    'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe',
    'd3590ed6-52b3-4102-aeff-aad2292ab01c',
    '4345a7b9-9a63-4910-a426-35363201d503',
    '00000003-0000-0000-c000-000000000000'
)

$script:AdminPortalAppIds = @(
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c',
    '00000006-0000-0ff1-ce00-000000000000',
    '0000000a-0000-0000-c000-000000000000',
    '00000002-0000-0000-c000-000000000000'
)

$script:UserActionMap = [ordered]@{
    'None (cloud apps)'                = ''
    'Register security information'    = 'registerSecurityInformation'
    'Register or join devices'         = 'registerOrJoinDevices'
}

$script:UserActionUrn = @{
    'registerSecurityInformation' = 'urn:user:registersecurityinfo'
    'registerOrJoinDevices'       = 'urn:user:registerdevice'
}

$script:AnalysisReasonText = @{
    notSet                 = 'Policy applies to this sign-in'
    notEnoughInformation   = 'Not enough information to evaluate a configured condition'
    invalidCondition       = 'Policy condition is invalid'
    users                  = 'User is not included, or is excluded'
    workloadIdentities     = 'Workload identity does not match'
    application            = 'Cloud app does not match'
    userActions            = 'User action does not match'
    authenticationContext  = 'Authentication context does not match'
    devicePlatform         = 'Device platform does not match'
    devices                = 'Device state or device filter does not match'
    clientApps             = 'Client app does not match'
    location               = 'Network location does not match'
    signInRisk             = 'Sign-in risk does not match'
    emptyPolicy            = 'Policy has no assignments'
    invalidPolicy          = 'Policy is invalid'
    policyNotEnabled       = 'Policy is disabled'
    userRisk               = 'User risk does not match'
    time                   = 'Time condition does not match'
    insiderRisk            = 'Insider risk does not match'
    authenticationFlow     = 'Authentication flow does not match'
    agentIdRisk            = 'Agent ID risk does not match'
    agentIdentities        = 'Agent identity does not match'
    unknownFutureValue     = 'Unrecognized future condition'
}

$script:GrantControlText = @{
    block                 = 'Block access'
    mfa                   = 'Require multifactor authentication'
    compliantDevice       = 'Require device to be marked as compliant'
    domainJoinedDevice    = 'Require Microsoft Entra hybrid joined device'
    approvedApplication   = 'Require approved client app'
    compliantApplication  = 'Require app protection policy'
    passwordChange        = 'Require password change'
    unknownFutureValue    = 'Unknown future grant control'
}

# ============================================================
# SESSION STATE
# ============================================================
$script:IsConnected          = $false
$script:TenantName           = ''
$script:AccountUpn           = ''
$script:EngineName           = 'Not connected'
$script:PolicyCache          = @()
$script:NamedLocationCache   = @{}
$script:AppNameCache         = @{}
$script:AuthContextCache     = @{}
$script:GroupNameCache       = @{}
$script:RoleNameCache        = @{}
$script:LastResults          = @()
$script:LastScenario         = $null
$script:LastCombined         = $null
$script:LastUser             = $null
$script:LogEntries           = New-Object System.Collections.Generic.List[string]
$script:txtLog               = $null
$script:txtUpn               = $null
$script:txtDetail            = $null
$script:lblStatus            = $null
$script:lblEngine            = $null
$script:lblTenant            = $null
$script:lblCombined          = $null
$script:pnlCombined          = $null
$script:dgvApply             = $null
$script:dgvSkip              = $null
$script:splitMain            = $null
$script:splitResults         = $null
$script:tabApply             = $null
$script:tabSkip              = $null

# ============================================================
# GENERIC HELPERS
# ============================================================
function Get-Timestamp {
    Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
}

function Write-AppLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO'
    )
    $line = '[{0}] [{1}] {2}' -f (Get-Timestamp), $Level, $Message
    [void]$script:LogEntries.Add($line)
    if ($script:txtLog -and -not $script:txtLog.IsDisposed) {
        $script:txtLog.AppendText($line + [Environment]::NewLine)
        $script:txtLog.SelectionStart = $script:txtLog.Text.Length
        $script:txtLog.ScrollToCaret()
    }
}

function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [hashtable] -or $Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        foreach ($key in $Object.Keys) {
            if ([string]$key -eq $Name) { return $Object[$key] }
        }
        return $null
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function ConvertTo-StringArray {
    param($Value)
    $out = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Value) { return $out }
    foreach ($item in @($Value)) {
        if ($null -eq $item) { continue }
        $text = [string]$item
        if (-not [string]::IsNullOrWhiteSpace($text)) { [void]$out.Add($text) }
    }
    return $out
}

function Get-ItemCount {
    param($Value)
    if ($null -eq $Value) { return 0 }
    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return 0 }
        return 1
    }
    if ($Value -is [System.Collections.ICollection]) { return [int]$Value.Count }
    return @($Value).Count
}

function Test-CollectionContains {
    param($Collection, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    foreach ($item in (ConvertTo-StringArray $Collection)) {
        if ([string]::Equals($item, $Value, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function ConvertTo-PolicyStateLabel {
    param([string]$State)
    switch -Regex ($State) {
        '^(enabled|enabledForEnforcement)$' { return 'Enforced' }
        '^(reportOnly|enabledForReportingButNotEnforced)$' { return 'Report-Only' }
        '^(disabled)$' { return 'Disabled' }
        default { return $(if ($State) { $State } else { 'Unknown' }) }
    }
}

function ConvertTo-AnalysisReasonText {
    param([string]$Reason)
    if ([string]::IsNullOrWhiteSpace($Reason) -or $Reason -eq 'notSet') {
        return $script:AnalysisReasonText.notSet
    }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($token in @($Reason -split '[,\s|]+' | Where-Object { $_ })) {
        if ($script:AnalysisReasonText.ContainsKey($token)) {
            [void]$parts.Add($script:AnalysisReasonText[$token])
        } else {
            [void]$parts.Add($token)
        }
    }
    if ($parts.Count -eq 0) { return $Reason }
    return ($parts -join '; ')
}

function ConvertTo-UInt32IPv4 {
    param([string]$IpAddress)
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($IpAddress, [ref]$parsed)) { return $null }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $null }
    $bytes = $parsed.GetAddressBytes()
    return ([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3]
}

function Test-IpInCidr {
    param([string]$IpAddress, [string]$CidrOrIp)
    if ([string]::IsNullOrWhiteSpace($IpAddress) -or [string]::IsNullOrWhiteSpace($CidrOrIp)) {
        return $false
    }
    $target = $CidrOrIp.Trim()
    if ($target -notmatch '/') {
        return [string]::Equals($IpAddress.Trim(), $target, [System.StringComparison]::OrdinalIgnoreCase)
    }
    $parts = $target -split '/', 2
    $networkIp = ConvertTo-UInt32IPv4 -IpAddress $parts[0]
    $hostIp = ConvertTo-UInt32IPv4 -IpAddress $IpAddress
    if ($null -eq $networkIp -or $null -eq $hostIp) { return $false }
    $prefix = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefix)) { return $false }
    if ($prefix -lt 0 -or $prefix -gt 32) { return $false }
    if ($prefix -eq 0) { return $true }
    $maskBits = ('1' * $prefix).PadRight(32, '0')
    $mask = [Convert]::ToUInt32($maskBits, 2)
    return (($hostIp -band $mask) -eq ($networkIp -band $mask))
}

function Get-AppDisplayName {
    param([string]$AppId)
    if ([string]::IsNullOrWhiteSpace($AppId)) { return '' }
    if ($AppId -eq 'All') { return 'All cloud apps' }
    if ($AppId -eq 'Office365') { return 'Office 365' }
    if ($AppId -eq 'MicrosoftAdminPortals') { return 'Microsoft Admin Portals' }
    if ($script:AppNameCache.ContainsKey($AppId)) { return $script:AppNameCache[$AppId] }
    foreach ($name in $script:WellKnownApps.Keys) {
        if ($script:WellKnownApps[$name] -eq $AppId) { return $name }
    }
    return $AppId
}

# ============================================================
# GRAPH CONNECTION AND CACHE
# ============================================================
function Test-GraphModulePresent {
    if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) { return $true }
    if (Get-Module -ListAvailable -Name Microsoft.Graph) { return $true }
    return $false
}

function Connect-CaGraphSession {
    if (-not (Test-GraphModulePresent)) {
        throw 'Microsoft.Graph PowerShell SDK is not installed. Install-Module Microsoft.Graph -Scope CurrentUser'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $context = Get-MgContext -ErrorAction SilentlyContinue
    $needed = @($script:GraphScopes)
    $have = @()
    if ($context) { $have = @($context.Scopes) }
    $missing = @($needed | Where-Object { $have -notcontains $_ })
    if (-not $context -or $missing.Count -gt 0) {
        Connect-MgGraph -Scopes $needed -NoWelcome
        $context = Get-MgContext
    }
    if (-not $context) { throw 'Connect-MgGraph did not return a context.' }

    $script:IsConnected = $true
    $script:AccountUpn = [string]$context.Account
    try {
        $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName,id' -ErrorAction Stop
        $first = @($org.value) | Select-Object -First 1
        $script:TenantName = [string](Get-Prop $first 'displayName')
    } catch {
        $script:TenantName = [string]$context.TenantId
    }

    Initialize-PolicyCache
    Write-AppLog ("Connected as {0} to {1}" -f $script:AccountUpn, $script:TenantName) 'OK'
}

function Invoke-GraphGetAll {
    param([Parameter(Mandatory = $true)][string]$Uri)
    $items = @()
    $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next
        $items += @($page.value)
        $next = Get-Prop $page '@odata.nextLink'
        if (-not $next) { $next = Get-Prop $page 'odata.nextLink' }
    }
    return $items
}

function Initialize-PolicyCache {
    Write-AppLog 'Loading Conditional Access policies, named locations, and referenced apps...' 'INFO'
    $script:PolicyCache = @(Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies')
    if ($script:PolicyCache.Count -eq 0) {
        $script:PolicyCache = @(Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies')
    }

    $script:NamedLocationCache = @{}
    try {
        $locations = @(Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations')
        foreach ($loc in $locations) {
            $id = [string](Get-Prop $loc 'id')
            if ($id) { $script:NamedLocationCache[$id] = $loc }
        }
    } catch {
        Write-AppLog ("Named locations could not be loaded: {0}" -f $_.Exception.Message) 'WARN'
    }

    $script:AuthContextCache = @{}
    try {
        $contexts = @(Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences')
        foreach ($ctx in $contexts) {
            $id = [string](Get-Prop $ctx 'id')
            if ($id) { $script:AuthContextCache[$id] = [string](Get-Prop $ctx 'displayName') }
        }
    } catch {
        Write-AppLog ("Authentication contexts could not be loaded: {0}" -f $_.Exception.Message) 'WARN'
    }

    $script:AppNameCache = @{}
    foreach ($name in $script:WellKnownApps.Keys) {
        $script:AppNameCache[$script:WellKnownApps[$name]] = $name
    }
    $referenced = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($policy in $script:PolicyCache) {
        $apps = Get-Prop (Get-Prop $policy 'conditions') 'applications'
        foreach ($id in (ConvertTo-StringArray (Get-Prop $apps 'includeApplications'))) { [void]$referenced.Add($id) }
        foreach ($id in (ConvertTo-StringArray (Get-Prop $apps 'excludeApplications'))) { [void]$referenced.Add($id) }
    }
    foreach ($appId in $referenced) {
        if ($appId -in @('All', 'None', 'Office365', 'MicrosoftAdminPortals')) { continue }
        if ($script:AppNameCache.ContainsKey($appId)) { continue }
        try {
            $filter = "appId eq '$appId'"
            $sp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter={0}&`$select=appId,displayName&`$top=1" -f [uri]::EscapeDataString($filter))
            $row = @($sp.value) | Select-Object -First 1
            if ($row) { $script:AppNameCache[$appId] = [string](Get-Prop $row 'displayName') }
        } catch { }
    }

    Write-AppLog ("Cached {0} policies, {1} named locations, {2} auth contexts." -f $script:PolicyCache.Count, $script:NamedLocationCache.Count, $script:AuthContextCache.Count) 'OK'
}

function Resolve-CaUser {
    param([Parameter(Mandatory = $true)][string]$UserPrincipalName)
    $upn = $UserPrincipalName.Trim()
    if ([string]::IsNullOrWhiteSpace($upn)) { throw 'Enter a user principal name.' }

    $select = 'id,displayName,userPrincipalName,userType,accountEnabled,identities'
    try {
        return Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select={1}" -f [uri]::EscapeDataString($upn), $select)
    } catch { }

    $filter = "userPrincipalName eq '{0}' or mail eq '{0}' or proxyAddresses/any(p:p eq 'SMTP:{0}')" -f ($upn.Replace("'", "''"))
    $page = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/v1.0/users?`$filter={0}&`$select={1}&`$top=2" -f [uri]::EscapeDataString($filter), $select)
    $match = @($page.value)
    if ($match.Count -eq 1) { return $match[0] }
    if ($match.Count -gt 1) { throw "Multiple users matched '$upn'. Use the exact UPN." }
    throw "User '$upn' was not found."
}

function Get-UserMembershipSnapshot {
    param([Parameter(Mandatory = $true)]$User)

    $userId = [string](Get-Prop $User 'id')
    $groupIds = New-Object 'System.Collections.Generic.HashSet[string]'
    $roleIds = New-Object 'System.Collections.Generic.HashSet[string]'

    try {
        $members = @(Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users/{0}/transitiveMemberOf?`$select=id,displayName" -f $userId))
        foreach ($obj in $members) {
            $id = [string](Get-Prop $obj 'id')
            $type = [string](Get-Prop $obj '@odata.type')
            if (-not $id) { continue }
            if ($type -match 'directoryRole') {
                [void]$roleIds.Add($id)
                $name = [string](Get-Prop $obj 'displayName')
                if ($name) { $script:RoleNameCache[$id] = $name }
            } else {
                [void]$groupIds.Add($id)
                $name = [string](Get-Prop $obj 'displayName')
                if ($name) { $script:GroupNameCache[$id] = $name }
            }
        }
    } catch {
        Write-AppLog ("Transitive membership lookup failed, falling back to direct memberOf: {0}" -f $_.Exception.Message) 'WARN'
        $members = @(Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users/{0}/memberOf?`$select=id,displayName" -f $userId))
        foreach ($obj in $members) {
            $id = [string](Get-Prop $obj 'id')
            if ($id) { [void]$groupIds.Add($id) }
        }
    }

    try {
        $filter = "principalId eq '$userId'"
        $assignments = @(Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter={0}" -f [uri]::EscapeDataString($filter)))
        foreach ($row in $assignments) {
            $def = [string](Get-Prop $row 'roleDefinitionId')
            if ($def) { [void]$roleIds.Add($def) }
        }
    } catch {
        Write-AppLog ("Directory role assignments could not be loaded: {0}" -f $_.Exception.Message) 'WARN'
    }

    return [pscustomobject]@{
        UserId     = $userId
        GroupIds   = @($groupIds)
        RoleIds    = @($roleIds)
        UserType   = [string](Get-Prop $User 'userType')
        DisplayName = [string](Get-Prop $User 'displayName')
        Upn        = [string](Get-Prop $User 'userPrincipalName')
        Enabled    = [bool](Get-Prop $User 'accountEnabled')
    }
}

function Resolve-CloudAppId {
    param([string]$Selected)
    if ([string]::IsNullOrWhiteSpace($Selected)) { return $null }
    $text = $Selected.Trim()
    if ($script:WellKnownApps.Contains($text)) { return $script:WellKnownApps[$text] }
    if ($script:AppNameCache.ContainsKey($text)) { return $text }
    foreach ($key in @($script:AppNameCache.Keys)) {
        if ([string]::Equals($script:AppNameCache[$key], $text, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $key
        }
    }
    if ($text -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return $text }
    if ($text -in @('All', 'Office365', 'MicrosoftAdminPortals')) { return $text }
    return $text
}

# ============================================================
# LOCAL WHAT IF ENGINE
# Matches Entra assignment + condition semantics as closely as
# possible when the official evaluate API is unavailable.
# ============================================================
function Test-GuestMatch {
    param($UserSnapshot, $GuestCondition)
    if ($null -eq $GuestCondition) { return $false }
    $userType = [string]$UserSnapshot.UserType
    $isGuest = [string]::Equals($userType, 'Guest', [System.StringComparison]::OrdinalIgnoreCase)
    $types = ConvertTo-StringArray (Get-Prop $GuestCondition 'guestOrExternalUserTypes')
    if ((Get-ItemCount $types) -eq 0) { return $isGuest }
    foreach ($t in $types) {
        switch -Regex ($t) {
            'internalGuest' { if ($isGuest) { return $true } }
            'b2bCollaborationGuest' { if ($isGuest) { return $true } }
            'b2bCollaborationMember' { if ($isGuest) { return $true } }
            'otherExternalUser' { if ($isGuest) { return $true } }
            default { if ($isGuest) { return $true } }
        }
    }
    return $false
}

function Test-UserAssignment {
    param($PolicyUsers, $UserSnapshot)
    $includeUsers   = ConvertTo-StringArray (Get-Prop $PolicyUsers 'includeUsers')
    $excludeUsers   = ConvertTo-StringArray (Get-Prop $PolicyUsers 'excludeUsers')
    $includeGroups  = ConvertTo-StringArray (Get-Prop $PolicyUsers 'includeGroups')
    $excludeGroups  = ConvertTo-StringArray (Get-Prop $PolicyUsers 'excludeGroups')
    $includeRoles   = ConvertTo-StringArray (Get-Prop $PolicyUsers 'includeRoles')
    $excludeRoles   = ConvertTo-StringArray (Get-Prop $PolicyUsers 'excludeRoles')
    $includeGuests  = Get-Prop $PolicyUsers 'includeGuestsOrExternalUsers'
    $excludeGuests  = Get-Prop $PolicyUsers 'excludeGuestsOrExternalUsers'

    $reasons = New-Object System.Collections.Generic.List[string]
    $included = $false

    if (Test-CollectionContains $includeUsers 'None') {
        return @{ Matches = $false; Detail = 'Assignment is None' }
    }
    if (Test-CollectionContains $includeUsers 'All') {
        $included = $true
        [void]$reasons.Add('All users')
    }
    if (Test-CollectionContains $includeUsers $UserSnapshot.UserId) {
        $included = $true
        [void]$reasons.Add('Direct user assignment')
    }
    foreach ($gid in @($UserSnapshot.GroupIds)) {
        if (Test-CollectionContains $includeGroups $gid) {
            $included = $true
            $gname = if ($script:GroupNameCache.ContainsKey($gid)) { $script:GroupNameCache[$gid] } else { $gid }
            [void]$reasons.Add("Include group: $gname")
        }
    }
    foreach ($rid in @($UserSnapshot.RoleIds)) {
        if (Test-CollectionContains $includeRoles $rid) {
            $included = $true
            $rname = if ($script:RoleNameCache.ContainsKey($rid)) { $script:RoleNameCache[$rid] } else { $rid }
            [void]$reasons.Add("Include directory role: $rname")
        }
    }
    if (Test-GuestMatch -UserSnapshot $UserSnapshot -GuestCondition $includeGuests) {
        $included = $true
        [void]$reasons.Add('Guest or external user assignment')
    }

    if (-not $included) {
        return @{ Matches = $false; Detail = 'User is not in include users, groups, roles, or guests' }
    }

    if (Test-CollectionContains $excludeUsers $UserSnapshot.UserId) {
        return @{ Matches = $false; Detail = 'User is explicitly excluded' }
    }
    foreach ($gid in @($UserSnapshot.GroupIds)) {
        if (Test-CollectionContains $excludeGroups $gid) {
            $gname = if ($script:GroupNameCache.ContainsKey($gid)) { $script:GroupNameCache[$gid] } else { $gid }
            return @{ Matches = $false; Detail = "Excluded via group: $gname" }
        }
    }
    foreach ($rid in @($UserSnapshot.RoleIds)) {
        if (Test-CollectionContains $excludeRoles $rid) {
            return @{ Matches = $false; Detail = 'Excluded via directory role' }
        }
    }
    if (Test-GuestMatch -UserSnapshot $UserSnapshot -GuestCondition $excludeGuests) {
        return @{ Matches = $false; Detail = 'Excluded as guest or external user' }
    }

    return @{ Matches = $true; Detail = ($reasons -join '; ') }
}

function Test-AppBundleMatch {
    param([string]$SelectedAppId, [string]$PolicyAppId)
    if ([string]::Equals($SelectedAppId, $PolicyAppId, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($PolicyAppId -eq 'Office365' -and ($SelectedAppId -eq 'Office365' -or $script:Office365AppIds -contains $SelectedAppId)) { return $true }
    if ($SelectedAppId -eq 'Office365' -and ($PolicyAppId -eq 'Office365' -or $script:Office365AppIds -contains $PolicyAppId)) { return $true }
    if ($PolicyAppId -eq 'MicrosoftAdminPortals' -and ($SelectedAppId -eq 'MicrosoftAdminPortals' -or $script:AdminPortalAppIds -contains $SelectedAppId)) { return $true }
    if ($SelectedAppId -eq 'MicrosoftAdminPortals' -and ($PolicyAppId -eq 'MicrosoftAdminPortals' -or $script:AdminPortalAppIds -contains $PolicyAppId)) { return $true }
    return $false
}

function Test-ApplicationAssignment {
    param($PolicyApps, $Scenario)
    $includeApps     = ConvertTo-StringArray (Get-Prop $PolicyApps 'includeApplications')
    $excludeApps     = ConvertTo-StringArray (Get-Prop $PolicyApps 'excludeApplications')
    $includeActions  = ConvertTo-StringArray (Get-Prop $PolicyApps 'includeUserActions')
    $includeContexts = ConvertTo-StringArray (Get-Prop $PolicyApps 'includeAuthenticationContextClassReferences')

    if ($Scenario.ContextType -eq 'userAction') {
        if ((Get-ItemCount $includeActions) -eq 0) {
            return @{ Matches = $false; Reason = 'userActions'; Detail = 'Policy does not target user actions' }
        }
        $urn = $script:UserActionUrn[$Scenario.UserAction]
        $ok = (Test-CollectionContains $includeActions $Scenario.UserAction) -or
              ($urn -and (Test-CollectionContains $includeActions $urn))
        if ($ok) { return @{ Matches = $true; Reason = $null; Detail = 'User action matches' } }
        return @{ Matches = $false; Reason = 'userActions'; Detail = 'User action does not match' }
    }

    if ($Scenario.ContextType -eq 'authContext') {
        if ((Get-ItemCount $includeContexts) -eq 0) {
            return @{ Matches = $false; Reason = 'authenticationContext'; Detail = 'Policy does not target authentication context' }
        }
        if (Test-CollectionContains $includeContexts $Scenario.AuthContext) {
            return @{ Matches = $true; Reason = $null; Detail = 'Authentication context matches' }
        }
        return @{ Matches = $false; Reason = 'authenticationContext'; Detail = 'Authentication context does not match' }
    }

    # Cloud app sign-in. A policy that only targets user actions / auth
    # context must not apply just because applications were omitted.
    if ((Get-ItemCount $includeApps) -eq 0 -and ((Get-ItemCount $includeActions) -gt 0 -or (Get-ItemCount $includeContexts) -gt 0)) {
        return @{ Matches = $false; Reason = 'application'; Detail = 'Policy targets user actions or auth context, not this cloud app' }
    }
    if (Test-CollectionContains $includeApps 'None') {
        return @{ Matches = $false; Reason = 'application'; Detail = 'Application assignment is None' }
    }

    $selected = $Scenario.CloudAppId
    $included = $false
    if (Test-CollectionContains $includeApps 'All') {
        $included = $true
    } else {
        foreach ($app in $includeApps) {
            if (Test-AppBundleMatch -SelectedAppId $selected -PolicyAppId $app) { $included = $true; break }
        }
    }
    if (-not $included) {
        return @{ Matches = $false; Reason = 'application'; Detail = 'Cloud app is not in include applications' }
    }
    foreach ($app in $excludeApps) {
        if (Test-AppBundleMatch -SelectedAppId $selected -PolicyAppId $app) {
            return @{ Matches = $false; Reason = 'application'; Detail = 'Cloud app is excluded' }
        }
    }
    return @{ Matches = $true; Reason = $null; Detail = 'Cloud app matches' }
}

function Test-PlatformCondition {
    param($Platforms, $Scenario)
    if ($null -eq $Platforms) { return @{ Matches = $true; Detail = 'Platform condition not configured' } }
    $include = ConvertTo-StringArray (Get-Prop $Platforms 'includePlatforms')
    $exclude = ConvertTo-StringArray (Get-Prop $Platforms 'excludePlatforms')
    if ((Get-ItemCount $include) -eq 0 -and (Get-ItemCount $exclude) -eq 0) {
        return @{ Matches = $true; Detail = 'Platform condition not configured' }
    }
    if ([string]::IsNullOrWhiteSpace($Scenario.DevicePlatform) -or $Scenario.DevicePlatform -eq 'notSpecified') {
        return @{ Matches = $false; Reason = 'notEnoughInformation'; Detail = 'Policy has a platform condition and no platform was supplied' }
    }
    $selected = $Scenario.DevicePlatform
    $included = (Test-CollectionContains $include 'all') -or (Test-CollectionContains $include $selected)
    if (-not $included) { return @{ Matches = $false; Reason = 'devicePlatform'; Detail = "Platform $selected is not included" } }
    if (Test-CollectionContains $exclude $selected) {
        return @{ Matches = $false; Reason = 'devicePlatform'; Detail = "Platform $selected is excluded" }
    }
    return @{ Matches = $true; Detail = "Platform $selected matches" }
}

function Test-ClientAppCondition {
    param($ClientAppTypes, $Scenario)
    $types = ConvertTo-StringArray $ClientAppTypes
    if ((Get-ItemCount $types) -eq 0 -or (Test-CollectionContains $types 'all')) {
        return @{ Matches = $true; Detail = 'Client app condition not configured (all)' }
    }
    if ([string]::IsNullOrWhiteSpace($Scenario.ClientAppType) -or $Scenario.ClientAppType -eq 'notSpecified') {
        return @{ Matches = $false; Reason = 'notEnoughInformation'; Detail = 'Policy has a client-app condition and no client app was supplied' }
    }
    if (Test-CollectionContains $types $Scenario.ClientAppType) {
        return @{ Matches = $true; Detail = "Client app $($Scenario.ClientAppType) matches" }
    }
    return @{ Matches = $false; Reason = 'clientApps'; Detail = "Client app $($Scenario.ClientAppType) is not included" }
}

function Test-NamedLocationMatch {
    param($LocationId, $Scenario)
    if ($LocationId -eq 'All') { return $true }
    if (-not $script:NamedLocationCache.ContainsKey($LocationId)) { return $false }
    $loc = $script:NamedLocationCache[$LocationId]
    $type = [string](Get-Prop $loc '@odata.type')
    $isTrusted = [bool](Get-Prop $loc 'isTrusted')

    if ($LocationId -eq 'AllTrusted' -or $LocationId -eq '00000000-0000-0000-0000-000000000000') {
        return $false
    }

    if ($type -match 'ipNamedLocation' -or (Get-Prop $loc 'ipRanges')) {
        if ([string]::IsNullOrWhiteSpace($Scenario.IpAddress)) { return $null }
        foreach ($range in @((Get-Prop $loc 'ipRanges'))) {
            $cidr = [string](Get-Prop $range 'cidrAddress')
            if (-not $cidr) { $cidr = [string]$range }
            if (Test-IpInCidr -IpAddress $Scenario.IpAddress -CidrOrIp $cidr) { return $true }
        }
        return $false
    }
    if ($type -match 'countryNamedLocation' -or (Get-Prop $loc 'countriesAndRegions')) {
        if ([string]::IsNullOrWhiteSpace($Scenario.Country)) { return $null }
        $countries = ConvertTo-StringArray (Get-Prop $loc 'countriesAndRegions')
        if (Test-CollectionContains $countries $Scenario.Country) { return $true }
        if ((Get-Prop $loc 'includeUnknownCountriesAndRegions') -and $Scenario.Country -eq 'ZZ') { return $true }
        return $false
    }
    return $false
}

function Test-TrustedLocation {
    param($Scenario)
    foreach ($id in @($script:NamedLocationCache.Keys)) {
        $loc = $script:NamedLocationCache[$id]
        if (-not (Get-Prop $loc 'isTrusted')) { continue }
        $hit = Test-NamedLocationMatch -LocationId $id -Scenario $Scenario
        if ($hit -eq $true) { return $true }
        if ($null -eq $hit) { return $null }
    }
    return $false
}

function Test-LocationCondition {
    param($Locations, $Scenario)
    if ($null -eq $Locations) { return @{ Matches = $true; Detail = 'Location condition not configured' } }
    $include = ConvertTo-StringArray (Get-Prop $Locations 'includeLocations')
    $exclude = ConvertTo-StringArray (Get-Prop $Locations 'excludeLocations')
    if ((Get-ItemCount $include) -eq 0 -and (Get-ItemCount $exclude) -eq 0) {
        return @{ Matches = $true; Detail = 'Location condition not configured' }
    }
    if ([string]::IsNullOrWhiteSpace($Scenario.IpAddress) -and [string]::IsNullOrWhiteSpace($Scenario.Country)) {
        return @{ Matches = $false; Reason = 'notEnoughInformation'; Detail = 'Policy has a location condition and no IP/country was supplied' }
    }

    $included = $false
    $unknown = $false
    foreach ($id in $include) {
        if ($id -eq 'All') { $included = $true; break }
        if ($id -eq 'AllTrusted') {
            $trusted = Test-TrustedLocation -Scenario $Scenario
            if ($null -eq $trusted) { $unknown = $true }
            elseif ($trusted) { $included = $true }
            continue
        }
        $hit = Test-NamedLocationMatch -LocationId $id -Scenario $Scenario
        if ($null -eq $hit) { $unknown = $true }
        elseif ($hit) { $included = $true }
    }
    if ($unknown -and -not $included) {
        return @{ Matches = $false; Reason = 'notEnoughInformation'; Detail = 'Named location could not be fully evaluated' }
    }
    if (-not $included) {
        return @{ Matches = $false; Reason = 'location'; Detail = 'Sign-in location is not in include locations' }
    }

    foreach ($id in $exclude) {
        if ($id -eq 'AllTrusted') {
            $trusted = Test-TrustedLocation -Scenario $Scenario
            if ($trusted -eq $true) {
                return @{ Matches = $false; Reason = 'location'; Detail = 'Sign-in is from a trusted location that is excluded' }
            }
            continue
        }
        $hit = Test-NamedLocationMatch -LocationId $id -Scenario $Scenario
        if ($hit -eq $true) {
            return @{ Matches = $false; Reason = 'location'; Detail = 'Sign-in location is excluded' }
        }
    }
    return @{ Matches = $true; Detail = 'Location matches' }
}

function Test-DeviceCondition {
    param($Devices, $DeviceStates, $Scenario)
    $hasLegacy = $false
    $includeStates = @()
    $excludeStates = @()
    if ($DeviceStates) {
        $includeStates = ConvertTo-StringArray (Get-Prop $DeviceStates 'includeStates')
        $excludeStates = ConvertTo-StringArray (Get-Prop $DeviceStates 'excludeStates')
        if ((Get-ItemCount $includeStates) -gt 0 -or (Get-ItemCount $excludeStates) -gt 0) { $hasLegacy = $true }
    }

    $filter = $null
    if ($Devices) { $filter = Get-Prop $Devices 'deviceFilter' }

    if (-not $hasLegacy -and $null -eq $filter) {
        return @{ Matches = $true; Detail = 'Device condition not configured' }
    }
    if ($Scenario.DeviceState -eq 'notSpecified' -or [string]::IsNullOrWhiteSpace($Scenario.DeviceState)) {
        return @{ Matches = $false; Reason = 'notEnoughInformation'; Detail = 'Policy has a device condition and no device state was supplied' }
    }

    $compliant = $Scenario.IsCompliant
    $hybrid = $Scenario.IsHybridJoined

    if ($hasLegacy) {
        $included = $false
        foreach ($state in $includeStates) {
            switch -Regex ($state) {
                'compliant' { if ($compliant) { $included = $true } }
                'domainJoined|hybrid' { if ($hybrid) { $included = $true } }
                'all' { $included = $true }
                default { $included = $true }
            }
        }
        if ((Get-ItemCount $includeStates) -eq 0) { $included = $true }
        foreach ($state in $excludeStates) {
            switch -Regex ($state) {
                'compliant' { if ($compliant) { $included = $false } }
                'domainJoined|hybrid' { if ($hybrid) { $included = $false } }
            }
        }
        if (-not $included) {
            return @{ Matches = $false; Reason = 'devices'; Detail = 'Device state does not match include/exclude device states' }
        }
    }

    if ($filter) {
        $mode = [string](Get-Prop $filter 'mode')
        $rule = [string](Get-Prop $filter 'rule')
        $eval = Test-SimpleDeviceFilter -Rule $rule -IsCompliant $compliant -IsHybridJoined $hybrid
        if ($null -eq $eval) {
            return @{ Matches = $false; Reason = 'notEnoughInformation'; Detail = "Device filter cannot be evaluated locally: $rule" }
        }
        $match = $eval
        if ($mode -match 'exclude') { $match = -not $eval }
        if (-not $match) {
            return @{ Matches = $false; Reason = 'devices'; Detail = 'Device filter did not match' }
        }
    }

    return @{ Matches = $true; Detail = 'Device condition matches' }
}

function Test-SimpleDeviceFilter {
    param([string]$Rule, [bool]$IsCompliant, [bool]$IsHybridJoined)
    if ([string]::IsNullOrWhiteSpace($Rule)) { return $true }
    $normalized = $Rule.Trim()
    if ($normalized -match 'device\.isCompliant\s+-eq\s+\$?True') { return $IsCompliant }
    if ($normalized -match 'device\.isCompliant\s+-eq\s+\$?False') { return -not $IsCompliant }
    if ($normalized -match 'device\.trustType\s+-eq\s+"ServerAD"') { return $IsHybridJoined }
    if ($normalized -match 'device\.trustType\s+-eq\s+"AzureAD"') { return (-not $IsHybridJoined) }
    if ($normalized -match 'device\.trustType\s+-ne\s+"ServerAD"') { return (-not $IsHybridJoined) }
    return $null
}

function Test-RiskCondition {
    param($ConfiguredLevels, [string]$SelectedLevel, [string]$ReasonName, [string]$Label)
    $levels = ConvertTo-StringArray $ConfiguredLevels
    if ((Get-ItemCount $levels) -eq 0) { return @{ Matches = $true; Detail = "$Label condition not configured" } }
    if ([string]::IsNullOrWhiteSpace($SelectedLevel) -or $SelectedLevel -eq 'notSpecified') {
        return @{ Matches = $false; Reason = 'notEnoughInformation'; Detail = "Policy has a $Label condition and no value was supplied" }
    }
    if (Test-CollectionContains $levels $SelectedLevel) {
        return @{ Matches = $true; Detail = "$Label $SelectedLevel matches" }
    }
    return @{ Matches = $false; Reason = $ReasonName; Detail = "$Label $SelectedLevel is not included" }
}

function Test-AuthenticationFlowCondition {
    param($Flows, $Scenario)
    if ($null -eq $Flows) { return @{ Matches = $true; Detail = 'Authentication flow condition not configured' } }
    $methods = ConvertTo-StringArray (Get-Prop $Flows 'transferMethods')
    if ((Get-ItemCount $methods) -eq 0) { return @{ Matches = $true; Detail = 'Authentication flow condition not configured' } }
    if ([string]::IsNullOrWhiteSpace($Scenario.AuthFlow) -or $Scenario.AuthFlow -eq 'none') {
        return @{ Matches = $false; Reason = 'authenticationFlow'; Detail = 'Policy requires an authentication-flow transfer and none was supplied' }
    }
    if (Test-CollectionContains $methods $Scenario.AuthFlow) {
        return @{ Matches = $true; Detail = "Authentication flow $($Scenario.AuthFlow) matches" }
    }
    return @{ Matches = $false; Reason = 'authenticationFlow'; Detail = 'Authentication flow does not match' }
}

function ConvertTo-GrantSummary {
    param($GrantControls)
    if ($null -eq $GrantControls) { return 'Grant (no extra controls)' }
    $builtIn = ConvertTo-StringArray (Get-Prop $GrantControls 'builtInControls')
    if (Test-CollectionContains $builtIn 'block') { return 'Block access' }
    $labels = New-Object System.Collections.Generic.List[string]
    foreach ($c in $builtIn) {
        if ($script:GrantControlText.ContainsKey($c)) { [void]$labels.Add($script:GrantControlText[$c]) }
        else { [void]$labels.Add($c) }
    }
    $strength = Get-Prop $GrantControls 'authenticationStrength'
    if ($strength) {
        $sname = Get-Prop $strength 'displayName'
        if (-not $sname) { $sname = Get-Prop $strength 'id' }
        if ($sname) { [void]$labels.Add("Authentication strength: $sname") }
    }
    foreach ($tou in (ConvertTo-StringArray (Get-Prop $GrantControls 'termsOfUse'))) {
        [void]$labels.Add("Terms of use: $tou")
    }
    if ($labels.Count -eq 0) { return 'Grant (no extra controls)' }
    $op = [string](Get-Prop $GrantControls 'operator')
    if ($op -eq 'OR') { return ($labels -join ' OR ') }
    return ($labels -join ' AND ')
}

function ConvertTo-SessionSummary {
    param($SessionControls)
    if ($null -eq $SessionControls) { return '' }
    $parts = New-Object System.Collections.Generic.List[string]
    $aer = Get-Prop $SessionControls 'applicationEnforcedRestrictions'
    if ($aer -and (Get-Prop $aer 'isEnabled')) { [void]$parts.Add('Application enforced restrictions') }
    $cas = Get-Prop $SessionControls 'cloudAppSecurity'
    if ($cas -and (Get-Prop $cas 'isEnabled')) {
        $ctype = Get-Prop $cas 'cloudAppSecurityType'
        [void]$parts.Add($(if ($ctype) { "Conditional Access App Control ($ctype)" } else { 'Conditional Access App Control' }))
    }
    $sif = Get-Prop $SessionControls 'signInFrequency'
    if ($sif -and (Get-Prop $sif 'isEnabled')) {
        $interval = Get-Prop $sif 'frequencyInterval'
        if ($interval -eq 'everyTime') {
            [void]$parts.Add('Sign-in frequency: every time')
        } else {
            [void]$parts.Add(('Sign-in frequency: {0} {1}' -f (Get-Prop $sif 'value'), (Get-Prop $sif 'type')))
        }
    }
    $pb = Get-Prop $SessionControls 'persistentBrowser'
    if ($pb -and (Get-Prop $pb 'isEnabled')) {
        [void]$parts.Add(('Persistent browser: {0}' -f (Get-Prop $pb 'mode')))
    }
    if (Get-Prop $SessionControls 'disableResilienceDefaults') { [void]$parts.Add('Disable resilience defaults') }
    $cae = Get-Prop $SessionControls 'continuousAccessEvaluation'
    if ($cae) { [void]$parts.Add(('Continuous access evaluation: {0}' -f (Get-Prop $cae 'mode'))) }
    return ($parts -join '; ')
}

function Invoke-LocalWhatIfEvaluate {
    param(
        [Parameter(Mandatory = $true)]$UserSnapshot,
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)]$Policies
    )

    $results = @()
    foreach ($policy in $Policies) {
        $name = [string](Get-Prop $policy 'displayName')
        $state = [string](Get-Prop $policy 'state')
        $conditions = Get-Prop $policy 'conditions'
        $matchNotes = New-Object System.Collections.Generic.List[string]

        if ($state -eq 'disabled') {
            $results += New-WhatIfRow -Policy $policy -Applies $false -Reason 'policyNotEnabled' -Detail 'Policy is disabled' -MatchNotes @()
            continue
        }

        $userTest = Test-UserAssignment -PolicyUsers (Get-Prop $conditions 'users') -UserSnapshot $UserSnapshot
        if (-not $userTest.Matches) {
            $results += New-WhatIfRow -Policy $policy -Applies $false -Reason 'users' -Detail $userTest.Detail -MatchNotes @()
            continue
        }
        [void]$matchNotes.Add($userTest.Detail)

        $appTest = Test-ApplicationAssignment -PolicyApps (Get-Prop $conditions 'applications') -Scenario $Scenario
        if (-not $appTest.Matches) {
            $reason = $appTest.Reason
            if (-not $reason) { $reason = 'application' }
            $results += New-WhatIfRow -Policy $policy -Applies $false -Reason $reason -Detail $appTest.Detail -MatchNotes @($matchNotes)
            continue
        }
        [void]$matchNotes.Add($appTest.Detail)

        $platTest = Test-PlatformCondition -Platforms (Get-Prop $conditions 'platforms') -Scenario $Scenario
        if (-not $platTest.Matches) {
            $results += New-WhatIfRow -Policy $policy -Applies $false -Reason $platTest.Reason -Detail $platTest.Detail -MatchNotes @($matchNotes)
            continue
        }
        [void]$matchNotes.Add($platTest.Detail)

        $clientTest = Test-ClientAppCondition -ClientAppTypes (Get-Prop $conditions 'clientAppTypes') -Scenario $Scenario
        if (-not $clientTest.Matches) {
            $results += New-WhatIfRow -Policy $policy -Applies $false -Reason $clientTest.Reason -Detail $clientTest.Detail -MatchNotes @($matchNotes)
            continue
        }
        [void]$matchNotes.Add($clientTest.Detail)

        $locTest = Test-LocationCondition -Locations (Get-Prop $conditions 'locations') -Scenario $Scenario
        if (-not $locTest.Matches) {
            $results += New-WhatIfRow -Policy $policy -Applies $false -Reason $locTest.Reason -Detail $locTest.Detail -MatchNotes @($matchNotes)
            continue
        }
        [void]$matchNotes.Add($locTest.Detail)

        $devTest = Test-DeviceCondition -Devices (Get-Prop $conditions 'devices') -DeviceStates (Get-Prop $conditions 'deviceStates') -Scenario $Scenario
        if (-not $devTest.Matches) {
            $results += New-WhatIfRow -Policy $policy -Applies $false -Reason $devTest.Reason -Detail $devTest.Detail -MatchNotes @($matchNotes)
            continue
        }
        [void]$matchNotes.Add($devTest.Detail)

        $sirTest = Test-RiskCondition -ConfiguredLevels (Get-Prop $conditions 'signInRiskLevels') -SelectedLevel $Scenario.SignInRisk -ReasonName 'signInRisk' -Label 'Sign-in risk'
        if (-not $sirTest.Matches) {
            $results += New-WhatIfRow -Policy $policy -Applies $false -Reason $sirTest.Reason -Detail $sirTest.Detail -MatchNotes @($matchNotes)
            continue
        }
        [void]$matchNotes.Add($sirTest.Detail)

        $urTest = Test-RiskCondition -ConfiguredLevels (Get-Prop $conditions 'userRiskLevels') -SelectedLevel $Scenario.UserRisk -ReasonName 'userRisk' -Label 'User risk'
        if (-not $urTest.Matches) {
            $results += New-WhatIfRow -Policy $policy -Applies $false -Reason $urTest.Reason -Detail $urTest.Detail -MatchNotes @($matchNotes)
            continue
        }
        [void]$matchNotes.Add($urTest.Detail)

        $irConfigured = Get-Prop $conditions 'insiderRiskLevels'
        if ($irConfigured) {
            $irTest = Test-RiskCondition -ConfiguredLevels $irConfigured -SelectedLevel $Scenario.InsiderRisk -ReasonName 'insiderRisk' -Label 'Insider risk'
            if (-not $irTest.Matches) {
                $results += New-WhatIfRow -Policy $policy -Applies $false -Reason $irTest.Reason -Detail $irTest.Detail -MatchNotes @($matchNotes)
                continue
            }
            [void]$matchNotes.Add($irTest.Detail)
        }

        $flowTest = Test-AuthenticationFlowCondition -Flows (Get-Prop $conditions 'authenticationFlows') -Scenario $Scenario
        if (-not $flowTest.Matches) {
            $results += New-WhatIfRow -Policy $policy -Applies $false -Reason $flowTest.Reason -Detail $flowTest.Detail -MatchNotes @($matchNotes)
            continue
        }
        [void]$matchNotes.Add($flowTest.Detail)

        $results += New-WhatIfRow -Policy $policy -Applies $true -Reason 'notSet' -Detail ($matchNotes -join ' | ') -MatchNotes @($matchNotes)
    }
    return $results
}

function New-WhatIfRow {
    param($Policy, [bool]$Applies, [string]$Reason, [string]$Detail, [string[]]$MatchNotes)
    $grant = Get-Prop $Policy 'grantControls'
    $session = Get-Prop $Policy 'sessionControls'
    $state = [string](Get-Prop $Policy 'state')
    return [pscustomobject]@{
        PolicyId        = [string](Get-Prop $Policy 'id')
        PolicyName      = [string](Get-Prop $Policy 'displayName')
        PolicyState     = ConvertTo-PolicyStateLabel -State $state
        RawState        = $state
        Applies         = $Applies
        AnalysisReason  = $Reason
        ReasonText      = ConvertTo-AnalysisReasonText -Reason $Reason
        Detail          = $Detail
        GrantControls   = ConvertTo-GrantSummary -GrantControls $grant
        SessionControls = ConvertTo-SessionSummary -SessionControls $session
        GrantObject     = $grant
        SessionObject   = $session
        Conditions      = Get-Prop $Policy 'conditions'
        MatchNotes      = ($MatchNotes -join ' | ')
        Source          = 'local'
    }
}

# ============================================================
# OFFICIAL GRAPH WHAT IF ENGINE
# ============================================================
function New-GraphEvaluateBody {
    param([Parameter(Mandatory = $true)]$User, [Parameter(Mandatory = $true)]$Scenario)

    $identity = @{
        '@odata.type' = '#microsoft.graph.userSignIn'
        userId        = [string](Get-Prop $User 'id')
    }
    if ($Scenario.IdentityType -match 'Guest') {
        $identity.externalUserType = 'b2bCollaborationGuest'
    }

    switch ($Scenario.ContextType) {
        'userAction' {
            $context = @{
                '@odata.type' = '#microsoft.graph.userActionContext'
                userAction    = $Scenario.UserAction
            }
        }
        'authContext' {
            $context = @{
                '@odata.type'               = '#microsoft.graph.authContext'
                authenticationContextValue  = $Scenario.AuthContext
            }
        }
        default {
            $appId = $Scenario.CloudAppId
            if ($appId -eq 'All' -or $appId -eq 'Office365' -or $appId -eq 'MicrosoftAdminPortals') {
                # Graph evaluate does not accept bundle tokens. Use a
                # representative first-party app and flag the limitation.
                $appId = '00000003-0000-0ff1-ce00-000000000000'
            }
            $context = @{
                '@odata.type'         = '#microsoft.graph.applicationContext'
                includeApplications   = @($appId)
            }
        }
    }

    $conditions = @{}
    if ($Scenario.DevicePlatform -and $Scenario.DevicePlatform -ne 'notSpecified') {
        $conditions.devicePlatform = $Scenario.DevicePlatform
    }
    if ($Scenario.ClientAppType -and $Scenario.ClientAppType -ne 'notSpecified') {
        $conditions.clientAppType = $Scenario.ClientAppType
    }
    if ($Scenario.IpAddress) { $conditions.ipAddress = $Scenario.IpAddress }
    if ($Scenario.Country) { $conditions.country = $Scenario.Country.ToUpper() }
    if ($Scenario.SignInRisk -and $Scenario.SignInRisk -ne 'notSpecified') {
        $conditions.signInRiskLevel = $Scenario.SignInRisk
    }
    if ($Scenario.UserRisk -and $Scenario.UserRisk -ne 'notSpecified') {
        $conditions.userRiskLevel = $Scenario.UserRisk
    }
    if ($Scenario.InsiderRisk -and $Scenario.InsiderRisk -ne 'notSpecified' -and $Scenario.InsiderRisk -ne 'none') {
        $conditions.insiderRiskLevel = $Scenario.InsiderRisk
    }
    if ($Scenario.AuthFlow -and $Scenario.AuthFlow -ne 'none') {
        $conditions.authenticationFlow = @{ transferMethod = $Scenario.AuthFlow }
    }
    if ($Scenario.DeviceState -and $Scenario.DeviceState -ne 'notSpecified') {
        $info = @{}
        if ($Scenario.IsCompliant) { $info.isCompliant = $true }
        if ($Scenario.IsHybridJoined) { $info.trustType = 'ServerAD' }
        elseif ($Scenario.DeviceState -eq 'entraJoined') { $info.trustType = 'AzureAD' }
        elseif ($Scenario.DeviceState -eq 'registered') { $info.trustType = 'Workplace' }
        if ($info.Count -gt 0) { $conditions.deviceInfo = $info }
    }
    if ($conditions.Count -eq 0) {
        $conditions.devicePlatform = 'windows'
        $conditions.clientAppType = 'browser'
    }

    return @{
        signInIdentity      = $identity
        signInContext       = $context
        signInConditions    = $conditions
        appliedPoliciesOnly = $false
    }
}

function ConvertFrom-GraphWhatIfResult {
    param($GraphItem)
    $reason = [string](Get-Prop $GraphItem 'analysisReasons')
    if (-not $reason) { $reason = 'notSet' }
    $applies = $false
    $flag = Get-Prop $GraphItem 'policyApplies'
    if ($flag -eq $true -or "$flag" -eq 'True') { $applies = $true }
    $state = [string](Get-Prop $GraphItem 'state')
    $grant = Get-Prop $GraphItem 'grantControls'
    $session = Get-Prop $GraphItem 'sessionControls'
    return [pscustomobject]@{
        PolicyId        = [string](Get-Prop $GraphItem 'id')
        PolicyName      = [string](Get-Prop $GraphItem 'displayName')
        PolicyState     = ConvertTo-PolicyStateLabel -State $state
        RawState        = $state
        Applies         = $applies
        AnalysisReason  = $reason
        ReasonText      = ConvertTo-AnalysisReasonText -Reason $reason
        Detail          = ConvertTo-AnalysisReasonText -Reason $reason
        GrantControls   = ConvertTo-GrantSummary -GrantControls $grant
        SessionControls = ConvertTo-SessionSummary -SessionControls $session
        GrantObject     = $grant
        SessionObject   = $session
        Conditions      = Get-Prop $GraphItem 'conditions'
        MatchNotes      = ''
        Source          = 'graph'
    }
}

function Invoke-GraphWhatIfEvaluate {
    param([Parameter(Mandatory = $true)]$User, [Parameter(Mandatory = $true)]$Scenario)

    $body = New-GraphEvaluateBody -User $User -Scenario $Scenario
    $uris = @(
        'https://graph.microsoft.com/v1.0/identity/conditionalAccess/evaluate',
        'https://graph.microsoft.com/beta/identity/conditionalAccess/evaluate'
    )
    $lastError = $null
    foreach ($uri in $uris) {
        try {
            Write-AppLog ("Calling What If evaluate API: {0}" -f $uri) 'INFO'
            try {
                $response = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body
            } catch {
                $json = $body | ConvertTo-Json -Depth 8 -Compress
                $response = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $json
            }
            $items = @(Get-Prop $response 'value')
            if ($items.Count -eq 0 -and (Get-Prop $response 'id')) { $items = @($response) }
            $rows = @()
            foreach ($item in $items) { $rows += ConvertFrom-GraphWhatIfResult -GraphItem $item }
            return $rows
        } catch {
            $lastError = $_
            Write-AppLog ("Evaluate API failed on {0}: {1}" -f $uri, $_.Exception.Message) 'WARN'
        }
    }
    throw $lastError
}

# ============================================================
# COMBINED ACCESS DECISION
# Enforced policies AND together. Block wins. Report-only is
# informational and never treated as an enforcement control.
# ============================================================
function Get-CombinedAccessDecision {
    param([Parameter(Mandatory = $true)][object[]]$Results)

    $enforcedApply = @($Results | Where-Object { $_.Applies -and $_.PolicyState -eq 'Enforced' })
    $reportApply   = @($Results | Where-Object { $_.Applies -and $_.PolicyState -eq 'Report-Only' })
    $gaps          = New-Object System.Collections.Generic.List[string]

    $blockPolicies = @()
    $grantLines    = New-Object System.Collections.Generic.List[string]
    $sessionLines  = New-Object System.Collections.Generic.List[string]

    foreach ($row in $enforcedApply) {
        if ($row.GrantControls -match '^Block access') {
            $blockPolicies += $row.PolicyName
        } else {
            [void]$grantLines.Add(('{0}: {1}' -f $row.PolicyName, $row.GrantControls))
        }
        if ($row.SessionControls) {
            [void]$sessionLines.Add(('{0}: {1}' -f $row.PolicyName, $row.SessionControls))
        }
    }

    $outcome = 'Grant'
    $headline = 'No enforced Conditional Access policies apply. Access is granted by default.'
    $severity = 'Gap'

    if ($blockPolicies.Count -gt 0) {
        $outcome = 'Block'
        $headline = 'Access is blocked by enforced policy: ' + ($blockPolicies -join '; ')
        $severity = 'Block'
    } elseif ($enforcedApply.Count -gt 0) {
        $outcome = 'GrantWithControls'
        $headline = 'Access is granted only if every enforced control below is satisfied.'
        $severity = 'Controls'
    } else {
        [void]$gaps.Add('No enforced policy applies to this sign-in. Confirm this is intentional (break-glass or uncovered scenario).')
    }

    if ($reportApply.Count -gt 0) {
        [void]$gaps.Add(('{0} report-only policy/policies would apply but are not enforced.' -f $reportApply.Count))
    }

    $notEnough = @($Results | Where-Object { -not $_.Applies -and $_.AnalysisReason -match 'notEnoughInformation' })
    if ($notEnough.Count -gt 0) {
        [void]$gaps.Add(('{0} policy/policies could not be fully evaluated (missing condition values).' -f $notEnough.Count))
    }

    return [pscustomobject]@{
        Outcome          = $outcome
        Severity         = $severity
        Headline         = $headline
        EnforcedCount    = $enforcedApply.Count
        ReportOnlyCount  = $reportApply.Count
        BlockPolicies    = $blockPolicies
        GrantLines       = @($grantLines)
        SessionLines     = @($sessionLines)
        Gaps             = @($gaps)
    }
}

function Format-PolicyDetail {
    param($Row, $UserSnapshot, $Scenario)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine(('Policy: {0}' -f $Row.PolicyName))
    [void]$sb.AppendLine(('Id:     {0}' -f $Row.PolicyId))
    [void]$sb.AppendLine(('State:  {0}' -f $Row.PolicyState))
    [void]$sb.AppendLine(('Applies to this sign-in: {0}' -f $Row.Applies))
    [void]$sb.AppendLine(('Reason: {0}' -f $Row.ReasonText))
    if ($Row.Detail) { [void]$sb.AppendLine(('Detail: {0}' -f $Row.Detail)) }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Grant controls:')
    [void]$sb.AppendLine('  ' + $Row.GrantControls)
    if ($Row.SessionControls) {
        [void]$sb.AppendLine('Session controls:')
        [void]$sb.AppendLine('  ' + $Row.SessionControls)
    }
    $apps = Get-Prop $Row.Conditions 'applications'
    if ($apps) {
        $inc = (ConvertTo-StringArray (Get-Prop $apps 'includeApplications')) | ForEach-Object { Get-AppDisplayName $_ }
        $exc = (ConvertTo-StringArray (Get-Prop $apps 'excludeApplications')) | ForEach-Object { Get-AppDisplayName $_ }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Cloud apps include: ' + $(if ($inc) { $inc -join ', ' } else { '(none)' }))
        if ($exc) { [void]$sb.AppendLine('Cloud apps exclude: ' + ($exc -join ', ')) }
        $actions = ConvertTo-StringArray (Get-Prop $apps 'includeUserActions')
        if ($actions) { [void]$sb.AppendLine('User actions: ' + ($actions -join ', ')) }
        $ctx = ConvertTo-StringArray (Get-Prop $apps 'includeAuthenticationContextClassReferences')
        if ($ctx) { [void]$sb.AppendLine('Auth context: ' + ($ctx -join ', ')) }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('Engine: {0}' -f $Row.Source))
    [void]$sb.AppendLine(('Evaluated user: {0}' -f $UserSnapshot.Upn))
    [void]$sb.AppendLine(('Target: {0} / platform {1} / client {2}' -f $Scenario.CloudAppId, $Scenario.DevicePlatform, $Scenario.ClientAppType))
    return $sb.ToString()
}

# ============================================================
# SELF-TEST (no Graph, no GUI)
# ============================================================
function New-MockPolicy {
    param(
        [string]$Name,
        [string]$State = 'enabled',
        [hashtable]$Users,
        [hashtable]$Applications,
        [string[]]$ClientAppTypes = @(),
        [hashtable]$Platforms,
        [hashtable]$Locations,
        [hashtable]$Grant
    )
    return [pscustomobject]@{
        id             = [guid]::NewGuid().ToString()
        displayName    = $Name
        state          = $State
        conditions     = [pscustomobject]@{
            users            = [pscustomobject]$Users
            applications     = [pscustomobject]$Applications
            clientAppTypes   = $ClientAppTypes
            platforms        = $(if ($Platforms) { [pscustomobject]$Platforms } else { $null })
            locations        = $(if ($Locations) { [pscustomobject]$Locations } else { $null })
            devices          = $null
            deviceStates     = $null
            signInRiskLevels = @()
            userRiskLevels   = @()
            insiderRiskLevels = $null
            authenticationFlows = $null
        }
        grantControls  = $(if ($Grant) { [pscustomobject]$Grant } else { $null })
        sessionControls = $null
    }
}

function Invoke-CaSelfTest {
    $failed = 0
    $passed = 0
    $user = [pscustomobject]@{
        UserId      = '11111111-1111-1111-1111-111111111111'
        GroupIds    = @('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
        RoleIds     = @()
        UserType    = 'Member'
        DisplayName = 'Test User'
        Upn         = 'user@contoso.com'
        Enabled     = $true
    }
    $scenario = [pscustomobject]@{
        ContextType      = 'application'
        CloudAppId       = '00000003-0000-0ff1-ce00-000000000000'
        UserAction       = ''
        AuthContext      = ''
        DevicePlatform   = 'windows'
        ClientAppType    = 'browser'
        IpAddress        = '10.0.0.8'
        Country          = 'US'
        DeviceState      = 'notSpecified'
        IsCompliant      = $false
        IsHybridJoined   = $false
        SignInRisk       = 'notSpecified'
        UserRisk         = 'notSpecified'
        InsiderRisk      = 'notSpecified'
        AuthFlow         = 'none'
    }

    function Assert-True {
        param([bool]$Condition, [string]$Name)
        if ($Condition) {
            Write-Host "PASS  $Name" -ForegroundColor Green
            $script:__pass++
        } else {
            Write-Host "FAIL  $Name" -ForegroundColor Red
            $script:__fail++
        }
    }
    $script:__pass = 0
    $script:__fail = 0

    $allUsersMfa = New-MockPolicy -Name 'All users MFA Office365' -Users @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('Office365'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() } -Grant @{ builtInControls = @('mfa'); operator = 'AND' }
    $rows = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $user -Scenario $scenario -Policies @($allUsersMfa))
    Assert-True ($rows[0].Applies -eq $true) 'Office 365 bundle matches SharePoint Online sign-in'
    Assert-True ($rows[0].GrantControls -match 'multifactor') 'Grant control surfaces MFA'

    $excludeUser = New-MockPolicy -Name 'Exclude this user' -Users @{ includeUsers = @('All'); excludeUsers = @($user.UserId); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() }
    $rows = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $user -Scenario $scenario -Policies @($excludeUser))
    Assert-True ($rows[0].Applies -eq $false -and $rows[0].AnalysisReason -eq 'users') 'Explicit user exclusion wins'

    $groupOnly = New-MockPolicy -Name 'Group include' -Users @{ includeUsers = @(); excludeUsers = @(); includeGroups = @('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() }
    $rows = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $user -Scenario $scenario -Policies @($groupOnly))
    Assert-True ($rows[0].Applies -eq $true) 'Transitive/direct group include applies'

    $otherGroup = New-MockPolicy -Name 'Other group' -Users @{ includeUsers = @(); excludeUsers = @(); includeGroups = @('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() }
    $rows = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $user -Scenario $scenario -Policies @($otherGroup))
    Assert-True ($rows[0].Applies -eq $false -and $rows[0].AnalysisReason -eq 'users') 'Non-member group does not apply'

    $disabled = New-MockPolicy -Name 'Disabled' -State 'disabled' -Users @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() }
    $rows = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $user -Scenario $scenario -Policies @($disabled))
    Assert-True ($rows[0].Applies -eq $false -and $rows[0].AnalysisReason -eq 'policyNotEnabled') 'Disabled policies never apply'

    $exchangeOnly = New-MockPolicy -Name 'Exchange only' -Users @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('00000002-0000-0ff1-ce00-000000000000'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() }
    $rows = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $user -Scenario $scenario -Policies @($exchangeOnly))
    Assert-True ($rows[0].Applies -eq $false -and $rows[0].AnalysisReason -eq 'application') 'Cloud-app mismatch does not apply (original script bug)'

    $androidOnly = New-MockPolicy -Name 'Android only' -Users @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() } -Platforms @{ includePlatforms = @('android'); excludePlatforms = @() }
    $rows = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $user -Scenario $scenario -Policies @($androidOnly))
    Assert-True ($rows[0].Applies -eq $false -and $rows[0].AnalysisReason -eq 'devicePlatform') 'Platform condition is required, not a reason to apply'

    $clientMobile = New-MockPolicy -Name 'Mobile clients' -Users @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() } -ClientAppTypes @('mobileAppsAndDesktopClients')
    $rows = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $user -Scenario $scenario -Policies @($clientMobile))
    Assert-True ($rows[0].Applies -eq $false -and $rows[0].AnalysisReason -eq 'clientApps') 'Client-app condition is required, not a reason to apply'

    $block = New-MockPolicy -Name 'Block legacy' -Users @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() } -Grant @{ builtInControls = @('block'); operator = 'AND' }
    $mfa = New-MockPolicy -Name 'Require MFA' -Users @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() } -Grant @{ builtInControls = @('mfa'); operator = 'AND' }
    $rows = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $user -Scenario $scenario -Policies @($block, $mfa))
    $combined = Get-CombinedAccessDecision -Results $rows
    Assert-True ($combined.Outcome -eq 'Block') 'Block grant wins over MFA when both apply'

    $report = New-MockPolicy -Name 'Report only MFA' -State 'enabledForReportingButNotEnforced' -Users @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() } -Grant @{ builtInControls = @('mfa'); operator = 'AND' }
    $rows = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $user -Scenario $scenario -Policies @($report))
    $combined = Get-CombinedAccessDecision -Results $rows
    Assert-True ($combined.Outcome -eq 'Grant' -and $combined.Severity -eq 'Gap') 'Report-only is not treated as enforced'
    Assert-True ($rows[0].Applies -eq $true -and $rows[0].PolicyState -eq 'Report-Only') 'Report-only still listed as applying'

    $empty = New-MockPolicy -Name 'Nobody' -Users @{ includeUsers = @('None'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() }
    $rows = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $user -Scenario $scenario -Policies @($empty))
    Assert-True ($rows[0].Applies -eq $false -and $rows[0].AnalysisReason -eq 'users') 'Include users None never applies'

    $riskPolicy = New-MockPolicy -Name 'High sign-in risk' -Users @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() }
    $riskPolicy.conditions = [pscustomobject]@{
        users                 = $riskPolicy.conditions.users
        applications          = $riskPolicy.conditions.applications
        clientAppTypes        = @()
        platforms             = $null
        locations             = $null
        devices               = $null
        deviceStates          = $null
        signInRiskLevels      = @('high')
        userRiskLevels        = @()
        insiderRiskLevels     = $null
        authenticationFlows   = $null
    }
    $rows = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $user -Scenario $scenario -Policies @($riskPolicy))
    Assert-True ($rows[0].Applies -eq $false -and $rows[0].AnalysisReason -eq 'notEnoughInformation') 'Configured risk without a value is not guessed'

    $script:NamedLocationCache = @{
        'loc-trusted' = [pscustomobject]@{
            id           = 'loc-trusted'
            isTrusted    = $true
            '@odata.type' = '#microsoft.graph.ipNamedLocation'
            ipRanges     = @([pscustomobject]@{ cidrAddress = '10.0.0.0/8' })
        }
    }
    $locPolicy = New-MockPolicy -Name 'Trusted locations' -Users @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } -Applications @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() } -Locations @{ includeLocations = @('AllTrusted'); excludeLocations = @() }
    $rows = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $user -Scenario $scenario -Policies @($locPolicy))
    Assert-True ($rows[0].Applies -eq $true) 'Trusted named location matches RFC1918 IP'
    $script:NamedLocationCache = @{}

    $pass = $script:__pass
    $fail = $script:__fail
    Write-Host ''
    Write-Host ("Self-test: {0} passed, {1} failed" -f $pass, $fail)
    if ($fail -gt 0) { return 1 }
    return 0
}

# ============================================================
# SCENARIO + EVALUATION ORCHESTRATION
# ============================================================
function New-SignInScenarioFromUi {
    $actionKey = [string]$script:cmbUserAction.SelectedItem
    $authCtx = [string]$script:txtAuthContext.Text
    if ($authCtx) { $authCtx = $authCtx.Trim() }

    $contextType = 'application'
    $userAction = ''
    if ($script:UserActionMap.Contains($actionKey) -and $script:UserActionMap[$actionKey]) {
        $contextType = 'userAction'
        $userAction = $script:UserActionMap[$actionKey]
    } elseif ($authCtx) {
        $contextType = 'authContext'
    }

    $deviceKey = [string]$script:cmbDeviceState.SelectedItem
    $isCompliant = $false
    $isHybrid = $false
    $deviceState = 'notSpecified'
    switch ($deviceKey) {
        'Compliant'                          { $deviceState = 'compliant'; $isCompliant = $true }
        'Microsoft Entra hybrid joined'      { $deviceState = 'hybrid'; $isHybrid = $true }
        'Compliant and hybrid joined'        { $deviceState = 'compliantHybrid'; $isCompliant = $true; $isHybrid = $true }
        'Microsoft Entra joined'             { $deviceState = 'entraJoined' }
        'Microsoft Entra registered'         { $deviceState = 'registered' }
        'Not compliant / not hybrid joined'  { $deviceState = 'notCompliant' }
    }

    $ip = [string]$script:txtIp.Text
    if ($ip) { $ip = $ip.Trim() }
    $country = [string]$script:cmbCountry.Text
    if ($country -eq '(not specified)') { $country = '' }
    if ($country) { $country = $country.Trim().ToUpper() }

    $platform = Get-ComboValue -Combo $script:cmbPlatform -Map @{
        '(not specified)' = 'notSpecified'
        'Windows'         = 'windows'
        'Windows Phone'   = 'windowsPhone'
        'macOS'           = 'macOS'
        'iOS'             = 'iOS'
        'Android'         = 'android'
        'Linux'           = 'linux'
    }
    $client = Get-ComboValue -Combo $script:cmbClientApp -Map @{
        '(not specified)'                    = 'notSpecified'
        'Browser'                            = 'browser'
        'Mobile apps and desktop clients'    = 'mobileAppsAndDesktopClients'
        'Exchange ActiveSync'                = 'exchangeActiveSync'
        'Other clients (legacy)'             = 'other'
    }
    $signInRisk = Get-ComboValue -Combo $script:cmbSignInRisk -Map @{
        '(not specified)' = 'notSpecified'
        'No risk'         = 'none'
        'Low'             = 'low'
        'Medium'          = 'medium'
        'High'            = 'high'
    }
    $userRisk = Get-ComboValue -Combo $script:cmbUserRisk -Map @{
        '(not specified)' = 'notSpecified'
        'No risk'         = 'none'
        'Low'             = 'low'
        'Medium'          = 'medium'
        'High'            = 'high'
    }
    $insider = Get-ComboValue -Combo $script:cmbInsiderRisk -Map @{
        '(not specified)' = 'notSpecified'
        'No risk'         = 'none'
        'Minor'           = 'minor'
        'Moderate'        = 'moderate'
        'Elevated'        = 'elevated'
    }
    $flow = Get-ComboValue -Combo $script:cmbAuthFlow -Map @{
        'None'                     = 'none'
        'Device code flow'         = 'deviceCodeFlow'
        'Authentication transfer'  = 'authenticationTransfer'
    }

    return [pscustomobject]@{
        ContextType     = $contextType
        CloudAppId      = Resolve-CloudAppId -Selected ([string]$script:cmbCloudApp.Text)
        UserAction      = $userAction
        AuthContext     = $authCtx
        DevicePlatform  = $platform
        ClientAppType   = $client
        IpAddress       = $ip
        Country         = $country
        DeviceState     = $deviceState
        IsCompliant     = $isCompliant
        IsHybridJoined  = $isHybrid
        SignInRisk      = $signInRisk
        UserRisk        = $userRisk
        InsiderRisk     = $insider
        AuthFlow        = $flow
        IdentityType    = [string]$script:cmbIdentityType.SelectedItem
    }
}

function Get-ComboValue {
    param($Combo, [hashtable]$Map)
    $text = [string]$Combo.SelectedItem
    if (-not $text) { $text = [string]$Combo.Text }
    if ($Map.ContainsKey($text)) { return $Map[$text] }
    return $text
}

function Invoke-WhatIfEvaluation {
    if (-not $script:IsConnected) {
        throw 'Connect to Microsoft Graph before running What If.'
    }
    $upn = [string]$script:txtUpn.Text
    if ([string]::IsNullOrWhiteSpace($upn)) { throw 'Enter a user principal name.' }

    $user = Resolve-CaUser -UserPrincipalName $upn
    $snapshot = Get-UserMembershipSnapshot -User $user
    $scenario = New-SignInScenarioFromUi
    if ([string]::IsNullOrWhiteSpace($scenario.CloudAppId) -and $scenario.ContextType -eq 'application') {
        throw 'Select a target cloud app (required by What If).'
    }
    if ($scenario.DevicePlatform -eq 'notSpecified' -or $scenario.ClientAppType -eq 'notSpecified') {
        throw 'Device platform and client app are required, matching the Entra What If tool.'
    }

    Write-AppLog ("Evaluating {0} ({1}) against {2} cached policies." -f $snapshot.Upn, $snapshot.UserId, $script:PolicyCache.Count) 'INFO'

    $results = @()
    try {
        $results = @(Invoke-GraphWhatIfEvaluate -User $user -Scenario $scenario)
        if ($results.Count -eq 0) { throw 'Evaluate API returned no policies.' }
        $script:EngineName = 'Microsoft Graph What If API'
        if ($scenario.CloudAppId -in @('All', 'Office365', 'MicrosoftAdminPortals')) {
            Write-AppLog 'Graph evaluate does not accept bundle app tokens. SharePoint Online was used as the representative target. Re-run with a specific app for tighter results.' 'WARN'
        }
    } catch {
        Write-AppLog ("Graph What If API unavailable, using local evaluator: {0}" -f $_.Exception.Message) 'WARN'
        $results = @(Invoke-LocalWhatIfEvaluate -UserSnapshot $snapshot -Scenario $scenario -Policies $script:PolicyCache)
        $script:EngineName = 'Local fallback evaluator'
    }

    $script:LastResults  = $results
    $script:LastScenario = $scenario
    $script:LastUser     = $snapshot
    $script:LastCombined = Get-CombinedAccessDecision -Results $results
    Write-AppLog ("{0}: {1} apply, {2} do not apply. Combined: {3}" -f $script:EngineName, @($results | Where-Object Applies).Count, @($results | Where-Object { -not $_.Applies }).Count, $script:LastCombined.Outcome) 'OK'
    Update-ResultsUi
}

# ============================================================
# GUI HELPERS (Windows 7 Aero)
# ============================================================
function New-AeroColor {
    param([int]$R, [int]$G, [int]$B)
    return [System.Drawing.Color]::FromArgb($R, $G, $B)
}

function New-UiFont {
    param([double]$Size = 9, [System.Drawing.FontStyle]$Style = [System.Drawing.FontStyle]::Regular)
    return New-Object System.Drawing.Font('Segoe UI', $Size, $Style)
}

function New-FieldLabel {
    param([string]$Text, [int]$X, [int]$Y, [int]$Width = 320)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Text
    $lbl.Location = New-Object System.Drawing.Point($X, $Y)
    $lbl.Size = New-Object System.Drawing.Size($Width, 18)
    $lbl.Font = New-UiFont -Size 8.5
    $lbl.ForeColor = New-AeroColor 40 62 88
    $lbl.BackColor = [System.Drawing.Color]::Transparent
    return $lbl
}

function New-FieldBox {
    param([int]$X, [int]$Y, [int]$Width = 320, [int]$Height = 24)
    $box = New-Object System.Windows.Forms.TextBox
    $box.Location = New-Object System.Drawing.Point($X, $Y)
    $box.Size = New-Object System.Drawing.Size($Width, $Height)
    $box.Font = New-UiFont -Size 9
    $box.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $box.BackColor = [System.Drawing.Color]::White
    return $box
}

function New-FieldCombo {
    param([int]$X, [int]$Y, [int]$Width = 320, [string[]]$Items, [int]$SelectedIndex = 0)
    $cmb = New-Object System.Windows.Forms.ComboBox
    $cmb.Location = New-Object System.Drawing.Point($X, $Y)
    $cmb.Size = New-Object System.Drawing.Size($Width, 24)
    $cmb.Font = New-UiFont -Size 9
    $cmb.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown
    $cmb.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    if ($Items) { [void]$cmb.Items.AddRange($Items) }
    if ($cmb.Items.Count -gt $SelectedIndex) { $cmb.SelectedIndex = $SelectedIndex }
    return $cmb
}

function New-AeroButton {
    param(
        [string]$Text,
        [int]$X,
        [int]$Y,
        [int]$Width = 150,
        [int]$Height = 32,
        [ValidateSet('Primary', 'Secondary', 'Danger', 'Ok')]$Kind = 'Secondary'
    )
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $Text
    $btn.Location = New-Object System.Drawing.Point($X, $Y)
    $btn.Size = New-Object System.Drawing.Size($Width, $Height)
    $btn.Font = New-UiFont -Size 9 -Style ([System.Drawing.FontStyle]::Bold)
    $btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $btn.UseVisualStyleBackColor = $false
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    switch ($Kind) {
        'Primary' {
            $btn.BackColor = New-AeroColor 43 117 198
            $btn.ForeColor = [System.Drawing.Color]::White
        }
        'Ok' {
            $btn.BackColor = New-AeroColor 46 125 50
            $btn.ForeColor = [System.Drawing.Color]::White
        }
        'Danger' {
            $btn.BackColor = New-AeroColor 183 70 40
            $btn.ForeColor = [System.Drawing.Color]::White
        }
        default {
            $btn.BackColor = New-AeroColor 232 239 247
            $btn.ForeColor = New-AeroColor 27 63 110
        }
    }
    return $btn
}

function Set-SplitContainerLayout {
    param(
        [Parameter(Mandatory = $true)][System.Windows.Forms.SplitContainer]$Split,
        [int]$DesiredDistance,
        [int]$Panel1Min = 150,
        [int]$Panel2Min = 150
    )
    if ($null -eq $Split -or $Split.IsDisposed) { return }

    $span = if ($Split.Orientation -eq [System.Windows.Forms.Orientation]::Vertical) {
        $Split.Width
    } else {
        $Split.Height
    }
    $bar = [Math]::Max(1, $Split.SplitterWidth)
    if ($span -le ($bar + 40)) { return }

    $usable = $span - $bar
    $p1 = [Math]::Min($Panel1Min, [int]($usable / 3))
    $p2 = [Math]::Min($Panel2Min, [int]($usable / 3))
    if ($p1 -lt 25) { $p1 = 25 }
    if ($p2 -lt 25) { $p2 = 25 }
    if (($p1 + $p2) -ge $usable) {
        $p1 = 25
        $p2 = 25
    }

    try {
        # Reset mins first so SplitterDistance can be assigned on the current size.
        $Split.Panel1MinSize = 25
        $Split.Panel2MinSize = 25
        $min = $p1
        $max = $usable - $p2
        if ($max -lt $min) { return }
        $distance = $DesiredDistance
        if ($distance -lt $min) { $distance = $min }
        if ($distance -gt $max) { $distance = $max }
        $Split.SplitterDistance = $distance
        $Split.Panel1MinSize = $p1
        $Split.Panel2MinSize = $p2
    } catch {
        # Control handle or size is not ready yet; Shown will retry.
    }
}

function Set-GridChrome {
    param($Grid)
    $Grid.AllowUserToAddRows = $false
    $Grid.AllowUserToDeleteRows = $false
    $Grid.ReadOnly = $true
    $Grid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $Grid.MultiSelect = $false
    $Grid.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
    $Grid.BackgroundColor = [System.Drawing.Color]::White
    $Grid.BorderStyle = [System.Windows.Forms.BorderStyle]::Fixed3D
    $Grid.RowHeadersVisible = $false
    $Grid.EnableHeadersVisualStyles = $false
    $Grid.ColumnHeadersHeight = 30
    $Grid.RowTemplate.Height = 26
    $Grid.ColumnHeadersDefaultCellStyle.BackColor = New-AeroColor 27 79 138
    $Grid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $Grid.ColumnHeadersDefaultCellStyle.Font = New-UiFont -Size 8.5 -Style ([System.Drawing.FontStyle]::Bold)
    $Grid.DefaultCellStyle.Font = New-UiFont -Size 8.5
    $Grid.DefaultCellStyle.SelectionBackColor = New-AeroColor 164 201 236
    $Grid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::Black
    $Grid.AlternatingRowsDefaultCellStyle.BackColor = New-AeroColor 240 247 252
    $Grid.GridColor = New-AeroColor 196 214 230
}

function Add-ResultColumns {
    param($Grid)
    $Grid.Columns.Clear()
    foreach ($spec in @(
            @{ Name = 'PolicyName'; Header = 'Policy'; Weight = 28 },
            @{ Name = 'PolicyState'; Header = 'State'; Weight = 10 },
            @{ Name = 'GrantControls'; Header = 'Grant controls'; Weight = 26 },
            @{ Name = 'SessionControls'; Header = 'Session controls'; Weight = 16 },
            @{ Name = 'ReasonText'; Header = 'Why'; Weight = 20 }
        )) {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $col.Name = $spec.Name
        $col.HeaderText = $spec.Header
        $col.DataPropertyName = $spec.Name
        $col.FillWeight = $spec.Weight
        [void]$Grid.Columns.Add($col)
    }
}

function Update-StatusBar {
    param([string]$Text)
    if ($script:lblStatus -and -not $script:lblStatus.IsDisposed) {
        $script:lblStatus.Text = $Text
    }
    if ($script:lblEngine -and -not $script:lblEngine.IsDisposed) {
        $script:lblEngine.Text = "Engine: $($script:EngineName)"
    }
    if ($script:lblTenant -and -not $script:lblTenant.IsDisposed) {
        if ($script:IsConnected) {
            $script:lblTenant.Text = "Tenant: $($script:TenantName)"
        } else {
            $script:lblTenant.Text = 'Tenant: not connected'
        }
    }
}

function Bind-ResultGrid {
    param($Grid, $Rows)
    $table = New-Object System.Data.DataTable
    foreach ($name in @('PolicyName', 'PolicyState', 'GrantControls', 'SessionControls', 'ReasonText', 'PolicyId')) {
        [void]$table.Columns.Add($name)
    }
    foreach ($row in $Rows) {
        $dr = $table.NewRow()
        $dr['PolicyName'] = $row.PolicyName
        $dr['PolicyState'] = $row.PolicyState
        $dr['GrantControls'] = $row.GrantControls
        $dr['SessionControls'] = $row.SessionControls
        $dr['ReasonText'] = $row.ReasonText
        $dr['PolicyId'] = $row.PolicyId
        [void]$table.Rows.Add($dr)
    }
    $Grid.DataSource = $table
    if ($Grid.Columns['PolicyId']) { $Grid.Columns['PolicyId'].Visible = $false }
}

function Apply-RowColors {
    param($Grid)
    foreach ($viewRow in $Grid.Rows) {
        if ($viewRow.IsNewRow) { continue }
        $state = [string]$viewRow.Cells['PolicyState'].Value
        switch ($state) {
            'Enforced'    { $viewRow.DefaultCellStyle.BackColor = New-AeroColor 210 237 210 }
            'Report-Only' { $viewRow.DefaultCellStyle.BackColor = New-AeroColor 255 246 196 }
            'Disabled'    { $viewRow.DefaultCellStyle.BackColor = New-AeroColor 230 230 230 }
        }
    }
}

function Update-ResultsUi {
    $apply = @($script:LastResults | Where-Object { $_.Applies } | Sort-Object PolicyState, PolicyName)
    $skip  = @($script:LastResults | Where-Object { -not $_.Applies } | Sort-Object PolicyState, PolicyName)
    Bind-ResultGrid -Grid $script:dgvApply -Rows $apply
    Bind-ResultGrid -Grid $script:dgvSkip  -Rows $skip
    Apply-RowColors -Grid $script:dgvApply
    Apply-RowColors -Grid $script:dgvSkip

    $script:tabApply.Text = ('  Policies that apply ({0})  ' -f $apply.Count)
    $script:tabSkip.Text  = ('  Policies that do not apply ({0})  ' -f $skip.Count)

    $c = $script:LastCombined
    $script:lblCombined.Text = $c.Headline
    switch ($c.Severity) {
        'Block'    { $script:pnlCombined.BackColor = New-AeroColor 183 70 40; $script:lblCombined.ForeColor = [System.Drawing.Color]::White }
        'Controls' { $script:pnlCombined.BackColor = New-AeroColor 232 184 36; $script:lblCombined.ForeColor = New-AeroColor 50 40 0 }
        'Gap'      { $script:pnlCombined.BackColor = New-AeroColor 198 80 40; $script:lblCombined.ForeColor = [System.Drawing.Color]::White }
        default    { $script:pnlCombined.BackColor = New-AeroColor 46 125 50; $script:lblCombined.ForeColor = [System.Drawing.Color]::White }
    }

    $detail = New-Object System.Text.StringBuilder
    [void]$detail.AppendLine($c.Headline)
    [void]$detail.AppendLine('')
    if ($c.GrantLines.Count -gt 0) {
        [void]$detail.AppendLine('Enforced grant controls (all must be satisfied):')
        foreach ($line in $c.GrantLines) { [void]$detail.AppendLine('  • ' + $line) }
        [void]$detail.AppendLine('')
    }
    if ($c.SessionLines.Count -gt 0) {
        [void]$detail.AppendLine('Session controls:')
        foreach ($line in $c.SessionLines) { [void]$detail.AppendLine('  • ' + $line) }
        [void]$detail.AppendLine('')
    }
    if ($c.Gaps.Count -gt 0) {
        [void]$detail.AppendLine('Coverage warnings:')
        foreach ($line in $c.Gaps) { [void]$detail.AppendLine('  • ' + $line) }
        [void]$detail.AppendLine('')
    }
    [void]$detail.AppendLine(('User: {0}  |  Groups: {1}  |  Directory roles: {2}' -f $script:LastUser.Upn, $script:LastUser.GroupIds.Count, $script:LastUser.RoleIds.Count))
    [void]$detail.AppendLine(('Engine: {0}' -f $script:EngineName))
    [void]$detail.AppendLine('What If does not expand Conditional Access service dependencies.')
    $script:txtDetail.Text = $detail.ToString()
    Update-StatusBar -Text ("Ready — {0} policies evaluated." -f $script:LastResults.Count)
}

function Show-SelectedPolicyDetail {
    param($Grid)
    if (-not $Grid.CurrentRow) { return }
    $id = [string]$Grid.CurrentRow.Cells['PolicyId'].Value
    $row = @($script:LastResults | Where-Object { $_.PolicyId -eq $id } | Select-Object -First 1)
    if (-not $row) { return }
    $script:txtDetail.Text = Format-PolicyDetail -Row $row -UserSnapshot $script:LastUser -Scenario $script:LastScenario
}

function Export-WhatIfReport {
    if (-not $script:LastResults -or $script:LastResults.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Run a What If evaluation before exporting.', 'Nothing to export', 'OK', 'Information') | Out-Null
        return
    }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV (*.csv)|*.csv|Text (*.txt)|*.txt|All files (*.*)|*.*'
    $dlg.FileName = ('CA-WhatIf_{0}_{1}' -f ($script:LastUser.Upn -replace '[^\w\.\-@]', '_'), (Get-Date -Format 'yyyyMMdd_HHmmss'))
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    if ($dlg.FileName -like '*.csv') {
        $script:LastResults |
            Select-Object PolicyName, PolicyState, Applies, ReasonText, Detail, GrantControls, SessionControls, PolicyId, Source |
            Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
    } else {
        $script:txtDetail.Text + [Environment]::NewLine + ($script:LogEntries -join [Environment]::NewLine) |
            Set-Content -Path $dlg.FileName -Encoding UTF8
    }
    Write-AppLog ("Exported report to {0}" -f $dlg.FileName) 'OK'
}

function Show-ErrorDialog {
    param([string]$Message)
    [System.Windows.Forms.MessageBox]::Show($Message, 'Conditional Access What If', 'OK', 'Error') | Out-Null
}

# ============================================================
# MAIN FORM
# ============================================================
function Show-WhatIfForm {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Data
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $aeroBg     = New-AeroColor 227 238 249
    $glass      = New-AeroColor 244 249 253
    $panelEdge  = New-AeroColor 164 191 216
    $navy       = New-AeroColor 20 55 100

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Conditional Access What If  —  Windows Aero  •  v$script:AppVersion"
    $form.StartPosition = 'CenterScreen'
    $form.Size = New-Object System.Drawing.Size(1280, 820)
    $form.MinimumSize = New-Object System.Drawing.Size(1100, 700)
    $form.BackColor = $aeroBg
    $form.Font = New-UiFont -Size 9
    $form.KeyPreview = $true

    $header = New-Object System.Windows.Forms.Panel
    $header.Dock = 'Top'
    $header.Height = 78
    $header.Add_Paint({
        param($s, $e)
        $rect = $s.ClientRectangle
        $c1 = [System.Drawing.Color]::FromArgb(255, 22, 82, 145)
        $c2 = [System.Drawing.Color]::FromArgb(255, 74, 155, 219)
        $c3 = [System.Drawing.Color]::FromArgb(255, 186, 222, 247)
        $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $c1, $c2, 90.0)
        $e.Graphics.FillRectangle($brush, $rect)
        $shine = New-Object System.Drawing.Rectangle(0, 0, $rect.Width, [int]($rect.Height / 2))
        $shineBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($shine, [System.Drawing.Color]::FromArgb(90, 255, 255, 255), [System.Drawing.Color]::FromArgb(0, 255, 255, 255), 90.0)
        $e.Graphics.FillRectangle($shineBrush, $shine)
        $brush.Dispose()
        $shineBrush.Dispose()
    })

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = 'Conditional Access  —  What If'
    $lblTitle.Font = New-UiFont -Size 18 -Style ([System.Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor = [System.Drawing.Color]::White
    $lblTitle.BackColor = [System.Drawing.Color]::Transparent
    $lblTitle.Location = New-Object System.Drawing.Point(18, 10)
    $lblTitle.AutoSize = $true

    $lblSub = New-Object System.Windows.Forms.Label
    $lblSub.Text = 'Simulate a sign-in the same way as Microsoft Entra ID  •  Graph evaluate API  •  Local fallback for coverage gaps'
    $lblSub.Font = New-UiFont -Size 9
    $lblSub.ForeColor = New-AeroColor 220 236 250
    $lblSub.BackColor = [System.Drawing.Color]::Transparent
    $lblSub.Location = New-Object System.Drawing.Point(20, 46)
    $lblSub.AutoSize = $true
    $header.Controls.AddRange(@($lblTitle, $lblSub))

    $status = New-Object System.Windows.Forms.StatusStrip
    $status.SizingGrip = $true
    $status.BackColor = New-AeroColor 214 228 241
    $script:lblStatus = New-Object System.Windows.Forms.ToolStripStatusLabel
    $script:lblStatus.Spring = $true
    $script:lblStatus.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $script:lblStatus.Text = 'Ready — connect to Microsoft Graph to load policies.'
    $script:lblEngine = New-Object System.Windows.Forms.ToolStripStatusLabel
    $script:lblEngine.Text = 'Engine: not connected'
    $script:lblTenant = New-Object System.Windows.Forms.ToolStripStatusLabel
    $script:lblTenant.Text = 'Tenant: not connected'
    [void]$status.Items.AddRange(@($script:lblStatus, $script:lblEngine, $script:lblTenant))

    $script:splitMain = New-Object System.Windows.Forms.SplitContainer
    $script:splitMain.Dock = 'Fill'
    $script:splitMain.SplitterWidth = 6
    $script:splitMain.BackColor = $panelEdge
    $script:splitMain.Panel1.BackColor = $glass
    $script:splitMain.Panel2.BackColor = $aeroBg

    # ----- Left: sign-in conditions (scrollable Aero group) -----
    $leftScroll = New-Object System.Windows.Forms.Panel
    $leftScroll.Dock = 'Fill'
    $leftScroll.AutoScroll = $true
    $leftScroll.BackColor = $glass
    $leftScroll.Padding = New-Object System.Windows.Forms.Padding(8)

    $grpIdentity = New-Object System.Windows.Forms.GroupBox
    $grpIdentity.Text = ' Identity '
    $grpIdentity.Font = New-UiFont -Size 9 -Style ([System.Drawing.FontStyle]::Bold)
    $grpIdentity.ForeColor = $navy
    $grpIdentity.Location = New-Object System.Drawing.Point(12, 10)
    $grpIdentity.Size = New-Object System.Drawing.Size(340, 118)

    $script:txtUpn = New-FieldBox -X 12 -Y 42 -Width 316
    $script:cmbIdentityType = New-FieldCombo -X 12 -Y 86 -Width 316 -Items @('User', 'Guest or external user') -SelectedIndex 0
    $grpIdentity.Controls.AddRange(@(
            (New-FieldLabel -Text 'User principal name *' -X 12 -Y 22),
            $script:txtUpn,
            (New-FieldLabel -Text 'Identity type' -X 12 -Y 68),
            $script:cmbIdentityType
        ))

    $grpTarget = New-Object System.Windows.Forms.GroupBox
    $grpTarget.Text = ' Target resource '
    $grpTarget.Font = New-UiFont -Size 9 -Style ([System.Drawing.FontStyle]::Bold)
    $grpTarget.ForeColor = $navy
    $grpTarget.Location = New-Object System.Drawing.Point(12, 136)
    $grpTarget.Size = New-Object System.Drawing.Size(340, 168)

    $script:cmbCloudApp = New-FieldCombo -X 12 -Y 42 -Width 316 -Items @($script:WellKnownApps.Keys) -SelectedIndex 4
    $script:cmbUserAction = New-FieldCombo -X 12 -Y 86 -Width 316 -Items @($script:UserActionMap.Keys) -SelectedIndex 0
    $script:txtAuthContext = New-FieldBox -X 12 -Y 130 -Width 316
    $grpTarget.Controls.AddRange(@(
            (New-FieldLabel -Text 'Cloud app *' -X 12 -Y 22),
            $script:cmbCloudApp,
            (New-FieldLabel -Text 'User action (optional)' -X 12 -Y 68),
            $script:cmbUserAction,
            (New-FieldLabel -Text 'Authentication context id (optional)' -X 12 -Y 112),
            $script:txtAuthContext
        ))

    $grpCond = New-Object System.Windows.Forms.GroupBox
    $grpCond.Text = ' Sign-in conditions '
    $grpCond.Font = New-UiFont -Size 9 -Style ([System.Drawing.FontStyle]::Bold)
    $grpCond.ForeColor = $navy
    $grpCond.Location = New-Object System.Drawing.Point(12, 312)
    $grpCond.Size = New-Object System.Drawing.Size(340, 430)

    $script:cmbPlatform = New-FieldCombo -X 12 -Y 42 -Width 316 -Items @('(not specified)', 'Windows', 'Windows Phone', 'macOS', 'iOS', 'Android', 'Linux') -SelectedIndex 1
    $script:cmbClientApp = New-FieldCombo -X 12 -Y 86 -Width 316 -Items @('(not specified)', 'Browser', 'Mobile apps and desktop clients', 'Exchange ActiveSync', 'Other clients (legacy)') -SelectedIndex 1
    $script:txtIp = New-FieldBox -X 12 -Y 130 -Width 316
    $script:cmbCountry = New-FieldCombo -X 12 -Y 174 -Width 316 -Items @('(not specified)', 'US', 'CA', 'GB', 'DE', 'FR', 'AU', 'IN', 'JP', 'BR', 'MX', 'NL', 'IE', 'SG', 'AE', 'ZZ') -SelectedIndex 0
    $script:cmbDeviceState = New-FieldCombo -X 12 -Y 218 -Width 316 -Items @(
        '(not specified)',
        'Compliant',
        'Microsoft Entra hybrid joined',
        'Compliant and hybrid joined',
        'Microsoft Entra joined',
        'Microsoft Entra registered',
        'Not compliant / not hybrid joined'
    ) -SelectedIndex 0
    $script:cmbSignInRisk = New-FieldCombo -X 12 -Y 262 -Width 316 -Items @('(not specified)', 'No risk', 'Low', 'Medium', 'High') -SelectedIndex 0
    $script:cmbUserRisk = New-FieldCombo -X 12 -Y 306 -Width 316 -Items @('(not specified)', 'No risk', 'Low', 'Medium', 'High') -SelectedIndex 0
    $script:cmbInsiderRisk = New-FieldCombo -X 12 -Y 350 -Width 316 -Items @('(not specified)', 'No risk', 'Minor', 'Moderate', 'Elevated') -SelectedIndex 0
    $script:cmbAuthFlow = New-FieldCombo -X 12 -Y 394 -Width 316 -Items @('None', 'Device code flow', 'Authentication transfer') -SelectedIndex 0

    $grpCond.Controls.AddRange(@(
            (New-FieldLabel -Text 'Device platform *' -X 12 -Y 22), $script:cmbPlatform,
            (New-FieldLabel -Text 'Client app *' -X 12 -Y 66), $script:cmbClientApp,
            (New-FieldLabel -Text 'IP address' -X 12 -Y 110), $script:txtIp,
            (New-FieldLabel -Text 'Country (ISO-3166)' -X 12 -Y 154), $script:cmbCountry,
            (New-FieldLabel -Text 'Device state' -X 12 -Y 198), $script:cmbDeviceState,
            (New-FieldLabel -Text 'Sign-in risk' -X 12 -Y 242), $script:cmbSignInRisk,
            (New-FieldLabel -Text 'User risk' -X 12 -Y 286), $script:cmbUserRisk,
            (New-FieldLabel -Text 'Insider risk' -X 12 -Y 330), $script:cmbInsiderRisk,
            (New-FieldLabel -Text 'Authentication flow' -X 12 -Y 374), $script:cmbAuthFlow
        ))

    $grpActions = New-Object System.Windows.Forms.GroupBox
    $grpActions.Text = ' Actions '
    $grpActions.Font = New-UiFont -Size 9 -Style ([System.Drawing.FontStyle]::Bold)
    $grpActions.ForeColor = $navy
    $grpActions.Location = New-Object System.Drawing.Point(12, 750)
    $grpActions.Size = New-Object System.Drawing.Size(340, 118)

    $btnConnect = New-AeroButton -Text 'Connect' -X 12 -Y 28 -Width 150 -Kind Secondary
    $btnWhatIf  = New-AeroButton -Text 'What If' -X 174 -Y 28 -Width 150 -Kind Primary
    $btnExport  = New-AeroButton -Text 'Export' -X 12 -Y 70 -Width 150 -Kind Secondary
    $btnClear   = New-AeroButton -Text 'Clear' -X 174 -Y 70 -Width 150 -Kind Secondary
    $grpActions.Controls.AddRange(@($btnConnect, $btnWhatIf, $btnExport, $btnClear))

    $leftScroll.Controls.AddRange(@($grpIdentity, $grpTarget, $grpCond, $grpActions))
    $script:splitMain.Panel1.Controls.Add($leftScroll)

    # ----- Right: combined result + tabs + detail -----
    $right = New-Object System.Windows.Forms.Panel
    $right.Dock = 'Fill'
    $right.BackColor = $aeroBg
    $right.Padding = New-Object System.Windows.Forms.Padding(8)

    $script:pnlCombined = New-Object System.Windows.Forms.Panel
    $script:pnlCombined.Dock = 'Top'
    $script:pnlCombined.Height = 58
    $script:pnlCombined.BackColor = New-AeroColor 43 117 198
    $script:pnlCombined.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 8)

    $script:lblCombined = New-Object System.Windows.Forms.Label
    $script:lblCombined.Dock = 'Fill'
    $script:lblCombined.ForeColor = [System.Drawing.Color]::White
    $script:lblCombined.Font = New-UiFont -Size 10.5 -Style ([System.Drawing.FontStyle]::Bold)
    $script:lblCombined.Text = 'Configure a sign-in and select What If. Combined enforced controls appear here.'
    $script:pnlCombined.Controls.Add($script:lblCombined)

    $script:splitResults = New-Object System.Windows.Forms.SplitContainer
    $script:splitResults.Dock = 'Fill'
    $script:splitResults.Orientation = 'Horizontal'
    $script:splitResults.SplitterWidth = 6
    $script:splitResults.BackColor = $panelEdge
    $script:splitResults.Panel1.BackColor = $aeroBg
    $script:splitResults.Panel2.BackColor = $glass

    $script:tabs = New-Object System.Windows.Forms.TabControl
    $script:tabs.Dock = 'Fill'
    $script:tabs.Font = New-UiFont -Size 9
    $script:tabs.Padding = New-Object System.Drawing.Point(12, 6)

    $script:tabApply = New-Object System.Windows.Forms.TabPage
    $script:tabApply.Text = '  Policies that apply  '
    $script:tabApply.BackColor = $glass
    $script:dgvApply = New-Object System.Windows.Forms.DataGridView
    $script:dgvApply.Dock = 'Fill'
    Set-GridChrome -Grid $script:dgvApply
    Add-ResultColumns -Grid $script:dgvApply
    $script:tabApply.Controls.Add($script:dgvApply)

    $script:tabSkip = New-Object System.Windows.Forms.TabPage
    $script:tabSkip.Text = '  Policies that do not apply  '
    $script:tabSkip.BackColor = $glass
    $script:dgvSkip = New-Object System.Windows.Forms.DataGridView
    $script:dgvSkip.Dock = 'Fill'
    Set-GridChrome -Grid $script:dgvSkip
    Add-ResultColumns -Grid $script:dgvSkip
    $script:tabSkip.Controls.Add($script:dgvSkip)

    $script:tabLog = New-Object System.Windows.Forms.TabPage
    $script:tabLog.Text = '  Activity log  '
    $script:tabLog.BackColor = $glass
    $script:txtLog = New-Object System.Windows.Forms.TextBox
    $script:txtLog.Dock = 'Fill'
    $script:txtLog.Multiline = $true
    $script:txtLog.ScrollBars = 'Both'
    $script:txtLog.ReadOnly = $true
    $script:txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
    $script:txtLog.BackColor = New-AeroColor 250 252 255
    $script:tabLog.Controls.Add($script:txtLog)

    [void]$script:tabs.TabPages.AddRange(@($script:tabApply, $script:tabSkip, $script:tabLog))

    $grpDetail = New-Object System.Windows.Forms.GroupBox
    $grpDetail.Text = ' Details / combined controls '
    $grpDetail.Dock = 'Fill'
    $grpDetail.Font = New-UiFont -Size 9 -Style ([System.Drawing.FontStyle]::Bold)
    $grpDetail.ForeColor = $navy
    $grpDetail.Padding = New-Object System.Windows.Forms.Padding(8, 16, 8, 8)
    $script:txtDetail = New-Object System.Windows.Forms.TextBox
    $script:txtDetail.Dock = 'Fill'
    $script:txtDetail.Multiline = $true
    $script:txtDetail.ScrollBars = 'Vertical'
    $script:txtDetail.ReadOnly = $true
    $script:txtDetail.Font = New-Object System.Drawing.Font('Consolas', 9)
    $script:txtDetail.BackColor = [System.Drawing.Color]::White
    $script:txtDetail.Text = @"
This tool follows the Entra Conditional Access What If model.

Required: user, cloud app (or user action / auth context), device platform, client app.
Optional conditions (IP, country, device, risk, authentication flow) should be filled in whenever a policy in the tenant uses them. Empty optional conditions can produce "not enough information" — that is safer than guessing.

Accuracy notes
• Primary engine is POST /identity/conditionalAccess/evaluate (the official What If API).
• Local fallback uses the same include/exclude and condition order as Entra.
• Report-only policies never count as enforced.
• Service dependencies are not expanded (same as Entra What If).
• The original script treated listed apps/platforms as a reason the policy applied to a user. That bug is removed.
"@
    $grpDetail.Controls.Add($script:txtDetail)

    $script:splitResults.Panel1.Controls.Add($script:tabs)
    $script:splitResults.Panel2.Controls.Add($grpDetail)

    $rightInner = New-Object System.Windows.Forms.Panel
    $rightInner.Dock = 'Fill'
    $rightInner.Padding = New-Object System.Windows.Forms.Padding(10, 8, 10, 8)
    $rightInner.Controls.Add($script:splitResults)
    $rightInner.Controls.Add($script:pnlCombined)
    $script:splitMain.Panel2.Controls.Add($rightInner)

    $form.Controls.Add($script:splitMain)
    $form.Controls.Add($status)
    $form.Controls.Add($header)

    $script:dgvApply.Add_SelectionChanged({ Show-SelectedPolicyDetail -Grid $script:dgvApply })
    $script:dgvSkip.Add_SelectionChanged({ Show-SelectedPolicyDetail -Grid $script:dgvSkip })

    $btnConnect.Add_Click({
        $form.Cursor = 'WaitCursor'
        try {
            Update-StatusBar -Text 'Connecting to Microsoft Graph...'
            [System.Windows.Forms.Application]::DoEvents()
            Connect-CaGraphSession
            foreach ($name in ($script:AppNameCache.Values | Sort-Object -Unique)) {
                if (-not $script:cmbCloudApp.Items.Contains($name)) {
                    [void]$script:cmbCloudApp.Items.Add($name)
                }
            }
            Update-StatusBar -Text ("Connected. {0} policies loaded." -f $script:PolicyCache.Count)
        } catch {
            Show-ErrorDialog -Message $_.Exception.Message
            Write-AppLog $_.Exception.Message 'ERROR'
            Update-StatusBar -Text 'Connection failed.'
        } finally {
            $form.Cursor = 'Default'
        }
    })

    $btnWhatIf.Add_Click({
        $form.Cursor = 'WaitCursor'
        try {
            Update-StatusBar -Text 'Evaluating Conditional Access policies...'
            [System.Windows.Forms.Application]::DoEvents()
            Invoke-WhatIfEvaluation
        } catch {
            Show-ErrorDialog -Message $_.Exception.Message
            Write-AppLog $_.Exception.Message 'ERROR'
            Update-StatusBar -Text 'Evaluation failed.'
        } finally {
            $form.Cursor = 'Default'
        }
    })

    $btnExport.Add_Click({ Export-WhatIfReport })
    $btnClear.Add_Click({
        $script:LastResults = @()
        $script:dgvApply.DataSource = $null
        $script:dgvSkip.DataSource = $null
        $script:tabApply.Text = '  Policies that apply  '
        $script:tabSkip.Text = '  Policies that do not apply  '
        $script:pnlCombined.BackColor = New-AeroColor 43 117 198
        $script:lblCombined.ForeColor = [System.Drawing.Color]::White
        $script:lblCombined.Text = 'Results cleared. Configure a sign-in and select What If.'
        $script:txtDetail.Clear()
        Update-StatusBar -Text 'Cleared.'
    })

    $form.Add_KeyDown({
        param($s, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::F5) { $btnWhatIf.PerformClick() }
    })
    $script:txtUpn.Add_KeyDown({
        param($s, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $e.SuppressKeyPress = $true
            $btnWhatIf.PerformClick()
        }
    })

    $form.Add_Shown({
        $form.PerformLayout()
        Set-SplitContainerLayout -Split $script:splitMain -DesiredDistance 370 -Panel1Min 300 -Panel2Min 420
        Set-SplitContainerLayout -Split $script:splitResults -DesiredDistance 360 -Panel1Min 160 -Panel2Min 140
        $script:txtUpn.Focus()
        Write-AppLog "Conditional Access What If v$script:AppVersion started." 'INFO'
    })
    $form.TopMost = $false
    [void]$form.ShowDialog()
}

# ============================================================
# ENTRY POINT
# ============================================================
if ($SelfTest) {
    $code = Invoke-CaSelfTest
    exit $code
}

Show-WhatIfForm

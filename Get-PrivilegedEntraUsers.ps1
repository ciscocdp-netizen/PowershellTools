<#
.SYNOPSIS
    Returns Entra ID (Azure AD) privileged directory role assignments for users,
    service principals, and groups.

.DESCRIPTION
    Connects to Microsoft Graph using the Microsoft Graph PowerShell SDK and enumerates
    every directory role definition flagged by Microsoft as privileged (isPrivileged = true).

    For each privileged role it resolves:
        - Active assignments
              * Permanent  - standing assignment with no end date
              * Time-bound - standing assignment that expires
              * Activated  - currently activated PIM eligible assignment
        - Eligible assignments (PIM eligible; requires Entra ID P2 + PIM)

    Each assignment is attributed to the directory principal it is granted to:
        - User
        - Service principal (enterprise apps, managed identities, etc.)
        - Group (role-assignable groups)

    Group assignments are reported in two ways:
        1. A row for the group itself (so you can see which groups hold privileged roles
           and whether that grant is Eligible or Permanent/Active).
        2. A row for every transitive user and service-principal member, with
           AssignmentPath = Group and AssignedVia = "Group: <group name>".

    Direct assignments use AssignmentPath = Direct.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER TenantId
    Optional. The tenant (directory) ID or domain to connect to. If omitted, the
    default tenant of the signing-in account is used.

.PARAMETER IncludeActive
    Include active role assignments (permanent, time-bound, and currently activated).
    Default: $true.

.PARAMETER IncludeEligible
    Include PIM eligible role assignments. Default: $true.

.PARAMETER IncludeUsers
    Include user principals in the output. Default: $true.

.PARAMETER IncludeServicePrincipals
    Include service principal principals in the output. Default: $true.

.PARAMETER IncludeGroups
    Include a row for each group that is assigned a privileged role. Default: $true.

.PARAMETER ExpandGroupMembers
    When a role is assigned to a group, also emit rows for the group's transitive
    user and service-principal members. Default: $true.

.PARAMETER ExportCsvPath
    Optional. If supplied, results are also written to this CSV path.

.EXAMPLE
    .\Get-PrivilegedEntraUsers.ps1

.EXAMPLE
    .\Get-PrivilegedEntraUsers.ps1 -TenantId contoso.onmicrosoft.com -ExportCsvPath .\privileged.csv

.EXAMPLE
    # Groups that hold privileged roles, and whether each grant is eligible or permanent:
    .\Get-PrivilegedEntraUsers.ps1 | Where-Object { $_.PrincipalType -eq 'Group' } |
        Select-Object PrincipalDisplayName, RoleName, AssignmentState, DurationType, AssignmentPath

.EXAMPLE
    # Service principals with privileged roles:
    .\Get-PrivilegedEntraUsers.ps1 | Where-Object { $_.PrincipalType -eq 'ServicePrincipal' }

.NOTES
    Requires the following delegated permissions (consented at first interactive sign-in):
        RoleManagement.Read.Directory
        Directory.Read.All
    Required modules (installed automatically if missing):
        Microsoft.Graph.Authentication
        Microsoft.Graph.Identity.Governance
        Microsoft.Graph.Users
        Microsoft.Graph.Groups
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string] $TenantId,
    [bool]   $IncludeActive             = $true,
    [bool]   $IncludeEligible           = $true,
    [bool]   $IncludeUsers              = $true,
    [bool]   $IncludeServicePrincipals  = $true,
    [bool]   $IncludeGroups             = $true,
    [bool]   $ExpandGroupMembers        = $true,
    [string] $ExportCsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Module bootstrap ---------------------------------------------------------

$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.Governance',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Groups'
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing missing module: $module" -ForegroundColor Yellow
        Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $module -ErrorAction Stop
}

#endregion

#region Connect ------------------------------------------------------------------

$scopes = @('RoleManagement.Read.Directory', 'Directory.Read.All')

$connectParams = @{ Scopes = $scopes }
if ($TenantId) { $connectParams['TenantId'] = $TenantId }

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph @connectParams | Out-Null

$context = Get-MgContext
Write-Host ("Connected to tenant '{0}' as '{1}'." -f $context.TenantId, $context.Account) -ForegroundColor Green

#endregion

#region Helpers ------------------------------------------------------------------

$script:PrincipalCache               = @{}
$script:GroupMemberCache             = @{}
$script:SeenKeys                     = @{}
$script:Results                      = New-Object System.Collections.Generic.List[object]
$script:GroupAssignmentsForExpansion = New-Object System.Collections.Generic.List[object]

function Get-GraphHashValue {
    <#
        Reads a property from a Hashtable or PSObject under Set-StrictMode.
        Tries each name in order so camelCase / PascalCase JSON both work.
    #>
    param(
        [AllowNull()] $Object,
        [Parameter(Mandatory)] [string[]] $Name
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
        }
    }

    return $null
}

function Get-GraphPaged {
    param(
        [Parameter(Mandatory)] [string] $Uri
    )

    $items = New-Object System.Collections.Generic.List[object]
    $next  = $Uri

    do {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Hashtable

        if ($page.ContainsKey('value') -and $page['value']) {
            foreach ($item in @($page['value'])) { $items.Add($item) }
        }

        if ($page.ContainsKey('@odata.nextLink') -and $page['@odata.nextLink']) {
            $next = $page['@odata.nextLink']
        }
        else {
            $next = $null
        }
    } while ($next)

    return $items
}

function New-PrincipalRecord {
    param(
        [Parameter(Mandatory)] [string] $PrincipalType,
        [Parameter(Mandatory)] [string] $PrincipalId,
        [string] $DisplayName,
        [string] $UserPrincipalName,
        [string] $AppId,
        $AccountEnabled,
        [string] $Subtype
    )

    if ([string]::IsNullOrEmpty($DisplayName)) { $DisplayName = $PrincipalId }

    return [pscustomobject]@{
        PrincipalType     = $PrincipalType
        PrincipalId       = $PrincipalId
        DisplayName       = $DisplayName
        UserPrincipalName = $UserPrincipalName
        AppId             = $AppId
        AccountEnabled    = $AccountEnabled
        Subtype           = $Subtype
    }
}

function Resolve-DirectoryPrincipal {
    <#
        Resolves a directory object id to a user, group, or service principal.
        Uses GET /directoryObjects/{id} to detect type, then fetches typed properties.
    #>
    param(
        [Parameter(Mandatory)] [string] $PrincipalId
    )

    if ($script:PrincipalCache.ContainsKey($PrincipalId)) {
        return $script:PrincipalCache[$PrincipalId]
    }

    $odataType = $null
    try {
        $dirObj = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/v1.0/directoryObjects/{0}" -f $PrincipalId) -OutputType Hashtable
        $odataType = [string](Get-GraphHashValue -Object $dirObj -Name @('@odata.type', 'odataType'))
    }
    catch {
        $unknown = New-PrincipalRecord -PrincipalType 'Unknown' -PrincipalId $PrincipalId -DisplayName '(unresolved principal)'
        $script:PrincipalCache[$PrincipalId] = $unknown
        return $unknown
    }

    $record = $null

    if ($odataType -match 'user$') {
        try {
            $user = Get-MgUser -UserId $PrincipalId -Property 'id,displayName,userPrincipalName,accountEnabled,userType' -ErrorAction Stop
            $record = New-PrincipalRecord -PrincipalType 'User' -PrincipalId $user.Id `
                -DisplayName $user.DisplayName -UserPrincipalName $user.UserPrincipalName `
                -AccountEnabled $user.AccountEnabled -Subtype $user.UserType
        }
        catch {
            $record = New-PrincipalRecord -PrincipalType 'User' -PrincipalId $PrincipalId `
                -DisplayName (Get-GraphHashValue -Object $dirObj -Name @('displayName')) `
                -UserPrincipalName (Get-GraphHashValue -Object $dirObj -Name @('userPrincipalName'))
        }
    }
    elseif ($odataType -match 'group$') {
        try {
            $group = Get-MgGroup -GroupId $PrincipalId -Property 'id,displayName,mail,securityEnabled,isAssignableToRole,groupTypes' -ErrorAction Stop
            $isAssignable = Get-GraphHashValue -Object $group -Name @('IsAssignableToRole', 'isAssignableToRole')
            $subtype = 'Group'
            if ($isAssignable -eq $true) { $subtype = 'RoleAssignableGroup' }
            $record = New-PrincipalRecord -PrincipalType 'Group' -PrincipalId $group.Id `
                -DisplayName $group.DisplayName -UserPrincipalName $group.Mail `
                -Subtype $subtype
        }
        catch {
            $record = New-PrincipalRecord -PrincipalType 'Group' -PrincipalId $PrincipalId `
                -DisplayName (Get-GraphHashValue -Object $dirObj -Name @('displayName'))
        }
    }
    elseif ($odataType -match 'servicePrincipal$') {
        try {
            $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals/{0}?`$select=id,displayName,appId,accountEnabled,servicePrincipalType,appOwnerOrganizationId" -f $PrincipalId
            $sp    = Invoke-MgGraphRequest -Method GET -Uri $spUri -OutputType Hashtable
            $spId  = [string](Get-GraphHashValue -Object $sp -Name @('id'))
            if ([string]::IsNullOrEmpty($spId)) { $spId = $PrincipalId }
            $record = New-PrincipalRecord -PrincipalType 'ServicePrincipal' -PrincipalId $spId `
                -DisplayName (Get-GraphHashValue -Object $sp -Name @('displayName')) `
                -AppId (Get-GraphHashValue -Object $sp -Name @('appId')) `
                -AccountEnabled (Get-GraphHashValue -Object $sp -Name @('accountEnabled')) `
                -Subtype (Get-GraphHashValue -Object $sp -Name @('servicePrincipalType'))
        }
        catch {
            $record = New-PrincipalRecord -PrincipalType 'ServicePrincipal' -PrincipalId $PrincipalId `
                -DisplayName (Get-GraphHashValue -Object $dirObj -Name @('displayName'))
        }
    }
    else {
        $record = New-PrincipalRecord -PrincipalType 'Unknown' -PrincipalId $PrincipalId `
            -DisplayName (Get-GraphHashValue -Object $dirObj -Name @('displayName')) `
            -Subtype $odataType
    }

    $script:PrincipalCache[$PrincipalId] = $record
    return $record
}

function Get-GroupTransitivePrincipals {
    <#
        Returns user and service-principal members of a group (transitive).
        Nested groups are walked by the Graph transitiveMembers API; nested
        group objects themselves are not emitted (directory roles do not
        flow through nested groups).
    #>
    param(
        [Parameter(Mandatory)] [string] $GroupId
    )

    if ($script:GroupMemberCache.ContainsKey($GroupId)) {
        return $script:GroupMemberCache[$GroupId]
    }

    $records = New-Object System.Collections.Generic.List[object]

    $userUri = "https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers/microsoft.graph.user?`$select=id,displayName,userPrincipalName,accountEnabled,userType" -f $GroupId
    try {
        foreach ($u in (Get-GraphPaged -Uri $userUri)) {
            $id = [string](Get-GraphHashValue -Object $u -Name @('id'))
            if ([string]::IsNullOrEmpty($id)) { continue }
            $rec = New-PrincipalRecord -PrincipalType 'User' -PrincipalId $id `
                -DisplayName (Get-GraphHashValue -Object $u -Name @('displayName')) `
                -UserPrincipalName (Get-GraphHashValue -Object $u -Name @('userPrincipalName')) `
                -AccountEnabled (Get-GraphHashValue -Object $u -Name @('accountEnabled')) `
                -Subtype (Get-GraphHashValue -Object $u -Name @('userType'))
            $records.Add($rec)
            if (-not $script:PrincipalCache.ContainsKey($id)) {
                $script:PrincipalCache[$id] = $rec
            }
        }
    }
    catch {
        Write-Warning ("Could not expand user members of group {0}: {1}" -f $GroupId, $_.Exception.Message)
    }

    $spUri = "https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers/microsoft.graph.servicePrincipal?`$select=id,displayName,appId,accountEnabled,servicePrincipalType" -f $GroupId
    try {
        foreach ($sp in (Get-GraphPaged -Uri $spUri)) {
            $id = [string](Get-GraphHashValue -Object $sp -Name @('id'))
            if ([string]::IsNullOrEmpty($id)) { continue }
            $rec = New-PrincipalRecord -PrincipalType 'ServicePrincipal' -PrincipalId $id `
                -DisplayName (Get-GraphHashValue -Object $sp -Name @('displayName')) `
                -AppId (Get-GraphHashValue -Object $sp -Name @('appId')) `
                -AccountEnabled (Get-GraphHashValue -Object $sp -Name @('accountEnabled')) `
                -Subtype (Get-GraphHashValue -Object $sp -Name @('servicePrincipalType'))
            $records.Add($rec)
            if (-not $script:PrincipalCache.ContainsKey($id)) {
                $script:PrincipalCache[$id] = $rec
            }
        }
    }
    catch {
        Write-Warning ("Could not expand service-principal members of group {0}: {1}" -f $GroupId, $_.Exception.Message)
    }

    $script:GroupMemberCache[$GroupId] = $records
    return $records
}

function Convert-ToDateTimeString {
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text
}

function Get-DurationType {
    param($EndDateTime)
    $end = Convert-ToDateTimeString -Value $EndDateTime
    if ($null -eq $end) { return 'Permanent' }
    return 'Time-bound'
}

function Get-AssignmentStateFromInstance {
    <#
        Maps Graph assignmentType + endDateTime onto the Entra PIM vocabulary:
            Permanent  - standing active assignment, no expiry
            TimeBound  - standing active assignment that expires
            Activated  - currently activated PIM eligible assignment
    #>
    param($AssignmentType, $EndDateTime)

    $typeText = [string]$AssignmentType
    if ($typeText -match 'activated') {
        return @{ AssignmentState = 'Activated'; DurationType = 'Time-bound'; IsPimActivated = $true }
    }

    $duration = Get-DurationType -EndDateTime $EndDateTime
    if ($duration -eq 'Permanent') {
        return @{ AssignmentState = 'Permanent'; DurationType = 'Permanent'; IsPimActivated = $false }
    }

    return @{ AssignmentState = 'TimeBound'; DurationType = 'Time-bound'; IsPimActivated = $false }
}

function Get-AssignmentPathFromMemberType {
    param($MemberType)

    $text = [string]$MemberType
    if ($text -match 'group')     { return 'Group' }
    if ($text -match 'composite') { return 'Composite' }
    return 'Direct'
}

function Test-ShouldEmitPrincipalType {
    param([Parameter(Mandatory)] [string] $PrincipalType)

    switch ($PrincipalType) {
        'User'              { return [bool]$IncludeUsers }
        'ServicePrincipal'  { return [bool]$IncludeServicePrincipals }
        'Group'             { return [bool]$IncludeGroups }
        default             { return $true }
    }
}

function Get-AssignmentRowKey {
    param(
        [string] $PrincipalId,
        [string] $RoleId,
        [string] $AssignmentState,
        [string] $AssignmentPath,
        [string] $DirectoryScopeId
    )
    return '{0}|{1}|{2}|{3}|{4}' -f $PrincipalId, $RoleId, $AssignmentState, $AssignmentPath, $DirectoryScopeId
}

function Add-ResultRow {
    param(
        [Parameter(Mandatory)] $TargetPrincipal,
        [Parameter(Mandatory)] $Role,
        [Parameter(Mandatory)] [string] $AssignmentState,
        [Parameter(Mandatory)] [string] $DurationType,
        [Parameter(Mandatory)] [string] $AssignmentPath,
        [bool]   $IsPimActivated = $false,
        [string] $DirectoryScopeId,
        $StartDateTime,
        $EndDateTime,
        [string] $GraphMemberType,
        [string] $AssignedVia = 'Direct',
        [string] $AssignedViaGroup,
        [string] $AssignedViaGroupId
    )

    if (-not (Test-ShouldEmitPrincipalType -PrincipalType $TargetPrincipal.PrincipalType)) {
        return
    }

    $key = Get-AssignmentRowKey -PrincipalId $TargetPrincipal.PrincipalId -RoleId $Role.Id `
        -AssignmentState $AssignmentState -AssignmentPath $AssignmentPath -DirectoryScopeId $DirectoryScopeId

    if ($script:SeenKeys.ContainsKey($key)) {
        $existing = $script:Results[$script:SeenKeys[$key]]
        # Prefer the row that names the source group when Graph also returned a memberType=Group instance.
        $existingViaGroup = [string](Get-GraphHashValue -Object $existing -Name @('AssignedViaGroup'))
        if ([string]::IsNullOrEmpty($existingViaGroup) -and -not [string]::IsNullOrEmpty($AssignedViaGroup)) {
            $existing.AssignedVia        = $AssignedVia
            $existing.AssignedViaGroup   = $AssignedViaGroup
            $existing.AssignedViaGroupId = $AssignedViaGroupId
        }
        return
    }

    $row = [pscustomobject]@{
        PrincipalType        = $TargetPrincipal.PrincipalType
        PrincipalDisplayName = $TargetPrincipal.DisplayName
        PrincipalId          = $TargetPrincipal.PrincipalId
        UserPrincipalName    = $TargetPrincipal.UserPrincipalName
        AppId                = $TargetPrincipal.AppId
        AccountEnabled       = $TargetPrincipal.AccountEnabled
        PrincipalSubtype     = $TargetPrincipal.Subtype
        RoleName             = $Role.DisplayName
        RoleDefinitionId     = $Role.Id
        AssignmentState      = $AssignmentState   # Permanent | Eligible | Activated | TimeBound
        DurationType         = $DurationType      # Permanent | Time-bound
        AssignmentPath       = $AssignmentPath    # Direct | Group | Composite
        AssignedVia          = $AssignedVia       # Direct | Group: <name>
        AssignedViaGroup     = $AssignedViaGroup
        AssignedViaGroupId   = $AssignedViaGroupId
        IsPimActivated       = [bool]$IsPimActivated
        DirectoryScopeId     = $DirectoryScopeId
        StartDateTime        = (Convert-ToDateTimeString -Value $StartDateTime)
        EndDateTime          = (Convert-ToDateTimeString -Value $EndDateTime)
        GraphMemberType      = $GraphMemberType
    }
    $row.PSObject.TypeNames.Insert(0, 'PrivilegedEntraAssignment')
    $script:SeenKeys[$key] = $script:Results.Count
    $script:Results.Add($row)
}

function Add-PrincipalAssignment {
    <#
        Records the assignment against the principal Graph named (user, SP, or group).
        Group member expansion happens in a second pass so every group-held role is
        listed on the group itself and on its members.
    #>
    param(
        [Parameter(Mandatory)] $Role,
        [Parameter(Mandatory)] [string] $PrincipalId,
        [Parameter(Mandatory)] [string] $AssignmentState,
        [Parameter(Mandatory)] [string] $DurationType,
        [Parameter(Mandatory)] [string] $AssignmentPath,
        [bool]   $IsPimActivated = $false,
        [string] $DirectoryScopeId,
        $StartDateTime,
        $EndDateTime,
        [string] $GraphMemberType
    )

    if ([string]::IsNullOrEmpty($PrincipalId)) { return }

    $principal = Resolve-DirectoryPrincipal -PrincipalId $PrincipalId

    # A group is always a direct assignee of the directory role (members inherit it).
    if ($principal.PrincipalType -eq 'Group') {
        Add-ResultRow -TargetPrincipal $principal -Role $Role `
            -AssignmentState $AssignmentState -DurationType $DurationType -AssignmentPath 'Direct' `
            -IsPimActivated $IsPimActivated -DirectoryScopeId $DirectoryScopeId `
            -StartDateTime $StartDateTime -EndDateTime $EndDateTime `
            -GraphMemberType $GraphMemberType -AssignedVia 'Direct'

        $script:GroupAssignmentsForExpansion.Add([pscustomobject]@{
            PrincipalId          = $principal.PrincipalId
            PrincipalDisplayName = $principal.DisplayName
            RoleDefinitionId     = $Role.Id
            RoleName             = $Role.DisplayName
            AssignmentState      = $AssignmentState
            DurationType         = $DurationType
            IsPimActivated       = [bool]$IsPimActivated
            DirectoryScopeId     = $DirectoryScopeId
            StartDateTime        = $StartDateTime
            EndDateTime          = $EndDateTime
        })
        return
    }

    $path = $AssignmentPath
    $via  = 'Direct'
    if ($path -eq 'Group' -or $path -eq 'Composite') {
        $via = 'Group'
    }
    else {
        $path = 'Direct'
    }

    Add-ResultRow -TargetPrincipal $principal -Role $Role `
        -AssignmentState $AssignmentState -DurationType $DurationType -AssignmentPath $path `
        -IsPimActivated $IsPimActivated -DirectoryScopeId $DirectoryScopeId `
        -StartDateTime $StartDateTime -EndDateTime $EndDateTime `
        -GraphMemberType $GraphMemberType -AssignedVia $via
}

function Add-ExpandedGroupMemberRows {
    param(
        [Parameter(Mandatory)] $GroupRow
    )

    $members = Get-GroupTransitivePrincipals -GroupId $GroupRow.PrincipalId
    $viaLabel = "Group: {0}" -f $GroupRow.PrincipalDisplayName
    $role = [pscustomobject]@{
        Id          = $GroupRow.RoleDefinitionId
        DisplayName = $GroupRow.RoleName
    }

    foreach ($member in @($members)) {
        Add-ResultRow -TargetPrincipal $member -Role $role `
            -AssignmentState $GroupRow.AssignmentState -DurationType $GroupRow.DurationType `
            -AssignmentPath 'Group' -IsPimActivated ([bool]$GroupRow.IsPimActivated) `
            -DirectoryScopeId $GroupRow.DirectoryScopeId `
            -StartDateTime $GroupRow.StartDateTime -EndDateTime $GroupRow.EndDateTime `
            -GraphMemberType 'Group' -AssignedVia $viaLabel `
            -AssignedViaGroup $GroupRow.PrincipalDisplayName -AssignedViaGroupId $GroupRow.PrincipalId
    }
}

#endregion

#region 1. Get privileged role definitions --------------------------------------

Write-Host "Retrieving privileged role definitions (isPrivileged = true)..." -ForegroundColor Cyan

# NOTE: 'isPrivileged' only exists on the Microsoft Graph BETA endpoint - it is not
# present on the v1.0 unifiedRoleDefinition type (the v1.0 cmdlet returns a 400
# 'Could not find a property named isPrivileged'). We therefore query the beta
# endpoint directly through the already-authenticated SDK connection via
# Invoke-MgGraphRequest, and filter client-side because beta does not reliably
# support $filter on isPrivileged.

$roleDefUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?`$select=id,displayName,isPrivileged,isBuiltIn"

$allRoleDefs = Get-GraphPaged -Uri $roleDefUri

# Client-side filter to Microsoft-flagged privileged roles, and normalize the
# shape so downstream code can keep using .Id / .DisplayName.
$privilegedRoles = $allRoleDefs |
    Where-Object { (Get-GraphHashValue -Object $_ -Name @('isPrivileged')) -eq $true } |
    ForEach-Object {
        [pscustomobject]@{
            Id           = [string](Get-GraphHashValue -Object $_ -Name @('id'))
            DisplayName  = [string](Get-GraphHashValue -Object $_ -Name @('displayName'))
            IsPrivileged = $true
            IsBuiltIn    = (Get-GraphHashValue -Object $_ -Name @('isBuiltIn'))
        }
    }

if (-not $privilegedRoles) {
    Write-Warning "No privileged role definitions returned. Nothing to do."
    Disconnect-MgGraph | Out-Null
    return
}

$roleById = @{}
foreach ($role in @($privilegedRoles)) { $roleById[$role.Id] = $role }

Write-Host ("Found {0} privileged role definition(s)." -f @($privilegedRoles).Count) -ForegroundColor Green

#endregion

#region 2. Collect assignments ---------------------------------------------------

$script:Results = New-Object System.Collections.Generic.List[object]
$script:GroupAssignmentsForExpansion = New-Object System.Collections.Generic.List[object]

function Get-CmdletProperty {
    param($Object, [string[]] $Name)
    return Get-GraphHashValue -Object $Object -Name $Name
}

# --- Active / permanent / activated assignments ---
if ($IncludeActive) {
    Write-Host "Retrieving ACTIVE role assignments (permanent, time-bound, and PIM-activated)..." -ForegroundColor Cyan

    $usedScheduleInstances = $false
    $activeItems = @()

    try {
        $activeItems = @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction Stop)
        $usedScheduleInstances = $true
        Write-Host ("Retrieved {0} assignment schedule instance(s)." -f $activeItems.Count) -ForegroundColor Green
    }
    catch {
        Write-Warning ("Could not retrieve assignment schedule instances ({0}). Falling back to directory role assignments (cannot distinguish PIM-activated from permanent)." -f $_.Exception.Message)
        $activeItems = @(Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop)
        Write-Host ("Retrieved {0} directory role assignment(s)." -f $activeItems.Count) -ForegroundColor Green
    }

    foreach ($item in $activeItems) {
        $roleDefId = [string](Get-CmdletProperty -Object $item -Name @('RoleDefinitionId', 'roleDefinitionId'))
        if (-not $roleById.ContainsKey($roleDefId)) { continue }

        $role          = $roleById[$roleDefId]
        $principalId   = [string](Get-CmdletProperty -Object $item -Name @('PrincipalId', 'principalId'))
        $scopeId       = [string](Get-CmdletProperty -Object $item -Name @('DirectoryScopeId', 'directoryScopeId'))
        $memberType    = Get-CmdletProperty -Object $item -Name @('MemberType', 'memberType')
        $assignType    = Get-CmdletProperty -Object $item -Name @('AssignmentType', 'assignmentType')
        $start         = Get-CmdletProperty -Object $item -Name @('StartDateTime', 'startDateTime')
        $end           = Get-CmdletProperty -Object $item -Name @('EndDateTime', 'endDateTime')

        if ($usedScheduleInstances) {
            $mapped = Get-AssignmentStateFromInstance -AssignmentType $assignType -EndDateTime $end
            $path   = Get-AssignmentPathFromMemberType -MemberType $memberType
        }
        else {
            $mapped = @{ AssignmentState = 'Permanent'; DurationType = 'Permanent'; IsPimActivated = $false }
            $path   = 'Direct'
        }

        Add-PrincipalAssignment -Role $role -PrincipalId $principalId `
            -AssignmentState $mapped.AssignmentState -DurationType $mapped.DurationType `
            -AssignmentPath $path -IsPimActivated $mapped.IsPimActivated `
            -DirectoryScopeId $scopeId -StartDateTime $start -EndDateTime $end `
            -GraphMemberType ([string]$memberType)
    }
}

# --- PIM eligible assignments ---
if ($IncludeEligible) {
    Write-Host "Retrieving PIM ELIGIBLE role assignments..." -ForegroundColor Cyan
    try {
        $eligibleItems = @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ErrorAction Stop)
        Write-Host ("Retrieved {0} eligibility schedule instance(s)." -f $eligibleItems.Count) -ForegroundColor Green

        foreach ($item in $eligibleItems) {
            $roleDefId = [string](Get-CmdletProperty -Object $item -Name @('RoleDefinitionId', 'roleDefinitionId'))
            if (-not $roleById.ContainsKey($roleDefId)) { continue }

            $role        = $roleById[$roleDefId]
            $principalId = [string](Get-CmdletProperty -Object $item -Name @('PrincipalId', 'principalId'))
            $scopeId     = [string](Get-CmdletProperty -Object $item -Name @('DirectoryScopeId', 'directoryScopeId'))
            $memberType  = Get-CmdletProperty -Object $item -Name @('MemberType', 'memberType')
            $start       = Get-CmdletProperty -Object $item -Name @('StartDateTime', 'startDateTime')
            $end         = Get-CmdletProperty -Object $item -Name @('EndDateTime', 'endDateTime')
            $path        = Get-AssignmentPathFromMemberType -MemberType $memberType
            $duration    = Get-DurationType -EndDateTime $end

            Add-PrincipalAssignment -Role $role -PrincipalId $principalId `
                -AssignmentState 'Eligible' -DurationType $duration `
                -AssignmentPath $path -IsPimActivated $false `
                -DirectoryScopeId $scopeId -StartDateTime $start -EndDateTime $end `
                -GraphMemberType ([string]$memberType)
        }
    }
    catch {
        Write-Warning ("Could not retrieve eligible (PIM) assignments. This requires Entra ID P2 + PIM. Details: {0}" -f $_.Exception.Message)
    }
}

# --- Expand groups to user and service-principal members ---
if ($ExpandGroupMembers -and $script:GroupAssignmentsForExpansion.Count -gt 0) {
    Write-Host ("Expanding {0} group assignment(s) to member users and service principals..." -f $script:GroupAssignmentsForExpansion.Count) -ForegroundColor Cyan
    foreach ($groupRow in $script:GroupAssignmentsForExpansion) {
        Add-ExpandedGroupMemberRows -GroupRow $groupRow
    }
}

#endregion

#region 3. Output ----------------------------------------------------------------

$final = @($script:Results | Sort-Object PrincipalType, PrincipalDisplayName, RoleName, AssignmentState, AssignmentPath, AssignedVia)

$userCount  = @($final | Where-Object { $_.PrincipalType -eq 'User' }).Count
$spCount    = @($final | Where-Object { $_.PrincipalType -eq 'ServicePrincipal' }).Count
$groupCount = @($final | Where-Object { $_.PrincipalType -eq 'Group' }).Count
$eligCount  = @($final | Where-Object { $_.AssignmentState -eq 'Eligible' }).Count
$permCount  = @($final | Where-Object { $_.AssignmentState -eq 'Permanent' }).Count
$actCount   = @($final | Where-Object { $_.AssignmentState -eq 'Activated' }).Count
$tbCount    = @($final | Where-Object { $_.AssignmentState -eq 'TimeBound' }).Count
$directCount= @($final | Where-Object { $_.AssignmentPath -eq 'Direct' }).Count
$viaGrpCount= @($final | Where-Object { $_.AssignmentPath -eq 'Group' }).Count

Write-Host ""
Write-Host ("Total privileged assignment records: {0}" -f $final.Count) -ForegroundColor Green
Write-Host ("  Principals : {0} user(s), {1} service principal(s), {2} group(s)" -f $userCount, $spCount, $groupCount)
Write-Host ("  State      : {0} permanent, {1} eligible, {2} PIM-activated, {3} time-bound active" -f $permCount, $eligCount, $actCount, $tbCount)
Write-Host ("  Path       : {0} direct, {1} via group" -f $directCount, $viaGrpCount)

$groupRows = @($final | Where-Object { $_.PrincipalType -eq 'Group' })
if ($groupRows.Count -gt 0) {
    Write-Host ""
    Write-Host "Groups with privileged role assignments:" -ForegroundColor Cyan
    $groupRows |
        Select-Object PrincipalDisplayName, RoleName, AssignmentState, DurationType, AssignmentPath, DirectoryScopeId |
        Format-Table -AutoSize | Out-String | Write-Host
}

if ($ExportCsvPath) {
    $final | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host ("Results exported to: {0}" -f $ExportCsvPath) -ForegroundColor Green
}

Disconnect-MgGraph | Out-Null

# Default display columns when the caller does not select specific properties.
try {
    Update-TypeData -TypeName 'PrivilegedEntraAssignment' -DefaultDisplayPropertySet @(
        'PrincipalType',
        'PrincipalDisplayName',
        'UserPrincipalName',
        'AppId',
        'RoleName',
        'AssignmentState',
        'DurationType',
        'AssignmentPath',
        'AssignedVia'
    ) -Force -ErrorAction SilentlyContinue
}
catch {
    # Non-fatal: objects still contain every property.
}

# Emit objects to the pipeline so the caller can further process/format them.
$final

#endregion

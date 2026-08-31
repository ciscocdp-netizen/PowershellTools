#Requires -Version 5.1
<#
.SYNOPSIS
    GPO Drive-Mapping Collision Finder (WPF GUI).

.DESCRIPTION
    Helps migrate logon-script drive mappings into Group Policy Preferences (GPP)
    "Drive Maps" that use Item Level Targeting (ILT).

    Given a target user and a proposed drive mapping, the tool:
      * Resolves the user's effective (nested) group membership and OU chain.
      * Determines every GPO that actually applies to that user
        (OU inheritance via Get-GPInheritance + security filtering).
      * Reads the existing Drive Maps (Drives.xml) out of SYSVOL for those GPOs.
      * Evaluates each existing mapping's ILT filters (Group / User / OU / Domain
        with AND / OR / NOT and nested Collections) against the user.
      * Compares the proposed drive letter against every existing mapping that
        would ALSO apply to the user, and flags collisions.

    Collision scope: the selected GPO PLUS every other GPO that applies to the
    user, so cross-GPO drive-letter conflicts are caught.

.PARAMETER SkipGui
    Dot-source / load functions only (used by unit tests). No WPF window.

.REQUIREMENTS
    - PowerShell 5.1
    - RSAT: ActiveDirectory module (Get-ADUser, tokenGroups)
    - RSAT: GroupPolicy module (Get-GPO, Get-GPInheritance, Get-GPPermission)
    - Read access to \\<domain>\SYSVOL
    - Run as a user who can read AD and GPO objects.
    - WPF requires STA: powershell.exe -STA -File .\GPO-DriveMap-CollisionFinder.ps1

.NOTES
    ILT coverage: FilterGroup, FilterUser, FilterOrgUnit, FilterDomain, and nested
    Collections. Any other ILT filter type (WMI, LDAP query, computer-context
    group, etc.) is treated as "could apply" (conservative) and the row is flagged
    in Notes so you know the verdict is best-effort for that mapping.

    Bugs fixed vs. the original collision logic:
      * tokenGroups is a constructed attribute and is ONLY returned by a base-scope
        LDAP read (Get-ADUser -Identity <DN|SID>). Using -Filter left GroupSids
        empty, so group-targeted ILT and security-filtered GPOs were skipped and
        collisions were missed.
      * Primary group SID is always merged (not always present on tokenGroups).
      * Well-known SIDs Everyone (S-1-1-0) and Authenticated Users (S-1-5-11) are
        treated as matching for both GpoApply and FilterGroup.
      * Deny "Apply Group Policy" wins over Allow.
      * Disabled GPO links, User Settings disabled, and disabled Drive items are
        skipped (they cannot collide).
      * SYSVOL policy folder uses a normalized {GUID} (avoids {{guid}} misses
        when GpoId is already braced).
      * [guid]::Empty is truthy in PowerShell; an unselected GPO no longer injects
        a fake {00000000-...} policy into the applicable set.
      * Returning ", `$array" from Get-ApplicableGpo nested the GPO list, so
        foreach ran once and $gpo.DisplayName became string[]. On Windows
        PowerShell 5.1 that throws: Cannot convert value to type System.String
        (parameter GpoName). Items are now emitted one-by-one and flattened.
      * Same-letter Delete mappings are collisions (CSE order can unmap the
        proposed drive).
      * UNC path compare is case-insensitive and ignores trailing slashes.
      * WPF bindings for properties named Path and Source use Path=Path / Path=Source.
      * Banner colors are real SolidColorBrush objects, not hex strings.
#>
[CmdletBinding()]
param(
    [switch]$SkipGui
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LoadGui = -not $SkipGui
if ($MyInvocation.InvocationName -eq '.') { $script:LoadGui = $false }

# Well-known SIDs that are in every interactive domain-user token but are often
# absent from tokenGroups.
$script:WellKnownUserSids = @('S-1-1-0', 'S-1-5-11')

# ---------------------------------------------------------------------------
# Small helpers (pure / testable)
# ---------------------------------------------------------------------------
function ConvertTo-SidString {
    param($Sid)
    if ($null -eq $Sid) { return $null }
    if ($Sid -is [string]) {
        $s = $Sid.Trim()
        if ($s) { return $s } else { return $null }
    }
    if ($Sid -is [System.Security.Principal.SecurityIdentifier]) { return $Sid.Value }
    if ($Sid.PSObject.Properties['Value'] -and $Sid.Value) { return [string]$Sid.Value }
    $s = [string]$Sid
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    return $s
}

function ConvertTo-NormalizedGuid {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [guid]) {
        if ($Value -eq [guid]::Empty) { return $null }
        return [guid]$Value
    }
    $text = ([string]$Value).Trim()
    if (-not $text) { return $null }
    try {
        $g = [guid]$text
        if ($g -eq [guid]::Empty) { return $null }
        return $g
    }
    catch { return $null }
}

function Get-SysvolPolicyFolderName {
    param([Parameter(Mandatory)]$GpoId)
    $g = ConvertTo-NormalizedGuid $GpoId
    if (-not $g) { return $null }
    return $g.ToString('B')  # {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
}

function ConvertTo-NormalizedDriveLetter {
    param([string]$Letter)
    if ([string]::IsNullOrWhiteSpace($Letter)) { return '' }
    return $Letter.Trim().TrimEnd(':').ToUpperInvariant()
}

function ConvertTo-SingleString {
    <#
        PowerShell [string] parameters cannot bind a multi-element array
        ("Cannot convert value to type System.String"). That happens when a
        nested GPO/map collection is member-enumerated (e.g. $gpos.DisplayName).
    #>
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Array]) {
        if ($Value.Length -eq 0) { return '' }
        return [string]$Value[0]
    }
    return [string]$Value
}

function ConvertTo-FlatList {
    <#
        Unwraps the extra Object[] layer created by "return , $array" so
        foreach iterates real GPO/map objects instead of one nested array.
    #>
    param($InputObject)
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($InputObject)) {
        if ($null -eq $item) { continue }
        if ($item -is [System.Array]) {
            foreach ($inner in $item) {
                if ($null -ne $inner) { [void]$list.Add($inner) }
            }
            continue
        }
        [void]$list.Add($item)
    }
    return $list
}

function ConvertTo-NormalizedUncPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    return $Path.Trim().TrimEnd('\').ToUpperInvariant()
}

function Test-DnIsUnderOu {
    <#
        True when $ObjectDn is a direct child of $OuDn (directMember), or when
        $ObjectDn is anywhere under $OuDn (including nested OUs).
        Matching is done with a leading-comma suffix so OU=HR,DC=x does not
        match OU=CHR,DC=x.
    #>
    param(
        [Parameter(Mandatory)][string]$ObjectDn,
        [Parameter(Mandatory)][string]$OuDn,
        [bool]$DirectMember = $false
    )
    if ([string]::IsNullOrWhiteSpace($ObjectDn) -or [string]::IsNullOrWhiteSpace($OuDn)) { return $false }

    $objectDn = $ObjectDn.Trim()
    $ouDn = $OuDn.Trim()
    $parent = ($objectDn -split '(?<!\\),', 2)[1]
    if (-not $parent) { return $false }

    if ($DirectMember) { return [string]::Equals($parent, $ouDn, [StringComparison]::OrdinalIgnoreCase) }

    if ([string]::Equals($parent, $ouDn, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $parent.EndsWith(',' + $ouDn, [StringComparison]::OrdinalIgnoreCase)
}

function Resolve-DriveMapCollision {
    <#
        Compares a proposed mapping against one existing mapping that already
        applies to the same user. Returns a hashtable:
          IsCollision <bool>
          Note       <string>
    #>
    param(
        [Parameter(Mandatory)][string]$ProposedLetter,
        [string]$ProposedPath = '',
        [Parameter(Mandatory)][string]$ExistingLetter,
        [string]$ExistingPath = '',
        [string]$ExistingAction = ''
    )

    $pLetter = ConvertTo-NormalizedDriveLetter $ProposedLetter
    $eLetter = ConvertTo-NormalizedDriveLetter $ExistingLetter
    if (-not $pLetter -or $pLetter -ne $eLetter) {
        return @{ IsCollision = $false; Note = '' }
    }

    $pPath = ConvertTo-NormalizedUncPath $ProposedPath
    $ePath = ConvertTo-NormalizedUncPath $ExistingPath
    $action = if ($ExistingAction) { $ExistingAction } else { '' }

    if ($action -eq 'Delete') {
        return @{
            IsCollision = $true
            Note        = "CONFLICT: letter $pLetter is deleted by an applicable GPO (CSE order can unmap the proposed drive)"
        }
    }
    if ($pPath -and $ePath -and $pPath -ne $ePath) {
        return @{
            IsCollision = $true
            Note        = "CONFLICT: letter $pLetter already maps to $ExistingPath"
        }
    }
    if ($pPath -and $ePath -and $pPath -eq $ePath) {
        return @{
            IsCollision = $true
            Note        = "CONFLICT: letter $pLetter already maps to the same path (duplicate GPP item)"
        }
    }
    return @{
        IsCollision = $true
        Note        = "CONFLICT: letter $pLetter already used"
    }
}

function ConvertFrom-DrivesXml {
    <#
        Parses a GPP Drives.xml document into mapping objects. Skips the whole
        file when the outer <Drives> is disabled, and skips inner <Drive>
        elements with disabled="1".
    #>
    param(
        [Parameter(Mandatory)][xml]$Xml,
        [Parameter(Mandatory)]$GpoName
    )
    $GpoName = ConvertTo-SingleString $GpoName

    if (-not $Xml.DocumentElement) { return @() }
    $root = $Xml.DocumentElement
    if ($root.LocalName -ne 'Drives') { return @() }
    if ($root.GetAttribute('disabled') -eq '1') { return @() }

    $maps = New-Object System.Collections.Generic.List[object]
    foreach ($drive in @($root.ChildNodes)) {
        if ($drive.NodeType -ne 'Element' -or $drive.LocalName -ne 'Drive') { continue }
        if ($drive.GetAttribute('disabled') -eq '1') { continue }

        $props = $null
        $filtersNode = $null
        foreach ($c in $drive.ChildNodes) {
            if ($c.NodeType -ne 'Element') { continue }
            if ($c.LocalName -eq 'Properties') { $props = $c }
            elseif ($c.LocalName -eq 'Filters') { $filtersNode = $c }
        }
        if (-not $props) { continue }

        $actionCode = $props.GetAttribute('action')
        $action = switch ($actionCode) {
            'C' { 'Create' }
            'R' { 'Replace' }
            'U' { 'Update' }
            'D' { 'Delete' }
            default { $actionCode }
        }

        $letter = ConvertTo-NormalizedDriveLetter ($props.GetAttribute('letter'))
        $useLetter = $props.GetAttribute('useLetter')

        $maps.Add([pscustomobject]@{
            GpoName     = (ConvertTo-SingleString $GpoName)
            Letter      = $letter
            Path        = $props.GetAttribute('path')
            Action      = $action
            Label       = $props.GetAttribute('label')
            UseLetter   = $useLetter
            Disabled    = $false
            FiltersNode = $filtersNode
            DriveName   = $drive.GetAttribute('name')
        }) | Out-Null
    }

    # Emit items one-by-one. Do NOT "return , $array" — the caller then gets a
    # nested array, foreach runs once, and $gpo.DisplayName becomes string[].
    foreach ($item in $maps) { $item }
}

function Get-XmlAttr {
    param($Node, [string]$Name)
    if ($null -eq $Node) { return '' }
    if ($Node.PSObject.Properties[$Name]) {
        $v = $Node.$Name
        if ($null -eq $v) { return '' }
        return [string]$v
    }
    try { return [string]$Node.GetAttribute($Name) } catch { return '' }
}

# ---------------------------------------------------------------------------
# Backend: user context
# ---------------------------------------------------------------------------
function Get-UserContext {
    <#
        Resolves a user (sAMAccountName, UPN, DN, or SID) into:
          UserSid, UserName (DOMAIN\sam), DistinguishedName,
          GroupSids  (effective/nested, from tokenGroups + primary group),
          GroupNames (DOMAIN\Group),
          OuChain    (list of OU/container DNs from the user's OU up to the domain root)
    #>
    param([Parameter(Mandatory)][string]$Identity)

    $found = $null
    try {
        if ($Identity -match '^(CN|OU)=.+,DC=') {
            $found = Get-ADUser -Identity $Identity -Properties distinguishedName, SID, sAMAccountName, primaryGroupID
        }
        else {
            # -Identity with sAMAccountName/UPN does a subtree search. Fine for
            # locating the object; tokenGroups is fetched separately by DN.
            try {
                $found = Get-ADUser -Identity $Identity -Properties distinguishedName, SID, sAMAccountName, primaryGroupID
            }
            catch {
                $escaped = $Identity.Replace("'", "''")
                $filter = "sAMAccountName -eq '$escaped' -or userPrincipalName -eq '$escaped'"
                $found = Get-ADUser -Filter $filter -Properties distinguishedName, SID, sAMAccountName, primaryGroupID |
                    Select-Object -First 1
            }
        }
    }
    catch {
        throw "Could not resolve user '$Identity': $($_.Exception.Message)"
    }
    if (-not $found) { throw "User '$Identity' was not found in Active Directory." }

    # tokenGroups requires a BASE-scope LDAP read. Re-fetch by DN (not Filter).
    $user = $null
    try {
        $user = Get-ADUser -Identity $found.DistinguishedName -Properties tokenGroups, primaryGroupID, distinguishedName, SID, sAMAccountName
    }
    catch {
        $user = $found
    }

    $domain = Get-ADDomain
    $nb = $domain.NetBIOSName
    $dns = $domain.DNSRoot

    $groupSidSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($wk in $script:WellKnownUserSids) { [void]$groupSidSet.Add($wk) }

    $tokenGroups = $null
    if ($user.PSObject.Properties['tokenGroups']) { $tokenGroups = $user.tokenGroups }
    if ($tokenGroups) {
        foreach ($tg in @($tokenGroups)) {
            $sid = ConvertTo-SidString $tg
            if ($sid) { [void]$groupSidSet.Add($sid) }
        }
    }

    # Primary group is not always present on tokenGroups.
    try {
        $rid = $user.primaryGroupID
        if ($rid -and $user.SID -and $user.SID.AccountDomainSid) {
            $primary = '{0}-{1}' -f $user.SID.AccountDomainSid.Value, $rid
            [void]$groupSidSet.Add($primary)
        }
    }
    catch { }

    # ADSI RefreshCache fallback when the AD module returned no tokenGroups.
    $domainGroupCount = @($groupSidSet | Where-Object { $_ -like 'S-1-5-21-*' }).Count
    if ($domainGroupCount -eq 0) {
        try {
            foreach ($sid in Get-TokenGroupSidFromAdsi -DistinguishedName $user.DistinguishedName) {
                if ($sid) { [void]$groupSidSet.Add($sid) }
            }
        }
        catch { }
    }

    $domainGroupCount = @($groupSidSet | Where-Object { $_ -like 'S-1-5-21-*' }).Count
    if ($domainGroupCount -eq 0) {
        try {
            foreach ($g in @(Get-ADPrincipalGroupMembership -Identity $user.DistinguishedName -ErrorAction Stop)) {
                $sid = ConvertTo-SidString $g.SID
                if ($sid) { [void]$groupSidSet.Add($sid) }
            }
        }
        catch { }
    }

    $groupSids = @($groupSidSet)

    $groupNames = New-Object System.Collections.Generic.List[string]
    foreach ($sid in $groupSids) {
        if ($sid -notlike 'S-1-5-21-*') { continue }  # skip well-known; ILT matches those by SID
        try {
            $nt = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value
            if ($nt) { $groupNames.Add($nt) | Out-Null }
        }
        catch {
            try {
                $g = Get-ADGroup -Identity $sid -ErrorAction Stop
                $groupNames.Add("$nb\$($g.SamAccountName)") | Out-Null
            }
            catch { }
        }
    }

    $ouChain = New-Object System.Collections.Generic.List[string]
    $dn = $user.DistinguishedName
    $parent = ($dn -split '(?<!\\),', 2)[1]
    while ($parent -and $parent -match '^(OU|CN)=') {
        $ouChain.Add($parent) | Out-Null
        $parent = ($parent -split '(?<!\\),', 2)[1]
    }
    if ($parent) { $ouChain.Add($parent) | Out-Null }

    [pscustomobject]@{
        UserName          = "$nb\$($user.SamAccountName)"
        UserSid           = (ConvertTo-SidString $user.SID)
        DistinguishedName = $user.DistinguishedName
        GroupSids         = @($groupSids)
        GroupNames        = @($groupNames)
        OuChain           = @($ouChain)
        NetBIOSName       = $nb
        DomainDns         = $dns
        PrimaryGroupSid   = $(
            try { '{0}-{1}' -f $user.SID.AccountDomainSid.Value, $user.primaryGroupID }
            catch { $null }
        )
    }
}

function Get-TokenGroupSidFromAdsi {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    $sids = New-Object System.Collections.Generic.List[string]
    $entry = $null
    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DistinguishedName")
        $entry.RefreshCache(@('tokenGroups'))
        foreach ($bytes in @($entry.Properties['tokenGroups'])) {
            if ($null -eq $bytes) { continue }
            $sid = New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)
            $sids.Add($sid.Value) | Out-Null
        }
    }
    finally {
        if ($entry) { $entry.Dispose() }
    }
    foreach ($s in $sids) { $s }
}

# ---------------------------------------------------------------------------
# Backend: applicable GPOs
# ---------------------------------------------------------------------------
function Get-TrusteeSidString {
    param($Trustee)
    if ($null -eq $Trustee) { return $null }
    $sid = $null
    if ($Trustee.PSObject.Properties['Sid']) { $sid = ConvertTo-SidString $Trustee.Sid }
    if ($sid) { return $sid }
    $name = $null
    if ($Trustee.PSObject.Properties['Name']) { $name = [string]$Trustee.Name }
    if ($name -eq 'Everyone') { return 'S-1-1-0' }
    if ($name -eq 'Authenticated Users') { return 'S-1-5-11' }
    return $null
}

function Test-GpoPermissionApplies {
    <#
        Security filtering: the user (or a group in their token) must have Allow
        GpoApply, and must not have Deny GpoApply. Authenticated Users / Everyone
        count as a match. Unreadable ACLs are treated as applies (conservative).
    #>
    param(
        [Parameter(Mandatory)]$GpoId,
        [Parameter(Mandatory)][string[]]$ApplyPrincipals
    )

    $note = ''
    try {
        $perms = @(Get-GPPermission -Guid $GpoId -All -ErrorAction Stop)
    }
    catch {
        return @{ Applies = $true; Note = 'Security filter unreadable - assumed applies' }
    }

    $allow = $false
    $deny = $false
    $principalSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $ApplyPrincipals) { if ($p) { [void]$principalSet.Add($p) } }
    foreach ($wk in $script:WellKnownUserSids) { [void]$principalSet.Add($wk) }

    foreach ($perm in $perms) {
        if (-not $perm) { continue }
        $permission = [string]$perm.Permission
        if ($permission -ne 'GpoApply') { continue }

        $trusteeSid = Get-TrusteeSidString $perm.Trustee
        if (-not $trusteeSid) { continue }
        if (-not $principalSet.Contains($trusteeSid)) { continue }

        $isDenied = $false
        if ($perm.PSObject.Properties['Denied'] -and $perm.Denied) { $isDenied = $true }
        if ($isDenied) { $deny = $true } else { $allow = $true }
    }

    if ($deny) {
        return @{ Applies = $false; Note = 'Denied Apply Group Policy' }
    }
    if (-not $allow) {
        return @{ Applies = $false; Note = 'Security filtering: no matching GpoApply' }
    }
    return @{ Applies = $true; Note = $note }
}

function Get-ApplicableGpo {
    <#
        Returns GPO objects (Id, DisplayName) that apply to the user:
          1. Inherited + direct link set for the user's parent OU.
             InheritedGpoLinks is the effective client list (enabled links that
             survive block-inheritance / enforcement). GpoLinks is unioned in
             and then disabled links / user-disabled GPOs are dropped.
          2. Security filtering: Allow GpoApply and not Deny GpoApply.
    #>
    param([Parameter(Mandatory)]$UserContext)

    $userOu = ($UserContext.DistinguishedName -split '(?<!\\),', 2)[1]
    if (-not $userOu) { throw "Could not determine parent OU for '$($UserContext.DistinguishedName)'." }

    $inh = $null
    try {
        $inh = Get-GPInheritance -Target $userOu -ErrorAction Stop
    }
    catch {
        throw "Get-GPInheritance failed for '$userOu': $($_.Exception.Message)"
    }

    $applyPrincipals = @($UserContext.UserSid) + @($UserContext.GroupSids)
    $result = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[guid]'

    $linkLists = @()
    if ($inh.PSObject.Properties['InheritedGpoLinks'] -and $inh.InheritedGpoLinks) {
        $linkLists += , @($inh.InheritedGpoLinks)
    }
    if ($inh.PSObject.Properties['GpoLinks'] -and $inh.GpoLinks) {
        $linkLists += , @($inh.GpoLinks)
    }

    foreach ($list in $linkLists) {
        foreach ($link in @($list)) {
            if (-not $link) { continue }

            $gpoId = ConvertTo-NormalizedGuid $(if ($link.PSObject.Properties['GpoId']) { $link.GpoId } else { $null })
            if (-not $gpoId) { continue }
            if (-not $seen.Add($gpoId)) { continue }

            if ($link.PSObject.Properties['Enabled'] -and ($link.Enabled -eq $false)) { continue }

            $displayName = if ($link.PSObject.Properties['DisplayName']) { [string]$link.DisplayName } else { [string]$gpoId }

            $filterNote = ''
            $skipUser = $false
            try {
                $gpoObj = Get-GPO -Guid $gpoId -ErrorAction Stop
                if ($gpoObj.PSObject.Properties['DisplayName'] -and $gpoObj.DisplayName) {
                    $displayName = [string]$gpoObj.DisplayName
                }
                $status = [string]$gpoObj.GpoStatus
                if ($status -eq 'AllSettingsDisabled' -or $status -eq 'UserSettingsDisabled') {
                    $skipUser = $true
                }
                if ($gpoObj.PSObject.Properties['WmiFilter'] -and $gpoObj.WmiFilter) {
                    $filterNote = 'WMI filter present - may not apply on every client'
                }
            }
            catch { }

            if ($skipUser) { continue }

            $sec = Test-GpoPermissionApplies -GpoId $gpoId -ApplyPrincipals $applyPrincipals
            if (-not $sec.Applies) { continue }
            if ($sec.Note) {
                if ($filterNote) { $filterNote = $filterNote + '; ' + $sec.Note }
                else { $filterNote = $sec.Note }
            }

            $result.Add([pscustomobject]@{
                Id          = $gpoId
                DisplayName = (ConvertTo-SingleString $displayName)
                Enabled     = $true
                FilterNote  = $filterNote
            }) | Out-Null
        }
    }

    foreach ($item in $result) { $item }
}

# ---------------------------------------------------------------------------
# Backend: read drive maps from SYSVOL
# ---------------------------------------------------------------------------
function Get-GpoDriveMap {
    <#
        Reads User\Preferences\Drives\Drives.xml for a GPO and returns one object
        per enabled <Drive> element, including the raw <Filters> node for ILT.
    #>
    param(
        [Parameter(Mandatory)]$GpoId,
        [Parameter(Mandatory)]$GpoName,
        [Parameter(Mandatory)]$DomainDns
    )
    $GpoName = ConvertTo-SingleString $GpoName
    $DomainDns = ConvertTo-SingleString $DomainDns

    $folder = Get-SysvolPolicyFolderName -GpoId $GpoId
    if (-not $folder) { return @() }

    $candidates = @(
        "\\$DomainDns\SYSVOL\$DomainDns\Policies\$folder\User\Preferences\Drives\Drives.xml"
    )
    if ($env:USERDNSDOMAIN -and $env:USERDNSDOMAIN -ne $DomainDns) {
        $candidates += "\\$($env:USERDNSDOMAIN)\SYSVOL\$($env:USERDNSDOMAIN)\Policies\$folder\User\Preferences\Drives\Drives.xml"
    }

    $path = $null
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { $path = $c; break }
    }
    if (-not $path) { return @() }

    $xml = New-Object System.Xml.XmlDocument
    $xml.PreserveWhitespace = $false
    try {
        # XmlDocument.Load detects BOM/UTF-8; Get-Content -Raw in 5.1 uses ANSI.
        $xml.Load($path)
    }
    catch { return @() }

    return ConvertFrom-DrivesXml -Xml $xml -GpoName $GpoName
}

# ---------------------------------------------------------------------------
# Backend: Item Level Targeting evaluator
# ---------------------------------------------------------------------------
function Test-IltFilterList {
    <#
        Evaluates an ILT filter container (<Filters> or a <FilterCollection>)
        against the user context using GPP's strict left-to-right combination:
          - Each item's 'bool' attribute (AND/OR) combines it with the running
            result. The first item's bool is ignored.
          - 'not="1"' negates the individual item before combination.
          - Collections are evaluated recursively as a single grouped item.

        Returns a hashtable: @{ Result = <bool>; Unknown = <bool> }
        Unknown = $true means an unsupported filter type was present, so the
        verdict is best-effort (unknown items are treated as $true / "applies").
    #>
    param(
        [Parameter(Mandatory)]$FilterNode,
        [Parameter(Mandatory)]$UserContext
    )

    $result = $true
    $first = $true
    $unknown = $false

    foreach ($child in $FilterNode.ChildNodes) {
        if ($child.NodeType -ne 'Element') { continue }

        $notRaw = Get-XmlAttr $child 'not'
        $notFlag = ($notRaw -eq '1')
        $boolRaw = Get-XmlAttr $child 'bool'
        $boolOp = if ($boolRaw) { $boolRaw.ToUpperInvariant() } else { 'AND' }

        $itemResult = $true
        switch -Regex ($child.LocalName) {
            '^(FilterCollection|Collection)$' {
                $sub = Test-IltFilterList -FilterNode $child -UserContext $UserContext
                $itemResult = [bool]$sub.Result
                if ($sub.Unknown) { $unknown = $true }
            }
            '^FilterGroup$' {
                $g = Test-FilterGroup -Node $child -UserContext $UserContext
                $itemResult = [bool]$g.Result
                if ($g.Unknown) { $unknown = $true }
            }
            '^FilterUser$' {
                $itemResult = Test-FilterUser -Node $child -UserContext $UserContext
            }
            '^FilterOrgUnit$' {
                $itemResult = Test-FilterOrgUnit -Node $child -UserContext $UserContext
            }
            '^FilterDomain$' {
                $itemResult = Test-FilterDomain -Node $child -UserContext $UserContext
            }
            default {
                # Unsupported filter type -> conservative "could apply".
                $itemResult = $true
                $unknown = $true
            }
        }

        if ($notFlag) { $itemResult = -not $itemResult }

        if ($first) {
            $result = $itemResult
            $first = $false
        }
        elseif ($boolOp -eq 'OR') {
            $result = ($result -or $itemResult)
        }
        else {
            $result = ($result -and $itemResult)
        }
    }

    @{ Result = $result; Unknown = $unknown }
}

function Test-FilterGroup {
    param($Node, $UserContext)

    # Computer-token group filters cannot be evaluated for a user-only lookup.
    $userContextAttr = Get-XmlAttr $Node 'userContext'
    if ($userContextAttr -eq '0') {
        return @{ Result = $true; Unknown = $true }
    }

    $localGroup = Get-XmlAttr $Node 'localGroup'
    if ($localGroup -eq '1') {
        return @{ Result = $true; Unknown = $true }
    }

    $sid = (Get-XmlAttr $Node 'sid').Trim()
    $primaryOnly = (Get-XmlAttr $Node 'primaryGroup') -eq '1'

    if ($primaryOnly) {
        $pSid = $null
        if ($UserContext.PSObject.Properties['PrimaryGroupSid']) { $pSid = $UserContext.PrimaryGroupSid }
        $matched = $false
        if ($sid -and $pSid -and [string]::Equals($sid, $pSid, [StringComparison]::OrdinalIgnoreCase)) {
            $matched = $true
        }
        return @{ Result = $matched; Unknown = $false }
    }

    if ($sid) {
        foreach ($g in @($UserContext.GroupSids)) {
            if ($g -and [string]::Equals($g, $sid, [StringComparison]::OrdinalIgnoreCase)) {
                return @{ Result = $true; Unknown = $false }
            }
        }
    }

    $n = (Get-XmlAttr $Node 'name').Trim()
    if ($n) {
        foreach ($g in @($UserContext.GroupNames)) {
            if ($g -and [string]::Equals($g, $n, [StringComparison]::OrdinalIgnoreCase)) {
                return @{ Result = $true; Unknown = $false }
            }
        }
        $bare = ($n -split '\\')[-1]
        foreach ($g in @($UserContext.GroupNames)) {
            if (-not $g) { continue }
            if ([string]::Equals(($g -split '\\')[-1], $bare, [StringComparison]::OrdinalIgnoreCase)) {
                return @{ Result = $true; Unknown = $false }
            }
        }
        if ($n -eq 'Authenticated Users' -or $n -eq 'NT AUTHORITY\Authenticated Users') {
            return @{ Result = $true; Unknown = $false }
        }
        if ($n -eq 'Everyone' -or $n -eq 'NT AUTHORITY\Everyone') {
            return @{ Result = $true; Unknown = $false }
        }
    }

    @{ Result = $false; Unknown = $false }
}

function Test-FilterUser {
    param($Node, $UserContext)
    $sid = (Get-XmlAttr $Node 'sid').Trim()
    if ($sid -and [string]::Equals($sid, $UserContext.UserSid, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    $n = (Get-XmlAttr $Node 'name').Trim()
    if ($n) {
        if ([string]::Equals($n, $UserContext.UserName, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        $bare = ($n -split '\\')[-1]
        if ([string]::Equals($bare, ($UserContext.UserName -split '\\')[-1], [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Test-FilterOrgUnit {
    param($Node, $UserContext)
    $ouDn = (Get-XmlAttr $Node 'name').Trim()
    if (-not $ouDn) { return $false }
    $direct = (Get-XmlAttr $Node 'directMember') -eq '1'
    return Test-DnIsUnderOu -ObjectDn $UserContext.DistinguishedName -OuDn $ouDn -DirectMember $direct
}

function Test-FilterDomain {
    param($Node, $UserContext)
    $n = (Get-XmlAttr $Node 'name').Trim()
    if (-not $n) { return $false }
    $dns = ''
    $nb = ''
    if ($UserContext.PSObject.Properties['DomainDns']) { $dns = [string]$UserContext.DomainDns }
    if ($UserContext.PSObject.Properties['NetBIOSName']) { $nb = [string]$UserContext.NetBIOSName }
    if ($dns -and [string]::Equals($n, $dns, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($nb -and [string]::Equals($n, $nb, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $false
}

function Test-DriveMapApplies {
    <#
        Returns @{ Applies = <bool>; Unknown = <bool>; Summary = <string> }
        A mapping with no <Filters> applies to everyone the GPO reaches.
    #>
    param($DriveMap, $UserContext)

    if (-not $DriveMap.FiltersNode) {
        return @{ Applies = $true; Unknown = $false; Summary = 'No ILT (applies to all)' }
    }
    $eval = Test-IltFilterList -FilterNode $DriveMap.FiltersNode -UserContext $UserContext
    $summary = Get-IltSummary -FilterNode $DriveMap.FiltersNode
    @{ Applies = $eval.Result; Unknown = $eval.Unknown; Summary = $summary }
}

function Get-IltSummary {
    # Human-readable one-line description of the filters (best-effort).
    param($FilterNode)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($child in $FilterNode.ChildNodes) {
        if ($child.NodeType -ne 'Element') { continue }
        $notRaw = Get-XmlAttr $child 'not'
        $prefix = if ($notRaw -eq '1') { 'NOT ' } else { '' }
        $piece = ''
        switch -Regex ($child.LocalName) {
            '^(FilterCollection|Collection)$' { $piece = "$prefix( " + (Get-IltSummary $child) + " )" }
            '^FilterGroup$' { $piece = $prefix + "Group:$(Get-XmlAttr $child 'name')" }
            '^FilterUser$' { $piece = $prefix + "User:$(Get-XmlAttr $child 'name')" }
            '^FilterOrgUnit$' { $piece = $prefix + "OU:$(Get-XmlAttr $child 'name')" }
            '^FilterDomain$' { $piece = $prefix + "Domain:$(Get-XmlAttr $child 'name')" }
            default { $piece = $prefix + "$($child.LocalName)?" }
        }
        $boolRaw = Get-XmlAttr $child 'bool'
        if ($boolRaw) { $piece = $piece + " [$($boolRaw.ToUpperInvariant())]" }
        $parts.Add($piece) | Out-Null
    }
    ($parts -join ' ')
}

# ---------------------------------------------------------------------------
# Backend: orchestrator
# ---------------------------------------------------------------------------
function Invoke-CollisionCheck {
    <#
        Core logic. Returns a hashtable with Rows (for the grid), Summary text,
        and a HasCollision flag.
    #>
    param(
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$ProposedLetter,
        [string]$ProposedPath = '',
        [string]$ProposedAction = 'Create',
        [guid]$SelectedGpoId = [guid]::Empty,
        [string]$SelectedGpoName
    )

    $domainDns = (Get-ADDomain).DNSRoot
    $userCtx = Get-UserContext -Identity $Identity
    $letter = ConvertTo-NormalizedDriveLetter $ProposedLetter

    $applicable = ConvertTo-FlatList (Get-ApplicableGpo -UserContext $userCtx)

    # Ensure the selected GPO is always evaluated even if filtering excluded it.
    # [guid]::Empty is truthy in PowerShell — only honor a real caller-supplied id.
    $hasSelected = $PSBoundParameters.ContainsKey('SelectedGpoId') -and
        $SelectedGpoId -ne [guid]::Empty
    if ($hasSelected) {
        $already = $false
        foreach ($g in $applicable) {
            if ((ConvertTo-NormalizedGuid $g.Id) -eq $SelectedGpoId) { $already = $true; break }
        }
        if (-not $already) {
            [void]$applicable.Add([pscustomobject]@{
                Id          = $SelectedGpoId
                DisplayName = (ConvertTo-SingleString $SelectedGpoName)
                Enabled     = $true
                FilterNote  = 'Selected GPO (not in user scope - shown anyway)'
            })
        }
    }

    $rows = New-Object System.Collections.ArrayList

    [void]$rows.Add([pscustomobject]@{
        Letter      = $letter
        Source      = '>> PROPOSED <<'
        Path        = $ProposedPath
        Action      = $ProposedAction
        Applies     = 'Yes'
        Targeting   = "User:$($userCtx.UserName)"
        Notes       = ''
        IsCollision = $false
    })

    $collidingCount = 0
    foreach ($gpo in $applicable) {
        $gpoName = ConvertTo-SingleString $gpo.DisplayName
        $maps = ConvertTo-FlatList (Get-GpoDriveMap -GpoId $gpo.Id -GpoName $gpoName -DomainDns $domainDns)
        foreach ($m in $maps) {
            if (-not $m) { continue }
            $eval = Test-DriveMapApplies -DriveMap $m -UserContext $userCtx
            if (-not $eval.Applies) { continue }

            $notes = New-Object System.Collections.Generic.List[string]
            if ($eval.Unknown) { $notes.Add('ILT has unsupported filter(s) - verdict best-effort') | Out-Null }
            if ($gpo.FilterNote) { $notes.Add([string]$gpo.FilterNote) | Out-Null }
            if ((Get-XmlAttr $m 'UseLetter') -eq '0' -or $m.UseLetter -eq '0') {
                $notes.Add("GPP 'Use first available' starting at $($m.Letter):") | Out-Null
            }

            $hit = Resolve-DriveMapCollision `
                -ProposedLetter $letter `
                -ProposedPath $ProposedPath `
                -ExistingLetter $m.Letter `
                -ExistingPath $m.Path `
                -ExistingAction $m.Action

            if ($hit.IsCollision) {
                $collidingCount++
                if ($hit.Note) { $notes.Add($hit.Note) | Out-Null }
            }

            [void]$rows.Add([pscustomobject]@{
                Letter      = $m.Letter
                Source      = $gpoName
                Path        = $m.Path
                Action      = $m.Action
                Applies     = 'Yes'
                Targeting   = $eval.Summary
                Notes       = ($notes -join '; ')
                IsCollision = [bool]$hit.IsCollision
            })
        }
    }

    $gpoCount = $applicable.Count
    $summary = if ($collidingCount -gt 0) {
        "COLLISION: drive letter $($letter): conflicts with $collidingCount existing mapping(s) that also apply to $($userCtx.UserName)."
    }
    else {
        "OK: drive letter $($letter): is free for $($userCtx.UserName) across all $gpoCount applicable GPO(s)."
    }

    @{
        Rows         = $rows
        Summary      = $summary
        HasCollision = ($collidingCount -gt 0)
        UserContext  = $userCtx
        GpoCount     = $gpoCount
    }
}

# ---------------------------------------------------------------------------
# GUI (WPF / XAML) — skipped when -SkipGui or when the file is dot-sourced
# ---------------------------------------------------------------------------
if (-not $script:LoadGui) { return }

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

function Assert-Modules {
    $missing = @()
    foreach ($m in 'ActiveDirectory', 'GroupPolicy') {
        if (-not (Get-Module -ListAvailable -Name $m)) { $missing += $m }
    }
    if ($missing.Count -gt 0) {
        [System.Windows.MessageBox]::Show(
            "Required module(s) not found: $($missing -join ', ').`n`n" +
            "Install RSAT (ActiveDirectory + GroupPolicy) and try again.",
            'Missing Prerequisites', 'OK', 'Error') | Out-Null
        return $false
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
    return $true
}

function ConvertTo-GuiBrush {
    param([Parameter(Mandatory)][string]$Hex)
    $color = [System.Windows.Media.ColorConverter]::ConvertFromString($Hex)
    return New-Object System.Windows.Media.SolidColorBrush $color
}

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="GPO Drive-Mapping Collision Finder" Height="720" Width="1100"
        WindowStartupLocation="CenterScreen" Background="#FF1E1E24">
    <Window.Resources>
        <SolidColorBrush x:Key="Bg"      Color="#FF1E1E24"/>
        <SolidColorBrush x:Key="Panel"   Color="#FF2A2A33"/>
        <SolidColorBrush x:Key="Accent"  Color="#FF4C8DFF"/>
        <SolidColorBrush x:Key="Fg"      Color="#FFEDEDF2"/>
        <SolidColorBrush x:Key="Muted"   Color="#FF9A9AA6"/>

        <Style TargetType="Label">
            <Setter Property="Foreground" Value="{StaticResource Muted}"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,0,0,2"/>
        </Style>
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="#FF20202A"/>
            <Setter Property="Foreground" Value="{StaticResource Fg}"/>
            <Setter Property="BorderBrush" Value="#FF3A3A46"/>
            <Setter Property="Padding" Value="6,4"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>
        <Style TargetType="ComboBox">
            <Setter Property="Padding" Value="6,4"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>
        <Style TargetType="Button">
            <Setter Property="Background" Value="{StaticResource Accent}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="16,8"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>
    </Window.Resources>

    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <StackPanel Grid.Row="0" Margin="0,0,0,14">
            <TextBlock Text="GPO Drive-Mapping Collision Finder"
                       Foreground="{StaticResource Fg}" FontSize="20" FontWeight="Bold"/>
            <TextBlock Text="Check a proposed drive mapping against every GPO that applies to a user (OU inheritance + security filtering + Item Level Targeting). Site-linked GPOs and loopback are not evaluated."
                       Foreground="{StaticResource Muted}" FontSize="12" TextWrapping="Wrap" Margin="0,4,0,0"/>
        </StackPanel>

        <!-- Inputs -->
        <Border Grid.Row="1" Background="{StaticResource Panel}" CornerRadius="8" Padding="16" Margin="0,0,0,12">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="2*"/>
                    <ColumnDefinition Width="12"/>
                    <ColumnDefinition Width="2*"/>
                    <ColumnDefinition Width="12"/>
                    <ColumnDefinition Width="1*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <StackPanel Grid.Row="0" Grid.Column="0">
                    <Label Content="Group Policy Object"/>
                    <ComboBox x:Name="cmbGpo" IsEditable="True" IsTextSearchEnabled="True"/>
                </StackPanel>

                <StackPanel Grid.Row="0" Grid.Column="2">
                    <Label Content="User (sAMAccountName / UPN / DN)"/>
                    <TextBox x:Name="txtUser"/>
                </StackPanel>

                <StackPanel Grid.Row="0" Grid.Column="4">
                    <Label Content="Proposed Drive Letter"/>
                    <ComboBox x:Name="cmbLetter"/>
                </StackPanel>

                <StackPanel Grid.Row="1" Grid.Column="0" Margin="0,12,0,0">
                    <Label Content="Proposed UNC Path (optional)"/>
                    <TextBox x:Name="txtPath"/>
                </StackPanel>

                <StackPanel Grid.Row="1" Grid.Column="2" Margin="0,12,0,0">
                    <Label Content="Proposed Action"/>
                    <ComboBox x:Name="cmbAction"/>
                </StackPanel>

                <StackPanel Grid.Row="1" Grid.Column="4" Margin="0,12,0,0" VerticalAlignment="Bottom">
                    <Button x:Name="btnCheck" Content="Check Collisions"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Verdict banner -->
        <Border x:Name="banner" Grid.Row="2" CornerRadius="6" Padding="12,8" Margin="0,0,0,10"
                Background="#FF2A2A33" Visibility="Collapsed">
            <TextBlock x:Name="txtBanner" Foreground="White" FontSize="13" FontWeight="SemiBold" TextWrapping="Wrap"/>
        </Border>

        <!-- Results grid -->
        <DataGrid x:Name="grid" Grid.Row="3" AutoGenerateColumns="False" IsReadOnly="True"
                  Background="#FF20202A" Foreground="{StaticResource Fg}" BorderBrush="#FF3A3A46"
                  GridLinesVisibility="Horizontal" HeadersVisibility="Column"
                  RowBackground="#FF20202A" AlternatingRowBackground="#FF24242E"
                  CanUserResizeRows="False" HorizontalScrollBarVisibility="Auto">
            <DataGrid.RowStyle>
                <Style TargetType="DataGridRow">
                    <Style.Triggers>
                        <DataTrigger Binding="{Binding Path=IsCollision}" Value="True">
                            <Setter Property="Background" Value="#FF5A2130"/>
                            <Setter Property="Foreground" Value="#FFFFD7DE"/>
                        </DataTrigger>
                        <DataTrigger Binding="{Binding Path=Source}" Value="&gt;&gt; PROPOSED &lt;&lt;">
                            <Setter Property="Background" Value="#FF1F3B2A"/>
                            <Setter Property="Foreground" Value="#FFCFF5DD"/>
                        </DataTrigger>
                    </Style.Triggers>
                </Style>
            </DataGrid.RowStyle>
            <DataGrid.Columns>
                <DataGridTextColumn Header="Letter"    Binding="{Binding Path=Letter}"    Width="60"/>
                <DataGridTextColumn Header="Source"    Binding="{Binding Path=Source}"    Width="200"/>
                <DataGridTextColumn Header="Path"      Binding="{Binding Path=Path}"      Width="220"/>
                <DataGridTextColumn Header="Action"    Binding="{Binding Path=Action}"    Width="80"/>
                <DataGridTextColumn Header="Applies"   Binding="{Binding Path=Applies}"   Width="60"/>
                <DataGridTextColumn Header="Targeting" Binding="{Binding Path=Targeting}" Width="260"/>
                <DataGridTextColumn Header="Notes"     Binding="{Binding Path=Notes}"     Width="*"/>
            </DataGrid.Columns>
        </DataGrid>

        <!-- Status bar -->
        <StatusBar Grid.Row="4" Background="{StaticResource Panel}" Margin="0,10,0,0">
            <StatusBarItem>
                <TextBlock x:Name="txtStatus" Foreground="{StaticResource Muted}" Text="Ready."/>
            </StatusBarItem>
        </StatusBar>
    </Grid>
</Window>
"@

if (-not (Assert-Modules)) { return }

if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    [System.Windows.MessageBox]::Show(
        "WPF requires a single-threaded apartment.`n`n" +
        "Start with:`n  powershell.exe -STA -ExecutionPolicy Bypass -File `"$PSCommandPath`"",
        'STA Required', 'OK', 'Warning') | Out-Null
}

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$cmbGpo    = $window.FindName('cmbGpo')
$txtUser   = $window.FindName('txtUser')
$cmbLetter = $window.FindName('cmbLetter')
$txtPath   = $window.FindName('txtPath')
$cmbAction = $window.FindName('cmbAction')
$btnCheck  = $window.FindName('btnCheck')
$grid      = $window.FindName('grid')
$banner    = $window.FindName('banner')
$txtBanner = $window.FindName('txtBanner')
$txtStatus = $window.FindName('txtStatus')

foreach ($l in [char[]](68..90)) { [void]$cmbLetter.Items.Add("$l") }  # D-Z
$cmbLetter.SelectedIndex = 0

foreach ($a in 'Create', 'Replace', 'Update', 'Delete') { [void]$cmbAction.Items.Add($a) }
$cmbAction.SelectedIndex = 0

function Set-Status([string]$msg) { $txtStatus.Text = $msg; $window.Dispatcher.Invoke([action]{}, 'Render') }

Set-Status 'Loading GPOs...'
$script:GpoLookup = @{}
try {
    Get-GPO -All | Sort-Object DisplayName | ForEach-Object {
        [void]$cmbGpo.Items.Add($_.DisplayName)
        $script:GpoLookup[$_.DisplayName] = $_.Id
    }
    Set-Status "Loaded $($cmbGpo.Items.Count) GPO(s). Ready."
}
catch {
    Set-Status "Failed to load GPOs: $($_.Exception.Message)"
}

$btnCheck.Add_Click({
    $window.Cursor = 'Wait'
    $banner.Visibility = 'Collapsed'
    $grid.ItemsSource = $null
    try {
        $userText = $txtUser.Text.Trim()
        if (-not $userText) { throw 'Enter a user (sAMAccountName, UPN, or DN).' }
        if (-not $cmbLetter.SelectedItem) { throw 'Select a proposed drive letter.' }

        $gpoName = "$($cmbGpo.Text)".Trim()
        $gpoId   = [guid]::Empty
        if ($gpoName -and $script:GpoLookup.ContainsKey($gpoName)) { $gpoId = $script:GpoLookup[$gpoName] }

        Set-Status "Resolving $userText and evaluating applicable GPOs..."

        $params = @{
            Identity       = $userText
            ProposedLetter = "$($cmbLetter.SelectedItem)"
            ProposedPath   = $txtPath.Text.Trim()
            ProposedAction = "$($cmbAction.SelectedItem)"
        }
        if ($gpoId -ne [guid]::Empty) {
            $params.SelectedGpoId   = $gpoId
            $params.SelectedGpoName = $gpoName
        }

        $out = Invoke-CollisionCheck @params

        $grid.ItemsSource = $out.Rows
        $txtBanner.Text = $out.Summary
        $banner.Background = if ($out.HasCollision) {
            ConvertTo-GuiBrush '#FF7A2333'
        }
        else {
            ConvertTo-GuiBrush '#FF1F5A38'
        }
        $banner.Visibility = 'Visible'
        $existing = @($out.Rows).Count - 1
        if ($existing -lt 0) { $existing = 0 }
        Set-Status "Checked $($out.GpoCount) applicable GPO(s) for $($out.UserContext.UserName). $existing applicable existing mapping(s) found."
    }
    catch {
        $txtBanner.Text = "Error: $($_.Exception.Message)"
        $banner.Background = ConvertTo-GuiBrush '#FF7A2333'
        $banner.Visibility = 'Visible'
        Set-Status "Error: $($_.Exception.Message)"
    }
    finally {
        $window.Cursor = 'Arrow'
    }
})

$txtUser.Add_KeyDown({
    if ($_.Key -eq 'Return') {
        $btnCheck.RaiseEvent(
            (New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    }
})

[void]$window.ShowDialog()

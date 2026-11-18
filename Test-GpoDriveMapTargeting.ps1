#Requires -Version 5.1
<#
.SYNOPSIS
    Validates Group Policy Preference (GPP) drive mappings and their Item-Level
    Targeting (ILT) filters BEFORE the GPO is linked/applied, by evaluating the
    real Drives.xml filter tree against actual Active Directory data.

.DESCRIPTION
    Group Policy Preferences drive maps are stored in a GPO's SysVol path at:
        \\<domain>\SysVol\<domain>\Policies\{GPO-GUID}\User\Preferences\Drives\Drives.xml

    That XML contains one <Drive> element per mapping, each optionally carrying
    a <Filters> tree built from:
        FilterGroup       (AD security group membership - user or computer)
        FilterUser        (specific user SID/name)
        FilterComputer    (specific computer SID/name)
        FilterOrgUnit     (AD OU, with optional sub-OU matching)
        FilterSite        (AD site)
        FilterLdapQuery   (raw LDAP filter against a user/computer object)
        FilterCollection  (a nested AND/OR group of any of the above - "()" grouping)

    Each filter node carries:
        bool="AND"|"OR"   -> how it combines with the RUNNING result so far
        not="1"           -> negate this node's own result before combining

    This script parses that exact structure and evaluates it the same way the
    GPP client-side extension does (sequential left-to-right AND/OR with a
    running boolean, not a flat "all filters ANDed" assumption), then reports,
    for each user you supply, which drive letters they will actually receive.

    It supports two data sources for test subjects:
      1. Live AD accounts (default) - queried via the ActiveDirectory module.
      2. Simulated identities - a hashtable you supply, for testing scenarios
         that don't exist in AD yet (e.g. "what if this user were moved to
         OU=Contractors").

.PARAMETER GpoName
    Display name of the GPO to validate (must already exist, even if unlinked
    or disabled - it does not need to be linked to any OU to be validated).

.PARAMETER Domain
    FQDN of the domain the GPO lives in. Defaults to the current user's domain.

.PARAMETER TargetUsers
    One or more sAMAccountNames of real AD users to test against the filters.

.PARAMETER TargetOU
    Instead of -TargetUsers, evaluate every user found under this OU
    (DistinguishedName), recursively.

.PARAMETER SimulatedUsers
    Array of hashtables describing hypothetical users who may not exist in AD
    yet. Each hashtable supports:
        Name            (display label for the report)
        DistinguishedName
        MemberOfGroups  (array of group DNs or names)
        ComputerName
        ComputerMemberOfGroups (array, for FilterGroup targeting the computer)
        Site

.PARAMETER ComputerNameOverride
    Optional hashtable of Username -> ComputerName, used when a live AD user
    should be evaluated as if logging on to a specific machine (for
    FilterComputer / computer-group filters). If omitted, computer-based
    filters are marked "unverified" for live AD users.

.PARAMETER ExportCsvPath
    Optional path to write the full per-user/per-drive result matrix as CSV.

.PARAMETER ShowFilterTrace
    Switch. When set, prints the step-by-step filter evaluation for every
    user/drive combination (verbose audit trail) instead of just the summary.

.PARAMETER ReturnObject
    Switch. When set, returns the results as PowerShell objects instead of
    displaying console output. Useful for GUI integration.

.EXAMPLE
    .\Test-GpoDriveMapTargeting.ps1 -GpoName "Mapped Drives - Finance" `
        -TargetUsers alice, bob, contractor01 -ShowFilterTrace

.EXAMPLE
    .\Test-GpoDriveMapTargeting.ps1 -GpoName "Mapped Drives - Finance" `
        -TargetOU "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com" `
        -ExportCsvPath C:\temp\drivemap-validation.csv

.EXAMPLE
    $sim = @(
        @{ Name = "FutureContractor"; DistinguishedName = "OU=Contractors,DC=corp,DC=contoso,DC=com";
           MemberOfGroups = @("CN=VPN-Users,OU=Groups,DC=corp,DC=contoso,DC=com") }
    )
    .\Test-GpoDriveMapTargeting.ps1 -GpoName "Mapped Drives - Finance" -SimulatedUsers $sim

.NOTES
    Requires: RSAT ActiveDirectory PowerShell module (for live AD lookups) and
    GroupPolicy module (for GPO resolution) - or run with -SimulatedUsers only
    if neither module is available on this machine, using -DrivesXmlPath instead.

    This script is READ-ONLY. It never modifies the GPO, AD, or Drives.xml.
    
    Version: 2.0
    - Fixed XML parsing for disabled drives
    - Enhanced error handling
    - Added ReturnObject parameter for GUI integration
    - Improved group membership detection
    - Better handling of primary groups
#>

[CmdletBinding(DefaultParameterSetName = 'ByGpoName')]
param(
    [Parameter(ParameterSetName = 'ByGpoName', Mandatory = $true)]
    [string]$GpoName,

    [Parameter(ParameterSetName = 'ByXmlPath', Mandatory = $true)]
    [string]$DrivesXmlPath,

    [string]$Domain = $env:USERDNSDOMAIN,

    [string[]]$TargetUsers,

    [string]$TargetOU,

    [hashtable[]]$SimulatedUsers,

    [hashtable]$ComputerNameOverride = @{},

    [string]$ExportCsvPath,

    [switch]$ShowFilterTrace,
    
    [switch]$ReturnObject
)

$ErrorActionPreference = 'Stop'
$script:UnverifiedFilterWarnings = New-Object System.Collections.Generic.List[string]

# ---------------------------------------------------------------------------
# 0. Module checks
# ---------------------------------------------------------------------------
function Test-ModuleAvailable {
    param([string]$Name)
    return [bool](Get-Module -ListAvailable -Name $Name)
}

$adAvailable = Test-ModuleAvailable -Name 'ActiveDirectory'
if ($adAvailable) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        $adAvailable = $false
        Write-Warning "ActiveDirectory module found but failed to load: $($_.Exception.Message)"
    }
}
elseif (-not $SimulatedUsers -and -not $ReturnObject) {
    Write-Warning "ActiveDirectory module not found and no -SimulatedUsers supplied. Live AD evaluation will not be possible."
}

# ---------------------------------------------------------------------------
# 1. Locate and load Drives.xml
# ---------------------------------------------------------------------------
function Get-DrivesXmlPathFromGpoName {
    param([string]$Name, [string]$DomainFqdn)

    if (-not (Test-ModuleAvailable -Name 'GroupPolicy')) {
        throw "GroupPolicy module not available. Supply -DrivesXmlPath directly instead of -GpoName."
    }
    
    try {
        Import-Module GroupPolicy -ErrorAction Stop
    }
    catch {
        throw "Failed to load GroupPolicy module: $($_.Exception.Message)"
    }

    try {
        $gpo = Get-GPO -Name $Name -Domain $DomainFqdn -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve GPO '$Name' from domain '$DomainFqdn': $($_.Exception.Message)"
    }
    
    $guid = $gpo.Id.ToString('B')
    $path = "\\$DomainFqdn\SysVol\$DomainFqdn\Policies\$guid\User\Preferences\Drives\Drives.xml"
    
    if (-not (Test-Path $path)) {
        throw "GPO '$Name' was found, but no User-side Drives.xml exists at:`n  $path`nDrive maps may not have been configured yet, or they were configured under Computer Preferences (uncommon)."
    }
    
    return $path
}

if ($PSCmdlet.ParameterSetName -eq 'ByGpoName') {
    if (-not $Domain) { 
        throw "Could not determine domain automatically. Pass -Domain explicitly." 
    }
    
    $resolvedXmlPath = Get-DrivesXmlPathFromGpoName -Name $GpoName -DomainFqdn $Domain
    
    if (-not $ReturnObject) {
        Write-Host "Loaded Drives.xml from: $resolvedXmlPath" -ForegroundColor Cyan
    }
}
else {
    $resolvedXmlPath = $DrivesXmlPath
    
    if (-not (Test-Path $resolvedXmlPath)) {
        throw "Drives.xml file not found at: $resolvedXmlPath"
    }
}

try {
    [xml]$drivesXml = Get-Content -Path $resolvedXmlPath -Raw -ErrorAction Stop
}
catch {
    throw "Failed to load or parse Drives.xml: $($_.Exception.Message)"
}

$driveNodes = $drivesXml.SelectNodes('//Drive')
if ($driveNodes.Count -eq 0) {
    throw "No <Drive> elements found in Drives.xml. Nothing to validate."
}

# ---------------------------------------------------------------------------
# 2. Build test-subject list (live AD and/or simulated)
# ---------------------------------------------------------------------------
class TestSubject {
    [string]$Label
    [string]$SamAccountName
    [string]$DistinguishedName
    [string[]]$MemberOfGroupDNs
    [string]$ComputerName
    [string[]]$ComputerMemberOfGroupDNs
    [string]$Site
    [bool]$IsSimulated
}

$subjects = New-Object System.Collections.Generic.List[TestSubject]

function Resolve-LiveAdUser {
    param([string]$SamAccountName)

    if (-not $adAvailable) {
        throw "Cannot resolve live AD user '$SamAccountName' - ActiveDirectory module is not available."
    }

    try {
        $u = Get-ADUser -Identity $SamAccountName -Properties MemberOf, DistinguishedName -ErrorAction Stop
        $groupDns = @($u.MemberOf)

        # Primary group (usually Domain Users) is not reflected in MemberOf; include it explicitly.
        try {
            $primaryGroupID = (Get-ADUser $SamAccountName -Properties primaryGroupID -ErrorAction Stop).primaryGroupID
            $domainObj = Get-ADDomain -Server $Domain -ErrorAction Stop
            $domainSid = $domainObj.DomainSID.Value
            $primaryGroupSid = "$domainSid-$primaryGroupID"
            $primaryGroup = Get-ADGroup -Identity $primaryGroupSid -ErrorAction SilentlyContinue
            if ($primaryGroup) { 
                $groupDns += $primaryGroup.DistinguishedName 
            }
        } 
        catch { 
            # Primary group resolution is best-effort
        }

        $subj = [TestSubject]::new()
        $subj.Label = $SamAccountName
        $subj.SamAccountName = $SamAccountName
        $subj.DistinguishedName = $u.DistinguishedName
        $subj.MemberOfGroupDNs = $groupDns
        $subj.IsSimulated = $false

        if ($ComputerNameOverride.ContainsKey($SamAccountName)) {
            $compName = $ComputerNameOverride[$SamAccountName]
            $subj.ComputerName = $compName
            try {
                $comp = Get-ADComputer -Identity $compName -Properties MemberOf -ErrorAction Stop
                $subj.ComputerMemberOfGroupDNs = @($comp.MemberOf)
            } 
            catch {
                $script:UnverifiedFilterWarnings.Add("Could not resolve computer '$compName' for user '$SamAccountName' - computer-based filters for this user are unverified.")
            }
        }

        return $subj
    }
    catch {
        throw "Failed to resolve AD user '$SamAccountName': $($_.Exception.Message)"
    }
}

if ($TargetUsers) {
    foreach ($u in $TargetUsers) { 
        try {
            $subjects.Add((Resolve-LiveAdUser -SamAccountName $u))
        }
        catch {
            Write-Warning "Skipping user '$u': $_"
        }
    }
}

if ($TargetOU) {
    if (-not $adAvailable) { 
        throw "-TargetOU requires the ActiveDirectory module." 
    }
    
    try {
        $ouUsers = Get-ADUser -SearchBase $TargetOU -Filter * -Properties MemberOf -ErrorAction Stop
        foreach ($u in $ouUsers) {
            $subj = [TestSubject]::new()
            $subj.Label = $u.SamAccountName
            $subj.SamAccountName = $u.SamAccountName
            $subj.DistinguishedName = $u.DistinguishedName
            $subj.MemberOfGroupDNs = @($u.MemberOf)
            $subj.IsSimulated = $false
            
            # Try to get primary group
            try {
                $primaryGroupID = (Get-ADUser $u.SamAccountName -Properties primaryGroupID -ErrorAction Stop).primaryGroupID
                $domainObj = Get-ADDomain -Server $Domain -ErrorAction Stop
                $domainSid = $domainObj.DomainSID.Value
                $primaryGroupSid = "$domainSid-$primaryGroupID"
                $primaryGroup = Get-ADGroup -Identity $primaryGroupSid -ErrorAction SilentlyContinue
                if ($primaryGroup) { 
                    $subj.MemberOfGroupDNs += $primaryGroup.DistinguishedName 
                }
            } 
            catch { }
            
            $subjects.Add($subj)
        }
    }
    catch {
        throw "Failed to query OU '$TargetOU': $($_.Exception.Message)"
    }
}

if ($SimulatedUsers) {
    foreach ($su in $SimulatedUsers) {
        $subj = [TestSubject]::new()
        $subj.Label = [string]$su.Name
        $subj.DistinguishedName = [string]$su.DistinguishedName
        $subj.MemberOfGroupDNs = @($su.MemberOfGroups)
        $subj.ComputerName = [string]$su.ComputerName
        $subj.ComputerMemberOfGroupDNs = @($su.ComputerMemberOfGroups)
        $subj.Site = [string]$su.Site
        $subj.IsSimulated = $true
        $subjects.Add($subj)
    }
}

if ($subjects.Count -eq 0) {
    throw "No test subjects supplied. Use -TargetUsers, -TargetOU, and/or -SimulatedUsers."
}

# ---------------------------------------------------------------------------
# 3. Helper: does DN live under OU (optionally recursive)?
# ---------------------------------------------------------------------------
function Test-DnUnderOu {
    param([string]$Dn, [string]$OuDn, [bool]$IncludeSubOus)

    if (-not $Dn -or -not $OuDn) { return $false }
    if ($Dn -eq $OuDn) { return $true }

    if ($IncludeSubOus) {
        return $Dn.ToLower().EndsWith(",$($OuDn.ToLower())")
    }
    else {
        # Direct child only: strip the leading RDN of $Dn and compare the remainder to $OuDn.
        $firstComma = $Dn.IndexOf(',')
        if ($firstComma -lt 0) { return $false }
        $parentOfDn = $Dn.Substring($firstComma + 1)
        return $parentOfDn.ToLower() -eq $OuDn.ToLower()
    }
}

function Test-GroupMembership {
    param([string[]]$MemberOfDns, [string]$GroupIdentity)

    if (-not $MemberOfDns -or -not $GroupIdentity) { return $false }
    
    foreach ($dn in $MemberOfDns) {
        # Exact match
        if ($dn -ieq $GroupIdentity) { return $true }
        
        # Extract CN from both and compare
        if ($dn -match '^CN=([^,]+)' -and $GroupIdentity -match '^CN=([^,]+)') {
            $dnCN = $matches[1]
            $groupCN = if ($GroupIdentity -match '^CN=([^,]+)') { $matches[1] } else { $GroupIdentity }
            if ($dnCN -ieq $groupCN) { return $true }
        }
        
        # Handle DOMAIN\GroupName format
        if ($GroupIdentity -match '\\') {
            $groupNameOnly = ($GroupIdentity -split '\\')[-1]
            if ($dn -match "^CN=$([regex]::Escape($groupNameOnly)),") { return $true }
        }
    }
    
    return $false
}

# ---------------------------------------------------------------------------
# 4. Recursive ILT filter evaluator (mirrors GPP CSE semantics)
# ---------------------------------------------------------------------------
function Invoke-FilterNode {
    param(
        [System.Xml.XmlElement]$Node,
        [TestSubject]$Subject,
        [System.Collections.Generic.List[string]]$Trace,
        [int]$Depth = 0
    )

    $indent = ('  ' * $Depth)
    $isNot = ($Node.GetAttribute('not') -eq '1')
    $raw = $null

    switch ($Node.LocalName) {

        'FilterCollection' {
            $raw = Invoke-FilterTree -Node $Node -Subject $Subject -Trace $Trace -Depth ($Depth + 1)
        }

        'FilterGroup' {
            $groupName = $Node.GetAttribute('name')
            $userMatch = Test-GroupMembership -MemberOfDns $Subject.MemberOfGroupDNs -GroupIdentity $groupName
            $compMatch = Test-GroupMembership -MemberOfDns $Subject.ComputerMemberOfGroupDNs -GroupIdentity $groupName
            $raw = $userMatch -or $compMatch
            $Trace.Add("$indent FilterGroup '$groupName' -> user-member:$userMatch computer-member:$compMatch")
        }

        'FilterUser' {
            $target = $Node.GetAttribute('name')
            $raw = ($Subject.SamAccountName -and $target -match [regex]::Escape($Subject.SamAccountName)) `
                   -or ($Subject.DistinguishedName -ieq $target)
            $Trace.Add("$indent FilterUser '$target' -> $raw")
        }

        'FilterComputer' {
            $target = $Node.GetAttribute('name')
            if (-not $Subject.ComputerName) {
                $raw = $false
                $script:UnverifiedFilterWarnings.Add("FilterComputer '$target' for subject '$($Subject.Label)': no ComputerName supplied - defaulting to NOT matched. Supply -ComputerNameOverride or SimulatedUsers.ComputerName to verify.")
            } else {
                $raw = ($Subject.ComputerName -ieq $target) -or ($target -match [regex]::Escape($Subject.ComputerName))
            }
            $Trace.Add("$indent FilterComputer '$target' -> $raw")
        }

        'FilterOrgUnit' {
            $ouDn = $Node.GetAttribute('name')
            $includeSub = $true
            $raw = Test-DnUnderOu -Dn $Subject.DistinguishedName -OuDn $ouDn -IncludeSubOus $includeSub
            $Trace.Add("$indent FilterOrgUnit '$ouDn' -> $raw (subject DN: $($Subject.DistinguishedName))")
        }

        'FilterSite' {
            $siteName = $Node.GetAttribute('name')
            if (-not $Subject.Site) {
                $raw = $false
                $script:UnverifiedFilterWarnings.Add("FilterSite '$siteName' for subject '$($Subject.Label)': no Site supplied - defaulting to NOT matched.")
            } else {
                $raw = ($Subject.Site -ieq $siteName)
            }
            $Trace.Add("$indent FilterSite '$siteName' -> $raw")
        }

        'FilterLdapQuery' {
            $filterText = $Node.GetAttribute('filter')
            if (-not $adAvailable -or -not $Subject.DistinguishedName -or $Subject.IsSimulated) {
                $raw = $false
                $script:UnverifiedFilterWarnings.Add("FilterLdapQuery '$filterText' for subject '$($Subject.Label)': cannot be verified for simulated subjects or without AD module - defaulting to NOT matched.")
            } else {
                try {
                    $match = Get-ADObject -LDAPFilter $filterText -SearchBase $Subject.DistinguishedName -SearchScope Base -ErrorAction Stop
                    $raw = [bool]$match
                } catch {
                    $raw = $false
                    $script:UnverifiedFilterWarnings.Add("FilterLdapQuery '$filterText' errored for subject '$($Subject.Label)': $($_.Exception.Message)")
                }
            }
            $Trace.Add("$indent FilterLdapQuery '$filterText' -> $raw")
        }

        default {
            $raw = $false
            $script:UnverifiedFilterWarnings.Add("Unsupported filter type '<$($Node.LocalName)>' encountered - not evaluated (e.g. WMI/RAM/Battery/Date/etc). Defaulting to NOT matched; verify manually.")
            $Trace.Add("$indent [UNSUPPORTED] <$($Node.LocalName)> -> forced FALSE, needs manual review")
        }
    }

    $final = if ($isNot) { -not $raw } else { $raw }
    if ($isNot) { $Trace.Add("$indent  (NOT applied -> $final)") }
    return $final
}

function Invoke-FilterTree {
    param(
        [System.Xml.XmlElement]$Node,
        [TestSubject]$Subject,
        [System.Collections.Generic.List[string]]$Trace,
        [int]$Depth = 0
    )

    $children = @($Node.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] })
    if ($children.Count -eq 0) { return $true }

    $result = $null
    foreach ($child in $children) {
        $value = Invoke-FilterNode -Node $child -Subject $Subject -Trace $Trace -Depth $Depth
        $boolOp = $child.GetAttribute('bool')

        if ($null -eq $result) {
            $result = $value
        }
        elseif ($boolOp -ieq 'OR') {
            $result = $result -or $value
        }
        else {
            $result = $result -and $value
        }
    }
    return [bool]$result
}

# ---------------------------------------------------------------------------
# 5. Evaluate every Drive x Subject combination
# ---------------------------------------------------------------------------
$results = New-Object System.Collections.Generic.List[object]

foreach ($driveNode in $driveNodes) {
    $props = $driveNode.SelectSingleNode('Properties')
    
    if (-not $props) {
        Write-Warning "Drive node missing Properties element, skipping"
        continue
    }
    
    $letter = $props.letter
    $path = $props.path
    $label = $props.label
    $action = $props.action
    
    # Check multiple disable flags
    $isDisabledAttr = $driveNode.GetAttribute('disabled') -eq '1'
    $status = $driveNode.GetAttribute('status')
    
    $filtersNode = $driveNode.SelectSingleNode('Filters')

    foreach ($subject in $subjects) {
        $trace = New-Object System.Collections.Generic.List[string]
        $trace.Add("Drive $letter ($path) evaluated for '$($subject.Label)':")

        if ($isDisabledAttr) {
            $applies = $false
            $trace.Add("  Mapping is DISABLED in the GPO ('disabled=1') - never applies regardless of filters.")
        }
        elseif ($null -eq $filtersNode -or $filtersNode.ChildNodes.Count -eq 0) {
            $applies = $true
            $trace.Add("  No item-level targeting filters present -> applies to ALL users.")
        }
        else {
            $applies = Invoke-FilterTree -Node $filtersNode -Subject $subject -Trace $trace -Depth 1
        }

        $results.Add([pscustomobject]@{
            Subject      = $subject.Label
            DriveLetter  = $letter
            Path         = $path
            Label        = $label
            Action       = $action
            Applies      = $applies
            IsDisabled   = $isDisabledAttr
            Trace        = ($trace -join "`n")
        })

        if ($ShowFilterTrace -and -not $ReturnObject) {
            Write-Host ($trace -join "`n") -ForegroundColor (if ($applies) { 'Green' } else { 'DarkGray' })
            Write-Host ""
        }
    }
}

# ---------------------------------------------------------------------------
# 6. Summary report
# ---------------------------------------------------------------------------
if (-not $ReturnObject) {
    Write-Host "`n=================== SUMMARY: Who receives which drive ===================" -ForegroundColor Yellow
    $bySubject = $results | Group-Object Subject
    foreach ($grp in $bySubject) {
        $granted = $grp.Group | Where-Object { $_.Applies -and -not $_.IsDisabled }
        Write-Host "`n$($grp.Name):" -ForegroundColor Cyan
        if ($granted.Count -eq 0) {
            Write-Host "  (no drives mapped)" -ForegroundColor DarkGray
        } else {
            foreach ($g in $granted) {
                Write-Host ("  {0}:  {1}   ({2})" -f $g.DriveLetter, $g.Path, $g.Label)
            }
        }
    }

    # ---------------------------------------------------------------------------
    # 7. Conflict detection
    # ---------------------------------------------------------------------------
    Write-Host "`n=================== DRIVE-LETTER CONFLICTS ===================" -ForegroundColor Yellow
    $conflicts = $results | Where-Object { $_.Applies -and -not $_.IsDisabled } | 
        Group-Object Subject, DriveLetter | Where-Object { $_.Count -gt 1 }

    if ($conflicts.Count -eq 0) {
        Write-Host "None detected." -ForegroundColor Green
    } else {
        foreach ($c in $conflicts) {
            Write-Host "CONFLICT: $($c.Name) - multiple mappings evaluate TRUE simultaneously:" -ForegroundColor Red
            foreach ($item in $c.Group) {
                Write-Host ("   -> $($item.Path)  [$($item.Label)]") -ForegroundColor Red
            }
        }
    }

    # ---------------------------------------------------------------------------
    # 8. Unverifiable warnings
    # ---------------------------------------------------------------------------
    if ($script:UnverifiedFilterWarnings.Count -gt 0) {
        Write-Host "`n=================== FILTERS THAT COULD NOT BE FULLY VERIFIED ===================" -ForegroundColor Yellow
        $script:UnverifiedFilterWarnings | Sort-Object -Unique | ForEach-Object {
            Write-Host "  - $_" -ForegroundColor DarkYellow
        }
        Write-Host "`nTreat any 'Applies = True' result touching these filters with caution; verify those specific conditions manually." -ForegroundColor DarkYellow
    }

    Write-Host "`nValidation complete. Review conflicts and unverified filters above before linking/enabling this GPO." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 9. Export
# ---------------------------------------------------------------------------
if ($ExportCsvPath) {
    $results | Select-Object Subject, DriveLetter, Path, Label, Action, Applies, IsDisabled |
        Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
    
    if (-not $ReturnObject) {
        Write-Host "`nFull result matrix exported to: $ExportCsvPath" -ForegroundColor Cyan
    }
}

# ---------------------------------------------------------------------------
# 10. Return results for GUI integration
# ---------------------------------------------------------------------------
if ($ReturnObject) {
    return [pscustomobject]@{
        Results = $results
        Conflicts = ($results | Where-Object { $_.Applies -and -not $_.IsDisabled } | 
            Group-Object Subject, DriveLetter | Where-Object { $_.Count -gt 1 })
        Warnings = ($script:UnverifiedFilterWarnings | Sort-Object -Unique)
        XmlPath = $resolvedXmlPath
    }
}

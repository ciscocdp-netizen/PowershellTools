#Requires -Version 5.1
<#
.SYNOPSIS
    Unit tests for GPO-DriveMap-CollisionFinder.ps1 (no AD / no WPF).

    Run:
      pwsh -NoProfile -File ./tests/GPO-DriveMap-CollisionFinder.Tests.ps1
      powershell.exe -NoProfile -File .\tests\GPO-DriveMap-CollisionFinder.Tests.ps1
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSScriptRoot) {
    $repoRoot = Split-Path -Parent $PSScriptRoot
}
else {
    $repoRoot = (Get-Location).Path
}
$scriptPath = Join-Path $repoRoot 'GPO-DriveMap-CollisionFinder.ps1'
if (-not (Test-Path -LiteralPath $scriptPath)) {
    throw "Cannot find $scriptPath"
}

. $scriptPath -SkipGui

$script:Pass = 0
$script:Fail = 0
$script:Failures = New-Object System.Collections.Generic.List[string]

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        $script:Pass++
        Write-Host "  PASS  $Message"
    }
    else {
        $script:Fail++
        $script:Failures.Add($Message) | Out-Null
        Write-Host "  FAIL  $Message"
    }
}

function Assert-Eq {
    param($Actual, $Expected, [string]$Message)
    $ok = $false
    if ($null -eq $Actual -and $null -eq $Expected) { $ok = $true }
    elseif ($null -ne $Actual -and $null -ne $Expected) {
        $ok = [string]::Equals([string]$Actual, [string]$Expected, [StringComparison]::Ordinal)
    }
    if (-not $ok) {
        $Message = "$Message (expected='$Expected' actual='$Actual')"
    }
    Assert-True -Condition $ok -Message $Message
}

function New-TestUserContext {
    param(
        [string]$UserName = 'CONTOSO\alice',
        [string]$UserSid = 'S-1-5-21-1-2-3-1001',
        [string]$Dn = 'CN=Alice,OU=Finance,OU=Depts,DC=contoso,DC=com',
        [string[]]$GroupSids = @(),
        [string[]]$GroupNames = @(),
        [string]$PrimaryGroupSid = 'S-1-5-21-1-2-3-513',
        [string]$NetBIOSName = 'CONTOSO',
        [string]$DomainDns = 'contoso.com'
    )
    $ouChain = New-Object System.Collections.Generic.List[string]
    $parent = ($Dn -split '(?<!\\),', 2)[1]
    while ($parent -and $parent -match '^(OU|CN)=') {
        $ouChain.Add($parent) | Out-Null
        $parent = ($parent -split '(?<!\\),', 2)[1]
    }
    if ($parent) { $ouChain.Add($parent) | Out-Null }

    $sids = New-Object System.Collections.Generic.List[string]
    foreach ($wk in @('S-1-1-0', 'S-1-5-11')) { $sids.Add($wk) | Out-Null }
    if ($PrimaryGroupSid) { $sids.Add($PrimaryGroupSid) | Out-Null }
    foreach ($g in $GroupSids) { $sids.Add($g) | Out-Null }

    [pscustomobject]@{
        UserName          = $UserName
        UserSid           = $UserSid
        DistinguishedName = $Dn
        GroupSids         = @($sids)
        GroupNames        = @($GroupNames)
        OuChain           = @($ouChain)
        NetBIOSName       = $NetBIOSName
        DomainDns         = $DomainDns
        PrimaryGroupSid   = $PrimaryGroupSid
    }
}

function New-FiltersXml {
    param([Parameter(Mandatory)][string]$Inner)
    [xml]$xml = "<Filters>$Inner</Filters>"
    return $xml.DocumentElement
}

Write-Host "`n=== GUID / SYSVOL path ==="
$raw = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
$braced = '{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}'
Assert-Eq (Get-SysvolPolicyFolderName $raw) $braced 'unbraced guid -> {guid} folder'
Assert-Eq (Get-SysvolPolicyFolderName $braced) $braced 'already-braced guid is not doubled'
Assert-Eq (Get-SysvolPolicyFolderName ([guid]$raw)) $braced 'System.Guid -> {guid} folder'
Assert-True ($null -eq (Get-SysvolPolicyFolderName ([guid]::Empty))) 'Empty guid is rejected'
Assert-True ($null -eq (ConvertTo-NormalizedGuid $null)) 'null guid -> null'
Assert-True ((ConvertTo-NormalizedGuid $raw) -eq [guid]$raw) 'string parses to guid'

Write-Host "`n=== Drive letter / UNC normalize ==="
Assert-Eq (ConvertTo-NormalizedDriveLetter 's:') 'S' 's: -> S'
Assert-Eq (ConvertTo-NormalizedDriveLetter 'S') 'S' 'S stays S'
Assert-Eq (ConvertTo-NormalizedUncPath '\\Server\Share\') '\\SERVER\SHARE' 'UNC case + trailing slash'
Assert-Eq (ConvertTo-NormalizedUncPath '\\SERVER\SHARE') '\\SERVER\SHARE' 'UNC already canonical'

Write-Host "`n=== OU DN matching ==="
$userDn = 'CN=Alice,OU=Finance,OU=Depts,DC=contoso,DC=com'
Assert-True (Test-DnIsUnderOu -ObjectDn $userDn -OuDn 'OU=Finance,OU=Depts,DC=contoso,DC=com' -DirectMember $true) 'directMember matches parent OU'
Assert-True (-not (Test-DnIsUnderOu -ObjectDn $userDn -OuDn 'OU=Depts,DC=contoso,DC=com' -DirectMember $true)) 'directMember does not match grandparent'
Assert-True (Test-DnIsUnderOu -ObjectDn $userDn -OuDn 'OU=Depts,DC=contoso,DC=com' -DirectMember $false) 'nested OU matches grandparent'
Assert-True (Test-DnIsUnderOu -ObjectDn $userDn -OuDn 'DC=contoso,DC=com' -DirectMember $false) 'nested OU matches domain root'
Assert-True (-not (Test-DnIsUnderOu -ObjectDn $userDn -OuDn 'OU=HR,OU=Depts,DC=contoso,DC=com' -DirectMember $false)) 'sibling OU does not match'
Assert-True (-not (Test-DnIsUnderOu -ObjectDn $userDn -OuDn 'OU=s,DC=contoso,DC=com' -DirectMember $false)) 'suffix-of-RDN does not match (OU=s vs OU=Depts)'

Write-Host "`n=== Collision comparison ==="
$c1 = Resolve-DriveMapCollision -ProposedLetter 'S' -ProposedPath '\\fs\data' -ExistingLetter 'S' -ExistingPath '\\fs\other' -ExistingAction 'Update'
Assert-True $c1.IsCollision 'different path same letter is a collision'
Assert-True ($c1.Note -like '*already maps to*') 'different-path note mentions existing UNC'

$c2 = Resolve-DriveMapCollision -ProposedLetter 'S:' -ProposedPath '\\FS\Data\' -ExistingLetter 's' -ExistingPath '\\fs\data' -ExistingAction 'Replace'
Assert-True $c2.IsCollision 'same path (case/slash) is still a duplicate collision'
Assert-True ($c2.Note -like '*same path*') 'duplicate note'

$c3 = Resolve-DriveMapCollision -ProposedLetter 'S' -ProposedPath '\\fs\data' -ExistingLetter 'S' -ExistingPath '\\fs\data' -ExistingAction 'Delete'
Assert-True $c3.IsCollision 'Delete of the same letter is a collision'
Assert-True ($c3.Note -like '*deleted*') 'Delete note mentions unmap risk'

$c4 = Resolve-DriveMapCollision -ProposedLetter 'S' -ProposedPath '\\fs\data' -ExistingLetter 'T' -ExistingPath '\\fs\other' -ExistingAction 'Update'
Assert-True (-not $c4.IsCollision) 'different letter is not a collision'

$c5 = Resolve-DriveMapCollision -ProposedLetter 'S' -ProposedPath '' -ExistingLetter 'S' -ExistingPath '\\fs\data' -ExistingAction 'Create'
Assert-True $c5.IsCollision 'same letter with no proposed path still collides'
Assert-True ($c5.Note -like '*already used*') 'generic already-used note'

Write-Host "`n=== Drives.xml parse (disabled items, single/multi) ==="
[xml]$disabledOuter = @'
<Drives clsid="{8FDDCC1A-0C3C-43cd-A79A-527EB819D39E}" disabled="1">
  <Drive name="S:"><Properties action="U" path="\\fs\data" letter="S"/></Drive>
</Drives>
'@
$none = @(ConvertFrom-DrivesXml -Xml $disabledOuter -GpoName 'G1')
Assert-Eq $none.Count 0 'outer disabled=1 yields no maps'

[xml]$disabledItem = @'
<Drives clsid="{8FDDCC1A-0C3C-43cd-A79A-527EB819D39E}">
  <Drive name="S:" disabled="1"><Properties action="U" path="\\fs\old" letter="S"/></Drive>
  <Drive name="T:"><Properties action="C" path="\\fs\ok" letter="T" label="OK"/></Drive>
</Drives>
'@
$parsed = @(ConvertFrom-DrivesXml -Xml $disabledItem -GpoName 'G1')
Assert-Eq $parsed.Count 1 'disabled inner Drive is skipped'
Assert-Eq $parsed[0].Letter 'T' 'remaining map is T'
Assert-Eq $parsed[0].Action 'Create' 'action C -> Create'
Assert-Eq $parsed[0].Path '\\fs\ok' 'path preserved'

[xml]$single = @'
<Drives>
  <Drive name="S:">
    <Properties action="U" path="\\fs\data" letter="s"/>
    <Filters>
      <FilterGroup bool="AND" not="0" name="CONTOSO\Finance" sid="S-1-5-21-1-2-3-1111"/>
    </Filters>
  </Drive>
</Drives>
'@
$one = @(ConvertFrom-DrivesXml -Xml $single -GpoName 'Maps')
Assert-Eq $one.Count 1 'single Drive is not lost to array unrolling'
Assert-Eq $one[0].Letter 'S' 'letter normalized to S'
Assert-True ($null -ne $one[0].FiltersNode) 'Filters node is kept for ILT'

[xml]$twoDrives = @'
<Drives>
  <Drive name="S:"><Properties action="U" path="\\fs\a" letter="S"/></Drive>
  <Drive name="I:"><Properties action="C" path="\\fs\appdata" letter="I"/></Drive>
</Drives>
'@
$twoMaps = @(ConvertFrom-DrivesXml -Xml $twoDrives -GpoName 'MAC Drive Mapping')
Assert-Eq $twoMaps.Count 2 'two Drive elements enumerate as two objects (not one nested array)'
Assert-Eq $twoMaps[0].Letter 'S' 'first map letter is a single string S'
Assert-Eq $twoMaps[1].Letter 'I' 'second map letter is I'
Assert-True ($twoMaps[0].Letter -is [string]) 'Letter is System.String, not string[]'

Write-Host "`n=== Nested GPO array / GpoName [string] bind ==="
$nestedGpos = , @(
    [pscustomobject]@{ Id = [guid]::NewGuid(); DisplayName = 'MAC Drive Mapping' },
    [pscustomobject]@{ Id = [guid]::NewGuid(); DisplayName = 'Other GPO' }
)
$flatGpos = ConvertTo-FlatList $nestedGpos
Assert-Eq $flatGpos.Count 2 'ConvertTo-FlatList unwraps return , $array'

# Same shape as foreach ($gpo in $applicable) when $applicable is a nested array:
# $gpo is Object[] of GPO rows, so $gpo.DisplayName member-enumerates to string[].
$asOneGpo = $nestedGpos[0]
$enumeratedNames = @($asOneGpo | ForEach-Object { $_.DisplayName })
Assert-True ($enumeratedNames.Count -gt 1) 'nested GPO row.DisplayName is a multi-element array'
# Windows PowerShell 5.1 throws "Cannot convert value to type System.String" here.
# PowerShell 7 joins the names with a space. Neither is a valid -GpoName.
$bound = ConvertTo-SingleString $enumeratedNames
Assert-Eq $bound 'MAC Drive Mapping' 'ConvertTo-SingleString binds the first name instead of throwing or joining'

foreach ($g in $flatGpos) {
    $n = ConvertTo-SingleString $g.DisplayName
    Assert-True ($n -is [string]) ("flattened GPO DisplayName is a string: $n")
}

Write-Host "`n=== ILT: group / user / OU / domain ==="
$financeSid = 'S-1-5-21-1-2-3-1111'
$ctx = New-TestUserContext -GroupSids @($financeSid) -GroupNames @('CONTOSO\Finance')

$fg = Test-FilterGroup -Node (New-FiltersXml '<FilterGroup bool="AND" not="0" name="CONTOSO\Finance" sid="S-1-5-21-1-2-3-1111"/>').FirstChild -UserContext $ctx
Assert-True $fg.Result 'FilterGroup matches nested group SID'
Assert-True (-not $fg.Unknown) 'FilterGroup SID match is not unknown'

$fgMiss = Test-FilterGroup -Node (New-FiltersXml '<FilterGroup bool="AND" not="0" name="CONTOSO\HR" sid="S-1-5-21-1-2-3-2222"/>').FirstChild -UserContext $ctx
Assert-True (-not $fgMiss.Result) 'FilterGroup does not match a foreign group'

$fgAuth = Test-FilterGroup -Node (New-FiltersXml '<FilterGroup bool="AND" not="0" name="Authenticated Users" sid="S-1-5-11"/>').FirstChild -UserContext $ctx
Assert-True $fgAuth.Result 'FilterGroup Authenticated Users (S-1-5-11) matches'

$fgComp = Test-FilterGroup -Node (New-FiltersXml '<FilterGroup bool="AND" not="0" userContext="0" name="CONTOSO\Workstations" sid="S-1-5-21-1-2-3-3333"/>').FirstChild -UserContext $ctx
Assert-True $fgComp.Result 'computer-context FilterGroup is conservative-true'
Assert-True $fgComp.Unknown 'computer-context FilterGroup is flagged unknown'

$fgPrimary = Test-FilterGroup -Node (New-FiltersXml '<FilterGroup bool="AND" not="0" primaryGroup="1" sid="S-1-5-21-1-2-3-513" name="CONTOSO\Domain Users"/>').FirstChild -UserContext $ctx
Assert-True $fgPrimary.Result 'primaryGroup=1 matches PrimaryGroupSid'

$fu = Test-FilterUser -Node (New-FiltersXml '<FilterUser bool="AND" not="0" name="CONTOSO\alice" sid="S-1-5-21-1-2-3-1001"/>').FirstChild -UserContext $ctx
Assert-True $fu 'FilterUser matches SID/name'

$fuMiss = Test-FilterUser -Node (New-FiltersXml '<FilterUser bool="AND" not="0" name="CONTOSO\bob" sid="S-1-5-21-1-2-3-1002"/>').FirstChild -UserContext $ctx
Assert-True (-not $fuMiss) 'FilterUser does not match another user'

$ouDirect = Test-FilterOrgUnit -Node (New-FiltersXml '<FilterOrgUnit bool="AND" not="0" name="OU=Finance,OU=Depts,DC=contoso,DC=com" directMember="1"/>').FirstChild -UserContext $ctx
Assert-True $ouDirect 'FilterOrgUnit directMember matches user parent'

$ouNested = Test-FilterOrgUnit -Node (New-FiltersXml '<FilterOrgUnit bool="AND" not="0" name="OU=Depts,DC=contoso,DC=com" directMember="0"/>').FirstChild -UserContext $ctx
Assert-True $ouNested 'FilterOrgUnit without directMember matches descendant'

$ouMiss = Test-FilterOrgUnit -Node (New-FiltersXml '<FilterOrgUnit bool="AND" not="0" name="OU=HR,OU=Depts,DC=contoso,DC=com"/>').FirstChild -UserContext $ctx
Assert-True (-not $ouMiss) 'FilterOrgUnit does not match sibling OU'

$dom = Test-FilterDomain -Node (New-FiltersXml '<FilterDomain bool="AND" not="0" name="contoso.com"/>').FirstChild -UserContext $ctx
Assert-True $dom 'FilterDomain matches DNS root'

Write-Host "`n=== ILT: AND / OR / NOT / Collection ==="
$andXml = New-FiltersXml @'
<FilterGroup bool="AND" not="0" sid="S-1-5-21-1-2-3-1111" name="CONTOSO\Finance"/>
<FilterOrgUnit bool="AND" not="0" name="OU=Depts,DC=contoso,DC=com"/>
'@
$andEval = Test-IltFilterList -FilterNode $andXml -UserContext $ctx
Assert-True $andEval.Result 'AND of matching group + OU applies'

$andFail = New-FiltersXml @'
<FilterGroup bool="AND" not="0" sid="S-1-5-21-1-2-3-1111" name="CONTOSO\Finance"/>
<FilterOrgUnit bool="AND" not="0" name="OU=HR,DC=contoso,DC=com"/>
'@
$andFailEval = Test-IltFilterList -FilterNode $andFail -UserContext $ctx
Assert-True (-not $andFailEval.Result) 'AND with failing OU does not apply'

$orXml = New-FiltersXml @'
<FilterGroup bool="AND" not="0" sid="S-1-5-21-1-2-3-9999" name="CONTOSO\Nobody"/>
<FilterUser bool="OR" not="0" name="CONTOSO\alice" sid="S-1-5-21-1-2-3-1001"/>
'@
$orEval = Test-IltFilterList -FilterNode $orXml -UserContext $ctx
Assert-True $orEval.Result 'OR recovers after a failing first item'

$notXml = New-FiltersXml @'
<FilterGroup bool="AND" not="1" sid="S-1-5-21-1-2-3-1111" name="CONTOSO\Finance"/>
'@
$notEval = Test-IltFilterList -FilterNode $notXml -UserContext $ctx
Assert-True (-not $notEval.Result) 'NOT group membership excludes the user'

$collXml = New-FiltersXml @'
<FilterGroup bool="AND" not="0" sid="S-1-5-21-1-2-3-9999" name="CONTOSO\Nobody"/>
<FilterCollection bool="OR" not="0">
  <FilterUser bool="AND" not="0" name="CONTOSO\alice" sid="S-1-5-21-1-2-3-1001"/>
  <FilterOrgUnit bool="AND" not="0" name="OU=Finance,OU=Depts,DC=contoso,DC=com"/>
</FilterCollection>
'@
$collEval = Test-IltFilterList -FilterNode $collXml -UserContext $ctx
Assert-True $collEval.Result 'nested FilterCollection OR-ed with a failing group applies'

$wmiXml = New-FiltersXml @'
<FilterWmi bool="AND" not="0" query="SELECT * FROM Win32_OperatingSystem"/>
'@
$wmiEval = Test-IltFilterList -FilterNode $wmiXml -UserContext $ctx
Assert-True $wmiEval.Result 'unsupported WMI filter is conservative-true'
Assert-True $wmiEval.Unknown 'unsupported WMI filter sets Unknown'

$iltTree = Get-IltDetail -FilterNode $collXml
Assert-True ($iltTree -like '*security group*CONTOSO\Nobody*') 'ILT detail names the group'
Assert-True ($iltTree -like '*collection*') 'ILT detail nests FilterCollection'
Assert-True ($iltTree -like '*user  CONTOSO\alice*') 'ILT detail names the user'
$noIltText = Get-IltDetail -FilterNode $null
Assert-True ($noIltText -like '*No Item Level Targeting*') 'null Filters node explains no ILT'

$detailRow = [pscustomobject]@{
    Letter          = 'I'
    Source          = 'MAC Drive Mapping'
    Path            = '\\appdata.mcgnt.org\appdata'
    Action          = 'Update'
    Applies         = 'Yes'
    Targeting       = 'Group:CONTOSO\Finance'
    TargetingDetail = "WHEN security group  CONTOSO\Finance`n    SID: S-1-5-21-1-2-3-1111"
    Notes           = 'CONFLICT: letter I already used'
    Label           = 'AppData'
    DriveName       = 'I:'
    GpoId           = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    Collision       = 'Yes'
    IsCollision     = $true
}
$popup = Get-DriveMapDetailText -Row $detailRow
Assert-True ($popup -like '*Drive letter:  I*') 'detail text includes drive letter'
Assert-True ($popup -like '*Source GPO:    MAC Drive Mapping*') 'detail text includes source GPO'
Assert-True ($popup -like '*\\appdata.mcgnt.org\appdata*') 'detail text includes UNC path'
Assert-True ($popup -like '*Item Level Targeting*') 'detail text has ILT section'
Assert-True ($popup -like '*CONTOSO\Finance*') 'detail text includes ILT group'
Assert-True ($popup -like '*CONFLICT: letter I already used*') 'detail text includes notes'
Assert-True ($popup -like '*Collision:     Yes*') 'detail text includes collision flag'

Write-Host "`n=== End-to-end: group-targeted map would be missed without tokenGroups ==="
# This is the original bug: empty GroupSids made FilterGroup false, so the
# colliding S: map was skipped. With SIDs populated it must be reported.
$ctxNoGroups = New-TestUserContext -GroupSids @() -GroupNames @()
$ctxNoGroups.GroupSids = @('S-1-1-0', 'S-1-5-11')  # only well-known, no Finance

$maps = @(ConvertFrom-DrivesXml -Xml $single -GpoName 'Finance Drives')
$evalWithGroups = Test-DriveMapApplies -DriveMap $maps[0] -UserContext $ctx
$evalNoGroups = Test-DriveMapApplies -DriveMap $maps[0] -UserContext $ctxNoGroups
Assert-True $evalWithGroups.Applies 'group-targeted S: map applies when tokenGroups contains Finance'
Assert-True (-not $evalNoGroups.Applies) 'group-targeted S: map does not apply without Finance membership'

$hit = Resolve-DriveMapCollision -ProposedLetter 'S' -ProposedPath '\\fs\new' -ExistingLetter $maps[0].Letter -ExistingPath $maps[0].Path -ExistingAction $maps[0].Action
Assert-True ($evalWithGroups.Applies -and $hit.IsCollision) 'collision is reported for the group-targeted S: map'

$missed = ($evalNoGroups.Applies -eq $false)
Assert-True $missed 'empty tokenGroups would hide the same collision (the original bug)'

Write-Host "`n=== Empty <Filters> applies to everyone ==="
[xml]$noIlt = @'
<Drives>
  <Drive name="Z:"><Properties action="C" path="\\fs\home" letter="Z"/></Drive>
</Drives>
'@
$z = @(ConvertFrom-DrivesXml -Xml $noIlt -GpoName 'Home')
$zEval = Test-DriveMapApplies -DriveMap $z[0] -UserContext $ctx
Assert-True $zEval.Applies 'no ILT applies to all users the GPO reaches'
Assert-Eq $zEval.Summary 'No ILT (applies to all)' 'summary for no ILT'

Write-Host "`n=== Empty guid is truthy in PowerShell (guard required) ==="
$emptyIsTruthy = $false
if ([guid]::Empty) { $emptyIsTruthy = $true }
Assert-True $emptyIsTruthy '[guid]::Empty evaluates as $true so SelectedGpoId must use ContainsKey / -ne Empty'

Write-Host ""
Write-Host "Results: $($script:Pass) passed, $($script:Fail) failed"
if ($script:Fail -gt 0) {
    Write-Host "Failed assertions:"
    foreach ($f in $script:Failures) { Write-Host "  - $f" }
    exit 1
}
exit 0

<#
.SYNOPSIS
    GUI tool that compares a list of AD users and recommends Group Policy
    drive-map Item-Level Targeting (ILT) rules.

.DESCRIPTION
    Imports SamAccountNames from a CSV or a pasted list, reads their Active
    Directory attributes, and shows which security group, OU, or LDAP query
    would cover them. It can also reconcile the list against an existing
    group (matched, missing, and extra members).

    Requires Windows PowerShell 5.1, the ActiveDirectory module (RSAT), and
    permission to read the user and group objects. ILTAnalysis.Core.ps1 must
    sit in the same folder as this script.

.PARAMETER CsvPath
    Optional CSV or text file to load on startup. When a domain connection
    succeeds, the accounts are queried immediately.

.PARAMETER LogFolder
    Folder for the transcript-style log and for exported reports.
    Defaults to .\Logs next to this script.

.PARAMETER SelfTest
    Runs the logic tests in Tests\Invoke-ILTSelfTest.ps1 and exits. Does not
    open the GUI or contact Active Directory.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Analyze-ADUsersForILT.ps1

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Analyze-ADUsersForILT.ps1 -CsvPath C:\Temp\users.csv

.NOTES
    Version 2.0. The console menu was replaced with this GUI, and the
    analysis bugs below were fixed:

    - A single MemberOf value was enumerated character by character, so group
      names were shredded. One-item PowerShell results were also counted with
      string Length instead of 1, including a one-user OU path.
    - A header-less CSV treated the first SamAccountName as the header and
      dropped that user. UTF-8 without a BOM was misread. DOMAIN\user values
      were sent to Active Directory unchanged.
    - Distinguished names with escaped commas were split in the wrong place.
    - The primary group was queried and discarded. Get-ADPrimaryGroup is not
      an Active Directory cmdlet. Get-ADGroupMember also omits users whose
      primary group is the group being checked, and -Recursive aborts when one
      member cannot be resolved. Membership is now an LDAP query plus
      primaryGroupID, with an optional nested matching rule.
    - Group CN was used as the ILT name even when it differed from
      sAMAccountName, and CNs containing escaped commas were parsed wrong.
    - Office and physicalDeliveryOfficeName are the same attribute and were
      scored twice.
    - There is no Item-level targeting "User Property" rule. Recommendations
      are Security Group, Organizational Unit, or an LDAP Query anchored with
      (sAMAccountName=%USERNAME%). An unanchored department filter matches
      every user as soon as any user in the search base has that department.
    - Domain Users and other automatic groups are no longer recommended just
      because they cover 100% of the list. Distribution groups are called out
      as unusable for Security Group targeting.
    - extensionAttribute1-15 (Exchange schema) no longer fail the whole query
      on domains that do not have them.
    - HTML report values are encoded.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$CsvPath,
    [string]$LogFolder,
    [switch]$SelfTest
)

if ($SelfTest) {
    $testPath = Join-Path $PSScriptRoot 'Tests\Invoke-ILTSelfTest.ps1'
    if (-not (Test-Path -LiteralPath $testPath)) {
        Write-Error "Test script not found: $testPath"
        exit 1
    }
    & $testPath
    exit $LASTEXITCODE
}

$windowsHost = $true
if (Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue) {
    $windowsHost = [bool]$IsWindows
}
if (-not $windowsHost) {
    Write-Error 'Analyze-ADUsersForILT.ps1 requires Windows PowerShell 5.1 and the ActiveDirectory module.'
    exit 1
}

if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $hostExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $hostExe)) { $hostExe = 'powershell.exe' }
    $argList = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    if ($PSBoundParameters.ContainsKey('CsvPath') -and $CsvPath) { $argList += @('-CsvPath', $CsvPath) }
    if ($PSBoundParameters.ContainsKey('LogFolder') -and $LogFolder) { $argList += @('-LogFolder', $LogFolder) }
    Start-Process -FilePath $hostExe -ArgumentList $argList | Out-Null
    return
}

$corePath = Join-Path $PSScriptRoot 'ILTAnalysis.Core.ps1'
if (-not (Test-Path -LiteralPath $corePath)) {
    Write-Error "Required file not found: $corePath"
    exit 1
}
. $corePath

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }
[System.Windows.Forms.Application]::EnableVisualStyles()

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    [System.Windows.Forms.MessageBox]::Show(
        "The ActiveDirectory module is not installed or could not be loaded.`r`n`r`nInstall RSAT: Active Directory Domain Services and Lightweight Directory Services Tools, then run this script again.`r`n`r`n$($_.Exception.Message)",
        'Active Directory module required',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit 1
}

if ([string]::IsNullOrWhiteSpace($LogFolder)) {
    $LogFolder = Join-Path $PSScriptRoot 'Logs'
}
if (-not (Test-Path -LiteralPath $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
}

$script:AppVersion = '2.0'
$script:LogFolder = $LogFolder
$script:LogFile = Join-Path $LogFolder ('ADUserAnalysis_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$script:LogEntries = New-Object System.Collections.Generic.List[string]
$script:LogWriter = $null
try {
    $script:LogWriter = New-Object System.IO.StreamWriter($script:LogFile, $true, (New-Object System.Text.UTF8Encoding $false))
    $script:LogWriter.AutoFlush = $true
} catch {
    $script:LogWriter = $null
}

$script:ADUserData = New-Object System.Collections.Generic.List[object]
$script:NotFoundUsers = New-Object System.Collections.Generic.List[object]
$script:LastAnalysis = $null
$script:LastGroupCheck = $null
$script:TargetServer = $null
$script:TargetDomain = $null
$script:DomainDn = $null
$script:NetBiosName = $null
$script:TokenGroupsResolved = $false
$script:CancelRequested = $false
$script:OperationRunning = $false
$script:CloseAfterOperation = $false
$script:UiReady = $false
$script:WorkingPropertySet = $null

$script:ColorHeader = [System.Drawing.Color]::FromArgb(24, 42, 68)
$script:ColorBlue = [System.Drawing.Color]::FromArgb(0, 120, 212)
$script:ColorGreen = [System.Drawing.Color]::FromArgb(16, 124, 78)
$script:ColorRed = [System.Drawing.Color]::FromArgb(196, 43, 28)
$script:ColorSlate = [System.Drawing.Color]::FromArgb(70, 78, 92)
$script:ColorBg = [System.Drawing.Color]::FromArgb(245, 247, 250)
$script:ColorGood = [System.Drawing.Color]::FromArgb(225, 245, 232)
$script:ColorWarn = [System.Drawing.Color]::FromArgb(255, 244, 214)
$script:ColorBad = [System.Drawing.Color]::FromArgb(253, 232, 230)
$script:ColorInfo = [System.Drawing.Color]::FromArgb(226, 238, 252)
$script:FontUi = New-Object System.Drawing.Font('Segoe UI', 9)
$script:FontUiBold = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:FontTitle = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
$script:FontMono = New-Object System.Drawing.Font('Consolas', 10)

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    [void]$script:LogEntries.Add($line)
    if ($script:LogWriter) {
        try { $script:LogWriter.WriteLine($line) } catch { }
    }
    if ($script:txtLog) {
        $color = $script:ColorHeader
        if ($Level -eq 'ERROR') { $color = $script:ColorRed }
        elseif ($Level -eq 'WARN') { $color = [System.Drawing.Color]::FromArgb(153, 92, 0) }
        elseif ($Level -eq 'SUCCESS') { $color = $script:ColorGreen }
        $script:txtLog.SelectionStart = $script:txtLog.TextLength
        $script:txtLog.SelectionLength = 0
        $script:txtLog.SelectionColor = $color
        $script:txtLog.AppendText($line + "`r`n")
        $script:txtLog.ScrollToCaret()
    }
}

function Set-Progress {
    param([int]$Percent, [string]$Status)
    if ($Percent -lt 0) { $Percent = 0 }
    if ($Percent -gt 100) { $Percent = 100 }
    if ($script:progress) { $script:progress.Value = $Percent }
    if ($script:lblStatus) { $script:lblStatus.Text = $Status }
    [System.Windows.Forms.Application]::DoEvents()
}

function Set-Busy {
    param([bool]$Busy)
    $script:OperationRunning = $Busy
    foreach ($button in @(
            $script:btnQuery, $script:btnAnalyze, $script:btnExport, $script:btnImport,
            $script:btnConnect, $script:btnCompare, $script:btnClear, $script:btnBrowseGroup,
            $script:btnCopyFilter, $script:btnCopySteps
        )) {
        if ($button) { $button.Enabled = -not $Busy }
    }
    if ($script:btnCancel) { $script:btnCancel.Enabled = $Busy }
    foreach ($item in @($script:BusyMenus)) {
        if ($item) { $item.Enabled = -not $Busy }
    }
    if ($script:MainForm) { $script:MainForm.UseWaitCursor = $Busy }
}

function Test-NotFoundMessage {
    param([string]$Message)
    return $Message -match 'Cannot find an object with identity|Cannot find an object|no object with identity|Directory object not found|ObjectNotFound'
}

function Get-LookupKind {
    param([string]$Value)
    if ($Value -match '@') { return 'Upn' }
    if ($Value -match '^S-1-\d') { return 'Sid' }
    if ($Value -match '(?i)^CN=.+,DC=') { return 'Dn' }
    return 'Sam'
}

function New-OrEqualsFilter {
    param([string]$Attribute, $Values)
    $clauses = New-Object System.Collections.Generic.List[string]
    foreach ($value in (Get-Collection $Values)) {
        $text = [string]$value
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        if ($Attribute -eq 'objectSid') {
            $clauses.Add('(objectSid=' + (ConvertTo-LdapSidValue $text) + ')')
        } else {
            $clauses.Add('(' + $Attribute + '=' + (ConvertTo-LdapFilterValue $text) + ')')
        }
    }
    if ($clauses.Count -eq 0) { return '' }
    if ($clauses.Count -eq 1) { return $clauses[0] }
    return '(|' + ($clauses -join '') + ')'
}

function Get-UserPropertySets {
    $safe = @(
        'DisplayName', 'GivenName', 'Surname', 'Description', 'Department', 'Division', 'Title', 'Company',
        'Office', 'City', 'State', 'Country', 'StreetAddress', 'PostalCode',
        'EmployeeID', 'EmployeeNumber', 'EmployeeType', 'Manager',
        'HomeDirectory', 'HomeDrive', 'ProfilePath', 'ScriptPath',
        'MemberOf', 'PrimaryGroup', 'PrimaryGroupID', 'EmailAddress', 'UserPrincipalName',
        'whenCreated', 'PasswordNeverExpires', 'CanonicalName'
    )
    $ext = @('co')
    foreach ($name in (Get-ExtensionAttributeNames)) { $ext += $name }
    $calc = @('LastLogonDate', 'PasswordLastSet', 'PasswordExpired', 'LockedOut')

    $sets = New-Object System.Collections.Generic.List[object]
    [void]$sets.Add(($safe + $ext + $calc))
    [void]$sets.Add(($safe + $calc))
    [void]$sets.Add(($safe + $ext))
    [void]$sets.Add($safe)
    return ,$sets
}

function Get-CandidatePropertySets {
    $sets = New-Object System.Collections.Generic.List[object]
    $savedFirst = $false
    if ($script:WorkingPropertySet) {
        [void]$sets.Add($script:WorkingPropertySet)
        $savedFirst = $true
    }
    foreach ($set in (Get-UserPropertySets)) { [void]$sets.Add($set) }
    [PSCustomObject]@{
        Sets       = $sets
        SavedFirst = [bool]$savedFirst
    }
}

function Invoke-AdPropertyAttempts {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Filter', 'Identity')][string]$Mode,
        [string]$Filter,
        $Identity,
        [Parameter(Mandatory = $true)][string]$Server,
        [string]$SearchBase
    )

    $plan = Get-CandidatePropertySets
    $lastError = $null
    $setIndex = 0
    foreach ($set in $plan.Sets) {
        $isSaved = ($plan.SavedFirst -and $setIndex -eq 0)
        $setIndex++
        try {
            if ($Mode -eq 'Filter') {
                $found = @(Get-ADUser -LDAPFilter $Filter -SearchBase $SearchBase -Server $Server -Properties $set -ErrorAction Stop)
            } else {
                $found = @(Get-ADUser -Identity $Identity -Server $Server -Properties $set -ErrorAction Stop)
            }
            $script:WorkingPropertySet = $set
            $names = @($set)
            return [PSCustomObject]@{
                Users          = $found
                Error          = $null
                UsedExtension  = [bool]($names -contains 'extensionAttribute1')
                UsedCalculated = [bool]($names -contains 'LockedOut')
            }
        } catch {
            $lastError = $_
            if ($isSaved) { $script:WorkingPropertySet = $null }
            # A missing account will not succeed on a smaller property list.
            if (Test-NotFoundMessage $_.Exception.Message) { break }
        }
    }
    return [PSCustomObject]@{
        Users          = @()
        Error          = $lastError
        UsedExtension  = $false
        UsedCalculated = $false
    }
}

function Invoke-AdUserSearch {
    param(
        [Parameter(Mandatory = $true)][string]$Filter,
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$SearchBase
    )
    return Invoke-AdPropertyAttempts -Mode Filter -Filter $Filter -Server $Server -SearchBase $SearchBase
}

function Format-UiDate {
    param($Value)
    if ($null -eq $Value -or [string]$Value -eq '') { return '' }
    if ($Value -is [datetime]) {
        if ($Value.Year -le 1601) { return '' }
        return $Value.ToString('yyyy-MM-dd HH:mm')
    }
    return [string]$Value
}

function Format-YesNo {
    param($Value)
    if ($Value -eq $true) { return 'Yes' }
    if ($Value -eq $false) { return 'No' }
    return ''
}

function New-DirectoryUser {
    param($ADUser)
    $dn = [string]$ADUser.DistinguishedName
    $memberOf = New-Object System.Collections.Generic.List[string]
    foreach ($entry in (Get-Collection $ADUser.MemberOf)) {
        $text = [string]$entry
        if (-not [string]::IsNullOrWhiteSpace($text)) { [void]$memberOf.Add($text.Trim()) }
    }

    $row = [ordered]@{
        SamAccountName       = [string]$ADUser.SamAccountName
        Name                 = [string]$ADUser.Name
        DisplayName          = [string]$ADUser.DisplayName
        GivenName            = [string]$ADUser.GivenName
        Surname              = [string]$ADUser.Surname
        Enabled              = $(if ($null -eq $ADUser.Enabled) { $null } else { [bool]$ADUser.Enabled })
        DistinguishedName    = $dn
        CanonicalName        = [string]$ADUser.CanonicalName
        ParentOU             = (Get-ParentOuDn $dn)
        OUComponents         = (Get-OUComponents $dn)
        Description          = [string]$ADUser.Description
        Department           = [string]$ADUser.Department
        Division             = [string]$ADUser.Division
        Title                = [string]$ADUser.Title
        Company              = [string]$ADUser.Company
        Office               = [string]$ADUser.Office
        City                 = [string]$ADUser.City
        State                = [string]$ADUser.State
        Country              = [string]$ADUser.Country
        CountryName          = [string]$ADUser.co
        StreetAddress        = [string]$ADUser.StreetAddress
        PostalCode           = [string]$ADUser.PostalCode
        EmployeeID           = [string]$ADUser.EmployeeID
        EmployeeNumber       = [string]$ADUser.EmployeeNumber
        EmployeeType         = [string]$ADUser.EmployeeType
        Manager              = [string]$ADUser.Manager
        ManagerName          = ''
        EmailAddress         = [string]$ADUser.EmailAddress
        UserPrincipalName    = [string]$ADUser.UserPrincipalName
        HomeDirectory        = [string]$ADUser.HomeDirectory
        HomeDrive            = [string]$ADUser.HomeDrive
        ProfilePath          = [string]$ADUser.ProfilePath
        ScriptPath           = [string]$ADUser.ScriptPath
        PasswordNeverExpires = $(if ($null -eq $ADUser.PasswordNeverExpires) { $null } else { [bool]$ADUser.PasswordNeverExpires })
        PasswordExpired      = $(if ($null -eq $ADUser.PasswordExpired) { $null } else { [bool]$ADUser.PasswordExpired })
        LockedOut            = $(if ($null -eq $ADUser.LockedOut) { $null } else { [bool]$ADUser.LockedOut })
        LastLogonDate        = $ADUser.LastLogonDate
        PasswordLastSet      = $ADUser.PasswordLastSet
        WhenCreated          = $ADUser.whenCreated
        MemberOfRaw          = $memberOf
        PrimaryGroupDn       = [string]$ADUser.PrimaryGroup
        TokenSids            = (New-Object System.Collections.Generic.List[string])
        Groups               = (New-Object System.Collections.Generic.List[object])
    }
    foreach ($name in (Get-ExtensionAttributeNames)) {
        $value = $ADUser.$name
        if ($null -eq $value) { $row[$name] = '' } else { $row[$name] = [string]$value }
    }
    return [PSCustomObject]$row
}

function Add-ResolvedDirectoryUser {
    param($Bucket, $ADUser, $ResolvedKeys, $SamKeys, $UpnKeys, $DnKeys)
    if ($null -eq $ADUser) { return }
    $sam = [string]$ADUser.SamAccountName
    if ([string]::IsNullOrWhiteSpace($sam)) { return }
    if (-not $Bucket.Seen.Add($sam)) { return }
    if ($SamKeys.Contains($sam)) { [void]$ResolvedKeys.Add($sam) }
    $upn = [string]$ADUser.UserPrincipalName
    if ($upn -and $UpnKeys.Contains($upn)) { [void]$ResolvedKeys.Add($upn) }
    $dn = [string]$ADUser.DistinguishedName
    if ($dn -and $DnKeys.Contains($dn)) { [void]$ResolvedKeys.Add($dn) }
    [void]$Bucket.Users.Add((New-DirectoryUser $ADUser))
}

function Invoke-IndividualLookup {
    param($Identity, [string]$Kind, [string]$Server, [string]$SearchBase)
    if ($Kind -eq 'Upn') {
        $filter = '(userPrincipalName=' + (ConvertTo-LdapFilterValue $Identity) + ')'
        $search = Invoke-AdUserSearch -Filter $filter -Server $Server -SearchBase $SearchBase
    } else {
        $search = Invoke-AdPropertyAttempts -Mode Identity -Identity $Identity -Server $Server
    }
    if ($search.Error) {
        $message = ''
        if ($search.Error.Exception) { $message = [string]$search.Error.Exception.Message }
        if ([string]::IsNullOrWhiteSpace($message)) { $message = [string]$search.Error }
        throw $message
    }
    return ,$search.Users
}

function Get-TokenSidList {
    param([string]$DistinguishedName, [string]$Server)
    try {
        $user = Get-ADUser -Identity $DistinguishedName -Server $Server -Properties tokenGroups -ErrorAction Stop
        return ConvertTo-SidList $user.tokenGroups
    } catch {
        return ,(New-Object System.Collections.Generic.List[string])
    }
}

function ConvertTo-GroupMeta {
    param($Group)
    $sid = ''
    if ($Group.SID -is [System.Security.Principal.SecurityIdentifier]) {
        $sid = $Group.SID.Value
    } elseif ($Group.SID) {
        $sid = [string]$Group.SID
    }
    [PSCustomObject]@{
        SamAccountName    = [string]$Group.SamAccountName
        Name              = [string]$Group.Name
        DistinguishedName = [string]$Group.DistinguishedName
        ObjectSid         = $sid
        GroupCategory     = [string]$Group.GroupCategory
        GroupScope        = [string]$Group.GroupScope
    }
}

function Get-GroupCatalog {
    param($DistinguishedNames, $Sids, [string]$Server)
    $metas = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    $dnValues = New-Object System.Collections.Generic.List[string]
    foreach ($dn in (Get-Collection $DistinguishedNames)) {
        $text = [string]$dn
        if ($text -and $seen.Add('DN:' + $text)) { [void]$dnValues.Add($text) }
    }
    $sidValues = New-Object System.Collections.Generic.List[string]
    foreach ($sid in (Get-Collection $Sids)) {
        $text = [string]$sid
        if ($text -and $seen.Add('SID:' + $text)) { [void]$sidValues.Add($text) }
    }

    $batches = @(
        @{ Attribute = 'distinguishedName'; Values = $dnValues },
        @{ Attribute = 'objectSid'; Values = $sidValues }
    )
    foreach ($batch in $batches) {
        $values = $batch.Values
        for ($offset = 0; $offset -lt $values.Count; $offset += 25) {
            if ($script:CancelRequested) { return ,$metas }
            $slice = New-Object System.Collections.Generic.List[string]
            $end = [Math]::Min($offset + 25, $values.Count)
            for ($i = $offset; $i -lt $end; $i++) { [void]$slice.Add($values[$i]) }
            $filter = New-OrEqualsFilter -Attribute $batch.Attribute -Values $slice
            if (-not $filter) { continue }
            try {
                $groups = @(Get-ADGroup -LDAPFilter $filter -Server $Server -Properties GroupCategory, GroupScope, SamAccountName, DistinguishedName -ErrorAction Stop)
                foreach ($group in $groups) { [void]$metas.Add((ConvertTo-GroupMeta $group)) }
            } catch {
                Write-Log ("Group lookup failed for a batch of {0} values: {1}" -f $slice.Count, $_.Exception.Message) 'WARN'
            }
        }
    }
    return ,$metas
}

function Resolve-ManagerNames {
    param($Users, [string]$Server, [string]$SearchBase)
    $dns = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($user in (Get-Collection $Users)) {
        $dn = [string]$user.Manager
        if ($dn -and $seen.Add($dn)) { [void]$dns.Add($dn) }
    }
    if ($dns.Count -eq 0) { return }

    $names = @{}
    for ($offset = 0; $offset -lt $dns.Count; $offset += 25) {
        if ($script:CancelRequested) { break }
        $slice = New-Object System.Collections.Generic.List[string]
        $end = [Math]::Min($offset + 25, $dns.Count)
        for ($i = $offset; $i -lt $end; $i++) { [void]$slice.Add($dns[$i]) }
        $filter = New-OrEqualsFilter -Attribute 'distinguishedName' -Values $slice
        try {
            $objects = @(Get-ADObject -LDAPFilter $filter -SearchBase $SearchBase -Server $Server -Properties displayName, name, sAMAccountName -ErrorAction Stop)
            foreach ($object in $objects) {
                $label = [string]$object.DisplayName
                if ([string]::IsNullOrWhiteSpace($label)) { $label = [string]$object.Name }
                if ($label) { $names[[string]$object.DistinguishedName] = $label }
            }
        } catch {
            Write-Log ("Manager name lookup failed: {0}" -f $_.Exception.Message) 'WARN'
        }
    }
    foreach ($user in (Get-Collection $Users)) {
        $dn = [string]$user.Manager
        if ($dn -and $names.ContainsKey($dn)) { $user.ManagerName = [string]$names[$dn] }
    }
}

function Invoke-DirectoryQuery {
    param([string[]]$Names, [bool]$IncludeTokenGroups)

    $users = New-Object System.Collections.Generic.List[object]
    $notFound = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $bucket = [PSCustomObject]@{ Users = $users; Seen = $seen }
    $resolved = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $samKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $upnKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $dnKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $sidKeys = New-Object System.Collections.Generic.List[string]
    $ordered = New-Object System.Collections.Generic.List[string]

    foreach ($name in (Get-Collection $Names)) {
        $text = [string]$name
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        [void]$ordered.Add($text)
        switch (Get-LookupKind $text) {
            'Upn' { [void]$upnKeys.Add($text) }
            'Dn' { [void]$dnKeys.Add($text) }
            'Sid' { [void]$sidKeys.Add($text) }
            default { [void]$samKeys.Add($text) }
        }
    }

    $work = @(
        @{ Kind = 'Sam'; Attribute = 'sAMAccountName'; Keys = @($samKeys) },
        @{ Kind = 'Upn'; Attribute = 'userPrincipalName'; Keys = @($upnKeys) },
        @{ Kind = 'Dn'; Attribute = 'distinguishedName'; Keys = @($dnKeys) }
    )

    $total = $ordered.Count
    if ($total -lt 1) { $total = 1 }
    $done = 0
    $loggedMode = $false

    foreach ($job in $work) {
        $keys = @($job.Keys)
        for ($offset = 0; $offset -lt $keys.Count; $offset += 25) {
            if ($script:CancelRequested) { break }
            $slice = New-Object System.Collections.Generic.List[string]
            $end = [Math]::Min($offset + 25, $keys.Count)
            for ($i = $offset; $i -lt $end; $i++) { [void]$slice.Add([string]$keys[$i]) }
            Set-Progress -Percent ([int](($done / $total) * 70)) -Status ("Reading accounts {0} of {1}" -f ([Math]::Min($done + $slice.Count, $total)), $ordered.Count)
            $filter = New-OrEqualsFilter -Attribute $job.Attribute -Values $slice
            $search = Invoke-AdUserSearch -Filter $filter -Server $script:TargetServer -SearchBase $script:DomainDn
            if (-not $loggedMode -and -not $search.Error) {
                Write-Log ("Query mode: extension attributes {0}; lockout and last logon {1}." -f $(if ($search.UsedExtension) { 'available' } else { 'not used' }), $(if ($search.UsedCalculated) { 'available' } else { 'not used' })) 'INFO'
                $loggedMode = $true
            }
            if ($search.Error) {
                Write-Log ("Batch lookup failed ({0}). Retrying those accounts one at a time. {1}" -f $job.Kind, $search.Error.Exception.Message) 'WARN'
                foreach ($identity in $slice) {
                    if ($script:CancelRequested) { break }
                    try {
                        $single = @(Invoke-IndividualLookup -Identity $identity -Kind $job.Kind -Server $script:TargetServer -SearchBase $script:DomainDn)
                        foreach ($adUser in $single) {
                            Add-ResolvedDirectoryUser -Bucket $bucket -ADUser $adUser -ResolvedKeys $resolved -SamKeys $samKeys -UpnKeys $upnKeys -DnKeys $dnKeys
                        }
                        if ($single.Count -eq 0) {
                            [void]$notFound.Add([PSCustomObject]@{ Name = $identity; Reason = 'Not found in Active Directory' })
                            [void]$resolved.Add($identity)
                        }
                    } catch {
                        $message = $_.Exception.Message
                        if (Test-NotFoundMessage $message) {
                            [void]$notFound.Add([PSCustomObject]@{ Name = $identity; Reason = 'Not found in Active Directory' })
                        } else {
                            [void]$notFound.Add([PSCustomObject]@{ Name = $identity; Reason = $message })
                            Write-Log ("Failed to read {0}: {1}" -f $identity, $message) 'ERROR'
                        }
                        [void]$resolved.Add($identity)
                    }
                }
            } else {
                foreach ($adUser in @($search.Users)) {
                    Add-ResolvedDirectoryUser -Bucket $bucket -ADUser $adUser -ResolvedKeys $resolved -SamKeys $samKeys -UpnKeys $upnKeys -DnKeys $dnKeys
                }
            }
            $done += $slice.Count
        }
    }

    foreach ($sid in $sidKeys) {
        if ($script:CancelRequested) { break }
        try {
            $single = @(Invoke-IndividualLookup -Identity $sid -Kind 'Sid' -Server $script:TargetServer -SearchBase $script:DomainDn)
            foreach ($adUser in $single) {
                Add-ResolvedDirectoryUser -Bucket $bucket -ADUser $adUser -ResolvedKeys $resolved -SamKeys $samKeys -UpnKeys $upnKeys -DnKeys $dnKeys
                [void]$resolved.Add($sid)
            }
            if ($single.Count -eq 0) {
                [void]$notFound.Add([PSCustomObject]@{ Name = $sid; Reason = 'Not found in Active Directory' })
                [void]$resolved.Add($sid)
            }
        } catch {
            $message = $_.Exception.Message
            $reason = $(if (Test-NotFoundMessage $message) { 'Not found in Active Directory' } else { $message })
            [void]$notFound.Add([PSCustomObject]@{ Name = $sid; Reason = $reason })
            [void]$resolved.Add($sid)
        }
    }

    if (-not $script:CancelRequested) {
        foreach ($name in $ordered) {
            if (-not $resolved.Contains($name)) {
                [void]$notFound.Add([PSCustomObject]@{ Name = $name; Reason = 'Not found in Active Directory' })
            }
        }
    }

    $tokenResolved = $false
    if ($IncludeTokenGroups -and -not $script:CancelRequested -and $users.Count -gt 0) {
        $tokenFailures = 0
        $index = 0
        foreach ($user in $users) {
            if ($script:CancelRequested) { break }
            $index++
            Set-Progress -Percent (70 + [int](($index / $users.Count) * 18)) -Status ("Reading logon tokens {0} of {1} (matches nested security groups)" -f $index, $users.Count)
            $sids = Get-TokenSidList -DistinguishedName $user.DistinguishedName -Server $script:TargetServer
            $sidItems = Get-Collection $sids
            if ($sidItems.Count -eq 0) { $tokenFailures++ }
            $user.TokenSids = $sidItems
        }
        if (-not $script:CancelRequested -and $tokenFailures -lt $users.Count) { $tokenResolved = $true }
        if ($tokenFailures -gt 0) {
            Write-Log ("tokenGroups was empty or unreadable for {0} of {1} account(s). Nested coverage may be incomplete." -f $tokenFailures, $users.Count) 'WARN'
        }
    } elseif (-not $IncludeTokenGroups) {
        Write-Log 'Nested security-group expansion is off. Group coverage is direct membership plus the primary group only.' 'WARN'
    }

    if ($users.Count -gt 0) {
        Set-Progress -Percent 90 -Status 'Resolving group names'
        $dnAll = New-Object System.Collections.Generic.List[string]
        $sidAll = New-Object System.Collections.Generic.List[string]
        foreach ($user in $users) {
            foreach ($dn in (Get-Collection $user.MemberOfRaw)) { [void]$dnAll.Add([string]$dn) }
            if ($user.PrimaryGroupDn) { [void]$dnAll.Add([string]$user.PrimaryGroupDn) }
            foreach ($sid in (Get-Collection $user.TokenSids)) { [void]$sidAll.Add([string]$sid) }
        }
        $catalog = Get-GroupCatalog -DistinguishedNames $dnAll -Sids $sidAll -Server $script:TargetServer
        $directory = New-GroupDirectory $catalog
        foreach ($user in $users) {
            $merged = Merge-UserGroups -MemberOf $user.MemberOfRaw -PrimaryGroupDn $user.PrimaryGroupDn -TokenSids $user.TokenSids -Directory $directory
            $user.Groups = $merged
        }
        Set-Progress -Percent 96 -Status 'Resolving manager names'
        Resolve-ManagerNames -Users $users -Server $script:TargetServer -SearchBase $script:DomainDn
    }

    [PSCustomObject]@{
        Users               = $users
        NotFound            = $notFound
        TokenGroupsResolved = [bool]$tokenResolved
        Cancelled           = [bool]$script:CancelRequested
    }
}

function Test-UserClass {
    param($Object)
    foreach ($className in (Get-Collection $Object.objectClass)) {
        if ([string]$className -eq 'user') { return $true }
    }
    foreach ($className in (Get-Collection $Object.ObjectClass)) {
        if ([string]$className -eq 'user') { return $true }
    }
    return $false
}

function Get-ReconciliationNames {
    $names = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($user in (Get-Collection $script:ADUserData)) {
        $sam = [string]$user.SamAccountName
        if ($sam -and $seen.Add($sam)) { [void]$names.Add($sam) }
    }
    foreach ($entry in (Get-Collection $script:NotFoundUsers)) {
        $sam = ConvertTo-SamAccountName ([string]$entry.Name)
        if ($sam -and $seen.Add($sam)) { [void]$names.Add($sam) }
    }
    return ,$names
}

function Invoke-GroupReconciliation {
    param([Parameter(Mandatory = $true)][string]$GroupIdentity, [bool]$Nested)

    $group = Get-ADGroup -Identity $GroupIdentity -Server $script:TargetServer -Properties primaryGroupToken, GroupCategory, GroupScope, DistinguishedName, SamAccountName -ErrorAction Stop
    $rid = $null
    if ($null -ne $group.primaryGroupToken -and "$($group.primaryGroupToken)" -match '^\d+$') {
        $rid = [int]$group.primaryGroupToken
    }
    $filter = New-GroupMembershipFilter -GroupDistinguishedName ([string]$group.DistinguishedName) -PrimaryGroupId $rid -Nested:$Nested
    Write-Log ("Group filter: {0}" -f $filter) 'INFO'
    Set-Progress -Percent 20 -Status ("Reading members of {0}" -f $group.SamAccountName)

    $objects = @(Get-ADObject -LDAPFilter $filter -SearchBase $script:DomainDn -Server $script:TargetServer -Properties objectClass, SamAccountName, Name -ErrorAction Stop)
    $members = New-Object System.Collections.Generic.List[string]
    $nonUsers = New-Object System.Collections.Generic.List[object]
    foreach ($object in $objects) {
        if (Test-UserClass $object) {
            $sam = [string]$object.SamAccountName
            if ($sam) { [void]$members.Add($sam) }
        } else {
            $className = ''
            $classes = Get-Collection $object.objectClass
            if ($classes.Count -gt 0) { $className = [string]$classes[$classes.Count - 1] }
            [void]$nonUsers.Add([PSCustomObject]@{ Name = [string]$object.Name; ObjectClass = $className })
        }
    }

    $tokenOnly = New-Object System.Collections.Generic.List[string]
    $groupSid = ''
    if ($group.SID -is [System.Security.Principal.SecurityIdentifier]) { $groupSid = $group.SID.Value }
    elseif ($group.SID) { $groupSid = [string]$group.SID }
    if ($groupSid -and $script:TokenGroupsResolved) {
        foreach ($user in (Get-Collection $script:ADUserData)) {
            foreach ($sid in (Get-Collection $user.TokenSids)) {
                if ([string]$sid -eq $groupSid) {
                    [void]$tokenOnly.Add([string]$user.SamAccountName)
                    break
                }
            }
        }
    }

    $result = Get-GroupReconciliation -CsvNames (Get-ReconciliationNames) -MemberNames $members -NonUserMembers $nonUsers -TokenOnlyNames $tokenOnly -GroupName ([string]$group.SamAccountName)
    $warning = ''
    if ([string]$group.GroupCategory -match 'Distribution') {
        $warning = 'This is a distribution group. Security Group item-level targeting will not match it.'
    }
    if (-not $script:TokenGroupsResolved) {
        $extra = 'Imported accounts were not checked against tokenGroups, so a parent security group that only matches through nesting can still look like a miss.'
        if ($warning) { $warning = $warning + ' ' + $extra } else { $warning = $extra }
    }
    $result | Add-Member -NotePropertyName Warning -NotePropertyValue $warning -Force
    $result | Add-Member -NotePropertyName GroupCategory -NotePropertyValue ([string]$group.GroupCategory) -Force
    $result | Add-Member -NotePropertyName GroupScope -NotePropertyValue ([string]$group.GroupScope) -Force
    $result | Add-Member -NotePropertyName DistinguishedName -NotePropertyValue ([string]$group.DistinguishedName) -Force
    $result | Add-Member -NotePropertyName Nested -NotePropertyValue ([bool]$Nested) -Force
    return $result
}

function Connect-TargetDomain {
    param([bool]$Quiet)
    $domainInput = ''
    $serverInput = ''
    if ($script:txtDomain) { $domainInput = $script:txtDomain.Text.Trim() }
    if ($script:txtServer) { $serverInput = $script:txtServer.Text.Trim() }

    try {
        if ($serverInput -and $domainInput) {
            $domain = Get-ADDomain -Identity $domainInput -Server $serverInput -ErrorAction Stop
        } elseif ($serverInput) {
            $domain = Get-ADDomain -Server $serverInput -ErrorAction Stop
        } elseif ($domainInput) {
            $domain = Get-ADDomain -Identity $domainInput -ErrorAction Stop
        } else {
            $domain = Get-ADDomain -ErrorAction Stop
        }
        $script:TargetDomain = [string]$domain.DNSRoot
        $script:DomainDn = [string]$domain.DistinguishedName
        $script:NetBiosName = [string]$domain.NetBIOSName
        if ($serverInput) { $script:TargetServer = $serverInput } else { $script:TargetServer = [string]$domain.PDCEmulator }
        if ($script:lblDomainStatus) {
            $script:lblDomainStatus.Text = 'Domain: ' + $script:TargetDomain
            $script:lblDomainStatus.ForeColor = [System.Drawing.Color]::FromArgb(170, 235, 190)
        }
        if ($script:lblServerStatus) {
            $script:lblServerStatus.Text = 'DC: ' + $script:TargetServer
            $script:lblServerStatus.ForeColor = [System.Drawing.Color]::FromArgb(170, 235, 190)
        }
        Write-Log ("Connected to {0} ({1}) via {2}." -f $script:TargetDomain, $script:NetBiosName, $script:TargetServer) 'SUCCESS'
        return $true
    } catch {
        if ($script:lblDomainStatus) {
            $script:lblDomainStatus.Text = 'Domain: not connected'
            $script:lblDomainStatus.ForeColor = [System.Drawing.Color]::FromArgb(255, 170, 160)
        }
        if ($script:lblServerStatus) {
            $script:lblServerStatus.Text = 'DC: unavailable'
            $script:lblServerStatus.ForeColor = [System.Drawing.Color]::FromArgb(255, 170, 160)
        }
        Write-Log ("Domain connection failed: {0}" -f $_.Exception.Message) 'ERROR'
        if (-not $Quiet) {
            [System.Windows.Forms.MessageBox]::Show(
                "Could not connect to Active Directory.`r`n`r`n$($_.Exception.Message)",
                'Domain connection failed',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
        return $false
    }
}

function Initialize-ResultGrid {
    param($Grid)
    $Grid.Dock = 'Fill'
    $Grid.ReadOnly = $true
    $Grid.AllowUserToAddRows = $false
    $Grid.AllowUserToDeleteRows = $false
    $Grid.AllowUserToResizeRows = $false
    $Grid.MultiSelect = $true
    $Grid.SelectionMode = 'FullRowSelect'
    $Grid.RowHeadersVisible = $false
    $Grid.BackgroundColor = [System.Drawing.Color]::White
    $Grid.BorderStyle = 'None'
    $Grid.AutoSizeColumnsMode = 'Fill'
    $Grid.ClipboardCopyMode = 'EnableAlwaysIncludeHeaderText'
    $Grid.EnableHeadersVisualStyles = $false
    $Grid.ColumnHeadersDefaultCellStyle.BackColor = $script:ColorHeader
    $Grid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $Grid.ColumnHeadersDefaultCellStyle.Font = $script:FontUiBold
    $Grid.ColumnHeadersHeight = 28
    $Grid.DefaultCellStyle.Font = $script:FontUi
    $Grid.DefaultCellStyle.SelectionBackColor = $script:ColorBlue
    $Grid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $Grid.AlternatingRowsDefaultCellStyle.BackColor = $script:ColorBg
    $Grid.RowTemplate.Height = 24
    $Grid.AutoGenerateColumns = $false
}

function Add-GridTextColumn {
    param($Grid, [string]$Name, [string]$Header, [int]$Fill, [switch]$Numeric)
    $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $col.Name = $Name
    $col.HeaderText = $Header
    $col.FillWeight = $Fill
    $col.MinimumWidth = 45
    $col.SortMode = 'Automatic'
    if ($Numeric) { $col.ValueType = [double] }
    [void]$Grid.Columns.Add($col)
}

function Set-RowColor {
    param($Row, [System.Drawing.Color]$Color)
    $Row.DefaultCellStyle.BackColor = $Color
}

function Format-GroupSummary {
    param($User)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($group in (Get-Collection $User.Groups)) {
        $normalized = Get-NormalizedGroup $group
        if ($null -eq $normalized) { continue }
        $label = [string]$normalized.SamAccountName
        if (-not $label) { $label = [string]$normalized.Name }
        if ($label) { [void]$names.Add($label) }
    }
    if ($names.Count -le 6) { return ($names -join '; ') }
    $head = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt 6; $i++) { [void]$head.Add($names[$i]) }
    return (($head -join '; ') + ' (+' + ($names.Count - 6) + ')')
}

function Update-CountLabel {
    $resolved = 0
    if ($script:ADUserData) { $resolved = $script:ADUserData.Count }
    $missing = 0
    if ($script:NotFoundUsers) { $missing = $script:NotFoundUsers.Count }
    if ($script:lblCounts) { $script:lblCounts.Text = ('Resolved {0}    Not found {1}' -f $resolved, $missing) }
}

function Update-UserGrid {
    if (-not $script:gridUsers) { return }
    $filter = ''
    if ($script:txtUserFilter) { $filter = $script:txtUserFilter.Text.Trim() }
    $grid = $script:gridUsers
    $grid.SuspendLayout()
    $grid.Rows.Clear()
    $shown = 0
    foreach ($user in (Get-Collection $script:ADUserData)) {
        if ($filter) {
            $hay = ((@(
                        $user.SamAccountName, $user.Name, $user.DisplayName, $user.Department, $user.Title,
                        $user.Office, $user.Company, $user.City, $user.State, $user.ParentOU, $user.EmailAddress, $user.EmployeeType
                    ) | Where-Object { $_ }) -join ' ')
            # The two-argument IndexOf binds to (string, int) on Windows PowerShell 5.1.
            if ($hay.IndexOf($filter, 0, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        }
        $index = $grid.Rows.Add(
            [string]$user.SamAccountName,
            [string]$user.Name,
            (Format-YesNo $user.Enabled),
            [string]$user.Department,
            [string]$user.Title,
            [string]$user.Office,
            [string]$user.City,
            [string]$user.State,
            [string]$user.ParentOU,
            (Format-GroupSummary $user),
            [string]$user.HomeDirectory,
            (Format-YesNo $user.LockedOut),
            (Format-UiDate $user.LastLogonDate)
        )
        $row = $grid.Rows[$index]
        $row.Tag = $user
        if ($user.Enabled -eq $false) { Set-RowColor $row $script:ColorBad }
        elseif ($user.LockedOut -eq $true) { Set-RowColor $row $script:ColorWarn }
        $shown++
    }
    $grid.ResumeLayout()
    if ($script:lblUserFilter) {
        $script:lblUserFilter.Text = ('Showing {0} of {1}' -f $shown, $script:ADUserData.Count)
    }
    Update-CountLabel
}

function Update-NotFoundGrid {
    if (-not $script:gridMissing) { return }
    $script:gridMissing.Rows.Clear()
    foreach ($entry in (Get-Collection $script:NotFoundUsers)) {
        [void]$script:gridMissing.Rows.Add([string]$entry.Name, [string]$entry.Reason)
    }
    if ($script:tabMissing) { $script:tabMissing.Text = ('Not Found ({0})' -f $script:NotFoundUsers.Count) }
    Update-CountLabel
}

function Get-SelectedRecommendation {
    if (-not $script:gridRec -or $script:gridRec.SelectedRows.Count -eq 0) { return $null }
    return $script:gridRec.SelectedRows[0].Tag
}

function Update-RecommendationDetails {
    $rec = Get-SelectedRecommendation
    if (-not $script:txtRecNotes) { return }
    if ($null -eq $rec) { $script:txtRecNotes.Text = ''; return }
    $script:txtRecNotes.Text = ([string]$rec.Notes).Trim() + "`r`n`r`n" + ([string]$rec.Steps).Trim()
}

function Update-AnalysisView {
    if (-not $script:LastAnalysis -or -not $script:gridRec) { return }
    $analysis = $script:LastAnalysis
    $hidePoor = $false
    if ($script:chkHidePoor) { $hidePoor = [bool]$script:chkHidePoor.Checked }

    $script:gridRec.Rows.Clear()
    $hidden = 0
    $best = $null
    foreach ($rec in (Get-Collection $analysis.Recommendations)) {
        if ($hidePoor -and [string]$rec.Quality -eq 'Poor') { $hidden++; continue }
        if ($null -eq $best -and [string]$rec.Quality -eq 'Recommended') { $best = $rec }
        $index = $script:gridRec.Rows.Add(
            [string]$rec.Quality,
            [double]$rec.Coverage,
            [string]$rec.IltItem,
            [string]$rec.Target,
            [string]$rec.Filter,
            [string]$rec.Binding
        )
        $row = $script:gridRec.Rows[$index]
        $row.Tag = $rec
        if ($rec.Quality -eq 'Recommended') { Set-RowColor $row $script:ColorGood }
        elseif ($rec.Quality -eq 'Possible') { Set-RowColor $row $script:ColorWarn }
        else { Set-RowColor $row $script:ColorBad }
    }
    if ($script:gridRec.Rows.Count -gt 0) { $script:gridRec.Rows[0].Selected = $true }
    Update-RecommendationDetails

    if ($script:lblBest) {
        if ($best) {
            $script:lblBest.Text = 'Best ILT rule: ' + $best.IltItem + ' - ' + $best.Target
        } elseif ($hidden -gt 0 -and $script:gridRec.Rows.Count -eq 0) {
            $script:lblBest.Text = 'Only built-in or unusable groups cover this list. Uncheck the hide option to review them.'
        } else {
            $script:lblBest.Text = 'No single rule covers every user. The closest matches are listed below.'
        }
    }
    if ($script:lblHidden) {
        $script:lblHidden.Text = $(if ($hidden -gt 0) { "$hidden built-in, privileged, or distribution group row(s) hidden." } else { '' })
    }

    if ($script:gridAttr) {
        $script:gridAttr.Rows.Clear()
        foreach ($rowData in (Get-Collection $analysis.Scalar)) {
            $index = $script:gridAttr.Rows.Add(
                [string]$rowData.Attribute,
                [string]$rowData.LdapAttribute,
                [string]$rowData.TopValue,
                [int]$rowData.UsersMatching,
                [int]$rowData.UsersBlank,
                [int]$rowData.TotalUsers,
                [double]$rowData.PercentMatching,
                [int]$rowData.DistinctValues,
                (Format-YesNo $rowData.FullyCommon),
                [string]$rowData.LdapFilter
            )
            if ($rowData.FullyCommon) { Set-RowColor $script:gridAttr.Rows[$index] $script:ColorGood }
            elseif ([double]$rowData.PercentMatching -ge 80) { Set-RowColor $script:gridAttr.Rows[$index] $script:ColorWarn }
        }
    }
    if ($script:gridGroups) {
        $script:gridGroups.Rows.Clear()
        foreach ($rowData in (Get-Collection $analysis.Groups)) {
            $index = $script:gridGroups.Rows.Add(
                [string]$rowData.GroupName,
                [string]$rowData.SamAccountName,
                [string]$rowData.GroupCategory,
                [string]$rowData.GroupScope,
                [int]$rowData.UsersInGroup,
                [int]$rowData.TotalUsers,
                [double]$rowData.PercentCoverage,
                (Format-YesNo $rowData.FullyCommon),
                (Format-YesNo $rowData.IsBroad),
                (Format-YesNo $rowData.IltEligible),
                [string]$rowData.UsersMissing
            )
            if ($rowData.IsBroad -or $rowData.IsPrivileged -or -not $rowData.IltEligible) { Set-RowColor $script:gridGroups.Rows[$index] $script:ColorBad }
            elseif ($rowData.FullyCommon) { Set-RowColor $script:gridGroups.Rows[$index] $script:ColorGood }
            elseif ([double]$rowData.PercentCoverage -ge 80) { Set-RowColor $script:gridGroups.Rows[$index] $script:ColorWarn }
        }
    }
    if ($script:gridOu -and $analysis.OU) {
        $script:gridOu.Rows.Clear()
        foreach ($rowData in (Get-Collection $analysis.OU.ParentOUs)) {
            [void]$script:gridOu.Rows.Add([string]$rowData.ParentOU, [int]$rowData.UserCount, [double]$rowData.PercentOfTotal)
        }
        if ($script:lblAncestor) {
            $ancestor = [string]$analysis.OU.CommonAncestor
            if ([string]::IsNullOrWhiteSpace($ancestor)) { $ancestor = '(none)' }
            $suffix = ''
            if ($analysis.OU.CommonAncestorIsDomainRoot) { $suffix = '  - domain root, too broad to target' }
            $script:lblAncestor.Text = 'Common ancestor OU: ' + $ancestor + $suffix
        }
    }
    if ($script:gridHealth) {
        $script:gridHealth.Rows.Clear()
        foreach ($rowData in (Get-Collection $analysis.Health)) {
            $index = $script:gridHealth.Rows.Add([string]$rowData.Issue, [int]$rowData.Count, [string]$rowData.Accounts)
            if ([int]$rowData.Count -gt 0 -and [string]$rowData.Issue -match 'Disabled|Locked|expired') {
                Set-RowColor $script:gridHealth.Rows[$index] $script:ColorBad
            } elseif ([int]$rowData.Count -gt 0) {
                Set-RowColor $script:gridHealth.Rows[$index] $script:ColorWarn
            }
        }
    }
    if ($script:gridPaths) {
        $script:gridPaths.Rows.Clear()
        foreach ($rowData in (Get-Collection $analysis.Paths)) {
            [void]$script:gridPaths.Rows.Add([string]$rowData.Attribute, [string]$rowData.SharedPrefix, [int]$rowData.Populated, [int]$rowData.TotalUsers, [string]$rowData.Note)
        }
    }
}

function Update-ReconcileGrid {
    if (-not $script:gridReconcile) { return }
    $script:gridReconcile.Rows.Clear()
    if (-not $script:LastGroupCheck) {
        if ($script:lblReconcile) { $script:lblReconcile.Text = 'Choose a group and click Compare.' }
        return
    }
    $want = 'All'
    if ($script:cmbStatus -and $script:cmbStatus.SelectedItem) { $want = [string]$script:cmbStatus.SelectedItem }
    $shown = 0
    foreach ($rowData in (Get-Collection $script:LastGroupCheck.Rows)) {
        if ($want -ne 'All' -and [string]$rowData.Status -ne $want) { continue }
        if ($shown -ge 5000) { break }
        $index = $script:gridReconcile.Rows.Add([string]$rowData.SamAccountName, [string]$rowData.Status, [string]$rowData.Notes)
        $row = $script:gridReconcile.Rows[$index]
        switch ([string]$rowData.Status) {
            'Matched' { Set-RowColor $row $script:ColorGood }
            'Matched (logon token only)' { Set-RowColor $row $script:ColorInfo }
            'Missing from group' { Set-RowColor $row $script:ColorBad }
            'Extra in group' { Set-RowColor $row $script:ColorWarn }
            default { }
        }
        $shown++
    }
    $check = $script:LastGroupCheck
    $text = '{0} ({1}, {2}{3}): matched {4}, token-only {5}, missing {6}, extra {7}, non-user {8}.' -f `
        $check.GroupName, $check.GroupCategory, $(if ($check.Nested) { 'nested' } else { 'direct' }), `
        $(if ($check.GroupScope) { ', ' + $check.GroupScope } else { '' }), `
        $check.Matched, $check.TokenMatched, $check.Missing, $check.Extra, $check.NonUser
    if ($check.Rows.Count -gt 5000) { $text += ' Showing the first 5000 rows. Export the report for the full list.' }
    if ($check.Warning) { $text += ' ' + $check.Warning }
    if ($script:lblReconcile) { $script:lblReconcile.Text = $text }
}

function Show-ColumnChooser {
    param($Columns)
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'Choose the SamAccountName column'
    $dialog.StartPosition = 'CenterParent'
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.MinimizeBox = $false
    $dialog.MaximizeBox = $false
    $dialog.ClientSize = New-Object System.Drawing.Size(420, 140)
    $dialog.Font = $script:FontUi
    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Which column contains the account name?'
    $label.Location = New-Object System.Drawing.Point(12, 12)
    $label.Size = New-Object System.Drawing.Size(390, 20)
    $combo = New-Object System.Windows.Forms.ComboBox
    $combo.DropDownStyle = 'DropDownList'
    $combo.Location = New-Object System.Drawing.Point(12, 40)
    $combo.Size = New-Object System.Drawing.Size(390, 24)
    foreach ($column in (Get-Collection $Columns)) { [void]$combo.Items.Add([string]$column) }
    if ($combo.Items.Count -gt 0) { $combo.SelectedIndex = 0 }
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Use column'
    $ok.DialogResult = 'OK'
    $ok.Location = New-Object System.Drawing.Point(226, 90)
    $ok.Size = New-Object System.Drawing.Size(90, 28)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.DialogResult = 'Cancel'
    $cancel.Location = New-Object System.Drawing.Point(322, 90)
    $cancel.Size = New-Object System.Drawing.Size(80, 28)
    $dialog.Controls.AddRange(@($label, $combo, $ok, $cancel))
    $dialog.AcceptButton = $ok
    $dialog.CancelButton = $cancel
    $answer = $dialog.ShowDialog($script:MainForm)
    $chosen = $null
    if ($answer -eq 'OK' -and $combo.SelectedItem) { $chosen = [string]$combo.SelectedItem }
    $dialog.Dispose()
    return $chosen
}

function Show-GroupSearch {
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'Find an Active Directory group'
    $dialog.StartPosition = 'CenterParent'
    $dialog.ClientSize = New-Object System.Drawing.Size(760, 480)
    $dialog.Font = $script:FontUi
    $dialog.MinimizeBox = $false
    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Location = New-Object System.Drawing.Point(12, 12)
    $txt.Size = New-Object System.Drawing.Size(520, 24)
    $search = New-Object System.Windows.Forms.Button
    $search.Text = 'Search'
    $search.Location = New-Object System.Drawing.Point(540, 10)
    $search.Size = New-Object System.Drawing.Size(90, 28)
    $search.FlatStyle = 'Flat'
    $search.BackColor = $script:ColorBlue
    $search.ForeColor = [System.Drawing.Color]::White
    $grid = New-Object System.Windows.Forms.DataGridView
    Initialize-ResultGrid $grid
    $grid.Dock = 'None'
    $grid.Location = New-Object System.Drawing.Point(12, 48)
    $grid.Size = New-Object System.Drawing.Size(736, 370)
    $grid.Anchor = 'Top,Bottom,Left,Right'
    Add-GridTextColumn $grid 'Name' 'Name' 30
    Add-GridTextColumn $grid 'Sam' 'sAMAccountName' 25
    Add-GridTextColumn $grid 'Category' 'Category' 15
    Add-GridTextColumn $grid 'Scope' 'Scope' 15
    Add-GridTextColumn $grid 'Dn' 'Distinguished name' 40
    $use = New-Object System.Windows.Forms.Button
    $use.Text = 'Use group'
    $use.Location = New-Object System.Drawing.Point(548, 432)
    $use.Size = New-Object System.Drawing.Size(90, 30)
    $use.Anchor = 'Bottom,Right'
    $close = New-Object System.Windows.Forms.Button
    $close.Text = 'Cancel'
    $close.DialogResult = 'Cancel'
    $close.Location = New-Object System.Drawing.Point(646, 432)
    $close.Size = New-Object System.Drawing.Size(90, 30)
    $close.Anchor = 'Bottom,Right'
    $dialog.Controls.AddRange(@($txt, $search, $grid, $use, $close))
    $dialog.CancelButton = $close
    $script:PickedGroup = $null

    $runSearch = {
        if (-not $script:TargetServer) { return }
        $term = $script:GroupSearchText.Text.Trim()
        if ($term.Length -lt 2) {
            [System.Windows.Forms.MessageBox]::Show('Enter at least two characters.', 'Group search')
            return
        }
        $script:GroupSearchGrid.Rows.Clear()
        try {
            $escaped = ConvertTo-LdapFilterValue $term
            $filter = '(|(name=*' + $escaped + '*)(sAMAccountName=*' + $escaped + '*))'
            $groups = @(Get-ADGroup -LDAPFilter $filter -Server $script:TargetServer -ResultSetSize 200 -Properties GroupCategory, GroupScope, SamAccountName, DistinguishedName -ErrorAction Stop)
            foreach ($group in $groups) {
                $index = $script:GroupSearchGrid.Rows.Add([string]$group.Name, [string]$group.SamAccountName, [string]$group.GroupCategory, [string]$group.GroupScope, [string]$group.DistinguishedName)
                $script:GroupSearchGrid.Rows[$index].Tag = [string]$group.SamAccountName
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Group search')
        }
    }
    $script:GroupSearchText = $txt
    $script:GroupSearchGrid = $grid
    $script:GroupSearchDialog = $dialog
    $script:GroupSearchAction = $runSearch
    $search.Add_Click({ $script:GroupSearchAction.Invoke() })
    $txt.Add_KeyDown({
            if ($_.KeyCode -eq 'Enter') {
                $script:GroupSearchAction.Invoke()
                $_.SuppressKeyPress = $true
            }
        })
    $use.Add_Click({
            if ($script:GroupSearchGrid.SelectedRows.Count -eq 0) { return }
            $script:PickedGroup = [string]$script:GroupSearchGrid.SelectedRows[0].Tag
            $script:GroupSearchDialog.DialogResult = 'OK'
            $script:GroupSearchDialog.Close()
        })
    $grid.Add_CellDoubleClick({
            if ($_.RowIndex -lt 0) { return }
            $script:PickedGroup = [string]$script:GroupSearchGrid.Rows[$_.RowIndex].Tag
            $script:GroupSearchDialog.DialogResult = 'OK'
            $script:GroupSearchDialog.Close()
        })
    [void]$dialog.ShowDialog($script:MainForm)
    $picked = $script:PickedGroup
    $dialog.Dispose()
    return $picked
}

function Show-UserDetail {
    param($User)
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'Account detail - ' + [string]$User.SamAccountName
    $dialog.StartPosition = 'CenterParent'
    $dialog.ClientSize = New-Object System.Drawing.Size(860, 640)
    $dialog.Font = $script:FontUi
    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = 'Fill'
    $tabAttr = New-Object System.Windows.Forms.TabPage
    $tabAttr.Text = 'Attributes'
    $tabGroups = New-Object System.Windows.Forms.TabPage
    $tabGroups.Text = 'Groups'
    $gridAttr = New-Object System.Windows.Forms.DataGridView
    $gridGroups = New-Object System.Windows.Forms.DataGridView
    Initialize-ResultGrid $gridAttr
    Initialize-ResultGrid $gridGroups
    Add-GridTextColumn $gridAttr 'Property' 'Property' 30
    Add-GridTextColumn $gridAttr 'Value' 'Value' 70
    Add-GridTextColumn $gridGroups 'Name' 'Name' 25
    Add-GridTextColumn $gridGroups 'Sam' 'sAMAccountName' 20
    Add-GridTextColumn $gridGroups 'Category' 'Category' 15
    Add-GridTextColumn $gridGroups 'Scope' 'Scope' 12
    Add-GridTextColumn $gridGroups 'Via' 'Via' 12
    Add-GridTextColumn $gridGroups 'Dn' 'Distinguished name' 40
    $tabAttr.Controls.Add($gridAttr)
    $tabGroups.Controls.Add($gridGroups)
    [void]$tabs.TabPages.Add($tabAttr)
    [void]$tabs.TabPages.Add($tabGroups)
    $dialog.Controls.Add($tabs)

    $fields = @(
        'SamAccountName', 'Name', 'DisplayName', 'GivenName', 'Surname', 'Enabled', 'EmailAddress', 'UserPrincipalName',
        'Department', 'Division', 'Title', 'Company', 'Office', 'City', 'State', 'Country', 'CountryName',
        'StreetAddress', 'PostalCode', 'EmployeeID', 'EmployeeNumber', 'EmployeeType', 'Manager', 'ManagerName',
        'HomeDirectory', 'HomeDrive', 'ProfilePath', 'ScriptPath', 'Description', 'ParentOU', 'DistinguishedName',
        'CanonicalName', 'LockedOut', 'PasswordExpired', 'PasswordNeverExpires', 'LastLogonDate', 'PasswordLastSet', 'WhenCreated'
    )
    foreach ($field in $fields) {
        $value = $User.$field
        if ($value -is [datetime]) { $value = Format-UiDate $value }
        elseif ($value -is [bool]) { $value = Format-YesNo $value }
        [void]$gridAttr.Rows.Add($field, [string]$value)
    }
    foreach ($name in (Get-ExtensionAttributeNames)) {
        $value = [string]$User.$name
        if (-not [string]::IsNullOrWhiteSpace($value)) { [void]$gridAttr.Rows.Add($name, $value) }
    }
    foreach ($group in (Get-Collection $User.Groups)) {
        $normalized = Get-NormalizedGroup $group
        if ($null -eq $normalized) { continue }
        $via = 'Direct'
        if ($normalized.IsPrimary -and -not $normalized.IsDirect) { $via = 'Primary' }
        elseif ($normalized.InToken -and -not $normalized.IsDirect) { $via = 'Nested' }
        [void]$gridGroups.Rows.Add(
            [string]$normalized.Name,
            [string]$normalized.SamAccountName,
            [string]$normalized.GroupCategory,
            [string]$normalized.GroupScope,
            $via,
            [string]$normalized.DistinguishedName
        )
    }
    [void]$dialog.ShowDialog($script:MainForm)
    $dialog.Dispose()
}

function Show-About {
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'About AD User ILT Analysis'
    $dialog.StartPosition = 'CenterParent'
    $dialog.ClientSize = New-Object System.Drawing.Size(640, 520)
    $dialog.Font = $script:FontUi
    $dialog.MinimizeBox = $false
    $text = New-Object System.Windows.Forms.TextBox
    $text.Multiline = $true
    $text.ReadOnly = $true
    $text.ScrollBars = 'Vertical'
    $text.Dock = 'Fill'
    $text.Text = @"
AD User ILT Analysis $script:AppVersion

Compares a list of Active Directory users and recommends the cleanest Group Policy drive-map Item-level targeting rule: a security group, an organizational unit, or an LDAP query.

Item-level targeting has no generic user-property condition. An LDAP filter such as (department=Sales) matches everyone as soon as any user in the search base has that department. The filters this tool builds include (sAMAccountName=%USERNAME%) so they describe the user who is logging on.

What changed from the console script
- One-item results are no longer counted or enumerated as characters. A user in a single group used to produce fake groups named C, N, and so on.
- Header-less CSVs keep the first account. UTF-8 files and DOMAIN\user values are handled.
- Distinguished names with escaped commas split correctly.
- The primary group is included. Get-ADGroupMember drops primary-group members and can abort the whole compare when one member is unreadable. Membership is an LDAP query plus primaryGroupID.
- Group recommendations use sAMAccountName. Domain Users and distribution groups are not offered as the drive-map filter.
- Office is no longer scored twice (it is the same attribute as physicalDeliveryOfficeName).
- extensionAttribute1-15 are skipped automatically when the schema does not have them.
- HTML reports encode directory values.

Requirements: Windows PowerShell 5.1, RSAT Active Directory module, and read access to the accounts.
"@
    $dialog.Controls.Add($text)
    [void]$dialog.ShowDialog($script:MainForm)
    $dialog.Dispose()
}

function Set-ClipboardText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    try {
        [System.Windows.Forms.Clipboard]::SetText($Text)
        return $true
    } catch {
        Write-Log ("Clipboard copy failed: {0}" -f $_.Exception.Message) 'WARN'
        return $false
    }
}

function Get-RequestedImport {
    $result = Import-SamAccountNamesFromText -Text $script:txtNames.Text -SourceName 'the account list'
    if ($result.Mode -eq 'NeedsColumn') {
        $choice = Show-ColumnChooser -Columns $result.Columns
        if (-not $choice) { return $null }
        $result = Select-SamNamesFromColumn -Text $script:txtNames.Text -ColumnName $choice
    }
    return $result
}

function Import-AccountFile {
    param([string]$Path)
    try {
        $imported = Import-SamAccountNamesFromFile -Path $Path
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Could not read the file', 'OK', 'Error')
        return
    }
    if ($imported.Mode -eq 'NeedsColumn') {
        $choice = Show-ColumnChooser -Columns $imported.Columns
        if (-not $choice) { return }
        $file = Read-TextFile -Path $Path
        $imported = Select-SamNamesFromColumn -Text $file.Text -ColumnName $choice
    }
    if ($imported.Names.Count -eq 0) {
        $message = $(if ($imported.Warning) { $imported.Warning } else { 'No account names were found in that file.' })
        [System.Windows.Forms.MessageBox]::Show($message, 'Nothing to import', 'OK', 'Warning')
        return
    }

    $append = $false
    if ($script:txtNames.Text.Trim().Length -gt 0) {
        $answer = [System.Windows.Forms.MessageBox]::Show(
            "The list already has names.`r`n`r`nYes replaces the list.`r`nNo appends the new names.`r`nCancel leaves the list unchanged.",
            'Import accounts',
            [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($answer -eq 'Cancel') { return }
        $append = ($answer -eq 'No')
    }

    $bag = New-NameBag
    if ($append) {
        $current = Import-SamAccountNamesFromText -Text $script:txtNames.Text -SourceName 'current list'
        if ($current.Mode -eq 'NeedsColumn') {
            foreach ($line in ($script:txtNames.Text -split '\r\n|\n')) { Add-SamName -Bag $bag -Value $line }
        } else {
            foreach ($name in (Get-Collection $current.Names)) { Add-SamName -Bag $bag -Value $name }
        }
    }
    foreach ($name in (Get-Collection $imported.Names)) { Add-SamName -Bag $bag -Value $name }
    $script:txtNames.Text = ($bag.Names -join "`r`n")
    Write-Log ("Imported {0} unique name(s) from {1} (column: {2}, duplicates skipped: {3})." -f $imported.Names.Count, $Path, $(if ($imported.Column) { $imported.Column } else { $imported.Mode }), $imported.DuplicateCount) 'SUCCESS'
    if ($imported.Warning) {
        Write-Log $imported.Warning 'WARN'
        [System.Windows.Forms.MessageBox]::Show($imported.Warning, 'Import warning', 'OK', 'Warning')
    }
}

function Import-CsvInteractive {
    if ($script:OperationRunning) { return }
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = 'Account lists (*.csv;*.txt)|*.csv;*.txt|All files (*.*)|*.*'
    $dialog.Title = 'Import account names'
    if ($dialog.ShowDialog($script:MainForm) -ne 'OK') { return }
    Import-AccountFile -Path $dialog.FileName
}

function Clear-Session {
    if ($script:OperationRunning) { return }
    $script:txtNames.Text = ''
    $script:ADUserData = New-Object System.Collections.Generic.List[object]
    $script:NotFoundUsers = New-Object System.Collections.Generic.List[object]
    $script:LastAnalysis = $null
    $script:LastGroupCheck = $null
    $script:TokenGroupsResolved = $false
    Update-UserGrid
    Update-NotFoundGrid
    if ($script:gridRec) { $script:gridRec.Rows.Clear() }
    if ($script:gridAttr) { $script:gridAttr.Rows.Clear() }
    if ($script:gridGroups) { $script:gridGroups.Rows.Clear() }
    if ($script:gridOu) { $script:gridOu.Rows.Clear() }
    if ($script:gridHealth) { $script:gridHealth.Rows.Clear() }
    if ($script:gridPaths) { $script:gridPaths.Rows.Clear() }
    if ($script:gridReconcile) { $script:gridReconcile.Rows.Clear() }
    if ($script:lblBest) { $script:lblBest.Text = 'Import accounts and query Active Directory to build ILT recommendations.' }
    if ($script:lblReconcile) { $script:lblReconcile.Text = 'Choose a group and click Compare.' }
    if ($script:txtRecNotes) { $script:txtRecNotes.Text = '' }
    Set-Progress -Percent 0 -Status 'Cleared.'
    Write-Log 'Cleared the current list and results.' 'INFO'
}

function Start-Analysis {
    if ($script:ADUserData.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Query Active Directory before running the analysis.', 'Nothing to analyze', 'OK', 'Information')
        return
    }
    $min = 50.0
    if ($script:numMin) { $min = [double]$script:numMin.Value }
    $script:LastAnalysis = Get-FullAnalysis -Users $script:ADUserData -MinPercent $min -DomainDn $script:DomainDn -NetBiosName $script:NetBiosName -TokenGroupsResolved:([bool]$script:TokenGroupsResolved)
    Update-AnalysisView
    if ($script:tabMain) { $script:tabMain.SelectedTab = $script:tabAnalysis }
    $recommended = 0
    foreach ($rec in (Get-Collection $script:LastAnalysis.Recommendations)) {
        if ([string]$rec.Quality -eq 'Recommended') { $recommended++ }
    }
    Write-Log ("Analysis complete for {0} user(s). {1} recommended ILT rule(s)." -f $script:ADUserData.Count, $recommended) 'SUCCESS'
    Set-Progress -Percent 100 -Status ("Analysis complete. {0} recommended rule(s)." -f $recommended)
}

function Start-DirectoryQuery {
    if ($script:OperationRunning) { return }
    if (-not $script:TargetServer -or -not $script:DomainDn) {
        if (-not (Connect-TargetDomain -Quiet $false)) { return }
    }
    $imported = Get-RequestedImport
    if ($null -eq $imported) { return }
    if ($imported.Names.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Enter or import at least one account name.', 'No accounts', 'OK', 'Information')
        return
    }
    if ($imported.Warning) { Write-Log $imported.Warning 'WARN' }

    $script:CancelRequested = $false
    Set-Busy $true
    try {
        Write-Log ("Querying {0} unique name(s)." -f $imported.Names.Count) 'INFO'
        $includeTokens = $true
        if ($script:chkTokens) { $includeTokens = [bool]$script:chkTokens.Checked }
        $result = Invoke-DirectoryQuery -Names $imported.Names -IncludeTokenGroups $includeTokens
        $script:ADUserData = $result.Users
        $script:NotFoundUsers = $result.NotFound
        $script:TokenGroupsResolved = [bool]$result.TokenGroupsResolved
        $script:LastAnalysis = $null
        $script:LastGroupCheck = $null
        Update-UserGrid
        Update-NotFoundGrid
        if ($result.Cancelled) {
            Write-Log ("Query cancelled. Retrieved {0} account(s)." -f $result.Users.Count) 'WARN'
            Set-Progress -Percent 0 -Status 'Query cancelled.'
        } else {
            Write-Log ("Resolved {0} account(s). Not found or failed: {1}." -f $result.Users.Count, $result.NotFound.Count) $(if ($result.NotFound.Count -gt 0) { 'WARN' } else { 'SUCCESS' })
            if ($result.Users.Count -gt 0) {
                Start-Analysis
            } else {
                if ($script:tabMain) { $script:tabMain.SelectedTab = $script:tabMissing }
                Set-Progress -Percent 100 -Status 'No accounts were found in Active Directory.'
            }
        }
    } catch {
        Write-Log ("Query failed: {0}" -f $_.Exception.Message) 'ERROR'
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Query failed', 'OK', 'Error')
    } finally {
        Set-Busy $false
        if ($script:CloseAfterOperation -and $script:MainForm) { $script:MainForm.Close() }
    }
}

function Start-GroupCompare {
    if ($script:OperationRunning) { return }
    if (-not $script:TargetServer) {
        if (-not (Connect-TargetDomain -Quiet $false)) { return }
    }
    if ((Get-ReconciliationNames).Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Import a list before comparing it to a group.', 'No accounts', 'OK', 'Information')
        return
    }
    $groupName = ''
    if ($script:txtGroup) { $groupName = $script:txtGroup.Text.Trim() }
    if (-not $groupName) {
        [System.Windows.Forms.MessageBox]::Show('Enter a group name or browse for one.', 'No group', 'OK', 'Information')
        return
    }
    $nested = $true
    if ($script:chkNested) { $nested = [bool]$script:chkNested.Checked }
    $script:CancelRequested = $false
    Set-Busy $true
    try {
        Write-Log ("Comparing the list to group {0} (nested: {1})." -f $groupName, $nested) 'INFO'
        $script:LastGroupCheck = Invoke-GroupReconciliation -GroupIdentity $groupName -Nested:$nested
        Update-ReconcileGrid
        if ($script:tabMain) { $script:tabMain.SelectedTab = $script:tabReconcile }
        $check = $script:LastGroupCheck
        Write-Log ("Group {0}: matched {1}, token-only {2}, missing {3}, extra {4}, non-user {5}." -f $check.GroupName, $check.Matched, $check.TokenMatched, $check.Missing, $check.Extra, $check.NonUser) 'SUCCESS'
        Set-Progress -Percent 100 -Status ("Group compare complete. Missing {0}, extra {1}." -f $check.Missing, $check.Extra)
    } catch {
        Write-Log ("Group compare failed: {0}" -f $_.Exception.Message) 'ERROR'
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Group compare failed', 'OK', 'Error')
    } finally {
        Set-Busy $false
        if ($script:CloseAfterOperation -and $script:MainForm) { $script:MainForm.Close() }
    }
}

function Copy-ReconcileStatus {
    param([string]$Status)
    if (-not $script:LastGroupCheck) { return }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($row in (Get-Collection $script:LastGroupCheck.Rows)) {
        if ([string]$row.Status -eq $Status) { [void]$names.Add([string]$row.SamAccountName) }
    }
    if ($names.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No rows with status '$Status'.", 'Nothing to copy', 'OK', 'Information')
        return
    }
    if (Set-ClipboardText ($names -join "`r`n")) {
        Set-Progress -Percent $script:progress.Value -Status ("Copied {0} account(s) to the clipboard." -f $names.Count)
    }
}

function Export-DataCsv {
    param($Rows, [string]$Path)
    $items = @(Get-Collection $Rows | Where-Object { $null -ne $_ })
    if ($items.Count -eq 0) {
        [System.IO.File]::WriteAllText($Path, '', (New-Object System.Text.UTF8Encoding $true))
        return
    }
    $items | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

function Export-ReportsInteractive {
    if (-not $script:LastAnalysis) {
        [System.Windows.Forms.MessageBox]::Show('Run the analysis before exporting a report.', 'Nothing to export', 'OK', 'Information')
        return
    }
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Choose a folder for the CSV, HTML, and text reports'
    $dialog.SelectedPath = $script:LogFolder
    if ($dialog.ShowDialog($script:MainForm) -ne 'OK') { return }
    $folder = $dialog.SelectedPath
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $base = Join-Path $folder ("ADUserAnalysis_{0}" -f $stamp)

    Export-DataCsv -Rows (Get-UserDetailRows $script:ADUserData) -Path ($base + '_UserDetail.csv')
    Export-DataCsv -Rows $script:LastAnalysis.Scalar -Path ($base + '_AttributeCommonality.csv')
    Export-DataCsv -Rows $script:LastAnalysis.Groups -Path ($base + '_GroupCommonality.csv')
    if ($script:LastAnalysis.OU) {
        Export-DataCsv -Rows $script:LastAnalysis.OU.ParentOUs -Path ($base + '_OUDistribution.csv')
    }
    $recommendationRows = @(Get-Collection $script:LastAnalysis.Recommendations | Select-Object Quality, Coverage, IltItem, Target, Filter, Binding, Notes)
    Export-DataCsv -Rows $recommendationRows -Path ($base + '_Recommendations.csv')
    Export-DataCsv -Rows $script:NotFoundUsers -Path ($base + '_NotFound.csv')

    $missingNames = New-Object System.Collections.Generic.List[string]
    foreach ($entry in (Get-Collection $script:NotFoundUsers)) { [void]$missingNames.Add([string]$entry.Name) }
    $importedCount = $script:ADUserData.Count + $script:NotFoundUsers.Count
    $html = New-IltHtmlReport -Analysis $script:LastAnalysis -Users $script:ADUserData -NotFound $missingNames -GroupCheck $script:LastGroupCheck -Domain $script:TargetDomain -Server $script:TargetServer -Timestamp $stamp -ImportedCount $importedCount
    $htmlPath = $base + '_Report.html'
    [System.IO.File]::WriteAllText($htmlPath, $html, (New-Object System.Text.UTF8Encoding $true))

    $text = New-IltTextReport -Analysis $script:LastAnalysis -Domain $script:TargetDomain -Timestamp $stamp
    $textPath = $base + '_ILT.txt'
    [System.IO.File]::WriteAllText($textPath, $text, (New-Object System.Text.UTF8Encoding $true))

    if ($script:LastGroupCheck) {
        $safeGroup = ConvertTo-SafeFileName ([string]$script:LastGroupCheck.GroupName)
        Export-DataCsv -Rows $script:LastGroupCheck.Rows -Path (Join-Path $folder ("GroupCheck_{0}_{1}.csv" -f $safeGroup, $stamp))
    }

    Write-Log ("Exported reports to {0}" -f $folder) 'SUCCESS'
    $open = [System.Windows.Forms.MessageBox]::Show(
        "Reports saved in:`r`n$folder`r`n`r`nOpen the HTML report?",
        'Export complete',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    if ($open -eq 'Yes') { Start-Process -FilePath $htmlPath }
}

function New-ActionButton {
    param([string]$Text, [int]$Width, [System.Drawing.Color]$Back)
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Width = $Width
    $button.Height = 30
    $button.FlatStyle = 'Flat'
    $button.FlatAppearance.BorderSize = 0
    $button.BackColor = $Back
    $button.ForeColor = [System.Drawing.Color]::White
    $button.Font = $script:FontUiBold
    $button.Cursor = [System.Windows.Forms.Cursors]::Hand
    $button.Margin = New-Object System.Windows.Forms.Padding(0, 6, 8, 0)
    return $button
}

$script:MainForm = New-Object System.Windows.Forms.Form
$script:MainForm.Text = 'AD User ILT Analysis ' + $script:AppVersion
$script:MainForm.StartPosition = 'CenterScreen'
$script:MainForm.ClientSize = New-Object System.Drawing.Size(1440, 900)
$script:MainForm.MinimumSize = New-Object System.Drawing.Size(1100, 700)
$script:MainForm.Font = $script:FontUi
$script:MainForm.BackColor = $script:ColorBg
$script:MainForm.KeyPreview = $true
$script:MainForm.AllowDrop = $true

$menu = New-Object System.Windows.Forms.MenuStrip
$fileMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$fileMenu.Text = 'File'
$miImport = New-Object System.Windows.Forms.ToolStripMenuItem
$miImport.Text = 'Import CSV...'
$miImport.ShortcutKeys = [System.Windows.Forms.Keys]([int][System.Windows.Forms.Keys]::Control -bor [int][System.Windows.Forms.Keys]::O)
$miExport = New-Object System.Windows.Forms.ToolStripMenuItem
$miExport.Text = 'Export reports...'
$miExport.ShortcutKeys = [System.Windows.Forms.Keys]([int][System.Windows.Forms.Keys]::Control -bor [int][System.Windows.Forms.Keys]::E)
$miLogs = New-Object System.Windows.Forms.ToolStripMenuItem
$miLogs.Text = 'Open log folder'
$miExit = New-Object System.Windows.Forms.ToolStripMenuItem
$miExit.Text = 'Exit'
$miFileSep = New-Object System.Windows.Forms.ToolStripSeparator
[void]$fileMenu.DropDownItems.AddRange(@($miImport, $miExport, $miLogs, $miFileSep, $miExit))
$actionMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$actionMenu.Text = 'Actions'
$miQuery = New-Object System.Windows.Forms.ToolStripMenuItem
$miQuery.Text = 'Query Active Directory'
$miQuery.ShortcutKeys = [System.Windows.Forms.Keys]::F5
$miAnalyze = New-Object System.Windows.Forms.ToolStripMenuItem
$miAnalyze.Text = 'Run ILT analysis'
$miCompare = New-Object System.Windows.Forms.ToolStripMenuItem
$miCompare.Text = 'Compare to group'
$miClear = New-Object System.Windows.Forms.ToolStripMenuItem
$miClear.Text = 'Clear list and results'
[void]$actionMenu.DropDownItems.AddRange(@($miQuery, $miAnalyze, $miCompare, $miClear))
$helpMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$helpMenu.Text = 'Help'
$miAbout = New-Object System.Windows.Forms.ToolStripMenuItem
$miAbout.Text = 'About'
[void]$helpMenu.DropDownItems.Add($miAbout)
[void]$menu.Items.AddRange(@($fileMenu, $actionMenu, $helpMenu))
$script:BusyMenus = @($miImport, $miExport, $miQuery, $miAnalyze, $miCompare, $miClear)

$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'
$header.Height = 104
$header.BackColor = $script:ColorHeader
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = 'AD User Item-Level Targeting'
$lblTitle.Font = $script:FontTitle
$lblTitle.ForeColor = [System.Drawing.Color]::White
$lblTitle.AutoSize = $true
$lblTitle.Location = New-Object System.Drawing.Point(16, 10)
$lblSubtitle = New-Object System.Windows.Forms.Label
$lblSubtitle.Text = 'Find the security group, OU, or LDAP query that covers a drive-map audience.'
$lblSubtitle.ForeColor = [System.Drawing.Color]::FromArgb(176, 196, 216)
$lblSubtitle.AutoSize = $true
$lblSubtitle.Location = New-Object System.Drawing.Point(18, 40)
$lblDomain = New-Object System.Windows.Forms.Label
$lblDomain.Text = 'Domain'
$lblDomain.ForeColor = [System.Drawing.Color]::White
$lblDomain.AutoSize = $true
$lblDomain.Location = New-Object System.Drawing.Point(16, 72)
$script:txtDomain = New-Object System.Windows.Forms.TextBox
$script:txtDomain.Location = New-Object System.Drawing.Point(68, 68)
$script:txtDomain.Size = New-Object System.Drawing.Size(180, 24)
$lblServer = New-Object System.Windows.Forms.Label
$lblServer.Text = 'Server'
$lblServer.ForeColor = [System.Drawing.Color]::White
$lblServer.AutoSize = $true
$lblServer.Location = New-Object System.Drawing.Point(258, 72)
$script:txtServer = New-Object System.Windows.Forms.TextBox
$script:txtServer.Location = New-Object System.Drawing.Point(306, 68)
$script:txtServer.Size = New-Object System.Drawing.Size(180, 24)
$script:btnConnect = New-ActionButton 'Connect' 90 $script:ColorBlue
$script:btnConnect.Location = New-Object System.Drawing.Point(496, 66)
$script:btnConnect.Margin = New-Object System.Windows.Forms.Padding(0)
$script:lblDomainStatus = New-Object System.Windows.Forms.Label
$script:lblDomainStatus.Text = 'Domain: not connected'
$script:lblDomainStatus.ForeColor = [System.Drawing.Color]::FromArgb(255, 170, 160)
$script:lblDomainStatus.AutoSize = $true
$script:lblDomainStatus.Location = New-Object System.Drawing.Point(600, 64)
$script:lblServerStatus = New-Object System.Windows.Forms.Label
$script:lblServerStatus.Text = 'DC: not connected'
$script:lblServerStatus.ForeColor = [System.Drawing.Color]::FromArgb(176, 196, 216)
$script:lblServerStatus.AutoSize = $true
$script:lblServerStatus.Location = New-Object System.Drawing.Point(600, 82)
$header.Controls.AddRange(@($lblTitle, $lblSubtitle, $lblDomain, $script:txtDomain, $lblServer, $script:txtServer, $script:btnConnect, $script:lblDomainStatus, $script:lblServerStatus))

$toolbar = New-Object System.Windows.Forms.FlowLayoutPanel
$toolbar.Dock = 'Top'
$toolbar.Height = 44
$toolbar.Padding = New-Object System.Windows.Forms.Padding(12, 0, 0, 0)
$toolbar.BackColor = $script:ColorBg
$toolbar.WrapContents = $false
$script:btnQuery = New-ActionButton 'Query AD' 110 $script:ColorBlue
$script:btnAnalyze = New-ActionButton 'Analyze ILT' 110 $script:ColorGreen
$script:btnExport = New-ActionButton 'Export' 90 $script:ColorSlate
$script:btnCancel = New-ActionButton 'Cancel' 90 $script:ColorRed
$script:btnCancel.Enabled = $false
$script:chkTokens = New-Object System.Windows.Forms.CheckBox
$script:chkTokens.Text = 'Include nested security groups (tokenGroups)'
$script:chkTokens.Checked = $true
$script:chkTokens.AutoSize = $true
$script:chkTokens.Margin = New-Object System.Windows.Forms.Padding(12, 12, 0, 0)
$toolbar.Controls.AddRange(@($script:btnQuery, $script:btnAnalyze, $script:btnExport, $script:btnCancel, $script:chkTokens))

$script:status = New-Object System.Windows.Forms.StatusStrip
$script:lblStatus = New-Object System.Windows.Forms.ToolStripStatusLabel
$script:lblStatus.Spring = $true
$script:lblStatus.TextAlign = 'MiddleLeft'
$script:lblStatus.Text = 'Ready.'
$script:progress = New-Object System.Windows.Forms.ToolStripProgressBar
$script:progress.Width = 180
$script:progress.Minimum = 0
$script:progress.Maximum = 100
$script:lblCounts = New-Object System.Windows.Forms.ToolStripStatusLabel
$script:lblCounts.Text = 'Resolved 0    Not found 0'
$script:lblCounts.TextAlign = 'MiddleRight'
[void]$script:status.Items.AddRange(@($script:lblStatus, $script:progress, $script:lblCounts))

$script:tabMain = New-Object System.Windows.Forms.TabControl
$script:tabMain.Dock = 'Fill'
$script:tabUsers = New-Object System.Windows.Forms.TabPage
$script:tabUsers.Text = 'Accounts'
$script:tabUsers.BackColor = $script:ColorBg
$script:tabAnalysis = New-Object System.Windows.Forms.TabPage
$script:tabAnalysis.Text = 'ILT Analysis'
$script:tabAnalysis.BackColor = $script:ColorBg
$script:tabReconcile = New-Object System.Windows.Forms.TabPage
$script:tabReconcile.Text = 'Group Reconcile'
$script:tabReconcile.BackColor = $script:ColorBg
$script:tabMissing = New-Object System.Windows.Forms.TabPage
$script:tabMissing.Text = 'Not Found (0)'
$script:tabMissing.BackColor = $script:ColorBg
$script:tabLog = New-Object System.Windows.Forms.TabPage
$script:tabLog.Text = 'Log'
$script:tabLog.BackColor = $script:ColorBg
[void]$script:tabMain.TabPages.AddRange(@($script:tabUsers, $script:tabAnalysis, $script:tabReconcile, $script:tabMissing, $script:tabLog))

$inputPanel = New-Object System.Windows.Forms.Panel
$inputPanel.Dock = 'Top'
$inputPanel.Height = 170
$inputPanel.Padding = New-Object System.Windows.Forms.Padding(8)
$sideButtons = New-Object System.Windows.Forms.Panel
$sideButtons.Dock = 'Right'
$sideButtons.Width = 130
$script:btnImport = New-ActionButton 'Import CSV' 110 $script:ColorBlue
$script:btnImport.Location = New-Object System.Drawing.Point(8, 28)
$script:btnImport.Margin = New-Object System.Windows.Forms.Padding(0)
$script:btnClear = New-ActionButton 'Clear' 110 $script:ColorSlate
$script:btnClear.Location = New-Object System.Drawing.Point(8, 66)
$script:btnClear.Margin = New-Object System.Windows.Forms.Padding(0)
$script:lblNameCount = New-Object System.Windows.Forms.Label
$script:lblNameCount.Text = '0 entries'
$script:lblNameCount.Location = New-Object System.Drawing.Point(8, 104)
$script:lblNameCount.Size = New-Object System.Drawing.Size(116, 32)
$sideButtons.Controls.AddRange(@($script:btnImport, $script:btnClear, $script:lblNameCount))
$lblNames = New-Object System.Windows.Forms.Label
$lblNames.Dock = 'Top'
$lblNames.Height = 22
$lblNames.Text = 'Account names (one per line, DOMAIN\user, UPN, or a pasted CSV). You can also drop a file here.'
$script:txtNames = New-Object System.Windows.Forms.TextBox
$script:txtNames.Multiline = $true
$script:txtNames.ScrollBars = 'Both'
$script:txtNames.AcceptsReturn = $true
$script:txtNames.AcceptsTab = $false
$script:txtNames.Dock = 'Fill'
$script:txtNames.Font = $script:FontMono
$script:txtNames.WordWrap = $false
$inputPanel.Controls.Add($script:txtNames)
$inputPanel.Controls.Add($lblNames)
$inputPanel.Controls.Add($sideButtons)

$filterBar = New-Object System.Windows.Forms.Panel
$filterBar.Dock = 'Top'
$filterBar.Height = 32
$lblFilter = New-Object System.Windows.Forms.Label
$lblFilter.Text = 'Filter'
$lblFilter.AutoSize = $true
$lblFilter.Location = New-Object System.Drawing.Point(8, 8)
$script:txtUserFilter = New-Object System.Windows.Forms.TextBox
$script:txtUserFilter.Location = New-Object System.Drawing.Point(48, 4)
$script:txtUserFilter.Size = New-Object System.Drawing.Size(280, 24)
$script:lblUserFilter = New-Object System.Windows.Forms.Label
$script:lblUserFilter.Text = 'Showing 0 of 0'
$script:lblUserFilter.AutoSize = $true
$script:lblUserFilter.Location = New-Object System.Drawing.Point(340, 8)
$filterBar.Controls.AddRange(@($lblFilter, $script:txtUserFilter, $script:lblUserFilter))

$script:gridUsers = New-Object System.Windows.Forms.DataGridView
Initialize-ResultGrid $script:gridUsers
Add-GridTextColumn $script:gridUsers 'Sam' 'Account' 14
Add-GridTextColumn $script:gridUsers 'Name' 'Name' 14
Add-GridTextColumn $script:gridUsers 'Enabled' 'Enabled' 8
Add-GridTextColumn $script:gridUsers 'Department' 'Department' 12
Add-GridTextColumn $script:gridUsers 'Title' 'Title' 12
Add-GridTextColumn $script:gridUsers 'Office' 'Office' 10
Add-GridTextColumn $script:gridUsers 'City' 'City' 8
Add-GridTextColumn $script:gridUsers 'State' 'State' 8
Add-GridTextColumn $script:gridUsers 'OU' 'Parent OU' 22
Add-GridTextColumn $script:gridUsers 'Groups' 'Groups' 22
Add-GridTextColumn $script:gridUsers 'Home' 'Home directory' 16
Add-GridTextColumn $script:gridUsers 'Locked' 'Locked' 8
Add-GridTextColumn $script:gridUsers 'Logon' 'Last logon' 12
$script:tabUsers.Controls.Add($script:gridUsers)
$script:tabUsers.Controls.Add($filterBar)
$script:tabUsers.Controls.Add($inputPanel)

$analysisTools = New-Object System.Windows.Forms.Panel
$analysisTools.Dock = 'Top'
$analysisTools.Height = 64
$script:lblBest = New-Object System.Windows.Forms.Label
$script:lblBest.Text = 'Import accounts and query Active Directory to build ILT recommendations.'
$script:lblBest.Font = $script:FontUiBold
$script:lblBest.Dock = 'Top'
$script:lblBest.Height = 22
$script:lblBest.Padding = New-Object System.Windows.Forms.Padding(8, 4, 0, 0)
$toolRow = New-Object System.Windows.Forms.FlowLayoutPanel
$toolRow.Dock = 'Fill'
$toolRow.Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
$toolRow.WrapContents = $false
$lblMin = New-Object System.Windows.Forms.Label
$lblMin.Text = 'Minimum coverage %'
$lblMin.AutoSize = $true
$lblMin.Margin = New-Object System.Windows.Forms.Padding(0, 10, 6, 0)
$script:numMin = New-Object System.Windows.Forms.NumericUpDown
$script:numMin.Minimum = 0
$script:numMin.Maximum = 100
$script:numMin.Value = 50
$script:numMin.Width = 60
$script:numMin.Margin = New-Object System.Windows.Forms.Padding(0, 6, 12, 0)
$script:chkHidePoor = New-Object System.Windows.Forms.CheckBox
$script:chkHidePoor.Text = 'Hide built-in, privileged, and distribution groups'
$script:chkHidePoor.Checked = $true
$script:chkHidePoor.AutoSize = $true
$script:chkHidePoor.Margin = New-Object System.Windows.Forms.Padding(0, 8, 12, 0)
$script:btnCopyFilter = New-ActionButton 'Copy filter' 100 $script:ColorBlue
$script:btnCopySteps = New-ActionButton 'Copy GPMC steps' 140 $script:ColorSlate
$script:lblHidden = New-Object System.Windows.Forms.Label
$script:lblHidden.AutoSize = $true
$script:lblHidden.Margin = New-Object System.Windows.Forms.Padding(8, 10, 0, 0)
$script:lblHidden.ForeColor = $script:ColorSlate
$toolRow.Controls.AddRange(@($lblMin, $script:numMin, $script:chkHidePoor, $script:btnCopyFilter, $script:btnCopySteps, $script:lblHidden))
$analysisTools.Controls.Add($toolRow)
$analysisTools.Controls.Add($script:lblBest)

$script:AnalysisSplit = New-Object System.Windows.Forms.SplitContainer
$script:AnalysisSplit.Dock = 'Fill'
$script:AnalysisSplit.Orientation = 'Horizontal'
$script:gridRec = New-Object System.Windows.Forms.DataGridView
Initialize-ResultGrid $script:gridRec
Add-GridTextColumn $script:gridRec 'Quality' 'Quality' 12
Add-GridTextColumn $script:gridRec 'Coverage' 'Coverage %' 10 -Numeric
Add-GridTextColumn $script:gridRec 'Item' 'ILT item' 16
Add-GridTextColumn $script:gridRec 'Target' 'Target' 28
Add-GridTextColumn $script:gridRec 'Filter' 'Filter to paste' 34
Add-GridTextColumn $script:gridRec 'Binding' 'LDAP binding' 20
$script:txtRecNotes = New-Object System.Windows.Forms.TextBox
$script:txtRecNotes.Multiline = $true
$script:txtRecNotes.ReadOnly = $true
$script:txtRecNotes.ScrollBars = 'Vertical'
$script:txtRecNotes.Dock = 'Bottom'
$script:txtRecNotes.Height = 150
$script:txtRecNotes.Font = $script:FontUi
$script:txtRecNotes.BackColor = [System.Drawing.Color]::White
$script:AnalysisSplit.Panel1.Controls.Add($script:gridRec)
$script:AnalysisSplit.Panel1.Controls.Add($script:txtRecNotes)

$detailTabs = New-Object System.Windows.Forms.TabControl
$detailTabs.Dock = 'Fill'
$tabAttr = New-Object System.Windows.Forms.TabPage
$tabAttr.Text = 'Attributes'
$tabGrp = New-Object System.Windows.Forms.TabPage
$tabGrp.Text = 'Groups'
$tabOu = New-Object System.Windows.Forms.TabPage
$tabOu.Text = 'OUs'
$tabHealth = New-Object System.Windows.Forms.TabPage
$tabHealth.Text = 'Account health'
$tabPath = New-Object System.Windows.Forms.TabPage
$tabPath.Text = 'Path prefixes'
$script:gridAttr = New-Object System.Windows.Forms.DataGridView
$script:gridGroups = New-Object System.Windows.Forms.DataGridView
$script:gridOu = New-Object System.Windows.Forms.DataGridView
$script:gridHealth = New-Object System.Windows.Forms.DataGridView
$script:gridPaths = New-Object System.Windows.Forms.DataGridView
Initialize-ResultGrid $script:gridAttr
Initialize-ResultGrid $script:gridGroups
Initialize-ResultGrid $script:gridOu
Initialize-ResultGrid $script:gridHealth
Initialize-ResultGrid $script:gridPaths
Add-GridTextColumn $script:gridAttr 'Attribute' 'Attribute' 14
Add-GridTextColumn $script:gridAttr 'Ldap' 'LDAP attribute' 14
Add-GridTextColumn $script:gridAttr 'Top' 'Top value' 18
Add-GridTextColumn $script:gridAttr 'Match' 'Matching' 8 -Numeric
Add-GridTextColumn $script:gridAttr 'Blank' 'Blank' 8 -Numeric
Add-GridTextColumn $script:gridAttr 'Total' 'Total' 8 -Numeric
Add-GridTextColumn $script:gridAttr 'Percent' '%' 8 -Numeric
Add-GridTextColumn $script:gridAttr 'Distinct' 'Distinct' 8 -Numeric
Add-GridTextColumn $script:gridAttr 'Full' '100%' 8
Add-GridTextColumn $script:gridAttr 'Filter' 'Anchored LDAP filter' 28
Add-GridTextColumn $script:gridGroups 'Group' 'Group' 16
Add-GridTextColumn $script:gridGroups 'Sam' 'sAMAccountName' 14
Add-GridTextColumn $script:gridGroups 'Category' 'Category' 10
Add-GridTextColumn $script:gridGroups 'Scope' 'Scope' 10
Add-GridTextColumn $script:gridGroups 'Users' 'Users' 8 -Numeric
Add-GridTextColumn $script:gridGroups 'Total' 'Total' 8 -Numeric
Add-GridTextColumn $script:gridGroups 'Percent' '%' 8 -Numeric
Add-GridTextColumn $script:gridGroups 'Full' '100%' 8
Add-GridTextColumn $script:gridGroups 'Broad' 'Broad' 8
Add-GridTextColumn $script:gridGroups 'Ilt' 'ILT ok' 8
Add-GridTextColumn $script:gridGroups 'Missing' 'Not covered' 22
Add-GridTextColumn $script:gridOu 'OU' 'Parent OU' 70
Add-GridTextColumn $script:gridOu 'Users' 'Users' 15 -Numeric
Add-GridTextColumn $script:gridOu 'Percent' '%' 15 -Numeric
Add-GridTextColumn $script:gridHealth 'Issue' 'Issue' 25
Add-GridTextColumn $script:gridHealth 'Count' 'Count' 10 -Numeric
Add-GridTextColumn $script:gridHealth 'Accounts' 'Accounts' 65
Add-GridTextColumn $script:gridPaths 'Attribute' 'Attribute' 15
Add-GridTextColumn $script:gridPaths 'Prefix' 'Shared prefix' 30
Add-GridTextColumn $script:gridPaths 'Populated' 'Populated' 10 -Numeric
Add-GridTextColumn $script:gridPaths 'Total' 'Total' 10 -Numeric
Add-GridTextColumn $script:gridPaths 'Note' 'Note' 35
$script:lblAncestor = New-Object System.Windows.Forms.Label
$script:lblAncestor.Dock = 'Bottom'
$script:lblAncestor.Height = 36
$script:lblAncestor.Text = 'Common ancestor OU: (run the analysis)'
$script:lblAncestor.Padding = New-Object System.Windows.Forms.Padding(8, 8, 0, 0)
$tabAttr.Controls.Add($script:gridAttr)
$tabGrp.Controls.Add($script:gridGroups)
$tabOu.Controls.Add($script:gridOu)
$tabOu.Controls.Add($script:lblAncestor)
$tabHealth.Controls.Add($script:gridHealth)
$tabPath.Controls.Add($script:gridPaths)
[void]$detailTabs.TabPages.AddRange(@($tabAttr, $tabGrp, $tabOu, $tabHealth, $tabPath))
$script:AnalysisSplit.Panel2.Controls.Add($detailTabs)
$script:tabAnalysis.Controls.Add($script:AnalysisSplit)
$script:tabAnalysis.Controls.Add($analysisTools)

$reconcileTop = New-Object System.Windows.Forms.Panel
$reconcileTop.Dock = 'Top'
$reconcileTop.Height = 92
$lblGroup = New-Object System.Windows.Forms.Label
$lblGroup.Text = 'Group'
$lblGroup.AutoSize = $true
$lblGroup.Location = New-Object System.Drawing.Point(8, 14)
$script:txtGroup = New-Object System.Windows.Forms.TextBox
$script:txtGroup.Location = New-Object System.Drawing.Point(52, 10)
$script:txtGroup.Size = New-Object System.Drawing.Size(280, 24)
$script:btnBrowseGroup = New-ActionButton 'Browse' 80 $script:ColorSlate
$script:btnBrowseGroup.Location = New-Object System.Drawing.Point(340, 8)
$script:btnBrowseGroup.Margin = New-Object System.Windows.Forms.Padding(0)
$script:chkNested = New-Object System.Windows.Forms.CheckBox
$script:chkNested.Text = 'Include nested members'
$script:chkNested.Checked = $true
$script:chkNested.AutoSize = $true
$script:chkNested.Location = New-Object System.Drawing.Point(430, 12)
$script:btnCompare = New-ActionButton 'Compare' 100 $script:ColorBlue
$script:btnCompare.Location = New-Object System.Drawing.Point(600, 8)
$script:btnCompare.Margin = New-Object System.Windows.Forms.Padding(0)
$btnCopyMissing = New-ActionButton 'Copy missing' 110 $script:ColorRed
$btnCopyMissing.Location = New-Object System.Drawing.Point(710, 8)
$btnCopyMissing.Margin = New-Object System.Windows.Forms.Padding(0)
$btnCopyExtra = New-ActionButton 'Copy extras' 110 $script:ColorSlate
$btnCopyExtra.Location = New-Object System.Drawing.Point(828, 8)
$btnCopyExtra.Margin = New-Object System.Windows.Forms.Padding(0)
$lblStatusFilter = New-Object System.Windows.Forms.Label
$lblStatusFilter.Text = 'Show'
$lblStatusFilter.AutoSize = $true
$lblStatusFilter.Location = New-Object System.Drawing.Point(8, 52)
$script:cmbStatus = New-Object System.Windows.Forms.ComboBox
$script:cmbStatus.DropDownStyle = 'DropDownList'
$script:cmbStatus.Location = New-Object System.Drawing.Point(52, 48)
$script:cmbStatus.Size = New-Object System.Drawing.Size(220, 24)
[void]$script:cmbStatus.Items.AddRange(@('All', 'Matched', 'Matched (logon token only)', 'Missing from group', 'Extra in group', 'Non-user member'))
$script:cmbStatus.SelectedIndex = 0
$script:lblReconcile = New-Object System.Windows.Forms.Label
$script:lblReconcile.Text = 'Choose a group and click Compare.'
$script:lblReconcile.AutoSize = $false
$script:lblReconcile.Location = New-Object System.Drawing.Point(284, 44)
$script:lblReconcile.Size = New-Object System.Drawing.Size(980, 40)
$reconcileTop.Controls.AddRange(@($lblGroup, $script:txtGroup, $script:btnBrowseGroup, $script:chkNested, $script:btnCompare, $btnCopyMissing, $btnCopyExtra, $lblStatusFilter, $script:cmbStatus, $script:lblReconcile))
$script:gridReconcile = New-Object System.Windows.Forms.DataGridView
Initialize-ResultGrid $script:gridReconcile
Add-GridTextColumn $script:gridReconcile 'Account' 'Account' 20
Add-GridTextColumn $script:gridReconcile 'Status' 'Status' 22
Add-GridTextColumn $script:gridReconcile 'Notes' 'Notes' 58
$script:tabReconcile.Controls.Add($script:gridReconcile)
$script:tabReconcile.Controls.Add($reconcileTop)

$missingHint = New-Object System.Windows.Forms.Label
$missingHint.Dock = 'Top'
$missingHint.Height = 28
$missingHint.Padding = New-Object System.Windows.Forms.Padding(8, 6, 0, 0)
$missingHint.Text = 'Names from the list that Active Directory did not return, plus accounts that failed to read.'
$script:gridMissing = New-Object System.Windows.Forms.DataGridView
Initialize-ResultGrid $script:gridMissing
Add-GridTextColumn $script:gridMissing 'Name' 'Account' 30
Add-GridTextColumn $script:gridMissing 'Reason' 'Reason' 70
$script:tabMissing.Controls.Add($script:gridMissing)
$script:tabMissing.Controls.Add($missingHint)

$logTools = New-Object System.Windows.Forms.Panel
$logTools.Dock = 'Top'
$logTools.Height = 40
$btnOpenLog = New-ActionButton 'Open log folder' 130 $script:ColorSlate
$btnOpenLog.Location = New-Object System.Drawing.Point(8, 6)
$btnOpenLog.Margin = New-Object System.Windows.Forms.Padding(0)
$btnSaveLog = New-ActionButton 'Save log as...' 120 $script:ColorBlue
$btnSaveLog.Location = New-Object System.Drawing.Point(146, 6)
$btnSaveLog.Margin = New-Object System.Windows.Forms.Padding(0)
$logTools.Controls.AddRange(@($btnOpenLog, $btnSaveLog))
$script:txtLog = New-Object System.Windows.Forms.RichTextBox
$script:txtLog.Dock = 'Fill'
$script:txtLog.ReadOnly = $true
$script:txtLog.Font = $script:FontMono
$script:txtLog.BackColor = [System.Drawing.Color]::White
$script:txtLog.BorderStyle = 'None'
$script:tabLog.Controls.Add($script:txtLog)
$script:tabLog.Controls.Add($logTools)

$script:MainForm.Controls.Add($script:tabMain)
$script:MainForm.Controls.Add($script:status)
$script:MainForm.Controls.Add($toolbar)
$script:MainForm.Controls.Add($header)
$script:MainForm.MainMenuStrip = $menu
$script:MainForm.Controls.Add($menu)

$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.SetToolTip($script:txtDomain, 'Leave blank to use the domain you are logged on to.')
$toolTip.SetToolTip($script:txtServer, 'Optional domain controller. Blank uses the PDC emulator.')
$toolTip.SetToolTip($script:chkTokens, 'Reads tokenGroups so nested security groups match what Item-level targeting sees at logon. Slower on large lists.')
$toolTip.SetToolTip($script:chkNested, 'Uses the LDAP in-chain matching rule. Primary-group members are included either way. Get-ADGroupMember is not used.')
$toolTip.SetToolTip($script:numMin, 'Partial attribute and group matches below this percentage stay in the detail grids but drop out of the recommendation list.')

$script:btnConnect.Add_Click({ Connect-TargetDomain -Quiet $false })
$script:btnImport.Add_Click({ Import-CsvInteractive })
$script:btnClear.Add_Click({ Clear-Session })
$script:btnQuery.Add_Click({ Start-DirectoryQuery })
$script:btnAnalyze.Add_Click({
        if ($script:OperationRunning) { return }
        try { Start-Analysis } catch {
            Write-Log $_.Exception.Message 'ERROR'
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Analysis failed', 'OK', 'Error')
        }
    })
$script:btnExport.Add_Click({
        try { Export-ReportsInteractive } catch {
            Write-Log $_.Exception.Message 'ERROR'
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Export failed', 'OK', 'Error')
        }
    })
$script:btnCancel.Add_Click({
        $script:CancelRequested = $true
        Write-Log 'Cancel requested. The current account finishes, then the query stops.' 'WARN'
        Set-Progress -Percent $script:progress.Value -Status 'Cancelling...'
    })
$script:btnCompare.Add_Click({ Start-GroupCompare })
$script:btnBrowseGroup.Add_Click({
        if (-not $script:TargetServer) {
            if (-not (Connect-TargetDomain -Quiet $false)) { return }
        }
        $picked = Show-GroupSearch
        if ($picked) { $script:txtGroup.Text = $picked }
    })
$btnCopyMissing.Add_Click({ Copy-ReconcileStatus 'Missing from group' })
$btnCopyExtra.Add_Click({ Copy-ReconcileStatus 'Extra in group' })
$script:cmbStatus.Add_SelectedIndexChanged({ Update-ReconcileGrid })
$script:txtUserFilter.Add_TextChanged({ Update-UserGrid })
$script:txtNames.Add_TextChanged({
        $text = $script:txtNames.Text
        if ([string]::IsNullOrWhiteSpace($text)) { $script:lblNameCount.Text = '0 entries'; return }
        $parts = [regex]::Split($text, '[\r\n,;\t]+')
        $count = 0
        if ($parts -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace($parts)) { $count = 1 }
        } else {
            foreach ($part in $parts) {
                if (-not [string]::IsNullOrWhiteSpace([string]$part)) { $count++ }
            }
        }
        $script:lblNameCount.Text = "$count entries"
    })
$script:gridUsers.Add_CellDoubleClick({
        if ($_.RowIndex -lt 0) { return }
        $user = $script:gridUsers.Rows[$_.RowIndex].Tag
        if ($user) { Show-UserDetail $user }
    })
$script:gridRec.Add_SelectionChanged({ Update-RecommendationDetails })
$script:gridRec.Add_CellDoubleClick({
        if ($_.RowIndex -lt 0) { return }
        $rec = $script:gridRec.Rows[$_.RowIndex].Tag
        if ($rec -and (Set-ClipboardText ([string]$rec.Filter))) {
            Set-Progress -Percent $script:progress.Value -Status 'Copied the ILT filter to the clipboard.'
        }
    })
$script:btnCopyFilter.Add_Click({
        $rec = Get-SelectedRecommendation
        if ($null -eq $rec) { return }
        if (Set-ClipboardText ([string]$rec.Filter)) { Set-Progress -Percent $script:progress.Value -Status 'Copied the ILT filter to the clipboard.' }
    })
$script:btnCopySteps.Add_Click({
        $rec = Get-SelectedRecommendation
        if ($null -eq $rec) { return }
        $payload = ([string]$rec.Target) + "`r`n" + ([string]$rec.Filter) + "`r`n" + ([string]$rec.Steps)
        if (Set-ClipboardText $payload) { Set-Progress -Percent $script:progress.Value -Status 'Copied the GPMC steps to the clipboard.' }
    })
$script:chkHidePoor.Add_CheckedChanged({ if ($script:UiReady) { Update-AnalysisView } })
$script:numMin.Add_ValueChanged({
        if (-not $script:UiReady -or -not $script:LastAnalysis) { return }
        $min = [double]$script:numMin.Value
        $script:LastAnalysis.Recommendations = Get-IltRecommendations -ScalarRows $script:LastAnalysis.Scalar -GroupRows $script:LastAnalysis.Groups -OuResult $script:LastAnalysis.OU -MinPercent $min -DomainDn $script:DomainDn -NetBiosName $script:NetBiosName -TokenGroupsResolved:([bool]$script:LastAnalysis.TokenGroupsResolved)
        $script:LastAnalysis.MinPercent = $min
        Update-AnalysisView
    })
$miImport.Add_Click({ Import-CsvInteractive })
$miExport.Add_Click({
        try { Export-ReportsInteractive } catch {
            Write-Log $_.Exception.Message 'ERROR'
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Export failed', 'OK', 'Error')
        }
    })
$miLogs.Add_Click({ Start-Process -FilePath $script:LogFolder })
$miExit.Add_Click({ $script:MainForm.Close() })
$miQuery.Add_Click({ Start-DirectoryQuery })
$miAnalyze.Add_Click({
        if ($script:OperationRunning) { return }
        try { Start-Analysis } catch {
            Write-Log $_.Exception.Message 'ERROR'
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Analysis failed', 'OK', 'Error')
        }
    })
$miCompare.Add_Click({ if ($script:tabMain) { $script:tabMain.SelectedTab = $script:tabReconcile } })
$miClear.Add_Click({ Clear-Session })
$miAbout.Add_Click({ Show-About })
$btnOpenLog.Add_Click({ Start-Process -FilePath $script:LogFolder })
$btnSaveLog.Add_Click({
        $save = New-Object System.Windows.Forms.SaveFileDialog
        $save.Filter = 'Log files (*.log)|*.log|Text files (*.txt)|*.txt'
        $save.FileName = 'ADUserAnalysis.log'
        if ($save.ShowDialog($script:MainForm) -ne 'OK') { return }
        [System.IO.File]::WriteAllLines($save.FileName, $script:LogEntries.ToArray(), (New-Object System.Text.UTF8Encoding $true))
        Write-Log ("Saved a copy of the log to {0}" -f $save.FileName) 'SUCCESS'
    })
$script:MainForm.Add_DragEnter({
        if ($_.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) { $_.Effect = 'Copy' }
    })
$script:MainForm.Add_DragDrop({
        if ($script:OperationRunning) { return }
        $files = @($_.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop))
        if ($files.Count -gt 0) { Import-AccountFile -Path ([string]$files[0]) }
    })
$script:MainForm.Add_FormClosing({
        if ($script:OperationRunning) {
            $_.Cancel = $true
            $script:CancelRequested = $true
            $script:CloseAfterOperation = $true
            Set-Progress -Percent $script:progress.Value -Status 'Cancelling so the window can close...'
        } elseif ($script:LogWriter) {
            try { $script:LogWriter.Dispose() } catch { }
            $script:LogWriter = $null
        }
    })

Write-Log ("AD User ILT Analysis {0} started. Log: {1}" -f $script:AppVersion, $script:LogFile) 'INFO'
$script:MainForm.Add_Shown({
        $script:UiReady = $true
        try {
            $split = $script:AnalysisSplit
            $available = $split.Height - $split.SplitterWidth
            if ($available -gt 200) {
                $split.Panel1MinSize = 80
                $split.Panel2MinSize = 80
                $desired = [int]($available * 0.46)
                $max = $available - 80
                if ($desired -lt 80) { $desired = 80 }
                if ($desired -gt $max) { $desired = $max }
                $split.SplitterDistance = $desired
            }
        } catch {
            Write-Log ("Could not set the analysis splitter: {0}" -f $_.Exception.Message) 'WARN'
        }
        Connect-TargetDomain -Quiet $true | Out-Null
        if ($CsvPath -and (Test-Path -LiteralPath $CsvPath)) {
            Import-AccountFile -Path $CsvPath
            if ($script:TargetServer) { Start-DirectoryQuery }
        } elseif ($CsvPath) {
            Write-Log ("CSV path was not found: {0}" -f $CsvPath) 'ERROR'
        }
    })

[void]$script:MainForm.ShowDialog()
if ($script:LogWriter) {
    try { $script:LogWriter.Dispose() } catch { }
}

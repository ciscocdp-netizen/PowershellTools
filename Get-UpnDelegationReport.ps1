#Requires -Version 5.1

<#
.SYNOPSIS
    Reports the who / what / where / when of the delegated permissions listed in a
    Semperis "unprivileged accounts can change UPN" findings export.

.DESCRIPTION
    READ-ONLY. This script does not change anything in Active Directory.

    Launch with no parameters for a fully interactive GUI (file pickers, options,
    CSV preview, live log). Supply -CsvPath to run unattended from the console.

    For every row in the Semperis CSV the script reads the live ACL of the target object
    and reports every ACE held by the flagged trustee:

      WHO    The trustee: resolved name, SID, type, enabled state, last logon, group
             membership, and (for groups) every effective member, nested included.
             SIDs that no longer resolve are checked against SIDHistory and Deleted Objects.
      WHAT   The rights, the attribute / property set / class they are scoped to, what
             they apply to, and whether they allow a UPN change directly or indirectly.
      WHERE  The target object, whether the ACE is explicit or inherited, the object the
             ACE is actually set on, and how many users / computers sit underneath it.
      WHEN   When the security descriptor carrying the ACE was last modified and on which
             domain controller (replication metadata), plus object and trustee timestamps.

    Active Directory does not store a timestamp per ACE. The WHEN columns show the last time
    the whole security descriptor of the object was changed. Use -SearchEventLogs to pull
    the matching 5136 audit events, which also name the account that made the change.

    Accepted Semperis CSV columns (header text is matched case-insensitively, extra
    columns are ignored):

      Distinguished name, Object guid, Object class, Identity, Permissions,
      Applies to, Attribute, Ignored

    The same layout as KCI_SemperisFindings.csv / Samples/SemperisFindings.sample.csv.

.PARAMETER CsvPath
    Path to the Semperis CSV export. Optional: a file picker is shown when omitted.

.PARAMETER OutputPath
    Folder for the report files. Created if missing. A folder picker is shown in the GUI.
    Default (console): .\DelegationAudit_<timestamp>

.PARAMETER Server
    Domain controller to query. Default: the PDC emulator of the current domain.

.PARAMETER Credential
    Alternate credential for the Active Directory and event log queries.

.PARAMETER SkipGroupExpansion
    Do not expand group trustees into their effective members.

.PARAMETER SkipScopeCount
    Do not count the user and computer objects underneath container targets.

.PARAMETER SearchEventLogs
    Search the Security log of every domain controller for event 5136 changes to
    nTSecurityDescriptor on the objects in the report. Requires "Audit Directory Service
    Changes" to be enabled and rights to read the Security log on the domain controllers.

.PARAMETER EventLogDays
    How many days back to search when -SearchEventLogs is used. Default: 30

.PARAMETER Interactive
    Force the GUI even when -CsvPath is supplied (fields are pre-filled).

.PARAMETER NonInteractive
    Never show the GUI or file pickers. -CsvPath is then required.

.PARAMETER ValidateCsvOnly
    Load and validate the CSV, print a summary, and exit. Does not contact Active Directory.

.EXAMPLE
    .\Get-UpnDelegationReport.ps1

    Opens the interactive GUI. Use Browse to pick the Semperis CSV and the output folder.

.EXAMPLE
    .\Get-UpnDelegationReport.ps1 -CsvPath .\KCI_SemperisFindings.csv

.EXAMPLE
    .\Get-UpnDelegationReport.ps1 -CsvPath .\KCI_SemperisFindings.csv -Server dc01.kci-net.karmanos.org -SearchEventLogs -EventLogDays 90

.OUTPUTS
    00_Summary.txt                 Human-readable run summary
    01_DelegationDetail.csv        One row per live ACE (who / what / where / when)
    02_SemperisFindingStatus.csv   Every input row and whether it still exists in the live ACL
    03_Trustees.csv                One row per flagged trustee
    04_GroupMembers.csv            Effective members of every group trustee
    05_AclChangeEvents.csv         Event 5136 ACL changes (only with -SearchEventLogs)
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$CsvPath,

    [string]$OutputPath,

    [string]$Server,

    [AllowNull()]
    [System.Management.Automation.PSCredential]$Credential,

    [switch]$SkipGroupExpansion,

    [switch]$SkipScopeCount,

    [switch]$SearchEventLogs,

    [ValidateRange(1, 3650)]
    [int]$EventLogDays = 30,

    [Alias('Gui')]
    [switch]$Interactive,

    [switch]$NonInteractive,

    [switch]$ValidateCsvOnly
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

#region Script state

$script:EmptyGuid = [Guid]::Empty.ToString()
$script:DateFormat = 'yyyy-MM-dd HH:mm:ss'
$script:AppVersion = '1.1'

$script:ReportServer = $Server
$script:ReportCredential = $Credential
$script:LocalDomainSid = $null
$script:UpnAttributeGuid = '28630ebb-41d5-11d1-a9c1-0000f80367c1'
$script:UpnPropertySetGuid = 'e48d0154-bcf8-11d1-8702-00c04fb96050'

$script:ObjectCache = @{}
$script:TrusteeCache = @{}
$script:SdMetadataCache = @{}
$script:ScopeCountCache = @{}
$script:DomainsBySid = @{}
$script:DomainsByNetBios = @{}
$script:SchemaGuidMap = @{}
$script:RightsGuidMap = @{}
$script:UpnClassGuids = @{}

$script:OnStatus = $null
$script:IsRunning = $false
$script:LastOutputPath = $null
$script:WinFormsLoaded = $false
$script:GuiCredential = $null
$script:GuiLogBox = $null
$script:GuiProgress = $null
$script:GuiCsvStatus = $null
$script:GuiGrid = $null
$script:GuiForm = $null
$script:GuiCsvPathBox = $null
$script:GuiOutPathBox = $null
$script:GuiServerBox = $null
$script:GuiCredLabel = $null
$script:GuiRunButton = $null
$script:GuiBrowseCsvButton = $null
$script:GuiOpenButton = $null
$script:GuiChkExpand = $null
$script:GuiChkScope = $null
$script:GuiChkEvents = $null
$script:GuiNumDays = $null
$script:OkGreen = $null
$script:MutedColor = $null

$script:TrusteeProperties = @(
    'sAMAccountName', 'displayName', 'description', 'objectSid', 'whenCreated', 'whenChanged',
    'userAccountControl', 'lastLogonTimestamp', 'pwdLastSet', 'adminCount', 'memberOf',
    'userPrincipalName', 'lastKnownParent', 'isDeleted'
)

$script:UpnClassNames = @(
    'user', 'computer', 'inetOrgPerson',
    'msDS-ManagedServiceAccount', 'msDS-GroupManagedServiceAccount'
)

$script:ColumnAliases = @{
    DistinguishedName = @(
        'Distinguished name', 'DistinguishedName', 'Distinguished Name',
        'DN', 'ObjectDN', 'Object DN', 'objectDistinguishedName'
    )
    ObjectGuid = @(
        'Object guid', 'ObjectGUID', 'Object GUID', 'GUID', 'objectGuid', 'ObjectGuid'
    )
    ObjectClass = @(
        'Object class', 'ObjectClass', 'Object Class', 'Class', 'objectClass'
    )
    Identity = @(
        'Identity', 'Trustee', 'Account', 'Principal', 'Who', 'TrusteeName'
    )
    Permissions = @(
        'Permissions', 'Permission', 'Rights', 'Access', 'ActiveDirectoryRights'
    )
    AppliesTo = @(
        'Applies to', 'AppliesTo', 'Applies To', 'Inheritance', 'Apply To'
    )
    Attribute = @(
        'Attribute', 'ObjectType', 'Object Type', 'Property', 'Property Name', 'PropertyName'
    )
    Ignored = @(
        'Ignored', 'Ignore', 'IsIgnored'
    )
}

$script:RequiredLogicalColumns = @(
    'DistinguishedName', 'ObjectGuid', 'Identity', 'Permissions', 'AppliesTo', 'Attribute'
)

$script:PermissionAliases = @{
    'fullcontrol'          = 'GenericAll'
    'full control'         = 'GenericAll'
    'generic all'          = 'GenericAll'
    'writeproperty'        = 'WriteProperty'
    'write property'       = 'WriteProperty'
    'write all properties' = 'WriteProperty'
    'createchild'          = 'CreateChild'
    'create child'         = 'CreateChild'
    'deletechild'          = 'DeleteChild'
    'delete child'         = 'DeleteChild'
    'writedacl'            = 'WriteDacl'
    'write dacl'           = 'WriteDacl'
    'writeowner'           = 'WriteOwner'
    'write owner'          = 'WriteOwner'
}

#endregion Script state

#region UI / picker helpers

function Test-IsStaThread {
    return ([System.Threading.Thread]::CurrentThread.ApartmentState -eq 'STA')
}

function Test-WindowsDesktop {
    if ($env:OS -notmatch 'Windows') { return $false }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $script:WinFormsLoaded = $true
        return $true
    }
    catch {
        return $false
    }
}

function Initialize-WinForms {
    if ($script:WinFormsLoaded) { return $true }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        [System.Windows.Forms.Application]::EnableVisualStyles()
        $script:WinFormsLoaded = $true
        return $true
    }
    catch {
        return $false
    }
}

function ConvertTo-ProcessArgument {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '""' }
    if ($Value -match '[\s"]') {
        return ('"{0}"' -f ($Value -replace '"', '\"'))
    }
    return $Value
}

function Restart-InStaIfNeeded {
    if (Test-IsStaThread) { return $false }
    $exe = (Get-Process -Id $PID).Path
    if (-not $exe) { $exe = 'powershell.exe' }

    $parts = New-Object System.Collections.Generic.List[string]
    [void]$parts.Add('-NoProfile')
    [void]$parts.Add('-STA')
    [void]$parts.Add('-ExecutionPolicy')
    [void]$parts.Add('Bypass')
    [void]$parts.Add('-File')
    [void]$parts.Add((ConvertTo-ProcessArgument -Value $PSCommandPath))

    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -eq 'Credential') { continue }
        $val = $PSBoundParameters[$key]
        if ($val -is [System.Management.Automation.SwitchParameter]) {
            if ($val) { [void]$parts.Add("-$key") }
        }
        else {
            [void]$parts.Add("-$key")
            [void]$parts.Add((ConvertTo-ProcessArgument -Value ([string]$val)))
        }
    }

    Write-Host 'Restarting in a single-threaded apartment so file pickers can open...' -ForegroundColor Yellow
    $proc = Start-Process -FilePath $exe -ArgumentList ($parts -join ' ') -Wait -PassThru -NoNewWindow
    exit $proc.ExitCode
}

function Show-UiMessage {
    param(
        [string]$Message,
        [string]$Title = 'UPN Delegation Report',
        [string]$Icon = 'Information'
    )
    if ($script:WinFormsLoaded) {
        $iconValue = [System.Windows.Forms.MessageBoxIcon]::$Icon
        [void][System.Windows.Forms.MessageBox]::Show(
            $Message, $Title,
            [System.Windows.Forms.MessageBoxButtons]::OK,
            $iconValue
        )
    }
    else {
        Write-Host $Message
    }
}

function Get-OpenCsvPath {
    param(
        [string]$Title = 'Select the Semperis findings CSV',
        [string]$InitialDirectory
    )
    if (-not (Initialize-WinForms)) { return $null }
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = $Title
    $dialog.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $dialog.Multiselect = $false
    $dialog.CheckFileExists = $true
    $dialog.RestoreDirectory = $true
    if ($InitialDirectory -and (Test-Path -LiteralPath $InitialDirectory)) {
        $dialog.InitialDirectory = $InitialDirectory
    }
    elseif ($PSScriptRoot) {
        $dialog.InitialDirectory = $PSScriptRoot
    }
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $dialog.FileName
    }
    return $null
}

function Get-OutputFolderPath {
    param(
        [string]$Description = 'Select the folder for the delegation report files',
        [string]$SelectedPath
    )
    if (-not (Initialize-WinForms)) { return $null }
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = $Description
    $dialog.ShowNewFolderButton = $true
    if ($SelectedPath -and (Test-Path -LiteralPath $SelectedPath)) {
        $dialog.SelectedPath = $SelectedPath
    }
    elseif ($PSScriptRoot) {
        $dialog.SelectedPath = $PSScriptRoot
    }
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $dialog.SelectedPath
    }
    return $null
}

function Find-NearbySemperisCsv {
    $roots = @()
    try { $roots += (Get-Location).Path } catch { }
    if ($PSScriptRoot) { $roots += $PSScriptRoot }
    $patterns = @(
        'KCI_SemperisFindings.csv',
        '*Semperis*.csv',
        '*Findings*.csv'
    )
    foreach ($root in ($roots | Select-Object -Unique)) {
        if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }
        foreach ($pattern in $patterns) {
            $hit = Get-ChildItem -LiteralPath $root -Filter $pattern -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }
    }
    return $null
}

function Get-DefaultOutputPath {
    $root = $null
    try { $root = (Get-Location).Path } catch { }
    if (-not $root) { $root = $PSScriptRoot }
    if (-not $root) { $root = [Environment]::GetFolderPath('Desktop') }
    if (-not $root) { $root = $env:TEMP }
    return (Join-Path -Path $root -ChildPath ('DelegationAudit_{0:yyyyMMdd_HHmmss}' -f (Get-Date)))
}

#endregion UI / picker helpers

#region CSV helpers

function Get-NormalizedHeaderName {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return '' }
    return ($Name.TrimStart([char]0xFEFF).Trim())
}

function Get-RowField {
    param(
        $Row,
        [string]$LogicalName
    )
    if ($null -eq $Row) { return '' }
    $aliases = @($script:ColumnAliases[$LogicalName])
    $props = @($Row.PSObject.Properties)
    foreach ($alias in $aliases) {
        foreach ($prop in $props) {
            $header = Get-NormalizedHeaderName -Name $prop.Name
            if ($header -ieq $alias) {
                return ([string]$prop.Value)
            }
            if (($header -replace '\s', '') -ieq ($alias -replace '\s', '')) {
                return ([string]$prop.Value)
            }
        }
    }
    return ''
}

function Get-CsvLogicalHeaders {
    param($Row)
    $found = [ordered]@{}
    foreach ($logical in $script:ColumnAliases.Keys) {
        $valueProbe = Get-RowField -Row $Row -LogicalName $logical
        $matched = $false
        foreach ($prop in $Row.PSObject.Properties) {
            $header = Get-NormalizedHeaderName -Name $prop.Name
            foreach ($alias in $script:ColumnAliases[$logical]) {
                if ($header -ieq $alias -or (($header -replace '\s', '') -ieq ($alias -replace '\s', ''))) {
                    $found[$logical] = $header
                    $matched = $true
                    break
                }
            }
            if ($matched) { break }
        }
        if (-not $matched -and $valueProbe) {
            $found[$logical] = '(matched)'
        }
    }
    return $found
}

function Test-CsvHasRequiredColumns {
    param($Row)
    $found = Get-CsvLogicalHeaders -Row $Row
    $missing = @($script:RequiredLogicalColumns | Where-Object { -not $found.Contains($_) })
    return $missing
}

function Import-SemperisCsv {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "CSV file not found: $Path"
    }

    $encodings = @('UTF8', 'Unicode', 'Default')
    $lastError = $null
    $bestRows = $null
    $bestMissing = $script:RequiredLogicalColumns

    foreach ($encoding in $encodings) {
        try {
            $rows = @(Import-Csv -LiteralPath $Path -Encoding $encoding -ErrorAction Stop)
            if ($rows.Count -eq 0) { continue }
            $missing = @(Test-CsvHasRequiredColumns -Row $rows[0])
            if ($missing.Count -eq 0) { return $rows }
            if ($null -eq $bestRows -or $missing.Count -lt $bestMissing.Count) {
                $bestRows = $rows
                $bestMissing = $missing
            }
        }
        catch {
            $lastError = $_
        }
    }

    if ($bestRows) {
        throw ('The CSV is missing required column(s): {0}. Present columns: {1}' -f `
            ($bestMissing -join ', '),
            (($bestRows[0].PSObject.Properties.Name | ForEach-Object { Get-NormalizedHeaderName $_ }) -join ', '))
    }

    if ($lastError) { throw $lastError }
    throw "No rows found in $Path"
}

function Get-CsvPreviewInfo {
    param([string]$Path)
    $rows = @(Import-SemperisCsv -Path $Path)
    $identities = @($rows | ForEach-Object { (Get-RowField -Row $_ -LogicalName 'Identity').Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $targets = @($rows | ForEach-Object { (Get-RowField -Row $_ -LogicalName 'DistinguishedName').Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $headers = @($rows[0].PSObject.Properties.Name | ForEach-Object { Get-NormalizedHeaderName $_ })
    return [PSCustomObject]@{
        Rows             = $rows
        RowCount         = $rows.Count
        Headers          = $headers
        UniqueIdentities = $identities.Count
        UniqueTargets    = $targets.Count
        Preview          = @($rows | Select-Object -First 50)
    }
}

#endregion CSV helpers

#region Logging

function Write-AuditStatus {
    param(
        [string]$Message,
        [string]$Color = 'White',
        [int]$Percent = -1,
        [string]$Activity = 'UPN Delegation Report',
        [switch]$NoNewLine
    )
    if ($script:OnStatus) {
        & $script:OnStatus $Message $Color $Percent $Activity
        return
    }
    $fg = $Color
    try { $null = [ConsoleColor]$Color } catch { $fg = 'White' }
    if ($NoNewLine) {
        Write-Host $Message -ForegroundColor $fg -NoNewline
    }
    else {
        Write-Host $Message -ForegroundColor $fg
    }
    if ($Percent -ge 0) {
        Write-Progress -Activity $Activity -Status $Message -PercentComplete ([Math]::Min(100, [Math]::Max(0, $Percent)))
    }
}

function Complete-AuditProgress {
    param([string]$Activity = 'UPN Delegation Report')
    if (-not $script:OnStatus) {
        Write-Progress -Activity $Activity -Completed
    }
}

#endregion Logging

#region AD helpers

function Get-AdSplat {
    param([string]$TargetServer)
    $splat = @{}
    if ($TargetServer) {
        $splat['Server'] = $TargetServer
    }
    elseif ($script:ReportServer) {
        $splat['Server'] = $script:ReportServer
    }
    if ($script:ReportCredential) {
        $splat['Credential'] = $script:ReportCredential
    }
    return $splat
}

function ConvertTo-LdapFilterValue {
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    return ($Value -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29')
}

function ConvertFrom-FileTimeValue {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        $ticks = [int64]$Value
        if ($ticks -le 0 -or $ticks -eq [int64]::MaxValue) { return $null }
        return [DateTime]::FromFileTime($ticks)
    }
    catch { return $null }
}

function Format-ReportDate {
    param($Value)
    if ($null -eq $Value) { return '' }
    try { return ([DateTime]$Value).ToString($script:DateFormat) } catch { return [string]$Value }
}

function Get-ParentDN {
    param([string]$DN)
    if ([string]::IsNullOrWhiteSpace($DN)) { return $null }
    $parent = $DN -replace '^(?:[^,\\]|\\.)+,', ''
    if ($parent -eq $DN) { return $null }
    return $parent
}

function Get-RdnValue {
    param([string]$DN)
    if ([string]::IsNullOrWhiteSpace($DN)) { return '' }
    $rdn = ($DN -split '(?<!\\),')[0]
    return (($rdn -replace '^[A-Za-z]+=', '') -replace '\\(.)', '$1')
}

function Get-EnabledState {
    param($UserAccountControl)
    if ($null -eq $UserAccountControl -or $UserAccountControl -eq '') { return 'N/A' }
    if (([int]$UserAccountControl -band 2) -eq 2) { return 'False' }
    return 'True'
}

function ConvertTo-ActiveDirectorySecurity {
    param($Descriptor)
    if ($null -eq $Descriptor) { return $null }
    if ($Descriptor -is [System.DirectoryServices.ActiveDirectorySecurity]) { return $Descriptor }
    if ($Descriptor -is [byte[]]) {
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm($Descriptor)
        return $sd
    }
    if ($Descriptor -is [string] -and $Descriptor -match '^O:') {
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorSddlForm($Descriptor)
        return $sd
    }
    return $null
}

function Resolve-ObjectTypeGuid {
    param([Guid]$Guid, [System.DirectoryServices.ActiveDirectoryRights]$Rights)

    $key = $Guid.ToString()
    if ($key -eq $script:EmptyGuid) {
        return [PSCustomObject]@{ Name = 'All'; Kind = '' }
    }

    $rightsEnum = [System.DirectoryServices.ActiveDirectoryRights]
    $controlAccess = [int]($rightsEnum::ExtendedRight -bor $rightsEnum::Self)
    $preferRights = (([int]$Rights -band $controlAccess) -ne 0) -and
        (([int]$Rights -band [int]($rightsEnum::WriteProperty -bor $rightsEnum::ReadProperty -bor $rightsEnum::CreateChild -bor $rightsEnum::DeleteChild)) -eq 0)

    $first = $script:SchemaGuidMap
    $second = $script:RightsGuidMap
    if ($preferRights) {
        $first = $script:RightsGuidMap
        $second = $script:SchemaGuidMap
    }

    if ($first.ContainsKey($key)) { return $first[$key] }
    if ($second.ContainsKey($key)) { return $second[$key] }
    return [PSCustomObject]@{ Name = ('Unknown ({0})' -f $key); Kind = 'Unknown' }
}

function Get-AppliesToText {
    param($Ace)

    $className = ''
    if ($Ace.InheritedObjectType.ToString() -ne $script:EmptyGuid) {
        $className = (Resolve-ObjectTypeGuid -Guid $Ace.InheritedObjectType -Rights ([System.DirectoryServices.ActiveDirectoryRights]::CreateChild)).Name + ' '
    }

    switch ($Ace.InheritanceType.ToString()) {
        'None' { return 'This object only' }
        'All' {
            if ($className) { return ('This object and all descendant {0}objects' -f $className) }
            return 'This object and all descendant objects'
        }
        'Descendents' { return ('All descendant {0}objects' -f $className) }
        'Children' { return ('Immediate child {0}objects only' -f $className) }
        'SelfAndChildren' { return ('This object and immediate child {0}objects' -f $className) }
        default { return $Ace.InheritanceType.ToString() }
    }
}

function Get-UpnWriteAssessment {
    param($Ace, [bool]$TargetIsPrincipal)

    if ($Ace.AccessControlType.ToString() -ne 'Allow') { return 'No (Deny ACE)' }

    $rightsEnum = [System.DirectoryServices.ActiveDirectoryRights]
    $rights = [int]$Ace.ActiveDirectoryRights
    $objectType = $Ace.ObjectType.ToString()
    $inheritedType = $Ace.InheritedObjectType.ToString()

    $appliesToSelf = (([int]$Ace.PropagationFlags -band [int][System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0)
    $appliesToDescendants = ($Ace.InheritanceType.ToString() -ne 'None')
    $classIsRelevant = ($inheritedType -eq $script:EmptyGuid) -or $script:UpnClassGuids.ContainsKey($inheritedType)

    $isFullControl = (($rights -band [int]$rightsEnum::GenericAll) -eq [int]$rightsEnum::GenericAll)
    $canWriteProperty = (($rights -band [int]$rightsEnum::WriteProperty) -ne 0)

    $direct = $null
    if ($isFullControl) { $direct = 'Full Control' }
    elseif ($canWriteProperty -and $objectType -eq $script:EmptyGuid) { $direct = 'Write all properties' }
    elseif ($canWriteProperty -and $objectType -eq $script:UpnAttributeGuid) { $direct = 'Write userPrincipalName' }
    elseif ($canWriteProperty -and $objectType -eq $script:UpnPropertySetGuid) { $direct = 'Write property set that contains userPrincipalName' }

    $scope = @()
    if ($TargetIsPrincipal -and $appliesToSelf) { $scope += 'this object' }
    if ($appliesToDescendants -and $classIsRelevant) { $scope += 'descendant objects' }

    if ($direct -and $scope.Count -gt 0) {
        return ('Direct - {0} on {1}' -f $direct, ($scope -join ' and '))
    }

    if (-not $appliesToSelf -and -not $classIsRelevant) {
        return 'No (scoped to an object class that has no UPN)'
    }

    if ($isFullControl) {
        return 'Indirect - Full Control of the container itself (can change its ACL and create child objects)'
    }
    if (($rights -band [int]$rightsEnum::WriteDacl) -ne 0) {
        return 'Indirect - WriteDacl (can grant itself UPN write)'
    }
    if (($rights -band [int]$rightsEnum::WriteOwner) -ne 0) {
        return 'Indirect - WriteOwner (can take ownership, then change the ACL)'
    }
    if ((($rights -band [int]$rightsEnum::CreateChild) -ne 0) -and (($objectType -eq $script:EmptyGuid) -or $script:UpnClassGuids.ContainsKey($objectType))) {
        return 'Indirect - CreateChild (can create user or computer objects with any UPN)'
    }
    return 'No'
}

function ConvertTo-RightsFlag {
    param([string]$Permissions)
    if ([string]::IsNullOrWhiteSpace($Permissions)) { return $null }
    $text = $Permissions.Trim()
    try {
        return [int][Enum]::Parse([System.DirectoryServices.ActiveDirectoryRights], $text, $true)
    }
    catch { }
    $lookup = ($text -replace '\s', '').ToLower()
    $spaced = $text.ToLower()
    $mapped = $null
    if ($script:PermissionAliases.ContainsKey($spaced)) { $mapped = $script:PermissionAliases[$spaced] }
    elseif ($script:PermissionAliases.ContainsKey($lookup)) { $mapped = $script:PermissionAliases[$lookup] }
    if ($mapped) {
        try {
            return [int][Enum]::Parse([System.DirectoryServices.ActiveDirectoryRights], $mapped, $true)
        }
        catch { }
    }
    return $null
}

function Test-AppliesToMatchesAce {
    param([string]$AppliesTo, $Ace)
    if ([string]::IsNullOrWhiteSpace($AppliesTo)) { return $true }

    $text = $AppliesTo.Trim()
    $inherit = $Ace.InheritanceType.ToString()
    $inheritedGuid = $Ace.InheritedObjectType.ToString()
    $inheritedName = ''
    if ($inheritedGuid -ne $script:EmptyGuid) {
        $inheritedName = (Resolve-ObjectTypeGuid -Guid $Ace.InheritedObjectType -Rights ([System.DirectoryServices.ActiveDirectoryRights]::CreateChild)).Name
    }

    if ($text -eq 'This object only') {
        return ($inherit -eq 'None')
    }

    $classMatch = [regex]::Match($text, '(?i)descendant\s+(\S+)\s+objects')
    $wantedClass = $null
    if ($classMatch.Success) { $wantedClass = $classMatch.Groups[1].Value }

    $wantsThisObject = $text -match '(?i)^this object'
    $wantsDescendants = $text -match '(?i)descendant'

    if ($wantsThisObject -and -not $wantsDescendants) {
        return ($inherit -eq 'None')
    }
    if ($wantsDescendants -and $inherit -eq 'None') {
        return $false
    }
    if ($wantedClass -and $inheritedName -and ($inheritedName -ne 'All') -and ($inheritedName -ine $wantedClass)) {
        return $false
    }
    return $true
}

function Test-FindingMatchesAce {
    param([string]$Permissions, [string]$Attribute, [string]$AppliesTo, $Ace)

    if ($Ace.AccessControlType.ToString() -ne 'Allow') { return $false }

    $flag = ConvertTo-RightsFlag -Permissions $Permissions
    if ($null -eq $flag) { return $false }
    if (([int]$Ace.ActiveDirectoryRights -band $flag) -ne $flag) { return $false }

    $expectedGuid = $script:EmptyGuid
    $guidMatch = [regex]::Match([string]$Attribute, '\(([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\)')
    if ($guidMatch.Success) {
        $expectedGuid = $guidMatch.Groups[1].Value.ToLower()
    }
    if ($Ace.ObjectType.ToString() -ne $expectedGuid) { return $false }

    return (Test-AppliesToMatchesAce -AppliesTo $AppliesTo -Ace $Ace)
}

function Get-DirObject {
    param([string]$Identity)

    if ([string]::IsNullOrWhiteSpace($Identity)) { return $null }
    $key = $Identity.ToLower()
    if ($script:ObjectCache.ContainsKey($key)) { return $script:ObjectCache[$key] }

    $result = $null
    try {
        $splat = Get-AdSplat -TargetServer $script:ReportServer
        $object = Get-ADObject -Identity $Identity -Properties nTSecurityDescriptor, whenCreated, whenChanged -ErrorAction Stop @splat
        $descriptor = ConvertTo-ActiveDirectorySecurity -Descriptor $object.nTSecurityDescriptor

        if ($null -eq $descriptor) {
            try {
                if (-not (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
                    $null = Get-ADRootDSE -ErrorAction SilentlyContinue @splat
                }
                $acl = Get-Acl -Path ('AD:{0}' -f $object.DistinguishedName) -ErrorAction Stop
                $descriptor = ConvertTo-ActiveDirectorySecurity -Descriptor $acl
                if ($null -eq $descriptor -and $acl) { $descriptor = $acl }
            }
            catch { }
        }

        $rules = @()
        $ownerSid = $null
        $inheritanceBlocked = $null
        $readable = $false
        if ($null -ne $descriptor) {
            $readable = $true
            $rules = @($descriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
            $inheritanceBlocked = $descriptor.AreAccessRulesProtected
            try { $ownerSid = $descriptor.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { }
        }

        $result = [PSCustomObject]@{
            DN                 = $object.DistinguishedName
            Guid               = $object.ObjectGUID.ToString()
            Class              = $object.ObjectClass
            WhenCreated        = $object.whenCreated
            WhenChanged        = $object.whenChanged
            OwnerSid           = $ownerSid
            InheritanceBlocked = $inheritanceBlocked
            SdReadable         = $readable
            Rules              = $rules
        }
        $script:ObjectCache[$result.DN.ToLower()] = $result
        $script:ObjectCache[$result.Guid.ToLower()] = $result
    }
    catch {
        Write-Verbose ('Lookup failed for {0} - {1}' -f $Identity, $_.Exception.Message)
    }

    $script:ObjectCache[$key] = $result
    return $result
}

function Find-AceSource {
    param([string]$TargetDN, $Ace)

    $sid = $Ace.IdentityReference.Value
    $dn = Get-ParentDN -DN $TargetDN
    while ($dn) {
        $parent = Get-DirObject -Identity $dn
        if ($parent) {
            foreach ($rule in $parent.Rules) {
                if (-not $rule.IsInherited -and
                    $rule.IdentityReference.Value -eq $sid -and
                    $rule.AccessControlType -eq $Ace.AccessControlType -and
                    $rule.ActiveDirectoryRights -eq $Ace.ActiveDirectoryRights -and
                    $rule.ObjectType -eq $Ace.ObjectType -and
                    $rule.InheritedObjectType -eq $Ace.InheritedObjectType -and
                    $rule.InheritanceType.ToString() -ne 'None') {
                    return $parent.DN
                }
            }
        }
        if ($dn -match '^DC=') { break }
        $dn = Get-ParentDN -DN $dn
    }
    return $null
}

function Get-SdMetadata {
    param([string]$DN)

    $key = $DN.ToLower()
    if ($script:SdMetadataCache.ContainsKey($key)) { return $script:SdMetadataCache[$key] }

    $result = [PSCustomObject]@{ LastChanged = $null; ChangedOnDC = ''; Version = '' }
    try {
        $splat = Get-AdSplat -TargetServer $script:ReportServer
        $metadata = Get-ADReplicationAttributeMetadata -Object $DN -Properties nTSecurityDescriptor -ErrorAction Stop @splat |
            Select-Object -First 1
        if ($metadata) {
            $originatingDc = [string]$metadata.LastOriginatingChangeDirectoryServerIdentity
            $dcMatch = [regex]::Match($originatingDc, '^CN=NTDS Settings,CN=([^,]+),')
            if ($dcMatch.Success) { $originatingDc = $dcMatch.Groups[1].Value }
            $result = [PSCustomObject]@{
                LastChanged = $metadata.LastOriginatingChangeTime
                ChangedOnDC = $originatingDc
                Version     = $metadata.Version
            }
        }
    }
    catch {
        Write-Verbose ('Replication metadata not available for {0} - {1}' -f $DN, $_.Exception.Message)
    }

    $script:SdMetadataCache[$key] = $result
    return $result
}

function Get-ScopeCount {
    param([string]$DN, [string]$SearchScope)

    $key = ('{0}|{1}' -f $SearchScope, $DN).ToLower()
    if ($script:ScopeCountCache.ContainsKey($key)) { return $script:ScopeCountCache[$key] }

    $result = [PSCustomObject]@{ Users = ''; Computers = '' }
    try {
        $splat = Get-AdSplat -TargetServer $script:ReportServer
        $users = @(Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user))' -SearchBase $DN -SearchScope $SearchScope -ErrorAction Stop @splat).Count
        $computers = @(Get-ADObject -LDAPFilter '(objectCategory=computer)' -SearchBase $DN -SearchScope $SearchScope -ErrorAction Stop @splat).Count
        $result = [PSCustomObject]@{ Users = $users; Computers = $computers }
    }
    catch {
        Write-Verbose ('Scope count failed for {0} - {1}' -f $DN, $_.Exception.Message)
    }

    $script:ScopeCountCache[$key] = $result
    return $result
}

function Find-AdObjectBySid {
    param([string]$Sid, [string]$TargetServer, [string]$Attribute = 'objectSid', [switch]$Deleted)

    $splat = Get-AdSplat -TargetServer $TargetServer
    $filter = '({0}={1})' -f $Attribute, $Sid
    if ($Deleted) {
        $splat['IncludeDeletedObjects'] = $true
        $filter = '(&(isDeleted=TRUE){0})' -f $filter
    }
    try {
        return (Get-ADObject -LDAPFilter $filter -Properties $script:TrusteeProperties -ErrorAction Stop @splat | Select-Object -First 1)
    }
    catch {
        Write-Verbose ('SID search ({0}) failed on {1} - {2}' -f $Attribute, $TargetServer, $_.Exception.Message)
        return $null
    }
}

function Resolve-TrusteeSid {
    param([string]$Identity)

    if ([string]::IsNullOrWhiteSpace($Identity)) { return $null }
    if ($Identity -match '^S-1-\d+(-\d+)+$') { return $Identity }

    try {
        return ([System.Security.Principal.NTAccount]$Identity).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch { }

    $parts = $Identity -split '\\', 2
    if ($parts.Count -eq 2 -and $script:DomainsByNetBios.ContainsKey($parts[0].ToUpper())) {
        $domainInfo = $script:DomainsByNetBios[$parts[0].ToUpper()]
        try {
            $splat = Get-AdSplat -TargetServer $domainInfo.Server
            $filter = '(sAMAccountName={0})' -f (ConvertTo-LdapFilterValue -Value $parts[1])
            $found = Get-ADObject -LDAPFilter $filter -Properties objectSid -ErrorAction Stop @splat | Select-Object -First 1
            if ($found -and $found.objectSid) { return $found.objectSid.Value }
        }
        catch {
            Write-Verbose ('Name lookup failed for {0} - {1}' -f $Identity, $_.Exception.Message)
        }
    }
    return $null
}

function Get-TrusteeInfo {
    param([string]$Sid)

    if ($script:TrusteeCache.ContainsKey($Sid)) { return $script:TrusteeCache[$Sid] }

    $info = [PSCustomObject]@{
        Sid               = $Sid
        Name              = $Sid
        SamAccountName    = ''
        Type              = 'Unknown'
        Status            = ''
        Domain            = ''
        DistinguishedName = ''
        Enabled           = 'N/A'
        Description       = ''
        WhenCreated       = $null
        WhenChanged       = $null
        LastLogon         = $null
        PasswordLastSet   = $null
        AdminCount        = ''
        MemberOf          = ''
        EffectiveMembers  = ''
        LookupServer      = ''
    }
    $script:TrusteeCache[$Sid] = $info

    $translated = $null
    try {
        $translated = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
    }
    catch { }
    if ($translated) { $info.Name = $translated }

    if ($Sid -notmatch '^S-1-5-21-') {
        $info.Type = 'WellKnown'
        $info.Status = 'Well-known security principal'
        if ($Sid -eq 'S-1-5-11') { $info.EffectiveMembers = 'Every authenticated user and computer' }
        if ($Sid -eq 'S-1-1-0') { $info.EffectiveMembers = 'Everyone' }
        if ($Sid -eq 'S-1-5-10') { $info.EffectiveMembers = 'The object itself' }
        if ($Sid -eq 'S-1-5-7') { $info.EffectiveMembers = 'Anonymous logon' }
        return $info
    }

    $domainSid = $Sid.Substring(0, $Sid.LastIndexOf('-'))
    $domainInfo = $script:DomainsBySid[$domainSid]
    $localDomain = $script:DomainsBySid[$script:LocalDomainSid]
    $object = $null

    if ($domainInfo) {
        $info.Domain = $domainInfo.NetBios
        $info.LookupServer = $domainInfo.Server
        $object = Find-AdObjectBySid -Sid $Sid -TargetServer $domainInfo.Server
        if ($object) { $info.Status = 'Resolved' }
    }

    if (-not $object -and $localDomain) {
        $object = Find-AdObjectBySid -Sid $Sid -TargetServer $localDomain.Server -Attribute 'sIDHistory'
        if ($object) {
            $info.Status = 'Resolved through SIDHistory (SID belongs to a migrated account)'
            $info.Domain = $localDomain.NetBios
            $info.LookupServer = $localDomain.Server
        }
    }

    if (-not $object -and $localDomain -and $domainSid -eq $script:LocalDomainSid) {
        $object = Find-AdObjectBySid -Sid $Sid -TargetServer $localDomain.Server -Deleted
        if ($object) {
            $info.Status = 'Deleted object (deleted about {0}; last parent: {1})' -f (Format-ReportDate $object.whenChanged), $object.lastKnownParent
        }
    }

    if (-not $object -and -not $domainInfo -and $localDomain) {
        $globalCatalog = '{0}:3268' -f $localDomain.Server
        $object = Find-AdObjectBySid -Sid $Sid -TargetServer $globalCatalog
        if ($object) {
            $info.Status = 'Resolved through the global catalog'
            $info.LookupServer = $globalCatalog
        }
    }

    if (-not $object) {
        if ($domainSid -eq $script:LocalDomainSid) {
            $info.Type = 'Orphaned'
            $info.Status = 'Orphaned SID - no live or deleted object in this domain (account was removed)'
        }
        elseif ($domainInfo) {
            $info.Status = 'Not resolved - no matching object found in trusted domain {0}' -f $domainInfo.Dns
        }
        else {
            $info.Status = 'Not resolved - SID is from an unknown or no longer trusted domain'
        }
        return $info
    }

    $info.SamAccountName = [string]$object.sAMAccountName
    $info.Type = [string]$object.ObjectClass
    $info.DistinguishedName = [string]$object.DistinguishedName
    $info.Description = (@($object.description) -join '; ')
    $info.WhenCreated = $object.whenCreated
    $info.WhenChanged = $object.whenChanged
    $info.LastLogon = ConvertFrom-FileTimeValue -Value $object.lastLogonTimestamp
    $info.PasswordLastSet = ConvertFrom-FileTimeValue -Value $object.pwdLastSet
    $info.AdminCount = [string]$object.adminCount
    $info.MemberOf = (@($object.memberOf | ForEach-Object { Get-RdnValue -DN $_ }) -join '; ')
    if ($info.Type -ne 'group') { $info.Enabled = Get-EnabledState -UserAccountControl $object.userAccountControl }

    if (-not $translated -and $info.SamAccountName) {
        if ($info.Domain) { $info.Name = '{0}\{1}' -f $info.Domain, $info.SamAccountName }
        else { $info.Name = $info.SamAccountName }
    }
    if ($object.isDeleted) { $info.Type = 'Deleted {0}' -f $object.ObjectClass }

    return $info
}

function Get-EffectiveGroupMembers {
    param($Trustee)

    $rows = @()
    try {
        $splat = Get-AdSplat -TargetServer $Trustee.LookupServer
        $filter = '(memberOf:1.2.840.113556.1.4.1941:={0})' -f (ConvertTo-LdapFilterValue -Value $Trustee.DistinguishedName)
        $members = @(Get-ADObject -LDAPFilter $filter -Properties $script:TrusteeProperties -ErrorAction Stop @splat)
        foreach ($member in $members) {
            $enabled = 'N/A'
            if ($member.ObjectClass -ne 'group') { $enabled = Get-EnabledState -UserAccountControl $member.userAccountControl }
            $rows += [PSCustomObject]@{
                Group                   = $Trustee.Name
                GroupSid                = $Trustee.Sid
                MemberSamAccountName    = [string]$member.sAMAccountName
                MemberDisplayName       = [string]$member.displayName
                MemberObjectClass       = [string]$member.ObjectClass
                MemberEnabled           = $enabled
                MemberLastLogon         = Format-ReportDate (ConvertFrom-FileTimeValue -Value $member.lastLogonTimestamp)
                MemberPasswordLastSet   = Format-ReportDate (ConvertFrom-FileTimeValue -Value $member.pwdLastSet)
                MemberWhenCreated       = Format-ReportDate $member.whenCreated
                MemberAdminCount        = [string]$member.adminCount
                MemberDistinguishedName = [string]$member.DistinguishedName
            }
        }
    }
    catch {
        Write-AuditStatus -Message ('Could not expand group {0} - {1}' -f $Trustee.Name, $_.Exception.Message) -Color 'Yellow'
    }
    return $rows
}

function Reset-AuditCaches {
    $script:ObjectCache = @{}
    $script:TrusteeCache = @{}
    $script:SdMetadataCache = @{}
    $script:ScopeCountCache = @{}
    $script:DomainsBySid = @{}
    $script:DomainsByNetBios = @{}
    $script:SchemaGuidMap = @{}
    $script:RightsGuidMap = @{}
    $script:UpnClassGuids = @{}
}

function Import-ActiveDirectoryModule {
    if (Get-Module -Name ActiveDirectory) { return }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        throw "The ActiveDirectory PowerShell module is not installed or could not be loaded. Install RSAT or run this on a domain controller. $($_.Exception.Message)"
    }
    Add-Type -AssemblyName System.DirectoryServices
}

#endregion AD helpers

#region Engine

function Invoke-UpnDelegationAudit {
    param(
        [Parameter(Mandatory = $true)][string]$CsvPath,
        [string]$OutputPath,
        [string]$Server,
        [AllowNull()]
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$SkipGroupExpansion,
        [switch]$SkipScopeCount,
        [switch]$SearchEventLogs,
        [int]$EventLogDays = 30
    )

    Reset-AuditCaches
    $script:ReportServer = $Server
    $script:ReportCredential = $Credential

    Import-ActiveDirectoryModule

    if (-not $OutputPath) { $OutputPath = Get-DefaultOutputPath }
    $script:LastOutputPath = $OutputPath

    Write-AuditStatus -Message 'Connecting to Active Directory...' -Color 'Cyan' -Percent 1 -Activity 'Connecting'

    $initialSplat = Get-AdSplat -TargetServer $script:ReportServer
    $domain = Get-ADDomain -ErrorAction Stop @initialSplat
    if (-not $script:ReportServer) { $script:ReportServer = $domain.PDCEmulator }

    $script:LocalDomainSid = $domain.DomainSID.Value
    $localDomainInfo = [PSCustomObject]@{ NetBios = $domain.NetBIOSName; Dns = $domain.DNSRoot; Server = $script:ReportServer }
    $script:DomainsBySid[$script:LocalDomainSid] = $localDomainInfo
    $script:DomainsByNetBios[$domain.NetBIOSName.ToUpper()] = $localDomainInfo

    $adSplat = Get-AdSplat -TargetServer $script:ReportServer

    try {
        $trusts = @(Get-ADObject -SearchBase ('CN=System,{0}' -f $domain.DistinguishedName) -LDAPFilter '(objectClass=trustedDomain)' -Properties flatName, trustPartner, securityIdentifier -ErrorAction Stop @adSplat)
        foreach ($trust in $trusts) {
            $trustSid = $trust.securityIdentifier
            if ($trustSid -is [byte[]]) { $trustSid = New-Object System.Security.Principal.SecurityIdentifier($trustSid, 0) }
            if (-not $trustSid) { continue }
            $trustInfo = [PSCustomObject]@{ NetBios = [string]$trust.flatName; Dns = [string]$trust.trustPartner; Server = [string]$trust.trustPartner }
            $script:DomainsBySid[[string]$trustSid] = $trustInfo
            if ($trustInfo.NetBios) { $script:DomainsByNetBios[$trustInfo.NetBios.ToUpper()] = $trustInfo }
        }
    }
    catch {
        Write-AuditStatus -Message ('Could not read domain trusts - {0}' -f $_.Exception.Message) -Color 'Yellow'
    }

    Write-AuditStatus -Message ('  Domain: {0} ({1})   Server: {2}   Trusted domains: {3}' -f $domain.DNSRoot, $domain.NetBIOSName, $script:ReportServer, ($script:DomainsBySid.Count - 1)) -Color 'White'
    Write-AuditStatus -Message 'Loading schema and extended rights GUIDs...' -Color 'Cyan' -Percent 5

    $rootDse = Get-ADRootDSE -ErrorAction Stop @adSplat
    $schemaNC = $rootDse.schemaNamingContext
    $configNC = $rootDse.configurationNamingContext

    $script:UpnAttributeGuid = '28630ebb-41d5-11d1-a9c1-0000f80367c1'
    $script:UpnPropertySetGuid = 'e48d0154-bcf8-11d1-8702-00c04fb96050'

    Get-ADObject -SearchBase $schemaNC -LDAPFilter '(schemaIDGUID=*)' -Properties lDAPDisplayName, schemaIDGUID, attributeSecurityGUID -ErrorAction Stop @adSplat |
        ForEach-Object {
            $guid = (New-Object Guid (, [byte[]]$_.schemaIDGUID)).ToString()
            $kind = 'Attribute'
            if ($_.ObjectClass -eq 'classSchema') { $kind = 'Class' }
            $script:SchemaGuidMap[$guid] = [PSCustomObject]@{ Name = [string]$_.lDAPDisplayName; Kind = $kind }

            if ($kind -eq 'Class' -and $script:UpnClassNames -contains $_.lDAPDisplayName) { $script:UpnClassGuids[$guid] = $true }
            if ($_.lDAPDisplayName -eq 'userPrincipalName') {
                $script:UpnAttributeGuid = $guid
                if ($_.attributeSecurityGUID) {
                    $script:UpnPropertySetGuid = (New-Object Guid (, [byte[]]$_.attributeSecurityGUID)).ToString()
                }
            }
        }

    Get-ADObject -SearchBase ('CN=Extended-Rights,{0}' -f $configNC) -LDAPFilter '(rightsGuid=*)' -Properties displayName, rightsGuid, validAccesses -ErrorAction Stop @adSplat |
        ForEach-Object {
            $guid = ([string]$_.rightsGuid).ToLower()
            $kind = 'Extended right'
            if ([int]$_.validAccesses -eq 48) { $kind = 'Property set' }
            elseif ([int]$_.validAccesses -eq 8) { $kind = 'Validated write' }

            $name = [string]$_.displayName
            if (-not $name) { $name = [string]$_.Name }
            if ($script:RightsGuidMap.ContainsKey($guid)) {
                $script:RightsGuidMap[$guid].Name = '{0} / {1}' -f $script:RightsGuidMap[$guid].Name, $name
            }
            else {
                $script:RightsGuidMap[$guid] = [PSCustomObject]@{ Name = $name; Kind = $kind }
            }
        }

    Write-AuditStatus -Message ('  {0} schema GUIDs, {1} rights GUIDs' -f $script:SchemaGuidMap.Count, $script:RightsGuidMap.Count) -Color 'White' -Percent 10

    $rows = @(Import-SemperisCsv -Path $CsvPath)
    Write-AuditStatus -Message ('Processing {0} findings from {1}...' -f $rows.Count, (Split-Path -Path $CsvPath -Leaf)) -Color 'Cyan' -Percent 12 -Activity 'Reading live ACLs'

    $findingRows = New-Object System.Collections.Generic.List[object]
    $pairs = @{}
    $flaggedSidMap = @{}
    $rowNumber = 0

    foreach ($row in $rows) {
        $rowNumber++
        $pct = 12 + [int](($rowNumber / [Math]::Max(1, $rows.Count)) * 40)
        Write-AuditStatus -Message ('Finding {0} of {1}' -f $rowNumber, $rows.Count) -Color 'Gray' -Percent $pct -Activity 'Reading live ACLs'

        $findingDn = (Get-RowField -Row $row -LogicalName 'DistinguishedName').Trim()
        $findingGuid = (Get-RowField -Row $row -LogicalName 'ObjectGuid').Trim()
        $findingIdentity = (Get-RowField -Row $row -LogicalName 'Identity').Trim()
        $findingPermissions = (Get-RowField -Row $row -LogicalName 'Permissions').Trim()
        $findingAttribute = (Get-RowField -Row $row -LogicalName 'Attribute').Trim()
        $findingAppliesTo = (Get-RowField -Row $row -LogicalName 'AppliesTo').Trim()
        $findingClass = (Get-RowField -Row $row -LogicalName 'ObjectClass').Trim()
        $findingIgnored = (Get-RowField -Row $row -LogicalName 'Ignored').Trim()

        $target = $null
        if ($findingGuid) { $target = Get-DirObject -Identity $findingGuid }
        if (-not $target -and $findingDn) { $target = Get-DirObject -Identity $findingDn }

        $sid = Resolve-TrusteeSid -Identity $findingIdentity
        $trustee = $null
        if ($sid) {
            $trustee = Get-TrusteeInfo -Sid $sid
            $flaggedSidMap[$sid] = $true
        }

        $status = ''
        $matchCount = 0
        $trusteeAceCount = 0

        if (-not $target) {
            $status = 'Target object not found (deleted, in another domain, or not readable)'
        }
        elseif (-not $target.SdReadable) {
            $status = 'Target found but its ACL could not be read (insufficient rights)'
        }
        elseif (-not $sid) {
            $status = 'Trustee name could not be resolved to a SID'
        }
        else {
            $pairKey = '{0}|{1}' -f $target.Guid, $sid
            if (-not $pairs.ContainsKey($pairKey)) {
                $pairs[$pairKey] = [PSCustomObject]@{
                    Target  = $target
                    Sid     = $sid
                    Aces    = @($target.Rules | Where-Object { $_.IdentityReference.Value -eq $sid })
                    Matched = @{}
                }
            }
            $pair = $pairs[$pairKey]
            $trusteeAceCount = $pair.Aces.Count

            for ($index = 0; $index -lt $pair.Aces.Count; $index++) {
                if (Test-FindingMatchesAce -Permissions $findingPermissions -Attribute $findingAttribute -AppliesTo $findingAppliesTo -Ace $pair.Aces[$index]) {
                    $pair.Matched[$index] = $true
                    $matchCount++
                }
            }

            if ($matchCount -gt 0) { $status = 'Confirmed - ACE is present in the live ACL' }
            elseif ($trusteeAceCount -gt 0) { $status = 'Not matched - trustee holds other ACEs on this object (see detail report)' }
            else { $status = 'Not present - trustee has no ACE on this object (remediated or changed)' }
        }

        $trusteeName = $findingIdentity
        $trusteeStatus = ''
        if ($trustee) {
            $trusteeName = $trustee.Name
            $trusteeStatus = $trustee.Status
        }
        $liveDn = ''
        if ($target) { $liveDn = $target.DN }

        $findingRows.Add([PSCustomObject]@{
                Row                  = $rowNumber
                Status               = $status
                MatchingLiveAces     = $matchCount
                TrusteeAcesOnObject  = $trusteeAceCount
                Semperis_DN          = $findingDn
                Semperis_ObjectGuid  = $findingGuid
                Semperis_ObjectClass = $findingClass
                Semperis_Identity    = $findingIdentity
                Semperis_Permissions = $findingPermissions
                Semperis_AppliesTo   = $findingAppliesTo
                Semperis_Attribute   = $findingAttribute
                Semperis_Ignored     = $findingIgnored
                Live_DN              = $liveDn
                Trustee_Resolved     = $trusteeName
                Trustee_Sid          = [string]$sid
                Trustee_Status       = $trusteeStatus
            })
    }
    Complete-AuditProgress -Activity 'Reading live ACLs'

    $flaggedSids = @($flaggedSidMap.Keys)

    $groupMemberRows = New-Object System.Collections.Generic.List[object]
    if (-not $SkipGroupExpansion) {
        $groupTrustees = @($flaggedSids | ForEach-Object { $script:TrusteeCache[$_] } | Where-Object { $_.Type -eq 'group' -and $_.DistinguishedName })
        if ($groupTrustees.Count -gt 0) {
            Write-AuditStatus -Message ('Expanding {0} group trustee(s)...' -f $groupTrustees.Count) -Color 'Cyan' -Percent 55
        }
        $gIndex = 0
        foreach ($groupTrustee in $groupTrustees) {
            $gIndex++
            Write-AuditStatus -Message ('  Group {0} of {1}: {2}' -f $gIndex, $groupTrustees.Count, $groupTrustee.Name) -Color 'Gray' -Percent (55 + [int](($gIndex / [Math]::Max(1, $groupTrustees.Count)) * 8))
            $members = @(Get-EffectiveGroupMembers -Trustee $groupTrustee)
            foreach ($member in $members) { $groupMemberRows.Add($member) }
            $groupTrustee.EffectiveMembers = [string]@($members | Where-Object { $_.MemberObjectClass -ne 'group' }).Count
        }
    }

    Write-AuditStatus -Message 'Building the who / what / where / when report...' -Color 'Cyan' -Percent 64 -Activity 'Analysing ACEs'

    $detailRows = New-Object System.Collections.Generic.List[object]
    $pairNumber = 0
    $pairTotal = [Math]::Max(1, $pairs.Count)

    foreach ($pair in $pairs.Values) {
        $pairNumber++
        Write-AuditStatus -Message $pair.Target.DN -Color 'Gray' -Percent (64 + [int](($pairNumber / $pairTotal) * 20)) -Activity 'Analysing ACEs'

        $target = $pair.Target
        $trustee = Get-TrusteeInfo -Sid $pair.Sid
        $targetIsPrincipal = ($script:UpnClassNames -contains $target.Class)

        $ownerName = ''
        if ($target.OwnerSid) { $ownerName = (Get-TrusteeInfo -Sid $target.OwnerSid).Name }

        for ($index = 0; $index -lt $pair.Aces.Count; $index++) {
            $ace = $pair.Aces[$index]
            $objectType = Resolve-ObjectTypeGuid -Guid $ace.ObjectType -Rights $ace.ActiveDirectoryRights

            $inheritedTypeName = 'All'
            if ($ace.InheritedObjectType.ToString() -ne $script:EmptyGuid) {
                $inheritedTypeName = (Resolve-ObjectTypeGuid -Guid $ace.InheritedObjectType -Rights ([System.DirectoryServices.ActiveDirectoryRights]::CreateChild)).Name
            }

            $sourceDn = $target.DN
            if ($ace.IsInherited) { $sourceDn = Find-AceSource -TargetDN $target.DN -Ace $ace }

            $sourceLabel = $sourceDn
            $metadata = [PSCustomObject]@{ LastChanged = $null; ChangedOnDC = ''; Version = '' }
            if ($sourceDn) { $metadata = Get-SdMetadata -DN $sourceDn }
            else { $sourceLabel = 'Unknown (no matching explicit ACE found on a parent)' }

            $usersInScope = ''
            $computersInScope = ''
            if (-not $SkipScopeCount -and -not $targetIsPrincipal -and $ace.InheritanceType.ToString() -ne 'None') {
                $searchScope = 'Subtree'
                if ($ace.InheritanceType.ToString() -in @('Children', 'SelfAndChildren')) { $searchScope = 'OneLevel' }
                $counts = Get-ScopeCount -DN $target.DN -SearchScope $searchScope
                $usersInScope = $counts.Users
                $computersInScope = $counts.Computers
            }

            $detailRows.Add([PSCustomObject]@{
                    Who_Trustee                   = $trustee.Name
                    Who_TrusteeSid                = $trustee.Sid
                    Who_TrusteeType               = $trustee.Type
                    Who_TrusteeStatus             = $trustee.Status
                    Who_TrusteeEnabled            = $trustee.Enabled
                    Who_TrusteeLastLogon          = Format-ReportDate $trustee.LastLogon
                    Who_EffectiveMembers          = $trustee.EffectiveMembers
                    Who_TrusteeDescription        = $trustee.Description

                    What_AccessType               = $ace.AccessControlType.ToString()
                    What_Rights                   = $ace.ActiveDirectoryRights.ToString()
                    What_ObjectType               = $objectType.Name
                    What_ObjectTypeKind           = $objectType.Kind
                    What_ObjectTypeGuid           = $ace.ObjectType.ToString()
                    What_AppliesTo                = Get-AppliesToText -Ace $ace
                    What_AppliesToClass           = $inheritedTypeName
                    What_UpnChangeAssessment      = Get-UpnWriteAssessment -Ace $ace -TargetIsPrincipal $targetIsPrincipal
                    What_ListedInSemperisFinding  = [bool]$pair.Matched.ContainsKey($index)

                    Where_TargetDN                = $target.DN
                    Where_TargetClass             = $target.Class
                    Where_AceIsInherited          = $ace.IsInherited
                    Where_AceSetOnDN              = $sourceLabel
                    Where_UsersInScope            = $usersInScope
                    Where_ComputersInScope        = $computersInScope
                    Where_TargetOwner             = $ownerName
                    Where_TargetBlocksInheritance = $target.InheritanceBlocked

                    When_AclLastChanged           = Format-ReportDate $metadata.LastChanged
                    When_AclChangedOnDC           = $metadata.ChangedOnDC
                    When_AclVersion               = $metadata.Version
                    When_TargetCreated            = Format-ReportDate $target.WhenCreated
                    When_TargetLastChanged        = Format-ReportDate $target.WhenChanged
                    When_TrusteeCreated           = Format-ReportDate $trustee.WhenCreated
                    When_TrusteeLastChanged       = Format-ReportDate $trustee.WhenChanged
                })
        }
    }
    Complete-AuditProgress -Activity 'Analysing ACEs'

    $trusteeRows = @($flaggedSids | ForEach-Object {
            $trustee = $script:TrusteeCache[$_]
            $sid = $_
            $trusteeDetail = @($detailRows | Where-Object { $_.Who_TrusteeSid -eq $sid })
            [PSCustomObject]@{
                Trustee             = $trustee.Name
                Sid                 = $trustee.Sid
                Type                = $trustee.Type
                Status              = $trustee.Status
                Domain              = $trustee.Domain
                Enabled             = $trustee.Enabled
                Description         = $trustee.Description
                EffectiveMembers    = $trustee.EffectiveMembers
                AdminCount          = $trustee.AdminCount
                MemberOf            = $trustee.MemberOf
                LastLogon           = Format-ReportDate $trustee.LastLogon
                PasswordLastSet     = Format-ReportDate $trustee.PasswordLastSet
                WhenCreated         = Format-ReportDate $trustee.WhenCreated
                WhenChanged         = Format-ReportDate $trustee.WhenChanged
                ObjectsWithAces     = @($trusteeDetail | Select-Object -ExpandProperty Where_TargetDN -Unique).Count
                TotalAces           = $trusteeDetail.Count
                DirectUpnChangeAces = @($trusteeDetail | Where-Object { $_.What_UpnChangeAssessment -like 'Direct*' }).Count
                DistinguishedName   = $trustee.DistinguishedName
            }
        })

    $eventRows = New-Object System.Collections.Generic.List[object]
    if ($SearchEventLogs) {
        Write-AuditStatus -Message ('Searching domain controller Security logs for ACL changes (last {0} days)...' -f $EventLogDays) -Color 'Cyan' -Percent 86

        $watchedDns = @{}
        foreach ($detail in $detailRows) {
            foreach ($dn in @($detail.Where_TargetDN, $detail.Where_AceSetOnDN)) {
                if ($dn -and $dn -notlike 'Unknown*') { $watchedDns[$dn.ToLower()] = $true }
            }
        }

        $milliseconds = [int64]$EventLogDays * 86400000
        $xpath = "*[System[(EventID=5136) and TimeCreated[timediff(@SystemTime) <= $milliseconds]]] and *[EventData[Data[@Name='AttributeLDAPDisplayName']='nTSecurityDescriptor']]"
        $operationNames = @{ '%%14674' = 'Value Added'; '%%14675' = 'Value Deleted' }

        $domainControllers = @()
        try { $domainControllers = @(Get-ADDomainController -Filter * -ErrorAction Stop @adSplat) }
        catch { Write-AuditStatus -Message ('Could not list domain controllers - {0}' -f $_.Exception.Message) -Color 'Yellow' }

        $dcIndex = 0
        foreach ($domainController in $domainControllers) {
            $dcIndex++
            Write-AuditStatus -Message ('  {0}' -f $domainController.HostName) -Color 'White' -Percent (86 + [int](($dcIndex / [Math]::Max(1, $domainControllers.Count)) * 8))
            $eventSplat = @{ ComputerName = $domainController.HostName; LogName = 'Security'; FilterXPath = $xpath; ErrorAction = 'Stop' }
            if ($script:ReportCredential) { $eventSplat['Credential'] = $script:ReportCredential }

            $events = @()
            try { $events = @(Get-WinEvent @eventSplat) }
            catch {
                if ($_.Exception.Message -notmatch 'No events were found') {
                    Write-AuditStatus -Message ('Could not read the Security log on {0} - {1}' -f $domainController.HostName, $_.Exception.Message) -Color 'Yellow'
                }
            }

            foreach ($event in $events) {
                $data = @{}
                foreach ($node in ([xml]$event.ToXml()).Event.EventData.Data) { $data[$node.Name] = [string]$node.'#text' }

                $objectDn = [string]$data['ObjectDN']
                if (-not $objectDn -or -not $watchedDns.ContainsKey($objectDn.ToLower())) { continue }

                $sddl = [string]$data['AttributeValue']
                $trusteesInValue = @($flaggedSids | Where-Object { $sddl -like ('*{0}*' -f $_) } | ForEach-Object { $script:TrusteeCache[$_].Name })
                $operation = [string]$data['OperationType']
                if ($operationNames.ContainsKey($operation)) { $operation = $operationNames[$operation] }
                if ($sddl.Length -gt 30000) { $sddl = $sddl.Substring(0, 30000) + '...(truncated)' }

                $eventRows.Add([PSCustomObject]@{
                        When_TimeCreated            = Format-ReportDate $event.TimeCreated
                        Who_ChangedBy               = ('{0}\{1}' -f $data['SubjectDomainName'], $data['SubjectUserName'])
                        Who_ChangedBySid            = $data['SubjectUserSid']
                        Where_ObjectDN              = $objectDn
                        Where_ObjectClass           = $data['ObjectClass']
                        Where_DomainController      = $domainController.HostName
                        What_Operation              = $operation
                        What_FlaggedTrusteesInValue = ($trusteesInValue -join '; ')
                        What_CorrelationId          = $data['OpCorrelationID']
                        What_SecurityDescriptor     = $sddl
                    })
            }
        }
    }

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $summaryFile = Join-Path -Path $OutputPath -ChildPath '00_Summary.txt'
    $detailFile = Join-Path -Path $OutputPath -ChildPath '01_DelegationDetail.csv'
    $findingFile = Join-Path -Path $OutputPath -ChildPath '02_SemperisFindingStatus.csv'
    $trusteeFile = Join-Path -Path $OutputPath -ChildPath '03_Trustees.csv'
    $memberFile = Join-Path -Path $OutputPath -ChildPath '04_GroupMembers.csv'
    $eventFile = Join-Path -Path $OutputPath -ChildPath '05_AclChangeEvents.csv'

    $detailRows | Export-Csv -Path $detailFile -NoTypeInformation -Encoding UTF8
    $findingRows | Export-Csv -Path $findingFile -NoTypeInformation -Encoding UTF8
    $trusteeRows | Export-Csv -Path $trusteeFile -NoTypeInformation -Encoding UTF8
    if ($groupMemberRows.Count -gt 0) { $groupMemberRows | Export-Csv -Path $memberFile -NoTypeInformation -Encoding UTF8 }
    if ($SearchEventLogs) {
        $eventRows | Sort-Object When_TimeCreated -Descending | Export-Csv -Path $eventFile -NoTypeInformation -Encoding UTF8
    }

    $confirmed = @($findingRows | Where-Object { $_.Status -like 'Confirmed*' }).Count
    $directAces = @($detailRows | Where-Object { $_.What_UpnChangeAssessment -like 'Direct*' }).Count
    $orphaned = @($trusteeRows | Where-Object { $_.Type -eq 'Orphaned' -or $_.Type -like 'Deleted*' }).Count
    $unresolved = @($trusteeRows | Where-Object { $_.Status -like 'Not resolved*' }).Count

    $summaryLines = @(
        'UPN Delegation Report'
        ('Generated : {0}' -f (Get-Date).ToString($script:DateFormat))
        ('CSV       : {0}' -f $CsvPath)
        ('Domain    : {0} ({1})' -f $domain.DNSRoot, $domain.NetBIOSName)
        ('Server    : {0}' -f $script:ReportServer)
        ''
        'Summary'
        ('  Semperis findings read            : {0}' -f $findingRows.Count)
        ('  Confirmed in the live ACL         : {0}' -f $confirmed)
        ('  Not confirmed (see file 02)       : {0}' -f ($findingRows.Count - $confirmed))
        ('  Live ACEs reported                : {0}' -f $detailRows.Count)
        ('  ACEs that allow a direct UPN write: {0}' -f $directAces)
        ('  Distinct trustees                 : {0}' -f @($trusteeRows).Count)
        ('  Orphaned or deleted trustees      : {0}' -f $orphaned)
        ('  Trustees not resolved             : {0}' -f $unresolved)
    )
    if ($SearchEventLogs) {
        $summaryLines += ('  ACL change events found           : {0}' -f $eventRows.Count)
    }
    $summaryLines += ''
    $summaryLines += ('Reports written to {0}' -f $OutputPath)
    $summaryLines | Set-Content -Path $summaryFile -Encoding UTF8

    Write-AuditStatus -Message '' -Color 'White' -Percent 98
    Write-AuditStatus -Message 'Summary' -Color 'Green'
    foreach ($line in ($summaryLines | Select-Object -Skip 7)) {
        if ($line) { Write-AuditStatus -Message $line -Color 'White' }
    }

    $broadTrustees = @($trusteeRows | Where-Object { $_.Sid -in @('S-1-5-11', 'S-1-1-0', 'S-1-5-7') -and $_.DirectUpnChangeAces -gt 0 })
    foreach ($broadTrustee in $broadTrustees) {
        Write-AuditStatus -Message ('{0} holds {1} ACE(s) that allow a direct UPN change. Review these first.' -f $broadTrustee.Trustee, $broadTrustee.DirectUpnChangeAces) -Color 'Yellow'
    }

    Write-AuditStatus -Message '' -Color 'White'
    Write-AuditStatus -Message ('Reports written to {0}' -f $OutputPath) -Color 'Green' -Percent 100
    Get-ChildItem -LiteralPath $OutputPath -Filter '*.csv' -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
        Write-AuditStatus -Message ('  {0}' -f $_.Name) -Color 'White'
    }

    return [PSCustomObject]@{
        OutputPath     = $OutputPath
        FindingCount   = $findingRows.Count
        ConfirmedCount = $confirmed
        DetailCount    = $detailRows.Count
        DirectAces     = $directAces
        TrusteeCount   = @($trusteeRows).Count
        EventCount     = $eventRows.Count
        Summary        = ($summaryLines -join [Environment]::NewLine)
    }
}

#endregion Engine

#region Interactive GUI

function Write-GuiLog {
    param([string]$Message, [string]$Color = 'White', [int]$Percent = -1, [string]$Activity = '')
    if ($script:GuiLogBox -and $Message) {
        $script:GuiLogBox.AppendText(('{0}  {1}{2}' -f (Get-Date -Format 'HH:mm:ss'), $Message, [Environment]::NewLine))
        $script:GuiLogBox.SelectionStart = $script:GuiLogBox.Text.Length
        $script:GuiLogBox.ScrollToCaret()
    }
    if ($script:GuiProgress -and $Percent -ge 0) {
        $script:GuiProgress.Value = [Math]::Min(100, [Math]::Max(0, $Percent))
    }
    if ($script:WinFormsLoaded) {
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Set-GuiCsvStatus {
    param([string]$Text, $Color)
    if (-not $script:GuiCsvStatus) { return }
    $script:GuiCsvStatus.Text = $Text
    if ($Color) { $script:GuiCsvStatus.ForeColor = $Color }
    elseif ($script:MutedColor) { $script:GuiCsvStatus.ForeColor = $script:MutedColor }
}

function Show-GuiCsvPreview {
    param([string]$Path, [switch]$Quiet)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ($script:GuiGrid) { $script:GuiGrid.DataSource = $null }
        Set-GuiCsvStatus -Text 'Pick the Semperis findings export (CSV).'
        return $false
    }
    try {
        $info = Get-CsvPreviewInfo -Path $Path
        if ($script:GuiGrid) {
            $bindList = New-Object System.Collections.ArrayList
            foreach ($item in @($info.Preview)) { [void]$bindList.Add($item) }
            $script:GuiGrid.DataSource = $bindList
        }
        Set-GuiCsvStatus -Text ('{0} rows  |  {1} unique trustees  |  {2} unique targets  |  columns: {3}' -f `
                $info.RowCount, $info.UniqueIdentities, $info.UniqueTargets, ($info.Headers -join ', ')) -Color $script:OkGreen
        if (-not $Quiet) {
            Write-GuiLog -Message ('Loaded {0} finding(s) from {1}' -f $info.RowCount, $Path) -Percent 0
        }
        return $true
    }
    catch {
        if ($script:GuiGrid) { $script:GuiGrid.DataSource = $null }
        Set-GuiCsvStatus -Text $_.Exception.Message -Color ([System.Drawing.Color]::FromArgb(196, 43, 28))
        if (-not $Quiet) {
            Show-UiMessage -Message $_.Exception.Message -Title 'CSV validation failed' -Icon 'Error'
        }
        return $false
    }
}

function Add-FormLabel {
    param($Parent, $Text, $X, $Y, $W = 160, $H = 20, [switch]$Bold, $Color, $FontSize = 9)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Text
    $lbl.Location = New-Object System.Drawing.Point($X, $Y)
    $lbl.Size = New-Object System.Drawing.Size($W, $H)
    $style = [System.Drawing.FontStyle]::Regular
    if ($Bold) { $style = [System.Drawing.FontStyle]::Bold }
    $lbl.Font = New-Object System.Drawing.Font('Segoe UI', $FontSize, $style)
    if ($Color) { $lbl.ForeColor = $Color }
    $Parent.Controls.Add($lbl)
    return $lbl
}

function Add-FormTextBox {
    param($Parent, $X, $Y, $W, $H = 24, $Text = '')
    $box = New-Object System.Windows.Forms.TextBox
    $box.Location = New-Object System.Drawing.Point($X, $Y)
    $box.Size = New-Object System.Drawing.Size($W, $H)
    $box.Text = $Text
    $box.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $box.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Left,Right'
    $Parent.Controls.Add($box)
    return $box
}

function Add-FormButton {
    param($Parent, $Text, $X, $Y, $W = 90, $H = 26, $BackColor)
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $Text
    $btn.Location = New-Object System.Drawing.Point($X, $Y)
    $btn.Size = New-Object System.Drawing.Size($W, $H)
    $btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btn.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btn.FlatAppearance.BorderSize = 0
    if ($BackColor) {
        $btn.BackColor = $BackColor
        $btn.ForeColor = [System.Drawing.Color]::White
    }
    $Parent.Controls.Add($btn)
    return $btn
}

function Show-AuditGui {
    param(
        [string]$CsvPath,
        [string]$OutputPath,
        [string]$Server,
        [AllowNull()]
        [System.Management.Automation.PSCredential]$Credential,
        [bool]$SkipGroupExpansion,
        [bool]$SkipScopeCount,
        [bool]$SearchEventLogs,
        [int]$EventLogDays = 30
    )

    if (-not (Initialize-WinForms)) {
        throw 'Windows Forms is not available, so the GUI cannot be shown. Re-run with -CsvPath and -NonInteractive.'
    }

    $navy = [System.Drawing.Color]::FromArgb(24, 42, 68)
    $navy2 = [System.Drawing.Color]::FromArgb(32, 52, 80)
    $accent = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $okGreen = [System.Drawing.Color]::FromArgb(16, 124, 65)
    $page = [System.Drawing.Color]::FromArgb(245, 247, 250)
    $muted = [System.Drawing.Color]::FromArgb(90, 110, 130)
    $script:OkGreen = $okGreen
    $script:MutedColor = $muted

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "UPN Delegation Report  v$($script:AppVersion)"
    $form.Size = New-Object System.Drawing.Size(1100, 820)
    $form.MinimumSize = New-Object System.Drawing.Size(1000, 700)
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.BackColor = $page
    $form.Icon = [System.Drawing.SystemIcons]::Shield

    $body = New-Object System.Windows.Forms.Panel
    $body.Dock = [System.Windows.Forms.DockStyle]::Fill
    $body.Padding = New-Object System.Windows.Forms.Padding(16, 12, 16, 12)
    [void]$form.Controls.Add($body)

    $header = New-Object System.Windows.Forms.Panel
    $header.Dock = [System.Windows.Forms.DockStyle]::Top
    $header.Height = 64
    $header.BackColor = $navy
    [void]$form.Controls.Add($header)

    $null = Add-FormLabel -Parent $header -Text 'UPN Delegation Report' -X 20 -Y 8 -W 500 -H 28 -Bold -Color ([System.Drawing.Color]::White) -FontSize 16
    $null = Add-FormLabel -Parent $header -Text 'Semperis findings  |  live AD who / what / where / when  |  read-only' -X 22 -Y 38 -W 700 -H 20 -Color ([System.Drawing.Color]::FromArgb(160, 185, 215))

    $y = 12
    $null = Add-FormLabel -Parent $body -Text 'Semperis CSV' -X 16 -Y $y -W 140 -Bold
    $txtCsv = Add-FormTextBox -Parent $body -X 160 -Y ($y - 2) -W 700 -Text $CsvPath
    $btnBrowseCsv = Add-FormButton -Parent $body -Text 'Browse...' -X 870 -Y ($y - 3) -W 90 -BackColor $accent
    $btnBrowseCsv.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Right'
    $txtCsv.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Left,Right'

    $y = 42
    $lblCsvStatus = Add-FormLabel -Parent $body -Text 'Pick the Semperis findings export (CSV).' -X 160 -Y $y -W 700 -H 20 -Color $muted

    $y = 68
    $null = Add-FormLabel -Parent $body -Text 'Output folder' -X 16 -Y $y -W 140 -Bold
    $txtOut = Add-FormTextBox -Parent $body -X 160 -Y ($y - 2) -W 700 -Text $OutputPath
    $btnBrowseOut = Add-FormButton -Parent $body -Text 'Browse...' -X 870 -Y ($y - 3) -W 90 -BackColor $navy2
    $btnBrowseOut.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Right'
    $txtOut.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Left,Right'

    $y = 102
    $null = Add-FormLabel -Parent $body -Text 'Domain controller' -X 16 -Y $y -W 140 -Bold
    $txtServer = Add-FormTextBox -Parent $body -X 160 -Y ($y - 2) -W 420 -Text $Server
    $txtServer.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Left'
    $null = Add-FormLabel -Parent $body -Text '(blank = PDC emulator of the current domain)' -X 590 -Y $y -W 360 -Color $muted

    $y = 136
    $null = Add-FormLabel -Parent $body -Text 'Credential' -X 16 -Y $y -W 140 -Bold
    $lblCred = Add-FormLabel -Parent $body -Text 'Current Windows logon' -X 160 -Y $y -W 300 -Color $okGreen
    $btnCred = Add-FormButton -Parent $body -Text 'Set...' -X 470 -Y ($y - 3) -W 80 -BackColor $navy2
    $btnCredClear = Add-FormButton -Parent $body -Text 'Clear' -X 556 -Y ($y - 3) -W 70 -BackColor ([System.Drawing.Color]::FromArgb(90, 110, 130))

    $script:GuiCredential = $Credential
    if ($script:GuiCredential) { $lblCred.Text = $script:GuiCredential.UserName }

    $y = 172
    $chkExpand = New-Object System.Windows.Forms.CheckBox
    $chkExpand.Text = 'Expand group trustees into effective members'
    $chkExpand.Location = New-Object System.Drawing.Point(160, $y)
    $chkExpand.Size = New-Object System.Drawing.Size(360, 22)
    $chkExpand.Checked = -not $SkipGroupExpansion
    $body.Controls.Add($chkExpand)

    $chkScope = New-Object System.Windows.Forms.CheckBox
    $chkScope.Text = 'Count users / computers under container targets'
    $chkScope.Location = New-Object System.Drawing.Point(530, $y)
    $chkScope.Size = New-Object System.Drawing.Size(360, 22)
    $chkScope.Checked = -not $SkipScopeCount
    $body.Controls.Add($chkScope)

    $y = 198
    $chkEvents = New-Object System.Windows.Forms.CheckBox
    $chkEvents.Text = 'Search DC Security logs for event 5136 (ACL changes)'
    $chkEvents.Location = New-Object System.Drawing.Point(160, $y)
    $chkEvents.Size = New-Object System.Drawing.Size(390, 22)
    $chkEvents.Checked = [bool]$SearchEventLogs
    $body.Controls.Add($chkEvents)

    $null = Add-FormLabel -Parent $body -Text 'Days back' -X 560 -Y ($y + 1) -W 70
    $numDays = New-Object System.Windows.Forms.NumericUpDown
    $numDays.Location = New-Object System.Drawing.Point(635, $y)
    $numDays.Size = New-Object System.Drawing.Size(70, 24)
    $numDays.Minimum = 1
    $numDays.Maximum = 3650
    $numDays.Value = $EventLogDays
    $body.Controls.Add($numDays)

    $y = 230
    $null = Add-FormLabel -Parent $body -Text 'CSV preview' -X 16 -Y $y -W 140 -Bold
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Location = New-Object System.Drawing.Point(160, $y)
    $grid.Size = New-Object System.Drawing.Size(800, 160)
    $grid.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Left,Right'
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.RowHeadersVisible = $false
    $grid.SelectionMode = 'FullRowSelect'
    $grid.AutoSizeColumnsMode = 'DisplayedCells'
    $grid.BackgroundColor = [System.Drawing.Color]::White
    $body.Controls.Add($grid)

    $y = 400
    $btnRun = Add-FormButton -Parent $body -Text 'Run report' -X 160 -Y $y -W 130 -H 32 -BackColor $okGreen
    $btnOpen = Add-FormButton -Parent $body -Text 'Open output folder' -X 300 -Y $y -W 160 -H 32 -BackColor $accent
    $btnOpen.Enabled = $false
    $btnValidate = Add-FormButton -Parent $body -Text 'Validate CSV' -X 470 -Y $y -W 120 -H 32 -BackColor $navy2

    $progress = New-Object System.Windows.Forms.ProgressBar
    $progress.Location = New-Object System.Drawing.Point(610, ($y + 6))
    $progress.Size = New-Object System.Drawing.Size(350, 20)
    $progress.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Left,Right'
    $progress.Minimum = 0
    $progress.Maximum = 100
    $body.Controls.Add($progress)

    $y = 444
    $null = Add-FormLabel -Parent $body -Text 'Log' -X 16 -Y $y -W 140 -Bold
    $log = New-Object System.Windows.Forms.TextBox
    $log.Multiline = $true
    $log.ScrollBars = 'Both'
    $log.ReadOnly = $true
    $log.Font = New-Object System.Drawing.Font('Consolas', 9)
    $log.BackColor = [System.Drawing.Color]::FromArgb(18, 22, 28)
    $log.ForeColor = [System.Drawing.Color]::FromArgb(200, 230, 201)
    $log.Location = New-Object System.Drawing.Point(160, $y)
    $log.Size = New-Object System.Drawing.Size(800, 250)
    $log.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Bottom,Left,Right'
    $log.WordWrap = $false
    $body.Controls.Add($log)

    $script:GuiForm = $form
    $script:GuiLogBox = $log
    $script:GuiProgress = $progress
    $script:GuiCsvStatus = $lblCsvStatus
    $script:GuiGrid = $grid
    $script:GuiCsvPathBox = $txtCsv
    $script:GuiOutPathBox = $txtOut
    $script:GuiServerBox = $txtServer
    $script:GuiCredLabel = $lblCred
    $script:GuiRunButton = $btnRun
    $script:GuiBrowseCsvButton = $btnBrowseCsv
    $script:GuiOpenButton = $btnOpen
    $script:GuiChkExpand = $chkExpand
    $script:GuiChkScope = $chkScope
    $script:GuiChkEvents = $chkEvents
    $script:GuiNumDays = $numDays

    $btnBrowseCsv.Add_Click({
            $startDir = $PSScriptRoot
            if ($script:GuiCsvPathBox -and $script:GuiCsvPathBox.Text -and (Test-Path -LiteralPath $script:GuiCsvPathBox.Text)) {
                $startDir = Split-Path -Path $script:GuiCsvPathBox.Text -Parent
            }
            $picked = Get-OpenCsvPath -InitialDirectory $startDir
            if ($picked) {
                $script:GuiCsvPathBox.Text = $picked
                [void](Show-GuiCsvPreview -Path $picked)
            }
        })

    $btnBrowseOut.Add_Click({
            $picked = Get-OutputFolderPath -SelectedPath $script:GuiOutPathBox.Text
            if ($picked) { $script:GuiOutPathBox.Text = $picked }
        })

    $btnCred.Add_Click({
            try {
                $cred = Get-Credential -Message 'Credential for Active Directory (and event log) queries'
                if ($cred) {
                    $script:GuiCredential = $cred
                    $script:GuiCredLabel.Text = $cred.UserName
                    $script:GuiCredLabel.ForeColor = $script:OkGreen
                }
            }
            catch { }
        })

    $btnCredClear.Add_Click({
            $script:GuiCredential = $null
            $script:GuiCredLabel.Text = 'Current Windows logon'
            $script:GuiCredLabel.ForeColor = $script:OkGreen
        })

    $btnValidate.Add_Click({
            [void](Show-GuiCsvPreview -Path $script:GuiCsvPathBox.Text)
        })

    $btnOpen.Add_Click({
            $folder = $script:GuiOutPathBox.Text
            if (-not $folder) { $folder = $script:LastOutputPath }
            if ($folder -and (Test-Path -LiteralPath $folder)) {
                Start-Process explorer.exe -ArgumentList $folder
            }
            else {
                Show-UiMessage -Message 'The output folder does not exist yet. Run the report first.' -Title 'Output folder' -Icon 'Warning'
            }
        })

    $txtCsv.Add_Leave({
            if ($script:GuiCsvPathBox.Text -and (Test-Path -LiteralPath $script:GuiCsvPathBox.Text -PathType Leaf)) {
                [void](Show-GuiCsvPreview -Path $script:GuiCsvPathBox.Text -Quiet)
            }
        })

    $btnRun.Add_Click({
            if ($script:IsRunning) { return }
            $csv = $script:GuiCsvPathBox.Text.Trim()
            if (-not $csv) {
                $picked = Get-OpenCsvPath
                if (-not $picked) { return }
                $script:GuiCsvPathBox.Text = $picked
                $csv = $picked
            }
            if (-not (Show-GuiCsvPreview -Path $csv)) { return }

            $out = $script:GuiOutPathBox.Text.Trim()
            if (-not $out) {
                $pickedOut = Get-OutputFolderPath
                if ($pickedOut) {
                    $stamp = 'DelegationAudit_{0:yyyyMMdd_HHmmss}' -f (Get-Date)
                    $out = Join-Path -Path $pickedOut -ChildPath $stamp
                    $script:GuiOutPathBox.Text = $out
                }
                else {
                    $out = Get-DefaultOutputPath
                    $script:GuiOutPathBox.Text = $out
                }
            }

            $script:IsRunning = $true
            $script:GuiRunButton.Enabled = $false
            $script:GuiBrowseCsvButton.Enabled = $false
            $script:GuiProgress.Value = 0
            $script:OnStatus = { param($m, $c, $p, $a) Write-GuiLog -Message $m -Color $c -Percent $p -Activity $a }
            $script:GuiForm.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
            try {
                $auditSplat = New-AuditSplat -CsvPath $csv -OutputPath $out `
                    -Server $script:GuiServerBox.Text.Trim() -Credential $script:GuiCredential `
                    -SkipGroupExpansion:(-not $script:GuiChkExpand.Checked) `
                    -SkipScopeCount:(-not $script:GuiChkScope.Checked) `
                    -SearchEventLogs:($script:GuiChkEvents.Checked) `
                    -EventLogDays ([int]$script:GuiNumDays.Value)
                $result = Invoke-UpnDelegationAudit @auditSplat
                $script:GuiOpenButton.Enabled = $true
                $script:LastOutputPath = $result.OutputPath
                Show-UiMessage -Message $result.Summary -Title 'Report complete' -Icon 'Information'
            }
            catch {
                Write-GuiLog -Message ('ERROR: {0}' -f $_.Exception.Message) -Color 'Red' -Percent 0
                Show-UiMessage -Message $_.Exception.Message -Title 'Report failed' -Icon 'Error'
            }
            finally {
                $script:OnStatus = $null
                $script:IsRunning = $false
                $script:GuiRunButton.Enabled = $true
                $script:GuiBrowseCsvButton.Enabled = $true
                $script:GuiForm.Cursor = [System.Windows.Forms.Cursors]::Default
            }
        })

    $form.Add_FormClosing({
            if ($script:IsRunning) {
                $_.Cancel = $true
                Show-UiMessage -Message 'A report is still running. Please wait for it to finish.' -Title 'Busy' -Icon 'Warning'
            }
        })

    $form.Add_Shown({
            if (-not $script:GuiCsvPathBox.Text) {
                $nearby = Find-NearbySemperisCsv
                if ($nearby) { $script:GuiCsvPathBox.Text = $nearby }
            }
            if (-not $script:GuiOutPathBox.Text) {
                $script:GuiOutPathBox.Text = Get-DefaultOutputPath
            }
            if ($script:GuiCsvPathBox.Text) {
                [void](Show-GuiCsvPreview -Path $script:GuiCsvPathBox.Text -Quiet)
            }
            Write-GuiLog -Message 'Ready. Pick a Semperis CSV if needed, then click Run report.'
        })

    [void]$form.ShowDialog()
}

function Show-ConsoleWizard {
    param(
        [string]$CsvPath,
        [string]$OutputPath,
        [string]$Server,
        [AllowNull()]
        [System.Management.Automation.PSCredential]$Credential,
        [bool]$SkipGroupExpansion,
        [bool]$SkipScopeCount,
        [bool]$SearchEventLogs,
        [int]$EventLogDays = 30
    )

    Write-Host ''
    Write-Host 'UPN Delegation Report' -ForegroundColor Cyan
    Write-Host 'Read-only audit of Semperis UPN-delegation findings against live AD.' -ForegroundColor Gray
    Write-Host ''

    if (-not $CsvPath) {
        $nearby = Find-NearbySemperisCsv
        if ($nearby) {
            Write-Host ('Found a Semperis-style CSV: {0}' -f $nearby) -ForegroundColor Green
            $use = Read-Host 'Use this file? [Y/n]'
            if ($use -notmatch '^[nN]') { $CsvPath = $nearby }
        }
    }
    if (-not $CsvPath) {
        Write-Host 'Press Enter to open a file picker, or type a full path to the Semperis CSV.' -ForegroundColor Yellow
        $typed = Read-Host 'CSV path'
        if ([string]::IsNullOrWhiteSpace($typed)) {
            $CsvPath = Get-OpenCsvPath
        }
        else {
            $CsvPath = $typed.Trim('"')
        }
    }
    if (-not $CsvPath) { throw 'No CSV selected.' }

    $info = Get-CsvPreviewInfo -Path $CsvPath
    Write-Host ('  {0} rows, {1} unique trustees, {2} unique targets' -f $info.RowCount, $info.UniqueIdentities, $info.UniqueTargets) -ForegroundColor Green

    if (-not $OutputPath) {
        Write-Host 'Press Enter to open a folder picker, or type an output folder path.' -ForegroundColor Yellow
        $typedOut = Read-Host 'Output folder (blank = picker / default)'
        if ([string]::IsNullOrWhiteSpace($typedOut)) {
            $picked = Get-OutputFolderPath
            if ($picked) {
                $OutputPath = Join-Path -Path $picked -ChildPath ('DelegationAudit_{0:yyyyMMdd_HHmmss}' -f (Get-Date))
            }
            else {
                $OutputPath = Get-DefaultOutputPath
            }
        }
        else {
            $OutputPath = $typedOut.Trim('"')
        }
    }

    if (-not $Server) {
        $typedServer = Read-Host 'Domain controller (blank = PDC emulator)'
        if ($typedServer) { $Server = $typedServer.Trim() }
    }

    if (-not $Credential) {
        $wantCred = Read-Host 'Use an alternate credential? [y/N]'
        if ($wantCred -match '^[yY]') {
            $Credential = Get-Credential -Message 'Credential for Active Directory queries'
        }
    }

    $ans = Read-Host 'Expand group trustees into effective members? [Y/n]'
    if ($ans -match '^[nN]') { $SkipGroupExpansion = $true }

    $ans = Read-Host 'Count users/computers under container targets? [Y/n]'
    if ($ans -match '^[nN]') { $SkipScopeCount = $true }

    $ans = Read-Host 'Search DC Security logs for ACL change events (5136)? [y/N]'
    if ($ans -match '^[yY]') {
        $SearchEventLogs = $true
        $days = Read-Host ("Days back [{0}]" -f $EventLogDays)
        if ($days -match '^\d+$') { $EventLogDays = [int]$days }
    }

    Write-Host ''
    Write-Host 'Starting report...' -ForegroundColor Cyan
    $auditSplat = New-AuditSplat -CsvPath $CsvPath -OutputPath $OutputPath -Server $Server -Credential $Credential `
        -SkipGroupExpansion:$SkipGroupExpansion -SkipScopeCount:$SkipScopeCount `
        -SearchEventLogs:$SearchEventLogs -EventLogDays $EventLogDays
    $result = Invoke-UpnDelegationAudit @auditSplat

    if ([Environment]::UserInteractive) {
        $open = Read-Host 'Open the report folder in Explorer? [Y/n]'
        if ($open -notmatch '^[nN]' -and $result.OutputPath) {
            Start-Process explorer.exe -ArgumentList $result.OutputPath
        }
    }
    return $result
}

#endregion Interactive GUI

#region Entry point

function New-AuditSplat {
    param(
        [string]$CsvPath,
        [string]$OutputPath,
        [string]$Server,
        [AllowNull()]
        [System.Management.Automation.PSCredential]$Credential,
        [bool]$SkipGroupExpansion,
        [bool]$SkipScopeCount,
        [bool]$SearchEventLogs,
        [int]$EventLogDays = 30
    )
    $splat = @{
        CsvPath              = $CsvPath
        SkipGroupExpansion   = $SkipGroupExpansion
        SkipScopeCount       = $SkipScopeCount
        SearchEventLogs      = $SearchEventLogs
        EventLogDays         = $EventLogDays
    }
    if ($OutputPath) { $splat['OutputPath'] = $OutputPath }
    if ($Server) { $splat['Server'] = $Server }
    if ($Credential) { $splat['Credential'] = $Credential }
    return $splat
}

function Invoke-CsvValidationOnly {
    param([string]$Path)
    if (-not $Path) {
        $Path = Find-NearbySemperisCsv
        if (-not $Path) { $Path = Get-OpenCsvPath }
    }
    if (-not $Path) { throw 'No CSV selected.' }
    $info = Get-CsvPreviewInfo -Path $Path
    Write-Host ('CSV        : {0}' -f $Path) -ForegroundColor Green
    Write-Host ('Rows       : {0}' -f $info.RowCount)
    Write-Host ('Trustees   : {0}' -f $info.UniqueIdentities)
    Write-Host ('Targets    : {0}' -f $info.UniqueTargets)
    Write-Host ('Columns    : {0}' -f ($info.Headers -join ', '))
    Write-Host 'Required columns are present. This file can be ingested.' -ForegroundColor Green
}

$needPicker = [string]::IsNullOrWhiteSpace($CsvPath)
$wantGui = $Interactive -or ($needPicker -and -not $NonInteractive)

if ($ValidateCsvOnly) {
    if ($wantGui -and -not (Test-IsStaThread) -and (Test-WindowsDesktop)) {
        Restart-InStaIfNeeded | Out-Null
    }
    try {
        Invoke-CsvValidationOnly -Path $CsvPath
        exit 0
    }
    catch {
        Write-Error $_.Exception.Message
        exit 1
    }
}

if ($NonInteractive -and $needPicker) {
    Write-Error 'CsvPath is required when -NonInteractive is set. Supply -CsvPath or omit -NonInteractive to use the file picker.'
    exit 1
}

if ($CsvPath -and -not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
    if ($NonInteractive) {
        Write-Error "CSV file not found: $CsvPath"
        exit 1
    }
    Write-Warning "CSV file not found: $CsvPath"
    $CsvPath = ''
    $needPicker = $true
    $wantGui = -not $NonInteractive
}

if ($wantGui) {
    if (-not (Test-IsStaThread) -and (Test-WindowsDesktop)) {
        Restart-InStaIfNeeded | Out-Null
    }
    try {
        $uiSplat = @{
            CsvPath            = $CsvPath
            OutputPath         = $OutputPath
            Server             = $Server
            SkipGroupExpansion = [bool]$SkipGroupExpansion
            SkipScopeCount     = [bool]$SkipScopeCount
            SearchEventLogs    = [bool]$SearchEventLogs
            EventLogDays       = $EventLogDays
        }
        if ($Credential) { $uiSplat['Credential'] = $Credential }
        if (Initialize-WinForms) {
            Show-AuditGui @uiSplat
            exit 0
        }
        Show-ConsoleWizard @uiSplat | Out-Null
        exit 0
    }
    catch {
        Write-Error $_.Exception.Message
        exit 1
    }
}

try {
    if (-not $OutputPath) { $OutputPath = Get-DefaultOutputPath }
    $auditSplat = New-AuditSplat -CsvPath $CsvPath -OutputPath $OutputPath -Server $Server -Credential $Credential `
        -SkipGroupExpansion:$SkipGroupExpansion -SkipScopeCount:$SkipScopeCount `
        -SearchEventLogs:$SearchEventLogs -EventLogDays $EventLogDays
    $null = Invoke-UpnDelegationAudit @auditSplat
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

#endregion Entry point

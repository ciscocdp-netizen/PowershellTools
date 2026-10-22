<#
.SYNOPSIS
    Interactive export of user last-logon and password dates for an OU you choose.

.DESCRIPTION
    Compatible with Windows PowerShell 5.1. Requires the ActiveDirectory module (RSAT).

    Run it with no parameters to open a window that scans the domain and lets you
    pick an OU from the tree. Use -Console on Server Core or in Windows Terminal
    sessions that are not STA. Pass -SearchBase to run unattended, the same way
    the original script did.

    By default the replicated lastLogonTimestamp attribute is used. It is fast but
    can lag the real last logon by up to about 14 days. Choose "Query every domain
    controller" (or -QueryAllDCs) to read the non-replicated lastLogon attribute
    from every reachable domain controller and keep the most recent value.

.PARAMETER SearchBase
    Distinguished name of the target OU, container, or domain root.
    Omit it to choose the target interactively.
    Example: "OU=Staff,DC=contoso,DC=com"

.PARAMETER OutputPath
    Output file path. A .xlsx path creates an Excel file when the ImportExcel
    module is installed. Any other path (or a missing module) writes a CSV that
    Excel can open. When omitted, the file is saved in Documents.

.PARAMETER SearchScope
    Subtree (default, includes child OUs), OneLevel (direct children only), or Base.

.PARAMETER QueryAllDCs
    Query every reachable domain controller for the true most-recent lastLogon.

.PARAMETER Server
    Optional domain controller to query. Ignored for the per-DC lastLogon sweep
    targets themselves; that sweep still contacts each reachable DC.
    The inventory and the main user query use this server.

.PARAMETER OnlyEnabled
    Export enabled accounts only.

.PARAMETER ExcludeCriticalSystemAccounts
    Skip isCriticalSystemObject accounts and krbtgt.

.PARAMETER PassThru
    Also write the report objects to the pipeline. Used with -SearchBase.

.PARAMETER Interactive
    Open the browser even when -SearchBase is supplied, and preselect that OU.

.PARAMETER Console
    Use the text browser instead of the window.

.PARAMETER SelfTest
    Run the built-in checks for DN parsing, date conversion, and the report row.
    Does not contact Active Directory.

.EXAMPLE
    .\Export-OUUserLogonReport.ps1

.EXAMPLE
    .\Export-OUUserLogonReport.ps1 -Console

.EXAMPLE
    .\Export-OUUserLogonReport.ps1 -SearchBase "OU=Staff,DC=contoso,DC=com" -QueryAllDCs -OutputPath "C:\Reports\Staff.xlsx"

.NOTES
    Fixes in this version:
    - Write-Error under ErrorActionPreference Stop no longer hides the real failure.
    - The domain root and containers such as CN=Users are valid targets.
    - Missing AD attributes and the throwing PasswordExpired property cannot abort the export.
    - Out-of-range file times are reported as "Never" instead of crashing.
    - An offline domain controller is skipped after a short port check instead of stalling the run.
    - The DC list follows -Server, and DN matching is case-insensitive.
    - The default file lands in Documents, not the elevated process's System32 directory.
    - CSV files keep a UTF-8 BOM so Excel reads them, including under PowerShell 7.
    - ImportExcel table export no longer also sets a conflicting autofilter.
    - OU names that contain commas stay intact when the tree is built.
    - Values that start with =, +, -, or @ cannot become Excel formulas.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$SearchBase,

    [string]$OutputPath,

    [ValidateSet('Base', 'OneLevel', 'Subtree')]
    [string]$SearchScope = 'Subtree',

    [switch]$QueryAllDCs,

    [string]$Server,

    [switch]$OnlyEnabled,

    [switch]$ExcludeCriticalSystemAccounts,

    [switch]$PassThru,

    [switch]$Interactive,

    [switch]$Console,

    [switch]$SelfTest
)

$script:ReportCancelledMessage = 'OU report export cancelled.'
$script:ReportSync = $null
$script:PendingSearchBase = $null

function Import-ActiveDirectoryModule {
    if (Get-Module -Name ActiveDirectory) { return }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        throw 'The ActiveDirectory module is not available. Install RSAT: Active Directory Domain Services and Lightweight Directory Services Tools, then run this script again.'
    }
}

function Split-ADDistinguishedName {
    param([AllowNull()][AllowEmptyString()][string]$DistinguishedName)

    $parts = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrEmpty($DistinguishedName)) { return $null }

    $current = New-Object System.Text.StringBuilder
    $escaped = $false
    foreach ($ch in $DistinguishedName.ToCharArray()) {
        if ($escaped) {
            [void]$current.Append('\')
            [void]$current.Append($ch)
            $escaped = $false
            continue
        }
        if ($ch -eq '\') {
            $escaped = $true
            continue
        }
        if ($ch -eq ',') {
            $parts.Add($current.ToString())
            [void]$current.Clear()
            continue
        }
        [void]$current.Append($ch)
    }
    if ($escaped) { [void]$current.Append('\') }
    if ($current.Length -gt 0) { $parts.Add($current.ToString()) }
    if ($parts.Count -eq 0) { return $null }
    return ,$parts.ToArray()
}

function Get-CollectionItems {
    param($Value)
    # @($genericList) throws "Argument types do not match" for List[object].
    # Returning a real array also keeps a one-item result from turning into a string.
    $copy = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Value) {
        $enumerable = ($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])
        if ($enumerable) {
            foreach ($item in $Value) {
                if ($null -ne $item) { [void]$copy.Add($item) }
            }
        }
        else {
            [void]$copy.Add($Value)
        }
    }
    return ,$copy.ToArray()
}

function Get-ADParentDistinguishedName {
    param([AllowNull()][AllowEmptyString()][string]$DistinguishedName)

    $parts = Get-CollectionItems (Split-ADDistinguishedName -DistinguishedName $DistinguishedName)
    if ($null -eq $parts -or $parts.Count -le 1) { return $null }
    $tail = New-Object System.Collections.Generic.List[string]
    for ($index = 1; $index -lt $parts.Count; $index++) {
        [void]$tail.Add([string]$parts[$index])
    }
    return [string]::Join(',', $tail.ToArray())
}

function Test-ExcludedInfrastructureDn {
    param([AllowNull()][AllowEmptyString()][string]$DistinguishedName)

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return $false }
    $blocked = @(
        'CN=System',
        'CN=Program Data',
        'CN=ForeignSecurityPrincipals',
        'CN=Managed Service Accounts',
        'CN=Keys',
        'CN=NTDS Quotas',
        'CN=TPM Devices'
    )
    $parts = Get-CollectionItems (Split-ADDistinguishedName -DistinguishedName $DistinguishedName)
    foreach ($part in $parts) {
        foreach ($name in $blocked) {
            if ([string]::Equals([string]$part, $name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    }
    return $false
}

function Get-ObjectPropertySafe {
    param(
        $InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    try {
        $property = $InputObject.PSObject.Properties[$Name]
        if ($null -eq $property) { return $null }
        return $property.Value
    }
    catch {
        return $null
    }
}

function Get-MostSpecificClass {
    param($Object)
    $class = Get-ObjectPropertySafe -InputObject $Object -Name 'objectClass'
    if ($null -eq $class) {
        $class = Get-ObjectPropertySafe -InputObject $Object -Name 'ObjectClass'
    }
    if ($null -eq $class) { return $null }
    $values = Get-CollectionItems $class
    if ($null -eq $values -or $values.Count -eq 0) { return $null }
    return [string]$values[$values.Count - 1]
}

function Convert-FileTimeSafe {
    param([object]$FileTime)
    if ($null -eq $FileTime) { return $null }
    if ($FileTime -is [string] -and [string]::IsNullOrWhiteSpace($FileTime)) { return $null }

    $value = [int64]0
    try {
        $value = [int64]$FileTime
    }
    catch {
        return $null
    }
    if ($value -le 0 -or $value -eq [int64]::MaxValue) { return $null }
    try {
        return [DateTime]::FromFileTime($value)
    }
    catch {
        return $null
    }
}

function ConvertTo-SpreadsheetSafeValue {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool] -or $Value -is [byte] -or $Value -is [int16] -or $Value -is [int] -or
        $Value -is [int64] -or $Value -is [decimal] -or $Value -is [double] -or $Value -is [single] -or
        $Value -is [datetime]) {
        return $Value
    }
    $text = [string]$Value
    if ($text.Length -eq 0) { return $text }
    $first = [int][char]$text[0]
    if ($first -eq 9 -or $first -eq 13 -or $first -eq 10 -or $text[0] -match '[=+\-@]') {
        return "'" + $text
    }
    return $text
}

function ConvertTo-ExportRow {
    param($Row)
    $copy = [ordered]@{}
    foreach ($property in $Row.PSObject.Properties) {
        $copy[$property.Name] = ConvertTo-SpreadsheetSafeValue -Value $property.Value
    }
    return [PSCustomObject]$copy
}

function Get-CsvEncodingName {
    if ($PSVersionTable.PSVersion.Major -ge 6) { return 'utf8BOM' }
    return 'UTF8'
}

function Get-DefaultReportPath {
    param([string]$Extension = '.csv')
    if ([string]::IsNullOrWhiteSpace($Extension)) { $Extension = '.csv' }
    if (-not $Extension.StartsWith('.')) { $Extension = '.' + $Extension }

    $folder = $null
    try { $folder = [Environment]::GetFolderPath('MyDocuments') } catch { $folder = $null }
    if ([string]::IsNullOrWhiteSpace($folder)) {
        try { $folder = [Environment]::GetFolderPath('UserProfile') } catch { $folder = $null }
    }
    if ([string]::IsNullOrWhiteSpace($folder)) { $folder = (Get-Location).Path }
    $name = 'OU_User_Logon_Report_{0}{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $Extension
    return (Join-Path -Path $folder -ChildPath $name)
}

function Add-ReportLog {
    param([string]$Message)
    if ($null -eq $script:ReportSync) {
        Write-Host $Message
        return
    }
    [System.Threading.Monitor]::Enter($script:ReportSync.Lock)
    try {
        [void]$script:ReportSync.Lines.Add($Message)
    }
    finally {
        [System.Threading.Monitor]::Exit($script:ReportSync.Lock)
    }
}

function Write-ReportWarning {
    param([string]$Message)
    if ($null -ne $script:ReportSync) {
        Add-ReportLog ("WARNING: " + $Message)
    }
    else {
        Write-Warning $Message
    }
}

function Update-ReportProgress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$Percent,
        [switch]$Log
    )
    if ($Percent -lt 0) { $Percent = 0 }
    if ($Percent -gt 100) { $Percent = 100 }
    Test-ReportCancelled
    if ($null -ne $script:ReportSync) {
        $script:ReportSync.Status = $Status
        $script:ReportSync.Percent = $Percent
        if ($Log) { Add-ReportLog $Status }
        return
    }
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $Percent
    if ($Log) { Write-Host $Status }
}

function Test-ReportCancelled {
    if ($null -ne $script:ReportSync -and $script:ReportSync.Cancel) {
        throw $script:ReportCancelledMessage
    }
}

function Test-MapContains {
    param($Map, [string]$Key)
    if ($null -eq $Map -or [string]::IsNullOrWhiteSpace($Key)) { return $false }
    $containsKey = $Map.PSObject.Methods['ContainsKey']
    if ($null -ne $containsKey) {
        return [bool]$Map.ContainsKey($Key)
    }
    $contains = $Map.PSObject.Methods['Contains']
    if ($null -ne $contains) {
        return [bool]$Map.Contains($Key)
    }
    return $false
}

function Get-DirectoryClassRank {
    param([string]$ObjectClass)
    switch ($ObjectClass) {
        'domainDNS' { return 0 }
        'organizationalUnit' { return 1 }
        'container' { return 2 }
        'builtinDomain' { return 3 }
        default { return 4 }
    }
}

function Format-DirectoryNodeLabel {
    param($Node)
    $class = [string]$Node.Item.ObjectClass
    $suffix = ''
    if ($class -eq 'container' -or $class -eq 'builtinDomain') { $suffix = '  [container]' }
    elseif ($class -eq 'domainDNS') { $suffix = '  [domain]' }
    return ('{0}{1}' -f $Node.Item.Name, $suffix)
}

function Build-DirectoryTree {
    param($Items)

    $nodes = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $order = New-Object System.Collections.Generic.List[string]

    foreach ($item in (Get-CollectionItems $Items)) {
        if ($null -eq $item) { continue }
        $dn = [string](Get-ObjectPropertySafe -InputObject $item -Name 'DistinguishedName')
        if ([string]::IsNullOrWhiteSpace($dn)) { continue }
        if ($nodes.ContainsKey($dn)) { continue }
        $node = [PSCustomObject]@{
            Item     = $item
            ParentDn = Get-ADParentDistinguishedName -DistinguishedName $dn
            Children = (New-Object System.Collections.Generic.List[object])
        }
        $nodes.Add($dn, $node)
        $order.Add($dn)
    }

    $roots = New-Object System.Collections.Generic.List[object]
    foreach ($dn in $order) {
        $node = $nodes[$dn]
        $parentDn = [string]$node.ParentDn
        $attached = $false
        while (-not [string]::IsNullOrWhiteSpace($parentDn)) {
            if ($nodes.ContainsKey($parentDn)) {
                if (-not [string]::Equals($parentDn, $dn, [System.StringComparison]::OrdinalIgnoreCase)) {
                    [void]$nodes[$parentDn].Children.Add($node)
                    $attached = $true
                }
                break
            }
            $parentDn = Get-ADParentDistinguishedName -DistinguishedName $parentDn
        }
        if (-not $attached) { [void]$roots.Add($node) }
    }
    return ,$roots.ToArray()
}

function Find-TreeNodeByDn {
    param($Nodes, [string]$DistinguishedName)
    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return $null }
    $pending = New-Object System.Collections.Generic.Stack[object]
    foreach ($node in (Get-CollectionItems $Nodes)) {
        if ($null -ne $node) { $pending.Push($node) }
    }
    while ($pending.Count -gt 0) {
        $node = $pending.Pop()
        $dn = [string](Get-ObjectPropertySafe -InputObject $node.Item -Name 'DistinguishedName')
        if ([string]::Equals($dn, $DistinguishedName, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $node
        }
        foreach ($child in (Get-CollectionItems $node.Children)) {
            if ($null -ne $child) { $pending.Push($child) }
        }
    }
    return $null
}

function Sort-DirectoryNodes {
    param($Nodes)
    return @($Nodes | Sort-Object { Get-DirectoryClassRank -ObjectClass ([string]$_.Item.ObjectClass) }, { [string]$_.Item.Name })
}

function Test-CriticalAccount {
    param($User)
    $critical = Get-ObjectPropertySafe -InputObject $User -Name 'isCriticalSystemObject'
    if ($critical -eq $true) { return $true }
    $sam = [string](Get-ObjectPropertySafe -InputObject $User -Name 'SamAccountName')
    if ($sam -match '^(?i)krbtgt$') { return $true }
    return $false
}

function New-UserLogonReportRow {
    param(
        [Parameter(Mandatory = $true)]$User,
        $LastLogonByDn,
        [Parameter(Mandatory = $true)][datetime]$Now,
        [bool]$QueryAllDCs,
        $MaxPasswordAge
    )

    $sam = Get-ObjectPropertySafe -InputObject $User -Name 'SamAccountName'
    $upn = Get-ObjectPropertySafe -InputObject $User -Name 'UserPrincipalName'
    $display = Get-ObjectPropertySafe -InputObject $User -Name 'DisplayName'
    $enabled = Get-ObjectPropertySafe -InputObject $User -Name 'Enabled'
    $dn = [string](Get-ObjectPropertySafe -InputObject $User -Name 'DistinguishedName')
    $canonical = Get-ObjectPropertySafe -InputObject $User -Name 'CanonicalName'
    $whenCreated = Get-ObjectPropertySafe -InputObject $User -Name 'whenCreated'

    $lastLogonTimestamp = Convert-FileTimeSafe -FileTime (Get-ObjectPropertySafe -InputObject $User -Name 'lastLogonTimestamp')
    $lastLogon = $lastLogonTimestamp
    $logonSource = 'lastLogonTimestamp'

    if ($QueryAllDCs -and (Test-MapContains -Map $LastLogonByDn -Key $dn)) {
        $dcValue = Convert-FileTimeSafe -FileTime $LastLogonByDn[$dn]
        if ($null -ne $dcValue -and ($null -eq $lastLogon -or $dcValue -gt $lastLogon)) {
            $lastLogon = $dcValue
            $logonSource = 'lastLogon (all domain controllers)'
        }
    }

    $pwdRaw = Get-ObjectPropertySafe -InputObject $User -Name 'pwdLastSet'
    $mustChange = $false
    if ($null -ne $pwdRaw -and "$pwdRaw" -ne '') {
        try {
            if ([int64]$pwdRaw -eq 0) { $mustChange = $true }
        }
        catch { }
    }
    $pwdLastSet = Convert-FileTimeSafe -FileTime $pwdRaw

    $daysSinceLogon = $null
    if ($null -ne $lastLogon) {
        $daysSinceLogon = [int][Math]::Floor(($Now - $lastLogon).TotalDays)
    }
    $passwordAge = $null
    if ($null -ne $pwdLastSet) {
        $passwordAge = [int][Math]::Floor(($Now - $pwdLastSet).TotalDays)
    }

    $uac = Get-ObjectPropertySafe -InputObject $User -Name 'userAccountControl'
    $never = Get-ObjectPropertySafe -InputObject $User -Name 'PasswordNeverExpires'
    if ($null -eq $never -and $null -ne $uac -and "$uac" -ne '') {
        try { $never = (([int64]$uac -band 0x10000) -ne 0) } catch { $never = $null }
    }

    $locked = Get-ObjectPropertySafe -InputObject $User -Name 'LockedOut'
    $computed = Get-ObjectPropertySafe -InputObject $User -Name 'msDS-User-Account-Control-Computed'
    $passwordExpired = $null
    $passwordNote = $null
    $computedValue = $null
    if ($null -ne $computed -and "$computed" -ne '') {
        try { $computedValue = [int64]$computed } catch { $computedValue = $null }
    }
    if ($null -ne $computedValue) {
        $passwordExpired = (($computedValue -band 0x800000) -ne 0)
        if ($null -eq $locked) {
            $locked = (($computedValue -band 0x0010) -ne 0)
        }
    }
    elseif ($mustChange) {
        $passwordExpired = $false
        $passwordNote = 'Must change at next logon'
    }
    elseif ($never -eq $true) {
        $passwordExpired = $false
    }
    elseif ($null -ne $pwdLastSet -and $null -ne $MaxPasswordAge -and $MaxPasswordAge -is [timespan]) {
        if ($MaxPasswordAge.Ticks -le 0) {
            $passwordExpired = $false
            $passwordNote = 'Domain policy does not expire passwords'
        }
        else {
            try {
                $passwordExpired = ($pwdLastSet.Add($MaxPasswordAge) -le $Now)
                $passwordNote = 'Estimated from the default domain password policy'
            }
            catch {
                $passwordExpired = $null
                $passwordNote = 'Password expiry could not be calculated'
            }
        }
    }

    $passwordLastSetText = 'Never'
    if ($null -ne $pwdLastSet) {
        $passwordLastSetText = $pwdLastSet.ToString('yyyy-MM-dd HH:mm:ss')
    }
    elseif ($mustChange) {
        $passwordLastSetText = 'Must change at next logon'
    }

    $createdText = $null
    if ($whenCreated -is [datetime]) {
        $createdText = $whenCreated.ToString('yyyy-MM-dd HH:mm:ss')
    }
    elseif ($null -ne $whenCreated) {
        $createdText = [string]$whenCreated
    }

    if ($null -eq $lastLogon) { $logonSource = 'Never logged on' }

    return [PSCustomObject]@{
        SamAccountName          = $sam
        UserPrincipalName       = $upn
        DisplayName             = $display
        Enabled                 = $enabled
        LastLogon               = $(if ($null -ne $lastLogon) { $lastLogon.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' })
        LastLogonTimestamp      = $(if ($null -ne $lastLogonTimestamp) { $lastLogonTimestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' })
        DaysSinceLastLogon      = $daysSinceLogon
        PasswordLastSet         = $passwordLastSetText
        PasswordAgeDays         = $passwordAge
        PasswordNeverExpires    = $never
        PasswordExpired         = $passwordExpired
        PasswordStatusNote      = $passwordNote
        LockedOut               = $locked
        WhenCreated             = $createdText
        CanonicalName           = $canonical
        ParentDistinguishedName = $(if ([string]::IsNullOrWhiteSpace($dn)) { $null } else { Get-ADParentDistinguishedName -DistinguishedName $dn })
        DistinguishedName       = $dn
        LogonSource             = $logonSource
    }
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutMs = 3000
    )
    $client = New-Object System.Net.Sockets.TcpClient
    $wait = $null
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $wait = $async.AsyncWaitHandle
        if (-not $wait.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($async)
        return [bool]$client.Connected
    }
    catch {
        return $false
    }
    finally {
        if ($null -ne $wait) { $wait.Close() }
        $client.Close()
    }
}

function Test-DirectoryServerReachable {
    param([Parameter(Mandatory = $true)][string]$ComputerName)
    if (Test-TcpPort -ComputerName $ComputerName -Port 389) { return $true }
    return [bool](Test-TcpPort -ComputerName $ComputerName -Port 636)
}

function Get-AdServerParameter {
    param([string]$Server)
    $params = @{}
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $params.Server = $Server.Trim()
    }
    return $params
}

function Get-ADDirectoryInventory {
    param(
        [string]$Server,
        [bool]$IncludeContainers = $true
    )
    Import-ActiveDirectoryModule
    $adParams = Get-AdServerParameter -Server $Server
    Update-ReportProgress -Activity 'Scanning directory' -Status 'Reading the domain and organizational units...' -Percent 15 -Log

    $domain = Get-ADDomain @adParams
    $items = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    $domainDn = [string]$domain.DistinguishedName
    [void]$seen.Add($domainDn)
    [void]$items.Add([PSCustomObject]@{
            Name              = [string]$domain.DNSRoot
            DistinguishedName = $domainDn
            ObjectClass       = 'domainDNS'
            Description       = 'Domain root'
            CanonicalName     = [string]$domain.DNSRoot
        })

    $ouParams = @{
        Filter      = '*'
        SearchBase  = $domainDn
        SearchScope = 'Subtree'
        Properties  = @('Description', 'CanonicalName')
        ErrorAction = 'Stop'
    }
    if ($adParams.ContainsKey('Server')) { $ouParams.Server = $adParams.Server }
    foreach ($ou in @(Get-ADOrganizationalUnit @ouParams)) {
        $dn = [string]$ou.DistinguishedName
        if ([string]::IsNullOrWhiteSpace($dn) -or $seen.Contains($dn)) { continue }
        [void]$seen.Add($dn)
        [void]$items.Add([PSCustomObject]@{
                Name              = [string]$ou.Name
                DistinguishedName = $dn
                ObjectClass       = 'organizationalUnit'
                Description       = [string](Get-ObjectPropertySafe -InputObject $ou -Name 'Description')
                CanonicalName     = [string](Get-ObjectPropertySafe -InputObject $ou -Name 'CanonicalName')
            })
    }
    Update-ReportProgress -Activity 'Scanning directory' -Status ("Found {0} organizational units." -f ($items.Count - 1)) -Percent 55 -Log

    if ($IncludeContainers) {
        $containerParams = @{
            LDAPFilter  = '(|(objectClass=container)(objectClass=builtinDomain))'
            SearchBase  = $domainDn
            SearchScope = 'Subtree'
            Properties  = @('Description', 'CanonicalName', 'objectClass')
            ErrorAction = 'Stop'
        }
        if ($adParams.ContainsKey('Server')) { $containerParams.Server = $adParams.Server }
        foreach ($container in @(Get-ADObject @containerParams)) {
            $dn = [string]$container.DistinguishedName
            if ([string]::IsNullOrWhiteSpace($dn) -or $seen.Contains($dn)) { continue }
            if (Test-ExcludedInfrastructureDn -DistinguishedName $dn) { continue }
            [void]$seen.Add($dn)
            $class = Get-MostSpecificClass -Object $container
            if ([string]::IsNullOrWhiteSpace($class)) { $class = 'container' }
            [void]$items.Add([PSCustomObject]@{
                    Name              = [string]$container.Name
                    DistinguishedName = $dn
                    ObjectClass       = $class
                    Description       = [string](Get-ObjectPropertySafe -InputObject $container -Name 'Description')
                    CanonicalName     = [string](Get-ObjectPropertySafe -InputObject $container -Name 'CanonicalName')
                })
        }
    }

    Update-ReportProgress -Activity 'Scanning directory' -Status ("Directory scan complete. {0} locations loaded." -f $items.Count) -Percent 100 -Log
    return [PSCustomObject]@{
        Domain = [string]$domain.DNSRoot
        DomainDn = $domainDn
        Pdc    = [string]$domain.PDCEmulator
        Items  = $items
    }
}

function Resolve-ADSearchBase {
    param(
        [Parameter(Mandatory = $true)][string]$SearchBase,
        [string]$Server
    )
    $params = @{
        Identity    = $SearchBase
        Properties  = @('objectClass', 'Name')
        ErrorAction = 'Stop'
    }
    $adParams = Get-AdServerParameter -Server $Server
    if ($adParams.ContainsKey('Server')) { $params.Server = $adParams.Server }
    try {
        $object = Get-ADObject @params
    }
    catch {
        throw "The location '$SearchBase' was not found or is not accessible. $($_.Exception.Message)"
    }
    $class = Get-MostSpecificClass -Object $object
    $allowed = @('organizationalUnit', 'domainDNS', 'container', 'builtinDomain')
    if ($allowed -notcontains $class) {
        throw "The location '$SearchBase' is a $class. Choose an OU, a container, or the domain root."
    }
    return $object
}

function Get-ADReportUsers {
    param(
        [Parameter(Mandatory = $true)][string]$SearchBase,
        [Parameter(Mandatory = $true)][string]$SearchScope,
        [string]$Server,
        [bool]$ExcludeCritical
    )
    # The leading comma keeps each attribute list intact. A nested @() array is flattened.
    $fullAttributes = @('SamAccountName', 'UserPrincipalName', 'DisplayName', 'Enabled', 'lastLogonTimestamp', 'pwdLastSet', 'PasswordNeverExpires', 'LockedOut', 'whenCreated', 'DistinguishedName', 'userAccountControl', 'CanonicalName', 'msDS-User-Account-Control-Computed')
    if ($ExcludeCritical) { $fullAttributes += 'isCriticalSystemObject' }
    $basicAttributes = @('SamAccountName', 'UserPrincipalName', 'DisplayName', 'Enabled', 'lastLogonTimestamp', 'pwdLastSet', 'PasswordNeverExpires', 'whenCreated', 'DistinguishedName', 'userAccountControl', 'CanonicalName')
    $propertySets = @(
        ,$fullAttributes
        ,$basicAttributes
    )

    $adParams = Get-AdServerParameter -Server $Server
    $lastError = $null
    foreach ($properties in $propertySets) {
        try {
            $query = @{
                Filter         = '*'
                SearchBase     = $SearchBase
                SearchScope    = $SearchScope
                Properties     = $properties
                ResultPageSize = 500
                ErrorAction    = 'Stop'
            }
            if ($adParams.ContainsKey('Server')) { $query.Server = $adParams.Server }
            return @(Get-ADUser @query)
        }
        catch {
            $lastError = $_.Exception.Message
            Write-ReportWarning "The user query did not accept every requested attribute ($lastError). Retrying with a smaller attribute list."
        }
    }
    throw "Could not retrieve users from '$SearchBase'. $lastError"
}

function Get-DomainMaxPasswordAge {
    param([string]$Server)
    try {
        $params = @{ ErrorAction = 'Stop' }
        $adParams = Get-AdServerParameter -Server $Server
        if ($adParams.ContainsKey('Server')) { $params.Server = $adParams.Server }
        $policy = Get-ADDefaultDomainPasswordPolicy @params
        return $policy.MaxPasswordAge
    }
    catch {
        Write-ReportWarning "Could not read the default domain password policy. Password expiry is left blank when the directory does not supply it. $($_.Exception.Message)"
        return $null
    }
}

function Get-MostRecentLastLogonMap {
    param(
        [Parameter(Mandatory = $true)][string]$SearchBase,
        [Parameter(Mandatory = $true)][string]$SearchScope,
        [string]$Server
    )
    $map = New-Object 'System.Collections.Generic.Dictionary[string,int64]' ([System.StringComparer]::OrdinalIgnoreCase)
    $dcParams = @{ Filter = '*'; ErrorAction = 'Stop' }
    $adParams = Get-AdServerParameter -Server $Server
    if ($adParams.ContainsKey('Server')) { $dcParams.Server = $adParams.Server }

    $domainControllers = @(Get-ADDomainController @dcParams)
    if ($domainControllers.Count -eq 0) {
        Write-ReportWarning 'No domain controllers were returned. The report will use lastLogonTimestamp only.'
        return $map
    }

    $index = 0
    foreach ($dc in $domainControllers) {
        Test-ReportCancelled
        $index++
        $hostName = [string](Get-ObjectPropertySafe -InputObject $dc -Name 'HostName')
        if ([string]::IsNullOrWhiteSpace($hostName)) { $hostName = [string](Get-ObjectPropertySafe -InputObject $dc -Name 'Name') }
        $percent = [int](10 + (($index / [double]$domainControllers.Count) * 60))
        Update-ReportProgress -Activity 'Querying domain controllers' -Status ("Querying {0} ({1} of {2})" -f $hostName, $index, $domainControllers.Count) -Percent $percent -Log

        $matchesPreferred = $false
        if ($adParams.ContainsKey('Server')) {
            $preferred = [string]$adParams.Server
            $candidates = @(
                [string](Get-ObjectPropertySafe -InputObject $dc -Name 'HostName'),
                [string](Get-ObjectPropertySafe -InputObject $dc -Name 'Name'),
                [string](Get-ObjectPropertySafe -InputObject $dc -Name 'IPv4Address'),
                [string](Get-ObjectPropertySafe -InputObject $dc -Name 'IPv6Address')
            )
            foreach ($candidate in $candidates) {
                if ([string]::Equals($candidate, $preferred, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $matchesPreferred = $true
                }
            }
        }
        if (-not $matchesPreferred -and -not (Test-DirectoryServerReachable -ComputerName $hostName)) {
            Write-ReportWarning "Skipped $hostName because LDAP ports 389 and 636 did not respond within 3 seconds."
            continue
        }

        try {
            $dcUsers = @(Get-ADUser -Filter * -SearchBase $SearchBase -SearchScope $SearchScope -Server $hostName -Properties lastLogon -ResultPageSize 500 -ErrorAction Stop)
            foreach ($dcUser in $dcUsers) {
                $dn = [string]$dcUser.DistinguishedName
                if ([string]::IsNullOrWhiteSpace($dn)) { continue }
                $raw = Get-ObjectPropertySafe -InputObject $dcUser -Name 'lastLogon'
                $value = [int64]0
                if ($null -ne $raw -and "$raw" -ne '') {
                    try { $value = [int64]$raw } catch { $value = [int64]0 }
                }
                $hasExisting = $map.ContainsKey($dn)
                if (-not $hasExisting -or $value -gt $map[$dn]) {
                    $map[$dn] = $value
                }
            }
        }
        catch {
            Write-ReportWarning "Could not query ${hostName}: $($_.Exception.Message)"
        }
    }
    return $map
}

function Export-CsvReport {
    param(
        [Parameter(Mandatory = $true)]$Rows,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )
    $parent = [System.IO.Path]::GetDirectoryName($OutputPath)
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not [System.IO.Directory]::Exists($parent)) {
        [void][System.IO.Directory]::CreateDirectory($parent)
    }
    $encoding = Get-CsvEncodingName
    try {
        $Rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding $encoding
    }
    catch {
        throw "Could not write '$OutputPath'. If that file is open in Excel, close it and export again. $($_.Exception.Message)"
    }
    return $OutputPath
}

function Export-UserLogonReportFile {
    param(
        [Parameter(Mandatory = $true)]$Report,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )
    $exportRows = New-Object System.Collections.Generic.List[object]
    foreach ($row in @($Report)) {
        if ($null -eq $row) { continue }
        $exportRows.Add((ConvertTo-ExportRow -Row $row))
    }
    $exportRows = @($exportRows.ToArray())
    if ($exportRows.Count -eq 0) { throw 'No rows were available to export.' }

    if ([string]::IsNullOrWhiteSpace([System.IO.Path]::GetExtension($OutputPath))) {
        $OutputPath = $OutputPath + '.csv'
    }
    $parent = [System.IO.Path]::GetDirectoryName($OutputPath)
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not [System.IO.Directory]::Exists($parent)) {
        [void][System.IO.Directory]::CreateDirectory($parent)
    }

    $extension = [System.IO.Path]::GetExtension($OutputPath)
    $wantsExcel = [string]::Equals($extension, '.xlsx', [System.StringComparison]::OrdinalIgnoreCase)
    if ($wantsExcel) {
        $module = @(Get-Module -ListAvailable -Name ImportExcel)
        if ($module.Count -eq 0) {
            $csvPath = [System.IO.Path]::ChangeExtension($OutputPath, '.csv')
            Write-ReportWarning "ImportExcel is not installed, so the report was written as CSV. Install it with: Install-Module ImportExcel -Scope CurrentUser"
            return (Export-CsvReport -Rows $exportRows -OutputPath $csvPath)
        }
        try {
            Import-Module ImportExcel -ErrorAction Stop
            $exportRows | Export-Excel -Path $OutputPath -WorksheetName 'Users' -AutoSize -FreezeTopRow -BoldTopRow -TableName 'UserLogonReport' -TableStyle Medium2
            return $OutputPath
        }
        catch {
            $csvPath = [System.IO.Path]::ChangeExtension($OutputPath, '.csv')
            Write-ReportWarning "Excel export failed ($($_.Exception.Message)). Writing CSV instead."
            return (Export-CsvReport -Rows $exportRows -OutputPath $csvPath)
        }
    }
    return (Export-CsvReport -Rows $exportRows -OutputPath $OutputPath)
}

function Invoke-OUUserLogonExport {
    param(
        [Parameter(Mandatory = $true)][string]$SearchBase,
        [string]$OutputPath,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [string]$SearchScope = 'Subtree',
        [bool]$QueryAllDCs = $false,
        [string]$Server,
        [bool]$OnlyEnabled = $false,
        [bool]$ExcludeCritical = $false,
        [switch]$PassThru
    )

    try {
        Import-ActiveDirectoryModule
        $SearchBase = $SearchBase.Trim()
        if ([string]::IsNullOrWhiteSpace($SearchBase)) { throw 'Choose an OU before exporting.' }
        if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Get-DefaultReportPath }
        if (Test-Path -LiteralPath $OutputPath -PathType Container) {
            $OutputPath = Join-Path -Path $OutputPath -ChildPath ([System.IO.Path]::GetFileName((Get-DefaultReportPath)))
        }

        Update-ReportProgress -Activity 'OU User Logon Report' -Status "Checking $SearchBase" -Percent 2 -Log
        [void](Resolve-ADSearchBase -SearchBase $SearchBase -Server $Server)

        Update-ReportProgress -Activity 'OU User Logon Report' -Status "Retrieving users from $SearchBase (scope: $SearchScope)..." -Percent 8 -Log
        $users = @(Get-ADReportUsers -SearchBase $SearchBase -SearchScope $SearchScope -Server $Server -ExcludeCritical $ExcludeCritical)
        $foundCount = $users.Count

        $filtered = New-Object System.Collections.Generic.List[object]
        foreach ($user in $users) {
            if ($null -eq $user) { continue }
            if ($OnlyEnabled -and (Get-ObjectPropertySafe -InputObject $user -Name 'Enabled') -ne $true) { continue }
            if ($ExcludeCritical -and (Test-CriticalAccount -User $user)) { continue }
            [void]$filtered.Add($user)
        }
        $users = @($filtered.ToArray())
        Update-ReportProgress -Activity 'OU User Logon Report' -Status ("Found {0} user account(s); {1} will be exported." -f $foundCount, $users.Count) -Percent 12 -Log

        if ($users.Count -eq 0) {
            throw 'No user accounts matched this OU and the selected filters. Nothing was exported.'
        }

        $lastLogonByDn = $null
        if ($QueryAllDCs) {
            $lastLogonByDn = Get-MostRecentLastLogonMap -SearchBase $SearchBase -SearchScope $SearchScope -Server $Server
        }

        $maxPasswordAge = Get-DomainMaxPasswordAge -Server $Server
        $now = Get-Date
        $report = New-Object System.Collections.Generic.List[object]
        $index = 0
        foreach ($user in $users) {
            $index++
            if (($index % 50) -eq 0 -or $index -eq $users.Count) {
                Test-ReportCancelled
                $percent = [int](75 + (($index / [double]$users.Count) * 15))
                Update-ReportProgress -Activity 'OU User Logon Report' -Status ("Building the report ({0} of {1})" -f $index, $users.Count) -Percent $percent
            }
            [void]$report.Add((New-UserLogonReportRow -User $user -LastLogonByDn $lastLogonByDn -Now $now -QueryAllDCs $QueryAllDCs -MaxPasswordAge $maxPasswordAge))
        }

        $sorted = @($report.ToArray() | Sort-Object SamAccountName, DistinguishedName)
        Update-ReportProgress -Activity 'OU User Logon Report' -Status "Writing $OutputPath" -Percent 95 -Log
        $finalPath = Export-UserLogonReportFile -Report $sorted -OutputPath $OutputPath
        Update-ReportProgress -Activity 'OU User Logon Report' -Status ("Exported {0} account(s) to {1}" -f $sorted.Count, $finalPath) -Percent 100 -Log

        $output = [PSCustomObject]@{
            Path  = $finalPath
            Count = $sorted.Count
        }
        if ($PassThru) {
            $output | Add-Member -NotePropertyName Report -NotePropertyValue $sorted
        }
        return $output
    }
    finally {
        if ($null -eq $script:ReportSync) {
            Write-Progress -Activity 'OU User Logon Report' -Completed
        }
    }
}

function Get-ScriptFunctionMap {
    $map = @{}
    $path = $PSCommandPath
    foreach ($function in @(Get-ChildItem -Path Function:)) {
        $file = $null
        try { $file = $function.ScriptBlock.File } catch { $file = $null }
        if ($file -and [string]::Equals([string]$file, [string]$path, [System.StringComparison]::OrdinalIgnoreCase)) {
            $map[$function.Name] = $function.ScriptBlock
        }
    }
    return $map
}

function New-ReportSync {
    return [hashtable]::Synchronized(@{
            Lines       = (New-Object System.Collections.ArrayList)
            Lock        = (New-Object System.Object)
            Percent     = 0
            Status      = 'Working'
            Done        = $false
            Error       = $null
            Cancelled   = $false
            ResultPath  = $null
            ResultCount = 0
            Inventory   = $null
            Cancel      = $false
        })
}

function Start-ReportJob {
    param(
        [Parameter(Mandatory = $true)][string]$EntryPoint,
        [hashtable]$Arguments
    )
    if ($script:Ui.Running) { return }
    $script:Ui.Running = $true
    Set-UiBusy -Busy $true

    $sync = New-ReportSync
    $script:Ui.Sync = $sync
    $map = Get-ScriptFunctionMap
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $powershell = [powershell]::Create()
    $powershell.Runspace = $runspace

    $wrapper = {
        param($Functions, $EntryPointName, $JobArguments, $Sync)
        Set-StrictMode -Version 2.0
        $ErrorActionPreference = 'Stop'
        try {
            foreach ($key in @($Functions.Keys)) {
                Set-Item -Path "Function:$key" -Value $Functions[$key]
            }
            $script:ReportSync = $Sync
            $script:ReportCancelledMessage = 'OU report export cancelled.'
            $result = & $EntryPointName @JobArguments
            if ($EntryPointName -eq 'Get-ADDirectoryInventory') {
                $Sync.Inventory = $result
            }
            elseif ($null -ne $result) {
                $pathProperty = $result.PSObject.Properties['Path']
                $countProperty = $result.PSObject.Properties['Count']
                if ($null -ne $pathProperty) { $Sync.ResultPath = [string]$pathProperty.Value }
                if ($null -ne $countProperty) { $Sync.ResultCount = [int]$countProperty.Value }
            }
        }
        catch {
            $message = $_.Exception.Message
            if ($message -eq 'OU report export cancelled.') {
                $Sync.Cancelled = $true
            }
            else {
                $Sync.Error = $message
            }
        }
        finally {
            [System.Threading.Monitor]::Enter($Sync.Lock)
            try { $Sync.Done = $true }
            finally { [System.Threading.Monitor]::Exit($Sync.Lock) }
        }
    }

    [void]$powershell.AddScript($wrapper).AddArgument($map).AddArgument($EntryPoint).AddArgument($Arguments).AddArgument($sync)
    $script:Ui.Runner = $powershell
    $script:Ui.Runspace = $runspace
    $script:Ui.Handle = $powershell.BeginInvoke()
    $script:Ui.Timer.Start()
}

function Update-ExportButtonState {
    param([bool]$Enabled)
    $script:Ui.ExportButton.Enabled = $Enabled
    if ($Enabled) {
        $script:Ui.ExportButton.BackColor = ConvertTo-UiColor -Red 0 -Green 120 -Blue 212
    }
    else {
        $script:Ui.ExportButton.BackColor = ConvertTo-UiColor -Red 170 -Green 185 -Blue 200
    }
    $script:Ui.ExportButton.ForeColor = Get-UiKnownColor -Name White
}

function Set-UiBusy {
    param([bool]$Busy)
    $hasSelection = $null -ne $script:Ui.Tree.SelectedNode
    Update-ExportButtonState -Enabled ((-not $Busy) -and $hasSelection)
    $script:Ui.CancelButton.Enabled = $Busy
    $script:Ui.RefreshButton.Enabled = -not $Busy
    $script:Ui.FindButton.Enabled = -not $Busy
    $script:Ui.BrowseButton.Enabled = -not $Busy
    $script:Ui.PdcButton.Enabled = -not $Busy
    $script:Ui.Tree.Enabled = -not $Busy
    $script:Ui.IncludeContainers.Enabled = -not $Busy
}

function Add-UiLog {
    param([string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return }
    $stamp = Get-Date -Format 'HH:mm:ss'
    $script:Ui.Log.AppendText(("[{0}] {1}`r`n" -f $stamp, $Message))
    if ($script:Ui.Log.TextLength -gt 200000) {
        $script:Ui.Log.Text = $script:Ui.Log.Text.Substring($script:Ui.Log.TextLength - 100000)
    }
    $script:Ui.Log.SelectionStart = $script:Ui.Log.TextLength
    $script:Ui.Log.ScrollToCaret()
}

function Add-DirectoryNodes {
    param($Collection, $Nodes)
    foreach ($node in @(Sort-DirectoryNodes -Nodes $Nodes)) {
        if ($null -eq $node) { continue }
        $treeNode = New-Object System.Windows.Forms.TreeNode
        $treeNode.Text = Format-DirectoryNodeLabel -Node $node
        $treeNode.Tag = $node.Item
        $tip = [string]$node.Item.DistinguishedName
        $description = [string](Get-ObjectPropertySafe -InputObject $node.Item -Name 'Description')
        if (-not [string]::IsNullOrWhiteSpace($description)) { $tip = $tip + "`r`n" + $description }
        $treeNode.ToolTipText = $tip
        [void]$Collection.Add($treeNode)
        [void]$script:Ui.FlatNodes.Add($treeNode)
        if ($node.Children.Count -gt 0) {
            Add-DirectoryNodes -Collection $treeNode.Nodes -Nodes $node.Children
        }
    }
}

function Select-TreeDn {
    param([string]$DistinguishedName)
    foreach ($treeNode in (Get-CollectionItems $script:Ui.FlatNodes)) {
        $item = $treeNode.Tag
        $dn = [string](Get-ObjectPropertySafe -InputObject $item -Name 'DistinguishedName')
        if ([string]::Equals($dn, $DistinguishedName, [System.StringComparison]::OrdinalIgnoreCase)) {
            $script:Ui.Tree.SelectedNode = $treeNode
            $treeNode.EnsureVisible()
            return $true
        }
    }
    return $false
}

function Set-DirectoryTree {
    param($Inventory)
    $script:Ui.Inventory = $Inventory
    $roots = @(Build-DirectoryTree -Items $Inventory.Items)
    $script:Ui.FlatNodes = New-Object System.Collections.Generic.List[object]
    $script:Ui.SearchIndex = -1
    $script:Ui.Tree.BeginUpdate()
    try {
        $script:Ui.Tree.Nodes.Clear()
        Add-DirectoryNodes -Collection $script:Ui.Tree.Nodes -Nodes $roots
    }
    finally {
        $script:Ui.Tree.EndUpdate()
    }
    if ($script:Ui.Tree.Nodes.Count -gt 0) {
        $script:Ui.Tree.Nodes[0].Expand()
        $script:Ui.Tree.SelectedNode = $script:Ui.Tree.Nodes[0]
    }
    $script:Ui.DomainLabel.Text = '{0}    PDC {1}    {2} locations' -f $Inventory.Domain, $Inventory.Pdc, $Inventory.Items.Count
    if (-not [string]::IsNullOrWhiteSpace($script:PendingSearchBase)) {
        $found = Select-TreeDn -DistinguishedName $script:PendingSearchBase
        if (-not $found) {
            Add-UiLog "Could not preselect '$($script:PendingSearchBase)'. It is not in this domain's tree."
        }
    }
    Add-UiLog ("Loaded {0} locations from {1}." -f $Inventory.Items.Count, $Inventory.Domain)
}

function Complete-ReportJob {
    $sync = $script:Ui.Sync
    if ($null -eq $sync) { return }

    $lines = @()
    $done = $false
    $errorText = $null
    $cancelled = $false
    $inventory = $null
    $resultPath = $null
    $resultCount = 0
    $percent = 0
    $status = ''

    [System.Threading.Monitor]::Enter($sync.Lock)
    try {
        if ($sync.Lines.Count -gt 0) {
            $lines = @($sync.Lines.ToArray())
            $sync.Lines.Clear()
        }
        $done = [bool]$sync.Done
        $errorText = $sync.Error
        $cancelled = [bool]$sync.Cancelled
        $inventory = $sync.Inventory
        $resultPath = $sync.ResultPath
        $resultCount = $sync.ResultCount
        try { $percent = [int]$sync.Percent } catch { $percent = 0 }
        $status = [string]$sync.Status
    }
    finally {
        [System.Threading.Monitor]::Exit($sync.Lock)
    }

    foreach ($line in $lines) { Add-UiLog -Message ([string]$line) }
    if ($percent -lt 0) { $percent = 0 }
    if ($percent -gt 100) { $percent = 100 }
    $script:Ui.Progress.Value = $percent
    if (-not [string]::IsNullOrWhiteSpace($status)) { $script:Ui.Status.Text = $status }
    if (-not $done) { return }

    $script:Ui.Timer.Stop()
    $runner = $script:Ui.Runner
    try {
        if ($null -ne $runner -and $null -ne $script:Ui.Handle) {
            $runner.EndInvoke($script:Ui.Handle) | Out-Null
        }
    }
    catch {
        if ([string]::IsNullOrWhiteSpace([string]$errorText)) { $errorText = $_.Exception.Message }
    }
    if ($null -ne $runner -and $runner.Streams.Error.Count -gt 0 -and [string]::IsNullOrWhiteSpace([string]$errorText) -and -not $cancelled) {
        $errorText = [string]$runner.Streams.Error[0].Exception.Message
    }
    try { if ($null -ne $runner) { $runner.Dispose() } } catch { }
    try { if ($null -ne $script:Ui.Runspace) { $script:Ui.Runspace.Close(); $script:Ui.Runspace.Dispose() } } catch { }
    $script:Ui.Runner = $null
    $script:Ui.Runspace = $null
    $script:Ui.Handle = $null
    $script:Ui.Running = $false
    Set-UiBusy -Busy $false

    if ($cancelled) {
        $script:Ui.Status.Text = 'Cancelled'
        $script:Ui.Progress.Value = 0
        Add-UiLog 'Cancelled.'
        return
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$errorText)) {
        $script:Ui.Status.Text = 'Failed'
        Add-UiLog ("ERROR: " + $errorText)
        [void](Show-UiMessage -Text ([string]$errorText) -Caption 'OU User Logon Report' -Buttons OK -Icon Error)
        return
    }
    if ($null -ne $inventory) {
        Set-DirectoryTree -Inventory $inventory
        $script:Ui.Status.Text = 'Choose an OU, then export.'
        $script:Ui.Progress.Value = 0
        return
    }

    $script:Ui.Status.Text = "Exported $resultCount account(s)"
    if (-not [string]::IsNullOrWhiteSpace([string]$resultPath)) {
        $script:Ui.OutputPath.Text = [string]$resultPath
    }
    Add-UiLog ("Exported {0} account(s) to {1}" -f $resultCount, $resultPath)
    if ($script:Ui.OpenWhenDone.Checked -and -not [string]::IsNullOrWhiteSpace([string]$resultPath)) {
        try { Invoke-Item -LiteralPath $resultPath }
        catch { Add-UiLog ("Could not open the file: " + $_.Exception.Message) }
    }
    [void](Show-UiMessage -Text ("Exported {0} account(s) to:`r`n{1}" -f $resultCount, $resultPath) -Caption 'Export complete' -Buttons OK -Icon Information)
}

function Start-InventoryLoad {
    $server = ''
    if ($null -ne $script:Ui.Server) { $server = $script:Ui.Server.Text.Trim() }
    $include = $true
    if ($null -ne $script:Ui.IncludeContainers) { $include = [bool]$script:Ui.IncludeContainers.Checked }
    $script:Ui.Status.Text = 'Scanning organizational units...'
    $script:Ui.Progress.Value = 5
    Add-UiLog 'Scanning the OU structure...'
    Start-ReportJob -EntryPoint 'Get-ADDirectoryInventory' -Arguments @{
        Server             = $server
        IncludeContainers  = $include
    }
}

function Get-SelectedScope {
    if ($script:Ui.ScopeOneLevel.Checked) { return 'OneLevel' }
    if ($script:Ui.ScopeBase.Checked) { return 'Base' }
    return 'Subtree'
}

function Start-GuiExport {
    if ($null -eq $script:Ui.Tree.SelectedNode -or $null -eq $script:Ui.Tree.SelectedNode.Tag) {
        [void](Show-UiMessage -Text 'Choose an OU in the tree first.' -Caption 'OU User Logon Report' -Buttons OK -Icon Information)
        return
    }
    $item = $script:Ui.Tree.SelectedNode.Tag
    $dn = [string]$item.DistinguishedName
    $scope = Get-SelectedScope
    $queryAll = [bool]$script:Ui.QueryAllDcs.Checked
    if ([string]$item.ObjectClass -eq 'domainDNS' -and $scope -eq 'Subtree' -and $queryAll) {
        $answer = Show-UiMessage -Text "This queries every domain controller for every user in the domain. It can take a long time.`r`n`r`nContinue?" -Caption 'Confirm domain-wide query' -Buttons YesNo -Icon Warning
        if ("$answer" -ne 'Yes') { return }
    }

    $path = $script:Ui.OutputPath.Text.Trim()
    $extension = '.csv'
    if ($script:Ui.FormatXlsx.Checked) { $extension = '.xlsx' }
    if ([string]::IsNullOrWhiteSpace($path)) { $path = Get-DefaultReportPath -Extension $extension }
    $path = [System.IO.Path]::ChangeExtension($path, $extension)
    $script:Ui.OutputPath.Text = $path

    if ([System.IO.File]::Exists($path)) {
        $overwrite = Show-UiMessage -Text "Overwrite this file?`r`n$path" -Caption 'Overwrite file' -Buttons YesNo -Icon Question
        if ("$overwrite" -ne 'Yes') { return }
    }
    if ($script:Ui.FormatXlsx.Checked -and @(Get-Module -ListAvailable -Name ImportExcel).Count -eq 0) {
        $continue = Show-UiMessage -Text "The ImportExcel module is not installed, so this export will be saved as CSV.`r`n`r`nContinue?" -Caption 'Excel module not found' -Buttons YesNo -Icon Warning
        if ("$continue" -ne 'Yes') { return }
    }

    Start-ReportJob -EntryPoint 'Invoke-OUUserLogonExport' -Arguments @{
        SearchBase       = $dn
        OutputPath       = $path
        SearchScope      = $scope
        QueryAllDCs      = $queryAll
        Server           = $script:Ui.Server.Text.Trim()
        OnlyEnabled      = [bool]$script:Ui.OnlyEnabled.Checked
        ExcludeCritical  = [bool]$script:Ui.ExcludeCritical.Checked
    }
}

function Find-NextTreeNode {
    $query = $script:Ui.SearchBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($query)) { return }
    $nodes = Get-CollectionItems $script:Ui.FlatNodes
    if ($nodes.Count -eq 0) { return }
    $start = [int]$script:Ui.SearchIndex + 1
    if ($start -ge $nodes.Count -or $start -lt 0) { $start = 0 }
    $found = -1
    for ($i = 0; $i -lt $nodes.Count; $i++) {
        $index = ($start + $i) % $nodes.Count
        $item = $nodes[$index].Tag
        $hay = ('{0} {1} {2}' -f $item.Name, $item.DistinguishedName, $item.CanonicalName)
        if ($hay.IndexOf($query, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $found = $index
            break
        }
    }
    if ($found -lt 0) {
        Add-UiLog "No location matches '$query'."
        return
    }
    $script:Ui.SearchIndex = $found
    $script:Ui.Tree.SelectedNode = $nodes[$found]
    $nodes[$found].EnsureVisible()
}

function Get-LoadedType {
    param(
        [Parameter(Mandatory = $true)][string]$TypeName,
        [Parameter(Mandatory = $true)][string]$AssemblyName
    )
    Add-Type -AssemblyName $AssemblyName -ErrorAction SilentlyContinue
    $type = [Type]::GetType("$TypeName, $AssemblyName")
    if ($null -eq $type) { throw "$TypeName from $AssemblyName is not available on this host." }
    return $type
}

function ConvertTo-UiColor {
    param(
        [int]$Red,
        [int]$Green,
        [int]$Blue
    )
    $color = Get-LoadedType -TypeName 'System.Drawing.Color' -AssemblyName 'System.Drawing'
    foreach ($method in @($color.GetMethods())) {
        if ($method.Name -ne 'FromArgb') { continue }
        $parameters = @($method.GetParameters())
        if ($parameters.Count -ne 3) { continue }
        $allIntegers = $true
        foreach ($parameter in $parameters) {
            if ($parameter.ParameterType -ne [int]) { $allIntegers = $false }
        }
        if ($allIntegers) { return $method.Invoke($null, @($Red, $Green, $Blue)) }
    }
    throw 'Could not create a color.'
}

function Get-UiKnownColor {
    param([Parameter(Mandatory = $true)][string]$Name)
    $color = Get-LoadedType -TypeName 'System.Drawing.Color' -AssemblyName 'System.Drawing'
    $flags = [System.Reflection.BindingFlags]'Public,Static'
    $property = $color.GetProperty($Name, $flags)
    if ($null -eq $property) { throw "Unknown color $Name." }
    return $property.GetValue($null, $null)
}

function Enable-UiVisualStyles {
    $application = Get-LoadedType -TypeName 'System.Windows.Forms.Application' -AssemblyName 'System.Windows.Forms'
    $parameterTypes = New-Object System.Type[] 1
    $parameterTypes[0] = [bool]
    $setDefault = $application.GetMethod('SetCompatibleTextRenderingDefault', $parameterTypes)
    try { [void]$setDefault.Invoke($null, @($false)) } catch { }
    $enable = $application.GetMethod('EnableVisualStyles')
    [void]$enable.Invoke($null, $null)
}

function Show-UiMessage {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$Caption = 'OU User Logon Report',
        [string]$Buttons = 'OK',
        [string]$Icon = 'None'
    )
    $messageBox = Get-LoadedType -TypeName 'System.Windows.Forms.MessageBox' -AssemblyName 'System.Windows.Forms'
    $buttonType = Get-LoadedType -TypeName 'System.Windows.Forms.MessageBoxButtons' -AssemblyName 'System.Windows.Forms'
    $iconType = Get-LoadedType -TypeName 'System.Windows.Forms.MessageBoxIcon' -AssemblyName 'System.Windows.Forms'
    $buttonValue = [Enum]::Parse($buttonType, $Buttons)
    $iconValue = [Enum]::Parse($iconType, $Icon)
    foreach ($method in @($messageBox.GetMethods())) {
        if ($method.Name -ne 'Show') { continue }
        $parameters = @($method.GetParameters())
        if ($parameters.Count -ne 4) { continue }
        if ($parameters[0].ParameterType -ne [string] -or $parameters[1].ParameterType -ne [string]) { continue }
        return $method.Invoke($null, @($Text, $Caption, $buttonValue, $iconValue))
    }
    throw 'Could not display the message box.'
}

function New-UiFont {
    param(
        [string]$Name,
        [double]$Size,
        [string]$Style = 'Regular'
    )
    $styleType = Get-LoadedType -TypeName 'System.Drawing.FontStyle' -AssemblyName 'System.Drawing'
    $styleValue = [Enum]::Parse($styleType, $Style)
    try {
        return (New-Object System.Drawing.Font $Name, $Size, $styleValue)
    }
    catch {
        return (New-Object System.Drawing.Font 'Microsoft Sans Serif', $Size, $styleValue)
    }
}

function Test-GuiSupported {
    if (-not [Environment]::UserInteractive) { return $false }
    try {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
            return $false
        }
    }
    catch { return $false }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Start-OUReportGui {
    param(
        [string]$SearchBase,
        [string]$OutputPath,
        [string]$SearchScope = 'Subtree',
        [bool]$QueryAllDCs = $false,
        [string]$Server,
        [bool]$OnlyEnabled = $false,
        [bool]$ExcludeCritical = $false
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Enable-UiVisualStyles

    $script:PendingSearchBase = $SearchBase
    $script:Ui = @{
        Running     = $false
        SearchIndex = -1
        FlatNodes   = (New-Object System.Collections.Generic.List[object])
        Inventory   = $null
        Sync        = $null
        Runner      = $null
        Runspace    = $null
        Handle      = $null
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'OU User Logon Report'
    $form.StartPosition = 'CenterScreen'
    $form.Size = New-Object System.Drawing.Size 1180, 780
    $form.MinimumSize = New-Object System.Drawing.Size 1020, 680
    $form.BackColor = ConvertTo-UiColor -Red 245 -Green 247 -Blue 250
    $form.Font = New-UiFont -Name 'Segoe UI' -Size 9
    $form.KeyPreview = $true

    $header = New-Object System.Windows.Forms.Panel
    $header.Dock = 'Top'
    $header.Height = 72
    $header.BackColor = ConvertTo-UiColor -Red 24 -Green 42 -Blue 68
    $title = New-Object System.Windows.Forms.Label
    $title.Text = 'OU User Logon Report'
    $title.ForeColor = Get-UiKnownColor -Name White
    $title.Font = New-UiFont -Name 'Segoe UI' -Size 16 -Style Bold
    $title.AutoSize = $true
    $title.Location = New-Object System.Drawing.Point 16, 10
    $subtitle = New-Object System.Windows.Forms.Label
    $subtitle.Text = 'Scan the directory, choose an OU, and export last logon and password dates.'
    $subtitle.ForeColor = ConvertTo-UiColor -Red 160 -Green 185 -Blue 215
    $subtitle.AutoSize = $true
    $subtitle.Location = New-Object System.Drawing.Point 18, 42
    [void]$header.Controls.Add($title)
    [void]$header.Controls.Add($subtitle)

    $bottom = New-Object System.Windows.Forms.Panel
    $bottom.Dock = 'Bottom'
    $bottom.Height = 170
    $bottom.Padding = New-Object System.Windows.Forms.Padding 12, 8, 12, 8
    $bottom.BackColor = ConvertTo-UiColor -Red 245 -Green 247 -Blue 250

    $status = New-Object System.Windows.Forms.Label
    $status.Dock = 'Top'
    $status.Height = 22
    $status.Text = 'Starting...'
    $progress = New-Object System.Windows.Forms.ProgressBar
    $progress.Dock = 'Bottom'
    $progress.Height = 18
    $log = New-Object System.Windows.Forms.TextBox
    $log.Multiline = $true
    $log.ReadOnly = $true
    $log.ScrollBars = 'Vertical'
    $log.Dock = 'Fill'
    $log.Font = New-UiFont -Name 'Consolas' -Size 9
    $log.BackColor = Get-UiKnownColor -Name White
    [void]$bottom.Controls.Add($log)
    [void]$bottom.Controls.Add($progress)
    [void]$bottom.Controls.Add($status)

    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'
    $split.Panel1MinSize = 280
    $split.Panel2MinSize = 420

    $left = New-Object System.Windows.Forms.TableLayoutPanel
    $left.Dock = 'Fill'
    $left.ColumnCount = 1
    $left.RowCount = 4
    $left.Padding = New-Object System.Windows.Forms.Padding 12, 10, 12, 10
    [void]$left.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle 'Percent', 100))
    [void]$left.RowStyles.Add((New-Object System.Windows.Forms.RowStyle 'Absolute', 36))
    [void]$left.RowStyles.Add((New-Object System.Windows.Forms.RowStyle 'Absolute', 36))
    [void]$left.RowStyles.Add((New-Object System.Windows.Forms.RowStyle 'Absolute', 28))
    [void]$left.RowStyles.Add((New-Object System.Windows.Forms.RowStyle 'Percent', 100))

    $domainLabel = New-Object System.Windows.Forms.Label
    $domainLabel.Dock = 'Fill'
    $domainLabel.TextAlign = 'MiddleLeft'
    $domainLabel.Text = 'Scanning the directory...'
    $domainLabel.AutoEllipsis = $true
    $domainLabel.Font = New-UiFont -Name 'Segoe UI' -Size 9 -Style Bold

    $searchRow = New-Object System.Windows.Forms.Panel
    $searchRow.Dock = 'Fill'
    $searchBox = New-Object System.Windows.Forms.TextBox
    $searchBox.Dock = 'Fill'
    $findButton = New-Object System.Windows.Forms.Button
    $findButton.Text = 'Find'
    $findButton.Dock = 'Right'
    $findButton.Width = 72
    $refreshButton = New-Object System.Windows.Forms.Button
    $refreshButton.Text = 'Refresh'
    $refreshButton.Dock = 'Right'
    $refreshButton.Width = 84
    # Add the fill control first so the right-docked buttons keep their width.
    [void]$searchRow.Controls.Add($searchBox)
    [void]$searchRow.Controls.Add($findButton)
    [void]$searchRow.Controls.Add($refreshButton)

    $includeContainers = New-Object System.Windows.Forms.CheckBox
    $includeContainers.Text = 'Include containers such as Users and Computers'
    $includeContainers.Checked = $true
    $includeContainers.AutoSize = $true
    $includeContainers.Dock = 'Fill'

    $tree = New-Object System.Windows.Forms.TreeView
    $tree.Dock = 'Fill'
    $tree.HideSelection = $false
    $tree.ShowNodeToolTips = $true
    $tree.Font = New-UiFont -Name 'Segoe UI' -Size 10

    $left.Controls.Add($domainLabel, 0, 0)
    $left.Controls.Add($searchRow, 0, 1)
    $left.Controls.Add($includeContainers, 0, 2)
    $left.Controls.Add($tree, 0, 3)
    [void]$split.Panel1.Controls.Add($left)

    $right = New-Object System.Windows.Forms.Panel
    $right.Dock = 'Fill'
    $right.AutoScroll = $true
    $inner = New-Object System.Windows.Forms.Panel
    $inner.Location = New-Object System.Drawing.Point 0, 0
    $inner.Size = New-Object System.Drawing.Size 500, 680
    [void]$right.Controls.Add($inner)
    [void]$split.Panel2.Controls.Add($right)

    $targetGroup = New-Object System.Windows.Forms.GroupBox
    $targetGroup.Text = 'Target'
    $targetGroup.Location = New-Object System.Drawing.Point 12, 8
    $targetGroup.Size = New-Object System.Drawing.Size 470, 214
    $selectedName = New-Object System.Windows.Forms.Label
    $selectedName.Location = New-Object System.Drawing.Point 12, 22
    $selectedName.Size = New-Object System.Drawing.Size 446, 22
    $selectedName.AutoEllipsis = $true
    $selectedName.Font = New-UiFont -Name 'Segoe UI' -Size 10 -Style Bold
    $selectedName.Text = 'No OU selected'
    $selectedDn = New-Object System.Windows.Forms.TextBox
    $selectedDn.Location = New-Object System.Drawing.Point 12, 46
    $selectedDn.Size = New-Object System.Drawing.Size 446, 44
    $selectedDn.Multiline = $true
    $selectedDn.ReadOnly = $true
    $selectedDn.ScrollBars = 'Vertical'

    $scopeLabel = New-Object System.Windows.Forms.Label
    $scopeLabel.Text = 'Search scope'
    $scopeLabel.Location = New-Object System.Drawing.Point 12, 98
    $scopeLabel.AutoSize = $true
    $scopeSubtree = New-Object System.Windows.Forms.RadioButton
    $scopeSubtree.Text = 'Subtree (include child OUs)'
    $scopeSubtree.Location = New-Object System.Drawing.Point 12, 118
    $scopeSubtree.AutoSize = $true
    $scopeSubtree.Checked = ($SearchScope -eq 'Subtree')
    $scopeOneLevel = New-Object System.Windows.Forms.RadioButton
    $scopeOneLevel.Text = 'One level'
    $scopeOneLevel.Location = New-Object System.Drawing.Point 12, 140
    $scopeOneLevel.AutoSize = $true
    $scopeOneLevel.Checked = ($SearchScope -eq 'OneLevel')
    $scopeBase = New-Object System.Windows.Forms.RadioButton
    $scopeBase.Text = 'Base (this object only)'
    $scopeBase.Location = New-Object System.Drawing.Point 120, 140
    $scopeBase.AutoSize = $true
    $scopeBase.Checked = ($SearchScope -eq 'Base')
    $scopeHint = New-Object System.Windows.Forms.Label
    $scopeHint.Location = New-Object System.Drawing.Point 12, 166
    $scopeHint.Size = New-Object System.Drawing.Size 446, 36
    $scopeHint.Text = 'Subtree includes users in child OUs. One level is only the users directly in the selected OU.'
    [void]$targetGroup.Controls.Add($selectedName)
    [void]$targetGroup.Controls.Add($selectedDn)
    [void]$targetGroup.Controls.Add($scopeLabel)
    [void]$targetGroup.Controls.Add($scopeSubtree)
    [void]$targetGroup.Controls.Add($scopeOneLevel)
    [void]$targetGroup.Controls.Add($scopeBase)
    [void]$targetGroup.Controls.Add($scopeHint)

    $accountGroup = New-Object System.Windows.Forms.GroupBox
    $accountGroup.Text = 'Accounts'
    $accountGroup.Location = New-Object System.Drawing.Point 12, 230
    $accountGroup.Size = New-Object System.Drawing.Size 470, 78
    $onlyEnabledBox = New-Object System.Windows.Forms.CheckBox
    $onlyEnabledBox.Text = 'Enabled accounts only'
    $onlyEnabledBox.Location = New-Object System.Drawing.Point 12, 24
    $onlyEnabledBox.AutoSize = $true
    $onlyEnabledBox.Checked = [bool]$OnlyEnabled
    $excludeCriticalBox = New-Object System.Windows.Forms.CheckBox
    $excludeCriticalBox.Text = 'Skip critical system accounts (krbtgt and similar)'
    $excludeCriticalBox.Location = New-Object System.Drawing.Point 12, 48
    $excludeCriticalBox.AutoSize = $true
    $excludeCriticalBox.Checked = [bool]$ExcludeCritical
    [void]$accountGroup.Controls.Add($onlyEnabledBox)
    [void]$accountGroup.Controls.Add($excludeCriticalBox)

    $logonGroup = New-Object System.Windows.Forms.GroupBox
    $logonGroup.Text = 'Last logon'
    $logonGroup.Location = New-Object System.Drawing.Point 12, 316
    $logonGroup.Size = New-Object System.Drawing.Size 470, 124
    $replicatedRadio = New-Object System.Windows.Forms.RadioButton
    $replicatedRadio.Text = 'Replicated timestamp (fast, can lag by up to 14 days)'
    $replicatedRadio.Location = New-Object System.Drawing.Point 12, 22
    $replicatedRadio.AutoSize = $true
    $replicatedRadio.Checked = -not $QueryAllDCs
    $queryAllRadio = New-Object System.Windows.Forms.RadioButton
    $queryAllRadio.Text = 'Query every domain controller (accurate, slower)'
    $queryAllRadio.Location = New-Object System.Drawing.Point 12, 46
    $queryAllRadio.AutoSize = $true
    $queryAllRadio.Checked = [bool]$QueryAllDCs
    $serverLabel = New-Object System.Windows.Forms.Label
    $serverLabel.Text = 'Domain controller (optional)'
    $serverLabel.Location = New-Object System.Drawing.Point 12, 74
    $serverLabel.AutoSize = $true
    $serverBox = New-Object System.Windows.Forms.TextBox
    $serverBox.Location = New-Object System.Drawing.Point 12, 94
    $serverBox.Size = New-Object System.Drawing.Size 330, 24
    $serverBox.Text = [string]$Server
    $pdcButton = New-Object System.Windows.Forms.Button
    $pdcButton.Text = 'Use PDC'
    $pdcButton.Location = New-Object System.Drawing.Point 350, 92
    $pdcButton.Size = New-Object System.Drawing.Size 108, 26
    [void]$logonGroup.Controls.Add($replicatedRadio)
    [void]$logonGroup.Controls.Add($queryAllRadio)
    [void]$logonGroup.Controls.Add($serverLabel)
    [void]$logonGroup.Controls.Add($serverBox)
    [void]$logonGroup.Controls.Add($pdcButton)

    $outputGroup = New-Object System.Windows.Forms.GroupBox
    $outputGroup.Text = 'Output'
    $outputGroup.Location = New-Object System.Drawing.Point 12, 448
    $outputGroup.Size = New-Object System.Drawing.Size 470, 130
    $formatCsv = New-Object System.Windows.Forms.RadioButton
    $formatCsv.Text = 'CSV'
    $formatCsv.Location = New-Object System.Drawing.Point 12, 22
    $formatCsv.AutoSize = $true
    $formatXlsx = New-Object System.Windows.Forms.RadioButton
    $formatXlsx.Text = 'Excel (.xlsx, needs ImportExcel)'
    $formatXlsx.Location = New-Object System.Drawing.Point 80, 22
    $formatXlsx.AutoSize = $true
    $initialPath = $OutputPath
    if ([string]::IsNullOrWhiteSpace($initialPath)) { $initialPath = Get-DefaultReportPath -Extension '.csv' }
    if ([string]::Equals([System.IO.Path]::GetExtension([string]$initialPath), '.xlsx', [System.StringComparison]::OrdinalIgnoreCase)) {
        $formatXlsx.Checked = $true
    }
    else {
        $formatCsv.Checked = $true
    }
    $outputBox = New-Object System.Windows.Forms.TextBox
    $outputBox.Location = New-Object System.Drawing.Point 12, 52
    $outputBox.Size = New-Object System.Drawing.Size 350, 24
    $outputBox.Text = [string]$initialPath
    $browseButton = New-Object System.Windows.Forms.Button
    $browseButton.Text = 'Browse...'
    $browseButton.Location = New-Object System.Drawing.Point 370, 50
    $browseButton.Size = New-Object System.Drawing.Size 88, 26
    $openWhenDone = New-Object System.Windows.Forms.CheckBox
    $openWhenDone.Text = 'Open the file when the export finishes'
    $openWhenDone.Location = New-Object System.Drawing.Point 12, 88
    $openWhenDone.AutoSize = $true
    $openWhenDone.Checked = $true
    [void]$outputGroup.Controls.Add($formatCsv)
    [void]$outputGroup.Controls.Add($formatXlsx)
    [void]$outputGroup.Controls.Add($outputBox)
    [void]$outputGroup.Controls.Add($browseButton)
    [void]$outputGroup.Controls.Add($openWhenDone)

    $exportButton = New-Object System.Windows.Forms.Button
    $exportButton.Text = 'Export report'
    $exportButton.Location = New-Object System.Drawing.Point 12, 590
    $exportButton.Size = New-Object System.Drawing.Size 220, 36
    $exportButton.Enabled = $false
    $exportButton.FlatStyle = 'Flat'
    $exportButton.BackColor = ConvertTo-UiColor -Red 0 -Green 120 -Blue 212
    $exportButton.ForeColor = Get-UiKnownColor -Name White
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = 'Cancel'
    $cancelButton.Location = New-Object System.Drawing.Point 244, 590
    $cancelButton.Size = New-Object System.Drawing.Size 110, 36
    $cancelButton.Enabled = $false
    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = 'Close'
    $closeButton.Location = New-Object System.Drawing.Point 364, 590
    $closeButton.Size = New-Object System.Drawing.Size 118, 36
    [void]$inner.Controls.Add($targetGroup)
    [void]$inner.Controls.Add($accountGroup)
    [void]$inner.Controls.Add($logonGroup)
    [void]$inner.Controls.Add($outputGroup)
    [void]$inner.Controls.Add($exportButton)
    [void]$inner.Controls.Add($cancelButton)
    [void]$inner.Controls.Add($closeButton)

    $script:Ui.Form = $form
    $script:Ui.Tree = $tree
    $script:Ui.DomainLabel = $domainLabel
    $script:Ui.SearchBox = $searchBox
    $script:Ui.FindButton = $findButton
    $script:Ui.RefreshButton = $refreshButton
    $script:Ui.IncludeContainers = $includeContainers
    $script:Ui.SelectedName = $selectedName
    $script:Ui.SelectedDn = $selectedDn
    $script:Ui.ScopeSubtree = $scopeSubtree
    $script:Ui.ScopeOneLevel = $scopeOneLevel
    $script:Ui.ScopeBase = $scopeBase
    $script:Ui.ScopeHint = $scopeHint
    $script:Ui.OnlyEnabled = $onlyEnabledBox
    $script:Ui.ExcludeCritical = $excludeCriticalBox
    $script:Ui.QueryAllDcs = $queryAllRadio
    $script:Ui.Server = $serverBox
    $script:Ui.PdcButton = $pdcButton
    $script:Ui.FormatCsv = $formatCsv
    $script:Ui.FormatXlsx = $formatXlsx
    $script:Ui.OutputPath = $outputBox
    $script:Ui.BrowseButton = $browseButton
    $script:Ui.OpenWhenDone = $openWhenDone
    $script:Ui.ExportButton = $exportButton
    $script:Ui.CancelButton = $cancelButton
    $script:Ui.Log = $log
    $script:Ui.Progress = $progress
    $script:Ui.Status = $status
    $script:Ui.Split = $split

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 200
    $timer.Add_Tick({ Complete-ReportJob })
    $script:Ui.Timer = $timer
    $tree.Add_AfterSelect({ Update-SelectedOuDisplay })
    $findButton.Add_Click({ Find-NextTreeNode })
    $searchBox.Add_TextChanged({ $script:Ui.SearchIndex = -1 })
    $searchBox.Add_KeyDown({
            if ($_.KeyCode.ToString() -eq 'Enter') {
                Find-NextTreeNode
                $_.SuppressKeyPress = $true
            }
        })
    $refreshButton.Add_Click({ Start-InventoryLoad })
    $includeContainers.Add_CheckedChanged({
            if (-not $script:Ui.Running) { Start-InventoryLoad }
        })
    $exportButton.Add_Click({ Start-GuiExport })
    $cancelButton.Add_Click({
            if ($null -ne $script:Ui.Sync) { $script:Ui.Sync.Cancel = $true }
            $script:Ui.Status.Text = 'Cancelling...'
            Add-UiLog 'Cancel requested. It takes effect when the current directory query returns.'
        })
    $closeButton.Add_Click({ $script:Ui.Form.Close() })
    $pdcButton.Add_Click({
            if ($null -eq $script:Ui.Inventory -or [string]::IsNullOrWhiteSpace([string]$script:Ui.Inventory.Pdc)) {
                Add-UiLog 'The PDC emulator is not known yet.'
                return
            }
            $script:Ui.Server.Text = [string]$script:Ui.Inventory.Pdc
            Start-InventoryLoad
        })
    $browseButton.Add_Click({ Show-ReportSaveDialog })
    $formatCsv.Add_CheckedChanged({
            if ($script:Ui.FormatCsv.Checked -and -not [string]::IsNullOrWhiteSpace($script:Ui.OutputPath.Text)) {
                $script:Ui.OutputPath.Text = [System.IO.Path]::ChangeExtension($script:Ui.OutputPath.Text, '.csv')
            }
        })
    $formatXlsx.Add_CheckedChanged({
            if ($script:Ui.FormatXlsx.Checked -and -not [string]::IsNullOrWhiteSpace($script:Ui.OutputPath.Text)) {
                $script:Ui.OutputPath.Text = [System.IO.Path]::ChangeExtension($script:Ui.OutputPath.Text, '.xlsx')
            }
        })
    $form.Add_KeyDown({
            if ($_.KeyCode.ToString() -eq 'F5') {
                if (-not $script:Ui.Running) { Start-InventoryLoad }
                $_.Handled = $true
            }
            elseif ($_.Control -and $_.KeyCode.ToString() -eq 'F') {
                [void]$script:Ui.SearchBox.Focus()
                $_.Handled = $true
            }
        })
    $form.Add_Shown({
            try { $script:Ui.Split.SplitterDistance = 500 } catch { }
            Start-InventoryLoad
        })
    $form.Add_FormClosing({
            if ($script:Ui.Running) {
                $answer = Show-UiMessage -Text 'An operation is still running. Cancel it and close?' -Caption 'Close' -Buttons YesNo -Icon Question
                if ("$answer" -ne 'Yes') {
                    $_.Cancel = $true
                    return
                }
                if ($null -ne $script:Ui.Sync) { $script:Ui.Sync.Cancel = $true }
                try { if ($null -ne $script:Ui.Runner) { [void]$script:Ui.Runner.Stop() } } catch { }
            }
            try { $script:Ui.Timer.Stop() } catch { }
            try { $script:Ui.Timer.Dispose() } catch { }
        })

    [void]$form.Controls.Add($split)
    [void]$form.Controls.Add($bottom)
    [void]$form.Controls.Add($header)
    [void]$form.ShowDialog()
    try { $timer.Dispose() } catch { }
}

function Update-SelectedOuDisplay {
    $node = $script:Ui.Tree.SelectedNode
    if ($null -eq $node -or $null -eq $node.Tag) { return }
    $item = $node.Tag
    $script:Ui.SelectedName.Text = [string]$item.Name
    $script:Ui.SelectedDn.Text = [string]$item.DistinguishedName
    if ([string]$item.ObjectClass -eq 'domainDNS' -and $script:Ui.ScopeSubtree.Checked) {
        $script:Ui.ScopeHint.Text = 'Domain root with Subtree exports every user in the domain.'
    }
    else {
        $script:Ui.ScopeHint.Text = 'Subtree includes users in child OUs. One level is only the users directly in the selected OU.'
    }
    if (-not $script:Ui.Running) { Update-ExportButtonState -Enabled $true }
}

function Show-ReportSaveDialog {
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Title = 'Save the user logon report'
    $dialog.Filter = 'CSV files (*.csv)|*.csv|Excel workbook (*.xlsx)|*.xlsx'
    $current = [string]$script:Ui.OutputPath.Text
    if (-not [string]::IsNullOrWhiteSpace($current)) {
        $dialog.FileName = [System.IO.Path]::GetFileName($current)
        $directory = [System.IO.Path]::GetDirectoryName($current)
        if (-not [string]::IsNullOrWhiteSpace($directory) -and [System.IO.Directory]::Exists($directory)) {
            $dialog.InitialDirectory = $directory
        }
    }
    if ($script:Ui.FormatXlsx.Checked) { $dialog.FilterIndex = 2 }
    $dialogResult = $dialog.ShowDialog()
    if ($dialogResult.ToString() -ne 'OK') { return }
    $script:Ui.OutputPath.Text = $dialog.FileName
    if ([string]::Equals([System.IO.Path]::GetExtension($dialog.FileName), '.xlsx', [System.StringComparison]::OrdinalIgnoreCase)) {
        $script:Ui.FormatXlsx.Checked = $true
    }
    else {
        $script:Ui.FormatCsv.Checked = $true
    }
}

function Read-ConsoleDefault {
    param(
        [string]$Prompt,
        [string]$Default
    )
    $entered = Read-Host ("{0} [{1}]" -f $Prompt, $Default)
    if ([string]::IsNullOrWhiteSpace($entered)) { return $Default }
    return $entered.Trim()
}

function Find-ConsoleNode {
    param($Roots, $Current)
    $query = Read-Host 'Find name or distinguished name (Enter cancels)'
    if ([string]::IsNullOrWhiteSpace($query)) { return $Current }
    $matches = New-Object System.Collections.Generic.List[object]
    $pending = New-Object System.Collections.Generic.Stack[object]
    foreach ($node in (Get-CollectionItems $Roots)) {
        if ($null -ne $node) { $pending.Push($node) }
    }
    while ($pending.Count -gt 0) {
        $node = $pending.Pop()
        $hay = '{0} {1} {2}' -f $node.Item.Name, $node.Item.DistinguishedName, $node.Item.CanonicalName
        if ($hay.IndexOf($query.Trim(), [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            [void]$matches.Add($node)
        }
        foreach ($child in (Get-CollectionItems $node.Children)) {
            if ($null -ne $child) { $pending.Push($child) }
        }
    }
    if ($matches.Count -eq 0) {
        Write-Host 'No matches.' -ForegroundColor Yellow
        return $Current
    }
    $limit = [Math]::Min(30, $matches.Count)
    for ($i = 0; $i -lt $limit; $i++) {
        Write-Host ('  {0,3}) {1}' -f ($i + 1), $matches[$i].Item.DistinguishedName)
    }
    if ($matches.Count -gt $limit) {
        Write-Host ("  {0} more matches were not listed. Narrow the search." -f ($matches.Count - $limit))
    }
    $pick = Read-Host 'Open match number (Enter cancels)'
    $number = 0
    if ([int]::TryParse([string]$pick, [ref]$number) -and $number -ge 1 -and $number -le $limit) {
        return $matches[$number - 1]
    }
    return $Current
}

function Start-OUReportConsole {
    param(
        [string]$SearchBase,
        [string]$OutputPath,
        [string]$SearchScope = 'Subtree',
        [bool]$QueryAllDCs = $false,
        [string]$Server,
        [bool]$OnlyEnabled = $false,
        [bool]$ExcludeCritical = $false
    )

    Write-Host ''
    Write-Host 'OU User Logon Report' -ForegroundColor Cyan
    Write-Host 'Scan the directory, choose an OU, then export last logon and password dates.'
    Write-Host 'Commands: a number opens that child, S selects, U goes up, F finds, R rescans, Q quits.'
    Write-Host ''
    if ([string]::IsNullOrWhiteSpace($Server)) {
        $enteredServer = Read-Host 'Domain controller (press Enter for the default)'
        if (-not [string]::IsNullOrWhiteSpace($enteredServer)) { $Server = $enteredServer.Trim() }
    }

    $includeContainers = $true
    $inventory = Get-ADDirectoryInventory -Server $Server -IncludeContainers:$includeContainers
    $roots = @(Build-DirectoryTree -Items $inventory.Items)
    if ($roots.Count -eq 0) { throw 'The directory scan did not return any locations.' }
    $current = $roots[0]
    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
        $match = Find-TreeNodeByDn -Nodes $roots -DistinguishedName $SearchBase
        if ($null -ne $match) { $current = $match }
        else { Write-ReportWarning "Could not find '$SearchBase' in the scanned tree. Starting at the domain root." }
    }

    $selected = $null
    while ($null -eq $selected) {
        Write-Host ''
        Write-Host ('Domain:   {0}   PDC: {1}' -f $inventory.Domain, $inventory.Pdc) -ForegroundColor DarkCyan
        Write-Host ('Location: {0}' -f (Format-DirectoryNodeLabel -Node $current)) -ForegroundColor Green
        Write-Host ('DN:       {0}' -f $current.Item.DistinguishedName)
        $children = @(Sort-DirectoryNodes -Nodes $current.Children)
        if ($children.Count -eq 0) {
            Write-Host '  (no child OUs)'
        }
        else {
            for ($i = 0; $i -lt $children.Count; $i++) {
                $description = [string]$children[$i].Item.Description
                $line = '  {0,3}) {1}' -f ($i + 1), (Format-DirectoryNodeLabel -Node $children[$i])
                if (-not [string]::IsNullOrWhiteSpace($description) -and $description -ne 'Domain root') {
                    $line = $line + '  -  ' + $description
                }
                Write-Host $line
            }
        }
        Write-Host 'S) Select this location    U) Up    F) Find    R) Refresh    Q) Quit'
        $choice = Read-Host 'Choice'
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }
        $choice = $choice.Trim()
        if ($choice -match '^(?i)(q|quit)$') {
            Write-Host 'Cancelled.'
            return
        }
        if ($choice -match '^(?i)(s|select)$') {
            $selected = $current
            break
        }
        if ($choice -match '^(?i)(u|up)$') {
            if ([string]::IsNullOrWhiteSpace([string]$current.ParentDn)) {
                Write-Host 'Already at the top of the tree.'
                continue
            }
            $parent = Find-TreeNodeByDn -Nodes $roots -DistinguishedName ([string]$current.ParentDn)
            if ($null -eq $parent) { Write-Host 'That parent is not in the current tree.' }
            else { $current = $parent }
            continue
        }
        if ($choice -match '^(?i)(f|find)$') {
            $current = Find-ConsoleNode -Roots $roots -Current $current
            continue
        }
        if ($choice -match '^(?i)(r|refresh)$') {
            $inventory = Get-ADDirectoryInventory -Server $Server -IncludeContainers:$includeContainers
            $roots = @(Build-DirectoryTree -Items $inventory.Items)
            if ($roots.Count -eq 0) { throw 'The directory scan did not return any locations.' }
            $current = $roots[0]
            continue
        }
        $number = 0
        if ([int]::TryParse($choice, [ref]$number)) {
            if ($number -ge 1 -and $number -le $children.Count) { $current = $children[$number - 1] }
            else { Write-Host 'That number is not in the list.' }
            continue
        }
        Write-Host 'Enter a number, or S, U, F, R, or Q.'
    }

    Write-Host ''
    Write-Host ('Selected: {0}' -f $selected.Item.DistinguishedName) -ForegroundColor Green
    $scopeInput = Read-ConsoleDefault -Prompt 'Search scope (Subtree, OneLevel, Base)' -Default $SearchScope
    switch -Regex ($scopeInput) {
        '^(?i)subtree$' { $SearchScope = 'Subtree' }
        '^(?i)one\s*level$' { $SearchScope = 'OneLevel' }
        '^(?i)base$' { $SearchScope = 'Base' }
        default { Write-Host "Keeping search scope $SearchScope." }
    }
    $logonDefault = $(if ($QueryAllDCs) { 'Y' } else { 'N' })
    $logonAnswer = Read-ConsoleDefault -Prompt 'Query every domain controller for the real lastLogon value? (Y/N)' -Default $logonDefault
    $QueryAllDCs = $logonAnswer -match '^(?i)(y|yes)$'
    $enabledDefault = $(if ($OnlyEnabled) { 'Y' } else { 'N' })
    $enabledAnswer = Read-ConsoleDefault -Prompt 'Enabled accounts only? (Y/N)' -Default $enabledDefault
    $OnlyEnabled = $enabledAnswer -match '^(?i)(y|yes)$'
    $criticalDefault = $(if ($ExcludeCritical) { 'Y' } else { 'N' })
    $criticalAnswer = Read-ConsoleDefault -Prompt 'Skip critical system accounts? (Y/N)' -Default $criticalDefault
    $ExcludeCritical = $criticalAnswer -match '^(?i)(y|yes)$'
    if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Get-DefaultReportPath }
    $OutputPath = Read-ConsoleDefault -Prompt 'Output file' -Default $OutputPath
    if ([System.IO.File]::Exists($OutputPath)) {
        $overwrite = Read-ConsoleDefault -Prompt 'That file exists. Overwrite? (Y/N)' -Default 'N'
        if ($overwrite -notmatch '^(?i)(y|yes)$') {
            Write-Host 'Cancelled.'
            return
        }
    }

    $result = Invoke-OUUserLogonExport -SearchBase ([string]$selected.Item.DistinguishedName) -OutputPath $OutputPath -SearchScope $SearchScope -QueryAllDCs $QueryAllDCs -Server $Server -OnlyEnabled $OnlyEnabled -ExcludeCritical $ExcludeCritical
    Write-Host ("Exported {0} account(s) to: {1}" -f $result.Count, $result.Path) -ForegroundColor Green
    $open = Read-ConsoleDefault -Prompt 'Open the file now? (Y/N)' -Default 'N'
    if ($open -match '^(?i)(y|yes)$') {
        Invoke-Item -LiteralPath ([string]$result.Path)
    }
}

function Invoke-OUUserLogonReportSelfTest {
    $script:SelfTestFailures = 0
    $script:SelfTestCount = 0
    $WarningPreference = 'SilentlyContinue'

    function Assert-Same {
        param($Name, $Expected, $Actual)
        $script:SelfTestCount++
        $same = $false
        if ($null -eq $Expected -and $null -eq $Actual) { $same = $true }
        elseif ($null -ne $Expected -and $null -ne $Actual -and [string]$Expected -eq [string]$Actual) { $same = $true }
        if (-not $same) {
            $script:SelfTestFailures++
            Write-Host "FAIL  $Name" -ForegroundColor Red
            Write-Host "      expected: $Expected"
            Write-Host "      actual:   $Actual"
        }
    }

    Assert-Same 'parent of escaped OU' 'OU=Staff,DC=contoso,DC=com' (Get-ADParentDistinguishedName 'OU=Sales\, East,OU=Staff,DC=contoso,DC=com')
    Assert-Same 'parent of user' 'OU=Sales\, East,OU=Staff,DC=contoso,DC=com' (Get-ADParentDistinguishedName 'CN=Jane Doe,OU=Sales\, East,OU=Staff,DC=contoso,DC=com')
    Assert-Same 'parent of domain' 'DC=com' (Get-ADParentDistinguishedName 'DC=contoso,DC=com')
    Assert-Same 'parent of two-part OU' 'DC=contoso,DC=com' (Get-ADParentDistinguishedName 'OU=Staff,DC=contoso,DC=com')
    $onePart = @('DC=com')
    Assert-Same 'one RDN stays one item' '1' (Get-CollectionItems $onePart).Count
    $directoryList = New-Object System.Collections.Generic.List[object]
    [void]$directoryList.Add('Staff')
    [void]$directoryList.Add('Users')
    Assert-Same 'generic list count' '2' (Get-CollectionItems $directoryList).Count
    Assert-Same 'parent of single RDN' $null (Get-ADParentDistinguishedName 'DC=com')
    Assert-Same 'parent of trailing escape' $null (Get-ADParentDistinguishedName 'OU=Sales\')
    Assert-Same 'exclude system container' 'True' (Test-ExcludedInfrastructureDn 'CN=Policies,CN=System,DC=contoso,DC=com')
    Assert-Same 'keep OU named System' 'False' (Test-ExcludedInfrastructureDn 'OU=System,DC=contoso,DC=com')
    Assert-Same 'keep Users container' 'False' (Test-ExcludedInfrastructureDn 'CN=Users,DC=contoso,DC=com')
    Assert-Same 'exclude Keys container' 'True' (Test-ExcludedInfrastructureDn 'CN=Keys,DC=contoso,DC=com')

    $full = @('a', 'b', 'c')
    $basic = @('a', 'b')
    $sets = @(
        ,$full
        ,$basic
    )
    Assert-Same 'attribute set count' '2' $sets.Count
    Assert-Same 'attribute set length' '3' @($sets[0]).Count
    $preservedNumber = ConvertTo-SpreadsheetSafeValue 4
    Assert-Same 'number type' 'Int32' $preservedNumber.GetType().Name

    Assert-Same 'filetime null' $null (Convert-FileTimeSafe $null)
    Assert-Same 'filetime zero' $null (Convert-FileTimeSafe 0)
    Assert-Same 'filetime string zero' $null (Convert-FileTimeSafe '0')
    Assert-Same 'filetime negative' $null (Convert-FileTimeSafe -1)
    Assert-Same 'filetime max' $null (Convert-FileTimeSafe ([int64]::MaxValue))
    Assert-Same 'filetime text' $null (Convert-FileTimeSafe 'not-a-time')
    $sample = [datetime]::new(2024, 3, 1, 8, 30, 0)
    $converted = Convert-FileTimeSafe $sample.ToFileTime()
    Assert-Same 'filetime roundtrip' $sample.ToString('yyyy-MM-dd HH:mm:ss') $converted.ToString('yyyy-MM-dd HH:mm:ss')

    $throwing = New-Object PSObject
    Add-Member -InputObject $throwing -MemberType ScriptProperty -Name pwdLastSet -Value { throw 'unavailable' }
    Assert-Same 'throwing property' $null (Get-ObjectPropertySafe -InputObject $throwing -Name 'pwdLastSet')
    Assert-Same 'missing property' $null (Get-ObjectPropertySafe -InputObject $throwing -Name 'DisplayName')
    Assert-Same 'formula text' "'=1+1" (ConvertTo-SpreadsheetSafeValue '=1+1')
    Assert-Same 'plain text' 'Jane' (ConvertTo-SpreadsheetSafeValue 'Jane')
    Assert-Same 'number stays number' '3' (ConvertTo-SpreadsheetSafeValue 3)
    Assert-Same 'bool stays bool' 'True' (ConvertTo-SpreadsheetSafeValue $true)
    Assert-Same 'csv encoding' $(if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }) (Get-CsvEncodingName)

    Assert-Same 'krbtgt is critical' 'True' (Test-CriticalAccount ([PSCustomObject]@{ SamAccountName = 'krbtgt' }))
    Assert-Same 'flagged account is critical' 'True' (Test-CriticalAccount ([PSCustomObject]@{ SamAccountName = 'svc'; isCriticalSystemObject = $true }))
    Assert-Same 'normal account is not critical' 'False' (Test-CriticalAccount ([PSCustomObject]@{ SamAccountName = 'jane' }))

    $now = [datetime]::new(2024, 3, 10, 12, 0, 0)
    $logon = [datetime]::new(2024, 3, 7, 18, 0, 0)
    $created = [datetime]::new(2020, 1, 2, 3, 4, 5)
    $user = [PSCustomObject]@{
        SamAccountName       = 'jsmith'
        UserPrincipalName    = 'jsmith@contoso.com'
        DisplayName          = '=1+1'
        Enabled              = $true
        DistinguishedName    = 'CN=Jane Doe,OU=Sales\, East,OU=Staff,DC=contoso,DC=com'
        CanonicalName        = 'contoso.com/Staff/Sales, East/Jane Doe'
        whenCreated          = $created
        lastLogonTimestamp   = $logon.ToFileTime()
        pwdLastSet           = 0
        PasswordNeverExpires = $false
        LockedOut            = $false
    }
    $row = New-UserLogonReportRow -User $user -LastLogonByDn $null -Now $now -QueryAllDCs $false -MaxPasswordAge $null
    Assert-Same 'days since logon' '2' $row.DaysSinceLastLogon
    Assert-Same 'must change text' 'Must change at next logon' $row.PasswordLastSet
    Assert-Same 'must change not expired' 'False' $row.PasswordExpired
    Assert-Same 'must change note' 'Must change at next logon' $row.PasswordStatusNote
    Assert-Same 'parent ou column' 'OU=Sales\, East,OU=Staff,DC=contoso,DC=com' $row.ParentDistinguishedName
    Assert-Same 'created format' '2020-01-02 03:04:05' $row.WhenCreated
    Assert-Same 'logon source replicated' 'lastLogonTimestamp' $row.LogonSource
    Assert-Same 'display kept until export' '=1+1' $row.DisplayName

    $older = [datetime]::new(2024, 1, 1, 0, 0, 0)
    $newer = [datetime]::new(2024, 3, 9, 9, 0, 0)
    $dn = 'CN=Jane Doe,OU=Staff,DC=contoso,DC=com'
    $map = New-Object 'System.Collections.Generic.Dictionary[string,int64]' ([System.StringComparer]::OrdinalIgnoreCase)
    $map[$dn.ToLower()] = $newer.ToFileTime()
    $compared = New-UserLogonReportRow -User ([PSCustomObject]@{
            SamAccountName     = 'jane'
            DistinguishedName  = $dn
            lastLogonTimestamp = $older.ToFileTime()
            pwdLastSet         = $older.ToFileTime()
            userAccountControl = 65536
        }) -LastLogonByDn $map -Now $now -QueryAllDCs $true -MaxPasswordAge ([timespan]::FromDays(90))
    Assert-Same 'dc logon wins' $newer.ToString('yyyy-MM-dd HH:mm:ss') $compared.LastLogon
    Assert-Same 'dc logon source' 'lastLogon (all domain controllers)' $compared.LogonSource
    Assert-Same 'uac never expires' 'True' $compared.PasswordNeverExpires
    Assert-Same 'never expires is not expired' 'False' $compared.PasswordExpired

    $staleMap = New-Object 'System.Collections.Generic.Dictionary[string,int64]' ([System.StringComparer]::OrdinalIgnoreCase)
    $staleMap[$dn] = $older.ToFileTime()
    $kept = New-UserLogonReportRow -User ([PSCustomObject]@{
            SamAccountName     = 'jane'
            DistinguishedName  = $dn
            lastLogonTimestamp = $newer.ToFileTime()
            pwdLastSet         = $older.ToFileTime()
        }) -LastLogonByDn $staleMap -Now $now -QueryAllDCs $true -MaxPasswordAge ([timespan]::FromDays(30))
    Assert-Same 'replicated logon kept when newer' $newer.ToString('yyyy-MM-dd HH:mm:ss') $kept.LastLogon
    Assert-Same 'estimated expiry' 'True' $kept.PasswordExpired
    Assert-Same 'estimated note' 'Estimated from the default domain password policy' $kept.PasswordStatusNote

    $locked = New-UserLogonReportRow -User ([PSCustomObject]@{
            SamAccountName                        = 'locked'
            DistinguishedName                     = $dn
            'msDS-User-Account-Control-Computed'  = 0x800010
        }) -LastLogonByDn $null -Now $now -QueryAllDCs $false -MaxPasswordAge $null
    Assert-Same 'computed password expired' 'True' $locked.PasswordExpired
    Assert-Same 'computed lockout' 'True' $locked.LockedOut
    Assert-Same 'computed note empty' $null $locked.PasswordStatusNote
    Assert-Same 'never logged on' 'Never' $locked.LastLogon

    $domainPolicy = New-UserLogonReportRow -User ([PSCustomObject]@{
            SamAccountName    = 'policy'
            DistinguishedName = $dn
            pwdLastSet        = $newer.ToFileTime()
        }) -LastLogonByDn $null -Now $now -QueryAllDCs $false -MaxPasswordAge ([timespan]::Zero)
    Assert-Same 'zero max age' 'False' $domainPolicy.PasswordExpired
    Assert-Same 'zero max age note' 'Domain policy does not expire passwords' $domainPolicy.PasswordStatusNote

    $items = @(
        [PSCustomObject]@{ Name = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com'; ObjectClass = 'domainDNS'; Description = ''; CanonicalName = 'contoso.com' }
        [PSCustomObject]@{ Name = 'Staff'; DistinguishedName = 'OU=Staff,DC=contoso,DC=com'; ObjectClass = 'organizationalUnit'; Description = 'People'; CanonicalName = 'contoso.com/Staff' }
        [PSCustomObject]@{ Name = 'Sales, East'; DistinguishedName = 'OU=Sales\, East,OU=Staff,DC=contoso,DC=com'; ObjectClass = 'organizationalUnit'; Description = ''; CanonicalName = 'contoso.com/Staff/Sales, East' }
        [PSCustomObject]@{ Name = 'Users'; DistinguishedName = 'CN=Users,DC=contoso,DC=com'; ObjectClass = 'container'; Description = ''; CanonicalName = 'contoso.com/Users' }
        [PSCustomObject]@{ Name = 'Policies'; DistinguishedName = 'CN=Policies,CN=System,DC=contoso,DC=com'; ObjectClass = 'container'; Description = ''; CanonicalName = 'contoso.com/System/Policies' }
    )
    $roots = @(Build-DirectoryTree -Items $items)
    Assert-Same 'one tree root' '1' $roots.Count
    $rootChildren = @(Sort-DirectoryNodes -Nodes $roots[0].Children)
    Assert-Same 'root child count' '3' $rootChildren.Count
    Assert-Same 'ou sorted before containers' 'Staff' $rootChildren[0].Item.Name
    Assert-Same 'escaped child count' '1' $rootChildren[0].Children.Count
    Assert-Same 'escaped child name' 'Sales, East' $rootChildren[0].Children[0].Item.Name
    $found = Find-TreeNodeByDn -Nodes $roots -DistinguishedName 'ou=staff,dc=contoso,dc=com'
    Assert-Same 'case insensitive find' 'Staff' $(if ($null -eq $found) { $null } else { $found.Item.Name })
    $asList = New-Object System.Collections.Generic.List[object]
    foreach ($item in $items) { [void]$asList.Add($item) }
    $listRoots = @(Build-DirectoryTree -Items $asList)
    Assert-Same 'tree from generic list' '1' $listRoots.Count
    Assert-Same 'single node sort' '1' @(Sort-DirectoryNodes -Nodes @($roots[0])).Count
    Assert-Same 'empty node sort' '0' @(Sort-DirectoryNodes -Nodes @()).Count

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ou-report-{0}' -f [guid]::NewGuid().ToString('N'))
    $csvPath = Join-Path $tempRoot 'report.csv'
    $xlsxPath = Join-Path $tempRoot 'report.xlsx'
    try {
        $final = Export-UserLogonReportFile -Report @($row) -OutputPath $csvPath
        $imported = @(Import-Csv -LiteralPath $final)
        Assert-Same 'csv count' '1' $imported.Count
        Assert-Same 'csv account' 'jsmith' $imported[0].SamAccountName
        Assert-Same 'csv formula guarded' "'=1+1" $imported[0].DisplayName
        Assert-Same 'csv days' '2' $imported[0].DaysSinceLastLogon
        if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
            $excelFallback = Export-UserLogonReportFile -Report @($row) -OutputPath $xlsxPath
            Assert-Same 'xlsx falls back to csv' '.csv' ([System.IO.Path]::GetExtension($excelFallback))
            Assert-Same 'fallback file exists' 'True' ([System.IO.File]::Exists($excelFallback))
        }
    }
    finally {
        if ([System.IO.Directory]::Exists($tempRoot)) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        }
    }

    $mapOfFunctions = Get-ScriptFunctionMap
    Assert-Same 'function map has converter' 'True' $mapOfFunctions.ContainsKey('Convert-FileTimeSafe')
    $sync = New-ReportSync
    $runspace = $null
    $powershell = $null
    try {
        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.Open()
        $powershell = [powershell]::Create()
        $powershell.Runspace = $runspace
        $worker = {
            param($Functions, $Sync)
            Set-StrictMode -Version 2.0
            $ErrorActionPreference = 'Stop'
            try {
                foreach ($key in @($Functions.Keys)) {
                    Set-Item -Path "Function:$key" -Value $Functions[$key]
                }
                $convertedValue = Convert-FileTimeSafe 0
                if ($null -ne $convertedValue) { throw 'expected a null filetime' }
                $Sync.ResultCount = 7
                $Sync.ResultPath = 'ok'
            }
            catch {
                $Sync.ResultPath = $_.Exception.Message
                $Sync.ResultCount = -1
            }
        }
        [void]$powershell.AddScript($worker).AddArgument($mapOfFunctions).AddArgument($sync)
        $handle = $powershell.BeginInvoke()
        [void]$powershell.EndInvoke($handle)
        Assert-Same 'runspace result' 'ok' $sync.ResultPath
        Assert-Same 'runspace count' '7' $sync.ResultCount
        if ($powershell.Streams.Error.Count -gt 0) {
            Assert-Same 'runspace error' '' ([string]$powershell.Streams.Error[0].Exception.Message)
        }
    }
    finally {
        if ($null -ne $powershell) { $powershell.Dispose() }
        if ($null -ne $runspace) { $runspace.Close(); $runspace.Dispose() }
    }

    if ($script:SelfTestFailures -eq 0) {
        Write-Host ("Passed {0} checks." -f $script:SelfTestCount) -ForegroundColor Green
    }
    else {
        Write-Host ("{0} of {1} checks failed." -f $script:SelfTestFailures, $script:SelfTestCount) -ForegroundColor Red
    }
    return $script:SelfTestFailures
}

if ($MyInvocation.InvocationName -eq '.') { return }

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($SelfTest) {
    $failedChecks = Invoke-OUUserLogonReportSelfTest
    if ($failedChecks -gt 0) { exit 1 }
    exit 0
}

try {
    if (-not [string]::IsNullOrWhiteSpace($SearchBase) -and -not $Interactive -and -not $Console) {
        $script:ReportSync = $null
        if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Get-DefaultReportPath }
        $result = Invoke-OUUserLogonExport -SearchBase $SearchBase -OutputPath $OutputPath -SearchScope $SearchScope -QueryAllDCs ([bool]$QueryAllDCs) -Server $Server -OnlyEnabled ([bool]$OnlyEnabled) -ExcludeCritical ([bool]$ExcludeCriticalSystemAccounts) -PassThru:$PassThru
        Write-Host ("Exported {0} account(s) to: {1}" -f $result.Count, $result.Path) -ForegroundColor Green
        if ($PassThru) {
            $reportProperty = $result.PSObject.Properties['Report']
            if ($null -ne $reportProperty) { $reportProperty.Value }
        }
        return
    }

    $useConsole = [bool]$Console
    if (-not $useConsole -and -not (Test-GuiSupported)) {
        Write-Host 'This session cannot open a window (it needs an interactive Windows PowerShell STA host). Starting the console browser.' -ForegroundColor Yellow
        $useConsole = $true
    }
    if ($useConsole) {
        $script:ReportSync = $null
        Start-OUReportConsole -SearchBase $SearchBase -OutputPath $OutputPath -SearchScope $SearchScope -QueryAllDCs ([bool]$QueryAllDCs) -Server $Server -OnlyEnabled ([bool]$OnlyEnabled) -ExcludeCritical ([bool]$ExcludeCriticalSystemAccounts)
        return
    }
    Start-OUReportGui -SearchBase $SearchBase -OutputPath $OutputPath -SearchScope $SearchScope -QueryAllDCs ([bool]$QueryAllDCs) -Server $Server -OnlyEnabled ([bool]$OnlyEnabled) -ExcludeCritical ([bool]$ExcludeCriticalSystemAccounts)
}
catch {
    $message = $_.Exception.Message
    if ([string]::IsNullOrWhiteSpace($message)) { $message = [string]$_ }
    Write-Host $message -ForegroundColor Red
    if ($Host.Name -match 'ISE|Visual Studio Code') { return }
    exit 1
}
</tool_result>

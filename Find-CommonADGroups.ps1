#Requires -Version 5.1
<#
.SYNOPSIS
    Compare Active Directory users from a CSV and write an interactive HTML report.

.DESCRIPTION
    Reads a CSV of user identifiers, resolves each account in Active Directory, and
    reports groups shared by every in-scope user plus groups shared by a minimum
    number of users. It also compares user attributes and organizational units so
    you can see which value, if any, is the same for the whole list. An optional
    second CSV compares groups with a reference list.

    Direct membership includes the primary group. MemberOf does not, and Domain Users
    is usually stored only as the primary group. Use -Recursive to include nested groups.

    The HTML report is self-contained. It can hide disabled accounts, change the
    sharing threshold, and compare the reference list without regenerating the file.

.PARAMETER CsvPath
    CSV of users. Recognized columns: SamAccountName, Username, User, LoginName,
    UserPrincipalName, UPN, Email, and EmployeeID. If none of those exist, the
    first column is used. A file picker opens when this is omitted and a desktop
    session is available.

.PARAMETER UserColumn
    CSV header that identifies each account, such as Email, EmployeeID, or
    SamAccountName. The match is case-insensitive. On a desktop session, when
    this is omitted and the file has more than one column, a prompt lists the
    headers. Use -NoGui together with this parameter to choose a column without
    a prompt.

.PARAMETER GroupCsvPath
    Optional CSV of reference groups. Recognized columns: GroupName, Name, Group,
    SamAccountName, sAMAccountName. Names are matched to group CN and sAMAccountName.

.PARAMETER OutputPath
    HTML report path. A save dialog opens when this is omitted on a desktop session.
    Otherwise the file is written next to the users CSV, or in the current directory
    for -Demo.

.PARAMETER MinimumUserCount
    Initial "at least this many users" threshold in the report. Default 2.
    The report still contains every group, so the threshold can be lowered in the page.

.PARAMETER PromptForGroupCsv
    Always ask for a reference-group CSV when a desktop session is available.

.PARAMETER NoGui
    Do not open file dialogs. Paths must be supplied, or an output path is chosen
    automatically.

.PARAMETER Recursive
    Include nested group membership (LDAP matching rule in chain) in addition to
    the primary group. Distribution groups are included. This is slower.

.PARAMETER ExcludeDisabled
    Open the report with disabled accounts excluded from sharing calculations.
    The page can include them again.

.PARAMETER Server
    Domain controller or domain to query. Recommended when -Credential is used.

.PARAMETER Credential
    Alternate credentials for the Active Directory queries.

.PARAMETER Demo
    Write a sample report from built-in data. Does not contact Active Directory.
    Useful for reviewing the layout and for offline checks.

.EXAMPLE
    .\Find-CommonADGroups.ps1

.EXAMPLE
    .\Find-CommonADGroups.ps1 -CsvPath .\users.csv -GroupCsvPath .\groups.csv -NoGui

.EXAMPLE
    .\Find-CommonADGroups.ps1 -CsvPath .\users.csv -UserColumn Email -NoGui

.EXAMPLE
    .\Find-CommonADGroups.ps1 -CsvPath .\users.csv -MinimumUserCount 3 -Recursive -Server dc01.contoso.com

.EXAMPLE
    .\Find-CommonADGroups.ps1 -Demo -NoGui -OutputPath .\sample-report.html

.NOTES
    Requires the ActiveDirectory module (RSAT) for live queries.
    Compatible with Windows PowerShell 5.1 and PowerShell 7.
    File dialogs need a desktop session. PowerShell 7 dialogs run on an STA thread.
#>
[CmdletBinding()]
param(
    [string]$CsvPath,
    [string]$UserColumn,
    [string]$GroupCsvPath,
    [string]$OutputPath,
    [ValidateRange(1, 9999)]
    [int]$MinimumUserCount = 2,
    [switch]$PromptForGroupCsv,
    [switch]$NoGui,
    [switch]$Recursive,
    [switch]$ExcludeDisabled,
    [string]$Server,
    [pscredential]$Credential,
    [switch]$Demo
)

$toolFileName = if ($PSCommandPath) { [System.IO.Path]::GetFileName($PSCommandPath) } else { 'Find-CommonADGroups.ps1' }

function Write-ToolStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $color = switch ($Level) {
        'OK' { 'Green' }
        'WARN' { 'Yellow' }
        'ERROR' { 'Red' }
        default { 'Cyan' }
    }
    Write-Host ("[{0}][{1}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message) -ForegroundColor $color
}

function ConvertTo-ObjectList {
    param($Value)
    $list = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Value) { return ,$list }
    if ($Value -is [string] -or $Value -is [char]) {
        $text = [string]$Value
        if (-not [string]::IsNullOrWhiteSpace($text)) { [void]$list.Add($text) }
        return ,$list
    }
    foreach ($item in $Value) {
        if ($null -ne $item) { [void]$list.Add($item) }
    }
    return ,$list
}

function ConvertTo-JsonString {
    param([AllowNull()][object]$Text)
    if ($null -eq $Text) { return '""' }
    $value = [string]$Text
    $sb = New-Object System.Text.StringBuilder ($value.Length + 8)
    [void]$sb.Append('"')
    foreach ($ch in $value.ToCharArray()) {
        $code = [int]$ch
        if ($code -eq 8) { [void]$sb.Append('\b') }
        elseif ($code -eq 9) { [void]$sb.Append('\t') }
        elseif ($code -eq 10) { [void]$sb.Append('\n') }
        elseif ($code -eq 12) { [void]$sb.Append('\f') }
        elseif ($code -eq 13) { [void]$sb.Append('\r') }
        elseif ($code -eq 34) { [void]$sb.Append('\"') }
        elseif ($code -eq 92) { [void]$sb.Append('\\') }
        elseif ($code -lt 32 -or $code -eq 0x2028 -or $code -eq 0x2029 -or $ch -eq '<' -or $ch -eq '>' -or $ch -eq '&') {
            [void]$sb.Append('\u')
            [void]$sb.Append($code.ToString('x4'))
        }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function ConvertTo-JsonStringArray {
    param($Items)
    $list = ConvertTo-ObjectList $Items
    if ($list.Count -eq 0) { return '[]' }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($item in $list) { [void]$parts.Add((ConvertTo-JsonString $item)) }
    return '[' + ($parts -join ',') + ']'
}

function ConvertTo-JsonBool {
    param($Value)
    if ($Value -eq $true) { return 'true' }
    if ($Value -eq $false) { return 'false' }
    return 'null'
}

function ConvertTo-LdapFilterLiteral {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int]$ch
        if ($code -eq 0 -or $ch -eq '\' -or $ch -eq '*' -or $ch -eq '(' -or $ch -eq ')' -or $code -gt 127) {
            [void]$sb.Append('\')
            [void]$sb.Append($code.ToString('x2'))
        }
        else { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}

function Get-CnFromDistinguishedName {
    param([AllowNull()][string]$DistinguishedName)
    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return '' }
    if ($DistinguishedName -notmatch '(?i)^CN=') { return $DistinguishedName }
    $rest = $DistinguishedName.Substring(3)
    $sb = New-Object System.Text.StringBuilder
    $escaped = $false
    foreach ($ch in $rest.ToCharArray()) {
        if ($escaped) {
            [void]$sb.Append($ch)
            $escaped = $false
            continue
        }
        if ($ch -eq '\') { $escaped = $true; continue }
        if ($ch -eq ',') { break }
        [void]$sb.Append($ch)
    }
    $name = $sb.ToString()
    if ([string]::IsNullOrWhiteSpace($name)) { return $DistinguishedName }
    return $name
}

function New-GroupMeta {
    param(
        [string]$Name,
        [string]$SamAccountName = '',
        [string]$DistinguishedName,
        [string]$GroupScope = '',
        [string]$GroupCategory = '',
        [string]$Description = ''
    )
    if ([string]::IsNullOrWhiteSpace($SamAccountName)) { $SamAccountName = $Name }
    [pscustomobject]@{
        Name                = $Name
        SamAccountName      = $SamAccountName
        DistinguishedName   = $DistinguishedName
        GroupScope          = $GroupScope
        GroupCategory       = $GroupCategory
        Description         = $Description
    }
}

function New-ReportUser {
    param(
        [string]$SamAccountName,
        [string]$DisplayName = '',
        [string]$Email = '',
        [string]$Department = '',
        [string]$Title = '',
        [object]$Enabled = $true,
        [string]$DistinguishedName = '',
        [string]$UserPrincipalName = '',
        [string]$ManagerDn = '',
        $Attributes,
        $Groups
    )
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = $SamAccountName }
    $bag = @{}
    if ($null -ne $Attributes) {
        foreach ($key in @($Attributes.Keys)) {
            $bag[[string]$key] = $Attributes[$key]
        }
    }
    [pscustomobject]@{
        SamAccountName    = $SamAccountName
        DisplayName       = $DisplayName
        Email             = $Email
        Department        = $Department
        Title             = $Title
        Enabled           = $Enabled
        DistinguishedName = $DistinguishedName
        UserPrincipalName = $UserPrincipalName
        ManagerDn         = $ManagerDn
        Attributes        = $bag
        Groups            = $Groups
    }
}

function Get-UserAttributeDefinitions {
    $defs = New-Object System.Collections.Generic.List[object]
    $add = {
        param($Key, $Label, $Section, $Property, $YesOnly, $OptionalGroup)
        [void]$defs.Add([pscustomobject]@{
            Key           = [string]$Key
            Label         = [string]$Label
            Section       = [string]$Section
            Property      = [string]$Property
            YesOnly       = [bool]$YesOnly
            Derived       = [string]::IsNullOrWhiteSpace([string]$Property)
            Optional      = -not [string]::IsNullOrWhiteSpace([string]$OptionalGroup)
            OptionalGroup = [string]$OptionalGroup
        })
    }
    & $add 'company' 'Company' 'Organization' 'Company' $false ''
    & $add 'department' 'Department' 'Organization' 'Department' $false ''
    & $add 'title' 'Title' 'Organization' 'Title' $false ''
    & $add 'division' 'Division' 'Organization' 'Division' $false ''
    & $add 'organization' 'Organization' 'Organization' 'Organization' $false ''
    & $add 'employeeType' 'Employee type' 'Organization' 'EmployeeType' $false ''
    & $add 'employeeId' 'Employee ID' 'Organization' 'EmployeeID' $false ''
    & $add 'employeeNumber' 'Employee number' 'Organization' 'EmployeeNumber' $false ''
    & $add 'manager' 'Manager' 'Organization' 'Manager' $false ''
    & $add 'description' 'Description' 'Organization' 'Description' $false ''
    & $add 'office' 'Office' 'Location' 'Office' $false ''
    & $add 'city' 'City' 'Location' 'City' $false ''
    & $add 'state' 'State' 'Location' 'State' $false ''
    & $add 'country' 'Country' 'Location' 'Country' $false ''
    & $add 'postalCode' 'Postal code' 'Location' 'PostalCode' $false ''
    & $add 'street' 'Street' 'Location' 'StreetAddress' $false ''
    & $add 'poBox' 'PO box' 'Location' 'POBox' $false ''
    & $add 'officePhone' 'Office phone' 'Contact' 'OfficePhone' $false ''
    & $add 'mobile' 'Mobile' 'Contact' 'MobilePhone' $false ''
    & $add 'homePhone' 'Home phone' 'Contact' 'HomePhone' $false ''
    & $add 'fax' 'Fax' 'Contact' 'Fax' $false ''
    & $add 'scriptPath' 'Logon script' 'Paths' 'ScriptPath' $false ''
    & $add 'profilePath' 'Profile path' 'Paths' 'ProfilePath' $false ''
    & $add 'homeDirectory' 'Home directory' 'Paths' 'HomeDirectory' $false ''
    & $add 'homeDrive' 'Home drive' 'Paths' 'HomeDrive' $false ''
    & $add 'homepage' 'Web page' 'Paths' 'HomePage' $false ''
    & $add 'logonWorkstations' 'Logon workstations' 'Account' 'LogonWorkstations' $false ''
    & $add 'accountExpires' 'Account expiration' 'Account' 'AccountExpirationDate' $false ''
    & $add 'passwordNeverExpires' 'Password never expires' 'Account' 'PasswordNeverExpires' $true ''
    & $add 'smartcardRequired' 'Smart card required' 'Account' 'SmartcardLogonRequired' $true ''
    & $add 'cannotChangePassword' 'Cannot change password' 'Account' 'CannotChangePassword' $true ''
    & $add 'passwordNotRequired' 'Password not required' 'Account' 'PasswordNotRequired' $true ''
    & $add 'ouPath' 'OU path' 'Organizational unit' '' $false ''
    & $add 'ouDn' 'OU distinguished name' 'Organizational unit' '' $false ''
    & $add 'upnSuffix' 'UPN suffix' 'Account' '' $false ''
    & $add 'mailDomain' 'Mail domain' 'Account' '' $false ''
    for ($index = 1; $index -le 15; $index++) {
        & $add ("extensionAttribute{0}" -f $index) ("Extension attribute {0}" -f $index) 'Custom' ("extensionAttribute{0}" -f $index) $false 'exchange'
    }
    for ($index = 1; $index -le 5; $index++) {
        & $add ("cloudExtension{0}" -f $index) ("Cloud extension {0}" -f $index) 'Custom' ("msDS-cloudExtensionAttribute{0}" -f $index) $false 'cloud'
    }
    return ,$defs
}

function Get-AdUserQueryProperties {
    $props = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @('MemberOf', 'DisplayName', 'mail', 'Enabled', 'PrimaryGroupID', 'DistinguishedName', 'SamAccountName', 'UserPrincipalName', 'SID')) {
        if ($seen.ContainsKey($name)) { continue }
        $seen[$name] = $true
        [void]$props.Add($name)
    }
    foreach ($def in (Get-UserAttributeDefinitions)) {
        if ($def.Derived -or $def.Optional) { continue }
        $name = [string]$def.Property
        if ([string]::IsNullOrWhiteSpace($name) -or $seen.ContainsKey($name)) { continue }
        $seen[$name] = $true
        [void]$props.Add($name)
    }
    return ,$props
}

function Get-OptionalPropertyNames {
    param([Parameter(Mandatory = $true)][string]$GroupName)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($def in (Get-UserAttributeDefinitions)) {
        if ($def.Optional -and $def.OptionalGroup -eq $GroupName -and -not [string]::IsNullOrWhiteSpace([string]$def.Property)) {
            [void]$names.Add([string]$def.Property)
        }
    }
    return ,$names
}

function ConvertTo-AttributeText {
    param($Value, [bool]$YesOnly = $false)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) {
        if ($Value) { return 'Yes' }
        if ($YesOnly) { return '' }
        return 'No'
    }
    if ($Value -is [datetime]) {
        $when = [datetime]$Value
        if ($when.Year -le 1601 -or $when.Year -ge 9999) { return '' }
        return $when.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    $parts = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in (ConvertTo-ObjectList $Value)) {
        $text = ''
        if ($item -is [bool] -or $item -is [datetime]) {
            $text = ConvertTo-AttributeText -Value $item -YesOnly:$YesOnly
        }
        else { $text = ([string]$item).Trim() }
        if ([string]::IsNullOrWhiteSpace($text) -or $seen.ContainsKey($text)) { continue }
        $seen[$text] = $true
        [void]$parts.Add($text)
    }
    if ($parts.Count -eq 0) { return '' }
    $sorted = $parts.ToArray()
    [Array]::Sort($sorted, [System.StringComparer]::OrdinalIgnoreCase)
    return ($sorted -join '; ')
}

function Split-DistinguishedName {
    param([AllowNull()][string]$DistinguishedName)
    $parts = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return ,$parts }
    $current = New-Object System.Text.StringBuilder
    $escaped = $false
    foreach ($ch in $DistinguishedName.ToCharArray()) {
        if ($escaped) {
            [void]$current.Append($ch)
            $escaped = $false
            continue
        }
        if ($ch -eq '\') { $escaped = $true; continue }
        if ($ch -eq ',') {
            $text = $current.ToString().Trim()
            if (-not [string]::IsNullOrWhiteSpace($text)) { [void]$parts.Add($text) }
            [void]$current.Clear()
            continue
        }
        [void]$current.Append($ch)
    }
    if ($escaped) { [void]$current.Append('\') }
    $tail = $current.ToString().Trim()
    if (-not [string]::IsNullOrWhiteSpace($tail)) { [void]$parts.Add($tail) }
    return ,$parts
}

function Get-ParentDistinguishedName {
    param([AllowNull()][string]$DistinguishedName)
    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return '' }
    $escaped = $false
    $chars = $DistinguishedName.ToCharArray()
    for ($index = 0; $index -lt $chars.Length; $index++) {
        $ch = $chars[$index]
        if ($escaped) { $escaped = $false; continue }
        if ($ch -eq '\') { $escaped = $true; continue }
        if ($ch -eq ',') { return $DistinguishedName.Substring($index + 1).Trim() }
    }
    return ''
}

function ConvertTo-DirectoryPath {
    param([AllowNull()][string]$DistinguishedName)
    $ous = New-Object System.Collections.Generic.List[string]
    $dcs = New-Object System.Collections.Generic.List[string]
    foreach ($part in (Split-DistinguishedName $DistinguishedName)) {
        if ($part -match '(?i)^OU=(.*)$') { [void]$ous.Add($Matches[1]) }
        elseif ($part -match '(?i)^DC=(.*)$') { [void]$dcs.Add($Matches[1]) }
    }
    $ouNames = $ous.ToArray()
    $dcNames = $dcs.ToArray()
    [Array]::Reverse($ouNames)
    $domain = ($dcNames -join '.')
    if ($ouNames.Count -eq 0) { return $domain }
    if ([string]::IsNullOrWhiteSpace($domain)) { return ($ouNames -join '/') }
    return ($domain + '/' + ($ouNames -join '/'))
}

function Get-CommonDirectoryPath {
    param($Paths)
    $lists = New-Object System.Collections.Generic.List[object]
    foreach ($path in (ConvertTo-ObjectList $Paths)) {
        $text = ([string]$path).Trim().Trim('/')
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $segments = New-Object System.Collections.Generic.List[string]
        foreach ($piece in $text.Split('/')) {
            $piece = $piece.Trim()
            if (-not [string]::IsNullOrWhiteSpace($piece)) { [void]$segments.Add($piece) }
        }
        if ($segments.Count -gt 0) { [void]$lists.Add($segments) }
    }
    if ($lists.Count -eq 0) { return '' }
    $first = $lists[0]
    $count = $first.Count
    foreach ($segments in $lists) {
        $limit = [Math]::Min($count, $segments.Count)
        $index = 0
        while ($index -lt $limit -and [string]::Compare([string]$first[$index], [string]$segments[$index], [System.StringComparison]::OrdinalIgnoreCase) -eq 0) {
            $index++
        }
        $count = $index
        if ($count -eq 0) { break }
    }
    if ($count -le 0) { return '' }
    $slice = New-Object System.Collections.Generic.List[string]
    for ($index = 0; $index -lt $count; $index++) { [void]$slice.Add([string]$first[$index]) }
    return ($slice.ToArray() -join '/')
}

function Get-MapValue {
    param($Map, [string]$Key)
    if ($null -eq $Map -or [string]::IsNullOrWhiteSpace($Key)) { return $null }
    if ($Map -is [System.Collections.IDictionary]) {
        foreach ($candidate in @($Map.Keys)) {
            if ([string]::Compare([string]$candidate, $Key, [System.StringComparison]::OrdinalIgnoreCase) -eq 0) {
                return $Map[$candidate]
            }
        }
        return $null
    }
    $prop = $Map.PSObject.Properties[$Key]
    if ($null -ne $prop) { return $prop.Value }
    return $null
}

function Test-MapHasKey {
    param($Map, [string]$Key)
    if ($null -eq $Map -or [string]::IsNullOrWhiteSpace($Key)) { return $false }
    if ($Map -is [System.Collections.IDictionary]) {
        foreach ($candidate in @($Map.Keys)) {
            if ([string]::Compare([string]$candidate, $Key, [System.StringComparison]::OrdinalIgnoreCase) -eq 0) { return $true }
        }
        return $false
    }
    return ($null -ne $Map.PSObject.Properties[$Key])
}

function New-UserAttributeDictionary {
    param($Source, [string]$DistinguishedName, [string]$UserPrincipalName, [string]$Email)
    $map = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($def in (Get-UserAttributeDefinitions)) {
        if ($def.Derived) { continue }
        $raw = $null
        $propertyName = [string]$def.Property
        if (Test-MapHasKey -Map $Source -Key $propertyName) { $raw = Get-MapValue -Map $Source -Key $propertyName }
        elseif (Test-MapHasKey -Map $Source -Key ([string]$def.Key)) { $raw = Get-MapValue -Map $Source -Key ([string]$def.Key) }
        else { continue }
        $text = ConvertTo-AttributeText -Value $raw -YesOnly:([bool]$def.YesOnly)
        if ($def.Key -eq 'manager' -and $text -match '(?i)^(CN|OU|DC)=') {
            $text = Get-CnFromDistinguishedName $text
        }
        if (-not [string]::IsNullOrWhiteSpace($text)) { $map[[string]$def.Key] = $text }
    }
    $ouDn = Get-ParentDistinguishedName -DistinguishedName $DistinguishedName
    $ouPath = ConvertTo-DirectoryPath -DistinguishedName $DistinguishedName
    if (-not [string]::IsNullOrWhiteSpace($ouDn)) { $map['ouDn'] = $ouDn }
    if (-not [string]::IsNullOrWhiteSpace($ouPath)) { $map['ouPath'] = $ouPath }
    if ($UserPrincipalName -match '@([^@\s]+)$') { $map['upnSuffix'] = $Matches[1].ToLowerInvariant() }
    if ($Email -match '@([^@\s]+)$') { $map['mailDomain'] = $Matches[1].ToLowerInvariant() }
    return ,$map
}

function Get-UserAttributeValue {
    param($User, [string]$Key)
    if ($null -eq $User) { return '' }
    $attrs = $User.Attrs
    if ($null -eq $attrs) { return '' }
    if ($attrs -is [System.Collections.Generic.Dictionary[string,string]]) {
        if ($attrs.ContainsKey($Key)) { return [string]$attrs[$Key] }
        return ''
    }
    $raw = Get-MapValue -Map $attrs -Key $Key
    if ($null -eq $raw) { return '' }
    return [string]$raw
}

function Get-AttributeTieSummary {
    param($Model)
    $includeDisabled = -not [bool]$Model.ExcludeDisabled
    $users = New-Object System.Collections.Generic.List[object]
    foreach ($user in (ConvertTo-ObjectList $Model.Users)) {
        if ($includeDisabled -or ($user.Enabled -eq $true)) { [void]$users.Add($user) }
    }
    $shared = New-Object System.Collections.Generic.List[object]
    foreach ($def in (ConvertTo-ObjectList $Model.AttributeCatalog)) {
        $counts = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($user in $users) {
            $value = (Get-UserAttributeValue -User $user -Key ([string]$def.Key)).Trim()
            if ([string]::IsNullOrWhiteSpace($value)) { continue }
            if (-not $counts.ContainsKey($value)) {
                $counts[$value] = [pscustomobject]@{ Value = $value; Count = 0 }
            }
            $counts[$value].Count++
        }
        $best = $null
        foreach ($entry in $counts.Values) {
            if ($null -eq $best -or $entry.Count -gt $best.Count) { $best = $entry }
            elseif ($entry.Count -eq $best.Count -and [string]::Compare([string]$entry.Value, [string]$best.Value, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
                $best = $entry
            }
        }
        if ($null -eq $best -or $users.Count -eq 0 -or $best.Count -ne $users.Count) { continue }
        [void]$shared.Add([pscustomobject]@{
            Key   = [string]$def.Key
            Label = [string]$def.Label
            Value = [string]$best.Value
            Count = [int]$best.Count
        })
    }
    $paths = New-Object System.Collections.Generic.List[string]
    $missingOu = $false
    foreach ($user in $users) {
        $path = (Get-UserAttributeValue -User $user -Key 'ouPath').Trim()
        if ([string]::IsNullOrWhiteSpace($path)) { $missingOu = $true }
        else { [void]$paths.Add($path) }
    }
    $commonOu = ''
    if (-not $missingOu) { $commonOu = Get-CommonDirectoryPath -Paths $paths }
    [pscustomobject]@{
        SharedCount = $shared.Count
        Shared      = $shared
        CommonOu    = $commonOu
        InScope     = $users.Count
    }
}

function New-AdCommonParameter {
    param([string]$ServerName, $AdCredential)
    $params = @{}
    if (-not [string]::IsNullOrWhiteSpace($ServerName)) { $params['Server'] = $ServerName }
    if ($null -ne $AdCredential) { $params['Credential'] = $AdCredential }
    return ,$params
}

function Add-DictionaryParameter {
    param($Target, $Source)
    if ($null -eq $Source) { return }
    foreach ($key in @($Source.Keys)) {
        $Target[$key] = $Source[$key]
    }
}

function Read-TextAutoEncoding {
    param([Parameter(Mandatory = $true)][string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    $strict = New-Object System.Text.UTF8Encoding $false, $true
    try { return $strict.GetString($bytes) }
    catch { return [System.Text.Encoding]::Default.GetString($bytes) }
}

function Get-CsvDelimiter {
    param([AllowNull()][string]$HeaderLine)
    if ([string]::IsNullOrEmpty($HeaderLine)) { return ',' }
    $comma = ([regex]::Matches($HeaderLine, ',')).Count
    $semi = ([regex]::Matches($HeaderLine, ';')).Count
    $tab = ([regex]::Matches($HeaderLine, "`t")).Count
    if ($semi -gt $comma -and $semi -ge $tab) { return ';' }
    if ($tab -gt $comma -and $tab -gt $semi) { return "`t" }
    return ','
}

function Get-CleanCsvHeader {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    return ([string]$Name).Trim().TrimStart([char]0xFEFF)
}

function Read-CsvTable {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Label = 'CSV'
    )
    $headers = New-Object System.Collections.Generic.List[string]
    $rows = @()
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label file was not found: $Path"
    }
    $text = Read-TextAutoEncoding -Path $Path
    if ($text.Length -gt 0 -and [int][char]$text[0] -eq 0xFEFF) { $text = $text.Substring(1) }
    $lines = @([regex]::Split($text, '\r\n|\n|\r') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) {
        return [pscustomobject]@{ Rows = $rows; Headers = $headers; HasLines = $false }
    }
    $delimiter = Get-CsvDelimiter -HeaderLine $lines[0]
    $temp = [System.IO.Path]::GetTempFileName()
    try {
        $utf8Bom = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($temp, $text, $utf8Bom)
        $rows = @(Import-Csv -LiteralPath $temp -Delimiter $delimiter)
    }
    finally {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    }
    if ($rows.Count -gt 0) {
        foreach ($prop in @($rows[0].PSObject.Properties)) { [void]$headers.Add([string]$prop.Name) }
    }
    return [pscustomobject]@{ Rows = $rows; Headers = $headers; HasLines = $true }
}

function Get-CsvColumnNames {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Label = 'CSV'
    )
    $table = Read-CsvTable -Path $Path -Label $Label
    if (-not $table.HasLines) { throw "The $Label file is empty." }
    if ($table.Headers.Count -eq 0) { throw "The $Label file has a header but no data rows." }
    return ,$table.Headers
}

function Select-CsvColumn {
    param(
        $Headers,
        [string]$Column = '',
        [string[]]$Aliases = @(),
        [string]$Label = 'CSV',
        [switch]$Quiet
    )
    $headerList = New-Object System.Collections.Generic.List[string]
    foreach ($header in (ConvertTo-ObjectList $Headers)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$header)) { [void]$headerList.Add([string]$header) }
    }
    if ($headerList.Count -eq 0) { throw "The $Label file has a header but no data rows." }
    if (-not [string]::IsNullOrWhiteSpace($Column)) {
        $wanted = Get-CleanCsvHeader $Column
        foreach ($header in $headerList) {
            if ([string]::Equals((Get-CleanCsvHeader $header), $wanted, [System.StringComparison]::OrdinalIgnoreCase)) {
                return [string]$header
            }
        }
        $shown = New-Object System.Collections.Generic.List[string]
        foreach ($header in $headerList) { [void]$shown.Add((Get-CleanCsvHeader $header)) }
        throw "Column '$wanted' was not found in the $Label CSV. Headers: $($shown -join ', ')"
    }
    foreach ($header in $headerList) {
        $clean = Get-CleanCsvHeader $header
        foreach ($alias in $Aliases) {
            if ($clean -eq $alias) { return [string]$header }
        }
    }
    $fallback = [string]$headerList[0]
    if (-not $Quiet) {
        Write-ToolStatus "$Label CSV has no recognized column. Using '$(Get-CleanCsvHeader $fallback)'. Add a header such as $($Aliases -join ', ') so the first row is not treated as a header." 'WARN'
    }
    return $fallback
}

function Get-UserLookupAttribute {
    param([Parameter(Mandatory = $true)][string]$ColumnName)
    $key = ((Get-CleanCsvHeader $ColumnName) -replace '[\s_-]', '').ToLowerInvariant()
    switch ($key) {
        { $_ -in @('samaccountname', 'username', 'user', 'loginname', 'login', 'account') } { return 'sAMAccountName' }
        { $_ -in @('userprincipalname', 'upn') } { return 'userPrincipalName' }
        { $_ -in @('email', 'emailaddress', 'mail') } { return 'mail' }
        'employeeid' { return 'employeeID' }
        'employeenumber' { return 'employeeNumber' }
        { $_ -in @('distinguishedname', 'dn') } { return 'distinguishedName' }
        { $_ -in @('objectguid', 'guid') } { return 'objectGUID' }
        { $_ -in @('objectsid', 'sid') } { return 'objectSid' }
        'displayname' { return 'displayName' }
        { $_ -in @('name', 'cn') } { return 'name' }
        default {
            $raw = Get-CleanCsvHeader $ColumnName
            if ($raw -match '^[A-Za-z][A-Za-z0-9-]*$') { return $raw }
            throw "Column '$raw' is not a recognized account field and cannot be used as an Active Directory attribute. Choose a column such as SamAccountName, Email, EmployeeID, or extensionAttribute1."
        }
    }
}

function Import-NameCsv {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Aliases,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$Column = '',
        [switch]$AllowEmpty
    )
    $table = Read-CsvTable -Path $Path -Label $Label
    if (-not $table.HasLines) {
        if ($AllowEmpty) { return ,(New-Object System.Collections.Generic.List[string]) }
        throw "The $Label file is empty."
    }
    if ($table.Rows.Count -eq 0) {
        if ($AllowEmpty) { return ,(New-Object System.Collections.Generic.List[string]) }
        throw "The $Label file has a header but no data rows."
    }
    $chosen = Select-CsvColumn -Headers $table.Headers -Column $Column -Aliases $Aliases -Label $Label
    $rows = @($table.Rows)
    $names = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $duplicates = 0
    foreach ($row in $rows) {
        $raw = [string]$row.$chosen
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $name = $raw.Trim()
        if ($seen.ContainsKey($name)) { $duplicates++; continue }
        $seen[$name] = $true
        [void]$names.Add($name)
    }
    if ($duplicates -gt 0) {
        Write-ToolStatus "$Label CSV contained $duplicates duplicate name(s); kept the first of each." 'WARN'
    }
    if ($names.Count -eq 0 -and -not $AllowEmpty) { throw "The $Label file did not contain any names." }
    return ,$names
}

function Add-GroupAlias {
    param($AliasIndex, $MetaMap, [string]$Alias, $Meta)
    if ([string]::IsNullOrWhiteSpace($Alias) -or $null -eq $Meta) { return }
    $dn = [string]$Meta.DistinguishedName
    if ([string]::IsNullOrWhiteSpace($dn)) { return }
    if (-not $MetaMap.ContainsKey($dn)) { $MetaMap[$dn] = $Meta }
    if (-not $AliasIndex.ContainsKey($Alias)) {
        $AliasIndex[$Alias] = New-Object System.Collections.Generic.List[string]
    }
    $list = $AliasIndex[$Alias]
    foreach ($existing in $list) {
        if ([string]::Equals([string]$existing, $dn, [System.StringComparison]::OrdinalIgnoreCase)) { return }
    }
    [void]$list.Add($dn)
}

function New-CommonGroupReportModel {
    param(
        $Users,
        $NotFound,
        $CompareNames,
        $ExtraGroups,
        [int]$MinimumUserCount = 2,
        [bool]$ExcludeDisabled = $false,
        [bool]$Recursive = $false,
        [string]$UsersCsv = '',
        [string]$UserColumn = '',
        [string]$GroupsCsv = '',
        [string]$ServerName = '',
        [string]$Domain = '',
        [string]$Generated = '',
        [string]$ScriptName = ''
    )
    if ([string]::IsNullOrWhiteSpace($Generated)) {
        $Generated = Get-Date -Format 'dddd d MMMM yyyy, HH:mm:ss'
    }
    if ([string]::IsNullOrWhiteSpace($ScriptName)) { $ScriptName = $toolFileName }
    if ($MinimumUserCount -lt 1) { $MinimumUserCount = 1 }

    $metaMap = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $aliasIndex = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $modelUsers = New-Object System.Collections.Generic.List[object]

    # Assign the list first. Piping the function result would treat the whole list
    # as one object because it is returned as a single value on purpose.
    $inputUsers = @((ConvertTo-ObjectList $Users).ToArray() | Sort-Object { [string]$_.SamAccountName })
    foreach ($user in $inputUsers) {
        $dns = New-Object System.Collections.Generic.List[string]
        $seenDn = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($group in (ConvertTo-ObjectList $user.Groups)) {
            $meta = $null
            if ($group -is [string]) {
                $meta = New-GroupMeta -Name (Get-CnFromDistinguishedName $group) -DistinguishedName $group -GroupScope 'Unknown' -GroupCategory 'Unknown'
            }
            else { $meta = $group }
            $dn = [string]$meta.DistinguishedName
            if ([string]::IsNullOrWhiteSpace($dn) -or $seenDn.ContainsKey($dn)) { continue }
            $seenDn[$dn] = $true
            [void]$dns.Add($dn)
            Add-GroupAlias -AliasIndex $aliasIndex -MetaMap $metaMap -Alias $meta.Name -Meta $meta
            Add-GroupAlias -AliasIndex $aliasIndex -MetaMap $metaMap -Alias $meta.SamAccountName -Meta $meta
        }
        $enabledValue = $null
        if ($user.Enabled -eq $true) { $enabledValue = $true }
        elseif ($user.Enabled -eq $false) { $enabledValue = $false }
        $attrs = New-UserAttributeDictionary -Source $user.Attributes -DistinguishedName ([string]$user.DistinguishedName) -UserPrincipalName ([string]$user.UserPrincipalName) -Email ([string]$user.Email)
        [void]$modelUsers.Add([pscustomobject]@{
            Sam       = [string]$user.SamAccountName
            Display   = [string]$(if ($user.DisplayName) { $user.DisplayName } else { $user.SamAccountName })
            Email     = [string]$user.Email
            Dept      = [string]$user.Department
            Title     = [string]$user.Title
            Enabled   = $enabledValue
            GroupDns  = $dns
            Attrs     = $attrs
        })
    }

    $usedKeys = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($modelUser in $modelUsers) {
        if ($null -eq $modelUser.Attrs) { continue }
        foreach ($attrKey in @($modelUser.Attrs.Keys)) { $usedKeys[[string]$attrKey] = $true }
    }
    $attributeCatalog = New-Object System.Collections.Generic.List[object]
    foreach ($def in (Get-UserAttributeDefinitions)) {
        if (-not $usedKeys.ContainsKey([string]$def.Key)) { continue }
        [void]$attributeCatalog.Add([pscustomobject]@{
            Key     = [string]$def.Key
            Label   = [string]$def.Label
            Section = [string]$def.Section
        })
    }

    foreach ($extra in (ConvertTo-ObjectList $ExtraGroups)) {
        Add-GroupAlias -AliasIndex $aliasIndex -MetaMap $metaMap -Alias $extra.Name -Meta $extra
        Add-GroupAlias -AliasIndex $aliasIndex -MetaMap $metaMap -Alias $extra.SamAccountName -Meta $extra
    }

    $notFoundList = New-Object System.Collections.Generic.List[string]
    $seenMissing = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in (ConvertTo-ObjectList $NotFound)) {
        $text = ([string]$name).Trim()
        if ([string]::IsNullOrWhiteSpace($text) -or $seenMissing.ContainsKey($text)) { continue }
        $seenMissing[$text] = $true
        [void]$notFoundList.Add($text)
    }
    $notFoundList.Sort([System.StringComparer]::OrdinalIgnoreCase)

    $compareEntries = New-Object System.Collections.Generic.List[object]
    $seenCompare = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rawName in (ConvertTo-ObjectList $CompareNames)) {
        $name = ([string]$rawName).Trim()
        if ([string]::IsNullOrWhiteSpace($name) -or $seenCompare.ContainsKey($name)) { continue }
        $seenCompare[$name] = $true
        $dns = New-Object System.Collections.Generic.List[string]
        if ($aliasIndex.ContainsKey($name)) {
            foreach ($dn in $aliasIndex[$name]) { [void]$dns.Add([string]$dn) }
        }
        [void]$compareEntries.Add([pscustomobject]@{
            Name   = $name
            Exists = ($dns.Count -gt 0)
            Dns    = $dns
        })
    }

    [pscustomobject]@{
        Generated          = $Generated
        ScriptName         = $ScriptName
        UsersCsv           = $UsersCsv
        UserColumn         = $UserColumn
        GroupsCsv          = $GroupsCsv
        Server             = $ServerName
        Domain             = $Domain
        Recursive          = [bool]$Recursive
        ExcludeDisabled    = [bool]$ExcludeDisabled
        MinimumUserCount   = $MinimumUserCount
        InputCount         = ($modelUsers.Count + $notFoundList.Count)
        Users              = $modelUsers
        AttributeCatalog   = $attributeCatalog
        NotFound           = $notFoundList
        GroupMeta          = $metaMap
        CompareEnabled     = ($compareEntries.Count -gt 0)
        CompareEntries     = $compareEntries
    }
}

function Get-MembershipStats {
    param($Model)
    $includeDisabled = -not [bool]$Model.ExcludeDisabled
    $users = New-Object System.Collections.Generic.List[object]
    foreach ($user in (ConvertTo-ObjectList $Model.Users)) {
        if ($includeDisabled -or ($user.Enabled -eq $true)) { [void]$users.Add($user) }
    }
    $memberMap = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($user in $users) {
        $seen = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($dnRaw in (ConvertTo-ObjectList $user.GroupDns)) {
            $dn = [string]$dnRaw
            if ([string]::IsNullOrWhiteSpace($dn) -or $seen.ContainsKey($dn)) { continue }
            $seen[$dn] = $true
            if (-not $memberMap.ContainsKey($dn)) {
                $memberMap[$dn] = New-Object System.Collections.Generic.List[string]
            }
            [void]$memberMap[$dn].Add([string]$user.Sam)
        }
    }
    $inScope = $users.Count
    $min = [int]$Model.MinimumUserCount
    if ($min -lt 1) { $min = 1 }
    $groupCount = 0
    $shared = 0
    $threshold = 0
    $memberDns = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($dnRaw in @($Model.GroupMeta.Keys)) {
        $dn = [string]$dnRaw
        $count = 0
        if ($memberMap.ContainsKey($dn)) { $count = $memberMap[$dn].Count }
        if ($count -le 0) { continue }
        $memberDns[$dn] = $count
        $groupCount++
        if ($inScope -gt 0 -and $count -eq $inScope) { $shared++ }
        if ($count -ge $min) { $threshold++ }
    }
    $matched = 0
    $noMembers = 0
    $missing = 0
    $claimed = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ($Model.CompareEnabled) {
        foreach ($entry in (ConvertTo-ObjectList $Model.CompareEntries)) {
            $dns = ConvertTo-ObjectList $entry.Dns
            if ((-not $entry.Exists) -or $dns.Count -eq 0) { $missing++; continue }
            foreach ($dnRaw in $dns) {
                $dn = [string]$dnRaw
                $claimed[$dn] = $true
                $count = 0
                if ($memberMap.ContainsKey($dn)) { $count = $memberMap[$dn].Count }
                if ($count -gt 0) { $matched++ } else { $noMembers++ }
            }
        }
    }
    $adOnly = 0
    foreach ($dn in @($memberDns.Keys)) {
        if (-not $claimed.ContainsKey([string]$dn)) { $adOnly++ }
    }
    [pscustomobject]@{
        Input       = [int]$Model.InputCount
        Resolved    = (ConvertTo-ObjectList $Model.Users).Count
        NotFound    = (ConvertTo-ObjectList $Model.NotFound).Count
        InScope     = $inScope
        Groups      = $groupCount
        SharedByAll = $shared
        Threshold   = $threshold
        Matched     = $matched
        NoMembers   = $noMembers
        Missing     = $missing
        AdOnly      = $adOnly
    }
}

function ConvertTo-ReportJson {
    param($Model)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{')
    [void]$sb.Append('"generated":').Append((ConvertTo-JsonString $Model.Generated))
    [void]$sb.Append(',"scriptName":').Append((ConvertTo-JsonString $Model.ScriptName))
    [void]$sb.Append(',"usersCsv":').Append((ConvertTo-JsonString $Model.UsersCsv))
    [void]$sb.Append(',"userColumn":').Append((ConvertTo-JsonString $Model.UserColumn))
    [void]$sb.Append(',"groupsCsv":').Append((ConvertTo-JsonString $Model.GroupsCsv))
    [void]$sb.Append(',"server":').Append((ConvertTo-JsonString $Model.Server))
    [void]$sb.Append(',"domain":').Append((ConvertTo-JsonString $Model.Domain))
    [void]$sb.Append(',"recursive":').Append((ConvertTo-JsonBool $Model.Recursive))
    [void]$sb.Append(',"excludeDisabled":').Append((ConvertTo-JsonBool $Model.ExcludeDisabled))
    [void]$sb.Append(',"minimumUserCount":').Append(([int]$Model.MinimumUserCount).ToString([Globalization.CultureInfo]::InvariantCulture))
    [void]$sb.Append(',"inputCount":').Append(([int]$Model.InputCount).ToString([Globalization.CultureInfo]::InvariantCulture))
    [void]$sb.Append(',"attributeCatalog":[')
    $firstCatalog = $true
    foreach ($def in (ConvertTo-ObjectList $Model.AttributeCatalog)) {
        if (-not $firstCatalog) { [void]$sb.Append(',') }
        $firstCatalog = $false
        [void]$sb.Append('{"key":').Append((ConvertTo-JsonString $def.Key))
        [void]$sb.Append(',"label":').Append((ConvertTo-JsonString $def.Label))
        [void]$sb.Append(',"section":').Append((ConvertTo-JsonString $def.Section))
        [void]$sb.Append('}')
    }
    [void]$sb.Append('],"users":[')
    $firstUser = $true
    foreach ($user in (ConvertTo-ObjectList $Model.Users)) {
        if (-not $firstUser) { [void]$sb.Append(',') }
        $firstUser = $false
        [void]$sb.Append('{')
        [void]$sb.Append('"sam":').Append((ConvertTo-JsonString $user.Sam))
        [void]$sb.Append(',"display":').Append((ConvertTo-JsonString $user.Display))
        [void]$sb.Append(',"email":').Append((ConvertTo-JsonString $user.Email))
        [void]$sb.Append(',"dept":').Append((ConvertTo-JsonString $user.Dept))
        [void]$sb.Append(',"title":').Append((ConvertTo-JsonString $user.Title))
        [void]$sb.Append(',"enabled":').Append((ConvertTo-JsonBool $user.Enabled))
        [void]$sb.Append(',"groups":').Append((ConvertTo-JsonStringArray $user.GroupDns))
        [void]$sb.Append(',"attrs":{')
        $attrKeys = New-Object System.Collections.Generic.List[string]
        if ($null -ne $user.Attrs) {
            foreach ($attrKey in @($user.Attrs.Keys)) { [void]$attrKeys.Add([string]$attrKey) }
        }
        $attrKeys.Sort([System.StringComparer]::OrdinalIgnoreCase)
        $firstAttr = $true
        foreach ($attrKey in $attrKeys) {
            $attrValue = Get-UserAttributeValue -User $user -Key $attrKey
            if ([string]::IsNullOrWhiteSpace($attrValue)) { continue }
            if (-not $firstAttr) { [void]$sb.Append(',') }
            $firstAttr = $false
            [void]$sb.Append((ConvertTo-JsonString $attrKey)).Append(':').Append((ConvertTo-JsonString $attrValue))
        }
        [void]$sb.Append('}}')
    }
    [void]$sb.Append('],"notFound":').Append((ConvertTo-JsonStringArray $Model.NotFound))
    [void]$sb.Append(',"groupMeta":{')
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($key in @($Model.GroupMeta.Keys)) { [void]$keys.Add([string]$key) }
    $keys.Sort([System.StringComparer]::OrdinalIgnoreCase)
    $firstGroup = $true
    foreach ($dn in $keys) {
        $meta = $Model.GroupMeta[$dn]
        if (-not $firstGroup) { [void]$sb.Append(',') }
        $firstGroup = $false
        [void]$sb.Append((ConvertTo-JsonString $dn)).Append(':{')
        [void]$sb.Append('"name":').Append((ConvertTo-JsonString $meta.Name))
        [void]$sb.Append(',"sam":').Append((ConvertTo-JsonString $meta.SamAccountName))
        [void]$sb.Append(',"dn":').Append((ConvertTo-JsonString $meta.DistinguishedName))
        [void]$sb.Append(',"scope":').Append((ConvertTo-JsonString $meta.GroupScope))
        [void]$sb.Append(',"category":').Append((ConvertTo-JsonString $meta.GroupCategory))
        [void]$sb.Append(',"description":').Append((ConvertTo-JsonString $meta.Description))
        [void]$sb.Append('}')
    }
    [void]$sb.Append('},"compare":{')
    [void]$sb.Append('"enabled":').Append((ConvertTo-JsonBool $Model.CompareEnabled))
    [void]$sb.Append(',"entries":[')
    $firstEntry = $true
    foreach ($entry in (ConvertTo-ObjectList $Model.CompareEntries)) {
        if (-not $firstEntry) { [void]$sb.Append(',') }
        $firstEntry = $false
        [void]$sb.Append('{')
        [void]$sb.Append('"name":').Append((ConvertTo-JsonString $entry.Name))
        [void]$sb.Append(',"exists":').Append((ConvertTo-JsonBool $entry.Exists))
        [void]$sb.Append(',"dns":').Append((ConvertTo-JsonStringArray $entry.Dns))
        [void]$sb.Append('}')
    }
    [void]$sb.Append(']}}')
    return $sb.ToString()
}

function Write-Utf8NoBomFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content)
    $directory = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $Content, $utf8)
}

function New-CommonAdGroupsHtml {
    param($Model)
    $json = ConvertTo-ReportJson $Model
    $template = Get-ReportTemplate
    $token = '__REPORT_JSON__'
    if ($template.IndexOf($token) -lt 0) { throw 'Report template is missing the data placeholder.' }
    return $template.Replace($token, $json)
}

function New-DemoReportModel {
    param([bool]$ExcludeDisabled = $false)
    $domainUsers = New-GroupMeta -Name 'Domain Users' -DistinguishedName 'CN=Domain Users,CN=Users,DC=contoso,DC=com' -GroupScope 'Global' -GroupCategory 'Security' -Description 'Primary group for every domain account'
    $allStaff = New-GroupMeta -Name 'All Staff' -SamAccountName 'AllStaff' -DistinguishedName 'CN=All Staff,OU=Groups,DC=contoso,DC=com' -GroupScope 'Global' -GroupCategory 'Security' -Description 'All employees'
    $finance = New-GroupMeta -Name 'Finance' -DistinguishedName 'CN=Finance,OU=Groups,DC=contoso,DC=com' -GroupScope 'Global' -GroupCategory 'Security' -Description "Finance share access`nIncludes budget folders"
    $vpn = New-GroupMeta -Name 'VPN Users' -SamAccountName 'VPNUsers' -DistinguishedName 'CN=VPN Users,OU=Groups,DC=contoso,DC=com' -GroupScope 'Universal' -GroupCategory 'Security' -Description 'Remote access'
    $adminsFinance = New-GroupMeta -Name 'Admins' -SamAccountName 'Admins-FIN' -DistinguishedName 'CN=Admins,OU=Finance,DC=contoso,DC=com' -GroupScope 'DomainLocal' -GroupCategory 'Security' -Description 'Finance administrators'
    $adminsHr = New-GroupMeta -Name 'Admins' -SamAccountName 'Admins-HR' -DistinguishedName 'CN=Admins,OU=HR,DC=contoso,DC=com' -GroupScope 'DomainLocal' -GroupCategory 'Security' -Description 'HR administrators'
    $contractors = New-GroupMeta -Name 'Contractors' -DistinguishedName 'CN=Contractors,OU=Groups,DC=contoso,DC=com' -GroupScope 'Global' -GroupCategory 'Distribution' -Description 'External contractors'
    $legacy = New-GroupMeta -Name 'Legacy App' -SamAccountName 'LegacyApp' -DistinguishedName 'CN=Legacy App,OU=Groups,DC=contoso,DC=com' -GroupScope 'Global' -GroupCategory 'Security' -Description 'Retired application'
    $weird = New-GroupMeta -Name 'Sales "West" </script><img src=x onerror=alert(1)>' -SamAccountName 'SalesWest' -DistinguishedName 'CN=Weird,OU=Groups,DC=contoso,DC=com' -GroupScope 'Global' -GroupCategory 'Distribution' -Description "Use \\fileserver\sales <b>not html</b>"
    $archive = New-GroupMeta -Name 'Archive Mail' -SamAccountName 'ArchiveMail' -DistinguishedName 'CN=Archive Mail,OU=Groups,DC=contoso,DC=com' -GroupScope 'Universal' -GroupCategory 'Distribution' -Description 'Mailbox archive. No selected user is a member.'

    $sharedOrg = @{ Company = 'Contoso'; Division = 'Corporate'; City = 'Seattle'; State = 'WA'; Country = 'US' }
    $aliceAttr = $sharedOrg.Clone()
    $aliceAttr.Department = 'Finance'; $aliceAttr.Title = 'Analyst'; $aliceAttr.Office = 'London'; $aliceAttr.Manager = 'Pat Lee'; $aliceAttr.EmployeeType = 'Employee'; $aliceAttr.EmployeeID = 'E1001'; $aliceAttr.extensionAttribute1 = 'FALCON'; $aliceAttr.Description = 'Budget & planning'
    $bobAttr = $sharedOrg.Clone()
    $bobAttr.Department = 'IT'; $bobAttr.Title = 'Engineer'; $bobAttr.Office = 'London'; $bobAttr.Manager = 'Sam Roy'; $bobAttr.EmployeeType = 'Employee'; $bobAttr.EmployeeID = 'E1002'; $bobAttr.extensionAttribute1 = 'FALCON'
    $carolAttr = $sharedOrg.Clone()
    $carolAttr.Department = 'R&D'; $carolAttr.Title = 'Manager'; $carolAttr.Office = 'London'; $carolAttr.Manager = 'Pat Lee'; $carolAttr.EmployeeType = 'Employee'; $carolAttr.EmployeeID = 'E1003'; $carolAttr.extensionAttribute1 = 'FALCON'
    $daveAttr = $sharedOrg.Clone()
    $daveAttr.Department = 'Finance'; $daveAttr.Title = 'Contractor'; $daveAttr.Office = 'Remote'; $daveAttr.Manager = 'Pat Lee'; $daveAttr.EmployeeType = 'Contractor'; $daveAttr.EmployeeID = 'E1004'; $daveAttr.extensionAttribute1 = 'LEGACY'
    $eveAttr = $sharedOrg.Clone()
    $eveAttr.Department = 'Interns'; $eveAttr.Title = 'Intern'; $eveAttr.Office = 'London'; $eveAttr.Manager = 'Pat Lee'; $eveAttr.EmployeeType = 'Intern'; $eveAttr.EmployeeID = 'E1005'; $eveAttr.extensionAttribute1 = 'FALCON'
    $users = @(
        (New-ReportUser -SamAccountName 'alice' -DisplayName 'Alice Nguyen' -Email 'alice@contoso.example' -Department 'Finance' -Title 'Analyst' -Enabled $true -DistinguishedName 'CN=Alice Nguyen,OU=Finance,OU=Users,DC=contoso,DC=com' -UserPrincipalName 'alice@contoso.example' -Attributes $aliceAttr -Groups @($domainUsers, $allStaff, $finance, $vpn, $adminsFinance, $weird))
        (New-ReportUser -SamAccountName 'bob' -DisplayName 'Bob Singh' -Email 'bob@contoso.example' -Department 'IT' -Title 'Engineer' -Enabled $true -DistinguishedName 'CN=Bob Singh,OU=IT,OU=Users,DC=contoso,DC=com' -UserPrincipalName 'bob@contoso.example' -Attributes $bobAttr -Groups @($domainUsers, $allStaff, $finance, $vpn, $contractors))
        (New-ReportUser -SamAccountName 'carol' -DisplayName "Carol O'Neil" -Email 'carol@contoso.example' -Department 'R&D' -Title 'Manager' -Enabled $true -DistinguishedName "CN=Carol O'Neil,OU=R&D,OU=Users,DC=contoso,DC=com" -UserPrincipalName 'carol@contoso.example' -Attributes $carolAttr -Groups @($domainUsers, $allStaff, $finance, $adminsHr))
        (New-ReportUser -SamAccountName 'dave' -DisplayName 'Dave Chen' -Email 'dave@contoso.example' -Department 'Finance' -Title 'Contractor' -Enabled $false -DistinguishedName 'CN=Dave Chen,OU=Contractors,OU=Finance,OU=Users,DC=contoso,DC=com' -UserPrincipalName 'dave@contoso.example' -Attributes $daveAttr -Groups @($domainUsers, $allStaff, $legacy))
        (New-ReportUser -SamAccountName 'eve' -DisplayName 'Eve Patel' -Email '' -Department 'Interns' -Title 'Intern' -Enabled $true -DistinguishedName 'CN=Eve Patel,OU=Interns,OU=Users,DC=contoso,DC=com' -UserPrincipalName 'eve@contoso.example' -Attributes $eveAttr -Groups $domainUsers)
    )
    New-CommonGroupReportModel -Users $users -NotFound @('frank') -CompareNames @('Domain Users', 'Finance', 'Ghost Group', 'Archive Mail', 'Admins', 'Legacy App') -ExtraGroups @($archive) -MinimumUserCount 2 -ExcludeDisabled:$ExcludeDisabled -UsersCsv 'users.csv' -GroupsCsv 'groups.csv' -Domain 'contoso.example' -Generated 'Wednesday 30 September 2026, 12:00:00' -ScriptName 'Find-CommonADGroups.ps1'
}

function Get-PrimaryGroupSid {
    param($AdUser)
    if ($null -eq $AdUser -or $null -eq $AdUser.PrimaryGroupID) { return $null }
    $sid = [string]$AdUser.SID
    if ([string]::IsNullOrWhiteSpace($sid)) { return $null }
    $split = $sid.LastIndexOf('-')
    if ($split -lt 1) { return $null }
    return ($sid.Substring(0, $split) + '-' + [string]$AdUser.PrimaryGroupID)
}

function ConvertFrom-AdGroupObject {
    param($Group)
    $description = ''
    if ($null -ne $Group.Description) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($part in (ConvertTo-ObjectList $Group.Description)) {
            $text = [string]$part
            if (-not [string]::IsNullOrWhiteSpace($text)) { [void]$parts.Add($text) }
        }
        $description = ($parts -join "`n")
    }
    $name = [string]$Group.Name
    $dn = [string]$Group.DistinguishedName
    if ([string]::IsNullOrWhiteSpace($name)) { $name = Get-CnFromDistinguishedName $dn }
    $scope = ''
    $category = ''
    if ($null -ne $Group.GroupScope) { $scope = [string]$Group.GroupScope }
    if ($null -ne $Group.GroupCategory) { $category = [string]$Group.GroupCategory }
    New-GroupMeta -Name $name -SamAccountName ([string]$Group.SamAccountName) -DistinguishedName $dn -GroupScope $scope -GroupCategory $category -Description $description
}

function New-UnknownGroupMeta {
    param([string]$Identity)
    $dn = $Identity
    $name = $Identity
    if ($Identity -match '(?i)^(CN|OU|DC)=') { $name = Get-CnFromDistinguishedName $Identity }
    New-GroupMeta -Name $name -SamAccountName '' -DistinguishedName $dn -GroupScope 'Unknown' -GroupCategory 'Unknown' -Description 'The group could not be read from Active Directory.'
}

function Resolve-CachedGroup {
    param($Cache, [string]$Identity, $CommonParams)
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $null }
    if ($Cache.ContainsKey($Identity)) { return $Cache[$Identity] }
    try {
        $params = @{
            Identity    = $Identity
            Properties  = @('Description', 'GroupScope', 'GroupCategory', 'SamAccountName', 'DistinguishedName', 'Name')
            ErrorAction = 'Stop'
        }
        Add-DictionaryParameter -Target $params -Source $CommonParams
        $group = Get-ADGroup @params
        $meta = ConvertFrom-AdGroupObject $group
        $Cache[$Identity] = $meta
        if (-not [string]::IsNullOrWhiteSpace($meta.DistinguishedName)) { $Cache[$meta.DistinguishedName] = $meta }
        return $meta
    }
    catch {
        $meta = New-UnknownGroupMeta -Identity $Identity
        $Cache[$Identity] = $meta
        return $meta
    }
}

function Get-AdGroupMetadataForUser {
    param($AdUser, $Cache, [bool]$IncludeNested, $CommonParams)
    $identities = New-Object System.Collections.Generic.List[string]
    if ($IncludeNested) {
        $userDn = [string]$AdUser.DistinguishedName
        $filter = '(member:1.2.840.113556.1.4.1941:=' + (ConvertTo-LdapFilterLiteral $userDn) + ')'
        try {
            $params = @{
                LDAPFilter  = $filter
                Properties  = @('Description', 'GroupScope', 'GroupCategory', 'SamAccountName', 'DistinguishedName', 'Name')
                ErrorAction = 'Stop'
            }
            Add-DictionaryParameter -Target $params -Source $CommonParams
            foreach ($group in @(Get-ADGroup @params)) {
                $meta = ConvertFrom-AdGroupObject $group
                if (-not [string]::IsNullOrWhiteSpace($meta.DistinguishedName)) {
                    $Cache[$meta.DistinguishedName] = $meta
                    [void]$identities.Add($meta.DistinguishedName)
                }
            }
        }
        catch {
            Write-ToolStatus "Nested lookup failed for $($AdUser.SamAccountName): $($_.Exception.Message). Falling back to direct membership." 'WARN'
            $IncludeNested = $false
        }
    }
    if (-not $IncludeNested) {
        foreach ($memberDn in (ConvertTo-ObjectList $AdUser.MemberOf)) {
            $text = [string]$memberDn
            if (-not [string]::IsNullOrWhiteSpace($text)) { [void]$identities.Add($text) }
        }
    }
    $primary = Get-PrimaryGroupSid $AdUser
    if ($primary) { [void]$identities.Add($primary) }

    $metas = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($identity in $identities) {
        $meta = Resolve-CachedGroup -Cache $Cache -Identity $identity -CommonParams $CommonParams
        if ($null -eq $meta) { continue }
        $dn = [string]$meta.DistinguishedName
        if ([string]::IsNullOrWhiteSpace($dn)) { $dn = $identity }
        if ($seen.ContainsKey($dn)) { continue }
        $seen[$dn] = $true
        [void]$metas.Add($meta)
    }
    return ,$metas
}

function Find-AdGroupsForCompareNames {
    param($Names, $CommonParams)
    $found = New-Object System.Collections.Generic.List[object]
    $nameList = ConvertTo-ObjectList $Names
    if ($nameList.Count -eq 0) { return ,$found }
    $batchSize = 20
    $properties = @('Description', 'GroupScope', 'GroupCategory', 'SamAccountName', 'DistinguishedName', 'Name')
    for ($offset = 0; $offset -lt $nameList.Count; $offset += $batchSize) {
        $end = [Math]::Min($offset + $batchSize - 1, $nameList.Count - 1)
        $clauses = New-Object System.Collections.Generic.List[string]
        $batch = New-Object System.Collections.Generic.List[string]
        for ($index = $offset; $index -le $end; $index++) {
            $name = [string]$nameList[$index]
            [void]$batch.Add($name)
            $literal = ConvertTo-LdapFilterLiteral $name
            [void]$clauses.Add('(name=' + $literal + ')')
            [void]$clauses.Add('(sAMAccountName=' + $literal + ')')
        }
        $filter = '(|' + ($clauses -join '') + ')'
        $results = @()
        try {
            $params = @{ LDAPFilter = $filter; Properties = $properties; ErrorAction = 'Stop' }
            Add-DictionaryParameter -Target $params -Source $CommonParams
            $results = @(Get-ADGroup @params)
        }
        catch {
            Write-ToolStatus "Group comparison lookup failed for a batch ($($_.Exception.Message)). Retrying one name at a time." 'WARN'
            foreach ($name in $batch) {
                try {
                    $literal = ConvertTo-LdapFilterLiteral $name
                    $params = @{
                        LDAPFilter  = "(|(name=$literal)(sAMAccountName=$literal))"
                        Properties  = $properties
                        ErrorAction = 'Stop'
                    }
                    Add-DictionaryParameter -Target $params -Source $CommonParams
                    $results += @(Get-ADGroup @params)
                }
                catch {
                    Write-ToolStatus "Could not search for reference group '$name': $($_.Exception.Message)" 'WARN'
                }
            }
        }
        foreach ($group in $results) {
            if ($null -ne $group) { [void]$found.Add((ConvertFrom-AdGroupObject $group)) }
        }
    }
    return ,$found
}

function Test-IdentityLookupAttribute {
    param([string]$Attribute)
    return @('distinguishedName', 'objectGUID', 'objectSid') -contains $Attribute
}

function Test-AmbiguousUserMatch {
    param($Value)
    return ($null -ne $Value -and $null -ne $Value.PSObject.Properties['AmbiguousMatch'] -and $Value.AmbiguousMatch -eq $true)
}

function Get-AdUserQueryPropertyList {
    param([string]$LookupAttribute)
    $props = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @(Get-AdUserQueryProperties)) {
        $text = [string]$name
        if ([string]::IsNullOrWhiteSpace($text) -or $seen.ContainsKey($text)) { continue }
        $seen[$text] = $true
        [void]$props.Add($text)
    }
    if (-not [string]::IsNullOrWhiteSpace($LookupAttribute) -and -not $seen.ContainsKey($LookupAttribute)) {
        [void]$props.Add($LookupAttribute)
    }
    return ,$props
}

function Get-AdUserLookupText {
    param($AdUser, [string]$Attribute)
    if ($null -eq $AdUser -or [string]::IsNullOrWhiteSpace($Attribute)) { return '' }
    $names = New-Object System.Collections.Generic.List[string]
    switch ($Attribute) {
        'sAMAccountName' { [void]$names.Add('SamAccountName') }
        'userPrincipalName' { [void]$names.Add('UserPrincipalName') }
        'mail' { [void]$names.Add('mail'); [void]$names.Add('EmailAddress') }
        'employeeID' { [void]$names.Add('EmployeeID') }
        'employeeNumber' { [void]$names.Add('EmployeeNumber') }
        'distinguishedName' { [void]$names.Add('DistinguishedName') }
        'displayName' { [void]$names.Add('DisplayName') }
        'name' { [void]$names.Add('Name') }
        'objectGUID' { [void]$names.Add('ObjectGUID') }
        'objectSid' { [void]$names.Add('SID') }
    }
    [void]$names.Add($Attribute)
    foreach ($name in $names) {
        $prop = $AdUser.PSObject.Properties[$name]
        if ($null -eq $prop -or $null -eq $prop.Value) { continue }
        $text = ([string]$prop.Value).Trim()
        if (-not [string]::IsNullOrWhiteSpace($text)) { return $text }
    }
    return ''
}

function Add-ResolvedUserLookup {
    param($Map, [string]$Key, $AdUser)
    if ($null -eq $Map -or [string]::IsNullOrWhiteSpace($Key) -or $null -eq $AdUser) { return }
    if ($Map.ContainsKey($Key)) {
        $existing = $Map[$Key]
        if (Test-AmbiguousUserMatch $existing) { return }
        $existingSam = ''
        $newSam = ''
        if ($null -ne $existing -and $existing.SamAccountName) { $existingSam = [string]$existing.SamAccountName }
        if ($AdUser.SamAccountName) { $newSam = [string]$AdUser.SamAccountName }
        if ([string]::IsNullOrWhiteSpace($existingSam) -or [string]::IsNullOrWhiteSpace($newSam) -or $existingSam -ne $newSam) {
            $Map[$Key] = [pscustomobject]@{ AmbiguousMatch = $true }
        }
        return
    }
    $Map[$Key] = $AdUser
}

function Get-AdUserBySamBatch {
    param($SamList, $CommonParams, [string]$LookupAttribute = 'sAMAccountName')
    if ([string]::IsNullOrWhiteSpace($LookupAttribute)) { $LookupAttribute = 'sAMAccountName' }
    $map = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $props = @(Get-AdUserQueryPropertyList -LookupAttribute $LookupAttribute)
    $identityLookup = Test-IdentityLookupAttribute $LookupAttribute
    $batchSize = 40
    for ($offset = 0; $offset -lt $SamList.Count; $offset += $batchSize) {
        $end = [Math]::Min($offset + $batchSize - 1, $SamList.Count - 1)
        $batch = New-Object System.Collections.Generic.List[string]
        $clauses = New-Object System.Collections.Generic.List[string]
        $wanted = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        for ($index = $offset; $index -le $end; $index++) {
            $sam = [string]$SamList[$index]
            [void]$batch.Add($sam)
            $wanted[$sam] = $true
            [void]$clauses.Add('(' + $LookupAttribute + '=' + (ConvertTo-LdapFilterLiteral $sam) + ')')
        }
        $resolved = $false
        if ($identityLookup) {
            foreach ($sam in $batch) {
                try {
                    $params = @{ Identity = $sam; Properties = $props; ErrorAction = 'Stop' }
                    Add-DictionaryParameter -Target $params -Source $CommonParams
                    $user = Get-ADUser @params
                    if ($user) { Add-ResolvedUserLookup -Map $map -Key $sam -AdUser $user }
                }
                catch { }
            }
            $resolved = $true
        }
        else {
            try {
                $params = @{ LDAPFilter = ('(|' + ($clauses -join '') + ')'); Properties = $props; ErrorAction = 'Stop' }
                Add-DictionaryParameter -Target $params -Source $CommonParams
                foreach ($user in @(Get-ADUser @params)) {
                    $text = Get-AdUserLookupText -AdUser $user -Attribute $LookupAttribute
                    if ([string]::IsNullOrWhiteSpace($text) -or -not $wanted.ContainsKey($text)) { continue }
                    Add-ResolvedUserLookup -Map $map -Key $text -AdUser $user
                }
                $resolved = $true
            }
            catch {
                Write-ToolStatus "User batch failed ($($_.Exception.Message)). Retrying each account." 'WARN'
            }
        }
        if (-not $resolved) {
            foreach ($sam in $batch) {
                try {
                    if ($LookupAttribute -eq 'sAMAccountName') {
                        $params = @{ Identity = $sam; Properties = $props; ErrorAction = 'Stop' }
                        Add-DictionaryParameter -Target $params -Source $CommonParams
                        $user = Get-ADUser @params
                        if ($user) { Add-ResolvedUserLookup -Map $map -Key $sam -AdUser $user }
                    }
                    else {
                        $params = @{
                            LDAPFilter  = ('(' + $LookupAttribute + '=' + (ConvertTo-LdapFilterLiteral $sam) + ')')
                            Properties  = $props
                            ErrorAction = 'Stop'
                        }
                        Add-DictionaryParameter -Target $params -Source $CommonParams
                        $found = @(Get-ADUser @params)
                        if ($found.Count -gt 1) { $map[$sam] = [pscustomobject]@{ AmbiguousMatch = $true } }
                        elseif ($found.Count -eq 1) { Add-ResolvedUserLookup -Map $map -Key $sam -AdUser $found[0] }
                    }
                }
                catch { }
            }
        }
        $percent = [int](($end + 1) * 100 / [Math]::Max(1, $SamList.Count))
        Write-Progress -Activity 'Find common AD groups' -Status "Resolved accounts $($end + 1) of $($SamList.Count)" -PercentComplete $percent
    }
    return ,$map
}

function Find-AdUserAlternate {
    param([string]$Value, $CommonParams, [string]$LookupAttribute = 'sAMAccountName')
    if ([string]::IsNullOrWhiteSpace($LookupAttribute)) { $LookupAttribute = 'sAMAccountName' }
    $props = @(Get-AdUserQueryPropertyList -LookupAttribute $LookupAttribute)
    if ($LookupAttribute -ne 'sAMAccountName' -and -not (Test-IdentityLookupAttribute $LookupAttribute)) {
        try {
            $params = @{
                LDAPFilter  = ('(' + $LookupAttribute + '=' + (ConvertTo-LdapFilterLiteral $Value) + ')')
                Properties  = $props
                ErrorAction = 'Stop'
            }
            Add-DictionaryParameter -Target $params -Source $CommonParams
            $found = @(Get-ADUser @params)
            if ($found.Count -gt 1) { return [pscustomobject]@{ AmbiguousMatch = $true } }
            if ($found.Count -eq 1) { return $found[0] }
        }
        catch { }
    }
    $looksSpecial = ($Value -match '@') -or ($Value -like 'CN=*') -or ($Value -like '*=*') -or ($Value -like 'S-1-*') -or ($Value -match '^[0-9a-fA-F-]{36}$')
    if (-not $looksSpecial) { return $null }
    try {
        if ($Value -match '@') {
            $params = @{
                LDAPFilter  = ('(userPrincipalName=' + (ConvertTo-LdapFilterLiteral $Value) + ')')
                Properties  = $props
                ErrorAction = 'Stop'
            }
            Add-DictionaryParameter -Target $params -Source $CommonParams
            $found = @(Get-ADUser @params)
            if ($found.Count -gt 0) { return $found[0] }
        }
        $params = @{ Identity = $Value; Properties = $props; ErrorAction = 'Stop' }
        Add-DictionaryParameter -Target $params -Source $CommonParams
        return Get-ADUser @params
    }
    catch { return $null }
}

function Get-RawAttributesFromAdUser {
    param($AdUser, $Extra)
    $bag = @{}
    if ($null -eq $AdUser) { return $bag }
    foreach ($def in (Get-UserAttributeDefinitions)) {
        if ($def.Derived) { continue }
        $propertyName = [string]$def.Property
        if ([string]::IsNullOrWhiteSpace($propertyName)) { continue }
        $value = $null
        if ($def.Optional) {
            if ($null -ne $Extra -and (Test-MapHasKey -Map $Extra -Key $propertyName)) {
                $value = Get-MapValue -Map $Extra -Key $propertyName
            }
            else { continue }
        }
        else {
            $prop = $AdUser.PSObject.Properties[$propertyName]
            if ($null -eq $prop) { continue }
            $value = $prop.Value
        }
        if ($null -ne $value) { $bag[$propertyName] = $value }
    }
    return $bag
}

function Get-OptionalAdAttributeMap {
    param($SamList, $PropertyNames, $CommonParams)
    $map = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($name in (ConvertTo-ObjectList $PropertyNames)) {
        $text = ([string]$name).Trim()
        if (-not [string]::IsNullOrWhiteSpace($text)) { [void]$names.Add($text) }
    }
    $accounts = New-Object System.Collections.Generic.List[string]
    foreach ($sam in (ConvertTo-ObjectList $SamList)) {
        $text = ([string]$sam).Trim()
        if (-not [string]::IsNullOrWhiteSpace($text)) { [void]$accounts.Add($text) }
    }
    if ($names.Count -eq 0 -or $accounts.Count -eq 0) { return ,$map }
    try {
        $probeParams = @{ Identity = [string]$accounts[0]; Properties = @([string]$names[0]); ErrorAction = 'Stop' }
        Add-DictionaryParameter -Target $probeParams -Source $CommonParams
        $null = Get-ADUser @probeParams
    }
    catch { return ,$map }
    $batchSize = 40
    for ($offset = 0; $offset -lt $accounts.Count; $offset += $batchSize) {
        $end = [Math]::Min($offset + $batchSize - 1, $accounts.Count - 1)
        $clauses = New-Object System.Collections.Generic.List[string]
        for ($index = $offset; $index -le $end; $index++) {
            [void]$clauses.Add('(sAMAccountName=' + (ConvertTo-LdapFilterLiteral ([string]$accounts[$index])) + ')')
        }
        try {
            $params = @{
                LDAPFilter  = ('(|' + ($clauses -join '') + ')')
                Properties  = $names.ToArray()
                ErrorAction = 'Stop'
            }
            Add-DictionaryParameter -Target $params -Source $CommonParams
            foreach ($user in @(Get-ADUser @params)) {
                if (-not $user.SamAccountName) { continue }
                $bag = @{}
                foreach ($name in $names) {
                    $prop = $user.PSObject.Properties[[string]$name]
                    if ($null -ne $prop -and $null -ne $prop.Value) { $bag[[string]$name] = $prop.Value }
                }
                $map[[string]$user.SamAccountName] = $bag
            }
        }
        catch {
            Write-ToolStatus "Optional attributes could not be read: $($_.Exception.Message)" 'WARN'
            break
        }
    }
    return ,$map
}

function Merge-OptionalAttributeBags {
    param($Target, $SourceMap, [string]$Sam)
    if ($null -eq $Target -or $null -eq $SourceMap -or [string]::IsNullOrWhiteSpace($Sam)) { return }
    if (-not $SourceMap.ContainsKey($Sam)) { return }
    $bag = $SourceMap[$Sam]
    if ($null -eq $bag) { return }
    foreach ($key in @($bag.Keys)) { $Target[[string]$key] = $bag[$key] }
}

function Resolve-ManagerDisplayNames {
    param($Users, $CommonParams)
    $pending = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($user in (ConvertTo-ObjectList $Users)) {
        $dn = [string]$user.ManagerDn
        if ([string]::IsNullOrWhiteSpace($dn)) { continue }
        if (-not $pending.ContainsKey($dn)) {
            $pending[$dn] = New-Object System.Collections.Generic.List[object]
        }
        [void]$pending[$dn].Add($user)
    }
    foreach ($dn in @($pending.Keys)) {
        $label = Get-CnFromDistinguishedName $dn
        try {
            $params = @{ Identity = $dn; Properties = @('DisplayName', 'SamAccountName'); ErrorAction = 'Stop' }
            Add-DictionaryParameter -Target $params -Source $CommonParams
            $manager = Get-ADUser @params
            $display = [string]$manager.DisplayName
            if ([string]::IsNullOrWhiteSpace($display)) { $display = Get-CnFromDistinguishedName ([string]$manager.DistinguishedName) }
            $sam = [string]$manager.SamAccountName
            if (-not [string]::IsNullOrWhiteSpace($display) -and -not [string]::IsNullOrWhiteSpace($sam) -and ($display -ne $sam)) {
                $label = '{0} ({1})' -f $display, $sam
            }
            elseif (-not [string]::IsNullOrWhiteSpace($display)) { $label = $display }
        }
        catch { }
        foreach ($user in $pending[$dn]) {
            if ($null -eq $user.Attributes) { continue }
            $user.Attributes['Manager'] = $label
        }
    }
}

function Get-AdReportRecords {
    param($SamList, $CompareNames, [bool]$IncludeNested, $CommonParams, [string]$LookupAttribute = 'sAMAccountName', [string]$ColumnName = '')
    if ([string]::IsNullOrWhiteSpace($LookupAttribute)) { $LookupAttribute = 'sAMAccountName' }
    if ([string]::IsNullOrWhiteSpace($ColumnName)) { $ColumnName = $LookupAttribute }
    $userMap = Get-AdUserBySamBatch -SamList $SamList -CommonParams $CommonParams -LookupAttribute $LookupAttribute
    $cache = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $pending = New-Object System.Collections.Generic.List[object]
    $notFound = New-Object System.Collections.Generic.List[string]
    $index = 0
    foreach ($sam in $SamList) {
        $index++
        $adUser = $null
        if ($userMap.ContainsKey([string]$sam)) { $adUser = $userMap[[string]$sam] }
        if (Test-AmbiguousUserMatch $adUser) {
            Write-ToolStatus "More than one account matches '$sam' in column '$ColumnName'." 'WARN'
            [void]$notFound.Add([string]$sam)
            continue
        }
        if ($null -eq $adUser) { $adUser = Find-AdUserAlternate -Value $sam -CommonParams $CommonParams -LookupAttribute $LookupAttribute }
        if (Test-AmbiguousUserMatch $adUser) {
            Write-ToolStatus "More than one account matches '$sam' in column '$ColumnName'." 'WARN'
            [void]$notFound.Add([string]$sam)
            continue
        }
        if ($null -eq $adUser) {
            Write-ToolStatus "Account not found: $sam" 'WARN'
            [void]$notFound.Add([string]$sam)
        }
        else { [void]$pending.Add([pscustomobject]@{ Input = [string]$sam; AdUser = $adUser }) }
        $percent = [int]($index * 100 / [Math]::Max(1, $SamList.Count))
        Write-Progress -Activity 'Find common AD groups' -Status "Resolved accounts $index of $($SamList.Count)" -PercentComplete $percent
    }
    $resolvedSams = New-Object System.Collections.Generic.List[string]
    $seenResolved = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $pending) {
        $resolvedSam = [string]$item.AdUser.SamAccountName
        if ([string]::IsNullOrWhiteSpace($resolvedSam) -or $seenResolved.ContainsKey($resolvedSam)) { continue }
        $seenResolved[$resolvedSam] = $true
        [void]$resolvedSams.Add($resolvedSam)
    }
    $exchangeMap = Get-OptionalAdAttributeMap -SamList $resolvedSams -PropertyNames (Get-OptionalPropertyNames 'exchange') -CommonParams $CommonParams
    $cloudMap = Get-OptionalAdAttributeMap -SamList $resolvedSams -PropertyNames (Get-OptionalPropertyNames 'cloud') -CommonParams $CommonParams
    $users = New-Object System.Collections.Generic.List[object]
    $index = 0
    foreach ($item in $pending) {
        $index++
        $sam = [string]$item.Input
        $adUser = $item.AdUser
        Write-ToolStatus "Querying $($adUser.SamAccountName)"
        try {
            $groups = Get-AdGroupMetadataForUser -AdUser $adUser -Cache $cache -IncludeNested:$IncludeNested -CommonParams $CommonParams
            $email = ''
            if ($adUser.mail) { $email = [string]$adUser.mail }
            $extra = @{}
            Merge-OptionalAttributeBags -Target $extra -SourceMap $exchangeMap -Sam ([string]$adUser.SamAccountName)
            Merge-OptionalAttributeBags -Target $extra -SourceMap $cloudMap -Sam ([string]$adUser.SamAccountName)
            $raw = Get-RawAttributesFromAdUser -AdUser $adUser -Extra $extra
            $managerDn = ''
            if ($raw.Contains('Manager') -and [string]$raw['Manager'] -match '(?i)^(CN|OU|DC)=') {
                $managerDn = [string]$raw['Manager']
                $raw['Manager'] = Get-CnFromDistinguishedName $managerDn
            }
            [void]$users.Add((New-ReportUser -SamAccountName ([string]$adUser.SamAccountName) -DisplayName ([string]$adUser.DisplayName) -Email $email -Department ([string]$adUser.Department) -Title ([string]$adUser.Title) -Enabled $adUser.Enabled -DistinguishedName ([string]$adUser.DistinguishedName) -UserPrincipalName ([string]$adUser.UserPrincipalName) -ManagerDn $managerDn -Attributes $raw -Groups $groups))
            Write-ToolStatus "  $($groups.Count) group(s), including the primary group." 'OK'
        }
        catch {
            Write-ToolStatus "Failed to read groups for $($adUser.SamAccountName): $($_.Exception.Message)" 'WARN'
            [void]$notFound.Add([string]$sam)
        }
        $percent = [int]($index * 100 / [Math]::Max(1, $pending.Count))
        Write-Progress -Activity 'Find common AD groups' -Status "Read groups for $index of $($pending.Count)" -PercentComplete $percent
    }
    Resolve-ManagerDisplayNames -Users $users -CommonParams $CommonParams
    $extra = Find-AdGroupsForCompareNames -Names $CompareNames -CommonParams $CommonParams
    Write-Progress -Activity 'Find common AD groups' -Completed
    [pscustomobject]@{
        Users       = $users
        NotFound    = $notFound
        ExtraGroups = $extra
    }
}

function Test-GuiSessionAvailable {
    if ($NoGui) { return $false }
    try { Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop } catch { return $false }
    try {
        $sessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        if ($sessionId -le 0) { return $false }
    }
    catch { return $false }
    return $true
}

function Invoke-StaDialog {
    param([Parameter(Mandatory = $true)][string]$Kind, [Parameter(Mandatory = $true)][hashtable]$Options)
    $code = @'
Add-Type -AssemblyName System.Windows.Forms
$opt = $args[0]
$kind = [string]$args[1]
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$owner.ShowInTaskbar = $false
$owner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
$owner.Opacity = 0
$owner.Width = 1
$owner.Height = 1
$owner.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
[void]$owner.Show()
$owner.Activate()
try {
    if ($kind -eq 'open') {
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Title = [string]$opt.Title
        $dlg.Filter = [string]$opt.Filter
        $dlg.InitialDirectory = [string]$opt.InitialDirectory
        $dlg.CheckFileExists = $true
        $dlg.Multiselect = $false
        if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { $dlg.FileName }
    }
    elseif ($kind -eq 'save') {
        $dlg = New-Object System.Windows.Forms.SaveFileDialog
        $dlg.Title = [string]$opt.Title
        $dlg.Filter = [string]$opt.Filter
        $dlg.DefaultExt = [string]$opt.DefaultExt
        $dlg.InitialDirectory = [string]$opt.InitialDirectory
        $dlg.FileName = [string]$opt.FileName
        $dlg.OverwritePrompt = $true
        if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { $dlg.FileName }
    }
    elseif ($kind -eq 'choose') {
        Add-Type -AssemblyName System.Drawing
        $form = New-Object System.Windows.Forms.Form
        $form.Text = [string]$opt.Title
        $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
        $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false
        $form.TopMost = $true
        $form.ClientSize = New-Object System.Drawing.Size(480, 168)
        $label = New-Object System.Windows.Forms.Label
        $label.Text = [string]$opt.Message
        $label.Location = New-Object System.Drawing.Point(12, 12)
        $label.Size = New-Object System.Drawing.Size(456, 48)
        $combo = New-Object System.Windows.Forms.ComboBox
        $combo.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
        $combo.Location = New-Object System.Drawing.Point(12, 68)
        $combo.Size = New-Object System.Drawing.Size(456, 24)
        foreach ($item in @($opt.Items)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$item)) { [void]$combo.Items.Add([string]$item) }
        }
        $selected = [string]$opt.Selected
        $selectedIndex = 0
        for ($i = 0; $i -lt $combo.Items.Count; $i++) {
            if ([string]::Equals([string]$combo.Items[$i], $selected, [System.StringComparison]::OrdinalIgnoreCase)) { $selectedIndex = $i; break }
        }
        if ($combo.Items.Count -gt 0) { $combo.SelectedIndex = $selectedIndex }
        $ok = New-Object System.Windows.Forms.Button
        $ok.Text = 'Use this column'
        $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $ok.Location = New-Object System.Drawing.Point(268, 116)
        $ok.Size = New-Object System.Drawing.Size(118, 28)
        $cancel = New-Object System.Windows.Forms.Button
        $cancel.Text = 'Cancel'
        $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $cancel.Location = New-Object System.Drawing.Point(392, 116)
        $cancel.Size = New-Object System.Drawing.Size(76, 28)
        $form.AcceptButton = $ok
        $form.CancelButton = $cancel
        [void]$form.Controls.Add($label)
        [void]$form.Controls.Add($combo)
        [void]$form.Controls.Add($ok)
        [void]$form.Controls.Add($cancel)
        if ($form.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK -and $null -ne $combo.SelectedItem) {
            [string]$combo.SelectedItem
        }
    }
    else {
        $result = [System.Windows.Forms.MessageBox]::Show([string]$opt.Message, [string]$opt.Title, [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        $result -eq [System.Windows.Forms.DialogResult]::Yes
    }
}
finally { $owner.Dispose() }
'@
    $apartment = [System.Threading.Thread]::CurrentThread.GetApartmentState()
    if ($apartment -eq [System.Threading.ApartmentState]::STA) {
        $output = @(Invoke-Command -ScriptBlock ([scriptblock]::Create($code)) -ArgumentList $Options, $Kind)
        if ($output.Count -eq 0) { return $null }
        return $output[0]
    }
    $ps = [powershell]::Create()
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = 'STA'
    $runspace.Open()
    $ps.Runspace = $runspace
    try {
        [void]$ps.AddScript($code)
        [void]$ps.AddArgument($Options)
        [void]$ps.AddArgument($Kind)
        $output = @($ps.Invoke())
        if ($ps.HadErrors) {
            $detail = ($ps.Streams.Error | Select-Object -First 1 | Out-String).Trim()
            throw "The file dialog could not be opened. Pass -NoGui and the file paths. $detail"
        }
        if ($output.Count -eq 0) { return $null }
        return $output[0]
    }
    finally {
        $ps.Dispose()
        $runspace.Close()
        $runspace.Dispose()
    }
}

function Get-PickerStartDirectory {
    param([string]$Preferred)
    if (-not [string]::IsNullOrWhiteSpace($Preferred) -and (Test-Path -LiteralPath $Preferred -PathType Container)) { return $Preferred }
    $desktop = [Environment]::GetFolderPath('Desktop')
    if (-not [string]::IsNullOrWhiteSpace($desktop) -and (Test-Path -LiteralPath $desktop -PathType Container)) { return $desktop }
    return [Environment]::GetFolderPath('UserProfile')
}

function Get-DefaultOutputPath {
    param([string]$NearFile)
    $directory = (Get-Location).Path
    if (-not [string]::IsNullOrWhiteSpace($NearFile) -and (Test-Path -LiteralPath $NearFile)) {
        $directory = [System.IO.Path]::GetDirectoryName((Resolve-Path -LiteralPath $NearFile).Path)
    }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    return (Join-Path $directory ("CommonADGroups_{0}.html" -f $stamp))
}

function Invoke-FindCommonADGroups {
    try {
        $model = $null
        $nearFile = ''
        if ($Demo) {
            if ($CsvPath -or $GroupCsvPath) { Write-ToolStatus '-Demo ignores CSV paths and Active Directory.' 'WARN' }
            Write-ToolStatus 'Building the sample report.' 'INFO'
            $model = New-DemoReportModel
            $model.ExcludeDisabled = [bool]$ExcludeDisabled
            $model.MinimumUserCount = $MinimumUserCount
        }
        else {
            if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
                Write-ToolStatus 'ActiveDirectory module not found. Install RSAT: Active Directory Domain Services and Lightweight Directory Services Tools.' 'ERROR'
                return 1
            }
            Import-Module ActiveDirectory -ErrorAction Stop
            $common = New-AdCommonParameter -ServerName $Server -AdCredential $Credential
            if ($null -ne $Credential -and [string]::IsNullOrWhiteSpace($Server)) {
                Write-ToolStatus '-Credential is more reliable with -Server set to a domain controller.' 'WARN'
            }
            try {
                $probe = @{ ErrorAction = 'Stop' }
                Add-DictionaryParameter -Target $probe -Source $common
                $domainInfo = Get-ADDomain @probe
                $domainName = [string]$domainInfo.DNSRoot
                Write-ToolStatus "Connected to domain $domainName." 'OK'
            }
            catch {
                Write-ToolStatus "Could not contact Active Directory: $($_.Exception.Message)" 'ERROR'
                return 1
            }

            $gui = Test-GuiSessionAvailable
            if ([string]::IsNullOrWhiteSpace($CsvPath)) {
                if (-not $gui) {
                    Write-ToolStatus '-CsvPath is required when dialogs are unavailable. Use -NoGui only together with -CsvPath.' 'ERROR'
                    return 1
                }
                Write-ToolStatus 'Select the users CSV.'
                $CsvPath = [string](Invoke-StaDialog -Kind 'open' -Options @{
                    Title = 'Select the CSV of user account names'
                    Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
                    InitialDirectory = (Get-PickerStartDirectory)
                })
                if ([string]::IsNullOrWhiteSpace($CsvPath)) {
                    Write-ToolStatus 'No users CSV selected. Exiting.' 'WARN'
                    return 0
                }
            }
            if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
                Write-ToolStatus "Users CSV was not found: $CsvPath" 'ERROR'
                return 1
            }
            $nearFile = $CsvPath

            if ([string]::IsNullOrWhiteSpace($GroupCsvPath) -and $gui) {
                $ask = [bool]$PromptForGroupCsv
                if (-not $ask) {
                    $ask = [bool](Invoke-StaDialog -Kind 'yesno' -Options @{
                        Title = 'Load a reference group list?'
                        Message = "Compare discovered groups with a second CSV?`r`n`r`nYes opens a file picker. No continues without a comparison."
                    })
                }
                if ($ask) {
                    $GroupCsvPath = [string](Invoke-StaDialog -Kind 'open' -Options @{
                        Title = 'Select the CSV of reference group names'
                        Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
                        InitialDirectory = (Get-PickerStartDirectory -Preferred ([System.IO.Path]::GetDirectoryName((Resolve-Path -LiteralPath $CsvPath).Path)))
                    })
                    if ([string]::IsNullOrWhiteSpace($GroupCsvPath)) {
                        Write-ToolStatus 'No reference CSV selected. The comparison tab will be omitted.' 'WARN'
                    }
                }
            }
            elseif ($PromptForGroupCsv -and -not $gui -and [string]::IsNullOrWhiteSpace($GroupCsvPath)) {
                Write-ToolStatus '-PromptForGroupCsv needs a desktop session. Continuing without comparison.' 'WARN'
            }
            if (-not [string]::IsNullOrWhiteSpace($GroupCsvPath) -and -not (Test-Path -LiteralPath $GroupCsvPath -PathType Leaf)) {
                Write-ToolStatus "Reference CSV was not found: $GroupCsvPath. Continuing without comparison." 'WARN'
                $GroupCsvPath = ''
            }

            $userAliases = @('SamAccountName', 'sAMAccountName', 'Username', 'UserName', 'User', 'LoginName', 'UserPrincipalName', 'UPN', 'Account', 'Email', 'EmailAddress', 'Mail', 'EmployeeID', 'EmployeeId')
            $headers = Get-CsvColumnNames -Path $CsvPath -Label 'Users'
            $selectedColumn = ''
            if (-not [string]::IsNullOrWhiteSpace($UserColumn)) {
                $selectedColumn = Select-CsvColumn -Headers $headers -Column $UserColumn -Aliases $userAliases -Label 'Users'
            }
            elseif ($gui -and $headers.Count -gt 1) {
                $preferred = Select-CsvColumn -Headers $headers -Aliases $userAliases -Label 'Users' -Quiet
                $displayHeaders = New-Object System.Collections.Generic.List[string]
                foreach ($header in $headers) { [void]$displayHeaders.Add((Get-CleanCsvHeader $header)) }
                Write-ToolStatus 'Select the CSV column that identifies each user.'
                $picked = Invoke-StaDialog -Kind 'choose' -Options @{
                    Title = 'Which column identifies each user?'
                    Message = 'The user comparison looks up every value in this column. Choose the header that contains the account name, email, employee ID, or other directory value.'
                    Items = $displayHeaders.ToArray()
                    Selected = (Get-CleanCsvHeader $preferred)
                }
                if ([string]::IsNullOrWhiteSpace([string]$picked)) {
                    Write-ToolStatus 'No CSV column selected. Exiting.' 'WARN'
                    return 0
                }
                $selectedColumn = Select-CsvColumn -Headers $headers -Column ([string]$picked) -Aliases $userAliases -Label 'Users'
            }
            else {
                $selectedColumn = Select-CsvColumn -Headers $headers -Aliases $userAliases -Label 'Users'
            }
            $displayColumn = Get-CleanCsvHeader $selectedColumn
            $lookupAttribute = Get-UserLookupAttribute -ColumnName $displayColumn
            $samList = Import-NameCsv -Path $CsvPath -Aliases $userAliases -Label 'Users' -Column $selectedColumn
            Write-ToolStatus "Matching $($samList.Count) value(s) from column '$displayColumn' using $lookupAttribute." 'OK'
            $compareNames = New-Object System.Collections.Generic.List[string]
            if (-not [string]::IsNullOrWhiteSpace($GroupCsvPath)) {
                $groupAliases = @('GroupName', 'Name', 'Group', 'SamAccountName', 'sAMAccountName', 'GroupSamAccountName')
                $compareNames = Import-NameCsv -Path $GroupCsvPath -Aliases $groupAliases -Label 'Reference group' -AllowEmpty
                Write-ToolStatus "Loaded $($compareNames.Count) reference group name(s)." 'OK'
            }
            $records = Get-AdReportRecords -SamList $samList -CompareNames $compareNames -IncludeNested:([bool]$Recursive) -CommonParams $common -LookupAttribute $lookupAttribute -ColumnName $displayColumn
            $model = New-CommonGroupReportModel -Users $records.Users -NotFound $records.NotFound -CompareNames $compareNames -ExtraGroups $records.ExtraGroups -MinimumUserCount $MinimumUserCount -ExcludeDisabled:([bool]$ExcludeDisabled) -Recursive:([bool]$Recursive) -UsersCsv ([System.IO.Path]::GetFileName($CsvPath)) -UserColumn $displayColumn -GroupsCsv $(if ($GroupCsvPath) { [System.IO.Path]::GetFileName($GroupCsvPath) } else { '' }) -ServerName $Server -Domain $domainName -ScriptName $toolFileName
        }

        $stats = Get-MembershipStats $model
        if (-not $Demo -and $stats.Resolved -eq 0) {
            Write-ToolStatus 'No accounts were resolved. The report will still list the names that were not found.' 'WARN'
        }
        if ($stats.InScope -gt 0 -and $MinimumUserCount -gt $stats.InScope) {
            Write-ToolStatus "MinimumUserCount ($MinimumUserCount) is higher than the in-scope user count ($($stats.InScope)). Lower the threshold in the report to see groups." 'WARN'
        }

        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            if ((Test-GuiSessionAvailable) -and -not $NoGui) {
                $suggested = [System.IO.Path]::GetFileName((Get-DefaultOutputPath -NearFile $nearFile))
                $initial = Get-PickerStartDirectory
                if ($nearFile) { $initial = Get-PickerStartDirectory -Preferred ([System.IO.Path]::GetDirectoryName((Resolve-Path -LiteralPath $nearFile).Path)) }
                $OutputPath = [string](Invoke-StaDialog -Kind 'save' -Options @{
                    Title = 'Save the HTML report'
                    Filter = 'HTML files (*.html)|*.html|All files (*.*)|*.*'
                    DefaultExt = 'html'
                    FileName = $suggested
                    InitialDirectory = $initial
                })
                if ([string]::IsNullOrWhiteSpace($OutputPath)) {
                    Write-ToolStatus 'No save location selected. Exiting.' 'WARN'
                    return 0
                }
            }
            else {
                $OutputPath = Get-DefaultOutputPath -NearFile $nearFile
                Write-ToolStatus "Output path defaulting to $OutputPath"
            }
        }
        if (Test-Path -LiteralPath $OutputPath -PathType Container) {
            Write-ToolStatus "Output path is a directory, not a file: $OutputPath" 'ERROR'
            return 1
        }
        $html = New-CommonAdGroupsHtml -Model $model
        Write-Utf8NoBomFile -Path $OutputPath -Content $html
        Write-ToolStatus "Report saved: $OutputPath" 'OK'
        Write-Host ''
        Write-Host ("  Report           : {0}" -f $OutputPath)
        Write-Host ("  Users            : {0} resolved / {1} input / {2} in scope" -f $stats.Resolved, $stats.Input, $stats.InScope)
        Write-Host ("  Not found        : {0}" -f $stats.NotFound)
        Write-Host ("  Distinct groups  : {0}" -f $stats.Groups)
        Write-Host ("  Shared by all    : {0}" -f $stats.SharedByAll)
        Write-Host ("  Threshold (>= {0}) : {1}" -f $model.MinimumUserCount, $stats.Threshold)
        $attributeSummary = Get-AttributeTieSummary -Model $model
        Write-Host ("  Shared attributes: {0}" -f $attributeSummary.SharedCount)
        foreach ($tie in $attributeSummary.Shared) {
            Write-Host ("    {0} = {1}" -f $tie.Label, $tie.Value)
        }
        $commonOuText = [string]$attributeSummary.CommonOu
        if ([string]::IsNullOrWhiteSpace($commonOuText)) { $commonOuText = 'None' }
        Write-Host ("  Common OU        : {0}" -f $commonOuText)
        if ($model.CompareEnabled) {
            Write-Host ("  Comparison       : {0} matched, {1} in AD with nobody in scope, {2} not in AD, {3} AD only" -f $stats.Matched, $stats.NoMembers, $stats.Missing, $stats.AdOnly)
        }
        return 0
    }
    catch {
        Write-ToolStatus $_.Exception.Message 'ERROR'
        return 1
    }
}

function Get-ReportTemplate {
    return @'
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>AD Account Analysis Report</title>
<script>
window.onerror = function(message, source, line, col) {
  var banner = document.getElementById('errBanner');
  var text = String(message) + ' (' + line + ':' + col + ')';
  if (banner) { banner.style.display = 'block'; banner.textContent += text + '\n'; }
};
</script>
<style>
:root {
  --bg:#f1f5f9; --surface:#fff; --surface2:#f8fafc; --surface3:#f1f5f9;
  --border:#e2e8f0; --border2:#cbd5e1; --text:#0f172a; --text-muted:#64748b; --text-subtle:#94a3b8;
  --accent:#6366f1; --accent-light:#eef2ff; --accent-dark:#4f46e5; --accent2:#06b6d4; --accent2-light:#ecfeff;
  --green:#059669; --green-bg:#ecfdf5; --amber:#d97706; --amber-bg:#fffbeb; --red:#dc2626; --red-bg:#fef2f2;
  --purple:#7c3aed; --purple-bg:#f5f3ff; --nav-bg:#0f172a; --nav-text:#94a3b8; --nav-hover:#1e293b;
  --nav-width:232px; --top-h:60px; --radius:10px; --shadow:0 1px 3px rgba(15,23,42,.06),0 1px 2px rgba(15,23,42,.04);
}
[data-theme="dark"] {
  --bg:#0b0f1a; --surface:#111827; --surface2:#1a2234; --surface3:#1e293b;
  --border:#1e293b; --border2:#334155; --text:#f1f5f9; --text-muted:#94a3b8; --text-subtle:#64748b;
  --accent:#818cf8; --accent-light:#1e1b4b; --accent-dark:#c7d2fe; --accent2:#22d3ee; --accent2-light:#083344;
  --green:#34d399; --green-bg:#022c22; --amber:#fbbf24; --amber-bg:#1c1400; --red:#f87171; --red-bg:#1f0707;
  --purple:#a78bfa; --purple-bg:#1e1240; --nav-bg:#060c18; --nav-hover:#111827;
}
*{box-sizing:border-box} html{font-size:14px}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
[hidden]{display:none !important}
button,input,select{font:inherit}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.topbar{position:fixed;top:0;left:0;right:0;z-index:30;height:var(--top-h);background:var(--nav-bg);color:#fff;display:flex;align-items:center;gap:14px;padding:0 16px;border-bottom:1px solid rgba(255,255,255,.06)}
.brand{display:flex;align-items:center;gap:10px;min-width:0}
.brand-mark{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#6366f1,#06b6d4);display:flex;align-items:center;justify-content:center;font-weight:800;flex:none}
.brand h1{font-size:.95rem;margin:0;font-weight:700}
.brand p{margin:1px 0 0;color:var(--nav-text);font-size:.72rem}
.topbar-spacer{flex:1}
.topbar-meta{color:var(--nav-text);font-size:.72rem;text-align:right;line-height:1.45}
.toggle{display:flex;align-items:center;gap:8px;color:#e2e8f0;font-size:.78rem;white-space:nowrap}
.toggle-short{display:none}
.theme-btn,.icon-btn{width:36px;height:36px;border-radius:8px;border:0;background:rgba(255,255,255,.06);color:#e2e8f0;cursor:pointer}
.theme-btn:hover,.icon-btn:hover{background:rgba(255,255,255,.12)}
.icon-moon{display:none} [data-theme="dark"] .icon-sun{display:none} [data-theme="dark"] .icon-moon{display:inline}
.sidebar{position:fixed;top:var(--top-h);left:0;bottom:0;width:var(--nav-width);background:var(--nav-bg);padding:14px 10px;overflow:auto;z-index:20}
.nav-label{font-size:.65rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#64748b;padding:12px 8px 4px}
.nav-btn{width:100%;display:flex;align-items:center;gap:8px;padding:9px 10px;border:0;border-radius:8px;background:transparent;color:var(--nav-text);cursor:pointer;text-align:left}
.nav-btn:hover{background:var(--nav-hover);color:#fff}
.nav-btn.active{background:rgba(99,102,241,.18);color:#c7d2fe}
.nav-btn span.name{flex:1}
.badge{font-size:.68rem;font-weight:700;padding:1px 6px;border-radius:999px;background:rgba(99,102,241,.25);color:#c7d2fe}
.badge.warn{background:rgba(220,38,38,.25);color:#fecaca}
.main{margin-left:var(--nav-width);margin-top:var(--top-h);padding:28px 28px 48px}
.tab-pane{display:none} .tab-pane.active{display:block}
.page-head{margin-bottom:18px} .page-head h2{margin:0 0 4px;font-size:1.4rem} .page-head p{margin:0;color:var(--text-muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:16px 16px 12px;box-shadow:var(--shadow);position:relative;overflow:hidden}
.card:before{content:"";position:absolute;left:0;right:0;top:0;height:3px;background:var(--card,#6366f1)}
.card.c-green{--card:var(--green)} .card.c-amber{--card:var(--amber)} .card.c-red{--card:var(--red)} .card.c-cyan{--card:var(--accent2)} .card.c-purple{--card:var(--purple)}
.card-label{font-size:.68rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--text-muted)}
.card-value{font-size:1.9rem;font-weight:800;margin:6px 0 2px}
.card-sub{color:var(--text-muted);font-size:.75rem}
.note,.callout{border:1px solid var(--border);background:var(--surface);border-radius:10px;padding:12px 14px;color:var(--text-muted);margin:8px 0 16px;line-height:1.45}
.callout.warn{background:var(--amber-bg);color:var(--amber);border-color:rgba(217,119,6,.25)}
.callout.ok{background:var(--green-bg);color:var(--text);border-color:rgba(5,150,105,.28)}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.toolbar .grow{flex:1;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.search{position:relative}
.search input{height:36px;border:1px solid var(--border2);border-radius:8px;background:var(--surface);color:var(--text);padding:0 10px 0 30px;min-width:220px}
.search svg{position:absolute;left:9px;top:10px;color:var(--text-muted)}
select,input[type="number"]{height:36px;border:1px solid var(--border2);border-radius:8px;background:var(--surface);color:var(--text);padding:0 8px}
.btn{height:36px;padding:0 12px;border-radius:8px;border:1px solid var(--border2);background:var(--surface);color:var(--text);cursor:pointer}
.btn:hover{border-color:var(--accent)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn:disabled{opacity:.45;cursor:default}
.pills-row{display:flex;gap:6px;flex-wrap:wrap}
.filter-pill{border:1px solid var(--border2);background:var(--surface);color:var(--text-muted);border-radius:999px;padding:4px 10px;cursor:pointer}
.filter-pill.active{background:var(--accent);border-color:var(--accent);color:#fff}
.table-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;box-shadow:var(--shadow);overflow:hidden}
.table-scroll{overflow:auto;max-height:70vh}
table{width:100%;border-collapse:collapse}
th,td{padding:10px 12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--border)}
th{position:sticky;top:0;background:var(--surface2);font-size:.72rem;letter-spacing:.04em;text-transform:uppercase;color:var(--text-muted);cursor:pointer;white-space:nowrap;z-index:1}
th .si:after{content:" \2195";opacity:.35} th.s-asc .si:after{content:" \25B2";opacity:1;color:var(--accent)} th.s-desc .si:after{content:" \25BC";opacity:1;color:var(--accent)}
tbody tr:hover{background:var(--surface2)}
.footer{padding:8px 12px;color:var(--text-muted);font-size:.75rem;background:var(--surface2)}
.empty-row td{text-align:center;color:var(--text-muted);padding:28px}
.chip{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.7rem;font-weight:700;white-space:nowrap}
.chip-indigo{background:var(--accent-light);color:var(--accent-dark)} .chip-cyan{background:var(--accent2-light);color:var(--accent2)}
.chip-green{background:var(--green-bg);color:var(--green)} .chip-amber{background:var(--amber-bg);color:var(--amber)}
.chip-red{background:var(--red-bg);color:var(--red)} .chip-purple{background:var(--purple-bg);color:var(--purple)}
.chip-neutral{background:var(--surface3);color:var(--text-muted);border:1px solid var(--border2)}
.name-cell{display:flex;gap:6px;align-items:flex-start}
.name-stack{min-width:0}
.sub,.muted{color:var(--text-subtle);font-size:.75rem}
.sub{margin-top:2px}
.pills{display:flex;flex-wrap:wrap;gap:4px}
.pill,.pill-more{border-radius:999px;padding:2px 7px;font-size:.7rem;border:1px solid var(--border2);background:var(--surface3);color:var(--text-muted)}
.pill-more{background:var(--accent-light);color:var(--accent-dark);cursor:pointer;font-weight:700}
.exp-btn{border:0;background:transparent;color:var(--text-muted);cursor:pointer;padding:2px 4px;line-height:1}
.exp-btn.open{transform:rotate(90deg);color:var(--accent)}
.detail-row{display:none} .detail-row.open{display:table-row}
.detail-cell{background:var(--surface2)}
.detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px 18px}
.detail-wide{grid-column:1 / -1}
.detail-item label,.detail-wide label{display:block;font-size:.68rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--text-muted);margin-bottom:3px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.75rem;word-break:break-word}
.desc-cell{white-space:pre-wrap;color:var(--text-muted)}
.count-text{font-weight:700;color:var(--accent)}
.prog-wrap{display:flex;align-items:center;gap:8px;min-width:120px}
.prog-track{flex:1;height:6px;background:var(--border2);border-radius:999px;overflow:hidden}
.prog-fill{height:100%;background:var(--accent)} .tone-green{background:var(--green)} .tone-amber{background:var(--amber)} .tone-red{background:var(--red)} .tone-accent{background:var(--accent)}
.prog-pct{min-width:36px;text-align:right;color:var(--text-muted);font-size:.75rem}
.venn{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.venn-card{border-radius:14px;padding:16px;text-align:center;border:1px solid var(--border);background:var(--surface)}
.venn-card b{display:block;font-size:1.8rem}
.venn-card.matched{background:var(--green-bg)} .venn-card.matched b{color:var(--green)}
.venn-card.none{background:var(--amber-bg)} .venn-card.none b{color:var(--amber)}
.venn-card.missing{background:var(--red-bg)} .venn-card.missing b{color:var(--red)}
.venn-card.ad{background:var(--accent-light)} .venn-card.ad b{color:var(--accent)}
.venn-card span{display:block;color:var(--text-muted);font-size:.75rem;margin-top:4px}
#heatmapWrap{overflow:auto;max-height:70vh;background:var(--surface);border:1px solid var(--border);border-radius:14px}
#heatmapTable{border-collapse:separate;border-spacing:0;font-size:.72rem}
#heatmapTable th,#heatmapTable td{border-right:1px solid var(--border);border-bottom:1px solid var(--border);background:var(--surface)}
#heatmapTable th.gcol{writing-mode:vertical-rl;transform:rotate(180deg);height:140px;min-width:28px;max-width:34px;font-weight:600;color:var(--text-muted);text-transform:none;letter-spacing:0}
.hm-cell{width:18px;height:18px;border-radius:4px;margin:auto}
.hm-yes{background:var(--accent)} .hm-no{background:var(--surface3);border:1px solid var(--border)}
.sticky{position:sticky;left:0;z-index:2}
.page-footer{margin-left:var(--nav-width);padding:14px 28px 28px;color:var(--text-muted);font-size:.75rem}
.linkish{background:none;border:0;color:var(--accent);cursor:pointer;padding:0;font-weight:700}
@media (max-width:900px){
  body{padding-top:var(--top-h)}
  .brand p,.toggle-long,.topbar-spacer{display:none}
  .toggle-short{display:inline}
  .topbar{gap:8px;padding:0 10px}
  .sidebar{position:sticky;top:var(--top-h);width:100%;height:auto;display:flex;gap:4px;overflow:auto;padding:8px;z-index:25}
  .nav-label{display:none} .nav-btn{width:auto;white-space:nowrap}
  .main,.page-footer{margin-left:0} .main{margin-top:0;padding:16px}
  .topbar-meta{display:none} .search input{min-width:0;width:100%}
  .toolbar .grow{width:100%}
}
@media print{
  .sidebar,.topbar,.toolbar,.page-footer .noprint{display:none !important}
  .main,.page-footer{margin:0 !important} .tab-pane{display:block !important} .detail-row{display:table-row !important}
  .table-scroll{max-height:none;overflow:visible}
}
@media (prefers-reduced-motion:reduce){*{transition:none !important}}
</style>
</head>
<body>
<div id="errBanner" style="display:none;position:sticky;top:0;z-index:80;background:#991b1b;color:#fff;padding:10px 14px;white-space:pre-wrap"></div>
<header class="topbar">
  <div class="brand">
    <div class="brand-mark">AD</div>
    <div><h1>AD Account Analysis</h1><p id="brandSub"></p></div>
  </div>
  <div class="topbar-spacer"></div>
  <div class="topbar-meta" id="topbarMeta"></div>
  <label class="toggle" for="includeDisabled"><input id="includeDisabled" type="checkbox"/> <span id="disabledLabel" class="toggle-long">Include disabled accounts</span><span id="disabledShort" class="toggle-short">Disabled</span></label>
  <button type="button" class="theme-btn" data-action="theme" aria-label="Toggle color theme"><span class="icon-sun">Light</span><span class="icon-moon">Dark</span></button>
</header>
<nav class="sidebar" aria-label="Report sections">
  <div class="nav-label">Analysis</div>
  <button type="button" class="nav-btn active" data-action="show-tab" data-tab="overview"><span class="name">Overview</span></button>
  <button type="button" class="nav-btn" data-action="show-tab" data-tab="attributes"><span class="name">Common attributes</span><span class="badge" id="badge-attributes">0</span></button>
  <button type="button" class="nav-btn" data-action="show-tab" data-tab="common"><span class="name">Shared by all</span><span class="badge" id="badge-shared">0</span></button>
  <button type="button" class="nav-btn" data-action="show-tab" data-tab="threshold"><span class="name">Threshold</span><span class="badge" id="badge-threshold">0</span></button>
  <button type="button" class="nav-btn" data-action="show-tab" data-tab="heatmap"><span class="name">Matrix</span></button>
  <button type="button" class="nav-btn" id="navCompare" data-action="show-tab" data-tab="compare" hidden><span class="name">Comparison</span><span class="badge" id="badge-compare">0</span></button>
  <div class="nav-label">Accounts</div>
  <button type="button" class="nav-btn" data-action="show-tab" data-tab="users"><span class="name">Resolved users</span><span class="badge" id="badge-users">0</span></button>
  <button type="button" class="nav-btn" id="navNotFound" data-action="show-tab" data-tab="notfound" hidden><span class="name">Not found</span><span class="badge warn" id="badge-notfound">0</span></button>
</nav>
<main class="main">
  <section class="tab-pane active" id="tab-overview">
    <div class="page-head"><h2>Report overview</h2><p id="overviewLead"></p></div>
    <div class="cards" id="overviewCards"></div>
    <div id="overviewAlert"></div>
    <div class="note" id="overviewNote"></div>
    <div id="overviewAttributes"></div>
    <div id="overviewCompare"></div>
  </section>
  <section class="tab-pane" id="tab-attributes">
    <div class="page-head"><h2>Attributes and OUs in common</h2><p id="attributeLead"></p></div>
    <div id="attributeSummary"></div>
    <div class="page-head"><h2>Organizational units</h2><p id="ouLead"></p></div>
    <div class="table-card"><div class="table-scroll"><table id="tblOu"><thead><tr>
      <th data-action="sort" data-table="ous" data-sort="path">OU path <span class="si"></span></th>
      <th data-action="sort" data-table="ous" data-sort="dn">Distinguished name <span class="si"></span></th>
      <th data-action="sort" data-table="ous" data-sort="count">Users <span class="si"></span></th>
      <th data-action="sort" data-table="ous" data-sort="coverage">Coverage <span class="si"></span></th>
      <th>Accounts</th>
    </tr></thead><tbody id="tblOuBody"></tbody></table></div><div class="footer" id="footerOu"></div></div>
    <div class="page-head"><h2>Attribute values</h2><p>Blank values are ignored. An attribute can tie this list together only when every in-scope account has the same non-blank value.</p></div>
    <div class="toolbar"><div class="grow"><div class="search"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.3-4.3"/></svg><input id="searchAttrs" type="text" placeholder="Search attributes or values" aria-label="Search attributes"/></div>
      <div class="pills-row">
        <button type="button" class="filter-pill active" data-action="filter" data-group="attrs" data-value="all">All</button>
        <button type="button" class="filter-pill" data-action="filter" data-group="attrs" data-value="shared">Shared by everyone</button>
        <button type="button" class="filter-pill" data-action="filter" data-group="attrs" data-value="partial">Partial matches</button>
      </div>
    </div><button type="button" class="btn" data-action="export" data-kind="attributes">Export CSV</button><button type="button" class="btn primary" data-action="export" data-kind="attribute-matrix">Export user matrix</button></div>
    <div class="table-card"><div class="table-scroll"><table id="tblAttrs"><thead><tr>
      <th data-action="sort" data-table="attributes" data-sort="label">Attribute <span class="si"></span></th>
      <th data-action="sort" data-table="attributes" data-sort="section">Section <span class="si"></span></th>
      <th data-action="sort" data-table="attributes" data-sort="value">Most common value <span class="si"></span></th>
      <th data-action="sort" data-table="attributes" data-sort="count">Users <span class="si"></span></th>
      <th data-action="sort" data-table="attributes" data-sort="coverage">Coverage <span class="si"></span></th>
      <th data-action="sort" data-table="attributes" data-sort="distinct">Distinct <span class="si"></span></th>
      <th data-action="sort" data-table="attributes" data-sort="blanks">Blank <span class="si"></span></th>
    </tr></thead><tbody id="tblAttrBody"></tbody></table></div><div class="footer" id="footerAttrs"></div></div>
  </section>
  <section class="tab-pane" id="tab-common">
    <div class="page-head"><h2>Groups shared by all users</h2><p>Every account currently in scope is a direct member. The primary group is included.</p></div>
    <div class="toolbar"><div class="grow"><div class="search"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.3-4.3"/></svg><input id="searchAll" type="text" placeholder="Search groups or users" aria-label="Search groups shared by all"/></div></div><button type="button" class="btn primary" data-action="export" data-kind="common">Export CSV</button></div>
    <div class="table-card"><div class="table-scroll"><table id="tblAll"><thead><tr>
      <th data-action="sort" data-table="common" data-sort="name">Group <span class="si"></span></th>
      <th data-action="sort" data-table="common" data-sort="scope">Scope <span class="si"></span></th>
      <th data-action="sort" data-table="common" data-sort="category">Category <span class="si"></span></th>
      <th>Description</th><th>Users in this report</th>
    </tr></thead><tbody id="tblAllBody"></tbody></table></div><div class="footer" id="footerAll"></div></div>
  </section>
  <section class="tab-pane" id="tab-threshold">
    <div class="page-head"><h2>Threshold groups</h2><p id="thresholdLead"></p></div>
    <div class="toolbar"><div class="grow">
      <div class="search"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.3-4.3"/></svg><input id="searchThresh" type="text" placeholder="Search groups or users" aria-label="Search threshold groups"/></div>
      <label>Minimum users <input id="threshMin" type="number" min="1" step="1" value="2" aria-label="Minimum users sharing a group"/></label>
      <select id="scopeFilter" aria-label="Group scope"><option value="all">All scopes</option><option value="DomainLocal">Domain local</option><option value="Global">Global</option><option value="Universal">Universal</option></select>
      <div class="pills-row">
        <button type="button" class="filter-pill active" data-action="filter" data-group="category" data-value="all">All types</button>
        <button type="button" class="filter-pill" data-action="filter" data-group="category" data-value="Security">Security</button>
        <button type="button" class="filter-pill" data-action="filter" data-group="category" data-value="Distribution">Distribution</button>
        <button type="button" class="filter-pill" id="hideSharedPill" data-action="toggle-hide-shared">Hide shared by all</button>
      </div>
    </div><button type="button" class="btn primary" data-action="export" data-kind="threshold">Export CSV</button></div>
    <div class="table-card"><div class="table-scroll"><table id="tblThresh"><thead><tr>
      <th data-action="sort" data-table="threshold" data-sort="name">Group <span class="si"></span></th>
      <th data-action="sort" data-table="threshold" data-sort="scope">Scope <span class="si"></span></th>
      <th data-action="sort" data-table="threshold" data-sort="category">Category <span class="si"></span></th>
      <th data-action="sort" data-table="threshold" data-sort="count">Users <span class="si"></span></th>
      <th data-action="sort" data-table="threshold" data-sort="coverage">Coverage <span class="si"></span></th>
      <th>Users in this report</th>
    </tr></thead><tbody id="tblThreshBody"></tbody></table></div><div class="footer" id="footerThresh"></div></div>
  </section>
  <section class="tab-pane" id="tab-heatmap">
    <div class="page-head"><h2>Membership matrix</h2><p>A filled cell means that account is a member. Columns are paged so large group lists stay usable.</p></div>
    <div class="toolbar"><div class="grow">
      <div class="search"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.3-4.3"/></svg><input id="searchHeatmap" type="text" placeholder="Filter groups" aria-label="Filter matrix groups"/></div>
      <div class="search"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.3-4.3"/></svg><input id="searchHeatUsers" type="text" placeholder="Filter users" aria-label="Filter matrix users"/></div>
      <label>Columns per page <input id="hmPageSize" type="number" min="1" max="100" value="20" aria-label="Matrix columns per page"/></label>
    </div>
      <button type="button" class="btn" id="hmPrev" data-action="hm-page" data-delta="-1">Previous</button>
      <span id="hmPageLabel"></span>
      <button type="button" class="btn" id="hmNext" data-action="hm-page" data-delta="1">Next</button>
      <button type="button" class="btn primary" data-action="export" data-kind="matrix">Export CSV</button>
    </div>
    <div id="heatmapWrap"><table id="heatmapTable"></table></div>
  </section>
  <section class="tab-pane" id="tab-compare">
    <div class="page-head"><h2>Group comparison</h2><p id="compareLead"></p></div>
    <div class="venn" id="vennRow"></div>
    <div class="toolbar"><div class="grow">
      <div class="search"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.3-4.3"/></svg><input id="searchCompare" type="text" placeholder="Search comparison" aria-label="Search comparison"/></div>
      <div class="pills-row">
        <button type="button" class="filter-pill active" data-action="filter" data-group="compare" data-value="all">All</button>
        <button type="button" class="filter-pill" data-action="filter" data-group="compare" data-value="matched">Matched</button>
        <button type="button" class="filter-pill" data-action="filter" data-group="compare" data-value="no_members">No members in scope</button>
        <button type="button" class="filter-pill" data-action="filter" data-group="compare" data-value="not_in_ad">Not in AD</button>
        <button type="button" class="filter-pill" data-action="filter" data-group="compare" data-value="ad_only">AD only</button>
      </div>
    </div><button type="button" class="btn primary" data-action="export" data-kind="compare">Export CSV</button></div>
    <div class="table-card"><div class="table-scroll"><table id="tblCompare"><thead><tr>
      <th data-action="sort" data-table="compare" data-sort="name">Group <span class="si"></span></th>
      <th data-action="sort" data-table="compare" data-sort="status">Status <span class="si"></span></th>
      <th data-action="sort" data-table="compare" data-sort="scope">Scope <span class="si"></span></th>
      <th data-action="sort" data-table="compare" data-sort="category">Category <span class="si"></span></th>
      <th data-action="sort" data-table="compare" data-sort="count">Users <span class="si"></span></th>
      <th data-action="sort" data-table="compare" data-sort="coverage">Coverage <span class="si"></span></th>
      <th>Users in this report</th>
    </tr></thead><tbody id="tblCompareBody"></tbody></table></div><div class="footer" id="footerCompare"></div></div>
  </section>
  <section class="tab-pane" id="tab-users">
    <div class="page-head"><h2>Resolved users</h2><p id="usersLead"></p></div>
    <div class="toolbar"><div class="grow"><div class="search"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.3-4.3"/></svg><input id="searchUsers" type="text" placeholder="Search users or their groups" aria-label="Search users"/></div></div><button type="button" class="btn primary" data-action="export" data-kind="users">Export CSV</button></div>
    <div class="table-card"><div class="table-scroll"><table id="tblUsers"><thead><tr>
      <th data-action="sort" data-table="users" data-sort="sam">SamAccountName <span class="si"></span></th>
      <th data-action="sort" data-table="users" data-sort="display">Display name <span class="si"></span></th>
      <th data-action="sort" data-table="users" data-sort="email">Email <span class="si"></span></th>
      <th data-action="sort" data-table="users" data-sort="dept">Department <span class="si"></span></th>
      <th data-action="sort" data-table="users" data-sort="title">Title <span class="si"></span></th>
      <th data-action="sort" data-table="users" data-sort="enabled">Status <span class="si"></span></th>
      <th data-action="sort" data-table="users" data-sort="groups">Groups <span class="si"></span></th>
    </tr></thead><tbody id="tblUsersBody"></tbody></table></div><div class="footer" id="footerUsers"></div></div>
  </section>
  <section class="tab-pane" id="tab-notfound">
    <div class="page-head"><h2>Not found</h2><p id="notFoundLead"></p></div>
    <div class="toolbar"><div class="grow"></div><button type="button" class="btn primary" data-action="export" data-kind="notfound">Export CSV</button></div>
    <div class="table-card"><div class="table-scroll"><table><thead><tr><th>Name from the CSV</th><th>Status</th></tr></thead><tbody id="notFoundBody"></tbody></table></div></div>
  </section>
</main>
<footer class="page-footer" id="pageFooter"></footer>
<script>
var REPORT = __REPORT_JSON__;
var sortState = {
  common: { key: 'name', dir: 1 },
  threshold: { key: 'count', dir: -1 },
  compare: { key: 'status', dir: 1 },
  users: { key: 'sam', dir: 1 },
  attributes: { key: 'coverage', dir: -1 },
  ous: { key: 'path', dir: 1 }
};
var filters = { category: 'all', hideShared: false, compare: 'all', attrs: 'all' };
var latestAttributeSummary = { rows: [], shared: [], ous: [], commonOu: '' };
var memberStore = {};
var hmPage = 0;
var activeUserCount = 0;

function asArray(value) {
  if (value == null) return [];
  if (Object.prototype.toString.call(value) === '[object Array]') return value;
  return [value];
}
function esc(value) {
  if (value == null) return '';
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function showErr(label, err) {
  var message = '[AD Report] ' + label + ' failed: ' + (err && err.message ? err.message : err);
  if (window.console && console.error) console.error(message, err);
  var banner = document.getElementById('errBanner');
  if (banner) { banner.style.display = 'block'; banner.textContent += message + '\n'; }
}
function safeRun(label, fn) { try { fn(); } catch (err) { showErr(label, err); } }
function valueOf(id) {
  var el = document.getElementById(id);
  return el ? el.value : '';
}
function loadTheme() { try { return localStorage.getItem('ad-group-report-theme'); } catch (e) { return null; } }
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme === 'dark' ? 'dark' : 'light');
  try { localStorage.setItem('ad-group-report-theme', theme === 'dark' ? 'dark' : 'light'); } catch (e) {}
}
function showTab(id) {
  var panes = document.querySelectorAll('.tab-pane');
  var buttons = document.querySelectorAll('.nav-btn');
  for (var i = 0; i < panes.length; i++) panes[i].classList.remove('active');
  for (var j = 0; j < buttons.length; j++) buttons[j].classList.remove('active');
  var pane = document.getElementById('tab-' + id);
  if (pane) pane.classList.add('active');
  for (var k = 0; k < buttons.length; k++) {
    if (buttons[k].getAttribute('data-tab') === id) buttons[k].classList.add('active');
  }
}
function compareValues(a, b, dir) {
  if (typeof a === 'number' && typeof b === 'number') return (a - b) * dir;
  return String(a == null ? '' : a).localeCompare(String(b == null ? '' : b)) * dir;
}
function sortRows(rows, table) {
  var state = sortState[table];
  rows.sort(function(a, b) {
    var primary = compareValues(sortValue(table, state.key, a), sortValue(table, state.key, b), state.dir);
    if (primary !== 0) return primary;
    return compareValues(a.name || a.sam || '', b.name || b.sam || '', 1);
  });
}
function sortValue(table, key, row) {
  if (table === 'attributes') {
    if (key === 'label') return row.label || '';
    if (key === 'section') return row.section || '';
    if (key === 'value') return row.topValue || '';
    if (key === 'distinct') return row.distinct || 0;
    if (key === 'blanks') return row.blanks || 0;
    if (key === 'count' || key === 'coverage') return row.count || 0;
  }
  if (table === 'ous') {
    if (key === 'dn') return row.dn || '';
    if (key === 'path') return row.path || '';
    if (key === 'count' || key === 'coverage') return row.count || 0;
  }
  if (table === 'users') {
    if (key === 'sam') return row.sam || '';
    if (key === 'display') return row.display || '';
    if (key === 'email') return row.email || '';
    if (key === 'dept') return row.dept || '';
    if (key === 'title') return row.title || '';
    if (key === 'enabled') return row.enabled === true ? 1 : (row.enabled === false ? 0 : -1);
    if (key === 'groups') return asArray(row.groups).length;
  }
  if (key === 'count' || key === 'coverage') return row.count || 0;
  if (key === 'status') return row.status || '';
  if (key === 'scope') return row.scope || '';
  if (key === 'category') return row.category || '';
  return row.name || '';
}
function markSortHeaders() {
  var headers = document.querySelectorAll('th[data-sort]');
  for (var i = 0; i < headers.length; i++) {
    var th = headers[i];
    th.classList.remove('s-asc', 's-desc');
    th.removeAttribute('aria-sort');
    var state = sortState[th.getAttribute('data-table')];
    if (state && state.key === th.getAttribute('data-sort')) {
      th.classList.add(state.dir === 1 ? 's-asc' : 's-desc');
      th.setAttribute('aria-sort', state.dir === 1 ? 'ascending' : 'descending');
    }
  }
}
function matchesQuery(row, query) {
  if (!query) return true;
  var fields = [row.name, row.sam, row.description, row.dn, row.display, row.email, row.dept, row.title, row.listName];
  for (var i = 0; i < fields.length; i++) {
    if (fields[i] && String(fields[i]).toLowerCase().indexOf(query) >= 0) return true;
  }
  var members = asArray(row.members);
  for (var m = 0; m < members.length; m++) {
    if (String(members[m]).toLowerCase().indexOf(query) >= 0) return true;
  }
  return false;
}
function ouLabel(dn) {
  var idx = String(dn).indexOf(',');
  return idx >= 0 ? dn.substring(idx + 1) : dn;
}
function scopeChip(scope) {
  var cls = 'chip-neutral';
  if (scope === 'DomainLocal') cls = 'chip-cyan';
  else if (scope === 'Global') cls = 'chip-indigo';
  else if (scope === 'Universal') cls = 'chip-purple';
  return '<span class="chip ' + cls + '">' + esc(scope || '\u2014') + '</span>';
}
function catChip(cat) {
  var cls = cat === 'Security' ? 'chip-indigo' : (cat === 'Distribution' ? 'chip-amber' : 'chip-neutral');
  return '<span class="chip ' + cls + '">' + esc(cat || '\u2014') + '</span>';
}
function statusChip(status) {
  if (status === 'matched') return '<span class="chip chip-green">Matched</span>';
  if (status === 'no_members') return '<span class="chip chip-amber">No members in scope</span>';
  if (status === 'not_in_ad') return '<span class="chip chip-red">Not in AD</span>';
  if (status === 'ad_only') return '<span class="chip chip-indigo">AD only</span>';
  return '<span class="chip chip-neutral">' + esc(status || '\u2014') + '</span>';
}
function enabledChip(enabled) {
  if (enabled === true) return '<span class="chip chip-green">Enabled</span>';
  if (enabled === false) return '<span class="chip chip-red">Disabled</span>';
  return '<span class="chip chip-neutral">Unknown</span>';
}
function coverageHtml(count) {
  var pct = activeUserCount > 0 ? Math.round((count / activeUserCount) * 100) : 0;
  var tone = pct >= 100 ? 'green' : (pct >= 50 ? 'accent' : (pct >= 25 ? 'amber' : 'red'));
  return '<div class="prog-wrap"><div class="prog-track"><div class="prog-fill tone-' + tone + '" style="width:' + pct + '%"></div></div><span class="prog-pct">' + pct + '%</span></div>';
}
function pillsPreview(members, key) {
  members = asArray(members);
  if (!members.length) return '<span class="muted">None in this report</span>';
  var html = '';
  var shown = Math.min(8, members.length);
  for (var i = 0; i < shown; i++) html += '<span class="pill">' + esc(members[i]) + '</span>';
  if (members.length > shown) html += '<button type="button" class="pill-more" data-action="toggle-detail" data-detail="' + key + '">+' + (members.length - shown) + ' more</button>';
  return html;
}
function nameCell(row, key) {
  var html = '<div class="name-cell"><button type="button" class="exp-btn" data-action="toggle-detail" data-exp="' + key + '" data-detail="' + key + '" aria-expanded="false" aria-label="Show members">&#9656;</button><div class="name-stack"><strong>' + esc(row.name) + '</strong>';
  if (row.allUsers) html += ' <span class="chip chip-green">All</span>';
  if (row.duplicate) html += ' <span class="chip chip-amber">Duplicate name</span>';
  if (row.sam && String(row.sam).toLowerCase() !== String(row.name || '').toLowerCase()) html += '<div class="sub">sAMAccountName: ' + esc(row.sam) + '</div>';
  if (row.duplicate && row.dn) html += '<div class="sub">' + esc(ouLabel(row.dn)) + '</div>';
  if (row.listName && String(row.listName).toLowerCase() !== String(row.name || '').toLowerCase()) html += '<div class="sub">Reference list: ' + esc(row.listName) + '</div>';
  return html + '</div></div>';
}
function detailHtml(key, row, colspan) {
  var description = row.description ? '<span class="desc-cell">' + esc(row.description) + '</span>' : '<span class="muted">None</span>';
  var dn = row.dn ? '<span class="mono">' + esc(row.dn) + '</span>' : '<span class="muted">Not found in Active Directory</span>';
  var copy = row.dn ? '<button type="button" class="btn" data-action="copy" data-copy="' + esc(row.dn) + '">Copy DN</button>' : '';
  return '<tr class="detail-row" id="detail-' + key + '"><td class="detail-cell" colspan="' + colspan + '"><div class="detail-grid">'
    + '<div class="detail-item"><label>Distinguished name</label><div>' + dn + '</div></div>'
    + '<div class="detail-item"><label>Description</label><div>' + description + '</div></div>'
    + '<div class="detail-item"><label>Scope</label><div>' + esc(row.scope || '\u2014') + '</div></div>'
    + '<div class="detail-item"><label>Category</label><div>' + esc(row.category || '\u2014') + '</div></div>'
    + '<div class="detail-item detail-wide"><label>Users in this report (' + asArray(row.members).length + ')</label><div class="detail-members-body"></div>' + copy + '</div>'
    + '</div></td></tr>';
}
function renderGroupTable(bodyId, footerId, rows, columns, prefix, emptyText) {
  var body = document.getElementById(bodyId);
  if (!rows.length) {
    body.innerHTML = '<tr class="empty-row"><td colspan="' + columns.length + '">' + esc(emptyText) + '</td></tr>';
    document.getElementById(footerId).textContent = '0 groups';
    return;
  }
  var html = [];
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    var key = prefix + '-' + i;
    memberStore[key] = asArray(row.members);
    html.push('<tr>');
    for (var c = 0; c < columns.length; c++) html.push('<td>' + groupCell(columns[c], row, key) + '</td>');
    html.push('</tr>');
    html.push(detailHtml(key, row, columns.length));
  }
  body.innerHTML = html.join('');
  document.getElementById(footerId).textContent = rows.length + (rows.length === 1 ? ' group' : ' groups');
}
function groupCell(kind, row, key) {
  if (kind === 'name') return nameCell(row, key);
  if (kind === 'scope') return scopeChip(row.scope);
  if (kind === 'category') return catChip(row.category);
  if (kind === 'description') return '<span class="desc-cell">' + esc(row.description || '') + '</span>';
  if (kind === 'members') return '<div class="pills">' + pillsPreview(row.members, key) + '</div>';
  if (kind === 'count') {
    if (row.status === 'not_in_ad') return '<span class="muted">\u2014</span>';
    return '<span class="count-text">' + row.count + '/' + activeUserCount + '</span>';
  }
  if (kind === 'coverage') {
    if (row.status === 'not_in_ad') return '<span class="muted">\u2014</span>';
    return coverageHtml(row.count || 0);
  }
  if (kind === 'status') return statusChip(row.status);
  return '';
}
function compute() {
  var includeDisabled = document.getElementById('includeDisabled').checked;
  var minRaw = parseInt(document.getElementById('threshMin').value, 10);
  var minCount = (!isNaN(minRaw) && minRaw > 0) ? minRaw : 1;
  var sourceUsers = asArray(REPORT.users);
  var users = [];
  var disabledCount = 0;
  for (var i = 0; i < sourceUsers.length; i++) {
    if (sourceUsers[i].enabled === false) disabledCount++;
    if (includeDisabled || sourceUsers[i].enabled === true) users.push(sourceUsers[i]);
  }
  var memberMap = Object.create(null);
  for (var u = 0; u < users.length; u++) {
    var seen = Object.create(null);
    var dns = asArray(users[u].groups);
    for (var g = 0; g < dns.length; g++) {
      var dn = dns[g];
      if (!dn || seen[dn]) continue;
      seen[dn] = true;
      if (!memberMap[dn]) memberMap[dn] = [];
      memberMap[dn].push(users[u].sam);
    }
  }
  var meta = REPORT.groupMeta || {};
  var rows = [];
  var nameCounts = Object.create(null);
  for (var key in meta) {
    if (!Object.prototype.hasOwnProperty.call(meta, key)) continue;
    var members = memberMap[key] ? memberMap[key].slice() : [];
    if (!members.length) continue;
    members.sort();
    var info = meta[key] || {};
    var row = {
      dn: key, name: info.name || key, sam: info.sam || '', scope: info.scope || '',
      category: info.category || '', description: info.description || '', members: members,
      count: members.length, allUsers: users.length > 0 && members.length === users.length, duplicate: false, status: ''
    };
    rows.push(row);
    var nameKey = row.name.toLowerCase();
    nameCounts[nameKey] = (nameCounts[nameKey] || 0) + 1;
  }
  for (var r = 0; r < rows.length; r++) rows[r].duplicate = nameCounts[rows[r].name.toLowerCase()] > 1;
  var shared = [];
  var threshold = [];
  for (var s = 0; s < rows.length; s++) {
    if (rows[s].allUsers) shared.push(rows[s]);
    if (rows[s].count >= minCount) threshold.push(rows[s]);
  }
  return {
    users: users, rows: rows, shared: shared, threshold: threshold, minCount: minCount,
    inScope: users.length, disabledCount: disabledCount, memberMap: memberMap, meta: meta,
    compare: buildCompare(rows, memberMap, meta, users.length)
  };
}
function buildCompare(rows, memberMap, meta, userCount) {
  var result = { enabled: !!(REPORT.compare && REPORT.compare.enabled), rows: [], matched: 0, noMembers: 0, missing: 0, adOnly: 0 };
  if (!result.enabled) return result;
  var claimed = Object.create(null);
  var entries = asArray(REPORT.compare.entries);
  for (var i = 0; i < entries.length; i++) {
    var entry = entries[i];
    var dns = asArray(entry.dns);
    if (!entry.exists || !dns.length) {
      result.missing++;
      result.rows.push({ name: entry.name, sam: '', dn: '', scope: '', category: '', description: '', members: [], count: 0, allUsers: false, duplicate: false, status: 'not_in_ad', listName: entry.name });
      continue;
    }
    for (var d = 0; d < dns.length; d++) {
      var dn = dns[d];
      claimed[dn] = true;
      var info = meta[dn] || {};
      var members = memberMap[dn] ? memberMap[dn].slice().sort() : [];
      var status = members.length ? 'matched' : 'no_members';
      if (status === 'matched') result.matched++; else result.noMembers++;
      result.rows.push({
        name: info.name || entry.name, sam: info.sam || '', dn: dn, scope: info.scope || '',
        category: info.category || '', description: info.description || '', members: members,
        count: members.length, allUsers: userCount > 0 && members.length === userCount,
        duplicate: false, status: status, listName: entry.name
      });
    }
  }
  var compareNameCounts = Object.create(null);
  for (var c = 0; c < result.rows.length; c++) {
    if (!result.rows[c].dn) continue;
    var nk = String(result.rows[c].name || '').toLowerCase();
    compareNameCounts[nk] = (compareNameCounts[nk] || 0) + 1;
  }
  for (var n = 0; n < rows.length; n++) {
    if (claimed[rows[n].dn]) continue;
    result.adOnly++;
    var copy = {
      name: rows[n].name, sam: rows[n].sam, dn: rows[n].dn, scope: rows[n].scope, category: rows[n].category,
      description: rows[n].description, members: rows[n].members, count: rows[n].count, allUsers: rows[n].allUsers,
      duplicate: rows[n].duplicate, status: 'ad_only', listName: ''
    };
    result.rows.push(copy);
    var adKey = String(copy.name || '').toLowerCase();
    compareNameCounts[adKey] = (compareNameCounts[adKey] || 0) + 1;
  }
  for (var m = 0; m < result.rows.length; m++) {
    if (result.rows[m].dn && compareNameCounts[String(result.rows[m].name || '').toLowerCase()] > 1) result.rows[m].duplicate = true;
  }
  return result;
}
function visibleCommon(model) {
  var query = valueOf('searchAll').toLowerCase();
  var rows = model.shared.filter(function(row) { return matchesQuery(row, query); });
  sortRows(rows, 'common');
  return rows;
}
function visibleThreshold(model) {
  var query = valueOf('searchThresh').toLowerCase();
  var scope = valueOf('scopeFilter') || 'all';
  var rows = model.threshold.filter(function(row) {
    if (filters.category !== 'all' && row.category !== filters.category) return false;
    if (filters.hideShared && row.allUsers) return false;
    if (scope !== 'all' && row.scope !== scope) return false;
    return matchesQuery(row, query);
  });
  sortRows(rows, 'threshold');
  return rows;
}
function visibleCompare(model) {
  var query = valueOf('searchCompare').toLowerCase();
  var rows = model.compare.rows.filter(function(row) {
    if (filters.compare !== 'all' && row.status !== filters.compare) return false;
    return matchesQuery(row, query);
  });
  sortRows(rows, 'compare');
  return rows;
}
function userGroupNames(user) {
  var names = [];
  var dns = asArray(user.groups);
  for (var i = 0; i < dns.length; i++) {
    var info = REPORT.groupMeta[dns[i]];
    names.push(info && info.name ? info.name : dns[i]);
  }
  names.sort();
  return names;
}
function visibleUsers(model) {
  var query = valueOf('searchUsers').toLowerCase();
  var rows = asArray(REPORT.users).filter(function(user) {
    if (!query) return true;
    if (matchesQuery(user, query)) return true;
    var names = userGroupNames(user);
    for (var i = 0; i < names.length; i++) {
      if (names[i].toLowerCase().indexOf(query) >= 0) return true;
    }
    return false;
  });
  sortRows(rows, 'users');
  return rows;
}
function attrValue(user, key) {
  if (!user || !user.attrs) return '';
  var value = user.attrs[key];
  if (value == null) return '';
  return String(value).trim();
}
function commonDirectoryPath(paths) {
  var lists = [];
  for (var i = 0; i < paths.length; i++) {
    var text = String(paths[i] || '').replace(/^\/+|\/+$/g, '');
    if (!text) continue;
    var parts = text.split('/');
    var clean = [];
    for (var p = 0; p < parts.length; p++) {
      if (parts[p]) clean.push(parts[p]);
    }
    if (clean.length) lists.push(clean);
  }
  if (!lists.length) return '';
  var count = lists[0].length;
  for (var n = 0; n < lists.length; n++) {
    var limit = Math.min(count, lists[n].length);
    var index = 0;
    while (index < limit && String(lists[0][index]).toLowerCase() === String(lists[n][index]).toLowerCase()) index++;
    count = index;
    if (!count) break;
  }
  if (!count) return '';
  return lists[0].slice(0, count).join('/');
}
function analyzeAttributes(users) {
  var catalog = asArray(REPORT.attributeCatalog);
  var rows = [];
  for (var i = 0; i < catalog.length; i++) {
    var def = catalog[i];
    var buckets = Object.create(null);
    var order = [];
    var blanks = 0;
    for (var u = 0; u < users.length; u++) {
      var value = attrValue(users[u], def.key);
      if (!value) { blanks++; continue; }
      var fold = value.toLowerCase();
      if (!buckets[fold]) {
        buckets[fold] = { value: value, users: [] };
        order.push(fold);
      }
      buckets[fold].users.push(users[u].sam);
    }
    if (!order.length) continue;
    var values = [];
    for (var b = 0; b < order.length; b++) values.push(buckets[order[b]]);
    values.sort(function(a, b) {
      if (b.users.length !== a.users.length) return b.users.length - a.users.length;
      return String(a.value).localeCompare(String(b.value));
    });
    var top = values[0];
    rows.push({
      key: def.key, label: def.label, section: def.section, name: def.label,
      values: values, blanks: blanks, count: top.users.length, distinct: values.length,
      topValue: top.value, shared: users.length > 0 && top.users.length === users.length
    });
  }
  var ouMap = Object.create(null);
  var ouOrder = [];
  var ouPaths = [];
  var missingOu = false;
  for (var n = 0; n < users.length; n++) {
    var path = attrValue(users[n], 'ouPath');
    var dn = attrValue(users[n], 'ouDn');
    if (!path) missingOu = true;
    else ouPaths.push(path);
    var ouKey = (path || dn || '').toLowerCase();
    if (!ouKey) continue;
    if (!ouMap[ouKey]) {
      ouMap[ouKey] = { path: path || dn, dn: dn, users: [] };
      ouOrder.push(ouKey);
    }
    ouMap[ouKey].users.push(users[n].sam);
  }
  var ous = [];
  for (var o = 0; o < ouOrder.length; o++) {
    var item = ouMap[ouOrder[o]];
    ous.push({ path: item.path, dn: item.dn, users: item.users, count: item.users.length, name: item.path });
  }
  return {
    rows: rows,
    shared: rows.filter(function(row) { return row.shared; }),
    ous: ous,
    commonOu: missingOu ? '' : commonDirectoryPath(ouPaths)
  };
}
function visibleAttributeRows(analysis) {
  var query = valueOf('searchAttrs').toLowerCase();
  var mode = filters.attrs || 'all';
  var rows = analysis.rows.filter(function(row) {
    if (mode === 'shared' && !row.shared) return false;
    if (mode === 'partial' && (row.shared || row.count < 2)) return false;
    if (!query) return true;
    var blob = (row.label + ' ' + row.section + ' ' + row.topValue).toLowerCase();
    return blob.indexOf(query) >= 0;
  });
  sortRows(rows, 'attributes');
  return rows;
}
function userPills(sams) {
  var sorted = asArray(sams).slice().sort();
  if (!sorted.length) return '<span class="muted">None</span>';
  var html = '<div class="pills">';
  for (var i = 0; i < sorted.length; i++) html += '<span class="pill">' + esc(sorted[i]) + '</span>';
  return html + '</div>';
}
function attributeDetailHtml(row) {
  var key = 'attr-' + row.key;
  var html = '<tr class="detail-row" id="detail-' + key + '"><td class="detail-cell" colspan="7"><div class="detail-grid">';
  for (var i = 0; i < row.values.length; i++) {
    var bucket = row.values[i];
    html += '<div><label>' + esc(bucket.value) + ' (' + bucket.users.length + ')</label>' + userPills(bucket.users) + '</div>';
  }
  if (row.blanks) html += '<div><label>Blank (' + row.blanks + ')</label><span class="muted">These accounts have no value, so they are not a match.</span></div>';
  return html + '</div></td></tr>';
}
function renderAttributes(model) {
  var analysis = latestAttributeSummary || analyzeAttributes(model.users);
  var shared = analysis.shared;
  var sentences = [];
  if (!model.inScope) sentences.push('No accounts are in scope.');
  else if (!shared.length) sentences.push('No attribute has the same non-blank value on every in-scope account. The closest matches are listed first.');
  else sentences.push('Every in-scope account has ' + shared.map(function(row) { return row.label + ' = ' + row.topValue; }).join('; ') + '.');
  if (analysis.commonOu && analysis.ous.length === 1) sentences.push('Every in-scope account is in ' + analysis.commonOu + '.');
  else if (analysis.commonOu) sentences.push('The deepest organizational unit that contains every in-scope account is ' + analysis.commonOu + '. They are spread across ' + analysis.ous.length + ' OUs.');
  else if (model.inScope) sentences.push('These accounts do not share one organizational unit path.');
  var lead = document.getElementById('attributeLead');
  if (lead) lead.textContent = 'Use this view to find a directory value that applies to the whole CSV. Blank values are not treated as a match.';
  var summary = document.getElementById('attributeSummary');
  if (summary) summary.innerHTML = '<div class="callout' + (shared.length ? ' ok' : '') + '">' + esc(sentences.join(' ')) + '</div>';
  var ouLead = document.getElementById('ouLead');
  if (ouLead) ouLead.textContent = analysis.commonOu ? ('Common ancestor: ' + analysis.commonOu) : 'No shared OU path for every account in scope.';
  var ouRows = analysis.ous.slice();
  sortRows(ouRows, 'ous');
  var ouBody = document.getElementById('tblOuBody');
  if (ouBody) {
    if (!ouRows.length) ouBody.innerHTML = '<tr class="empty-row"><td colspan="5">No organizational unit was available for the accounts in scope.</td></tr>';
    else {
      var ouHtml = [];
      for (var i = 0; i < ouRows.length; i++) {
        var ou = ouRows[i];
        ouHtml.push('<tr><td class="mono">' + esc(ou.path) + '</td><td class="mono">' + esc(ou.dn || '') + '</td><td>' + ou.count + '</td><td>' + coverageHtml(ou.count) + '</td><td>' + userPills(ou.users) + '</td></tr>');
      }
      ouBody.innerHTML = ouHtml.join('');
    }
  }
  var footerOu = document.getElementById('footerOu');
  if (footerOu) footerOu.textContent = ouRows.length + (ouRows.length === 1 ? ' OU' : ' OUs');
  var rows = visibleAttributeRows(analysis);
  var body = document.getElementById('tblAttrBody');
  if (body) {
    if (!rows.length) body.innerHTML = '<tr class="empty-row"><td colspan="7">No attributes match the current filter.</td></tr>';
    else {
      var html = [];
      for (var r = 0; r < rows.length; r++) {
        var row = rows[r];
        var key = 'attr-' + row.key;
        html.push('<tr><td><div class="name-cell"><button type="button" class="exp-btn" data-action="toggle-detail" data-exp="' + key + '" data-detail="' + key + '" aria-expanded="false" aria-label="Show values">&#9656;</button><div class="name-stack"><strong>' + esc(row.label) + '</strong>' + (row.shared ? ' <span class="chip chip-green">All</span>' : '') + '</div></div></td><td>' + esc(row.section) + '</td><td>' + esc(row.topValue) + '</td><td>' + row.count + '</td><td>' + coverageHtml(row.count) + '</td><td>' + row.distinct + '</td><td>' + row.blanks + '</td></tr>');
        html.push(attributeDetailHtml(row));
      }
      body.innerHTML = html.join('');
    }
  }
  var footer = document.getElementById('footerAttrs');
  if (footer) footer.textContent = rows.length + (rows.length === 1 ? ' attribute' : ' attributes');
  var badge = document.getElementById('badge-attributes');
  if (badge) badge.textContent = String(shared.length);
}
function statCard(key, label, value, sub, cls) {
  return '<article class="card ' + (cls || '') + '" data-stat="' + esc(key) + '"><div class="card-label">' + esc(label) + '</div><div class="card-value">' + esc(String(value)) + '</div><div class="card-sub">' + esc(sub) + '</div></article>';
}
function renderOverview(model) {
  var cards = [
    statCard('input', 'Input accounts', REPORT.inputCount, 'Unique names from the CSV', ''),
    statCard('resolved', 'Resolved in AD', asArray(REPORT.users).length, 'Accounts that were found', 'c-green'),
    statCard('scope', 'In scope', model.inScope, model.inScope === 1 ? 'Account in the calculation' : 'Accounts in the calculation', 'c-cyan'),
    statCard('notfound', 'Not found', asArray(REPORT.notFound).length, 'Excluded from sharing', 'c-red'),
    statCard('groups', 'Distinct groups', model.rows.length, 'Groups with someone in scope', ''),
    statCard('shared', 'Shared by all', model.shared.length, 'Common to every in-scope account', 'c-cyan'),
    statCard('attributes', 'Shared attributes', latestAttributeSummary.shared.length, 'Same non-blank value for everyone in scope', 'c-green'),
    statCard('threshold', 'Threshold groups', model.threshold.length, 'Shared by at least ' + model.minCount, 'c-purple')
  ];
  if (model.compare.enabled) {
    cards.push(statCard('matched', 'Matched', model.compare.matched, 'Reference groups with members', 'c-green'));
    cards.push(statCard('nomembers', 'No members in scope', model.compare.noMembers, 'Exists in AD, nobody in scope', 'c-amber'));
    cards.push(statCard('missing', 'Not in AD', model.compare.missing, 'Reference name was not found', 'c-red'));
    cards.push(statCard('adonly', 'AD only', model.compare.adOnly, 'In the results, not in the list', ''));
  }
  document.getElementById('overviewCards').innerHTML = cards.join('');
  var overviewLead = asArray(REPORT.users).length + ' of ' + REPORT.inputCount + ' input accounts were resolved. ' + model.inScope + ' are included in the sharing totals.';
  if (REPORT.userColumn) overviewLead += ' Accounts were matched from the "' + REPORT.userColumn + '" column.';
  document.getElementById('overviewLead').textContent = overviewLead;
  var alert = document.getElementById('overviewAlert');
  var missingCount = asArray(REPORT.notFound).length;
  if (missingCount) {
    var missingWord = missingCount === 1 ? 'name was' : 'names were';
    alert.innerHTML = '<div class="callout warn">' + missingCount + ' ' + missingWord + ' not found and ' + (missingCount === 1 ? 'is' : 'are') + ' excluded. <button type="button" class="linkish" data-action="show-tab" data-tab="notfound">Review them</button></div>';
  } else alert.innerHTML = '';
  var mode = REPORT.recursive ? 'Nested membership is included, plus each account primary group.' : 'Direct membership is included, plus each account primary group. Domain Users is usually only the primary group, so it is part of this report. Nested groups are omitted unless the report was generated with -Recursive.';
  document.getElementById('overviewNote').textContent = mode + ' The users shown beside a group are the accounts in this report, not the full Active Directory membership.';
  var tieHost = document.getElementById('overviewAttributes');
  if (tieHost) {
    var tieText = latestAttributeSummary.shared.length
      ? (latestAttributeSummary.shared.length + ' attribute' + (latestAttributeSummary.shared.length === 1 ? '' : 's') + ' match on every account in scope.')
      : 'No attribute is the same for every account in scope.';
    if (latestAttributeSummary.commonOu) tieText += ' Deepest shared OU: ' + latestAttributeSummary.commonOu + '.';
    tieHost.innerHTML = '<div class="callout">' + esc(tieText) + ' <button type="button" class="linkish" data-action="show-tab" data-tab="attributes">Compare attributes and OUs</button></div>';
  }
  var compareHost = document.getElementById('overviewCompare');
  if (model.compare.enabled) {
    compareHost.innerHTML = '<div class="page-head"><h2>Comparison</h2><p>Reference file: ' + esc(REPORT.groupsCsv || 'reference list') + '</p></div>' + vennHtml(model.compare);
  } else compareHost.innerHTML = '';
  document.getElementById('thresholdLead').textContent = 'Groups shared by at least ' + model.minCount + ' of the ' + model.inScope + ' accounts in scope.';
  var resolvedCount = asArray(REPORT.users).length;
  document.getElementById('usersLead').textContent = resolvedCount + (resolvedCount === 1 ? ' resolved account. ' : ' resolved accounts. ') + model.inScope + (model.inScope === 1 ? ' is included in the sharing totals.' : ' are included in the sharing totals.');
  document.getElementById('disabledLabel').textContent = model.disabledCount ? ('Include disabled accounts (' + model.disabledCount + ')') : 'Include disabled accounts';
  document.getElementById('disabledShort').textContent = model.disabledCount ? ('Disabled (' + model.disabledCount + ')') : 'Disabled';
}
function vennHtml(compare) {
  return '<div class="venn">'
    + '<div class="venn-card matched"><b>' + compare.matched + '</b><span>Matched. In the list and at least one in-scope account is a member.</span></div>'
    + '<div class="venn-card none"><b>' + compare.noMembers + '</b><span>In Active Directory, but nobody currently in scope is a member.</span></div>'
    + '<div class="venn-card missing"><b>' + compare.missing + '</b><span>On the reference list, but no group with that name or sAMAccountName was found.</span></div>'
    + '<div class="venn-card ad"><b>' + compare.adOnly + '</b><span>Found from these accounts and absent from the reference list.</span></div>'
    + '</div>';
}
function renderCommon(model) {
  renderGroupTable('tblAllBody', 'footerAll', visibleCommon(model), ['name', 'scope', 'category', 'description', 'members'], 'all', 'No group is shared by every account in scope.');
}
function renderThreshold(model) {
  renderGroupTable('tblThreshBody', 'footerThresh', visibleThreshold(model), ['name', 'scope', 'category', 'count', 'coverage', 'members'], 'th', 'No groups match the current threshold and filters.');
}
function renderCompare(model) {
  var section = document.getElementById('tab-compare');
  var nav = document.getElementById('navCompare');
  nav.hidden = !model.compare.enabled;
  if (!model.compare.enabled) { section.classList.remove('active'); return; }
  document.getElementById('compareLead').textContent = 'Reference names are matched to group CN and sAMAccountName, ignoring case. Duplicate CNs stay separate.';
  document.getElementById('vennRow').innerHTML = vennHtml(model.compare);
  renderGroupTable('tblCompareBody', 'footerCompare', visibleCompare(model), ['name', 'status', 'scope', 'category', 'count', 'coverage', 'members'], 'cmp', 'No groups match the current comparison filter.');
}
function renderUsers(model) {
  var rows = visibleUsers(model);
  var body = document.getElementById('tblUsersBody');
  if (!rows.length) {
    body.innerHTML = '<tr class="empty-row"><td colspan="7">No resolved users match the current filter.</td></tr>';
    document.getElementById('footerUsers').textContent = '0 users';
    return;
  }
  var html = [];
  for (var i = 0; i < rows.length; i++) {
    var user = rows[i];
    var names = userGroupNames(user);
    var key = 'user-' + i;
    memberStore[key] = names;
    var email = user.email && /^[^\s<>"']+@[^\s<>"']+$/.test(user.email) ? '<a href="mailto:' + esc(user.email) + '">' + esc(user.email) + '</a>' : esc(user.email || '\u2014');
    html.push('<tr><td class="mono">' + esc(user.sam) + '</td><td>' + esc(user.display) + '</td><td>' + email + '</td><td>' + esc(user.dept) + '</td><td>' + esc(user.title) + '</td><td>' + enabledChip(user.enabled) + '</td><td><div class="name-cell"><button type="button" class="exp-btn" data-action="toggle-detail" data-exp="' + key + '" data-detail="' + key + '" aria-expanded="false" aria-label="Show groups">&#9656;</button><strong class="count-text">' + names.length + '</strong></div></td></tr>');
    html.push('<tr class="detail-row" id="detail-' + key + '"><td class="detail-cell" colspan="7"><div class="detail-wide"><label>Groups in this report (' + names.length + ')</label><div class="detail-members-body"></div></div></td></tr>');
  }
  body.innerHTML = html.join('');
  document.getElementById('footerUsers').textContent = rows.length + (rows.length === 1 ? ' user' : ' users');
}
function renderNotFound() {
  var names = asArray(REPORT.notFound);
  var nav = document.getElementById('navNotFound');
  nav.hidden = names.length === 0;
  document.getElementById('badge-notfound').textContent = String(names.length);
  document.getElementById('notFoundLead').textContent = names.length ? 'These CSV values did not resolve to an Active Directory account.' : 'Every CSV value resolved.';
  var body = document.getElementById('notFoundBody');
  if (!names.length) { body.innerHTML = '<tr class="empty-row"><td colspan="2">None.</td></tr>'; return; }
  var html = [];
  for (var i = 0; i < names.length; i++) html.push('<tr><td class="mono">' + esc(names[i]) + '</td><td><span class="chip chip-red">Not found</span></td></tr>');
  body.innerHTML = html.join('');
}
function renderHeatmap(model) {
  var groupQuery = valueOf('searchHeatmap').toLowerCase();
  var userQuery = valueOf('searchHeatUsers').toLowerCase();
  var groups = model.rows.filter(function(row) {
    if (!groupQuery) return true;
    return row.name.toLowerCase().indexOf(groupQuery) >= 0 || String(row.sam || '').toLowerCase().indexOf(groupQuery) >= 0;
  });
  groups.sort(function(a, b) { return String(a.name).localeCompare(String(b.name)); });
  var users = model.users.filter(function(user) {
    if (!userQuery) return true;
    return String(user.sam).toLowerCase().indexOf(userQuery) >= 0 || String(user.display || '').toLowerCase().indexOf(userQuery) >= 0;
  });
  var pageSize = parseInt(valueOf('hmPageSize'), 10);
  if (isNaN(pageSize) || pageSize < 1) pageSize = 20;
  if (pageSize > 100) pageSize = 100;
  var pages = Math.max(1, Math.ceil(groups.length / pageSize));
  if (hmPage > pages - 1) hmPage = pages - 1;
  if (hmPage < 0) hmPage = 0;
  var start = hmPage * pageSize;
  var page = groups.slice(start, start + pageSize);
  document.getElementById('hmPageLabel').textContent = groups.length ? ('Page ' + (hmPage + 1) + ' of ' + pages + ' (' + groups.length + ' groups)') : 'No groups';
  document.getElementById('hmPrev').disabled = hmPage <= 0 || !groups.length;
  document.getElementById('hmNext').disabled = hmPage >= pages - 1 || !groups.length;
  var table = document.getElementById('heatmapTable');
  if (!page.length || !users.length) {
    table.innerHTML = '<tbody><tr><td style="padding:28px;color:var(--text-muted)">Nothing matches the current matrix filter.</td></tr></tbody>';
    return;
  }
  var html = '<thead><tr><th class="sticky">User</th>';
  for (var g = 0; g < page.length; g++) html += '<th class="gcol" title="' + esc(page[g].name + ' \u2014 ' + page[g].dn) + '">' + esc(page[g].name) + '</th>';
  html += '</tr></thead><tbody>';
  for (var u = 0; u < users.length; u++) {
    var owned = Object.create(null);
    var dns = asArray(users[u].groups);
    for (var d = 0; d < dns.length; d++) owned[dns[d]] = true;
    html += '<tr><td class="mono sticky">' + esc(users[u].sam) + '</td>';
    for (var c = 0; c < page.length; c++) {
      var yes = !!owned[page[c].dn];
      html += '<td title="' + esc(users[u].sam + (yes ? ' is in ' : ' is not in ') + page[c].name) + '"><div class="hm-cell ' + (yes ? 'hm-yes' : 'hm-no') + '"></div></td>';
    }
    html += '</tr>';
  }
  table.innerHTML = html + '</tbody>';
}
function updateChrome(model) {
  document.getElementById('badge-shared').textContent = String(model.shared.length);
  document.getElementById('badge-threshold').textContent = String(model.threshold.length);
  document.getElementById('badge-users').textContent = String(asArray(REPORT.users).length);
  document.getElementById('badge-compare').textContent = model.compare.enabled ? String(model.compare.matched) : '0';
  var meta = [];
  if (REPORT.generated) meta.push(REPORT.generated);
  if (REPORT.domain) meta.push(REPORT.domain);
  if (REPORT.server) meta.push(REPORT.server);
  if (REPORT.usersCsv) meta.push('Users: ' + REPORT.usersCsv);
  if (REPORT.userColumn) meta.push('Column: ' + REPORT.userColumn);
  if (REPORT.groupsCsv) meta.push('Groups: ' + REPORT.groupsCsv);
  document.getElementById('topbarMeta').innerHTML = esc(meta.join('  |  ')).replace(/ \| /g, '<br>');
  document.getElementById('brandSub').textContent = (REPORT.scriptName || 'Find-CommonADGroups.ps1') + (REPORT.recursive ? '  |  Nested + primary group' : '  |  Direct + primary group');
  document.getElementById('pageFooter').textContent = 'AD Account Analysis  |  ' + (REPORT.generated || '') + '  |  ' + REPORT.inputCount + ' input, ' + asArray(REPORT.users).length + ' resolved';
  markSortHeaders();
}
function renderAll() {
  memberStore = {};
  var model = null;
  safeRun('compute', function() { model = compute(); });
  if (!model) return;
  activeUserCount = model.inScope;
  latestAttributeSummary = analyzeAttributes(model.users);
  safeRun('overview', function() { renderOverview(model); });
  safeRun('attributes', function() { renderAttributes(model); });
  safeRun('common', function() { renderCommon(model); });
  safeRun('threshold', function() { renderThreshold(model); });
  safeRun('compare', function() { renderCompare(model); });
  safeRun('users', function() { renderUsers(model); });
  safeRun('notfound', renderNotFound);
  safeRun('heatmap', function() { renderHeatmap(model); });
  safeRun('chrome', function() { updateChrome(model); });
  window.__reportModel = {
    inScope: model.inScope, shared: model.shared.length, threshold: model.threshold.length,
    groups: model.rows.length, matched: model.compare.matched, noMembers: model.compare.noMembers,
    missing: model.compare.missing, adOnly: model.compare.adOnly,
    attributeShared: latestAttributeSummary.shared.length, commonOu: latestAttributeSummary.commonOu
  };
}
function csvField(value) {
  return '"' + String(value == null ? '' : value).replace(/"/g, '""') + '"';
}
function downloadCsv(name, lines) {
  var blob = new Blob(['\ufeff' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
  var url = URL.createObjectURL(blob);
  var link = document.createElement('a');
  link.href = url;
  link.download = name + '_' + new Date().toISOString().slice(0, 10) + '.csv';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
function exportGroups(rows, name, includeStatus) {
  var header = ['GroupName', 'SamAccountName', 'Scope', 'Category', 'UserCount', 'CoveragePercent', 'SharedByAll', 'Members', 'Description', 'DistinguishedName'];
  if (includeStatus) header.splice(1, 0, 'Status');
  var lines = [header.map(csvField).join(',')];
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    var pct = activeUserCount > 0 ? Math.round((row.count / activeUserCount) * 100) : 0;
    var values = [row.name, row.sam, row.scope, row.category, row.count, pct, row.allUsers ? 'Yes' : 'No', asArray(row.members).join('; '), row.description, row.dn];
    if (includeStatus) values.splice(1, 0, row.status || '');
    lines.push(values.map(csvField).join(','));
  }
  downloadCsv(name, lines);
}
function exportCurrent(kind) {
  var model = compute();
  activeUserCount = model.inScope;
  if (kind === 'common') exportGroups(visibleCommon(model), 'shared_by_all', false);
  else if (kind === 'threshold') exportGroups(visibleThreshold(model), 'threshold_groups', false);
  else if (kind === 'compare') exportGroups(visibleCompare(model), 'group_comparison', true);
  else if (kind === 'users') {
    var rows = visibleUsers(model);
    var lines = [['SamAccountName', 'DisplayName', 'Email', 'Department', 'Title', 'Enabled', 'GroupCount', 'Groups'].map(csvField).join(',')];
    for (var i = 0; i < rows.length; i++) {
      var user = rows[i];
      var names = userGroupNames(user);
      lines.push([user.sam, user.display, user.email, user.dept, user.title, user.enabled === true ? 'Enabled' : (user.enabled === false ? 'Disabled' : 'Unknown'), names.length, names.join('; ')].map(csvField).join(','));
    }
    downloadCsv('resolved_users', lines);
  }
  else if (kind === 'notfound') {
    var names = asArray(REPORT.notFound);
    var missing = [['SamAccountName', 'Status'].map(csvField).join(',')];
    for (var n = 0; n < names.length; n++) missing.push([names[n], 'Not found'].map(csvField).join(','));
    downloadCsv('not_found', missing);
  }
  else if (kind === 'attributes') {
    var analysis = analyzeAttributes(model.users);
    var attrRows = visibleAttributeRows(analysis);
    var attrLines = [['Attribute', 'Section', 'MostCommonValue', 'UserCount', 'InScope', 'CoveragePercent', 'DistinctValues', 'BlankCount', 'SharedByAll', 'ValueBreakdown'].map(csvField).join(',')];
    for (var a = 0; a < attrRows.length; a++) {
      var attr = attrRows[a];
      var pct = model.inScope > 0 ? Math.round((attr.count / model.inScope) * 100) : 0;
      var breakdown = attr.values.map(function(bucket) { return bucket.value + ' (' + bucket.users.length + ': ' + bucket.users.join(', ') + ')'; }).join('; ');
      attrLines.push([attr.label, attr.section, attr.topValue, attr.count, model.inScope, pct, attr.distinct, attr.blanks, attr.shared ? 'Yes' : 'No', breakdown].map(csvField).join(','));
    }
    downloadCsv('common_attributes', attrLines);
  }
  else if (kind === 'attribute-matrix') {
    var matrixAnalysis = analyzeAttributes(model.users);
    var matrixHeader = ['SamAccountName', 'DisplayName', 'Enabled'].concat(matrixAnalysis.rows.map(function(row) { return row.label; }));
    var matrixLines = [matrixHeader.map(csvField).join(',')];
    for (var mu = 0; mu < model.users.length; mu++) {
      var account = model.users[mu];
      var matrixValues = [account.sam, account.display, account.enabled === true ? 'Enabled' : (account.enabled === false ? 'Disabled' : 'Unknown')];
      for (var mc = 0; mc < matrixAnalysis.rows.length; mc++) matrixValues.push(attrValue(account, matrixAnalysis.rows[mc].key));
      matrixLines.push(matrixValues.map(csvField).join(','));
    }
    downloadCsv('attribute_matrix', matrixLines);
  }
  else if (kind === 'matrix') {
    var groups = model.rows.slice().sort(function(a, b) { return String(a.name).localeCompare(String(b.name)); });
    var header = ['SamAccountName'].concat(groups.map(function(g) { return g.name; }));
    var lines = [header.map(csvField).join(',')];
    for (var u = 0; u < model.users.length; u++) {
      var owned = Object.create(null);
      var dns = asArray(model.users[u].groups);
      for (var d = 0; d < dns.length; d++) owned[dns[d]] = true;
      var values = [model.users[u].sam];
      for (var g = 0; g < groups.length; g++) values.push(owned[groups[g].dn] ? 'Y' : 'N');
      lines.push(values.map(csvField).join(','));
    }
    downloadCsv('membership_matrix', lines);
  }
}
function closestAction(node) {
  while (node && node !== document) {
    if (node.getAttribute && node.getAttribute('data-action')) return node;
    node = node.parentNode;
  }
  return null;
}
function toggleDetail(host) {
  var key = host.getAttribute('data-detail');
  var row = document.getElementById('detail-' + key);
  if (!row) return;
  var open = !row.classList.contains('open');
  if (open) row.classList.add('open'); else row.classList.remove('open');
  var buttons = document.querySelectorAll('[data-exp="' + key + '"]');
  for (var i = 0; i < buttons.length; i++) {
    if (open) buttons[i].classList.add('open'); else buttons[i].classList.remove('open');
    buttons[i].setAttribute('aria-expanded', open ? 'true' : 'false');
  }
  if (open) {
    var slot = row.querySelector('.detail-members-body');
    if (slot && slot.getAttribute('data-loaded') !== '1') {
      var members = memberStore[key] || [];
      var html = members.length ? '<div class="pills">' : '<span class="muted">No users in this report.</span>';
      for (var m = 0; m < members.length; m++) html += '<span class="pill">' + esc(members[m]) + '</span>';
      if (members.length) html += '</div>';
      slot.innerHTML = html;
      slot.setAttribute('data-loaded', '1');
    }
  }
}
function copyText(text, host) {
  function done() {
    if (!host) return;
    var previous = host.textContent;
    host.textContent = 'Copied';
    setTimeout(function() { host.textContent = previous; }, 1000);
  }
  function fallback() {
    var area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', 'readonly');
    area.style.position = 'fixed';
    area.style.left = '-9999px';
    document.body.appendChild(area);
    area.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(area);
    done();
  }
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, fallback);
  else fallback();
}
document.addEventListener('click', function(event) {
  var host = closestAction(event.target);
  if (!host) return;
  var action = host.getAttribute('data-action');
  if (action === 'show-tab') showTab(host.getAttribute('data-tab'));
  else if (action === 'toggle-detail') toggleDetail(host);
  else if (action === 'theme') applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
  else if (action === 'export') exportCurrent(host.getAttribute('data-kind'));
  else if (action === 'copy') copyText(host.getAttribute('data-copy') || '', host);
  else if (action === 'hm-page') { hmPage += parseInt(host.getAttribute('data-delta'), 10) || 0; renderAll(); }
  else if (action === 'toggle-hide-shared') {
    filters.hideShared = !filters.hideShared;
    host.classList.toggle('active', filters.hideShared);
    renderAll();
  }
  else if (action === 'filter') {
    var group = host.getAttribute('data-group');
    filters[group] = host.getAttribute('data-value');
    var pills = document.querySelectorAll('[data-group="' + group + '"]');
    for (var i = 0; i < pills.length; i++) pills[i].classList.toggle('active', pills[i] === host);
    renderAll();
  }
  else if (action === 'sort') {
    var table = host.getAttribute('data-table');
    var key = host.getAttribute('data-sort');
    if (sortState[table].key === key) sortState[table].dir = -sortState[table].dir;
    else sortState[table] = { key: key, dir: (key === 'count' || key === 'coverage' || key === 'groups') ? -1 : 1 };
    renderAll();
  }
});
document.addEventListener('input', function(event) {
  var id = event.target && event.target.id;
  if (id === 'searchHeatmap' || id === 'searchHeatUsers' || id === 'hmPageSize') hmPage = 0;
  if (id === 'searchAll' || id === 'searchThresh' || id === 'searchCompare' || id === 'searchUsers' || id === 'searchAttrs' || id === 'threshMin' || id === 'includeDisabled' || id === 'searchHeatmap' || id === 'searchHeatUsers' || id === 'hmPageSize') renderAll();
});
document.addEventListener('change', function(event) {
  var id = event.target && event.target.id;
  if (id === 'scopeFilter' || id === 'includeDisabled' || id === 'hmPageSize') {
    if (id === 'hmPageSize') hmPage = 0;
    renderAll();
  }
});
function init() {
  try {
    document.getElementById('includeDisabled').checked = !REPORT.excludeDisabled;
    document.getElementById('threshMin').value = String(REPORT.minimumUserCount || 2);
    applyTheme(loadTheme() || 'light');
    renderAll();
    window.__reportReady = true;
  } catch (err) { showErr('init', err); }
}
init();
</script>
</body>
</html>
'@
}

if ($MyInvocation.InvocationName -ne '.') {
    exit $(Invoke-FindCommonADGroups)
}

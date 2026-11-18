<#
.SYNOPSIS
    Pure analysis functions for the AD Item-Level Targeting tool.

.DESCRIPTION
    No Active Directory or WinForms calls live here, so the CSV, DN, commonality,
    LDAP, and reconciliation logic can be tested without RSAT. The GUI script
    dot-sources this file and supplies the directory data.

    Several bugs in the original console script came from Windows PowerShell 5.1
    unwrapping a one-item collection. A single MemberOf value was walked character
    by character, a single user's OU path was indexed as characters, and .Count on
    a single SamAccountName returned the length of the name. Collection results
    are returned as a one-item array (the comma operator) and string values are
    never enumerated.
#>

function Get-Collection {
    param($Value)

    $list = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Value) { return ,$list }

    # A string is enumerable (characters). A PSCustomObject is enumerable
    # (note properties). Both must stay one item.
    if ($Value -is [string] -or ($Value -is [pscustomobject] -and -not ($Value -is [System.Collections.IList]))) {
        $list.Add($Value)
        return ,$list
    }

    foreach ($item in $Value) {
        if ($null -ne $item) { $list.Add($item) }
    }
    return ,$list
}

function Get-UserList {
    param($Users)

    $list = New-Object System.Collections.Generic.List[object]
    foreach ($item in (Get-Collection $Users)) {
        if ($null -eq $item) { continue }
        $names = @($item.PSObject.Properties.Name)
        if ($names -contains 'SamAccountName') { $list.Add($item) }
    }
    return ,$list
}

function ConvertTo-HtmlEncoded {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function ConvertTo-LdapFilterValue {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value -or $Value -eq '') { return '' }

    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '\' { [void]$sb.Append('\5c') }
            '*' { [void]$sb.Append('\2a') }
            '(' { [void]$sb.Append('\28') }
            ')' { [void]$sb.Append('\29') }
            "`0" { [void]$sb.Append('\00') }
            default { [void]$sb.Append($ch) }
        }
    }
    return $sb.ToString()
}

function New-AnchoredLdapFilter {
    param($Clauses)

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add('(objectCategory=person)')
    $parts.Add('(objectClass=user)')
    # Without this clause an LDAP Query item matches when ANY user in the
    # search base has the attribute, and the drive map applies to everyone.
    $parts.Add('(sAMAccountName=%USERNAME%)')
    foreach ($clause in (Get-Collection $Clauses)) {
        $text = [string]$clause
        if (-not [string]::IsNullOrWhiteSpace($text)) { $parts.Add($text) }
    }
    return '(&' + ($parts -join '') + ')'
}

function ConvertTo-SamAccountName {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return '' }

    $v = $Value.Trim()
    if ($v.Length -ge 2) {
        $first = $v.Substring(0, 1)
        $last = $v.Substring($v.Length - 1, 1)
        if (($first -eq '"' -and $last -eq '"') -or ($first -eq "'" -and $last -eq "'")) {
            $v = $v.Substring(1, $v.Length - 2).Trim()
        }
    }

    # DOMAIN\sam is a logon name. user@domain is left intact because
    # Get-ADUser -Identity does not accept a UPN; the query layer searches
    # userPrincipalName for values that contain '@'.
    if ($v -match '^[^\\]+\\(.+)$') {
        $v = $Matches[1].Trim()
    }
    return $v
}

function ConvertTo-SafeFileName {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return 'report' }

    # Include the Windows set explicitly. This library is also tested on
    # Linux, where ':' and '*' are legal file-name characters.
    $invalid = New-Object System.Collections.Generic.List[char]
    foreach ($bad in [System.IO.Path]::GetInvalidFileNameChars()) { $invalid.Add($bad) }
    foreach ($bad in [char[]]@('"', '<', '>', '|', ':', '*', '?', '\', '/')) {
        if (-not $invalid.Contains($bad)) { $invalid.Add($bad) }
    }
    for ($code = 0; $code -le 31; $code++) {
        $control = [char]$code
        if (-not $invalid.Contains($control)) { $invalid.Add($control) }
    }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Name.ToCharArray()) {
        if ($invalid.Contains($ch)) { [void]$sb.Append('_') } else { [void]$sb.Append($ch) }
    }
    $safe = $sb.ToString().Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($safe)) { return 'report' }
    return $safe
}

function Read-TextFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $encoding = $null
    $offset = 0

    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $encoding = New-Object System.Text.UTF8Encoding $true
        $offset = 3
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $encoding = [System.Text.Encoding]::Unicode
        $offset = 2
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        $encoding = [System.Text.Encoding]::BigEndianUnicode
        $offset = 2
    } else {
        $strict = New-Object System.Text.UTF8Encoding $false, $true
        try {
            $null = $strict.GetString($bytes)
            $encoding = New-Object System.Text.UTF8Encoding $false
        } catch {
            $encoding = [System.Text.Encoding]::Default
        }
    }

    $text = $encoding.GetString($bytes, $offset, $bytes.Length - $offset)
    if ($text.Length -gt 0 -and [int][char]$text[0] -eq 0xFEFF) {
        $text = $text.Substring(1)
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $parts = [regex]::Split($text, "\r\n|\n|\r")
    if ($parts -is [string]) {
        $lines.Add($parts)
    } elseif ($null -ne $parts) {
        foreach ($part in $parts) { $lines.Add([string]$part) }
    }

    [PSCustomObject]@{
        Text  = $text
        Lines = $lines
    }
}

function Test-SamColumnName {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }

    $candidates = @(
        'SamAccountName', 'sAMAccountName', 'Username', 'UserName', 'User', 'Account',
        'Login', 'ID', 'Logon', 'LogonName', 'UserID', 'UserId', 'LoginName',
        'AccountName', 'SAM', 'sAM'
    )
    foreach ($candidate in $candidates) {
        if ([string]::Equals($Name, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    $compact = ($Name -replace '[^A-Za-z]', '').ToLowerInvariant()
    $labels = @(
        'samaccountname', 'username', 'user', 'account', 'login', 'logon',
        'userid', 'loginname', 'accountname', 'sam'
    )
    return ($labels -contains $compact)
}

function Test-GenericColumnLabel {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $compact = ($Name -replace '[^A-Za-z]', '').ToLowerInvariant()
    $labels = @(
        'name', 'employee', 'email', 'department', 'title', 'office', 'company',
        'users', 'accounts', 'list', 'givenname', 'surname', 'displayname',
        'firstname', 'lastname', 'mail', 'upn', 'userprincipalname', 'city',
        'state', 'country', 'description', 'manager', 'division', 'groups'
    )
    return ($labels -contains $compact)
}

function Test-ColumnLabel {
    param([AllowNull()][string]$Name)
    return ((Test-SamColumnName $Name) -or (Test-GenericColumnLabel $Name))
}

function Find-SamColumn {
    param($Columns)
    foreach ($column in (Get-Collection $Columns)) {
        if (Test-SamColumnName ([string]$column)) { return [string]$column }
    }
    return $null
}

function New-NameBag {
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    [PSCustomObject]@{
        Names = (New-Object System.Collections.Generic.List[string])
        Seen  = $seen
        DuplicateCount = 0
    }
}

function Add-SamName {
    param($Bag, [AllowNull()][string]$Value)
    $sam = ConvertTo-SamAccountName $Value
    if ([string]::IsNullOrWhiteSpace($sam)) { return }
    if ($Bag.Seen.Add($sam)) {
        $Bag.Names.Add($sam)
    } else {
        $Bag.DuplicateCount++
    }
}

function Get-ParsedCsvRows {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ,@(New-Object System.Collections.Generic.List[object])
    }
    $rows = New-Object System.Collections.Generic.List[object]
    $parsed = @($Text | ConvertFrom-Csv | Where-Object { $null -ne $_ })
    foreach ($row in $parsed) { $rows.Add($row) }
    return ,$rows
}

function Get-CsvColumnNames {
    param($Rows, [AllowNull()][string]$Text)
    $names = New-Object System.Collections.Generic.List[string]
    $rowList = Get-Collection $Rows
    if ($rowList.Count -gt 0) {
        foreach ($name in @($rowList[0].PSObject.Properties.Name)) { $names.Add([string]$name) }
        return ,$names
    }
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,$names }
    $dummy = $Text.TrimEnd() + "`r`n__dummy__"
    $probe = @( $dummy | ConvertFrom-Csv | Where-Object { $null -ne $_ } )
    if ($probe.Count -gt 0) {
        foreach ($name in @($probe[0].PSObject.Properties.Name)) { $names.Add([string]$name) }
    }
    return ,$names
}

function Get-LengthWarning {
    param($Names)
    $long = 0
    foreach ($name in (Get-Collection $Names)) {
        $text = [string]$name
        if ($text.Length -gt 20 -and $text -notmatch '@') { $long++ }
    }
    if ($long -eq 0) { return '' }
    return "$long value(s) are longer than 20 characters. sAMAccountName cannot exceed 20 characters; those entries may be display names or other identifiers and can show up as not found."
}

function Select-SamNamesFromColumn {
    param(
        [AllowNull()][string]$Text,
        [Parameter(Mandatory = $true)][string]$ColumnName
    )

    $bag = New-NameBag
    foreach ($row in (Get-ParsedCsvRows $Text)) {
        $value = $row.$ColumnName
        Add-SamName -Bag $bag -Value ([string]$value)
    }

    $warning = Get-LengthWarning $bag.Names
    [PSCustomObject]@{
        Names          = $bag.Names
        Mode           = 'Column'
        Column         = $ColumnName
        Columns        = (New-Object System.Collections.Generic.List[string])
        DuplicateCount = $bag.DuplicateCount
        Warning        = $warning
    }
}

function Import-SamAccountNamesFromText {
    param(
        [AllowNull()][string]$Text,
        [string]$SourceName = 'input'
    )

    $emptyColumns = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return [PSCustomObject]@{
            Names = (New-Object System.Collections.Generic.List[string]); Mode = 'Empty'; Column = ''
            Columns = $emptyColumns; DuplicateCount = 0; Warning = "No names found in $SourceName."
        }
    }

    $rows = Get-ParsedCsvRows $Text
    $columns = Get-CsvColumnNames -Rows $rows -Text $Text
    $bag = New-NameBag

    if ($rows.Count -eq 0) {
        $tokens = [regex]::Split($Text, '[\r\n,;\t]+')
        $tokenList = New-Object System.Collections.Generic.List[string]
        if ($tokens -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace($tokens)) { $tokenList.Add($tokens.Trim()) }
        } else {
            foreach ($token in $tokens) {
                if (-not [string]::IsNullOrWhiteSpace([string]$token)) { $tokenList.Add(([string]$token).Trim()) }
            }
        }
        if ($tokenList.Count -eq 1 -and (Test-ColumnLabel $tokenList[0])) {
            return [PSCustomObject]@{
                Names = $bag.Names; Mode = 'Empty'; Column = $tokenList[0]
                Columns = $columns; DuplicateCount = 0
                Warning = 'The file has a header but no user rows.'
            }
        }
        foreach ($token in $tokenList) { Add-SamName -Bag $bag -Value $token }
        return [PSCustomObject]@{
            Names = $bag.Names; Mode = 'Headerless'; Column = ''
            Columns = $columns; DuplicateCount = $bag.DuplicateCount
            Warning = (Get-LengthWarning $bag.Names)
        }
    }

    $samColumn = Find-SamColumn $columns
    if ($samColumn) {
        foreach ($row in $rows) { Add-SamName -Bag $bag -Value ([string]$row.$samColumn) }
        return [PSCustomObject]@{
            Names = $bag.Names; Mode = 'Header'; Column = $samColumn
            Columns = $columns; DuplicateCount = $bag.DuplicateCount
            Warning = (Get-LengthWarning $bag.Names)
        }
    }

    if ($columns.Count -eq 1 -and (Test-GenericColumnLabel ([string]$columns[0]))) {
        $only = [string]$columns[0]
        foreach ($row in $rows) { Add-SamName -Bag $bag -Value ([string]$row.$only) }
        return [PSCustomObject]@{
            Names = $bag.Names; Mode = 'Header'; Column = $only
            Columns = $columns; DuplicateCount = $bag.DuplicateCount
            Warning = (Get-LengthWarning $bag.Names)
        }
    }

    if ($columns.Count -eq 1) {
        # Import-Csv treated the first SamAccountName as the header. Put it back.
        $tokens = [regex]::Split($Text, '[\r\n,;\t]+')
        if ($tokens -is [string]) {
            Add-SamName -Bag $bag -Value $tokens
        } else {
            foreach ($token in $tokens) { Add-SamName -Bag $bag -Value ([string]$token) }
        }
        return [PSCustomObject]@{
            Names = $bag.Names; Mode = 'Headerless'; Column = ''
            Columns = $columns; DuplicateCount = $bag.DuplicateCount
            Warning = (Get-LengthWarning $bag.Names)
        }
    }

    return [PSCustomObject]@{
        Names = $bag.Names; Mode = 'NeedsColumn'; Column = ''
        Columns = $columns; DuplicateCount = 0
        Warning = 'More than one column was found and none is a SamAccountName column.'
    }
}

function Import-SamAccountNamesFromFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "File not found: $Path"
    }
    $file = Read-TextFile -Path $Path
    Import-SamAccountNamesFromText -Text $file.Text -SourceName $Path
}

function Split-DistinguishedName {
    param([AllowNull()][string]$DistinguishedName)

    $parts = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return ,$parts }

    # Split on commas that are not escaped. An even number of backslashes
    # before a comma means the comma is a separator (\\, is a literal slash
    # followed by a separator). Regex lookbehind cannot count that.
    $current = New-Object System.Text.StringBuilder
    $escape = $false
    foreach ($ch in $DistinguishedName.ToCharArray()) {
        if ($escape) {
            [void]$current.Append('\')
            [void]$current.Append($ch)
            $escape = $false
            continue
        }
        if ($ch -eq '\') { $escape = $true; continue }
        if ($ch -eq ',') {
            $parts.Add($current.ToString().Trim())
            [void]$current.Clear()
            continue
        }
        [void]$current.Append($ch)
    }
    if ($escape) { [void]$current.Append('\') }
    if ($current.Length -gt 0) { $parts.Add($current.ToString().Trim()) }
    return ,$parts
}

function ConvertFrom-DnEscaped {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }

    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Value.Length; $i++) {
        $ch = $Value[$i]
        if ($ch -eq '\' -and ($i + 1) -lt $Value.Length) {
            $next = $Value[$i + 1]
            $hex = $false
            if ($next -match '[0-9A-Fa-f]' -and ($i + 2) -lt $Value.Length -and $Value[$i + 2] -match '[0-9A-Fa-f]') {
                $hex = $true
            }
            if ($hex) {
                $code = [convert]::ToInt32($Value.Substring($i + 1, 2), 16)
                [void]$sb.Append([char]$code)
                $i += 2
            } else {
                [void]$sb.Append($next)
                $i += 1
            }
        } else {
            [void]$sb.Append($ch)
        }
    }
    return $sb.ToString()
}

function Get-RdnValue {
    param([AllowNull()][string]$DistinguishedName)
    $parts = Split-DistinguishedName $DistinguishedName
    if ($parts.Count -eq 0) { return '' }
    $rdn = [string]$parts[0]
    $eq = $rdn.IndexOf('=')
    if ($eq -ge 0 -and $eq -lt ($rdn.Length - 1)) {
        return (ConvertFrom-DnEscaped $rdn.Substring($eq + 1))
    }
    return (ConvertFrom-DnEscaped $rdn)
}

function Get-ParentOuDn {
    param([AllowNull()][string]$DistinguishedName)
    $parts = Split-DistinguishedName $DistinguishedName
    if ($parts.Count -le 1) { return '' }
    $rest = New-Object System.Collections.Generic.List[string]
    for ($i = 1; $i -lt $parts.Count; $i++) { $rest.Add([string]$parts[$i]) }
    return ($rest -join ',')
}

function Get-OUComponents {
    param([AllowNull()][string]$DistinguishedName)

    # Root-first (DC=com, DC=contoso, OU=Users) so a common ancestor is a shared prefix.
    $parts = Split-DistinguishedName $DistinguishedName
    $ouParts = New-Object System.Collections.Generic.List[string]
    for ($i = 1; $i -lt $parts.Count; $i++) {
        if ([string]$parts[$i] -match '^(?i)(OU|DC)=') { $ouParts.Add([string]$parts[$i]) }
    }
    $rootFirst = New-Object System.Collections.Generic.List[string]
    for ($i = $ouParts.Count - 1; $i -ge 0; $i--) { $rootFirst.Add($ouParts[$i]) }
    return ,$rootFirst
}

function Test-DomainDistinguishedName {
    param([AllowNull()][string]$DistinguishedName)
    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return $false }
    $parts = Split-DistinguishedName $DistinguishedName
    if ($parts.Count -eq 0) { return $false }
    foreach ($part in $parts) {
        if ([string]$part -notmatch '^(?i)DC=') { return $false }
    }
    return $true
}

function Join-DistinguishedName {
    param($RootFirstComponents)
    $stack = New-Object System.Collections.Generic.List[string]
    foreach ($component in (Get-Collection $RootFirstComponents)) {
        $text = [string]$component
        if (-not [string]::IsNullOrWhiteSpace($text)) { $stack.Add($text) }
    }
    $dnParts = New-Object System.Collections.Generic.List[string]
    for ($i = $stack.Count - 1; $i -ge 0; $i--) { $dnParts.Add($stack[$i]) }
    return ($dnParts -join ',')
}

function Test-BroadGroupName {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $broad = @(
        'Domain Users', 'Domain Computers', 'Domain Guests', 'Users', 'Everyone',
        'Authenticated Users', 'Pre-Windows 2000 Compatible Access', 'Interactive',
        'This Organization'
    )
    foreach ($candidate in $broad) {
        if ([string]::Equals($Name, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Test-PrivilegedGroupName {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $names = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'Account Operators', 'Server Operators', 'Backup Operators', 'DnsAdmins'
    )
    foreach ($candidate in $names) {
        if ([string]::Equals($Name, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Test-BroadSid {
    param([AllowNull()][string]$Sid)
    if ([string]::IsNullOrWhiteSpace($Sid)) { return $false }
    if ($Sid -match '^S-1-1-0$') { return $true }          # Everyone
    if ($Sid -match '^S-1-5-11$') { return $true }         # Authenticated Users
    if ($Sid -match '^S-1-5-4$') { return $true }          # Interactive
    if ($Sid -match '^S-1-5-32-545$') { return $true }     # Builtin Users
    if ($Sid -match '-513$') { return $true }              # Domain Users
    if ($Sid -match '-514$') { return $true }              # Domain Guests
    if ($Sid -match '-515$') { return $true }              # Domain Computers
    return $false
}

function Test-PrivilegedSid {
    param([AllowNull()][string]$Sid)
    if ([string]::IsNullOrWhiteSpace($Sid)) { return $false }
    if ($Sid -match '^S-1-5-32-544$') { return $true }
    if ($Sid -match '^S-1-5-32-548$') { return $true }
    if ($Sid -match '^S-1-5-32-549$') { return $true }
    if ($Sid -match '^S-1-5-32-551$') { return $true }
    if ($Sid -match '-512$') { return $true } # Domain Admins
    if ($Sid -match '-518$') { return $true } # Schema Admins
    if ($Sid -match '-519$') { return $true } # Enterprise Admins
    return $false
}

function Test-IltSecurityGroup {
    param([AllowNull()][string]$Category)
    if ([string]::IsNullOrWhiteSpace($Category)) { return $true }
    if ($Category -match 'Distribution') { return $false }
    return $true
}

function Get-ExtensionAttributeNames {
    $names = New-Object System.Collections.Generic.List[string]
    for ($i = 1; $i -le 15; $i++) { $names.Add("extensionAttribute$i") }
    return ,$names
}

function Get-ScalarPropertyNames {
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($name in @(
            'Department', 'Division', 'Title', 'Company', 'Office',
            'City', 'State', 'Country', 'CountryName', 'StreetAddress', 'PostalCode',
            'EmployeeID', 'EmployeeNumber', 'EmployeeType', 'Manager',
            'HomeDirectory', 'HomeDrive', 'ProfilePath', 'ScriptPath',
            'Description', 'EmailAddress'
        )) {
        $names.Add($name)
    }
    foreach ($name in (Get-ExtensionAttributeNames)) { $names.Add([string]$name) }
    return ,$names
}

function Get-LdapAttributeName {
    param([AllowNull()][string]$PropertyName)
    if ([string]::IsNullOrWhiteSpace($PropertyName)) { return '' }

    $map = @{
        Department     = 'department'
        Division       = 'division'
        Title          = 'title'
        Company        = 'company'
        Office         = 'physicalDeliveryOfficeName'
        City           = 'l'
        State          = 'st'
        Country        = 'c'
        CountryName    = 'co'
        StreetAddress  = 'street'
        PostalCode     = 'postalCode'
        EmployeeID     = 'employeeID'
        EmployeeNumber = 'employeeNumber'
        EmployeeType   = 'employeeType'
        Manager        = 'manager'
        HomeDirectory  = 'homeDirectory'
        HomeDrive      = 'homeDrive'
        ProfilePath    = 'profilePath'
        ScriptPath     = 'scriptPath'
        Description    = 'description'
        EmailAddress   = 'mail'
    }
    if ($map.ContainsKey($PropertyName)) { return [string]$map[$PropertyName] }
    if ($PropertyName -match '^extensionAttribute\d+$') { return $PropertyName }
    return ''
}

function Get-Percent {
    param($Part, $Total)
    $whole = 0
    $portion = 0
    if ($null -ne $Total) { $whole = [double]$Total }
    if ($null -ne $Part) { $portion = [double]$Part }
    if ($whole -le 0) { return [double]0 }
    return [math]::Round(($portion / $whole) * 100, 1)
}

function Format-NameList {
    param($Names, [int]$Max = 30)
    $list = Get-Collection $Names
    if ($list.Count -eq 0) { return '' }
    $take = [Math]::Min($Max, $list.Count)
    $slice = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $take; $i++) { $slice.Add([string]$list[$i]) }
    $text = $slice -join '; '
    if ($list.Count -gt $Max) {
        $text = $text + '; ... (+' + ($list.Count - $Max) + ' more)'
    }
    return $text
}

function Get-AttributeText {
    param($User, [string]$PropertyName)
    $raw = $User.$PropertyName
    if ($null -eq $raw) { return '' }
    return ([string]$raw).Trim()
}

function New-OrAttributeFilter {
    param([string]$LdapAttribute, $Values)
    $ors = New-Object System.Collections.Generic.List[string]
    foreach ($value in (Get-Collection $Values)) {
        $text = [string]$value
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $ors.Add('(' + $LdapAttribute + '=' + (ConvertTo-LdapFilterValue $text) + ')')
    }
    if ($ors.Count -eq 0) { return '' }
    if ($ors.Count -eq 1) { return (New-AnchoredLdapFilter -Clauses $ors[0]) }
    return (New-AnchoredLdapFilter -Clauses ('(|' + ($ors -join '') + ')'))
}

function Get-ScalarAttributeCommonality {
    param($Users)

    $userList = Get-UserList $Users
    $rows = New-Object System.Collections.Generic.List[object]
    $total = $userList.Count
    if ($total -eq 0) { return ,$rows }

    foreach ($prop in (Get-ScalarPropertyNames)) {
        $values = New-Object System.Collections.Generic.List[string]
        $blank = 0
        foreach ($user in $userList) {
            $text = Get-AttributeText -User $user -PropertyName $prop
            if ($text -eq '') { $blank++ } else { $values.Add($text) }
        }
        if ($values.Count -eq 0) { continue }

        $grouped = @($values | Group-Object | Sort-Object Count -Descending)
        $top = $grouped[0]
        $matching = [int]$top.Count
        $distinct = @($grouped).Count
        $fully = ($distinct -eq 1 -and $blank -eq 0)
        $ldapAttr = Get-LdapAttributeName $prop
        $topValue = [string]$top.Name
        $ldapFilter = ''
        $orFilter = ''
        $allValues = New-Object System.Collections.Generic.List[string]
        foreach ($group in $grouped) { $allValues.Add([string]$group.Name) }
        if (-not [string]::IsNullOrWhiteSpace($ldapAttr)) {
            $ldapFilter = New-AnchoredLdapFilter -Clauses ('(' + $ldapAttr + '=' + (ConvertTo-LdapFilterValue $topValue) + ')')
            if ($distinct -ge 2 -and $distinct -le 4 -and $blank -eq 0) {
                $orFilter = New-OrAttributeFilter -LdapAttribute $ldapAttr -Values $allValues
            }
        }

        $missing = New-Object System.Collections.Generic.List[string]
        foreach ($user in $userList) {
            $text = Get-AttributeText -User $user -PropertyName $prop
            if ($text -ne $topValue) { $missing.Add([string]$user.SamAccountName) }
        }

        $rows.Add([PSCustomObject]@{
                Attribute          = $prop
                LdapAttribute      = $ldapAttr
                TopValue           = $topValue
                UsersMatching      = $matching
                UsersBlank         = $blank
                TotalUsers         = $total
                PercentMatching    = (Get-Percent $matching $total)
                DistinctValues     = $distinct
                FullyCommon        = [bool]$fully
                LdapFilter         = $ldapFilter
                OrLdapFilter       = $orFilter
                DistinctValueList  = ($allValues -join '; ')
                UsersMissing       = (Format-NameList $missing)
                UsersMissingCount  = $missing.Count
            })
    }

    $sorted = @($rows | Sort-Object @{ Expression = 'PercentMatching'; Descending = $true }, @{ Expression = 'DistinctValues'; Ascending = $true }, @{ Expression = 'Attribute'; Ascending = $true })
    $ordered = New-Object System.Collections.Generic.List[object]
    foreach ($row in $sorted) { $ordered.Add($row) }
    return ,$ordered
}

function Get-GroupRecordKey {
    param($Group)
    if ($null -eq $Group) { return '' }
    if ($Group -is [string]) { return [string]$Group }
    $sid = [string]$Group.ObjectSid
    if (-not [string]::IsNullOrWhiteSpace($sid)) { return "SID:$sid" }
    $dn = [string]$Group.DistinguishedName
    if (-not [string]::IsNullOrWhiteSpace($dn)) { return "DN:$dn" }
    $sam = [string]$Group.SamAccountName
    if (-not [string]::IsNullOrWhiteSpace($sam)) { return "NAME:$sam" }
    return ("NAME:" + [string]$Group.Name)
}

function Get-NormalizedGroup {
    param($Group)
    if ($null -eq $Group) { return $null }
    if ($Group -is [string]) {
        $name = [string]$Group
        return [PSCustomObject]@{
            Key               = "NAME:$name"
            SamAccountName    = $name
            Name              = $name
            DistinguishedName = ''
            ObjectSid         = ''
            GroupCategory     = ''
            GroupScope        = ''
            IsPrimary         = $false
            IsDirect          = $true
            InToken           = $false
            IsBroad           = ((Test-BroadGroupName $name) -or (Test-BroadSid $name))
            IsPrivileged      = ((Test-PrivilegedGroupName $name) -or (Test-PrivilegedSid $name))
        }
    }

    $sam = [string]$Group.SamAccountName
    $name = [string]$Group.Name
    $dn = [string]$Group.DistinguishedName
    $sid = [string]$Group.ObjectSid
    $category = [string]$Group.GroupCategory
    $scope = [string]$Group.GroupScope
    if ([string]::IsNullOrWhiteSpace($name) -and $dn) { $name = Get-RdnValue $dn }
    if ([string]::IsNullOrWhiteSpace($sam)) { $sam = $name }
    if ([string]::IsNullOrWhiteSpace($sam) -and $sid) { $sam = $sid }
    if ([string]::IsNullOrWhiteSpace($name)) { $name = $sam }

    [PSCustomObject]@{
        Key               = (Get-GroupRecordKey $Group)
        SamAccountName    = $sam
        Name              = $name
        DistinguishedName = $dn
        ObjectSid         = $sid
        GroupCategory     = $category
        GroupScope        = $scope
        IsPrimary         = [bool]($Group.IsPrimary -eq $true)
        IsDirect          = [bool]($Group.IsDirect -ne $false)
        InToken           = [bool]($Group.InToken -eq $true)
        IsBroad           = ((Test-BroadGroupName $name) -or (Test-BroadGroupName $sam) -or (Test-BroadSid $sid) -or (Test-BroadSid $name))
        IsPrivileged      = ((Test-PrivilegedGroupName $name) -or (Test-PrivilegedGroupName $sam) -or (Test-PrivilegedSid $sid))
    }
}

function Get-GroupCommonality {
    param($Users)

    $userList = Get-UserList $Users
    $rows = New-Object System.Collections.Generic.List[object]
    $total = $userList.Count
    if ($total -eq 0) { return ,$rows }

    $counts = @{}
    $meta = @{}
    $missing = @{}

    foreach ($user in $userList) {
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($rawGroup in (Get-Collection $user.Groups)) {
            $group = Get-NormalizedGroup $rawGroup
            if ($null -eq $group -or [string]::IsNullOrWhiteSpace($group.Key)) { continue }
            if (-not $seen.Add($group.Key)) { continue }
            if (-not $counts.ContainsKey($group.Key)) {
                $counts[$group.Key] = 0
                $meta[$group.Key] = $group
                $missing[$group.Key] = (New-Object System.Collections.Generic.List[string])
            }
            $counts[$group.Key] = [int]$counts[$group.Key] + 1
            $current = $meta[$group.Key]
            if ($group.IsPrimary) { $current.IsPrimary = $true }
            if ($group.InToken) { $current.InToken = $true }
            if ($group.IsDirect) { $current.IsDirect = $true }
            if ($group.IsBroad) { $current.IsBroad = $true }
            if ($group.IsPrivileged) { $current.IsPrivileged = $true }
            if ([string]::IsNullOrWhiteSpace([string]$current.GroupCategory) -and $group.GroupCategory) {
                $current.GroupCategory = $group.GroupCategory
            }
        }
    }

    foreach ($user in $userList) {
        $held = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($rawGroup in (Get-Collection $user.Groups)) {
            $group = Get-NormalizedGroup $rawGroup
            if ($null -ne $group -and $group.Key) { [void]$held.Add($group.Key) }
        }
        foreach ($key in @($counts.Keys)) {
            if (-not $held.Contains([string]$key)) { $missing[$key].Add([string]$user.SamAccountName) }
        }
    }

    foreach ($key in @($counts.Keys)) {
        $group = $meta[$key]
        $count = [int]$counts[$key]
        $category = [string]$group.GroupCategory
        $rows.Add([PSCustomObject]@{
                GroupName         = [string]$group.Name
                SamAccountName    = [string]$group.SamAccountName
                DistinguishedName = [string]$group.DistinguishedName
                ObjectSid         = [string]$group.ObjectSid
                GroupCategory     = $category
                GroupScope        = [string]$group.GroupScope
                IsBroad           = [bool]$group.IsBroad
                IsPrivileged      = [bool]$group.IsPrivileged
                IsPrimary         = [bool]$group.IsPrimary
                InToken           = [bool]$group.InToken
                IltEligible       = (Test-IltSecurityGroup $category)
                UsersInGroup      = $count
                TotalUsers        = $total
                PercentCoverage   = (Get-Percent $count $total)
                FullyCommon       = [bool]($count -eq $total)
                UsersMissing      = (Format-NameList $missing[$key])
                UsersMissingCount = $missing[$key].Count
            })
    }

    $sorted = @($rows | Sort-Object @{ Expression = 'PercentCoverage'; Descending = $true }, @{ Expression = 'GroupName'; Ascending = $true })
    $ordered = New-Object System.Collections.Generic.List[object]
    foreach ($row in $sorted) { $ordered.Add($row) }
    return ,$ordered
}

function Get-OUCommonality {
    param($Users)

    $userList = Get-UserList $Users
    $total = $userList.Count
    $distribution = New-Object System.Collections.Generic.List[object]
    if ($total -eq 0) {
        return [PSCustomObject]@{
            ParentOUs                  = $distribution
            CommonAncestor             = ''
            CommonAncestorIsDomainRoot = $false
            AllUsersSameOU             = $false
            SameParentOu               = ''
        }
    }

    $buckets = @{}
    $order = New-Object System.Collections.Generic.List[string]
    $perUser = New-Object System.Collections.Generic.List[object]
    foreach ($user in $userList) {
        $parent = [string]$user.ParentOU
        if (-not $buckets.ContainsKey($parent)) {
            $buckets[$parent] = 0
            $order.Add($parent)
        }
        $buckets[$parent] = [int]$buckets[$parent] + 1

        $components = New-Object System.Collections.Generic.List[string]
        foreach ($component in (Get-Collection $user.OUComponents)) {
            $components.Add([string]$component)
        }
        $perUser.Add($components)
    }

    foreach ($parent in $order) {
        $count = [int]$buckets[$parent]
        $label = $parent
        if ([string]::IsNullOrWhiteSpace($label)) { $label = '(no parent OU)' }
        $distribution.Add([PSCustomObject]@{
                ParentOU       = $label
                UserCount      = $count
                PercentOfTotal = (Get-Percent $count $total)
            })
    }
    $orderedDist = New-Object System.Collections.Generic.List[object]
    $sortedDist = @($distribution | Sort-Object @{ Expression = 'UserCount'; Descending = $true }, @{ Expression = 'ParentOU'; Ascending = $true })
    foreach ($row in $sortedDist) { $orderedDist.Add($row) }

    $min = [int]::MaxValue
    foreach ($components in $perUser) {
        if ($components.Count -lt $min) { $min = $components.Count }
    }
    if ($min -eq [int]::MaxValue) { $min = 0 }

    $common = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $min; $i++) {
        $value = [string]$perUser[0][$i]
        $allEqual = $true
        foreach ($components in $perUser) {
            if ([string]$components[$i] -ne $value) { $allEqual = $false; break }
        }
        if ($allEqual) { $common.Add($value) } else { break }
    }

    $ancestor = Join-DistinguishedName $common
    $sameParent = ''
    $allSame = ($orderedDist.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace([string]$userList[0].ParentOU))
    if ($allSame) { $sameParent = [string]$userList[0].ParentOU }

    [PSCustomObject]@{
        ParentOUs                  = $orderedDist
        CommonAncestor             = $ancestor
        CommonAncestorIsDomainRoot = (Test-DomainDistinguishedName $ancestor)
        AllUsersSameOU             = [bool]$allSame
        SameParentOu               = $sameParent
    }
}

function Get-AccountHealth {
    param($Users)

    $userList = Get-UserList $Users
    $rows = New-Object System.Collections.Generic.List[object]
    $checks = @(
        'Disabled',
        'Locked out',
        'Password expired',
        'Password never expires',
        'No home directory',
        'No home drive'
    )

    foreach ($check in $checks) {
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($user in $userList) {
            $match = $false
            switch ($check) {
                'Disabled' { $match = ($user.Enabled -eq $false) }
                'Locked out' { $match = ($user.LockedOut -eq $true) }
                'Password expired' { $match = ($user.PasswordExpired -eq $true) }
                'Password never expires' { $match = ($user.PasswordNeverExpires -eq $true) }
                'No home directory' { $match = [string]::IsNullOrWhiteSpace((Get-AttributeText $user 'HomeDirectory')) }
                'No home drive' { $match = [string]::IsNullOrWhiteSpace((Get-AttributeText $user 'HomeDrive')) }
            }
            if ($match) { $names.Add([string]$user.SamAccountName) }
        }
        $rows.Add([PSCustomObject]@{
                Issue    = $check
                Count    = $names.Count
                Accounts = (Format-NameList $names -Max 50)
            })
    }
    return ,$rows
}

function Get-SharedPrefix {
    param($Values)
    $vals = New-Object System.Collections.Generic.List[string]
    foreach ($value in (Get-Collection $Values)) {
        $text = if ($null -eq $value) { '' } else { ([string]$value).Trim() }
        if ($text -ne '') { $vals.Add($text) }
    }
    if ($vals.Count -eq 0) { return '' }

    $prefix = $vals[0]
    for ($i = 1; $i -lt $vals.Count; $i++) {
        $other = $vals[$i]
        $max = [Math]::Min($prefix.Length, $other.Length)
        $len = 0
        while ($len -lt $max -and ([char]::ToUpperInvariant($prefix[$len]) -eq [char]::ToUpperInvariant($other[$len]))) {
            $len++
        }
        if ($len -le 0) { return '' }
        $prefix = $prefix.Substring(0, $len)
    }

    $slash = [Math]::Max($prefix.LastIndexOf('\'), $prefix.LastIndexOf('/'))
    if ($slash -gt 0) { return $prefix.Substring(0, $slash + 1) }
    return $prefix
}

function Get-PathPrefixInsights {
    param($Users)
    $userList = Get-UserList $Users
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($prop in @('HomeDirectory', 'HomeDrive', 'ProfilePath', 'ScriptPath')) {
        $vals = New-Object System.Collections.Generic.List[string]
        foreach ($user in $userList) {
            $text = Get-AttributeText $user $prop
            if ($text -ne '') { $vals.Add($text) }
        }
        if ($vals.Count -lt 2) { continue }
        $prefix = Get-SharedPrefix $vals
        if ([string]::IsNullOrWhiteSpace($prefix) -or $prefix.Length -lt 3) { continue }
        $rows.Add([PSCustomObject]@{
                Attribute    = $prop
                SharedPrefix = $prefix
                Populated    = $vals.Count
                TotalUsers   = $userList.Count
                Note         = 'Informational only. Item-level targeting cannot match a path prefix. Use it to see which file server these accounts already point at.'
            })
    }
    return ,$rows
}

function Get-GpmcSteps {
    param($Recommendation)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('Open Group Policy Management and edit the GPO that contains the drive map.')
    $lines.Add('Go to User Configuration > Preferences > Windows Settings > Drive Maps.')
    $lines.Add('Open the mapped drive (or create it), then open the Common tab.')
    $lines.Add('Check "Item-level targeting" and click Targeting.')

    $item = [string]$Recommendation.IltItem
    if ($item -eq 'Security Group') {
        $lines.Add('New Item > Security Group.')
        $lines.Add('Choose the group ' + [string]$Recommendation.Filter + '. Match the user, not the computer.')
        $lines.Add('Security Group targeting uses the logon token, so nested security-group membership counts.')
    } elseif ($item -eq 'Organizational Unit') {
        $lines.Add('New Item > Organizational Unit.')
        $lines.Add('Select the user object, not the computer object.')
        $filterText = [string]$Recommendation.Filter
        if ($filterText -match "`n") {
            $lines.Add('Add one Organizational Unit item for each DN below. Leave the first item as AND and set each following item to OR.')
            $lines.Add($filterText)
            $lines.Add('Check "Direct member only" on each item when you do not want child OUs to match.')
        } else {
            $lines.Add('Browse to this OU: ' + $filterText)
            $lines.Add([string]$Recommendation.Notes)
        }
    } elseif ($item -eq 'LDAP Query') {
        $lines.Add('New Item > LDAP Query.')
        $lines.Add('Filter: ' + [string]$Recommendation.Filter)
        $binding = [string]$Recommendation.Binding
        if ([string]::IsNullOrWhiteSpace($binding)) { $binding = '(leave binding at the domain default)' }
        $lines.Add('Binding: ' + $binding)
        $lines.Add('Leave Attribute blank. Keep (sAMAccountName=%USERNAME%) in the filter so the query describes the user who is logging on. If %USERNAME% is not expanded, try %LogonUser%.')
    }

    $lines.Add('Click OK and run gpupdate /target:user as one of the accounts to confirm the drive maps.')

    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $lines.Count; $i++) {
        [void]$sb.AppendLine(($i + 1).ToString() + '. ' + [string]$lines[$i])
    }
    return $sb.ToString().TrimEnd()
}

function New-IltRecommendation {
    param(
        [int]$Rank,
        [string]$Quality,
        [double]$Coverage,
        [string]$Type,
        [string]$IltItem,
        [string]$Target,
        [string]$Filter,
        [string]$Binding,
        [string]$Notes
    )

    $rec = [PSCustomObject]@{
        Rank     = $Rank
        Quality  = $Quality
        Coverage = $Coverage
        Type     = $Type
        IltItem  = $IltItem
        Target   = $Target
        Filter   = $Filter
        Binding  = $Binding
        Notes    = $Notes
        Steps    = ''
    }
    $rec.Steps = Get-GpmcSteps -Recommendation $rec
    return $rec
}

function Get-GroupFilterLabel {
    param($Group, [string]$NetBiosName)
    $sam = [string]$Group.SamAccountName
    if (-not [string]::IsNullOrWhiteSpace($NetBiosName) -and -not [string]::IsNullOrWhiteSpace($sam) -and $sam -notmatch '^S-1-') {
        return ($NetBiosName + '\' + $sam)
    }
    if (-not [string]::IsNullOrWhiteSpace($sam)) { return $sam }
    return [string]$Group.GroupName
}

function Get-IltRecommendations {
    param(
        $ScalarRows,
        $GroupRows,
        $OuResult,
        [double]$MinPercent = 50,
        [string]$DomainDn,
        [string]$NetBiosName,
        [bool]$TokenGroupsResolved = $false
    )

    $recs = New-Object System.Collections.Generic.List[object]
    $bindingDn = $DomainDn
    if ($null -ne $OuResult) {
        $ancestor = [string]$OuResult.CommonAncestor
        if (-not [string]::IsNullOrWhiteSpace($ancestor) -and -not (Test-DomainDistinguishedName $ancestor)) {
            $bindingDn = $ancestor
        }
    }
    $binding = ''
    if (-not [string]::IsNullOrWhiteSpace($bindingDn)) { $binding = 'LDAP://' + $bindingDn }

    $tokenNote = ''
    if (-not $TokenGroupsResolved) {
        $tokenNote = ' Nested group coverage was not expanded. Re-query with tokenGroups enabled before relying on a parent security group.'
    }

    foreach ($group in (Get-Collection $GroupRows)) {
        $coverage = [double]$group.PercentCoverage
        if (-not $group.FullyCommon -and $coverage -lt $MinPercent) { continue }

        $label = Get-GroupFilterLabel -Group $group -NetBiosName $NetBiosName
        $target = [string]$group.GroupName
        if ([string]$group.SamAccountName -and [string]$group.SamAccountName -ne $target) {
            $target = $target + ' (' + [string]$group.SamAccountName + ')'
        }

        $quality = 'Possible'
        $rank = 6
        $notes = ''
        $unresolved = ([string]$group.SamAccountName -match '^S-1-' -or [string]$group.GroupName -match '^S-1-')

        if ($group.IsPrivileged) {
            $quality = 'Poor'
            $rank = 8
            $notes = 'This is a privileged built-in group. Do not target a drive map at it.'
        } elseif ($group.IsBroad) {
            $quality = 'Poor'
            $rank = 8
            $notes = 'This group covers the imported users because it is a built-in or automatic group (often Domain Users). Targeting it would apply the drive map far too widely.'
        } elseif (-not $group.IltEligible) {
            $quality = 'Poor'
            $rank = 8
            $notes = 'Distribution groups are not present in the logon token and cannot be used for Security Group item-level targeting. Create a security group, or target an attribute with an LDAP Query instead.'
        } elseif ($unresolved) {
            $quality = 'Possible'
            $rank = 6
            $notes = 'This SID covers the users but did not resolve to a group name. Look it up in Active Directory before using it.'
        } elseif ($group.FullyCommon) {
            $quality = 'Recommended'
            $rank = 1
            $notes = 'Every imported user is covered by this security group. This is the cleanest Item-level targeting rule for a drive map.'
        } else {
            $quality = 'Possible'
            $rank = 6
            $notes = 'Covers ' + $coverage + '% (' + $group.UsersInGroup + ' of ' + $group.TotalUsers + '). Not covered: ' + [string]$group.UsersMissing + '.'
        }

        if ([string]$group.GroupScope -match 'DomainLocal') {
            $notes = $notes + ' Domain-local groups are in the token only when the user logs on to a computer in this domain.'
        }
        if ([string]$group.DistinguishedName) {
            $notes = $notes + ' DN: ' + [string]$group.DistinguishedName + '.'
        }
        if ($quality -ne 'Poor' -and [string]::IsNullOrWhiteSpace([string]$group.GroupCategory)) {
            $notes = 'The directory lookup did not return a group category. Confirm this is a security group; distribution groups cannot be used for Security Group targeting. ' + $notes
        }
        if ($quality -ne 'Poor') { $notes = $notes + $tokenNote }

        $recs.Add((New-IltRecommendation -Rank $rank -Quality $quality -Coverage $coverage -Type 'Security Group' -IltItem 'Security Group' -Target $target -Filter $label -Binding '' -Notes $notes))
    }

    if ($null -ne $OuResult) {
        $same = [string]$OuResult.SameParentOu
        if ($OuResult.AllUsersSameOU -and -not [string]::IsNullOrWhiteSpace($same) -and -not (Test-DomainDistinguishedName $same)) {
            $notes = 'All imported users are direct children of this OU. Add an Organizational Unit targeting item, choose User, and check "Direct member only". The OU may also contain accounts that were not in the CSV; those users would receive the drive map too. A security group is tighter when the OU is shared.'
            $recs.Add((New-IltRecommendation -Rank 2 -Quality 'Recommended' -Coverage 100 -Type 'Organizational Unit' -IltItem 'Organizational Unit' -Target $same -Filter $same -Binding '' -Notes $notes))
        }

        $ancestor = [string]$OuResult.CommonAncestor
        $ancestorIsUseful = -not [string]::IsNullOrWhiteSpace($ancestor) -and -not (Test-DomainDistinguishedName $ancestor) -and ($ancestor -ne $same)
        if ($ancestorIsUseful) {
            $notes = 'This is the deepest OU that still contains every imported user. Add one Organizational Unit targeting item and leave "Direct member only" unchecked so child OUs match. Anyone else under this OU also matches, including people who were not in the CSV.'
            $recs.Add((New-IltRecommendation -Rank 4 -Quality 'Possible' -Coverage 100 -Type 'Organizational Unit' -IltItem 'Organizational Unit' -Target $ancestor -Filter $ancestor -Binding '' -Notes $notes))
        }

        $parents = New-Object System.Collections.Generic.List[string]
        foreach ($row in (Get-Collection $OuResult.ParentOUs)) {
            $parent = [string]$row.ParentOU
            if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq '(no parent OU)') { continue }
            if (Test-DomainDistinguishedName $parent) { continue }
            $parents.Add($parent)
        }
        if (-not $OuResult.AllUsersSameOU -and $parents.Count -ge 2 -and $parents.Count -le 6) {
            $filter = $parents -join "`r`n"
            $target = $parents -join ' OR '
            $notes = 'These ' + $parents.Count + ' parent OUs cover the imported users. Add one Organizational Unit item per OU, keep the first as AND, and set the rest to OR. Check "Direct member only" unless you also want child OUs. Each OU may contain other people.'
            $recs.Add((New-IltRecommendation -Rank 5 -Quality 'Possible' -Coverage 100 -Type 'Organizational Unit' -IltItem 'Organizational Unit' -Target $target -Filter $filter -Binding '' -Notes $notes))
        }
    }

    foreach ($row in (Get-Collection $ScalarRows)) {
        $coverage = [double]$row.PercentMatching
        $ldap = [string]$row.LdapAttribute
        if ([string]::IsNullOrWhiteSpace($ldap)) { continue }
        if (-not $row.FullyCommon -and $coverage -lt $MinPercent -and [string]::IsNullOrWhiteSpace([string]$row.OrLdapFilter)) { continue }

        if ($row.FullyCommon) {
            $target = [string]$row.Attribute + ' = ' + [string]$row.TopValue
            $notes = 'Every imported user has this value. Item-level targeting has no generic "user property" rule. Use an LDAP Query item and keep (sAMAccountName=%USERNAME%) so the filter describes the logging-on user. A filter of only (' + $ldap + '=' + (ConvertTo-LdapFilterValue ([string]$row.TopValue)) + ') is true for everyone as soon as any user in the search base has that value. Other people who share the value and were not in the CSV will also match.'
            $recs.Add((New-IltRecommendation -Rank 3 -Quality 'Recommended' -Coverage $coverage -Type 'LDAP Query' -IltItem 'LDAP Query' -Target $target -Filter ([string]$row.LdapFilter) -Binding $binding -Notes $notes))
        } elseif (-not [string]::IsNullOrWhiteSpace([string]$row.OrLdapFilter)) {
            $target = [string]$row.Attribute + ' is one of ' + [string]$row.DistinctValueList
            $notes = 'The imported users share ' + $row.DistinctValues + ' values of ' + $row.Attribute + ' and none are blank. One LDAP Query item can OR them together. People outside the CSV who have any of these values will also match.'
            $recs.Add((New-IltRecommendation -Rank 7 -Quality 'Possible' -Coverage 100 -Type 'LDAP Query' -IltItem 'LDAP Query' -Target $target -Filter ([string]$row.OrLdapFilter) -Binding $binding -Notes $notes))
        } elseif ($coverage -ge $MinPercent) {
            $target = [string]$row.Attribute + ' = ' + [string]$row.TopValue
            $notes = 'Closest value covers ' + $coverage + '% (' + $row.UsersMatching + ' of ' + $row.TotalUsers + '). Not covered: ' + [string]$row.UsersMissing + '. Use an LDAP Query anchored with (sAMAccountName=%USERNAME%). There is no Item-level targeting "user property" condition.'
            $recs.Add((New-IltRecommendation -Rank 7 -Quality 'Possible' -Coverage $coverage -Type 'LDAP Query' -IltItem 'LDAP Query' -Target $target -Filter ([string]$row.LdapFilter) -Binding $binding -Notes $notes))
        }
    }

    $sorted = @($recs | Sort-Object Rank, @{ Expression = 'Coverage'; Descending = $true }, Target)
    $ordered = New-Object System.Collections.Generic.List[object]
    foreach ($rec in $sorted) { $ordered.Add($rec) }
    return ,$ordered
}

function Get-FullAnalysis {
    param(
        $Users,
        [double]$MinPercent = 50,
        [string]$DomainDn,
        [string]$NetBiosName,
        [bool]$TokenGroupsResolved = $false
    )

    $userList = Get-UserList $Users
    $scalar = Get-ScalarAttributeCommonality $userList
    $groups = Get-GroupCommonality $userList
    $ou = Get-OUCommonality $userList
    $health = Get-AccountHealth $userList
    $paths = Get-PathPrefixInsights $userList
    $recs = Get-IltRecommendations -ScalarRows $scalar -GroupRows $groups -OuResult $ou -MinPercent $MinPercent -DomainDn $DomainDn -NetBiosName $NetBiosName -TokenGroupsResolved:$TokenGroupsResolved

    [PSCustomObject]@{
        Scalar              = $scalar
        Groups              = $groups
        OU                  = $ou
        Health              = $health
        Paths               = $paths
        Recommendations     = $recs
        TokenGroupsResolved = [bool]$TokenGroupsResolved
        UserCount           = $userList.Count
        MinPercent          = $MinPercent
    }
}

function Get-UserDetailRows {
    param($Users)
    $rows = New-Object System.Collections.Generic.List[object]
    $props = @(
        'SamAccountName', 'Name', 'DisplayName', 'Enabled', 'Department', 'Division', 'Title',
        'Company', 'Office', 'City', 'State', 'Country', 'CountryName', 'EmployeeType',
        'EmployeeID', 'Manager', 'ManagerName', 'EmailAddress', 'ParentOU', 'HomeDirectory',
        'HomeDrive', 'ProfilePath', 'ScriptPath', 'LockedOut', 'PasswordExpired',
        'PasswordNeverExpires', 'LastLogonDate', 'WhenCreated'
    )
    foreach ($user in (Get-UserList $Users)) {
        $groupNames = New-Object System.Collections.Generic.List[string]
        foreach ($group in (Get-Collection $user.Groups)) {
            $normalized = Get-NormalizedGroup $group
            if ($null -eq $normalized) { continue }
            $label = [string]$normalized.SamAccountName
            if ([string]::IsNullOrWhiteSpace($label)) { $label = [string]$normalized.Name }
            if ($label) { $groupNames.Add($label) }
        }
        $row = [ordered]@{
            SamAccountName = [string]$user.SamAccountName
            Groups         = ($groupNames -join '; ')
        }
        foreach ($prop in $props) {
            if ($prop -eq 'SamAccountName') { continue }
            $row[$prop] = Get-AttributeText $user $prop
        }
        $rows.Add([PSCustomObject]$row)
    }
    return ,$rows
}

function New-GroupMembershipFilter {
    param(
        [Parameter(Mandatory = $true)][string]$GroupDistinguishedName,
        $PrimaryGroupId,
        [bool]$Nested
    )

    $escaped = ConvertTo-LdapFilterValue $GroupDistinguishedName
    if ($Nested) {
        $memberClause = '(memberOf:1.2.840.113556.1.4.1941:=' + $escaped + ')'
    } else {
        $memberClause = '(memberOf=' + $escaped + ')'
    }

    $ridText = ''
    if ($null -ne $PrimaryGroupId -and "$PrimaryGroupId" -ne '') {
        $ridText = "$PrimaryGroupId"
    }
    if ($ridText -match '^\d+$') {
        return '(|' + $memberClause + '(primaryGroupID=' + $ridText + '))'
    }
    return $memberClause
}

function Get-GroupReconciliation {
    param(
        $CsvNames,
        $MemberNames,
        $NonUserMembers,
        $TokenOnlyNames,
        [string]$GroupName
    )

    $csv = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in (Get-Collection $CsvNames)) {
        $text = ConvertTo-SamAccountName ([string]$name)
        if ($text) { [void]$csv.Add($text) }
    }
    $members = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in (Get-Collection $MemberNames)) {
        $text = ConvertTo-SamAccountName ([string]$name)
        if ($text) { [void]$members.Add($text) }
    }
    $tokenOnly = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in (Get-Collection $TokenOnlyNames)) {
        $text = ConvertTo-SamAccountName ([string]$name)
        if ($text -and -not $members.Contains($text)) { [void]$tokenOnly.Add($text) }
    }

    $rows = New-Object System.Collections.Generic.List[object]
    $matched = 0
    $tokenMatched = 0
    $missing = 0
    $extra = 0
    $nonUser = 0

    foreach ($name in $csv) {
        if ($members.Contains($name)) {
            $rows.Add([PSCustomObject]@{ SamAccountName = $name; Status = 'Matched'; Notes = 'In the CSV and a member of the group.' })
            $matched++
        } elseif ($tokenOnly.Contains($name)) {
            $rows.Add([PSCustomObject]@{ SamAccountName = $name; Status = 'Matched (logon token only)'; Notes = 'Not returned by memberOf. The group is in the user access token (nested security group or primary-group nesting). Security Group item-level targeting will match.' })
            $tokenMatched++
        } else {
            $rows.Add([PSCustomObject]@{ SamAccountName = $name; Status = 'Missing from group'; Notes = 'In the CSV but not a member of this group.' })
            $missing++
        }
    }
    foreach ($name in $members) {
        if (-not $csv.Contains($name)) {
            $rows.Add([PSCustomObject]@{ SamAccountName = $name; Status = 'Extra in group'; Notes = 'Member of the group but not in the CSV.' })
            $extra++
        }
    }
    foreach ($entry in (Get-Collection $NonUserMembers)) {
        $label = ''
        $className = ''
        if ($entry -is [string]) {
            $label = [string]$entry
        } else {
            $label = [string]$entry.Name
            $className = [string]$entry.ObjectClass
        }
        if ([string]::IsNullOrWhiteSpace($label)) { continue }
        $note = 'Group contains a non-user object.'
        if ($className) { $note = 'objectClass: ' + $className }
        $rows.Add([PSCustomObject]@{ SamAccountName = $label; Status = 'Non-user member'; Notes = $note })
        $nonUser++
    }

    $ordered = New-Object System.Collections.Generic.List[object]
    $rank = @{
        'Missing from group'          = 0
        'Matched (logon token only)'  = 1
        'Matched'                     = 2
        'Extra in group'              = 3
        'Non-user member'             = 4
    }
    $sorted = @($rows | Sort-Object @{ Expression = { $rank[$_.Status] } }, SamAccountName)
    foreach ($row in $sorted) { $ordered.Add($row) }

    [PSCustomObject]@{
        GroupName    = $GroupName
        Rows         = $ordered
        CsvCount     = $csv.Count
        MemberCount  = $members.Count
        Matched      = $matched
        TokenMatched = $tokenMatched
        Missing      = $missing
        Extra        = $extra
        NonUser      = $nonUser
    }
}

function Add-HtmlTable {
    param($Builder, $Objects, [string[]]$Properties)
    $items = Get-Collection $Objects
    if ($items.Count -eq 0) {
        [void]$Builder.AppendLine('<p class="empty">None</p>')
        return
    }

    [void]$Builder.AppendLine('<table><thead><tr>')
    foreach ($property in $Properties) {
        [void]$Builder.Append('<th>')
        [void]$Builder.Append((ConvertTo-HtmlEncoded $property))
        [void]$Builder.AppendLine('</th>')
    }
    [void]$Builder.AppendLine('</tr></thead><tbody>')

    foreach ($item in $items) {
        $class = ''
        $propertyNames = @($item.PSObject.Properties.Name)
        $broad = ($propertyNames -contains 'IsBroad' -and $item.IsBroad) -or ($propertyNames -contains 'IsPrivileged' -and $item.IsPrivileged)
        $notIlt = ($propertyNames -contains 'IltEligible' -and $item.IltEligible -eq $false)
        if ($propertyNames -contains 'Quality' -and [string]$item.Quality -eq 'Recommended') { $class = 'good' }
        elseif ($propertyNames -contains 'Quality' -and [string]$item.Quality -eq 'Possible') { $class = 'possible' }
        elseif ($propertyNames -contains 'Quality' -and [string]$item.Quality -eq 'Poor') { $class = 'poor' }
        elseif ($broad -or $notIlt) { $class = 'poor' }
        elseif ($propertyNames -contains 'FullyCommon' -and $item.FullyCommon) { $class = 'good' }
        elseif ($propertyNames -contains 'PercentMatching' -and [double]$item.PercentMatching -ge 80) { $class = 'possible' }
        elseif ($propertyNames -contains 'PercentCoverage' -and [double]$item.PercentCoverage -ge 80) { $class = 'possible' }
        if ($class) {
            [void]$Builder.AppendLine('<tr class="' + $class + '">')
        } else {
            [void]$Builder.AppendLine('<tr>')
        }
        foreach ($property in $Properties) {
            $value = ''
            if ($propertyNames -contains $property) { $value = [string]$item.$property }
            [void]$Builder.Append('<td>')
            [void]$Builder.Append((ConvertTo-HtmlEncoded $value))
            [void]$Builder.AppendLine('</td>')
        }
        [void]$Builder.AppendLine('</tr>')
    }
    [void]$Builder.AppendLine('</tbody></table>')
}

function New-IltHtmlReport {
    param(
        $Analysis,
        $Users,
        $NotFound,
        $GroupCheck,
        [string]$Domain,
        [string]$Server,
        [string]$Timestamp,
        [int]$ImportedCount
    )

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<title>AD User ILT Analysis</title><style>')
    [void]$sb.AppendLine('body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1c2330;background:#f7f8fa;}')
    [void]$sb.AppendLine('h1{color:#182a44;margin-bottom:4px;} h2{color:#182a44;margin-top:28px;border-bottom:2px solid #d5dbe3;padding-bottom:4px;}')
    [void]$sb.AppendLine('table{border-collapse:collapse;width:100%;background:#fff;margin:8px 0 18px;}')
    [void]$sb.AppendLine('th,td{border:1px solid #d5dbe3;padding:6px 8px;vertical-align:top;text-align:left;font-size:13px;}')
    [void]$sb.AppendLine('th{background:#182a44;color:#fff;} tr.good{background:#e7f6ee;} tr.possible{background:#fff8e6;} tr.poor{background:#fdecea;}')
    [void]$sb.AppendLine('code,pre{font-family:Consolas,monospace;background:#eef2f6;padding:2px 4px;} pre{padding:10px;white-space:pre-wrap;word-break:break-word;}')
    [void]$sb.AppendLine('.meta{color:#526070;} .empty{color:#6b7280;font-style:italic;} .card{background:#fff;border:1px solid #d5dbe3;padding:12px 14px;margin:8px 0;}')
    [void]$sb.AppendLine('</style></head><body>')
    [void]$sb.AppendLine('<h1>AD User Item-Level Targeting Analysis</h1>')
    [void]$sb.AppendLine('<p class="meta">Generated ' + (ConvertTo-HtmlEncoded $Timestamp) + ' &middot; Domain ' + (ConvertTo-HtmlEncoded $Domain) + ' &middot; Server ' + (ConvertTo-HtmlEncoded $Server) + '</p>')
    [void]$sb.AppendLine('<p>Imported ' + $ImportedCount + ' name(s). Resolved ' + [int]$Analysis.UserCount + ' user(s).</p>')
    [void]$sb.AppendLine('<div class="card"><strong>How to apply a result.</strong> Drive Map item-level targeting does not have a generic user-property condition. Use Security Group when a group covers the list, Organizational Unit when they share an OU, or an LDAP Query that includes <code>(sAMAccountName=%USERNAME%)</code>. An LDAP filter without the user name matches everybody as soon as any user in the search base has that attribute.</div>')

    [void]$sb.AppendLine('<h2>Recommended targeting rules</h2>')
    Add-HtmlTable -Builder $sb -Objects $Analysis.Recommendations -Properties @('Quality', 'Coverage', 'IltItem', 'Target', 'Filter', 'Binding', 'Notes')

    [void]$sb.AppendLine('<h2>Account health</h2>')
    Add-HtmlTable -Builder $sb -Objects $Analysis.Health -Properties @('Issue', 'Count', 'Accounts')

    [void]$sb.AppendLine('<h2>Attribute commonality</h2>')
    Add-HtmlTable -Builder $sb -Objects $Analysis.Scalar -Properties @('Attribute', 'LdapAttribute', 'TopValue', 'UsersMatching', 'UsersBlank', 'TotalUsers', 'PercentMatching', 'DistinctValues', 'FullyCommon', 'LdapFilter')

    [void]$sb.AppendLine('<h2>Group commonality</h2>')
    if (-not $Analysis.TokenGroupsResolved) {
        [void]$sb.AppendLine('<p class="empty">Nested security groups were not expanded (tokenGroups). Parent groups can still match at logon.</p>')
    }
    Add-HtmlTable -Builder $sb -Objects $Analysis.Groups -Properties @('GroupName', 'SamAccountName', 'GroupCategory', 'GroupScope', 'UsersInGroup', 'TotalUsers', 'PercentCoverage', 'FullyCommon', 'IsBroad', 'IltEligible', 'UsersMissing')

    [void]$sb.AppendLine('<h2>Organizational units</h2>')
    if ($null -ne $Analysis.OU) {
        Add-HtmlTable -Builder $sb -Objects $Analysis.OU.ParentOUs -Properties @('ParentOU', 'UserCount', 'PercentOfTotal')
        [void]$sb.AppendLine('<p><strong>Common ancestor:</strong> ' + (ConvertTo-HtmlEncoded ([string]$Analysis.OU.CommonAncestor)) + '</p>')
    }

    [void]$sb.AppendLine('<h2>Shared path prefixes</h2>')
    Add-HtmlTable -Builder $sb -Objects $Analysis.Paths -Properties @('Attribute', 'SharedPrefix', 'Populated', 'TotalUsers', 'Note')

    $missing = Get-Collection $NotFound
    [void]$sb.AppendLine('<h2>CSV entries not found in Active Directory</h2>')
    if ($missing.Count -eq 0) {
        [void]$sb.AppendLine('<p class="empty">None</p>')
    } else {
        [void]$sb.AppendLine('<ul>')
        foreach ($name in $missing) {
            [void]$sb.AppendLine('<li>' + (ConvertTo-HtmlEncoded ([string]$name)) + '</li>')
        }
        [void]$sb.AppendLine('</ul>')
    }

    if ($null -ne $GroupCheck) {
        [void]$sb.AppendLine('<h2>Group reconciliation: ' + (ConvertTo-HtmlEncoded ([string]$GroupCheck.GroupName)) + '</h2>')
        [void]$sb.AppendLine('<p>Matched ' + $GroupCheck.Matched + ' &middot; Token only ' + $GroupCheck.TokenMatched + ' &middot; Missing ' + $GroupCheck.Missing + ' &middot; Extra ' + $GroupCheck.Extra + ' &middot; Non-user ' + $GroupCheck.NonUser + '</p>')
        Add-HtmlTable -Builder $sb -Objects $GroupCheck.Rows -Properties @('SamAccountName', 'Status', 'Notes')
    }

    [void]$sb.AppendLine('<h2>Per-user detail</h2>')
    $detail = Get-UserDetailRows $Users
    Add-HtmlTable -Builder $sb -Objects $detail -Properties @('SamAccountName', 'Name', 'Enabled', 'Department', 'Title', 'Office', 'Company', 'City', 'State', 'EmployeeType', 'ParentOU', 'HomeDirectory', 'Groups')
    [void]$sb.AppendLine('</body></html>')
    return $sb.ToString()
}

function New-IltTextReport {
    param($Analysis, [string]$Domain, [string]$Timestamp)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('AD User Item-Level Targeting Analysis')
    [void]$sb.AppendLine('Generated: ' + $Timestamp)
    [void]$sb.AppendLine('Domain: ' + $Domain)
    [void]$sb.AppendLine('Users analyzed: ' + [int]$Analysis.UserCount)
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Item-level targeting has no "User Property" condition.')
    [void]$sb.AppendLine('Use Security Group, Organizational Unit, or an LDAP Query that includes (sAMAccountName=%USERNAME%).')
    [void]$sb.AppendLine('')
    foreach ($rec in (Get-Collection $Analysis.Recommendations)) {
        [void]$sb.AppendLine('[' + $rec.Quality + '] ' + $rec.IltItem + '  ' + $rec.Coverage + '%')
        [void]$sb.AppendLine('Target: ' + $rec.Target)
        [void]$sb.AppendLine('Filter: ' + $rec.Filter)
        if ([string]$rec.Binding) { [void]$sb.AppendLine('Binding: ' + $rec.Binding) }
        [void]$sb.AppendLine($rec.Notes)
        [void]$sb.AppendLine($rec.Steps)
        [void]$sb.AppendLine('')
    }
    return $sb.ToString()
}

function New-GroupDirectory {
    param($Groups)
    $map = @{}
    foreach ($group in (Get-Collection $Groups)) {
        if ($null -eq $group) { continue }
        $dn = [string]$group.DistinguishedName
        $sid = [string]$group.ObjectSid
        if (-not [string]::IsNullOrWhiteSpace($dn)) { $map[$dn] = $group }
        if (-not [string]::IsNullOrWhiteSpace($sid)) { $map[$sid] = $group }
    }
    return $map
}

function Get-DirectoryGroup {
    param($Directory, [AllowNull()][string]$Key)
    if ($null -eq $Directory -or [string]::IsNullOrWhiteSpace($Key)) { return $null }
    if ($Directory.ContainsKey($Key)) { return $Directory[$Key] }
    return $null
}

function Merge-UserGroups {
    <#
        MemberOf is a single string when the user is in only one group.
        Enumerating that string yields characters, which is how the original
        script invented groups named "C", "N", "=" and so on. Primary group
        membership is not in MemberOf at all; it has to be added from the
        PrimaryGroup DN. tokenGroups (SID list) supplies nested security groups.
    #>
    param(
        $MemberOf,
        [AllowNull()][string]$PrimaryGroupDn,
        $TokenSids,
        $Directory
    )

    $byKey = @{}

    $direct = New-Object System.Collections.Generic.List[string]
    foreach ($dn in (Get-Collection $MemberOf)) {
        $text = [string]$dn
        if (-not [string]::IsNullOrWhiteSpace($text)) { $direct.Add($text.Trim()) }
    }

    $primary = ''
    if (-not [string]::IsNullOrWhiteSpace($PrimaryGroupDn)) { $primary = $PrimaryGroupDn.Trim() }

    foreach ($dn in $direct) {
        $isPrimary = ($primary -and ($dn -eq $primary))
        Add-MergedGroup -Map $byKey -Directory $Directory -Dn $dn -Sid '' -IsDirect $true -IsPrimary $isPrimary -InToken $false
    }
    if ($primary) {
        $already = $false
        foreach ($dn in $direct) {
            if ($dn -eq $primary) { $already = $true; break }
        }
        if (-not $already) {
            Add-MergedGroup -Map $byKey -Directory $Directory -Dn $primary -Sid '' -IsDirect $false -IsPrimary $true -InToken $false
        }
    }
    foreach ($sid in (Get-Collection $TokenSids)) {
        $text = [string]$sid
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        Add-MergedGroup -Map $byKey -Directory $Directory -Dn '' -Sid $text.Trim() -IsDirect $false -IsPrimary $false -InToken $true
    }

    $groups = New-Object System.Collections.Generic.List[object]
    foreach ($key in @($byKey.Keys)) { $groups.Add($byKey[$key]) }
    return ,$groups
}

function Add-MergedGroup {
    param(
        $Map,
        $Directory,
        [string]$Dn,
        [string]$Sid,
        [bool]$IsDirect,
        [bool]$IsPrimary,
        [bool]$InToken
    )

    $meta = Get-DirectoryGroup -Directory $Directory -Key $Dn
    if ($null -eq $meta) { $meta = Get-DirectoryGroup -Directory $Directory -Key $Sid }

    $sam = ''
    $name = ''
    $dnValue = $Dn
    $sidValue = $Sid
    $category = ''
    $scope = ''
    if ($null -ne $meta) {
        $sam = [string]$meta.SamAccountName
        $name = [string]$meta.Name
        if ([string]$meta.DistinguishedName) { $dnValue = [string]$meta.DistinguishedName }
        if ([string]$meta.ObjectSid) { $sidValue = [string]$meta.ObjectSid }
        $category = [string]$meta.GroupCategory
        $scope = [string]$meta.GroupScope
    }
    if ([string]::IsNullOrWhiteSpace($name) -and $dnValue) { $name = Get-RdnValue $dnValue }
    if ([string]::IsNullOrWhiteSpace($sam)) { $sam = $name }
    if ([string]::IsNullOrWhiteSpace($sam) -and $sidValue) { $sam = $sidValue }
    if ([string]::IsNullOrWhiteSpace($name)) { $name = $sam }
    if ([string]::IsNullOrWhiteSpace($sam) -and [string]::IsNullOrWhiteSpace($dnValue)) { return }

    if ($sidValue) {
        $key = 'SID:' + $sidValue
    } elseif ($dnValue) {
        $key = 'DN:' + $dnValue
    } else {
        $key = 'NAME:' + $sam
    }

    if ($Map.ContainsKey($key)) {
        $existing = $Map[$key]
        if ($IsDirect) { $existing.IsDirect = $true }
        if ($IsPrimary) { $existing.IsPrimary = $true }
        if ($InToken) { $existing.InToken = $true }
        if ($category -and -not [string]$existing.GroupCategory) { $existing.GroupCategory = $category }
        return
    }

    $Map[$key] = [PSCustomObject]@{
        SamAccountName    = $sam
        Name              = $name
        DistinguishedName = $dnValue
        ObjectSid         = $sidValue
        GroupCategory     = $category
        GroupScope        = $scope
        IsPrimary         = [bool]$IsPrimary
        IsDirect          = [bool]$IsDirect
        InToken           = [bool]$InToken
    }
}

function ConvertTo-SidList {
    param($TokenGroups)
    $sids = New-Object System.Collections.Generic.List[string]
    if ($null -eq $TokenGroups) { return ,$sids }

    $blobs = New-Object System.Collections.Generic.List[object]
    if ($TokenGroups -is [byte[]]) {
        $blobs.Add($TokenGroups)
    } elseif ($TokenGroups -is [System.Security.Principal.SecurityIdentifier]) {
        $sids.Add($TokenGroups.Value)
    } elseif ($TokenGroups -is [string]) {
        if ($TokenGroups -match '^S-1-') { $sids.Add($TokenGroups) }
    } else {
        foreach ($item in (Get-Collection $TokenGroups)) {
            if ($item -is [byte[]]) {
                $blobs.Add($item)
            } elseif ($item -is [System.Security.Principal.SecurityIdentifier]) {
                $sids.Add($item.Value)
            } elseif ($item -is [string] -and $item -match '^S-1-') {
                $sids.Add([string]$item)
            }
        }
    }

    foreach ($blob in $blobs) {
        try {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($blob, 0)
            $sids.Add($sid.Value)
        } catch {
            continue
        }
    }
    return ,$sids
}

function ConvertTo-LdapSidValue {
    param([Parameter(Mandatory = $true)][string]$Sid)
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $bytes = New-Object byte[] ($sidObj.BinaryLength)
    $sidObj.GetBinaryForm($bytes, 0)
    $sb = New-Object System.Text.StringBuilder
    foreach ($byte in $bytes) {
        [void]$sb.AppendFormat('\{0:x2}', $byte)
    }
    return $sb.ToString()
}

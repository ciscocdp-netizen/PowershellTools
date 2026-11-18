# Logic tests for ILTAnalysis.Core.ps1. No Active Directory or WinForms required.
$ErrorActionPreference = 'Stop'
$core = Join-Path $PSScriptRoot '..\ILTAnalysis.Core.ps1'
. $core

$script:Failures = New-Object System.Collections.Generic.List[string]

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        $script:Failures.Add("FAIL: $Message")
    }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ("$Actual" -ne "$Expected") {
        $script:Failures.Add("FAIL: $Message`n  Actual:   [$Actual]`n  Expected: [$Expected]")
    }
}

function New-Group {
    param(
        [string]$Name,
        [string]$Sam = $Name,
        [string]$Category = 'Security',
        [string]$Scope = 'Global',
        [string]$Dn = '',
        [string]$Sid = '',
        [bool]$IsPrimary = $false,
        [bool]$IsDirect = $true,
        [bool]$InToken = $false
    )
    if (-not $Dn) { $Dn = "CN=$Name,OU=Groups,DC=contoso,DC=com" }
    [PSCustomObject]@{
        SamAccountName    = $Sam
        Name              = $Name
        DistinguishedName = $Dn
        ObjectSid         = $Sid
        GroupCategory     = $Category
        GroupScope        = $Scope
        IsPrimary         = $IsPrimary
        IsDirect          = $IsDirect
        InToken           = $InToken
    }
}

function New-TestUser {
    param(
        [string]$Sam,
        [string]$Department = '',
        [string]$Dn,
        $Groups,
        [string]$HomeDirectory = '',
        [bool]$Enabled = $true,
        [string]$Office = '',
        [string]$Title = '',
        [bool]$LockedOut = $false
    )
    if (-not $Dn) { $Dn = "CN=$Sam,OU=Sales,OU=Users,DC=contoso,DC=com" }
    [PSCustomObject]@{
        SamAccountName       = $Sam
        Name                 = $Sam
        Enabled              = $Enabled
        Department           = $Department
        Title                = $Title
        Office               = $Office
        ParentOU             = (Get-ParentOuDn $Dn)
        DistinguishedName    = $Dn
        OUComponents         = (Get-OUComponents $Dn)
        Groups               = $Groups
        HomeDirectory        = $HomeDirectory
        HomeDrive            = ''
        LockedOut            = $LockedOut
        PasswordExpired      = $false
        PasswordNeverExpires = $false
    }
}

try {
    $one = Get-Collection 'Finance'
    Assert-Equal $one.Count 1 'A single group name is one item, not one item per character'
    Assert-Equal $one[0] 'Finance' 'Single group name round-trips'

    $props = Get-ScalarPropertyNames
    $officeHits = 0
    $physicalHits = 0
    foreach ($prop in $props) {
        if ($prop -eq 'Office') { $officeHits++ }
        if ($prop -eq 'PhysicalDeliveryOffice') { $physicalHits++ }
    }
    Assert-Equal $officeHits 1 'Office is scored once'
    Assert-Equal $physicalHits 0 'physicalDeliveryOfficeName is not a second attribute'
    Assert-Equal (Get-LdapAttributeName 'Office') 'physicalDeliveryOfficeName' 'Office maps to the LDAP attribute'
    Assert-Equal (Get-LdapAttributeName 'City') 'l' 'City maps to l'
    Assert-Equal (Get-LdapAttributeName 'extensionAttribute7') 'extensionAttribute7' 'extensionAttribute LDAP name'

    Assert-Equal (ConvertTo-LdapFilterValue 'Sales (East)\Team*A') 'Sales \28East\29\5cTeam\2aA' 'LDAP filter escaping'
    $anchored = New-AnchoredLdapFilter -Clauses '(department=Finance)'
    Assert-True ($anchored.Contains('(sAMAccountName=%USERNAME%)')) 'LDAP filters are anchored to the logging-on user'
    Assert-True ($anchored.StartsWith('(&')) 'LDAP filter is a conjunction'

    Assert-Equal (ConvertTo-SamAccountName ' CONTOSO\jdoe ') 'jdoe' 'DOMAIN\sam is reduced to the sam'
    Assert-Equal (ConvertTo-SamAccountName '"jdoe"') 'jdoe' 'Quoted sam is unwrapped'
    Assert-Equal (ConvertTo-SamAccountName 'jdoe@contoso.com') 'jdoe@contoso.com' 'UPN is preserved for a UPN search'
    Assert-Equal (ConvertTo-SafeFileName 'Finance:Team*') 'Finance_Team_' 'File name strips invalid characters'

    $parts = Split-DistinguishedName 'CN=Doe\, John,OU=Sales,DC=contoso,DC=com'
    Assert-Equal $parts.Count 4 'Escaped comma does not split the CN'
    Assert-Equal (Get-RdnValue 'CN=Doe\, John,OU=Sales,DC=contoso,DC=com') 'Doe, John' 'Escaped CN unescapes to a comma'
    Assert-Equal (Get-ParentOuDn 'CN=Doe\, John,OU=Sales,DC=contoso,DC=com') 'OU=Sales,DC=contoso,DC=com' 'Parent OU ignores the escaped comma'

    $singleOu = Get-Collection (Get-OUComponents 'CN=A,DC=com')
    Assert-Equal $singleOu.Count 1 'A one-part OU path is not indexed as characters'
    Assert-Equal $singleOu[0] 'DC=com' 'Single OU component value'
    Assert-True (Test-DomainDistinguishedName 'DC=contoso,DC=com') 'Domain DN detected'
    Assert-True (-not (Test-DomainDistinguishedName 'OU=Users,DC=contoso,DC=com')) 'OU DN is not the domain root'

    $multi = Get-Collection (Get-OUComponents 'CN=A,OU=Sales,OU=Users,DC=contoso,DC=com')
    Assert-Equal $multi.Count 4 'Four OU/DC components'
    Assert-Equal $multi[0] 'DC=com' 'Components are root-first'
    Assert-Equal $multi[3] 'OU=Sales' 'Leaf OU is last'

    $merged = Merge-UserGroups -MemberOf 'CN=Finance,OU=Groups,DC=contoso,DC=com' -PrimaryGroupDn 'CN=Domain Users,CN=Users,DC=contoso,DC=com' -TokenSids $null -Directory $null
    $mergedItems = Get-Collection $merged
    Assert-Equal $mergedItems.Count 2 'One MemberOf string plus the primary group is two groups, not a character stream'
    $mergedNames = @($mergedItems | ForEach-Object { $_.Name })
    Assert-True ($mergedNames -contains 'Finance') 'Direct group CN survived'
    Assert-True ($mergedNames -contains 'Domain Users') 'Primary group was kept'
    $charGroups = @($mergedItems | Where-Object { $_.Name.Length -eq 1 })
    Assert-Equal @($charGroups).Count 0 'No single-character fake groups'

    $escapedGroups = Get-Collection (Merge-UserGroups -MemberOf 'CN=Team\, Special,OU=Groups,DC=contoso,DC=com' -PrimaryGroupDn $null -TokenSids $null -Directory $null)
    Assert-Equal $escapedGroups.Count 1 'Escaped group CN is one group'
    Assert-Equal $escapedGroups[0].Name 'Team, Special' 'Escaped group CN is unescaped'

    $catalog = New-GroupDirectory @(
        [PSCustomObject]@{
            SamAccountName = 'Finance'; Name = 'Finance Team'
            DistinguishedName = 'CN=Finance Team,OU=Groups,DC=contoso,DC=com'
            ObjectSid = 'S-1-5-21-1-2-1111'; GroupCategory = 'Security'; GroupScope = 'Global'
        }
    )
    $resolved = Get-Collection (Merge-UserGroups -MemberOf 'CN=Finance Team,OU=Groups,DC=contoso,DC=com' -PrimaryGroupDn $null -TokenSids @('S-1-5-21-1-2-1111') -Directory $catalog)
    Assert-Equal $resolved.Count 1 'Direct DN and token SID collapse to one group'
    Assert-True ($resolved[0].IsDirect -and $resolved[0].InToken) 'Merged group records both direct and token membership'
    Assert-Equal $resolved[0].SamAccountName 'Finance' 'Resolved group uses sAMAccountName, not only the CN'

    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ('ilt-test-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temp | Out-Null
    try {
        $headerless = Join-Path $temp 'headerless.csv'
        [System.IO.File]::WriteAllText($headerless, "jdoe`r`nasmith`r`n")
        $imported = Import-SamAccountNamesFromFile $headerless
        Assert-Equal $imported.Mode 'Headerless' 'Two-line file without a header is headerless'
        Assert-Equal $imported.Names.Count 2 'Headerless import keeps the first user'
        Assert-True ($imported.Names -contains 'jdoe' -and $imported.Names -contains 'asmith') 'Both headerless names are present'

        $oneLine = Join-Path $temp 'one.txt'
        [System.IO.File]::WriteAllText($oneLine, 'jdoe')
        $oneImport = Import-SamAccountNamesFromFile $oneLine
        Assert-Equal $oneImport.Names.Count 1 'A single username is one user, not a character count'
        Assert-Equal $oneImport.Names[0] 'jdoe' 'Single username value'

        $headerOnly = Join-Path $temp 'header-only.csv'
        [System.IO.File]::WriteAllText($headerOnly, "SamAccountName`r`n")
        $emptyImport = Import-SamAccountNamesFromFile $headerOnly
        Assert-Equal $emptyImport.Names.Count 0 'A header with no rows does not invent a user named SamAccountName'

        $headed = Join-Path $temp 'headed.csv'
        $headedText = "Name,SamAccountName,Department`r`n`"Doe, Jane`",jdoe,Sales`r`n`"Doe, Jane`",JDOE,Sales`r`nCONTOSO\asmith,asmith,IT`r`n"
        # The third data row is Name=CONTOSO\asmith, Sam=asmith. Duplicate jdoe differs only by case.
        [System.IO.File]::WriteAllText($headed, "Name,SamAccountName,Department`r`n`"Doe, Jane`",jdoe,Sales`r`n`"Smith, Ann`",JDOE,Sales`r`n")
        $headedImport = Import-SamAccountNamesFromFile $headed
        Assert-Equal $headedImport.Mode 'Header' 'Known header is detected'
        Assert-Equal $headedImport.Column 'SamAccountName' 'SamAccountName column wins over Name'
        Assert-Equal $headedImport.Names.Count 1 'Case-insensitive duplicate is removed'
        Assert-Equal $headedImport.DuplicateCount 1 'Duplicate is counted'
        Assert-Equal $headedImport.Names[0] 'jdoe' 'First casing is kept and the Name column is not imported'

        $domainRow = Join-Path $temp 'domain.csv'
        [System.IO.File]::WriteAllText($domainRow, "Username`r`nCONTOSO\asmith`r`n")
        $domainImport = Import-SamAccountNamesFromFile $domainRow
        Assert-Equal $domainImport.Names[0] 'asmith' 'CSV DOMAIN\user values are normalized'

        $employee = Join-Path $temp 'employee.csv'
        [System.IO.File]::WriteAllText($employee, "Employee`r`njdoe`r`nasmith`r`n")
        $employeeImport = Import-SamAccountNamesFromFile $employee
        Assert-Equal $employeeImport.Names.Count 2 'Generic Employee header is not treated as a user'
        Assert-True (-not ($employeeImport.Names -contains 'Employee')) 'Employee label is excluded'

        $ambiguous = Join-Path $temp 'ambiguous.csv'
        [System.IO.File]::WriteAllText($ambiguous, "Foo,Bar`r`njdoe,Sales`r`nasmith,IT`r`n")
        $ambiguousImport = Import-SamAccountNamesFromFile $ambiguous
        Assert-Equal $ambiguousImport.Mode 'NeedsColumn' 'Unknown multi-column CSV asks for a column'
        $chosen = Select-SamNamesFromColumn -Text ([System.IO.File]::ReadAllText($ambiguous)) -ColumnName 'Foo'
        Assert-Equal $chosen.Names.Count 2 'Chosen column returns both users'
        Assert-True ($chosen.Names -contains 'jdoe') 'Chosen column value'

        $bomPath = Join-Path $temp 'bom.csv'
        $accented = ([string][char]0x00E9) + 'mile'
        $utf8 = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllBytes($bomPath, $utf8.GetBytes("SamAccountName`r`n$accented`r`n"))
        $bomImport = Import-SamAccountNamesFromFile $bomPath
        Assert-Equal $bomImport.Names.Count 1 'UTF-8 BOM CSV imports one user'
        Assert-Equal $bomImport.Names[0] $accented 'UTF-8 name is preserved'
    } finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }

    $solo = New-TestUser -Sam 'jdoe' -Department 'Engineering' -Groups @(New-Group -Name 'Finance' -Sam 'Finance')
    $soloScalar = Get-ScalarAttributeCommonality $solo
    $soloRows = Get-Collection $soloScalar
    Assert-Equal $soloRows.Count 1 'One populated attribute produces one row'
    Assert-Equal $soloRows[0].UsersMatching 1 'One user does not report a match count equal to the value length'
    Assert-Equal $soloRows[0].TotalUsers 1 'Total users is 1'
    Assert-True ($soloRows[0].FullyCommon) 'A single populated value is fully common'
    Assert-Equal $soloRows[0].LdapAttribute 'department' 'Department LDAP name'

    $finance = New-Group -Name 'Finance Team' -Sam 'Finance' -Sid 'S-1-5-21-9-9-1111'
    $domainUsers = New-Group -Name 'Domain Users' -Sam 'Domain Users' -Sid 'S-1-5-21-9-9-513' -IsPrimary $true -IsDirect $false -InToken $true -Dn 'CN=Domain Users,CN=Users,DC=contoso,DC=com'
    $dist = New-Group -Name 'All Mail' -Sam 'AllMail' -Category 'Distribution' -Sid 'S-1-5-21-9-9-2222'
    $users = @(
        (New-TestUser -Sam 'jdoe' -Department 'Sales (East)' -Office 'HQ' -Groups @($finance, $domainUsers, $dist) -HomeDirectory '\\fileserver\users\jdoe'),
        (New-TestUser -Sam 'asmith' -Department 'Sales (East)' -Office 'HQ' -Groups @($finance, $domainUsers, $dist) -HomeDirectory '\\fileserver\users\asmith')
    )
    $analysis = Get-FullAnalysis -Users $users -MinPercent 50 -DomainDn 'DC=contoso,DC=com' -NetBiosName 'CONTOSO' -TokenGroupsResolved $true
    Assert-Equal $analysis.UserCount 2 'Analysis user count'
    $dept = $null
    foreach ($row in (Get-Collection $analysis.Scalar)) {
        if ($row.Attribute -eq 'Department') { $dept = $row }
        Assert-True ($row.Attribute -ne 'PhysicalDeliveryOffice') 'Analysis does not duplicate Office'
        Assert-True ($row.Attribute -ne 'ParentOU') 'Parent OU is not scored as a user attribute'
    }
    Assert-True ($null -ne $dept) 'Department row exists'
    Assert-Equal $dept.UsersMatching 2 'Both users match the department'
    Assert-True ($dept.FullyCommon) 'Shared department is fully common'
    Assert-True ($dept.LdapFilter.Contains('\28East\29')) 'Department filter escapes parentheses'
    Assert-True ($dept.LdapFilter.Contains('(sAMAccountName=%USERNAME%)')) 'Department filter targets the logging-on user'

    $recommended = @((Get-Collection $analysis.Recommendations) | Where-Object { $_.Quality -eq 'Recommended' })
    $iltItems = @($recommended | ForEach-Object { $_.IltItem } | Sort-Object -Unique)
    foreach ($item in $iltItems) {
        Assert-True ($item -eq 'Security Group' -or $item -eq 'Organizational Unit' -or $item -eq 'LDAP Query') "Recommended item uses a real ILT type ($item)"
    }
    $financeRec = @((Get-Collection $analysis.Recommendations) | Where-Object { $_.Filter -eq 'CONTOSO\Finance' })
    Assert-Equal $financeRec.Count 1 'Security group recommendation uses NetBIOS\sAMAccountName'
    Assert-Equal $financeRec[0].Quality 'Recommended' 'Full security-group coverage is recommended'
    Assert-Equal $financeRec[0].IltItem 'Security Group' 'Group rule is a Security Group item'

    $domainRec = @((Get-Collection $analysis.Recommendations) | Where-Object { $_.Target -like 'Domain Users*' })
    Assert-Equal $domainRec.Count 1 'Domain Users is still visible'
    Assert-Equal $domainRec[0].Quality 'Poor' 'Domain Users is not a recommended drive-map filter'

    $mailRec = @((Get-Collection $analysis.Recommendations) | Where-Object { $_.Filter -eq 'CONTOSO\AllMail' })
    Assert-Equal $mailRec.Count 1 'Distribution group is listed'
    Assert-Equal $mailRec[0].Quality 'Poor' 'Distribution groups cannot be Security Group ILT'

    $ouRec = @((Get-Collection $analysis.Recommendations) | Where-Object { $_.IltItem -eq 'Organizational Unit' -and $_.Quality -eq 'Recommended' })
    Assert-Equal $ouRec.Count 1 'Shared parent OU is recommended'
    Assert-Equal $ouRec[0].Filter 'OU=Sales,OU=Users,DC=contoso,DC=com' 'OU filter is the parent DN'
    Assert-True ($analysis.OU.AllUsersSameOU) 'OU analysis sees one parent'
    Assert-Equal $analysis.OU.CommonAncestor 'OU=Sales,OU=Users,DC=contoso,DC=com' 'Single-OU ancestor is not character-indexed'

    $splitUsers = @(
        (New-TestUser -Sam 'jdoe' -Department 'Sales' -Dn 'CN=jdoe,OU=Sales,OU=Users,DC=contoso,DC=com' -Groups @()),
        (New-TestUser -Sam 'asmith' -Department 'IT' -Dn 'CN=asmith,OU=IT,OU=Users,DC=contoso,DC=com' -Groups @())
    )
    $split = Get-FullAnalysis -Users $splitUsers -MinPercent 50 -DomainDn 'DC=contoso,DC=com' -NetBiosName 'CONTOSO'
    Assert-Equal $split.OU.CommonAncestor 'OU=Users,DC=contoso,DC=com' 'Common ancestor stops at the shared OU'
    Assert-True (-not $split.OU.AllUsersSameOU) 'Different parent OUs are not treated as one'
    $orLdap = @((Get-Collection $split.Recommendations) | Where-Object { $_.IltItem -eq 'LDAP Query' -and $_.Filter -match '\(\|\(department=' })
    Assert-Equal $orLdap.Count 1 'Two departments with no blanks produce one OR LDAP filter'
    Assert-True ($orLdap[0].Filter.Contains('(sAMAccountName=%USERNAME%)')) 'OR filter stays anchored'

    $health = Get-Collection (Get-AccountHealth @(
            (New-TestUser -Sam 'gone' -Enabled $false -LockedOut $true -Groups @())
        ))
    $disabled = @($health | Where-Object { $_.Issue -eq 'Disabled' })
    Assert-Equal $disabled[0].Count 1 'Disabled account is counted once'
    $locked = @($health | Where-Object { $_.Issue -eq 'Locked out' })
    Assert-Equal $locked[0].Count 1 'Locked account is counted once'

    $paths = Get-Collection $analysis.Paths
    $homePrefix = @($paths | Where-Object { $_.Attribute -eq 'HomeDirectory' })
    Assert-Equal $homePrefix.Count 1 'Home directory prefix is reported'
    Assert-Equal $homePrefix[0].SharedPrefix '\\fileserver\users\' 'Home directory prefix stops at the last shared slash'

    $nestedFilter = New-GroupMembershipFilter -GroupDistinguishedName 'CN=Team (East),OU=Groups,DC=contoso,DC=com' -PrimaryGroupId 513 -Nested $true
    Assert-True ($nestedFilter.Contains('1.2.840.113556.1.4.1941')) 'Nested membership uses the matching rule'
    Assert-True ($nestedFilter.Contains('primaryGroupID=513')) 'Primary group RID is included; Get-ADGroupMember omits it'
    Assert-True ($nestedFilter.Contains('\28East\29')) 'Group DN is LDAP-escaped'
    $directFilter = New-GroupMembershipFilter -GroupDistinguishedName 'CN=Finance,OU=Groups,DC=contoso,DC=com' -PrimaryGroupId $null -Nested $false
    Assert-True ($directFilter -eq '(memberOf=CN=Finance,OU=Groups,DC=contoso,DC=com)') 'Direct filter is plain memberOf'
    Assert-True ($directFilter -notmatch '1\.2\.840\.113556\.1\.4\.1941') 'Direct filter is not transitive'

    $recon = Get-GroupReconciliation -CsvNames @('CONTOSO\jdoe', 'asmith', 'missing') -MemberNames @('jdoe', 'extra') -TokenOnlyNames @('asmith') -NonUserMembers @([PSCustomObject]@{ Name = 'Workstation1'; ObjectClass = 'computer' }) -GroupName 'Finance'
    Assert-Equal $recon.Matched 1 'DOMAIN\user matches the sam returned by LDAP'
    Assert-Equal $recon.TokenMatched 1 'Token-only coverage is not marked missing'
    Assert-Equal $recon.Missing 1 'CSV user absent from the group is missing'
    Assert-Equal $recon.Extra 1 'Unexpected member is extra'
    Assert-Equal $recon.NonUser 1 'Computer member is reported'
    $statuses = @{}
    foreach ($row in $recon.Rows) { $statuses[$row.SamAccountName] = $row.Status }
    Assert-Equal $statuses['jdoe'] 'Matched' 'jdoe status'
    Assert-Equal $statuses['asmith'] 'Matched (logon token only)' 'asmith status'
    Assert-Equal $statuses['missing'] 'Missing from group' 'missing status'
    Assert-Equal $statuses['extra'] 'Extra in group' 'extra status'

    $unsafe = New-TestUser -Sam 'jdoe' -Department '<script>alert(1)</script>' -Groups @() -Dn 'CN=jdoe,OU=Sales,DC=contoso,DC=com'
    $unsafeAnalysis = Get-FullAnalysis -Users @($unsafe) -DomainDn 'DC=contoso,DC=com' -NetBiosName 'CONTOSO'
    $html = New-IltHtmlReport -Analysis $unsafeAnalysis -Users @($unsafe) -NotFound @('<script>nope</script>') -GroupCheck $null -Domain 'contoso.com' -Server 'dc1' -Timestamp '2026-01-01' -ImportedCount 1
    Assert-True ($html -notmatch '<script') 'HTML report does not emit raw markup from directory data'
    Assert-True ($html.Contains('&lt;script&gt;')) 'HTML report encodes directory values'
    Assert-True ($html.Contains('(sAMAccountName=%USERNAME%)')) 'HTML report keeps the anchored LDAP filter'
    $text = New-IltTextReport -Analysis $unsafeAnalysis -Domain 'contoso.com' -Timestamp '2026-01-01'
    Assert-True ($text.Contains('LDAP Query')) 'Text report names the LDAP Query item'
    Assert-True ($text -notmatch 'ILT ''User Property''') 'Text report does not invent a user-property ILT item'

    $sidSupported = $true
    try {
        $anon = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-7'
        $anonBytes = New-Object byte[] ($anon.BinaryLength)
        $anon.GetBinaryForm($anonBytes, 0)
    } catch {
        $sidSupported = $false
    }
    if ($sidSupported) {
        $sid = ConvertTo-LdapSidValue 'S-1-5-7'
        Assert-True ($sid.StartsWith('\')) 'SID bytes are escaped for an LDAP filter'
        $sidList = Get-Collection (ConvertTo-SidList $anonBytes)
        Assert-Equal $sidList.Count 1 'A single tokenGroups byte array is one SID'
        Assert-Equal $sidList[0] 'S-1-5-7' 'SID bytes convert back to S-1-5-7'
        $multiSid = Get-Collection (ConvertTo-SidList @($anonBytes, $anonBytes))
        Assert-Equal $multiSid.Count 2 'Multiple tokenGroups blobs stay separate SIDs'
    }
} catch {
    $script:Failures.Add('EXCEPTION: ' + $_.Exception.Message + "`n" + $_.ScriptStackTrace)
}

if ($script:Failures.Count -gt 0) {
    Write-Host ($script:Failures -join "`n`n")
    Write-Host ""
    Write-Host ("{0} failure(s)" -f $script:Failures.Count)
    exit 1
}

Write-Host 'All ILT analysis tests passed.'
exit 0

#Requires -Version 5.1
<#
.SYNOPSIS
    Entra ID dynamic group membership rule engine (PowerShell 5.1+).

.DESCRIPTION
    Pure functions for building, quoting, combining, and validating Entra ID
    dynamic membership rules. No WinForms or Graph SDK dependency.

    Canonical syntax is taken from:
    https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership
#>

# Cached catalog. Cleared only by re-dot-sourcing.
$script:EntraDgmPropertyCatalog = $null

function Get-EntraDgmCanonicalOperatorMap {
    @{
        'eq'             = '-eq'
        '-eq'            = '-eq'
        'ne'             = '-ne'
        '-ne'            = '-ne'
        'startswith'     = '-startsWith'
        '-startswith'    = '-startsWith'
        'notstartswith'  = '-notStartsWith'
        '-notstartswith' = '-notStartsWith'
        'endswith'       = '-endsWith'
        '-endswith'      = '-endsWith'
        'notendswith'    = '-notEndsWith'
        '-notendswith'   = '-notEndsWith'
        'contains'       = '-contains'
        '-contains'      = '-contains'
        'notcontains'    = '-notContains'
        '-notcontains'   = '-notContains'
        'match'          = '-match'
        '-match'         = '-match'
        'notmatch'       = '-notMatch'
        '-notmatch'      = '-notMatch'
        'in'             = '-in'
        '-in'            = '-in'
        'notin'          = '-notIn'
        '-notin'         = '-notIn'
        'ge'             = '-ge'
        '-ge'            = '-ge'
        'le'             = '-le'
        '-le'            = '-le'
        'eq null'        = '-eq'
        '-eq null'       = '-eq'
        'ne null'        = '-ne'
        '-ne null'       = '-ne'
    }
}

function Get-EntraDgmStringOperators {
    @('-eq', '-ne', '-startsWith', '-notStartsWith', '-endsWith', '-notEndsWith', '-contains', '-notContains', '-match', '-notMatch', '-in', '-notIn')
}

function Get-EntraDgmBooleanOperators { @('-eq', '-ne') }

function Get-EntraDgmDateOperators { @('-eq', '-ne', '-ge', '-le') }

function New-EntraDgmCatalogItem {
    param(
        [string]$Name,
        [string]$GraphName,
        [string]$GraphPath,
        [ValidateSet('String', 'Boolean', 'DateTime', 'StringCollection', 'ObjectCollection', 'MemberOf')]
        [string]$Type,
        [ValidateSet('user', 'device')]
        [string]$ObjectType,
        [string[]]$Aliases = @(),
        [string[]]$CollectionFields = @(),
        [bool]$SupportsNull = $true,
        [string]$Notes = ''
    )

    if ([string]::IsNullOrWhiteSpace($GraphName)) { $GraphName = $Name }
    if ([string]::IsNullOrWhiteSpace($GraphPath)) { $GraphPath = $GraphName }

    [pscustomobject]@{
        Name             = $Name
        GraphName        = $GraphName
        GraphPath        = $GraphPath
        Type             = $Type
        ObjectType       = $ObjectType
        Aliases          = @($Aliases)
        CollectionFields = @($CollectionFields)
        SupportsNull     = $SupportsNull
        Notes            = $Notes
    }
}

function Get-EntraDgmPropertyCatalog {
    if ($null -ne $script:EntraDgmPropertyCatalog) {
        return $script:EntraDgmPropertyCatalog
    }

    $items = New-Object System.Collections.ArrayList

    $userStrings = @(
        @{ Name = 'city'; GraphName = 'city' }
        @{ Name = 'country'; GraphName = 'country' }
        @{ Name = 'companyName'; GraphName = 'companyName' }
        @{ Name = 'department'; GraphName = 'department' }
        @{ Name = 'displayName'; GraphName = 'displayName' }
        @{ Name = 'employeeId'; GraphName = 'employeeId'; Notes = 'Empty employeeId is often the literal string "null". Microsoft documents user.employeeId -ne "null".' }
        @{ Name = 'facsimileTelephoneNumber'; GraphName = 'faxNumber'; Aliases = @('faxNumber') }
        @{ Name = 'givenName'; GraphName = 'givenName' }
        @{ Name = 'jobTitle'; GraphName = 'jobTitle' }
        @{ Name = 'mail'; GraphName = 'mail' }
        @{ Name = 'mailNickName'; GraphName = 'mailNickname'; Aliases = @('mailNickname') }
        @{ Name = 'mobile'; GraphName = 'mobilePhone'; Aliases = @('mobilePhone') }
        @{ Name = 'objectId'; GraphName = 'id'; Aliases = @('id') }
        @{ Name = 'onPremisesDistinguishedName'; GraphName = 'onPremisesDistinguishedName' }
        @{ Name = 'onPremisesSecurityIdentifier'; GraphName = 'onPremisesSecurityIdentifier' }
        @{ Name = 'passwordPolicies'; GraphName = 'passwordPolicies' }
        @{ Name = 'physicalDeliveryOfficeName'; GraphName = 'officeLocation'; Aliases = @('officeLocation') }
        @{ Name = 'postalCode'; GraphName = 'postalCode' }
        @{ Name = 'preferredLanguage'; GraphName = 'preferredLanguage' }
        @{ Name = 'sipProxyAddress'; GraphName = 'imAddresses'; Aliases = @('imAddresses') }
        @{ Name = 'state'; GraphName = 'state' }
        @{ Name = 'streetAddress'; GraphName = 'streetAddress' }
        @{ Name = 'surname'; GraphName = 'surname' }
        @{ Name = 'telephoneNumber'; GraphName = 'businessPhones'; Aliases = @('businessPhones') }
        @{ Name = 'usageLocation'; GraphName = 'usageLocation' }
        @{ Name = 'userPrincipalName'; GraphName = 'userPrincipalName' }
        @{ Name = 'userType'; GraphName = 'userType' }
    )

    foreach ($row in $userStrings) {
        $aliases = @()
        if ($row.ContainsKey('Aliases')) { $aliases = @($row.Aliases) }
        $notes = ''
        if ($row.ContainsKey('Notes')) { $notes = $row.Notes }
        $items.Add((New-EntraDgmCatalogItem -Name $row.Name -GraphName $row.GraphName -GraphPath $row.GraphName -Type 'String' -ObjectType 'user' -Aliases $aliases -Notes $notes)) | Out-Null
    }

    $items.Add((New-EntraDgmCatalogItem -Name 'accountEnabled' -GraphName 'accountEnabled' -Type 'Boolean' -ObjectType 'user' -SupportsNull $false -Notes 'Boolean values must be unquoted true/false.')) | Out-Null
    $items.Add((New-EntraDgmCatalogItem -Name 'dirSyncEnabled' -GraphName 'onPremisesSyncEnabled' -GraphPath 'onPremisesSyncEnabled' -Type 'Boolean' -ObjectType 'user' -Aliases @('onPremisesSyncEnabled') -Notes 'Maps from Graph onPremisesSyncEnabled. Boolean values must be unquoted true/false.')) | Out-Null
    $items.Add((New-EntraDgmCatalogItem -Name 'employeeHireDate' -GraphName 'employeeHireDate' -Type 'DateTime' -ObjectType 'user' -Notes 'Use -ge/-le with an ISO-8601 timestamp or system.now [-plus|-minus] p1d.')) | Out-Null

    $items.Add((New-EntraDgmCatalogItem -Name 'otherMails' -GraphName 'otherMails' -Type 'StringCollection' -ObjectType 'user' -Notes 'Requires -any or -all with the _ item placeholder.')) | Out-Null
    $items.Add((New-EntraDgmCatalogItem -Name 'proxyAddresses' -GraphName 'proxyAddresses' -Type 'StringCollection' -ObjectType 'user' -Notes 'Requires -any or -all with the _ item placeholder.')) | Out-Null
    $items.Add((New-EntraDgmCatalogItem -Name 'assignedPlans' -GraphName 'assignedPlans' -Type 'ObjectCollection' -ObjectType 'user' -CollectionFields @('servicePlanId', 'service', 'capabilityStatus') -SupportsNull $true -Notes 'Use -any/-all on assignedPlan.<field>. Include capabilityStatus -eq "Enabled" when matching a license.')) | Out-Null
    $items.Add((New-EntraDgmCatalogItem -Name 'memberOf' -GraphName 'memberOf' -Type 'MemberOf' -ObjectType 'user' -Notes 'Preview syntax: user.memberOf -any (group.objectId -in [''group-id'']). Prefer fewer, simpler rules.')) | Out-Null

    foreach ($i in 1..15) {
        $items.Add((New-EntraDgmCatalogItem -Name "extensionAttribute$i" -GraphName "extensionAttribute$i" -GraphPath "onPremisesExtensionAttributes.extensionAttribute$i" -Type 'String' -ObjectType 'user' -Notes 'On-premises / Graph extensionAttribute1-15. Rule name is user.extensionAttributeN, not onPremisesExtensionAttributes.')) | Out-Null
    }

    $deviceStrings = @(
        'deviceCategory', 'deviceId', 'deviceManagementAppId', 'deviceManufacturer', 'deviceModel',
        'displayName', 'deviceOSType', 'deviceOSVersion', 'deviceOwnership', 'deviceTrustType',
        'enrollmentProfileName', 'managementType', 'objectId', 'profileType', 'systemLabels'
    )
    foreach ($name in $deviceStrings) {
        $graphName = $name
        $aliases = @()
        if ($name -eq 'objectId') {
            $graphName = 'id'
            $aliases = @('id')
        }
        $items.Add((New-EntraDgmCatalogItem -Name $name -GraphName $graphName -Type 'String' -ObjectType 'device' -Aliases $aliases)) | Out-Null
    }

    $items.Add((New-EntraDgmCatalogItem -Name 'accountEnabled' -GraphName 'accountEnabled' -Type 'Boolean' -ObjectType 'device' -SupportsNull $false)) | Out-Null
    $items.Add((New-EntraDgmCatalogItem -Name 'isRooted' -GraphName 'isRooted' -Type 'Boolean' -ObjectType 'device' -SupportsNull $false)) | Out-Null
    $items.Add((New-EntraDgmCatalogItem -Name 'devicePhysicalIds' -GraphName 'devicePhysicalIds' -Type 'StringCollection' -ObjectType 'device' -Aliases @('devicePhysicalIDs') -Notes 'Autopilot ZTDId / OrderID / PurchaseOrderID. Use -any with _.')) | Out-Null
    $items.Add((New-EntraDgmCatalogItem -Name 'memberOf' -GraphName 'memberOf' -Type 'MemberOf' -ObjectType 'device' -Notes 'Preview syntax: device.memberOf -any (group.objectId -in [''group-id'']).')) | Out-Null

    foreach ($i in 1..15) {
        $items.Add((New-EntraDgmCatalogItem -Name "extensionAttribute$i" -GraphName "extensionAttribute$i" -GraphPath "extensionAttributes.extensionAttribute$i" -Type 'String' -ObjectType 'device')) | Out-Null
    }

    $script:EntraDgmPropertyCatalog = @($items)
    return $script:EntraDgmPropertyCatalog
}

function Test-EntraDgmCustomExtensionName {
    param([string]$Name)
    return [bool]($Name -match '^extension_[0-9a-fA-F]{32}_[A-Za-z][A-Za-z0-9_]*$')
}

function Resolve-EntraDgmProperty {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [ValidateSet('user', 'device')]
        [string]$ObjectType = 'user'
    )

    $catalog = @(Get-EntraDgmPropertyCatalog | Where-Object { $_.ObjectType -eq $ObjectType })
    $warnings = New-Object System.Collections.Generic.List[string]

    $exact = @($catalog | Where-Object { $_.Name -ceq $Name })
    if ($exact.Count -eq 1) {
        return [pscustomobject]@{
            Found      = $true
            Property   = $exact[0]
            InputName  = $Name
            MappedFrom = $null
            Warnings   = @()
            IsCustomExtension = $false
        }
    }

    $caseInsensitive = @($catalog | Where-Object { $_.Name -eq $Name })
    if ($caseInsensitive.Count -ge 1) {
        $prop = $caseInsensitive[0]
        $warnings.Add("Property names are case-sensitive in Entra ID. Use '$($prop.Name)' instead of '$Name'.") | Out-Null
        return [pscustomobject]@{
            Found      = $true
            Property   = $prop
            InputName  = $Name
            MappedFrom = $Name
            Warnings   = @($warnings)
            IsCustomExtension = $false
        }
    }

    foreach ($prop in $catalog) {
        $aliasHit = $false
        if ($prop.GraphName -eq $Name) { $aliasHit = $true }
        foreach ($alias in @($prop.Aliases)) {
            if ($alias -eq $Name) { $aliasHit = $true; break }
        }
        if ($aliasHit -and $prop.Name -ne $Name) {
            $warnings.Add("Graph/API name '$Name' is not valid in a membership rule. Mapped to '$($prop.Name)'.") | Out-Null
            return [pscustomobject]@{
                Found      = $true
                Property   = $prop
                InputName  = $Name
                MappedFrom = $Name
                Warnings   = @($warnings)
                IsCustomExtension = $false
            }
        }
    }

    if (Test-EntraDgmCustomExtensionName -Name $Name) {
        $custom = New-EntraDgmCatalogItem -Name $Name -GraphName $Name -Type 'String' -ObjectType $ObjectType -Notes 'Directory / custom extension property.'
        return [pscustomobject]@{
            Found      = $true
            Property   = $custom
            InputName  = $Name
            MappedFrom = $null
            Warnings   = @()
            IsCustomExtension = $true
        }
    }

    return [pscustomobject]@{
        Found      = $false
        Property   = $null
        InputName  = $Name
        MappedFrom = $null
        Warnings   = @("'$Name' is not a supported $ObjectType property for Entra ID dynamic membership rules.")
        IsCustomExtension = $false
    }
}

function ConvertTo-EntraDgmQuotedString {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($null -eq $Value) { $Value = '' }
    # Entra ID escapes embedded double quotes with a backtick, not a backslash.
    $escaped = $Value.Replace([string][char]0x60, ([string][char]0x60) * 2).Replace('"', ([string][char]0x60) + '"')
    return '"' + $escaped + '"'
}

function ConvertTo-EntraDgmInList {
    param(
        [Parameter(Mandatory)]
        [string]$Value,
        [ValidateSet('Double', 'Single')]
        [string]$QuoteStyle = 'Double'
    )

    $parts = @($Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    if ($parts.Count -eq 0) {
        return [pscustomobject]@{
            List   = $null
            Values = @()
            Error  = '-in / -notIn requires at least one comma-separated value.'
        }
    }

    $quoted = New-Object System.Collections.Generic.List[string]
    foreach ($part in $parts) {
        $clean = $part
        if (($clean.StartsWith('"') -and $clean.EndsWith('"') -and $clean.Length -ge 2) -or
            ($clean.StartsWith("'") -and $clean.EndsWith("'") -and $clean.Length -ge 2)) {
            $clean = $clean.Substring(1, $clean.Length - 2)
        }
        if ($QuoteStyle -eq 'Single') {
            $quoted.Add("'" + $clean.Replace("'", "''") + "'") | Out-Null
        }
        else {
            $quoted.Add((ConvertTo-EntraDgmQuotedString -Value $clean)) | Out-Null
        }
    }

    return [pscustomobject]@{
        List   = '[' + ($quoted -join ', ') + ']'
        Values = @($parts)
        Error  = $null
    }
}

function Resolve-EntraDgmOperator {
    param(
        [Parameter(Mandatory)]
        [string]$Operator
    )

    $raw = $Operator.Trim()
    $nullValue = $false
    if ($raw -match '(?i)null$') {
        $nullValue = $true
    }

    $lookup = Get-EntraDgmCanonicalOperatorMap
    $key = $raw.ToLowerInvariant()
    if ($lookup.ContainsKey($key)) {
        return [pscustomobject]@{
            Operator  = $lookup[$key]
            NullValue = $nullValue
            Error     = $null
        }
    }

    return [pscustomobject]@{
        Operator  = $null
        NullValue = $false
        Error     = "Unsupported operator '$Operator'."
    }
}

function Get-EntraDgmAllowedOperators {
    param(
        [Parameter(Mandatory)]
        $Property
    )

    switch ($Property.Type) {
        'Boolean'          { return @(Get-EntraDgmBooleanOperators) }
        'DateTime'         { return @(Get-EntraDgmDateOperators) }
        'StringCollection' { return @(Get-EntraDgmStringOperators) }
        'ObjectCollection' { return @(Get-EntraDgmStringOperators) }
        'MemberOf'         { return @('-in', '-notIn', '-eq') }
        default            { return @(Get-EntraDgmStringOperators) }
    }
}

function Test-EntraDgmSystemNowValue {
    param([string]$Value)
    return [bool]($Value -match '^(?i)system\.now(\s+-(plus|minus)\s+p\d+[dhms])?$')
}

function Test-EntraDgmIsoDateValue {
    param([string]$Value)
    return [bool]($Value -match '^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})?)?$')
}

function New-EntraDgmExpression {
    [CmdletBinding()]
    param(
        [ValidateSet('user', 'device')]
        [string]$ObjectType = 'user',
        [Parameter(Mandatory)]
        [string]$Property,
        [Parameter(Mandatory)]
        [string]$Operator,
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value = '',
        [switch]$NullValue,
        [ValidateSet('', 'any', 'all')]
        [string]$CollectionMode = '',
        [string]$CollectionField = '',
        [switch]$Negate,
        [switch]$RequireEnabled,
        [switch]$AllowUnsupported
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]

    $resolved = Resolve-EntraDgmProperty -Name $Property -ObjectType $ObjectType
    foreach ($w in @($resolved.Warnings)) { $warnings.Add($w) | Out-Null }

    if (-not $resolved.Found) {
        if (-not $AllowUnsupported) {
            $errors.Add($resolved.Warnings[0]) | Out-Null
            return [pscustomobject]@{
                Rule            = $null
                Property        = $Property
                GraphName       = $Property
                GraphPath       = $Property
                Operator        = $Operator
                Value           = $Value
                Type            = 'Unknown'
                ObjectType      = $ObjectType
                CollectionMode  = $CollectionMode
                CollectionField = $CollectionField
                NullValue       = [bool]$NullValue
                Negate          = [bool]$Negate
                Errors          = @($errors)
                Warnings        = @($warnings)
                IsValid         = $false
            }
        }
    }

    $propMeta = $resolved.Property
    $ruleName = if ($propMeta) { $propMeta.Name } else { $Property }
    $type = if ($propMeta) { $propMeta.Type } else { 'String' }

    $opInfo = Resolve-EntraDgmOperator -Operator $Operator
    if ($opInfo.Error) {
        $errors.Add($opInfo.Error) | Out-Null
    }
    $op = $opInfo.Operator
    if ($opInfo.NullValue) { $NullValue = $true }

    if ($propMeta -and $op) {
        $allowed = Get-EntraDgmAllowedOperators -Property $propMeta
        if ($allowed -notcontains $op) {
            $errors.Add("Operator '$op' is not valid for $type property '$ruleName'. Allowed: $($allowed -join ', ').") | Out-Null
        }
    }

    if ($type -eq 'Boolean' -and $NullValue) {
        $errors.Add("Boolean property '$ruleName' cannot be compared to null. Use true or false.") | Out-Null
    }

    $body = $null

    if ($errors.Count -eq 0) {
        if ($type -eq 'MemberOf') {
            $list = ConvertTo-EntraDgmInList -Value $Value -QuoteStyle Single
            if ($list.Error) {
                $errors.Add("memberOf requires one or more group object IDs.") | Out-Null
            }
            else {
                $membershipOp = if ($op -eq '-notIn') { '-notIn' } else { '-in' }
                $body = "$ObjectType.memberOf -any (group.objectId $membershipOp $($list.List))"
                $warnings.Add('memberOf is a preview-style rule and has been deprecated/replaced in some tenants. Confirm it is enabled before using it in production.') | Out-Null
            }
        }
        elseif ($NullValue) {
            if ($op -notin @('-eq', '-ne')) {
                $errors.Add('Null comparisons must use -eq or -ne. Do not use -not with null.') | Out-Null
            }
            else {
                $body = "$ObjectType.$ruleName $op null"
                if ($ruleName -eq 'employeeId') {
                    $warnings.Add('For employeeId, Microsoft also documents the literal string comparison user.employeeId -ne "null" because empty values are often stored as "null".') | Out-Null
                }
            }
        }
        elseif ($type -eq 'Boolean') {
            $normalized = $Value.Trim().ToLowerInvariant()
            if ($normalized -in @('true', 'false')) {
                $body = "$ObjectType.$ruleName $op $normalized"
            }
            else {
                $errors.Add("Boolean property '$ruleName' requires unquoted true or false, not '$Value'.") | Out-Null
            }
        }
        elseif ($type -eq 'DateTime') {
            $trimmed = $Value.Trim()
            if (-not (Test-EntraDgmSystemNowValue -Value $trimmed) -and -not (Test-EntraDgmIsoDateValue -Value $trimmed)) {
                $errors.Add("employeeHireDate values must be an ISO-8601 timestamp (2020-06-10T18:13:20Z) or system.now [-plus|-minus p1d].") | Out-Null
            }
            else {
                $body = "$ObjectType.$ruleName $op $trimmed"
            }
        }
        elseif ($type -eq 'StringCollection') {
            if ([string]::IsNullOrWhiteSpace($CollectionMode)) { $CollectionMode = 'any' }
            if ($CollectionMode -notin @('any', 'all')) {
                $errors.Add('String collection properties require -any or -all.') | Out-Null
            }
            else {
                if ($op -in @('-in', '-notIn')) {
                    $list = ConvertTo-EntraDgmInList -Value $Value
                    if ($list.Error) { $errors.Add($list.Error) | Out-Null }
                    else { $itemExpr = "_ $op $($list.List)" }
                }
                else {
                    $itemExpr = "_ $op $(ConvertTo-EntraDgmQuotedString -Value $Value)"
                }
                if ($itemExpr) {
                    $body = "($ObjectType.$ruleName -$CollectionMode ($itemExpr))"
                }
            }
        }
        elseif ($type -eq 'ObjectCollection') {
            if ([string]::IsNullOrWhiteSpace($CollectionMode)) { $CollectionMode = 'any' }
            $field = $CollectionField
            if ([string]::IsNullOrWhiteSpace($field)) { $field = 'servicePlanId' }
            $prefix = 'assignedPlan'
            $allowedFields = @($propMeta.CollectionFields)
            if ($allowedFields -notcontains $field) {
                $errors.Add("Unknown assignedPlans field '$field'. Use: $($allowedFields -join ', ').") | Out-Null
            }
            else {
                $inner = "$prefix.$field $op $(ConvertTo-EntraDgmQuotedString -Value $Value)"
                if ($RequireEnabled -and $field -ne 'capabilityStatus') {
                    $inner = "$inner -and $prefix.capabilityStatus -eq $(ConvertTo-EntraDgmQuotedString -Value 'Enabled')"
                }
                $body = "$ObjectType.$ruleName -$CollectionMode ($inner)"
            }
        }
        else {
            # String
            if ($op -in @('-in', '-notIn')) {
                $list = ConvertTo-EntraDgmInList -Value $Value
                if ($list.Error) { $errors.Add($list.Error) | Out-Null }
                else { $body = "$ObjectType.$ruleName $op $($list.List)" }
            }
            else {
                if ([string]::IsNullOrWhiteSpace($Value) -and $op -notin @('-eq', '-ne')) {
                    $errors.Add("Operator '$op' requires a value.") | Out-Null
                }
                else {
                    $body = "$ObjectType.$ruleName $op $(ConvertTo-EntraDgmQuotedString -Value $Value)"
                }
            }

            if ($op -in @('-match', '-notMatch')) {
                $warnings.Add("-$($op.TrimStart('-')) is expensive in large tenants. Prefer -eq, -startsWith, or -endsWith when possible.") | Out-Null
            }
            elseif ($op -in @('-contains', '-notContains')) {
                $warnings.Add("-$($op.TrimStart('-')) is expensive in large tenants. Prefer -eq, -startsWith, or -endsWith when possible.") | Out-Null
            }
        }
    }

    if ($body -and $Negate) {
        if ($body.StartsWith('(') -and $body.EndsWith(')')) {
            $body = "-not $body"
        }
        else {
            $body = "-not ($body)"
        }
    }

    if ($body -and $body -notmatch '^\(' -and $body -notmatch '^-not ') {
        $body = "($body)"
    }

    if ($propMeta -and $propMeta.Notes) {
        if ($propMeta.Notes -like '*employeeId*') {
            # already added a targeted warning when NullValue
        }
    }

    return [pscustomobject]@{
        Rule            = $body
        Property        = $ruleName
        GraphName       = if ($propMeta) { $propMeta.GraphName } else { $Property }
        GraphPath       = if ($propMeta) { $propMeta.GraphPath } else { $Property }
        Operator        = $op
        Value           = $Value
        Type            = $type
        ObjectType      = $ObjectType
        CollectionMode  = $CollectionMode
        CollectionField = $CollectionField
        NullValue       = [bool]$NullValue
        Negate          = [bool]$Negate
        RequireEnabled  = [bool]$RequireEnabled
        Errors          = @($errors)
        Warnings        = @($warnings)
        IsValid         = ($errors.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($body))
    }
}

function New-EntraDgmDirectReportsRule {
    param(
        [Parameter(Mandatory)]
        [string]$ManagerObjectId
    )

    $id = $ManagerObjectId.Trim()
    $errors = New-Object System.Collections.Generic.List[string]
    if ($id -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        $errors.Add('Direct Reports requires the manager object ID as a GUID, not a display name or UPN.') | Out-Null
    }

    $rule = "Direct Reports for `"$id`""
    return [pscustomobject]@{
        Rule           = $rule
        Property       = 'DirectReports'
        Operator       = 'DirectReports'
        Value          = $id
        Type           = 'DirectReports'
        ObjectType     = 'user'
        Errors         = @($errors)
        Warnings       = @('Direct Reports cannot be combined with any other membership expressions. The manager is also included in the group.')
        IsValid        = ($errors.Count -eq 0)
        IsDirectReports = $true
    }
}

function Join-EntraDgmExpressions {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Conditions
    )

    $list = @($Conditions | Where-Object { $_ })
    if ($list.Count -eq 0) {
        return [pscustomobject]@{
            Rule       = ''
            Grouping   = 'none'
            Errors     = @('No conditions to join.')
            IsValid    = $false
        }
    }

    $direct = @($list | Where-Object { $_.Type -eq 'DirectReports' -or $_.Operator -eq 'DirectReports' -or $_.Property -eq 'DirectReports' })
    if ($direct.Count -gt 0 -and $list.Count -gt 1) {
        return [pscustomobject]@{
            Rule     = $direct[0].Rule
            Grouping = 'invalid'
            Errors   = @('Direct Reports cannot be combined with other membership expressions.')
            IsValid  = $false
        }
    }

    if ($list.Count -eq 1) {
        return [pscustomobject]@{
            Rule     = $list[0].Rule
            Grouping = 'single'
            Errors   = @()
            IsValid  = $true
        }
    }

    $joins = New-Object System.Collections.Generic.List[string]
    for ($i = 1; $i -lt $list.Count; $i++) {
        $join = $list[$i].JoinOperator
        if ([string]::IsNullOrWhiteSpace($join)) { $join = '-and' }
        $join = $join.Trim().ToLowerInvariant()
        if ($join -eq 'and' -or $join -eq '-and') { $join = '-and' }
        elseif ($join -eq 'or' -or $join -eq '-or') { $join = '-or' }
        else { $join = '-and' }
        $joins.Add($join) | Out-Null
    }

    $uniqueJoins = @($joins | Select-Object -Unique)
    $parts = @($list | ForEach-Object { $_.Rule })

    # Always parenthesize mixed AND/OR left-to-right so the rule matches the
    # builder (Entra gives -and higher precedence than -or).
    if ($uniqueJoins.Count -eq 1) {
        $rule = $parts -join " $($uniqueJoins[0]) "
        $grouping = "all $($uniqueJoins[0])"
    }
    else {
        $acc = $parts[0]
        for ($i = 1; $i -lt $parts.Count; $i++) {
            $acc = "($acc $($joins[$i - 1]) $($parts[$i]))"
        }
        $rule = $acc
        $grouping = 'left-to-right mixed'
    }

    return [pscustomobject]@{
        Rule     = $rule
        Grouping = $grouping
        Errors   = @()
        IsValid  = $true
    }
}

function Test-EntraDgmBalancedDelimiters {
    param([string]$Text)

    $paren = 0
    $bracket = 0
    $inDouble = $false
    $i = 0
    $bt = [char]0x60
    while ($i -lt $Text.Length) {
        $c = $Text[$i]
        if ($inDouble) {
            if ($c -eq $bt -and ($i + 1) -lt $Text.Length) {
                $i += 2
                continue
            }
            if ($c -eq '"') { $inDouble = $false }
            $i++
            continue
        }
        switch ($c) {
            '"' { $inDouble = $true }
            '(' { $paren++ }
            ')' { $paren--; if ($paren -lt 0) { return [pscustomobject]@{ IsBalanced = $false; Error = 'Unmatched closing parenthesis.' } } }
            '[' { $bracket++ }
            ']' { $bracket--; if ($bracket -lt 0) { return [pscustomobject]@{ IsBalanced = $false; Error = 'Unmatched closing bracket.' } } }
        }
        $i++
    }

    if ($inDouble) { return [pscustomobject]@{ IsBalanced = $false; Error = 'Unterminated double-quoted string.' } }
    if ($paren -ne 0) { return [pscustomobject]@{ IsBalanced = $false; Error = 'Unbalanced parentheses.' } }
    if ($bracket -ne 0) { return [pscustomobject]@{ IsBalanced = $false; Error = 'Unbalanced square brackets on an -in / -notIn list.' } }
    return [pscustomobject]@{ IsBalanced = $true; Error = $null }
}

function Test-EntraDgmRuleSyntax {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Rule
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]

    if ([string]::IsNullOrWhiteSpace($Rule) -or $Rule -eq 'No conditions added yet') {
        $errors.Add('Rule is empty.') | Out-Null
        return [pscustomobject]@{
            IsValid          = $false
            Errors           = @($errors)
            Warnings         = @()
            Length           = 0
            Remaining        = 3072
            IsDirectReports  = $false
        }
    }

    $length = $Rule.Length
    if ($length -gt 3072) {
        $errors.Add("Rule is $length characters. Entra ID limits membership rules to 3072 characters.") | Out-Null
    }
    elseif ($length -gt 2800) {
        $warnings.Add("Rule is $length/3072 characters and is approaching the Entra ID limit.") | Out-Null
    }

    $isDirectReports = [bool]($Rule -match '^\s*Direct Reports for\s+"[^"]+"\s*$')
    if ($Rule -match 'Direct Reports for' -and -not $isDirectReports) {
        $errors.Add('Direct Reports must stand alone as: Direct Reports for "{manager-object-id}". It cannot be combined with other expressions.') | Out-Null
    }

    $hasUser = $Rule -match '(?i)(?<![\w])user\.'
    $hasDevice = $Rule -match '(?i)(?<![\w])device\.'
    if ($hasUser -and $hasDevice) {
        $errors.Add('A membership rule cannot mix user and device properties.') | Out-Null
    }

    $balance = Test-EntraDgmBalancedDelimiters -Text $Rule
    if (-not $balance.IsBalanced) {
        $errors.Add($balance.Error) | Out-Null
    }

    if ($Rule -match '\$null') {
        $errors.Add('Use null (not $null) for empty-value comparisons.') | Out-Null
    }

    if ($Rule -match '\\"') {
        $errors.Add('Found backslash-escaped quotes (\"). Entra ID requires backtick-escaped quotes inside strings (`").') | Out-Null
    }

    if ($Rule -match '(?i)-not\s+(\$null|null)') {
        $errors.Add('Do not use -not with null. Use -eq null or -ne null.') | Out-Null
    }

    $graphNameMap = [ordered]@{
        'user.id'                       = 'user.objectId'
        'device.id'                     = 'device.objectId'
        'user.mobilePhone'              = 'user.mobile'
        'user.officeLocation'           = 'user.physicalDeliveryOfficeName'
        'user.mailNickname'             = 'user.mailNickName'
        'user.faxNumber'                = 'user.facsimileTelephoneNumber'
        'user.onPremisesSyncEnabled'    = 'user.dirSyncEnabled'
        'user.businessPhones'           = 'user.telephoneNumber'
        'user.imAddresses'              = 'user.sipProxyAddress'
        'user.manager'                  = 'Direct Reports for "{manager-object-id}" (manager display name is not a valid rule property)'
        'user.onPremisesExtensionAttributes' = 'user.extensionAttribute1 through user.extensionAttribute15'
        'user.employeeType'             = 'not supported; sync it to extensionAttributeN or a directory extension'
        'user.employeeOrgData'          = 'not supported; sync costCenter/division to an extension attribute'
        'user.countryCode'              = 'user.country or user.usageLocation'
    }

    foreach ($wrong in $graphNameMap.Keys) {
        $escaped = [regex]::Escape($wrong)
        $pattern = "(?<![A-Za-z])$escaped(?![A-Za-z])"
        if ($Rule -cmatch $pattern) {
            $errors.Add("Invalid property '$wrong'. Use $($graphNameMap[$wrong]).") | Out-Null
        }
        elseif ($Rule -match $pattern) {
            $warnings.Add("Property names are case-sensitive. If you meant '$wrong', use $($graphNameMap[$wrong]).") | Out-Null
        }
    }

    if ($Rule -match '(?i)(accountEnabled|dirSyncEnabled|isRooted)\s+-eq\s+"(true|false)"') {
        $errors.Add('Boolean values must be unquoted: user.accountEnabled -eq true.') | Out-Null
    }

    if ($Rule -match '(?i)(proxyAddresses|otherMails|devicePhysicalIds)\s+-(eq|ne|startsWith|contains|match)\s') {
        $errors.Add('Collection properties (proxyAddresses, otherMails, devicePhysicalIds) require -any or -all, for example (user.proxyAddresses -any (_ -startsWith "SMTP:")).') | Out-Null
    }

    if ($Rule -match '(?i)assignedPlans\s+-(eq|ne|startsWith|contains)\s') {
        $errors.Add('assignedPlans requires -any/-all, for example user.assignedPlans -any (assignedPlan.servicePlanId -eq "guid" -and assignedPlan.capabilityStatus -eq "Enabled").') | Out-Null
    }

    if ($Rule -match '(?i)(?<![A-Za-z])-(in|notin)\s+(?!\[)') {
        $errors.Add('The -in / -notIn operators require a bracketed list, for example user.department -in ["Sales", "Marketing"].') | Out-Null
    }

    if ($Rule -match '(?i)-(contains|match)\s') {
        $warnings.Add('-contains and -match are the slowest operators. Prefer -eq, -startsWith, -endsWith, or -in.') | Out-Null
    }

    if ($Rule -match '(?i)employeeId\s+-n?eq\s+null') {
        $warnings.Add('For employeeId, Microsoft documents user.employeeId -ne "null" (quoted) because empty values are often the literal string null.') | Out-Null
    }

    $orEqMatches = [regex]::Matches($Rule, '(?i)user\.(\w+)\s+-eq\s+"[^"]+"\s+-or\s+user\.\1\s+-eq')
    if ($orEqMatches.Count -ge 1) {
        $warnings.Add('Multiple -eq comparisons of the same property with -or can usually be rewritten with -in, which is faster.') | Out-Null
    }

    return [pscustomobject]@{
        IsValid         = ($errors.Count -eq 0)
        Errors          = @($errors)
        Warnings        = @($warnings)
        Length          = $length
        Remaining       = 3072 - $length
        IsDirectReports = $isDirectReports
    }
}

function Get-EntraDgmCommonTemplates {
    @(
        [pscustomobject]@{ Name = 'All users'; ObjectType = 'user'; Rule = 'user.objectId -ne null'; Notes = 'Includes members and guests.' }
        [pscustomobject]@{ Name = 'Members only'; ObjectType = 'user'; Rule = '(user.objectId -ne null) -and (user.userType -eq "Member")'; Notes = 'Excludes guests.' }
        [pscustomobject]@{ Name = 'Guests only'; ObjectType = 'user'; Rule = '(user.objectId -ne null) -and (user.userType -eq "Guest")'; Notes = '' }
        [pscustomobject]@{ Name = 'Enabled accounts'; ObjectType = 'user'; Rule = 'user.accountEnabled -eq true'; Notes = 'Boolean is unquoted.' }
        [pscustomobject]@{ Name = 'Cloud-only users'; ObjectType = 'user'; Rule = 'user.dirSyncEnabled -ne true'; Notes = 'dirSyncEnabled maps from onPremisesSyncEnabled.' }
        [pscustomobject]@{ Name = 'Synced from AD'; ObjectType = 'user'; Rule = 'user.dirSyncEnabled -eq true'; Notes = '' }
        [pscustomobject]@{ Name = 'Has an enabled service plan'; ObjectType = 'user'; Rule = 'user.assignedPlans -any (assignedPlan.capabilityStatus -eq "Enabled")'; Notes = 'Users with at least one enabled service plan.' }
        [pscustomobject]@{ Name = 'Exchange Online Plan 2 enabled'; ObjectType = 'user'; Rule = 'user.assignedPlans -any (assignedPlan.servicePlanId -eq "efb87545-963c-4e0d-99df-69c6916d9eb0" -and assignedPlan.capabilityStatus -eq "Enabled")'; Notes = 'Uses the Exchange Online (Plan 2) service plan ID.' }
        [pscustomobject]@{ Name = 'All devices'; ObjectType = 'device'; Rule = 'device.objectId -ne null'; Notes = '' }
        [pscustomobject]@{ Name = 'Entra joined devices'; ObjectType = 'device'; Rule = 'device.deviceTrustType -eq "AzureAD"'; Notes = 'AzureAD = Entra joined, ServerAD = hybrid, Workplace = registered.' }
        [pscustomobject]@{ Name = 'Autopilot devices'; ObjectType = 'device'; Rule = '(device.devicePhysicalIds -any (_ -startsWith "[ZTDId]"))'; Notes = '' }
    )
}

function Get-EntraDgmGraphSelectProperties {
    param(
        [ValidateSet('user', 'device')]
        [string]$ObjectType = 'user',
        [string[]]$Extra = @()
    )

    $names = New-Object System.Collections.Generic.List[string]
    $skipSelect = @('memberOf', 'manager')
    foreach ($prop in @(Get-EntraDgmPropertyCatalog | Where-Object { $_.ObjectType -eq $ObjectType })) {
        $top = ($prop.GraphPath -split '\.')[0]
        if ([string]::IsNullOrWhiteSpace($top)) { continue }
        if ($skipSelect -contains $top) { continue }
        if (-not $names.Contains($top)) {
            $names.Add($top) | Out-Null
        }
    }

    foreach ($extraName in @($Extra)) {
        if (-not [string]::IsNullOrWhiteSpace($extraName) -and -not $names.Contains($extraName)) {
            $names.Add($extraName) | Out-Null
        }
    }

    if ($ObjectType -eq 'user') {
        foreach ($required in @('id', 'displayName', 'userPrincipalName', 'onPremisesExtensionAttributes')) {
            if (-not $names.Contains($required)) { $names.Add($required) | Out-Null }
        }
    }

    return @($names)
}

function Get-EntraDgmExactProperty {
    param(
        $Object,
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Object) {
        return [pscustomobject]@{ Found = $false; Value = $null }
    }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ([string]$key -ceq $Name) {
                return [pscustomobject]@{ Found = $true; Value = $Object[$key] }
            }
        }
        return [pscustomobject]@{ Found = $false; Value = $null }
    }

    foreach ($prop in $Object.PSObject.Properties) {
        if ($prop.Name -ceq $Name) {
            return [pscustomobject]@{ Found = $true; Value = $prop.Value }
        }
    }
    return [pscustomobject]@{ Found = $false; Value = $null }
}

function Get-EntraDgmODataValue {
    param($Result)

    $prop = Get-EntraDgmExactProperty -Object $Result -Name 'value'
    if (-not $prop.Found -or $null -eq $prop.Value) { return @() }
    if ($prop.Value -is [string]) { return @($prop.Value) }
    if ($prop.Value -is [System.Collections.IEnumerable]) { return @($prop.Value) }
    return @($prop.Value)
}

function Resolve-EntraDgmGraphEntity {
    param(
        $Result,
        [string]$ObjectType = 'user'
    )

    if ($null -eq $Result) { return $null }

    # Hashtable/PSObject adapters expose a .Values property. Case-insensitive
    # lookups like $result.value or PSObject.Properties['value'] can return that
    # collection instead of an OData page. Require an exact JSON 'value' member.
    $valueProp = Get-EntraDgmExactProperty -Object $Result -Name 'value'
    if (-not $valueProp.Found) { return $Result }

    $page = $valueProp.Value
    if ($null -eq $page) { return $Result }
    if ($page -is [string]) { return $Result }
    if (-not ($page -is [System.Collections.IEnumerable])) { return $Result }

    $hits = @($page)
    if ($hits.Count -eq 0) {
        throw "No $ObjectType matched."
    }
    return $hits[0]
}

function Get-EntraDgmObjectProperty {
    param(
        $Object,
        [string]$Name
    )

    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return $null }

    if ($Object -is [hashtable] -or $Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        foreach ($key in $Object.Keys) {
            if ([string]$key -eq $Name) { return $Object[$key] }
        }
        return $null
    }

    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function Get-EntraDgmPropertyByPath {
    param(
        $Object,
        [string]$Path
    )

    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Path)) { return $null }
    $current = $Object
    foreach ($part in ($Path -split '\.')) {
        $current = Get-EntraDgmObjectProperty -Object $current -Name $part
        if ($null -eq $current) { return $null }
    }
    return $current
}

function ConvertTo-EntraDgmCollection {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable]) { return @($Value) }
    return @($Value)
}

function ConvertTo-EntraDgmDisplayValue {
    param($Value)

    if ($null -eq $Value) { return '<null>' }
    if ($Value -is [bool]) { return $Value.ToString().ToLowerInvariant() }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($Value -is [string]) {
        if ($Value -eq '') { return '<null>' }
        return $Value
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $bits = New-Object System.Collections.Generic.List[string]
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            if ($item -is [string]) {
                $bits.Add($item) | Out-Null
            }
            elseif ($item.PSObject.Properties['servicePlanId'] -or $item.PSObject.Properties['service']) {
                $svc = Get-EntraDgmObjectProperty -Object $item -Name 'service'
                $plan = Get-EntraDgmObjectProperty -Object $item -Name 'servicePlanId'
                $status = Get-EntraDgmObjectProperty -Object $item -Name 'capabilityStatus'
                $bits.Add("$svc|$plan|$status") | Out-Null
            }
            elseif ($item.PSObject.Properties['id'] -or $item.PSObject.Properties['displayName']) {
                $dn = Get-EntraDgmObjectProperty -Object $item -Name 'displayName'
                $id = Get-EntraDgmObjectProperty -Object $item -Name 'id'
                if ($dn) { $bits.Add("$dn ($id)") | Out-Null } else { $bits.Add([string]$id) | Out-Null }
            }
            else {
                $bits.Add($item.ToString()) | Out-Null
            }
            if ($bits.Count -ge 8) { break }
        }
        if ($bits.Count -eq 0) { return '<null>' }
        return ($bits -join '; ')
    }

    if ($Value -is [psobject] -or $Value -is [pscustomobject]) {
        return '<complex object>'
    }

    return $Value.ToString()
}

function ConvertFrom-EntraDgmGraphObject {
    param(
        [Parameter(Mandatory)]
        $GraphObject,
        [ValidateSet('user', 'device')]
        [string]$ObjectType = 'user',
        [string[]]$ExtraExtensionNames = @()
    )

    $rows = New-Object System.Collections.ArrayList
    $catalog = @(Get-EntraDgmPropertyCatalog | Where-Object { $_.ObjectType -eq $ObjectType })

    foreach ($prop in $catalog) {
        $raw = Get-EntraDgmPropertyByPath -Object $GraphObject -Path $prop.GraphPath
        if ($null -eq $raw) {
            $raw = Get-EntraDgmObjectProperty -Object $GraphObject -Name $prop.GraphName
        }
        if ($prop.Name -eq 'objectId' -and $null -eq $raw) {
            $raw = Get-EntraDgmObjectProperty -Object $GraphObject -Name 'id'
        }
        if ($prop.Name -eq 'telephoneNumber' -and $raw -is [System.Collections.IEnumerable] -and -not ($raw -is [string])) {
            $first = @($raw | Select-Object -First 1)
            if ($first.Count -gt 0) { $rawForScalar = $first[0] } else { $rawForScalar = $null }
            $display = ConvertTo-EntraDgmDisplayValue -Value $raw
            $rows.Add([pscustomobject]@{
                Name        = $prop.Name
                GraphName   = $prop.GraphName
                GraphPath   = $prop.GraphPath
                Type        = $prop.Type
                ObjectType  = $prop.ObjectType
                Value       = $display
                RawValue    = $rawForScalar
                Collection  = @($raw)
                Supported   = $true
                Notes       = $prop.Notes
            }) | Out-Null
            continue
        }
        if ($prop.Name -eq 'sipProxyAddress' -and $raw -is [System.Collections.IEnumerable] -and -not ($raw -is [string])) {
            $first = @($raw | Select-Object -First 1)
            $rawForScalar = $null
            if ($first.Count -gt 0) { $rawForScalar = $first[0] }
            $rows.Add([pscustomobject]@{
                Name        = $prop.Name
                GraphName   = $prop.GraphName
                GraphPath   = $prop.GraphPath
                Type        = $prop.Type
                ObjectType  = $prop.ObjectType
                Value       = (ConvertTo-EntraDgmDisplayValue -Value $raw)
                RawValue    = $rawForScalar
                Collection  = @($raw)
                Supported   = $true
                Notes       = $prop.Notes
            }) | Out-Null
            continue
        }

        $rows.Add([pscustomobject]@{
            Name        = $prop.Name
            GraphName   = $prop.GraphName
            GraphPath   = $prop.GraphPath
            Type        = $prop.Type
            ObjectType  = $prop.ObjectType
            Value       = (ConvertTo-EntraDgmDisplayValue -Value $raw)
            RawValue    = $raw
            Collection  = $(if ($prop.Type -in @('StringCollection', 'ObjectCollection', 'MemberOf')) { ConvertTo-EntraDgmCollection -Value $raw } else { @() })
            Supported   = $true
            Notes       = $prop.Notes
        }) | Out-Null
    }

    foreach ($extName in @($ExtraExtensionNames)) {
        if ([string]::IsNullOrWhiteSpace($extName)) { continue }
        if (-not (Test-EntraDgmCustomExtensionName -Name $extName)) { continue }
        $raw = Get-EntraDgmObjectProperty -Object $GraphObject -Name $extName
        $rows.Add([pscustomobject]@{
            Name        = $extName
            GraphName   = $extName
            GraphPath   = $extName
            Type        = 'String'
            ObjectType  = $ObjectType
            Value       = (ConvertTo-EntraDgmDisplayValue -Value $raw)
            RawValue    = $raw
            Collection  = @()
            Supported   = $true
            Notes       = 'Directory / custom extension property'
        }) | Out-Null
    }

    if ($ObjectType -eq 'user') {
        $manager = Get-EntraDgmObjectProperty -Object $GraphObject -Name 'manager'
        $managerId = $null
        $managerName = $null
        if ($manager) {
            $managerId = Get-EntraDgmObjectProperty -Object $manager -Name 'id'
            $managerName = Get-EntraDgmObjectProperty -Object $manager -Name 'displayName'
        }
        $rows.Add([pscustomobject]@{
            Name        = 'managerObjectId'
            GraphName   = 'manager'
            GraphPath   = 'manager.id'
            Type        = 'Info'
            ObjectType  = 'user'
            Value       = $(if ($managerId) { $managerId } else { '<null>' })
            RawValue    = $managerId
            Collection  = @()
            Supported   = $false
            Notes       = 'Not a rule property. Use Direct Reports for "{this object id}".'
        }) | Out-Null
        $rows.Add([pscustomobject]@{
            Name        = 'managerDisplayName'
            GraphName   = 'manager'
            GraphPath   = 'manager.displayName'
            Type        = 'Info'
            ObjectType  = 'user'
            Value       = $(if ($managerName) { $managerName } else { '<null>' })
            RawValue    = $managerName
            Collection  = @()
            Supported   = $false
            Notes       = 'Manager display name cannot be used in a membership rule.'
        }) | Out-Null
    }

    return @($rows | Sort-Object @{ Expression = 'Supported'; Descending = $true }, Name)
}

function ConvertFrom-EntraDgmInListText {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    $text = $Value.Trim()
    if ($text.StartsWith('[') -and $text.EndsWith(']')) {
        $text = $text.Substring(1, $text.Length - 2)
    }
    $parts = @($text -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    $clean = foreach ($part in $parts) {
        $item = $part
        if (($item.StartsWith('"') -and $item.EndsWith('"') -and $item.Length -ge 2) -or
            ($item.StartsWith("'") -and $item.EndsWith("'") -and $item.Length -ge 2)) {
            $item = $item.Substring(1, $item.Length - 2)
        }
        $item.Replace((([string][char]0x60) + '"'), '"')
    }
    return @($clean)
}

function Test-EntraDgmStringOperator {
    param(
        $Actual,
        [string]$Operator,
        $Expected
    )

    if ($null -eq $Actual) { $actualText = '' }
    else { $actualText = [string]$Actual }

    switch ($Operator) {
        '-eq'            { return $actualText -eq [string]$Expected }
        '-ne'            { return $actualText -ne [string]$Expected }
        '-startsWith'    { return $actualText.StartsWith([string]$Expected, [System.StringComparison]::OrdinalIgnoreCase) }
        '-notStartsWith' { return -not $actualText.StartsWith([string]$Expected, [System.StringComparison]::OrdinalIgnoreCase) }
        '-endsWith'      { return $actualText.EndsWith([string]$Expected, [System.StringComparison]::OrdinalIgnoreCase) }
        '-notEndsWith'   { return -not $actualText.EndsWith([string]$Expected, [System.StringComparison]::OrdinalIgnoreCase) }
        '-contains'      { return $actualText.ToLowerInvariant().Contains(([string]$Expected).ToLowerInvariant()) }
        '-notContains'   { return -not $actualText.ToLowerInvariant().Contains(([string]$Expected).ToLowerInvariant()) }
        '-match'         { return $actualText -match [string]$Expected }
        '-notMatch'      { return $actualText -notmatch [string]$Expected }
        '-in' {
            $values = @(ConvertFrom-EntraDgmInListText -Value ([string]$Expected))
            foreach ($item in $values) { if ($actualText -eq $item) { return $true } }
            return $false
        }
        '-notIn' {
            $values = @(ConvertFrom-EntraDgmInListText -Value ([string]$Expected))
            foreach ($item in $values) { if ($actualText -eq $item) { return $false } }
            return $true
        }
        default { return $false }
    }
}

function Test-EntraDgmConditionLocally {
    param(
        [Parameter(Mandatory)]
        $Condition,
        [Parameter(Mandatory)]
        $AttributeRows
    )

    $lookup = @{}
    foreach ($row in @($AttributeRows)) {
        $lookup[$row.Name] = $row
        if ($row.GraphName) { $lookup[$row.GraphName] = $row }
    }

    $propName = $Condition.Property
    $row = $null
    if ($lookup.ContainsKey($propName)) { $row = $lookup[$propName] }

    $actual = $null
    $collection = @()
    if ($row) {
        $actual = $row.RawValue
        $collection = @(ConvertTo-EntraDgmCollection -Value $row.Collection)
        if ($collection.Count -eq 0 -and $null -ne $actual) {
            $collection = @(ConvertTo-EntraDgmCollection -Value $actual)
        }
    }

    $op = $Condition.Operator
    $expected = $Condition.Value
    $passed = $false

    if ($Condition.Type -eq 'DirectReports' -or $op -eq 'DirectReports') {
        $managerRow = $lookup['managerObjectId']
        $passed = ($null -ne $managerRow -and [string]$managerRow.RawValue -eq [string]$expected)
        return [pscustomobject]@{
            Property = $propName
            Operator = $op
            Expected = $expected
            Actual   = $(if ($managerRow) { $managerRow.RawValue } else { $null })
            Passed   = $passed
        }
    }

    if ($Condition.NullValue -or $op -in @('-eq null', '-ne null')) {
        $isNull = $null -eq $actual -or ([string]$actual -eq '')
        $passed = if ($op -eq '-ne' -or $op -eq '-ne null') { -not $isNull } else { $isNull }
    }
    elseif ($Condition.Type -eq 'Boolean') {
        $actualBool = [bool]$actual
        $expectedBool = [string]$expected -eq 'true'
        $passed = if ($op -eq '-ne') { $actualBool -ne $expectedBool } else { $actualBool -eq $expectedBool }
        $actual = $actualBool.ToString().ToLowerInvariant()
    }
    elseif ($Condition.Type -eq 'MemberOf') {
        $ids = @()
        foreach ($item in $collection) {
            $id = Get-EntraDgmObjectProperty -Object $item -Name 'id'
            if ($id) { $ids += [string]$id } else { $ids += [string]$item }
        }
        $wanted = @(ConvertFrom-EntraDgmInListText -Value ([string]$expected))
        $hit = $false
        foreach ($id in $ids) {
            foreach ($w in $wanted) { if ($id -eq $w) { $hit = $true } }
        }
        $passed = if ($op -eq '-notIn') { -not $hit } else { $hit }
        $actual = ($ids -join ', ')
    }
    elseif ($Condition.Type -eq 'StringCollection') {
        $mode = $Condition.CollectionMode
        if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'any' }
        $itemResults = @()
        foreach ($item in $collection) {
            $itemResults += Test-EntraDgmStringOperator -Actual $item -Operator $op -Expected $expected
        }
        if ($mode -eq 'all') {
            $passed = ($itemResults.Count -eq 0) -or ($itemResults -notcontains $false)
        }
        else {
            $passed = $itemResults -contains $true
        }
        $actual = ($collection -join '; ')
    }
    elseif ($Condition.Type -eq 'ObjectCollection') {
        $mode = $Condition.CollectionMode
        if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'any' }
        $field = $Condition.CollectionField
        if ([string]::IsNullOrWhiteSpace($field)) { $field = 'servicePlanId' }
        $itemResults = @()
        foreach ($item in $collection) {
            $fieldValue = Get-EntraDgmObjectProperty -Object $item -Name $field
            $match = Test-EntraDgmStringOperator -Actual $fieldValue -Operator $op -Expected $expected
            if ($Condition.RequireEnabled) {
                $status = Get-EntraDgmObjectProperty -Object $item -Name 'capabilityStatus'
                $match = $match -and ($status -eq 'Enabled')
            }
            $itemResults += $match
        }
        if ($mode -eq 'all') {
            $passed = ($itemResults.Count -eq 0) -or ($itemResults -notcontains $false)
        }
        else {
            $passed = $itemResults -contains $true
        }
        $actual = ConvertTo-EntraDgmDisplayValue -Value $collection
    }
    else {
        $passed = Test-EntraDgmStringOperator -Actual $actual -Operator $op -Expected $expected
    }

    if ($Condition.Negate) { $passed = -not $passed }

    return [pscustomobject]@{
        Property = $propName
        Operator = $op
        Expected = $expected
        Actual   = $actual
        Passed   = [bool]$passed
    }
}

function Test-EntraDgmRuleLocally {
    param(
        [object[]]$Conditions,
        $AttributeRows
    )

    $results = New-Object System.Collections.ArrayList
    $list = @($Conditions)
    if ($list.Count -eq 0) {
        return [pscustomobject]@{
            Matched = $false
            Results = @()
            Error   = 'No conditions to evaluate.'
        }
    }

    foreach ($condition in $list) {
        $results.Add((Test-EntraDgmConditionLocally -Condition $condition -AttributeRows $AttributeRows)) | Out-Null
    }

    $final = [bool]$results[0].Passed
    for ($i = 1; $i -lt $results.Count; $i++) {
        $join = $list[$i].JoinOperator
        if ([string]::IsNullOrWhiteSpace($join)) { $join = '-and' }
        $join = $join.Trim().ToLowerInvariant()
        if ($join -eq 'or' -or $join -eq '-or') {
            $final = $final -or [bool]$results[$i].Passed
        }
        else {
            $final = $final -and [bool]$results[$i].Passed
        }
    }

    return [pscustomobject]@{
        Matched = [bool]$final
        Results = @($results)
        Error   = $null
    }
}

#Requires -Version 5.1
<#
.SYNOPSIS
    Shared logic for the Exchange Online Quota Manager.

.DESCRIPTION
    Header auto-detection, quota parsing, quota validation, and license formatting.
    This file has no UI and does not connect to Exchange or Microsoft Graph.
#>

function Get-NormalizedHeaderName {
    param([AllowNull()][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return ''
    }

    $clean = $Name.Trim().TrimStart([char]0xFEFF)
    $clean = [regex]::Replace($clean, '[^A-Za-z0-9]', '')
    return $clean.ToLowerInvariant()
}

function Get-HeaderAliases {
    # Exact normalized names only. "prohibitsend" must not steal "prohibitsendreceive".
    return @{
        Identity = @(
            'userprincipalname', 'upn', 'email', 'emailaddress', 'mail',
            'primarysmtpaddress', 'smtp', 'smtpaddress', 'identity',
            'username', 'user', 'login', 'loginname', 'account', 'mailbox',
            'useremail', 'emailid', 'principalname', 'primaryemail',
            'userprincipal', 'samaccountname'
        )
        DisplayName = @(
            'displayname', 'fullname', 'commonname', 'display', 'userdisplayname'
        )
        ProhibitSendReceiveGB = @(
            'prohibitsendreceivegb', 'prohibitsendreceive', 'prohibitsendreceivequota',
            'prohibitsendreceivequotaingb', 'prohibitsendreceivequotagb',
            'sendreceivequota', 'sendreceivegb', 'sendreceive',
            'mailboxprohibitsendreceivequota'
        )
        ProhibitSendGB = @(
            'prohibitsendgb', 'prohibitsend', 'prohibitsendquota',
            'prohibitsendquotaingb', 'prohibitsendquotagb',
            'sendquota', 'sendgb', 'mailboxprohibitsendquota'
        )
        IssueWarningGB = @(
            'issuewarninggb', 'issuewarning', 'issuewarningquota',
            'issuewarningquotaingb', 'issuewarningquotagb',
            'warningquota', 'warninggb', 'warning', 'mailboxissuewarningquota'
        )
        QuotaInGB = @(
            'quotaingb', 'quotagb', 'mailboxquota', 'mailboxsizegb', 'sizegb',
            'newquota', 'newquotagb', 'targetquota', 'targetquotagb', 'quota'
        )
    }
}

function Get-CsvColumnMap {
    param([AllowEmptyCollection()][string[]]$Headers)

    $byNorm = @{}
    foreach ($header in @($Headers)) {
        $norm = Get-NormalizedHeaderName $header
        if ([string]::IsNullOrWhiteSpace($norm)) {
            continue
        }
        if (-not $byNorm.ContainsKey($norm)) {
            $byNorm[$norm] = $header
        }
    }

    $aliases = Get-HeaderAliases
    $map = [ordered]@{
        Identity                = $null
        DisplayName             = $null
        ProhibitSendReceiveGB   = $null
        ProhibitSendGB          = $null
        IssueWarningGB          = $null
        QuotaInGB               = $null
    }

    foreach ($field in @($map.Keys)) {
        foreach ($alias in $aliases[$field]) {
            if ($byNorm.ContainsKey($alias)) {
                $map[$field] = [string]$byNorm[$alias]
                break
            }
        }
    }

    # Exchange "Name" is a valid mailbox identity, but only when nothing stronger was found.
    if (-not $map.Identity -and $byNorm.ContainsKey('name')) {
        $map.Identity = [string]$byNorm['name']
    }
    elseif (-not $map.DisplayName -and $byNorm.ContainsKey('name') -and $map.Identity -ne $byNorm['name']) {
        $map.DisplayName = [string]$byNorm['name']
    }

    return [pscustomobject]$map
}

function Get-CsvDelimiter {
    param([Parameter(Mandatory)][string]$HeaderLine)

    $comma = ([regex]::Matches($HeaderLine, ',')).Count
    $semi = ([regex]::Matches($HeaderLine, ';')).Count
    $tab = ([regex]::Matches($HeaderLine, "`t")).Count

    if ($tab -gt $comma -and $tab -gt $semi) {
        return "`t"
    }
    if ($semi -gt $comma) {
        return ';'
    }
    return ','
}

function Repair-CsvHeaderNames {
    param($Rows)

    $rows = @($Rows)
    if ($rows.Count -eq 0 -or $null -eq $rows[0]) {
        return @()
    }

    $names = @($rows[0].PSObject.Properties.Name)
    $clean = foreach ($name in $names) {
        ($name -replace '^\uFEFF', '').Trim()
    }
    $clean = @($clean)

    $changed = $false
    for ($i = 0; $i -lt $names.Count; $i++) {
        if ($names[$i] -ne $clean[$i]) {
            $changed = $true
            break
        }
    }
    if (-not $changed) {
        return $rows
    }

    $rebuilt = foreach ($row in $rows) {
        $obj = [ordered]@{}
        for ($i = 0; $i -lt $names.Count; $i++) {
            $obj[$clean[$i]] = $row.($names[$i])
        }
        [pscustomobject]$obj
    }
    return @($rebuilt)
}

function Import-QuotaCsv {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "File not found: $Path"
    }

    $content = [System.IO.File]::ReadAllText($Path)
    if ([string]::IsNullOrWhiteSpace($content)) {
        throw 'The CSV file is empty.'
    }

    $content = $content.TrimStart([char]0xFEFF)
    $firstNewline = [regex]::Match($content, '\r?\n')
    $firstLine = if ($firstNewline.Success) { $content.Substring(0, $firstNewline.Index) } else { $content }
    if ([string]::IsNullOrWhiteSpace($firstLine)) {
        throw 'The CSV file does not contain a header row.'
    }

    $delimiter = Get-CsvDelimiter -HeaderLine $firstLine
    $rows = @(ConvertFrom-Csv -InputObject $content -Delimiter $delimiter)
    $rows = @(Repair-CsvHeaderNames $rows)
    $rows = @($rows | Where-Object {
        $null -ne $_ -and @($_.PSObject.Properties.Value | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0
    })
    if ($rows.Count -eq 0 -or $null -eq $rows[0]) {
        throw 'The CSV file has a header row but no mailbox records.'
    }

    $headers = @($rows[0].PSObject.Properties.Name)
    $delimiterName = if ($delimiter -eq "`t") { 'Tab' } elseif ($delimiter -eq ';') { 'Semicolon' } else { 'Comma' }

    return [pscustomobject]@{
        Path       = $Path
        Delimiter  = $delimiterName
        Headers    = $headers
        Rows       = $rows
        ColumnMap  = (Get-CsvColumnMap -Headers $headers)
    }
}

function Get-QuotaCsvTemplateRows {
    return @(
        [pscustomobject]@{
            DisplayName             = 'John Doe'
            UserPrincipalName       = 'john.doe@company.com'
            ProhibitSendReceiveGB   = '100'
            ProhibitSendGB          = '99'
            IssueWarningGB          = '98'
        }
        [pscustomobject]@{
            DisplayName             = 'Jane Smith'
            UserPrincipalName       = 'jane.smith@company.com'
            ProhibitSendReceiveGB   = '50'
            ProhibitSendGB          = '49'
            IssueWarningGB          = '48'
        }
    )
}

function ConvertTo-FlexibleDecimal {
    param([Parameter(Mandatory)][string]$NumberText)

    $t = $NumberText.Trim()
    $lastDot = $t.LastIndexOf('.')
    $lastComma = $t.LastIndexOf(',')

    if ($lastDot -ge 0 -and $lastComma -ge 0) {
        if ($lastDot -gt $lastComma) {
            $t = $t.Replace(',', '')
        }
        else {
            $t = $t.Replace('.', '').Replace(',', '.')
        }
    }
    elseif ($lastComma -ge 0) {
        if ($t -match '^\d{1,3}(,\d{3})+$') {
            $t = $t.Replace(',', '')
        }
        else {
            $t = $t.Replace(',', '.')
        }
    }

    $style = [System.Globalization.NumberStyles]::AllowDecimalPoint -bor `
             [System.Globalization.NumberStyles]::AllowLeadingSign
    return [decimal]::Parse($t, $style, [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-QuotaGigabytes {
    param([AllowNull()][AllowEmptyString()][string]$Raw)

    if ([string]::IsNullOrWhiteSpace($Raw)) {
        return $null
    }

    $text = $Raw.Trim()
    if ($text -match '(?i)^(n/?a|none|null|-+|—)$') {
        return $null
    }
    if ($text -match '(?i)^unlimited\b') {
        throw "Unlimited is not a valid Exchange Online mailbox quota. Enter a size such as 50 or 50GB."
    }

    # Exchange display form: 49.5 GB (53,150,220,288 bytes)
    $text = ($text -replace '\(.*$', '').Trim()
    if ($text -notmatch '(?i)^([+-]?[\d][\d\.,]*)\s*(GB|MB|TB|KB)?$') {
        throw "Unrecognized quota value '$Raw'. Use gigabytes, for example 50 or 50GB."
    }

    $number = ConvertTo-FlexibleDecimal $Matches[1]
    $unit = if ($Matches[2]) { $Matches[2].ToUpperInvariant() } else { 'GB' }
    $gb = switch ($unit) {
        'TB' { $number * [decimal]1024 }
        'MB' { $number / [decimal]1024 }
        'KB' { $number / [decimal]1048576 }
        default { $number }
    }

    return [decimal]::Round($gb, 2, [System.MidpointRounding]::AwayFromZero)
}

function ConvertFrom-ExchangeQuotaValue {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }
    if ($text -match '(?i)unlimited') {
        return $null
    }

    return ConvertTo-QuotaGigabytes $text
}

function Format-ExchangeQuotaParameter {
    param([Parameter(Mandatory)][decimal]$Gigabytes)

    $rounded = [decimal]::Round($Gigabytes, 2, [System.MidpointRounding]::AwayFromZero)
    $number = $rounded.ToString('0.##', [System.Globalization.CultureInfo]::InvariantCulture)
    return "$number`GB"
}

function Format-QuotaNumber {
    param($Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return ''
    }

    $rounded = [decimal]::Round([decimal]$Value, 2, [System.MidpointRounding]::AwayFromZero)
    return $rounded.ToString('0.##', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-MappedCellValue {
    param($Row, [AllowNull()][string]$ColumnName)

    if ([string]::IsNullOrWhiteSpace($ColumnName) -or $null -eq $Row) {
        return $null
    }

    $property = $Row.PSObject.Properties[$ColumnName]
    if ($null -eq $property -or $null -eq $property.Value) {
        return $null
    }

    $text = [string]$property.Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }
    return $text.Trim()
}

function Get-MappedQuotaValue {
    param($Row, [AllowNull()][string]$ColumnName, $ErrorList, [string]$Label)

    if ([string]::IsNullOrWhiteSpace($ColumnName)) {
        return $null
    }

    $raw = Get-MappedCellValue -Row $Row -ColumnName $ColumnName
    if ($null -eq $raw) {
        return $null
    }

    try {
        return ConvertTo-QuotaGigabytes $raw
    }
    catch {
        [void]$ErrorList.Add("${Label}: $($_.Exception.Message)")
        return $null
    }
}

function Resolve-MailboxQuotaRow {
    param(
        [Parameter(Mandatory)]$Row,
        [Parameter(Mandatory)]$ColumnMap
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $identity = Get-MappedCellValue -Row $Row -ColumnName $ColumnMap.Identity
    $display = Get-MappedCellValue -Row $Row -ColumnName $ColumnMap.DisplayName

    $receive = Get-MappedQuotaValue $Row $ColumnMap.ProhibitSendReceiveGB $errors 'ProhibitSendReceiveGB'
    $send = Get-MappedQuotaValue $Row $ColumnMap.ProhibitSendGB $errors 'ProhibitSendGB'
    $warning = Get-MappedQuotaValue $Row $ColumnMap.IssueWarningGB $errors 'IssueWarningGB'

    $usedFallback = $false
    if ($null -eq $receive -and $null -eq $send -and $null -eq $warning -and $errors.Count -eq 0) {
        $fallbackErrors = New-Object System.Collections.Generic.List[string]
        $fallback = Get-MappedQuotaValue $Row $ColumnMap.QuotaInGB $fallbackErrors 'QuotaInGB'
        foreach ($item in $fallbackErrors) {
            [void]$errors.Add($item)
        }
        if ($fallbackErrors.Count -eq 0 -and $null -ne $fallback) {
            $usedFallback = $true
            $receive = $fallback
            $send = $fallback
            if ($fallback -gt 1) {
                $warning = [decimal]::Round($fallback - [decimal]1, 2, [System.MidpointRounding]::AwayFromZero)
            }
            else {
                $warning = $fallback
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($identity)) {
        [void]$errors.Add('No user identity in the mapped identity column.')
    }

    return [pscustomobject]@{
        Identity              = $(if ($identity) { $identity.Trim() } else { '' })
        DisplayName           = $(if ($display) { $display.Trim() } else { '' })
        IssueWarningGB        = $warning
        ProhibitSendGB        = $send
        ProhibitSendReceiveGB = $receive
        UsedQuotaFallback     = $usedFallback
        Errors                = @($errors)
        HasQuotaValue         = (($null -ne $receive) -or ($null -ne $send) -or ($null -ne $warning))
    }
}

function Test-SameQuota {
    param($Left, $Right)

    $leftBlank = ($null -eq $Left -or [string]::IsNullOrWhiteSpace([string]$Left))
    $rightBlank = ($null -eq $Right -or [string]::IsNullOrWhiteSpace([string]$Right))
    if ($leftBlank -and $rightBlank) {
        return $true
    }
    if ($leftBlank -or $rightBlank) {
        return $false
    }

    $a = [decimal]::Round([decimal]$Left, 2, [System.MidpointRounding]::AwayFromZero)
    $b = [decimal]::Round([decimal]$Right, 2, [System.MidpointRounding]::AwayFromZero)
    return ($a -eq $b)
}

function Merge-QuotaTargets {
    param(
        $CurrentIssueWarningGB,
        $CurrentProhibitSendGB,
        $CurrentProhibitSendReceiveGB,
        $RequestedIssueWarningGB,
        $RequestedProhibitSendGB,
        $RequestedProhibitSendReceiveGB
    )

    $pick = {
        param($Requested, $Current)
        if ($null -ne $Requested -and -not [string]::IsNullOrWhiteSpace([string]$Requested)) {
            return [decimal]$Requested
        }
        if ($null -ne $Current -and -not [string]::IsNullOrWhiteSpace([string]$Current)) {
            return [decimal]$Current
        }
        return $null
    }

    $warning = & $pick $RequestedIssueWarningGB $CurrentIssueWarningGB
    $send = & $pick $RequestedProhibitSendGB $CurrentProhibitSendGB
    $receive = & $pick $RequestedProhibitSendReceiveGB $CurrentProhibitSendReceiveGB

    $missing = New-Object System.Collections.Generic.List[string]
    if ($null -eq $warning) { [void]$missing.Add('Issue warning') }
    if ($null -eq $send) { [void]$missing.Add('Prohibit send') }
    if ($null -eq $receive) { [void]$missing.Add('Prohibit send/receive') }

    $changed = $false
    if ($null -ne $RequestedIssueWarningGB -and -not (Test-SameQuota $RequestedIssueWarningGB $CurrentIssueWarningGB)) { $changed = $true }
    if ($null -ne $RequestedProhibitSendGB -and -not (Test-SameQuota $RequestedProhibitSendGB $CurrentProhibitSendGB)) { $changed = $true }
    if ($null -ne $RequestedProhibitSendReceiveGB -and -not (Test-SameQuota $RequestedProhibitSendReceiveGB $CurrentProhibitSendReceiveGB)) { $changed = $true }

    return [pscustomobject]@{
        IssueWarningGB        = $warning
        ProhibitSendGB        = $send
        ProhibitSendReceiveGB = $receive
        Missing               = @($missing)
        IsComplete            = ($missing.Count -eq 0)
        Changed               = $changed
    }
}

function Test-QuotaTargets {
    param(
        $IssueWarningGB,
        $ProhibitSendGB,
        $ProhibitSendReceiveGB
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $present = 0

    $checks = @(
        @{ Name = 'Issue warning'; Value = $IssueWarningGB }
        @{ Name = 'Prohibit send'; Value = $ProhibitSendGB }
        @{ Name = 'Prohibit send/receive'; Value = $ProhibitSendReceiveGB }
    )

    foreach ($check in $checks) {
        if ($null -eq $check.Value -or [string]::IsNullOrWhiteSpace([string]$check.Value)) {
            continue
        }
        $present++
        $number = [decimal]$check.Value
        if ($number -le 0) {
            [void]$errors.Add("$($check.Name) must be greater than 0 GB.")
        }
        elseif ($number -gt 100) {
            [void]$warnings.Add("$($check.Name) is $number GB. Exchange Online primary mailbox quota cannot exceed 100 GB on Plan 2, or 50 GB on Plan 1. The service may reject this value.")
        }
    }

    if ($present -eq 0) {
        [void]$errors.Add('No quota values were provided.')
    }

    $hasWarning = ($null -ne $IssueWarningGB -and -not [string]::IsNullOrWhiteSpace([string]$IssueWarningGB))
    $hasSend = ($null -ne $ProhibitSendGB -and -not [string]::IsNullOrWhiteSpace([string]$ProhibitSendGB))
    $hasReceive = ($null -ne $ProhibitSendReceiveGB -and -not [string]::IsNullOrWhiteSpace([string]$ProhibitSendReceiveGB))

    if ($hasWarning -and $hasSend -and ([decimal]$IssueWarningGB -gt [decimal]$ProhibitSendGB)) {
        [void]$errors.Add('Issue warning must be less than or equal to prohibit send.')
    }
    if ($hasSend -and $hasReceive -and ([decimal]$ProhibitSendGB -gt [decimal]$ProhibitSendReceiveGB)) {
        [void]$errors.Add('Prohibit send must be less than or equal to prohibit send/receive.')
    }
    if ($hasWarning -and $hasReceive -and -not $hasSend -and ([decimal]$IssueWarningGB -gt [decimal]$ProhibitSendReceiveGB)) {
        [void]$errors.Add('Issue warning must be less than or equal to prohibit send/receive.')
    }

    return [pscustomobject]@{
        IsValid  = ($errors.Count -eq 0)
        Errors   = @($errors)
        Warnings = @($warnings)
    }
}

function Format-QuotaValidationMessage {
    param(
        [AllowEmptyCollection()][string[]]$ParseErrors,
        [bool]$HasQuotaValue,
        [bool]$UsedQuotaFallback,
        $IssueWarningGB,
        $ProhibitSendGB,
        $ProhibitSendReceiveGB
    )

    $parseErrors = @($ParseErrors | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($parseErrors.Count -gt 0) {
        return 'Error: ' + ($parseErrors -join ' ')
    }
    if (-not $HasQuotaValue) {
        return 'Skipped: no quota values'
    }

    $check = Test-QuotaTargets -IssueWarningGB $IssueWarningGB -ProhibitSendGB $ProhibitSendGB -ProhibitSendReceiveGB $ProhibitSendReceiveGB
    if (-not $check.IsValid) {
        return 'Error: ' + ($check.Errors -join ' ')
    }
    if ($check.Warnings.Count -gt 0) {
        return 'Warning: ' + ($check.Warnings -join ' ')
    }
    if ($UsedQuotaFallback) {
        return 'Ready (from QuotaInGB)'
    }
    return 'Ready'
}

function Get-MailboxQuotaWriteSteps {
    <#
        Exchange can reject a quota change when the new issue-warning value is
        applied before the send or send/receive ceiling has been raised.
        Raise any ceiling that must grow, then write the final trio.
        Test mode returns one combined step because nothing is changed.
    #>
    param(
        $CurrentIssueWarningGB,
        $CurrentProhibitSendGB,
        $CurrentProhibitSendReceiveGB,
        [Parameter(Mandatory)][decimal]$TargetIssueWarningGB,
        [Parameter(Mandatory)][decimal]$TargetProhibitSendGB,
        [Parameter(Mandatory)][decimal]$TargetProhibitSendReceiveGB,
        [bool]$TestMode
    )

    $final = [pscustomobject]@{
        IssueWarningQuota          = Format-ExchangeQuotaParameter $TargetIssueWarningGB
        ProhibitSendQuota          = Format-ExchangeQuotaParameter $TargetProhibitSendGB
        ProhibitSendReceiveQuota   = Format-ExchangeQuotaParameter $TargetProhibitSendReceiveGB
    }

    $canStage = ($null -ne $CurrentIssueWarningGB -and $null -ne $CurrentProhibitSendGB -and $null -ne $CurrentProhibitSendReceiveGB)
    if ($TestMode -or -not $canStage) {
        return @($final)
    }

    $steps = New-Object System.Collections.Generic.List[object]
    if ([decimal]$TargetProhibitSendReceiveGB -gt [decimal]$CurrentProhibitSendReceiveGB) {
        $steps.Add([pscustomobject]@{
            IssueWarningQuota        = $null
            ProhibitSendQuota        = $null
            ProhibitSendReceiveQuota = Format-ExchangeQuotaParameter $TargetProhibitSendReceiveGB
        }) | Out-Null
    }
    if ([decimal]$TargetProhibitSendGB -gt [decimal]$CurrentProhibitSendGB) {
        $steps.Add([pscustomobject]@{
            IssueWarningQuota        = $null
            ProhibitSendQuota        = Format-ExchangeQuotaParameter $TargetProhibitSendGB
            ProhibitSendReceiveQuota = $null
        }) | Out-Null
    }

    $steps.Add($final) | Out-Null
    return @($steps.ToArray())
}

function Get-SkuDisplayNames {
    if ($script:SkuDisplayNames) {
        return $script:SkuDisplayNames
    }

    # Unknown SKUs stay visible as their SkuPartNumber. This map only adds the product name.
    $script:SkuDisplayNames = @{
        'SPE_E3'                            = 'Microsoft 365 E3'
        'SPE_E5'                            = 'Microsoft 365 E5'
        'SPE_F1'                            = 'Microsoft 365 F3'
        'M365_F1'                           = 'Microsoft 365 F1'
        'DEVELOPERPACK_E5'                  = 'Microsoft 365 E5 Developer'
        'ENTERPRISEPACK'                    = 'Office 365 E3'
        'ENTERPRISEPREMIUM'                 = 'Office 365 E5'
        'ENTERPRISEPREMIUM_NOPSTNCONF'      = 'Office 365 E5 without Audio Conferencing'
        'STANDARDPACK'                      = 'Office 365 E1'
        'STANDARDWOFFPACK'                  = 'Office 365 E2'
        'DESKLESSPACK'                      = 'Office 365 F3'
        'O365_BUSINESS_ESSENTIALS'          = 'Microsoft 365 Business Basic'
        'O365_BUSINESS_PREMIUM'             = 'Microsoft 365 Business Standard'
        'SPB'                               = 'Microsoft 365 Business Premium'
        'SMB_BUSINESS'                      = 'Microsoft 365 Apps for business'
        'OFFICESUBSCRIPTION'                = 'Microsoft 365 Apps for enterprise'
        'EXCHANGESTANDARD'                  = 'Exchange Online (Plan 1)'
        'EXCHANGEENTERPRISE'                = 'Exchange Online (Plan 2)'
        'EXCHANGEDESKLESS'                  = 'Exchange Online Kiosk'
        'EXCHANGEESSENTIALS'                = 'Exchange Online Essentials'
        'EXCHANGEARCHIVE_ADDON'             = 'Exchange Online Archiving for Exchange Online'
        'EXCHANGEARCHIVE'                   = 'Exchange Online Archiving for Exchange Server'
        'ATP_ENTERPRISE'                    = 'Microsoft Defender for Office 365 (Plan 1)'
        'THREAT_INTELLIGENCE'               = 'Microsoft Defender for Office 365 (Plan 2)'
        'EMS'                               = 'Enterprise Mobility + Security E3'
        'EMSPREMIUM'                        = 'Enterprise Mobility + Security E5'
        'AAD_PREMIUM'                       = 'Microsoft Entra ID P1'
        'AAD_PREMIUM_P2'                    = 'Microsoft Entra ID P2'
        'INTUNE_A'                          = 'Microsoft Intune Plan 1'
        'RIGHTSMANAGEMENT'                  = 'Azure Information Protection Plan 1'
        'FLOW_FREE'                         = 'Microsoft Power Automate Free'
        'POWER_BI_STANDARD'                 = 'Power BI (Free)'
        'POWER_BI_PRO'                      = 'Power BI Pro'
        'PBI_PREMIUM_PER_USER'              = 'Power BI Premium Per User'
        'POWERAPPS_VIRAL'                   = 'Microsoft Power Apps Plan 2 Trial'
        'TEAMS_EXPLORATORY'                 = 'Microsoft Teams Exploratory'
        'MCOEV'                             = 'Microsoft Teams Phone Standard'
        'MCOMEETADV'                        = 'Microsoft 365 Audio Conferencing'
        'MCOPSTN1'                          = 'Microsoft 365 Domestic Calling Plan'
        'MCOPSTN2'                          = 'Microsoft 365 International Calling Plan'
        'PHONESYSTEM_VIRTUALUSER'           = 'Microsoft Teams Phone Resource Account'
        'PROJECTPROFESSIONAL'               = 'Planner and Project Plan 3'
        'PROJECTPREMIUM'                    = 'Planner and Project Plan 5'
        'VISIOCLIENT'                       = 'Visio Plan 2'
        'VISIOONLINE_PLAN1'                 = 'Visio Plan 1'
        'STREAM'                            = 'Microsoft Stream'
        'WIN_DEF_ATP'                       = 'Microsoft Defender for Endpoint P2'
        'IDENTITY_THREAT_PROTECTION'        = 'Microsoft 365 E5 Security'
        'INFORMATION_PROTECTION_COMPLIANCE' = 'Microsoft 365 E5 Compliance'
        'MICROSOFT_365_COPILOT'             = 'Microsoft 365 Copilot'
    }
    return $script:SkuDisplayNames
}

function Get-ServicePlanDisplayNames {
    if ($script:ServicePlanDisplayNames) {
        return $script:ServicePlanDisplayNames
    }

    $script:ServicePlanDisplayNames = @{
        'EXCHANGE_S_ENTERPRISE'    = 'Exchange Online (Plan 2)'
        'EXCHANGE_S_STANDARD'      = 'Exchange Online (Plan 1)'
        'EXCHANGE_S_DESKLESS'      = 'Exchange Online Kiosk'
        'EXCHANGE_S_ESSENTIALS'    = 'Exchange Online Essentials'
        'EXCHANGE_S_ARCHIVE_ADDON' = 'Exchange Online Archiving'
        'EXCHANGE_S_ARCHIVE'       = 'Exchange Online Archiving'
        'EXCHANGE_S_FOUNDATION'    = 'Exchange Foundation'
        'TEAMS1'                   = 'Microsoft Teams'
        'SHAREPOINTENTERPRISE'     = 'SharePoint Online (Plan 2)'
        'SHAREPOINTSTANDARD'       = 'SharePoint Online (Plan 1)'
        'SHAREPOINTDESKLESS'       = 'SharePoint Online Kiosk'
        'OFFICESUBSCRIPTION'       = 'Microsoft 365 Apps for enterprise'
        'MCOSTANDARD'              = 'Skype for Business Online (Plan 2)'
        'MCOEV'                    = 'Microsoft Teams Phone Standard'
    }
    return $script:ServicePlanDisplayNames
}

function Get-SkuPartNumberOnly {
    param([AllowNull()][string]$SkuPartNumber)

    if ([string]::IsNullOrWhiteSpace($SkuPartNumber)) {
        return ''
    }
    $part = $SkuPartNumber.Trim()
    if ($part -match ':') {
        $part = ($part -split ':', 2)[1]
    }
    return $part
}

function Get-SkuDisplayName {
    param([AllowNull()][string]$SkuPartNumber)

    $part = Get-SkuPartNumberOnly $SkuPartNumber
    if ([string]::IsNullOrWhiteSpace($part)) {
        return 'Unknown license'
    }

    $map = Get-SkuDisplayNames
    $key = $part.ToUpperInvariant()
    if ($map.ContainsKey($key)) {
        return [string]$map[$key]
    }
    return $part
}

function Get-ServicePlanDisplayName {
    param([AllowNull()][string]$ServicePlanName)

    if ([string]::IsNullOrWhiteSpace($ServicePlanName)) {
        return ''
    }
    $map = Get-ServicePlanDisplayNames
    $key = $ServicePlanName.Trim().ToUpperInvariant()
    if ($map.ContainsKey($key)) {
        return [string]$map[$key]
    }
    return $ServicePlanName.Trim()
}

function ConvertTo-NormalizedLicenses {
    param($Licenses)

    $result = New-Object System.Collections.ArrayList
    foreach ($license in @($Licenses)) {
        if ($null -eq $license) {
            continue
        }

        $part = $null
        if ($license.PSObject.Properties['SkuPartNumber']) {
            $part = [string]$license.SkuPartNumber
        }
        elseif ($license.PSObject.Properties['AccountSkuId']) {
            $part = [string]$license.AccountSkuId
        }

        $skuId = ''
        if ($license.PSObject.Properties['SkuId'] -and $null -ne $license.SkuId) {
            $skuId = [string]$license.SkuId
        }

        $planSource = @()
        if ($license.PSObject.Properties['ServicePlans'] -and $null -ne $license.ServicePlans) {
            $planSource = @($license.ServicePlans)
        }
        elseif ($license.PSObject.Properties['ServiceStatus'] -and $null -ne $license.ServiceStatus) {
            $planSource = @($license.ServiceStatus)
        }

        $plans = New-Object System.Collections.ArrayList
        foreach ($plan in $planSource) {
            if ($null -eq $plan) {
                continue
            }
            $planName = $null
            $status = ''
            if ($plan.PSObject.Properties['ServicePlanName'] -and $null -ne $plan.ServicePlanName) {
                $planName = [string]$plan.ServicePlanName
            }
            elseif ($plan.PSObject.Properties['ServicePlan'] -and $null -ne $plan.ServicePlan) {
                $planName = [string]$plan.ServicePlan.ServiceName
            }
            if ($plan.PSObject.Properties['ProvisioningStatus'] -and $null -ne $plan.ProvisioningStatus) {
                $status = [string]$plan.ProvisioningStatus
            }
            if ([string]::IsNullOrWhiteSpace($planName)) {
                continue
            }

            $planRecord = [pscustomobject]@{
                ServicePlanName = $planName
                ProvisioningStatus = $status
                DisplayName = (Get-ServicePlanDisplayName $planName)
                Enabled = ($status -ne 'Disabled')
            }
            [void]$plans.Add($planRecord)
        }

        $partOnly = Get-SkuPartNumberOnly $part
        $planArray = @($plans.ToArray())
        $enabled = @($planArray | Where-Object { $_.Enabled })
        $disabled = @($planArray | Where-Object { -not $_.Enabled })
        $record = [pscustomobject]@{
            SkuPartNumber = $partOnly
            SkuId         = $skuId
            Product       = (Get-SkuDisplayName $part)
            ServicePlans  = $planArray
            EnabledPlans  = $enabled
            DisabledPlans = $disabled
        }
        [void]$result.Add($record)
    }

    return @($result | Sort-Object Product, SkuPartNumber)
}

function Format-ServicePlanList {
    param($Plans)

    $items = foreach ($plan in @($Plans)) {
        if ($null -eq $plan) {
            continue
        }
        $raw = [string]$plan.ServicePlanName
        $friendly = [string]$plan.DisplayName
        if (-not [string]::IsNullOrWhiteSpace($friendly) -and $friendly -ne $raw) {
            '{0} [{1}]' -f $friendly, $raw
        }
        else {
            $raw
        }
    }
    return ((@($items) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '; ')
}

function Format-LicenseSummary {
    param($Licenses)

    $normalized = @(ConvertTo-NormalizedLicenses $Licenses)
    if ($normalized.Count -eq 0) {
        return 'No licenses assigned'
    }

    $parts = foreach ($item in $normalized) {
        '{0} ({1})' -f $item.Product, $item.SkuPartNumber
    }
    return ($parts -join '; ')
}

function Get-LicenseQuotaWarnings {
    param(
        $Licenses,
        $IssueWarningGB,
        $ProhibitSendGB,
        $ProhibitSendReceiveGB
    )

    $normalized = @(ConvertTo-NormalizedLicenses $Licenses)
    if ($normalized.Count -eq 0) {
        return @()
    }

    $planNames = New-Object System.Collections.Generic.List[string]
    foreach ($license in $normalized) {
        foreach ($plan in @($license.EnabledPlans)) {
            if ($plan.ServicePlanName) {
                [void]$planNames.Add(([string]$plan.ServicePlanName).ToUpperInvariant())
            }
        }
    }

    $hasPlan2 = $planNames.Contains('EXCHANGE_S_ENTERPRISE')
    $hasPlan1 = $planNames.Contains('EXCHANGE_S_STANDARD')
    $warnings = New-Object System.Collections.Generic.List[string]
    $values = @($IssueWarningGB, $ProhibitSendGB, $ProhibitSendReceiveGB) | Where-Object {
        $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_)
    }

    foreach ($value in $values) {
        $number = [decimal]$value
        if ($hasPlan2 -and $number -gt 100) {
            [void]$warnings.Add('Enabled service plan EXCHANGE_S_ENTERPRISE (Exchange Online Plan 2) limits the primary mailbox to 100 GB.')
            break
        }
        if ($hasPlan1 -and -not $hasPlan2 -and $number -gt 50) {
            [void]$warnings.Add('Enabled service plan EXCHANGE_S_STANDARD (Exchange Online Plan 1) limits the primary mailbox to 50 GB.')
            break
        }
    }

    return @($warnings)
}

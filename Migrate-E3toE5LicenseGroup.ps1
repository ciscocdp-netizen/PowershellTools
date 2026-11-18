#Requires -Version 5.1
<#
.SYNOPSIS
    Interactively migrates users from an E3 license group to an E5 license group
    in on-premises Active Directory, then removes them from the E3 group.

.DESCRIPTION
    Workflow:
      1. Pick the SOURCE (E3) group and TARGET (E5) group by searching AD.
      2. Review the user list and back it up to CSV.
      3. Choose Dry Run (no changes) or Live mode.
      4. Phase 1 - Add every source user to the target (E5) group.
      5. Verify target membership in AD (per-user, not a full group dump).
      6. Optional - Trigger an Entra Connect (Azure AD Connect) delta sync.
      7. Optional - Verify the E5 license actually landed in Microsoft 365
         via Microsoft Graph before removing E3.
      8. Phase 2 - Remove only the verified users from the source (E3) group.
      9. Export a full results report to CSV.

    Only users that were successfully added (and optionally verified as licensed
    for E5 with an Active, error-free assignment) are removed from E3, so nobody
    ends up with no license.

    This revision keeps the original interactive flow and fixes production bugs:
      - Add/Remove-ADGroupMember are not used (they enumerate members and fail
        once a group exceeds the ADWS 5,000-member limit). Membership is changed
        with Set-ADObject LDAP add/remove on the member attribute.
      - Target membership is verified per user (SearchScope Base) instead of
        loading every member of a large E5 group.
      - Users are de-duplicated and tracked by distinguishedName, not SAM
        (sAMAccountName is unique per domain, not per forest).
      - MemberOf is not requested on user objects (same 5,000-value ADWS limit).
      - Universal groups are read from a global catalog so other-domain members
        are not missed; writes stay on a writable DC.
      - Domain-local and distribution groups are flagged (they will not apply
        Entra group-based licensing).
      - Graph checks licenseAssignmentStates (Active, no error) instead of
        treating a failed CountViolation assignment as "has E5".
      - Graph lookups retry 429/503/504, fall back from UPN to mail / SAM,
        and do not require the newer Connect-MgGraph -NoWelcome switch.
      - REMOVE confirmation trims whitespace; Read-Host null is safe under
        StrictMode; empty MyDocuments falls back to TEMP.
      - Results are saved after Phase 1 so a later Graph wait cannot lose work.

.PARAMETER SelfTest
    Run helper-function checks and exit. Does not contact Active Directory,
    Entra Connect, or Microsoft Graph.

.PARAMETER OutputDirectory
    Parent folder for the timestamped run folder. Defaults to
    Documents\LicenseGroupMigration (TEMP if Documents is empty).

.NOTES
    Requires : Windows PowerShell 5.1, RSAT ActiveDirectory module (live runs)
    Optional : Microsoft.Graph.Users (license verification)
               ADSync module or remote access to the Entra Connect server
    Rights   : Permission to modify membership of both groups

.EXAMPLE
    .\Migrate-E3toE5LicenseGroup.ps1

.EXAMPLE
    .\Migrate-E3toE5LicenseGroup.ps1 -SelfTest
#>

[CmdletBinding()]
param(
    [switch]$SelfTest,
    [string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Get-NotePropertyValue {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ([string]$key -eq $Name) { return $Object[$key] }
        }
        return $Default
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    if ($null -eq $prop.Value) { return $Default }
    return $prop.Value
}

function ConvertTo-SafeString {
    param($Value)
    if ($null -eq $Value) { return '' }
    return ([string]$Value)
}

function ConvertTo-TrimmedString {
    param($Value)
    return (ConvertTo-SafeString $Value).Trim()
}

function New-IgnoreCaseStringSet {
    # Unary comma: PowerShell enumerates a HashSet on return, so an empty set
    # would otherwise become $null.
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    return , $set
}

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '\'     { [void]$sb.Append('\5c') }
            '*'     { [void]$sb.Append('\2a') }
            '('     { [void]$sb.Append('\28') }
            ')'     { [void]$sb.Append('\29') }
            "`0"    { [void]$sb.Append('\00') }
            default { [void]$sb.Append($ch) }
        }
    }
    $sb.ToString()
}

function ConvertTo-ODataLiteral {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    return $Value.Replace("'", "''")
}

function ConvertTo-SkuKey {
    param([AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $trimmed = $Value.Trim()
    try { return ([guid]$trimmed).ToString('D').ToLowerInvariant() }
    catch { return $trimmed.ToLowerInvariant() }
}

function ConvertTo-GroupSearchFilter {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Term)
    $escaped = ConvertTo-LdapFilterValue -Value $Term
    return "(|(name=*$escaped*)(sAMAccountName=*$escaped*)(displayName=*$escaped*))"
}

function ConvertTo-GroupMemberUserFilter {
    param(
        [Parameter(Mandatory)][string]$GroupDn,
        [bool]$Recursive = $false
    )
    $dnValue = ConvertTo-LdapFilterValue -Value $GroupDn
    $member = if ($Recursive) {
        "(memberOf:1.2.840.113556.1.4.1941:=$dnValue)"
    } else {
        "(memberOf=$dnValue)"
    }
    return "(&(objectCategory=person)(objectClass=user)$member)"
}

function Get-DirectMembershipLdapFilter {
    param([Parameter(Mandatory)][string]$GroupDn)
    $dnValue = ConvertTo-LdapFilterValue -Value $GroupDn
    return "(memberOf=$dnValue)"
}

function Get-DefaultE5SkuCatalog {
    # Well-known full E5 products (not EMS E5 / E5 Security / E5 Compliance add-ons).
    return @(
        [pscustomobject]@{ PartNumber = 'SPE_E5';                         SkuId = '06ebc4ee-1bb5-47dd-8120-11324bc54e06'; Name = 'Microsoft 365 E5' }
        [pscustomobject]@{ PartNumber = 'SPE_E5_NOPSTNCONF';              SkuId = 'cd2925a3-5076-4233-8931-638a8c94f773'; Name = 'Microsoft 365 E5 without Audio Conferencing' }
        [pscustomobject]@{ PartNumber = 'ENTERPRISEPREMIUM';              SkuId = 'c7df2760-2c81-4ef7-b578-5b5392b571df'; Name = 'Office 365 E5' }
        [pscustomobject]@{ PartNumber = 'ENTERPRISEPREMIUM_NOPSTNCONF';   SkuId = '26d45bd9-adf1-46cd-a9e1-51e9a5524128'; Name = 'Office 365 E5 without Audio Conferencing' }
    )
}

function Resolve-E5SkuSets {
    param([string[]]$OperatorValues)

    $partNumbers = New-IgnoreCaseStringSet
    $skuIds = New-IgnoreCaseStringSet
    $catalog = @(Get-DefaultE5SkuCatalog)
    $catalogByPart = @{}
    $catalogById = @{}
    foreach ($row in $catalog) {
        $partKey = ConvertTo-SkuKey $row.PartNumber
        $idKey = ConvertTo-SkuKey $row.SkuId
        $catalogByPart[$partKey] = $row
        $catalogById[$idKey] = $row
        [void]$partNumbers.Add($partKey)
        [void]$skuIds.Add($idKey)
    }

    $requested = @($OperatorValues | ForEach-Object { ConvertTo-TrimmedString $_ } | Where-Object { $_ })
    if ($requested.Count -gt 0) {
        [void]$partNumbers.Clear()
        [void]$skuIds.Clear()
        foreach ($item in $requested) {
            $key = ConvertTo-SkuKey $item
            if (-not $key) { continue }
            if ($catalogByPart.ContainsKey($key)) {
                $row = $catalogByPart[$key]
                [void]$partNumbers.Add((ConvertTo-SkuKey $row.PartNumber))
                [void]$skuIds.Add((ConvertTo-SkuKey $row.SkuId))
            }
            elseif ($catalogById.ContainsKey($key)) {
                $row = $catalogById[$key]
                [void]$partNumbers.Add((ConvertTo-SkuKey $row.PartNumber))
                [void]$skuIds.Add((ConvertTo-SkuKey $row.SkuId))
            }
            elseif ($item -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
                [void]$skuIds.Add($key)
            }
            else {
                [void]$partNumbers.Add($key)
            }
        }
    }

    return [pscustomobject]@{
        PartNumbers = $partNumbers
        SkuIds      = $skuIds
    }
}

function Test-IsE5LicenseActive {
    param(
        $AssignmentStates,
        $LicenseDetails,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$E5PartNumbers,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$E5SkuIds
    )

    $states = @($AssignmentStates)
    if ($states.Count -gt 0 -and $null -ne $states[0]) {
        foreach ($stateObj in $states) {
            $state = ConvertTo-TrimmedString (Get-NotePropertyValue $stateObj 'state' '')
            if ($state -ne 'Active') { continue }
            $err = ConvertTo-TrimmedString (Get-NotePropertyValue $stateObj 'error' '')
            if ($err -and $err -notin @('None', 'NoneError')) { continue }
            $skuId = ConvertTo-SkuKey (Get-NotePropertyValue $stateObj 'skuId' '')
            $part = ConvertTo-SkuKey (Get-NotePropertyValue $stateObj 'skuPartNumber' '')
            if ($skuId -and $E5SkuIds.Contains($skuId)) { return $true }
            if ($part -and $E5PartNumbers.Contains($part)) { return $true }
        }
        return $false
    }

    foreach ($detail in @($LicenseDetails)) {
        if ($null -eq $detail) { continue }
        $part = ConvertTo-SkuKey (Get-NotePropertyValue $detail 'SkuPartNumber' '')
        $skuId = ConvertTo-SkuKey (Get-NotePropertyValue $detail 'SkuId' '')
        if ($part -and $E5PartNumbers.Contains($part)) { return $true }
        if ($skuId -and $E5SkuIds.Contains($skuId)) { return $true }
    }
    return $false
}

function Get-SourceRemovalDecision {
    param(
        [Parameter(Mandatory)]$Result,
        [bool]$RequireE5Verification = $false,
        [bool]$DryRun = $false
    )
    $verified = [bool](Get-NotePropertyValue $Result 'TargetVerified' $false)
    if (-not $verified) { return 'Skipped-NotInTarget' }

    $e5 = ConvertTo-SafeString (Get-NotePropertyValue $Result 'E5LicenseVerified' 'NotChecked')
    if ($RequireE5Verification -and $e5 -ne 'Yes') { return 'Skipped-E5NotConfirmed' }

    $direct = [bool](Get-NotePropertyValue $Result 'DirectSourceMember' $false)
    if (-not $direct) { return 'Skipped-NestedMember' }

    if ($DryRun) { return 'WouldRemove' }
    return 'Eligible'
}

function Get-CloudLicenseGroupWarnings {
    param($Group)
    $warnings = New-Object System.Collections.Generic.List[string]
    $category = ConvertTo-SafeString (Get-NotePropertyValue $Group 'GroupCategory' '')
    $scope = ConvertTo-SafeString (Get-NotePropertyValue $Group 'GroupScope' '')
    if ($category -and $category -ne 'Security') {
        [void]$warnings.Add("Group category is '$category'. Group-based licensing requires a Security group that Entra Connect syncs.")
    }
    if ($scope -eq 'DomainLocal') {
        [void]$warnings.Add("Group scope is DomainLocal. Entra Connect does not sync domain-local groups to Microsoft 365.")
    }
    return @($warnings.ToArray())
}

function Get-UniqueUsersByDn {
    param($Users)
    $seen = New-IgnoreCaseStringSet
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($user in @($Users)) {
        if ($null -eq $user) { continue }
        $dn = ConvertTo-TrimmedString (Get-NotePropertyValue $user 'DistinguishedName' '')
        if (-not $dn) { continue }
        if ($seen.Add($dn)) { [void]$out.Add($user) }
    }
    return @($out.ToArray())
}

function New-UserMigrationResult {
    param($User, [bool]$DirectSourceMember)
    return [pscustomobject]@{
        SamAccountName     = ConvertTo-SafeString (Get-NotePropertyValue $User 'SamAccountName' '')
        DistinguishedName  = ConvertTo-SafeString (Get-NotePropertyValue $User 'DistinguishedName' '')
        DisplayName        = ConvertTo-SafeString (Get-NotePropertyValue $User 'DisplayName' '')
        UserPrincipalName  = ConvertTo-SafeString (Get-NotePropertyValue $User 'UserPrincipalName' '')
        Mail               = ConvertTo-SafeString (Get-NotePropertyValue $User 'mail' '')
        DirectSourceMember = [bool]$DirectSourceMember
        AddToTarget        = 'Pending'
        TargetVerified     = $false
        E5LicenseVerified  = 'NotChecked'
        RemoveFromSource   = 'Pending'
        Notes              = ''
    }
}

function Add-ResultNote {
    param($Result, [string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return }
    $existing = ConvertTo-TrimmedString (Get-NotePropertyValue $Result 'Notes' '')
    if ($existing) { $Result.Notes = "$existing $Message" }
    else { $Result.Notes = $Message.Trim() }
}

function Get-PercentComplete {
    param([int]$Current, [int]$Total)
    if ($Total -le 0) { return 0 }
    $value = [int][Math]::Floor(($Current / $Total) * 100)
    if ($value -lt 0) { return 0 }
    if ($value -gt 100) { return 100 }
    return $value
}

function Test-IntInRange {
    param(
        [AllowEmptyString()][string]$Text,
        [int]$Minimum,
        [int]$Maximum,
        [Parameter(Mandatory)][ref]$Value
    )
    $parsed = 0
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    if (-not [int]::TryParse($Text.Trim(), [ref]$parsed)) { return $false }
    if ($parsed -lt $Minimum -or $parsed -gt $Maximum) { return $false }
    $Value.Value = $parsed
    return $true
}

function ConvertTo-WaitMinutes {
    param([AllowEmptyString()][string]$Text, [int]$Default = 5)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Default }
    $parsed = 0
    if (-not [int]::TryParse($Text.Trim(), [ref]$parsed)) { return $Default }
    if ($parsed -lt 1) { return 1 }
    if ($parsed -gt 120) { return 120 }
    return $parsed
}

function Test-YesNoAnswer {
    param([AllowEmptyString()][string]$Text, [bool]$Default = $false)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Default }
    switch -Regex ($Text.Trim()) {
        '^(y|yes)$' { return $true }
        '^(n|no)$'  { return $false }
        default     { return $null }
    }
}

function Test-ConfirmationPhrase {
    param([AllowEmptyString()][string]$Typed, [Parameter(Mandatory)][string]$Expected)
    if ($null -eq $Typed) { return $false }
    return ($Typed.Trim() -ceq $Expected)
}

function Test-IsAlreadyMemberError {
    param($ErrorRecord)
    $text = ''
    if ($ErrorRecord) {
        try { $text = [string]$ErrorRecord.Exception.Message } catch { $text = [string]$ErrorRecord }
        try {
            if ($ErrorRecord.Exception.InnerException) {
                $text = $text + ' ' + [string]$ErrorRecord.Exception.InnerException.Message
            }
        } catch { }
    }
    return ($text -match 'already exists|attribute or value exists')
}

function Test-IsNotAMemberError {
    param($ErrorRecord)
    $text = ''
    if ($ErrorRecord) {
        try { $text = [string]$ErrorRecord.Exception.Message } catch { $text = [string]$ErrorRecord }
    }
    return ($text -match 'does not exist|not a member|cannot find')
}

function Get-HttpStatusFromError {
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return 0 }

    $response = $null
    try { $response = $ErrorRecord.Exception.Response } catch { }
    if ($response) {
        try {
            $code = Get-NotePropertyValue $response 'StatusCode' $null
            if ($code -is [enum] -or $code -is [int] -or $code -is [byte]) { return [int]$code }
            if ($code -and ($code.PSObject.Properties.Name -contains 'value__')) { return [int]$code.value__ }
        } catch { }
    }

    $ex = $ErrorRecord.Exception
    while ($ex) {
        foreach ($name in @('StatusCode', 'ResponseStatusCode', 'HResult')) {
            try {
                $code = Get-NotePropertyValue $ex $name $null
                if ($code -is [enum] -or $code -is [int]) {
                    $intCode = [int]$code
                    if ($intCode -ge 100 -and $intCode -le 599) { return $intCode }
                }
            } catch { }
        }
        $msg = ConvertTo-SafeString $ex.Message
        if ($msg -match 'status code[^\d]*(\d{3})' -or $msg -match '\b(429|503|504)\b') {
            return [int]$Matches[1]
        }
        try { $ex = $ex.InnerException } catch { break }
    }

    $details = ''
    try { $details = [string]$ErrorRecord.ErrorDetails.Message } catch { }
    if ($details -match '"status"\s*:\s*(\d{3})' -or $details -match '\b(429|503|504)\b') {
        return [int]$Matches[1]
    }
    return 0
}

function Get-RetryAfterSeconds {
    param($ErrorRecord, [int]$Attempt = 1)
    $headerValue = $null
    try {
        $headers = $ErrorRecord.Exception.Response.Headers
        if ($headers) {
            foreach ($key in @('Retry-After', 'RetryAfter')) {
                try {
                    $headerValue = $headers[$key]
                    if ($headerValue) { break }
                } catch { }
            }
        }
    } catch { }

    $seconds = 0
    if ($headerValue) {
        $text = ConvertTo-TrimmedString ($headerValue | Select-Object -First 1)
        [void][int]::TryParse($text, [ref]$seconds)
    }
    if ($seconds -lt 1) {
        $seconds = [Math]::Min(60, [int][Math]::Pow(2, [Math]::Min($Attempt, 5)))
    }
    return $seconds
}

function Test-IsTransientGraphError {
    param($ErrorRecord)
    $status = Get-HttpStatusFromError $ErrorRecord
    return ($status -in 429, 503, 504)
}

function Get-AdUserQueryProperties {
    # Do not request MemberOf: ADWS MaxGroupOrMemberEntries (5,000) can fail the
    # whole user query, and this script never uses the attribute.
    return @('DisplayName', 'UserPrincipalName', 'Enabled', 'mail')
}

function Get-UserGraphLookupKeys {
    param($UserOrResult)
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('UserPrincipalName', 'Mail', 'mail', 'SamAccountName')) {
        $value = ConvertTo-TrimmedString (Get-NotePropertyValue $UserOrResult $name '')
        if ($value -and -not $keys.Contains($value)) { [void]$keys.Add($value) }
    }
    return @($keys.ToArray())
}

function Get-MigrationOutputRoot {
    param([string]$Override)
    if (-not [string]::IsNullOrWhiteSpace($Override)) { return $Override.Trim() }

    $docs = [Environment]::GetFolderPath('MyDocuments')
    if ([string]::IsNullOrWhiteSpace($docs)) {
        $docs = [Environment]::GetFolderPath('UserProfile')
    }
    if ([string]::IsNullOrWhiteSpace($docs)) {
        $docs = [System.IO.Path]::GetTempPath()
    }
    return (Join-Path $docs 'LicenseGroupMigration')
}

function Read-InputLine {
    param([Parameter(Mandatory)][string]$Prompt)
    try {
        $raw = Read-Host $Prompt
    }
    catch {
        $raw = $null
    }
    if ($null -eq $raw) { return '' }
    return $raw.Trim()
}

function Read-YesNo {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [bool]$Default = $false
    )
    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $parsed = Test-YesNoAnswer -Text (Read-InputLine "$Prompt $suffix") -Default $Default
        if ($null -ne $parsed) { return [bool]$parsed }
        Write-Host 'Please answer Y or N.' -ForegroundColor Yellow
    }
}

function Read-ConfirmationPhrase {
    param([Parameter(Mandatory)][string]$Expected)
    $first = Read-InputLine "Type $Expected to confirm"
    if (Test-ConfirmationPhrase -Typed $first -Expected $Expected) { return $true }
    Write-Host "Confirmation did not match. Received: '$first'" -ForegroundColor Yellow
    $second = Read-InputLine "Type $Expected again to confirm, or press Enter to cancel"
    return (Test-ConfirmationPhrase -Typed $second -Expected $Expected)
}

function Show-Header {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'STEP')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    if ($script:LogFile) {
        try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'STEP'  { 'Cyan' }
        default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
}

function Stop-MigrationTranscript {
    if ($script:TranscriptStarted) {
        try { Stop-Transcript | Out-Null } catch { }
        $script:TranscriptStarted = $false
    }
}

function Save-MigrationResults {
    param([string]$Path)
    if (-not $Path) { return }
    $rows = @($script:Results.Values | Sort-Object SamAccountName, DistinguishedName)
    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Copy-Hashtable {
    param([hashtable]$Source)
    $copy = @{}
    if ($Source) {
        foreach ($key in $Source.Keys) { $copy[$key] = $Source[$key] }
    }
    return $copy
}

function Get-ServerHostName {
    param([string]$Server)
    if ([string]::IsNullOrWhiteSpace($Server)) { return '' }
    return ($Server -replace ':\d+$', '')
}

# ---------------------------------------------------------------------------
# AD / Graph operations (live path)
# ---------------------------------------------------------------------------

function Test-ActiveDirectoryModule {
    if (Get-Module -Name ActiveDirectory) { return $true }
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction Stop
        return $true
    }
    return $false
}

function Test-DirectGroupMembership {
    param(
        [Parameter(Mandatory)][string]$UserDn,
        [Parameter(Mandatory)][string]$GroupDn,
        [hashtable]$AdParams
    )
    $filter = Get-DirectMembershipLdapFilter -GroupDn $GroupDn
    $splat = Copy-Hashtable $AdParams
    try {
        $hit = @(Get-ADUser -SearchBase $UserDn -SearchScope Base -LDAPFilter $filter -ResultSetSize 1 @splat)
        return ($hit.Count -gt 0)
    }
    catch {
        return $null
    }
}

function Get-GroupUsers {
    param(
        [Parameter(Mandatory)][string]$GroupDn,
        [bool]$Recursive = $false,
        [hashtable]$AdParams,
        [string[]]$Properties
    )
    $filter = ConvertTo-GroupMemberUserFilter -GroupDn $GroupDn -Recursive:$Recursive
    $splat = Copy-Hashtable $AdParams
    @(Get-ADUser -LDAPFilter $filter -Properties $Properties -ResultPageSize 1000 -ResultSetSize $null @splat)
}

function Add-GroupMemberDirect {
    param(
        [Parameter(Mandatory)][string]$GroupDn,
        [Parameter(Mandatory)][string]$MemberDn,
        [hashtable]$AdParams
    )
    $splat = Copy-Hashtable $AdParams
    try {
        Set-ADObject -Identity $GroupDn -Add @{ member = $MemberDn } @splat
        return 'Added'
    }
    catch {
        if (Test-IsAlreadyMemberError $_) { return 'AlreadyMember' }
        throw
    }
}

function Remove-GroupMemberDirect {
    param(
        [Parameter(Mandatory)][string]$GroupDn,
        [Parameter(Mandatory)][string]$MemberDn,
        [hashtable]$AdParams
    )
    $splat = Copy-Hashtable $AdParams
    try {
        Set-ADObject -Identity $GroupDn -Remove @{ member = $MemberDn } @splat
        return 'Removed'
    }
    catch {
        if (Test-IsNotAMemberError $_) { return 'AlreadyRemoved' }
        throw
    }
}

function Resolve-ReadAdParams {
    param(
        $Group,
        [hashtable]$WriteParams
    )
    $read = Copy-Hashtable $WriteParams
    $scope = ConvertTo-SafeString (Get-NotePropertyValue $Group 'GroupScope' '')
    if ($scope -ne 'Universal') { return $read }

    $gcHost = ''
    try {
        $forest = Get-ADForest @WriteParams
        $gcHost = ConvertTo-TrimmedString (@($forest.GlobalCatalogs) | Select-Object -First 1)
    }
    catch { }

    if (-not $gcHost) {
        $existing = Get-ServerHostName (ConvertTo-SafeString $read['Server'])
        if ($existing) { $gcHost = $existing }
    }

    if ($gcHost) {
        $read['Server'] = "${gcHost}:3268"
        Write-Log "Reading Universal group members from global catalog ${gcHost}:3268 so other-domain users are included."
    }
    return $read
}

function Invoke-GraphWithRetry {
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 5
    )
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return & $ScriptBlock
        }
        catch {
            if (-not (Test-IsTransientGraphError $_) -or $attempt -ge $MaxAttempts) { throw }
            $wait = Get-RetryAfterSeconds -ErrorRecord $_ -Attempt $attempt
            Write-Log "Graph throttled or unavailable (attempt $attempt/$MaxAttempts). Waiting $wait second(s)." -Level WARN
            Start-Sleep -Seconds $wait
        }
    }
}

function Connect-MigrationGraph {
    $connect = Get-Command Connect-MgGraph -ErrorAction Stop
    $params = @{
        Scopes      = @('User.Read.All')
        ErrorAction = 'Stop'
    }
    if ($connect.Parameters.ContainsKey('NoWelcome')) {
        $params['NoWelcome'] = $true
    }
    Connect-MgGraph @params
}

function Get-EntraUserForLicenseCheck {
    param([Parameter(Mandatory)]$Result)

    $select = @('Id', 'UserPrincipalName', 'Mail', 'OnPremisesSamAccountName', 'AssignedLicenses', 'LicenseAssignmentStates')
    $keys = @(Get-UserGraphLookupKeys $Result)

    foreach ($key in $keys) {
        try {
            return Invoke-GraphWithRetry -ScriptBlock {
                Get-MgUser -UserId $key -Property $select -ErrorAction Stop
            }
        }
        catch {
            $status = Get-HttpStatusFromError $_
            if ($status -notin 0, 404) { throw }
        }
    }

    $sam = ConvertTo-TrimmedString (Get-NotePropertyValue $Result 'SamAccountName' '')
    $mail = ConvertTo-TrimmedString (Get-NotePropertyValue $Result 'Mail' '')
    $filters = @()
    if ($sam) { $filters += "onPremisesSamAccountName eq '$(ConvertTo-ODataLiteral $sam)'" }
    if ($mail) { $filters += "mail eq '$(ConvertTo-ODataLiteral $mail)'" }

    foreach ($filter in $filters) {
        $found = @(Invoke-GraphWithRetry -ScriptBlock {
            Get-MgUser -Filter $filter -Property $select -ErrorAction Stop
        })
        if ($found.Count -eq 1) { return $found[0] }
        if ($found.Count -gt 1) {
            throw "Multiple Entra users matched filter $filter"
        }
    }
    return $null
}

function Install-GraphUsersModule {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
    }
    $gallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if ($gallery -and $gallery.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }
    Install-Module Microsoft.Graph.Users -Scope CurrentUser -Force -AllowClobber
}

function Select-ADGroupInteractive {
    param(
        [Parameter(Mandatory)][string]$Purpose,
        [hashtable]$AdParams
    )

    while ($true) {
        $term = Read-InputLine "Search for the $Purpose group (name, partial name, or exact sAMAccountName)"
        if (-not $term) { continue }

        $filter = ConvertTo-GroupSearchFilter -Term $term
        try {
            $found = @(Get-ADGroup -LDAPFilter $filter -Properties Description, GroupCategory, GroupScope -ResultSetSize 51 @AdParams |
                Sort-Object Name)
        }
        catch {
            Write-Log "Group search failed: $($_.Exception.Message)" -Level ERROR
            continue
        }

        if ($found.Count -eq 0) {
            Write-Host 'No groups matched. Try again.' -ForegroundColor Yellow
            continue
        }

        $truncated = $false
        if ($found.Count -gt 50) {
            $truncated = $true
            $found = @($found | Select-Object -First 50)
        }

        Write-Host ''
        for ($i = 0; $i -lt $found.Count; $i++) {
            $g = $found[$i]
            $name = ConvertTo-SafeString (Get-NotePropertyValue $g 'Name' '')
            $category = ConvertTo-SafeString (Get-NotePropertyValue $g 'GroupCategory' '')
            $scope = ConvertTo-SafeString (Get-NotePropertyValue $g 'GroupScope' '')
            Write-Host ('  [{0,2}] {1}  ({2}/{3})' -f ($i + 1), $name, $category, $scope) -ForegroundColor White
            $description = ConvertTo-TrimmedString (Get-NotePropertyValue $g 'Description' '')
            if ($description) { Write-Host "        $description" -ForegroundColor DarkGray }
        }
        if ($truncated) { Write-Host '  (Showing first 50 results - refine your search if needed)' -ForegroundColor DarkYellow }

        $pick = Read-InputLine "Enter the number of the $Purpose group (or press Enter to search again)"
        $index = 0
        if (Test-IntInRange -Text $pick -Minimum 1 -Maximum $found.Count -Value ([ref]$index)) {
            $chosen = $found[$index - 1]
            Write-Host "Selected: $(Get-NotePropertyValue $chosen 'Name' '')" -ForegroundColor Green
            Write-Host "DN      : $(Get-NotePropertyValue $chosen 'DistinguishedName' '')" -ForegroundColor DarkGray
            foreach ($warning in @(Get-CloudLicenseGroupWarnings $chosen)) {
                Write-Log $warning -Level WARN
            }
            if (Read-YesNo -Prompt 'Is this correct?' -Default $true) { return $chosen }
        }
    }
}

# ---------------------------------------------------------------------------
# Self-test (no AD / Graph / network)
# ---------------------------------------------------------------------------

function Invoke-SelfTest {
    function Assert-True {
        param([bool]$Condition, [string]$Name)
        if ($Condition) {
            $script:SelfTestPassed++
            Write-Host "  PASS  $Name" -ForegroundColor Green
        }
        else {
            $script:SelfTestFailed++
            Write-Host "  FAIL  $Name" -ForegroundColor Red
        }
    }

    $script:SelfTestPassed = 0
    $script:SelfTestFailed = 0
    $script:LogFile = $null

    Show-Header 'Migrate-E3toE5LicenseGroup self-test'

    $parseErrors = $null
    $tokens = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$tokens, [ref]$parseErrors)
    Assert-True -Condition ($parseErrors.Count -eq 0) -Name 'Script AST parses with no errors'

    $requiresAd = $false
    foreach ($token in @($tokens)) {
        if ($token.Kind.ToString() -eq 'Comment' -and $token.Text -match '(?im)^#Requires\s+-Modules\s+ActiveDirectory') {
            $requiresAd = $true
            break
        }
    }
    Assert-True -Condition (-not $requiresAd) -Name '#Requires -Modules ActiveDirectory is omitted so -SelfTest runs without RSAT'

    Assert-True -Condition ((ConvertTo-LdapFilterValue -Value 'Group (E3)*\x') -eq 'Group \28E3\29\2a\5cx') -Name 'LDAP filter escaping covers RFC 4515 specials'
    Assert-True -Condition ((ConvertTo-ODataLiteral -Value "O'Brien") -eq "O''Brien") -Name 'OData literals double single quotes'

    $filter = ConvertTo-GroupSearchFilter -Term 'Lic*E5'
    Assert-True -Condition ($filter -eq '(|(name=*Lic\2aE5*)(sAMAccountName=*Lic\2aE5*)(displayName=*Lic\2aE5*))') -Name 'Group search wildcards wrap an escaped term'

    $memberFilter = ConvertTo-GroupMemberUserFilter -GroupDn 'CN=E3 (Lic),OU=Groups,DC=contoso,DC=com'
    Assert-True -Condition ($memberFilter -like '(&(objectCategory=person)(objectClass=user)(memberOf=CN=E3 \28Lic\29,OU=Groups,DC=contoso,DC=com))') -Name 'Direct member query uses memberOf, not Get-ADGroupMember'
    $nestedFilter = ConvertTo-GroupMemberUserFilter -GroupDn 'CN=E3,DC=x' -Recursive $true
    Assert-True -Condition ($nestedFilter -like '*memberOf:1.2.840.113556.1.4.1941:=CN=E3,DC=x*') -Name 'Nested query uses LDAP_MATCHING_RULE_IN_CHAIN'

    $missing = [pscustomobject]@{ SamAccountName = 'jsmith' }
    Assert-True -Condition ((Get-NotePropertyValue -Object $missing -Name 'DisplayName' -Default '') -eq '') -Name 'Get-NotePropertyValue is StrictMode-safe for missing AD properties'

    $emptySet = New-IgnoreCaseStringSet
    Assert-True -Condition ($null -ne $emptySet -and $emptySet.Count -eq 0) -Name 'Empty HashSet is returned without being enumerated to $null'
    $set = New-IgnoreCaseStringSet
    [void]$set.Add('CN=User,DC=Contoso,DC=Com')
    Assert-True -Condition ($set.Contains('cn=user,dc=contoso,dc=com')) -Name 'DN HashSet matching is case-insensitive'

    $dupUsers = @(
        [pscustomobject]@{ SamAccountName = 'jsmith'; DistinguishedName = 'CN=John Smith,OU=A,DC=contoso,DC=com' }
        [pscustomobject]@{ SamAccountName = 'jsmith'; DistinguishedName = 'CN=Jane Smith,OU=B,DC=fabrikam,DC=com' }
        [pscustomobject]@{ SamAccountName = 'jsmith'; DistinguishedName = 'CN=John Smith,OU=A,DC=contoso,DC=com' }
        [pscustomobject]@{ SamAccountName = 'blank'; DistinguishedName = '' }
    )
    $unique = @(Get-UniqueUsersByDn $dupUsers)
    Assert-True -Condition ($unique.Count -eq 2) -Name 'Users are de-duplicated by distinguishedName, not sAMAccountName'

    $defaults = Resolve-E5SkuSets -OperatorValues @()
    Assert-True -Condition ($defaults.PartNumbers.Contains('spe_e5') -and $defaults.SkuIds.Contains('06ebc4ee-1bb5-47dd-8120-11324bc54e06')) -Name 'Default E5 catalog includes SPE_E5 GUID and part number'

    $custom = Resolve-E5SkuSets -OperatorValues @('SPE_E5', 'c7df2760-2c81-4ef7-b578-5b5392b571df')
    Assert-True -Condition ($custom.PartNumbers.Contains('spe_e5') -and $custom.SkuIds.Contains('c7df2760-2c81-4ef7-b578-5b5392b571df') -and -not $custom.PartNumbers.Contains('spe_e5_nopstnconf')) -Name 'Operator SKU list replaces defaults and accepts GUIDs'

    $countViolation = [pscustomobject]@{ skuId = '06ebc4ee-1bb5-47dd-8120-11324bc54e06'; state = 'Error'; error = 'CountViolation' }
    Assert-True -Condition (-not (Test-IsE5LicenseActive -AssignmentStates $countViolation -LicenseDetails $null -E5PartNumbers $defaults.PartNumbers -E5SkuIds $defaults.SkuIds)) -Name 'CountViolation / Error assignment is not treated as licensed'
    $active = [pscustomobject]@{ skuId = '06ebc4ee-1bb5-47dd-8120-11324bc54e06'; state = 'Active'; error = $null }
    Assert-True -Condition (Test-IsE5LicenseActive -AssignmentStates $active -LicenseDetails $null -E5PartNumbers $defaults.PartNumbers -E5SkuIds $defaults.SkuIds) -Name 'Active error-free E5 assignment is accepted'
    $detailOnly = [pscustomobject]@{ SkuPartNumber = 'SPE_E5'; SkuId = '06ebc4ee-1bb5-47dd-8120-11324bc54e06' }
    Assert-True -Condition (Test-IsE5LicenseActive -AssignmentStates @() -LicenseDetails $detailOnly -E5PartNumbers $defaults.PartNumbers -E5SkuIds $defaults.SkuIds) -Name 'LicenseDetails fallback still matches SKU part numbers'

    $alex = [pscustomobject]@{ SamAccountName = 'alex'; DistinguishedName = 'CN=Alex,DC=x'; DisplayName = 'Alex'; UserPrincipalName = 'alex@x.com'; mail = 'alex@x.com' }
    $base = New-UserMigrationResult -User $alex -DirectSourceMember $true
    $base.TargetVerified = $true
    $base.E5LicenseVerified = 'Yes'
    Assert-True -Condition ((Get-SourceRemovalDecision -Result $base -RequireE5Verification $true -DryRun $false) -eq 'Eligible') -Name 'Direct member with verified E5 is eligible for E3 removal'

    $notInTarget = New-UserMigrationResult -User $alex -DirectSourceMember $true
    $notInTarget.TargetVerified = $false
    $notInTarget.E5LicenseVerified = 'Yes'
    Assert-True -Condition ((Get-SourceRemovalDecision -Result $notInTarget -RequireE5Verification $true) -eq 'Skipped-NotInTarget') -Name 'Users not verified in E5 are not removed from E3'

    $noE5 = New-UserMigrationResult -User $alex -DirectSourceMember $true
    $noE5.TargetVerified = $true
    $noE5.E5LicenseVerified = 'No'
    Assert-True -Condition ((Get-SourceRemovalDecision -Result $noE5 -RequireE5Verification $true) -eq 'Skipped-E5NotConfirmed') -Name 'Users without confirmed E5 are not removed from E3'

    $nested = New-UserMigrationResult -User $alex -DirectSourceMember $false
    $nested.TargetVerified = $true
    $nested.E5LicenseVerified = 'Yes'
    Assert-True -Condition ((Get-SourceRemovalDecision -Result $nested -RequireE5Verification $true) -eq 'Skipped-NestedMember') -Name 'Nested-only members are not removed from the parent E3 group'

    $dry = New-UserMigrationResult -User $alex -DirectSourceMember $true
    $dry.TargetVerified = $true
    Assert-True -Condition ((Get-SourceRemovalDecision -Result $dry -RequireE5Verification $false -DryRun $true) -eq 'WouldRemove') -Name 'Dry run marks eligible users WouldRemove'

    $domainLocal = [pscustomobject]@{ GroupCategory = 'Security'; GroupScope = 'DomainLocal' }
    $distro = [pscustomobject]@{ GroupCategory = 'Distribution'; GroupScope = 'Universal' }
    $dlWarn = @(Get-CloudLicenseGroupWarnings $domainLocal)
    $distroWarn = @(Get-CloudLicenseGroupWarnings $distro)
    Assert-True -Condition ($dlWarn.Count -eq 1 -and $dlWarn[0] -like '*DomainLocal*') -Name 'Domain-local groups are flagged as not Entra-synced'
    Assert-True -Condition ($distroWarn.Count -eq 1 -and $distroWarn[0] -like '*Distribution*') -Name 'Distribution groups are flagged as unsuitable for group-based licensing'

    Assert-True -Condition ((Test-YesNoAnswer -Text '' -Default $true) -eq $true) -Name 'Blank yes/no uses the default'
    Assert-True -Condition ((Test-YesNoAnswer -Text 'Y' -Default $false) -eq $true) -Name 'Y is accepted as yes'
    Assert-True -Condition ($null -eq (Test-YesNoAnswer -Text 'maybe' -Default $false)) -Name 'Unrecognized yes/no returns null so the prompt retries'
    Assert-True -Condition (Test-ConfirmationPhrase -Typed " REMOVE`r " -Expected 'REMOVE') -Name 'REMOVE confirmation trims whitespace and CR'
    Assert-True -Condition (-not (Test-ConfirmationPhrase -Typed 'remove' -Expected 'REMOVE')) -Name 'REMOVE confirmation stays case-sensitive'
    Assert-True -Condition ((ConvertTo-TrimmedString $null) -eq '') -Name 'Null input trims to empty instead of throwing under StrictMode'

    $n = 0
    Assert-True -Condition ((Test-IntInRange -Text '2' -Minimum 1 -Maximum 3 -Value ([ref]$n)) -and $n -eq 2) -Name 'Menu index parser accepts a value in range'
    Assert-True -Condition (-not (Test-IntInRange -Text '9' -Minimum 1 -Maximum 3 -Value ([ref]$n))) -Name 'Menu index parser rejects out-of-range values'
    Assert-True -Condition ((ConvertTo-WaitMinutes -Text '' -Default 5) -eq 5) -Name 'Blank wait uses default minutes'
    Assert-True -Condition ((ConvertTo-WaitMinutes -Text '0') -eq 1) -Name 'Zero wait is clamped to at least one minute'
    Assert-True -Condition ((ConvertTo-WaitMinutes -Text '999') -eq 120) -Name 'Excessive wait is clamped to 120 minutes'
    Assert-True -Condition ((Get-PercentComplete -Current 1 -Total 0) -eq 0) -Name 'PercentComplete is 0 when the total is 0'
    Assert-True -Condition ((Get-PercentComplete -Current 3 -Total 3) -eq 100) -Name 'PercentComplete reaches 100 on the last item'

    $already = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.InvalidOperationException 'The specified directory service attribute or value already exists'),
        'AlreadyExists',
        [System.Management.Automation.ErrorCategory]::ResourceExists,
        $null
    )
    Assert-True -Condition (Test-IsAlreadyMemberError $already) -Name 'Set-ADObject already-exists is treated as AlreadyMember'
    $missingMember = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.InvalidOperationException 'The specified directory service attribute or value does not exist'),
        'DoesNotExist',
        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
        $null
    )
    Assert-True -Condition (Test-IsNotAMemberError $missingMember) -Name 'Set-ADObject does-not-exist is treated as already removed'

    $throttled = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.Exception 'Response status code does not indicate success: 429 (Too Many Requests).'),
        'Throttled',
        [System.Management.Automation.ErrorCategory]::ResourceBusy,
        $null
    )
    Assert-True -Condition ((Get-HttpStatusFromError $throttled) -eq 429) -Name 'Graph 429 is parsed from the exception message'
    Assert-True -Condition (Test-IsTransientGraphError $throttled) -Name '429 is retried as a transient Graph error'

    $lookup = Get-UserGraphLookupKeys ([pscustomobject]@{ UserPrincipalName = 'a@x.com'; Mail = 'a@x.com'; SamAccountName = 'a' })
    Assert-True -Condition ($lookup.Count -eq 2 -and $lookup[0] -eq 'a@x.com' -and $lookup[1] -eq 'a') -Name 'Graph lookup keys de-duplicate UPN/mail and fall back to SAM'

    $userProps = @(Get-AdUserQueryProperties)
    Assert-True -Condition (($userProps -contains 'mail') -and ($userProps -notcontains 'MemberOf')) -Name 'User queries do not request MemberOf (ADWS 5,000-value limit)'

    $docsFallback = Get-MigrationOutputRoot -Override ''
    Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($docsFallback)) -Name 'Output root falls back when Documents is empty or omitted'

    $hostOnly = Get-ServerHostName 'dc01.contoso.com:3268'
    Assert-True -Condition ($hostOnly -eq 'dc01.contoso.com') -Name 'GC port is stripped when deriving a writable DC host name'

    Write-Host ''
    Write-Host ("  {0} passed, {1} failed" -f $script:SelfTestPassed, $script:SelfTestFailed) -ForegroundColor $(if ($script:SelfTestFailed) { 'Red' } else { 'Green' })
    return ($script:SelfTestFailed -eq 0)
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

$script:IsDotSourced = ($MyInvocation.InvocationName -eq '.')
$script:TranscriptStarted = $false
$script:LogFile = $null
$script:Results = @{}

if ($SelfTest) {
    $ok = Invoke-SelfTest
    if ($ok) { exit 0 } else { exit 1 }
}

if ($script:IsDotSourced) { return }

# ---------------------------------------------------------------------------
# Setup: output folder, transcript, logging
# ---------------------------------------------------------------------------

$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutputDir = Join-Path -Path (Get-MigrationOutputRoot -Override $OutputDirectory) -ChildPath $Timestamp
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

$script:LogFile = Join-Path $OutputDir 'Migration.log'
$BackupFile     = Join-Path $OutputDir 'SourceGroup_Backup.csv'
$ResultsFile    = Join-Path $OutputDir 'Migration_Results.csv'

try {
    Start-Transcript -Path (Join-Path $OutputDir 'Transcript.txt') -Append | Out-Null
    $script:TranscriptStarted = $true
}
catch {
    Write-Host "Transcript could not be started: $($_.Exception.Message)" -ForegroundColor Yellow
}

Show-Header 'E3 -> E5 License Group Migration'
Write-Host "Output folder: $OutputDir" -ForegroundColor Gray

if (-not (Test-ActiveDirectoryModule)) {
    Write-Log 'The ActiveDirectory module (RSAT) is required for a live run. Use -SelfTest to validate the script without RSAT.' -Level ERROR
    Stop-MigrationTranscript
    return
}

$AdParams = @{}

$dc = Read-InputLine 'Domain controller to use (press Enter for auto-discover)'
if ($dc) { $AdParams['Server'] = $dc }

if (Read-YesNo -Prompt 'Use alternate credentials for AD changes?' -Default $false) {
    $AdParams['Credential'] = Get-Credential -Message 'Enter AD credentials with rights to modify group membership'
}

try {
    $domain = Get-ADDomain @AdParams
    Write-Log "Connected to domain $($domain.DNSRoot) (PDC: $($domain.PDCEmulator))" -Level OK
    if (-not $AdParams.ContainsKey('Server')) {
        # Pin to one DC so reads immediately reflect our writes (avoids replication lag).
        $AdParams['Server'] = $domain.PDCEmulator
        Write-Log "Pinned all write operations to $($domain.PDCEmulator) for consistency."
    }
}
catch {
    Write-Log "Unable to contact Active Directory: $($_.Exception.Message)" -Level ERROR
    Stop-MigrationTranscript
    return
}

$WriteAdParams = Copy-Hashtable $AdParams

# ---------------------------------------------------------------------------
# Group selection
# ---------------------------------------------------------------------------

Show-Header 'Step 1: Select Groups'
$SourceGroup = Select-ADGroupInteractive -Purpose 'SOURCE (E3 license)' -AdParams $WriteAdParams
$TargetGroup = Select-ADGroupInteractive -Purpose 'TARGET (E5 license)' -AdParams $WriteAdParams

$sourceDn = ConvertTo-SafeString (Get-NotePropertyValue $SourceGroup 'DistinguishedName' '')
$targetDn = ConvertTo-SafeString (Get-NotePropertyValue $TargetGroup 'DistinguishedName' '')
$sourceName = ConvertTo-SafeString (Get-NotePropertyValue $SourceGroup 'Name' '')
$targetName = ConvertTo-SafeString (Get-NotePropertyValue $TargetGroup 'Name' '')

if ($sourceDn -eq $targetDn) {
    Write-Log 'Source and target groups are the same. Exiting.' -Level ERROR
    Stop-MigrationTranscript
    return
}

Write-Log "Source (E3) group: $sourceDn"
Write-Log "Target (E5) group: $targetDn"

# ---------------------------------------------------------------------------
# Gather users
# Uses memberOf LDAP queries instead of Get-ADGroupMember, which fails on
# groups over 5,000 members and on foreign security principals.
# ---------------------------------------------------------------------------

Show-Header 'Step 2: Gather Users'

$includeNested = Read-YesNo -Prompt 'Include users from NESTED groups inside the source group? (Only direct members are removed from source. Nested members of a licensed group do not receive the license until they are direct members.)' -Default $false
$includeDisabled = Read-YesNo -Prompt 'Include DISABLED user accounts?' -Default $false

$UserProps = @(Get-AdUserQueryProperties)
$SourceReadParams = Resolve-ReadAdParams -Group $SourceGroup -WriteParams $WriteAdParams
$TargetReadParams = Resolve-ReadAdParams -Group $TargetGroup -WriteParams $WriteAdParams

try {
    $DirectSourceUsers = @(Get-GroupUsers -GroupDn $sourceDn -AdParams $SourceReadParams -Properties $UserProps)
    $SourceUsers = if ($includeNested) {
        try {
            @(Get-GroupUsers -GroupDn $sourceDn -Recursive $true -AdParams $SourceReadParams -Properties $UserProps)
        }
        catch {
            Write-Log "Recursive member search via global catalog failed ($($_.Exception.Message)). Retrying against the writable DC." -Level WARN
            @(Get-GroupUsers -GroupDn $sourceDn -Recursive $true -AdParams $WriteAdParams -Properties $UserProps)
        }
    } else { $DirectSourceUsers }
}
catch {
    Write-Log "Failed to read source group members: $($_.Exception.Message)" -Level ERROR
    Stop-MigrationTranscript
    return
}

$DirectDnSet = New-IgnoreCaseStringSet
foreach ($u in $DirectSourceUsers) {
    $dn = ConvertTo-TrimmedString (Get-NotePropertyValue $u 'DistinguishedName' '')
    if ($dn) { [void]$DirectDnSet.Add($dn) }
}

if (-not $includeDisabled) {
    $enabledUsers = New-Object System.Collections.Generic.List[object]
    $disabledCount = 0
    foreach ($u in @($SourceUsers)) {
        $isEnabled = Get-NotePropertyValue $u 'Enabled' $true
        if ($isEnabled -eq $false) { $disabledCount++ }
        else { [void]$enabledUsers.Add($u) }
    }
    $SourceUsers = @($enabledUsers.ToArray())
    if ($disabledCount -gt 0) { Write-Log "Excluded $disabledCount disabled account(s)." -Level WARN }
}

$SourceUsers = @(Get-UniqueUsersByDn $SourceUsers | Sort-Object SamAccountName, DistinguishedName)

if ($SourceUsers.Count -eq 0) {
    Write-Log 'No users found in the source group with the selected options. Nothing to do.' -Level WARN
    Stop-MigrationTranscript
    return
}

$SourceUsers |
    Select-Object SamAccountName, DisplayName, UserPrincipalName, mail, Enabled, DistinguishedName,
        @{ n = 'DirectMember'; e = { $DirectDnSet.Contains((ConvertTo-SafeString $_.DistinguishedName)) } } |
    Export-Csv -Path $BackupFile -NoTypeInformation -Encoding UTF8
Write-Log "Found $($SourceUsers.Count) user(s). Backup saved to $BackupFile" -Level OK

Write-Host ''
Write-Host 'Preview (first 25):' -ForegroundColor Cyan
$SourceUsers | Select-Object -First 25 SamAccountName, DisplayName, UserPrincipalName, Enabled | Format-Table -AutoSize | Out-Host

if (Read-YesNo -Prompt 'Open the full list in a grid view window?' -Default $false) {
    try { $SourceUsers | Select-Object SamAccountName, DisplayName, UserPrincipalName, Enabled | Out-GridView -Title 'Users to migrate' -Wait }
    catch { Write-Log 'Out-GridView is not available on this system.' -Level WARN }
}

# ---------------------------------------------------------------------------
# Mode selection
# ---------------------------------------------------------------------------

Show-Header 'Step 3: Choose Mode'
Write-Host '  [1] Dry Run  - show what would happen, make NO changes' -ForegroundColor White
Write-Host '  [2] Live Run - make changes in Active Directory' -ForegroundColor White
$modeChoice = ''
do { $modeChoice = Read-InputLine 'Select mode (1 or 2)' } until ($modeChoice -in @('1', '2'))
$DryRun = ($modeChoice -eq '1')

if ($DryRun) {
    Write-Log 'DRY RUN mode selected. No changes will be made.' -Level WARN
}
else {
    Write-Host ''
    Write-Host "You are about to add $($SourceUsers.Count) user(s) to '$targetName'." -ForegroundColor Yellow
    if (-not (Read-YesNo -Prompt 'Continue with LIVE changes?' -Default $false)) {
        Write-Log 'Operator cancelled before Phase 1.' -Level WARN
        Stop-MigrationTranscript
        return
    }
}

$script:Results = @{}
foreach ($u in $SourceUsers) {
    $dn = ConvertTo-TrimmedString (Get-NotePropertyValue $u 'DistinguishedName' '')
    $script:Results[$dn] = New-UserMigrationResult -User $u -DirectSourceMember $DirectDnSet.Contains($dn)
}

# ---------------------------------------------------------------------------
# Phase 1: Add to target (E5) group
# ---------------------------------------------------------------------------

Show-Header 'Step 4: Add Users to TARGET (E5) Group'

$i = 0
foreach ($u in $SourceUsers) {
    $i++
    $dn = ConvertTo-TrimmedString (Get-NotePropertyValue $u 'DistinguishedName' '')
    $r = $script:Results[$dn]
    $sam = $r.SamAccountName
    Write-Progress -Activity "Adding to $targetName" -Status $sam -PercentComplete (Get-PercentComplete -Current $i -Total $SourceUsers.Count)

    $already = Test-DirectGroupMembership -UserDn $dn -GroupDn $targetDn -AdParams $TargetReadParams
    if ($already -eq $true) {
        $r.AddToTarget = 'AlreadyMember'
        $r.TargetVerified = $true
        Write-Log "$sam is already in target group."
        continue
    }

    if ($DryRun) {
        $r.AddToTarget = 'WouldAdd'
        Write-Log "[DRY RUN] Would add $sam to $targetName."
        continue
    }

    try {
        $r.AddToTarget = Add-GroupMemberDirect -GroupDn $targetDn -MemberDn $dn -AdParams $WriteAdParams
        if ($r.AddToTarget -eq 'AlreadyMember') {
            $r.TargetVerified = $true
            Write-Log "$sam is already in target group."
        }
        else {
            Write-Log "Added $sam to $targetName." -Level OK
        }
    }
    catch {
        $r.AddToTarget = 'Failed'
        Add-ResultNote $r "Add failed: $($_.Exception.Message)"
        Write-Log "FAILED to add ${sam}: $($_.Exception.Message)" -Level ERROR
    }
}
Write-Progress -Activity "Adding to $targetName" -Completed

# ---------------------------------------------------------------------------
# Verify target membership in AD
# ---------------------------------------------------------------------------

Show-Header 'Step 5: Verify TARGET Membership in AD'

foreach ($u in $SourceUsers) {
    $dn = ConvertTo-TrimmedString (Get-NotePropertyValue $u 'DistinguishedName' '')
    $r = $script:Results[$dn]
    if ($r.TargetVerified) { continue }

    if ($DryRun -and $r.AddToTarget -eq 'WouldAdd') {
        $r.TargetVerified = $true
        continue
    }

    if ($r.AddToTarget -eq 'Added') {
        $check = Test-DirectGroupMembership -UserDn $dn -GroupDn $targetDn -AdParams $WriteAdParams
        # Set-ADObject succeeded on this DC; do not block E3 removal on a cross-domain memberOf lag.
        $r.TargetVerified = $true
        if ($check -eq $false) {
            Add-ResultNote $r 'Add succeeded but a follow-up memberOf read did not see the membership yet.'
        }
    }
}

$verifiedCount = @($script:Results.Values | Where-Object { $_.TargetVerified }).Count
$failedCount   = $SourceUsers.Count - $verifiedCount
Write-Log "Verified in target group: $verifiedCount  |  Not verified: $failedCount" -Level $(if ($failedCount) { 'WARN' } else { 'OK' })
Save-MigrationResults -Path $ResultsFile

# ---------------------------------------------------------------------------
# Optional: Entra Connect delta sync
# ---------------------------------------------------------------------------

Show-Header 'Step 6: Sync to Microsoft 365 (Optional)'
Write-Host 'Group-based licensing is applied in Entra ID after the membership change syncs.' -ForegroundColor Gray
Write-Host 'Nested membership is ignored by group-based licensing; users must be direct members of the licensed group.' -ForegroundColor Gray

if (-not $DryRun -and (Read-YesNo -Prompt 'Trigger an Entra Connect (Azure AD Connect) delta sync now?' -Default $true)) {
    try {
        Import-Module ADSync -ErrorAction SilentlyContinue
        if (Get-Command -Name Start-ADSyncSyncCycle -ErrorAction SilentlyContinue) {
            Start-ADSyncSyncCycle -PolicyType Delta | Out-Null
            Write-Log 'Delta sync started on this server.' -Level OK
        }
        else {
            $syncServer = Read-InputLine 'Enter the Entra Connect server name (blank to skip)'
            if ($syncServer) {
                $icmParams = @{
                    ComputerName = $syncServer
                    ScriptBlock  = { Import-Module ADSync; Start-ADSyncSyncCycle -PolicyType Delta }
                }
                if ($WriteAdParams.ContainsKey('Credential')) { $icmParams['Credential'] = $WriteAdParams['Credential'] }
                Invoke-Command @icmParams | Out-Null
                Write-Log "Delta sync started on $syncServer." -Level OK
            }
            else { Write-Log 'Sync skipped by operator.' -Level WARN }
        }
    }
    catch {
        Write-Log "Could not start delta sync: $($_.Exception.Message)" -Level WARN
        Write-Log 'Membership will sync on the next scheduled cycle (default every 30 minutes).' -Level WARN
    }
}

# ---------------------------------------------------------------------------
# Optional: Verify E5 license in Microsoft 365 via Microsoft Graph
# ---------------------------------------------------------------------------

Show-Header 'Step 7: Verify E5 License in Microsoft 365 (Recommended)'
Write-Host 'Checking the license in Microsoft 365 ensures no user loses service when E3 is removed.' -ForegroundColor Gray
Write-Host 'Assignments in Error (for example CountViolation / not enough seats) are treated as NOT licensed.' -ForegroundColor Gray

$RequireE5Verification = $false
$script:ConnectedToGraph = $false

if (-not $DryRun -and (Read-YesNo -Prompt 'Verify E5 license assignment via Microsoft Graph before removing E3?' -Default $true)) {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
        Write-Log 'Microsoft.Graph.Users module not found. Install with: Install-Module Microsoft.Graph.Users -Scope CurrentUser' -Level WARN
        if (Read-YesNo -Prompt 'Try installing Microsoft.Graph.Users for the current user now?' -Default $false) {
            try { Install-GraphUsersModule }
            catch { Write-Log "Install failed: $($_.Exception.Message)" -Level ERROR }
        }
    }

    if (Get-Module -ListAvailable -Name Microsoft.Graph.Users) {
        try {
            Import-Module Microsoft.Graph.Users -ErrorAction Stop
            Connect-MigrationGraph
            $script:ConnectedToGraph = $true
            $RequireE5Verification = $true

            Write-Host ''
            Write-Host 'Common E5 SKU part numbers: SPE_E5 (Microsoft 365 E5), ENTERPRISEPREMIUM (Office 365 E5),' -ForegroundColor Gray
            Write-Host '  ENTERPRISEPREMIUM_NOPSTNCONF, SPE_E5_NOPSTNCONF. GUIDs are also accepted.' -ForegroundColor Gray
            $skuInput = Read-InputLine 'Enter E5 SKU part number(s) or GUID(s), comma-separated (Enter for defaults)'
            $skuValues = if ($skuInput) { @($skuInput.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } else { @() }
            $skuSets = Resolve-E5SkuSets -OperatorValues $skuValues

            $toCheck = @($script:Results.Values | Where-Object { $_.TargetVerified })
            $keepChecking = $true

            while ($keepChecking) {
                $pending = @($toCheck | Where-Object { $_.E5LicenseVerified -ne 'Yes' })
                $n = 0
                foreach ($r in $pending) {
                    $n++
                    Write-Progress -Activity 'Checking E5 licenses in Microsoft 365' -Status $r.UserPrincipalName -PercentComplete (Get-PercentComplete -Current $n -Total $pending.Count)
                    $keys = @(Get-UserGraphLookupKeys $r)
                    if ($keys.Count -eq 0) { $r.E5LicenseVerified = 'NoUPN'; continue }
                    try {
                        $mgUser = Get-EntraUserForLicenseCheck -Result $r
                        if ($null -eq $mgUser) {
                            $r.E5LicenseVerified = 'LookupFailed'
                            Add-ResultNote $r 'Graph user not found by UPN, mail, or onPremisesSamAccountName.'
                            continue
                        }
                        $states = @(Get-NotePropertyValue $mgUser 'LicenseAssignmentStates' @())
                        $hasE5 = Test-IsE5LicenseActive -AssignmentStates $states -LicenseDetails $null -E5PartNumbers $skuSets.PartNumbers -E5SkuIds $skuSets.SkuIds
                        if (-not $hasE5 -and (@($states).Count -eq 0 -or $null -eq $states[0])) {
                            $details = @(Invoke-GraphWithRetry -ScriptBlock {
                                Get-MgUserLicenseDetail -UserId $mgUser.Id -ErrorAction Stop
                            })
                            $hasE5 = Test-IsE5LicenseActive -AssignmentStates $null -LicenseDetails $details -E5PartNumbers $skuSets.PartNumbers -E5SkuIds $skuSets.SkuIds
                        }
                        $r.E5LicenseVerified = if ($hasE5) { 'Yes' } else { 'No' }
                    }
                    catch {
                        $r.E5LicenseVerified = 'LookupFailed'
                        Add-ResultNote $r "Graph lookup failed: $($_.Exception.Message)"
                    }
                }
                Write-Progress -Activity 'Checking E5 licenses in Microsoft 365' -Completed
                Save-MigrationResults -Path $ResultsFile

                $licensed   = @($toCheck | Where-Object { $_.E5LicenseVerified -eq 'Yes' }).Count
                $unlicensed = $toCheck.Count - $licensed
                Write-Log "E5 license confirmed: $licensed  |  Not yet confirmed: $unlicensed" -Level $(if ($unlicensed) { 'WARN' } else { 'OK' })

                if ($unlicensed -eq 0) { $keepChecking = $false }
                else {
                    Write-Host ''
                    Write-Host '  [1] Wait and re-check (licensing can take several minutes after sync)' -ForegroundColor White
                    Write-Host '  [2] Proceed - remove E3 ONLY from users with confirmed E5' -ForegroundColor White
                    Write-Host '  [3] Stop here - do not remove anyone from E3' -ForegroundColor White
                    $c = ''
                    do { $c = Read-InputLine 'Choose 1, 2, or 3' } until ($c -in @('1', '2', '3'))
                    switch ($c) {
                        '1' {
                            $mins = ConvertTo-WaitMinutes -Text (Read-InputLine 'Minutes to wait before re-checking [5]') -Default 5
                            Write-Log "Waiting $mins minute(s) before re-checking..."
                            Start-Sleep -Seconds ($mins * 60)
                        }
                        '2' { $keepChecking = $false }
                        '3' {
                            Write-Log 'Operator stopped before removing E3. Users remain in both groups.' -Level WARN
                            foreach ($r in $script:Results.Values) {
                                if ($r.RemoveFromSource -eq 'Pending') { $r.RemoveFromSource = 'SkippedByOperator' }
                            }
                            Save-MigrationResults -Path $ResultsFile
                            Write-Log "Results saved to $ResultsFile" -Level OK
                            if ($script:ConnectedToGraph) { try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { } }
                            Stop-MigrationTranscript
                            Read-InputLine 'Press Enter to exit' | Out-Null
                            return
                        }
                    }
                }
            }
        }
        catch {
            Write-Log "Microsoft Graph verification unavailable: $($_.Exception.Message)" -Level ERROR
            $RequireE5Verification = $false
        }
    }
}

if (-not $DryRun -and -not $RequireE5Verification) {
    Write-Host ''
    Write-Host 'E5 licensing was NOT verified in Microsoft 365.' -ForegroundColor Yellow
    Write-Host 'Confirm in the Microsoft 365 admin center (Billing > Licenses) that E5 is assigned before continuing.' -ForegroundColor Yellow
    if (-not (Read-YesNo -Prompt 'Have you confirmed E5 licenses are applied and want to continue?' -Default $false)) {
        Write-Log 'Operator chose not to remove E3 yet. Re-run the script later to finish.' -Level WARN
        foreach ($r in $script:Results.Values) {
            if ($r.RemoveFromSource -eq 'Pending') { $r.RemoveFromSource = 'SkippedByOperator' }
        }
        Save-MigrationResults -Path $ResultsFile
        Write-Log "Results saved to $ResultsFile" -Level OK
        Stop-MigrationTranscript
        Read-InputLine 'Press Enter to exit' | Out-Null
        return
    }
}

# ---------------------------------------------------------------------------
# Phase 2: Remove from source (E3) group
# ---------------------------------------------------------------------------

Show-Header 'Step 8: Remove Users from SOURCE (E3) Group'

$eligible = @(
    foreach ($u in $SourceUsers) {
        $dn = ConvertTo-TrimmedString (Get-NotePropertyValue $u 'DistinguishedName' '')
        $r = $script:Results[$dn]
        $decision = Get-SourceRemovalDecision -Result $r -RequireE5Verification:$RequireE5Verification -DryRun:$DryRun
        if ($decision -eq 'Eligible' -or $decision -eq 'WouldRemove') {
            $u
        }
        else {
            $r.RemoveFromSource = $decision
            if ($decision -eq 'Skipped-NestedMember') {
                Add-ResultNote $r 'Member via nested group; remove from the nested group manually. Group-based licensing also ignores nested members.'
            }
        }
    }
)

Write-Log "$($eligible.Count) user(s) eligible for removal from $sourceName."

if ($eligible.Count -gt 0 -and -not $DryRun) {
    Write-Host ''
    Write-Host "This will REMOVE $($eligible.Count) user(s) from '$sourceName'." -ForegroundColor Yellow
    if (-not (Read-ConfirmationPhrase -Expected 'REMOVE')) {
        Write-Log 'Removal not confirmed. Users remain in both groups.' -Level WARN
        foreach ($u in $eligible) {
            $dn = ConvertTo-TrimmedString (Get-NotePropertyValue $u 'DistinguishedName' '')
            $script:Results[$dn].RemoveFromSource = 'SkippedByOperator'
        }
        $eligible = @()
    }
}

$i = 0
foreach ($u in $eligible) {
    $i++
    $dn = ConvertTo-TrimmedString (Get-NotePropertyValue $u 'DistinguishedName' '')
    $r = $script:Results[$dn]
    Write-Progress -Activity "Removing from $sourceName" -Status $r.SamAccountName -PercentComplete (Get-PercentComplete -Current $i -Total $eligible.Count)

    if ($DryRun) {
        $r.RemoveFromSource = 'WouldRemove'
        Write-Log "[DRY RUN] Would remove $($r.SamAccountName) from $sourceName."
        continue
    }

    try {
        $status = Remove-GroupMemberDirect -GroupDn $sourceDn -MemberDn $dn -AdParams $WriteAdParams
        $r.RemoveFromSource = $(if ($status -eq 'AlreadyRemoved') { 'AlreadyRemoved' } else { 'Removed' })
        Write-Log "Removed $($r.SamAccountName) from $sourceName." -Level OK
    }
    catch {
        $r.RemoveFromSource = 'Failed'
        Add-ResultNote $r "Remove failed: $($_.Exception.Message)"
        Write-Log "FAILED to remove $($r.SamAccountName): $($_.Exception.Message)" -Level ERROR
    }
}
Write-Progress -Activity "Removing from $sourceName" -Completed

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Show-Header 'Step 9: Summary'

$all = @($script:Results.Values | Sort-Object SamAccountName, DistinguishedName)
Save-MigrationResults -Path $ResultsFile

Write-Host ''
Write-Host 'Add to target (E5):' -ForegroundColor Cyan
$all | Group-Object AddToTarget | Select-Object Name, Count | Format-Table -AutoSize | Out-Host
Write-Host 'Remove from source (E3):' -ForegroundColor Cyan
$all | Group-Object RemoveFromSource | Select-Object Name, Count | Format-Table -AutoSize | Out-Host

$problems = @($all | Where-Object { $_.AddToTarget -eq 'Failed' -or $_.RemoveFromSource -like 'Skipped*' -or $_.RemoveFromSource -eq 'Failed' })
if ($problems.Count -gt 0) {
    Write-Log "$($problems.Count) user(s) need attention. See $ResultsFile" -Level WARN
}
else {
    Write-Log 'All users migrated successfully.' -Level OK
}

if (-not $DryRun -and $RequireE5Verification) {
    Write-Host ''
    Write-Host 'Reminder: run another delta sync so the E3 group removal reaches Microsoft 365.' -ForegroundColor Gray
}

if ($DryRun) { Write-Log 'DRY RUN complete. No changes were made. Re-run and choose Live mode to apply.' -Level WARN }

Write-Log "Log:     $script:LogFile"
Write-Log "Backup:  $BackupFile"
Write-Log "Results: $ResultsFile"

if ($script:ConnectedToGraph -and (Get-Command -Name Disconnect-MgGraph -ErrorAction SilentlyContinue)) {
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
}
Stop-MigrationTranscript
Read-InputLine 'Press Enter to exit' | Out-Null

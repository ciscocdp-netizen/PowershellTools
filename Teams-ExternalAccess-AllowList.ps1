#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive manager for the Microsoft Teams external-access allow list.

.DESCRIPTION
    Signs in to Microsoft Teams, confirms the tenant, and keeps a menu open for
    viewing, exporting, checking, and adding allowed domains. Nothing is written
    until you type ADD.

    The script refuses to replace an "allow all known domains" policy with an
    explicit allow list. That change would block every domain not on the list.

.EXAMPLE
    .\Teams-ExternalAccess-AllowList.ps1

.EXAMPLE
    .\Teams-ExternalAccess-AllowList.ps1 -SelfTest

.NOTES
    Requires the MicrosoftTeams module and permission to read and update the
    tenant federation configuration. AllowedDomains supports at most 4,000 domains.
#>
[CmdletBinding()]
param(
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0

$script:TeamsAllowListLimit = 4000
$script:OpenedTeamsConnection = $false
$script:InputClosed = $false
$script:ConnectedAccount = $null
$script:ConnectedTenantId = $null
$script:ConfigProvider = $null
$script:DomainListUpdater = $null
$script:SessionConnector = $null
$script:SessionDisconnector = $null
$script:SimulatedInput = $null
$script:PromptLog = $null
$script:SnapshotRoot = $null

$script:PromptTenantConfirm = 'Type YES to manage external access for this tenant (anything else stops)'
$script:PromptMenu = 'Select an option (1-6)'
$script:PromptShowBlocked = 'Show blocked domains? (Y/N)'
$script:PromptContinue = 'Press Enter to return to the menu'
$script:PromptCheck = 'Enter domain to check'
$script:PromptAdd = 'Enter a domain (for example, partner.com)'
$script:PromptConfirm = 'Type ADD to apply these changes (anything else cancels)'
$script:PromptShowAllAdditions = 'Show every domain before confirming? (Y/N)'
$script:PromptCsvPath = 'Enter the full path to the CSV file'
$script:PromptCsvColumn = 'Type the column name that contains domains (press Enter to cancel)'
$script:PromptExportPath = 'CSV path (press Enter for the suggested path, or CANCEL)'
$script:PromptCreateFolder = 'Create that folder? (Y/N)'
$script:PromptReplaceFile = 'That file already exists. Replace it? (Y/N)'
$script:PromptFilter = 'Filter (press Enter for the full list, or type part of a domain)'
$script:PromptMore = 'Press Enter for more, or Q to stop'
$script:PromptDisconnect = 'Disconnect from Microsoft Teams? (Y/N)'

function Read-ConsoleLine {
    param([Parameter(Mandatory)][string]$Prompt)

    if ($null -ne $script:PromptLog) {
        [void]$script:PromptLog.Add($Prompt)
    }

    if ($null -ne $script:SimulatedInput) {
        if ($script:SimulatedInput.Count -eq 0) {
            $script:InputClosed = $true
            return $null
        }
        return ([string]$script:SimulatedInput.Dequeue()).Trim()
    }

    $value = Read-Host $Prompt
    if ($null -eq $value) {
        $script:InputClosed = $true
        return $null
    }
    return $value.Trim()
}

function Test-InteractiveSession {
    if ($null -ne $script:SimulatedInput) { return $true }
    if ($Host.Name -eq 'Windows PowerShell ISE Host') { return $true }
    try {
        return -not [Console]::IsInputRedirected
    }
    catch {
        return ($null -ne $Host.UI -and $null -ne $Host.UI.RawUI)
    }
}

function ConvertTo-UserPath {
    param([string]$Path)
    if ($null -eq $Path) { return '' }
    $text = $Path.Trim()
    if ($text.Length -ge 2) {
        $first = $text[0]
        $last = $text[$text.Length - 1]
        if (($first -eq '"' -and $last -eq '"') -or ($first -eq "'" -and $last -eq "'")) {
            $text = $text.Substring(1, $text.Length - 2).Trim()
        }
    }
    return $text
}

function ConvertTo-BooleanValue {
    param($Value)
    if ($Value -is [bool]) { return [bool]$Value }
    $text = ([string]$Value).Trim()
    # [bool]'False' is $true in PowerShell because any non-empty string converts
    # to true. Federation flags sometimes arrive as the strings True and False.
    if ([string]::IsNullOrWhiteSpace($text) -or $text -eq '0') { return $false }
    if ($text -eq '1') { return $true }
    return [System.Convert]::ToBoolean($text)
}

function Get-PropertyValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-NormalizedDomain {
    param([string]$InputDomain)
    if ([string]::IsNullOrWhiteSpace($InputDomain)) { return $null }

    $text = $InputDomain.Trim()
    if ($text.Length -ge 2 -and $text.StartsWith('<') -and $text.EndsWith('>')) {
        $text = $text.Substring(1, $text.Length - 2).Trim()
    }

    if ($text -match '^(?i)https?://') {
        try {
            $uri = [Uri]$text
            if ([string]::IsNullOrWhiteSpace($uri.IdnHost)) { return $null }
            $text = $uri.IdnHost
        }
        catch {
            return $null
        }
    }
    else {
        if ($text -match '^(?i)mailto:(.+)$') {
            $text = $Matches[1].Trim()
        }
        if ($text -match '^[^@\s/]+@(?<Domain>[^@\s/]+)$') {
            $text = $Matches['Domain']
        }
        $slash = $text.IndexOf('/')
        if ($slash -ge 0) { $text = $text.Substring(0, $slash) }
        if ($text -match '^(?<Host>.+):(?<Port>\d+)$') { $text = $Matches['Host'] }
    }

    $text = $text.Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $idn = New-Object System.Globalization.IdnMapping
    $ascii = New-Object 'System.Collections.Generic.List[string]'
    foreach ($label in $text.Split('.')) {
        if ($label -eq '') { return $null }
        try {
            [void]$ascii.Add($idn.GetAscii($label))
        }
        catch {
            return $null
        }
    }
    return ($ascii -join '.').ToLowerInvariant()
}

function Test-DomainName {
    param([string]$Domain)
    if ([string]::IsNullOrWhiteSpace($Domain)) { return $false }
    $parsedAddress = [System.Net.IPAddress]::None
    if ([System.Net.IPAddress]::TryParse($Domain, [ref]$parsedAddress)) { return $false }
    return [bool]($Domain -match '^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$')
}

function ConvertTo-SortedDomainArray {
    param($Values)
    $unique = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($value in @($Values)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            [void]$unique.Add(([string]$value).ToLowerInvariant())
        }
    }
    $sorted = New-Object 'System.Collections.Generic.List[string]'
    foreach ($value in @($unique | Sort-Object)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            [void]$sorted.Add([string]$value)
        }
    }
    # NoEnumerate keeps a 0- or 1-item array intact. A normal return would
    # unwrap it into $null or a single string.
    Write-Output -NoEnumerate $sorted.ToArray()
}

function Get-NameFromDomainEntry {
    param($Entry)
    if ($null -eq $Entry) { return $null }
    if ($Entry -is [string]) { return (ConvertTo-NormalizedDomain -InputDomain $Entry) }

    $domain = Get-PropertyValue -Object $Entry -Name 'Domain'
    if (-not [string]::IsNullOrWhiteSpace([string]$domain)) {
        return (ConvertTo-NormalizedDomain -InputDomain ([string]$domain))
    }

    $text = [string]$Entry
    if ($text -match '^(?i)[a-z0-9][a-z0-9.\-]*(\.[a-z0-9][a-z0-9.\-]*)+$') {
        return (ConvertTo-NormalizedDomain -InputDomain $text)
    }
    return $null
}

function ConvertTo-DomainArray {
    param($Value)
    $names = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $Value) {
        Write-Output -NoEnumerate $names.ToArray()
        return
    }

    $items = New-Object System.Collections.Generic.List[object]
    if ($Value -is [string]) {
        [void]$items.Add($Value)
    }
    else {
        $allowedDomain = Get-PropertyValue -Object $Value -Name 'AllowedDomain'
        $source = $Value
        if ($null -ne $allowedDomain) { $source = $allowedDomain }
        if ($source -is [string] -or -not ($source -is [System.Collections.IEnumerable])) {
            [void]$items.Add($source)
        }
        else {
            foreach ($entry in $source) { [void]$items.Add($entry) }
        }
    }

    foreach ($item in $items) {
        $name = Get-NameFromDomainEntry -Entry $item
        if ($name -and (Test-DomainName -Domain $name)) {
            [void]$names.Add($name)
        }
    }
    Write-Output -NoEnumerate (ConvertTo-SortedDomainArray -Values $names)
}

function Test-AllowAllKnownDomains {
    param($AllowedDomains)
    if ($null -eq $AllowedDomains) { return $false }
    if ($AllowedDomains -is [string]) {
        return ($AllowedDomains.Trim() -eq 'AllowAllKnownDomains')
    }

    $typeNames = New-Object 'System.Collections.Generic.List[string]'
    foreach ($typeName in @($AllowedDomains.PSObject.TypeNames)) {
        [void]$typeNames.Add([string]$typeName)
    }
    [void]$typeNames.Add($AllowedDomains.GetType().FullName)
    foreach ($typeName in $typeNames) {
        if ($typeName -match 'AllowAllKnownDomains') { return $true }
    }
    return ([string]$AllowedDomains -eq 'AllowAllKnownDomains')
}

function Get-Config {
    [CmdletBinding()]
    param()
    if ($null -ne $script:ConfigProvider) {
        return (& $script:ConfigProvider)
    }
    return (Get-CsTenantFederationConfiguration -ErrorAction Stop)
}

function Get-AllowedDomainInfo {
    param([Parameter(Mandatory)]$Config)

    $allowed = Get-PropertyValue -Object $Config -Name 'AllowedDomains'
    $allowAll = Test-AllowAllKnownDomains -AllowedDomains $allowed
    if ($allowAll) {
        $domains = ConvertTo-SortedDomainArray -Values @()
    }
    else {
        $domains = ConvertTo-DomainArray -Value $allowed
    }

    $federationRaw = Get-PropertyValue -Object $Config -Name 'AllowFederatedUsers'
    $federationEnabled = $null
    if ($null -ne $federationRaw) {
        $federationEnabled = ConvertTo-BooleanValue -Value $federationRaw
    }

    $blockAllRaw = Get-PropertyValue -Object $Config -Name 'BlockAllSubdomains'
    $blockAll = $false
    if ($null -ne $blockAllRaw) {
        $blockAll = ConvertTo-BooleanValue -Value $blockAllRaw
    }

    [pscustomobject]@{
        Mode                = $(if ($allowAll) { 'AllowAllKnownDomains' } else { 'AllowList' })
        FederationEnabled   = $federationEnabled
        Domains             = $domains
        BlockedDomains      = (ConvertTo-DomainArray -Value (Get-PropertyValue -Object $Config -Name 'BlockedDomains'))
        BlockAllSubdomains  = [bool]$blockAll
    }
}

function Get-SnapshotFolder {
    if (-not [string]::IsNullOrWhiteSpace($script:SnapshotRoot)) { return $script:SnapshotRoot }
    return (Join-Path -Path (Get-Location).Path -ChildPath 'TeamsAllowListSnapshots')
}

function Export-DomainFile {
    param([string[]]$Domains, [Parameter(Mandatory)][string]$Path)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($domain in @($Domains)) {
        if (-not [string]::IsNullOrWhiteSpace($domain)) {
            [void]$rows.Add([pscustomobject]@{ Domain = $domain })
        }
    }
    if ($rows.Count -eq 0) {
        Set-Content -LiteralPath $Path -Value 'Domain' -Encoding UTF8 -ErrorAction Stop
        return
    }
    $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
}

function Save-DomainSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Info,
        [string]$Prefix = 'Export',
        [string]$Path,
        [switch]$AskPath
    )

    if ($AskPath) {
        $suggested = Join-Path -Path (Get-Location).Path -ChildPath ('AllowedDomains-{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Write-Host "Suggested file: $suggested"
        $entered = Read-ConsoleLine $script:PromptExportPath
        if ($script:InputClosed) { return $null }
        if ([string]::IsNullOrWhiteSpace($entered)) { $Path = $suggested }
        elseif ($entered -eq 'CANCEL') {
            Write-Host 'Export cancelled.' -ForegroundColor Yellow
            return $null
        }
        else { $Path = ConvertTo-UserPath -Path $entered }
    }
    elseif ([string]::IsNullOrWhiteSpace($Path)) {
        $folder = Get-SnapshotFolder
        if (-not (Test-Path -LiteralPath $folder)) {
            New-Item -ItemType Directory -Path $folder -ErrorAction Stop | Out-Null
        }
        $safePrefix = ($Prefix -replace '[^A-Za-z0-9\-]', '')
        if ([string]::IsNullOrWhiteSpace($safePrefix)) { $safePrefix = 'Export' }
        $Path = Join-Path -Path $folder -ChildPath ('{0}-{1}.csv' -f $safePrefix, (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    }
    else {
        $Path = ConvertTo-UserPath -Path $Path
    }

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        Write-Host "Folder does not exist: $parent"
        $create = Read-ConsoleLine $script:PromptCreateFolder
        if ($script:InputClosed -or $create -ne 'Y') {
            Write-Host 'Export cancelled.' -ForegroundColor Yellow
            return $null
        }
        New-Item -ItemType Directory -Path $parent -ErrorAction Stop | Out-Null
    }

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $replace = Read-ConsoleLine $script:PromptReplaceFile
        if ($script:InputClosed -or $replace -ne 'Y') {
            Write-Host 'Export cancelled.' -ForegroundColor Yellow
            return $null
        }
    }

    Export-DomainFile -Domains $Info.Domains -Path $Path
    Write-Host "Wrote $($Info.Domains.Count) domain(s) to $Path" -ForegroundColor Green
    if ($Info.Mode -eq 'AllowAllKnownDomains') {
        Write-Warning 'The exported CSV is not an exhaustive list of allowed external domains because the tenant allows all known domains.'
    }
    return $Path
}

function Get-TextItems {
    param($Value)
    $items = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $Value) {
        Write-Output -NoEnumerate $items.ToArray()
        return
    }
    # A string is enumerable as characters. Treat it as one domain name.
    if ($Value -is [string]) {
        if (-not [string]::IsNullOrWhiteSpace($Value)) { [void]$items.Add($Value) }
    }
    else {
        foreach ($item in $Value) {
            $text = [string]$item
            if (-not [string]::IsNullOrWhiteSpace($text)) { [void]$items.Add($text) }
        }
    }
    Write-Output -NoEnumerate $items.ToArray()
}

function Merge-AllowedDomains {
    param($Existing, $Add)
    $merged = New-Object 'System.Collections.Generic.List[string]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($domain in (Get-TextItems -Value $Existing)) {
        if ($seen.Add($domain)) { [void]$merged.Add($domain) }
    }
    foreach ($domain in (Get-TextItems -Value $Add)) {
        if ($seen.Add($domain)) { [void]$merged.Add($domain) }
    }
    Write-Output -NoEnumerate $merged
}

function Test-RetryableAllowListError {
    param($ErrorRecord)
    if ($ErrorRecord.Exception -is [System.Management.Automation.ParameterBindingException]) { return $true }
    if ($ErrorRecord.Exception -is [System.Management.Automation.CommandNotFoundException]) { return $true }
    $message = [string]$ErrorRecord.Exception.Message
    return ($message -match 'Invalid input parameters' -or $message -match 'list modifier' -or $message -match 'is not recognized' -or $message -match 'not supported')
}

function Get-TeamsCommandErrorText {
    param($ErrorRecord)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($text in @(
        [string]$ErrorRecord.Exception.Message
        $(if ($ErrorRecord.ErrorDetails) { [string]$ErrorRecord.ErrorDetails.Message })
        $(if ($ErrorRecord.Exception.InnerException) { [string]$ErrorRecord.Exception.InnerException.Message })
        [string]$ErrorRecord.FullyQualifiedErrorId
    )) {
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $trimmed = $text.Trim()
        if (-not $lines.Contains($trimmed)) { [void]$lines.Add($trimmed) }
    }
    return ($lines -join ' | ')
}

function Get-FederationSetParameters {
    param(
        [Parameter(Mandatory)][string]$ParameterName,
        $Value
    )
    # The modern cmdlet forwards this call to Set-CsConfigurationModern, whose
    # only body fields are ConfigType and PropertyBag. Any other bound parameter
    # is copied into that bag. -Confirm:$false therefore arrives as a setting
    # the service does not recognize, and every write returns
    # "[ClientError] : Invalid input parameters". Identity has the same problem
    # unless Tenant is sent with it, which this cmdlet fills in on its own.
    return @{ $ParameterName = $Value }
}

function Invoke-TeamsFederationUpdate {
    param([Parameter(Mandatory)][hashtable]$Parameters)
    $ErrorActionPreference = 'Stop'
    $ConfirmPreference = 'None'
    Set-CsTenantFederationConfiguration @Parameters
}

function Add-AllowedDomainPatterns {
    param([Parameter(Mandatory)]$Domains)
    if (-not (Get-Command -Name New-CsEdgeDomainPattern -ErrorAction SilentlyContinue)) {
        throw [System.Management.Automation.CommandNotFoundException]::new('New-CsEdgeDomainPattern is not available.')
    }
    foreach ($domain in (Get-TextItems -Value $Domains)) {
        $pattern = New-CsEdgeDomainPattern -Domain $domain
        Invoke-TeamsFederationUpdate -Parameters (Get-FederationSetParameters -ParameterName 'AllowedDomainsAsAList' -Value @{ Add = $pattern })
    }
}

function Add-AllowedDomainList {
    param([Parameter(Mandatory)]$Domains)
    $values = New-Object 'System.Collections.Generic.List[string]'
    foreach ($domain in (Get-TextItems -Value $Domains)) {
        [void]$values.Add($domain)
    }
    # Example 8: a List[string] inside @{ Add = $list } adds names and leaves
    # every domain already on the allow list in place.
    Invoke-TeamsFederationUpdate -Parameters (Get-FederationSetParameters -ParameterName 'AllowedDomainsAsAList' -Value @{ Add = $values })
}

function Add-AllowedDomainStrings {
    param([Parameter(Mandatory)]$Domains)
    $values = New-Object 'System.Collections.Generic.List[string]'
    foreach ($domain in (Get-TextItems -Value $Domains)) {
        [void]$values.Add($domain)
    }
    Invoke-TeamsFederationUpdate -Parameters (Get-FederationSetParameters -ParameterName 'AllowedDomainsAsAList' -Value @{ Add = $values.ToArray() })
}

function Set-AllowedDomainStrings {
    param([Parameter(Mandatory)]$Domains)
    $values = New-Object 'System.Collections.Generic.List[string]'
    foreach ($domain in (Get-TextItems -Value $Domains)) {
        [void]$values.Add($domain)
    }
    # Example 7: assigning the list replaces the allow list. The merged list
    # already contains every domain that was configured before this add.
    Invoke-TeamsFederationUpdate -Parameters (Get-FederationSetParameters -ParameterName 'AllowedDomainsAsAList' -Value $values)
}

function Set-AllowedDomainsByPattern {
    param([Parameter(Mandatory)]$Domains)
    if (-not (Get-Command -Name New-CsEdgeDomainPattern -ErrorAction SilentlyContinue) -or
        -not (Get-Command -Name New-CsEdgeAllowList -ErrorAction SilentlyContinue)) {
        throw 'The Teams module rejected the allow-list update, and New-CsEdgeDomainPattern is not available. Update the module with: Update-Module MicrosoftTeams'
    }

    $names = @(Get-TextItems -Value $Domains)
    $patterns = New-Object object[] $names.Count
    for ($i = 0; $i -lt $names.Count; $i++) {
        $patterns[$i] = New-CsEdgeDomainPattern -Domain $names[$i]
    }
    $allowList = New-CsEdgeAllowList -AllowedDomain @($patterns)
    Invoke-TeamsFederationUpdate -Parameters (Get-FederationSetParameters -ParameterName 'AllowedDomains' -Value $allowList)
}

function Update-AllowedDomainList {
    param(
        [Parameter(Mandatory)]$List,
        [string[]]$ExistingDomains
    )
    if ($List.Count -eq 0) { throw 'No domains were supplied to add.' }

    if ($null -ne $script:DomainListUpdater) {
        & $script:DomainListUpdater $List
        return
    }

    $command = Get-Command -Name Set-CsTenantFederationConfiguration -ErrorAction SilentlyContinue
    if (-not $command) {
        throw 'Set-CsTenantFederationConfiguration is not available. Install or update the MicrosoftTeams module.'
    }

    $attempts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($attempt in @(
        @{ Name = 'Domain list add'; Action = { Add-AllowedDomainList -Domains $List } }
        @{ Name = 'String array add'; Action = { Add-AllowedDomainStrings -Domains $List } }
        @{ Name = 'Domain pattern add'; Action = { Add-AllowedDomainPatterns -Domains $List } }
    )) {
        try {
            & $attempt.Action
            return
        }
        catch {
            if (-not (Test-RetryableAllowListError -ErrorRecord $_)) { throw }
            $detail = Get-TeamsCommandErrorText -ErrorRecord $_
            [void]$attempts.Add("$($attempt.Name): $detail")
            Write-Host "$($attempt.Name) was rejected: $detail" -ForegroundColor Yellow
        }
    }

    Write-Host 'Retrying with the full allow list, including every domain already configured.' -ForegroundColor Yellow

    $merged = Merge-AllowedDomains -Existing $ExistingDomains -Add $List
    foreach ($domain in @($ExistingDomains)) {
        if ([string]::IsNullOrWhiteSpace($domain)) { continue }
        if (-not $merged.Contains($domain)) {
            throw "Stopped before replacing the allow list because $domain was missing from the rebuilt list. $($attempts[0])"
        }
    }

    if ($command.Parameters.ContainsKey('AllowedDomainsAsAList')) {
        try {
            Set-AllowedDomainStrings -Domains $merged
            return
        }
        catch {
            if (-not (Test-RetryableAllowListError -ErrorRecord $_)) { throw }
            $detail = Get-TeamsCommandErrorText -ErrorRecord $_
            [void]$attempts.Add("Full list replace: $detail")
            Write-Host "Full list replace was also rejected: $detail" -ForegroundColor Yellow
        }
    }

    try {
        Set-AllowedDomainsByPattern -Domains $merged
    }
    catch {
        [void]$attempts.Add("Domain pattern replace: $(Get-TeamsCommandErrorText -ErrorRecord $_)")
        $module = Get-Module -Name MicrosoftTeams | Select-Object -First 1
        $version = if ($module) { [string]$module.Version } else { 'not reported' }
        throw ("The Teams service rejected the allow-list update. No domains were changed. MicrosoftTeams module: $version`n" + ($attempts -join "`n"))
    }
}

function Get-AllowedDomainAddition {
    param([string[]]$RequestedDomains, [Parameter(Mandatory)]$Info)

    $notices = New-Object 'System.Collections.Generic.List[object]'
    $selected = New-Object 'System.Collections.Generic.List[string]'
    if ($Info.Mode -eq 'AllowAllKnownDomains') {
        return [pscustomobject]@{
            Status   = 'AllowAllRefused'
            Domains  = $selected
            Notices  = $notices
            HadInput = $false
        }
    }

    $existing = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($domain in @($Info.Domains)) {
        if (-not [string]::IsNullOrWhiteSpace($domain)) { [void]$existing.Add($domain) }
    }
    $pending = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $hadInput = $false

    foreach ($inputDomain in @($RequestedDomains)) {
        if ([string]::IsNullOrWhiteSpace($inputDomain)) { continue }
        $hadInput = $true
        if ($inputDomain -match '\*') {
            [void]$notices.Add([pscustomobject]@{
                Level   = 'Warning'
                Message = "Skipping wildcard entry: $inputDomain. Add the domain name itself."
            })
            continue
        }

        $domain = ConvertTo-NormalizedDomain -InputDomain $inputDomain
        if (-not (Test-DomainName -Domain $domain)) {
            [void]$notices.Add([pscustomobject]@{
                Level   = 'Warning'
                Message = "Skipping invalid domain: $inputDomain"
            })
            continue
        }
        if ($existing.Contains($domain)) {
            [void]$notices.Add([pscustomobject]@{
                Level   = 'Info'
                Message = "Already in the allow list: $domain"
            })
            continue
        }
        if (-not $pending.Add($domain)) {
            [void]$notices.Add([pscustomobject]@{
                Level   = 'Info'
                Message = "Duplicate in this request: $domain"
            })
            continue
        }
        [void]$selected.Add($domain)
    }

    if (-not $hadInput) {
        return [pscustomobject]@{ Status = 'NoInput'; Domains = $selected; Notices = $notices; HadInput = $false }
    }
    if ($selected.Count -eq 0) {
        return [pscustomobject]@{ Status = 'NothingToAdd'; Domains = $selected; Notices = $notices; HadInput = $true }
    }

    $resulting = @($Info.Domains).Count + $selected.Count
    if ($resulting -gt $script:TeamsAllowListLimit) {
        throw "The resulting allow list would contain $resulting domains, which exceeds the documented limit of $($script:TeamsAllowListLimit)."
    }

    return [pscustomobject]@{ Status = 'Ready'; Domains = $selected; Notices = $notices; HadInput = $true }
}

function Write-DomainNotices {
    param($Notices)
    if ($null -eq $Notices) { return }
    # @($genericList) throws under StrictMode. Enumerate the list directly.
    foreach ($notice in $Notices) {
        if ($null -eq $notice) { continue }
        if ($notice.Level -eq 'Warning') { Write-Warning $notice.Message }
        else { Write-Host $notice.Message -ForegroundColor Yellow }
    }
}

function Show-AdditionPreview {
    param($Domains)
    Write-Host ''
    Write-Host 'Domains to add:' -ForegroundColor Cyan
    $limit = 30
    $count = $Domains.Count
    $preview = $count
    if ($count -gt $limit) { $preview = $limit }
    for ($i = 0; $i -lt $preview; $i++) {
        Write-Host ("  {0}" -f $Domains[$i])
    }
    if ($count -gt $limit) {
        Write-Host ("  ... and {0} more" -f ($count - $limit))
        $showAll = Read-ConsoleLine $script:PromptShowAllAdditions
        if ($script:InputClosed) { return $false }
        if ($showAll -eq 'Y') {
            foreach ($domain in $Domains) { Write-Host ("  {0}" -f $domain) }
        }
    }
    return $true
}

function Add-AllowedDomains {
    param([string[]]$RequestedDomains)

    $info = Get-AllowedDomainInfo -Config (Get-Config)
    if ($info.FederationEnabled -eq $false) {
        Write-Warning 'AllowFederatedUsers is FALSE. Adding domains will not make external federation work until an administrator enables it.'
    }

    $plan = Get-AllowedDomainAddition -RequestedDomains $RequestedDomains -Info $info
    if ($plan.Status -eq 'AllowAllRefused') {
        Write-Warning 'Your tenant is currently configured to allow ALL known external domains (subject to any blocklist).'
        Write-Warning 'An explicit allowlist would change the access model. This script will not make that change.'
        return
    }

    Write-DomainNotices -Notices $plan.Notices
    if ($plan.Status -eq 'NoInput') {
        Write-Host 'No domain entered.' -ForegroundColor Yellow
        return
    }
    if ($plan.Status -eq 'NothingToAdd') {
        Write-Host 'No new valid domains to add.' -ForegroundColor Yellow
        return
    }

    $stillPreviewing = Show-AdditionPreview -Domains $plan.Domains
    if (-not $stillPreviewing -or $script:InputClosed) { return }

    $answer = Read-ConsoleLine $script:PromptConfirm
    if ($script:InputClosed -or $answer -cne 'ADD') {
        Write-Host 'Cancelled.'
        return
    }

    $beforePath = Save-DomainSnapshot -Info $info -Prefix 'BeforeAdd'
    Write-Host "Saved a rollback snapshot: $beforePath" -ForegroundColor Cyan
    Write-Host "Adding $($plan.Domains.Count) domain(s)..." -ForegroundColor Cyan
    Update-AllowedDomainList -List $plan.Domains -ExistingDomains $info.Domains

    Write-Host 'Update command completed. Re-reading the tenant configuration...' -ForegroundColor Cyan
    $after = Get-AllowedDomainInfo -Config (Get-Config)
    if ($after.Mode -eq 'AllowAllKnownDomains') {
        Write-Warning 'The tenant is still set to allow all known domains. The new entries are not an enforced allow list.'
    }
    foreach ($domain in $plan.Domains) {
        if ($after.Domains -contains $domain) {
            Write-Host "Verified: $domain" -ForegroundColor Green
        }
        else {
            Write-Warning "Not yet visible in the retrieved configuration: $domain. Check again after propagation."
        }
    }
    $afterPath = Save-DomainSnapshot -Info $after -Prefix 'AfterAdd'
    Write-Host "Saved the post-change snapshot: $afterPath" -ForegroundColor Cyan
}

function Format-CheckedDomain {
    param([string]$Raw, [string]$Normalized)
    $trimmed = $Raw.Trim()
    if ($trimmed -eq $Normalized) { return "'$Normalized'" }
    return "'$trimmed' (as '$Normalized')"
}

function Find-BlockedDomainMatch {
    param([string]$Domain, [string[]]$Blocked)
    $exact = $null
    $parent = $null
    foreach ($blocked in @($Blocked)) {
        if ([string]::IsNullOrWhiteSpace($blocked)) { continue }
        if ($Domain -eq $blocked) { $exact = $blocked }
        elseif ($Domain.EndsWith(".$blocked") -and ($null -eq $parent -or $blocked.Length -gt $parent.Length)) {
            $parent = $blocked
        }
    }
    [pscustomobject]@{ Exact = $exact; Parent = $parent }
}

function New-DomainStatus {
    param([string]$Code, [string]$Message, [string]$Color)
    [pscustomobject]@{ Code = $Code; Message = $Message; Color = $Color }
}

function Get-ExternalDomainStatus {
    param([Parameter(Mandatory)][string]$InputDomain, [Parameter(Mandatory)]$Info)

    if ($InputDomain -match '\*') {
        return (New-DomainStatus -Code 'Invalid' -Color 'Yellow' -Message "'$($InputDomain.Trim())' is not a valid domain name. Wildcards are not accepted; add the domain itself.")
    }

    $normalized = ConvertTo-NormalizedDomain -InputDomain $InputDomain
    if (-not (Test-DomainName -Domain $normalized)) {
        return (New-DomainStatus -Code 'Invalid' -Color 'Yellow' -Message "'$($InputDomain.Trim())' is not a valid domain name.")
    }

    $subject = Format-CheckedDomain -Raw $InputDomain -Normalized $normalized
    $match = Find-BlockedDomainMatch -Domain $normalized -Blocked $Info.BlockedDomains
    $listed = $Info.Domains -contains $normalized
    $unknownFederation = ''
    if ($null -eq $Info.FederationEnabled) {
        $unknownFederation = ' The AllowFederatedUsers setting was not returned, so this does not confirm that federation is turned on.'
    }

    if ($Info.FederationEnabled -eq $false) {
        if ($Info.Mode -eq 'AllowAllKnownDomains') {
            return (New-DomainStatus -Code 'FederationDisabled' -Color 'Yellow' -Message "AllowFederatedUsers is FALSE, so $subject is not allowed. The tenant would otherwise allow all known domains.")
        }
        if ($listed) {
            return (New-DomainStatus -Code 'FederationDisabled' -Color 'Yellow' -Message "$subject is on the allow list, but AllowFederatedUsers is FALSE, so external federation is off for the tenant.")
        }
        return (New-DomainStatus -Code 'FederationDisabled' -Color 'Yellow' -Message "AllowFederatedUsers is FALSE, so $subject is not allowed. It is also not on the allow list.")
    }

    if ($Info.Mode -eq 'AllowAllKnownDomains') {
        if ($match.Exact) {
            return (New-DomainStatus -Code 'Blocked' -Color 'Red' -Message "$subject is blocked.$unknownFederation")
        }
        if ($match.Parent -and $Info.BlockAllSubdomains) {
            return (New-DomainStatus -Code 'Blocked' -Color 'Red' -Message "$subject is blocked because it is a subdomain of '$($match.Parent)' and BlockAllSubdomains is on.$unknownFederation")
        }
        if ($match.Parent) {
            return (New-DomainStatus -Code 'AllowedThoughParentBlocked' -Color 'Yellow' -Message "$subject is allowed because the tenant allows all known domains. '$($match.Parent)' is on the block list, and BlockAllSubdomains is off, so this subdomain is not blocked.$unknownFederation")
        }
        return (New-DomainStatus -Code 'AllowedByOpenFederation' -Color 'Green' -Message "$subject is allowed because the tenant allows all known domains and it is not on the block list.$unknownFederation")
    }

    if ($listed) {
        $message = "$subject is explicitly allowed."
        if ($match.Exact -or $match.Parent) {
            $message += ' It is also on the block list, which is ignored while an explicit allow list is in use.'
        }
        return (New-DomainStatus -Code 'ExplicitlyAllowed' -Color 'Green' -Message ($message + $unknownFederation))
    }

    $message = "$subject is not on the organization-wide allow list."
    if ($match.Exact -or ($match.Parent -and $Info.BlockAllSubdomains)) {
        $message += ' It is also on the block list, which is ignored while an explicit allow list is in use.'
    }
    return (New-DomainStatus -Code 'NotListed' -Color 'Yellow' -Message ($message + $unknownFederation))
}

function Format-FederationState {
    param($Value)
    if ($null -eq $Value) { return 'Unknown' }
    if ($Value) { return 'True' }
    return 'False'
}

function Show-DomainPages {
    param([string[]]$Domains)
    $items = New-Object 'System.Collections.Generic.List[string]'
    foreach ($domain in @($Domains)) {
        if (-not [string]::IsNullOrWhiteSpace($domain)) { [void]$items.Add($domain) }
    }
    if ($items.Count -eq 0) {
        Write-Host '(none)'
        return
    }

    if ($items.Count -gt 40) {
        $filter = Read-ConsoleLine $script:PromptFilter
        if ($script:InputClosed) { return }
        if (-not [string]::IsNullOrWhiteSpace($filter)) {
            $pattern = '*{0}*' -f [System.Management.Automation.WildcardPattern]::Escape($filter.ToLowerInvariant())
            $filtered = New-Object 'System.Collections.Generic.List[string]'
            foreach ($domain in $items) {
                if ($domain.ToLowerInvariant() -like $pattern) { [void]$filtered.Add($domain) }
            }
            Write-Host "Matches: $($filtered.Count)"
            $items = $filtered
        }
    }

    if ($items.Count -eq 0) {
        Write-Host 'No domains match that filter.' -ForegroundColor Yellow
        return
    }

    $pageSize = 40
    for ($index = 0; $index -lt $items.Count; $index += $pageSize) {
        $end = [Math]::Min($index + $pageSize, $items.Count)
        for ($i = $index; $i -lt $end; $i++) { Write-Host $items[$i] }
        if ($end -lt $items.Count) {
            Write-Host ("Showing {0} of {1}." -f $end, $items.Count)
            $more = Read-ConsoleLine $script:PromptMore
            if ($script:InputClosed -or $more -eq 'Q') { break }
        }
    }
}

function Show-AllowedDomainReport {
    param([Parameter(Mandatory)]$Info)
    Write-Host ("Mode: {0} | Federation enabled: {1}" -f $Info.Mode, (Format-FederationState -Value $Info.FederationEnabled)) -ForegroundColor Cyan
    Write-Host ("Block all subdomains: {0} | Blocked domains: {1}" -f $Info.BlockAllSubdomains, @($Info.BlockedDomains).Count)
    if ($Info.Mode -eq 'AllowList') {
        Write-Host 'The block list is ignored while an explicit allow list is in use.'
    }
    if ($Info.FederationEnabled -eq $false) {
        Write-Warning 'AllowFederatedUsers is FALSE. External federation is off for the whole tenant.'
    }
    if ($Info.Mode -eq 'AllowAllKnownDomains') {
        Write-Host 'All known domains are allowed, subject to the block list and applicable policies.'
    }
    elseif ($Info.Domains.Count -eq 0) {
        Write-Host 'No explicit allowed domains found.'
    }
    else {
        Show-DomainPages -Domains $Info.Domains
    }
    Write-Host "Explicit domains found: $($Info.Domains.Count)"
    if (@($Info.BlockedDomains).Count -gt 0) {
        $show = Read-ConsoleLine $script:PromptShowBlocked
        if (-not $script:InputClosed -and $show -eq 'Y') {
            Show-DomainPages -Domains $Info.BlockedDomains
        }
    }
}

function Get-CsvDelimiter {
    param([string]$FirstLine)
    $line = [string]$FirstLine
    if ($line.Length -gt 0 -and [int][char]$line[0] -eq 0xFEFF) {
        $line = $line.Substring(1)
    }
    if ($line -notmatch ',' -and $line -match ';') { return ';' }
    return ','
}

function Find-ColumnByName {
    param([string[]]$ColumnNames, [string]$Name)
    $wanted = $Name.Trim()
    foreach ($column in @($ColumnNames)) {
        if ($column.Trim() -eq $wanted) { return $column }
    }
    return $null
}

function Read-CsvRecords {
    param([string]$Path, [string]$Delimiter)
    $data = Import-Csv -LiteralPath $Path -Delimiter $Delimiter -ErrorAction Stop
    $rows = New-Object 'System.Collections.Generic.List[object]'
    if ($null -ne $data) {
        foreach ($row in @($data)) {
            if ($null -ne $row) { [void]$rows.Add($row) }
        }
    }
    Write-Output -NoEnumerate $rows
}

function Import-RequestedDomainsFromCsv {
    param([Parameter(Mandatory)][string]$Path)
    $pathToRead = ConvertTo-UserPath -Path $Path
    if (-not (Test-Path -LiteralPath $pathToRead -PathType Leaf)) {
        throw "File not found: $pathToRead"
    }

    $firstLines = @(Get-Content -LiteralPath $pathToRead -TotalCount 1 -ErrorAction Stop)
    $firstLine = ''
    if ($firstLines.Count -gt 0 -and $null -ne $firstLines[0]) { $firstLine = [string]$firstLines[0] }
    $rows = Read-CsvRecords -Path $pathToRead -Delimiter (Get-CsvDelimiter -FirstLine $firstLine)
    if ($rows.Count -eq 0) {
        throw 'CSV must have a header and at least one data row.'
    }

    $columnNames = @($rows[0].PSObject.Properties.Name)
    $column = Find-ColumnByName -ColumnNames $columnNames -Name 'Domain'
    if (-not $column) {
        Write-Host ("Columns found: {0}" -f ($columnNames -join ', '))
        $picked = Read-ConsoleLine $script:PromptCsvColumn
        if ($script:InputClosed -or [string]::IsNullOrWhiteSpace($picked)) {
            return [pscustomobject]@{ Cancelled = $true; Domains = (ConvertTo-SortedDomainArray -Values @()) }
        }
        $column = Find-ColumnByName -ColumnNames $columnNames -Name $picked
        if (-not $column) { throw "Column not found: $picked" }
    }

    $domains = New-Object 'System.Collections.Generic.List[string]'
    foreach ($row in $rows) {
        [void]$domains.Add([string](Get-PropertyValue -Object $row -Name $column))
    }
    return [pscustomobject]@{ Cancelled = $false; Domains = $domains.ToArray() }
}

function Connect-TeamsSession {
    if ($null -ne $script:SessionConnector) { return (& $script:SessionConnector) }

    if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
        throw 'The MicrosoftTeams module is not installed. Install it with: Install-Module MicrosoftTeams -Scope CurrentUser'
    }
    Import-Module MicrosoftTeams -ErrorAction Stop

    $reused = $false
    try {
        $null = Get-Config
        $reused = $true
        Write-Host 'Using the existing Microsoft Teams connection.' -ForegroundColor Cyan
    }
    catch {
        Write-Host 'Sign in to Microsoft Teams. A browser or device-code prompt will open.' -ForegroundColor Cyan
        $account = @(Connect-MicrosoftTeams -ErrorAction Stop) | Select-Object -Last 1
        $script:OpenedTeamsConnection = $true
        $null = Get-Config
        if ($null -ne $account) {
            $script:ConnectedAccount = [string](Get-PropertyValue -Object $account -Name 'Account')
            $script:ConnectedTenantId = [string](Get-PropertyValue -Object $account -Name 'TenantId')
        }
    }

    $displayName = $null
    $tenantId = $script:ConnectedTenantId
    try {
        $tenant = @(Get-CsTenant -ErrorAction Stop) | Select-Object -First 1
        if ($null -ne $tenant) {
            $displayName = [string](Get-PropertyValue -Object $tenant -Name 'DisplayName')
            $reportedId = [string](Get-PropertyValue -Object $tenant -Name 'TenantId')
            if (-not [string]::IsNullOrWhiteSpace($reportedId)) { $tenantId = $reportedId }
        }
    }
    catch {
        Write-Warning "Could not read the tenant display name: $($_.Exception.Message)"
    }

    [pscustomobject]@{
        Account     = $script:ConnectedAccount
        DisplayName = $displayName
        TenantId    = $tenantId
        ReusedConnection = $reused
    }
}

function Disconnect-TeamsSession {
    if ($null -ne $script:SessionDisconnector) {
        & $script:SessionDisconnector
        return
    }
    Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
    $script:OpenedTeamsConnection = $false
}

function Invoke-AllowListMenu {
    do {
        if ($script:InputClosed) { break }

        $info = $null
        try {
            $info = Get-AllowedDomainInfo -Config (Get-Config)
        }
        catch {
            Write-Host "Could not read federation settings: $($_.Exception.Message)" -ForegroundColor Red
        }

        Write-Host ''
        Write-Host '========== TEAMS EXTERNAL ACCESS ALLOWLIST ==========' -ForegroundColor Cyan
        if ($null -ne $info) {
            Write-Host ("Mode: {0} | Federation enabled: {1} | Explicit domains: {2}" -f $info.Mode, (Format-FederationState -Value $info.FederationEnabled), $info.Domains.Count) -ForegroundColor Cyan
            if ($info.FederationEnabled -eq $false) {
                Write-Host 'AllowFederatedUsers is FALSE. List changes will not turn external federation on.' -ForegroundColor Yellow
            }
            if ($info.Mode -eq 'AllowAllKnownDomains') {
                Write-Host 'This tenant allows all known domains. Adding domains here will not switch it to an allow list.' -ForegroundColor Yellow
            }
        }
        Write-Host '1. View allowed domains'
        Write-Host '2. Export allowed domains to CSV'
        Write-Host '3. Add one domain'
        Write-Host '4. Bulk add domains from CSV (Domain column)'
        Write-Host '5. Check a domain'
        Write-Host '6. Exit'

        $choice = Read-ConsoleLine $script:PromptMenu
        if ($null -eq $choice -or $script:InputClosed) {
            Write-Host 'No input available. Exiting.'
            break
        }

        try {
            switch ($choice) {
                '1' {
                    $current = $info
                    if ($null -eq $current) { $current = Get-AllowedDomainInfo -Config (Get-Config) }
                    Show-AllowedDomainReport -Info $current
                }
                '2' {
                    $current = $info
                    if ($null -eq $current) { $current = Get-AllowedDomainInfo -Config (Get-Config) }
                    $null = Save-DomainSnapshot -Info $current -AskPath
                }
                '3' {
                    $domain = Read-ConsoleLine $script:PromptAdd
                    if ($script:InputClosed) { break }
                    Add-AllowedDomains -RequestedDomains @($domain)
                }
                '4' {
                    $csvPath = Read-ConsoleLine $script:PromptCsvPath
                    if ($script:InputClosed) { break }
                    if ([string]::IsNullOrWhiteSpace($csvPath)) {
                        Write-Host 'Import cancelled.' -ForegroundColor Yellow
                    }
                    else {
                        $imported = Import-RequestedDomainsFromCsv -Path $csvPath
                        if ($imported.Cancelled -or $script:InputClosed) {
                            Write-Host 'Import cancelled.' -ForegroundColor Yellow
                        }
                        else {
                            Add-AllowedDomains -RequestedDomains $imported.Domains
                        }
                    }
                }
                '5' {
                    $domain = Read-ConsoleLine $script:PromptCheck
                    if ($script:InputClosed) { break }
                    if ([string]::IsNullOrWhiteSpace($domain)) {
                        Write-Host 'No domain entered.' -ForegroundColor Yellow
                    }
                    else {
                        $current = $info
                        if ($null -eq $current) { $current = Get-AllowedDomainInfo -Config (Get-Config) }
                        $status = Get-ExternalDomainStatus -InputDomain $domain -Info $current
                        Write-Host $status.Message -ForegroundColor $status.Color
                    }
                }
                '6' { Write-Host 'Exiting...' }
                default { Write-Host 'Enter a number from 1 to 6.' -ForegroundColor Yellow }
            }
        }
        catch [System.Management.Automation.PipelineStoppedException] {
            throw
        }
        catch {
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        }

        if ($script:InputClosed) { break }
        if ($choice -eq '6') {
            $disconnect = Read-ConsoleLine $script:PromptDisconnect
            if (-not $script:InputClosed -and $disconnect -eq 'Y') {
                Disconnect-TeamsSession
                Write-Host 'Disconnected.'
            }
            break
        }
        $null = Read-ConsoleLine $script:PromptContinue
    } while ($true)
}

function Invoke-AllowListMain {
    if (-not (Test-InteractiveSession)) {
        Write-Host 'This script must be run in an interactive console.' -ForegroundColor Red
        return 1
    }

    try {
        $session = Connect-TeamsSession
    }
    catch {
        Write-Host "Unable to connect to Microsoft Teams or read federation settings: $($_.Exception.Message)" -ForegroundColor Red
        return 1
    }

    Write-Host ''
    Write-Host 'Connected tenant' -ForegroundColor Cyan
    if ($session.Account) { Write-Host "Account:  $($session.Account)" }
    if ($session.DisplayName) { Write-Host "Name:     $($session.DisplayName)" }
    if ($session.TenantId) { Write-Host "TenantId: $($session.TenantId)" }
    if (-not $session.Account -and -not $session.DisplayName -and -not $session.TenantId) {
        Write-Warning 'The signed-in tenant could not be identified. Continue only if you are sure this is the right tenant.'
    }

    $answer = Read-ConsoleLine $script:PromptTenantConfirm
    if ($script:InputClosed -or $answer -ne 'YES') {
        Write-Host 'Stopped. No changes were made.'
        if ($script:OpenedTeamsConnection) { Disconnect-TeamsSession }
        return 1
    }

    Invoke-AllowListMenu
    return 0
}

function Invoke-AllowListSelfTest {
    $script:TestFailures = New-Object 'System.Collections.Generic.List[string]'

    function Assert-True {
        param([string]$Name, [bool]$Condition)
        if (-not $Condition) { [void]$script:TestFailures.Add($Name) }
    }

    function Assert-SameList {
        param($Name, $Actual, $Expected)
        $left = @($Actual) -join "`n"
        $right = @($Expected) -join "`n"
        if ($left -ne $right) {
            [void]$script:TestFailures.Add("$Name`nACTUAL:`n$left`nEXPECTED:`n$right")
        }
    }

    $tempRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('teams-allowlist-' + [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $tempRoot -ErrorAction Stop | Out-Null
    $script:SnapshotRoot = Join-Path -Path $tempRoot -ChildPath 'snapshots'
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'

    try {
        Assert-True 'string false is false' ((ConvertTo-BooleanValue -Value 'False') -eq $false)
        Assert-True 'string true is true' ((ConvertTo-BooleanValue -Value 'True') -eq $true)
        Assert-True 'bool false stays false' ((ConvertTo-BooleanValue -Value $false) -eq $false)

        Assert-True 'partner.com' (Test-DomainName -Domain (ConvertTo-NormalizedDomain -InputDomain 'partner.com'))
        Assert-True 'url' ((ConvertTo-NormalizedDomain -InputDomain 'https://Partner.COM/teams') -eq 'partner.com')
        Assert-True 'email' ((ConvertTo-NormalizedDomain -InputDomain 'Admin@Partner.COM') -eq 'partner.com')
        Assert-True 'mailto' ((ConvertTo-NormalizedDomain -InputDomain 'mailto:admin@partner.com') -eq 'partner.com')
        Assert-True 'trailing dot' ((ConvertTo-NormalizedDomain -InputDomain 'partner.com.') -eq 'partner.com')
        $idn = ConvertTo-NormalizedDomain -InputDomain 'münchen.de'
        Assert-True 'idn' ($idn.StartsWith('xn--') -and $idn.EndsWith('.de') -and (Test-DomainName -Domain $idn))
        Assert-True 'single label rejected' (-not (Test-DomainName -Domain 'localhost'))
        Assert-True 'leading hyphen rejected' (-not (Test-DomainName -Domain '-bad.com'))
        Assert-True 'trailing hyphen rejected' (-not (Test-DomainName -Domain 'bad-.com'))
        Assert-True 'ip rejected' (-not (Test-DomainName -Domain '8.8.8.8'))
        Assert-True 'short domain' (Test-DomainName -Domain 'a.b')
        $label63 = 'a' + ('b' * 61) + 'c'
        $label64 = 'a' + ('b' * 62) + 'c'
        Assert-True 'label 63' (Test-DomainName -Domain "$label63.com")
        Assert-True 'label 64 rejected' (-not (Test-DomainName -Domain "$label64.com"))

        function New-DomainOfLength {
            param([int]$Length)
            $parts = New-Object 'System.Collections.Generic.List[string]'
            $used = 0
            while ($used -lt $Length) {
                $remaining = $Length - $used
                if ($parts.Count -gt 0) { $remaining-- }
                if ($remaining -le 0) { break }
                $take = [Math]::Min(63, $remaining)
                if ($parts.Count -gt 0) { $used++ }
                $used += $take
                [void]$parts.Add(('a' * $take))
            }
            return ($parts -join '.')
        }
        $domain253 = New-DomainOfLength -Length 253
        $domain254 = New-DomainOfLength -Length 254
        Assert-True 'length helper 253' ($domain253.Length -eq 253)
        Assert-True 'length helper 254' ($domain254.Length -eq 254)
        Assert-True '253 accepted' (Test-DomainName -Domain $domain253)
        Assert-True '254 rejected' (-not (Test-DomainName -Domain $domain254))

        Assert-True 'quoted path' ((ConvertTo-UserPath -Path '  "C:\temp\a.csv"  ') -eq 'C:\temp\a.csv')
        Assert-True 'single quoted path' ((ConvertTo-UserPath -Path "  'C:\temp\a.csv'  ") -eq 'C:\temp\a.csv')
        $bomLine = [string]([char]0xFEFF) + 'Domain;Note'
        Assert-True 'semicolon delimiter' ((Get-CsvDelimiter -FirstLine $bomLine) -eq ';')
        Assert-True 'comma delimiter' ((Get-CsvDelimiter -FirstLine 'Domain,Note') -eq ',')

        $stringFalseConfig = [pscustomobject]@{
            AllowFederatedUsers = 'False'
            AllowedDomains      = [pscustomobject]@{ AllowedDomain = [pscustomobject]@{ Domain = 'Partner.COM.' } }
            BlockedDomains      = 'Evil.COM'
            BlockAllSubdomains  = 'True'
        }
        $parsed = Get-AllowedDomainInfo -Config $stringFalseConfig
        Assert-True 'federation string false' ($parsed.FederationEnabled -eq $false)
        Assert-True 'mode allow list' ($parsed.Mode -eq 'AllowList')
        Assert-True 'normalized existing domain' ($parsed.Domains.Count -eq 1 -and $parsed.Domains[0] -eq 'partner.com')
        Assert-True 'normalized block' ($parsed.BlockedDomains.Count -eq 1 -and $parsed.BlockedDomains[0] -eq 'evil.com')
        Assert-True 'block subdomains string true' ($parsed.BlockAllSubdomains -eq $true)

        $missingFederation = Get-AllowedDomainInfo -Config ([pscustomobject]@{
            AllowedDomains = $null
            BlockedDomains = $null
        })
        Assert-True 'null allow list is not allow-all' ($missingFederation.Mode -eq 'AllowList' -and $missingFederation.Domains.Count -eq 0)
        Assert-True 'missing federation is unknown' ($null -eq $missingFederation.FederationEnabled)

        $allowAllObject = New-Object psobject
        $allowAllObject.PSObject.TypeNames.Insert(0, 'Deserialized.Microsoft.Rtc.Management.WritableConfig.Settings.Edge.AllowAllKnownDomains')
        $allowAllInfo = Get-AllowedDomainInfo -Config ([pscustomobject]@{
            AllowFederatedUsers = $true
            AllowedDomains      = $allowAllObject
            BlockedDomains      = @([pscustomobject]@{ Domain = 'Bad.COM' }, 'other.com')
            BlockAllSubdomains  = $false
        })
        Assert-True 'typed allow all' ($allowAllInfo.Mode -eq 'AllowAllKnownDomains' -and $allowAllInfo.Domains.Count -eq 0)
        Assert-True 'object and string blocks' ($allowAllInfo.BlockedDomains.Count -eq 2)

        $many = Get-AllowedDomainInfo -Config ([pscustomobject]@{
            AllowFederatedUsers = 'True'
            AllowedDomains      = [pscustomobject]@{
                AllowedDomain = @(
                    [pscustomobject]@{ Domain = 'B.com' }
                    'a.com'
                    [pscustomobject]@{ Domain = 'B.com' }
                )
            }
        })
        Assert-SameList 'unique sorted domains' $many.Domains @('a.com', 'b.com')

        $listed = Get-ExternalDomainStatus -InputDomain 'https://Partner.COM/path' -Info $parsed
        Assert-True 'check listed while federation off' ($listed.Code -eq 'FederationDisabled' -and $listed.Message -match 'AllowFederatedUsers is FALSE')

        $open = Get-AllowedDomainInfo -Config ([pscustomobject]@{
            AllowFederatedUsers = $true
            AllowedDomains      = 'AllowAllKnownDomains'
            BlockedDomains      = @('evil.com')
            BlockAllSubdomains  = $false
        })
        $parent = Get-ExternalDomainStatus -InputDomain 'sub.evil.com' -Info $open
        Assert-True 'subdomain stays allowed' ($parent.Code -eq 'AllowedThoughParentBlocked' -and $parent.Message -match 'BlockAllSubdomains is off')
        $exactBlock = Get-ExternalDomainStatus -InputDomain 'evil.com' -Info $open
        Assert-True 'exact block' ($exactBlock.Code -eq 'Blocked')
        $open.BlockAllSubdomains = $true
        $subBlocked = Get-ExternalDomainStatus -InputDomain 'a.b.evil.com' -Info $open
        Assert-True 'subdomain blocked when enabled' ($subBlocked.Code -eq 'Blocked' -and $subBlocked.Message -match 'BlockAllSubdomains is on')
        $unrelated = Get-ExternalDomainStatus -InputDomain 'notevil.com' -Info $open
        Assert-True 'suffix lookalike is not a subdomain' ($unrelated.Code -eq 'AllowedByOpenFederation')

        $allowListInfo = Get-AllowedDomainInfo -Config ([pscustomobject]@{
            AllowFederatedUsers = $true
            AllowedDomains      = [pscustomobject]@{ AllowedDomain = @('partner.com') }
            BlockedDomains      = @('evil.com')
            BlockAllSubdomains  = $true
        })
        $explicit = Get-ExternalDomainStatus -InputDomain 'partner.com' -Info $allowListInfo
        Assert-True 'explicit allow' ($explicit.Code -eq 'ExplicitlyAllowed')
        $ignoredBlock = Get-ExternalDomainStatus -InputDomain 'evil.com' -Info $allowListInfo
        Assert-True 'block ignored on allow list' ($ignoredBlock.Code -eq 'NotListed' -and $ignoredBlock.Message -match 'which is ignored')

        $plan = Get-AllowedDomainAddition -RequestedDomains @(
            'https://Partner.com/path'
            'PARTNER.com'
            'new.org'
            'not a domain'
            '*.wild.com'
            'new.org'
        ) -Info $allowListInfo
        Assert-True 'plan ready' ($plan.Status -eq 'Ready' -and $plan.Domains.Count -eq 1 -and $plan.Domains[0] -eq 'new.org')
        $noticeText = @($plan.Notices | ForEach-Object { $_.Message }) -join "`n"
        Assert-True 'already listed notice' ($noticeText -match 'Already in the allow list: partner.com')
        Assert-True 'invalid notice' ($noticeText -match 'Skipping invalid domain')
        Assert-True 'wildcard notice' ($noticeText -match 'Skipping wildcard entry')
        Assert-True 'duplicate notice' ($noticeText -match 'Duplicate in this request: new.org')

        $emptyPlan = Get-AllowedDomainAddition -RequestedDomains @('   ') -Info $allowListInfo
        Assert-True 'blank input' ($emptyPlan.Status -eq 'NoInput')
        $refused = Get-AllowedDomainAddition -RequestedDomains @('x.com') -Info $open
        Assert-True 'allow all refused' ($refused.Status -eq 'AllowAllRefused')

        $full = New-Object 'System.Collections.Generic.List[string]'
        for ($i = 1; $i -le 4000; $i++) { [void]$full.Add(('d{0}.com' -f $i)) }
        $fullInfo = [pscustomobject]@{
            Mode               = 'AllowList'
            FederationEnabled  = $true
            Domains            = $full.ToArray()
            BlockedDomains     = @()
            BlockAllSubdomains = $false
        }
        $threw = $false
        try {
            $null = Get-AllowedDomainAddition -RequestedDomains @('extra.com') -Info $fullInfo
        }
        catch {
            $threw = $true
            Assert-True 'limit message' ($_.Exception.Message -match '4001' -and $_.Exception.Message -match '4000')
        }
        Assert-True 'limit throws' $threw
        $duplicateAtLimit = Get-AllowedDomainAddition -RequestedDomains @('d1.com') -Info $fullInfo
        Assert-True 'duplicate at the limit does not throw' ($duplicateAtLimit.Status -eq 'NothingToAdd')

        $merged = Merge-AllowedDomains -Existing @('b.com', 'a.com') -Add @('c.com', 'a.com')
        Assert-SameList 'replace list keeps current domains first' $merged @('b.com', 'a.com', 'c.com')
        $oneDomain = New-Object 'System.Collections.Generic.List[string]'
        [void]$oneDomain.Add('premiercommfw.com')
        $mergedOne = Merge-AllowedDomains -Existing @('partner.com') -Add $oneDomain
        Assert-SameList 'one domain is not split into characters' $mergedOne @('partner.com', 'premiercommfw.com')
        try { throw '[ClientError] : Invalid input parameters' } catch {
            Assert-True 'client error can be retried' (Test-RetryableAllowListError -ErrorRecord $_)
        }
        try { throw (New-Object System.Management.Automation.CommandNotFoundException 'New-CsEdgeDomainPattern is not available.') } catch {
            Assert-True 'missing pattern cmdlet can be retried' (Test-RetryableAllowListError -ErrorRecord $_)
        }
        $setParameters = Get-FederationSetParameters -ParameterName 'AllowedDomainsAsAList' -Value @('premiercommfw.com')
        Assert-True 'update sends only the domain parameter' ($setParameters.Count -eq 1 -and $setParameters.ContainsKey('AllowedDomainsAsAList'))
        Assert-True 'update does not bind Confirm, ErrorAction, or Identity' (-not $setParameters.ContainsKey('Confirm') -and -not $setParameters.ContainsKey('ErrorAction') -and -not $setParameters.ContainsKey('Identity'))
        try { throw 'Access denied' } catch {
            Assert-True 'access denied is not retried' (-not (Test-RetryableAllowListError -ErrorRecord $_))
        }

        $semiPath = Join-Path -Path $tempRoot -ChildPath 'semi.csv'
        Set-Content -LiteralPath $semiPath -Value "Domain;Note`r`nsemi.org;x" -Encoding UTF8
        $semi = Import-RequestedDomainsFromCsv -Path $semiPath
        Assert-True 'semicolon csv' (-not $semi.Cancelled -and $semi.Domains.Count -eq 1 -and $semi.Domains[0] -eq 'semi.org')

        $websitePath = Join-Path -Path $tempRoot -ChildPath 'website.csv'
        Set-Content -LiteralPath $websitePath -Value "Website,Note`r`nweb.org,a" -Encoding UTF8
        $script:PromptLog = New-Object 'System.Collections.Generic.List[string]'
        $script:SimulatedInput = New-Object 'System.Collections.Generic.Queue[string]'
        $script:SimulatedInput.Enqueue('Website')
        $website = Import-RequestedDomainsFromCsv -Path $websitePath
        Assert-True 'prompted column' (-not $website.Cancelled -and $website.Domains[0] -eq 'web.org')
        Assert-SameList 'column prompt' $script:PromptLog @($script:PromptCsvColumn)
        $script:SimulatedInput = $null
        $script:PromptLog = $null

        $headerOnly = Join-Path -Path $tempRoot -ChildPath 'empty-info.csv'
        $emptyInfo = [pscustomobject]@{
            Mode               = 'AllowList'
            FederationEnabled  = $true
            Domains            = @()
            BlockedDomains     = @()
            BlockAllSubdomains = $false
        }
        Export-DomainFile -Domains $emptyInfo.Domains -Path $headerOnly
        $headerText = @(Get-Content -LiteralPath $headerOnly)
        Assert-True 'header only export' ($headerText.Count -ge 1 -and $headerText[0].Trim('"') -eq 'Domain')

        $script:FakeMode = 'AllowList'
        $script:FakeDomains = New-Object 'System.Collections.Generic.List[string]'
        [void]$script:FakeDomains.Add('partner.com')
        $script:UpdateCalls = New-Object 'System.Collections.Generic.List[object]'
        $script:DisconnectCalls = 0
        $script:InputClosed = $false
        $script:OpenedTeamsConnection = $false
        $script:ConfigProvider = {
            if ($script:FakeMode -eq 'AllowAllKnownDomains') {
                $allowed = 'AllowAllKnownDomains'
            }
            else {
                $entries = New-Object 'System.Collections.Generic.List[object]'
                foreach ($domain in $script:FakeDomains) {
                    [void]$entries.Add([pscustomobject]@{ Domain = $domain })
                }
                $allowed = [pscustomobject]@{ AllowedDomain = $entries.ToArray() }
            }
            [pscustomobject]@{
                AllowFederatedUsers = $true
                AllowedDomains      = $allowed
                BlockedDomains      = @('evil.com')
                BlockAllSubdomains  = $false
            }
        }
        $script:DomainListUpdater = {
            param($List)
            if ($List -isnot [System.Collections.Generic.List[string]]) {
                throw "Expected List[string] but got $($List.GetType().FullName)"
            }
            $copy = New-Object 'System.Collections.Generic.List[string]'
            foreach ($item in $List) { [void]$copy.Add([string]$item) }
            [void]$script:UpdateCalls.Add($copy)
            foreach ($item in $copy) { [void]$script:FakeDomains.Add($item) }
        }
        $script:SessionConnector = {
            [pscustomobject]@{
                Account          = 'admin@contoso.com'
                DisplayName      = 'Contoso'
                TenantId         = 'tenant-id'
                ReusedConnection = $false
            }
        }
        $script:SessionDisconnector = { $script:DisconnectCalls++ }

        $bulkPath = Join-Path -Path $tempRoot -ChildPath 'bulk.csv'
        Set-Content -LiteralPath $bulkPath -Value "Domain,Note`r`nbulk.org,a`r`npartner.com,b`r`nnot a domain,c" -Encoding UTF8
        $exportPath = Join-Path -Path $tempRoot -ChildPath 'export.csv'
        $missingPath = Join-Path -Path $tempRoot -ChildPath 'missing.csv'

        $script:PromptLog = New-Object 'System.Collections.Generic.List[string]'
        $script:SimulatedInput = New-Object 'System.Collections.Generic.Queue[string]'
        foreach ($line in @(
            'YES', '1', 'N', '',
            '5', 'partner.com', '',
            '5', 'evil.com', '',
            '3', 'new.org', 'ADD', '',
            '5', 'new.org', '',
            '3', 'skip.org', 'no', '',
            '3', '', '',
            '9', '',
            '4', $missingPath, '',
            '4', $bulkPath, 'ADD', '',
            '2', $exportPath, '',
            '6', 'N'
        )) {
            $script:SimulatedInput.Enqueue($line)
        }

        $sessionOutput = Invoke-AllowListMain *>&1 | Out-String
        Assert-SameList 'interactive prompts' $script:PromptLog @(
            $script:PromptTenantConfirm,
            $script:PromptMenu, $script:PromptShowBlocked, $script:PromptContinue,
            $script:PromptMenu, $script:PromptCheck, $script:PromptContinue,
            $script:PromptMenu, $script:PromptCheck, $script:PromptContinue,
            $script:PromptMenu, $script:PromptAdd, $script:PromptConfirm, $script:PromptContinue,
            $script:PromptMenu, $script:PromptCheck, $script:PromptContinue,
            $script:PromptMenu, $script:PromptAdd, $script:PromptConfirm, $script:PromptContinue,
            $script:PromptMenu, $script:PromptAdd, $script:PromptContinue,
            $script:PromptMenu, $script:PromptContinue,
            $script:PromptMenu, $script:PromptCsvPath, $script:PromptContinue,
            $script:PromptMenu, $script:PromptCsvPath, $script:PromptConfirm, $script:PromptContinue,
            $script:PromptMenu, $script:PromptExportPath, $script:PromptContinue,
            $script:PromptMenu, $script:PromptDisconnect
        )
        Assert-True 'queue consumed' ($script:SimulatedInput.Count -eq 0)
        Assert-True 'verified new domain' ($sessionOutput -match 'Verified: new\.org')
        Assert-True 'verified bulk domain' ($sessionOutput -match 'Verified: bulk\.org')
        Assert-True 'cancel keeps the menu alive' ($sessionOutput -match 'Cancelled\.')
        Assert-True 'blank add stays in the menu' ($sessionOutput -match 'No domain entered\.')
        Assert-True 'invalid choice stays in the menu' ($sessionOutput -match 'Enter a number from 1 to 6\.')
        Assert-True 'missing csv stays in the menu' ($sessionOutput -match 'File not found')
        Assert-True 'check reports the allow entry' ($sessionOutput -match "partner\.com' is explicitly allowed")
        Assert-True 'check explains an ignored block' ($sessionOutput -match 'which is ignored')
        Assert-True 'did not disconnect' ($script:DisconnectCalls -eq 0)
        Assert-True 'two updates' ($script:UpdateCalls.Count -eq 2)
        Assert-SameList 'first update' $script:UpdateCalls[0] @('new.org')
        Assert-SameList 'second update' $script:UpdateCalls[1] @('bulk.org')
        Assert-True 'skip was not added' (-not ($script:FakeDomains -contains 'skip.org'))
        $exported = @(Import-Csv -LiteralPath $exportPath | ForEach-Object { $_.Domain })
        Assert-SameList 'export contains the allow list' $exported @('bulk.org', 'new.org', 'partner.com')
        $snapshots = @(Get-ChildItem -LiteralPath $script:SnapshotRoot -Filter '*.csv' -File)
        Assert-True 'before and after snapshots' ($snapshots.Count -eq 4)

        $script:FakeMode = 'AllowAllKnownDomains'
        $script:UpdateCalls.Clear()
        $script:PromptLog = New-Object 'System.Collections.Generic.List[string]'
        $script:SimulatedInput = New-Object 'System.Collections.Generic.Queue[string]'
        foreach ($line in @('yes', '3', 'x.com', '', '6', 'N')) {
            $script:SimulatedInput.Enqueue($line)
        }
        $allowAllOutput = Invoke-AllowListMain *>&1 | Out-String
        Assert-SameList 'allow-all prompts do not ask for ADD' $script:PromptLog @(
            $script:PromptTenantConfirm,
            $script:PromptMenu, $script:PromptAdd, $script:PromptContinue,
            $script:PromptMenu, $script:PromptDisconnect
        )
        Assert-True 'allow-all warning' ($allowAllOutput -match 'will not make that change')
        Assert-True 'allow-all made no update' ($script:UpdateCalls.Count -eq 0)

        foreach ($name in @('Test-DomainName', 'Add-AllowedDomains', 'Get-Config', 'Get-AllowedDomainInfo', 'Save-DomainSnapshot')) {
            Assert-True "function $name" ($null -ne (Get-Command -Name $name -ErrorAction SilentlyContinue))
        }
    }
    catch {
        [void]$script:TestFailures.Add("Unhandled test error: $($_.Exception.Message)`n$($_.ScriptStackTrace)`n$($_.InvocationInfo.PositionMessage)")
    }
    finally {
        $ErrorActionPreference = $previousPreference
        $script:SimulatedInput = $null
        $script:PromptLog = $null
        $script:ConfigProvider = $null
        $script:DomainListUpdater = $null
        $script:SessionConnector = $null
        $script:SessionDisconnector = $null
        $script:SnapshotRoot = $null
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    if ($script:TestFailures.Count -eq 0) {
        Write-Host 'Self-test passed.' -ForegroundColor Green
    }
    else {
        Write-Host "Self-test failed: $($script:TestFailures.Count)" -ForegroundColor Red
        foreach ($failure in $script:TestFailures) {
            Write-Host $failure -ForegroundColor Red
            Write-Host '---'
        }
    }
    return $script:TestFailures.Count
}

if ($SelfTest) {
    $failed = Invoke-AllowListSelfTest
    if ($MyInvocation.InvocationName -ne '.') {
        exit $(if ($failed -gt 0) { 1 } else { 0 })
    }
    return
}

if ($MyInvocation.InvocationName -ne '.') {
    $code = Invoke-AllowListMain
    if ($code -ne 0) { $global:LASTEXITCODE = $code }
}

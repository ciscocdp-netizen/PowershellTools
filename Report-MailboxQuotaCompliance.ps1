#Requires -Version 5.1
<#
.SYNOPSIS
    Reports on (and optionally remediates) Exchange Online mailbox storage quotas
    for users licensed with Office 365 / Microsoft 365 E3 or E5.

.DESCRIPTION
    This script performs three checks:

      1. Storage cap compliance
         Flags E3/E5 mailboxes whose effective ProhibitSendReceiveQuota is not
         the target storage size (default 100 GB).

      2. Warning/send quota alignment
         Verifies ProhibitSendQuota and IssueWarningQuota match policy targets
         (defaults 99 GB / 98 GB - the standard Exchange Online 100 GB profile).

         NOTE: ProhibitSendReceiveQuota is the hard storage cap. A 98 GB value
         there would contradict a 100 GB mailbox. In the standard 100 GB profile,
         98 GB is IssueWarningQuota. All three targets are parameters.

      3. Near-legacy-cap usage
         Flags E3 mailboxes that still carry the legacy ProhibitSendReceiveQuota
         (default 50 GB) and whose current usage is at/above the warning
         threshold (default 90% = 45 GB). That is a reporting signal; remediation
         still only rewrites quota misconfiguration (which a 50 GB cap is).

    License data is read from Microsoft Graph. Mailbox data is read from Exchange
    Online. Nothing is changed unless you pass -Remediate (which honors -WhatIf
    and -Confirm via ShouldProcess).

    Bugs fixed vs. the original script:
    - Get-EXOMailbox / Get-EXOMailboxStatistics were called once per licensed
      user (N+1 REST). That throttles and can run for hours. Mailboxes are now
      pulled in one Minimum+Quota property-set query and joined in memory.
    - License-to-mailbox join used Graph UPN only. UPNs that do not match the
      mailbox identity were skipped. Join is ExternalDirectoryObjectId first,
      then UPN.
    - Get-EXOMailbox -PropertySets Quota (or a Properties list without Minimum)
      drops DisplayName / UserPrincipalName. Minimum is always requested with
      Quota.
    - Get-EXOMailboxStatistics -Properties TotalItemSize can fail because
      TotalItemSize is already in the Minimum set, not an "additional" property.
    - ConvertTo-Bytes returned $null for numeric REST sizes and ByteQuantifiedSize
      objects (.Value / ToBytes()), so every quota compared as Unknown.
    - Exact -eq on doubles treated 99.99 GB as non-compliant. Comparison uses a
      byte tolerance (default 2 MB).
    - UseDatabaseQuotaDefaults was collected then ignored. It is reported, and
      remediation still sets it to $false so custom quotas actually apply.
    - Only ENTERPRISEPACK / ENTERPRISEPREMIUM were treated as E3/E5. Microsoft 365
      E3/E5 (SPE_E3 / SPE_E5) are included by default.
    - Reused Graph sessions were not checked for User.Read.All /
      Organization.Read.All, so Get-Mg* could 403.
    - Mailbox-not-found and throttling were both swallowed by "continue".
    - Windows PowerShell 5.1 Connect-ExchangeOnline often fails with
      "An error occurred while sending the request" unless TLS 1.2 is enabled
      before the module loads.
    - Sessions were left open on error paths. Disconnect runs in finally, and
      only if this script created the connection.
    - The "Not100GB" CSV name ignored -TargetStorageQuotaGB.
    - StrictMode could throw on missing Graph @odata.nextLink / null UPNs.
    - StrictMode Latest threw "The property 'Count' cannot be found" while paging
      Graph users (Get-MgUser -All / Invoke-MgGraphRequest). Module cmdlets now
      run with StrictMode off, and collection counts no longer use raw .Count.
    - An omitted -Identity was treated as one $null identity because
      @($null).Count is 1, so the tenant-wide Graph query never ran.

.PARAMETER OutputFolder
    Folder where CSV and HTML reports are written. Defaults to the current directory.

.PARAMETER TargetStorageQuotaGB
    Expected ProhibitSendReceiveQuota for compliant E3/E5 mailboxes. Default 100.

.PARAMETER ProhibitSendQuotaGB
    Target ProhibitSendQuota used for compliance check and remediation. Default 99.

.PARAMETER IssueWarningQuotaGB
    Target IssueWarningQuota used for compliance check and remediation. Default 98.

.PARAMETER LegacyQuotaGB
    The old/small cap to detect for near-limit reporting. Default 50.

.PARAMETER NearLimitPercent
    Percent of the legacy cap at which a mailbox is considered "close". Default 90.

.PARAMETER QuotaToleranceMB
    Byte-comparison tolerance in megabytes. Default 2.

.PARAMETER E3SkuPartNumber
    Graph SkuPartNumber values treated as E3. Default ENTERPRISEPACK, SPE_E3.

.PARAMETER E5SkuPartNumber
    Graph SkuPartNumber values treated as E5. Default ENTERPRISEPREMIUM, SPE_E5.

.PARAMETER Identity
    Optional UPN / SMTP / alias list. When set, only those mailboxes are evaluated.

.PARAMETER RecipientTypeDetails
    Mailbox types included in the EXO query. Default UserMailbox.

.PARAMETER UserPrincipalName
    Optional UPN passed to Connect-ExchangeOnline (useful for modern auth / MFA).

.PARAMETER TenantId
    Optional tenant ID passed to Connect-MgGraph.

.PARAMETER Remediate
    Switch. When present, the script sets non-compliant quotas to the target values.
    Supports -WhatIf and -Confirm.

.PARAMETER SkipStatistics
    Switch. Do not call Get-EXOMailboxStatistics. Faster; near-legacy-limit
    detection and size columns are skipped.

.PARAMETER SkipDisconnect
    Switch. Leave EXO / Graph sessions connected when the script ends.

.PARAMETER SelfTest
    Switch. Runs built-in unit tests (converters, join, compliance logic, HTML)
    and exits. Does not connect to Exchange Online or Graph.

.PARAMETER DemoReport
    Switch. Writes a sample CSV/HTML report using built-in example mailboxes.
    Does not connect to Exchange Online or Graph. Use this to preview the HTML.

.EXAMPLE
    .\Report-MailboxQuotaCompliance.ps1 -OutputFolder C:\Reports

.EXAMPLE
    .\Report-MailboxQuotaCompliance.ps1 -Remediate -WhatIf

.EXAMPLE
    .\Report-MailboxQuotaCompliance.ps1 -Remediate -Confirm:$false

.EXAMPLE
    .\Report-MailboxQuotaCompliance.ps1 -Identity jane@contoso.com -OutputFolder C:\Reports

.EXAMPLE
    .\Report-MailboxQuotaCompliance.ps1 -SelfTest

.EXAMPLE
    .\Report-MailboxQuotaCompliance.ps1 -DemoReport -OutputFolder C:\Reports
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]     $OutputFolder         = (Get-Location).Path,
    [int]        $TargetStorageQuotaGB = 100,
    [int]        $ProhibitSendQuotaGB  = 99,
    [int]        $IssueWarningQuotaGB  = 98,
    [int]        $LegacyQuotaGB        = 50,
    [ValidateRange(1, 100)]
    [int]        $NearLimitPercent     = 90,
    [ValidateRange(0, 1024)]
    [int]        $QuotaToleranceMB     = 2,
    [string[]]   $E3SkuPartNumber      = @('ENTERPRISEPACK', 'SPE_E3'),
    [string[]]   $E5SkuPartNumber      = @('ENTERPRISEPREMIUM', 'SPE_E5'),
    [string[]]   $Identity             = @(),
    [string[]]   $RecipientTypeDetails = @('UserMailbox'),
    [string]     $UserPrincipalName,
    [string]     $TenantId,
    [switch]     $Remediate,
    [switch]     $SkipStatistics,
    [switch]     $SkipDisconnect,
    [switch]     $SelfTest,
    [switch]     $DemoReport
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:ExoConnectedByThisScript   = $false
$script:GraphConnectedByThisScript = $false

#--------------------------------------------------------------------
# Helpers
#--------------------------------------------------------------------

function Write-Info { param([string]$Message) Write-Host "[INFO ] $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "[ OK  ] $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "[WARN ] $Message" -ForegroundColor Yellow }
function Write-Err  { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-PropertyValue {
    param(
        $Object,
        [Parameter(Mandatory)]
        [string]$Name,
        $Default = $null
    )

    if ($null -eq $Object) {
        return $Default
    }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in @($Object.Keys)) {
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $Object[$key]
            }
        }
        return $Default
    }

    $prop = $Object.PSObject.Properties[$Name]
    if ($null -ne $prop) {
        return $prop.Value
    }

    foreach ($candidate in @($Object.PSObject.Properties)) {
        if ([string]::Equals($candidate.Name, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $candidate.Value
        }
    }

    return $Default
}

# StrictMode Latest throws on .Count for $null, a single PSCustomObject, or a string.
# Graph JSON objects are often hashtables; @($hashtable) enumerates KEYS, not "one object".
function Get-CollectionCount {
    param($InputObject)

    if ($null -eq $InputObject) {
        return 0
    }
    if ($InputObject -is [string]) {
        return 1
    }
    if ($InputObject -is [System.Array]) {
        return $InputObject.Length
    }
    if ($InputObject -is [System.Collections.ICollection]) {
        return [int]$InputObject.Count
    }

    $countProp = $InputObject.PSObject.Properties['Count']
    if ($null -ne $countProp -and $null -ne $countProp.Value) {
        try {
            return [int]$countProp.Value
        }
        catch {
            return 1
        }
    }
    return 1
}

function ConvertTo-ObjectArray {
    param($InputObject)

    $list = New-Object System.Collections.Generic.List[object]
    if ($null -eq $InputObject) {
        return , $list.ToArray()
    }

    # Strings, dictionaries, and scalars must NOT be enumerated (@($hash) yields KEYS).
    $enumerate = $InputObject -is [System.Collections.IEnumerable] -and
        $InputObject -isnot [string] -and
        $InputObject -isnot [System.Collections.IDictionary]

    if ($enumerate) {
        foreach ($item in $InputObject) {
            if ($null -ne $item) {
                [void]$list.Add($item)
            }
        }
    }
    else {
        [void]$list.Add($InputObject)
    }

    return , $list.ToArray()
}

function ConvertTo-StringArray {
    param($Value)

    $items = New-Object System.Collections.Generic.List[string]
    foreach ($item in (ConvertTo-ObjectArray $Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace([string]$item)) {
            [void]$items.Add([string]$item)
        }
    }
    return , $items.ToArray()
}

function ConvertTo-NormalizedGuid {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    $guid = [guid]::Empty
    if ([guid]::TryParse($text, [ref]$guid)) {
        return $guid.ToString()
    }

    return $text.Trim().ToLowerInvariant()
}

# Converts an Exchange quota/size value to bytes.
# Handles ByteQuantifiedSize objects, numeric REST values, "Unlimited",
# and strings like "99 GB (106,300,440,576 bytes)".
function ConvertTo-Bytes {
    param($SizeValue)

    if ($null -eq $SizeValue) {
        return $null
    }

    if ($SizeValue -is [double] -or $SizeValue -is [single]) {
        if ([double]::IsNaN([double]$SizeValue)) {
            return $null
        }
        if ([double]::IsInfinity([double]$SizeValue)) {
            return [double]::PositiveInfinity
        }
        return [double]$SizeValue
    }

    if ($SizeValue -is [byte] -or $SizeValue -is [int16] -or $SizeValue -is [uint16] -or
        $SizeValue -is [int] -or $SizeValue -is [uint32] -or
        $SizeValue -is [long] -or $SizeValue -is [uint64] -or
        $SizeValue -is [decimal]) {
        return [double]$SizeValue
    }

    $toBytes = $SizeValue.PSObject.Methods['ToBytes']
    if ($null -ne $toBytes) {
        try {
            return [double]$SizeValue.ToBytes()
        }
        catch {
            Write-Verbose "ToBytes() failed; falling back to string parsing: $($_.Exception.Message)"
        }
    }

    $inner = Get-PropertyValue -Object $SizeValue -Name 'Value'
    if ($null -ne $inner -and -not [object]::ReferenceEquals($inner, $SizeValue)) {
        $unwrapped = ConvertTo-Bytes $inner
        if ($null -ne $unwrapped) {
            return $unwrapped
        }
    }

    $text = $SizeValue.ToString()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    if ($text -match 'Unlimited') {
        return [double]::PositiveInfinity
    }

    if ($text -match '\(([\d\.,\s]+)\s*bytes\)') {
        $digits = $matches[1] -replace '\D', ''
        if ($digits.Length -gt 0) {
            return [double]$digits
        }
    }

    if ($text -match '^\s*([\d\.]+)\s*$') {
        return [double]$matches[1]
    }

    if ($text -match '([\d\.,]+)\s*(TB|GB|MB|KB|B)\b') {
        $raw = $matches[1]
        if ($raw -match ',' -and $raw -match '\.') {
            $raw = $raw -replace '\.', ''
            $raw = $raw -replace ',', '.'
        }
        else {
            $raw = $raw -replace ',', ''
        }
        $num = [double]$raw
        switch ($matches[2]) {
            'TB' { return $num * 1TB }
            'GB' { return $num * 1GB }
            'MB' { return $num * 1MB }
            'KB' { return $num * 1KB }
            'B'  { return $num }
        }
    }

    return $null
}

function Format-GB {
    param($Bytes)

    if ($null -eq $Bytes) {
        return 'Unknown'
    }
    if ([double]::IsInfinity([double]$Bytes)) {
        return 'Unlimited'
    }
    return ('{0:N2} GB' -f ([double]$Bytes / 1GB))
}

function Test-QuotaEquals {
    param(
        $ActualBytes,
        [double]$ExpectedBytes,
        [double]$ToleranceBytes
    )

    if ($null -eq $ActualBytes) {
        return $false
    }

    $actual = [double]$ActualBytes
    if ([double]::IsInfinity($actual) -and [double]::IsInfinity($ExpectedBytes)) {
        return $true
    }
    if ([double]::IsInfinity($actual) -or [double]::IsInfinity($ExpectedBytes)) {
        return $false
    }

    return [Math]::Abs($actual - $ExpectedBytes) -le $ToleranceBytes
}

function ConvertTo-HtmlEncoded {
    param([string]$Text)

    if ([string]::IsNullOrEmpty($Text)) {
        return ''
    }

    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Test-HasCmdletParameter {
    param(
        [Parameter(Mandatory)]
        [string]$CommandName,
        [Parameter(Mandatory)]
        [string]$ParameterName
    )

    $cmd = Get-Command -Name $CommandName -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        return $false
    }
    return $cmd.Parameters.ContainsKey($ParameterName)
}

function Get-ExceptionMessageChain {
    param($Exception)

    $parts = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $queue = New-Object System.Collections.Generic.Queue[System.Exception]
    if ($null -ne $Exception) {
        $queue.Enqueue($Exception)
    }

    while ($queue.Count -gt 0) {
        $ex = $queue.Dequeue()
        if ($null -eq $ex) {
            continue
        }

        $msg = $ex.Message
        if (-not [string]::IsNullOrWhiteSpace($msg) -and $seen.Add($msg)) {
            [void]$parts.Add($msg)
        }

        if ($null -ne $ex.InnerException) {
            $queue.Enqueue($ex.InnerException)
        }

        if ($ex -is [System.AggregateException]) {
            foreach ($inner in @($ex.InnerExceptions)) {
                if ($null -ne $inner) {
                    $queue.Enqueue($inner)
                }
            }
        }
    }

    if ($parts.Count -eq 0) {
        return 'Unknown error'
    }
    return ($parts -join ' --> ')
}

function Test-IsTransientError {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    return [bool]($Message -match 'throttl|429|503|timeout|temporarily|too many requests|server cannot service|Try again|busy|rate limit')
}

function Test-IsMissingMailboxError {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    return [bool]($Message -match "couldn't be found|couldn't find|doesn't exist|cannot find|not found|couldn't be located|no mailbox")
}

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 5,
        [string]$Activity = 'request'
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            # Microsoft.Graph and EXO cmdlets are not StrictMode-safe; they read .Count
            # on scalars and throw PropertyNotFoundStrict back into this script.
            Set-StrictMode -Off
            try {
                return & $ScriptBlock
            }
            finally {
                Set-StrictMode -Version Latest
            }
        }
        catch {
            $msg = Get-ExceptionMessageChain -Exception $_.Exception
            $transient = Test-IsTransientError -Message $msg
            if (-not $transient -or $attempt -ge $MaxAttempts) {
                throw
            }
            $delay = [Math]::Min(60, [int][Math]::Pow(2, $attempt))
            Write-Warn ("Transient error on {0} (attempt {1}/{2}), retrying in {3}s: {4}" -f $Activity, $attempt, $MaxAttempts, $delay, $msg)
            Start-Sleep -Seconds $delay
        }
    }
}

function Enable-Tls12 {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return
    }

    $tls12 = [Net.SecurityProtocolType]::Tls12
    try {
        $current = [Net.ServicePointManager]::SecurityProtocol
        if (($current -band $tls12) -ne $tls12) {
            [Net.ServicePointManager]::SecurityProtocol = $current -bor $tls12
        }
    }
    catch {
        try {
            [Net.ServicePointManager]::SecurityProtocol = $tls12
        }
        catch {
            Write-Verbose "Unable to force TLS 1.2: $($_.Exception.Message)"
        }
    }
}

function Enable-DefaultProxyCredentials {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return
    }

    try {
        $proxy = [Net.WebRequest]::DefaultWebProxy
        if ($null -ne $proxy -and $null -eq $proxy.Credentials) {
            $proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials
        }
    }
    catch {
        Write-Verbose "Unable to set default proxy credentials: $($_.Exception.Message)"
    }
}

function Install-RequiredModuleIfMissing {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (Get-Module -ListAvailable -Name $Name) {
        return
    }

    Write-Info "Module '$Name' not found. Installing for current user..."
    Enable-Tls12

    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    if ($null -eq $nuget -or $nuget.Version -lt [version]'2.8.5.201') {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
    }

    $gallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if ($null -ne $gallery -and $gallery.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }

    Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
}

function Import-RequiredModule {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    Install-RequiredModuleIfMissing -Name $Name
    Import-Module $Name -ErrorAction Stop
}

function Get-CsvEncodingName {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return 'utf8BOM'
    }
    return 'UTF8'
}

function Get-MailboxQuotaPropertySets {
    return @('Minimum', 'Quota')
}

function ConvertTo-Bool {
    param($Value)

    if ($null -eq $Value) {
        return $false
    }
    if ($Value -is [bool]) {
        return $Value
    }

    $text = [string]$Value
    switch -Regex ($text.Trim()) {
        '^(1|true|yes|y)$' { return $true }
        default            { return $false }
    }
}

function New-QuotaPolicy {
    param(
        [int]$TargetStorageQuotaGB,
        [int]$ProhibitSendQuotaGB,
        [int]$IssueWarningQuotaGB,
        [int]$LegacyQuotaGB,
        [int]$NearLimitPercent,
        [int]$QuotaToleranceMB
    )

    if ($IssueWarningQuotaGB -ge $ProhibitSendQuotaGB -or $ProhibitSendQuotaGB -ge $TargetStorageQuotaGB) {
        throw "Quotas must satisfy IssueWarning < ProhibitSend < ProhibitSendReceive (got $IssueWarningQuotaGB / $ProhibitSendQuotaGB / $TargetStorageQuotaGB)."
    }

    return @{
        TargetStorageQuotaGB = $TargetStorageQuotaGB
        ProhibitSendQuotaGB  = $ProhibitSendQuotaGB
        IssueWarningQuotaGB  = $IssueWarningQuotaGB
        LegacyQuotaGB        = $LegacyQuotaGB
        NearLimitPercent     = $NearLimitPercent
        TargetStorageBytes   = [double]$TargetStorageQuotaGB * 1GB
        TargetSendBytes      = [double]$ProhibitSendQuotaGB * 1GB
        TargetWarnBytes      = [double]$IssueWarningQuotaGB * 1GB
        LegacyBytes          = [double]$LegacyQuotaGB * 1GB
        NearLimitBytes       = ([double]$LegacyQuotaGB * 1GB) * ($NearLimitPercent / 100.0)
        ToleranceBytes       = [double]$QuotaToleranceMB * 1MB
    }
}

function Get-MailboxQuotaEvaluation {
    param(
        [Parameter(Mandatory)]
        $Mailbox,
        $UsedBytes,
        [Parameter(Mandatory)]
        $License,
        [Parameter(Mandatory)]
        [hashtable]$Policy
    )

    $srBytes   = ConvertTo-Bytes (Get-PropertyValue $Mailbox 'ProhibitSendReceiveQuota')
    $sendBytes = ConvertTo-Bytes (Get-PropertyValue $Mailbox 'ProhibitSendQuota')
    $warnBytes = ConvertTo-Bytes (Get-PropertyValue $Mailbox 'IssueWarningQuota')
    $useDefaults = ConvertTo-Bool (Get-PropertyValue $Mailbox 'UseDatabaseQuotaDefaults')

    $issues = New-Object System.Collections.Generic.List[string]

    $storageCompliant = Test-QuotaEquals -ActualBytes $srBytes -ExpectedBytes $Policy.TargetStorageBytes -ToleranceBytes $Policy.ToleranceBytes
    if (-not $storageCompliant) {
        [void]$issues.Add("ProhibitSendReceiveQuota is $(Format-GB $srBytes), expected $($Policy.TargetStorageQuotaGB) GB")
    }

    $sendCompliant = Test-QuotaEquals -ActualBytes $sendBytes -ExpectedBytes $Policy.TargetSendBytes -ToleranceBytes $Policy.ToleranceBytes
    if (-not $sendCompliant) {
        [void]$issues.Add("ProhibitSendQuota is $(Format-GB $sendBytes), expected $($Policy.ProhibitSendQuotaGB) GB")
    }

    $warnCompliant = Test-QuotaEquals -ActualBytes $warnBytes -ExpectedBytes $Policy.TargetWarnBytes -ToleranceBytes $Policy.ToleranceBytes
    if (-not $warnCompliant) {
        [void]$issues.Add("IssueWarningQuota is $(Format-GB $warnBytes), expected $($Policy.IssueWarningQuotaGB) GB")
    }

    if ($useDefaults -and $issues.Count -gt 0) {
        [void]$issues.Add('UseDatabaseQuotaDefaults is True (custom quota values may be ignored until it is set to False)')
    }

    $nearLegacyLimit = $false
    $hasE3 = ConvertTo-Bool (Get-PropertyValue $License 'HasE3')
    if ($hasE3 -and (Test-QuotaEquals -ActualBytes $srBytes -ExpectedBytes $Policy.LegacyBytes -ToleranceBytes $Policy.ToleranceBytes) -and ($null -ne $UsedBytes)) {
        if ([double]$UsedBytes -ge $Policy.NearLimitBytes) {
            $nearLegacyLimit = $true
            [void]$issues.Add("E3 mailbox on $($Policy.LegacyQuotaGB) GB cap at $(Format-GB $UsedBytes) (>= $($Policy.NearLimitPercent)%)")
        }
    }

    $percentUsed = $null
    if ($null -ne $UsedBytes -and $null -ne $srBytes -and -not [double]::IsInfinity([double]$srBytes) -and [double]$srBytes -gt 0) {
        $percentUsed = [Math]::Round(([double]$UsedBytes / [double]$srBytes) * 100, 1)
    }

    $quotasAligned = $storageCompliant -and $sendCompliant -and $warnCompliant
    $needsQuotaFix = -not $quotasAligned

    $upn = Get-PropertyValue $Mailbox 'UserPrincipalName'
    if ([string]::IsNullOrWhiteSpace([string]$upn)) {
        $upn = Get-PropertyValue $License 'UserPrincipalName'
    }

    $displayName = Get-PropertyValue $Mailbox 'DisplayName'
    if ([string]::IsNullOrWhiteSpace([string]$displayName)) {
        $displayName = Get-PropertyValue $License 'DisplayName'
    }

    return [pscustomobject]@{
        UserPrincipalName        = $upn
        DisplayName              = $displayName
        ExternalDirectoryObjectId = Get-PropertyValue $Mailbox 'ExternalDirectoryObjectId'
        RecipientTypeDetails     = Get-PropertyValue $Mailbox 'RecipientTypeDetails'
        LicenseE3                = $hasE3
        LicenseE5                = ConvertTo-Bool (Get-PropertyValue $License 'HasE5')
        UseDatabaseQuotaDefaults = $useDefaults
        ProhibitSendReceiveGB    = Format-GB $srBytes
        ProhibitSendGB           = Format-GB $sendBytes
        IssueWarningGB           = Format-GB $warnBytes
        TotalItemSizeGB          = Format-GB $UsedBytes
        PercentOfCapUsed         = $percentUsed
        StorageCompliant         = $storageCompliant
        QuotasAligned            = $quotasAligned
        NearLegacyLimit          = $nearLegacyLimit
        Issues                   = ($issues -join '; ')
        NeedsRemediation         = $needsQuotaFix
        StorageBytes             = $srBytes
        SendBytes                = $sendBytes
        WarnBytes                = $warnBytes
        UsedBytes                = $UsedBytes
    }
}

function Resolve-MailboxLicense {
    param(
        $Mailbox,
        [hashtable]$LicenseByObjectId,
        [hashtable]$LicenseByUpn
    )

    $extId = ConvertTo-NormalizedGuid (Get-PropertyValue $Mailbox 'ExternalDirectoryObjectId')
    if ($extId -and $LicenseByObjectId.ContainsKey($extId)) {
        return $LicenseByObjectId[$extId]
    }

    foreach ($name in @('UserPrincipalName', 'PrimarySmtpAddress', 'WindowsLiveID', 'Alias')) {
        $value = Get-PropertyValue $Mailbox $name
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            $key = ([string]$value).Trim().ToLowerInvariant()
            if ($LicenseByUpn.ContainsKey($key)) {
                return $LicenseByUpn[$key]
            }
        }
    }

    return $null
}

function New-HtmlReport {
    param(
        [Parameter(Mandatory)] $Results,
        [Parameter(Mandatory)] [hashtable] $Summary,
        [Parameter(Mandatory)] [string] $Path
    )

    $notCompliant = @($Results | Where-Object { -not $_.StorageCompliant } | Sort-Object UserPrincipalName)
    $nearLimit    = @($Results | Where-Object { $_.NearLegacyLimit } | Sort-Object PercentOfCapUsed -Descending)

    function Build-Table {
        param($Rows, [string[]]$Columns, [hashtable]$Headers, [string]$EmptyMessage)

        $rowList = @($Rows)
        if ($rowList.Count -eq 0) {
            return "<p class='empty'>$(ConvertTo-HtmlEncoded $EmptyMessage)</p>"
        }

        $head = foreach ($col in $Columns) {
            $label = $col
            if ($Headers -and $Headers.ContainsKey($col) -and -not [string]::IsNullOrWhiteSpace([string]$Headers[$col])) {
                $label = [string]$Headers[$col]
            }
            "<th>$(ConvertTo-HtmlEncoded $label)</th>"
        }
        $bodyRows = New-Object System.Collections.Generic.List[string]
        foreach ($row in $rowList) {
            $cells = foreach ($col in $Columns) {
                $value = Get-PropertyValue $row $col
                $extraClass = if ($col -eq 'Issues') { ' issues' } else { '' }
                if ($value -is [bool]) {
                    $cls  = if ($value) { 'yes' } else { 'no' }
                    $text = if ($value) { 'Yes' } else { 'No' }
                    "<td class='$cls$extraClass'>$text</td>"
                }
                else {
                    "<td class='text$extraClass'>$(ConvertTo-HtmlEncoded ([string]$value))</td>"
                }
            }
            [void]$bodyRows.Add("<tr>$($cells -join '')</tr>")
        }
        return "<table><thead><tr>$($head -join '')</tr></thead><tbody>$($bodyRows -join '')</tbody></table>"
    }

    $columnHeaders = @{
        UserPrincipalName     = 'UPN'
        DisplayName           = 'Name'
        LicenseE3             = 'E3'
        LicenseE5             = 'E5'
        ProhibitSendReceiveGB = 'Cap'
        ProhibitSendGB        = 'Send'
        IssueWarningGB        = 'Warn'
        TotalItemSizeGB       = 'Used'
        PercentOfCapUsed      = '% cap'
        Issues                = 'Issues'
    }
    $detailColumns = @(
        'UserPrincipalName', 'DisplayName', 'LicenseE3', 'LicenseE5',
        'ProhibitSendReceiveGB', 'ProhibitSendGB', 'IssueWarningGB',
        'TotalItemSizeGB', 'PercentOfCapUsed', 'Issues'
    )
    $nearColumns = @(
        'UserPrincipalName', 'DisplayName', 'ProhibitSendReceiveGB',
        'TotalItemSizeGB', 'PercentOfCapUsed'
    )

    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $mode      = if ($Summary.Remediated) { 'Remediation' } else { 'Report only' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mailbox Quota Compliance Report</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         background: #f5f6f8; color: #1f2933; line-height: 1.5; }
  header { background: #0f2540; color: #fff; padding: 2rem 2.5rem; }
  header h1 { margin: 0 0 .25rem; font-size: 1.5rem; }
  header p { margin: 0; color: #9fb3c8; font-size: .875rem; }
  main { padding: 2rem 2.5rem; max-width: 1200px; margin: 0 auto; }
  .cards { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 2rem; }
  .card { flex: 1 1 180px; background: #fff; border: 1px solid #e4e7eb; border-radius: 8px;
          padding: 1.25rem; }
  .card .value { font-size: 2rem; font-weight: 700; }
  .card .label { font-size: .8125rem; color: #616e7c; text-transform: uppercase; letter-spacing: .03em; }
  .card.alert .value { color: #b91c1c; }
  .card.warn .value  { color: #b45309; }
  .card.ok .value    { color: #047857; }
  section { margin-bottom: 2.5rem; }
  h2 { font-size: 1.125rem; border-bottom: 2px solid #e4e7eb; padding-bottom: .5rem; }
  table { width: 100%; border-collapse: collapse; background: #fff; font-size: .8125rem;
          border: 1px solid #e4e7eb; border-radius: 8px; overflow: hidden; }
  th, td { text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #eef1f4; vertical-align: top; }
  th { background: #f0f3f6; font-weight: 600; white-space: nowrap; }
  td.text { white-space: nowrap; }
  td.issues { white-space: normal; min-width: 16rem; max-width: 28rem; }
  tbody tr:last-child td { border-bottom: none; }
  td.yes { color: #047857; font-weight: 600; }
  td.no  { color: #9aa5b1; }
  .empty { color: #616e7c; font-style: italic; }
  footer { padding: 1.5rem 2.5rem; color: #9aa5b1; font-size: .75rem; text-align: center; }
  .scroll { overflow-x: auto; }
</style>
</head>
<body>
<header>
  <h1>Mailbox Quota Compliance Report</h1>
  <p>Generated $(ConvertTo-HtmlEncoded $generated) &middot; Mode: $(ConvertTo-HtmlEncoded $mode) &middot; Target storage cap: $($Summary.TargetStorageQuotaGB) GB</p>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="value">$($Summary.Total)</div><div class="label">Licensed mailboxes</div></div>
    <div class="card alert"><div class="value">$($Summary.NotCompliant)</div><div class="label">Not $($Summary.TargetStorageQuotaGB) GB storage</div></div>
    <div class="card warn"><div class="value">$($Summary.NearLimit)</div><div class="label">E3 near $($Summary.LegacyQuotaGB) GB cap</div></div>
    <div class="card ok"><div class="value">$($Summary.Compliant)</div><div class="label">Storage compliant</div></div>
  </div>

  <section>
    <h2>Mailboxes not configured for $($Summary.TargetStorageQuotaGB) GB storage</h2>
    <div class="scroll">$(Build-Table -Rows $notCompliant -Columns $detailColumns -Headers $columnHeaders -EmptyMessage 'All licensed mailboxes meet the storage target.')</div>
  </section>

  <section>
    <h2>E3 mailboxes approaching the $($Summary.LegacyQuotaGB) GB limit (&ge; $($Summary.NearLimitPercent)%)</h2>
    <div class="scroll">$(Build-Table -Rows $nearLimit -Columns $nearColumns -Headers $columnHeaders -EmptyMessage 'No E3 mailboxes are near the legacy cap.')</div>
  </section>
</main>
<footer>Generated by Report-MailboxQuotaCompliance.ps1</footer>
</body>
</html>
"@

    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $html, $utf8NoBom)
}

function Get-LicenseLookupTables {
    param(
        $Users,
        [hashtable]$SkuMap,
        [string[]]$E3SkuIds,
        [string[]]$E5SkuIds
    )

    $byObjectId = @{}
    $byUpn      = @{}
    $e3Set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $e5Set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($E3SkuIds)) { if ($id) { [void]$e3Set.Add($id) } }
    foreach ($id in @($E5SkuIds)) { if ($id) { [void]$e5Set.Add($id) } }

    foreach ($user in (ConvertTo-ObjectArray $Users)) {
        $assigned = ConvertTo-ObjectArray (Get-PropertyValue $user 'AssignedLicenses')
        if ((Get-CollectionCount $assigned) -eq 0) {
            continue
        }

        $hasE3 = $false
        $hasE5 = $false
        foreach ($lic in $assigned) {
            $skuId = ConvertTo-NormalizedGuid (Get-PropertyValue $lic 'SkuId')
            if (-not $skuId) {
                continue
            }
            if ($e3Set.Contains($skuId)) { $hasE3 = $true }
            if ($e5Set.Contains($skuId)) { $hasE5 = $true }
        }

        if (-not ($hasE3 -or $hasE5)) {
            continue
        }

        $upn = Get-PropertyValue $user 'UserPrincipalName'
        $info = [pscustomobject]@{
            GraphId            = Get-PropertyValue $user 'Id'
            UserPrincipalName  = $upn
            DisplayName        = Get-PropertyValue $user 'DisplayName'
            AccountEnabled     = ConvertTo-Bool (Get-PropertyValue $user 'AccountEnabled')
            HasE3              = $hasE3
            HasE5              = $hasE5
        }

        $objectId = ConvertTo-NormalizedGuid $info.GraphId
        if ($objectId) {
            $byObjectId[$objectId] = $info
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$upn)) {
            $byUpn[([string]$upn).Trim().ToLowerInvariant()] = $info
        }
    }

    return @{
        ByObjectId = $byObjectId
        ByUpn      = $byUpn
        UserCount  = [int]$byObjectId.Count
        SkuMap     = $SkuMap
    }
}

function Test-SelfTestNumeric {
    param($Value)

    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [char] -or $Value -is [string]) {
        return $false
    }
    return ($Value -is [ValueType] -or $Value -is [decimal])
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Name)

    if ($null -eq $Actual -and $null -eq $Expected) {
        return
    }
    if ($Actual -is [bool] -or $Expected -is [bool]) {
        if ([bool]$Actual -ne [bool]$Expected) {
            throw "SelfTest failed: $Name. Expected '$Expected', got '$Actual'."
        }
        return
    }
    if ((Test-SelfTestNumeric $Actual) -and (Test-SelfTestNumeric $Expected)) {
        $left = [double]$Actual
        $right = [double]$Expected
        $bothInfinity = [double]::IsInfinity($left) -and [double]::IsInfinity($right) -and ([double]::IsPositiveInfinity($left) -eq [double]::IsPositiveInfinity($right))
        if ($bothInfinity) {
            return
        }
        if ([Math]::Abs($left - $right) -gt 0.5) {
            throw "SelfTest failed: $Name. Expected '$Expected', got '$Actual'."
        }
        return
    }
    if ([string]$Actual -ne [string]$Expected) {
        throw "SelfTest failed: $Name. Expected '$Expected', got '$Actual'."
    }
}

function Invoke-MailboxQuotaSelfTest {
    Write-Info 'Running Report-MailboxQuotaCompliance self-tests...'

    $policy = New-QuotaPolicy -TargetStorageQuotaGB 100 -ProhibitSendQuotaGB 99 -IssueWarningQuotaGB 98 -LegacyQuotaGB 50 -NearLimitPercent 90 -QuotaToleranceMB 2

    Assert-Equal (ConvertTo-Bytes $null) $null 'null size'
    Assert-Equal (ConvertTo-Bytes 'Unlimited') ([double]::PositiveInfinity) 'unlimited string'
    Assert-Equal (ConvertTo-Bytes 106300440576) 106300440576 'numeric bytes'
    Assert-Equal (ConvertTo-Bytes '99 GB (106,300,440,576 bytes)') 106300440576 'string with byte count'
    Assert-Equal (ConvertTo-Bytes '50 GB (53.687.091.200 bytes)') 53687091200 'european thousands in parentheses'
    Assert-Equal (ConvertTo-Bytes '100 GB') (100 * 1GB) 'GB without byte count'
    Assert-Equal (ConvertTo-Bytes '100GB') (100 * 1GB) 'GB without space'
    $wrapped = [pscustomobject]@{ Value = '45 GB (48,318,382,080 bytes)' }
    Assert-Equal (ConvertTo-Bytes $wrapped) 48318382080 'Value wrapper'
    $methodObj = [pscustomobject]@{}
    $methodObj | Add-Member -MemberType ScriptMethod -Name ToBytes -Value { 12345 }
    Assert-Equal (ConvertTo-Bytes $methodObj) 12345 'ToBytes method'

    Assert-Equal (Format-GB $null) 'Unknown' 'format null'
    Assert-Equal (Format-GB ([double]::PositiveInfinity)) 'Unlimited' 'format unlimited'
    Assert-Equal (Test-QuotaEquals -ActualBytes (100 * 1GB) -ExpectedBytes $policy.TargetStorageBytes -ToleranceBytes $policy.ToleranceBytes) $true 'exact 100 GB'
    Assert-Equal (Test-QuotaEquals -ActualBytes ((100 * 1GB) + 1MB) -ExpectedBytes $policy.TargetStorageBytes -ToleranceBytes $policy.ToleranceBytes) $true 'within 2 MB tolerance'
    Assert-Equal (Test-QuotaEquals -ActualBytes ((100 * 1GB) + 5MB) -ExpectedBytes $policy.TargetStorageBytes -ToleranceBytes $policy.ToleranceBytes) $false 'outside tolerance'
    Assert-Equal (Test-QuotaEquals -ActualBytes $null -ExpectedBytes $policy.TargetStorageBytes -ToleranceBytes $policy.ToleranceBytes) $false 'null not equal'

    Assert-Equal (ConvertTo-HtmlEncoded '<b>&"') '&lt;b&gt;&amp;&quot;' 'html encode'
    Assert-Equal ((Get-MailboxQuotaPropertySets) -contains 'Minimum') $true 'Minimum property set required'
    Assert-Equal ((Get-MailboxQuotaPropertySets) -contains 'Quota') $true 'Quota property set required'

    Assert-Equal (Get-CollectionCount $null) 0 'null collection count'
    Assert-Equal (Get-CollectionCount @()) 0 'empty array count'
    Assert-Equal (Get-CollectionCount @(1, 2)) 2 'array count'
    Assert-Equal (Get-CollectionCount 'jane@contoso.com') 1 'string is one item, not characters'
    $oneHash = @{ skuId = 'abc'; disabledPlans = @() }
    Assert-Equal (Get-CollectionCount (ConvertTo-ObjectArray $oneHash)) 1 'hashtable is one object, not its keys'
    $hashUsers = ConvertTo-ObjectArray $oneHash
    Assert-Equal ($hashUsers[0].skuId) 'abc' 'hashtable element preserved'
    Assert-Equal (Get-CollectionCount (ConvertTo-StringArray $null)) 0 'omitted Identity is empty, not one null'

    $e3Sku = [guid]'6fd2c87f-b296-42f0-b197-1e91e994b900'
    $graphUser = @{
        id                = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        userPrincipalName = 'single@contoso.com'
        displayName       = 'Single'
        assignedLicenses  = @{ skuId = $e3Sku }
    }
    $singleLookup = Get-LicenseLookupTables -Users $graphUser -SkuMap @{} -E3SkuIds @($e3Sku.ToString()) -E5SkuIds @()
    Assert-Equal $singleLookup.UserCount 1 'single Graph hashtable user is not enumerated by key'
    $otherSku = [guid]'f245ecc8-75af-4f8e-b61f-27d8114de5f3'
    $users = @(
        [pscustomobject]@{
            Id                 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            UserPrincipalName  = 'Jane@Contoso.com'
            DisplayName        = 'Jane Doe'
            AccountEnabled     = $true
            AssignedLicenses   = @([pscustomobject]@{ SkuId = $e3Sku })
        },
        [pscustomobject]@{
            Id                 = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
            UserPrincipalName  = 'guest@fabrikam.com'
            DisplayName        = 'No E3'
            AssignedLicenses   = @([pscustomobject]@{ SkuId = $otherSku })
        }
    )
    $lookup = Get-LicenseLookupTables -Users $users -SkuMap @{} -E3SkuIds @($e3Sku.ToString()) -E5SkuIds @()
    Assert-Equal $lookup.UserCount 1 'one E3 user indexed'
    Assert-Equal $lookup.ByUpn.ContainsKey('jane@contoso.com') $true 'UPN indexed lowercase'
    Assert-Equal $lookup.ByObjectId.ContainsKey('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa') $true 'object id indexed'

    $mbxByGuid = [pscustomobject]@{
        UserPrincipalName         = 'alias-mismatch@contoso.com'
        DisplayName               = 'Jane Doe'
        ExternalDirectoryObjectId = 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA'
        PrimarySmtpAddress        = 'jane@contoso.com'
        ProhibitSendReceiveQuota  = '50 GB (53,687,091,200 bytes)'
        ProhibitSendQuota         = '49 GB (52,613,349,376 bytes)'
        IssueWarningQuota         = '48 GB (51,539,607,552 bytes)'
        UseDatabaseQuotaDefaults  = $false
        RecipientTypeDetails      = 'UserMailbox'
    }
    $lic = Resolve-MailboxLicense -Mailbox $mbxByGuid -LicenseByObjectId $lookup.ByObjectId -LicenseByUpn $lookup.ByUpn
    Assert-Equal $lic.UserPrincipalName 'Jane@Contoso.com' 'join by ExternalDirectoryObjectId beats UPN mismatch'

    $usedNear = 46 * 1GB
    $evalNear = Get-MailboxQuotaEvaluation -Mailbox $mbxByGuid -UsedBytes $usedNear -License $lic -Policy $policy
    Assert-Equal $evalNear.StorageCompliant $false '50 GB is not 100 GB'
    Assert-Equal $evalNear.NearLegacyLimit $true 'E3 46/50 GB is near limit'
    Assert-Equal $evalNear.NeedsRemediation $true 'legacy cap still needs quota fix'
    Assert-Equal ($evalNear.Issues -match 'UseDatabaseQuotaDefaults') $false 'defaults false is not flagged'

    $compliant = [pscustomobject]@{
        UserPrincipalName         = 'ok@contoso.com'
        DisplayName               = 'OK User'
        ExternalDirectoryObjectId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        ProhibitSendReceiveQuota  = '100 GB (107,374,182,400 bytes)'
        ProhibitSendQuota         = '99 GB (106,300,440,576 bytes)'
        IssueWarningQuota         = '98 GB (105,226,698,752 bytes)'
        UseDatabaseQuotaDefaults  = $true
        RecipientTypeDetails      = 'UserMailbox'
    }
    $evalOk = Get-MailboxQuotaEvaluation -Mailbox $compliant -UsedBytes (10 * 1GB) -License $lic -Policy $policy
    Assert-Equal $evalOk.StorageCompliant $true '100 GB storage compliant'
    Assert-Equal $evalOk.QuotasAligned $true 'all three quotas aligned'
    Assert-Equal $evalOk.NeedsRemediation $false 'no remediation'
    Assert-Equal $evalOk.NearLegacyLimit $false 'not on legacy cap'
    Assert-Equal $evalOk.UseDatabaseQuotaDefaults $true 'defaults preserved when quotas already match'

    $defaultsWrong = [pscustomobject]@{
        UserPrincipalName         = 'old@contoso.com'
        DisplayName               = 'Old Defaults'
        ProhibitSendReceiveQuota  = '50 GB (53,687,091,200 bytes)'
        ProhibitSendQuota         = '49 GB (52,613,349,376 bytes)'
        IssueWarningQuota         = '48 GB (51,539,607,552 bytes)'
        UseDatabaseQuotaDefaults  = $true
    }
    $evalDefaults = Get-MailboxQuotaEvaluation -Mailbox $defaultsWrong -UsedBytes (1 * 1GB) -License $lic -Policy $policy
    Assert-Equal ($evalDefaults.Issues -match 'UseDatabaseQuotaDefaults is True') $true 'defaults noted when quotas are wrong'

    $sendMismatch = [pscustomobject]@{
        UserPrincipalName         = 'send@contoso.com'
        DisplayName               = 'Send Mismatch'
        ProhibitSendReceiveQuota  = '100 GB (107,374,182,400 bytes)'
        ProhibitSendQuota         = '90 GB (96,636,764,160 bytes)'
        IssueWarningQuota         = '98 GB (105,226,698,752 bytes)'
        UseDatabaseQuotaDefaults  = $false
    }
    $evalSend = Get-MailboxQuotaEvaluation -Mailbox $sendMismatch -UsedBytes (1 * 1GB) -License $lic -Policy $policy
    Assert-Equal $evalSend.StorageCompliant $true 'storage cap ok'
    Assert-Equal $evalSend.QuotasAligned $false 'send quota not aligned'
    Assert-Equal $evalSend.NeedsRemediation $true 'send mismatch remediates'

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('MailboxQuotaSelfTest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    try {
        $sample = New-Object System.Collections.Generic.List[object]
        $sample.Add($evalNear) | Out-Null
        $sample.Add($evalOk) | Out-Null
        $htmlPath = Join-Path $tempRoot 'summary.html'
        New-HtmlReport -Results $sample -Path $htmlPath -Summary @{
            Total                = $sample.Count
            Compliant            = 1
            NotCompliant         = 1
            NearLimit            = 1
            TargetStorageQuotaGB = 100
            LegacyQuotaGB        = 50
            NearLimitPercent     = 90
            Remediated           = $false
        }
        Assert-Equal (Test-Path -LiteralPath $htmlPath) $true 'html report written'
        $html = [System.IO.File]::ReadAllText($htmlPath)
        Assert-Equal ($html -match 'Mailbox Quota Compliance Report') $true 'html title'
        Assert-Equal ($html -match 'alias-mismatch@contoso.com') $true 'non-compliant row rendered'
        Assert-Equal ($html -match "class='text issues'") $true 'issues column wraps'
        Assert-Equal ($html -match '<script') $false 'no script tags'
        Assert-Equal ($html -match 'ok@contoso.com') $false 'compliant mailbox not in non-compliant table'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    $one = @($evalOk)
    Assert-Equal $one.Count 1 'array wrap of one result'
    $chars = 0
    foreach ($item in $one) { $chars++ }
    Assert-Equal $chars 1 'foreach over single result is not character enumeration'

    try {
        New-QuotaPolicy -TargetStorageQuotaGB 50 -ProhibitSendQuotaGB 99 -IssueWarningQuotaGB 98 -LegacyQuotaGB 50 -NearLimitPercent 90 -QuotaToleranceMB 2 | Out-Null
        throw 'SelfTest failed: invalid quota ordering should throw.'
    }
    catch {
        if ($_.Exception.Message -notmatch 'IssueWarning < ProhibitSend') {
            throw
        }
    }

    $demo = @(Get-MailboxQuotaDemoRows -Policy $policy)
    Assert-Equal $demo.Count 3 'demo report has three sample mailboxes'
    $alex = $demo | Where-Object { $_.UserPrincipalName -eq 'alex@contoso.com' } | Select-Object -First 1
    Assert-Equal $alex.NearLegacyLimit $true 'demo Alex is near the 50 GB cap'
    Assert-Equal $alex.StorageCompliant $false 'demo Alex is not at 100 GB'
    $sam = $demo | Where-Object { $_.UserPrincipalName -eq 'sam@contoso.com' } | Select-Object -First 1
    Assert-Equal $sam.QuotasAligned $true 'demo Sam is fully aligned'
    $jordan = $demo | Where-Object { $_.UserPrincipalName -eq 'jordan@contoso.com' } | Select-Object -First 1
    Assert-Equal $jordan.StorageCompliant $true 'demo Jordan storage cap is 100 GB'
    Assert-Equal $jordan.NeedsRemediation $true 'demo Jordan send/warn still remediates'

    Write-Ok 'Self-tests passed.'
}

function Get-MailboxQuotaDemoRows {
    param([hashtable]$Policy)

    $licE3 = [pscustomobject]@{ HasE3 = $true; HasE5 = $false; UserPrincipalName = 'alex@contoso.com'; DisplayName = 'Alex Rivera' }
    $licE5 = [pscustomobject]@{ HasE3 = $false; HasE5 = $true; UserPrincipalName = 'sam@contoso.com'; DisplayName = 'Sam Okonkwo' }
    $licBoth = [pscustomobject]@{ HasE3 = $true; HasE5 = $true; UserPrincipalName = 'jordan@contoso.com'; DisplayName = 'Jordan Lee' }

    $rows = New-Object System.Collections.Generic.List[object]
    $samples = @(
        @{
            Mailbox = [pscustomobject]@{
                UserPrincipalName         = 'alex@contoso.com'
                DisplayName               = 'Alex Rivera'
                ExternalDirectoryObjectId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                RecipientTypeDetails      = 'UserMailbox'
                ProhibitSendReceiveQuota  = '50 GB (53,687,091,200 bytes)'
                ProhibitSendQuota         = '49 GB (52,613,349,376 bytes)'
                IssueWarningQuota         = '47.5 GB (51,003,566,080 bytes)'
                UseDatabaseQuotaDefaults  = $false
            }
            UsedBytes = 46.2 * 1GB
            License   = $licE3
        }
        @{
            Mailbox = [pscustomobject]@{
                UserPrincipalName         = 'sam@contoso.com'
                DisplayName               = 'Sam Okonkwo'
                ExternalDirectoryObjectId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
                RecipientTypeDetails      = 'UserMailbox'
                ProhibitSendReceiveQuota  = '100 GB (107,374,182,400 bytes)'
                ProhibitSendQuota         = '99 GB (106,300,440,576 bytes)'
                IssueWarningQuota         = '98 GB (105,226,698,752 bytes)'
                UseDatabaseQuotaDefaults  = $true
            }
            UsedBytes = 12.4 * 1GB
            License   = $licE5
        }
        @{
            Mailbox = [pscustomobject]@{
                UserPrincipalName         = 'jordan@contoso.com'
                DisplayName               = 'Jordan Lee'
                ExternalDirectoryObjectId = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
                RecipientTypeDetails      = 'UserMailbox'
                ProhibitSendReceiveQuota  = '100 GB (107,374,182,400 bytes)'
                ProhibitSendQuota         = '90 GB (96,636,764,160 bytes)'
                IssueWarningQuota         = '88 GB (94,488,899,584 bytes)'
                UseDatabaseQuotaDefaults  = $false
            }
            UsedBytes = 67.8 * 1GB
            License   = $licBoth
        }
    )

    foreach ($sample in $samples) {
        [void]$rows.Add((Get-MailboxQuotaEvaluation -Mailbox $sample.Mailbox -UsedBytes $sample.UsedBytes -License $sample.License -Policy $Policy))
    }
    return $rows
}

#--------------------------------------------------------------------
# Graph / EXO
#--------------------------------------------------------------------

function Test-ExchangeOnlineConnected {
    Set-StrictMode -Off
    try {
        if (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) {
            $info = @(Get-ConnectionInformation -ErrorAction Stop)
            return ((Get-CollectionCount $info) -gt 0)
        }
        Get-OrganizationConfig -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
    finally {
        Set-StrictMode -Version Latest
    }
}

function Connect-QuotaExchangeOnline {
    param([string]$UserPrincipalName)

    if (Test-ExchangeOnlineConnected) {
        Write-Ok 'Reusing existing Exchange Online session.'
        return
    }

    $connectParams = @{
        ShowBanner  = $false
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        $connectParams['UserPrincipalName'] = $UserPrincipalName
    }

    $isWindowsPowerShell = $PSVersionTable.PSVersion.Major -lt 6
    if ($isWindowsPowerShell -and (Test-HasCmdletParameter -CommandName 'Connect-ExchangeOnline' -ParameterName 'DisableWAM')) {
        $connectParams['DisableWAM'] = $true
    }

    Invoke-WithRetry -Activity 'Connect-ExchangeOnline' -ScriptBlock { Connect-ExchangeOnline @connectParams }
    $script:ExoConnectedByThisScript = $true
    Write-Ok 'Connected to Exchange Online.'
}

function Test-GraphHasRequiredScopes {
    param([string[]]$Required)

    try {
        $ctx = Invoke-WithRetry -Activity 'Get-MgContext' -ScriptBlock { Get-MgContext -ErrorAction Stop }
    }
    catch {
        return $false
    }

    if ($null -eq $ctx) {
        return $false
    }

    $have = ConvertTo-StringArray (Get-PropertyValue $ctx 'Scopes')
    if ((Get-CollectionCount $have) -eq 0) {
        return $false
    }

    $haveSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($scope in $have) {
        if ($scope) { [void]$haveSet.Add([string]$scope) }
    }

    if ($haveSet.Contains('.default') -or $haveSet.Contains('Directory.Read.All') -or $haveSet.Contains('Directory.ReadWrite.All')) {
        return $true
    }

    foreach ($need in $Required) {
        if (-not $haveSet.Contains($need)) {
            return $false
        }
    }
    return $true
}

function Connect-QuotaGraph {
    param(
        [string]$TenantId,
        [string[]]$Scopes
    )

    $hasContext = $false
    try {
        $ctx = Invoke-WithRetry -Activity 'Get-MgContext' -ScriptBlock { Get-MgContext -ErrorAction SilentlyContinue }
        $hasContext = ($null -ne $ctx)
    }
    catch {
        $hasContext = $false
    }

    if ($hasContext -and (Test-GraphHasRequiredScopes -Required $Scopes)) {
        Write-Ok 'Reusing existing Microsoft Graph session.'
        return
    }

    $connectParams = @{
        Scopes      = $Scopes
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $connectParams['TenantId'] = $TenantId
    }
    if (Test-HasCmdletParameter -CommandName 'Connect-MgGraph' -ParameterName 'NoWelcome') {
        $connectParams['NoWelcome'] = $true
    }

    Invoke-WithRetry -Activity 'Connect-MgGraph' -ScriptBlock { Connect-MgGraph @connectParams }
    $script:GraphConnectedByThisScript = $true
    Write-Ok 'Connected to Microsoft Graph.'
}

function Invoke-GraphGetPaged {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [hashtable]$Headers
    )

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    while (-not [string]::IsNullOrWhiteSpace($next)) {
        $params = @{
            Method      = 'GET'
            Uri         = $next
            ErrorAction = 'Stop'
        }
        if ($Headers) {
            $params['Headers'] = $Headers
        }
        if (Test-HasCmdletParameter -CommandName 'Invoke-MgGraphRequest' -ParameterName 'OutputType') {
            $params['OutputType'] = 'PSObject'
        }

        $resp = Invoke-WithRetry -Activity "GET $Uri" -ScriptBlock { Invoke-MgGraphRequest @params }
        foreach ($item in (ConvertTo-ObjectArray (Get-PropertyValue $resp 'value'))) {
            [void]$items.Add($item)
        }

        $next = Get-PropertyValue $resp '@odata.nextLink'
        if ([string]::IsNullOrWhiteSpace([string]$next)) {
            $next = $null
        }
    }
    return , $items.ToArray()
}

function Get-GraphSubscribedSkuMap {
    $skus = Invoke-GraphGetPaged -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus'
    $map = @{}
    foreach ($sku in (ConvertTo-ObjectArray $skus)) {
        $id = ConvertTo-NormalizedGuid (Get-PropertyValue $sku 'SkuId')
        $part = Get-PropertyValue $sku 'SkuPartNumber'
        if ($id -and $part) {
            $map[$id] = [string]$part
        }
    }
    return $map
}

function Get-SkuIdsByPartNumber {
    param(
        [hashtable]$SkuMap,
        [string[]]$PartNumbers
    )

    $wanted = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($part in @($PartNumbers)) {
        if ($part) { [void]$wanted.Add($part.Trim()) }
    }

    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $SkuMap.GetEnumerator()) {
        if ($wanted.Contains([string]$entry.Value)) {
            [void]$ids.Add([string]$entry.Key)
        }
    }
    return @($ids.ToArray())
}

function Get-GraphLicensedUsers {
    param([string[]]$Identity)

    $requested = ConvertTo-StringArray $Identity
    if ((Get-CollectionCount $requested) -gt 0) {
        $users = New-Object System.Collections.Generic.List[object]
        foreach ($id in $requested) {
            $encoded = [uri]::EscapeDataString($id)
            $uri = "https://graph.microsoft.com/v1.0/users/${encoded}?`$select=id,userPrincipalName,displayName,assignedLicenses,accountEnabled"
            $params = @{
                Method      = 'GET'
                Uri         = $uri
                ErrorAction = 'Stop'
            }
            if (Test-HasCmdletParameter -CommandName 'Invoke-MgGraphRequest' -ParameterName 'OutputType') {
                $params['OutputType'] = 'PSObject'
            }
            try {
                $user = Invoke-WithRetry -Activity "GET user $id" -ScriptBlock { Invoke-MgGraphRequest @params }
                [void]$users.Add($user)
            }
            catch {
                Write-Warn "Graph user '$id' was not found: $(Get-ExceptionMessageChain $_.Exception)"
            }
        }
        return , $users.ToArray()
    }

    $select = 'id,userPrincipalName,displayName,assignedLicenses,accountEnabled'
    $filterUri = "https://graph.microsoft.com/v1.0/users?`$count=true&`$filter=assignedLicenses/`$count ne 0&`$select=$select"
    try {
        return Invoke-GraphGetPaged -Uri $filterUri -Headers @{ ConsistencyLevel = 'eventual' }
    }
    catch {
        Write-Warn "Licensed-user Graph filter was not accepted ($($_.Exception.Message)). Falling back to a full user scan..."
        $fallback = "https://graph.microsoft.com/v1.0/users?`$select=$select"
        return Invoke-GraphGetPaged -Uri $fallback
    }
}

function Get-ExoMailboxesForQuota {
    param(
        [string[]]$Identity,
        [string[]]$RecipientTypeDetails
    )

    $propertySets = Get-MailboxQuotaPropertySets
    $base = @{
        PropertySets = $propertySets
        ErrorAction  = 'Stop'
    }
    if (Test-HasCmdletParameter -CommandName 'Get-EXOMailbox' -ParameterName 'Properties') {
        $base['Properties'] = @('ExternalDirectoryObjectId', 'MailboxPlan', 'UseDatabaseQuotaDefaults')
    }

    if ((Get-CollectionCount (ConvertTo-StringArray $Identity)) -gt 0) {
        $found = New-Object System.Collections.Generic.List[object]
        foreach ($id in (ConvertTo-StringArray $Identity)) {
            try {
                $mbx = Invoke-WithRetry -Activity "Get-EXOMailbox $id" -ScriptBlock {
                    Get-EXOMailbox -Identity $id @base
                }
                foreach ($item in (ConvertTo-ObjectArray $mbx)) {
                    [void]$found.Add($item)
                }
            }
            catch {
                $msg = Get-ExceptionMessageChain $_.Exception
                if (Test-IsMissingMailboxError -Message $msg) {
                    Write-Verbose "No mailbox for $id - skipping."
                    continue
                }
                Write-Warn "Get-EXOMailbox failed for ${id}: $msg"
            }
        }
        return , $found.ToArray()
    }

    $query = @{
        ResultSize   = 'Unlimited'
        PropertySets = $propertySets
        ErrorAction  = 'Stop'
    }
    if ($base.ContainsKey('Properties')) {
        $query['Properties'] = $base['Properties']
    }
    if (((Get-CollectionCount $RecipientTypeDetails) -gt 0) -and (Test-HasCmdletParameter -CommandName 'Get-EXOMailbox' -ParameterName 'RecipientTypeDetails')) {
        $query['RecipientTypeDetails'] = $RecipientTypeDetails
    }

    return , (ConvertTo-ObjectArray (Invoke-WithRetry -Activity 'Get-EXOMailbox (bulk)' -ScriptBlock { Get-EXOMailbox @query }))
}

function Get-MailboxUsedBytes {
    param($Mailbox)

    $candidates = ConvertTo-ObjectArray (@(
        Get-PropertyValue $Mailbox 'UserPrincipalName'
        Get-PropertyValue $Mailbox 'PrimarySmtpAddress'
        Get-PropertyValue $Mailbox 'ExternalDirectoryObjectId'
        Get-PropertyValue $Mailbox 'Identity'
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })

    $lastError = $null
    foreach ($id in $candidates) {
        try {
            $stats = Invoke-WithRetry -Activity "Get-EXOMailboxStatistics $id" -ScriptBlock {
                Get-EXOMailboxStatistics -Identity $id -ErrorAction Stop
            }
            return ConvertTo-Bytes (Get-PropertyValue $stats 'TotalItemSize')
        }
        catch {
            $lastError = Get-ExceptionMessageChain $_.Exception
            if (Test-IsMissingMailboxError -Message $lastError) {
                continue
            }
            Write-Verbose "Statistics failed for ${id}: $lastError"
        }
    }

    if ($lastError) {
        Write-Warn ("Could not read mailbox statistics for {0}: {1}" -f (Get-PropertyValue $Mailbox 'UserPrincipalName'), $lastError)
    }
    return $null
}

function Disconnect-QuotaSessions {
    param([switch]$SkipDisconnect)

    if ($SkipDisconnect) {
        return
    }

    if ($script:ExoConnectedByThisScript -and (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue)) {
        try {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        }
        catch {
            Write-Verbose "Disconnect-ExchangeOnline: $($_.Exception.Message)"
        }
    }

    if ($script:GraphConnectedByThisScript -and (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue)) {
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            Write-Verbose "Disconnect-MgGraph: $($_.Exception.Message)"
        }
    }
}

function Export-QuotaCsv {
    param(
        $InputObject,
        [string]$Path
    )

    $rows = @($InputObject)
    $encoding = Get-CsvEncodingName
    if ($rows.Count -eq 0) {
        # Keep a header-only file so callers always get a report path.
        [pscustomobject]@{ Notice = 'No matching mailboxes' } |
            Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding $encoding
        return
    }

    $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding $encoding
}

function Write-QuotaReportSet {
    param(
        [Parameter(Mandatory)] $Results,
        [Parameter(Mandatory)] [hashtable] $Policy,
        [Parameter(Mandatory)] [string] $OutputFolder,
        [int] $LicensedWithoutMailbox = 0,
        [switch] $Remediated,
        [switch] $SkipRemediateHint
    )

    if (-not (Test-Path -LiteralPath $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $fullPath      = Join-Path $OutputFolder "MailboxQuota-Full-$stamp.csv"
    $notCompliant  = Join-Path $OutputFolder ("MailboxQuota-Not{0}GB-$stamp.csv" -f $Policy.TargetStorageQuotaGB)
    $nearLimitPath = Join-Path $OutputFolder "MailboxQuota-NearLegacyLimit-$stamp.csv"
    $htmlPath      = Join-Path $OutputFolder "MailboxQuota-Summary-$stamp.html"

    $exportColumns = @(
        'UserPrincipalName', 'DisplayName', 'ExternalDirectoryObjectId', 'RecipientTypeDetails',
        'LicenseE3', 'LicenseE5', 'UseDatabaseQuotaDefaults',
        'ProhibitSendReceiveGB', 'ProhibitSendGB', 'IssueWarningGB',
        'TotalItemSizeGB', 'PercentOfCapUsed',
        'StorageCompliant', 'QuotasAligned', 'NearLegacyLimit',
        'Issues', 'NeedsRemediation'
    )
    $sorted = @($Results | Sort-Object UserPrincipalName | Select-Object $exportColumns)
    Export-QuotaCsv -InputObject $sorted -Path $fullPath
    Export-QuotaCsv -InputObject @($Results | Where-Object { -not $_.StorageCompliant } | Sort-Object UserPrincipalName | Select-Object $exportColumns) -Path $notCompliant
    Export-QuotaCsv -InputObject @($Results | Where-Object { $_.NearLegacyLimit } | Sort-Object PercentOfCapUsed -Descending | Select-Object $exportColumns) -Path $nearLimitPath

    $notCompliantCount = @($Results | Where-Object { -not $_.StorageCompliant }).Count
    $nearLimitCount    = @($Results | Where-Object { $_.NearLegacyLimit }).Count
    $total = @($Results).Count

    New-HtmlReport -Results $Results -Path $htmlPath -Summary @{
        Total                = $total
        Compliant            = $total - $notCompliantCount
        NotCompliant         = $notCompliantCount
        NearLimit            = $nearLimitCount
        TargetStorageQuotaGB = $Policy.TargetStorageQuotaGB
        LegacyQuotaGB        = $Policy.LegacyQuotaGB
        NearLimitPercent     = $Policy.NearLimitPercent
        Remediated           = [bool]$Remediated
    }

    Write-Host ''
    Write-Ok  ("Evaluated {0} licensed mailboxes." -f $total)
    if ($LicensedWithoutMailbox -gt 0) {
        Write-Warn ("Licensed E3/E5 users with no matching mailbox: {0}" -f $LicensedWithoutMailbox)
    }
    Write-Warn ("Not configured for {0} GB storage: {1}" -f $Policy.TargetStorageQuotaGB, $notCompliantCount)
    Write-Warn ("E3 mailboxes near {0} GB cap (>= {1}%): {2}" -f $Policy.LegacyQuotaGB, $Policy.NearLimitPercent, $nearLimitCount)
    Write-Host ''
    Write-Info 'Reports written to:'
    Write-Host "  $fullPath"
    Write-Host "  $notCompliant"
    Write-Host "  $nearLimitPath"
    Write-Host "  $htmlPath"

    if (-not $SkipRemediateHint) {
        Write-Host ''
        Write-Info 'Report-only run. Re-run with -Remediate (add -WhatIf first) to apply quota fixes.'
    }

    return [pscustomobject]@{
        FullCsv      = $fullPath
        NotCompliant = $notCompliant
        NearLimit    = $nearLimitPath
        Html         = $htmlPath
    }
}

#--------------------------------------------------------------------
# Self-test short-circuit
#--------------------------------------------------------------------

if ($SelfTest) {
    Invoke-MailboxQuotaSelfTest
    return
}

$policy = New-QuotaPolicy `
    -TargetStorageQuotaGB $TargetStorageQuotaGB `
    -ProhibitSendQuotaGB $ProhibitSendQuotaGB `
    -IssueWarningQuotaGB $IssueWarningQuotaGB `
    -LegacyQuotaGB $LegacyQuotaGB `
    -NearLimitPercent $NearLimitPercent `
    -QuotaToleranceMB $QuotaToleranceMB

if ($DemoReport) {
    Write-Info 'Writing a sample report (no tenant connection)...'
    $results = Get-MailboxQuotaDemoRows -Policy $policy
    Write-QuotaReportSet -Results $results -Policy $policy -OutputFolder $OutputFolder -SkipRemediateHint | Out-Null
    return
}
#--------------------------------------------------------------------
# Connect
#--------------------------------------------------------------------

Write-Info 'Checking required modules...'
Enable-Tls12
Enable-DefaultProxyCredentials
Import-RequiredModule -Name 'ExchangeOnlineManagement'
Import-RequiredModule -Name 'Microsoft.Graph.Authentication'

Write-Info 'Connecting to Exchange Online...'
Connect-QuotaExchangeOnline -UserPrincipalName $UserPrincipalName

Write-Info 'Connecting to Microsoft Graph...'
Connect-QuotaGraph -TenantId $TenantId -Scopes @('User.Read.All', 'Organization.Read.All')

$results = New-Object System.Collections.Generic.List[object]
$licensedWithoutMailbox = 0

try {
    Write-Info 'Resolving subscribed SKUs...'
    $skuMap = Get-GraphSubscribedSkuMap
    $e3SkuIds = Get-SkuIdsByPartNumber -SkuMap $skuMap -PartNumbers $E3SkuPartNumber
    $e5SkuIds = Get-SkuIdsByPartNumber -SkuMap $skuMap -PartNumbers $E5SkuPartNumber

    if ((Get-CollectionCount $e3SkuIds) -eq 0) {
        Write-Warn ("E3 SKU(s) '{0}' not found in this tenant." -f ($E3SkuPartNumber -join ', '))
    }
    if ((Get-CollectionCount $e5SkuIds) -eq 0) {
        Write-Warn ("E5 SKU(s) '{0}' not found in this tenant." -f ($E5SkuPartNumber -join ', '))
    }

    Write-Info 'Retrieving licensed users from Microsoft Graph (this can take a while)...'
    $allUsers = Get-GraphLicensedUsers -Identity $Identity
    $lookup = Get-LicenseLookupTables -Users $allUsers -SkuMap $skuMap -E3SkuIds $e3SkuIds -E5SkuIds $e5SkuIds
    Write-Ok ("Found {0} users with an E3 and/or E5 license." -f $lookup.UserCount)

    if ([int]$lookup.UserCount -eq 0) {
        Write-Warn 'No E3/E5 licensed users were found. Reports will be empty.'
    }
    else {
        Write-Info 'Retrieving Exchange Online mailboxes (Minimum + Quota property sets)...'
        $mailboxes = ConvertTo-ObjectArray (Get-ExoMailboxesForQuota -Identity $Identity -RecipientTypeDetails $RecipientTypeDetails)
        Write-Ok ("Retrieved {0} mailbox object(s)." -f (Get-CollectionCount $mailboxes))

        $matchedObjectIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $index = 0
        $total = Get-CollectionCount $mailboxes

        foreach ($mbx in $mailboxes) {
            $index++
            $status = [string](Get-PropertyValue $mbx 'UserPrincipalName')
            if ([string]::IsNullOrWhiteSpace($status)) {
                $status = [string](Get-PropertyValue $mbx 'PrimarySmtpAddress')
            }
            Write-Progress -Activity 'Evaluating mailboxes' -Status $status -PercentComplete (($index / [Math]::Max($total, 1)) * 100)

            $lic = Resolve-MailboxLicense -Mailbox $mbx -LicenseByObjectId $lookup.ByObjectId -LicenseByUpn $lookup.ByUpn
            if ($null -eq $lic) {
                continue
            }

            $objectId = ConvertTo-NormalizedGuid (Get-PropertyValue $mbx 'ExternalDirectoryObjectId')
            if ($objectId) {
                [void]$matchedObjectIds.Add($objectId)
            }

            $usedBytes = $null
            if (-not $SkipStatistics) {
                $usedBytes = Get-MailboxUsedBytes -Mailbox $mbx
            }

            $row = Get-MailboxQuotaEvaluation -Mailbox $mbx -UsedBytes $usedBytes -License $lic -Policy $policy
            [void]$results.Add($row)

            if ($Remediate -and $row.NeedsRemediation) {
                $target = "SR=$TargetStorageQuotaGB GB, Send=$ProhibitSendQuotaGB GB, Warn=$IssueWarningQuotaGB GB"
                $identityForSet = $row.UserPrincipalName
                if ([string]::IsNullOrWhiteSpace([string]$identityForSet)) {
                    $identityForSet = Get-PropertyValue $mbx 'PrimarySmtpAddress'
                }
                if ($PSCmdlet.ShouldProcess($identityForSet, "Set quotas to $target")) {
                    try {
                        Invoke-WithRetry -Activity "Set-Mailbox $identityForSet" -ScriptBlock {
                            Set-Mailbox -Identity $identityForSet `
                                -UseDatabaseQuotaDefaults $false `
                                -ProhibitSendReceiveQuota ("{0}GB" -f $TargetStorageQuotaGB) `
                                -ProhibitSendQuota        ("{0}GB" -f $ProhibitSendQuotaGB) `
                                -IssueWarningQuota        ("{0}GB" -f $IssueWarningQuotaGB) `
                                -ErrorAction Stop
                        }
                        Write-Ok "Remediated quotas for $identityForSet."
                    }
                    catch {
                        Write-Err "Failed to remediate ${identityForSet}: $(Get-ExceptionMessageChain $_.Exception)"
                    }
                }
            }
        }

        foreach ($key in @($lookup.ByObjectId.Keys)) {
            if (-not $matchedObjectIds.Contains($key)) {
                $licensedWithoutMailbox++
            }
        }
    }
}
finally {
    Write-Progress -Activity 'Evaluating mailboxes' -Completed
    Disconnect-QuotaSessions -SkipDisconnect:$SkipDisconnect
}

#--------------------------------------------------------------------
# Output
#--------------------------------------------------------------------

Write-QuotaReportSet `
    -Results $results `
    -Policy $policy `
    -OutputFolder $OutputFolder `
    -LicensedWithoutMailbox $licensedWithoutMailbox `
    -Remediated:$Remediate `
    -SkipRemediateHint:$Remediate | Out-Null

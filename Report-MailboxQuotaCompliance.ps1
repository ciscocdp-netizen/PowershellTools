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

    License data is read from Microsoft Graph. By default, mailbox quotas and
    usage come from the Graph mailbox usage report (one download for the whole
    tenant — typically minutes even at 30,000+ mailboxes). That report can lag
    24-48 hours. Pass -DataSource ExchangeLive for real-time Get-EXOMailbox
    values (much slower; tokens are refreshed before the one-hour expiry).

    F1 (frontline) licensed mailboxes are reported as a separate tier. They are
    expected to sit on the -F1QuotaGB cap (default 50 GB), are listed in their
    own CSV with usage, and are never remediated to 100 GB.

    Nothing is changed unless you pass -Remediate (which honors -WhatIf and
    -Confirm via ShouldProcess). Remediation uses Exchange Online only for the
    mailboxes that actually need a quota fix.

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
    - Get-EXOMailbox -ResultSize Unlimited with the full Quota property set
      drops on large tenants ("The underlying connection was closed"). Mailboxes
      are pulled in UPN-prefix shards, with reconnect + per-identity fallback.
    - Per-mailbox Get-EXOMailbox / Get-EXOMailboxStatistics on 16k-31k mailboxes
      runs for hours and outlives a one-hour auth token. Default data source is
      now the Graph mailbox usage report (quotas + size in one CSV). Exchange
      live queries remain available via -DataSource ExchangeLive, with token
      refresh and optional app-only certificate auth.
    - Evaluating ~30k report rows made ~100 small helper calls per mailbox
      (Get-PropertyValue / ConvertTo-Bytes / Format-GB ...). Windows PowerShell
      5.1 spends most of the run there. The usage-report path now resolves CSV
      columns once and parses numbers with TryParse, and the license lookup
      reads Graph objects directly. Every phase prints its elapsed time.
    - A missing Reports.Read.All grant silently fell back to the multi-hour
      ExchangeLive path. The script now stops with instructions unless
      -AllowExchangeLiveFallback is set.
    - F1 licensed users were ignored (or would have been flagged as "not
      100 GB"). They are tracked separately against -F1QuotaGB (50 GB).

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

.PARAMETER F1SkuPartNumber
    Graph SkuPartNumber values treated as frontline (F1) licenses. Default
    M365_F1 (Microsoft 365 F1), SPE_F1 (Microsoft 365 F3, formerly F1) and
    DESKLESSPACK (Office 365 F3). F1 mailboxes are reported against
    -F1QuotaGB instead of the 100 GB target and are never remediated.

.PARAMETER F1QuotaGB
    Expected ProhibitSendReceiveQuota for F1-licensed mailboxes. Default 50.
    F1 mailboxes at or above -NearLimitPercent of their cap are listed in the
    near-limit report and in a dedicated F1 CSV.

.PARAMETER AllowExchangeLiveFallback
    Switch. When the Graph mailbox usage report cannot be downloaded (usually a
    missing Reports.Read.All grant), fall back to the slow ExchangeLive path
    instead of stopping. Off by default so a permissions problem does not
    silently turn a five-minute run into a multi-hour one.

.PARAMETER HtmlMaxRows
    Maximum rows rendered per table in the HTML summary. Default 1000. The CSV
    files always contain every row.

.PARAMETER Identity
    Optional UPN / SMTP / alias list. When set, only those mailboxes are evaluated.

.PARAMETER RecipientTypeDetails
    Mailbox types included in the EXO query. Default UserMailbox.

.PARAMETER UserPrincipalName
    Optional UPN passed to Connect-ExchangeOnline (useful for modern auth / MFA).

.PARAMETER TenantId
    Optional tenant ID passed to Connect-MgGraph. Required for app-only auth.

.PARAMETER Organization
    Exchange Online organization domain (contoso.onmicrosoft.com). Required for
    app-only Connect-ExchangeOnline.

.PARAMETER AppId
    Optional Entra app (client) ID for app-only certificate authentication.
    Avoids interactive MFA and is the reliable way to run past one-hour token
    lifetimes. Grant the app User.Read.All, Organization.Read.All,
    Reports.Read.All, and (for -Remediate) Exchange.ManageAsApp plus the
    Exchange Administrator role.

.PARAMETER CertificateThumbprint
    Certificate thumbprint in the current-user or local-machine store, used with
    -AppId for app-only auth.

.PARAMETER DataSource
    GraphReports (default) uses GET /reports/getMailboxUsageDetail — one
    download with storage used and the three quota values. ExchangeLive queries
    Exchange Online in UPN shards (real-time, much slower).

.PARAMETER MailboxUsagePeriod
    Graph report window: D7, D30, D90, or D180. Default D7.

.PARAMETER TokenRefreshMinutes
    When using ExchangeLive, reconnect before this many minutes (default 45)
    so a one-hour delegated token does not expire mid-run.

.PARAMETER Remediate
    Switch. When present, the script sets non-compliant quotas to the target values.
    Supports -WhatIf and -Confirm.

.PARAMETER SkipStatistics
    Switch. ExchangeLive only. Do not call Get-EXOMailboxStatistics. GraphReports
    already includes storage used, so this switch has no effect there.

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
    .\Report-MailboxQuotaCompliance.ps1 -F1SkuPartNumber M365_F1, SPE_F1 -F1QuotaGB 50 -OutputFolder C:\Reports

.EXAMPLE
    .\Report-MailboxQuotaCompliance.ps1 -DataSource ExchangeLive -SkipStatistics

.EXAMPLE
    .\Report-MailboxQuotaCompliance.ps1 -AppId '<app-id>' -TenantId '<tenant-id>' -CertificateThumbprint '<thumbprint>' -Organization contoso.onmicrosoft.com

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
    [string[]]   $F1SkuPartNumber      = @('M365_F1', 'SPE_F1', 'DESKLESSPACK'),
    [ValidateRange(1, 1024)]
    [int]        $F1QuotaGB            = 50,
    [switch]     $AllowExchangeLiveFallback,
    [ValidateRange(50, 100000)]
    [int]        $HtmlMaxRows          = 1000,
    [string[]]   $Identity             = @(),
    [string[]]   $RecipientTypeDetails = @('UserMailbox'),
    [string]     $UserPrincipalName,
    [string]     $TenantId,
    [string]     $Organization,
    [string]     $AppId,
    [string]     $CertificateThumbprint,
    [ValidateSet('GraphReports', 'ExchangeLive')]
    [string]     $DataSource           = 'GraphReports',
    [ValidateSet('D7', 'D30', 'D90', 'D180')]
    [string]     $MailboxUsagePeriod   = 'D7',
    [ValidateRange(10, 90)]
    [int]        $TokenRefreshMinutes  = 45,
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
$script:ExoConnectParams           = @{
    ShowBanner  = $false
    ErrorAction = 'Stop'
}
$script:GraphConnectParams         = $null
$script:LastTokenRefresh           = [datetime]::MinValue
$script:TokenRefreshMinutes        = 45

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
        $candidateName = [string]$candidate.Name
        if ($candidateName.Length -gt 0 -and [int][char]$candidateName[0] -eq 0xFEFF) {
            $candidateName = $candidateName.Substring(1)
        }
        if ([string]::Equals($candidateName, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
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

    return [bool]($Message -match 'throttl|429|503|timeout|timed out|temporarily|too many requests|server cannot service|Try again|busy|rate limit|underlying connection was closed|unexpected error occurred on a receive|connection was closed|forcibly closed|The request was aborted|Unable to read data from the transport|SendFailure|KeepAliveFailure|existing connection|receive')
}

function Test-IsTransportError {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    return [bool]($Message -match 'underlying connection was closed|unexpected error occurred on a receive|connection was closed|forcibly closed|The request was aborted|Unable to read data from the transport|SendFailure|KeepAliveFailure|SSL/TLS|secure channel')
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
            if ((Test-IsTransportError -Message $msg) -and ($Activity -match 'Get-EXOMailbox|Set-Mailbox|Get-EXOMailboxStatistics')) {
                try {
                    Reset-QuotaExchangeOnline
                }
                catch {
                    Write-Warn ("Reconnect after transport error failed: {0}" -f (Get-ExceptionMessageChain $_.Exception))
                }
            }
            $delay = [Math]::Min(60, [int][Math]::Pow(2, $attempt) + 3)
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

function Get-ExoMailboxSelectParams {
    $params = @{
        ErrorAction  = 'Stop'
        PropertySets = @('Minimum')
    }
    if (Test-HasCmdletParameter -CommandName 'Get-EXOMailbox' -ParameterName 'Properties') {
        # Prefer named quota properties over PropertySets=Quota. The full Quota
        # set is a large REST payload and often drops on tenants with 10k+ mailboxes.
        $params['Properties'] = @(
            'ProhibitSendReceiveQuota',
            'ProhibitSendQuota',
            'IssueWarningQuota',
            'UseDatabaseQuotaDefaults',
            'ExternalDirectoryObjectId',
            'MailboxPlan'
        )
    }
    else {
        $params['PropertySets'] = @('Minimum', 'Quota')
    }
    return $params
}

function Get-UpnPrefixList {
    param(
        $Upns,
        [int]$Length = 1,
        [string]$StartsWith = ''
    )

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($upn in (ConvertTo-ObjectArray $Upns)) {
        $text = [string]$upn
        if ([string]::IsNullOrWhiteSpace($text)) {
            continue
        }
        $local = ($text.Split('@')[0])
        if ($local.Length -lt 1) {
            continue
        }
        if ($StartsWith -and -not $local.StartsWith($StartsWith, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        $len = [Math]::Min($Length, $local.Length)
        if ($len -lt 1) {
            continue
        }
        [void]$set.Add($local.Substring(0, $len).ToLowerInvariant())
    }
    return , @($set)
}

function ConvertTo-ExoLikeFilter {
    param([Parameter(Mandatory)][string]$Prefix)

    $escaped = $Prefix.Replace("'", "''").Replace('*', '').Replace('?', '')
    if ([string]::IsNullOrWhiteSpace($escaped)) {
        return $null
    }
    return "UserPrincipalName -like '$escaped*'"
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
        [int]$QuotaToleranceMB,
        [int]$F1QuotaGB = 50
    )

    if ($IssueWarningQuotaGB -ge $ProhibitSendQuotaGB -or $ProhibitSendQuotaGB -ge $TargetStorageQuotaGB) {
        throw "Quotas must satisfy IssueWarning < ProhibitSend < ProhibitSendReceive (got $IssueWarningQuotaGB / $ProhibitSendQuotaGB / $TargetStorageQuotaGB)."
    }

    return @{
        TargetStorageQuotaGB = $TargetStorageQuotaGB
        ProhibitSendQuotaGB  = $ProhibitSendQuotaGB
        IssueWarningQuotaGB  = $IssueWarningQuotaGB
        LegacyQuotaGB        = $LegacyQuotaGB
        F1QuotaGB            = $F1QuotaGB
        NearLimitPercent     = $NearLimitPercent
        TargetStorageBytes   = [double]$TargetStorageQuotaGB * 1GB
        TargetSendBytes      = [double]$ProhibitSendQuotaGB * 1GB
        TargetWarnBytes      = [double]$IssueWarningQuotaGB * 1GB
        LegacyBytes          = [double]$LegacyQuotaGB * 1GB
        F1Bytes              = [double]$F1QuotaGB * 1GB
        NearLimitBytes       = ([double]$LegacyQuotaGB * 1GB) * ($NearLimitPercent / 100.0)
        NearLimitFraction    = $NearLimitPercent / 100.0
        ToleranceBytes       = [double]$QuotaToleranceMB * 1MB
    }
}

function Get-LicenseFlag {
    param($License, [string]$Name)

    if ($null -eq $License) {
        return $false
    }
    if ($License -is [System.Collections.IDictionary]) {
        if ($License.Contains($Name)) { return [bool]$License[$Name] }
        return $false
    }
    $prop = $License.PSObject.Properties[$Name]
    if ($null -eq $prop -or $null -eq $prop.Value) {
        return $false
    }
    return [bool]$prop.Value
}

# Core compliance logic. Takes already-parsed byte values so the hot loops
# (30k+ rows) do not pay for ConvertTo-Bytes / Format-GB / Test-QuotaEquals
# calls per column. Get-MailboxQuotaEvaluation wraps this for mailbox objects.
function New-MailboxQuotaResult {
    param(
        $UserPrincipalName,
        $DisplayName,
        $ExternalDirectoryObjectId,
        $RecipientTypeDetails,
        [Parameter(Mandatory)] $License,
        $SrBytes,
        $SendBytes,
        $WarnBytes,
        $UsedBytes,
        [bool]$UseDefaults,
        [Parameter(Mandatory)] [hashtable]$Policy
    )

    if ($License -is [System.Collections.IDictionary]) {
        $hasE3 = Get-LicenseFlag $License 'HasE3'
        $hasE5 = Get-LicenseFlag $License 'HasE5'
        $hasF1 = Get-LicenseFlag $License 'HasF1'
    }
    else {
        $lp = $License.PSObject.Properties
        $p = $lp['HasE3']; $hasE3 = ($null -ne $p -and $null -ne $p.Value -and [bool]$p.Value)
        $p = $lp['HasE5']; $hasE5 = ($null -ne $p -and $null -ne $p.Value -and [bool]$p.Value)
        $p = $lp['HasF1']; $hasF1 = ($null -ne $p -and $null -ne $p.Value -and [bool]$p.Value)
    }
    $isEnterprise = $hasE3 -or $hasE5
    $tier = if ($hasE5) { 'E5' } elseif ($hasE3) { 'E3' } elseif ($hasF1) { 'F1' } else { 'Other' }

    $tol = [double]$Policy.ToleranceBytes
    $srKnown   = ($null -ne $SrBytes)   -and -not [double]::IsInfinity([double]$SrBytes)
    $sendKnown = ($null -ne $SendBytes) -and -not [double]::IsInfinity([double]$SendBytes)
    $warnKnown = ($null -ne $WarnBytes) -and -not [double]::IsInfinity([double]$WarnBytes)

    $srText   = if ($null -eq $SrBytes)   { 'Unknown' } elseif ([double]::IsInfinity([double]$SrBytes))   { 'Unlimited' } else { '{0:N2} GB' -f ([double]$SrBytes / 1GB) }
    $sendText = if ($null -eq $SendBytes) { 'Unknown' } elseif ([double]::IsInfinity([double]$SendBytes)) { 'Unlimited' } else { '{0:N2} GB' -f ([double]$SendBytes / 1GB) }
    $warnText = if ($null -eq $WarnBytes) { 'Unknown' } elseif ([double]::IsInfinity([double]$WarnBytes)) { 'Unlimited' } else { '{0:N2} GB' -f ([double]$WarnBytes / 1GB) }
    $usedText = if ($null -eq $UsedBytes) { 'Unknown' } elseif ([double]::IsInfinity([double]$UsedBytes)) { 'Unlimited' } else { '{0:N2} GB' -f ([double]$UsedBytes / 1GB) }

    $issues = [System.Collections.Generic.List[string]]::new()
    $nearLimit = $false

    if ($isEnterprise -or -not $hasF1) {
        $expectedCapGB = [int]$Policy.TargetStorageQuotaGB
        $storageCompliant = $srKnown   -and ([Math]::Abs([double]$SrBytes   - [double]$Policy.TargetStorageBytes) -le $tol)
        $sendCompliant    = $sendKnown -and ([Math]::Abs([double]$SendBytes - [double]$Policy.TargetSendBytes)    -le $tol)
        $warnCompliant    = $warnKnown -and ([Math]::Abs([double]$WarnBytes - [double]$Policy.TargetWarnBytes)    -le $tol)

        if (-not $storageCompliant) { [void]$issues.Add("ProhibitSendReceiveQuota is $srText, expected $($Policy.TargetStorageQuotaGB) GB") }
        if (-not $sendCompliant)    { [void]$issues.Add("ProhibitSendQuota is $sendText, expected $($Policy.ProhibitSendQuotaGB) GB") }
        if (-not $warnCompliant)    { [void]$issues.Add("IssueWarningQuota is $warnText, expected $($Policy.IssueWarningQuotaGB) GB") }
        if ($UseDefaults -and $issues.Count -gt 0) {
            [void]$issues.Add('UseDatabaseQuotaDefaults is True (custom quota values may be ignored until it is set to False)')
        }

        if ($hasE3 -and $srKnown -and ($null -ne $UsedBytes) -and
            ([Math]::Abs([double]$SrBytes - [double]$Policy.LegacyBytes) -le $tol) -and
            ([double]$UsedBytes -ge [double]$Policy.NearLimitBytes)) {
            $nearLimit = $true
            [void]$issues.Add("E3 mailbox on $($Policy.LegacyQuotaGB) GB cap at $usedText (>= $($Policy.NearLimitPercent)%)")
        }

        $quotasAligned = $storageCompliant -and $sendCompliant -and $warnCompliant
        $needsFix = -not $quotasAligned
    }
    else {
        # F1 only: expected to sit on the frontline cap; never pushed to 100 GB.
        $expectedCapGB = [int]$Policy.F1QuotaGB
        $storageCompliant = $srKnown -and ([Math]::Abs([double]$SrBytes - [double]$Policy.F1Bytes) -le $tol)
        $sendCompliant = $true
        $warnCompliant = $true
        if (-not $storageCompliant) {
            [void]$issues.Add("F1 ProhibitSendReceiveQuota is $srText, expected $($Policy.F1QuotaGB) GB")
        }
        if ($srKnown -and ($null -ne $UsedBytes) -and [double]$SrBytes -gt 0 -and
            ([double]$UsedBytes -ge ([double]$SrBytes * [double]$Policy.NearLimitFraction))) {
            $nearLimit = $true
            [void]$issues.Add("F1 mailbox at $usedText of $srText cap (>= $($Policy.NearLimitPercent)%)")
        }
        $quotasAligned = $storageCompliant
        $needsFix = $false
    }

    $percentUsed = $null
    if ($null -ne $UsedBytes -and $srKnown -and [double]$SrBytes -gt 0) {
        $percentUsed = [Math]::Round(([double]$UsedBytes / [double]$SrBytes) * 100, 1)
    }

    $upn = $UserPrincipalName
    if ([string]::IsNullOrWhiteSpace([string]$upn)) {
        $upn = Get-PropertyValue $License 'UserPrincipalName'
    }
    $name = $DisplayName
    if ([string]::IsNullOrWhiteSpace([string]$name)) {
        $name = Get-PropertyValue $License 'DisplayName'
    }

    return [pscustomobject]@{
        UserPrincipalName         = $upn
        DisplayName               = $name
        ExternalDirectoryObjectId = $ExternalDirectoryObjectId
        RecipientTypeDetails      = $RecipientTypeDetails
        LicenseTier               = $tier
        LicenseE3                 = $hasE3
        LicenseE5                 = $hasE5
        LicenseF1                 = $hasF1
        ExpectedCapGB             = $expectedCapGB
        UseDatabaseQuotaDefaults  = $UseDefaults
        ProhibitSendReceiveGB     = $srText
        ProhibitSendGB            = $sendText
        IssueWarningGB            = $warnText
        TotalItemSizeGB           = $usedText
        PercentOfCapUsed          = $percentUsed
        StorageCompliant          = $storageCompliant
        QuotasAligned             = $quotasAligned
        NearLegacyLimit           = $nearLimit
        Issues                    = ($issues -join '; ')
        NeedsRemediation          = $needsFix
        StorageBytes              = $SrBytes
        SendBytes                 = $SendBytes
        WarnBytes                 = $WarnBytes
        UsedBytes                 = $UsedBytes
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

    return New-MailboxQuotaResult `
        -UserPrincipalName (Get-PropertyValue $Mailbox 'UserPrincipalName') `
        -DisplayName (Get-PropertyValue $Mailbox 'DisplayName') `
        -ExternalDirectoryObjectId (Get-PropertyValue $Mailbox 'ExternalDirectoryObjectId') `
        -RecipientTypeDetails (Get-PropertyValue $Mailbox 'RecipientTypeDetails') `
        -License $License `
        -SrBytes (ConvertTo-Bytes (Get-PropertyValue $Mailbox 'ProhibitSendReceiveQuota')) `
        -SendBytes (ConvertTo-Bytes (Get-PropertyValue $Mailbox 'ProhibitSendQuota')) `
        -WarnBytes (ConvertTo-Bytes (Get-PropertyValue $Mailbox 'IssueWarningQuota')) `
        -UsedBytes $UsedBytes `
        -UseDefaults (ConvertTo-Bool (Get-PropertyValue $Mailbox 'UseDatabaseQuotaDefaults')) `
        -Policy $Policy
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
        [Parameter(Mandatory)] [string] $Path,
        [int] $MaxRows = 1000
    )

    $all = ConvertTo-ObjectArray $Results
    $notCompliantList = New-Object System.Collections.Generic.List[object]
    $nearList = New-Object System.Collections.Generic.List[object]
    $f1NearList = New-Object System.Collections.Generic.List[object]
    foreach ($r in $all) {
        $isF1Only = (Get-LicenseFlag $r 'LicenseF1') -and -not ((Get-LicenseFlag $r 'LicenseE3') -or (Get-LicenseFlag $r 'LicenseE5'))
        if (-not $r.StorageCompliant -and -not $isF1Only) { [void]$notCompliantList.Add($r) }
        if ($r.NearLegacyLimit) {
            if ($isF1Only) { [void]$f1NearList.Add($r) } else { [void]$nearList.Add($r) }
        }
    }
    $notCompliant = @($notCompliantList | Sort-Object UserPrincipalName)
    $nearLimit    = @($nearList | Sort-Object PercentOfCapUsed -Descending)
    $f1Near       = @($f1NearList | Sort-Object PercentOfCapUsed -Descending)

    function Build-Table {
        param($Rows, [string[]]$Columns, [hashtable]$Headers, [string]$EmptyMessage, [int]$Limit)

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
        $shown = 0
        foreach ($row in $rowList) {
            if ($Limit -gt 0 -and $shown -ge $Limit) { break }
            $shown++
            $props = $row.PSObject.Properties
            $cells = foreach ($col in $Columns) {
                $prop = $props[$col]
                $value = if ($null -ne $prop) { $prop.Value } else { $null }
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
        $note = ''
        if ($shown -lt $rowList.Count) {
            $note = "<p class='empty'>Showing first $shown of $($rowList.Count) rows. The CSV files contain every row.</p>"
        }
        return "<table><thead><tr>$($head -join '')</tr></thead><tbody>$($bodyRows -join '')</tbody></table>$note"
    }

    $columnHeaders = @{
        UserPrincipalName     = 'UPN'
        DisplayName           = 'Name'
        LicenseTier           = 'Tier'
        LicenseE3             = 'E3'
        LicenseE5             = 'E5'
        LicenseF1             = 'F1'
        ProhibitSendReceiveGB = 'Cap'
        ProhibitSendGB        = 'Send'
        IssueWarningGB        = 'Warn'
        TotalItemSizeGB       = 'Used'
        PercentOfCapUsed      = '% cap'
        Issues                = 'Issues'
    }
    $detailColumns = @(
        'UserPrincipalName', 'DisplayName', 'LicenseTier',
        'ProhibitSendReceiveGB', 'ProhibitSendGB', 'IssueWarningGB',
        'TotalItemSizeGB', 'PercentOfCapUsed', 'Issues'
    )
    $nearColumns = @(
        'UserPrincipalName', 'DisplayName', 'LicenseTier', 'ProhibitSendReceiveGB',
        'TotalItemSizeGB', 'PercentOfCapUsed'
    )

    $f1Total     = [int](Get-PropertyValue $Summary 'F1Total' 0)
    $f1NearCount = [int](Get-PropertyValue $Summary 'F1NearLimit' 0)
    $f1QuotaGB   = [int](Get-PropertyValue $Summary 'F1QuotaGB' 50)
    $enterpriseNotCompliant = Get-PropertyValue $Summary 'EnterpriseNotCompliant' $null
    if ($null -eq $enterpriseNotCompliant) { $enterpriseNotCompliant = $Summary.NotCompliant }

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
  <p>Generated $(ConvertTo-HtmlEncoded $generated) &middot; Mode: $(ConvertTo-HtmlEncoded $mode) &middot; Source: $(ConvertTo-HtmlEncoded ([string](Get-PropertyValue $Summary 'DataSource'))) &middot; Target storage cap: $($Summary.TargetStorageQuotaGB) GB</p>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="value">$($Summary.Total)</div><div class="label">Licensed mailboxes</div></div>
    <div class="card alert"><div class="value">$enterpriseNotCompliant</div><div class="label">E3/E5 not $($Summary.TargetStorageQuotaGB) GB storage</div></div>
    <div class="card warn"><div class="value">$($nearLimit.Count)</div><div class="label">E3 near $($Summary.LegacyQuotaGB) GB cap</div></div>
    <div class="card"><div class="value">$f1Total</div><div class="label">F1 mailboxes ($f1QuotaGB GB cap)</div></div>
    <div class="card warn"><div class="value">$f1NearCount</div><div class="label">F1 near cap</div></div>
    <div class="card ok"><div class="value">$($Summary.Compliant)</div><div class="label">Storage compliant</div></div>
  </div>

  <section>
    <h2>E3/E5 mailboxes not configured for $($Summary.TargetStorageQuotaGB) GB storage</h2>
    <div class="scroll">$(Build-Table -Rows $notCompliant -Columns $detailColumns -Headers $columnHeaders -Limit $MaxRows -EmptyMessage 'All E3/E5 mailboxes meet the storage target.')</div>
  </section>

  <section>
    <h2>E3 mailboxes approaching the $($Summary.LegacyQuotaGB) GB limit (&ge; $($Summary.NearLimitPercent)%)</h2>
    <div class="scroll">$(Build-Table -Rows $nearLimit -Columns $nearColumns -Headers $columnHeaders -Limit $MaxRows -EmptyMessage 'No E3 mailboxes are near the legacy cap.')</div>
  </section>

  <section>
    <h2>F1 mailboxes approaching their $f1QuotaGB GB cap (&ge; $($Summary.NearLimitPercent)%)</h2>
    <p class='empty'>F1 licenses are limited to $f1QuotaGB GB and are never remediated to $($Summary.TargetStorageQuotaGB) GB. All $f1Total F1 mailboxes are listed in the F1 CSV.</p>
    <div class="scroll">$(Build-Table -Rows $f1Near -Columns $nearColumns -Headers $columnHeaders -Limit $MaxRows -EmptyMessage 'No F1 mailboxes are near their cap.')</div>
  </section>
</main>
<footer>Generated by Report-MailboxQuotaCompliance.ps1</footer>
</body>
</html>
"@

    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $html, $utf8NoBom)
}

# Reads one member from a Graph object (hashtable or PSObject) without going
# through Get-PropertyValue. Used only inside the 30k-user hot loop.
function Get-GraphMemberFast {
    param($Object, [string]$Name)

    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        foreach ($key in $Object.Keys) {
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $Object[$key]
            }
        }
        return $null
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -ne $prop) { return $prop.Value }
    return $null
}

function Get-LicenseLookupTables {
    param(
        $Users,
        [hashtable]$SkuMap,
        [string[]]$E3SkuIds,
        [string[]]$E5SkuIds,
        [string[]]$F1SkuIds = @()
    )

    $byObjectId = @{}
    $byUpn      = @{}
    $e3Set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $e5Set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $f1Set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($E3SkuIds)) { if ($id) { [void]$e3Set.Add($id) } }
    foreach ($id in @($E5SkuIds)) { if ($id) { [void]$e5Set.Add($id) } }
    foreach ($id in @($F1SkuIds)) { if ($id) { [void]$f1Set.Add($id) } }

    $e3Count = 0
    $e5Count = 0
    $f1Count = 0

    foreach ($user in (ConvertTo-ObjectArray $Users)) {
        if ($null -eq $user) { continue }

        # Direct member access (hashtable from Invoke-MgGraphRequest, or
        # PSObject); Get-GraphMemberFast only as a fallback for odd casing.
        $isDict = $user -is [System.Collections.IDictionary]
        if ($isDict) {
            $assigned = $user['assignedLicenses']
            if ($null -eq $assigned) { $assigned = Get-GraphMemberFast $user 'assignedLicenses' }
        }
        else {
            $up = $user.PSObject.Properties
            $p = $up['assignedLicenses']
            $assigned = if ($null -ne $p) { $p.Value } else { $null }
        }
        if ($null -eq $assigned) { continue }

        # A single license arrives as one dictionary/object, not a list.
        if ($assigned -is [System.Collections.IDictionary] -or $assigned -is [string] -or $assigned -isnot [System.Collections.IEnumerable]) {
            $assigned = @($assigned)
        }

        $hasE3 = $false
        $hasE5 = $false
        $hasF1 = $false
        foreach ($lic in $assigned) {
            if ($null -eq $lic) { continue }
            if ($lic -is [System.Collections.IDictionary]) {
                $skuRaw = $lic['skuId']
                if ($null -eq $skuRaw) { $skuRaw = Get-GraphMemberFast $lic 'skuId' }
            }
            else {
                $p = $lic.PSObject.Properties['skuId']
                $skuRaw = if ($null -ne $p) { $p.Value } else { $null }
            }
            if ($null -eq $skuRaw) { continue }
            $skuId = ([string]$skuRaw).Trim().Trim('{', '}')
            if ($skuId.Length -eq 0) { continue }
            if ($e3Set.Contains($skuId)) { $hasE3 = $true }
            elseif ($e5Set.Contains($skuId)) { $hasE5 = $true }
            elseif ($f1Set.Contains($skuId)) { $hasF1 = $true }
        }

        if (-not ($hasE3 -or $hasE5 -or $hasF1)) {
            continue
        }
        if ($hasE3) { $e3Count++ }
        if ($hasE5) { $e5Count++ }
        if ($hasF1) { $f1Count++ }

        if ($isDict) {
            $upn = $user['userPrincipalName'];  if ($null -eq $upn) { $upn = Get-GraphMemberFast $user 'userPrincipalName' }
            $graphId = $user['id'];             if ($null -eq $graphId) { $graphId = Get-GraphMemberFast $user 'id' }
            $display = $user['displayName'];    if ($null -eq $display) { $display = Get-GraphMemberFast $user 'displayName' }
            $enabledRaw = $user['accountEnabled']; if ($null -eq $enabledRaw) { $enabledRaw = Get-GraphMemberFast $user 'accountEnabled' }
        }
        else {
            $p = $up['userPrincipalName']; $upn = if ($null -ne $p) { $p.Value } else { $null }
            $p = $up['id'];                $graphId = if ($null -ne $p) { $p.Value } else { $null }
            $p = $up['displayName'];       $display = if ($null -ne $p) { $p.Value } else { $null }
            $p = $up['accountEnabled'];    $enabledRaw = if ($null -ne $p) { $p.Value } else { $null }
        }
        $enabled = if ($enabledRaw -is [bool]) { $enabledRaw } elseif ($null -eq $enabledRaw) { $false } else { ConvertTo-Bool $enabledRaw }

        $info = [pscustomobject]@{
            GraphId            = $graphId
            UserPrincipalName  = $upn
            DisplayName        = $display
            AccountEnabled     = $enabled
            HasE3              = $hasE3
            HasE5              = $hasE5
            HasF1              = $hasF1
        }

        if ($null -ne $graphId) {
            $objectId = ([string]$graphId).Trim().Trim('{', '}').ToLowerInvariant()
            if ($objectId.Length -gt 0) {
                $byObjectId[$objectId] = $info
            }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$upn)) {
            $byUpn[([string]$upn).Trim().ToLowerInvariant()] = $info
        }
    }

    return @{
        ByObjectId = $byObjectId
        ByUpn      = $byUpn
        UserCount  = [int]$byObjectId.Count
        E3Count    = $e3Count
        E5Count    = $e5Count
        F1Count    = $f1Count
        SkuMap     = $SkuMap
    }
}

# Resolves the actual CSV header names once (BOM / spelling variants) so the
# per-row loop uses direct property lookups.
function Resolve-UsageReportColumns {
    param($FirstRow)

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($prop in @($FirstRow.PSObject.Properties)) {
        [void]$names.Add([string]$prop.Name)
    }

    $wanted = @{
        Upn       = @('User Principal Name', 'UserPrincipalName', 'UPN')
        Display   = @('Display Name', 'DisplayName')
        Deleted   = @('Is Deleted', 'IsDeleted')
        Used      = @('Storage Used (Byte)', 'Storage Used (Bytes)', 'StorageUsed')
        Sr        = @('Prohibit Send/Receive Quota (Byte)', 'Prohibit Send/Receive Quota (Bytes)', 'ProhibitSendReceiveQuota')
        Send      = @('Prohibit Send Quota (Byte)', 'Prohibit Send Quota (Bytes)', 'ProhibitSendQuota')
        Warn      = @('Issue Warning Quota (Byte)', 'Issue Warning Quota (Bytes)', 'IssueWarningQuota')
        Recipient = @('Recipient Type', 'RecipientType', 'RecipientTypeDetails')
    }

    $map = @{}
    foreach ($key in $wanted.Keys) {
        $map[$key] = $null
        foreach ($candidate in $wanted[$key]) {
            foreach ($actual in $names) {
                $clean = $actual
                if ($clean.Length -gt 0 -and [int][char]$clean[0] -eq 0xFEFF) { $clean = $clean.Substring(1) }
                if ([string]::Equals($clean, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $map[$key] = $actual
                    break
                }
            }
            if ($null -ne $map[$key]) { break }
        }
    }

    if ($null -eq $map['Upn']) {
        throw ("Graph mailbox usage CSV has no User Principal Name column. Columns: {0}" -f [string]::Join(', ', $names.ToArray()))
    }
    return $map
}

# Evaluates every usage-report row for a licensed user. One pass, minimal
# helper calls; adds result rows to $Results and matched UPNs to $MatchedUpns.
function Invoke-UsageReportEvaluation {
    param(
        $Rows,
        [Parameter(Mandatory)] [hashtable]$Lookup,
        [Parameter(Mandatory)] [hashtable]$Policy,
        [AllowEmptyCollection()] [System.Collections.Generic.List[object]]$Results,
        [AllowEmptyCollection()] [System.Collections.Generic.HashSet[string]]$MatchedUpns,
        [int]$ProgressEvery = 1000
    )

    if ($null -eq $Results) { throw 'Invoke-UsageReportEvaluation requires -Results.' }
    if ($null -eq $MatchedUpns) { throw 'Invoke-UsageReportEvaluation requires -MatchedUpns.' }

    $rowList = ConvertTo-ObjectArray $Rows
    $total = $rowList.Length
    if ($total -eq 0) { return 0 }

    $cols = Resolve-UsageReportColumns -FirstRow $rowList[0]
    $upnCol = $cols['Upn']; $nameCol = $cols['Display']; $delCol = $cols['Deleted']
    $usedCol = $cols['Used']; $srCol = $cols['Sr']; $sendCol = $cols['Send']; $warnCol = $cols['Warn']; $rcptCol = $cols['Recipient']
    $byUpn = $Lookup.ByUpn

    $styles  = [System.Globalization.NumberStyles]::Float
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $num = [double]0
    $added = 0
    $index = 0

    foreach ($row in $rowList) {
        $index++
        if (($index % $ProgressEvery) -eq 0) {
            Write-Progress -Activity 'Evaluating mailbox usage report' -Status "$index of $total" -PercentComplete (($index / $total) * 100)
        }

        $props = $row.PSObject.Properties
        $upnProp = $props[$upnCol]
        if ($null -eq $upnProp) { continue }
        $upn = [string]$upnProp.Value
        if ([string]::IsNullOrWhiteSpace($upn)) { continue }
        $upn = $upn.Trim()

        if ($null -ne $delCol) {
            $delProp = $props[$delCol]
            if ($null -ne $delProp -and ([string]$delProp.Value) -match '^(true|1|yes)$') { continue }
        }

        $lic = $byUpn[$upn.ToLowerInvariant()]
        if ($null -eq $lic) { continue }
        [void]$MatchedUpns.Add($upn)

        $sr = $null
        if ($null -ne $srCol) {
            $text = [string]$props[$srCol].Value
            if ($text.Length -gt 0) {
                if ([double]::TryParse($text, $styles, $culture, [ref]$num)) { $sr = $num } else { $sr = ConvertTo-Bytes $text }
            }
        }
        $send = $null
        if ($null -ne $sendCol) {
            $text = [string]$props[$sendCol].Value
            if ($text.Length -gt 0) {
                if ([double]::TryParse($text, $styles, $culture, [ref]$num)) { $send = $num } else { $send = ConvertTo-Bytes $text }
            }
        }
        $warn = $null
        if ($null -ne $warnCol) {
            $text = [string]$props[$warnCol].Value
            if ($text.Length -gt 0) {
                if ([double]::TryParse($text, $styles, $culture, [ref]$num)) { $warn = $num } else { $warn = ConvertTo-Bytes $text }
            }
        }
        $used = $null
        if ($null -ne $usedCol) {
            $text = [string]$props[$usedCol].Value
            if ($text.Length -gt 0) {
                if ([double]::TryParse($text, $styles, $culture, [ref]$num)) { $used = $num } else { $used = ConvertTo-Bytes $text }
            }
        }

        $name = if ($null -ne $nameCol) { $props[$nameCol].Value } else { $null }
        $rcpt = if ($null -ne $rcptCol) { $props[$rcptCol].Value } else { 'UserMailbox' }

        $result = New-MailboxQuotaResult `
            -UserPrincipalName $upn `
            -DisplayName $name `
            -ExternalDirectoryObjectId $lic.GraphId `
            -RecipientTypeDetails $rcpt `
            -License $lic `
            -SrBytes $sr -SendBytes $send -WarnBytes $warn -UsedBytes $used `
            -UseDefaults $false `
            -Policy $Policy
        [void]$Results.Add($result)
        $added++
    }

    Write-Progress -Activity 'Evaluating mailbox usage report' -Completed
    return $added
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

    $policy = New-QuotaPolicy -TargetStorageQuotaGB 100 -ProhibitSendQuotaGB 99 -IssueWarningQuotaGB 98 -LegacyQuotaGB 50 -NearLimitPercent 90 -QuotaToleranceMB 2 -F1QuotaGB 50

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

    Assert-Equal (Test-IsTransientError 'The underlying connection was closed: An unexpected error occurred on a receive.') $true 'EXO receive drop is transient'
    Assert-Equal (Test-IsTransportError 'The underlying connection was closed: An unexpected error occurred on a receive.') $true 'EXO receive drop is transport'
    $prefixList = Get-UpnPrefixList -Upns @('Alex@contoso.com', 'amy@contoso.com', 'bob@contoso.com')
    Assert-Equal ((Get-CollectionCount $prefixList) -ge 2) $true 'UPN prefixes include a and b'
    Assert-Equal (ConvertTo-ExoLikeFilter -Prefix 'al') "UserPrincipalName -like 'al*'" 'EXO like filter'

    $skuUri = New-GraphLicensedUsersUri -SkuIds @('6fd2c87f-b296-42f0-b197-1e91e994b900', 'c7df2760-2c81-4ef7-b578-5b5392b571df')
    Assert-Equal ($skuUri -match 'assignedLicenses%2Fany') $true 'licensed-user URI uses SKU any() filter'
    Assert-Equal ($skuUri -match '\$top=999') $true 'licensed-user URI pages 999'
    $anyUri = New-GraphLicensedUsersUri -AnyLicense
    Assert-Equal ($anyUri -match 'assignedLicenses') $true 'any-license URI still filters assigned licenses'
    Assert-Equal ($anyUri -match '\$top=999') $true 'any-license URI pages 999'
    $skuListUri = 'https://graph.microsoft.com/v1.0/subscribedSkus'
    Assert-Equal ($skuListUri -notmatch '\$top=') $true 'subscribedSkus URI has no custom page size'
    $withTop = Add-GraphQueryParameter -Uri 'https://graph.microsoft.com/v1.0/users?$select=id' -Name '$top' -Value '999'
    Assert-Equal ($withTop -match '\$top=999') $true 'adds $top when missing'
    $already = Add-GraphQueryParameter -Uri $withTop -Name '$top' -Value '999'
    Assert-Equal $already $withTop 'does not duplicate $top'

    $usageRow = [pscustomobject]@{
        'User Principal Name'                = 'alex@contoso.com'
        'Display Name'                       = 'Alex Rivera'
        'Is Deleted'                         = 'False'
        'Storage Used (Byte)'                = [string](46.2 * 1GB)
        'Prohibit Send/Receive Quota (Byte)' = [string](50 * 1GB)
        'Prohibit Send Quota (Byte)'         = [string](49 * 1GB)
        'Issue Warning Quota (Byte)'         = [string](47.5 * 1GB)
    }
    $parsedUsage = ConvertFrom-MailboxUsageRow -Row $usageRow
    Assert-Equal $parsedUsage.Mailbox.UserPrincipalName 'alex@contoso.com' 'usage CSV UPN'
    Assert-Equal (Test-QuotaEquals -ActualBytes $parsedUsage.UsedBytes -ExpectedBytes (46.2 * 1GB) -ToleranceBytes 1MB) $true 'usage CSV used bytes'
    $deletedRow = [pscustomobject]@{ 'User Principal Name' = 'gone@contoso.com'; 'Is Deleted' = 'True' }
    Assert-Equal (ConvertFrom-MailboxUsageRow -Row $deletedRow) $null 'deleted usage rows skipped'
    $bomName = ([string][char]0xFEFF) + 'User Principal Name'
    $bomRow = New-Object psobject
    $bomRow | Add-Member -NotePropertyName $bomName -NotePropertyValue 'bom@contoso.com'
    $bomRow | Add-Member -NotePropertyName 'Is Deleted' -NotePropertyValue 'False'
    $bomRow | Add-Member -NotePropertyName 'Prohibit Send/Receive Quota (Byte)' -NotePropertyValue '1000'
    Assert-Equal (Get-CsvColumnValue -Row $bomRow -Names @('User Principal Name')) 'bom@contoso.com' 'BOM-prefixed CSV column'

    $csvTmp = Join-Path ([System.IO.Path]::GetTempPath()) ('QuotaSelfTest-' + [guid]::NewGuid().ToString('N') + '.csv')
    try {
        $utf8 = New-Object System.Text.UTF8Encoding $true
        $csvText = "User Principal Name,Display Name,Is Deleted,Storage Used (Byte),Prohibit Send/Receive Quota (Byte),Prohibit Send Quota (Byte),Issue Warning Quota (Byte)`r`nalex@contoso.com,Alex,False,100,200,150,140`r`n"
        [System.IO.File]::WriteAllText($csvTmp, $csvText, $utf8)
        $imported = ConvertTo-ObjectArray (Import-GraphReportCsv -LiteralPath $csvTmp)
        Assert-Equal (Get-CollectionCount $imported) 1 'UTF8 BOM usage CSV imports one row'
        Assert-Equal (Get-CsvColumnValue -Row $imported[0] -Names @('User Principal Name')) 'alex@contoso.com' 'imported usage CSV UPN'
        Assert-Equal (Get-CsvFileEncodingName -LiteralPath $csvTmp) 'UTF8' 'detects UTF8 BOM'
    }
    finally {
        Remove-Item -LiteralPath $csvTmp -Force -ErrorAction SilentlyContinue
    }

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
    Assert-Equal $lookup.E3Count 1 'E3 count'

    $f1Sku = [guid]'44575883-256e-4a79-9da4-ebe9acabe2b2'
    $f1Users = @(
        @{ id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'; userPrincipalName = 'Front@Contoso.com'; displayName = 'Front Line'; accountEnabled = $true; assignedLicenses = @(@{ skuId = $f1Sku.ToString(); disabledPlans = @() }) },
        @{ id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'; userPrincipalName = 'both@contoso.com'; displayName = 'Both'; accountEnabled = $true; assignedLicenses = @(@{ skuId = $f1Sku }, @{ skuId = $e3Sku }) }
    )
    $f1Lookup = Get-LicenseLookupTables -Users $f1Users -SkuMap @{} -E3SkuIds @($e3Sku.ToString()) -E5SkuIds @() -F1SkuIds @($f1Sku.ToString())
    Assert-Equal $f1Lookup.UserCount 2 'F1 and E3+F1 users indexed'
    Assert-Equal $f1Lookup.F1Count 2 'F1 count includes mixed user'
    Assert-Equal $f1Lookup.E3Count 1 'E3 count with mixed user'
    Assert-Equal $f1Lookup.ByUpn['front@contoso.com'].HasF1 $true 'hashtable Graph user F1 flag'
    Assert-Equal $f1Lookup.ByUpn['front@contoso.com'].HasE3 $false 'F1-only user not E3'

    $f1Only = $f1Lookup.ByUpn['front@contoso.com']
    $f1Eval = New-MailboxQuotaResult -UserPrincipalName 'front@contoso.com' -DisplayName 'Front Line' -License $f1Only `
        -SrBytes (50 * 1GB) -SendBytes (49 * 1GB) -WarnBytes (49 * 1GB) -UsedBytes (46 * 1GB) -UseDefaults $true -Policy $policy
    Assert-Equal $f1Eval.LicenseTier 'F1' 'F1 tier'
    Assert-Equal $f1Eval.ExpectedCapGB 50 'F1 expected cap is F1QuotaGB'
    Assert-Equal $f1Eval.StorageCompliant $true 'F1 on 50 GB is compliant'
    Assert-Equal $f1Eval.QuotasAligned $true 'F1 send/warn not enforced'
    Assert-Equal $f1Eval.NearLegacyLimit $true 'F1 46/50 GB is near cap'
    Assert-Equal $f1Eval.NeedsRemediation $false 'F1 is never remediated'
    $f1Big = New-MailboxQuotaResult -UserPrincipalName 'front@contoso.com' -License $f1Only `
        -SrBytes (100 * 1GB) -SendBytes (99 * 1GB) -WarnBytes (98 * 1GB) -UsedBytes (10 * 1GB) -UseDefaults $false -Policy $policy
    Assert-Equal $f1Big.StorageCompliant $false 'F1 on 100 GB is flagged'
    Assert-Equal $f1Big.NeedsRemediation $false 'F1 on 100 GB still not remediated'
    Assert-Equal $f1Big.NearLegacyLimit $false 'F1 10/100 GB not near'
    $mixed = $f1Lookup.ByUpn['both@contoso.com']
    $mixedEval = New-MailboxQuotaResult -UserPrincipalName 'both@contoso.com' -License $mixed `
        -SrBytes (50 * 1GB) -SendBytes (49 * 1GB) -WarnBytes (48 * 1GB) -UsedBytes (1 * 1GB) -UseDefaults $false -Policy $policy
    Assert-Equal $mixedEval.LicenseTier 'E3' 'E3+F1 user is treated as E3'
    Assert-Equal $mixedEval.NeedsRemediation $true 'E3+F1 on 50 GB remediates'

    $usageRows = @(
        [pscustomobject]@{ 'User Principal Name' = 'Front@contoso.com'; 'Display Name' = 'Front Line'; 'Is Deleted' = 'False'; 'Storage Used (Byte)' = [string](47 * 1GB); 'Prohibit Send/Receive Quota (Byte)' = [string](50 * 1GB); 'Prohibit Send Quota (Byte)' = [string](49 * 1GB); 'Issue Warning Quota (Byte)' = [string](49 * 1GB); 'Recipient Type' = 'UserMailbox' },
        [pscustomobject]@{ 'User Principal Name' = 'both@contoso.com'; 'Display Name' = 'Both'; 'Is Deleted' = 'False'; 'Storage Used (Byte)' = '1073741824'; 'Prohibit Send/Receive Quota (Byte)' = [string](100 * 1GB); 'Prohibit Send Quota (Byte)' = [string](99 * 1GB); 'Issue Warning Quota (Byte)' = [string](98 * 1GB); 'Recipient Type' = 'UserMailbox' },
        [pscustomobject]@{ 'User Principal Name' = 'gone@contoso.com'; 'Display Name' = 'Gone'; 'Is Deleted' = 'True'; 'Storage Used (Byte)' = '1'; 'Prohibit Send/Receive Quota (Byte)' = '1'; 'Prohibit Send Quota (Byte)' = '1'; 'Issue Warning Quota (Byte)' = '1'; 'Recipient Type' = 'UserMailbox' },
        [pscustomobject]@{ 'User Principal Name' = 'nolicense@contoso.com'; 'Display Name' = 'None'; 'Is Deleted' = 'False'; 'Storage Used (Byte)' = '1'; 'Prohibit Send/Receive Quota (Byte)' = '1'; 'Prohibit Send Quota (Byte)' = '1'; 'Issue Warning Quota (Byte)' = '1'; 'Recipient Type' = 'SharedMailbox' }
    )
    $fastResults = New-Object System.Collections.Generic.List[object]
    $fastMatched = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $fastAdded = Invoke-UsageReportEvaluation -Rows $usageRows -Lookup $f1Lookup -Policy $policy -Results $fastResults -MatchedUpns $fastMatched
    Assert-Equal $fastAdded 2 'fast evaluator keeps licensed, skips deleted and unlicensed'
    Assert-Equal $fastMatched.Contains('front@contoso.com') $true 'fast evaluator records matched UPN case-insensitively'
    $fastFront = $fastResults | Where-Object { $_.UserPrincipalName -eq 'Front@contoso.com' } | Select-Object -First 1
    Assert-Equal $fastFront.LicenseTier 'F1' 'fast evaluator F1 tier'
    Assert-Equal $fastFront.NearLegacyLimit $true 'fast evaluator F1 near cap'
    Assert-Equal $fastFront.TotalItemSizeGB '47.00 GB' 'fast evaluator used bytes formatting'
    Assert-Equal $fastFront.ExternalDirectoryObjectId 'ffffffff-ffff-ffff-ffff-ffffffffffff' 'fast evaluator carries Graph id'
    $fastBoth = $fastResults | Where-Object { $_.UserPrincipalName -eq 'both@contoso.com' } | Select-Object -First 1
    Assert-Equal $fastBoth.QuotasAligned $true 'fast evaluator 100/99/98 aligned'
    Assert-Equal $fastBoth.PercentOfCapUsed 1 'fast evaluator percent of cap'
    $colMap = Resolve-UsageReportColumns -FirstRow $bomRow
    Assert-Equal $colMap['Upn'] $bomName 'column resolver maps BOM header'

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
    Assert-Equal $demo.Count 4 'demo report has four sample mailboxes'
    $priya = $demo | Where-Object { $_.UserPrincipalName -eq 'priya@contoso.com' } | Select-Object -First 1
    Assert-Equal $priya.LicenseTier 'F1' 'demo Priya is F1'
    Assert-Equal $priya.StorageCompliant $true 'demo Priya F1 on 50 GB is compliant for F1'
    Assert-Equal $priya.NearLegacyLimit $true 'demo Priya F1 near 50 GB cap'
    Assert-Equal $priya.NeedsRemediation $false 'demo Priya F1 never remediated'
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

    $licE3 = [pscustomobject]@{ HasE3 = $true; HasE5 = $false; HasF1 = $false; UserPrincipalName = 'alex@contoso.com'; DisplayName = 'Alex Rivera' }
    $licE5 = [pscustomobject]@{ HasE3 = $false; HasE5 = $true; HasF1 = $false; UserPrincipalName = 'sam@contoso.com'; DisplayName = 'Sam Okonkwo' }
    $licBoth = [pscustomobject]@{ HasE3 = $true; HasE5 = $true; HasF1 = $false; UserPrincipalName = 'jordan@contoso.com'; DisplayName = 'Jordan Lee' }
    $licF1 = [pscustomobject]@{ HasE3 = $false; HasE5 = $false; HasF1 = $true; UserPrincipalName = 'priya@contoso.com'; DisplayName = 'Priya Natarajan' }

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
        @{
            Mailbox = [pscustomobject]@{
                UserPrincipalName         = 'priya@contoso.com'
                DisplayName               = 'Priya Natarajan'
                ExternalDirectoryObjectId = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
                RecipientTypeDetails      = 'UserMailbox'
                ProhibitSendReceiveQuota  = '50 GB (53,687,091,200 bytes)'
                ProhibitSendQuota         = '49 GB (52,613,349,376 bytes)'
                IssueWarningQuota         = '49 GB (52,613,349,376 bytes)'
                UseDatabaseQuotaDefaults  = $true
            }
            UsedBytes = 47.1 * 1GB
            License   = $licF1
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
    param(
        [string]$UserPrincipalName,
        [string]$AppId,
        [string]$CertificateThumbprint,
        [string]$Organization
    )

    $connectParams = @{
        ShowBanner  = $false
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($AppId)) {
        if ([string]::IsNullOrWhiteSpace($CertificateThumbprint) -or [string]::IsNullOrWhiteSpace($Organization)) {
            throw 'App-only Exchange Online auth requires -AppId, -CertificateThumbprint, and -Organization.'
        }
        $connectParams['AppId'] = $AppId
        $connectParams['CertificateThumbprint'] = $CertificateThumbprint
        $connectParams['Organization'] = $Organization
    }
    elseif (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        $connectParams['UserPrincipalName'] = $UserPrincipalName
    }

    $isWindowsPowerShell = $PSVersionTable.PSVersion.Major -lt 6
    if ($isWindowsPowerShell -and (Test-HasCmdletParameter -CommandName 'Connect-ExchangeOnline' -ParameterName 'DisableWAM')) {
        $connectParams['DisableWAM'] = $true
    }
    $script:ExoConnectParams = $connectParams
    $script:LastTokenRefresh = Get-Date

    if (Test-ExchangeOnlineConnected) {
        Write-Ok 'Reusing existing Exchange Online session.'
        return
    }

    Invoke-WithRetry -Activity 'Connect-ExchangeOnline' -ScriptBlock { Connect-ExchangeOnline @script:ExoConnectParams }
    $script:ExoConnectedByThisScript = $true
    Write-Ok 'Connected to Exchange Online.'
}

function Reset-QuotaExchangeOnline {
    Write-Warn 'Exchange Online connection dropped. Reconnecting...'
    Set-StrictMode -Off
    try {
        if (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 4
        Enable-Tls12
        Enable-DefaultProxyCredentials
        if ($null -eq $script:ExoConnectParams) {
            $script:ExoConnectParams = @{
                ShowBanner  = $false
                ErrorAction = 'Stop'
            }
        }
        Connect-ExchangeOnline @script:ExoConnectParams
        $script:ExoConnectedByThisScript = $true
        $script:LastTokenRefresh = Get-Date
        Write-Ok 'Reconnected to Exchange Online.'
    }
    finally {
        Set-StrictMode -Version Latest
    }
}

function Confirm-QuotaTokens {
    param([switch]$Exchange)

    if ($script:TokenRefreshMinutes -le 0) {
        return
    }
    if ($script:LastTokenRefresh -eq [datetime]::MinValue) {
        $script:LastTokenRefresh = Get-Date
        return
    }

    $age = ((Get-Date) - $script:LastTokenRefresh).TotalMinutes
    if ($age -lt $script:TokenRefreshMinutes) {
        return
    }

    Write-Info ("Refreshing authentication after {0:N0} minutes (delegated tokens typically last 60 minutes)..." -f $age)
    $refreshExo = $Exchange -or [bool]$script:ExoConnectedByThisScript
    if ($refreshExo) {
        Reset-QuotaExchangeOnline
    }
    if ($null -ne $script:GraphConnectParams) {
        try {
            Set-StrictMode -Off
            if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue
            }
            Set-StrictMode -Version Latest
            Invoke-WithRetry -Activity 'Connect-MgGraph' -ScriptBlock { Connect-MgGraph @script:GraphConnectParams }
            $script:GraphConnectedByThisScript = $true
        }
        catch {
            Write-Warn ("Graph re-auth failed: {0}" -f (Get-ExceptionMessageChain $_.Exception))
        }
        finally {
            Set-StrictMode -Version Latest
        }
    }
    $script:LastTokenRefresh = Get-Date
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

    $directoryRead = $haveSet.Contains('.default') -or
        $haveSet.Contains('Directory.Read.All') -or
        $haveSet.Contains('Directory.ReadWrite.All')

    foreach ($need in $Required) {
        if ([string]::IsNullOrWhiteSpace($need)) {
            continue
        }
        if ($haveSet.Contains($need)) {
            continue
        }
        # Directory.Read.All covers user/org reads, not Reports.Read.All.
        if ($directoryRead -and (
                [string]::Equals($need, 'User.Read.All', [System.StringComparison]::OrdinalIgnoreCase) -or
                [string]::Equals($need, 'Organization.Read.All', [System.StringComparison]::OrdinalIgnoreCase) -or
                [string]::Equals($need, '.default', [System.StringComparison]::OrdinalIgnoreCase)
            )) {
            continue
        }
        return $false
    }
    return $true
}

function Connect-QuotaGraph {
    param(
        [string]$TenantId,
        [string[]]$Scopes,
        [string]$AppId,
        [string]$CertificateThumbprint
    )

    $connectParams = @{
        ErrorAction = 'Stop'
    }
    if (Test-HasCmdletParameter -CommandName 'Connect-MgGraph' -ParameterName 'NoWelcome') {
        $connectParams['NoWelcome'] = $true
    }
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $connectParams['TenantId'] = $TenantId
    }

    $appOnly = -not [string]::IsNullOrWhiteSpace($AppId)
    if ($appOnly) {
        if ([string]::IsNullOrWhiteSpace($CertificateThumbprint) -or [string]::IsNullOrWhiteSpace($TenantId)) {
            throw 'App-only Graph auth requires -AppId, -CertificateThumbprint, and -TenantId.'
        }
        $connectParams['ClientId'] = $AppId
        $connectParams['CertificateThumbprint'] = $CertificateThumbprint
    }
    else {
        $connectParams['Scopes'] = $Scopes
    }

    $script:GraphConnectParams = $connectParams

    $hasContext = $false
    try {
        $ctx = Invoke-WithRetry -Activity 'Get-MgContext' -ScriptBlock { Get-MgContext -ErrorAction SilentlyContinue }
        $hasContext = ($null -ne $ctx)
    }
    catch {
        $hasContext = $false
    }

    if (-not $appOnly -and $hasContext -and (Test-GraphHasRequiredScopes -Required $Scopes)) {
        Write-Ok 'Reusing existing Microsoft Graph session.'
        $script:LastTokenRefresh = Get-Date
        return
    }

    Invoke-WithRetry -Activity 'Connect-MgGraph' -ScriptBlock { Connect-MgGraph @script:GraphConnectParams }
    $script:GraphConnectedByThisScript = $true
    $script:LastTokenRefresh = Get-Date
    Write-Ok 'Connected to Microsoft Graph.'
}

function Add-GraphQueryParameter {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )

    if ($Uri -match ('(\?|&)' + [regex]::Escape($Name) + '=')) {
        return $Uri
    }
    if ($Uri -match '\?') {
        return ($Uri + '&' + $Name + '=' + $Value)
    }
    return ($Uri + '?' + $Name + '=' + $Value)
}

function Invoke-GraphGetPaged {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [hashtable]$Headers
    )

    # Do not inject $top here. /subscribedSkus (and several other Graph
    # resources) return 400 Request_UnsupportedQuery: "This resource does not
    # support custom page sizes." User list URIs already include $top=999.
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $page = 0
    while (-not [string]::IsNullOrWhiteSpace($next)) {
        $page++
        Confirm-QuotaTokens
        Write-Progress -Activity 'Microsoft Graph paging' -Status ("Page {0}; {1} item(s) so far" -f $page, $items.Count)

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
    Write-Progress -Activity 'Microsoft Graph paging' -Completed
    return , $items.ToArray()
}

function Get-CsvColumnValue {
    param(
        $Row,
        [string[]]$Names
    )

    foreach ($name in $Names) {
        $value = Get-PropertyValue $Row $name
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
            return $value
        }
    }
    return $null
}

function Get-CsvFileEncodingName {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $bytes = [System.IO.File]::ReadAllBytes($LiteralPath)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return 'UTF8'
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return 'Unicode'
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        return 'BigEndianUnicode'
    }
    return 'UTF8'
}

function Import-GraphReportCsv {
    param([Parameter(Mandatory)][string]$LiteralPath)

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        throw "Graph mailbox usage report was not written to '$LiteralPath'."
    }

    $item = Get-Item -LiteralPath $LiteralPath
    if ($item.Length -lt 20) {
        throw 'Graph mailbox usage report file is empty. Grant Reports.Read.All (and wait a minute after consent) or use -DataSource ExchangeLive.'
    }

    $encoding = Get-CsvFileEncodingName -LiteralPath $LiteralPath
    $rows = @(Import-Csv -LiteralPath $LiteralPath -Encoding $encoding)
    if ((Get-CollectionCount $rows) -eq 0) {
        throw 'Graph mailbox usage report CSV had headers but no rows.'
    }

    $sample = $rows[0]
    $columnNames = New-Object System.Collections.Generic.List[string]
    foreach ($prop in @($sample.PSObject.Properties)) {
        $name = [string]$prop.Name
        if ($name.Length -gt 0 -and [int][char]$name[0] -eq 0xFEFF) {
            $name = $name.Substring(1)
        }
        [void]$columnNames.Add($name)
    }
    $joined = [string]::Join('|', $columnNames.ToArray())
    if ($joined -notmatch 'User Principal Name|UserPrincipalName') {
        throw ("Unexpected Graph mailbox usage CSV columns: {0}. Grant Reports.Read.All or use -DataSource ExchangeLive." -f [string]::Join(', ', $columnNames.ToArray()))
    }
    return , $rows
}

function ConvertFrom-MailboxUsageRow {
    param($Row)

    $deleted = ConvertTo-Bool (Get-CsvColumnValue -Row $Row -Names @('Is Deleted', 'IsDeleted'))
    if ($deleted) {
        return $null
    }

    $upn = Get-CsvColumnValue -Row $Row -Names @('User Principal Name', 'UserPrincipalName', 'UPN')
    if ([string]::IsNullOrWhiteSpace([string]$upn)) {
        return $null
    }

    $mailbox = [pscustomobject]@{
        UserPrincipalName         = $upn
        DisplayName               = Get-CsvColumnValue -Row $Row -Names @('Display Name', 'DisplayName')
        ExternalDirectoryObjectId = $null
        RecipientTypeDetails      = 'UserMailbox'
        ProhibitSendReceiveQuota  = Get-CsvColumnValue -Row $Row -Names @('Prohibit Send/Receive Quota (Byte)', 'Prohibit Send/Receive Quota (Bytes)', 'ProhibitSendReceiveQuota')
        ProhibitSendQuota         = Get-CsvColumnValue -Row $Row -Names @('Prohibit Send Quota (Byte)', 'Prohibit Send Quota (Bytes)', 'ProhibitSendQuota')
        IssueWarningQuota         = Get-CsvColumnValue -Row $Row -Names @('Issue Warning Quota (Byte)', 'Issue Warning Quota (Bytes)', 'IssueWarningQuota')
        UseDatabaseQuotaDefaults  = $null
    }

    $used = Get-CsvColumnValue -Row $Row -Names @('Storage Used (Byte)', 'Storage Used (Bytes)', 'StorageUsed')
    return [pscustomobject]@{
        Mailbox   = $mailbox
        UsedBytes = $(if ($null -eq $used) { $null } else { ConvertTo-Bytes $used })
    }
}

function Save-GraphReportCsv {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$LiteralPath
    )

    Set-StrictMode -Off
    try {
        if (Test-HasCmdletParameter -CommandName 'Invoke-MgGraphRequest' -ParameterName 'OutputFilePath') {
            Invoke-WithRetry -Activity 'GET mailbox usage report' -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputFilePath $LiteralPath -ErrorAction Stop
            }
            if ((Test-Path -LiteralPath $LiteralPath) -and ((Get-Item -LiteralPath $LiteralPath).Length -gt 50)) {
                return
            }
        }

        $resp = Invoke-WithRetry -Activity 'GET mailbox usage report' -ScriptBlock {
            Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
        }

        if ($resp -is [string] -and $resp -match 'User Principal Name|Prohibit Send') {
            $utf8 = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::WriteAllText($LiteralPath, $resp, $utf8)
            return
        }

        if ($resp -is [byte[]]) {
            [System.IO.File]::WriteAllBytes($LiteralPath, $resp)
            return
        }

        $location = Get-PropertyValue $resp 'Location'
        if ([string]::IsNullOrWhiteSpace([string]$location)) {
            $location = Get-PropertyValue $resp '@odata.mediaReadLink'
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$location)) {
            Invoke-WebRequest -Uri $location -OutFile $LiteralPath -UseBasicParsing -ErrorAction Stop
            return
        }

        throw "Unexpected Graph mailbox usage report response ($($resp.GetType().FullName)). Grant Reports.Read.All or use -DataSource ExchangeLive."
    }
    finally {
        Set-StrictMode -Version Latest
    }
}

function Get-GraphMailboxUsageRows {
    param(
        [Parameter(Mandatory)][string]$Period
    )

    $uri = "https://graph.microsoft.com/v1.0/reports/getMailboxUsageDetail(period='$Period')"
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('MailboxUsageDetail-' + [guid]::NewGuid().ToString('N') + '.csv')
    try {
        Write-Info ("Downloading Graph mailbox usage report ({0})..." -f $Period)
        Save-GraphReportCsv -Uri $uri -LiteralPath $tmp
        $rows = ConvertTo-ObjectArray (Import-GraphReportCsv -LiteralPath $tmp)
        Write-Ok ("Mailbox usage report rows: {0}" -f (Get-CollectionCount $rows))
        return , $rows
    }
    finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
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

function New-GraphLicensedUsersUri {
    param(
        [string[]]$SkuIds,
        [switch]$AnyLicense
    )

    $select = 'id,userPrincipalName,displayName,assignedLicenses,accountEnabled'
    $skuList = ConvertTo-StringArray $SkuIds
    if ((-not $AnyLicense) -and ((Get-CollectionCount $skuList) -gt 0)) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($id in $skuList) {
            [void]$parts.Add(('assignedLicenses/any(x:x/skuId eq {0})' -f $id))
        }
        $filter = [string]::Join(' or ', $parts.ToArray())
    }
    else {
        $filter = 'assignedLicenses/$count ne 0'
    }
    $encodedFilter = [uri]::EscapeDataString($filter)
    return "https://graph.microsoft.com/v1.0/users?`$count=true&`$filter=$encodedFilter&`$select=$select&`$top=999"
}

function Get-GraphLicensedUsers {
    param(
        [string[]]$Identity,
        [string[]]$SkuIds
    )

    $requested = ConvertTo-StringArray $Identity
    if ((Get-CollectionCount $requested) -gt 0) {
        $users = New-Object System.Collections.Generic.List[object]
        foreach ($id in $requested) {
            Confirm-QuotaTokens
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

    $headers = @{ ConsistencyLevel = 'eventual' }
    $skuList = ConvertTo-StringArray $SkuIds
    if ((Get-CollectionCount $skuList) -gt 0) {
        try {
            Write-Info 'Retrieving E3/E5 users from Microsoft Graph (paged, $top=999)...'
            return Invoke-GraphGetPaged -Uri (New-GraphLicensedUsersUri -SkuIds $skuList) -Headers $headers
        }
        catch {
            Write-Warn ("E3/E5 SKU filter was not accepted ({0}). Retrying with any assigned license..." -f (Get-ExceptionMessageChain $_.Exception))
        }
    }

    try {
        Write-Info 'Retrieving licensed users from Microsoft Graph (paged, $top=999)...'
        return Invoke-GraphGetPaged -Uri (New-GraphLicensedUsersUri -AnyLicense) -Headers $headers
    }
    catch {
        Write-Warn ("Licensed-user Graph filter was not accepted ({0}). Falling back to a full user scan..." -f (Get-ExceptionMessageChain $_.Exception))
        $fallback = "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName,displayName,assignedLicenses,accountEnabled&`$top=999"
        return Invoke-GraphGetPaged -Uri $fallback
    }
}

function Get-ExoMailboxesForQuota {
    param(
        [string[]]$Identity,
        [string[]]$RecipientTypeDetails,
        [string[]]$LicensedUpn
    )

    $base = Get-ExoMailboxSelectParams
    $requested = ConvertTo-StringArray $Identity
    if ((Get-CollectionCount $requested) -gt 0) {
        return , (Get-ExoMailboxByIdentityList -Identities $requested -QueryBase $base)
    }

    $licensed = ConvertTo-StringArray $LicensedUpn
    $licensedCount = Get-CollectionCount $licensed

    # A single Unlimited pull of Minimum+Quota drops on large tenants
    # ("underlying connection was closed"). Prefer UPN-prefix shards, and
    # only attempt a tenant-wide pull when the licensed set is small.
    if ($licensedCount -gt 0 -and $licensedCount -le 2000) {
        try {
            Write-Info 'Trying a single tenant-wide Get-EXOMailbox query...'
            return , (Get-ExoMailboxBulk -QueryBase $base -RecipientTypeDetails $RecipientTypeDetails)
        }
        catch {
            Write-Warn ("Tenant-wide mailbox query failed ({0}). Switching to UPN-prefix shards." -f (Get-ExceptionMessageChain $_.Exception))
        }
    }
    elseif ($licensedCount -gt 2000) {
        Write-Info ("Large licensed set ({0}). Skipping tenant-wide Get-EXOMailbox and using UPN-prefix shards." -f $licensedCount)
    }

    if ($licensedCount -gt 0) {
        return , (Get-ExoMailboxByUpnPrefix -LicensedUpn $licensed -QueryBase $base -RecipientTypeDetails $RecipientTypeDetails)
    }

    return , (Get-ExoMailboxBulk -QueryBase $base -RecipientTypeDetails $RecipientTypeDetails)
}

function Get-ExoMailboxBulk {
    param(
        [Parameter(Mandatory)][hashtable]$QueryBase,
        [string[]]$RecipientTypeDetails
    )

    $query = @{}
    foreach ($key in $QueryBase.Keys) {
        $query[$key] = $QueryBase[$key]
    }
    $query['ResultSize'] = 'Unlimited'
    if (((Get-CollectionCount $RecipientTypeDetails) -gt 0) -and (Test-HasCmdletParameter -CommandName 'Get-EXOMailbox' -ParameterName 'RecipientTypeDetails')) {
        $query['RecipientTypeDetails'] = $RecipientTypeDetails
    }

    return , (ConvertTo-ObjectArray (Invoke-WithRetry -Activity 'Get-EXOMailbox (bulk)' -MaxAttempts 3 -ScriptBlock { Get-EXOMailbox @query }))
}

function Get-ExoMailboxByIdentityList {
    param(
        [Parameter(Mandatory)]$Identities,
        [Parameter(Mandatory)][hashtable]$QueryBase
    )

    $found = New-Object System.Collections.Generic.List[object]
    $list = ConvertTo-StringArray $Identities
    $total = Get-CollectionCount $list
    $index = 0
    foreach ($id in $list) {
        $index++
        Write-Progress -Activity 'Get-EXOMailbox by identity' -Status $id -PercentComplete (($index / [Math]::Max($total, 1)) * 100)
        if (($index % 20) -eq 0) {
            Confirm-QuotaTokens -Exchange
        }
        try {
            $mbx = Invoke-WithRetry -Activity "Get-EXOMailbox $id" -ScriptBlock {
                Get-EXOMailbox -Identity $id @QueryBase
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
    Write-Progress -Activity 'Get-EXOMailbox by identity' -Completed
    return , $found.ToArray()
}

function Get-ExoMailboxByUpnPrefix {
    param(
        [Parameter(Mandatory)]$LicensedUpn,
        [Parameter(Mandatory)][hashtable]$QueryBase,
        [string[]]$RecipientTypeDetails,
        [int]$PrefixLength = 1
    )

    $found = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $unmatched = New-Object System.Collections.Generic.List[string]
    $prefixes = Get-UpnPrefixList -Upns $LicensedUpn -Length $PrefixLength
    $prefixCount = Get-CollectionCount $prefixes
    $prefixIndex = 0

    foreach ($prefix in $prefixes) {
        $prefixIndex++
        $filter = ConvertTo-ExoLikeFilter -Prefix $prefix
        if (-not $filter) {
            continue
        }

        Write-Info ("Mailbox shard {0}/{1}: {2}" -f $prefixIndex, $prefixCount, $filter)
        Confirm-QuotaTokens -Exchange
        $query = @{}
        foreach ($key in $QueryBase.Keys) {
            $query[$key] = $QueryBase[$key]
        }
        $query['ResultSize'] = 'Unlimited'
        $query['Filter'] = $filter
        if (((Get-CollectionCount $RecipientTypeDetails) -gt 0) -and (Test-HasCmdletParameter -CommandName 'Get-EXOMailbox' -ParameterName 'RecipientTypeDetails')) {
            $query['RecipientTypeDetails'] = $RecipientTypeDetails
        }

        $batch = @()
        $shardFailed = $false
        try {
            $batch = ConvertTo-ObjectArray (Invoke-WithRetry -Activity "Get-EXOMailbox shard $prefix" -MaxAttempts 4 -ScriptBlock { Get-EXOMailbox @query })
        }
        catch {
            $shardFailed = $true
            Write-Warn ("Shard '{0}' failed ({1})." -f $prefix, (Get-ExceptionMessageChain $_.Exception))
        }

        if ($shardFailed) {
            if ($PrefixLength -lt 2) {
                $subset = New-Object System.Collections.Generic.List[string]
                foreach ($upn in (ConvertTo-StringArray $LicensedUpn)) {
                    $local = ($upn.Split('@')[0])
                    if ($local.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                        [void]$subset.Add($upn)
                    }
                }
                $subPrefixes = Get-UpnPrefixList -Upns $subset -Length 2
                if ((Get-CollectionCount $subPrefixes) -gt 1) {
                    Write-Info ("Splitting '{0}*' into {1} two-character shards..." -f $prefix, (Get-CollectionCount $subPrefixes))
                    $nested = Get-ExoMailboxByUpnPrefix -LicensedUpn $subset.ToArray() -QueryBase $QueryBase -RecipientTypeDetails $RecipientTypeDetails -PrefixLength 2
                    foreach ($item in (ConvertTo-ObjectArray $nested)) {
                        $key = [string](Get-PropertyValue $item 'ExternalDirectoryObjectId')
                        if ([string]::IsNullOrWhiteSpace($key)) {
                            $key = [string](Get-PropertyValue $item 'UserPrincipalName')
                        }
                        if ($key -and $seen.Add($key)) {
                            [void]$found.Add($item)
                        }
                    }
                    continue
                }
            }

            $fallbackIds = New-Object System.Collections.Generic.List[string]
            foreach ($upn in (ConvertTo-StringArray $LicensedUpn)) {
                $local = ($upn.Split('@')[0])
                if ($local.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    [void]$fallbackIds.Add($upn)
                }
            }
            Write-Info ("Falling back to per-mailbox Get-EXOMailbox for {0} licensed UPN(s) in '{1}*'." -f (Get-CollectionCount $fallbackIds), $prefix)
            foreach ($item in (ConvertTo-ObjectArray (Get-ExoMailboxByIdentityList -Identities $fallbackIds.ToArray() -QueryBase $QueryBase))) {
                $key = [string](Get-PropertyValue $item 'ExternalDirectoryObjectId')
                if ([string]::IsNullOrWhiteSpace($key)) {
                    $key = [string](Get-PropertyValue $item 'UserPrincipalName')
                }
                if ($key -and $seen.Add($key)) {
                    [void]$found.Add($item)
                }
            }
            continue
        }

        foreach ($item in $batch) {
            $key = [string](Get-PropertyValue $item 'ExternalDirectoryObjectId')
            if ([string]::IsNullOrWhiteSpace($key)) {
                $key = [string](Get-PropertyValue $item 'UserPrincipalName')
            }
            if ($key -and $seen.Add($key)) {
                [void]$found.Add($item)
            }
        }
    }

    $foundUpns = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $found) {
        $upn = Get-PropertyValue $item 'UserPrincipalName'
        if (-not [string]::IsNullOrWhiteSpace([string]$upn)) {
            [void]$foundUpns.Add(([string]$upn).Trim())
        }
        $smtp = Get-PropertyValue $item 'PrimarySmtpAddress'
        if (-not [string]::IsNullOrWhiteSpace([string]$smtp)) {
            [void]$foundUpns.Add(([string]$smtp).Trim())
        }
    }

    foreach ($upn in (ConvertTo-StringArray $LicensedUpn)) {
        if (-not $foundUpns.Contains($upn)) {
            [void]$unmatched.Add($upn)
        }
    }

    if ((Get-CollectionCount $unmatched) -gt 0) {
        Write-Info ("Filling {0} licensed UPN(s) that prefix shards did not return..." -f (Get-CollectionCount $unmatched))
        foreach ($item in (ConvertTo-ObjectArray (Get-ExoMailboxByIdentityList -Identities $unmatched.ToArray() -QueryBase $QueryBase))) {
            $key = [string](Get-PropertyValue $item 'ExternalDirectoryObjectId')
            if ([string]::IsNullOrWhiteSpace($key)) {
                $key = [string](Get-PropertyValue $item 'UserPrincipalName')
            }
            if ($key -and $seen.Add($key)) {
                [void]$found.Add($item)
            }
        }
    }

    return , $found.ToArray()
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
        [string] $DataSource = '',
        [int] $HtmlMaxRows = 1000,
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
    $f1Path        = Join-Path $OutputFolder "MailboxQuota-F1-$stamp.csv"
    $htmlPath      = Join-Path $OutputFolder "MailboxQuota-Summary-$stamp.html"

    $exportColumns = @(
        'UserPrincipalName', 'DisplayName', 'ExternalDirectoryObjectId', 'RecipientTypeDetails',
        'LicenseTier', 'LicenseE3', 'LicenseE5', 'LicenseF1', 'ExpectedCapGB', 'UseDatabaseQuotaDefaults',
        'ProhibitSendReceiveGB', 'ProhibitSendGB', 'IssueWarningGB',
        'TotalItemSizeGB', 'PercentOfCapUsed',
        'StorageCompliant', 'QuotasAligned', 'NearLegacyLimit',
        'Issues', 'NeedsRemediation'
    )

    # One pass over the results instead of four Where-Object pipelines.
    $all          = ConvertTo-ObjectArray $Results
    $notCompliantList = New-Object System.Collections.Generic.List[object]
    $nearList     = New-Object System.Collections.Generic.List[object]
    $f1List       = New-Object System.Collections.Generic.List[object]
    $f1NearCount  = 0
    $enterpriseNotCompliant = 0
    foreach ($r in $all) {
        $isF1Only = (Get-LicenseFlag $r 'LicenseF1') -and -not ((Get-LicenseFlag $r 'LicenseE3') -or (Get-LicenseFlag $r 'LicenseE5'))
        if (-not $r.StorageCompliant) {
            [void]$notCompliantList.Add($r)
            if (-not $isF1Only) { $enterpriseNotCompliant++ }
        }
        if ($r.NearLegacyLimit) {
            [void]$nearList.Add($r)
            if ($isF1Only) { $f1NearCount++ }
        }
        if ($isF1Only) { [void]$f1List.Add($r) }
    }

    $total             = $all.Length
    $notCompliantCount = $notCompliantList.Count
    $nearLimitCount    = $nearList.Count
    $f1Count           = $f1List.Count

    Export-QuotaCsv -InputObject @($all | Sort-Object UserPrincipalName | Select-Object $exportColumns) -Path $fullPath
    Export-QuotaCsv -InputObject @($notCompliantList | Sort-Object UserPrincipalName | Select-Object $exportColumns) -Path $notCompliant
    Export-QuotaCsv -InputObject @($nearList | Sort-Object PercentOfCapUsed -Descending | Select-Object $exportColumns) -Path $nearLimitPath
    Export-QuotaCsv -InputObject @($f1List | Sort-Object PercentOfCapUsed -Descending | Select-Object $exportColumns) -Path $f1Path

    New-HtmlReport -Results $all -Path $htmlPath -MaxRows $HtmlMaxRows -Summary @{
        Total                  = $total
        Compliant              = $total - $notCompliantCount
        NotCompliant           = $notCompliantCount
        EnterpriseNotCompliant = $enterpriseNotCompliant
        NearLimit              = $nearLimitCount
        F1Total                = $f1Count
        F1NearLimit            = $f1NearCount
        F1QuotaGB              = $Policy.F1QuotaGB
        TargetStorageQuotaGB   = $Policy.TargetStorageQuotaGB
        LegacyQuotaGB          = $Policy.LegacyQuotaGB
        NearLimitPercent       = $Policy.NearLimitPercent
        Remediated             = [bool]$Remediated
        DataSource             = $DataSource
    }

    Write-Host ''
    Write-Ok  ("Evaluated {0} licensed mailboxes ({1} E3/E5, {2} F1-only)." -f $total, ($total - $f1Count), $f1Count)
    if ($LicensedWithoutMailbox -gt 0) {
        Write-Warn ("Licensed users with no matching mailbox in the data source: {0}" -f $LicensedWithoutMailbox)
    }
    Write-Warn ("E3/E5 mailboxes not configured for {0} GB storage: {1}" -f $Policy.TargetStorageQuotaGB, $enterpriseNotCompliant)
    Write-Warn ("E3 mailboxes near {0} GB cap (>= {1}%): {2}" -f $Policy.LegacyQuotaGB, $Policy.NearLimitPercent, ($nearLimitCount - $f1NearCount))
    Write-Warn ("F1 mailboxes ({0} GB cap): {1}; near cap (>= {2}%): {3}" -f $Policy.F1QuotaGB, $f1Count, $Policy.NearLimitPercent, $f1NearCount)
    Write-Host ''
    Write-Info 'Reports written to:'
    Write-Host "  $fullPath"
    Write-Host "  $notCompliant"
    Write-Host "  $nearLimitPath"
    Write-Host "  $f1Path"
    Write-Host "  $htmlPath"

    if (-not $SkipRemediateHint) {
        Write-Host ''
        Write-Info 'Report-only run. Re-run with -Remediate (add -WhatIf first) to apply quota fixes.'
    }

    return [pscustomobject]@{
        FullCsv      = $fullPath
        NotCompliant = $notCompliant
        NearLimit    = $nearLimitPath
        F1           = $f1Path
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
    -QuotaToleranceMB $QuotaToleranceMB `
    -F1QuotaGB $F1QuotaGB

if ($DemoReport) {
    Write-Info 'Writing a sample report (no tenant connection)...'
    $results = Get-MailboxQuotaDemoRows -Policy $policy
    Write-QuotaReportSet -Results $results -Policy $policy -OutputFolder $OutputFolder -DataSource 'Demo' -HtmlMaxRows $HtmlMaxRows -SkipRemediateHint | Out-Null
    return
}
#--------------------------------------------------------------------
# Connect
#--------------------------------------------------------------------

$script:TokenRefreshMinutes = $TokenRefreshMinutes
$useGraphReports = ($DataSource -eq 'GraphReports')
$needExo = $Remediate -or ($DataSource -eq 'ExchangeLive')
$sourceLabel = $DataSource
$runClock = [System.Diagnostics.Stopwatch]::StartNew()
$phaseClock = [System.Diagnostics.Stopwatch]::StartNew()
$script:QuotaCmdlet = $PSCmdlet

function Write-Phase {
    param([string]$Message)
    Write-Ok ("{0} [{1:mm\:ss} this step, {2:hh\:mm\:ss} total]" -f $Message, $phaseClock.Elapsed, $runClock.Elapsed)
    $phaseClock.Restart()
}

Write-Info 'Checking required modules...'
Enable-Tls12
Enable-DefaultProxyCredentials
Import-RequiredModule -Name 'Microsoft.Graph.Authentication'
if ($needExo) {
    Import-RequiredModule -Name 'ExchangeOnlineManagement'
}

$graphScopes = New-Object System.Collections.Generic.List[string]
[void]$graphScopes.Add('User.Read.All')
[void]$graphScopes.Add('Organization.Read.All')
if ($useGraphReports) {
    [void]$graphScopes.Add('Reports.Read.All')
}

Write-Info 'Connecting to Microsoft Graph...'
Connect-QuotaGraph -TenantId $TenantId -Scopes @($graphScopes.ToArray()) -AppId $AppId -CertificateThumbprint $CertificateThumbprint

if ($needExo) {
    Write-Info 'Connecting to Exchange Online...'
    Connect-QuotaExchangeOnline -UserPrincipalName $UserPrincipalName -AppId $AppId -CertificateThumbprint $CertificateThumbprint -Organization $Organization
}
Write-Phase 'Connected.'

$results = New-Object System.Collections.Generic.List[object]
$licensedWithoutMailbox = 0

function Invoke-QuotaRemediation {
    param(
        [Parameter(Mandatory)] $Rows,
        $FallbackIdentityByUpn = $null
    )

    $targets = New-Object System.Collections.Generic.List[object]
    foreach ($r in (ConvertTo-ObjectArray $Rows)) {
        if ($r.NeedsRemediation) { [void]$targets.Add($r) }
    }
    if ($targets.Count -eq 0) {
        Write-Info 'No E3/E5 mailboxes need quota remediation.'
        return
    }

    Write-Info ("Remediating {0} mailbox(es) via Set-Mailbox..." -f $targets.Count)
    if (-not (Test-ExchangeOnlineConnected)) {
        Import-RequiredModule -Name 'ExchangeOnlineManagement'
        Connect-QuotaExchangeOnline -UserPrincipalName $UserPrincipalName -AppId $AppId -CertificateThumbprint $CertificateThumbprint -Organization $Organization
    }

    $target = "SR=$TargetStorageQuotaGB GB, Send=$ProhibitSendQuotaGB GB, Warn=$IssueWarningQuotaGB GB"
    $index = 0
    foreach ($row in $targets) {
        $index++
        if (($index % 25) -eq 0) {
            Confirm-QuotaTokens -Exchange
        }
        $identityForSet = [string]$row.UserPrincipalName
        if ([string]::IsNullOrWhiteSpace($identityForSet) -and $null -ne $FallbackIdentityByUpn) {
            $identityForSet = [string]$FallbackIdentityByUpn[$row.UserPrincipalName]
        }
        if ([string]::IsNullOrWhiteSpace($identityForSet)) {
            Write-Warn 'Skipping a remediation row with no identity.'
            continue
        }
        Write-Progress -Activity 'Remediating quotas' -Status $identityForSet -PercentComplete (($index / $targets.Count) * 100)
        if ($script:QuotaCmdlet.ShouldProcess($identityForSet, "Set quotas to $target")) {
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
    Write-Progress -Activity 'Remediating quotas' -Completed
}

try {
    Write-Info 'Resolving subscribed SKUs...'
    $skuMap = Get-GraphSubscribedSkuMap
    $e3SkuIds = Get-SkuIdsByPartNumber -SkuMap $skuMap -PartNumbers $E3SkuPartNumber
    $e5SkuIds = Get-SkuIdsByPartNumber -SkuMap $skuMap -PartNumbers $E5SkuPartNumber
    $f1SkuIds = Get-SkuIdsByPartNumber -SkuMap $skuMap -PartNumbers $F1SkuPartNumber

    if ((Get-CollectionCount $e3SkuIds) -eq 0) {
        Write-Warn ("E3 SKU(s) '{0}' not found in this tenant." -f ($E3SkuPartNumber -join ', '))
    }
    if ((Get-CollectionCount $e5SkuIds) -eq 0) {
        Write-Warn ("E5 SKU(s) '{0}' not found in this tenant." -f ($E5SkuPartNumber -join ', '))
    }
    if ((Get-CollectionCount $f1SkuIds) -eq 0) {
        Write-Warn ("F1 SKU(s) '{0}' not found in this tenant. Tenant SKUs: {1}" -f ($F1SkuPartNumber -join ', '), (($skuMap.Values | Sort-Object -Unique) -join ', '))
    }
    Write-Phase ("Resolved {0} tenant SKU(s)." -f $skuMap.Count)

    $usageRows = @()
    if ($useGraphReports) {
        Write-Info 'Downloading the Microsoft Graph mailbox usage report (one tenant-wide CSV; data can lag 24-48 hours)...'
        try {
            $usageRows = ConvertTo-ObjectArray (Get-GraphMailboxUsageRows -Period $MailboxUsagePeriod)
            $sourceLabel = "GraphReports ($MailboxUsagePeriod, ~24-48h delay)"
            Write-Phase ("Usage report downloaded: {0} row(s)." -f $usageRows.Length)
        }
        catch {
            $reason = Get-ExceptionMessageChain $_.Exception
            if (-not $AllowExchangeLiveFallback) {
                throw ("The Graph mailbox usage report could not be downloaded: {0}`n" +
                       "Fix: grant Reports.Read.All to the signed-in account (or the app registration) and re-run. " +
                       "In Entra: Enterprise applications > Microsoft Graph Command Line Tools > Permissions, or ask a Global Admin to consent once.`n" +
                       "Only if you really need it, re-run with -AllowExchangeLiveFallback (or -DataSource ExchangeLive) to use the slow per-mailbox Exchange path; " +
                       "at ~30k mailboxes that takes hours and needs app-only certificate auth to survive token expiry.") -f $reason
            }
            Write-Warn ("Graph mailbox usage report failed ({0}). -AllowExchangeLiveFallback is set, so falling back to ExchangeLive (slow)." -f $reason)
            $useGraphReports = $false
            $needExo = $true
            Import-RequiredModule -Name 'ExchangeOnlineManagement'
            if (-not (Test-ExchangeOnlineConnected)) {
                Connect-QuotaExchangeOnline -UserPrincipalName $UserPrincipalName -AppId $AppId -CertificateThumbprint $CertificateThumbprint -Organization $Organization
            }
        }
    }

    Write-Info 'Retrieving licensed users from Microsoft Graph...'
    $skuIdsForFilter = ConvertTo-StringArray (@(ConvertTo-ObjectArray $e3SkuIds) + @(ConvertTo-ObjectArray $e5SkuIds) + @(ConvertTo-ObjectArray $f1SkuIds))
    $allUsers = Get-GraphLicensedUsers -Identity $Identity -SkuIds $skuIdsForFilter
    Write-Phase ("Graph returned {0} user object(s)." -f (Get-CollectionCount $allUsers))

    $lookup = Get-LicenseLookupTables -Users $allUsers -SkuMap $skuMap -E3SkuIds $e3SkuIds -E5SkuIds $e5SkuIds -F1SkuIds $f1SkuIds
    Write-Phase ("Indexed {0} licensed user(s): E3={1}, E5={2}, F1={3}." -f $lookup.UserCount, $lookup.E3Count, $lookup.E5Count, $lookup.F1Count)
    $allUsers = $null

    if ([int]$lookup.UserCount -eq 0) {
        Write-Warn 'No E3/E5/F1 licensed users were found. Reports will be empty.'
    }
    elseif ($useGraphReports) {
        $matchedUpns = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $added = Invoke-UsageReportEvaluation -Rows $usageRows -Lookup $lookup -Policy $policy -Results $results -MatchedUpns $matchedUpns
        Write-Phase ("Evaluated {0} licensed mailbox(es) from the usage report." -f $added)
        $usageRows = $null

        foreach ($upn in @($lookup.ByUpn.Keys)) {
            if (-not $matchedUpns.Contains($upn)) {
                $licensedWithoutMailbox++
            }
        }

        if ($Remediate) {
            Invoke-QuotaRemediation -Rows $results
            Write-Phase 'Remediation pass finished.'
        }
    }

    if (-not $useGraphReports -and [int]$lookup.UserCount -gt 0) {
        $sourceLabel = 'ExchangeLive'
        Write-Info 'Retrieving Exchange Online mailboxes (sharded Get-EXOMailbox; this can take a while)...'
        $mailboxes = ConvertTo-ObjectArray (Get-ExoMailboxesForQuota -Identity $Identity -RecipientTypeDetails $RecipientTypeDetails -LicensedUpn @($lookup.ByUpn.Keys))
        Write-Phase ("Retrieved {0} mailbox object(s)." -f (Get-CollectionCount $mailboxes))

        $matchedObjectIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $smtpByUpn = @{}
        $index = 0
        $total = Get-CollectionCount $mailboxes

        foreach ($mbx in $mailboxes) {
            $index++
            if (($index % 25) -eq 0) {
                Confirm-QuotaTokens -Exchange
                $status = [string](Get-PropertyValue $mbx 'UserPrincipalName')
                Write-Progress -Activity 'Evaluating mailboxes' -Status "$index of $total ($status)" -PercentComplete (($index / [Math]::Max($total, 1)) * 100)
            }

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

            $smtp = [string](Get-PropertyValue $mbx 'PrimarySmtpAddress')
            if ($row.NeedsRemediation -and -not [string]::IsNullOrWhiteSpace($smtp)) {
                $smtpByUpn[[string]$row.UserPrincipalName] = $smtp
            }
        }
        Write-Progress -Activity 'Evaluating mailboxes' -Completed
        Write-Phase ("Evaluated {0} licensed mailbox(es) from Exchange Online." -f $results.Count)

        foreach ($key in @($lookup.ByObjectId.Keys)) {
            if (-not $matchedObjectIds.Contains($key)) {
                $licensedWithoutMailbox++
            }
        }

        if ($Remediate) {
            Invoke-QuotaRemediation -Rows $results -FallbackIdentityByUpn $smtpByUpn
            Write-Phase 'Remediation pass finished.'
        }
    }
}
finally {
    Write-Progress -Activity 'Evaluating mailboxes' -Completed
    Write-Progress -Activity 'Evaluating mailbox usage report' -Completed
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
    -DataSource $sourceLabel `
    -HtmlMaxRows $HtmlMaxRows `
    -Remediated:$Remediate `
    -SkipRemediateHint:$Remediate | Out-Null
Write-Phase 'Reports written.'

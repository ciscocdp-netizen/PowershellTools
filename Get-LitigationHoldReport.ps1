#Requires -Version 5.1
<#
.SYNOPSIS
    Reports Exchange Online mailboxes that have Litigation Hold enabled.

.DESCRIPTION
    Connects to Exchange Online (EXO V3 module), finds mailboxes with
    LitigationHoldEnabled = True (including inactive / former-employee mailboxes
    that remain on hold), shows them on screen, and exports a CSV.

    A graphical Save File dialog is used when -OutputCsv is omitted.

.NOTES
    Requires: Windows PowerShell 5.1 or PowerShell 7+ (Windows) for the GUI picker,
    and the ExchangeOnlineManagement module.

    Bugs fixed vs. the original script:
    - Get-EXOMailbox -PropertySets Hold replaces the default Minimum set, so
      DisplayName / UserPrincipalName / PrimarySmtpAddress were blank. Request
      Minimum,Hold,SoftDelete together.
    - Every mailbox was downloaded then filtered client-side. LitigationHoldEnabled
      is filterable; filter server-side (with a client-side fallback).
    - A single matching mailbox is a scalar, not an array, so .Count / foreach
      can misbehave. Results are always wrapped with @().
    - WinForms SaveFileDialog requires STA; powershell.exe / pwsh default to MTA
      in some hosts, so the dialog hangs or never appears. The script relaunches
      itself with -STA when a picker is needed.
    - ShowDialog() without an owner opens behind the console. Dialogs are owned
      by a TopMost form.
    - LitigationHoldDuration is a TimeSpan / "Unlimited", not a day count. The
      Days column now converts 90.00:00:00 -> 90.
    - Inactive mailboxes (held, then deleted) were omitted. They are included
      unless -SkipInactiveMailboxes is passed.
    - Disconnect-ExchangeOnline was skipped on several error paths, leaving the
      session open. Disconnect runs in finally, and only if this script connected.
    - Install-Module could fail on TLS 1.0 defaults / missing NuGet provider.
    - Connect-ExchangeOnline on Windows PowerShell 5.1 often fails with
      "An error occurred while sending the request" because .NET still offers
      TLS 1.0/1.1. TLS 1.2 is enabled before the module loads. Inner exceptions
      are printed, WAM is disabled on 5.1, and default proxy credentials are set.

.PARAMETER OutputCsv
    Optional. Path to write the report. When omitted, a Save File dialog is shown.

.PARAMETER UserPrincipalName
    Optional UPN passed to Connect-ExchangeOnline (useful for modern auth / MFA).

.PARAMETER SkipInactiveMailboxes
    Switch. Do not include inactive mailboxes (soft-deleted mailboxes that remain
    on Litigation Hold). By default they ARE included — a legal-hold report is
    incomplete without them.

.PARAMETER SkipDisconnect
    Switch. Leave the Exchange Online session connected when the script ends.
    Implied when this script reused an existing connection it did not create.

.PARAMETER SelfTest
    Switch. Runs built-in unit tests for duration conversion, boolean coercion,
    property-set selection, and array wrapping, then exits. Does not connect to
    Exchange Online or show dialogs.

.EXAMPLE
    .\Get-LitigationHoldReport.ps1

.EXAMPLE
    .\Get-LitigationHoldReport.ps1 -OutputCsv .\LitigationHoldReport.csv

.EXAMPLE
    .\Get-LitigationHoldReport.ps1 -UserPrincipalName admin@contoso.com -SkipInactiveMailboxes

.EXAMPLE
    .\Get-LitigationHoldReport.ps1 -SelfTest
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputCsv,

    [Parameter()]
    [string]$UserPrincipalName,

    [switch]$SkipInactiveMailboxes,

    [switch]$SkipDisconnect,

    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region STA -------------------------------------------------------------------

$script:UseGui = (-not $SelfTest) -and [string]::IsNullOrWhiteSpace($OutputCsv)

if ($script:UseGui -and [System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        Write-Host "File dialogs require STA. Restart with: powershell.exe -STA -File <script>  (or pass -OutputCsv)" -ForegroundColor Red
        exit 1
    }

    $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $argParts = New-Object System.Collections.Generic.List[string]
    [void]$argParts.Add('-NoProfile')
    [void]$argParts.Add('-STA')
    [void]$argParts.Add('-ExecutionPolicy')
    [void]$argParts.Add('Bypass')
    [void]$argParts.Add('-File')
    [void]$argParts.Add(('"{0}"' -f $PSCommandPath))
    if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        [void]$argParts.Add('-UserPrincipalName')
        [void]$argParts.Add(('"{0}"' -f $UserPrincipalName))
    }
    if ($SkipInactiveMailboxes) {
        [void]$argParts.Add('-SkipInactiveMailboxes')
    }
    if ($SkipDisconnect) {
        [void]$argParts.Add('-SkipDisconnect')
    }

    Write-Host "Relaunching in STA mode so the Save File dialog works..." -ForegroundColor Yellow
    $proc = Start-Process -FilePath $exe -ArgumentList ($argParts -join ' ') -Wait -PassThru -NoNewWindow
    if ($null -eq $proc.ExitCode) { exit 1 }
    exit $proc.ExitCode
}

#endregion

#region Helpers ----------------------------------------------------------------

function Enable-Tls12 {
    # Windows PowerShell 5.1 / .NET 4.x still defaults to TLS 1.0/1.1.
    # Connect-ExchangeOnline then fails with "An error occurred while sending the request".
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
            # Runtime may not expose the enum; connection will fail with a clearer chain later.
        }
    }

    try {
        $tls13 = [Net.SecurityProtocolType]::Tls13
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $tls13
    }
    catch {
        # TLS 1.3 is not available on all .NET Framework builds.
    }
}

function Enable-DefaultProxyCredentials {
    try {
        $proxy = [Net.WebRequest]::DefaultWebProxy
        if ($null -ne $proxy -and $null -eq $proxy.Credentials) {
            $proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials
        }
    }
    catch {
        # No proxy or the runtime does not allow this; ignore.
    }
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

function Test-IsTransportFailure {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    return [bool]($Message -match 'sending the request|SSL/TLS|secure channel|common algorithm|underlying connection was closed|The request was aborted|Could not create SSL')
}

function Write-ConnectionFailureHelp {
    param([string]$Message)

    if (-not (Test-IsTransportFailure -Message $Message)) {
        return
    }

    Write-Host @"

This is almost always a TLS 1.2 or proxy/firewall problem on Windows PowerShell 5.1.
The script already enabled TLS 1.2 for this process. If it still fails:

  1. Update the module:   Update-Module ExchangeOnlineManagement -Force
  2. Allow HTTPS to login.microsoftonline.com and outlook.office365.com
  3. Confirm Internet Options has the corporate proxy (if you use one)
  4. Run from PowerShell 7 instead:  pwsh -File .\Get-LitigationHoldReport.ps1
"@ -ForegroundColor Yellow
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

function Connect-LitigationHoldExchange {
    param(
        [string]$UserPrincipalName
    )

    $connectParams = @{
        ShowBanner  = $false
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        $connectParams['UserPrincipalName'] = $UserPrincipalName
    }

    # EXO module 3.7+ uses the Windows WAM broker by default; on Windows
    # PowerShell 5.1 that often surfaces as HttpRequestException.
    $isWindowsPowerShell = $PSVersionTable.PSVersion.Major -lt 6
    if ($isWindowsPowerShell -and (Test-HasCmdletParameter -CommandName 'Connect-ExchangeOnline' -ParameterName 'DisableWAM')) {
        $connectParams['DisableWAM'] = $true
    }

    Connect-ExchangeOnline @connectParams
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Name)
    $ok = $false
    if ($null -eq $Expected -and $null -eq $Actual) {
        $ok = $true
    }
    elseif ($null -ne $Expected -and $null -ne $Actual -and "$Expected" -eq "$Actual") {
        $ok = $true
    }
    if (-not $ok) {
        throw "SelfTest failed: $Name. Expected '$Expected', got '$Actual'."
    }
}

function ConvertTo-BooleanFlag {
    param($Value)

    if ($null -eq $Value) {
        return $false
    }
    if ($Value -is [bool]) {
        return [bool]$Value
    }

    $text = "$Value".Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $false
    }

    switch -Regex ($text) {
        '^(?i:true|yes|1)$'  { return $true }
        '^(?i:false|no|0)$' { return $false }
        default {
            # Left-hand string vs $true would treat any non-empty value as True
            # if the boolean were on the left. Fail closed for unknown tokens.
            return $false
        }
    }
}

function Convert-LitigationHoldDurationDays {
    param($Duration)

    if ($null -eq $Duration) {
        return 'Unlimited'
    }

    $text = "$Duration".Trim()
    if ([string]::IsNullOrWhiteSpace($text) -or $text -eq 'Unlimited') {
        return 'Unlimited'
    }

    # Exchange stores this as EnhancedTimeSpan ("90.00:00:00") or a day count.
    $ts = [TimeSpan]::Zero
    if ([TimeSpan]::TryParse($text, [ref]$ts)) {
        return [int][Math]::Round($ts.TotalDays, 0)
    }

    $days = 0
    if ([int]::TryParse($text, [ref]$days)) {
        return $days
    }

    return $text
}

function Convert-InPlaceHolds {
    param($Value)

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [string]) {
        return $Value
    }

    $items = @(
        $Value |
            ForEach-Object { "$_" } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    return ($items -join '; ')
}

function Format-ReportDate {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    $text = "$Value".Trim()
    if ([string]::IsNullOrWhiteSpace($text) -or $text -eq 'Unlimited') {
        return $null
    }

    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse($text, [ref]$parsed)) {
        if ($parsed.Year -le 1601) {
            return $null
        }
        return $parsed.ToString('yyyy-MM-dd HH:mm:ss')
    }

    return $text
}

function Get-MailboxProperty {
    param(
        [Parameter(Mandatory)]
        $Mailbox,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $prop = $Mailbox.PSObject.Properties[$Name]
    if ($null -eq $prop) {
        return $null
    }
    return $prop.Value
}

function Test-LitigationHoldEnabled {
    param(
        [Parameter(Mandatory)]
        $Mailbox
    )

    return (ConvertTo-BooleanFlag (Get-MailboxProperty -Mailbox $Mailbox -Name 'LitigationHoldEnabled'))
}

function Get-LitigationHoldQuerySpec {
    <#
        PropertySets Hold does NOT include identity fields. Minimum must be
        requested explicitly or DisplayName / UPN / SMTP are blank.
        SoftDelete adds IsInactiveMailbox / WhenSoftDeleted for inactive holds.
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeInactive
    )

    $spec = [ordered]@{
        Filter            = 'LitigationHoldEnabled -eq $true'
        ResultSize        = 'Unlimited'
        PropertySets      = @('Minimum', 'Hold', 'SoftDelete')
        IncludeInactive   = [bool]$IncludeInactive
    }
    return [pscustomobject]$spec
}

function ConvertTo-LitigationHoldReportRow {
    param(
        [Parameter(Mandatory)]
        $Mailbox
    )

    $durationRaw = Get-MailboxProperty -Mailbox $Mailbox -Name 'LitigationHoldDuration'

    return [pscustomobject][ordered]@{
        DisplayName                  = Get-MailboxProperty -Mailbox $Mailbox -Name 'DisplayName'
        UserPrincipalName            = Get-MailboxProperty -Mailbox $Mailbox -Name 'UserPrincipalName'
        PrimarySmtpAddress           = Get-MailboxProperty -Mailbox $Mailbox -Name 'PrimarySmtpAddress'
        RecipientTypeDetails         = Get-MailboxProperty -Mailbox $Mailbox -Name 'RecipientTypeDetails'
        LitigationHoldEnabled        = Test-LitigationHoldEnabled -Mailbox $Mailbox
        LitigationHoldDate           = Format-ReportDate (Get-MailboxProperty -Mailbox $Mailbox -Name 'LitigationHoldDate')
        LitigationHoldOwner          = Get-MailboxProperty -Mailbox $Mailbox -Name 'LitigationHoldOwner'
        LitigationHoldDurationDays   = Convert-LitigationHoldDurationDays $durationRaw
        LitigationHoldDurationRaw    = $(if ($null -eq $durationRaw) { $null } else { "$durationRaw" })
        IsInactiveMailbox            = ConvertTo-BooleanFlag (Get-MailboxProperty -Mailbox $Mailbox -Name 'IsInactiveMailbox')
        WhenSoftDeleted              = Format-ReportDate (Get-MailboxProperty -Mailbox $Mailbox -Name 'WhenSoftDeleted')
        InPlaceHolds                 = Convert-InPlaceHolds (Get-MailboxProperty -Mailbox $Mailbox -Name 'InPlaceHolds')
        DelayHoldApplied             = ConvertTo-BooleanFlag (Get-MailboxProperty -Mailbox $Mailbox -Name 'DelayHoldApplied')
        ComplianceTagHoldApplied     = ConvertTo-BooleanFlag (Get-MailboxProperty -Mailbox $Mailbox -Name 'ComplianceTagHoldApplied')
    }
}

function Get-DefaultPickerDirectory {
    foreach ($special in @('Desktop', 'MyDocuments')) {
        $path = [Environment]::GetFolderPath($special)
        if ($path -and (Test-Path -LiteralPath $path)) {
            return $path
        }
    }
    return (Get-Location).Path
}

function Show-OwnedDialog {
    param($Dialog)

    $owner = New-Object System.Windows.Forms.Form
    $owner.TopMost = $true
    $owner.ShowInTaskbar = $false
    $owner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
    $owner.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $owner.Width = 1
    $owner.Height = 1
    $owner.Opacity = 0
    [void]$owner.Show()
    try {
        return $Dialog.ShowDialog($owner)
    }
    finally {
        $owner.Close()
        $owner.Dispose()
    }
}

function Select-OutputCsv {
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Title = "Save Litigation Hold Report"
    $dialog.Filter = "CSV file (*.csv)|*.csv|All files (*.*)|*.*"
    $dialog.FileName = "LitigationHoldReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $dialog.DefaultExt = 'csv'
    $dialog.AddExtension = $true
    $dialog.OverwritePrompt = $true
    $dialog.CheckPathExists = $true
    $dialog.RestoreDirectory = $true
    $dialog.InitialDirectory = Get-DefaultPickerDirectory

    try {
        $result = Show-OwnedDialog -Dialog $dialog
        if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
            return $null
        }
        return $dialog.FileName
    }
    finally {
        $dialog.Dispose()
    }
}

function Test-ExchangeOnlineConnected {
    try {
        $connections = @(Get-ConnectionInformation -ErrorAction Stop)
        return ($connections.Count -ge 1)
    }
    catch {
        return $false
    }
}

function Install-ExchangeOnlineModuleIfMissing {
    if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
        return
    }

    Write-Host "ExchangeOnlineManagement module not found. Installing for current user..." -ForegroundColor Yellow

    Enable-Tls12

    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    if ($null -eq $nuget -or $nuget.Version -lt [version]'2.8.5.201') {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
    }

    Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
}

function Invoke-LitigationHoldMailboxQuery {
    param(
        [Parameter(Mandatory)]
        $QuerySpec
    )

    $exoParams = @{
        ResultSize   = 'Unlimited'
        PropertySets = $QuerySpec.PropertySets
        ErrorAction  = 'Stop'
    }
    if ($QuerySpec.IncludeInactive) {
        $exoParams['IncludeInactiveMailbox'] = $true
    }

    $raw = @()
    try {
        Write-Host "Querying mailboxes with Litigation Hold enabled (server-side filter)..." -ForegroundColor Cyan
        $raw = @(Get-EXOMailbox @exoParams -Filter $QuerySpec.Filter)
    }
    catch {
        Write-Host "Server-side filter was not accepted ($($_.Exception.Message)). Falling back to a full mailbox scan..." -ForegroundColor Yellow
        $raw = @(Get-EXOMailbox @exoParams)
    }

    # REST filters are not always honored; keep only confirmed holds.
    return @($raw | Where-Object { Test-LitigationHoldEnabled -Mailbox $_ })
}

function Invoke-LitigationHoldSelfTest {
    Write-Host "Running Get-LitigationHoldReport self-tests..." -ForegroundColor Cyan

    Assert-Equal (ConvertTo-BooleanFlag $true) $true 'bool true'
    Assert-Equal (ConvertTo-BooleanFlag $false) $false 'bool false'
    Assert-Equal (ConvertTo-BooleanFlag 'True') $true 'string True'
    Assert-Equal (ConvertTo-BooleanFlag 'FALSE') $false 'string FALSE'
    Assert-Equal (ConvertTo-BooleanFlag 'no') $false 'string no'
    Assert-Equal (ConvertTo-BooleanFlag $null) $false 'null is false'
    Assert-Equal (ConvertTo-BooleanFlag 'maybe') $false 'unknown token is false'

    Assert-Equal (Convert-LitigationHoldDurationDays $null) 'Unlimited' 'null duration'
    Assert-Equal (Convert-LitigationHoldDurationDays 'Unlimited') 'Unlimited' 'unlimited duration'
    Assert-Equal (Convert-LitigationHoldDurationDays '90.00:00:00') 90 'timespan 90 days'
    Assert-Equal (Convert-LitigationHoldDurationDays ([TimeSpan]::FromDays(30))) 30 'timespan object 30 days'
    Assert-Equal (Convert-LitigationHoldDurationDays 45) 45 'integer days'

    Assert-Equal (Convert-InPlaceHolds $null) '' 'null holds'
    Assert-Equal (Convert-InPlaceHolds 'UniH123') 'UniH123' 'single hold string'
    Assert-Equal (Convert-InPlaceHolds @('UniH1', 'mbxcd2')) 'UniH1; mbxcd2' 'hold array'

    Assert-Equal (Format-ReportDate $null) $null 'null date'
    $sample = [datetime]::ParseExact('2024-06-01 13:45:00', 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    Assert-Equal (Format-ReportDate $sample) '2024-06-01 13:45:00' 'format datetime'

    $spec = Get-LitigationHoldQuerySpec -IncludeInactive
    Assert-Equal ($spec.PropertySets -contains 'Minimum') $true 'Minimum property set required'
    Assert-Equal ($spec.PropertySets -contains 'Hold') $true 'Hold property set required'
    Assert-Equal ($spec.PropertySets -contains 'SoftDelete') $true 'SoftDelete property set required'
    Assert-Equal $spec.Filter 'LitigationHoldEnabled -eq $true' 'OPATH filter'
    Assert-Equal $spec.IncludeInactive $true 'inactive included by default spec'

    $skipSpec = Get-LitigationHoldQuerySpec
    Assert-Equal $skipSpec.IncludeInactive $false 'inactive omitted when not requested'

    # Hold-only objects have no identity properties — the original bug.
    $holdOnly = [pscustomobject]@{
        LitigationHoldEnabled  = $true
        LitigationHoldDuration = '90.00:00:00'
        LitigationHoldDate     = $sample
        LitigationHoldOwner    = 'admin@contoso.com'
        InPlaceHolds           = @('UniHabc')
    }
    $holdRow = ConvertTo-LitigationHoldReportRow -Mailbox $holdOnly
    Assert-Equal $holdRow.DisplayName $null 'Hold-only mailbox has no DisplayName'
    Assert-Equal $holdRow.PrimarySmtpAddress $null 'Hold-only mailbox has no SMTP'
    Assert-Equal $holdRow.LitigationHoldDurationDays 90 'converted duration days'
    Assert-Equal $holdRow.LitigationHoldEnabled $true 'hold enabled'

    $complete = [pscustomobject]@{
        DisplayName            = 'Jane Doe'
        UserPrincipalName      = 'jane@contoso.com'
        PrimarySmtpAddress     = 'jane@contoso.com'
        RecipientTypeDetails   = 'UserMailbox'
        LitigationHoldEnabled  = 'True'
        LitigationHoldDuration = 'Unlimited'
        LitigationHoldDate     = $sample
        LitigationHoldOwner    = 'admin@contoso.com'
        IsInactiveMailbox      = $false
        WhenSoftDeleted        = $null
        InPlaceHolds           = @()
        DelayHoldApplied       = $false
        ComplianceTagHoldApplied = $false
    }
    $row = ConvertTo-LitigationHoldReportRow -Mailbox $complete
    Assert-Equal $row.DisplayName 'Jane Doe' 'identity preserved with Minimum set'
    Assert-Equal $row.LitigationHoldDurationDays 'Unlimited' 'unlimited stays Unlimited'
    Assert-Equal $row.IsInactiveMailbox $false 'active mailbox'

    $falseString = [pscustomobject]@{ LitigationHoldEnabled = 'False' }
    Assert-Equal (Test-LitigationHoldEnabled -Mailbox $falseString) $false 'string False is not on hold'

    # Single object from a pipeline must still Count as 1.
    $one = @($complete)
    Assert-Equal $one.Count 1 'array wrap of one mailbox'
    $chars = 0
    foreach ($item in $one) { $chars++ }
    Assert-Equal $chars 1 'foreach over single mailbox is not character enumeration'

    $none = @()
    Assert-Equal $none.Count 0 'empty result count'

    $inner = New-Object System.Exception 'The client and server cannot communicate, because they do not possess a common algorithm'
    $outer = New-Object System.Exception 'An error occurred while sending the request.', $inner
    Assert-Equal (Get-ExceptionMessageChain $outer) 'An error occurred while sending the request. --> The client and server cannot communicate, because they do not possess a common algorithm' 'inner exception chain'
    Assert-Equal (Test-IsTransportFailure -Message $outer.Message) $true 'transport failure detected'

    Enable-Tls12
    $tls12 = [Net.SecurityProtocolType]::Tls12
    Assert-Equal (([Net.ServicePointManager]::SecurityProtocol -band $tls12) -eq $tls12) $true 'TLS 1.2 enabled'

    Write-Host "All self-tests passed." -ForegroundColor Green
}

#endregion

if ($SelfTest) {
    Invoke-LitigationHoldSelfTest
    exit 0
}

#region Setup ------------------------------------------------------------------

# TLS 1.2 MUST be enabled before Import-Module ExchangeOnlineManagement.
# Windows PowerShell 5.1 otherwise fails Connect-ExchangeOnline with
# "An error occurred while sending the request".
Enable-Tls12
Enable-DefaultProxyCredentials

$script:WinFormsLoaded = $false
if ($script:UseGui) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        [void][System.Windows.Forms.Application]::EnableVisualStyles()
        $script:WinFormsLoaded = $true
    }
    catch {
        Write-Host "Failed to load System.Windows.Forms. Pass -OutputCsv to run without a GUI. $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

try {
    Install-ExchangeOnlineModuleIfMissing
}
catch {
    Write-Host "Failed to install ExchangeOnlineManagement module: $(Get-ExceptionMessageChain $_.Exception)" -ForegroundColor Red
    exit 1
}

Import-Module ExchangeOnlineManagement -ErrorAction Stop

$script:WeConnected = $false

try {
    if (Test-ExchangeOnlineConnected) {
        Write-Host "Using existing Exchange Online connection." -ForegroundColor Cyan
    }
    else {
        Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
        Connect-LitigationHoldExchange -UserPrincipalName $UserPrincipalName
        $script:WeConnected = $true
    }

    $includeInactive = -not $SkipInactiveMailboxes
    $querySpec = Get-LitigationHoldQuerySpec -IncludeInactive:$includeInactive
    if ($includeInactive) {
        Write-Host "Inactive (held, then deleted) mailboxes will be included." -ForegroundColor Cyan
    }

    Write-Host "Retrieving mailboxes with Litigation Hold enabled (this can take a while)..." -ForegroundColor Cyan
    $mailboxes = @(Invoke-LitigationHoldMailboxQuery -QuerySpec $querySpec)
    $report = @($mailboxes | ForEach-Object { ConvertTo-LitigationHoldReportRow -Mailbox $_ })

    if ($report.Count -eq 0) {
        Write-Host "No mailboxes with Litigation Hold enabled were found." -ForegroundColor Green
        return
    }

    Write-Host ("`nFound {0} mailbox(es) with Litigation Hold enabled:`n" -f $report.Count) -ForegroundColor Green
    $report |
        Sort-Object DisplayName |
        Format-Table DisplayName, PrimarySmtpAddress, RecipientTypeDetails, LitigationHoldDate, LitigationHoldDurationDays, IsInactiveMailbox -AutoSize |
        Out-String |
        Write-Host

    $targetPath = $OutputCsv
    if ([string]::IsNullOrWhiteSpace($targetPath)) {
        $targetPath = Select-OutputCsv
        if ([string]::IsNullOrWhiteSpace($targetPath)) {
            Write-Host "`nSave cancelled - no report was written." -ForegroundColor Yellow
            return
        }
    }

    $parent = Split-Path -Parent $targetPath
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $report |
        Sort-Object DisplayName |
        Export-Csv -Path $targetPath -NoTypeInformation -Encoding UTF8

    Write-Host "`nReport saved to: $targetPath" -ForegroundColor Green
}
catch {
    $chain = Get-ExceptionMessageChain $_.Exception
    Write-Host "Litigation Hold report failed: $chain" -ForegroundColor Red
    Write-ConnectionFailureHelp -Message $chain
    exit 1
}
finally {
    if ($script:WeConnected -and -not $SkipDisconnect) {
        try {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
            Write-Host "Disconnected from Exchange Online." -ForegroundColor Cyan
        }
        catch {
            Write-Host "Warning: could not disconnect from Exchange Online: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

#endregion

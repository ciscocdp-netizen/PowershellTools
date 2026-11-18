<#
.SYNOPSIS
    Interactively revokes Microsoft 365 / Entra ID sign-in sessions (refresh tokens)
    for a list of users loaded from a CSV file.

.DESCRIPTION
    - Opens a Windows file picker so you can choose the CSV containing user UPNs
      (falls back to a path prompt if the dialog cannot be shown).
    - Detects the UPN column automatically (UserPrincipalName, UPN, Email, Mail...)
      or lets you pick the column if it cannot be detected.
    - Validates, trims and de-duplicates the UPNs.
    - Offers a DRY RUN (no changes) or a LIVE run, with confirmation.
    - Connects to Microsoft Graph and calls POST /users/{id}/revokeSignInSessions
      for each user, with retry/back-off on throttling.
    - On a live run, verifies each revoke by re-reading
      signInSessionsValidFromDateTime (and refreshTokensValidFromDateTime) until
      the timestamp advances, then records Verified / NotVerified in the report.
    - Processes users with Microsoft Graph JSON batching (up to 20 requests
      per HTTP call) so large CSVs are not one round-trip per user.
    - Processes users with Microsoft Graph JSON batching (up to 20 requests
      per HTTP call) so large CSVs are not one round-trip per user.
    - Shows a progress bar and writes a results CSV (chosen via a Save dialog).

    Fixes versus the original script:
    - Auto-relaunches Windows PowerShell in STA so the file picker works with
      powershell.exe -File (MTA would throw or hide the dialog).
    - Sets ShowHelp on WinForms dialogs and uses a real owner form so the picker
      is not stuck behind the console.
    - Sends an empty JSON object on POST revoke; Graph expects
      Content-Type: application/json.
    - Uses [Math]::Min with doubles so retry back-off does not crash on
      Windows PowerShell 5.1 (int vs double overload failure).
    - Reads CSVs as UTF-8, strips a UTF-8 BOM from headers, and honours Excel
      "sep=" lines / semicolon-delimited files.
    - Wraps delimiter counts in @() so StrictMode does not crash when a candidate
      delimiter appears 0 or 1 times in the header (typical CSVs).
    - Resolves each user first, then revokes by object id (UPN %40 encoding
      can 404). Falls back to POST-by-UPN if the account cannot be read.
    - Signs in once with the OAuth device-code flow, stores the access and
      refresh tokens in memory, and sends Bearer tokens on Graph HTTP calls.
      Invoke-MgGraphRequest is not used: that cmdlet asks WAM for a new login
      after every batch. Token refresh is a silent HTTP POST (no prompt).
    - Disconnect at the end defaults to No and only clears this script's
      in-memory tokens.
    - Treats Graph { "value": false } as a failure, honours Retry-After, and
      warns that guest/#EXT# users cannot be revoked in the resource tenant.

.REQUIREMENTS
    - Windows PowerShell 5.1 or PowerShell 7+ on Windows, with outbound HTTPS
      to login.microsoftonline.com and graph.microsoft.com.
    - An admin account able to consent to / use the delegated permission
      User.RevokeSessions.All (or User.ReadWrite.All).
      Roles that can do this include User Administrator, Privileged Authentication
      Administrator, or Global Administrator.

.NOTES
    Revoking sessions invalidates refresh tokens and session cookies. Existing
    access tokens can remain valid until they expire (typically up to 1 hour),
    unless the app supports Continuous Access Evaluation (CAE).

    Guest / B2B users (#EXT#) sign in through their home tenant. Microsoft Graph
    does not revoke those sessions from the resource tenant.

    Verification proves Graph reset the session-validity timestamp. It cannot
    prove that a given access token is already dead: access tokens can remain
    valid until they expire (typically up to 1 hour) unless the app uses CAE.

    Interactive Windows (WAM) sign-in needs a parent window handle. Hosts such
    as PowerShell ISE, VS Code, Cursor, and many embedded terminals have none,
    which produces: "A window handle must be configured." This script therefore
    signs in with OAuth device code (not Connect-MgGraph) and opens
    https://microsoft.com/devicelogin in your default browser. Enter the code
    printed in the console, then complete MFA / admin consent in that browser
    tab. Later Graph batches reuse the access token and refresh it silently.

.PARAMETER SelfTest
    Run built-in regression tests for helpers (CSV, UPN, retry math, Graph URI,
    HTTP status parsing) and exit. Does not connect to Microsoft Graph.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Revoke-M365Sessions.ps1

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Revoke-M365Sessions.ps1 -SelfTest
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:UpnRegex = '^[^@\s]+@[^@\s]+\.[^@\s]+$'

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

function Write-Banner {
    param([string]$Text)
    $line = '=' * 70
    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  " + $Text) -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Write-Info    { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor Gray }
function Write-Ok      { param([string]$m) Write-Host "[ OK ]  $m" -ForegroundColor Green }
function Write-Warn2   { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err2    { param([string]$m) Write-Host "[FAIL]  $m" -ForegroundColor Red }

function Test-IsWindowsOs {
    return ($env:OS -eq 'Windows_NT')
}

function Test-IsUserPrincipalName {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value.Trim() -match $script:UpnRegex)
}

function Test-IsGuestUpn {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value -match '(?i)#EXT#@')
}

function Get-RetryWaitSeconds {
    param(
        [int]$Attempt,
        [int]$CapSeconds = 60,
        [int]$RetryAfterSeconds = 0
    )
    if ($RetryAfterSeconds -gt 0) {
        return [int][Math]::Min([double]$CapSeconds, [double]$RetryAfterSeconds)
    }
    if ($Attempt -lt 1) { $Attempt = 1 }
    $pow = [Math]::Pow(2, $Attempt)
    return [int][Math]::Min([double]$CapSeconds, $pow)
}

function Get-GraphUserPathUri {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserIdOrUpn
    )
    # EscapeDataString turns @ into %40. Some Graph path lookups then 404
    # because they treat the segment as a literal id. Keep '@' unencoded.
    $encoded = [Uri]::EscapeDataString($UserIdOrUpn) -replace '%40', '@'
    return "https://graph.microsoft.com/v1.0/users/$encoded"
}

function Get-GraphUserRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserIdOrUpn,
        [string]$Select = $null,
        [switch]$Revoke
    )
    $encoded = [Uri]::EscapeDataString($UserIdOrUpn) -replace '%40', '@'
    if ($Revoke) {
        return "/users/$encoded/revokeSignInSessions"
    }
    if ([string]::IsNullOrWhiteSpace($Select)) {
        return "/users/$encoded"
    }
    return '/users/{0}?{1}' -f $encoded, ('$select=' + $Select)
}

function Split-IntoChunks {
    param(
        $Items,
        [int]$Size = 20
    )
    $arr = @($Items)
    if ($arr.Count -eq 0 -or $Size -lt 1) { return @() }
    $chunks = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $arr.Count; $i += $Size) {
        $last = [Math]::Min($i + $Size - 1, $arr.Count - 1)
        $chunks.Add(@($arr[$i..$last]))
    }
    if ($chunks.Count -eq 0) { return @() }
    # Unary comma prevents PowerShell from unwrapping a single chunk into loose items.
    return ,$chunks.ToArray()
}

function Get-HttpStatusCode {
    param($ErrorRecord)

    if ($null -eq $ErrorRecord) { return 0 }

    try {
        $ex = $ErrorRecord.Exception
        if ($null -ne $ex) {
            if ($null -ne $ex.PSObject.Properties['Response'] -and $null -ne $ex.Response) {
                $resp = $ex.Response
                if ($null -ne $resp.PSObject.Properties['StatusCode'] -and $null -ne $resp.StatusCode) {
                    return [int]$resp.StatusCode
                }
            }
            if ($null -ne $ex.PSObject.Properties['StatusCode'] -and $null -ne $ex.StatusCode) {
                return [int]$ex.StatusCode
            }
        }
    } catch { }

    $msg = ''
    try {
        if ($null -ne $ErrorRecord.Exception) { $msg = [string]$ErrorRecord.Exception.Message }
    } catch { }
    try {
        if ($null -ne $ErrorRecord.ErrorDetails -and $null -ne $ErrorRecord.ErrorDetails.Message) {
            $msg = ($msg + ' ' + $ErrorRecord.ErrorDetails.Message)
        }
    } catch { }

    if ($msg -match '"code"\s*:\s*"Request_ResourceNotFound"') { return 404 }
    if ($msg -match '"code"\s*:\s*"Authorization_RequestDenied"') { return 403 }
    if ($msg -match '"code"\s*:\s*"TooManyRequests"') { return 429 }
    if ($msg -match '(?i)NotFound|Request_ResourceNotFound|does not exist') { return 404 }
    if ($msg -match '(?i)Forbidden|Authorization_RequestDenied|Insufficient privileges') { return 403 }
    if ($msg -match '(?i)TooManyRequests|throttl') { return 429 }
    if ($msg -match '\b(429|503|504|401|403|404|400|409|500|502)\b') { return [int]$Matches[1] }
    if ($msg -match '\b(4\d\d|5\d\d)\b') { return [int]$Matches[1] }
    return 0
}

function Get-RetryAfterSeconds {
    param(
        $Headers,
        $ErrorRecord
    )
    $raw = $null
    if ($null -ne $Headers) {
        foreach ($key in @('Retry-After', 'retry-after', 'RetryAfter')) {
            try {
                if ($Headers -is [System.Collections.IDictionary] -and $Headers.Contains($key)) {
                    $raw = $Headers[$key]
                    break
                }
            } catch { }
            try {
                if ($null -ne $Headers.PSObject.Properties[$key]) {
                    $raw = $Headers.$key
                    break
                }
            } catch { }
            try {
                $raw = $Headers[$key]
                if ($null -ne $raw) { break }
            } catch { }
        }
    }
    if ($null -eq $raw -and $null -ne $ErrorRecord) {
        $blob = ''
        try { $blob = [string]$ErrorRecord.Exception.Message } catch { }
        try {
            if ($null -ne $ErrorRecord.ErrorDetails) { $blob += ' ' + $ErrorRecord.ErrorDetails.Message }
        } catch { }
        if ($blob -match '(?i)Retry-After:\s*(\d+)') { $raw = $Matches[1] }
    }
    if ($null -eq $raw) { return 0 }
    if ($raw -is [System.Array] -and $raw.Count -gt 0) { $raw = $raw[0] }
    $n = 0
    if ([int]::TryParse([string]$raw, [ref]$n) -and $n -gt 0) { return $n }
    return 0
}

function Get-GraphBooleanValue {
    param($Response)
    if ($null -eq $Response) { return $null }
    try {
        if ($Response -is [System.Collections.IDictionary] -and $Response.Contains('value')) {
            return [bool]$Response['value']
        }
    } catch { }
    try {
        if ($null -ne $Response.PSObject.Properties['value']) {
            return [bool]$Response.value
        }
    } catch { }
    return $null
}

function Get-GraphObjectProperty {
    param(
        $Object,
        [string]$Name
    )
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return $null }
    try {
        if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) {
            return $Object[$Name]
        }
    } catch { }
    try {
        if ($null -ne $Object.PSObject.Properties[$Name]) {
            return $Object.$Name
        }
    } catch { }
    return $null
}

function ConvertTo-UtcDateTime {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return ([datetime]$Value).ToUniversalTime() }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.ToUniversalTime()
    }
    return $null
}

function Format-UtcStamp {
    param($Value)
    $dt = ConvertTo-UtcDateTime $Value
    if ($null -eq $dt) { return '' }
    return $dt.ToString('yyyy-MM-dd HH:mm:ss UTC')
}

function New-SessionStampSet {
    param(
        $SessionsValidFrom = $null,
        $RefreshTokensValidFrom = $null
    )
    return [pscustomobject]@{
        SessionsValidFrom      = $SessionsValidFrom
        RefreshTokensValidFrom = $RefreshTokensValidFrom
    }
}

function Get-UserSessionStamps {
    param($UserObject)
    return New-SessionStampSet `
        -SessionsValidFrom (ConvertTo-UtcDateTime (Get-GraphObjectProperty -Object $UserObject -Name 'signInSessionsValidFromDateTime')) `
        -RefreshTokensValidFrom (ConvertTo-UtcDateTime (Get-GraphObjectProperty -Object $UserObject -Name 'refreshTokensValidFromDateTime'))
}

function Test-RevokeTimestampMoved {
    param(
        $BeforeUtc,
        $AfterUtc,
        $NowUtc,
        [int]$RecentMinutes = 15
    )
    if ($null -eq $AfterUtc) {
        return [pscustomobject]@{
            Verified = $false
            Reason   = 'timestamp was missing after revoke'
        }
    }
    if ($null -ne $BeforeUtc) {
        if ($AfterUtc -gt $BeforeUtc) {
            return [pscustomobject]@{
                Verified = $true
                Reason   = 'timestamp advanced'
            }
        }
        return [pscustomobject]@{
            Verified = $false
            Reason   = 'timestamp did not change'
        }
    }
    if ($null -eq $NowUtc) { $NowUtc = [datetime]::UtcNow }
    $age = $NowUtc - $AfterUtc
    if ($age.TotalMinutes -ge -1 -and $age.TotalMinutes -le $RecentMinutes) {
        return [pscustomobject]@{
            Verified = $true
            Reason   = 'timestamp is recent (no prior baseline)'
        }
    }
    return [pscustomobject]@{
        Verified = $false
        Reason   = 'timestamp is not recent and had no prior baseline'
    }
}

function Test-SessionRevokeEvidence {
    param(
        $Before,
        $After,
        $NowUtc
    )
    if ($null -eq $Before) { $Before = New-SessionStampSet }
    if ($null -eq $After) { $After = New-SessionStampSet }

    $sessionCheck = Test-RevokeTimestampMoved -BeforeUtc $Before.SessionsValidFrom -AfterUtc $After.SessionsValidFrom -NowUtc $NowUtc
    if ($sessionCheck.Verified) {
        return [pscustomobject]@{
            Verified = $true
            Reason   = ('signInSessionsValidFromDateTime {0}' -f $sessionCheck.Reason)
        }
    }

    $refreshCheck = Test-RevokeTimestampMoved -BeforeUtc $Before.RefreshTokensValidFrom -AfterUtc $After.RefreshTokensValidFrom -NowUtc $NowUtc
    if ($refreshCheck.Verified) {
        return [pscustomobject]@{
            Verified = $true
            Reason   = ('refreshTokensValidFromDateTime {0}' -f $refreshCheck.Reason)
        }
    }

    return [pscustomobject]@{
        Verified = $false
        Reason   = ('signInSessionsValidFromDateTime {0}' -f $sessionCheck.Reason)
    }
}

function Get-TextFileEncodingName {
    param([string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $bom = New-Object byte[] 4
        $read = $stream.Read($bom, 0, 4)
        if ($read -ge 3 -and $bom[0] -eq 0xEF -and $bom[1] -eq 0xBB -and $bom[2] -eq 0xBF) { return 'UTF8' }
        if ($read -ge 2 -and $bom[0] -eq 0xFF -and $bom[1] -eq 0xFE) { return 'Unicode' }
        if ($read -ge 2 -and $bom[0] -eq 0xFE -and $bom[1] -eq 0xFF) { return 'BigEndianUnicode' }
        return 'UTF8'
    } finally {
        $stream.Dispose()
    }
}

function Get-CsvDelimiter {
    param(
        [string]$Path,
        [string]$Encoding = 'UTF8'
    )
    $firstLine = Get-Content -Path $Path -Encoding $Encoding -TotalCount 1
    if ($null -eq $firstLine -or [string]::IsNullOrWhiteSpace([string]$firstLine)) { return ',' }
    $firstLine = ([string]$firstLine).TrimStart([char]0xFEFF)
    if ($firstLine -match '^sep=(.)$') { return $Matches[1] }

    $candidates = @(',', ';', "`t", '|')
    $best = ','
    $bestCount = -1
    foreach ($c in $candidates) {
        $ch = $c[0]
        $count = @($firstLine.ToCharArray() | Where-Object { $_ -eq $ch }).Count
        if ($count -gt $bestCount) {
            $best = $c
            $bestCount = $count
        }
    }
    return $best
}

function Convert-CsvRowsNormalized {
    param([object[]]$Rows)
    if ($null -eq $Rows -or $Rows.Count -eq 0) { return @() }

    $names = @($Rows[0].PSObject.Properties.Name)
    $cleaned = New-Object System.Collections.Generic.List[string]
    $changed = $false
    foreach ($n in $names) {
        $c = ([string]$n).Trim().TrimStart([char]0xFEFF)
        if ($c -ne $n) { $changed = $true }
        $cleaned.Add($c)
    }
    if (-not $changed) { return @($Rows) }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($row in $Rows) {
        $h = [ordered]@{}
        for ($i = 0; $i -lt $names.Count; $i++) {
            $h[$cleaned[$i]] = $row.($names[$i])
        }
        $out.Add([pscustomobject]$h)
    }
    return @($out.ToArray())
}

function Read-UserCsv {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "CSV file not found: $Path"
    }

    $encoding = Get-TextFileEncodingName -Path $Path
    $firstLine = Get-Content -Path $Path -Encoding $encoding -TotalCount 1
    $delimiter = Get-CsvDelimiter -Path $Path -Encoding $encoding
    $skipSep = $false
    if ($null -ne $firstLine -and ([string]$firstLine).TrimStart([char]0xFEFF) -match '^sep=(.)$') {
        $delimiter = $Matches[1]
        $skipSep = $true
    }

    $rows = @()
    if ($skipSep) {
        $lines = @(Get-Content -Path $Path -Encoding $encoding)
        if ($lines.Count -le 1) { return @() }
        $csvText = ($lines | Select-Object -Skip 1) -join "`r`n"
        $rows = @(ConvertFrom-Csv -InputObject $csvText -Delimiter $delimiter)
    } else {
        $rows = @(Import-Csv -Path $Path -Delimiter $delimiter -Encoding $encoding)
    }

    return @(Convert-CsvRowsNormalized -Rows $rows)
}

function Get-UpnColumn {
    param(
        [string[]]$Headers,
        [switch]$NoPrompt
    )

    $preferred = @(
        'UserPrincipalName', 'UPN', 'User Principal Name', 'User_Principal_Name',
        'SignInName', 'Email', 'EmailAddress', 'Email Address', 'Mail', 'PrimarySmtpAddress'
    )
    foreach ($p in $preferred) {
        $match = $Headers | Where-Object { $_.Trim() -ieq $p } | Select-Object -First 1
        if ($match) { return $match }
    }

    if ($Headers.Count -eq 1) { return $Headers[0] }
    if ($NoPrompt) { return $null }

    Write-Warn2 "Could not automatically detect the UPN column."
    $index = Read-Choice -Title 'Which column contains the users'' UPNs?' -Options $Headers
    return $Headers[$index]
}

function Read-YesNo {
    param(
        [string]$Prompt,
        [bool]$Default = $false
    )
    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = Read-Host "$Prompt $suffix"
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        switch -Regex ($answer.Trim()) {
            '^(y|yes)$' { return $true }
            '^(n|no)$'  { return $false }
            default     { Write-Warn2 "Please answer Y or N." }
        }
    }
}

function Read-Choice {
    param(
        [string]$Title,
        [string[]]$Options
    )
    Write-Host ''
    Write-Host $Title -ForegroundColor White
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $Options[$i])
    }
    while ($true) {
        $raw = Read-Host "Enter a number (1-$($Options.Count))"
        $n = 0
        if ([int]::TryParse($raw, [ref]$n) -and $n -ge 1 -and $n -le $Options.Count) {
            return ($n - 1)
        }
        Write-Warn2 "Invalid selection."
    }
}

function Show-TopMostFileDialog {
    param(
        $Dialog
    )
    $Dialog.ShowHelp = $true

    $owner = New-Object System.Windows.Forms.Form
    $owner.TopMost = $true
    $owner.ShowInTaskbar = $false
    $owner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
    $owner.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
    $owner.Location = New-Object System.Drawing.Point -ArgumentList @(-2000, -2000)
    $owner.Size = New-Object System.Drawing.Size -ArgumentList @(1, 1)
    try {
        [void]$owner.Show()
        $owner.Activate()
        return $Dialog.ShowDialog($owner)
    } finally {
        $owner.Dispose()
        Reset-UiSynchronizationContext
    }
}

function Select-CsvFile {
    if (-not (Test-IsWindowsOs)) {
        $path = Read-Host 'Enter the full path to the CSV file containing user UPNs'
        if ([string]::IsNullOrWhiteSpace($path)) { return $null }
        return $path.Trim().Trim('"')
    }

    try {
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        Add-Type -AssemblyName System.Drawing | Out-Null
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title            = 'Select the CSV file containing user UPNs'
        $dialog.Filter           = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
        $dialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')
        if ([string]::IsNullOrWhiteSpace($dialog.InitialDirectory) -or -not (Test-Path -LiteralPath $dialog.InitialDirectory)) {
            $dialog.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
        }
        $dialog.Multiselect      = $false
        $dialog.CheckFileExists  = $true
        $result = Show-TopMostFileDialog -Dialog $dialog
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.FileName }
        return $null
    } catch {
        Write-Warn2 "File picker could not be opened: $($_.Exception.Message)"
        $path = Read-Host 'Enter the full path to the CSV file containing user UPNs'
        if ([string]::IsNullOrWhiteSpace($path)) { return $null }
        return $path.Trim().Trim('"')
    }
}

function Select-SaveFile {
    param([string]$DefaultName, [string]$InitialDirectory)

    if (-not (Test-IsWindowsOs)) {
        $path = Read-Host "Enter a path to save the results CSV (default: $DefaultName)"
        if ([string]::IsNullOrWhiteSpace($path)) {
            if ([string]::IsNullOrWhiteSpace($InitialDirectory)) { $InitialDirectory = (Get-Location).Path }
            return (Join-Path -Path $InitialDirectory -ChildPath $DefaultName)
        }
        return $path.Trim().Trim('"')
    }

    try {
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        Add-Type -AssemblyName System.Drawing | Out-Null
        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Title            = 'Save results report'
        $dialog.Filter           = 'CSV files (*.csv)|*.csv'
        $dialog.FileName         = $DefaultName
        $dialog.InitialDirectory = $InitialDirectory
        $dialog.OverwritePrompt  = $true
        $dialog.AddExtension     = $true
        $dialog.DefaultExt       = 'csv'
        $result = Show-TopMostFileDialog -Dialog $dialog
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.FileName }
        return $null
    } catch {
        Write-Warn2 "Save dialog could not be opened: $($_.Exception.Message)"
        $path = Read-Host "Enter a path to save the results CSV"
        if ([string]::IsNullOrWhiteSpace($path)) { return $null }
        return $path.Trim().Trim('"')
    }
}

function Restart-InStaIfNeeded {
    if ($SelfTest) { return }
    if (-not (Test-IsWindowsOs)) { return }

    $state = [Threading.Thread]::CurrentThread.GetApartmentState()
    if ($state -eq 'STA') { return }

    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        Write-Warn2 "PowerShell is not running in STA mode; the file picker may not open."
        Write-Warn2 "Run with: powershell.exe -STA -File .\Revoke-M365Sessions.ps1"
        return
    }

    $exe = Join-Path -Path $PSHOME -ChildPath 'powershell.exe'
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $pwsh = Get-Command -Name pwsh -ErrorAction SilentlyContinue
        if ($pwsh) { $exe = $pwsh.Source }
    }

    Write-Info "Relaunching in STA mode so file dialogs work (current apartment: $state)..."
    $argList = @(
        '-STA'
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-File', $PSCommandPath
    )
    $proc = Start-Process -FilePath $exe -ArgumentList $argList -Wait -PassThru -NoNewWindow
    if ($null -ne $proc) {
        exit $proc.ExitCode
    }
    exit 1
}

function Disable-GraphInteractiveBroker {
    # Device-code tokens are otherwise refreshed via WAM, which prompts again
    # (or fails with "window handle must be configured") on every Graph call.
    $env:AZURE_IDENTITY_DISABLE_CP1 = 'true'
    $env:AZURE_IDENTITY_DISABLE_BROKER = 'true'
    $env:MSAL_DISABLE_BROKER = 'true'
    $cmd = Get-Command Set-MgGraphOption -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { return }
    if ($cmd.Parameters.ContainsKey('DisableLoginByWAM')) {
        try { Set-MgGraphOption -DisableLoginByWAM $true } catch { }
    }
    if ($cmd.Parameters.ContainsKey('EnableLoginByWAM')) {
        try { Set-MgGraphOption -EnableLoginByWAM $false } catch { }
    }
}

function Initialize-GraphHttp {
    Disable-GraphInteractiveBroker
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }
}

function Get-NormalizedGraphScopeSet {
    param([string[]]$CurrentScopes)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($raw in @($CurrentScopes)) {
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        foreach ($part in @($raw -split '[,\s]+')) {
            $s = $part.Trim()
            if ([string]::IsNullOrWhiteSpace($s)) { continue }
            foreach ($prefix in @('https://graph.microsoft.com/', 'http://graph.microsoft.com/')) {
                if ($s.Length -gt $prefix.Length -and $s.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                    $s = $s.Substring($prefix.Length)
                    break
                }
            }
            [void]$set.Add($s)
        }
    }
    # Unary comma keeps the HashSet intact; PowerShell otherwise unwraps it
    # (one scope becomes a string and .Count fails under StrictMode).
    return ,$set
}

function Test-GraphScopesSufficient {
    param([string[]]$CurrentScopes)
    $set = Get-NormalizedGraphScopeSet -CurrentScopes $CurrentScopes
    if ($set.Count -eq 0) { return $false }
    $canRevoke = $set.Contains('User.RevokeSessions.All') -or
                 $set.Contains('User.ReadWrite.All') -or
                 $set.Contains('Directory.ReadWrite.All') -or
                 $set.Contains('Directory.AccessAsUser.All')
    $canRead   = $set.Contains('User.Read.All') -or
                 $set.Contains('User.ReadWrite.All') -or
                 $set.Contains('Directory.Read.All') -or
                 $set.Contains('Directory.ReadWrite.All') -or
                 $set.Contains('Directory.AccessAsUser.All')
    return ($canRevoke -and $canRead)
}

# Microsoft Graph PowerShell public client (same app Connect-MgGraph uses).
$script:GraphPublicClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
$script:GraphOAuthScopeString = 'https://graph.microsoft.com/User.RevokeSessions.All https://graph.microsoft.com/User.Read.All https://graph.microsoft.com/User.ReadWrite.All offline_access openid profile'
$script:DeviceLoginUrl = 'https://microsoft.com/devicelogin'
$script:GraphAccessToken = $null
$script:GraphRefreshToken = $null
$script:GraphTokenExpiresOn = [datetime]::MinValue
$script:GraphTokenAccount = $null
$script:GraphTokenTenant = $null
$script:GraphTokenScopes = @()
$script:GraphOAuthTenant = 'organizations'

function ConvertTo-JsonForGraph {
    param($Object, [int]$Depth = 12)
    if ($null -eq $Object) { return '{}' }
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return ($Object | ConvertTo-Json -Depth $Depth -Compress)
    }
    if (-not ('System.Web.Script.Serialization.JavaScriptSerializer' -as [type])) {
        Add-Type -AssemblyName System.Web.Extensions
    }
    $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $ser.MaxJsonLength = [int]::MaxValue
    $ser.RecursionLimit = [Math]::Max(100, $Depth)
    return $ser.Serialize($Object)
}

function ConvertFrom-JsonObject {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    return ($Text | ConvertFrom-Json)
}

function ConvertFrom-JwtPayload {
    param([string]$Jwt)
    if ([string]::IsNullOrWhiteSpace($Jwt)) { return $null }
    $parts = @($Jwt.Split('.'))
    if ($parts.Count -lt 2) { return $null }
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }
    try {
        $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return (ConvertFrom-JsonObject -Text $json)
    } catch {
        return $null
    }
}

function Get-WebExceptionBody {
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return '' }
    try {
        if ($null -ne $ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace([string]$ErrorRecord.ErrorDetails.Message)) {
            return [string]$ErrorRecord.ErrorDetails.Message
        }
    } catch { }
    try {
        $resp = $ErrorRecord.Exception.Response
        if ($null -eq $resp) { return '' }
        if ($null -ne $resp.PSObject.Properties['Content'] -and $null -ne $resp.Content) {
            $task = $resp.Content.ReadAsStringAsync()
            return [string]$task.GetAwaiter().GetResult()
        }
        $stream = $resp.GetResponseStream()
        if ($null -eq $stream) { return '' }
        $reader = New-Object System.IO.StreamReader($stream)
        try { return [string]$reader.ReadToEnd() } finally { $reader.Dispose() }
    } catch {
        return ''
    }
}

function Invoke-WebRequestRaw {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [hashtable]$Headers,
        $Body,
        [string]$ContentType,
        [int]$TimeoutSec = 300
    )

    $params = @{
        Method          = $Method
        Uri             = $Uri
        UseBasicParsing = $true
        TimeoutSec      = $TimeoutSec
        ErrorAction     = 'Stop'
    }
    if ($Headers -and $Headers.Count -gt 0) { $params['Headers'] = $Headers }
    if ($PSBoundParameters.ContainsKey('Body')) { $params['Body'] = $Body }
    if (-not [string]::IsNullOrWhiteSpace($ContentType)) { $params['ContentType'] = $ContentType }
    $cmd = Get-Command Invoke-WebRequest -ErrorAction Stop
    if ($cmd.Parameters.ContainsKey('SkipHttpErrorCheck')) {
        $params['SkipHttpErrorCheck'] = $true
    }

    try {
        $response = Invoke-WebRequest @params
        return [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Content    = [string]$response.Content
            Headers    = $response.Headers
            Error      = $null
        }
    } catch {
        $code = Get-HttpStatusCode -ErrorRecord $_
        $text = Get-WebExceptionBody -ErrorRecord $_
        if ($code -lt 1) { $code = 0 }
        return [pscustomobject]@{
            StatusCode = $code
            Content    = $text
            Headers    = $(if ($_.Exception.Response) { $_.Exception.Response.Headers } else { $null })
            Error      = $_.Exception.Message
        }
    }
}

function ConvertTo-FormUrlEncoded {
    param([hashtable]$Fields)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($key in $Fields.Keys) {
        $parts.Add(('{0}={1}' -f [Uri]::EscapeDataString([string]$key), [Uri]::EscapeDataString([string]$Fields[$key])))
    }
    return [string]::Join('&', $parts.ToArray())
}

function Get-OAuthErrorCode {
    param($Object)
    $code = [string](Get-GraphObjectProperty -Object $Object -Name 'error')
    if (-not [string]::IsNullOrWhiteSpace($code)) { return $code }
    return ''
}

function Invoke-OAuthFormPost {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $true)]
        [hashtable]$Fields
    )
    $body = ConvertTo-FormUrlEncoded -Fields $Fields
    $raw = Invoke-WebRequestRaw -Method POST -Uri $Uri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $json = $null
    try { $json = ConvertFrom-JsonObject -Text $raw.Content } catch { $json = $null }
    $oauthError = Get-OAuthErrorCode -Object $json
    if ($raw.StatusCode -ge 200 -and $raw.StatusCode -lt 300 -and [string]::IsNullOrWhiteSpace($oauthError)) {
        return [pscustomobject]@{ Ok = $true; StatusCode = $raw.StatusCode; Content = $json; Error = $null; ErrorCode = '' }
    }
    $detail = $oauthError
    $desc = [string](Get-GraphObjectProperty -Object $json -Name 'error_description')
    if (-not [string]::IsNullOrWhiteSpace($desc)) {
        if ([string]::IsNullOrWhiteSpace($detail)) { $detail = $desc } else { $detail = '{0}: {1}' -f $detail, $desc }
    }
    if ([string]::IsNullOrWhiteSpace($detail)) { $detail = $raw.Error }
    if ([string]::IsNullOrWhiteSpace($detail)) { $detail = "OAuth HTTP $($raw.StatusCode)" }
    return [pscustomobject]@{
        Ok         = $false
        StatusCode = $raw.StatusCode
        Content    = $json
        Error      = $detail
        ErrorCode  = $oauthError
    }
}

function Get-GraphOAuthAuthority {
    param([string]$Tenant)
    $id = 'organizations'
    if (-not [string]::IsNullOrWhiteSpace($Tenant)) { $id = $Tenant.Trim() }
    return "https://login.microsoftonline.com/$id/oauth2/v2.0"
}

function Test-GraphAccessTokenFresh {
    param([int]$SkewSeconds = 180)
    if ([string]::IsNullOrWhiteSpace([string]$script:GraphAccessToken)) { return $false }
    if ($null -eq $script:GraphTokenExpiresOn) { return $false }
    return ([datetime]::UtcNow.AddSeconds($SkewSeconds) -lt $script:GraphTokenExpiresOn.ToUniversalTime())
}

function Clear-GraphTokenCache {
    $script:GraphAccessToken = $null
    $script:GraphRefreshToken = $null
    $script:GraphTokenExpiresOn = [datetime]::MinValue
    $script:GraphTokenAccount = $null
    $script:GraphTokenTenant = $null
    $script:GraphTokenScopes = @()
}

function Set-GraphTokenFromOAuthResponse {
    param($Response)
    $access = [string](Get-GraphObjectProperty -Object $Response -Name 'access_token')
    if ([string]::IsNullOrWhiteSpace($access)) {
        throw 'Token response did not include access_token.'
    }
    $script:GraphAccessToken = $access
    $refresh = [string](Get-GraphObjectProperty -Object $Response -Name 'refresh_token')
    if (-not [string]::IsNullOrWhiteSpace($refresh)) {
        $script:GraphRefreshToken = $refresh
    }
    $expiresIn = 3600
    $rawExpires = Get-GraphObjectProperty -Object $Response -Name 'expires_in'
    if ($null -ne $rawExpires) {
        $parsed = 0
        if ([int]::TryParse([string]$rawExpires, [ref]$parsed) -and $parsed -gt 0) {
            $expiresIn = $parsed
        }
    }
    $script:GraphTokenExpiresOn = [datetime]::UtcNow.AddSeconds([Math]::Max(60, $expiresIn))
    $scopeText = [string](Get-GraphObjectProperty -Object $Response -Name 'scope')
    if ([string]::IsNullOrWhiteSpace($scopeText)) { $scopeText = $script:GraphOAuthScopeString }
    $script:GraphTokenScopes = @(@($scopeText -split '\s+') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    $jwt = ConvertFrom-JwtPayload -Jwt $access
    $account = [string](Get-GraphObjectProperty -Object $jwt -Name 'upn')
    if ([string]::IsNullOrWhiteSpace($account)) {
        $account = [string](Get-GraphObjectProperty -Object $jwt -Name 'preferred_username')
    }
    if ([string]::IsNullOrWhiteSpace($account)) {
        $account = [string](Get-GraphObjectProperty -Object $jwt -Name 'unique_name')
    }
    if (-not [string]::IsNullOrWhiteSpace($account)) { $script:GraphTokenAccount = $account }
    $tid = [string](Get-GraphObjectProperty -Object $jwt -Name 'tid')
    if (-not [string]::IsNullOrWhiteSpace($tid)) { $script:GraphTokenTenant = $tid }
}

function Update-GraphTokenFromRefresh {
    if ([string]::IsNullOrWhiteSpace([string]$script:GraphRefreshToken)) { return $false }
    $uri = (Get-GraphOAuthAuthority -Tenant $script:GraphOAuthTenant) + '/token'
    $result = Invoke-OAuthFormPost -Uri $uri -Fields @{
        client_id     = $script:GraphPublicClientId
        grant_type    = 'refresh_token'
        refresh_token = $script:GraphRefreshToken
        scope         = $script:GraphOAuthScopeString
    }
    if (-not $result.Ok) {
        Write-Warn2 ("Silent Graph token refresh failed: {0}" -f $result.Error)
        return $false
    }
    Set-GraphTokenFromOAuthResponse -Response $result.Content
    return $true
}

function Get-GraphAccessToken {
    param([switch]$ForceRefresh)
    if ($ForceRefresh) {
        if (Update-GraphTokenFromRefresh) { return $script:GraphAccessToken }
        throw 'The Microsoft Graph access token could not be refreshed silently. Re-run the script to sign in once.'
    }
    if (Test-GraphAccessTokenFresh) { return $script:GraphAccessToken }
    if (Update-GraphTokenFromRefresh) { return $script:GraphAccessToken }
    if (-not [string]::IsNullOrWhiteSpace([string]$script:GraphAccessToken)) {
        return $script:GraphAccessToken
    }
    throw 'No Microsoft Graph access token is available. Sign in first.'
}

function Get-CurrentGraphContext {
    if ([string]::IsNullOrWhiteSpace([string]$script:GraphAccessToken)) { return $null }
    $account = $script:GraphTokenAccount
    if ([string]::IsNullOrWhiteSpace($account)) { $account = '(signed-in Graph session)' }
    return [pscustomobject]@{
        Account  = $account
        TenantId = $script:GraphTokenTenant
        Scopes   = @($script:GraphTokenScopes)
        AuthType = 'DeviceCode'
    }
}

function Invoke-GraphApi {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        $Body,
        [int]$MaxRetries = 5
    )

    $attempt = 0
    $didRefreshOn401 = $false

    while ($true) {
        $attempt++
        $token = Get-GraphAccessToken
        $headers = @{
            Authorization = "Bearer $token"
            Accept        = 'application/json'
        }

        $rawBody = $null
        $contentType = $null
        if ($Method -eq 'POST') {
            $payload = @{}
            if ($PSBoundParameters.ContainsKey('Body')) { $payload = $Body }
            $json = ConvertTo-JsonForGraph -Object $payload
            $rawBody = [System.Text.Encoding]::UTF8.GetBytes($json)
            $contentType = 'application/json; charset=utf-8'
        }

        $raw = $null
        if ($Method -eq 'POST') {
            $raw = Invoke-WebRequestRaw -Method $Method -Uri $Uri -Headers $headers -Body $rawBody -ContentType $contentType
        } else {
            $raw = Invoke-WebRequestRaw -Method $Method -Uri $Uri -Headers $headers
        }

        $code = [int]$raw.StatusCode
        if ($code -eq 401 -and -not $didRefreshOn401) {
            $didRefreshOn401 = $true
            Write-Warn2 'Graph returned 401. Refreshing the access token silently (no login prompt)...'
            try {
                $null = Get-GraphAccessToken -ForceRefresh
                continue
            } catch {
                return [pscustomobject]@{
                    Ok         = $false
                    StatusCode = 401
                    Content    = $null
                    Headers    = $raw.Headers
                    Attempts   = $attempt
                    Error      = $_.Exception.Message
                }
            }
        }

        if ($code -ge 200 -and $code -lt 300) {
            $parsed = $null
            try { $parsed = ConvertFrom-JsonObject -Text $raw.Content } catch { $parsed = $raw.Content }
            return [pscustomobject]@{
                Ok         = $true
                StatusCode = $code
                Content    = $parsed
                Headers    = $raw.Headers
                Attempts   = $attempt
                Error      = $null
            }
        }

        $retryAfter = Get-RetryAfterSeconds -Headers $raw.Headers -ErrorRecord $null
        if (($code -eq 429 -or $code -eq 503 -or $code -eq 504) -and $attempt -lt $MaxRetries) {
            $wait = Get-RetryWaitSeconds -Attempt $attempt -RetryAfterSeconds $retryAfter
            Write-Warn2 "Throttled/unavailable (HTTP $code). Retrying in $wait s (attempt $attempt of $MaxRetries)..."
            Start-Sleep -Seconds $wait
            continue
        }

        $message = $raw.Error
        $errObj = $null
        try { $errObj = ConvertFrom-JsonObject -Text $raw.Content } catch { $errObj = $null }
        $graphMsg = [string](Get-GraphObjectProperty -Object (Get-GraphObjectProperty -Object $errObj -Name 'error') -Name 'message')
        if (-not [string]::IsNullOrWhiteSpace($graphMsg)) { $message = $graphMsg }
        if ([string]::IsNullOrWhiteSpace($message)) { $message = "Graph request failed with HTTP $code for $Uri" }

        return [pscustomobject]@{
            Ok         = $false
            StatusCode = $code
            Content    = $errObj
            Headers    = $raw.Headers
            Attempts   = $attempt
            Error      = $message
        }
    }
}

function Get-GraphBatchResponseItems {
    param($Content)
    if ($null -eq $Content) { return @() }
    $items = Get-GraphObjectProperty -Object $Content -Name 'responses'
    if ($null -eq $items) { return @() }
    return @($items)
}

function Invoke-GraphBatch {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Requests,
        [int]$MaxRetries = 5
    )
    $uri = 'https://graph.microsoft.com/v1.0/$batch'
    $body = @{ requests = @($Requests) }
    $response = Invoke-GraphApi -Method POST -Uri $uri -Body $body -MaxRetries $MaxRetries
    if (-not $response.Ok) {
        return [pscustomobject]@{
            Ok       = $false
            Attempts = $response.Attempts
            Error    = $response.Error
            ById     = @{}
        }
    }

    $byId = @{}
    foreach ($item in (Get-GraphBatchResponseItems -Content $response.Content)) {
        $id = [string](Get-GraphObjectProperty -Object $item -Name 'id')
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $byId[$id] = $item
        }
    }
    return [pscustomobject]@{
        Ok       = $true
        Attempts = $response.Attempts
        Error    = $null
        ById     = $byId
    }
}

function Get-BatchItemStatusCode {
    param($Item)
    if ($null -eq $Item) { return 0 }
    $raw = Get-GraphObjectProperty -Object $Item -Name 'status'
    $n = 0
    if ([int]::TryParse([string]$raw, [ref]$n)) { return $n }
    return 0
}

function Get-BatchItemErrorMessage {
    param($Item)
    $body = Get-GraphObjectProperty -Object $Item -Name 'body'
    $err = Get-GraphObjectProperty -Object $body -Name 'error'
    $msg = Get-GraphObjectProperty -Object $err -Name 'message'
    if (-not [string]::IsNullOrWhiteSpace([string]$msg)) { return [string]$msg }
    $code = Get-GraphObjectProperty -Object $err -Name 'code'
    if (-not [string]::IsNullOrWhiteSpace([string]$code)) { return [string]$code }
    return 'Graph batch item failed'
}

function ConvertTo-GraphUserLookup {
    param(
        $Body,
        [int]$StatusCode,
        [int]$Attempts = 1,
        [string]$ErrorMessage = $null
    )
    if ($StatusCode -ge 200 -and $StatusCode -lt 300) {
        return [pscustomobject]@{
            Status      = 'Found'
            Id          = [string](Get-GraphObjectProperty -Object $Body -Name 'id')
            DisplayName = [string](Get-GraphObjectProperty -Object $Body -Name 'displayName')
            UserType    = [string](Get-GraphObjectProperty -Object $Body -Name 'userType')
            Stamps      = (Get-UserSessionStamps -UserObject $Body)
            Detail      = 'User found'
            Attempts    = $Attempts
        }
    }
    $status = switch ($StatusCode) {
        404     { 'NotFound' }
        403     { 'AccessDenied' }
        401     { 'AccessDenied' }
        default { 'Failed' }
    }
    if ([string]::IsNullOrWhiteSpace($ErrorMessage)) { $ErrorMessage = "HTTP $StatusCode" }
    return [pscustomobject]@{
        Status      = $status
        Id          = $null
        DisplayName = $null
        UserType    = $null
        Stamps      = (New-SessionStampSet)
        Detail      = $ErrorMessage
        Attempts    = $Attempts
    }
}

function Resolve-GraphUser {
    param([string]$Upn)

    $select = 'id,displayName,userPrincipalName,accountEnabled,userType,signInSessionsValidFromDateTime,refreshTokensValidFromDateTime'
    $uri = '{0}?{1}' -f (Get-GraphUserPathUri -UserIdOrUpn $Upn), ('$select=' + $select)
    $response = Invoke-GraphApi -Method GET -Uri $uri
    if ($response.Ok) {
        return ConvertTo-GraphUserLookup -Body $response.Content -StatusCode 200 -Attempts $response.Attempts
    }
    return ConvertTo-GraphUserLookup -Body $null -StatusCode $response.StatusCode -Attempts $response.Attempts -ErrorMessage $response.Error
}

function Invoke-RevokeSession {
    param(
        [string]$Upn,
        [string]$UserId,
        [int]$MaxRetries = 5
    )

    $target = $null
    if (-not [string]::IsNullOrWhiteSpace($UserId)) {
        $target = "https://graph.microsoft.com/v1.0/users/$UserId/revokeSignInSessions"
    } else {
        $target = (Get-GraphUserPathUri -UserIdOrUpn $Upn) + '/revokeSignInSessions'
    }

    $response = Invoke-GraphApi -Method POST -Uri $target -MaxRetries $MaxRetries
    if ($response.Ok) {
        $flag = Get-GraphBooleanValue -Response $response.Content
        if ($false -eq $flag) {
            return [pscustomobject]@{
                Status   = 'Failed'
                Detail   = 'Graph returned value=false (sessions were not revoked)'
                Attempts = $response.Attempts
            }
        }
        return [pscustomobject]@{
            Status   = 'Revoked'
            Detail   = 'Sign-in sessions revoked'
            Attempts = $response.Attempts
        }
    }

    $status = switch ($response.StatusCode) {
        404     { 'NotFound' }
        403     { 'AccessDenied' }
        401     { 'AccessDenied' }
        default { 'Failed' }
    }
    return [pscustomobject]@{
        Status   = $status
        Detail   = $response.Error
        Attempts = $response.Attempts
    }
}

function Confirm-RevokedSignInSession {
    param(
        [string]$Upn,
        [string]$UserId,
        $BeforeStamps,
        [int]$MaxAttempts = 2,
        [int]$DelaySeconds = 1
    )

    if ($null -eq $BeforeStamps) { $BeforeStamps = New-SessionStampSet }

    $userUri = $null
    if (-not [string]::IsNullOrWhiteSpace($UserId)) {
        $userUri = "https://graph.microsoft.com/v1.0/users/$UserId"
    } else {
        $userUri = Get-GraphUserPathUri -UserIdOrUpn $Upn
    }
    $select = '$select=id,signInSessionsValidFromDateTime,refreshTokensValidFromDateTime'
    $uri = '{0}?{1}' -f $userUri, $select

    $lastDetail = 'Verification GET did not run'
    $after = New-SessionStampSet
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        if ($i -gt 1) { Start-Sleep -Seconds $DelaySeconds }
        $response = Invoke-GraphApi -Method GET -Uri $uri
        if (-not $response.Ok) {
            $lastDetail = $response.Error
            if ($i -ge $MaxAttempts) {
                return [pscustomobject]@{
                    Status              = 'CheckFailed'
                    Detail              = "Could not re-read user after revoke: $lastDetail"
                    SessionsValidFrom   = $null
                    RefreshTokensValidFrom = $null
                    Attempts            = $i
                }
            }
            continue
        }

        $after = Get-UserSessionStamps -UserObject $response.Content
        $check = Test-SessionRevokeEvidence -Before $BeforeStamps -After $after -NowUtc ([datetime]::UtcNow)
        if ($check.Verified) {
            return [pscustomobject]@{
                Status                 = 'Verified'
                Detail                 = $check.Reason
                SessionsValidFrom      = $after.SessionsValidFrom
                RefreshTokensValidFrom = $after.RefreshTokensValidFrom
                Attempts               = $i
            }
        }
        $lastDetail = $check.Reason
    }

    return [pscustomobject]@{
        Status                 = 'NotVerified'
        Detail                 = $lastDetail
        SessionsValidFrom      = $after.SessionsValidFrom
        RefreshTokensValidFrom = $after.RefreshTokensValidFrom
        Attempts               = $MaxAttempts
    }
}

$script:GraphUserSelect = 'id,displayName,userPrincipalName,accountEnabled,userType,signInSessionsValidFromDateTime,refreshTokensValidFromDateTime'
$script:GraphStampSelect = 'id,signInSessionsValidFromDateTime,refreshTokensValidFromDateTime'
$script:GraphBatchSize = 20

function New-ProcessedUserResult {
    param(
        [string]$Upn,
        [string]$DisplayName = $null,
        [string]$Status,
        [string]$Verification = 'Skipped',
        [string]$VerificationDetail = 'Verification not run',
        $StampBefore = $null,
        $StampAfter = $null,
        [string]$Detail,
        [int]$Attempts = 1,
        [bool]$DryRun = $false
    )
    return [pscustomobject]@{
        UserPrincipalName       = $Upn
        DisplayName             = $DisplayName
        Status                  = $Status
        Verification            = $Verification
        VerificationDetail      = $VerificationDetail
        SessionsValidFromBefore = (Format-UtcStamp $StampBefore)
        SessionsValidFromAfter  = (Format-UtcStamp $StampAfter)
        Detail                  = $Detail
        Attempts                = $Attempts
        Mode                    = $(if ($DryRun) { 'DryRun' } else { 'Live' })
        Timestamp               = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }
}

function Invoke-RevokeUserSequential {
    param(
        [string]$Upn,
        [bool]$DryRun,
        [bool]$VerifyRevoke
    )

    $lookup = Resolve-GraphUser -Upn $Upn
    $guestNote = $null
    if ((Test-IsGuestUpn $Upn) -or ($lookup.UserType -eq 'Guest')) {
        $guestNote = 'Guest/B2B: Graph does not revoke home-tenant sessions from this tenant.'
    }
    $stampBefore = $null
    if ($null -ne $lookup.Stamps) { $stampBefore = $lookup.Stamps.SessionsValidFrom }

    $verification = 'Skipped'
    $verifyDetail = 'Verification not run'
    $stampAfter = $null
    $status = $lookup.Status
    $detail = $lookup.Detail
    $attempts = $lookup.Attempts

    if ($DryRun) {
        if ($lookup.Status -eq 'Found') {
            $status = 'WouldRevoke'
            $detail = 'User found (dry run, no change made)'
            if ($guestNote) { $detail = $detail + ' ' + $guestNote }
        }
    } elseif ($lookup.Status -ne 'NotFound') {
        $userId = $null
        if ($lookup.Status -eq 'Found') { $userId = $lookup.Id }
        $outcome = Invoke-RevokeSession -Upn $Upn -UserId $userId
        $status = $outcome.Status
        $detail = $outcome.Detail
        $attempts = $outcome.Attempts
        if ($guestNote -and $status -eq 'Revoked') { $detail = $detail + ' ' + $guestNote }
        if ($VerifyRevoke -and $status -eq 'Revoked') {
            $check = Confirm-RevokedSignInSession -Upn $Upn -UserId $userId -BeforeStamps $lookup.Stamps
            $verification = $check.Status
            $verifyDetail = $check.Detail
            $stampAfter = $check.SessionsValidFrom
            if ($verification -eq 'Verified') {
                $detail = $detail + " Verified: $verifyDetail."
            } elseif ($verification -eq 'NotVerified') {
                $detail = $detail + " Not verified: $verifyDetail."
            } else {
                $detail = $detail + " Verification check failed: $verifyDetail."
            }
        }
    }

    return New-ProcessedUserResult -Upn $Upn -DisplayName $lookup.DisplayName -Status $status `
        -Verification $verification -VerificationDetail $verifyDetail `
        -StampBefore $stampBefore -StampAfter $stampAfter -Detail $detail `
        -Attempts $attempts -DryRun $DryRun
}

function Update-ChunkVerification {
    param(
        [int[]]$Indexes,
        [object[]]$Results,
        $Lookups,
        [string[]]$Upns,
        [int]$Attempt
    )
    $still = New-Object System.Collections.Generic.List[int]
    $vReqs = New-Object System.Collections.Generic.List[object]
    foreach ($i in @($Indexes)) {
        $lookup = $Lookups[$i]
        $target = $Upns[$i]
        if ($lookup.Status -eq 'Found' -and -not [string]::IsNullOrWhiteSpace($lookup.Id)) {
            $target = $lookup.Id
        }
        $vReqs.Add(@{
            id     = "v$i"
            method = 'GET'
            url    = (Get-GraphUserRelativePath -UserIdOrUpn $target -Select $script:GraphStampSelect)
        })
    }
    $vBatch = Invoke-GraphBatch -Requests @($vReqs.ToArray())
    if (-not $vBatch.Ok) {
        foreach ($i in @($Indexes)) {
            $Results[$i].Verification = 'CheckFailed'
            $Results[$i].VerificationDetail = $vBatch.Error
            $Results[$i].Detail = $Results[$i].Detail + " Verification check failed: $($vBatch.Error)."
        }
        return @()
    }
    foreach ($i in @($Indexes)) {
        $item = $null
        if ($vBatch.ById.ContainsKey("v$i")) { $item = $vBatch.ById["v$i"] }
        $code = Get-BatchItemStatusCode -Item $item
        if ($code -lt 200 -or $code -ge 300) {
            $Results[$i].Verification = 'CheckFailed'
            $Results[$i].VerificationDetail = (Get-BatchItemErrorMessage -Item $item)
            $Results[$i].Detail = $Results[$i].Detail + " Verification check failed: $($Results[$i].VerificationDetail)."
            $still.Add($i)
            continue
        }
        $after = Get-UserSessionStamps -UserObject (Get-GraphObjectProperty -Object $item -Name 'body')
        $check = Test-SessionRevokeEvidence -Before $Lookups[$i].Stamps -After $after -NowUtc ([datetime]::UtcNow)
        $Results[$i].SessionsValidFromAfter = (Format-UtcStamp $after.SessionsValidFrom)
        if ($check.Verified) {
            $Results[$i].Verification = 'Verified'
            $Results[$i].VerificationDetail = $check.Reason
            $Results[$i].Detail = $Results[$i].Detail + " Verified: $($check.Reason)."
        } else {
            $Results[$i].Verification = 'NotVerified'
            $Results[$i].VerificationDetail = $check.Reason
            if ($Attempt -ge 2) {
                $Results[$i].Detail = $Results[$i].Detail + " Not verified: $($check.Reason)."
            }
            $still.Add($i)
        }
    }
    return @($still.ToArray())
}

function Invoke-RevokeUserChunk {
    param(
        [string[]]$Upns,
        [bool]$DryRun,
        [bool]$VerifyRevoke
    )

    $upns = @($Upns)
    $lookupSelect = $script:GraphUserSelect
    $requests = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $upns.Count; $i++) {
        $requests.Add(@{
            id     = "u$i"
            method = 'GET'
            url    = (Get-GraphUserRelativePath -UserIdOrUpn $upns[$i] -Select $lookupSelect)
        })
    }

    $batch = Invoke-GraphBatch -Requests @($requests.ToArray())
    if (-not $batch.Ok) {
        Write-Warn2 "Graph batch lookup failed ($($batch.Error)). Falling back to per-user calls for this group of $($upns.Count)."
        $fallback = New-Object System.Collections.Generic.List[object]
        foreach ($upn in $upns) {
            $fallback.Add((Invoke-RevokeUserSequential -Upn $upn -DryRun $DryRun -VerifyRevoke $VerifyRevoke))
        }
        return @($fallback.ToArray())
    }

    $lookups = New-Object 'System.Collections.Generic.List[object]'
    for ($i = 0; $i -lt $upns.Count; $i++) {
        $item = $null
        if ($batch.ById.ContainsKey("u$i")) { $item = $batch.ById["u$i"] }
        $code = Get-BatchItemStatusCode -Item $item
        $body = Get-GraphObjectProperty -Object $item -Name 'body'
        $err = $null
        if ($code -ge 400) { $err = Get-BatchItemErrorMessage -Item $item }
        $lookups.Add((ConvertTo-GraphUserLookup -Body $body -StatusCode $code -Attempts $batch.Attempts -ErrorMessage $err))
    }

    if ($DryRun) {
        $out = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $upns.Count; $i++) {
            $upn = $upns[$i]
            $lookup = $lookups[$i]
            $guestNote = $null
            if ((Test-IsGuestUpn $upn) -or ($lookup.UserType -eq 'Guest')) {
                $guestNote = 'Guest/B2B: Graph does not revoke home-tenant sessions from this tenant.'
            }
            $stampBefore = $null
            if ($null -ne $lookup.Stamps) { $stampBefore = $lookup.Stamps.SessionsValidFrom }
            if ($lookup.Status -eq 'Found') {
                $detail = 'User found (dry run, no change made)'
                if ($guestNote) { $detail = $detail + ' ' + $guestNote }
                $out.Add((New-ProcessedUserResult -Upn $upn -DisplayName $lookup.DisplayName -Status 'WouldRevoke' `
                    -StampBefore $stampBefore -Detail $detail -Attempts $lookup.Attempts -DryRun $true))
            } else {
                $out.Add((New-ProcessedUserResult -Upn $upn -DisplayName $lookup.DisplayName -Status $lookup.Status `
                    -StampBefore $stampBefore -Detail $lookup.Detail -Attempts $lookup.Attempts -DryRun $true))
            }
        }
        return @($out.ToArray())
    }

    $revokeReqs = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $upns.Count; $i++) {
        $lookup = $lookups[$i]
        if ($lookup.Status -eq 'NotFound') { continue }
        $target = $upns[$i]
        if ($lookup.Status -eq 'Found' -and -not [string]::IsNullOrWhiteSpace($lookup.Id)) {
            $target = $lookup.Id
        }
        $revokeReqs.Add(@{
            id      = "r$i"
            method  = 'POST'
            url     = (Get-GraphUserRelativePath -UserIdOrUpn $target -Revoke)
            headers = @{ 'Content-Type' = 'application/json' }
            body    = @{}
        })
    }

    $revokeById = @{}
    $revokeAttempts = 1
    if ($revokeReqs.Count -gt 0) {
        $revokeBatch = Invoke-GraphBatch -Requests @($revokeReqs.ToArray())
        $revokeAttempts = $revokeBatch.Attempts
        if (-not $revokeBatch.Ok) {
            Write-Warn2 "Graph batch revoke failed ($($revokeBatch.Error)). Falling back to per-user calls for this group."
            $fallback = New-Object System.Collections.Generic.List[object]
            foreach ($upn in $upns) {
                $fallback.Add((Invoke-RevokeUserSequential -Upn $upn -DryRun $false -VerifyRevoke $VerifyRevoke))
            }
            return @($fallback.ToArray())
        }
        $revokeById = $revokeBatch.ById
    }

    $pendingVerify = New-Object System.Collections.Generic.List[int]
    $results = New-Object object[] $upns.Count
    for ($i = 0; $i -lt $upns.Count; $i++) {
        $upn = $upns[$i]
        $lookup = $lookups[$i]
        $guestNote = $null
        if ((Test-IsGuestUpn $upn) -or ($lookup.UserType -eq 'Guest')) {
            $guestNote = 'Guest/B2B: Graph does not revoke home-tenant sessions from this tenant.'
        }
        $stampBefore = $null
        if ($null -ne $lookup.Stamps) { $stampBefore = $lookup.Stamps.SessionsValidFrom }

        if ($lookup.Status -eq 'NotFound') {
            $results[$i] = New-ProcessedUserResult -Upn $upn -DisplayName $lookup.DisplayName -Status 'NotFound' `
                -StampBefore $stampBefore -Detail $lookup.Detail -Attempts $lookup.Attempts
            continue
        }

        $item = $null
        if ($revokeById.ContainsKey("r$i")) { $item = $revokeById["r$i"] }
        $code = Get-BatchItemStatusCode -Item $item
        $body = Get-GraphObjectProperty -Object $item -Name 'body'
        $status = 'Failed'
        $detail = Get-BatchItemErrorMessage -Item $item
        if ($code -ge 200 -and $code -lt 300) {
            $flag = Get-GraphBooleanValue -Response $body
            if ($false -eq $flag) {
                $status = 'Failed'
                $detail = 'Graph returned value=false (sessions were not revoked)'
            } else {
                $status = 'Revoked'
                $detail = 'Sign-in sessions revoked'
            }
        } else {
            $status = switch ($code) {
                404     { 'NotFound' }
                403     { 'AccessDenied' }
                401     { 'AccessDenied' }
                default { 'Failed' }
            }
        }
        if ($guestNote -and $status -eq 'Revoked') { $detail = $detail + ' ' + $guestNote }

        $verification = 'Skipped'
        $verifyDetail = 'Verification not run'
        $stampAfter = $null
        if ($VerifyRevoke -and $status -eq 'Revoked') {
            $pendingVerify.Add($i)
        }

        $results[$i] = New-ProcessedUserResult -Upn $upn -DisplayName $lookup.DisplayName -Status $status `
            -Verification $verification -VerificationDetail $verifyDetail `
            -StampBefore $stampBefore -StampAfter $stampAfter -Detail $detail `
            -Attempts ([Math]::Max($lookup.Attempts, $revokeAttempts))
    }

    if ($VerifyRevoke -and $pendingVerify.Count -gt 0) {
        $remaining = Update-ChunkVerification -Indexes @($pendingVerify.ToArray()) -Results $results -Lookups $lookups -Upns $upns -Attempt 1
        if (@($remaining).Count -gt 0) {
            Start-Sleep -Seconds 1
            $null = Update-ChunkVerification -Indexes @($remaining) -Results $results -Lookups $lookups -Upns $upns -Attempt 2
        }
    }

    return @($results)
}

function Get-GraphDeviceCodeParameterName {
    $cmd = Get-Command Connect-MgGraph -ErrorAction Stop
    foreach ($name in @('UseDeviceCode', 'UseDeviceAuthentication')) {
        if ($cmd.Parameters.ContainsKey($name)) { return $name }
    }
    return $null
}

function Test-WamParentWindowAvailable {
    if (-not (Test-IsWindowsOs)) { return $false }
    if ($Host.Name -match 'ISE|Visual Studio Code') { return $false }
    if ($env:TERM_PROGRAM -or $env:VSCODE_PID -or $env:VSCODE_INJECTION -or $env:CURSOR_TRACE_ID) { return $false }

    try {
        $main = [System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle
        if ($main -ne [IntPtr]::Zero) { return $true }
    } catch { }

    try {
        if (-not ('NativeConsoleWindow' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class NativeConsoleWindow {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
}
"@
        }
        $console = [NativeConsoleWindow]::GetConsoleWindow()
        if ($console -ne [IntPtr]::Zero) { return $true }
    } catch { }

    return $false
}

function Open-UrlInBrowser {
    param([string]$Url)
    Write-Host ("Opening {0} in your default browser..." -f $Url) -ForegroundColor Cyan
    try {
        Start-Process -FilePath $Url | Out-Null
        return $true
    } catch { }
    if (Test-IsWindowsOs) {
        try {
            Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList @('/c', 'start', '', $Url) | Out-Null
            return $true
        } catch { }
    }
    Write-Warn2 "Could not open a browser automatically. Please open: $Url"
    return $false
}

function Reset-UiSynchronizationContext {
    # File-picker dialogs install WindowsFormsSynchronizationContext on this
    # STA thread. Connect-MgGraph -UseDeviceCode then deadlocks (async over
    # sync) and the device code never appears.
    try {
        [System.Threading.SynchronizationContext]::SetSynchronizationContext($null)
    } catch { }
}

function Get-GraphConnectOutputText {
    param($Object)
    if ($null -eq $Object) { return '' }
    try {
        if ($Object -is [System.Management.Automation.VerboseRecord] -or
            $Object -is [System.Management.Automation.WarningRecord] -or
            $Object -is [System.Management.Automation.InformationRecord]) {
            return [string]$Object.Message
        }
    } catch { }
    try {
        if ($Object -is [System.Management.Automation.ErrorRecord] -and $null -ne $Object.Exception) {
            return [string]$Object.Exception.Message
        }
    } catch { }
    return [string]$Object
}

function Get-DeviceCodeFromMessage {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    if ($Text -match '(?i)enter the code\s+([A-Z0-9]{4,})') { return $Matches[1] }
    if ($Text -match '(?i)code\s+([A-Z0-9]{8,9})\s+to authenticate') { return $Matches[1] }
    return $null
}

function Write-GraphConnectOutput {
    param($Object)
    $text = Get-GraphConnectOutputText -Object $Object
    if ([string]::IsNullOrWhiteSpace($text)) { return }
    Write-Host $text -ForegroundColor White
    $code = Get-DeviceCodeFromMessage -Text $text
    if ($code) {
        Write-Host ''
        Write-Host ('Your device code is: {0}' -f $code) -ForegroundColor Green
        Write-Host ("Enter it at {0}" -f $script:DeviceLoginUrl) -ForegroundColor Green
        Write-Host ''
    }
}

function Invoke-GraphDeviceCodeSignIn {
    param([string]$Tenant)

    Reset-UiSynchronizationContext
    Initialize-GraphHttp

    if (-not [string]::IsNullOrWhiteSpace($Tenant)) {
        $script:GraphOAuthTenant = $Tenant.Trim()
    } else {
        $script:GraphOAuthTenant = 'organizations'
    }

    $authority = Get-GraphOAuthAuthority -Tenant $script:GraphOAuthTenant
    Write-Host ''
    Write-Host 'DEVICE CODE SIGN-IN' -ForegroundColor Cyan
    Write-Host 'A browser window will open. Sign in there with the code printed below.' -ForegroundColor White
    Write-Host ("If no browser opens, go to {0} yourself." -f $script:DeviceLoginUrl) -ForegroundColor Yellow
    Write-Host ''

    $start = Invoke-OAuthFormPost -Uri ($authority + '/devicecode') -Fields @{
        client_id = $script:GraphPublicClientId
        scope     = $script:GraphOAuthScopeString
    }
    if (-not $start.Ok) {
        throw "Could not start device-code sign-in: $($start.Error)"
    }

    $dc = $start.Content
    $userCode = [string](Get-GraphObjectProperty -Object $dc -Name 'user_code')
    $deviceCode = [string](Get-GraphObjectProperty -Object $dc -Name 'device_code')
    $message = [string](Get-GraphObjectProperty -Object $dc -Name 'message')
    $verifyUrl = [string](Get-GraphObjectProperty -Object $dc -Name 'verification_uri')
    $verifyComplete = [string](Get-GraphObjectProperty -Object $dc -Name 'verification_uri_complete')
    if ([string]::IsNullOrWhiteSpace($verifyUrl)) { $verifyUrl = $script:DeviceLoginUrl }
    $interval = 5
    $rawInterval = Get-GraphObjectProperty -Object $dc -Name 'interval'
    if ($null -ne $rawInterval) {
        $parsedInterval = 0
        if ([int]::TryParse([string]$rawInterval, [ref]$parsedInterval) -and $parsedInterval -gt 0) {
            $interval = $parsedInterval
        }
    }
    $expiresIn = 900
    $rawExpires = Get-GraphObjectProperty -Object $dc -Name 'expires_in'
    if ($null -ne $rawExpires) {
        $parsedExpires = 0
        if ([int]::TryParse([string]$rawExpires, [ref]$parsedExpires) -and $parsedExpires -gt 0) {
            $expiresIn = $parsedExpires
        }
    }
    if ([string]::IsNullOrWhiteSpace($deviceCode)) {
        throw 'Microsoft did not return a device_code.'
    }

    if (-not [string]::IsNullOrWhiteSpace($message)) {
        Write-Host $message -ForegroundColor White
    }
    if (-not [string]::IsNullOrWhiteSpace($userCode)) {
        Write-Host ''
        Write-Host ('Your device code is: {0}' -f $userCode) -ForegroundColor Green
        Write-Host ("Enter it at {0}" -f $verifyUrl) -ForegroundColor Green
        Write-Host ''
    }

    $openUrl = $verifyUrl
    if (-not [string]::IsNullOrWhiteSpace($verifyComplete)) { $openUrl = $verifyComplete }
    [void](Open-UrlInBrowser -Url $openUrl)

    $deadline = [datetime]::UtcNow.AddSeconds($expiresIn)
    $tokenUri = $authority + '/token'
    Write-Host 'Waiting for you to complete sign-in in the browser...' -ForegroundColor Gray
    while ([datetime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds $interval
        $poll = Invoke-OAuthFormPost -Uri $tokenUri -Fields @{
            client_id   = $script:GraphPublicClientId
            grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
            device_code = $deviceCode
        }
        if ($poll.Ok) {
            Set-GraphTokenFromOAuthResponse -Response $poll.Content
            $ctx = Get-CurrentGraphContext
            Write-Ok ("Signed in as {0}" -f $ctx.Account)
            return $ctx
        }
        $code = [string]$poll.ErrorCode
        if ($code -eq 'authorization_pending') { continue }
        if ($code -eq 'slow_down') {
            $interval += 5
            continue
        }
        if ($code -eq 'expired_token') {
            throw 'The device code expired before sign-in completed. Re-run the script.'
        }
        if ($code -eq 'authorization_declined') {
            throw 'Sign-in was declined in the browser.'
        }
        throw "Device-code sign-in failed: $($poll.Error)"
    }
    throw 'Timed out waiting for device-code sign-in. Re-run the script.'
}

function Connect-RevokeGraphSession {
    param(
        [string]$Tenant,
        [ValidateSet('DeviceCode', 'Browser')]
        [string]$AuthMethod = 'DeviceCode'
    )

    Initialize-GraphHttp

    if ($AuthMethod -eq 'Browser') {
        Write-Warn2 'Windows account picker / WAM re-prompts on every Graph batch in ISE, VS Code, and Cursor.'
        Write-Warn2 'Using device-code sign-in instead so later batches reuse a Bearer token with no extra login.'
    }

    $ctx = Get-CurrentGraphContext
    if ($null -ne $ctx -and (Test-GraphAccessTokenFresh)) {
        $tenantOk = [string]::IsNullOrWhiteSpace($Tenant) -or [string]::IsNullOrWhiteSpace([string]$ctx.TenantId) -or ($ctx.TenantId -eq $Tenant) -or ([string]$ctx.TenantId -ieq $Tenant)
        if ($tenantOk) {
            Write-Info ("Reusing Graph session as {0}. Sign-in will not be requested again." -f $ctx.Account)
            return $ctx
        }
        Write-Warn2 'Existing Graph session is for a different tenant. Signing in again for the tenant you entered.'
        Clear-GraphTokenCache
    }

    Write-Info 'Requesting Graph scopes (single device-code sign-in): User.RevokeSessions.All, User.Read.All, User.ReadWrite.All'
    $ctx = Invoke-GraphDeviceCodeSignIn -Tenant $Tenant
    if ($null -eq $ctx) { throw 'No Microsoft Graph context after sign-in.' }
    if (-not (Test-GraphScopesSufficient -CurrentScopes @($ctx.Scopes))) {
        $granted = '(none reported)'
        if ($ctx.Scopes) { $granted = ($ctx.Scopes -join ', ') }
        Write-Warn2 "Sign-in succeeded, but the token did not list the usual revoke/read scopes. Granted: $granted"
        Write-Warn2 'Continuing with this session instead of asking you to sign in again. Graph will return 403 if the account cannot revoke sessions.'
    }
    return $ctx
}

function Invoke-SelfTest {
    function Assert-True {
        param([string]$Name, [bool]$Condition, [string]$Detail = '')
        if ($Condition) {
            Write-Ok $Name
            $script:SelfPassed++
        } else {
            if ($Detail) { Write-Err2 "$Name -- $Detail" } else { Write-Err2 $Name }
            $script:SelfFailed++
        }
    }

    $script:SelfPassed = 0
    $script:SelfFailed = 0

    Write-Banner 'Revoke-M365Sessions self-test'

    Assert-True 'UPN accepts standard address' (Test-IsUserPrincipalName 'first.user@contoso.com')
    Assert-True 'UPN rejects blank' (-not (Test-IsUserPrincipalName '  '))
    Assert-True 'UPN rejects missing domain dot' (-not (Test-IsUserPrincipalName 'user@contoso'))
    Assert-True 'UPN accepts guest #EXT# address' (Test-IsUserPrincipalName 'john_gmail.com#EXT#@contoso.onmicrosoft.com')
    Assert-True 'Guest detector matches #EXT#' (Test-IsGuestUpn 'john_gmail.com#EXT#@contoso.onmicrosoft.com')
    Assert-True 'Guest detector ignores members' (-not (Test-IsGuestUpn 'first.user@contoso.com'))

    Assert-True 'Retry wait attempt 1 is 2s' ((Get-RetryWaitSeconds -Attempt 1) -eq 2)
    Assert-True 'Retry wait attempt 2 is 4s' ((Get-RetryWaitSeconds -Attempt 2) -eq 4)
    Assert-True 'Retry wait attempt 6 is capped at 60s' ((Get-RetryWaitSeconds -Attempt 6) -eq 60)
    Assert-True 'Retry-After header wins' ((Get-RetryWaitSeconds -Attempt 1 -RetryAfterSeconds 12) -eq 12)
    Assert-True 'Retry-After is capped' ((Get-RetryWaitSeconds -Attempt 1 -RetryAfterSeconds 120) -eq 60)

    $uri = Get-GraphUserPathUri -UserIdOrUpn 'first.user@contoso.com'
    Assert-True 'Graph user URI keeps @ unencoded' ($uri -eq 'https://graph.microsoft.com/v1.0/users/first.user@contoso.com')
    $uriGuid = Get-GraphUserPathUri -UserIdOrUpn 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    Assert-True 'Graph user URI accepts object id' ($uriGuid -match '/users/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee$')

    $err404 = [System.Management.Automation.ErrorRecord]::new(
        [Exception]::new('GET https://graph.microsoft.com/v1.0/users/x HTTP/1.1 404 Not Found'),
        'NotFound',
        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
        $null
    )
    Assert-True 'HTTP parser reads 404 from message' ((Get-HttpStatusCode -ErrorRecord $err404) -eq 404)

    $errGraph = [System.Management.Automation.ErrorRecord]::new(
        [Exception]::new('Request_ResourceNotFound: User does not exist'),
        'NotFound',
        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
        $null
    )
    Assert-True 'HTTP parser maps Request_ResourceNotFound to 404' ((Get-HttpStatusCode -ErrorRecord $errGraph) -eq 404)

    $err403 = [System.Management.Automation.ErrorRecord]::new(
        [Exception]::new('Authorization_RequestDenied: Insufficient privileges to complete the operation.'),
        'Denied',
        [System.Management.Automation.ErrorCategory]::PermissionDenied,
        $null
    )
    Assert-True 'HTTP parser maps Authorization_RequestDenied to 403' ((Get-HttpStatusCode -ErrorRecord $err403) -eq 403)

    $err429 = [System.Management.Automation.ErrorRecord]::new(
        [Exception]::new('TooManyRequests. Retry-After: 7'),
        'Throttle',
        [System.Management.Automation.ErrorCategory]::LimitsExceeded,
        $null
    )
    Assert-True 'HTTP parser maps TooManyRequests to 429' ((Get-HttpStatusCode -ErrorRecord $err429) -eq 429)
    Assert-True 'Retry-After parsed from exception text' ((Get-RetryAfterSeconds -Headers $null -ErrorRecord $err429) -eq 7)

    Assert-True 'Graph boolean true from hashtable' ($true -eq (Get-GraphBooleanValue @{ value = $true }))
    Assert-True 'Graph boolean false from hashtable' ($false -eq (Get-GraphBooleanValue @{ value = $false }))

    $iso = ConvertTo-UtcDateTime '2026-11-17T12:00:00Z'
    Assert-True 'ISO Z timestamp parses to UTC' ($null -ne $iso -and $iso.Hour -eq 12)
    Assert-True 'Empty timestamp parses as null' ($null -eq (ConvertTo-UtcDateTime ''))
    $fromDt = ConvertTo-UtcDateTime ([datetime]::SpecifyKind([datetime]'2026-11-17 12:00:00', 'Utc'))
    Assert-True 'DateTime value converts to UTC' ($null -ne $fromDt -and $fromDt.Kind -eq [datetimeKind]::Utc)

    $now = [datetime]::SpecifyKind([datetime]'2026-11-17 12:00:00', 'Utc')
    $before = $now.AddMinutes(-30)
    $after = $now
    $moved = Test-RevokeTimestampMoved -BeforeUtc $before -AfterUtc $after -NowUtc $now
    Assert-True 'Timestamp advanced is verified' ($moved.Verified -eq $true)
    $unchanged = Test-RevokeTimestampMoved -BeforeUtc $before -AfterUtc $before -NowUtc $now
    Assert-True 'Unchanged timestamp is not verified' ($unchanged.Verified -eq $false)
    $missing = Test-RevokeTimestampMoved -BeforeUtc $before -AfterUtc $null -NowUtc $now
    Assert-True 'Missing after timestamp is not verified' ($missing.Verified -eq $false)
    $recent = Test-RevokeTimestampMoved -BeforeUtc $null -AfterUtc $now.AddMinutes(-2) -NowUtc $now
    Assert-True 'Recent stamp without baseline is verified' ($recent.Verified -eq $true)
    $stale = Test-RevokeTimestampMoved -BeforeUtc $null -AfterUtc $now.AddHours(-2) -NowUtc $now
    Assert-True 'Stale stamp without baseline is not verified' ($stale.Verified -eq $false)

    $evidence = Test-SessionRevokeEvidence `
        -Before (New-SessionStampSet -SessionsValidFrom $before) `
        -After (New-SessionStampSet -SessionsValidFrom $before -RefreshTokensValidFrom $after) `
        -NowUtc $now
    Assert-True 'Refresh-token stamp can satisfy verification' ($evidence.Verified -eq $true)

    $propObj = [pscustomobject]@{ signInSessionsValidFromDateTime = '2026-11-17T12:00:00Z' }
    $stamps = Get-UserSessionStamps -UserObject $propObj
    Assert-True 'Session stamps read from PSCustomObject' ($null -ne $stamps.SessionsValidFrom)
    $stampsHash = Get-UserSessionStamps -UserObject @{ signInSessionsValidFromDateTime = '2026-11-17T12:00:00Z' }
    Assert-True 'Session stamps read from hashtable' ($null -ne $stampsHash.SessionsValidFrom)
    Assert-True 'Format-UtcStamp renders UTC' ((Format-UtcStamp $now) -eq '2026-11-17 12:00:00 UTC')

    Assert-True 'User.ReadWrite.All is sufficient' (Test-GraphScopesSufficient -CurrentScopes @('User.ReadWrite.All'))
    Assert-True 'Revoke+Read is sufficient' (Test-GraphScopesSufficient -CurrentScopes @('User.RevokeSessions.All', 'User.Read.All'))
    Assert-True 'Revoke-only is not sufficient for lookup' (-not (Test-GraphScopesSufficient -CurrentScopes @('User.RevokeSessions.All')))
    Assert-True 'Empty scopes are not sufficient' (-not (Test-GraphScopesSufficient -CurrentScopes @()))
    Assert-True 'Prefixed Graph scopes are sufficient' (Test-GraphScopesSufficient -CurrentScopes @('https://graph.microsoft.com/User.ReadWrite.All'))

    $oneReqJson = ConvertTo-JsonForGraph -Object @{ requests = @(@{ id = 'u0'; method = 'GET'; url = '/users/a' }) }
    Assert-True 'Single batch request stays a JSON array' ($oneReqJson -match '"requests"\s*:\s*\[')
    $form = ConvertTo-FormUrlEncoded -Fields @{ client_id = 'abc'; scope = 'a b' }
    Assert-True 'Form body encodes spaces in scope' ($form -match 'scope=a%20b' -and $form -match 'client_id=abc')
    $jwtPayload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"upn":"admin@contoso.com","tid":"tenant-guid"}')).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $jwt = ConvertFrom-JwtPayload -Jwt ('hdr.' + $jwtPayload + '.sig')
    Assert-True 'JWT payload upn is parsed' (([string](Get-GraphObjectProperty -Object $jwt -Name 'upn')) -eq 'admin@contoso.com')
    $prevToken = $script:GraphAccessToken
    $prevExp = $script:GraphTokenExpiresOn
    try {
        $script:GraphAccessToken = 'token-value'
        $script:GraphTokenExpiresOn = [datetime]::UtcNow.AddMinutes(10)
        Assert-True 'Access token with 10 minutes left is fresh' (Test-GraphAccessTokenFresh)
        $script:GraphTokenExpiresOn = [datetime]::UtcNow.AddSeconds(30)
        Assert-True 'Access token near expiry is not treated as fresh' (-not (Test-GraphAccessTokenFresh))
        Clear-GraphTokenCache
        $noTokenMsg = ''
        try { $null = Get-GraphAccessToken } catch { $noTokenMsg = $_.Exception.Message }
        Assert-True 'Missing token does not start an interactive login' ($noTokenMsg -match 'access token')
    } finally {
        $script:GraphAccessToken = $prevToken
        $script:GraphTokenExpiresOn = $prevExp
    }

    $col = Get-UpnColumn -Headers @('DisplayName', 'UserPrincipalName', 'Department') -NoPrompt
    Assert-True 'UPN column auto-detects UserPrincipalName' ($col -eq 'UserPrincipalName')
    $col2 = Get-UpnColumn -Headers @('Full Name', 'Mail') -NoPrompt
    Assert-True 'UPN column auto-detects Mail' ($col2 -eq 'Mail')
    $col3 = Get-UpnColumn -Headers @('Full Name', 'SamAccountName') -NoPrompt
    Assert-True 'UPN column returns null when undetectable' ($null -eq $col3)

    $tmpRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('revoke-selftest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmpRoot | Out-Null
    try {
        $utf8Bom = New-Object System.Text.UTF8Encoding $true
        $bomCsv = Join-Path $tmpRoot 'bom.csv'
        [System.IO.File]::WriteAllText($bomCsv, "UserPrincipalName,DisplayName`r`nfirst.user@contoso.com,First User`r`n", $utf8Bom)
        $bomRows = @(Read-UserCsv -Path $bomCsv)
        $bomHeaders = @($bomRows[0].PSObject.Properties.Name)
        Assert-True 'UTF-8 BOM CSV loads one row' ($bomRows.Count -eq 1)
        Assert-True 'UTF-8 BOM stripped from header' ($bomHeaders[0] -eq 'UserPrincipalName')
        Assert-True 'UTF-8 BOM CSV UPN value' ($bomRows[0].UserPrincipalName -eq 'first.user@contoso.com')

        $semiCsv = Join-Path $tmpRoot 'semi.csv'
        [System.IO.File]::WriteAllText($semiCsv, "UserPrincipalName;Department`r`nsecond.user@contoso.com;IT`r`n", [Text.UTF8Encoding]::new($false))
        $semiRows = @(Read-UserCsv -Path $semiCsv)
        Assert-True 'Semicolon CSV delimiter detected' ($semiRows.Count -eq 1 -and $semiRows[0].UserPrincipalName -eq 'second.user@contoso.com')

        $sepCsv = Join-Path $tmpRoot 'sep.csv'
        [System.IO.File]::WriteAllText($sepCsv, "sep=;`r`nUserPrincipalName;Mail`r`nthird.user@contoso.com;third.user@contoso.com`r`n", [Text.UTF8Encoding]::new($false))
        $sepRows = @(Read-UserCsv -Path $sepCsv)
        Assert-True 'Excel sep= line is skipped' (
            $sepRows.Count -eq 1 -and $sepRows[0].UserPrincipalName -eq 'third.user@contoso.com'
        )

        $commaCsv = Join-Path $tmpRoot 'comma.csv'
        [System.IO.File]::WriteAllText($commaCsv, "UserPrincipalName,Department`r`nvalid.user@contoso.com,IT`r`nnot-an-email,IT`r`n,IT`r`nvalid.user@contoso.com,IT`r`n", [Text.UTF8Encoding]::new($false))
        $commaRows = @(Read-UserCsv -Path $commaCsv)
        $upnColumn = Get-UpnColumn -Headers @($commaRows[0].PSObject.Properties.Name) -NoPrompt
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $valid = New-Object System.Collections.Generic.List[string]
        $invalid = 0
        $dupes = 0
        foreach ($row in $commaRows) {
            $value = ([string]$row.$upnColumn).Trim()
            if ([string]::IsNullOrWhiteSpace($value) -or -not (Test-IsUserPrincipalName $value)) {
                $invalid++
                continue
            }
            if ($seen.Add($value)) { $valid.Add($value) } else { $dupes++ }
        }
        Assert-True 'Validation keeps one unique UPN' ($valid.Count -eq 1 -and $valid[0] -eq 'valid.user@contoso.com')
        Assert-True 'Validation counts invalid/blank rows' ($invalid -eq 2)
        Assert-True 'Validation counts duplicate UPN' ($dupes -eq 1)
    } finally {
        Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    # The original 5.1 crash: [Math]::Min(60, [Math]::Pow(2, n)) is int vs double.
    $wait = Get-RetryWaitSeconds -Attempt 3
    Assert-True 'Retry helper returns int 8 for attempt 3' ($wait -eq 8 -and $wait -is [int])

    $wamProbeOk = $false
    try { $null = Test-WamParentWindowAvailable; $wamProbeOk = $true } catch { $wamProbeOk = $false }
    Assert-True 'WAM window probe runs without throwing' $wamProbeOk
    Assert-True 'Device login URL is microsoft.com/devicelogin' ($script:DeviceLoginUrl -eq 'https://microsoft.com/devicelogin')
    $sampleMsg = 'To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code LK6RW4ZSN to authenticate.'
    Assert-True 'Device code parsed from Graph message' ((Get-DeviceCodeFromMessage -Text $sampleMsg) -eq 'LK6RW4ZSN')
    Assert-True 'Device code parser ignores empty text' ($null -eq (Get-DeviceCodeFromMessage -Text ''))

    $oneChunk = Split-IntoChunks -Items @('a','b','c') -Size 20
    Assert-True 'Single chunk is not unwrapped' ($oneChunk.Count -eq 1 -and @($oneChunk[0]).Count -eq 3)
    $twoChunks = Split-IntoChunks -Items @(1..25) -Size 20
    Assert-True '25 items split into 2 chunks' ($twoChunks.Count -eq 2 -and @($twoChunks[0]).Count -eq 20 -and @($twoChunks[1]).Count -eq 5)
    $rel = Get-GraphUserRelativePath -UserIdOrUpn 'first.user@contoso.com' -Select 'id,displayName'
    Assert-True 'Batch path keeps @ and uses $select' ($rel -eq '/users/first.user@contoso.com?$select=id,displayName')
    $relRevoke = Get-GraphUserRelativePath -UserIdOrUpn 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -Revoke
    Assert-True 'Batch revoke path uses object id' ($relRevoke -eq '/users/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/revokeSignInSessions')

    Write-Host ''
    Write-Info ("Passed: {0}  Failed: {1}" -f $script:SelfPassed, $script:SelfFailed)
    return $script:SelfFailed
}

function Start-RevokeM365Sessions {
    Write-Banner 'Microsoft 365 - Revoke User Sign-In Sessions'

    if ($PSVersionTable.PSVersion.Major -lt 5 -or
        ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
        Write-Err2 "This script requires Windows PowerShell 5.1 or later. Current: $($PSVersionTable.PSVersion)"
        return
    }

    # --- Step 1: pick the CSV ----------------------------------------------------
    Write-Info 'Step 1 of 5: Select the CSV file containing your users.'
    $csvPath = Select-CsvFile
    if (-not $csvPath) {
        Write-Warn2 'No file selected. Exiting.'
        return
    }
    if (-not (Test-Path -LiteralPath $csvPath)) {
        Write-Err2 "File not found: $csvPath"
        return
    }
    Write-Ok "Selected: $csvPath"

    # --- Step 2: load + validate users -------------------------------------------
    Write-Info 'Step 2 of 5: Reading and validating users...'

    try {
        $rows = @(Read-UserCsv -Path $csvPath)
    } catch {
        Write-Err2 "Failed to read CSV: $($_.Exception.Message)"
        return
    }

    if ($rows.Count -eq 0) {
        Write-Err2 'The CSV file contains no data rows.'
        return
    }

    $headers = @($rows[0].PSObject.Properties.Name)
    $upnColumn = Get-UpnColumn -Headers $headers
    Write-Ok "Using column '$upnColumn' as the UPN."

    $seen     = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $valid    = New-Object System.Collections.Generic.List[string]
    $invalid  = New-Object System.Collections.Generic.List[object]
    $dupes    = 0
    $guestCount = 0
    $rowNum   = 1

    foreach ($row in $rows) {
        $rowNum++
        $value = [string]$row.$upnColumn
        if ($null -ne $value) { $value = $value.Trim() }

        if ([string]::IsNullOrWhiteSpace($value)) {
            $invalid.Add([pscustomobject]@{ Row = $rowNum; Value = '(blank)' })
            continue
        }
        if (-not (Test-IsUserPrincipalName $value)) {
            $invalid.Add([pscustomobject]@{ Row = $rowNum; Value = $value })
            continue
        }
        if ($seen.Add($value)) {
            $valid.Add($value)
            if (Test-IsGuestUpn $value) { $guestCount++ }
        } else {
            $dupes++
        }
    }

    Write-Host ''
    Write-Host ('  Rows in file     : {0}' -f $rows.Count)
    Write-Host ('  Valid UPNs       : {0}' -f $valid.Count) -ForegroundColor Green
    Write-Host ('  Duplicates skipped: {0}' -f $dupes) -ForegroundColor Yellow
    Write-Host ('  Invalid / blank  : {0}' -f $invalid.Count) -ForegroundColor $(if ($invalid.Count) { 'Red' } else { 'Gray' })
    if ($guestCount -gt 0) {
        Write-Host ('  Guest / #EXT#    : {0} (Graph cannot revoke home-tenant sessions)' -f $guestCount) -ForegroundColor Yellow
    }

    if ($invalid.Count -gt 0) {
        Write-Host ''
        Write-Warn2 'Invalid entries (first 10):'
        $invalid | Select-Object -First 10 | Format-Table -AutoSize | Out-Host
    }

    if ($valid.Count -eq 0) {
        Write-Err2 'No valid UPNs to process. Exiting.'
        return
    }

    if (Read-YesNo -Prompt 'Preview the list of users to be processed?' -Default $false) {
        $preview = $valid | ForEach-Object {
            [pscustomobject]@{
                UserPrincipalName = $_
                GuestUser         = $(if (Test-IsGuestUpn $_) { 'Yes' } else { 'No' })
            }
        }
        if (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
            $preview | Out-GridView -Title "Users to process ($($valid.Count))" -Wait
        } else {
            $preview | Format-Table -AutoSize | Out-Host
        }
    }

    # --- Step 3: choose mode -----------------------------------------------------
    Write-Info 'Step 3 of 5: Choose run mode.'
    $modeIndex = Read-Choice -Title 'How would you like to run?' -Options @(
        'DRY RUN  - connect and list what would happen, make no changes',
        'LIVE RUN - revoke sign-in sessions for all valid users',
        'Cancel'
    )
    if ($modeIndex -eq 2) { Write-Warn2 'Cancelled by user.'; return }
    $dryRun = ($modeIndex -eq 0)

    $verifyRevoke = $false
    if (-not $dryRun) {
        Write-Host ''
        Write-Host "You are about to REVOKE sign-in sessions for $($valid.Count) user(s)." -ForegroundColor Red
        Write-Host 'Affected users will be signed out of Microsoft 365 apps and will need to sign in again.' -ForegroundColor Red
        $confirm = Read-Host "Type REVOKE to continue"
        if ($confirm -cne 'REVOKE') {
            Write-Warn2 'Confirmation not received. Exiting without changes.'
            return
        }
        $verifyRevoke = Read-YesNo -Prompt 'Verify each revocation by re-reading signInSessionsValidFromDateTime from Graph?' -Default $true
        if ($verifyRevoke) {
            Write-Info 'After each batch of revokes the script will re-read users and confirm the session-validity timestamp moved forward.'
        }
    }

    # --- Step 4: connect to Graph ------------------------------------------------
    Write-Info 'Step 4 of 5: Connecting to Microsoft Graph...'
    try { Initialize-GraphHttp } catch {
        Write-Err2 "Could not prepare Graph HTTP: $($_.Exception.Message)"
        return
    }

    $existing = Get-CurrentGraphContext
    $authMethod = 'DeviceCode'
    $tenant = ''
    if ($null -ne $existing -and (Test-GraphAccessTokenFresh)) {
        Write-Info ("Already signed in as {0}. Skipping Microsoft login." -f $existing.Account)
    } else {
        $authIndex = Read-Choice -Title 'How do you want to sign in to Microsoft Graph?' -Options @(
            'Open a browser and sign in with a device code (recommended; one login for the whole run)',
            'Windows account picker (not used: WAM re-prompts after every batch)',
            'Cancel'
        )
        if ($authIndex -eq 2) { Write-Warn2 'Cancelled by user.'; return }
        if ($authIndex -eq 1) { $authMethod = 'Browser' }
        $tenant = Read-Host 'Tenant ID or domain (press Enter to use your account''s home tenant)'
    }

    try {
        $ctx = Connect-RevokeGraphSession -Tenant $tenant -AuthMethod $authMethod
        Write-Ok ("Connected as {0} (tenant {1})" -f $ctx.Account, $ctx.TenantId)
        if ($ctx.Scopes) {
            Write-Info ("Granted scopes: {0}" -f ($ctx.Scopes -join ', '))
        }
        Write-Info 'Graph batches use this access token. Microsoft login will not open again; expiry is refreshed silently.'
    } catch {
        Write-Err2 "Could not connect to Microsoft Graph: $($_.Exception.Message)"
        Write-Err2 'If a browser window never opened, re-run and choose device-code sign-in.'
        return
    }

    # --- Step 5: process users ---------------------------------------------------
    Write-Info ("Step 5 of 5: Processing {0} user(s){1} in batches of {2}..." -f $valid.Count, $(if ($dryRun) { ' (DRY RUN)' } else { '' }), $script:GraphBatchSize)

    $results   = New-Object System.Collections.Generic.List[object]
    $total     = $valid.Count
    $index     = 0
    $startTime = Get-Date
    $chunks    = Split-IntoChunks -Items @($valid) -Size $script:GraphBatchSize

    foreach ($chunk in $chunks) {
        $chunkUpns = @($chunk)
        $chunkResults = @(Invoke-RevokeUserChunk -Upns $chunkUpns -DryRun $dryRun -VerifyRevoke $verifyRevoke)
        foreach ($row in $chunkResults) {
            $index++
            $pct = [int](($index / $total) * 100)
            Write-Progress -Activity 'Revoking sign-in sessions' -Status "$index of $total : $($row.UserPrincipalName)" -PercentComplete $pct
            switch ($row.Status) {
                'Revoked' {
                    if ($row.Verification -eq 'Verified') { Write-Ok "$($row.UserPrincipalName) (verified)" }
                    elseif ($row.Verification -eq 'NotVerified') { Write-Warn2 "$($row.UserPrincipalName) - revoked, but session timestamp did not advance" }
                    elseif ($row.Verification -eq 'CheckFailed') { Write-Warn2 "$($row.UserPrincipalName) - revoked, but verification GET failed" }
                    else { Write-Ok "$($row.UserPrincipalName)" }
                }
                'WouldRevoke' { Write-Ok    "$($row.UserPrincipalName) (would revoke)" }
                'NotFound'    { Write-Warn2 "$($row.UserPrincipalName) - user not found" }
                default       { Write-Err2  "$($row.UserPrincipalName) - $($row.Status): $($row.Detail)" }
            }
            $results.Add($row)
        }
    }

    Write-Progress -Activity 'Revoking sign-in sessions' -Completed

    foreach ($bad in $invalid) {
        $results.Add([pscustomobject]@{
            UserPrincipalName          = $bad.Value
            DisplayName                = $null
            Status                     = 'Skipped'
            Verification               = 'Skipped'
            VerificationDetail         = 'Invalid or blank UPN'
            SessionsValidFromBefore    = ''
            SessionsValidFromAfter     = ''
            Detail                     = "Invalid or blank UPN on CSV row $($bad.Row)"
            Attempts                   = 0
            Mode                       = $(if ($dryRun) { 'DryRun' } else { 'Live' })
            Timestamp                  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        })
    }

    # --- Summary -----------------------------------------------------------------
    $elapsed = (Get-Date) - $startTime
    Write-Banner 'Summary'
    $results | Group-Object Status | Sort-Object Count -Descending |
        Select-Object @{ n = 'Status'; e = { $_.Name } }, Count |
        Format-Table -AutoSize | Out-Host
    if ($verifyRevoke) {
        Write-Host 'Verification (live revokes):' -ForegroundColor White
        $results |
            Where-Object { $_.Status -eq 'Revoked' } |
            Group-Object Verification |
            Sort-Object Count -Descending |
            Select-Object @{ n = 'Verification'; e = { $_.Name } }, Count |
            Format-Table -AutoSize | Out-Host
        Write-Info 'Verified means Graph advanced signInSessionsValidFromDateTime (or refreshTokensValidFromDateTime). Access tokens may still work until they expire.'
    }
    Write-Info ("Elapsed time: {0:hh\:mm\:ss}" -f $elapsed)
    if ($guestCount -gt 0) {
        Write-Warn2 'Guest/B2B (#EXT#) users were included. Graph does not revoke their home-tenant sessions.'
    }

    # --- Save report -------------------------------------------------------------
    if (Read-YesNo -Prompt 'Save a results report (CSV)?' -Default $true) {
        $defaultName = 'RevokeSessions_{0}_{1}.csv' -f $(if ($dryRun) { 'DryRun' } else { 'Live' }), (Get-Date -Format 'yyyyMMdd_HHmmss')
        $savePath = Select-SaveFile -DefaultName $defaultName -InitialDirectory (Split-Path -Path $csvPath -Parent)
        if ($savePath) {
            $results | Export-Csv -Path $savePath -NoTypeInformation -Encoding UTF8
            Write-Ok "Report saved to: $savePath"
        } else {
            Write-Warn2 'Report not saved.'
        }
    }

    if (Read-YesNo -Prompt 'Disconnect from Microsoft Graph?' -Default $false) {
        Clear-GraphTokenCache
        Write-Ok 'Disconnected.'
    }

    if ([Environment]::UserInteractive -and $Host.Name -eq 'ConsoleHost') {
        Write-Host ''
        Read-Host 'Press Enter to exit' | Out-Null
    }
}

# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------

if ($SelfTest) {
    $failures = Invoke-SelfTest
    if ($failures -gt 0) { exit 1 }
    exit 0
}

Disable-GraphInteractiveBroker
Restart-InStaIfNeeded
Start-RevokeM365Sessions

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
    - Shows a progress bar and writes a results CSV (chosen via a Save dialog).

    Fixes versus the original script:
    - Auto-relaunches Windows PowerShell in STA so the file picker works with
      powershell.exe -File (MTA would throw or hide the dialog).
    - Sets ShowHelp on WinForms dialogs and uses a real owner form so the picker
      is not stuck behind the console.
    - Sends -Body @{} on POST; Invoke-MgGraphRequest requires a body for POST
      and Graph expects Content-Type: application/json.
    - Uses [Math]::Min with doubles so retry back-off does not crash on
      Windows PowerShell 5.1 (int vs double overload failure).
    - Reads CSVs as UTF-8, strips a UTF-8 BOM from headers, and honours Excel
      "sep=" lines / semicolon-delimited files.
    - Wraps delimiter counts in @() so StrictMode does not crash when a candidate
      delimiter appears 0 or 1 times in the header (typical CSVs).
    - Resolves each user first, then revokes by object id (UPN %40 encoding
      can 404). Falls back to POST-by-UPN if the account cannot be read.
    - Reconnects when the current Graph session lacks revoke/read scopes, and
      falls back to User.ReadWrite.All if User.RevokeSessions.All cannot be
      consented.
    - Treats Graph { "value": false } as a failure, honours Retry-After, and
      warns that guest/#EXT# users cannot be revoked in the resource tenant.

.REQUIREMENTS
    - Windows PowerShell 5.1 or PowerShell 7+ on Windows
    - Microsoft.Graph.Authentication module (installed automatically if missing)
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
                if ($null -ne $Headers.PSObject.Properties[$key]) {
                    $raw = $Headers.$key
                    break
                }
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

function Initialize-GraphAuthModule {
    $moduleName = 'Microsoft.Graph.Authentication'
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Write-Warn2 "$moduleName module is not installed."
        if (-not (Read-YesNo -Prompt "Install it now for the current user from the PowerShell Gallery?" -Default $true)) {
            throw "The $moduleName module is required. Aborting."
        }

        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        try {
            if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
            }
        } catch {
            Write-Warn2 "NuGet package provider install skipped: $($_.Exception.Message)"
        }

        $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($null -ne $repo -and $repo.InstallationPolicy -ne 'Trusted') {
            try {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            } catch {
                Write-Warn2 "Could not mark PSGallery as trusted; Install-Module -Force will be used."
            }
        }

        Install-Module -Name $moduleName -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -Confirm:$false
        Write-Ok "$moduleName installed."
    }
    Import-Module $moduleName -ErrorAction Stop
}

function Test-GraphScopesSufficient {
    param([string[]]$CurrentScopes)
    if ($null -eq $CurrentScopes -or $CurrentScopes.Count -eq 0) { return $false }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $CurrentScopes) { [void]$set.Add($s) }
    $canRevoke = $set.Contains('User.RevokeSessions.All') -or
                 $set.Contains('User.ReadWrite.All') -or
                 $set.Contains('Directory.ReadWrite.All')
    $canRead   = $set.Contains('User.Read.All') -or
                 $set.Contains('User.ReadWrite.All') -or
                 $set.Contains('Directory.Read.All') -or
                 $set.Contains('Directory.ReadWrite.All')
    return ($canRevoke -and $canRead)
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

    $cmd = Get-Command Invoke-MgGraphRequest -ErrorAction Stop
    $attempt = 0

    while ($true) {
        $attempt++
        $statusCode = 0
        $responseHeaders = $null
        try {
            $params = @{
                Method      = $Method
                Uri         = $Uri
                ErrorAction = 'Stop'
            }
            if ($Method -eq 'POST') {
                if ($PSBoundParameters.ContainsKey('Body')) {
                    $params['Body'] = $Body
                } else {
                    $params['Body'] = @{}
                }
                if ($cmd.Parameters.ContainsKey('ContentType')) {
                    $params['ContentType'] = 'application/json'
                }
            }
            if ($cmd.Parameters.ContainsKey('StatusCodeVariable')) {
                $params['StatusCodeVariable'] = 'statusCode'
            }
            if ($cmd.Parameters.ContainsKey('ResponseHeadersVariable')) {
                $params['ResponseHeadersVariable'] = 'responseHeaders'
            }

            $result = Invoke-MgGraphRequest @params
            if ($statusCode -ge 400) {
                throw "Graph request failed with HTTP $statusCode for $Uri"
            }

            $okCode = $statusCode
            if ($okCode -lt 1) { $okCode = 200 }
            return [pscustomobject]@{
                Ok         = $true
                StatusCode = $okCode
                Content    = $result
                Headers    = $responseHeaders
                Attempts   = $attempt
                Error      = $null
            }
        } catch {
            $code = $statusCode
            if ($code -lt 400) { $code = Get-HttpStatusCode -ErrorRecord $_ }
            $retryAfter = Get-RetryAfterSeconds -Headers $responseHeaders -ErrorRecord $_
            if (($code -eq 429 -or $code -eq 503 -or $code -eq 504) -and $attempt -lt $MaxRetries) {
                $wait = Get-RetryWaitSeconds -Attempt $attempt -RetryAfterSeconds $retryAfter
                Write-Warn2 "Throttled/unavailable (HTTP $code). Retrying in $wait s (attempt $attempt of $MaxRetries)..."
                Start-Sleep -Seconds $wait
                continue
            }

            $message = $_.Exception.Message
            return [pscustomobject]@{
                Ok         = $false
                StatusCode = $code
                Content    = $null
                Headers    = $responseHeaders
                Attempts   = $attempt
                Error      = $message
            }
        }
    }
}

function Resolve-GraphUser {
    param([string]$Upn)

    $select = '$select=id,displayName,userPrincipalName,accountEnabled,userType'
    $uri = '{0}?{1}' -f (Get-GraphUserPathUri -UserIdOrUpn $Upn), $select
    $response = Invoke-GraphApi -Method GET -Uri $uri
    if ($response.Ok) {
        $content = $response.Content
        $id = $null
        $display = $null
        $userType = $null
        try { $id = [string]$content.id } catch { }
        try { $display = [string]$content.displayName } catch { }
        try { $userType = [string]$content.userType } catch { }
        if ([string]::IsNullOrWhiteSpace($id) -and ($content -is [System.Collections.IDictionary])) {
            $id = [string]$content['id']
            $display = [string]$content['displayName']
            $userType = [string]$content['userType']
        }
        return [pscustomobject]@{
            Status     = 'Found'
            Id         = $id
            DisplayName = $display
            UserType   = $userType
            Detail     = 'User found'
            Attempts   = $response.Attempts
        }
    }

    $status = switch ($response.StatusCode) {
        404     { 'NotFound' }
        403     { 'AccessDenied' }
        401     { 'AccessDenied' }
        default { 'Failed' }
    }
    return [pscustomobject]@{
        Status      = $status
        Id          = $null
        DisplayName = $null
        UserType    = $null
        Detail      = $response.Error
        Attempts    = $response.Attempts
    }
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

function Connect-RevokeGraphSession {
    param([string]$Tenant)

    Initialize-GraphAuthModule

    $scopeSets = @(
        ,@('User.RevokeSessions.All', 'User.Read.All')
        ,@('User.ReadWrite.All')
        ,@('Directory.ReadWrite.All')
    )

    $ctx = $null
    try { $ctx = Get-MgContext } catch { $ctx = $null }
    if ($null -ne $ctx -and (Test-GraphScopesSufficient -CurrentScopes @($ctx.Scopes))) {
        $tenantOk = [string]::IsNullOrWhiteSpace($Tenant) -or ($ctx.TenantId -eq $Tenant) -or ([string]$ctx.TenantId -ieq $Tenant)
        if ($tenantOk) {
            Write-Info "Reusing existing Graph session with sufficient scopes."
            return $ctx
        }
    }

    if ($null -ne $ctx) {
        Write-Warn2 "Existing Graph session is missing revoke/read scopes or is for a different tenant. Reconnecting..."
        try { Disconnect-MgGraph | Out-Null } catch { }
    }

    $connectCmd = Get-Command Connect-MgGraph
    $lastError = $null
    foreach ($scopes in $scopeSets) {
        $connectParams = @{
            Scopes = @($scopes)
        }
        if (-not [string]::IsNullOrWhiteSpace($Tenant)) { $connectParams['TenantId'] = $Tenant.Trim() }
        if ($connectCmd.Parameters.ContainsKey('NoWelcome')) { $connectParams['NoWelcome'] = $true }
        if ($connectCmd.Parameters.ContainsKey('ContextScope')) { $connectParams['ContextScope'] = 'Process' }

        try {
            Write-Info ("Requesting Graph scopes: {0}" -f ($scopes -join ', '))
            Connect-MgGraph @connectParams | Out-Null
            $ctx = Get-MgContext
            if ($null -eq $ctx) { throw 'No Microsoft Graph context after sign-in.' }
            if (-not (Test-GraphScopesSufficient -CurrentScopes @($ctx.Scopes))) {
                throw "Connected, but the token is missing required revoke/read scopes. Granted: $($ctx.Scopes -join ', ')"
            }
            return $ctx
        } catch {
            $lastError = $_
            Write-Warn2 ("Could not connect with scopes [{0}]: {1}" -f ($scopes -join ', '), $_.Exception.Message)
            try { Disconnect-MgGraph | Out-Null } catch { }
        }
    }

    $deviceParam = $null
    if ($connectCmd.Parameters.ContainsKey('UseDeviceCode')) { $deviceParam = 'UseDeviceCode' }
    elseif ($connectCmd.Parameters.ContainsKey('UseDeviceAuthentication')) { $deviceParam = 'UseDeviceAuthentication' }

    if ($deviceParam) {
        Write-Warn2 "Interactive sign-in failed. Trying device-code authentication..."
        $connectParams = @{ Scopes = @('User.RevokeSessions.All', 'User.Read.All') }
        $connectParams[$deviceParam] = $true
        if (-not [string]::IsNullOrWhiteSpace($Tenant)) { $connectParams['TenantId'] = $Tenant.Trim() }
        if ($connectCmd.Parameters.ContainsKey('NoWelcome')) { $connectParams['NoWelcome'] = $true }
        if ($connectCmd.Parameters.ContainsKey('ContextScope')) { $connectParams['ContextScope'] = 'Process' }
        try {
            Connect-MgGraph @connectParams | Out-Null
            $ctx = Get-MgContext
            if ($null -eq $ctx) { throw 'No Microsoft Graph context after device-code sign-in.' }
            return $ctx
        } catch {
            $lastError = $_
        }
    }

    if ($null -ne $lastError) { throw $lastError }
    throw 'Could not connect to Microsoft Graph.'
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

    Assert-True 'User.ReadWrite.All is sufficient' (Test-GraphScopesSufficient -CurrentScopes @('User.ReadWrite.All'))
    Assert-True 'Revoke+Read is sufficient' (Test-GraphScopesSufficient -CurrentScopes @('User.RevokeSessions.All', 'User.Read.All'))
    Assert-True 'Revoke-only is not sufficient for lookup' (-not (Test-GraphScopesSufficient -CurrentScopes @('User.RevokeSessions.All')))
    Assert-True 'Empty scopes are not sufficient' (-not (Test-GraphScopesSufficient -CurrentScopes @()))

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

    if (-not $dryRun) {
        Write-Host ''
        Write-Host "You are about to REVOKE sign-in sessions for $($valid.Count) user(s)." -ForegroundColor Red
        Write-Host 'Affected users will be signed out of Microsoft 365 apps and will need to sign in again.' -ForegroundColor Red
        $confirm = Read-Host "Type REVOKE to continue"
        if ($confirm -cne 'REVOKE') {
            Write-Warn2 'Confirmation not received. Exiting without changes.'
            return
        }
    }

    # --- Step 4: connect to Graph ------------------------------------------------
    Write-Info 'Step 4 of 5: Connecting to Microsoft Graph...'
    try {
        $tenant = Read-Host 'Tenant ID or domain (press Enter to use your account''s home tenant)'
        $ctx = Connect-RevokeGraphSession -Tenant $tenant
        Write-Ok ("Connected as {0} (tenant {1})" -f $ctx.Account, $ctx.TenantId)
        if ($ctx.Scopes) {
            Write-Info ("Granted scopes: {0}" -f ($ctx.Scopes -join ', '))
        }
    } catch {
        Write-Err2 "Could not connect to Microsoft Graph: $($_.Exception.Message)"
        return
    }

    # --- Step 5: process users ---------------------------------------------------
    Write-Info ("Step 5 of 5: Processing {0} user(s){1}..." -f $valid.Count, $(if ($dryRun) { ' (DRY RUN)' } else { '' }))

    $results   = New-Object System.Collections.Generic.List[object]
    $total     = $valid.Count
    $index     = 0
    $startTime = Get-Date

    foreach ($upn in $valid) {
        $index++
        $pct = [int](($index / $total) * 100)
        Write-Progress -Activity 'Revoking sign-in sessions' -Status "$index of $total : $upn" -PercentComplete $pct

        $lookup = Resolve-GraphUser -Upn $upn
        $displayName = $lookup.DisplayName
        $guestNote = $null
        if ((Test-IsGuestUpn $upn) -or ($lookup.UserType -eq 'Guest')) {
            $guestNote = 'Guest/B2B: Graph does not revoke home-tenant sessions from this tenant.'
        }

        if ($dryRun) {
            if ($lookup.Status -eq 'Found') {
                $detail = 'User found (dry run, no change made)'
                if ($guestNote) { $detail = $detail + ' ' + $guestNote }
                $outcome = [pscustomobject]@{ Status = 'WouldRevoke'; Detail = $detail; Attempts = $lookup.Attempts }
            } else {
                $outcome = [pscustomobject]@{ Status = $lookup.Status; Detail = $lookup.Detail; Attempts = $lookup.Attempts }
            }
        } else {
            if ($lookup.Status -eq 'NotFound') {
                $outcome = [pscustomobject]@{ Status = 'NotFound'; Detail = $lookup.Detail; Attempts = $lookup.Attempts }
            } else {
                $userId = $null
                if ($lookup.Status -eq 'Found') { $userId = $lookup.Id }
                $outcome = Invoke-RevokeSession -Upn $upn -UserId $userId
                if ($guestNote -and $outcome.Status -eq 'Revoked') {
                    $outcome = [pscustomobject]@{
                        Status   = $outcome.Status
                        Detail   = $outcome.Detail + ' ' + $guestNote
                        Attempts = $outcome.Attempts
                    }
                }
            }
        }

        switch ($outcome.Status) {
            'Revoked'     { Write-Ok    "$upn" }
            'WouldRevoke' { Write-Ok    "$upn (would revoke)" }
            'NotFound'    { Write-Warn2 "$upn - user not found" }
            default       { Write-Err2  "$upn - $($outcome.Status): $($outcome.Detail)" }
        }

        $results.Add([pscustomobject]@{
            UserPrincipalName = $upn
            DisplayName       = $displayName
            Status            = $outcome.Status
            Detail            = $outcome.Detail
            Attempts          = $outcome.Attempts
            Mode              = $(if ($dryRun) { 'DryRun' } else { 'Live' })
            Timestamp         = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        })
    }

    Write-Progress -Activity 'Revoking sign-in sessions' -Completed

    foreach ($bad in $invalid) {
        $results.Add([pscustomobject]@{
            UserPrincipalName = $bad.Value
            DisplayName       = $null
            Status            = 'Skipped'
            Detail            = "Invalid or blank UPN on CSV row $($bad.Row)"
            Attempts          = 0
            Mode              = $(if ($dryRun) { 'DryRun' } else { 'Live' })
            Timestamp         = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        })
    }

    # --- Summary -----------------------------------------------------------------
    $elapsed = (Get-Date) - $startTime
    Write-Banner 'Summary'
    $results | Group-Object Status | Sort-Object Count -Descending |
        Select-Object @{ n = 'Status'; e = { $_.Name } }, Count |
        Format-Table -AutoSize | Out-Host
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

    if (Read-YesNo -Prompt 'Disconnect from Microsoft Graph?' -Default $true) {
        try { Disconnect-MgGraph | Out-Null } catch { }
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

Restart-InStaIfNeeded
Start-RevokeM365Sessions

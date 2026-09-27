<#
.SYNOPSIS
    Entra ID (Azure AD) Connect Sync Error Analyzer with a modern WPF GUI.

.DESCRIPTION
    A comprehensive, PowerShell 5.1-compatible tool that:
      * Connects to Entra ID with a device code (same public client as Connect-MgGraph).
      * Pulls users, groups, and contacts that carry on-premises provisioning (AD Connect Sync) errors,
        then lists every other cloud object that holds the same proxy address or UPN.
      * Presents rich, detailed error information (category, property, offending value, timestamp).
      * Cross-references each errored object against on-prem Active Directory to surface the
        likely root cause (e.g. duplicate proxyAddresses / UPN, orphaned objects, mismatched
        immutableId / ms-DS-ConsistencyGuid).
      * Calls out a null mailNickname (alias). Entra Connect rejects a null alias on
        mail-enabled objects, and the cloud offending value is often empty — the report
        states explicitly that the mailNickname attribute has a null value.
      * Lets you scan Active Directory ad-hoc for any user and inspect the attributes that
        commonly break directory synchronization.
      * Exports findings to CSV / HTML.

    Everything runs inside a single robust, modern-looking dark-themed WPF window.

.NOTES
    Author  : v0
    Requires: Windows PowerShell 5.1
              Microsoft.Graph module (auto-install offered)
              RSAT ActiveDirectory module (optional, for on-prem cross-reference)
    Scopes  : User.Read.All, Directory.Read.All, Organization.Read.All

.EXAMPLE
    .\Invoke-EntraSyncErrorAnalyzer.ps1
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    # Pre-fill the tenant id / domain for the Graph connection (optional).
    [string]$TenantId,

    # Skip the on-prem Active Directory cross-reference features entirely.
    [switch]$SkipActiveDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------------------------
#  Load WPF assemblies (must succeed before anything else)
# ------------------------------------------------------------------------------------
try {
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
    Add-Type -AssemblyName System.Windows.Forms   # only used for file save dialogs
}
catch {
    Write-Error "Unable to load required WPF assemblies. This script must run on a Windows desktop with .NET / WPF available. $_"
    return
}

# ====================================================================================
#  SECTION 1 :: Shared state & helper functions
# ====================================================================================

# Global-ish state bag kept on the script scope so event handlers can reach it.
$script:State = [ordered]@{
    Connected        = $false
    TenantInfo       = $null
    SyncErrorRecords = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    AdModuleLoaded   = $false
    GraphModule      = $null
    Stopwatch        = New-Object System.Diagnostics.Stopwatch
    UiTimer          = $null
}

function Write-UiLog {
    <#
        Thread-safe append to the on-screen activity log + optional severity colouring.
    #>
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')][string]$Level = 'Info'
    )

    $timestamp = (Get-Date).ToString('HH:mm:ss')
    $line = "[$timestamp] $Message"

    if ($script:UI -and $script:UI.LogBox) {
        $script:UI.LogBox.Dispatcher.Invoke([action] {
            $prefix = switch ($Level) {
                'Success' { '[ OK ] ' }
                'Warning' { '[WARN] ' }
                'Error'   { '[FAIL] ' }
                default   { '[INFO] ' }
            }
            $script:UI.LogBox.AppendText(($prefix + $line + [Environment]::NewLine))
            $script:UI.LogBox.ScrollToEnd()
        })
    }

    # Also mirror to the host console for headless troubleshooting.
    switch ($Level) {
        'Success' { Write-Host $line -ForegroundColor Green }
        'Warning' { Write-Host $line -ForegroundColor Yellow }
        'Error'   { Write-Host $line -ForegroundColor Red }
        default   { Write-Host $line -ForegroundColor Gray }
    }
}

function Set-UiStatus {
    <#
        Lightweight status text update (no timing). Kept for simple, instantaneous updates.
    #>
    param(
        [Parameter(Mandatory)][string]$Text,
        [switch]$Busy
    )
    if (-not $script:UI) { return }
    $script:UI.Window.Dispatcher.Invoke([action] {
        $script:UI.StatusText.Text = $Text
        $script:UI.Progress.IsIndeterminate = [bool]$Busy
        $script:UI.Progress.Visibility = $(if ($Busy) { 'Visible' } else { 'Collapsed' })
    })
}

function Invoke-UiRefresh {
    <#
        Pumps the dispatcher queue so pending UI updates (progress bar, elapsed timer,
        status text) actually paint during a synchronous, long-running operation.
        This is what keeps the status bar "live" while a button handler is still running.
    #>
    if (-not $script:UI) { return }
    $script:UI.Window.Dispatcher.Invoke([action] {}, [System.Windows.Threading.DispatcherPriority]::Background)
}

function Update-UiElapsed {
    <#
        Refreshes the elapsed-time label from the running stopwatch (mm:ss).
    #>
    if (-not $script:UI) { return }
    $ts = $script:State.Stopwatch.Elapsed
    $text = ('{0:00}:{1:00}' -f [int][math]::Floor($ts.TotalMinutes), $ts.Seconds)
    $script:UI.Window.Dispatcher.Invoke([action] { $script:UI.ElapsedText.Text = $text })
}

function Start-UiOperation {
    <#
        Begins a tracked operation: resets + starts the stopwatch, shows the progress bar
        (indeterminate until progress counts arrive) and starts a live 'ticking' timer so
        the elapsed clock advances on-screen even while we wait on the network.
    #>
    param(
        [Parameter(Mandatory)][string]$Text,
        [string]$Stage = ''
    )
    if (-not $script:UI) { return }

    $script:State.Stopwatch.Restart()

    $script:UI.Window.Dispatcher.Invoke([action] {
        $script:UI.StatusText.Text        = $Text
        $script:UI.StageText.Text         = $Stage
        $script:UI.StageChip.Visibility   = $(if ([string]::IsNullOrWhiteSpace($Stage)) { 'Collapsed' } else { 'Visible' })
        $script:UI.PercentText.Text       = ''
        $script:UI.ElapsedText.Text       = '00:00'
        $script:UI.Progress.Visibility    = 'Visible'
        $script:UI.Progress.IsIndeterminate = $true
        $script:UI.Progress.Value         = 0
    })

    # A DispatcherTimer keeps the elapsed clock advancing whenever the UI thread is idle.
    if (-not $script:State.UiTimer) {
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds(500)
        $timer.Add_Tick({ Update-UiElapsed })
        $script:State.UiTimer = $timer
    }
    $script:State.UiTimer.Start()

    Write-UiLog $Text
    Invoke-UiRefresh
}

function Update-UiProgress {
    <#
        Reports determinate progress: fills the bar to a percentage and shows "n / total"
        plus a live status message. Call this from inside processing loops.
    #>
    param(
        [Parameter(Mandatory)][int]$Current,
        [Parameter(Mandatory)][int]$Total,
        [string]$Text
    )
    if (-not $script:UI) { return }

    $pct = $(if ($Total -gt 0) { [int](($Current / $Total) * 100) } else { 0 })
    if ($pct -lt 0)   { $pct = 0 }
    if ($pct -gt 100) { $pct = 100 }

    $script:UI.Window.Dispatcher.Invoke([action] {
        if ($Text) { $script:UI.StatusText.Text = $Text }
        $script:UI.Progress.IsIndeterminate = $false
        $script:UI.Progress.Value           = $pct
        $script:UI.PercentText.Text         = "$pct%  ($Current / $Total)"
    })

    Update-UiElapsed
    Invoke-UiRefresh
}

function Stop-UiOperation {
    <#
        Ends a tracked operation: stops the stopwatch + ticking timer, hides the progress
        bar and leaves the final elapsed time on-screen next to the closing status message.
    #>
    param([Parameter(Mandatory)][string]$Text)
    if (-not $script:UI) { return }

    $script:State.Stopwatch.Stop()
    if ($script:State.UiTimer) { $script:State.UiTimer.Stop() }

    $ts = $script:State.Stopwatch.Elapsed
    $elapsedStr = ('{0:00}:{1:00}' -f [int][math]::Floor($ts.TotalMinutes), $ts.Seconds)

    $script:UI.Window.Dispatcher.Invoke([action] {
        $script:UI.StatusText.Text          = $Text
        $script:UI.StageText.Text           = ''
        $script:UI.StageChip.Visibility     = 'Collapsed'
        $script:UI.PercentText.Text         = ''
        $script:UI.ElapsedText.Text         = $elapsedStr
        $script:UI.Progress.IsIndeterminate = $false
        $script:UI.Progress.Value           = 0
        $script:UI.Progress.Visibility      = 'Collapsed'
    })

    Write-UiLog "$Text  (elapsed $elapsedStr)" -Level Success
    Invoke-UiRefresh
}

function Test-CommandExists {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Test-IsBlankAttributeValue {
    <#
        True when an attribute is null, missing, or only whitespace.
        A null mailNickname arrives this way from both AD and Graph.
    #>
    param($Value)
    if ($null -eq $Value) { return $true }
    return [string]::IsNullOrWhiteSpace("$Value")
}

function Format-MailNicknameDisplay {
    <#
        Render mailNickname so a missing alias cannot disappear into a blank column.
        Blank in, the literal sentinel '(null)' out.
    #>
    param($Value)
    if (Test-IsBlankAttributeValue $Value) { return '(null)' }
    return "$Value"
}

function Test-IsReportedNullValue {
    <#
        True when an Entra offending value is empty, or when this tool has already
        replaced that empty value with the '(null)' display sentinel.
        Do not use this on a raw directory attribute: a real alias could theoretically
        be stored as the sentinel text only after we rewrote it.
    #>
    param($Value)
    if (Test-IsBlankAttributeValue $Value) { return $true }
    return ("$Value".Trim() -eq '(null)')
}

function Get-DirectoryAttributeValue {
    <#
        StrictMode-safe attribute read. Returns $null when the property was not loaded
        or the directory stored no value — both of which mean "no mailNickname".

        Graph pages are sometimes hashtables (Invoke-MgGraphRequest default) and
        sometimes PSCustomObjects (-OutputType PSObject). Hashtable keys are not
        PSObject properties, so a property-only read would drop every group and contact.
    #>
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in @($Object.Keys)) {
            if ("$key" -eq $Name) { return $Object[$key] }
        }
        return $null
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function Get-GraphMailNickname {
    <#
        mailNickname from a Graph user. Typed SDK objects expose MailNickname; some
        payloads only place it in AdditionalProperties when it was $selected.
        Hashtable pages from Invoke-MgGraphRequest store it as a dictionary key.
    #>
    param($User)
    if ($null -eq $User) { return $null }
    if ($User -is [System.Collections.IDictionary]) {
        return Get-DirectoryAttributeValue $User 'mailNickname'
    }
    $prop = $User.PSObject.Properties['MailNickname']
    if ($prop) { return $prop.Value }
    $extraProp = $User.PSObject.Properties['AdditionalProperties']
    if (-not $extraProp -or $null -eq $extraProp.Value) { return $null }

    # Graph SDK builds AdditionalProperties as Dictionary<string,object>.
    # That type's Contains(object) is an explicit IDictionary method and is not
    # callable here; ContainsKey is the public method. Hashtable has both.
    $map = $extraProp.Value
    $methodNames = @($map.PSObject.Methods | ForEach-Object { $_.Name })
    $hasKey = $false
    if ($methodNames -contains 'ContainsKey') {
        $hasKey = [bool]$map.ContainsKey('mailNickname')
    }
    elseif ($methodNames -contains 'Contains') {
        $hasKey = [bool]$map.Contains('mailNickname')
    }
    if ($hasKey) { return $map['mailNickname'] }
    return $null
}

function Get-MailNicknameNullIssue {
    <#
        Describes a null mailNickname, or returns $null when the alias is populated
        and Entra did not report it as empty.

        Mail-enabled objects (mail or proxyAddresses set) and any object Entra already
        flagged are Critical: Connect rejects a null alias. A user with no mail data
        is still reported, as Warning, so the blank value is not silent.
    #>
    param(
        $MailNickname,
        $Mail,
        $ProxyAddresses,
        [bool]$EntraReportedNull = $false
    )

    $nicknameBlank = Test-IsBlankAttributeValue $MailNickname
    if (-not $nicknameBlank -and -not $EntraReportedNull) { return $null }

    $proxyValues = @(@($ProxyAddresses) | Where-Object { -not (Test-IsBlankAttributeValue $_) })
    $mailEnabled = (-not (Test-IsBlankAttributeValue $Mail)) -or ($proxyValues.Count -gt 0)

    if ($nicknameBlank) {
        $message = 'The mailNickname attribute has a null value.'
        if ($null -ne $MailNickname -and -not [string]::IsNullOrEmpty("$MailNickname")) {
            $message = 'The mailNickname attribute has a null value (it contains only whitespace).'
        }
        if ($mailEnabled) {
            $message += ' This object has mail and/or proxyAddresses, so Entra Connect will reject the sync until mailNickname is set to a unique alias.'
        }
        if ($EntraReportedNull) {
            $message += ' Entra reported mailNickname as the attribute causing the provisioning error.'
        }
        $severity = if ($mailEnabled -or $EntraReportedNull) { 'Critical' } else { 'Warning' }
        return [pscustomobject]@{
            Severity = $severity
            Value    = '(null)'
            Message  = $message
        }
    }

    return [pscustomobject]@{
        Severity = 'Critical'
        Value    = '(null)'
        Message  = "Entra reports that the mailNickname attribute has a null value, but the on-prem mailNickname is '$(Format-MailNicknameDisplay $MailNickname)'. Confirm mailNickname is in the synchronization rules and the cloud object is not stale."
    }
}

function Initialize-GraphModule {
    <#
        Ensures the Microsoft Graph SDK is available. Offers to install it (CurrentUser
        scope) if missing. Returns $true when the module can be imported.
    #>
    Write-UiLog "Checking for the Microsoft Graph PowerShell SDK..."

    $required = 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Identity.DirectoryManagement'
    $missing = $required | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

    if ($missing) {
        Write-UiLog "Missing Graph sub-modules: $($missing -join ', ')" -Level Warning
        $answer = [System.Windows.MessageBox]::Show(
            "The Microsoft Graph PowerShell SDK is required but not fully installed.`n`nMissing:`n$($missing -join "`n")`n`nInstall now for the current user? (requires internet access)",
            'Install Microsoft Graph SDK',
            'YesNo', 'Question')

        if ($answer -ne 'Yes') {
            Write-UiLog "User declined Graph SDK installation." -Level Error
            return $false
        }

        try {
            Start-UiOperation -Text "Installing Microsoft Graph SDK..." -Stage "Downloading modules"
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
            }
            # Only install the sub-modules we actually need (far faster than the full meta-module).
            $mi = 0
            $mtotal = @($missing).Count
            foreach ($m in $missing) {
                $mi++
                Update-UiProgress -Current $mi -Total $mtotal -Text "Installing module $mi of $mtotal : $m ..."
                Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
            }
            Write-UiLog "Graph SDK installed." -Level Success
        }
        catch {
            Write-UiLog "Failed to install Graph SDK: $($_.Exception.Message)" -Level Error
            return $false
        }
        finally {
            Stop-UiOperation -Text "Ready"
        }
    }

    try {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Users -ErrorAction Stop
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
        $script:State.GraphModule = (Get-Module Microsoft.Graph.Authentication).Version.ToString()
        Write-UiLog "Microsoft Graph SDK loaded (Authentication v$($script:State.GraphModule))." -Level Success
        return $true
    }
    catch {
        Write-UiLog "Unable to import Graph modules: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Initialize-AdModule {
    <#
        Best-effort import of the on-prem ActiveDirectory module. Non-fatal if absent.
    #>
    if ($SkipActiveDirectory) {
        Write-UiLog "Active Directory features disabled by -SkipActiveDirectory." -Level Warning
        return $false
    }
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-UiLog "ActiveDirectory RSAT module not found. On-prem cross-reference disabled." -Level Warning
        return $false
    }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $script:State.AdModuleLoaded = $true
        Write-UiLog "ActiveDirectory module loaded (on-prem cross-reference enabled)." -Level Success
        return $true
    }
    catch {
        Write-UiLog "Failed to load ActiveDirectory module: $($_.Exception.Message)" -Level Warning
        return $false
    }
}

# ====================================================================================
#  SECTION 2 :: Core data operations (Graph + AD)
# ====================================================================================

function Enable-Tls12 {
    <#
        Windows PowerShell 5.1 often leaves ServicePointManager on TLS 1.0.
        login.microsoftonline.com refuses that, so device-code requests never start.
    #>
    try {
        $tls12 = [System.Net.SecurityProtocolType]::Tls12
        $current = [System.Net.ServicePointManager]::SecurityProtocol
        if (($current -band $tls12) -ne $tls12) {
            [System.Net.ServicePointManager]::SecurityProtocol = $current -bor $tls12
        }
    }
    catch {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }
}

function Get-ErrorRecordText {
    <#
        Join every place a device-code HTTP 400 might hide its JSON body.
        Windows PowerShell 5.1 puts it on ErrorDetails; some failures only
        expose it on the WebException response stream.
    #>
    param($ErrorRecord)
    $parts = New-Object System.Collections.Generic.List[string]
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        [void]$parts.Add("$($ErrorRecord.ErrorDetails.Message)")
    }
    $ex = $ErrorRecord.Exception
    while ($ex) {
        if ($ex.Message) { [void]$parts.Add("$($ex.Message)") }
        $responseProp = $ex.PSObject.Properties['Response']
        if ($responseProp -and $responseProp.Value) {
            try {
                $stream = $responseProp.Value.GetResponseStream()
                if ($stream) {
                    if ($stream.CanSeek) { $stream.Position = 0 }
                    $reader = New-Object System.IO.StreamReader($stream)
                    $body = $reader.ReadToEnd()
                    $reader.Dispose()
                    if (-not [string]::IsNullOrWhiteSpace($body)) { [void]$parts.Add($body) }
                }
            }
            catch {}
        }
        $ex = $ex.InnerException
    }
    return ($parts -join "`n")
}

function Get-HttpStatusCode {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    while ($ex) {
        $responseProp = $ex.PSObject.Properties['Response']
        if ($responseProp -and $responseProp.Value) {
            try { return [int]$responseProp.Value.StatusCode } catch {}
        }
        $ex = $ex.InnerException
    }
    if ("$($ErrorRecord.Exception.Message)" -match '\((\d{3})\)') { return [int]$Matches[1] }
    return 0
}

function Get-OAuthErrorCode {
    <#
        Device-code polling returns HTTP 400 for authorization_pending and slow_down.
        Pull the OAuth error code out of that body so those are not treated as failures.
    #>
    param($ErrorRecord)
    $text = Get-ErrorRecordText $ErrorRecord
    if ($text -match '"error"\s*:\s*"([^"]+)"') { return $Matches[1] }
    foreach ($known in @(
            'authorization_pending', 'slow_down', 'authorization_declined', 'expired_token',
            'access_denied', 'invalid_grant', 'invalid_client', 'invalid_request',
            'unauthorized_client', 'bad_verification_code'
        )) {
        if ($text -match $known) { return $known }
    }
    return $null
}

function Get-DeviceCodePollAction {
    <#
        pending  - user has not finished sign-in yet; keep polling
        slow_down - keep polling, but wait longer
        declined / expired / fatal - stop
        A bare HTTP 400 with no parsed code is treated as pending. PowerShell 5.1
        sometimes drops the JSON body and would otherwise abort the wait immediately.
    #>
    param($ErrorRecord)
    $code = Get-OAuthErrorCode $ErrorRecord
    switch ($code) {
        'authorization_pending' { return 'pending' }
        'slow_down' { return 'slow_down' }
        'authorization_declined' { return 'declined' }
        'access_denied' { return 'declined' }
        'expired_token' { return 'expired' }
        'invalid_grant' { return 'expired' }
        'invalid_client' { return 'fatal' }
        'invalid_request' { return 'fatal' }
        'unauthorized_client' { return 'fatal' }
        'bad_verification_code' { return 'fatal' }
    }
    if ((Get-HttpStatusCode $ErrorRecord) -eq 400) { return 'pending' }
    return 'fatal'
}

function Get-JwtPayload {
    <#
        Decode the JWT payload (no signature check). Used only to label the signed-in
        account when Connect-MgGraph -AccessToken leaves Get-MgContext.Account empty.
    #>
    param([string]$Token)
    if ([string]::IsNullOrWhiteSpace($Token)) { return $null }
    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) { return $null }
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '=='; break }
        3 { $payload += '='; break }
        1 { return $null }
    }
    try {
        $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
        return ($json | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Get-DeviceCodePromptText {
    param(
        $Device,
        [switch]$CopiedToClipboard
    )
    $message = "$(Get-DirectoryAttributeValue $Device 'message')".Trim()
    $userCode = "$(Get-DirectoryAttributeValue $Device 'user_code')".Trim()
    $url = "$(Get-DirectoryAttributeValue $Device 'verification_uri')".Trim()
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = "To sign in, open $url and enter the code $userCode."
    }
    $clipNote = if ($CopiedToClipboard) {
        'The device code has been copied to the clipboard.'
    } else {
        'Copy the device code from this message.'
    }
    return $message + "`r`n`r`n$clipNote`r`n`r`nFinish sign-in in the browser. This window keeps waiting until that completes."
}

function Write-DeviceCodeBanner {
    <#
        Print the code on the console that launched the script. A modal dialog is
        easy to leave behind that window, which is the same failure mode as WAM.
    #>
    param(
        [Parameter(Mandatory)][string]$UserCode,
        [Parameter(Mandatory)][string]$Url
    )
    $line = ('=' * 64)
    Write-Host ''
    Write-Host $line -ForegroundColor Yellow
    Write-Host '  DEVICE CODE SIGN-IN' -ForegroundColor Yellow
    Write-Host "  Code : $UserCode" -ForegroundColor Yellow
    Write-Host "  URL  : $Url" -ForegroundColor Yellow
    Write-Host $line -ForegroundColor Yellow
    Write-Host ''
}

function Wait-UiInterval {
    <#
        Sleep in short slices so the elapsed clock and log can paint while we poll.
    #>
    param([int]$Seconds)
    if ($Seconds -lt 1) { $Seconds = 1 }
    $end = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $end) {
        $remaining = ($end - (Get-Date)).TotalMilliseconds
        $slice = [int][Math]::Min(250, [Math]::Max(1, $remaining))
        Start-Sleep -Milliseconds $slice
        Update-UiElapsed
        Invoke-UiRefresh
    }
}

function Connect-MgGraphWithAccessToken {
    <#
        SDK 2.x takes a SecureString; older builds take a plain string.
    #>
    param([Parameter(Mandatory)][string]$Token)
    $cmd = Get-Command Connect-MgGraph -ErrorAction Stop
    if (-not $cmd.Parameters.ContainsKey('AccessToken')) {
        throw "Installed Microsoft.Graph.Authentication cannot accept an access token from device-code sign-in."
    }
    $paramType = $cmd.Parameters['AccessToken'].ParameterType
    if ($paramType -eq [System.Security.SecureString]) {
        $secure = ConvertTo-SecureString -String $Token -AsPlainText -Force
        Connect-MgGraph -AccessToken $secure -NoWelcome -ErrorAction Stop
    }
    else {
        Connect-MgGraph -AccessToken $Token -NoWelcome -ErrorAction Stop
    }
}

function Connect-EntraTenant {
    <#
        Device-code sign-in with the least-privilege read scopes needed for sync errors.
        The user code is shown in this window (and copied to the clipboard). Sign-in is
        finished at https://microsoft.com/devicelogin, including from another device.
        The resulting token is passed to Connect-MgGraph so the rest of the tool is unchanged.
    #>
    # Same first-party public client Connect-MgGraph uses (Microsoft Graph Command Line Tools).
    $clientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
    $scopes = @('User.Read.All', 'Directory.Read.All', 'Organization.Read.All')
    $tenant = if ($TenantId) { $TenantId.Trim() } else { 'organizations' }
    try {
        Enable-Tls12
        Start-UiOperation -Text "Requesting a device code..." -Stage "Device code"
        Write-UiLog "Sign-in mode: device code. The interactive browser / WAM prompt is not used."
        Write-UiLog "Starting Microsoft Graph device-code sign-in (scopes: $($scopes -join ', '))..."

        $deviceBody = @{
            client_id = $clientId
            scope     = ($scopes -join ' ')
        }
        $deviceUri = "https://login.microsoftonline.com/$([uri]::EscapeDataString($tenant))/oauth2/v2.0/devicecode"
        $device = Invoke-RestMethod -Method Post -Uri $deviceUri -Body $deviceBody -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop

        $userCode = "$(Get-DirectoryAttributeValue $device 'user_code')".Trim()
        $deviceCode = "$(Get-DirectoryAttributeValue $device 'device_code')".Trim()
        if ([string]::IsNullOrWhiteSpace($userCode) -or [string]::IsNullOrWhiteSpace($deviceCode)) {
            throw "The device-code endpoint did not return a user code."
        }

        $copied = $false
        try {
            Set-Clipboard -Value $userCode
            $copied = $true
        }
        catch {
            Write-UiLog "Could not copy the device code to the clipboard. Copy it from the dialog." -Level Warning
        }
        $verifyUrl = "$(Get-DirectoryAttributeValue $device 'verification_uri')".Trim()
        if ([string]::IsNullOrWhiteSpace($verifyUrl)) { $verifyUrl = 'https://microsoft.com/devicelogin' }
        $prompt = Get-DeviceCodePromptText $device -CopiedToClipboard:$copied
        Write-DeviceCodeBanner -UserCode $userCode -Url $verifyUrl
        Write-UiLog $prompt -Level Warning
        Invoke-UiRefresh

        $interval = 5
        $intervalRaw = Get-DirectoryAttributeValue $device 'interval'
        $intervalParsed = 0
        if ([int]::TryParse("$intervalRaw", [ref]$intervalParsed) -and $intervalParsed -ge 1) {
            $interval = $intervalParsed
        }
        $expiresIn = 900
        $expiresRaw = Get-DirectoryAttributeValue $device 'expires_in'
        $expiresParsed = 0
        if ([int]::TryParse("$expiresRaw", [ref]$expiresParsed) -and $expiresParsed -ge 30) {
            $expiresIn = $expiresParsed
        }
        $deadline = (Get-Date).AddSeconds($expiresIn)
        $tokenUri = "https://login.microsoftonline.com/$([uri]::EscapeDataString($tenant))/oauth2/v2.0/token"
        $accessToken = $null

        $script:UI.Window.Dispatcher.Invoke([action] {
            $script:UI.StatusText.Text = "Waiting for device-code sign-in ($userCode)..."
        })

        while ((Get-Date) -lt $deadline) {
            Wait-UiInterval -Seconds $interval
            if ((Get-Date) -ge $deadline) { break }
            try {
                $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUri -Body @{
                    grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                    client_id   = $clientId
                    device_code = $deviceCode
                } -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
                $accessToken = "$(Get-DirectoryAttributeValue $tokenResponse 'access_token')"
                if ([string]::IsNullOrWhiteSpace($accessToken)) {
                    throw "Sign-in completed but no access token was returned."
                }
                break
            }
            catch {
                $action = Get-DeviceCodePollAction $_
                if ($action -eq 'pending') { continue }
                if ($action -eq 'slow_down') { $interval += 5; continue }
                if ($action -eq 'declined') { throw "Sign-in was declined." }
                if ($action -eq 'expired') { throw "The device code expired before sign-in completed." }
                $detail = Get-ErrorRecordText $_
                throw "Device-code sign-in failed: $detail"
            }
        }

        if ([string]::IsNullOrWhiteSpace($accessToken)) {
            throw "The device code expired before sign-in completed."
        }

        Write-UiLog "Device-code sign-in completed. Connecting Microsoft Graph..."
        $claims = Get-JwtPayload $accessToken
        Connect-MgGraphWithAccessToken -Token $accessToken
        # The SDK now holds the token. Don't keep another copy in this function.
        $accessToken = $null
        $tokenResponse = $null

        $ctx = Get-MgContext
        if (-not $ctx) { throw "No Graph context returned after sign-in." }

        $account = "$(Get-DirectoryAttributeValue $ctx 'Account')"
        $tenantIdShown = "$(Get-DirectoryAttributeValue $ctx 'TenantId')"
        if ([string]::IsNullOrWhiteSpace($account)) {
            foreach ($claimName in @('preferred_username', 'upn', 'unique_name', 'email')) {
                $claim = "$(Get-DirectoryAttributeValue $claims $claimName)"
                if (-not [string]::IsNullOrWhiteSpace($claim)) { $account = $claim; break }
            }
        }
        if ([string]::IsNullOrWhiteSpace($tenantIdShown)) {
            $tenantIdShown = "$(Get-DirectoryAttributeValue $claims 'tid')"
        }
        if ([string]::IsNullOrWhiteSpace($account)) { $account = '(signed in)' }
        $claims = $null

        # Fetch tenant org details for the header.
        $org = $null
        try { $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1 } catch {}

        $scopeText = (@(Get-DirectoryAttributeValue $ctx 'Scopes') | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") }) -join ', '
        if ([string]::IsNullOrWhiteSpace($scopeText)) { $scopeText = ($scopes -join ', ') }

        $script:State.Connected = $true
        $script:State.TenantInfo = [pscustomobject]@{
            Account   = $account
            TenantId  = $tenantIdShown
            OrgName   = if ($org) { $org.DisplayName } else { '(unknown)' }
            Scopes    = $scopeText
        }

        $script:UI.Window.Dispatcher.Invoke([action] {
            $script:UI.TenantLabel.Text = "$($script:State.TenantInfo.OrgName)  |  $($script:State.TenantInfo.Account)"
            $script:UI.ConnectButton.Content = "Reconnect"
            $script:UI.ScanButton.IsEnabled = $true
        })

        Write-UiLog "Connected to '$($script:State.TenantInfo.OrgName)' as $account." -Level Success
    }
    catch {
        Write-UiLog "Sign-in failed: $($_.Exception.Message)" -Level Error
        [System.Windows.MessageBox]::Show("Sign-in failed:`n`n$($_.Exception.Message)", 'Connection Error', 'OK', 'Error') | Out-Null
    }
    finally {
        Stop-UiOperation -Text $(if ($script:State.Connected) { "Connected to $($script:State.TenantInfo.OrgName)" } else { "Sign-in cancelled / failed" })
    }
}

function Get-SyncValueKey {
    <#
        Identity of one directory object plus one duplicated value, ignoring SMTP: vs smtp:
        and the word "Proxy address" vs "ProxyAddresses".
    #>
    param([string]$ObjectId, [string]$Property, [string]$Value)
    $bare = "$Value"
    if ($bare -match '^(?i)[a-z0-9]+:(.+)$') { $bare = $Matches[1] }
    $prop = "$Property"
    if ($prop -match '(?i)proxy') { $prop = 'proxy' }
    elseif ($prop -match '(?i)userprincipalname|^upn$') { $prop = 'upn' }
    elseif ($prop -match '(?i)mailnickname|mail nickname') { $prop = 'mailnickname' }
    elseif ($prop -match '(?i)^mail$') { $prop = 'mail' }
    else { $prop = $prop.ToLower() }
    return ('{0}|{1}|{2}' -f "$ObjectId".ToLower(), $prop, $bare.Trim().ToLower())
}

function Get-BareAddress {
    param([string]$Value)
    $bare = "$Value".Trim()
    if ($bare -match '^(?i)[a-z0-9]+:(.+)$') { return $Matches[1] }
    return $bare
}

function Get-CloudLookupPlan {
    <#
        Queries that find every user, group, and contact holding an address Entra
        flagged. The portal lists all of those objects; a user-only error scan does not.
    #>
    param([string]$Value)
    # Return nothing when there is nothing to query. `return ,@()` still becomes
    # one empty array under @(), and the next loop then reads .Filter on it.
    if ([string]::IsNullOrWhiteSpace($Value) -or "$Value".Trim() -eq '(null)') { return }
    $bare = Get-BareAddress $Value
    if ([string]::IsNullOrWhiteSpace($bare)) { return }
    $odataBare = $bare.Replace("'", "''")
    $selectUser = 'id,displayName,userPrincipalName,mail,proxyAddresses'
    $selectGroup = 'id,displayName,mail,proxyAddresses'
    $selectContact = 'id,displayName,mail,proxyAddresses'
    $plans = New-Object System.Collections.Generic.List[object]
    # Case-sensitive: SMTP: and smtp: are different Graph filters, and a normal
    # hashtable would treat them as the same key and drop the second query.
    $seen = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    $candidates = New-Object System.Collections.Generic.List[object]
    $proxyLiterals = @()
    if ("$Value" -match '^(?i)smtp:(.+)$') {
        $addr = $Matches[1].Replace("'", "''")
        $proxyLiterals = @("SMTP:$addr", "smtp:$addr")
    }
    elseif ($bare -match '@') {
        $proxyLiterals = @("SMTP:$odataBare", "smtp:$odataBare")
    }
    foreach ($pv in $proxyLiterals) {
        [void]$candidates.Add([pscustomobject]@{ Resource = 'users';    ObjectType = 'User';    Filter = "proxyAddresses/any(p:p eq '$pv')"; Select = $selectUser })
        [void]$candidates.Add([pscustomobject]@{ Resource = 'groups';   ObjectType = 'Group';   Filter = "proxyAddresses/any(p:p eq '$pv')"; Select = $selectGroup })
        [void]$candidates.Add([pscustomobject]@{ Resource = 'contacts'; ObjectType = 'Contact'; Filter = "proxyAddresses/any(p:p eq '$pv')"; Select = $selectContact })
    }
    if ($bare -match '@') {
        [void]$candidates.Add([pscustomobject]@{ Resource = 'users';    ObjectType = 'User';    Filter = "mail eq '$odataBare'"; Select = $selectUser })
        [void]$candidates.Add([pscustomobject]@{ Resource = 'users';    ObjectType = 'User';    Filter = "userPrincipalName eq '$odataBare'"; Select = $selectUser })
        [void]$candidates.Add([pscustomobject]@{ Resource = 'groups';   ObjectType = 'Group';   Filter = "mail eq '$odataBare'"; Select = $selectGroup })
        [void]$candidates.Add([pscustomobject]@{ Resource = 'contacts'; ObjectType = 'Contact'; Filter = "mail eq '$odataBare'"; Select = $selectContact })
    }
    foreach ($candidate in $candidates) {
        $key = "$($candidate.Resource)|$($candidate.Filter)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [void]$plans.Add($candidate)
    }
    if ($plans.Count -eq 0) { return }
    Write-Output -NoEnumerate $plans.ToArray()
}

function Format-CloudHolderSummary {
    param($Holders)
    $lines = @(
        @($Holders) | Where-Object { $null -ne $_ } | ForEach-Object {
            $name = "$(Get-DirectoryAttributeValue $_ 'DisplayName')".Trim()
            if ([string]::IsNullOrWhiteSpace($name)) { $name = "$(Get-DirectoryAttributeValue $_ 'Id')" }
            $type = "$(Get-DirectoryAttributeValue $_ 'ObjectType')".Trim()
            if ([string]::IsNullOrWhiteSpace($type)) { "$name" } else { "$name ($type)" }
        }
    )
    return ($lines -join '; ')
}

function Invoke-GraphGetAll {
    <#
        Follow @odata.nextLink. -NoEnumerate so an empty page stays an empty array
        instead of becoming $null (and then a fake count of 1).
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers,
        [string]$ProgressLabel
    )
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $guard = 0
    while (-not [string]::IsNullOrWhiteSpace($next) -and $guard -lt 500) {
        $guard++
        $params = @{ Method = 'GET'; Uri = $next }
        $cmd = Get-Command Invoke-MgGraphRequest -ErrorAction Stop
        if ($cmd.Parameters.ContainsKey('OutputType')) { $params['OutputType'] = 'PSObject' }
        if ($Headers) { $params['Headers'] = $Headers }
        $page = Invoke-MgGraphRequest @params
        $value = @(Get-DirectoryAttributeValue $page 'value' | Where-Object { $null -ne $_ })
        foreach ($item in $value) { [void]$items.Add($item) }
        if ($ProgressLabel -and $script:UI) {
            $loaded = $items.Count
            $script:UI.Window.Dispatcher.Invoke([action] {
                $script:UI.StatusText.Text = "$ProgressLabel ($loaded downloaded)..."
            })
            Invoke-UiRefresh
        }
        $next = "$(Get-DirectoryAttributeValue $page '@odata.nextLink')".Trim()
    }
    if ($items.Count -eq 0) { return }
    Write-Output -NoEnumerate $items.ToArray()
}

function ConvertTo-SyncDirectoryObject {
    param($Raw, [Parameter(Mandatory)][string]$ObjectType)
    if ($null -eq $Raw) { return $null }
    $errors = @(Get-DirectoryAttributeValue $Raw 'OnPremisesProvisioningErrors' | Where-Object { $null -ne $_ })
    if ($errors.Count -eq 0) { return $null }
    $proxies = @(Get-DirectoryAttributeValue $Raw 'ProxyAddresses' | Where-Object { -not (Test-IsBlankAttributeValue $_) })
    return [pscustomobject]@{
        ObjectType        = $ObjectType
        Id                = "$(Get-DirectoryAttributeValue $Raw 'Id')"
        DisplayName       = "$(Get-DirectoryAttributeValue $Raw 'DisplayName')"
        UserPrincipalName = "$(Get-DirectoryAttributeValue $Raw 'UserPrincipalName')"
        Mail              = "$(Get-DirectoryAttributeValue $Raw 'Mail')"
        MailNickname      = Get-GraphMailNickname $Raw
        ProxyAddresses    = $proxies
        SamAccountName    = "$(Get-DirectoryAttributeValue $Raw 'OnPremisesSamAccountName')"
        OnPremDomain      = "$(Get-DirectoryAttributeValue $Raw 'OnPremisesDomainName')"
        ImmutableId       = "$(Get-DirectoryAttributeValue $Raw 'OnPremisesImmutableId')"
        LastSync          = Get-DirectoryAttributeValue $Raw 'OnPremisesLastSyncDateTime'
        AccountEnabled    = Get-DirectoryAttributeValue $Raw 'AccountEnabled'
        Errors            = $errors
    }
}

function Find-CloudAttributeHolders {
    <#
        Directory objects in Entra that already contain this proxy address, mail, or UPN.
        This is the contact or group the portal shows next to the user that failed to sync.
    #>
    param([Parameter(Mandatory)][string]$Value)
    $plans = Get-CloudLookupPlan -Value $Value
    if ($null -eq $plans) { $plans = @() }
    $holders = New-Object System.Collections.Generic.List[object]
    $seenIds = @{}
    $headers = @{ ConsistencyLevel = 'eventual' }
    foreach ($plan in $plans) {
        $filter = [uri]::EscapeDataString($plan.Filter)
        $uri = "https://graph.microsoft.com/v1.0/$($plan.Resource)?`$count=true&`$top=50&`$select=$($plan.Select)&`$filter=$filter"
        try {
            $hits = Invoke-GraphGetAll -Uri $uri -Headers $headers
            if ($null -eq $hits) { $hits = @() }
        }
        catch {
            Write-UiLog "Lookup for '$Value' on $($plan.ObjectType) failed: $($_.Exception.Message)" -Level Warning
            continue
        }
        foreach ($hit in $hits) {
            $id = "$(Get-DirectoryAttributeValue $hit 'Id')"
            if ([string]::IsNullOrWhiteSpace($id) -or $seenIds.ContainsKey($id)) { continue }
            $seenIds[$id] = $true
            [void]$holders.Add([pscustomobject]@{
                Id                = $id
                DisplayName       = "$(Get-DirectoryAttributeValue $hit 'DisplayName')"
                ObjectType        = $plan.ObjectType
                UserPrincipalName = "$(Get-DirectoryAttributeValue $hit 'UserPrincipalName')"
                Mail              = "$(Get-DirectoryAttributeValue $hit 'Mail')"
                ProxyAddresses    = @(Get-DirectoryAttributeValue $hit 'ProxyAddresses' | Where-Object { -not (Test-IsBlankAttributeValue $_) })
            })
        }
    }
    if ($holders.Count -eq 0) { return }
    Write-Output -NoEnumerate $holders.ToArray()
}

function Get-SyncErrorRecords {
    <#
        Enumerates users, groups, and contacts carrying onPremisesProvisioningErrors.
        Entra's duplicate-attribute table also lists the other cloud object that already
        holds the value (often a contact or group). Those holders are added too.
        Optionally cross-references on-prem AD.
        A null cloud mailNickname is written as '(null)'.
    #>
    if (-not $script:State.Connected) {
        [System.Windows.MessageBox]::Show("Connect to Entra ID first.", 'Not Connected', 'OK', 'Warning') | Out-Null
        return
    }

    $doAd = $script:State.AdModuleLoaded -and $script:UI.CrossRefCheck.IsChecked

    Start-UiOperation -Text "Querying Entra ID for users, groups, and contacts with sync errors..." -Stage "Downloading directory"
    Write-UiLog "Querying users, groups, and contacts for on-premises provisioning errors..."

    $script:State.SyncErrorRecords.Clear()

    try {
        $directoryObjects = New-Object System.Collections.Generic.List[object]

        $props = @(
            'id', 'displayName', 'userPrincipalName', 'mail', 'mailNickname', 'proxyAddresses',
            'onPremisesProvisioningErrors', 'onPremisesImmutableId',
            'onPremisesSamAccountName', 'onPremisesDomainName',
            'onPremisesSyncEnabled', 'onPremisesLastSyncDateTime', 'accountEnabled'
        )
        # Graph cannot server-side $filter on onPremisesProvisioningErrors, so page through
        # each object type and filter client-side.
        $users = @(Get-MgUser -All -Property $props -PageSize 999 -ErrorAction Stop |
                 Where-Object { $_.OnPremisesProvisioningErrors -and @($_.OnPremisesProvisioningErrors).Count -gt 0 })
        foreach ($u in $users) {
            $converted = ConvertTo-SyncDirectoryObject -Raw $u -ObjectType 'User'
            if ($null -ne $converted) { [void]$directoryObjects.Add($converted) }
        }
        Write-UiLog "Users with provisioning errors: $($directoryObjects.Count)." -Level $(if ($directoryObjects.Count) { 'Warning' } else { 'Success' })

        $groupSelect = 'id,displayName,mail,mailNickname,proxyAddresses,onPremisesProvisioningErrors,onPremisesSamAccountName,onPremisesDomainName,onPremisesLastSyncDateTime'
        $contactSelect = 'id,displayName,mail,mailNickname,proxyAddresses,onPremisesProvisioningErrors,onPremisesLastSyncDateTime'
        $extraTypes = @(
            @{ Resource = 'groups';   ObjectType = 'Group';   Select = $groupSelect;   Label = 'Groups' },
            @{ Resource = 'contacts'; ObjectType = 'Contact'; Select = $contactSelect; Label = 'Contacts' }
        )
        foreach ($kind in $extraTypes) {
            $before = $directoryObjects.Count
            $selectAttempts = @(
                $kind.Select,
                'id,displayName,mail,mailNickname,proxyAddresses,onPremisesProvisioningErrors'
            )
            $rawItems = @()
            $loaded = $false
            $lastScanError = ''
            foreach ($select in $selectAttempts) {
                try {
                    $uri = "https://graph.microsoft.com/v1.0/$($kind.Resource)?`$select=$select&`$top=999"
                    $rawItems = Invoke-GraphGetAll -Uri $uri -ProgressLabel "Downloading $($kind.Label)"
                    if ($null -eq $rawItems) { $rawItems = @() }
                    $loaded = $true
                    break
                }
                catch {
                    $lastScanError = "$($_.Exception.Message)"
                }
            }
            if (-not $loaded) {
                Write-UiLog "$($kind.Label) scan failed: $lastScanError" -Level Warning
                continue
            }
            foreach ($raw in $rawItems) {
                $converted = ConvertTo-SyncDirectoryObject -Raw $raw -ObjectType $kind.ObjectType
                if ($null -ne $converted) { [void]$directoryObjects.Add($converted) }
            }
            $found = $directoryObjects.Count - $before
            Write-UiLog "$($kind.Label) with provisioning errors: $found." -Level $(if ($found) { 'Warning' } else { 'Success' })
        }

        $objectCount = $directoryObjects.Count
        Write-UiLog "Building detail for $objectCount directory object(s)..." -Level $(if ($objectCount) { 'Warning' } else { 'Success' })

        $seenKeys = @{}
        $i = 0
        foreach ($obj in $directoryObjects) {
            $i++
            $label = if (-not [string]::IsNullOrWhiteSpace($obj.UserPrincipalName)) { $obj.UserPrincipalName } else { $obj.DisplayName }
            $stageMsg = $(if ($doAd) { "Processing $($obj.ObjectType) & cross-referencing AD" } else { "Processing $($obj.ObjectType)" })
            Update-UiProgress -Current $i -Total $objectCount -Text "$stageMsg : $label"

            $graphShape = [pscustomobject]@{
                MailNickname               = $obj.MailNickname
                Mail                       = $obj.Mail
                ProxyAddresses             = $obj.ProxyAddresses
                OnPremisesSamAccountName   = $obj.SamAccountName
            }
            $mailNicknameDisplay = Format-MailNicknameDisplay (Get-GraphMailNickname $graphShape)

            foreach ($err in @($obj.Errors)) {
                $propertyName = "$(Get-DirectoryAttributeValue $err 'PropertyCausingError')"
                $category = "$(Get-DirectoryAttributeValue $err 'Category')"
                $rawValue = Get-DirectoryAttributeValue $err 'Value'
                $occurred = Get-DirectoryAttributeValue $err 'OccurredDateTime'

                $adFinding = $null
                if ($doAd) {
                    $adFinding = Resolve-AdRootCause -User $graphShape -Error $err
                }

                $offendingValue = $rawValue
                if ((Test-IsBlankAttributeValue $offendingValue) -and ($propertyName -match '(?i)mailnickname')) {
                    $offendingValue = '(null)'
                }

                $rootCause = if ($adFinding -and -not (Test-IsBlankAttributeValue $adFinding.Summary)) { $adFinding.Summary } else { '(not checked)' }
                if ($mailNicknameDisplay -eq '(null)' -and $rootCause -notmatch '(?i)The mailNickname attribute has a null value') {
                    $cloudIssue = Get-MailNicknameNullIssue `
                        -MailNickname $obj.MailNickname `
                        -Mail $obj.Mail `
                        -ProxyAddresses $obj.ProxyAddresses `
                        -EntraReportedNull (
                            ($propertyName -match '(?i)mailnickname') -and (Test-IsBlankAttributeValue $rawValue)
                        )
                    $nullNote = if ($cloudIssue) { $cloudIssue.Message } else { 'The mailNickname attribute has a null value.' }
                    if ($rootCause -eq '(not checked)') { $rootCause = $nullNote }
                    else { $rootCause = "$rootCause $nullNote" }
                }

                $rowKey = Get-SyncValueKey -ObjectId $obj.Id -Property $propertyName -Value "$offendingValue"
                $seenKeys[$rowKey] = $true

                $lastSyncText = ''
                if ($obj.LastSync) { $lastSyncText = ([datetime]$obj.LastSync).ToString('yyyy-MM-dd HH:mm') }
                $occurredText = ''
                if ($occurred) { $occurredText = ([datetime]$occurred).ToString('yyyy-MM-dd HH:mm') }

                $record = [pscustomobject]@{
                    DisplayName       = $obj.DisplayName
                    ObjectType        = $obj.ObjectType
                    UserPrincipalName = $(if ($obj.UserPrincipalName) { $obj.UserPrincipalName } else { $obj.Mail })
                    Category          = $category
                    Property          = $propertyName
                    OffendingValue    = $offendingValue
                    CloudHolders      = ''
                    OccurredUtc       = $occurredText
                    SamAccountName    = $obj.SamAccountName
                    OnPremDomain      = $obj.OnPremDomain
                    ImmutableId       = $obj.ImmutableId
                    LastSyncUtc       = $lastSyncText
                    AccountEnabled    = $obj.AccountEnabled
                    MailNickname      = $mailNicknameDisplay
                    ProxyAddresses    = ($obj.ProxyAddresses -join '; ')
                    AdRootCause       = $rootCause
                    AdConflictObjects = if ($adFinding) { $adFinding.Conflicts } else { '' }
                    ObjectId          = $obj.Id
                    HolderOnly        = $false
                }
                $script:UI.Window.Dispatcher.Invoke([action] { $script:State.SyncErrorRecords.Add($record) })
            }
        }

        # Match the Entra duplicate-attribute table: every cloud object that holds the value.
        $valuesToResolve = @(
            $script:State.SyncErrorRecords |
                Where-Object { -not (Test-IsBlankAttributeValue $_.OffendingValue) -and "$($_.OffendingValue)" -ne '(null)' } |
                Select-Object -ExpandProperty OffendingValue -Unique
        )
        $holderCache = @{}
        $lookupTotal = @($valuesToResolve).Count
        $lookupIndex = 0
        foreach ($lookupValue in $valuesToResolve) {
            $lookupIndex++
            Update-UiProgress -Current $lookupIndex -Total $lookupTotal -Text "Finding other Entra objects with '$lookupValue'..."
            $bareKey = (Get-BareAddress "$lookupValue").ToLower()
            if ([string]::IsNullOrWhiteSpace($bareKey)) { continue }
            if (-not $holderCache.ContainsKey($bareKey)) {
                $foundHolders = Find-CloudAttributeHolders -Value "$lookupValue"
                if ($null -eq $foundHolders) { $foundHolders = @() }
                $holderCache[$bareKey] = $foundHolders
            }
            $holders = $holderCache[$bareKey]
            if ($null -eq $holders) { $holders = @() }
            $summary = Format-CloudHolderSummary $holders

            foreach ($existing in @($script:State.SyncErrorRecords)) {
                $existingBare = (Get-BareAddress "$($existing.OffendingValue)").ToLower()
                if ($existingBare -eq $bareKey) { $existing.CloudHolders = $summary }
            }

            $sample = @($script:State.SyncErrorRecords | Where-Object { (Get-BareAddress "$($_.OffendingValue)").ToLower() -eq $bareKey } | Select-Object -First 1)
            if ($sample.Count -eq 0) { continue }
            $template = $sample[0]
            foreach ($holder in $holders) {
                $holderKey = Get-SyncValueKey -ObjectId $holder.Id -Property $template.Property -Value "$lookupValue"
                if ($seenKeys.ContainsKey($holderKey)) { continue }
                $seenKeys[$holderKey] = $true
                $holderRecord = [pscustomobject]@{
                    DisplayName       = $holder.DisplayName
                    ObjectType        = $holder.ObjectType
                    UserPrincipalName = $(if ($holder.UserPrincipalName) { $holder.UserPrincipalName } else { $holder.Mail })
                    Category          = 'PropertyConflict'
                    Property          = $template.Property
                    OffendingValue    = $lookupValue
                    CloudHolders      = $summary
                    OccurredUtc       = ''
                    SamAccountName    = ''
                    OnPremDomain      = ''
                    ImmutableId       = ''
                    LastSyncUtc       = ''
                    AccountEnabled    = ''
                    MailNickname      = ''
                    ProxyAddresses    = (@($holder.ProxyAddresses) -join '; ')
                    AdRootCause       = "Holds this duplicated value in Entra ($($holder.ObjectType)). The portal lists this object next to the one that failed to sync."
                    AdConflictObjects = ''
                    ObjectId          = $holder.Id
                    HolderOnly        = $true
                }
                $script:UI.Window.Dispatcher.Invoke([action] { $script:State.SyncErrorRecords.Add($holderRecord) })
                Write-UiLog "Also in Entra: $($holder.DisplayName) ($($holder.ObjectType)) has '$lookupValue'." -Level Warning
            }
        }

        $boundView = [System.Windows.Data.CollectionViewSource]::GetDefaultView($script:State.SyncErrorRecords)
        if ($boundView) { $boundView.Refresh() }

        $total = $script:State.SyncErrorRecords.Count
        $objectIds = @($script:State.SyncErrorRecords | Select-Object -ExpandProperty ObjectId -Unique)
        $typeCounts = @($script:State.SyncErrorRecords | Group-Object ObjectType | ForEach-Object { "$($_.Count) $($_.Name.ToLower())" })
        $nullNickUsers = @($script:State.SyncErrorRecords |
            Where-Object { $_.MailNickname -eq '(null)' -and $_.ObjectType -eq 'User' } |
            Select-Object -ExpandProperty UserPrincipalName -Unique)
        $script:UI.Window.Dispatcher.Invoke([action] {
            $countText = "$total record(s) across $($objectIds.Count) object(s)"
            if ($typeCounts.Count -gt 0) { $countText += " ($($typeCounts -join ', '))" }
            if ($nullNickUsers.Count -gt 0) {
                $countText += "  |  $($nullNickUsers.Count) with null mailNickname"
            }
            $script:UI.ResultCount.Text = $countText
        })
        Write-UiLog "Scan complete: $total record(s) across $($objectIds.Count) directory object(s)." -Level Success
        if ($nullNickUsers.Count -gt 0) {
            $preview = ($nullNickUsers | Select-Object -First 15) -join ', '
            $more = if ($nullNickUsers.Count -gt 15) { ' ...' } else { '' }
            Write-UiLog "$($nullNickUsers.Count) user(s) have a null mailNickname: $preview$more" -Level Warning
        }
    }
    catch {
        Write-UiLog "Sync error scan failed: $($_.Exception.Message)" -Level Error
        [System.Windows.MessageBox]::Show("Scan failed:`n`n$($_.Exception.Message)", 'Scan Error', 'OK', 'Error') | Out-Null
    }
    finally {
        Stop-UiOperation -Text $(if ($script:State.SyncErrorRecords.Count) { "Scan finished: $($script:State.SyncErrorRecords.Count) error record(s)" } else { "Scan finished: no sync errors found" })
    }
}

function Resolve-AdRootCause {
    <#
        Given an errored cloud user + a specific provisioning error, inspect on-prem AD to
        find the objects that most likely caused it (duplicate attribute values are the
        overwhelmingly common cause of AD Connect sync errors).

        A null mailNickname is reported in plain language. The cloud offending value for
        that failure is empty, which otherwise reads as "no matching object".
    #>
    param(
        [Parameter(Mandatory)]$User,
        [Parameter(Mandatory)]$Error
    )

    $result = [pscustomobject]@{ Summary = ''; Conflicts = '' }
    if (-not $script:State.AdModuleLoaded) { return $result }

    try {
        $prop  = ("$($Error.PropertyCausingError)").ToLower()
        $value = "$($Error.Value)"

        $conflicts = @()

        switch -Wildcard ($prop) {
            '*proxyaddress*' {
                # Find every AD object that carries the offending proxy address value.
                $filterVal = $value -replace "'", "''"
                $conflicts = Get-ADObject -LDAPFilter "(proxyAddresses=*$filterVal*)" -Properties proxyAddresses, userPrincipalName, mail -ErrorAction SilentlyContinue |
                             ForEach-Object { "$($_.Name) [$($_.DistinguishedName)]" }
                break
            }
            '*userprincipalname*' {
                $conflicts = Get-ADUser -LDAPFilter "(userPrincipalName=$value)" -Properties userPrincipalName -ErrorAction SilentlyContinue |
                             ForEach-Object { "$($_.SamAccountName) -> $($_.UserPrincipalName) [$($_.DistinguishedName)]" }
                break
            }
            '*mailnickname*' {
                $sources = @()
                if ($User.OnPremisesSamAccountName) {
                    $samEsc = Format-LdapFilterValue "$($User.OnPremisesSamAccountName)"
                    # Filter $null so a miss stays Count 0. @($null).Count is 1 in Windows PowerShell 5.1.
                    $sources = @(
                        Get-ADUser -LDAPFilter "(sAMAccountName=$samEsc)" -Properties mailNickname, mail, proxyAddresses, userPrincipalName -ErrorAction SilentlyContinue |
                            Where-Object { $null -ne $_ }
                    )
                }
                $result.Conflicts = @(
                    $sources | ForEach-Object {
                        "$($_.SamAccountName) mailNickname=$(Format-MailNicknameDisplay $_.mailNickname) [$($_.DistinguishedName)]"
                    }
                ) -join ' || '

                if (Test-IsBlankAttributeValue $value) {
                    $onPremSet = @($sources | Where-Object { -not (Test-IsBlankAttributeValue $_.mailNickname) })
                    if ($sources.Count -eq 0) {
                        $result.Summary = "The mailNickname attribute has a null value. The on-prem source object could not be located."
                    }
                    elseif ($onPremSet.Count -eq 0) {
                        $result.Summary = "The mailNickname attribute has a null value on the on-prem source object."
                    }
                    else {
                        $vals = ($onPremSet | ForEach-Object { Format-MailNicknameDisplay $_.mailNickname }) -join ', '
                        $result.Summary = "Entra reports that the mailNickname attribute has a null value, but on-prem mailNickname is '$vals'."
                    }
                    break
                }

                $holders = @(
                    Get-AdObjectsWithAttribute -Attribute 'mailNickname' -Value $value |
                        Where-Object { $null -ne $_ }
                )
                $sourceDns = @($sources | ForEach-Object { "$($_.DistinguishedName)" })
                $dupes = @($holders | Where-Object { $sourceDns -notcontains "$($_.DistinguishedName)" })
                if ($dupes.Count -ge 1) {
                    $result.Summary = "DUPLICATE: $($dupes.Count) other AD object(s) share mailNickname '$value'."
                    $result.Conflicts = ($dupes | ForEach-Object { "$($_.Name) [$($_.DistinguishedName)]" }) -join ' || '
                }
                elseif ($sources.Count -ge 1) {
                    $result.Summary = "Source object located; mailNickname '$value' appears unique in AD (check other domains/forests)."
                }
                else {
                    $result.Summary = "No matching AD object found for mailNickname '$value' (possible orphaned/soft-matched cloud object)."
                }
                break
            }
            '*mail*' {
                $conflicts = Get-ADObject -LDAPFilter "(mail=$value)" -Properties mail -ErrorAction SilentlyContinue |
                             ForEach-Object { "$($_.Name) [$($_.DistinguishedName)]" }
                break
            }
            default {
                # Generic fallback: locate the source object by the immutableId / sAMAccountName.
                if ($User.OnPremisesSamAccountName) {
                    $conflicts = Get-ADUser -LDAPFilter "(sAMAccountName=$($User.OnPremisesSamAccountName))" -Properties userPrincipalName, proxyAddresses, mail -ErrorAction SilentlyContinue |
                                 ForEach-Object { "$($_.SamAccountName) [$($_.DistinguishedName)]" }
                }
            }
        }

        # The mailNickname branch writes Summary/Conflicts itself and then breaks.
        # Every other branch still flows through this shared duplicate summary.
        if (-not (Test-IsBlankAttributeValue $result.Summary)) {
            return $result
        }

        if ($conflicts.Count -gt 1) {
            $result.Summary   = "DUPLICATE: $($conflicts.Count) AD objects share '$value' on '$prop'."
            $result.Conflicts = ($conflicts -join ' || ')
        }
        elseif ($conflicts.Count -eq 1) {
            $result.Summary   = "Source object located; value '$value' appears unique in AD (check other domains/forests)."
            $result.Conflicts = ($conflicts -join ' || ')
        }
        else {
            $result.Summary   = "No matching AD object found for '$value' (possible orphaned/soft-matched cloud object)."
        }
    }
    catch {
        $result.Summary = "AD lookup error: $($_.Exception.Message)"
    }

    return $result
}

function Format-LdapFilterValue {
    <#
        RFC 4515 escaping so attribute values containing ( ) * \ or NUL are matched literally
        instead of breaking (or worse, silently widening) the LDAP filter.
    #>
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '\'  { [void]$sb.Append('\5c') }
            '*'  { [void]$sb.Append('\2a') }
            '('  { [void]$sb.Append('\28') }
            ')'  { [void]$sb.Append('\29') }
            "`0" { [void]$sb.Append('\00') }
            default { [void]$sb.Append($ch) }
        }
    }
    return $sb.ToString()
}

function Get-AdObjectsWithAttribute {
    <#
        Returns every AD object (user, contact, or group) that carries an exact attribute
        value, excluding the object we are currently inspecting. This is how we catch the
        "two objects share the same value" condition that Entra rejects.
    #>
    param(
        [Parameter(Mandatory)][string]$Attribute,
        [Parameter(Mandatory)][string]$Value,
        [string]$ExcludeDn
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    $esc = Format-LdapFilterValue $Value
    $out = @()
    try {
        $hits = Get-ADObject -LDAPFilter "($Attribute=$esc)" -Properties $Attribute, userPrincipalName, mail, objectClass -ErrorAction Stop
        foreach ($h in @($hits)) {
            if ($ExcludeDn -and $h.DistinguishedName -eq $ExcludeDn) { continue }
            $out += $h
        }
    }
    catch {
        Write-UiLog "Lookup on '$Attribute' failed: $($_.Exception.Message)" -Level Warning
    }
    return $out
}

function Find-AddressUsage {
    <#
        Directory-wide reverse lookup. Given an email/proxy address (with or without a type
        prefix), find EVERY object that references it in proxyAddresses, mail, targetAddress,
        or userPrincipalName. Queries the forest Global Catalog (port 3268) so a duplicate
        living in a DIFFERENT domain of the forest is also caught, then falls back to the
        local domain. This is what answers "where else is this address being used?"
    #>
    param(
        [Parameter(Mandatory)][string]$Address,
        [string]$ExcludeDn
    )

    # Normalize: strip a leading type prefix (smtp:, sip:, x500: ...) to get the bare address.
    $bare = $Address -replace '^(?i)[a-z0-9]+:', ''
    if ([string]::IsNullOrWhiteSpace($bare)) { return @() }
    $escBare = Format-LdapFilterValue $bare

    # Prefer the Global Catalog (forest-wide); fall back to the local domain if unreachable.
    $server = $null
    try {
        $rootDse = Get-ADRootDSE -ErrorAction Stop
        $server  = "$($rootDse.dnsHostName):3268"
    } catch { $server = $null }

    $filter = "(|(proxyAddresses=smtp:$escBare)(mail=$escBare)(targetAddress=smtp:$escBare)(userPrincipalName=$escBare))"
    $params = @{
        LDAPFilter  = $filter
        Properties  = @('proxyAddresses', 'mail', 'targetAddress', 'userPrincipalName', 'objectClass', 'userAccountControl', 'displayName')
        ErrorAction = 'SilentlyContinue'
    }
    if ($server) { $params['Server'] = $server }

    $hits = $null
    try {
        $hits = Get-ADObject @params
        # If the GC query yielded nothing (or errored), retry against the local domain.
        if (-not $hits -and $server) {
            $params.Remove('Server')
            $hits = Get-ADObject @params
        }
    }
    catch {
        Write-UiLog "Address lookup for '$bare' failed: $($_.Exception.Message)" -Level Warning
        return @()
    }

    $results = @()
    foreach ($h in @($hits)) {
        # Get-ADObject returns multi-valued ADPropertyValueCollection objects even for
        # single-valued attributes, so extract scalar values explicitly. Passing a raw
        # collection to the bitwise -band operator throws "Argument types do not match".
        $hMail   = "$(@($h.mail)[0])"
        $hUpn    = "$(@($h.userPrincipalName)[0])"
        $hTarget = "$(@($h.targetAddress)[0])"
        $uacVal  = @($h.userAccountControl)[0]

        # Determine exactly HOW this object references the address.
        $refs = @()
        foreach ($p in @($h.proxyAddresses)) {
            if (("$p" -replace '^(?i)[a-z0-9]+:', '') -ieq $bare) {
                $refs += $(if ("$p" -cmatch '^SMTP:') { "proxyAddresses (PRIMARY SMTP)" } else { "proxyAddresses (secondary: $p)" })
            }
        }
        if ($hMail -ieq $bare) { $refs += 'mail' }
        if ($hUpn  -ieq $bare) { $refs += 'userPrincipalName' }
        if (($hTarget -replace '^(?i)[a-z0-9]+:', '') -ieq $bare) { $refs += 'targetAddress' }

        # Cast the scalar to a plain [int] before the bitwise test (0x2 = ACCOUNTDISABLE).
        $disabled = $false
        if ($null -ne $uacVal) {
            $uacInt = 0
            if ([int]::TryParse("$uacVal", [ref]$uacInt)) { $disabled = [bool]($uacInt -band 0x2) }
        }

        $results += [pscustomobject]@{
            Name        = "$($h.Name)"
            ObjectClass = "$($h.objectClass)"
            Dn          = "$($h.DistinguishedName)"
            Disabled    = $disabled
            IsSelf      = ($ExcludeDn -and "$($h.DistinguishedName)" -eq $ExcludeDn)
            HeldIn      = $(if ($refs.Count) { $refs -join ', ' } else { '(matched by filter)' })
        }
    }
    return $results
}

function Get-AdSyncDiagnosis {
    <#
        The robustness core of the AD Scanner. For a single AD user it:
          1. Checks every uniqueness-constrained attribute (UPN, mail, mailNickname,
             each proxyAddress, ms-DS-ConsistencyGuid) for DUPLICATE values elsewhere in AD.
             A null mailNickname is reported on its own. It is not a duplicate, but Entra
             Connect still rejects a null alias on mail-enabled objects, and the cloud
             offending value for that failure is empty.
          2. Validates on-prem formatting that Entra Connect refuses to sync
             (bad UPN, non-routable domain, multiple/zero primary SMTP, bad proxy prefixes,
             mail vs primary-SMTP mismatch, illegal/whitespace characters, disabled sourceAnchor).
          3. Cross-references the errors Entra ITSELF reported for this user (from the last
             Sync Errors scan) so the exact offending attribute is named authoritatively.
        Returns an object holding a ranked issue list plus the matched Entra errors.
    #>
    param([Parameter(Mandatory)]$User)

    $issues = New-Object System.Collections.Generic.List[object]
    $dn = $User.DistinguishedName

    function Add-Issue {
        param([string]$Severity, [string]$Attribute, [string]$Value, [string]$Message, [string[]]$Conflicts = @())
        $issues.Add([pscustomobject]@{
            Severity  = $Severity      # Critical | Warning | Info
            Attribute = $Attribute
            Value     = $Value
            Message   = $Message
            Conflicts = $Conflicts
        })
    }

    $addressUsage    = New-Object System.Collections.Generic.List[object]
    $tracedAddresses = @{}

    # ---- 1. Uniqueness-constrained single-valued attributes -----------------------------
    $uniqueAttrs = @(
        @{ Name = 'userPrincipalName'; Value = "$($User.UserPrincipalName)" },
        @{ Name = 'mail';              Value = "$($User.mail)" },
        @{ Name = 'mailNickname';      Value = "$(Get-DirectoryAttributeValue $User 'mailNickname')" }
    )
    foreach ($a in $uniqueAttrs) {
        # Blank values are not duplicates. A null mailNickname is reported in section 7b.
        if ([string]::IsNullOrWhiteSpace($a.Value)) { continue }
        $others = Get-AdObjectsWithAttribute -Attribute $a.Name -Value $a.Value -ExcludeDn $dn
        if (@($others).Count -ge 1) {
            $names = @($others | ForEach-Object { "$($_.Name) ($($_.objectClass)) [$($_.DistinguishedName)]" })
            Add-Issue -Severity 'Critical' -Attribute $a.Name -Value $a.Value `
                -Message "DUPLICATE VALUE shared with $(@($others).Count) other AD object(s). Entra requires '$($a.Name)' to be unique across the tenant." `
                -Conflicts $names
        }
    }

    # ---- 2. proxyAddresses: per-value duplicates + structural validation ----------------
    $proxies      = @($User.proxyAddresses)
    $primarySmtp  = @($proxies | Where-Object { $_ -cmatch '^SMTP:' })   # case-sensitive: uppercase = primary
    $seenLower    = @{}
    foreach ($pa in $proxies) {
        if ([string]::IsNullOrWhiteSpace($pa)) { continue }
        $paLower = $pa.ToLower()

        # duplicate value WITHIN this same object
        if ($seenLower.ContainsKey($paLower)) {
            Add-Issue -Severity 'Critical' -Attribute 'proxyAddresses' -Value $pa `
                -Message "Address '$pa' is listed more than once on THIS object (case-insensitive duplicate)."
        } else { $seenLower[$paLower] = $true }

        # valid address-type prefix?
        if ($pa -notmatch '^(?i)(smtp:|sip:|x500:|x400:|eum:|eumproxy:|onmicrosoft:)') {
            Add-Issue -Severity 'Warning' -Attribute 'proxyAddresses' -Value $pa `
                -Message "Address '$pa' has a missing or unrecognized type prefix (expected e.g. 'smtp:' / 'sip:' / 'x500:'). Entra may reject it."
        }

        # duplicate value across the DIRECTORY/forest (only meaningful for smtp addresses)
        if ($pa -match '^(?i)smtp:') {
            $bareKey = ($pa -replace '^(?i)smtp:', '').ToLower()
            if (-not $tracedAddresses.ContainsKey($bareKey)) {
                $tracedAddresses[$bareKey] = $true
                $holders = Find-AddressUsage -Address $pa -ExcludeDn $dn
                $others  = @($holders | Where-Object { -not $_.IsSelf })
                $addressUsage.Add([pscustomobject]@{ Address = ($pa -replace '^(?i)smtp:', ''); Source = 'AD proxyAddress'; Holders = $holders })
                if ($others.Count -ge 1) {
                    $names = @($others | ForEach-Object { "$($_.Name) ($($_.ObjectClass), held in $($_.HeldIn))$(if ($_.Disabled) { ' [DISABLED]' })  [$($_.Dn)]" })
                    Add-Issue -Severity 'Critical' -Attribute 'proxyAddresses' -Value $pa `
                        -Message "DUPLICATE ADDRESS: '$pa' is also used by $($others.Count) other object(s) in the directory. This is the #1 cause of Connect sync errors." `
                        -Conflicts $names
                }
            }
        }
    }
    if (@($primarySmtp).Count -gt 1) {
        Add-Issue -Severity 'Critical' -Attribute 'proxyAddresses' -Value ($primarySmtp -join ', ') `
            -Message "Object has $(@($primarySmtp).Count) PRIMARY SMTP addresses (uppercase 'SMTP:'). Exactly one is allowed."
    }
    elseif (@($primarySmtp).Count -eq 0 -and @($proxies).Count -gt 0) {
        Add-Issue -Severity 'Warning' -Attribute 'proxyAddresses' -Value '' `
            -Message "Object has proxyAddresses but NO primary SMTP (uppercase 'SMTP:') entry."
    }

    # ---- 3. mail vs primary SMTP alignment ----------------------------------------------
    if (@($primarySmtp).Count -eq 1 -and -not [string]::IsNullOrWhiteSpace("$($User.mail)")) {
        $primaryValue = ($primarySmtp[0] -replace '^(?i)smtp:', '')
        if ($primaryValue -ne "$($User.mail)") {
            Add-Issue -Severity 'Warning' -Attribute 'mail' -Value "$($User.mail)" `
                -Message "The 'mail' attribute ('$($User.mail)') does not match the primary SMTP ('$primaryValue')."
        }
    }

    # ---- 4. UPN format validation -------------------------------------------------------
    $upn = "$($User.UserPrincipalName)"
    if ([string]::IsNullOrWhiteSpace($upn)) {
        Add-Issue -Severity 'Critical' -Attribute 'userPrincipalName' -Value '' `
            -Message "userPrincipalName is EMPTY. Entra cannot provision a user without a UPN."
    }
    else {
        $atCount = @($upn.ToCharArray() | Where-Object { $_ -eq '@' }).Count
        if ($atCount -ne 1) {
            Add-Issue -Severity 'Critical' -Attribute 'userPrincipalName' -Value $upn `
                -Message "UPN '$upn' must contain exactly one '@' (found $atCount)."
        }
        else {
            $domain = $upn.Split('@')[1]
            if ($domain -match '(?i)\.(local|internal|corp|lan)$' -or $domain -notmatch '\.') {
                Add-Issue -Severity 'Warning' -Attribute 'userPrincipalName' -Value $upn `
                    -Message "UPN suffix '@$domain' is not an internet-routable / verified domain. Users sync but may fall back to '.onmicrosoft.com'."
            }
        }
        if ($upn -match '\s') {
            Add-Issue -Severity 'Critical' -Attribute 'userPrincipalName' -Value $upn `
                -Message "UPN contains whitespace, which Entra rejects."
        }
    }

    # ---- 5. sourceAnchor (ms-DS-ConsistencyGuid) duplication ----------------------------
    if ($User.'mS-DS-ConsistencyGuid') {
        try {
            $cgBytes = [byte[]]$User.'mS-DS-ConsistencyGuid'
            # Build the escaped octet string for an exact binary LDAP match.
            $escaped = (($cgBytes | ForEach-Object { '\{0:x2}' -f $_ }) -join '')
            $cgHits = Get-ADObject -LDAPFilter "(mS-DS-ConsistencyGuid=$escaped)" -Properties distinguishedName -ErrorAction SilentlyContinue
            $cgOthers = @($cgHits | Where-Object { $_.DistinguishedName -ne $dn })
            if (@($cgOthers).Count -ge 1) {
                $names = @($cgOthers | ForEach-Object { "$($_.Name) [$($_.DistinguishedName)]" })
                Add-Issue -Severity 'Critical' -Attribute 'mS-DS-ConsistencyGuid' -Value '(binary)' `
                    -Message "DUPLICATE sourceAnchor: another object shares this ms-DS-ConsistencyGuid. This causes hard sync/soft-match failures." `
                    -Conflicts $names
            }
        } catch {}
    }

    # ---- 6. Illegal / control characters in key text attributes -------------------------
    foreach ($chk in @(
        @{ Name = 'userPrincipalName'; Value = "$($User.UserPrincipalName)" },
        @{ Name = 'mail';              Value = "$($User.mail)" },
        @{ Name = 'displayName';       Value = "$($User.DisplayName)" }
    )) {
        if ([string]::IsNullOrEmpty($chk.Value)) { continue }
        if ($chk.Value -match '[\x00-\x1F\x7F]') {
            Add-Issue -Severity 'Critical' -Attribute $chk.Name -Value $chk.Value `
                -Message "'$($chk.Name)' contains non-printable/control characters."
        }
        elseif ($chk.Value -ne $chk.Value.Trim()) {
            Add-Issue -Severity 'Warning' -Attribute $chk.Name -Value $chk.Value `
                -Message "'$($chk.Name)' has leading or trailing whitespace."
        }
    }

    # ---- 7. Cross-reference what Entra ITSELF reported for this user ---------------------
    $entra = @()
    if ($script:State.SyncErrorRecords -and $script:State.SyncErrorRecords.Count -gt 0) {
        $sam = "$($User.SamAccountName)"
        $entra = @($script:State.SyncErrorRecords | Where-Object {
            ($upn -and $_.UserPrincipalName -eq $upn) -or
            ($sam -and $_.SamAccountName -eq $sam)
        })
    }

    # ---- 7b. Null mailNickname (alias) ---------------------------------------------------
    # The duplicate check above skips a blank mailNickname, so without this block a user
    # whose alias was never set looks sync-healthy. State the null explicitly.
    $mailNickRaw = Get-DirectoryAttributeValue $User 'mailNickname'
    $entraNickNull = @($entra | Where-Object {
        "$($_.Property)" -match '(?i)mailnickname' -and (Test-IsReportedNullValue $_.OffendingValue)
    })
    $nickIssue = Get-MailNicknameNullIssue -MailNickname $mailNickRaw `
        -Mail (Get-DirectoryAttributeValue $User 'mail') `
        -ProxyAddresses (Get-DirectoryAttributeValue $User 'proxyAddresses') `
        -EntraReportedNull ($entraNickNull.Count -gt 0)
    if ($nickIssue) {
        Add-Issue -Severity $nickIssue.Severity -Attribute 'mailNickname' -Value $nickIssue.Value -Message $nickIssue.Message
    }

    # ---- 8. Trace every Entra-reported OFFENDING VALUE back through the directory --------
    # Entra's offending value is authoritative (its prefix/case may differ from what the
    # object currently holds), so hunt it down explicitly and list every holder. This is
    # the direct answer to "where else is this proxy address being used?"
    foreach ($e in $entra) {
        $val = "$($e.OffendingValue)"
        if ([string]::IsNullOrWhiteSpace($val) -or $val.Trim() -eq '(null)') { continue }
        if ($val -notmatch '@') { continue }   # only trace address-like values
        $bareKey = ($val -replace '^(?i)[a-z0-9]+:', '').ToLower()
        if ($tracedAddresses.ContainsKey($bareKey)) { continue }
        $tracedAddresses[$bareKey] = $true

        $holders = Find-AddressUsage -Address $val -ExcludeDn $dn
        $others  = @($holders | Where-Object { -not $_.IsSelf })
        $addressUsage.Add([pscustomobject]@{ Address = ($val -replace '^(?i)[a-z0-9]+:', ''); Source = "Entra $($e.Property) conflict"; Holders = $holders })

        if ($others.Count -ge 1) {
            $names = @($others | ForEach-Object { "$($_.Name) ($($_.ObjectClass), held in $($_.HeldIn))$(if ($_.Disabled) { ' [DISABLED]' })  [$($_.Dn)]" })
            Add-Issue -Severity 'Critical' -Attribute "$($e.Property)" -Value $val `
                -Message "CONFLICT SOURCE FOUND: Entra flagged '$val' and it is used by $($others.Count) other directory object(s)." `
                -Conflicts $names
        }
        else {
            Add-Issue -Severity 'Warning' -Attribute "$($e.Property)" -Value $val `
                -Message "Entra flagged '$val' as a conflict, but NO other on-prem/forest object holds it. The duplicate almost certainly lives in the cloud (a cloud-only mailbox/M365 group, a soft-matched or orphaned Entra object, or another synced forest). Check Entra directly and run IdFix."
        }
    }

    # Return plain arrays (NOT System.Collections.Generic.List[object]). Comparing a raw
    # generic List with -gt/-lt in PS 5.1 throws "Argument types do not match"; a normal
    # object[] behaves correctly, matching how EntraErrors is handled.
    return [pscustomobject]@{
        Issues       = @($issues.ToArray())
        EntraErrors  = @($entra)
        AddressUsage = @($addressUsage.ToArray())
    }
}

function Search-ActiveDirectoryUser {
    <#
        Ad-hoc on-prem AD lookup. Accepts a UPN, sAMAccountName, display name fragment, or
        email and returns the sync-relevant attributes plus a full sync diagnosis.
    #>
    param([Parameter(Mandatory)][string]$Query)

    if (-not $script:State.AdModuleLoaded) {
        [System.Windows.MessageBox]::Show("The ActiveDirectory module is not loaded. Install RSAT and rerun (or remove -SkipActiveDirectory).", 'AD Unavailable', 'OK', 'Warning') | Out-Null
        return
    }

    Start-UiOperation -Text "Searching Active Directory for '$Query'..." -Stage "Querying AD"
    $script:UI.LastAdSummary = ''
    $script:UI.AdResultsBox.Dispatcher.Invoke([action] { $script:UI.AdResultsBox.Clear() })

    try {
        $q = $Query.Trim() -replace "'", "''"
        $ldap = "(|(userPrincipalName=$q)(sAMAccountName=$q)(mail=$q)(proxyAddresses=*$q*)(anr=$q))"

        $props = @('userPrincipalName', 'mail', 'mailNickname', 'proxyAddresses', 'targetAddress',
                   'mS-DS-ConsistencyGuid', 'objectGUID', 'whenCreated', 'whenChanged', 'enabled',
                   'distinguishedName', 'displayName', 'sAMAccountName', 'userAccountControl')

        $found = Get-ADUser -LDAPFilter $ldap -Properties $props -ErrorAction Stop

        if (-not $found) {
            Write-UiLog "No AD users matched '$Query'." -Level Warning
            $script:UI.AdResultsBox.Dispatcher.Invoke([action] { $script:UI.AdResultsBox.AppendText("No matching AD users found.`r`n") })
            return
        }

        $sb = New-Object System.Text.StringBuilder
        $adList  = @($found)
        $adTotal = $adList.Count
        $adIdx   = 0
        $grandCritical = 0
        $grandWarning  = 0
        foreach ($u in $adList) {
            $adIdx++
            Update-UiProgress -Current $adIdx -Total $adTotal -Text "Inspecting & diagnosing $($u.SamAccountName) ($adIdx of $adTotal)..."
            [void]$sb.AppendLine("================================================================")
            [void]$sb.AppendLine("  $($u.DisplayName)   ($($u.SamAccountName))")
            [void]$sb.AppendLine("================================================================")
            [void]$sb.AppendLine("  Enabled            : $($u.Enabled)")
            [void]$sb.AppendLine("  UserPrincipalName  : $($u.UserPrincipalName)")
            [void]$sb.AppendLine("  Mail               : $($u.mail)")
            $nickShown = Format-MailNicknameDisplay (Get-DirectoryAttributeValue $u 'mailNickname')
            [void]$sb.AppendLine("  mailNickname       : $nickShown")
            if ($nickShown -eq '(null)') {
                [void]$sb.AppendLine("    ^ The mailNickname attribute has a null value.")
            }
            [void]$sb.AppendLine("  DistinguishedName  : $($u.DistinguishedName)")
            [void]$sb.AppendLine("  objectGUID         : $($u.objectGUID)")

            # ImmutableId / ms-DS-ConsistencyGuid comparison (a top sync-mismatch cause).
            $guidB64 = [System.Convert]::ToBase64String(([guid]$u.objectGUID).ToByteArray())
            [void]$sb.AppendLine("  ImmutableId(objGUID): $guidB64")
            if ($u.'mS-DS-ConsistencyGuid') {
                try {
                    $cgB64 = [System.Convert]::ToBase64String([byte[]]$u.'mS-DS-ConsistencyGuid')
                    [void]$sb.AppendLine("  ConsistencyGuid    : $cgB64")
                    if ($cgB64 -ne $guidB64) {
                        [void]$sb.AppendLine("    ^ NOTE: ConsistencyGuid differs from objectGUID (sourceAnchor = ms-DS-ConsistencyGuid).")
                    }
                } catch {}
            }
            [void]$sb.AppendLine("  whenCreated        : $($u.whenCreated)")
            [void]$sb.AppendLine("  whenChanged        : $($u.whenChanged)")

            # List proxy addresses (primary SMTP marked). Duplicate analysis happens in the diagnosis below.
            if ($u.proxyAddresses) {
                [void]$sb.AppendLine("  proxyAddresses:")
                foreach ($pa in $u.proxyAddresses) {
                    $tag = $(if ($pa -cmatch '^SMTP:') { "  (PRIMARY)" } else { "" })
                    [void]$sb.AppendLine("      $pa$tag")
                }
            }
            [void]$sb.AppendLine("")

            # ================= SYNC DIAGNOSIS =================
            # Run the diagnosis in isolation so a single failure reports its exact location
            # and still lets the rest of the search (and other users) complete.
            $diag = $null
            try {
                $diag = Get-AdSyncDiagnosis -User $u
            }
            catch {
                $dLine = $_.InvocationInfo.ScriptLineNumber
                $dType = $_.Exception.GetType().Name
                [void]$sb.AppendLine("  ---------------- SYNC DIAGNOSIS ----------------")
                [void]$sb.AppendLine("  >> DIAGNOSIS ERROR for this object: $($_.Exception.Message)")
                [void]$sb.AppendLine("     ($dType at line $dLine) - AD attributes above are still valid.")
                [void]$sb.AppendLine("  ------------------------------------------------")
                [void]$sb.AppendLine("")
                Write-UiLog "Diagnosis failed for $($u.SamAccountName): $($_.Exception.Message) [$dType line $dLine]" -Level Error
                continue
            }

            $critical = @($diag.Issues | Where-Object { $_.Severity -eq 'Critical' })
            $warnings = @($diag.Issues | Where-Object { $_.Severity -eq 'Warning' })
            $infos    = @($diag.Issues | Where-Object { $_.Severity -eq 'Info' })
            $grandCritical += $critical.Count
            $grandWarning  += $warnings.Count

            [void]$sb.AppendLine("  ---------------- SYNC DIAGNOSIS ----------------")

            # What Entra itself reported (authoritative attribute causing the error).
            if (@($diag.EntraErrors).Count -gt 0) {
                [void]$sb.AppendLine("  >> ENTRA-REPORTED SYNC ERRORS (from last scan):")
                foreach ($e in $diag.EntraErrors) {
                    [void]$sb.AppendLine("       * Attribute causing error : $($e.Property)")
                    [void]$sb.AppendLine("         Category               : $($e.Category)")
                    if ((Test-IsReportedNullValue $e.OffendingValue) -and ("$($e.Property)" -match '(?i)mailnickname')) {
                        [void]$sb.AppendLine("         Offending value        : (null)")
                        [void]$sb.AppendLine("         ^ The mailNickname attribute has a null value.")
                    }
                    else {
                        [void]$sb.AppendLine("         Offending value        : $($e.OffendingValue)")
                    }
                    if ($e.AdRootCause -and $e.AdRootCause -ne '(not checked)') {
                        [void]$sb.AppendLine("         AD root cause          : $($e.AdRootCause)")
                    }
                }
                [void]$sb.AppendLine("")
            }
            else {
                [void]$sb.AppendLine("  >> No Entra-reported error on file for this user (run 'Scan Sync Errors' to cross-reference).")
            }

            # Locally-detected issues, ranked Critical -> Warning -> Info.
            if ($diag.Issues.Count -eq 0) {
                [void]$sb.AppendLine("  >> No local attribute problems detected. This object looks sync-healthy.")
            }
            else {
                if ($critical.Count -gt 0) {
                    [void]$sb.AppendLine("  >> CRITICAL ($($critical.Count)) - will block or break synchronization:")
                    foreach ($it in $critical) {
                        [void]$sb.AppendLine("       [X] [$($it.Attribute)] $($it.Message)")
                        foreach ($c in @($it.Conflicts)) { [void]$sb.AppendLine("            -> conflicts with: $c") }
                    }
                }
                if ($warnings.Count -gt 0) {
                    [void]$sb.AppendLine("  >> WARNING ($($warnings.Count)) - may cause errors or unexpected results:")
                    foreach ($it in $warnings) {
                        [void]$sb.AppendLine("       [!] [$($it.Attribute)] $($it.Message)")
                        foreach ($c in @($it.Conflicts)) { [void]$sb.AppendLine("            -> conflicts with: $c") }
                    }
                }
                if ($infos.Count -gt 0) {
                    [void]$sb.AppendLine("  >> INFO ($($infos.Count)):")
                    foreach ($it in $infos) { [void]$sb.AppendLine("       [i] [$($it.Attribute)] $($it.Message)") }
                }
            }
            # Address usage map: exactly WHERE each traced address lives in the directory.
            $usageEntries = @($diag.AddressUsage)
            if ($usageEntries.Count -gt 0) {
                [void]$sb.AppendLine("  >> ADDRESS USAGE MAP (where each address is used across the directory/forest):")
                foreach ($au in $usageEntries) {
                    [void]$sb.AppendLine("       Address: $($au.Address)   [flagged via: $($au.Source)]")
                    $mapHolders = @($au.Holders)
                    if ($mapHolders.Count -eq 0) {
                        [void]$sb.AppendLine("            (not found on any on-prem/forest object - likely a cloud-only or orphaned Entra object)")
                    }
                    else {
                        foreach ($h in $mapHolders) {
                            $selfTag = $(if ($h.IsSelf) { "  <-- THIS OBJECT" } else { "" })
                            $disTag  = $(if ($h.Disabled) { " [DISABLED]" } else { "" })
                            [void]$sb.AppendLine("            - $($h.Name) ($($h.ObjectClass))$disTag  held in: $($h.HeldIn)$selfTag")
                            [void]$sb.AppendLine("                $($h.Dn)")
                        }
                    }
                }
                [void]$sb.AppendLine("")
            }

            [void]$sb.AppendLine("  ------------------------------------------------")
            [void]$sb.AppendLine("")
        }

        $text = $sb.ToString()
        $script:UI.AdResultsBox.Dispatcher.Invoke([action] { $script:UI.AdResultsBox.AppendText($text) })

        $summary = "AD search: $(@($found).Count) object(s), $grandCritical critical / $grandWarning warning issue(s) found."
        $lvl = $(if ($grandCritical -gt 0) { 'Error' } elseif ($grandWarning -gt 0) { 'Warning' } else { 'Success' })
        Write-UiLog $summary -Level $lvl
        $script:UI.LastAdSummary = "$grandCritical critical / $grandWarning warning"
    }
    catch {
        # Surface actionable detail: exception type + the exact line that threw, not just the message.
        $exType = $_.Exception.GetType().FullName
        $line   = $_.InvocationInfo.ScriptLineNumber
        $near   = "$($_.InvocationInfo.Line)".Trim()
        Write-UiLog "AD search failed: $($_.Exception.Message) [$exType at line $line]" -Level Error
        $detail = "ERROR: $($_.Exception.Message)`r`n  Type : $exType`r`n  Line : $line`r`n  Near : $near`r`n"
        $script:UI.AdResultsBox.Dispatcher.Invoke([action] { $script:UI.AdResultsBox.AppendText($detail) })
    }
    finally {
        $tail = $(if ($script:UI.LastAdSummary) { " ($($script:UI.LastAdSummary))" } else { "" })
        Stop-UiOperation -Text "Active Directory diagnosis complete$tail"
    }
}

function Export-SyncErrorRecords {
    param([ValidateSet('CSV', 'HTML')][string]$Format = 'CSV')

    if ($script:State.SyncErrorRecords.Count -eq 0) {
        [System.Windows.MessageBox]::Show("There is nothing to export. Run a scan first.", 'Nothing to Export', 'OK', 'Information') | Out-Null
        return
    }

    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = if ($Format -eq 'CSV') { 'CSV files (*.csv)|*.csv' } else { 'HTML files (*.html)|*.html' }
    $dialog.FileName = "EntraSyncErrors_$(Get-Date -Format 'yyyyMMdd_HHmmss').$($Format.ToLower())"

    if ($dialog.ShowDialog() -ne 'OK') { return }

    try {
        $data = @($script:State.SyncErrorRecords)
        if ($Format -eq 'CSV') {
            $data | Export-Csv -Path $dialog.FileName -NoTypeInformation -Encoding UTF8
        }
        else {
            $style = "<style>body{font-family:Segoe UI,Arial;background:#1e1e2e;color:#e0e0e0}table{border-collapse:collapse;width:100%}th{background:#0078d4;color:#fff;padding:8px;text-align:left}td{border:1px solid #444;padding:6px}tr:nth-child(even){background:#2a2a3a}</style>"
            $html = $data | ConvertTo-Html -Title 'Entra ID Sync Errors' -Head $style
            # ConvertTo-Html encodes the cell text first, so this highlight is not escaped.
            $html = $html -replace '\(null\)', '<span style="color:#ff8a80;font-weight:700">(null)</span>'
            $html | Out-File -FilePath $dialog.FileName -Encoding UTF8
        }
        Write-UiLog "Exported $($data.Count) record(s) to $($dialog.FileName)" -Level Success
        [System.Windows.MessageBox]::Show("Exported to:`n$($dialog.FileName)", 'Export Complete', 'OK', 'Information') | Out-Null
    }
    catch {
        Write-UiLog "Export failed: $($_.Exception.Message)" -Level Error
    }
}

# ====================================================================================
#  SECTION 3 :: The WPF user interface (XAML)
# ====================================================================================

[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Entra ID :: AD Connect Sync Error Analyzer"
    Height="820" Width="1280" WindowStartupLocation="CenterScreen"
    Background="#FF1B1B2A" FontFamily="Segoe UI">

    <Window.Resources>
        <!-- Modern flat button style -->
        <Style x:Key="AccentButton" TargetType="Button">
            <Setter Property="Background" Value="#FF0078D4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="14,8"/>
            <Setter Property="Margin" Value="4,0"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="6" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Background" Value="#FF2B95E9"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="b" Property="Background" Value="#FF444455"/>
                                <Setter Property="Foreground" Value="#FF888899"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="GhostButton" TargetType="Button" BasedOn="{StaticResource AccentButton}">
            <Setter Property="Background" Value="#FF2E2E44"/>
        </Style>

        <Style TargetType="TabItem">
            <Setter Property="Foreground" Value="#FFCCCCDD"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Padding" Value="16,8"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TabItem">
                        <Border x:Name="brd" Background="Transparent" BorderThickness="0,0,0,3" BorderBrush="Transparent" Padding="{TemplateBinding Padding}">
                            <ContentPresenter ContentSource="Header" HorizontalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter TargetName="brd" Property="BorderBrush" Value="#FF0078D4"/>
                                <Setter Property="Foreground" Value="White"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="DataGrid">
            <Setter Property="Background" Value="#FF232336"/>
            <Setter Property="Foreground" Value="#FFE0E0E0"/>
            <Setter Property="RowBackground" Value="#FF232336"/>
            <Setter Property="AlternatingRowBackground" Value="#FF2A2A40"/>
            <Setter Property="BorderBrush" Value="#FF3A3A50"/>
            <Setter Property="GridLinesVisibility" Value="Horizontal"/>
            <Setter Property="HorizontalGridLinesBrush" Value="#FF3A3A50"/>
            <Setter Property="RowHeaderWidth" Value="0"/>
        </Style>

        <!-- Column headers: the default WPF template renders dark text on system chrome,
             which is nearly invisible on this dark theme. Retemplate so the header bar and
             its (bold, light) text match the app palette and stay legible. -->
        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Foreground" Value="#FFEDEDF5"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Padding" Value="10,7"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="DataGridColumnHeader">
                        <Border x:Name="hdr" Background="#FF15151F" BorderBrush="#FF3A3A50"
                                BorderThickness="0,0,1,2" Padding="{TemplateBinding Padding}">
                            <ContentPresenter VerticalAlignment="Center"
                                              HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="hdr" Property="Background" Value="#FF20202E"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Grid Margin="0">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>  <!-- header -->
            <RowDefinition Height="Auto"/>  <!-- toolbar -->
            <RowDefinition Height="*"/>     <!-- tabs -->
            <RowDefinition Height="150"/>   <!-- log -->
            <RowDefinition Height="Auto"/>  <!-- status bar -->
        </Grid.RowDefinitions>

        <!-- ===== Header ===== -->
        <Border Grid.Row="0" Background="#FF15151F" Padding="20,14">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0">
                    <TextBlock Text="AD Connect Sync Error Analyzer" Foreground="White" FontSize="22" FontWeight="Bold"/>
                    <TextBlock Text="Entra ID (Azure AD) directory synchronization diagnostics" Foreground="#FF9A9AB5" FontSize="12" Margin="0,2,0,0"/>
                </StackPanel>
                <StackPanel Grid.Column="1" HorizontalAlignment="Right" VerticalAlignment="Center">
                    <TextBlock x:Name="TenantLabel" Text="Not connected" Foreground="#FF8AD4FF" FontSize="13" HorizontalAlignment="Right"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- ===== Toolbar ===== -->
        <Border Grid.Row="1" Background="#FF20202E" Padding="16,10">
            <StackPanel Orientation="Horizontal">
                <Button x:Name="ConnectButton" Content="Connect with device code" Style="{StaticResource AccentButton}"/>
                <Button x:Name="ScanButton" Content="Scan Sync Errors" Style="{StaticResource AccentButton}" IsEnabled="False"/>
                <CheckBox x:Name="CrossRefCheck" Content="Cross-reference on-prem AD" Foreground="#FFCCCCDD" VerticalAlignment="Center" Margin="12,0" IsChecked="True"/>
                <Separator Margin="8,0" Background="#FF3A3A50"/>
                <Button x:Name="ExportCsvButton" Content="Export CSV" Style="{StaticResource GhostButton}"/>
                <Button x:Name="ExportHtmlButton" Content="Export HTML" Style="{StaticResource GhostButton}"/>
                <TextBlock x:Name="ResultCount" Text="" Foreground="#FF9A9AB5" VerticalAlignment="Center" Margin="16,0"/>
            </StackPanel>
        </Border>

        <!-- ===== Tabs ===== -->
        <TabControl Grid.Row="2" Background="Transparent" BorderThickness="0" Margin="12,8">

            <!-- Tab 1 : Sync errors -->
            <TabItem Header="Sync Errors">
                <Grid Margin="0,8,0,0">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <TextBox x:Name="FilterBox" Grid.Row="0" Margin="0,0,0,8" Padding="8,6"
                             Background="#FF232336" Foreground="White" BorderBrush="#FF3A3A50"
                             Tag="Filter results (name, object type, UPN, property, value)..."/>

                    <DataGrid x:Name="ErrorGrid" Grid.Row="1" AutoGenerateColumns="False"
                              IsReadOnly="True" SelectionMode="Single" CanUserResizeColumns="True">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Display Name" Binding="{Binding DisplayName}" Width="160"/>
                            <DataGridTextColumn Header="Object Type" Binding="{Binding ObjectType}" Width="90"/>
                            <DataGridTextColumn Header="UPN" Binding="{Binding UserPrincipalName}" Width="180"/>
                            <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="110"/>
                            <DataGridTextColumn Header="Property" Binding="{Binding Property}" Width="120"/>
                            <DataGridTextColumn Header="Offending Value" Binding="{Binding OffendingValue}" Width="200"/>
                            <DataGridTextColumn Header="Objects with this value" Binding="{Binding CloudHolders}" Width="260"/>
                            <DataGridTextColumn Header="Mail Nickname" Binding="{Binding MailNickname}" Width="140">
                                <DataGridTextColumn.ElementStyle>
                                    <Style TargetType="TextBlock">
                                        <Style.Triggers>
                                            <DataTrigger Binding="{Binding MailNickname}" Value="(null)">
                                                <Setter Property="Foreground" Value="#FFFF8A80"/>
                                                <Setter Property="FontWeight" Value="Bold"/>
                                            </DataTrigger>
                                        </Style.Triggers>
                                    </Style>
                                </DataGridTextColumn.ElementStyle>
                            </DataGridTextColumn>
                            <DataGridTextColumn Header="AD Root Cause" Binding="{Binding AdRootCause}" Width="280"/>
                            <DataGridTextColumn Header="Occurred (UTC)" Binding="{Binding OccurredUtc}" Width="120"/>
                        </DataGrid.Columns>
                    </DataGrid>

                    <!-- Detail pane -->
                    <Border Grid.Row="2" Background="#FF1A1A28" CornerRadius="6" Margin="0,8,0,0" Padding="14">
                        <ScrollViewer VerticalScrollBarVisibility="Auto" MaxHeight="180">
                            <TextBox x:Name="DetailBox" IsReadOnly="True" TextWrapping="Wrap"
                                     Background="Transparent" Foreground="#FFD5D5E5" BorderThickness="0"
                                     FontFamily="Consolas" FontSize="12"
                                     Text="Select an error row to see full details..."/>
                        </ScrollViewer>
                    </Border>
                </Grid>
            </TabItem>

            <!-- Tab 2 : AD scanner -->
            <TabItem Header="Active Directory Scanner">
                <Grid Margin="0,8,0,0">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,8">
                        <TextBox x:Name="AdQueryBox" Width="420" Padding="8,6"
                                 Background="#FF232336" Foreground="White" BorderBrush="#FF3A3A50"
                                 Tag="UPN, sAMAccountName, email, proxy address, or name..."/>
                        <Button x:Name="AdSearchButton" Content="Search AD" Style="{StaticResource AccentButton}"/>
                    </StackPanel>
                    <Border Grid.Row="1" Background="#FF1A1A28" CornerRadius="6" Padding="4">
                        <TextBox x:Name="AdResultsBox" IsReadOnly="True" TextWrapping="NoWrap"
                                 VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                                 Background="Transparent" Foreground="#FFB8E6B8" BorderThickness="0"
                                 FontFamily="Consolas" FontSize="12"/>
                    </Border>
                </Grid>
            </TabItem>
        </TabControl>

        <!-- ===== Activity log ===== -->
        <Border Grid.Row="3" Background="#FF15151F" Margin="12,0,12,8" CornerRadius="6">
            <DockPanel>
                <TextBlock DockPanel.Dock="Top" Text="  Activity Log" Foreground="#FF9A9AB5" FontSize="11" Margin="6,4,0,0"/>
                <TextBox x:Name="LogBox" IsReadOnly="True" TextWrapping="NoWrap"
                         VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                         Background="Transparent" Foreground="#FF88DD88" BorderThickness="0"
                         FontFamily="Consolas" FontSize="11" Margin="6"/>
            </DockPanel>
        </Border>

        <!-- ===== Status bar ===== -->
        <Border Grid.Row="4" Background="#FF0078D4" Padding="12,5">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>       <!-- live status message -->
                    <ColumnDefinition Width="Auto"/>    <!-- stage chip -->
                    <ColumnDefinition Width="Auto"/>    <!-- elapsed clock -->
                    <ColumnDefinition Width="240"/>     <!-- progress bar + percent -->
                </Grid.ColumnDefinitions>

                <TextBlock x:Name="StatusText" Grid.Column="0" Text="Ready" Foreground="White"
                           VerticalAlignment="Center" FontSize="12" TextTrimming="CharacterEllipsis"/>

                <Border Grid.Column="1" x:Name="StageChip" Background="#33FFFFFF" CornerRadius="3"
                        Padding="8,2" Margin="10,0" VerticalAlignment="Center" Visibility="Collapsed">
                    <TextBlock x:Name="StageText" Text="" Foreground="White" FontSize="11" FontWeight="SemiBold"/>
                </Border>

                <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center" Margin="4,0,12,0">
                    <TextBlock Text="Elapsed:" Foreground="#FFD6ECFF" FontSize="11" VerticalAlignment="Center" Margin="0,0,6,0"/>
                    <TextBlock x:Name="ElapsedText" Text="00:00" Foreground="White" FontFamily="Consolas"
                               FontSize="13" FontWeight="Bold" VerticalAlignment="Center"/>
                </StackPanel>

                <Grid Grid.Column="3" VerticalAlignment="Center">
                    <ProgressBar x:Name="Progress" Height="16" Minimum="0" Maximum="100" IsIndeterminate="False"
                                 Visibility="Collapsed" Background="#FF005A9E" Foreground="#FF4FC3F7" BorderThickness="0"/>
                    <TextBlock x:Name="PercentText" Text="" Foreground="White" FontSize="11" FontWeight="SemiBold"
                               HorizontalAlignment="Center" VerticalAlignment="Center"/>
                </Grid>
            </Grid>
        </Border>
    </Grid>
</Window>
"@

# ------------------------------------------------------------------------------------
#  Build the window and grab named elements
# ------------------------------------------------------------------------------------
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$script:UI = [ordered]@{
    Window          = $window
    ConnectButton   = $window.FindName('ConnectButton')
    ScanButton      = $window.FindName('ScanButton')
    CrossRefCheck   = $window.FindName('CrossRefCheck')
    ExportCsvButton = $window.FindName('ExportCsvButton')
    ExportHtmlButton= $window.FindName('ExportHtmlButton')
    ResultCount     = $window.FindName('ResultCount')
    TenantLabel     = $window.FindName('TenantLabel')
    FilterBox       = $window.FindName('FilterBox')
    ErrorGrid       = $window.FindName('ErrorGrid')
    DetailBox       = $window.FindName('DetailBox')
    AdQueryBox      = $window.FindName('AdQueryBox')
    AdSearchButton  = $window.FindName('AdSearchButton')
    AdResultsBox    = $window.FindName('AdResultsBox')
    LogBox          = $window.FindName('LogBox')
    StatusText      = $window.FindName('StatusText')
    StageChip       = $window.FindName('StageChip')
    StageText       = $window.FindName('StageText')
    ElapsedText     = $window.FindName('ElapsedText')
    PercentText     = $window.FindName('PercentText')
    Progress        = $window.FindName('Progress')
}

# Bind the grid to the observable collection + a filtered view.
$view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($script:State.SyncErrorRecords)
$script:UI.ErrorGrid.ItemsSource = $view

# ====================================================================================
#  SECTION 4 :: Event wiring
# ====================================================================================

$script:UI.ConnectButton.Add_Click({
    if (Initialize-GraphModule) { Connect-EntraTenant }
})

$script:UI.ScanButton.Add_Click({ Get-SyncErrorRecords })

$script:UI.ExportCsvButton.Add_Click({ Export-SyncErrorRecords -Format CSV })
$script:UI.ExportHtmlButton.Add_Click({ Export-SyncErrorRecords -Format HTML })

$script:UI.AdSearchButton.Add_Click({
    $q = $script:UI.AdQueryBox.Text
    if ([string]::IsNullOrWhiteSpace($q)) { return }
    Search-ActiveDirectoryUser -Query $q
})
$script:UI.AdQueryBox.Add_KeyDown({
    param($sender, $e)
    if ($e.Key -eq 'Return') {
        $q = $script:UI.AdQueryBox.Text
        if (-not [string]::IsNullOrWhiteSpace($q)) { Search-ActiveDirectoryUser -Query $q }
    }
})

# Live filter over the grid.
$script:UI.FilterBox.Add_TextChanged({
    $text = $script:UI.FilterBox.Text
    $view.Filter = [Predicate[object]]{
        param($item)
        if ([string]::IsNullOrWhiteSpace($text)) { return $true }
        $t = $text.ToLower()
        return (
            ("$($item.DisplayName)".ToLower().Contains($t)) -or
            ("$($item.ObjectType)".ToLower().Contains($t)) -or
            ("$($item.UserPrincipalName)".ToLower().Contains($t)) -or
            ("$($item.Category)".ToLower().Contains($t)) -or
            ("$($item.Property)".ToLower().Contains($t)) -or
            ("$($item.OffendingValue)".ToLower().Contains($t)) -or
            ("$($item.CloudHolders)".ToLower().Contains($t)) -or
            ("$($item.MailNickname)".ToLower().Contains($t)) -or
            ("$($item.AdRootCause)".ToLower().Contains($t))
        )
    }
    $view.Refresh()
})

# Populate the detail pane when a row is selected.
$script:UI.ErrorGrid.Add_SelectionChanged({
    $sel = $script:UI.ErrorGrid.SelectedItem
    if (-not $sel) { return }
    $nickBanner = ''
    if ("$($sel.MailNickname)" -eq '(null)') {
        $nickBanner = "*** The mailNickname attribute has a null value. ***`r`n`r`n"
    }
    $detail = @"
${nickBanner}DIRECTORY OBJECT
  Display Name       : $($sel.DisplayName)
  Object Type        : $($sel.ObjectType)
  UserPrincipalName  : $($sel.UserPrincipalName)
  Account Enabled    : $($sel.AccountEnabled)
  Cloud ObjectId     : $($sel.ObjectId)
  Mail Nickname      : $($sel.MailNickname)

ERROR
  Category           : $($sel.Category)
  Property           : $($sel.Property)
  Offending Value    : $($sel.OffendingValue)
  Occurred (UTC)     : $($sel.OccurredUtc)

OBJECTS IN ENTRA WITH THIS VALUE
  $($sel.CloudHolders)

ON-PREM SOURCE
  sAMAccountName     : $($sel.SamAccountName)
  On-Prem Domain     : $($sel.OnPremDomain)
  ImmutableId        : $($sel.ImmutableId)
  Last Sync (UTC)    : $($sel.LastSyncUtc)
  Proxy Addresses    : $($sel.ProxyAddresses)

AD ROOT CAUSE ANALYSIS
  Summary            : $($sel.AdRootCause)
  Conflicting Objects: $($sel.AdConflictObjects)
"@
    $script:UI.DetailBox.Text = $detail
})

# Cleanly disconnect Graph on close.
$window.Add_Closing({
    try { if ($script:State.Connected) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } } catch {}
})

# ====================================================================================
#  SECTION 5 :: Startup
# ====================================================================================

$window.Add_Loaded({
    Write-UiLog "Entra ID Sync Error Analyzer started (PowerShell $($PSVersionTable.PSVersion))." -Level Success
    Write-UiLog "Step 1: Click 'Connect with device code' and finish sign-in at https://microsoft.com/devicelogin. Step 2: Click 'Scan Sync Errors'."
    Write-UiLog "The scan lists users, groups, and contacts with sync errors, plus every other Entra object that already holds the same proxy address or UPN."
    # Best-effort AD module load so the scanner tab is usable immediately.
    Initialize-AdModule | Out-Null
})

# Show the window (ShowDialog blocks until closed; works in STA console/ISE).
$null = $window.ShowDialog()


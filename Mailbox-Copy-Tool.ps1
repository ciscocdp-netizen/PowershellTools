<#
.SYNOPSIS
    Copy emails and calendar items between Microsoft 365 mailboxes using interactive login.

.DESCRIPTION
    This script provides a GUI to copy emails and/or calendar items from one mailbox to another
    using Microsoft Graph API with interactive (delegated) authentication. You'll sign in with
    your own credentials via browser-based OAuth.

    Before copying, grant FullAccess on both mailboxes manually via the Exchange Admin
    Center or EXO PowerShell, tick the pre-flight checklist in the UI, then run the copy.
    Remove the permissions manually when finished.

.NOTES
    Author: v0
    Version: 1.12
    Requires: Microsoft.Graph PowerShell SDK
    Authentication: Interactive (Delegated Permissions via browser)

    Changelog v1.12:
    - Fixed: Graph 400 BadRequest on every create (log showed only "BadRequest [line 411]").
      v1.11 posted a byte[] when Get-MgGraphAccessToken was unavailable, which Graph
      rejects, and Windows PowerShell ConvertTo-Json turns ArrayList / single-element
      arrays into objects ({Count,Capacity,value} or a lone {id,value}) instead of a
      JSON array. Creates now send UTF-8 JSON via Invoke-RestMethod first (never byte[]
      to the SDK), serialize with Newtonsoft or JavaScriptSerializer so arrays stay
      arrays, and failures log Graph error.code/message.
    - Fixed: body contentType/importance/showAs/sensitivity/recurrence enums are sent
      as Graph's camelCase values (html/text, normal, busy, weekly, ...).
    - Fixed: Mail create retries without from/sender/internetMessageId (SendAs and
      duplicate Internet-Message-Id are common 400s). Original From is still stamped
      via MAPI sender properties so Outlook can show the original sender.

    Changelog v1.11:
    - Fixed: Every mail and calendar create failed with "Argument types do not match".
      Invoke-MgGraphRequest -Body was given a JSON string; several Microsoft.Graph.Authentication
      builds type -Body as Hashtable/Byte[] and throw that error. Posts now go through
      Invoke-RestMethod with the Graph token (UTF-8 JSON), with byte[]/hashtable SDK fallbacks.
    - Fixed: [math]::Min(double, int) throws the same error in Windows PowerShell when updating
      the progress bar (Round returns double, 100 is int). Progress now uses integer percent.

    Changelog v1.10:
    - Fixed: UI appeared hung on large folders (e.g. Inbox with 16k+ items). Get-Mg* -All
      downloaded every message body on the WinForms thread with no progress or DoEvents,
      so Cancel/progress never painted. Listing now pages via @odata.nextLink, selects
      headers only (no body), pumps the UI after each page, and GETs the full message
      only for items that are actually copied.
    - Fixed: Verification no longer enumerates every message (that hung after a large copy).
    - Fixed: Draft copies retry a minimal payload so empty/incomplete drafts are less likely
      to fail the whole item.

    Changelog v1.9:
    - Fixed: Copied emails showed the copy time instead of the original sent/received time.
      Graph ignores receivedDateTime/sentDateTime on POST. The copy now stamps the MAPI
      properties Outlook actually displays: PidTagClientSubmitTime (SystemTime 0x0039) and
      PidTagMessageDeliveryTime (SystemTime 0x0E06), together with PidTagMessageFlags.
    - Fixed: Teams meetings were copied as plain appointments with no Join link. Graph's
      isOnlineMeeting=true creates a NEW meeting (or is ignored), so the copy now preserves
      the original body/location and stamps SkypeTeamsMeetingUrl / OnlineMeetingConfLink /
      conferencing MAPI properties from the source join URL.
    - Fixed: Calendar attendees can now be copied WITHOUT sending invitation emails. Graph
      sends invites whenever the attendees collection is posted, so attendees are written
      via MAPI attendee-string properties instead of the Graph attendees array.
    - New: File attachments are copied after each message is created.
    - Changed: Recurring series occurrences are skipped; the series master is copied once.

    Changelog v1.8:
    - Fixed: "UnableToDeserializePostBody" (HTTP 400) when creating messages. Passing a
      hashtable with a nested singleValueExtendedProperties array to
      New-MgUser*Message -BodyParameter fails, because the SDK cannot coerce it into a
      typed IMicrosoftGraphMessage. The message create now builds explicit camelCase
      JSON and POSTs it with Invoke-MgGraphRequest, converting SDK recipient/from/sender
      objects into plain { emailAddress: { address, name } } hashtables so the payload
      matches exactly what Graph expects.

    Changelog v1.7:
    - Fixed: Copied emails appeared as "Drafts" in the destination mailbox. A message
      created via POST is ALWAYS placed in the draft state by Graph, and setting IsRead
      in the body does not change that. The copy now stamps the PidTagMessageFlags
      extended property (Integer 0x0E07) at creation time WITHOUT the MSGFLAG_UNSENT
      (0x8) draft bit — value 1 (read) or 0 (unread) depending on the source — which
      clears the draft status while preserving the read/unread state.

    Changelog v1.6:
    - Removed: ExchangeOnlineManagement module dependency entirely. Connect-ExchangeOnline
      could not authenticate in a PowerShell 5.1 WinForms thread under MFA/Conditional
      Access — browser OAuth, WAM broker, device code, and basic credential auth all
      failed or are not available in PS 5.1.
    - Changed: Mailbox permission grant/revoke is now a manual pre-flight step. Step 2
      is replaced by a checklist checkbox the user must tick before copying begins.
    - Changed: Completion message reminds the user to remove FullAccess permissions.

    Changelog v1.5:
    - Changed: Attendees are intentionally excluded from copied calendar events.
      Including them causes Exchange Online to send invitation emails to every
      attendee. All other event metadata is preserved (subject, body, start/end
      times, location, recurrence, reminder).
    - Removed: Direct-to-Calendar transport rule helpers (no longer needed).

    Changelog v1.4:
    - Fixed: Calendar events were copied without their attendee lists (reverted in v1.5).

    Changelog v1.3:
    - New: Automatically grants FullAccess mailbox permission to a specified admin/delegate
      account on both source and target mailboxes before copying begins.
    - New: Permissions are always revoked in a finally block, ensuring cleanup even on
      error or user cancellation.
    - New: UI field for the delegate UPN (the account that needs access).
    - New: Grant-MailboxFullAccess and Revoke-MailboxFullAccess helper functions using
      Exchange Online PowerShell (Add-MailboxPermission / Remove-MailboxPermission).
    - New: Connect-ToExchangeOnline helper; EXO session is established alongside Graph auth.

    Changelog v1.2:
    - Fixed "The stream was already consumed. It cannot be read again." error caused by using
      -Top + -Skip pagination. Replaced with proper NextLink-based paging via Invoke-GraphPagedRequest.
    - Fixed "Too many retries performed" throttling error by adding exponential back-off retry
      logic (Invoke-WithRetry) around every Graph API call.
    - Added 250 ms inter-page delay to stay within Graph throttling limits.
#>

# ------------------------------------------------------------------------------
# Module bootstrap
# ------------------------------------------------------------------------------
foreach ($mod in @('Microsoft.Graph.Mail', 'Microsoft.Graph.Calendar', 'Microsoft.Graph.Authentication')) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Installing $mod..." -ForegroundColor Yellow
        Install-Module $mod -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $mod -ErrorAction Stop
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ------------------------------------------------------------------------------
# Global state
# ------------------------------------------------------------------------------
$script:Connected       = $false
$script:CancelRequested = $false
$script:GraphBase       = 'https://graph.microsoft.com/v1.0'

# MAPI / Outlook named-property identifiers
$script:PsetAppointment   = '{00062002-0000-0000-C000-000000000046}'
$script:PsetMeeting       = '{6ED8DA90-450B-101B-98DA-00AA003F1305}'
$script:PsetPublicStrings = '{00020329-0000-0000-C000-000000000046}'

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

<#
.SYNOPSIS
    Retries a script block up to $MaxRetries times with exponential back-off.
    Handles both throttle (429) errors and the "stream already consumed" SDK bug.
#>
function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = 5,
        [int]$BaseDelaySeconds = 2
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return (& $ScriptBlock)
        }
        catch {
            $msg = $_.Exception.Message
            $isRetryable = ($msg -match 'stream was already consumed') -or
                           ($msg -match 'Too many retries')             -or
                           ($msg -match '429')                          -or
                           ($msg -match 'ServiceUnavailable')           -or
                           ($msg -match 'timeout')

            if ($isRetryable -and $attempt -le $MaxRetries) {
                $retryAfter = $null
                if ($_.Exception.Response -and
                    $_.Exception.Response.Headers -and
                    $_.Exception.Response.Headers['Retry-After']) {
                    $retryAfter = [int]$_.Exception.Response.Headers['Retry-After']
                }
                $delay = if ($retryAfter) { $retryAfter } else { [math]::Pow(2, $attempt) * $BaseDelaySeconds }
                Write-Host "  [Retry $attempt/$MaxRetries] Waiting ${delay}s - $msg" -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
                continue
            }
            throw
        }
    }
}

<#
.SYNOPSIS
    Pages through ALL results from a Get-Mg* cmdlet using the SDK's built-in
    -All switch, but wraps every call in Invoke-WithRetry to survive transient
    throttle / stream-consumed errors. Returns a flat array of all objects.
#>
function Invoke-GraphPagedRequest {
    param(
        [scriptblock]$CommandBlock,
        [int]$PageDelayMs = 250
    )

    $results = Invoke-WithRetry -ScriptBlock {
        & $CommandBlock
    }

    Start-Sleep -Milliseconds $PageDelayMs
    return $results
}

function Update-CopyUi {
    param(
        [System.Windows.Forms.TextBox]$StatusBox,
        [System.Windows.Forms.ProgressBar]$ProgressBar
    )
    try {
        if ($StatusBox)    { $StatusBox.Refresh() }
        if ($ProgressBar)  { $ProgressBar.Refresh() }
        [System.Windows.Forms.Application]::DoEvents()
    }
    catch { }
}

function Get-GraphProperty {
    param(
        $Object,
        [Parameter(Mandatory = $true)][string[]]$Names
    )
    if ($null -eq $Object) { return $null }
    foreach ($name in $Names) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($name)) { return $Object[$name] }
            foreach ($k in @($Object.Keys)) {
                if ([string]$k -ieq $name) { return $Object[$k] }
            }
        }
        $prop = $Object.PSObject.Properties[$name]
        if ($prop) { return $prop.Value }
        $match = $Object.PSObject.Properties | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
        if ($match) { return $match.Value }
    }
    return $null
}

function Get-GraphItemList {
    param($Value)
    $items = New-Object System.Collections.ArrayList
    if ($null -eq $Value) { return , $items }
    # Hashtable is IEnumerable of its values — a lone Graph object must stay one item.
    if ($Value -is [System.Collections.IDictionary]) {
        [void]$items.Add($Value)
        return , $items
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        foreach ($i in $Value) {
            if ($null -ne $i) { [void]$items.Add($i) }
        }
        return , $items
    }
    [void]$items.Add($Value)
    return , $items
}

function Get-GraphNextLink {
    param($Response)
    $link = Get-GraphProperty -Object $Response -Names @('@odata.nextLink')
    if ($link) { return $link }
    if ($Response -is [System.Collections.IDictionary]) {
        foreach ($k in @($Response.Keys)) {
            if ([string]$k -match 'nextLink$') { return $Response[$k] }
        }
    }
    return $null
}

function Get-GraphCollection {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [System.Windows.Forms.TextBox]$StatusBox,
        [string]$ProgressPrefix = '',
        [int]$ExpectedCount = 0,
        [int]$PageDelayMs = 150
    )
    $items = New-Object System.Collections.Generic.List[object]
    $page  = 0
    $next  = $Uri
    while ($next) {
        if ($script:CancelRequested) { break }
        $page++
        $resp = Invoke-WithRetry -ScriptBlock {
            Invoke-MgGraphRequest -Method GET -Uri $next
        }
        $pageItems = Get-GraphProperty -Object $resp -Names @('value', 'Value')
        foreach ($it in @($pageItems)) {
            [void]$items.Add($it)
        }
        if ($StatusBox -and $ProgressPrefix) {
            $of = if ($ExpectedCount -gt 0) { " / $ExpectedCount" } else { '' }
            $StatusBox.AppendText("    $ProgressPrefix page $page : $($items.Count)$of items`r`n")
            Update-CopyUi -StatusBox $StatusBox
        }
        $next = Get-GraphNextLink -Response $resp
        if ($next) { Start-Sleep -Milliseconds $PageDelayMs }
    }
    return , $items
}

function Format-DedupeDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return 'nodate' }
    try {
        if ($Value -is [datetimeoffset]) { return $Value.ToString('yyyy-MM-dd HH:mm') }
        if ($Value -is [datetime])       { return $Value.ToString('yyyy-MM-dd HH:mm') }
        $dto = [datetimeoffset]::Parse("$Value", [cultureinfo]::InvariantCulture, [globalization.datetimestyles]::RoundtripKind)
        return $dto.ToString('yyyy-MM-dd HH:mm')
    }
    catch {
        return 'nodate'
    }
}

function Get-MessageDedupeKey {
    param($Message)
    $from    = Get-GraphProperty -Object $Message -Names @('from', 'From')
    $email   = Get-GraphProperty -Object $from -Names @('emailAddress', 'EmailAddress')
    $sAddr   = Get-GraphProperty -Object $email -Names @('address', 'Address')
    if (-not $sAddr) { $sAddr = 'unknown' }
    $subject = Get-GraphProperty -Object $Message -Names @('subject', 'Subject')
    $rDate   = Format-DedupeDate (Get-GraphProperty -Object $Message -Names @('receivedDateTime', 'ReceivedDateTime'))
    return "$subject|$rDate|$sAddr"
}

function New-FolderMessagesListUri {
    param(
        [Parameter(Mandatory = $true)][string]$UserId,
        [string]$FolderId,
        [Parameter(Mandatory = $true)][string]$Select
    )
    $uEnc = [uri]::EscapeDataString($UserId)
    if ($FolderId) {
        $fEnc = [uri]::EscapeDataString($FolderId)
        return "$script:GraphBase/users/$uEnc/mailFolders/$fEnc/messages?`$top=100&`$select=$Select"
    }
    return "$script:GraphBase/users/$uEnc/messages?`$top=100&`$select=$Select"
}

function Get-GraphMessageById {
    param(
        [Parameter(Mandatory = $true)][string]$UserId,
        [Parameter(Mandatory = $true)][string]$MessageId
    )
    $uEnc  = [uri]::EscapeDataString($UserId)
    $idEnc = [uri]::EscapeDataString($MessageId)
    Invoke-WithRetry -ScriptBlock {
        Invoke-MgGraphRequest -Method GET -Uri "$script:GraphBase/users/$uEnc/messages/$idEnc"
    }
}

function ConvertTo-PlainGraphObject {
    param(
        $Object,
        [int]$Depth = 12
    )
    if ($null -eq $Object -or $Depth -le 0) { return $null }
    if ($Object -is [string] -or $Object -is [bool] -or
        $Object -is [int] -or $Object -is [long] -or $Object -is [double] -or
        $Object -is [decimal] -or $Object -is [byte]) {
        return $Object
    }
    # byte[] is IEnumerable; never expand it into a JSON number array
    if ($Object -is [byte[]]) {
        return [convert]::ToBase64String($Object)
    }
    if ($Object -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($k in @($Object.Keys)) {
            $converted = ConvertTo-PlainGraphObject -Object $Object[$k] -Depth ($Depth - 1)
            if ($null -ne $converted) { $h["$k"] = $converted }
        }
        return $h
    }
    if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [string])) {
        $list = New-Object System.Collections.ArrayList
        foreach ($item in $Object) {
            $converted = ConvertTo-PlainGraphObject -Object $item -Depth ($Depth - 1)
            if ($null -ne $converted) { [void]$list.Add($converted) }
        }
        # Unary comma keeps a single-element object[] from collapsing to a hashtable
        return , $list.ToArray()
    }
    return "$Object"
}

function ConvertTo-GraphJson {
    param([Parameter(Mandatory = $true)]$InputObject)
    $plain = ConvertTo-PlainGraphObject -Object $InputObject

    try {
        $loaded = [appdomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GetName().Name -eq 'Newtonsoft.Json' }
        if (-not $loaded) {
            $authMod = Get-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
            if ($authMod) {
                $njs = Get-ChildItem -Path (Split-Path $authMod.Path -Parent) -Filter 'Newtonsoft.Json.dll' -Recurse -ErrorAction SilentlyContinue |
                    Select-Object -First 1
                if ($njs) { Add-Type -Path $njs.FullName -ErrorAction SilentlyContinue }
            }
        }
        $json = [Newtonsoft.Json.JsonConvert]::SerializeObject($plain)
        if ($json -and $json -ne 'null') { return $json }
    }
    catch { }

    # JavaScriptSerializer preserves single-element arrays. ConvertTo-Json in
    # Windows PowerShell 5.1 turns @( @{id=...} ) into a JSON object, which Graph
    # rejects for collection properties (400 Bad Request).
    try {
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength = [int]::MaxValue
        $ser.RecursionLimit = 100
        $json = $ser.Serialize($plain)
        if ($json -and $json -ne 'null') { return $json }
    }
    catch { }

    return ($plain | ConvertTo-Json -Depth 30 -Compress)
}

function Get-GraphAccessTokenString {
    $cmd = Get-Command Get-MgGraphAccessToken -ErrorAction SilentlyContinue
    if ($cmd) {
        $attempts = @(@{})
        if ($cmd.Parameters.ContainsKey('AsSecureString')) {
            $attempts += @{ AsSecureString = $true }
        }
        foreach ($splat in $attempts) {
            try {
                $token = Get-MgGraphAccessToken @splat -ErrorAction Stop
                if ($token -is [securestring]) {
                    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
                    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
                    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
                }
                if ($token) { return [string]$token }
            }
            catch { }
        }
    }

    try {
        $sessionType = [type]::GetType('Microsoft.Graph.PowerShell.Authentication.GraphSession, Microsoft.Graph.Authentication')
        if ($sessionType) {
            $instance = $sessionType.GetProperty('Instance').GetValue($null)
            $auth = $instance.AuthContext
            if ($auth.AccessToken) { return [string]$auth.AccessToken }
        }
    }
    catch { }

    return $null
}

function Invoke-GraphJsonPost {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)]$BodyObject
    )

    $plain = ConvertTo-PlainGraphObject -Object $BodyObject
    $json  = ConvertTo-GraphJson -InputObject $plain

    Invoke-WithRetry -ScriptBlock {
        $lastError = $null

        # Prefer RestMethod + UTF-8 JSON. Invoke-MgGraphRequest -Body byte[] (v1.11)
        # made Graph return 400 Bad Request on every create.
        $token = Get-GraphAccessTokenString
        if ($token) {
            try {
                $headers = @{
                    Authorization = "Bearer $token"
                    Accept        = 'application/json'
                }
                return Invoke-RestMethod -Method Post -Uri $Uri -Headers $headers -Body $json -ContentType 'application/json; charset=utf-8'
            }
            catch { $lastError = $_ }
        }

        try {
            return Invoke-MgGraphRequest -Method POST -Uri $Uri -Body $plain -ContentType 'application/json'
        }
        catch { $lastError = $_ }

        try {
            return Invoke-MgGraphRequest -Method POST -Uri $Uri -Body $json -ContentType 'application/json'
        }
        catch { $lastError = $_ }

        if ($lastError) { throw $lastError }
        throw 'Graph POST failed (no access token for Invoke-RestMethod, and Invoke-MgGraphRequest did not succeed).'
    }
}

function Expand-GraphErrorJson {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try {
        $obj = $Text | ConvertFrom-Json
        $err = $obj.error
        if (-not $err -and $obj.Error) { $err = $obj.Error }
        if ($err) {
            $code = $err.code; if (-not $code) { $code = $err.Code }
            $message = $err.message; if (-not $message) { $message = $err.Message }
            if ($code -and $message) { return "${code}: $message" }
            if ($message) { return [string]$message }
        }
    }
    catch { }
    if ($Text.Length -gt 500) { return $Text.Substring(0, 500) }
    return $Text
}

function Get-ExceptionHttpBody {
    param($Exception)
    $ex = $Exception
    $seen = 0
    while ($ex -and $seen -lt 8) {
        $seen++
        try {
            $resp = $ex.Response
            if ($resp) {
                if ($resp.PSObject.Properties['Content'] -and $resp.Content) {
                    try {
                        $task = $resp.Content.ReadAsStringAsync()
                        $text = $task.GetAwaiter().GetResult()
                        if ($text) { return $text }
                    }
                    catch { }
                }
                if ($resp.PSObject.Methods['GetResponseStream']) {
                    $stream = $resp.GetResponseStream()
                    if ($stream) {
                        if ($stream.CanSeek) { [void]$stream.Seek(0, [System.IO.SeekOrigin]::Begin) }
                        $reader = New-Object System.IO.StreamReader($stream)
                        $text = $reader.ReadToEnd()
                        if ($text) { return $text }
                    }
                }
            }
        }
        catch { }
        if ($ex.PSObject.Properties['Error'] -and $ex.Error) {
            $code = $ex.Error.code; if (-not $code) { $code = $ex.Error.Code }
            $message = $ex.Error.message; if (-not $message) { $message = $ex.Error.Message }
            if ($code -or $message) { return (@{ error = @{ code = "$code"; message = "$message" } } | ConvertTo-Json -Compress) }
        }
        $ex = $ex.InnerException
    }
    return $null
}

function Get-CopyErrorDetail {
    param($ErrorRecord)
    $parts = New-Object System.Collections.ArrayList

    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $g = Expand-GraphErrorJson $ErrorRecord.ErrorDetails.Message
        if ($g) { [void]$parts.Add($g) }
    }

    $body = Get-ExceptionHttpBody $ErrorRecord.Exception
    if ($body) {
        $g = Expand-GraphErrorJson $body
        if ($g) { [void]$parts.Add($g) }
    }

    $ex = $ErrorRecord.Exception
    $seen = 0
    while ($ex -and $seen -lt 8) {
        $seen++
        if ($ex.Message) {
            $g = Expand-GraphErrorJson $ex.Message
            if ($g) { [void]$parts.Add($g) } else { [void]$parts.Add($ex.Message) }
        }
        $ex = $ex.InnerException
    }

    if ($parts.Count -eq 0) { return 'Unknown error' }
    $unique = @($parts | Select-Object -Unique)
    return ($unique -join ' | ')
}

function Set-CopyProgress {
    param(
        [System.Windows.Forms.ProgressBar]$ProgressBar,
        [double]$Current,
        [double]$Total
    )
    if (-not $ProgressBar) { return }
    if ($Total -le 0) { $ProgressBar.Value = 0; return }
    $pct = [int](($Current / $Total) * 100)
    if ($pct -lt 0)   { $pct = 0 }
    if ($pct -gt 100) { $pct = 100 }
    $ProgressBar.Value = $pct
}

function New-ExtPropList {
    return , (New-Object System.Collections.ArrayList)
}

function Add-ExtProp {
    param(
        [Parameter(Mandatory = $true)]$List,
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Value
    )
    [void]$List.Add(@{ id = $Id; value = $Value })
}

function Add-ExtPropRange {
    param(
        [Parameter(Mandatory = $true)]$List,
        $Items
    )
    foreach ($item in $Items) {
        if ($item -is [hashtable] -and ($item.ContainsKey('id') -or $item.id)) {
            [void]$List.Add($item)
        }
    }
}

function Convert-ExtPropArray {
    param($List)
    $out = New-Object System.Collections.ArrayList
    if ($null -eq $List) { return $null }

    $items = New-Object System.Collections.ArrayList
    # Hashtable is IEnumerable of its values — never foreach a lone {id,value} property.
    if ($List -is [System.Collections.IDictionary]) {
        [void]$items.Add($List)
    }
    elseif ($List -is [System.Collections.IEnumerable] -and -not ($List -is [string])) {
        foreach ($p in $List) { if ($null -ne $p) { [void]$items.Add($p) } }
    }
    else {
        [void]$items.Add($List)
    }

    foreach ($p in $items) {
        $id  = $null
        $val = $null
        if ($p -is [System.Collections.IDictionary]) {
            $id  = $p['id'];  if (-not $id)  { $id  = $p.id }
            $val = $p['value']; if ($null -eq $val) { $val = $p.value }
        }
        else {
            $id  = $p.id
            $val = $p.value
        }
        if ($id -and $null -ne $val) {
            [void]$out.Add(@{ id = "$id"; value = "$val" })
        }
    }
    if ($out.Count -eq 0) { return $null }
    return , $out.ToArray()
}

function Copy-HashtableExcept {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Source,
        [string[]]$ExcludeKeys = @()
    )
    $copy = @{}
    foreach ($k in $Source.Keys) {
        if ($ExcludeKeys -contains $k) { continue }
        $copy[$k] = $Source[$k]
    }
    return $copy
}

function Convert-GraphEnumString {
    param($Value, [string]$Fallback = $null)
    if ($null -eq $Value -or "$Value" -eq '') { return $Fallback }
    $s = "$Value".Trim()
    $key = $s.ToLowerInvariant()
    $known = @{
        'html'              = 'html'
        'text'              = 'text'
        'low'               = 'low'
        'normal'            = 'normal'
        'high'              = 'high'
        'free'              = 'free'
        'tentative'         = 'tentative'
        'busy'              = 'busy'
        'oof'               = 'oof'
        'workingelsewhere'  = 'workingElsewhere'
        'unknown'           = 'unknown'
        'personal'          = 'personal'
        'private'           = 'private'
        'confidential'      = 'confidential'
        'daily'             = 'daily'
        'weekly'            = 'weekly'
        'absolutemonthly'   = 'absoluteMonthly'
        'relativemonthly'   = 'relativeMonthly'
        'absoluteyearly'    = 'absoluteYearly'
        'relativeyearly'    = 'relativeYearly'
        'enddate'           = 'endDate'
        'noend'             = 'noEnd'
        'numbered'          = 'numbered'
        'sunday'            = 'sunday'
        'monday'            = 'monday'
        'tuesday'           = 'tuesday'
        'wednesday'         = 'wednesday'
        'thursday'          = 'thursday'
        'friday'            = 'friday'
        'saturday'          = 'saturday'
        'first'             = 'first'
        'second'            = 'second'
        'third'             = 'third'
        'fourth'            = 'fourth'
        'last'              = 'last'
        'required'          = 'required'
        'optional'          = 'optional'
        'resource'          = 'resource'
        'singleinstance'    = 'singleInstance'
        'occurrence'        = 'occurrence'
        'exception'         = 'exception'
        'seriesmaster'      = 'seriesMaster'
        'default'           = 'default'
        'conferenceroom'    = 'conferenceRoom'
        'homeaddress'       = 'homeAddress'
        'businessaddress'   = 'businessAddress'
        'geocoordinates'    = 'geoCoordinates'
        'streetaddress'     = 'streetAddress'
        'hotel'             = 'hotel'
        'restaurant'        = 'restaurant'
        'localbusiness'     = 'localBusiness'
        'postaladdress'     = 'postalAddress'
    }
    if ($known.ContainsKey($key)) { return $known[$key] }
    return $s
}

function Format-MapiSystemTime {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    try {
        if ($Value -is [datetimeoffset]) {
            return $Value.ToString('yyyy-MM-ddTHH:mm:ss.fffffffzzz')
        }
        if ($Value -is [datetime]) {
            $kind = $Value.Kind
            if ($kind -eq [datetimekind]::Unspecified) {
                return ([datetimeoffset]::new($Value, [timespan]::Zero)).ToString('yyyy-MM-ddTHH:mm:ss.fffffffzzz')
            }
            return ([datetimeoffset]$Value).ToString('yyyy-MM-ddTHH:mm:ss.fffffffzzz')
        }
        $parsed = [datetimeoffset]::Parse("$Value", [cultureinfo]::InvariantCulture, [globalization.datetimestyles]::RoundtripKind)
        return $parsed.ToString('yyyy-MM-ddTHH:mm:ss.fffffffzzz')
    }
    catch {
        return $null
    }
}

function Convert-GraphEmailRecipient {
    param($Recipient)
    if (-not $Recipient) { return $null }
    $email   = Get-GraphProperty -Object $Recipient -Names @('emailAddress', 'EmailAddress')
    $address = Get-GraphProperty -Object $email -Names @('address', 'Address')
    if (-not $address) { $address = Get-GraphProperty -Object $Recipient -Names @('address', 'Address') }
    $name = Get-GraphProperty -Object $email -Names @('name', 'Name')
    if (-not $name) { $name = Get-GraphProperty -Object $Recipient -Names @('name', 'Name') }
    if (-not $address) { return $null }
    return @{
        emailAddress = @{
            address = "$address"
            name    = $(if ($name) { "$name" } else { "$address" })
        }
    }
}

function Convert-GraphDateTimeTimeZone {
    param($DateTimeTimeZone)
    if (-not $DateTimeTimeZone) { return $null }
    $dt = Get-GraphProperty -Object $DateTimeTimeZone -Names @('dateTime', 'DateTime')
    if (-not $dt) { return $null }
    $tz = Convert-GraphEnumString -Value (Get-GraphProperty -Object $DateTimeTimeZone -Names @('timeZone', 'TimeZone')) -Fallback 'UTC'
    return @{
        dateTime = "$dt"
        timeZone = $tz
    }
}

function Convert-GraphLocation {
    param($Location)
    if (-not $Location) { return $null }
    $display = $Location.DisplayName
    $uri     = $Location.LocationUri
    if (-not $display -and -not $uri) { return $null }
    $result = @{}
    if ($display) { $result.displayName = "$display" }
    if ($uri)     { $result.locationUri = "$uri" }
    # Do not copy uniqueId / locationType from the source mailbox; those ids are
    # not valid on the target and Graph returns 400 Bad Request.
    return $result
}

function Format-GraphDateOnly {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    $s = "$Value"
    if ($s -match '^\d{4}-\d{2}-\d{2}') { return $s.Substring(0, 10) }
    try { return ([datetime]$Value).ToString('yyyy-MM-dd') } catch { return $null }
}

function Convert-GraphRecurrence {
    param($Recurrence)
    if (-not $Recurrence -or -not $Recurrence.Pattern -or -not $Recurrence.Range) { return $null }

    $p = $Recurrence.Pattern
    $r = $Recurrence.Range

    $pattern = @{
        type     = (Convert-GraphEnumString -Value $p.Type)
        interval = [int]$p.Interval
    }
    if ($p.DaysOfWeek) {
        $pattern.daysOfWeek = @($p.DaysOfWeek | ForEach-Object { Convert-GraphEnumString -Value $_ })
    }
    if ($p.FirstDayOfWeek) { $pattern.firstDayOfWeek = (Convert-GraphEnumString -Value $p.FirstDayOfWeek) }
    if ($null -ne $p.Month -and "$($p.Month)" -ne '' -and [int]$p.Month -gt 0) { $pattern.month = [int]$p.Month }
    if ($null -ne $p.DayOfMonth -and "$($p.DayOfMonth)" -ne '' -and [int]$p.DayOfMonth -gt 0) { $pattern.dayOfMonth = [int]$p.DayOfMonth }
    if ($p.Index -and "$( $p.Index )" -ne '' -and "$( $p.Index )" -ne 'Default') { $pattern.index = (Convert-GraphEnumString -Value $p.Index) }

    $range = @{
        type = (Convert-GraphEnumString -Value $r.Type)
    }
    $startDate = Format-GraphDateOnly $r.StartDate
    $endDate   = Format-GraphDateOnly $r.EndDate
    if ($startDate) { $range.startDate = $startDate }
    if ($endDate)   { $range.endDate   = $endDate }
    if ($r.RecurrenceTimeZone) { $range.recurrenceTimeZone = "$($r.RecurrenceTimeZone)" }
    if ($null -ne $r.NumberOfOccurrences -and [int]$r.NumberOfOccurrences -gt 0) {
        $range.numberOfOccurrences = [int]$r.NumberOfOccurrences
    }

    return @{ pattern = $pattern; range = $range }
}

function Get-WellKnownFolderId {
    param(
        [string]$UserId,
        [string]$WellKnownName
    )
    try {
        $folder = Invoke-WithRetry -ScriptBlock {
            Get-MgUserMailFolder -UserId $UserId -MailFolderId $WellKnownName -ErrorAction Stop
        }
        return $folder.Id
    }
    catch {
        return $null
    }
}

function Get-TeamsMeetingJoinUrl {
    param($Event)

    $url = $null
    if ($Event.OnlineMeeting -and $Event.OnlineMeeting.JoinUrl) {
        $url = "$($Event.OnlineMeeting.JoinUrl)"
    }
    if (-not $url -and $Event.OnlineMeetingUrl) {
        $url = "$($Event.OnlineMeetingUrl)"
    }
    if (-not $url -and $Event.Location) {
        $locUri = [string](Get-GraphProperty -Object $Event.Location -Names @('locationUri', 'LocationUri'))
        if ($locUri -and $locUri -match 'teams\.microsoft\.com') {
            $url = $locUri
        }
    }
    if (-not $url -and $Event.Location -and "$($Event.Location.DisplayName)" -match 'https://teams\.microsoft\.com') {
        $locMatch = [regex]::Match("$($Event.Location.DisplayName)", 'https://teams\.microsoft\.com[^\s<>"]+')
        if ($locMatch.Success) { $url = $locMatch.Value }
    }
    if (-not $url -and $Event.Body -and $Event.Body.Content) {
        $content = "$($Event.Body.Content)"
        $bodyMatch = [regex]::Match($content, 'https://teams\.microsoft\.com/l/meetup-join[^\s<>"]+')
        if ($bodyMatch.Success) {
            $url = [System.Net.WebUtility]::HtmlDecode($bodyMatch.Value)
        }
    }
    if ($url) {
        $url = $url.TrimEnd([char[]]@('.', ',', ')', ']'))
    }
    return $url
}

function New-TeamsMeetingExtendedProperties {
    param(
        [string]$JoinUrl,
        [string]$OrganizerEmail
    )

    $props = New-ExtPropList
    if (-not $JoinUrl) { return , $props }

    Add-ExtProp -List $props -Id "String $script:PsetPublicStrings Name SkypeTeamsMeetingUrl" -Value $JoinUrl
    Add-ExtProp -List $props -Id "String $script:PsetAppointment Id 0x8248" -Value $JoinUrl   # PidLidNetShowUrl
    Add-ExtProp -List $props -Id "Boolean $script:PsetAppointment Id 0x8240" -Value 'true'    # PidLidConferencingCheck

    $threadId = $null
    $tid      = $null
    $oid      = $null

    try {
        $decoded = [uri]::UnescapeDataString($JoinUrl)
        if ($decoded -match 'meetup-join/([^/?]+)') {
            $threadId = $Matches[1]
        }
        if ($JoinUrl -match 'context=([^&]+)') {
            $ctxJson = [uri]::UnescapeDataString($Matches[1])
            $ctx = $ctxJson | ConvertFrom-Json
            $tid = $ctx.Tid
            $oid = $ctx.Oid
        }
    }
    catch { }

    if ($threadId) {
        $teamsPropsJson = (@{ cid = $threadId; private = $true; type = 0; mid = 0; rid = 0; uid = $null } | ConvertTo-Json -Compress)
        Add-ExtProp -List $props -Id "String $script:PsetPublicStrings Name SkypeTeamsProperties" -Value $teamsPropsJson
    }

    if ($threadId -and $tid -and $oid) {
        $threadForConf = $threadId -replace '@', '-'
        $oidCompact    = ($oid -replace '-', '')
        $tidCompact    = ($tid -replace '-', '')
        $sip           = if ($OrganizerEmail) { $OrganizerEmail } else { 'organizer@teams.microsoft.com' }
        $confLink      = "conf:sip:${sip};gruu;opaque=app:conf:focus:id:teams:2:0!${threadForConf}!${oidCompact}!${tidCompact}"
        Add-ExtProp -List $props -Id "String $script:PsetPublicStrings Name OnlineMeetingConfLink" -Value $confLink

        $threadForPath = $threadId -replace '^19:', '19_'
        Add-ExtProp -List $props -Id "String $script:PsetPublicStrings Name SchedulingServiceUpdateUrl" `
            -Value "https://api.scheduler.teams.microsoft.com/teams/$tid/$oid/$threadForPath/0"
        Add-ExtProp -List $props -Id "String $script:PsetPublicStrings Name SchedulingServiceMeetingOptionsUrl" `
            -Value "https://teams.microsoft.com/meetingOptions/?organizerId=$oid&tenantId=$tid&threadId=$threadForPath&messageId=0"
    }

    return , $props
}

function Add-TeamsJoinLinkToBody {
    param(
        [hashtable]$Body,
        [string]$JoinUrl
    )
    if (-not $JoinUrl) { return $Body }
    if (-not $Body) {
        $Body = @{ contentType = 'html'; content = '' }
    }

    $content     = if ($Body.content) { "$($Body.content)" } else { '' }
    $contentType = if ($Body.contentType) { "$($Body.contentType)" } else { 'html' }

    if ($content -match [regex]::Escape($JoinUrl) -or $content -match 'meetup-join') {
        return $Body
    }

    if ($contentType -match '(?i)html') {
        $linkHtml = "<div style=`"margin-bottom:12px;`"><a href=`"$JoinUrl`">Join Microsoft Teams Meeting</a></div>"
        $Body.content     = $linkHtml + $content
        $Body.contentType = 'html'
    }
    else {
        $Body.content = "Join Microsoft Teams Meeting: $JoinUrl`r`n`r`n$content"
    }
    return $Body
}

function Add-AttendeeListToBody {
    param(
        [hashtable]$Body,
        $Attendees
    )
    if (-not $Attendees) { return $Body }
    $required = New-Object System.Collections.Generic.List[string]
    $optional = New-Object System.Collections.Generic.List[string]
    foreach ($att in (Get-GraphItemList $Attendees)) {
        $address = $null
        $name    = $null
        $email   = Get-GraphProperty -Object $att -Names @('emailAddress', 'EmailAddress')
        $address = Get-GraphProperty -Object $email -Names @('address', 'Address')
        $name    = Get-GraphProperty -Object $email -Names @('name', 'Name')
        if (-not $address) { continue }
        $entry = if ($name) { "$name <$address>" } else { "$address" }
        $type  = (Convert-GraphEnumString -Value $att.Type -Fallback 'required').ToLowerInvariant()
        if ($type -match 'optional') { [void]$optional.Add($entry) } else { [void]$required.Add($entry) }
    }
    if ($required.Count -eq 0 -and $optional.Count -eq 0) { return $Body }

    if (-not $Body) { $Body = @{ contentType = 'html'; content = '' } }
    $content     = if ($Body.content) { "$($Body.content)" } else { '' }
    $contentType = if ($Body.contentType) { "$($Body.contentType)" } else { 'html' }

    $reqText = ($required -join '; ')
    $optText = ($optional -join '; ')
    if ($contentType -match '(?i)html') {
        $html = '<div style="margin-bottom:12px;color:#5f6a7d;font-size:12px;">'
        if ($reqText) { $html += "<div><b>Required attendees:</b> $([System.Net.WebUtility]::HtmlEncode($reqText))</div>" }
        if ($optText) { $html += "<div><b>Optional attendees:</b> $([System.Net.WebUtility]::HtmlEncode($optText))</div>" }
        $html += '</div>'
        $Body.content     = $html + $content
        $Body.contentType = 'html'
    }
    else {
        $block = ''
        if ($reqText) { $block += "Required attendees: $reqText`r`n" }
        if ($optText) { $block += "Optional attendees: $optText`r`n" }
        $Body.content = $block + "`r`n" + $content
    }
    return $Body
}

function Convert-ShowAsToBusyStatus {
    param($ShowAs)
    switch -Regex ("$ShowAs") {
        'free'              { return 0 }
        'tentative'         { return 1 }
        'oof|workingElsewhere' { return 3 }
        default             { return 2 } # busy
    }
}

function Add-SenderExtendedProperties {
    param(
        $List,
        $FromObj,
        $SenderObj
    )
    $fromAddr = $null; $fromName = $null
    $sendAddr = $null; $sendName = $null
    if ($FromObj -and $FromObj.emailAddress) {
        $fromAddr = $FromObj.emailAddress.address
        $fromName = $FromObj.emailAddress.name
    }
    if ($SenderObj -and $SenderObj.emailAddress) {
        $sendAddr = $SenderObj.emailAddress.address
        $sendName = $SenderObj.emailAddress.name
    }
    if (-not $sendAddr) { $sendAddr = $fromAddr }
    if (-not $sendName) { $sendName = $fromName }

    # PidTagSenderSmtpAddress / PidTagSenderEmailAddress / PidTagSenderName
    if ($sendAddr) {
        Add-ExtProp -List $List -Id 'String 0x5D01' -Value "$sendAddr"
        Add-ExtProp -List $List -Id 'String 0x0C1F' -Value "$sendAddr"
    }
    if ($sendName) {
        Add-ExtProp -List $List -Id 'String 0x0C1A' -Value "$sendName"
    }
    # PidTagSentRepresentingSmtpAddress / EmailAddress / Name (Outlook From)
    if ($fromAddr) {
        Add-ExtProp -List $List -Id 'String 0x5D02' -Value "$fromAddr"
        Add-ExtProp -List $List -Id 'String 0x0065' -Value "$fromAddr"
    }
    if ($fromName) {
        Add-ExtProp -List $List -Id 'String 0x0042' -Value "$fromName"
    }
}

function New-SilentAttendeeExtendedProperties {
    param($Attendees)

    $props = New-ExtPropList
    if (-not $Attendees) { return , $props }

    $required  = New-Object System.Collections.Generic.List[string]
    $optional  = New-Object System.Collections.Generic.List[string]
    $resource  = New-Object System.Collections.Generic.List[string]
    $toNames   = New-Object System.Collections.Generic.List[string]
    $ccNames   = New-Object System.Collections.Generic.List[string]

    foreach ($att in (Get-GraphItemList $Attendees)) {
        $address = $null
        $name    = $null
        $email   = Get-GraphProperty -Object $att -Names @('emailAddress', 'EmailAddress')
        $address = Get-GraphProperty -Object $email -Names @('address', 'Address')
        $name    = Get-GraphProperty -Object $email -Names @('name', 'Name')
        if (-not $address) { continue }
        $label = if ($name) { "$name" } else { "$address" }
        $entry = if ($name) { "$name <$address>" } else { "$address" }
        $type  = (Convert-GraphEnumString -Value $att.Type -Fallback 'required').ToLowerInvariant()

        switch -Regex ($type) {
            'optional' {
                [void]$optional.Add($entry)
                [void]$ccNames.Add($label)
            }
            'resource' {
                [void]$resource.Add($entry)
            }
            default {
                [void]$required.Add($entry)
                [void]$toNames.Add($label)
            }
        }
    }

    # PidLidToAttendeesString / PidLidCcAttendeesString — shown in the Outlook meeting UI
    if ($toNames.Count -gt 0) {
        Add-ExtProp -List $props -Id "String $script:PsetAppointment Id 0x823B" -Value ($toNames -join '; ')
    }
    if ($ccNames.Count -gt 0) {
        Add-ExtProp -List $props -Id "String $script:PsetAppointment Id 0x823C" -Value ($ccNames -join '; ')
    }
    # PidLidRequiredAttendees / Optional / Resource (PSETID_Meeting)
    if ($required.Count -gt 0) {
        Add-ExtProp -List $props -Id "String $script:PsetMeeting Id 0x0006" -Value ($required -join '; ')
    }
    if ($optional.Count -gt 0) {
        Add-ExtProp -List $props -Id "String $script:PsetMeeting Id 0x0007" -Value ($optional -join '; ')
    }
    if ($resource.Count -gt 0) {
        Add-ExtProp -List $props -Id "String $script:PsetMeeting Id 0x0008" -Value ($resource -join '; ')
    }

    return , $props
}

function Copy-MessageAttachments {
    param(
        [string]$SourceUserId,
        [string]$SourceMessageId,
        [string]$TargetUserId,
        [string]$TargetMessageId,
        [bool]$HasAttachments
    )

    if (-not $HasAttachments -or -not $TargetMessageId) { return }

    try {
        $attachments = Invoke-GraphPagedRequest -CommandBlock {
            Get-MgUserMessageAttachment -UserId $SourceUserId -MessageId $SourceMessageId -All
        }
        if (-not $attachments) { return }

        foreach ($att in @($attachments)) {
            $odataType = $null
            if ($att.AdditionalProperties -and $att.AdditionalProperties['@odata.type']) {
                $odataType = $att.AdditionalProperties['@odata.type']
            }
            elseif ($att.OdataType) {
                $odataType = $att.OdataType
            }
            if ($odataType -and $odataType -notmatch 'fileAttachment') { continue }

            $full = Invoke-WithRetry -ScriptBlock {
                Get-MgUserMessageAttachment -UserId $SourceUserId -MessageId $SourceMessageId -AttachmentId $att.Id -ErrorAction Stop
            }

            $bytes = $null
            if ($full.AdditionalProperties -and $full.AdditionalProperties['contentBytes']) {
                $bytes = $full.AdditionalProperties['contentBytes']
            }
            elseif ($full.ContentBytes) {
                $bytes = $full.ContentBytes
            }
            if ($bytes -is [byte[]]) {
                $bytes = [convert]::ToBase64String($bytes)
            }
            if (-not $bytes) { continue }

            $attBody = @{
                '@odata.type' = '#microsoft.graph.fileAttachment'
                name          = $full.Name
                contentType   = $full.ContentType
                contentBytes  = "$bytes"
            }
            if ($full.IsInline) { $attBody.isInline = $true }
            $contentId = $null
            if ($full.AdditionalProperties -and $full.AdditionalProperties['contentId']) {
                $contentId = $full.AdditionalProperties['contentId']
            }
            elseif ($full.ContentId) {
                $contentId = $full.ContentId
            }
            if ($contentId) { $attBody.contentId = "$contentId" }

            $uEnc = [uri]::EscapeDataString($TargetUserId)
            $uri  = "$script:GraphBase/users/$uEnc/messages/$TargetMessageId/attachments"
            Invoke-GraphJsonPost -Uri $uri -BodyObject $attBody | Out-Null
        }
    }
    catch {
        # Attachment copy is best-effort; the message itself was already created.
    }
}

# ------------------------------------------------------------------------------
# Authentication
# ------------------------------------------------------------------------------
function Connect-ToGraph {
    param([System.Windows.Forms.TextBox]$StatusBox)

    try {
        $StatusBox.AppendText("Opening browser for Microsoft Graph authentication...`r`n")
        $StatusBox.AppendText("Complete the sign-in in your browser, then return here.`r`n")
        $StatusBox.Refresh()

        Connect-MgGraph -Scopes "Mail.ReadWrite",
                                "Calendars.ReadWrite",
                                "Mail.ReadWrite.Shared",
                                "Calendars.ReadWrite.Shared" `
                        -NoWelcome -ErrorAction Stop

        $context = Get-MgContext
        $StatusBox.AppendText("Authenticated as: $($context.Account)`r`n")
        $StatusBox.AppendText("Ready. Confirm pre-flight checklist and click Start Copy.`r`n`r`n")
        $StatusBox.Refresh()

        $script:Connected = $true
        return $true
    }
    catch {
        $StatusBox.AppendText("Authentication failed: $($_.Exception.Message)`r`n")
        $StatusBox.Refresh()
        return $false
    }
}

# ------------------------------------------------------------------------------
# Folder helpers
# ------------------------------------------------------------------------------
function Get-AllMailFolders {
    param(
        [string]$UserId,
        [string]$ParentFolderId = $null,
        [string]$ParentPath    = ""
    )

    $allFolders = @()

    try {
        if ($ParentFolderId) {
            $folders = Invoke-GraphPagedRequest -CommandBlock {
                Get-MgUserMailFolderChildFolder -UserId $UserId -MailFolderId $ParentFolderId -All
            }
        }
        else {
            $folders = Invoke-GraphPagedRequest -CommandBlock {
                Get-MgUserMailFolder -UserId $UserId -All
            }
        }

        foreach ($folder in $folders) {
            $folderPath = if ($ParentPath) { "$ParentPath\$($folder.DisplayName)" } else { $folder.DisplayName }

            $allFolders += [PSCustomObject]@{
                Id               = $folder.Id
                DisplayName      = $folder.DisplayName
                FullPath         = $folderPath
                TotalItemCount   = $folder.TotalItemCount
                UnreadItemCount  = $folder.UnreadItemCount
                ChildFolderCount = $folder.ChildFolderCount
            }

            if ($folder.ChildFolderCount -gt 0) {
                $allFolders += Get-AllMailFolders -UserId $UserId -ParentFolderId $folder.Id -ParentPath $folderPath
            }
        }
    }
    catch {
        Write-Host "Error getting folders: $($_.Exception.Message)"
    }

    return $allFolders
}

function Ensure-FolderStructure {
    param(
        [string]$TargetUserId,
        [string]$FolderPath,
        [System.Windows.Forms.TextBox]$StatusBox
    )

    $pathParts      = $FolderPath -split '\\'
    $currentPath    = ""
    $parentFolderId = $null

    foreach ($part in $pathParts) {
        $currentPath = if ($currentPath) { "$currentPath\$part" } else { $part }

        try {
            if ($parentFolderId) {
                $existingFolder = Invoke-WithRetry -ScriptBlock {
                    Get-MgUserMailFolderChildFolder -UserId $TargetUserId `
                        -MailFolderId $parentFolderId `
                        -Filter "displayName eq '$part'" `
                        -ErrorAction SilentlyContinue |
                        Select-Object -First 1
                }
            }
            else {
                $existingFolder = Invoke-WithRetry -ScriptBlock {
                    Get-MgUserMailFolder -UserId $TargetUserId `
                        -Filter "displayName eq '$part'" `
                        -ErrorAction SilentlyContinue |
                        Select-Object -First 1
                }
            }

            if ($existingFolder) {
                $parentFolderId = $existingFolder.Id
            }
            else {
                $newFolderParams = @{ DisplayName = $part }

                if ($parentFolderId) {
                    $newFolder = Invoke-WithRetry -ScriptBlock {
                        New-MgUserMailFolderChildFolder -UserId $TargetUserId `
                            -MailFolderId $parentFolderId `
                            -BodyParameter $newFolderParams
                    }
                }
                else {
                    $newFolder = Invoke-WithRetry -ScriptBlock {
                        New-MgUserMailFolder -UserId $TargetUserId -BodyParameter $newFolderParams
                    }
                }

                $parentFolderId = $newFolder.Id
                $StatusBox.AppendText("  Created folder: $currentPath`r`n")
                $StatusBox.Refresh()
            }
        }
        catch {
            $StatusBox.AppendText("  Error creating folder $currentPath : $($_.Exception.Message)`r`n")
        }
    }

    return $parentFolderId
}

# ------------------------------------------------------------------------------
# Email copy
# ------------------------------------------------------------------------------
function Copy-Emails {
    param(
        [string]$SourceEmail,
        [string]$TargetEmail,
        [System.Windows.Forms.TextBox]$StatusBox,
        [System.Windows.Forms.ProgressBar]$ProgressBar
    )

    try {
        $StatusBox.AppendText("`r`n=== STARTING EMAIL COPY ===`r`n")
        $StatusBox.Refresh()

        $StatusBox.AppendText("Scanning folder structure from $SourceEmail...`r`n")
        $StatusBox.Refresh()
        $sourceFolders = Get-AllMailFolders -UserId $SourceEmail

        $StatusBox.AppendText("Found $($sourceFolders.Count) folders:`r`n`r`n--- FOLDER STRUCTURE ---`r`n")
        foreach ($f in $sourceFolders) {
            $StatusBox.AppendText("  $($f.FullPath) ($($f.TotalItemCount) items)`r`n")
        }
        $StatusBox.AppendText("`r`n")
        $StatusBox.Refresh()

        $totalMessages = ($sourceFolders | Measure-Object -Property TotalItemCount -Sum).Sum
        if ($totalMessages -eq 0) {
            $StatusBox.AppendText("No emails found in source mailbox.`r`n")
            return @{ Success = $true; Copied = 0; Failed = 0; Folders = 0; Skipped = 0; Cancelled = $false }
        }

        $StatusBox.AppendText("Total emails to process: $totalMessages across $($sourceFolders.Count) folders`r`n`r`n")
        $StatusBox.Refresh()

        $sentItemsId = Get-WellKnownFolderId -UserId $SourceEmail -WellKnownName 'sentitems'
        $draftsId    = Get-WellKnownFolderId -UserId $SourceEmail -WellKnownName 'drafts'

        $totalCopied     = 0
        $totalFailed     = 0
        $totalSkipped    = 0
        $foldersCopied   = 0
        $overallProgress = 0

        foreach ($sourceFolder in $sourceFolders) {
            if ($sourceFolder.TotalItemCount -eq 0) { continue }

            $StatusBox.AppendText("--- Processing Folder: $($sourceFolder.FullPath) ---`r`n")
            $StatusBox.Refresh()

            $StatusBox.AppendText("  Ensuring folder structure in target mailbox...`r`n")
            $targetFolderId = Ensure-FolderStructure -TargetUserId $TargetEmail `
                                                     -FolderPath $sourceFolder.FullPath `
                                                     -StatusBox $StatusBox

            $StatusBox.AppendText("  Checking for existing messages in destination folder...`r`n")
            $StatusBox.Refresh()

            $headerSelect = 'id,subject,from,receivedDateTime,sentDateTime,isRead,isDraft,hasAttachments,importance'

            $targetMessages = @{}
            try {
                $existingUri = New-FolderMessagesListUri -UserId $TargetEmail -FolderId $targetFolderId -Select $headerSelect
                $existingMessages = Get-GraphCollection -Uri $existingUri -StatusBox $StatusBox `
                    -ProgressPrefix 'Destination index' -ExpectedCount 0
                foreach ($msg in $existingMessages) {
                    if ($script:CancelRequested) {
                        $StatusBox.AppendText("`r`n*** COPY CANCELLED BY USER ***`r`n")
                        Update-CopyUi -StatusBox $StatusBox
                        return @{ Copied = $totalCopied; Skipped = $totalSkipped; Failed = $totalFailed; Cancelled = $true }
                    }
                    $targetMessages[(Get-MessageDedupeKey -Message $msg)] = $true
                }
                $StatusBox.AppendText("  Found $($targetMessages.Count) existing messages in destination`r`n")
            }
            catch {
                $StatusBox.AppendText("  Could not retrieve existing messages: $($_.Exception.Message)`r`n")
            }
            Update-CopyUi -StatusBox $StatusBox

            $StatusBox.AppendText("  Listing $($sourceFolder.TotalItemCount) source messages (headers only, no body)...`r`n")
            Update-CopyUi -StatusBox $StatusBox

            try {
                $folderCopied  = 0
                $folderFailed  = 0
                $folderSkipped = 0

                $sourceUri = New-FolderMessagesListUri -UserId $SourceEmail -FolderId $sourceFolder.Id -Select $headerSelect
                $sourceMessages = Get-GraphCollection -Uri $sourceUri -StatusBox $StatusBox `
                    -ProgressPrefix 'Source list' -ExpectedCount ([int]$sourceFolder.TotalItemCount)

                if ($script:CancelRequested) {
                    $StatusBox.AppendText("`r`n*** COPY CANCELLED BY USER ***`r`n")
                    Update-CopyUi -StatusBox $StatusBox
                    return @{ Copied = $totalCopied; Skipped = $totalSkipped; Failed = $totalFailed; Cancelled = $true }
                }

                $StatusBox.AppendText("  Listed $($sourceMessages.Count) messages. Starting copy...`r`n")
                Update-CopyUi -StatusBox $StatusBox

                $batchSize   = 100
                $batchNumber = 0
                $isSentFolder  = ($sentItemsId -and $sourceFolder.Id -eq $sentItemsId)
                $isDraftFolder = ($draftsId -and $sourceFolder.Id -eq $draftsId)

                for ($i = 0; $i -lt $sourceMessages.Count; $i += $batchSize) {
                    if ($script:CancelRequested) {
                        $StatusBox.AppendText("`r`n*** COPY CANCELLED BY USER ***`r`n")
                        Update-CopyUi -StatusBox $StatusBox
                        return @{ Copied = $totalCopied; Skipped = $totalSkipped; Failed = $totalFailed; Cancelled = $true }
                    }

                    $batchNumber++
                    $end = $i + $batchSize
                    if ($end -gt $sourceMessages.Count) { $end = $sourceMessages.Count }
                    $end = $end - 1
                    $batchCount = ($end - $i) + 1

                    $StatusBox.AppendText("  Batch $batchNumber : Processing $batchCount messages ($($i + 1)-$($end + 1) of $($sourceMessages.Count))...`r`n")
                    Update-CopyUi -StatusBox $StatusBox -ProgressBar $ProgressBar

                    for ($j = $i; $j -le $end; $j++) {
                        if ($script:CancelRequested) {
                            $StatusBox.AppendText("`r`n*** COPY CANCELLED BY USER ***`r`n")
                            Update-CopyUi -StatusBox $StatusBox
                            return @{ Copied = $totalCopied; Skipped = $totalSkipped; Failed = $totalFailed; Cancelled = $true }
                        }

                        $summary    = $sourceMessages[$j]
                        $messageKey = Get-MessageDedupeKey -Message $summary

                        if ($targetMessages.ContainsKey($messageKey)) {
                            $folderSkipped++; $totalSkipped++; $overallProgress++
                            if (($overallProgress % 25) -eq 0) {
                                Set-CopyProgress -ProgressBar $ProgressBar -Current $overallProgress -Total $totalMessages
                                Update-CopyUi -StatusBox $StatusBox -ProgressBar $ProgressBar
                            }
                            continue
                        }

                        try {
                            $msgId = Get-GraphProperty -Object $summary -Names @('id', 'Id')
                            if (-not $msgId) { throw 'Source message is missing an id' }

                            $message = Get-GraphMessageById -UserId $SourceEmail -MessageId $msgId

                            $bodyObj     = Get-GraphProperty -Object $message -Names @('body', 'Body')
                            $bodyType    = Get-GraphProperty -Object $bodyObj -Names @('contentType', 'ContentType')
                            $bodyContent = Get-GraphProperty -Object $bodyObj -Names @('content', 'Content')
                            $isRead      = [bool](Get-GraphProperty -Object $message -Names @('isRead', 'IsRead'))
                            $isDraft     = [bool](Get-GraphProperty -Object $message -Names @('isDraft', 'IsDraft'))
                            $hasAttach   = [bool](Get-GraphProperty -Object $message -Names @('hasAttachments', 'HasAttachments'))
                            $subject     = Get-GraphProperty -Object $message -Names @('subject', 'Subject')
                            $importance  = Get-GraphProperty -Object $message -Names @('importance', 'Importance')
                            $sentDt      = Get-GraphProperty -Object $message -Names @('sentDateTime', 'SentDateTime')
                            $recvDt      = Get-GraphProperty -Object $message -Names @('receivedDateTime', 'ReceivedDateTime')

                            $msgBody = @{
                                subject = $subject
                                body    = @{
                                    contentType = Convert-GraphEnumString -Value $bodyType -Fallback 'text'
                                    content     = if ($bodyContent) { "$bodyContent" } else { '' }
                                }
                                importance = Convert-GraphEnumString -Value $importance -Fallback 'normal'
                                isRead     = $isRead
                            }

                            $msgFlags = 0
                            if ($isRead) { $msgFlags = $msgFlags -bor 1 }
                            if ($isSentFolder) { $msgFlags = $msgFlags -bor 0x20 }
                            if ($isDraftFolder -or $isDraft) { $msgFlags = $msgFlags -bor 0x8 }

                            $extended = New-ExtPropList
                            Add-ExtProp -List $extended -Id 'Integer 0x0E07' -Value "$msgFlags"

                            $submitTime   = Format-MapiSystemTime $(if ($sentDt) { $sentDt } else { $recvDt })
                            $deliveryTime = Format-MapiSystemTime $(if ($recvDt) { $recvDt } else { $sentDt })
                            if ($submitTime)   { Add-ExtProp -List $extended -Id 'SystemTime 0x0039' -Value $submitTime }
                            if ($deliveryTime) { Add-ExtProp -List $extended -Id 'SystemTime 0x0E06' -Value $deliveryTime }

                            $toList = New-Object System.Collections.ArrayList
                            foreach ($r in (Get-GraphItemList (Get-GraphProperty -Object $message -Names @('toRecipients', 'ToRecipients')))) {
                                $conv = Convert-GraphEmailRecipient -Recipient $r
                                if ($conv) { [void]$toList.Add($conv) }
                            }
                            if ($toList.Count) { $msgBody.toRecipients = $toList.ToArray() }

                            $ccList = New-Object System.Collections.ArrayList
                            foreach ($r in (Get-GraphItemList (Get-GraphProperty -Object $message -Names @('ccRecipients', 'CcRecipients')))) {
                                $conv = Convert-GraphEmailRecipient -Recipient $r
                                if ($conv) { [void]$ccList.Add($conv) }
                            }
                            if ($ccList.Count) { $msgBody.ccRecipients = $ccList.ToArray() }

                            $bccList = New-Object System.Collections.ArrayList
                            foreach ($r in (Get-GraphItemList (Get-GraphProperty -Object $message -Names @('bccRecipients', 'BccRecipients')))) {
                                $conv = Convert-GraphEmailRecipient -Recipient $r
                                if ($conv) { [void]$bccList.Add($conv) }
                            }
                            if ($bccList.Count) { $msgBody.bccRecipients = $bccList.ToArray() }

                            $fromObj = $null
                            $senderObj = $null
                            if (-not $isDraftFolder) {
                                $fromObj = Convert-GraphEmailRecipient -Recipient (Get-GraphProperty -Object $message -Names @('from', 'From'))
                                $senderObj = Convert-GraphEmailRecipient -Recipient (Get-GraphProperty -Object $message -Names @('sender', 'Sender'))
                                if ($fromObj) { $msgBody.from = $fromObj }
                                if ($senderObj) { $msgBody.sender = $senderObj }
                                $internetId = Get-GraphProperty -Object $message -Names @('internetMessageId', 'InternetMessageId')
                                if ($internetId) { $msgBody.internetMessageId = "$internetId" }
                                Add-SenderExtendedProperties -List $extended -FromObj $fromObj -SenderObj $senderObj
                            }

                            $extArr = Convert-ExtPropArray $extended
                            if ($extArr) { $msgBody.singleValueExtendedProperties = $extArr }

                            $categories = Get-GraphProperty -Object $message -Names @('categories', 'Categories')
                            if ($categories -and @($categories).Count -gt 0) {
                                $msgBody.categories = @($categories | ForEach-Object { "$_" })
                            }

                            $uEnc      = [uri]::EscapeDataString($TargetEmail)
                            $createUri = if ($targetFolderId) {
                                "$script:GraphBase/users/$uEnc/mailFolders/$targetFolderId/messages"
                            } else {
                                "$script:GraphBase/users/$uEnc/messages"
                            }

                            try {
                                $created = Invoke-GraphJsonPost -Uri $createUri -BodyObject $msgBody
                            }
                            catch {
                                $noIdentity = Copy-HashtableExcept -Source $msgBody -ExcludeKeys @('from', 'sender', 'internetMessageId')
                                try {
                                    $created = Invoke-GraphJsonPost -Uri $createUri -BodyObject $noIdentity
                                }
                                catch {
                                    $flagsOnly = Copy-HashtableExcept -Source $noIdentity -ExcludeKeys @('singleValueExtendedProperties')
                                    $flagsOnly.singleValueExtendedProperties = Convert-ExtPropArray @(@{ id = 'Integer 0x0E07'; value = "$msgFlags" })
                                    try {
                                        $created = Invoke-GraphJsonPost -Uri $createUri -BodyObject $flagsOnly
                                    }
                                    catch {
                                        $minimal = @{
                                            subject = $subject
                                            body    = $msgBody.body
                                            isRead  = $isRead
                                            singleValueExtendedProperties = Convert-ExtPropArray @(@{ id = 'Integer 0x0E07'; value = "$msgFlags" })
                                        }
                                        $created = Invoke-GraphJsonPost -Uri $createUri -BodyObject $minimal
                                    }
                                }
                            }
                            $newId = Get-GraphProperty -Object $created -Names @('id', 'Id')

                            if ($hasAttach -and $newId) {
                                Copy-MessageAttachments -SourceUserId $SourceEmail -SourceMessageId $msgId `
                                    -TargetUserId $TargetEmail -TargetMessageId $newId -HasAttachments $true
                            }

                            $folderCopied++; $totalCopied++
                            $targetMessages[$messageKey] = $true
                        }
                        catch {
                            $folderFailed++; $totalFailed++
                            if ($folderFailed -le 8) {
                                $failSubj = Get-GraphProperty -Object $summary -Names @('subject', 'Subject')
                                $StatusBox.AppendText("    Failed '$failSubj': $(Get-CopyErrorDetail $_ )`r`n")
                                Update-CopyUi -StatusBox $StatusBox
                            }
                        }

                        $overallProgress++
                        Set-CopyProgress -ProgressBar $ProgressBar -Current $overallProgress -Total $totalMessages
                        if (($overallProgress % 10) -eq 0) {
                            Update-CopyUi -StatusBox $StatusBox -ProgressBar $ProgressBar
                        }
                    }

                    $StatusBox.AppendText("  Batch $batchNumber complete: $folderCopied copied, $folderSkipped skipped, $folderFailed failed`r`n")
                    Update-CopyUi -StatusBox $StatusBox -ProgressBar $ProgressBar
                }

                $StatusBox.AppendText("  Folder '$($sourceFolder.FullPath)' done:`r`n")
                $StatusBox.AppendText("    - $folderCopied new messages copied`r`n")
                $StatusBox.AppendText("    - $folderSkipped duplicates skipped`r`n")
                $StatusBox.AppendText("    - $folderFailed failed`r`n`r`n")
                $foldersCopied++
            }
            catch {
                $StatusBox.AppendText("  Error processing folder: $($_.Exception.Message)`r`n`r`n")
            }

            $StatusBox.Refresh()
        }

        $StatusBox.AppendText("`r`n=== EMAIL COPY COMPLETED ===`r`n")
        $StatusBox.AppendText("Folders processed : $foldersCopied / $($sourceFolders.Count)`r`n")
        $StatusBox.AppendText("New messages copied: $totalCopied`r`n")
        $StatusBox.AppendText("Duplicates skipped : $totalSkipped`r`n")
        $StatusBox.AppendText("Failed             : $totalFailed`r`n")

        return @{ Success = $true; Copied = $totalCopied; Failed = $totalFailed; Folders = $foldersCopied; Skipped = $totalSkipped; Cancelled = $false }
    }
    catch {
        $StatusBox.AppendText("Error copying emails: $($_.Exception.Message)`r`n")
        return @{ Success = $false; Copied = 0; Failed = 0; Folders = 0; Skipped = 0; Cancelled = $false }
    }
}

# ------------------------------------------------------------------------------
# Calendar copy
# ------------------------------------------------------------------------------
function Copy-CalendarItems {
    param(
        [string]$SourceEmail,
        [string]$TargetEmail,
        [System.Windows.Forms.TextBox]$StatusBox,
        [System.Windows.Forms.ProgressBar]$ProgressBar
    )

    try {
        $StatusBox.AppendText("`r`n=== STARTING CALENDAR COPY ===`r`n")
        $StatusBox.AppendText("Attendees will be copied silently (no invitation emails).`r`n")
        $StatusBox.AppendText("Teams meetings keep the original join link (no new meeting is created).`r`n")
        $StatusBox.Refresh()

        $StatusBox.AppendText("Getting source calendar from $SourceEmail...`r`n")
        $StatusBox.Refresh()

        $sourceCalendar = Invoke-WithRetry -ScriptBlock {
            Get-MgUserCalendar -UserId $SourceEmail -Filter "name eq 'Calendar'" -ErrorAction Stop |
                Select-Object -First 1
        }
        if (-not $sourceCalendar) {
            $sourceCalendar = Invoke-WithRetry -ScriptBlock {
                Get-MgUserCalendar -UserId $SourceEmail -ErrorAction Stop | Select-Object -First 1
            }
        }
        if (-not $sourceCalendar) {
            $StatusBox.AppendText("ERROR: Could not find calendar for $SourceEmail`r`n")
            return @{ Copied = 0; Skipped = 0; Failed = 0; Cancelled = $false }
        }

        $StatusBox.AppendText("Retrieving calendar items from source...`r`n")
        Update-CopyUi -StatusBox $StatusBox

        $eventSelect = @(
            'id','subject','start','end','isAllDay','body','location','locations','attendees',
            'recurrence','showAs','importance','sensitivity','isReminderOn','reminderMinutesBeforeStart',
            'isOnlineMeeting','onlineMeetingProvider','onlineMeeting','onlineMeetingUrl',
            'organizer','isOrganizer','type','seriesMasterId','isCancelled','categories',
            'hideAttendees','responseStatus','responseRequested','hasAttachments'
        ) -join ','

        $srcCalEnc = [uri]::EscapeDataString($SourceEmail)
        $srcCalIdEnc = [uri]::EscapeDataString($sourceCalendar.Id)
        $eventUri  = "$script:GraphBase/users/$srcCalEnc/calendars/$srcCalIdEnc/events?`$top=50&`$select=$eventSelect"
        try {
            $events = Get-GraphCollection -Uri $eventUri -StatusBox $StatusBox -ProgressPrefix 'Source calendar'
        }
        catch {
            $StatusBox.AppendText("  Full property select failed ($($_.Exception.Message)); retrying with a reduced set...`r`n")
            Update-CopyUi -StatusBox $StatusBox
            $reducedSelect = 'id,subject,start,end,isAllDay,body,location,attendees,recurrence,showAs,importance,sensitivity,isReminderOn,reminderMinutesBeforeStart,isOnlineMeeting,onlineMeeting,onlineMeetingUrl,organizer,type,isCancelled,categories'
            $eventUri = "$script:GraphBase/users/$srcCalEnc/calendars/$srcCalIdEnc/events?`$top=50&`$select=$reducedSelect"
            $events = Get-GraphCollection -Uri $eventUri -StatusBox $StatusBox -ProgressPrefix 'Source calendar'
        }
        $totalEvents = $events.Count

        $StatusBox.AppendText("Found $totalEvents calendar items.`r`n")
        $StatusBox.Refresh()

        if ($script:CancelRequested) {
            $StatusBox.AppendText("`r`n*** COPY CANCELLED BY USER ***`r`n")
            $StatusBox.Refresh()
            return @{ Copied = 0; Skipped = 0; Failed = 0; Cancelled = $true }
        }

        if ($totalEvents -eq 0) {
            $StatusBox.AppendText("No calendar items to copy.`r`n")
            return @{ Copied = 0; Skipped = 0; Failed = 0; Cancelled = $false }
        }

        $StatusBox.AppendText("Checking for existing calendar items in $TargetEmail...`r`n")
        $StatusBox.Refresh()

        $targetCalendar = Invoke-WithRetry -ScriptBlock {
            Get-MgUserCalendar -UserId $TargetEmail -Filter "name eq 'Calendar'" -ErrorAction Stop |
                Select-Object -First 1
        }
        if (-not $targetCalendar) {
            $targetCalendar = Invoke-WithRetry -ScriptBlock {
                Get-MgUserCalendar -UserId $TargetEmail -ErrorAction Stop | Select-Object -First 1
            }
        }
        if (-not $targetCalendar) {
            $StatusBox.AppendText("ERROR: Could not find calendar for $TargetEmail`r`n")
            return @{ Copied = 0; Skipped = 0; Failed = 0; Cancelled = $false }
        }

        $StatusBox.AppendText("Fetching target calendar index...`r`n")
        Update-CopyUi -StatusBox $StatusBox

        $tgtCalEnc = [uri]::EscapeDataString($TargetEmail)
        $tgtCalIdEnc = [uri]::EscapeDataString($targetCalendar.Id)
        $targetIndexUri = "$script:GraphBase/users/$tgtCalEnc/calendars/$tgtCalIdEnc/events?`$top=100&`$select=subject,start"
        $targetCalendarItems = Get-GraphCollection -Uri $targetIndexUri -StatusBox $StatusBox -ProgressPrefix 'Target calendar index'

        $StatusBox.AppendText("Found $($targetCalendarItems.Count) existing items in target. Building duplicate index...`r`n")
        $StatusBox.Refresh()

        $targetEvents = @{}
        foreach ($te in $targetCalendarItems) {
            if ($script:CancelRequested) {
                $StatusBox.AppendText("`r`n*** COPY CANCELLED BY USER ***`r`n")
                $StatusBox.Refresh()
                return @{ Copied = 0; Skipped = 0; Failed = 0; Cancelled = $true }
            }
            $startTime = if ($te.Start.DateTime) { $te.Start.DateTime } else { "nodate" }
            $targetEvents["$($te.Subject)|$startTime"] = $true
        }

        $StatusBox.AppendText("Index complete. Starting copy...`r`n`r`n")
        $StatusBox.Refresh()

        $copiedCount  = 0
        $skippedCount = 0
        $failedCount  = 0
        $occurrenceSkip = 0
        $batchSize    = 250
        $batchNumber  = 0
        $uEnc         = [uri]::EscapeDataString($TargetEmail)
        $createUri    = "$script:GraphBase/users/$uEnc/calendars/$([uri]::EscapeDataString($targetCalendar.Id))/events"

        for ($i = 0; $i -lt $totalEvents; $i += $batchSize) {
            if ($script:CancelRequested) {
                $StatusBox.AppendText("`r`n*** COPY CANCELLED BY USER ***`r`n")
                $StatusBox.Refresh()
                return @{ Copied = $copiedCount; Skipped = $skippedCount; Failed = $failedCount; Cancelled = $true }
            }

            $batchNumber++
            $end = $i + $batchSize
            if ($end -gt $totalEvents) { $end = $totalEvents }
            $end = $end - 1
            $batchCount = ($end - $i) + 1

            $StatusBox.AppendText("  Batch $batchNumber : Processing $batchCount calendar items...`r`n")
            Update-CopyUi -StatusBox $StatusBox -ProgressBar $ProgressBar

            for ($j = $i; $j -le $end; $j++) {
                $event = $events[$j]
                if ($script:CancelRequested) {
                    $StatusBox.AppendText("`r`n*** COPY CANCELLED BY USER ***`r`n")
                    $StatusBox.Refresh()
                    return @{ Copied = $copiedCount; Skipped = $skippedCount; Failed = $failedCount; Cancelled = $true }
                }

                $eventType = (Convert-GraphEnumString -Value $event.Type -Fallback 'singleInstance').ToLowerInvariant()
                if ($eventType -eq 'occurrence') {
                    # Expanded instances of a recurring series. The series master is copied once.
                    $occurrenceSkip++
                    $skippedCount++
                    continue
                }

                $startTime = if ($event.Start.DateTime) { $event.Start.DateTime } else { "nodate" }
                $eventKey  = "$($event.Subject)|$startTime"

                if ($targetEvents.ContainsKey($eventKey)) {
                    $skippedCount++
                    continue
                }

                try {
                    $bodyContent = @{
                        contentType = Convert-GraphEnumString -Value $(if ($event.Body) { $event.Body.ContentType } else { $null }) -Fallback 'text'
                        content     = if ($event.Body.Content)     { "$($event.Body.Content)" }     else { '' }
                    }

                    $joinUrl = Get-TeamsMeetingJoinUrl -Event $event
                    $isTeams = [bool]$event.IsOnlineMeeting -or
                               ((Convert-GraphEnumString -Value $event.OnlineMeetingProvider) -match 'teams') -or
                               [bool]$joinUrl

                    if ($isTeams -and $joinUrl) {
                        $bodyContent = Add-TeamsJoinLinkToBody -Body $bodyContent -JoinUrl $joinUrl
                    }
                    if ($event.Attendees) {
                        $bodyContent = Add-AttendeeListToBody -Body $bodyContent -Attendees $event.Attendees
                    }
                    $bodyContent.contentType = Convert-GraphEnumString -Value $bodyContent.contentType -Fallback 'text'

                    $start = Convert-GraphDateTimeTimeZone -DateTimeTimeZone $event.Start
                    $end   = Convert-GraphDateTimeTimeZone -DateTimeTimeZone $event.End
                    if (-not $start -or -not $end) {
                        throw "Event is missing start/end: $($event.Subject)"
                    }

                    $eventBody = @{
                        subject     = $event.Subject
                        body        = $bodyContent
                        start       = $start
                        end         = $end
                        isAllDay    = [bool]$event.IsAllDay
                        showAs      = (Convert-GraphEnumString -Value $event.ShowAs -Fallback 'busy')
                        importance  = (Convert-GraphEnumString -Value $event.Importance -Fallback 'normal')
                        sensitivity = (Convert-GraphEnumString -Value $event.Sensitivity -Fallback 'normal')
                        isReminderOn = [bool]$event.IsReminderOn
                        responseRequested = $false
                        allowNewTimeProposals = $false
                    }

                    # Do NOT set isOnlineMeeting=true: Graph would provision a brand-new Teams
                    # meeting (new join URL) or drop the original meeting blob. Teams identity
                    # is restored via extended properties below.

                    $location = Convert-GraphLocation -Location $event.Location
                    if ($isTeams -and $joinUrl) {
                        if (-not $location) { $location = @{} }
                        if (-not $location.displayName) { $location.displayName = 'Microsoft Teams Meeting' }
                        if (-not $location.locationUri) { $location.locationUri = $joinUrl }
                    }
                    if ($location) { $eventBody.location = $location }

                    $recurrence = Convert-GraphRecurrence -Recurrence $event.Recurrence
                    if ($recurrence) { $eventBody.recurrence = $recurrence }

                    if ($event.IsReminderOn -and $null -ne $event.ReminderMinutesBeforeStart) {
                        $eventBody.reminderMinutesBeforeStart = [int]$event.ReminderMinutesBeforeStart
                    }
                    if ($event.Categories -and @($event.Categories).Count -gt 0) {
                        $eventBody.categories = @($event.Categories | ForEach-Object { "$_" })
                    }
                    if ($null -ne $event.HideAttendees) { $eventBody.hideAttendees = [bool]$event.HideAttendees }

                    $extended = New-ExtPropList

                    # AppointmentStateFlags: asfMeeting=1 so Outlook treats this as a meeting,
                    # not a private appointment. asfCanceled=4 when the source was cancelled.
                    $stateFlags = 1
                    if ($event.IsCancelled) { $stateFlags = $stateFlags -bor 4 }
                    Add-ExtProp -List $extended -Id "Integer $script:PsetAppointment Id 0x8217" -Value "$stateFlags"

                    # PidLidResponseStatus: respOrganized=1 (mailbox copy = target owns the item)
                    Add-ExtProp -List $extended -Id "Integer $script:PsetAppointment Id 0x8218" -Value '1'
                    Add-ExtProp -List $extended -Id "Integer $script:PsetAppointment Id 0x8205" -Value "$(Convert-ShowAsToBusyStatus $event.ShowAs)"

                    $organizerEmail = $null
                    $organizer = Get-GraphProperty -Object $event -Names @('organizer', 'Organizer')
                    $orgEmailObj = Get-GraphProperty -Object $organizer -Names @('emailAddress', 'EmailAddress')
                    $organizerEmail = Get-GraphProperty -Object $orgEmailObj -Names @('address', 'Address')
                    if ($organizerEmail) {
                        Add-ExtProp -List $extended -Id "String $script:PsetAppointment Id 0x8243" -Value "$organizerEmail"
                    }

                    # Attendees MUST NOT be posted in the Graph attendees collection — Exchange
                    # would send invitation emails to every recipient. Stamp display strings
                    # instead so Outlook still shows who was invited.
                    Add-ExtPropRange -List $extended -Items (New-SilentAttendeeExtendedProperties -Attendees $event.Attendees)

                    if ($isTeams) {
                        Add-ExtPropRange -List $extended -Items (New-TeamsMeetingExtendedProperties -JoinUrl $joinUrl -OrganizerEmail $organizerEmail)
                    }

                    $extArr = Convert-ExtPropArray $extended
                    if ($extArr) { $eventBody.singleValueExtendedProperties = $extArr }

                    try {
                        Invoke-GraphJsonPost -Uri $createUri -BodyObject $eventBody | Out-Null
                    }
                    catch {
                        # Retry without named properties if Graph rejected an extended-property id.
                        # Body still contains the Teams join hyperlink; invitations are still not sent.
                        $reduced = Copy-HashtableExcept -Source $eventBody -ExcludeKeys @('singleValueExtendedProperties', 'hideAttendees', 'allowNewTimeProposals', 'responseRequested')
                        try {
                            Invoke-GraphJsonPost -Uri $createUri -BodyObject $reduced | Out-Null
                        }
                        catch {
                            $minimal = @{
                                subject = $event.Subject
                                body    = $bodyContent
                                start   = $start
                                end     = $end
                            }
                            Invoke-GraphJsonPost -Uri $createUri -BodyObject $minimal | Out-Null
                        }
                    }
                    $copiedCount++
                }
                catch {
                    $failedCount++
                    if ($failedCount -le 8) {
                        $StatusBox.AppendText("    Failed '$($event.Subject)': $(Get-CopyErrorDetail $_ )`r`n")
                        $StatusBox.Refresh()
                    }
                }

                Set-CopyProgress -ProgressBar $ProgressBar -Current ($copiedCount + $failedCount + $skippedCount) -Total $totalEvents
                if ((($copiedCount + $failedCount + $skippedCount) % 10) -eq 0) {
                    Update-CopyUi -StatusBox $StatusBox -ProgressBar $ProgressBar
                }
            }

            $StatusBox.AppendText("  Batch $batchNumber : $copiedCount copied, $skippedCount skipped, $failedCount failed`r`n")
            $StatusBox.Refresh()
        }

        $StatusBox.AppendText("`r`n=== CALENDAR COPY COMPLETED ===`r`n")
        $StatusBox.AppendText("New items copied  : $copiedCount`r`n")
        $StatusBox.AppendText("Duplicates skipped: $skippedCount`r`n")
        if ($occurrenceSkip -gt 0) {
            $StatusBox.AppendText("  (includes $occurrenceSkip recurring occurrences skipped; series masters were copied)`r`n")
        }
        $StatusBox.AppendText("Failed            : $failedCount`r`n`r`n")

        return @{ Copied = $copiedCount; Skipped = $skippedCount; Failed = $failedCount; Cancelled = $false }
    }
    catch {
        $StatusBox.AppendText("ERROR during calendar copy: $($_.Exception.Message)`r`n")
        throw
    }
}

# ------------------------------------------------------------------------------
# Verification
# ------------------------------------------------------------------------------
function Verify-CopiedItems {
    param(
        [string]$SourceEmail,
        [string]$TargetEmail,
        [bool]$CheckEmails,
        [bool]$CheckCalendar,
        [System.Windows.Forms.TextBox]$StatusBox
    )

    try {
        $StatusBox.AppendText("`r`n--- Verifying Copied Items ---`r`n")

        if ($CheckEmails) {
            $srcFolders = Get-AllMailFolders -UserId $SourceEmail
            $tgtFolders = Get-AllMailFolders -UserId $TargetEmail
            $srcCount = ($srcFolders | Measure-Object -Property TotalItemCount -Sum).Sum
            $tgtCount = ($tgtFolders | Measure-Object -Property TotalItemCount -Sum).Sum
            $StatusBox.AppendText("Source mailbox emails: $srcCount`r`n")
            $StatusBox.AppendText("Target mailbox emails: $tgtCount`r`n")
            Update-CopyUi -StatusBox $StatusBox
        }

        if ($CheckCalendar) {
            $srcCal = Invoke-WithRetry -ScriptBlock {
                Get-MgUserCalendar -UserId $SourceEmail -Filter "name eq 'Calendar'" -Top 1
            }
            $tgtCal = Invoke-WithRetry -ScriptBlock {
                Get-MgUserCalendar -UserId $TargetEmail -Filter "name eq 'Calendar'" -Top 1
            }

            if ($srcCal -and $tgtCal) {
                $srcEnc = [uri]::EscapeDataString($SourceEmail)
                $tgtEnc = [uri]::EscapeDataString($TargetEmail)
                $srcEvtCount = (Get-GraphCollection -Uri "$script:GraphBase/users/$srcEnc/calendars/$([uri]::EscapeDataString($srcCal.Id))/events?`$top=100&`$select=id" -StatusBox $StatusBox -ProgressPrefix 'Verify source calendar').Count
                $tgtEvtCount = (Get-GraphCollection -Uri "$script:GraphBase/users/$tgtEnc/calendars/$([uri]::EscapeDataString($tgtCal.Id))/events?`$top=100&`$select=id" -StatusBox $StatusBox -ProgressPrefix 'Verify target calendar').Count
                $StatusBox.AppendText("Source calendar items: $srcEvtCount`r`n")
                $StatusBox.AppendText("Target calendar items: $tgtEvtCount`r`n")
            }
            else {
                $StatusBox.AppendText("Could not retrieve calendar for verification.`r`n")
            }
        }

        $StatusBox.AppendText("`r`nVerification completed!`r`n")
    }
    catch {
        $StatusBox.AppendText("Verification error: $($_.Exception.Message)`r`n")
    }
}

# ------------------------------------------------------------------------------
# GUI
# ------------------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text            = "Microsoft 365 Mailbox Copy Tool v1.12 (Interactive Login)"
$form.Size            = New-Object System.Drawing.Size(700, 760)
$form.StartPosition   = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox     = $false

$titleLabel          = New-Object System.Windows.Forms.Label
$titleLabel.Location = New-Object System.Drawing.Point(20, 20)
$titleLabel.Size     = New-Object System.Drawing.Size(660, 30)
$titleLabel.Text     = "Copy Emails and Calendar Items Between Mailboxes"
$titleLabel.Font     = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($titleLabel)

$authLabel          = New-Object System.Windows.Forms.Label
$authLabel.Location = New-Object System.Drawing.Point(20, 60)
$authLabel.Size     = New-Object System.Drawing.Size(660, 20)
$authLabel.Text     = "Step 1: Authenticate (Microsoft Graph)"
$authLabel.Font     = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($authLabel)

$connectButton          = New-Object System.Windows.Forms.Button
$connectButton.Location = New-Object System.Drawing.Point(20, 85)
$connectButton.Size     = New-Object System.Drawing.Size(220, 35)
$connectButton.Text     = "Sign In to Microsoft 365"
$connectButton.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$form.Controls.Add($connectButton)

$preflightLabel          = New-Object System.Windows.Forms.Label
$preflightLabel.Location = New-Object System.Drawing.Point(20, 140)
$preflightLabel.Size     = New-Object System.Drawing.Size(660, 20)
$preflightLabel.Text     = "Step 2: Pre-flight Checklist (must be completed before copying)"
$preflightLabel.Font     = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($preflightLabel)

$preflightHint          = New-Object System.Windows.Forms.Label
$preflightHint.Location = New-Object System.Drawing.Point(20, 163)
$preflightHint.Size     = New-Object System.Drawing.Size(660, 32)
$preflightHint.Text     = "Grant FullAccess on both mailboxes via Exchange Admin Center or EXO PowerShell before proceeding. Remove it manually when done."
$preflightHint.Font     = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
$preflightHint.ForeColor = [System.Drawing.Color]::Gray
$form.Controls.Add($preflightHint)

$accessGrantedCheckbox          = New-Object System.Windows.Forms.CheckBox
$accessGrantedCheckbox.Location = New-Object System.Drawing.Point(20, 198)
$accessGrantedCheckbox.Size     = New-Object System.Drawing.Size(640, 22)
$accessGrantedCheckbox.Text     = "I have granted FullAccess on both the source and target mailboxes to my account"
$accessGrantedCheckbox.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$accessGrantedCheckbox.Checked  = $false
$form.Controls.Add($accessGrantedCheckbox)

$sourceLabel          = New-Object System.Windows.Forms.Label
$sourceLabel.Location = New-Object System.Drawing.Point(20, 232)
$sourceLabel.Size     = New-Object System.Drawing.Size(660, 20)
$sourceLabel.Text     = "Step 3: Source Mailbox (copy FROM)"
$sourceLabel.Font     = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($sourceLabel)

$sourceTextbox          = New-Object System.Windows.Forms.TextBox
$sourceTextbox.Location = New-Object System.Drawing.Point(20, 255)
$sourceTextbox.Size     = New-Object System.Drawing.Size(500, 25)
$sourceTextbox.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$form.Controls.Add($sourceTextbox)

$targetLabel          = New-Object System.Windows.Forms.Label
$targetLabel.Location = New-Object System.Drawing.Point(20, 293)
$targetLabel.Size     = New-Object System.Drawing.Size(660, 20)
$targetLabel.Text     = "Step 4: Target Mailbox (copy TO)"
$targetLabel.Font     = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($targetLabel)

$targetTextbox          = New-Object System.Windows.Forms.TextBox
$targetTextbox.Location = New-Object System.Drawing.Point(20, 318)
$targetTextbox.Size     = New-Object System.Drawing.Size(500, 25)
$targetTextbox.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$form.Controls.Add($targetTextbox)

$optionsLabel          = New-Object System.Windows.Forms.Label
$optionsLabel.Location = New-Object System.Drawing.Point(20, 357)
$optionsLabel.Size     = New-Object System.Drawing.Size(660, 20)
$optionsLabel.Text     = "Step 5: What to Copy"
$optionsLabel.Font     = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($optionsLabel)

$emailCheckbox          = New-Object System.Windows.Forms.CheckBox
$emailCheckbox.Location = New-Object System.Drawing.Point(20, 382)
$emailCheckbox.Size     = New-Object System.Drawing.Size(200, 25)
$emailCheckbox.Text     = "Copy Email Messages"
$emailCheckbox.Checked  = $true
$emailCheckbox.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$form.Controls.Add($emailCheckbox)

$calendarCheckbox          = New-Object System.Windows.Forms.CheckBox
$calendarCheckbox.Location = New-Object System.Drawing.Point(20, 410)
$calendarCheckbox.Size     = New-Object System.Drawing.Size(420, 25)
$calendarCheckbox.Text     = "Copy Calendar Items (attendees silent, Teams links kept)"
$calendarCheckbox.Checked  = $true
$calendarCheckbox.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$form.Controls.Add($calendarCheckbox)

$copyButton          = New-Object System.Windows.Forms.Button
$copyButton.Location = New-Object System.Drawing.Point(20, 450)
$copyButton.Size     = New-Object System.Drawing.Size(200, 40)
$copyButton.Text     = "Start Copy"
$copyButton.Font     = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$copyButton.Enabled  = $false
$form.Controls.Add($copyButton)

$cancelButton           = New-Object System.Windows.Forms.Button
$cancelButton.Location  = New-Object System.Drawing.Point(230, 450)
$cancelButton.Size      = New-Object System.Drawing.Size(150, 40)
$cancelButton.Text      = "Cancel"
$cancelButton.Font      = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$cancelButton.Enabled   = $false
$cancelButton.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
$cancelButton.ForeColor = [System.Drawing.Color]::White
$form.Controls.Add($cancelButton)

$progressBar          = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(20, 505)
$progressBar.Size     = New-Object System.Drawing.Size(660, 25)
$form.Controls.Add($progressBar)

$statusBox            = New-Object System.Windows.Forms.TextBox
$statusBox.Location   = New-Object System.Drawing.Point(20, 540)
$statusBox.Size       = New-Object System.Drawing.Size(660, 178)
$statusBox.Multiline  = $true
$statusBox.ScrollBars = "Vertical"
$statusBox.ReadOnly   = $true
$statusBox.Font       = New-Object System.Drawing.Font("Consolas", 9)
$statusBox.Text       = "Welcome! Click 'Sign In to Microsoft 365' to begin.`r`n"
$form.Controls.Add($statusBox)

$connectButton.Add_Click({
    $connectButton.Enabled = $false
    $connectButton.Text    = "Connecting..."
    $statusBox.Refresh()

    if (Connect-ToGraph -StatusBox $statusBox) {
        $connectButton.Text      = "Connected"
        $connectButton.BackColor = [System.Drawing.Color]::LightGreen
        $copyButton.Enabled      = $true
    }
    else {
        $connectButton.Text    = "Sign In to Microsoft 365"
        $connectButton.Enabled = $true
    }
})

$cancelButton.Add_Click({
    if (-not $script:CancelRequested) {
        $r = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to cancel the copy operation?",
            "Confirm Cancel",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning)

        if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
            $script:CancelRequested = $true
            $statusBox.AppendText("`r`nCancel requested... stopping operation...`r`n")
            $statusBox.Refresh()
            $cancelButton.Text    = "Cancelling..."
            $cancelButton.Enabled = $false
        }
    }
})

$copyButton.Add_Click({
    $sourceEmail = $sourceTextbox.Text.Trim()
    $targetEmail = $targetTextbox.Text.Trim()

    if (-not $accessGrantedCheckbox.Checked) {
        [System.Windows.Forms.MessageBox]::Show("Please confirm the pre-flight checklist (Step 2) before copying.", "Pre-flight Check Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    if ([string]::IsNullOrWhiteSpace($sourceEmail) -or [string]::IsNullOrWhiteSpace($targetEmail)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter both source and target email addresses.", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    if ($sourceEmail -eq $targetEmail) {
        [System.Windows.Forms.MessageBox]::Show("Source and target email addresses must be different.", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    if (-not $emailCheckbox.Checked -and -not $calendarCheckbox.Checked) {
        [System.Windows.Forms.MessageBox]::Show("Please select at least one item type to copy.", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    if (-not $script:Connected) {
        [System.Windows.Forms.MessageBox]::Show("Please sign in first.", "Authentication Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $confirmMsg  = "You are about to COPY items from:`r`n$sourceEmail`r`n`r`nTo:`r`n$targetEmail`r`n`r`n"
    if ($emailCheckbox.Checked)    { $confirmMsg += "- Email messages will be copied (original sent/received times preserved)`r`n" }
    if ($calendarCheckbox.Checked) { $confirmMsg += "- Calendar items will be copied`r`n  Attendees are added without sending invitation emails`r`n  Teams meetings keep the original join link`r`n" }
    $confirmMsg += "`r`nOriginal items remain in the source mailbox.`r`n`r`nDo you want to continue?"

    $r = [System.Windows.Forms.MessageBox]::Show($confirmMsg, "Confirm Copy", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)

    if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
        $script:CancelRequested        = $false
        $cancelButton.Enabled          = $true
        $cancelButton.Text             = "Cancel"
        $copyButton.Enabled            = $false
        $sourceTextbox.Enabled         = $false
        $targetTextbox.Enabled         = $false
        $accessGrantedCheckbox.Enabled = $false
        $emailCheckbox.Enabled         = $false
        $calendarCheckbox.Enabled      = $false
        $progressBar.Value             = 0

        $statusBox.Clear()
        $statusBox.AppendText("=== COPY OPERATION STARTED ===`r`n")
        $statusBox.AppendText("Source : $sourceEmail`r`n")
        $statusBox.AppendText("Target : $targetEmail`r`n")
        $statusBox.Refresh()

        try {
            if ($emailCheckbox.Checked -and -not $script:CancelRequested) {
                $emailResult = Copy-Emails -SourceEmail $sourceEmail -TargetEmail $targetEmail -StatusBox $statusBox -ProgressBar $progressBar
            }
            if ($calendarCheckbox.Checked -and -not $script:CancelRequested) {
                $calendarResult = Copy-CalendarItems -SourceEmail $sourceEmail -TargetEmail $targetEmail -StatusBox $statusBox -ProgressBar $progressBar
            }

            if (-not $script:CancelRequested) {
                Verify-CopiedItems -SourceEmail $sourceEmail -TargetEmail $targetEmail `
                    -CheckEmails $emailCheckbox.Checked -CheckCalendar $calendarCheckbox.Checked `
                    -StatusBox $statusBox
                $progressBar.Value = 100
                $statusBox.AppendText("`r`n=== COPY OPERATION COMPLETED ===`r`n")
                $statusBox.AppendText("Remember to remove FullAccess permissions from both mailboxes.`r`n")
                [System.Windows.Forms.MessageBox]::Show(
                    "Copy operation completed!`r`n`r`nRemember to remove FullAccess permissions from both mailboxes.",
                    "Success",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information)
            }
            else {
                $statusBox.AppendText("`r`n=== COPY OPERATION CANCELLED ===`r`n")
                [System.Windows.Forms.MessageBox]::Show("Copy operation was cancelled by user.", "Cancelled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            }
        }
        catch {
            $statusBox.AppendText("`r`nERROR: $($_.Exception.Message)`r`n")
            [System.Windows.Forms.MessageBox]::Show("An error occurred. Check the status window for details.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
        finally {
            $copyButton.Enabled            = $true
            $sourceTextbox.Enabled         = $true
            $targetTextbox.Enabled         = $true
            $accessGrantedCheckbox.Enabled = $true
            $emailCheckbox.Enabled         = $true
            $calendarCheckbox.Enabled      = $true
            $cancelButton.Enabled          = $false
            $script:CancelRequested        = $false
        }
    }
})

[void]$form.ShowDialog()

if ($script:Connected) { Disconnect-MgGraph | Out-Null }

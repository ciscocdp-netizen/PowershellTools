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
    Version: 1.16
    Requires: Microsoft.Graph PowerShell SDK
    Authentication: Interactive (Delegated Permissions via browser)

    Changelog v1.16:
    - New: The target folder tree is enumerated and compared against the source
      before anything is created, and only the folders the target is missing are
      added. Folders that already exist are reused as they are, and folders that
      exist only in the target are reported and left alone. Nothing is renamed,
      moved or deleted.
    - Changed: Folder resolution no longer walks a path segment at a time with a
      lookup per segment; both trees are read once and diffed in memory, so a
      target that is already in sync costs no create/lookup calls at all.
    - New: Live status line above the progress bar naming the current phase
      (scanning source, scanning target, creating missing folders, copying email,
      copying calendar, verifying), the folder being worked on with its position
      in the run, and the item counter within that folder.
    - New: ETA line showing elapsed time, estimated time remaining, the wall-clock
      time the copy is expected to finish, throughput, and running copied /
      skipped / failed totals. The estimate uses recent throughput rather than the
      average since the start, so throttling is reflected instead of averaged out.
    - Changed: The progress bar is a marquee during phases whose size is not yet
      known and switches to a percentage once a total exists. The message total is
      corrected mid-run when a folder returns a different count than its
      TotalItemCount claimed, so the percentage and ETA stay honest.
    - Changed: Per-page and per-batch chatter moved out of the status log and into
      the live status line, so the log holds folder-level events instead of
      thousands of paging lines.

    Changelog v1.15:
    - Fixed: A folder whose display name contains an apostrophe (O'Brien Ltd) was
      never created. Its name went unescaped into $filter=displayName eq '...',
      Graph answered 400, and because the catch block left $parentFolderId at the
      previous value the folder's mail was written to its PARENT and its child
      folders were created one level too high. Names are now escaped ('' per
      OData), and a lookup failure falls back to a client-side name match instead
      of being treated as "folder does not exist".
    - Fixed: Mail from an unresolvable folder is no longer posted to
      /users/{id}/messages, which silently filed it in the target's Drafts folder
      (and made the duplicate-detection query enumerate the whole target mailbox).
      Such folders are now reported and skipped.
    - Fixed: Empty folders were never created, so the target hierarchy was missing
      every folder that held no mail. Folders are now mirrored before the
      item-count check.
    - Fixed: A failed folder listing (throttling, 403) dropped whole subtrees from
      the copy while only writing to the console via Write-Host, invisible in the
      GUI, and the run still reported success. Failures now go to the status log
      and set $script:FolderScanIncomplete, which downgrades the completion
      message.
    - Fixed: Well-known folders were matched by display name, so a target mailbox
      in another language (or with renamed folders) got a second "Inbox" and
      "Sent Items" beside its real ones. Root segments now resolve through the
      target's well-known folder names.
    - Fixed: A display name containing a backslash (HR\Payroll) was split into a
      nested path. Folder paths are carried as segment arrays instead of a joined
      string.
    - Changed: Resolved folder paths are cached, so a deep tree no longer re-walks
      every ancestor for each folder.
    - New: Verification compares the source and target folder structures and lists
      folders that are missing from the target.

    Changelog v1.14:
    - Changed: The GUI is resizable (including maximize). Controls stay docked in a
      table layout so they are not clipped or lost, long labels wrap instead of
      cutting off, and the status log fills leftover space. A minimum window size
      keeps the form usable when shrunk.

    Changelog v1.13:
    - Fixed: Calendar copy aborted after the first item with
      Could not compare "1" to "System.Collections.Hashtable". The batch loop and
      the event's Graph end time both used $end, so after item 1 the for-loop
      compared the next index to a hashtable. Those are now separate variables.

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

# Set when a folder listing fails, so the run cannot claim a complete copy.
$script:FolderScanIncomplete = $false

# Well-known folder names are resolved on the TARGET so a localized or renamed
# mailbox does not end up with a duplicate "Inbox" / "Sent Items".
$script:WellKnownFolderNames = @(
    'inbox', 'drafts', 'sentitems', 'deleteditems', 'junkemail',
    'outbox', 'archive', 'conversationhistory', 'clutter', 'scheduled'
)

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

# ------------------------------------------------------------------------------
# Live status, progress and ETA
#
# The copy runs on the UI thread, so everything here is deliberately cheap and
# repaints are throttled: the point is to show where the run is without slowing
# it down. Every function is a no-op until Initialize-CopyUi has run, which
# keeps the folder logic callable from tests with no UI at all.
# ------------------------------------------------------------------------------
$script:Ui   = $null
$script:Prog = $null

# Single source of "now" for the progress engine, so the ETA maths can be
# exercised against a controlled clock instead of the wall clock.
function Get-CopyClockNow {
    return (Get-Date)
}

function Initialize-CopyUi {
    param(
        [System.Windows.Forms.TextBox]$StatusBox,
        [System.Windows.Forms.ProgressBar]$ProgressBar,
        [System.Windows.Forms.Label]$PhaseLabel,
        [System.Windows.Forms.Label]$EtaLabel
    )

    $script:Ui = @{
        StatusBox   = $StatusBox
        ProgressBar = $ProgressBar
        PhaseLabel  = $PhaseLabel
        EtaLabel    = $EtaLabel
    }
    $now = Get-CopyClockNow
    $script:Prog = @{
        OverallStart  = $now
        PhaseName     = ''
        PhaseStart    = $now
        Detail        = ''
        Total         = 0.0
        Done          = 0.0
        Copied        = 0
        Skipped       = 0
        Failed        = 0
        Indeterminate = $true
        Samples       = New-Object System.Collections.ArrayList
        LastPaint     = [datetime]::MinValue
    }
}

function Write-CopyLog {
    param([string]$Message, [switch]$NoNewline)

    if (-not $script:Ui -or -not $script:Ui.StatusBox) {
        Write-Host $Message
        return
    }
    if ($NoNewline) { $script:Ui.StatusBox.AppendText($Message) }
    else            { $script:Ui.StatusBox.AppendText("$Message`r`n") }
    Update-CopyUi -StatusBox $script:Ui.StatusBox
}

function Format-CopyDuration {
    param([double]$Seconds)

    if ($Seconds -lt 0 -or [double]::IsNaN($Seconds) -or [double]::IsInfinity($Seconds)) { return '--' }
    # Floor, not [int]: a cast rounds, which turns 90 seconds into "2m 30s".
    $span = [timespan]::FromSeconds([math]::Round($Seconds))
    if ($span.TotalDays -ge 1) { return ('{0}d {1:00}h {2:00}m' -f [math]::Floor($span.TotalDays), $span.Hours, $span.Minutes) }
    if ($span.TotalHours -ge 1) { return ('{0}h {1:00}m {2:00}s' -f [math]::Floor($span.TotalHours), $span.Minutes, $span.Seconds) }
    if ($span.TotalMinutes -ge 1) { return ('{0}m {1:00}s' -f [math]::Floor($span.TotalMinutes), $span.Seconds) }
    return ('{0}s' -f [math]::Floor($span.TotalSeconds))
}

function Start-CopyPhase {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [double]$Total = 0,
        [string]$Detail = '',
        [switch]$Indeterminate
    )

    if (-not $script:Prog) { return }

    $script:Prog.PhaseName     = $Name
    $script:Prog.PhaseStart    = Get-CopyClockNow
    $script:Prog.Detail        = $Detail
    $script:Prog.Total         = [double]$Total
    $script:Prog.Done          = 0.0
    $script:Prog.Copied        = 0
    $script:Prog.Skipped       = 0
    $script:Prog.Failed        = 0
    $script:Prog.Indeterminate = [bool]$Indeterminate -or ($Total -le 0)
    $script:Prog.Samples.Clear()
    Update-CopyStatusDisplay -Force
}

function Set-CopyPhaseTotal {
    param([double]$Total)

    if (-not $script:Prog) { return }
    $script:Prog.Total = [double]$Total
    $script:Prog.Indeterminate = ($Total -le 0)
    Update-CopyStatusDisplay -Force
}

function Set-CopyDetail {
    param([string]$Detail, [switch]$Force)

    if (-not $script:Prog) { return }
    $script:Prog.Detail = $Detail
    Update-CopyStatusDisplay -Force:$Force
}

function Add-CopyWork {
    param(
        [double]$Done = 0,
        [int]$Copied = 0,
        [int]$Skipped = 0,
        [int]$Failed = 0,
        [string]$Detail
    )

    if (-not $script:Prog) { return }
    $script:Prog.Done    += $Done
    $script:Prog.Copied  += $Copied
    $script:Prog.Skipped += $Skipped
    $script:Prog.Failed  += $Failed
    if ($PSBoundParameters.ContainsKey('Detail')) { $script:Prog.Detail = $Detail }
    Update-CopyStatusDisplay
}

<#
.SYNOPSIS
    Items per second for the current phase.

.DESCRIPTION
    Uses the throughput over the last couple of minutes once there is enough of
    a window for it to mean anything, because Graph throttling makes the average
    since the phase started a poor predictor. Falls back to that average early on.
#>
function Get-CopyRate {
    if (-not $script:Prog) { return 0 }

    $now     = Get-CopyClockNow
    $elapsed = ($now - $script:Prog.PhaseStart).TotalSeconds
    $overall = 0
    if ($elapsed -gt 0) { $overall = $script:Prog.Done / $elapsed }

    $samples = $script:Prog.Samples
    if ($samples.Count -ge 2) {
        $first = $samples[0]
        $span  = ($now - $first.Time).TotalSeconds
        if ($span -ge 15) {
            $windowed = ($script:Prog.Done - $first.Done) / $span
            if ($windowed -gt 0) { return $windowed }
        }
    }
    return $overall
}

function Update-CopyStatusDisplay {
    param([switch]$Force)

    if (-not $script:Prog -or -not $script:Ui) { return }

    $now = Get-CopyClockNow
    if (-not $Force -and ($now - $script:Prog.LastPaint).TotalMilliseconds -lt 250) { return }
    $script:Prog.LastPaint = $now

    # Keep a ~2 minute trailing window of (time, done) for the rate estimate.
    $samples = $script:Prog.Samples
    [void]$samples.Add([pscustomobject]@{ Time = $now; Done = $script:Prog.Done })
    while ($samples.Count -gt 2 -and ($now - $samples[0].Time).TotalSeconds -gt 120) {
        $samples.RemoveAt(0)
    }

    $phaseElapsed   = ($now - $script:Prog.PhaseStart).TotalSeconds
    $overallElapsed = ($now - $script:Prog.OverallStart).TotalSeconds

    if ($script:Prog.Indeterminate) {
        $position = ''
        if ($script:Prog.Done -gt 0) { $position = ('{0:N0} so far' -f $script:Prog.Done) }
        $etaText = ('Elapsed {0}   |   working...' -f (Format-CopyDuration $overallElapsed))
    }
    else {
        $total = $script:Prog.Total
        $done  = $script:Prog.Done
        if ($done -gt $total) { $done = $total }
        $pct = 0
        if ($total -gt 0) { $pct = [int](($done / $total) * 100) }
        if ($pct -lt 0)   { $pct = 0 }
        if ($pct -gt 100) { $pct = 100 }
        $position = ('{0:N0} / {1:N0}  ({2}%)' -f $done, $total, $pct)

        $rate      = Get-CopyRate
        $remaining = $total - $done
        $etaText   = ''
        if ($rate -gt 0 -and $remaining -gt 0) {
            $secondsLeft = $remaining / $rate
            $finishAt    = $now.AddSeconds($secondsLeft)
            $etaText = ('Elapsed {0}   |   remaining ~{1}   |   done by {2}   |   {3}' -f `
                (Format-CopyDuration $overallElapsed),
                (Format-CopyDuration $secondsLeft),
                $finishAt.ToString('HH:mm'),
                (Format-CopyRateText $rate))
        }
        elseif ($remaining -le 0) {
            $etaText = ('Elapsed {0}   |   phase complete in {1}' -f `
                (Format-CopyDuration $overallElapsed), (Format-CopyDuration $phaseElapsed))
        }
        else {
            $etaText = ('Elapsed {0}   |   estimating...' -f (Format-CopyDuration $overallElapsed))
        }

        if ($script:Prog.Copied -gt 0 -or $script:Prog.Skipped -gt 0 -or $script:Prog.Failed -gt 0) {
            $etaText += ('   |   copied {0:N0}, skipped {1:N0}, failed {2:N0}' -f `
                $script:Prog.Copied, $script:Prog.Skipped, $script:Prog.Failed)
        }

        if ($script:Ui.ProgressBar) {
            try {
                if ($script:Ui.ProgressBar.Style -ne [System.Windows.Forms.ProgressBarStyle]::Continuous) {
                    $script:Ui.ProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
                }
                $script:Ui.ProgressBar.Value = $pct
            }
            catch { }
        }
    }

    if ($script:Prog.Indeterminate -and $script:Ui.ProgressBar) {
        try {
            if ($script:Ui.ProgressBar.Style -ne [System.Windows.Forms.ProgressBarStyle]::Marquee) {
                $script:Ui.ProgressBar.MarqueeAnimationSpeed = 30
                $script:Ui.ProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
            }
        }
        catch { }
    }

    $phaseText = $script:Prog.PhaseName
    if ($script:Prog.Detail)  { $phaseText += "  -  $($script:Prog.Detail)" }
    if ($position)            { $phaseText += "  -  $position" }

    if ($script:Ui.PhaseLabel) {
        try { $script:Ui.PhaseLabel.Text = $phaseText } catch { }
    }
    if ($script:Ui.EtaLabel) {
        try { $script:Ui.EtaLabel.Text = $etaText } catch { }
    }

    Update-CopyUi -StatusBox $script:Ui.StatusBox -ProgressBar $script:Ui.ProgressBar
}

function Format-CopyRateText {
    param([double]$Rate)

    if ($Rate -ge 1) { return ('{0:N1} items/s' -f $Rate) }
    if ($Rate -gt 0) { return ('{0:N1} items/min' -f ($Rate * 60)) }
    return 'rate unknown'
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
        foreach ($it in (Get-GraphItemList $pageItems)) {
            [void]$items.Add($it)
        }
        # Paging goes to the live status line rather than the log: a 16k-item
        # folder would otherwise bury everything else under page counters.
        if ($ProgressPrefix) {
            $of = if ($ExpectedCount -gt 0) { " of $ExpectedCount" } else { '' }
            Set-CopyDetail -Detail "$ProgressPrefix - page $page, $($items.Count)$of retrieved"
        }
        elseif ($StatusBox) {
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
function Get-WellKnownFolderMap {
    param([string]$UserId)

    $map = @{}
    foreach ($name in $script:WellKnownFolderNames) {
        $id = Get-WellKnownFolderId -UserId $UserId -WellKnownName $name
        if ($id -and -not $map.ContainsKey($id)) { $map[$id] = $name }
    }
    return $map
}

function Get-FolderPathKey {
    param([string[]]$PathParts)
    # [char]1 cannot appear in an Exchange folder name, so it is a safe separator
    # for cache keys; '\' is not, because a display name may contain one.
    return (@($PathParts) -join ([string][char]1))
}

function Get-AllMailFolders {
    param(
        [string]$UserId,
        [string]$ParentFolderId = $null,
        [string[]]$ParentPath = @(),
        [hashtable]$WellKnownMap = @{},
        [string]$RootWellKnownName = $null,
        [System.Windows.Forms.TextBox]$StatusBox
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
    }
    catch {
        # A dropped listing means part of the mailbox is invisible to the copy.
        # Write-Host alone hid this: the GUI showed nothing and the run still
        # reported success.
        $script:FolderScanIncomplete = $true
        $where = 'mailbox root'
        if ($ParentPath.Count -gt 0) { $where = ($ParentPath -join '\') }
        $message = "  WARNING: could not list child folders of '$where': $($_.Exception.Message)"
        Write-Host $message
        if ($StatusBox) {
            $StatusBox.AppendText("$message`r`n")
            $StatusBox.AppendText("  WARNING: that subtree will NOT be copied.`r`n")
            Update-CopyUi -StatusBox $StatusBox
        }
        return $allFolders
    }

    foreach ($folder in $folders) {
        $pathParts = @($ParentPath) + @($folder.DisplayName)

        $wellKnown = $null
        if ($WellKnownMap.ContainsKey($folder.Id)) { $wellKnown = $WellKnownMap[$folder.Id] }

        # The well-known name of the top-level ancestor travels down the tree, so
        # 'Inbox\Clients' and 'Postvak IN\Clients' can be recognised as the same
        # folder in two mailboxes with different display languages.
        $rootWellKnown = $RootWellKnownName
        if ($ParentPath.Count -eq 0) { $rootWellKnown = $wellKnown }

        $allFolders += [PSCustomObject]@{
            Id                = $folder.Id
            DisplayName       = $folder.DisplayName
            PathParts         = $pathParts
            FullPath          = ($pathParts -join '\')
            WellKnownName     = $wellKnown
            RootWellKnownName = $rootWellKnown
            TotalItemCount    = $folder.TotalItemCount
            UnreadItemCount   = $folder.UnreadItemCount
            ChildFolderCount  = $folder.ChildFolderCount
        }

        Add-CopyWork -Done 1 -Detail ($pathParts -join '\')

        if ($folder.ChildFolderCount -gt 0) {
            $allFolders += Get-AllMailFolders -UserId $UserId -ParentFolderId $folder.Id `
                -ParentPath $pathParts -WellKnownMap $WellKnownMap `
                -RootWellKnownName $rootWellKnown -StatusBox $StatusBox
        }
    }

    return $allFolders
}

<#
.SYNOPSIS
    Path of a folder in a form that can be compared across two mailboxes.

.DESCRIPTION
    A well-known root is represented by its well-known name instead of its
    display name, so the source Inbox matches the target Inbox even when the two
    mailboxes are in different display languages or a folder has been renamed.
#>
function Get-CanonicalFolderParts {
    param($Folder)

    $segments = @($Folder.PathParts)
    if ($segments.Count -eq 0) { return @() }

    $root = $segments[0]
    if ($Folder.RootWellKnownName) { $root = "wellknown:$($Folder.RootWellKnownName)" }

    $parts = @($root)
    if ($segments.Count -gt 1) { $parts += $segments[1..($segments.Count - 1)] }
    return $parts
}

function Get-CanonicalFolderKey {
    param($Folder)
    return (Get-FolderPathKey -PathParts (Get-CanonicalFolderParts -Folder $Folder))
}

function New-MailFolderIndex {
    param($Folders)

    $index = @{}
    foreach ($folder in @($Folders)) {
        $key = Get-CanonicalFolderKey -Folder $folder
        if (-not $index.ContainsKey($key)) { $index[$key] = $folder.Id }
    }
    return $index
}

function Get-IndexedFolderId {
    param([hashtable]$Index, $Folder)

    $key = Get-CanonicalFolderKey -Folder $Folder
    if ($Index.ContainsKey($key)) { return $Index[$key] }
    return $null
}

<#
.SYNOPSIS
    Diffs the source folder tree against the target folder tree.

.OUTPUTS
    Hashtable with TargetIndex (canonical path -> target folder id), Present and
    Missing (source folder objects) and TargetOnly (folders the target has that
    the source does not; these are reported but never touched).
#>
function Compare-MailFolderStructure {
    param($SourceFolders, $TargetFolders)

    $targetIndex = New-MailFolderIndex -Folders $TargetFolders
    $sourceKeys  = @{}
    $present     = New-Object System.Collections.ArrayList
    $missing     = New-Object System.Collections.ArrayList

    foreach ($folder in @($SourceFolders)) {
        $key = Get-CanonicalFolderKey -Folder $folder
        $sourceKeys[$key] = $true
        if ($targetIndex.ContainsKey($key)) { [void]$present.Add($folder) }
        else                                { [void]$missing.Add($folder) }
    }

    $targetOnly = New-Object System.Collections.ArrayList
    foreach ($folder in @($TargetFolders)) {
        if (-not $sourceKeys.ContainsKey((Get-CanonicalFolderKey -Folder $folder))) {
            [void]$targetOnly.Add($folder)
        }
    }

    return @{
        TargetIndex = $targetIndex
        Present     = $present
        Missing     = $missing
        TargetOnly  = $targetOnly
    }
}

function Find-ChildFolderByName {
    param(
        [string]$UserId,
        [string]$ParentId,
        [string]$Name
    )

    # An OData string literal escapes a single quote by doubling it. Without this,
    # "O'Brien Ltd" produces a 400 and the folder looks like it does not exist.
    $escaped = $Name.Replace("'", "''")
    $filter  = "displayName eq '$escaped'"

    try {
        if ($ParentId) {
            $hit = Invoke-WithRetry -ScriptBlock {
                Get-MgUserMailFolderChildFolder -UserId $UserId -MailFolderId $ParentId `
                    -Filter $filter -ErrorAction Stop |
                    Select-Object -First 1
            }
        }
        else {
            $hit = Invoke-WithRetry -ScriptBlock {
                Get-MgUserMailFolder -UserId $UserId -Filter $filter -ErrorAction Stop |
                    Select-Object -First 1
            }
        }
        if ($hit) { return $hit }
    }
    catch {
        # Fall through to a client-side match: a lookup that errors out must never
        # be read as "the folder is not there", or a duplicate gets created.
    }

    if ($ParentId) {
        $all = Invoke-GraphPagedRequest -CommandBlock {
            Get-MgUserMailFolderChildFolder -UserId $UserId -MailFolderId $ParentId -All
        }
    }
    else {
        $all = Invoke-GraphPagedRequest -CommandBlock {
            Get-MgUserMailFolder -UserId $UserId -All
        }
    }
    return (@($all) | Where-Object { $_.DisplayName -eq $Name } | Select-Object -First 1)
}

<#
.SYNOPSIS
    Creates one folder in the target mailbox, tolerating a stale index.

.DESCRIPTION
    ErrorFolderExists means the folder is already there but was not in the index
    we compared against - a display name that collides with a well-known folder,
    or another client creating it. Either way the existing folder is adopted
    rather than reported as a failure.

.OUTPUTS
    Hashtable with Folder and Adopted ($true when an existing folder was reused).
#>
function New-TargetMailFolder {
    param(
        [string]$TargetUserId,
        [string]$ParentFolderId,
        [string]$DisplayName
    )

    $newFolderParams = @{ DisplayName = $DisplayName }
    $folder  = $null
    $adopted = $false

    try {
        if ($ParentFolderId) {
            $folder = Invoke-WithRetry -ScriptBlock {
                New-MgUserMailFolderChildFolder -UserId $TargetUserId -MailFolderId $ParentFolderId `
                    -BodyParameter $newFolderParams -ErrorAction Stop
            }
        }
        else {
            $folder = Invoke-WithRetry -ScriptBlock {
                New-MgUserMailFolder -UserId $TargetUserId -BodyParameter $newFolderParams -ErrorAction Stop
            }
        }
    }
    catch {
        if ("$($_.Exception.Message)" -match 'ErrorFolderExists|already exists') {
            $folder  = Find-ChildFolderByName -UserId $TargetUserId -ParentId $ParentFolderId -Name $DisplayName
            $adopted = [bool]$folder
        }
        if (-not $folder) {
            throw "Could not create folder '$DisplayName': $(Get-CopyErrorDetail $_)"
        }
    }

    if (-not $folder -or -not $folder.Id) {
        throw "Could not create folder '$DisplayName' (Graph returned no folder id)."
    }
    return @{ Folder = $folder; Adopted = $adopted }
}

<#
.SYNOPSIS
    Brings the target folder tree in line with the source by adding only what is
    missing. Nothing in the target is renamed, moved or deleted.

.DESCRIPTION
    Both trees are enumerated once and diffed, so a folder that already exists in
    the target costs no extra Graph calls. Missing folders are created in the
    source's own depth-first order, which guarantees a parent exists before its
    children. When a folder cannot be created its whole subtree is marked
    unavailable, so the caller skips that mail instead of filing it elsewhere.

.OUTPUTS
    Hashtable with Index (canonical path -> target folder id), Comparison,
    Created, Failed, Unavailable and Cancelled.
#>
function Sync-MailFolderStructure {
    param(
        [string]$TargetUserId,
        $SourceFolders,
        $TargetFolders,
        [System.Windows.Forms.TextBox]$StatusBox
    )

    $comparison  = Compare-MailFolderStructure -SourceFolders $SourceFolders -TargetFolders $TargetFolders
    $index       = $comparison.TargetIndex
    $unavailable = @{}
    $created     = 0
    $adopted     = 0
    $failed      = 0
    $cancelled   = $false

    $missing = @($comparison.Missing)
    Start-CopyPhase -Name 'Creating missing folders' -Total $missing.Count

    foreach ($folder in $missing) {
        if ($script:CancelRequested) { $cancelled = $true; break }

        $parts = Get-CanonicalFolderParts -Folder $folder
        $key   = Get-FolderPathKey -PathParts $parts

        if ($index.ContainsKey($key)) {
            Add-CopyWork -Done 1
            continue
        }

        $parentId  = $null
        $parentKey = $null
        if ($parts.Count -gt 1) {
            $parentKey = Get-FolderPathKey -PathParts @($parts[0..($parts.Count - 2)])
            if ($unavailable.ContainsKey($parentKey)) {
                $unavailable[$key] = "parent folder is unavailable"
                $failed++
                Add-CopyWork -Done 1
                continue
            }
            if (-not $index.ContainsKey($parentKey)) {
                $unavailable[$key] = "parent folder was never created"
                $failed++
                Write-CopyLog "  ERROR: cannot create '$($folder.FullPath)': its parent folder is missing from the target."
                Add-CopyWork -Done 1
                continue
            }
            $parentId = $index[$parentKey]
        }

        Set-CopyDetail -Detail $folder.FullPath
        try {
            $result = New-TargetMailFolder -TargetUserId $TargetUserId -ParentFolderId $parentId `
                -DisplayName $folder.DisplayName
            $index[$key] = $result.Folder.Id
            if ($result.Adopted) {
                $adopted++
                Write-CopyLog "  = reused existing: $($folder.FullPath)"
            }
            else {
                $created++
                Write-CopyLog "  + created: $($folder.FullPath)"
            }
        }
        catch {
            $unavailable[$key] = "$($_.Exception.Message)"
            $failed++
            Write-CopyLog "  ERROR creating '$($folder.FullPath)': $($_.Exception.Message)"
        }
        Add-CopyWork -Done 1
    }

    return @{
        Index       = $index
        Comparison  = $comparison
        Created     = $created
        Adopted     = $adopted
        Failed      = $failed
        Unavailable = $unavailable
        Cancelled   = $cancelled
    }
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
        Write-CopyLog ''
        Write-CopyLog '=== STARTING EMAIL COPY ==='

        $script:FolderScanIncomplete = $false

        Start-CopyPhase -Name "Scanning source folders ($SourceEmail)" -Indeterminate
        $sourceWellKnown = Get-WellKnownFolderMap -UserId $SourceEmail
        $sourceFolders   = @(Get-AllMailFolders -UserId $SourceEmail -WellKnownMap $sourceWellKnown -StatusBox $StatusBox)
        Write-CopyLog "Source: $($sourceFolders.Count) folders, $('{0:N0}' -f (($sourceFolders | Measure-Object -Property TotalItemCount -Sum).Sum)) messages."

        if ($script:CancelRequested) {
            Write-CopyLog ''
            Write-CopyLog '*** COPY CANCELLED BY USER ***'
            return @{ Success = $true; Copied = 0; Failed = 0; Folders = 0; Skipped = 0; Cancelled = $true }
        }

        Start-CopyPhase -Name "Scanning target folders ($TargetEmail)" -Indeterminate
        $targetWellKnown = Get-WellKnownFolderMap -UserId $TargetEmail
        $targetFolders   = @(Get-AllMailFolders -UserId $TargetEmail -WellKnownMap $targetWellKnown -StatusBox $StatusBox)
        Write-CopyLog "Target: $($targetFolders.Count) folders already present."

        if ($script:CancelRequested) {
            Write-CopyLog ''
            Write-CopyLog '*** COPY CANCELLED BY USER ***'
            return @{ Success = $true; Copied = 0; Failed = 0; Folders = 0; Skipped = 0; Cancelled = $true }
        }

        # Compare the two trees first and add only what the target is missing.
        # Folders the target already has are reused as they are, and folders it
        # has that the source does not are listed but never touched.
        Start-CopyPhase -Name 'Comparing folder structures' -Indeterminate
        $sync = Sync-MailFolderStructure -TargetUserId $TargetEmail -SourceFolders $sourceFolders `
            -TargetFolders $targetFolders -StatusBox $StatusBox
        $folderIndex = $sync.Index

        Write-CopyLog ''
        Write-CopyLog '--- FOLDER STRUCTURE COMPARISON ---'
        Write-CopyLog "  Source folders            : $($sourceFolders.Count)"
        Write-CopyLog "  Already present in target : $($sync.Comparison.Present.Count)"
        Write-CopyLog "  Missing from target       : $($sync.Comparison.Missing.Count)"
        Write-CopyLog "  Created now               : $($sync.Created)"
        if ($sync.Adopted -gt 0) {
            Write-CopyLog "  Matched by name instead   : $($sync.Adopted)"
        }
        if ($sync.Failed -gt 0) {
            Write-CopyLog "  Could NOT be created      : $($sync.Failed)"
        }
        if ($sync.Comparison.TargetOnly.Count -gt 0) {
            Write-CopyLog "  Extra folders in target   : $($sync.Comparison.TargetOnly.Count) (left untouched)"
            $shown = 0
            foreach ($extra in $sync.Comparison.TargetOnly) {
                if ($shown -ge 10) {
                    Write-CopyLog "      ... and $($sync.Comparison.TargetOnly.Count - $shown) more"
                    break
                }
                Write-CopyLog "      $($extra.FullPath)"
                $shown++
            }
        }
        Write-CopyLog ''

        if ($sync.Cancelled -or $script:CancelRequested) {
            Write-CopyLog '*** COPY CANCELLED BY USER ***'
            return @{ Success = $true; Copied = 0; Failed = 0; Folders = 0; Skipped = 0; Cancelled = $true }
        }

        $totalMessages = ($sourceFolders | Measure-Object -Property TotalItemCount -Sum).Sum
        if ($totalMessages -eq 0) {
            Write-CopyLog 'No emails found in source mailbox; folder structure is in sync.'
            return @{ Success = $true; Copied = 0; Failed = 0; Folders = 0; Skipped = 0; Cancelled = $false }
        }

        $foldersWithMail = @($sourceFolders | Where-Object { $_.TotalItemCount -gt 0 })
        Write-CopyLog "Copying $('{0:N0}' -f $totalMessages) messages from $($foldersWithMail.Count) folders..."
        Start-CopyPhase -Name 'Copying email' -Total $totalMessages
        $mailPhaseStart = Get-Date

        $sentItemsId = Get-WellKnownFolderId -UserId $SourceEmail -WellKnownName 'sentitems'
        $draftsId    = Get-WellKnownFolderId -UserId $SourceEmail -WellKnownName 'drafts'

        $totalCopied     = 0
        $totalFailed     = 0
        $totalSkipped    = 0
        $foldersCopied   = 0
        $folderNumber    = 0

        foreach ($sourceFolder in $sourceFolders) {
            if ($sourceFolder.TotalItemCount -eq 0) { continue }

            $folderNumber++
            $folderPosition = "folder $folderNumber/$($foldersWithMail.Count) '$($sourceFolder.FullPath)'"
            Write-CopyLog "--- $folderPosition : $('{0:N0}' -f $sourceFolder.TotalItemCount) messages ---"
            Set-CopyDetail -Detail "$folderPosition - starting" -Force

            $targetFolderId = Get-IndexedFolderId -Index $folderIndex -Folder $sourceFolder
            if (-not $targetFolderId) {
                # Posting to /users/{id}/messages instead would silently file these
                # messages as drafts in the target mailbox.
                Write-CopyLog "  SKIPPED: no target folder, $($sourceFolder.TotalItemCount) messages not copied."
                Write-CopyLog ''
                $totalFailed += $sourceFolder.TotalItemCount
                Add-CopyWork -Done $sourceFolder.TotalItemCount -Failed $sourceFolder.TotalItemCount
                continue
            }

            $headerSelect = 'id,subject,from,receivedDateTime,sentDateTime,isRead,isDraft,hasAttachments,importance'

            $targetMessages = @{}
            try {
                Set-CopyDetail -Detail "$folderPosition - indexing destination" -Force
                $existingUri = New-FolderMessagesListUri -UserId $TargetEmail -FolderId $targetFolderId -Select $headerSelect
                $existingMessages = Get-GraphCollection -Uri $existingUri -StatusBox $StatusBox `
                    -ProgressPrefix "$folderPosition - indexing destination" -ExpectedCount 0
                foreach ($msg in $existingMessages) {
                    if ($script:CancelRequested) {
                        Write-CopyLog ''
                        Write-CopyLog '*** COPY CANCELLED BY USER ***'
                        return @{ Copied = $totalCopied; Skipped = $totalSkipped; Failed = $totalFailed; Cancelled = $true }
                    }
                    $targetMessages[(Get-MessageDedupeKey -Message $msg)] = $true
                }
                Write-CopyLog "  destination already holds $($targetMessages.Count) messages"
            }
            catch {
                Write-CopyLog "  Could not retrieve existing messages: $($_.Exception.Message)"
            }

            try {
                $folderCopied  = 0
                $folderFailed  = 0
                $folderSkipped = 0

                Set-CopyDetail -Detail "$folderPosition - listing source" -Force
                $sourceUri = New-FolderMessagesListUri -UserId $SourceEmail -FolderId $sourceFolder.Id -Select $headerSelect
                $sourceMessages = Get-GraphCollection -Uri $sourceUri -StatusBox $StatusBox `
                    -ProgressPrefix "$folderPosition - listing source" -ExpectedCount ([int]$sourceFolder.TotalItemCount)

                if ($script:CancelRequested) {
                    Write-CopyLog ''
                    Write-CopyLog '*** COPY CANCELLED BY USER ***'
                    return @{ Copied = $totalCopied; Skipped = $totalSkipped; Failed = $totalFailed; Cancelled = $true }
                }

                # TotalItemCount can disagree with what the folder actually returns
                # (hidden associated items, mail arriving mid-run). Correct the
                # overall total so the percentage and ETA stay honest.
                $listed = $sourceMessages.Count
                if ($listed -ne [int]$sourceFolder.TotalItemCount) {
                    $totalMessages = $totalMessages - [int]$sourceFolder.TotalItemCount + $listed
                    Set-CopyPhaseTotal -Total $totalMessages
                }

                $batchSize   = 100
                $batchNumber = 0
                $isSentFolder  = ($sentItemsId -and $sourceFolder.Id -eq $sentItemsId)
                $isDraftFolder = ($draftsId -and $sourceFolder.Id -eq $draftsId)

                for ($i = 0; $i -lt $sourceMessages.Count; $i += $batchSize) {
                    if ($script:CancelRequested) {
                        Write-CopyLog ''
                        Write-CopyLog '*** COPY CANCELLED BY USER ***'
                        return @{ Copied = $totalCopied; Skipped = $totalSkipped; Failed = $totalFailed; Cancelled = $true }
                    }

                    $batchNumber++
                    $batchEnd = $i + $batchSize
                    if ($batchEnd -gt $sourceMessages.Count) { $batchEnd = $sourceMessages.Count }
                    $batchEnd = $batchEnd - 1
                    $batchCount = ($batchEnd - $i) + 1

                    for ($j = $i; $j -le $batchEnd; $j++) {
                        if ($script:CancelRequested) {
                            Write-CopyLog ''
                            Write-CopyLog '*** COPY CANCELLED BY USER ***'
                            return @{ Copied = $totalCopied; Skipped = $totalSkipped; Failed = $totalFailed; Cancelled = $true }
                        }

                        $summary    = $sourceMessages[$j]
                        $messageKey = Get-MessageDedupeKey -Message $summary

                        Set-CopyDetail -Detail ("{0} - message {1:N0}/{2:N0}" -f $folderPosition, ($j + 1), $sourceMessages.Count)

                        if ($targetMessages.ContainsKey($messageKey)) {
                            $folderSkipped++; $totalSkipped++
                            Add-CopyWork -Done 1 -Skipped 1
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
                            $fEnc      = [uri]::EscapeDataString($targetFolderId)
                            $createUri = "$script:GraphBase/users/$uEnc/mailFolders/$fEnc/messages"

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
                            Add-CopyWork -Done 1 -Copied 1
                        }
                        catch {
                            $folderFailed++; $totalFailed++
                            Add-CopyWork -Done 1 -Failed 1
                            if ($folderFailed -le 8) {
                                $failSubj = Get-GraphProperty -Object $summary -Names @('subject', 'Subject')
                                Write-CopyLog "    Failed '$failSubj': $(Get-CopyErrorDetail $_ )"
                            }
                        }
                    }

                    Write-CopyLog ("  batch {0} of {1} done ({2:N0} copied, {3:N0} skipped, {4:N0} failed so far in this folder)" -f `
                        $batchNumber, [math]::Ceiling($sourceMessages.Count / $batchSize), $folderCopied, $folderSkipped, $folderFailed)
                }

                Write-CopyLog "  '$($sourceFolder.FullPath)' done: $folderCopied copied, $folderSkipped duplicates skipped, $folderFailed failed"
                Write-CopyLog ''
                $foldersCopied++
            }
            catch {
                Write-CopyLog "  Error processing folder: $($_.Exception.Message)"
                Write-CopyLog ''
            }
        }

        Set-CopyDetail -Detail 'email copy finished' -Force
        Write-CopyLog ''
        Write-CopyLog '=== EMAIL COPY COMPLETED ==='
        Write-CopyLog "Folders created    : $($sync.Created) (of $($sync.Comparison.Missing.Count) missing)"
        Write-CopyLog "Folders processed  : $foldersCopied / $($foldersWithMail.Count) with mail"
        Write-CopyLog "New messages copied: $('{0:N0}' -f $totalCopied)"
        Write-CopyLog "Duplicates skipped : $('{0:N0}' -f $totalSkipped)"
        Write-CopyLog "Failed             : $('{0:N0}' -f $totalFailed)"
        Write-CopyLog "Email phase took   : $(Format-CopyDuration ((Get-Date) - $mailPhaseStart).TotalSeconds)"

        return @{
            Success        = $true
            Copied         = $totalCopied
            Failed         = $totalFailed
            Folders        = $foldersCopied
            Skipped        = $totalSkipped
            Cancelled      = $false
            FoldersCreated = $sync.Created
            FoldersExisted = $sync.Comparison.Present.Count
            FoldersMissing = $sync.Comparison.Missing.Count
            FoldersFailed  = $sync.Failed
        }
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
        Write-CopyLog ''
        Write-CopyLog '=== STARTING CALENDAR COPY ==='
        Write-CopyLog 'Attendees will be copied silently (no invitation emails).'
        Write-CopyLog 'Teams meetings keep the original join link (no new meeting is created).'

        Start-CopyPhase -Name 'Reading source calendar' -Detail $SourceEmail -Indeterminate

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
            Write-CopyLog "ERROR: Could not find calendar for $SourceEmail"
            return @{ Copied = 0; Skipped = 0; Failed = 0; Cancelled = $false }
        }

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
            $events = Get-GraphCollection -Uri $eventUri -StatusBox $StatusBox -ProgressPrefix 'Reading source calendar'
        }
        catch {
            Write-CopyLog "  Full property select failed ($($_.Exception.Message)); retrying with a reduced set..."
            $reducedSelect = 'id,subject,start,end,isAllDay,body,location,attendees,recurrence,showAs,importance,sensitivity,isReminderOn,reminderMinutesBeforeStart,isOnlineMeeting,onlineMeeting,onlineMeetingUrl,organizer,type,isCancelled,categories'
            $eventUri = "$script:GraphBase/users/$srcCalEnc/calendars/$srcCalIdEnc/events?`$top=50&`$select=$reducedSelect"
            $events = Get-GraphCollection -Uri $eventUri -StatusBox $StatusBox -ProgressPrefix 'Reading source calendar (reduced)'
        }
        $totalEvents = $events.Count

        Write-CopyLog "Source calendar holds $('{0:N0}' -f $totalEvents) items."

        if ($script:CancelRequested) {
            Write-CopyLog ''
            Write-CopyLog '*** COPY CANCELLED BY USER ***'
            return @{ Copied = 0; Skipped = 0; Failed = 0; Cancelled = $true }
        }

        if ($totalEvents -eq 0) {
            Write-CopyLog 'No calendar items to copy.'
            return @{ Copied = 0; Skipped = 0; Failed = 0; Cancelled = $false }
        }

        Start-CopyPhase -Name 'Indexing target calendar' -Detail $TargetEmail -Indeterminate

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
            Write-CopyLog "ERROR: Could not find calendar for $TargetEmail"
            return @{ Copied = 0; Skipped = 0; Failed = 0; Cancelled = $false }
        }

        $tgtCalEnc = [uri]::EscapeDataString($TargetEmail)
        $tgtCalIdEnc = [uri]::EscapeDataString($targetCalendar.Id)
        $targetIndexUri = "$script:GraphBase/users/$tgtCalEnc/calendars/$tgtCalIdEnc/events?`$top=100&`$select=subject,start"
        $targetCalendarItems = Get-GraphCollection -Uri $targetIndexUri -StatusBox $StatusBox -ProgressPrefix 'Indexing target calendar'

        Write-CopyLog "Target calendar already holds $('{0:N0}' -f $targetCalendarItems.Count) items."

        $targetEvents = @{}
        foreach ($te in $targetCalendarItems) {
            if ($script:CancelRequested) {
                Write-CopyLog ''
                Write-CopyLog '*** COPY CANCELLED BY USER ***'
                return @{ Copied = 0; Skipped = 0; Failed = 0; Cancelled = $true }
            }
            $startTime = if ($te.Start.DateTime) { $te.Start.DateTime } else { "nodate" }
            $targetEvents["$($te.Subject)|$startTime"] = $true
        }

        Write-CopyLog "Copying $('{0:N0}' -f $totalEvents) calendar items..."
        Start-CopyPhase -Name 'Copying calendar' -Total $totalEvents
        $calendarPhaseStart = Get-Date

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
                Write-CopyLog ''
                Write-CopyLog '*** COPY CANCELLED BY USER ***'
                return @{ Copied = $copiedCount; Skipped = $skippedCount; Failed = $failedCount; Cancelled = $true }
            }

            $batchNumber++
            $batchEnd = $i + $batchSize
            if ($batchEnd -gt $totalEvents) { $batchEnd = $totalEvents }
            $batchEnd = $batchEnd - 1
            $batchCount = ($batchEnd - $i) + 1

            for ($j = $i; $j -le $batchEnd; $j++) {
                $event = $events[$j]
                if ($script:CancelRequested) {
                    Write-CopyLog ''
                    Write-CopyLog '*** COPY CANCELLED BY USER ***'
                    return @{ Copied = $copiedCount; Skipped = $skippedCount; Failed = $failedCount; Cancelled = $true }
                }

                Set-CopyDetail -Detail ("item {0:N0}/{1:N0}: {2}" -f ($j + 1), $totalEvents, $event.Subject)

                $eventType = (Convert-GraphEnumString -Value $event.Type -Fallback 'singleInstance').ToLowerInvariant()
                if ($eventType -eq 'occurrence') {
                    # Expanded instances of a recurring series. The series master is copied once.
                    $occurrenceSkip++
                    $skippedCount++
                    Add-CopyWork -Done 1 -Skipped 1
                    continue
                }

                $startTime = if ($event.Start.DateTime) { $event.Start.DateTime } else { "nodate" }
                $eventKey  = "$($event.Subject)|$startTime"

                if ($targetEvents.ContainsKey($eventKey)) {
                    $skippedCount++
                    Add-CopyWork -Done 1 -Skipped 1
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

                    $eventStart = Convert-GraphDateTimeTimeZone -DateTimeTimeZone (Get-GraphProperty -Object $event -Names @('start', 'Start'))
                    $eventEnd   = Convert-GraphDateTimeTimeZone -DateTimeTimeZone (Get-GraphProperty -Object $event -Names @('end', 'End'))
                    if (-not $eventStart -or -not $eventEnd) {
                        throw "Event is missing start/end: $($event.Subject)"
                    }

                    $eventBody = @{
                        subject     = $event.Subject
                        body        = $bodyContent
                        start       = $eventStart
                        end         = $eventEnd
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
                                start   = $eventStart
                                end     = $eventEnd
                            }
                            Invoke-GraphJsonPost -Uri $createUri -BodyObject $minimal | Out-Null
                        }
                    }
                    $copiedCount++
                    Add-CopyWork -Done 1 -Copied 1
                }
                catch {
                    $failedCount++
                    Add-CopyWork -Done 1 -Failed 1
                    if ($failedCount -le 8) {
                        Write-CopyLog "    Failed '$($event.Subject)': $(Get-CopyErrorDetail $_ )"
                    }
                }
            }

            Write-CopyLog ("  batch {0} of {1} done ({2:N0} copied, {3:N0} skipped, {4:N0} failed so far)" -f `
                $batchNumber, [math]::Ceiling($totalEvents / $batchSize), $copiedCount, $skippedCount, $failedCount)
        }

        Set-CopyDetail -Detail 'calendar copy finished' -Force
        Write-CopyLog ''
        Write-CopyLog '=== CALENDAR COPY COMPLETED ==='
        Write-CopyLog "New items copied  : $('{0:N0}' -f $copiedCount)"
        Write-CopyLog "Duplicates skipped: $('{0:N0}' -f $skippedCount)"
        if ($occurrenceSkip -gt 0) {
            Write-CopyLog "  (includes $occurrenceSkip recurring occurrences skipped; series masters were copied)"
        }
        Write-CopyLog "Failed            : $('{0:N0}' -f $failedCount)"
        Write-CopyLog "Calendar phase took: $(Format-CopyDuration ((Get-Date) - $calendarPhaseStart).TotalSeconds)"
        Write-CopyLog ''

        return @{ Copied = $copiedCount; Skipped = $skippedCount; Failed = $failedCount; Cancelled = $false }
    }
    catch {
        Write-CopyLog "ERROR during calendar copy: $($_.Exception.Message)"
        return @{ Copied = 0; Skipped = 0; Failed = 0; Cancelled = $false }
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
        Write-CopyLog ''
        Write-CopyLog '--- Verifying Copied Items ---'

        if ($CheckEmails) {
            Start-CopyPhase -Name 'Verifying folder structure' -Indeterminate
            $srcWellKnown = Get-WellKnownFolderMap -UserId $SourceEmail
            $tgtWellKnown = Get-WellKnownFolderMap -UserId $TargetEmail
            $srcFolders = @(Get-AllMailFolders -UserId $SourceEmail -WellKnownMap $srcWellKnown -StatusBox $StatusBox)
            $tgtFolders = @(Get-AllMailFolders -UserId $TargetEmail -WellKnownMap $tgtWellKnown -StatusBox $StatusBox)
            $srcCount = ($srcFolders | Measure-Object -Property TotalItemCount -Sum).Sum
            $tgtCount = ($tgtFolders | Measure-Object -Property TotalItemCount -Sum).Sum
            Write-CopyLog "Source mailbox emails: $('{0:N0}' -f $srcCount)"
            Write-CopyLog "Target mailbox emails: $('{0:N0}' -f $tgtCount)"

            # Item totals alone cannot show a structure problem, so re-run the same
            # comparison the copy used and report anything still missing.
            $check = Compare-MailFolderStructure -SourceFolders $srcFolders -TargetFolders $tgtFolders
            Write-CopyLog "Source folders: $($srcFolders.Count)  |  present in target: $($check.Present.Count)"
            if ($check.Missing.Count -gt 0) {
                Write-CopyLog "Folders MISSING from target ($($check.Missing.Count)):"
                $shown = 0
                foreach ($m in $check.Missing) {
                    if ($shown -ge 25) {
                        Write-CopyLog "  ... and $($check.Missing.Count - $shown) more"
                        break
                    }
                    Write-CopyLog "  $($m.FullPath)"
                    $shown++
                }
            }
            else {
                Write-CopyLog 'Folder structure matches: every source folder exists in the target.'
            }
        }

        if ($CheckCalendar) {
            Start-CopyPhase -Name 'Verifying calendars' -Indeterminate
            $srcCal = Invoke-WithRetry -ScriptBlock {
                Get-MgUserCalendar -UserId $SourceEmail -Filter "name eq 'Calendar'" -Top 1
            }
            $tgtCal = Invoke-WithRetry -ScriptBlock {
                Get-MgUserCalendar -UserId $TargetEmail -Filter "name eq 'Calendar'" -Top 1
            }

            if ($srcCal -and $tgtCal) {
                $srcEnc = [uri]::EscapeDataString($SourceEmail)
                $tgtEnc = [uri]::EscapeDataString($TargetEmail)
                $srcEvtCount = (Get-GraphCollection -Uri "$script:GraphBase/users/$srcEnc/calendars/$([uri]::EscapeDataString($srcCal.Id))/events?`$top=100&`$select=id" -StatusBox $StatusBox -ProgressPrefix 'Verifying source calendar').Count
                $tgtEvtCount = (Get-GraphCollection -Uri "$script:GraphBase/users/$tgtEnc/calendars/$([uri]::EscapeDataString($tgtCal.Id))/events?`$top=100&`$select=id" -StatusBox $StatusBox -ProgressPrefix 'Verifying target calendar').Count
                Write-CopyLog "Source calendar items: $('{0:N0}' -f $srcEvtCount)"
                Write-CopyLog "Target calendar items: $('{0:N0}' -f $tgtEvtCount)"
            }
            else {
                Write-CopyLog 'Could not retrieve calendar for verification.'
            }
        }

        Set-CopyDetail -Detail 'verification finished' -Force
        Write-CopyLog ''
        Write-CopyLog 'Verification completed!'
    }
    catch {
        Write-CopyLog "Verification error: $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------------------------
# GUI
# ------------------------------------------------------------------------------
$script:GuiWrapControls = New-Object System.Collections.ArrayList
$script:GuiLayoutRoot   = $null

function New-GuiLabel {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][System.Drawing.Font]$Font,
        [System.Drawing.Color]$ForeColor = [System.Drawing.Color]::Empty,
        [int]$TopMargin = 6,
        [int]$BottomMargin = 2
    )
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.Font = $Font
    $l.AutoSize = $true
    $l.Margin = New-Object System.Windows.Forms.Padding(0, $TopMargin, 0, $BottomMargin)
    if ($ForeColor -ne [System.Drawing.Color]::Empty) { $l.ForeColor = $ForeColor }
    [void]$script:GuiWrapControls.Add($l)
    return $l
}

function New-GuiCheckRow {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [bool]$Checked = $false
    )
    $row = New-Object System.Windows.Forms.TableLayoutPanel
    $row.AutoSize = $true
    $row.ColumnCount = 2
    $row.RowCount = 1
    $row.Dock = [System.Windows.Forms.DockStyle]::Fill
    $row.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 2)
    [void]$row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 28)))
    [void]$row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $cb = New-Object System.Windows.Forms.CheckBox
    $cb.AutoSize = $true
    $cb.Checked = $Checked
    $cb.Text = ''
    $cb.Margin = New-Object System.Windows.Forms.Padding(0, 1, 0, 0)
    $cb.Dock = [System.Windows.Forms.DockStyle]::Left

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Text
    $lbl.AutoSize = $true
    $lbl.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $lbl.Margin = New-Object System.Windows.Forms.Padding(0, 3, 0, 0)
    $lbl.Cursor = [System.Windows.Forms.Cursors]::Hand
    $lbl.Tag = $cb
    $lbl.Add_Click({
        $box = [System.Windows.Forms.CheckBox]$this.Tag
        if ($box -and $box.Enabled) { $box.Checked = -not $box.Checked }
    })
    [void]$script:GuiWrapControls.Add($lbl)

    $row.Controls.Add($cb, 0, 0)
    $row.Controls.Add($lbl, 1, 0)
    return @{ Row = $row; CheckBox = $cb; Label = $lbl }
}

function Update-GuiWrapWidths {
    if (-not $script:GuiLayoutRoot) { return }
    $w = $script:GuiLayoutRoot.ClientSize.Width - $script:GuiLayoutRoot.Padding.Left - $script:GuiLayoutRoot.Padding.Right
    if ($w -lt 80) { $w = 80 }
    foreach ($c in $script:GuiWrapControls) {
        $c.MaximumSize = New-Object System.Drawing.Size($w, 0)
    }
}

$fontTitle   = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
$fontStep    = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$fontBody    = New-Object System.Drawing.Font('Segoe UI', 9)
$fontHint    = New-Object System.Drawing.Font('Segoe UI', 8, [System.Drawing.FontStyle]::Italic)
$fontButton  = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$fontStatus  = New-Object System.Drawing.Font('Consolas', 9)

$form = New-Object System.Windows.Forms.Form
$form.Text            = "Microsoft 365 Mailbox Copy Tool v1.16 (Interactive Login)"
$form.Size            = New-Object System.Drawing.Size(780, 820)
$form.MinimumSize     = New-Object System.Drawing.Size(600, 700)
$form.StartPosition   = "CenterScreen"
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
$form.MaximizeBox     = $true
$form.MinimizeBox     = $true
$form.AutoScaleMode   = [System.Windows.Forms.AutoScaleMode]::Font
$form.Padding         = New-Object System.Windows.Forms.Padding(0)

$root = New-Object System.Windows.Forms.TableLayoutPanel
$root.Dock = [System.Windows.Forms.DockStyle]::Fill
$root.ColumnCount = 1
$root.RowCount = 18
$root.Padding = New-Object System.Windows.Forms.Padding(16)
$root.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::FixedSize
[void]$root.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
for ($guiRow = 0; $guiRow -lt 17; $guiRow++) {
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
}
[void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$script:GuiLayoutRoot = $root
$form.Controls.Add($root)

$titleLabel = New-GuiLabel -Text "Copy Emails and Calendar Items Between Mailboxes" -Font $fontTitle -TopMargin 0 -BottomMargin 8
$root.Controls.Add($titleLabel, 0, 0)

$authLabel = New-GuiLabel -Text "Step 1: Authenticate (Microsoft Graph)" -Font $fontStep -TopMargin 4
$root.Controls.Add($authLabel, 0, 1)

$connectButton = New-Object System.Windows.Forms.Button
$connectButton.Text = "Sign In to Microsoft 365"
$connectButton.Font = $fontBody
$connectButton.AutoSize = $true
$connectButton.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$connectButton.MinimumSize = New-Object System.Drawing.Size(200, 32)
$connectButton.Margin = New-Object System.Windows.Forms.Padding(0, 2, 8, 10)
$connectButton.Anchor = [System.Windows.Forms.AnchorStyles]::Left
$root.Controls.Add($connectButton, 0, 2)

$preflightLabel = New-GuiLabel -Text "Step 2: Pre-flight Checklist (must be completed before copying)" -Font $fontStep
$root.Controls.Add($preflightLabel, 0, 3)

$preflightHint = New-GuiLabel -Text "Grant FullAccess on both mailboxes via Exchange Admin Center or EXO PowerShell before proceeding. Remove it manually when done." -Font $fontHint -ForeColor ([System.Drawing.Color]::Gray) -TopMargin 0 -BottomMargin 4
$root.Controls.Add($preflightHint, 0, 4)

$accessRow = New-GuiCheckRow -Text "I have granted FullAccess on both the source and target mailboxes to my account" -Checked $false
$accessGrantedCheckbox = $accessRow.CheckBox
$accessGrantedLabel    = $accessRow.Label
$root.Controls.Add($accessRow.Row, 0, 5)

$sourceLabel = New-GuiLabel -Text "Step 3: Source Mailbox (copy FROM)" -Font $fontStep
$root.Controls.Add($sourceLabel, 0, 6)

$sourceTextbox = New-Object System.Windows.Forms.TextBox
$sourceTextbox.Font = $fontBody
$sourceTextbox.Dock = [System.Windows.Forms.DockStyle]::Fill
$sourceTextbox.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 8)
$sourceTextbox.MinimumSize = New-Object System.Drawing.Size(100, 24)
$root.Controls.Add($sourceTextbox, 0, 7)

$targetLabel = New-GuiLabel -Text "Step 4: Target Mailbox (copy TO)" -Font $fontStep
$root.Controls.Add($targetLabel, 0, 8)

$targetTextbox = New-Object System.Windows.Forms.TextBox
$targetTextbox.Font = $fontBody
$targetTextbox.Dock = [System.Windows.Forms.DockStyle]::Fill
$targetTextbox.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 8)
$targetTextbox.MinimumSize = New-Object System.Drawing.Size(100, 24)
$root.Controls.Add($targetTextbox, 0, 9)

$optionsLabel = New-GuiLabel -Text "Step 5: What to Copy" -Font $fontStep
$root.Controls.Add($optionsLabel, 0, 10)

$emailRow = New-GuiCheckRow -Text "Copy Email Messages" -Checked $true
$emailCheckbox = $emailRow.CheckBox
$emailLabel    = $emailRow.Label
$root.Controls.Add($emailRow.Row, 0, 11)

$calendarRow = New-GuiCheckRow -Text "Copy Calendar Items (attendees silent, Teams links kept)" -Checked $true
$calendarCheckbox = $calendarRow.CheckBox
$calendarLabel    = $calendarRow.Label
$root.Controls.Add($calendarRow.Row, 0, 12)

$buttonRow = New-Object System.Windows.Forms.FlowLayoutPanel
$buttonRow.AutoSize = $true
$buttonRow.WrapContents = $true
$buttonRow.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
$buttonRow.Dock = [System.Windows.Forms.DockStyle]::Fill
$buttonRow.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 8)
$buttonRow.Padding = New-Object System.Windows.Forms.Padding(0)

$copyButton = New-Object System.Windows.Forms.Button
$copyButton.Text = "Start Copy"
$copyButton.Font = $fontButton
$copyButton.AutoSize = $true
$copyButton.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$copyButton.MinimumSize = New-Object System.Drawing.Size(140, 36)
$copyButton.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 6)
$copyButton.Enabled = $false
$buttonRow.Controls.Add($copyButton)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = "Cancel"
$cancelButton.Font = $fontButton
$cancelButton.AutoSize = $true
$cancelButton.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$cancelButton.MinimumSize = New-Object System.Drawing.Size(120, 36)
$cancelButton.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
$cancelButton.Enabled = $false
$cancelButton.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
$cancelButton.ForeColor = [System.Drawing.Color]::White
$buttonRow.Controls.Add($cancelButton)
$root.Controls.Add($buttonRow, 0, 13)

# Two labels above the bar carry the live position and the ETA. They are updated
# in place so the scrolling log stays readable, and are deliberately fixed-height
# single lines with an ellipsis so a long folder path cannot reflow the layout.
$phaseLabel = New-Object System.Windows.Forms.Label
$phaseLabel.Text = "Idle."
$phaseLabel.Font = $fontBody
$phaseLabel.AutoSize = $false
$phaseLabel.AutoEllipsis = $true
$phaseLabel.Dock = [System.Windows.Forms.DockStyle]::Fill
$phaseLabel.Height = 20
$phaseLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
$root.Controls.Add($phaseLabel, 0, 14)

$etaLabel = New-Object System.Windows.Forms.Label
$etaLabel.Text = ""
$etaLabel.Font = $fontHint
$etaLabel.ForeColor = [System.Drawing.Color]::FromArgb(70, 70, 70)
$etaLabel.AutoSize = $false
$etaLabel.AutoEllipsis = $true
$etaLabel.Dock = [System.Windows.Forms.DockStyle]::Fill
$etaLabel.Height = 18
$etaLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 4)
$root.Controls.Add($etaLabel, 0, 15)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Dock = [System.Windows.Forms.DockStyle]::Fill
$progressBar.Height = 22
$progressBar.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 8)
$progressBar.MinimumSize = New-Object System.Drawing.Size(100, 18)
$root.Controls.Add($progressBar, 0, 16)

$statusBox = New-Object System.Windows.Forms.TextBox
$statusBox.Multiline = $true
$statusBox.ScrollBars = "Vertical"
$statusBox.ReadOnly = $true
$statusBox.WordWrap = $true
$statusBox.Font = $fontStatus
$statusBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$statusBox.Margin = New-Object System.Windows.Forms.Padding(0)
$statusBox.MinimumSize = New-Object System.Drawing.Size(100, 80)
$statusBox.Text = "Welcome! Click 'Sign In to Microsoft 365' to begin.`r`n"
$root.Controls.Add($statusBox, 0, 17)

$form.Add_Resize({ Update-GuiWrapWidths })
$form.Add_Shown({ Update-GuiWrapWidths })

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
        $accessGrantedLabel.Enabled    = $false
        $emailCheckbox.Enabled         = $false
        $emailLabel.Enabled            = $false
        $calendarCheckbox.Enabled      = $false
        $calendarLabel.Enabled         = $false
        $progressBar.Style             = [System.Windows.Forms.ProgressBarStyle]::Continuous
        $progressBar.Value             = 0

        $statusBox.Clear()
        Initialize-CopyUi -StatusBox $statusBox -ProgressBar $progressBar -PhaseLabel $phaseLabel -EtaLabel $etaLabel
        $runStart = Get-Date
        Write-CopyLog "=== COPY OPERATION STARTED $($runStart.ToString('yyyy-MM-dd HH:mm:ss')) ==="
        Write-CopyLog "Source : $sourceEmail"
        Write-CopyLog "Target : $targetEmail"
        Start-CopyPhase -Name 'Starting' -Indeterminate

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
                $progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
                $progressBar.Value = 100
                $phaseLabel.Text   = "Finished."
                $etaLabel.Text     = "Total run time $(Format-CopyDuration ((Get-Date) - $runStart).TotalSeconds)."
                Write-CopyLog ''
                Write-CopyLog '=== COPY OPERATION COMPLETED ==='
                Write-CopyLog "Total run time: $(Format-CopyDuration ((Get-Date) - $runStart).TotalSeconds)"
                Write-CopyLog 'Remember to remove FullAccess permissions from both mailboxes.'

                if ($script:FolderScanIncomplete) {
                    $statusBox.AppendText("WARNING: at least one folder listing failed, so the source was not fully`r`n")
                    $statusBox.AppendText("         enumerated. Review the log above and re-run before you rely on`r`n")
                    $statusBox.AppendText("         this copy - it is NOT complete.`r`n")
                    [System.Windows.Forms.MessageBox]::Show(
                        "Copy finished, but the source mailbox could not be fully enumerated, so some folders were NOT copied.`r`n`r`nReview the status log and re-run before relying on this copy.`r`n`r`nRemember to remove FullAccess permissions from both mailboxes.",
                        "Completed With Warnings",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Warning)
                }
                else {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Copy operation completed!`r`n`r`nRemember to remove FullAccess permissions from both mailboxes.",
                        "Success",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information)
                }
            }
            else {
                $phaseLabel.Text = "Cancelled."
                $etaLabel.Text   = "Stopped after $(Format-CopyDuration ((Get-Date) - $runStart).TotalSeconds)."
                Write-CopyLog ''
                Write-CopyLog '=== COPY OPERATION CANCELLED ==='
                [System.Windows.Forms.MessageBox]::Show("Copy operation was cancelled by user.", "Cancelled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            }
        }
        catch {
            $phaseLabel.Text = "Failed."
            $etaLabel.Text   = "See the status log for details."
            Write-CopyLog ''
            Write-CopyLog "ERROR: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show("An error occurred. Check the status window for details.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
        finally {
            $progressBar.Style             = [System.Windows.Forms.ProgressBarStyle]::Continuous
            $copyButton.Enabled            = $true
            $sourceTextbox.Enabled         = $true
            $targetTextbox.Enabled         = $true
            $accessGrantedCheckbox.Enabled = $true
            $accessGrantedLabel.Enabled    = $true
            $emailCheckbox.Enabled         = $true
            $emailLabel.Enabled            = $true
            $calendarCheckbox.Enabled      = $true
            $calendarLabel.Enabled         = $true
            $cancelButton.Enabled          = $false
            $script:CancelRequested        = $false
        }
    }
})

[void]$form.ShowDialog()

if ($script:Connected) { Disconnect-MgGraph | Out-Null }

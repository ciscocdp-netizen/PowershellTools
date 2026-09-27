#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Removes users whose extensionAttribute3 contains "Spinco" from M365 license groups.

.DESCRIPTION
    Finds Active Directory users with extensionAttribute3 matching -MatchValue (default: Spinco)
    and removes them from the configured license groups.

    When run without -NonInteractive (the default), the script is fully interactive:
      - choose Preview / WhatIf or Live removals from a menu
      - confirm match value, DC, and which license groups to target
      - review the matching-user table before anything is processed
      - type REMOVE to confirm a live run
      - after a WhatIf preview, optionally run the same users live

    Verbose progress is always written to the console so you can see:
      - each target group as it is resolved
      - each matching user (sAMAccountName, display name, UPN, extensionAttribute3)
      - each group they are being removed from (or skipped / WhatIf)
      - a final per-group and per-status summary

    A CSV audit log is written incrementally (one row per user/group action) so a
    mid-run failure does not lose the trail. A full console transcript is also saved.

.PARAMETER MatchValue
    Substring to match in extensionAttribute3. Default: Spinco.
    In interactive mode this is the default at the prompt.

.PARAMETER LogPath
    CSV audit log path. Default: .\SpincoGroupRemoval_<timestamp>.csv

.PARAMETER TranscriptPath
    Console transcript path. Default: same basename as LogPath with a .log extension.

.PARAMETER Server
    Optional domain controller FQDN or NetBIOS name. Uses the default DC if omitted.
    In interactive mode this is the default at the prompt.

.PARAMETER NonInteractive
    Skip all prompts. Use -WhatIf for a preview, or omit it to perform live removals.
    Intended for scheduled / scripted runs.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1
    Interactive menu. Choose Preview (WhatIf) or Live, then confirm before changes.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1 -WhatIf
    Skip the mode menu and run a WhatIf preview. Other interactive prompts still appear.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1 -NonInteractive -WhatIf
    Unattended preview. No prompts.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1 -Server dc01.contoso.com -MatchValue Spinco
    Interactive run with those values pre-filled as defaults.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$MatchValue      = "Spinco",
    [string]$LogPath         = ".\SpincoGroupRemoval_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$TranscriptPath,
    [string]$Server,
    [switch]$NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-ScreenLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR', 'WHATIF', 'SKIP', 'PROGRESS')]
        [string]$Level = 'INFO'
    )

    $color = switch ($Level) {
        'INFO'     { 'Cyan' }
        'SUCCESS'  { 'Green' }
        'WARN'     { 'Yellow' }
        'ERROR'    { 'Red' }
        'WHATIF'   { 'Magenta' }
        'SKIP'     { 'DarkYellow' }
        'PROGRESS' { 'Gray' }
    }

    $line = "[{0}] [{1,-8}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line -ForegroundColor $color
}

function Escape-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    $builder = New-Object System.Text.StringBuilder
    foreach ($char in $Value.ToCharArray()) {
        switch ($char) {
            '\'  { [void]$builder.Append('\5c') }
            '*'  { [void]$builder.Append('\2a') }
            '('  { [void]$builder.Append('\28') }
            ')'  { [void]$builder.Append('\29') }
            "`0" { [void]$builder.Append('\00') }
            default { [void]$builder.Append($char) }
        }
    }
    return $builder.ToString()
}

function Escape-AdFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)
    return ($Value -replace "'", "''")
}

function Get-AdCmdletParams {
    $p = @{}
    if ($script:Server) { $p['Server'] = $script:Server }
    return $p
}

function Write-Banner {
    param([string[]]$Lines)

    $rule = ('=' * 78)
    Write-Host ""
    Write-Host $rule -ForegroundColor Cyan
    foreach ($line in $Lines) {
        Write-Host $line -ForegroundColor Cyan
    }
    Write-Host $rule -ForegroundColor Cyan
    Write-Host ""
}

function Add-ActionResult {
    param([Parameter(Mandatory = $true)]$Result)

    [void]$script:Results.Add($Result)

    try {
        # Logging must run even when the script itself is in -WhatIf mode.
        $Result | Export-Csv -Path $script:ResolvedLogPath -NoTypeInformation -Encoding UTF8 -Append -WhatIf:$false
    }
    catch {
        Write-ScreenLog "Could not append to CSV log '$($script:ResolvedLogPath)': $($_.Exception.Message)" -Level WARN
    }
}

function Format-UserIdentity {
    param($User)

    $display = if ($User.DisplayName) { $User.DisplayName } else { '(no display name)' }
    $upn     = if ($User.UserPrincipalName) { $User.UserPrincipalName } else { '(no UPN)' }
    return "{0} | {1} | {2}" -f $User.SamAccountName, $display, $upn
}

function Test-ShouldPrompt {
    if ($NonInteractive) { return $false }
    return [Environment]::UserInteractive
}

function Read-RawInput {
    param([Parameter(Mandatory = $true)][string]$PromptText)

    $redirected = $false
    try { $redirected = [Console]::IsInputRedirected } catch { }

    if ($redirected) {
        Write-Host "$PromptText " -NoNewline
        $line = [Console]::In.ReadLine()
        if ($null -eq $line) { $line = '' }
        Write-Host $line
        return $line
    }

    try {
        return Read-Host $PromptText
    }
    catch {
        Write-Host "$PromptText " -NoNewline
        $line = [Console]::In.ReadLine()
        if ($null -eq $line) { return '' }
        return $line
    }
}

function Read-Prompt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$Default
    )

    $suffix = if ($PSBoundParameters.ContainsKey('Default')) { " [$Default]" } else { '' }
    $raw = Read-RawInput -PromptText ($Message + $suffix)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        if ($PSBoundParameters.ContainsKey('Default')) { return $Default }
        return ''
    }
    return $raw.Trim()
}

function Read-YesNo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [bool]$Default = $true
    )

    $hint = if ($Default) { 'Y/n' } else { 'y/N' }
    while ($true) {
        $raw = Read-RawInput -PromptText "$Message [$hint]"
        if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
        switch -Regex ($raw.Trim()) {
            '^(y|yes)$' { return $true }
            '^(n|no)$'  { return $false }
            default {
                Write-Host "Please enter Y or N." -ForegroundColor Yellow
            }
        }
    }
}

function Read-RunMode {
    param([bool]$WhatIfAlreadySet)

    if ($WhatIfAlreadySet) {
        Write-Host ""
        Write-Host "Mode: Preview / WhatIf  (from -WhatIf). No AD memberships will be changed." -ForegroundColor Magenta
        return 'WhatIf'
    }

    Write-Host ""
    Write-Host "---- Run mode ----------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  [1] Preview only (WhatIf)   Show who would be removed. No AD changes." -ForegroundColor Magenta
    Write-Host "  [2] Live removals           Actually remove users from license groups." -ForegroundColor Yellow
    Write-Host "  [Q] Quit" -ForegroundColor Gray
    Write-Host ""

    while ($true) {
        $choice = Read-Prompt -Message "Select a run mode" -Default "1"
        switch -Regex ($choice) {
            '^(1|p|preview|whatif)$' { return 'WhatIf' }
            '^(2|l|live)$'           { return 'Live' }
            '^(q|quit|exit)$'        { return 'Quit' }
            default {
                Write-Host "Enter 1 (Preview/WhatIf), 2 (Live), or Q (Quit)." -ForegroundColor Yellow
            }
        }
    }
}

function Read-SelectedGroups {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$AllNames
    )

    Write-Host ""
    Write-Host "---- License groups ----------------------------------------------------------" -ForegroundColor Cyan
    for ($i = 0; $i -lt $AllNames.Count; $i++) {
        Write-Host ("  {0,2}) {1}" -f ($i + 1), $AllNames[$i])
    }
    Write-Host ""
    Write-Host "Enter A for all groups, or a comma-separated list of numbers (e.g. 1,4,6)." -ForegroundColor Gray

    while ($true) {
        $raw = Read-Prompt -Message "Groups to include" -Default "A"
        if ($raw -match '^(a|all)$') { return @($AllNames) }

        $picked = [System.Collections.Generic.List[string]]::new()
        $ok = $true
        foreach ($part in ($raw -split ',')) {
            $token = $part.Trim()
            if (-not $token) { continue }
            $num = 0
            if (-not [int]::TryParse($token, [ref]$num) -or $num -lt 1 -or $num -gt $AllNames.Count) {
                Write-Host "Invalid group number: '$token'. Use 1-$($AllNames.Count) or A." -ForegroundColor Yellow
                $ok = $false
                break
            }
            $name = $AllNames[$num - 1]
            if (-not $picked.Contains($name)) { [void]$picked.Add($name) }
        }

        if ($ok -and $picked.Count -gt 0) { return @($picked) }
        if ($ok -and $picked.Count -eq 0) {
            Write-Host "Select at least one group." -ForegroundColor Yellow
        }
    }
}

function Confirm-LiveRemoval {
    Write-Host ""
    Write-Host "WARNING: LIVE mode will REMOVE users from the selected license groups." -ForegroundColor Red
    $typed = Read-Prompt -Message "Type REMOVE to continue, or anything else to cancel"
    return ($typed -eq 'REMOVE')
}

function Show-MatchingUserTable {
    param(
        [Parameter(Mandatory = $true)]$Users,
        [Parameter(Mandatory = $true)]$Groups
    )

    Write-Host ""
    Write-Host "---- Matching users -------------------------------------------------------" -ForegroundColor Cyan
    $preview = foreach ($u in $Users) {
        $hitDns = @($u.MemberOf | Where-Object { $_ -and $Groups.ContainsKey($_) })
        [pscustomobject]@{
            SamAccountName      = $u.SamAccountName
            Hits                = $hitDns.Count
            TargetGroups        = ($(foreach ($dn in $hitDns) { $Groups[$dn].Name })) -join '; '
            DisplayName         = $u.DisplayName
            UserPrincipalName   = $u.UserPrincipalName
            Enabled             = $u.Enabled
            ExtensionAttribute3 = $u.extensionAttribute3
        }
    }
    $preview |
        Format-Table SamAccountName, Hits, TargetGroups, DisplayName, UserPrincipalName, Enabled, ExtensionAttribute3 -AutoSize -Wrap |
        Out-Host
    Write-Host ""
}

function Invoke-LicenseGroupPass {
    param(
        [Parameter(Mandatory = $true)]$Users,
        [Parameter(Mandatory = $true)]$Groups,
        [Parameter(Mandatory = $true)]$AdParams
    )

    $usersWithActions = 0
    $usersSkipped     = 0
    $index            = 0
    $activity         = if ($script:PreviewOnly) {
        "Previewing Spinco users in license groups (WhatIf)"
    } else {
        "Removing Spinco users from license groups"
    }

    foreach ($user in $Users) {
        $index++
        $percent = [int](($index / $Users.Count) * 100)
        Write-Progress -Activity $activity `
                       -Status ("[{0}/{1}] {2}" -f $index, $Users.Count, $user.SamAccountName) `
                       -PercentComplete $percent

        $identity = Format-UserIdentity -User $user
        $enabledText = if ($user.Enabled) { 'Enabled' } else { 'Disabled' }

        Write-Host ""
        Write-Host ("-------- User {0}/{1} ({2}%) --------" -f $index, $Users.Count, $percent) -ForegroundColor White
        Write-ScreenLog "User       : $identity" -Level PROGRESS
        Write-ScreenLog "Account    : $enabledText" -Level PROGRESS
        Write-ScreenLog "DN         : $($user.DistinguishedName)" -Level PROGRESS
        Write-ScreenLog "ExtAttr3   : $($user.extensionAttribute3)" -Level PROGRESS

        $memberOf = @($user.MemberOf | Where-Object { $_ })
        $targetMemberships = @($memberOf | Where-Object { $Groups.ContainsKey($_) })

        Write-ScreenLog "Direct memberships : $($memberOf.Count) total / $($targetMemberships.Count) target license group(s)" -Level PROGRESS

        if ($targetMemberships.Count -eq 0) {
            $usersSkipped++
            Write-ScreenLog "SKIP $($user.SamAccountName) — not a direct member of any target license group." -Level SKIP

            Add-ActionResult -Result ([pscustomobject]@{
                Timestamp           = Get-Date
                SamAccountName      = $user.SamAccountName
                DisplayName         = $user.DisplayName
                UserPrincipalName   = $user.UserPrincipalName
                DistinguishedName   = $user.DistinguishedName
                Enabled             = $user.Enabled
                ExtensionAttribute3 = $user.extensionAttribute3
                Group               = ''
                GroupDN             = ''
                Status              = 'Skipped - not in any target group'
                Message             = 'User matched extensionAttribute3 but is not a direct member of the configured license groups.'
            })
            continue
        }

        $usersWithActions++
        foreach ($groupDN in $targetMemberships) {
            $group = $Groups[$groupDN]
            $actionTarget = "{0} <{1}>" -f $user.SamAccountName, $user.UserPrincipalName
            $actionDesc   = "Remove from license group '{0}'" -f $group.Name

            Write-ScreenLog "Action     : $actionDesc" -Level INFO
            Write-ScreenLog "             Group DN: $groupDN" -Level PROGRESS

            $status  = $null
            $message = $null

            if ($script:PreviewOnly) {
                $status  = 'WhatIf - would remove'
                $message = "WhatIf: would remove $($user.SamAccountName) from '$($group.Name)'"
                Write-ScreenLog "WOULD REMOVE $($user.SamAccountName) ($($user.UserPrincipalName))  from  '$($group.Name)'" -Level WHATIF
            }
            else {
                try {
                    Remove-ADGroupMember -Identity $group.DistinguishedName -Members $user.DistinguishedName -Confirm:$false -ErrorAction Stop @AdParams
                    $status  = 'Removed'
                    $message = "Removed $($user.SamAccountName) from '$($group.Name)'"
                    Write-ScreenLog "REMOVED $($user.SamAccountName) ($($user.UserPrincipalName))  from  '$($group.Name)'" -Level SUCCESS
                }
                catch {
                    $status  = 'Failed'
                    $message = $_.Exception.Message
                    Write-ScreenLog "FAILED  $($user.SamAccountName) ($($user.UserPrincipalName))  from  '$($group.Name)' — $message" -Level ERROR
                }
            }

            Add-ActionResult -Result ([pscustomobject]@{
                Timestamp           = Get-Date
                SamAccountName      = $user.SamAccountName
                DisplayName         = $user.DisplayName
                UserPrincipalName   = $user.UserPrincipalName
                DistinguishedName   = $user.DistinguishedName
                Enabled             = $user.Enabled
                ExtensionAttribute3 = $user.extensionAttribute3
                Group               = $group.Name
                GroupDN             = $group.DistinguishedName
                Status              = $status
                Message             = $message
            })
        }
    }

    Write-Progress -Activity $activity -Completed

    return [pscustomobject]@{
        UsersWithActions = $usersWithActions
        UsersSkipped     = $usersSkipped
    }
}

function Write-RunSummary {
    param(
        [Parameter(Mandatory = $true)]$Users,
        [Parameter(Mandatory = $true)]$PassCounts
    )

    $removed  = @($script:Results | Where-Object { $_.Status -eq 'Removed' }).Count
    $failed   = @($script:Results | Where-Object { $_.Status -eq 'Failed' }).Count
    $whatIf   = @($script:Results | Where-Object { $_.Status -eq 'WhatIf - would remove' }).Count
    $declined = @($script:Results | Where-Object { $_.Status -eq 'Skipped - operator declined' }).Count
    $skipped  = @($script:Results | Where-Object { $_.Status -eq 'Skipped - not in any target group' }).Count

    Write-Host ""
    Write-Banner @(
        " SUMMARY"
        " Users scanned              : $($Users.Count)"
        " Users with group actions   : $($PassCounts.UsersWithActions)"
        " Users skipped (no groups)  : $($PassCounts.UsersSkipped)"
        " Removals succeeded         : $removed"
        " Removals failed            : $failed"
        " WhatIf (would remove)      : $whatIf"
        " Declined at confirm prompt : $declined"
        " Skip rows logged           : $skipped"
        " Total CSV rows             : $($script:Results.Count)"
        " CSV log                    : $script:ResolvedLogPath"
        " Transcript                 : $script:ResolvedTranscriptPath"
    )

    if ($script:Results.Count -gt 0) {
        Write-Host "---- Actions by group -----------------------------------------------------" -ForegroundColor Cyan
        $script:Results |
            Where-Object { $_.Group } |
            Group-Object Group |
            Select-Object @{n = 'Group'; e = { $_.Name } }, @{n = 'Actions'; e = { $_.Count } } |
            Format-Table -AutoSize |
            Out-Host

        Write-Host "---- Actions by status ----------------------------------------------------" -ForegroundColor Cyan
        $script:Results |
            Group-Object Status |
            Select-Object @{n = 'Status'; e = { $_.Name } }, @{n = 'Count'; e = { $_.Count } } |
            Format-Table -AutoSize |
            Out-Host

        Write-Host "---- Detail (user -> group -> status) -------------------------------------" -ForegroundColor Cyan
        $script:Results |
            Select-Object SamAccountName, UserPrincipalName, Group, Status |
            Format-Table -AutoSize -Wrap |
            Out-Host
    }
    else {
        Write-ScreenLog "No matching users are members of the target groups. Nothing to do." -Level WARN
    }
}

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
$script:IsInteractive     = Test-ShouldPrompt
$script:Server            = $Server
$script:Results           = [System.Collections.Generic.List[object]]::new()
$script:TranscriptStarted = $false
$script:UserCancelled     = $false
$script:PreviewOnly       = [bool]$WhatIfPreference -or $PSBoundParameters.ContainsKey('WhatIf')

$AllGroupNames = @(
    "EXO P1 License"
    "EXO P2 License"
    "F3_Archive_License_ApriaUserOnly"
    "E3 Licenses"
    "M365-License-E5-eDiscovery"
    "F3 Licenses"
    "Power BI Pro License"
)
$GroupNames = @($AllGroupNames)

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    if ($script:IsInteractive) {
        Write-Banner @(
            " Remove-SpincoFromLicenseGroups"
            " Interactive setup — choose Preview (WhatIf) or Live before any changes."
        )

        $mode = Read-RunMode -WhatIfAlreadySet:$script:PreviewOnly
        if ($mode -eq 'Quit') {
            Write-Host "Cancelled. No changes made." -ForegroundColor Yellow
            $script:UserCancelled = $true
            return
        }

        $script:PreviewOnly = ($mode -eq 'WhatIf')
        $WhatIfPreference = $script:PreviewOnly

        $MatchValue = Read-Prompt -Message "extensionAttribute3 contains" -Default $MatchValue
        if ([string]::IsNullOrWhiteSpace($MatchValue)) {
            throw "MatchValue cannot be empty."
        }

        if ($script:Server) {
            $serverAnswer = Read-Prompt -Message "Domain controller (blank = default)" -Default $script:Server
        }
        else {
            $serverAnswer = Read-Prompt -Message "Domain controller (blank = default)"
        }
        $script:Server = $serverAnswer
        $Server = $script:Server

        $GroupNames = Read-SelectedGroups -AllNames $AllGroupNames

        Write-Host ""
        Write-Host "Selected $($GroupNames.Count) group(s): $($GroupNames -join ', ')" -ForegroundColor Cyan
    }
    elseif ($script:PreviewOnly) {
        Write-Host "Non-interactive WhatIf preview." -ForegroundColor Magenta
    }
    else {
        Write-Host "Non-interactive LIVE run. Users will be removed from license groups." -ForegroundColor Yellow
    }

    if ([string]::IsNullOrWhiteSpace($MatchValue)) {
        throw "MatchValue cannot be empty."
    }

    $script:ResolvedLogPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)
    if (-not $TranscriptPath) {
        $TranscriptPath = [System.IO.Path]::ChangeExtension($script:ResolvedLogPath, '.log')
    }
    $script:ResolvedTranscriptPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TranscriptPath)

    $logDir = Split-Path -Parent $script:ResolvedLogPath
    if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force -WhatIf:$false | Out-Null
    }

    try {
        Start-Transcript -Path $script:ResolvedTranscriptPath -Append -ErrorAction Stop -WhatIf:$false | Out-Null
        $script:TranscriptStarted = $true
    }
    catch {
        Write-Warning "Could not start transcript at '$script:ResolvedTranscriptPath': $($_.Exception.Message)"
    }

    $modeText = if ($script:PreviewOnly) {
        'WHATIF - preview only; no group memberships will be changed'
    } else {
        'LIVE - users WILL be removed from license groups'
    }

    Write-Banner @(
        " Remove-SpincoFromLicenseGroups"
        " Started     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        " Mode        : $modeText"
        " Match       : extensionAttribute3 like '*$MatchValue*'"
        " Target DC   : $(if ($script:Server) { $script:Server } else { '(default)' })"
        " CSV log     : $script:ResolvedLogPath"
        " Transcript  : $script:ResolvedTranscriptPath"
        " Groups      : $($GroupNames.Count) selected"
    )

    $adParams = Get-AdCmdletParams

    # -----------------------------------------------------------------------
    # Resolve groups once (Name OR sAMAccountName — Identity alone misses
    # groups whose CN/display name differs from the pre-Windows 2000 name)
    # -----------------------------------------------------------------------
    Write-ScreenLog "Resolving $($GroupNames.Count) target license group(s)..." -Level INFO

    $Groups = @{}
    $resolvedCount = 0
    $missingGroups = [System.Collections.Generic.List[string]]::new()

    foreach ($name in $GroupNames) {
        $escapedName = Escape-AdFilterValue -Value $name
        try {
            $found = @(Get-ADGroup -Filter "Name -eq '$escapedName' -or SamAccountName -eq '$escapedName'" @adParams)
            if ($found.Count -eq 0) {
                throw "No group with Name or sAMAccountName '$name'."
            }
            if ($found.Count -gt 1) {
                Write-ScreenLog "Multiple groups match '$name'. Using first: $($found[0].DistinguishedName)" -Level WARN
            }

            $g = $found[0]
            $Groups[$g.DistinguishedName] = $g
            $resolvedCount++
            Write-ScreenLog ("Resolved  [{0}/{1}] '{2}'  (sAM={3})" -f $resolvedCount, $GroupNames.Count, $g.Name, $g.SamAccountName) -Level SUCCESS
            Write-ScreenLog "           DN: $($g.DistinguishedName)" -Level PROGRESS
        }
        catch {
            [void]$missingGroups.Add($name)
            Write-ScreenLog "Group not found: '$name' - skipping. $($_.Exception.Message)" -Level WARN
        }
    }

    if ($Groups.Count -eq 0) {
        throw "None of the target groups were found. Exiting."
    }

    Write-ScreenLog "Resolved $($Groups.Count) of $($GroupNames.Count) group(s). Missing: $(if ($missingGroups.Count) { $missingGroups -join ', ' } else { 'none' })" -Level INFO

    # -----------------------------------------------------------------------
    # Find matching users
    # -----------------------------------------------------------------------
    $ldapValue = Escape-LdapFilterValue -Value $MatchValue
    $ldapFilter = "(extensionAttribute3=*$ldapValue*)"

    Write-ScreenLog "Searching for users with LDAP filter $ldapFilter ..." -Level INFO

    $userProperties = @(
        'extensionAttribute3'
        'MemberOf'
        'DisplayName'
        'UserPrincipalName'
        'SamAccountName'
        'DistinguishedName'
        'Enabled'
    )

    try {
        $Users = @(Get-ADUser -LDAPFilter $ldapFilter -Properties $userProperties @adParams)
    }
    catch {
        throw "Get-ADUser failed for filter $ldapFilter : $($_.Exception.Message)"
    }

    Write-ScreenLog "Found $($Users.Count) matching user(s)." -Level INFO

    if ($Users.Count -eq 0) {
        Write-ScreenLog "No users have extensionAttribute3 matching '*$MatchValue*'. Nothing to do." -Level WARN
        return
    }

    Show-MatchingUserTable -Users $Users -Groups $Groups

    $actionable = @($Users | Where-Object {
        @($_.MemberOf | Where-Object { $_ -and $Groups.ContainsKey($_) }).Count -gt 0
    }).Count

    Write-ScreenLog "$actionable of $($Users.Count) matching user(s) are in at least one selected license group." -Level INFO

    if ($script:IsInteractive) {
        $continueHint = if ($script:PreviewOnly) {
            "Continue with WHATIF preview of $actionable user(s)?"
        } else {
            "Continue with LIVE removal of $actionable user(s) from the selected groups?"
        }
        if (-not (Read-YesNo -Message $continueHint -Default $true)) {
            Write-Host "Cancelled after review. No memberships were changed." -ForegroundColor Yellow
            $script:UserCancelled = $true
            return
        }

        if (-not $script:PreviewOnly) {
            if (-not (Confirm-LiveRemoval)) {
                Write-Host "Live run not confirmed. No memberships were changed." -ForegroundColor Yellow
                $script:UserCancelled = $true
                return
            }
        }
    }

    $passCounts = Invoke-LicenseGroupPass -Users $Users -Groups $Groups -AdParams $adParams
    Write-RunSummary -Users $Users -PassCounts $passCounts

    # After a WhatIf preview, offer to perform the same removals live
    if ($script:IsInteractive -and $script:PreviewOnly -and $actionable -gt 0) {
        Write-Host ""
        Write-Host "WhatIf preview finished. No memberships have been changed yet." -ForegroundColor Magenta
        if (Read-YesNo -Message "Run LIVE removals now for the same $actionable user(s)?" -Default $false) {
            if (Confirm-LiveRemoval) {
                $script:PreviewOnly = $false
                $WhatIfPreference = $false
                Write-Banner @(
                    " LIVE PASS"
                    " Mode        : LIVE - users WILL be removed from license groups"
                    " Users       : $actionable with target group memberships"
                )
                $passCounts = Invoke-LicenseGroupPass -Users $Users -Groups $Groups -AdParams $adParams
                Write-RunSummary -Users $Users -PassCounts $passCounts
            }
            else {
                Write-Host "Live run not confirmed. Leaving WhatIf results as-is." -ForegroundColor Yellow
            }
        }
    }
}
catch {
    Write-ScreenLog $_.Exception.Message -Level ERROR
    throw
}
finally {
    if ($script:TranscriptStarted) {
        try { Stop-Transcript -WhatIf:$false | Out-Null } catch { }
    }

    $inputRedirected = $false
    try { $inputRedirected = [Console]::IsInputRedirected } catch { }
    if ($script:IsInteractive -and -not $inputRedirected) {
        Write-Host ""
        try { [void](Read-RawInput -PromptText "Press Enter to exit") } catch { }
    }
}

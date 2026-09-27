#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Removes users whose extensionAttribute3 contains "Spinco" from M365 license groups.

.DESCRIPTION
    Finds Active Directory users with extensionAttribute3 matching -MatchValue (default: Spinco)
    and removes them from the configured license groups.

    Verbose progress is always written to the console so you can see:
      - each target group as it is resolved
      - each matching user (sAMAccountName, display name, UPN, extensionAttribute3)
      - each group they are being removed from (or skipped / WhatIf)
      - a final per-group and per-status summary

    A CSV audit log is written incrementally (one row per user/group action) so a
    mid-run failure does not lose the trail. A full console transcript is also saved.

.PARAMETER MatchValue
    Substring to match in extensionAttribute3. Default: Spinco.

.PARAMETER LogPath
    CSV audit log path. Default: .\SpincoGroupRemoval_<timestamp>.csv

.PARAMETER TranscriptPath
    Console transcript path. Default: same basename as LogPath with a .log extension.

.PARAMETER Server
    Optional domain controller FQDN or NetBIOS name. Uses the default DC if omitted.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1 -WhatIf
    Preview removals only. Every user and group is printed; no AD changes are made.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1
    Perform removals and print each user/group result to the screen.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1 -Server dc01.contoso.com -MatchValue Spinco
    Run against a specific DC.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$MatchValue      = "Spinco",
    [string]$LogPath         = ".\SpincoGroupRemoval_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$TranscriptPath,
    [string]$Server
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
        $Result | Export-Csv -Path $script:ResolvedLogPath -NoTypeInformation -Encoding UTF8 -Append
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

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
$script:Server          = $Server
$script:Results         = [System.Collections.Generic.List[object]]::new()
$script:TranscriptStarted = $false

$script:ResolvedLogPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)
if (-not $TranscriptPath) {
    $TranscriptPath = [System.IO.Path]::ChangeExtension($script:ResolvedLogPath, '.log')
}
$script:ResolvedTranscriptPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TranscriptPath)

$logDir = Split-Path -Parent $script:ResolvedLogPath
if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

try {
    Start-Transcript -Path $script:ResolvedTranscriptPath -Append -ErrorAction Stop | Out-Null
    $script:TranscriptStarted = $true
}
catch {
    Write-Warning "Could not start transcript at '$script:ResolvedTranscriptPath': $($_.Exception.Message)"
}

$modeText = if ($WhatIfPreference) {
    'WHATIF - preview only; no group memberships will be changed'
} else {
    'LIVE - users WILL be removed from license groups'
}

$GroupNames = @(
    "EXO P1 License"
    "EXO P2 License"
    "F3_Archive_License_ApriaUserOnly"
    "E3 Licenses"
    "M365-License-E5-eDiscovery"
    "F3 Licenses"
    "Power BI Pro License"
)

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Banner @(
        " Remove-SpincoFromLicenseGroups"
        " Started     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        " Mode        : $modeText"
        " Match       : extensionAttribute3 like '*$MatchValue*'"
        " Target DC   : $(if ($Server) { $Server } else { '(default)' })"
        " CSV log     : $script:ResolvedLogPath"
        " Transcript  : $script:ResolvedTranscriptPath"
        " Groups      : $($GroupNames.Count) configured"
    )

    if ([string]::IsNullOrWhiteSpace($MatchValue)) {
        throw "MatchValue cannot be empty."
    }

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

    # Preview the user list so you can verify the search before removals start
    Write-Host ""
    Write-Host "---- Matching users -------------------------------------------------------" -ForegroundColor Cyan
    $preview = foreach ($u in $Users) {
        [pscustomobject]@{
            SamAccountName      = $u.SamAccountName
            DisplayName         = $u.DisplayName
            UserPrincipalName   = $u.UserPrincipalName
            Enabled             = $u.Enabled
            ExtensionAttribute3 = $u.extensionAttribute3
            TargetGroupHits     = @($u.MemberOf | Where-Object { $_ -and $Groups.ContainsKey($_) }).Count
        }
    }
    $preview | Format-Table -AutoSize | Out-Host
    Write-Host ""

    $usersWithActions = 0
    $usersSkipped     = 0
    $index            = 0

    foreach ($user in $Users) {
        $index++
        $percent = [int](($index / $Users.Count) * 100)
        Write-Progress -Activity "Removing Spinco users from license groups" `
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

            if ($PSCmdlet.ShouldProcess($actionTarget, $actionDesc)) {
                try {
                    Remove-ADGroupMember -Identity $group.DistinguishedName -Members $user.DistinguishedName -Confirm:$false -ErrorAction Stop @adParams
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
            else {
                if ($WhatIfPreference) {
                    $status  = 'WhatIf - would remove'
                    $message = "WhatIf: would remove $($user.SamAccountName) from '$($group.Name)'"
                    Write-ScreenLog "WOULD REMOVE $($user.SamAccountName) ($($user.UserPrincipalName))  from  '$($group.Name)'" -Level WHATIF
                }
                else {
                    $status  = 'Skipped - operator declined'
                    $message = "Operator declined removal of $($user.SamAccountName) from '$($group.Name)'"
                    Write-ScreenLog "DECLINED $($user.SamAccountName) ($($user.UserPrincipalName))  from  '$($group.Name)'" -Level SKIP
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

    Write-Progress -Activity "Removing Spinco users from license groups" -Completed

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    $removed  = @($script:Results | Where-Object { $_.Status -eq 'Removed' }).Count
    $failed   = @($script:Results | Where-Object { $_.Status -eq 'Failed' }).Count
    $whatIf   = @($script:Results | Where-Object { $_.Status -eq 'WhatIf - would remove' }).Count
    $declined = @($script:Results | Where-Object { $_.Status -eq 'Skipped - operator declined' }).Count
    $skipped  = @($script:Results | Where-Object { $_.Status -eq 'Skipped - not in any target group' }).Count

    Write-Host ""
    Write-Banner @(
        " SUMMARY"
        " Users scanned              : $($Users.Count)"
        " Users with group actions   : $usersWithActions"
        " Users skipped (no groups)  : $usersSkipped"
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
            Format-Table -AutoSize |
            Out-Host
    }
    else {
        Write-ScreenLog "No matching users are members of the target groups. Nothing to do." -Level WARN
    }
}
catch {
    Write-ScreenLog $_.Exception.Message -Level ERROR
    throw
}
finally {
    if ($script:TranscriptStarted) {
        try { Stop-Transcript | Out-Null } catch { }
    }
}

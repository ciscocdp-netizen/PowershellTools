#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Removes Spinco users from AD license groups and strips directly assigned Microsoft 365 licenses.

.DESCRIPTION
    Finds Active Directory users with extensionAttribute3 matching -MatchValue (default: Spinco)
    and:
      1. Removes them from the configured on-prem license groups (group-based licensing)
      2. Removes any Microsoft 365 / Office 365 licenses assigned DIRECTLY on the user
         in Entra ID (not inherited from a group)

    Direct vs group-based:
      - Group-based licenses are removed by taking the user out of the AD groups.
      - Direct licenses were assigned in the M365 admin center / Graph and must be
        cleared with Set-MgUserLicense. Those are identified via
        licenseAssignmentStates where assignedByGroup is empty.

    When run without -NonInteractive (the default), the script is fully interactive:
      - choose Preview / WhatIf or Live removals from a menu
      - confirm match value, DC, groups, and whether to strip direct licenses
      - review matching users and their direct SKUs before anything is processed
      - type REMOVE to confirm a live run
      - after a WhatIf preview, optionally run the same users live

    Requires the Microsoft Graph PowerShell SDK for the direct-license pass:
      Install-Module Microsoft.Graph.Users, Microsoft.Graph.Users.Actions,
                     Microsoft.Graph.Identity.DirectoryManagement

.PARAMETER MatchValue
    Substring to match in extensionAttribute3. Default: Spinco.

.PARAMETER LogPath
    CSV audit log path. Default: .\SpincoGroupRemoval_<timestamp>.csv

.PARAMETER TranscriptPath
    Console transcript path. Default: same basename as LogPath with a .log extension.

.PARAMETER Server
    Optional domain controller FQDN or NetBIOS name.

.PARAMETER NonInteractive
    Skip all prompts. Use -WhatIf for a preview.

.PARAMETER SkipDirectLicenses
    Do not connect to Graph or remove directly assigned M365 licenses.
    Only AD license-group memberships are processed.

.PARAMETER TenantId
    Optional tenant ID for Graph app-only auth (with ClientId and CertificateThumbprint).

.PARAMETER ClientId
    Optional app (client) ID for Graph app-only auth.

.PARAMETER CertificateThumbprint
    Optional certificate thumbprint for Graph app-only auth.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1
    Interactive. Choose WhatIf or Live; review groups and direct licenses; confirm.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1 -WhatIf
    Preview group and direct-license removals.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1 -NonInteractive -WhatIf
    Unattended preview.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1 -SkipDirectLicenses
    Interactive, but only AD group memberships (no Graph).
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$MatchValue      = "Spinco",
    [string]$LogPath         = ".\SpincoGroupRemoval_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$TranscriptPath,
    [string]$Server,
    [switch]$NonInteractive,
    [switch]$SkipDirectLicenses,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint
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

function New-ActionResult {
    param(
        $User,
        [string]$ActionType,
        [string]$Status,
        [string]$Message,
        [string]$Group = '',
        [string]$GroupDN = '',
        [string]$LicenseSku = '',
        [string]$LicenseSkuId = ''
    )

    return [pscustomobject]@{
        Timestamp           = Get-Date
        SamAccountName      = $User.SamAccountName
        DisplayName         = $User.DisplayName
        UserPrincipalName   = $User.UserPrincipalName
        DistinguishedName   = $User.DistinguishedName
        Enabled             = $User.Enabled
        ExtensionAttribute3 = $User.extensionAttribute3
        ActionType          = $ActionType
        Group               = $Group
        GroupDN             = $GroupDN
        LicenseSku          = $LicenseSku
        LicenseSkuId        = $LicenseSkuId
        Status              = $Status
        Message             = $Message
    }
}

function Add-ActionResult {
    param([Parameter(Mandatory = $true)]$Result)

    [void]$script:Results.Add($Result)

    try {
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
        Write-Host "Mode: Preview / WhatIf  (from -WhatIf). No AD or Graph license changes will be made." -ForegroundColor Magenta
        return 'WhatIf'
    }

    Write-Host ""
    Write-Host "---- Run mode ----------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  [1] Preview only (WhatIf)   Show groups and direct licenses. No changes." -ForegroundColor Magenta
    Write-Host "  [2] Live removals           Remove AD group memberships AND direct licenses." -ForegroundColor Yellow
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
    Write-Host "WARNING: LIVE mode will:" -ForegroundColor Red
    Write-Host "  - Remove users from the selected AD license groups" -ForegroundColor Red
    if ($script:RemoveDirectLicenses) {
        Write-Host "  - Remove Microsoft 365 licenses assigned DIRECTLY on each user" -ForegroundColor Red
        Write-Host "    (group-based licenses are not stripped here; group removal covers those)" -ForegroundColor Red
    }
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

function Test-IsDirectLicenseAssignment {
    param($State)

    if ($null -eq $State) { return $false }
    $groupId = $null
    try { $groupId = $State.AssignedByGroup } catch { $groupId = $null }
    if ($null -eq $groupId) { return $true }
    $text = [string]$groupId
    if ([string]::IsNullOrWhiteSpace($text)) { return $true }
    if ($text -eq '00000000-0000-0000-0000-000000000000') { return $true }
    return $false
}

function Import-GraphLicenseModules {
    $required = @(
        @{ Name = 'Microsoft.Graph.Authentication'; Commands = @('Connect-MgGraph', 'Get-MgContext') }
        @{ Name = 'Microsoft.Graph.Users'; Commands = @('Get-MgUser') }
        @{ Name = 'Microsoft.Graph.Users.Actions'; Commands = @('Set-MgUserLicense') }
        @{ Name = 'Microsoft.Graph.Identity.DirectoryManagement'; Commands = @('Get-MgSubscribedSku') }
    )

    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($mod in $required) {
        $needImport = $false
        foreach ($cmd in $mod.Commands) {
            if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
                $needImport = $true
                break
            }
        }
        if (-not $needImport) { continue }

        try {
            Import-Module $mod.Name -ErrorAction Stop
        }
        catch {
            [void]$missing.Add($mod.Name)
            Write-ScreenLog "Could not import $($mod.Name): $($_.Exception.Message)" -Level WARN
        }
    }

    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue) -or
        -not (Get-Command Get-MgUser -ErrorAction SilentlyContinue) -or
        -not (Get-Command Set-MgUserLicense -ErrorAction SilentlyContinue)) {
        $hint = if ($missing.Count) { $missing -join ', ' } else { 'Microsoft.Graph.Users, Microsoft.Graph.Users.Actions, Microsoft.Graph.Identity.DirectoryManagement' }
        throw "Microsoft Graph PowerShell SDK is required to remove directly assigned licenses. Install: Install-Module Microsoft.Graph -Scope CurrentUser  (missing: $hint)"
    }
}

function Connect-SpincoGraph {
    Import-GraphLicenseModules

    $neededScopes = @('User.ReadWrite.All', 'Organization.Read.All')
    $ctx = $null
    try { $ctx = Get-MgContext } catch { $ctx = $null }

    $scopeOk = $false
    if ($ctx -and $ctx.Scopes) {
        $have = @($ctx.Scopes)
        $scopeOk = $true
        foreach ($s in $neededScopes) {
            if ($have -contains $s) { continue }
            if ($s -eq 'Organization.Read.All' -and ($have -contains 'Directory.Read.All' -or $have -contains 'Directory.ReadWrite.All')) { continue }
            if ($s -eq 'User.ReadWrite.All' -and ($have -contains 'Directory.ReadWrite.All')) { continue }
            $scopeOk = $false
            break
        }
    }

    if ($scopeOk) {
        Write-ScreenLog "Using existing Graph session (account: $($ctx.Account); tenant: $($ctx.TenantId))." -Level INFO
        return
    }

    if ($script:TenantId -and $script:ClientId -and $script:CertificateThumbprint) {
        Write-ScreenLog "Connecting to Microsoft Graph with app certificate auth..." -Level INFO
        Connect-MgGraph -TenantId $script:TenantId -ClientId $script:ClientId -CertificateThumbprint $script:CertificateThumbprint -NoWelcome -ErrorAction Stop
        return
    }

    Write-ScreenLog "Connecting to Microsoft Graph (scopes: $($neededScopes -join ', '))..." -Level INFO
    Connect-MgGraph -Scopes $neededScopes -NoWelcome -ErrorAction Stop
}

function Get-SkuPartNumberMap {
    $map = @{}
    if (Get-Command Get-MgSubscribedSku -ErrorAction SilentlyContinue) {
        try {
            foreach ($sku in @(Get-MgSubscribedSku -ErrorAction Stop)) {
                if ($sku.SkuId) {
                    $map[[string]$sku.SkuId] = $sku.SkuPartNumber
                }
            }
        }
        catch {
            Write-ScreenLog "Could not load subscribed SKUs (names will be GUIDs): $($_.Exception.Message)" -Level WARN
        }
    }
    return $map
}

function Get-EntraUserForAdUser {
    param($AdUser)

    $upn = $AdUser.UserPrincipalName
    $sam = $AdUser.SamAccountName
    $props = @('Id', 'UserPrincipalName', 'DisplayName', 'AssignedLicenses', 'LicenseAssignmentStates')

    if ($upn) {
        try {
            return Get-MgUser -UserId $upn -Property $props -ErrorAction Stop
        }
        catch {
            Write-ScreenLog "Get-MgUser by UPN '$upn' failed: $($_.Exception.Message)" -Level PROGRESS
        }
    }

    if ($sam) {
        $escaped = ($sam -replace "'", "''")
        $found = @(Get-MgUser -Filter "onPremisesSamAccountName eq '$escaped'" -Property $props -ErrorAction SilentlyContinue)
        if ($found.Count -eq 1) { return $found[0] }
        if ($found.Count -gt 1) {
            throw "Multiple Entra users match onPremisesSamAccountName '$sam'."
        }
    }

    return $null
}

function Get-DirectLicensesForMgUser {
    param($MgUser, [hashtable]$SkuMap)

    $states = @()
    try { $states = @($MgUser.LicenseAssignmentStates) } catch { $states = @() }
    $states = @($states | Where-Object { $_ })

    $direct = @(foreach ($state in $states) {
        if (-not (Test-IsDirectLicenseAssignment -State $state)) { continue }
        $skuId = [string]$state.SkuId
        if ([string]::IsNullOrWhiteSpace($skuId)) { continue }
        $part = $skuId
        if ($SkuMap.ContainsKey($skuId) -and $SkuMap[$skuId]) { $part = [string]$SkuMap[$skuId] }
        [pscustomobject]@{
            SkuId         = $skuId
            SkuPartNumber = $part
            State         = $(if ($state.PSObject.Properties['State']) { [string]$state.State } else { '' })
        }
    })

    return $direct
}

function Get-DirectLicenseInventory {
    param(
        [Parameter(Mandatory = $true)]$Users,
        [hashtable]$SkuMap
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($user in $Users) {
        $index++
        $percent = [int](($index / $Users.Count) * 100)
        Write-Progress -Activity "Scanning Entra ID for directly assigned licenses" `
                       -Status ("[{0}/{1}] {2}" -f $index, $Users.Count, $user.SamAccountName) `
                       -PercentComplete $percent

        $entry = [pscustomobject]@{
            AdUser        = $user
            MgUser        = $null
            DirectLicenses = @()
            LookupStatus  = 'OK'
            LookupMessage = ''
        }

        if (-not $user.UserPrincipalName -and -not $user.SamAccountName) {
            $entry.LookupStatus = 'Skipped'
            $entry.LookupMessage = 'No UPN or sAMAccountName to look up in Entra ID.'
            [void]$rows.Add($entry)
            continue
        }

        try {
            $mgUser = Get-EntraUserForAdUser -AdUser $user
            if (-not $mgUser) {
                $entry.LookupStatus = 'NotFound'
                $entry.LookupMessage = 'No matching Entra ID user.'
            }
            else {
                $entry.MgUser = $mgUser
                $entry.DirectLicenses = @(Get-DirectLicensesForMgUser -MgUser $mgUser -SkuMap $SkuMap)
            }
        }
        catch {
            $entry.LookupStatus = 'Failed'
            $entry.LookupMessage = $_.Exception.Message
        }

        [void]$rows.Add($entry)
    }

    Write-Progress -Activity "Scanning Entra ID for directly assigned licenses" -Completed
    return $rows
}

function Show-DirectLicenseTable {
    param([Parameter(Mandatory = $true)]$Inventory)

    Write-Host ""
    Write-Host "---- Directly assigned Microsoft 365 licenses -----------------------------" -ForegroundColor Cyan
    $preview = foreach ($row in $Inventory) {
        $skus = @($row.DirectLicenses | ForEach-Object { $_.SkuPartNumber })
        [pscustomobject]@{
            SamAccountName    = $row.AdUser.SamAccountName
            UserPrincipalName = $row.AdUser.UserPrincipalName
            Lookup            = $row.LookupStatus
            DirectSkuCount    = $skus.Count
            DirectSkus        = ($skus -join '; ')
        }
    }
    $preview |
        Format-Table SamAccountName, UserPrincipalName, Lookup, DirectSkuCount, DirectSkus -AutoSize -Wrap |
        Out-Host
    Write-Host ""

    $withDirect = @($Inventory | Where-Object { $_.DirectLicenses.Count -gt 0 }).Count
    Write-ScreenLog "$withDirect of $($Inventory.Count) user(s) have one or more directly assigned licenses." -Level INFO
}

function Remove-DirectLicensesFromUser {
    param(
        [Parameter(Mandatory = $true)]$MgUser,
        [Parameter(Mandatory = $true)][string[]]$SkuIds
    )

    $unique = @($SkuIds | Where-Object { $_ } | Select-Object -Unique)
    if ($unique.Count -eq 0) { return }

    $removed = $false
    try {
        Set-MgUserLicense -UserId $MgUser.Id -AddLicenses @() -RemoveLicenses $unique -ErrorAction Stop | Out-Null
        $removed = $true
    }
    catch {
        try {
            Set-MgUserLicense -UserId $MgUser.Id -BodyParameter @{
                addLicenses    = @()
                removeLicenses = $unique
            } -ErrorAction Stop | Out-Null
            $removed = $true
        }
        catch {
            throw
        }
    }

    return $removed
}

function Invoke-DirectLicensePass {
    param([Parameter(Mandatory = $true)]$Inventory)

    $usersWithActions = 0
    $usersSkipped     = 0
    $index            = 0
    $activity         = if ($script:PreviewOnly) {
        "Previewing direct Microsoft 365 license removals (WhatIf)"
    } else {
        "Removing directly assigned Microsoft 365 licenses"
    }

    foreach ($row in $Inventory) {
        $index++
        $user = $row.AdUser
        $percent = [int](($index / $Inventory.Count) * 100)
        Write-Progress -Activity $activity `
                       -Status ("[{0}/{1}] {2}" -f $index, $Inventory.Count, $user.SamAccountName) `
                       -PercentComplete $percent

        Write-Host ""
        Write-Host ("-------- Direct licenses {0}/{1} ({2}%) --------" -f $index, $Inventory.Count, $percent) -ForegroundColor White
        Write-ScreenLog "User       : $(Format-UserIdentity -User $user)" -Level PROGRESS

        if ($row.LookupStatus -ne 'OK') {
            $usersSkipped++
            $status = "Skipped - Entra $($row.LookupStatus)"
            Write-ScreenLog "SKIP $($user.SamAccountName) — $($row.LookupMessage)" -Level SKIP
            Add-ActionResult -Result (New-ActionResult -User $user -ActionType 'DirectLicense' -Status $status -Message $row.LookupMessage)
            continue
        }

        $direct = @($row.DirectLicenses)
        if ($direct.Count -eq 0) {
            $usersSkipped++
            Write-ScreenLog "SKIP $($user.SamAccountName) — no directly assigned licenses (group-based only or unlicensed)." -Level SKIP
            Add-ActionResult -Result (New-ActionResult -User $user -ActionType 'DirectLicense' -Status 'Skipped - no direct licenses' -Message 'No licenses assigned directly on the user.')
            continue
        }

        $usersWithActions++
        $skuList = ($direct | ForEach-Object { $_.SkuPartNumber }) -join ', '
        Write-ScreenLog "Direct SKUs : $skuList" -Level INFO

        if ($script:PreviewOnly) {
            foreach ($lic in $direct) {
                $msg = "WhatIf: would remove direct license $($lic.SkuPartNumber) from $($user.SamAccountName)"
                Write-ScreenLog "WOULD REMOVE DIRECT LICENSE $($user.SamAccountName) ($($user.UserPrincipalName))  sku  $($lic.SkuPartNumber)" -Level WHATIF
                Add-ActionResult -Result (New-ActionResult -User $user -ActionType 'DirectLicense' -Status 'WhatIf - would remove' -Message $msg -LicenseSku $lic.SkuPartNumber -LicenseSkuId $lic.SkuId)
            }
            continue
        }

        $skuIds = @($direct | ForEach-Object { $_.SkuId })
        try {
            [void](Remove-DirectLicensesFromUser -MgUser $row.MgUser -SkuIds $skuIds)
            foreach ($lic in $direct) {
                $msg = "Removed direct license $($lic.SkuPartNumber) from $($user.SamAccountName)"
                Write-ScreenLog "REMOVED DIRECT LICENSE $($user.SamAccountName) ($($user.UserPrincipalName))  sku  $($lic.SkuPartNumber)" -Level SUCCESS
                Add-ActionResult -Result (New-ActionResult -User $user -ActionType 'DirectLicense' -Status 'Removed' -Message $msg -LicenseSku $lic.SkuPartNumber -LicenseSkuId $lic.SkuId)
            }
        }
        catch {
            $batchError = $_.Exception.Message
            Write-ScreenLog "Batch license removal failed for $($user.SamAccountName): $batchError — retrying per SKU." -Level WARN
            foreach ($lic in $direct) {
                try {
                    [void](Remove-DirectLicensesFromUser -MgUser $row.MgUser -SkuIds @($lic.SkuId))
                    $msg = "Removed direct license $($lic.SkuPartNumber) from $($user.SamAccountName)"
                    Write-ScreenLog "REMOVED DIRECT LICENSE $($user.SamAccountName) ($($user.UserPrincipalName))  sku  $($lic.SkuPartNumber)" -Level SUCCESS
                    Add-ActionResult -Result (New-ActionResult -User $user -ActionType 'DirectLicense' -Status 'Removed' -Message $msg -LicenseSku $lic.SkuPartNumber -LicenseSkuId $lic.SkuId)
                }
                catch {
                    $msg = $_.Exception.Message
                    Write-ScreenLog "FAILED  DIRECT LICENSE $($user.SamAccountName) ($($user.UserPrincipalName))  sku  $($lic.SkuPartNumber) — $msg" -Level ERROR
                    Add-ActionResult -Result (New-ActionResult -User $user -ActionType 'DirectLicense' -Status 'Failed' -Message $msg -LicenseSku $lic.SkuPartNumber -LicenseSkuId $lic.SkuId)
                }
            }
        }
    }

    Write-Progress -Activity $activity -Completed

    return [pscustomobject]@{
        UsersWithActions = $usersWithActions
        UsersSkipped     = $usersSkipped
    }
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
            Write-ScreenLog "SKIP group removal for $($user.SamAccountName) — not a direct member of any target license group." -Level SKIP
            Add-ActionResult -Result (New-ActionResult -User $user -ActionType 'ADGroup' -Status 'Skipped - not in any target group' -Message 'User matched extensionAttribute3 but is not a direct member of the configured license groups.')
            continue
        }

        $usersWithActions++
        foreach ($groupDN in $targetMemberships) {
            $group = $Groups[$groupDN]
            Write-ScreenLog "Action     : Remove from license group '$($group.Name)'" -Level INFO
            Write-ScreenLog "             Group DN: $groupDN" -Level PROGRESS

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

            Add-ActionResult -Result (New-ActionResult -User $user -ActionType 'ADGroup' -Status $status -Message $message -Group $group.Name -GroupDN $group.DistinguishedName)
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
        $GroupPassCounts,
        $LicensePassCounts
    )

    $groupRemoved = @($script:Results | Where-Object { $_.ActionType -eq 'ADGroup' -and $_.Status -eq 'Removed' }).Count
    $groupWhatIf  = @($script:Results | Where-Object { $_.ActionType -eq 'ADGroup' -and $_.Status -eq 'WhatIf - would remove' }).Count
    $licRemoved   = @($script:Results | Where-Object { $_.ActionType -eq 'DirectLicense' -and $_.Status -eq 'Removed' }).Count
    $licWhatIf    = @($script:Results | Where-Object { $_.ActionType -eq 'DirectLicense' -and $_.Status -eq 'WhatIf - would remove' }).Count
    $failed       = @($script:Results | Where-Object { $_.Status -eq 'Failed' }).Count

    $groupActionUsers = 0
    $groupSkipUsers   = 0
    if ($GroupPassCounts) {
        $groupActionUsers = $GroupPassCounts.UsersWithActions
        $groupSkipUsers   = $GroupPassCounts.UsersSkipped
    }
    $licActionUsers = 0
    $licSkipUsers   = 0
    if ($LicensePassCounts) {
        $licActionUsers = $LicensePassCounts.UsersWithActions
        $licSkipUsers   = $LicensePassCounts.UsersSkipped
    }

    Write-Host ""
    Write-Banner @(
        " SUMMARY"
        " Users scanned                    : $($Users.Count)"
        " AD group — users with actions    : $groupActionUsers"
        " AD group — users skipped         : $groupSkipUsers"
        " AD group — removed / WhatIf      : $groupRemoved / $groupWhatIf"
        " Direct license — users with SKUs : $licActionUsers"
        " Direct license — users skipped   : $licSkipUsers"
        " Direct license — removed / WhatIf: $licRemoved / $licWhatIf"
        " Failures                         : $failed"
        " Total CSV rows                   : $($script:Results.Count)"
        " CSV log                          : $script:ResolvedLogPath"
        " Transcript                       : $script:ResolvedTranscriptPath"
    )

    if ($script:Results.Count -gt 0) {
        Write-Host "---- Actions by type ------------------------------------------------------" -ForegroundColor Cyan
        $script:Results |
            Group-Object ActionType |
            Select-Object @{n = 'ActionType'; e = { $_.Name } }, @{n = 'Count'; e = { $_.Count } } |
            Format-Table -AutoSize |
            Out-Host

        Write-Host "---- AD groups -------------------------------------------------------------" -ForegroundColor Cyan
        $script:Results |
            Where-Object { $_.ActionType -eq 'ADGroup' -and $_.Group } |
            Group-Object Group |
            Select-Object @{n = 'Group'; e = { $_.Name } }, @{n = 'Actions'; e = { $_.Count } } |
            Format-Table -AutoSize |
            Out-Host

        Write-Host "---- Direct licenses (SKU) -------------------------------------------------" -ForegroundColor Cyan
        $script:Results |
            Where-Object { $_.ActionType -eq 'DirectLicense' -and $_.LicenseSku } |
            Group-Object LicenseSku |
            Select-Object @{n = 'LicenseSku'; e = { $_.Name } }, @{n = 'Actions'; e = { $_.Count } } |
            Format-Table -AutoSize |
            Out-Host

        Write-Host "---- Actions by status ----------------------------------------------------" -ForegroundColor Cyan
        $script:Results |
            Group-Object Status |
            Select-Object @{n = 'Status'; e = { $_.Name } }, @{n = 'Count'; e = { $_.Count } } |
            Format-Table -AutoSize |
            Out-Host

        Write-Host "---- Detail (user -> action -> target -> status) --------------------------" -ForegroundColor Cyan
        $script:Results |
            Select-Object SamAccountName, UserPrincipalName, ActionType, Group, LicenseSku, Status |
            Format-Table -AutoSize -Wrap |
            Out-Host
    }
    else {
        Write-ScreenLog "Nothing was logged. No group memberships or direct licenses to process." -Level WARN
    }
}

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
$script:IsInteractive           = Test-ShouldPrompt
$script:Server                  = $Server
$script:TenantId                = $TenantId
$script:ClientId                = $ClientId
$script:CertificateThumbprint   = $CertificateThumbprint
$script:Results                 = [System.Collections.Generic.List[object]]::new()
$script:TranscriptStarted       = $false
$script:UserCancelled           = $false
$script:PreviewOnly             = [bool]$WhatIfPreference -or $PSBoundParameters.ContainsKey('WhatIf')
$script:RemoveDirectLicenses    = -not $SkipDirectLicenses

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
            " This run can remove AD license groups AND directly assigned M365 licenses."
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

        if (-not $SkipDirectLicenses) {
            Write-Host ""
            Write-Host "---- Direct Microsoft 365 licenses ------------------------------------------" -ForegroundColor Cyan
            Write-Host "A user can still have Office 365 / Microsoft 365 licenses assigned directly" -ForegroundColor Gray
            Write-Host "in the admin center even after they are removed from the AD groups above." -ForegroundColor Gray
            Write-Host "Those direct assignments are identified in Entra ID (assignedByGroup is empty)." -ForegroundColor Gray
            $script:RemoveDirectLicenses = Read-YesNo -Message "Also remove directly assigned Microsoft 365 licenses from each matching user?" -Default $true
        }
    }
    elseif ($script:PreviewOnly) {
        Write-Host "Non-interactive WhatIf preview." -ForegroundColor Magenta
    }
    else {
        Write-Host "Non-interactive LIVE run. Group memberships and direct licenses will be removed." -ForegroundColor Yellow
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
        'WHATIF - preview only; no group or license changes will be made'
    } else {
        'LIVE - users WILL be removed from groups and/or direct licenses'
    }
    $directText = if ($script:RemoveDirectLicenses) { 'Yes (Entra ID direct assignments)' } else { 'No' }

    Write-Banner @(
        " Remove-SpincoFromLicenseGroups"
        " Started          : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        " Mode             : $modeText"
        " Match            : extensionAttribute3 like '*$MatchValue*'"
        " Target DC        : $(if ($script:Server) { $script:Server } else { '(default)' })"
        " Direct licenses  : $directText"
        " CSV log          : $script:ResolvedLogPath"
        " Transcript       : $script:ResolvedTranscriptPath"
        " Groups           : $($GroupNames.Count) selected"
    )

    $adParams = Get-AdCmdletParams

    # -----------------------------------------------------------------------
    # Resolve groups once (Name OR sAMAccountName)
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

    $inventory = $null
    if ($script:RemoveDirectLicenses) {
        try {
            Connect-SpincoGraph
            $skuMap = Get-SkuPartNumberMap
            Write-ScreenLog "Scanning $($Users.Count) user(s) in Entra ID for directly assigned licenses..." -Level INFO
            $inventory = Get-DirectLicenseInventory -Users $Users -SkuMap $skuMap
            Show-DirectLicenseTable -Inventory $inventory
        }
        catch {
            $graphError = $_.Exception.Message
            Write-ScreenLog $graphError -Level ERROR
            if ($script:IsInteractive -and (Read-YesNo -Message "Graph lookup failed. Continue with AD group removals only?" -Default $false)) {
                $script:RemoveDirectLicenses = $false
                $inventory = $null
            }
            else {
                throw "Direct license lookup failed: $graphError"
            }
        }
    }

    $directActionable = 0
    if ($inventory) {
        $directActionable = @($inventory | Where-Object { $_.DirectLicenses.Count -gt 0 }).Count
    }

    if ($script:IsInteractive) {
        $bits = @()
        $bits += "$actionable group membership(s)"
        if ($script:RemoveDirectLicenses) { $bits += "$directActionable user(s) with direct licenses" }
        $continueHint = if ($script:PreviewOnly) {
            "Continue with WHATIF preview ($($bits -join '; '))?"
        } else {
            "Continue with LIVE removal ($($bits -join '; '))?"
        }
        if (-not (Read-YesNo -Message $continueHint -Default $true)) {
            Write-Host "Cancelled after review. No memberships or licenses were changed." -ForegroundColor Yellow
            $script:UserCancelled = $true
            return
        }

        if (-not $script:PreviewOnly) {
            if (-not (Confirm-LiveRemoval)) {
                Write-Host "Live run not confirmed. No memberships or licenses were changed." -ForegroundColor Yellow
                $script:UserCancelled = $true
                return
            }
        }
    }

    $groupPassCounts = Invoke-LicenseGroupPass -Users $Users -Groups $Groups -AdParams $adParams
    $licensePassCounts = $null
    if ($script:RemoveDirectLicenses -and $inventory) {
        $licensePassCounts = Invoke-DirectLicensePass -Inventory $inventory
    }
    Write-RunSummary -Users $Users -GroupPassCounts $groupPassCounts -LicensePassCounts $licensePassCounts

    $anyActionable = ($actionable -gt 0) -or ($directActionable -gt 0)
    if ($script:IsInteractive -and $script:PreviewOnly -and $anyActionable) {
        Write-Host ""
        Write-Host "WhatIf preview finished. No memberships or licenses have been changed yet." -ForegroundColor Magenta
        if (Read-YesNo -Message "Run LIVE removals now for the same users (groups and direct licenses)?" -Default $false) {
            if (Confirm-LiveRemoval) {
                $script:PreviewOnly = $false
                $WhatIfPreference = $false
                Write-Banner @(
                    " LIVE PASS"
                    " Mode        : LIVE - groups and/or direct licenses WILL be changed"
                    " Users       : $($Users.Count) matching extensionAttribute3"
                )
                $groupPassCounts = Invoke-LicenseGroupPass -Users $Users -Groups $Groups -AdParams $adParams
                $licensePassCounts = $null
                if ($script:RemoveDirectLicenses -and $inventory) {
                    $licensePassCounts = Invoke-DirectLicensePass -Inventory $inventory
                }
                Write-RunSummary -Users $Users -GroupPassCounts $groupPassCounts -LicensePassCounts $licensePassCounts
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

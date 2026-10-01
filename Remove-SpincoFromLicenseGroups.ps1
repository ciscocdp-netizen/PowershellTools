#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Report and remove Office 365 licenses for Spinco or Remainco users
    (AD license groups and/or direct Entra assignments).

.DESCRIPTION
    When run without -NonInteractive (the default), the script is a fully
    interactive loop: pick a task, answer each prompt, then return to the
    main menu until you choose Q.

      1. License source report — for Spinco or Remainco users, show HOW each user
         gets Office 365 (AD license group, Entra group, and/or direct assignment)
         and export a CSV.
      2. Remove by extensionAttribute3 — find Spinco or Remainco users in AD and
         remove them from the AD groups that apply the license and/or strip
         directly assigned SKUs.
      3. Remove from CSV — file picker, choose which column is the user id, then
         remove licenses the same way.

    Direct vs group-based:
      - Typical path in this environment: AD group membership -> group-based license.
      - Direct licenses were assigned in the M365 admin center and are identified
        via licenseAssignmentStates where assignedByGroup is empty.

    Requires Microsoft Graph PowerShell for Entra lookups and direct-license removal:
      Install-Module Microsoft.Graph -Scope CurrentUser

.PARAMETER Workflow
    Report, RemoveByAttribute, or RemoveFromCsv. Omit to choose from the interactive menu.

.PARAMETER MatchValue
    Substring in extensionAttribute3 (Spinco or Remainco). Interactive menu offers both.

.PARAMETER CsvPath
    CSV to import for RemoveFromCsv. Interactive runs can pick a file instead.

.PARAMETER IdentityColumn
    CSV header that contains the user id (sAMAccountName, UPN, or email).

.PARAMETER ReportPath
    Where to write the license-source report. Interactive runs can pick a save path.

.PARAMETER RemovalTarget
    Groups (AD license groups only), Direct (Entra direct SKUs only), or Both.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1
    Interactive menu: report, Spinco/Remainco removal, or CSV import.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1 -Workflow Report -MatchValue Remainco -ReportPath .\remainco-licenses.csv
    Export how Remainco users receive their licenses.

.EXAMPLE
    .\Remove-SpincoFromLicenseGroups.ps1 -Workflow RemoveFromCsv -CsvPath .\leavers.csv -IdentityColumn UserPrincipalName -WhatIf
    Preview license removal for a CSV of users.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$Workflow,
    [string]$MatchValue      = "Spinco",
    [string]$LogPath,
    [string]$TranscriptPath,
    [string]$Server,
    [switch]$NonInteractive,
    [switch]$SkipDirectLicenses,
    [switch]$SkipGroupRemoval,
    [string]$RemovalTarget,
    [string]$CsvPath,
    [string]$IdentityColumn,
    [string]$ReportPath,
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

    # Always use Read-Host in a real console. [Console]::IsInputRedirected is
    # true in some Windows PowerShell hosts even when the user is at a prompt,
    # which previously made the menu treat Enter as EOF and quit immediately.
    try {
        return Read-Host $PromptText
    }
    catch {
        Write-Host "$PromptText " -NoNewline
        try {
            $line = [Console]::In.ReadLine()
        }
        catch {
            $line = ''
        }
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

function Read-MainWorkflow {
    param([switch]$ForceMenu)

    if (-not $ForceMenu -and $script:Workflow) {
        switch -Regex ($script:Workflow) {
            '^(Report|RemoveByAttribute|RemoveFromCsv)$' { return $script:Workflow }
            default { throw "Unknown Workflow '$($script:Workflow)'. Use Report, RemoveByAttribute, or RemoveFromCsv." }
        }
    }
    if (-not $ForceMenu -and -not $script:IsInteractive) {
        if ($script:CsvPath) { return 'RemoveFromCsv' }
        if ($script:ReportPath) { return 'Report' }
        return 'RemoveByAttribute'
    }

    Write-Host ""
    Write-Host "---- What do you want to do? ------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  [1] License source report     How Spinco/Remainco users get Office 365 (export CSV)" -ForegroundColor Cyan
    Write-Host "  [2] Remove licenses           Find users by extensionAttribute3 (Spinco / Remainco)" -ForegroundColor Yellow
    Write-Host "  [3] Remove licenses from CSV  File picker, choose the user-id column" -ForegroundColor Yellow
    Write-Host "  [Q] Quit" -ForegroundColor Gray
    Write-Host "Type 1, 2, 3, or Q and press Enter. Press Enter alone to pick [1]." -ForegroundColor Gray
    Write-Host ""

    while ($true) {
        $choice = Read-Prompt -Message "Select a workflow" -Default "1"
        switch -Regex ($choice) {
            '^(1|r|report)$' { return 'Report' }
            '^(2|a|attribute|spinco|remainco)$' { return 'RemoveByAttribute' }
            '^(3|c|csv)$' { return 'RemoveFromCsv' }
            '^(q|quit|exit)$' { return 'Quit' }
            default {
                Write-Host "Enter 1 (Report), 2 (Remove by Spinco/Remainco), 3 (CSV), or Q." -ForegroundColor Yellow
            }
        }
    }
}

function Read-Population {
    param([string]$Current)

    $default = '1'
    if ($Current -match '^(?i)remainco$') { $default = '2' }
    elseif ($Current -and $Current -notmatch '^(?i)spinco$') { $default = '3' }

    Write-Host ""
    Write-Host "---- User population (extensionAttribute3) ----------------------------------" -ForegroundColor Cyan
    Write-Host "  [1] Spinco" -ForegroundColor Cyan
    Write-Host "  [2] Remainco" -ForegroundColor Cyan
    Write-Host "  [3] Custom value" -ForegroundColor Gray
    Write-Host ""

    while ($true) {
        $choice = Read-Prompt -Message "Which users?" -Default $default
        switch -Regex ($choice) {
            '^(1|s|spinco)$'    { return 'Spinco' }
            '^(2|r|remainco)$'  { return 'Remainco' }
            '^(3|c|custom)$' {
                $custom = Read-Prompt -Message "extensionAttribute3 contains" -Default $(if ($Current) { $Current } else { 'Spinco' })
                if ([string]::IsNullOrWhiteSpace($custom)) {
                    Write-Host "Value cannot be empty." -ForegroundColor Yellow
                    continue
                }
                return $custom
            }
            default {
                Write-Host "Enter 1 (Spinco), 2 (Remainco), or 3 (Custom)." -ForegroundColor Yellow
            }
        }
    }
}

function Read-RemovalTarget {
    if ($script:SkipGroupRemoval -and $script:SkipDirectLicenses) {
        throw "Cannot use -SkipGroupRemoval and -SkipDirectLicenses together."
    }
    if (-not $script:IsInteractive) {
        if ($script:SkipGroupRemoval) { return 'Direct' }
        if ($script:SkipDirectLicenses) { return 'Groups' }
        if ($script:RemovalTarget) {
            switch -Regex ($script:RemovalTarget) {
                '^(Groups|Direct|Both)$' { return $script:RemovalTarget }
                default { throw "Unknown RemovalTarget '$($script:RemovalTarget)'. Use Groups, Direct, or Both." }
            }
        }
        return 'Both'
    }

    $default = '3'
    if ($script:SkipGroupRemoval) { $default = '2' }
    elseif ($script:SkipDirectLicenses) { $default = '1' }
    elseif ($script:RemovalTarget -match '^(?i)Groups$') { $default = '1' }
    elseif ($script:RemovalTarget -match '^(?i)Direct$') { $default = '2' }
    elseif ($script:RemovalTarget -match '^(?i)Both$') { $default = '3' }

    Write-Host ""
    Write-Host "---- How should licenses be removed? ----------------------------------------" -ForegroundColor Cyan
    Write-Host "  [1] AD license groups only     Typical — users get licenses from groups" -ForegroundColor Green
    Write-Host "  [2] Direct assignments only    Strip SKUs assigned in the M365 admin center" -ForegroundColor Yellow
    Write-Host "  [3] Both                       Groups and leftover direct assignments" -ForegroundColor Yellow
    Write-Host ""

    while ($true) {
        $choice = Read-Prompt -Message "Removal target" -Default $default
        switch -Regex ($choice) {
            '^(1|g|group|groups)$' { return 'Groups' }
            '^(2|d|direct)$'       { return 'Direct' }
            '^(3|b|both)$'         { return 'Both' }
            default {
                Write-Host "Enter 1 (Groups), 2 (Direct), or 3 (Both)." -ForegroundColor Yellow
            }
        }
    }
}

function Read-DomainController {
    param([string]$Current)

    Write-Host ""
    Write-Host "---- Domain controller ------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "Press Enter to use the default DC for this machine." -ForegroundColor Gray
    if ($Current) {
        return (Read-Prompt -Message "Domain controller FQDN or NetBIOS name" -Default $Current)
    }
    return (Read-Prompt -Message "Domain controller FQDN or NetBIOS name (blank = default)")
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
    if ($script:RemoveFromGroups) {
        Write-Host "  - Remove users from the selected AD license groups (typical license path)" -ForegroundColor Red
    }
    if ($script:RemoveDirectLicenses) {
        Write-Host "  - Remove Microsoft 365 licenses assigned DIRECTLY on each user" -ForegroundColor Red
        Write-Host "    (group-based SKUs stay until the user is out of the applying group)" -ForegroundColor Red
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

function Test-IsGraphAuthError {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
    return $Message -match 'Authentication needed|Please call Connect-MgGraph|Access token is empty|token is expired|Lifetime validation failed|invalid_grant|AADSTS70043|AADSTS50058|MSAL|Unauthorized|InvalidAuthenticationToken|CompactToken|401'
}

function Test-IsGraphNotFoundError {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
    return $Message -match 'does not exist|Request_ResourceNotFound|ErrorCode:\s*Request_ResourceNotFound|NotFound'
}

function Get-GraphScopeShortName {
    param([string]$Scope)

    $s = [string]$Scope
    if ($s -match '^https://graph\.microsoft\.com/(.+)$') { return $Matches[1] }
    return $s
}

function Test-GraphScopesOk {
    param($Context, [string[]]$NeededScopes)

    if (-not $Context -or -not $Context.Scopes) { return $false }
    $have = @(
        $Context.Scopes |
            ForEach-Object { Get-GraphScopeShortName $_ } |
            Where-Object { $_ -and $_ -notin @('offline_access', 'openid', 'profile') }
    )
    foreach ($s in $NeededScopes) {
        $need = Get-GraphScopeShortName $s
        if ($need -in @('offline_access', 'openid', 'profile')) { continue }
        if ($have -contains $need) { continue }
        if ($need -eq 'Organization.Read.All' -and ($have -contains 'Directory.Read.All' -or $have -contains 'Directory.ReadWrite.All')) { continue }
        if ($need -eq 'Group.Read.All' -and ($have -contains 'Directory.Read.All' -or $have -contains 'Directory.ReadWrite.All')) { continue }
        if ($need -eq 'User.ReadWrite.All' -and ($have -contains 'Directory.ReadWrite.All')) { continue }
        if ($need -eq 'User.Read.All' -and ($have -contains 'User.ReadWrite.All' -or $have -contains 'Directory.Read.All' -or $have -contains 'Directory.ReadWrite.All')) { continue }
        return $false
    }
    return $true
}

function Get-RequiredGraphScopes {
    if ($script:GraphNeedWrite) {
        return @('User.ReadWrite.All', 'Organization.Read.All', 'Group.Read.All')
    }
    return @('User.Read.All', 'Organization.Read.All', 'Group.Read.All')
}

function Enable-GraphNetwork {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }
    try {
        $proxy = [Net.WebRequest]::DefaultWebProxy
        if ($proxy) {
            $proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
        }
    } catch { }
}

function Invoke-GraphApi {
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory = $true)][string]$Path,
        $Body
    )

    Enable-GraphNetwork
    if (-not $script:GraphAccessToken) {
        throw "Authentication needed. Please complete Graph sign-in."
    }

    $uri = if ($Path -match '^https://') { $Path } else { "https://graph.microsoft.com/v1.0/$Path" }
    $headers = @{
        Authorization    = "Bearer $($script:GraphAccessToken)"
        ConsistencyLevel = 'eventual'
    }

    try {
        if ($Method -eq 'GET') {
            $resp = Invoke-WebRequest -Method GET -Uri $uri -Headers $headers -UseBasicParsing -ErrorAction Stop
        }
        else {
            $headers['Content-Type'] = 'application/json'
            $json = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 8 -Compress } else { '' }
            $resp = Invoke-WebRequest -Method $Method -Uri $uri -Headers $headers -Body $json -UseBasicParsing -ErrorAction Stop
        }
        if ($resp.Content) { return ($resp.Content | ConvertFrom-Json) }
        return $null
    }
    catch {
        $content = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $content = $_.ErrorDetails.Message }
        elseif ($_.Exception.Response) {
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                if ($stream) {
                    if ($stream.CanSeek) { [void]$stream.Seek(0, [System.IO.SeekOrigin]::Begin) }
                    $reader = New-Object System.IO.StreamReader($stream)
                    $content = $reader.ReadToEnd()
                    $reader.Close()
                }
            }
            catch { }
        }
        if ($content) {
            try {
                $err = $content | ConvertFrom-Json
                $code = $null
                $msg = $null
                try { $code = [string]$err.error.code } catch { }
                try { $msg = [string]$err.error.message } catch { }
                if ($code -or $msg) { throw ("{0}: {1}" -f $code, $msg) }
            }
            catch {
                if ($_.Exception.Message -match '^\w+:') { throw }
            }
            throw $content
        }
        throw
    }
}

function Resolve-OAuthErrorMessage {
    param([string]$Message)

    $tenant = if ($script:TenantId) { $script:TenantId } else { 'organizations' }
    $clientId = if ($script:ClientId) { $script:ClientId } else { '14d82eec-204b-4c2f-b7e8-296a70dab67e' }
    if ($Message -match 'AADSTS65001|AADSTS65004|consent|admin approval|Authorization_RequestDenied') {
        return "Admin consent is required for Microsoft Graph PowerShell. Ask a Global Admin to open: https://login.microsoftonline.com/$tenant/adminconsent?client_id=$clientId  then re-run this script. Detail: $Message"
    }
    if ($Message -match 'AADSTS53003|AADSTS50005|device.?code|AADSTS7000218|blocked by Conditional Access') {
        return "Sign-in was blocked by Conditional Access or tenant policy. Sign in with an allowed work account, or use app-certificate auth (-TenantId, -ClientId, -CertificateThumbprint). Detail: $Message"
    }
    return $Message
}

function Test-GraphSession {
    if ($script:GraphAccessToken) {
        try {
            $org = Invoke-GraphApi -Path 'organization?$select=id'
            if ($org) { return $true }
        }
        catch {
            try {
                $me = Invoke-GraphApi -Path 'me?$select=id'
                if ($me) { return $true }
            }
            catch { return $false }
        }
    }

    try {
        $ctx = Get-MgContext -ErrorAction Stop
        if (-not $ctx) { return $false }

        if (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
            [void](Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id' -ErrorAction Stop)
            return $true
        }
        if (Get-Command Get-MgSubscribedSku -ErrorAction SilentlyContinue) {
            [void]@(Get-MgSubscribedSku -ErrorAction Stop | Select-Object -First 1)
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Suspend-RunTranscript {
    if ($script:TranscriptStarted) {
        try { Stop-Transcript -WhatIf:$false | Out-Null } catch { }
        $script:TranscriptStarted = $false
        $script:TranscriptPaused = $true
    }
}

function Resume-RunTranscript {
    if (-not $script:TranscriptPaused) { return }
    $script:TranscriptPaused = $false
    if ($script:ResolvedTranscriptPath) {
        try {
            Start-Transcript -Path $script:ResolvedTranscriptPath -Append -ErrorAction Stop -WhatIf:$false | Out-Null
            $script:TranscriptStarted = $true
        }
        catch {
            Write-Warning "Could not resume transcript: $($_.Exception.Message)"
        }
    }
}

function Invoke-GraphConnect {
    param(
        [Parameter(Mandatory = $true)][string[]]$Scopes
    )

    $cmd = Get-Command Connect-MgGraph -ErrorAction Stop
    $params = @{
        Scopes      = $Scopes
        ErrorAction = 'Stop'
    }
    if ($cmd.Parameters.ContainsKey('ContextScope')) {
        $params.ContextScope = 'Process'
    }
    if ($script:TenantId -and $cmd.Parameters.ContainsKey('TenantId')) {
        $params.TenantId = $script:TenantId
    }
    # Regular Microsoft 365 sign-in window (browser / Windows account picker).
    # Do not pass -UseDeviceCode.
    Connect-MgGraph @params
}

function Import-GraphLicenseModules {
    $required = @(
        @{ Name = 'Microsoft.Graph.Authentication'; Commands = @('Connect-MgGraph', 'Get-MgContext', 'Invoke-MgGraphRequest', 'Disconnect-MgGraph') }
        @{ Name = 'Microsoft.Graph.Users'; Commands = @('Get-MgUser') }
        @{ Name = 'Microsoft.Graph.Users.Actions'; Commands = @('Set-MgUserLicense') }
        @{ Name = 'Microsoft.Graph.Identity.DirectoryManagement'; Commands = @('Get-MgSubscribedSku') }
        @{ Name = 'Microsoft.Graph.Groups'; Commands = @('Get-MgGroup') }
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
        -not (Get-Command Get-MgUser -ErrorAction SilentlyContinue)) {
        $hint = if ($missing.Count) { $missing -join ', ' } else { 'Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement' }
        throw "Microsoft Graph PowerShell SDK is required. Install: Install-Module Microsoft.Graph -Scope CurrentUser  (missing: $hint)"
    }
}

function Connect-SpincoGraph {
    Import-GraphLicenseModules
    $neededScopes = @(Get-RequiredGraphScopes)

    $ctx = $null
    try { $ctx = Get-MgContext } catch { $ctx = $null }

    if ((Test-GraphScopesOk -Context $ctx -NeededScopes $neededScopes) -and (Test-GraphSession)) {
        Write-ScreenLog "Using existing Graph session (account: $($ctx.Account); tenant: $($ctx.TenantId))." -Level INFO
        $script:GraphReady = $true
        return
    }

    if ($ctx) {
        Write-ScreenLog "Existing Graph session is missing, expired, or not authenticated. Signing in again..." -Level WARN
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    }

    if ($script:TenantId -and $script:ClientId -and $script:CertificateThumbprint) {
        Write-ScreenLog "Connecting to Microsoft Graph with app certificate auth..." -Level INFO
        $certParams = @{
            TenantId              = $script:TenantId
            ClientId              = $script:ClientId
            CertificateThumbprint = $script:CertificateThumbprint
            ErrorAction           = 'Stop'
        }
        $cmd = Get-Command Connect-MgGraph
        if ($cmd.Parameters.ContainsKey('NoWelcome')) { $certParams.NoWelcome = $true }
        Connect-MgGraph @certParams
    }
    else {
        Suspend-RunTranscript
        try {
            if ($script:IsInteractive) {
                Write-Host ""
                Write-Host "---- Microsoft 365 sign-in -----------------------------------------------" -ForegroundColor Cyan
                Write-Host " A sign-in window should open. Sign in with your work or school account." -ForegroundColor Yellow
                Write-Host " After you finish in the browser/window, this script will continue." -ForegroundColor Gray
                Write-Host ""
            }
            else {
                Write-ScreenLog "Connecting to Microsoft Graph (interactive sign-in)..." -Level INFO
            }
            Invoke-GraphConnect -Scopes $neededScopes
        }
        finally {
            Resume-RunTranscript
        }
    }

    if (-not (Test-GraphSession)) {
        throw "Microsoft 365 sign-in did not complete. Close any leftover browser tabs and run the workflow again."
    }

    $ctx = $null
    try { $ctx = Get-MgContext } catch { }
    $who = if ($ctx -and $ctx.Account) { $ctx.Account } else { 'signed-in' }
    $tid = if ($ctx -and $ctx.TenantId) { $ctx.TenantId } else { '' }
    Write-ScreenLog "Connected to Microsoft Graph (account: $who; tenant: $tid)." -Level SUCCESS
    $script:GraphReady = $true
}

function Initialize-GraphForLicenses {
    param(
        [switch]$Required,
        [switch]$AllowWrite
    )

    $script:GraphNeedWrite = [bool]$AllowWrite
    $script:GraphReady = $false
    try {
        Connect-SpincoGraph
        return $true
    }
    catch {
        Write-ScreenLog $_.Exception.Message -Level ERROR
    }

    if ($Required) {
        throw "Microsoft 365 sign-in is required for Entra / direct-license work. Sign in when the Microsoft prompt appears, then retry."
    }

    Write-ScreenLog "Continuing without Entra ID. Direct / Entra license columns will be empty until you sign in." -Level WARN
    return $false
}

function Get-SkuPartNumberMap {
    $map = @{}
    if (-not $script:GraphReady) { return $map }
    if ($script:GraphAccessToken) {
        try {
            $skus = Invoke-GraphApi -Path 'subscribedSkus'
            foreach ($sku in @($skus.value)) {
                if ($sku.skuId) {
                    $map[[string]$sku.skuId] = $sku.skuPartNumber
                }
            }
            return $map
        }
        catch {
            if (Test-IsGraphAuthError $_.Exception.Message) {
                $script:GraphReady = $false
                throw
            }
            Write-ScreenLog "Could not load subscribed SKUs (names will be GUIDs): $($_.Exception.Message)" -Level WARN
            return $map
        }
    }
    if (Get-Command Get-MgSubscribedSku -ErrorAction SilentlyContinue) {
        try {
            foreach ($sku in @(Get-MgSubscribedSku -ErrorAction Stop)) {
                if ($sku.SkuId) {
                    $map[[string]$sku.SkuId] = $sku.SkuPartNumber
                }
            }
        }
        catch {
            if (Test-IsGraphAuthError $_.Exception.Message) {
                $script:GraphReady = $false
                throw
            }
            Write-ScreenLog "Could not load subscribed SKUs (names will be GUIDs): $($_.Exception.Message)" -Level WARN
        }
    }
    return $map
}

function Get-EntraUserForAdUser {
    param($AdUser)

    if (-not $script:GraphReady) { return $null }

    $upn = $AdUser.UserPrincipalName
    $sam = $AdUser.SamAccountName
    $props = @('Id', 'UserPrincipalName', 'DisplayName', 'AssignedLicenses', 'LicenseAssignmentStates')
    $select = 'id,userPrincipalName,displayName,assignedLicenses,licenseAssignmentStates'

    if ($script:GraphAccessToken) {
        try {
            if ($upn) {
                try {
                    $enc = [uri]::EscapeDataString($upn)
                    return Invoke-GraphApi -Path ("users/{0}?`$select={1}" -f $enc, $select)
                }
                catch {
                    if (Test-IsGraphAuthError $_.Exception.Message) { throw }
                    if ($sam -and (Test-IsGraphNotFoundError $_.Exception.Message)) { }
                    elseif ($sam) {
                        Write-ScreenLog "Graph user lookup by UPN '$upn' failed: $($_.Exception.Message)" -Level WARN
                    }
                    else {
                        if (Test-IsGraphNotFoundError $_.Exception.Message) { return $null }
                        throw
                    }
                }
            }
            if ($sam) {
                $escaped = ($sam -replace "'", "''")
                $filter = [uri]::EscapeDataString("onPremisesSamAccountName eq '$escaped'")
                $found = Invoke-GraphApi -Path ("users?`$filter={0}&`$select={1}" -f $filter, $select)
                $vals = @()
                try { $vals = @($found.value) } catch { $vals = @($found) }
                $vals = @($vals | Where-Object { $_ })
                if ($vals.Count -eq 1) { return $vals[0] }
                if ($vals.Count -gt 1) {
                    throw "Multiple Entra users match onPremisesSamAccountName '$sam'."
                }
            }
            return $null
        }
        catch {
            if (Test-IsGraphAuthError $_.Exception.Message) {
                $script:GraphReady = $false
                throw [System.InvalidOperationException]::new(
                    "Microsoft Graph authentication is required. $($_.Exception.Message)"
                )
            }
            throw
        }
    }

    try {
        if ($upn) {
            try {
                return Get-MgUser -UserId $upn -Property $props -ErrorAction Stop
            }
            catch {
                if (Test-IsGraphAuthError $_.Exception.Message) { throw }
                if ($sam -and (Test-IsGraphNotFoundError $_.Exception.Message)) {
                    # Fall through to sAMAccountName lookup.
                }
                elseif ($sam) {
                    Write-ScreenLog "Get-MgUser by UPN '$upn' failed: $($_.Exception.Message)" -Level WARN
                }
                else {
                    if (Test-IsGraphNotFoundError $_.Exception.Message) { return $null }
                    throw
                }
            }
        }

        if ($sam) {
            $escaped = ($sam -replace "'", "''")
            $found = @(Get-MgUser -Filter "onPremisesSamAccountName eq '$escaped'" -Property $props -ErrorAction Stop)
            if ($found.Count -eq 1) { return $found[0] }
            if ($found.Count -gt 1) {
                throw "Multiple Entra users match onPremisesSamAccountName '$sam'."
            }
        }

        return $null
    }
    catch {
        if (Test-IsGraphAuthError $_.Exception.Message) {
            $script:GraphReady = $false
            throw [System.InvalidOperationException]::new(
                "Microsoft Graph authentication is required. $($_.Exception.Message)"
            )
        }
        throw
    }
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

function Resolve-EntraGroupDisplayName {
    param([string]$GroupId)

    if ([string]::IsNullOrWhiteSpace($GroupId)) { return '' }
    if ($script:EntraGroupCache.ContainsKey($GroupId)) {
        return [string]$script:EntraGroupCache[$GroupId]
    }

    $name = $GroupId
    if ($script:GraphAccessToken) {
        try {
            $g = Invoke-GraphApi -Path ("groups/{0}?`$select=id,displayName" -f $GroupId)
            if ($g.displayName) { $name = [string]$g.displayName }
        }
        catch { }
        $script:EntraGroupCache[$GroupId] = $name
        return $name
    }
    if (Get-Command Get-MgGroup -ErrorAction SilentlyContinue) {
        try {
            $g = Get-MgGroup -GroupId $GroupId -Property Id, DisplayName -ErrorAction Stop
            if ($g.DisplayName) { $name = [string]$g.DisplayName }
        }
        catch { }
    }
    $script:EntraGroupCache[$GroupId] = $name
    return $name
}

function Get-GroupAssignedLicensesForMgUser {
    param($MgUser, [hashtable]$SkuMap)

    if (-not $SkuMap) { $SkuMap = @{} }
    $states = @()
    try { $states = @($MgUser.LicenseAssignmentStates) } catch { $states = @() }
    $states = @($states | Where-Object { $_ })

    return @(foreach ($state in $states) {
        if (Test-IsDirectLicenseAssignment -State $state) { continue }
        $skuId = [string]$state.SkuId
        if ([string]::IsNullOrWhiteSpace($skuId)) { continue }
        $groupId = [string]$state.AssignedByGroup
        $part = $skuId
        if ($SkuMap.ContainsKey($skuId) -and $SkuMap[$skuId]) { $part = [string]$SkuMap[$skuId] }
        [pscustomobject]@{
            SkuId          = $skuId
            SkuPartNumber  = $part
            AssignedByGroup = $groupId
            GroupName      = (Resolve-EntraGroupDisplayName -GroupId $groupId)
            State          = $(if ($state.PSObject.Properties['State']) { [string]$state.State } else { '' })
        }
    })
}

function Get-GraphUserSelectProperties {
    return 'id,userPrincipalName,displayName,assignedLicenses,licenseAssignmentStates,onPremisesSamAccountName'
}

function Split-GraphBatchChunks {
    param(
        [Parameter(Mandatory = $true)]$Items,
        [int]$Size = 20
    )

    $list = @($Items)
    if ($list.Count -eq 0) { return @() }
    $chunks = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $list.Count; $i += $Size) {
        $end = [Math]::Min($i + $Size - 1, $list.Count - 1)
        [void]$chunks.Add(@($list[$i..$end]))
    }
    return @($chunks)
}

function Invoke-GraphBatch {
    param([Parameter(Mandatory = $true)][array]$Requests)

    if ($Requests.Count -eq 0) { return @() }
    if ($Requests.Count -gt 20) {
        throw "Microsoft Graph `$batch allows at most 20 requests."
    }
    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw "Invoke-MgGraphRequest is not available."
    }

    $uri = 'https://graph.microsoft.com/v1.0/$batch'
    $attempts = 0
    $maxAttempts = 5
    $pending = @($Requests)

    while ($attempts -lt $maxAttempts) {
        $attempts++
        $body = @{ requests = @($pending) }
        $result = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ErrorAction Stop
        $responses = @()
        try { $responses = @($result.responses) } catch { $responses = @() }
        if ($responses.Count -eq 0) {
            try { $responses = @($result.Responses) } catch { $responses = @() }
        }

        $retry = [System.Collections.Generic.List[object]]::new()
        $wait = 0
        foreach ($r in $responses) {
            $status = 0
            try { $status = [int]$r.status } catch {
                try { $status = [int]$r.Status } catch { }
            }
            if ($status -eq 429) {
                $rid = $null
                try { $rid = [string]$r.id } catch { try { $rid = [string]$r.Id } catch { } }
                foreach ($req in $pending) {
                    if ([string]$req.id -eq $rid) { [void]$retry.Add($req) }
                }
                if ($wait -lt 5) { $wait = 5 }
            }
        }

        if ($retry.Count -eq 0) { return $responses }
        Start-Sleep -Seconds $wait
        $pending = @($retry)
    }

    return @()
}

function Get-GraphBatchResponseBody {
    param($Response)

    if ($null -eq $Response) { return $null }
    try { if ($Response.body) { return $Response.body } } catch { }
    try { if ($Response.Body) { return $Response.Body } } catch { }
    return $null
}

function Get-GraphBatchResponseStatus {
    param($Response)

    try { return [int]$Response.status } catch { }
    try { return [int]$Response.Status } catch { }
    return 0
}

function Import-EntraUsersByUpn {
    param([string[]]$Upns)

    $byUpn = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
    $bySam = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
    $notFound = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
    $select = Get-GraphUserSelectProperties
    $unique = @($Upns | Where-Object { $_ } | Select-Object -Unique)
    if ($unique.Count -eq 0) {
        return @{ ByUpn = $byUpn; BySam = $bySam; NotFoundUpns = $notFound }
    }

    $chunks = @(Split-GraphBatchChunks -Items $unique -Size 20)
    $done = 0
    foreach ($chunk in $chunks) {
        $requests = [System.Collections.Generic.List[object]]::new()
        $id = 0
        $idToUpn = @{}
        foreach ($upn in @($chunk)) {
            $id++
            $sid = [string]$id
            $idToUpn[$sid] = $upn
            $enc = [uri]::EscapeDataString($upn)
            [void]$requests.Add(@{
                id     = $sid
                method = 'GET'
                url    = '/users/' + $enc + '?$select=' + $select
            })
        }

        $responses = @(Invoke-GraphBatch -Requests @($requests))
        foreach ($r in $responses) {
            $status = Get-GraphBatchResponseStatus -Response $r
            $rid = $null
            try { $rid = [string]$r.id } catch { try { $rid = [string]$r.Id } catch { } }
            $requestedUpn = $null
            if ($rid -and $idToUpn.ContainsKey($rid)) { $requestedUpn = $idToUpn[$rid] }

            if ($status -eq 200) {
                $user = Get-GraphBatchResponseBody -Response $r
                if ($user) {
                    if ($requestedUpn) { $byUpn[$requestedUpn] = $user }
                    $upnVal = $null
                    try { $upnVal = [string]$user.userPrincipalName } catch { }
                    if (-not $upnVal) { try { $upnVal = [string]$user.UserPrincipalName } catch { } }
                    if ($upnVal) { $byUpn[$upnVal] = $user }
                    $samVal = $null
                    try { $samVal = [string]$user.onPremisesSamAccountName } catch { }
                    if (-not $samVal) { try { $samVal = [string]$user.OnPremisesSamAccountName } catch { } }
                    if ($samVal) { $bySam[$samVal] = $user }
                }
            }
            elseif ($status -eq 404) {
                if ($requestedUpn) { $notFound[$requestedUpn] = $true }
            }
            elseif ($status -eq 401 -or $status -eq 403) {
                $body = Get-GraphBatchResponseBody -Response $r
                $msg = "Graph batch user lookup failed with status $status"
                try { if ($body.error.message) { $msg = [string]$body.error.message } } catch { }
                throw $msg
            }
        }

        $done += @($chunk).Count
        Write-Progress -Activity "Looking up licenses in Entra ID" `
                       -Status ("Users {0}/{1}" -f $done, $unique.Count) `
                       -PercentComplete ([int](($done / $unique.Count) * 100))
        if ($done -eq $unique.Count -or ($done % 500) -eq 0) {
            Write-ScreenLog ("Entra UPN lookup {0}/{1}..." -f $done, $unique.Count) -Level PROGRESS
        }
    }

    return @{ ByUpn = $byUpn; BySam = $bySam; NotFoundUpns = $notFound }
}

function Import-EntraUsersBySam {
    param(
        [string[]]$Sams,
        $Lookup
    )

    $select = Get-GraphUserSelectProperties
    $unique = @($Sams | Where-Object { $_ } | Select-Object -Unique)
    if ($unique.Count -eq 0) { return $Lookup }

    $chunks = @(Split-GraphBatchChunks -Items $unique -Size 20)
    $done = 0
    $total = $unique.Count
    foreach ($chunk in $chunks) {
        $quoted = @(
            foreach ($sam in @($chunk)) {
                "'" + ($sam -replace "'", "''") + "'"
            }
        ) -join ','
        $filter = [uri]::EscapeDataString("onPremisesSamAccountName in ($quoted)")
        $url = '/users?$filter=' + $filter + '&$count=true&$select=' + $select
        $requests = @(
            @{
                id      = '1'
                method  = 'GET'
                url     = $url
                headers = @{ ConsistencyLevel = 'eventual' }
            }
        )

        $responses = @(Invoke-GraphBatch -Requests $requests)
        foreach ($r in $responses) {
            $status = Get-GraphBatchResponseStatus -Response $r
            if ($status -ne 200) {
                if ($status -eq 401 -or $status -eq 403) {
                    throw "Graph SAM lookup failed with status $status"
                }
                continue
            }
            $body = Get-GraphBatchResponseBody -Response $r
            $vals = @()
            try { $vals = @($body.value) } catch { }
            if ($vals.Count -eq 0 -and $body -and $body.userPrincipalName) { $vals = @($body) }
            foreach ($user in $vals) {
                $upnVal = $null
                try { $upnVal = [string]$user.userPrincipalName } catch { }
                if (-not $upnVal) { try { $upnVal = [string]$user.UserPrincipalName } catch { } }
                if ($upnVal) { $Lookup.ByUpn[$upnVal] = $user }
                $samVal = $null
                try { $samVal = [string]$user.onPremisesSamAccountName } catch { }
                if (-not $samVal) { try { $samVal = [string]$user.OnPremisesSamAccountName } catch { } }
                if ($samVal) { $Lookup.BySam[$samVal] = $user }
            }
        }

        $done += @($chunk).Count
        Write-Progress -Activity "Resolving remaining users by sAMAccountName" `
                       -Status ("{0}/{1}" -f $done, $total) `
                       -PercentComplete ([int](($done / $total) * 100))
        if ($done -eq $total -or ($done % 200) -eq 0) {
            Write-ScreenLog ("sAMAccountName lookup {0}/{1}..." -f $done, $total) -Level PROGRESS
        }
    }

    Write-Progress -Activity "Resolving remaining users by sAMAccountName" -Completed
    return $Lookup
}

function Import-EntraGroupDisplayNames {
    param([string[]]$GroupIds)

    $missing = @(
        $GroupIds |
            Where-Object { $_ -and -not $script:EntraGroupCache.ContainsKey($_) } |
            Select-Object -Unique
    )
    if ($missing.Count -eq 0) { return }

    $chunks = @(Split-GraphBatchChunks -Items $missing -Size 20)
    foreach ($chunk in $chunks) {
        $requests = [System.Collections.Generic.List[object]]::new()
        $id = 0
        $idToGroup = @{}
        foreach ($gid in @($chunk)) {
            $id++
            $sid = [string]$id
            $idToGroup[$sid] = $gid
            [void]$requests.Add(@{
                id     = $sid
                method = 'GET'
                url    = '/groups/' + [uri]::EscapeDataString($gid) + '?$select=id,displayName'
            })
        }

        $responses = @(Invoke-GraphBatch -Requests @($requests))
        foreach ($r in $responses) {
            $rid = $null
            try { $rid = [string]$r.id } catch { try { $rid = [string]$r.Id } catch { } }
            $gid = $null
            if ($rid -and $idToGroup.ContainsKey($rid)) { $gid = $idToGroup[$rid] }
            $status = Get-GraphBatchResponseStatus -Response $r
            $name = $gid
            if ($status -eq 200) {
                $g = Get-GraphBatchResponseBody -Response $r
                try { if ($g.displayName) { $name = [string]$g.displayName } } catch { }
                try { if (-not $name -or $name -eq $gid) { if ($g.DisplayName) { $name = [string]$g.DisplayName } } } catch { }
            }
            if ($gid) { $script:EntraGroupCache[$gid] = $name }
        }
    }
}

function Find-EntraUserFromLookup {
    param($AdUser, $Lookup)

    if (-not $Lookup) { return $null }
    $upn = $AdUser.UserPrincipalName
    $sam = $AdUser.SamAccountName
    if ($upn -and $Lookup.ByUpn -and $Lookup.ByUpn.ContainsKey($upn)) {
        return $Lookup.ByUpn[$upn]
    }
    if ($sam -and $Lookup.BySam -and $Lookup.BySam.ContainsKey($sam)) {
        return $Lookup.BySam[$sam]
    }
    return $null
}

function Get-DirectLicenseInventory {
    param(
        [Parameter(Mandatory = $true)]$Users,
        [hashtable]$SkuMap,
        $Groups
    )

    if (-not $Groups) { $Groups = @{} }
    if (-not $SkuMap) { $SkuMap = @{} }

    $userList = @($Users)
    if (-not $script:GraphReady -and $userList.Count -gt 0) {
        Write-ScreenLog "Skipping Entra lookups for $($userList.Count) user(s) because Microsoft Graph is not signed in." -Level WARN
    }

    $lookup = $null
    if ($script:GraphReady -and (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        try {
            Write-ScreenLog "Looking up $($userList.Count) user(s) in Entra ID (20 per Graph batch)..." -Level INFO
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $upns = @($userList | ForEach-Object { $_.UserPrincipalName } | Where-Object { $_ })
            $lookup = Import-EntraUsersByUpn -Upns $upns
            $missingSams = @(
                $userList |
                    Where-Object {
                        $_.SamAccountName -and
                        -not (Find-EntraUserFromLookup -AdUser $_ -Lookup $lookup) -and
                        (
                            -not $_.UserPrincipalName -or
                            -not ($lookup.NotFoundUpns -and $lookup.NotFoundUpns.ContainsKey($_.UserPrincipalName))
                        )
                    } |
                    ForEach-Object { $_.SamAccountName }
            )
            $skipped404 = @(
                $userList |
                    Where-Object {
                        $_.UserPrincipalName -and
                        $lookup.NotFoundUpns -and
                        $lookup.NotFoundUpns.ContainsKey($_.UserPrincipalName)
                    }
            ).Count
            if ($skipped404 -gt 0) {
                Write-ScreenLog "Skipping sAMAccountName lookup for $skipped404 user(s) already not found by UPN." -Level INFO
            }
            if ($missingSams.Count -gt 0) {
                Write-ScreenLog "Resolving $($missingSams.Count) user(s) with no UPN match by sAMAccountName..." -Level INFO
                $lookup = Import-EntraUsersBySam -Sams $missingSams -Lookup $lookup
            }

            $groupIds = [System.Collections.Generic.List[string]]::new()
            $seenMg = @{}
            $mgUsers = @()
            try { $mgUsers += @($lookup.ByUpn.Values) } catch { }
            try { $mgUsers += @($lookup.BySam.Values) } catch { }
            foreach ($mg in $mgUsers) {
                $mid = $null
                try { $mid = [string]$mg.id } catch { }
                if (-not $mid) { try { $mid = [string]$mg.Id } catch { } }
                if ($mid) {
                    if ($seenMg.ContainsKey($mid)) { continue }
                    $seenMg[$mid] = $true
                }
                $states = @()
                try { $states = @($mg.licenseAssignmentStates) } catch { }
                if ($states.Count -eq 0) { try { $states = @($mg.LicenseAssignmentStates) } catch { } }
                foreach ($state in $states) {
                    if (Test-IsDirectLicenseAssignment -State $state) { continue }
                    $gid = $null
                    try { $gid = [string]$state.AssignedByGroup } catch { }
                    if (-not $gid) { try { $gid = [string]$state.assignedByGroup } catch { } }
                    if ($gid) { [void]$groupIds.Add($gid) }
                }
            }
            Import-EntraGroupDisplayNames -GroupIds @($groupIds)
            $sw.Stop()
            Write-ScreenLog ("Entra lookup finished in {0:N1}s ({1} unique UPN(s))." -f $sw.Elapsed.TotalSeconds, @($lookup.ByUpn.Keys).Count) -Level SUCCESS
            Write-Progress -Activity "Looking up licenses in Entra ID" -Completed
        }
        catch {
            Write-Progress -Activity "Looking up licenses in Entra ID" -Completed
            if (Test-IsGraphAuthError $_.Exception.Message) {
                $script:GraphReady = $false
                Write-ScreenLog "Graph is not authenticated. Skipping Entra lookups." -Level ERROR
                $lookup = $null
            }
            else {
                Write-ScreenLog "Batched Entra lookup failed ($($_.Exception.Message)); falling back to per-user calls." -Level WARN
                $lookup = $null
            }
        }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $index = 0
    $useSequential = $script:GraphReady -and ($null -eq $lookup)
    foreach ($user in $userList) {
        $index++
        if ($useSequential -or -not $script:GraphReady) {
            $percent = [int](($index / [Math]::Max($userList.Count, 1)) * 100)
            Write-Progress -Activity "Scanning license sources (AD groups + Entra ID)" `
                           -Status ("[{0}/{1}] {2}" -f $index, $userList.Count, $user.SamAccountName) `
                           -PercentComplete $percent
        }

        $adGroupNames = @(foreach ($dn in @($user.MemberOf | Where-Object { $_ -and $Groups.ContainsKey($_) })) {
            $Groups[$dn].Name
        })

        $entry = [pscustomobject]@{
            AdUser                 = $user
            MgUser                 = $null
            DirectLicenses         = @()
            GroupAssignedLicenses  = @()
            AdLicenseGroups        = $adGroupNames
            LookupStatus           = 'OK'
            LookupMessage          = ''
        }

        if (-not $script:GraphReady) {
            $entry.LookupStatus = 'Skipped'
            $entry.LookupMessage = 'Microsoft Graph is not signed in.'
            [void]$rows.Add($entry)
            continue
        }

        if (-not $user.UserPrincipalName -and -not $user.SamAccountName) {
            $entry.LookupStatus = 'Skipped'
            $entry.LookupMessage = 'No UPN or sAMAccountName to look up in Entra ID.'
            [void]$rows.Add($entry)
            continue
        }

        try {
            $mgUser = $null
            if ($lookup) {
                $mgUser = Find-EntraUserFromLookup -AdUser $user -Lookup $lookup
            }
            else {
                $mgUser = Get-EntraUserForAdUser -AdUser $user
            }

            if (-not $mgUser) {
                $entry.LookupStatus = 'NotFound'
                $entry.LookupMessage = 'No matching Entra ID user.'
            }
            else {
                $entry.MgUser = $mgUser
                $entry.DirectLicenses = @(Get-DirectLicensesForMgUser -MgUser $mgUser -SkuMap $SkuMap)
                $entry.GroupAssignedLicenses = @(Get-GroupAssignedLicensesForMgUser -MgUser $mgUser -SkuMap $SkuMap)
            }
        }
        catch {
            if (Test-IsGraphAuthError $_.Exception.Message) {
                $script:GraphReady = $false
                $entry.LookupStatus = 'Failed'
                $entry.LookupMessage = 'Graph authentication needed. Remaining Entra lookups skipped.'
                [void]$rows.Add($entry)
                Write-ScreenLog "Graph is not authenticated. Stopping Entra lookups (will not repeat this error for every user)." -Level ERROR
                Write-ScreenLog "Complete Microsoft 365 sign-in, then re-run the report." -Level WARN
                foreach ($rest in @($userList | Select-Object -Skip $index)) {
                    $restGroups = @(foreach ($dn in @($rest.MemberOf | Where-Object { $_ -and $Groups.ContainsKey($_) })) {
                        $Groups[$dn].Name
                    })
                    [void]$rows.Add([pscustomobject]@{
                        AdUser                 = $rest
                        MgUser                 = $null
                        DirectLicenses         = @()
                        GroupAssignedLicenses  = @()
                        AdLicenseGroups        = $restGroups
                        LookupStatus           = 'Skipped'
                        LookupMessage          = 'Skipped because Graph is not authenticated.'
                    })
                }
                break
            }
            $entry.LookupStatus = 'Failed'
            $entry.LookupMessage = $_.Exception.Message
        }

        [void]$rows.Add($entry)
    }

    Write-Progress -Activity "Scanning license sources (AD groups + Entra ID)" -Completed
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

    $userId = $null
    try { $userId = $MgUser.Id } catch { }
    if (-not $userId) { try { $userId = $MgUser.id } catch { } }

    if ($script:GraphAccessToken -and $userId) {
        Invoke-GraphApi -Method POST -Path ("users/{0}/assignLicense" -f $userId) -Body @{
            addLicenses    = @()
            removeLicenses = $unique
        } | Out-Null
        return $true
    }

    $removed = $false
    try {
        Set-MgUserLicense -UserId $userId -AddLicenses @() -RemoveLicenses $unique -ErrorAction Stop | Out-Null
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

function Get-AdUserPropertyList {
    return @(
        'extensionAttribute3'
        'MemberOf'
        'DisplayName'
        'UserPrincipalName'
        'SamAccountName'
        'DistinguishedName'
        'Enabled'
        'mail'
    )
}

function Resolve-LicenseGroups {
    param(
        [Parameter(Mandatory = $true)][string[]]$GroupNames,
        $AdParams
    )

    Write-ScreenLog "Resolving $($GroupNames.Count) target license group(s)..." -Level INFO
    $Groups = @{}
    $resolvedCount = 0
    $missingGroups = [System.Collections.Generic.List[string]]::new()

    foreach ($name in $GroupNames) {
        $escapedName = Escape-AdFilterValue -Value $name
        try {
            $found = @(Get-ADGroup -Filter "Name -eq '$escapedName' -or SamAccountName -eq '$escapedName'" @AdParams)
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

    Write-ScreenLog "Resolved $($Groups.Count) of $($GroupNames.Count) group(s). Missing: $(if ($missingGroups.Count) { $missingGroups -join ', ' } else { 'none' })" -Level INFO
    return $Groups
}

function Get-UsersByExtensionAttribute {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        $AdParams
    )

    $ldapValue = Escape-LdapFilterValue -Value $Value
    $ldapFilter = "(extensionAttribute3=*$ldapValue*)"
    Write-ScreenLog "Searching for users with LDAP filter $ldapFilter ..." -Level INFO
    try {
        $users = @(Get-ADUser -LDAPFilter $ldapFilter -Properties (Get-AdUserPropertyList) @AdParams)
    }
    catch {
        throw "Get-ADUser failed for filter $ldapFilter : $($_.Exception.Message)"
    }
    Write-ScreenLog "Found $($users.Count) matching user(s)." -Level INFO
    return $users
}

function Get-AdUserFromIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        $AdParams
    )

    $Value = $Value.Trim()
    if (-not $Value) { return $null }
    $escaped = Escape-AdFilterValue -Value $Value
    $props = Get-AdUserPropertyList

    if ($Value -like '*@*') {
        $found = @(Get-ADUser -Filter "UserPrincipalName -eq '$escaped'" -Properties $props @AdParams)
        if ($found.Count -ge 1) { return $found[0] }
        $found = @(Get-ADUser -Filter "mail -eq '$escaped'" -Properties $props @AdParams)
        if ($found.Count -ge 1) { return $found[0] }
    }

    try {
        return Get-ADUser -Identity $Value -Properties $props -ErrorAction Stop @AdParams
    }
    catch { }

    $found = @(Get-ADUser -Filter "SamAccountName -eq '$escaped'" -Properties $props @AdParams)
    if ($found.Count -ge 1) { return $found[0] }
    return $null
}

function Show-FileDialog {
    param(
        [ValidateSet('Open', 'Save')]
        [string]$Mode = 'Open',
        [string]$Title = 'Select a file',
        [string]$Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*',
        [string]$FileName
    )

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $code = @"
Add-Type -AssemblyName System.Windows.Forms
`$d = New-Object System.Windows.Forms.$($Mode)FileDialog
`$d.Filter = '$($Filter.Replace("'", "''"))'
`$d.Title = '$($Title.Replace("'", "''"))'
`$d.CheckFileExists = `$$($Mode -eq 'Open')
if ('$($FileName.Replace("'", "''"))') { `$d.FileName = '$($FileName.Replace("'", "''"))' }
if (`$d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { `$d.FileName }
"@
        $state = [System.Threading.Thread]::CurrentThread.GetApartmentState()
        if ($state -eq 'STA') {
            $dialog = if ($Mode -eq 'Open') {
                New-Object System.Windows.Forms.OpenFileDialog
            } else {
                New-Object System.Windows.Forms.SaveFileDialog
            }
            $dialog.Filter = $Filter
            $dialog.Title = $Title
            if ($Mode -eq 'Open') { $dialog.CheckFileExists = $true }
            if ($FileName) { $dialog.FileName = $FileName }
            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                return $dialog.FileName
            }
            return $null
        }

        $ps = [powershell]::Create()
        try {
            $rs = [runspacefactory]::CreateRunspace()
            $rs.ApartmentState = 'STA'
            $rs.Open()
            $ps.Runspace = $rs
            [void]$ps.AddScript($code)
            $out = $ps.Invoke()
            if ($out -and $out.Count -gt 0) { return [string]$out[-1] }
            return $null
        }
        finally {
            $ps.Dispose()
        }
    }
    catch {
        Write-ScreenLog "File picker unavailable: $($_.Exception.Message)" -Level WARN
        return $null
    }
}

function Get-CsvPathInteractive {
    param([string]$Existing)

    if ($Existing -and -not $script:IsInteractive) {
        if (-not (Test-Path -LiteralPath $Existing)) { throw "CSV file not found: $Existing" }
        return (Resolve-Path -LiteralPath $Existing).Path
    }

    Write-Host ""
    Write-Host "---- Import CSV -------------------------------------------------------------" -ForegroundColor Cyan
    if ($Existing -and (Test-Path -LiteralPath $Existing)) {
        if (Read-YesNo -Message "Use this CSV? $Existing" -Default $true) {
            return (Resolve-Path -LiteralPath $Existing).Path
        }
    }

    Write-Host "A file picker will open. Choose the CSV of users." -ForegroundColor Gray
    $picked = Show-FileDialog -Mode Open -Title 'Select a CSV of users to process'
    if ($picked) {
        Write-ScreenLog "Selected CSV: $picked" -Level INFO
        return $picked
    }

    $path = Read-Prompt -Message "CSV path (file picker cancelled or unavailable)"
    if ([string]::IsNullOrWhiteSpace($path)) { throw "No CSV path provided." }
    if (-not (Test-Path -LiteralPath $path)) { throw "CSV file not found: $path" }
    return (Resolve-Path -LiteralPath $path).Path
}

function Read-CsvIdentityColumn {
    param(
        [Parameter(Mandatory = $true)]$Rows,
        [string]$Preferred
    )

    if (-not $Rows -or @($Rows).Count -eq 0) { throw "CSV has no data rows." }
    $headers = @($Rows[0].PSObject.Properties.Name)
    $preferredNames = @(
        'UserPrincipalName', 'UPN', 'sAMAccountName', 'SamAccountName',
        'UserName', 'User', 'Mail', 'EmailAddress', 'Email'
    )
    $defaultHeader = $null
    if ($Preferred) {
        $defaultHeader = $headers | Where-Object { $_ -eq $Preferred } | Select-Object -First 1
        if (-not $defaultHeader -and -not $script:IsInteractive) {
            throw "CSV has no column named '$Preferred'. Columns: $($headers -join ', ')"
        }
    }
    if (-not $defaultHeader) {
        $defaultHeader = $headers | Where-Object { $preferredNames -contains $_ } | Select-Object -First 1
    }
    if (-not $defaultHeader) { $defaultHeader = $headers[0] }

    if (-not $script:IsInteractive) { return [string]$defaultHeader }

    Write-Host ""
    Write-Host "---- CSV columns (choose the user identifier) -------------------------------" -ForegroundColor Cyan
    for ($i = 0; $i -lt $headers.Count; $i++) {
        $samples = @($Rows | Select-Object -First 3 | ForEach-Object { [string]$_.($headers[$i]) } | Where-Object { $_ })
        Write-Host ("  {0,2}) {1,-24}  e.g. {2}" -f ($i + 1), $headers[$i], ($samples -join ', '))
    }
    Write-Host ""

    while ($true) {
        $raw = Read-Prompt -Message "Column number or header name" -Default $defaultHeader
        $num = 0
        if ([int]::TryParse($raw, [ref]$num) -and $num -ge 1 -and $num -le $headers.Count) {
            return [string]$headers[$num - 1]
        }
        $hit = $headers | Where-Object { $_ -eq $raw } | Select-Object -First 1
        if ($hit) { return [string]$hit }
        Write-Host "Pick a listed number or an exact column name." -ForegroundColor Yellow
    }
}

function Import-UsersFromCsv {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Column,
        $AdParams
    )

    Write-ScreenLog "Reading CSV $Path ..." -Level INFO
    $rows = @(Import-Csv -Path $Path)
    $column = Read-CsvIdentityColumn -Rows $rows -Preferred $Column
    Write-ScreenLog "Using CSV column '$column' as the user identifier." -Level INFO

    $users = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    $rowNum = 1
    foreach ($row in $rows) {
        $rowNum++
        $raw = ''
        try { $raw = [string]$row.$column } catch { $raw = '' }
        if ([string]::IsNullOrWhiteSpace($raw)) {
            Write-ScreenLog "CSV row $rowNum : empty '$column' — skipped." -Level SKIP
            continue
        }
        $key = $raw.Trim().ToLowerInvariant()
        if ($seen.ContainsKey($key)) {
            Write-ScreenLog "CSV row $rowNum : duplicate '$raw' — skipped." -Level SKIP
            continue
        }
        $seen[$key] = $true

        $adUser = Get-AdUserFromIdentity -Value $raw.Trim() -AdParams $AdParams
        if (-not $adUser) {
            Write-ScreenLog "CSV row $rowNum : '$raw' was not found in AD." -Level WARN
            $stub = [pscustomobject]@{
                SamAccountName      = $raw.Trim()
                DisplayName         = ''
                UserPrincipalName   = $raw.Trim()
                DistinguishedName   = ''
                Enabled             = $false
                extensionAttribute3 = ''
                MemberOf            = @()
                CsvUnresolved       = $true
            }
            [void]$users.Add($stub)
            continue
        }

        Write-ScreenLog "CSV row $rowNum : '$raw' -> $($adUser.SamAccountName) <$($adUser.UserPrincipalName)>" -Level SUCCESS
        [void]$users.Add($adUser)
    }

    Write-ScreenLog "CSV loaded: $($users.Count) identity(ies); unresolved will be skipped at removal." -Level INFO
    return @($users)
}

function ConvertTo-LicenseSourceReport {
    param([Parameter(Mandatory = $true)]$Inventory)

    foreach ($row in $Inventory) {
        $u = $row.AdUser
        $adNames = @($row.AdLicenseGroups)
        $directNames = @($row.DirectLicenses | ForEach-Object { $_.SkuPartNumber })
        $entraBits = @($row.GroupAssignedLicenses | ForEach-Object {
            if ($_.GroupName) { '{0} via {1}' -f $_.SkuPartNumber, $_.GroupName }
            else { [string]$_.SkuPartNumber }
        })

        $sources = [System.Collections.Generic.List[string]]::new()
        if ($adNames.Count -gt 0) { [void]$sources.Add('AD group') }
        if ($directNames.Count -gt 0) { [void]$sources.Add('Direct') }
        if ($entraBits.Count -gt 0) { [void]$sources.Add('Entra group') }
        $how = if ($sources.Count -eq 0) { 'Unlicensed' }
               elseif ($sources.Count -eq 1) { [string]$sources[0] }
               else { 'Mixed: ' + ($sources -join ' + ') }

        if ($row.LookupStatus -eq 'Skipped' -and $row.LookupMessage -match 'Graph') {
            $how = if ($adNames.Count -gt 0) { 'AD group (Entra lookup skipped)' } else { 'Unknown (Graph not signed in)' }
        }

        $summaryParts = [System.Collections.Generic.List[string]]::new()
        if ($adNames.Count -gt 0) { [void]$summaryParts.Add('AD groups: ' + ($adNames -join ', ')) }
        if ($directNames.Count -gt 0) { [void]$summaryParts.Add('Direct: ' + ($directNames -join ', ')) }
        if ($entraBits.Count -gt 0) { [void]$summaryParts.Add('Entra groups: ' + ($entraBits -join ', ')) }
        if ($summaryParts.Count -eq 0) { [void]$summaryParts.Add('No Office 365 license source found') }

        [pscustomobject]@{
            SamAccountName         = $u.SamAccountName
            DisplayName            = $u.DisplayName
            UserPrincipalName      = $u.UserPrincipalName
            Enabled                = $u.Enabled
            ExtensionAttribute3    = $u.extensionAttribute3
            HowLicensed            = $how
            AdLicenseGroups        = ($adNames -join '; ')
            AdLicenseGroupCount    = $adNames.Count
            DirectSkus             = ($directNames -join '; ')
            DirectSkuCount         = $directNames.Count
            EntraGroupLicenses     = ($entraBits -join '; ')
            EntraGroupLicenseCount = $entraBits.Count
            LicenseSourceSummary   = ($summaryParts -join ' | ')
            EntraLookup            = $row.LookupStatus
            EntraLookupMessage     = $row.LookupMessage
        }
    }
}

function Show-LicenseSourceReport {
    param([Parameter(Mandatory = $true)]$ReportRows)

    Write-Host ""
    Write-Host "---- How each user gets Office 365 ----------------------------------------" -ForegroundColor Cyan
    $ReportRows |
        Select-Object SamAccountName, HowLicensed, AdLicenseGroups, DirectSkus, EntraGroupLicenses, UserPrincipalName |
        Format-Table -AutoSize -Wrap |
        Out-Host
    Write-Host ""

    $byHow = $ReportRows | Group-Object HowLicensed
    Write-Host "---- Totals by license source ---------------------------------------------" -ForegroundColor Cyan
    $byHow | Select-Object @{n = 'HowLicensed'; e = { $_.Name } }, @{n = 'Users'; e = { $_.Count } } |
        Format-Table -AutoSize | Out-Host
}

function Export-LicenseSourceReport {
    param(
        [Parameter(Mandatory = $true)]$ReportRows,
        [string]$Path,
        [string]$Population
    )

    if (-not $Path) {
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $defaultName = "LicenseSourceReport_${Population}_$stamp.csv"
        $picked = Show-FileDialog -Mode Save -Title 'Save license source report' -FileName $defaultName
        if ($picked) {
            $Path = $picked
        }
        else {
            $Path = ".\$defaultName"
            Write-Host "File picker unavailable or cancelled. Saving to $Path" -ForegroundColor Gray
            if ($script:IsInteractive -and (Read-YesNo -Message "Save to a different path instead?" -Default $false)) {
                $alt = Read-Prompt -Message "Report CSV path" -Default $Path
                if ($alt) { $Path = $alt }
            }
        }
    }

    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $dir = Split-Path -Parent $full
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null
    }
    $ReportRows | Export-Csv -Path $full -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    Write-ScreenLog "License source report exported: $full" -Level SUCCESS
    return $full
}

function Invoke-RemovalPipeline {
    param(
        [Parameter(Mandatory = $true)]$Users,
        [Parameter(Mandatory = $true)]$Groups,
        $AdParams
    )

    $resolvedUsers = @($Users | Where-Object { -not ($_.PSObject.Properties['CsvUnresolved'] -and $_.CsvUnresolved) })
    $unresolved = @($Users | Where-Object { $_.PSObject.Properties['CsvUnresolved'] -and $_.CsvUnresolved })
    foreach ($stub in $unresolved) {
        Add-ActionResult -Result (New-ActionResult -User $stub -ActionType 'Lookup' -Status 'Failed - not found in AD' -Message 'CSV identity did not resolve to an AD user.')
    }

    if ($resolvedUsers.Count -eq 0) {
        Write-ScreenLog "No resolvable AD users to process." -Level WARN
        Write-RunSummary -Users $Users -GroupPassCounts $null -LicensePassCounts $null
        return
    }

    Show-MatchingUserTable -Users $resolvedUsers -Groups $Groups

    $actionable = @($resolvedUsers | Where-Object {
        @($_.MemberOf | Where-Object { $_ -and $Groups.ContainsKey($_) }).Count -gt 0
    }).Count
    Write-ScreenLog "$actionable of $($resolvedUsers.Count) user(s) are in at least one selected license group." -Level INFO

    $inventory = $null
    if ($script:RemoveDirectLicenses -or $script:IsInteractive) {
        try {
            $graphRequired = [bool]$script:RemoveDirectLicenses
            if (Initialize-GraphForLicenses -Required:$graphRequired -AllowWrite:([bool]$script:RemoveDirectLicenses)) {
                $skuMap = Get-SkuPartNumberMap
                Write-ScreenLog "Scanning $($resolvedUsers.Count) user(s) in Entra ID for license assignment sources..." -Level INFO
                $inventory = Get-DirectLicenseInventory -Users $resolvedUsers -SkuMap $skuMap -Groups $Groups
                Show-DirectLicenseTable -Inventory $inventory
                $reportRows = @(ConvertTo-LicenseSourceReport -Inventory $inventory)
                Show-LicenseSourceReport -ReportRows $reportRows
            }
            else {
                Write-ScreenLog "Skipping Entra / direct-license scan because Graph is not signed in." -Level WARN
            }
        }
        catch {
            $graphError = $_.Exception.Message
            Write-ScreenLog $graphError -Level ERROR
            if ($script:RemoveDirectLicenses) {
                if ($script:IsInteractive -and (Read-YesNo -Message "Graph lookup failed. Continue with AD group removals only?" -Default $false)) {
                    $script:RemoveDirectLicenses = $false
                    $inventory = $null
                }
                else {
                    throw "Direct license lookup failed: $graphError"
                }
            }
        }
    }

    $directActionable = 0
    if ($inventory) {
        $directActionable = @($inventory | Where-Object { $_.DirectLicenses.Count -gt 0 }).Count
    }

    if ($script:IsInteractive) {
        $bits = @()
        if ($script:RemoveFromGroups) { $bits += "$actionable AD group membership(s)" }
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

    $groupPassCounts = $null
    if ($script:RemoveFromGroups) {
        $groupPassCounts = Invoke-LicenseGroupPass -Users $resolvedUsers -Groups $Groups -AdParams $AdParams
    }
    $licensePassCounts = $null
    if ($script:RemoveDirectLicenses -and $inventory) {
        $licensePassCounts = Invoke-DirectLicensePass -Inventory $inventory
    }
    Write-RunSummary -Users $resolvedUsers -GroupPassCounts $groupPassCounts -LicensePassCounts $licensePassCounts

    $anyActionable = (($script:RemoveFromGroups) -and ($actionable -gt 0)) -or (($script:RemoveDirectLicenses) -and ($directActionable -gt 0))
    if ($script:IsInteractive -and $script:PreviewOnly -and $anyActionable) {
        Write-Host ""
        Write-Host "WhatIf preview finished. No memberships or licenses have been changed yet." -ForegroundColor Magenta
        if (Read-YesNo -Message "Run LIVE removals now for the same users?" -Default $false) {
            if (Confirm-LiveRemoval) {
                $script:PreviewOnly = $false
                $WhatIfPreference = $false
                Write-Banner @(
                    " LIVE PASS"
                    " Mode        : LIVE - groups and/or direct licenses WILL be changed"
                    " Users       : $($resolvedUsers.Count)"
                )
                if ($script:RemoveFromGroups) {
                    $groupPassCounts = Invoke-LicenseGroupPass -Users $resolvedUsers -Groups $Groups -AdParams $AdParams
                }
                $licensePassCounts = $null
                if ($script:RemoveDirectLicenses -and $inventory) {
                    $licensePassCounts = Invoke-DirectLicensePass -Inventory $inventory
                }
                Write-RunSummary -Users $resolvedUsers -GroupPassCounts $groupPassCounts -LicensePassCounts $licensePassCounts
            }
            else {
                Write-Host "Live run not confirmed. Leaving WhatIf results as-is." -ForegroundColor Yellow
            }
        }
    }
}

function Start-RunLogging {
    param(
        [string]$ChosenWorkflow,
        [string]$Population
    )

    if ($script:TranscriptStarted) {
        try { Stop-Transcript -WhatIf:$false | Out-Null } catch { }
        $script:TranscriptStarted = $false
    }

    if (-not $script:LogPathWasBound -or -not $script:SessionLogPath) {
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $tag = if ($ChosenWorkflow -eq 'RemoveFromCsv') { 'CsvImport' }
               elseif ($ChosenWorkflow -eq 'Report') { "Report_$Population" }
               elseif ($Population) { $Population }
               else { 'Session' }
        $LogPath = ".\LicenseTool_${tag}_$stamp.csv"
    }
    else {
        $LogPath = $script:SessionLogPath
    }

    $script:ResolvedLogPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)
    if ($script:TranscriptPathBound) {
        $TranscriptPath = $script:SessionTranscriptPath
    }
    else {
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
}

function Invoke-ConfiguredWorkflow {
    param(
        [Parameter(Mandatory = $true)][string]$ChosenWorkflow,
        [string]$MatchValue,
        [string[]]$GroupNames,
        $AdParams
    )

    $Groups = Resolve-LicenseGroups -GroupNames $GroupNames -AdParams $AdParams

    if ($Groups.Count -eq 0 -and $ChosenWorkflow -ne 'Report' -and $script:RemoveFromGroups) {
        throw "None of the target groups were found. Exiting."
    }

    if ($ChosenWorkflow -eq 'Report') {
        $Users = Get-UsersByExtensionAttribute -Value $MatchValue -AdParams $AdParams
        if ($Users.Count -eq 0) {
            Write-ScreenLog "No users have extensionAttribute3 matching '*$MatchValue*'. Nothing to report." -Level WARN
            return
        }
        Show-MatchingUserTable -Users $Users -Groups $Groups
        $graphOk = Initialize-GraphForLicenses
        $skuMap = @{}
        if ($graphOk) {
            try { $skuMap = Get-SkuPartNumberMap } catch {
                Write-ScreenLog "Could not load SKU names: $($_.Exception.Message)" -Level WARN
                $skuMap = @{}
            }
        }
        else {
            Write-ScreenLog "Report will include AD license groups only (Entra/direct columns empty)." -Level WARN
        }
        $inventory = Get-DirectLicenseInventory -Users $Users -SkuMap $skuMap -Groups $Groups
        $reportRows = @(ConvertTo-LicenseSourceReport -Inventory $inventory)
        Show-LicenseSourceReport -ReportRows $reportRows
        $exported = Export-LicenseSourceReport -ReportRows $reportRows -Path $script:ReportPath -Population $MatchValue
        $script:ReportPath = $exported

        if ($script:IsInteractive -and (Read-YesNo -Message "Run license removal for these same users now?" -Default $false)) {
            $target = Read-RemovalTarget
            $script:RemoveFromGroups = ($target -eq 'Groups' -or $target -eq 'Both')
            $script:RemoveDirectLicenses = ($target -eq 'Direct' -or $target -eq 'Both')
            $mode = Read-RunMode -WhatIfAlreadySet:$script:WhatIfBound
            if ($mode -eq 'Quit') { return }
            $script:PreviewOnly = ($mode -eq 'WhatIf')
            $WhatIfPreference = $script:PreviewOnly
            Invoke-RemovalPipeline -Users $Users -Groups $Groups -AdParams $AdParams
        }
    }
    elseif ($ChosenWorkflow -eq 'RemoveFromCsv') {
        $csvFile = Get-CsvPathInteractive -Existing $script:CsvPath
        $Users = Import-UsersFromCsv -Path $csvFile -Column $IdentityColumn -AdParams $AdParams
        if ($Users.Count -eq 0) {
            Write-ScreenLog "CSV produced no identities to process." -Level WARN
            return
        }
        Invoke-RemovalPipeline -Users $Users -Groups $Groups -AdParams $AdParams
    }
    else {
        $Users = Get-UsersByExtensionAttribute -Value $MatchValue -AdParams $AdParams
        if ($Users.Count -eq 0) {
            Write-ScreenLog "No users have extensionAttribute3 matching '*$MatchValue*'. Nothing to do." -Level WARN
            return
        }
        Invoke-RemovalPipeline -Users $Users -Groups $Groups -AdParams $AdParams
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
$script:EntraGroupCache         = @{}
$script:GraphReady              = $false
$script:GraphAccessToken        = $null
$script:GraphNeedWrite          = $false
$script:GraphTokenHasWrite      = $false
$script:TranscriptStarted       = $false
$script:TranscriptPaused        = $false
$script:UserCancelled           = $false
$script:WhatIfBound             = [bool]$WhatIfPreference -or $PSBoundParameters.ContainsKey('WhatIf')
$script:PreviewOnly             = $script:WhatIfBound
$script:Workflow                = $Workflow
$script:WorkflowBound           = $PSBoundParameters.ContainsKey('Workflow')
$script:CsvPath                 = $CsvPath
$script:ReportPath              = $ReportPath
$script:RemovalTarget           = $RemovalTarget
$script:SkipDirectLicenses      = [bool]$SkipDirectLicenses
$script:SkipGroupRemoval        = [bool]$SkipGroupRemoval
$script:LogPathWasBound         = $PSBoundParameters.ContainsKey('LogPath')
$script:MatchValueWasBound      = $PSBoundParameters.ContainsKey('MatchValue')
$script:TranscriptPathBound     = $PSBoundParameters.ContainsKey('TranscriptPath')
$script:SessionLogPath          = $LogPath
$script:SessionTranscriptPath   = $TranscriptPath
$script:RemoveFromGroups        = $true
$script:RemoveDirectLicenses    = $true

$AllGroupNames = @(
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

    if ($script:IsInteractive) {
        Write-Banner @(
            " Office 365 license report & removal"
            " Fully interactive — menus at every step. Choose Q on the main menu to exit."
            " Typical license path: AD group membership. Direct assignments are listed separately."
        )
    }

    $firstPass = $true
    while ($true) {
        $script:UserCancelled = $false
        $script:GraphReady = $false
        $script:Results = [System.Collections.Generic.List[object]]::new()
        $script:PreviewOnly = $script:WhatIfBound
        $runMatchValue = $MatchValue
        $GroupNames = @($AllGroupNames)

        if ($script:IsInteractive) {
            $forceMenu = -not ($firstPass -and $script:WorkflowBound)
            $chosenWorkflow = Read-MainWorkflow -ForceMenu:$forceMenu
        }
        else {
            $chosenWorkflow = Read-MainWorkflow
        }
        $firstPass = $false

        if ($chosenWorkflow -eq 'Quit') {
            Write-Host "Exiting. No further changes." -ForegroundColor Yellow
            $script:UserCancelled = $true
            break
        }
        $script:Workflow = $chosenWorkflow

        if ($script:IsInteractive -and $chosenWorkflow -ne 'Report') {
            $mode = Read-RunMode -WhatIfAlreadySet:$script:WhatIfBound
            if ($mode -eq 'Quit') {
                Write-Host "Cancelled this run. Returning to the main menu." -ForegroundColor Yellow
                continue
            }
            $script:PreviewOnly = ($mode -eq 'WhatIf')
            $WhatIfPreference = $script:PreviewOnly
        }

        if ($script:IsInteractive) {
            $script:Server = Read-DomainController -Current $script:Server
        }
        $Server = $script:Server

        if ($chosenWorkflow -ne 'RemoveFromCsv') {
            if ($script:IsInteractive) {
                $runMatchValue = Read-Population -Current $runMatchValue
            }
            if ([string]::IsNullOrWhiteSpace($runMatchValue)) {
                throw "MatchValue cannot be empty."
            }
        }

        if ($script:IsInteractive) {
            $GroupNames = Read-SelectedGroups -AllNames $AllGroupNames
            Write-Host ""
            Write-Host "Selected $($GroupNames.Count) group(s): $($GroupNames -join ', ')" -ForegroundColor Cyan
        }

        if ($chosenWorkflow -ne 'Report') {
            $target = Read-RemovalTarget
            $script:RemoveFromGroups = ($target -eq 'Groups' -or $target -eq 'Both')
            $script:RemoveDirectLicenses = ($target -eq 'Direct' -or $target -eq 'Both')
        }
        else {
            $script:RemoveFromGroups = $false
            $script:RemoveDirectLicenses = $false
        }

        Start-RunLogging -ChosenWorkflow $chosenWorkflow -Population $runMatchValue

        $modeText = if ($chosenWorkflow -eq 'Report') {
            'REPORT - no license changes'
        } elseif ($script:PreviewOnly) {
            'WHATIF - preview only; no group or license changes will be made'
        } else {
            'LIVE - users WILL be removed from groups and/or direct licenses'
        }
        $removeText = if ($chosenWorkflow -eq 'Report') { 'None (report only)' }
                      elseif ($script:RemoveFromGroups -and $script:RemoveDirectLicenses) { 'AD groups + direct SKUs' }
                      elseif ($script:RemoveFromGroups) { 'AD groups only' }
                      else { 'Direct SKUs only' }

        Write-Banner @(
            " Office 365 license report & removal"
            " Started          : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            " Workflow         : $chosenWorkflow"
            " Mode             : $modeText"
            " Population       : $(if ($chosenWorkflow -eq 'RemoveFromCsv') { 'CSV import' } else { "extensionAttribute3 like '*$runMatchValue*'" })"
            " Target DC        : $(if ($script:Server) { $script:Server } else { '(default)' })"
            " Removal target   : $removeText"
            " CSV log          : $script:ResolvedLogPath"
            " Transcript       : $script:ResolvedTranscriptPath"
            " Groups           : $($GroupNames.Count) selected"
        )

        $adParams = Get-AdCmdletParams
        try {
            Invoke-ConfiguredWorkflow -ChosenWorkflow $chosenWorkflow -MatchValue $runMatchValue -GroupNames $GroupNames -AdParams $adParams
        }
        catch {
            Write-ScreenLog $_.Exception.Message -Level ERROR
            if (-not $script:IsInteractive) { throw }
            Write-Host "That run failed. You can choose another option from the main menu." -ForegroundColor Yellow
        }

        if (-not $script:IsInteractive) { break }

        Write-Host ""
        Write-Host "Finished that run. Returning to the main menu (Q to quit)." -ForegroundColor Cyan
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

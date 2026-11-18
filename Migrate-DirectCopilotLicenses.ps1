#requires -Version 5.1
<#
.SYNOPSIS
Interactive discovery and migration of direct Copilot licenses to a synced AD group.

.DESCRIPTION
Run without parameters in Windows PowerShell 5.1 (console or ISE). Requires
Microsoft.Graph.Authentication; AD actions also require RSAT ActiveDirectory.
Prompts for installation of the Graph authentication module if missing.

The target AD security group must already be synced and assigned the selected
Copilot SKU. This script does not assign licenses to groups or trigger AD sync.

Report mode needs only Graph read access. Removal additionally needs delegated
LicenseAssignment.ReadWrite.All and an appropriate Entra role.

AD writes use your current Windows credentials and the chosen domain controller.
Only SID-matched, enabled, synced AD users are eligible for changes.

Direct removal requires direct AD membership and a fresh Active, error-free
assignment from the exact target group, with no reduction in enabled plans.

Run on a few selected users first. CSV logs are saved after every action.

.PARAMETER SelfTest
Run helper-function checks and exit. Does not connect to Graph or Active Directory.

.PARAMETER OutputDirectory
Folder for discovery reports and the action CSV. Defaults to
Documents\CopilotLicenseMigration.

References:
https://learn.microsoft.com/en-us/graph/api/resources/licenseassignmentstate
https://learn.microsoft.com/en-us/entra/identity/users/licensing-powershell-graph-examples
https://learn.microsoft.com/en-us/graph/api/user-assignlicense
#>
[CmdletBinding()]
param(
    [switch]$SelfTest,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
function Ask-Yes([string]$Message) {
    $answer = Read-Host "$Message [y/N]"
    if ($null -eq $answer) { return $false }
    return ($answer.Trim() -match '^(y|yes)$')
}

function Pick-Number([string]$Message, [int]$Maximum) {
    if ($Maximum -lt 1) { return 0 }
    while ($true) {
        $n = 0
        $answer = Read-Host "$Message (1-$Maximum, blank cancels)"
        if ([string]::IsNullOrWhiteSpace($answer)) { return 0 }
        if ([int]::TryParse($answer.Trim(), [ref]$n) -and $n -ge 1 -and $n -le $Maximum) { return $n }
        Write-Host 'Enter a valid number.' -ForegroundColor Yellow
    }
}

function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        foreach ($key in $Object.Keys) {
            if ([string]$key -eq $Name) { return $Object[$key] }
        }
        return $null
    }
    return $Object.$Name
}

function ConvertTo-IdList {
    param($Value)
    $out = New-Object System.Collections.Generic.List[string]
    $pending = New-Object System.Collections.Generic.Queue[object]
    foreach ($item in @($Value)) { $pending.Enqueue($item) }
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        if ($null -eq $current) { continue }
        if ($current -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace($current)) { [void]$out.Add($current.Trim()) }
            continue
        }
        if ($current -is [guid]) {
            [void]$out.Add($current.ToString('D'))
            continue
        }
        if ($current -is [ValueType]) {
            [void]$out.Add(([string]$current).Trim())
            continue
        }
        if ($current -is [System.Collections.IEnumerable]) {
            foreach ($child in $current) { $pending.Enqueue($child) }
            continue
        }
        $text = [string]$current
        if (-not [string]::IsNullOrWhiteSpace($text)) { [void]$out.Add($text.Trim()) }
    }
    return @($out.ToArray())
}

function ConvertTo-SkuKey([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $trimmed = $Value.Trim()
    try { return ([guid]$trimmed).ToString('D').ToLowerInvariant() }
    catch { return $trimmed.ToLowerInvariant() }
}

function Test-Blank([string]$Value) {
    return [string]::IsNullOrWhiteSpace($Value)
}

function Test-DirectAssignment($State) {
    return (Test-Blank ([string](Get-Prop $State 'assignedByGroup')))
}

function Get-DisabledPlanKeys($State) {
    return @(ConvertTo-IdList (Get-Prop $State 'disabledPlans') | ForEach-Object { ConvertTo-SkuKey $_ } | Where-Object { $_ })
}

function Test-NoPlanReduction {
    param($DirectState, $GroupState)
    $directDisabled = Get-DisabledPlanKeys $DirectState
    $groupDisabled = Get-DisabledPlanKeys $GroupState
    $reduced = @($groupDisabled | Where-Object { $directDisabled -notcontains $_ })
    return [pscustomobject]@{
        Pass            = ($reduced.Count -eq 0)
        ReducedPlanIds  = $reduced
        DirectDisabled  = $directDisabled
        GroupDisabled   = $groupDisabled
    }
}

function Test-GroupAssignmentReady {
    param($State, [string]$TargetGroupId)
    if ($null -eq $State) { return $false }
    $assignedBy = ConvertTo-SkuKey ([string](Get-Prop $State 'assignedByGroup'))
    if ($assignedBy -ne (ConvertTo-SkuKey $TargetGroupId)) { return $false }
    $status = [string](Get-Prop $State 'state')
    if ($status -ne 'Active') { return $false }
    if (-not (Test-Blank ([string](Get-Prop $State 'error')))) { return $false }
    return $true
}

function New-RemoveLicenseJson([string]$SkuId) {
    $guid = ([guid]$SkuId).ToString('D')
    # Built by hand: Windows PowerShell 5.1 ConvertTo-Json turns @() into null
    # and unwraps a single-item array, both of which break assignLicense.
    return ('{{"addLicenses":[],"removeLicenses":["{0}"]}}' -f $guid)
}

function Parse-SelectionIndexes {
    param(
        [string]$Text,
        [int]$Maximum
    )
    $picked = New-Object System.Collections.Generic.List[int]
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    foreach ($part in ($Text -split ',')) {
        $token = $part.Trim()
        if ($token -eq '') { continue }
        if ($token -match '^(\d+)\s*-\s*(\d+)$') {
            $start = [int]$Matches[1]
            $end = [int]$Matches[2]
            if ($start -gt $end) { $tmp = $start; $start = $end; $end = $tmp }
            for ($i = $start; $i -le $end; $i++) {
                if ($i -ge 1 -and $i -le $Maximum -and -not $picked.Contains($i)) { [void]$picked.Add($i) }
            }
            continue
        }
        $n = 0
        if (-not [int]::TryParse($token, [ref]$n) -or $n -lt 1 -or $n -gt $Maximum) {
            throw "Invalid selection '$token'. Use numbers or ranges such as 1,2,5-8."
        }
        if (-not $picked.Contains($n)) { [void]$picked.Add($n) }
    }
    return @($picked.ToArray())
}

function Get-HttpStatusFromError {
    param($ErrorRecord)
    $status = 0
    if ($null -eq $ErrorRecord) { return 0 }

    $response = $null
    try { $response = $ErrorRecord.Exception.Response } catch {}
    if ($response) {
        try {
            $code = $response.StatusCode
            if ($code -is [enum] -or $code -is [int] -or $code -is [byte]) { return [int]$code }
            if ($code -and ($code.PSObject.Properties.Name -contains 'value__')) { return [int]$code.value__ }
        } catch {}
        try {
            $code = Get-Prop $response 'StatusCode'
            if ($code) { return [int]$code }
        } catch {}
    }

    $text = ''
    try { $text = [string]$ErrorRecord.Exception.Message } catch {}
    try {
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            $text = $text + ' ' + $ErrorRecord.ErrorDetails.Message
        }
    } catch {}

    if ($text -match 'HTTP/\d\.\d\s+(\d{3})') { return [int]$Matches[1] }
    if ($text -match '\((\d{3})\)') { return [int]$Matches[1] }
    if ($text -match '\b(429|503|504)\b') { return [int]$Matches[1] }
    return $status
}

function Get-RetryAfterSeconds {
    param($ErrorRecord, [int]$Attempt)
    $fallback = [int][math]::Min(30, [math]::Pow(2, $Attempt + 1))
    $response = $null
    try { $response = $ErrorRecord.Exception.Response } catch {}
    if (-not $response) { return $fallback }
    try {
        $headers = $response.Headers
        if ($headers -and $headers['Retry-After']) {
            $raw = [string]@($headers['Retry-After'])[0]
            $n = 0
            if ([int]::TryParse($raw, [ref]$n) -and $n -ge 0) { return [int][math]::Min(60, $n) }
        }
    } catch {}
    return $fallback
}

# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------
function Graph-Get([string]$Uri) {
    # GETs may retry; mutations are never blindly retried.
    if ($null -eq $script:graphHasOutputType) {
        $cmd = Get-Command Invoke-MgGraphRequest -ErrorAction Stop
        $script:graphHasOutputType = [bool]$cmd.Parameters.ContainsKey('OutputType')
    }
    for ($attempt = 0; $attempt -lt 4; $attempt++) {
        try {
            if ($script:graphHasOutputType) {
                return (Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject)
            }
            return (Invoke-MgGraphRequest -Method GET -Uri $Uri)
        } catch {
            $status = Get-HttpStatusFromError $_
            if ($status -eq 404) { throw }
            if ($status -notin @(429, 503, 504) -or $attempt -eq 3) { throw }
            $wait = Get-RetryAfterSeconds $_ $attempt
            Write-Host "Graph GET $status; retrying in $wait second(s)..." -ForegroundColor Yellow
            Start-Sleep -Seconds $wait
        }
    }
}

function Graph-TryGet([string]$Uri) {
    try { return Graph-Get $Uri }
    catch {
        $status = Get-HttpStatusFromError $_
        if ($status -eq 404) { return $null }
        throw
    }
}

function Graph-All([string]$Uri) {
    while ($Uri) {
        $page = Graph-Get $Uri
        $items = @(Get-Prop $page 'value')
        foreach ($item in $items) {
            if ($null -ne $item) { $item }
        }
        $Uri = [string](Get-Prop $page '@odata.nextLink')
        if ([string]::IsNullOrWhiteSpace($Uri)) { $Uri = $null }
    }
}

function Graph-PostJson([string]$Uri, [string]$Json) {
    # Never retry this POST. The cmdlet parameter set is chosen before the call.
    $cmd = Get-Command Invoke-MgGraphRequest -ErrorAction Stop
    if ($cmd.Parameters.ContainsKey('ContentType')) {
        return Invoke-MgGraphRequest -Method POST -Uri $Uri -Body $Json -ContentType 'application/json'
    }
    return Invoke-MgGraphRequest -Method POST -Uri $Uri -Body $Json
}

function User-States($User) {
    $states = @(Get-Prop $User 'licenseAssignmentStates')
    $wanted = ConvertTo-SkuKey $script:skuId
    return @($states | Where-Object { (ConvertTo-SkuKey ([string](Get-Prop $_ 'skuId'))) -eq $wanted })
}

function Get-UserFresh([string]$UserId) {
    $select = 'id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled,onPremisesSecurityIdentifier,licenseAssignmentStates'
    return Graph-Get ("https://graph.microsoft.com/v1.0/users/{0}?`$select={1}" -f $UserId, $select)
}

# ---------------------------------------------------------------------------
# Logging / reports
# ---------------------------------------------------------------------------
function Initialize-Output {
    if ([string]::IsNullOrWhiteSpace($script:outputDir)) {
        $docs = [Environment]::GetFolderPath('MyDocuments')
        if ([string]::IsNullOrWhiteSpace($docs)) { $docs = [Environment]::GetFolderPath('Desktop') }
        if ([string]::IsNullOrWhiteSpace($docs)) { $docs = $PWD.Path }
        $script:outputDir = Join-Path $docs 'CopilotLicenseMigration'
    }
    if (-not (Test-Path -LiteralPath $script:outputDir)) {
        New-Item -ItemType Directory -Path $script:outputDir -Force | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
    $script:actionsPath = Join-Path $script:outputDir ("Copilot_Actions_{0}.csv" -f $stamp)
    $header = '"Timestamp","UserPrincipalName","EntraUserId","SkuId","TargetADGroup","TargetEntraGroupId","Action","Detail"'
    Set-Content -LiteralPath $script:actionsPath -Value $header -Encoding UTF8
    Write-Host "Action log: $($script:actionsPath)" -ForegroundColor Cyan
}

function Log-Action($Row, [string]$Action, [string]$Detail) {
    $upn = ''
    $id = ''
    if ($Row) {
        $upn = [string](Get-Prop $Row 'UserPrincipalName')
        $id = [string](Get-Prop $Row 'EntraUserId')
        if (-not $id) { $id = [string](Get-Prop $Row 'id') }
        if (-not $upn) { $upn = [string](Get-Prop $Row 'userPrincipalName') }
    }
    $groupDn = ''
    if ($script:adGroup) { $groupDn = [string]$script:adGroup.DistinguishedName }
    [pscustomobject]@{
        Timestamp          = (Get-Date).ToString('o')
        UserPrincipalName  = $upn
        EntraUserId        = $id
        SkuId              = $script:skuId
        TargetADGroup      = $groupDn
        TargetEntraGroupId = $script:cloudGroupId
        Action             = $Action
        Detail             = $Detail
    } | Export-Csv -LiteralPath $script:actionsPath -NoTypeInformation -Encoding UTF8 -Append
    Write-Host "${upn}: $Action - $Detail"
}

# ---------------------------------------------------------------------------
# Module / Graph connect / SKU / AD
# ---------------------------------------------------------------------------
function Ensure-GraphModule {
    $mod = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $mod) {
        Write-Host 'Microsoft.Graph.Authentication is not installed.' -ForegroundColor Yellow
        if (-not (Ask-Yes 'Install Microsoft.Graph.Authentication for CurrentUser from PSGallery?')) {
            throw 'Microsoft.Graph.Authentication is required.'
        }
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
        $mod = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Write-Host ("Using Microsoft.Graph.Authentication {0}" -f $mod.Version)
}

function Get-GraphScopes {
    $ctx = $null
    try { $ctx = Get-MgContext } catch { $ctx = $null }
    if (-not $ctx) { return @() }
    return @($ctx.Scopes)
}

function Connect-GraphRead {
    $scopes = @('User.Read.All', 'Group.Read.All', 'Organization.Read.All')
    $have = Get-GraphScopes
    $missing = @($scopes | Where-Object { $have -notcontains $_ })
    if ($have.Count -gt 0 -and $missing.Count -eq 0) { return }
    Write-Host 'Sign in to Microsoft Graph (read scopes). A browser window may open.'
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome
    } catch {
        Connect-MgGraph -Scopes $scopes
    }
}

function Connect-GraphWrite {
    $scopes = @('User.Read.All', 'Group.Read.All', 'Organization.Read.All', 'LicenseAssignment.ReadWrite.All')
    $have = Get-GraphScopes
    if ($have -contains 'LicenseAssignment.ReadWrite.All') { return }
    Write-Host 'Reconnecting with LicenseAssignment.ReadWrite.All for direct-license removal.'
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome
    } catch {
        Connect-MgGraph -Scopes $scopes
    }
}

function Pick-Sku {
    Write-Host 'Reading subscribed SKUs...'
    $all = @(Graph-All 'https://graph.microsoft.com/v1.0/subscribedSkus')
    if ($all.Count -eq 0) { throw 'No subscribed SKUs were returned. Check Organization.Read.All.' }
    $copilot = @($all | Where-Object {
        $part = [string](Get-Prop $_ 'skuPartNumber')
        $part -match 'copilot'
    })
    $showAll = ($copilot.Count -eq 0)
    if ($showAll) {
        Write-Host 'No SKU part number matched Copilot. Showing all subscribed SKUs.' -ForegroundColor Yellow
    } elseif ($script:sku -and (Ask-Yes 'List every subscribed SKU instead of Copilot matches?')) {
        $showAll = $true
    } else {
        Write-Host ("Found {0} Copilot SKU(s). Use menu option 8 to pick a different SKU." -f $copilot.Count)
    }
    $list = if ($showAll) { $all } else { $copilot }
    $list = @($list | Sort-Object { [string](Get-Prop $_ 'skuPartNumber') })
    for ($i = 0; $i -lt $list.Count; $i++) {
        $sku = $list[$i]
        $prepaid = Get-Prop $sku 'prepaidUnits'
        $enabled = Get-Prop $prepaid 'enabled'
        $consumed = Get-Prop $sku 'consumedUnits'
        Write-Host ("{0,3}. {1}  skuId={2}  enabled={3} consumed={4}  {5}" -f ($i + 1), (Get-Prop $sku 'skuPartNumber'), (Get-Prop $sku 'skuId'), $enabled, $consumed, (Get-Prop $sku 'capabilityStatus'))
    }
    $n = Pick-Number 'Select SKU' $list.Count
    if ($n -eq 0) {
        if ($script:sku) {
            Write-Host 'Keeping the current SKU.'
            return
        }
        throw 'SKU selection cancelled.'
    }
    $script:sku = $list[$n - 1]
    $script:skuId = ConvertTo-SkuKey ([string](Get-Prop $script:sku 'skuId'))
    if ([string]::IsNullOrWhiteSpace($script:skuId)) { throw 'Selected SKU has no skuId.' }
    Write-Host ("Using {0} ({1})" -f (Get-Prop $script:sku 'skuPartNumber'), $script:skuId) -ForegroundColor Cyan
}

function Ensure-AdModule {
    if (Get-Module -Name ActiveDirectory) { return }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        throw 'RSAT Active Directory module is required for AD group actions. Install RSAT-AD-PowerShell.'
    }
}

function Get-AdServerParams {
    $p = @{}
    if ($script:domainController) { $p['Server'] = $script:domainController }
    return $p
}

function Pick-DomainController {
    Ensure-AdModule
    $dcs = @(Get-ADDomainController -Filter * | Sort-Object HostName)
    $pdc = $null
    try { $pdc = (Get-ADDomain).PDCEmulator } catch {}
    if ($dcs.Count -eq 0) {
        $name = Read-Host 'No DCs discovered. Enter a domain controller host name (blank = default DC)'
        $script:domainController = if ([string]::IsNullOrWhiteSpace($name)) { $null } else { $name.Trim() }
        return
    }
    Write-Host 'Domain controllers:'
    for ($i = 0; $i -lt $dcs.Count; $i++) {
        $mark = ''
        if ($pdc -and ($dcs[$i].HostName -eq $pdc -or $dcs[$i].Name -eq $pdc)) { $mark = ' (PDC emulator)' }
        Write-Host ("{0,3}. {1}{2}" -f ($i + 1), $dcs[$i].HostName, $mark)
    }
    $n = Pick-Number 'Select domain controller' $dcs.Count
    if ($n -eq 0) {
        $script:domainController = $pdc
        Write-Host ("Using PDC emulator / default: {0}" -f $(if ($script:domainController) { $script:domainController } else { '(default)' }))
        return
    }
    $script:domainController = $dcs[$n - 1].HostName
    Write-Host ("AD writes will target {0}" -f $script:domainController) -ForegroundColor Cyan
}

function Resolve-CloudGroupFromAd {
    param($AdGroup)
    $sid = [string]$AdGroup.SID.Value
    if ([string]::IsNullOrWhiteSpace($sid)) { throw 'AD group has no SID.' }
    $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=onPremisesSecurityIdentifier eq '$sid'&`$select=id,displayName,securityEnabled,onPremisesSyncEnabled,assignedLicenses"
    $matches = @(Graph-All $uri)
    if ($matches.Count -eq 0) {
        throw "AD group '$($AdGroup.SamAccountName)' SID $sid was not found in Entra. It must already be synced."
    }
    $cloud = $matches[0]
    if ((Get-Prop $cloud 'onPremisesSyncEnabled') -ne $true) {
        throw "Entra group '$(Get-Prop $cloud 'displayName')' is not marked onPremisesSyncEnabled."
    }
    if ((Get-Prop $cloud 'securityEnabled') -ne $true) {
        throw "Entra group '$(Get-Prop $cloud 'displayName')' is not a security group."
    }
    $assigned = @(Get-Prop $cloud 'assignedLicenses')
    $hasSku = $false
    foreach ($lic in $assigned) {
        if ((ConvertTo-SkuKey ([string](Get-Prop $lic 'skuId'))) -eq $script:skuId) { $hasSku = $true; break }
    }
    if (-not $hasSku) {
        throw "Entra group '$(Get-Prop $cloud 'displayName')' does not have SKU $($script:skuId) assigned. Assign the license to the group first; this script will not do that."
    }
    return $cloud
}

function Pick-AdGroup {
    Ensure-AdModule
    if (-not $script:domainController) { Pick-DomainController }
    $adParams = Get-AdServerParams
    $query = Read-Host 'Target AD group name, sAMAccountName, GUID, or DN'
    if ([string]::IsNullOrWhiteSpace($query)) { Write-Host 'Cancelled.'; return }
    $query = $query.Trim()
    $found = @()
    try { $found = @((Get-ADGroup -Identity $query -Properties DistinguishedName,SID,SamAccountName,GroupCategory,GroupScope @adParams)) } catch { $found = @() }
    if ($found.Count -eq 0) {
        $escaped = $query.Replace("'", "''")
        $found = @(Get-ADGroup -Filter "Name -like '*$escaped*' -or SamAccountName -like '*$escaped*'" -Properties DistinguishedName,SID,SamAccountName,GroupCategory,GroupScope @adParams)
    }
    if ($found.Count -eq 0) { Write-Host 'No AD group matched.' -ForegroundColor Yellow; return }
    if ($found.Count -gt 1) {
        for ($i = 0; $i -lt $found.Count; $i++) {
            Write-Host ("{0,3}. {1}  {2}" -f ($i + 1), $found[$i].SamAccountName, $found[$i].DistinguishedName)
        }
        $n = Pick-Number 'Select AD group' $found.Count
        if ($n -eq 0) { return }
        $found = @($found[$n - 1])
    }
    $group = $found[0]
    if ($group.GroupCategory -ne 'Security') {
        Write-Host 'Warning: group category is not Security. Group-based licensing requires a security group.' -ForegroundColor Yellow
        if (-not (Ask-Yes 'Continue with this group anyway?')) { return }
    }
    Write-Host 'Resolving the synced Entra group and confirming the SKU is assigned to it...'
    $cloud = Resolve-CloudGroupFromAd $group
    $script:adGroup = $group
    $script:cloudGroupId = [string](Get-Prop $cloud 'id')
    $script:cloudGroup = $cloud
    Write-Host ("Target AD group: {0}" -f $group.DistinguishedName) -ForegroundColor Cyan
    Write-Host ("Target Entra group: {0} ({1})" -f (Get-Prop $cloud 'displayName'), $script:cloudGroupId) -ForegroundColor Cyan
}

function Get-AdUserBySid([string]$Sid) {
    Ensure-AdModule
    if ([string]::IsNullOrWhiteSpace($Sid)) { return $null }
    $adParams = Get-AdServerParams
    try {
        return Get-ADUser -Identity $Sid -Properties Enabled,DistinguishedName,SamAccountName,UserPrincipalName,objectSid,memberOf @adParams
    } catch {
        return $null
    }
}

function Test-DirectAdMember($AdUser) {
    if (-not $AdUser -or -not $script:adGroup) { return $false }
    $dn = [string]$script:adGroup.DistinguishedName
    $membership = @(Get-Prop $AdUser 'memberOf')
    foreach ($link in $membership) {
        if ([string]$link -eq $dn) { return $true }
    }
    # Refresh memberOf; Get-ADUser -Identity SID may omit it depending on properties.
    try {
        $adParams = Get-AdServerParams
        $fresh = Get-ADUser -Identity $AdUser.DistinguishedName -Properties memberOf @adParams
        foreach ($link in @($fresh.memberOf)) {
            if ([string]$link -eq $dn) { return $true }
        }
    } catch {}
    return $false
}

function Get-Eligibility($Row) {
    $reasons = New-Object System.Collections.Generic.List[string]
    $synced = $false
    if ($Row.PSObject.Properties.Name -contains 'OnPremisesSynced') { $synced = [bool]$Row.OnPremisesSynced }
    elseif ((Get-Prop $Row 'onPremisesSyncEnabled') -eq $true) { $synced = $true }
    if (-not $synced) { [void]$reasons.Add('not Entra-synced') }

    $sid = [string]$Row.OnPremisesSID
    if (-not $sid) { $sid = [string](Get-Prop $Row 'onPremisesSecurityIdentifier') }
    if ([string]::IsNullOrWhiteSpace($sid)) { [void]$reasons.Add('missing onPremisesSecurityIdentifier') }

    $adUser = $null
    if ($sid) { $adUser = Get-AdUserBySid $sid }
    if (-not $adUser) { [void]$reasons.Add('no SID-matched AD user') }
    elseif ($adUser.Enabled -ne $true) { [void]$reasons.Add('AD user is disabled') }

    return [pscustomobject]@{
        Eligible = ($reasons.Count -eq 0)
        Reasons  = ($reasons -join '; ')
        AdUser   = $adUser
        Sid      = $sid
    }
}

# ---------------------------------------------------------------------------
# Discovery / selection
# ---------------------------------------------------------------------------
function Discover {
    Write-Host 'Reading tenant users and license assignment sources...'
    $select = 'id,displayName,userPrincipalName,onPremisesSyncEnabled,onPremisesSecurityIdentifier,licenseAssignmentStates'
    $skuGuid = ([guid]$script:skuId).ToString('D')
    $uri = "https://graph.microsoft.com/v1.0/users?`$filter=assignedLicenses/any(s:s/skuId eq $skuGuid)&`$select=$select&`$top=999"
    $users = @()
    try {
        $users = @(Graph-All $uri)
    } catch {
        Write-Host "SKU filter was rejected by Graph ($($_.Exception.Message)). Falling back to paging all users." -ForegroundColor Yellow
        $uri = "https://graph.microsoft.com/v1.0/users?`$select=$select&`$top=999"
        $users = @(Graph-All $uri)
    }

    $script:rows = @(foreach ($u in $users) {
        $states = @(User-States $u)
        $direct = @($states | Where-Object { Test-DirectAssignment $_ })
        if ($direct.Count -eq 0) { continue }
        $inherited = @($states | Where-Object { -not (Test-DirectAssignment $_) })
        $directPlans = ConvertTo-IdList ($direct | ForEach-Object { Get-Prop $_ 'disabledPlans' })
        [pscustomobject]@{
            UserPrincipalName   = Get-Prop $u 'userPrincipalName'
            DisplayName         = Get-Prop $u 'displayName'
            EntraUserId         = Get-Prop $u 'id'
            SkuPartNumber       = Get-Prop $script:sku 'skuPartNumber'
            SkuId               = $script:skuId
            OnPremisesSynced    = ((Get-Prop $u 'onPremisesSyncEnabled') -eq $true)
            OnPremisesSID       = Get-Prop $u 'onPremisesSecurityIdentifier'
            DirectState         = ((@($direct | ForEach-Object { Get-Prop $_ 'state' })) -join ';')
            DirectError         = ((@($direct | ForEach-Object { Get-Prop $_ 'error' })) -join ';')
            DirectDisabledPlans = ($directPlans -join ';')
            InheritedGroupIds   = ((@($inherited | ForEach-Object { Get-Prop $_ 'assignedByGroup' })) -join ';')
            InheritedStates     = ((@($inherited | ForEach-Object { Get-Prop $_ 'state' })) -join ';')
            InheritedErrors     = ((@($inherited | ForEach-Object { Get-Prop $_ 'error' })) -join ';')
        }
    })
    $script:rows = @($script:rows | Sort-Object UserPrincipalName)
    $report = Join-Path $script:outputDir ('Copilot_DirectAssignments_' + (Get-Date -Format 'yyyyMMdd_HHmmss_fff') + '.csv')
    $cols = @('UserPrincipalName','DisplayName','EntraUserId','SkuPartNumber','SkuId','OnPremisesSynced','OnPremisesSID','DirectState','DirectError','DirectDisabledPlans','InheritedGroupIds','InheritedStates','InheritedErrors')
    if ($script:rows.Count) {
        $script:rows | Select-Object $cols | Export-Csv -LiteralPath $report -NoTypeInformation -Encoding UTF8
    } else {
        ('"' + ($cols -join '","') + '"') | Set-Content -LiteralPath $report -Encoding UTF8
    }
    Write-Host "Found $($script:rows.Count) users with a direct assignment. Report: $report" -ForegroundColor Cyan
    $script:selected = @()
}

function Select-Users {
    if (-not $script:rows.Count) { Write-Host 'No direct assignments to select.'; return }
    Write-Host "1. All reported users`n2. Select in Out-GridView`n3. Import reviewed CSV (UserPrincipalName column)`n4. Select by console numbers"
    $choice = Pick-Number 'Selection method' 4
    switch ($choice) {
        1 { $script:selected = @($script:rows) }
        2 {
            try {
                $picked = @($script:rows | Out-GridView -PassThru -Title 'Select users with a direct Copilot assignment')
                $script:selected = @($picked)
            } catch {
                Write-Host "Out-GridView is unavailable ($($_.Exception.Message)). Use console numbers." -ForegroundColor Yellow
            }
        }
        3 {
            $path = Read-Host 'CSV path'
            if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path.Trim())) {
                Write-Host 'CSV not found.'; return
            }
            $csv = @(Import-Csv -LiteralPath $path.Trim())
            if ($csv.Count -eq 0) { Write-Host 'CSV is empty.'; return }
            $names = @($csv[0].PSObject.Properties.Name)
            $col = 'UserPrincipalName'
            if ($names -notcontains $col) {
                Write-Host ("Columns: {0}" -f ($names -join ', '))
                $col = Read-Host 'Column that contains UserPrincipalName'
            }
            $wanted = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($item in $csv) {
                $value = [string](Get-Prop $item $col)
                if (-not [string]::IsNullOrWhiteSpace($value)) { [void]$wanted.Add($value.Trim()) }
            }
            $script:selected = @($script:rows | Where-Object { $wanted.Contains([string]$_.UserPrincipalName) })
            $missing = @($wanted | Where-Object { $_ -notin @($script:rows | ForEach-Object { $_.UserPrincipalName }) })
            if ($missing.Count) {
                Write-Host ("{0} CSV UPN(s) were not in the current discovery report." -f $missing.Count) -ForegroundColor Yellow
            }
        }
        4 {
            for ($i = 0; $i -lt $script:rows.Count; $i++) {
                $r = $script:rows[$i]
                Write-Host ("{0,4}. {1}  {2}  synced={3}" -f ($i + 1), $r.UserPrincipalName, $r.DisplayName, $r.OnPremisesSynced)
            }
            $raw = Read-Host 'Enter numbers or ranges (e.g. 1,2,5-8); blank cancels'
            if ([string]::IsNullOrWhiteSpace($raw)) { return }
            try {
                $idx = @(Parse-SelectionIndexes -Text $raw -Maximum $script:rows.Count)
            } catch {
                Write-Host $_.Exception.Message -ForegroundColor Yellow
                return
            }
            $script:selected = @($idx | ForEach-Object { $script:rows[$_ - 1] })
        }
        default { return }
    }
    $script:selected = @($script:selected | Sort-Object UserPrincipalName)
    Write-Host ("Selected {0} user(s)." -f $script:selected.Count) -ForegroundColor Cyan
}

function Show-Selected {
    if (-not $script:selected.Count) { Write-Host 'No users selected.'; return }
    $script:selected | Select-Object UserPrincipalName, DisplayName, OnPremisesSynced, DirectState, InheritedGroupIds | Format-Table -AutoSize | Out-Host
    Write-Host ("Selected {0} user(s)." -f $script:selected.Count)
}

# ---------------------------------------------------------------------------
# AD add / license removal
# ---------------------------------------------------------------------------
function Add-SelectedToAdGroup {
    if (-not $script:selected.Count) { Write-Host 'Select users first.'; return }
    if (-not $script:adGroup) { Write-Host 'Choose the target AD group first.'; return }
    Ensure-AdModule
    $adParams = Get-AdServerParams
    Write-Host ("Add {0} selected user(s) to {1} on {2}?" -f $script:selected.Count, $script:adGroup.SamAccountName, $(if ($script:domainController) { $script:domainController } else { 'default DC' }))
    Write-Host 'This does not trigger Entra Connect sync and does not assign the SKU to the group.'
    if (-not (Ask-Yes 'Add eligible users to the AD group now?')) { return }

    foreach ($row in $script:selected) {
        $check = Get-Eligibility $row
        if (-not $check.Eligible) {
            Log-Action $row 'SkipAdd' $check.Reasons
            continue
        }
        $adUser = $check.AdUser
        if (Test-DirectAdMember $adUser) {
            Log-Action $row 'SkipAdd' 'already a direct member of the target AD group'
            continue
        }
        try {
            Add-ADGroupMember -Identity $script:adGroup -Members $adUser -ErrorAction Stop @adParams
            $script:adAddUtc[$row.EntraUserId] = [datetime]::UtcNow
            Log-Action $row 'AddedToAdGroup' $script:adGroup.DistinguishedName
        } catch {
            Log-Action $row 'AddFailed' $_.Exception.Message
        }
    }
}

function Get-RemovalBlockReason($Row) {
    if (-not $script:adGroup -or [string]::IsNullOrWhiteSpace($script:cloudGroupId)) {
        return 'target AD/Entra group is not selected'
    }
    $check = Get-Eligibility $Row
    if (-not $check.Eligible) { return $check.Reasons }
    if (-not (Test-DirectAdMember $check.AdUser)) {
        return 'not a direct member of the target AD group'
    }

    $fresh = Get-UserFresh $Row.EntraUserId
    $states = @(User-States $fresh)
    $direct = @($states | Where-Object { Test-DirectAssignment $_ })
    if ($direct.Count -eq 0) { return 'no direct assignment remains for this SKU' }

    $fromTarget = @($states | Where-Object { Test-GroupAssignmentReady $_ $script:cloudGroupId })
    if ($fromTarget.Count -eq 0) {
        $inherited = @($states | Where-Object { -not (Test-DirectAssignment $_) -and (ConvertTo-SkuKey ([string](Get-Prop $_ 'assignedByGroup'))) -eq (ConvertTo-SkuKey $script:cloudGroupId) } | Select-Object -First 1)
        if ($inherited) {
            return "target group assignment is not a fresh Active error-free state (state=$(Get-Prop $inherited 'state'); error=$(Get-Prop $inherited 'error'))"
        }
        return 'no license assignment from the exact target Entra group yet (wait for AD sync and Entra license processing)'
    }

    $plan = Test-NoPlanReduction -DirectState $direct[0] -GroupState $fromTarget[0]
    if (-not $plan.Pass) {
        return ("group assignment would reduce enabled plans; extra disabled plan(s): {0}" -f ($plan.ReducedPlanIds -join ','))
    }
    return $null
}

function Remove-DirectForSelected {
    if (-not $script:selected.Count) { Write-Host 'Select users first.'; return }
    if (-not $script:adGroup -or -not $script:cloudGroupId) { Write-Host 'Choose the target AD group first.'; return }

    Write-Host 'Re-reading each user from Graph. Direct removal happens only when:'
    Write-Host '  - the user is SID-matched, enabled, and Entra-synced'
    Write-Host '  - the user is a direct member of the target AD group'
    Write-Host '  - Graph shows an Active, error-free assignment from that exact synced group'
    Write-Host '  - the group assignment does not disable plans that the direct assignment had enabled'
    Write-Host 'This script will not retry assignLicense on failure.'

    $preview = @()
    foreach ($row in $script:selected) {
        $reason = Get-RemovalBlockReason $row
        if ($reason) {
            $preview += [pscustomobject]@{ UserPrincipalName = $row.UserPrincipalName; Ready = $false; Reason = $reason }
        } else {
            $preview += [pscustomobject]@{ UserPrincipalName = $row.UserPrincipalName; Ready = $true; Reason = 'ready' }
        }
    }
    $preview | Format-Table -AutoSize | Out-Host
    $ready = @($preview | Where-Object Ready)
    Write-Host ("{0} of {1} selected user(s) are ready for direct removal." -f $ready.Count, $preview.Count) -ForegroundColor Cyan
    if ($ready.Count -eq 0) { return }
    if (-not (Ask-Yes 'Remove the direct SKU assignment for the ready users now?')) { return }

    Connect-GraphWrite
    $body = New-RemoveLicenseJson $script:skuId
    foreach ($row in $script:selected) {
        $reason = Get-RemovalBlockReason $row
        if ($reason) {
            Log-Action $row 'SkipRemove' $reason
            continue
        }
        $uri = "https://graph.microsoft.com/v1.0/users/$($row.EntraUserId)/assignLicense"
        try {
            Graph-PostJson $uri $body | Out-Null
            Log-Action $row 'RemovedDirect' "Removed direct skuId $($script:skuId); group assignment retained"
        } catch {
            Log-Action $row 'RemoveFailed' $_.Exception.Message
        }
    }
}

function Wait-ThenRemove {
    if (-not $script:selected.Count) { Write-Host 'Select users first.'; return }
    $raw = Read-Host 'Poll Graph for up to how many minutes for the target group assignment? (blank cancels)'
    if ([string]::IsNullOrWhiteSpace($raw)) { return }
    $minutes = 0
    if (-not [int]::TryParse($raw.Trim(), [ref]$minutes) -or $minutes -lt 1) {
        Write-Host 'Enter a positive number of minutes.'; return
    }
    $deadline = (Get-Date).AddMinutes($minutes)
    Write-Host "Polling until $deadline. AD sync is not triggered by this script."
    do {
        $blocked = 0
        foreach ($row in $script:selected) {
            $reason = Get-RemovalBlockReason $row
            if ($reason) {
                $blocked++
                Write-Host ("  waiting: {0} - {1}" -f $row.UserPrincipalName, $reason) -ForegroundColor DarkYellow
            } else {
                Write-Host ("  ready:   {0}" -f $row.UserPrincipalName) -ForegroundColor Green
            }
        }
        if ($blocked -eq 0) { break }
        if ((Get-Date) -ge $deadline) {
            Write-Host 'Timed out waiting for group assignments.' -ForegroundColor Yellow
            break
        }
        Start-Sleep -Seconds 30
    } while ((Get-Date) -lt $deadline)
    Remove-DirectForSelected
}

# ---------------------------------------------------------------------------
# Self-test (no Graph / AD)
# ---------------------------------------------------------------------------
function Invoke-SelfTest {
    $script:failed = 0
    function Assert-True($cond, [string]$name) {
        if ($cond) { Write-Host "PASS $name" -ForegroundColor Green }
        else { Write-Host "FAIL $name" -ForegroundColor Red; $script:failed = $script:failed + 1 }
    }

    Assert-True (Test-DirectAssignment ([pscustomobject]@{ assignedByGroup = $null; skuId = 'x' })) 'direct when assignedByGroup is null'
    Assert-True (Test-DirectAssignment ([pscustomobject]@{ assignedByGroup = ''; skuId = 'x' })) 'direct when assignedByGroup is empty'
    Assert-True (-not (Test-DirectAssignment ([pscustomobject]@{ assignedByGroup = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' }))) 'inherited when assignedByGroup is set'

    $direct = [pscustomobject]@{ disabledPlans = @('11111111-1111-1111-1111-111111111111') }
    $groupOk = [pscustomobject]@{ disabledPlans = @('11111111-1111-1111-1111-111111111111') }
    $groupWorse = [pscustomobject]@{ disabledPlans = @('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222') }
    Assert-True ((Test-NoPlanReduction $direct $groupOk).Pass) 'no reduction when group disables the same plans'
    Assert-True (-not (Test-NoPlanReduction $direct $groupWorse).Pass) 'reduction when group disables an extra plan'
    Assert-True ((Test-NoPlanReduction ([pscustomobject]@{ disabledPlans = @() }) ([pscustomobject]@{ disabledPlans = @() })).Pass) 'no reduction when both enable all plans'

    $ready = [pscustomobject]@{ assignedByGroup = 'BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB'; state = 'Active'; error = $null }
    Assert-True (Test-GroupAssignmentReady $ready 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb') 'group assignment ready (Active, no error, matching group)'
    Assert-True (-not (Test-GroupAssignmentReady $ready 'cccccccccccccccccccccccccccccccccccc')) 'group assignment rejected for a different group'
    Assert-True (-not (Test-GroupAssignmentReady ([pscustomobject]@{ assignedByGroup = $ready.assignedByGroup; state = 'ActiveWithError'; error = $null }) $ready.assignedByGroup)) 'ActiveWithError is not ready'
    Assert-True (-not (Test-GroupAssignmentReady ([pscustomobject]@{ assignedByGroup = $ready.assignedByGroup; state = 'Active'; error = 'CountViolation' }) $ready.assignedByGroup)) 'error state is not ready'

    $json = New-RemoveLicenseJson '639dec6b-bb19-468b-871c-c5c441c4b0cb'
    Assert-True ($json -eq '{"addLicenses":[],"removeLicenses":["639dec6b-bb19-468b-871c-c5c441c4b0cb"]}') 'assignLicense JSON keeps empty addLicenses array'
    Assert-True ($json -notmatch '"addLicenses":null') 'assignLicense JSON does not use null addLicenses'
    Assert-True ($json -match '"removeLicenses":\[') 'assignLicense JSON keeps removeLicenses as an array'

    $idx = Parse-SelectionIndexes -Text '1,3-5,2' -Maximum 8
    Assert-True (($idx -join ',') -eq '1,3,4,5,2') 'selection parser accepts lists and ranges'

    $nested = ConvertTo-IdList @(@('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'), 'BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB')
    Assert-True ($nested.Count -eq 2) 'disabledPlans nested arrays flatten to two ids'

    $err = [pscustomobject]@{ Exception = [pscustomobject]@{ Message = 'GET https://graph.microsoft.com/v1.0/users HTTP/1.1 429 Too Many Requests'; Response = $null }; ErrorDetails = $null }
    Assert-True ((Get-HttpStatusFromError $err) -eq 429) 'HTTP status parsed from Graph error text'

    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$null, [ref]$parseErrors)
    Assert-True (@($parseErrors).Count -eq 0) 'script AST has no parse errors'

    if ($script:failed -gt 0) { throw "$($script:failed) self-test assertion(s) failed." }
    Write-Host 'Self-test passed.' -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------
function Show-Menu {
    Write-Host ''
    Write-Host '==============================================================' -ForegroundColor Cyan
    $skuLabel = if ($script:sku) { Get-Prop $script:sku 'skuPartNumber' } else { '(none)' }
    $groupLabel = if ($script:adGroup) { $script:adGroup.SamAccountName } else { '(none)' }
    Write-Host ("SKU: {0}   AD group: {1}   Selected: {2}   Reported: {3}" -f $skuLabel, $groupLabel, @($script:selected).Count, @($script:rows).Count)
    Write-Host '1. Discover users with a direct assignment of this SKU'
    Write-Host '2. Select users'
    Write-Host '3. Show selected users'
    Write-Host '4. Choose domain controller and target AD group'
    Write-Host '5. Add selected users to the AD group'
    Write-Host '6. Remove direct licenses (safety-checked, no retry)'
    Write-Host '7. Wait for group assignment, then remove direct licenses'
    Write-Host '8. Re-pick SKU'
    Write-Host 'Q. Quit'
    Write-Host '==============================================================' -ForegroundColor Cyan
}

function Start-Interactive {
    Ensure-GraphModule
    Initialize-Output
    Connect-GraphRead
    Pick-Sku
    $script:rows = @()
    $script:selected = @()
    $script:adGroup = $null
    $script:cloudGroupId = ''
    $script:cloudGroup = $null
    $script:domainController = $null
    $script:adAddUtc = @{}

    Write-Host ''
    Write-Host 'Run discovery, select a few users, add them to the already-licensed synced group,'
    Write-Host 'wait for Entra Connect, then remove direct assignments. Do not start with everyone.'
    while ($true) {
        Show-Menu
        $choice = Read-Host 'Choice'
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }
        try {
            switch -Regex ($choice.Trim()) {
                '^[Qq]$' { return }
                '^1$' { Discover }
                '^2$' { Select-Users }
                '^3$' { Show-Selected }
                '^4$' { Pick-AdGroup }
                '^5$' { Add-SelectedToAdGroup }
                '^6$' { Remove-DirectForSelected }
                '^7$' { Wait-ThenRemove }
                '^8$' { Pick-Sku }
                default { Write-Host 'Enter 1-8 or Q.' -ForegroundColor Yellow }
            }
        } catch {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }
}

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------
$script:outputDir = $OutputDirectory
$script:sku = $null
$script:skuId = ''
$script:rows = @()
$script:selected = @()
$script:adGroup = $null
$script:cloudGroupId = ''
$script:actionsPath = $null
$script:adAddUtc = @{}
$script:graphHasOutputType = $null

if ($SelfTest) {
    Invoke-SelfTest
    return
}

Start-Interactive

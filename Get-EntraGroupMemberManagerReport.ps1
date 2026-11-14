<#
.SYNOPSIS
    Export Entra ID group members with UPN, on-premises SAM account name, and manager details.

.DESCRIPTION
    Queries a cloud-only Entra ID (Azure AD) group and, for each user member, returns:

      - User UPN
      - User on-premises SamAccountName (Entra Connect / Cloud Sync attribute)
      - Manager display name
      - Manager email address
      - Manager UPN

    Defaults to the MFA-SMS_Users cloud-only group:

      Group Name : MFA-SMS_Users
      Object ID  : cf5c24b8-2289-4311-8b80-e43e6df8455d

    Built for Windows PowerShell 5.1. It uses Microsoft Graph (Microsoft.Graph.Authentication
    only — not the full Microsoft.Graph module set) and prefers a single paged members
    query with $expand=manager so manager data is retrieved in the same round-trips.
    If Graph rejects that expand, managers are resolved with the JSON $batch endpoint
    (20 requests per call) instead of one HTTP call per user.

.PARAMETER GroupId
    Entra ID object ID of the group. Defaults to the MFA-SMS_Users group.

.PARAMETER GroupName
    Expected display name of the group. Used in the report header and to warn if the
    object ID resolves to a different name.

.PARAMETER OutputPath
    CSV path for the report. Defaults to .\MFA-SMS_Users_MemberReport_<timestamp>.csv
    in the current directory.

.PARAMETER TenantId
    Optional tenant ID or domain (contoso.onmicrosoft.com) for Connect-MgGraph.

.PARAMETER Transitive
    Include nested group membership (transitiveMembers) instead of direct members only.

.PARAMETER ShowGridView
    Open the results in Out-GridView after the CSV is written.

.PARAMETER PassThru
    Write result objects to the pipeline in addition to exporting CSV.

.PARAMETER SkipConnect
    Skip Connect-MgGraph. Use when this session is already authenticated to Graph
    with GroupMember.Read.All (or Group.Read.All) and User.Read.All.

.PARAMETER Disconnect
    Call Disconnect-MgGraph when the script finishes.

.EXAMPLE
    .\Get-EntraGroupMemberManagerReport.ps1

    Sign in interactively, query MFA-SMS_Users, and write a timestamped CSV.

.EXAMPLE
    .\Get-EntraGroupMemberManagerReport.ps1 -OutputPath C:\Temp\MFA-SMS_Users.csv -ShowGridView

    Save to a specific path and review the rows in Out-GridView.

.EXAMPLE
    .\Get-EntraGroupMemberManagerReport.ps1 -GroupId 'cf5c24b8-2289-4311-8b80-e43e6df8455d' -Transitive

    Include users nested through member groups.

.NOTES
    Version     : 1.0
    Compatible  : Windows PowerShell 5.1 (also runs on PowerShell 7+)
    Requires    : Microsoft.Graph.Authentication
    Permissions : GroupMember.Read.All (or Group.Read.All), User.Read.All
                  Directory.Read.All also works as a single broader alternative.

    onPremisesSamAccountName is populated by Entra Connect / Cloud Sync. Cloud-only
    users (never synced from AD) will have an empty SAM column. That is expected.

    Sign-in account must be able to read group membership and user manager properties.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$GroupId = 'cf5c24b8-2289-4311-8b80-e43e6df8455d',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$GroupName = 'MFA-SMS_Users',

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [switch]$Transitive,

    [Parameter()]
    [switch]$ShowGridView,

    [Parameter()]
    [switch]$PassThru,

    [Parameter()]
    [switch]$SkipConnect,

    [Parameter()]
    [switch]$Disconnect
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# CONSTANTS
# ============================================================
$script:GraphBaseUrl      = 'https://graph.microsoft.com/v1.0'
$script:GraphBatchSize    = 20
$script:GraphPageSize     = 999
$script:UserSelectFields  = 'id,displayName,userPrincipalName,mail,onPremisesSamAccountName,accountEnabled'
$script:ManagerSelect     = 'id,displayName,mail,userPrincipalName'
$script:RequiredScopes    = @('GroupMember.Read.All', 'User.Read.All')
$script:AppVersion        = '1.0'

# ============================================================
# OUTPUT HELPERS
# ============================================================
function Get-Timestamp {
    Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
}

function Write-ReportLog {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        default   { 'Cyan' }
    }

    Write-Host ("[{0}] [{1}] {2}" -f (Get-Timestamp), $Level, $Message) -ForegroundColor $color
}

function Get-GraphProperty {
    <#
    .SYNOPSIS
        Read a property from a Graph hashtable or PSCustomObject without StrictMode errors.
    #>
    param(
        [AllowNull()]
        $Object,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) {
            return $Object[$Name]
        }
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function ConvertTo-PlainText {
    param(
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return ([string]$Value).Trim()
}

function ConvertTo-GraphBatchJson {
    <#
    .SYNOPSIS
        Build a Graph $batch JSON payload without PowerShell 5.1 collapsing a
        single-item requests array into an object.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Requests
    )

    $requestJsonItems = New-Object 'System.Collections.Generic.List[string]'
    foreach ($request in @($Requests)) {
        $itemJson = ($request | ConvertTo-Json -Depth 6 -Compress)
        [void]$requestJsonItems.Add($itemJson)
    }

    return ('{{"requests":[{0}]}}' -f ($requestJsonItems -join ','))
}

function Get-DefaultOutputPath {
    param([string]$Name)

    $safeName = ($Name -replace '[\\/:*?"<>|]', '_')
    $fileName = '{0}_MemberReport_{1}.csv' -f $safeName, (Get-Date -Format 'yyyyMMdd_HHmmss')
    return Join-Path -Path (Get-Location).Path -ChildPath $fileName
}

# ============================================================
# MODULE / CONNECTION
# ============================================================
function Initialize-GraphTls {
    try {
        $current = [Net.ServicePointManager]::SecurityProtocol
        $tls12   = [Net.SecurityProtocolType]::Tls12
        if (($current -band $tls12) -ne $tls12) {
            [Net.ServicePointManager]::SecurityProtocol = $current -bor $tls12
        }
    } catch {
        Write-ReportLog "Could not pin TLS 1.2: $($_.Exception.Message)" 'WARN'
    }
}

function Import-GraphAuthenticationModule {
    $moduleName = 'Microsoft.Graph.Authentication'

    if (Get-Module -Name $moduleName -ErrorAction SilentlyContinue) {
        return
    }

    $available = Get-Module -ListAvailable -Name $moduleName | Select-Object -First 1
    if (-not $available) {
        Write-ReportLog "Installing $moduleName from PSGallery (CurrentUser)..." 'INFO'
        try {
            $installParams = @{
                Name         = $moduleName
                Scope        = 'CurrentUser'
                Force        = $true
                AllowClobber = $true
                ErrorAction  = 'Stop'
            }
            if (Get-Command Install-Module -ErrorAction SilentlyContinue) {
                Install-Module @installParams
            } else {
                throw 'Install-Module is not available. Install PowerShellGet, then install Microsoft.Graph.Authentication.'
            }
        } catch {
            throw @"
Failed to install $moduleName.

Install it manually in an elevated or CurrentUser session:

    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force

Original error: $($_.Exception.Message)
"@
        }
    }

    Import-Module -Name $moduleName -ErrorAction Stop
    Write-ReportLog "Loaded $moduleName" 'SUCCESS'
}

function Connect-EntraGraph {
    param(
        [string]$Tenant,
        [switch]$Skip,
        [string[]]$Scopes
    )

    if ($Skip) {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($null -eq $context) {
            throw 'SkipConnect was set but this session is not connected to Microsoft Graph. Run Connect-MgGraph first or omit -SkipConnect.'
        }
        $account = ConvertTo-PlainText (Get-GraphProperty -Object $context -Name 'Account')
        if ([string]::IsNullOrWhiteSpace($account)) {
            $account = 'app-only / current context'
        }
        Write-ReportLog ("Using existing Graph connection as {0}" -f $account) 'INFO'
        return $context
    }

    $connectParams = @{
        Scopes      = $Scopes
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($Tenant)) {
        $connectParams['TenantId'] = $Tenant
    }

    Write-ReportLog ('Connecting to Microsoft Graph (scopes: {0})...' -f ($Scopes -join ', ')) 'INFO'

    $connected = $false
    try {
        Connect-MgGraph @connectParams -NoWelcome
        $connected = $true
    } catch {
        if ($_.Exception.Message -notmatch 'NoWelcome') {
            throw
        }
        Connect-MgGraph @connectParams
        $connected = $true
    }

    if (-not $connected) {
        throw 'Connect-MgGraph did not complete.'
    }

    $context = Get-MgContext
    $account = ConvertTo-PlainText (Get-GraphProperty -Object $context -Name 'Account')
    if ([string]::IsNullOrWhiteSpace($account)) {
        $account = '(app-only)'
    }
    $tenantIdValue = ConvertTo-PlainText (Get-GraphProperty -Object $context -Name 'TenantId')
    Write-ReportLog ("Connected as {0} (tenant {1})" -f $account, $tenantIdValue) 'SUCCESS'
    return $context
}

# ============================================================
# GRAPH HTTP
# ============================================================
function Get-GraphRetryAfterSeconds {
    param(
        $ErrorRecord,
        [int]$Attempt
    )

    $headerValue = $null
    try {
        $response = $ErrorRecord.Exception.Response
        if ($response -and $response.Headers) {
            $headerValue = $response.Headers['Retry-After']
            if (-not $headerValue -and $response.Headers.Contains) {
                if ($response.Headers.Contains('Retry-After')) {
                    $headerValue = $response.Headers.GetValues('Retry-After') | Select-Object -First 1
                }
            }
        }
    } catch {
        $headerValue = $null
    }

    $seconds = 0
    if ($headerValue -and [int]::TryParse([string]$headerValue, [ref]$seconds) -and $seconds -gt 0) {
        return [Math]::Min($seconds, 60)
    }

    return [Math]::Min(60, [Math]::Pow(2, $Attempt))
}

function Test-GraphThrottled {
    param($ErrorRecord)

    $message = [string]$ErrorRecord.Exception.Message
    if ($message -match '(^|[^\d])429([^\d]|$)|Too Many Requests|Request_ThrottledTemporarily') {
        return $true
    }

    try {
        $status = $ErrorRecord.Exception.Response.StatusCode
        if ($status -and ([int]$status -eq 429)) {
            return $true
        }
    } catch {
        return $false
    }

    return $false
}

function Invoke-GraphRequestRetry {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        $Body,

        [int]$MaxAttempts = 6
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $Body -ErrorAction Stop
            }
            return Invoke-MgGraphRequest -Method $Method -Uri $Uri -ErrorAction Stop
        } catch {
            $throttled = Test-GraphThrottled -ErrorRecord $_
            if ($throttled -and $attempt -lt $MaxAttempts) {
                $wait = Get-GraphRetryAfterSeconds -ErrorRecord $_ -Attempt $attempt
                Write-ReportLog "Graph throttled the request. Retrying in $wait second(s) (attempt $attempt/$MaxAttempts)..." 'WARN'
                Start-Sleep -Seconds $wait
                continue
            }
            throw
        }
    }
}

function Get-GraphPagedCollection {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [string]$ProgressActivity = 'Querying Microsoft Graph'
    )

    $items = New-Object 'System.Collections.Generic.List[object]'
    $next  = $Uri
    $page  = 0

    while (-not [string]::IsNullOrWhiteSpace($next)) {
        $page++
        Write-Progress -Activity $ProgressActivity -Status "Downloading page $page..." -PercentComplete -1
        Write-Verbose "GET $next"

        $response = Invoke-GraphRequestRetry -Method GET -Uri $next
        $value    = Get-GraphProperty -Object $response -Name 'value'

        if ($null -ne $value) {
            foreach ($item in @($value)) {
                [void]$items.Add($item)
            }
        }

        $next = Get-GraphProperty -Object $response -Name '@odata.nextLink'
        Write-ReportLog ("Retrieved page {0} ({1} item(s) so far)" -f $page, $items.Count) 'INFO'
    }

    Write-Progress -Activity $ProgressActivity -Completed
    return $items
}

# ============================================================
# GROUP / MEMBER / MANAGER
# ============================================================
function Get-EntraGroupInfo {
    param([string]$Id)

    $select = 'id,displayName,description,groupTypes,mailEnabled,securityEnabled,membershipRule,onPremisesSyncEnabled,mailNickname'
    $uri    = '{0}/groups/{1}?$select={2}' -f $script:GraphBaseUrl, $Id, $select
    Write-Verbose "GET $uri"
    return Invoke-GraphRequestRetry -Method GET -Uri $uri
}

function Get-GroupMemberUsers {
    param(
        [string]$Id,
        [switch]$UseTransitive,
        [switch]$ExpandManager
    )

    $nav = 'members'
    if ($UseTransitive) {
        $nav = 'transitiveMembers'
    }

    $query = '?$select={0}&$top={1}' -f $script:UserSelectFields, $script:GraphPageSize
    if ($ExpandManager) {
        $query += '&$expand=manager($select={0})' -f $script:ManagerSelect
    }

    $uri = '{0}/groups/{1}/{2}/microsoft.graph.user{3}' -f $script:GraphBaseUrl, $Id, $nav, $query
    $activity = if ($UseTransitive) { 'Downloading transitive user members' } else { 'Downloading direct user members' }

    Write-ReportLog ("Querying Graph {0} as users (expand manager: {1})..." -f $nav, [bool]$ExpandManager) 'INFO'
    return Get-GraphPagedCollection -Uri $uri -ProgressActivity $activity
}

function ConvertTo-ManagerInfo {
    param(
        [AllowNull()]
        $ManagerObject
    )

    $info = [ordered]@{
        Name  = ''
        Email = ''
        UPN   = ''
        Id    = ''
    }

    if ($null -eq $ManagerObject) {
        return [pscustomobject]$info
    }

    $odataType = ConvertTo-PlainText (Get-GraphProperty -Object $ManagerObject -Name '@odata.type')
    if ($odataType -eq '#microsoft.graph.null') {
        return [pscustomobject]$info
    }

    $info.Name  = ConvertTo-PlainText (Get-GraphProperty -Object $ManagerObject -Name 'displayName')
    $info.Email = ConvertTo-PlainText (Get-GraphProperty -Object $ManagerObject -Name 'mail')
    $info.UPN   = ConvertTo-PlainText (Get-GraphProperty -Object $ManagerObject -Name 'userPrincipalName')
    $info.Id    = ConvertTo-PlainText (Get-GraphProperty -Object $ManagerObject -Name 'id')

    return [pscustomobject]$info
}

function Test-ManagerExpanded {
    param($Members)

    if ($null -eq $Members -or $Members.Count -eq 0) {
        return $true
    }

    $sampleSize = [Math]::Min(10, $Members.Count)
    $withProperty = 0

    for ($i = 0; $i -lt $sampleSize; $i++) {
        $member = $Members[$i]
        if ($member -is [System.Collections.IDictionary]) {
            if ($member.Contains('manager')) {
                $withProperty++
            }
            continue
        }

        if ($null -ne $member.PSObject.Properties['manager']) {
            $withProperty++
        }
    }

    return ($withProperty -gt 0)
}

function Get-UserManagersByBatch {
    param(
        [Parameter(Mandatory)]
        [string[]]$UserIds
    )

    $map = @{}
    if ($null -eq $UserIds -or $UserIds.Count -eq 0) {
        return $map
    }

    $total      = $UserIds.Count
    $batchCount = [Math]::Ceiling($total / [double]$script:GraphBatchSize)
    $batchIndex = 0
    $uri        = '{0}/$batch' -f $script:GraphBaseUrl

    Write-ReportLog ("Resolving managers with Graph `$batch ({0} user(s), {1} batch(es))..." -f $total, $batchCount) 'INFO'

    for ($offset = 0; $offset -lt $total; $offset += $script:GraphBatchSize) {
        $batchIndex++
        $end = [Math]::Min($offset + $script:GraphBatchSize - 1, $total - 1)
        $chunk = $UserIds[$offset..$end]

        Write-Progress -Activity 'Resolving managers' -Status ("Batch {0} of {1}" -f $batchIndex, $batchCount) -PercentComplete (($batchIndex / $batchCount) * 100)

        $requests = New-Object 'System.Collections.Generic.List[hashtable]'
        foreach ($userId in $chunk) {
            [void]$requests.Add(@{
                id     = [string]$userId
                method = 'GET'
                url    = '/users/{0}/manager?$select={1}' -f $userId, $script:ManagerSelect
            })
        }

        $retryIds  = New-Object 'System.Collections.Generic.List[string]'
        $batchJson = ConvertTo-GraphBatchJson -Requests @($requests.ToArray())

        $response  = Invoke-GraphRequestRetry -Method POST -Uri $uri -Body $batchJson
        $responses = @(Get-GraphProperty -Object $response -Name 'responses')

        foreach ($item in $responses) {
            $id     = ConvertTo-PlainText (Get-GraphProperty -Object $item -Name 'id')
            $status = [int](Get-GraphProperty -Object $item -Name 'status')
            $body   = Get-GraphProperty -Object $item -Name 'body'

            if ($status -eq 200) {
                $map[$id] = ConvertTo-ManagerInfo -ManagerObject $body
            } elseif ($status -eq 404) {
                $map[$id] = ConvertTo-ManagerInfo -ManagerObject $null
            } elseif ($status -eq 429) {
                [void]$retryIds.Add($id)
            } else {
                Write-ReportLog ("Manager lookup failed for {0} (HTTP {1})" -f $id, $status) 'WARN'
                $map[$id] = ConvertTo-ManagerInfo -ManagerObject $null
            }
        }

        if ($retryIds.Count -gt 0) {
            Write-ReportLog ("Retrying {0} throttled manager lookup(s)..." -f $retryIds.Count) 'WARN'
            Start-Sleep -Seconds 2
            foreach ($retryId in $retryIds) {
                try {
                    $managerUri = '{0}/users/{1}/manager?$select={2}' -f $script:GraphBaseUrl, $retryId, $script:ManagerSelect
                    $manager    = Invoke-GraphRequestRetry -Method GET -Uri $managerUri
                    $map[$retryId] = ConvertTo-ManagerInfo -ManagerObject $manager
                } catch {
                    if ($_.Exception.Message -match '404|Request_ResourceNotFound|does not exist') {
                        $map[$retryId] = ConvertTo-ManagerInfo -ManagerObject $null
                    } else {
                        Write-ReportLog ("Manager retry failed for {0}: {1}" -f $retryId, $_.Exception.Message) 'WARN'
                        $map[$retryId] = ConvertTo-ManagerInfo -ManagerObject $null
                    }
                }
            }
        }
    }

    Write-Progress -Activity 'Resolving managers' -Completed
    return $map
}

function ConvertTo-MemberReportRow {
    param(
        $Member,
        $ManagerInfo
    )

    $upn = ConvertTo-PlainText (Get-GraphProperty -Object $Member -Name 'userPrincipalName')
    $sam = ConvertTo-PlainText (Get-GraphProperty -Object $Member -Name 'onPremisesSamAccountName')

    if ($null -eq $ManagerInfo) {
        $ManagerInfo = ConvertTo-ManagerInfo -ManagerObject $null
    }

    [pscustomobject]@{
        UserDisplayName          = ConvertTo-PlainText (Get-GraphProperty -Object $Member -Name 'displayName')
        UserPrincipalName        = $upn
        OnPremisesSamAccountName = $sam
        ManagerName              = $ManagerInfo.Name
        ManagerEmail             = $ManagerInfo.Email
        ManagerUPN               = $ManagerInfo.UPN
        AccountEnabled           = Get-GraphProperty -Object $Member -Name 'accountEnabled'
        UserObjectId             = ConvertTo-PlainText (Get-GraphProperty -Object $Member -Name 'id')
    }
}

# ============================================================
# MAIN
# ============================================================
$reportRows = New-Object 'System.Collections.Generic.List[object]'
$connectedThisRun = $false

try {
    Write-Host ''
    Write-ReportLog "Entra Group Member + Manager Report v$script:AppVersion" 'INFO'
    Write-ReportLog "PowerShell $($PSVersionTable.PSVersion)" 'INFO'

    Initialize-GraphTls
    Import-GraphAuthenticationModule
    $null = Connect-EntraGraph -Tenant $TenantId -Skip:$SkipConnect -Scopes $script:RequiredScopes
    $connectedThisRun = -not $SkipConnect

    Write-ReportLog "Looking up group $GroupId..." 'INFO'
    $group = Get-EntraGroupInfo -Id $GroupId

    $resolvedName = ConvertTo-PlainText (Get-GraphProperty -Object $group -Name 'displayName')
    $syncEnabled  = Get-GraphProperty -Object $group -Name 'onPremisesSyncEnabled'
    $groupTypes   = @(Get-GraphProperty -Object $group -Name 'groupTypes')
    $isCloudOnly  = ($null -eq $syncEnabled -or $syncEnabled -eq $false)

    if (-not [string]::IsNullOrWhiteSpace($GroupName) -and $resolvedName -ne $GroupName) {
        Write-ReportLog ("Group display name is '{0}', expected '{1}'. Continuing with the object ID." -f $resolvedName, $GroupName) 'WARN'
    }

    $cloudLabel = 'Yes'
    if (-not $isCloudOnly) {
        $cloudLabel = 'No (synced from on-premises)'
    }

    Write-ReportLog ("Group     : {0}" -f $resolvedName) 'SUCCESS'
    Write-ReportLog ("Object ID : {0}" -f (Get-GraphProperty -Object $group -Name 'id')) 'INFO'
    Write-ReportLog ("Cloud-only: {0}" -f $cloudLabel) 'INFO'
    if ($groupTypes.Count -gt 0) {
        Write-ReportLog ("Types     : {0}" -f ($groupTypes -join ', ')) 'INFO'
    }

    $members = $null
    $expanded = $false
    try {
        $members  = Get-GroupMemberUsers -Id $GroupId -UseTransitive:$Transitive -ExpandManager
        $expanded = Test-ManagerExpanded -Members $members
        if (-not $expanded -and $members.Count -gt 0) {
            Write-ReportLog 'Graph returned members but did not include expanded manager objects. Falling back to $batch.' 'WARN'
        }
    } catch {
        Write-ReportLog ("Member query with `$expand=manager failed: {0}" -f $_.Exception.Message) 'WARN'
        Write-ReportLog 'Retrying member query without expand, then resolving managers via $batch.' 'INFO'
        $members  = Get-GroupMemberUsers -Id $GroupId -UseTransitive:$Transitive
        $expanded = $false
    }

    Write-ReportLog ("User members returned: {0}" -f $members.Count) 'SUCCESS'

    $managerMap = @{}
    if (-not $expanded -and $members.Count -gt 0) {
        $userIds = foreach ($member in $members) {
            ConvertTo-PlainText (Get-GraphProperty -Object $member -Name 'id')
        }
        $userIds = @($userIds | Where-Object { $_ -ne '' } | Select-Object -Unique)
        $managerMap = Get-UserManagersByBatch -UserIds $userIds
    }

    foreach ($member in $members) {
        $userId = ConvertTo-PlainText (Get-GraphProperty -Object $member -Name 'id')

        if ($expanded) {
            $managerInfo = ConvertTo-ManagerInfo -ManagerObject (Get-GraphProperty -Object $member -Name 'manager')
        } else {
            $managerInfo = $null
            if ($userId -and $managerMap.ContainsKey($userId)) {
                $managerInfo = $managerMap[$userId]
            }
        }

        [void]$reportRows.Add((ConvertTo-MemberReportRow -Member $member -ManagerInfo $managerInfo))
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Get-DefaultOutputPath -Name $resolvedName
    } else {
        $directory = Split-Path -Path $OutputPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
    }

    $sortedRows = @($reportRows | Sort-Object -Property UserDisplayName, UserPrincipalName)
    if ($sortedRows.Count -eq 0) {
        'UserDisplayName,UserPrincipalName,OnPremisesSamAccountName,ManagerName,ManagerEmail,ManagerUPN,AccountEnabled,UserObjectId' |
            Set-Content -Path $OutputPath -Encoding UTF8
    } else {
        $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    }

    $withSam     = @($reportRows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.OnPremisesSamAccountName) }).Count
    $withManager = @($reportRows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ManagerUPN) -or -not [string]::IsNullOrWhiteSpace($_.ManagerName) }).Count
    $enabled     = @($reportRows | Where-Object { $_.AccountEnabled -eq $true }).Count

    Write-Host ''
    Write-ReportLog 'Report complete' 'SUCCESS'
    Write-ReportLog ("Users exported              : {0}" -f $reportRows.Count) 'INFO'
    Write-ReportLog ("Enabled accounts            : {0}" -f $enabled) 'INFO'
    Write-ReportLog ("With on-premises SAM        : {0}" -f $withSam) 'INFO'
    Write-ReportLog ("With a manager              : {0}" -f $withManager) 'INFO'
    Write-ReportLog ("CSV                         : {0}" -f $OutputPath) 'SUCCESS'
    Write-Host ''
    Write-Host 'Columns: UserPrincipalName, OnPremisesSamAccountName, ManagerName, ManagerEmail, ManagerUPN' -ForegroundColor DarkGray
    Write-Host ''

    $table = $reportRows |
        Sort-Object -Property UserDisplayName, UserPrincipalName |
        Select-Object UserDisplayName, UserPrincipalName, OnPremisesSamAccountName, ManagerName, ManagerEmail, ManagerUPN

    $table | Format-Table -AutoSize | Out-Host

    if ($ShowGridView) {
        try {
            $table | Out-GridView -Title ("{0} member report" -f $resolvedName)
        } catch {
            Write-ReportLog ("Out-GridView is not available in this host: {0}" -f $_.Exception.Message) 'WARN'
        }
    }

    if ($PassThru) {
        $reportRows.ToArray()
    }
} catch {
    Write-ReportLog $_.Exception.Message 'ERROR'
    if ($_.ScriptStackTrace) {
        Write-Verbose $_.ScriptStackTrace
    }
    exit 1
} finally {
    if ($Disconnect -and $connectedThisRun) {
        try {
            Disconnect-MgGraph | Out-Null
            Write-ReportLog 'Disconnected from Microsoft Graph' 'INFO'
        } catch {
            Write-ReportLog "Disconnect-MgGraph failed: $($_.Exception.Message)" 'WARN'
        }
    }
}

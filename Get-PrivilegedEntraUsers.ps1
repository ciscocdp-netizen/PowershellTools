<#
.SYNOPSIS
    Returns Entra ID (Azure AD) privileged directory role assignments for users,
    service principals, and groups.

.DESCRIPTION
    Connects to Microsoft Graph using the Microsoft Graph PowerShell SDK and enumerates
    every directory role definition flagged by Microsoft as privileged (isPrivileged = true).

    For each privileged role it resolves:
        - Active assignments
              * Permanent  - standing assignment with no end date
              * Time-bound - standing assignment that expires
              * Activated  - currently activated PIM eligible assignment
        - Eligible assignments (PIM eligible; requires Entra ID P2 + PIM)

    Each assignment is attributed to the directory principal it is granted to:
        - User
        - Service principal (enterprise apps, managed identities, etc.)
        - Group (role-assignable groups)

    Group assignments are reported in two ways:
        1. A row for the group itself (so you can see which groups hold privileged roles
           and whether that grant is Eligible or Permanent/Active).
        2. A row for every transitive user and service-principal member, with
           AssignmentPath = Group and AssignedVia = "Group: <group name>".

    Direct assignments use AssignmentPath = Direct.

    Signs in with the OAuth 2.0 device code flow (no local browser is required).
    The device code is printed in the console and, by default, copied to the clipboard
    so it can be pasted at the verification URL.

    After the inventory completes, a Save As dialog is shown so you can choose
    where to write the CSV. Pass -ExportCsvPath to skip the dialog, or
    -PromptForCsvPath $false to skip CSV export unless a path is supplied.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER TenantId
    Optional. The tenant (directory) ID or domain to connect to. If omitted,
    work/school accounts from any organization can be used to sign in.

.PARAMETER IncludeActive
    Include active role assignments (permanent, time-bound, and currently activated).
    Default: $true.

.PARAMETER IncludeEligible
    Include PIM eligible role assignments. Default: $true.

.PARAMETER IncludeUsers
    Include user principals in the output. Default: $true.

.PARAMETER IncludeServicePrincipals
    Include service principal principals in the output. Default: $true.

.PARAMETER IncludeGroups
    Include a row for each group that is assigned a privileged role. Default: $true.

.PARAMETER ExpandGroupMembers
    When a role is assigned to a group, also emit rows for the group's transitive
    user and service-principal members. Default: $true.

.PARAMETER ExportCsvPath
    Optional. Full path of the CSV file to write. If supplied, the Save As
    dialog is skipped and this path is used.

.PARAMETER PromptForCsvPath
    Show a Save As file picker for the CSV output when -ExportCsvPath is not
    supplied. Default: $true.

.PARAMETER CopyDeviceCodeToClipboard
    Copy the device login code to the clipboard so it can be pasted at the
    Microsoft device-login page. Default: $true.

.EXAMPLE
    .\Get-PrivilegedEntraUsers.ps1

.EXAMPLE
    .\Get-PrivilegedEntraUsers.ps1 -TenantId contoso.onmicrosoft.com -ExportCsvPath .\privileged.csv

.EXAMPLE
    # Skip the Save As dialog (pipeline output only):
    .\Get-PrivilegedEntraUsers.ps1 -PromptForCsvPath $false

.EXAMPLE
    # Groups that hold privileged roles, and whether each grant is eligible or permanent:
    .\Get-PrivilegedEntraUsers.ps1 | Where-Object { $_.PrincipalType -eq 'Group' } |
        Select-Object PrincipalDisplayName, RoleName, AssignmentState, DurationType, AssignmentPath

.EXAMPLE
    # Service principals with privileged roles:
    .\Get-PrivilegedEntraUsers.ps1 | Where-Object { $_.PrincipalType -eq 'ServicePrincipal' }

.NOTES
    Signs in using the OAuth 2.0 device code flow. The user code is copied to the
    clipboard by default. Open the displayed URL, paste the code, and complete
    sign-in; the script waits until authentication finishes.

    When inventory is complete, a Save As dialog lets you choose the CSV path
    unless -ExportCsvPath is already supplied.

    Requires the following delegated permissions (consented at first interactive sign-in):
        RoleManagement.Read.Directory
        Directory.Read.All
    Required modules (installed automatically if missing):
        Microsoft.Graph.Authentication
        Microsoft.Graph.Identity.Governance
        Microsoft.Graph.Users
        Microsoft.Graph.Groups
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string] $TenantId,
    [bool]   $IncludeActive             = $true,
    [bool]   $IncludeEligible           = $true,
    [bool]   $IncludeUsers              = $true,
    [bool]   $IncludeServicePrincipals  = $true,
    [bool]   $IncludeGroups             = $true,
    [bool]   $ExpandGroupMembers        = $true,
    [string] $ExportCsvPath,
    [bool]   $PromptForCsvPath          = $true,
    [bool]   $CopyDeviceCodeToClipboard = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Module bootstrap ---------------------------------------------------------

$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.Governance',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Groups'
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing missing module: $module" -ForegroundColor Yellow
        Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $module -ErrorAction Stop
}

#endregion

#region Connect ------------------------------------------------------------------

# Microsoft Graph PowerShell public client (same app Connect-MgGraph uses).
$script:GraphPowerShellClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
$script:GraphDelegatedScopes    = 'https://graph.microsoft.com/RoleManagement.Read.Directory https://graph.microsoft.com/Directory.Read.All offline_access openid profile'

function Get-NotePropertyValue {
    param(
        [AllowNull()] $Object,
        [Parameter(Mandatory)] [string[]] $Name
    )

    if ($null -eq $Object) { return $null }

    foreach ($n in $Name) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($n)) { return $Object[$n] }
        }
        else {
            $prop = $Object.PSObject.Properties[$n]
            if ($null -ne $prop) { return $prop.Value }
        }
    }

    return $null
}

function Copy-TextToClipboard {
    param([Parameter(Mandatory)] [string] $Text)

    # Prefer native Set-Clipboard (Windows PowerShell 5+ / PowerShell 7+).
    $setClipboard = Get-Command -Name Set-Clipboard -ErrorAction SilentlyContinue
    if ($setClipboard) {
        try {
            Set-Clipboard -Value $Text
            return $true
        }
        catch {
            # Fall through to other methods.
        }
    }

    # clip.exe is available on most Windows SKUs and works from the console.
    $clip = Get-Command -Name clip.exe -ErrorAction SilentlyContinue
    if ($clip) {
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName               = $clip.Source
            $psi.RedirectStandardInput  = $true
            $psi.UseShellExecute        = $false
            $psi.CreateNoWindow         = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $proc.StandardInput.Write($Text)
            $proc.StandardInput.Close()
            $proc.WaitForExit()
            if ($proc.ExitCode -eq 0) { return $true }
        }
        catch {
            # Fall through to Windows Forms.
        }
    }

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [System.Windows.Forms.Clipboard]::SetText($Text)
        return $true
    }
    catch {
        return $false
    }
}

function Get-OAuthErrorFromException {
    param($ErrorRecord)

    $raw = $null
    $details = Get-NotePropertyValue -Object $ErrorRecord -Name @('ErrorDetails')
    $detailMessage = Get-NotePropertyValue -Object $details -Name @('Message')
    if ($detailMessage) {
        $raw = [string]$detailMessage
    }
    else {
        $exception = Get-NotePropertyValue -Object $ErrorRecord -Name @('Exception')
        $response  = Get-NotePropertyValue -Object $exception -Name @('Response')
        if ($response) {
            try {
                $stream = $response.GetResponseStream()
                if ($stream) {
                    if ($stream.CanSeek) { [void]$stream.Seek(0, [System.IO.SeekOrigin]::Begin) }
                    $reader = New-Object System.IO.StreamReader($stream)
                    $raw = $reader.ReadToEnd()
                    $reader.Dispose()
                }
            }
            catch {
                $raw = $null
            }
        }
    }

    if ([string]::IsNullOrEmpty($raw)) { return $null }

    try {
        return ($raw | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Invoke-EntraDeviceCodeAuth {
    param(
        [string] $Tenant,
        [bool]   $CopyCodeToClipboard
    )

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch {
        # Best-effort; modern Windows already uses TLS 1.2+.
    }

    $deviceCodeUri = "https://login.microsoftonline.com/{0}/oauth2/v2.0/devicecode" -f $Tenant
    $tokenUri      = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $Tenant

    $device = Invoke-RestMethod -Method POST -Uri $deviceCodeUri -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id = $script:GraphPowerShellClientId
        scope     = $script:GraphDelegatedScopes
    }

    $userCode = [string](Get-NotePropertyValue -Object $device -Name @('user_code', 'userCode'))
    $verifyUrl = [string](Get-NotePropertyValue -Object $device -Name @('verification_uri', 'verificationUri'))
    if ([string]::IsNullOrEmpty($verifyUrl)) { $verifyUrl = 'https://microsoft.com/devicelogin' }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Device code sign-in required" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ("  URL:  {0}" -f $verifyUrl)
    Write-Host ("  Code: {0}" -f $userCode) -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan

    $message = Get-NotePropertyValue -Object $device -Name @('message')
    if ($message) {
        Write-Host ([string]$message)
    }
    else {
        Write-Host ("Open {0} and enter the code {1} to authenticate." -f $verifyUrl, $userCode)
    }

    if ($CopyCodeToClipboard) {
        if (Copy-TextToClipboard -Text $userCode) {
            Write-Host ("Device code '{0}' copied to the clipboard. Paste it in the browser, then sign in." -f $userCode) -ForegroundColor Green
        }
        else {
            Write-Host "Could not copy the device code to the clipboard. Copy the code shown above." -ForegroundColor Yellow
        }
    }

    Write-Host "Waiting for you to complete sign-in in the browser..." -ForegroundColor Cyan

    $interval = 5
    $intervalRaw = Get-NotePropertyValue -Object $device -Name @('interval')
    if ($null -ne $intervalRaw) {
        try { $interval = [int]$intervalRaw } catch { $interval = 5 }
    }
    if ($interval -lt 5) { $interval = 5 }

    $expiresIn = 900
    $expiresRaw = Get-NotePropertyValue -Object $device -Name @('expires_in', 'expiresIn')
    if ($null -ne $expiresRaw) {
        try { $expiresIn = [int]$expiresRaw } catch { $expiresIn = 900 }
    }
    $deadline = (Get-Date).AddSeconds($expiresIn)

    $deviceCode = Get-NotePropertyValue -Object $device -Name @('device_code', 'deviceCode')
    $accessToken = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval

        try {
            $token = Invoke-RestMethod -Method POST -Uri $tokenUri -ContentType 'application/x-www-form-urlencoded' -Body @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $script:GraphPowerShellClientId
                device_code = $deviceCode
            }
            $accessToken = [string](Get-NotePropertyValue -Object $token -Name @('access_token', 'accessToken'))
            if (-not [string]::IsNullOrEmpty($accessToken)) { break }
        }
        catch {
            $oauthErr = Get-OAuthErrorFromException -ErrorRecord $_
            $errCode  = $null
            if ($oauthErr) {
                $errProp = $oauthErr.PSObject.Properties['error']
                if ($errProp) { $errCode = [string]$errProp.Value }
            }

            if ($errCode -eq 'authorization_pending') { continue }
            if ($errCode -eq 'slow_down') { $interval += 5; continue }
            if ($errCode -eq 'expired_token' -or $errCode -eq 'code_expired') {
                throw "The device code expired before sign-in completed. Run the script again."
            }
            if ($errCode -eq 'authorization_declined' -or $errCode -eq 'access_denied') {
                throw "Sign-in was declined in the browser."
            }
            if ($errCode) {
                $desc = $null
                $descProp = $oauthErr.PSObject.Properties['error_description']
                if ($descProp) { $desc = [string]$descProp.Value }
                throw ("Device code sign-in failed ({0}): {1}" -f $errCode, $desc)
            }
            throw
        }
    }

    if ([string]::IsNullOrEmpty($accessToken)) {
        throw "Timed out waiting for device code sign-in. Run the script again."
    }

    $secureToken = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
    try {
        Connect-MgGraph -AccessToken $secureToken | Out-Null
    }
    catch {
        # Microsoft.Graph.Authentication 1.x accepted a raw string.
        Connect-MgGraph -AccessToken $accessToken | Out-Null
    }

    return $accessToken
}

function Get-ConnectedAccountName {
    param([string] $AccessToken)

    $context = Get-MgContext
    if ($context) {
        $accountProp = $context.PSObject.Properties['Account']
        if ($accountProp -and $accountProp.Value) { return [string]$accountProp.Value }
    }

    try {
        $me = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=userPrincipalName,displayName' -OutputType Hashtable
        if ($me.ContainsKey('userPrincipalName') -and $me['userPrincipalName']) {
            return [string]$me['userPrincipalName']
        }
        if ($me.ContainsKey('displayName') -and $me['displayName']) {
            return [string]$me['displayName']
        }
    }
    catch {
        # Token may not include User.Read; fall through to JWT.
    }

    if ([string]::IsNullOrEmpty($AccessToken)) { return '(signed in)' }

    try {
        $payload = $AccessToken.Split('.')[1]
        $payload = $payload.Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) {
            2 { $payload += '==' }
            3 { $payload += '=' }
        }
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        $claims = $json | ConvertFrom-Json
        foreach ($name in @('upn', 'preferred_username', 'unique_name', 'name')) {
            $prop = $claims.PSObject.Properties[$name]
            if ($prop -and $prop.Value) { return [string]$prop.Value }
        }
    }
    catch {
        # Ignore decode failures.
    }

    return '(signed in)'
}

$authTenant = 'organizations'
if ($TenantId) { $authTenant = $TenantId }

Write-Host "Connecting to Microsoft Graph with device code authentication..." -ForegroundColor Cyan
$script:GraphAccessToken = Invoke-EntraDeviceCodeAuth -Tenant $authTenant -CopyCodeToClipboard $CopyDeviceCodeToClipboard

$context = Get-MgContext
$accountName = Get-ConnectedAccountName -AccessToken $script:GraphAccessToken
$tenantName = $null
if ($context) {
    $tidProp = $context.PSObject.Properties['TenantId']
    if ($tidProp) { $tenantName = [string]$tidProp.Value }
}
if ([string]::IsNullOrEmpty($tenantName)) { $tenantName = $authTenant }

Write-Host ("Connected to tenant '{0}' as '{1}'." -f $tenantName, $accountName) -ForegroundColor Green

#endregion

#region Helpers ------------------------------------------------------------------

$script:PrincipalCache               = @{}
$script:GroupMemberCache             = @{}
$script:SeenKeys                     = @{}
$script:Results                      = New-Object System.Collections.Generic.List[object]
$script:GroupAssignmentsForExpansion = New-Object System.Collections.Generic.List[object]

function Get-GraphHashValue {
    <#
        Reads a property from a Hashtable or PSObject under Set-StrictMode.
        Tries each name in order so camelCase / PascalCase JSON both work.
    #>
    param(
        [AllowNull()] $Object,
        [Parameter(Mandatory)] [string[]] $Name
    )

    if ($null -eq $Object) { return $null }

    foreach ($n in $Name) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($n)) { return $Object[$n] }
            foreach ($key in @($Object.Keys)) {
                if ([string]$key -eq $n) { return $Object[$key] }
            }
        }
        else {
            $prop = $Object.PSObject.Properties[$n]
            if ($null -ne $prop) { return $prop.Value }
        }
    }

    return $null
}

function Get-GraphPaged {
    param(
        [Parameter(Mandatory)] [string] $Uri
    )

    $items = New-Object System.Collections.Generic.List[object]
    $next  = $Uri

    do {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Hashtable

        if ($page.ContainsKey('value') -and $page['value']) {
            foreach ($item in @($page['value'])) { $items.Add($item) }
        }

        if ($page.ContainsKey('@odata.nextLink') -and $page['@odata.nextLink']) {
            $next = $page['@odata.nextLink']
        }
        else {
            $next = $null
        }
    } while ($next)

    return $items
}

function New-PrincipalRecord {
    param(
        [Parameter(Mandatory)] [string] $PrincipalType,
        [Parameter(Mandatory)] [string] $PrincipalId,
        [string] $DisplayName,
        [string] $UserPrincipalName,
        [string] $AppId,
        $AccountEnabled,
        [string] $Subtype
    )

    if ([string]::IsNullOrEmpty($DisplayName)) { $DisplayName = $PrincipalId }

    return [pscustomobject]@{
        PrincipalType     = $PrincipalType
        PrincipalId       = $PrincipalId
        DisplayName       = $DisplayName
        UserPrincipalName = $UserPrincipalName
        AppId             = $AppId
        AccountEnabled    = $AccountEnabled
        Subtype           = $Subtype
    }
}

function Resolve-DirectoryPrincipal {
    <#
        Resolves a directory object id to a user, group, or service principal.
        Uses GET /directoryObjects/{id} to detect type, then fetches typed properties.
    #>
    param(
        [Parameter(Mandatory)] [string] $PrincipalId
    )

    if ($script:PrincipalCache.ContainsKey($PrincipalId)) {
        return $script:PrincipalCache[$PrincipalId]
    }

    $odataType = $null
    try {
        $dirObj = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/v1.0/directoryObjects/{0}" -f $PrincipalId) -OutputType Hashtable
        $odataType = [string](Get-GraphHashValue -Object $dirObj -Name @('@odata.type', 'odataType'))
    }
    catch {
        $unknown = New-PrincipalRecord -PrincipalType 'Unknown' -PrincipalId $PrincipalId -DisplayName '(unresolved principal)'
        $script:PrincipalCache[$PrincipalId] = $unknown
        return $unknown
    }

    $record = $null

    if ($odataType -match 'user$') {
        try {
            $user = Get-MgUser -UserId $PrincipalId -Property 'id,displayName,userPrincipalName,accountEnabled,userType' -ErrorAction Stop
            $record = New-PrincipalRecord -PrincipalType 'User' -PrincipalId $user.Id `
                -DisplayName $user.DisplayName -UserPrincipalName $user.UserPrincipalName `
                -AccountEnabled $user.AccountEnabled -Subtype $user.UserType
        }
        catch {
            $record = New-PrincipalRecord -PrincipalType 'User' -PrincipalId $PrincipalId `
                -DisplayName (Get-GraphHashValue -Object $dirObj -Name @('displayName')) `
                -UserPrincipalName (Get-GraphHashValue -Object $dirObj -Name @('userPrincipalName'))
        }
    }
    elseif ($odataType -match 'group$') {
        try {
            $group = Get-MgGroup -GroupId $PrincipalId -Property 'id,displayName,mail,securityEnabled,isAssignableToRole,groupTypes' -ErrorAction Stop
            $isAssignable = Get-GraphHashValue -Object $group -Name @('IsAssignableToRole', 'isAssignableToRole')
            $subtype = 'Group'
            if ($isAssignable -eq $true) { $subtype = 'RoleAssignableGroup' }
            $record = New-PrincipalRecord -PrincipalType 'Group' -PrincipalId $group.Id `
                -DisplayName $group.DisplayName -UserPrincipalName $group.Mail `
                -Subtype $subtype
        }
        catch {
            $record = New-PrincipalRecord -PrincipalType 'Group' -PrincipalId $PrincipalId `
                -DisplayName (Get-GraphHashValue -Object $dirObj -Name @('displayName'))
        }
    }
    elseif ($odataType -match 'servicePrincipal$') {
        try {
            $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals/{0}?`$select=id,displayName,appId,accountEnabled,servicePrincipalType,appOwnerOrganizationId" -f $PrincipalId
            $sp    = Invoke-MgGraphRequest -Method GET -Uri $spUri -OutputType Hashtable
            $spId  = [string](Get-GraphHashValue -Object $sp -Name @('id'))
            if ([string]::IsNullOrEmpty($spId)) { $spId = $PrincipalId }
            $record = New-PrincipalRecord -PrincipalType 'ServicePrincipal' -PrincipalId $spId `
                -DisplayName (Get-GraphHashValue -Object $sp -Name @('displayName')) `
                -AppId (Get-GraphHashValue -Object $sp -Name @('appId')) `
                -AccountEnabled (Get-GraphHashValue -Object $sp -Name @('accountEnabled')) `
                -Subtype (Get-GraphHashValue -Object $sp -Name @('servicePrincipalType'))
        }
        catch {
            $record = New-PrincipalRecord -PrincipalType 'ServicePrincipal' -PrincipalId $PrincipalId `
                -DisplayName (Get-GraphHashValue -Object $dirObj -Name @('displayName'))
        }
    }
    else {
        $record = New-PrincipalRecord -PrincipalType 'Unknown' -PrincipalId $PrincipalId `
            -DisplayName (Get-GraphHashValue -Object $dirObj -Name @('displayName')) `
            -Subtype $odataType
    }

    $script:PrincipalCache[$PrincipalId] = $record
    return $record
}

function Get-GroupTransitivePrincipals {
    <#
        Returns user and service-principal members of a group (transitive).
        Nested groups are walked by the Graph transitiveMembers API; nested
        group objects themselves are not emitted (directory roles do not
        flow through nested groups).
    #>
    param(
        [Parameter(Mandatory)] [string] $GroupId
    )

    if ($script:GroupMemberCache.ContainsKey($GroupId)) {
        return $script:GroupMemberCache[$GroupId]
    }

    $records = New-Object System.Collections.Generic.List[object]

    $userUri = "https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers/microsoft.graph.user?`$select=id,displayName,userPrincipalName,accountEnabled,userType" -f $GroupId
    try {
        foreach ($u in (Get-GraphPaged -Uri $userUri)) {
            $id = [string](Get-GraphHashValue -Object $u -Name @('id'))
            if ([string]::IsNullOrEmpty($id)) { continue }
            $rec = New-PrincipalRecord -PrincipalType 'User' -PrincipalId $id `
                -DisplayName (Get-GraphHashValue -Object $u -Name @('displayName')) `
                -UserPrincipalName (Get-GraphHashValue -Object $u -Name @('userPrincipalName')) `
                -AccountEnabled (Get-GraphHashValue -Object $u -Name @('accountEnabled')) `
                -Subtype (Get-GraphHashValue -Object $u -Name @('userType'))
            $records.Add($rec)
            if (-not $script:PrincipalCache.ContainsKey($id)) {
                $script:PrincipalCache[$id] = $rec
            }
        }
    }
    catch {
        Write-Warning ("Could not expand user members of group {0}: {1}" -f $GroupId, $_.Exception.Message)
    }

    $spUri = "https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers/microsoft.graph.servicePrincipal?`$select=id,displayName,appId,accountEnabled,servicePrincipalType" -f $GroupId
    try {
        foreach ($sp in (Get-GraphPaged -Uri $spUri)) {
            $id = [string](Get-GraphHashValue -Object $sp -Name @('id'))
            if ([string]::IsNullOrEmpty($id)) { continue }
            $rec = New-PrincipalRecord -PrincipalType 'ServicePrincipal' -PrincipalId $id `
                -DisplayName (Get-GraphHashValue -Object $sp -Name @('displayName')) `
                -AppId (Get-GraphHashValue -Object $sp -Name @('appId')) `
                -AccountEnabled (Get-GraphHashValue -Object $sp -Name @('accountEnabled')) `
                -Subtype (Get-GraphHashValue -Object $sp -Name @('servicePrincipalType'))
            $records.Add($rec)
            if (-not $script:PrincipalCache.ContainsKey($id)) {
                $script:PrincipalCache[$id] = $rec
            }
        }
    }
    catch {
        Write-Warning ("Could not expand service-principal members of group {0}: {1}" -f $GroupId, $_.Exception.Message)
    }

    $script:GroupMemberCache[$GroupId] = $records
    return $records
}

function Convert-ToDateTimeString {
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text
}

function Get-DurationType {
    param($EndDateTime)
    $end = Convert-ToDateTimeString -Value $EndDateTime
    if ($null -eq $end) { return 'Permanent' }
    return 'Time-bound'
}

function Get-AssignmentStateFromInstance {
    <#
        Maps Graph assignmentType + endDateTime onto the Entra PIM vocabulary:
            Permanent  - standing active assignment, no expiry
            TimeBound  - standing active assignment that expires
            Activated  - currently activated PIM eligible assignment
    #>
    param($AssignmentType, $EndDateTime)

    $typeText = [string]$AssignmentType
    if ($typeText -match 'activated') {
        return @{ AssignmentState = 'Activated'; DurationType = 'Time-bound'; IsPimActivated = $true }
    }

    $duration = Get-DurationType -EndDateTime $EndDateTime
    if ($duration -eq 'Permanent') {
        return @{ AssignmentState = 'Permanent'; DurationType = 'Permanent'; IsPimActivated = $false }
    }

    return @{ AssignmentState = 'TimeBound'; DurationType = 'Time-bound'; IsPimActivated = $false }
}

function Get-AssignmentPathFromMemberType {
    param($MemberType)

    $text = [string]$MemberType
    if ($text -match 'group')     { return 'Group' }
    if ($text -match 'composite') { return 'Composite' }
    return 'Direct'
}

function Test-ShouldEmitPrincipalType {
    param([Parameter(Mandatory)] [string] $PrincipalType)

    switch ($PrincipalType) {
        'User'              { return [bool]$IncludeUsers }
        'ServicePrincipal'  { return [bool]$IncludeServicePrincipals }
        'Group'             { return [bool]$IncludeGroups }
        default             { return $true }
    }
}

function Get-AssignmentRowKey {
    param(
        [string] $PrincipalId,
        [string] $RoleId,
        [string] $AssignmentState,
        [string] $AssignmentPath,
        [string] $DirectoryScopeId
    )
    return '{0}|{1}|{2}|{3}|{4}' -f $PrincipalId, $RoleId, $AssignmentState, $AssignmentPath, $DirectoryScopeId
}

function Add-ResultRow {
    param(
        [Parameter(Mandatory)] $TargetPrincipal,
        [Parameter(Mandatory)] $Role,
        [Parameter(Mandatory)] [string] $AssignmentState,
        [Parameter(Mandatory)] [string] $DurationType,
        [Parameter(Mandatory)] [string] $AssignmentPath,
        [bool]   $IsPimActivated = $false,
        [string] $DirectoryScopeId,
        $StartDateTime,
        $EndDateTime,
        [string] $GraphMemberType,
        [string] $AssignedVia = 'Direct',
        [string] $AssignedViaGroup,
        [string] $AssignedViaGroupId
    )

    if (-not (Test-ShouldEmitPrincipalType -PrincipalType $TargetPrincipal.PrincipalType)) {
        return
    }

    $key = Get-AssignmentRowKey -PrincipalId $TargetPrincipal.PrincipalId -RoleId $Role.Id `
        -AssignmentState $AssignmentState -AssignmentPath $AssignmentPath -DirectoryScopeId $DirectoryScopeId

    if ($script:SeenKeys.ContainsKey($key)) {
        $existing = $script:Results[$script:SeenKeys[$key]]
        # Prefer the row that names the source group when Graph also returned a memberType=Group instance.
        $existingViaGroup = [string](Get-GraphHashValue -Object $existing -Name @('AssignedViaGroup'))
        if ([string]::IsNullOrEmpty($existingViaGroup) -and -not [string]::IsNullOrEmpty($AssignedViaGroup)) {
            $existing.AssignedVia        = $AssignedVia
            $existing.AssignedViaGroup   = $AssignedViaGroup
            $existing.AssignedViaGroupId = $AssignedViaGroupId
        }
        return
    }

    $row = [pscustomobject]@{
        PrincipalType        = $TargetPrincipal.PrincipalType
        PrincipalDisplayName = $TargetPrincipal.DisplayName
        PrincipalId          = $TargetPrincipal.PrincipalId
        UserPrincipalName    = $TargetPrincipal.UserPrincipalName
        AppId                = $TargetPrincipal.AppId
        AccountEnabled       = $TargetPrincipal.AccountEnabled
        PrincipalSubtype     = $TargetPrincipal.Subtype
        RoleName             = $Role.DisplayName
        RoleDefinitionId     = $Role.Id
        AssignmentState      = $AssignmentState   # Permanent | Eligible | Activated | TimeBound
        DurationType         = $DurationType      # Permanent | Time-bound
        AssignmentPath       = $AssignmentPath    # Direct | Group | Composite
        AssignedVia          = $AssignedVia       # Direct | Group: <name>
        AssignedViaGroup     = $AssignedViaGroup
        AssignedViaGroupId   = $AssignedViaGroupId
        IsPimActivated       = [bool]$IsPimActivated
        DirectoryScopeId     = $DirectoryScopeId
        StartDateTime        = (Convert-ToDateTimeString -Value $StartDateTime)
        EndDateTime          = (Convert-ToDateTimeString -Value $EndDateTime)
        GraphMemberType      = $GraphMemberType
    }
    $row.PSObject.TypeNames.Insert(0, 'PrivilegedEntraAssignment')
    $script:SeenKeys[$key] = $script:Results.Count
    $script:Results.Add($row)
}

function Add-PrincipalAssignment {
    <#
        Records the assignment against the principal Graph named (user, SP, or group).
        Group member expansion happens in a second pass so every group-held role is
        listed on the group itself and on its members.
    #>
    param(
        [Parameter(Mandatory)] $Role,
        [Parameter(Mandatory)] [string] $PrincipalId,
        [Parameter(Mandatory)] [string] $AssignmentState,
        [Parameter(Mandatory)] [string] $DurationType,
        [Parameter(Mandatory)] [string] $AssignmentPath,
        [bool]   $IsPimActivated = $false,
        [string] $DirectoryScopeId,
        $StartDateTime,
        $EndDateTime,
        [string] $GraphMemberType
    )

    if ([string]::IsNullOrEmpty($PrincipalId)) { return }

    $principal = Resolve-DirectoryPrincipal -PrincipalId $PrincipalId

    # A group is always a direct assignee of the directory role (members inherit it).
    if ($principal.PrincipalType -eq 'Group') {
        Add-ResultRow -TargetPrincipal $principal -Role $Role `
            -AssignmentState $AssignmentState -DurationType $DurationType -AssignmentPath 'Direct' `
            -IsPimActivated $IsPimActivated -DirectoryScopeId $DirectoryScopeId `
            -StartDateTime $StartDateTime -EndDateTime $EndDateTime `
            -GraphMemberType $GraphMemberType -AssignedVia 'Direct'

        $script:GroupAssignmentsForExpansion.Add([pscustomobject]@{
            PrincipalId          = $principal.PrincipalId
            PrincipalDisplayName = $principal.DisplayName
            RoleDefinitionId     = $Role.Id
            RoleName             = $Role.DisplayName
            AssignmentState      = $AssignmentState
            DurationType         = $DurationType
            IsPimActivated       = [bool]$IsPimActivated
            DirectoryScopeId     = $DirectoryScopeId
            StartDateTime        = $StartDateTime
            EndDateTime          = $EndDateTime
        })
        return
    }

    $path = $AssignmentPath
    $via  = 'Direct'
    if ($path -eq 'Group' -or $path -eq 'Composite') {
        $via = 'Group'
    }
    else {
        $path = 'Direct'
    }

    Add-ResultRow -TargetPrincipal $principal -Role $Role `
        -AssignmentState $AssignmentState -DurationType $DurationType -AssignmentPath $path `
        -IsPimActivated $IsPimActivated -DirectoryScopeId $DirectoryScopeId `
        -StartDateTime $StartDateTime -EndDateTime $EndDateTime `
        -GraphMemberType $GraphMemberType -AssignedVia $via
}

function Add-ExpandedGroupMemberRows {
    param(
        [Parameter(Mandatory)] $GroupRow
    )

    $members = Get-GroupTransitivePrincipals -GroupId $GroupRow.PrincipalId
    $viaLabel = "Group: {0}" -f $GroupRow.PrincipalDisplayName
    $role = [pscustomobject]@{
        Id          = $GroupRow.RoleDefinitionId
        DisplayName = $GroupRow.RoleName
    }

    foreach ($member in @($members)) {
        Add-ResultRow -TargetPrincipal $member -Role $role `
            -AssignmentState $GroupRow.AssignmentState -DurationType $GroupRow.DurationType `
            -AssignmentPath 'Group' -IsPimActivated ([bool]$GroupRow.IsPimActivated) `
            -DirectoryScopeId $GroupRow.DirectoryScopeId `
            -StartDateTime $GroupRow.StartDateTime -EndDateTime $GroupRow.EndDateTime `
            -GraphMemberType 'Group' -AssignedVia $viaLabel `
            -AssignedViaGroup $GroupRow.PrincipalDisplayName -AssignedViaGroupId $GroupRow.PrincipalId
    }
}

#endregion

#region 1. Get privileged role definitions --------------------------------------

Write-Host "Retrieving privileged role definitions (isPrivileged = true)..." -ForegroundColor Cyan

# NOTE: 'isPrivileged' only exists on the Microsoft Graph BETA endpoint - it is not
# present on the v1.0 unifiedRoleDefinition type (the v1.0 cmdlet returns a 400
# 'Could not find a property named isPrivileged'). We therefore query the beta
# endpoint directly through the already-authenticated SDK connection via
# Invoke-MgGraphRequest, and filter client-side because beta does not reliably
# support $filter on isPrivileged.

$roleDefUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?`$select=id,displayName,isPrivileged,isBuiltIn"

$allRoleDefs = Get-GraphPaged -Uri $roleDefUri

# Client-side filter to Microsoft-flagged privileged roles, and normalize the
# shape so downstream code can keep using .Id / .DisplayName.
$privilegedRoles = $allRoleDefs |
    Where-Object { (Get-GraphHashValue -Object $_ -Name @('isPrivileged')) -eq $true } |
    ForEach-Object {
        [pscustomobject]@{
            Id           = [string](Get-GraphHashValue -Object $_ -Name @('id'))
            DisplayName  = [string](Get-GraphHashValue -Object $_ -Name @('displayName'))
            IsPrivileged = $true
            IsBuiltIn    = (Get-GraphHashValue -Object $_ -Name @('isBuiltIn'))
        }
    }

if (-not $privilegedRoles) {
    Write-Warning "No privileged role definitions returned. Nothing to do."
    Disconnect-MgGraph | Out-Null
    return
}

$roleById = @{}
foreach ($role in @($privilegedRoles)) { $roleById[$role.Id] = $role }

Write-Host ("Found {0} privileged role definition(s)." -f @($privilegedRoles).Count) -ForegroundColor Green

#endregion

#region 2. Collect assignments ---------------------------------------------------

$script:Results = New-Object System.Collections.Generic.List[object]
$script:GroupAssignmentsForExpansion = New-Object System.Collections.Generic.List[object]

function Get-CmdletProperty {
    param($Object, [string[]] $Name)
    return Get-GraphHashValue -Object $Object -Name $Name
}

# --- Active / permanent / activated assignments ---
if ($IncludeActive) {
    Write-Host "Retrieving ACTIVE role assignments (permanent, time-bound, and PIM-activated)..." -ForegroundColor Cyan

    $usedScheduleInstances = $false
    $activeItems = @()

    try {
        $activeItems = @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction Stop)
        $usedScheduleInstances = $true
        Write-Host ("Retrieved {0} assignment schedule instance(s)." -f $activeItems.Count) -ForegroundColor Green
    }
    catch {
        Write-Warning ("Could not retrieve assignment schedule instances ({0}). Falling back to directory role assignments (cannot distinguish PIM-activated from permanent)." -f $_.Exception.Message)
        $activeItems = @(Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop)
        Write-Host ("Retrieved {0} directory role assignment(s)." -f $activeItems.Count) -ForegroundColor Green
    }

    foreach ($item in $activeItems) {
        $roleDefId = [string](Get-CmdletProperty -Object $item -Name @('RoleDefinitionId', 'roleDefinitionId'))
        if (-not $roleById.ContainsKey($roleDefId)) { continue }

        $role          = $roleById[$roleDefId]
        $principalId   = [string](Get-CmdletProperty -Object $item -Name @('PrincipalId', 'principalId'))
        $scopeId       = [string](Get-CmdletProperty -Object $item -Name @('DirectoryScopeId', 'directoryScopeId'))
        $memberType    = Get-CmdletProperty -Object $item -Name @('MemberType', 'memberType')
        $assignType    = Get-CmdletProperty -Object $item -Name @('AssignmentType', 'assignmentType')
        $start         = Get-CmdletProperty -Object $item -Name @('StartDateTime', 'startDateTime')
        $end           = Get-CmdletProperty -Object $item -Name @('EndDateTime', 'endDateTime')

        if ($usedScheduleInstances) {
            $mapped = Get-AssignmentStateFromInstance -AssignmentType $assignType -EndDateTime $end
            $path   = Get-AssignmentPathFromMemberType -MemberType $memberType
        }
        else {
            $mapped = @{ AssignmentState = 'Permanent'; DurationType = 'Permanent'; IsPimActivated = $false }
            $path   = 'Direct'
        }

        Add-PrincipalAssignment -Role $role -PrincipalId $principalId `
            -AssignmentState $mapped.AssignmentState -DurationType $mapped.DurationType `
            -AssignmentPath $path -IsPimActivated $mapped.IsPimActivated `
            -DirectoryScopeId $scopeId -StartDateTime $start -EndDateTime $end `
            -GraphMemberType ([string]$memberType)
    }
}

# --- PIM eligible assignments ---
if ($IncludeEligible) {
    Write-Host "Retrieving PIM ELIGIBLE role assignments..." -ForegroundColor Cyan
    try {
        $eligibleItems = @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ErrorAction Stop)
        Write-Host ("Retrieved {0} eligibility schedule instance(s)." -f $eligibleItems.Count) -ForegroundColor Green

        foreach ($item in $eligibleItems) {
            $roleDefId = [string](Get-CmdletProperty -Object $item -Name @('RoleDefinitionId', 'roleDefinitionId'))
            if (-not $roleById.ContainsKey($roleDefId)) { continue }

            $role        = $roleById[$roleDefId]
            $principalId = [string](Get-CmdletProperty -Object $item -Name @('PrincipalId', 'principalId'))
            $scopeId     = [string](Get-CmdletProperty -Object $item -Name @('DirectoryScopeId', 'directoryScopeId'))
            $memberType  = Get-CmdletProperty -Object $item -Name @('MemberType', 'memberType')
            $start       = Get-CmdletProperty -Object $item -Name @('StartDateTime', 'startDateTime')
            $end         = Get-CmdletProperty -Object $item -Name @('EndDateTime', 'endDateTime')
            $path        = Get-AssignmentPathFromMemberType -MemberType $memberType
            $duration    = Get-DurationType -EndDateTime $end

            Add-PrincipalAssignment -Role $role -PrincipalId $principalId `
                -AssignmentState 'Eligible' -DurationType $duration `
                -AssignmentPath $path -IsPimActivated $false `
                -DirectoryScopeId $scopeId -StartDateTime $start -EndDateTime $end `
                -GraphMemberType ([string]$memberType)
        }
    }
    catch {
        Write-Warning ("Could not retrieve eligible (PIM) assignments. This requires Entra ID P2 + PIM. Details: {0}" -f $_.Exception.Message)
    }
}

# --- Expand groups to user and service-principal members ---
if ($ExpandGroupMembers -and $script:GroupAssignmentsForExpansion.Count -gt 0) {
    Write-Host ("Expanding {0} group assignment(s) to member users and service principals..." -f $script:GroupAssignmentsForExpansion.Count) -ForegroundColor Cyan
    foreach ($groupRow in $script:GroupAssignmentsForExpansion) {
        Add-ExpandedGroupMemberRows -GroupRow $groupRow
    }
}

#endregion

#region 3. Output ----------------------------------------------------------------

function Get-CsvPathFromSaveDialog {
    param(
        [string] $DefaultFileName,
        [string] $InitialDirectory
    )

    $dialogScript = {
        param($DefaultFileName, $InitialDirectory)

        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        [System.Windows.Forms.Application]::EnableVisualStyles()

        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Title            = 'Save privileged Entra role assignments'
        $dialog.Filter           = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
        $dialog.FilterIndex      = 1
        $dialog.DefaultExt       = 'csv'
        $dialog.AddExtension     = $true
        $dialog.OverwritePrompt  = $true
        $dialog.RestoreDirectory = $true
        $dialog.FileName         = $DefaultFileName
        if (-not [string]::IsNullOrEmpty($InitialDirectory) -and (Test-Path -LiteralPath $InitialDirectory)) {
            $dialog.InitialDirectory = $InitialDirectory
        }

        $owner = New-Object System.Windows.Forms.Form
        $owner.TopMost       = $true
        $owner.ShowInTaskbar = $false
        $owner.StartPosition = 'CenterScreen'
        $owner.Size          = New-Object System.Drawing.Size(1, 1)
        $owner.Opacity       = 0
        [void]$owner.Show()
        $owner.Activate()

        try {
            $result = $dialog.ShowDialog($owner)
            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                return $dialog.FileName
            }
            return $null
        }
        finally {
            $owner.Close()
            $owner.Dispose()
            $dialog.Dispose()
        }
    }

    $apartment = [System.Threading.Thread]::CurrentThread.GetApartmentState()
    if ($apartment -eq [System.Threading.ApartmentState]::STA) {
        return & $dialogScript $DefaultFileName $InitialDirectory
    }

    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = 'STA'
    $runspace.ThreadOptions  = 'ReuseThread'
    $runspace.Open()
    try {
        $ps = [powershell]::Create()
        $ps.Runspace = $runspace
        [void]$ps.AddScript($dialogScript).AddArgument($DefaultFileName).AddArgument($InitialDirectory)
        $invokeResult = $ps.Invoke()
        if ($ps.Streams.Error.Count -gt 0) {
            throw ($ps.Streams.Error[0].Exception)
        }
        if ($invokeResult -and @($invokeResult).Count -gt 0) {
            return [string]@($invokeResult)[0]
        }
        return $null
    }
    finally {
        $runspace.Close()
        $runspace.Dispose()
    }
}

$final = @($script:Results | Sort-Object PrincipalType, PrincipalDisplayName, RoleName, AssignmentState, AssignmentPath, AssignedVia)

$userCount  = @($final | Where-Object { $_.PrincipalType -eq 'User' }).Count
$spCount    = @($final | Where-Object { $_.PrincipalType -eq 'ServicePrincipal' }).Count
$groupCount = @($final | Where-Object { $_.PrincipalType -eq 'Group' }).Count
$eligCount  = @($final | Where-Object { $_.AssignmentState -eq 'Eligible' }).Count
$permCount  = @($final | Where-Object { $_.AssignmentState -eq 'Permanent' }).Count
$actCount   = @($final | Where-Object { $_.AssignmentState -eq 'Activated' }).Count
$tbCount    = @($final | Where-Object { $_.AssignmentState -eq 'TimeBound' }).Count
$directCount= @($final | Where-Object { $_.AssignmentPath -eq 'Direct' }).Count
$viaGrpCount= @($final | Where-Object { $_.AssignmentPath -eq 'Group' }).Count

Write-Host ""
Write-Host ("Total privileged assignment records: {0}" -f $final.Count) -ForegroundColor Green
Write-Host ("  Principals : {0} user(s), {1} service principal(s), {2} group(s)" -f $userCount, $spCount, $groupCount)
Write-Host ("  State      : {0} permanent, {1} eligible, {2} PIM-activated, {3} time-bound active" -f $permCount, $eligCount, $actCount, $tbCount)
Write-Host ("  Path       : {0} direct, {1} via group" -f $directCount, $viaGrpCount)

$groupRows = @($final | Where-Object { $_.PrincipalType -eq 'Group' })
if ($groupRows.Count -gt 0) {
    Write-Host ""
    Write-Host "Groups with privileged role assignments:" -ForegroundColor Cyan
    $groupRows |
        Select-Object PrincipalDisplayName, RoleName, AssignmentState, DurationType, AssignmentPath, DirectoryScopeId |
        Format-Table -AutoSize | Out-String | Write-Host
}

if ([string]::IsNullOrWhiteSpace($ExportCsvPath) -and $PromptForCsvPath) {
    $defaultName = 'PrivilegedEntraAssignments-{0:yyyyMMdd-HHmmss}.csv' -f (Get-Date)
    $initialDir  = [Environment]::GetFolderPath('MyDocuments')
    if ([string]::IsNullOrEmpty($initialDir)) {
        $initialDir = (Get-Location).Path
    }

    Write-Host ""
    Write-Host "Choose where to save the CSV export..." -ForegroundColor Cyan
    try {
        $ExportCsvPath = Get-CsvPathFromSaveDialog -DefaultFileName $defaultName -InitialDirectory $initialDir
    }
    catch {
        Write-Warning ("Could not open the Save As dialog ({0}). Pass -ExportCsvPath to save without a picker." -f $_.Exception.Message)
        $ExportCsvPath = $null
    }

    if ([string]::IsNullOrWhiteSpace($ExportCsvPath)) {
        Write-Warning "CSV export cancelled. Results will only be returned to the pipeline."
    }
}

if (-not [string]::IsNullOrWhiteSpace($ExportCsvPath)) {
    $exportDir = Split-Path -Parent $ExportCsvPath
    if (-not [string]::IsNullOrEmpty($exportDir) -and -not (Test-Path -LiteralPath $exportDir)) {
        New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
    }
    $final | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host ("Results exported to: {0}" -f $ExportCsvPath) -ForegroundColor Green
}

Disconnect-MgGraph | Out-Null

# Default display columns when the caller does not select specific properties.
try {
    Update-TypeData -TypeName 'PrivilegedEntraAssignment' -DefaultDisplayPropertySet @(
        'PrincipalType',
        'PrincipalDisplayName',
        'UserPrincipalName',
        'AppId',
        'RoleName',
        'AssignmentState',
        'DurationType',
        'AssignmentPath',
        'AssignedVia'
    ) -Force -ErrorAction SilentlyContinue
}
catch {
    # Non-fatal: objects still contain every property.
}

# Emit objects to the pipeline so the caller can further process/format them.
$final

#endregion

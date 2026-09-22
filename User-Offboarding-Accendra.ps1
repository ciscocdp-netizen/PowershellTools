#Requires -Version 5.1
#Requires -Modules ActiveDirectory, ExchangeOnlineManagement

<#
.SYNOPSIS
    Graph-Based User Offboarding Script - ACCENDRA / APRIA / BYRAM SCOPE (Batch & Interactive)

.DESCRIPTION
    Automates user offboarding/termination for the Accendra (corporateacc.com),
    Apria (corporate.apria.com) and Byram (corp.byramhealthcare.com) Active Directory
    domains, PLUS all Microsoft Entra ID and Exchange Online actions.

    ----------------------------------------------------------------------------------
    SCRIPT SCOPE (SPLIT 2 of 2)
    ----------------------------------------------------------------------------------
    This is one half of a two-script split of the original all-domain offboarding tool:

      * THIS SCRIPT (User-Offboarding-Accendra.ps1):
          - Main domain      : corporateacc.com   (Accendra)  <-- NEW primary/anchor
          - Cross-domain     : corporate.apria.com (Apria)
                               corp.byramhealthcare.com (Byram)
          - Cloud            : ALL Entra ID + Exchange Online actions
          - Accendra is now the anchor domain. The Accendra AD user object carries
            cross-domain SID attributes (accAapriaSID / accByramSID) used to locate
            the Apria and Byram accounts.

      * SISTER SCRIPT (User-Offboarding-OMI-Halyard.ps1):
          - Handles OMI (omi.com, its main domain) and Halyard (hcus.corp),
            plus its own copy of all Entra ID + Exchange Online actions.

    NOTE: Both scripts perform the Entra/Exchange (cloud) actions. If you run BOTH
    scripts for the same user, the cloud actions will be attempted twice (they are
    idempotent, so this is safe, but you generally only need the cloud actions once).

.AUTHOR
    Anthony Blake (Enhanced version) - split into Accendra/Apria/Byram scope

.VERSION
    2.9.0-ACC - Accendra (main) + Apria + Byram AD scope with full Entra/Exchange actions
                Exchange Online uses app + certificate thumbprint authentication

.NOTES
    - Requires ActiveDirectory module
    - Requires ExchangeOnlineManagement module
    - Requires Graph API App Registration with appropriate permissions
    - Exchange Online: Connect-ExchangeOnline -AppId -CertificateThumbprint -Organization.
      The app certificate must be installed in the local certificate store
      (typically CurrentUser\My) and the app needs Exchange admin permissions.
    - Run with appropriate administrative privileges

.EXAMPLE
    .\User-Offboarding-Accendra.ps1
    # Launches interactive menu to select processing mode
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Interactive', 'Batch', 'Menu')]
    [string]$Mode = 'Menu',
    
    [Parameter(Mandatory = $false)]
    [string]$CsvInputPath,
    
    [Parameter(Mandatory = $false)]
    [string]$CsvOutputPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipExchangeConnection
)

# ============================================================================
# CONFIGURATION
# ============================================================================
$script:Config = @{
  TenantId          = "0b49482a-98e0-4876-8cccccccccc"
  ClientId          = "cd77e6e3-e40a-4085-ac99cccccccccccccccc"
  ClientSecret      = "0NK8Q~12345696654123541236565414444"
  # IAM Hold OU for the MAIN domain. In this script the main domain is Accendra,
  # so disabled users on corporateacc.com are moved into the Accendra IAM Hold OU.
  IAMHoldOU         = "OU=IAM Hold,DC=corporateacc,DC=com"

  # ------------------------------------------------------------------------
  # MICROSOFT IDENTITY MANAGER (MIM) - Lithnet RMA
  # After offboarding, MIM can re-sync from Workday and REVERSE our actions
  # (e.g. re-enable the account). Setting the "_Ignore_Workday_Active_Status"
  # flags on the MIM Person object tells MIM to stop enforcing Workday's
  # active status for this user, so our offboarding changes stick.
  # NOTE: MIM is a single central service (keyed by AccountName), so the same
  # service URI is used regardless of which domain the account lives in.
  # ------------------------------------------------------------------------
  MIMEnabled        = $true
  MIMServiceUri     = "http://acormim001vpm22.corporateacc.com:5725/resourcemanagementservice%22"
  
  # ------------------------------------------------------------------------
  # DOMAIN SCOPE FOR THIS SCRIPT: Accendra (main) + Apria + Byram.
  # Accendra (corporateacc.com) is now the primary/anchor domain.
  # OMI and Halyard are intentionally NOT handled here - they are processed
  # by the sister script (User-Offboarding-OMI-Halyard.ps1).
  # ------------------------------------------------------------------------
  Domains           = @{
  Main     = "corporateacc.com"          # Accendra - primary/anchor domain
  Apria    = "corporate.apria.com"       # Apria - cross-domain (via accAapriaSID)
  Byram    = "corp.byramhealthcare.com"  # Byram - cross-domain (via accByramSID)
  }

  # SID attributes on the Accendra user that point at the linked Apria/Byram accounts.
  # Empty values mean the user has no account in that domain; that is not an error.
  CrossDomainSidAttributes = @{
      Apria = 'accAapriaSID'
      Byram = 'accByramSID'
  }
  
  # Cross-Domain IAM Hold OUs (Apria + Byram are in scope for this script)
  CrossDomainHoldOUs = @{
      Apria    = "OU=IAM Hold,DC=corporate,DC=apria,DC=com"
      Byram    = "OU=IAM Hold,DC=corp,DC=byramhealthcare,DC=com"
  }
    
    # ------------------------------------------------------------------------
    # Exchange Online — app + certificate (no stored password)
    # The certificate identified by thumbprint must be in the cert store.
    # ------------------------------------------------------------------------
    ExchangeOrganization          = "accendra.onmicrosoft.com"
    ExchangeAppId                 = "056fd019-2f2e-409sjndyey436433w"
    ExchangeCertificateThumbprint = "a70caee3205f6e452f435sjnhdye6645efaqwe"
    
    # Validation Settings
    ValidationDelaySeconds     = 10
    PasswordAgeThresholdMinutes = 5
    RetryAttempts              = 3
    RetryDelaySeconds          = 2
    
    # Logging
    EnableTranscript  = $true
    LogDirectory      = "E:\Scripts\Logs\Offboarding"
}

# ============================================================================
# SCRIPT-LEVEL VARIABLES
# ============================================================================
$script:ValidationResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:OperationResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:AllUserResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:PDCEmulators = @{}
$script:GraphToken = $null
$script:GraphHeaders = @{}
$script:ExchangeConnected = $false
$script:ScriptStartTime = Get-Date
$script:ErrorCount = 0
$script:WarningCount = 0
$script:CrossDomainSidAttributesAvailable = $null

# ============================================================================
# ENUMERATIONS FOR STATUS TRACKING
# ============================================================================
enum ValidationStatus {
    Success
    Failed
    Warning
    Skipped
    NotApplicable
}

enum OperationStatus {
    Success
    Error
    Warning
    Info
    Skipped
}

# ============================================================================
# LOGGING & OUTPUT FUNCTIONS
# ============================================================================
function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Debug', 'Header', 'SubHeader')]
        [string]$Level = 'Info',
        
        [Parameter(Mandatory = $false)]
        [int]$Indent = 0
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $indentString = "  " * $Indent
    
    $colorMap = @{
        'Info'      = 'White'
        'Success'   = 'Green'
        'Warning'   = 'Yellow'
        'Error'     = 'Red'
        'Debug'     = 'Gray'
        'Header'    = 'Cyan'
        'SubHeader' = 'DarkCyan'
    }
    
    $color = $colorMap[$Level]
    
    switch ($Level) {
        'Header' {
            Write-Host ""
            Write-Host ("=" * 70) -ForegroundColor $color
            Write-Host "$indentString$Message" -ForegroundColor $color
            Write-Host ("=" * 70) -ForegroundColor $color
        }
        'SubHeader' {
            Write-Host ""
            Write-Host "$indentString$Message" -ForegroundColor $color
            Write-Host ("$indentString" + ("-" * 50)) -ForegroundColor DarkGray
        }
        'Error' {
            $script:ErrorCount++
            Write-Host "[$timestamp] [ERROR] $indentString$Message" -ForegroundColor $color
        }
        'Warning' {
            $script:WarningCount++
            Write-Host "[$timestamp] [WARN]  $indentString$Message" -ForegroundColor $color
        }
        default {
            Write-Host "$indentString$Message" -ForegroundColor $color
        }
    }
}

function Write-OperationStatus {
    [CmdletBinding(DefaultParameterSetName = 'InProgress')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'InProgress')]
        [string]$Operation,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'InProgress')]
        [switch]$InProgress,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Success')]
        [switch]$Success,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Failed')]
        [switch]$Failed,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'Failed')]
        [string]$ErrorMessage
    )
    
    $indent = "    "
    
    switch ($PSCmdlet.ParameterSetName) {
        'InProgress' {
            Write-Host "$indent- $Operation..." -ForegroundColor Gray -NoNewline
        }
        'Success' {
            Write-Host " [OK]" -ForegroundColor Green
        }
        'Failed' {
            Write-Host " [FAILED]" -ForegroundColor Red
            if ($ErrorMessage) {
                Write-Host "$indent  Error: $ErrorMessage" -ForegroundColor Yellow
            }
        }
    }
}

function Initialize-Logging {
    [CmdletBinding()]
    param()
    
    if ($script:Config.EnableTranscript) {
        $logDir = $script:Config.LogDirectory
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $transcriptPath = Join-Path $logDir "Offboarding_$timestamp.log"
        
        try {
            Start-Transcript -Path $transcriptPath -Append
            Write-LogMessage "Transcript logging started: $transcriptPath" -Level Debug
        }
        catch {
            Write-LogMessage "Could not start transcript logging: $_" -Level Warning
        }
    }
}

# ============================================================================
# VALIDATION RESULT MANAGEMENT
# ============================================================================
function Add-ValidationResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $true)]
        [string]$Check,
        
        [Parameter(Mandatory = $true)]
        [ValidationStatus]$Status,
        
        [Parameter(Mandatory = $false)]
        [string]$Details = "",
        
        [Parameter(Mandatory = $false)]
        [string]$ExpectedValue = "",
        
        [Parameter(Mandatory = $false)]
        [string]$ActualValue = "",
        
        [Parameter(Mandatory = $false)]
        [datetime]$Timestamp = (Get-Date)
    )
    
    $result = [PSCustomObject]@{
        Domain        = $Domain
        Check         = $Check
        Status        = $Status.ToString()
        Details       = $Details
        ExpectedValue = $ExpectedValue
        ActualValue   = $ActualValue
        Timestamp     = $Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")
    }
    
    $script:ValidationResults.Add($result)
    return $result
}

function Add-OperationResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Action,
        
        [Parameter(Mandatory = $true)]
        [OperationStatus]$Status,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [string]$Target = "",
        
        [Parameter(Mandatory = $false)]
        [int]$Duration = 0,
        
        [Parameter(Mandatory = $false)]
        [datetime]$Timestamp = (Get-Date)
    )
    
    $result = [PSCustomObject]@{
        Action      = $Action
        Status      = $Status.ToString()
        Description = $Description
        Target      = $Target
        Duration    = $Duration
        Timestamp   = $Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")
    }
    
    $script:OperationResults.Add($result)
    return $result
}

function Reset-UserResults {
    [CmdletBinding()]
    param()
    
    $script:ValidationResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:OperationResults = [System.Collections.Generic.List[PSCustomObject]]::new()
}

# ============================================================================
# PDC EMULATOR DISCOVERY WITH RETRY LOGIC
# ============================================================================
function Get-PDCEmulatorWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        
        [Parameter(Mandatory = $false)]
        [string]$Server = $null
    )
    
    $retryCount = 0
    $maxRetries = $script:Config.RetryAttempts
    $retryDelay = $script:Config.RetryDelaySeconds
    
    while ($retryCount -lt $maxRetries) {
        try {
            $params = @{
                Identity    = $DomainName
                ErrorAction = 'Stop'
            }
            
            if ($Server) {
                $params.Server = $Server
            }
            
            $domain = Get-ADDomain @params
            return $domain.PDCEmulator
        }
        catch {
            $retryCount++
            if ($retryCount -lt $maxRetries) {
                Write-LogMessage "Retry $retryCount/$maxRetries for $DomainName PDC discovery..." -Level Debug
                Start-Sleep -Seconds $retryDelay
            }
            else {
                Write-LogMessage "Failed to discover PDC for $DomainName after $maxRetries attempts: $_" -Level Error
                return $null
            }
        }
    }
}

function Initialize-PDCEmulators {
    [CmdletBinding()]
    param()
    
    Write-LogMessage "PDC EMULATOR DISCOVERY" -Level Header
    
    try {
        $domains = $script:Config.Domains
        $pdcs = @{}
        
        # Main domain (corporateacc.com / Accendra)
        Write-Host "  Discovering PDC for " -NoNewline
        Write-Host $domains.Main -ForegroundColor White -NoNewline
        Write-Host "..." -NoNewline
        
        try {
            $mainPDC = Get-PDCEmulatorWithRetry -DomainName $domains.Main
            if ($mainPDC) {
                $pdcs[$domains.Main] = $mainPDC
                Write-Host " Found: " -ForegroundColor Green -NoNewline
                Write-Host $mainPDC -ForegroundColor Cyan
            }
            else {
                Write-Host " FAILED" -ForegroundColor Red
            }
        }
        catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-LogMessage "Error discovering main domain PDC: $($_.Exception.Message)" -Level Error
        }
        
        # Child/Trust domains (this script only touches Apria and Byram)
        $childDomains = @($domains.Apria, $domains.Byram)
        
        foreach ($domain in $childDomains) {
            Write-Host "  Discovering PDC for " -NoNewline
            Write-Host $domain -ForegroundColor White -NoNewline
            Write-Host "..." -NoNewline
            
            try {
                $pdc = Get-PDCEmulatorWithRetry -DomainName $domain -Server $domain
                if ($pdc) {
                    $pdcs[$domain] = $pdc
                    Write-Host " Found: " -ForegroundColor Green -NoNewline
                    Write-Host $pdc -ForegroundColor Cyan
                }
                else {
                    Write-Host " FAILED" -ForegroundColor Red
                }
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                Write-LogMessage "Error discovering PDC for $domain : $($_.Exception.Message)" -Level Error
            }
        }
        
        $script:PDCEmulators = $pdcs
        
        # Summary
        Write-Host ""
        Write-Host "  PDC Discovery Complete: " -NoNewline
        Write-Host "$($pdcs.Count)/$($childDomains.Count + 1)" -ForegroundColor $(if ($pdcs.Count -eq ($childDomains.Count + 1)) { 'Green' } else { 'Yellow' }) -NoNewline
        Write-Host " domains available"
        
        return $pdcs
    }
    catch {
        Write-LogMessage "Critical error during PDC discovery: $($_.Exception.Message)" -Level Error
        return @{}
    }
}

# ============================================================================
# GRAPH API AUTHENTICATION
# ============================================================================
function Get-GraphAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret
    )
    
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    
    $body = @{
        grant_type    = "client_credentials"
        scope         = "https://graph.microsoft.com/.default"
        client_id     = $ClientId
        client_secret = $ClientSecret
    }
    
    try {
        $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        
        # Parse token for expiration
        $tokenPayload = $response.access_token.Split('.')[1]
        # Pad the base64 string if needed
        $paddedPayload = $tokenPayload.PadRight([Math]::Ceiling($tokenPayload.Length / 4) * 4, '=')
        $decodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($paddedPayload)) | ConvertFrom-Json
        $expiresAt = [DateTimeOffset]::FromUnixTimeSeconds($decodedPayload.exp).LocalDateTime
        
        Write-LogMessage "Graph token acquired, expires: $($expiresAt.ToString('HH:mm:ss'))" -Level Debug
        
        return @{
            Token     = $response.access_token
            ExpiresAt = $expiresAt
        }
    }
    catch {
        $detail = $_.Exception.Message
        if ($detail -match 'AADSTS90002') {
            Write-LogMessage "Graph tenant '$TenantId' was not found (AADSTS90002). Use the Directory (tenant) ID from Entra admin center > Overview — not a Subscription ID. Update TenantId in this script's `$script:Config." -Level Error
        }
        Write-LogMessage "Failed to acquire Graph token: $_" -Level Error
        throw
    }
}

function Initialize-GraphConnection {
    [CmdletBinding()]
    param()
    
    Write-LogMessage "MICROSOFT GRAPH CONNECTION" -Level Header
    
    try {
        $tokenResult = Get-GraphAccessToken -TenantId $script:Config.TenantId `
            -ClientId $script:Config.ClientId `
            -ClientSecret $script:Config.ClientSecret
        
        $script:GraphToken = $tokenResult.Token
        $script:GraphHeaders = @{
            Authorization  = "Bearer $($script:GraphToken)"
            'Content-Type' = 'application/json'
        }
        
        Write-LogMessage "Graph API connection established" -Level Success -Indent 1
        return $true
    }
    catch {
        Write-LogMessage "Graph API connection failed: $_" -Level Error -Indent 1
        return $false
    }
}

# ============================================================================
# EXCHANGE ONLINE CONNECTION
# ============================================================================
function Connect-ExchangeOnlineSecure {
    [CmdletBinding()]
    param()
    
    Write-LogMessage "EXCHANGE ONLINE CONNECTION" -Level Header
    
    if ($script:SkipExchangeConnection -or $SkipExchangeConnection) {
        Write-LogMessage "Exchange connection skipped (parameter specified)" -Level Warning -Indent 1
        return $false
    }
    
    try {
        # Check if already connected
        $existingSession = Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.State -eq 'Opened' }
        if ($existingSession) {
            Write-LogMessage "Using existing Exchange Online session" -Level Success -Indent 1
            $script:ExchangeConnected = $true
            return $true
        }
        
        Import-Module ExchangeOnlineManagement -ErrorAction Stop

        $organization = $script:Config.ExchangeOrganization
        $appId = $script:Config.ExchangeAppId
        $certThumbprint = $script:Config.ExchangeCertificateThumbprint
        if ([string]::IsNullOrWhiteSpace($organization) -or
            [string]::IsNullOrWhiteSpace($appId) -or
            [string]::IsNullOrWhiteSpace($certThumbprint)) {
            throw "Exchange app authentication is not configured. Set ExchangeOrganization, ExchangeAppId, and ExchangeCertificateThumbprint in `$script:Config."
        }

        Write-LogMessage "Connecting to Exchange Online as app $appId ($organization)" -Level Debug -Indent 1
        Connect-ExchangeOnline -AppId $appId -CertificateThumbprint $certThumbprint -Organization $organization -ShowBanner:$false -ErrorAction Stop
        
        Write-LogMessage "Exchange Online connection established" -Level Success -Indent 1
        $script:ExchangeConnected = $true
        return $true
    }
    catch {
        Write-LogMessage "Exchange Online connection failed: $_" -Level Error -Indent 1
        $script:ExchangeConnected = $false
        return $false
    }
}

# ============================================================================
# USER INFORMATION RETRIEVAL
# ============================================================================
function Get-GraphUserInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    $selectProperties = @(
        'id', 'displayName', 'mail', 'userPrincipalName', 'employeeId',
        'onPremisesSamAccountName', 'onPremisesDistinguishedName',
        'accountEnabled', 'jobTitle', 'department', 'officeLocation',
        'createdDateTime', 'lastPasswordChangeDateTime'
    ) -join ','
    
    $uri = "https://graph.microsoft.com/v1.0/users/$([Uri]::EscapeDataString($UserPrincipalName))?`$select=$selectProperties"
    
    try {
        $user = Invoke-RestMethod -Uri $uri -Headers $script:GraphHeaders -Method Get -ErrorAction Stop
        return $user
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 404) {
            Write-LogMessage "User not found in Microsoft Graph: $UserPrincipalName" -Level Warning
        }
        else {
            Write-LogMessage "Error retrieving user from Graph: $_" -Level Error
        }
        return $null
    }
}

function Get-ADUserDetailedInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,
        
        [Parameter(Mandatory = $true)]
        [string]$PDCEmulator
    )
    
    # Accendra is the anchor object. accAapriaSID / accByramSID locate the linked
    # Apria and Byram accounts when those attributes have values.
    $apriaAttr = 'accAapriaSID'
    $byramAttr = 'accByramSID'
    if ($script:Config.ContainsKey('CrossDomainSidAttributes') -and $script:Config.CrossDomainSidAttributes) {
        if ($script:Config.CrossDomainSidAttributes['Apria']) {
            $apriaAttr = [string]$script:Config.CrossDomainSidAttributes['Apria']
        }
        if ($script:Config.CrossDomainSidAttributes['Byram']) {
            $byramAttr = [string]$script:Config.CrossDomainSidAttributes['Byram']
        }
    }

    $coreProperties = @(
        'Enabled', 'Description', 'PasswordLastSet', 'LastLogonDate',
        'Manager', 'DistinguishedName', 'SID', 'whenCreated', 'whenChanged',
        'memberOf'
    )
    $sidProperties = @($apriaAttr, $byramAttr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    
    try {
        $properties = @($coreProperties)
        if ($script:CrossDomainSidAttributesAvailable -ne $false -and $sidProperties.Count -gt 0) {
            $properties = @($coreProperties + $sidProperties)
        }

        try {
            $user = Get-ADUser -Identity $SamAccountName -Server $PDCEmulator -Properties $properties -ErrorAction Stop
            $script:CrossDomainSidAttributesAvailable = $true
        }
        catch {
            if ($_.Exception.Message -match 'properties are invalid|null value') {
                $script:CrossDomainSidAttributesAvailable = $false
                $user = Get-ADUser -Identity $SamAccountName -Server $PDCEmulator -Properties $coreProperties -ErrorAction Stop
            }
            else {
                throw
            }
        }

        $apriaSid = $null
        $byramSid = $null
        if ($apriaAttr -and $user.PSObject.Properties[$apriaAttr] -and $user.$apriaAttr) {
            $apriaSid = $user.$apriaAttr
        }
        if ($byramAttr -and $user.PSObject.Properties[$byramAttr] -and $user.$byramAttr) {
            $byramSid = $user.$byramAttr
        }
        
        $managerName = "Not Assigned"
        if ($user.Manager) {
            try {
                $manager = Get-ADUser -Identity $user.Manager -Server $PDCEmulator -Properties DisplayName -ErrorAction Stop
                $managerName = $manager.DisplayName
            }
            catch {
                $managerName = "Unable to retrieve"
            }
        }
        
        return @{
            User        = $user
            ManagerName = $managerName
            CrossDomainSIDs = @{
                Apria    = $apriaSid
                Byram    = $byramSid
            }
        }
    }
    catch {
        Write-LogMessage "Error retrieving AD user details for $SamAccountName : $_" -Level Error
        return $null
    }
}

# ============================================================================
# AD ACCOUNT OPERATIONS WITH ENHANCED VALIDATION
# ============================================================================
function Disable-ADAccountWithValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,
        
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $true)]
        [string]$PDCEmulator,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [bool]$ResetPassword = $true,
        
        [Parameter(Mandatory = $false)]
        [bool]$MoveToHoldOU = $true
    )
    
    $operationStart = Get-Date
    $results = @{
        DisableAccount  = $false
        SetDescription  = $false
        ResetPassword   = $false
        ExpireAccount   = $false
        MoveToOU        = $false
        PasswordBefore  = $null
        PasswordAfter   = $null
        Errors          = @()
    }
    
    # Capture initial state for validation
    try {
        $initialState = Get-ADUser -Identity $SamAccountName -Server $PDCEmulator -Properties Enabled, Description, PasswordLastSet -ErrorAction Stop
        $results.PasswordBefore = $initialState.PasswordLastSet
    }
    catch {
        $results.Errors += "Failed to capture initial state: $_"
        return $results
    }
    
    # 1. Disable Account
    Write-OperationStatus -Operation "Disabling account" -InProgress
    try {
        if (-not $WhatIf) {
            Disable-ADAccount -Identity $SamAccountName -Server $PDCEmulator -ErrorAction Stop
        }
        $results.DisableAccount = $true
        Write-OperationStatus -Success
    }
    catch {
        Write-OperationStatus -Failed -ErrorMessage $_.Exception.Message
        $results.Errors += "Disable account: $($_.Exception.Message)"
    }
    
    # 2. Set Description
    Write-OperationStatus -Operation "Setting description" -InProgress
    try {
        if (-not $WhatIf) {
            Set-ADUser -Identity $SamAccountName -Description $Description -Server $PDCEmulator -ErrorAction Stop
        }
        $results.SetDescription = $true
        Write-OperationStatus -Success
    }
    catch {
        Write-OperationStatus -Failed -ErrorMessage $_.Exception.Message
        $results.Errors += "Set description: $($_.Exception.Message)"
    }
    
    # 3. Reset Password (if requested)
    if ($ResetPassword) {
        Write-OperationStatus -Operation "Resetting password" -InProgress
        try {
            # Generate cryptographically secure password
            $passwordChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $bytes = New-Object byte[] 32
            $rng.GetBytes($bytes)
            $newPassword = -join ($bytes | ForEach-Object { $passwordChars[$_ % $passwordChars.Length] })
            $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
            
            if (-not $WhatIf) {
                Set-ADAccountPassword -Identity $SamAccountName -NewPassword $securePassword -Reset -Server $PDCEmulator -ErrorAction Stop
            }
            $results.ResetPassword = $true
            Write-OperationStatus -Success
        }
        catch {
            Write-OperationStatus -Failed -ErrorMessage $_.Exception.Message
            $results.Errors += "Reset password: $($_.Exception.Message)"
        }
    }
    
    # 4. Expire Account (set expiration to today so account is immediately expired)
    Write-OperationStatus -Operation "Expiring account" -InProgress
    try {
        # Set account expiration to today (account expires at end of this date)
        $expirationDate = (Get-Date).Date
        if (-not $WhatIf) {
            Set-ADAccountExpiration -Identity $SamAccountName -DateTime $expirationDate -Server $PDCEmulator -ErrorAction Stop
        }
        $results.ExpireAccount = $true
        Write-OperationStatus -Success
    }
    catch {
        Write-OperationStatus -Failed -ErrorMessage $_.Exception.Message
        $results.Errors += "Expire account: $($_.Exception.Message)"
    }
    
    # 5. Move to Hold OU (if requested)
    if ($MoveToHoldOU) {
        # Determine the correct Hold OU based on domain
        $targetHoldOU = $null
        # Main domain here is Accendra; its Hold OU comes from $script:Config.IAMHoldOU.
        if ($Domain -eq $script:Config.Domains.Main) {
            $targetHoldOU = $script:Config.IAMHoldOU
        }
        elseif ($Domain -eq $script:Config.Domains.Apria) {
            $targetHoldOU = $script:Config.CrossDomainHoldOUs.Apria
        }
        elseif ($Domain -eq $script:Config.Domains.Byram) {
            $targetHoldOU = $script:Config.CrossDomainHoldOUs.Byram
        }
        
        if ($targetHoldOU) {
            Write-OperationStatus -Operation "Moving to IAM Hold OU ($Domain)" -InProgress
            try {
                $userDN = (Get-ADUser -Identity $SamAccountName -Server $PDCEmulator).DistinguishedName
                if (-not $WhatIf) {
                    Move-ADObject -Identity $userDN -TargetPath $targetHoldOU -Server $PDCEmulator -ErrorAction Stop
                }
                $results.MoveToOU = $true
                Write-OperationStatus -Success
            }
            catch {
                Write-OperationStatus -Failed -ErrorMessage $_.Exception.Message
                $results.Errors += "Move to OU: $($_.Exception.Message)"
            }
        }
    }
    
    # Validation delay for replication
    Write-Host "    Waiting for replication..." -ForegroundColor Gray
    Start-Sleep -Seconds $script:Config.ValidationDelaySeconds
    
    # Validate changes
    try {
        $finalState = Get-ADUser -Identity $SamAccountName -Server $PDCEmulator -Properties Enabled, Description, PasswordLastSet, DistinguishedName, AccountExpirationDate -ErrorAction Stop
        $results.PasswordAfter = $finalState.PasswordLastSet
        
        # Validate: Account Disabled
        if ($finalState.Enabled -eq $false) {
            Add-ValidationResult -Domain $Domain -Check "Account Disabled" -Status Success `
                -Details "Account successfully disabled" `
                -ExpectedValue "Disabled" -ActualValue "Disabled"
        }
        else {
            Add-ValidationResult -Domain $Domain -Check "Account Disabled" -Status Failed `
                -Details "Account is still enabled after disable operation" `
                -ExpectedValue "Disabled" -ActualValue "Enabled"
        }
        
        # Validate: Description
        if ($finalState.Description -eq $Description) {
            Add-ValidationResult -Domain $Domain -Check "Description Updated" -Status Success `
                -Details "Description matches expected value" `
                -ExpectedValue $Description -ActualValue $finalState.Description
        }
        else {
            Add-ValidationResult -Domain $Domain -Check "Description Updated" -Status Failed `
                -Details "Description mismatch" `
                -ExpectedValue $Description -ActualValue $(if ($finalState.Description) { $finalState.Description } else { "<empty>" })
        }
        
        # Validate: Password Reset
        if ($ResetPassword) {
            $previousPwdDisplay = if ($results.PasswordBefore) { $results.PasswordBefore.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never Set" }
            $currentPwdDisplay = if ($finalState.PasswordLastSet) { $finalState.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never Set" }
            
            if ($finalState.PasswordLastSet -and $results.PasswordBefore) {
                $passwordAge = (Get-Date) - $finalState.PasswordLastSet
                if ($passwordAge.TotalMinutes -lt $script:Config.PasswordAgeThresholdMinutes -and $finalState.PasswordLastSet -gt $results.PasswordBefore) {
                    Add-ValidationResult -Domain $Domain -Check "Password Reset" -Status Success `
                        -Details "Password was reset successfully (Previous: $previousPwdDisplay, Current: $currentPwdDisplay)" `
                        -ExpectedValue "New password timestamp" -ActualValue $currentPwdDisplay
                }
                else {
                    Add-ValidationResult -Domain $Domain -Check "Password Reset" -Status Failed `
                        -Details "Password timestamp not updated as expected (Previous: $previousPwdDisplay, Current: $currentPwdDisplay)" `
                        -ExpectedValue "New password timestamp" -ActualValue $currentPwdDisplay
                }
            }
            elseif (-not $results.PasswordBefore -and $finalState.PasswordLastSet) {
                Add-ValidationResult -Domain $Domain -Check "Password Reset" -Status Success `
                    -Details "Password set for first time (Current: $currentPwdDisplay)" `
                    -ExpectedValue "New password" -ActualValue $currentPwdDisplay
            }
            else {
                Add-ValidationResult -Domain $Domain -Check "Password Reset" -Status Warning `
                    -Details "Unable to verify password change (Previous: $previousPwdDisplay)" `
                    -ExpectedValue "New password timestamp" -ActualValue "Verification inconclusive"
            }
        }
        
        # Validate: Account Expiration
        $expirationDate = $finalState.AccountExpirationDate
        if ($expirationDate) {
            # Check that the expiration date is set to today or in the past (i.e., account is expired)
            if ($expirationDate -le (Get-Date).Date.AddDays(1)) {
                Add-ValidationResult -Domain $Domain -Check "Account Expired" -Status Success `
                    -Details "Account expiration verified (Expires: $($expirationDate.ToString('yyyy-MM-dd')))" `
                    -ExpectedValue "Expired (today or earlier)" -ActualValue $expirationDate.ToString('yyyy-MM-dd')
            }
            else {
                Add-ValidationResult -Domain $Domain -Check "Account Expired" -Status Failed `
                    -Details "Account expiration date is in the future: $($expirationDate.ToString('yyyy-MM-dd'))" `
                    -ExpectedValue "Expired (today or earlier)" -ActualValue $expirationDate.ToString('yyyy-MM-dd')
            }
        }
        else {
            Add-ValidationResult -Domain $Domain -Check "Account Expired" -Status Failed `
                -Details "Account expiration date is not set" `
                -ExpectedValue "Expired (today or earlier)" -ActualValue "No expiration set"
        }
        
        # Validate: OU Move (all domains with Hold OUs)
        if ($MoveToHoldOU) {
            # Determine expected Hold OU based on domain
            $expectedHoldOU = $null
            if ($Domain -eq $script:Config.Domains.Main) {
                $expectedHoldOU = $script:Config.IAMHoldOU
            }
            elseif ($Domain -eq $script:Config.Domains.Apria) {
                $expectedHoldOU = $script:Config.CrossDomainHoldOUs.Apria
            }
            elseif ($Domain -eq $script:Config.Domains.Byram) {
                $expectedHoldOU = $script:Config.CrossDomainHoldOUs.Byram
            }
            
            if ($expectedHoldOU) {
                if ($finalState.DistinguishedName -like "*$expectedHoldOU") {
                    Add-ValidationResult -Domain $Domain -Check "Moved to IAM Hold OU" -Status Success `
                        -Details "User moved to IAM Hold OU in $Domain" `
                        -ExpectedValue $expectedHoldOU -ActualValue $finalState.DistinguishedName
                }
                else {
                    Add-ValidationResult -Domain $Domain -Check "Moved to IAM Hold OU" -Status Failed `
                        -Details "User not in expected OU for $Domain" `
                        -ExpectedValue $expectedHoldOU -ActualValue $finalState.DistinguishedName
                }
            }
        }
    }
    catch {
        Add-ValidationResult -Domain $Domain -Check "Post-Operation Validation" -Status Failed `
            -Details "Could not validate changes: $_"
    }
    
    $operationDuration = ((Get-Date) - $operationStart).TotalSeconds
    Write-LogMessage "AD operations completed in $([math]::Round($operationDuration, 2)) seconds" -Level Debug -Indent 2
    
    return $results
}

function Disable-CrossDomainAccountWithValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SID,
        
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $true)]
        [string]$PDCEmulator,
        
        [Parameter(Mandatory = $true)]
        [string]$Description
    )
    
    try {
        # Find user by SID
        $user = Get-ADUser -Filter "SID -eq '$SID'" -Server $PDCEmulator -ErrorAction Stop
        
        if (-not $user) {
            Write-LogMessage "No account found with SID in $Domain" -Level Warning -Indent 2
            Add-ValidationResult -Domain $Domain -Check "User Lookup" -Status Failed `
                -Details "No account found with matching SID" `
                -ExpectedValue "User account" -ActualValue "Not found"
            return $false
        }
        
        Write-LogMessage "Found user: $($user.SamAccountName)" -Level Info -Indent 2
        
        # Perform operations (no password reset, but move to Hold OU for cross-domain)
        $results = Disable-ADAccountWithValidation -SamAccountName $user.SamAccountName `
            -Domain $Domain -PDCEmulator $PDCEmulator `
            -Description $Description -ResetPassword $false -MoveToHoldOU $true
        
        return ($results.DisableAccount -and $results.SetDescription -and $results.ExpireAccount -and $results.MoveToOU)
    }
    catch {
        Write-LogMessage "Cross-domain operation error for $Domain : $_" -Level Error -Indent 2
        Add-ValidationResult -Domain $Domain -Check "Cross-Domain Operation" -Status Failed `
            -Details $_.Exception.Message
        return $false
    }
}

# ============================================================================
# M365 OPERATIONS WITH VALIDATION
# ============================================================================
function Set-AzureAccountDisabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    $uri = "https://graph.microsoft.com/v1.0/users/$([Uri]::EscapeDataString($UserPrincipalName))"
    $body = @{ accountEnabled = $false } | ConvertTo-Json
    
    try {
        if (-not $WhatIf) {
            Invoke-RestMethod -Uri $uri -Headers $script:GraphHeaders -Method Patch -Body $body -ErrorAction Stop
        }
        
        # Verify the change
        Start-Sleep -Milliseconds 500
        $verifyUser = Invoke-RestMethod -Uri "$uri`?`$select=accountEnabled" -Headers $script:GraphHeaders -Method Get -ErrorAction Stop
        
        if ($verifyUser.accountEnabled -eq $false) {
            return Add-OperationResult -Action "Block User Sign-In" -Status Success `
                -Description "User sign-in blocked and verified for $UserPrincipalName" -Target $UserPrincipalName
        }
        else {
            return Add-OperationResult -Action "Block User Sign-In" -Status Warning `
                -Description "Sign-in block command sent but verification shows account still enabled" -Target $UserPrincipalName
        }
    }
    catch {
        return Add-OperationResult -Action "Block User Sign-In" -Status Error `
            -Description $_.Exception.Message -Target $UserPrincipalName
    }
}

function Revoke-UserSessionsWithValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    $uri = "https://graph.microsoft.com/v1.0/users/$([Uri]::EscapeDataString($UserPrincipalName))/revokeSignInSessions"
    
    try {
        if (-not $WhatIf) {
            $result = Invoke-RestMethod -Uri $uri -Headers $script:GraphHeaders -Method Post -Body "{}" -ErrorAction Stop
        }
        
        return Add-OperationResult -Action "Revoke Sessions" -Status Success `
            -Description "All active sessions revoked for $UserPrincipalName" -Target $UserPrincipalName
    }
    catch {
        return Add-OperationResult -Action "Revoke Sessions" -Status Error `
            -Description $_.Exception.Message -Target $UserPrincipalName
    }
}

function Grant-MailboxAccessWithValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory = $true)]
        [string]$DelegateUser
    )
    
    if (-not $script:ExchangeConnected) {
        return Add-OperationResult -Action "Grant Mailbox Access" -Status Skipped `
            -Description "Exchange Online not connected" -Target $UserPrincipalName
    }
    
    try {
        if (-not $WhatIf) {
            Add-MailboxPermission -Identity $UserPrincipalName -User $DelegateUser `
                -AccessRights FullAccess -InheritanceType All -AutoMapping:$true -ErrorAction Stop | Out-Null
        }
        
        # Verify permission was granted
        Start-Sleep -Seconds 1
        $permissions = Get-MailboxPermission -Identity $UserPrincipalName -User $DelegateUser -ErrorAction SilentlyContinue
        
        if ($permissions -and $permissions.AccessRights -contains 'FullAccess') {
            return Add-OperationResult -Action "Grant Mailbox Access" -Status Success `
                -Description "Full access granted and verified to $DelegateUser on $UserPrincipalName's mailbox" -Target $UserPrincipalName
        }
        else {
            return Add-OperationResult -Action "Grant Mailbox Access" -Status Warning `
                -Description "Permission grant command sent but verification inconclusive" -Target $UserPrincipalName
        }
    }
    catch {
        return Add-OperationResult -Action "Grant Mailbox Access" -Status Error `
            -Description $_.Exception.Message -Target $UserPrincipalName
    }
}

function Set-AutoReplyWithValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    # Try Exchange Online cmdlet first
    if ($script:ExchangeConnected) {
        try {
            if (-not $WhatIf) {
                Set-MailboxAutoReplyConfiguration -Identity $UserPrincipalName `
                    -AutoReplyState Enabled `
                    -InternalMessage $Message `
                    -ExternalMessage $Message `
                    -ExternalAudience All `
                    -ErrorAction Stop
            }
            
            # Verify
            $config = Get-MailboxAutoReplyConfiguration -Identity $UserPrincipalName -ErrorAction SilentlyContinue
            if ($config -and $config.AutoReplyState -eq 'Enabled') {
                return Add-OperationResult -Action "Set Out of Office" -Status Success `
                    -Description "Auto-reply configured and verified for $UserPrincipalName (via Exchange Online)" -Target $UserPrincipalName
            }
            else {
                return Add-OperationResult -Action "Set Out of Office" -Status Warning `
                    -Description "Auto-reply configured but verification inconclusive" -Target $UserPrincipalName
            }
        }
        catch {
            Write-LogMessage "Exchange cmdlet failed, trying Graph API: $_" -Level Debug
        }
    }
    
    # Fallback to Graph API
    $uri = "https://graph.microsoft.com/v1.0/users/$([Uri]::EscapeDataString($UserPrincipalName))/mailboxSettings"
    $body = @{
        automaticRepliesSetting = @{
            status               = "alwaysEnabled"
            externalAudience     = "all"
            internalReplyMessage = $Message
            externalReplyMessage = $Message
        }
    } | ConvertTo-Json -Depth 3
    
    try {
        if (-not $WhatIf) {
            Invoke-RestMethod -Uri $uri -Headers $script:GraphHeaders -Method Patch -Body $body -ErrorAction Stop
        }
        
        return Add-OperationResult -Action "Set Out of Office" -Status Success `
            -Description "Auto-reply configured for $UserPrincipalName (via Graph API)" -Target $UserPrincipalName
    }
    catch {
        return Add-OperationResult -Action "Set Out of Office" -Status Error `
            -Description "Both Exchange and Graph API methods failed: $($_.Exception.Message)" -Target $UserPrincipalName
    }
}

function Disable-UserDevicesWithValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    $allDevices = @()
    $disabledCount = 0
    $errorCount = 0
    
    try {
        # Get registered devices
        $registeredUri = "https://graph.microsoft.com/v1.0/users/$([Uri]::EscapeDataString($UserPrincipalName))/registeredDevices"
        $registered = Invoke-RestMethod -Uri $registeredUri -Headers $script:GraphHeaders -Method Get -ErrorAction SilentlyContinue
        if ($registered.value) { $allDevices += $registered.value }
        
        # Get owned devices
        $ownedUri = "https://graph.microsoft.com/v1.0/users/$([Uri]::EscapeDataString($UserPrincipalName))/ownedDevices"
        $owned = Invoke-RestMethod -Uri $ownedUri -Headers $script:GraphHeaders -Method Get -ErrorAction SilentlyContinue
        if ($owned.value) { $allDevices += $owned.value }
        
        # Remove duplicates
        $uniqueDevices = $allDevices | Sort-Object -Property id -Unique
        
        if ($uniqueDevices.Count -eq 0) {
            return Add-OperationResult -Action "Disable Devices" -Status Info `
                -Description "No devices found for user" -Target $UserPrincipalName
        }
        
        foreach ($device in $uniqueDevices) {
            $deviceName = if ($device.displayName) { $device.displayName } else { "Unknown" }
            $deviceId = $device.id
            
            try {
                $disableUri = "https://graph.microsoft.com/v1.0/devices/$deviceId"
                $disableBody = @{ accountEnabled = $false } | ConvertTo-Json
                
                if (-not $WhatIf) {
                    Invoke-RestMethod -Uri $disableUri -Headers $script:GraphHeaders -Method Patch -Body $disableBody -ErrorAction Stop
                }
                
                # Verify
                Start-Sleep -Milliseconds 300
                $verifyDevice = Invoke-RestMethod -Uri $disableUri -Headers $script:GraphHeaders -Method Get -ErrorAction SilentlyContinue
                
                if ($verifyDevice.accountEnabled -eq $false) {
                    $disabledCount++
                }
                else {
                    $errorCount++
                }
            }
            catch {
                $errorCount++
                Write-LogMessage "Failed to disable device $deviceName : $_" -Level Debug
            }
        }
        
        $totalDevices = $uniqueDevices.Count
        if ($errorCount -eq 0) {
            return Add-OperationResult -Action "Disable Devices" -Status Success `
                -Description "$disabledCount of $totalDevices devices disabled successfully" -Target $UserPrincipalName
        }
        else {
            return Add-OperationResult -Action "Disable Devices" -Status Warning `
                -Description "$disabledCount of $totalDevices devices disabled, $errorCount failed" -Target $UserPrincipalName
        }
    }
    catch {
        return Add-OperationResult -Action "Disable Devices" -Status Error `
            -Description $_.Exception.Message -Target $UserPrincipalName
    }
}

function Get-LitigationHoldStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    if (-not $script:ExchangeConnected) {
        return @{
            Enabled  = $null
            Date     = $null
            Owner    = $null
            Duration = $null
            Status   = "Not checked (Exchange not connected)"
        }
    }
    
    try {
        $mailbox = Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop
        return @{
            Enabled  = $mailbox.LitigationHoldEnabled
            Date     = $mailbox.LitigationHoldDate
            Owner    = $mailbox.LitigationHoldOwner
            Duration = $mailbox.LitigationHoldDuration
            Status   = if ($mailbox.LitigationHoldEnabled) { "ACTIVE - Proceed with caution" } else { "Not enabled" }
        }
    }
    catch {
        return @{
            Enabled  = $null
            Date     = $null
            Owner    = $null
            Duration = $null
            Status   = "Error: $($_.Exception.Message)"
        }
    }
}

# ============================================================================
# REPORTING FUNCTIONS
# ============================================================================
function Show-ValidationResultsReport {
    [CmdletBinding()]
    param()
    
    if ($script:ValidationResults.Count -eq 0) {
        return
    }
    
    Write-LogMessage "AD VALIDATION RESULTS" -Level Header
    
    $groupedResults = $script:ValidationResults | Group-Object -Property Domain
    
    foreach ($group in $groupedResults) {
        Write-Host ""
        Write-Host "  Domain: " -ForegroundColor White -NoNewline
        Write-Host $group.Name -ForegroundColor Cyan
        Write-Host ("  " + ("-" * 55)) -ForegroundColor DarkGray
        
        foreach ($result in $group.Group) {
            $statusIcon = switch ($result.Status) {
                'Success' { "[✓]"; break }
                'Failed'  { "[✗]"; break }
                'Warning' { "[!]"; break }
                default   { "[-]" }
            }
            $statusColor = switch ($result.Status) {
                'Success' { 'Green'; break }
                'Failed'  { 'Red'; break }
                'Warning' { 'Yellow'; break }
                default   { 'Gray' }
            }
            
            Write-Host "    $statusIcon " -ForegroundColor $statusColor -NoNewline
            Write-Host "$($result.Check): " -ForegroundColor White -NoNewline
            Write-Host $result.Status -ForegroundColor $statusColor
            
            if ($result.Details) {
                Write-Host "        $($result.Details)" -ForegroundColor Gray
            }
        }
    }
    
    # Summary
    $successCount = ($script:ValidationResults | Where-Object { $_.Status -eq 'Success' }).Count
    $failedCount = ($script:ValidationResults | Where-Object { $_.Status -eq 'Failed' }).Count
    $totalCount = $script:ValidationResults.Count
    
    Write-Host ""
    Write-Host "  Summary: " -NoNewline
    Write-Host "$successCount passed" -ForegroundColor Green -NoNewline
    Write-Host ", " -NoNewline
    Write-Host "$failedCount failed" -ForegroundColor Red -NoNewline
    Write-Host " of $totalCount checks"
}

function Show-OperationResultsReport {
    [CmdletBinding()]
    param()
    
    if ($script:OperationResults.Count -eq 0) {
        return
    }
    
    Write-LogMessage "M365 OPERATION RESULTS" -Level Header
    
    foreach ($result in $script:OperationResults) {
        $statusIcon = switch ($result.Status) {
            'Success' { "[✓]"; break }
            'Error'   { "[✗]"; break }
            'Warning' { "[!]"; break }
            'Info'    { "[i]"; break }
            'Skipped' { "[-]"; break }
            default   { "[ ]" }
        }
        $statusColor = switch ($result.Status) {
            'Success' { 'Green'; break }
            'Error'   { 'Red'; break }
            'Warning' { 'Yellow'; break }
            'Info'    { 'Cyan'; break }
            'Skipped' { 'Gray'; break }
            default   { 'White' }
        }
        
        Write-Host "  $statusIcon " -ForegroundColor $statusColor -NoNewline
        Write-Host "$($result.Action): " -ForegroundColor White -NoNewline
        Write-Host $result.Status -ForegroundColor $statusColor
        
        if ($result.Description) {
            Write-Host "      $($result.Description)" -ForegroundColor Gray
        }
    }
    
    # Summary - Force array context to ensure .Count works correctly
    $successCount = @($script:OperationResults | Where-Object { $_.Status -eq 'Success' }).Count
    $errorCount = @($script:OperationResults | Where-Object { $_.Status -eq 'Error' }).Count
    $totalCount = $script:OperationResults.Count
    
    Write-Host ""
    Write-Host "  Summary: " -NoNewline
    Write-Host "$successCount successful" -ForegroundColor Green -NoNewline
    Write-Host ", " -NoNewline
    Write-Host "$errorCount errors" -ForegroundColor Red -NoNewline
    Write-Host " of $totalCount operations"
}

function Add-ConsolidatedUserResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory = $false)]
        [string]$DisplayName = "N/A",
        
        [Parameter(Mandatory = $false)]
        [string]$EmployeeId = "N/A",
        
        [Parameter(Mandatory = $false)]
        [string]$Manager = "N/A",
        
        [Parameter(Mandatory = $false)]
        [string]$DelegateEmail = "N/A",
        
        [Parameter(Mandatory = $false)]
        [datetime]$ProcessingTimestamp = (Get-Date)
    )
    
    # Build validation summary
    $validationSummary = @{}
    foreach ($result in $script:ValidationResults) {
        $key = "$($result.Domain)_$($result.Check)"
        $validationSummary[$key] = $result.Status
    }
    
    # Build operation summary
    $operationSummary = @{}
    foreach ($result in $script:OperationResults) {
        $operationSummary[$result.Action] = $result.Status
    }
    
    # Calculate overall status
    $hasErrors = ($script:ValidationResults | Where-Object { $_.Status -eq 'Failed' }).Count -gt 0 -or
                 ($script:OperationResults | Where-Object { $_.Status -eq 'Error' }).Count -gt 0
    $hasWarnings = ($script:ValidationResults | Where-Object { $_.Status -eq 'Warning' }).Count -gt 0 -or
                   ($script:OperationResults | Where-Object { $_.Status -eq 'Warning' }).Count -gt 0
    
    $overallStatus = if ($hasErrors) { "Completed with Errors" }
                     elseif ($hasWarnings) { "Completed with Warnings" }
                     else { "Success" }
    
    $domains = $script:Config.Domains
    
    $consolidatedResult = [PSCustomObject]@{
        UserPrincipalName     = $UserPrincipalName
        DisplayName           = $DisplayName
        EmployeeId            = $EmployeeId
        Manager               = $Manager
        DelegateEmail         = $DelegateEmail
        ProcessingTimestamp   = $ProcessingTimestamp.ToString("yyyy-MM-dd HH:mm:ss")
        OverallStatus         = $overallStatus
        
        # AD Operations - Main Domain (Accendra / corporateacc.com)
        Accendra_AccountDisabled   = if ($validationSummary["$($domains.Main)_Account Disabled"]) { $validationSummary["$($domains.Main)_Account Disabled"] } else { "N/A" }
        Accendra_DescriptionUpdated = if ($validationSummary["$($domains.Main)_Description Updated"]) { $validationSummary["$($domains.Main)_Description Updated"] } else { "N/A" }
        Accendra_PasswordReset     = if ($validationSummary["$($domains.Main)_Password Reset"]) { $validationSummary["$($domains.Main)_Password Reset"] } else { "N/A" }
        Accendra_AccountExpired    = if ($validationSummary["$($domains.Main)_Account Expired"]) { $validationSummary["$($domains.Main)_Account Expired"] } else { "N/A" }
        Accendra_MovedToHoldOU     = if ($validationSummary["$($domains.Main)_Moved to IAM Hold OU"]) { $validationSummary["$($domains.Main)_Moved to IAM Hold OU"] } else { "N/A" }
        
        # AD Operations - Apria (cross-domain)
        Apria_AccountDisabled   = if ($validationSummary["$($domains.Apria)_Account Disabled"]) { $validationSummary["$($domains.Apria)_Account Disabled"] } else { "N/A" }
        Apria_DescriptionUpdated = if ($validationSummary["$($domains.Apria)_Description Updated"]) { $validationSummary["$($domains.Apria)_Description Updated"] } else { "N/A" }
        Apria_AccountExpired    = if ($validationSummary["$($domains.Apria)_Account Expired"]) { $validationSummary["$($domains.Apria)_Account Expired"] } else { "N/A" }
        
        # AD Operations - Byram (cross-domain)
        Byram_AccountDisabled   = if ($validationSummary["$($domains.Byram)_Account Disabled"]) { $validationSummary["$($domains.Byram)_Account Disabled"] } else { "N/A" }
        Byram_DescriptionUpdated = if ($validationSummary["$($domains.Byram)_Description Updated"]) { $validationSummary["$($domains.Byram)_Description Updated"] } else { "N/A" }
        Byram_AccountExpired    = if ($validationSummary["$($domains.Byram)_Account Expired"]) { $validationSummary["$($domains.Byram)_Account Expired"] } else { "N/A" }
        
        # M365 Operations
        BlockSignIn           = if ($operationSummary["Block User Sign-In"]) { $operationSummary["Block User Sign-In"] } else { "N/A" }
        RevokeSessions        = if ($operationSummary["Revoke Sessions"]) { $operationSummary["Revoke Sessions"] } else { "N/A" }
        MailboxAccess         = if ($operationSummary["Grant Mailbox Access"]) { $operationSummary["Grant Mailbox Access"] } else { "N/A" }
        OutOfOffice           = if ($operationSummary["Set Out of Office"]) { $operationSummary["Set Out of Office"] } else { "N/A" }
        DisableDevices        = if ($operationSummary["Disable Devices"]) { $operationSummary["Disable Devices"] } else { "N/A" }
        
        # Counts
        ValidationsPassed     = ($script:ValidationResults | Where-Object { $_.Status -eq 'Success' }).Count
        ValidationsFailed     = ($script:ValidationResults | Where-Object { $_.Status -eq 'Failed' }).Count
        OperationsSucceeded   = ($script:OperationResults | Where-Object { $_.Status -eq 'Success' }).Count
        OperationsFailed      = ($script:OperationResults | Where-Object { $_.Status -eq 'Error' }).Count
        
        # Detailed JSON for troubleshooting
        ValidationDetails     = ($script:ValidationResults | ConvertTo-Json -Compress -Depth 3)
        OperationDetails      = ($script:OperationResults | ConvertTo-Json -Compress -Depth 3)
    }
    
    $script:AllUserResults.Add($consolidatedResult)
}

# ============================================================================
# MICROSOFT IDENTITY MANAGER (MIM) - PREVENT OFFBOARDING REVERSAL
# ============================================================================
function Set-MIMIgnoreWorkdayStatus {
    <#
    .SYNOPSIS
        Sets the "_Ignore_Workday_Active_Status" flags on the user's MIM
        Person object so Microsoft Identity Manager does not reverse the
        offboarding actions on its next sync from Workday.

    .PARAMETER SamAccountName
        The on-prem SAM account name used to locate the MIM Person object
        (matched against the AccountName attribute).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName
    )

    # Respect the master switch in config.
    if (-not $script:Config.MIMEnabled) {
        Write-LogMessage "MIM integration disabled in config - skipping Workday ignore flags." -Level Debug -Indent 1
        return [PSCustomObject]@{ Status = 'Skipped'; Description = 'MIM integration disabled' }
    }

    try {
        # The LithnetRMA module and RM client must be available/initialised.
        # The client is set once at startup; we set it again here defensively
        # in case this function is called standalone.
        Set-ResourceManagementClient $script:Config.MIMServiceUri -ErrorAction Stop

        # Locate the MIM Person object by AccountName. Only pull the attributes
        # we intend to change to keep the request lightweight.
        $person = Search-Resources -XPath "/Person[(AccountName = '$SamAccountName')]" `
            -AttributesToGet @(
                "AccountName",
                "_Ignore_Workday_Active_Status",
                "_Byram_Ignore_Workday_Active_Status",
                "_Apria_Ignore_Workday_Active_Status"
            ) -ErrorAction Stop

        if (-not $person) {
            Write-LogMessage "No MIM Person object found for AccountName '$SamAccountName'." -Level Warning -Indent 1
            # NOTE: use "return Add-OperationResult ..." (single object out) to match
            # the other operation handlers. Calling Add-OperationResult AND returning
            # a second PSCustomObject makes this function emit an ARRAY, which breaks
            # the "$result.Status" / "$result.Description" checks at the call site.
            return Add-OperationResult -Action "MIM Ignore Workday Status" -Status Warning `
                -Description "MIM Person not found" -Target $SamAccountName
        }

        # Guard against multiple matches - we only expect one Person per account.
        if ($person -is [System.Array] -and $person.Count -gt 1) {
            Write-LogMessage "Multiple MIM Person objects matched '$SamAccountName' ($($person.Count)). Skipping to avoid ambiguous update." -Level Warning -Indent 1
            return Add-OperationResult -Action "MIM Ignore Workday Status" -Status Warning `
                -Description "Multiple MIM Person matches ($($person.Count))" -Target $SamAccountName
        }

        # Set ignore flags so neither the standard nor the other Workday instance 
        # active-status enforcement reverses the offboarding.
        $person._Ignore_Workday_Active_Status     = $true
        $person._Apria_Ignore_Workday_Active_Status = $true
        $person._Byram_Ignore_Workday_Active_Status = $true

        Save-Resource $person -ErrorAction Stop

        Write-LogMessage "MIM Workday ignore flags set for '$SamAccountName' (offboarding protected from reversal)." -Level Success -Indent 1
        return Add-OperationResult -Action "MIM Ignore Workday Status" -Status Success `
            -Description "Set _Ignore_Workday_Active_Status, _Apria_Ignore_Workday_Active_Status, and _Byram_Ignore_Workday_Active_Status" -Target $SamAccountName
    }
    catch {
        Write-LogMessage "Failed to set MIM Workday ignore flags for '$SamAccountName': $($_.Exception.Message)" -Level Error -Indent 1
        return Add-OperationResult -Action "MIM Ignore Workday Status" -Status Error `
            -Description $_.Exception.Message -Target $SamAccountName
    }
}

# ============================================================================
# MAIN PROCESSING FUNCTIONS
# ============================================================================
function Process-SingleUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory = $true)]
        [string]$DelegateUser,
        
        [Parameter(Mandatory = $false)]
        [bool]$BatchMode = $false
    )
    
    try {
        # Reset per-user results
        Reset-UserResults
        
        $processingStart = Get-Date
        $processingTimestamp = $processingStart
        
        Write-LogMessage "PROCESSING USER: $UserPrincipalName" -Level Header
        
        # Get user from Graph
        Write-Host "  Retrieving user information..." -ForegroundColor Gray
        $graphUser = $null
        try {
            $graphUser = Get-GraphUserInfo -UserPrincipalName $UserPrincipalName
        }
        catch {
            Write-LogMessage "Error retrieving user from Graph: $($_.Exception.Message)" -Level Error
        }
    
    if (-not $graphUser) {
        Write-LogMessage "User not found in Microsoft Graph. Aborting." -Level Error -Indent 1
        
        if ($BatchMode) {
            $script:AllUserResults.Add([PSCustomObject]@{
                UserPrincipalName   = $UserPrincipalName
                DisplayName         = "N/A"
                EmployeeId          = "N/A"
                Manager             = "N/A"
                DelegateEmail       = $DelegateUser
                ProcessingTimestamp = $processingTimestamp.ToString("yyyy-MM-dd HH:mm:ss")
                OverallStatus       = "Failed - User Not Found in Graph"
                Accendra_AccountDisabled = "N/A"
                Accendra_DescriptionUpdated = "N/A"
                Accendra_PasswordReset   = "N/A"
                Accendra_AccountExpired  = "N/A"
                Accendra_MovedToHoldOU   = "N/A"
                Apria_AccountDisabled = "N/A"
                Apria_DescriptionUpdated = "N/A"
                Apria_AccountExpired = "N/A"
                Byram_AccountDisabled = "N/A"
                Byram_DescriptionUpdated = "N/A"
                Byram_AccountExpired = "N/A"
                BlockSignIn         = "N/A"
                RevokeSessions      = "N/A"
                MailboxAccess       = "N/A"
                OutOfOffice         = "N/A"
                DisableDevices      = "N/A"
                ValidationsPassed   = 0
                ValidationsFailed   = 0
                OperationsSucceeded = 0
                OperationsFailed    = 0
                ValidationDetails   = "User not found"
                OperationDetails    = "N/A"
            })
        }
        return $false
    }
    
    $samAccountName = $graphUser.onPremisesSamAccountName
    if (-not $samAccountName) {
        Write-LogMessage "SamAccountName not found for user. Cannot proceed with AD operations." -Level Error -Indent 1
        
        if ($BatchMode) {
            Add-ConsolidatedUserResult -UserPrincipalName $UserPrincipalName `
                -DisplayName $graphUser.displayName `
                -EmployeeId $graphUser.employeeId `
                -DelegateEmail $DelegateUser `
                -ProcessingTimestamp $processingTimestamp
        }
        return $false
    }
    
    # Get AD details
    $mainPDC = $script:PDCEmulators[$script:Config.Domains.Main]
    $adDetails = Get-ADUserDetailedInfo -SamAccountName $samAccountName -PDCEmulator $mainPDC
    
    if (-not $adDetails) {
        Write-LogMessage "Could not retrieve AD user details. Aborting." -Level Error -Indent 1
        
        if ($BatchMode) {
            Add-ConsolidatedUserResult -UserPrincipalName $UserPrincipalName `
                -DisplayName $graphUser.displayName `
                -EmployeeId $graphUser.employeeId `
                -DelegateEmail $DelegateUser `
                -ProcessingTimestamp $processingTimestamp
        }
        return $false
    }
    
    # Build domain presence string
    $domainPresence = @("Accendra Domain")
    if ($adDetails.CrossDomainSIDs.Apria) { $domainPresence += "Apria Domain" }
    if ($adDetails.CrossDomainSIDs.Byram) { $domainPresence += "Byram Domain" }
    
    # Check litigation hold
    $litigationHold = Get-LitigationHoldStatus -UserPrincipalName $UserPrincipalName
    
    # Display user information
    Write-Host ""
    Write-Host "  User Information:" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "    Name:           " -NoNewline; Write-Host $graphUser.displayName -ForegroundColor White
    Write-Host "    Email:          " -NoNewline; Write-Host $graphUser.mail -ForegroundColor White
    Write-Host "    Employee ID:    " -NoNewline; Write-Host $graphUser.employeeId -ForegroundColor White
    Write-Host "    SAM Account:    " -NoNewline; Write-Host $samAccountName -ForegroundColor White
    Write-Host "    Manager:        " -NoNewline; Write-Host $adDetails.ManagerName -ForegroundColor White
    Write-Host "    Delegate:       " -NoNewline; Write-Host $DelegateUser -ForegroundColor Cyan
    Write-Host "    Domains:        " -NoNewline; Write-Host ($domainPresence -join ", ") -ForegroundColor White
    Write-Host "    Account Status: " -NoNewline
    if ($adDetails.User.Enabled) {
        Write-Host "Enabled" -ForegroundColor Green
    } else {
        Write-Host "Already Disabled" -ForegroundColor Yellow
    }
    Write-Host "    Litigation Hold:" -NoNewline
    if ($litigationHold.Enabled) {
        Write-Host " $($litigationHold.Status)" -ForegroundColor Red
    } else {
        Write-Host " $($litigationHold.Status)" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Confirmation (interactive mode only)
    if (-not $BatchMode) {
        $confirm = Read-Host "  Proceed with offboarding? (Y/N)"
        if ($confirm -ne 'Y' -and $confirm -ne 'y') {
            Write-LogMessage "User skipped by operator" -Level Warning -Indent 1
            return $false
        }
    }
    
    # Build description
    $currentDate = Get-Date -Format "MM/dd/yyyy"
    $description = "$currentDate`: PER HR, Do Not Reset the Password"
    $outOfOfficeMessage = "Thank you for reaching out. For further assistance, kindly direct all emails to $DelegateUser."
    
        # ─────────────────────────────────────────────────────────────────────────
        # ON-PREMISES AD OPERATIONS
        # ─────────────────────────────────────────────────────────────────────────
        Write-LogMessage "ON-PREMISES AD OPERATIONS" -Level Header
        
        # Main domain operations
        try {
            Write-LogMessage "Processing main domain ($($script:Config.Domains.Main))..." -Level SubHeader
            Disable-ADAccountWithValidation -SamAccountName $samAccountName `
                -Domain $script:Config.Domains.Main `
                -PDCEmulator $mainPDC `
                -Description $description `
                -ResetPassword $true `
                -MoveToHoldOU $true
        }
        catch {
            Write-LogMessage "Error processing main domain: $($_.Exception.Message)" -Level Error
            Add-ValidationResult -Domain $script:Config.Domains.Main -Check "Main Domain Operations" -Status Failed `
                -Details "Critical error: $($_.Exception.Message)"
        }
        
        # Cross-domain operations (this script: Apria + Byram).
        # Accounts are located via accAapriaSID / accByramSID on the Accendra user.
        # No SID value means no linked account in that domain; skip quietly.
        $domains = $script:Config.Domains
        
        if ($adDetails.CrossDomainSIDs.Apria -and $script:PDCEmulators.ContainsKey($domains.Apria)) {
            try {
                Write-LogMessage "Processing Apria domain..." -Level SubHeader
                Disable-CrossDomainAccountWithValidation -SID $adDetails.CrossDomainSIDs.Apria `
                    -Domain $domains.Apria `
                    -PDCEmulator $script:PDCEmulators[$domains.Apria] `
                    -Description $description
            }
            catch {
                Write-LogMessage "Error processing Apria domain: $($_.Exception.Message)" -Level Error
                Add-ValidationResult -Domain $domains.Apria -Check "Cross-Domain Operations" -Status Failed `
                    -Details "Critical error: $($_.Exception.Message)"
            }
        }
        
        if ($adDetails.CrossDomainSIDs.Byram -and $script:PDCEmulators.ContainsKey($domains.Byram)) {
            try {
                Write-LogMessage "Processing Byram domain..." -Level SubHeader
                Disable-CrossDomainAccountWithValidation -SID $adDetails.CrossDomainSIDs.Byram `
                    -Domain $domains.Byram `
                    -PDCEmulator $script:PDCEmulators[$domains.Byram] `
                    -Description $description
            }
            catch {
                Write-LogMessage "Error processing Byram domain: $($_.Exception.Message)" -Level Error
                Add-ValidationResult -Domain $domains.Byram -Check "Cross-Domain Operations" -Status Failed `
                    -Details "Critical error: $($_.Exception.Message)"
            }
        }
        
        # M365 OPERATIONS
        # ─────────────────────────────────────────────────────────────────────────
        Write-LogMessage "M365 CLOUD OPERATIONS" -Level Header

        try {
            Write-OperationStatus -Operation "Blocking user sign-in" -InProgress
            $result = Set-AzureAccountDisabled -UserPrincipalName $UserPrincipalName
            if ($result.Status -eq 'Success') {
                Write-OperationStatus -Success
            } else {
                Write-OperationStatus -Failed -ErrorMessage $result.Description
            }
        }
        catch {
            Write-OperationStatus -Failed -ErrorMessage $_.Exception.Message
            Add-OperationResult -Action "Block User Sign-In" -Status Error -Description $_.Exception.Message -Target $UserPrincipalName
        }

        try {
            Write-OperationStatus -Operation "Revoking active sessions" -InProgress
            $result = Revoke-UserSessionsWithValidation -UserPrincipalName $UserPrincipalName
            if ($result.Status -eq 'Success') {
                Write-OperationStatus -Success
            } else {
                Write-OperationStatus -Failed -ErrorMessage $result.Description
            }
        }
        catch {
            Write-OperationStatus -Failed -ErrorMessage $_.Exception.Message
            Add-OperationResult -Action "Revoke Sessions" -Status Error -Description $_.Exception.Message -Target $UserPrincipalName
        }

        try {
            Write-OperationStatus -Operation "Granting mailbox access to delegate" -InProgress
            $result = Grant-MailboxAccessWithValidation -UserPrincipalName $UserPrincipalName -DelegateUser $DelegateUser
            if ($result.Status -eq 'Success') {
                Write-OperationStatus -Success
            } else {
                Write-OperationStatus -Failed -ErrorMessage $result.Description
            }
        }
        catch {
            Write-OperationStatus -Failed -ErrorMessage $_.Exception.Message
            Add-OperationResult -Action "Grant Mailbox Access" -Status Error -Description $_.Exception.Message -Target $UserPrincipalName
        }

        try {
            Write-OperationStatus -Operation "Setting out-of-office reply" -InProgress
            $result = Set-AutoReplyWithValidation -UserPrincipalName $UserPrincipalName -Message $outOfOfficeMessage
            if ($result.Status -eq 'Success') {
                Write-OperationStatus -Success
            } else {
                Write-OperationStatus -Failed -ErrorMessage $result.Description
            }
        }
        catch {
            Write-OperationStatus -Failed -ErrorMessage $_.Exception.Message
            Add-OperationResult -Action "Set Out of Office" -Status Error -Description $_.Exception.Message -Target $UserPrincipalName
        }

        try {
            Write-OperationStatus -Operation "Disabling user devices" -InProgress
            $result = Disable-UserDevicesWithValidation -UserPrincipalName $UserPrincipalName
            if ($result.Status -in @('Success', 'Info')) {  # Info = "No devices found"
                Write-OperationStatus -Success
            } else {
                Write-OperationStatus -Failed -ErrorMessage $result.Description
            }
        }
        catch {
            Write-OperationStatus -Failed -ErrorMessage $_.Exception.Message
            Add-OperationResult -Action "Disable Devices" -Status Error -Description $_.Exception.Message -Target $UserPrincipalName
        }

        # ─────────────────────────────────────────────────────────────────────────
        # MICROSOFT IDENTITY MANAGER (MIM) - PREVENT REVERSAL
        # Set the Workday "ignore" flags so MIM does not re-enable / undo the
        # offboarding on its next sync. Run this AFTER the AD + M365 actions so
        # the account is already disabled before MIM stops enforcing Workday.
        # ─────────────────────────────────────────────────────────────────────────
        Write-LogMessage "MICROSOFT IDENTITY MANAGER (MIM)" -Level Header

        try {
            Write-OperationStatus -Operation "Setting MIM Workday ignore flags" -InProgress
            $result = Set-MIMIgnoreWorkdayStatus -SamAccountName $samAccountName
            if ($result.Status -in @('Success', 'Skipped')) {
                Write-OperationStatus -Success
            } else {
                Write-OperationStatus -Failed -ErrorMessage $result.Description
            }
        }
        catch {
            Write-OperationStatus -Failed -ErrorMessage $_.Exception.Message
            Add-OperationResult -Action "MIM Ignore Workday Status" -Status Error -Description $_.Exception.Message -Target $samAccountName
        }

    # ─────────────────────────────────────────────────────────────────────────
    # SHOW RESULTS
    # ─────────────────────────────────────────────────────────────────────────
    Show-ValidationResultsReport
    Show-OperationResultsReport
    
    # Add to consolidated results (batch mode)
    if ($BatchMode) {
        Add-ConsolidatedUserResult -UserPrincipalName $UserPrincipalName `
            -DisplayName $graphUser.displayName `
            -EmployeeId $graphUser.employeeId `
            -Manager $adDetails.ManagerName `
            -DelegateEmail $DelegateUser `
            -ProcessingTimestamp $processingTimestamp
    }
    
        # Processing complete
        $processingDuration = ((Get-Date) - $processingStart).TotalSeconds
        
        Write-Host ""
        Write-Host ("=" * 70) -ForegroundColor Green
        Write-Host "  OFFBOARDING COMPLETE FOR " -ForegroundColor Green -NoNewline
        Write-Host $UserPrincipalName.ToUpper() -ForegroundColor White
        Write-Host "  Processing time: $([math]::Round($processingDuration, 2)) seconds" -ForegroundColor Gray
        Write-Host ("=" * 70) -ForegroundColor Green
        Write-Host ""
        
        return $true
    }
    catch {
        Write-LogMessage "Critical error processing user $UserPrincipalName : $($_.Exception.Message)" -Level Error
        
        if ($BatchMode) {
            # Still add a result record for tracking purposes
            try {
                $script:AllUserResults.Add([PSCustomObject]@{
                    UserPrincipalName   = $UserPrincipalName
                    DisplayName         = "N/A"
                    EmployeeId          = "N/A"
                    Manager             = "N/A"
                    DelegateEmail       = $DelegateUser
                    ProcessingTimestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    OverallStatus       = "Failed - Critical Error: $($_.Exception.Message)"
                    Accendra_AccountDisabled = "N/A"
                    Accendra_DescriptionUpdated = "N/A"
                    Accendra_PasswordReset   = "N/A"
                    Accendra_AccountExpired  = "N/A"
                    Accendra_MovedToHoldOU   = "N/A"
                    Apria_AccountDisabled = "N/A"
                    Apria_DescriptionUpdated = "N/A"
                    Apria_AccountExpired = "N/A"
                    Byram_AccountDisabled = "N/A"
                    Byram_DescriptionUpdated = "N/A"
                    Byram_AccountExpired = "N/A"
                    BlockSignIn         = "N/A"
                    RevokeSessions      = "N/A"
                    MailboxAccess       = "N/A"
                    OutOfOffice         = "N/A"
                    DisableDevices      = "N/A"
                    ValidationsPassed   = 0
                    ValidationsFailed   = 0
                    OperationsSucceeded = 0
                    OperationsFailed    = 0
                    ValidationDetails   = "Critical error occurred"
                    OperationDetails    = $_.Exception.Message
                })
            }
            catch {
                Write-LogMessage "Failed to add error result to batch: $($_.Exception.Message)" -Level Warning
            }
        }
        
        return $false
    }
}

function Start-BatchOffboarding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    Write-LogMessage "BATCH OFFBOARDING MODE" -Level Header
    
    try {
        # Validate CSV file
        if (-not (Test-Path $CsvPath)) {
            Write-LogMessage "CSV file not found: $CsvPath" -Level Error
            return
        }
        
        # Import and validate CSV
        try {
            $users = Import-Csv -Path $CsvPath -ErrorAction Stop
        }
        catch {
            Write-LogMessage "Failed to import CSV file: $($_.Exception.Message)" -Level Error
            return
        }
        
        $totalUsers = $users.Count
        
        if ($totalUsers -eq 0) {
            Write-LogMessage "No users found in CSV file" -Level Error
            return
        }
        
        # Validate required columns
        $requiredColumns = @('UserPrincipalName', 'DelegateEmail')
        $csvColumns = $users[0].PSObject.Properties.Name
        $missingColumns = $requiredColumns | Where-Object { $_ -notin $csvColumns }
        
        if ($missingColumns) {
            Write-LogMessage "Missing required CSV columns: $($missingColumns -join ', ')" -Level Error
            Write-Host "  Required columns: UserPrincipalName, DelegateEmail" -ForegroundColor Yellow
            return
        }
        
        Write-Host "  Loaded " -NoNewline
        Write-Host "$totalUsers" -ForegroundColor Cyan -NoNewline
        Write-Host " users from CSV file"
        Write-Host ""
        
        # Preview
        Write-Host "  CSV Preview (first 5 users):" -ForegroundColor Yellow
        $users | Select-Object -First 5 UserPrincipalName, DelegateEmail | Format-Table -AutoSize | Out-String | Write-Host
        
        $confirm = Read-Host "  Proceed with batch processing? (Y/N)"
        if ($confirm -ne 'Y' -and $confirm -ne 'y') {
            Write-LogMessage "Batch processing cancelled by user" -Level Warning
            return
        }
        
        # Process each user
        $currentUser = 0
        $successCount = 0
        $errorCount = 0
        $batchStartTime = Get-Date
        
        foreach ($userRecord in $users) {
            $currentUser++
            
            Write-Host ""
            Write-Host ("*" * 70) -ForegroundColor Magenta
            Write-Host "  USER $currentUser OF $totalUsers" -ForegroundColor Magenta
            Write-Host ("*" * 70) -ForegroundColor Magenta
            
            try {
                $upn = if ($userRecord.UserPrincipalName) { $userRecord.UserPrincipalName.Trim() } else { $null }
                $delegate = if ($userRecord.DelegateEmail) { $userRecord.DelegateEmail.Trim() } else { $null }
                
                if ([string]::IsNullOrWhiteSpace($upn)) {
                    Write-LogMessage "Skipping row with empty UserPrincipalName" -Level Warning
                    continue
                }
                
                if ([string]::IsNullOrWhiteSpace($delegate)) {
                    Write-LogMessage "No delegate email for $upn - using fallback" -Level Warning
                    $delegate = "support@company.com"
                }
                
                $result = Process-SingleUser -UserPrincipalName $upn -DelegateUser $delegate -BatchMode $true
                
                if ($result) {
                    $successCount++
                } else {
                    $errorCount++
                }
            }
            catch {
                Write-LogMessage "Unexpected error processing user $upn : $($_.Exception.Message)" -Level Error
                $errorCount++
            }
            
            # Brief pause between users
            Start-Sleep -Seconds 2
        }
    
# Export results
        Write-LogMessage "EXPORTING RESULTS" -Level Header
        
        if ($script:AllUserResults.Count -gt 0) {
            try {
                $script:AllUserResults | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                
                Write-Host "  Report exported to: " -NoNewline
                Write-Host $OutputPath -ForegroundColor Cyan
                Write-Host ""
            }
            catch {
                Write-LogMessage "Failed to export results to CSV: $($_.Exception.Message)" -Level Error
                Write-LogMessage "Attempting to export to fallback location..." -Level Warning
                try {
                    $fallbackPath = Join-Path ([Environment]::GetFolderPath('Desktop')) "offboarding_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                    $script:AllUserResults | Export-Csv -Path $fallbackPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                    Write-Host "  Report exported to fallback: " -NoNewline
                    Write-Host $fallbackPath -ForegroundColor Yellow
                }
                catch {
                    Write-LogMessage "Failed to export to fallback location: $($_.Exception.Message)" -Level Error
                }
            }
            
            # Final summary
            $batchDuration = ((Get-Date) - $batchStartTime).TotalMinutes
            
            Write-Host "  ┌──────────────────────────────────────────────────────────┐" -ForegroundColor Gray
            Write-Host "  │" -ForegroundColor Gray -NoNewline
            Write-Host "                    BATCH SUMMARY                       " -ForegroundColor White -NoNewline
            Write-Host "│" -ForegroundColor Gray
            Write-Host "  ├──────────────────────────────────────────────────────────┤" -ForegroundColor Gray
            Write-Host "  │  Total Users Processed: " -ForegroundColor Gray -NoNewline
            Write-Host ("{0,-31}" -f $totalUsers) -ForegroundColor White -NoNewline
            Write-Host "│" -ForegroundColor Gray
            Write-Host "  │  Successful:            " -ForegroundColor Gray -NoNewline
            Write-Host ("{0,-31}" -f $successCount) -ForegroundColor Green -NoNewline
            Write-Host "│" -ForegroundColor Gray
            Write-Host "  │  With Errors:           " -ForegroundColor Gray -NoNewline
            Write-Host ("{0,-31}" -f $errorCount) -ForegroundColor Red -NoNewline
            Write-Host "│" -ForegroundColor Gray
            Write-Host "  │  Duration:              " -ForegroundColor Gray -NoNewline
            Write-Host ("{0,-31}" -f "$([math]::Round($batchDuration, 2)) minutes") -ForegroundColor White -NoNewline
            Write-Host "│" -ForegroundColor Gray
            Write-Host "  └──────────────────────────────────────────────────────────┘" -ForegroundColor Gray
        }
        else {
            Write-LogMessage "No results to export" -Level Warning
        }
        
        Write-Host ""
        Write-LogMessage "BATCH PROCESSING COMPLETE" -Level Header
    }
    catch {
        Write-LogMessage "Critical error during batch processing: $($_.Exception.Message)" -Level Error
    }
}

function Start-InteractiveOffboarding {
    [CmdletBinding()]
    param()
    
    do {
        try {
            Write-LogMessage "USER SELECTION" -Level Header
            
            $userPrincipalName = Read-Host "  Enter user's UPN (or 'exit' to quit)"
            if ($userPrincipalName -eq 'exit') { break }
            
            if ([string]::IsNullOrWhiteSpace($userPrincipalName)) {
                Write-LogMessage "UPN cannot be empty. Please try again." -Level Warning
                continue
            }
            
            $delegateUser = Read-Host "  Enter delegate/manager email address"
            
            if ([string]::IsNullOrWhiteSpace($delegateUser)) {
                Write-LogMessage "Delegate email cannot be empty. Please try again." -Level Warning
                continue
            }
            
            Process-SingleUser -UserPrincipalName $userPrincipalName -DelegateUser $delegateUser -BatchMode $false
        }
        catch {
            Write-LogMessage "Error during interactive processing: $($_.Exception.Message)" -Level Error
        }
        
    } while ($true)
}

# ============================================================================
# FILE DIALOG HELPERS
# ============================================================================
function Show-OpenFileDialog {
    [CmdletBinding()]
    param(
        [string]$Title = "Select a file",
        [string]$Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*",
        [string]$InitialDirectory = [Environment]::GetFolderPath('Desktop')
    )
    
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = $Title
        $dialog.Filter = $Filter
        $dialog.InitialDirectory = $InitialDirectory
        
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            return $dialog.FileName
        }
        return $null
    }
    catch {
        Write-LogMessage "Failed to open file dialog: $($_.Exception.Message)" -Level Error
        Write-Host "  Please enter the file path manually: " -ForegroundColor Yellow -NoNewline
        $manualPath = Read-Host
        if (Test-Path $manualPath) {
            return $manualPath
        }
        return $null
    }
}

function Show-SaveFileDialog {
    [CmdletBinding()]
    param(
        [string]$Title = "Save file as",
        [string]$Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*",
        [string]$DefaultFileName = "report.csv",
        [string]$InitialDirectory = [Environment]::GetFolderPath('Desktop')
    )
    
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        
        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Title = $Title
        $dialog.Filter = $Filter
        $dialog.FileName = $DefaultFileName
        $dialog.InitialDirectory = $InitialDirectory
        
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            return $dialog.FileName
        }
        return $null
    }
    catch {
        Write-LogMessage "Failed to open save dialog: $($_.Exception.Message)" -Level Error
        Write-Host "  Please enter the save path manually: " -ForegroundColor Yellow -NoNewline
        $manualPath = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($manualPath)) {
            return $manualPath
        }
        return $null
    }
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
function Start-Offboarding {
    [CmdletBinding()]
    param()
    
    try {
        # Initialize logging
        Initialize-Logging
        
        Write-Host ""
        Write-Host ("=" * 70) -ForegroundColor Cyan
        Write-Host "  USER OFFBOARDING SCRIPT v2.9 - Accendra / Apria / Byram" -ForegroundColor Cyan
        Write-Host "  Author: Anthony Blake | Enhanced: $(Get-Date -Format 'yyyy-MM-dd')" -ForegroundColor DarkCyan
        Write-Host "  Exchange: app + certificate thumbprint ($($script:Config.ExchangeOrganization))" -ForegroundColor DarkCyan
        Write-Host ("=" * 70) -ForegroundColor Cyan
        
        # Import required modules
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        catch {
            Write-LogMessage "Failed to import ActiveDirectory module: $($_.Exception.Message)" -Level Error
            return
        }

        # Import Lithnet RMA and initialise the MIM Resource Management client.
        # If this fails we only warn (and disable MIM for the run) so the rest
        # of the offboarding can still proceed; the MIM step will be skipped.
        if ($script:Config.MIMEnabled) {
            try {
                Import-Module LithnetRMA -ErrorAction Stop
                Set-ResourceManagementClient $script:Config.MIMServiceUri -ErrorAction Stop
                Write-LogMessage "Lithnet RMA connected to MIM: $($script:Config.MIMServiceUri)" -Level Success -Indent 1
            }
            catch {
                Write-LogMessage "Failed to initialise Lithnet RMA / MIM connection: $($_.Exception.Message). MIM step will be skipped." -Level Warning -Indent 1
                $script:Config.MIMEnabled = $false
            }
        }
        
        # Initialize connections
        try {
            $pdcs = Initialize-PDCEmulators
            $mainPDC = $pdcs[$script:Config.Domains.Main]
            
            if (-not $mainPDC) {
                Write-LogMessage "Cannot proceed without main domain PDC. Exiting." -Level Error
                return
            }
        }
        catch {
            Write-LogMessage "Failed to initialize PDC emulators: $($_.Exception.Message)" -Level Error
            return
        }
        
        try {
            $graphConnected = Initialize-GraphConnection
            if (-not $graphConnected) {
                Write-LogMessage "Cannot proceed without Graph API connection. Exiting." -Level Error
                return
            }
        }
        catch {
            Write-LogMessage "Failed to initialize Graph connection: $($_.Exception.Message)" -Level Error
            return
        }
        
        try {
            $script:ExchangeConnected = Connect-ExchangeOnlineSecure
        }
        catch {
            Write-LogMessage "Failed to connect to Exchange Online: $($_.Exception.Message)" -Level Warning
            $script:ExchangeConnected = $false
        }
        
        # Mode selection
        if ($Mode -eq 'Menu') {
            Write-Host ""
            Write-Host "  Select processing mode:" -ForegroundColor Yellow
            Write-Host "    1. Interactive Mode (single user)" -ForegroundColor White
            Write-Host "    2. Batch Mode (CSV file)" -ForegroundColor White
            Write-Host ""
            
            $modeSelection = Read-Host "  Enter mode (1 or 2)"
            $Mode = if ($modeSelection -eq '2') { 'Batch' } else { 'Interactive' }
        }
        
        switch ($Mode) {
            'Batch' {
                try {
                    # Get CSV paths
                    if (-not $CsvInputPath) {
                        Write-Host "  Opening file picker for CSV import..." -ForegroundColor Gray
                        $CsvInputPath = Show-OpenFileDialog -Title "Select CSV File with User List"
                    }
                    
                    if (-not $CsvInputPath) {
                        Write-LogMessage "No input file selected. Exiting." -Level Warning
                        return
                    }
                    
                    if (-not $CsvOutputPath) {
                        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                        Write-Host "  Opening file picker for export location..." -ForegroundColor Gray
                        $CsvOutputPath = Show-SaveFileDialog -Title "Save Validation Report As" `
                            -DefaultFileName "offboarding_report_$timestamp.csv"
                    }
                    
                    if (-not $CsvOutputPath) {
                        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                        $CsvOutputPath = ".\offboarding_report_$timestamp.csv"
                        Write-LogMessage "Using default output path: $CsvOutputPath" -Level Warning
                    }
                    
                    Start-BatchOffboarding -CsvPath $CsvInputPath -OutputPath $CsvOutputPath
                }
                catch {
                    Write-LogMessage "Error during batch mode execution: $($_.Exception.Message)" -Level Error
                }
            }
            
            'Interactive' {
                try {
                    Start-InteractiveOffboarding
                }
                catch {
                    Write-LogMessage "Error during interactive mode execution: $($_.Exception.Message)" -Level Error
                }
            }
        }
    }
    catch {
        Write-LogMessage "Critical error in Start-Offboarding: $($_.Exception.Message)" -Level Error
    }
    finally {
        # Cleanup - always runs
        try {
            if ($script:ExchangeConnected) {
                Write-Host "  Disconnecting from Exchange Online..." -ForegroundColor Gray
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-LogMessage "Error disconnecting from Exchange: $($_.Exception.Message)" -Level Warning
        }
        
        try {
            if ($script:Config.EnableTranscript) {
                Stop-Transcript -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Silently ignore transcript stop errors
        }
        
        Write-Host ""
        Write-LogMessage "Script execution completed" -Level Success
        Write-Host "  Total errors: $($script:ErrorCount) | Total warnings: $($script:WarningCount)" -ForegroundColor Gray
        Write-Host ""
    }
}

# ============================================================================
# EXECUTION
# ============================================================================
Start-Offboarding

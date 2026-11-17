#Requires -Version 5.1
<#
.SYNOPSIS
    Unit tests for the M365 PowerShell forensics engine. No tenant connection required.
#>
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot '..\M365PowerShellForensics.psm1'
Import-Module $modulePath -Force -DisableNameChecking

$script:Passed = 0
$script:Failed = 0

function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        $script:Passed++
        Write-Host "  PASS  $Name" -ForegroundColor Green
    } else {
        $script:Failed++
        Write-Host "  FAIL  $Name" -ForegroundColor Red
    }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Name)
    if ($Actual -eq $Expected) {
        $script:Passed++
        Write-Host "  PASS  $Name" -ForegroundColor Green
    } else {
        $script:Failed++
        Write-Host "  FAIL  $Name" -ForegroundColor Red
        Write-Host "        expected: [$Expected]" -ForegroundColor DarkRed
        Write-Host "        actual  : [$Actual]" -ForegroundColor DarkRed
    }
}

function Assert-Contains {
    param([string]$Haystack, [string]$Needle, [string]$Name)
    Assert-True ($Haystack -like "*$Needle*") $Name
}

function Assert-NotContains {
    param([string]$Haystack, [string]$Needle, [string]$Name)
    Assert-True ($Haystack -notlike "*$Needle*") $Name
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Name)
    $threw = $false
    try { & $Action } catch { $threw = $true }
    Assert-True $threw $Name
}

function New-FakeUal {
    param($Audit, [string]$RecordType = '', [string]$Identity = '')
    if (-not $Identity) { $Identity = [guid]::NewGuid().ToString() }
    if (-not $RecordType -and $Audit.RecordType) { $RecordType = [string]$Audit.RecordType }
    [pscustomobject]@{
        AuditData  = ($Audit | ConvertTo-Json -Depth 8 -Compress)
        RecordType = $RecordType
        Operations = $Audit.Operation
        UserIds    = $Audit.UserId
        Identity   = $Identity
    }
}

Write-Host 'Helpers'
Assert-Equal (Format-Ip '203.0.113.50:443') '203.0.113.50' 'IPv4:port is stripped'
Assert-Equal (Format-Ip '[2001:db8::1]:443') '2001:db8::1' 'bracketed IPv6:port is stripped'
Assert-Equal (Format-Ip '  10.1.2.3  ') '10.1.2.3' 'IP whitespace is trimmed'
Assert-Equal (Get-Outcome 'Succeeded') 'Succeeded' 'Succeeded stays Succeeded'
Assert-Equal (Get-Outcome 'True') 'Succeeded' 'True is Succeeded'
Assert-Equal (Get-Outcome 'Failed') 'Failed' 'Failed stays Failed'
Assert-Equal (Get-Outcome '') 'Unknown' 'empty outcome is Unknown'
Assert-Equal (Protect-CsvValue '=cmd|calc') "'=cmd|calc" 'equals-prefix CSV is quoted'
Assert-Equal (Protect-CsvValue '-2+3') "'-2+3" 'hyphen-prefix CSV is quoted'
Assert-Equal (Protect-CsvValue 'normal') 'normal' 'ordinary CSV text is unchanged'
Assert-Equal (ConvertTo-HtmlEncoded '<img src=x>') '&lt;img src=x&gt;' 'HTML is encoded'
Assert-Equal (Get-AppName '14d82eec-204b-4c2f-b7e8-296a70dab67e') 'Microsoft Graph PowerShell / Graph CLI' 'Graph PowerShell app id is named'
Assert-Equal (Get-ClientFromUserAgent 'WindowsPowerShell/5.1') 'PowerShell' 'PowerShell user agent is detected'
Assert-Equal (Get-ClientFromUserAgent 'python-requests/2.31.0') 'Script / attack tooling' 'python-requests is tooling'
Assert-Equal (Get-ClientFromUserAgent 'Mozilla/5.0') '' 'browser user agent is not PowerShell'
$iso = ConvertTo-UtcIso ([datetime]::SpecifyKind([datetime]'2026-01-02T03:04:05', 'Utc'))
Assert-Equal $iso '2026-01-02T03:04:05Z' 'UTC datetime becomes ISO Z'
Assert-Equal (ConvertFrom-UtcIso '2026-01-02T03:04:05Z').Year 2026 'ISO Z parses'
$est = ConvertTo-EasternTime ([datetime]::SpecifyKind([datetime]'2026-01-02T03:04:05', 'Utc'))
Assert-Equal $est '2026-01-01 22:04:05 -05:00' 'January UTC converts to Eastern Standard Time'
$edt = ConvertTo-EasternTime ([datetime]::SpecifyKind([datetime]'2026-07-02T03:04:05', 'Utc'))
Assert-Equal $edt '2026-07-01 23:04:05 -04:00' 'July UTC converts to Eastern Daylight Time'
Assert-Equal (ConvertTo-EasternTime $est) $est 'Eastern conversion is idempotent'
$ids = Get-NormalizedIdList @('Jane@Contoso.com, bob@contoso.com', 'jane@contoso.com')
Assert-Equal $ids.Count 2 'duplicate UPNs collapse'
Assert-True ($ids -contains 'jane@contoso.com') 'UPNs are lowercased'
$types = Get-NormalizedTokenList 'MicrosoftTeams, PowerBIAudit' -KeepCase
Assert-Equal $types.Count 2 'record types split'
Assert-True ($types -contains 'MicrosoftTeams') 'UAL record types keep their casing'

Write-Host 'Command line and channel'
$params = @(
    [pscustomobject]@{ Name = 'Identity'; Value = 'jdoe@contoso.com' },
    [pscustomobject]@{ Name = 'ForwardingSmtpAddress'; Value = 'smtp:evil@evil.example' },
    [pscustomobject]@{ Name = 'DeliverToMailboxAndForward'; Value = 'True' }
)
$cmd = Format-CommandLine 'Set-Mailbox' $params
Assert-Contains $cmd "Set-Mailbox" 'cmdlet name is first'
Assert-Contains $cmd "-Identity 'jdoe@contoso.com'" 'Identity is quoted'
Assert-Contains $cmd '-DeliverToMailboxAndForward:$true' 'boolean switch is :$true'
Assert-Equal (Get-TargetIdentity $params) 'jdoe@contoso.com' 'Mailbox/Identity target is extracted'
$ch = Get-ExecutionChannel -AppId 'fb78d390-0c51-40cd-8e17-fdbfab77341b' -UserAgent '' -RecordType 'ExchangeAdmin'
Assert-Equal $ch[0] 'Yes' 'EXO REST app is PowerShell'
Assert-Contains $ch[1] 'Exchange Online' 'EXO REST app is named'
$chSys = Get-ExecutionChannel -AppId '' -UserAgent '' -RecordType 'ExchangeAdmin' -ExternalAccess 'True' -Actor 'NT AUTHORITY\SYSTEM'
Assert-Equal $chSys[0] 'System' 'ExternalAccess cmdlet is System'
$chTok = Get-ExecutionChannel -AppId 'd3590ed6-52b3-4102-aeff-aad2292ab01c' -UserAgent '' -RecordType 'AzureActiveDirectory'
Assert-Equal $chTok[0] 'Possible' 'Office FOCI client is Possible'

Write-Host 'UAL record conversion and MITRE classification'
Initialize-SuspectSets -Users @('attacker@contoso.com') -IPs @('203.0.113.50')
$ual = New-FakeUal -RecordType 'ExchangeAdmin' -Audit ([pscustomobject]@{
        CreationTime = '2026-10-01T12:00:00'
        Operation    = 'Set-Mailbox'
        UserId       = 'attacker@contoso.com'
        ClientIP     = '203.0.113.50:443'
        ResultStatus = 'Succeeded'
        Workload     = 'Exchange'
        Parameters   = @(
            [pscustomobject]@{ Name = 'Identity'; Value = 'cfo@contoso.com' },
            [pscustomobject]@{ Name = 'ForwardingSmtpAddress'; Value = 'smtp:evil@evil.example' }
        )
        ObjectId     = 'cfo@contoso.com'
    })
$row = ConvertFrom-UalRecord $ual 'Admin'
Assert-Contains $row.TimeUtc '2026-10-01 08:00:00 -04:00' 'UAL event time is Eastern (EDT in October)'
Assert-Equal $row.Actor 'attacker@contoso.com' 'actor is the UAL UserId'
Assert-Equal $row.ClientIP '203.0.113.50' 'client IP port is stripped'
Assert-Contains $row.CommandLine 'Set-Mailbox' 'command line is reconstructed'
Assert-Contains $row.CommandLine 'ForwardingSmtpAddress' 'forwarding parameter is in the command line'
Assert-Equal $row.Severity 'High' 'forwarding cmdlet is High (or higher from suspect IP)'
Assert-Contains $row.Category 'Mail Forwarding' 'forwarding category'
Assert-Contains $row.SuspectMatch 'Actor' 'suspect actor is tagged'
Assert-Contains $row.SuspectMatch 'IP' 'suspect IP is tagged'
Assert-Equal $row.Mitre 'T1114.003' 'forwarding maps to T1114.003'
Assert-Contains $row.AccessGained 'forwarding' 'access gained describes forwarding'

$fed = New-FakeUal -RecordType 'AzureActiveDirectory' -Audit ([pscustomobject]@{
        CreationTime = '2026-10-01T13:00:00'
        Operation    = 'Set domain authentication'
        UserId       = 'attacker@contoso.com'
        ResultStatus = 'Success'
        Workload     = 'AzureActiveDirectory'
        ObjectId     = 'contoso.com'
    })
$fedRow = ConvertFrom-UalRecord $fed 'Admin'
Assert-Equal $fedRow.Severity 'Critical' 'federation change is Critical'
Assert-Contains $fedRow.Category 'Federation' 'federation category'

$getish = New-FakeUal -RecordType 'ExchangeAdmin' -Audit ([pscustomobject]@{
        CreationTime = '2026-10-01T14:00:00'
        Operation    = 'Set-Mailbox'
        UserId       = 'admin@contoso.com'
        ResultStatus = 'Succeeded'
        Workload     = 'Exchange'
        Parameters   = @([pscustomobject]@{ Name = 'Identity'; Value = 'user@contoso.com' }, [pscustomobject]@{ Name = 'DisplayName'; Value = 'User' })
        ObjectId     = 'user@contoso.com'
        ExternalAccess = 'True'
    })
$sysRow = ConvertFrom-UalRecord $getish 'Admin'
Assert-Equal $sysRow.PowerShellRelated 'System' 'ExternalAccess without a user actor match is System'
# DisplayName-only Set-Mailbox is Account Manipulation (Medium) then System drops it to Low unless Critical
Assert-True ($sysRow.Severity -in @('Low', 'Info', 'Medium')) 'system cmdlets that are not Critical are de-escalated'

$fail = New-FakeUal -RecordType 'ExchangeAdmin' -Audit ([pscustomobject]@{
        CreationTime = '2026-10-01T15:00:00'
        Operation    = 'New-ManagementRoleAssignment'
        UserId       = 'attacker@contoso.com'
        ResultStatus = 'Failed'
        Workload     = 'Exchange'
        Parameters   = @([pscustomobject]@{ Name = 'Role'; Value = 'ApplicationImpersonation' }, [pscustomobject]@{ Name = 'User'; Value = 'attacker@contoso.com' })
    })
$failRow = ConvertFrom-UalRecord $fail 'Admin'
Assert-Contains $failRow.AccessGained 'ATTEMPTED (FAILED)' 'failed privilege grant is marked attempted'

Write-Host 'Sign-ins'
$si = ConvertFrom-UalSignIn (New-FakeUal -RecordType 'AzureActiveDirectoryStsLogon' -Audit ([pscustomobject]@{
            CreationTime = '2026-10-01T11:50:00'
            Operation    = 'UserLoggedIn'
            UserId       = 'attacker@contoso.com'
            ClientIP     = '203.0.113.50'
            ApplicationId = '1b730954-1685-4b74-9bfd-dac224a7b894'
            UserAgent    = 'WindowsPowerShell/5.1'
            ErrorNumber  = '0'
            ExtendedProperties = @(
                [pscustomobject]@{ Name = 'ResultStatusDetail'; Value = 'Success' },
                [pscustomobject]@{ Name = 'City'; Value = 'Ashburn' },
                [pscustomobject]@{ Name = 'CountryOrRegion'; Value = 'US' },
                [pscustomobject]@{ Name = 'OS'; Value = 'Windows 10' },
                [pscustomobject]@{ Name = 'Browser'; Value = 'Chrome 120' },
                [pscustomobject]@{ Name = 'DeviceId'; Value = 'dev-1' },
                [pscustomobject]@{ Name = 'SessionId'; Value = 'sess-ual-1' },
                [pscustomobject]@{ Name = 'RequestType'; Value = 'Login:login' }
            )
        }))
Assert-Equal $si.PowerShellApp 'Yes' 'MSOnline app id is a PowerShell sign-in'
Assert-Equal $si.Result 'Success' 'error 0 is success'
Assert-Contains $si.Location 'Ashburn' 'UAL sign-in city is kept'
Assert-Contains $si.SuspectMatch 'User' 'suspect user sign-in is tagged'
Assert-Equal $si.OperatingSystem 'Windows 10' 'UAL sign-in keeps OS from ExtendedProperties'
Assert-Equal $si.SessionId 'sess-ual-1' 'UAL sign-in keeps session id'
Assert-Contains $si.Story 'attacker@contoso.com' 'UAL sign-in story names the account'

$gsiRaw = [pscustomobject]@{
    createdDateTime = '2026-10-01T11:55:00Z'
    appId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
    appDisplayName = 'Microsoft Graph PowerShell'
    userPrincipalName = 'attacker@contoso.com'
    userDisplayName = 'Attacker'
    userId = '11111111-1111-1111-1111-111111111111'
    ipAddress = '203.0.113.50'
    userAgent = 'Mozilla/5.0 PowerShell/7.4'
    clientAppUsed = 'Mobile Apps and Desktop clients'
    status = [pscustomobject]@{ errorCode = 0; failureReason = ''; additionalDetails = 'MFA completed in Azure AD' }
    location = [pscustomobject]@{
        city = 'Ashburn'; state = 'VA'; countryOrRegion = 'US'
        geoCoordinates = [pscustomobject]@{ latitude = 39.04; longitude = -77.49 }
    }
    resourceDisplayName = 'Microsoft Graph'
    resourceId = '00000003-0000-0000-c000-000000000000'
    isInteractive = $true
    signInEventTypes = @('interactiveUser')
    authenticationRequirement = 'multiFactorAuthentication'
    authenticationMethodsUsed = @('Password', 'Mobile app notification')
    authenticationDetails = @(
        [pscustomobject]@{ authenticationMethod = 'Password'; authenticationMethodDetail = 'Password in the cloud'; authenticationStepRequirement = 'primary'; authenticationStepResultDetail = 'Correct password'; succeeded = $true }
        [pscustomobject]@{ authenticationMethod = 'Mobile app notification'; authenticationMethodDetail = 'Pixel 8'; authenticationStepRequirement = 'multifactor authentication'; authenticationStepResultDetail = 'MFA completed in Azure AD'; succeeded = $true }
    )
    authenticationAppDeviceDetails = [pscustomobject]@{
        clientApp = 'Microsoft Authenticator'; appVersion = '6.2401.0'; deviceId = 'auth-dev-1'; operatingSystem = 'Android 14'
    }
    authenticationAppPolicyEvaluationDetails = @(
        [pscustomobject]@{ policyName = 'Number matching'; adminConfiguration = 'enabled'; status = 'numberMatchCorrectNumberEntered'; authenticationEvaluation = 'success' }
    )
    authenticationProtocol = 'oAuth2'
    incomingTokenType = 'none'
    tokenIssuerType = 'AzureAD'
    clientCredentialType = 'none'
    conditionalAccessStatus = 'success'
    appliedConditionalAccessPolicies = @(
        [pscustomobject]@{ displayName = 'Require MFA for admins'; result = 'success'; enforcedGrantControls = @('Mfa'); enforcedSessionControls = @() }
        [pscustomobject]@{ displayName = 'Block legacy'; result = 'notApplied'; enforcedGrantControls = @(); enforcedSessionControls = @() }
    )
    riskLevelDuringSignIn = 'none'
    riskState = 'none'
    riskDetail = 'none'
    riskEventTypes_v2 = @()
    deviceDetail = [pscustomobject]@{
        deviceId = 'dev-graph-1'; displayName = 'ATTACKER-LAPTOP'; operatingSystem = 'Windows 11'
        browser = 'Edge 120'; isCompliant = $true; isManaged = $true; trustType = 'Hybrid Azure AD joined'
    }
    correlationId = 'corr-1'
    sessionId = 'sess-graph-1'
    uniqueTokenIdentifier = 'uti-1'
    originalRequestId = 'req-1'
    autonomousSystemNumber = '174'
    crossTenantAccessType = 'none'
    flaggedForReview = $false
    id = 'abc'
}
$gsi = ConvertFrom-GraphSignIn $gsiRaw 'SignIn'
Assert-Equal $gsi.PowerShellApp 'Yes' 'Graph PowerShell sign-in is Yes'
Assert-Contains $gsi.Location 'Ashburn' 'Graph location is joined'
Assert-Equal $gsi.DeviceName 'ATTACKER-LAPTOP' 'Graph sign-in keeps device name'
Assert-Contains $gsi.AuthMethods 'Password' 'Graph sign-in lists auth methods'
Assert-Contains $gsi.MfaChallenge 'number matching' 'Graph sign-in names the Authenticator number-match challenge'
Assert-Contains $gsi.AuthAppDevice 'Microsoft Authenticator' 'Graph sign-in keeps the Authenticator app/device'
Assert-Contains $gsi.AuthSteps 'Pixel 8' 'Graph sign-in keeps the Authenticator device name from the MFA step'
Assert-Contains $gsi.ConditionalAccessPolicies 'Require MFA for admins=success' 'Graph sign-in keeps applied CA policy'
Assert-Equal $gsi.SessionId 'sess-graph-1' 'Graph sign-in keeps session id'
Assert-Equal $gsi.ASN '174' 'Graph sign-in keeps ASN'
Assert-Contains $gsi.Story 'multiFactorAuthentication' 'sign-in story includes the auth requirement'

$failSi = ConvertFrom-GraphSignIn ([pscustomobject]@{
        createdDateTime = '2026-10-01T11:40:00Z'
        appId = '1b730954-1685-4b74-9bfd-dac224a7b894'
        appDisplayName = 'Azure Active Directory PowerShell'
        userPrincipalName = 'attacker@contoso.com'
        ipAddress = '203.0.113.50'
        userAgent = 'WindowsPowerShell/5.1'
        status = [pscustomobject]@{ errorCode = 50126; failureReason = 'Invalid username or password.'; additionalDetails = 'The user did not enter the right credentials.' }
        location = [pscustomobject]@{ city = 'Ashburn'; state = 'VA'; countryOrRegion = 'US' }
        resourceDisplayName = 'Windows Azure Active Directory'
        isInteractive = $true
        id = 'fail-si-1'
    }) 'SignIn'
Assert-Equal $failSi.Result 'Failure' 'non-zero Graph error is a failed sign-in'
Assert-Equal $failSi.PowerShellApp 'Yes' 'failed AAD PowerShell sign-in is still PowerShell'
Assert-Contains $failSi.Story 'Invalid username or password' 'failed sign-in story keeps the failure reason'

$smsSi = ConvertFrom-GraphSignIn ([pscustomobject]@{
        createdDateTime = '2026-10-01T11:56:00Z'
        appId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
        appDisplayName = 'Microsoft Graph PowerShell'
        userPrincipalName = 'attacker@contoso.com'
        ipAddress = '203.0.113.50'
        userAgent = 'Mozilla/5.0 PowerShell/7.4'
        status = [pscustomobject]@{ errorCode = 0; failureReason = ''; additionalDetails = '' }
        location = [pscustomobject]@{ city = 'Ashburn'; state = 'VA'; countryOrRegion = 'US' }
        resourceDisplayName = 'Microsoft Graph'
        isInteractive = $true
        authenticationRequirement = 'multiFactorAuthentication'
        authenticationDetails = @(
            [pscustomobject]@{ authenticationMethod = 'Password'; authenticationMethodDetail = 'Password in the cloud'; succeeded = $true }
            [pscustomobject]@{ authenticationMethod = 'Text message'; authenticationMethodDetail = '+1 XXXXXX5555'; authenticationStepRequirement = 'multifactor authentication'; authenticationStepResultDetail = 'MFA completed in Azure AD'; succeeded = $true }
        )
        mfaDetail = [pscustomobject]@{ authMethod = 'Text message'; authDetail = '+1 XXXXXX5555' }
        id = 'sms-si-1'
    }) 'SignIn'
Assert-Contains $smsSi.MfaPhone '+1 XXXXXX5555' 'SMS sign-in keeps the destination number'
Assert-Contains $smsSi.MfaChallenge 'SMS to +1 XXXXXX5555' 'SMS sign-in challenge names the phone number'
Assert-Contains $smsSi.AuthSteps '+1 XXXXXX5555' 'SMS auth steps include the destination number'

$fromSi = ConvertTo-EventFromSignIn $gsi
Assert-Equal $fromSi.RecordType 'SignIn' 'sign-in events keep RecordType SignIn'
Assert-Equal $fromSi.PowerShellRelated 'Yes' 'Graph PowerShell sign-in becomes a PowerShell-related event'
Assert-Equal $fromSi.Outcome 'Succeeded' 'successful sign-in maps to Succeeded'
Assert-Equal $fromSi.Actor 'attacker@contoso.com' 'sign-in user becomes the event actor'
Assert-Contains $fromSi.CommandLine 'Success sign-in' 'sign-in event command line is the story'
Assert-Contains $fromSi.Details 'ATTACKER-LAPTOP' 'sign-in event details include the device'
$fromFailSi = ConvertTo-EventFromSignIn $failSi
Assert-Equal $fromFailSi.Outcome 'Failed' 'failed PowerShell sign-in maps to a Failed event'
Assert-Equal $fromFailSi.Operation 'UserLoginFailed' 'failed sign-in operation is UserLoginFailed'
Assert-Equal $fromFailSi.Severity 'Medium' 'failed sign-in is Medium so it appears on Failed'

$ga = ConvertFrom-GraphDirectoryAudit ([pscustomobject]@{
        activityDateTime = '2026-10-01T12:10:00Z'
        activityDisplayName = 'Add member to role'
        result = 'success'
        category = 'RoleManagement'
        loggedByService = 'Core Directory'
        resultReason = ''
        initiatedBy = [pscustomobject]@{
            user = [pscustomobject]@{ userPrincipalName = 'attacker@contoso.com'; ipAddress = '203.0.113.50' }
            app = $null
        }
        additionalDetails = @([pscustomobject]@{ key = 'User-Agent'; value = 'Microsoft.Graph.PowerShell' })
        targetResources = @([pscustomobject]@{
                userPrincipalName = 'attacker@contoso.com'
                displayName = 'Attacker'
                modifiedProperties = @([pscustomobject]@{ displayName = 'Role.DisplayName'; oldValue = ''; newValue = 'Global Administrator' })
            })
        id = 'dir-1'
    })
Assert-Equal $ga.Severity 'Critical' 'Entra role add is Critical'
Assert-Equal $ga.PowerShellRelated 'Yes' 'Graph PowerShell UA marks the directory audit as PowerShell'
Assert-Equal $ga.ClientIP '203.0.113.50' 'directory audit keeps initiator IP'
Assert-Contains $ga.Details 'Global Administrator' 'modified properties are in details'

Write-Host 'JSON, report, cancel, and ReportOnly'
$json = ConvertTo-ReportJson @{ Name = 'A <b> tag'; Items = @(@{ A = 1 }) }
Assert-NotContains $json '<' 'report JSON does not contain raw less-than'
Assert-Contains $json '\u003c' 'less-than is escaped for script safety'
$one = ConvertTo-ReportJson @(@{ X = 'only' })
Assert-True ($one.TrimStart().StartsWith('[')) 'single-element arrays stay arrays'

$out = Join-Path ([System.IO.Path]::GetTempPath()) ('m365ps-' + [guid]::NewGuid().ToString('n'))
Initialize-M365PsForensicsOutput -OutputPath $out | Out-Null
Initialize-SuspectSets -Users @('attacker@contoso.com') -IPs @('203.0.113.50')
Initialize-InvestigationWindow -StartDate ([datetime]'2026-09-01') -EndDate ([datetime]'2026-10-02')
Save-Rows -Rows @($row, $fedRow, $failRow, $ga) -FileName 'Events-UAL-Admin.csv'
Save-Rows -Rows @($si, $gsi, $failSi, $smsSi) -FileName 'SignIns-Entra.csv'
$rawDir = Join-Path $out 'raw'
if (-not (Test-Path -LiteralPath $rawDir)) { New-Item -ItemType Directory -Path $rawDir -Force | Out-Null }
$gsiRaw | ConvertTo-Json -Depth 8 -Compress | Set-Content -LiteralPath (Join-Path $rawDir 'Graph-SignIns.jsonl') -Encoding utf8
Add-Coverage -Source 'Tenant (Graph)' -Status 'INFO' -Notes 'TenantId=11111111-1111-1111-1111-111111111111; Investigator=ir@contoso.com'
Add-Coverage -Source 'Unified Audit Log - ExchangeAdmin (Admin)' -Status 'OK' -Records 3 -From ([datetime]'2026-09-01') -To ([datetime]'2026-10-02')
$report = New-InvestigationReport
Assert-True (Test-Path -LiteralPath $report) 'HTML report is written'
Assert-True (Test-Path -LiteralPath (Join-Path $out 'Timeline-Master.csv')) 'master timeline is written'
$html = [System.IO.File]::ReadAllText($report)
Assert-Contains $html 'id="report-data"' 'report embeds JSON data'
Assert-Contains $html 'Set-Mailbox' 'report includes the reconstructed command'
Assert-NotContains $html '<img src=x' 'report does not emit a raw image tag'
Assert-Contains $html 'function(' 'report includes the interactive script'
Assert-Contains $html 'PowerShell related' 'report has a PowerShell filter chip'
Assert-True ($html.IndexOf('alreadyScoped') -ge 0) 'report detects suspect-user collection scope in JS'
Assert-True ($html.IndexOf('function matchSignIn') -ge 0) 'report filters sign-ins separately from cmdlet events'
Assert-True ($html.IndexOf('S.ps="yes";') -lt 0) 'report does not force PowerShell-related after load'
Assert-Contains $html 'Suspect users' 'report records suspect-user collection scope'
Assert-Contains $html 'Eastern Time' 'report header states Eastern Time'
Assert-NotContains $html 'All times are UTC' 'report no longer claims all times are UTC'
Assert-Contains $html '2026-10-01 08:00:00 -04:00' 'report embeds Eastern event timestamps'
Assert-Contains $html 'id="tFrom"' 'report has an Eastern From time filter'
Assert-Contains $html 'id="failOnly"' 'report has a failed-sign-in chip'
Assert-Contains $html 'Focus timeline' 'report can focus the timeline around a sign-in'
Assert-Contains $html 'id="tbl-sisummary"' 'report rolls up sign-ins by account and client'
Assert-Contains $html 'function inTime' 'report applies a shared time-window filter'
Assert-Contains $html 'Sign-in detail' 'report has a dedicated sign-in detail drawer'
Assert-Contains $html 'Show these sign-ins' 'report can pivot from a client rollup to the matching log'
Assert-Contains $html 'ATTACKER-LAPTOP' 'report embeds the Graph device name'
Assert-Contains $html 'Require MFA for admins=success' 'report embeds applied Conditional Access'
Assert-Contains $html 'sess-graph-1' 'report embeds the sign-in session id'
Assert-Contains $html 'Auth methods' 'report labels authentication methods in the drawer'
Assert-Contains $html 'MFA phone' 'report labels the SMS/voice destination number'
Assert-Contains $html 'MFA challenge' 'report labels the Authenticator challenge type'
Assert-Contains $html 'number matching' 'report embeds Authenticator number matching'
Assert-Contains $html '+1 XXXXXX5555' 'report embeds the SMS destination number'
Assert-Contains $html 'Pixel 8' 'report embeds the Authenticator device name'
$tl = @(Import-Csv -LiteralPath (Join-Path $out 'Timeline-Master.csv'))
$siEvents = @($tl | Where-Object { $_.RecordType -eq 'SignIn' })
Assert-True ($siEvents.Count -ge 3) 'PowerShell sign-ins are copied onto the command timeline'
Assert-True (@($siEvents | Where-Object { $_.Outcome -eq 'Failed' }).Count -ge 1) 'failed PowerShell sign-ins appear as Failed events'
Assert-Contains $html '"PsFail":1' 'report counts the failed PowerShell sign-in'
$cov = @(Import-Csv -LiteralPath (Join-Path $out 'Coverage.csv'))
Assert-Equal $cov.Count 2 'coverage has two data rows, not a repeated header'
Assert-Equal @($cov | Where-Object { $_.Source -like 'RunUtc*' }).Count 0 'coverage did not treat a header as a row'

Write-EvidenceManifest
$man = @(Import-Csv -LiteralPath (Join-Path $out 'Evidence-Manifest.csv'))
Assert-True ($man.Count -ge 3) 'manifest hashes evidence files'
Assert-True ($man[0].SHA256 -match '^[0-9A-F]{64}$') 'manifest SHA-256 is 64 hex chars'

$log1 = 'hello from log'
Write-Log 'INFO' $log1
$logBytes = [System.IO.File]::ReadAllBytes((Join-Path $out 'Collection-Log.txt'))
$bomAt = @()
for ($i = 1; $i -lt $logBytes.Length - 2; $i++) {
    if ($logBytes[$i] -eq 0xEF -and $logBytes[$i + 1] -eq 0xBB -and $logBytes[$i + 2] -eq 0xBF) { $bomAt += $i }
}
Assert-Equal $bomAt.Count 0 'log appends do not insert a UTF-8 BOM after the first byte'

Assert-Throws { Initialize-M365PsForensicsOutput -OutputPath (Join-Path $out 'missing') -ReportOnly } 'ReportOnly missing folder throws'
$empty = Join-Path $out 'empty'
New-Item -ItemType Directory -Path $empty -Force | Out-Null
Assert-Throws { Initialize-M365PsForensicsOutput -OutputPath $empty -ReportOnly } 'ReportOnly empty folder throws'

$result = Invoke-M365PowerShellForensics -ReportOnly -OutputPath $out -StartDate ([datetime]'2026-09-01') -EndDate ([datetime]'2026-10-02') -SuspectUsers 'attacker@contoso.com' -SuspectIPs '203.0.113.50'
Assert-Equal $result.ExitCode 0 'ReportOnly rebuild succeeds'
Assert-True (Test-Path -LiteralPath $result.ReportPath) 'ReportOnly writes a report'

Set-M365PsForensicsUiBridge -Sync ([hashtable]::Synchronized(@{ Cancel = $true; Queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]' }))
$cancelled = Invoke-M365PowerShellForensics -ReportOnly -OutputPath $out -StartDate ([datetime]'2026-09-01') -EndDate ([datetime]'2026-10-02')
Assert-Equal $cancelled.ExitCode 2 'a cancel flag stops the run'
Set-M365PsForensicsUiBridge -Sync $null

Assert-Throws { Initialize-InvestigationWindow -StartDate (Get-Date) -EndDate (Get-Date).AddDays(-1) } 'reversed dates throw'

$guiPath = Join-Path $PSScriptRoot '..\M365PowerShellForensics-GUI.ps1'
$cliPath = Join-Path $PSScriptRoot '..\Invoke-M365PowerShellForensics.ps1'
$guiErrors = $null
$cliErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($guiPath, [ref]$null, [ref]$guiErrors)
$null = [System.Management.Automation.Language.Parser]::ParseFile($cliPath, [ref]$null, [ref]$cliErrors)
Assert-Equal @($guiErrors).Count 0 'GUI script parses'
Assert-Equal @($cliErrors).Count 0 'CLI wrapper parses'
$modErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$null, [ref]$modErrors)
Assert-Equal @($modErrors).Count 0 'engine module parses'

Assert-Equal (Get-M365PsForensicsVersion) '2.1.9' 'engine version is 2.1.9'
Assert-True (Test-Path -LiteralPath (Join-Path $out 'SignIns-Master.csv')) 'detailed sign-in master CSV is written'
$siMaster = @(Import-Csv -LiteralPath (Join-Path $out 'SignIns-Master.csv'))
Assert-True (@($siMaster | Where-Object { $_.DeviceName -eq 'ATTACKER-LAPTOP' }).Count -ge 1) 'sign-in master CSV keeps device name'

Write-Host 'Exchange cmdlet status and Graph UAL shaping'
$exoStatus = Get-ExoCmdletStatus
Assert-True ($null -ne $exoStatus.GetMailbox) 'EXO cmdlet status reports Get-Mailbox'
Assert-True ($null -ne $exoStatus.SearchUnifiedAuditLog) 'EXO cmdlet status reports Search-UnifiedAuditLog'
Assert-Equal (Get-GraphAuditRecordTypeName 'ExchangeAdmin') 'exchangeAdmin' 'UAL ExchangeAdmin maps to Graph exchangeAdmin'
Assert-Equal (Get-GraphAuditRecordTypeName 'AzureActiveDirectoryStsLogon') 'azureActiveDirectoryStsLogon' 'STS logon record type is camel-cased'
$shaped = ConvertTo-UalShapedRecord ([pscustomobject]@{
        id                 = 'rec-1'
        createdDateTime    = '2026-11-16T12:00:00Z'
        auditLogRecordType = 'ExchangeAdmin'
        operation          = 'Set-Mailbox'
        userPrincipalName  = 'attacker@contoso.com'
        objectId           = 'victim@contoso.com'
        auditData          = [pscustomobject]@{
            CreationTime = '2026-11-16T12:00:00'
            Operation    = 'Set-Mailbox'
            UserId       = 'attacker@contoso.com'
            ResultStatus = 'Succeeded'
            Workload     = 'Exchange'
            Parameters   = @([pscustomobject]@{ Name = 'Identity'; Value = 'victim@contoso.com' })
        }
    })
Assert-Equal $shaped.Identity 'rec-1' 'Graph audit record keeps id as Identity'
Assert-Equal $shaped.UserIds 'attacker@contoso.com' 'Graph audit record keeps UPN'
$fromGraph = ConvertFrom-UalRecord $shaped 'Admin'
Assert-Equal $fromGraph.Actor 'attacker@contoso.com' 'Graph-shaped UAL record converts the actor'
Assert-Contains $fromGraph.CommandLine 'Set-Mailbox' 'Graph-shaped UAL record reconstructs the cmdlet'
$connState = Get-M365PsForensicsConnectionState
Assert-True ($connState.PSObject.Properties.Name -contains 'ExchangeCmdletsLoaded') 'connection state reports whether EXO cmdlets are loaded'
Assert-True ($connState.PSObject.Properties.Name -contains 'UnifiedAuditLogLoaded') 'connection state reports whether Search-UnifiedAuditLog is loaded'

Write-Host 'Suspect-user collection scope'
Initialize-SuspectSets -Users @('attacker@contoso.com') -IPs @()
Set-M365PsForensicsConfig -Values @{ TenantWide = $false; SuspectUsers = @('attacker@contoso.com') }
Assert-True (Test-SuspectScoped) 'suspect users without TenantWide scopes collection'
$scopedIds = Get-ScopedUserIds
Assert-Equal $scopedIds.Count 1 'scoped user list has the suspect'
Assert-Equal ([string]$scopedIds[0]) 'attacker@contoso.com' 'scoped user is the suspect UPN'
$gFilter = Get-GraphSuspectUserFilter -Field 'userPrincipalName'
Assert-Contains $gFilter "userPrincipalName eq 'attacker@contoso.com'" 'Graph sign-in filter uses the suspect UPN'
$dirFilter = Get-GraphSuspectUserFilter -Field 'initiatedBy/user/userPrincipalName'
Assert-Contains $dirFilter "initiatedBy/user/userPrincipalName eq 'attacker@contoso.com'" 'directory audit filter uses initiatedBy UPN'
Set-M365PsForensicsConfig -Values @{ TenantWide = $false; SuspectUsers = @("o'brien@contoso.com") }
Initialize-SuspectSets -Users @("o'brien@contoso.com") -IPs @()
Assert-Contains (Get-GraphSuspectUserFilter) "userPrincipalName eq 'o''brien@contoso.com'" 'OData filter escapes a quote in the UPN'
Set-M365PsForensicsConfig -Values @{ TenantWide = $true; SuspectUsers = @('attacker@contoso.com') }
Initialize-SuspectSets -Users @('attacker@contoso.com') -IPs @()
Assert-True (-not (Test-SuspectScoped)) 'TenantWide keeps collection tenant-wide'
$none = Get-ScopedUserIds
Assert-Equal $none.Count 0 'TenantWide returns no UAL UserIds filter'
Set-M365PsForensicsConfig -Values @{ TenantWide = $false; SuspectUsers = @() }
Initialize-SuspectSets -Users @() -IPs @()
Assert-True (-not (Test-SuspectScoped)) 'no suspects means tenant-wide collection'
Initialize-SuspectSets -Users @('attacker@contoso.com') -IPs @()
Set-M365PsForensicsConfig -Values @{ TenantWide = $false; SuspectUsers = @('attacker@contoso.com') }
$inScope = [pscustomobject]@{ Actor = 'attacker@contoso.com'; Target = 'victim@contoso.com'; SuspectMatch = 'Actor'; CommandLine = 'Set-Mailbox' }
$outScope = [pscustomobject]@{ Actor = 'other@contoso.com'; Target = 'helpdesk@contoso.com'; SuspectMatch = ''; CommandLine = 'Get-Mailbox' }
$targetScope = [pscustomobject]@{ Actor = 'other@contoso.com'; Target = 'attacker@contoso.com'; SuspectMatch = 'Target/Params'; CommandLine = 'Set-Mailbox' }
Assert-True (Test-RowInSuspectScope $inScope) 'actor match is in suspect scope'
Assert-True (Test-RowInSuspectScope $targetScope) 'target match is in suspect scope'
Assert-True (-not (Test-RowInSuspectScope $outScope)) 'unrelated actor/target is out of suspect scope'
Set-M365PsForensicsConfig -Values @{ TenantWide = $true }
Assert-True (Test-RowInSuspectScope $outScope) 'tenant-wide keeps unrelated rows'

Write-Host 'Add-Finding severity when collection is suspect-scoped'
$engine = Get-Module M365PowerShellForensics
& $engine { $script:Findings.Clear() }
Initialize-SuspectSets -Users @('attacker@contoso.com') -IPs @()
Set-M365PsForensicsConfig -Values @{ TenantWide = $false; SuspectUsers = @('attacker@contoso.com') }
Add-Finding 'Info' 'Entra Directory Role / Group' 'attacker@contoso.com: Users' 'MemberType=group' 'Directory role or group membership' $null 'test'
$got = & $engine { $script:Findings[0] }
Assert-Equal $got.Severity 'Info' 'suspect-scoped collection does not promote every mention to High'
Assert-Equal $got.SuspectMatch 'User' 'finding still records the suspect user match'
& $engine { $script:Findings.Clear() }
Set-M365PsForensicsConfig -Values @{ TenantWide = $true; SuspectUsers = @('attacker@contoso.com') }
Add-Finding 'Info' 'Entra Directory Role / Group' 'attacker@contoso.com: Users' 'MemberType=group' 'Directory role or group membership' $null 'test'
$got = & $engine { $script:Findings[0] }
Assert-Equal $got.Severity 'High' 'tenant-wide hunt still promotes suspect mentions to High'
& $engine { $script:Findings.Clear() }
Initialize-SuspectSets -Users @() -IPs @('203.0.113.50')
Set-M365PsForensicsConfig -Values @{ TenantWide = $false; SuspectUsers = @('attacker@contoso.com') }
Add-Finding 'Info' 'Mailbox' 'forwarding to 203.0.113.50' 'Smtp=evil' 'Suspicious IP on mailbox' $null 'test'
$got = & $engine { $script:Findings[0] }
Assert-Equal $got.Severity 'High' 'suspect IP still promotes a finding to High when scoped'

Set-M365PsForensicsConfig -Values @{ Fast = $true; IncludeDiscovery = $false; AdditionalRecordTypes = @(); ChunkHours = 24 }
$adminTypes = Get-UalAdminRecordTypes
Assert-True ($adminTypes -contains 'ExchangeAdmin') 'fast mode still collects ExchangeAdmin cmdlets'
Assert-True ($adminTypes -contains 'SecurityComplianceCenterEOPCmdlet') 'fast mode still collects Purview cmdlets'
Assert-True ($adminTypes -notcontains 'Discovery') 'fast mode skips Discovery UAL'
Assert-Equal (Get-AdminUalChunkHours) 168 'fast mode uses 7-day UAL slices'
Set-M365PsForensicsConfig -Values @{ Fast = $false; IncludeDiscovery = $true; ChunkHours = 24 }
Assert-True ((Get-UalAdminRecordTypes) -contains 'Discovery') 'full mode can include Discovery'
Assert-Equal (Get-AdminUalChunkHours) 72 'full mode uses at least 72-hour UAL slices'
Set-M365PsForensicsConfig -Values @{ Fast = $true; IncludeDiscovery = $false; ChunkHours = 24 }

$liveQ = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
Set-M365PsForensicsUiBridge -Sync ([hashtable]::Synchronized(@{ Cancel = $false; Queue = $liveQ }))
Reset-InvestigationActivity
Set-InvestigationActivity -Phase 'Unified Audit Log' -Step 'ExchangeAdmin' -WaitingOn 'Search-UnifiedAuditLog page 1' -EventsDelta 12 -Percent 10
$liveItem = $null
Assert-True ($liveQ.TryDequeue([ref]$liveItem)) 'activity heartbeat is published to the UI queue'
Assert-Equal $liveItem.Type 'Activity' 'heartbeat type is Activity'
Assert-Equal $liveItem.Snapshot.Phase 'Unified Audit Log' 'heartbeat phase is set'
Assert-Equal $liveItem.Snapshot.Events 12 'heartbeat event count increments'
Assert-Equal $liveItem.Snapshot.WaitingOn 'Search-UnifiedAuditLog page 1' 'heartbeat waiting-on is set'
Assert-Contains (Get-ActivityStatusLine) 'waiting: Search-UnifiedAuditLog page 1' 'status line includes the in-flight call'
Add-Coverage -Source 'Unified Audit Log - ExchangeAdmin (Admin)' -Status 'OK' -Records 12
$covItem = $null
$sawCoverage = $false
while ($liveQ.TryDequeue([ref]$covItem)) {
    if ($covItem.Type -eq 'Coverage') { $sawCoverage = $true; break }
}
Assert-True $sawCoverage 'coverage rows are published live to the UI queue'
Set-M365PsForensicsUiBridge -Sync $null
$pre = Get-M365PsForensicsPrerequisite
Assert-True ($pre.PowerShell.Length -gt 0) 'prerequisite reports a PowerShell version'

Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:Passed, $script:Failed)
if ($script:Failed -gt 0) { exit 1 }
exit 0

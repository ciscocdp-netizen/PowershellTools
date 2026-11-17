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
                [pscustomobject]@{ Name = 'CountryOrRegion'; Value = 'US' }
            )
        }))
Assert-Equal $si.PowerShellApp 'Yes' 'MSOnline app id is a PowerShell sign-in'
Assert-Equal $si.Result 'Success' 'error 0 is success'
Assert-Contains $si.Location 'Ashburn' 'UAL sign-in city is kept'
Assert-Contains $si.SuspectMatch 'User' 'suspect user sign-in is tagged'

$gsi = ConvertFrom-GraphSignIn ([pscustomobject]@{
        createdDateTime = '2026-10-01T11:55:00Z'
        appId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
        appDisplayName = 'Microsoft Graph PowerShell'
        userPrincipalName = 'attacker@contoso.com'
        ipAddress = '203.0.113.50'
        userAgent = 'Mozilla/5.0 PowerShell/7.4'
        status = [pscustomobject]@{ errorCode = 0; failureReason = '' }
        location = [pscustomobject]@{ city = 'Ashburn'; state = 'VA'; countryOrRegion = 'US' }
        resourceDisplayName = 'Microsoft Graph'
        isInteractive = $true
        id = 'abc'
    }) 'SignIn'
Assert-Equal $gsi.PowerShellApp 'Yes' 'Graph PowerShell sign-in is Yes'
Assert-Contains $gsi.Location 'Ashburn' 'Graph location is joined'

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
Save-Rows -Rows @($si, $gsi) -FileName 'SignIns-Entra.csv'
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

Assert-Equal (Get-M365PsForensicsVersion) '2.1.0' 'engine version is 2.1.0'
$pre = Get-M365PsForensicsPrerequisite
Assert-True ($pre.PowerShell.Length -gt 0) 'prerequisite reports a PowerShell version'

Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:Passed, $script:Failed)
if ($script:Failed -gt 0) { exit 1 }
exit 0

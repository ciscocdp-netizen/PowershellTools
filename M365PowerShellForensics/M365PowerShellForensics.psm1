#Requires -Version 5.1
<#
.SYNOPSIS
    Engine for Microsoft 365 PowerShell / admin-command breach investigation.

.DESCRIPTION
    READ-ONLY. Makes no changes to the tenant.

    Import this module and call Invoke-M365PowerShellForensics, or use the
    command-line wrapper / WinForms GUI in this folder. The module does not
    exit the host, so a GUI can run a collection and keep sessions open.

    Reconstructs PowerShell and administrative commands executed across
    Exchange Online, Purview, Entra ID, SharePoint, Teams and related clients,
    then builds a fully interactive Investigation-Report.html plus CSV/JSONL
    evidence files.

.NOTES
    Version 2.1.0 fixes, relative to the 2.0.0 script:
      - Coverage.csv no longer repeats a header on every source (Windows PowerShell
        5.1 Export-Csv -Append writes a header each time).
      - Collection-Log.txt is UTF-8 without a BOM on every append.
      - CSV formula injection also prefixes values that start with '-'.
      - -ReportOnly into a missing/empty folder no longer creates a blank case.
      - Desktop-less hosts fall back to Documents / the current directory.
      - Unified Audit Log AzureActiveDirectory is collected for the full window so
        a Graph failure does not silently drop the last 30 days of Entra changes.
      - UAL paging, Graph, and retry sleeps honour GUI cancel.
      - StreamWriter cleanup is null-safe.
      - Investigation-Report.html is a self-contained interactive analyst workbench
        (search, filters, sort, pagination, click-to-pivot, command copy, dark mode).
      - Config, output path, and chunk size are script-scoped so the GUI/module
        host can run the engine more than once.
#>

$script:ScriptVersion = '2.1.0'
$script:Inv = [Globalization.CultureInfo]::InvariantCulture
$script:UiSync = $null
$script:LogFile = $null
$script:CoverageFile = $null
$script:CoverageRows = New-Object System.Collections.Generic.List[object]
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:OutputPath = $null
$script:RawPath = $null
$script:OpenedExo = $false
$script:OpenedGraph = $false
$script:SuspectUserSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$script:SuspectIpSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

$script:SevRank = @{ 'Critical' = 4; 'High' = 3; 'Medium' = 2; 'Low' = 1; 'Info' = 0; '' = 0 }

$script:PowerShellApps = @{
    '1b730954-1685-4b74-9bfd-dac224a7b894' = 'Azure AD PowerShell (MSOnline / AzureAD / AADInternals)'
    '14d82eec-204b-4c2f-b7e8-296a70dab67e' = 'Microsoft Graph PowerShell / Graph CLI'
    'fb78d390-0c51-40cd-8e17-fdbfab77341b' = 'Exchange Online / S&C PowerShell (EXO V3 REST)'
    'a0c73c16-a7e3-4564-9a95-2bdf47383716' = 'Exchange Online Remote PowerShell (legacy RPS)'
    '1950a258-227b-4e31-a9cf-717495945fc2' = 'Microsoft Azure PowerShell (Az)'
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Microsoft Azure CLI'
    '9bc3ab49-b65d-410a-85ad-de819febfddc' = 'SharePoint Online Management Shell'
    '31359c7f-bd7e-475c-86db-fdb8c937548e' = 'PnP Management Shell'
    '12128f48-ec9e-42f0-b203-ea49fb6af367' = 'Microsoft Teams PowerShell'
    'd1ddf0e4-d672-4dae-b554-9d5bdfd93547' = 'Microsoft Intune PowerShell'
}
$script:AbuseProneApps = @{
    'd3590ed6-52b3-4102-aeff-aad2292ab01c' = 'Microsoft Office (FOCI - common token-abuse client)'
    '29d9ed98-a469-4536-ade2-f981bc1d605e' = 'Microsoft Authentication Broker (device-code / PRT abuse)'
    '1fec8e78-bce4-4aaf-ab1b-5451cc387264' = 'Microsoft Teams (FOCI)'
    '00b41c95-dab0-4487-9791-b9d2c32c80f2' = 'Office 365 Management'
}
$script:MicrosoftTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'

$script:EventColumns = @('TimeUtc', 'Severity', 'Category', 'Operation', 'Outcome', 'Actor', 'ClientIP', 'InferredIP',
    'InferredLocation', 'Target', 'TargetIdentity', 'CommandLine', 'Details', 'AccessGained', 'Mitre', 'PowerShellRelated',
    'ExecutionChannel', 'AppId', 'UserAgent', 'SuspectMatch', 'Workload', 'RecordType', 'Source', 'RecordId')
$script:SignInColumns = @('TimeUtc', 'User', 'Result', 'ErrorCode', 'FailureReason', 'AppName', 'AppId', 'PowerShellApp',
    'IPAddress', 'Location', 'Resource', 'UserAgent', 'ClientTool', 'ClientAppUsed', 'SignInType', 'ConditionalAccess',
    'Risk', 'AuthRequirement', 'SuspectMatch', 'Source', 'Id')
$script:FindingColumns = @('Severity', 'Area', 'Item', 'Detail', 'Reason', 'WhenUtc', 'SuspectMatch', 'Source')

$script:Config = @{
    StartDate = (Get-Date).AddDays(-90)
    EndDate = (Get-Date)
    SuspectUsers = @()
    SuspectIPs = @()
    OutputPath = ''
    AdminUPN = ''
    TenantId = ''
    ChunkHours = 24
    AdditionalRecordTypes = @()
    MaxSignInsPerQuery = 50000
    MaxDirectoryAuditRecords = 250000
    CorrelationWindowHours = 12
    MaxMailboxesToInspect = 200
    IncludeServicePrincipalSignIns = $false
    SkipSuspectDataAccess = $false
    SkipExchange = $false
    SkipGraph = $false
    SkipCurrentState = $false
    ReportOnly = $false
    InstallModules = $false
    NoDisconnect = $false
    OpenReport = $false
    MaxReportEvents = 12000
}

#region Config / UI bridge
function Set-M365PsForensicsUiBridge {
    param($Sync)
    $script:UiSync = $Sync
}

function Set-M365PsForensicsConfig {
    param([hashtable]$Values)
    if (-not $Values) { return }
    foreach ($k in @($Values.Keys)) {
        if ($k -eq 'UiSync') { $script:UiSync = $Values[$k] }
        elseif ($k -eq 'LogFile') { $script:LogFile = $Values[$k] }
        else { $script:Config[$k] = $Values[$k] }
    }
}

function Get-M365PsForensicsVersion { return $script:ScriptVersion }

function Get-M365PsForensicsPrerequisite {
    $exo = Get-Module -ListAvailable -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    $graph = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    [pscustomobject]@{
        PowerShell        = $PSVersionTable.PSVersion.ToString()
        ScriptVersion     = $script:ScriptVersion
        ExchangeInstalled = [bool]$exo
        ExchangeVersion   = if ($exo) { $exo.Version.ToString() } else { $null }
        GraphInstalled    = [bool]$graph
        GraphVersion      = if ($graph) { $graph.Version.ToString() } else { $null }
    }
}

function Get-M365PsForensicsConnectionState {
    $exo = $null
    try {
        if (Get-Command -Name Get-ConnectionInformation -ErrorAction SilentlyContinue) {
            $exo = @(Get-ConnectionInformation -ErrorAction Stop) |
                Where-Object { $_.State -eq 'Connected' } |
                Select-Object -First 1
        }
    } catch { $exo = $null }
    $graph = $null
    try {
        if (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) {
            $graph = Get-MgContext -ErrorAction SilentlyContinue
        }
    } catch { $graph = $null }
    [pscustomobject]@{
        ExchangeConnected = [bool]$exo
        ExchangeUser      = if ($exo) { [string](Get-FirstValue $exo @('UserPrincipalName', 'UserName')) } else { '' }
        GraphConnected    = [bool]$graph
        GraphUser         = if ($graph) { [string]$graph.Account } else { '' }
        TenantId          = if ($graph) { [string]$graph.TenantId } elseif ($exo) { [string](Get-FirstValue $exo @('TenantID', 'TenantId')) } else { '' }
        Connected         = [bool]$exo -or [bool]$graph
    }
}

function Publish-UiEvent {
    param(
        [string]$Type = 'Log',
        [string]$Message = '',
        [string]$Level = 'INFO',
        [int]$Percent = -1,
        [string]$Activity = ''
    )
    $sync = $script:UiSync
    if (-not $sync -or -not $sync.Queue) { return }
    if ($Message -and $Message.Length -gt 4000) { $Message = $Message.Substring(0, 4000) + '...' }
    $entry = [pscustomobject]@{
        Type = $Type; Message = $Message; Level = $Level; Percent = $Percent
        Activity = $Activity; Time = (Get-Date)
    }
    try { $sync.Queue.Enqueue($entry) } catch { }
}

function Write-Log {
    param([string]$Level = 'INFO', [string]$Message)
    $line = '{0} [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $script:Inv), $Level, $Message
    $color = switch ($Level) { 'ERROR' { 'Red' } 'WARN' { 'Yellow' } 'OK' { 'Green' } default { 'Gray' } }
    try { Write-Host $line -ForegroundColor $color } catch { }
    if ($script:LogFile) {
        try {
            $utf8 = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::AppendAllText($script:LogFile, ($line + [Environment]::NewLine), $utf8)
        } catch { }
    }
    Publish-UiEvent -Type 'Log' -Message $line -Level $Level
}

function Write-InvestigationProgress {
    param([string]$Activity, [string]$Status, [int]$Percent = -1)
    $pct = $Percent
    if ($pct -lt 0) { $pct = 0 }
    if ($pct -gt 100) { $pct = 100 }
    try { Write-Progress -Activity $Activity -Status $Status -PercentComplete $pct } catch { }
    Publish-UiEvent -Type 'Progress' -Activity $Activity -Message $Status -Percent $pct
}

function Test-InvestigationCancel {
    if ($script:UiSync -and $script:UiSync.Cancel) {
        throw (New-Object System.OperationCanceledException 'Investigation cancelled.')
    }
}

function Test-IsCancelError {
    param($ErrorRecord)
    if ($script:UiSync -and $script:UiSync.Cancel) { return $true }
    $ex = $null
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ex = $ErrorRecord.Exception }
    elseif ($ErrorRecord -is [System.Exception]) { $ex = $ErrorRecord }
    while ($ex) {
        if ($ex -is [System.OperationCanceledException]) { return $true }
        if ($ex -is [System.Management.Automation.PipelineStoppedException]) { return $true }
        $ex = $ex.InnerException
    }
    return $false
}

function Start-SleepInterruptible {
    param([int]$Seconds)
    $left = [math]::Max(0, $Seconds)
    while ($left -gt 0) {
        Test-InvestigationCancel
        $step = [math]::Min(2, $left)
        Start-Sleep -Seconds $step
        $left -= $step
    }
}
#endregion

#region Helpers
function ConvertTo-UtcIso {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return '' }
    $d = [datetime]::MinValue
    if ($Value -is [datetime]) {
        $d = $Value
        if ($d.Kind -eq [DateTimeKind]::Local) { $d = $d.ToUniversalTime() }
        elseif ($d.Kind -eq [DateTimeKind]::Unspecified) { $d = [datetime]::SpecifyKind($d, [DateTimeKind]::Utc) }
    }
    else {
        $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        if (-not [datetime]::TryParse([string]$Value, $script:Inv, $styles, [ref]$d)) { return [string]$Value }
    }
    return $d.ToString('yyyy-MM-ddTHH:mm:ssZ', $script:Inv)
}

function ConvertFrom-UtcIso {
    param([string]$Value)
    $d = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse($Value, $script:Inv, $styles, [ref]$d)) { return $d }
    return $null
}

function Get-FirstValue {
    param($Object, [string[]]$Names)
    if ($null -eq $Object) { return $null }
    foreach ($n in $Names) {
        $p = $Object.PSObject.Properties[$n]
        if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne '') { return $p.Value }
    }
    return $null
}

function Limit-Text {
    param($Text, [int]$Max = 500)
    $s = [string]$Text
    if ($s.Length -gt $Max) { return $s.Substring(0, $Max) + '...' }
    return $s
}

function Protect-CsvValue {
    param([string]$Value)
    if ($Value -and $Value -match '^[=+\-@\t\r]') { return "'" + $Value }
    return $Value
}

function Format-Ip {
    param([string]$Ip)
    if (-not $Ip) { return '' }
    $Ip = $Ip.Trim()
    if ($Ip -match '^\[(.+)\](:\d+)?$') { return $matches[1].ToLowerInvariant() }
    if ($Ip -match '^(\d{1,3}(\.\d{1,3}){3}):\d+$') { return $matches[1] }
    return $Ip.ToLowerInvariant()
}

function Get-Outcome {
    param($Value)
    $s = [string]$Value
    if ($s -match '^(True|Succeeded|Success|0)$') { return 'Succeeded' }
    if ($s -match 'False|Fail|Error|Denied|Partial|Interrupt') { return 'Failed' }
    if ($s) { return $s }
    return 'Unknown'
}

function Get-AppName {
    param([string]$AppId)
    if (-not $AppId) { return '' }
    $k = $AppId.ToLowerInvariant()
    if ($script:PowerShellApps.ContainsKey($k)) { return $script:PowerShellApps[$k] }
    if ($script:AbuseProneApps.ContainsKey($k)) { return $script:AbuseProneApps[$k] }
    return ''
}

function Get-ClientFromUserAgent {
    param([string]$UserAgent)
    if (-not $UserAgent) { return '' }
    if ($UserAgent -match 'WindowsPowerShell|PowerShell|PSVersion|Invoke-MgGraphRequest|Microsoft\.Graph\.PowerShell') { return 'PowerShell' }
    if ($UserAgent -match 'AADInternals|ROADtools|roadrecon|roadtx|TokenTactics|GraphRunner|MicroBurst|MFASweep|o365spray|python-requests|python/|aiohttp|httpx|curl/|Wget|Go-http-client|axios|okhttp|PostmanRuntime|node-fetch|libwww|Java/') { return 'Script / attack tooling' }
    return ''
}

function Get-ExecutionChannel {
    param([string]$AppId, [string]$UserAgent, [string]$RecordType, $ExternalAccess, [string]$ClientApplication, [string]$Actor)
    $id = ''
    if ($AppId) { $id = $AppId.ToLowerInvariant() }
    if ($id -and $script:PowerShellApps.ContainsKey($id)) { return @('Yes', ('PowerShell client: ' + $script:PowerShellApps[$id])) }
    $uaKind = Get-ClientFromUserAgent $UserAgent
    if ($uaKind -eq 'PowerShell') { return @('Yes', 'PowerShell (user agent)') }
    if ($uaKind) { return @('Yes', ($uaKind + ' (user agent)')) }
    if ($ClientApplication -match 'PowerShell|RemotePowerShell|EXO') { return @('Yes', ('PowerShell (' + $ClientApplication + ')')) }
    if ($RecordType -match 'ExchangeAdmin|SecurityComplianceCenterEOPCmdlet') {
        if ("$ExternalAccess" -eq 'True' -or $Actor -match '^NT AUTHORITY|S-1-5-18|ServiceHost|Microsoft\.Exchange|^FIM\b') {
            return @('System', 'Cmdlet - Microsoft service / datacenter (ExternalAccess)')
        }
        return @('Yes', 'Cmdlet - Exchange/Purview PowerShell or Admin Center (client not recorded)')
    }
    if ($id -and $script:AbuseProneApps.ContainsKey($id)) { return @('Possible', ('Token-abuse-prone client: ' + $script:AbuseProneApps[$id])) }
    return @('No', '')
}

function New-EventRow {
    param([hashtable]$H)
    $o = [ordered]@{}
    foreach ($c in $script:EventColumns) {
        $v = ''
        if ($H.ContainsKey($c) -and $null -ne $H[$c]) { $v = [string]$H[$c] }
        $o[$c] = Protect-CsvValue $v
    }
    return [pscustomobject]$o
}

function New-SignInRow {
    param([hashtable]$H)
    $o = [ordered]@{}
    foreach ($c in $script:SignInColumns) {
        $v = ''
        if ($H.ContainsKey($c) -and $null -ne $H[$c]) { $v = [string]$H[$c] }
        $o[$c] = Protect-CsvValue $v
    }
    $m = @()
    if ($o['User'] -and $script:SuspectUserSet.Contains($o['User'])) { $m += 'User' }
    if ($o['IPAddress'] -and $script:SuspectIpSet.Contains($o['IPAddress'])) { $m += 'IP' }
    $o['SuspectMatch'] = $m -join ','
    return [pscustomobject]$o
}

function Add-Finding {
    param([string]$Severity, [string]$Area, [string]$Item, [string]$Detail, [string]$Reason, $When = $null, [string]$Source = '')
    $hay = "$Item $Detail"
    $m = @()
    foreach ($u in $script:SuspectUserSet) { if ($hay.IndexOf($u, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $m += 'User'; break } }
    foreach ($i in $script:SuspectIpSet) { if ($hay.IndexOf($i, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $m += 'IP'; break } }
    if ($m.Count -gt 0 -and $script:SevRank[[string]$Severity] -lt 3) { $Severity = 'High' }
    $script:Findings.Add([pscustomobject]@{
            Severity     = $Severity
            Area         = Protect-CsvValue $Area
            Item         = Protect-CsvValue (Limit-Text $Item 400)
            Detail       = Protect-CsvValue (Limit-Text $Detail 1500)
            Reason       = $Reason
            WhenUtc      = ConvertTo-UtcIso $When
            SuspectMatch = $m -join ','
            Source       = $Source
        })
}

function Add-Coverage {
    param([string]$Source, [string]$Status, [int]$Records = 0, $From = $null, $To = $null, [string]$Notes = '')
    $row = [pscustomobject]@{
        RunUtc  = ConvertTo-UtcIso (Get-Date)
        Source  = $Source
        Status  = $Status
        Records = $Records
        FromUtc = ConvertTo-UtcIso $From
        ToUtc   = ConvertTo-UtcIso $To
        Notes   = $Notes
    }
    if ($null -eq $script:CoverageRows) {
        $script:CoverageRows = New-Object System.Collections.Generic.List[object]
    }
    $script:CoverageRows.Add($row)
    if (-not $script:CoverageFile -and $script:OutputPath) {
        $script:CoverageFile = Join-Path $script:OutputPath 'Coverage.csv'
    }
    if ($script:CoverageFile) {
        Export-EvidenceCsv -Rows $script:CoverageRows -Path $script:CoverageFile
    }
}

function Export-EvidenceCsv {
    param($Rows, [string]$Path)
    $arr = @($Rows | Where-Object { $null -ne $_ })
    $params = @{ LiteralPath = $Path; Encoding = 'UTF8' }
    if ($PSVersionTable.PSVersion.Major -le 5) { $params['NoTypeInformation'] = $true }
    $arr | Export-Csv @params
}

function Save-Rows {
    param($Rows, [string]$FileName, [string]$SortProperty = 'TimeUtc')
    $path = Join-Path $script:OutputPath $FileName
    $arr = @($Rows | Where-Object { $null -ne $_ })
    if ($arr.Count -gt 0) {
        if ($SortProperty -and $arr[0].PSObject.Properties[$SortProperty]) {
            $arr = @($arr | Sort-Object $SortProperty)
        }
        Export-EvidenceCsv -Rows $arr -Path $path
        Write-Log 'OK' ("Saved {0:N0} rows -> {1}" -f $arr.Count, $FileName)
    }
    else { Write-Log 'INFO' "No rows for $FileName" }
}

function Invoke-WithRetry {
    param([scriptblock]$Script, [int]$MaxAttempts = 5, [string]$Activity = 'operation', [object[]]$ArgumentList)
    $attempt = 0
    while ($true) {
        Test-InvestigationCancel
        $attempt++
        try {
            if ($ArgumentList) { return (& $Script @ArgumentList) }
            return (& $Script)
        }
        catch {
            if (Test-IsCancelError $_) { throw }
            $msg = $_.Exception.Message
            $fatal = $msg -match 'BadRequest|\(400\)|Forbidden|\(403\)|Unauthorized|\(401\)|NotFound|\(404\)|is not recognized|parameter cannot be found|Authorization_RequestDenied|RequestFromNonPremiumTenant|Invalid filter|not supported'
            if ($fatal -or $attempt -ge $MaxAttempts) { throw }
            $delay = [int][math]::Min(120, [math]::Pow(2, $attempt) * 5)
            if ($msg -match 'Retry-After\D{0,5}(\d+)') { $delay = [int]$matches[1] + 1 }
            Write-Log 'WARN' ("{0} failed (attempt {1}/{2}): {3} - retrying in {4}s" -f $Activity, $attempt, $MaxAttempts, (Limit-Text $msg 300), $delay)
            Start-SleepInterruptible -Seconds $delay
        }
    }
}

function Test-RequiredModule {
    param([string]$Name, [version]$MinVersion)
    $m = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $m -or $m.Version -lt $MinVersion) {
        if ($script:Config.InstallModules) {
            try {
                Write-Log 'INFO' "Installing $Name (CurrentUser)..."
                Install-Module -Name $Name -MinimumVersion $MinVersion -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            }
            catch { Write-Log 'ERROR' "Install of $Name failed: $($_.Exception.Message)"; return $false }
        }
        else {
            Write-Log 'ERROR' "Module $Name >= $MinVersion not found. Run: Install-Module $Name -Scope CurrentUser   (or re-run with -InstallModules)"
            return $false
        }
    }
    try { Import-Module -Name $Name -MinimumVersion $MinVersion -ErrorAction Stop; return $true }
    catch {
        Write-Log 'ERROR' ("Import of $Name failed: {0}. If this is an assembly (MSAL) conflict, run the Exchange and Graph phases in separate PowerShell windows (-SkipGraph / -SkipExchange) into the same -OutputPath, then -ReportOnly." -f $_.Exception.Message)
        return $false
    }
}

function Get-NormalizedTokenList {
    param($Values, [switch]$KeepCase)
    $items = @($Values | ForEach-Object {
            if ($null -eq $_) { return }
            if ($_ -is [string]) { $_ -split '[,;\r\n\s]+' } else { $_ }
        } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    if (-not $KeepCase) { $items = @($items | ForEach-Object { $_.ToLowerInvariant() }) }
    return @($items | Select-Object -Unique)
}

function Get-NormalizedIdList {
    param($Values)
    return @(Get-NormalizedTokenList $Values)
}

function Get-DefaultOutputParent {
    foreach ($known in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('MyDocuments'), $env:USERPROFILE, (Get-Location).Path)) {
        if ($known -and "$known".Trim()) { return $known }
    }
    return [System.IO.Path]::GetTempPath()
}

function ConvertTo-HtmlEncoded { param($Text) return [System.Net.WebUtility]::HtmlEncode([string]$Text) }

function ConvertTo-ReportJson {
    param($Object)
    $json = $null
    $isList = $Object -is [System.Collections.IList] -and $Object -isnot [string]
    try {
        $json = $Object | ConvertTo-Json -Depth 8 -Compress
        if ($isList -and @($Object).Count -eq 1 -and $json -and $json.TrimStart().StartsWith('{')) {
            $json = '[' + $json + ']'
        }
    } catch {
        $json = 'null'
    }
    if (-not $json) { $json = 'null' }
    return ($json -replace '<', '\u003c')
}

function ConvertTo-JsonMap {
    param($Row, [string[]]$Columns)
    $h = [ordered]@{}
    foreach ($c in $Columns) {
        $v = ''
        if ($Row -and $Row.PSObject.Properties[$c] -and $null -ne $Row.$c) { $v = [string]$Row.$c }
        $h[$c] = $v
    }
    return $h
}
#endregion

#region Classification
function New-Rule { param($Pattern, $Category, $Severity, $Mitre, $Access) [pscustomobject]@{ Pattern = $Pattern; Category = $Category; Severity = $Severity; Mitre = $Mitre; Access = $Access } }

$script:Rules = @(
    (New-Rule 'Set-MsolDomainAuthentication|Set-MsolDomainFederationSettings|New-MsolFederatedDomain|Convert-MsolDomainToFederated|DomainFederationConfiguration|Set federation settings on domain|Set domain authentication|New-MgDomainFederationConfiguration|Update-MgDomainFederationConfiguration' 'Persistence - Identity Federation (Golden SAML)' 'Critical' 'T1484.002' 'Domain federation trust created/changed - attacker can forge SAML tokens and sign in as ANY user, bypassing passwords and MFA')
    (New-Rule 'New-ComplianceSearchAction.*(-Export|-Purge)|SearchExported|SearchExportDownloaded|ViewedSearchExported|PreviewItemDownloaded|New-MailboxExportRequest|Search-Mailbox|New-MailboxSearch' 'Exfiltration - Bulk Mailbox/Site Export' 'Critical' 'T1114.002' 'Bulk export / download of mailbox or SharePoint content through eDiscovery or export requests')
    (New-Rule 'Set-AdminAuditLogConfig|UnifiedAuditLogIngestionEnabled|AuditDisabled|-AuditEnabled|AuditOwner|AuditDelegate|AuditAdmin|Set-MailboxAuditBypassAssociation|Disable-ProtectionAlert|Remove-ProtectionAlert|Set-ProtectionAlert|Remove-ActivityAlert|Set-ActivityAlert' 'Defense Evasion - Audit/Alert Tampering' 'Critical' 'T1562.008' 'Audit logging or alerting disabled, reduced or bypassed - attacker hiding their activity')
    (New-Rule 'ApplicationImpersonation|Mailbox Import Export' 'Privilege Escalation - Mailbox Impersonation/Export Role' 'Critical' 'T1098' 'ApplicationImpersonation / Mailbox Import Export role - can read, send as, or export ANY mailbox')
    (New-Rule 'New-ManagementRoleAssignment|Set-ManagementRoleAssignment|Add-RoleGroupMember|Update-RoleGroupMember|New-RoleGroup|New-ManagementRole\b|New-ManagementScope|Add-ComplianceRoleGroupMember' 'Privilege Escalation - Exchange/Purview RBAC' 'Critical' 'T1098' 'Exchange Online / Purview administrative role granted')
    (New-Rule 'Add member to role|Add eligible member to role|Add scoped member to role|Add-MsolRoleMember|Add-AzureADDirectoryRoleMember|New-MgRoleManagementDirectoryRoleAssignment|New-MgDirectoryRoleMemberByRef|Add-MgDirectoryRoleMember|New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest' 'Privilege Escalation - Entra Directory Role' 'Critical' 'T1098.003' 'Entra ID administrator role granted (Global/Privileged/Exchange/App admin, etc.)')
    (New-Rule 'Add service principal credentials|Certificates and secrets management|KeyCredentials|PasswordCredentials|New-AzureADApplicationPasswordCredential|New-AzureADServicePrincipalPasswordCredential|New-AzureADApplicationKeyCredential|Add-MgApplicationPassword|Add-MgServicePrincipalPassword|Add-MgApplicationKey|New-MsolServicePrincipalCredential' 'Persistence - App/Service Principal Credential' 'Critical' 'T1098.001' 'Secret or certificate added to an application/service principal - persistent app-only access that survives password resets and MFA')
    (New-Rule 'Add app role assignment to service principal|Add app role assignment grant to user|Consent to application|Add delegated permission grant|Add OAuth2PermissionGrant|New-MgOauth2PermissionGrant|New-MgServicePrincipalAppRoleAssignment|Update-MgOauth2PermissionGrant' 'Persistence - OAuth Consent / API Permissions' 'High' 'T1528' 'API permissions granted to an application (possible illicit consent grant giving mailbox/file/directory access)')
    (New-Rule 'New-ComplianceSearch|Start-ComplianceSearch|Set-ComplianceSearch|New-ComplianceCase|Add-ComplianceCaseMember|Add-eDiscoveryCaseAdmin|New-CaseHoldPolicy|SearchCreated|SearchStarted|SearchViewed|SearchPreviewed|CaseAdded|CaseMemberAdded' 'Collection - eDiscovery / Content Search' 'High' 'T1114.002' 'Content search across mailboxes/sites - attacker locating sensitive data')
    (New-Rule 'Add-MailboxPermission|Add-RecipientPermission|Add-MailboxFolderPermission|Set-MailboxFolderPermission|GrantSendOnBehalfTo|Add-ADPermission|AddFolderPermissions|UpdateFolderPermissions|Add-MailboxCalendarDelegate' 'Collection - Mailbox Access Granted' 'High' 'T1098.002' 'Delegated FullAccess / SendAs / SendOnBehalf / folder permission granted on a mailbox')
    (New-Rule 'New-InboxRule|Set-InboxRule|Enable-InboxRule|UpdateInboxRules|New-TransportRule|Set-TransportRule|Enable-TransportRule|ForwardingSmtpAddress|ForwardingAddress|DeliverToMailboxAndForward|AutoForwardEnabled|AutoForwardingMode|Set-MailboxJunkEmailConfiguration' 'Exfiltration - Mail Forwarding / Mail Rules' 'High' 'T1114.003' 'Mail forwarding, redirect, or inbox/transport rule created or changed (exfiltration or hiding replies)')
    (New-Rule 'New-InboundConnector|Set-InboundConnector|Enable-InboundConnector|New-OutboundConnector|Set-OutboundConnector' 'Exfiltration - Mail Flow Connector' 'High' 'T1564.008' 'Mail flow connector created/changed - relay, spoofing, or mail-flow exfiltration path')
    (New-Rule 'Set-HostedContentFilterPolicy|Set-MalwareFilterPolicy|Set-SafeLinksPolicy|Set-SafeAttachmentPolicy|Set-AntiPhishPolicy|Set-AtpPolicyForO365|Set-HostedOutboundSpamFilterPolicy|Set-HostedConnectionFilterPolicy|New-TenantAllowBlockListItems|Set-TenantAllowBlockListItems|Remove-\w*(Policy|Rule)\b|Disable-\w*(Policy|Rule)\b' 'Defense Evasion - Security Control Weakened' 'High' 'T1562.001' 'Email security policy weakened, disabled, or attacker infrastructure allow-listed')
    (New-Rule 'conditional access policy|Update-MgIdentityConditionalAccessPolicy|Remove-MgIdentityConditionalAccessPolicy|New-MgIdentityConditionalAccessPolicy|named location|Update authorization policy|Update-MgPolicyAuthorizationPolicy|Set Company Information|Set-MsolCompanySettings|Update-MgPolicyAuthenticationMethodPolicy|Set-AzureADPolicy|Security defaults' 'Defense Evasion - Tenant Security Policy' 'High' 'T1556.009' 'Conditional Access / tenant authentication policy changed (possible MFA or location bypass)')
    (New-Rule 'Disable Strong Authentication|StrongAuthentication|registered security info|deleted security info|authentication method|Temporary Access Pass|Reset user password|Change user password|Reset password|Set-MsolUserPassword|Set-AzureADUserPassword|Reset-MgUserAuthenticationMethodPassword|PasswordProfile|New-MgUserAuthentication|Remove-MgUserAuthentication|Set-MgUserAuthentication|Update StsRefreshTokenValidFrom' 'Credential Access - Password / MFA Manipulation' 'High' 'T1556.006' 'Password reset or MFA / authentication method added, removed or changed on an account (account takeover)')
    (New-Rule 'Add owner to application|Add owner to service principal|Add application|Add service principal|New-AzureADApplication|New-MgApplication|New-MgServicePrincipal|New-AzureADServicePrincipal|New-MsolServicePrincipal|Update application|Update service principal' 'Persistence - Application Registered/Changed' 'High' 'T1098.001' 'Application or service principal created, changed, or new owner added')
    (New-Rule 'Add domain to company|Verify domain|Add unverified domain|New-AcceptedDomain|New-MsolDomain|New-MgDomain|Confirm-MsolDomain|Confirm-MgDomain' 'Persistence - Domain Added' 'High' 'T1484.002' 'Domain added/verified in the tenant (often staging for a federation backdoor)')
    (New-Rule 'SiteCollectionAdminAdded|IsSiteCollectionAdmin|Add-SPOUser|Set-SPOTenant|Set-SPOSite|Grant-SPOSiteDesignRights|Add-PnPSiteCollectionAdmin|Set-PnPTenant|SharingPolicyChanged|SiteAdminChangeRequest|AnonymousLinkCreated|CompanyLinkCreated|SharingInvitationCreated' 'Collection - SharePoint/OneDrive Access' 'High' 'T1213.002' 'SharePoint / OneDrive site-admin rights or external sharing granted')
    (New-Rule 'CreateFlow|EditFlow|PutConnection|CreateConnection' 'Exfiltration - Power Automate Flow' 'High' 'T1567' 'Power Automate flow or connection created/changed (automated data exfiltration)')
    (New-Rule 'Set-Team\b|New-Team\b|Set-CsTenantFederationConfiguration|Set-CsExternalAccessPolicy|TeamCreated|AddedToRoster' 'Persistence - Teams Admin / Federation' 'High' 'T1484' 'Teams tenant, team, or federation settings changed through PowerShell or admin APIs')
    (New-Rule 'Set-CASMailbox|OAuth2ClientProfileEnabled|AuthenticationPolicy|New-ApplicationAccessPolicy|Remove-ApplicationAccessPolicy|Set-OrganizationConfig|Set-OwaMailboxPolicy|Set-SharingPolicy' 'Defense Evasion - Protocol / Org Config' 'Medium' 'T1562' 'Mailbox protocol (IMAP/POP/EWS/ActiveSync), sharing, or organization configuration changed')
    (New-Rule 'Add user|New-MsolUser|New-AzureADUser|New-MgUser|New-Mailbox|Invite external user|New-MgInvitation|Redeem external user invite|Add guest' 'Persistence - Account Created' 'Medium' 'T1136.003' 'New user, mailbox, or guest account created')
    (New-Rule 'Add member to group|Add-MgGroupMember|Add-AzureADGroupMember|Add-MsolGroupMember|Add-DistributionGroupMember|Add-UnifiedGroupLinks|Add owner to group' 'Privilege Escalation - Group Membership' 'Medium' 'T1098' 'Account added to a group (check whether the group grants privileged access or app/role assignments)')
    (New-Rule 'Update user|Set-MsolUser|Set-AzureADUser|Update-MgUser|Set-Mailbox|Set-User\b' 'Account Manipulation' 'Medium' 'T1098' 'User or mailbox attributes changed')
    (New-Rule 'Remove-|Delete |HardDelete|SoftDelete|MoveToDeletedItems|Remove member|Disable account|Purge' 'Impact / Anti-Forensics - Deletion' 'Medium' 'T1070.008' 'Objects, mail, or rules removed/deleted (destruction or covering tracks)')
)

function Set-Classification {
    param($Row)
    $text = '{0} {1} {2}' -f $Row.Operation, $Row.CommandLine, $Row.Details
    $rule = $null
    foreach ($r in $script:Rules) { if ($text -match $r.Pattern) { $rule = $r; break } }
    $access = ''
    if ($rule) {
        $Row.Category = $rule.Category; $Row.Severity = $rule.Severity; $Row.Mitre = $rule.Mitre; $access = $rule.Access
    }
    elseif ($Row.RecordType -match 'ExchangeAdmin|SecurityComplianceCenterEOPCmdlet') { $Row.Category = 'Configuration Change (cmdlet)'; $Row.Severity = 'Low' }
    elseif ($Row.Source -eq 'UAL-SuspectActivity') {
        if ($Row.Operation -match 'MailItemsAccessed|FileDownloaded|FileSyncDownloaded|FileAccessed|Send$|SendAs|SendOnBehalf|MessageSent') { $Row.Category = 'Collection - Data Accessed by Suspect'; $Row.Severity = 'Low'; $Row.Mitre = 'T1114 / T1530' }
        else { $Row.Category = 'Suspect Account Activity'; $Row.Severity = 'Info' }
    }
    else { $Row.Category = 'Other Activity'; $Row.Severity = 'Info' }

    if ($access) {
        if ($Row.Outcome -eq 'Failed') { $Row.AccessGained = 'ATTEMPTED (FAILED): ' + $access }
        else { $Row.AccessGained = $access }
    }

    $m = New-Object System.Collections.Generic.List[string]
    if ($Row.Actor -and $script:SuspectUserSet.Contains($Row.Actor)) { $m.Add('Actor') }
    if ($Row.ClientIP -and $script:SuspectIpSet.Contains($Row.ClientIP)) { $m.Add('IP') }
    if ($script:SuspectUserSet.Count -gt 0 -and -not $m.Contains('Actor')) {
        $hay = '{0} {1} {2} {3}' -f $Row.Target, $Row.TargetIdentity, $Row.CommandLine, $Row.Details
        foreach ($u in $script:SuspectUserSet) { if ($hay.IndexOf($u, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $m.Add('Target/Params'); break } }
    }
    $Row.SuspectMatch = $m -join ','
    if ($Row.PowerShellRelated -eq 'System' -and $m.Count -eq 0 -and $script:SevRank[[string]$Row.Severity] -lt 4) { $Row.Severity = 'Low' }
    if ($m.Count -gt 0 -and $script:SevRank[[string]$Row.Severity] -lt 2 -and $Row.Source -ne 'UAL-SuspectActivity') { $Row.Severity = 'Medium' }
    if ($m.Contains('IP') -and $script:SevRank[[string]$Row.Severity] -lt 3) { $Row.Severity = 'High' }
}
#endregion

#region Unified Audit Log
function Format-CommandLine {
    param([string]$Cmdlet, $Parameters)
    $parts = New-Object System.Collections.Generic.List[string]
    if ($Cmdlet) { $parts.Add($Cmdlet) }
    if ($Parameters -is [string]) { if ($Parameters.Trim()) { $parts.Add($Parameters.Trim()) } }
    elseif ($Parameters) {
        foreach ($p in @($Parameters)) {
            if ($null -eq $p) { continue }
            $n = [string]$p.Name; $v = [string]$p.Value
            if (-not $n) { continue }
            if ($v -eq '') { $parts.Add('-' + $n) }
            elseif ($v -eq 'True') { $parts.Add('-' + $n + ':$true') }
            elseif ($v -eq 'False') { $parts.Add('-' + $n + ':$false') }
            else { $parts.Add('-' + $n + " '" + ($v -replace "'", "''") + "'") }
        }
    }
    return ($parts -join ' ')
}

function Get-TargetIdentity {
    param($Parameters)
    if (-not $Parameters -or $Parameters -is [string]) { return '' }
    foreach ($want in @('Mailbox', 'Identity')) {
        foreach ($p in @($Parameters)) {
            if ($p -and $p.Name -eq $want -and $p.Value) {
                $v = [string]$p.Value
                if ($want -eq 'Identity' -and $v -match '^(.+?)\\[^\\]+$') { $v = $matches[1] }
                return $v
            }
        }
    }
    return ''
}

function Get-UalUserAgent {
    param($A)
    $ua = Get-FirstValue $A @('UserAgent')
    if (-not $ua -and $A.ExtendedProperties) {
        foreach ($p in @($A.ExtendedProperties)) { if ($p -and $p.Name -eq 'UserAgent') { $ua = $p.Value; break } }
    }
    if (-not $ua) { $ua = Get-FirstValue $A @('ClientInfoString') }
    return [string]$ua
}

function Get-UalLocation {
    param($A)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($want in @('City', 'State', 'StateOrProvince', 'CountryOrRegion', 'Country')) {
        $v = Get-FirstValue $A @($want)
        if (-not $v -and $A.ExtendedProperties) {
            foreach ($p in @($A.ExtendedProperties)) { if ($p -and $p.Name -eq $want -and $p.Value) { $v = $p.Value; break } }
        }
        if ($v) { $parts.Add([string]$v) }
    }
    return ($parts | Select-Object -Unique) -join ', '
}

function Get-UalDetails {
    param($A)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($m in @($A.ModifiedProperties)) {
        if ($m -and $m.Name) { $parts.Add(('{0}: {1} -> {2}' -f $m.Name, (Limit-Text $m.OldValue 200), (Limit-Text $m.NewValue 300))) }
    }
    foreach ($n in @('SiteUrl', 'SourceRelativeUrl', 'SourceFileName', 'DestinationRelativeUrl', 'TargetUserOrGroupName', 'ModifiedObjectResolvedName',
            'EventData', 'Query', 'MailboxOwnerUPN', 'LogonType', 'ClientApplication', 'FlowDetailsUrl', 'OperationCount')) {
        $v = Get-FirstValue $A @($n)
        if ($v) { $parts.Add(($n + '=' + (Limit-Text ([string]$v) 300))) }
    }
    if ($A.Folders) {
        $paths = @($A.Folders | ForEach-Object { $_.Path } | Where-Object { $_ } | Select-Object -First 5)
        if ($paths.Count) { $parts.Add('Folders=' + ($paths -join ', ')) }
    }
    return (Limit-Text ($parts -join ' | ') 2500)
}

function ConvertFrom-UalRecord {
    param($Record, [string]$Label)
    try { $a = ([string]$Record.AuditData) | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    $recordType = [string]$Record.RecordType
    if (-not $recordType) { $recordType = [string](Get-FirstValue $a @('RecordType')) }
    $op = [string](Get-FirstValue $a @('Operation')); if (-not $op) { $op = [string]$Record.Operations }
    $actor = [string](Get-FirstValue $a @('UserId')); if (-not $actor) { $actor = [string]$Record.UserIds }
    $ip = Format-Ip ([string](Get-FirstValue $a @('ClientIP', 'ClientIPAddress', 'ActorIpAddress', 'ClientIp')))
    $appId = ([string](Get-FirstValue $a @('AppId', 'ClientAppId', 'ApplicationId'))).ToLowerInvariant()
    $ua = Get-UalUserAgent $a
    $params = $null
    if ($a.PSObject.Properties['Parameters']) { $params = $a.Parameters }
    $isCmdlet = ($recordType -match 'ExchangeAdmin|SecurityComplianceCenterEOPCmdlet') -or ($op -match '^[A-Za-z]+-[A-Za-z0-9]+$' -and $params)
    $cmd = ''
    if ($isCmdlet) { $cmd = Format-CommandLine $op $params }
    $target = [string](Get-FirstValue $a @('ObjectId'))
    if (-not $target -and $a.Target) { $target = (@($a.Target) | ForEach-Object { $_.ID } | Where-Object { $_ } | Select-Object -First 5) -join '; ' }
    $clientApp = [string](Get-FirstValue $a @('ClientApplication', 'ClientAppName'))
    $ch = Get-ExecutionChannel -AppId $appId -UserAgent $ua -RecordType $recordType -ExternalAccess $a.ExternalAccess -ClientApplication $clientApp -Actor $actor
    $row = New-EventRow @{
        TimeUtc           = (ConvertTo-UtcIso $a.CreationTime)
        Operation         = $op
        Outcome           = (Get-Outcome (Get-FirstValue $a @('ResultStatus')))
        Actor             = $actor
        ClientIP          = $ip
        Target            = $target
        TargetIdentity    = (Get-TargetIdentity $params)
        CommandLine       = (Limit-Text $cmd 4000)
        Details           = (Get-UalDetails $a)
        PowerShellRelated = $ch[0]
        ExecutionChannel  = $ch[1]
        AppId             = $appId
        UserAgent         = (Limit-Text $ua 400)
        Workload          = [string]$a.Workload
        RecordType        = $recordType
        Source            = ('UAL-' + $Label)
        RecordId          = [string]$Record.Identity
    }
    Set-Classification $row
    return $row
}

function ConvertFrom-UalSignIn {
    param($Record)
    try { $a = ([string]$Record.AuditData) | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    $appId = ([string](Get-FirstValue $a @('ApplicationId', 'AppId'))).ToLowerInvariant()
    $ua = Get-UalUserAgent $a
    $detail = ''
    foreach ($p in @($a.ExtendedProperties)) { if ($p -and $p.Name -eq 'ResultStatusDetail') { $detail = [string]$p.Value } }
    $err = [string]$a.ErrorNumber
    $result = 'Success'
    if ($a.Operation -eq 'UserLoginFailed' -or ($err -and $err -ne '0')) { $result = 'Failure' }
    $tool = Get-ClientFromUserAgent $ua
    $psApp = 'No'
    if ($script:PowerShellApps.ContainsKey($appId) -or $tool -eq 'PowerShell') { $psApp = 'Yes' }
    elseif ($tool) { $psApp = 'Tooling' }
    elseif ($script:AbuseProneApps.ContainsKey($appId)) { $psApp = 'Abuse-prone client' }
    return (New-SignInRow @{
            TimeUtc = (ConvertTo-UtcIso $a.CreationTime); User = [string]$a.UserId; Result = $result; ErrorCode = $err
            FailureReason = $detail; AppName = (Get-AppName $appId); AppId = $appId; PowerShellApp = $psApp
            IPAddress = (Format-Ip ([string]$a.ClientIP)); Location = (Get-UalLocation $a); Resource = [string]$a.ObjectId
            UserAgent = (Limit-Text $ua 400); ClientTool = $tool; SignInType = 'Interactive (UAL)'; Source = 'UAL-StsLogon'
            Id = [string]$Record.Identity
        })
}

function Get-UalRecords {
    param([datetime]$From, [datetime]$To, [string]$RecordType = '', [string[]]$Operations = @(), [string[]]$UserIds = @(), [int]$Depth = 0)
    $results = New-Object System.Collections.Generic.List[object]
    $sessionRetries = 0
    while ($true) {
        Test-InvestigationCancel
        $sessionId = [guid]::NewGuid().ToString()
        $results.Clear()
        $expected = -1
        $pages = 0
        $badSession = $false
        while ($true) {
            Test-InvestigationCancel
            $ualParams = @{ StartDate = $From; EndDate = $To; SessionId = $sessionId; SessionCommand = 'ReturnLargeSet'; ResultSize = 5000; ErrorAction = 'Stop' }
            if ($RecordType) { $ualParams['RecordType'] = $RecordType }
            if ($Operations.Count -gt 0) { $ualParams['Operations'] = $Operations }
            if ($UserIds.Count -gt 0) { $ualParams['UserIds'] = $UserIds }
            $page = @(Invoke-WithRetry -Activity ("UAL {0}" -f $RecordType) -Script { Search-UnifiedAuditLog @ualParams })
            $pages++
            if ($page.Count -eq 0 -or $null -eq $page[0]) { break }
            if ($expected -lt 0) {
                $expected = [int]$page[0].ResultCount
                if ($expected -eq 0) { $badSession = $true; break }
                if ($expected -ge 50000 -and ($To - $From).TotalMinutes -gt 2) {
                    $mid = $From.AddTicks([long](($To - $From).Ticks / 2))
                    Write-Log 'WARN' ("UAL {0}: {1:N0} results in {2:u} -> {3:u} exceeds the 50,000 session cap - splitting window" -f $RecordType, $expected, $From, $To)
                    $combined = New-Object System.Collections.Generic.List[object]
                    foreach ($x in (Get-UalRecords -From $From -To $mid -RecordType $RecordType -Operations $Operations -UserIds $UserIds -Depth ($Depth + 1))) { $combined.Add($x) }
                    foreach ($x in (Get-UalRecords -From $mid -To $To -RecordType $RecordType -Operations $Operations -UserIds $UserIds -Depth ($Depth + 1))) { $combined.Add($x) }
                    return , $combined.ToArray()
                }
                if ($expected -ge 50000) { Write-Log 'WARN' "UAL ${RecordType}: >50,000 events in a 2-minute window - results truncated (export this window via Purview Audit search)." }
            }
            foreach ($r in $page) { $results.Add($r) }
            if ($results.Count -ge $expected -or $pages -ge 11) { break }
        }
        if ($badSession -and $sessionRetries -lt 3) {
            $sessionRetries++
            Write-Log 'WARN' "UAL ${RecordType}: service returned an invalid result set - retrying window with a new session ($sessionRetries/3)"
            Start-SleepInterruptible -Seconds (10 * $sessionRetries)
            continue
        }
        break
    }
    return , $results.ToArray()
}

function Invoke-UalCollection {
    param([string]$Name, [datetime]$From, [datetime]$To, [string]$RecordType = '', [string[]]$Operations = @(), [string[]]$UserIds = @(), [string]$Label = 'Admin', [string]$Kind = 'Event')
    $rows = New-Object System.Collections.Generic.List[object]
    if ($From -ge $To) { return , $rows.ToArray() }
    $rawFile = Join-Path $script:RawPath ('UAL-{0}-{1}.jsonl' -f $Label, $Name)
    $writer = $null
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $status = 'OK'; $notes = ''
    try {
        $writer = New-Object System.IO.StreamWriter($rawFile, $false, (New-Object System.Text.UTF8Encoding($false)))
        $cursor = $From
        $chunkHours = [int]$script:Config.ChunkHours
        if ($chunkHours -lt 1) { $chunkHours = 24 }
        while ($cursor -lt $To) {
            Test-InvestigationCancel
            $chunkEnd = $cursor.AddHours($chunkHours)
            if ($chunkEnd -gt $To) { $chunkEnd = $To }
            $records = Get-UalRecords -From $cursor -To $chunkEnd -RecordType $RecordType -Operations $Operations -UserIds $UserIds
            $new = 0
            foreach ($r in $records) {
                $id = [string]$r.Identity
                if ($id -and -not $seen.Add($id)) { continue }
                if ($writer) { $writer.WriteLine([string]$r.AuditData) }
                if ($Kind -eq 'SignIn') { $row = ConvertFrom-UalSignIn $r } else { $row = ConvertFrom-UalRecord $r $Label }
                if ($row) { $rows.Add($row); $new++ }
            }
            Write-Log 'INFO' ("UAL {0,-36} {1:yyyy-MM-dd HH:mm} -> {2:yyyy-MM-dd HH:mm} UTC : {3,6:N0} records (total {4:N0})" -f $Name, $cursor, $chunkEnd, $new, $rows.Count)
            $cursor = $chunkEnd
        }
    }
    catch {
        if (Test-IsCancelError $_) { throw }
        $status = 'ERROR'; $notes = $_.Exception.Message
        Write-Log 'ERROR' ("UAL {0} collection failed: {1}" -f $Name, $notes)
    }
    finally { if ($writer) { try { $writer.Close() } catch { } } }
    Add-Coverage -Source ("Unified Audit Log - {0} ({1})" -f $Name, $Label) -Status $status -Records $rows.Count -From $From -To $To -Notes $notes
    return , $rows.ToArray()
}
#endregion

#region Exchange phase
function Invoke-ExchangeStateCollection {
    param($UalRows)
    $script:Findings.Clear()
    Write-Log 'INFO' 'Exchange current-state persistence sweep...'
    Write-InvestigationProgress 'Exchange current state' 'Sweeping persistence' 55
    $src = 'Exchange Online (current state)'

    try {
        $c = Get-AdminAuditLogConfig -ErrorAction Stop
        $sev = 'Info'; if (-not $c.UnifiedAuditLogIngestionEnabled) { $sev = 'Critical' }
        Add-Finding $sev 'Audit Configuration' 'Unified Audit Log ingestion' ("UnifiedAuditLogIngestionEnabled=" + $c.UnifiedAuditLogIngestionEnabled) 'If disabled, activity after it was turned off was NOT recorded.' $null $src
    }
    catch { Write-Log 'WARN' "Get-AdminAuditLogConfig: $($_.Exception.Message)" }

    try {
        $o = Get-OrganizationConfig -ErrorAction Stop
        $sev = 'Info'; if ($o.AuditDisabled) { $sev = 'Critical' }
        Add-Finding $sev 'Audit Configuration' 'Mailbox auditing (organization default)' ("AuditDisabled=" + $o.AuditDisabled) 'Mailbox auditing off org-wide hides mailbox access (MailItemsAccessed, Send, rules).' $null $src
        Add-Coverage -Source 'Tenant (Exchange)' -Status 'INFO' -Notes ("Organization=" + $o.DisplayName + "; Identity=" + $o.Identity)
    }
    catch { Write-Log 'WARN' "Get-OrganizationConfig: $($_.Exception.Message)" }

    try {
        foreach ($b in @(Get-MailboxAuditBypassAssociation -ResultSize Unlimited -ErrorAction Stop | Where-Object { $_.AuditBypassEnabled })) {
            Add-Finding 'Critical' 'Audit Configuration' ("Audit bypass enabled: " + $b.Name) ("Identity=" + $b.Identity + "; WhenChanged=" + $b.WhenChanged) 'Actions by this account against mailboxes are not audited (T1562.008).' $b.WhenChanged $src
        }
    }
    catch { Write-Log 'WARN' "Get-MailboxAuditBypassAssociation: $($_.Exception.Message)" }

    try {
        $noAudit = @(Get-Mailbox -ResultSize Unlimited -Filter 'AuditEnabled -eq $false' -ErrorAction Stop)
        foreach ($m in ($noAudit | Select-Object -First 500)) {
            Add-Finding 'Medium' 'Audit Configuration' ("Mailbox auditing disabled: " + $m.PrimarySmtpAddress) ("WhenChanged=" + $m.WhenChanged) 'Access to this mailbox is not audited.' $m.WhenChanged $src
        }
    }
    catch { Write-Log 'WARN' "Mailbox audit status: $($_.Exception.Message)" }

    try {
        foreach ($m in @(Get-Mailbox -ResultSize Unlimited -Filter 'ForwardingSmtpAddress -ne $null -or ForwardingAddress -ne $null' -ErrorAction Stop)) {
            $sev = 'Medium'; if ($m.ForwardingSmtpAddress) { $sev = 'High' }
            $recent = $m.WhenChanged -and $m.WhenChanged.ToUniversalTime() -ge $script:StartUtc
            if ($recent -and $sev -eq 'High') { $sev = 'Critical' }
            Add-Finding $sev 'Mail Forwarding' ([string]$m.PrimarySmtpAddress) ("ForwardingSmtpAddress={0}; ForwardingAddress={1}; DeliverToMailboxAndForward={2}; MailboxLastChanged={3}" -f $m.ForwardingSmtpAddress, $m.ForwardingAddress, $m.DeliverToMailboxAndForward, $m.WhenChanged) 'Mailbox-level forwarding is a primary exfiltration technique (T1114.003).' $m.WhenChanged $src
        }
    }
    catch { Write-Log 'WARN' "Forwarding sweep: $($_.Exception.Message)" }

    try {
        foreach ($p in @(Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop)) {
            if ($p.AutoForwardingMode -eq 'On') {
                Add-Finding 'High' 'Mail Forwarding' ("Outbound spam policy allows auto-forwarding: " + $p.Name) ("AutoForwardingMode=On; WhenChanged=" + $p.WhenChanged) 'Automatic external forwarding is permitted tenant-wide for users in scope.' $p.WhenChanged $src
            }
        }
    }
    catch { Write-Log 'WARN' "Get-HostedOutboundSpamFilterPolicy: $($_.Exception.Message)" }

    try {
        foreach ($t in @(Get-TransportRule -ResultSize Unlimited -ErrorAction Stop)) {
            $risky = @()
            if ($t.RedirectMessageTo) { $risky += ('RedirectMessageTo=' + ($t.RedirectMessageTo -join ',')) }
            if ($t.BlindCopyTo) { $risky += ('BlindCopyTo=' + ($t.BlindCopyTo -join ',')) }
            if ($t.CopyTo) { $risky += ('CopyTo=' + ($t.CopyTo -join ',')) }
            if ($t.AddToRecipients) { $risky += ('AddToRecipients=' + ($t.AddToRecipients -join ',')) }
            if ($t.DeleteMessage) { $risky += 'DeleteMessage=True' }
            if ("$($t.SetSCL)" -eq '-1') { $risky += 'SetSCL=-1 (bypass spam filtering)' }
            if ($t.RouteMessageOutboundConnector) { $risky += ('RouteMessageOutboundConnector=' + $t.RouteMessageOutboundConnector) }
            $recent = $t.WhenChanged -and $t.WhenChanged.ToUniversalTime() -ge $script:StartUtc
            if ($risky.Count -gt 0 -or $recent) {
                $sev = 'Medium'
                if ($risky.Count -gt 0) { $sev = 'High' }
                if ($risky.Count -gt 0 -and $recent) { $sev = 'Critical' }
                Add-Finding $sev 'Transport Rule' ([string]$t.Name) (("State={0}; Priority={1}; WhenChanged={2}; " -f $t.State, $t.Priority, $t.WhenChanged) + ($risky -join '; ')) 'Transport rules can silently copy, redirect or delete mail for the whole organization.' $t.WhenChanged $src
            }
        }
    }
    catch { Write-Log 'WARN' "Get-TransportRule: $($_.Exception.Message)" }

    foreach ($kind in @('Inbound', 'Outbound')) {
        try {
            $list = @()
            if ($kind -eq 'Inbound') { $list = @(Get-InboundConnector -ErrorAction Stop) } else { $list = @(Get-OutboundConnector -ErrorAction Stop) }
            foreach ($cn in $list) {
                $recent = ($cn.WhenCreated -and $cn.WhenCreated.ToUniversalTime() -ge $script:StartUtc) -or ($cn.WhenChanged -and $cn.WhenChanged.ToUniversalTime() -ge $script:StartUtc)
                $sev = 'Info'; if ($recent) { $sev = 'High' }
                $detail = "Enabled={0}; Type={1}; SenderIPs={2}; SmartHosts={3}; RecipientDomains={4}; SenderDomains={5}; Created={6}; Changed={7}" -f $cn.Enabled, $cn.ConnectorType, ($cn.SenderIPAddresses -join ','), ($cn.SmartHosts -join ','), ($cn.RecipientDomains -join ','), ($cn.SenderDomains -join ','), $cn.WhenCreated, $cn.WhenChanged
                Add-Finding $sev ("$kind Connector") ([string]$cn.Name) $detail 'Connectors created/changed in the window may relay, spoof, or exfiltrate mail.' $cn.WhenChanged $src
            }
        }
        catch { Write-Log 'WARN' "Get-${kind}Connector: $($_.Exception.Message)" }
    }

    try {
        foreach ($ra in @(Get-ManagementRoleAssignment -ErrorAction Stop)) {
            if ("$($ra.RoleAssignmentDelegationType)" -like 'Delegating*') { continue }
            $recent = $ra.WhenCreated -and $ra.WhenCreated.ToUniversalTime() -ge $script:StartUtc
            $dangerous = "$($ra.Role)" -match 'ApplicationImpersonation|Mailbox Import Export|Mailbox Search|Role Management|Organization Management|Security Admin|eDiscovery'
            if (-not ($recent -or $dangerous)) { continue }
            $sev = 'Medium'
            if ($dangerous) { $sev = 'High' }
            if ($dangerous -and $recent) { $sev = 'Critical' }
            if ("$($ra.RoleAssigneeType)" -eq 'RoleGroup' -and -not $recent) { $sev = 'Info' }
            Add-Finding $sev 'Exchange RBAC' ("{0} -> {1}" -f $ra.Role, $ra.RoleAssigneeName) ("AssigneeType={0}; Enabled={1}; RecipientScope={2}; CustomScope={3}; Name={4}; Created={5}" -f $ra.RoleAssigneeType, $ra.Enabled, $ra.RecipientWriteScope, $ra.CustomRecipientWriteScope, $ra.Name, $ra.WhenCreated) 'Direct or recent assignments of powerful Exchange roles are a common persistence/escalation path.' $ra.WhenCreated $src
        }
    }
    catch { Write-Log 'WARN' "Get-ManagementRoleAssignment: $($_.Exception.Message)" }

    foreach ($rg in @('Organization Management', 'Recipient Management', 'Discovery Management', 'Compliance Management', 'Security Administrator', 'Hygiene Management')) {
        try {
            foreach ($m in @(Get-RoleGroupMember -Identity $rg -ResultSize Unlimited -ErrorAction Stop)) {
                $nm = [string](Get-FirstValue $m @('PrimarySmtpAddress', 'WindowsLiveID', 'Name'))
                Add-Finding 'Info' 'Exchange Role Group Member' ("{0}: {1}" -f $rg, $nm) ("RecipientType=" + $m.RecipientType) 'Validate every member; unexpected members indicate privilege escalation.' $null $src
            }
        }
        catch { Write-Log 'INFO' "Role group '$rg' not readable or not present: $($_.Exception.Message)" }
    }

    $targets = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($u in $script:SuspectUserSet) { [void]$targets.Add($u) }
    foreach ($e in $UalRows) {
        if ($null -eq $e) { continue }
        if ($e.Category -match 'Mailbox Access|Mail Forwarding|Mailbox Impersonation' -and $e.TargetIdentity) { [void]$targets.Add($e.TargetIdentity) }
    }
    $hasHidden = $false
    try { $hasHidden = (Get-Command Get-InboxRule -ErrorAction Stop).Parameters.ContainsKey('IncludeHidden') } catch { }
    $n = 0
    $cap = [int]$script:Config.MaxMailboxesToInspect
    foreach ($mbx in $targets) {
        Test-InvestigationCancel
        $n++
        if ($n -gt $cap) { Write-Log 'WARN' "Mailbox inspection capped at $cap mailboxes (-MaxMailboxesToInspect)."; break }
        try {
            foreach ($p in @(Get-MailboxPermission -Identity $mbx -ErrorAction Stop | Where-Object { -not $_.IsInherited -and -not $_.Deny -and "$($_.User)" -notmatch 'NT AUTHORITY\\SELF|^S-1-5-' })) {
                Add-Finding 'High' 'Mailbox Permission' ("{0}  <-  {1}" -f $mbx, $p.User) ("AccessRights=" + ($p.AccessRights -join ',')) 'The delegate can open and read this entire mailbox.' $null $src
            }
        }
        catch { Write-Log 'INFO' "Get-MailboxPermission ${mbx}: $($_.Exception.Message)" }
        try {
            foreach ($p in @(Get-RecipientPermission -Identity $mbx -ErrorAction Stop | Where-Object { "$($_.Trustee)" -notmatch 'NT AUTHORITY\\SELF' -and -not $_.IsInherited })) {
                Add-Finding 'High' 'SendAs Permission' ("{0}  <-  {1}" -f $mbx, $p.Trustee) ("AccessRights=" + ($p.AccessRights -join ',')) 'The trustee can send mail as this mailbox (BEC / internal phishing).' $null $src
            }
        }
        catch { Write-Log 'INFO' "Get-RecipientPermission ${mbx}: $($_.Exception.Message)" }
        try {
            $ruleParams = @{ Mailbox = $mbx; ErrorAction = 'Stop' }
            if ($hasHidden) { $ruleParams['IncludeHidden'] = $true }
            foreach ($r in @(Get-InboxRule @ruleParams)) {
                $flags = @()
                if ($r.ForwardTo) { $flags += ('ForwardTo=' + ($r.ForwardTo -join ',')) }
                if ($r.ForwardAsAttachmentTo) { $flags += ('ForwardAsAttachmentTo=' + ($r.ForwardAsAttachmentTo -join ',')) }
                if ($r.RedirectTo) { $flags += ('RedirectTo=' + ($r.RedirectTo -join ',')) }
                if ($r.DeleteMessage) { $flags += 'DeleteMessage' }
                if ($r.MoveToFolder -and "$($r.MoveToFolder)" -match 'RSS|Archive|Conversation History|Deleted|Junk|Notes|Sync Issues') { $flags += ('MoveToFolder=' + $r.MoveToFolder) }
                if ($r.MarkAsRead) { $flags += 'MarkAsRead' }
                if ("$($r.Name)".Trim().Length -le 3 -or "$($r.Name)" -match '^[\W_]+$') { $flags += 'Suspicious short/symbol-only name' }
                if ($flags.Count -eq 0) { continue }
                $sev = 'Medium'
                if ($flags -match 'ForwardTo|ForwardAsAttachmentTo|RedirectTo|DeleteMessage|MoveToFolder') { $sev = 'High' }
                $cond = "From={0}; SubjectOrBodyContains={1}; SubjectContains={2}" -f ($r.From -join ','), ($r.SubjectOrBodyContainsWords -join ','), ($r.SubjectContainsWords -join ',')
                Add-Finding $sev 'Inbox Rule' ("{0}: '{1}'" -f $mbx, $r.Name) (("Enabled={0}; " -f $r.Enabled) + ($flags -join '; ') + '; ' + $cond) 'Attackers use inbox rules to exfiltrate mail and hide security / payment replies from the victim.' $null $src
            }
        }
        catch { Write-Log 'INFO' "Get-InboxRule ${mbx}: $($_.Exception.Message)" }
    }
    Save-Rows -Rows $script:Findings -FileName 'Findings-Exchange.csv' -SortProperty 'WhenUtc'
    Add-Coverage -Source 'Exchange current-state sweep' -Status 'OK' -Records $script:Findings.Count -Notes ("Mailboxes inspected: " + [math]::Min($targets.Count, $cap))
}

function Connect-M365PsForensicsExchange {
    param(
        [string]$UserPrincipalName,
        [string]$AppId,
        [string]$CertificateThumbprint,
        [string]$Organization,
        [switch]$UseDeviceCode,
        [switch]$DisableWAM
    )
    if (-not (Test-RequiredModule -Name 'ExchangeOnlineManagement' -MinVersion '3.0.0')) {
        return [pscustomobject]@{ Connected = $false; Error = 'ExchangeOnlineManagement module unavailable' }
    }
    try {
        $p = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($UserPrincipalName) { $p['UserPrincipalName'] = $UserPrincipalName }
        elseif ($script:Config.AdminUPN) { $p['UserPrincipalName'] = $script:Config.AdminUPN }
        if ($AppId -and $CertificateThumbprint -and $Organization) {
            $p['AppId'] = $AppId
            $p['CertificateThumbprint'] = ($CertificateThumbprint -replace '\s', '')
            $p['Organization'] = $Organization
        }
        $cmd = Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue
        if ($UseDeviceCode -and $cmd -and $cmd.Parameters.ContainsKey('Device')) { $p['Device'] = $true }
        if ($DisableWAM -and $cmd -and $cmd.Parameters.ContainsKey('DisableWAM')) { $p['DisableWAM'] = $true }
        Write-Log 'INFO' 'Connecting to Exchange Online (sign in with your IR / Global Reader account)...'
        Connect-ExchangeOnline @p
        $script:OpenedExo = $true
        Write-Log 'OK' 'Connected to Exchange Online.'
        return Get-M365PsForensicsConnectionState
    }
    catch {
        Write-Log 'ERROR' "Connect-ExchangeOnline failed: $($_.Exception.Message)"
        return [pscustomobject]@{ Connected = $false; Error = $_.Exception.Message }
    }
}

function Invoke-ExchangePhase {
    $conn = Get-M365PsForensicsConnectionState
    if (-not $conn.ExchangeConnected) {
        $conn = Connect-M365PsForensicsExchange -UserPrincipalName $script:Config.AdminUPN
        if (-not $conn.ExchangeConnected -and -not $conn.Connected) {
            Add-Coverage -Source 'Exchange Online' -Status 'ERROR' -From $script:StartUtc -To $script:EndUtc -Notes ([string]$conn.Error)
            return
        }
    }
    if ($script:StartUtc -lt $script:NowUtc.AddDays(-180)) {
        Write-Log 'WARN' 'Start date is older than 180 days: data beyond your audit retention (180 days Standard / 1 year+ Premium) will not exist.'
    }

    Write-InvestigationProgress 'Unified Audit Log' 'Collecting admin cmdlets' 10
    $adminRows = New-Object System.Collections.Generic.List[object]
    $tenantTypes = @('ExchangeAdmin', 'SecurityComplianceCenterEOPCmdlet', 'Discovery') + @($script:Config.AdditionalRecordTypes) | Where-Object { $_ } | Select-Object -Unique
    foreach ($rt in $tenantTypes) {
        Test-InvestigationCancel
        foreach ($x in (Invoke-UalCollection -Name $rt -RecordType $rt -From $script:StartUtc -To $script:EndUtc -Label 'Admin')) { $adminRows.Add($x) }
    }

    $highSignalOps = @('SiteCollectionAdminAdded', 'SiteCollectionAdminRemoved', 'SharingPolicyChanged', 'SiteAdminChangeRequest',
        'UpdateInboxRules', 'New-InboxRule', 'Set-InboxRule', 'AddFolderPermissions', 'UpdateFolderPermissions', 'CreateFlow', 'EditFlow',
        'TeamCreated', 'MemberAdded', 'MemberRemoved', 'AddedToRoster')
    Write-InvestigationProgress 'Unified Audit Log' 'High-signal operations' 25
    foreach ($x in (Invoke-UalCollection -Name 'HighSignalOperations' -Operations $highSignalOps -From $script:StartUtc -To $script:EndUtc -Label 'Admin')) {
        if ($x.RecordType -notmatch 'ExchangeAdmin') { $adminRows.Add($x) }
    }

    # Full-window Entra UAL so a later Graph failure cannot drop the last 30 days.
    Write-InvestigationProgress 'Unified Audit Log' 'Entra directory changes' 35
    if ($script:EndUtc -gt $script:StartUtc) {
        foreach ($x in (Invoke-UalCollection -Name 'AzureActiveDirectory' -RecordType 'AzureActiveDirectory' -From $script:StartUtc -To $script:EndUtc -Label 'Admin')) { $adminRows.Add($x) }
    }
    Save-Rows -Rows $adminRows -FileName 'Events-UAL-Admin.csv'

    $suspects = @($script:Config.SuspectUsers)
    if ($suspects.Count -gt 0) {
        Write-InvestigationProgress 'Unified Audit Log' 'Suspect sign-ins and activity' 45
        $signIns = Invoke-UalCollection -Name 'AzureActiveDirectoryStsLogon' -RecordType 'AzureActiveDirectoryStsLogon' -UserIds $suspects -From $script:StartUtc -To $script:EndUtc -Label 'Suspect' -Kind 'SignIn'
        Save-Rows -Rows $signIns -FileName 'SignIns-UAL-SuspectUsers.csv'
        if (-not $script:Config.SkipSuspectDataAccess) {
            $actRows = New-Object System.Collections.Generic.List[object]
            foreach ($rt in @('ExchangeItem', 'ExchangeItemAggregated', 'ExchangeItemGroup', 'SharePointFileOperation', 'SharePointSharingOperation', 'SharePoint', 'MicrosoftTeams', 'MicrosoftFlow')) {
                Test-InvestigationCancel
                foreach ($x in (Invoke-UalCollection -Name $rt -RecordType $rt -UserIds $suspects -From $script:StartUtc -To $script:EndUtc -Label 'SuspectActivity')) { $actRows.Add($x) }
            }
            Save-Rows -Rows $actRows -FileName 'Events-UAL-SuspectActivity.csv'
        }
    }
    else { Write-Log 'INFO' 'No -SuspectUsers supplied: per-account sign-in and data-access collection skipped (tenant-wide collection still performed).' }

    if (-not $script:Config.SkipCurrentState) { Invoke-ExchangeStateCollection -UalRows $adminRows.ToArray() }
    if (-not $script:Config.NoDisconnect) {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
        $script:OpenedExo = $false
    }
}
#endregion

#region Graph phase
function New-GraphUri {
    param([string]$Path, [System.Collections.Specialized.OrderedDictionary]$Query)
    $qs = @()
    foreach ($k in $Query.Keys) { $qs += ('{0}={1}' -f $k, [uri]::EscapeDataString([string]$Query[$k])) }
    return ('https://graph.microsoft.com/' + $Path + '?' + ($qs -join '&'))
}

function Get-GraphAll {
    param([string]$Uri, [int]$MaxItems = 0, [hashtable]$Headers = @{})
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    while ($next) {
        Test-InvestigationCancel
        $resp = Invoke-WithRetry -Activity 'Graph request' -Script { Invoke-MgGraphRequest -Method GET -Uri $next -Headers $Headers -OutputType PSObject -ErrorAction Stop }
        if ($resp.value) { foreach ($v in $resp.value) { $items.Add($v) } }
        $next = $resp.'@odata.nextLink'
        if ($MaxItems -gt 0 -and $items.Count -ge $MaxItems) {
            Write-Log 'WARN' ("Graph result capped at {0:N0} items for {1}" -f $MaxItems, (Limit-Text $Uri 120)); break
        }
    }
    return , $items.ToArray()
}

function ConvertFrom-GraphSignIn {
    param($S, [string]$Label)
    $appId = ([string]$S.appId).ToLowerInvariant()
    $err = [string]$S.status.errorCode
    $result = 'Success'; if ($err -and $err -ne '0') { $result = 'Failure' }
    $loc = (@($S.location.city, $S.location.state, $S.location.countryOrRegion) | Where-Object { $_ }) -join ', '
    $types = ''
    if ($S.signInEventTypes) { $types = @($S.signInEventTypes) -join ',' }
    elseif ($null -ne $S.isInteractive) { if ($S.isInteractive) { $types = 'interactiveUser' } else { $types = 'nonInteractiveUser' } }
    $user = [string]$S.userPrincipalName
    if (-not $user -and $S.servicePrincipalName) { $user = 'SP: ' + $S.servicePrincipalName }
    $ua = [string]$S.userAgent
    $tool = Get-ClientFromUserAgent $ua
    $psApp = 'No'
    if ($script:PowerShellApps.ContainsKey($appId) -or $tool -eq 'PowerShell') { $psApp = 'Yes' }
    elseif ($tool) { $psApp = 'Tooling' }
    elseif ($script:AbuseProneApps.ContainsKey($appId)) { $psApp = 'Abuse-prone client' }
    $appName = [string]$S.appDisplayName
    if (-not $appName) { $appName = Get-AppName $appId }
    return (New-SignInRow @{
            TimeUtc = (ConvertTo-UtcIso $S.createdDateTime); User = $user; Result = $result; ErrorCode = $err
            FailureReason = [string]$S.status.failureReason; AppName = $appName; AppId = $appId; PowerShellApp = $psApp
            IPAddress = (Format-Ip ([string]$S.ipAddress)); Location = $loc; Resource = [string]$S.resourceDisplayName
            UserAgent = (Limit-Text $ua 400); ClientTool = $tool; ClientAppUsed = [string]$S.clientAppUsed; SignInType = $types
            ConditionalAccess = [string]$S.conditionalAccessStatus; Risk = [string]$S.riskLevelDuringSignIn
            AuthRequirement = [string]$S.authenticationRequirement; Source = ('Graph-' + $Label); Id = [string]$S.id
        })
}

function ConvertFrom-GraphDirectoryAudit {
    param($D)
    $actor = ''; $ip = ''; $appId = ''
    if ($D.initiatedBy.user) {
        $actor = [string](Get-FirstValue $D.initiatedBy.user @('userPrincipalName', 'displayName', 'id'))
        $ip = [string]$D.initiatedBy.user.ipAddress
    }
    if ($D.initiatedBy.app) {
        $appId = ([string]$D.initiatedBy.app.appId).ToLowerInvariant()
        if (-not $actor) { $actor = 'App: ' + [string](Get-FirstValue $D.initiatedBy.app @('displayName', 'servicePrincipalName', 'appId')) }
    }
    $ua = ''
    foreach ($ad in @($D.additionalDetails)) { if ($ad -and $ad.key -eq 'User-Agent') { $ua = [string]$ad.value } }
    $targets = @(); $mods = @()
    foreach ($t in @($D.targetResources)) {
        if (-not $t) { continue }
        $targets += [string](Get-FirstValue $t @('userPrincipalName', 'displayName', 'id'))
        foreach ($m in @($t.modifiedProperties)) {
            if ($m -and $m.displayName) { $mods += ('{0}: {1} -> {2}' -f $m.displayName, (Limit-Text $m.oldValue 200), (Limit-Text $m.newValue 300)) }
        }
    }
    $ch = Get-ExecutionChannel -AppId $appId -UserAgent $ua -RecordType 'EntraDirectoryAudit'
    $row = New-EventRow @{
        TimeUtc           = (ConvertTo-UtcIso $D.activityDateTime)
        Operation         = [string]$D.activityDisplayName
        Outcome           = (Get-Outcome $D.result)
        Actor             = $actor
        ClientIP          = (Format-Ip $ip)
        Target            = ($targets -join '; ')
        Details           = (Limit-Text ((@(('Category=' + $D.category), ('Service=' + $D.loggedByService), ('Reason=' + $D.resultReason)) + $mods) -join ' | ') 2500)
        PowerShellRelated = $ch[0]
        ExecutionChannel  = $ch[1]
        AppId             = $appId
        UserAgent         = (Limit-Text $ua 400)
        Workload          = 'Entra ID'
        RecordType        = [string]$D.category
        Source            = 'Graph-DirectoryAudit'
        RecordId          = [string]$D.id
    }
    Set-Classification $row
    return $row
}

function Get-GraphSignIns {
    param([string]$Filter, [string]$Label, [string]$EventTypeClause = "(signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser'))")
    $items = $null; $note = 'interactive + non-interactive (beta)'
    try {
        $f = $Filter
        if ($EventTypeClause) { $f = $Filter + ' and ' + $EventTypeClause }
        $items = Get-GraphAll -Uri (New-GraphUri 'beta/auditLogs/signIns' ([ordered]@{ '$filter' = $f; '$top' = '999' })) -MaxItems $script:Config.MaxSignInsPerQuery
    }
    catch {
        Write-Log 'WARN' ("Beta sign-in query failed for {0} ({1}) - falling back to v1.0 interactive sign-ins only" -f $Label, (Limit-Text $_.Exception.Message 200))
        $note = 'interactive only (v1.0 fallback)'
        $items = Get-GraphAll -Uri (New-GraphUri 'v1.0/auditLogs/signIns' ([ordered]@{ '$filter' = $Filter; '$top' = '999' })) -MaxItems $script:Config.MaxSignInsPerQuery
    }
    return @($items, $note)
}

function Invoke-GraphStateCollection {
    $script:Findings.Clear()
    $src = 'Entra ID (current state)'
    Write-Log 'INFO' 'Entra current-state persistence sweep...'
    Write-InvestigationProgress 'Entra current state' 'Sweeping persistence' 85
    $privRoles = 'Global Administrator|Privileged Role Administrator|Privileged Authentication Administrator|Exchange Administrator|Application Administrator|Cloud Application Administrator|Security Administrator|SharePoint Administrator|User Administrator|Authentication Administrator|Hybrid Identity Administrator|Compliance Administrator|Conditional Access Administrator|Intune Administrator|Teams Administrator|Helpdesk Administrator|Directory Writers|Partner Tier2 Support'

    try {
        $roles = Get-GraphAll -Uri 'https://graph.microsoft.com/v1.0/directoryRoles'
        foreach ($role in $roles) {
            Test-InvestigationCancel
            $members = Get-GraphAll -Uri ('https://graph.microsoft.com/v1.0/directoryRoles/{0}/members?$select=id,displayName,userPrincipalName,appId' -f $role.id)
            foreach ($m in $members) {
                $type = ([string]$m.'@odata.type') -replace '#microsoft.graph.', ''
                $name = [string](Get-FirstValue $m @('userPrincipalName', 'displayName', 'id'))
                $sev = 'Info'
                if ($role.displayName -match $privRoles -and $type -eq 'servicePrincipal') { $sev = 'Medium' }
                if ($role.displayName -match 'Global Administrator|Privileged Role Administrator' -and $type -eq 'servicePrincipal') { $sev = 'High' }
                Add-Finding $sev 'Entra Privileged Role' ("{0}: {1}" -f $role.displayName, $name) ("MemberType={0}; ObjectId={1}; AppId={2}" -f $type, $m.id, $m.appId) 'Validate every member; attackers add accounts or service principals to admin roles for persistence. (PIM-eligible assignments are not listed here.)' $null $src
            }
        }
    }
    catch { Write-Log 'WARN' "Directory roles: $($_.Exception.Message)" }

    $spLookup = @{}
    $startIso = ConvertTo-UtcIso $script:StartUtc
    foreach ($kind in @('applications', 'servicePrincipals')) {
        try {
            $sel = 'id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials'
            if ($kind -eq 'servicePrincipals') { $sel = 'id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,passwordCredentials,keyCredentials' }
            $objs = Get-GraphAll -Uri (New-GraphUri ('v1.0/' + $kind) ([ordered]@{ '$select' = $sel; '$top' = '999' }))
            foreach ($o in $objs) {
                if ($kind -eq 'servicePrincipals') { $spLookup[[string]$o.id] = $o }
                $creds = @()
                foreach ($c in @($o.passwordCredentials)) { if ($c) { $creds += [pscustomobject]@{ T = 'Client secret'; C = $c } } }
                foreach ($c in @($o.keyCredentials)) { if ($c) { $creds += [pscustomobject]@{ T = 'Certificate'; C = $c } } }
                foreach ($cr in $creds) {
                    $st = ConvertTo-UtcIso $cr.C.startDateTime
                    if ($st -and [string]::CompareOrdinal($st, $startIso) -ge 0) {
                        Add-Finding 'Critical' ('App Credential (' + $kind + ')') ("{0}  (appId {1})" -f $o.displayName, $o.appId) ("{0}; KeyId={1}; Name={2}; Hint={3}; Start={4}; End={5}" -f $cr.T, $cr.C.keyId, $cr.C.displayName, $cr.C.hint, $st, (ConvertTo-UtcIso $cr.C.endDateTime)) 'Credential created inside the investigation window - confirm it is authorized; otherwise it is an app-only backdoor (T1098.001). Remove it and review service-principal sign-ins.' $st $src
                    }
                }
                if ($kind -eq 'applications') {
                    $cd = ConvertTo-UtcIso $o.createdDateTime
                    if ($cd -and [string]::CompareOrdinal($cd, $startIso) -ge 0) {
                        Add-Finding 'Medium' 'New Application Registration' ("{0}  (appId {1})" -f $o.displayName, $o.appId) ("Created=" + $cd) 'Application registered during the investigation window.' $cd $src
                    }
                }
            }
        }
        catch { Write-Log 'WARN' "$kind credential sweep: $($_.Exception.Message)" }
    }

    try {
        $riskyScopes = '(?i)\b(Mail\.Read|Mail\.ReadWrite|Mail\.Send|MailboxSettings\.ReadWrite|EWS\.AccessAsUser\.All|full_access_as_user|Files\.Read\.All|Files\.ReadWrite\.All|Sites\.Read\.All|Sites\.ReadWrite\.All|Sites\.FullControl\.All|Directory\.ReadWrite\.All|RoleManagement\.ReadWrite\.Directory|AppRoleAssignment\.ReadWrite\.All|Application\.ReadWrite\.All|User\.ReadWrite\.All|Notes\.Read\.All|Chat\.Read|Contacts\.Read)\b'
        foreach ($g in (Get-GraphAll -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999')) {
            if (-not ([string]$g.scope -match $riskyScopes)) { continue }
            $client = $spLookup[[string]$g.clientId]
            if ($client -and [string]$client.appOwnerOrganizationId -eq $script:MicrosoftTenantId) { continue }
            $clientName = [string]$g.clientId; if ($client) { $clientName = "{0} (appId {1})" -f $client.displayName, $client.appId }
            $res = [string]$g.resourceId; if ($spLookup.ContainsKey($res)) { $res = $spLookup[$res].displayName }
            $sev = 'Medium'; if ($g.consentType -eq 'AllPrincipals') { $sev = 'High' }
            Add-Finding $sev 'OAuth Delegated Grant' $clientName ("ConsentType={0}; Principal={1}; Resource={2}; Scopes={3}" -f $g.consentType, $g.principalId, $res, $g.scope) 'Third-party app holds delegated access to mail/files/directory - verify it was intentionally consented (illicit consent, T1528).' $null $src
        }
    }
    catch { Write-Log 'WARN' "OAuth grant sweep: $($_.Exception.Message)" }

    try {
        foreach ($d in (Get-GraphAll -Uri 'https://graph.microsoft.com/v1.0/domains')) {
            if (-not $d.isVerified) { Add-Finding 'Info' 'Domain' ([string]$d.id) 'Unverified domain present' 'Unexpected domains can be staging for a federation backdoor.' $null $src }
            if ($d.authenticationType -eq 'Federated') {
                try {
                    foreach ($fc in (Get-GraphAll -Uri ('https://graph.microsoft.com/v1.0/domains/{0}/federationConfiguration' -f $d.id))) {
                        $thumb = ''
                        foreach ($certB64 in @($fc.signingCertificate, $fc.nextSigningCertificate)) {
                            if (-not $certB64) { continue }
                            try {
                                $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String([string]$certB64))
                                $thumb += ("[{0} subject='{1}' notBefore={2:u}] " -f $x.Thumbprint, $x.Subject, $x.NotBefore.ToUniversalTime())
                            }
                            catch { }
                        }
                        Add-Finding 'High' 'Domain Federation' ([string]$d.id) ("IssuerUri={0}; PassiveSignInUri={1}; SigningCerts={2}; PreferredAuthProtocol={3}; MfaBehavior={4}" -f $fc.issuerUri, $fc.passiveSignInUri, $thumb, $fc.preferredAuthenticationProtocol, $fc.federatedIdpMfaBehavior) 'Verify the IdP URL and signing certificate belong to your organization. A rogue federation configuration lets the attacker forge tokens for ANY user (Golden SAML, T1484.002).' $null $src
                    }
                }
                catch { Write-Log 'WARN' "Federation config for $($d.id): $($_.Exception.Message)" }
            }
        }
    }
    catch { Write-Log 'WARN' "Domain sweep: $($_.Exception.Message)" }

    try {
        $uri = New-GraphUri 'v1.0/users' ([ordered]@{ '$filter' = ('createdDateTime ge ' + $startIso); '$select' = 'id,userPrincipalName,displayName,createdDateTime,userType,accountEnabled,creationType'; '$count' = 'true'; '$top' = '999' })
        foreach ($u in (Get-GraphAll -Uri $uri -Headers @{ ConsistencyLevel = 'eventual' })) {
            Add-Finding 'Medium' 'New Account' ([string]$u.userPrincipalName) ("DisplayName={0}; Type={1}; Enabled={2}; CreationType={3}; Created={4}" -f $u.displayName, $u.userType, $u.accountEnabled, $u.creationType, (ConvertTo-UtcIso $u.createdDateTime)) 'Account created during the investigation window - confirm it is legitimate (T1136.003).' $u.createdDateTime $src
        }
    }
    catch { Write-Log 'WARN' "New-account sweep: $($_.Exception.Message)" }

    Save-Rows -Rows $script:Findings -FileName 'Findings-Entra.csv' -SortProperty 'WhenUtc'
    Add-Coverage -Source 'Entra current-state sweep' -Status 'OK' -Records $script:Findings.Count
}

function Connect-M365PsForensicsGraph {
    param(
        [string]$TenantId,
        [string]$UserPrincipalName
    )
    if (-not (Test-RequiredModule -Name 'Microsoft.Graph.Authentication' -MinVersion '2.0.0')) {
        return [pscustomobject]@{ Connected = $false; Error = 'Microsoft.Graph.Authentication module unavailable' }
    }
    try {
        $scopes = @('AuditLog.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'Application.Read.All', 'Policy.Read.All', 'Domain.Read.All')
        $p = @{ Scopes = $scopes; ErrorAction = 'Stop' }
        if ($TenantId) { $p['TenantId'] = $TenantId }
        elseif ($script:Config.TenantId) { $p['TenantId'] = $script:Config.TenantId }
        if ($UserPrincipalName -and (Get-Command Connect-MgGraph).Parameters.ContainsKey('ContextScope')) { }
        if ((Get-Command Connect-MgGraph).Parameters.ContainsKey('NoWelcome')) { $p['NoWelcome'] = $true }
        Write-Log 'INFO' 'Connecting to Microsoft Graph...'
        Connect-MgGraph @p | Out-Null
        $script:OpenedGraph = $true
        $ctx = Get-MgContext
        Write-Log 'OK' ("Connected to Graph as {0} (tenant {1})" -f $ctx.Account, $ctx.TenantId)
        Add-Coverage -Source 'Tenant (Graph)' -Status 'INFO' -Notes ("TenantId=" + $ctx.TenantId + "; Investigator=" + $ctx.Account)
        return Get-M365PsForensicsConnectionState
    }
    catch {
        Write-Log 'ERROR' "Connect-MgGraph failed: $($_.Exception.Message)"
        return [pscustomobject]@{ Connected = $false; Error = $_.Exception.Message }
    }
}

function Disconnect-M365PsForensicsSessions {
    param([switch]$Force)
    if ($Force -or $script:OpenedExo) {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
        $script:OpenedExo = $false
    }
    if ($Force -or $script:OpenedGraph) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        $script:OpenedGraph = $false
    }
    return Get-M365PsForensicsConnectionState
}

function Invoke-GraphPhase {
    $conn = Get-M365PsForensicsConnectionState
    if (-not $conn.GraphConnected) {
        $conn = Connect-M365PsForensicsGraph -TenantId $script:Config.TenantId
        if (-not $conn.GraphConnected) {
            Add-Coverage -Source 'Microsoft Graph' -Status 'ERROR' -From $script:StartUtc -To $script:EndUtc -Notes ([string]$conn.Error)
            return
        }
    }

    $gFrom = $script:GraphCutoffUtc; $gTo = $script:EndUtc
    if ($gFrom -lt $gTo) {
        Write-InvestigationProgress 'Microsoft Graph' 'PowerShell client sign-ins' 65
        $sIso = ConvertTo-UtcIso $gFrom; $eIso = ConvertTo-UtcIso $gTo
        $win = "createdDateTime ge $sIso and createdDateTime le $eIso"
        $signIns = New-Object System.Collections.Generic.List[object]
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        $raw = $null
        try {
            $raw = New-Object System.IO.StreamWriter((Join-Path $script:RawPath 'Graph-SignIns.jsonl'), $false, (New-Object System.Text.UTF8Encoding($false)))
            $queries = New-Object System.Collections.Generic.List[object]
            foreach ($appId in $script:PowerShellApps.Keys) { $queries.Add(@(("appId eq '$appId' and " + $win), ('PowerShell app ' + $script:PowerShellApps[$appId]), $null)) }
            foreach ($u in @($script:Config.SuspectUsers)) { $queries.Add(@(("userPrincipalName eq '" + ($u -replace "'", "''") + "' and " + $win), ('Suspect user ' + $u), $null)) }
            if ($script:Config.IncludeServicePrincipalSignIns) { $queries.Add(@($win, 'All service principal sign-ins', "signInEventTypes/any(t: t eq 'servicePrincipal')")) }
            foreach ($q in $queries) {
                Test-InvestigationCancel
                try {
                    if ($null -eq $q[2]) { $res = Get-GraphSignIns -Filter $q[0] -Label $q[1] }
                    else { $res = Get-GraphSignIns -Filter $q[0] -Label $q[1] -EventTypeClause $q[2] }
                    $items = $res[0]; $count = 0
                    foreach ($s in $items) {
                        if (-not $seen.Add([string]$s.id)) { continue }
                        if ($raw) { $raw.WriteLine(($s | ConvertTo-Json -Depth 8 -Compress)) }
                        $signIns.Add((ConvertFrom-GraphSignIn $s 'SignIn')); $count++
                    }
                    Write-Log 'INFO' ("Graph sign-ins {0}: {1:N0}" -f $q[1], $count)
                    Add-Coverage -Source ('Entra sign-ins - ' + $q[1]) -Status 'OK' -Records $count -From $gFrom -To $gTo -Notes $res[1]
                }
                catch {
                    if (Test-IsCancelError $_) { throw }
                    $msg = $_.Exception.Message
                    if ($msg -match 'NonPremium|premium') { $msg = 'Sign-in logs require Entra ID P1/P2. ' + $msg }
                    Write-Log 'ERROR' ("Graph sign-ins {0}: {1}" -f $q[1], $msg)
                    Add-Coverage -Source ('Entra sign-ins - ' + $q[1]) -Status 'ERROR' -From $gFrom -To $gTo -Notes $msg
                }
            }
        }
        finally { if ($raw) { try { $raw.Close() } catch { } } }
        Save-Rows -Rows $signIns -FileName 'SignIns-Entra.csv'

        Write-InvestigationProgress 'Microsoft Graph' 'Directory audit log' 75
        $aRows = New-Object System.Collections.Generic.List[object]
        $rawA = $null
        try {
            $rawA = New-Object System.IO.StreamWriter((Join-Path $script:RawPath 'Graph-DirectoryAudits.jsonl'), $false, (New-Object System.Text.UTF8Encoding($false)))
            $uri = New-GraphUri 'v1.0/auditLogs/directoryAudits' ([ordered]@{ '$filter' = "activityDateTime ge $sIso and activityDateTime le $eIso"; '$top' = '999' })
            $audits = Get-GraphAll -Uri $uri -MaxItems $script:Config.MaxDirectoryAuditRecords
            foreach ($d in $audits) {
                if ($rawA) { $rawA.WriteLine(($d | ConvertTo-Json -Depth 8 -Compress)) }
                $aRows.Add((ConvertFrom-GraphDirectoryAudit $d))
            }
            Write-Log 'OK' ("Graph directory audits: {0:N0}" -f $aRows.Count)
            Add-Coverage -Source 'Entra directory audit log (Graph)' -Status 'OK' -Records $aRows.Count -From $gFrom -To $gTo
        }
        catch {
            if (Test-IsCancelError $_) { throw }
            Write-Log 'ERROR' "Directory audits: $($_.Exception.Message)"
            Add-Coverage -Source 'Entra directory audit log (Graph)' -Status 'ERROR' -From $gFrom -To $gTo -Notes $_.Exception.Message
        }
        finally { if ($rawA) { try { $rawA.Close() } catch { } } }
        Save-Rows -Rows $aRows -FileName 'Events-Entra-DirectoryAudit.csv'
    }
    else { Write-Log 'WARN' 'Investigation window ends more than 30 days ago - Graph sign-in/audit logs are out of retention; UAL is the only source.' }

    if (-not $script:Config.SkipCurrentState) { Invoke-GraphStateCollection }
    if (-not $script:Config.NoDisconnect) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        $script:OpenedGraph = $false
    }
}

function Install-M365PsForensicsModules {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $nuget) {
        Write-Log 'INFO' 'Installing the NuGet package provider...'
        Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
    }
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    foreach ($pair in @(@('ExchangeOnlineManagement', '3.0.0'), @('Microsoft.Graph.Authentication', '2.0.0'))) {
        Write-Log 'INFO' ("Installing {0} for the current user..." -f $pair[0])
        Install-Module -Name $pair[0] -MinimumVersion $pair[1] -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Import-Module -Name $pair[0] -MinimumVersion $pair[1] -ErrorAction Stop
        Write-Log 'OK' ("{0} is installed." -f $pair[0])
    }
    return Get-M365PsForensicsPrerequisite
}
#endregion

#region Report
function Get-TopValues {
    param($Values, [int]$Top = 5)
    $v = @($Values | Where-Object { $_ -and "$_".Trim() })
    if ($v.Count -eq 0) { return '' }
    return (@($v | Group-Object | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count }) -join '; ')
}

function Get-FirstLast {
    param($Values)
    $s = @($Values | Where-Object { $_ } | Sort-Object)
    if ($s.Count -eq 0) { return @('', '') }
    return @($s[0], $s[$s.Count - 1])
}

function New-InvestigationReport {
    Write-Log 'INFO' 'Building correlated timeline and interactive HTML report...'
    Write-InvestigationProgress 'Report' 'Correlating evidence' 90
    $events = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-ChildItem -LiteralPath $script:OutputPath -Filter 'Events-*.csv' -File -ErrorAction SilentlyContinue)) {
        foreach ($r in @(Import-Csv -LiteralPath $f.FullName)) { $events.Add($r) }
    }
    $signIns = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-ChildItem -LiteralPath $script:OutputPath -Filter 'SignIns-*.csv' -File -ErrorAction SilentlyContinue)) {
        foreach ($r in @(Import-Csv -LiteralPath $f.FullName)) { $signIns.Add($r) }
    }
    $findings = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $script:OutputPath -Filter 'Findings-*.csv' -File -ErrorAction SilentlyContinue)) { $findings += @(Import-Csv -LiteralPath $f.FullName) }
    $coverage = @()
    if ($script:CoverageFile -and (Test-Path -LiteralPath $script:CoverageFile)) { $coverage = @(Import-Csv -LiteralPath $script:CoverageFile) }

    $graphTimes = @($events | Where-Object { $_.Source -eq 'Graph-DirectoryAudit' } | ForEach-Object { $_.TimeUtc } | Sort-Object)
    if ($graphTimes.Count -gt 0) {
        $gMin = $graphTimes[0]
        $kept = New-Object System.Collections.Generic.List[object]
        foreach ($e in $events) {
            if (-not ($e.Source -eq 'UAL-Admin' -and $e.RecordType -eq 'AzureActiveDirectory' -and [string]::CompareOrdinal($e.TimeUtc, $gMin) -ge 0)) { $kept.Add($e) }
        }
        $events = $kept
    }
    $seenSi = New-Object 'System.Collections.Generic.HashSet[string]'
    $signIns = @($signIns | Where-Object { -not $_.Id -or $seenSi.Add($_.Id) })

    $psSi = @{}
    foreach ($s in $signIns) {
        if ($s.Result -eq 'Success' -and ($s.PowerShellApp -eq 'Yes' -or $s.PowerShellApp -eq 'Tooling') -and $s.User) {
            $k = $s.User.ToLowerInvariant()
            if (-not $psSi.ContainsKey($k)) { $psSi[$k] = New-Object System.Collections.Generic.List[object] }
            $psSi[$k].Add($s)
        }
    }
    foreach ($k in @($psSi.Keys)) { $psSi[$k] = @($psSi[$k] | Sort-Object TimeUtc) }
    $corrHours = [int]$script:Config.CorrelationWindowHours
    foreach ($e in $events) {
        if ($e.ClientIP -or $e.PowerShellRelated -ne 'Yes' -or -not $e.Actor) { continue }
        $k = $e.Actor.ToLowerInvariant()
        if (-not $psSi.ContainsKey($k)) { continue }
        $list = $psSi[$k]; $best = $null
        for ($i = $list.Count - 1; $i -ge 0; $i--) { if ([string]::CompareOrdinal($list[$i].TimeUtc, $e.TimeUtc) -le 0) { $best = $list[$i]; break } }
        if (-not $best) { continue }
        $et = ConvertFrom-UtcIso $e.TimeUtc; $bt = ConvertFrom-UtcIso $best.TimeUtc
        if ($null -eq $et -or $null -eq $bt) { continue }
        $gap = ($et - $bt).TotalHours
        if ($gap -le $corrHours) {
            $e.InferredIP = $best.IPAddress
            $locText = 'location n/a'
            if ($best.Location) { $locText = $best.Location }
            $appText = $best.AppName
            if (-not $appText) { $appText = $best.AppId }
            $e.InferredLocation = ('{0} via {1} (sign-in {2:N1}h earlier)' -f $locText, $appText, $gap)
            if ($e.InferredIP -and $script:SuspectIpSet.Contains($e.InferredIP)) {
                $e.SuspectMatch = (@($e.SuspectMatch, 'InferredIP') | Where-Object { $_ }) -join ','
                if ($script:SevRank[[string]$e.Severity] -lt 3) { $e.Severity = 'High' }
            }
        }
    }

    $sorted = @($events | Sort-Object TimeUtc)
    if ($sorted.Count -gt 0) { Export-EvidenceCsv -Rows $sorted -Path (Join-Path $script:OutputPath 'Timeline-Master.csv') }
    $desc = @($sorted)
    if ($desc.Count -gt 1) { [array]::Reverse($desc) }
    $sevSort = @{ Expression = { $script:SevRank[[string]$_.Severity] }; Descending = $true }, @{ Expression = 'TimeUtc'; Descending = $true }

    $psEvents = @($desc | Where-Object { $_.PowerShellRelated -eq 'Yes' -or $_.PowerShellRelated -eq 'Possible' })
    $keyEvents = @($desc | Where-Object { $script:SevRank[[string]$_.Severity] -ge 2 -or $_.SuspectMatch })
    $access = @($keyEvents | Where-Object { $_.AccessGained -and $_.Outcome -ne 'Failed' -and $script:SevRank[[string]$_.Severity] -ge 3 } | Sort-Object $sevSort)
    $failed = @($desc | Where-Object { $_.Outcome -eq 'Failed' -and ($script:SevRank[[string]$_.Severity] -ge 2 -or $_.SuspectMatch -or $_.PowerShellRelated -eq 'Yes') })
    $psSignIns = @($signIns | Where-Object { $_.PowerShellApp -ne 'No' -or $_.SuspectMatch } | Sort-Object TimeUtc -Descending)
    $psFailSignIns = @($psSignIns | Where-Object { $_.Result -eq 'Failure' })
    $suspectAct = @($events | Where-Object { $_.Source -eq 'UAL-SuspectActivity' })
    $findSorted = @($findings | Sort-Object @{ Expression = { $script:SevRank[[string]$_.Severity] }; Descending = $true }, Area)

    $tactics = foreach ($g in @($keyEvents | Where-Object { $script:SevRank[[string]$_.Severity] -ge 2 } | Group-Object Category)) {
        $fl = Get-FirstLast ($g.Group | ForEach-Object { $_.TimeUtc })
        $sevMax = @($g.Group | Sort-Object @{ Expression = { $script:SevRank[[string]$_.Severity] }; Descending = $true })[0].Severity
        [pscustomobject]@{
            Severity = $sevMax; Category = $g.Name; Mitre = (Get-TopValues ($g.Group | ForEach-Object { $_.Mitre }) 3)
            Events = $g.Count; Succeeded = @($g.Group | Where-Object { $_.Outcome -eq 'Succeeded' }).Count
            Failed = @($g.Group | Where-Object { $_.Outcome -eq 'Failed' }).Count; FirstUtc = $fl[0]; LastUtc = $fl[1]
            Actors = (Get-TopValues ($g.Group | ForEach-Object { $_.Actor }) 5); Operations = (Get-TopValues ($g.Group | ForEach-Object { $_.Operation }) 6)
        }
    }
    $tactics = @($tactics | Sort-Object @{ Expression = { $script:SevRank[[string]$_.Severity] }; Descending = $true }, @{ Expression = 'Events'; Descending = $true })

    $actors = foreach ($g in @($psEvents + @($keyEvents | Where-Object { $_.PowerShellRelated -ne 'System' }) | Where-Object { $_.Actor } | Sort-Object RecordId, TimeUtc -Unique | Group-Object Actor)) {
        $fl = Get-FirstLast ($g.Group | ForEach-Object { $_.TimeUtc })
        $isSus = ''; if ($script:SuspectUserSet.Contains($g.Name) -or @($g.Group | Where-Object { $_.SuspectMatch -match 'IP' }).Count) { $isSus = 'YES' }
        [pscustomobject]@{
            Actor = $g.Name; Suspect = $isSus; Events = $g.Count
            Critical = @($g.Group | Where-Object { $_.Severity -eq 'Critical' }).Count; High = @($g.Group | Where-Object { $_.Severity -eq 'High' }).Count
            Failed = @($g.Group | Where-Object { $_.Outcome -eq 'Failed' }).Count; FirstUtc = $fl[0]; LastUtc = $fl[1]
            IPs = (Get-TopValues ($g.Group | ForEach-Object { $_.ClientIP; $_.InferredIP }) 6)
            Channels = (Get-TopValues ($g.Group | ForEach-Object { $_.ExecutionChannel }) 3)
            TopOperations = (Get-TopValues ($g.Group | ForEach-Object { $_.Operation }) 8)
        }
    }
    $actors = @($actors | Sort-Object @{ Expression = 'Suspect'; Descending = $true }, @{ Expression = 'Critical'; Descending = $true }, @{ Expression = 'High'; Descending = $true }, @{ Expression = 'Events'; Descending = $true })

    $siSummary = foreach ($g in @($psSignIns | Group-Object User, AppName)) {
        $fl = Get-FirstLast ($g.Group | ForEach-Object { $_.TimeUtc })
        $first = $g.Group[0]
        $isSus = ''; if (@($g.Group | Where-Object { $_.SuspectMatch }).Count) { $isSus = 'YES' }
        [pscustomobject]@{
            User = $first.User; Client = $first.AppName; ClientClass = $first.PowerShellApp; Suspect = $isSus
            Success = @($g.Group | Where-Object { $_.Result -eq 'Success' }).Count; Failure = @($g.Group | Where-Object { $_.Result -eq 'Failure' }).Count
            FirstUtc = $fl[0]; LastUtc = $fl[1]; IPs = (Get-TopValues ($g.Group | ForEach-Object { $_.IPAddress }) 6)
            Locations = (Get-TopValues ($g.Group | ForEach-Object { $_.Location }) 4); Resources = (Get-TopValues ($g.Group | ForEach-Object { $_.Resource }) 5)
            UserAgents = (Get-TopValues ($g.Group | ForEach-Object { $_.UserAgent }) 2)
        }
    }
    $siSummary = @($siSummary | Sort-Object @{ Expression = 'Suspect'; Descending = $true }, @{ Expression = 'Success'; Descending = $true })

    $ipRows = New-Object System.Collections.Generic.List[object]
    foreach ($s in $psSignIns) { if ($s.IPAddress) { $ipRows.Add([pscustomobject]@{ IP = $s.IPAddress; Time = $s.TimeUtc; Who = $s.User; What = ('sign-in ' + $s.Result + ': ' + $s.AppName); Loc = $s.Location; Sus = $s.SuspectMatch }) } }
    foreach ($e in $keyEvents + $psEvents) {
        $ipv = $e.ClientIP; if (-not $ipv) { $ipv = $e.InferredIP }
        if ($ipv -and $e.PowerShellRelated -ne 'System') { $ipRows.Add([pscustomobject]@{ IP = $ipv; Time = $e.TimeUtc; Who = $e.Actor; What = $e.Operation; Loc = ''; Sus = $e.SuspectMatch }) }
    }
    $ipSummary = foreach ($g in @($ipRows | Group-Object IP)) {
        $fl = Get-FirstLast ($g.Group | ForEach-Object { $_.Time })
        $isSus = ''; if ($script:SuspectIpSet.Contains($g.Name) -or @($g.Group | Where-Object { $_.Sus -match 'User|Actor' }).Count) { $isSus = 'YES' }
        [pscustomobject]@{
            IPAddress = $g.Name; Suspect = $isSus; Activity = $g.Count; FirstUtc = $fl[0]; LastUtc = $fl[1]
            Accounts = (Get-TopValues ($g.Group | ForEach-Object { $_.Who }) 5); Locations = (Get-TopValues ($g.Group | ForEach-Object { $_.Loc }) 3)
            Activities = (Get-TopValues ($g.Group | ForEach-Object { $_.What }) 6)
        }
    }
    $ipSummary = @($ipSummary | Sort-Object @{ Expression = 'Suspect'; Descending = $true }, @{ Expression = 'Activity'; Descending = $true })

    $resourceSummary = foreach ($g in @($signIns | Where-Object { $_.SuspectMatch -or $_.PowerShellApp -in @('Yes', 'Tooling') } | Group-Object Resource, Result)) {
        $fl = Get-FirstLast ($g.Group | ForEach-Object { $_.TimeUtc })
        [pscustomobject]@{ Resource = $g.Group[0].Resource; Result = $g.Group[0].Result; Count = $g.Count; FirstUtc = $fl[0]; LastUtc = $fl[1]; Accounts = (Get-TopValues ($g.Group | ForEach-Object { $_.User }) 5); FailureReasons = (Get-TopValues ($g.Group | ForEach-Object { $_.FailureReason }) 3) }
    }
    $resourceSummary = @($resourceSummary | Sort-Object Count -Descending)

    $actSummary = foreach ($g in @($suspectAct | Group-Object Actor, Workload, Operation)) {
        $fl = Get-FirstLast ($g.Group | ForEach-Object { $_.TimeUtc })
        [pscustomobject]@{ Actor = $g.Group[0].Actor; Workload = $g.Group[0].Workload; Operation = $g.Group[0].Operation; Count = $g.Count; FirstUtc = $fl[0]; LastUtc = $fl[1]; IPs = (Get-TopValues ($g.Group | ForEach-Object { $_.ClientIP }) 5); Sample = (Limit-Text $g.Group[0].Details 300) }
    }
    $actSummary = @($actSummary | Sort-Object Count -Descending)

    $cats = @($access | ForEach-Object { $_.Category }) + @($findSorted | Where-Object { $script:SevRank[[string]$_.Severity] -ge 3 } | ForEach-Object { $_.Area })
    $catText = $cats -join ' | '
    $rec = New-Object System.Collections.Generic.List[string]
    if ($catText -match 'Federation') { $rec.Add('CRITICAL: Federation trust changed. Validate IssuerUri and signing certificates; if not yours, convert the domain back to managed authentication immediately - every account must be treated as compromised.') }
    if ($catText -match 'App/Service Principal Credential|App Credential') { $rec.Add('Remove unauthorized app/service-principal secrets and certificates, then review service-principal sign-ins (re-run with -IncludeServicePrincipalSignIns).') }
    if ($catText -match 'Entra Directory Role|Exchange/Purview RBAC|Impersonation') { $rec.Add('Remove role assignments granted by the attacker (Entra roles, PIM eligibility, Exchange RBAC, ApplicationImpersonation) and review what those identities did afterwards.') }
    if ($catText -match 'Forwarding|Inbox Rule|Transport Rule|Connector') { $rec.Add('Remove malicious forwarding, inbox/transport rules and connectors; run a message trace on the forwarding destinations to scope exfiltrated mail.') }
    if ($catText -match 'eDiscovery|Export') { $rec.Add('eDiscovery searches/exports were performed: treat the searched content as exfiltrated and engage legal/privacy for notification obligations.') }
    if ($catText -match 'Audit') { $rec.Add('Audit or alerting was tampered with: re-enable it immediately and treat the period it was disabled as an evidence gap.') }
    if ($catText -match 'OAuth') { $rec.Add('Revoke illicit OAuth grants and disable the offending service principals.') }
    if ($catText -match 'Password / MFA') { $rec.Add('Authentication methods were changed: remove attacker-registered MFA methods and re-register affected users in person.') }
    $rec.Add('For every compromised account: reset password, revoke sessions (Revoke-MgUserSignInSession), remove unknown MFA methods and devices, and block attacker IPs with a Conditional Access named location.')
    $rec.Add('Get-* (read-only) cmdlets are never audited by Microsoft - assume the attacker enumerated users, groups, mailboxes and permissions.')
    $rec.Add('Preserve this folder unmodified (hashes in Evidence-Manifest.csv) and export the Purview audit search for the same window as a secondary copy.')

    $cnt = @{
        Commands = $psEvents.Count; Critical = @($keyEvents | Where-Object { $_.Severity -eq 'Critical' }).Count; High = @($keyEvents | Where-Object { $_.Severity -eq 'High' }).Count
        Access = $access.Count; Failed = $failed.Count; PsSignIns = @($psSignIns | Where-Object { $_.Result -eq 'Success' }).Count; PsFail = $psFailSignIns.Count
        Actors = $actors.Count; IPs = $ipSummary.Count; FindCrit = @($findSorted | Where-Object { $script:SevRank[[string]$_.Severity] -ge 3 }).Count
        Events = $sorted.Count; SignIns = $signIns.Count; Findings = $findSorted.Count
    }
    $tenantNotes = (@($coverage | Where-Object { $_.Source -like 'Tenant*' } | ForEach-Object { $_.Notes } | Select-Object -Unique) -join ' | ')
    $errCount = @($coverage | Where-Object { $_.Status -eq 'ERROR' }).Count
    $maxEmbed = [int]$script:Config.MaxReportEvents
    if ($maxEmbed -lt 500) { $maxEmbed = 12000 }
    $embedEvents = @($desc)
    $truncated = $false
    if ($embedEvents.Count -gt $maxEmbed) {
        $embedEvents = $embedEvents[0..($maxEmbed - 1)]
        $truncated = $true
    }

    $payload = [ordered]@{
        meta = [ordered]@{
            StartUtc = (ConvertTo-UtcIso $script:StartUtc)
            EndUtc = (ConvertTo-UtcIso $script:EndUtc)
            GeneratedUtc = (ConvertTo-UtcIso (Get-Date))
            Version = $script:ScriptVersion
            User = [string]$env:USERNAME
            Computer = [string]$env:COMPUTERNAME
            Suspects = @($script:Config.SuspectUsers)
            SuspectIPs = @($script:Config.SuspectIPs)
            Tenant = $tenantNotes
            CorrelationHours = $corrHours
            Errors = $errCount
            Truncated = $truncated
            EmbeddedEvents = $embedEvents.Count
            TotalEvents = $sorted.Count
        }
        counts = $cnt
        recs = @($rec)
        notes = @(
            'Exchange Online / Purview cmdlets are logged with full parameters, but Get-* (read) cmdlets are never logged.',
            ('Entra, SharePoint, Teams and Az PowerShell do not log command text; the resulting change plus the PowerShell-client sign-in is shown instead. "InferredIP" links a cmdlet to the same actor''s preceding PowerShell sign-in within ' + $corrHours + ' hours - treat it as a lead, not proof.'),
            '"Cmdlet - PowerShell or Admin Center" means Microsoft did not record which interface was used; the Exchange Admin Center also executes cmdlets.',
            'Entra sign-in and directory audit logs via Graph cover the last 30 days only; older Entra changes come from the Unified Audit Log.',
            'All times are UTC. Raw source records are preserved in the raw\ folder; hashes are in Evidence-Manifest.csv.',
            'Click a row for the full command. Click an actor, IP, or category to pivot. Press / to search, Esc to clear, j/k to move, c to copy the command.'
        )
        events = @($embedEvents | ForEach-Object { ConvertTo-JsonMap $_ $script:EventColumns })
        signIns = @($psSignIns | ForEach-Object { ConvertTo-JsonMap $_ $script:SignInColumns })
        findings = @($findSorted | ForEach-Object { ConvertTo-JsonMap $_ $script:FindingColumns })
        coverage = @($coverage | ForEach-Object { ConvertTo-JsonMap $_ @('RunUtc', 'Source', 'Status', 'Records', 'FromUtc', 'ToUtc', 'Notes') })
        tactics = @($tactics | ForEach-Object { ConvertTo-JsonMap $_ @('Severity', 'Category', 'Mitre', 'Events', 'Succeeded', 'Failed', 'FirstUtc', 'LastUtc', 'Actors', 'Operations') })
        actors = @($actors | ForEach-Object { ConvertTo-JsonMap $_ @('Actor', 'Suspect', 'Events', 'Critical', 'High', 'Failed', 'FirstUtc', 'LastUtc', 'IPs', 'Channels', 'TopOperations') })
        siSummary = @($siSummary | ForEach-Object { ConvertTo-JsonMap $_ @('User', 'Client', 'ClientClass', 'Suspect', 'Success', 'Failure', 'FirstUtc', 'LastUtc', 'IPs', 'Locations', 'Resources', 'UserAgents') })
        ipSummary = @($ipSummary | ForEach-Object { ConvertTo-JsonMap $_ @('IPAddress', 'Suspect', 'Activity', 'FirstUtc', 'LastUtc', 'Accounts', 'Locations', 'Activities') })
        resources = @($resourceSummary | ForEach-Object { ConvertTo-JsonMap $_ @('Resource', 'Result', 'Count', 'FirstUtc', 'LastUtc', 'Accounts', 'FailureReasons') })
        activity = @($actSummary | ForEach-Object { ConvertTo-JsonMap $_ @('Actor', 'Workload', 'Operation', 'Count', 'FirstUtc', 'LastUtc', 'IPs', 'Sample') })
        access = @($access | ForEach-Object { ConvertTo-JsonMap $_ $script:EventColumns })
    }
    $json = ConvertTo-ReportJson $payload
    $html = Get-InteractiveReportHtml -Json $json
    $reportPath = Join-Path $script:OutputPath 'Investigation-Report.html'
    [System.IO.File]::WriteAllText($reportPath, $html, (New-Object System.Text.UTF8Encoding($true)))
    Write-Log 'OK' "Interactive report written: $reportPath"
    return $reportPath
}

function Get-InteractiveReportHtml {
    param([string]$Json)
    $css = @'
:root{--bg:#f4f6f9;--fg:#111827;--mut:#6b7280;--card:#fff;--bd:#e5e7eb;--crit:#b91c1c;--high:#c2410c;--med:#a16207;--low:#1d4ed8;--info:#4b5563;--acc:#0f172a;--chip:#e2e8f0;--sel:#0f172a}
.dark{--bg:#0b1220;--fg:#e5e7eb;--mut:#94a3b8;--card:#111827;--bd:#1f2937;--chip:#1f2937;--sel:#38bdf8;--acc:#020617}
*{box-sizing:border-box}html,body{margin:0;height:100%}body{font-family:Segoe UI,system-ui,sans-serif;background:var(--bg);color:var(--fg);font-size:13px;line-height:1.45}
header{background:var(--acc);color:#fff;padding:18px 24px 12px}header h1{margin:0 0 4px;font-size:20px}header .sub{color:#cbd5e1;margin:2px 0;font-size:12px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}
input[type=search],select{padding:7px 10px;border:1px solid var(--bd);border-radius:6px;font:inherit;background:var(--card);color:var(--fg)}
input[type=search]{min-width:280px;flex:1}
.btn{border:1px solid var(--bd);background:var(--card);color:var(--fg);border-radius:6px;padding:6px 10px;cursor:pointer;font:inherit}
.btn:hover{border-color:#93c5fd}
nav.tabs{display:flex;gap:4px;flex-wrap:wrap;padding:10px 24px 0;background:var(--bg);position:sticky;top:0;z-index:5;border-bottom:1px solid var(--bd)}
nav.tabs button{border:0;background:transparent;color:var(--mut);padding:8px 12px;border-bottom:2px solid transparent;cursor:pointer;font:inherit}
nav.tabs button.on{color:var(--fg);border-bottom-color:var(--sel);font-weight:600}
main{padding:16px 24px 80px;max-width:1800px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:12px;cursor:pointer}
.card .n{font-size:24px;font-weight:700}.card .l{color:var(--mut);font-size:11px}
.card.crit .n{color:var(--crit)}.card.high .n{color:var(--high)}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0}
.chip{background:var(--chip);border:1px solid var(--bd);border-radius:999px;padding:3px 10px;cursor:pointer;font-size:12px}
.chip.on{background:var(--sel);color:#fff;border-color:var(--sel)}
.tw{overflow:auto;max-height:62vh;border:1px solid var(--bd);border-radius:6px;background:var(--card)}
table{border-collapse:collapse;width:100%}th{position:sticky;top:0;background:#f1f5f9;text-align:left;padding:7px 8px;border-bottom:1px solid var(--bd);white-space:nowrap;cursor:pointer}
.dark th{background:#1e293b}td{padding:6px 8px;border-bottom:1px solid var(--bd);vertical-align:top;max-width:420px;word-break:break-word}
tr:hover td{background:rgba(56,189,248,.08)}tr.sel td{outline:2px solid var(--sel)}
tr.sev-critical td{background:#fef2f2}.dark tr.sev-critical td{background:#3f1212}
tr.sev-high td{background:#fff7ed}.dark tr.sev-high td{background:#3b2710}
tr.suspect td:first-child{box-shadow:inset 4px 0 0 #7c3aed}
code,pre{font-family:Consolas,ui-monospace,monospace;font-size:12px;white-space:pre-wrap}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:600}
.b-critical{background:var(--crit)}.b-high{background:var(--high)}.b-medium{background:var(--med)}.b-low{background:var(--low)}.b-info{background:var(--info)}
.note,.empty,.pager{color:var(--mut);margin:8px 0}
.pager button{margin-right:6px}
.detail{position:fixed;right:0;top:0;height:100%;width:min(520px,46vw);background:var(--card);border-left:1px solid var(--bd);padding:16px 18px;overflow:auto;transform:translateX(110%);transition:transform .15s;z-index:20;box-shadow:0 0 24px rgba(0,0,0,.2)}
.detail.open{transform:none}.detail h3{margin:0 0 8px}.kv{margin:6px 0}.kv b{display:inline-block;min-width:120px;color:var(--mut)}
.warn{background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;padding:10px 14px;margin:8px 0}
.dark .warn{background:#3b2f0b;border-color:#a16207}
ul{margin:6px 0 0 18px}li{margin:3px 0}
.hide{display:none}
'@
    $js = @'
(function(){
  var D = JSON.parse(document.getElementById("report-data").textContent);
  var S = {q:"", sev:"", cat:"", actor:"", ip:"", ps:"", suspect:false, sort:"TimeUtc", dir:-1, page:1, size:100, tab:"commands", row:-1};
  var TABS = [
    ["commands","Commands"],["timeline","Timeline"],["access","Access gained"],["path","Attack path"],
    ["actors","Actors"],["signins","Sign-ins"],["ips","IPs"],["failed","Failed"],["findings","Persistence"],["coverage","Coverage"]
  ];
  function $(id){ return document.getElementById(id); }
  function lc(v){ return (v||"").toString().toLowerCase(); }
  function enc(v){ return String(v==null?"":v).replace(/[&<>"']/g, function(c){ return ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]); }); }
  function badge(sev){ if(!sev) return ""; return '<span class="badge b-'+enc(lc(sev))+'">'+enc(sev)+'</span>'; }
  function blob(row){ var k, s=[]; for(k in row){ if(Object.prototype.hasOwnProperty.call(row,k)) s.push(row[k]); } return s.join(" ").toLowerCase(); }
  function matchEvent(r){
    if(S.sev && lc(r.Severity)!==lc(S.sev)) return false;
    if(S.cat && lc(r.Category)!==lc(S.cat)) return false;
    if(S.actor && lc(r.Actor)!==lc(S.actor)) return false;
    if(S.ip && lc(r.ClientIP)!==lc(S.ip) && lc(r.InferredIP)!==lc(S.ip) && lc(r.IPAddress)!==lc(S.ip)) return false;
    if(S.ps==="yes" && r.PowerShellRelated!=="Yes" && r.PowerShellRelated!=="Possible") return false;
    if(S.ps==="cmd" && !(r.CommandLine||"").length) return false;
    if(S.suspect && !r.SuspectMatch) return false;
    if(S.q && blob(r).indexOf(S.q)<0) return false;
    return true;
  }
  function sortRows(rows, key){
    var dir = S.dir, sev = {critical:4,high:3,medium:2,low:1,info:0};
    rows.sort(function(a,b){
      var va=a[key], vb=b[key];
      if(key==="Severity"){ va=sev[lc(va)]||0; vb=sev[lc(vb)]||0; }
      if(va<vb) return -1*dir; if(va>vb) return 1*dir; return 0;
    });
    return rows;
  }
  function page(rows){
    var start=(S.page-1)*S.size;
    return {total:rows.length, slice:rows.slice(start, start+S.size), pages: Math.max(1, Math.ceil(rows.length/S.size))};
  }
  function setTab(id){ S.tab=id; S.page=1; S.row=-1; render(); }
  function setFilter(k,v){
    if(S[k]===v) S[k]=""; else S[k]=v;
    S.page=1; render();
  }
  function copyCmd(text){
    if(!text) return;
    if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(text); }
    else { var t=document.createElement("textarea"); t.value=text; document.body.appendChild(t); t.select(); try{ document.execCommand("copy"); }catch(e){} document.body.removeChild(t); }
  }
  function showDetail(row){
    var d=$("detail"), h=["<h3>Event detail</h3>","<button class='btn' onclick='window._irCloseDetail()'>Close</button>"];
    if(!row){ d.className="detail"; d.innerHTML=""; return; }
    var keys=["TimeUtc","Severity","Category","Operation","Outcome","Actor","ClientIP","InferredIP","InferredLocation","Target","TargetIdentity","CommandLine","Details","AccessGained","Mitre","PowerShellRelated","ExecutionChannel","AppId","UserAgent","SuspectMatch","Workload","RecordType","Source","RecordId"];
    keys.forEach(function(k){ if(row[k]) h.push('<div class="kv"><b>'+enc(k)+'</b> '+(k==="CommandLine"?"<pre><code>"+enc(row[k])+"</code></pre>":enc(row[k]))+"</div>"); });
    if(row.CommandLine) h.push("<p><button class='btn' onclick='window._irCopy()'>Copy command</button></p>");
    d.innerHTML=h.join(""); d.className="detail open"; window._irCopy=function(){ copyCmd(row.CommandLine||row.Operation||""); };
    window._irCloseDetail=function(){ d.className="detail"; };
  }
  function table(id, rows, cols, opts){
    opts=opts||{};
    var filtered=rows.filter(opts.match||function(){return true;});
    if(opts.sortKey) sortRows(filtered, S.sort && filtered[0] && filtered[0][S.sort]!==undefined ? S.sort : opts.sortKey);
    else sortRows(filtered, S.sort);
    var pg=page(filtered);
    var html=["<p class='note'>"+pg.total.toLocaleString()+" matching row(s)</p>"];
    if(!pg.total){ html.push("<p class='empty'>No records match the current filters.</p>"); $(id).innerHTML=html.join(""); return filtered; }
    html.push("<div class='tw'><table><thead><tr>");
    cols.forEach(function(c){ html.push("<th data-col='"+enc(c)+"'>"+enc(c)+"</th>"); });
    html.push("</tr></thead><tbody>");
    pg.slice.forEach(function(r,i){
      var cls=[];
      if(r.Severity) cls.push("sev-"+lc(r.Severity));
      if(r.SuspectMatch) cls.push("suspect");
      html.push("<tr class='"+cls.join(" ")+"' data-i='"+i+"'>");
      cols.forEach(function(c){
        var v=r[c]||"";
        if(c==="Severity") html.push("<td>"+badge(v)+"</td>");
        else if(c==="CommandLine") html.push("<td><code>"+enc(v)+"</code></td>");
        else if(c==="Actor"||c==="User") html.push("<td class='clk-actor'>"+enc(v)+"</td>");
        else if(c==="ClientIP"||c==="InferredIP"||c==="IPAddress") html.push("<td class='clk-ip'>"+enc(v)+"</td>");
        else if(c==="Category") html.push("<td class='clk-cat'>"+enc(v)+"</td>");
        else html.push("<td>"+enc(v)+"</td>");
      });
      html.push("</tr>");
    });
    html.push("</tbody></table></div>");
    html.push("<div class='pager'><button data-p='prev'>Prev</button> Page "+S.page+" / "+pg.pages+" <button data-p='next'>Next</button> <select data-size='1'><option>50</option><option>100</option><option>250</option><option>500</option></select> per page</div>");
    $(id).innerHTML=html.join("");
    $(id).querySelector("select").value=String(S.size);
    $(id).querySelector("select").onchange=function(){ S.size=parseInt(this.value,10)||100; S.page=1; render(); };
    $(id).querySelectorAll("th").forEach(function(th){
      th.onclick=function(){ var col=th.getAttribute("data-col"); if(S.sort===col) S.dir=-S.dir; else { S.sort=col; S.dir=1; } render(); };
    });
    $(id).querySelectorAll("tbody tr").forEach(function(tr,i){
      tr.onclick=function(){ showDetail(pg.slice[i]); };
    });
    $(id).querySelectorAll(".clk-actor").forEach(function(td){ td.onclick=function(ev){ ev.stopPropagation(); if(td.textContent) setFilter("actor", td.textContent); }; });
    $(id).querySelectorAll(".clk-ip").forEach(function(td){ td.onclick=function(ev){ ev.stopPropagation(); if(td.textContent) setFilter("ip", td.textContent); }; });
    $(id).querySelectorAll(".clk-cat").forEach(function(td){ td.onclick=function(ev){ ev.stopPropagation(); if(td.textContent) setFilter("cat", td.textContent); }; });
    $(id).querySelectorAll("button[data-p]").forEach(function(b){
      b.onclick=function(){ if(b.getAttribute("data-p")==="next") S.page=Math.min(pg.pages,S.page+1); else S.page=Math.max(1,S.page-1); render(); };
    });
    return filtered;
  }
  function fillSelect(sel, values, current){
    var u={}, list=["(any)"];
    values.forEach(function(v){ if(v && !u[v]){ u[v]=1; list.push(v); } });
    sel.innerHTML=list.map(function(v){ return "<option"+(v===current?" selected":"")+">"+enc(v)+"</option>"; }).join("");
  }
  function render(){
    document.body.className = localStorage.getItem("m365ps-dark")==="1" ? "dark" : "";
    $("meta").innerHTML = "Window: "+enc(D.meta.StartUtc)+" → "+enc(D.meta.EndUtc)+" (UTC) &nbsp;|&nbsp; Generated "+enc(D.meta.GeneratedUtc)+" by "+enc(D.meta.User)+" on "+enc(D.meta.Computer)+" &nbsp;|&nbsp; v"+enc(D.meta.Version);
    $("tenant").textContent = "Tenant: "+(D.meta.Tenant||"(not recorded)");
    $("suspects").textContent = "Suspect accounts: "+((D.meta.Suspects||[]).join(", ")||"(none)")+"  |  Suspect IPs: "+((D.meta.SuspectIPs||[]).join(", ")||"(none)");
    var nav=$("tabs"); nav.innerHTML="";
    TABS.forEach(function(t){ var b=document.createElement("button"); b.textContent=t[1]; if(S.tab===t[0]) b.className="on"; b.onclick=function(){ setTab(t[0]); }; nav.appendChild(b); });
    var cards=[
      ["",D.counts.Commands,"PowerShell / cmdlet events","ps","yes"],
      ["crit",D.counts.Critical,"Critical events","sev","Critical"],
      ["high",D.counts.High,"High events","sev","High"],
      ["crit",D.counts.Access,"Access-gaining actions","tab","access"],
      ["high",D.counts.Failed,"Failed attempts","tab","failed"],
      ["",D.counts.PsSignIns,"Successful PS/tool sign-ins","tab","signins"],
      ["high",D.counts.PsFail,"Failed PS/tool sign-ins","tab","signins"],
      ["",D.counts.Actors,"Actors","tab","actors"],
      ["",D.counts.IPs,"Source IPs","tab","ips"],
      ["crit",D.counts.FindCrit,"High/Critical persistence","tab","findings"]
    ];
    $("cards").innerHTML=cards.map(function(c){ return '<div class="card '+c[0]+'" data-k="'+c[3]+'" data-v="'+c[4]+'"><div class="n">'+(c[1]||0).toLocaleString()+'</div><div class="l">'+c[2]+'</div></div>'; }).join("");
    $("cards").querySelectorAll(".card").forEach(function(el){
      el.onclick=function(){
        var k=el.getAttribute("data-k"), v=el.getAttribute("data-v");
        if(k==="tab") setTab(v);
        else { S[k]=S[k]===v?"":v; S.page=1; if(k==="ps"||k==="sev") S.tab="commands"; render(); }
      };
    });
    $("recs").innerHTML="<h2>Priority actions</h2><ul>"+(D.recs||[]).map(function(r){ return "<li>"+enc(r)+"</li>"; }).join("")+"</ul>";
    if(D.meta.Errors) $("gaps").innerHTML="<div class='warn'><b>Collection gaps:</b> "+D.meta.Errors+" source(s) reported errors. Absence of evidence from those sources is not evidence of absence.</div>";
    else $("gaps").innerHTML="";
    if(D.meta.Truncated) $("trunc").innerHTML="<p class='note'>Interactive view embeds "+D.meta.EmbeddedEvents.toLocaleString()+" of "+D.meta.TotalEvents.toLocaleString()+" events. Full set is in Timeline-Master.csv.</p>";
    else $("trunc").innerHTML="";
    $("q").value=S.q;
    fillSelect($("sev"), ["Critical","High","Medium","Low","Info"], S.sev||"(any)");
    var cats=(D.events||[]).map(function(e){ return e.Category; });
    fillSelect($("cat"), cats.filter(function(v,i){ return cats.indexOf(v)===i; }).sort(), S.cat||"(any)");
    $("psOnly").className = "chip"+(S.ps==="yes"?" on":"");
    $("cmdOnly").className = "chip"+(S.ps==="cmd"?" on":"");
    $("susOnly").className = "chip"+(S.suspect?" on":"");
    ["overview","commands","timeline","access","path","actors","signins","ips","failed","findings","coverage"].forEach(function(t){
      var n=$("view-"+t); if(n) n.className = (S.tab===t || (t==="overview" && S.tab==="commands" && false)) ? "" : "hide";
    });
    $("view-overview").className = (S.tab==="commands") ? "" : "hide";
    var eventMatch=matchEvent;
    if(S.tab==="commands"){
      $("view-commands").className="";
      table("tbl-commands", D.events||[], ["TimeUtc","Severity","Actor","CommandLine","Operation","Outcome","ClientIP","InferredIP","Target","ExecutionChannel","UserAgent","SuspectMatch"], {match:function(r){ return eventMatch(r) && (S.ps?true:(r.PowerShellRelated==="Yes"||r.PowerShellRelated==="Possible"||(r.CommandLine||""))); }});
    } else $("view-commands").className="hide";
    if(S.tab==="timeline"){ $("view-timeline").className=""; table("tbl-timeline", D.events||[], ["TimeUtc","Severity","Category","Operation","Outcome","Actor","ClientIP","InferredIP","Target","CommandLine","SuspectMatch","Source"], {match:function(r){ return eventMatch(r) && (({Critical:1,High:1,Medium:1}[r.Severity]) || r.SuspectMatch); }}); } else $("view-timeline").className="hide";
    if(S.tab==="access"){ $("view-access").className=""; table("tbl-access", D.access||[], ["TimeUtc","Severity","Category","AccessGained","Actor","ClientIP","Target","CommandLine","ExecutionChannel","Mitre"], {match:eventMatch}); } else $("view-access").className="hide";
    if(S.tab==="path"){ $("view-path").className=""; table("tbl-path", D.tactics||[], ["Severity","Category","Mitre","Events","Succeeded","Failed","FirstUtc","LastUtc","Actors","Operations"], {match:function(r){ return !S.q || blob(r).indexOf(S.q)>=0; }}); } else $("view-path").className="hide";
    if(S.tab==="actors"){ $("view-actors").className=""; table("tbl-actors", D.actors||[], ["Actor","Suspect","Events","Critical","High","Failed","FirstUtc","LastUtc","IPs","Channels","TopOperations"], {match:function(r){ return (!S.q || blob(r).indexOf(S.q)>=0) && (!S.suspect || r.Suspect==="YES"); }}); } else $("view-actors").className="hide";
    if(S.tab==="signins"){ $("view-signins").className=""; table("tbl-signins", D.signIns||[], ["TimeUtc","User","Result","AppName","PowerShellApp","IPAddress","Location","ErrorCode","FailureReason","Resource","UserAgent","SuspectMatch"], {match:function(r){ return matchEvent(r); }}); } else $("view-signins").className="hide";
    if(S.tab==="ips"){ $("view-ips").className=""; table("tbl-ips", D.ipSummary||[], ["IPAddress","Suspect","Activity","FirstUtc","LastUtc","Accounts","Locations","Activities"], {match:function(r){ return (!S.q || blob(r).indexOf(S.q)>=0) && (!S.ip || r.IPAddress===S.ip) && (!S.suspect || r.Suspect==="YES"); }}); } else $("view-ips").className="hide";
    if(S.tab==="failed"){ $("view-failed").className=""; table("tbl-failed", D.events||[], ["TimeUtc","Severity","Category","AccessGained","Operation","Actor","ClientIP","Target","CommandLine","Details"], {match:function(r){ return eventMatch(r) && r.Outcome==="Failed"; }}); } else $("view-failed").className="hide";
    if(S.tab==="findings"){ $("view-findings").className=""; table("tbl-findings", D.findings||[], ["Severity","Area","Item","Detail","Reason","WhenUtc","SuspectMatch"], {match:function(r){ return (!S.sev || lc(r.Severity)===lc(S.sev)) && (!S.q || blob(r).indexOf(S.q)>=0) && (!S.suspect || r.SuspectMatch); }}); } else $("view-findings").className="hide";
    if(S.tab==="coverage"){ $("view-coverage").className=""; table("tbl-coverage", D.coverage||[], ["RunUtc","Source","Status","Records","FromUtc","ToUtc","Notes"], {match:function(r){ return !S.q || blob(r).indexOf(S.q)>=0; }}); } else $("view-coverage").className="hide";
    $("notes").innerHTML="<h2>Interpretation notes</h2><ul>"+(D.notes||[]).map(function(n){ return "<li>"+enc(n)+"</li>"; }).join("")+"</ul>";
  }
  $("q").addEventListener("input", function(){ S.q=this.value.toLowerCase(); S.page=1; render(); });
  $("sev").addEventListener("change", function(){ S.sev=this.value==="(any)"?"":this.value; S.page=1; render(); });
  $("cat").addEventListener("change", function(){ S.cat=this.value==="(any)"?"":this.value; S.page=1; render(); });
  $("psOnly").onclick=function(){ S.ps=S.ps==="yes"?"":"yes"; S.page=1; render(); };
  $("cmdOnly").onclick=function(){ S.ps=S.ps==="cmd"?"":"cmd"; S.page=1; render(); };
  $("susOnly").onclick=function(){ S.suspect=!S.suspect; S.page=1; render(); };
  $("clear").onclick=function(){ S.q=""; S.sev=""; S.cat=""; S.actor=""; S.ip=""; S.ps=""; S.suspect=false; S.page=1; render(); };
  $("dark").onclick=function(){ var on=document.body.className==="dark"; localStorage.setItem("m365ps-dark", on?"0":"1"); render(); };
  document.addEventListener("keydown", function(e){
    if(e.key==="/" && document.activeElement.tagName!=="INPUT"){ e.preventDefault(); $("q").focus(); }
    if(e.key==="Escape"){ S.q=""; S.actor=""; S.ip=""; S.cat=""; showDetail(null); render(); }
    if(e.key==="c" && document.activeElement.tagName!=="INPUT"){ var d=$("detail"); if(d.className.indexOf("open")>=0 && window._irCopy) window._irCopy(); }
  });
  S.ps="yes";
  render();
})();
'@
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>M365 PowerShell Breach Investigation</title><style>')
    [void]$sb.Append($css)
    [void]$sb.Append('</style></head><body><header><h1>Microsoft 365 PowerShell &amp; Admin Activity &mdash; Interactive Investigation</h1>')
    [void]$sb.Append('<div class="sub" id="meta"></div><div class="sub" id="tenant"></div><div class="sub" id="suspects"></div>')
    [void]$sb.Append('<div class="toolbar"><input id="q" type="search" placeholder="Search commands, actors, IPs, operations... (/ )" />')
    [void]$sb.Append('<select id="sev"></select><select id="cat"></select>')
    [void]$sb.Append('<button type="button" class="chip" id="psOnly">PowerShell related</button>')
    [void]$sb.Append('<button type="button" class="chip" id="cmdOnly">Has command line</button>')
    [void]$sb.Append('<button type="button" class="chip" id="susOnly">Suspect match</button>')
    [void]$sb.Append('<button type="button" class="btn" id="clear">Clear filters</button>')
    [void]$sb.Append('<button type="button" class="btn" id="dark">Dark mode</button></div></header>')
    [void]$sb.Append('<nav class="tabs" id="tabs"></nav><main>')
    [void]$sb.Append('<div class="cards" id="cards"></div><div id="gaps"></div><div id="trunc"></div>')
    [void]$sb.Append('<section id="view-overview"><div id="recs"></div></section>')
    [void]$sb.Append('<section id="view-commands"><h2>Every PowerShell / cmdlet command</h2><p class="lead">Reconstructed command lines from Exchange/Purview audit plus Entra changes made from PowerShell clients. Click a row for details; click an actor or IP to pivot.</p><div id="tbl-commands"></div></section>')
    [void]$sb.Append('<section id="view-timeline"><h2>Investigation timeline</h2><div id="tbl-timeline"></div></section>')
    [void]$sb.Append('<section id="view-access"><h2>What access was gained</h2><div id="tbl-access"></div></section>')
    [void]$sb.Append('<section id="view-path"><h2>Attack path by tactic</h2><div id="tbl-path"></div></section>')
    [void]$sb.Append('<section id="view-actors"><h2>Who ran commands</h2><div id="tbl-actors"></div></section>')
    [void]$sb.Append('<section id="view-signins"><h2>PowerShell &amp; tooling sign-ins</h2><div id="tbl-signins"></div></section>')
    [void]$sb.Append('<section id="view-ips"><h2>Source IP addresses</h2><div id="tbl-ips"></div></section>')
    [void]$sb.Append('<section id="view-failed"><h2>Failed attempts</h2><div id="tbl-failed"></div></section>')
    [void]$sb.Append('<section id="view-findings"><h2>Current-state persistence</h2><div id="tbl-findings"></div></section>')
    [void]$sb.Append('<section id="view-coverage"><h2>Data coverage</h2><div id="tbl-coverage"></div></section>')
    [void]$sb.Append('<div id="notes"></div></main><aside id="detail" class="detail"></aside>')
    [void]$sb.Append('<script type="application/json" id="report-data">')
    [void]$sb.Append($Json)
    [void]$sb.Append('</script><script>')
    [void]$sb.Append($js)
    [void]$sb.Append('</script></body></html>')
    return $sb.ToString()
}

function Write-EvidenceManifest {
    $manifest = Join-Path $script:OutputPath 'Evidence-Manifest.csv'
    Write-Log 'INFO' 'Hashing evidence files (SHA-256)...'
    $rows = foreach ($f in @(Get-ChildItem -LiteralPath $script:OutputPath -Recurse -File | Where-Object { $_.FullName -ne $manifest -and $_.FullName -ne $script:LogFile })) {
        [pscustomobject]@{
            File         = $f.FullName.Substring($script:OutputPath.Length).TrimStart('\', '/')
            SizeBytes    = $f.Length
            SHA256       = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
            LastWriteUtc = ConvertTo-UtcIso $f.LastWriteTimeUtc
        }
    }
    Export-EvidenceCsv -Rows $rows -Path $manifest
    Write-Log 'OK' "Evidence manifest: $manifest"
}

function Initialize-M365PsForensicsOutput {
    param([string]$OutputPath, [switch]$ReportOnly)
    if (-not $OutputPath) {
        $OutputPath = Join-Path (Get-DefaultOutputParent) ('M365-PS-Forensics-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }
    if ($ReportOnly) {
        if (-not (Test-Path -LiteralPath $OutputPath)) {
            throw "ReportOnly requires an existing evidence folder. Not found: $OutputPath"
        }
        $OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
        $hasEvidence = @(Get-ChildItem -LiteralPath $OutputPath -Filter 'Events-*.csv' -File -ErrorAction SilentlyContinue).Count -gt 0 -or
            @(Get-ChildItem -LiteralPath $OutputPath -Filter 'SignIns-*.csv' -File -ErrorAction SilentlyContinue).Count -gt 0 -or
            @(Get-ChildItem -LiteralPath $OutputPath -Filter 'Findings-*.csv' -File -ErrorAction SilentlyContinue).Count -gt 0
        if (-not $hasEvidence) {
            throw "ReportOnly folder has no Events-*.csv, SignIns-*.csv or Findings-*.csv files: $OutputPath"
        }
    }
    else {
        if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
        $OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
    }
    $script:OutputPath = $OutputPath
    $script:RawPath = Join-Path $OutputPath 'raw'
    if (-not (Test-Path -LiteralPath $script:RawPath)) { New-Item -ItemType Directory -Path $script:RawPath -Force | Out-Null }
    $script:LogFile = Join-Path $OutputPath 'Collection-Log.txt'
    $script:CoverageFile = Join-Path $OutputPath 'Coverage.csv'
    if (-not $ReportOnly) {
        $script:CoverageRows = New-Object System.Collections.Generic.List[object]
        if (Test-Path -LiteralPath $script:CoverageFile) {
            try { foreach ($r in @(Import-Csv -LiteralPath $script:CoverageFile)) { $script:CoverageRows.Add($r) } } catch { }
        }
    }
    else {
        $script:CoverageRows = New-Object System.Collections.Generic.List[object]
        if (Test-Path -LiteralPath $script:CoverageFile) {
            try { foreach ($r in @(Import-Csv -LiteralPath $script:CoverageFile)) { $script:CoverageRows.Add($r) } } catch { }
        }
    }
    return $OutputPath
}

function Initialize-InvestigationWindow {
    param([datetime]$StartDate, [datetime]$EndDate)
    $script:NowUtc = (Get-Date).ToUniversalTime()
    $script:StartUtc = $StartDate.ToUniversalTime()
    $script:EndUtc = $EndDate.ToUniversalTime()
    if ($script:EndUtc -gt $script:NowUtc) { $script:EndUtc = $script:NowUtc }
    if ($script:StartUtc -ge $script:EndUtc) { throw 'StartDate must be earlier than EndDate.' }
    $script:GraphCutoffUtc = $script:NowUtc.AddDays(-30).AddMinutes(10)
    if ($script:GraphCutoffUtc -lt $script:StartUtc) { $script:GraphCutoffUtc = $script:StartUtc }
}

function Initialize-SuspectSets {
    param([string[]]$Users, [string[]]$IPs)
    $script:SuspectUserSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $script:SuspectIpSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($u in @(Get-NormalizedIdList $Users)) { [void]$script:SuspectUserSet.Add($u) }
    foreach ($i in @(Get-NormalizedIdList $IPs)) { [void]$script:SuspectIpSet.Add((Format-Ip $i)) }
}
#endregion

#region Main
function Invoke-M365PowerShellForensics {
    <#
    .SYNOPSIS
        Microsoft 365 breach investigation: reconstructs PowerShell / admin commands across the tenant.
    .DESCRIPTION
        READ-ONLY collector. Builds an interactive Investigation-Report.html plus CSV/JSONL evidence.
        Does not exit the host.
    #>
    [CmdletBinding()]
    param(
        [datetime]$StartDate = (Get-Date).AddDays(-90),
        [datetime]$EndDate = (Get-Date),
        [string[]]$SuspectUsers = @(),
        [string[]]$SuspectIPs = @(),
        [string]$OutputPath = '',
        [string]$AdminUPN = '',
        [string]$TenantId = '',
        [ValidateRange(1, 168)][int]$ChunkHours = 24,
        [string[]]$AdditionalRecordTypes = @(),
        [int]$MaxSignInsPerQuery = 50000,
        [int]$MaxDirectoryAuditRecords = 250000,
        [int]$CorrelationWindowHours = 12,
        [int]$MaxMailboxesToInspect = 200,
        [int]$MaxReportEvents = 12000,
        [switch]$IncludeServicePrincipalSignIns,
        [switch]$SkipSuspectDataAccess,
        [switch]$SkipExchange,
        [switch]$SkipGraph,
        [switch]$SkipCurrentState,
        [switch]$ReportOnly,
        [switch]$InstallModules,
        [switch]$NoDisconnect,
        [switch]$OpenReport
    )

    $exitCode = 0
    $fatal = $null
    $report = $null
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    $ErrorActionPreference = 'Continue'

    $script:Config = @{
        StartDate = $StartDate
        EndDate = $EndDate
        SuspectUsers = @(Get-NormalizedIdList $SuspectUsers)
        SuspectIPs = @(Get-NormalizedIdList $SuspectIPs)
        OutputPath = $OutputPath
        AdminUPN = $AdminUPN
        TenantId = $TenantId
        ChunkHours = $ChunkHours
        AdditionalRecordTypes = @(Get-NormalizedTokenList $AdditionalRecordTypes -KeepCase)
        MaxSignInsPerQuery = $MaxSignInsPerQuery
        MaxDirectoryAuditRecords = $MaxDirectoryAuditRecords
        CorrelationWindowHours = $CorrelationWindowHours
        MaxMailboxesToInspect = $MaxMailboxesToInspect
        MaxReportEvents = $MaxReportEvents
        IncludeServicePrincipalSignIns = [bool]$IncludeServicePrincipalSignIns
        SkipSuspectDataAccess = [bool]$SkipSuspectDataAccess
        SkipExchange = [bool]$SkipExchange
        SkipGraph = [bool]$SkipGraph
        SkipCurrentState = [bool]$SkipCurrentState
        ReportOnly = [bool]$ReportOnly
        InstallModules = [bool]$InstallModules
        NoDisconnect = [bool]$NoDisconnect
        OpenReport = [bool]$OpenReport
    }

    try {
        Test-InvestigationCancel
        $resolved = Initialize-M365PsForensicsOutput -OutputPath $OutputPath -ReportOnly:$ReportOnly
        $script:Config.OutputPath = $resolved
        Initialize-InvestigationWindow -StartDate $StartDate -EndDate $EndDate
        Initialize-SuspectSets -Users $script:Config.SuspectUsers -IPs $script:Config.SuspectIPs

        Write-Log 'INFO' ("M365 PowerShell Forensics v{0} | PowerShell {1} | Output: {2}" -f $script:ScriptVersion, $PSVersionTable.PSVersion, $script:OutputPath)
        Write-Log 'INFO' ("Window (UTC): {0} -> {1} | Suspect users: {2} | Suspect IPs: {3}" -f (ConvertTo-UtcIso $script:StartUtc), (ConvertTo-UtcIso $script:EndUtc), ($script:Config.SuspectUsers -join ', '), ($script:Config.SuspectIPs -join ', '))

        if (-not $ReportOnly) {
            if (-not $SkipExchange) { Invoke-ExchangePhase } else { Write-Log 'INFO' 'Exchange / Unified Audit Log phase skipped (-SkipExchange).' }
            Test-InvestigationCancel
            if (-not $SkipGraph) { Invoke-GraphPhase } else { Write-Log 'INFO' 'Microsoft Graph phase skipped (-SkipGraph).' }
        }

        Test-InvestigationCancel
        try { $report = New-InvestigationReport }
        catch {
            if (Test-IsCancelError $_) { throw }
            $exitCode = 1
            Write-Log 'ERROR' ("Report generation failed: {0} | {1} (evidence CSVs are intact; re-run with -ReportOnly)" -f $_.Exception.Message, ($_.ScriptStackTrace -replace '\r?\n', ' <- '))
        }
        try { Write-EvidenceManifest } catch { Write-Log 'ERROR' "Manifest failed: $($_.Exception.Message)" }

        if ($report -and $OpenReport -and (Test-Path -LiteralPath $report)) {
            try { Start-Process -FilePath $report } catch { Write-Log 'WARN' "Could not open the report: $($_.Exception.Message)" }
        }

        Write-Host ''
        Write-Host '==================================================================' -ForegroundColor Cyan
        Write-Host ' Collection complete.' -ForegroundColor Cyan
        Write-Host (' Evidence folder : ' + $script:OutputPath) -ForegroundColor Cyan
        if ($report) { Write-Host (' Report          : ' + $report) -ForegroundColor Cyan }
        Write-Host '==================================================================' -ForegroundColor Cyan
    }
    catch {
        if (Test-IsCancelError $_) {
            $exitCode = 2
            Write-Log 'WARN' 'Investigation cancelled.'
        }
        else {
            $exitCode = 1
            $fatal = $_.Exception.Message
            Write-Log 'ERROR' $fatal
        }
    }
    finally {
        try { Write-Progress -Activity 'M365 PowerShell Forensics' -Completed } catch { }
    }

    return [pscustomobject]@{
        ExitCode   = $exitCode
        Error      = $fatal
        OutputPath = $script:OutputPath
        ReportPath = $report
        Version    = $script:ScriptVersion
    }
}

function Read-WizardLine {
    param([string]$Prompt, [string]$Default = '')
    $suffix = ''
    if ($Default -ne '') { $suffix = " [$Default]" }
    $raw = Read-Host ($Prompt + $suffix)
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
    return $raw
}

function Read-WizardYesNo {
    param([string]$Prompt, [bool]$Default = $true)
    $hint = if ($Default) { 'Y/n' } else { 'y/N' }
    $raw = Read-Host "$Prompt [$hint]"
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
    return ($raw -match '^(y|yes|1|true)$')
}

function Start-M365PsForensicsWizard {
    <#
    .SYNOPSIS
        Console prompts for an investigation, then runs Invoke-M365PowerShellForensics.
    #>
    Write-Host ''
    Write-Host 'Microsoft 365 PowerShell / admin-command investigation' -ForegroundColor Cyan
    Write-Host 'READ-ONLY. Sign in with a break-glass / IR account the attacker has not touched.' -ForegroundColor Yellow
    Write-Host ''
    $startDefault = (Get-Date).AddDays(-90).ToString('yyyy-MM-dd')
    $endDefault = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    $startText = Read-WizardLine 'Start date (local)' $startDefault
    $endText = Read-WizardLine 'End date (local)' $endDefault
    $start = [datetime]::Parse($startText, $script:Inv)
    $end = [datetime]::Parse($endText, $script:Inv)
    $users = Read-WizardLine 'Suspect users (comma-separated UPNs, blank = none)' ''
    $ips = Read-WizardLine 'Suspect IPs (comma-separated, blank = none)' ''
    $out = Read-WizardLine 'Evidence folder (blank = auto)' ''
    $admin = Read-WizardLine 'Investigator UPN for Exchange (blank = sign-in picker)' ''
    $tenant = Read-WizardLine 'Tenant ID for Graph (blank = sign-in picker)' ''
    $skipEx = -not (Read-WizardYesNo 'Collect Exchange Online / Unified Audit Log?' $true)
    $skipGraph = -not (Read-WizardYesNo 'Collect Microsoft Graph sign-ins and directory audit?' $true)
    $skipState = -not (Read-WizardYesNo 'Run current-state persistence sweep?' $true)
    $skipData = -not (Read-WizardYesNo 'Collect suspect mailbox/file/Teams activity (needs suspect users)?' $true)
    $sp = Read-WizardYesNo 'Include all service-principal sign-ins?' $false
    $install = Read-WizardYesNo 'Install missing modules for the current user if needed?' $false
    $extra = Read-WizardLine 'Additional UAL record types (comma-separated, e.g. MicrosoftTeams,PowerBIAudit)' ''
    $open = Read-WizardYesNo 'Open the HTML report when finished?' $true

    $p = @{
        StartDate = $start
        EndDate = $end
        OpenReport = $open
        InstallModules = $install
        IncludeServicePrincipalSignIns = $sp
        SkipExchange = $skipEx
        SkipGraph = $skipGraph
        SkipCurrentState = $skipState
        SkipSuspectDataAccess = $skipData
    }
    if ($users) { $p.SuspectUsers = @(Get-NormalizedIdList $users) }
    if ($ips) { $p.SuspectIPs = @(Get-NormalizedIdList $ips) }
    if ($out) { $p.OutputPath = $out }
    if ($admin) { $p.AdminUPN = $admin }
    if ($tenant) { $p.TenantId = $tenant }
    if ($extra) { $p.AdditionalRecordTypes = @(Get-NormalizedTokenList $extra -KeepCase) }
    return Invoke-M365PowerShellForensics @p
}
#endregion

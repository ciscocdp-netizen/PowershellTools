#Requires -Version 5.1
# ActiveDirectory is imported at runtime so -OfflineDemo still works without RSAT.

<#
.SYNOPSIS
    Builds an interactive HTML onboarding brief for an Active Directory domain.

.DESCRIPTION
    Queries the current (or specified) AD forest/domain and produces a single HTML
    report a new administrator can use to learn the environment quickly.

    The report covers:
      - Forest and domain identity, functional levels, schema, recycle bin, UPNs
      - FSMO role holders with plain-language explanations
      - Sites, subnets, site links, and empty-site / missing-subnet findings
      - Every domain controller: health, FSMO, GC/RODC, roles/features, services
      - Replication partners (inbound) with last success and consecutive failures
      - Trusts, password policy, fine-grained password policies, KRBTGT age
      - Privileged group membership (recursive where possible)
      - Stale users/computers, password-never-expires, unconstrained delegation
      - GPO inventory and OU tree
      - Directory-integrated services (AD CS, DHCP, Exchange, Entra Connect, LAPS)
      - Auto-generated findings that tell you what to look at first

    Original bugs this rewrite fixes:
      1. Replication partner names parsed as "CN=NTDS Settings" (DN split was wrong)
      2. "Outbound" partners reused inbound Get-ADReplicationPartnerMetadata
      3. FSMO matching failed when one side was FQDN and the other was NetBIOS
      4. Single-DC / single-role pipelines were not wrapped in @(), so .Count lied
      5. -IncludeSubFeatures was accepted and then ignored
      6. $fsmoSummaryHtml was built and never inserted
      7. #Requires ServerManager + RunAsAdministrator blocked RSAT workstations
      8. Feature descriptions with quotes broke HTML attributes (now encoded)
      9. Output directory was not created; browser launch failed in non-interactive hosts
     10. Remote feature objects were serialized poorly by Invoke-Command

.NOTES
    Author : Anthony Blake (enhanced)
    Version: 2.0
    Run from a domain-joined Windows machine with the ActiveDirectory module (RSAT).
    WinRM/admin rights on each DC are only required for roles, features, disks, and services.
    Forest-wide AD reads work with a typical delegated admin account.

.EXAMPLE
    .\AD-DomainDiscovery-Report.ps1

.EXAMPLE
    .\AD-DomainDiscovery-Report.ps1 -Domain contoso.com -OutputPath C:\Reports\contoso.html

.EXAMPLE
    .\AD-DomainDiscovery-Report.ps1 -SkipRemoteQueries -StaleDays 60

.EXAMPLE
    .\AD-DomainDiscovery-Report.ps1 -OfflineDemo
    Generates a sample report with fictional data so you can learn the layout first.
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$Domain,
    [string]$Server,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$IncludeSubFeatures,
    [switch]$SkipRemoteQueries,
    [switch]$SkipOptionalInventory,
    [int]$StaleDays = 90,
    [int]$MaxInventoryObjects = 8000,
    [int]$RemoteTimeoutSec = 45,
    [switch]$ExportJson,
    [switch]$NoBrowser,
    [switch]$OfflineDemo
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

#region Knowledge

$script:FsmoKnowledge = [ordered]@{
    'Schema Master' = @{
        Scope = 'Forest'
        What  = 'The only DC that can write to the AD schema (new classes and attributes).'
        Why   = 'Schema updates are rare (Exchange, AD Connect, Windows functional-level raises) but they must succeed.'
        Look  = 'Keep it on a healthy, well-connected hub DC. Treat schema extensions as change-controlled events.'
    }
    'Domain Naming Master' = @{
        Scope = 'Forest'
        What  = 'The only DC that can add or remove domains and application partitions.'
        Why   = 'Idle most of the time. Required when creating domains, trusts that add partitions, or some DNS app partitions.'
        Look  = 'Usually colocated with Schema Master. Confirm it is reachable from wherever you would run domain-create tools.'
    }
    'PDC Emulator' = @{
        Scope = 'Domain'
        What  = 'Password changes and lockouts, time source for the domain, GPO editing target, backward-compat PDC.'
        Why   = 'This is the FSMO you will feel immediately if it is down: logons, lockouts, and time drift.'
        Look  = 'Put it on your most reliable, lowest-latency DC. Clients and other DCs sync time from here (directly or indirectly).'
    }
    'RID Master' = @{
        Scope = 'Domain'
        What  = 'Hands each DC pools of Relative IDs used to build new SIDs for users, computers, and groups.'
        Why   = 'If it is offline long enough that RID pools exhaust, that DC cannot create new security principals.'
        Look  = 'Short outages are fine. Multi-day outages plus a hiring/build surge are not. Confirm every DC has a RID pool.'
    }
    'Infrastructure Master' = @{
        Scope = 'Domain'
        What  = 'Updates cross-domain group-to-user references (phantoms) so memberships stay consistent.'
        Why   = 'In a single-domain forest this role is effectively idle. In multi-domain forests it matters.'
        Look  = 'Do not place it on a GC unless every DC in the domain is a GC (the usual modern design).'
    }
}

$script:LevelNames = @{
    0 = 'Windows 2000'; 1 = 'Windows Server 2003 interim'; 2 = 'Windows Server 2003'
    3 = 'Windows Server 2008'; 4 = 'Windows Server 2008 R2'; 5 = 'Windows Server 2012'
    6 = 'Windows Server 2012 R2'; 7 = 'Windows Server 2016'; 10 = 'Windows Server 2025'
}

$script:SchemaNames = @{
    13 = 'Windows 2000'; 30 = 'Windows Server 2003'; 31 = 'Windows Server 2003 R2'
    44 = 'Windows Server 2008'; 47 = 'Windows Server 2008 R2'; 56 = 'Windows Server 2012'
    69 = 'Windows Server 2012 R2'; 87 = 'Windows Server 2016'; 88 = 'Windows Server 2019'
    91 = 'Windows Server 2022'; 92 = 'Windows Server 2025'
}

$script:PrivilegedGroupNames = @(
    'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
    'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators',
    'DnsAdmins', 'Group Policy Creator Owners', 'Cert Publishers',
    'Enterprise Key Admins', 'Key Admins', 'Protected Users',
    'DHCP Administrators', 'Hyper-V Administrators'
)

#endregion

#region Helpers

function Write-ReportLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'STEP')]
        [string]$Level = 'INFO'
    )
    $colors = @{
        INFO    = 'Cyan'
        WARN    = 'Yellow'
        ERROR   = 'Red'
        SUCCESS = 'Green'
        STEP    = 'Magenta'
    }
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $colors[$Level]
}

function ConvertTo-HtmlEncoded {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Get-ShortHostName {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    return ($Name.Split('.')[0]).ToUpperInvariant()
}

function Test-SameHost {
    param([string]$Left, [string]$Right)
    $a = Get-ShortHostName $Left
    $b = Get-ShortHostName $Right
    return ($a -and $a -eq $b)
}

function Get-PartnerNameFromDn {
    param([AllowNull()][string]$Partner)
    if ([string]::IsNullOrWhiteSpace($Partner)) { return 'Unknown' }
    if ($Partner -match 'CN=NTDS Settings,CN=([^,]+)') { return $Matches[1] }
    $parts = @($Partner -split ',')
    if ($parts.Count -ge 2 -and $parts[1] -like 'CN=*') {
        return $parts[1].Substring(3)
    }
    return $Partner
}

function Get-LevelName {
    param($Value)
    if ($null -eq $Value) { return 'Unknown' }
    $n = 0
    if (-not [int]::TryParse([string]$Value, [ref]$n)) {
        return [string]$Value
    }
    if ($script:LevelNames.ContainsKey($n)) {
        return '{0} ({1})' -f $script:LevelNames[$n], $n
    }
    return 'Unknown ({0})' -f $n
}

function Get-SchemaName {
    param($Value)
    if ($null -eq $Value) { return 'Unknown' }
    $n = 0
    if (-not [int]::TryParse([string]$Value, [ref]$n)) {
        return [string]$Value
    }
    if ($script:SchemaNames.ContainsKey($n)) {
        return '{0} (objectVersion {1})' -f $script:SchemaNames[$n], $n
    }
    return 'Unknown schema (objectVersion {0})' -f $n
}

function Get-SafeCount {
    param($Value)
    if ($null -eq $Value) { return 0 }
    if ($Value -is [System.Collections.ICollection] -and -not ($Value -is [string])) {
        return $Value.Count
    }
    return @($Value).Count
}

function Format-Uptime {
    param($LastBoot)
    if (-not $LastBoot) { return 'N/A' }
    try {
        $boot = [datetime]$LastBoot
        $u = (Get-Date) - $boot
        if ($u.TotalDays -ge 1) {
            return '{0}d {1}h {2}m' -f [int]$u.Days, $u.Hours, $u.Minutes
        }
        return '{0}h {1}m' -f $u.Hours, $u.Minutes
    } catch {
        return 'N/A'
    }
}

function Format-When {
    param($Value)
    if (-not $Value) { return 'N/A' }
    try { return ([datetime]$Value).ToString('yyyy-MM-dd HH:mm') } catch { return [string]$Value }
}

function Format-AgeDays {
    param($Value)
    if (-not $Value) { return $null }
    try { return [int]((Get-Date) - [datetime]$Value).TotalDays } catch { return $null }
}

function New-ReportWarning {
    param([string]$Area, [string]$Message)
    [pscustomobject]@{
        Area    = $Area
        Message = $Message
    }
}

function Get-AdSplat {
    $splat = @{ ErrorAction = 'Stop' }
    if ($script:TargetServer) { $splat.Server = $script:TargetServer }
    if ($script:Credential) { $splat.Credential = $script:Credential }
    return $splat
}

function ConvertTo-TextList {
    param($Values, [string]$Empty = 'None')
    $items = @($Values | Where-Object { $_ -and [string]$_ -ne '' } | ForEach-Object { [string]$_ } | Select-Object -Unique)
    if ($items.Count -eq 0) { return $Empty }
    return ($items -join ', ')
}

#endregion

#region Collectors

function Get-ForestAndDomainInfo {
    param($Ad)
    $info = [ordered]@{
        ForestName              = $null
        ForestMode              = $null
        ForestModeRaw           = $null
        RootDomain              = $null
        Domains                 = @()
        GlobalCatalogs          = @()
        UPNSuffixes             = @()
        Sites                   = @()
        SchemaMaster            = $null
        DomainNamingMaster      = $null
        RecycleBinEnabled       = $false
        OptionalFeatures        = @()
        DomainName              = $null
        DomainNetBIOS           = $null
        DomainDN                = $null
        DomainSID               = $null
        DomainMode              = $null
        DomainModeRaw           = $null
        PDCEmulator             = $null
        RIDMaster               = $null
        InfrastructureMaster    = $null
        DNSRoot                 = $null
        ChildDomains            = @()
        ReplicaDirectoryServers = @()
        RODC                    = @()
        SchemaVersion           = $null
        SchemaVersionName       = 'Unknown'
        TombstoneLifetime       = $null
        ConfigurationNC         = $null
        SchemaNC                = $null
        RootDSEHost             = $null
        CurrentTime             = $null
    }

    $forest = Get-ADForest @Ad
    $domain = if ($Domain) { Get-ADDomain -Identity $Domain @Ad } else { Get-ADDomain @Ad }

    $info.ForestName         = $forest.Name
    $info.ForestModeRaw      = [string]$forest.ForestMode
    $info.ForestMode         = [string]$forest.ForestMode
    $info.RootDomain         = $forest.RootDomain
    $info.Domains            = @($forest.Domains)
    $info.GlobalCatalogs     = @($forest.GlobalCatalogs)
    $info.UPNSuffixes        = @($forest.UPNSuffixes)
    $info.Sites              = @($forest.Sites)
    $info.SchemaMaster       = $forest.SchemaMaster
    $info.DomainNamingMaster = $forest.DomainNamingMaster

    $info.DomainName              = $domain.DNSRoot
    $info.DomainNetBIOS           = $domain.NetBIOSName
    $info.DomainDN                = $domain.DistinguishedName
    $info.DomainSID               = [string]$domain.DomainSID
    $info.DomainModeRaw           = [string]$domain.DomainMode
    $info.DomainMode              = [string]$domain.DomainMode
    $info.PDCEmulator             = $domain.PDCEmulator
    $info.RIDMaster               = $domain.RIDMaster
    $info.InfrastructureMaster    = $domain.InfrastructureMaster
    $info.DNSRoot                 = $domain.DNSRoot
    $info.ChildDomains            = @($domain.ChildDomains)
    $info.ReplicaDirectoryServers = @($domain.ReplicaDirectoryServers)
    $info.RODC                    = @($domain.ReadOnlyReplicaDirectoryServers)

    try {
        $rootDse = Get-ADRootDSE @Ad
        $info.ConfigurationNC = $rootDse.configurationNamingContext
        $info.SchemaNC        = $rootDse.schemaNamingContext
        $info.RootDSEHost     = $rootDse.dnsHostName
        $info.CurrentTime     = $rootDse.currentTime
        if ($rootDse.domainFunctionality) {
            $info.DomainMode = Get-LevelName $rootDse.domainFunctionality
        }
        if ($rootDse.forestFunctionality) {
            $info.ForestMode = Get-LevelName $rootDse.forestFunctionality
        }
    } catch {
        Write-ReportLog "RootDSE read failed: $($_.Exception.Message)" 'WARN'
    }

    try {
        $features = @(Get-ADOptionalFeature -Filter * @Ad | Select-Object Name, EnabledScopes, RequiredDomainMode, RequiredForestMode)
        $info.OptionalFeatures = $features
        $recycle = $features | Where-Object { $_.Name -like '*Recycle Bin*' }
        $info.RecycleBinEnabled = [bool]($recycle -and (Get-SafeCount $recycle.EnabledScopes) -gt 0)
    } catch {
        Write-ReportLog "Optional features read failed: $($_.Exception.Message)" 'WARN'
    }

    if ($info.SchemaNC) {
        try {
            $schema = Get-ADObject -Identity $info.SchemaNC -Properties objectVersion @Ad
            $info.SchemaVersion     = $schema.objectVersion
            $info.SchemaVersionName = Get-SchemaName $schema.objectVersion
        } catch {
            Write-ReportLog "Schema version read failed: $($_.Exception.Message)" 'WARN'
        }
    }

    if ($info.ConfigurationNC) {
        try {
            $dsDn = 'CN=Directory Service,CN=Windows NT,CN=Services,{0}' -f $info.ConfigurationNC
            $ds = Get-ADObject -Identity $dsDn -Properties tombstoneLifetime @Ad
            $info.TombstoneLifetime = if ($ds.tombstoneLifetime) { [int]$ds.tombstoneLifetime } else { 60 }
        } catch {
            $info.TombstoneLifetime = 60
        }
    }

    return [pscustomobject]$info
}

function Get-FSMORoleTable {
    param($ForestInfo)
    $roles = [ordered]@{
        'Schema Master'          = $ForestInfo.SchemaMaster
        'Domain Naming Master'   = $ForestInfo.DomainNamingMaster
        'PDC Emulator'           = $ForestInfo.PDCEmulator
        'RID Master'             = $ForestInfo.RIDMaster
        'Infrastructure Master'  = $ForestInfo.InfrastructureMaster
    }
    return $roles
}

function Get-AllDomainControllers {
    param($Ad)
    $raw = @(Get-ADDomainController -Filter * @Ad)
    $list = foreach ($dc in $raw) {
        [pscustomobject]@{
            Name                    = $dc.Name
            HostName                = $dc.HostName
            IPv4Address             = $dc.IPv4Address
            Site                    = $dc.Site
            OperatingSystem         = $dc.OperatingSystem
            OperatingSystemVersion  = $dc.OperatingSystemVersion
            IsGlobalCatalog         = [bool]$dc.IsGlobalCatalog
            IsReadOnly              = [bool]$dc.IsReadOnly
            Enabled                 = [bool]$dc.Enabled
            OperationMasterRoles    = @($dc.OperationMasterRoles | ForEach-Object { [string]$_ })
            LdapPort                = $dc.LdapPort
            SslPort                 = $dc.SslPort
            Forest                  = [string]$dc.Forest
            Domain                  = [string]$dc.Domain
        }
    }
    return @($list | Sort-Object Name)
}

function Get-DcReplicationDetails {
    param($ComputerName, $Ad)
    $result = [pscustomobject]@{
        Inbound     = @()
        Connections = @()
        Failures    = @()
        Error       = $null
    }

    try {
        $meta = @(Get-ADReplicationPartnerMetadata -Target $ComputerName -Partition * @Ad -ErrorAction Stop)
        $grouped = $meta | Group-Object { Get-PartnerNameFromDn $_.Partner }
        foreach ($g in $grouped) {
            $worst = $g.Group | Sort-Object ConsecutiveReplicationFailures -Descending | Select-Object -First 1
            $partitions = @($g.Group | ForEach-Object {
                    if ($_.Partition) { ($_.Partition -split ',')[0] -replace '^CN=|^DC=', '' } else { 'Unknown' }
                } | Select-Object -Unique)
            $result.Inbound += [pscustomobject]@{
                Partner          = $g.Name
                LastSuccess      = $worst.LastReplicationSuccess
                LastAttempt      = $worst.LastReplicationAttempt
                LastResult       = [string]$worst.LastReplicationResult
                ConsecutiveFails = [int]$worst.ConsecutiveReplicationFailures
                Partitions       = $partitions
                UsnFilter        = $worst.LastReplicationSuccess
            }
        }
    } catch {
        $result.Error = $_.Exception.Message
    }

    try {
        $conns = @(Get-ADReplicationConnection -Server $ComputerName -Filter * @Ad -ErrorAction SilentlyContinue)
        foreach ($c in $conns) {
            $from = Get-PartnerNameFromDn ([string]$c.ReplicateFromDirectoryServer)
            $result.Connections += [pscustomobject]@{
                Name           = $c.Name
                From           = $from
                AutoGenerated  = [bool]$c.AutoGenerated
                Enabled        = if ($null -ne $c.Enabled) { [bool]$c.Enabled } else { $true }
            }
        }
    } catch {
        # Connection objects are nice-to-have.
    }

    return $result
}

function Get-RemoteDcDetails {
    param(
        [string]$ComputerName,
        [bool]$SubFeatures
    )

    $empty = [pscustomobject]@{
        Status              = 'Skipped'
        Roles               = @()
        Features            = @()
        LastBootTime        = $null
        LastBootTimeFormatted = 'N/A'
        Uptime              = 'N/A'
        MemoryGB            = $null
        Disks               = @()
        TimeSource          = 'N/A'
        Services            = @()
        LastHotfix          = 'N/A'
        PendingReboot       = $null
        Error               = $null
    }

    if ($SkipRemoteQueries) {
        $empty.Status = 'Skipped'
        $empty.Error = 'Remote queries disabled (-SkipRemoteQueries).'
        return $empty
    }

    $invokeParams = @{
        ComputerName = $ComputerName
        ScriptBlock  = {
            $ErrorActionPreference = 'SilentlyContinue'
            Import-Module ServerManager -ErrorAction SilentlyContinue

            $features = @()
            try {
                $features = @(Get-WindowsFeature | Where-Object { $_.Installed -eq $true } | ForEach-Object {
                        [pscustomobject]@{
                            Name        = [string]$_.Name
                            DisplayName = [string]$_.DisplayName
                            Description = [string]$_.Description
                            FeatureType = [string]$_.FeatureType
                            Depth       = [int]$_.Depth
                            Path        = [string]$_.Path
                        }
                    })
            } catch {
                $features = @()
            }

            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
            $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [pscustomobject]@{
                        DeviceID  = $_.DeviceID
                        SizeGB    = if ($_.Size) { [math]::Round($_.Size / 1GB, 1) } else { 0 }
                        FreeGB    = if ($_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 1) } else { 0 }
                    }
                })

            $timeSource = 'Unknown'
            try {
                $raw = & w32tm /query /source 2>$null
                if ($raw) { $timeSource = ([string]$raw).Trim() }
            } catch { }

            $svcNames = @('NTDS', 'DNS', 'KDC', 'DFSR', 'NtFrs', 'W32Time', 'Netlogon', 'ADWS', 'DHCPServer', 'CertSvc')
            $services = foreach ($n in $svcNames) {
                $s = Get-Service -Name $n -ErrorAction SilentlyContinue
                if ($s) {
                    [pscustomobject]@{
                        Name        = $s.Name
                        DisplayName = $s.DisplayName
                        Status      = [string]$s.Status
                    }
                }
            }

            $hotfix = Get-HotFix -ErrorAction SilentlyContinue |
                Where-Object { $_.InstalledOn } |
                Sort-Object InstalledOn -Descending |
                Select-Object -First 1

            $pending = $false
            foreach ($p in @(
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                )) {
                if (Test-Path $p) { $pending = $true }
            }

            [pscustomobject]@{
                Features      = $features
                LastBootTime  = if ($os) { $os.LastBootUpTime } else { $null }
                MemoryGB      = if ($cs -and $cs.TotalPhysicalMemory) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) } else { $null }
                Disks         = $disks
                TimeSource    = $timeSource
                Services      = @($services)
                LastHotfix    = if ($hotfix) { '{0} ({1})' -f $hotfix.HotFixID, $hotfix.InstalledOn.ToString('yyyy-MM-dd') } else { 'Unknown' }
                PendingReboot = $pending
            }
        }
        ErrorAction  = 'Stop'
    }

    if ($script:Credential) { $invokeParams.Credential = $script:Credential }

    try {
        if (Get-Command New-PSSessionOption -ErrorAction SilentlyContinue) {
            $ms = [math]::Max(5000, $RemoteTimeoutSec * 1000)
            $invokeParams.SessionOption = New-PSSessionOption -OpenTimeout $ms -CancelTimeout $ms -OperationTimeout $ms
        }
        $remote = Invoke-Command @invokeParams
    } catch {
        $empty.Status = 'Error'
        $empty.Error = $_.Exception.Message
        return $empty
    }

    $allFeatures = @($remote.Features)
    $roles = @($allFeatures | Where-Object { $_.FeatureType -eq 'Role' })
    $features = @($allFeatures | Where-Object { $_.FeatureType -ne 'Role' })
    if (-not $SubFeatures) {
        $features = @($features | Where-Object { $_.FeatureType -ne 'Role Service' -and ([int]$_.Depth -le 1) })
    }

    $boot = $remote.LastBootTime
    [pscustomobject]@{
        Status                = 'Online'
        Roles                 = $roles
        Features              = $features
        LastBootTime          = $boot
        LastBootTimeFormatted = Format-When $boot
        Uptime                = Format-Uptime $boot
        MemoryGB              = $remote.MemoryGB
        Disks                 = @($remote.Disks)
        TimeSource            = [string]$remote.TimeSource
        Services              = @($remote.Services)
        LastHotfix            = [string]$remote.LastHotfix
        PendingReboot         = [bool]$remote.PendingReboot
        Error                 = $null
    }
}

function Get-DcRecord {
    param($Dc, $FsmoRoles, $Ad, [bool]$SubFeatures)

    $held = @()
    foreach ($role in $FsmoRoles.Keys) {
        if (Test-SameHost $FsmoRoles[$role] $Dc.Name -or (Test-SameHost $FsmoRoles[$role] $Dc.HostName)) {
            $held += $role
        }
    }
    foreach ($native in @($Dc.OperationMasterRoles)) {
        $label = switch -Regex ($native) {
            'PDC'            { 'PDC Emulator' }
            'RID'            { 'RID Master' }
            'Infrastructure' { 'Infrastructure Master' }
            'Schema'         { 'Schema Master' }
            'Naming'         { 'Domain Naming Master' }
            default          { $native }
        }
        if ($label -and $label -notin $held) { $held += $label }
    }

    Write-ReportLog "Querying $($Dc.Name)..." 'INFO'
    $remote = Get-RemoteDcDetails -ComputerName $Dc.HostName -SubFeatures $SubFeatures
    if ($remote.Status -eq 'Error' -and $Dc.Name -ne $Dc.HostName) {
        Write-ReportLog "Retrying $($Dc.Name) by short name..." 'WARN'
        $retry = Get-RemoteDcDetails -ComputerName $Dc.Name -SubFeatures $SubFeatures
        if ($retry.Status -eq 'Online') { $remote = $retry }
    }

    $repl = Get-DcReplicationDetails -ComputerName $Dc.HostName -Ad $Ad

    [pscustomobject]@{
        ComputerName          = $Dc.Name
        HostName              = $Dc.HostName
        IPv4Address           = $Dc.IPv4Address
        Site                  = $Dc.Site
        OperatingSystem       = $Dc.OperatingSystem
        OperatingSystemVersion = $Dc.OperatingSystemVersion
        IsGlobalCatalog       = $Dc.IsGlobalCatalog
        IsReadOnly            = $Dc.IsReadOnly
        Status                = $remote.Status
        Roles                 = @($remote.Roles)
        Features              = @($remote.Features)
        FSMORoles             = @($held)
        LastBootTime          = $remote.LastBootTime
        LastBootTimeFormatted = $remote.LastBootTimeFormatted
        Uptime                = $remote.Uptime
        MemoryGB              = $remote.MemoryGB
        Disks                 = @($remote.Disks)
        TimeSource            = $remote.TimeSource
        Services              = @($remote.Services)
        LastHotfix            = $remote.LastHotfix
        PendingReboot         = $remote.PendingReboot
        ReplicationPartners   = @{
            Inbound     = @($repl.Inbound)
            Connections = @($repl.Connections)
        }
        ReplicationError      = $repl.Error
        Error                 = $remote.Error
    }
}

function Get-SiteTopology {
    param($Ad)
    $sites = @()
    $subnets = @()
    $links = @()
    try {
        $sites = @(Get-ADReplicationSite -Filter * @Ad | ForEach-Object {
                [pscustomobject]@{
                    Name        = $_.Name
                    Description = [string]$_.Description
                    Location    = [string]$_.Location
                    DN          = $_.DistinguishedName
                }
            })
    } catch {
        Write-ReportLog "Sites read failed: $($_.Exception.Message)" 'WARN'
    }
    try {
        $subnets = @(Get-ADReplicationSubnet -Filter * @Ad | ForEach-Object {
                [pscustomobject]@{
                    Name        = $_.Name
                    Site        = if ($_.Site) { ($_.Site -split ',')[0] -replace '^CN=', '' } else { '' }
                    Description = [string]$_.Description
                    Location    = [string]$_.Location
                }
            })
    } catch {
        Write-ReportLog "Subnets read failed: $($_.Exception.Message)" 'WARN'
    }
    try {
        $links = @(Get-ADReplicationSiteLink -Filter * @Ad | ForEach-Object {
                $siteNames = @($_.SitesIncluded | ForEach-Object {
                        if ($_ -match 'CN=([^,]+)') { $Matches[1] } else { $_ }
                    })
                [pscustomobject]@{
                    Name              = $_.Name
                    Cost              = $_.Cost
                    ReplicationFrequencyInMinutes = $_.ReplicationFrequencyInMinutes
                    Sites             = $siteNames
                    InterSiteTransportProtocol = [string]$_.InterSiteTransportProtocol
                }
            })
    } catch {
        Write-ReportLog "Site links read failed: $($_.Exception.Message)" 'WARN'
    }

    [pscustomobject]@{
        Sites   = $sites
        Subnets = $subnets
        Links   = $links
    }
}

function Get-TrustInfo {
    param($Ad)
    try {
        return @(Get-ADTrust -Filter * @Ad | ForEach-Object {
                [pscustomobject]@{
                    Name           = $_.Name
                    Direction      = [string]$_.Direction
                    TrustType      = [string]$_.TrustType
                    IntraForest    = [bool]$_.IntraForest
                    ForestTransitive = [bool]$_.ForestTransitive
                    SelectiveAuth  = [bool]$_.SelectiveAuthentication
                    SIDFilteringQuarantined = [bool]$_.SIDFilteringQuarantined
                    DisallowTransivity = [bool]$_.DisallowTransivity
                    Target         = [string]$_.Target
                }
            })
    } catch {
        Write-ReportLog "Trusts read failed: $($_.Exception.Message)" 'WARN'
        return @()
    }
}

function Get-ReplicationFailures {
    param($Ad, $DomainName)
    try {
        $target = if ($DomainName) { $DomainName } else { $script:TargetServer }
        return @(Get-ADReplicationFailure -Target $target -Scope Domain -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    Server              = $_.Server
                    Partner             = Get-PartnerNameFromDn ([string]$_.Partner)
                    FailureType         = [string]$_.FailureType
                    FirstFailureTime    = $_.FirstFailureTime
                    FailureCount        = $_.FailureCount
                    LastError           = [string]$_.LastError
                    LastErrorDesc       = [string]$_.LastErrorDescription
                }
            })
    } catch {
        Write-ReportLog "Replication failure query failed: $($_.Exception.Message)" 'WARN'
        return @()
    }
}

function Get-PasswordPolicyInfo {
    param($Ad)
    $policy = $null
    $fgpp = @()
    try {
        $p = Get-ADDefaultDomainPasswordPolicy @Ad
        $policy = [pscustomobject]@{
            ComplexityEnabled           = [bool]$p.ComplexityEnabled
            MinPasswordLength           = [int]$p.MinPasswordLength
            MinPasswordAgeDays          = [int]$p.MinPasswordAge.TotalDays
            MaxPasswordAgeDays          = [int]$p.MaxPasswordAge.TotalDays
            PasswordHistoryCount        = [int]$p.PasswordHistoryCount
            LockoutThreshold            = [int]$p.LockoutThreshold
            LockoutDurationMinutes      = [int]$p.LockoutDuration.TotalMinutes
            LockoutObservationMinutes   = [int]$p.LockoutObservationWindow.TotalMinutes
            ReversibleEncryptionEnabled = [bool]$p.ReversibleEncryptionEnabled
        }
    } catch {
        Write-ReportLog "Password policy read failed: $($_.Exception.Message)" 'WARN'
    }
    try {
        $fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * @Ad | ForEach-Object {
                [pscustomobject]@{
                    Name              = $_.Name
                    Precedence        = $_.Precedence
                    MinPasswordLength = $_.MinPasswordLength
                    MaxPasswordAgeDays = if ($_.MaxPasswordAge) { [int]$_.MaxPasswordAge.TotalDays } else { $null }
                    LockoutThreshold  = $_.LockoutThreshold
                    AppliesTo         = @($_.AppliesTo)
                }
            })
    } catch { }
    [pscustomobject]@{ Default = $policy; FineGrained = $fgpp }
}

function Get-KrbtgtInfo {
    param($Ad)
    try {
        $k = Get-ADUser -Identity krbtgt -Properties PasswordLastSet, PasswordNeverExpires, whenCreated, Enabled @Ad
        [pscustomobject]@{
            Name              = $k.SamAccountName
            Enabled           = [bool]$k.Enabled
            PasswordLastSet   = $k.PasswordLastSet
            PasswordAgeDays   = Format-AgeDays $k.PasswordLastSet
            PasswordNeverExpires = [bool]$k.PasswordNeverExpires
            Created           = $k.whenCreated
        }
    } catch {
        Write-ReportLog "krbtgt read failed: $($_.Exception.Message)" 'WARN'
        return $null
    }
}

function Get-PrivilegedGroupInfo {
    param($Ad, $DomainDN)
    $results = @()
    foreach ($name in $script:PrivilegedGroupNames) {
        try {
            $group = Get-ADGroup -Identity $name @Ad -ErrorAction Stop
        } catch {
            continue
        }
        $members = @()
        $recursive = $true
        try {
            $members = @(Get-ADGroupMember -Identity $group.DistinguishedName -Recursive @Ad -ErrorAction Stop |
                    Select-Object Name, SamAccountName, objectClass, distinguishedName)
        } catch {
            $recursive = $false
            try {
                $members = @(Get-ADGroupMember -Identity $group.DistinguishedName @Ad -ErrorAction Stop |
                        Select-Object Name, SamAccountName, objectClass, distinguishedName)
            } catch {
                Write-ReportLog "Could not enumerate $name : $($_.Exception.Message)" 'WARN'
            }
        }
        $results += [pscustomobject]@{
            Name       = $group.Name
            DN         = $group.DistinguishedName
            Recursive  = $recursive
            Count      = $members.Count
            Members    = $members
        }
    }
    return $results
}

function Get-DirectoryInventory {
    param($Ad, $Cutoff, $Max)
    $inv = [ordered]@{
        UserEnabled            = 0
        UserDisabled           = 0
        UserStale              = 0
        UserNeverLogon         = 0
        UserNeverExpire        = 0
        UserAdminCount         = 0
        ComputerEnabled        = 0
        ComputerDisabled       = 0
        ComputerStale          = 0
        GroupsSecurity         = 0
        GroupsDistribution     = 0
        Contacts               = 0
        ComputersByOS          = @()
        StaleUsers             = @()
        StaleComputers         = @()
        NeverExpireUsers       = @()
        UnconstrainedComputers = @()
        UnconstrainedUsers     = @()
        Truncated              = $false
        Skipped                = $false
        Error                  = $null
    }

    if ($SkipOptionalInventory) {
        $inv.Skipped = $true
        return [pscustomobject]$inv
    }

    try {
        $users = @(Get-ADUser -Filter * -ResultSetSize $Max -Properties Enabled, PasswordLastSet, PasswordNeverExpires, LastLogonDate, whenCreated, adminCount, TrustedForDelegation, PasswordNotRequired @Ad)
        if ($users.Count -ge $Max) { $inv.Truncated = $true }
        foreach ($u in $users) {
            if ($u.Enabled) { $inv.UserEnabled++ } else { $inv.UserDisabled++ }
            if ($u.PasswordNeverExpires -and $u.Enabled) {
                $inv.UserNeverExpire++
                if ($inv.NeverExpireUsers.Count -lt 50) {
                    $inv.NeverExpireUsers += [pscustomobject]@{
                        Name = $u.SamAccountName; PasswordLastSet = $u.PasswordLastSet
                    }
                }
            }
            if ($u.adminCount -ge 1) { $inv.UserAdminCount++ }
            if ($u.Enabled -and -not $u.LastLogonDate) {
                $inv.UserNeverLogon++
            } elseif ($u.Enabled -and $u.LastLogonDate -and $u.LastLogonDate -lt $Cutoff) {
                $inv.UserStale++
                if ($inv.StaleUsers.Count -lt 50) {
                    $inv.StaleUsers += [pscustomobject]@{
                        Name = $u.SamAccountName; LastLogonDate = $u.LastLogonDate
                    }
                }
            }
            if ($u.TrustedForDelegation) {
                $inv.UnconstrainedUsers += [pscustomobject]@{ Name = $u.SamAccountName }
            }
        }
    } catch {
        $inv.Error = $_.Exception.Message
        Write-ReportLog "User inventory failed: $($_.Exception.Message)" 'WARN'
    }

    try {
        $computers = @(Get-ADComputer -Filter * -ResultSetSize $Max -Properties Enabled, LastLogonDate, OperatingSystem, TrustedForDelegation, PasswordLastSet @Ad)
        if ($computers.Count -ge $Max) { $inv.Truncated = $true }
        $osMap = @{}
        foreach ($c in $computers) {
            if ($c.Enabled) { $inv.ComputerEnabled++ } else { $inv.ComputerDisabled++ }
            $os = if ($c.OperatingSystem) { $c.OperatingSystem } else { '(none)' }
            if (-not $osMap.ContainsKey($os)) { $osMap[$os] = 0 }
            $osMap[$os]++
            if ($c.Enabled -and $c.LastLogonDate -and $c.LastLogonDate -lt $Cutoff) {
                $inv.ComputerStale++
                if ($inv.StaleComputers.Count -lt 50) {
                    $inv.StaleComputers += [pscustomobject]@{
                        Name = $c.Name; OS = $c.OperatingSystem; LastLogonDate = $c.LastLogonDate
                    }
                }
            }
            if ($c.TrustedForDelegation) {
                $inv.UnconstrainedComputers += [pscustomobject]@{ Name = $c.Name; OS = $c.OperatingSystem }
            }
        }
        $inv.ComputersByOS = @(
            $osMap.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
                [pscustomobject]@{ OperatingSystem = $_.Key; Count = $_.Value }
            }
        )
    } catch {
        Write-ReportLog "Computer inventory failed: $($_.Exception.Message)" 'WARN'
    }

    try {
        $inv.GroupsSecurity     = @(Get-ADGroup -LDAPFilter '(groupType:1.2.840.113556.1.4.803:=2147483648)' -ResultSetSize $Max @Ad).Count
        $inv.GroupsDistribution = @(Get-ADGroup -LDAPFilter '(!(groupType:1.2.840.113556.1.4.803:=2147483648))' -ResultSetSize $Max @Ad).Count
    } catch { }

    try {
        $inv.Contacts = @(Get-ADObject -LDAPFilter '(objectClass=contact)' -ResultSetSize $Max @Ad).Count
    } catch { }

    return [pscustomobject]$inv
}

function Get-GpoAndOuInfo {
    param($Ad, $DomainDN, $DomainName)
    $gpos = @()
    $ous = @()

    if (Get-Module -ListAvailable -Name GroupPolicy) {
        try {
            Import-Module GroupPolicy -ErrorAction Stop
            $gpoParams = @{ All = $true; ErrorAction = 'Stop' }
            if ($DomainName) { $gpoParams.Domain = $DomainName }
            if ($script:TargetServer) { $gpoParams.Server = $script:TargetServer }
            $gpos = @(Get-GPO @gpoParams | ForEach-Object {
                    [pscustomobject]@{
                        DisplayName = $_.DisplayName
                        Id          = [string]$_.Id
                        GpoStatus   = [string]$_.GpoStatus
                        CreationTime = $_.CreationTime
                        ModificationTime = $_.ModificationTime
                        UserVersion = '{0}.{1}' -f $_.User.DSVersion, $_.User.SysvolVersion
                        ComputerVersion = '{0}.{1}' -f $_.Computer.DSVersion, $_.Computer.SysvolVersion
                    }
                })
        } catch {
            Write-ReportLog "Get-GPO failed; falling back to AD objects: $($_.Exception.Message)" 'WARN'
        }
    }

    if ($gpos.Count -eq 0) {
        try {
            $search = 'CN=Policies,CN=System,{0}' -f $DomainDN
            $gpos = @(Get-ADObject -SearchBase $search -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties displayName, whenCreated, whenChanged, flags, gPCFileSysPath @Ad |
                ForEach-Object {
                    [pscustomobject]@{
                        DisplayName      = if ($_.displayName) { $_.displayName } else { $_.Name }
                        Id               = $_.Name
                        GpoStatus        = [string]$_.flags
                        CreationTime     = $_.whenCreated
                        ModificationTime = $_.whenChanged
                        UserVersion      = ''
                        ComputerVersion  = ''
                    }
                })
        } catch {
            Write-ReportLog "GPO container read failed: $($_.Exception.Message)" 'WARN'
        }
    }

    try {
        $ous = @(Get-ADOrganizationalUnit -Filter * -Properties CanonicalName, LinkedGroupPolicyObjects, ProtectedFromAccidentalDeletion, Description, gpLink @Ad |
            Sort-Object CanonicalName |
            ForEach-Object {
                $linked = @()
                if ($_.gpLink) {
                    $linked = [regex]::Matches([string]$_.gpLink, 'cn=\{([0-9A-Fa-f-]+)\}') | ForEach-Object { $_.Groups[1].Value }
                } elseif ($_.LinkedGroupPolicyObjects) {
                    $linked = @($_.LinkedGroupPolicyObjects)
                }
                [pscustomobject]@{
                    Name        = $_.Name
                    Canonical   = $_.CanonicalName
                    DN          = $_.DistinguishedName
                    Description = [string]$_.Description
                    Protected   = [bool]$_.ProtectedFromAccidentalDeletion
                    GpoCount    = @( $linked ).Count
                }
            })
    } catch {
        Write-ReportLog "OU read failed: $($_.Exception.Message)" 'WARN'
    }

    [pscustomobject]@{ GPOs = $gpos; OUs = $ous }
}

function Get-DirectoryServicesInfo {
    param($Ad, $ConfigNC, $SchemaNC, $DomainDN)
    $svc = [ordered]@{
        CertificateAuthorities = @()
        DhcpServers            = @()
        Exchange               = $null
        EntraConnect           = @()
        LegacyLaps             = $false
        WindowsLaps            = $false
        Adfs                   = @()
    }

    if ($ConfigNC) {
        try {
            $caBase = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,{0}' -f $ConfigNC
            $svc.CertificateAuthorities = @(Get-ADObject -SearchBase $caBase -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName, displayName, certificateTemplates @Ad -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [pscustomobject]@{
                        Name     = if ($_.displayName) { $_.displayName } else { $_.Name }
                        HostName = [string]$_.dNSHostName
                    }
                })
        } catch { }

        try {
            $dhcpBase = 'CN=NetServices,CN=Services,{0}' -f $ConfigNC
            $svc.DhcpServers = @(Get-ADObject -SearchBase $dhcpBase -LDAPFilter '(objectClass=dHCPClass)' @Ad -ErrorAction SilentlyContinue |
                ForEach-Object { [pscustomobject]@{ Name = $_.Name; DN = $_.DistinguishedName } })
        } catch { }

        try {
            $exBase = 'CN=Microsoft Exchange,CN=Services,{0}' -f $ConfigNC
            $ex = Get-ADObject -Identity $exBase @Ad -ErrorAction SilentlyContinue
            if ($ex) {
                $orgs = @(Get-ADObject -SearchBase $exBase -LDAPFilter '(objectClass=msExchOrganizationContainer)' @Ad -ErrorAction SilentlyContinue)
                $svc.Exchange = [pscustomobject]@{
                    Present      = $true
                    Organizations = @($orgs | ForEach-Object { $_.Name })
                }
            }
        } catch { }

        try {
            $adfsBase = 'CN=ADFS,CN=Microsoft,CN=Program Data,{0}' -f $DomainDN
            # Presence of ADFS farm objects varies; also look for CAs / SPNs via computers later.
        } catch { }
    }

    if ($SchemaNC) {
        try {
            $svc.LegacyLaps  = [bool](Get-ADObject -SearchBase $SchemaNC -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwd)' @Ad -ErrorAction SilentlyContinue)
            $svc.WindowsLaps = [bool](Get-ADObject -SearchBase $SchemaNC -LDAPFilter '(lDAPDisplayName=msLAPS-Password)' @Ad -ErrorAction SilentlyContinue)
            if (-not $svc.WindowsLaps) {
                $svc.WindowsLaps = [bool](Get-ADObject -SearchBase $SchemaNC -LDAPFilter '(name=ms-LAPS-Password)' @Ad -ErrorAction SilentlyContinue)
            }
        } catch { }
    }

    try {
        $svc.EntraConnect = @(Get-ADUser -Filter "Name -like 'MSOL_*' -or SamAccountName -like 'Sync_*' -or Name -like 'AAD_*'" -Properties Description, PasswordLastSet, whenCreated @Ad -ErrorAction SilentlyContinue |
            ForEach-Object {
                [pscustomobject]@{
                    Name            = $_.SamAccountName
                    Description     = [string]$_.Description
                    PasswordLastSet = $_.PasswordLastSet
                    Created         = $_.whenCreated
                }
            })
    } catch { }

    return [pscustomobject]$svc
}

#endregion

#region Findings

function Add-Finding {
    param(
        [System.Collections.IList]$List,
        [ValidateSet('Critical', 'Warning', 'Info', 'Good')]
        [string]$Severity,
        [string]$Area,
        [string]$Title,
        [string]$Detail,
        [string]$Why,
        [string]$Next
    )
    try {
        $item = [pscustomobject]@{
            Severity = $Severity
            Area     = $Area
            Title    = $Title
            Detail   = $Detail
            Why      = $Why
            Next     = $Next
        }
        [void]$List.Add($item)
    } catch {
        throw "Failed to record finding '$Title': $($_.Exception.Message)"
    }
}

function Get-DiscoveryFindings {
    param($Report)

    $findings = [System.Collections.Generic.List[object]]::new()
    $online = @($Report.DomainControllers | Where-Object { $_.Status -eq 'Online' })
    $errorDcs = @($Report.DomainControllers | Where-Object { $_.Status -eq 'Error' })
    $dcs = @($Report.DomainControllers)

    if ((Get-SafeCount $dcs) -lt 2) {
        Add-Finding $findings Critical 'Availability' 'Only one domain controller is visible' `
            'A single DC means any outage takes down authentication, GPO, and LDAP for this domain.' `
            'New environments sometimes start with one DC and never get the second. That is a weekend-ending risk.' `
            'Stand up a second DC in a different site or rack before you change anything else.'
    }

    if ((Get-SafeCount $errorDcs) -gt 0) {
        Add-Finding $findings Warning 'Availability' ("{0} DC(s) could not be queried remotely" -f $errorDcs.Count) `
            (($errorDcs | ForEach-Object { '{0}: {1}' -f $_.ComputerName, $_.Error }) -join '; ') `
            'WinRM, firewall, or credential problems hide roles, disks, and service health.' `
            'Confirm WinRM (5985/5986) and that your account is local admin on those DCs. AD data in this report is still valid.'
    }

    $holders = @($Report.FSMO.Values | ForEach-Object { Get-ShortHostName $_ } | Select-Object -Unique)
    if ($holders.Count -eq 1 -and (Get-SafeCount $dcs) -gt 1) {
        Add-Finding $findings Info 'FSMO' 'All FSMO roles sit on one DC' `
            ("Holder: {0}" -f ($Report.FSMO.Values | Select-Object -First 1)) `
            'Convenient, and common, but that one DC is now a special snowflake. Losing it means seizing roles.' `
            'Keep roles on a pair of well-known hub DCs. Document who owns them and how you would seize.'
    }

    if ($Report.Identity.InfrastructureMaster -and (Get-SafeCount $Report.Identity.Domains) -gt 1) {
        $infraDc = @($dcs | Where-Object { Test-SameHost $_.HostName $Report.Identity.InfrastructureMaster -or (Test-SameHost $_.ComputerName $Report.Identity.InfrastructureMaster) } | Select-Object -First 1)
        if ($infraDc -and $infraDc.IsGlobalCatalog) {
            $allGc = -not (@($dcs | Where-Object { -not $_.IsGlobalCatalog }))
            if (-not $allGc) {
                Add-Finding $findings Warning 'FSMO' 'Infrastructure Master is a GC in a multi-domain forest' `
                    ("{0} holds Infrastructure Master and is a global catalog." -f $infraDc.ComputerName) `
                    'A GC already has every object, so the IM never sees phantoms that need fixing. Cross-domain membership can go stale.' `
                    'Move Infrastructure Master to a non-GC, or make every DC in the domain a GC (typical modern design).'
            }
        }
    }

    if (-not $Report.Identity.RecycleBinEnabled) {
        Add-Finding $findings Warning 'Forest' 'AD Recycle Bin is not enabled' `
            'Deleted users, groups, and computers are not recoverable with full attributes after tombstone processing.' `
            'This is the first optional feature most new owners enable. It cannot be turned off once enabled.' `
            'Enable-ADOptionalFeature "Recycle Bin Feature" after you confirm forest functional level is 2008 R2+.'
    } else {
        Add-Finding $findings Good 'Forest' 'AD Recycle Bin is enabled' `
            'You can restore deleted objects with attributes intact (within tombstone lifetime).' `
            'Know the restore cmdlets before you need them: Get-ADObject -IncludeDeletedObjects / Restore-ADObject.' `
            'Practice a restore in a lab or on a test OU.'
    }

    $ts = $Report.Identity.TombstoneLifetime
    if ($ts -and $ts -lt 60) {
        Add-Finding $findings Warning 'Forest' ("Tombstone lifetime is {0} days" -f $ts) `
            'Default in modern forests is 180 (older default was 60). Shorter windows increase lingering-object risk after a long outage.' `
            'A DC offline longer than tombstone lifetime must not replicate; it needs metadata cleanup / demote.' `
            'Confirm the value was chosen on purpose. Do not raise it casually without understanding backup implications.'
    }

    $replFails = @($Report.ReplicationFailures)
    if ($replFails.Count -gt 0) {
        Add-Finding $findings Critical 'Replication' ("{0} replication failure record(s)" -f $replFails.Count) `
            (($replFails | Select-Object -First 5 | ForEach-Object { '{0} -> {1}: {2}' -f $_.Server, $_.Partner, $_.LastErrorDesc }) -join '; ') `
            'If DCs disagree, passwords, group membership, and GPOs become location-dependent. That is how "it works in this building" starts.' `
            'Start with repadmin /replsummary and the failing partner pair. Fix DNS and connectivity before you seize roles.'
    }

    foreach ($dc in $dcs) {
        $bad = @($dc.ReplicationPartners.Inbound | Where-Object { $_.ConsecutiveFails -gt 0 })
        if ($bad.Count -gt 0) {
            Add-Finding $findings Warning 'Replication' ("{0} has consecutive replication failures" -f $dc.ComputerName) `
                (($bad | ForEach-Object { '{0} ({1} fails, last result {2})' -f $_.Partner, $_.ConsecutiveFails, $_.LastResult }) -join '; ') `
                'A partner that has not succeeded recently will diverge. Users, groups, and passwords will not match.' `
                'On that DC run: Get-ADReplicationPartnerMetadata -Target localhost | Format-Table Partner, LastReplicationSuccess, ConsecutiveReplicationFailures'
        }
    }

    $emptySites = @()
    $siteNames = @($Report.Topology.Sites | ForEach-Object { $_.Name })
    foreach ($site in $siteNames) {
        $hasDc = @($dcs | Where-Object { $_.Site -eq $site })
        $hasSubnet = @($Report.Topology.Subnets | Where-Object { $_.Site -eq $site })
        if ($hasDc.Count -eq 0) {
            $emptySites += $site
        }
        if ($hasDc.Count -gt 0 -and $hasSubnet.Count -eq 0) {
            Add-Finding $findings Warning 'Sites' ("Site '{0}' has DCs but no subnet" -f $site) `
                'Clients and servers whose IPs are not in any subnet map to the Default-First-Site-Name locator behavior.' `
                'Site-aware logon, DFSR, and DFS referrals depend on subnet-to-site mapping.' `
                'Add every production prefix with New-ADReplicationSubnet and associate it to the correct site.'
        }
    }
    if ($emptySites.Count -gt 0) {
        Add-Finding $findings Info 'Sites' ("{0} site(s) have no domain controller" -f $emptySites.Count) `
            ($emptySites -join ', ') `
            'Empty sites are valid (client-only sites) if subnets still exist so clients locate a nearby DC.' `
            'If a site has neither DCs nor subnets, it is leftover topology. Clean it up after you confirm nothing uses it.'
    }

    $trusts = @($Report.Trusts)
    if ($trusts.Count -gt 0) {
        Add-Finding $findings Info 'Trusts' ("{0} trust(s) are configured" -f $trusts.Count) `
            (($trusts | ForEach-Object { '{0} ({1}, {2})' -f $_.Name, $_.TrustType, $_.Direction }) -join '; ') `
            'Trusts extend authentication. They are also the path attackers use to walk forests. Know every one.' `
            'Document direction, transitivity, SID filtering, and who owns the other side. Test with nltest /sc_verify.'
    }

    $pol = $Report.PasswordPolicy.Default
    if ($pol) {
        if ($pol.MinPasswordLength -lt 12) {
            Add-Finding $findings Warning 'Identity' ("Default minimum password length is {0}" -f $pol.MinPasswordLength) `
                'Modern baselines start at 12–15, plus ban-list / Windows Hello / gMSA for services.' `
                'Length beats complexity theater. Fine-grained policies can raise length for admins first.' `
                'Review Default Domain Policy and any FGPP before you tighten anything — you can lock out service accounts.'
        }
        if ($pol.LockoutThreshold -eq 0) {
            Add-Finding $findings Warning 'Identity' 'Account lockout threshold is 0 (never lock out)' `
                'Brute-force password guesses never lock the account.' `
                'A threshold of 0 is sometimes kept to avoid DoS lockouts. Know which it is.' `
                'Prefer smart lockout (Azure) or a modest threshold plus a short observation window.'
        }
        if ($pol.ReversibleEncryptionEnabled) {
            Add-Finding $findings Critical 'Identity' 'Reversible password encryption is enabled' `
                'The domain can store passwords in a way that can be reversed. Almost nothing still needs this.' `
                'This is a red-flag finding on a domain you just inherited.' `
                'Find the GPO/FGPP that set it, confirm no leftover RAS/CHAP dependency, then disable it.'
        }
    }

    if ($Report.Krbtgt -and $Report.Krbtgt.PasswordAgeDays -gt 180) {
        Add-Finding $findings Warning 'Identity' ("krbtgt password is {0} days old" -f $Report.Krbtgt.PasswordAgeDays) `
            'krbtgt is the account that encrypts Kerberos TGTs. A stolen hash remains useful until this password is rotated twice.' `
            'Microsoft guidance is a two-stage reset (then wait for replication / ticket lifetime, then reset again).' `
            'Use Microsoft KRBTGT reset guidance. Never treat this as a casual Set-ADAccountPassword.'
    }

    foreach ($g in @($Report.PrivilegedGroups)) {
        if ($g.Name -in @('Enterprise Admins', 'Schema Admins') -and $g.Count -gt 0) {
            $standing = @($g.Members | Where-Object { $_.SamAccountName -ne 'Administrator' -and $_.objectClass -ne 'group' })
            if ($g.Count -gt 1 -or $standing.Count -gt 0) {
                Add-Finding $findings Warning 'Identity' ("{0} has {1} member(s)" -f $g.Name, $g.Count) `
                    (ConvertTo-TextList ($g.Members | ForEach-Object { $_.SamAccountName })) `
                    'These forest-wide groups should be empty in daily operations. Membership is a break-glass event.' `
                    'Remove standing membership. Use PAM / privileged access workstations / just-in-time groups.'
            }
        }
        if ($g.Name -eq 'Domain Admins' -and $g.Count -gt 5) {
            Add-Finding $findings Warning 'Identity' ("Domain Admins has {0} members" -f $g.Count) `
                (ConvertTo-TextList ($g.Members | ForEach-Object { $_.SamAccountName })) `
                'DA is the keys to the domain. Broad membership is the most common inherited-domain smell.' `
                'Inventory each member, move day-to-day work to lesser groups, and keep DA for DC/domain work only.'
        }
        if ($g.Name -eq 'DnsAdmins' -and $g.Count -gt 0) {
            Add-Finding $findings Info 'Identity' 'DnsAdmins is populated' `
                (ConvertTo-TextList ($g.Members | ForEach-Object { $_.SamAccountName })) `
                'DnsAdmins can be abused for privilege escalation on DCs that run DNS (load a DLL as dns.exe).' `
                'Treat DnsAdmins as tier-0. Confirm every member still needs it.'
        }
    }

    if ($Report.Inventory -and -not $Report.Inventory.Skipped) {
        if ($Report.Inventory.UserStale -gt 0) {
            Add-Finding $findings Info 'Hygiene' ("{0} enabled user(s) have not logged on in {1}+ days" -f $Report.Inventory.UserStale, $Report.StaleDays) `
                'Stale enabled accounts are extra passwords an attacker can try, plus license and audit noise.' `
                'Disable, not delete, until you confirm they are not service or seasonal accounts.' `
                'Start with a disable + description stamp. Deletion comes after a sitting period.'
        }
        if ($Report.Inventory.ComputerStale -gt 0) {
            Add-Finding $findings Info 'Hygiene' ("{0} enabled computer(s) look stale ({1}+ days)" -f $Report.Inventory.ComputerStale, $Report.StaleDays) `
                'Stale computer accounts still have passwords and SPNs. They clutter GPOs and inventories.' `
                'Disable first. Confirm they are not clustered VMs or rarely-booted appliances.' `
                'Use LastLogonDate as a hint, not gospel — it is not replicated in real time.'
        }
        if ((Get-SafeCount $Report.Inventory.UnconstrainedComputers) -gt 0 -or (Get-SafeCount $Report.Inventory.UnconstrainedUsers) -gt 0) {
            Add-Finding $findings Warning 'Delegation' 'Unconstrained Kerberos delegation is in use' `
                ('Computers: {0}. Users: {1}.' -f (ConvertTo-TextList ($Report.Inventory.UnconstrainedComputers.Name)), (ConvertTo-TextList ($Report.Inventory.UnconstrainedUsers.Name))) `
                'Unconstrained delegation lets that host request tickets to any service as the inbound user. It is a tier-0 risk.' `
                'Prefer constrained or resource-based constrained delegation. DCs have this by design — focus on member servers.'
        }
    }

    if ((Get-SafeCount $Report.Services.CertificateAuthorities) -gt 0) {
        Add-Finding $findings Info 'Services' 'Active Directory Certificate Services is present' `
            (ConvertTo-TextList ($Report.Services.CertificateAuthorities | ForEach-Object { '{0} ({1})' -f $_.Name, $_.HostName })) `
            'AD CS is part of your tier-0 boundary. A compromised CA issues logon certificates forever until you catch it.' `
            'Inventory templates, ESC1–ESC8 misissuance patterns, and who can enroll. Back up the CA and its keys.'
    }
    if ((Get-SafeCount $Report.Services.EntraConnect) -gt 0) {
        Add-Finding $findings Info 'Services' 'Entra ID Connect / Azure AD Connect artifacts found' `
            (ConvertTo-TextList ($Report.Services.EntraConnect | ForEach-Object { $_.Name })) `
            'The sync server and its MSOL/AAD_* account are tier-0. They can write back into AD.' `
            'Find the actual sync server, confirm staging vs active, and protect that host like a DC.'
    }
    if (-not $Report.Services.LegacyLaps -and -not $Report.Services.WindowsLaps) {
        Add-Finding $findings Info 'Services' 'No LAPS schema attributes detected' `
            'Local admin passwords on workstations/servers may be shared or unmanaged.' `
            'Windows LAPS is built into current Windows and stores passwords in AD or Entra.' `
            'Plan LAPS before you rotate built-in Administrator passwords across the fleet.'
    }

    foreach ($dc in $online) {
        $low = @($dc.Disks | Where-Object { $_.SizeGB -gt 0 -and ($_.FreeGB / $_.SizeGB) -lt 0.15 })
        if ($low.Count -gt 0) {
            Add-Finding $findings Warning 'Capacity' ("{0} has a volume under 15% free" -f $dc.ComputerName) `
                (($low | ForEach-Object { '{0} {1} GB free of {2} GB' -f $_.DeviceID, $_.FreeGB, $_.SizeGB }) -join '; ') `
                'NTDS and SYSVOL on a full volume halt the DC. You will notice via logon and replication failures.' `
                'Move logs, purge old dumps, expand the VMDK. Never delete NTDS.dit by hand.'
        }
        $frs = @($dc.Services | Where-Object { $_.Name -eq 'NtFrs' -and $_.Status -eq 'Running' })
        $dfsr = @($dc.Services | Where-Object { $_.Name -eq 'DFSR' -and $_.Status -eq 'Running' })
        if ($frs.Count -gt 0 -and $dfsr.Count -eq 0) {
            Add-Finding $findings Warning 'SYSVOL' ("{0} still appears to use FRS for SYSVOL" -f $dc.ComputerName) `
                'File Replication Service is removed in newer Windows. You must migrate to DFSR before a later OS upgrade.' `
                'FRS is a landmine in any domain you plan to raise past 2016-era DCs.' `
                'Check dfsrmig /getglobalstate and plan a DFSR migration window.'
        }
        if ($dc.PendingReboot) {
            Add-Finding $findings Info 'Patching' ("{0} has a pending reboot" -f $dc.ComputerName) `
                'Updates are staged but not fully applied.' `
                'Pending reboots hide whether a DC is actually patched and can block further CU installs.' `
                'Schedule a controlled reboot. Do not reboot every DC at once.'
        }
    }

    if ($findings.Count -eq 0) {
        Add-Finding $findings Good 'Brief' 'No automatic red flags fired' `
            'The obvious health checks passed. That is not the same as "this domain is clean."' `
            'Use the rest of the report to learn topology, who is privileged, and how GPOs are shaped.' `
            'Walk every tab once. Write down questions. Then pick one hygiene project.'
    }

    return $findings.ToArray()
}

#endregion

#region HTML

function New-LearnBox {
    param([string]$Title, [string]$Body)
    @"
<div class="learn">
    <div class="learn-title">$(ConvertTo-HtmlEncoded $Title)</div>
    <p>$(ConvertTo-HtmlEncoded $Body)</p>
</div>
"@
}

function New-Badge {
    param([string]$Text, [string]$Kind = 'neutral')
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    '<span class="badge badge-{0}">{1}</span>' -f $Kind, (ConvertTo-HtmlEncoded $Text)
}

function ConvertTo-EmbeddedJson {
    param($InputObject)
    $json = $InputObject | ConvertTo-Json -Depth 8 -Compress
    if ([string]::IsNullOrEmpty($json)) { return '{}' }
    return ($json -replace '<', '\u003c')
}

function New-ChartItem {
    param(
        [string]$Title,
        [string]$Subtitle = '',
        [string]$Detail = '',
        [string]$Tab = '',
        [string]$Filter = ''
    )
    [ordered]@{
        title    = $Title
        subtitle = $Subtitle
        detail   = $Detail
        tab      = $Tab
        filter   = $Filter
    }
}

function New-DiscoveryReportHtml {
    param($Report)

    $gen = Format-When $Report.GeneratedAt
    $domainName = ConvertTo-HtmlEncoded $Report.Identity.DomainName
    $forestName = ConvertTo-HtmlEncoded $Report.Identity.ForestName
    $dcs = @($Report.DomainControllers)
    $onlineDCs = @($dcs | Where-Object { $_.Status -eq 'Online' }).Count
    $errorDCs = @($dcs | Where-Object { $_.Status -eq 'Error' }).Count
    $skippedDCs = @($dcs | Where-Object { $_.Status -eq 'Skipped' }).Count
    $findings = @($Report.Findings)
    $crit = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $warn = @($findings | Where-Object { $_.Severity -eq 'Warning' }).Count
    $infoN = @($findings | Where-Object { $_.Severity -eq 'Info' }).Count
    $good = @($findings | Where-Object { $_.Severity -eq 'Good' }).Count

    $allRoles = @{}
    $allFeatures = @{}
    foreach ($dc in $dcs | Where-Object { $_.Status -eq 'Online' }) {
        foreach ($role in @($dc.Roles)) {
            $key = [string]$role.DisplayName
            if (-not $allRoles.ContainsKey($key)) {
                $allRoles[$key] = @{
                    Name        = $role.Name
                    DisplayName = $role.DisplayName
                    Description = $role.Description
                    InstalledOn = [System.Collections.Generic.List[string]]::new()
                }
            }
            [void]$allRoles[$key].InstalledOn.Add($dc.ComputerName)
        }
        foreach ($feature in @($dc.Features)) {
            $key = [string]$feature.DisplayName
            if (-not $allFeatures.ContainsKey($key)) {
                $allFeatures[$key] = @{
                    Name        = $feature.Name
                    DisplayName = $feature.DisplayName
                    Description = $feature.Description
                    Type        = $feature.FeatureType
                    InstalledOn = [System.Collections.Generic.List[string]]::new()
                }
            }
            [void]$allFeatures[$key].InstalledOn.Add($dc.ComputerName)
        }
    }

    $findingHtml = New-Object System.Text.StringBuilder
    foreach ($f in $findings) {
        $sev = $f.Severity.ToLowerInvariant()
        [void]$findingHtml.AppendLine(@"
<article class="finding sev-$sev" data-sev="$sev">
    <div class="finding-head">
        <span class="sev-pill sev-$sev">$(ConvertTo-HtmlEncoded $f.Severity)</span>
        <span class="finding-area">$(ConvertTo-HtmlEncoded $f.Area)</span>
        <h3>$(ConvertTo-HtmlEncoded $f.Title)</h3>
    </div>
    <p class="finding-detail">$(ConvertTo-HtmlEncoded $f.Detail)</p>
    <div class="finding-why"><strong>Why it matters.</strong> $(ConvertTo-HtmlEncoded $f.Why)</div>
    <div class="finding-next"><strong>What to do next.</strong> $(ConvertTo-HtmlEncoded $f.Next)</div>
</article>
"@)
    }

    $fsmoCards = New-Object System.Text.StringBuilder
    foreach ($role in $Report.FSMO.Keys) {
        $holder = $Report.FSMO[$role]
        $know = $script:FsmoKnowledge[$role]
        $scope = if ($know) { $know.Scope } else { '' }
        [void]$fsmoCards.AppendLine(@"
<div class="fsmo-card">
    <div class="fsmo-kicker">$(ConvertTo-HtmlEncoded $scope) FSMO</div>
    <h3>$(ConvertTo-HtmlEncoded $role)</h3>
    <div class="fsmo-holder">$(ConvertTo-HtmlEncoded $holder)</div>
    <p>$(ConvertTo-HtmlEncoded $(if ($know) { $know.What } else { '' }))</p>
    <p class="muted">$(ConvertTo-HtmlEncoded $(if ($know) { $know.Why } else { '' }))</p>
    <div class="look">$(ConvertTo-HtmlEncoded $(if ($know) { $know.Look } else { '' }))</div>
</div>
"@)
    }

    $dcCards = New-Object System.Text.StringBuilder
    $cmpRows = New-Object System.Text.StringBuilder
    foreach ($dc in $dcs) {
        $statusClass = switch ($dc.Status) {
            'Online'  { 'online' }
            'Skipped' { 'skipped' }
            default   { 'error' }
        }
        $badges = ''
        if ($dc.IsGlobalCatalog) { $badges += (New-Badge 'GC' 'gc') }
        if ($dc.IsReadOnly) { $badges += (New-Badge 'RODC' 'rodc') }
        if ((Get-SafeCount $dc.FSMORoles) -gt 0) { $badges += (New-Badge 'FSMO' 'fsmo') }

        $fsmoHtml = if ((Get-SafeCount $dc.FSMORoles) -gt 0) {
            ($dc.FSMORoles | ForEach-Object { '<span class="tag tag-fsmo">{0}</span>' -f (ConvertTo-HtmlEncoded $_) }) -join ''
        } else { '<span class="muted">None</span>' }

        $rolesHtml = if ($dc.Status -eq 'Error') {
            '<span class="error-msg">{0}</span>' -f (ConvertTo-HtmlEncoded $dc.Error)
        } elseif ((Get-SafeCount $dc.Roles) -eq 0) {
            '<span class="muted">None collected</span>'
        } else {
            ($dc.Roles | ForEach-Object {
                    '<span class="tag tag-role" title="{0}">{1}</span>' -f (ConvertTo-HtmlEncoded $_.Description), (ConvertTo-HtmlEncoded $_.DisplayName)
                }) -join ''
        }

        $featHtml = if ((Get-SafeCount $dc.Features) -eq 0) {
            '<span class="muted">None collected</span>'
        } else {
            ($dc.Features | ForEach-Object {
                    '<span class="tag tag-feature" title="{0}">{1}</span>' -f (ConvertTo-HtmlEncoded $_.Description), (ConvertTo-HtmlEncoded $_.DisplayName)
                }) -join ''
        }

        $replHtml = if ($dc.ReplicationError) {
            '<span class="error-msg">{0}</span>' -f (ConvertTo-HtmlEncoded $dc.ReplicationError)
        } elseif ((Get-SafeCount $dc.ReplicationPartners.Inbound) -eq 0) {
            '<span class="muted">None detected</span>'
        } else {
            ($dc.ReplicationPartners.Inbound | ForEach-Object {
                    $failClass = if ($_.ConsecutiveFails -gt 0) { 'repl-bad' } else { 'repl-ok' }
                    $parts = ConvertTo-TextList $_.Partitions
                    '<div class="repl-row {0}"><strong>{1}</strong> · last success {2} · fails {3} · {4}</div>' -f `
                        $failClass,
                        (ConvertTo-HtmlEncoded $_.Partner),
                        (ConvertTo-HtmlEncoded (Format-When $_.LastSuccess)),
                        [int]$_.ConsecutiveFails,
                        (ConvertTo-HtmlEncoded $parts)
                }) -join ''
        }

        $diskHtml = if ((Get-SafeCount $dc.Disks) -eq 0) {
            '<span class="muted">N/A</span>'
        } else {
            ($dc.Disks | ForEach-Object {
                    $pct = if ($_.SizeGB) { [int](($_.FreeGB / $_.SizeGB) * 100) } else { 0 }
                    '<div class="disk"><span>{0}</span><span>{1} / {2} GB free ({3}%)</span></div>' -f `
                        (ConvertTo-HtmlEncoded $_.DeviceID), $_.FreeGB, $_.SizeGB, $pct
                }) -join ''
        }

        $svcHtml = if ((Get-SafeCount $dc.Services) -eq 0) {
            '<span class="muted">N/A</span>'
        } else {
            ($dc.Services | ForEach-Object {
                    $cls = if ($_.Status -eq 'Running') { 'svc-on' } else { 'svc-off' }
                    '<span class="tag {0}">{1}: {2}</span>' -f $cls, (ConvertTo-HtmlEncoded $_.Name), (ConvertTo-HtmlEncoded $_.Status)
                }) -join ''
        }

        $searchParts = [System.Collections.Generic.List[string]]::new()
        foreach ($part in @($dc.ComputerName, $dc.HostName, $dc.IPv4Address, $dc.Site, $dc.OperatingSystem, $dc.Status)) {
            if ($part) { [void]$searchParts.Add([string]$part) }
        }
        foreach ($part in @($dc.FSMORoles)) {
            if ($part) { [void]$searchParts.Add([string]$part) }
        }
        foreach ($item in @($dc.Roles) + @($dc.Features)) {
            if ($item.DisplayName) { [void]$searchParts.Add([string]$item.DisplayName) }
            if ($item.Name) { [void]$searchParts.Add([string]$item.Name) }
        }
        $searchBlob = ($searchParts.ToArray() -join ' ')

        [void]$dcCards.AppendLine(@"
<article class="dc-card" data-status="$statusClass" data-name="$(ConvertTo-HtmlEncoded $dc.ComputerName)" data-search="$(ConvertTo-HtmlEncoded $searchBlob.ToLowerInvariant())">
    <header class="dc-head">
        <div>
            <h3>$(ConvertTo-HtmlEncoded $dc.ComputerName)</h3>
            <div class="dc-host">$(ConvertTo-HtmlEncoded $dc.HostName)</div>
        </div>
        <div class="dc-flags">
            <span class="status-badge status-$statusClass">$(ConvertTo-HtmlEncoded $dc.Status)</span>
            $badges
        </div>
    </header>
    <div class="info-grid">
        <div><span class="lbl">IP</span><span>$(ConvertTo-HtmlEncoded $dc.IPv4Address)</span></div>
        <div><span class="lbl">Site</span><span>$(ConvertTo-HtmlEncoded $dc.Site)</span></div>
        <div><span class="lbl">OS</span><span>$(ConvertTo-HtmlEncoded $dc.OperatingSystem)</span></div>
        <div><span class="lbl">Version</span><span>$(ConvertTo-HtmlEncoded $dc.OperatingSystemVersion)</span></div>
        <div><span class="lbl">Last boot</span><span>$(ConvertTo-HtmlEncoded $dc.LastBootTimeFormatted)</span></div>
        <div><span class="lbl">Uptime</span><span class="uptime">$(ConvertTo-HtmlEncoded $dc.Uptime)</span></div>
        <div><span class="lbl">Memory</span><span>$(if ($dc.MemoryGB) { "$($dc.MemoryGB) GB" } else { 'N/A' })</span></div>
        <div><span class="lbl">Time source</span><span>$(ConvertTo-HtmlEncoded $dc.TimeSource)</span></div>
        <div><span class="lbl">Last hotfix</span><span>$(ConvertTo-HtmlEncoded $dc.LastHotfix)</span></div>
        <div><span class="lbl">Pending reboot</span><span>$(if ($null -eq $dc.PendingReboot) { 'N/A' } elseif ($dc.PendingReboot) { 'Yes' } else { 'No' })</span></div>
    </div>
    <section><h4>FSMO roles held</h4><div class="tags">$fsmoHtml</div></section>
    <section><h4>Replication partners (inbound)</h4><div class="repl">$replHtml</div></section>
    <section><h4>Disks</h4>$diskHtml</section>
    <section><h4>Key services</h4><div class="tags">$svcHtml</div></section>
    <section class="collapsible">
        <h4 class="collapse-h" onclick="toggleCollapse(this)"><span class="chev">&#9654;</span> Roles ($(Get-SafeCount $dc.Roles))</h4>
        <div class="collapse-c"><div class="tags">$rolesHtml</div></div>
    </section>
    <section class="collapsible">
        <h4 class="collapse-h" onclick="toggleCollapse(this)"><span class="chev">&#9654;</span> Features ($(Get-SafeCount $dc.Features))</h4>
        <div class="collapse-c"><div class="tags">$featHtml</div></div>
    </section>
</article>
"@)

        $fsmoList = if ((Get-SafeCount $dc.FSMORoles) -gt 0) { $dc.FSMORoles -join ', ' } else { '-' }
        $replList = if ((Get-SafeCount $dc.ReplicationPartners.Inbound) -gt 0) {
            ($dc.ReplicationPartners.Inbound | ForEach-Object { $_.Partner }) -join ', '
        } else { '-' }
        [void]$cmpRows.AppendLine(@"
<tr>
    <td><strong>$(ConvertTo-HtmlEncoded $dc.ComputerName)</strong></td>
    <td><span class="status-badge status-$statusClass">$(ConvertTo-HtmlEncoded $dc.Status)</span></td>
    <td>$(ConvertTo-HtmlEncoded $dc.IPv4Address)</td>
    <td>$(ConvertTo-HtmlEncoded $dc.Site)</td>
    <td>$(ConvertTo-HtmlEncoded $dc.OperatingSystem)</td>
    <td>$(ConvertTo-HtmlEncoded $dc.LastBootTimeFormatted)</td>
    <td>$(ConvertTo-HtmlEncoded $dc.Uptime)</td>
    <td>$(ConvertTo-HtmlEncoded $fsmoList)</td>
    <td>$(ConvertTo-HtmlEncoded $replList)</td>
</tr>
"@)
    }

    $siteRows = New-Object System.Text.StringBuilder
    foreach ($s in @($Report.Topology.Sites)) {
        $dcHere = @($dcs | Where-Object { $_.Site -eq $s.Name })
        $subs = @($Report.Topology.Subnets | Where-Object { $_.Site -eq $s.Name })
        [void]$siteRows.AppendLine(@"
<tr>
    <td><strong>$(ConvertTo-HtmlEncoded $s.Name)</strong></td>
    <td>$(ConvertTo-HtmlEncoded $s.Description)</td>
    <td>$($dcHere.Count)</td>
    <td>$(ConvertTo-HtmlEncoded (ConvertTo-TextList ($dcHere.ComputerName)))</td>
    <td>$(ConvertTo-HtmlEncoded (ConvertTo-TextList ($subs.Name)))</td>
</tr>
"@)
    }

    $subnetRows = (
        @($Report.Topology.Subnets) | ForEach-Object {
            '<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-HtmlEncoded $_.Name), (ConvertTo-HtmlEncoded $_.Site), (ConvertTo-HtmlEncoded $_.Description)
        }
    ) -join "`n"

    $linkRows = (
        @($Report.Topology.Links) | ForEach-Object {
            '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f `
                (ConvertTo-HtmlEncoded $_.Name), $_.Cost, $_.ReplicationFrequencyInMinutes, `
                (ConvertTo-HtmlEncoded $_.InterSiteTransportProtocol), (ConvertTo-HtmlEncoded (ConvertTo-TextList $_.Sites))
        }
    ) -join "`n"

    $trustRows = if ((Get-SafeCount $Report.Trusts) -eq 0) {
        '<tr><td colspan="6" class="muted">No trusts found. This domain does not authenticate other forests/domains via AD trusts.</td></tr>'
    } else {
        (@($Report.Trusts) | ForEach-Object {
                '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f `
                    (ConvertTo-HtmlEncoded $_.Name), (ConvertTo-HtmlEncoded $_.TrustType), (ConvertTo-HtmlEncoded $_.Direction),
                    $(if ($_.ForestTransitive) { 'Yes' } else { 'No' }),
                    $(if ($_.SIDFilteringQuarantined) { 'On' } else { 'Off / unknown' }),
                    $(if ($_.SelectiveAuth) { 'Yes' } else { 'No' })
            }) -join "`n"
    }

    $failRows = if ((Get-SafeCount $Report.ReplicationFailures) -eq 0) {
        '<tr><td colspan="6" class="muted">No domain-scope replication failures returned. That is good — still read partner last-success times on each DC card.</td></tr>'
    } else {
        (@($Report.ReplicationFailures) | ForEach-Object {
                '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f `
                    (ConvertTo-HtmlEncoded $_.Server), (ConvertTo-HtmlEncoded $_.Partner), (ConvertTo-HtmlEncoded $_.FailureType),
                    (ConvertTo-HtmlEncoded (Format-When $_.FirstFailureTime)), $_.FailureCount, (ConvertTo-HtmlEncoded $_.LastErrorDesc)
            }) -join "`n"
    }

    $privHtml = New-Object System.Text.StringBuilder
    foreach ($g in @($Report.PrivilegedGroups)) {
        $memberList = if ($g.Count -eq 0) {
            '<li class="muted">Empty — good for Schema/Enterprise Admins in daily ops.</li>'
        } else {
            (@($g.Members) | ForEach-Object {
                    '<li><strong>{0}</strong> <span class="muted">({1}, {2})</span></li>' -f `
                        (ConvertTo-HtmlEncoded $_.SamAccountName), (ConvertTo-HtmlEncoded $_.Name), (ConvertTo-HtmlEncoded $_.objectClass)
                }) -join ''
        }
        $rec = if ($g.Recursive) { 'recursive' } else { 'direct only' }
        [void]$privHtml.AppendLine(@"
<div class="priv-card" data-priv="$(ConvertTo-HtmlEncoded $g.Name)">
    <h3>$(ConvertTo-HtmlEncoded $g.Name) <span class="count">$($g.Count)</span></h3>
    <div class="muted">Enumeration: $rec</div>
    <ul>$memberList</ul>
</div>
"@)
    }

    $pol = $Report.PasswordPolicy.Default
    $polRows = if ($pol) {
        @(
            @{ k = 'Complexity'; v = $pol.ComplexityEnabled }
            @{ k = 'Minimum length'; v = $pol.MinPasswordLength }
            @{ k = 'Minimum age (days)'; v = $pol.MinPasswordAgeDays }
            @{ k = 'Maximum age (days)'; v = $pol.MaxPasswordAgeDays }
            @{ k = 'History'; v = $pol.PasswordHistoryCount }
            @{ k = 'Lockout threshold'; v = $pol.LockoutThreshold }
            @{ k = 'Lockout duration (min)'; v = $pol.LockoutDurationMinutes }
            @{ k = 'Observation window (min)'; v = $pol.LockoutObservationMinutes }
            @{ k = 'Reversible encryption'; v = $pol.ReversibleEncryptionEnabled }
        ) | ForEach-Object { '<tr><td>{0}</td><td>{1}</td></tr>' -f $_.k, (ConvertTo-HtmlEncoded ([string]$_.v)) }
    } else { '<tr><td colspan="2">Not collected</td></tr>' }
    $polRows = $polRows -join "`n"

    $fgppRows = if ((Get-SafeCount $Report.PasswordPolicy.FineGrained) -eq 0) {
        '<tr><td colspan="5" class="muted">No fine-grained password policies. Everyone uses the default domain policy.</td></tr>'
    } else {
        (@($Report.PasswordPolicy.FineGrained) | ForEach-Object {
                '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f `
                    (ConvertTo-HtmlEncoded $_.Name), $_.Precedence, $_.MinPasswordLength, $_.MaxPasswordAgeDays, $_.LockoutThreshold
            }) -join "`n"
    }

    $upnList = ConvertTo-TextList $Report.Identity.UPNSuffixes 'Only the default domain UPN'
    $domainList = ConvertTo-TextList $Report.Identity.Domains
    $optFeat = if ((Get-SafeCount $Report.Identity.OptionalFeatures) -eq 0) { 'None collected' } else {
        (@($Report.Identity.OptionalFeatures) | ForEach-Object {
                $on = (Get-SafeCount $_.EnabledScopes) -gt 0
                '{0} ({1})' -f $_.Name, $(if ($on) { 'enabled' } else { 'disabled' })
            }) -join ', '
    }

    $inv = $Report.Inventory
    $osRows = if ($inv -and (Get-SafeCount $inv.ComputersByOS) -gt 0) {
        (@($inv.ComputersByOS) | ForEach-Object {
                '<tr><td>{0}</td><td>{1}</td></tr>' -f (ConvertTo-HtmlEncoded $_.OperatingSystem), $_.Count
            }) -join "`n"
    } else { '<tr><td colspan="2" class="muted">Not collected</td></tr>' }

    $staleUserRows = if ($inv -and (Get-SafeCount $inv.StaleUsers) -gt 0) {
        (@($inv.StaleUsers) | ForEach-Object {
                '<tr><td>{0}</td><td>{1}</td></tr>' -f (ConvertTo-HtmlEncoded $_.Name), (ConvertTo-HtmlEncoded (Format-When $_.LastLogonDate))
            }) -join "`n"
    } else { '<tr><td colspan="2" class="muted">None in the first 50 (or inventory skipped).</td></tr>' }

    $stalePcRows = if ($inv -and (Get-SafeCount $inv.StaleComputers) -gt 0) {
        (@($inv.StaleComputers) | ForEach-Object {
                '<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-HtmlEncoded $_.Name), (ConvertTo-HtmlEncoded $_.OS), (ConvertTo-HtmlEncoded (Format-When $_.LastLogonDate))
            }) -join "`n"
    } else { '<tr><td colspan="3" class="muted">None in the first 50 (or inventory skipped).</td></tr>' }

    $gpoRows = if ((Get-SafeCount $Report.GpoOu.GPOs) -eq 0) {
        '<tr><td colspan="4" class="muted">No GPOs collected.</td></tr>'
    } else {
        (@($Report.GpoOu.GPOs | Sort-Object DisplayName) | ForEach-Object {
                '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f `
                    (ConvertTo-HtmlEncoded $_.DisplayName), (ConvertTo-HtmlEncoded $_.GpoStatus),
                    (ConvertTo-HtmlEncoded (Format-When $_.CreationTime)), (ConvertTo-HtmlEncoded (Format-When $_.ModificationTime))
            }) -join "`n"
    }

    $ouRows = if ((Get-SafeCount $Report.GpoOu.OUs) -eq 0) {
        '<tr><td colspan="4" class="muted">No OUs collected.</td></tr>'
    } else {
        (@($Report.GpoOu.OUs) | ForEach-Object {
                $prot = if ($_.Protected) { 'Yes' } else { 'No' }
                '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f `
                    (ConvertTo-HtmlEncoded $_.Canonical), (ConvertTo-HtmlEncoded $_.Description), $prot, $_.GpoCount
            }) -join "`n"
    }

    $roleRows = if ($allRoles.Count -eq 0) {
        '<tr><td colspan="4" class="muted">No installed roles collected. Use a privileged WinRM session or omit -SkipRemoteQueries.</td></tr>'
    } else {
        ($allRoles.Values | Sort-Object DisplayName | ForEach-Object {
                '<tr><td><strong>{0}</strong><br><small class="muted">{1}</small></td><td>{2} / {3}</td><td>{4}</td><td class="desc">{5}</td></tr>' -f `
                    (ConvertTo-HtmlEncoded $_.DisplayName), (ConvertTo-HtmlEncoded $_.Name),
                    $_.InstalledOn.Count, $onlineDCs,
                    (ConvertTo-HtmlEncoded ($_.InstalledOn -join ', ')),
                    (ConvertTo-HtmlEncoded $_.Description)
            }) -join "`n"
    }

    $featureRows = if ($allFeatures.Count -eq 0) {
        '<tr><td colspan="4" class="muted">No installed features collected.</td></tr>'
    } else {
        ($allFeatures.Values | Sort-Object DisplayName | ForEach-Object {
                '<tr><td><strong>{0}</strong><br><small class="muted">{1}</small></td><td>{2}</td><td>{3} / {4}</td><td>{5}</td></tr>' -f `
                    (ConvertTo-HtmlEncoded $_.DisplayName), (ConvertTo-HtmlEncoded $_.Name),
                    (ConvertTo-HtmlEncoded $_.Type), $_.InstalledOn.Count, $onlineDCs,
                    (ConvertTo-HtmlEncoded ($_.InstalledOn -join ', '))
            }) -join "`n"
    }

    $svc = $Report.Services
    $svcRows = @(
        '<tr><td>AD CS (Enterprise CAs)</td><td>{0}</td></tr>' -f (ConvertTo-HtmlEncoded (ConvertTo-TextList (@($svc.CertificateAuthorities) | ForEach-Object { '{0} on {1}' -f $_.Name, $_.HostName }) 'None found'))
        '<tr><td>DHCP servers registered in AD</td><td>{0}</td></tr>' -f (ConvertTo-HtmlEncoded (ConvertTo-TextList (@($svc.DhcpServers).Name) 'None found'))
        '<tr><td>Exchange org in configuration NC</td><td>{0}</td></tr>' -f $(if ($svc.Exchange -and $svc.Exchange.Present) { ConvertTo-HtmlEncoded (ConvertTo-TextList $svc.Exchange.Organizations 'Present') } else { 'Not found' })
        '<tr><td>Entra / Azure AD Connect accounts</td><td>{0}</td></tr>' -f (ConvertTo-HtmlEncoded (ConvertTo-TextList (@($svc.EntraConnect).Name) 'None found'))
        '<tr><td>Legacy LAPS schema (ms-Mcs-AdmPwd)</td><td>{0}</td></tr>' -f $(if ($svc.LegacyLaps) { 'Present' } else { 'Not present' })
        '<tr><td>Windows LAPS schema</td><td>{0}</td></tr>' -f $(if ($svc.WindowsLaps) { 'Present' } else { 'Not present' })
    ) -join "`n"

    $warnRows = if ((Get-SafeCount $Report.Warnings) -eq 0) {
        '<tr><td colspan="2" class="muted">Collectors completed without extra warnings.</td></tr>'
    } else {
        (@($Report.Warnings) | ForEach-Object {
                '<tr><td>{0}</td><td>{1}</td></tr>' -f (ConvertTo-HtmlEncoded $_.Area), (ConvertTo-HtmlEncoded $_.Message)
            }) -join "`n"
    }

    $modeNote = if ($Report.Mode -eq 'OfflineDemo') {
        '<div class="banner">Offline demo data — fictional Northwind Lab forest. Run without -OfflineDemo on a domain-joined box to scan a real environment.</div>'
    } else { '' }

    $krb = $Report.Krbtgt
    $krbHtml = if ($krb) {
        '<tr><td>krbtgt last password set</td><td>{0} ({1} days ago)</td></tr>' -f (ConvertTo-HtmlEncoded (Format-When $krb.PasswordLastSet)), $krb.PasswordAgeDays
    } else { '<tr><td>krbtgt</td><td>Not collected</td></tr>' }

    $invNote = if (-not $inv -or $inv.Skipped) {
        'Directory inventory was skipped.'
    } elseif ($inv.Truncated) {
        "Inventory truncated at $($Report.MaxInventoryObjects) objects — counts are lower bounds."
    } else { 'Inventory covers enabled/disabled, stale, and delegation flags up to the result cap.' }

    $osPalette = @('#6366f1', '#06b6d4', '#8b5cf6', '#14b8a6', '#f43f5e', '#84cc16', '#f97316', '#64748b')
    $chartFindings = [System.Collections.Generic.List[object]]::new()
    foreach ($sev in @('Critical', 'Warning', 'Info', 'Good')) {
        $set = @($findings | Where-Object { $_.Severity -eq $sev })
        if ($set.Count -eq 0) { continue }
        $color = switch ($sev) { 'Critical' { '#e11d48' } 'Warning' { '#f59e0b' } 'Info' { '#3b82f6' } default { '#10b981' } }
        $items = @(
            $set | ForEach-Object {
                New-ChartItem -Title $_.Title -Subtitle $_.Area -Detail $_.Detail -Tab 'brief' -Filter ('finding:{0}' -f $sev.ToLowerInvariant())
            }
        )
        [void]$chartFindings.Add([ordered]@{
                key = $sev.ToLowerInvariant(); label = $sev; value = $set.Count; color = $color; items = $items
            })
    }

    $chartDc = [System.Collections.Generic.List[object]]::new()
    foreach ($st in @('Online', 'Error', 'Skipped')) {
        $set = @($dcs | Where-Object { $_.Status -eq $st })
        if ($set.Count -eq 0) { continue }
        $color = switch ($st) { 'Online' { '#10b981' } 'Error' { '#e11d48' } default { '#f59e0b' } }
        $items = @(
            $set | ForEach-Object {
                New-ChartItem -Title $_.ComputerName -Subtitle $_.Status -Detail ('{0} · {1} · {2}' -f $_.IPv4Address, $_.Site, $_.OperatingSystem) -Tab 'dcs' -Filter ('dc:{0}' -f $st.ToLowerInvariant())
            }
        )
        [void]$chartDc.Add([ordered]@{
                key = $st.ToLowerInvariant(); label = $st; value = $set.Count; color = $color; items = $items
            })
    }

    $chartUsers = @()
    $chartOs = @()
    $chartComputers = @()
    if ($inv -and -not $inv.Skipped) {
        $healthyUsers = [math]::Max(0, [int]$inv.UserEnabled - [int]$inv.UserStale)
        $userSlices = @(
            @{ k = 'healthy'; l = 'Enabled (active)'; v = $healthyUsers; c = '#2563eb'; items = @((New-ChartItem -Title 'Enabled accounts still logging on' -Subtitle "$healthyUsers users" -Detail 'Enabled minus the stale-enabled count. Not a guarantee they are human or current.' -Tab 'identity' -Filter 'identity:users')) }
            @{ k = 'stale'; l = 'Enabled + stale'; v = [int]$inv.UserStale; c = '#f59e0b'; items = @(@($inv.StaleUsers) | ForEach-Object { New-ChartItem -Title $_.Name -Subtitle 'Stale user' -Detail ('Last logon {0}' -f (Format-When $_.LastLogonDate)) -Tab 'identity' -Filter 'identity:stale-users' }) }
            @{ k = 'disabled'; l = 'Disabled'; v = [int]$inv.UserDisabled; c = '#94a3b8'; items = @((New-ChartItem -Title 'Disabled user accounts' -Subtitle "$($inv.UserDisabled) accounts" -Detail 'Disabled is not the same as deleted. Confirm these are intentional.' -Tab 'identity' -Filter 'identity:users')) }
        )
        $chartUsers = @(
            $userSlices | Where-Object { $_.v -gt 0 } | ForEach-Object {
                $sliceItems = @($_.items)
                if ($sliceItems.Count -eq 0) {
                    $sliceItems = @((New-ChartItem -Title $_.l -Subtitle "$($_.v) accounts" -Tab 'identity' -Filter 'identity:users'))
                }
                [ordered]@{ key = $_.k; label = $_.l; value = $_.v; color = $_.c; items = $sliceItems }
            }
        )
        $healthyPc = [math]::Max(0, [int]$inv.ComputerEnabled - [int]$inv.ComputerStale)
        $chartComputers = @(
            @{ k = 'healthy'; l = 'Enabled (active)'; v = $healthyPc; c = '#0ea5e9' },
            @{ k = 'stale'; l = 'Enabled + stale'; v = [int]$inv.ComputerStale; c = '#f59e0b' },
            @{ k = 'disabled'; l = 'Disabled'; v = [int]$inv.ComputerDisabled; c = '#94a3b8' }
        ) | Where-Object { $_.v -gt 0 } | ForEach-Object {
            [ordered]@{
                key = $_.k; label = $_.l; value = $_.v; color = $_.c
                items = @(
                    if ($_.k -eq 'stale') {
                        @($inv.StaleComputers) | ForEach-Object { New-ChartItem -Title $_.Name -Subtitle $_.OS -Detail ('Last logon {0}' -f (Format-When $_.LastLogonDate)) -Tab 'identity' -Filter 'identity:stale-computers' }
                    } else {
                        New-ChartItem -Title $_.l -Subtitle "$($_.v) computers" -Tab 'identity' -Filter 'identity:computers'
                    }
                )
            }
        }
        $iColor = 0
        $chartOs = @(
            @($inv.ComputersByOS) | ForEach-Object {
                $c = $osPalette[$iColor % $osPalette.Count]
                $iColor++
                $osName = $_.OperatingSystem
                $samples = @($inv.StaleComputers | Where-Object { $_.OS -eq $osName } | ForEach-Object {
                        New-ChartItem -Title $_.Name -Subtitle $_.OS -Detail ('Last logon {0}' -f (Format-When $_.LastLogonDate)) -Tab 'identity' -Filter 'identity:os'
                    })
                if ($samples.Count -eq 0) {
                    $samples = @((New-ChartItem -Title $osName -Subtitle "$($_.Count) computers" -Detail 'Full inventory is in the Computers by operating system table.' -Tab 'identity' -Filter 'identity:os'))
                }
                [ordered]@{ key = $osName; label = $osName; value = [int]$_.Count; color = $c; items = $samples }
            }
        )
    }

    $chartPriv = @(
        @($Report.PrivilegedGroups) | ForEach-Object {
            $g = $_
            $items = @(
                @($g.Members) | ForEach-Object {
                    New-ChartItem -Title $_.SamAccountName -Subtitle $_.Name -Detail $_.objectClass -Tab 'identity' -Filter ('priv:{0}' -f $g.Name)
                }
            )
            if ($items.Count -eq 0) {
                $items = @((New-ChartItem -Title $g.Name -Subtitle 'Empty group' -Detail 'Empty is the desired daily state for Schema/Enterprise Admins.' -Tab 'identity' -Filter ('priv:{0}' -f $g.Name)))
            }
            [ordered]@{ key = $g.Name; label = $g.Name; value = [int]$g.Count; color = '#6366f1'; items = $items }
        }
    )

    $chartSites = @(
        @($Report.Topology.Sites) | ForEach-Object {
            $siteName = $_.Name
            $here = @($dcs | Where-Object { $_.Site -eq $siteName })
            $subs = @($Report.Topology.Subnets | Where-Object { $_.Site -eq $siteName })
            $items = @(
                $here | ForEach-Object { New-ChartItem -Title $_.ComputerName -Subtitle $_.Status -Detail ('{0} · {1}' -f $_.IPv4Address, $_.OperatingSystem) -Tab 'dcs' -Filter ('dcname:{0}' -f $_.ComputerName) }
            )
            if ($items.Count -eq 0) {
                $items = @((New-ChartItem -Title $siteName -Subtitle 'No DC in this site' -Detail ('Subnets: {0}' -f (ConvertTo-TextList $subs.Name 'none')) -Tab 'sites' -Filter 'sites:empty'))
            }
            [ordered]@{ key = $siteName; label = $siteName; value = $here.Count; color = '#0ea5e9'; items = $items }
        }
    )

    $chartRoles = @(
        $allRoles.Values | Sort-Object { $_.InstalledOn.Count } -Descending | Select-Object -First 8 | ForEach-Object {
            $display = $_.DisplayName
            $installed = @($_.InstalledOn)
            $items = @(
                $installed | ForEach-Object { New-ChartItem -Title $_ -Subtitle $display -Detail 'Role is installed on this DC.' -Tab 'dcs' -Filter ('dcname:{0}' -f $_) }
            )
            [ordered]@{ key = $display; label = $display; value = $installed.Count; color = '#8b5cf6'; items = $items }
        }
    )

    $fsmoColors = @{
        'Schema Master'         = '#6366f1'
        'Domain Naming Master'  = '#06b6d4'
        'PDC Emulator'          = '#8b5cf6'
        'RID Master'            = '#14b8a6'
        'Infrastructure Master' = '#f59e0b'
    }
    $chartFsmo = @(
        foreach ($roleName in $Report.FSMO.Keys) {
            $holder = [string]$Report.FSMO[$roleName]
            if (-not $holder) { continue }
            $short = Get-ShortHostName $holder
            $c = if ($fsmoColors.ContainsKey($roleName)) { $fsmoColors[$roleName] } else { '#64748b' }
            [ordered]@{
                key   = $roleName
                label = $roleName
                value = 1
                color = $c
                items = @((New-ChartItem -Title $roleName -Subtitle $holder -Detail 'This FSMO write can only happen on this DC.' -Tab 'fsmo' -Filter ('dcname:{0}' -f $short)))
            }
        }
    )

    $chartPayload = [ordered]@{
        findings  = [ordered]@{ title = 'Findings'; type = 'donut'; hint = 'Click a slice to open those cards'; tab = 'brief'; slices = @($chartFindings) }
        dcStatus  = [ordered]@{ title = 'Domain controllers'; type = 'donut'; hint = 'Click to filter DC cards'; tab = 'dcs'; slices = @($chartDc) }
        users     = [ordered]@{ title = 'User accounts'; type = 'donut'; hint = 'Click a slice for the sample list'; tab = 'identity'; slices = @($chartUsers) }
        computers = [ordered]@{ title = 'Computer accounts'; type = 'donut'; hint = 'Click a slice to inspect'; tab = 'identity'; slices = @($chartComputers) }
        os        = [ordered]@{ title = 'Computers by OS'; type = 'donut'; hint = 'Click an OS to see samples'; tab = 'identity'; slices = @($chartOs) }
        priv      = [ordered]@{ title = 'Privileged groups'; type = 'bar'; hint = 'Click a group to see members'; tab = 'identity'; slices = @($chartPriv) }
        sites     = [ordered]@{ title = 'DCs per site'; type = 'bar'; hint = 'Click a site to see its DCs'; tab = 'sites'; slices = @($chartSites) }
        roles     = [ordered]@{ title = 'Top installed roles'; type = 'bar'; hint = 'Click a role to see which DCs have it'; tab = 'roles'; slices = @($chartRoles) }
        fsmo      = [ordered]@{ title = 'FSMO role holders'; type = 'bar'; hint = 'Each bar is one role — click to see the holder'; tab = 'fsmo'; slices = @($chartFsmo) }
    }
    $chartJson = (ConvertTo-EmbeddedJson $chartPayload).Replace('$', '\u0024')

    $css = @'
:root {
  --bg:#f5f7fb; --card:#ffffff; --ink:#0f172a; --muted:#64748b;
  --line:#e2e8f0; --accent:#4f46e5; --accent-2:#0891b2; --warn:#d97706;
  --crit:#e11d48; --good:#059669; --info:#2563eb; --skip:#d97706;
  --fsmo:#7c3aed; --shadow:0 1px 2px rgba(15,23,42,.06), 0 8px 24px rgba(15,23,42,.04);
  --side:#0b1220; --side-ink:#e2e8f0; --side-muted:#94a3b8; --side-active:#818cf8;
  --drawer:420px;
}
:root[data-theme="dark"] {
  --bg:#0b1220; --card:#121a2b; --ink:#e8eef8; --muted:#9aa8bd;
  --line:#243049; --accent:#818cf8; --accent-2:#22d3ee; --warn:#fbbf24;
  --crit:#fb7185; --good:#34d399; --info:#60a5fa; --skip:#fbbf24;
  --fsmo:#c4b5fd; --shadow:none;
  --side:#070b14; --side-ink:#e8eef8; --side-muted:#8b9bb3; --side-active:#a5b4fc;
}
* { box-sizing:border-box; margin:0; padding:0; }
html,body { height:100%; }
body { font-family:"Segoe UI",ui-sans-serif,system-ui,sans-serif; background:var(--bg); color:var(--ink); line-height:1.5; }
.app { display:grid; grid-template-columns:248px 1fr; min-height:100vh; }
.sidebar {
  background:var(--side); color:var(--side-ink); padding:22px 16px; position:sticky; top:0; height:100vh;
  display:flex; flex-direction:column; gap:18px;
}
.brand { padding:4px 10px 12px; }
.brand-kicker { font-size:.68rem; letter-spacing:.14em; text-transform:uppercase; color:var(--side-muted); }
.brand h1 { font-size:1.15rem; font-weight:700; letter-spacing:-.03em; margin-top:4px; }
.side-nav { display:flex; flex-direction:column; gap:4px; }
.tab {
  display:flex; align-items:center; gap:10px; width:100%; text-align:left;
  background:transparent; border:none; color:var(--side-muted); padding:10px 12px; border-radius:10px;
  cursor:pointer; font:inherit; font-size:.92rem;
}
.tab:hover { background:rgba(255,255,255,.06); color:var(--side-ink); }
.tab.active { background:rgba(129,140,248,.16); color:var(--side-active); font-weight:650; }
.tab .ico { width:18px; text-align:center; opacity:.85; }
.side-foot { margin-top:auto; display:flex; flex-direction:column; gap:8px; }
.theme-btn, .ghost-btn {
  background:rgba(255,255,255,.06); color:var(--side-ink); border:1px solid rgba(255,255,255,.08);
  padding:8px 10px; border-radius:10px; cursor:pointer; font:inherit;
}
.main { min-width:0; }
.topbar {
  padding:22px 28px 8px; display:flex; justify-content:space-between; align-items:flex-start; gap:16px;
}
.topbar h2 { font-size:1.55rem; letter-spacing:-.03em; }
.topbar p { color:var(--muted); font-size:.92rem; }
.content { padding:8px 28px 40px; }
.banner { background:#fff7ed; color:#9a3412; padding:10px 14px; border-radius:12px; margin:8px 0 14px; border:1px solid #ffedd5; }
:root[data-theme="dark"] .banner { background:#3b2410; color:#fed7aa; border-color:#7c4a1e; }
.kpis { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin:8px 0 18px; }
.kpi {
  background:var(--card); border:1px solid var(--line); border-radius:16px; padding:14px 16px;
  box-shadow:var(--shadow); cursor:pointer; text-align:left; font:inherit; color:inherit;
  transition:transform .15s ease, border-color .15s ease;
}
.kpi:hover { transform:translateY(-2px); border-color:var(--accent); }
.kpi .n { font-size:1.7rem; font-weight:750; letter-spacing:-.03em; color:var(--accent); }
.kpi.crit .n { color:var(--crit); } .kpi.warn .n { color:var(--warn); }
.kpi.good .n { color:var(--good); } .kpi.fsmo .n { color:var(--fsmo); }
.kpi .l { color:var(--muted); font-size:.75rem; text-transform:uppercase; letter-spacing:.04em; margin-top:2px; }
.panel { display:none; } .panel.active { display:block; }
.card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:18px 20px; box-shadow:var(--shadow); margin-bottom:16px; }
.card h2, .card h3 { letter-spacing:-.02em; }
.learn { background:rgba(79,70,229,.06); border:1px solid rgba(79,70,229,.12); padding:12px 14px; border-radius:12px; margin:0 0 16px; }
.learn-title { font-weight:700; margin-bottom:4px; }
.muted { color:var(--muted); }
.grid-2 { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:12px; }
.chart-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:14px; margin-bottom:18px; }
.chart-card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:16px; box-shadow:var(--shadow); }
.chart-card h3 { font-size:.95rem; margin-bottom:2px; }
.chart-hint { color:var(--muted); font-size:.78rem; margin-bottom:8px; }
.chart-box { min-height:210px; }
.chart-box svg { width:100%; height:auto; display:block; }
.chart-legend { display:flex; flex-wrap:wrap; gap:8px 12px; margin-top:10px; }
.legend-item { display:flex; align-items:center; gap:6px; font-size:.8rem; cursor:pointer; color:var(--muted); }
.legend-item:hover { color:var(--ink); }
.swatch { width:10px; height:10px; border-radius:99px; display:inline-block; }
.kv { display:flex; justify-content:space-between; gap:12px; padding:8px 0; border-bottom:1px solid var(--line); }
.kv span:last-child { font-weight:600; text-align:right; }
.finding { border-radius:14px; padding:16px 18px; margin-bottom:12px; background:var(--card); border:1px solid var(--line); border-left:5px solid var(--info); }
.finding.sev-critical { border-left-color:var(--crit); }
.finding.sev-warning { border-left-color:var(--warn); }
.finding.sev-good { border-left-color:var(--good); }
.finding-head { display:flex; flex-wrap:wrap; gap:8px; align-items:baseline; margin-bottom:8px; }
.finding-head h3 { font-size:1.02rem; }
.finding-area { color:var(--muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.04em; }
.sev-pill { font-size:.68rem; font-weight:700; text-transform:uppercase; padding:2px 8px; border-radius:999px; background:var(--line); }
.sev-pill.sev-critical { background:#ffe4e6; color:#9f1239; }
.sev-pill.sev-warning { background:#ffedd5; color:#9a3412; }
.sev-pill.sev-info { background:#dbeafe; color:#1e3a8a; }
.sev-pill.sev-good { background:#d1fae5; color:#065f46; }
.finding-why, .finding-next { margin-top:8px; }
.fsmo-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:12px; }
.fsmo-card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:16px; border-top:4px solid var(--fsmo); }
.fsmo-kicker { font-size:.72rem; letter-spacing:.08em; text-transform:uppercase; color:var(--fsmo); }
.fsmo-holder { font-size:1.15rem; font-weight:700; margin:6px 0 10px; }
.look { margin-top:8px; font-size:.9rem; }
.dc-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(500px,1fr)); gap:16px; }
.dc-card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:16px 18px; box-shadow:var(--shadow); }
.dc-card.pulse { outline:2px solid var(--accent); }
.dc-head { display:flex; justify-content:space-between; gap:10px; align-items:flex-start; margin-bottom:10px; }
.dc-host { color:var(--muted); font-size:.85rem; }
.info-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:8px; background:rgba(15,23,42,.03); padding:10px; border-radius:10px; margin-bottom:10px; }
.info-grid .lbl { display:block; font-size:.7rem; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
.uptime { color:var(--good); font-weight:700; }
.tags { display:flex; flex-wrap:wrap; gap:6px; }
.tag { display:inline-block; padding:3px 8px; border-radius:6px; font-size:.8rem; background:var(--line); }
.tag-role { background:#e2e8f0; }
.tag-feature { background:#dbeafe; color:#1d4ed8; }
.tag-fsmo { background:#ede9fe; color:#6d28d9; font-weight:650; }
.svc-on { background:#d1fae5; color:#065f46; }
.svc-off { background:#ffe4e6; color:#9f1239; }
.status-badge { padding:2px 8px; border-radius:999px; font-size:.72rem; font-weight:700; text-transform:uppercase; }
.status-online { background:#d1fae5; color:#065f46; }
.status-error { background:#ffe4e6; color:#9f1239; }
.status-skipped { background:#ffedd5; color:#9a3412; }
.badge { margin-left:4px; padding:2px 6px; border-radius:4px; font-size:.68rem; font-weight:700; }
.badge-gc { background:#ffedd5; color:#9a3412; }
.badge-rodc { background:#dbeafe; color:#1d4ed8; }
.badge-fsmo { background:#ede9fe; color:#6d28d9; }
.repl-row { padding:6px 8px; border-radius:8px; margin-bottom:4px; background:rgba(15,23,42,.03); font-size:.85rem; }
.repl-bad { background:#ffe4e6; }
.disk { display:flex; justify-content:space-between; font-size:.9rem; padding:3px 0; }
.controls { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:12px; }
.search { flex:1; min-width:220px; padding:9px 12px; border:1px solid var(--line); border-radius:10px; background:var(--card); color:var(--ink); font:inherit; }
.filter { padding:8px 12px; border:1px solid var(--line); background:var(--card); color:var(--ink); border-radius:10px; cursor:pointer; }
.filter.active { background:var(--accent); color:#fff; border-color:var(--accent); }
table { width:100%; border-collapse:collapse; background:var(--card); border-radius:12px; overflow:hidden; }
th,td { padding:10px 12px; text-align:left; border-bottom:1px solid var(--line); vertical-align:top; }
th { font-size:.75rem; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); background:rgba(15,23,42,.03); }
.desc { color:var(--muted); font-size:.85rem; max-width:360px; }
.table-wrap { overflow-x:auto; }
.hidden { display:none !important; }
.collapsible .collapse-c { display:none; padding-top:8px; }
.collapsible.open .collapse-c { display:block; }
.collapsible.open .chev { transform:rotate(90deg); display:inline-block; }
.collapse-h { cursor:pointer; user-select:none; }
.priv-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:12px; }
.priv-card { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:14px; }
.priv-card.pulse { outline:2px solid var(--accent); }
.priv-card ul { margin:8px 0 0 18px; }
.priv-card .count { float:right; color:var(--accent); }
.error-msg { color:var(--crit); }
.path { margin:0 0 16px; padding:12px 14px; }
.path ol { margin-left:20px; }
footer { text-align:center; color:var(--muted); padding:24px 0; font-size:.85rem; }
.scrim { display:none; position:fixed; inset:0; background:rgba(15,23,42,.35); z-index:40; }
.scrim.show { display:block; }
.drawer {
  position:fixed; top:0; right:0; width:var(--drawer); max-width:100%; height:100vh; background:var(--card);
  border-left:1px solid var(--line); z-index:50; transform:translateX(110%); transition:transform .22s ease;
  display:flex; flex-direction:column; box-shadow:var(--shadow);
}
.drawer.open { transform:translateX(0); }
.drawer-head { display:flex; justify-content:space-between; gap:12px; padding:18px 18px 10px; border-bottom:1px solid var(--line); }
.drawer-crumb { font-size:.75rem; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
.drawer-head h3 { font-size:1.1rem; }
.drawer-close { border:none; background:var(--line); width:32px; height:32px; border-radius:8px; cursor:pointer; font-size:1.1rem; color:var(--ink); }
.drawer-body { overflow:auto; padding:16px 18px 28px; }
.drill-item { border:1px solid var(--line); border-radius:12px; padding:12px; margin-bottom:10px; cursor:pointer; }
.drill-item:hover { border-color:var(--accent); }
.drill-item h4 { font-size:.95rem; }
.chart-slice { cursor:pointer; }
.chart-slice:hover { opacity:.86; }
@media (max-width:960px) {
  .app { grid-template-columns:1fr; }
  .sidebar { position:relative; height:auto; flex-direction:row; flex-wrap:wrap; }
  .side-nav { flex-direction:row; flex-wrap:wrap; }
  .side-foot { margin-top:0; }
  .dc-grid { grid-template-columns:1fr; }
}
@media print {
  .sidebar,.controls,.theme-btn,.drawer,.scrim,.kpis { display:none !important; }
  .panel { display:block !important; }
  .app { display:block; }
  .dc-card,.finding,.card { break-inside:avoid; }
}
'@

    $js = @'
(function () {
  const root = document.documentElement;
  const saved = localStorage.getItem("adbrief-theme");
  if (saved) root.setAttribute("data-theme", saved);
  const themeBtn = document.getElementById("themeBtn");
  if (themeBtn) themeBtn.addEventListener("click", function () {
    const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    localStorage.setItem("adbrief-theme", next);
  });

  function showTab(id) {
    document.querySelectorAll(".tab").forEach(function (t) { t.classList.toggle("active", t.getAttribute("data-tab") === id); });
    document.querySelectorAll(".panel").forEach(function (p) { p.classList.toggle("active", p.id === id); });
    const panel = document.getElementById(id);
    if (panel) panel.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  window.showTab = showTab;
  document.querySelectorAll(".tab").forEach(function (tab) {
    tab.addEventListener("click", function () { showTab(tab.getAttribute("data-tab")); });
  });

  window.toggleCollapse = function (el) {
    el.closest(".collapsible").classList.toggle("open");
  };

  const search = document.getElementById("dcSearch");
  const cards = document.querySelectorAll(".dc-card");
  let statusFilter = "all";
  let nameFilter = "";
  function applyDcFilter() {
    const q = ((search && search.value) || "").toLowerCase();
    cards.forEach(function (card) {
      const hay = card.getAttribute("data-search") || "";
      const okText = !q || hay.indexOf(q) !== -1;
      const st = card.getAttribute("data-status");
      const nm = (card.getAttribute("data-name") || "").toLowerCase();
      const okSt = statusFilter === "all" || st === statusFilter;
      const okName = !nameFilter || nm === nameFilter.toLowerCase();
      card.classList.toggle("hidden", !(okText && okSt && okName));
    });
  }
  if (search) search.addEventListener("input", applyDcFilter);
  document.querySelectorAll("[data-dc-filter]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      document.querySelectorAll("[data-dc-filter]").forEach(function (b) { b.classList.remove("active"); });
      btn.classList.add("active");
      statusFilter = btn.getAttribute("data-dc-filter");
      nameFilter = "";
      applyDcFilter();
    });
  });

  function applyFindingFilter(sev) {
    document.querySelectorAll("[data-find-filter]").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-find-filter") === sev);
    });
    document.querySelectorAll(".finding").forEach(function (f) {
      f.classList.toggle("hidden", !(sev === "all" || f.getAttribute("data-sev") === sev));
    });
  }
  document.querySelectorAll("[data-find-filter]").forEach(function (btn) {
    btn.addEventListener("click", function () { applyFindingFilter(btn.getAttribute("data-find-filter")); });
  });

  function bindTableSearch(inputId, tableId) {
    const input = document.getElementById(inputId);
    const table = document.getElementById(tableId);
    if (!input || !table) return;
    input.addEventListener("input", function () {
      const q = input.value.toLowerCase();
      table.querySelectorAll("tbody tr").forEach(function (row) {
        row.classList.toggle("hidden", row.textContent.toLowerCase().indexOf(q) === -1);
      });
    });
  }
  bindTableSearch("cmpSearch", "cmpTable");
  bindTableSearch("gpoSearch", "gpoTable");
  bindTableSearch("ouSearch", "ouTable");
  bindTableSearch("roleSearch", "roleTable");
  bindTableSearch("featSearch", "featTable");
  bindTableSearch("siteSearch", "siteTable");

  const drawer = document.getElementById("drawer");
  const scrim = document.getElementById("scrim");
  const drawerBody = document.getElementById("drawerBody");
  const drawerTitle = document.getElementById("drawerTitle");
  const drawerCrumb = document.getElementById("drawerCrumb");
  function closeDrawer() {
    if (drawer) drawer.classList.remove("open");
    if (scrim) scrim.classList.remove("show");
  }
  window.closeDrawer = closeDrawer;
  if (document.getElementById("drawerClose")) document.getElementById("drawerClose").addEventListener("click", closeDrawer);
  if (scrim) scrim.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeDrawer(); });

  function applyFilter(filter) {
    if (!filter) return;
    const parts = String(filter).split(":");
    const kind = parts[0];
    const val = parts.slice(1).join(":");
    if (kind === "finding") applyFindingFilter(val || "all");
    if (kind === "dc") {
      statusFilter = val || "all";
      nameFilter = "";
      document.querySelectorAll("[data-dc-filter]").forEach(function (b) {
        b.classList.toggle("active", b.getAttribute("data-dc-filter") === statusFilter);
      });
      applyDcFilter();
    }
    if (kind === "dcname") {
      statusFilter = "all";
      nameFilter = val;
      if (search) search.value = "";
      applyDcFilter();
      document.querySelectorAll(".dc-card").forEach(function (c) {
        c.classList.toggle("pulse", (c.getAttribute("data-name") || "").toLowerCase() === val.toLowerCase());
      });
    }
    if (kind === "priv") {
      document.querySelectorAll(".priv-card").forEach(function (c) {
        const on = (c.getAttribute("data-priv") || "") === val;
        c.classList.toggle("pulse", on);
        if (on) c.scrollIntoView({ behavior: "smooth", block: "center" });
      });
    }
  }

  function openDrill(chart, slice) {
    if (!drawer || !slice) return;
    drawerCrumb.textContent = (chart.title || "Chart") + " / " + (slice.label || "");
    drawerTitle.textContent = (slice.label || "Details") + " · " + (slice.value || 0);
    const items = slice.items || [];
    if (!items.length) {
      drawerBody.innerHTML = "<p class='muted'>No drill-down rows for this slice.</p>";
    } else {
      drawerBody.innerHTML = items.map(function (item) {
        return "<article class='drill-item' data-tab='" + (item.tab || "") + "' data-filter='" + (item.filter || "") + "'>" +
          "<h4>" + escapeHtml(item.title || "") + "</h4>" +
          (item.subtitle ? "<div class='muted'>" + escapeHtml(item.subtitle) + "</div>" : "") +
          (item.detail ? "<p>" + escapeHtml(item.detail) + "</p>" : "") +
          "</article>";
      }).join("");
      drawerBody.querySelectorAll(".drill-item").forEach(function (el) {
        el.addEventListener("click", function () {
          const tab = el.getAttribute("data-tab");
          const filter = el.getAttribute("data-filter");
          if (tab) showTab(tab);
          applyFilter(filter);
        });
      });
    }
    drawer.classList.add("open");
    scrim.classList.add("show");
    if (chart.tab) showTab(chart.tab);
    if (slice.items && slice.items[0] && slice.items[0].filter) applyFilter(slice.items[0].filter);
  }
  window.openDrill = openDrill;

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (ch) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch];
    });
  }

  const ns = "http://www.w3.org/2000/svg";
  function svgEl(name, attrs) {
    const el = document.createElementNS(ns, name);
    Object.keys(attrs || {}).forEach(function (k) { el.setAttribute(k, attrs[k]); });
    return el;
  }
  function polar(cx, cy, r, a) { return [cx + r * Math.cos(a), cy + r * Math.sin(a)]; }

  function renderDonut(host, chart) {
    const slices = (chart.slices || []).filter(function (s) { return Number(s.value) > 0; });
    const total = slices.reduce(function (n, s) { return n + Number(s.value); }, 0) || 1;
    const svg = svgEl("svg", { viewBox: "0 0 220 180", role: "img" });
    let angle = -Math.PI / 2;
    const cx = 90, cy = 90, r = 70, r0 = 42;
    slices.forEach(function (slice) {
      const sweep = (Number(slice.value) / total) * Math.PI * 2;
      const a2 = angle + sweep;
      const large = sweep > Math.PI ? 1 : 0;
      const p1 = polar(cx, cy, r, angle), p2 = polar(cx, cy, r, a2);
      const i1 = polar(cx, cy, r0, a2), i2 = polar(cx, cy, r0, angle);
      const d = "M " + p1[0] + " " + p1[1] + " A " + r + " " + r + " 0 " + large + " 1 " + p2[0] + " " + p2[1] +
        " L " + i1[0] + " " + i1[1] + " A " + r0 + " " + r0 + " 0 " + large + " 0 " + i2[0] + " " + i2[1] + " Z";
      const path = svgEl("path", { d: d, fill: slice.color || "#64748b", class: "chart-slice" });
      path.addEventListener("click", function () { openDrill(chart, slice); });
      path.appendChild(document.createElementNS(ns, "title")).textContent = slice.label + " · " + slice.value;
      svg.appendChild(path);
      angle = a2;
    });
    svg.appendChild(svgEl("text", { x: 90, y: 86, "text-anchor": "middle", fill: "currentColor", "font-size": "18", "font-weight": "700" })).textContent = String(total);
    svg.appendChild(svgEl("text", { x: 90, y: 104, "text-anchor": "middle", fill: "currentColor", "font-size": "10", opacity: ".65" })).textContent = "total";
    host.appendChild(svg);
    renderLegend(host, chart, slices);
  }

  function renderBar(host, chart) {
    const slices = chart.slices || [];
    const max = Math.max.apply(null, slices.map(function (s) { return Number(s.value) || 0; }).concat([1]));
    const rowH = 28;
    const h = Math.max(140, 20 + slices.length * rowH);
    const svg = svgEl("svg", { viewBox: "0 0 360 " + h, role: "img" });
    slices.forEach(function (slice, i) {
      const y = 8 + i * rowH;
      const w = Math.max(4, (Number(slice.value) / max) * 200);
      const label = svgEl("text", { x: 0, y: y + 14, fill: "currentColor", "font-size": "11" });
      label.textContent = (slice.label || "").slice(0, 22);
      svg.appendChild(label);
      const rect = svgEl("rect", { x: 130, y: y + 2, width: String(w), height: "16", rx: "8", fill: slice.color || "#6366f1", class: "chart-slice" });
      rect.addEventListener("click", function () { openDrill(chart, slice); });
      svg.appendChild(rect);
      svg.appendChild(svgEl("text", { x: 136 + w, y: y + 14, fill: "currentColor", "font-size": "11" })).textContent = String(slice.value);
    });
    host.appendChild(svg);
  }

  function renderLegend(host, chart, slices) {
    const legend = document.createElement("div");
    legend.className = "chart-legend";
    slices.forEach(function (slice) {
      const item = document.createElement("button");
      item.type = "button";
      item.className = "legend-item";
      item.innerHTML = "<span class='swatch' style='background:" + (slice.color || "#64748b") + "'></span>" +
        escapeHtml(slice.label) + " · " + slice.value;
      item.addEventListener("click", function () { openDrill(chart, slice); });
      legend.appendChild(item);
    });
    host.appendChild(legend);
  }

  function renderChart(host, chart) {
    if (!host || !chart) {
      if (host) host.innerHTML = "<p class='muted'>No data for this chart.</p>";
      return;
    }
    host.innerHTML = "";
    const slices = chart.slices || [];
    if (!slices.length) {
      host.innerHTML = "<p class='muted'>Nothing to chart in this collection.</p>";
      return;
    }
    if (chart.type === "bar") renderBar(host, chart);
    else renderDonut(host, chart);
  }

  let charts = {};
  const raw = document.getElementById("chartData");
  try { charts = raw ? JSON.parse(raw.textContent) : {}; } catch (e) { charts = {}; }

  document.querySelectorAll("[data-chart]").forEach(function (el) {
    renderChart(el, charts[el.getAttribute("data-chart")]);
  });
  document.querySelectorAll("[data-open-chart]").forEach(function (el) {
    el.addEventListener("click", function () {
      const name = el.getAttribute("data-open-chart");
      const key = el.getAttribute("data-open-slice");
      const chart = charts[name];
      if (!chart) return;
      const slice = (chart.slices || []).find(function (s) { return s.key === key; }) || chart.slices[0];
      openDrill(chart, slice);
    });
  });
})();
'@

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD Domain Brief — $domainName</title>
<style>
$css
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-kicker">Active Directory</div>
      <h1>Domain brief</h1>
    </div>
    <nav class="side-nav">
      <button class="tab active" data-tab="brief"><span class="ico">&#9632;</span> Dashboard</button>
      <button class="tab" data-tab="forest"><span class="ico">&#9633;</span> Forest &amp; domain</button>
      <button class="tab" data-tab="fsmo"><span class="ico">&#9670;</span> FSMO</button>
      <button class="tab" data-tab="sites"><span class="ico">&#9646;</span> Sites &amp; replication</button>
      <button class="tab" data-tab="dcs"><span class="ico">&#9638;</span> Domain controllers</button>
      <button class="tab" data-tab="identity"><span class="ico">&#9650;</span> Identity</button>
      <button class="tab" data-tab="gpo"><span class="ico">&#9660;</span> GPOs &amp; OUs</button>
      <button class="tab" data-tab="roles"><span class="ico">&#9644;</span> Roles &amp; features</button>
    </nav>
    <div class="side-foot">
      <button class="theme-btn" id="themeBtn" type="button">Toggle theme</button>
      <div class="muted" style="font-size:.75rem;padding:0 4px">Click any chart slice or KPI to drill down.</div>
    </div>
  </aside>
  <div class="main">
    <header class="topbar">
      <div>
        <h2>$domainName</h2>
        <p>Forest $forestName · Generated $gen · $($Report.Mode)</p>
      </div>
    </header>
    <div class="content">
  $modeNote

  <section id="brief" class="panel active">
    $(New-LearnBox 'Start on the charts' 'This dashboard is the map of the domain you just inherited. Click a pie slice, bar, legend item, or KPI tile. A drawer lists the underlying objects; click a row to jump to that section.')
    <div class="kpis">
      <button class="kpi" type="button" data-open-chart="dcStatus"><div class="n">$(Get-SafeCount $dcs)</div><div class="l">Domain controllers</div></button>
      <button class="kpi good" type="button" data-open-chart="dcStatus" data-open-slice="online"><div class="n">$onlineDCs</div><div class="l">Online / queried</div></button>
      <button class="kpi crit" type="button" data-open-chart="dcStatus" data-open-slice="error"><div class="n">$errorDCs</div><div class="l">Unreachable</div></button>
      <button class="kpi fsmo" type="button" data-open-chart="fsmo"><div class="n">5</div><div class="l">FSMO roles</div></button>
      <button class="kpi crit" type="button" data-open-chart="findings" data-open-slice="critical"><div class="n">$crit</div><div class="l">Critical findings</div></button>
      <button class="kpi warn" type="button" data-open-chart="findings" data-open-slice="warning"><div class="n">$warn</div><div class="l">Warnings</div></button>
      <button class="kpi" type="button" data-open-chart="roles"><div class="n">$($allRoles.Count)</div><div class="l">Unique roles</div></button>
      <button class="kpi" type="button" data-open-chart="users"><div class="n">$(if ($inv -and -not $inv.Skipped) { $inv.UserEnabled } else { '–' })</div><div class="l">Enabled users</div></button>
    </div>
    <div class="chart-grid">
      <div class="chart-card"><h3>Findings by severity</h3><p class="chart-hint">Click a slice to open those findings</p><div class="chart-box" data-chart="findings"></div></div>
      <div class="chart-card"><h3>Domain controller status</h3><p class="chart-hint">Click a slice to filter DC cards</p><div class="chart-box" data-chart="dcStatus"></div></div>
      <div class="chart-card"><h3>User account mix</h3><p class="chart-hint">Active vs stale vs disabled</p><div class="chart-box" data-chart="users"></div></div>
      <div class="chart-card"><h3>Computers by OS</h3><p class="chart-hint">Click an OS for sample machines</p><div class="chart-box" data-chart="os"></div></div>
      <div class="chart-card"><h3>Privileged group size</h3><p class="chart-hint">Click a bar to list members</p><div class="chart-box" data-chart="priv"></div></div>
      <div class="chart-card"><h3>DCs per site</h3><p class="chart-hint">Click a site to see its controllers</p><div class="chart-box" data-chart="sites"></div></div>
      <div class="chart-card"><h3>FSMO role holders</h3><p class="chart-hint">Each bar is one role — click for the holder</p><div class="chart-box" data-chart="fsmo"></div></div>
    </div>
    <div class="card path">
      <strong>Then read the sections in this order</strong>
      <ol>
        <li>Findings below — inherited risk, in priority order.</li>
        <li>Forest &amp; domain — what this directory is.</li>
        <li>FSMO — who can do the operations nobody else can.</li>
        <li>Sites &amp; replication — whether every DC has the same truth.</li>
        <li>Identity — who is powerful and what is stale.</li>
      </ol>
    </div>
    <div class="controls">
      <button class="filter active" data-find-filter="all">All ($($findings.Count))</button>
      <button class="filter" data-find-filter="critical">Critical ($crit)</button>
      <button class="filter" data-find-filter="warning">Warning ($warn)</button>
      <button class="filter" data-find-filter="info">Info ($infoN)</button>
      <button class="filter" data-find-filter="good">Good ($good)</button>
    </div>
    $($findingHtml.ToString())
    <div class="card">
      <h2>Collector warnings</h2>
      <div class="table-wrap"><table><thead><tr><th>Area</th><th>Message</th></tr></thead><tbody>$warnRows</tbody></table></div>
    </div>
  </section>

  <section id="forest" class="panel">
    $(New-LearnBox 'Identity first' 'Functional level is not the same as the OS on your DCs. The schema version tells you the newest AD binary that extended the forest. Recycle Bin, UPNs, and trusts tell you how this directory connects to the rest of the world.')
    <div class="grid-2">
      <div class="card">
        <h2>Forest</h2>
        <div class="kv"><span>Name</span><span>$(ConvertTo-HtmlEncoded $Report.Identity.ForestName)</span></div>
        <div class="kv"><span>Functional level</span><span>$(ConvertTo-HtmlEncoded $Report.Identity.ForestMode)</span></div>
        <div class="kv"><span>Root domain</span><span>$(ConvertTo-HtmlEncoded $Report.Identity.RootDomain)</span></div>
        <div class="kv"><span>Domains</span><span>$(ConvertTo-HtmlEncoded $domainList)</span></div>
        <div class="kv"><span>Schema</span><span>$(ConvertTo-HtmlEncoded $Report.Identity.SchemaVersionName)</span></div>
        <div class="kv"><span>Recycle Bin</span><span>$(if ($Report.Identity.RecycleBinEnabled) { 'Enabled' } else { 'Not enabled' })</span></div>
        <div class="kv"><span>Tombstone lifetime</span><span>$($Report.Identity.TombstoneLifetime) days</span></div>
        <div class="kv"><span>Optional features</span><span>$(ConvertTo-HtmlEncoded $optFeat)</span></div>
      </div>
      <div class="card">
        <h2>Domain</h2>
        <div class="kv"><span>DNS name</span><span>$(ConvertTo-HtmlEncoded $Report.Identity.DomainName)</span></div>
        <div class="kv"><span>NetBIOS</span><span>$(ConvertTo-HtmlEncoded $Report.Identity.DomainNetBIOS)</span></div>
        <div class="kv"><span>SID</span><span>$(ConvertTo-HtmlEncoded $Report.Identity.DomainSID)</span></div>
        <div class="kv"><span>Functional level</span><span>$(ConvertTo-HtmlEncoded $Report.Identity.DomainMode)</span></div>
        <div class="kv"><span>Distinguished name</span><span>$(ConvertTo-HtmlEncoded $Report.Identity.DomainDN)</span></div>
        <div class="kv"><span>UPN suffixes</span><span>$(ConvertTo-HtmlEncoded $upnList)</span></div>
        <div class="kv"><span>Child domains</span><span>$(ConvertTo-HtmlEncoded (ConvertTo-TextList $Report.Identity.ChildDomains 'None'))</span></div>
        <div class="kv"><span>Queried DC</span><span>$(ConvertTo-HtmlEncoded $Report.Identity.RootDSEHost)</span></div>
      </div>
    </div>
    <div class="card">
      <h2>Directory-integrated services</h2>
      $(New-LearnBox 'These objects live in the configuration partition' 'If you see a CA, Exchange, DHCP registration, or Entra Connect account, those products are part of this forest even if nobody mentioned them in the handover.')
      <div class="table-wrap"><table><thead><tr><th>Service</th><th>What we found</th></tr></thead><tbody>$svcRows</tbody></table></div>
    </div>
    <div class="card">
      <h2>Trusts</h2>
      $(New-LearnBox 'A trust is a security boundary you chose to thin' 'SID filtering should stay on for most external trusts. Forest-transitive trusts mean a compromise on the other side can become your problem.')
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Direction</th><th>Forest transitive</th><th>SID filtering</th><th>Selective auth</th></tr></thead><tbody>$trustRows</tbody></table></div>
    </div>
  </section>

  <section id="fsmo" class="panel">
    $(New-LearnBox 'FSMO means "this write can only happen in one place"' 'Most AD writes replicate multimaster. Five operations do not. If you inherit a domain, memorize the holders and keep them on DCs you would actually answer a page for.')
    <div class="chart-grid">
      <div class="chart-card"><h3>FSMO role holders</h3><p class="chart-hint">Each bar is one role — click to see the holder DC</p><div class="chart-box" data-chart="fsmo"></div></div>
    </div>
    <div class="fsmo-grid">
      $($fsmoCards.ToString())
    </div>
  </section>

  <section id="sites" class="panel">
    $(New-LearnBox 'Sites are how AD thinks about the network' 'A site should be a set of well-connected subnets. Clients in those subnets find a local DC. Site links (cost + interval) decide how often DCs across WAN links pull changes. Empty leftover sites and missing subnets are the usual mess.')
    <div class="chart-grid">
      <div class="chart-card"><h3>DCs per site</h3><p class="chart-hint">Click a bar to open the controllers in that site</p><div class="chart-box" data-chart="sites"></div></div>
    </div>
    <div class="controls"><input class="search" id="siteSearch" placeholder="Filter sites..."></div>
    <div class="table-wrap"><table id="siteTable"><thead><tr><th>Site</th><th>Description</th><th>DCs</th><th>DC names</th><th>Subnets</th></tr></thead><tbody>$($siteRows.ToString())</tbody></table></div>
    <div class="card" style="margin-top:16px">
      <h2>Subnets</h2>
      <div class="table-wrap"><table><thead><tr><th>Prefix</th><th>Site</th><th>Description</th></tr></thead><tbody>$subnetRows</tbody></table></div>
    </div>
    <div class="card">
      <h2>Site links</h2>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Cost</th><th>Interval (min)</th><th>Transport</th><th>Sites</th></tr></thead><tbody>$linkRows</tbody></table></div>
    </div>
    <div class="card">
      <h2>Replication failures (domain scope)</h2>
      <div class="table-wrap"><table><thead><tr><th>Server</th><th>Partner</th><th>Type</th><th>First failure</th><th>Count</th><th>Last error</th></tr></thead><tbody>$failRows</tbody></table></div>
    </div>
  </section>

  <section id="dcs" class="panel">
    $(New-LearnBox 'A DC is more than "online"' 'Uptime is not a virtue if patches are pending. Time source should chain to the PDC Emulator. Disks under 15% free are an outage waiting to happen. Inbound partners with consecutive failures mean this DC is drifting.')
    <div class="chart-grid">
      <div class="chart-card"><h3>Controller status</h3><p class="chart-hint">Click a slice to show only those DCs</p><div class="chart-box" data-chart="dcStatus"></div></div>
      <div class="chart-card"><h3>Roles on these DCs</h3><p class="chart-hint">Click a role to see which DC has it</p><div class="chart-box" data-chart="roles"></div></div>
    </div>
    <div class="controls">
      <input class="search" id="dcSearch" placeholder="Search name, IP, site, OS, FSMO, role, or feature...">
      <button class="filter active" data-dc-filter="all">All</button>
      <button class="filter" data-dc-filter="online">Online</button>
      <button class="filter" data-dc-filter="error">Errors</button>
      <button class="filter" data-dc-filter="skipped">Skipped</button>
    </div>
    <div class="dc-grid">
      $($dcCards.ToString())
    </div>
    <div class="card" style="margin-top:18px">
      <h2>Comparison table</h2>
      <div class="controls"><input class="search" id="cmpSearch" placeholder="Filter comparison rows..."></div>
      <div class="table-wrap">
        <table id="cmpTable">
          <thead><tr><th>Server</th><th>Status</th><th>IP</th><th>Site</th><th>OS</th><th>Last boot</th><th>Uptime</th><th>FSMO</th><th>Inbound partners</th></tr></thead>
          <tbody>$($cmpRows.ToString())</tbody>
        </table>
      </div>
    </div>
  </section>

  <section id="identity" class="panel">
    $(New-LearnBox 'Privilege is the real map of the domain' 'Domain Admins, Enterprise Admins, Schema Admins, DnsAdmins, and Backup Operators are tier-0. Count the humans, not just the groups. krbtgt age tells you how long a stolen KRBTGT hash would keep working.')
    <div class="chart-grid">
      <div class="chart-card"><h3>User account mix</h3><p class="chart-hint">Click for stale samples or the hygiene tables</p><div class="chart-box" data-chart="users"></div></div>
      <div class="chart-card"><h3>Computer account mix</h3><p class="chart-hint">Click stale to see the sample list</p><div class="chart-box" data-chart="computers"></div></div>
      <div class="chart-card"><h3>Computers by OS</h3><p class="chart-hint">Click an OS family</p><div class="chart-box" data-chart="os"></div></div>
      <div class="chart-card"><h3>Privileged groups</h3><p class="chart-hint">Click a bar to list members</p><div class="chart-box" data-chart="priv"></div></div>
    </div>
    <div class="grid-2">
      <div class="card">
        <h2>Default domain password policy</h2>
        <div class="table-wrap"><table><tbody>$polRows</tbody></table></div>
      </div>
      <div class="card">
        <h2>KRBTGT &amp; hygiene snapshot</h2>
        <div class="table-wrap"><table><tbody>
          $krbHtml
          <tr><td>Enabled users</td><td>$(if ($inv) { $inv.UserEnabled } else { 'n/a' })</td></tr>
          <tr><td>Disabled users</td><td>$(if ($inv) { $inv.UserDisabled } else { 'n/a' })</td></tr>
          <tr><td>Stale enabled users ($($Report.StaleDays)+ days)</td><td>$(if ($inv) { $inv.UserStale } else { 'n/a' })</td></tr>
          <tr><td>Never logged on (enabled)</td><td>$(if ($inv) { $inv.UserNeverLogon } else { 'n/a' })</td></tr>
          <tr><td>Password never expires</td><td>$(if ($inv) { $inv.UserNeverExpire } else { 'n/a' })</td></tr>
          <tr><td>adminCount &ge; 1</td><td>$(if ($inv) { $inv.UserAdminCount } else { 'n/a' })</td></tr>
          <tr><td>Enabled computers</td><td>$(if ($inv) { $inv.ComputerEnabled } else { 'n/a' })</td></tr>
          <tr><td>Stale enabled computers</td><td>$(if ($inv) { $inv.ComputerStale } else { 'n/a' })</td></tr>
          <tr><td>Security groups</td><td>$(if ($inv) { $inv.GroupsSecurity } else { 'n/a' })</td></tr>
          <tr><td>Distribution groups</td><td>$(if ($inv) { $inv.GroupsDistribution } else { 'n/a' })</td></tr>
        </tbody></table></div>
        <p class="muted" style="margin-top:8px">$(ConvertTo-HtmlEncoded $invNote)</p>
      </div>
    </div>
    <div class="card">
      <h2>Fine-grained password policies</h2>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Precedence</th><th>Min length</th><th>Max age (days)</th><th>Lockout</th></tr></thead><tbody>$fgppRows</tbody></table></div>
    </div>
    <div class="card">
      <h2>Privileged groups</h2>
      <div class="priv-grid">$($privHtml.ToString())</div>
    </div>
    <div class="grid-2">
      <div class="card">
        <h2>Stale users (sample)</h2>
        <div class="table-wrap"><table><thead><tr><th>Account</th><th>Last logon</th></tr></thead><tbody>$staleUserRows</tbody></table></div>
      </div>
      <div class="card">
        <h2>Stale computers (sample)</h2>
        <div class="table-wrap"><table><thead><tr><th>Name</th><th>OS</th><th>Last logon</th></tr></thead><tbody>$stalePcRows</tbody></table></div>
      </div>
    </div>
    <div class="card">
      <h2>Computers by operating system</h2>
      <div class="table-wrap"><table><thead><tr><th>Operating system</th><th>Count</th></tr></thead><tbody>$osRows</tbody></table></div>
    </div>
  </section>

  <section id="gpo" class="panel">
    $(New-LearnBox 'GPOs are where "the domain does X" actually lives' 'Unlinked GPOs are leftover experiments. Unprotected OUs can be deleted by a tired click. Start from the OU tree, then read which GPOs hang off each OU. Default Domain Policy and Default Domain Controllers Policy deserve a careful read on day one.')
    <div class="card">
      <h2>Group Policy objects ($(Get-SafeCount $Report.GpoOu.GPOs))</h2>
      <div class="controls"><input class="search" id="gpoSearch" placeholder="Filter GPOs..."></div>
      <div class="table-wrap"><table id="gpoTable"><thead><tr><th>Name</th><th>Status</th><th>Created</th><th>Modified</th></tr></thead><tbody>$gpoRows</tbody></table></div>
    </div>
    <div class="card">
      <h2>OU tree ($(Get-SafeCount $Report.GpoOu.OUs))</h2>
      <div class="controls"><input class="search" id="ouSearch" placeholder="Filter OUs..."></div>
      <div class="table-wrap"><table id="ouTable"><thead><tr><th>Canonical name</th><th>Description</th><th>Protected</th><th>Linked GPOs</th></tr></thead><tbody>$ouRows</tbody></table></div>
    </div>
  </section>

  <section id="roles" class="panel">
    $(New-LearnBox 'Installed roles tell you what else these DCs are doing' 'A DC that is also DHCP, CA, or RDS is a concentration-of-risk problem. Compare roles across DCs — drift is how "only DC02 has the thing" incidents start.')
    <div class="chart-grid">
      <div class="chart-card"><h3>Top installed roles</h3><p class="chart-hint">Click a bar to see the DCs that have it</p><div class="chart-box" data-chart="roles"></div></div>
    </div>
    <div class="card">
      <h2>Roles across the domain</h2>
      <div class="controls"><input class="search" id="roleSearch" placeholder="Filter roles..."></div>
      <div class="table-wrap"><table id="roleTable"><thead><tr><th>Role</th><th>Installed on</th><th>Domain controllers</th><th>Description</th></tr></thead><tbody>$roleRows</tbody></table></div>
    </div>
    <div class="card">
      <h2>Features across the domain</h2>
      <div class="controls"><input class="search" id="featSearch" placeholder="Filter features..."></div>
      <div class="table-wrap"><table id="featTable"><thead><tr><th>Feature</th><th>Type</th><th>Installed on</th><th>Domain controllers</th></tr></thead><tbody>$featureRows</tbody></table></div>
    </div>
  </section>

  <footer>
    <p>AD Domain Discovery Report v2.1 · Execution time $($Report.ExecTime) · Stale threshold $($Report.StaleDays) days</p>
    <p>Read-only discovery. This script does not change AD. Validate privileged-group counts before you act.</p>
  </footer>
    </div>
  </div>
</div>
<aside class="drawer" id="drawer" aria-label="Drill-down">
  <div class="drawer-head">
    <div>
      <div class="drawer-crumb" id="drawerCrumb">Selection</div>
      <h3 id="drawerTitle">Details</h3>
    </div>
    <button class="drawer-close" id="drawerClose" type="button" aria-label="Close">&times;</button>
  </div>
  <div class="drawer-body" id="drawerBody"></div>
</aside>
<div class="scrim" id="scrim"></div>
<script type="application/json" id="chartData">$chartJson</script>
<script>
$js
</script>
</body>
</html>
"@

    return $html
}

#endregion

#region Demo

function New-OfflineDemoReport {
    $now = Get-Date
    $identity = [pscustomobject]@{
        ForestName           = 'northwind.lab'
        ForestMode           = 'Windows Server 2016 (7)'
        RootDomain           = 'northwind.lab'
        Domains              = @('northwind.lab')
        GlobalCatalogs       = @('NW-DC01.northwind.lab', 'NW-DC02.northwind.lab')
        UPNSuffixes          = @('northwind.com')
        Sites                = @('HQ-Chicago', 'Plant-Austin', 'Default-First-Site-Name')
        SchemaMaster         = 'NW-DC01.northwind.lab'
        DomainNamingMaster   = 'NW-DC01.northwind.lab'
        RecycleBinEnabled    = $false
        OptionalFeatures     = @(
            [pscustomobject]@{ Name = 'Recycle Bin Feature'; EnabledScopes = @() }
            [pscustomobject]@{ Name = 'Privileged Access Management Feature'; EnabledScopes = @() }
        )
        DomainName           = 'northwind.lab'
        DomainNetBIOS        = 'NORTHWIND'
        DomainDN             = 'DC=northwind,DC=lab'
        DomainSID            = 'S-1-5-21-1000000000-2000000000-3000000000'
        DomainMode           = 'Windows Server 2016 (7)'
        PDCEmulator          = 'NW-DC01.northwind.lab'
        RIDMaster            = 'NW-DC01.northwind.lab'
        InfrastructureMaster = 'NW-DC01.northwind.lab'
        DNSRoot              = 'northwind.lab'
        ChildDomains         = @()
        SchemaVersion        = 88
        SchemaVersionName    = 'Windows Server 2019 (objectVersion 88)'
        TombstoneLifetime    = 180
        RootDSEHost          = 'NW-DC01.northwind.lab'
    }

    $fsmo = Get-FSMORoleTable -ForestInfo $identity

    $dc1Roles = @(
        [pscustomobject]@{ Name = 'AD-Domain-Services'; DisplayName = 'Active Directory Domain Services'; Description = 'Store directory data and manage communication between users and domains.'; FeatureType = 'Role' }
        [pscustomobject]@{ Name = 'DNS'; DisplayName = 'DNS Server'; Description = 'Domain Name System server.'; FeatureType = 'Role' }
        [pscustomobject]@{ Name = 'DHCP'; DisplayName = 'DHCP Server'; Description = 'Dynamic Host Configuration Protocol server.'; FeatureType = 'Role' }
    )
    $dc1Feats = @(
        [pscustomobject]@{ Name = 'RSAT-AD-PowerShell'; DisplayName = 'Active Directory module for Windows PowerShell'; Description = 'AD PowerShell'; FeatureType = 'Feature' }
        [pscustomobject]@{ Name = 'GPMC'; DisplayName = 'Group Policy Management'; Description = 'GPO admin console'; FeatureType = 'Feature' }
    )
    $dc2Roles = @(
        [pscustomobject]@{ Name = 'AD-Domain-Services'; DisplayName = 'Active Directory Domain Services'; Description = 'Store directory data and manage communication between users and domains.'; FeatureType = 'Role' }
        [pscustomobject]@{ Name = 'DNS'; DisplayName = 'DNS Server'; Description = 'Domain Name System server.'; FeatureType = 'Role' }
        [pscustomobject]@{ Name = 'ADCS-Cert-Authority'; DisplayName = 'Active Directory Certificate Services'; Description = 'Enterprise CA.'; FeatureType = 'Role' }
    )

    $dcs = @(
        [pscustomobject]@{
            ComputerName = 'NW-DC01'; HostName = 'NW-DC01.northwind.lab'; IPv4Address = '10.10.10.11'; Site = 'HQ-Chicago'
            OperatingSystem = 'Windows Server 2022 Standard'; OperatingSystemVersion = '10.0 (20348)'
            IsGlobalCatalog = $true; IsReadOnly = $false; Status = 'Online'
            Roles = $dc1Roles; Features = $dc1Feats
            FSMORoles = @('Schema Master', 'Domain Naming Master', 'PDC Emulator', 'RID Master', 'Infrastructure Master')
            LastBootTime = $now.AddDays(-42); LastBootTimeFormatted = Format-When $now.AddDays(-42); Uptime = '42d 3h 12m'
            MemoryGB = 16
            Disks = @([pscustomobject]@{ DeviceID = 'C:'; SizeGB = 127; FreeGB = 14.2 }, [pscustomobject]@{ DeviceID = 'D:'; SizeGB = 80; FreeGB = 41 })
            TimeSource = 'time.windows.com'
            Services = @(
                [pscustomobject]@{ Name = 'NTDS'; Status = 'Running' }
                [pscustomobject]@{ Name = 'DNS'; Status = 'Running' }
                [pscustomobject]@{ Name = 'KDC'; Status = 'Running' }
                [pscustomobject]@{ Name = 'DFSR'; Status = 'Running' }
                [pscustomobject]@{ Name = 'W32Time'; Status = 'Running' }
                [pscustomobject]@{ Name = 'DHCPServer'; Status = 'Running' }
            )
            LastHotfix = 'KB5044281 (2026-09-10)'; PendingReboot = $true; Error = $null; ReplicationError = $null
            ReplicationPartners = @{
                Inbound = @(
                    [pscustomobject]@{ Partner = 'NW-DC02'; LastSuccess = $now.AddMinutes(-18); ConsecutiveFails = 0; LastResult = '0'; Partitions = @('northwind', 'Configuration', 'Schema') }
                    [pscustomobject]@{ Partner = 'NW-RODC01'; LastSuccess = $now.AddHours(-3); ConsecutiveFails = 4; LastResult = '1722'; Partitions = @('northwind') }
                )
                Connections = @()
            }
        }
        [pscustomobject]@{
            ComputerName = 'NW-DC02'; HostName = 'NW-DC02.northwind.lab'; IPv4Address = '10.20.20.11'; Site = 'Plant-Austin'
            OperatingSystem = 'Windows Server 2019 Standard'; OperatingSystemVersion = '10.0 (17763)'
            IsGlobalCatalog = $true; IsReadOnly = $false; Status = 'Online'
            Roles = $dc2Roles; Features = @()
            FSMORoles = @()
            LastBootTime = $now.AddDays(-120); LastBootTimeFormatted = Format-When $now.AddDays(-120); Uptime = '120d 6h 1m'
            MemoryGB = 12
            Disks = @([pscustomobject]@{ DeviceID = 'C:'; SizeGB = 100; FreeGB = 22 })
            TimeSource = 'NW-DC01.northwind.lab'
            Services = @(
                [pscustomobject]@{ Name = 'NTDS'; Status = 'Running' }
                [pscustomobject]@{ Name = 'DNS'; Status = 'Running' }
                [pscustomobject]@{ Name = 'KDC'; Status = 'Running' }
                [pscustomobject]@{ Name = 'DFSR'; Status = 'Running' }
                [pscustomobject]@{ Name = 'CertSvc'; Status = 'Running' }
            )
            LastHotfix = 'KB5035849 (2025-11-02)'; PendingReboot = $false; Error = $null; ReplicationError = $null
            ReplicationPartners = @{
                Inbound = @(
                    [pscustomobject]@{ Partner = 'NW-DC01'; LastSuccess = $now.AddMinutes(-16); ConsecutiveFails = 0; LastResult = '0'; Partitions = @('northwind', 'Configuration', 'Schema') }
                )
                Connections = @()
            }
        }
        [pscustomobject]@{
            ComputerName = 'NW-RODC01'; HostName = 'NW-RODC01.northwind.lab'; IPv4Address = '10.30.30.11'; Site = 'Plant-Austin'
            OperatingSystem = 'Windows Server 2019 Standard'; OperatingSystemVersion = '10.0 (17763)'
            IsGlobalCatalog = $true; IsReadOnly = $true; Status = 'Error'
            Roles = @(); Features = @(); FSMORoles = @()
            LastBootTime = $null; LastBootTimeFormatted = 'N/A'; Uptime = 'N/A'; MemoryGB = $null; Disks = @()
            TimeSource = 'N/A'; Services = @(); LastHotfix = 'N/A'; PendingReboot = $null
            Error = 'WinRM cannot complete the operation. Verify the computer is up and WinRM is configured.'
            ReplicationError = $null
            ReplicationPartners = @{
                Inbound = @()
                Connections = @()
            }
        }
    )

    $topology = [pscustomobject]@{
        Sites = @(
            [pscustomobject]@{ Name = 'HQ-Chicago'; Description = 'Headquarters'; Location = 'Chicago' }
            [pscustomobject]@{ Name = 'Plant-Austin'; Description = 'Manufacturing'; Location = 'Austin' }
            [pscustomobject]@{ Name = 'Default-First-Site-Name'; Description = 'Leftover default site'; Location = '' }
        )
        Subnets = @(
            [pscustomobject]@{ Name = '10.10.10.0/24'; Site = 'HQ-Chicago'; Description = 'DC + servers' }
            [pscustomobject]@{ Name = '10.10.20.0/24'; Site = 'HQ-Chicago'; Description = 'Workstations' }
            [pscustomobject]@{ Name = '10.20.20.0/24'; Site = 'Plant-Austin'; Description = 'Plant servers' }
        )
        Links = @(
            [pscustomobject]@{ Name = 'HQ-AUSTIN'; Cost = 100; ReplicationFrequencyInMinutes = 15; InterSiteTransportProtocol = 'IP'; Sites = @('HQ-Chicago', 'Plant-Austin') }
        )
    }

    $priv = @(
        [pscustomobject]@{
            Name = 'Domain Admins'; Recursive = $true; Count = 6
            Members = @(
                [pscustomobject]@{ SamAccountName = 'Administrator'; Name = 'Administrator'; objectClass = 'user' }
                [pscustomobject]@{ SamAccountName = 'j.blake'; Name = 'Jordan Blake'; objectClass = 'user' }
                [pscustomobject]@{ SamAccountName = 's.patel'; Name = 'Sam Patel'; objectClass = 'user' }
                [pscustomobject]@{ SamAccountName = 'helpdesk.admin'; Name = 'Helpdesk Admin'; objectClass = 'user' }
                [pscustomobject]@{ SamAccountName = 'vendor.temp'; Name = 'Vendor Temp'; objectClass = 'user' }
                [pscustomobject]@{ SamAccountName = 'backup.svc'; Name = 'Backup Service'; objectClass = 'user' }
            )
        }
        [pscustomobject]@{
            Name = 'Enterprise Admins'; Recursive = $true; Count = 2
            Members = @(
                [pscustomobject]@{ SamAccountName = 'Administrator'; Name = 'Administrator'; objectClass = 'user' }
                [pscustomobject]@{ SamAccountName = 'j.blake'; Name = 'Jordan Blake'; objectClass = 'user' }
            )
        }
        [pscustomobject]@{
            Name = 'Schema Admins'; Recursive = $true; Count = 1
            Members = @([pscustomobject]@{ SamAccountName = 'Administrator'; Name = 'Administrator'; objectClass = 'user' })
        }
        [pscustomobject]@{
            Name = 'DnsAdmins'; Recursive = $true; Count = 2
            Members = @(
                [pscustomobject]@{ SamAccountName = 'netops'; Name = 'Network Ops'; objectClass = 'user' }
                [pscustomobject]@{ SamAccountName = 'dhcp.svc'; Name = 'DHCP Service'; objectClass = 'user' }
            )
        }
        [pscustomobject]@{
            Name = 'Protected Users'; Recursive = $true; Count = 0; Members = @()
        }
    )

    $report = [pscustomobject]@{
        GeneratedAt          = $now
        ExecTime             = '00:00.000'
        Mode                 = 'OfflineDemo'
        StaleDays            = 90
        MaxInventoryObjects  = 8000
        Identity             = $identity
        FSMO                 = $fsmo
        Topology             = $topology
        Trusts               = @(
            [pscustomobject]@{
                Name = 'fabrikam.lab'; TrustType = 'Forest'; Direction = 'Bidirectional'
                ForestTransitive = $true; SIDFilteringQuarantined = $true; SelectiveAuth = $false
            }
        )
        DomainControllers    = $dcs
        ReplicationFailures  = @(
            [pscustomobject]@{
                Server = 'NW-DC01'; Partner = 'NW-RODC01'; FailureType = 'Connection'; FirstFailureTime = $now.AddHours(-3)
                FailureCount = 4; LastErrorDesc = 'RPC server unavailable (1722)'
            }
        )
        PasswordPolicy       = [pscustomobject]@{
            Default = [pscustomobject]@{
                ComplexityEnabled = $true; MinPasswordLength = 8; MinPasswordAgeDays = 1; MaxPasswordAgeDays = 90
                PasswordHistoryCount = 12; LockoutThreshold = 0; LockoutDurationMinutes = 30
                LockoutObservationMinutes = 30; ReversibleEncryptionEnabled = $false
            }
            FineGrained = @(
                [pscustomobject]@{ Name = 'Admins-FGPP'; Precedence = 10; MinPasswordLength = 14; MaxPasswordAgeDays = 60; LockoutThreshold = 5 }
            )
        }
        Krbtgt               = [pscustomobject]@{
            Name = 'krbtgt'; Enabled = $false; PasswordLastSet = $now.AddDays(-640); PasswordAgeDays = 640; Created = $now.AddYears(-8)
        }
        PrivilegedGroups     = $priv
        Inventory            = [pscustomobject]@{
            UserEnabled = 412; UserDisabled = 88; UserStale = 37; UserNeverLogon = 14; UserNeverExpire = 11; UserAdminCount = 9
            ComputerEnabled = 260; ComputerDisabled = 41; ComputerStale = 22
            GroupsSecurity = 148; GroupsDistribution = 33; Contacts = 6
            Truncated = $false; Skipped = $false
            ComputersByOS = @(
                [pscustomobject]@{ OperatingSystem = 'Windows 11 Pro'; Count = 140 }
                [pscustomobject]@{ OperatingSystem = 'Windows 10 Pro'; Count = 70 }
                [pscustomobject]@{ OperatingSystem = 'Windows Server 2022 Standard'; Count = 18 }
                [pscustomobject]@{ OperatingSystem = 'Windows Server 2016 Standard'; Count = 12 }
                [pscustomobject]@{ OperatingSystem = '(none)'; Count = 20 }
            )
            StaleUsers = @(
                [pscustomobject]@{ Name = 'temp.contractor'; LastLogonDate = $now.AddDays(-210) }
                [pscustomobject]@{ Name = 'old.finance'; LastLogonDate = $now.AddDays(-400) }
            )
            StaleComputers = @(
                [pscustomobject]@{ Name = 'AUS-WKS-014'; OS = 'Windows 10 Pro'; LastLogonDate = $now.AddDays(-180) }
            )
            NeverExpireUsers = @([pscustomobject]@{ Name = 'backup.svc'; PasswordLastSet = $now.AddDays(-800) })
            UnconstrainedComputers = @([pscustomobject]@{ Name = 'NW-APP01'; OS = 'Windows Server 2016 Standard' })
            UnconstrainedUsers = @()
        }
        GpoOu                = [pscustomobject]@{
            GPOs = @(
                [pscustomobject]@{ DisplayName = 'Default Domain Policy'; GpoStatus = 'AllSettingsEnabled'; CreationTime = $now.AddYears(-8); ModificationTime = $now.AddDays(-12) }
                [pscustomobject]@{ DisplayName = 'Default Domain Controllers Policy'; GpoStatus = 'AllSettingsEnabled'; CreationTime = $now.AddYears(-8); ModificationTime = $now.AddDays(-40) }
                [pscustomobject]@{ DisplayName = 'Workstation-Baseline'; GpoStatus = 'AllSettingsEnabled'; CreationTime = $now.AddYears(-3); ModificationTime = $now.AddDays(-5) }
                [pscustomobject]@{ DisplayName = 'Map-Drives-Legacy'; GpoStatus = 'UserSettingsDisabled'; CreationTime = $now.AddYears(-6); ModificationTime = $now.AddYears(-2) }
            )
            OUs = @(
                [pscustomobject]@{ Name = 'HQ'; Canonical = 'northwind.lab/HQ'; Description = 'Chicago HQ'; Protected = $true; GpoCount = 1 }
                [pscustomobject]@{ Name = 'Workstations'; Canonical = 'northwind.lab/HQ/Workstations'; Description = 'End-user PCs'; Protected = $true; GpoCount = 1 }
                [pscustomobject]@{ Name = 'Servers'; Canonical = 'northwind.lab/HQ/Servers'; Description = 'Member servers'; Protected = $true; GpoCount = 0 }
                [pscustomobject]@{ Name = 'Austin'; Canonical = 'northwind.lab/Austin'; Description = 'Plant'; Protected = $false; GpoCount = 0 }
                [pscustomobject]@{ Name = 'Service Accounts'; Canonical = 'northwind.lab/Service Accounts'; Description = 'gMSA + legacy SVC'; Protected = $true; GpoCount = 1 }
            )
        }
        Services             = [pscustomobject]@{
            CertificateAuthorities = @([pscustomobject]@{ Name = 'NORTHWIND-CA'; HostName = 'NW-DC02.northwind.lab' })
            DhcpServers            = @([pscustomobject]@{ Name = 'nw-dc01.northwind.lab' })
            Exchange               = $null
            EntraConnect           = @([pscustomobject]@{ Name = 'MSOL_a1b2c3d4e5f6'; Description = 'Account created by Azure AD Connect'; PasswordLastSet = $now.AddDays(-90); Created = $now.AddYears(-2) })
            LegacyLaps             = $false
            WindowsLaps            = $false
            Adfs                   = @()
        }
        Findings             = @()
        Warnings             = @(
            [pscustomobject]@{ Area = 'Demo'; Message = 'This report is generated from built-in sample data. No directory was queried.' }
        )
    }

    $report.Findings = Get-DiscoveryFindings -Report $report
    return $report
}

#endregion

#region Main

function Get-DefaultOutputPath {
    param([string]$DomainLabel)
    $safe = if ($DomainLabel) { ($DomainLabel -replace '[^\w\.-]', '_') } else { 'AD' }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $name = 'AD_DomainDiscovery_{0}_{1}.html' -f $safe, $stamp
    $desktop = $null
    try { $desktop = [Environment]::GetFolderPath('Desktop') } catch { }
    if ([string]::IsNullOrWhiteSpace($desktop)) {
        if ($env:USERPROFILE) { $desktop = Join-Path $env:USERPROFILE 'Desktop' }
    }
    if ([string]::IsNullOrWhiteSpace($desktop) -or -not (Test-Path -LiteralPath $desktop)) {
        $desktop = [System.IO.Path]::GetTempPath()
    }
    return Join-Path $desktop $name
}

function Save-DiscoveryReport {
    param($Html, [string]$Path, $Report)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $Html, $utf8)
    Write-ReportLog "Report saved to $Path" 'SUCCESS'

    if ($ExportJson) {
        $jsonPath = [System.IO.Path]::ChangeExtension($Path, '.json')
        try {
            $Report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
            Write-ReportLog "JSON sidecar saved to $jsonPath" 'SUCCESS'
        } catch {
            Write-ReportLog "JSON export failed: $($_.Exception.Message)" 'WARN'
        }
    }

    if (-not $NoBrowser) {
        try {
            Start-Process $Path
        } catch {
            Write-ReportLog "Could not open the report in a browser: $($_.Exception.Message)" 'WARN'
        }
    }
}

function Invoke-LiveDiscovery {
    $warnings = [System.Collections.Generic.List[object]]::new()
    $Ad = Get-AdSplat

    Write-ReportLog 'Retrieving forest and domain identity...' 'STEP'
    $identity = Get-ForestAndDomainInfo -Ad $Ad
    $script:TargetServer = if ($Server) { $Server } elseif ($identity.PDCEmulator) { $identity.PDCEmulator } else { $identity.RootDSEHost }
    $Ad = Get-AdSplat
    Write-ReportLog ("Forest {0} / domain {1}" -f $identity.ForestName, $identity.DomainName) 'SUCCESS'

    $fsmo = Get-FSMORoleTable -ForestInfo $identity
    Write-ReportLog 'Retrieving domain controllers...' 'STEP'
    $dcList = Get-AllDomainControllers -Ad $Ad
    if ((Get-SafeCount $dcList) -eq 0) {
        throw 'No domain controllers were returned. Check domain name, credentials, and that the ActiveDirectory module can reach a DC.'
    }
    Write-ReportLog ("Found {0} domain controller(s)" -f $dcList.Count) 'SUCCESS'

    Write-ReportLog 'Querying each DC (replication, roles, health)...' 'STEP'
    $dcRecords = @()
    foreach ($dc in $dcList) {
        try {
            $dcRecords += Get-DcRecord -Dc $dc -FsmoRoles $fsmo -Ad $Ad -SubFeatures:$IncludeSubFeatures
        } catch {
            Write-ReportLog ("Unexpected failure on {0}: {1}" -f $dc.Name, $_.Exception.Message) 'ERROR'
            $warnings.Add((New-ReportWarning 'DC' ("{0}: {1}" -f $dc.Name, $_.Exception.Message))) | Out-Null
        }
    }

    Write-ReportLog 'Collecting sites, trusts, and replication failures...' 'STEP'
    $topology = Get-SiteTopology -Ad $Ad
    $trusts = Get-TrustInfo -Ad $Ad
    $replFails = Get-ReplicationFailures -Ad $Ad -DomainName $identity.DomainName

    Write-ReportLog 'Collecting identity hygiene...' 'STEP'
    $policy = Get-PasswordPolicyInfo -Ad $Ad
    $krbtgt = Get-KrbtgtInfo -Ad $Ad
    $priv = Get-PrivilegedGroupInfo -Ad $Ad -DomainDN $identity.DomainDN
    $cutoff = (Get-Date).AddDays(-1 * [math]::Abs($StaleDays))
    $inventory = Get-DirectoryInventory -Ad $Ad -Cutoff $cutoff -Max $MaxInventoryObjects

    Write-ReportLog 'Collecting GPOs, OUs, and directory services...' 'STEP'
    $gpoOu = Get-GpoAndOuInfo -Ad $Ad -DomainDN $identity.DomainDN -DomainName $identity.DomainName
    $services = Get-DirectoryServicesInfo -Ad $Ad -ConfigNC $identity.ConfigurationNC -SchemaNC $identity.SchemaNC -DomainDN $identity.DomainDN

    $report = [pscustomobject]@{
        GeneratedAt         = Get-Date
        ExecTime            = ''
        Mode                = 'Live'
        StaleDays           = $StaleDays
        MaxInventoryObjects = $MaxInventoryObjects
        Identity            = $identity
        FSMO                = $fsmo
        Topology            = $topology
        Trusts              = $trusts
        DomainControllers   = $dcRecords
        ReplicationFailures = $replFails
        PasswordPolicy      = $policy
        Krbtgt              = $krbtgt
        PrivilegedGroups    = $priv
        Inventory           = $inventory
        GpoOu               = $gpoOu
        Services            = $services
        Findings            = @()
        Warnings            = @($warnings)
    }
    $report.Findings = Get-DiscoveryFindings -Report $report
    return $report
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host ''
Write-Host '==============================================' -ForegroundColor Green
Write-Host '  AD Domain Discovery Report v2.1' -ForegroundColor Green
Write-Host '==============================================' -ForegroundColor Green
Write-Host ''

$script:Credential = $Credential
$script:TargetServer = $Server

try {
    if ($OfflineDemo) {
        Write-ReportLog 'Building offline demo report (no directory queries)...' 'STEP'
        $report = New-OfflineDemoReport
    } else {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw 'The ActiveDirectory module is not available. Install RSAT or run this on a domain controller.'
        }
        Import-Module ActiveDirectory -ErrorAction Stop
        if (-not $script:TargetServer -and $Domain) { $script:TargetServer = $Domain }
        $report = Invoke-LiveDiscovery
    }
} catch {
    Write-ReportLog $_.Exception.Message 'ERROR'
    if ($_.InvocationInfo.PositionMessage) {
        Write-ReportLog ($_.InvocationInfo.PositionMessage.Trim()) 'ERROR'
    }
    if ($_.ScriptStackTrace) {
        Write-ReportLog $_.ScriptStackTrace 'ERROR'
    }
    exit 1
}

$stopwatch.Stop()
$report.ExecTime = '{0:mm\:ss\.fff}' -f $stopwatch.Elapsed

if (-not $OutputPath) {
    $label = if ($report.Identity.DomainNetBIOS) { $report.Identity.DomainNetBIOS } else { $report.Identity.DomainName }
    $OutputPath = Get-DefaultOutputPath -DomainLabel $label
}

Write-ReportLog 'Generating interactive HTML report...' 'STEP'
$html = New-DiscoveryReportHtml -Report $report
Save-DiscoveryReport -Html $html -Path $OutputPath -Report $report

Write-Host ''
Write-Host '==============================================' -ForegroundColor Green
Write-Host "  Done in $($report.ExecTime)" -ForegroundColor Green
Write-Host "  Findings: $((@($report.Findings) | Where-Object { $_.Severity -eq 'Critical' }).Count) critical, $((@($report.Findings) | Where-Object { $_.Severity -eq 'Warning' }).Count) warning" -ForegroundColor Green
Write-Host '==============================================' -ForegroundColor Green
Write-Host ''

#endregion

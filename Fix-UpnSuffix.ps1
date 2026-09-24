#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive tool to correct wrong UPN (UserPrincipalName) suffixes on
    Active Directory accounts listed in a CSV file.

.DESCRIPTION
    - Fully interactive (menus / prompts). Optional -CsvPath skips the file picker.
    - GUI file picker to choose the CSV, with a path-prompt fallback (Server Core,
      remoting, or MTA sessions where WinForms dialogs fail).
    - Lets you map which CSV column identifies the user.
    - Auto-detects every UPN suffix AD will accept in this forest
      (current domain, every forest domain, and suffixes registered under
      AD Domains and Trusts / CN=Partitions) and lets you pick ONE to apply
      to every account in the CSV.
    - Alternate path: a CSV column with the per-row suffix or full UPN.
    - Dry-run preview first. Nothing is written until you confirm.
    - Writes a grouped HTML + CSV preview report (ready / warnings /
      collisions / cannot change) next to the source file before you apply.
      The report includes each object's primary SMTP and proxyAddresses
      when those attributes exist.
    - Optional rewrite of the Primary SMTP suffix (SMTP: proxy + mail)
      to the same new suffix. The old primary is kept as a smtp: alias
      unless -DiscardOldPrimarySmtp is used. Collisions are reported
      (SmtpInUseBySam) and that proxy is not written.
    - Optional per-account confirmation.
    - Writes a text log and a results CSV next to the source file.

    Performance and correctness (vs. the original per-row Get-ADUser loop):
    - Resolves users in LDAP batches (default 50) instead of 1-3 queries per row.
    - Pins reads and writes to a reachable DC over ADWS (not LDAP port 3268,
      which Get-ADUser cannot use). Writes still go to a writable DC for the
      user's domain so changes are not lost to replication lag.
    - Escapes LDAP filter metacharacters so identities with * ( ) \ or quotes
      cannot break or broaden the search.
    - Detects in-CSV and in-AD UPN collisions before applying anything.
    - Reuses the resolved DistinguishedName on Set-ADUser (no second lookup).

    Windows PowerShell 5.1 compatible. Requires the ActiveDirectory (RSAT) module
    and permissions to modify the target user accounts.

.PARAMETER CsvPath
    Optional path to the input CSV. When omitted, a file picker (or path prompt)
    is used.

.PARAMETER Server
    Optional domain controller FQDN. Used as the writable DC. Global Catalog
    discovery still runs unless it fails, in which case this server is used
    for reads as well.

.PARAMETER Suffix
    Apply this suffix to every account and skip the suffix picker.
    Example: omi.com

.PARAMETER AlsoChangePrimarySmtp
    Also switch each account's Primary SMTP suffix to the same target
    suffix. In non-interactive runs this is the only way to enable the
    SMTP rewrite (the interactive prompt is skipped).

.PARAMETER SkipPrimarySmtp
    Do not change Primary SMTP addresses, and do not ask.

.PARAMETER DiscardOldPrimarySmtp
    When rewriting Primary SMTP, do not keep the old address as a
    secondary smtp: alias. Default is to keep it so existing mail still
    delivers.

.PARAMETER SkipPause
    Skip the "Press ENTER to close" prompt (useful for automation).

.EXAMPLE
    powershell -STA -ExecutionPolicy Bypass -File .\Fix-UpnSuffix.ps1

.EXAMPLE
    powershell -STA -ExecutionPolicy Bypass -File .\Fix-UpnSuffix.ps1 -CsvPath C:\Temp\users.csv

.EXAMPLE
    powershell -STA -ExecutionPolicy Bypass -File .\Fix-UpnSuffix.ps1 -CsvPath C:\Temp\users.csv -Suffix omi.com

.EXAMPLE
    powershell -STA -ExecutionPolicy Bypass -File .\Fix-UpnSuffix.ps1 -CsvPath C:\Temp\users.csv -Suffix omi.com -AlsoChangePrimarySmtp

.NOTES
    Run from an elevated PowerShell session as an account with rights to modify users.
    Use -STA so the Windows file picker can open reliably (powershell.exe defaults to MTA).
#>

[CmdletBinding()]
param(
    [string]$CsvPath,
    [string]$Server,
    [string]$Suffix,
    [switch]$AlsoChangePrimarySmtp,
    [switch]$SkipPrimarySmtp,
    [switch]$DiscardOldPrimarySmtp,
    [switch]$SkipPause
)

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------ helpers ---

function Write-Info    { param([string]$Message) Write-Host $Message -ForegroundColor Cyan }
function Write-Ok      { param([string]$Message) Write-Host $Message -ForegroundColor Green }
function Write-Warn    { param([string]$Message) Write-Host $Message -ForegroundColor Yellow }
function Write-Err     { param([string]$Message) Write-Host $Message -ForegroundColor Red }
function Write-Section { param([string]$Message)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkGray
    Write-Host $Message -ForegroundColor White
    Write-Host ("=" * 70) -ForegroundColor DarkGray
}

$script:LogLines     = New-Object System.Collections.Generic.List[string]
$script:LastResults  = $null
$script:QueryServer  = $null   # DC hostname for Get-AD* reads (ADWS, no :3268)
$script:WriteServer  = $null   # Writable DC for the connected domain
$script:DomainDcCache = @{}    # domain DNS -> writable DC hostname
$script:WinFormsAvailable = $false
$script:BatchSize    = 50
$script:UserProperties = @("UserPrincipalName", "SamAccountName", "DistinguishedName", "Name", "Enabled", "proxyAddresses", "mail")
$script:OutputStamp    = $null
$script:CurrentDomainDns = $null
$script:AvailableSuffixInfo = @()
$script:ResultExportProperties = @(
    "Row", "Identity", "SamAccount", "DistinguishedName",
    "CurrentUPN", "NewUPN", "PrimarySmtp", "NewPrimarySmtp",
    "ProxyAddresses", "NewProxyAddresses", "SmtpStatus",
    "InUseBySam", "SmtpInUseBySam", "Status", "Recommendation", "Detail"
)
$script:ReportTableColumns = @(
    "Row", "Identity", "SamAccount", "CurrentUPN", "NewUPN",
    "PrimarySmtp", "NewPrimarySmtp", "ProxyAddresses", "NewProxyAddresses",
    "SmtpStatus", "InUseBySam", "SmtpInUseBySam", "Status", "Recommendation", "Detail"
)

function Log {
    param([string]$Message, [string]$Level = "INFO")
    $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line  = "[{0}] [{1}] {2}" -f $stamp, $Level, $Message
    [void]$script:LogLines.Add($line)
}

function Test-IsInteractive {
    try {
        return [Environment]::UserInteractive
    } catch {
        return $true
    }
}

function Read-Choice {
    <# Prompt until the user types one of the allowed values (case-insensitive). #>
    param(
        [Parameter(Mandatory)] [string]   $Prompt,
        [Parameter(Mandatory)] [string[]] $Valid,
        [string] $Default
    )
    while ($true) {
        $suffix = if ($Default) { " [$Default]" } else { "" }
        $answer = Read-Host ("{0}{1}" -f $Prompt, $suffix)
        if ([string]::IsNullOrWhiteSpace($answer) -and $Default) { return $Default }
        foreach ($v in $Valid) {
            if ($answer.Trim().Equals($v, [StringComparison]::OrdinalIgnoreCase)) { return $v }
        }
        Write-Warn ("Please enter one of: {0}" -f ($Valid -join ", "))
    }
}

function Confirm-YesNo {
    param([string]$Prompt, [switch]$DefaultYes)
    $def = if ($DefaultYes) { "Y" } else { "N" }
    $ans = Read-Choice -Prompt ("{0} (Y/N)" -f $Prompt) -Valid @("Y", "N") -Default $def
    return ($ans -eq "Y")
}

function ConvertTo-CaseInsensitiveSet {
    param([string[]]$Values)
    $set = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList @([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($v in @($Values)) {
        if (-not [string]::IsNullOrWhiteSpace($v)) { [void]$set.Add($v) }
    }
    return $set
}

function Test-SetContains {
    param($Set, [string]$Value)
    if (-not $Set -or [string]::IsNullOrWhiteSpace($Value)) { return $false }
    return $Set.Contains($Value)
}

# ---------------------------------------------------------- string helpers ---

function ConvertTo-LdapFilterValue {
    <#
        RFC 4515 / MS-ADTS LDAP filter escaping.
        Escapes \, *, (, ), NUL, and other ASCII control characters.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int][char]$ch
        switch ($code) {
            92  { [void]$sb.Append('\5c') }  # \
            42  { [void]$sb.Append('\2a') }  # *
            40  { [void]$sb.Append('\28') }  # (
            41  { [void]$sb.Append('\29') }  # )
            0   { [void]$sb.Append('\00') }
            default {
                if ($code -lt 32) {
                    [void]$sb.Append(('\{0:x2}' -f $code))
                }
                else {
                    [void]$sb.Append($ch)
                }
            }
        }
    }
    return $sb.ToString()
}

function Test-LooksLikeDn {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return $Value -match '^(CN|OU|DC)=' -and $Value -match ',DC='
}

function Get-SamFromIdentity {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    if ($Value -like '*\*') { return $Value.Split('\')[-1] }
    return $Value
}

function Test-UpnFormat {
    param([string]$Upn)
    if ([string]::IsNullOrWhiteSpace($Upn)) { return $false }
    # Exactly one @, no whitespace, both sides non-empty.
    return $Upn -match '^[^@\s]+@[^@\s]+$'
}

function Get-UpnSuffix {
    param([string]$Upn)
    if ([string]::IsNullOrWhiteSpace($Upn) -or $Upn -notlike '*@*') { return $null }
    return $Upn.Split('@')[-1]
}

function Get-DomainDnsFromDn {
    <# Extract DNS domain from a distinguished name: DC=child,DC=contoso,DC=com -> child.contoso.com #>
    param([string]$Dn)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return $null }
    $dcs = $Dn -split '(?<!\\),' | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_ -replace '^DC=', '' }
    if (-not $dcs) { return $null }
    return ($dcs -join '.')
}

function Get-CsvDelimiter {
    param([Parameter(Mandatory)][string]$Path)
    $first = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($first)) { return ',' }
    $comma = ([regex]::Matches($first, ',')).Count
    $semi  = ([regex]::Matches($first, ';')).Count
    $tab   = ([regex]::Matches($first, "`t")).Count
    if ($semi -gt $comma -and $semi -gt $tab) { return ';' }
    if ($tab -gt $comma -and $tab -gt $semi) { return "`t" }
    return ','
}

function Get-PrimarySmtpAddress {
    <# Primary SMTP from proxyAddresses (SMTP: first, then smtp:), else mail. #>
    param($User)
    if (-not $User) { return "" }

    $proxies = @()
    if ($User.proxyAddresses) { $proxies = @($User.proxyAddresses | Where-Object { $_ }) }
    foreach ($p in $proxies) {
        if ([string]$p -clike 'SMTP:*') { return ([string]$p).Substring(5) }
    }
    foreach ($p in $proxies) {
        if ([string]$p -like 'smtp:*') { return ([string]$p).Substring(5) }
    }
    if ($User.mail) { return [string]$User.mail }
    return ""
}

function Get-UserProxyValues {
    param($User)
    if (-not $User -or -not $User.proxyAddresses) { return @() }
    return @($User.proxyAddresses | Where-Object { $_ } | ForEach-Object { [string]$_ })
}

function Format-ProxyAddressValues {
    <# All proxy values, primary SMTP first, then aliases, then other types. #>
    param($Values)
    $proxies = @($Values | Where-Object { $_ } | ForEach-Object { [string]$_ })
    if ($proxies.Count -eq 0) { return "" }

    $primary = @($proxies | Where-Object { $_ -clike 'SMTP:*' } | Sort-Object)
    $aliases = @($proxies | Where-Object { $_ -clike 'smtp:*' } | Sort-Object)
    $other   = @($proxies | Where-Object { $_ -notlike 'smtp:*' } | Sort-Object)
    return ((@($primary) + @($aliases) + @($other)) -join '; ')
}

function Format-ProxyAddressList {
    <# All proxyAddresses on an AD user, primary SMTP first, then aliases, then other types. #>
    param($User)
    return (Format-ProxyAddressValues -Values (Get-UserProxyValues -User $User))
}

function Get-NewSmtpAddress {
    <# Keep the current Primary SMTP local-part and apply the target suffix. #>
    param(
        [string]$CurrentPrimary,
        [string]$TargetSuffix
    )
    $suffix = Get-NormalizedSuffix -Value $TargetSuffix
    if ([string]::IsNullOrWhiteSpace($CurrentPrimary) -or [string]::IsNullOrWhiteSpace($suffix)) { return "" }
    if ($CurrentPrimary -notlike '*@*') { return "" }
    $prefix = $CurrentPrimary.Split('@')[0]
    if ([string]::IsNullOrWhiteSpace($prefix)) { return "" }
    return ("{0}@{1}" -f $prefix, $suffix)
}

function Get-UpdatedProxyAddressList {
    <#
        Build a replacement proxyAddresses list: new address is SMTP: (primary),
        old primary becomes smtp: when KeepOldAsAlias is set, other values kept.
        A second SMTP: value is demoted so the object has only one primary.
    #>
    param(
        [string[]]$CurrentProxies,
        [string]$CurrentPrimary,
        [string]$NewPrimary,
        [bool]$KeepOldAsAlias = $true
    )
    if ([string]::IsNullOrWhiteSpace($NewPrimary)) { return @() }

    $result = New-Object System.Collections.ArrayList
    [void]$result.Add(("SMTP:{0}" -f $NewPrimary))

    foreach ($raw in @($CurrentProxies)) {
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $p = [string]$raw
        if ($p -like 'smtp:*') {
            $addr = $p.Substring(5)
            if ($addr.Equals($NewPrimary, [StringComparison]::OrdinalIgnoreCase)) { continue }
            if ($CurrentPrimary -and $p -clike 'SMTP:*' -and $addr.Equals($CurrentPrimary, [StringComparison]::OrdinalIgnoreCase)) { continue }
            if ($p -clike 'SMTP:*') {
                [void]$result.Add(("smtp:{0}" -f $addr))
            }
            else {
                [void]$result.Add($p)
            }
            continue
        }
        [void]$result.Add($p)
    }

    if ($KeepOldAsAlias -and $CurrentPrimary -and -not $CurrentPrimary.Equals($NewPrimary, [StringComparison]::OrdinalIgnoreCase)) {
        $already = $false
        foreach ($existing in $result) {
            if ($existing -like 'smtp:*' -and $existing.Substring(5).Equals($CurrentPrimary, [StringComparison]::OrdinalIgnoreCase)) {
                $already = $true
                break
            }
        }
        if (-not $already) {
            [void]$result.Add(("smtp:{0}" -f $CurrentPrimary))
        }
    }

    return @($result)
}

function Select-PrimarySmtpChange {
    <# Interactive opt-in. -AlsoChangePrimarySmtp forces on; -SkipPrimarySmtp forces off. #>
    param(
        [switch]$AlsoChange,
        [switch]$Skip
    )
    if ($Skip) { return $false }
    if ($AlsoChange) { return $true }
    if (-not (Test-IsInteractive)) { return $false }

    Write-Section "Primary SMTP suffix"
    Write-Host "Optionally switch the Primary SMTP (the SMTP: proxy, and mail) to the same new suffix on every account."
    Write-Host "The current primary is kept as a secondary smtp: alias so existing mail still delivers."
    Write-Host "Use -DiscardOldPrimarySmtp to drop the old primary instead of keeping it as an alias."
    return (Confirm-YesNo "Also change the Primary SMTP suffix on these accounts?" -DefaultYes)
}

function Get-NormalizedSuffix {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $raw = $Value.Trim().TrimStart('@')
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    if ($raw -like '*@*') { return $raw.Split('@')[-1] }
    return $raw
}

# ------------------------------------------------------- user resolution ------

function Get-NewUpn {
    <#
        Build the corrected UPN for a user based on the chosen mode.
        Returns the new UPN string, or $null if it cannot be built.
    #>
    param(
        [Parameter(Mandatory)] $User,
        [Parameter(Mandatory)] [string] $Mode,      # "SuffixColumn" | "FullUpnColumn" | "SingleSuffix"
        [string] $RowValue,
        [string] $SingleSuffix
    )

    $prefix = $null
    if ($User.UserPrincipalName -and $User.UserPrincipalName -like '*@*') {
        $prefix = $User.UserPrincipalName.Split('@')[0]
    }
    elseif ($User.SamAccountName) {
        $prefix = $User.SamAccountName
    }

    switch ($Mode) {
        "FullUpnColumn" {
            if ([string]::IsNullOrWhiteSpace($RowValue)) { return $null }
            return $RowValue.Trim()
        }
        "SuffixColumn" {
            $suffix = Get-NormalizedSuffix -Value $RowValue
            if (-not $suffix -or -not $prefix) { return $null }
            return ("{0}@{1}" -f $prefix, $suffix)
        }
        "SingleSuffix" {
            $suffix = Get-NormalizedSuffix -Value $SingleSuffix
            if (-not $suffix -or -not $prefix) { return $null }
            return ("{0}@{1}" -f $prefix, $suffix)
        }
    }
    return $null
}

function Get-AdwsServerName {
    <#
        Get-ADUser talks to Active Directory Web Services (TCP 9389), not LDAP.
        "host:3268" (the GC LDAP port) makes ADWS fail with "Unable to contact
        the server" / "does not have the Active Directory Web Services running".
    #>
    param([string]$Server)
    if ([string]::IsNullOrWhiteSpace($Server)) { return $null }
    $name = $Server.Trim()
    if ($name -match '^(.+):3268$') { return $Matches[1] }
    return $name
}

function Get-AdLookupServers {
    param([string]$Preferred)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($raw in @($Preferred, $script:QueryServer, $script:WriteServer)) {
        $name = Get-AdwsServerName -Server $raw
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $dup = $false
        foreach ($existing in $names) {
            if ($existing.Equals($name, [StringComparison]::OrdinalIgnoreCase)) { $dup = $true; break }
        }
        if (-not $dup) { [void]$names.Add($name) }
    }
    return @($names)
}

function Invoke-AdUserBatchLookup {
    <#
        Look up users in chunks with a single LDAP OR filter per chunk.
        Returns a case-insensitive hashtable keyed by the requested attribute value.
        If the preferred server is unreachable, retries the same batch on the
        writable DC before falling back to one-by-one.
    #>
    param(
        [Parameter(Mandatory)] [string]   $AttributeName,
        [Parameter(Mandatory)] [string[]] $Values,
        [string]   $Server,
        [string[]] $Properties
    )

    $map = @{}
    $unique = @(
        $Values |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim() } |
            Sort-Object { $_.ToLowerInvariant() } -Unique
    )
    if ($unique.Count -eq 0) { return $map }

    $props = if ($Properties) { $Properties } else { $script:UserProperties }
    $total = $unique.Count
    $servers = @(Get-AdLookupServers -Preferred $Server)
    if ($servers.Count -eq 0) { $servers = @($null) }

    for ($i = 0; $i -lt $unique.Count; $i += $script:BatchSize) {
        $end   = [Math]::Min($i + $script:BatchSize - 1, $unique.Count - 1)
        $batch = @($unique[$i..$end])

        $pct = if ($total -gt 0) { [int](($i / $total) * 100) } else { 0 }
        Write-Progress -Activity "Querying Active Directory" -Status ("{0}: {1}-{2} of {3}" -f $AttributeName, ($i + 1), ($end + 1), $total) -PercentComplete $pct

        $parts = foreach ($v in $batch) {
            "({0}={1})" -f $AttributeName, (ConvertTo-LdapFilterValue -Value $v)
        }
        $ldap = "(|{0})" -f ($parts -join "")

        $users = $null
        $lastError = $null
        foreach ($candidate in $servers) {
            $params = @{
                LDAPFilter     = $ldap
                Properties     = $props
                ResultPageSize = 200
                ErrorAction    = "Stop"
            }
            if ($candidate) { $params.Server = $candidate }
            try {
                $users = @(Get-ADUser @params)
                $lastError = $null
                if ($candidate) {
                    $script:QueryServer = $candidate
                    $servers = @($candidate) + @($servers | Where-Object { $_ -and -not $_.Equals($candidate, [StringComparison]::OrdinalIgnoreCase) })
                }
                break
            }
            catch {
                $lastError = $_
                Write-Warn ("Batch {0} lookup failed on {1}: {2}" -f $AttributeName, $candidate, $_.Exception.Message)
                Log ("Batch lookup failed for {0} on {1}: {2}" -f $AttributeName, $candidate, $_.Exception.Message) "WARN"
            }
        }

        if ($lastError -and $null -eq $users) {
            Write-Warn ("Falling back to one-by-one {0} lookup." -f $AttributeName)
            $fallbackServer = $null
            if ($servers.Count -gt 0) { $fallbackServer = $servers[-1] }
            $collected = New-Object System.Collections.ArrayList
            foreach ($v in $batch) {
                try {
                    $one = @{
                        LDAPFilter  = ("({0}={1})" -f $AttributeName, (ConvertTo-LdapFilterValue -Value $v))
                        Properties  = $props
                        ErrorAction = "Stop"
                    }
                    if ($fallbackServer) { $one.Server = $fallbackServer }
                    foreach ($u in @(Get-ADUser @one)) {
                        if ($u) { [void]$collected.Add($u) }
                    }
                }
                catch {
                    # Not found or inaccessible — leave it unresolved.
                }
            }
            $users = @($collected)
        }

        foreach ($u in @($users)) {
            if (-not $u) { continue }
            $key = $null
            switch ($AttributeName) {
                "userPrincipalName" { $key = $u.UserPrincipalName }
                "samAccountName"    { $key = $u.SamAccountName }
                "distinguishedName" { $key = $u.DistinguishedName }
                default             { $key = $u.SamAccountName }
            }
            if ($key) { $map[$key] = $u }
        }
    }

    Write-Progress -Activity "Querying Active Directory" -Completed
    return $map
}

function Resolve-AdUsersFromIdentities {
    <#
        Resolve many CSV identity values with as few AD round-trips as possible.
        Returns a hashtable: trimmed identity (case-insensitive key) -> AD user or $null.
    #>
    param([Parameter(Mandatory)] [string[]] $Identities)

    $resolved = @{}
    $upnIds   = New-Object System.Collections.Generic.List[string]
    $samIds   = New-Object System.Collections.Generic.List[string]
    $dnIds    = New-Object System.Collections.Generic.List[string]
    $seen     = @{}

    foreach ($raw in $Identities) {
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $id = $raw.Trim()
        if ($seen.ContainsKey($id)) { continue }
        $seen[$id] = $true

        if (Test-LooksLikeDn -Value $id) {
            [void]$dnIds.Add($id)
        }
        elseif ($id -like '*@*') {
            [void]$upnIds.Add($id)
        }
        else {
            [void]$samIds.Add((Get-SamFromIdentity -Value $id))
        }
    }

    $byUpn = @{}
    $bySam = @{}
    $byDn  = @{}

    if ($upnIds.Count -gt 0) {
        $byUpn = Invoke-AdUserBatchLookup -AttributeName "userPrincipalName" -Values $upnIds.ToArray() -Server $script:QueryServer -Properties $script:UserProperties
    }
    if ($samIds.Count -gt 0) {
        $bySam = Invoke-AdUserBatchLookup -AttributeName "samAccountName" -Values $samIds.ToArray() -Server $script:QueryServer -Properties $script:UserProperties
    }
    if ($dnIds.Count -gt 0) {
        $byDn = Invoke-AdUserBatchLookup -AttributeName "distinguishedName" -Values $dnIds.ToArray() -Server $script:QueryServer -Properties $script:UserProperties
    }

    # UPN identities that missed: try the local-part as sAMAccountName (original behaviour).
    $missedPrefixes = New-Object System.Collections.Generic.List[string]
    foreach ($upn in $upnIds) {
        if (-not $byUpn.ContainsKey($upn)) {
            $prefix = $upn.Split('@')[0]
            if (-not [string]::IsNullOrWhiteSpace($prefix) -and -not $bySam.ContainsKey($prefix)) {
                [void]$missedPrefixes.Add($prefix)
            }
        }
    }
    if ($missedPrefixes.Count -gt 0) {
        $extra = Invoke-AdUserBatchLookup -AttributeName "samAccountName" -Values $missedPrefixes.ToArray() -Server $script:QueryServer -Properties $script:UserProperties
        foreach ($k in @($extra.Keys)) {
            if (-not $bySam.ContainsKey($k)) { $bySam[$k] = $extra[$k] }
        }
    }

    foreach ($id in $seen.Keys) {
        $user = $null
        if (Test-LooksLikeDn -Value $id) {
            $user = $byDn[$id]
        }
        elseif ($id -like '*@*') {
            $user = $byUpn[$id]
            if (-not $user) {
                $user = $bySam[$id.Split('@')[0]]
            }
        }
        else {
            $user = $bySam[(Get-SamFromIdentity -Value $id)]
        }
        $resolved[$id] = $user
    }

    return $resolved
}

function Get-WritableServerForUser {
    param($User)
    $domainDns = Get-DomainDnsFromDn -Dn $User.DistinguishedName
    if ([string]::IsNullOrWhiteSpace($domainDns)) { return $script:WriteServer }
    if ($script:DomainDcCache.ContainsKey($domainDns)) { return $script:DomainDcCache[$domainDns] }

    try {
        $dc = Get-ADDomainController -DomainName $domainDns -Discover -Writable -ErrorAction Stop
        $script:DomainDcCache[$domainDns] = $dc.HostName
        return $dc.HostName
    }
    catch {
        Log ("Could not discover a writable DC for {0}: {1}. Using {2}." -f $domainDns, $_.Exception.Message, $script:WriteServer) "WARN"
        $script:DomainDcCache[$domainDns] = $script:WriteServer
        return $script:WriteServer
    }
}

# ---------------------------------------------------- suffix discovery --------

function Add-DiscoveredSuffix {
    <# Merge a suffix + source label into a case-insensitive map of lists. #>
    param(
        [Parameter(Mandatory)] $Map,
        [string] $Suffix,
        [string] $Source
    )
    $normalized = Get-NormalizedSuffix -Value $Suffix
    if ([string]::IsNullOrWhiteSpace($normalized) -or [string]::IsNullOrWhiteSpace($Source)) { return }

    if (-not $Map.ContainsKey($normalized)) {
        $Map[$normalized] = New-Object System.Collections.Generic.List[string]
    }
    foreach ($existing in $Map[$normalized]) {
        if ($existing.Equals($Source, [StringComparison]::OrdinalIgnoreCase)) { return }
    }
    [void]$Map[$normalized].Add($Source)
}

function ConvertTo-SuffixInfoObjects {
    <# Turn the discovery map into objects sorted with the current domain first. #>
    param(
        [Parameter(Mandatory)] $Map,
        [string] $CurrentDomain
    )
    $items = foreach ($key in $Map.Keys) {
        $sources = @($Map[$key])
        $isCurrent = -not [string]::IsNullOrWhiteSpace($CurrentDomain) -and $key.Equals($CurrentDomain, [StringComparison]::OrdinalIgnoreCase)
        [pscustomobject]@{
            Suffix          = $key
            Sources         = $sources
            SourceLabel     = ($sources -join "; ")
            IsCurrentDomain = [bool]$isCurrent
        }
    }
    return @(
        $items |
            Sort-Object @{ Expression = { -not $_.IsCurrentDomain } }, @{ Expression = { $_.Suffix.ToLowerInvariant() } }
    )
}

function Get-RegisteredPartitionUpnSuffixes {
    <# Extra suffixes live on CN=Partitions in the configuration naming context. #>
    param($Forest, [string] $Server)

    $dn = $null
    if ($Forest -and $Forest.PartitionsContainer) {
        $dn = $Forest.PartitionsContainer
    }
    else {
        try {
            $dseParams = @{ ErrorAction = "Stop" }
            if ($Server) { $dseParams.Server = $Server }
            $dse = Get-ADRootDSE @dseParams
            if ($dse.configurationNamingContext) {
                $dn = "CN=Partitions,$($dse.configurationNamingContext)"
            }
        }
        catch {
            Log ("Could not read RootDSE for Partitions DN: {0}" -f $_.Exception.Message) "WARN"
            return @()
        }
    }
    if ([string]::IsNullOrWhiteSpace($dn)) { return @() }

    try {
        $params = @{
            Identity   = $dn
            Properties = @("uPNSuffixes")
            ErrorAction = "Stop"
        }
        if ($Server) { $params.Server = $Server }
        $obj = Get-ADObject @params
        return @($obj.uPNSuffixes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    catch {
        Log ("Could not read Partitions uPNSuffixes: {0}" -f $_.Exception.Message) "WARN"
        return @()
    }
}

function Get-AvailableUpnSuffixes {
    <#
        Discover every UPN suffix Active Directory will accept:
          - current domain DNS name
          - every forest domain DNS name (implicit suffixes)
          - additional suffixes registered on the forest / Partitions container
        Returns Suffix / Sources / SourceLabel / IsCurrentDomain objects.
    #>
    param($Domain, $Forest)

    $map = @{}
    $current = $null
    if ($Domain -and $Domain.DNSRoot) { $current = $Domain.DNSRoot }

    if ($current) {
        Add-DiscoveredSuffix -Map $map -Suffix $current -Source "Current domain"
    }

    if ($Forest) {
        foreach ($d in @($Forest.Domains)) {
            if ($current -and $d -and $d.Equals($current, [StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
            Add-DiscoveredSuffix -Map $map -Suffix $d -Source "Forest domain"
        }
        foreach ($s in @($Forest.UPNSuffixes)) {
            Add-DiscoveredSuffix -Map $map -Suffix $s -Source "Forest UPN suffix"
        }
    }

    foreach ($s in @(Get-RegisteredPartitionUpnSuffixes -Forest $Forest -Server $script:WriteServer)) {
        Add-DiscoveredSuffix -Map $map -Suffix $s -Source "Registered on Partitions container"
    }

    return (ConvertTo-SuffixInfoObjects -Map $map -CurrentDomain $current)
}

# ---------------------------------------------------------------- prereqs -----

function Assert-Prerequisites {
    Write-Section "Checking prerequisites"

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Err "The ActiveDirectory PowerShell module was not found."
        Write-Err "Install RSAT: 'Active Directory Domain Services and Lightweight Directory Tools'."
        Log "ActiveDirectory module missing." "ERROR"
        throw "ActiveDirectory module not available."
    }

    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Ok "ActiveDirectory module loaded."
    Log "ActiveDirectory module loaded."

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $script:WriteServer = if ($Server) { $Server } else { $domain.PDCEmulator }
        $script:CurrentDomainDns = $domain.DNSRoot
        Write-Ok ("Connected to domain: {0} (NetBIOS: {1})" -f $domain.DNSRoot, $domain.NetBIOSName)
        Write-Ok ("Writable DC (this domain): {0}" -f $script:WriteServer)
        Log ("Connected to domain {0} / {1}; write DC {2}" -f $domain.DNSRoot, $domain.NetBIOSName, $script:WriteServer)
        $script:DomainDcCache[$domain.DNSRoot] = $script:WriteServer
    }
    catch {
        Write-Err "Could not reach a domain controller: $($_.Exception.Message)"
        Log "Domain controller unreachable: $($_.Exception.Message)" "ERROR"
        throw
    }

    $script:QueryServer = $script:WriteServer
    try {
        $gc = Get-ADDomainController -Discover -Service GlobalCatalog -ErrorAction Stop
        if ($gc -and $gc.HostName) {
            # Hostname only. Do not append :3268 — Get-ADUser uses ADWS (9389), not LDAP GC.
            $script:QueryServer = $gc.HostName
            Write-Ok ("Global Catalog host for reads (ADWS): {0}" -f $script:QueryServer)
            Log ("Using GC host {0} for reads via ADWS" -f $script:QueryServer)
        }
    }
    catch {
        Write-Warn "Could not discover a Global Catalog. Lookups use the writable DC."
        Log "GC discovery failed: $($_.Exception.Message)" "WARN"
    }

    $forest = $null
    try {
        $forest = Get-ADForest -ErrorAction Stop
    }
    catch {
        Write-Warn "Could not read forest metadata (continuing with the current domain only)."
        Log "Get-ADForest failed: $($_.Exception.Message)" "WARN"
    }

    $script:AvailableSuffixInfo = @(Get-AvailableUpnSuffixes -Domain $domain -Forest $forest)
    $validSuffixes = @($script:AvailableSuffixInfo | ForEach-Object { $_.Suffix })

    if ($validSuffixes.Count -gt 0) {
        Write-Info ("Auto-detected {0} available UPN suffix(es):" -f $validSuffixes.Count)
        foreach ($item in $script:AvailableSuffixInfo) {
            $marker = if ($item.IsCurrentDomain) { "  [current domain]" } else { "" }
            Write-Host ("  @{0,-32} {1}{2}" -f $item.Suffix, $item.SourceLabel, $marker)
        }
        Log ("Available UPN suffixes: {0}" -f (
            ($script:AvailableSuffixInfo | ForEach-Object { "{0} ({1})" -f $_.Suffix, $_.SourceLabel }) -join "; "
        ))
    }
    else {
        Write-Warn "No UPN suffixes could be auto-detected. You can type one later."
        Log "No UPN suffixes auto-detected." "WARN"
    }

    return $validSuffixes
}

function Initialize-WinForms {
    $script:WinFormsAvailable = $false
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop | Out-Null
        $script:WinFormsAvailable = $true
    }
    catch {
        Log "WinForms unavailable: $($_.Exception.Message)" "WARN"
    }
}

# ------------------------------------------------------------- file picker ----

function Select-CsvFile {
    Write-Section "Select the CSV file"

    if ($script:WinFormsAvailable) {
        try {
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.Title            = "Select the CSV file containing the accounts to fix"
            $dialog.Filter           = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
            $dialog.Multiselect      = $false
            $dialog.CheckFileExists  = $true
            $dialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")

            $topMost = New-Object System.Windows.Forms.Form -Property @{ TopMost = $true }
            $result  = $dialog.ShowDialog($topMost)
            $topMost.Dispose()

            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                Write-Ok ("Selected: {0}" -f $dialog.FileName)
                Log ("CSV selected: {0}" -f $dialog.FileName)
                return $dialog.FileName
            }
            Write-Warn "No file selected in the dialog. You can paste a path instead."
            Log "User cancelled file dialog." "WARN"
        }
        catch {
            Write-Warn ("File picker failed ({0}). Enter a path instead." -f $_.Exception.Message)
            Log "File picker failed: $($_.Exception.Message)" "WARN"
        }
    }
    else {
        Write-Info "GUI file picker is not available in this session (use powershell -STA for the dialog)."
    }

    while ($true) {
        $answer = Read-Host "Enter the full path to the CSV file (or C to cancel)"
        if ([string]::IsNullOrWhiteSpace($answer) -or $answer.Trim().Equals("C", [StringComparison]::OrdinalIgnoreCase)) {
            Write-Warn "No file selected. Exiting."
            Log "User cancelled file selection." "WARN"
            return $null
        }
        $path = $answer.Trim().Trim('"')
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Write-Ok ("Selected: {0}" -f $path)
            Log ("CSV selected: {0}" -f $path)
            return $path
        }
        Write-Warn "That path does not exist. Try again."
    }
}

# ------------------------------------------------------- column selection -----

function Select-Column {
    param(
        [Parameter(Mandatory)] [string[]] $Columns,
        [Parameter(Mandatory)] [string]   $Purpose,
        [string[]] $AutoDetect
    )

    $default = $null
    if ($AutoDetect) {
        foreach ($guess in $AutoDetect) {
            $match = $Columns | Where-Object { $_.Trim().Equals($guess, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
            if ($match) { $default = $match; break }
        }
    }

    Write-Host ""
    Write-Info ("Which column holds the {0}?" -f $Purpose)
    for ($i = 0; $i -lt $Columns.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $Columns[$i])
    }

    $defaultIndex = $null
    if ($default) {
        $defaultIndex = ([array]::IndexOf($Columns, $default)) + 1
        Write-Host ("  (auto-detected: {0})" -f $default) -ForegroundColor DarkGray
    }

    while ($true) {
        $prompt = if ($defaultIndex) { "Enter number [$defaultIndex]" } else { "Enter number" }
        $answer = Read-Host $prompt
        if ([string]::IsNullOrWhiteSpace($answer) -and $defaultIndex) { return $Columns[$defaultIndex - 1] }
        $n = 0
        if ([int]::TryParse($answer, [ref]$n) -and $n -ge 1 -and $n -le $Columns.Count) {
            return $Columns[$n - 1]
        }
        Write-Warn ("Enter a number between 1 and {0}." -f $Columns.Count)
    }
}

function New-TargetChoice {
    param(
        [Parameter(Mandatory)] [string] $Mode,
        [string] $Suffix,
        [string] $ValueCol
    )
    return [pscustomobject]@{
        Mode     = $Mode
        Suffix   = $Suffix
        ValueCol = $ValueCol
    }
}

function Select-CsvValueMode {
    param([Parameter(Mandatory)] [string[]] $Columns)

    Write-Section "Use a value from the CSV"
    Write-Host "  [1] A column contains just the suffix          (e.g. omi.com)"
    Write-Host "  [2] A column contains the full correct UPN     (e.g. user@omi.com)"
    Write-Host "  [C] Cancel"
    $sub = Read-Choice -Prompt "Choose 1 or 2" -Valid @("1", "2", "C")
    if ($sub -eq "C") { return $null }

    if ($sub -eq "1") {
        $col = Select-Column -Columns $Columns -Purpose "correct suffix" `
            -AutoDetect @("Suffix", "UPNSuffix", "NewSuffix", "CorrectSuffix", "Domain")
        return (New-TargetChoice -Mode "SuffixColumn" -ValueCol $col)
    }

    $col = Select-Column -Columns $Columns -Purpose "full correct UPN" `
        -AutoDetect @("NewUPN", "CorrectUPN", "NewUserPrincipalName", "TargetUPN")
    return (New-TargetChoice -Mode "FullUpnColumn" -ValueCol $col)
}

function Select-TargetSuffix {
    <#
        Primary path: pick one auto-detected suffix and apply it to every CSV row.
        Alternate path: type a custom suffix, or read the value from a CSV column.
    #>
    param(
        $SuffixInfo,
        [Parameter(Mandatory)] [string[]] $Columns
    )

    $list = @($SuffixInfo | Where-Object { $_ -and $_.Suffix })
    $validNames = @($list | ForEach-Object { $_.Suffix })

    Write-Section "Choose the UPN suffix to apply to ALL accounts"

    if ($list.Count -gt 0) {
        Write-Info ("Auto-detected {0} available suffix(es). Pick one to apply to every account." -f $list.Count)
        for ($i = 0; $i -lt $list.Count; $i++) {
            $item = $list[$i]
            $marker = if ($item.IsCurrentDomain) { " [current domain]" } else { "" }
            Write-Host ("  [{0}] @{1}" -f ($i + 1), $item.Suffix) -NoNewline
            Write-Host ("    {0}{1}" -f $item.SourceLabel, $marker) -ForegroundColor DarkGray
        }
        $customOption = $list.Count + 1
        $csvOption    = $list.Count + 2
        Write-Host ("  [{0}] Type a custom suffix" -f $customOption)
        Write-Host ("  [{0}] Use a CSV column instead (per-row suffix or full UPN)" -f $csvOption)
        Write-Host "  [C] Cancel"

        while ($true) {
            $answer = (Read-Host "Enter your choice").Trim()
            if ($answer.Equals("c", [StringComparison]::OrdinalIgnoreCase)) {
                Write-Warn "Cancelled."
                Log "User cancelled suffix selection." "WARN"
                return $null
            }
            $n = 0
            if ([int]::TryParse($answer, [ref]$n)) {
                if ($n -ge 1 -and $n -le $list.Count) {
                    $chosen = $list[$n - 1].Suffix
                    Write-Ok ("Selected suffix: @{0}  (applied to every account)" -f $chosen)
                    Log ("Selected auto-detected suffix: {0}" -f $chosen)
                    return (New-TargetChoice -Mode "SingleSuffix" -Suffix $chosen)
                }
                if ($n -eq $customOption) {
                    $typed = Read-CustomSuffix -ValidSuffixes $validNames
                    if (-not $typed) { return $null }
                    return (New-TargetChoice -Mode "SingleSuffix" -Suffix $typed)
                }
                if ($n -eq $csvOption) {
                    return (Select-CsvValueMode -Columns $Columns)
                }
            }
            Write-Warn ("Enter a number between 1 and {0}, or C to cancel." -f $csvOption)
        }
    }

    Write-Warn "No UPN suffixes could be auto-detected. You can type one or use a CSV column."
    Write-Host "  [1] Type a suffix to apply to every account"
    Write-Host "  [2] Use a CSV column instead (per-row suffix or full UPN)"
    Write-Host "  [C] Cancel"
    $fallback = Read-Choice -Prompt "Choose 1 or 2" -Valid @("1", "2", "C")
    if ($fallback -eq "C") { return $null }
    if ($fallback -eq "2") { return (Select-CsvValueMode -Columns $Columns) }
    $typed = Read-CustomSuffix -ValidSuffixes @()
    if (-not $typed) { return $null }
    return (New-TargetChoice -Mode "SingleSuffix" -Suffix $typed)
}

function Read-CustomSuffix {
    param([string[]] $ValidSuffixes)

    $suffixSet = ConvertTo-CaseInsensitiveSet -Values $ValidSuffixes

    while ($true) {
        $suffix = Get-NormalizedSuffix -Value (Read-Host "Enter the suffix to apply to ALL accounts (e.g. omi.com)")
        if ([string]::IsNullOrWhiteSpace($suffix)) {
            Write-Warn "Suffix cannot be empty."
            continue
        }
        if ($suffixSet.Count -gt 0 -and -not (Test-SetContains -Set $suffixSet -Value $suffix)) {
            Write-Warn ("'{0}' is not in the forest's UPN suffix list. It may be rejected by AD." -f $suffix)
            if (-not (Confirm-YesNo "Continue anyway?")) { continue }
        }
        Write-Ok ("Selected suffix: @{0}" -f $suffix)
        Log ("Selected custom suffix: {0}" -f $suffix)
        return $suffix
    }
}

function Import-UpnCsv {
    param([Parameter(Mandatory)][string]$Path)

    $delim = Get-CsvDelimiter -Path $Path
    Log ("Detected CSV delimiter: '{0}'" -f $(if ($delim -eq "`t") { '\t' } else { $delim }))

    $rows = $null
    try {
        $rows = @(Import-Csv -LiteralPath $Path -Delimiter $delim -Encoding UTF8 -ErrorAction Stop)
    }
    catch {
        Write-Warn ("UTF-8 import failed ({0}). Retrying with the system default encoding." -f $_.Exception.Message)
        $rows = @(Import-Csv -LiteralPath $Path -Delimiter $delim -ErrorAction Stop)
    }

    if ($rows.Count -eq 0) {
        throw "The CSV appears to be empty."
    }

    # A single-column parse usually means the wrong delimiter was used.
    $columns = @($rows[0].PSObject.Properties.Name)
    if ($columns.Count -eq 1 -and $delim -ne ',') {
        Write-Warn "Only one column was detected. Re-reading as a comma-separated file."
        $rows = @(Import-Csv -LiteralPath $Path -Delimiter ',' -Encoding UTF8 -ErrorAction Stop)
    }

    return $rows
}

function Add-RecordDetail {
    param($Record, [string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return }
    if ([string]::IsNullOrWhiteSpace($Record.Detail)) {
        $Record.Detail = $Message
    }
    else {
        $Record.Detail = "{0}; {1}" -f $Record.Detail, $Message
    }
}

function Get-RowRecommendation {
    <# Ready = safe to change. Warning = can change but review first. Blocked = do not change. #>
    param($Row)
    switch ($Row.Status) {
        "WillChange" {
            if ([string]::IsNullOrWhiteSpace($Row.Detail)) { return "Ready" }
            return "Warning"
        }
        "Collision"  { return "Blocked" }
        "InvalidUpn" { return "Blocked" }
        "NotFound"   { return "Blocked" }
        "NoChange"   { return "NoChange" }
        "Skipped"    { return "Skipped" }
        "Changed"    { return "Changed" }
        "Failed"     { return "Blocked" }
        "SkippedByUser" { return "Skipped" }
        default      { return $Row.Status }
    }
}

function Set-RowRecommendations {
    param($Results)
    foreach ($r in $Results) {
        $r.Recommendation = Get-RowRecommendation -Row $r
    }
}

function Set-DuplicateAccountFlags {
    <# Two CSV rows for the same AD account: keep the first, skip extras, or collide if target UPNs differ. #>
    param($Results)

    $byDn = @{}
    foreach ($r in $Results) {
        if ([string]::IsNullOrWhiteSpace($r.DistinguishedName)) { continue }
        if ($r.Status -ne "WillChange") { continue }
        if (-not $byDn.ContainsKey($r.DistinguishedName)) {
            $byDn[$r.DistinguishedName] = New-Object System.Collections.ArrayList
        }
        [void]$byDn[$r.DistinguishedName].Add($r)
    }

    foreach ($dn in @($byDn.Keys)) {
        $group = @($byDn[$dn])
        if ($group.Count -lt 2) { continue }
        $uniqueUpns = @($group | ForEach-Object { $_.NewUPN.ToLowerInvariant() } | Select-Object -Unique)
        if ($uniqueUpns.Count -gt 1) {
            $rows = ($group | ForEach-Object { $_.Row }) -join ", "
            foreach ($r in $group) {
                $r.Status = "Collision"
                $r.UpnAction = "Collision"
                $r.Detail = "Same account appears on multiple CSV rows ($rows) with different target UPNs"
            }
        }
        else {
            $firstRow = $group[0].Row
            Add-RecordDetail -Record $group[0] -Message "Duplicate CSV rows for this account (row $firstRow kept)"
            for ($i = 1; $i -lt $group.Count; $i++) {
                $group[$i].Status = "Skipped"
                $group[$i].SmtpStatus = "Skip"
                $group[$i].Detail = "Duplicate of row $firstRow"
            }
        }
    }
}

function Set-CollisionFlags {
    param($Results)

    $will = @($Results | Where-Object { $_.Status -eq "WillChange" })
    $firstRowByUpn = @{}

    foreach ($r in $will) {
        $key = $r.NewUPN
        if ($firstRowByUpn.ContainsKey($key)) {
            $otherRow = $firstRowByUpn[$key]
            $first = $Results | Where-Object { $_.Row -eq $otherRow } | Select-Object -First 1
            $otherSam = if ($first -and $first.SamAccount) { $first.SamAccount } else { "(row $otherRow)" }
            $thisSam  = if ($r.SamAccount) { $r.SamAccount } else { "(row $($r.Row))" }

            $r.Status = "Collision"
            $r.UpnAction = "Collision"
            $r.InUseBySam = $otherSam
            $r.Detail = "Duplicate target UPN in this CSV (also row {0}, sAMAccountName {1})" -f $otherRow, $otherSam

            if ($first -and $first.Status -eq "WillChange") {
                $first.Status = "Collision"
                $first.UpnAction = "Collision"
                $first.InUseBySam = $thisSam
                $first.Detail = "Duplicate target UPN in this CSV (also row {0}, sAMAccountName {1})" -f $r.Row, $thisSam
            }
        }
        else {
            $firstRowByUpn[$key] = $r.Row
        }
    }

    # Check AD for anyone who already holds the planned UPN — including rows
    # already flagged as CSV collisions, so InUseBySam can name the live account.
    $candidates = @($Results | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.NewUPN) -and
        ($_.Status -eq "WillChange" -or $_.Status -eq "Collision")
    })
    if ($candidates.Count -eq 0) { return }

    $planned = @($candidates | ForEach-Object { $_.NewUPN } | Select-Object -Unique)
    $existing = Invoke-AdUserBatchLookup -AttributeName "userPrincipalName" -Values $planned -Server $script:QueryServer -Properties $script:UserProperties

    foreach ($r in $candidates) {
        if (-not $existing.ContainsKey($r.NewUPN)) { continue }
        $other = $existing[$r.NewUPN]
        if (-not $other) { continue }
        if ($r.DistinguishedName -and $other.DistinguishedName -and
            $other.DistinguishedName.Equals($r.DistinguishedName, [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $occupantSam = $other.SamAccountName
        if ([string]::IsNullOrWhiteSpace($occupantSam)) { $occupantSam = $other.Name }
        if ([string]::IsNullOrWhiteSpace($occupantSam)) { continue }

        $r.Status = "Collision"
        $r.UpnAction = "Collision"
        if ([string]::IsNullOrWhiteSpace($r.InUseBySam)) {
            $r.InUseBySam = $occupantSam
        }
        elseif ($r.InUseBySam.IndexOf($occupantSam, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            $r.InUseBySam = "{0}; {1}" -f $r.InUseBySam, $occupantSam
        }

        $adDetail = "UPN already in use by sAMAccountName {0}" -f $occupantSam
        if ($other.UserPrincipalName) {
            $adDetail = "{0} (their current UPN: {1})" -f $adDetail, $other.UserPrincipalName
        }
        if ([string]::IsNullOrWhiteSpace($r.Detail) -or $r.Detail -notlike "*already in use*") {
            Add-RecordDetail -Record $r -Message $adDetail
        }
    }
}

function Invoke-ProxyAddressOccupantLookup {
    <#
        Find AD users that already hold a proxyAddresses or mail value.
        Returns a case-insensitive hashtable keyed by the requested SMTP address.
    #>
    param(
        [Parameter(Mandatory)] [string[]] $Addresses,
        [string] $Server
    )

    $map = @{}
    $unique = @(
        $Addresses |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim() } |
            Sort-Object { $_.ToLowerInvariant() } -Unique
    )
    if ($unique.Count -eq 0) { return $map }

    $servers = @(Get-AdLookupServers -Preferred $Server)
    if ($servers.Count -eq 0) { $servers = @($null) }

    for ($i = 0; $i -lt $unique.Count; $i += $script:BatchSize) {
        $end   = [Math]::Min($i + $script:BatchSize - 1, $unique.Count - 1)
        $batch = @($unique[$i..$end])

        $pct = if ($unique.Count -gt 0) { [int](($i / $unique.Count) * 100) } else { 0 }
        Write-Progress -Activity "Querying Active Directory" -Status ("proxyAddresses: {0}-{1} of {2}" -f ($i + 1), ($end + 1), $unique.Count) -PercentComplete $pct

        $parts = foreach ($addr in $batch) {
            $mailEsc  = ConvertTo-LdapFilterValue -Value $addr
            $smtpEsc  = ConvertTo-LdapFilterValue -Value ("SMTP:{0}" -f $addr)
            $aliasEsc = ConvertTo-LdapFilterValue -Value ("smtp:{0}" -f $addr)
            "(|(proxyAddresses={0})(proxyAddresses={1})(mail={2}))" -f $smtpEsc, $aliasEsc, $mailEsc
        }
        $ldap = "(|{0})" -f ($parts -join "")

        $users = $null
        $lastError = $null
        foreach ($candidate in $servers) {
            $params = @{
                LDAPFilter     = $ldap
                Properties     = $script:UserProperties
                ResultPageSize = 200
                ErrorAction    = "Stop"
            }
            if ($candidate) { $params.Server = $candidate }
            try {
                $users = @(Get-ADUser @params)
                $lastError = $null
                if ($candidate) {
                    $script:QueryServer = $candidate
                    $servers = @($candidate) + @($servers | Where-Object { $_ -and -not $_.Equals($candidate, [StringComparison]::OrdinalIgnoreCase) })
                }
                break
            }
            catch {
                $lastError = $_
                Write-Warn ("Batch proxyAddresses lookup failed on {0}: {1}" -f $candidate, $_.Exception.Message)
                Log ("Batch proxyAddresses lookup failed on {0}: {1}" -f $candidate, $_.Exception.Message) "WARN"
            }
        }

        if ($lastError -and $null -eq $users) {
            Write-Warn "Falling back to one-by-one proxyAddresses lookup."
            $fallbackServer = $null
            if ($servers.Count -gt 0) { $fallbackServer = $servers[-1] }
            $collected = New-Object System.Collections.ArrayList
            foreach ($addr in $batch) {
                try {
                    $mailEsc  = ConvertTo-LdapFilterValue -Value $addr
                    $smtpEsc  = ConvertTo-LdapFilterValue -Value ("SMTP:{0}" -f $addr)
                    $aliasEsc = ConvertTo-LdapFilterValue -Value ("smtp:{0}" -f $addr)
                    $one = @{
                        LDAPFilter  = ("(|(proxyAddresses={0})(proxyAddresses={1})(mail={2}))" -f $smtpEsc, $aliasEsc, $mailEsc)
                        Properties  = $script:UserProperties
                        ErrorAction = "Stop"
                    }
                    if ($fallbackServer) { $one.Server = $fallbackServer }
                    foreach ($u in @(Get-ADUser @one)) {
                        if ($u) { [void]$collected.Add($u) }
                    }
                }
                catch { }
            }
            $users = @($collected)
        }

        foreach ($u in @($users)) {
            if (-not $u) { continue }
            $owned = New-Object System.Collections.ArrayList
            if ($u.mail) { [void]$owned.Add([string]$u.mail) }
            foreach ($p in (Get-UserProxyValues -User $u)) {
                if ($p -like 'smtp:*') { [void]$owned.Add($p.Substring(5)) }
            }
            foreach ($addr in $batch) {
                foreach ($have in $owned) {
                    if ($have.Equals($addr, [StringComparison]::OrdinalIgnoreCase)) {
                        $map[$addr] = $u
                        break
                    }
                }
            }
        }
    }

    Write-Progress -Activity "Querying Active Directory" -Completed
    return $map
}

function Set-SmtpInUseBySam {
    param($Record, [string]$Sam)
    if ([string]::IsNullOrWhiteSpace($Sam)) { return }
    if ([string]::IsNullOrWhiteSpace($Record.SmtpInUseBySam)) {
        $Record.SmtpInUseBySam = $Sam
    }
    elseif ($Record.SmtpInUseBySam.IndexOf($Sam, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        $Record.SmtpInUseBySam = "{0}; {1}" -f $Record.SmtpInUseBySam, $Sam
    }
}

function Set-SmtpCollisionFlags {
    <# Flag planned Primary SMTP addresses that collide in the CSV or already exist in AD. #>
    param($Results)

    $will = @($Results | Where-Object { $_.SmtpStatus -eq "WillChange" -and -not [string]::IsNullOrWhiteSpace($_.NewPrimarySmtp) })
    $firstRowBySmtp = @{}

    foreach ($r in $will) {
        $key = $r.NewPrimarySmtp
        if ($firstRowBySmtp.ContainsKey($key)) {
            $otherRow = $firstRowBySmtp[$key]
            $first = $Results | Where-Object { $_.Row -eq $otherRow } | Select-Object -First 1
            $otherSam = if ($first -and $first.SamAccount) { $first.SamAccount } else { "(row $otherRow)" }
            $thisSam  = if ($r.SamAccount) { $r.SamAccount } else { "(row $($r.Row))" }

            $r.SmtpStatus = "Collision"
            Set-SmtpInUseBySam -Record $r -Sam $otherSam
            Add-RecordDetail -Record $r -Message ("Duplicate target Primary SMTP in this CSV (also row {0}, sAMAccountName {1})" -f $otherRow, $otherSam)

            if ($first -and $first.SmtpStatus -eq "WillChange") {
                $first.SmtpStatus = "Collision"
                Set-SmtpInUseBySam -Record $first -Sam $thisSam
                Add-RecordDetail -Record $first -Message ("Duplicate target Primary SMTP in this CSV (also row {0}, sAMAccountName {1})" -f $r.Row, $thisSam)
            }
        }
        else {
            $firstRowBySmtp[$key] = $r.Row
        }
    }

    $candidates = @($Results | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.NewPrimarySmtp) -and
        ($_.SmtpStatus -eq "WillChange" -or $_.SmtpStatus -eq "Collision")
    })
    if ($candidates.Count -eq 0) { return }

    $planned = @($candidates | ForEach-Object { $_.NewPrimarySmtp } | Select-Object -Unique)
    $existing = Invoke-ProxyAddressOccupantLookup -Addresses $planned -Server $script:QueryServer

    foreach ($r in $candidates) {
        if (-not $existing.ContainsKey($r.NewPrimarySmtp)) { continue }
        $other = $existing[$r.NewPrimarySmtp]
        if (-not $other) { continue }
        if ($r.DistinguishedName -and $other.DistinguishedName -and
            $other.DistinguishedName.Equals($r.DistinguishedName, [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $occupantSam = $other.SamAccountName
        if ([string]::IsNullOrWhiteSpace($occupantSam)) { $occupantSam = $other.Name }
        if ([string]::IsNullOrWhiteSpace($occupantSam)) { continue }

        $r.SmtpStatus = "Collision"
        Set-SmtpInUseBySam -Record $r -Sam $occupantSam

        $adDetail = "Primary SMTP already in use by sAMAccountName {0}" -f $occupantSam
        if ($other.UserPrincipalName) {
            $adDetail = "{0} (their current UPN: {1})" -f $adDetail, $other.UserPrincipalName
        }
        if ([string]::IsNullOrWhiteSpace($r.Detail) -or $r.Detail -notlike "*Primary SMTP already in use*") {
            Add-RecordDetail -Record $r -Message $adDetail
        }
    }

    foreach ($r in $Results) {
        if ($r.SmtpStatus -ne "Collision") { continue }
        if ($r.UpnAction -eq "WillChange") { continue }
        if ($r.Status -eq "WillChange" -or $r.Status -eq "NoChange") {
            $r.Status = "Collision"
        }
    }
}

function ConvertTo-HtmlEncoded {
    param($Value)
    $text = if ($null -eq $Value) { "" } else { [string]$Value }
    return [System.Net.WebUtility]::HtmlEncode($text)
}

function ConvertTo-ReportTableHtml {
    param($Rows, [string[]]$Columns)

    $sb = New-Object System.Text.StringBuilder
    if (-not $Rows -or @($Rows).Count -eq 0) {
        [void]$sb.AppendLine('<p class="empty">None</p>')
        return $sb.ToString()
    }

    [void]$sb.AppendLine('<table><thead><tr>')
    foreach ($c in $Columns) {
        [void]$sb.Append('<th>')
        [void]$sb.Append((ConvertTo-HtmlEncoded $c))
        [void]$sb.AppendLine('</th>')
    }
    [void]$sb.AppendLine('</tr></thead><tbody>')
    foreach ($row in @($Rows)) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            [void]$sb.Append('<td>')
            [void]$sb.Append((ConvertTo-HtmlEncoded $row.$c))
            [void]$sb.Append('</td>')
        }
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')
    return $sb.ToString()
}

function Get-PreviewBuckets {
    param($Results)
    return [pscustomobject]@{
        Ready     = @($Results | Where-Object { $_.Recommendation -eq "Ready" })
        Warning   = @($Results | Where-Object { $_.Recommendation -eq "Warning" })
        Collision = @($Results | Where-Object { $_.Status -eq "Collision" })
        NotFound  = @($Results | Where-Object { $_.Status -eq "NotFound" })
        Invalid   = @($Results | Where-Object { $_.Status -eq "InvalidUpn" })
        Skipped   = @($Results | Where-Object { $_.Status -eq "Skipped" -or $_.Status -eq "SkippedByUser" })
        NoChange  = @($Results | Where-Object { $_.Status -eq "NoChange" })
        Changed   = @($Results | Where-Object { $_.Status -eq "Changed" })
        Failed    = @($Results | Where-Object { $_.Status -eq "Failed" })
        Blocked   = @($Results | Where-Object { $_.Recommendation -eq "Blocked" })
    }
}

function Get-OutputDirectory {
    param([string]$CsvPath)
    $dir = Split-Path -Path $CsvPath -Parent
    if ([string]::IsNullOrWhiteSpace($dir)) { $dir = (Get-Location).Path }
    return $dir
}

function Get-OutputStamp {
    if (-not $script:OutputStamp) {
        $script:OutputStamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    }
    return $script:OutputStamp
}

function Export-UpnPreviewReport {
    <# Writes an HTML report plus a CSV copy of the preview, grouped by recommendation. #>
    param(
        [Parameter(Mandatory)] [string] $CsvPath,
        [Parameter(Mandatory)] $Results,
        [string] $Title = "UPN suffix change preview",
        [string] $NamePrefix = "UpnFix_Preview"
    )

    $dir   = Get-OutputDirectory -CsvPath $CsvPath
    $stamp = Get-OutputStamp
    $htmlPath = Join-Path $dir ("{0}_{1}.html" -f $NamePrefix, $stamp)
    $csvOut   = Join-Path $dir ("{0}_{1}.csv"  -f $NamePrefix, $stamp)
    $buckets  = Get-PreviewBuckets -Results $Results
    $cols     = $script:ReportTableColumns

    $generated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $readyCount = $buckets.Ready.Count
    $warnCount  = $buckets.Warning.Count
    $collCount  = $buckets.Collision.Count
    $blockCount = $buckets.Blocked.Count

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>')
    [void]$sb.AppendLine('<title>' + (ConvertTo-HtmlEncoded $Title) + '</title>')
    [void]$sb.AppendLine(@'
<style>
body{font-family:Segoe UI,Tahoma,sans-serif;margin:24px;color:#1b1b1b;background:#f6f7f9}
h1{margin:0 0 8px 0;font-size:22px}
h2{margin:28px 0 8px 0;font-size:16px;padding:6px 10px;border-radius:4px}
.meta{color:#555;margin-bottom:16px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0 8px 0}
.card{min-width:140px;background:#fff;border:1px solid #d8dce3;border-radius:6px;padding:12px 14px}
.card .n{font-size:28px;font-weight:700;line-height:1}
.card .l{color:#555;font-size:12px;margin-top:4px}
.ok{border-left:4px solid #0d7a3f}.ok .n{color:#0d7a3f}
.warn{border-left:4px solid #9a6b00}.warn .n{color:#9a6b00}
.bad{border-left:4px solid #b42318}.bad .n{color:#b42318}
.neutral{border-left:4px solid #667085}.neutral .n{color:#667085}
h2.ok{background:#e7f6ec;color:#0d7a3f}
h2.warn{background:#fff6d9;color:#7a5600}
h2.bad{background:#fde8e6;color:#b42318}
h2.neutral{background:#eef0f3;color:#3f4c5a}
table{border-collapse:collapse;width:100%;background:#fff;margin:8px 0 16px 0}
th,td{border:1px solid #d8dce3;padding:6px 8px;text-align:left;font-size:13px;vertical-align:top}
th{background:#eef0f3}
.empty{color:#667085;font-style:italic}
code{background:#eef0f3;padding:1px 4px;border-radius:3px}
</style></head><body>
'@)

    [void]$sb.AppendLine('<h1>' + (ConvertTo-HtmlEncoded $Title) + '</h1>')
    [void]$sb.AppendLine('<div class="meta">Generated ' + (ConvertTo-HtmlEncoded $generated) + ' from <code>' + (ConvertTo-HtmlEncoded $CsvPath) + '</code>. Nothing has been applied yet unless the Status column says Changed.</div>')
    [void]$sb.AppendLine('<div class="cards">')
    [void]$sb.AppendLine('<div class="card ok"><div class="n">' + $readyCount + '</div><div class="l">OK to change</div></div>')
    [void]$sb.AppendLine('<div class="card warn"><div class="n">' + $warnCount + '</div><div class="l">Warnings (review)</div></div>')
    [void]$sb.AppendLine('<div class="card bad"><div class="n">' + $collCount + '</div><div class="l">Collisions</div></div>')
    [void]$sb.AppendLine('<div class="card bad"><div class="n">' + $blockCount + '</div><div class="l">Blocked / cannot change</div></div>')
    [void]$sb.AppendLine('<div class="card neutral"><div class="n">' + $buckets.NoChange.Count + '</div><div class="l">Already correct</div></div>')
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('<p class="meta"><strong>PrimarySmtp</strong> is the current uppercase SMTP: proxy (or mail). <strong>NewPrimarySmtp</strong> / <strong>NewProxyAddresses</strong> are the planned values when Primary SMTP rewrite is enabled. The old primary is kept as a smtp: alias unless discarded. A UPN-only run does not rewrite proxies.</p>')

    [void]$sb.AppendLine('<h2 class="ok">OK to change — ' + $readyCount + '</h2>')
    [void]$sb.AppendLine('<p>These accounts have a valid new UPN, no collision, and no extra warnings. Safe to apply.</p>')
    [void]$sb.AppendLine((ConvertTo-ReportTableHtml -Rows $buckets.Ready -Columns $cols))

    [void]$sb.AppendLine('<h2 class="warn">Warnings — review before changing — ' + $warnCount + '</h2>')
    [void]$sb.AppendLine('<p>The suffix can be written, but something needs a look (unregistered suffix, disabled account, local-part change, duplicate rows, or a Primary SMTP collision). Apply these only if you intend to. A Primary SMTP collision still allows the UPN write; the proxy is skipped.</p>')
    [void]$sb.AppendLine((ConvertTo-ReportTableHtml -Rows $buckets.Warning -Columns $cols))

    [void]$sb.AppendLine('<h2 class="bad">Collisions — will not be changed — ' + $collCount + '</h2>')
    [void]$sb.AppendLine('<p>Two rows share a target UPN, the UPN is already used in AD, the same account is listed twice with different targets, or the only planned change was a Primary SMTP that is already taken. <strong>InUseBySam</strong> is who holds the UPN. <strong>SmtpInUseBySam</strong> is who holds the proxy.</p>')
    [void]$sb.AppendLine((ConvertTo-ReportTableHtml -Rows $buckets.Collision -Columns $cols))

    [void]$sb.AppendLine('<h2 class="bad">Cannot change — ' + (@($buckets.NotFound).Count + @($buckets.Invalid).Count + @($buckets.Skipped).Count + @($buckets.Failed).Count) + '</h2>')
    [void]$sb.AppendLine('<p>Not found, invalid UPN, skipped, or failed writes.</p>')
    $cannot = @($buckets.NotFound) + @($buckets.Invalid) + @($buckets.Skipped) + @($buckets.Failed)
    [void]$sb.AppendLine((ConvertTo-ReportTableHtml -Rows $cannot -Columns $cols))

    [void]$sb.AppendLine('<h2 class="neutral">Already correct — ' + $buckets.NoChange.Count + '</h2>')
    [void]$sb.AppendLine((ConvertTo-ReportTableHtml -Rows $buckets.NoChange -Columns $cols))

    if ($buckets.Changed.Count -gt 0) {
        [void]$sb.AppendLine('<h2 class="ok">Applied — ' + $buckets.Changed.Count + '</h2>')
        [void]$sb.AppendLine((ConvertTo-ReportTableHtml -Rows $buckets.Changed -Columns $cols))
    }

    [void]$sb.AppendLine('</body></html>')

    $htmlPathOut = $null
    $csvOutOut   = $null
    try {
        [System.IO.File]::WriteAllText($htmlPath, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
        $htmlPathOut = $htmlPath
        Write-Ok ("Preview report (HTML): {0}" -f $htmlPath)
        Log ("Preview HTML report: {0}" -f $htmlPath)
    }
    catch {
        Write-Warn ("Could not write HTML report: {0}" -f $_.Exception.Message)
    }

    try {
        $Results | Select-Object -Property $script:ResultExportProperties |
            Export-Csv -Path $csvOut -NoTypeInformation -Encoding UTF8
        $csvOutOut = $csvOut
        Write-Ok ("Preview report (CSV):  {0}" -f $csvOut)
        Log ("Preview CSV report: {0}" -f $csvOut)
    }
    catch {
        Write-Warn ("Could not write preview CSV: {0}" -f $_.Exception.Message)
    }

    return [pscustomobject]@{ HtmlPath = $htmlPathOut; CsvPath = $csvOutOut }
}

function Show-PreviewReport {
    param($Buckets)

    function Write-ReportSection {
        param($Rows, [string]$Title, [string]$Color, [int]$Limit = 25)
        Write-Host ""
        Write-Host $Title -ForegroundColor $Color
        if (-not $Rows -or @($Rows).Count -eq 0) {
            Write-Host "  (none)" -ForegroundColor DarkGray
            return
        }
        $total = @($Rows).Count
        @($Rows | Select-Object -First $Limit) |
            Format-Table Row, SamAccount, CurrentUPN, NewUPN, PrimarySmtp, NewPrimarySmtp, SmtpStatus, InUseBySam, SmtpInUseBySam, Recommendation, Detail -AutoSize |
            Out-Host
        if ($total -gt $Limit) {
            Write-Host ("  ... {0} more in the HTML/CSV report" -f ($total - $Limit)) -ForegroundColor DarkGray
        }
    }

    Write-Section "Preview report"
    Write-Host ("  OK to change : {0}" -f $Buckets.Ready.Count)     -ForegroundColor Green
    Write-Host ("  Warnings     : {0}" -f $Buckets.Warning.Count)   -ForegroundColor Yellow
    Write-Host ("  Collisions   : {0}" -f $Buckets.Collision.Count) -ForegroundColor Red
    Write-Host ("  Not found    : {0}" -f $Buckets.NotFound.Count)  -ForegroundColor Red
    Write-Host ("  Invalid UPN  : {0}" -f $Buckets.Invalid.Count)   -ForegroundColor Red
    Write-Host ("  Skipped      : {0}" -f $Buckets.Skipped.Count)   -ForegroundColor DarkYellow
    Write-Host ("  Already OK   : {0}" -f $Buckets.NoChange.Count)  -ForegroundColor Green

    Write-ReportSection $Buckets.Ready     ("OK to change ({0}) — these are safe to apply" -f $Buckets.Ready.Count) Green 25
    Write-ReportSection $Buckets.Warning   ("Warnings ({0}) — review before changing" -f $Buckets.Warning.Count) Yellow 25
    Write-ReportSection $Buckets.Collision ("Collisions ({0}) — will not be changed" -f $Buckets.Collision.Count) Red 25
    $cannot = @($Buckets.NotFound) + @($Buckets.Invalid) + @($Buckets.Skipped)
    Write-ReportSection $cannot            ("Cannot change ({0}) — not found, invalid, or skipped" -f $cannot.Count) DarkYellow 15
}

# --------------------------------------------------------------- main ---------

function Main {
    Write-Section "Active Directory UPN Suffix Fixer"
    Write-Host "This tool previews changes first. Nothing is modified until you confirm." -ForegroundColor Gray

    Initialize-WinForms
    $validSuffixes = Assert-Prerequisites
    $suffixSet     = ConvertTo-CaseInsensitiveSet -Values $validSuffixes

    $path = $CsvPath
    if ([string]::IsNullOrWhiteSpace($path)) {
        $path = Select-CsvFile
        if (-not $path) { return }
    }
    elseif (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Write-Err "CSV not found: $path"
        Log "CSV not found: $path" "ERROR"
        return
    }
    else {
        Write-Ok ("Using CSV: {0}" -f $path)
        Log ("CSV selected: {0}" -f $path)
    }

    try {
        $rows = Import-UpnCsv -Path $path
    }
    catch {
        Write-Err "Failed to read CSV: $($_.Exception.Message)"
        Log "Failed to read CSV: $($_.Exception.Message)" "ERROR"
        return
    }

    $columns = @($rows[0].PSObject.Properties.Name)
    Write-Ok ("Loaded {0} row(s). Columns: {1}" -f $rows.Count, ($columns -join ", "))
    Log ("Loaded {0} rows. Columns: {1}" -f $rows.Count, ($columns -join ", "))

    $identityCol = Select-Column -Columns $columns -Purpose "user identity (UPN, sAMAccountName, or DN)" `
        -AutoDetect @("UserPrincipalName", "UPN", "SamAccountName", "sAMAccountName", "User", "Username", "LogonName", "DistinguishedName")

    $mode         = $null
    $valueCol     = $null
    $singleSuffix = $null

    if (-not [string]::IsNullOrWhiteSpace($Suffix)) {
        $singleSuffix = Get-NormalizedSuffix -Value $Suffix
        if ([string]::IsNullOrWhiteSpace($singleSuffix)) {
            Write-Err "The -Suffix parameter is empty after normalization."
            return
        }
        if ($suffixSet.Count -gt 0 -and -not (Test-SetContains -Set $suffixSet -Value $singleSuffix)) {
            Write-Warn ("'{0}' was not in the auto-detected UPN suffix list. AD may reject it." -f $singleSuffix)
            if (-not (Confirm-YesNo "Continue anyway?")) { return }
        }
        $mode = "SingleSuffix"
        Write-Ok ("Using suffix from -Suffix: @{0}  (applied to every account)" -f $singleSuffix)
    }
    else {
        $choice = Select-TargetSuffix -SuffixInfo $script:AvailableSuffixInfo -Columns $columns
        if (-not $choice) { return }
        $mode         = $choice.Mode
        $valueCol     = $choice.ValueCol
        $singleSuffix = $choice.Suffix
    }
    Log ("Mode: {0}; IdentityCol: {1}; ValueCol: {2}; SingleSuffix: {3}" -f $mode, $identityCol, $valueCol, $singleSuffix)

    $changeSmtp = Select-PrimarySmtpChange -AlsoChange:$AlsoChangePrimarySmtp -Skip:$SkipPrimarySmtp
    $keepOldAlias = -not $DiscardOldPrimarySmtp
    if ($changeSmtp) {
        if ($keepOldAlias) {
            Write-Ok "Primary SMTP suffix will be switched as well. Old primaries stay as smtp: aliases."
        }
        else {
            Write-Warn "Primary SMTP suffix will be switched. Old primaries will NOT be kept as aliases."
        }
    }
    else {
        Write-Info "Primary SMTP addresses will be left unchanged."
    }
    Log ("ChangePrimarySmtp: {0}; KeepOldPrimaryAsAlias: {1}" -f $changeSmtp, $keepOldAlias)

    # ---------------------------------------------------- dry run / preview ---
    Write-Section "Building preview (no changes made yet)"

    $identities = New-Object System.Collections.Generic.List[string]
    foreach ($row in $rows) {
        $id = [string]$row.$identityCol
        if (-not [string]::IsNullOrWhiteSpace($id)) { [void]$identities.Add($id.Trim()) }
    }

    $uniqueCount = @($identities | Select-Object -Unique).Count
    Write-Info ("Resolving {0} unique identity value(s) via batched LDAP..." -f $uniqueCount)
    $resolved = if ($identities.Count -gt 0) {
        Resolve-AdUsersFromIdentities -Identities $identities.ToArray()
    } else {
        @{}
    }

    $results = New-Object System.Collections.ArrayList
    $counter = 0
    $total   = $rows.Count

    foreach ($row in $rows) {
        $counter++
        if ($total -gt 25 -and ($counter % 25 -eq 0 -or $counter -eq $total)) {
            Write-Progress -Activity "Building preview" -Status "$counter of $total" -PercentComplete ([int](($counter / $total) * 100))
        }

        $identity = [string]$row.$identityCol
        $rowValue = if ($valueCol) { [string]$row.$valueCol } else { $null }

        $record = [ordered]@{
            Row                = $counter
            Identity           = $identity
            SamAccount         = ""
            DistinguishedName  = ""
            CurrentUPN         = ""
            NewUPN             = ""
            PrimarySmtp        = ""
            NewPrimarySmtp     = ""
            ProxyAddresses     = ""
            NewProxyAddresses  = ""
            NewProxyList       = @()
            UpnAction          = ""
            SmtpStatus         = ""
            InUseBySam         = ""
            SmtpInUseBySam     = ""
            Status             = ""
            Recommendation     = ""
            Detail             = ""
        }

        if ([string]::IsNullOrWhiteSpace($identity)) {
            $record.Status = "Skipped"
            $record.Detail = "Empty identity value"
            [void]$results.Add([pscustomobject]$record)
            continue
        }

        $user = $resolved[$identity.Trim()]
        if (-not $user) {
            $record.Status = "NotFound"
            $record.Detail = "No AD user matched"
            [void]$results.Add([pscustomobject]$record)
            continue
        }

        $record.SamAccount        = $user.SamAccountName
        $record.DistinguishedName = $user.DistinguishedName
        $record.CurrentUPN        = $user.UserPrincipalName
        $record.PrimarySmtp       = Get-PrimarySmtpAddress -User $user
        $record.ProxyAddresses    = Format-ProxyAddressList -User $user

        $newUpn = Get-NewUpn -User $user -Mode $mode -RowValue $rowValue -SingleSuffix $singleSuffix
        if ([string]::IsNullOrWhiteSpace($newUpn)) {
            $record.Status = "Skipped"
            $record.UpnAction = "Skipped"
            $record.SmtpStatus = "None"
            $record.Detail = "Could not build a new UPN"
            [void]$results.Add([pscustomobject]$record)
            continue
        }

        $record.NewUPN = $newUpn
        if (-not (Test-UpnFormat -Upn $newUpn)) {
            $record.Status = "InvalidUpn"
            $record.UpnAction = "InvalidUpn"
            $record.SmtpStatus = "None"
            $record.Detail = "New UPN is not in local-part@domain form"
            [void]$results.Add([pscustomobject]$record)
            continue
        }

        $upnAlreadyCorrect = $user.UserPrincipalName -and $newUpn.Equals($user.UserPrincipalName, [StringComparison]::OrdinalIgnoreCase)
        $record.UpnAction = if ($upnAlreadyCorrect) { "NoChange" } else { "WillChange" }

        $newSuffix = Get-UpnSuffix -Upn $newUpn
        if ($changeSmtp) {
            $currentSmtp = $record.PrimarySmtp
            if ([string]::IsNullOrWhiteSpace($currentSmtp) -or $currentSmtp -notlike '*@*') {
                $record.SmtpStatus = "Skip"
                Add-RecordDetail -Record $record -Message "No Primary SMTP on this object"
            }
            else {
                $newSmtp = Get-NewSmtpAddress -CurrentPrimary $currentSmtp -TargetSuffix $newSuffix
                $record.NewPrimarySmtp = $newSmtp
                if ([string]::IsNullOrWhiteSpace($newSmtp) -or -not (Test-UpnFormat -Upn $newSmtp)) {
                    $record.SmtpStatus = "Skip"
                    Add-RecordDetail -Record $record -Message "Could not build a new Primary SMTP"
                }
                elseif ($newSmtp.Equals($currentSmtp, [StringComparison]::OrdinalIgnoreCase)) {
                    $record.SmtpStatus = "NoChange"
                }
                else {
                    $record.SmtpStatus = "WillChange"
                    $newList = Get-UpdatedProxyAddressList -CurrentProxies (Get-UserProxyValues -User $user) -CurrentPrimary $currentSmtp -NewPrimary $newSmtp -KeepOldAsAlias $keepOldAlias
                    $record.NewProxyList = $newList
                    $record.NewProxyAddresses = Format-ProxyAddressValues -Values $newList
                }
            }
        }
        else {
            $record.SmtpStatus = "None"
        }

        if ($upnAlreadyCorrect -and $record.SmtpStatus -ne "WillChange") {
            $record.Status = "NoChange"
            if ([string]::IsNullOrWhiteSpace($record.Detail)) {
                $record.Detail = "Already correct"
            }
            [void]$results.Add([pscustomobject]$record)
            continue
        }

        $record.Status = "WillChange"
        if ($upnAlreadyCorrect) {
            Add-RecordDetail -Record $record -Message "UPN already correct"
        }
        if ($record.UpnAction -eq "WillChange" -and $suffixSet.Count -gt 0 -and $newSuffix -and -not (Test-SetContains -Set $suffixSet -Value $newSuffix)) {
            Add-RecordDetail -Record $record -Message ("Suffix '{0}' is not in the forest UPN suffix list" -f $newSuffix)
        }
        if ($user.Enabled -eq $false) {
            Add-RecordDetail -Record $record -Message "Account is disabled"
        }
        $oldPrefix = $null
        if ($user.UserPrincipalName -and $user.UserPrincipalName -like '*@*') {
            $oldPrefix = $user.UserPrincipalName.Split('@')[0]
        }
        $newPrefix = $newUpn.Split('@')[0]
        if ($record.UpnAction -eq "WillChange" -and $oldPrefix -and $newPrefix -and -not $oldPrefix.Equals($newPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            Add-RecordDetail -Record $record -Message ("Local-part will change from '{0}' to '{1}'" -f $oldPrefix, $newPrefix)
        }
        [void]$results.Add([pscustomobject]$record)
    }

    Write-Progress -Activity "Building preview" -Completed

    Write-Info "Checking for duplicate rows, UPN collisions, and Primary SMTP collisions..."
    Set-DuplicateAccountFlags -Results $results
    Set-CollisionFlags -Results $results
    if ($changeSmtp) {
        Set-SmtpCollisionFlags -Results $results
    }
    Set-RowRecommendations -Results $results
    $script:LastResults = $results

    $buckets = Get-PreviewBuckets -Results $results
    Show-PreviewReport -Buckets $buckets
    Log ("Preview: Ready={0} Warning={1} Collision={2} NotFound={3} InvalidUpn={4} Skipped={5} NoChange={6}" -f `
        $buckets.Ready.Count, $buckets.Warning.Count, $buckets.Collision.Count, $buckets.NotFound.Count, $buckets.Invalid.Count, $buckets.Skipped.Count, $buckets.NoChange.Count)

    $reportFiles = Export-UpnPreviewReport -CsvPath $path -Results $results -Title "UPN suffix change preview"
    if ($reportFiles -and $reportFiles.HtmlPath -and (Test-IsInteractive)) {
        if (Confirm-YesNo "Open the HTML report in your browser?" -DefaultYes) {
            try { Start-Process $reportFiles.HtmlPath } catch {
                Write-Warn ("Could not open the report: {0}" -f $_.Exception.Message)
            }
        }
    }

    $ready   = $buckets.Ready
    $warning = $buckets.Warning

    if ($ready.Count -eq 0 -and $warning.Count -eq 0) {
        Write-Info "There is nothing safe to change. See the report for collisions and other issues."
        Save-Output -CsvPath $path -Results $results
        return
    }

    Write-Section "Apply changes"
    $toApply = @($ready)
    if ($ready.Count -gt 0) {
        if (-not (Confirm-YesNo ("Apply {0} account(s) marked OK to change?" -f $ready.Count))) {
            $toApply = @()
        }
    }
    else {
        Write-Warn "No accounts are marked OK to change."
        $toApply = @()
    }

    if ($warning.Count -gt 0) {
        Write-Warn ("{0} account(s) have warnings (unregistered suffix, disabled, local-part change, duplicates, or Primary SMTP collision)." -f $warning.Count)
        if (Confirm-YesNo "Also apply the warning account(s)?") {
            $toApply = @($toApply) + @($warning)
        }
    }

    if ($toApply.Count -eq 0) {
        Write-Warn "No changes applied."
        Log "User declined to apply changes." "WARN"
        Save-Output -CsvPath $path -Results $results
        return
    }

    $perAccount = Confirm-YesNo "Confirm each account individually?"

    $applied = 0
    $failed  = 0
    $applyTotal = $toApply.Count
    $applyIdx = 0

    foreach ($r in $toApply) {
        $applyIdx++
        if ($applyTotal -gt 5) {
            Write-Progress -Activity "Applying UPN changes" -Status ("{0} of {1}: {2}" -f $applyIdx, $applyTotal, $r.SamAccount) -PercentComplete ([int](($applyIdx / $applyTotal) * 100))
        }

        if ($perAccount) {
            $msg = ("Change {0}: {1}  ->  {2}" -f $r.SamAccount, $r.CurrentUPN, $r.NewUPN)
            if ($r.SmtpStatus -eq "WillChange") {
                $msg = "{0}; Primary SMTP {1} -> {2}" -f $msg, $r.PrimarySmtp, $r.NewPrimarySmtp
            }
            elseif ($r.SmtpStatus -eq "Collision") {
                $msg = "{0}; Primary SMTP skipped (in use by {1})" -f $msg, $r.SmtpInUseBySam
            }
            if (-not (Confirm-YesNo $msg -DefaultYes)) {
                $r.Status = "SkippedByUser"
                $r.Detail = "User skipped at confirmation"
                Log ("Skipped by user: {0}" -f $r.SamAccount) "WARN"
                continue
            }
        }

        $identity = if ($r.DistinguishedName) { $r.DistinguishedName } else { $r.SamAccount }
        $writeTo  = $script:WriteServer
        if ($r.DistinguishedName) {
            $fakeUser = [pscustomobject]@{ DistinguishedName = $r.DistinguishedName }
            $writeTo = Get-WritableServerForUser -User $fakeUser
        }

        try {
            $setParams = @{
                Identity    = $identity
                ErrorAction = "Stop"
            }
            if ($writeTo) { $setParams.Server = $writeTo }
            if ($r.UpnAction -eq "WillChange") {
                $setParams.UserPrincipalName = $r.NewUPN
            }

            $replace = @{}
            if ($r.SmtpStatus -eq "WillChange") {
                $proxyList = [string[]]@($r.NewProxyList)
                if ($proxyList.Count -gt 0) {
                    $replace["proxyAddresses"] = $proxyList
                }
                if (-not [string]::IsNullOrWhiteSpace($r.NewPrimarySmtp)) {
                    $replace["mail"] = $r.NewPrimarySmtp
                }
            }
            if ($replace.Count -gt 0) {
                $setParams.Replace = $replace
            }
            if (-not $setParams.ContainsKey("UserPrincipalName") -and -not $setParams.ContainsKey("Replace")) {
                $r.Status = "NoChange"
                $r.Detail = "Nothing left to apply"
                continue
            }

            Set-ADUser @setParams
            $r.Status = "Changed"
            $changedBits = New-Object System.Collections.ArrayList
            if ($setParams.ContainsKey("UserPrincipalName")) {
                [void]$changedBits.Add(("UPN {0} -> {1}" -f $r.CurrentUPN, $r.NewUPN))
            }
            if ($r.SmtpStatus -eq "WillChange") {
                [void]$changedBits.Add(("Primary SMTP {0} -> {1}" -f $r.PrimarySmtp, $r.NewPrimarySmtp))
                $r.PrimarySmtp = $r.NewPrimarySmtp
                $r.ProxyAddresses = $r.NewProxyAddresses
            }
            $r.Detail = "OK"
            $applied++
            $summary = ($changedBits -join "; ")
            Write-Ok ("Changed {0}: {1}" -f $r.SamAccount, $summary)
            Log ("Changed {0}: {1}" -f $r.SamAccount, $summary)
        }
        catch {
            $r.Status = "Failed"
            $r.Detail = $_.Exception.Message
            $failed++
            Write-Err ("Failed {0}: {1}" -f $r.SamAccount, $_.Exception.Message)
            Log ("Failed {0}: {1}" -f $r.SamAccount, $_.Exception.Message) "ERROR"
        }
    }

    Write-Progress -Activity "Applying UPN changes" -Completed

    Write-Section "Done"
    Write-Ok  ("Applied : {0}" -f $applied)
    if ($failed -gt 0) { Write-Err ("Failed  : {0}" -f $failed) }
    Log ("Applied={0} Failed={1}" -f $applied, $failed)

    Set-RowRecommendations -Results $results
    Export-UpnPreviewReport -CsvPath $path -Results $results -Title "UPN suffix change results" -NamePrefix "UpnFix_Results" | Out-Null
    Save-Output -CsvPath $path -Results $results
}

function Save-Output {
    param(
        [Parameter(Mandatory)] [string] $CsvPath,
        [Parameter(Mandatory)] $Results
    )
    $dir   = Get-OutputDirectory -CsvPath $CsvPath
    $stamp = Get-OutputStamp

    $resultsCsv = Join-Path $dir ("UpnFix_Results_{0}.csv" -f $stamp)
    $logTxt     = Join-Path $dir ("UpnFix_Log_{0}.txt"     -f $stamp)

    try {
        $Results | Select-Object -Property $script:ResultExportProperties |
            Export-Csv -Path $resultsCsv -NoTypeInformation -Encoding UTF8
        Write-Ok ("Results written to: {0}" -f $resultsCsv)
    }
    catch {
        Write-Warn ("Could not write results CSV: {0}" -f $_.Exception.Message)
    }

    try {
        $script:LogLines | Set-Content -Path $logTxt -Encoding UTF8
        Write-Ok ("Log written to:     {0}" -f $logTxt)
    }
    catch {
        Write-Warn ("Could not write log file: {0}" -f $_.Exception.Message)
    }
}

# --------------------------------------------------------------- run ----------
try {
    Main
}
catch {
    Write-Err ("Fatal error: {0}" -f $_.Exception.Message)
    Log ("Fatal error: {0}" -f $_.Exception.Message) "ERROR"
    if ($script:LastResults -and $CsvPath) {
        try { Save-Output -CsvPath $CsvPath -Results $script:LastResults } catch { }
    }
}
finally {
    Write-Host ""
    if (-not $SkipPause -and (Test-IsInteractive)) {
        try { Read-Host "Press ENTER to close" | Out-Null } catch { }
    }
}

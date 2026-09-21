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
    - Supports three ways to determine the CORRECT value:
        1) a column that contains just the suffix        (e.g. "omi.com")
        2) a column that contains the full correct UPN    (e.g. "user@omi.com")
        3) a single suffix you type, applied to everyone   (e.g. "omi.com")
    - Dry-run preview first. Nothing is written until you confirm.
    - Optional per-account confirmation.
    - Writes a text log and a results CSV next to the source file.

    Performance and correctness (vs. the original per-row Get-ADUser loop):
    - Resolves users in LDAP batches (default 50) instead of 1-3 queries per row.
    - Pins reads to a Global Catalog and writes to a writable DC so multi-domain
      forests resolve correctly and changes are not lost to replication lag.
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

.PARAMETER SkipPause
    Skip the "Press ENTER to close" prompt (useful for automation).

.EXAMPLE
    powershell -STA -ExecutionPolicy Bypass -File .\Fix-UpnSuffix.ps1

.EXAMPLE
    powershell -STA -ExecutionPolicy Bypass -File .\Fix-UpnSuffix.ps1 -CsvPath C:\Temp\users.csv

.NOTES
    Run from an elevated PowerShell session as an account with rights to modify users.
    Use -STA so the Windows file picker can open reliably (powershell.exe defaults to MTA).
#>

[CmdletBinding()]
param(
    [string]$CsvPath,
    [string]$Server,
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
$script:QueryServer  = $null   # Global Catalog host:port for reads
$script:WriteServer  = $null   # Writable DC for the connected domain
$script:DomainDcCache = @{}    # domain DNS -> writable DC hostname
$script:WinFormsAvailable = $false
$script:BatchSize    = 50
$script:UserProperties = @("UserPrincipalName", "SamAccountName", "DistinguishedName", "Name")

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

function Invoke-AdUserBatchLookup {
    <#
        Look up users in chunks with a single LDAP OR filter per chunk.
        Returns a case-insensitive hashtable keyed by the requested attribute value.
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

    for ($i = 0; $i -lt $unique.Count; $i += $script:BatchSize) {
        $end   = [Math]::Min($i + $script:BatchSize - 1, $unique.Count - 1)
        $batch = @($unique[$i..$end])

        $pct = if ($total -gt 0) { [int](($i / $total) * 100) } else { 0 }
        Write-Progress -Activity "Querying Active Directory" -Status ("{0}: {1}-{2} of {3}" -f $AttributeName, ($i + 1), ($end + 1), $total) -PercentComplete $pct

        $parts = foreach ($v in $batch) {
            "({0}={1})" -f $AttributeName, (ConvertTo-LdapFilterValue -Value $v)
        }
        $ldap = "(|{0})" -f ($parts -join "")

        $params = @{
            LDAPFilter     = $ldap
            Properties     = $props
            ResultPageSize = 200
            ErrorAction    = "Stop"
        }
        if ($Server) { $params.Server = $Server }

        $users = $null
        try {
            $users = @(Get-ADUser @params)
        }
        catch {
            Write-Warn ("Batch {0} lookup failed: {1}. Falling back to one-by-one." -f $AttributeName, $_.Exception.Message)
            Log ("Batch lookup failed for {0}: {1}" -f $AttributeName, $_.Exception.Message) "WARN"
            $users = New-Object System.Collections.Generic.List[object]
            foreach ($v in $batch) {
                try {
                    $one = @{
                        LDAPFilter  = ("({0}={1})" -f $AttributeName, (ConvertTo-LdapFilterValue -Value $v))
                        Properties  = $props
                        ErrorAction = "Stop"
                    }
                    if ($Server) { $one.Server = $Server }
                    $u = Get-ADUser @one
                    if ($u) { [void]$users.Add($u) }
                }
                catch {
                    # Not found or inaccessible — leave it unresolved.
                }
            }
            $users = @($users)
        }

        foreach ($u in $users) {
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
            $script:QueryServer = "{0}:3268" -f $gc.HostName
            Write-Ok ("Global Catalog (reads): {0}" -f $script:QueryServer)
            Log ("Using Global Catalog {0} for reads" -f $script:QueryServer)
        }
    }
    catch {
        Write-Warn "Could not discover a Global Catalog. Lookups are limited to the connected domain."
        Log "GC discovery failed: $($_.Exception.Message)" "WARN"
    }

    try {
        $forest = Get-ADForest -ErrorAction Stop
        # Every domain DNS name is a valid UPN suffix, plus any explicitly added suffixes.
        $raw = @($forest.Domains) + @($forest.UPNSuffixes)
        $validSuffixes = @(
            $raw |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Sort-Object { $_.ToLowerInvariant() } -Unique
        )
        Write-Info "UPN suffixes available in this forest:"
        $validSuffixes | ForEach-Object { Write-Host ("  - {0}" -f $_) }
        Log ("Forest UPN suffixes: {0}" -f ($validSuffixes -join ", "))
        return $validSuffixes
    }
    catch {
        Write-Warn "Could not enumerate forest UPN suffixes (continuing anyway)."
        Log "Could not enumerate forest UPN suffixes: $($_.Exception.Message)" "WARN"
        return @()
    }
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

function Select-Suffix {
    param([string[]] $ValidSuffixes)

    $list = @(
        $ValidSuffixes |
            Where-Object { $_ } |
            Sort-Object { $_.ToLowerInvariant() } -Unique
    )

    Write-Section "Choose the suffix to apply to ALL accounts in the CSV"

    if ($list.Count -gt 0) {
        for ($i = 0; $i -lt $list.Count; $i++) {
            Write-Host ("  [{0}] @{1}" -f ($i + 1), $list[$i])
        }
        $customOption = $list.Count + 1
        Write-Host ("  [{0}] Type a custom suffix" -f $customOption)
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
                    $chosen = $list[$n - 1]
                    Write-Ok ("Selected suffix: @{0}" -f $chosen)
                    Log ("Selected suffix from list: {0}" -f $chosen)
                    return $chosen
                }
                elseif ($n -eq $customOption) {
                    return Read-CustomSuffix -ValidSuffixes $list
                }
            }
            Write-Warn ("Enter a number between 1 and {0}, or C to cancel." -f $customOption)
        }
    }
    else {
        Write-Warn "No forest UPN suffixes could be listed. Please type one."
        return Read-CustomSuffix -ValidSuffixes @()
    }
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

function Show-PreviewTable {
    param($Results, $WillChange, $NotFound, $Invalid, $Collision)

    if ($Results.Count -le 40) {
        $Results | Format-Table Row, SamAccount, CurrentUPN, NewUPN, Status -AutoSize | Out-Host
        return
    }

    Write-Info ("CSV has {0} rows. Showing the rows that need attention (not the full table)." -f $Results.Count)

    if ($WillChange.Count -gt 0) {
        Write-Host ""
        Write-Info ("Will change (first 50 of {0}):" -f $WillChange.Count)
        $WillChange | Select-Object -First 50 | Format-Table Row, SamAccount, CurrentUPN, NewUPN, Status -AutoSize | Out-Host
    }
    if ($Collision.Count -gt 0) {
        Write-Host ""
        Write-Warn ("Collisions (first 20 of {0}):" -f $Collision.Count)
        $Collision | Select-Object -First 20 | Format-Table Row, SamAccount, CurrentUPN, NewUPN, Detail -AutoSize | Out-Host
    }
    if ($Invalid.Count -gt 0) {
        Write-Host ""
        Write-Warn ("Invalid UPN (first 20 of {0}):" -f $Invalid.Count)
        $Invalid | Select-Object -First 20 | Format-Table Row, Identity, NewUPN, Detail -AutoSize | Out-Host
    }
    if ($NotFound.Count -gt 0) {
        Write-Host ""
        Write-Warn ("Not found (first 20 of {0}):" -f $NotFound.Count)
        $NotFound | Select-Object -First 20 | Format-Table Row, Identity, Status, Detail -AutoSize | Out-Host
    }
    if ($WillChange.Count -eq 0 -and $Collision.Count -eq 0 -and $Invalid.Count -eq 0 -and $NotFound.Count -eq 0) {
        Write-Host ""
        Write-Info "First 20 rows:"
        $Results | Select-Object -First 20 | Format-Table Row, SamAccount, CurrentUPN, NewUPN, Status -AutoSize | Out-Host
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
            $r.Status = "Collision"
            $r.Detail = "Duplicate target UPN in this CSV (also row $otherRow)"
            $first = $Results | Where-Object { $_.Row -eq $otherRow } | Select-Object -First 1
            if ($first -and $first.Status -eq "WillChange") {
                $first.Status = "Collision"
                $first.Detail = "Duplicate target UPN in this CSV (also row $($r.Row))"
            }
        }
        else {
            $firstRowByUpn[$key] = $r.Row
        }
    }

    $still = @($Results | Where-Object { $_.Status -eq "WillChange" })
    if ($still.Count -eq 0) { return }

    $planned = @($still | ForEach-Object { $_.NewUPN } | Select-Object -Unique)
    $existing = Invoke-AdUserBatchLookup -AttributeName "userPrincipalName" -Values $planned -Server $script:QueryServer -Properties $script:UserProperties

    foreach ($r in $still) {
        if (-not $existing.ContainsKey($r.NewUPN)) { continue }
        $other = $existing[$r.NewUPN]
        if (-not $other) { continue }
        if ($r.DistinguishedName -and $other.DistinguishedName -and
            $other.DistinguishedName.Equals($r.DistinguishedName, [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        $r.Status = "Collision"
        $r.Detail = "UPN already in use by {0}" -f $other.SamAccountName
    }
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

    Write-Section "How should the correct UPN be determined?"
    Write-Host "  [1] A column contains just the suffix          (e.g. omi.com)"
    Write-Host "  [2] A column contains the full correct UPN     (e.g. user@omi.com)"
    Write-Host "  [3] Apply one suffix I type to every account   (e.g. omi.com)"
    $modeChoice = Read-Choice -Prompt "Choose 1, 2, or 3" -Valid @("1", "2", "3")

    $mode         = $null
    $valueCol     = $null
    $singleSuffix = $null

    switch ($modeChoice) {
        "1" {
            $mode     = "SuffixColumn"
            $valueCol = Select-Column -Columns $columns -Purpose "correct suffix" `
                -AutoDetect @("Suffix", "UPNSuffix", "NewSuffix", "CorrectSuffix", "Domain")
        }
        "2" {
            $mode     = "FullUpnColumn"
            $valueCol = Select-Column -Columns $columns -Purpose "full correct UPN" `
                -AutoDetect @("NewUPN", "CorrectUPN", "NewUserPrincipalName", "TargetUPN")
        }
        "3" {
            $mode         = "SingleSuffix"
            $singleSuffix = Select-Suffix -ValidSuffixes $validSuffixes
            if (-not $singleSuffix) { return }
        }
    }
    Log ("Mode: {0}; IdentityCol: {1}; ValueCol: {2}; SingleSuffix: {3}" -f $mode, $identityCol, $valueCol, $singleSuffix)

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

    $results = New-Object System.Collections.Generic.List[object]
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
            Status             = ""
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

        $newUpn = Get-NewUpn -User $user -Mode $mode -RowValue $rowValue -SingleSuffix $singleSuffix
        if ([string]::IsNullOrWhiteSpace($newUpn)) {
            $record.Status = "Skipped"
            $record.Detail = "Could not build a new UPN"
            [void]$results.Add([pscustomobject]$record)
            continue
        }

        $record.NewUPN = $newUpn
        if (-not (Test-UpnFormat -Upn $newUpn)) {
            $record.Status = "InvalidUpn"
            $record.Detail = "New UPN is not in local-part@domain form"
            [void]$results.Add([pscustomobject]$record)
            continue
        }

        if ($user.UserPrincipalName -and $newUpn.Equals($user.UserPrincipalName, [StringComparison]::OrdinalIgnoreCase)) {
            $record.Status = "NoChange"
            $record.Detail = "Already correct"
            [void]$results.Add([pscustomobject]$record)
            continue
        }

        $newSuffix = Get-UpnSuffix -Upn $newUpn
        if ($suffixSet.Count -gt 0 -and $newSuffix -and -not (Test-SetContains -Set $suffixSet -Value $newSuffix)) {
            $record.Status = "WillChange"
            $record.Detail = "Suffix '$newSuffix' is not in the forest UPN suffix list"
        }
        else {
            $record.Status = "WillChange"
        }
        [void]$results.Add([pscustomobject]$record)
    }

    Write-Progress -Activity "Building preview" -Completed

    Write-Info "Checking for UPN collisions..."
    Set-CollisionFlags -Results $results
    $script:LastResults = $results

    $willChange = @($results | Where-Object { $_.Status -eq "WillChange" })
    $noChange   = @($results | Where-Object { $_.Status -eq "NoChange" })
    $notFound   = @($results | Where-Object { $_.Status -eq "NotFound" })
    $skipped    = @($results | Where-Object { $_.Status -eq "Skipped" })
    $invalid    = @($results | Where-Object { $_.Status -eq "InvalidUpn" })
    $collision  = @($results | Where-Object { $_.Status -eq "Collision" })

    Show-PreviewTable -Results $results -WillChange $willChange -NotFound $notFound -Invalid $invalid -Collision $collision

    $unknownSuffix = @($willChange | Where-Object { $_.Detail -like "Suffix * is not in the forest UPN suffix list" })

    Write-Section "Summary"
    Write-Host ("  Will change : {0}" -f $willChange.Count) -ForegroundColor Yellow
    Write-Host ("  No change   : {0}" -f $noChange.Count)   -ForegroundColor Green
    Write-Host ("  Not found   : {0}" -f $notFound.Count)   -ForegroundColor Red
    Write-Host ("  Collision   : {0}" -f $collision.Count)  -ForegroundColor Red
    Write-Host ("  Invalid UPN : {0}" -f $invalid.Count)    -ForegroundColor Red
    Write-Host ("  Skipped     : {0}" -f $skipped.Count)    -ForegroundColor DarkYellow
    Log ("Preview: WillChange={0} NoChange={1} NotFound={2} Collision={3} InvalidUpn={4} Skipped={5}" -f `
        $willChange.Count, $noChange.Count, $notFound.Count, $collision.Count, $invalid.Count, $skipped.Count)

    if ($unknownSuffix.Count -gt 0) {
        Write-Warn ("{0} planned UPN(s) use a suffix that is not defined on the forest. AD may reject those writes." -f $unknownSuffix.Count)
    }

    if ($willChange.Count -eq 0) {
        Write-Info "There is nothing to change. Exiting."
        Save-Output -CsvPath $path -Results $results
        return
    }

    Write-Section "Apply changes"
    if (-not (Confirm-YesNo ("Apply {0} UPN change(s) now?" -f $willChange.Count))) {
        Write-Warn "No changes applied (user declined)."
        Log "User declined to apply changes." "WARN"
        Save-Output -CsvPath $path -Results $results
        return
    }

    $perAccount = Confirm-YesNo "Confirm each account individually?"

    $applied = 0
    $failed  = 0
    $applyTotal = $willChange.Count
    $applyIdx = 0

    foreach ($r in $willChange) {
        $applyIdx++
        if ($applyTotal -gt 5) {
            Write-Progress -Activity "Applying UPN changes" -Status ("{0} of {1}: {2}" -f $applyIdx, $applyTotal, $r.SamAccount) -PercentComplete ([int](($applyIdx / $applyTotal) * 100))
        }

        if ($perAccount) {
            $msg = ("Change {0}: {1}  ->  {2}" -f $r.SamAccount, $r.CurrentUPN, $r.NewUPN)
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
                Identity          = $identity
                UserPrincipalName = $r.NewUPN
                ErrorAction       = "Stop"
            }
            if ($writeTo) { $setParams.Server = $writeTo }
            Set-ADUser @setParams
            $r.Status = "Changed"
            $r.Detail = "OK"
            $applied++
            Write-Ok ("Changed {0}: {1} -> {2}" -f $r.SamAccount, $r.CurrentUPN, $r.NewUPN)
            Log ("Changed {0}: {1} -> {2}" -f $r.SamAccount, $r.CurrentUPN, $r.NewUPN)
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

    Save-Output -CsvPath $path -Results $results
}

function Save-Output {
    param(
        [Parameter(Mandatory)] [string] $CsvPath,
        [Parameter(Mandatory)] $Results
    )
    $dir   = Split-Path -Path $CsvPath -Parent
    if ([string]::IsNullOrWhiteSpace($dir)) { $dir = (Get-Location).Path }
    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")

    $resultsCsv = Join-Path $dir ("UpnFix_Results_{0}.csv" -f $stamp)
    $logTxt     = Join-Path $dir ("UpnFix_Log_{0}.txt"     -f $stamp)

    try {
        $Results | Export-Csv -Path $resultsCsv -NoTypeInformation -Encoding UTF8
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

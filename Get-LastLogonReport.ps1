#Requires -Version 5.1
<#
.SYNOPSIS
    Ingests a CSV of SamAccountNames, looks up each user's last logon date in Active Directory,
    and exports the results to a CSV. Uses GUI file pickers for both input and output.

.DESCRIPTION
    - Prompts with an Open File dialog to select the input CSV (must contain a SamAccountName column).
    - Prompts with a Save File dialog to choose where the results CSV should be written.
    - For each user, queries Active Directory for lastLogonTimestamp (fast, replicated, may lag up to
      ~14 days depending on domain policy) and optionally the true LastLogon by querying every
      Domain Controller (slower, but accurate to the most recent logon recorded on a reachable DC).
    - Handles users not found in AD and reports them in the output with a status column.

    Timestamps in the export are local time, formatted as yyyy-MM-dd HH:mm:ss.

    Accurate mode takes the latest of:
      - lastLogon from every reachable DC (non-replicated, most precise)
      - LastLogonDate / lastLogonTimestamp (replicated; used as a floor so an unreachable DC
        cannot hide a more recent replicated value)

.NOTES
    Requires the ActiveDirectory PowerShell module (RSAT: AD DS and AD LDS Tools).
    Tested against PowerShell 5.1 / Windows Server & Windows 10/11 with RSAT installed.

    Bugs fixed vs. the original script:
    - Single unique name / single DC: foreach enumerates STRING CHARACTERS unless wrapped in @().
    - WinForms dialogs require STA; powershell.exe is MTA by default (dialogs hang or never appear).
    - FileTime 0 / 1601-01-01 was at risk of being treated as a real logon date.
    - Select-Object -Unique is case-sensitive; sAMAccountName is not (jdoe vs JDOE).
    - Output path was chosen AFTER the AD queries, so canceling Save discarded all work.
    - Unreachable DCs could stall ~2 minutes each with no pre-check.
    - Accurate lastLogon ignored LastLogonTimestamp, so a down DC could yield a worse answer.
    - Get-ADUser -Identity is ambiguous (DN/GUID/SID/SAM); lookup is now by sAMAccountName.
    - ADIdentityNotFoundException typed catch can fail to bind; not-found is handled without it.
    - Dialogs could open behind the console; they are now owned by a TopMost form.

.PARAMETER AccurateLastLogon
    Switch. When specified, queries every DC in the domain for the true LastLogon attribute
    (most accurate, but much slower on large domains). Without this switch, the script uses
    the replicated LastLogonTimestamp attribute (exposed as LastLogonDate), which is fast
    but can be up to ~14 days stale.

.PARAMETER InputCsv
    Optional. Path to the input CSV. When omitted, an Open File dialog is shown.

.PARAMETER OutputCsv
    Optional. Path to write the report. When omitted, a Save File dialog is shown.

.PARAMETER SelfTest
    Switch. Runs built-in unit tests for date conversion, LDAP escaping, and CSV column
    detection, then exits. Does not contact Active Directory or show dialogs.

.EXAMPLE
    .\Get-LastLogonReport.ps1

.EXAMPLE
    .\Get-LastLogonReport.ps1 -AccurateLastLogon

.EXAMPLE
    .\Get-LastLogonReport.ps1 -InputCsv .\users.csv -OutputCsv .\LastLogonReport.csv

.EXAMPLE
    .\Get-LastLogonReport.ps1 -SelfTest
#>

[CmdletBinding()]
param(
    [switch]$AccurateLastLogon,

    [Parameter()]
    [string]$InputCsv,

    [Parameter()]
    [string]$OutputCsv,

    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region STA -------------------------------------------------------------------

# WinForms dialogs require STA. Windows PowerShell 5.1 console hosts are MTA.
$script:UseGui = (-not $SelfTest) -and (
    [string]::IsNullOrWhiteSpace($InputCsv) -or [string]::IsNullOrWhiteSpace($OutputCsv)
)

if ($script:UseGui -and [System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        Write-Host "File dialogs require STA. Restart with: powershell.exe -STA -File <script>" -ForegroundColor Red
        exit 1
    }
    $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $argParts = New-Object System.Collections.Generic.List[string]
    [void]$argParts.Add('-NoProfile')
    [void]$argParts.Add('-STA')
    [void]$argParts.Add('-ExecutionPolicy')
    [void]$argParts.Add('Bypass')
    [void]$argParts.Add('-File')
    [void]$argParts.Add(('"{0}"' -f $PSCommandPath))
    if ($AccurateLastLogon) {
        [void]$argParts.Add('-AccurateLastLogon')
    }
    if (-not [string]::IsNullOrWhiteSpace($InputCsv)) {
        [void]$argParts.Add('-InputCsv')
        [void]$argParts.Add(('"{0}"' -f $InputCsv))
    }
    if (-not [string]::IsNullOrWhiteSpace($OutputCsv)) {
        [void]$argParts.Add('-OutputCsv')
        [void]$argParts.Add(('"{0}"' -f $OutputCsv))
    }

    Write-Host "Relaunching in STA mode so file dialogs work..." -ForegroundColor Yellow
    $proc = Start-Process -FilePath $exe -ArgumentList ($argParts -join ' ') -Wait -PassThru -NoNewWindow
    if ($null -eq $proc.ExitCode) { exit 1 }
    exit $proc.ExitCode
}

#endregion

#region Helpers ----------------------------------------------------------------

function Show-UiMessage {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter(Mandatory)]
        [string]$Title,

        [ValidateSet('Information', 'Error', 'Warning')]
        [string]$Icon = 'Information'
    )

    if ($script:UseGui -and $script:WinFormsLoaded) {
        $boxIcon = [System.Windows.Forms.MessageBoxIcon]::$Icon
        [void][System.Windows.Forms.MessageBox]::Show(
            $Message,
            $Title,
            [System.Windows.Forms.MessageBoxButtons]::OK,
            $boxIcon
        )
        return
    }

    if ($Icon -eq 'Error') {
        Write-Host $Message -ForegroundColor Red
    }
    elseif ($Icon -eq 'Warning') {
        Write-Warning $Message
    }
    else {
        Write-Host $Message
    }
}

function Get-DefaultPickerDirectory {
    foreach ($special in @('Desktop', 'MyDocuments')) {
        $path = [Environment]::GetFolderPath($special)
        if ($path -and (Test-Path -LiteralPath $path)) {
            return $path
        }
    }
    return (Get-Location).Path
}

function Show-OwnedDialog {
    param($Dialog)

    $owner = New-Object System.Windows.Forms.Form
    $owner.TopMost = $true
    $owner.ShowInTaskbar = $false
    $owner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
    $owner.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $owner.Width = 1
    $owner.Height = 1
    $owner.Opacity = 0
    [void]$owner.Show()
    try {
        return $Dialog.ShowDialog($owner)
    }
    finally {
        $owner.Close()
        $owner.Dispose()
    }
}

function Select-InputCsv {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = "Select CSV file containing SamAccountNames"
    $dialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $dialog.Multiselect = $false
    $dialog.CheckFileExists = $true
    $dialog.InitialDirectory = Get-DefaultPickerDirectory
    try {
        $result = Show-OwnedDialog -Dialog $dialog
        if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
            Write-Warning "No input file selected. Exiting."
            exit 0
        }
        return $dialog.FileName
    }
    finally {
        $dialog.Dispose()
    }
}

function Select-OutputCsv {
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Title = "Choose where to save the last logon report"
    $dialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $dialog.FileName = "LastLogonReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $dialog.DefaultExt = 'csv'
    $dialog.AddExtension = $true
    $dialog.OverwritePrompt = $true
    $dialog.InitialDirectory = Get-DefaultPickerDirectory
    try {
        $result = Show-OwnedDialog -Dialog $dialog
        if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
            Write-Warning "No output file selected. Exiting."
            exit 0
        }
        return $dialog.FileName
    }
    finally {
        $dialog.Dispose()
    }
}

function Get-SamAccountNameColumn {
    param(
        [Parameter(Mandatory)]
        [object[]]$Rows
    )

    if ($null -eq $Rows -or $Rows.Count -eq 0) {
        throw "The input CSV appears to be empty."
    }

    $columns = @($Rows[0].PSObject.Properties.Name)
    if ($columns.Count -eq 0) {
        throw "The input CSV has no columns."
    }

    $preferred = @(
        'SamAccountName',
        'sAMAccountName',
        'SAMAccountName',
        'SAM',
        'Username',
        'UserName',
        'User Name',
        'LogonName',
        'Login',
        'User'
    )

    foreach ($name in $preferred) {
        $hit = @($columns | Where-Object { $_ -eq $name })
        if ($hit.Count -ge 1) {
            return [string]$hit[0]
        }
    }

    $candidates = @($columns | Where-Object {
            $_ -match '^(sam ?account ?name|samaccountname|user ?name|user)$'
        })
    if ($candidates.Count -ge 1) {
        return [string]$candidates[0]
    }

    Write-Warning "Could not find a column named 'SamAccountName'. Falling back to the first column: '$($columns[0])'."
    return [string]$columns[0]
}

function Get-UniqueSamAccountNames {
    param(
        [Parameter(Mandatory)]
        [object[]]$Rows,

        [Parameter(Mandatory)]
        [string]$Column
    )

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $names = [System.Collections.Generic.List[string]]::new()

    foreach ($row in $Rows) {
        $raw = $row.$Column
        if ($null -eq $raw) { continue }
        $value = ([string]$raw).Trim()
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        if ($seen.Add($value)) {
            [void]$names.Add($value)
        }
    }

    return $names
}

function ConvertFrom-AdLogonTime {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [datetime]) {
        if ($Value.Year -lt 1602) { return $null }
        return [datetime]$Value
    }

    $ft = [int64]0
    if (-not [int64]::TryParse([string]$Value, [ref]$ft)) {
        return $null
    }
    if ($ft -le 0 -or $ft -eq [int64]::MaxValue) {
        return $null
    }

    try {
        $dt = [datetime]::FromFileTime($ft)
        if ($dt.Year -lt 1602) { return $null }
        return $dt
    }
    catch {
        return $null
    }
}

function Format-LogonDate {
    param($Value)

    $dt = ConvertFrom-AdLogonTime $Value
    if ($null -eq $dt) { return $null }
    return $dt.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-LatestDate {
    param($Left, $Right)

    $a = ConvertFrom-AdLogonTime $Left
    $b = ConvertFrom-AdLogonTime $Right
    if ($null -eq $a) { return $b }
    if ($null -eq $b) { return $a }
    if ($b -gt $a) { return $b }
    return $a
}

function Escape-LdapFilterValue {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    # RFC 4515: escape \, *, (, ), and NUL
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ([int][char]$ch) {
            92 { [void]$sb.Append('\5c') } # \
            42 { [void]$sb.Append('\2a') } # *
            40 { [void]$sb.Append('\28') } # (
            41 { [void]$sb.Append('\29') } # )
            0  { [void]$sb.Append('\00') }
            default { [void]$sb.Append($ch) }
        }
    }
    return $sb.ToString()
}

function Test-LdapReachable {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [int]$TimeoutMs = 3000,

        [int]$Port = 389
    )

    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return $false
        }
        $client.EndConnect($async)
        return [bool]$client.Connected
    }
    catch {
        return $false
    }
    finally {
        if ($null -ne $client) {
            try { $client.Close() } catch { }
        }
    }
}

function Get-AdUserBatch {
    param(
        [Parameter(Mandatory)]
        [string[]]$SamAccountNames,

        [Parameter(Mandatory)]
        [string[]]$Properties,

        [string]$Server,

        [int]$BatchSize = 50,

        [hashtable]$ErrorMap
    )

    $found = @{}
    if ($null -eq $SamAccountNames -or $SamAccountNames.Count -eq 0) {
        return $found
    }

    $total = $SamAccountNames.Count
    for ($i = 0; $i -lt $total; $i += $BatchSize) {
        $end = [Math]::Min($i + $BatchSize - 1, $total - 1)
        $chunk = @($SamAccountNames[$i..$end])

        $clauses = foreach ($sam in $chunk) {
            '(sAMAccountName={0})' -f (Escape-LdapFilterValue $sam)
        }
        $filter = '(|{0})' -f ($clauses -join '')

        $params = @{
            LDAPFilter  = $filter
            Properties  = $Properties
            ErrorAction = 'Stop'
        }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $params.Server = $Server
        }

        $users = $null
        try {
            $users = @(Get-ADUser @params)
        }
        catch {
            Write-Verbose "Batch lookup failed ($($chunk.Count) names); falling back to per-user. $($_.Exception.Message)"
            $users = New-Object System.Collections.Generic.List[object]
            foreach ($sam in $chunk) {
                try {
                    $oneParams = @{
                        LDAPFilter  = '(sAMAccountName={0})' -f (Escape-LdapFilterValue $sam)
                        Properties  = $Properties
                        ErrorAction = 'Stop'
                    }
                    if ($params.ContainsKey('Server')) { $oneParams.Server = $params.Server }
                    $one = @(Get-ADUser @oneParams)
                    foreach ($u in $one) { [void]$users.Add($u) }
                }
                catch {
                    Write-Verbose "Lookup failed for '$sam': $($_.Exception.Message)"
                    if ($null -ne $ErrorMap) {
                        $ErrorMap[$sam] = $_.Exception.Message
                    }
                }
            }
            $users = @($users)
        }

        foreach ($user in $users) {
            if ($null -eq $user) { continue }
            $found[$user.SamAccountName] = $user
        }
    }

    return $found
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Name)
    $ok = $false
    if ($null -eq $Expected -and $null -eq $Actual) {
        $ok = $true
    }
    elseif ($null -ne $Expected -and $null -ne $Actual -and $Expected -eq $Actual) {
        $ok = $true
    }
    if (-not $ok) {
        throw "SelfTest failed: $Name. Expected '$Expected', got '$Actual'."
    }
}

function Invoke-LastLogonSelfTest {
    Write-Host "Running Get-LastLogonReport self-tests..." -ForegroundColor Cyan

    Assert-Equal (ConvertFrom-AdLogonTime $null) $null 'null filetime'
    Assert-Equal (ConvertFrom-AdLogonTime 0) $null 'zero filetime'
    Assert-Equal (ConvertFrom-AdLogonTime ([int64]0)) $null 'int64 zero filetime'
    Assert-Equal (ConvertFrom-AdLogonTime ([int64]::MaxValue)) $null 'max filetime'
    Assert-Equal (ConvertFrom-AdLogonTime ([datetime]'1601-01-01')) $null 'epoch datetime'

    $sample = [datetime]::ParseExact('2020-01-15 12:00:00', 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    $roundTrip = ConvertFrom-AdLogonTime $sample.ToFileTime()
    Assert-Equal $roundTrip $sample 'filetime round-trip'

    $older = [datetime]::ParseExact('2019-01-01 00:00:00', 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    $latest = Get-LatestDate $sample $older
    Assert-Equal $latest $sample 'latest date wins'

    Assert-Equal (Format-LogonDate $sample) '2020-01-15 12:00:00' 'format local datetime'
    Assert-Equal (Format-LogonDate 0) $null 'format zero is blank'

    Assert-Equal (Escape-LdapFilterValue 'user') 'user' 'ldap plain'
    Assert-Equal (Escape-LdapFilterValue 'a*b(c)\d') 'a\2ab\28c\29\5cd' 'ldap specials'

    $named = @(
        [PSCustomObject]@{ DisplayName = 'Ann'; SamAccountName = 'ann' }
    )
    Assert-Equal (Get-SamAccountNameColumn -Rows $named) 'SamAccountName' 'prefer SamAccountName'

    $userCol = @(
        [PSCustomObject]@{ User = 'ann'; Department = 'IT' }
    )
    Assert-Equal (Get-SamAccountNameColumn -Rows $userCol) 'User' 'fallback User column'

    $dupes = @(
        [PSCustomObject]@{ SamAccountName = ' jdoe ' }
        [PSCustomObject]@{ SamAccountName = 'JDOE' }
        [PSCustomObject]@{ SamAccountName = '' }
        [PSCustomObject]@{ SamAccountName = 'alice' }
    )
    $unique = Get-UniqueSamAccountNames -Rows $dupes -Column 'SamAccountName'
    Assert-Equal $unique.Count 2 'case-insensitive unique count'
    Assert-Equal $unique[0] 'jdoe' 'trim first occurrence'
    Assert-Equal $unique[1] 'alice' 'second unique name'

    $one = Get-UniqueSamAccountNames -Rows @([PSCustomObject]@{ SamAccountName = 'solo' }) -Column 'SamAccountName'
    $chars = 0
    foreach ($n in $one) { $chars++ }
    Assert-Equal $chars 1 'single-item list does not enumerate characters'

    Write-Host "All self-tests passed." -ForegroundColor Green
}

#endregion

if ($SelfTest) {
    Invoke-LastLogonSelfTest
    exit 0
}

#region Setup ------------------------------------------------------------------

$script:WinFormsLoaded = $false
if ($script:UseGui) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $script:WinFormsLoaded = $true
    }
    catch {
        Write-Host "Failed to load System.Windows.Forms. Pass -InputCsv and -OutputCsv to run without a GUI. $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Show-UiMessage -Message "The ActiveDirectory PowerShell module is not installed.`r`nInstall RSAT: Active Directory Domain Services and LDS Tools, then re-run this script." -Title "Missing Prerequisite" -Icon Error
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    $null = Get-ADRootDSE -ErrorAction Stop
}
catch {
    Show-UiMessage -Message "Cannot contact Active Directory:`r`n$($_.Exception.Message)" -Title "Active Directory Error" -Icon Error
    exit 1
}

#endregion

#region Main -------------------------------------------------------------------

if ([string]::IsNullOrWhiteSpace($InputCsv)) {
    $InputCsv = Select-InputCsv
}
if (-not (Test-Path -LiteralPath $InputCsv -PathType Leaf)) {
    Show-UiMessage -Message "Input CSV not found:`r`n$InputCsv" -Title "Import Error" -Icon Error
    exit 1
}

if ([string]::IsNullOrWhiteSpace($OutputCsv)) {
    $OutputCsv = Select-OutputCsv
}

try {
    $imported = Import-Csv -LiteralPath $InputCsv
}
catch {
    Show-UiMessage -Message "Failed to read the CSV file:`r`n$($_.Exception.Message)" -Title "Import Error" -Icon Error
    exit 1
}

if ($null -eq $imported) {
    Show-UiMessage -Message "The input CSV appears to be empty." -Title "Import Error" -Icon Error
    exit 1
}

$csvRows = @($imported)
$samColumn = Get-SamAccountNameColumn -Rows $csvRows
$samAccountNames = Get-UniqueSamAccountNames -Rows $csvRows -Column $samColumn

$total = $samAccountNames.Count
if ($total -eq 0) {
    Show-UiMessage -Message "No SamAccountNames were found in column '$samColumn'." -Title "Nothing to process" -Icon Warning
    exit 0
}

Write-Host "Found $total unique SamAccountName(s) in column '$samColumn'." -ForegroundColor Cyan

$reachableDcs = New-Object 'System.Collections.Generic.List[string]'
$unreachableDcs = New-Object 'System.Collections.Generic.List[string]'

if ($AccurateLastLogon) {
    Write-Host "Accurate mode enabled: enumerating domain controllers..." -ForegroundColor Yellow
    try {
        $dcNames = @(
            Get-ADDomainController -Filter * -ErrorAction Stop |
                ForEach-Object {
                    if ($_.HostName) { $_.HostName } else { $_.Name }
                } |
                Where-Object { $_ }
        )
    }
    catch {
        Show-UiMessage -Message "Failed to enumerate domain controllers:`r`n$($_.Exception.Message)" -Title "Active Directory Error" -Icon Error
        exit 1
    }

    $dcIndex = 0
    foreach ($dc in $dcNames) {
        $dcIndex++
        Write-Progress -Activity "Checking domain controllers" -Status $dc -PercentComplete (($dcIndex / [Math]::Max($dcNames.Count, 1)) * 100)
        if (Test-LdapReachable -ComputerName $dc) {
            [void]$reachableDcs.Add($dc)
        }
        else {
            [void]$unreachableDcs.Add($dc)
            Write-Warning "DC unreachable on LDAP 389 (skipping): $dc"
        }
    }
    Write-Progress -Activity "Checking domain controllers" -Completed

    Write-Host ("Reachable DCs: {0}/{1}" -f $reachableDcs.Count, $dcNames.Count) -ForegroundColor Yellow
    if ($reachableDcs.Count -eq 0) {
        Write-Warning "No domain controllers accepted an LDAP connection. Accurate LastLogon will fall back to the replicated LastLogonDate."
    }
}

$userProperties = @('DisplayName', 'Enabled', 'LastLogonTimestamp', 'LastLogonDate', 'LastLogon', 'UserPrincipalName')

Write-Host "Querying Active Directory for user attributes..." -ForegroundColor Cyan
$lookupErrors = @{}
$adUsers = Get-AdUserBatch -SamAccountNames @($samAccountNames) -Properties $userProperties -ErrorMap $lookupErrors

$accurateBySam = @{}
if ($AccurateLastLogon -and $reachableDcs.Count -gt 0 -and $adUsers.Count -gt 0) {
    $foundSams = @($adUsers.Keys)
    $dcCounter = 0
    foreach ($dc in $reachableDcs) {
        $dcCounter++
        Write-Progress -Activity "Querying LastLogon on each DC" -Status "$dc ($dcCounter of $($reachableDcs.Count))" -PercentComplete (($dcCounter / $reachableDcs.Count) * 100)
        Write-Verbose "Querying LastLogon on $dc"
        $dcUsers = Get-AdUserBatch -SamAccountNames $foundSams -Properties @('LastLogon') -Server $dc
        foreach ($key in $dcUsers.Keys) {
            $logon = ConvertFrom-AdLogonTime $dcUsers[$key].LastLogon
            if ($null -eq $logon) { continue }
            $accurateBySam[$key] = Get-LatestDate $accurateBySam[$key] $logon
        }
    }
    Write-Progress -Activity "Querying LastLogon on each DC" -Completed
}

$results = New-Object 'System.Collections.Generic.List[object]'
$counter = 0

foreach ($sam in $samAccountNames) {
    $counter++
    Write-Progress -Activity "Building last logon report" -Status "$sam ($counter of $total)" -PercentComplete (($counter / $total) * 100)

    $row = [ordered]@{
        SamAccountName      = $sam
        DisplayName         = $null
        UserPrincipalName   = $null
        DistinguishedName   = $null
        Enabled             = $null
        LastLogonDate       = $null
        AccurateLastLogon   = $null
        DCsReached          = $null
        DCsUnreachable      = $null
        Status              = 'OK'
    }

    if ($adUsers.ContainsKey($sam)) {
        $user = $adUsers[$sam]
        $row.DisplayName       = $user.DisplayName
        $row.UserPrincipalName = $user.UserPrincipalName
        $row.DistinguishedName = $user.DistinguishedName
        $row.Enabled           = $user.Enabled
        $row.LastLogonDate     = Format-LogonDate $user.LastLogonDate

        if ($AccurateLastLogon) {
            $row.DCsReached     = $reachableDcs.Count
            $row.DCsUnreachable = $unreachableDcs.Count

            $fromDcs = $null
            if ($accurateBySam.ContainsKey($sam)) {
                $fromDcs = $accurateBySam[$sam]
            }
            $best = Get-LatestDate $user.LastLogonDate (Get-LatestDate $user.LastLogon $fromDcs)
            $row.AccurateLastLogon = Format-LogonDate $best

            if ($null -eq $row.LastLogonDate -and $null -eq $row.AccurateLastLogon) {
                $row.Status = 'OK (never logged on)'
            }
            elseif ($reachableDcs.Count -eq 0) {
                $row.Status = 'OK (no DC reachable; replicated timestamp only)'
            }
            elseif ($unreachableDcs.Count -gt 0) {
                $row.Status = "OK (partial: $($reachableDcs.Count)/$($reachableDcs.Count + $unreachableDcs.Count) DCs)"
            }
        }
        elseif ($null -eq $row.LastLogonDate) {
            $row.Status = 'OK (never logged on)'
        }
    }
    elseif ($lookupErrors.ContainsKey($sam)) {
        $row.Status = "Error: $($lookupErrors[$sam])"
        if ($AccurateLastLogon) {
            $row.DCsReached     = $reachableDcs.Count
            $row.DCsUnreachable = $unreachableDcs.Count
        }
    }
    else {
        $row.Status = 'NotFound'
        if ($AccurateLastLogon) {
            $row.DCsReached     = $reachableDcs.Count
            $row.DCsUnreachable = $unreachableDcs.Count
        }
    }

    [void]$results.Add([PSCustomObject]$row)
}

Write-Progress -Activity "Building last logon report" -Completed

$exportEncoding = 'UTF8'
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $exportEncoding = 'utf8BOM'
}

try {
    $results | Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Encoding $exportEncoding
}
catch {
    Show-UiMessage -Message "Failed to write the output CSV:`r`n$($_.Exception.Message)" -Title "Export Error" -Icon Error
    exit 1
}

$notFoundCount = ($results | Where-Object { $_.Status -eq 'NotFound' } | Measure-Object).Count
$errorCount    = ($results | Where-Object { $_.Status -like 'Error*' } | Measure-Object).Count
$foundCount    = $total - $notFoundCount - $errorCount

$summary = @"
Processed $total unique user(s).
Found: $foundCount
Not found: $notFoundCount
Errors: $errorCount
Saved to:
$OutputCsv
"@
if ($AccurateLastLogon) {
    $summary += "`r`nDCs reached: $($reachableDcs.Count); unreachable: $($unreachableDcs.Count)"
}

Write-Host $summary -ForegroundColor Green
Show-UiMessage -Message $summary -Title "Last Logon Report Complete" -Icon Information

#endregion

#Requires -Version 5.1
<#
.SYNOPSIS
    Interactively removes (and reverts) the logon script (scriptPath) attribute on
    Active Directory user accounts listed in a CSV file.

.DESCRIPTION
    All lookups and writes target the domain's PDC Emulator (auto-discovered
    via Get-ADDomain). That keeps remove, verify and later revert on the same
    writable DC so replication lag cannot hide a change.

    Menu-driven tool with four main operations:

      1. Remove logon scripts
         - Pick a CSV of users using a file picker (or type a path if the picker
           is unavailable).
         - Looks up every user, previews who currently has a logon script set.
         - Choose a Dry Run or a Live run.
         - For every user whose logon script is successfully cleared, a row is
           immediately appended to a BACKUP CSV (used for revert). A full
           in-memory copy is also rewritten at the end of the run.

      2. Revert logon scripts
         - Pick a BACKUP CSV created by option 1 (or a RemovalResults CSV).
         - Restore every user in the file, or a subset (typed names or a filter
           CSV). One user and many users use the same path.
         - Lets you decide how to handle users whose scriptPath was changed
           since the removal (skip, overwrite, or ask).
         - Each user is independent: one failure does not stop the rest.

      3. Open output folder

      4. Re-discover the PDC Emulator / change domain or credentials

    Every action, skip and failure is written to a timestamped log file.
    A results CSV with the status of every processed user is created per run.

    Output folder layout (default: <script folder>\LogonScriptCleanup):
        Logs\     LogonScript_<timestamp>.log
        Backups\  LogonScriptBackup_<timestamp>.csv     <- use this to revert
        Reports\  RemovalResults_<timestamp>.csv
                  RevertResults_<timestamp>.csv

    Identity values in the input CSV may be sAMAccountName, DOMAIN\user, UPN,
    distinguishedName, GUID or SID. Headers are auto-detected for every column
    and you choose which column to key on. Known names (SamAccountName,
    Username, UPN, Email, DN, GUID, ...) are recommended as the default;
    any other column can still be selected.

.PARAMETER OutputRoot
    Root folder for logs, backups and reports.

.PARAMETER SkipMain
    Load functions only; do not start the interactive menu. Used when
    dot-sourcing the script or running -SelfTest.

.PARAMETER SelfTest
    Run built-in unit tests for helper functions (no Active Directory needed)
    and exit with 0 on success or 1 on failure.

.NOTES
    Requirements:
      - Windows PowerShell 5.1
      - RSAT ActiveDirectory module
      - Permission to modify the scriptPath attribute on the target users
    Run from a normal PowerShell console (STA) so the file picker can be shown.

    Bugs fixed versus the original script:
      - Auto-discovered DC name was truncated to the first character because a
        [string] HostName was piped to Select-Object (strings enumerate as chars).
      - Add-Content -Encoding UTF8 in Windows PowerShell 5.1 wrote a BOM on
        every log line, corrupting the log.
      - A successful Set-ADUser followed by a failed backup write was recorded
        as Failed-Remove, so the change was live but missing from the revert file.
      - Set-ADUser could prompt because -Confirm:$false was not specified.
      - WinForms file picker crashed on Server Core / missing assemblies
        instead of falling back to a typed path.
      - File-picker owner form was never shown, so the dialog often opened
        behind the console.
      - Import-Csv used the system ANSI code page, breaking UTF-8 names.
      - Building column choices with 1..$columns.Count when Count is 0 produced
        1,0 (PowerShell range operator).
      - user@domain values were always reduced to the UPN prefix, which is not
        always equal to sAMAccountName.
      - Revert accessed optional backup columns under StrictMode and could throw.
      - Write-Progress was left on screen if a phase aborted.
      - Not-found errors wrapped by $ErrorActionPreference = Stop were not
        recognised as ADIdentityNotFoundException.
      - DC discovery did not require ADWS (needed by the AD module).
      - Discovery picked any writable DC instead of the PDC Emulator, so
        verify/revert could read a replica that had not yet received the write.

.EXAMPLE
    .\Manage-ADLogonScript.ps1

.EXAMPLE
    .\Manage-ADLogonScript.ps1 -OutputRoot 'D:\ADChanges\LogonScripts'

.EXAMPLE
    .\Manage-ADLogonScript.ps1 -SelfTest
#>
[CmdletBinding()]
param(
    [string]$OutputRoot,
    [switch]$SkipMain,
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Script-scoped state
# ---------------------------------------------------------------------------
$script:ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if (-not $OutputRoot) { $OutputRoot = Join-Path -Path $script:ScriptRoot -ChildPath 'LogonScriptCleanup' }
$script:OutputRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputRoot)

$script:SessionStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogFolder    = Join-Path $script:OutputRoot 'Logs'
$script:BackupFolder = Join-Path $script:OutputRoot 'Backups'
$script:ReportFolder = Join-Path $script:OutputRoot 'Reports'
$script:LogFile      = Join-Path $script:LogFolder ("LogonScript_{0}.log" -f $script:SessionStamp)
$script:ADParams     = @{}
$script:PdcEmulator  = $null
$script:DomainDnsRoot = $null
$script:Operator     = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
$script:Utf8NoBom    = New-Object System.Text.UTF8Encoding $false
$script:BackupSchemaVersion = '2'
$script:LargeSetWarningThreshold = 1000
$script:PreviewRowLimit = 100

$script:IdentityColumnAliases = @(
    'SamAccountName', 'sAMAccountName', 'SAMAccountName', 'SAM',
    'Username', 'UserName', 'User', 'Account', 'AccountName',
    'Login', 'LoginName', 'LogonName', 'Identity'
)
$script:WeakIdentityColumnAliases = @('Name', 'DisplayName')
$script:UpnColumnAliases = @('UserPrincipalName', 'UPN', 'Email', 'EmailAddress', 'Mail')
$script:DnColumnAliases  = @('DistinguishedName', 'DN')
$script:GuidColumnAliases = @('ObjectGUID', 'GUID', 'ObjectGuid')
$script:SidColumnAliases  = @('SID', 'objectSid', 'ObjectSID', 'ObjectSid', 'SecurityIdentifier')

# ---------------------------------------------------------------------------
# Small helpers (no Active Directory dependency)
# ---------------------------------------------------------------------------
function Get-FirstNonEmptyString {
    param($Value)

    if ($null -eq $Value) { return $null }

    # Never pipe a [string] to Select-Object / foreach: strings enumerate as
    # characters, which previously truncated a DC FQDN to its first letter.
    if ($Value -is [string]) {
        $text = $Value.Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        return $text
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($item in $Value) {
            $text = Get-FirstNonEmptyString -Value $item
            if ($null -ne $text) { return $text }
        }
        return $null
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text.Trim()
}

function Get-NotePropertyValue {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )

    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    return $prop.Value
}

function Test-ScriptPathEqual {
    param([string]$Left, [string]$Right)

    $a = if ($null -eq $Left)  { '' } else { $Left.Trim() }
    $b = if ($null -eq $Right) { '' } else { $Right.Trim() }
    return [string]::Equals($a, $b, [System.StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-EscapedAdFilterString {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    if ($null -eq $Value) { return '' }
    return $Value.Replace("'", "''")
}

function ConvertTo-ChoiceIndexList {
    param([Parameter(Mandatory)][int]$Count)

    # 1..0 in PowerShell is 1,0 — never use the range operator when Count < 1.
    # Unary comma prevents an empty array from unwrapping to $null on return.
    if ($Count -lt 1) { return , [string[]]@() }
    return , [string[]]@(1..$Count | ForEach-Object { "$_" })
}

function Get-PropertyNameIgnoreCase {
    param(
        [Parameter(Mandatory)][string[]]$Names,
        [Parameter(Mandatory)][string[]]$Candidates
    )

    foreach ($candidate in $Candidates) {
        $match = $Names | Where-Object { $_ -ieq $candidate } | Select-Object -First 1
        if ($match) { return [string]$match }
    }
    return $null
}

function Get-CsvColumnKind {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    if (Get-PropertyNameIgnoreCase -Names @($Name) -Candidates $script:IdentityColumnAliases) { return 'SAM' }
    if (Get-PropertyNameIgnoreCase -Names @($Name) -Candidates $script:GuidColumnAliases) { return 'GUID' }
    if (Get-PropertyNameIgnoreCase -Names @($Name) -Candidates $script:SidColumnAliases) { return 'SID' }
    if (Get-PropertyNameIgnoreCase -Names @($Name) -Candidates $script:UpnColumnAliases) { return 'UPN' }
    if (Get-PropertyNameIgnoreCase -Names @($Name) -Candidates $script:DnColumnAliases) { return 'DN' }
    if (Get-PropertyNameIgnoreCase -Names @($Name) -Candidates $script:WeakIdentityColumnAliases) { return 'Name' }

    if ($Name -match '(?i)samaccount|sam_account|^sam$') { return 'SAM' }
    if ($Name -match '(?i)objectguid|^guid$') { return 'GUID' }
    if ($Name -match '(?i)\bsid\b') { return 'SID' }
    if ($Name -match '(?i)userprincipal|^upn$|e-?mail') { return 'UPN' }
    if ($Name -match '(?i)distinguished|^dn$') { return 'DN' }
    if ($Name -match '(?i)user|login|account|logon') { return 'SAM' }
    return $null
}

function Get-RecommendedCsvIdentityColumn {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Columns)

    if ($null -eq $Columns -or $Columns.Count -eq 0) { return $null }

    $groups = @(
        $script:IdentityColumnAliases,
        $script:GuidColumnAliases,
        $script:SidColumnAliases,
        $script:UpnColumnAliases,
        $script:DnColumnAliases,
        $script:WeakIdentityColumnAliases
    )
    foreach ($group in $groups) {
        $match = Get-PropertyNameIgnoreCase -Names $Columns -Candidates $group
        if ($match) { return $match }
    }

    foreach ($column in $Columns) {
        if (Get-CsvColumnKind -Name $column) { return $column }
    }
    return $null
}

function Get-CsvColumnSample {
    param(
        [Parameter(Mandatory)]$Rows,
        [Parameter(Mandatory)][string]$Column,
        [int]$Take = 3
    )

    $values = New-Object System.Collections.Generic.List[string]
    foreach ($row in $Rows) {
        $value = [string](Get-NotePropertyValue -Object $row -Name $Column)
        if ($null -ne $value) { $value = $value.Trim() }
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        if ($values.Count -ge $Take) { break }
        $values.Add($value)
    }
    return ($values -join ', ')
}

function Select-CsvIdentityColumn {
    param(
        [Parameter(Mandatory)][string[]]$Columns,
        [Parameter(Mandatory)]$Rows,
        [switch]$AutoSelect
    )

    $recommended = Get-RecommendedCsvIdentityColumn -Columns $Columns
    $recommendedIndex = $null
    if ($recommended) {
        for ($i = 0; $i -lt $Columns.Count; $i++) {
            if ($Columns[$i] -ieq $recommended) {
                $recommendedIndex = '{0}' -f ($i + 1)
                $recommended = $Columns[$i]
                break
            }
        }
    }

    if ($AutoSelect) {
        $column = $recommended
        if (-not $column -and $Columns.Count -ge 1) { $column = $Columns[0] }
        return [pscustomobject]@{
            Cancelled  = $false
            Headerless = $false
            Column     = $column
        }
    }

    Write-Host ''
    Write-Host '  Detected CSV headers (choose the column to key on):' -ForegroundColor Cyan
    for ($i = 0; $i -lt $Columns.Count; $i++) {
        $name    = $Columns[$i]
        $kind    = Get-CsvColumnKind -Name $name
        $sample  = Get-CsvColumnSample -Rows $Rows -Column $name
        $kindText = if ($kind) { ' [{0}]' -f $kind } else { '' }
        $marker  = if ($recommended -and $name -ieq $recommended) { '  <- recommended' } else { '' }
        Write-Host ("    [{0}] {1}{2}{3}" -f ($i + 1), $name, $kindText, $marker)
        if ($sample) {
            Write-Host ("         sample: {0}" -f $sample) -ForegroundColor DarkGray
        }
    }
    Write-Host '    [H] File has NO header row (first column is the user identity)'
    Write-Host '    [C] Cancel'

    $valid  = @('H', 'C') + (ConvertTo-ChoiceIndexList -Count $Columns.Count)
    $prompt = '  Select the column to key on'
    if ($recommendedIndex) {
        $prompt = '{0} [Enter = {1}, {2}]' -f $prompt, $recommendedIndex, $recommended
    }

    $choice = Read-Choice -Prompt $prompt -ValidChoices $valid -Default $recommendedIndex
    switch ($choice) {
        'C' {
            return [pscustomobject]@{ Cancelled = $true; Headerless = $false; Column = $null }
        }
        'H' {
            return [pscustomobject]@{ Cancelled = $false; Headerless = $true; Column = 'SamAccountName' }
        }
        default {
            return [pscustomobject]@{
                Cancelled  = $false
                Headerless = $false
                Column     = $Columns[[int]$choice - 1]
            }
        }
    }
}

function ConvertTo-IdentityTokenList {
    param([AllowEmptyString()][string]$RawText)

    if ([string]::IsNullOrWhiteSpace($RawText)) { return , [string[]]@() }

    $normalized = $RawText.Replace("`r`n", "`n").Replace("`r", "`n")
    $parts = @($normalized -split "[;`n]+" | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    $hasDn = $false
    foreach ($part in $parts) {
        if ((ConvertTo-AdUserIdentity -Value $part).Kind -eq 'DN') { $hasDn = $true; break }
    }

    # "jsmith, ajones" is a list of SAMs. A distinguishedName also contains
    # commas, so only split on comma when no DN token is present.
    if (-not $hasDn -and $parts.Count -eq 1 -and $parts[0] -match ',') {
        $parts = @($parts[0] -split ',' | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    return , [string[]]@($parts)
}

function ConvertTo-AdUserIdentity {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $raw = if ($null -eq $Value) { '' } else { $Value.Trim().Trim('"') }
    $result = [ordered]@{
        InputValue         = $raw
        Kind               = 'Unknown'
        SamAccountName     = $null
        UserPrincipalName  = $null
        DistinguishedName  = $null
        ObjectGUID         = $null
        SID                = $null
    }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        $result.Kind = 'Empty'
        return [pscustomobject]$result
    }

    $guid = [guid]::Empty
    if ([guid]::TryParse($raw, [ref]$guid)) {
        $result.Kind = 'GUID'
        $result.ObjectGUID = $guid
        return [pscustomobject]$result
    }

    if ($raw -match '^S-\d-\d+(-\d+)+$') {
        $result.Kind = 'SID'
        $result.SID = $raw
        return [pscustomobject]$result
    }

    if ($raw -match '^[A-Za-z]{1,3}=.+,.+=') {
        $result.Kind = 'DN'
        $result.DistinguishedName = $raw
        return [pscustomobject]$result
    }

    if ($raw -match '^[^\\/]+\\[^\\/]+$') {
        $result.Kind = 'NT4'
        $result.SamAccountName = $raw.Split('\')[-1]
        return [pscustomobject]$result
    }

    if ($raw -match '^[^@\s]+@[^@\s]+$') {
        $result.Kind = 'UPN'
        $result.UserPrincipalName = $raw
        $result.SamAccountName = $raw.Split('@')[0]
        return [pscustomobject]$result
    }

    $result.Kind = 'SAM'
    $result.SamAccountName = $raw
    return [pscustomobject]$result
}

function Test-ErrorRecordMatch {
    param(
        $ErrorRecord,
        [string[]]$TypePatterns,
        [string[]]$MessagePatterns,
        [string[]]$FullyQualifiedIdPatterns = @()
    )

    $messages = New-Object System.Collections.Generic.List[string]
    $types    = New-Object System.Collections.Generic.List[string]

    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $ex = $ErrorRecord.Exception
        $messages.Add([string]$ErrorRecord.Exception.Message)
        $types.Add($ErrorRecord.Exception.GetType().FullName)
        $fqid = [string]$ErrorRecord.FullyQualifiedErrorId
        foreach ($pattern in $FullyQualifiedIdPatterns) {
            if ($fqid -match $pattern) { return $true }
        }
        if ($ErrorRecord.CategoryInfo -and $ErrorRecord.CategoryInfo.Category -eq 'ObjectNotFound') {
            if ($TypePatterns -contains 'ObjectNotFound') { return $true }
        }
    }
    else {
        $ex = $ErrorRecord
    }

    while ($null -ne $ex) {
        $types.Add($ex.GetType().FullName)
        $messages.Add([string]$ex.Message)
        $ex = $ex.InnerException
    }

    foreach ($typeName in $types) {
        foreach ($pattern in $TypePatterns) {
            if ($pattern -and $typeName -match $pattern) { return $true }
        }
    }
    foreach ($message in $messages) {
        foreach ($pattern in $MessagePatterns) {
            if ($pattern -and $message -match $pattern) { return $true }
        }
    }
    return $false
}

function Test-IsIdentityNotFound {
    param($ErrorRecord)

    return Test-ErrorRecordMatch -ErrorRecord $ErrorRecord `
        -TypePatterns @('ADIdentityNotFound', 'ADIdentityResolution', 'ItemNotFound', 'ObjectNotFound') `
        -MessagePatterns @(
            'Cannot find an object with identity',
            'cannot be found',
            'was not found',
            'There is no such object'
        ) `
        -FullyQualifiedIdPatterns @('ADIdentityNotFound', 'IdentityNotFound')
}

function Test-IsTransientAdError {
    param($ErrorRecord)

    return Test-ErrorRecordMatch -ErrorRecord $ErrorRecord `
        -TypePatterns @('Timeout', 'ADServerDown', 'Busy', 'Unavailable') `
        -MessagePatterns @(
            'timeout',
            'timed out',
            'The server is not operational',
            'server down',
            'is busy',
            'unavailable',
            'RPC server',
            'The RPC',
            'network path',
            'connection',
            'try again',
            'directory service',
            '0x8007203a',
            '0x8007200e',
            'The server is unwilling'
        ) `
        -FullyQualifiedIdPatterns @('Timeout', 'ServerDown')
}

function Get-FileTextEncodingName {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $bom = New-Object byte[] 3
        $read = $stream.Read($bom, 0, 3)
        if ($read -ge 3 -and $bom[0] -eq 0xEF -and $bom[1] -eq 0xBB -and $bom[2] -eq 0xBF) { return 'UTF8' }
        if ($read -ge 2 -and $bom[0] -eq 0xFF -and $bom[1] -eq 0xFE) { return 'Unicode' }
        if ($read -ge 2 -and $bom[0] -eq 0xFE -and $bom[1] -eq 0xFF) { return 'BigEndianUnicode' }
    }
    finally {
        $stream.Dispose()
    }
    return 'UTF8'
}

function Get-CsvDelimiterFromPath {
    param([Parameter(Mandatory)][string]$Path)

    $encodingName = Get-FileTextEncodingName -Path $Path
    $firstLine = Get-Content -LiteralPath $Path -Encoding $encodingName -TotalCount 1
    if ([string]::IsNullOrWhiteSpace($firstLine)) { return ',' }

    $comma = ([regex]::Matches($firstLine, ',')).Count
    $semi  = ([regex]::Matches($firstLine, ';')).Count
    $tab   = ([regex]::Matches($firstLine, "`t")).Count

    if ($semi -gt $comma -and $semi -gt $tab) { return ';' }
    if ($tab -gt $comma -and $tab -gt $semi) { return "`t" }
    return ','
}

function Import-CsvSafe {
    param([Parameter(Mandatory)][string]$Path)

    $encodingName = Get-FileTextEncodingName -Path $Path
    $delimiter    = Get-CsvDelimiterFromPath -Path $Path
    $raw = Import-Csv -LiteralPath $Path -Encoding $encodingName -Delimiter $delimiter
    # Import-Csv returns $null for a header-only file. @( $null ) would become
    # a one-element array and later blow up under StrictMode.
    if ($null -eq $raw) { return , [object[]]@() }
    return , @($raw)
}

function Resolve-ExistingFilePath {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $clean = $Path.Trim().Trim('"')
    $clean = [Environment]::ExpandEnvironmentVariables($clean)
    if ([string]::IsNullOrWhiteSpace($clean)) { return $null }

    if (-not [System.IO.Path]::IsPathRooted($clean)) {
        $clean = Join-Path -Path (Get-Location).Path -ChildPath $clean
    }

    try {
        $full = [System.IO.Path]::GetFullPath($clean)
    }
    catch {
        return $null
    }

    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return $null }
    return $full
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'DRYRUN')][string]$Level = 'INFO',
        [switch]$NoConsole
    )

    $line = '{0} [{1,-7}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    try {
        $folder = Split-Path -Parent $script:LogFile
        if ($folder -and -not (Test-Path -LiteralPath $folder)) {
            New-Item -Path $folder -ItemType Directory -Force | Out-Null
        }
        # File.AppendAllText with UTF8Encoding(false) avoids the PS 5.1
        # Add-Content -Encoding UTF8 behaviour of writing a BOM on every call.
        [System.IO.File]::AppendAllText($script:LogFile, $line + [Environment]::NewLine, $script:Utf8NoBom)
    }
    catch {
        Write-Host "Unable to write to log file '$($script:LogFile)': $($_.Exception.Message)" -ForegroundColor Red
    }

    if (-not $NoConsole) {
        $color = switch ($Level) {
            'INFO'    { 'Gray' }
            'WARN'    { 'Yellow' }
            'ERROR'   { 'Red' }
            'SUCCESS' { 'Green' }
            'DRYRUN'  { 'Cyan' }
            default   { 'Gray' }
        }
        Write-Host $line -ForegroundColor $color
    }
}

function Complete-Progress {
    param([string]$Activity)
    try { Write-Progress -Activity $Activity -Completed } catch { }
}

# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
function Write-Header {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
    Write-Host ("  {0}" -f $Text) -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
}

function Read-YesNo {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [bool]$Default = $false
    )
    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = (Read-Host "$Prompt $suffix").Trim()
        if ([string]::IsNullOrEmpty($answer)) { return $Default }
        switch -Regex ($answer) {
            '^(y|yes)$' { return $true }
            '^(n|no)$'  { return $false }
            default     { Write-Host '  Please answer Y or N.' -ForegroundColor Yellow }
        }
    }
}

function Read-Choice {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string[]]$ValidChoices,
        [string]$Default
    )
    if ($Default) { $Default = $Default.Trim().ToUpper() }
    while ($true) {
        $answer = (Read-Host $Prompt).Trim().ToUpper()
        if ([string]::IsNullOrEmpty($answer) -and $Default -and ($ValidChoices -contains $Default)) {
            return $Default
        }
        if ($ValidChoices -contains $answer) { return $answer }
        $hint = $ValidChoices -join ', '
        if ($Default) { $hint = '{0} (Enter = {1})' -f $hint, $Default }
        Write-Host ("  Invalid choice. Valid options: {0}" -f $hint) -ForegroundColor Yellow
    }
}

function Show-ObjectPreview {
    param(
        $Items,
        [string[]]$Properties,
        [int]$MaxRows = 100
    )

    $arr = @($Items)
    if ($arr.Count -eq 0) { return }

    $arr | Select-Object -First $MaxRows -Property $Properties | Format-Table -AutoSize | Out-Host
    if ($arr.Count -gt $MaxRows) {
        Write-Host ("  ... and {0} more (see the report/log for the full list)." -f ($arr.Count - $MaxRows)) -ForegroundColor Yellow
    }
}

function Select-CsvFile {
    param(
        [Parameter(Mandatory)][string]$Title,
        [string]$InitialDirectory
    )

    $useDialog = $true
    $isSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
    if (-not $isSta) {
        Write-Log 'PowerShell is not running in STA mode; falling back to manual path entry.' -Level WARN
        $useDialog = $false
    }

    if ($useDialog) {
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
            Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        }
        catch {
            Write-Log "Windows Forms is unavailable ($($_.Exception.Message)); falling back to manual path entry." -Level WARN
            $useDialog = $false
        }
    }

    if ($useDialog) {
        $dialog = $null
        $owner  = $null
        $selectedPath = $null
        try {
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.Title            = $Title
            $dialog.Filter           = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
            $dialog.Multiselect      = $false
            $dialog.CheckFileExists  = $true
            $dialog.RestoreDirectory = $true
            if ($InitialDirectory -and (Test-Path -LiteralPath $InitialDirectory)) {
                $dialog.InitialDirectory = $InitialDirectory
            }

            # Show an off-screen TopMost owner so the dialog cannot open behind
            # the console. Creating the form without Show() does not work.
            $owner = New-Object System.Windows.Forms.Form
            $owner.Text            = $Title
            $owner.ShowInTaskbar   = $false
            $owner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
            $owner.StartPosition   = [System.Windows.Forms.FormStartPosition]::Manual
            $owner.Location        = New-Object System.Drawing.Point(-32000, -32000)
            $owner.Size            = New-Object System.Drawing.Size(1, 1)
            $owner.TopMost         = $true
            $owner.Show() | Out-Null
            $owner.TopMost = $true

            if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
                $selectedPath = $dialog.FileName
            }
        }
        catch {
            Write-Log "File picker failed ($($_.Exception.Message)); falling back to manual path entry." -Level WARN
            $selectedPath = $null
            $useDialog = $false
        }
        finally {
            if ($owner)  { $owner.Dispose() }
            if ($dialog) { $dialog.Dispose() }
        }

        if ($selectedPath) {
            $resolved = Resolve-ExistingFilePath -Path $selectedPath
            if ($resolved) { return $resolved }
            Write-Log "Selected path is not a readable file: $selectedPath" -Level WARN
        }
        elseif ($useDialog) {
            return $null
        }
    }

    $manual = (Read-Host "$Title - enter full path to CSV (blank to cancel)").Trim()
    if ([string]::IsNullOrWhiteSpace($manual)) { return $null }

    $resolvedManual = Resolve-ExistingFilePath -Path $manual
    if (-not $resolvedManual) {
        Write-Log "Path is not a readable file: $manual" -Level ERROR
        return $null
    }
    return $resolvedManual
}

# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------
function Initialize-Environment {
    foreach ($folder in @($script:LogFolder, $script:BackupFolder, $script:ReportFolder)) {
        if (-not (Test-Path -LiteralPath $folder)) {
            New-Item -Path $folder -ItemType Directory -Force | Out-Null
        }
    }

    Write-Log ('=' * 60) -NoConsole
    Write-Log "Session started by $($script:Operator) on $env:COMPUTERNAME" -Level INFO
    Write-Log "Log file: $($script:LogFile)" -Level INFO
    Write-Log "Output root: $($script:OutputRoot)" -Level INFO
    Write-Log ("PowerShell {0} ({1}), apartment {2}" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition, [System.Threading.Thread]::CurrentThread.GetApartmentState()) -Level INFO -NoConsole

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log 'ActiveDirectory module loaded.' -Level INFO
    }
    catch {
        Write-Log "Failed to load ActiveDirectory module (install RSAT): $($_.Exception.Message)" -Level ERROR
        throw
    }
}

function Invoke-ADOperation {
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 3,
        [string]$OperationName = 'AD operation'
    )

    $delaySeconds = 1
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $ScriptBlock
        }
        catch {
            $isTransient = Test-IsTransientAdError -ErrorRecord $_
            if (-not $isTransient -or $attempt -eq $MaxAttempts) { throw }
            Write-Log ("{0} failed (attempt {1}/{2}): {3} Retrying in {4}s." -f $OperationName, $attempt, $MaxAttempts, $_.Exception.Message, $delaySeconds) -Level WARN
            Start-Sleep -Seconds $delaySeconds
            $delaySeconds = [Math]::Min($delaySeconds * 2, 8)
        }
    }
}

function Get-AdConnectionSplat {
    $params = @{}
    if ($script:ADParams -and $script:ADParams.ContainsKey('Credential') -and $script:ADParams['Credential']) {
        $params['Credential'] = $script:ADParams['Credential']
    }
    return $params
}

function Resolve-PdcEmulator {
    param([string]$Hint)

    $base = Get-AdConnectionSplat

    $domain = Invoke-ADOperation -OperationName 'Get-ADDomain (locate PDC)' -ScriptBlock {
        if ($Hint) {
            try {
                return Get-ADDomain -Identity $Hint @base -ErrorAction Stop
            }
            catch {
                return Get-ADDomain -Server $Hint @base -ErrorAction Stop
            }
        }
        return Get-ADDomain @base -ErrorAction Stop
    }

    $pdc = Get-FirstNonEmptyString -Value (Get-NotePropertyValue -Object $domain -Name 'PDCEmulator')
    if (-not $pdc) {
        throw 'Get-ADDomain returned no PDCEmulator. Cannot continue.'
    }

    $verifyParams = Get-AdConnectionSplat
    $verifyParams['Server'] = $pdc

    $domainOnPdc = Invoke-ADOperation -OperationName ("Get-ADDomain via PDC {0}" -f $pdc) -ScriptBlock {
        Get-ADDomain @verifyParams -ErrorAction Stop
    }

    $confirmedPdc = Get-FirstNonEmptyString -Value (Get-NotePropertyValue -Object $domainOnPdc -Name 'PDCEmulator')
    if ($confirmedPdc -and -not (Test-ScriptPathEqual -Left $pdc -Right $confirmedPdc)) {
        Write-Log "PDC Emulator role is now '$confirmedPdc' (locator returned '$pdc'). Switching to the current PDC." -Level WARN
        $pdc = $confirmedPdc
        $verifyParams['Server'] = $pdc
        $domainOnPdc = Invoke-ADOperation -OperationName ("Get-ADDomain via current PDC {0}" -f $pdc) -ScriptBlock {
            Get-ADDomain @verifyParams -ErrorAction Stop
        }
    }

    try {
        $dc = Get-ADDomainController -Identity $pdc @verifyParams -ErrorAction Stop
        $roles = @($dc.OperationMasterRoles | ForEach-Object { $_.ToString() })
        if ($roles -notcontains 'PDCEmulator') {
            Write-Log ("WARNING: {0} does not currently list PDCEmulator in OperationMasterRoles ({1})." -f $pdc, ($roles -join ', ')) -Level WARN
        }
    }
    catch {
        Write-Log "Could not verify OperationMasterRoles on '$pdc': $($_.Exception.Message)" -Level WARN
    }

    return [pscustomobject]@{
        Server      = $pdc
        Domain      = [string](Get-NotePropertyValue -Object $domainOnPdc -Name 'DNSRoot')
        NetBIOSName = [string](Get-NotePropertyValue -Object $domainOnPdc -Name 'NetBIOSName')
    }
}

function Set-AdPdcTarget {
    param($PdcInfo)

    $script:PdcEmulator   = $PdcInfo.Server
    $script:DomainDnsRoot = $PdcInfo.Domain
    $script:ADParams['Server'] = $PdcInfo.Server
}

function Confirm-ConnectedPdc {
    try {
        $info = Resolve-PdcEmulator
        $current = [string]$script:ADParams['Server']
        if ($current -and -not (Test-ScriptPathEqual -Left $current -Right $info.Server)) {
            Write-Log "PDC Emulator changed from '$current' to '$($info.Server)'. All further changes will use the current PDC." -Level WARN
        }
        Set-AdPdcTarget -PdcInfo $info
        Write-Log "Using PDC Emulator '$($info.Server)' for domain '$($info.Domain)'." -Level INFO
        return $true
    }
    catch {
        $fallback = [string]$script:ADParams['Server']
        if ($fallback) {
            Write-Log "Could not re-confirm the PDC Emulator: $($_.Exception.Message). Continuing with '$fallback'." -Level WARN
            return $false
        }
        throw
    }
}

function Initialize-ADConnection {
    param([switch]$AllowHint)

    Write-Header 'Active Directory connection'
    Write-Host '  All changes will be made on the domain PDC Emulator.' -ForegroundColor Gray

    $connected = $false
    while (-not $connected) {
        $hint = $null
        if ($AllowHint) {
            $hint = (Read-Host '  Press Enter for the current domain, or type a domain / DC name').Trim()
            if ([string]::IsNullOrWhiteSpace($hint)) { $hint = $null }
        }

        if (Read-YesNo -Prompt '  Use alternate credentials?' -Default $false) {
            $cred = Get-Credential -Message 'Enter credentials with rights to modify AD user accounts'
            if ($cred) {
                $script:ADParams = @{ Credential = $cred }
                Write-Log "Using alternate credentials: $($cred.UserName)" -Level INFO
            }
            else {
                $script:ADParams = @{}
                Write-Log 'Credential prompt cancelled; connecting with the current security context.' -Level WARN
            }
        }
        else {
            $existingCred = $null
            if ($script:ADParams -and $script:ADParams.ContainsKey('Credential')) {
                $existingCred = $script:ADParams['Credential']
            }
            $script:ADParams = @{}
            if ($existingCred) { $script:ADParams['Credential'] = $existingCred }
        }

        try {
            Write-Host '  Locating the PDC Emulator...' -ForegroundColor Gray
            $info = Resolve-PdcEmulator -Hint $hint
            Set-AdPdcTarget -PdcInfo $info
            Write-Host "  Domain       : $($info.Domain)" -ForegroundColor Gray
            Write-Host "  PDC Emulator : $($info.Server)" -ForegroundColor Green
            Write-Log "Connected to domain '$($info.Domain)' via PDC Emulator '$($info.Server)'." -Level SUCCESS
            $connected = $true
        }
        catch {
            Write-Log "Unable to locate or reach the PDC Emulator: $($_.Exception.Message)" -Level ERROR
            if (-not (Read-YesNo -Prompt '  Try again (different domain or credentials)?' -Default $true)) {
                throw
            }
            $AllowHint = $true
        }
    }
}

# ---------------------------------------------------------------------------
# CSV input
# ---------------------------------------------------------------------------
function Get-UserListFromCsv {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AutoSelect
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Log "Input file not found: $Path" -Level ERROR
        return , [string[]]@()
    }

    try {
        $rows = Import-CsvSafe -Path $Path
    }
    catch {
        Write-Log "Failed to read CSV '$Path': $($_.Exception.Message)" -Level ERROR
        return , [string[]]@()
    }

    if ($rows.Count -eq 0) {
        Write-Log "Input file is empty: $Path" -Level ERROR
        return , [string[]]@()
    }

    $columns = @($rows[0].PSObject.Properties.Name)
    $selection = Select-CsvIdentityColumn -Columns $columns -Rows $rows -AutoSelect:$AutoSelect

    if ($selection.Cancelled) {
        Write-Log 'User cancelled column selection.' -Level WARN
        return , [string[]]@()
    }

    $column = $selection.Column
    if ($selection.Headerless) {
        $encodingName = Get-FileTextEncodingName -Path $Path
        $delimiter    = Get-CsvDelimiterFromPath -Path $Path
        $raw = Import-Csv -LiteralPath $Path -Header 'SamAccountName' -Encoding $encodingName -Delimiter $delimiter
        if ($null -eq $raw) { return , [string[]]@() }
        $rows = @($raw)
        $column = 'SamAccountName'
        Write-Log 'Treating the file as headerless; first column is the user identity.' -Level INFO
    }

    if (-not $column) {
        Write-Log 'No identity column was selected.' -Level ERROR
        return , [string[]]@()
    }

    $kind = Get-CsvColumnKind -Name $column
    if ($kind) {
        Write-Log "Using column '$column' ($kind) as the user identity." -Level INFO
    }
    else {
        Write-Log "Using column '$column' as the user identity (unrecognised header; values will still be resolved as SAM/UPN/DN/GUID/SID)." -Level WARN
    }

    $seen  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $users = New-Object System.Collections.Generic.List[string]
    $blank = 0
    $dupes = 0

    foreach ($row in $rows) {
        $value = [string](Get-NotePropertyValue -Object $row -Name $column)
        if ($null -ne $value) { $value = $value.Trim() }

        if ([string]::IsNullOrWhiteSpace($value)) { $blank++; continue }

        if ($seen.Add($value)) { $users.Add($value) } else { $dupes++ }
    }

    if ($blank -gt 0) { Write-Log "Skipped $blank blank row(s) in input file." -Level WARN }
    if ($dupes -gt 0) { Write-Log "Skipped $dupes duplicate entr(ies) in input file." -Level WARN }
    Write-Log "Loaded $($users.Count) unique user(s) from '$Path'." -Level INFO

    return , [string[]]$users.ToArray()
}

# ---------------------------------------------------------------------------
# AD user lookup
# ---------------------------------------------------------------------------
function Get-AdUserSafe {
    param(
        [Parameter(Mandatory)][string]$InputValue,
        [string]$ObjectGUID,
        [string]$SID,
        [string]$DistinguishedName
    )

    $properties = @(
        'scriptPath', 'ObjectGUID', 'DisplayName', 'Enabled',
        'UserPrincipalName', 'objectSid', 'DistinguishedName', 'SamAccountName'
    )

    $attempts = New-Object System.Collections.Generic.List[object]
    $seen     = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    $addAttempt = {
        param($Type, $Identity, $Filter)
        $key = '{0}|{1}|{2}' -f $Type, $Identity, $Filter
        if ($seen.Add($key)) {
            $attempts.Add([pscustomobject]@{ Type = $Type; Identity = $Identity; Filter = $Filter })
        }
    }

    $parsedGuid = [guid]::Empty
    if ($ObjectGUID -and [guid]::TryParse($ObjectGUID, [ref]$parsedGuid)) {
        & $addAttempt 'GUID' $parsedGuid $null
    }
    if ($SID) { & $addAttempt 'SID' $SID $null }
    if ($DistinguishedName) { & $addAttempt 'DN' $DistinguishedName $null }

    $parsed = ConvertTo-AdUserIdentity -Value $InputValue
    switch ($parsed.Kind) {
        'GUID' {
            & $addAttempt 'GUID' $parsed.ObjectGUID $null
        }
        'SID' {
            & $addAttempt 'SID' $parsed.SID $null
        }
        'DN' {
            & $addAttempt 'DN' $parsed.DistinguishedName $null
        }
        'UPN' {
            $escaped = ConvertTo-EscapedAdFilterString -Value $parsed.UserPrincipalName
            & $addAttempt 'UPN' $null ("UserPrincipalName -eq '{0}'" -f $escaped)
            if ($parsed.SamAccountName) { & $addAttempt 'SAM' $parsed.SamAccountName $null }
        }
        'NT4' {
            if ($parsed.SamAccountName) { & $addAttempt 'SAM' $parsed.SamAccountName $null }
        }
        default {
            if ($parsed.SamAccountName) { & $addAttempt 'SAM' $parsed.SamAccountName $null }
            & $addAttempt 'Identity' $InputValue $null
        }
    }

    $lastNotFound = $null
    foreach ($attempt in $attempts) {
        try {
            $user = Invoke-ADOperation -OperationName ("Get-ADUser [{0}] {1}" -f $attempt.Type, $InputValue) -ScriptBlock {
                if ($attempt.Filter) {
                    $found = @(Get-ADUser -Filter $attempt.Filter -Properties $properties @script:ADParams)
                    if ($found.Count -eq 0) {
                        throw (New-Object System.Management.Automation.ItemNotFoundException ("No user matched filter for '{0}'." -f $InputValue))
                    }
                    if ($found.Count -gt 1) {
                        throw ("Multiple users matched {0} '{1}'." -f $attempt.Type, $InputValue)
                    }
                    return $found[0]
                }
                return Get-ADUser -Identity $attempt.Identity -Properties $properties @script:ADParams -ErrorAction Stop
            }
            if ($parsed.Kind -eq 'UPN' -and $attempt.Type -eq 'SAM') {
                $userUpn = [string](Get-NotePropertyValue -Object $user -Name 'UserPrincipalName')
                if (-not (Test-ScriptPathEqual -Left $userUpn -Right $parsed.UserPrincipalName)) {
                    Write-Log "[$InputValue] sAMAccountName '$($user.SamAccountName)' is not the same account as UPN '$($parsed.UserPrincipalName)'. Continuing search." -Level WARN -NoConsole
                    continue
                }
                Write-Log "[$InputValue] UPN lookup missed; accepted sAMAccountName '$($user.SamAccountName)' because its UPN matches." -Level INFO
            }
            return $user
        }
        catch {
            if (Test-IsIdentityNotFound -ErrorRecord $_) {
                $lastNotFound = $_
                continue
            }
            throw
        }
    }

    if ($lastNotFound) { throw $lastNotFound }
    throw (New-Object System.Management.Automation.ItemNotFoundException ("User not found: {0}" -f $InputValue))
}

function New-ResultRow {
    param(
        [string]$SamAccountName = '',
        [string]$InputIdentity = '',
        [string]$DistinguishedName = '',
        [string]$ObjectGUID = '',
        [string]$Enabled = '',
        [string]$OriginalScriptPath = '',
        [string]$CurrentScriptPath = '',
        [string]$Status,
        [string]$Details = ''
    )

    [pscustomobject]@{
        SamAccountName     = $SamAccountName
        InputIdentity      = $InputIdentity
        DistinguishedName  = $DistinguishedName
        ObjectGUID         = $ObjectGUID
        Enabled            = $Enabled
        OriginalScriptPath = $OriginalScriptPath
        CurrentScriptPath  = $CurrentScriptPath
        Status             = $Status
        Details            = $Details
    }
}

function New-BackupRow {
    param(
        $User,
        [string]$OriginalScriptPath,
        [string]$InputIdentity,
        [string]$SourceFile
    )

    [pscustomobject]@{
        SchemaVersion      = $script:BackupSchemaVersion
        SamAccountName     = $User.SamAccountName
        UserPrincipalName  = [string](Get-NotePropertyValue -Object $User -Name 'UserPrincipalName')
        DistinguishedName  = $User.DistinguishedName
        ObjectGUID         = $User.ObjectGUID.ToString()
        SID                = [string](Get-NotePropertyValue -Object $User -Name 'SID')
        OriginalScriptPath = $OriginalScriptPath
        RemovedOn          = (Get-Date).ToString('o')
        RemovedBy          = $script:Operator
        DomainController   = [string]$script:ADParams['Server']
        SourceFile         = $SourceFile
        InputIdentity      = $InputIdentity
    }
}

function Add-BackupRow {
    param(
        [Parameter(Mandatory)]$Row,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$BackupRows
    )

    [void]$BackupRows.Add($Row)

    $maxAttempts = 5
    for ($i = 1; $i -le $maxAttempts; $i++) {
        try {
            $Row | Export-Csv -LiteralPath $Path -NoTypeInformation -Append -Encoding UTF8
            return $true
        }
        catch {
            if ($i -eq $maxAttempts) {
                Write-Log "Failed to append backup row for $($Row.SamAccountName): $($_.Exception.Message)" -Level ERROR
                return $false
            }
            Start-Sleep -Milliseconds (200 * $i)
        }
    }
    return $false
}

function Save-BackupSnapshot {
    param(
        [Parameter(Mandatory)][string]$Path,
        $Rows
    )

    $arr = @($Rows)
    if ($arr.Count -eq 0) { return $true }

    $tempPath = '{0}.{1}.tmp' -f $Path, $PID
    try {
        $arr | Export-Csv -LiteralPath $tempPath -NoTypeInformation -Encoding UTF8
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
        return $true
    }
    catch {
        Write-Log "Failed to rewrite backup snapshot '$Path': $($_.Exception.Message)" -Level ERROR
        return $false
    }
    finally {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Save-EmergencyBackup {
    param($Rows)

    $arr = @($Rows)
    if ($arr.Count -eq 0) { return $null }

    $emergency = Join-Path $script:BackupFolder ("LogonScriptBackup_EMERGENCY_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    try {
        $arr | Export-Csv -LiteralPath $emergency -NoTypeInformation -Encoding UTF8
        Write-Log "Emergency backup written: $emergency" -Level WARN
        return $emergency
    }
    catch {
        Write-Log "Failed to write emergency backup: $($_.Exception.Message)" -Level ERROR
        foreach ($row in $arr) {
            Write-Log ("EMERGENCY RECOVERY [{0}] ObjectGUID={1} OriginalScriptPath={2}" -f $row.SamAccountName, $row.ObjectGUID, $row.OriginalScriptPath) -Level ERROR
        }
        return $null
    }
}

# ---------------------------------------------------------------------------
# Removal
# ---------------------------------------------------------------------------
function Invoke-LogonScriptRemoval {
    Write-Header 'Remove logon scripts'

    $inputPath = Select-CsvFile -Title 'Select CSV file containing users' -InitialDirectory $script:ScriptRoot
    if (-not $inputPath) {
        Write-Log 'No input file selected. Returning to menu.' -Level WARN
        return
    }
    Write-Log "Input file selected: $inputPath" -Level INFO

    $samList = Get-UserListFromCsv -Path $inputPath
    if ($samList.Count -eq 0) {
        Write-Log 'No users to process.' -Level WARN
        return
    }

    if ($samList.Count -ge $script:LargeSetWarningThreshold) {
        Write-Log "Input contains $($samList.Count) unique identities." -Level WARN
        if (-not (Read-YesNo -Prompt ("  Continue looking up {0} users?" -f $samList.Count) -Default $false)) {
            Write-Log 'Removal cancelled after large-set warning.' -Level WARN
            return
        }
    }

    # ---- Phase 1: discovery ------------------------------------------------
    $results    = New-Object System.Collections.Generic.List[object]
    $candidates = New-Object System.Collections.Generic.List[object]
    $index      = 0

    try {
        foreach ($sam in $samList) {
            $index++
            Write-Progress -Activity 'Looking up users in Active Directory' -Status "$sam ($index of $($samList.Count))" -PercentComplete (($index / $samList.Count) * 100)

            try {
                $user = Get-AdUserSafe -InputValue $sam
                $currentScript = [string](Get-NotePropertyValue -Object $user -Name 'scriptPath')
                $enabledText   = [string](Get-NotePropertyValue -Object $user -Name 'Enabled')

                if ([string]::IsNullOrWhiteSpace($currentScript)) {
                    Write-Log "[$sam] No logon script set. Skipping." -Level INFO -NoConsole
                    $results.Add((New-ResultRow -SamAccountName $user.SamAccountName -InputIdentity $sam `
                        -DistinguishedName $user.DistinguishedName -ObjectGUID $user.ObjectGUID.ToString() `
                        -Enabled $enabledText -Status 'Skipped-NoLogonScript'))
                }
                else {
                    $candidates.Add([pscustomobject]@{
                        InputIdentity = $sam
                        User          = $user
                    })
                }
            }
            catch {
                if (Test-IsIdentityNotFound -ErrorRecord $_) {
                    Write-Log "[$sam] User not found in Active Directory." -Level WARN
                    $results.Add((New-ResultRow -InputIdentity $sam -SamAccountName $sam -Status 'Failed-NotFound' -Details 'User not found'))
                }
                else {
                    Write-Log "[$sam] Lookup failed: $($_.Exception.Message)" -Level ERROR
                    $results.Add((New-ResultRow -InputIdentity $sam -SamAccountName $sam -Status 'Failed-Lookup' -Details $_.Exception.Message))
                }
            }
        }
    }
    finally {
        Complete-Progress -Activity 'Looking up users in Active Directory'
    }

    $noScript = @($results | Where-Object Status -eq 'Skipped-NoLogonScript').Count
    $failed   = @($results | Where-Object Status -like 'Failed-*').Count

    Write-Header 'Discovery summary'
    Write-Host ("  Users in file           : {0}" -f $samList.Count)
    Write-Host ("  With a logon script     : {0}" -f $candidates.Count) -ForegroundColor Green
    Write-Host ("  Without a logon script  : {0}" -f $noScript)
    Write-Host ("  Not found / lookup error: {0}" -f $failed) -ForegroundColor $(if ($failed) { 'Yellow' } else { 'Gray' })
    Write-Log "Discovery: total=$($samList.Count) withScript=$($candidates.Count) noScript=$noScript failed=$failed" -Level INFO -NoConsole

    if ($candidates.Count -eq 0) {
        Write-Log 'No users have a logon script set. Nothing to change.' -Level WARN
        Export-RunReport -Results $results -Prefix 'RemovalResults'
        return
    }

    if (Read-YesNo -Prompt '  Show list of users that will be changed?' -Default $true) {
        $preview = $candidates | ForEach-Object {
            [pscustomobject]@{
                SamAccountName = $_.User.SamAccountName
                Name           = $_.User.Name
                Enabled        = Get-NotePropertyValue -Object $_.User -Name 'Enabled'
                scriptPath     = $_.User.scriptPath
            }
        }
        Show-ObjectPreview -Items $preview -Properties @('SamAccountName', 'Name', 'Enabled', 'scriptPath') -MaxRows $script:PreviewRowLimit
    }

    Write-Host '  [L] Live run  - clear the logon script in Active Directory'
    Write-Host '  [D] Dry run   - simulate only, no changes'
    Write-Host '  [C] Cancel'
    $mode = Read-Choice -Prompt '  Select mode' -ValidChoices @('L', 'D', 'C')

    if ($mode -eq 'C') {
        Write-Log 'Removal cancelled by user before changes were made.' -Level WARN
        Export-RunReport -Results $results -Prefix 'RemovalCancelled'
        return
    }

    $isDryRun = ($mode -eq 'D')
    if (-not $isDryRun) {
        $confirm = Read-Host "  Type REMOVE to confirm clearing the logon script on $($candidates.Count) user(s)"
        if ($confirm -cne 'REMOVE') {
            Write-Log 'Confirmation text did not match. Removal cancelled.' -Level WARN
            Export-RunReport -Results $results -Prefix 'RemovalCancelled'
            return
        }
        Confirm-ConnectedPdc | Out-Null
    }

    $backupFile = Join-Path $script:BackupFolder ("LogonScriptBackup_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $backupRows = New-Object System.Collections.Generic.List[object]
    if ($isDryRun) {
        Write-Log 'DRY RUN started. No changes will be written to Active Directory.' -Level DRYRUN
    }
    else {
        Write-Log "LIVE RUN started. Backup file: $backupFile" -Level INFO
    }

    # ---- Phase 2: change ---------------------------------------------------
    $index   = 0
    $success = 0
    $backupWriteFailures = 0
    try {
        foreach ($candidate in $candidates) {
            $index++
            $user     = $candidate.User
            $sam      = $user.SamAccountName
            $original = ([string]$user.scriptPath).Trim()
            Write-Progress -Activity 'Removing logon scripts' -Status "$sam ($index of $($candidates.Count))" -PercentComplete (($index / $candidates.Count) * 100)

            if ($isDryRun) {
                Write-Log "[$sam] WOULD clear logon script '$original'." -Level DRYRUN
                $results.Add((New-ResultRow -SamAccountName $sam -InputIdentity $candidate.InputIdentity `
                    -DistinguishedName $user.DistinguishedName -ObjectGUID $user.ObjectGUID.ToString() `
                    -Enabled ([string](Get-NotePropertyValue -Object $user -Name 'Enabled')) `
                    -OriginalScriptPath $original -CurrentScriptPath $original `
                    -Status 'DryRun-WouldRemove'))
                continue
            }

            $changeSucceeded = $false
            try {
                Invoke-ADOperation -OperationName "Clear scriptPath [$sam]" -ScriptBlock {
                    Set-ADUser -Identity $user.ObjectGUID -Clear scriptPath -Confirm:$false @script:ADParams -ErrorAction Stop
                }

                $verify = Invoke-ADOperation -OperationName "Verify scriptPath cleared [$sam]" -ScriptBlock {
                    Get-ADUser -Identity $user.ObjectGUID -Properties scriptPath @script:ADParams -ErrorAction Stop
                }
                $verifiedPath = [string](Get-NotePropertyValue -Object $verify -Name 'scriptPath')
                if (-not [string]::IsNullOrWhiteSpace($verifiedPath)) {
                    throw "Verification failed; scriptPath is still '$verifiedPath'."
                }

                $changeSucceeded = $true
            }
            catch {
                Write-Log "[$sam] Failed to remove logon script '$original': $($_.Exception.Message)" -Level ERROR
                $results.Add((New-ResultRow -SamAccountName $sam -InputIdentity $candidate.InputIdentity `
                    -DistinguishedName $user.DistinguishedName -ObjectGUID $user.ObjectGUID.ToString() `
                    -Enabled ([string](Get-NotePropertyValue -Object $user -Name 'Enabled')) `
                    -OriginalScriptPath $original -CurrentScriptPath $original `
                    -Status 'Failed-Remove' -Details $_.Exception.Message))
                continue
            }

            $backupRow = New-BackupRow -User $user -OriginalScriptPath $original -InputIdentity $candidate.InputIdentity -SourceFile $inputPath
            $backupOk  = Add-BackupRow -Row $backupRow -Path $backupFile -BackupRows $backupRows
            if (-not $backupOk) { $backupWriteFailures++ }

            $success++
            Write-Log "[$sam] Logon script '$original' removed." -Level SUCCESS
            $details = ''
            if (-not $backupOk) {
                $details = 'AD change succeeded but the backup CSV row could not be written; value is in the report and log.'
                Write-Log "[$sam] WARNING: scriptPath was cleared but the backup row was not written. Original='$original' GUID=$($user.ObjectGUID)" -Level ERROR
            }
            $results.Add((New-ResultRow -SamAccountName $sam -InputIdentity $candidate.InputIdentity `
                -DistinguishedName $user.DistinguishedName -ObjectGUID $user.ObjectGUID.ToString() `
                -Enabled ([string](Get-NotePropertyValue -Object $user -Name 'Enabled')) `
                -OriginalScriptPath $original -CurrentScriptPath '' `
                -Status 'Removed' -Details $details))
        }
    }
    finally {
        Complete-Progress -Activity 'Removing logon scripts'
    }

    if (-not $isDryRun -and $backupRows.Count -gt 0) {
        if (-not (Save-BackupSnapshot -Path $backupFile -Rows $backupRows)) {
            $emergency = Save-EmergencyBackup -Rows $backupRows
            if ($emergency) { $backupFile = $emergency }
        }
    }

    Write-Header 'Removal complete'
    if ($isDryRun) {
        Write-Log "DRY RUN finished. $($candidates.Count) user(s) would be changed." -Level DRYRUN
    }
    else {
        $removeFailures = $candidates.Count - $success
        $level = if ($removeFailures -or $backupWriteFailures) { 'WARN' } else { 'SUCCESS' }
        Write-Log "LIVE RUN finished. Removed=$success Failed=$removeFailures BackupWriteFailures=$backupWriteFailures" -Level $level
        if ($success -gt 0) {
            Write-Log "Revert backup file: $backupFile" -Level INFO
        }
        if ($backupWriteFailures -gt 0) {
            Write-Log 'One or more backup rows failed to write. Use the results report (OriginalScriptPath column) if the backup file is incomplete.' -Level ERROR
        }
    }
    Export-RunReport -Results $results -Prefix $(if ($isDryRun) { 'RemovalDryRun' } else { 'RemovalResults' })
}

# ---------------------------------------------------------------------------
# Revert
# ---------------------------------------------------------------------------
function Get-BackupEntries {
    param([Parameter(Mandatory)]$Rows)

    $usable = @($Rows | Where-Object {
        $sam  = [string](Get-NotePropertyValue -Object $_ -Name 'SamAccountName')
        $orig = [string](Get-NotePropertyValue -Object $_ -Name 'OriginalScriptPath')
        if ([string]::IsNullOrWhiteSpace($sam) -or [string]::IsNullOrWhiteSpace($orig)) { return $false }

        # Allow a RemovalResults CSV as a revert source, but never replay
        # dry-run / skip / failed rows that happen to have an original path.
        $status = [string](Get-NotePropertyValue -Object $_ -Name 'Status')
        if ($status) {
            if ($status -like 'DryRun-*' -or $status -like 'Skipped-*' -or $status -like 'Failed-*') {
                return $false
            }
        }
        return $true
    })

    $grouped = $usable | Group-Object -Property SamAccountName
    $entries = foreach ($group in $grouped) {
        $group.Group | Sort-Object {
            $raw = [string](Get-NotePropertyValue -Object $_ -Name 'RemovedOn')
            $parsed = [datetime]::MinValue
            if ($raw -and [datetime]::TryParse($raw, [ref]$parsed)) { $parsed } else { [datetime]::MinValue }
        } | Select-Object -First 1
    }
    if ($null -eq $entries) { return , [object[]]@() }
    return , @($entries)
}

function Test-BackupEntryIdentityMatch {
    param(
        $Entry,
        [Parameter(Mandatory)][string]$Identity
    )

    $parsed = ConvertTo-AdUserIdentity -Value $Identity
    $keys = @(
        [string](Get-NotePropertyValue -Object $Entry -Name 'SamAccountName')
        [string](Get-NotePropertyValue -Object $Entry -Name 'UserPrincipalName')
        [string](Get-NotePropertyValue -Object $Entry -Name 'DistinguishedName')
        [string](Get-NotePropertyValue -Object $Entry -Name 'ObjectGUID')
        [string](Get-NotePropertyValue -Object $Entry -Name 'SID')
        [string](Get-NotePropertyValue -Object $Entry -Name 'InputIdentity')
    )

    foreach ($key in $keys) {
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        if (Test-ScriptPathEqual -Left $key -Right $Identity) { return $true }
        if ($parsed.SamAccountName -and (Test-ScriptPathEqual -Left $key -Right $parsed.SamAccountName)) { return $true }
        if ($parsed.UserPrincipalName -and (Test-ScriptPathEqual -Left $key -Right $parsed.UserPrincipalName)) { return $true }
        if ($parsed.DistinguishedName -and (Test-ScriptPathEqual -Left $key -Right $parsed.DistinguishedName)) { return $true }
        if ($parsed.SID -and (Test-ScriptPathEqual -Left $key -Right $parsed.SID)) { return $true }
        if ($parsed.ObjectGUID -and (Test-ScriptPathEqual -Left $key -Right $parsed.ObjectGUID.ToString())) { return $true }
    }
    return $false
}

function Get-MatchingBackupEntries {
    param(
        [Parameter(Mandatory)]$Entries,
        [Parameter(Mandatory)][string[]]$Identities
    )

    $wanted = @($Identities | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $matched = New-Object System.Collections.Generic.List[object]
    foreach ($entry in $Entries) {
        foreach ($id in $wanted) {
            if (Test-BackupEntryIdentityMatch -Entry $entry -Identity $id) {
                $matched.Add($entry)
                break
            }
        }
    }

    $unmatched = New-Object System.Collections.Generic.List[string]
    foreach ($id in $wanted) {
        $hit = $false
        foreach ($entry in $matched) {
            if (Test-BackupEntryIdentityMatch -Entry $entry -Identity $id) { $hit = $true; break }
        }
        if (-not $hit) { $unmatched.Add($id) }
    }

    return [pscustomobject]@{
        Entries             = $matched.ToArray()
        UnmatchedIdentities = $unmatched.ToArray()
    }
}

function Select-BackupEntriesForRevert {
    param([Parameter(Mandatory)]$Entries)

    if ($Entries.Count -le 1) {
        Write-Log ("Revert set contains {0} user(s)." -f $Entries.Count) -Level INFO
        return , @($Entries)
    }

    Write-Host ''
    Write-Host "  [A] Revert ALL $($Entries.Count) users in this file"
    Write-Host '  [S] Select specific user(s) by name (one or many)'
    Write-Host '  [F] Filter using another CSV of identities'
    $scope = Read-Choice -Prompt '  Who should be reverted?' -ValidChoices @('A', 'S', 'F')

    $wanted = $null
    switch ($scope) {
        'A' { return , @($Entries) }
        'S' {
            $typed = Read-Host '  Enter one or more identities (comma, semicolon or newline separated)'
            $wanted = ConvertTo-IdentityTokenList -RawText $typed
        }
        'F' {
            $filterPath = Select-CsvFile -Title 'Select CSV of users to revert from the backup' -InitialDirectory $script:ScriptRoot
            if (-not $filterPath) {
                Write-Log 'No filter file selected. Revert cancelled.' -Level WARN
                return , [object[]]@()
            }
            $wanted = Get-UserListFromCsv -Path $filterPath
        }
    }

    if ($null -eq $wanted -or $wanted.Count -eq 0) {
        Write-Log 'No identities supplied for the revert filter.' -Level WARN
        return , [object[]]@()
    }

    $match = Get-MatchingBackupEntries -Entries $Entries -Identities $wanted
    foreach ($missing in @($match.UnmatchedIdentities)) {
        Write-Log "[$missing] Not present in the backup file. Skipped." -Level WARN
    }

    $selected = @($match.Entries)
    if ($selected.Count -eq 0) {
        Write-Log 'None of the requested identities were found in the backup file.' -Level ERROR
        return , [object[]]@()
    }

    Write-Log ("Revert filtered to {0} user(s) of {1}." -f $selected.Count, $Entries.Count) -Level INFO
    return , $selected
}

function Invoke-LogonScriptRevert {
    Write-Header 'Revert logon scripts'

    $backupPath = Select-CsvFile -Title 'Select logon script BACKUP CSV to revert' -InitialDirectory $script:BackupFolder
    if (-not $backupPath) {
        Write-Log 'No backup file selected. Returning to menu.' -Level WARN
        return
    }
    Write-Log "Backup file selected for revert: $backupPath" -Level INFO

    try {
        $rows = Import-CsvSafe -Path $backupPath
    }
    catch {
        Write-Log "Failed to read backup file: $($_.Exception.Message)" -Level ERROR
        return
    }

    if ($rows.Count -eq 0) {
        Write-Log 'Backup file is empty.' -Level ERROR
        return
    }

    $columns = @($rows[0].PSObject.Properties.Name)
    foreach ($required in @('SamAccountName', 'OriginalScriptPath')) {
        if (-not (Get-PropertyNameIgnoreCase -Names $columns -Candidates @($required))) {
            Write-Log "Backup file is missing required column '$required'. Is this a backup created by this script?" -Level ERROR
            return
        }
    }
    $hasGuid = [bool](Get-PropertyNameIgnoreCase -Names $columns -Candidates $script:GuidColumnAliases)

    $entries = Get-BackupEntries -Rows $rows
    if ($entries.Count -eq 0) {
        Write-Log 'Backup file has no usable rows (SamAccountName + OriginalScriptPath required).' -Level ERROR
        return
    }

    if ($entries.Count -lt $rows.Count) {
        Write-Log ("Using {0} unique user(s) from {1} backup row(s). Duplicate identities keep the earliest RemovedOn value." -f $entries.Count, $rows.Count) -Level INFO
    }

    $entries = Select-BackupEntriesForRevert -Entries $entries
    if ($entries.Count -eq 0) {
        Write-Log 'No users selected for revert.' -Level WARN
        return
    }

    Write-Host ("  Users selected to revert: {0}" -f $entries.Count)
    if (Read-YesNo -Prompt '  Show list of users that will be reverted?' -Default $true) {
        Show-ObjectPreview -Items $entries -Properties @('SamAccountName', 'OriginalScriptPath', 'RemovedOn') -MaxRows $script:PreviewRowLimit
    }

    Write-Host '  If a user currently has a DIFFERENT logon script than the backup:'
    Write-Host '    [S] Skip that user (recommended)'
    Write-Host '    [O] Overwrite with the backup value'
    Write-Host '    [A] Ask for each user'
    $conflictPolicy = Read-Choice -Prompt '  Select conflict handling' -ValidChoices @('S', 'O', 'A')

    Write-Host '  [L] Live run  - restore logon scripts in Active Directory'
    Write-Host '  [D] Dry run   - simulate only, no changes'
    Write-Host '  [C] Cancel'
    $mode = Read-Choice -Prompt '  Select mode' -ValidChoices @('L', 'D', 'C')
    if ($mode -eq 'C') {
        Write-Log 'Revert cancelled by user.' -Level WARN
        return
    }

    $isDryRun = ($mode -eq 'D')
    if (-not $isDryRun) {
        $confirm = Read-Host "  Type REVERT to confirm restoring logon scripts on $($entries.Count) user(s)"
        if ($confirm -cne 'REVERT') {
            Write-Log 'Confirmation text did not match. Revert cancelled.' -Level WARN
            return
        }
        Confirm-ConnectedPdc | Out-Null
    }

    Write-Log ("Revert {0} started. Conflict policy: {1}" -f $(if ($isDryRun) { 'DRY RUN' } else { 'LIVE RUN' }), $conflictPolicy) -Level $(if ($isDryRun) { 'DRYRUN' } else { 'INFO' })

    $results = New-Object System.Collections.Generic.List[object]
    $index   = 0

    try {
        foreach ($entry in $entries) {
            $index++
            $sam      = ([string](Get-NotePropertyValue -Object $entry -Name 'SamAccountName')).Trim()
            $original = ([string](Get-NotePropertyValue -Object $entry -Name 'OriginalScriptPath')).Trim()
            $guidText = [string](Get-NotePropertyValue -Object $entry -Name 'ObjectGUID')
            Write-Progress -Activity 'Reverting logon scripts' -Status "$sam ($index of $($entries.Count))" -PercentComplete (($index / $entries.Count) * 100)

            $status  = $null
            $details = ''
            $liveDn  = [string](Get-NotePropertyValue -Object $entry -Name 'DistinguishedName')
            $liveGuid = $guidText
            $enabledText = ''
            $current = ''

            try {
                $user = Get-AdUserSafe -InputValue $sam `
                    -ObjectGUID $(if ($hasGuid) { $guidText } else { $null }) `
                    -SID ([string](Get-NotePropertyValue -Object $entry -Name 'SID')) `
                    -DistinguishedName ([string](Get-NotePropertyValue -Object $entry -Name 'DistinguishedName'))
                $liveDn      = $user.DistinguishedName
                $liveGuid    = $user.ObjectGUID.ToString()
                $enabledText = [string](Get-NotePropertyValue -Object $user -Name 'Enabled')
                $current     = [string](Get-NotePropertyValue -Object $user -Name 'scriptPath')

                if (Test-ScriptPathEqual -Left $current -Right $original) {
                    Write-Log "[$sam] Logon script is already '$original'. Nothing to do." -Level INFO
                    $status = 'Skipped-AlreadySet'
                }
                elseif (-not [string]::IsNullOrWhiteSpace($current)) {
                    $overwrite = $false
                    switch ($conflictPolicy) {
                        'S' { $overwrite = $false }
                        'O' { $overwrite = $true }
                        'A' { $overwrite = Read-YesNo -Prompt "  [$sam] currently '$current', backup '$original'. Overwrite?" -Default $false }
                    }
                    if (-not $overwrite) {
                        Write-Log "[$sam] Current logon script '$current' differs from backup '$original'. Skipped." -Level WARN
                        $status  = 'Skipped-Conflict'
                        $details = "Current value: $current"
                    }
                }

                if (-not $status) {
                    if ($isDryRun) {
                        Write-Log "[$sam] WOULD restore logon script '$original' (current: '$current')." -Level DRYRUN
                        $status = 'DryRun-WouldRevert'
                    }
                    else {
                        Invoke-ADOperation -OperationName "Restore scriptPath [$sam]" -ScriptBlock {
                            Set-ADUser -Identity $user.ObjectGUID -Replace @{ scriptPath = $original } -Confirm:$false @script:ADParams -ErrorAction Stop
                        }

                        $verify = Invoke-ADOperation -OperationName "Verify scriptPath restored [$sam]" -ScriptBlock {
                            Get-ADUser -Identity $user.ObjectGUID -Properties scriptPath @script:ADParams -ErrorAction Stop
                        }
                        $verifiedPath = [string](Get-NotePropertyValue -Object $verify -Name 'scriptPath')
                        if (-not (Test-ScriptPathEqual -Left $verifiedPath -Right $original)) {
                            throw "Verification failed; scriptPath is '$verifiedPath'."
                        }
                        Write-Log "[$sam] Logon script restored to '$original'." -Level SUCCESS
                        $status = 'Reverted'
                        if (-not [string]::IsNullOrWhiteSpace($current)) { $details = "Overwrote: $current" }
                        $current = $original
                    }
                }
            }
            catch {
                if (Test-IsIdentityNotFound -ErrorRecord $_) {
                    Write-Log "[$sam] User not found in Active Directory." -Level ERROR
                    $status  = 'Failed-NotFound'
                    $details = 'User not found'
                }
                else {
                    Write-Log "[$sam] Failed to restore logon script '$original': $($_.Exception.Message)" -Level ERROR
                    $status  = 'Failed-Revert'
                    $details = $_.Exception.Message
                }
            }

            $results.Add((New-ResultRow -SamAccountName $sam -InputIdentity $sam `
                -DistinguishedName $liveDn -ObjectGUID $liveGuid -Enabled $enabledText `
                -OriginalScriptPath $original -CurrentScriptPath $current `
                -Status $status -Details $details))
        }
    }
    finally {
        Complete-Progress -Activity 'Reverting logon scripts'
    }

    $reverted = @($results | Where-Object Status -eq 'Reverted').Count
    $skipped  = @($results | Where-Object Status -like 'Skipped-*').Count
    $failed   = @($results | Where-Object Status -like 'Failed-*').Count

    Write-Header 'Revert complete'
    if ($isDryRun) {
        $would = @($results | Where-Object Status -eq 'DryRun-WouldRevert').Count
        Write-Log "DRY RUN finished. WouldRevert=$would Skipped=$skipped Failed=$failed" -Level DRYRUN
    }
    else {
        Write-Log "LIVE RUN finished. Reverted=$reverted Skipped=$skipped Failed=$failed" -Level $(if ($failed) { 'WARN' } else { 'SUCCESS' })
    }
    Export-RunReport -Results $results -Prefix $(if ($isDryRun) { 'RevertDryRun' } else { 'RevertResults' })
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
function Export-RunReport {
    param(
        [Parameter(Mandatory)]$Results,
        [Parameter(Mandatory)][string]$Prefix
    )
    $arr = @($Results)
    if ($arr.Count -eq 0) { return }

    $reportFile = Join-Path $script:ReportFolder ("{0}_{1}.csv" -f $Prefix, (Get-Date -Format 'yyyyMMdd_HHmmss'))
    try {
        $arr | Export-Csv -LiteralPath $reportFile -NoTypeInformation -Encoding UTF8
        Write-Log "Results report written: $reportFile" -Level INFO
    }
    catch {
        Write-Log "Failed to write results report '$reportFile': $($_.Exception.Message)" -Level ERROR
        $emergency = Join-Path $script:ReportFolder ("{0}_EMERGENCY_{1}.csv" -f $Prefix, (Get-Date -Format 'yyyyMMdd_HHmmss'))
        try {
            $arr | Export-Csv -LiteralPath $emergency -NoTypeInformation -Encoding UTF8
            Write-Log "Emergency results report written: $emergency" -Level WARN
        }
        catch {
            Write-Log "Failed to write emergency results report: $($_.Exception.Message)" -Level ERROR
        }
    }
}

function Open-OutputFolder {
    if (-not (Test-Path -LiteralPath $script:OutputRoot)) {
        New-Item -Path $script:OutputRoot -ItemType Directory -Force | Out-Null
    }

    try {
        Invoke-Item -LiteralPath $script:OutputRoot
        Write-Log "Opened output folder: $($script:OutputRoot)" -Level INFO -NoConsole
        return
    }
    catch {
        Write-Log "Invoke-Item failed: $($_.Exception.Message)" -Level WARN
    }

    try {
        Start-Process -FilePath 'explorer.exe' -ArgumentList @($script:OutputRoot) -ErrorAction Stop
        return
    }
    catch {
        Write-Log "Could not open Explorer. Output folder: $($script:OutputRoot)" -Level WARN
        Write-Host "  Output folder: $($script:OutputRoot)" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------
function Show-MainMenu {
    while ($true) {
        Write-Header 'AD Logon Script Manager'
        Write-Host "  Domain            : $($script:DomainDnsRoot)"
        Write-Host "  PDC Emulator      : $($script:PdcEmulator)"
        Write-Host "  Output folder     : $($script:OutputRoot)"
        Write-Host "  Log file          : $($script:LogFile)"
        Write-Host ''
        Write-Host '  [1] Remove logon scripts (select users CSV)'
        Write-Host '  [2] Revert logon scripts (select backup CSV)'
        Write-Host '  [3] Open output folder'
        Write-Host '  [4] Re-discover PDC Emulator / change credentials'
        Write-Host '  [Q] Quit'

        $choice = Read-Choice -Prompt '  Select an option' -ValidChoices @('1', '2', '3', '4', 'Q')
        Write-Log "Menu selection: $choice" -Level INFO -NoConsole

        try {
            switch ($choice) {
                '1' { Invoke-LogonScriptRemoval }
                '2' { Invoke-LogonScriptRevert }
                '3' { Open-OutputFolder }
                '4' { Initialize-ADConnection -AllowHint }
                'Q' { return }
            }
        }
        catch {
            Complete-Progress -Activity 'Looking up users in Active Directory'
            Complete-Progress -Activity 'Removing logon scripts'
            Complete-Progress -Activity 'Reverting logon scripts'
            Write-Log "Unexpected error: $($_.Exception.Message)" -Level ERROR
        }

        if ($choice -ne '3') {
            Write-Host ''
            Read-Host '  Press Enter to return to the main menu' | Out-Null
        }
    }
}

# ---------------------------------------------------------------------------
# Built-in tests (no Active Directory required)
# ---------------------------------------------------------------------------
function Invoke-SelfTest {
    function Assert-True {
        param([bool]$Condition, [string]$Name)
        if ($Condition) {
            $script:SelfTestPassed++
            Write-Host "  PASS  $Name" -ForegroundColor Green
        }
        else {
            $script:SelfTestFailed++
            Write-Host "  FAIL  $Name" -ForegroundColor Red
        }
    }

    $script:SelfTestPassed = 0
    $script:SelfTestFailed = 0

    $testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("LogonScriptSelfTest-{0}" -f [guid]::NewGuid().ToString('N'))
    $script:OutputRoot   = $testRoot
    $script:LogFolder    = Join-Path $testRoot 'Logs'
    $script:BackupFolder = Join-Path $testRoot 'Backups'
    $script:ReportFolder = Join-Path $testRoot 'Reports'
    $script:LogFile      = Join-Path $script:LogFolder 'selftest.log'

    Write-Header 'Manage-ADLogonScript self-test'

    Assert-True -Condition ((Get-FirstNonEmptyString -Value 'DC01.contoso.com') -eq 'DC01.contoso.com') -Name 'Get-FirstNonEmptyString keeps a full hostname'
    Assert-True -Condition ((Get-FirstNonEmptyString -Value @('DC01.contoso.com', 'DC02.contoso.com')) -eq 'DC01.contoso.com') -Name 'Get-FirstNonEmptyString uses the first array item, not the first character'
    Assert-True -Condition ((Get-FirstNonEmptyString -Value @('', '  ', 'DC01')) -eq 'DC01') -Name 'Get-FirstNonEmptyString skips blank entries and returns the first real value'

    $obj = [pscustomobject]@{ SamAccountName = 'jsmith' }
    Assert-True -Condition ((Get-NotePropertyValue -Object $obj -Name 'SamAccountName') -eq 'jsmith') -Name 'Get-NotePropertyValue reads an existing property'
    Assert-True -Condition ((Get-NotePropertyValue -Object $obj -Name 'RemovedOn' -Default 'missing') -eq 'missing') -Name 'Get-NotePropertyValue returns the default for a missing property (StrictMode-safe)'

    Assert-True -Condition (Test-ScriptPathEqual -Left 'Logon.bat' -Right 'logon.BAT') -Name 'Test-ScriptPathEqual is case-insensitive'
    Assert-True -Condition (Test-ScriptPathEqual -Left '  scripts\logon.bat  ' -Right 'scripts\logon.bat') -Name 'Test-ScriptPathEqual trims whitespace'
    Assert-True -Condition (-not (Test-ScriptPathEqual -Left 'a.bat' -Right 'b.bat')) -Name 'Test-ScriptPathEqual detects different values'

    Assert-True -Condition ((ConvertTo-EscapedAdFilterString -Value "O'Brien") -eq "O''Brien") -Name 'ConvertTo-EscapedAdFilterString doubles single quotes'

    $zeroChoices = ConvertTo-ChoiceIndexList -Count 0
    Assert-True -Condition ($null -ne $zeroChoices -and @($zeroChoices).Count -eq 0) -Name 'ConvertTo-ChoiceIndexList does not emit 1,0 when Count is 0'
    Assert-True -Condition (((ConvertTo-ChoiceIndexList -Count 2) -join ',') -eq '1,2') -Name 'ConvertTo-ChoiceIndexList emits 1..N'

    $alias = Get-PropertyNameIgnoreCase -Names @('EmployeeID', 'Username', 'Dept') -Candidates $script:IdentityColumnAliases
    Assert-True -Condition ($alias -eq 'Username') -Name 'Get-PropertyNameIgnoreCase matches Username alias'

    Assert-True -Condition ((Get-CsvColumnKind -Name 'EmailAddress') -eq 'UPN') -Name 'Get-CsvColumnKind classifies EmailAddress as UPN'
    Assert-True -Condition ((Get-CsvColumnKind -Name 'LoginName') -eq 'SAM') -Name 'Get-CsvColumnKind classifies LoginName as SAM'
    Assert-True -Condition ((Get-RecommendedCsvIdentityColumn -Columns @('EmployeeID', 'Email', 'Department')) -eq 'Email') -Name 'Get-RecommendedCsvIdentityColumn prefers Email over non-identity headers'
    Assert-True -Condition ((Get-RecommendedCsvIdentityColumn -Columns @('EmailAddress', 'SamAccountName', 'DisplayName')) -eq 'SamAccountName') -Name 'Get-RecommendedCsvIdentityColumn prefers SamAccountName over Email'

    $idSam = ConvertTo-AdUserIdentity -Value 'jsmith'
    Assert-True -Condition ($idSam.Kind -eq 'SAM' -and $idSam.SamAccountName -eq 'jsmith') -Name 'ConvertTo-AdUserIdentity parses sAMAccountName'

    $idNt4 = ConvertTo-AdUserIdentity -Value 'CONTOSO\jsmith'
    Assert-True -Condition ($idNt4.Kind -eq 'NT4' -and $idNt4.SamAccountName -eq 'jsmith') -Name 'ConvertTo-AdUserIdentity parses DOMAIN\user'

    $idUpn = ConvertTo-AdUserIdentity -Value 'john.smith@contoso.com'
    Assert-True -Condition ($idUpn.Kind -eq 'UPN' -and $idUpn.UserPrincipalName -eq 'john.smith@contoso.com' -and $idUpn.SamAccountName -eq 'john.smith') -Name 'ConvertTo-AdUserIdentity parses UPN without discarding the suffix'

    $idDn = ConvertTo-AdUserIdentity -Value 'CN=John Smith,OU=Users,DC=contoso,DC=com'
    Assert-True -Condition ($idDn.Kind -eq 'DN') -Name 'ConvertTo-AdUserIdentity parses a distinguishedName'

    $guid = [guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    $idGuid = ConvertTo-AdUserIdentity -Value $guid.ToString()
    Assert-True -Condition ($idGuid.Kind -eq 'GUID' -and $idGuid.ObjectGUID -eq $guid) -Name 'ConvertTo-AdUserIdentity parses a GUID'

    $idSid = ConvertTo-AdUserIdentity -Value 'S-1-5-21-1-2-3-1001'
    Assert-True -Condition ($idSid.Kind -eq 'SID') -Name 'ConvertTo-AdUserIdentity parses a SID'

    $notFound = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.Management.Automation.ItemNotFoundException 'Cannot find an object with identity: xyz'),
        'ADIdentityNotFoundException,Microsoft.ActiveDirectory.Management.Commands.GetADUser',
        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
        'xyz'
    )
    Assert-True -Condition (Test-IsIdentityNotFound -ErrorRecord $notFound) -Name 'Test-IsIdentityNotFound recognises wrapped not-found errors'

    $timeout = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.TimeoutException 'The server is not operational'),
        'Timeout',
        [System.Management.Automation.ErrorCategory]::OperationTimeout,
        $null
    )
    Assert-True -Condition (Test-IsTransientAdError -ErrorRecord $timeout) -Name 'Test-IsTransientAdError recognises timeout / DC-down messages'
    Assert-True -Condition (-not (Test-IsTransientAdError -ErrorRecord $notFound)) -Name 'Test-IsTransientAdError does not treat not-found as transient'

    $backupRows = @(
        [pscustomobject]@{ SamAccountName = 'jsmith'; OriginalScriptPath = 'old.bat'; RemovedOn = '2024-01-02T00:00:00' },
        [pscustomobject]@{ SamAccountName = 'jsmith'; OriginalScriptPath = 'newer.bat'; RemovedOn = '2024-06-01T00:00:00' },
        [pscustomobject]@{ SamAccountName = 'ajones'; OriginalScriptPath = 'login.vbs'; RemovedOn = '2024-03-01T00:00:00' },
        [pscustomobject]@{ SamAccountName = ''; OriginalScriptPath = 'x.bat'; RemovedOn = '2024-01-01T00:00:00' }
    )
    $deduped = Get-BackupEntries -Rows $backupRows
    $jsmith  = @($deduped | Where-Object { $_.SamAccountName -eq 'jsmith' })[0]
    Assert-True -Condition ($deduped.Count -eq 2) -Name 'Get-BackupEntries drops blank identities and collapses duplicates'
    Assert-True -Condition ([string]$jsmith.OriginalScriptPath -eq 'old.bat') -Name 'Get-BackupEntries keeps the earliest RemovedOn value as the true original'

    $singleBackup = Get-BackupEntries -Rows @([pscustomobject]@{ SamAccountName = 'onlyme'; OriginalScriptPath = 'one.bat'; RemovedOn = '2024-01-01T00:00:00' })
    Assert-True -Condition ($singleBackup.Count -eq 1 -and $singleBackup[0].SamAccountName -eq 'onlyme') -Name 'Get-BackupEntries keeps a single-user backup as a one-element array'

    $mixedStatus = Get-BackupEntries -Rows @(
        [pscustomobject]@{ SamAccountName = 'keep'; OriginalScriptPath = 'a.bat'; Status = 'Removed' },
        [pscustomobject]@{ SamAccountName = 'dry';  OriginalScriptPath = 'b.bat'; Status = 'DryRun-WouldRemove' },
        [pscustomobject]@{ SamAccountName = 'skip'; OriginalScriptPath = 'c.bat'; Status = 'Skipped-NoLogonScript' }
    )
    Assert-True -Condition ($mixedStatus.Count -eq 1 -and $mixedStatus[0].SamAccountName -eq 'keep') -Name 'Get-BackupEntries ignores dry-run and skipped rows when a Status column is present'

    $samList = ConvertTo-IdentityTokenList -RawText 'jsmith, ajones'
    Assert-True -Condition ($samList.Count -eq 2 -and $samList[0] -eq 'jsmith' -and $samList[1] -eq 'ajones') -Name 'ConvertTo-IdentityTokenList splits comma-separated SAM names'
    $dnList = ConvertTo-IdentityTokenList -RawText 'CN=John Smith,OU=Users,DC=contoso,DC=com'
    Assert-True -Condition ($dnList.Count -eq 1 -and $dnList[0] -like 'CN=John Smith,*') -Name 'ConvertTo-IdentityTokenList does not split a distinguishedName on commas'

    $filtered = Get-MatchingBackupEntries -Entries $deduped -Identities @('CONTOSO\jsmith', 'nobody')
    Assert-True -Condition (@($filtered.Entries).Count -eq 1 -and $filtered.Entries[0].SamAccountName -eq 'jsmith') -Name 'Get-MatchingBackupEntries can revert one user out of a multi-user backup'
    Assert-True -Condition (@($filtered.UnmatchedIdentities) -contains 'nobody') -Name 'Get-MatchingBackupEntries reports identities that are not in the backup'

    $tempCsv = Join-Path ([System.IO.Path]::GetTempPath()) ("logonscript-selftest-{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
        [System.IO.File]::WriteAllText($tempCsv, "SamAccountName`r`n", $script:Utf8NoBom)
        $emptyImport = Import-CsvSafe -Path $tempCsv
        Assert-True -Condition ($null -ne $emptyImport -and $emptyImport.Count -eq 0) -Name 'Import-CsvSafe returns an empty array for a header-only CSV'

        [System.IO.File]::WriteAllText($tempCsv, "SamAccountName`r`nalice`r`nbob`r`nalice`r`n`r`n", $script:Utf8NoBom)
        $loaded = Get-UserListFromCsv -Path $tempCsv -AutoSelect
        Assert-True -Condition ($loaded.Count -eq 2 -and $loaded[0] -eq 'alice' -and $loaded[1] -eq 'bob') -Name 'Get-UserListFromCsv de-duplicates and skips blank rows'

        [System.IO.File]::WriteAllText($tempCsv, "EmployeeID,EmailAddress,Department`r`n1,bob.lee@contoso.com,IT`r`n2,ann@contoso.com,HR`r`n", $script:Utf8NoBom)
        $byEmail = Get-UserListFromCsv -Path $tempCsv -AutoSelect
        Assert-True -Condition ($byEmail.Count -eq 2 -and $byEmail[0] -eq 'bob.lee@contoso.com') -Name 'Get-UserListFromCsv -AutoSelect keys on EmailAddress when no SAM column exists'
    }
    finally {
        if (Test-Path -LiteralPath $tempCsv) { Remove-Item -LiteralPath $tempCsv -Force }
    }

    Write-Host ''
    Write-Host ("  {0} passed, {1} failed" -f $script:SelfTestPassed, $script:SelfTestFailed) -ForegroundColor $(if ($script:SelfTestFailed) { 'Red' } else { 'Green' })

    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    return ($script:SelfTestFailed -eq 0)
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
$script:IsDotSourced = ($MyInvocation.InvocationName -eq '.')

if ($SelfTest) {
    $ok = Invoke-SelfTest
    if ($ok) { exit 0 } else { exit 1 }
}

if ($SkipMain -or $script:IsDotSourced) { return }

try {
    Initialize-Environment
    Initialize-ADConnection
    Show-MainMenu
}
catch {
    Write-Log "Fatal error: $($_.Exception.Message)" -Level ERROR
    Read-Host 'Press Enter to exit' | Out-Null
}
finally {
    Write-Log "Session ended." -Level INFO
}

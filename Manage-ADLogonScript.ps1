#Requires -Version 5.1
<#
.SYNOPSIS
    Removes and reverts the AD logon script (scriptPath) on users listed in a CSV.
    All reads and writes target the domain PDC Emulator.

.DESCRIPTION
    Menu-driven Windows PowerShell 5.1 tool:

      [1] Remove logon scripts
          Pick a user CSV, choose the identity column, preview who has a
          scriptPath, then type REMOVE for a live run (anything else is a dry run).
          Each successful backup row is written BEFORE the AD attribute is cleared
          so a later revert is possible even if the write then fails.

      [2] Revert
          Pick a backup CSV produced by option 1. Restore everyone, or a
          comma-separated subset. Type REVERT to apply.

      [3] Open the output folder
      [Q] Quit

    Identities may be sAMAccountName, DOMAIN\user, UPN, mail, distinguishedName,
    GUID or SID.

    Bugs fixed versus the script this was debugged from:
      - Get-ADUser -Filter (UPN/mail) returns $null instead of throwing, so a
        missing user was logged as "SKIP (no logon script)".
      - '$id -replace ''^.*\\''' is greedy and destroys DNs that contain an
        escaped comma (CN=Smith\, John,...).
      - Cancelling the file picker returned $null and Import-Csv then crashed.
      - A header-only / empty CSV hit $rows[0] and threw.
      - Format-Table inside a function races Read-Host (prompt appears first).
      - REMOVE / REVERT used -ceq / -cne with no trim, so a trailing space
        silently became a dry run or cancelled the revert.
      - The backup row was written AFTER Set-ADUser. A failed Export-Csv was
        logged as FAILED even though scriptPath was already cleared, and the
        user was missing from the revert file.
      - $PSScriptRoot is empty when the script is pasted or ISE-run, so the
        output folder default broke.
      - The file-picker owner form never created a handle, so the dialog often
        opened behind the console.
      - Multiple UPN/mail hits were treated as one object; $u.scriptPath then
        became an array (and if (@($null,$null)) is true in PowerShell).
      - Restore compared scriptPath with -ne (case-sensitive).
      - Column pick 0 selected the last column ($cols[-1]); a name throwed.
      - No recommended column + Enter processed an empty list with no error.
      - Revert's comma-split broke a pasted distinguishedName.
      - #Requires -Modules ActiveDirectory blocked -SelfTest and hid a friendly
        "install RSAT" error.
      - Confirmation / lookup helpers now trim BOM, quotes, NBSP and CR.

.PARAMETER Out
    Folder for the log and backup CSV. Default: <script folder>\LogonScriptCleanup

.PARAMETER SelfTest
    Run helper-function tests (no Active Directory required) and exit 0/1.

.PARAMETER SkipMain
    Load functions only; do not start the menu.

.EXAMPLE
    .\Manage-ADLogonScript.ps1

.EXAMPLE
    .\Manage-ADLogonScript.ps1 -Out D:\ADChanges\LogonScripts

.EXAMPLE
    .\Manage-ADLogonScript.ps1 -SelfTest
#>
[CmdletBinding()]
param(
    [string]$Out,
    [switch]$SelfTest,
    [switch]$SkipMain
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:OutParam = $Out
$script:Out = $null
$script:Stamp = $null
$script:LogFile = $null
$script:Pdc = $null
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding $false

# ---------------------------------------------------------------------------
# Small helpers (no Active Directory)
# ---------------------------------------------------------------------------

function ConvertTo-CleanIdentityValue {
    param([AllowEmptyString()]$Value)

    if ($null -eq $Value) { return '' }
    $clean = [string]$Value
    $clean = $clean.Trim().Trim('"').Trim("'")
    $clean = $clean -replace "^\uFEFF", ''
    $clean = $clean -replace '\u00A0', ' '
    $clean = $clean -replace '[\u200B-\u200D\u2060]', ''
    $clean = $clean -replace '[\r\n]+', ''
    return $clean.Trim()
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

function ConvertTo-EscapedAdFilterString {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    if ($null -eq $Value) { return '' }
    return $Value.Replace("'", "''")
}

function Test-ConfirmationPhrase {
    param(
        [AllowEmptyString()][string]$Typed,
        [Parameter(Mandatory)][string]$Expected
    )

    $clean = ConvertTo-CleanIdentityValue -Value $Typed
    return [string]::Equals($clean, $Expected, [System.StringComparison]::Ordinal)
}

function Test-ScriptPathEqual {
    param([AllowEmptyString()][string]$Left, [AllowEmptyString()][string]$Right)

    $a = if ($null -eq $Left)  { '' } else { $Left.Trim() }
    $b = if ($null -eq $Right) { '' } else { $Right.Trim() }
    return [string]::Equals($a, $b, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-HasLogonScript {
    param($User)

    $path = Get-NotePropertyValue -Object $User -Name 'scriptPath'
    return -not [string]::IsNullOrWhiteSpace([string]$path)
}

function Get-RemoveDecision {
    param($User)

    # Original bug: a $null Get-ADUser -Filter result was treated as "no script"
    # because ($null).scriptPath is $null / falsy. Keep this decision table
    # explicit so a miss cannot be classified as SkipNoScript.
    if ($null -eq $User) { return 'NotFound' }
    if (-not (Test-HasLogonScript -User $User)) { return 'SkipNoScript' }
    return 'Remove'
}

function Test-IsIdentityNotFound {
    param($ErrorRecord)

    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $ErrorRecord.Exception
    } else {
        $ErrorRecord
    }
    if ($null -eq $ex) { return $false }

    $msg = [string]$ex.Message
    # StrictMode "property Filter cannot be found" must not look like AD miss.
    if ($msg -match "property\s+'?Filter'?\s+cannot be found") { return $false }

    $name = $ex.GetType().FullName
    if ($name -match 'ADIdentityNotFound|ItemNotFound') { return $true }
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        if ([string]$ErrorRecord.FullyQualifiedErrorId -match 'ADIdentityNotFound') { return $true }
    }
    if ($msg -match '(?i)cannot find (an? )?(object|user)|user not found|no user with') { return $true }
    return $false
}

function ConvertTo-AdLookup {
    param([AllowEmptyString()][string]$Value)

    $raw = ConvertTo-CleanIdentityValue -Value $Value
    $result = [ordered]@{
        Kind           = 'Empty'
        Identity       = $null
        FilterEmail    = $null
        SamAccountName = $null
        InputValue     = $raw
    }
    if ([string]::IsNullOrWhiteSpace($raw)) { return [pscustomobject]$result }

    $guid = [guid]::Empty
    if ([guid]::TryParse($raw, [ref]$guid)) {
        $result.Kind = 'GUID'
        $result.Identity = $guid
        return [pscustomobject]$result
    }

    if ($raw -match '^S-\d-\d+(-\d+)+$') {
        $result.Kind = 'SID'
        $result.Identity = $raw
        return [pscustomobject]$result
    }

    # Distinguished names first: they may contain '\,' escapes. The original
    # '$id -replace ''^.*\\''' would strip everything through the last slash.
    if ($raw -match '^[A-Za-z]{1,3}=.+,.+=') {
        $result.Kind = 'DN'
        $result.Identity = $raw
        return [pscustomobject]$result
    }

    if ($raw -match '^[^@\s]+@[^@\s]+$') {
        $result.Kind = 'Filter'
        $result.FilterEmail = $raw
        $result.SamAccountName = $raw.Split('@')[0]
        return [pscustomobject]$result
    }

    if ($raw -match '^[^\\/=,]+\\[^\\/=,]+$') {
        $result.Kind = 'NT4'
        $result.Identity = $raw.Split('\')[-1]
        $result.SamAccountName = $result.Identity
        return [pscustomobject]$result
    }

    $result.Kind = 'SAM'
    $result.Identity = $raw
    $result.SamAccountName = $raw
    return [pscustomobject]$result
}

function Split-IdentityList {
    param([AllowEmptyString()][string]$Raw)

    $raw = ConvertTo-CleanIdentityValue -Value $Raw
    if (-not $raw) { return }
    if ($raw -match '^[A-Za-z]{1,3}=.+,.+=') { $raw; return }
    $raw -split '\s*,\s*' |
        ForEach-Object { ConvertTo-CleanIdentityValue -Value $_ } |
        Where-Object { $_ }
}

function Get-RecommendedCsvColumn {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Columns)

    $ranked = @(
        '^(samaccountname|samaccount|sam)$',
        '^(username|user|accountname|account|loginname|login|logonname|identity)$',
        '^(userprincipalname|upn)$',
        '^(emailaddress|email|mail)$',
        '^(distinguishedname|dn)$',
        '^(objectguid|guid)$',
        '^(objectsid|sid)$'
    )
    foreach ($pattern in $ranked) {
        $hit = $Columns | Where-Object { $_ -and $_ -match $pattern } | Select-Object -First 1
        if ($hit) { return [string]$hit }
    }
    return $null
}

function Resolve-CsvColumn {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Columns,
        [AllowEmptyString()][string]$Pick,
        [string]$Default
    )

    $pick = ConvertTo-CleanIdentityValue -Value $Pick
    if (-not $pick) {
        if ($Default) { return $Default }
        throw 'No identity column selected (no recommended header and nothing typed).'
    }

    $number = 0
    if ([int]::TryParse($pick, [ref]$number)) {
        if ($number -ge 1 -and $number -le $Columns.Count) { return $Columns[$number - 1] }
        throw "Column number $number is out of range (1-$($Columns.Count))."
    }

    $byName = $Columns | Where-Object { $_ -ieq $pick } | Select-Object -First 1
    if ($byName) { return [string]$byName }
    throw "Unknown column '$pick'."
}

function Test-BackupIdentityMatch {
    param($Entry, [Parameter(Mandatory)][string]$Token)

    $lookup = ConvertTo-AdLookup -Value $Token
    $sam  = [string](Get-NotePropertyValue -Object $Entry -Name 'SamAccountName' -Default '')
    $guid = [string](Get-NotePropertyValue -Object $Entry -Name 'ObjectGUID' -Default '')

    if ($lookup.Kind -eq 'GUID' -and $guid -and $guid -ieq ([string]$lookup.Identity)) { return $true }
    if ($lookup.SamAccountName -and $sam -and $sam -ieq $lookup.SamAccountName) { return $true }
    if ($lookup.Identity -is [string] -and $sam -and $sam -ieq $lookup.Identity) { return $true }
    if ($sam -and $sam -ieq $lookup.InputValue) { return $true }
    if ($guid -and $guid -ieq $lookup.InputValue) { return $true }
    return $false
}

function Get-BackupEntries {
    param($Rows)

    $valid = @(foreach ($row in @($Rows)) {
        $sam  = ConvertTo-CleanIdentityValue -Value (Get-NotePropertyValue -Object $row -Name 'SamAccountName')
        $path = ConvertTo-CleanIdentityValue -Value (Get-NotePropertyValue -Object $row -Name 'OriginalScriptPath')
        if (-not $sam -or -not $path) { continue }

        $status = ConvertTo-CleanIdentityValue -Value (Get-NotePropertyValue -Object $row -Name 'Status')
        if ($status -and $status -notmatch '^(Removed|Cleared|Success)') { continue }

        [pscustomobject]@{
            SamAccountName     = $sam
            ObjectGUID         = ConvertTo-CleanIdentityValue -Value (Get-NotePropertyValue -Object $row -Name 'ObjectGUID')
            OriginalScriptPath = $path
            RemovedOn          = ConvertTo-CleanIdentityValue -Value (Get-NotePropertyValue -Object $row -Name 'RemovedOn')
        }
    })
    if ($valid.Count -eq 0) { return }

    # Sort-Object on ISO-8601 's' timestamps is chronological. Group[0] after
    # an ascending sort is the earliest row = the true original scriptPath.
    $valid | Sort-Object RemovedOn | Group-Object SamAccountName | ForEach-Object { $_.Group[0] }
}

# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

function Write-Log {
    param([string]$Message)

    $line = '{0:s} {1}' -f (Get-Date), $Message
    Write-Host $line
    if ($script:LogFile) {
        $dir = Split-Path -Parent $script:LogFile
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            $null = New-Item -Path $dir -ItemType Directory -Force
        }
        [System.IO.File]::AppendAllText($script:LogFile, "$line`r`n", $script:Utf8NoBom)
    }
}

function Show-Table {
    param($InputObject, [string[]]$Property)

    $rows = @($InputObject)
    if ($rows.Count -eq 0) {
        Write-Host '(none)'
        return
    }
    # Format-Table must be forced to the host. Inside a function the format
    # objects otherwise sit on the success pipeline and the next Read-Host
    # prompt appears before the table.
    $rows | Format-Table -Property $Property -AutoSize | Out-Host
}

function Import-CsvSafe {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    $Path = ConvertTo-CleanIdentityValue -Value $Path
    if (-not $Path) { throw 'No CSV path was provided (file picker cancelled?).' }
    if (-not (Test-Path -LiteralPath $Path)) { throw "CSV not found: $Path" }

    $firstLine = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop
    $comma = ([regex]::Matches([string]$firstLine, ',')).Count
    $semi  = ([regex]::Matches([string]$firstLine, ';')).Count
    $delimiter = if ($semi -gt $comma) { ';' } else { ',' }

    $rows = $null
    try {
        $rows = @(Import-Csv -LiteralPath $Path -Delimiter $delimiter -Encoding UTF8)
    } catch {
        $rows = @(Import-Csv -LiteralPath $Path -Delimiter $delimiter)
    }
    $rows | Where-Object { $_ }
}

function Write-BackupRow {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Row
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -Path $dir -ItemType Directory -Force
    }
    $Row | Export-Csv -LiteralPath $Path -Append -NoTypeInformation -Encoding UTF8
}

function Pick-Csv {
    param([string]$Title)

    $picked = $null
    try {
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = $Title
        $dialog.Filter = 'CSV (*.csv)|*.csv|All files (*.*)|*.*'
        if ($script:Out -and (Test-Path -LiteralPath $script:Out)) {
            $dialog.InitialDirectory = $script:Out
        }
        $owner = New-Object System.Windows.Forms.Form
        $owner.TopMost = $true
        $owner.ShowInTaskbar = $false
        $owner.Opacity = 0
        $owner.Show()
        try {
            if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
                $picked = $dialog.FileName
            }
        } finally {
            $owner.Hide()
            $owner.Dispose()
            $dialog.Dispose()
        }
    } catch {
        $picked = ConvertTo-CleanIdentityValue -Value (Read-Host "$Title (full path, Enter to cancel)")
    }

    if (-not $picked) { return $null }
    return $picked
}

function Get-Ids {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Column,
        [switch]$AutoSelect
    )

    $rows = @(Import-CsvSafe -Path $Path)
    if ($rows.Count -eq 0) { throw "CSV has headers but no data rows: $Path" }

    $columns = @($rows[0].PSObject.Properties.Name)
    if ($columns.Count -eq 0) { throw "CSV has no columns: $Path" }
    $default = Get-RecommendedCsvColumn -Columns $columns

    if ($AutoSelect) {
        $chosen = if ($Column) {
            Resolve-CsvColumn -Columns $columns -Pick $Column -Default $default
        } elseif ($default) {
            $default
        } else {
            $columns[0]
        }
    } elseif ($Column) {
        $chosen = Resolve-CsvColumn -Columns $columns -Pick $Column -Default $default
    } else {
        for ($i = 0; $i -lt $columns.Count; $i++) {
            $mark = if ($default -and $columns[$i] -eq $default) { ' (recommended)' } else { '' }
            Write-Host ("  [{0}] {1}{2}" -f ($i + 1), $columns[$i], $mark)
        }
        $label = if ($default) { $default } else { 'none — type a number or name' }
        $pick = Read-Host "Column to key on [Enter = $label]"
        $chosen = Resolve-CsvColumn -Columns $columns -Pick $pick -Default $default
    }

    $seen = @{}
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($row in $rows) {
        $value = ConvertTo-CleanIdentityValue -Value (Get-NotePropertyValue -Object $row -Name $chosen)
        if (-not $value) { continue }
        $key = $value.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $ids.Add($value)
    }
    foreach ($id in $ids) { $id }
}

function Read-ConfirmPhrase {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string]$Expected
    )

    $typed = Read-Host $Prompt
    $ok = Test-ConfirmationPhrase -Typed $typed -Expected $Expected
    if (-not $ok) {
        $clean = ConvertTo-CleanIdentityValue -Value $typed
        Write-Host ("  Expected exactly {0}. Received '{1}' ({2} character(s))." -f $Expected, $clean, $clean.Length) -ForegroundColor Yellow
    }
    return $ok
}

# ---------------------------------------------------------------------------
# Active Directory
# ---------------------------------------------------------------------------

function Initialize-Session {
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    if ($script:OutParam) {
        $script:Out = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($script:OutParam)
    } else {
        $script:Out = Join-Path -Path $root -ChildPath 'LogonScriptCleanup'
    }
    $script:Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:LogFile = Join-Path -Path $script:Out -ChildPath ("LogonScript_{0}.log" -f $script:Stamp)
}

function Initialize-AdTarget {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        throw 'The ActiveDirectory module is not installed or could not be loaded. Install RSAT or run this on a domain controller.'
    }

    $domain = Get-ADDomain
    # Read the property directly. Never pipe a [string] into Select-Object —
    # strings enumerate as characters and used to truncate the DC to 1 letter.
    $script:Pdc = [string]$domain.PDCEmulator
    if ([string]::IsNullOrWhiteSpace($script:Pdc)) {
        throw 'Get-ADDomain returned an empty PDCEmulator.'
    }
}

function Find-User {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Id)

    $lookup = ConvertTo-AdLookup -Value $Id
    if ($lookup.Kind -eq 'Empty') { throw 'Empty identity.' }

    if ($lookup.Kind -eq 'Filter') {
        $escaped = ConvertTo-EscapedAdFilterString -Value $lookup.FilterEmail
        $hits = @(Get-ADUser -Server $script:Pdc -Filter "UserPrincipalName -eq '$escaped' -or mail -eq '$escaped'" -Properties scriptPath, Enabled)
        if ($hits.Count -eq 0) {
            throw (New-Object System.Management.Automation.ItemNotFoundException ("No user with UPN or mail '{0}'." -f $lookup.FilterEmail))
        }
        if ($hits.Count -gt 1) {
            $sams = @($hits | ForEach-Object { $_.SamAccountName }) -join ', '
            throw "Multiple users match UPN/mail '$($lookup.FilterEmail)': $sams"
        }
        return $hits[0]
    }

    return Get-ADUser -Identity $lookup.Identity -Server $script:Pdc -Properties scriptPath, Enabled
}

function Remove-Scripts {
    $path = Pick-Csv -Title 'Select user CSV'
    if (-not $path) {
        Write-Log 'Remove cancelled: no CSV selected.'
        return
    }

    $ids = @(Get-Ids -Path $path)
    if ($ids.Count -eq 0) {
        Write-Log "No identities found in $path"
        return
    }

    $users = New-Object System.Collections.Generic.List[object]
    foreach ($id in $ids) {
        try {
            $user = Find-User -Id $id
            switch (Get-RemoveDecision -User $user) {
                'Remove'       { $users.Add($user) }
                'SkipNoScript' { Write-Log "SKIP $id (no logon script)" }
                'NotFound'     { Write-Log "NOT FOUND $id" }
            }
        } catch {
            if (Test-IsIdentityNotFound -ErrorRecord $_) {
                Write-Log "NOT FOUND $id : $($_.Exception.Message)"
            } else {
                Write-Log "FAILED lookup $id : $($_.Exception.Message)"
            }
        }
    }

    if ($users.Count -eq 0) {
        Write-Log 'No users with a logon script.'
        return
    }

    Show-Table -InputObject $users -Property @('SamAccountName', 'Name', 'Enabled', 'scriptPath')
    $live = Read-ConfirmPhrase -Prompt "$($users.Count) user(s) have a logon script. Type REMOVE for a live run (anything else = dry run)" -Expected 'REMOVE'
    $backupPath = Join-Path -Path $script:Out -ChildPath ("LogonScriptBackup_{0}.csv" -f $script:Stamp)

    foreach ($user in $users) {
        $sam  = [string]$user.SamAccountName
        $orig = [string](Get-NotePropertyValue -Object $user -Name 'scriptPath')
        $guid = [string]$user.ObjectGUID
        if (-not $live) {
            Write-Log "DRYRUN would clear $sam ($orig)"
            continue
        }

        $record = [pscustomobject]@{
            SamAccountName     = $sam
            ObjectGUID         = $guid
            OriginalScriptPath = $orig
            RemovedOn          = Get-Date -Format s
            Status             = 'Removed'
        }

        # Backup first. If this throws, the AD attribute is left untouched.
        try {
            Write-BackupRow -Path $backupPath -Row $record
        } catch {
            Write-Log "FAILED $sam original=$orig guid=$guid : backup write failed; AD not changed. $($_.Exception.Message)"
            continue
        }

        try {
            Set-ADUser -Identity $user.ObjectGUID -Server $script:Pdc -Clear scriptPath -Confirm:$false
            Write-Log "REMOVED $sam ($orig)"
        } catch {
            Write-Log "FAILED $sam original=$orig guid=$guid : AD change failed (row is in the backup). $($_.Exception.Message)"
        }
    }
}

function Restore-Scripts {
    $path = Pick-Csv -Title 'Select backup CSV'
    if (-not $path) {
        Write-Log 'Revert cancelled: no CSV selected.'
        return
    }

    $rows = @(Get-BackupEntries -Rows @(Import-CsvSafe -Path $path))
    if ($rows.Count -eq 0) {
        Write-Log "No restorable rows in $path"
        return
    }

    $only = @(Split-IdentityList -Raw (Read-Host 'Only these users (comma-separated SAM/UPN/GUID, Enter = all)'))
    if ($only.Count -gt 0) {
        # @(foreach) so zero matches stay an empty array, not @($null).
        $filtered = @(foreach ($entry in $rows) {
            foreach ($token in $only) {
                if (Test-BackupIdentityMatch -Entry $entry -Token $token) { $entry; break }
            }
        })
        $rows = @($filtered)
        $unmatched = @(foreach ($token in $only) {
            $hit = $false
            foreach ($entry in $rows) {
                if (Test-BackupIdentityMatch -Entry $entry -Token $token) { $hit = $true; break }
            }
            if (-not $hit) { $token }
        })
        foreach ($token in $unmatched) {
            Write-Log "NOT IN BACKUP $token"
        }
    }

    if ($rows.Count -eq 0) {
        Write-Log 'No backup rows match the requested users.'
        return
    }

    Show-Table -InputObject $rows -Property @('SamAccountName', 'OriginalScriptPath', 'RemovedOn')
    if (-not (Read-ConfirmPhrase -Prompt "Type REVERT to restore $($rows.Count) user(s)" -Expected 'REVERT')) {
        Write-Log 'Revert cancelled: confirmation did not match REVERT.'
        return
    }

    $forceRaw = ConvertTo-CleanIdentityValue -Value (Read-Host 'Overwrite users whose scriptPath changed since removal? (y/N)')
    $force = $forceRaw -eq 'y'

    foreach ($row in $rows) {
        try {
            $identity = if ($row.ObjectGUID) { $row.ObjectGUID } else { $row.SamAccountName }
            $user = Get-ADUser -Identity $identity -Server $script:Pdc -Properties scriptPath
            $current = [string](Get-NotePropertyValue -Object $user -Name 'scriptPath')
            if ($current -and -not (Test-ScriptPathEqual -Left $current -Right $row.OriginalScriptPath) -and -not $force) {
                Write-Log "SKIP $($row.SamAccountName): changed to $current"
                continue
            }
            if (Test-ScriptPathEqual -Left $current -Right $row.OriginalScriptPath) {
                Write-Log "SKIP $($row.SamAccountName): already $($row.OriginalScriptPath)"
                continue
            }
            Set-ADUser -Identity $user.ObjectGUID -Server $script:Pdc -Replace @{ scriptPath = $row.OriginalScriptPath } -Confirm:$false
            Write-Log "RESTORED $($row.SamAccountName) ($($row.OriginalScriptPath))"
        } catch {
            Write-Log "FAILED $($row.SamAccountName) : $($_.Exception.Message)"
        }
    }
}

function Show-MainMenu {
    Write-Log "Started by $env:USERDOMAIN\$env:USERNAME against PDC $($script:Pdc)"
    while ($true) {
        try {
            $choice = ConvertTo-CleanIdentityValue -Value (Read-Host "`n[1] Remove logon scripts  [2] Revert  [3] Open output folder  [Q] Quit")
            switch ($choice) {
                '1' { Remove-Scripts }
                '2' { Restore-Scripts }
                '3' {
                    if (-not (Test-Path -LiteralPath $script:Out)) {
                        $null = New-Item -Path $script:Out -ItemType Directory -Force
                    }
                    Invoke-Item -LiteralPath $script:Out
                }
                'q' { return }
                ''  { }
                default { Write-Host "Unknown choice: $choice" }
            }
        } catch {
            Write-Log "ERROR: $($_.Exception.Message)"
        }
    }
}

# ---------------------------------------------------------------------------
# Self-test (no Active Directory)
# ---------------------------------------------------------------------------

function Invoke-SelfTest {
    function Assert-True {
        param([bool]$Condition, [string]$Name)
        if ($Condition) {
            $script:SelfTestPassed++
            Write-Host "  PASS  $Name" -ForegroundColor Green
        } else {
            $script:SelfTestFailed++
            Write-Host "  FAIL  $Name" -ForegroundColor Red
        }
    }

    $script:SelfTestPassed = 0
    $script:SelfTestFailed = 0
    $testRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("LogonScriptSelfTest-{0}" -f [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $testRoot -ItemType Directory -Force
    $script:Out = $testRoot
    $script:LogFile = Join-Path -Path $testRoot -ChildPath 'selftest.log'
    $script:Stamp = 'selftest'

    Write-Host ''
    Write-Host 'Manage-ADLogonScript self-test' -ForegroundColor Cyan
    Write-Host ''

    Assert-True -Condition ((ConvertTo-CleanIdentityValue -Value "  `"aalosman`"  ") -eq 'aalosman') -Name 'ConvertTo-CleanIdentityValue trims quotes and whitespace'
    Assert-True -Condition ((ConvertTo-CleanIdentityValue -Value " REMOVE`r ") -eq 'REMOVE') -Name 'ConvertTo-CleanIdentityValue strips trailing CR'
    Assert-True -Condition ((ConvertTo-EscapedAdFilterString -Value "O'Brien") -eq "O''Brien") -Name 'ConvertTo-EscapedAdFilterString doubles single quotes'

    Assert-True -Condition (Test-ConfirmationPhrase -Typed " REMOVE`r " -Expected 'REMOVE') -Name 'Test-ConfirmationPhrase accepts REMOVE with trailing whitespace/CR'
    Assert-True -Condition (-not (Test-ConfirmationPhrase -Typed 'remove' -Expected 'REMOVE')) -Name 'Test-ConfirmationPhrase still requires capital REMOVE'
    Assert-True -Condition (Test-ConfirmationPhrase -Typed 'REVERT' -Expected 'REVERT') -Name 'Test-ConfirmationPhrase accepts exact REVERT'

    Assert-True -Condition (Test-ScriptPathEqual -Left 'Logon.bat' -Right 'logon.BAT') -Name 'Test-ScriptPathEqual is case-insensitive'
    Assert-True -Condition (Test-ScriptPathEqual -Left '  scripts\logon.bat  ' -Right 'scripts\logon.bat') -Name 'Test-ScriptPathEqual trims whitespace'
    Assert-True -Condition (-not (Test-ScriptPathEqual -Left 'a.bat' -Right 'b.bat')) -Name 'Test-ScriptPathEqual detects different values'

    Assert-True -Condition ((Get-RemoveDecision -User $null) -eq 'NotFound') -Name 'Get-RemoveDecision classifies a null lookup as NotFound (not SkipNoScript)'
    Assert-True -Condition ((Get-RemoveDecision -User ([pscustomobject]@{ scriptPath = $null })) -eq 'SkipNoScript') -Name 'Get-RemoveDecision classifies a null scriptPath as SkipNoScript'
    Assert-True -Condition ((Get-RemoveDecision -User ([pscustomobject]@{ scriptPath = '' })) -eq 'SkipNoScript') -Name 'Get-RemoveDecision classifies a blank scriptPath as SkipNoScript'
    Assert-True -Condition ((Get-RemoveDecision -User ([pscustomobject]@{ scriptPath = 'logon.bat' })) -eq 'Remove') -Name 'Get-RemoveDecision classifies a set scriptPath as Remove'

    $propertyMissing = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.ArgumentException "The property 'Filter' cannot be found on this object. Verify that the property exists."),
        'PropertyNotFoundStrict',
        [System.Management.Automation.ErrorCategory]::InvalidOperation,
        1
    )
    Assert-True -Condition (-not (Test-IsIdentityNotFound -ErrorRecord $propertyMissing)) -Name 'Test-IsIdentityNotFound does not treat StrictMode Filter-property errors as AD not-found'

    $notFound = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.Management.Automation.ItemNotFoundException 'No user with UPN or mail ''missing@contoso.com''.'),
        'ItemNotFound',
        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
        'missing@contoso.com'
    )
    Assert-True -Condition (Test-IsIdentityNotFound -ErrorRecord $notFound) -Name 'Test-IsIdentityNotFound recognises a filter miss thrown as ItemNotFoundException'

    $sam = ConvertTo-AdLookup -Value 'jsmith'
    Assert-True -Condition ($sam.Kind -eq 'SAM' -and $sam.Identity -eq 'jsmith') -Name 'ConvertTo-AdLookup parses sAMAccountName'

    $nt4 = ConvertTo-AdLookup -Value 'CONTOSO\jsmith'
    Assert-True -Condition ($nt4.Kind -eq 'NT4' -and $nt4.Identity -eq 'jsmith') -Name 'ConvertTo-AdLookup parses DOMAIN\user and keeps only the SAM'

    $upn = ConvertTo-AdLookup -Value 'john.smith@contoso.com'
    Assert-True -Condition ($upn.Kind -eq 'Filter' -and $upn.FilterEmail -eq 'john.smith@contoso.com') -Name 'ConvertTo-AdLookup keeps the full UPN for a -Filter lookup'

    $dn = 'CN=Smith\, John,OU=Users,DC=contoso,DC=com'
    $broken = $dn -replace '^.*\\'
    Assert-True -Condition ($broken -ne $dn -and $broken -like '*John,OU=Users*') -Name 'Original greedy backslash replace still mangles an escaped DN (documented bug)'
    $dnLookup = ConvertTo-AdLookup -Value $dn
    Assert-True -Condition ($dnLookup.Kind -eq 'DN' -and $dnLookup.Identity -eq $dn) -Name 'ConvertTo-AdLookup does not strip backslashes out of a distinguishedName'

    $guid = [guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    $guidLookup = ConvertTo-AdLookup -Value $guid.ToString()
    Assert-True -Condition ($guidLookup.Kind -eq 'GUID' -and $guidLookup.Identity -eq $guid) -Name 'ConvertTo-AdLookup parses a GUID'

    $sid = ConvertTo-AdLookup -Value 'S-1-5-21-1-2-3-1001'
    Assert-True -Condition ($sid.Kind -eq 'SID' -and $sid.Identity -eq 'S-1-5-21-1-2-3-1001') -Name 'ConvertTo-AdLookup parses a SID'

    $quoted = ConvertTo-AdLookup -Value '  "CONTOSO\jsmith"  '
    Assert-True -Condition ($quoted.Kind -eq 'NT4' -and $quoted.Identity -eq 'jsmith') -Name 'ConvertTo-AdLookup cleans quoted DOMAIN\user values'

    Assert-True -Condition ((Get-RecommendedCsvColumn -Columns @('EmployeeID', 'Email', 'Department')) -eq 'Email') -Name 'Get-RecommendedCsvColumn prefers Email over non-identity headers'
    Assert-True -Condition ((Get-RecommendedCsvColumn -Columns @('EmailAddress', 'SamAccountName', 'DisplayName')) -eq 'SamAccountName') -Name 'Get-RecommendedCsvColumn prefers SamAccountName over Email'
    Assert-True -Condition ((Get-RecommendedCsvColumn -Columns @('Dept', 'Title')) -eq $null) -Name 'Get-RecommendedCsvColumn returns null when no identity header exists'

    $cols = @('EmployeeID', 'EmailAddress', 'SamAccountName')
    Assert-True -Condition ((Resolve-CsvColumn -Columns $cols -Pick '' -Default 'SamAccountName') -eq 'SamAccountName') -Name 'Resolve-CsvColumn uses the default on Enter'
    Assert-True -Condition ((Resolve-CsvColumn -Columns $cols -Pick '2' -Default 'SamAccountName') -eq 'EmailAddress') -Name 'Resolve-CsvColumn accepts a 1-based column number'
    Assert-True -Condition ((Resolve-CsvColumn -Columns $cols -Pick 'emailaddress' -Default 'SamAccountName') -eq 'EmailAddress') -Name 'Resolve-CsvColumn accepts a column name'
    $zeroThrew = $false
    try { Resolve-CsvColumn -Columns $cols -Pick '0' -Default 'SamAccountName' | Out-Null } catch { $zeroThrew = $true }
    Assert-True -Condition $zeroThrew -Name 'Resolve-CsvColumn rejects 0 (does not wrap to the last column)'

    $noDefaultThrew = $false
    try { Resolve-CsvColumn -Columns @('Dept', 'Title') -Pick '' -Default $null | Out-Null } catch { $noDefaultThrew = $true }
    Assert-True -Condition $noDefaultThrew -Name 'Resolve-CsvColumn errors when Enter is pressed and there is no recommended column'

    $list = @(Split-IdentityList -Raw 'jsmith, ajones')
    Assert-True -Condition ($list.Count -eq 2 -and $list[0] -eq 'jsmith' -and $list[1] -eq 'ajones') -Name 'Split-IdentityList splits comma-separated SAM names'
    $dnList = @(Split-IdentityList -Raw $dn)
    Assert-True -Condition ($dnList.Count -eq 1 -and $dnList[0] -eq $dn) -Name 'Split-IdentityList does not split a distinguishedName on commas'
    $emptyList = @(Split-IdentityList -Raw '')
    Assert-True -Condition ($emptyList.Count -eq 0) -Name 'Split-IdentityList returns an empty array for a blank prompt'

    $backupRows = @(
        [pscustomobject]@{ SamAccountName = 'jsmith'; OriginalScriptPath = 'old.bat';  RemovedOn = '2024-01-02T00:00:00' },
        [pscustomobject]@{ SamAccountName = 'jsmith'; OriginalScriptPath = 'newer.bat'; RemovedOn = '2024-06-01T00:00:00' },
        [pscustomobject]@{ SamAccountName = 'ajones'; OriginalScriptPath = 'login.vbs'; RemovedOn = '2024-03-01T00:00:00' },
        [pscustomobject]@{ SamAccountName = '';       OriginalScriptPath = 'x.bat';     RemovedOn = '2024-01-01T00:00:00' }
    )
    $deduped = @(Get-BackupEntries -Rows $backupRows)
    $jsmith = @($deduped | Where-Object { $_.SamAccountName -eq 'jsmith' })[0]
    Assert-True -Condition ($deduped.Count -eq 2) -Name 'Get-BackupEntries drops blank identities and collapses duplicates'
    Assert-True -Condition ([string]$jsmith.OriginalScriptPath -eq 'old.bat') -Name 'Get-BackupEntries keeps the earliest RemovedOn value as the true original'

    $single = @(Get-BackupEntries -Rows @([pscustomobject]@{ SamAccountName = 'onlyme'; OriginalScriptPath = 'one.bat'; RemovedOn = '2024-01-01T00:00:00' }))
    Assert-True -Condition ($single.Count -eq 1 -and $single[0].SamAccountName -eq 'onlyme') -Name 'Get-BackupEntries keeps a single-user backup as a one-element array'

    $mixed = @(Get-BackupEntries -Rows @(
        [pscustomobject]@{ SamAccountName = 'keep'; OriginalScriptPath = 'a.bat'; Status = 'Removed' },
        [pscustomobject]@{ SamAccountName = 'dry';  OriginalScriptPath = 'b.bat'; Status = 'DryRun-WouldRemove' },
        [pscustomobject]@{ SamAccountName = 'skip'; OriginalScriptPath = 'c.bat'; Status = 'Skipped-NoLogonScript' }
    ))
    Assert-True -Condition ($mixed.Count -eq 1 -and $mixed[0].SamAccountName -eq 'keep') -Name 'Get-BackupEntries ignores dry-run and skipped rows when a Status column is present'

    $none = @(Get-BackupEntries -Rows @(
        [pscustomobject]@{ SamAccountName = ''; OriginalScriptPath = 'x.bat' },
        [pscustomobject]@{ SamAccountName = 'dry'; OriginalScriptPath = 'b.bat'; Status = 'DryRun-WouldRemove' }
    ))
    Assert-True -Condition ($none.Count -eq 0) -Name 'Get-BackupEntries returns an empty array when every row is dropped'

    $matchSam = Test-BackupIdentityMatch -Entry $jsmith -Token 'CONTOSO\jsmith'
    $matchMiss = Test-BackupIdentityMatch -Entry $jsmith -Token 'nobody'
    Assert-True -Condition $matchSam -Name 'Test-BackupIdentityMatch matches DOMAIN\user against a SAM backup row'
    Assert-True -Condition (-not $matchMiss) -Name 'Test-BackupIdentityMatch rejects an unknown token'

    $tempCsv = Join-Path -Path $testRoot -ChildPath 'users.csv'
    try {
        [System.IO.File]::WriteAllText($tempCsv, "SamAccountName`r`n", $script:Utf8NoBom)
        $emptyImport = @(Import-CsvSafe -Path $tempCsv)
        Assert-True -Condition ($emptyImport.Count -eq 0) -Name 'Import-CsvSafe returns an empty array for a header-only CSV'
        $emptyThrew = $false
        try { Get-Ids -Path $tempCsv -AutoSelect | Out-Null } catch { $emptyThrew = $_.Exception.Message -match 'no data rows' }
        Assert-True -Condition $emptyThrew -Name 'Get-Ids throws on a header-only CSV instead of indexing $rows[0]'

        $cancelThrew = $false
        try { Import-CsvSafe -Path '' | Out-Null } catch { $cancelThrew = $_.Exception.Message -match 'picker cancelled' }
        Assert-True -Condition $cancelThrew -Name 'Import-CsvSafe explains a cancelled file picker'

        [System.IO.File]::WriteAllText($tempCsv, "SamAccountName`r`nalice`r`nbob`r`nalice`r`n`r`n", $script:Utf8NoBom)
        $loaded = @(Get-Ids -Path $tempCsv -AutoSelect)
        Assert-True -Condition ($loaded.Count -eq 2 -and $loaded[0] -eq 'alice' -and $loaded[1] -eq 'bob') -Name 'Get-Ids de-duplicates and skips blank rows'

        [System.IO.File]::WriteAllText($tempCsv, "EmployeeID,EmailAddress,Department`r`n1,bob.lee@contoso.com,IT`r`n2,ann@contoso.com,HR`r`n", $script:Utf8NoBom)
        $byEmail = @(Get-Ids -Path $tempCsv -AutoSelect)
        Assert-True -Condition ($byEmail.Count -eq 2 -and $byEmail[0] -eq 'bob.lee@contoso.com') -Name 'Get-Ids -AutoSelect keys on EmailAddress when no SAM column exists'

        [System.IO.File]::WriteAllText($tempCsv, "EmployeeID;Email;Dept`r`n1;ann@contoso.com;HR`r`n", $script:Utf8NoBom)
        $semiIds = @(Get-Ids -Path $tempCsv -AutoSelect)
        Assert-True -Condition ($semiIds.Count -eq 1 -and $semiIds[0] -eq 'ann@contoso.com') -Name 'Get-Ids detects a semicolon-delimited CSV'

        $bak = Join-Path -Path $testRoot -ChildPath 'backup.csv'
        Write-BackupRow -Path $bak -Row ([pscustomobject]@{
            SamAccountName = 'jsmith'; ObjectGUID = $guid.ToString(); OriginalScriptPath = 'logon.bat'; RemovedOn = '2024-01-01T00:00:00'; Status = 'Removed'
        })
        $fromDisk = @(Get-BackupEntries -Rows @(Import-CsvSafe -Path $bak))
        Assert-True -Condition ($fromDisk.Count -eq 1 -and $fromDisk[0].OriginalScriptPath -eq 'logon.bat' -and $fromDisk[0].ObjectGUID -eq $guid.ToString()) -Name 'Write-BackupRow round-trips ObjectGUID and OriginalScriptPath'
    } finally {
        if (Test-Path -LiteralPath $testRoot) {
            Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host ''
    Write-Host ("  {0} passed, {1} failed" -f $script:SelfTestPassed, $script:SelfTestFailed) -ForegroundColor $(if ($script:SelfTestFailed) { 'Red' } else { 'Green' })
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
    Initialize-Session
    $null = New-Item -Path $script:Out -ItemType Directory -Force
    Initialize-AdTarget
    Show-MainMenu
} catch {
    Write-Log "Fatal error: $($_.Exception.Message)"
    throw
}

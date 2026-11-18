#Requires -Version 5.1
# Removes / reverts the logon script (scriptPath) on AD users listed in a CSV. All reads/writes target the PDC Emulator.
param([string]$Out, [switch]$SelfTest)
$ErrorActionPreference = 'Stop'
if (-not $Out) { $Out = Join-Path $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }) 'LogonScriptCleanup' }
$stamp = Get-Date -Format yyyyMMdd_HHmmss
$log = Join-Path $Out "LogonScript_$stamp.log"
$pdc = $null

function T($v) {
    if ($null -eq $v) { return '' }
    (([string]$v).Trim().Trim('"').Trim("'") -replace "^\uFEFF" -replace '\u00A0', ' ' -replace '[\u200B-\u200D\u2060]' -replace '[\r\n]+').Trim()
}
function Log($m) { $l = '{0:s} {1}' -f (Get-Date), $m; Write-Host $l; if ($log) { [IO.File]::AppendAllText($log, "$l`r`n") } }
function Look($id) {
    $id = T $id; $g = [guid]::Empty
    if (-not $id) { return @{ K = 'E' } }
    if ([guid]::TryParse($id, [ref]$g)) { return @{ K = 'I'; I = $g } }
    if ($id -match '^S-\d-\d+(-\d+)+$') { return @{ K = 'I'; I = $id } }
    if ($id -match '^[A-Za-z]{1,3}=.+,.+=') { return @{ K = 'I'; I = $id } }   # DN before DOMAIN\user — '\,' must not be stripped
    if ($id -match '@') { return @{ K = 'F'; I = $id } }
    if ($id -match '^[^\\/=,]+\\[^\\/=,]+$') { return @{ K = 'I'; I = ($id -split '\\')[-1] } }
    @{ K = 'I'; I = $id }
}
function Same($e, $tok) {
    $l = Look $tok; $sam = T $e.SamAccountName; $guid = T $e.ObjectGUID
    ($guid -and ($guid -ieq [string]$l.I -or $guid -ieq $tok)) -or ($sam -and ($sam -ieq [string]$l.I -or $sam -ieq $tok))
}
function Csv($path) {
    $path = T $path
    if (-not $path) { throw 'No CSV path (picker cancelled?)' }
    if (-not (Test-Path -LiteralPath $path)) { throw "CSV not found: $path" }
    $h = [string](Get-Content -LiteralPath $path -TotalCount 1)
    $d = if (([regex]::Matches($h, ';')).Count -gt ([regex]::Matches($h, ',')).Count) { ';' } else { ',' }
    $(try { Import-Csv -LiteralPath $path -Delimiter $d -Encoding UTF8 } catch { Import-Csv -LiteralPath $path -Delimiter $d }) | Where-Object { $_ }
}

function Pick-Csv($title) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $dlg = New-Object Windows.Forms.OpenFileDialog -Property @{ Title = $title; Filter = 'CSV (*.csv)|*.csv|All (*.*)|*.*' }
        if (Test-Path $Out) { $dlg.InitialDirectory = $Out }
        $own = New-Object Windows.Forms.Form -Property @{ TopMost = $true; ShowInTaskbar = $false; Opacity = 0 }
        $own.Show()
        try { if ($dlg.ShowDialog($own) -eq 'OK') { $dlg.FileName } } finally { $own.Dispose(); $dlg.Dispose() }
    } catch { T (Read-Host "$title (full path)") }
}

function Find-User($id) {
    $l = Look $id
    if ($l.K -eq 'E') { throw 'Empty identity' }
    if ($l.K -eq 'F') {
        $e = $l.I.Replace("'", "''")
        $h = @(Get-ADUser -Server $pdc -Filter "UserPrincipalName -eq '$e' -or mail -eq '$e'" -Properties scriptPath | Where-Object { $_ })
        if (-not $h.Count) { throw "User not found: $id" }
        if ($h.Count -gt 1) { throw "Multiple users match ${id}: $($h.SamAccountName -join ', ')" }
        return $h[0]
    }
    Get-ADUser -Identity $l.I -Server $pdc -Properties scriptPath
}

function Get-Ids($path, $pick) {
    $rows = @(Csv $path)
    if (-not $rows.Count) { throw "CSV has no data rows: $path" }
    $cols = @($rows[0].PSObject.Properties.Name)
    $def = @('samaccountname','samaccount','sam','username','user','accountname','account','loginname','login','identity','userprincipalname','upn','emailaddress','email','mail','distinguishedname','dn','objectguid','guid','sid') |
        ForEach-Object { $n = $_; $cols | Where-Object { $_ -ieq $n } | Select-Object -First 1 } | Select-Object -First 1
    if (-not $PSBoundParameters.ContainsKey('pick')) {
        for ($i = 0; $i -lt $cols.Count; $i++) { Write-Host "  [$($i + 1)] $($cols[$i])$(if ($cols[$i] -eq $def) { ' *' })" }
        $pick = T (Read-Host "Column to key on [Enter = $def]")
    } else { $pick = T $pick }
    $n = 0
    $col = if (-not $pick) { if (-not $def) { throw 'No identity column' }; $def }
        elseif ([int]::TryParse($pick, [ref]$n)) { if ($n -lt 1 -or $n -gt $cols.Count) { throw "Column $n out of range" }; $cols[$n - 1] }
        else { $c = $cols | Where-Object { $_ -ieq $pick } | Select-Object -First 1; if (-not $c) { throw "Unknown column $pick" }; $c }
    $seen = @{}; foreach ($r in $rows) { $v = T $r.$col; if ($v -and -not $seen.ContainsKey($v.ToLowerInvariant())) { $seen[$v.ToLowerInvariant()] = $v; $v } }
}

function Remove-Scripts {
    $path = Pick-Csv 'Select user CSV'; if (-not $path) { return }
    $users = @(foreach ($id in @(Get-Ids $path)) {
        try {
            $u = Find-User $id
            if ([string]::IsNullOrWhiteSpace([string]$u.scriptPath)) { Log "SKIP $id (no logon script)" } else { $u }
        } catch { Log "NOT FOUND $id : $_" }
    })
    if (-not $users.Count) { return }
    $users | Format-Table SamAccountName, Name, Enabled, scriptPath -AutoSize | Out-Host
    $live = (T (Read-Host "$($users.Count) user(s) have a logon script. Type REMOVE for a live run (anything else = dry run)")) -ceq 'REMOVE'
    $bak = Join-Path $Out "LogonScriptBackup_$stamp.csv"
    foreach ($u in $users) {
        if (-not $live) { Log "DRYRUN would clear $($u.SamAccountName) ($($u.scriptPath))"; continue }
        $row = [pscustomobject]@{ SamAccountName = $u.SamAccountName; ObjectGUID = [string]$u.ObjectGUID; OriginalScriptPath = [string]$u.scriptPath; RemovedOn = Get-Date -Format s }
        try { $row | Export-Csv $bak -Append -NoTypeInformation -Encoding UTF8 } catch { Log "FAILED $($u.SamAccountName) backup; AD not changed : $_"; continue }
        try { Set-ADUser $u.ObjectGUID -Server $pdc -Clear scriptPath -Confirm:$false; Log "REMOVED $($u.SamAccountName) ($($u.scriptPath))" }
        catch { Log "FAILED $($u.SamAccountName) original=$($u.scriptPath) guid=$($u.ObjectGUID) : $_" }
    }
}

function Restore-Scripts {
    $path = Pick-Csv 'Select backup CSV'; if (-not $path) { return }
    $rows = @(Csv $path | Where-Object { T $_.SamAccountName -and T $_.OriginalScriptPath } | Sort-Object RemovedOn | Group-Object SamAccountName | ForEach-Object { $_.Group[0] })
    $raw = T (Read-Host 'Only these users (comma-separated, Enter = all)')
    if ($raw) {
        $only = @(if ($raw -match '^[A-Za-z]{1,3}=.+,.+=') { $raw } else { $raw -split '\s*,\s*' | ForEach-Object { T $_ } | Where-Object { $_ } })
        $rows = @(foreach ($e in $rows) { foreach ($t in $only) { if (Same $e $t) { $e; break } } })
    }
    if (-not $rows.Count) { return }
    $rows | Format-Table SamAccountName, OriginalScriptPath, RemovedOn -AutoSize | Out-Host
    if ((T (Read-Host "Type REVERT to restore $($rows.Count) user(s)")) -cne 'REVERT') { return }
    $force = (T (Read-Host 'Overwrite users whose scriptPath changed since removal? (y/N)')) -eq 'y'
    foreach ($r in $rows) {
        try {
            $u = Get-ADUser $(if (T $r.ObjectGUID) { T $r.ObjectGUID } else { $r.SamAccountName }) -Server $pdc -Properties scriptPath
            $cur = [string]$u.scriptPath
            if ($cur -and $cur -ine $r.OriginalScriptPath -and -not $force) { Log "SKIP $($r.SamAccountName): changed to $cur"; continue }
            Set-ADUser $u -Server $pdc -Replace @{ scriptPath = $r.OriginalScriptPath } -Confirm:$false
            Log "RESTORED $($r.SamAccountName) ($($r.OriginalScriptPath))"
        } catch { Log "FAILED $($r.SamAccountName) : $_" }
    }
}

if ($SelfTest) {
    $script:n = 0; $script:f = 0
    function A($c, $m) { $script:n++; if ($c) { Write-Host "  PASS  $m" -ForegroundColor Green } else { $script:f++; Write-Host "  FAIL  $m" -ForegroundColor Red } }
    $dn = 'CN=Smith\, John,OU=Users,DC=contoso,DC=com'
    A ((T "  `"x`"  ") -eq 'x' -and (T " REMOVE`r ") -eq 'REMOVE') 'T trims quotes/CR'
    A ((Look 'CONTOSO\jsmith').I -eq 'jsmith') 'DOMAIN\user -> SAM'
    A ((Look 'a@b.com').K -eq 'F' -and (Look 'a@b.com').I -eq 'a@b.com') 'UPN kept for -Filter'
    A ((($dn -replace '^.*\\') -like '*John,OU=*') -and (Look $dn).I -eq $dn) 'DN not stripped'
    A ((Look 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee').K -eq 'I') 'GUID'
    A ((Look 'S-1-5-21-1-2-3-1001').I -eq 'S-1-5-21-1-2-3-1001') 'SID'
    A ((T ' REMOVE ') -ceq 'REMOVE' -and (T 'remove') -cne 'REMOVE') 'REMOVE trim + case'
    A (Same ([pscustomobject]@{ SamAccountName = 'jsmith'; ObjectGUID = '' }) 'CONTOSO\jsmith') 'subset matches DOMAIN\user'
    $dir = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid()); $null = New-Item $dir -ItemType Directory
    try {
        $csv = Join-Path $dir 'u.csv'
        [IO.File]::WriteAllText($csv, "SamAccountName`r`n")
        A ((@(Csv $csv)).Count -eq 0) 'header-only CSV'
        $threw = $false; try { Get-Ids $csv | Out-Null } catch { $threw = "$_" -match 'no data rows' }; A $threw 'Get-Ids rejects empty CSV'
        $threw = $false; try { Csv '' | Out-Null } catch { $threw = "$_" -match 'cancelled' }; A $threw 'cancelled picker'
        [IO.File]::WriteAllText($csv, "SamAccountName`r`nalice`r`nbob`r`nalice`r`n")
        $ids = @(Get-Ids $csv SamAccountName); A ($ids.Count -eq 2 -and $ids[0] -eq 'alice') 'Get-Ids unique'
        [IO.File]::WriteAllText($csv, "EmployeeID,EmailAddress`r`n1,a@b.com`r`n")
        A ((@(Get-Ids $csv '')).Count -eq 1 -and (@(Get-Ids $csv ''))[0] -eq 'a@b.com') 'default EmailAddress'
        [IO.File]::WriteAllText($csv, "EmployeeID;Email;Dept`r`n1;a@b.com;HR`r`n")
        A ((@(Get-Ids $csv ''))[0] -eq 'a@b.com') 'semicolon CSV'
        $bak = Join-Path $dir 'b.csv'
        [pscustomobject]@{ SamAccountName = 'jsmith'; OriginalScriptPath = 'old.bat'; RemovedOn = '2024-01-01T00:00:00' },
        [pscustomobject]@{ SamAccountName = 'jsmith'; OriginalScriptPath = 'new.bat'; RemovedOn = '2024-06-01T00:00:00' } |
            Export-Csv $bak -NoTypeInformation -Encoding UTF8
        $b = @(Csv $bak | Where-Object { T $_.OriginalScriptPath } | Sort-Object RemovedOn | Group-Object SamAccountName | ForEach-Object { $_.Group[0] })
        A ($b.Count -eq 1 -and $b[0].OriginalScriptPath -eq 'old.bat') 'earliest backup wins'
    } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "  $($script:n - $script:f) passed, $($script:f) failed"
    exit $(if ($script:f) { 1 } else { 0 })
}

$null = New-Item $Out -ItemType Directory -Force
Import-Module ActiveDirectory -ErrorAction Stop
$pdc = [string](Get-ADDomain).PDCEmulator
if (-not $pdc) { throw 'Get-ADDomain returned an empty PDCEmulator' }
Log "Started by $env:USERDOMAIN\$env:USERNAME against PDC $pdc"
while ($true) {
    try {
        switch (T (Read-Host "`n[1] Remove logon scripts  [2] Revert  [3] Open output folder  [Q] Quit")) {
            '1' { Remove-Scripts } '2' { Restore-Scripts } '3' { Invoke-Item $Out } 'q' { return }
        }
    } catch { Log "ERROR: $_" }
}

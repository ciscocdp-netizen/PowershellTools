#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication
<#
================================================================================
 SCRIPT : Get-DeviceLapsPassword.ps1
 PURPOSE: Look up the current Windows LAPS password from Entra ID.
 AUTHOR : Anthony Blake
 UPDATED: 2026-11-12
 COMPAT : Windows PowerShell 5.1
================================================================================

.SYNOPSIS
    Interactive Windows LAPS password checkout from Entra ID.

.DESCRIPTION
    Run with no parameters. Enter a computer name. The script signs in with
    an app certificate (no browser, no user login) and reads the password
    that Windows LAPS backed up to Entra ID.

    Required Graph APPLICATION permission (admin consent):
        DeviceLocalCredential.Read.All

.EXAMPLE
    .\Get-DeviceLapsPassword.ps1
    .\LAPsPassAzure.ps1
    .\Get-DeviceLapsPassword.ps1 -ComputerName 015CD415BR20
#>
[CmdletBinding()]
param(
    [string]$ComputerName,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

#region ### 1. CONFIGURATION ###################################################

$TenantId              = if ($TenantId) { $TenantId } else { 'e18c199f-7bc4-489e-b810-eddee385899b' }
$ClientId              = if ($ClientId) { $ClientId } else { 'ea1351f4-ccb0-488d-8be6-a2be7b929894' }
$CertificateThumbprint = if ($CertificateThumbprint) { $CertificateThumbprint } else { 'CA226E648AE75DEFEE298111D8DC4A1E33E34A3B' }

$Graph = 'https://graph.microsoft.com/v1.0'

#endregion

#region ### 2. HELPERS #########################################################

function Write-Banner {
    $rule = ('=' * 72)
    Write-Host ''
    Write-Host $rule -ForegroundColor Cyan
    Write-Host '  Windows LAPS checkout' -ForegroundColor Cyan
    Write-Host '  Entra ID  |  app certificate  |  no user sign-in' -ForegroundColor Cyan
    Write-Host $rule -ForegroundColor Cyan
    Write-Host ''
}

function Write-Line {
    param([string]$Label, [string]$Value, [ConsoleColor]$Color = 'White')
    $text = if ([string]::IsNullOrWhiteSpace($Value)) { '(none)' } else { $Value }
    Write-Host ('  {0,-18}' -f "${Label}:") -NoNewline -ForegroundColor DarkGray
    Write-Host $text -ForegroundColor $Color
}

function Get-HostName {
    param([string]$Name)
    $hostName = ("$Name".Trim()).Split('.')[0]
    if ($hostName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$') {
        throw "'$Name' is not a valid computer name."
    }
    return $hostName.ToUpperInvariant()
}

function ConvertFrom-LapsPassword {
    param([string]$PasswordBase64)
    $bytes = [Convert]::FromBase64String($PasswordBase64)
    # Graph / Get-LapsAADPassword store this as UTF-16LE. UTF-8 decoding leaves
    # hidden NUL characters: the password looks right on screen and fails at logon.
    $plain = if (($bytes.Length -ge 2) -and ($bytes[1] -eq 0)) {
        [Text.Encoding]::Unicode.GetString($bytes)
    } else {
        [Text.Encoding]::UTF8.GetString($bytes)
    }
    return ($plain -replace [char]0, '').Trim()
}

function Format-LapsTime {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return '(none)' }
    try {
        $dt = [datetime]$Value
        if ($dt.Kind -eq [DateTimeKind]::Local) {
            $dt = $dt.ToUniversalTime()
        } elseif ($dt.Kind -eq [DateTimeKind]::Unspecified) {
            $dt = [datetime]::SpecifyKind($dt, [DateTimeKind]::Utc)
        } else {
            $dt = $dt.ToUniversalTime()
        }
        return $dt.ToString("dd-MMM-yyyy HH:mm 'UTC'", [cultureinfo]::InvariantCulture)
    } catch {
        return "$Value"
    }
}

function Connect-LapsGraph {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null

    $thumb = ($CertificateThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    $cert  = $null
    foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        if (-not (Test-Path -LiteralPath $store)) { continue }
        $cert = Get-ChildItem -Path $store | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
        if ($cert) { break }
    }
    if (-not $cert) {
        throw "Certificate $thumb was not found in CurrentUser\My or LocalMachine\My (running as $env:USERDOMAIN\$env:USERNAME)."
    }

    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

    # Do not pass -Headers on Graph calls. Custom headers drop the bearer token (HTTP 401).
    $params = @{
        TenantId              = $TenantId
        ClientId              = $ClientId
        CertificateThumbprint = $thumb
        ErrorAction           = 'Stop'
    }
    if ((Get-Command Connect-MgGraph).Parameters.ContainsKey('NoWelcome')) {
        $params['NoWelcome'] = $true
    }
    Connect-MgGraph @params | Out-Null
    Write-Host '  Signed in to Microsoft Graph.' -ForegroundColor Green
}

function Get-LapsPassword {
    param([string]$Name)

    $filter = [uri]::EscapeDataString("deviceName eq '$Name'")
    $list   = Invoke-MgGraphRequest -Method GET -Uri "$Graph/directory/deviceLocalCredentials?`$filter=$filter&`$select=id,deviceName,lastBackupDateTime,refreshDateTime"

    $matches = @()
    if ($list -and $list.value) { $matches = @($list.value) }
    if ($matches.Count -eq 0) {
        $filter = [uri]::EscapeDataString("startswith(deviceName,'$Name.')")
        $list   = Invoke-MgGraphRequest -Method GET -Uri "$Graph/directory/deviceLocalCredentials?`$filter=$filter&`$select=id,deviceName,lastBackupDateTime,refreshDateTime"
        if ($list -and $list.value) { $matches = @($list.value) }
    }
    if ($matches.Count -eq 0) {
        throw "$Name was not found in the Entra LAPS catalog. Confirm Windows LAPS is backing the password up to Entra ID."
    }

    $device = $matches | Sort-Object { [datetime]$_.lastBackupDateTime } -Descending | Select-Object -First 1
    $id     = $device.id
    $info   = Invoke-MgGraphRequest -Method GET -Uri "$Graph/directory/deviceLocalCredentials/${id}?`$select=id,deviceName,lastBackupDateTime,refreshDateTime,credentials"
    if ($info.value -and -not $info.credentials) { $info = $info.value }

    $allCreds = @($info.credentials)
    $current  = $allCreds | Where-Object {
        $_.backupDateTime -and $info.lastBackupDateTime -and
        ([datetime]$_.backupDateTime -eq [datetime]$info.lastBackupDateTime)
    } | Select-Object -First 1
    if (-not $current) {
        $current = $allCreds | Sort-Object { [datetime]$_.backupDateTime } -Descending | Select-Object -First 1
    }
    if (-not $current -or -not $current.passwordBase64) {
        throw "A LAPS record exists for $Name but the password was not returned. DeviceLocalCredential.Read.All (not ReadBasic.All) is required."
    }

    $hostName = if ($info.deviceName) { ("$($info.deviceName)").Split('.')[0] } else { $Name }
    return [pscustomobject]@{
        ComputerName = $hostName
        Account      = $current.accountName
        LoginName    = "$hostName\$($current.accountName)"
        Password     = (ConvertFrom-LapsPassword -PasswordBase64 $current.passwordBase64)
        LastUpdated  = $current.backupDateTime
        NextRotation = $info.refreshDateTime
    }
}

function Show-LapsPassword {
    param($Item)
    Write-Host ''
    Write-Host '  LAPS password retrieved' -ForegroundColor Green
    Write-Line 'Computer'      $Item.ComputerName 'Cyan'
    Write-Line 'Account'       $Item.Account
    Write-Line 'Logon as'      $Item.LoginName 'Cyan'
    Write-Line 'Password'      $Item.Password 'Yellow'
    Write-Line 'Last backup'   (Format-LapsTime $Item.LastUpdated)
    Write-Line 'Next rotation' (Format-LapsTime $Item.NextRotation)
    Write-Host ''
}

#endregion

#region ### 3. MAIN ############################################################

Write-Banner

try {
    Connect-LapsGraph
}
catch {
    Write-Host "  Sign-in failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ''
    Read-Host 'Press Enter to exit' | Out-Null
    exit 2
}

$prefill = $ComputerName
while ($true) {
    $inputName = $prefill
    $prefill   = $null
    if ([string]::IsNullOrWhiteSpace($inputName)) {
        $inputName = Read-Host 'Computer name'
    }
    if ($inputName -match '^(q|quit|exit)$') { break }
    if ([string]::IsNullOrWhiteSpace($inputName)) {
        Write-Host '  Enter a computer name, or Q to quit.' -ForegroundColor Yellow
        continue
    }

    try {
        $name = Get-HostName -Name $inputName
        Write-Host "  Looking up $name ..." -ForegroundColor Gray
        $item = Get-LapsPassword -Name $name
        Show-LapsPassword -Item $item

        $copy = Read-Host 'Copy password to clipboard? [Y/n]'
        if ([string]::IsNullOrWhiteSpace($copy) -or $copy -match '^(y|yes)$') {
            try {
                Set-Clipboard -Value $item.Password
                Write-Host '  Copied.' -ForegroundColor Green
            } catch {
                Write-Host '  Could not copy. Copy it from the line above.' -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ''
    }

    $again = Read-Host 'Look up another device? [Y/n]'
    if ($again -match '^(n|no)$') { break }
    Write-Host ''
}

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
Write-Host '  Done.' -ForegroundColor DarkGray
Write-Host ''

#endregion

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication
<#
================================================================================
 SCRIPT : LAPsPassAzure.ps1
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
    .\LAPsPassAzure.ps1
    .\LAPsPassAzure.ps1 -ComputerName 015CD415BR20
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
    $utf16 = ($bytes.Length -ge 2) -and (($bytes.Length % 2) -eq 0)
    if ($utf16) {
        $nuls = 0
        for ($i = 1; $i -lt $bytes.Length; $i += 2) {
            if ($bytes[$i] -eq 0) { $nuls++ }
        }
        if ($nuls -ge [math]::Ceiling($bytes.Length / 4.0)) {
            return [Text.Encoding]::Unicode.GetString($bytes).Trim([char]0)
        }
    }
    return [Text.Encoding]::UTF8.GetString($bytes).Trim([char]0)
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

    $device = $matches | Sort-Object lastBackupDateTime -Descending | Select-Object -First 1
    $id     = $device.id
    $info   = Invoke-MgGraphRequest -Method GET -Uri "$Graph/directory/deviceLocalCredentials/${id}?`$select=id,deviceName,lastBackupDateTime,refreshDateTime,credentials"

    $cred = @($info.credentials) | Sort-Object backupDateTime -Descending | Select-Object -First 1
    if (-not $cred -or -not $cred.passwordBase64) {
        throw "A LAPS record exists for $Name but the password was not returned. DeviceLocalCredential.Read.All (not ReadBasic.All) is required."
    }

    return [pscustomobject]@{
        ComputerName = $info.deviceName
        Account      = $cred.accountName
        LoginName    = ".\$($cred.accountName)"
        Password     = (ConvertFrom-LapsPassword -PasswordBase64 $cred.passwordBase64)
        LastUpdated  = $cred.backupDateTime
        Expires      = $info.refreshDateTime
    }
}

function Show-LapsPassword {
    param($Item)
    Write-Host ''
    Write-Host '  LAPS password retrieved' -ForegroundColor Green
    Write-Line 'Computer' $Item.ComputerName 'Cyan'
    Write-Line 'Account'  $Item.Account
    Write-Line 'Logon as' $Item.LoginName 'Cyan'
    Write-Line 'Password' $Item.Password 'Yellow'
    Write-Line 'Updated'  $Item.LastUpdated
    Write-Line 'Expires'  $Item.Expires
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

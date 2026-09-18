#Requires -Version 5.1
# Tests for DPAPI credential files (machine vs current-user) and the menu.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
$repo = Split-Path -Parent $here

$failed = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        Write-Host "  PASS  $Message" -ForegroundColor Green
    }
    else {
        Write-Host "  FAIL  $Message" -ForegroundColor Red
        $script:failed++
    }
}

function Test-ScriptParses {
    param([string]$Path, [string]$Label)
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) "$Label parses ($($parseErrors.Count) errors)"
    if ($parseErrors.Count -gt 0) {
        $parseErrors | ForEach-Object { Write-Host "    $($_.ToString())" -ForegroundColor Yellow }
    }
}

Write-Host '== Parser ==' -ForegroundColor Cyan
Test-ScriptParses -Path (Join-Path $repo 'User-Offboarding-Accendra.ps1') -Label 'Offboarding script'
Test-ScriptParses -Path (Join-Path $repo 'Set-ExchangeOnlineCredentialFile.ps1') -Label 'Credential updater'

$offboard = Get-Content -Raw -Path (Join-Path $repo 'User-Offboarding-Accendra.ps1')
$updater = Get-Content -Raw -Path (Join-Path $repo 'Set-ExchangeOnlineCredentialFile.ps1')
Assert-True ($offboard -match 'Import-OffboardingCredentialFile') 'Offboarding loads DPAPI helper'
Assert-True ($offboard -notmatch 'Import-Clixml -Path \$passwordFile') 'Offboarding no longer uses Import-Clixml for Exchange'
Assert-True ($updater -match 'Change encryption scope') 'Menu offers encryption-scope option'
Assert-True ($updater -match 'Any user on this computer') 'Menu can choose machine-wide decrypt'
Assert-True ($updater -match 'Only the current Windows user') 'Menu can choose user\+machine decrypt'

$dpapiOk = $false
try {
    Add-Type -AssemblyName System.Security -ErrorAction Stop
    [void][System.Security.Cryptography.ProtectedData]::Protect(
        [byte[]](1, 2, 3, 4),
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $dpapiOk = $true
}
catch {
    Write-Host '== DPAPI round-trip ==' -ForegroundColor Cyan
    Write-Host '  SKIP  Windows DPAPI is not available in this environment' -ForegroundColor Yellow
}

if ($dpapiOk) {
    Write-Host '== DPAPI round-trip (machine and current-user) ==' -ForegroundColor Cyan
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("exch-dpapi-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    $jsonPath = Join-Path $tempDir 'ExchangeOnline.json'
    $helper = Join-Path $repo 'Set-ExchangeOnlineCredentialFile.ps1'
    try {
        . $helper

        $pass1 = ConvertTo-SecureString 'First-Pass-1!' -AsPlainText -Force
        $cred1 = New-Object System.Management.Automation.PSCredential ('svcIAM@owens-minor.com', $pass1)
        & $helper -Path $jsonPath -Credential $cred1 -ProtectionScope LocalMachine
        $loaded = Import-OffboardingCredentialFile -FilePath $jsonPath
        Assert-True ($loaded.Username -eq 'svcIAM@owens-minor.com') 'Machine-scope create stores username'
        Assert-True ($loaded.Protection -eq 'DPAPI-LocalMachine') 'Machine-scope file records LocalMachine'
        Assert-True ($loaded.Password -eq 'First-Pass-1!') 'Machine-scope decrypts password'

        $pass2 = ConvertTo-SecureString 'Second-Pass-2!' -AsPlainText -Force
        & $helper -Path $jsonPath -UserName 'svcIAM@owens-minor.com' -Password $pass2
        $updated = Import-OffboardingCredentialFile -FilePath $jsonPath
        Assert-True ($updated.Password -eq 'Second-Pass-2!') 'Update replaces password'
        Assert-True ($updated.Protection -eq 'DPAPI-LocalMachine') 'Update keeps machine scope unless changed'

        & $helper -Path $jsonPath -ProtectionScope CurrentUser
        $userScoped = Import-OffboardingCredentialFile -FilePath $jsonPath
        Assert-True ($userScoped.Protection -eq 'DPAPI-CurrentUser') 'Menu/automation can switch to current-user scope'
        Assert-True ($userScoped.Password -eq 'Second-Pass-2!') 'Re-protect keeps the password'

        $showOut = & $helper -Path $jsonPath -Show *>&1 | Out-String
        Assert-True ($showOut -match 'svcIAM@owens-minor.com') '-Show prints stored username'
        Assert-True ($showOut -match 'current Windows user') '-Show prints user\+machine scope label'

        Write-Host '== Interactive menu: choose file ==' -ForegroundColor Cyan
        $hostExe = (Get-Process -Id $PID).Path
        $menuLines = @('2', $jsonPath, '6', 'Q')
        $menuOut = $menuLines | & $hostExe -NoLogo -File $helper *>&1 | Out-String
        Assert-True ($menuOut -match 'EXCHANGE ONLINE CREDENTIAL FILE') 'Menu banner is shown'
        Assert-True ($menuOut -match 'Change encryption scope') 'Menu lists encryption-scope option'
        Assert-True ($menuOut -match [regex]::Escape($jsonPath)) 'Menu binds the chosen file'
    }
    finally {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
else {
    Write-Host '== Interactive menu text ==' -ForegroundColor Cyan
    Assert-True ($updater -match '\[1\] Any user on this computer' -or $updater -match '1. Any user on this computer') 'Machine option text present'
}

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed." -ForegroundColor Red
    exit 1
}

Write-Host "`nAll Exchange credential file tests passed." -ForegroundColor Green
exit 0

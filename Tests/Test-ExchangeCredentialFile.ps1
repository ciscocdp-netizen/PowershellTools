#Requires -Version 5.1
# Tests for Export-Clixml Exchange credentials and the updater script.

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
Assert-True ($offboard -match 'Import-Clixml') 'Offboarding uses Import-Clixml'
Assert-True ($offboard -notmatch 'Unprotect-CredentialFile') 'Offboarding no longer calls Unprotect-CredentialFile'
Assert-True ($offboard -match 'Set-ExchangeOnlineCredentialFile') 'Offboarding points operators at the updater'

Write-Host '== Export-Clixml round-trip ==' -ForegroundColor Cyan
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("exch-clixml-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempDir | Out-Null
$xmlPath = Join-Path $tempDir 'ExchangeOnline.xml'
try {
    $pass1 = ConvertTo-SecureString 'First-Pass-1!' -AsPlainText -Force
    $cred1 = New-Object System.Management.Automation.PSCredential ('svcIAM@owens-minor.com', $pass1)
    & (Join-Path $repo 'Set-ExchangeOnlineCredentialFile.ps1') -Path $xmlPath -Credential $cred1
    $loaded = Import-Clixml -Path $xmlPath
    Assert-True ($loaded.UserName -eq 'svcIAM@owens-minor.com') 'Create stores username'

    $pass2 = ConvertTo-SecureString 'Second-Pass-2!' -AsPlainText -Force
    & (Join-Path $repo 'Set-ExchangeOnlineCredentialFile.ps1') -Path $xmlPath -UserName 'svcIAM@owens-minor.com' -Password $pass2
    $updated = Import-Clixml -Path $xmlPath
    Assert-True ($updated.UserName -eq 'svcIAM@owens-minor.com') 'Update keeps username'
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($updated.Password)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        Assert-True ($plain -eq 'Second-Pass-2!') 'Update replaces password'
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    $pass3 = ConvertTo-SecureString 'Third-Pass-3!' -AsPlainText -Force
    & (Join-Path $repo 'Set-ExchangeOnlineCredentialFile.ps1') -Path $xmlPath -PasswordOnly -Password $pass3
    $pwOnly = Import-Clixml -Path $xmlPath
    Assert-True ($pwOnly.UserName -eq 'svcIAM@owens-minor.com') 'PasswordOnly keeps username'
    $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwOnly.Password)
    try {
        $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr2)
        Assert-True ($plain2 -eq 'Third-Pass-3!') 'PasswordOnly replaces password'
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
    }
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed." -ForegroundColor Red
    exit 1
}

Write-Host "`nAll Exchange credential file tests passed." -ForegroundColor Green
exit 0

#Requires -Version 5.1
# Test ExchangeCreds encrypt/decrypt the same way User-Offboarding-Accendra.ps1 does.

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

Write-Host '== Parser: User-Offboarding-Accendra.ps1 ==' -ForegroundColor Cyan
$offboardPath = Join-Path $repo 'User-Offboarding-Accendra.ps1'
$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($offboardPath, [ref]$tokens, [ref]$parseErrors)
Assert-True ($parseErrors.Count -eq 0) "Offboarding script parses ($($parseErrors.Count) errors)"
if ($parseErrors.Count -gt 0) {
    $parseErrors | ForEach-Object { Write-Host "    $($_.ToString())" -ForegroundColor Yellow }
}

Write-Host '== Parser: Get-ExchangeOnlineVaultCredential.ps1 ==' -ForegroundColor Cyan
$helperPath = Join-Path $repo 'Get-ExchangeOnlineVaultCredential.ps1'
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($helperPath, [ref]$tokens, [ref]$parseErrors)
Assert-True ($parseErrors.Count -eq 0) "Helper script parses ($($parseErrors.Count) errors)"

Write-Host '== CredentialVault self-test ==' -ForegroundColor Cyan
& (Join-Path $repo 'CredentialVault.ps1') -SelfTest
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
    Write-Host "  FAIL  CredentialVault -SelfTest exit $LASTEXITCODE" -ForegroundColor Red
    $failed++
}

Write-Host '== ExchangeCreds round-trip (sample snippet) ==' -ForegroundColor Cyan
. (Join-Path $repo 'Encrypt_Creds.ps1')

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("exch-vault-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempDir | Out-Null
$encPath = Join-Path $tempDir 'creds.enc'
$passPhrase = 'Passphase'
$pass = ConvertTo-SecureString $passPhrase -AsPlainText -Force

try {
    $data = [ordered]@{
        _Type    = 'ExchangeCreds'
        Username = 'svcIAM@owens-minor.com'
        Password = 'S3cure-Test-Only!'
    }
    Protect-CredentialFile -Data $data -Path $encPath -Passphrase $pass

    # Exact generated-snippet shape (SecureString passphrase required by Unprotect-CredentialFile)
    $creds = Unprotect-CredentialFile -Path $encPath -Passphrase $pass
    Assert-True ($creds.Username -eq 'svcIAM@owens-minor.com') 'Snippet decrypt returns Username'
    Assert-True ($creds.Password -eq 'S3cure-Test-Only!') 'Snippet decrypt returns Password'

    $psCred = ConvertTo-PSCredential -UserName $creds.Username -Password $creds.Password
    Assert-True ($psCred.UserName -eq 'svcIAM@owens-minor.com') 'ConvertTo-PSCredential username'
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($psCred.Password)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        Assert-True ($plain -eq 'S3cure-Test-Only!') 'ConvertTo-PSCredential password'
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    Write-Host '== Get-ExchangeOnlineVaultCredential helper ==' -ForegroundColor Cyan
    . (Join-Path $repo 'Get-ExchangeOnlineVaultCredential.ps1')
    $helperCred = Get-ExchangeOnlineVaultCredential `
        -CredentialFile $encPath `
        -VaultScript (Join-Path $repo 'Encrypt_Creds.ps1') `
        -SearchRoot $repo `
        -Passphrase $passPhrase `
        -FallbackUserName 'unused@example.com'
    Assert-True ($helperCred.UserName -eq 'svcIAM@owens-minor.com') 'Helper returns vault Username (not fallback)'

    $wrong = ConvertTo-SecureString 'not-the-passphrase' -AsPlainText -Force
    $threw = $false
    try {
        Unprotect-CredentialFile -Path $encPath -Passphrase $wrong | Out-Null
    }
    catch {
        $threw = $true
    }
    Assert-True $threw 'Wrong passphrase fails integrity check'
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed." -ForegroundColor Red
    exit 1
}

Write-Host "`nAll Exchange vault credential tests passed." -ForegroundColor Green
exit 0

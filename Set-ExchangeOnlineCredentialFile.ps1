#Requires -Version 5.1
<#
.SYNOPSIS
    Create or update the encrypted Exchange Online credential file used by
    User-Offboarding-Accendra.ps1.

.DESCRIPTION
    Stores a PSCredential with Export-Clixml (Windows DPAPI). Only the same
    Windows user, on the same computer, can decrypt it.

    You cannot edit the ciphertext by hand. To change the username or password,
    run this script again — it reads the current file (if present), prompts for
    the new values, and overwrites the encrypted file.

.EXAMPLE
    .\Set-ExchangeOnlineCredentialFile.ps1
    # Interactive: show current username, then change password or both fields

.EXAMPLE
    .\Set-ExchangeOnlineCredentialFile.ps1 -Show
    # Print the username currently stored (password is never shown)

.EXAMPLE
    .\Set-ExchangeOnlineCredentialFile.ps1 -PasswordOnly
    # Keep the stored username; prompt for a new password

.EXAMPLE
    .\Set-ExchangeOnlineCredentialFile.ps1 -UserName 'svcIAM@owens-minor.com'
    # Set/replace username; prompt for password
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter()]
    [string]$Path = 'E:\Scripts\Passwords\ExchangeOnline.xml',

    [Parameter(ParameterSetName = 'Interactive')]
    [string]$UserName,

    [Parameter(ParameterSetName = 'Interactive')]
    [System.Security.SecureString]$Password,

    [Parameter(ParameterSetName = 'Credential')]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [switch]$PasswordOnly,

    [Parameter()]
    [switch]$Show
)

function Protect-CredentialFileAcl {
    param([Parameter(Mandatory)][string]$FilePath)
    if ($env:OS -ne 'Windows_NT') { return }
    try {
        $acl = Get-Acl -Path $FilePath
        $acl.SetAccessRuleProtection($true, $false)
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity,
            'FullControl',
            'Allow'
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $FilePath -AclObject $acl
    }
    catch {
        Write-Warning "Could not restrict NTFS ACLs on '${FilePath}': $($_.Exception.Message)"
    }
}

function Read-ExistingCredential {
    param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath)) {
        return $null
    }
    try {
        return Import-Clixml -Path $FilePath
    }
    catch {
        throw "Could not read '$FilePath'. The file is encrypted for a different Windows user/computer, or it is not a PSCredential CLIXML. $($_.Exception.Message)"
    }
}

function Save-ExchangeOnlineCredentialFile {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential
    )

    $parent = Split-Path -Parent $FilePath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $Credential | Export-Clixml -Path $FilePath
    Protect-CredentialFileAcl -FilePath $FilePath
    Write-Host "Saved encrypted credential for $($Credential.UserName) -> $FilePath" -ForegroundColor Green
}

$existing = $null
if (Test-Path -LiteralPath $Path) {
    $existing = Read-ExistingCredential -FilePath $Path
}

if ($Show) {
    if (-not $existing) {
        Write-Host "No credential file at $Path" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "Path:     $Path"
    Write-Host "Username: $($existing.UserName)"
    Write-Host "Password: (stored, not displayed)"
    exit 0
}

if ($Credential) {
    Save-ExchangeOnlineCredentialFile -FilePath $Path -Credential $Credential
    return
}

if ($existing) {
    Write-Host "Current file:     $Path" -ForegroundColor Cyan
    Write-Host "Current username: $($existing.UserName)" -ForegroundColor Cyan
}

$resolvedUser = $UserName
if ($PasswordOnly) {
    if (-not $existing) {
        throw "Cannot use -PasswordOnly; credential file not found: $Path"
    }
    $resolvedUser = $existing.UserName
}

if ([string]::IsNullOrWhiteSpace($resolvedUser)) {
    $hint = if ($existing) { $existing.UserName } else { 'svcIAM@owens-minor.com' }
    $entered = Read-Host "Exchange username [$hint]"
    $resolvedUser = if ([string]::IsNullOrWhiteSpace($entered)) { $hint } else { $entered.Trim() }
}

$resolvedPassword = $Password
if (-not $resolvedPassword) {
    $resolvedPassword = Read-Host "Password for $resolvedUser" -AsSecureString
    $confirm = Read-Host "Confirm password" -AsSecureString
    $unprotect = {
        param($Secure)
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
        try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    if ((& $unprotect $resolvedPassword) -ne (& $unprotect $confirm)) {
        throw 'Passwords do not match. File was not changed.'
    }
}

if ([string]::IsNullOrWhiteSpace($resolvedUser)) {
    throw 'Username cannot be empty.'
}
if (-not $resolvedPassword -or $resolvedPassword.Length -eq 0) {
    throw 'Password cannot be empty.'
}

$newCred = New-Object System.Management.Automation.PSCredential ($resolvedUser, $resolvedPassword)
Save-ExchangeOnlineCredentialFile -FilePath $Path -Credential $newCred

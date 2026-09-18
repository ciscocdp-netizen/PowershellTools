#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive menu to create or update encrypted Exchange Online credential files.

.DESCRIPTION
    Stores a PSCredential with Export-Clixml (Windows DPAPI). Only the same
    Windows user, on the same computer, can decrypt it.

    Run with no parameters for a menu:
      [1] Create a new encrypted credential file
      [2] Choose an existing file to modify
      [3] Change username and password on the selected file
      [4] Change password only
      [5] Show stored username
      [Q] Quit

    Automation parameters (-Path, -Credential, -UserName, -Password, -Show,
    -PasswordOnly) still work and skip the menu.

.EXAMPLE
    .\Set-ExchangeOnlineCredentialFile.ps1
    # Full interactive menu: create a new file or pick one to modify

.EXAMPLE
    .\Set-ExchangeOnlineCredentialFile.ps1 -Show -Path 'E:\Scripts\Passwords\ExchangeOnline.xml'
    # Print the username currently stored (password is never shown)

.EXAMPLE
    .\Set-ExchangeOnlineCredentialFile.ps1 -PasswordOnly -Path 'E:\Scripts\Passwords\ExchangeOnline.xml'
    # Keep the stored username; prompt for a new password
#>

[CmdletBinding(DefaultParameterSetName = 'Fields')]
param(
    [Parameter()]
    [string]$Path,

    [Parameter(ParameterSetName = 'Fields')]
    [string]$UserName,

    [Parameter(ParameterSetName = 'Fields')]
    [System.Security.SecureString]$Password,

    [Parameter(ParameterSetName = 'Credential')]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [switch]$PasswordOnly,

    [Parameter()]
    [switch]$Show
)

$script:IsDotSourced = ($MyInvocation.InvocationName -eq '.')
$script:DefaultCredentialPath = 'E:\Scripts\Passwords\ExchangeOnline.xml'
$script:CurrentPath = $Path

function ConvertFrom-SecureStringToPlain {
    param([System.Security.SecureString]$Secure)
    if (-not $Secure) { return '' }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-CredentialFullPath {
    param([Parameter(Mandatory)][string]$FilePath)

    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        throw 'Path cannot be empty.'
    }
    $FilePath = $FilePath.Trim().Trim('"')
    if (-not [System.IO.Path]::IsPathRooted($FilePath)) {
        $base = if (Test-Path -LiteralPath 'E:\Scripts\Passwords') {
            'E:\Scripts\Passwords'
        }
        else {
            (Get-Location).ProviderPath
        }
        $FilePath = Join-Path $base $FilePath
    }
    return [System.IO.Path]::GetFullPath($FilePath)
}

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
    if (-not $FilePath -or -not (Test-Path -LiteralPath $FilePath)) {
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

    $FilePath = Get-CredentialFullPath -FilePath $FilePath
    $parent = Split-Path -Parent $FilePath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $Credential | Export-Clixml -Path $FilePath
    Protect-CredentialFileAcl -FilePath $FilePath
    $script:CurrentPath = $FilePath
    Write-Host "Saved encrypted credential for $($Credential.UserName)" -ForegroundColor Green
    Write-Host "  $FilePath" -ForegroundColor Cyan
}

function Read-ConfirmedPassword {
    param([Parameter(Mandatory)][string]$UserName)

    $first = Read-Host "Password for $UserName" -AsSecureString
    $second = Read-Host 'Confirm password' -AsSecureString
    if ((ConvertFrom-SecureStringToPlain $first) -ne (ConvertFrom-SecureStringToPlain $second)) {
        throw 'Passwords do not match. File was not changed.'
    }
    if (-not $first -or $first.Length -eq 0) {
        throw 'Password cannot be empty.'
    }
    return $first
}

function Show-OpenCredentialDialog {
    param(
        [string]$Title = 'Select encrypted credential file',
        [string]$InitialDirectory
    )
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = $Title
        $dialog.Filter = 'Credential files (*.xml)|*.xml|All files (*.*)|*.*'
        $dialog.InitialDirectory = $InitialDirectory
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            return $dialog.FileName
        }
        return $null
    }
    catch {
        return $null
    }
}

function Show-SaveCredentialDialog {
    param(
        [string]$Title = 'Save encrypted credential file',
        [string]$DefaultFileName = 'ExchangeOnline.xml',
        [string]$InitialDirectory
    )
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Title = $Title
        $dialog.Filter = 'Credential files (*.xml)|*.xml|All files (*.*)|*.*'
        $dialog.FileName = $DefaultFileName
        $dialog.InitialDirectory = $InitialDirectory
        $dialog.OverwritePrompt = $true
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            return $dialog.FileName
        }
        return $null
    }
    catch {
        return $null
    }
}

function Get-CredentialDialogStartFolder {
    if ($script:CurrentPath) {
        $dir = Split-Path -Parent $script:CurrentPath
        if ($dir -and (Test-Path -LiteralPath $dir)) { return $dir }
    }
    if (Test-Path -LiteralPath 'E:\Scripts\Passwords') { return 'E:\Scripts\Passwords' }
    try {
        $desktop = [Environment]::GetFolderPath('Desktop')
        if (-not [string]::IsNullOrWhiteSpace($desktop) -and (Test-Path -LiteralPath $desktop)) {
            return $desktop
        }
    }
    catch { }
    $cwd = (Get-Location).ProviderPath
    if (-not [string]::IsNullOrWhiteSpace($cwd)) { return $cwd }
    return [System.IO.Path]::GetTempPath()
}

function Read-CredentialFilePath {
    param(
        [Parameter(Mandatory)][ValidateSet('Open', 'Save')]
        [string]$Mode,
        [string]$Prompt
    )

    $startFolder = Get-CredentialDialogStartFolder
    Write-Host ''
    Write-Host $Prompt -ForegroundColor Yellow
    Write-Host "  Suggested folder: $startFolder" -ForegroundColor DarkGray
    Write-Host '  Enter a full path, a file name, B to browse, or blank to browse.' -ForegroundColor DarkGray
    $entered = Read-Host '  Path'

    if ([string]::IsNullOrWhiteSpace($entered) -or $entered -eq 'B' -or $entered -eq 'b') {
        $picked = if ($Mode -eq 'Save') {
            Show-SaveCredentialDialog -InitialDirectory $startFolder
        }
        else {
            Show-OpenCredentialDialog -InitialDirectory $startFolder
        }
        if ($picked) { return (Get-CredentialFullPath -FilePath $picked) }
        $entered = Read-Host '  File picker unavailable or cancelled. Type a path (blank to cancel)'
        if ([string]::IsNullOrWhiteSpace($entered)) { return $null }
    }

    return (Get-CredentialFullPath -FilePath $entered)
}

function Show-SelectedCredentialStatus {
    Write-Host ''
    if (-not $script:CurrentPath) {
        Write-Host '  Selected file: (none)' -ForegroundColor Yellow
        return
    }
    Write-Host "  Selected file: $($script:CurrentPath)" -ForegroundColor Cyan
    if (-not (Test-Path -LiteralPath $script:CurrentPath)) {
        Write-Host '  Status:        file does not exist yet' -ForegroundColor Yellow
        return
    }
    try {
        $cred = Read-ExistingCredential -FilePath $script:CurrentPath
        Write-Host "  Username:      $($cred.UserName)" -ForegroundColor White
        Write-Host '  Password:      (stored, not displayed)' -ForegroundColor DarkGray
    }
    catch {
        Write-Host "  Status:        $($_.Exception.Message)" -ForegroundColor Red
    }
}

function New-CredentialFileInteractive {
    $filePath = Read-CredentialFilePath -Mode Save -Prompt 'Create a NEW encrypted credential file'
    if (-not $filePath) {
        Write-Host '  Cancelled.' -ForegroundColor Yellow
        return
    }

    if (Test-Path -LiteralPath $filePath) {
        $overwrite = Read-Host "  File exists. Overwrite? (Y/N)"
        if ($overwrite -ne 'Y' -and $overwrite -ne 'y') {
            Write-Host '  Cancelled.' -ForegroundColor Yellow
            return
        }
    }

    $hint = 'svcIAM@owens-minor.com'
    $entered = Read-Host "  Exchange username [$hint]"
    $userName = if ([string]::IsNullOrWhiteSpace($entered)) { $hint } else { $entered.Trim() }
    $password = Read-ConfirmedPassword -UserName $userName
    $cred = New-Object System.Management.Automation.PSCredential ($userName, $password)
    Save-ExchangeOnlineCredentialFile -FilePath $filePath -Credential $cred
}

function Select-CredentialFileInteractive {
    $filePath = Read-CredentialFilePath -Mode Open -Prompt 'Choose an EXISTING encrypted credential file to modify'
    if (-not $filePath) {
        Write-Host '  Cancelled.' -ForegroundColor Yellow
        return
    }
    if (-not (Test-Path -LiteralPath $filePath)) {
        $create = Read-Host '  File not found. Create it as a new file? (Y/N)'
        if ($create -eq 'Y' -or $create -eq 'y') {
            $script:CurrentPath = $filePath
            New-CredentialFileInteractiveFromPath -FilePath $filePath
            return
        }
        Write-Host '  Cancelled.' -ForegroundColor Yellow
        return
    }

    $cred = Read-ExistingCredential -FilePath $filePath
    $script:CurrentPath = $filePath
    Write-Host "  Selected $($cred.UserName)" -ForegroundColor Green
    Write-Host "  $filePath" -ForegroundColor Cyan
}

function New-CredentialFileInteractiveFromPath {
    param([string]$FilePath)
    $hint = 'svcIAM@owens-minor.com'
    $entered = Read-Host "  Exchange username [$hint]"
    $userName = if ([string]::IsNullOrWhiteSpace($entered)) { $hint } else { $entered.Trim() }
    $password = Read-ConfirmedPassword -UserName $userName
    $cred = New-Object System.Management.Automation.PSCredential ($userName, $password)
    Save-ExchangeOnlineCredentialFile -FilePath $FilePath -Credential $cred
}

function Update-SelectedCredentialInteractive {
    param([switch]$PasswordOnlyUpdate)

    if (-not $script:CurrentPath) {
        Write-Host '  No file selected. Use [1] to create or [2] to choose a file first.' -ForegroundColor Yellow
        return
    }

    $existing = $null
    if (Test-Path -LiteralPath $script:CurrentPath) {
        $existing = Read-ExistingCredential -FilePath $script:CurrentPath
    }
    elseif ($PasswordOnlyUpdate) {
        Write-Host "  File not found: $($script:CurrentPath)" -ForegroundColor Red
        return
    }

    $userName = $null
    if ($PasswordOnlyUpdate) {
        $userName = $existing.UserName
        Write-Host "  Keeping username: $userName" -ForegroundColor Cyan
    }
    else {
        $hint = if ($existing) { $existing.UserName } else { 'svcIAM@owens-minor.com' }
        $entered = Read-Host "  Exchange username [$hint]"
        $userName = if ([string]::IsNullOrWhiteSpace($entered)) { $hint } else { $entered.Trim() }
    }

    $password = Read-ConfirmedPassword -UserName $userName
    $cred = New-Object System.Management.Automation.PSCredential ($userName, $password)
    Save-ExchangeOnlineCredentialFile -FilePath $script:CurrentPath -Credential $cred
}

function Show-SelectedCredentialInteractive {
    if (-not $script:CurrentPath) {
        Write-Host '  No file selected. Use [1] to create or [2] to choose a file first.' -ForegroundColor Yellow
        return
    }
    Show-SelectedCredentialStatus
}

function Start-ExchangeCredentialMenu {
    if (-not $script:CurrentPath -and (Test-Path -LiteralPath $script:DefaultCredentialPath)) {
        $script:CurrentPath = $script:DefaultCredentialPath
    }
    elseif ($script:CurrentPath) {
        $script:CurrentPath = Get-CredentialFullPath -FilePath $script:CurrentPath
    }

    do {
        Write-Host ''
        Write-Host ('=' * 70) -ForegroundColor Cyan
        Write-Host '  EXCHANGE ONLINE CREDENTIAL FILE' -ForegroundColor Cyan
        Write-Host ('=' * 70) -ForegroundColor Cyan
        Show-SelectedCredentialStatus
        Write-Host ''
        Write-Host '    1. Create a new encrypted credential file' -ForegroundColor White
        Write-Host '    2. Choose an existing file to modify' -ForegroundColor White
        Write-Host '    3. Change username and password' -ForegroundColor White
        Write-Host '    4. Change password only' -ForegroundColor White
        Write-Host '    5. Show stored username' -ForegroundColor White
        Write-Host '    Q. Quit' -ForegroundColor White
        Write-Host ''
        $choice = Read-Host '  Select an option'
        if ([string]::IsNullOrWhiteSpace($choice)) {
            return
        }

        try {
            switch ($choice) {
                '1' { New-CredentialFileInteractive }
                '2' { Select-CredentialFileInteractive }
                '3' { Update-SelectedCredentialInteractive }
                '4' { Update-SelectedCredentialInteractive -PasswordOnlyUpdate }
                '5' { Show-SelectedCredentialInteractive }
                { $_ -in @('Q', 'q') } { return }
                default { Write-Host '  Not a valid option.' -ForegroundColor Yellow }
            }
        }
        catch {
            Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        }
    } while ($true)
}

function Invoke-NonInteractiveCredentialUpdate {
    $filePath = if ($Path) { Get-CredentialFullPath -FilePath $Path } else { $script:DefaultCredentialPath }
    $script:CurrentPath = $filePath
    $existing = Read-ExistingCredential -FilePath $filePath

    if ($Show) {
        if (-not $existing) {
            Write-Host "No credential file at $filePath" -ForegroundColor Yellow
            exit 1
        }
        Write-Host "Path:     $filePath"
        Write-Host "Username: $($existing.UserName)"
        Write-Host 'Password: (stored, not displayed)'
        return
    }

    if ($Credential) {
        Save-ExchangeOnlineCredentialFile -FilePath $filePath -Credential $Credential
        return
    }

    $resolvedUser = $UserName
    if ($PasswordOnly) {
        if (-not $existing) {
            throw "Cannot use -PasswordOnly; credential file not found: $filePath"
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
        $resolvedPassword = Read-ConfirmedPassword -UserName $resolvedUser
    }

    if ([string]::IsNullOrWhiteSpace($resolvedUser)) {
        throw 'Username cannot be empty.'
    }
    if (-not $resolvedPassword -or $resolvedPassword.Length -eq 0) {
        throw 'Password cannot be empty.'
    }

    $newCred = New-Object System.Management.Automation.PSCredential ($resolvedUser, $resolvedPassword)
    Save-ExchangeOnlineCredentialFile -FilePath $filePath -Credential $newCred
}

if (-not $script:IsDotSourced) {
    $runMenu = -not (
        $PSBoundParameters.ContainsKey('Credential') -or
        $PSBoundParameters.ContainsKey('UserName') -or
        $PSBoundParameters.ContainsKey('Password') -or
        $PasswordOnly -or
        $Show
    )

    if ($runMenu) {
        Start-ExchangeCredentialMenu
    }
    else {
        Invoke-NonInteractiveCredentialUpdate
    }
}

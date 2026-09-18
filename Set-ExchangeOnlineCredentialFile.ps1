#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive menu to create or update encrypted Exchange Online credential files.

.DESCRIPTION
    Encrypts Username + Password with Windows DPAPI. The menu asks which scope
    to use:

      * This computer (LocalMachine) — any account on this machine can decrypt
      * This user on this computer (CurrentUser) — only the Windows user that
        created the file, on this machine, can decrypt

    Run with no parameters for a menu:
      [1] Create a new encrypted credential file
      [2] Choose an existing file to modify
      [3] Change username and password
      [4] Change password only
      [5] Change encryption scope (computer vs user+computer)
      [6] Show stored username and encryption scope
      [Q] Quit

    Automation parameters (-Path, -Credential, -UserName, -Password,
    -ProtectionScope, -Show, -PasswordOnly) skip the menu.

.EXAMPLE
    .\Set-ExchangeOnlineCredentialFile.ps1
    # Menu: create a file, pick a file, or change encryption scope
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
    [ValidateSet('LocalMachine', 'CurrentUser')]
    [string]$ProtectionScope,

    [Parameter()]
    [switch]$PasswordOnly,

    [Parameter()]
    [switch]$Show
)

$script:IsDotSourced = ($MyInvocation.InvocationName -eq '.')
$script:DefaultCredentialPath = 'E:\Scripts\Passwords\ExchangeOnline.json'
$script:CurrentPath = $Path
$script:DpapiReady = $false

function ConvertFrom-SecureStringToPlain {
    param([System.Security.SecureString]$Secure)
    if (-not $Secure) { return '' }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function ConvertTo-SecretJson {
    param($InputObject)
    ConvertTo-Json -InputObject $InputObject -Compress -Depth 8
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

function ConvertTo-ProtectionName {
    param([string]$Scope)
    switch ($Scope) {
        'CurrentUser' { 'DPAPI-CurrentUser' }
        'DPAPI-CurrentUser' { 'DPAPI-CurrentUser' }
        default { 'DPAPI-LocalMachine' }
    }
}

function ConvertTo-DpapiScope {
    param([string]$ProtectionName)
    Initialize-DpapiAssembly
    if ($ProtectionName -eq 'DPAPI-CurrentUser') {
        return [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    }
    return [System.Security.Cryptography.DataProtectionScope]::LocalMachine
}

function Get-ProtectionScopeLabel {
    param([string]$ProtectionName)
    if ($ProtectionName -eq 'DPAPI-CurrentUser') {
        return 'This Windows user on this computer'
    }
    return 'Any user on this computer'
}

function Initialize-DpapiAssembly {
    if ($script:DpapiReady) { return }
    Add-Type -AssemblyName System.Security -ErrorAction Stop
    $script:DpapiReady = $true
}

function Protect-SecretBytes {
    param(
        [Parameter(Mandatory)][byte[]]$PlainBytes,
        [Parameter(Mandatory)][string]$ProtectionName
    )
    Initialize-DpapiAssembly
    $scope = ConvertTo-DpapiScope -ProtectionName $ProtectionName
    return [System.Security.Cryptography.ProtectedData]::Protect($PlainBytes, $null, $scope)
}

function Unprotect-SecretBytes {
    param(
        [Parameter(Mandatory)][byte[]]$CipherBytes,
        [Parameter(Mandatory)][string]$ProtectionName
    )
    Initialize-DpapiAssembly
    $scope = ConvertTo-DpapiScope -ProtectionName $ProtectionName
    return [System.Security.Cryptography.ProtectedData]::Unprotect($CipherBytes, $null, $scope)
}

function Protect-CredentialFileAcl {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$ProtectionName
    )
    if ($env:OS -ne 'Windows_NT') { return }
    try {
        $acl = Get-Acl -Path $FilePath
        $acl.SetAccessRuleProtection($true, $false)
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        if ($ProtectionName -eq 'DPAPI-LocalMachine') {
            foreach ($id in @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', $currentUser)) {
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $id, 'FullControl', 'Allow'
                )
                $acl.SetAccessRule($rule)
            }
        }
        else {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $currentUser, 'FullControl', 'Allow'
            )
            $acl.SetAccessRule($rule)
        }
        Set-Acl -Path $FilePath -AclObject $acl
    }
    catch {
        Write-Warning "Could not set NTFS ACLs on '${FilePath}': $($_.Exception.Message)"
    }
}

function Import-OffboardingCredentialFile {
    <#
    .SYNOPSIS
        Decrypt an offboarding credential file (machine or current-user DPAPI).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath
    )

    $FilePath = Get-CredentialFullPath -FilePath $FilePath
    if (-not (Test-Path -LiteralPath $FilePath)) {
        return $null
    }

    $raw = [System.IO.File]::ReadAllText($FilePath)
    if ($raw -match '<Objs(\s|>)|<Obj(\s|>)') {
        throw "Credential file '$FilePath' is the old user-only Export-Clixml format. Recreate it with Set-ExchangeOnlineCredentialFile.ps1 and choose an encryption scope in the menu."
    }

    try {
        $envelope = $raw | ConvertFrom-Json
    }
    catch {
        throw "Credential file '$FilePath' is not valid JSON. $($_.Exception.Message)"
    }

    if (-not $envelope.Cipher -or -not $envelope.Protection) {
        throw "Credential file '$FilePath' is missing Protection/Cipher. Recreate it with Set-ExchangeOnlineCredentialFile.ps1."
    }

    try {
        $cipherBytes = [Convert]::FromBase64String([string]$envelope.Cipher)
        $plainBytes = Unprotect-SecretBytes -CipherBytes $cipherBytes -ProtectionName ([string]$envelope.Protection)
        $plain = [System.Text.Encoding]::UTF8.GetString($plainBytes)
        $secrets = $plain | ConvertFrom-Json
    }
    catch {
        throw "Could not decrypt '$FilePath' with $($envelope.Protection). If the file is machine-scoped, run this on the same computer. If it is user-scoped, run it as the same Windows user. $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Username     = [string]$secrets.Username
        Password     = [string]$secrets.Password
        Protection   = [string]$envelope.Protection
        Path         = $FilePath
    }
}

function ConvertTo-OffboardingPSCredential {
    param($SecretRecord)
    if (-not $SecretRecord -or [string]::IsNullOrWhiteSpace($SecretRecord.Username) -or [string]::IsNullOrWhiteSpace($SecretRecord.Password)) {
        throw 'Credential file does not contain Username and Password.'
    }
    $sec = ConvertTo-SecureString -String $SecretRecord.Password -AsPlainText -Force
    New-Object System.Management.Automation.PSCredential ($SecretRecord.Username, $sec)
}

function Save-OffboardingCredentialSecrets {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$PasswordPlain,
        [Parameter(Mandatory)][string]$ProtectionName
    )

    $FilePath = Get-CredentialFullPath -FilePath $FilePath
    $parent = Split-Path -Parent $FilePath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $payload = [ordered]@{
        Username = $UserName
        Password = $PasswordPlain
    }
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-SecretJson -InputObject $payload))
    try {
        $cipherBytes = Protect-SecretBytes -PlainBytes $plainBytes -ProtectionName $ProtectionName
        $envelope = [ordered]@{
            Version    = 1
            Protection = $ProtectionName
            Cipher     = [Convert]::ToBase64String($cipherBytes)
        }
        $json = ConvertTo-SecretJson -InputObject $envelope
        $utf8 = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($FilePath, $json, $utf8)
        Protect-CredentialFileAcl -FilePath $FilePath -ProtectionName $ProtectionName
    }
    finally {
        if ($plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
    }

    $script:CurrentPath = $FilePath
    Write-Host "Saved encrypted credential for $UserName" -ForegroundColor Green
    Write-Host "  Scope: $(Get-ProtectionScopeLabel -ProtectionName $ProtectionName)" -ForegroundColor Cyan
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

function Read-ProtectionScopeInteractive {
    param([string]$CurrentProtection)

    Write-Host ''
    Write-Host '  Who should be able to decrypt this file?' -ForegroundColor Yellow
    Write-Host '    1. Any user on this computer (machine)' -ForegroundColor White
    Write-Host '    2. Only the current Windows user on this computer (user + machine)' -ForegroundColor White
    if ($CurrentProtection) {
        Write-Host "  Current: $(Get-ProtectionScopeLabel -ProtectionName $CurrentProtection)" -ForegroundColor DarkGray
    }
    $choice = Read-Host '  Choose 1 or 2'
    if ($choice -eq '2') {
        return 'DPAPI-CurrentUser'
    }
    if ($choice -eq '1' -or [string]::IsNullOrWhiteSpace($choice)) {
        return 'DPAPI-LocalMachine'
    }
    throw 'Not a valid encryption-scope choice. Use 1 or 2.'
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
        $dialog.Filter = 'Encrypted credential (*.json)|*.json|All files (*.*)|*.*'
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
        [string]$DefaultFileName = 'ExchangeOnline.json',
        [string]$InitialDirectory
    )
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Title = $Title
        $dialog.Filter = 'Encrypted credential (*.json)|*.json|All files (*.*)|*.*'
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
        $secrets = Import-OffboardingCredentialFile -FilePath $script:CurrentPath
        Write-Host "  Username:      $($secrets.Username)" -ForegroundColor White
        Write-Host "  Decryptable by: $(Get-ProtectionScopeLabel -ProtectionName $secrets.Protection)" -ForegroundColor White
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
        $overwrite = Read-Host '  File exists. Overwrite? (Y/N)'
        if ($overwrite -ne 'Y' -and $overwrite -ne 'y') {
            Write-Host '  Cancelled.' -ForegroundColor Yellow
            return
        }
    }
    New-CredentialFileInteractiveFromPath -FilePath $filePath
}

function New-CredentialFileInteractiveFromPath {
    param([string]$FilePath)

    $hint = 'svcIAM@owens-minor.com'
    $entered = Read-Host "  Exchange username [$hint]"
    $userName = if ([string]::IsNullOrWhiteSpace($entered)) { $hint } else { $entered.Trim() }
    $password = Read-ConfirmedPassword -UserName $userName
    $protection = Read-ProtectionScopeInteractive
    Save-OffboardingCredentialSecrets -FilePath $FilePath -UserName $userName `
        -PasswordPlain (ConvertFrom-SecureStringToPlain $password) -ProtectionName $protection
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

    $secrets = Import-OffboardingCredentialFile -FilePath $filePath
    $script:CurrentPath = $filePath
    Write-Host "  Selected $($secrets.Username)" -ForegroundColor Green
    Write-Host "  Decryptable by: $(Get-ProtectionScopeLabel -ProtectionName $secrets.Protection)" -ForegroundColor Cyan
    Write-Host "  $filePath" -ForegroundColor Cyan
}

function Update-SelectedCredentialInteractive {
    param([switch]$PasswordOnlyUpdate)

    if (-not $script:CurrentPath) {
        Write-Host '  No file selected. Use [1] to create or [2] to choose a file first.' -ForegroundColor Yellow
        return
    }

    $existing = $null
    if (Test-Path -LiteralPath $script:CurrentPath) {
        $existing = Import-OffboardingCredentialFile -FilePath $script:CurrentPath
    }
    elseif ($PasswordOnlyUpdate) {
        Write-Host "  File not found: $($script:CurrentPath)" -ForegroundColor Red
        return
    }

    $userName = $null
    if ($PasswordOnlyUpdate) {
        $userName = $existing.Username
        Write-Host "  Keeping username: $userName" -ForegroundColor Cyan
    }
    else {
        $hint = if ($existing) { $existing.Username } else { 'svcIAM@owens-minor.com' }
        $entered = Read-Host "  Exchange username [$hint]"
        $userName = if ([string]::IsNullOrWhiteSpace($entered)) { $hint } else { $entered.Trim() }
    }

    $password = Read-ConfirmedPassword -UserName $userName
    $protection = if ($existing) { $existing.Protection } else { Read-ProtectionScopeInteractive }
    Save-OffboardingCredentialSecrets -FilePath $script:CurrentPath -UserName $userName `
        -PasswordPlain (ConvertFrom-SecureStringToPlain $password) -ProtectionName $protection
}

function Update-SelectedProtectionScopeInteractive {
    if (-not $script:CurrentPath -or -not (Test-Path -LiteralPath $script:CurrentPath)) {
        Write-Host '  No file selected. Use [1] to create or [2] to choose a file first.' -ForegroundColor Yellow
        return
    }
    $existing = Import-OffboardingCredentialFile -FilePath $script:CurrentPath
    $protection = Read-ProtectionScopeInteractive -CurrentProtection $existing.Protection
    Save-OffboardingCredentialSecrets -FilePath $script:CurrentPath -UserName $existing.Username `
        -PasswordPlain $existing.Password -ProtectionName $protection
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
        Write-Host '    5. Change encryption scope (this computer vs this user + computer)' -ForegroundColor White
        Write-Host '    6. Show stored username and encryption scope' -ForegroundColor White
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
                '5' { Update-SelectedProtectionScopeInteractive }
                '6' { Show-SelectedCredentialStatus }
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
    $existing = $null
    if (Test-Path -LiteralPath $filePath) {
        $existing = Import-OffboardingCredentialFile -FilePath $filePath
    }

    if ($Show) {
        if (-not $existing) {
            Write-Host "No credential file at $filePath" -ForegroundColor Yellow
            exit 1
        }
        Write-Host "Path:     $filePath"
        Write-Host "Username: $($existing.Username)"
        Write-Host "Scope:    $(Get-ProtectionScopeLabel -ProtectionName $existing.Protection)"
        Write-Host 'Password: (stored, not displayed)'
        return
    }

    $protection = if ($ProtectionScope) {
        ConvertTo-ProtectionName -Scope $ProtectionScope
    }
    elseif ($existing) {
        $existing.Protection
    }
    else {
        'DPAPI-LocalMachine'
    }

    $changingScopeOnly = [bool]$ProtectionScope -and
        -not $Credential -and
        [string]::IsNullOrWhiteSpace($UserName) -and
        -not $Password -and
        -not $PasswordOnly
    if ($changingScopeOnly) {
        if (-not $existing) {
            throw "Cannot change encryption scope; credential file not found: $filePath"
        }
        Save-OffboardingCredentialSecrets -FilePath $filePath -UserName $existing.Username `
            -PasswordPlain $existing.Password -ProtectionName $protection
        return
    }

    $resolvedUser = $UserName
    $resolvedPasswordPlain = $null
    if ($Password) {
        $resolvedPasswordPlain = ConvertFrom-SecureStringToPlain $Password
    }

    if ($Credential) {
        $resolvedUser = $Credential.UserName
        $resolvedPasswordPlain = ConvertFrom-SecureStringToPlain $Credential.Password
    }

    if ($PasswordOnly) {
        if (-not $existing) {
            throw "Cannot use -PasswordOnly; credential file not found: $filePath"
        }
        $resolvedUser = $existing.Username
    }

    if ([string]::IsNullOrWhiteSpace($resolvedUser)) {
        $hint = if ($existing) { $existing.Username } else { 'svcIAM@owens-minor.com' }
        $entered = Read-Host "Exchange username [$hint]"
        $resolvedUser = if ([string]::IsNullOrWhiteSpace($entered)) { $hint } else { $entered.Trim() }
    }

    if ([string]::IsNullOrWhiteSpace($resolvedPasswordPlain)) {
        if ($PasswordOnly -or $existing) {
            if (-not $Password -and -not $Credential) {
                $resolvedPasswordPlain = ConvertFrom-SecureStringToPlain (Read-ConfirmedPassword -UserName $resolvedUser)
            }
        }
        else {
            $resolvedPasswordPlain = ConvertFrom-SecureStringToPlain (Read-ConfirmedPassword -UserName $resolvedUser)
        }
    }

    if ([string]::IsNullOrWhiteSpace($resolvedUser)) {
        throw 'Username cannot be empty.'
    }
    if ([string]::IsNullOrWhiteSpace($resolvedPasswordPlain)) {
        throw 'Password cannot be empty.'
    }

    Save-OffboardingCredentialSecrets -FilePath $filePath -UserName $resolvedUser `
        -PasswordPlain $resolvedPasswordPlain -ProtectionName $protection
}

if (-not $script:IsDotSourced) {
    $runMenu = -not (
        $PSBoundParameters.ContainsKey('Credential') -or
        $PSBoundParameters.ContainsKey('UserName') -or
        $PSBoundParameters.ContainsKey('Password') -or
        $PSBoundParameters.ContainsKey('ProtectionScope') -or
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

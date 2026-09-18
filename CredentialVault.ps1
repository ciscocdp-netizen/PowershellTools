#Requires -Version 5.1

# ============================================================================
# CredentialVault.ps1
# ----------------------------------------------------------------------------
# Windows PowerShell 5.1 compatible credential encryption toolkit.
#
# Encryption : AES-256-CBC
# Integrity  : HMAC-SHA256 (encrypt-then-MAC)
# Key deriv. : PBKDF2 (Rfc2898DeriveBytes) from a passphrase + random salt
#
# Stores an arbitrary set of fields as JSON, so it works for any credential
# shape (OAuth, Entra ID username/password, on-prem AD accounts, etc.).
#
# IMPORTANT (Windows PowerShell 5.1): never pipe a Hashtable / OrderedDictionary
# to ConvertTo-Json. That emits an array of {Key,Value} objects instead of a
# JSON object, which makes the file unreadable. Always use -InputObject.
#
# Usage:
#   .\CredentialVault.ps1            # fully interactive menu (create / decrypt / usage code)
#   .\CredentialVault.ps1 -SelfTest  # encrypt/decrypt round-trip self-test
#
#   . .\CredentialVault.ps1          # dot-source to load the functions into another script
#   Start-CredentialVault            # same interactive menu after dot-sourcing
#   Unprotect-CredentialFile ...     # programmatic decrypt for your own scripts
# ============================================================================

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'Interactive')]
    [string]$Path,

    [Parameter(ParameterSetName = 'SelfTest')]
    [switch]$SelfTest
)

# Remember this file's path at load time. After another script dot-sources us,
# $PSCommandPath would point at the caller, not the vault.
$script:CredentialVaultScriptPath = $PSCommandPath
if (-not $script:CredentialVaultScriptPath) {
    $script:CredentialVaultScriptPath = $MyInvocation.MyCommand.Path
}

$script:IsDotSourced = ($MyInvocation.InvocationName -eq '.')
$script:LastCredentialPath = $null

# ----------------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------------

function ConvertFrom-SecureStringToPlain {
    param([System.Security.SecureString]$Secure)
    if (-not $Secure) { return '' }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try   { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Test-BytesEqual {
    # Constant-time comparison to avoid timing side-channels
    param([byte[]]$A, [byte[]]$B)
    if ($null -eq $A -or $null -eq $B) { return $false }
    if ($A.Length -ne $B.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $A.Length; $i++) { $diff = $diff -bor ($A[$i] -bxor $B[$i]) }
    return ($diff -eq 0)
}

function ConvertTo-VaultJson {
    # Wrapper that never pipes dictionaries (PS 5.1 would serialize them wrong).
    param(
        [Parameter(Mandatory)] $InputObject,
        [int] $Depth = 20,
        [switch] $Compress
    )
    $jsonParams = @{ InputObject = $InputObject; Depth = $Depth }
    if ($Compress) { $jsonParams.Compress = $true }
    ConvertTo-Json @jsonParams
}

function Get-VaultFullPath {
    param([Parameter(Mandatory)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path cannot be empty.'
    }
    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        $Path = Join-Path -Path (Get-Location).ProviderPath -ChildPath $Path
    }
    return [System.IO.Path]::GetFullPath($Path)
}

function New-VaultKdf {
    param(
        [Parameter(Mandatory)] [byte[]] $Password,
        [Parameter(Mandatory)] [byte[]] $Salt,
        [Parameter(Mandatory)] [int]    $Iterations,
        [string] $Prf = 'SHA256'
    )
    if ($Iterations -lt 10000) {
        throw "PBKDF2 iteration count $Iterations is too low (minimum 10000)."
    }
    $prfName = if ($Prf) { $Prf.ToUpperInvariant() } else { 'SHA1' }

    if ($prfName -eq 'SHA256') {
        try {
            return [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
                $Password,
                $Salt,
                $Iterations,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256
            )
        } catch {
            throw "PBKDF2-SHA256 is not available on this system (.NET 4.7.2+ required). $($_.Exception.Message)"
        }
    }

    # Original Version 1 files (no Prf field) used the framework default HMAC-SHA1.
    return [System.Security.Cryptography.Rfc2898DeriveBytes]::new($Password, $Salt, $Iterations)
}

function Protect-FileAclToCurrentUser {
    param([Parameter(Mandatory)][string]$Path)
    if ($env:OS -ne 'Windows_NT') { return }
    try {
        $acl = Get-Acl -Path $Path
        $acl.SetAccessRuleProtection($true, $false)
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity,
            'FullControl',
            'Allow'
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl
    } catch {
        Write-Warning "Could not restrict NTFS ACLs on '${Path}': $($_.Exception.Message)"
    }
}

function Get-CredentialPropertyExpression {
    param(
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory)][string]$PropertyName
    )
    if ($PropertyName -match '^[A-Za-z_][A-Za-z0-9_]*$') {
        return ('${0}.{1}' -f $ObjectName, $PropertyName)
    }
    $escaped = $PropertyName.Replace("'", "''")
    return ('${0}.''{1}''' -f $ObjectName, $escaped)
}

function Test-VaultHasField {
    param(
        [string[]]$FieldNames,
        [string[]]$Candidates
    )
    # Prefer the candidate list order so "Password" wins over "ClientSecret".
    foreach ($candidate in $Candidates) {
        foreach ($name in $FieldNames) {
            if ([string]::Equals($name, $candidate, [StringComparison]::OrdinalIgnoreCase)) {
                return $name
            }
        }
    }
    return $null
}

function Get-VaultObjectFieldNames {
    param($Object)
    if ($null -eq $Object) { return @() }
    if ($Object -is [System.Collections.IDictionary]) {
        return @($Object.Keys | ForEach-Object { [string]$_ })
    }
    return @($Object.PSObject.Properties.Name)
}

function Test-VaultSecretFieldName {
    param([string]$Name)
    return [bool]($Name -match '(Secret|Password|Token|Key|Pass$|Thumbprint)')
}

function Get-VaultCredentialTemplates {
    return @(
        [pscustomobject]@{
            Id          = 'OAuth'
            Title       = 'OAuth / Entra app registration'
            Summary     = 'TenantId, ClientId, ClientSecret'
            DefaultFile = 'oauth-app.enc'
            Fields      = @(
                [pscustomobject]@{ Name = 'TenantId';     Secret = $false; Prompt = 'Tenant ID (GUID or domain)' }
                [pscustomobject]@{ Name = 'ClientId';     Secret = $false; Prompt = 'Application (client) ID' }
                [pscustomobject]@{ Name = 'ClientSecret'; Secret = $true;  Prompt = 'Client secret' }
            )
        }
        [pscustomobject]@{
            Id          = 'EntraID'
            Title       = 'Entra ID user'
            Summary     = 'UserName, Password, TenantId'
            DefaultFile = 'entra-user.enc'
            Fields      = @(
                [pscustomobject]@{ Name = 'UserName'; Secret = $false; Prompt = 'User principal name (user@domain)' }
                [pscustomobject]@{ Name = 'Password'; Secret = $true;  Prompt = 'Password' }
                [pscustomobject]@{ Name = 'TenantId'; Secret = $false; Prompt = 'Tenant ID (GUID or domain)' }
            )
        }
        [pscustomobject]@{
            Id          = 'OnPremAD'
            Title       = 'On-prem Active Directory'
            Summary     = 'UserName, Password, Domain'
            DefaultFile = 'ad-creds.enc'
            Fields      = @(
                [pscustomobject]@{ Name = 'UserName'; Secret = $false; Prompt = 'User name (DOMAIN\user or UPN)' }
                [pscustomobject]@{ Name = 'Password'; Secret = $true;  Prompt = 'Password' }
                [pscustomobject]@{ Name = 'Domain';   Secret = $false; Prompt = 'AD domain (e.g. CONTOSO or contoso.local)' }
            )
        }
        [pscustomobject]@{
            Id          = 'Custom'
            Title       = 'Custom fields'
            Summary     = 'enter your own field names'
            DefaultFile = 'creds.enc'
            Fields      = @()
        }
    )
}

function Read-VaultYesNo {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [bool]$Default = $true
    )
    $defaultLabel = if ($Default) { 'Y' } else { 'N' }
    while ($true) {
        $answer = Read-Host "$Prompt (Y/N) [$defaultLabel]"
        if ([string]::IsNullOrWhiteSpace($answer)) { return [bool]$Default }
        if ($answer -match '^(y|yes)$') { return $true }
        if ($answer -match '^(n|no)$') { return $false }
        Write-Host 'Please enter Y or N.' -ForegroundColor Yellow
    }
}

function Read-VaultMenuChoice {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string[]]$Valid
    )
    while ($true) {
        $answer = (Read-Host $Prompt)
        if ($null -eq $answer) { $answer = '' }
        $answer = $answer.Trim()
        if ($answer -match '^(q|quit|exit)$') { return 'Q' }
        foreach ($item in $Valid) {
            if ([string]::Equals($answer, $item, [StringComparison]::OrdinalIgnoreCase)) {
                return $item
            }
        }
        Write-Host "Please enter one of: $($Valid -join ', ')" -ForegroundColor Yellow
    }
}

function Read-VaultFilePath {
    param(
        [string]$Prompt = 'Encrypted file path',
        [string]$Default,
        [switch]$MustExist
    )
    if (-not $Default) { $Default = $script:LastCredentialPath }
    if (-not $Default) { $Default = Join-Path (Get-Location).ProviderPath 'creds.enc' }
    while ($true) {
        $answer = Read-Host "$Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $Default }
        try {
            $full = Get-VaultFullPath -Path $answer
        } catch {
            Write-Warning $_.Exception.Message
            continue
        }
        if ($MustExist -and -not (Test-Path -LiteralPath $full)) {
            Write-Warning "File not found: $full"
            continue
        }
        $script:LastCredentialPath = $full
        return $full
    }
}

function Read-VaultSecureInput {
    param([Parameter(Mandatory)][string]$Prompt)
    # Read-Host -AsSecureString needs a real console. When stdin is redirected
    # (tests, piped input) fall back to a normal Read-Host and wrap it.
    $redirected = $false
    try { $redirected = [Console]::IsInputRedirected } catch { $redirected = $false }

    if (-not $redirected) {
        return Read-Host $Prompt -AsSecureString
    }

    $plain = Read-Host $Prompt
    if ([string]::IsNullOrEmpty($plain)) {
        return New-Object System.Security.SecureString
    }
    ConvertTo-SecureString $plain -AsPlainText -Force
}

function Read-VaultFieldValue {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [bool]$Secret = $false,
        [bool]$AllowEmpty = $false
    )
    while ($true) {
        if ($Secret) {
            $sec = Read-VaultSecureInput -Prompt $Prompt
            $val = ConvertFrom-SecureStringToPlain $sec
            if ($sec) { $sec.Dispose() }
        } else {
            $val = Read-Host $Prompt
        }
        if (-not [string]::IsNullOrWhiteSpace($val) -or $AllowEmpty) {
            if ($null -eq $val) { $val = '' }
            return $val
        }
        Write-Warning 'Value cannot be empty.'
    }
}

function Read-VaultPassphraseConfirmed {
    while ($true) {
        $p1 = Read-VaultSecureInput -Prompt 'Encryption passphrase'
        $p2 = Read-VaultSecureInput -Prompt 'Confirm passphrase'
        $plain1 = ConvertFrom-SecureStringToPlain $p1
        $plain2 = ConvertFrom-SecureStringToPlain $p2
        if ($p2) { $p2.Dispose() }
        if ([string]::IsNullOrEmpty($plain1)) {
            Write-Warning 'Passphrase cannot be empty.'
            if ($p1) { $p1.Dispose() }
            continue
        }
        if ($plain1 -cne $plain2) {
            Write-Warning 'Passphrases do not match. Try again.'
            if ($p1) { $p1.Dispose() }
            continue
        }
        if ($plain1.Length -lt 8) {
            Write-Warning 'Passphrase is shorter than 8 characters. Use a longer one for production files.'
        }
        return $p1
    }
}

function Add-VaultCustomFields {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Data)
    Write-Host ''
    Write-Host 'Add extra fields. Leave the field name blank to finish.' -ForegroundColor Cyan
    while ($true) {
        $name = Read-Host 'Field name (blank to finish)'
        if ([string]::IsNullOrWhiteSpace($name)) { break }
        if ($name -eq '_Type') {
            Write-Warning '_Type is reserved. Choose a different field name.'
            continue
        }
        if ($Data.Contains($name)) {
            Write-Warning "Field '$name' already exists."
            continue
        }
        $secretDefault = Test-VaultSecretFieldName $name
        $secret = Read-VaultYesNo -Prompt "Mask input for '$name'?" -Default $secretDefault
        $Data[$name] = Read-VaultFieldValue -Prompt "Value for '$name'" -Secret $secret -AllowEmpty $true
    }
}

function Show-VaultDecryptedFields {
    param(
        $CredentialObject,
        [bool]$RevealSecrets = $false
    )
    $names = Get-VaultObjectFieldNames $CredentialObject
    Write-Host ''
    Write-Host 'Stored fields:' -ForegroundColor Cyan
    foreach ($name in $names) {
        $value = [string]($CredentialObject.$name)
        if ($name -ne '_Type' -and (Test-VaultSecretFieldName $name) -and -not $RevealSecrets) {
            $value = '********'
        }
        Write-Host ("  {0,-16} {1}" -f $name, $value)
    }
}

function Save-VaultUsageSnippet {
    param(
        [Parameter(Mandatory)][string]$Snippet,
        [Parameter(Mandatory)][string]$CredentialPath
    )
    if (-not (Read-VaultYesNo -Prompt 'Save this snippet to a .ps1 file you can paste from?' -Default $false)) {
        return
    }
    $dir  = Split-Path -Parent $CredentialPath
    $base = [System.IO.Path]::GetFileNameWithoutExtension($CredentialPath)
    $default = Join-Path $dir "$base.usage.ps1"
    $out = Read-Host "Snippet file path [$default]"
    if ([string]::IsNullOrWhiteSpace($out)) { $out = $default }
    $out = Get-VaultFullPath -Path $out
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($out, $snippet, $utf8NoBom)
    Write-Host "Wrote usage snippet to: $out" -ForegroundColor Green
}

function Invoke-VaultUsageDisplay {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$FieldNames = @(),
        [string]$TypeLabel
    )
    $snippet = Show-CredentialUsageSnippet -Path $Path -FieldNames $FieldNames -TypeLabel $TypeLabel -PassThru
    if ($snippet) {
        Save-VaultUsageSnippet -Snippet $snippet -CredentialPath $Path
    }
}

# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------

function Protect-CredentialFile {
    <#
    .SYNOPSIS
        Encrypts a set of credential fields to a JSON envelope on disk.
    .PARAMETER Data
        Hashtable / ordered dictionary of fields to encrypt (any shape).
    .PARAMETER Path
        Output path for the encrypted file.
    .PARAMETER Passphrase
        Passphrase used to derive the AES and HMAC keys.
    .PARAMETER Iterations
        PBKDF2 iteration count (default 200000).
    .PARAMETER ShowUsageSnippet
        Print copy-paste PowerShell that decrypts and uses this file.
        Protect-CredentialFile overwrites $Path if it already exists.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary]  $Data,
        [Parameter(Mandatory)] [string]                          $Path,
        [Parameter(Mandatory)] [System.Security.SecureString]    $Passphrase,
        [int] $Iterations = 200000,
        [switch] $ShowUsageSnippet
    )

    Set-StrictMode -Version Latest

    if ($Iterations -lt 10000) {
        throw "Iterations must be at least 10000. Supplied: $Iterations"
    }
    if ($Data.Count -eq 0) {
        throw 'Data cannot be empty.'
    }

    $Path = Get-VaultFullPath -Path $Path
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $plainBytes = $null
    $passBytes  = $null
    $km         = $null
    $aes        = $null
    $hmac       = $null
    $rng        = $null
    $kdf        = $null
    $encryptor  = $null
    $passPlain  = $null

    try {
        $plainText  = ConvertTo-VaultJson -InputObject $Data -Depth 20 -Compress
        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($plainText)

        $passPlain = ConvertFrom-SecureStringToPlain $Passphrase
        if ([string]::IsNullOrEmpty($passPlain)) {
            throw 'Passphrase cannot be empty.'
        }
        $passBytes = [System.Text.Encoding]::UTF8.GetBytes($passPlain)

        $salt = New-Object byte[] 32
        $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($salt)

        $kdf = New-VaultKdf -Password $passBytes -Salt $salt -Iterations $Iterations -Prf 'SHA256'
        $km  = $kdf.GetBytes(64)
        $aesKey  = [byte[]]($km[0..31])
        $hmacKey = [byte[]]($km[32..63])

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.Key     = $aesKey
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.GenerateIV()
        $iv = $aes.IV

        $encryptor   = $aes.CreateEncryptor()
        $cipherBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

        # ::new() avoids PowerShell unrolling the byte[] constructor argument.
        $hmac     = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
        $macInput = New-Object byte[] ($iv.Length + $cipherBytes.Length)
        [Array]::Copy($iv, 0, $macInput, 0, $iv.Length)
        [Array]::Copy($cipherBytes, 0, $macInput, $iv.Length, $cipherBytes.Length)
        $tag = $hmac.ComputeHash($macInput)

        $out = [ordered]@{
            Version    = 1
            Algorithm  = 'AES-256-CBC+HMAC-SHA256'
            Prf        = 'SHA256'
            Iterations = $Iterations
            Salt       = [Convert]::ToBase64String($salt)
            IV         = [Convert]::ToBase64String($iv)
            Cipher     = [Convert]::ToBase64String($cipherBytes)
            HMAC       = [Convert]::ToBase64String($tag)
        }

        # -InputObject is required on Windows PowerShell 5.1 (see file header).
        $jsonText  = ConvertTo-VaultJson -InputObject $out -Depth 5
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($Path, $jsonText, $utf8NoBom)
        Protect-FileAclToCurrentUser -Path $Path
    }
    finally {
        if ($plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
        if ($passBytes)  { [Array]::Clear($passBytes,  0, $passBytes.Length) }
        if ($km)         { [Array]::Clear($km, 0, $km.Length) }
        if ($encryptor)  { $encryptor.Dispose() }
        if ($aes)        { $aes.Dispose() }
        if ($hmac)       { $hmac.Dispose() }
        if ($rng)        { $rng.Dispose() }
        if ($kdf)        { $kdf.Dispose() }
        $passPlain = $null
    }

    Write-Verbose "Encrypted credentials written to $Path"
    if ($ShowUsageSnippet) {
        $typeLabel = $null
        if ($Data.Contains('_Type')) { $typeLabel = [string]$Data['_Type'] }
        Show-CredentialUsageSnippet -Path $Path -FieldNames @($Data.Keys) -TypeLabel $typeLabel
    }
}

function Unprotect-CredentialFile {
    <#
    .SYNOPSIS
        Decrypts a file produced by Protect-CredentialFile / New-EncryptedCredentialFile.
    .OUTPUTS
        PSCustomObject whose properties are the original credential fields.
    .EXAMPLE
        . .\CredentialVault.ps1
        $pass  = Read-Host 'Passphrase' -AsSecureString
        $creds = Unprotect-CredentialFile -Path 'C:\secure\creds.enc' -Passphrase $pass
        $creds.ClientId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]                       $Path,
        [Parameter(Mandatory)] [System.Security.SecureString] $Passphrase
    )

    Set-StrictMode -Version Latest

    $Path = Get-VaultFullPath -Path $Path
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Credential file not found: $Path"
    }

    $json = $null
    try {
        $raw  = [System.IO.File]::ReadAllText($Path)
        $json = $raw | ConvertFrom-Json
    } catch {
        throw "Credential file is not valid JSON: $Path. $($_.Exception.Message)"
    }

    if ($json -is [System.Array]) {
        throw @'
Credential file JSON is an array, not an object.
This usually means the file was written by piping a Hashtable to ConvertTo-Json
in Windows PowerShell 5.1. Re-create the file with this updated CredentialVault.ps1.
'@
    }

    foreach ($required in @('Salt', 'IV', 'Cipher', 'HMAC', 'Iterations')) {
        if (-not ($json.PSObject.Properties.Name -contains $required)) {
            throw "Credential file is missing required property '$required'. File may be corrupt."
        }
    }

    $salt       = [Convert]::FromBase64String($json.Salt)
    $iv         = [Convert]::FromBase64String($json.IV)
    $cipher     = [Convert]::FromBase64String($json.Cipher)
    $tag        = [Convert]::FromBase64String($json.HMAC)
    $iterations = [int]$json.Iterations
    $prf        = 'SHA1'
    if ($json.PSObject.Properties.Name -contains 'Prf' -and $json.Prf) {
        $prf = [string]$json.Prf
    }

    $passBytes  = $null
    $km         = $null
    $aes        = $null
    $hmac       = $null
    $kdf        = $null
    $decryptor  = $null
    $plainBytes = $null
    $passPlain  = $null
    $plain      = $null

    try {
        $passPlain = ConvertFrom-SecureStringToPlain $Passphrase
        $passBytes = [System.Text.Encoding]::UTF8.GetBytes($passPlain)

        $kdf = New-VaultKdf -Password $passBytes -Salt $salt -Iterations $iterations -Prf $prf
        $km  = $kdf.GetBytes(64)
        $aesKey  = [byte[]]($km[0..31])
        $hmacKey = [byte[]]($km[32..63])

        $hmac     = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
        $macInput = New-Object byte[] ($iv.Length + $cipher.Length)
        [Array]::Copy($iv, 0, $macInput, 0, $iv.Length)
        [Array]::Copy($cipher, 0, $macInput, $iv.Length, $cipher.Length)
        $calc = $hmac.ComputeHash($macInput)

        if (-not (Test-BytesEqual $calc $tag)) {
            throw 'Integrity check failed: wrong passphrase or the file was modified.'
        }

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.Key     = $aesKey
        $aes.IV      = $iv
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        $decryptor  = $aes.CreateDecryptor()
        $plainBytes = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
        $plain      = [System.Text.Encoding]::UTF8.GetString($plainBytes)
    }
    finally {
        if ($plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
        if ($passBytes)  { [Array]::Clear($passBytes,  0, $passBytes.Length) }
        if ($km)         { [Array]::Clear($km, 0, $km.Length) }
        if ($decryptor)  { $decryptor.Dispose() }
        if ($aes)        { $aes.Dispose() }
        if ($hmac)       { $hmac.Dispose() }
        if ($kdf)        { $kdf.Dispose() }
        $passPlain = $null
    }

    return ($plain | ConvertFrom-Json)
}

function ConvertTo-PSCredential {
    # Helper to turn stored username/password into a [PSCredential]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Password
    )
    Set-StrictMode -Version Latest
    $sec = ConvertTo-SecureString $Password -AsPlainText -Force
    New-Object System.Management.Automation.PSCredential($UserName, $sec)
}

function Get-CredentialUsageSnippet {
    <#
    .SYNOPSIS
        Builds copy-paste PowerShell that decrypts an encrypted credential file
        and uses the stored fields as credentials in another script.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$FieldNames = @(),
        [string]$TypeLabel,
        [string]$VaultScriptPath
    )

    Set-StrictMode -Version Latest

    $Path = Get-VaultFullPath -Path $Path
    if (-not $VaultScriptPath) { $VaultScriptPath = $script:CredentialVaultScriptPath }
    if (-not $VaultScriptPath) { $VaultScriptPath = Join-Path (Get-Location).ProviderPath 'CredentialVault.ps1' }
    $VaultScriptPath = Get-VaultFullPath -Path $VaultScriptPath

    $escPath  = $Path.Replace("'", "''")
    $escVault = $VaultScriptPath.Replace("'", "''")

    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add('#Requires -Version 5.1')
    [void]$lines.Add('# ---------------------------------------------------------------------------')
    [void]$lines.Add('# Generated by CredentialVault.ps1 — paste into your other script')
    if ($TypeLabel) {
        [void]$lines.Add("# Credential type: $TypeLabel")
    }
    [void]$lines.Add('# ---------------------------------------------------------------------------')
    [void]$lines.Add('')
    [void]$lines.Add('# 1. Load the vault functions (once per session)')
    [void]$lines.Add(". '$escVault'")
    [void]$lines.Add('')
    [void]$lines.Add('# 2. Decrypt the credential file (prompts for the passphrase)')
    [void]$lines.Add("`$pass  = Read-Host 'Passphrase' -AsSecureString")
    [void]$lines.Add("`$creds = Unprotect-CredentialFile -Path '$escPath' -Passphrase `$pass")
    [void]$lines.Add('')

    $usableNames = @($FieldNames | Where-Object { $_ -and $_ -ne '_Type' })
    $step = 3
    if ($usableNames.Count -gt 0) {
        [void]$lines.Add("# ${step}. Fields stored in this file (values stay encrypted on disk):")
        foreach ($name in $usableNames) {
            $expr = Get-CredentialPropertyExpression -ObjectName 'creds' -PropertyName $name
            [void]$lines.Add($expr)
        }
        [void]$lines.Add('')
        $step++
    } else {
        [void]$lines.Add("# ${step}. Access fields as properties, e.g. `$creds.UserName / `$creds.ClientSecret")
        [void]$lines.Add('')
        $step++
    }

    $userField = Test-VaultHasField -FieldNames $usableNames -Candidates @('UserName', 'Username', 'User', 'UPN', 'SamAccountName')
    $passField = Test-VaultHasField -FieldNames $usableNames -Candidates @('Password', 'Pass')
    if ($userField -and $passField) {
        $userExpr = Get-CredentialPropertyExpression -ObjectName 'creds' -PropertyName $userField
        $passExpr = Get-CredentialPropertyExpression -ObjectName 'creds' -PropertyName $passField
        [void]$lines.Add("# ${step}. Optional: wrap as a PSCredential for AD / WinRM / Connect-* cmdlets")
        [void]$lines.Add("`$psCred = ConvertTo-PSCredential -UserName $userExpr -Password $passExpr")
        [void]$lines.Add('# Example: Get-ADUser -Identity someuser -Credential $psCred')
        [void]$lines.Add('')
        $step++
    }

    $tenantField = Test-VaultHasField -FieldNames $usableNames -Candidates @('TenantId', 'Tenant', 'TenantID')
    $clientField = Test-VaultHasField -FieldNames $usableNames -Candidates @('ClientId', 'ApplicationId', 'AppId', 'ClientID')
    $secretField = Test-VaultHasField -FieldNames $usableNames -Candidates @('ClientSecret', 'AppSecret', 'Secret')
    if ($tenantField -and $clientField -and $secretField) {
        $tenantExpr = Get-CredentialPropertyExpression -ObjectName 'creds' -PropertyName $tenantField
        $clientExpr = Get-CredentialPropertyExpression -ObjectName 'creds' -PropertyName $clientField
        $secretExpr = Get-CredentialPropertyExpression -ObjectName 'creds' -PropertyName $secretField
        [void]$lines.Add("# ${step}. Optional: Microsoft Graph app-only login")
        [void]$lines.Add("`$appSecret = ConvertTo-SecureString $secretExpr -AsPlainText -Force")
        [void]$lines.Add("`$appCred   = New-Object System.Management.Automation.PSCredential ($clientExpr, `$appSecret)")
        [void]$lines.Add("Connect-MgGraph -TenantId $tenantExpr -ClientSecretCredential `$appCred")
        [void]$lines.Add('')
    }

    [void]$lines.Add('# Tip: never log $creds or $pass. Clear when finished:')
    [void]$lines.Add('# $creds = $null; $pass.Dispose()')

    return ($lines -join [Environment]::NewLine)
}

function Show-CredentialUsageSnippet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$FieldNames = @(),
        [string]$TypeLabel,
        [string]$VaultScriptPath,
        [switch]$ToClipboard,
        [switch]$PassThru
    )

    Set-StrictMode -Version Latest

    $snippet = Get-CredentialUsageSnippet -Path $Path -FieldNames $FieldNames -TypeLabel $TypeLabel -VaultScriptPath $VaultScriptPath

    $rule = ('=' * 72)
    Write-Host ''
    Write-Host $rule -ForegroundColor Cyan
    Write-Host ' COPY-PASTE: use this encrypted file from another script' -ForegroundColor Cyan
    Write-Host $rule -ForegroundColor Cyan
    Write-Host $snippet -ForegroundColor Yellow
    Write-Host $rule -ForegroundColor Cyan
    Write-Host ''

    $copy = $ToClipboard
    if (-not $PSBoundParameters.ContainsKey('ToClipboard')) {
        $copy = ($env:OS -eq 'Windows_NT')
    }
    if ($copy -and (Get-Command Set-Clipboard -ErrorAction SilentlyContinue)) {
        try {
            Set-Clipboard -Value $snippet
            Write-Host 'Snippet copied to the clipboard.' -ForegroundColor Green
        } catch {
            Write-Verbose "Clipboard copy skipped: $($_.Exception.Message)"
        }
    }

    if ($PassThru) { return $snippet }
}

function New-EncryptedCredentialFile {
    <#
    .SYNOPSIS
        Interactive builder: pick a credential type, enter fields, encrypt, print paste-ready usage code.
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [int]$Iterations = 200000
    )

    Set-StrictMode -Version Latest

    $templates = @(Get-VaultCredentialTemplates)

    Write-Host ''
    Write-Host 'Create a new encrypted credential file' -ForegroundColor Cyan
    Write-Host ''
    for ($i = 0; $i -lt $templates.Count; $i++) {
        $n = $i + 1
        Write-Host ("  [{0}] {1,-34} ({2})" -f $n, $templates[$i].Title, $templates[$i].Summary)
    }
    $typeChoice = Read-VaultMenuChoice -Prompt 'Select credential type' -Valid @('1', '2', '3', '4', 'Q')
    if ($typeChoice -eq 'Q') {
        Write-Warning 'Aborted.'
        return
    }
    $template = $templates[[int]$typeChoice - 1]

    $data = [ordered]@{}
    if ($template.Id -eq 'Custom') {
        $type = Read-Host 'Credential type label (e.g. OAuth, EntraID, OnPremAD) [optional]'
        if ($type) { $data['_Type'] = $type }
        Add-VaultCustomFields -Data $data
    } else {
        $data['_Type'] = $template.Id
        Write-Host ''
        Write-Host ("Enter values for {0}:" -f $template.Title) -ForegroundColor Cyan
        foreach ($field in @($template.Fields)) {
            $data[$field.Name] = Read-VaultFieldValue -Prompt $field.Prompt -Secret ([bool]$field.Secret)
        }
        if (Read-VaultYesNo -Prompt 'Add extra custom fields?' -Default $false) {
            Add-VaultCustomFields -Data $data
        }
    }

    if ($data.Count -eq 0 -or ($data.Count -eq 1 -and $data.Contains('_Type'))) {
        Write-Warning 'No fields entered. Aborting.'
        return
    }

    if (-not $Path) {
        $defaultPath = Join-Path (Get-Location).ProviderPath $template.DefaultFile
        $Path = Read-VaultFilePath -Prompt 'Output file path' -Default $defaultPath
    } else {
        $Path = Get-VaultFullPath -Path $Path
        $script:LastCredentialPath = $Path
    }

    if (Test-Path -LiteralPath $Path) {
        if (-not (Read-VaultYesNo -Prompt "File exists: $Path  Overwrite?" -Default $false)) {
            Write-Warning 'Aborted.'
            return
        }
    }

    $passphrase = $null
    try {
        $passphrase = Read-VaultPassphraseConfirmed
        Protect-CredentialFile -Data $data -Path $Path -Passphrase $passphrase -Iterations $Iterations
    }
    finally {
        if ($passphrase) { $passphrase.Dispose() }
    }

    Write-Host ''
    Write-Host "Encrypted credentials written to: $Path" -ForegroundColor Green

    $typeLabel = $null
    if ($data.Contains('_Type')) { $typeLabel = [string]$data['_Type'] }
    Invoke-VaultUsageDisplay -Path $Path -FieldNames @($data.Keys) -TypeLabel $typeLabel

    if (Read-VaultYesNo -Prompt 'Decrypt now to verify the file?' -Default $true) {
        $verify = $null
        try {
            $verify = Read-VaultSecureInput -Prompt 'Passphrase'
            $roundTrip = Unprotect-CredentialFile -Path $Path -Passphrase $verify
            Write-Host 'Decrypt succeeded.' -ForegroundColor Green
            $reveal = Read-VaultYesNo -Prompt 'Show secret values on screen?' -Default $false
            Show-VaultDecryptedFields -CredentialObject $roundTrip -RevealSecrets $reveal
        } catch {
            Write-Host "Verify failed: $($_.Exception.Message)" -ForegroundColor Red
        } finally {
            if ($verify) { $verify.Dispose() }
        }
    }
}

function Open-EncryptedCredentialFile {
    <#
    .SYNOPSIS
        Interactive decrypt: prompt for path and passphrase, show fields, print paste-ready usage code.
    #>
    [CmdletBinding()]
    param([string]$Path)

    Set-StrictMode -Version Latest

    Write-Host ''
    Write-Host 'Decrypt an existing credential file' -ForegroundColor Cyan
    if (-not $Path) {
        $Path = Read-VaultFilePath -Prompt 'Encrypted file path' -MustExist
    } else {
        $Path = Get-VaultFullPath -Path $Path
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "Credential file not found: $Path"
        }
        $script:LastCredentialPath = $Path
    }

    $passphrase = $null
    try {
        $passphrase = Read-VaultSecureInput -Prompt 'Passphrase'
        $creds = Unprotect-CredentialFile -Path $Path -Passphrase $passphrase
    } catch {
        Write-Host "Decrypt failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    } finally {
        if ($passphrase) { $passphrase.Dispose() }
    }

    Write-Host 'Decrypt succeeded.' -ForegroundColor Green
    $reveal = Read-VaultYesNo -Prompt 'Show secret values on screen?' -Default $false
    Show-VaultDecryptedFields -CredentialObject $creds -RevealSecrets $reveal

    $typeLabel = $null
    $names = Get-VaultObjectFieldNames $creds
    if ($names -contains '_Type') { $typeLabel = [string]$creds._Type }
    Invoke-VaultUsageDisplay -Path $Path -FieldNames $names -TypeLabel $typeLabel
}

function Show-EncryptedCredentialUsage {
    <#
    .SYNOPSIS
        Interactive helper: decrypt just enough to print paste-ready usage code (values stay hidden).
    #>
    [CmdletBinding()]
    param([string]$Path)

    Set-StrictMode -Version Latest

    Write-Host ''
    Write-Host 'Show paste-ready usage code' -ForegroundColor Cyan
    if (-not $Path) {
        $Path = Read-VaultFilePath -Prompt 'Encrypted file path' -MustExist
    } else {
        $Path = Get-VaultFullPath -Path $Path
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "Credential file not found: $Path"
        }
        $script:LastCredentialPath = $Path
    }

    $passphrase = $null
    try {
        $passphrase = Read-VaultSecureInput -Prompt 'Passphrase (needed to discover field names; values are not printed)'
        $creds = Unprotect-CredentialFile -Path $Path -Passphrase $passphrase
    } catch {
        Write-Host "Decrypt failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    } finally {
        if ($passphrase) { $passphrase.Dispose() }
    }

    $typeLabel = $null
    $names = Get-VaultObjectFieldNames $creds
    if ($names -contains '_Type') { $typeLabel = [string]$creds._Type }
    Invoke-VaultUsageDisplay -Path $Path -FieldNames $names -TypeLabel $typeLabel
}

function Start-CredentialVault {
    <#
    .SYNOPSIS
        Fully interactive menu: create, decrypt, or generate usage code for encrypted credentials.
    #>
    [CmdletBinding()]
    param([string]$Path)

    Set-StrictMode -Version Latest

    if ($Path) {
        $script:LastCredentialPath = Get-VaultFullPath -Path $Path
    }

    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host ' Credential Vault' -ForegroundColor Cyan
    Write-Host ' AES-256-CBC + HMAC-SHA256  |  PBKDF2-SHA256' -ForegroundColor DarkCyan
    Write-Host ' Create an encrypted file, then paste the generated code into' -ForegroundColor DarkCyan
    Write-Host ' another script to use those credentials.' -ForegroundColor DarkCyan
    Write-Host '================================================================' -ForegroundColor Cyan

    while ($true) {
        Write-Host ''
        Write-Host '  [1] Create a new encrypted credential file'
        Write-Host '  [2] Decrypt an existing file and show usage code'
        Write-Host '  [3] Show paste-ready usage code for a file'
        Write-Host '  [4] Run self-test'
        Write-Host '  [Q] Quit'
        Write-Host ''
        $choice = Read-VaultMenuChoice -Prompt 'Select an option' -Valid @('1', '2', '3', '4', 'Q')
        if ($choice -eq 'Q') {
            Write-Host 'Bye.'
            break
        }

        try {
            switch ($choice) {
                '1' { New-EncryptedCredentialFile }
                '2' { Open-EncryptedCredentialFile }
                '3' { Show-EncryptedCredentialUsage }
                '4' { Test-CredentialVault | Out-Null }
            }
        } catch {
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        }

        Write-Host ''
        [void](Read-Host 'Press Enter to return to the menu')
    }
}

function Test-CredentialVault {
    <#
    .SYNOPSIS
        Encrypt/decrypt round-trip self-test. Throws on failure.
    #>
    [CmdletBinding()]
    param()

    Set-StrictMode -Version Latest

    $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) ("CredentialVault-{0}.enc" -f [guid]::NewGuid().ToString('N'))
    $pass = ConvertTo-SecureString 'Vault-self-test-passphrase!' -AsPlainText -Force
    $data = [ordered]@{
        _Type        = 'OAuth'
        TenantId     = '11111111-2222-3333-4444-555555555555'
        ClientId     = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        ClientSecret = 'super-secret-value'
        UserName     = 'alice@contoso.com'
        Password     = 'P@ssw0rd'
        'Weird Key'  = 'needs quoting'
    }

    try {
        Protect-CredentialFile -Data $data -Path $tempPath -Passphrase $pass

        $rawJson = [System.IO.File]::ReadAllText($tempPath) | ConvertFrom-Json
        if ($rawJson -is [System.Array]) {
            throw 'Envelope JSON was serialized as an array (ConvertTo-Json piping bug).'
        }
        foreach ($required in @('Salt', 'IV', 'Cipher', 'HMAC', 'Iterations', 'Prf')) {
            if (-not ($rawJson.PSObject.Properties.Name -contains $required)) {
                throw "Envelope missing property '$required'."
            }
        }

        $roundTrip = Unprotect-CredentialFile -Path $tempPath -Passphrase $pass
        foreach ($key in @('TenantId', 'ClientId', 'ClientSecret', 'UserName', 'Password', 'Weird Key', '_Type')) {
            $expected = $data[$key]
            $actual   = $roundTrip.$key
            if ($actual -cne $expected) {
                throw "Round-trip mismatch for '$key'. Expected '$expected', got '$actual'."
            }
        }

        $wrong = ConvertTo-SecureString 'definitely-not-the-passphrase' -AsPlainText -Force
        $failed = $false
        try {
            Unprotect-CredentialFile -Path $tempPath -Passphrase $wrong | Out-Null
        } catch {
            $failed = $true
        }
        if (-not $failed) {
            throw 'Wrong passphrase did not fail integrity check.'
        }

        $tampered = [System.IO.File]::ReadAllText($tempPath)
        $tampered = $tampered.Replace('"Prf"', '"Prf_tamper_marker"').Replace($rawJson.HMAC.Substring(0, 4), 'AAAA')
        [System.IO.File]::WriteAllText($tempPath + '.tampered', $tampered)
        try {
            $failed = $false
            try {
                Unprotect-CredentialFile -Path ($tempPath + '.tampered') -Passphrase $pass | Out-Null
            } catch {
                $failed = $true
            }
            if (-not $failed) {
                throw 'Tampered file did not fail integrity check.'
            }
        } finally {
            Remove-Item -LiteralPath ($tempPath + '.tampered') -ErrorAction SilentlyContinue
        }

        $snippet = Get-CredentialUsageSnippet -Path $tempPath -FieldNames @($data.Keys) -TypeLabel 'OAuth'
        foreach ($needle in @(
            'Unprotect-CredentialFile',
            'Connect-MgGraph',
            '$creds.ClientSecret',
            '$creds.''Weird Key''',
            'ConvertTo-PSCredential -UserName $creds.UserName -Password $creds.Password'
        )) {
            if ($snippet -notlike "*$needle*") {
                throw "Usage snippet missing expected text: $needle"
            }
        }
        if ($snippet -like '*ConvertTo-PSCredential -UserName $creds.UserName -Password $creds.ClientSecret*') {
            throw 'Usage snippet incorrectly used ClientSecret as the PSCredential password.'
        }

        $psCred = ConvertTo-PSCredential -UserName 'alice@contoso.com' -Password 'P@ssw0rd'
        if ($psCred.UserName -ne 'alice@contoso.com') {
            throw 'ConvertTo-PSCredential failed.'
        }

        $templates = @(Get-VaultCredentialTemplates)
        if ($templates.Count -ne 4) {
            throw "Expected 4 credential templates, got $($templates.Count)."
        }
        $oauthNames = @($templates[0].Fields | ForEach-Object { $_.Name })
        foreach ($need in @('TenantId', 'ClientId', 'ClientSecret')) {
            if ($oauthNames -notcontains $need) {
                throw "OAuth template missing field $need"
            }
        }
        if (-not (Test-VaultSecretFieldName 'ClientSecret')) {
            throw 'ClientSecret should be treated as a secret field name.'
        }
        if (Test-VaultSecretFieldName 'TenantId') {
            throw 'TenantId should not be treated as a secret field name.'
        }

        Write-Host 'CredentialVault self-test passed.' -ForegroundColor Green
        return $true
    }
    finally {
        Remove-Item -LiteralPath $tempPath -ErrorAction SilentlyContinue
        if ($pass) { $pass.Dispose() }
    }
}

# Launch the interactive menu when the file is executed (not dot-sourced).
if (-not $script:IsDotSourced) {
    Set-StrictMode -Version Latest
    if ($SelfTest) {
        Test-CredentialVault | Out-Null
    } else {
        Start-CredentialVault -Path $Path
    }
}

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
#   . .\CredentialVault.ps1          # dot-source to load the functions
#   New-EncryptedCredentialFile      # interactive builder (prints paste-ready code)
#   Unprotect-CredentialFile ...     # read the file back in your scripts
#
#   .\CredentialVault.ps1            # run directly to launch the builder
#   .\CredentialVault.ps1 -SelfTest  # encrypt/decrypt round-trip self-test
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
        Interactive builder: collect fields, encrypt them, print paste-ready usage code.
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [int]$Iterations = 200000
    )

    Set-StrictMode -Version Latest

    if (-not $Path) {
        $Path = Read-Host 'Output file path (blank = .\creds.enc)'
        if ([string]::IsNullOrWhiteSpace($Path)) {
            $Path = Join-Path (Get-Location).ProviderPath 'creds.enc'
        }
    }
    $Path = Get-VaultFullPath -Path $Path

    if (Test-Path -LiteralPath $Path) {
        $overwrite = Read-Host "File exists: $Path  Overwrite? (Y/N)"
        if ($overwrite -notmatch '^(y|yes)$') {
            Write-Warning 'Aborted.'
            return
        }
    }

    $data = [ordered]@{}
    $type = Read-Host 'Credential type label (e.g. OAuth, EntraID, OnPremAD) [optional]'
    if ($type) { $data['_Type'] = $type }

    Write-Host ''
    Write-Host 'Enter each credential field. Leave the field name blank to finish.' -ForegroundColor Cyan
    while ($true) {
        $name = Read-Host 'Field name (blank to finish)'
        if ([string]::IsNullOrWhiteSpace($name)) { break }

        $isSecret = Read-Host "Mask input for '$name'? (Y/N)"
        if ($isSecret -match '^(y|yes)$') {
            $sec = Read-Host "Value for '$name'" -AsSecureString
            $data[$name] = ConvertFrom-SecureStringToPlain $sec
        } else {
            $data[$name] = Read-Host "Value for '$name'"
        }
    }

    if ($data.Count -eq 0 -or ($data.Count -eq 1 -and $data.Contains('_Type'))) {
        Write-Warning 'No fields entered. Aborting.'
        return
    }

    $p1 = $null
    $p2 = $null
    try {
        while ($true) {
            $p1 = Read-Host 'Encryption passphrase' -AsSecureString
            $p2 = Read-Host 'Confirm passphrase'    -AsSecureString
            $plain1 = ConvertFrom-SecureStringToPlain $p1
            $plain2 = ConvertFrom-SecureStringToPlain $p2
            if ($plain1 -ceq $plain2) {
                if ($plain1.Length -lt 8) {
                    Write-Warning 'Passphrase is shorter than 8 characters. Use a longer one for production files.'
                }
                break
            }
            Write-Warning 'Passphrases do not match. Try again.'
        }

        Protect-CredentialFile -Data $data -Path $Path -Passphrase $p1 -Iterations $Iterations
    }
    finally {
        if ($p1) { $p1.Dispose() }
        if ($p2) { $p2.Dispose() }
    }

    Write-Host "Encrypted credentials written to: $Path" -ForegroundColor Green
    Show-CredentialUsageSnippet -Path $Path -FieldNames @($data.Keys) -TypeLabel $type
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

        Write-Host 'CredentialVault self-test passed.' -ForegroundColor Green
        return $true
    }
    finally {
        Remove-Item -LiteralPath $tempPath -ErrorAction SilentlyContinue
        if ($pass) { $pass.Dispose() }
    }
}

# Launch the builder when the file is executed (not dot-sourced).
if (-not $script:IsDotSourced) {
    Set-StrictMode -Version Latest
    if ($SelfTest) {
        Test-CredentialVault | Out-Null
    } else {
        New-EncryptedCredentialFile -Path $Path
    }
}

#Requires -Version 5.1
<#
.SYNOPSIS
    Decrypt Exchange Online service-account credentials from a CredentialVault file.

.DESCRIPTION
    Loads Unprotect-CredentialFile / ConvertTo-PSCredential from CredentialVault.ps1
    (or Encrypt_Creds.ps1) and returns a PSCredential for Connect-ExchangeOnline.

    Encrypted files are created with CredentialVault.ps1 using the ExchangeCreds
    template (Username + Password).
#>

function Resolve-CredentialVaultScriptPath {
    [CmdletBinding()]
    param(
        [string]$ConfiguredPath,
        [string]$SearchRoot
    )

    $candidates = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath)) {
        [void]$candidates.Add($ConfiguredPath)
    }
    if (-not [string]::IsNullOrWhiteSpace($SearchRoot)) {
        [void]$candidates.Add((Join-Path $SearchRoot 'CredentialVault.ps1'))
        [void]$candidates.Add((Join-Path $SearchRoot 'Encrypt_Creds.ps1'))
    }

    foreach ($path in $candidates) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            return (Get-Item -LiteralPath $path).FullName
        }
    }

    $looked = if ($candidates.Count) { $candidates -join '; ' } else { '(no paths supplied)' }
    throw "Credential vault script not found. Looked for: $looked"
}

function Import-CredentialVaultFunctions {
    [CmdletBinding()]
    param(
        [string]$ConfiguredPath,
        [string]$SearchRoot = $PSScriptRoot
    )

    if (Get-Command Unprotect-CredentialFile -ErrorAction SilentlyContinue) {
        return
    }

    $vault = Resolve-CredentialVaultScriptPath -ConfiguredPath $ConfiguredPath -SearchRoot $SearchRoot
    . $vault

    if (-not (Get-Command Unprotect-CredentialFile -ErrorAction SilentlyContinue)) {
        throw "Loaded '$vault' but Unprotect-CredentialFile is not available."
    }
}

function ConvertTo-VaultPassphraseSecureString {
    [CmdletBinding()]
    param(
        $Passphrase,
        [string]$Prompt = 'Enter Exchange credential file passphrase'
    )

    if ($Passphrase -is [System.Security.SecureString]) {
        return @{ SecureString = $Passphrase; CreatedHere = $false }
    }

    if ($Passphrase -is [string] -and -not [string]::IsNullOrWhiteSpace($Passphrase)) {
        return @{
            SecureString = (ConvertTo-SecureString -String $Passphrase -AsPlainText -Force)
            CreatedHere  = $true
        }
    }

    $envPass = [Environment]::GetEnvironmentVariable('EXCHANGE_CRED_PASSPHRASE')
    if (-not [string]::IsNullOrWhiteSpace($envPass)) {
        return @{
            SecureString = (ConvertTo-SecureString -String $envPass -AsPlainText -Force)
            CreatedHere  = $true
        }
    }

    return @{
        SecureString = (Read-Host $Prompt -AsSecureString)
        CreatedHere  = $true
    }
}

function Get-VaultCredentialField {
    [CmdletBinding()]
    param(
        $CredentialObject,
        [Parameter(Mandatory)]
        [string[]]$FieldNames
    )

    if ($null -eq $CredentialObject) {
        return $null
    }

    foreach ($name in $FieldNames) {
        $prop = $CredentialObject.PSObject.Properties[$name]
        if ($prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
            return [string]$prop.Value
        }
    }

    return $null
}

function Get-ExchangeOnlineVaultCredential {
    <#
    .SYNOPSIS
        Decrypt a CredentialVault ExchangeCreds file and return a PSCredential.

    .EXAMPLE
        . .\Get-ExchangeOnlineVaultCredential.ps1
        $pass = Read-Host 'Passphrase' -AsSecureString
        $cred = Get-ExchangeOnlineVaultCredential -CredentialFile .\creds.enc -Passphrase $pass
        Connect-ExchangeOnline -Credential $cred
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CredentialFile,

        [string]$VaultScript,

        [string]$SearchRoot = $PSScriptRoot,

        $Passphrase,

        [string]$FallbackUserName
    )

    Import-CredentialVaultFunctions -ConfiguredPath $VaultScript -SearchRoot $SearchRoot

    if (-not (Test-Path -LiteralPath $CredentialFile)) {
        throw "Encrypted credential file not found: $CredentialFile"
    }

    $passInfo = ConvertTo-VaultPassphraseSecureString -Passphrase $Passphrase
    $creds = $null
    try {
        $creds = Unprotect-CredentialFile -Path $CredentialFile -Passphrase $passInfo.SecureString

        $userName = Get-VaultCredentialField -CredentialObject $creds -FieldNames @(
            'Username', 'UserName', 'User', 'UPN', 'SamAccountName'
        )
        if ([string]::IsNullOrWhiteSpace($userName)) {
            $userName = $FallbackUserName
        }

        $password = Get-VaultCredentialField -CredentialObject $creds -FieldNames @('Password', 'Pass')

        if ([string]::IsNullOrWhiteSpace($userName) -or [string]::IsNullOrWhiteSpace($password)) {
            throw "Encrypted credential file '$CredentialFile' does not contain Username and Password."
        }

        return (ConvertTo-PSCredential -UserName $userName -Password $password)
    }
    finally {
        $creds = $null
        if ($passInfo.CreatedHere -and $passInfo.SecureString) {
            $passInfo.SecureString.Dispose()
        }
    }
}

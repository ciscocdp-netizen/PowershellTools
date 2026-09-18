#Requires -Version 5.1
# Compatibility wrapper. Generated CredentialVault snippets often dot-source
# Encrypt_Creds.ps1; the functions live in CredentialVault.ps1 beside this file.
$script:EncryptCredsDotSourced = ($MyInvocation.InvocationName -eq '.')
$vaultPath = Join-Path $PSScriptRoot 'CredentialVault.ps1'
if (-not (Test-Path -LiteralPath $vaultPath)) {
    throw "CredentialVault.ps1 not found next to Encrypt_Creds.ps1: $vaultPath"
}
. $vaultPath
if (-not $script:EncryptCredsDotSourced) {
    Start-CredentialVault
}

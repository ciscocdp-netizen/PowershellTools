#Requires -Version 5.1
<#
.SYNOPSIS
    Exports detailed Microsoft Teams call records for a user.

.DESCRIPTION
    Uses Microsoft Graph /communications/callRecords to resolve a user, find calls
    in the last 30 days, and write Calls.csv, Participants.csv, Endpoints.csv,
    TargetUser.json, Summary.txt, and the unmodified Graph payloads under RawJson.

    Call records require application permissions. Delegated Graph sign-in is rejected
    by the API. Grant admin consent for:
        CallRecords.Read.All
        User.Read.All

    Graph keeps call records for 30 days, and a record appears only after the call ends.

.EXAMPLE
    .\Get-TeamsUserCallDetails.ps1 -User alice@contoso.com -TenantId <tenant-guid> `
        -ClientId <app-guid> -CertificateThumbprint <thumbprint>

.EXAMPLE
    $secret = Read-Host -AsSecureString "Client secret"
    .\Get-TeamsUserCallDetails.ps1 -User alice@contoso.com -TenantId <tenant-guid> `
        -ClientId <app-guid> -ClientSecret $secret -StartDate (Get-Date).AddDays(-7)

.EXAMPLE
    .\Get-TeamsUserCallDetails.ps1 -User alice@contoso.com -Sample
#>
[CmdletBinding(DefaultParameterSetName = 'Certificate')]
param(
    [Parameter(Mandatory)]
    [string] $User,

    [datetime] $StartDate = (Get-Date).AddDays(-29),

    [datetime] $EndDate = (Get-Date),

    [string] $OutputPath = (Join-Path (Get-Location) ("TeamsCallReport_{0:yyyyMMdd_HHmmss}" -f (Get-Date))),

    [Parameter(Mandatory, ParameterSetName = 'Certificate')]
    [Parameter(Mandatory, ParameterSetName = 'Secret')]
    [Parameter(Mandatory, ParameterSetName = 'Pfx')]
    [string] $TenantId,

    [Parameter(Mandatory, ParameterSetName = 'Certificate')]
    [Parameter(Mandatory, ParameterSetName = 'Secret')]
    [Parameter(Mandatory, ParameterSetName = 'Pfx')]
    [string] $ClientId,

    [Parameter(Mandatory, ParameterSetName = 'Certificate')]
    [string] $CertificateThumbprint,

    [Parameter(Mandatory, ParameterSetName = 'Pfx')]
    [string] $CertificatePath,

    [Parameter(ParameterSetName = 'Pfx')]
    [securestring] $CertificatePassword,

    [Parameter(Mandatory, ParameterSetName = 'Secret')]
    [securestring] $ClientSecret,

    [Parameter(Mandatory, ParameterSetName = 'Existing')]
    [switch] $UseExistingConnection,

    [Parameter(Mandatory, ParameterSetName = 'Sample')]
    [switch] $Sample,

    [ValidateSet('Public', 'USGov', 'USGovDoD')]
    [string] $Cloud = 'Public',

    [switch] $SkipDirectoryLookup,

    [switch] $SkipRawJson,

    [int] $MaxCalls = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
. (Join-Path $PSScriptRoot 'TeamsCallReport.Core.ps1')

$log = {
    param($Level, $Message)
    $color = 'Gray'
    if ($Level -eq 'WARN') { $color = 'Yellow' }
    elseif ($Level -eq 'ERROR') { $color = 'Red' }
    elseif ($Level -eq 'INFO') { $color = 'Cyan' }
    Write-Host ("{0,-5} {1}" -f $Level, $Message) -ForegroundColor $color
}
$progress = {
    param($Percent, $Status)
    Write-Progress -Activity 'Collecting Teams call details' -Status $Status -PercentComplete $Percent
}

if ($Sample) {
    Write-Host 'Using built-in sample call records (no tenant connection).' -ForegroundColor Yellow
    $client = New-TeamsSampleGraphClient
}
else {
    $clientParams = @{ Cloud = $Cloud }
    switch ($PSCmdlet.ParameterSetName) {
        'Certificate' {
            $clientParams.TenantId = $TenantId
            $clientParams.ClientId = $ClientId
            $clientParams.CertificateThumbprint = $CertificateThumbprint
        }
        'Pfx' {
            $clientParams.TenantId = $TenantId
            $clientParams.ClientId = $ClientId
            $clientParams.CertificatePath = $CertificatePath
            if ($CertificatePassword) { $clientParams.CertificatePassword = $CertificatePassword }
        }
        'Secret' {
            $clientParams.TenantId = $TenantId
            $clientParams.ClientId = $ClientId
            $clientParams.ClientSecret = $ClientSecret
        }
        'Existing' {
            $clientParams.UseExistingConnection = $true
        }
    }
    Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
    $client = New-TeamsGraphClient @clientParams
    $info = $client.TokenInfo
    if ($info) {
        $roles = @($info.Roles) -join ', '
        if (-not $roles) { $roles = '(none)' }
        Write-Host ("Connected. Tenant {0}; auth {1}; roles: {2}" -f $info.TenantId, $info.AuthType, $roles) -ForegroundColor Cyan
        foreach ($warning in @($info.Warnings)) {
            if ($warning) { Write-Warning $warning }
        }
    }
}

$exportParams = @{
    User                = $User
    StartDate           = $StartDate
    EndDate             = $EndDate
    OutputPath          = $OutputPath
    GraphClient         = $client
    MaxCalls            = $MaxCalls
    Log                 = $log
    Progress            = $progress
}
if ($SkipDirectoryLookup) { $exportParams.SkipDirectoryLookup = $true }
if ($SkipRawJson) { $exportParams.SkipRawJson = $true }

$result = Export-TeamsUserCallDetails @exportParams
Write-Progress -Activity 'Collecting Teams call details' -Completed

Write-Host ''
if ($result.SummaryText) { Write-Host $result.SummaryText }
if ($result.ErrorMessage) {
    Write-Host $result.ErrorMessage -ForegroundColor Red
    exit 1
}
if ($result.Cancelled) { exit 2 }
exit 0

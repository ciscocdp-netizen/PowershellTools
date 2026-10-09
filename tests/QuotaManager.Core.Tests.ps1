#Requires -Version 5.1
<#
    Tests for quota parsing, CSV header detection, quota ordering, and licenses.
    Run: pwsh -NoProfile -File tests/QuotaManager.Core.Tests.ps1
#>

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..' 'QuotaManager.Core.ps1')

$script:failures = New-Object System.Collections.Generic.List[string]
$script:passed = 0

function Assert-True {
    param([string]$Name, [bool]$Condition)
    if ($Condition) {
        $script:passed++
    }
    else {
        $script:failures.Add($Name) | Out-Null
        Write-Host "FAIL  $Name"
    }
}

function Assert-Equal {
    param([string]$Name, $Actual, $Expected)
    if (([string]$Actual) -eq ([string]$Expected)) {
        $script:passed++
    }
    else {
        $script:failures.Add("$Name | actual='$Actual' expected='$Expected'") | Out-Null
        Write-Host "FAIL  $Name"
        Write-Host "      actual:   $Actual"
        Write-Host "      expected: $Expected"
    }
}

function Assert-Null {
    param([string]$Name, $Actual)
    Assert-True $Name ($null -eq $Actual)
}

function New-Row {
    param([hashtable]$Values)
    return [pscustomobject]$Values
}

# Header normalization ignores spaces, punctuation, and case.
Assert-Equal 'normalize spaced header' (Get-NormalizedHeaderName 'Prohibit Send Receive (GB)') 'prohibitsendreceivegb'
Assert-Equal 'normalize bom and mixed case' (Get-NormalizedHeaderName "$( [char]0xFEFF )User Principal Name") 'userprincipalname'

$map = Get-CsvColumnMap -Headers @(
    'Display Name', 'E-mail', 'Prohibit Send Receive (GB)', 'Prohibit Send (GB)', 'Issue Warning (GB)'
)
Assert-Equal 'detect email identity' $map.Identity 'E-mail'
Assert-Equal 'detect display name' $map.DisplayName 'Display Name'
Assert-Equal 'detect receive' $map.ProhibitSendReceiveGB 'Prohibit Send Receive (GB)'
Assert-Equal 'detect send' $map.ProhibitSendGB 'Prohibit Send (GB)'
Assert-Equal 'detect warning' $map.IssueWarningGB 'Issue Warning (GB)'

# ProhibitSend must not consume ProhibitSendReceive.
$exact = Get-CsvColumnMap -Headers @('UserPrincipalName', 'ProhibitSendQuota', 'ProhibitSendReceiveQuota', 'IssueWarningQuota')
Assert-Equal 'exact identity' $exact.Identity 'UserPrincipalName'
Assert-Equal 'exact send is not receive' $exact.ProhibitSendGB 'ProhibitSendQuota'
Assert-Equal 'exact receive' $exact.ProhibitSendReceiveGB 'ProhibitSendReceiveQuota'
Assert-Equal 'exact warning' $exact.IssueWarningGB 'IssueWarningQuota'

$screenshot = Get-CsvColumnMap -Headers @('ProhibitSendReceiveGB', 'ProhibitSendGB', 'IssueWarningGB', 'UPN')
Assert-Equal 'screenshot receive' $screenshot.ProhibitSendReceiveGB 'ProhibitSendReceiveGB'
Assert-Equal 'screenshot send' $screenshot.ProhibitSendGB 'ProhibitSendGB'
Assert-Equal 'screenshot warning' $screenshot.IssueWarningGB 'IssueWarningGB'
Assert-Equal 'upn identity' $screenshot.Identity 'UPN'

$nameOnly = Get-CsvColumnMap -Headers @('Name', 'QuotaInGB')
Assert-Equal 'name fallback is identity' $nameOnly.Identity 'Name'
Assert-Null 'name fallback is not also display' $nameOnly.DisplayName
Assert-Equal 'quota fallback column' $nameOnly.QuotaInGB 'QuotaInGB'

$nameAndUpn = Get-CsvColumnMap -Headers @('Name', 'UserPrincipalName')
Assert-Equal 'upn wins over name' $nameAndUpn.Identity 'UserPrincipalName'
Assert-Equal 'name becomes display' $nameAndUpn.DisplayName 'Name'

# Original template used explicit quota columns AND QuotaInGB. Explicit columns win.
$legacy = Get-CsvColumnMap -Headers @(
    'DisplayName', 'UserPrincipalName', 'MailboxType',
    'ProhibitSendReceiveQuota', 'QuotaInGB', 'IssueWarningQuota', 'ProhibitSendQuota'
)
Assert-Equal 'legacy receive' $legacy.ProhibitSendReceiveGB 'ProhibitSendReceiveQuota'
Assert-Equal 'legacy send' $legacy.ProhibitSendGB 'ProhibitSendQuota'
Assert-Equal 'legacy warning' $legacy.IssueWarningGB 'IssueWarningQuota'
Assert-Equal 'legacy shorthand kept' $legacy.QuotaInGB 'QuotaInGB'

$legacyRow = Resolve-MailboxQuotaRow -ColumnMap $legacy -Row (New-Row @{
    DisplayName = 'John Doe'
    UserPrincipalName = 'john.doe@company.com'
    MailboxType = 'UserMailbox'
    ProhibitSendReceiveQuota = '50GB'
    QuotaInGB = '100'
    IssueWarningQuota = '99GB'
    ProhibitSendQuota = '100GB'
})
Assert-Equal 'explicit receive is not replaced by QuotaInGB' (Format-QuotaNumber $legacyRow.ProhibitSendReceiveGB) '50'
Assert-Equal 'explicit send kept' (Format-QuotaNumber $legacyRow.ProhibitSendGB) '100'
Assert-Equal 'explicit warning kept' (Format-QuotaNumber $legacyRow.IssueWarningGB) '99'
Assert-True 'inconsistent legacy row is not marked fallback' (-not $legacyRow.UsedQuotaFallback)
$legacyMessage = Format-QuotaValidationMessage -ParseErrors $legacyRow.Errors -HasQuotaValue $legacyRow.HasQuotaValue -UsedQuotaFallback $false -IssueWarningGB $legacyRow.IssueWarningGB -ProhibitSendGB $legacyRow.ProhibitSendGB -ProhibitSendReceiveGB $legacyRow.ProhibitSendReceiveGB
Assert-True 'inconsistent legacy quotas are rejected' $legacyMessage.StartsWith('Error:')

$fallbackRow = Resolve-MailboxQuotaRow -ColumnMap $nameOnly -Row (New-Row @{ Name = 'jane@company.com'; QuotaInGB = '100' })
Assert-Equal 'fallback receive' (Format-QuotaNumber $fallbackRow.ProhibitSendReceiveGB) '100'
Assert-Equal 'fallback send' (Format-QuotaNumber $fallbackRow.ProhibitSendGB) '100'
Assert-Equal 'fallback warning is one less' (Format-QuotaNumber $fallbackRow.IssueWarningGB) '99'
Assert-True 'fallback flag set' $fallbackRow.UsedQuotaFallback
Assert-Equal 'fallback message' (Format-QuotaValidationMessage -ParseErrors @() -HasQuotaValue $true -UsedQuotaFallback $true -IssueWarningGB 99 -ProhibitSendGB 100 -ProhibitSendReceiveGB 100) 'Ready (from QuotaInGB)'

$oneGb = Resolve-MailboxQuotaRow -ColumnMap $nameOnly -Row (New-Row @{ Name = 'a@b.com'; QuotaInGB = '1' })
Assert-Equal '1 GB warning stays 1' (Format-QuotaNumber $oneGb.IssueWarningGB) '1'

$partialMap = Get-CsvColumnMap -Headers @('Email', 'ProhibitSendReceiveGB', 'QuotaInGB')
$partial = Resolve-MailboxQuotaRow -ColumnMap $partialMap -Row (New-Row @{ Email = 'a@b.com'; ProhibitSendReceiveGB = '80'; QuotaInGB = '50' })
Assert-Equal 'partial receive' (Format-QuotaNumber $partial.ProhibitSendReceiveGB) '80'
Assert-Null 'partial does not invent send from QuotaInGB' $partial.ProhibitSendGB
Assert-True 'partial is not a full fallback' (-not $partial.UsedQuotaFallback)

Assert-Equal 'plain number' (Format-QuotaNumber (ConvertTo-QuotaGigabytes '50')) '50'
Assert-Equal 'gb suffix' (Format-QuotaNumber (ConvertTo-QuotaGigabytes '50GB')) '50'
Assert-Equal 'spaced gb' (Format-QuotaNumber (ConvertTo-QuotaGigabytes '50 gb')) '50'
Assert-Equal 'decimal comma' (Format-QuotaNumber (ConvertTo-QuotaGigabytes '50,5 GB')) '50.5'
Assert-Equal 'megabytes' (Format-QuotaNumber (ConvertTo-QuotaGigabytes '1536MB')) '1.5'
Assert-Equal 'exchange display text' (Format-QuotaNumber (ConvertTo-QuotaGigabytes '49.5 GB (53,150,220,288 bytes)')) '49.5'
Assert-Equal 'parameter format' (Format-ExchangeQuotaParameter 50.5) '50.5GB'
Assert-Null 'blank quota' (ConvertTo-QuotaGigabytes '  ')
Assert-Null 'na quota' (ConvertTo-QuotaGigabytes 'n/a')
Assert-Null 'unlimited exchange value' (ConvertFrom-ExchangeQuotaValue 'Unlimited')

$threw = $false
try { ConvertTo-QuotaGigabytes 'unlimited' } catch { $threw = $true }
Assert-True 'unlimited is rejected as an input' $threw
$threw = $false
try { ConvertTo-QuotaGigabytes 'lots' } catch { $threw = $true }
Assert-True 'words are rejected' $threw

$badOrder = Test-QuotaTargets -IssueWarningGB 99 -ProhibitSendGB 98 -ProhibitSendReceiveGB 100
Assert-True 'warning above send is invalid' (-not $badOrder.IsValid)
$sendAbove = Test-QuotaTargets -IssueWarningGB 40 -ProhibitSendGB 80 -ProhibitSendReceiveGB 50
Assert-True 'send above receive is invalid' (-not $sendAbove.IsValid)
$equal = Test-QuotaTargets -IssueWarningGB 50 -ProhibitSendGB 50 -ProhibitSendReceiveGB 50
Assert-True 'equal quotas are valid' $equal.IsValid
$over = Test-QuotaTargets -IssueWarningGB 98 -ProhibitSendGB 99 -ProhibitSendReceiveGB 150
Assert-True 'over 100 is a warning, not a block' ($over.IsValid -and $over.Warnings.Count -gt 0)
Assert-True 'same quota ignores scale' (Test-SameQuota 50 '50.00')
Assert-True 'different quota is not the same' (-not (Test-SameQuota 50 50.5))

$merged = Merge-QuotaTargets -CurrentIssueWarningGB 90 -CurrentProhibitSendGB 95 -CurrentProhibitSendReceiveGB 100 -RequestedIssueWarningGB 92 -RequestedProhibitSendGB $null -RequestedProhibitSendReceiveGB $null
Assert-Equal 'merge keeps current send' (Format-QuotaNumber $merged.ProhibitSendGB) '95'
Assert-Equal 'merge uses requested warning' (Format-QuotaNumber $merged.IssueWarningGB) '92'
Assert-True 'merge reports a change' $merged.Changed
Assert-True 'merge is complete' $merged.IsComplete

$raise = @(Get-MailboxQuotaWriteSteps -CurrentIssueWarningGB 90 -CurrentProhibitSendGB 95 -CurrentProhibitSendReceiveGB 100 -TargetIssueWarningGB 98 -TargetProhibitSendGB 99 -TargetProhibitSendReceiveGB 110)
Assert-Equal 'raise step count' $raise.Count 3
Assert-Equal 'raise receive first' $raise[0].ProhibitSendReceiveQuota '110GB'
Assert-Null 'raise receive does not set warning yet' $raise[0].IssueWarningQuota
Assert-Equal 'raise send second' $raise[1].ProhibitSendQuota '99GB'
Assert-Equal 'final warning' $raise[2].IssueWarningQuota '98GB'
Assert-Equal 'final send' $raise[2].ProhibitSendQuota '99GB'
Assert-Equal 'final receive' $raise[2].ProhibitSendReceiveQuota '110GB'

$lower = @(Get-MailboxQuotaWriteSteps -CurrentIssueWarningGB 98 -CurrentProhibitSendGB 99 -CurrentProhibitSendReceiveGB 100 -TargetIssueWarningGB 90 -TargetProhibitSendGB 95 -TargetProhibitSendReceiveGB 96)
Assert-Equal 'shrink is one command' $lower.Count 1
Assert-Equal 'shrink warning' $lower[0].IssueWarningQuota '90GB'

$testSteps = @(Get-MailboxQuotaWriteSteps -CurrentIssueWarningGB 90 -CurrentProhibitSendGB 95 -CurrentProhibitSendReceiveGB 100 -TargetIssueWarningGB 98 -TargetProhibitSendGB 99 -TargetProhibitSendReceiveGB 110 -TestMode:$true)
Assert-Equal 'test mode is one command' $testSteps.Count 1

$noCurrent = @(Get-MailboxQuotaWriteSteps -TargetIssueWarningGB 98 -TargetProhibitSendGB 99 -TargetProhibitSendReceiveGB 100)
Assert-Equal 'missing current values are one command' $noCurrent.Count 1

# CSV files: semicolon headers, one data row, and a BOM on the first header.
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("quota-tests-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $semiPath = Join-Path $temp 'semi.csv'
    $semiText = "Email;Prohibit Send Receive (GB);Prohibit Send (GB);Issue Warning (GB)`r`na@b.com;100;99;98`r`n"
    [System.IO.File]::WriteAllText($semiPath, $semiText)
    $semi = Import-QuotaCsv -Path $semiPath
    Assert-Equal 'semicolon delimiter' $semi.Delimiter 'Semicolon'
    Assert-Equal 'one row stays one row' $semi.Rows.Count 1
    Assert-Equal 'semicolon identity' $semi.ColumnMap.Identity 'Email'
    Assert-Equal 'semicolon receive' $semi.ColumnMap.ProhibitSendReceiveGB 'Prohibit Send Receive (GB)'
    $resolvedSemi = Resolve-MailboxQuotaRow -Row $semi.Rows[0] -ColumnMap $semi.ColumnMap
    Assert-Equal 'semicolon value' (Format-QuotaNumber $resolvedSemi.ProhibitSendGB) '99'

    $bomPath = Join-Path $temp 'bom.csv'
    $bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($bomPath, "UserPrincipalName,IssueWarningGB`r`nj@x.com,10`r`n", $bom)
    $bomCsv = Import-QuotaCsv -Path $bomPath
    Assert-Equal 'bom header is clean' $bomCsv.Headers[0] 'UserPrincipalName'
    Assert-Equal 'bom identity maps' $bomCsv.ColumnMap.Identity 'UserPrincipalName'
    $bomRow = Resolve-MailboxQuotaRow -Row $bomCsv.Rows[0] -ColumnMap $bomCsv.ColumnMap
    Assert-Equal 'bom user' $bomRow.Identity 'j@x.com'
    Assert-Equal 'bom warning' (Format-QuotaNumber $bomRow.IssueWarningGB) '10'

    $empty = $false
    try { Import-QuotaCsv -Path (Join-Path $temp 'missing.csv') } catch { $empty = $true }
    Assert-True 'missing file throws' $empty
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}

$graphLicense = [pscustomobject]@{
    SkuPartNumber = 'SPE_E3'
    SkuId = '11111111-1111-1111-1111-111111111111'
    ServicePlans = @(
        [pscustomobject]@{ ServicePlanName = 'EXCHANGE_S_ENTERPRISE'; ProvisioningStatus = 'Success' }
        [pscustomobject]@{ ServicePlanName = 'TEAMS1'; ProvisioningStatus = 'Success' }
        [pscustomobject]@{ ServicePlanName = 'EXCHANGE_S_ARCHIVE_ADDON'; ProvisioningStatus = 'Disabled' }
    )
}
$unknown = [pscustomobject]@{
    SkuPartNumber = 'CONTOSO_CUSTOM'
    SkuId = '22222222-2222-2222-2222-222222222222'
    ServicePlans = @()
}
$msol = [pscustomobject]@{
    AccountSkuId = 'contoso:POWER_BI_STANDARD'
    ServiceStatus = @(
        [pscustomobject]@{
            ServicePlan = [pscustomobject]@{ ServiceName = 'BI_AZURE_P0' }
            ProvisioningStatus = 'Success'
        }
    )
}

$normalized = @(ConvertTo-NormalizedLicenses @($graphLicense, $unknown, $msol))
Assert-Equal 'every license is kept' $normalized.Count 3
$summary = Format-LicenseSummary @($graphLicense, $unknown, $msol)
Assert-True 'known sku has a product name' ($summary.Contains('Microsoft 365 E3 (SPE_E3)'))
Assert-True 'unknown sku is still shown' ($summary.Contains('CONTOSO_CUSTOM'))
Assert-True 'account sku prefix is removed' ($summary.Contains('Power BI (Free) (POWER_BI_STANDARD)'))
Assert-True 'summary does not hide a license' ($summary.Split(';').Count -eq 3)

$e3 = $normalized | Where-Object { $_.SkuPartNumber -eq 'SPE_E3' } | Select-Object -First 1
Assert-Equal 'enabled plan count' @($e3.EnabledPlans).Count 2
Assert-Equal 'disabled plan count' @($e3.DisabledPlans).Count 1
$enabledText = Format-ServicePlanList $e3.EnabledPlans
Assert-True 'exchange plan 2 is visible inside the suite' ($enabledText.Contains('Exchange Online (Plan 2)') -and $enabledText.Contains('EXCHANGE_S_ENTERPRISE'))
Assert-True 'disabled archive is not in the enabled list' (-not $enabledText.Contains('ARCHIVE'))
Assert-Equal 'no licenses text' (Format-LicenseSummary @()) 'No licenses assigned'

$plan1Warning = @(Get-LicenseQuotaWarnings -Licenses @($graphLicense) -ProhibitSendReceiveGB 80)
Assert-Equal 'plan 2 under 100 has no extra warning' $plan1Warning.Count 0
$plan2Over = @(Get-LicenseQuotaWarnings -Licenses @($graphLicense) -ProhibitSendReceiveGB 120)
Assert-True 'plan 2 over 100 warns' ($plan2Over.Count -eq 1 -and $plan2Over[0].Contains('100 GB'))

$plan1 = [pscustomobject]@{
    SkuPartNumber = 'EXCHANGESTANDARD'
    SkuId = '33333333-3333-3333-3333-333333333333'
    ServicePlans = @(
        [pscustomobject]@{ ServicePlanName = 'EXCHANGE_S_STANDARD'; ProvisioningStatus = 'Success' }
    )
}
$plan1Limit = @(Get-LicenseQuotaWarnings -Licenses @($plan1) -ProhibitSendReceiveGB 80)
Assert-True 'plan 1 over 50 warns' ($plan1Limit.Count -eq 1 -and $plan1Limit[0].Contains('50 GB'))

# The window script must at least parse. It is not executed here.
$guiPath = Join-Path $PSScriptRoot '..' 'Exchange-Online-Quota-Manager.ps1'
$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $guiPath), [ref]$tokens, [ref]$parseErrors)
Assert-Equal 'gui parse error count' @($parseErrors).Count 0
if (@($parseErrors).Count -gt 0) {
    $parseErrors | ForEach-Object { Write-Host $_.ToString() }
}
$coreTokens = $null
$coreErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path (Join-Path $PSScriptRoot '..' 'QuotaManager.Core.ps1')), [ref]$coreTokens, [ref]$coreErrors)
Assert-Equal 'core parse error count' @($coreErrors).Count 0

$guiText = [System.IO.File]::ReadAllText((Resolve-Path $guiPath))
Assert-True 'gui exposes receive setting' $guiText.Contains('ProhibitSendReceiveGB')
Assert-True 'gui exposes send setting' $guiText.Contains('ProhibitSendGB')
Assert-True 'gui exposes warning setting' $guiText.Contains('IssueWarningGB')
Assert-True 'gui keeps exchange commands on the UI thread' $guiText.Contains('Commands now run on the')
Assert-True 'gui can list licenses' $guiText.Contains('Get-MgUserLicenseDetail')
Assert-True 'gui does not stop a sign-in timer' (-not $guiText.Contains('$timer.Stop()'))
Assert-True 'gui reads connection properties safely' $guiText.Contains('function Get-SafeText')

Write-Host ""
Write-Host "Passed: $($script:passed)"
Write-Host "Failed: $($script:failures.Count)"
if ($script:failures.Count -gt 0) {
    exit 1
}
exit 0

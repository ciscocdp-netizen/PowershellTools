#Requires -Version 5.1
<#
.SYNOPSIS
    Regression tests for Entra-DynamicGroupRuleEngine.ps1

.DESCRIPTION
    Run:
      pwsh -NoProfile -File ./Tests/Entra-DynamicGroupRuleEngine.Tests.ps1
      powershell.exe -NoProfile -File .\Tests\Entra-DynamicGroupRuleEngine.Tests.ps1
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path -Parent $here
. (Join-Path $repo 'Entra-DynamicGroupRuleBuilder.ps1') -SkipGui

$script:Passed = 0
$script:Failed = 0
$script:Failures = New-Object System.Collections.Generic.List[string]

function Should-Equal {
    param($Actual, $Expected, [string]$Name)
    $actualText = [string]$Actual
    $expectedText = [string]$Expected
    if ($actualText -ceq $expectedText) {
        $script:Passed++
        Write-Host "PASS  $Name"
    }
    else {
        $script:Failed++
        $msg = "FAIL  $Name`n      expected: $expectedText`n      actual:   $actualText"
        $script:Failures.Add($msg) | Out-Null
        Write-Host $msg
    }
}

function Should-BeTrue {
    param($Actual, [string]$Name)
    if ($Actual) {
        $script:Passed++
        Write-Host "PASS  $Name"
    }
    else {
        $script:Failed++
        $msg = "FAIL  $Name (expected true)"
        $script:Failures.Add($msg) | Out-Null
        Write-Host $msg
    }
}

function Should-BeFalse {
    param($Actual, [string]$Name)
    if (-not $Actual) {
        $script:Passed++
        Write-Host "PASS  $Name"
    }
    else {
        $script:Failed++
        $msg = "FAIL  $Name (expected false)"
        $script:Failures.Add($msg) | Out-Null
        Write-Host $msg
    }
}

function Should-Contain {
    param([string]$Actual, [string]$Needle, [string]$Name)
    if ($Actual -like "*$Needle*") {
        $script:Passed++
        Write-Host "PASS  $Name"
    }
    else {
        $script:Failed++
        $msg = "FAIL  $Name`n      missing: $Needle`n      in: $Actual"
        $script:Failures.Add($msg) | Out-Null
        Write-Host $msg
    }
}

Write-Host ''
Write-Host '=== Expression builder ==='

$eq = New-EntraDgmExpression -ObjectType user -Property department -Operator '-eq' -Value Sales
Should-BeTrue $eq.IsValid 'department -eq Sales is valid'
Should-Equal $eq.Rule '(user.department -eq "Sales")' 'strings are double-quoted'

$bool = New-EntraDgmExpression -ObjectType user -Property accountEnabled -Operator '-eq' -Value true
Should-Equal $bool.Rule '(user.accountEnabled -eq true)' 'booleans are unquoted'

$quotedBool = New-EntraDgmExpression -ObjectType user -Property accountEnabled -Operator '-eq' -Value '"true"'
Should-BeFalse $quotedBool.IsValid 'quoted boolean values are rejected'

$nullDept = New-EntraDgmExpression -ObjectType user -Property department -Operator '-eq null'
Should-Equal $nullDept.Rule '(user.department -eq null)' 'null is unquoted'

$idMap = New-EntraDgmExpression -ObjectType user -Property id -Operator '-eq' -Value 'aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb'
Should-Equal $idMap.Rule '(user.objectId -eq "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb")' 'Graph id maps to objectId'
Should-BeTrue ($idMap.Warnings.Count -gt 0) 'Graph name mapping emits a warning'

$mobile = New-EntraDgmExpression -ObjectType user -Property mobilePhone -Operator '-eq' -Value '+15551212'
Should-Equal $mobile.Rule '(user.mobile -eq "+15551212")' 'mobilePhone maps to mobile'

$office = New-EntraDgmExpression -ObjectType user -Property officeLocation -Operator '-eq' -Value 'Building 3'
Should-Equal $office.Rule '(user.physicalDeliveryOfficeName -eq "Building 3")' 'officeLocation maps to physicalDeliveryOfficeName'

$nick = New-EntraDgmExpression -ObjectType user -Property mailNickname -Operator '-endsWith' -Value '-vendor'
Should-Equal $nick.Rule '(user.mailNickName -endsWith "-vendor")' 'mailNickname maps to mailNickName'

$sync = New-EntraDgmExpression -ObjectType user -Property onPremisesSyncEnabled -Operator '-eq' -Value true
Should-Equal $sync.Rule '(user.dirSyncEnabled -eq true)' 'onPremisesSyncEnabled maps to dirSyncEnabled'

$bt = [char]0x60
$quoted = New-EntraDgmExpression -ObjectType user -Property department -Operator '-eq' -Value ('He said "Hi"')
Should-Equal $quoted.Rule ('(user.department -eq "He said ' + $bt + '"Hi' + $bt + '"")') 'embedded quotes use backticks, not backslashes'
Should-BeFalse ($quoted.Rule -like '*\"*') 'rule does not contain backslash-escaped quotes'

$inList = New-EntraDgmExpression -ObjectType user -Property department -Operator '-in' -Value 'Sales, Marketing, Finance'
Should-Equal $inList.Rule '(user.department -in ["Sales", "Marketing", "Finance"])' '-in uses a bracketed double-quoted list'

$notIn = New-EntraDgmExpression -ObjectType user -Property city -Operator '-notIn' -Value 'Lagos,Ibadan'
Should-Equal $notIn.Rule '(user.city -notIn ["Lagos", "Ibadan"])' '-notIn canonical casing'

$proxy = New-EntraDgmExpression -ObjectType user -Property proxyAddresses -Operator '-startsWith' -Value 'SMTP:'
Should-Equal $proxy.Rule '(user.proxyAddresses -any (_ -startsWith "SMTP:"))' 'proxyAddresses uses -any (_ )'

$other = New-EntraDgmExpression -ObjectType user -Property otherMails -Operator '-endsWith' -Value '@contoso.com' -CollectionMode all
Should-Equal $other.Rule '(user.otherMails -all (_ -endsWith "@contoso.com"))' 'otherMails supports -all'

$plans = New-EntraDgmExpression -ObjectType user -Property assignedPlans -Operator '-eq' -Value 'efb87545-963c-4e0d-99df-69c6916d9eb0' -CollectionField servicePlanId -RequireEnabled
Should-Equal $plans.Rule '(user.assignedPlans -any (assignedPlan.servicePlanId -eq "efb87545-963c-4e0d-99df-69c6916d9eb0" -and assignedPlan.capabilityStatus -eq "Enabled"))' 'assignedPlans requires nested assignedPlan fields'

$memberOf = New-EntraDgmExpression -ObjectType user -Property memberOf -Operator '-in' -Value 'aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb,bbbbbbbb-0000-1111-2222-aaaaaaaaaaaa'
Should-Equal $memberOf.Rule "(user.memberOf -any (group.objectId -in ['aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb', 'bbbbbbbb-0000-1111-2222-aaaaaaaaaaaa']))" 'memberOf uses single-quoted group IDs'

$ext = New-EntraDgmExpression -ObjectType user -Property extensionAttribute15 -Operator '-eq' -Value Marketing
Should-Equal $ext.Rule '(user.extensionAttribute15 -eq "Marketing")' 'extensionAttributeN uses the Entra rule name'

$custom = New-EntraDgmExpression -ObjectType user -Property 'extension_c272a57b722d4eb29bfe327874ae79cb_OfficeNumber' -Operator '-eq' -Value '123'
Should-Equal $custom.Rule '(user.extension_c272a57b722d4eb29bfe327874ae79cb_OfficeNumber -eq "123")' 'directory extensions keep the Graph extension_* name'

$hire = New-EntraDgmExpression -ObjectType user -Property employeeHireDate -Operator '-ge' -Value 'system.now -plus p1d'
Should-Equal $hire.Rule '(user.employeeHireDate -ge system.now -plus p1d)' 'employeeHireDate supports system.now -plus'

$hireIso = New-EntraDgmExpression -ObjectType user -Property employeeHireDate -Operator '-le' -Value '2020-06-10T18:13:20Z'
Should-Equal $hireIso.Rule '(user.employeeHireDate -le 2020-06-10T18:13:20Z)' 'employeeHireDate ISO timestamps are unquoted'

$notOp = New-EntraDgmExpression -ObjectType user -Property jobTitle -Operator '-startsWith' -Value SDE -Negate
Should-Equal $notOp.Rule '-not (user.jobTitle -startsWith "SDE")' 'Negate wraps the expression in -not'

$badProp = New-EntraDgmExpression -ObjectType user -Property employeeType -Operator '-eq' -Value Employee
Should-BeFalse $badProp.IsValid 'employeeType is not a supported rule property'

$dr = New-EntraDgmDirectReportsRule -ManagerObjectId 'aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb'
Should-Equal $dr.Rule 'Direct Reports for "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb"' 'Direct Reports uses the manager object ID'
$drBad = New-EntraDgmDirectReportsRule -ManagerObjectId 'Sales Manager'
Should-BeFalse $drBad.IsValid 'Direct Reports rejects display names'

Write-Host ''
Write-Host '=== Joining / precedence ==='

$c1 = New-EntraDgmExpression -ObjectType user -Property department -Operator '-eq' -Value Sales
$c2 = New-EntraDgmExpression -ObjectType user -Property country -Operator '-eq' -Value US
$c2 | Add-Member -NotePropertyName JoinOperator -NotePropertyValue '-and' -Force
$andJoin = Join-EntraDgmExpressions -Conditions @($c1, $c2)
Should-Equal $andJoin.Rule '(user.department -eq "Sales") -and (user.country -eq "US")' 'all-AND joins without extra grouping'

$c3 = New-EntraDgmExpression -ObjectType user -Property city -Operator '-eq' -Value Lagos
$c2.JoinOperator = '-or'
$c3 | Add-Member -NotePropertyName JoinOperator -NotePropertyValue '-and' -Force
$mixed = Join-EntraDgmExpressions -Conditions @($c1, $c2, $c3)
Should-Equal $mixed.Rule '(((user.department -eq "Sales") -or (user.country -eq "US")) -and (user.city -eq "Lagos"))' 'mixed AND/OR is parenthesized left-to-right'

$mixDirect = Join-EntraDgmExpressions -Conditions @(
    $dr,
    $c1
)
Should-BeFalse $mixDirect.IsValid 'Direct Reports cannot be combined with other expressions'

Write-Host ''
Write-Host '=== Syntax validator ==='

$ok = Test-EntraDgmRuleSyntax -Rule '(user.department -eq "Sales")'
Should-BeTrue $ok.IsValid 'valid simple rule'

$badId = Test-EntraDgmRuleSyntax -Rule '(user.id -eq "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb")'
Should-BeFalse $badId.IsValid 'user.id is rejected'
Should-Contain ($badId.Errors -join '; ') 'user.objectId' 'user.id error mentions objectId'

$identity = Test-EntraDgmRuleSyntax -Rule '(user.userPrincipalName -eq "user.identity@contoso.com")'
Should-BeTrue $identity.IsValid 'user.id is not a false positive inside user.identity@...'

$badMobile = Test-EntraDgmRuleSyntax -Rule '(user.mobilePhone -eq "1")'
Should-BeFalse $badMobile.IsValid 'user.mobilePhone is rejected'

$badBool = Test-EntraDgmRuleSyntax -Rule 'user.accountEnabled -eq "true"'
Should-BeFalse $badBool.IsValid 'quoted boolean is rejected'

$badNull = Test-EntraDgmRuleSyntax -Rule 'user.department -eq $null'
Should-BeFalse $badNull.IsValid '$null is rejected'

$badSlash = Test-EntraDgmRuleSyntax -Rule '(user.department -eq "He said \"Hi\"")'
Should-BeFalse $badSlash.IsValid 'backslash-escaped quotes are rejected'

$badColl = Test-EntraDgmRuleSyntax -Rule 'user.proxyAddresses -eq "SMTP:a@b.com"'
Should-BeFalse $badColl.IsValid 'proxyAddresses without -any is rejected'

$badIn = Test-EntraDgmRuleSyntax -Rule 'user.department -in "Sales"'
Should-BeFalse $badIn.IsValid '-in without brackets is rejected'

$goodIn = Test-EntraDgmRuleSyntax -Rule 'user.department -in ["Sales", "Marketing"]'
Should-BeTrue $goodIn.IsValid '-in with brackets is accepted'

$mixUd = Test-EntraDgmRuleSyntax -Rule '(user.department -eq "Sales") -and (device.displayName -eq "PC")'
Should-BeFalse $mixUd.IsValid 'user+device mix is rejected'

$unbalanced = Test-EntraDgmRuleSyntax -Rule '(user.department -eq "Sales"'
Should-BeFalse $unbalanced.IsValid 'unbalanced parentheses are rejected'

$empty = Test-EntraDgmRuleSyntax -Rule ''
Should-BeFalse $empty.IsValid 'empty rule is invalid'

$long = 'user.department -eq "' + ('A' * 3100) + '"'
$tooLong = Test-EntraDgmRuleSyntax -Rule $long
Should-BeFalse $tooLong.IsValid 'rules over 3072 characters are rejected'

Write-Host ''
Write-Host '=== Local evaluation / Graph flattening ==='

$user = [pscustomobject]@{
    id                         = '11111111-1111-1111-1111-111111111111'
    displayName                = 'Alex Sales'
    department                 = 'Sales'
    accountEnabled             = $true
    mailNickname               = 'alex'
    mobilePhone                = '+1555'
    officeLocation             = 'HQ'
    onPremisesSyncEnabled      = $false
    proxyAddresses             = @('SMTP:alex@contoso.com', 'smtp:alex@fabrikam.com')
    assignedPlans              = @(
        [pscustomobject]@{ service = 'exchange'; servicePlanId = 'efb87545-963c-4e0d-99df-69c6916d9eb0'; capabilityStatus = 'Enabled' }
    )
    onPremisesExtensionAttributes = [pscustomobject]@{
        extensionAttribute1 = 'MKT'
        extensionAttribute15 = 'Marketing'
    }
    manager = [pscustomobject]@{
        id          = 'aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb'
        displayName = 'Manager Person'
    }
}

$rows = ConvertFrom-EntraDgmGraphObject -GraphObject $user -ObjectType user
$deptRow = @($rows | Where-Object Name -eq 'department')[0]
Should-Equal $deptRow.Value 'Sales' 'department value is flattened'
$mobileRow = @($rows | Where-Object Name -eq 'mobile')[0]
Should-Equal $mobileRow.RawValue '+1555' 'mobilePhone is exposed as mobile'
$extRow = @($rows | Where-Object Name -eq 'extensionAttribute15')[0]
Should-Equal $extRow.Value 'Marketing' 'extensionAttribute15 is lifted out of onPremisesExtensionAttributes'
$mgr = @($rows | Where-Object Name -eq 'managerObjectId')[0]
Should-Equal $mgr.RawValue 'aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb' 'manager object ID is available for Direct Reports'
$objId = @($rows | Where-Object Name -eq 'objectId')[0]
Should-Equal $objId.RawValue '11111111-1111-1111-1111-111111111111' 'Graph id is exposed as objectId'

$condDept = New-EntraDgmExpression -ObjectType user -Property department -Operator '-eq' -Value Sales
$evalPass = Test-EntraDgmConditionLocally -Condition $condDept -AttributeRows $rows
Should-BeTrue $evalPass.Passed 'local eval matches department Sales'

$condMkt = New-EntraDgmExpression -ObjectType user -Property department -Operator '-eq' -Value Marketing
$evalFail = Test-EntraDgmConditionLocally -Condition $condMkt -AttributeRows $rows
Should-BeFalse $evalFail.Passed 'local eval rejects department Marketing'

$condProxy = New-EntraDgmExpression -ObjectType user -Property proxyAddresses -Operator '-startsWith' -Value 'SMTP:alex@'
$evalProxy = Test-EntraDgmConditionLocally -Condition $condProxy -AttributeRows $rows
Should-BeTrue $evalProxy.Passed 'local eval understands proxyAddresses -any'

$condPlan = New-EntraDgmExpression -ObjectType user -Property assignedPlans -Operator '-eq' -Value 'efb87545-963c-4e0d-99df-69c6916d9eb0' -CollectionField servicePlanId -RequireEnabled
$evalPlan = Test-EntraDgmConditionLocally -Condition $condPlan -AttributeRows $rows
Should-BeTrue $evalPlan.Passed 'local eval understands assignedPlans + Enabled'

$condBool = New-EntraDgmExpression -ObjectType user -Property accountEnabled -Operator '-eq' -Value true
$evalBool = Test-EntraDgmConditionLocally -Condition $condBool -AttributeRows $rows
Should-BeTrue $evalBool.Passed 'local eval understands unquoted booleans'

$cOr = New-EntraDgmExpression -ObjectType user -Property department -Operator '-eq' -Value Marketing
$cOr | Add-Member -NotePropertyName JoinOperator -NotePropertyValue '-or' -Force
$ruleEval = Test-EntraDgmRuleLocally -Conditions @($condDept, $cOr) -AttributeRows $rows
Should-BeTrue $ruleEval.Matched 'OR of matching + non-matching still matches'

Write-Host ''
Write-Host '=== Catalog ==='
$catalog = @(Get-EntraDgmPropertyCatalog)
$userProps = @($catalog | Where-Object ObjectType -eq 'user')
Should-BeTrue ($userProps.Count -ge 40) 'user catalog includes core + extensionAttribute1-15'
$deviceProps = @($catalog | Where-Object ObjectType -eq 'device')
Should-BeTrue ($deviceProps.Count -ge 20) 'device catalog is populated'
$select = Get-EntraDgmGraphSelectProperties -ObjectType user
Should-BeTrue ($select -contains 'onPremisesExtensionAttributes') 'Graph $select includes onPremisesExtensionAttributes'
Should-BeTrue ($select -contains 'id') 'Graph $select includes id'
Should-BeFalse ($select -contains 'memberOf') 'navigation properties are not $select-ed'

Write-Host ''
Write-Host '=== Graph response unwrap ==='
$userHash = [hashtable]@{
    displayName        = 'Blake, Anthony'
    userPrincipalName  = 'ablake4@owens-minor.com'
    id                 = '11111111-1111-1111-1111-111111111111'
    department         = 'Sales'
}
$unwrapped = Resolve-EntraDgmGraphEntity -Result $userHash -ObjectType user
Should-Equal $unwrapped.displayName 'Blake, Anthony' 'hashtable user is not mistaken for an OData page'
$page = [pscustomobject]@{
    value = @(
        [pscustomobject]@{ displayName = 'Device One'; id = 'dddddddd-dddd-dddd-dddd-dddddddddddd' }
    )
}
$fromPage = Resolve-EntraDgmGraphEntity -Result $page -ObjectType device
Should-Equal $fromPage.displayName 'Device One' 'OData value pages unwrap the first entity'

Write-Host ''
Write-Host ("Results: {0} passed, {1} failed" -f $script:Passed, $script:Failed)
if ($script:Failed -gt 0) {
    Write-Host ''
    Write-Host 'Failed assertions:'
    foreach ($f in $script:Failures) { Write-Host $f }
    exit 1
}
exit 0

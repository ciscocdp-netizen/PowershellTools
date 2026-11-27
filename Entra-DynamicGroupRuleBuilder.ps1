#Requires -Version 5.1
<#
.SYNOPSIS
    Entra ID Dynamic Group Rule Builder - GUI Edition (PowerShell 5.1)

.DESCRIPTION
    Windows Forms GUI that builds valid Entra ID dynamic membership rules:
      - Connects to Microsoft Graph and loads a user or device
      - Shows only properties that Entra ID actually accepts (Graph names are mapped)
      - Emits correct quoting, booleans, null checks, -in lists, and -any/-all collections
      - Validates syntax (3072-character limit, mixed AND/OR parentheses, invalid properties)
      - Tests a user against the rule locally and via Graph evaluateDynamicMembership

    Common syntax bugs this edition prevents:
      - Graph names in rules (user.id, user.mobilePhone, user.officeLocation, user.mailNickname)
      - Quoted booleans (user.accountEnabled -eq "true")
      - Backslash-escaped quotes (\" instead of `")
      - $null instead of null
      - Collection properties without -any/_
      - -in lists without brackets
      - Manager display name used as a rule property
      - Mixed -and/-or without parentheses (Entra gives -and higher precedence)

.PARAMETER SkipGui
    Load functions only; do not show the Windows Forms UI. Used by tests.

.PREREQS
    Microsoft Graph PowerShell SDK (Authentication module is enough for REST calls):
      Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

.NOTES
    Compatible with PowerShell 5.1
    Requires .NET Framework / Windows for the GUI
    Rule engine: Entra-DynamicGroupRuleEngine.ps1
#>

[CmdletBinding()]
param(
    [switch]$SkipGui
)

$enginePath = Join-Path $PSScriptRoot 'Entra-DynamicGroupRuleEngine.ps1'
if (-not (Test-Path -LiteralPath $enginePath)) {
    throw "Required file not found: $enginePath"
}
. $enginePath

if ($SkipGui) {
    return
}

function Start-EntraDgmStaRelaunch {
    $state = [System.Threading.Thread]::CurrentThread.GetApartmentState()
    if ($state -eq 'STA') { return $false }

    $hostFile = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $hostFile)) {
        $hostFile = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
    }
    if (-not $hostFile) {
        throw 'Windows Forms requires a STA PowerShell host. Rerun as: powershell.exe -STA -File .\Entra-DynamicGroupRuleBuilder.ps1'
    }

    $argList = @(
        '-NoProfile'
        '-STA'
        '-ExecutionPolicy', 'Bypass'
        '-File', $PSCommandPath
    )
    Start-Process -FilePath $hostFile -ArgumentList $argList | Out-Null
    return $true
}

if (Start-EntraDgmStaRelaunch) {
    return
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ===============================
# Script state
# ===============================
$script:GraphBaseUri     = 'https://graph.microsoft.com/v1.0'
$script:GraphBetaUri     = 'https://graph.microsoft.com/beta'
$script:IsConnected      = $false
$script:ObjectType       = 'user'
$script:AttributeRows    = @()
$script:Conditions       = New-Object System.Collections.ArrayList
$script:CustomExtensions = New-Object System.Collections.Generic.List[string]
$script:CurrentObject    = $null
$script:CurrentDisplay   = ''

$script:UiBlue   = [System.Drawing.Color]::FromArgb(0, 120, 212)
$script:UiGreen  = [System.Drawing.Color]::FromArgb(16, 124, 16)
$script:UiMuted  = [System.Drawing.Color]::FromArgb(96, 96, 96)
$script:UiWarn   = [System.Drawing.Color]::FromArgb(180, 80, 0)
$script:UiError  = [System.Drawing.Color]::FromArgb(180, 32, 32)

function Show-EntraDgmMessage {
    param(
        [string]$Text,
        [string]$Title = 'Entra ID Rule Builder',
        [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Information
    )
    [void][System.Windows.Forms.MessageBox]::Show(
        $Text,
        $Title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        $Icon
    )
}

function Set-EntraDgmStatus {
    param(
        [string]$Text,
        [System.Drawing.Color]$Color
    )
    $statusLabel.Text = $Text
    $statusLabel.ForeColor = $Color
    $form.Refresh()
}

function Test-EntraDgmGraphModule {
    $module = Get-Module Microsoft.Graph.Authentication -ListAvailable | Select-Object -First 1
    if (-not $module) {
        throw "Microsoft.Graph.Authentication is not installed.`r`n`r`nInstall-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null
}

function Invoke-EntraDgmGraph {
    param(
        [ValidateSet('GET', 'POST')]
        [string]$Method = 'GET',
        [Parameter(Mandatory)]
        [string]$Uri,
        $Body
    )

    $params = @{
        Method     = $Method
        Uri        = $Uri
        OutputType = 'PSObject'
        ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $params['Body'] = $Body
    }
    Invoke-MgGraphRequest @params
}

function Get-EntraDgmConnectParameters {
    $scopes = @('User.Read.All', 'Directory.Read.All', 'Device.Read.All')
    $params = @{
        Scopes      = $scopes
        ErrorAction = 'Stop'
    }
    $cmd = Get-Command Connect-MgGraph -ErrorAction Stop
    if ($cmd.Parameters.ContainsKey('NoWelcome')) {
        $params['NoWelcome'] = $true
    }
    return $params
}

function Connect-EntraDgmGraph {
    try {
        Test-EntraDgmGraphModule
        Set-EntraDgmStatus -Text 'Connecting to Microsoft Graph...' -Color ([System.Drawing.Color]::Orange)

        $existing = $null
        try { $existing = Get-MgContext } catch { $existing = $null }

        if (-not $existing -or -not $existing.Account) {
            $connectParams = Get-EntraDgmConnectParameters
            Connect-MgGraph @connectParams | Out-Null
            $existing = Get-MgContext
        }

        if ($existing -and $existing.Account) {
            $script:IsConnected = $true
            $btnConnect.Enabled = $false
            $btnDisconnect.Enabled = $true
            $btnLoadObject.Enabled = $true
            $txtObjectId.Enabled = $true
            $btnLoadExtensions.Enabled = $true
            $txtAppId.Enabled = $true
            $btnTestGraph.Enabled = $true
            Set-EntraDgmStatus -Text "Connected as $($existing.Account) | Tenant $($existing.TenantId)" -Color $script:UiGreen
            Show-EntraDgmMessage -Text "Connected to Microsoft Graph as $($existing.Account)." -Title 'Connected'
        }
        else {
            throw 'No Graph account was returned. Sign-in may have been cancelled.'
        }
    }
    catch {
        $script:IsConnected = $false
        Set-EntraDgmStatus -Text 'Not connected' -Color $script:UiError
        Show-EntraDgmMessage -Text "Failed to connect: $($_.Exception.Message)" -Title 'Connection Error' -Icon Error
    }
}

function Disconnect-EntraDgmGraph {
    try {
        if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
    catch { }

    $script:IsConnected = $false
    $btnConnect.Enabled = $true
    $btnDisconnect.Enabled = $false
    $btnLoadObject.Enabled = $false
    $txtObjectId.Enabled = $false
    $btnLoadExtensions.Enabled = $false
    $txtAppId.Enabled = $false
    $btnTestGraph.Enabled = $false
    Set-EntraDgmStatus -Text 'Not connected' -Color $script:UiError
}

function Get-EntraDgmDirectoryExtensions {
    param([string]$AppId)

    $names = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($AppId)) {
        $filter = [uri]::EscapeDataString("appId eq '$($AppId.Trim())'")
        $uri = "$($script:GraphBaseUri)/applications?`$filter=$filter&`$select=id,appId,displayName,extensionProperties"
        $page = Invoke-EntraDgmGraph -Uri $uri
        foreach ($app in @($page.value)) {
            foreach ($ext in @($app.extensionProperties)) {
                if ($ext.name) { $names.Add([string]$ext.name) | Out-Null }
            }
        }
        return @($names)
    }

    $uri = "$($script:GraphBaseUri)/applications?`$select=id,appId,displayName,extensionProperties&`$top=100"
    $guard = 0
    while ($uri -and $guard -lt 10) {
        $guard++
        $page = Invoke-EntraDgmGraph -Uri $uri
        foreach ($app in @($page.value)) {
            foreach ($ext in @($app.extensionProperties)) {
                $extName = [string]$ext.name
                if (Test-EntraDgmCustomExtensionName -Name $extName) {
                    $names.Add($extName) | Out-Null
                }
            }
        }
        $uri = $page.'@odata.nextLink'
    }
    return @($names | Select-Object -Unique)
}

function Get-EntraDgmObjectUri {
    param(
        [string]$Identifier,
        [string]$ObjectType,
        [string[]]$ExtraSelect
    )

    $select = Get-EntraDgmGraphSelectProperties -ObjectType $ObjectType -Extra $ExtraSelect
    $selectQuery = [uri]::EscapeDataString(($select -join ','))
    $idEsc = [uri]::EscapeDataString($Identifier.Trim())

    if ($ObjectType -eq 'device') {
        if ($Identifier -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            return "$($script:GraphBetaUri)/devices/$idEsc`?`$select=$selectQuery"
        }
        $filter = [uri]::EscapeDataString("displayName eq '$($Identifier.Trim().Replace("'","''"))'")
        return "$($script:GraphBetaUri)/devices?`$filter=$filter&`$select=$selectQuery"
    }

    $expand = [uri]::EscapeDataString('manager($select=id,displayName,userPrincipalName)')
    return "$($script:GraphBetaUri)/users/$idEsc`?`$select=$selectQuery&`$expand=$expand"
}

function Update-EntraDgmAttributeList {
    $lstAttributes.BeginUpdate()
    try {
        $lstAttributes.Items.Clear()
        $filter = ''
        if ($txtAttributeFilter) { $filter = $txtAttributeFilter.Text }
        $supportedOnly = $true
        if ($chkSupportedOnly) { $supportedOnly = $chkSupportedOnly.Checked }

        foreach ($row in @($script:AttributeRows)) {
            if ($supportedOnly -and -not $row.Supported -and $row.Name -ne 'managerObjectId') { continue }
            if (-not [string]::IsNullOrWhiteSpace($filter)) {
                $blob = "$($row.Name) $($row.GraphName) $($row.Value) $($row.Type)"
                if ($blob -notlike "*$filter*") { continue }
            }

            $item = New-Object System.Windows.Forms.ListViewItem($row.Name)
            [void]$item.SubItems.Add($row.Type)
            [void]$item.SubItems.Add([string]$row.Value)
            $item.Tag = $row
            $item.ToolTipText = $(if ($row.Notes) { $row.Notes } else { "Graph: $($row.GraphPath)" })

            if (-not $row.Supported) {
                $item.ForeColor = $script:UiMuted
            }
            elseif ($row.Name -match '^extensionAttribute\d+$' -or $row.Name -match '^extension_') {
                $item.ForeColor = [System.Drawing.Color]::DarkBlue
                $item.Font = New-Object System.Drawing.Font($lstAttributes.Font, [System.Drawing.FontStyle]::Bold)
            }
            $lstAttributes.Items.Add($item) | Out-Null
        }
    }
    finally {
        $lstAttributes.EndUpdate()
    }
}

function Import-EntraDgmGraphObject {
    param([string]$Identifier)

    if (-not $script:IsConnected) {
        Show-EntraDgmMessage -Text 'Connect to Microsoft Graph first.' -Title 'Not Connected' -Icon Warning
        return
    }
    if ([string]::IsNullOrWhiteSpace($Identifier)) {
        Show-EntraDgmMessage -Text 'Enter a user UPN/object ID or a device display name/object ID.' -Title 'Missing identifier' -Icon Warning
        return
    }

    try {
        Set-EntraDgmStatus -Text "Loading $($script:ObjectType): $Identifier..." -Color ([System.Drawing.Color]::Orange)
        $uri = Get-EntraDgmObjectUri -Identifier $Identifier -ObjectType $script:ObjectType -ExtraSelect @($script:CustomExtensions)
        $result = Invoke-EntraDgmGraph -Uri $uri

        $obj = $result
        if ($result.PSObject.Properties['value']) {
            $values = @($result.value)
            if ($values.Count -eq 0) { throw "No $($script:ObjectType) matched '$Identifier'." }
            $obj = $values[0]
        }

        $script:CurrentObject = $obj
        $script:AttributeRows = @(ConvertFrom-EntraDgmGraphObject -GraphObject $obj -ObjectType $script:ObjectType -ExtraExtensionNames @($script:CustomExtensions))
        Update-EntraDgmAttributeList

        $display = Get-EntraDgmObjectProperty -Object $obj -Name 'displayName'
        $upn = Get-EntraDgmObjectProperty -Object $obj -Name 'userPrincipalName'
        $id = Get-EntraDgmObjectProperty -Object $obj -Name 'id'
        if ($upn) {
            $script:CurrentDisplay = "$display ($upn)"
        }
        else {
            $script:CurrentDisplay = "$display ($id)"
        }
        $lblObjectInfo.Text = "Loaded: $($script:CurrentDisplay)"
        $lblObjectInfo.ForeColor = $script:UiGreen

        $supported = @($script:AttributeRows | Where-Object { $_.Supported }).Count
        $custom = @($script:AttributeRows | Where-Object { $_.Name -match '^extension_' -or $_.Name -match '^extensionAttribute\d+$' }).Count
        Set-EntraDgmStatus -Text "Loaded $supported supported properties ($custom extension) for $($script:CurrentDisplay)" -Color $script:UiGreen

        $lstAttributes.Enabled = $true
        if ([string]::IsNullOrWhiteSpace($txtTestId.Text)) {
            if ($upn) { $txtTestId.Text = $upn } else { $txtTestId.Text = $id }
        }
    }
    catch {
        $lblObjectInfo.Text = 'No object loaded'
        $lblObjectInfo.ForeColor = $script:UiMuted
        Set-EntraDgmStatus -Text "Failed to load $($script:ObjectType)" -Color $script:UiError
        Show-EntraDgmMessage -Text "Failed to load $($script:ObjectType): $($_.Exception.Message)" -Title 'Load Error' -Icon Error
    }
}

function Import-EntraDgmCustomExtensions {
    if (-not $script:IsConnected) {
        Show-EntraDgmMessage -Text 'Connect to Microsoft Graph first.' -Title 'Not Connected' -Icon Warning
        return
    }

    try {
        Set-EntraDgmStatus -Text 'Discovering directory extension properties...' -Color ([System.Drawing.Color]::Orange)
        $found = @(Get-EntraDgmDirectoryExtensions -AppId $txtAppId.Text)
        $script:CustomExtensions.Clear()
        foreach ($name in $found) { $script:CustomExtensions.Add($name) | Out-Null }
        Set-EntraDgmStatus -Text "Found $($found.Count) directory extension properties." -Color $script:UiGreen
        if ($found.Count -eq 0) {
            Show-EntraDgmMessage -Text "No directory extensions were returned.`r`nIf they live on a specific app, paste that application's App ID and try again.`r`nApplication.Read.All may be required for a full scan." -Title 'No extensions' -Icon Warning
        }
        else {
            Show-EntraDgmMessage -Text "Loaded $($found.Count) extension properties. Reload the user/device to see their values." -Title 'Extensions'
            if ($script:CurrentObject) {
                Import-EntraDgmGraphObject -Identifier $txtObjectId.Text
            }
        }
    }
    catch {
        Show-EntraDgmMessage -Text "Could not list extension properties: $($_.Exception.Message)`r`nPaste the extension app ID, or add Application.Read.All and reconnect." -Title 'Extensions' -Icon Error
    }
}

function Get-EntraDgmSelectedAttribute {
    if ($lstAttributes.SelectedItems.Count -eq 0) { return $null }
    return $lstAttributes.SelectedItems[0].Tag
}

function Reset-EntraDgmOperatorList {
    param($Attribute)

    $cmbOperator.Items.Clear()
    if (-not $Attribute -or -not $Attribute.Supported) {
        $cmbOperator.Enabled = $false
        $cmbCollectionMode.Enabled = $false
        $cmbCollectionField.Enabled = $false
        $txtValue.Enabled = $false
        $cmbBoolean.Enabled = $false
        $btnAddCondition.Enabled = $false
        return
    }

    $meta = $null
    $resolved = Resolve-EntraDgmProperty -Name $Attribute.Name -ObjectType $script:ObjectType
    if ($resolved.Found) { $meta = $resolved.Property }

    $ops = @('-eq', '-ne')
    if ($meta) { $ops = @(Get-EntraDgmAllowedOperators -Property $meta) }
    $cmbOperator.Items.AddRange($ops)
    if ($meta -and $meta.SupportsNull) {
        [void]$cmbOperator.Items.Add('-eq null')
        [void]$cmbOperator.Items.Add('-ne null')
    }
    $cmbOperator.Enabled = $true
    $cmbOperator.SelectedIndex = 0
    $btnAddCondition.Enabled = $true

    $isCollection = $Attribute.Type -in @('StringCollection', 'ObjectCollection')
    $cmbCollectionMode.Enabled = $isCollection
    if ($isCollection) { $cmbCollectionMode.SelectedIndex = 0 }

    $cmbCollectionField.Items.Clear()
    if ($Attribute.Type -eq 'ObjectCollection') {
        $cmbCollectionField.Items.AddRange(@('servicePlanId', 'service', 'capabilityStatus'))
        $cmbCollectionField.SelectedIndex = 0
        $cmbCollectionField.Enabled = $true
        $chkRequireEnabled.Enabled = $true
        $chkRequireEnabled.Checked = $true
    }
    else {
        $cmbCollectionField.Enabled = $false
        $chkRequireEnabled.Enabled = $false
        $chkRequireEnabled.Checked = $false
    }

    Update-EntraDgmValueInput
}

function Update-EntraDgmValueInput {
    $op = [string]$cmbOperator.SelectedItem
    $attr = Get-EntraDgmSelectedAttribute
    $isNullOp = $op -match 'null'
    $isBool = $attr -and $attr.Type -eq 'Boolean' -and -not $isNullOp

    $cmbBoolean.Visible = $isBool
    $cmbBoolean.Enabled = $isBool
    $txtValue.Visible = -not $isBool
    $txtValue.Enabled = (-not $isNullOp -and -not $isBool)

    if ($isNullOp) {
        $txtValue.Text = ''
        return
    }

    if ($isBool) {
        $cmbBoolean.SelectedItem = $(if ([string]$attr.Value -eq 'false') { 'false' } else { 'true' })
        return
    }

    if ($attr -and $attr.Value -ne '<null>' -and $attr.Value -ne '<complex object>' -and $attr.Type -notin @('StringCollection', 'ObjectCollection', 'MemberOf')) {
        $txtValue.Text = [string]$attr.RawValue
        if ([string]::IsNullOrWhiteSpace($txtValue.Text) -and $attr.Value -ne '<null>') {
            $txtValue.Text = [string]$attr.Value
        }
    }
}

function Refresh-EntraDgmConditionList {
    $lstConditions.BeginUpdate()
    try {
        $lstConditions.Items.Clear()
        for ($i = 0; $i -lt $script:Conditions.Count; $i++) {
            $c = $script:Conditions[$i]
            $item = New-Object System.Windows.Forms.ListViewItem($c.Property)
            [void]$item.SubItems.Add($(if ($c.NullValue) { "$($c.Operator) null" } else { [string]$c.Operator }))
            [void]$item.SubItems.Add($(if ($c.NullValue) { '' } else { [string]$c.Value }))
            if ($i -eq 0) {
                [void]$item.SubItems.Add('(first)')
            }
            else {
                [void]$item.SubItems.Add([string]$c.JoinOperator)
            }
            $item.Tag = $c
            $lstConditions.Items.Add($item) | Out-Null
        }
    }
    finally {
        $lstConditions.EndUpdate()
    }
    Update-EntraDgmRulePreview
}

function Update-EntraDgmRulePreview {
    if ($script:Conditions.Count -eq 0) {
        $txtRulePreview.Text = 'No conditions added yet'
        $lblCharCount.Text = '0 / 3072'
        $lblCharCount.ForeColor = $script:UiMuted
        $txtValidation.Text = 'Add a condition or apply a template to build a rule.'
        $txtValidation.ForeColor = $script:UiMuted
        $btnCopyRule.Enabled = $false
        $btnClearConditions.Enabled = $false
        return
    }

    $joined = Join-EntraDgmExpressions -Conditions @($script:Conditions)
    if (-not $joined.IsValid) {
        $txtRulePreview.Text = [string]$joined.Rule
        $txtValidation.Text = ($joined.Errors -join ' ')
        $txtValidation.ForeColor = $script:UiError
        $btnCopyRule.Enabled = -not [string]::IsNullOrWhiteSpace($joined.Rule)
        $btnClearConditions.Enabled = $true
        return
    }

    $txtRulePreview.Text = $joined.Rule
    $btnCopyRule.Enabled = $true
    $btnClearConditions.Enabled = $true
    Update-EntraDgmValidationUi -Rule $joined.Rule
}

function Update-EntraDgmValidationUi {
    param([string]$Rule)

    $result = Test-EntraDgmRuleSyntax -Rule $Rule
    $lblCharCount.Text = "$($result.Length) / 3072"
    if ($result.Length -gt 3072) {
        $lblCharCount.ForeColor = $script:UiError
    }
    elseif ($result.Length -gt 2800) {
        $lblCharCount.ForeColor = $script:UiWarn
    }
    else {
        $lblCharCount.ForeColor = $script:UiGreen
    }

    $lines = New-Object System.Collections.Generic.List[string]
    if ($result.IsValid) {
        $lines.Add('Syntax looks valid for Entra ID dynamic membership rules.') | Out-Null
    }
    foreach ($err in @($result.Errors)) { $lines.Add("ERROR: $err") | Out-Null }
    foreach ($warn in @($result.Warnings)) { $lines.Add("WARNING: $warn") | Out-Null }
    $txtValidation.Text = ($lines -join [Environment]::NewLine)
    $txtValidation.ForeColor = $(if ($result.IsValid) { $(if ($result.Warnings.Count) { $script:UiWarn } else { $script:UiGreen }) } else { $script:UiError })
}

function Add-EntraDgmConditionFromUi {
    $attr = Get-EntraDgmSelectedAttribute
    if (-not $attr) {
        Show-EntraDgmMessage -Text 'Select a supported attribute first.' -Title 'No attribute selected' -Icon Warning
        return
    }
    if (-not $attr.Supported) {
        Show-EntraDgmMessage -Text "$($attr.Name) cannot be used in a membership rule.`r`n$($attr.Notes)" -Title 'Unsupported property' -Icon Warning
        return
    }

    $op = [string]$cmbOperator.SelectedItem
    if ([string]::IsNullOrWhiteSpace($op)) {
        Show-EntraDgmMessage -Text 'Choose an operator.' -Title 'Missing operator' -Icon Warning
        return
    }

    $nullValue = $op -match 'null$'
    $value = $txtValue.Text
    if ($attr.Type -eq 'Boolean' -and -not $nullValue) {
        $value = [string]$cmbBoolean.SelectedItem
    }

    $exprParams = @{
        ObjectType      = $script:ObjectType
        Property        = $attr.Name
        Operator        = $op
        Value           = $value
        CollectionMode  = $(if ($cmbCollectionMode.Enabled) { [string]$cmbCollectionMode.SelectedItem } else { '' })
        CollectionField = $(if ($cmbCollectionField.Enabled) { [string]$cmbCollectionField.SelectedItem } else { '' })
        Negate          = $chkNegate.Checked
        RequireEnabled  = $chkRequireEnabled.Checked
    }
    if ($nullValue) { $exprParams['NullValue'] = $true }

    $expr = New-EntraDgmExpression @exprParams
    if (-not $expr.IsValid) {
        Show-EntraDgmMessage -Text ($expr.Errors -join [Environment]::NewLine) -Title 'Invalid condition' -Icon Error
        return
    }

    $joinOp = if ($rdoAnd.Checked) { '-and' } else { '-or' }
    $condition = [pscustomobject]@{
        Rule            = $expr.Rule
        Property        = $expr.Property
        GraphName       = $expr.GraphName
        GraphPath       = $expr.GraphPath
        Operator        = $expr.Operator
        Value           = $expr.Value
        Type            = $expr.Type
        ObjectType      = $expr.ObjectType
        CollectionMode  = $expr.CollectionMode
        CollectionField = $expr.CollectionField
        NullValue       = $expr.NullValue
        Negate          = $expr.Negate
        RequireEnabled  = $expr.RequireEnabled
        JoinOperator    = $joinOp
        Warnings        = $expr.Warnings
    }
    [void]$script:Conditions.Add($condition)
    Refresh-EntraDgmConditionList

    if ($expr.Warnings.Count) {
        $txtValidation.Text = ((@($expr.Warnings | ForEach-Object { "WARNING: $_" }) + $txtValidation.Text) -join [Environment]::NewLine)
        $txtValidation.ForeColor = $script:UiWarn
    }
}

function Add-EntraDgmDirectReportsCondition {
    $managerId = $txtValue.Text
    $attr = Get-EntraDgmSelectedAttribute
    if ($attr -and $attr.Name -eq 'managerObjectId' -and $attr.RawValue) {
        $managerId = [string]$attr.RawValue
    }
    if ([string]::IsNullOrWhiteSpace($managerId) -and $txtObjectId.Text -match '^[0-9a-fA-F-]{36}$') {
        $managerId = $txtObjectId.Text.Trim()
    }

    $expr = New-EntraDgmDirectReportsRule -ManagerObjectId $managerId
    if (-not $expr.IsValid) {
        Show-EntraDgmMessage -Text ($expr.Errors -join [Environment]::NewLine) -Title 'Direct Reports' -Icon Error
        return
    }
    if ($script:Conditions.Count -gt 0) {
        Show-EntraDgmMessage -Text 'Direct Reports cannot be combined with other expressions. Clear the current conditions first, or replace them.' -Title 'Direct Reports' -Icon Warning
        return
    }

    [void]$script:Conditions.Add([pscustomobject]@{
        Rule         = $expr.Rule
        Property     = 'DirectReports'
        Operator     = 'DirectReports'
        Value        = $expr.Value
        Type         = 'DirectReports'
        ObjectType   = 'user'
        JoinOperator = '-and'
        NullValue    = $false
        Negate       = $false
        Warnings     = $expr.Warnings
    })
    Refresh-EntraDgmConditionList
}

function Remove-EntraDgmSelectedCondition {
    if ($lstConditions.SelectedIndices.Count -eq 0) { return }
    $index = $lstConditions.SelectedIndices[0]
    $script:Conditions.RemoveAt($index)
    Refresh-EntraDgmConditionList
}

function Move-EntraDgmSelectedCondition {
    param([int]$Delta)

    if ($lstConditions.SelectedIndices.Count -eq 0) { return }
    $index = $lstConditions.SelectedIndices[0]
    $target = $index + $Delta
    if ($target -lt 0 -or $target -ge $script:Conditions.Count) { return }
    $item = $script:Conditions[$index]
    $script:Conditions.RemoveAt($index)
    $script:Conditions.Insert($target, $item)
    Refresh-EntraDgmConditionList
    $lstConditions.Items[$target].Selected = $true
}

function Clear-EntraDgmConditions {
    $script:Conditions.Clear()
    Refresh-EntraDgmConditionList
    $txtTestResult.Text = 'Add conditions, then test a user or device against the rule.'
    $lblTestStatus.Text = 'Not tested'
    $lblTestStatus.ForeColor = $script:UiMuted
}

function Copy-EntraDgmRule {
    $rule = $txtRulePreview.Text
    if ([string]::IsNullOrWhiteSpace($rule) -or $rule -eq 'No conditions added yet') {
        Show-EntraDgmMessage -Text 'No rule to copy.' -Title 'Empty rule' -Icon Warning
        return
    }
    [System.Windows.Forms.Clipboard]::SetText($rule)
    Show-EntraDgmMessage -Text 'Rule copied to the clipboard.' -Title 'Copied'
}

function Apply-EntraDgmTemplate {
    $name = [string]$cmbTemplate.SelectedItem
    if ([string]::IsNullOrWhiteSpace($name) -or $name -eq '(templates)') { return }
    $template = @(Get-EntraDgmCommonTemplates | Where-Object { $_.Name -eq $name } | Select-Object -First 1)
    if (-not $template) { return }

    if ($template.ObjectType -ne $script:ObjectType) {
        if ($template.ObjectType -eq 'device') { $rdoDevice.Checked = $true } else { $rdoUser.Checked = $true }
    }

    $script:Conditions.Clear()
    [void]$script:Conditions.Add([pscustomobject]@{
        Rule         = $template.Rule
        Property     = 'Template'
        Operator     = 'template'
        Value        = $template.Name
        Type         = 'Template'
        ObjectType   = $template.ObjectType
        JoinOperator = '-and'
        NullValue    = $false
        Negate       = $false
        Warnings     = @($template.Notes)
    })
    Refresh-EntraDgmConditionList
}

function Resolve-EntraDgmTestMemberId {
    param([string]$Identifier, [string]$ObjectType)

    $trimmed = $Identifier.Trim()
    if ($trimmed -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        return $trimmed
    }

    if ($ObjectType -eq 'device') {
        $filter = [uri]::EscapeDataString("displayName eq '$($trimmed.Replace("'","''"))'")
        $page = Invoke-EntraDgmGraph -Uri "$($script:GraphBaseUri)/devices?`$filter=$filter&`$select=id,displayName"
        $hit = @($page.value) | Select-Object -First 1
        if (-not $hit) { throw "No device named '$trimmed' was found." }
        return [string](Get-EntraDgmObjectProperty -Object $hit -Name 'id')
    }

    $idEsc = [uri]::EscapeDataString($trimmed)
    $user = Invoke-EntraDgmGraph -Uri "$($script:GraphBaseUri)/users/$idEsc`?`$select=id,displayName,userPrincipalName"
    return [string](Get-EntraDgmObjectProperty -Object $user -Name 'id')
}

function Write-EntraDgmTestOutput {
    param(
        [string[]]$Lines,
        [bool]$Matched,
        [string]$StatusText
    )
    $txtTestResult.Text = ($Lines -join "`r`n")
    $lblTestStatus.Text = $StatusText
    $lblTestStatus.ForeColor = $(if ($Matched) { $script:UiGreen } else { $script:UiError })
}

function Test-EntraDgmWithGraph {
    param([string]$Identifier)

    if (-not $script:IsConnected) {
        Show-EntraDgmMessage -Text 'Connect to Microsoft Graph first.' -Title 'Not Connected' -Icon Warning
        return
    }
    $rule = $txtRulePreview.Text
    $syntax = Test-EntraDgmRuleSyntax -Rule $rule
    if (-not $syntax.IsValid) {
        Show-EntraDgmMessage -Text ("Fix syntax errors before testing:`r`n" + ($syntax.Errors -join "`r`n")) -Title 'Invalid rule' -Icon Error
        return
    }
    if ([string]::IsNullOrWhiteSpace($Identifier)) {
        Show-EntraDgmMessage -Text 'Enter a UPN, device name, or object ID to test.' -Title 'Missing identifier' -Icon Warning
        return
    }

    try {
        Set-EntraDgmStatus -Text "Evaluating rule in Microsoft Graph for $Identifier..." -Color ([System.Drawing.Color]::Orange)
        $memberId = Resolve-EntraDgmTestMemberId -Identifier $Identifier -ObjectType $script:ObjectType
        $body = @{
            memberId       = $memberId
            membershipRule = $rule
        }
        $result = Invoke-EntraDgmGraph -Method POST -Uri "$($script:GraphBetaUri)/groups/evaluateDynamicMembership" -Body $body
        $matched = [bool]$result.membershipRuleEvaluationResult

        $lines = @(
            ('=' * 60)
            "GRAPH EVALUATION (evaluateDynamicMembership)"
            "Member ID: $memberId"
            "Rule: $rule"
            ('=' * 60)
            ''
            "membershipRuleEvaluationResult: $matched"
        )
        $details = $result.membershipRuleEvaluationDetails
        if ($details) {
            $lines += "expression: $($details.expression)"
            $lines += "expressionResult: $($details.expressionResult)"
            $prop = $details.propertyToEvaluate
            if ($prop) {
                $lines += "property: $($prop.propertyName) = $($prop.propertyValue)"
            }
        }
        $lines += ''
        if ($matched) {
            $lines += 'RESULT: Object WOULD BE INCLUDED in the dynamic group'
            $status = 'Matches (Graph)'
        }
        else {
            $lines += 'RESULT: Object WOULD BE EXCLUDED from the dynamic group'
            $status = 'Does not match (Graph)'
        }
        Write-EntraDgmTestOutput -Lines $lines -Matched $matched -StatusText $status
        Set-EntraDgmStatus -Text $status -Color $(if ($matched) { $script:UiGreen } else { $script:UiError })
    }
    catch {
        Set-EntraDgmStatus -Text 'Graph evaluation failed' -Color $script:UiError
        $lblTestStatus.Text = 'Graph evaluation failed'
        $lblTestStatus.ForeColor = $script:UiError
        $txtTestResult.Text = "Graph evaluation failed: $($_.Exception.Message)`r`n`r`nYou can still use local evaluation as an approximation."
    }
}

function Test-EntraDgmLocallyUi {
    param([string]$Identifier)

    $rule = $txtRulePreview.Text
    $syntax = Test-EntraDgmRuleSyntax -Rule $rule
    if (-not $syntax.IsValid) {
        Show-EntraDgmMessage -Text ("Fix syntax errors before testing:`r`n" + ($syntax.Errors -join "`r`n")) -Title 'Invalid rule' -Icon Error
        return
    }
    if ($script:Conditions.Count -eq 0) {
        Show-EntraDgmMessage -Text 'Add at least one condition, or apply a template, before local testing.' -Title 'No conditions' -Icon Warning
        return
    }

    try {
        $rows = $script:AttributeRows
        $headerName = $script:CurrentDisplay
        if ($script:IsConnected -and -not [string]::IsNullOrWhiteSpace($Identifier)) {
            $uri = Get-EntraDgmObjectUri -Identifier $Identifier -ObjectType $script:ObjectType -ExtraSelect @($script:CustomExtensions)
            $result = Invoke-EntraDgmGraph -Uri $uri
            $obj = $result
            if ($result.PSObject.Properties['value']) {
                $values = @($result.value)
                if ($values.Count -eq 0) { throw "No $($script:ObjectType) matched '$Identifier'." }
                $obj = $values[0]
            }
            $rows = @(ConvertFrom-EntraDgmGraphObject -GraphObject $obj -ObjectType $script:ObjectType -ExtraExtensionNames @($script:CustomExtensions))
            $headerName = "$(Get-EntraDgmObjectProperty -Object $obj -Name 'displayName') ($(Get-EntraDgmObjectProperty -Object $obj -Name 'userPrincipalName'))"
        }
        elseif (-not $rows -or $rows.Count -eq 0) {
            Show-EntraDgmMessage -Text 'Load a user or device first, or connect so the tester can fetch one.' -Title 'Nothing loaded' -Icon Warning
            return
        }

        $eval = Test-EntraDgmRuleLocally -Conditions @($script:Conditions) -AttributeRows $rows
        if ($eval.Error) { throw $eval.Error }

        $lines = @(
            ('=' * 60)
            "LOCAL EVALUATION (approximate; Graph is authoritative)"
            "Object: $headerName"
            "Rule: $rule"
            ('=' * 60)
            ''
        )
        foreach ($item in @($eval.Results)) {
            $mark = if ($item.Passed) { '[PASS]' } else { '[FAIL]' }
            $lines += "$mark $($item.Property) $($item.Operator) $($item.Expected)"
            $lines += "    Actual: $($item.Actual)"
            $lines += ''
        }
        $lines += $(if ($eval.Matched) {
            'RESULT: Object WOULD BE INCLUDED in the dynamic group'
        } else {
            'RESULT: Object WOULD BE EXCLUDED from the dynamic group'
        })
        $lines += 'Grouping is left-to-right and matches the parentheses in the generated rule.'
        $status = if ($eval.Matched) { 'Matches (local)' } else { 'Does not match (local)' }
        Write-EntraDgmTestOutput -Lines $lines -Matched $eval.Matched -StatusText $status
    }
    catch {
        $lblTestStatus.Text = 'Local evaluation failed'
        $lblTestStatus.ForeColor = $script:UiError
        $txtTestResult.Text = "Local evaluation failed: $($_.Exception.Message)"
    }
}

function Set-EntraDgmSplitterLayout {
    if (-not $splitMain -or $splitMain.IsDisposed) { return }

    $width = $splitMain.ClientSize.Width
    if ($width -le 80) { return }

    $splitterWidth = 4
    try { $splitterWidth = [Math]::Max(1, $splitMain.SplitterWidth) } catch { }

    # Keep mins small enough for the current width, then apply a ~50/50 split.
    $p1Min = 240
    $p2Min = 280
    $budget = [Math]::Max(40, [int][Math]::Floor(($width - $splitterWidth - 40) / 2))
    if ($p1Min -gt $budget) { $p1Min = $budget }
    if ($p2Min -gt $budget) { $p2Min = $budget }

    try {
        $splitMain.Panel1MinSize = 25
        $splitMain.Panel2MinSize = 25

        $desired = [int]($width * 0.48)
        $minDist = $p1Min
        $maxDist = $width - $p2Min - $splitterWidth
        if ($maxDist -lt $minDist) { return }
        if ($desired -lt $minDist) { $desired = $minDist }
        if ($desired -gt $maxDist) { $desired = $maxDist }
        $splitMain.SplitterDistance = $desired
        $splitMain.Panel1MinSize = $p1Min
        $splitMain.Panel2MinSize = $p2Min
    }
    catch {
        # Layout is best-effort; never block the form from opening.
    }
}

function Set-EntraDgmObjectType {
    param([string]$ObjectType)

    if ($script:ObjectType -eq $ObjectType) { return }
    $script:ObjectType = $ObjectType
    $script:AttributeRows = @()
    $script:CurrentObject = $null
    $lstAttributes.Items.Clear()
    $lblObjectInfo.Text = "No $ObjectType loaded"
    $lblObjectInfo.ForeColor = $script:UiMuted
    $lblObject.Text = $(if ($ObjectType -eq 'device') { 'Device:' } else { 'User UPN / ID:' })
    if ($script:Conditions.Count -gt 0) {
        $mixed = @($script:Conditions | Where-Object { $_.ObjectType -and $_.ObjectType -ne $ObjectType })
        if ($mixed.Count -gt 0) {
            Clear-EntraDgmConditions
        }
    }
}

# ===============================
# Form
# ===============================
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Entra ID Dynamic Group Rule Builder'
$form.Size = New-Object System.Drawing.Size(1280, 860)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(1180, 760)
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
$form.KeyPreview = $true
$form.Add_KeyDown({
    if ($_.KeyCode -eq 'Return' -and $txtObjectId.Focused) {
        Import-EntraDgmGraphObject -Identifier $txtObjectId.Text
        $_.SuppressKeyPress = $true
    }
})

$pnlTop = New-Object System.Windows.Forms.Panel
$pnlTop.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlTop.Height = 150
$form.Controls.Add($pnlTop)

$grpConnection = New-Object System.Windows.Forms.GroupBox
$grpConnection.Text = '1. Connect to Microsoft Graph'
$grpConnection.Location = New-Object System.Drawing.Point(10, 8)
$grpConnection.Size = New-Object System.Drawing.Size(1244, 58)
$grpConnection.Anchor = 'Top,Left,Right'
$pnlTop.Controls.Add($grpConnection)

$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Text = 'Connect to Graph'
$btnConnect.Location = New-Object System.Drawing.Point(16, 22)
$btnConnect.Size = New-Object System.Drawing.Size(150, 26)
$btnConnect.BackColor = $script:UiBlue
$btnConnect.ForeColor = [System.Drawing.Color]::White
$btnConnect.FlatStyle = 'Flat'
$btnConnect.Add_Click({ Connect-EntraDgmGraph })
$grpConnection.Controls.Add($btnConnect)

$btnDisconnect = New-Object System.Windows.Forms.Button
$btnDisconnect.Text = 'Disconnect'
$btnDisconnect.Location = New-Object System.Drawing.Point(172, 22)
$btnDisconnect.Size = New-Object System.Drawing.Size(100, 26)
$btnDisconnect.Enabled = $false
$btnDisconnect.Add_Click({ Disconnect-EntraDgmGraph })
$grpConnection.Controls.Add($btnDisconnect)

$rdoUser = New-Object System.Windows.Forms.RadioButton
$rdoUser.Text = 'Users'
$rdoUser.Location = New-Object System.Drawing.Point(290, 24)
$rdoUser.Size = New-Object System.Drawing.Size(70, 22)
$rdoUser.Checked = $true
$rdoUser.Add_CheckedChanged({ if ($rdoUser.Checked) { Set-EntraDgmObjectType -ObjectType 'user' } })
$grpConnection.Controls.Add($rdoUser)

$rdoDevice = New-Object System.Windows.Forms.RadioButton
$rdoDevice.Text = 'Devices'
$rdoDevice.Location = New-Object System.Drawing.Point(360, 24)
$rdoDevice.Size = New-Object System.Drawing.Size(80, 22)
$rdoDevice.Add_CheckedChanged({ if ($rdoDevice.Checked) { Set-EntraDgmObjectType -ObjectType 'device' } })
$grpConnection.Controls.Add($rdoDevice)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = 'Not connected'
$statusLabel.ForeColor = $script:UiError
$statusLabel.Location = New-Object System.Drawing.Point(450, 26)
$statusLabel.Size = New-Object System.Drawing.Size(770, 20)
$statusLabel.Anchor = 'Top,Left,Right'
$grpConnection.Controls.Add($statusLabel)

$grpObject = New-Object System.Windows.Forms.GroupBox
$grpObject.Text = '2. Load attributes from a real object'
$grpObject.Location = New-Object System.Drawing.Point(10, 70)
$grpObject.Size = New-Object System.Drawing.Size(1244, 72)
$grpObject.Anchor = 'Top,Left,Right'
$pnlTop.Controls.Add($grpObject)

$lblObject = New-Object System.Windows.Forms.Label
$lblObject.Text = 'User UPN / ID:'
$lblObject.Location = New-Object System.Drawing.Point(16, 24)
$lblObject.Size = New-Object System.Drawing.Size(110, 20)
$grpObject.Controls.Add($lblObject)

$txtObjectId = New-Object System.Windows.Forms.TextBox
$txtObjectId.Location = New-Object System.Drawing.Point(128, 22)
$txtObjectId.Size = New-Object System.Drawing.Size(320, 22)
$txtObjectId.Enabled = $false
$grpObject.Controls.Add($txtObjectId)

$btnLoadObject = New-Object System.Windows.Forms.Button
$btnLoadObject.Text = 'Load'
$btnLoadObject.Location = New-Object System.Drawing.Point(454, 20)
$btnLoadObject.Size = New-Object System.Drawing.Size(90, 26)
$btnLoadObject.Enabled = $false
$btnLoadObject.BackColor = $script:UiGreen
$btnLoadObject.ForeColor = [System.Drawing.Color]::White
$btnLoadObject.FlatStyle = 'Flat'
$btnLoadObject.Add_Click({ Import-EntraDgmGraphObject -Identifier $txtObjectId.Text })
$grpObject.Controls.Add($btnLoadObject)

$lblAppId = New-Object System.Windows.Forms.Label
$lblAppId.Text = 'Ext. App ID:'
$lblAppId.Location = New-Object System.Drawing.Point(560, 24)
$lblAppId.Size = New-Object System.Drawing.Size(80, 20)
$grpObject.Controls.Add($lblAppId)

$txtAppId = New-Object System.Windows.Forms.TextBox
$txtAppId.Location = New-Object System.Drawing.Point(642, 22)
$txtAppId.Size = New-Object System.Drawing.Size(250, 22)
$txtAppId.Enabled = $false
$grpObject.Controls.Add($txtAppId)

$btnLoadExtensions = New-Object System.Windows.Forms.Button
$btnLoadExtensions.Text = 'Load extensions'
$btnLoadExtensions.Location = New-Object System.Drawing.Point(898, 20)
$btnLoadExtensions.Size = New-Object System.Drawing.Size(120, 26)
$btnLoadExtensions.Enabled = $false
$btnLoadExtensions.Add_Click({ Import-EntraDgmCustomExtensions })
$grpObject.Controls.Add($btnLoadExtensions)

$lblObjectInfo = New-Object System.Windows.Forms.Label
$lblObjectInfo.Text = 'No user loaded'
$lblObjectInfo.ForeColor = $script:UiMuted
$lblObjectInfo.Location = New-Object System.Drawing.Point(16, 48)
$lblObjectInfo.Size = New-Object System.Drawing.Size(1210, 18)
$lblObjectInfo.Anchor = 'Top,Left,Right'
$grpObject.Controls.Add($lblObjectInfo)

$pnlBottom = New-Object System.Windows.Forms.Panel
$pnlBottom.Dock = [System.Windows.Forms.DockStyle]::Bottom
$pnlBottom.Height = 355
$form.Controls.Add($pnlBottom)

$splitMain = New-Object System.Windows.Forms.SplitContainer
$splitMain.Dock = [System.Windows.Forms.DockStyle]::Fill
$splitMain.Orientation = [System.Windows.Forms.Orientation]::Vertical
$form.Controls.Add($splitMain)

# Left: attributes
$grpAttributes = New-Object System.Windows.Forms.GroupBox
$grpAttributes.Text = '3. Supported attributes (rule name, not Graph name)'
$grpAttributes.Dock = [System.Windows.Forms.DockStyle]::Fill
$splitMain.Panel1.Controls.Add($grpAttributes)

$txtAttributeFilter = New-Object System.Windows.Forms.TextBox
$txtAttributeFilter.Location = New-Object System.Drawing.Point(10, 22)
$txtAttributeFilter.Size = New-Object System.Drawing.Size(280, 22)
$txtAttributeFilter.Anchor = 'Top,Left,Right'
$txtAttributeFilter.Add_TextChanged({ Update-EntraDgmAttributeList })
$grpAttributes.Controls.Add($txtAttributeFilter)

$chkSupportedOnly = New-Object System.Windows.Forms.CheckBox
$chkSupportedOnly.Text = 'Supported properties only'
$chkSupportedOnly.Checked = $true
$chkSupportedOnly.Location = New-Object System.Drawing.Point(300, 24)
$chkSupportedOnly.Size = New-Object System.Drawing.Size(200, 20)
$chkSupportedOnly.Anchor = 'Top,Right'
$chkSupportedOnly.Add_CheckedChanged({ Update-EntraDgmAttributeList })
$grpAttributes.Controls.Add($chkSupportedOnly)

$lstAttributes = New-Object System.Windows.Forms.ListView
$lstAttributes.Location = New-Object System.Drawing.Point(10, 50)
$lstAttributes.Size = New-Object System.Drawing.Size(590, 250)
$lstAttributes.Anchor = 'Top,Bottom,Left,Right'
$lstAttributes.View = 'Details'
$lstAttributes.FullRowSelect = $true
$lstAttributes.GridLines = $true
$lstAttributes.HideSelection = $false
$lstAttributes.Enabled = $false
$lstAttributes.ShowItemToolTips = $true
[void]$lstAttributes.Columns.Add('Property', 200)
[void]$lstAttributes.Columns.Add('Type', 110)
[void]$lstAttributes.Columns.Add('Current value', 260)
$lstAttributes.Add_SelectedIndexChanged({
    $attr = Get-EntraDgmSelectedAttribute
    Reset-EntraDgmOperatorList -Attribute $attr
})
$lstAttributes.Add_DoubleClick({ Add-EntraDgmConditionFromUi })
$grpAttributes.Controls.Add($lstAttributes)

# Right: builder
$grpBuilder = New-Object System.Windows.Forms.GroupBox
$grpBuilder.Text = '4. Build a condition'
$grpBuilder.Dock = [System.Windows.Forms.DockStyle]::Fill
$splitMain.Panel2.Controls.Add($grpBuilder)

$lblOperator = New-Object System.Windows.Forms.Label
$lblOperator.Text = 'Operator'
$lblOperator.Location = New-Object System.Drawing.Point(10, 24)
$lblOperator.Size = New-Object System.Drawing.Size(70, 20)
$grpBuilder.Controls.Add($lblOperator)

$cmbOperator = New-Object System.Windows.Forms.ComboBox
$cmbOperator.DropDownStyle = 'DropDownList'
$cmbOperator.Location = New-Object System.Drawing.Point(80, 20)
$cmbOperator.Size = New-Object System.Drawing.Size(140, 22)
$cmbOperator.Enabled = $false
$cmbOperator.Add_SelectedIndexChanged({ Update-EntraDgmValueInput })
$grpBuilder.Controls.Add($cmbOperator)

$lblCollection = New-Object System.Windows.Forms.Label
$lblCollection.Text = 'Collection'
$lblCollection.Location = New-Object System.Drawing.Point(230, 24)
$lblCollection.Size = New-Object System.Drawing.Size(70, 20)
$grpBuilder.Controls.Add($lblCollection)

$cmbCollectionMode = New-Object System.Windows.Forms.ComboBox
$cmbCollectionMode.DropDownStyle = 'DropDownList'
$cmbCollectionMode.Location = New-Object System.Drawing.Point(300, 20)
$cmbCollectionMode.Size = New-Object System.Drawing.Size(70, 22)
$cmbCollectionMode.Items.AddRange(@('any', 'all'))
$cmbCollectionMode.SelectedIndex = 0
$cmbCollectionMode.Enabled = $false
$grpBuilder.Controls.Add($cmbCollectionMode)

$cmbCollectionField = New-Object System.Windows.Forms.ComboBox
$cmbCollectionField.DropDownStyle = 'DropDownList'
$cmbCollectionField.Location = New-Object System.Drawing.Point(376, 20)
$cmbCollectionField.Size = New-Object System.Drawing.Size(130, 22)
$cmbCollectionField.Enabled = $false
$grpBuilder.Controls.Add($cmbCollectionField)

$chkRequireEnabled = New-Object System.Windows.Forms.CheckBox
$chkRequireEnabled.Text = 'Enabled plan'
$chkRequireEnabled.Location = New-Object System.Drawing.Point(512, 22)
$chkRequireEnabled.Size = New-Object System.Drawing.Size(110, 20)
$chkRequireEnabled.Enabled = $false
$grpBuilder.Controls.Add($chkRequireEnabled)

$lblValue = New-Object System.Windows.Forms.Label
$lblValue.Text = 'Value'
$lblValue.Location = New-Object System.Drawing.Point(10, 54)
$lblValue.Size = New-Object System.Drawing.Size(70, 20)
$grpBuilder.Controls.Add($lblValue)

$txtValue = New-Object System.Windows.Forms.TextBox
$txtValue.Location = New-Object System.Drawing.Point(80, 50)
$txtValue.Size = New-Object System.Drawing.Size(300, 22)
$txtValue.Enabled = $false
$txtValue.Anchor = 'Top,Left,Right'
$grpBuilder.Controls.Add($txtValue)

$cmbBoolean = New-Object System.Windows.Forms.ComboBox
$cmbBoolean.DropDownStyle = 'DropDownList'
$cmbBoolean.Location = New-Object System.Drawing.Point(80, 50)
$cmbBoolean.Size = New-Object System.Drawing.Size(100, 22)
$cmbBoolean.Items.AddRange(@('true', 'false'))
$cmbBoolean.SelectedIndex = 0
$cmbBoolean.Visible = $false
$grpBuilder.Controls.Add($cmbBoolean)

$chkNegate = New-Object System.Windows.Forms.CheckBox
$chkNegate.Text = 'Negate (-not)'
$chkNegate.Location = New-Object System.Drawing.Point(390, 52)
$chkNegate.Size = New-Object System.Drawing.Size(110, 20)
$chkNegate.Anchor = 'Top,Right'
$grpBuilder.Controls.Add($chkNegate)

$btnAddCondition = New-Object System.Windows.Forms.Button
$btnAddCondition.Text = 'Add condition'
$btnAddCondition.Location = New-Object System.Drawing.Point(508, 48)
$btnAddCondition.Size = New-Object System.Drawing.Size(120, 26)
$btnAddCondition.Enabled = $false
$btnAddCondition.BackColor = $script:UiBlue
$btnAddCondition.ForeColor = [System.Drawing.Color]::White
$btnAddCondition.FlatStyle = 'Flat'
$btnAddCondition.Anchor = 'Top,Right'
$btnAddCondition.Add_Click({ Add-EntraDgmConditionFromUi })
$grpBuilder.Controls.Add($btnAddCondition)

$lblJoin = New-Object System.Windows.Forms.Label
$lblJoin.Text = 'Join next with'
$lblJoin.Location = New-Object System.Drawing.Point(10, 82)
$lblJoin.Size = New-Object System.Drawing.Size(90, 20)
$grpBuilder.Controls.Add($lblJoin)

$rdoAnd = New-Object System.Windows.Forms.RadioButton
$rdoAnd.Text = 'AND'
$rdoAnd.Location = New-Object System.Drawing.Point(100, 80)
$rdoAnd.Size = New-Object System.Drawing.Size(55, 22)
$rdoAnd.Checked = $true
$grpBuilder.Controls.Add($rdoAnd)

$rdoOr = New-Object System.Windows.Forms.RadioButton
$rdoOr.Text = 'OR'
$rdoOr.Location = New-Object System.Drawing.Point(155, 80)
$rdoOr.Size = New-Object System.Drawing.Size(50, 22)
$grpBuilder.Controls.Add($rdoOr)

$btnDirectReports = New-Object System.Windows.Forms.Button
$btnDirectReports.Text = 'Direct Reports'
$btnDirectReports.Location = New-Object System.Drawing.Point(220, 78)
$btnDirectReports.Size = New-Object System.Drawing.Size(110, 26)
$btnDirectReports.Add_Click({ Add-EntraDgmDirectReportsCondition })
$grpBuilder.Controls.Add($btnDirectReports)

$cmbTemplate = New-Object System.Windows.Forms.ComboBox
$cmbTemplate.DropDownStyle = 'DropDownList'
$cmbTemplate.Location = New-Object System.Drawing.Point(336, 78)
$cmbTemplate.Size = New-Object System.Drawing.Size(170, 22)
$cmbTemplate.Anchor = 'Top,Left,Right'
$cmbTemplate.Items.Add('(templates)')
foreach ($t in Get-EntraDgmCommonTemplates) { [void]$cmbTemplate.Items.Add($t.Name) }
$cmbTemplate.SelectedIndex = 0
$grpBuilder.Controls.Add($cmbTemplate)

$btnApplyTemplate = New-Object System.Windows.Forms.Button
$btnApplyTemplate.Text = 'Apply'
$btnApplyTemplate.Location = New-Object System.Drawing.Point(512, 76)
$btnApplyTemplate.Size = New-Object System.Drawing.Size(120, 26)
$btnApplyTemplate.Anchor = 'Top,Right'
$btnApplyTemplate.Add_Click({ Apply-EntraDgmTemplate })
$grpBuilder.Controls.Add($btnApplyTemplate)

$lstConditions = New-Object System.Windows.Forms.ListView
$lstConditions.Location = New-Object System.Drawing.Point(10, 110)
$lstConditions.Size = New-Object System.Drawing.Size(620, 130)
$lstConditions.Anchor = 'Top,Bottom,Left,Right'
$lstConditions.View = 'Details'
$lstConditions.FullRowSelect = $true
$lstConditions.GridLines = $true
$lstConditions.HideSelection = $false
[void]$lstConditions.Columns.Add('Property', 180)
[void]$lstConditions.Columns.Add('Operator', 110)
[void]$lstConditions.Columns.Add('Value', 220)
[void]$lstConditions.Columns.Add('Join', 80)
$grpBuilder.Controls.Add($lstConditions)

$btnRemoveCondition = New-Object System.Windows.Forms.Button
$btnRemoveCondition.Text = 'Remove'
$btnRemoveCondition.Location = New-Object System.Drawing.Point(10, 246)
$btnRemoveCondition.Size = New-Object System.Drawing.Size(80, 26)
$btnRemoveCondition.Anchor = 'Bottom,Left'
$btnRemoveCondition.Add_Click({ Remove-EntraDgmSelectedCondition })
$grpBuilder.Controls.Add($btnRemoveCondition)

$btnMoveUp = New-Object System.Windows.Forms.Button
$btnMoveUp.Text = 'Up'
$btnMoveUp.Location = New-Object System.Drawing.Point(96, 246)
$btnMoveUp.Size = New-Object System.Drawing.Size(50, 26)
$btnMoveUp.Anchor = 'Bottom,Left'
$btnMoveUp.Add_Click({ Move-EntraDgmSelectedCondition -Delta -1 })
$grpBuilder.Controls.Add($btnMoveUp)

$btnMoveDown = New-Object System.Windows.Forms.Button
$btnMoveDown.Text = 'Down'
$btnMoveDown.Location = New-Object System.Drawing.Point(152, 246)
$btnMoveDown.Size = New-Object System.Drawing.Size(55, 26)
$btnMoveDown.Anchor = 'Bottom,Left'
$btnMoveDown.Add_Click({ Move-EntraDgmSelectedCondition -Delta 1 })
$grpBuilder.Controls.Add($btnMoveDown)

$lblTip = New-Object System.Windows.Forms.Label
$lblTip.Text = 'Tip: -in uses comma-separated values. Collections use -any (_ -startsWith "value"). Extension attributes are bold blue. Double-click an attribute to add it.'
$lblTip.ForeColor = $script:UiBlue
$lblTip.Location = New-Object System.Drawing.Point(220, 248)
$lblTip.Size = New-Object System.Drawing.Size(410, 32)
$lblTip.Anchor = 'Bottom,Left,Right'
$grpBuilder.Controls.Add($lblTip)

# Preview + test
$grpPreview = New-Object System.Windows.Forms.GroupBox
$grpPreview.Text = '5. Membership rule (editable)'
$grpPreview.Location = New-Object System.Drawing.Point(10, 8)
$grpPreview.Size = New-Object System.Drawing.Size(1244, 145)
$grpPreview.Anchor = 'Top,Left,Right'
$pnlBottom.Controls.Add($grpPreview)

$txtRulePreview = New-Object System.Windows.Forms.TextBox
$txtRulePreview.Multiline = $true
$txtRulePreview.ScrollBars = 'Vertical'
$txtRulePreview.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtRulePreview.Location = New-Object System.Drawing.Point(10, 20)
$txtRulePreview.Size = New-Object System.Drawing.Size(1090, 52)
$txtRulePreview.Anchor = 'Top,Left,Right'
$txtRulePreview.Text = 'No conditions added yet'
$txtRulePreview.Add_TextChanged({
    if ($txtRulePreview.Text -and $txtRulePreview.Text -ne 'No conditions added yet') {
        Update-EntraDgmValidationUi -Rule $txtRulePreview.Text
        $btnCopyRule.Enabled = $true
    }
})
$grpPreview.Controls.Add($txtRulePreview)

$btnCopyRule = New-Object System.Windows.Forms.Button
$btnCopyRule.Text = 'Copy rule'
$btnCopyRule.Location = New-Object System.Drawing.Point(1110, 20)
$btnCopyRule.Size = New-Object System.Drawing.Size(120, 26)
$btnCopyRule.Enabled = $false
$btnCopyRule.BackColor = $script:UiBlue
$btnCopyRule.ForeColor = [System.Drawing.Color]::White
$btnCopyRule.FlatStyle = 'Flat'
$btnCopyRule.Anchor = 'Top,Right'
$btnCopyRule.Add_Click({ Copy-EntraDgmRule })
$grpPreview.Controls.Add($btnCopyRule)

$btnClearConditions = New-Object System.Windows.Forms.Button
$btnClearConditions.Text = 'Clear all'
$btnClearConditions.Location = New-Object System.Drawing.Point(1110, 50)
$btnClearConditions.Size = New-Object System.Drawing.Size(120, 26)
$btnClearConditions.Enabled = $false
$btnClearConditions.Anchor = 'Top,Right'
$btnClearConditions.Add_Click({ Clear-EntraDgmConditions })
$grpPreview.Controls.Add($btnClearConditions)

$lblCharCount = New-Object System.Windows.Forms.Label
$lblCharCount.Text = '0 / 3072'
$lblCharCount.Location = New-Object System.Drawing.Point(10, 74)
$lblCharCount.Size = New-Object System.Drawing.Size(120, 16)
$lblCharCount.ForeColor = $script:UiMuted
$grpPreview.Controls.Add($lblCharCount)

$txtValidation = New-Object System.Windows.Forms.TextBox
$txtValidation.Multiline = $true
$txtValidation.ReadOnly = $true
$txtValidation.ScrollBars = 'Vertical'
$txtValidation.BorderStyle = 'None'
$txtValidation.Location = New-Object System.Drawing.Point(10, 92)
$txtValidation.Size = New-Object System.Drawing.Size(1220, 44)
$txtValidation.Anchor = 'Top,Left,Right'
$txtValidation.Text = 'Add a condition or apply a template to build a rule.'
$txtValidation.ForeColor = $script:UiMuted
$grpPreview.Controls.Add($txtValidation)

$grpTest = New-Object System.Windows.Forms.GroupBox
$grpTest.Text = '6. Test against the rule'
$grpTest.Location = New-Object System.Drawing.Point(10, 156)
$grpTest.Size = New-Object System.Drawing.Size(1244, 190)
$grpTest.Anchor = 'Top,Bottom,Left,Right'
$pnlBottom.Controls.Add($grpTest)

$lblTestId = New-Object System.Windows.Forms.Label
$lblTestId.Text = 'Test UPN / ID'
$lblTestId.Location = New-Object System.Drawing.Point(10, 24)
$lblTestId.Size = New-Object System.Drawing.Size(100, 20)
$grpTest.Controls.Add($lblTestId)

$txtTestId = New-Object System.Windows.Forms.TextBox
$txtTestId.Location = New-Object System.Drawing.Point(112, 22)
$txtTestId.Size = New-Object System.Drawing.Size(320, 22)
$grpTest.Controls.Add($txtTestId)

$btnTestGraph = New-Object System.Windows.Forms.Button
$btnTestGraph.Text = 'Test with Graph'
$btnTestGraph.Location = New-Object System.Drawing.Point(440, 20)
$btnTestGraph.Size = New-Object System.Drawing.Size(130, 26)
$btnTestGraph.Enabled = $false
$btnTestGraph.BackColor = $script:UiBlue
$btnTestGraph.ForeColor = [System.Drawing.Color]::White
$btnTestGraph.FlatStyle = 'Flat'
$btnTestGraph.Add_Click({ Test-EntraDgmWithGraph -Identifier $txtTestId.Text })
$grpTest.Controls.Add($btnTestGraph)

$btnTestLocal = New-Object System.Windows.Forms.Button
$btnTestLocal.Text = 'Test locally'
$btnTestLocal.Location = New-Object System.Drawing.Point(576, 20)
$btnTestLocal.Size = New-Object System.Drawing.Size(110, 26)
$btnTestLocal.Add_Click({ Test-EntraDgmLocallyUi -Identifier $txtTestId.Text })
$grpTest.Controls.Add($btnTestLocal)

$lblTestStatus = New-Object System.Windows.Forms.Label
$lblTestStatus.Text = 'Graph evaluation is authoritative; local evaluation is an approximation.'
$lblTestStatus.Location = New-Object System.Drawing.Point(700, 24)
$lblTestStatus.Size = New-Object System.Drawing.Size(520, 20)
$lblTestStatus.ForeColor = $script:UiMuted
$lblTestStatus.Anchor = 'Top,Left,Right'
$grpTest.Controls.Add($lblTestStatus)

$txtTestResult = New-Object System.Windows.Forms.TextBox
$txtTestResult.Multiline = $true
$txtTestResult.ScrollBars = 'Vertical'
$txtTestResult.ReadOnly = $true
$txtTestResult.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtTestResult.Location = New-Object System.Drawing.Point(10, 54)
$txtTestResult.Size = New-Object System.Drawing.Size(1220, 124)
$txtTestResult.Anchor = 'Top,Bottom,Left,Right'
$txtTestResult.Text = 'Load an object, add conditions, then test with Graph (recommended) or locally.'
$grpTest.Controls.Add($txtTestResult)

# Fill must sit first in the child collection so the top/bottom panels keep their docked space.
$form.Controls.SetChildIndex($splitMain, 0)
$form.Controls.SetChildIndex($pnlBottom, 1)
$form.Controls.SetChildIndex($pnlTop, 2)

$form.Add_Shown({
    Set-EntraDgmSplitterLayout
    try {
        Test-EntraDgmGraphModule
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        if ($ctx -and $ctx.Account) {
            $script:IsConnected = $true
            $btnConnect.Enabled = $false
            $btnDisconnect.Enabled = $true
            $btnLoadObject.Enabled = $true
            $txtObjectId.Enabled = $true
            $btnLoadExtensions.Enabled = $true
            $txtAppId.Enabled = $true
            $btnTestGraph.Enabled = $true
            Set-EntraDgmStatus -Text "Using existing Graph session: $($ctx.Account)" -Color $script:UiGreen
        }
    }
    catch { }
})

[void]$form.ShowDialog()

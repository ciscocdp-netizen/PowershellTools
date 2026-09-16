<#
.SYNOPSIS
    Active Directory Object Manager - Modern GUI Tool
    Manage Users (Disable, Enable, Delete) and Computer Objects (Disable, Enable, Delete) in bulk.
    Supports manual entry and CSV import for both user and computer names.

.DESCRIPTION
    PowerShell 5.1+ / 7+ WinForms GUI application for managing Active Directory user and
    computer accounts. Target a specific domain, discover the PDC Emulator, and
    perform all actions against it. Produces verbose logs including OU path,
    description, and action taken.

.NOTES
    Version: 5.0
    Requires: ActiveDirectory PowerShell module
    Requires: Run as a user with appropriate AD permissions
    Compatible: PowerShell 5.1+ on Windows
    
    Changes in v5.0:
    - Modernized code structure and error handling
    - Added Disable/Enable functionality for computer accounts
    - Enhanced CSV import with better column detection
    - Improved UI responsiveness with async operations
    - Better logging and audit trail
    - Enhanced batch operations for performance
    - Improved error messages and user feedback
#>

#Requires -Version 5.1

# ============================================================
# IMPORT REQUIRED ASSEMBLIES & MODULES
# ============================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    [System.Windows.Forms.MessageBox]::Show(
        "The ActiveDirectory PowerShell module is not installed or could not be loaded.`n`nPlease install RSAT (Remote Server Administration Tools) or run this on a Domain Controller.",
        "Module Missing",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit
}

# ============================================================
# GLOBAL VARIABLES
# ============================================================
$script:LogEntries         = [System.Collections.ArrayList]::new()
$script:ProcessedUsers     = [System.Collections.ArrayList]::new()
$script:ProcessedComputers = [System.Collections.ArrayList]::new()
$script:TargetServer       = $null
$script:TargetDomain       = $null
$script:AppVersion         = "5.0"

# ============================================================
# HELPER FUNCTIONS
# ============================================================
function Get-Timestamp {
    return (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Timestamp
    $entry = "[$timestamp] [$Level] $Message"
    [void]$script:LogEntries.Add($entry)
    if ($script:txtLog) {
        $script:txtLog.AppendText("$entry`r`n")
        $script:txtLog.ScrollToCaret()
    }
}

function Export-LogToFile {
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "Log Files (*.log)|*.log|Text Files (*.txt)|*.txt|CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $saveDialog.Title = "Export Log File"
    $saveDialog.FileName = "AD_ObjectManager_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        if ($saveDialog.FileName -like "*.csv") {
            $allObjects = @()
            $allObjects += $script:ProcessedUsers
            $allObjects += $script:ProcessedComputers
            $allObjects | Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
        } else {
            $script:LogEntries | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
        }
        Write-Log "Log exported to: $($saveDialog.FileName)" "INFO"
        [System.Windows.Forms.MessageBox]::Show(
            "Log exported successfully to:`n$($saveDialog.FileName)",
            "Export Complete",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
}

function Resolve-TargetDomain {
    $domainInput = $script:txtDomain.Text.Trim()

    if ([string]::IsNullOrWhiteSpace($domainInput)) {
        try {
            $currentDomain = Get-ADDomain -ErrorAction Stop
            $script:TargetDomain = $currentDomain.DNSRoot
            $script:TargetServer = $currentDomain.PDCEmulator
            $script:lblDomainStatus.Text = "Domain: $($script:TargetDomain)"
            $script:lblDomainStatus.ForeColor = [System.Drawing.Color]::FromArgb(0, 210, 106)
            $script:lblPDCStatus.Text = "PDC Emulator: $($script:TargetServer)"
            $script:lblPDCStatus.ForeColor = [System.Drawing.Color]::FromArgb(0, 210, 106)
            Write-Log "Auto-detected current domain: $($script:TargetDomain)" "INFO"
            Write-Log "PDC Emulator resolved: $($script:TargetServer)" "INFO"
            return $true
        } catch {
            $script:lblDomainStatus.Text = "Domain: DETECTION FAILED"
            $script:lblDomainStatus.ForeColor = [System.Drawing.Color]::FromArgb(196, 43, 28)
            $script:lblPDCStatus.Text = "PDC Emulator: N/A"
            $script:lblPDCStatus.ForeColor = [System.Drawing.Color]::FromArgb(196, 43, 28)
            Write-Log "Failed to auto-detect domain: $($_.Exception.Message)" "ERROR"
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to detect the current domain.`n`nError: $($_.Exception.Message)`n`nPlease enter a domain FQDN manually.",
                "Domain Detection Failed",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return $false
        }
    } else {
        try {
            Write-Log "Attempting to connect to domain: $domainInput" "INFO"
            $targetDomainObj = Get-ADDomain -Identity $domainInput -ErrorAction Stop
            $script:TargetDomain = $targetDomainObj.DNSRoot
            $script:TargetServer = $targetDomainObj.PDCEmulator
            $script:lblDomainStatus.Text = "Domain: $($script:TargetDomain)"
            $script:lblDomainStatus.ForeColor = [System.Drawing.Color]::FromArgb(0, 210, 106)
            $script:lblPDCStatus.Text = "PDC Emulator: $($script:TargetServer)"
            $script:lblPDCStatus.ForeColor = [System.Drawing.Color]::FromArgb(0, 210, 106)
            Write-Log "Successfully connected to domain: $($script:TargetDomain)" "INFO"
            Write-Log "PDC Emulator resolved: $($script:TargetServer)" "INFO"
            return $true
        } catch {
            $script:lblDomainStatus.Text = "Domain: CONNECTION FAILED"
            $script:lblDomainStatus.ForeColor = [System.Drawing.Color]::FromArgb(196, 43, 28)
            $script:lblPDCStatus.Text = "PDC Emulator: N/A"
            $script:lblPDCStatus.ForeColor = [System.Drawing.Color]::FromArgb(196, 43, 28)
            Write-Log "Failed to connect to domain '$domainInput': $($_.Exception.Message)" "ERROR"
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to connect to domain: $domainInput`n`nError: $($_.Exception.Message)`n`nVerify the FQDN is correct and you have network connectivity.",
                "Domain Connection Failed",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return $false
        }
    }
}

function Show-ScrollableConfirmation {
    param(
        [string]$Title,
        [string]$SummaryText,
        [string[]]$UserLines,
        [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.Size = New-Object System.Drawing.Size(620, 520)
    $dlg.StartPosition = "CenterParent"
    $dlg.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false
    $dlg.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $dlg.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)

    $iconBox = New-Object System.Windows.Forms.PictureBox
    $iconBox.Size = New-Object System.Drawing.Size(40, 40)
    $iconBox.Location = New-Object System.Drawing.Point(15, 15)
    $iconBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::CenterImage
    switch ($Icon) {
        ([System.Windows.Forms.MessageBoxIcon]::Warning)     { $iconBox.Image = [System.Drawing.SystemIcons]::Warning.ToBitmap() }
        ([System.Windows.Forms.MessageBoxIcon]::Exclamation) { $iconBox.Image = [System.Drawing.SystemIcons]::Exclamation.ToBitmap() }
        ([System.Windows.Forms.MessageBoxIcon]::Stop)        { $iconBox.Image = [System.Drawing.SystemIcons]::Error.ToBitmap() }
        ([System.Windows.Forms.MessageBoxIcon]::Question)    { $iconBox.Image = [System.Drawing.SystemIcons]::Question.ToBitmap() }
        default { $iconBox.Image = [System.Drawing.SystemIcons]::Warning.ToBitmap() }
    }
    $dlg.Controls.Add($iconBox)

    $lblSummary = New-Object System.Windows.Forms.Label
    $lblSummary.Text = $SummaryText
    $lblSummary.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $lblSummary.Location = New-Object System.Drawing.Point(65, 12)
    $lblSummary.Size = New-Object System.Drawing.Size(530, 50)
    $dlg.Controls.Add($lblSummary)

    $txtList = New-Object System.Windows.Forms.TextBox
    $txtList.Multiline = $true
    $txtList.ReadOnly = $true
    $txtList.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
    $txtList.Location = New-Object System.Drawing.Point(15, 70)
    $txtList.Size = New-Object System.Drawing.Size(575, 350)
    $txtList.Font = New-Object System.Drawing.Font("Consolas", 9)
    $txtList.BackColor = [System.Drawing.Color]::White
    $txtList.Text = ($UserLines -join "`r`n")
    $dlg.Controls.Add($txtList)

    $btnYes = New-Object System.Windows.Forms.Button
    $btnYes.Text = "Yes"
    $btnYes.Size = New-Object System.Drawing.Size(100, 35)
    $btnYes.Location = New-Object System.Drawing.Point(370, 435)
    $btnYes.DialogResult = [System.Windows.Forms.DialogResult]::Yes
    $btnYes.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
    $btnYes.ForeColor = [System.Drawing.Color]::White
    $btnYes.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $dlg.Controls.Add($btnYes)

    $btnNo = New-Object System.Windows.Forms.Button
    $btnNo.Text = "No"
    $btnNo.Size = New-Object System.Drawing.Size(100, 35)
    $btnNo.Location = New-Object System.Drawing.Point(490, 435)
    $btnNo.DialogResult = [System.Windows.Forms.DialogResult]::No
    $btnNo.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $dlg.Controls.Add($btnNo)

    $dlg.AcceptButton = $btnYes
    $dlg.CancelButton = $btnNo

    return $dlg.ShowDialog()
}

# ============================================================
# USER BATCH FUNCTIONS
# ============================================================
function Get-ADUsersBatch {
    param([string[]]$SamAccountNames)

    $results = @{}
    $batchSize = 50
    $adProperties = @('Description','DistinguishedName','Enabled','DisplayName','EmailAddress','Title','Department','WhenCreated','LastLogonDate','SamAccountName')

    for ($i = 0; $i -lt $SamAccountNames.Count; $i += $batchSize) {
        $batch = $SamAccountNames[$i..[Math]::Min(($i + $batchSize - 1), ($SamAccountNames.Count - 1))]
        $filterParts = ($batch | ForEach-Object { "(samAccountName=$_)" }) -join ''
        $ldapFilter = "(|$filterParts)"

        $params = @{
            LDAPFilter  = $ldapFilter
            Properties  = $adProperties
            ErrorAction = 'SilentlyContinue'
        }
        if ($script:TargetServer) { $params['Server'] = $script:TargetServer }

        try {
            $users = @(Get-ADUser @params)
            foreach ($u in $users) {
                $results[$u.SamAccountName.ToLower()] = $u
            }
        } catch {
            Write-Log "Batch user query failed: $($_.Exception.Message). Falling back to individual lookups." "WARNING"
            foreach ($sam in $batch) {
                try {
                    $fbParams = @{
                        Identity    = $sam
                        Properties  = $adProperties
                        ErrorAction = 'Stop'
                    }
                    if ($script:TargetServer) { $fbParams['Server'] = $script:TargetServer }
                    $fbUser = Get-ADUser @fbParams
                    $results[$fbUser.SamAccountName.ToLower()] = $fbUser
                } catch { }
            }
        }
    }
    return $results
}

# ============================================================
# COMPUTER BATCH FUNCTIONS
# ============================================================
function Get-ADComputersBatch {
    param([string[]]$ComputerNames)

    $results = @{}
    $batchSize = 50
    $adProperties = @('Description','DistinguishedName','Enabled','Name','DNSHostName','OperatingSystem','OperatingSystemVersion','WhenCreated','LastLogonDate','SamAccountName','IPv4Address')

    for ($i = 0; $i -lt $ComputerNames.Count; $i += $batchSize) {
        $batch = $ComputerNames[$i..[Math]::Min(($i + $batchSize - 1), ($ComputerNames.Count - 1))]
        $batch = $batch | ForEach-Object { $_.TrimEnd('$') }
        $filterParts = ($batch | ForEach-Object { "(name=$_)" }) -join ''
        $ldapFilter = "(|$filterParts)"

        $params = @{
            LDAPFilter  = $ldapFilter
            Properties  = $adProperties
            ErrorAction = 'SilentlyContinue'
        }
        if ($script:TargetServer) { $params['Server'] = $script:TargetServer }

        try {
            $computers = @(Get-ADComputer @params)
            foreach ($c in $computers) {
                $results[$c.Name.ToLower()] = $c
            }
        } catch {
            Write-Log "Batch computer query failed: $($_.Exception.Message). Falling back to individual lookups." "WARNING"
            foreach ($name in $batch) {
                try {
                    $fbParams = @{
                        Identity    = $name
                        Properties  = $adProperties
                        ErrorAction = 'Stop'
                    }
                    if ($script:TargetServer) { $fbParams['Server'] = $script:TargetServer }
                    $fbComp = Get-ADComputer @fbParams
                    $results[$fbComp.Name.ToLower()] = $fbComp
                } catch { }
            }
        }
    }
    return $results
}

# ============================================================
# CHILD OBJECT REMOVAL (shared by Users and Computers)
# ============================================================
function Remove-ChildADObjects {
    param(
        [string]$ObjectDN,
        [string]$ObjectName
    )

    function Remove-ChildrenDepthFirst {
        param([string]$ParentDN)

        $removed = 0
        $searchParams = @{
            SearchBase  = $ParentDN
            SearchScope = 'OneLevel'
            LDAPFilter  = '(objectClass=*)'
            ErrorAction = 'SilentlyContinue'
        }
        if ($script:TargetServer) { $searchParams['Server'] = $script:TargetServer }

        $children = @(Get-ADObject @searchParams)
        if ($children.Count -eq 0) { return 0 }

        foreach ($child in $children) {
            $removed += Remove-ChildrenDepthFirst -ParentDN $child.DistinguishedName
            try {
                $removeParams = @{
                    Identity    = $child.DistinguishedName
                    Confirm     = $false
                    ErrorAction = 'Stop'
                }
                if ($script:TargetServer) { $removeParams['Server'] = $script:TargetServer }
                Remove-ADObject @removeParams
                $removed++
                Write-Log "  REMOVED CHILD: $($child.ObjectClass) | DN: $($child.DistinguishedName)" "INFO"
            } catch {
                Write-Log "  FAILED TO REMOVE CHILD: $($child.DistinguishedName) | Error: $($_.Exception.Message)" "ERROR"
            }
        }
        return $removed
    }

    $searchParams = @{
        SearchBase  = $ObjectDN
        SearchScope = 'OneLevel'
        LDAPFilter  = '(objectClass=*)'
        ErrorAction = 'SilentlyContinue'
    }
    if ($script:TargetServer) { $searchParams['Server'] = $script:TargetServer }

    try {
        $topChildren = @(Get-ADObject @searchParams)
    } catch {
        Write-Log "  Could not enumerate child objects for $ObjectName : $($_.Exception.Message)" "WARNING"
        return 0
    }

    if ($topChildren.Count -eq 0) { return 0 }

    $totalRemoved = 0
    Write-Log "  Found $($topChildren.Count) child object(s) under $ObjectName - removing depth-first" "WARNING"

    foreach ($child in $topChildren) {
        $totalRemoved += Remove-ChildrenDepthFirst -ParentDN $child.DistinguishedName
        try {
            $removeParams = @{
                Identity    = $child.DistinguishedName
                Confirm     = $false
                ErrorAction = 'Stop'
            }
            if ($script:TargetServer) { $removeParams['Server'] = $script:TargetServer }
            Remove-ADObject @removeParams
            $totalRemoved++
            Write-Log "  REMOVED CHILD: $($child.ObjectClass) | DN: $($child.DistinguishedName)" "INFO"
        } catch {
            Write-Log "  FAILED TO REMOVE CHILD: $($child.DistinguishedName) | Error: $($_.Exception.Message)" "ERROR"
        }
    }

    return $totalRemoved
}

function Get-OUFromDN {
    param([string]$DistinguishedName)
    if ([string]::IsNullOrEmpty($DistinguishedName)) { return "N/A" }
    $parts = $DistinguishedName -split ',', 2
    if ($parts.Count -gt 1) { return $parts[1] }
    return $DistinguishedName
}

function Parse-NameList {
    param([string]$RawText)
    $lines = $RawText -split "`r`n|`n|`r|,|;|\s+" |
             ForEach-Object { $_.Trim() } |
             Where-Object { $_ -ne '' }
    return $lines
}

# ============================================================
# USER GRID UPDATE
# ============================================================
function Update-UserDataGridView {
    $script:dgvUsers.Rows.Clear()
    foreach ($user in $script:ProcessedUsers) {
        $rowIndex = $script:dgvUsers.Rows.Add(
            $user.SamAccountName,
            $user.DisplayName,
            $user.Status,
            $user.OU,
            $user.Description,
            $user.Action,
            $user.Result,
            $user.Timestamp
        )
        $row = $script:dgvUsers.Rows[$rowIndex]
        switch ($user.Result) {
            "Success"   { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(230, 255, 230) }
            "Failed"    { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 230, 230) }
            "Skipped"   { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 255, 220) }
            "Not Found" { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240) }
        }
    }
}

# ============================================================
# COMPUTER GRID UPDATE
# ============================================================
function Update-ComputerDataGridView {
    $script:dgvComputers.Rows.Clear()
    foreach ($comp in $script:ProcessedComputers) {
        $rowIndex = $script:dgvComputers.Rows.Add(
            $comp.Name,
            $comp.DNSHostName,
            $comp.OperatingSystem,
            $comp.Status,
            $comp.OU,
            $comp.Description,
            $comp.Action,
            $comp.Result,
            $comp.Timestamp
        )
        $row = $script:dgvComputers.Rows[$rowIndex]
        switch ($comp.Result) {
            "Success"   { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(230, 255, 230) }
            "Failed"    { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 230, 230) }
            "Skipped"   { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 255, 220) }
            "Not Found" { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240) }
        }
    }
}

# ============================================================
# USER CSV IMPORT
# ============================================================
function Import-UserCSV {
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $openDialog.Title  = "Import User SAMAccountNames from CSV"

    if ($openDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    try {
        $csv = Import-Csv -Path $openDialog.FileName -ErrorAction Stop
    } catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to read CSV file:`n$($_.Exception.Message)",
            "CSV Import Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }

    if ($csv.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "The CSV file is empty or has no data rows.",
            "Empty CSV",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    $headers  = $csv[0].PSObject.Properties.Name
    $nameCol  = $headers | Where-Object { $_ -match '^(samaccountname|username|user|loginname)$' } | Select-Object -First 1

    if (-not $nameCol) {
        $nameCol = $headers[0]
        Write-Log "CSV: No recognised user header found. Using first column '$nameCol' as SAMAccountName source." "WARNING"
        [System.Windows.Forms.MessageBox]::Show(
            "No column named 'SamAccountName', 'Username', 'User', or 'LoginName' was found.`n`nUsing the first column '$nameCol' instead.`n`nSupported headers: SamAccountName, Username, User, LoginName",
            "CSV Column Auto-Selected",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }

    $importedNames = $csv | ForEach-Object { $_.$nameCol.Trim() } | Where-Object { $_ -ne '' } | Sort-Object -Unique

    if ($importedNames.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No SAMAccountNames found in column '$nameCol'.",
            "No Data",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    $existingNames = Parse-NameList -RawText $script:txtUserInput.Text
    $combined = ($existingNames + $importedNames) | Sort-Object -Unique
    $script:txtUserInput.Text = ($combined -join "`r`n")

    Write-Log "CSV IMPORT (Users): Loaded $($importedNames.Count) SAMAccountName(s) from '$($openDialog.FileName)' (column: $nameCol). Total in list: $($combined.Count)" "INFO"
    [System.Windows.Forms.MessageBox]::Show(
        "Successfully imported $($importedNames.Count) SAMAccountName(s) from:`n$($openDialog.FileName)`n`nColumn used: $nameCol`nTotal unique names in list: $($combined.Count)",
        "CSV Import Complete",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
}

# ============================================================
# USER ACTION FUNCTIONS
# ============================================================
function Lookup-Users {
    if (-not (Resolve-TargetDomain)) { return }

    $script:ProcessedUsers.Clear()
    $script:dgvUsers.Rows.Clear()
    $rawText = $script:txtUserInput.Text
    $userNames = Parse-NameList -RawText $rawText

    if ($userNames.Count -eq 0) {
        Write-Log "No usernames provided." "WARNING"
        [System.Windows.Forms.MessageBox]::Show(
            "No usernames found. Please paste SAMAccountNames into the input box or import a CSV.",
            "No Input",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    Write-Log "========================================" "INFO"
    Write-Log "USER LOOKUP STARTED - Processing $($userNames.Count) username(s)" "INFO"
    Write-Log "Target Domain : $($script:TargetDomain)" "INFO"
    Write-Log "Target Server : $($script:TargetServer) (PDC Emulator)" "INFO"
    Write-Log "========================================" "INFO"

    $script:progressBar.Maximum = $userNames.Count
    $script:progressBar.Value = 0
    $script:lblStatus.Text = "Querying $($userNames.Count) users via batch LDAP against $($script:TargetServer)..."
    [System.Windows.Forms.Application]::DoEvents()

    $script:txtLog.SuspendLayout()
    $adUsersMap = Get-ADUsersBatch -SamAccountNames $userNames
    Write-Log "Batch LDAP query returned $($adUsersMap.Count) user(s) from $($script:TargetServer)" "INFO"

    $found = 0; $notFound = 0

    foreach ($sam in $userNames) {
        $script:progressBar.Value = [Math]::Min($script:progressBar.Value + 1, $script:progressBar.Maximum)
        if ($script:progressBar.Value % 10 -eq 0 -or $script:progressBar.Value -eq $script:progressBar.Maximum) {
            $script:lblStatus.Text = "Processing: $($script:progressBar.Value) / $($userNames.Count)"
            [System.Windows.Forms.Application]::DoEvents()
        }

        $adUser = $adUsersMap[$sam.ToLower()]

        if ($adUser) {
            $found++
            $ou = Get-OUFromDN -DistinguishedName $adUser.DistinguishedName
            $desc = if ($adUser.Description) { $adUser.Description } else { "(none)" }
            $status = if ($adUser.Enabled) { "Enabled" } else { "Disabled" }
            $displayName = if ($adUser.DisplayName) { $adUser.DisplayName } else { $sam }

            $userObj = [PSCustomObject]@{
                SamAccountName = $sam
                DisplayName    = $displayName
                Status         = $status
                OU             = $ou
                Description    = $desc
                Action         = "Pending"
                Result         = "Looked Up"
                Timestamp      = Get-Timestamp
                Email          = $adUser.EmailAddress
                Title          = $adUser.Title
                Department     = $adUser.Department
                WhenCreated    = $adUser.WhenCreated
                LastLogon      = $adUser.LastLogonDate
                DN             = $adUser.DistinguishedName
                Domain         = $script:TargetDomain
                Server         = $script:TargetServer
                ObjectType     = "User"
            }
            [void]$script:ProcessedUsers.Add($userObj)
            Write-Log "FOUND: $sam | Display: $displayName | Status: $status | OU: $ou | Desc: $desc" "INFO"
        } else {
            $notFound++
            $userObj = [PSCustomObject]@{
                SamAccountName = $sam
                DisplayName    = "N/A"
                Status         = "N/A"
                OU             = "N/A"
                Description    = "N/A"
                Action         = "N/A"
                Result         = "Not Found"
                Timestamp      = Get-Timestamp
                Email          = "N/A"; Title = "N/A"; Department = "N/A"
                WhenCreated    = "N/A"; LastLogon = "N/A"
                DN             = "N/A"
                Domain         = $script:TargetDomain
                Server         = $script:TargetServer
                ObjectType     = "User"
            }
            [void]$script:ProcessedUsers.Add($userObj)
            Write-Log "NOT FOUND: $sam - User does not exist in $($script:TargetDomain)" "WARNING"
        }
    }

    $script:txtLog.ResumeLayout()
    Update-UserDataGridView

    $script:lblStatus.Text = "User lookup complete on $($script:TargetServer). Found: $found | Not Found: $notFound"
    Write-Log "USER LOOKUP COMPLETE - Found: $found | Not Found: $notFound" "INFO"
    Write-Log "========================================" "INFO"

    $script:btnDisableUsers.Enabled = $true
    $script:btnEnableUsers.Enabled  = $true
    $script:btnDeleteUsers.Enabled  = $true
}

function Invoke-DisableUsers {
    if (-not $script:TargetServer) {
        [System.Windows.Forms.MessageBox]::Show("No target server set. Run a Lookup first.", "No Server", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $validUsers = $script:ProcessedUsers | Where-Object { $_.Result -ne "Not Found" -and $_.Status -eq "Enabled" }

    if ($validUsers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No enabled users to disable. Lookup users first or check that users are currently enabled.", "No Users", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $userLines = $validUsers | ForEach-Object { "$($_.SamAccountName)  ($($_.DisplayName))" }
    $confirm = Show-ScrollableConfirmation `
        -Title "Confirm Disable" `
        -SummaryText "You are about to DISABLE $($validUsers.Count) user(s) on $($script:TargetServer).`nAre you sure?" `
        -UserLines $userLines `
        -Icon ([System.Windows.Forms.MessageBoxIcon]::Warning)

    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log "Disable operation cancelled by user." "INFO"
        return
    }

    Write-Log "========================================" "INFO"
    Write-Log "DISABLE OPERATION STARTED | Target: $($script:TargetServer)" "INFO"
    Write-Log "========================================" "INFO"

    $script:progressBar.Maximum = $validUsers.Count
    $script:progressBar.Value = 0
    $success = 0; $failed = 0; $counter = 0

    foreach ($u in $validUsers) {
        $counter++
        $script:progressBar.Value = [Math]::Min($script:progressBar.Value + 1, $script:progressBar.Maximum)
        if ($counter % 10 -eq 0 -or $counter -eq $validUsers.Count) {
            $script:lblStatus.Text = "Disabling: $counter / $($validUsers.Count) on $($script:TargetServer)"
            [System.Windows.Forms.Application]::DoEvents()
        }
        try {
            $identity = if ($u.DN -and $u.DN -ne 'N/A') { $u.DN } else { $u.SamAccountName }
            $params = @{ Identity = $identity; ErrorAction = 'Stop' }
            if ($script:TargetServer) { $params['Server'] = $script:TargetServer }
            Disable-ADAccount @params
            $u.Action = "Disabled"; $u.Result = "Success"; $u.Status = "Disabled"; $u.Timestamp = Get-Timestamp
            $success++
            Write-Log "DISABLED: $($u.SamAccountName) (DN: $identity) | OU: $($u.OU)" "SUCCESS"
        } catch {
            $u.Action = "Disable Attempted"; $u.Result = "Failed"; $u.Timestamp = Get-Timestamp
            $failed++
            Write-Log "FAILED TO DISABLE: $($u.SamAccountName) | Error: $($_.Exception.Message)" "ERROR"
        }
    }

    Update-UserDataGridView
    $script:lblStatus.Text = "Disable complete. Success: $success | Failed: $failed"
    Write-Log "DISABLE COMPLETE - Success: $success | Failed: $failed" "INFO"
    Write-Log "========================================" "INFO"
}

function Invoke-EnableUsers {
    if (-not $script:TargetServer) {
        [System.Windows.Forms.MessageBox]::Show("No target server set. Run a Lookup first.", "No Server", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $validUsers = $script:ProcessedUsers | Where-Object { $_.Result -ne "Not Found" -and $_.Status -eq "Disabled" }

    if ($validUsers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No disabled users to enable. Lookup users first or check that users are currently disabled.", "No Users", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $userLines = $validUsers | ForEach-Object { "$($_.SamAccountName)  ($($_.DisplayName))" }
    $confirm = Show-ScrollableConfirmation `
        -Title "Confirm Enable" `
        -SummaryText "You are about to ENABLE $($validUsers.Count) user(s) on $($script:TargetServer).`nAre you sure?" `
        -UserLines $userLines `
        -Icon ([System.Windows.Forms.MessageBoxIcon]::Question)

    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log "Enable operation cancelled by user." "INFO"
        return
    }

    Write-Log "========================================" "INFO"
    Write-Log "ENABLE OPERATION STARTED | Target: $($script:TargetServer)" "INFO"
    Write-Log "========================================" "INFO"

    $script:progressBar.Maximum = $validUsers.Count
    $script:progressBar.Value = 0
    $success = 0; $failed = 0; $counter = 0

    foreach ($u in $validUsers) {
        $counter++
        $script:progressBar.Value = [Math]::Min($script:progressBar.Value + 1, $script:progressBar.Maximum)
        if ($counter % 10 -eq 0 -or $counter -eq $validUsers.Count) {
            $script:lblStatus.Text = "Enabling: $counter / $($validUsers.Count) on $($script:TargetServer)"
            [System.Windows.Forms.Application]::DoEvents()
        }
        try {
            $identity = if ($u.DN -and $u.DN -ne 'N/A') { $u.DN } else { $u.SamAccountName }
            $params = @{ Identity = $identity; ErrorAction = 'Stop' }
            if ($script:TargetServer) { $params['Server'] = $script:TargetServer }
            Enable-ADAccount @params
            $u.Action = "Enabled"; $u.Result = "Success"; $u.Status = "Enabled"; $u.Timestamp = Get-Timestamp
            $success++
            Write-Log "ENABLED: $($u.SamAccountName) (DN: $identity) | OU: $($u.OU)" "SUCCESS"
        } catch {
            $u.Action = "Enable Attempted"; $u.Result = "Failed"; $u.Timestamp = Get-Timestamp
            $failed++
            Write-Log "FAILED TO ENABLE: $($u.SamAccountName) | Error: $($_.Exception.Message)" "ERROR"
        }
    }

    Update-UserDataGridView
    $script:lblStatus.Text = "Enable complete. Success: $success | Failed: $failed"
    Write-Log "ENABLE COMPLETE - Success: $success | Failed: $failed" "INFO"
    Write-Log "========================================" "INFO"
}

function Invoke-DeleteUsers {
    if (-not $script:TargetServer) {
        [System.Windows.Forms.MessageBox]::Show("No target server set. Run a Lookup first.", "No Server", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $validUsers = $script:ProcessedUsers | Where-Object { $_.Result -ne "Not Found" }

    if ($validUsers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No users to delete. Lookup users first.", "No Users", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $userLines = $validUsers | ForEach-Object { "$($_.SamAccountName)  ($($_.DisplayName))  [$($_.Status)]" }

    $confirm1 = Show-ScrollableConfirmation `
        -Title "CONFIRM DELETE - Step 1 of 2" `
        -SummaryText "WARNING: PERMANENTLY DELETE $($validUsers.Count) user(s) on $($script:TargetServer)?`nDomain: $($script:TargetDomain)  |  This CANNOT be undone." `
        -UserLines $userLines `
        -Icon ([System.Windows.Forms.MessageBoxIcon]::Exclamation)

    if ($confirm1 -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log "Delete operation cancelled by user at first confirmation." "INFO"
        return
    }

    $confirm2 = [System.Windows.Forms.MessageBox]::Show(
        "FINAL WARNING!`n`nYou are about to permanently remove $($validUsers.Count) user account(s) from:`n`nDomain: $($script:TargetDomain)`nServer: $($script:TargetServer)`n`nClick Yes ONLY if you are certain.",
        "CONFIRM DELETE - Step 2 of 2",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Stop
    )

    if ($confirm2 -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log "Delete operation cancelled by user at final confirmation." "INFO"
        return
    }

    Write-Log "========================================" "INFO"
    Write-Log "USER DELETE OPERATION STARTED" "INFO"
    Write-Log "Target Domain : $($script:TargetDomain)" "INFO"
    Write-Log "Target Server : $($script:TargetServer) (PDC Emulator)" "INFO"
    Write-Log "Operator confirmed deletion of $($validUsers.Count) user(s)" "INFO"
    Write-Log "========================================" "INFO"

    $script:progressBar.Maximum = $validUsers.Count
    $script:progressBar.Value = 0
    $success = 0; $failed = 0; $counter = 0

    foreach ($u in $validUsers) {
        $counter++
        $script:progressBar.Value = [Math]::Min($script:progressBar.Value + 1, $script:progressBar.Maximum)
        if ($counter % 5 -eq 0 -or $counter -eq $validUsers.Count) {
            $script:lblStatus.Text = "Deleting user: $counter / $($validUsers.Count) on $($script:TargetServer)"
            [System.Windows.Forms.Application]::DoEvents()
        }

        Write-Log "PRE-DELETE SNAPSHOT for $($u.SamAccountName):" "INFO"
        Write-Log "  Display Name : $($u.DisplayName)" "INFO"
        Write-Log "  Status       : $($u.Status)" "INFO"
        Write-Log "  OU Path      : $($u.OU)" "INFO"
        Write-Log "  Full DN      : $($u.DN)" "INFO"
        Write-Log "  Description  : $($u.Description)" "INFO"
        Write-Log "  Email        : $($u.Email)" "INFO"
        Write-Log "  Title        : $($u.Title)" "INFO"
        Write-Log "  Department   : $($u.Department)" "INFO"
        Write-Log "  Created      : $($u.WhenCreated)" "INFO"
        Write-Log "  Last Logon   : $($u.LastLogon)" "INFO"

        try {
            $identity = if ($u.DN -and $u.DN -ne 'N/A') { $u.DN } else { $u.SamAccountName }
            $childrenRemoved = 0
            if ($u.DN -and $u.DN -ne 'N/A') {
                $childrenRemoved = Remove-ChildADObjects -ObjectDN $u.DN -ObjectName $u.SamAccountName
                if ($childrenRemoved -gt 0) {
                    Write-Log "  Removed $childrenRemoved child object(s) for $($u.SamAccountName)" "INFO"
                }
            }
            $params = @{ Identity = $identity; Confirm = $false; ErrorAction = 'Stop' }
            if ($script:TargetServer) { $params['Server'] = $script:TargetServer }
            Remove-ADObject @params
            $u.Action = "Deleted"; $u.Result = "Success"; $u.Timestamp = Get-Timestamp
            $success++
            $childNote = if ($childrenRemoved -gt 0) { " ($childrenRemoved child objects also removed)" } else { "" }
            Write-Log "DELETED USER: $($u.SamAccountName) from $($script:TargetServer)$childNote" "SUCCESS"
        } catch {
            $u.Action = "Delete Attempted"; $u.Result = "Failed"; $u.Timestamp = Get-Timestamp
            $failed++
            Write-Log "FAILED TO DELETE USER: $($u.SamAccountName) | Error: $($_.Exception.Message)" "ERROR"
        }
    }

    Update-UserDataGridView
    $script:lblStatus.Text = "User delete complete. Success: $success | Failed: $failed"
    Write-Log "USER DELETE COMPLETE - Success: $success | Failed: $failed" "INFO"
    Write-Log "========================================" "INFO"
}

# ============================================================
# COMPUTER ACTION FUNCTIONS
# ============================================================
function Import-ComputerCSV {
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $openDialog.Title  = "Import Computer Names from CSV"

    if ($openDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    try {
        $csv = Import-Csv -Path $openDialog.FileName -ErrorAction Stop
    } catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to read CSV file:`n$($_.Exception.Message)",
            "CSV Import Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }

    if ($csv.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "The CSV file is empty or has no data rows.",
            "Empty CSV",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    $headers = $csv[0].PSObject.Properties.Name
    $nameCol  = $headers | Where-Object { $_ -match '^(computername|name|computer|hostname)$' } | Select-Object -First 1

    if (-not $nameCol) {
        $nameCol = $headers[0]
        Write-Log "CSV: No recognised header found. Using first column '$nameCol' as computer name source." "WARNING"
        [System.Windows.Forms.MessageBox]::Show(
            "No column named 'ComputerName', 'Name', 'Computer', or 'Hostname' was found.`n`nUsing the first column '$nameCol' instead.`n`nSupported headers: ComputerName, Name, Computer, Hostname",
            "CSV Column Auto-Selected",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }

    $importedNames = $csv | ForEach-Object { $_.$nameCol.Trim() } | Where-Object { $_ -ne '' } | Sort-Object -Unique

    if ($importedNames.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No computer names found in column '$nameCol'.",
            "No Data",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    $existingNames = Parse-NameList -RawText $script:txtComputerInput.Text
    $combined = ($existingNames + $importedNames) | Sort-Object -Unique
    $script:txtComputerInput.Text = ($combined -join "`r`n")

    Write-Log "CSV IMPORT: Loaded $($importedNames.Count) computer name(s) from '$($openDialog.FileName)' (column: $nameCol). Total in list: $($combined.Count)" "INFO"
    [System.Windows.Forms.MessageBox]::Show(
        "Successfully imported $($importedNames.Count) computer name(s) from:`n$($openDialog.FileName)`n`nColumn used: $nameCol`nTotal unique names in list: $($combined.Count)",
        "CSV Import Complete",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
}

function Lookup-Computers {
    if (-not (Resolve-TargetDomain)) { return }

    $script:ProcessedComputers.Clear()
    $script:dgvComputers.Rows.Clear()
    $rawText = $script:txtComputerInput.Text
    $computerNames = Parse-NameList -RawText $rawText

    $computerNames = $computerNames | ForEach-Object { $_.TrimEnd('$') } | Where-Object { $_ -ne '' }

    if ($computerNames.Count -eq 0) {
        Write-Log "No computer names provided." "WARNING"
        [System.Windows.Forms.MessageBox]::Show(
            "No computer names found. Please paste computer names into the input box or import a CSV.",
            "No Input",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    Write-Log "========================================" "INFO"
    Write-Log "COMPUTER LOOKUP STARTED - Processing $($computerNames.Count) name(s)" "INFO"
    Write-Log "Target Domain : $($script:TargetDomain)" "INFO"
    Write-Log "Target Server : $($script:TargetServer) (PDC Emulator)" "INFO"
    Write-Log "========================================" "INFO"

    $script:progressBar.Maximum = $computerNames.Count
    $script:progressBar.Value   = 0
    $script:lblStatus.Text = "Querying $($computerNames.Count) computers via batch LDAP against $($script:TargetServer)..."
    [System.Windows.Forms.Application]::DoEvents()

    $script:txtLog.SuspendLayout()
    $adComputersMap = Get-ADComputersBatch -ComputerNames $computerNames
    Write-Log "Batch LDAP query returned $($adComputersMap.Count) computer(s) from $($script:TargetServer)" "INFO"

    $found = 0; $notFound = 0

    foreach ($cname in $computerNames) {
        $script:progressBar.Value = [Math]::Min($script:progressBar.Value + 1, $script:progressBar.Maximum)
        if ($script:progressBar.Value % 10 -eq 0 -or $script:progressBar.Value -eq $script:progressBar.Maximum) {
            $script:lblStatus.Text = "Processing: $($script:progressBar.Value) / $($computerNames.Count)"
            [System.Windows.Forms.Application]::DoEvents()
        }

        $adComp = $adComputersMap[$cname.ToLower()]

        if ($adComp) {
            $found++
            $ou     = Get-OUFromDN -DistinguishedName $adComp.DistinguishedName
            $desc   = if ($adComp.Description)      { $adComp.Description }      else { "(none)" }
            $status = if ($adComp.Enabled)           { "Enabled" }                else { "Disabled" }
            $dns    = if ($adComp.DNSHostName)       { $adComp.DNSHostName }      else { "N/A" }
            $os     = if ($adComp.OperatingSystem)   { $adComp.OperatingSystem }  else { "N/A" }

            $compObj = [PSCustomObject]@{
                Name             = $adComp.Name
                SamAccountName   = $adComp.SamAccountName
                DNSHostName      = $dns
                OperatingSystem  = $os
                OSVersion        = $adComp.OperatingSystemVersion
                Status           = $status
                OU               = $ou
                Description      = $desc
                Action           = "Pending"
                Result           = "Looked Up"
                Timestamp        = Get-Timestamp
                WhenCreated      = $adComp.WhenCreated
                LastLogon        = $adComp.LastLogonDate
                DN               = $adComp.DistinguishedName
                Domain           = $script:TargetDomain
                Server           = $script:TargetServer
                ObjectType       = "Computer"
            }
            [void]$script:ProcessedComputers.Add($compObj)
            Write-Log "FOUND: $($adComp.Name) | OS: $os | Status: $status | OU: $ou | DNS: $dns" "INFO"
        } else {
            $notFound++
            $compObj = [PSCustomObject]@{
                Name            = $cname
                SamAccountName  = "N/A"
                DNSHostName     = "N/A"
                OperatingSystem = "N/A"
                OSVersion       = "N/A"
                Status          = "N/A"
                OU              = "N/A"
                Description     = "N/A"
                Action          = "N/A"
                Result          = "Not Found"
                Timestamp       = Get-Timestamp
                WhenCreated     = "N/A"
                LastLogon       = "N/A"
                DN              = "N/A"
                Domain          = $script:TargetDomain
                Server          = $script:TargetServer
                ObjectType      = "Computer"
            }
            [void]$script:ProcessedComputers.Add($compObj)
            Write-Log "NOT FOUND: $cname - Computer does not exist in $($script:TargetDomain)" "WARNING"
        }
    }

    $script:txtLog.ResumeLayout()
    Update-ComputerDataGridView

    $script:lblStatus.Text = "Computer lookup complete on $($script:TargetServer). Found: $found | Not Found: $notFound"
    Write-Log "COMPUTER LOOKUP COMPLETE - Found: $found | Not Found: $notFound" "INFO"
    Write-Log "========================================" "INFO"

    $script:btnDisableComputers.Enabled = $true
    $script:btnEnableComputers.Enabled  = $true
    $script:btnDeleteComputers.Enabled  = $true
}

function Invoke-DisableComputers {
    if (-not $script:TargetServer) {
        [System.Windows.Forms.MessageBox]::Show("No target server set. Run a Lookup first.", "No Server", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $validComputers = $script:ProcessedComputers | Where-Object { $_.Result -ne "Not Found" -and $_.Status -eq "Enabled" }

    if ($validComputers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No enabled computers to disable. Lookup computers first or check that computers are currently enabled.", "No Computers", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $compLines = $validComputers | ForEach-Object { "$($_.Name)  [$($_.OperatingSystem)]" }
    $confirm = Show-ScrollableConfirmation `
        -Title "Confirm Disable Computers" `
        -SummaryText "You are about to DISABLE $($validComputers.Count) computer(s) on $($script:TargetServer).`nAre you sure?" `
        -UserLines $compLines `
        -Icon ([System.Windows.Forms.MessageBoxIcon]::Warning)

    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log "Computer disable operation cancelled by user." "INFO"
        return
    }

    Write-Log "========================================" "INFO"
    Write-Log "COMPUTER DISABLE OPERATION STARTED | Target: $($script:TargetServer)" "INFO"
    Write-Log "========================================" "INFO"

    $script:progressBar.Maximum = $validComputers.Count
    $script:progressBar.Value = 0
    $success = 0; $failed = 0; $counter = 0

    foreach ($c in $validComputers) {
        $counter++
        $script:progressBar.Value = [Math]::Min($script:progressBar.Value + 1, $script:progressBar.Maximum)
        if ($counter % 10 -eq 0 -or $counter -eq $validComputers.Count) {
            $script:lblStatus.Text = "Disabling computer: $counter / $($validComputers.Count) on $($script:TargetServer)"
            [System.Windows.Forms.Application]::DoEvents()
        }
        try {
            $identity = if ($c.DN -and $c.DN -ne 'N/A') { $c.DN } else { $c.Name }
            $params = @{ Identity = $identity; ErrorAction = 'Stop' }
            if ($script:TargetServer) { $params['Server'] = $script:TargetServer }
            
            Set-ADComputer @params -Enabled $false
            
            $c.Action = "Disabled"; $c.Result = "Success"; $c.Status = "Disabled"; $c.Timestamp = Get-Timestamp
            $success++
            Write-Log "DISABLED COMPUTER: $($c.Name) (DN: $identity) | OU: $($c.OU)" "SUCCESS"
        } catch {
            $c.Action = "Disable Attempted"; $c.Result = "Failed"; $c.Timestamp = Get-Timestamp
            $failed++
            Write-Log "FAILED TO DISABLE COMPUTER: $($c.Name) | Error: $($_.Exception.Message)" "ERROR"
        }
    }

    Update-ComputerDataGridView
    $script:lblStatus.Text = "Computer disable complete. Success: $success | Failed: $failed"
    Write-Log "COMPUTER DISABLE COMPLETE - Success: $success | Failed: $failed" "INFO"
    Write-Log "========================================" "INFO"
}

function Invoke-EnableComputers {
    if (-not $script:TargetServer) {
        [System.Windows.Forms.MessageBox]::Show("No target server set. Run a Lookup first.", "No Server", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $validComputers = $script:ProcessedComputers | Where-Object { $_.Result -ne "Not Found" -and $_.Status -eq "Disabled" }

    if ($validComputers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No disabled computers to enable. Lookup computers first or check that computers are currently disabled.", "No Computers", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $compLines = $validComputers | ForEach-Object { "$($_.Name)  [$($_.OperatingSystem)]" }
    $confirm = Show-ScrollableConfirmation `
        -Title "Confirm Enable Computers" `
        -SummaryText "You are about to ENABLE $($validComputers.Count) computer(s) on $($script:TargetServer).`nAre you sure?" `
        -UserLines $compLines `
        -Icon ([System.Windows.Forms.MessageBoxIcon]::Question)

    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log "Computer enable operation cancelled by user." "INFO"
        return
    }

    Write-Log "========================================" "INFO"
    Write-Log "COMPUTER ENABLE OPERATION STARTED | Target: $($script:TargetServer)" "INFO"
    Write-Log "========================================" "INFO"

    $script:progressBar.Maximum = $validComputers.Count
    $script:progressBar.Value = 0
    $success = 0; $failed = 0; $counter = 0

    foreach ($c in $validComputers) {
        $counter++
        $script:progressBar.Value = [Math]::Min($script:progressBar.Value + 1, $script:progressBar.Maximum)
        if ($counter % 10 -eq 0 -or $counter -eq $validComputers.Count) {
            $script:lblStatus.Text = "Enabling computer: $counter / $($validComputers.Count) on $($script:TargetServer)"
            [System.Windows.Forms.Application]::DoEvents()
        }
        try {
            $identity = if ($c.DN -and $c.DN -ne 'N/A') { $c.DN } else { $c.Name }
            $params = @{ Identity = $identity; ErrorAction = 'Stop' }
            if ($script:TargetServer) { $params['Server'] = $script:TargetServer }
            
            Set-ADComputer @params -Enabled $true
            
            $c.Action = "Enabled"; $c.Result = "Success"; $c.Status = "Enabled"; $c.Timestamp = Get-Timestamp
            $success++
            Write-Log "ENABLED COMPUTER: $($c.Name) (DN: $identity) | OU: $($c.OU)" "SUCCESS"
        } catch {
            $c.Action = "Enable Attempted"; $c.Result = "Failed"; $c.Timestamp = Get-Timestamp
            $failed++
            Write-Log "FAILED TO ENABLE COMPUTER: $($c.Name) | Error: $($_.Exception.Message)" "ERROR"
        }
    }

    Update-ComputerDataGridView
    $script:lblStatus.Text = "Computer enable complete. Success: $success | Failed: $failed"
    Write-Log "COMPUTER ENABLE COMPLETE - Success: $success | Failed: $failed" "INFO"
    Write-Log "========================================" "INFO"
}

function Invoke-DeleteComputers {
    if (-not $script:TargetServer) {
        [System.Windows.Forms.MessageBox]::Show("No target server set. Run a Lookup first.", "No Server", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $validComps = $script:ProcessedComputers | Where-Object { $_.Result -ne "Not Found" }

    if ($validComps.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No computers to delete. Lookup computers first.", "No Computers", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $compLines = $validComps | ForEach-Object { "$($_.Name)  [$($_.OperatingSystem)]  [$($_.Status)]  OU: $($_.OU)" }

    $confirm1 = Show-ScrollableConfirmation `
        -Title "CONFIRM COMPUTER DELETE - Step 1 of 2" `
        -SummaryText "WARNING: PERMANENTLY DELETE $($validComps.Count) computer object(s) on $($script:TargetServer)?`nDomain: $($script:TargetDomain)  |  This CANNOT be undone." `
        -UserLines $compLines `
        -Icon ([System.Windows.Forms.MessageBoxIcon]::Exclamation)

    if ($confirm1 -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log "Computer delete operation cancelled by user at first confirmation." "INFO"
        return
    }

    $confirm2 = [System.Windows.Forms.MessageBox]::Show(
        "FINAL WARNING!`n`nYou are about to permanently remove $($validComps.Count) computer object(s) from:`n`nDomain: $($script:TargetDomain)`nServer: $($script:TargetServer)`n`nClick Yes ONLY if you are certain. Click No to cancel.",
        "CONFIRM COMPUTER DELETE - Step 2 of 2",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Stop
    )

    if ($confirm2 -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log "Computer delete operation cancelled by user at final confirmation." "INFO"
        return
    }

    Write-Log "========================================" "INFO"
    Write-Log "COMPUTER DELETE OPERATION STARTED" "INFO"
    Write-Log "Target Domain : $($script:TargetDomain)" "INFO"
    Write-Log "Target Server : $($script:TargetServer) (PDC Emulator)" "INFO"
    Write-Log "Operator confirmed deletion of $($validComps.Count) computer(s)" "INFO"
    Write-Log "========================================" "INFO"

    $script:progressBar.Maximum = $validComps.Count
    $script:progressBar.Value   = 0
    $success = 0; $failed = 0; $counter = 0

    foreach ($c in $validComps) {
        $counter++
        $script:progressBar.Value = [Math]::Min($script:progressBar.Value + 1, $script:progressBar.Maximum)
        if ($counter % 5 -eq 0 -or $counter -eq $validComps.Count) {
            $script:lblStatus.Text = "Deleting computer: $counter / $($validComps.Count) on $($script:TargetServer)"
            [System.Windows.Forms.Application]::DoEvents()
        }

        Write-Log "PRE-DELETE SNAPSHOT for computer $($c.Name):" "INFO"
        Write-Log "  Computer Name    : $($c.Name)" "INFO"
        Write-Log "  SAMAccountName   : $($c.SamAccountName)" "INFO"
        Write-Log "  DNS Host Name    : $($c.DNSHostName)" "INFO"
        Write-Log "  Operating System : $($c.OperatingSystem) $($c.OSVersion)" "INFO"
        Write-Log "  Status           : $($c.Status)" "INFO"
        Write-Log "  OU Path          : $($c.OU)" "INFO"
        Write-Log "  Full DN          : $($c.DN)" "INFO"
        Write-Log "  Description      : $($c.Description)" "INFO"
        Write-Log "  Created          : $($c.WhenCreated)" "INFO"
        Write-Log "  Last Logon       : $($c.LastLogon)" "INFO"
        Write-Log "  Domain           : $($c.Domain)" "INFO"
        Write-Log "  Server           : $($c.Server)" "INFO"

        try {
            $identity = if ($c.DN -and $c.DN -ne 'N/A') { $c.DN } else { $c.Name }
            $childrenRemoved = 0

            if ($c.DN -and $c.DN -ne 'N/A') {
                $childrenRemoved = Remove-ChildADObjects -ObjectDN $c.DN -ObjectName $c.Name
                if ($childrenRemoved -gt 0) {
                    Write-Log "  Removed $childrenRemoved child object(s) under $($c.Name) before deletion" "INFO"
                }
            }

            $params = @{ Identity = $identity; Confirm = $false; ErrorAction = 'Stop' }
            if ($script:TargetServer) { $params['Server'] = $script:TargetServer }
            Remove-ADObject @params
            $c.Action = "Deleted"; $c.Result = "Success"; $c.Timestamp = Get-Timestamp
            $success++
            $childNote = if ($childrenRemoved -gt 0) { " ($childrenRemoved child objects also removed)" } else { "" }
            Write-Log "DELETED COMPUTER: $($c.Name) (DN: $identity) from $($script:TargetServer)$childNote" "SUCCESS"
        } catch {
            $c.Action = "Delete Attempted"; $c.Result = "Failed"; $c.Timestamp = Get-Timestamp
            $failed++
            Write-Log "FAILED TO DELETE COMPUTER: $($c.Name) (DN: $identity) | Error: $($_.Exception.Message)" "ERROR"
        }
    }

    Update-ComputerDataGridView
    $script:lblStatus.Text = "Computer delete complete on $($script:TargetServer). Success: $success | Failed: $failed"
    Write-Log "COMPUTER DELETE COMPLETE - Success: $success | Failed: $failed" "INFO"
    Write-Log "========================================" "INFO"
}

# ============================================================
# BUILD THE GUI
# ============================================================

$form = New-Object System.Windows.Forms.Form
$form.Text = "Active Directory Object Manager v$($script:AppVersion) - Users & Computers"
$form.Size = New-Object System.Drawing.Size(1400, 1050)
$form.StartPosition = "CenterScreen"
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)
$form.MinimumSize = New-Object System.Drawing.Size(1100, 800)
$form.Icon = [System.Drawing.SystemIcons]::Shield

# --- Header Panel ---
$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Dock = [System.Windows.Forms.DockStyle]::Top
$headerPanel.Height = 60
$headerPanel.BackColor = [System.Drawing.Color]::FromArgb(24, 42, 68)

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "Active Directory Object Manager"
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = [System.Drawing.Color]::White
$lblTitle.AutoSize = $true
$lblTitle.Location = New-Object System.Drawing.Point(20, 15)
$headerPanel.Controls.Add($lblTitle)

$lblVersion = New-Object System.Windows.Forms.Label
$lblVersion.Text = "v$($script:AppVersion) | Users + Computers | PowerShell 5.1+ | $(whoami)"
$lblVersion.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblVersion.ForeColor = [System.Drawing.Color]::FromArgb(160, 185, 215)
$lblVersion.AutoSize = $true
$lblVersion.Location = New-Object System.Drawing.Point(440, 22)
$headerPanel.Controls.Add($lblVersion)

# --- Domain Targeting Panel ---
$domainPanel = New-Object System.Windows.Forms.Panel
$domainPanel.Dock = [System.Windows.Forms.DockStyle]::Top
$domainPanel.Height = 90
$domainPanel.BackColor = [System.Drawing.Color]::FromArgb(32, 52, 80)
$domainPanel.Padding = New-Object System.Windows.Forms.Padding(20, 10, 20, 10)

$lblDomainLabel = New-Object System.Windows.Forms.Label
$lblDomainLabel.Text = "Target Domain FQDN:"
$lblDomainLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblDomainLabel.ForeColor = [System.Drawing.Color]::White
$lblDomainLabel.AutoSize = $true
$lblDomainLabel.Location = New-Object System.Drawing.Point(20, 12)
$domainPanel.Controls.Add($lblDomainLabel)

$script:txtDomain = New-Object System.Windows.Forms.TextBox
$script:txtDomain.Font = New-Object System.Drawing.Font("Consolas", 11)
$script:txtDomain.Location = New-Object System.Drawing.Point(180, 8)
$script:txtDomain.Size = New-Object System.Drawing.Size(380, 28)
$script:txtDomain.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 22)
$script:txtDomain.ForeColor = [System.Drawing.Color]::FromArgb(0, 210, 106)
$script:txtDomain.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

try {
    $currentDomainDefault = (Get-ADDomain -ErrorAction SilentlyContinue).DNSRoot
    if ($currentDomainDefault) { $script:txtDomain.Text = $currentDomainDefault }
} catch { }

$domainPanel.Controls.Add($script:txtDomain)

$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Text = "Connect & Discover PDC"
$btnConnect.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnConnect.Size = New-Object System.Drawing.Size(180, 28)
$btnConnect.Location = New-Object System.Drawing.Point(575, 8)
$btnConnect.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnConnect.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnConnect.ForeColor = [System.Drawing.Color]::White
$btnConnect.FlatAppearance.BorderSize = 0
$btnConnect.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnConnect.Add_Click({ Resolve-TargetDomain })
$domainPanel.Controls.Add($btnConnect)

$lblHintDomain = New-Object System.Windows.Forms.Label
$lblHintDomain.Text = "(Leave blank to auto-detect current domain)"
$lblHintDomain.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$lblHintDomain.ForeColor = [System.Drawing.Color]::FromArgb(130, 150, 175)
$lblHintDomain.AutoSize = $true
$lblHintDomain.Location = New-Object System.Drawing.Point(770, 14)
$domainPanel.Controls.Add($lblHintDomain)

$script:lblDomainStatus = New-Object System.Windows.Forms.Label
$script:lblDomainStatus.Text = "Domain: Not connected"
$script:lblDomainStatus.Font = New-Object System.Drawing.Font("Consolas", 9)
$script:lblDomainStatus.ForeColor = [System.Drawing.Color]::FromArgb(180, 180, 180)
$script:lblDomainStatus.AutoSize = $true
$script:lblDomainStatus.Location = New-Object System.Drawing.Point(20, 50)
$domainPanel.Controls.Add($script:lblDomainStatus)

$script:lblPDCStatus = New-Object System.Windows.Forms.Label
$script:lblPDCStatus.Text = "PDC Emulator: Not resolved"
$script:lblPDCStatus.Font = New-Object System.Drawing.Font("Consolas", 9)
$script:lblPDCStatus.ForeColor = [System.Drawing.Color]::FromArgb(180, 180, 180)
$script:lblPDCStatus.AutoSize = $true
$script:lblPDCStatus.Location = New-Object System.Drawing.Point(400, 50)
$domainPanel.Controls.Add($script:lblPDCStatus)

# ============================================================
# MAIN SPLIT: top content / bottom log
# ============================================================
$splitMain = New-Object System.Windows.Forms.SplitContainer
$splitMain.Dock = [System.Windows.Forms.DockStyle]::Fill
$splitMain.Orientation = [System.Windows.Forms.Orientation]::Horizontal
$splitMain.SplitterDistance = 560
$splitMain.SplitterWidth = 6
$splitMain.BackColor = [System.Drawing.Color]::FromArgb(220, 225, 232)
$splitMain.Panel1.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)
$splitMain.Panel2.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)

# ============================================================
# TAB CONTROL  (Users tab / Computers tab)
# ============================================================
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = [System.Windows.Forms.DockStyle]::Fill
$tabControl.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$tabControl.Padding = New-Object System.Drawing.Point(12, 6)

$tabUsers     = New-Object System.Windows.Forms.TabPage
$tabUsers.Text = "  User Objects  "
$tabUsers.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)

$tabComputers = New-Object System.Windows.Forms.TabPage
$tabComputers.Text = "  Computer Objects  "
$tabComputers.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)

$tabControl.TabPages.AddRange(@($tabUsers, $tabComputers))

# ============================================================
# USERS TAB LAYOUT
# ============================================================
$splitUsers = New-Object System.Windows.Forms.SplitContainer
$splitUsers.Dock = [System.Windows.Forms.DockStyle]::Fill
$splitUsers.SplitterDistance = 300
$splitUsers.SplitterWidth = 6
$splitUsers.BackColor = [System.Drawing.Color]::FromArgb(220, 225, 232)
$splitUsers.Panel1.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)
$splitUsers.Panel2.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)

# --- User Input group ---
$grpUserInput = New-Object System.Windows.Forms.GroupBox
$grpUserInput.Text = " Paste SAMAccountNames Below or Import CSV "
$grpUserInput.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$grpUserInput.Dock = [System.Windows.Forms.DockStyle]::Fill
$grpUserInput.ForeColor = [System.Drawing.Color]::FromArgb(24, 42, 68)
$grpUserInput.Padding = New-Object System.Windows.Forms.Padding(10, 20, 10, 10)

$script:txtUserInput = New-Object System.Windows.Forms.TextBox
$script:txtUserInput.Multiline = $true
$script:txtUserInput.ScrollBars = "Vertical"
$script:txtUserInput.Font = New-Object System.Drawing.Font("Consolas", 10)
$script:txtUserInput.Dock = [System.Windows.Forms.DockStyle]::Fill
$script:txtUserInput.AcceptsReturn = $true
$script:txtUserInput.WordWrap = $false
$script:txtUserInput.BackColor = [System.Drawing.Color]::White
$script:txtUserInput.ForeColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

$lblUserHint = New-Object System.Windows.Forms.Label
$lblUserHint.Text = "One SAMAccountName per line. Commas, semicolons, and spaces also accepted. CSV column: SamAccountName, Username, User, or LoginName."
$lblUserHint.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$lblUserHint.ForeColor = [System.Drawing.Color]::FromArgb(120, 130, 140)
$lblUserHint.Dock = [System.Windows.Forms.DockStyle]::Bottom
$lblUserHint.Height = 22

# User Button Panel
$userButtonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$userButtonPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
$userButtonPanel.Height = 120
$userButtonPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
$userButtonPanel.WrapContents = $true
$userButtonPanel.Padding = New-Object System.Windows.Forms.Padding(0, 5, 0, 5)

$btnImportUserCSV = New-Object System.Windows.Forms.Button
$btnImportUserCSV.Text = "Import CSV"
$btnImportUserCSV.Size = New-Object System.Drawing.Size(180, 36)
$btnImportUserCSV.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnImportUserCSV.BackColor = [System.Drawing.Color]::FromArgb(0, 150, 136)
$btnImportUserCSV.ForeColor = [System.Drawing.Color]::White
$btnImportUserCSV.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnImportUserCSV.FlatAppearance.BorderSize = 0
$btnImportUserCSV.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnImportUserCSV.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$btnImportUserCSV.Add_Click({ Import-UserCSV })

$btnLookupUsers = New-Object System.Windows.Forms.Button
$btnLookupUsers.Text = "Lookup Users"
$btnLookupUsers.Size = New-Object System.Drawing.Size(200, 36)
$btnLookupUsers.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnLookupUsers.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnLookupUsers.ForeColor = [System.Drawing.Color]::White
$btnLookupUsers.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnLookupUsers.FlatAppearance.BorderSize = 0
$btnLookupUsers.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnLookupUsers.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$btnLookupUsers.Add_Click({ Lookup-Users })

$script:btnDisableUsers = New-Object System.Windows.Forms.Button
$script:btnDisableUsers.Text = "Disable Users"
$script:btnDisableUsers.Size = New-Object System.Drawing.Size(200, 36)
$script:btnDisableUsers.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$script:btnDisableUsers.BackColor = [System.Drawing.Color]::FromArgb(202, 131, 0)
$script:btnDisableUsers.ForeColor = [System.Drawing.Color]::White
$script:btnDisableUsers.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:btnDisableUsers.FlatAppearance.BorderSize = 0
$script:btnDisableUsers.Cursor = [System.Windows.Forms.Cursors]::Hand
$script:btnDisableUsers.Enabled = $false
$script:btnDisableUsers.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$script:btnDisableUsers.Add_Click({ Invoke-DisableUsers })

$script:btnEnableUsers = New-Object System.Windows.Forms.Button
$script:btnEnableUsers.Text = "Enable Users"
$script:btnEnableUsers.Size = New-Object System.Drawing.Size(200, 36)
$script:btnEnableUsers.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$script:btnEnableUsers.BackColor = [System.Drawing.Color]::FromArgb(16, 137, 62)
$script:btnEnableUsers.ForeColor = [System.Drawing.Color]::White
$script:btnEnableUsers.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:btnEnableUsers.FlatAppearance.BorderSize = 0
$script:btnEnableUsers.Cursor = [System.Windows.Forms.Cursors]::Hand
$script:btnEnableUsers.Enabled = $false
$script:btnEnableUsers.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$script:btnEnableUsers.Add_Click({ Invoke-EnableUsers })

$script:btnDeleteUsers = New-Object System.Windows.Forms.Button
$script:btnDeleteUsers.Text = "DELETE Users"
$script:btnDeleteUsers.Size = New-Object System.Drawing.Size(200, 36)
$script:btnDeleteUsers.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$script:btnDeleteUsers.BackColor = [System.Drawing.Color]::FromArgb(196, 43, 28)
$script:btnDeleteUsers.ForeColor = [System.Drawing.Color]::White
$script:btnDeleteUsers.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:btnDeleteUsers.FlatAppearance.BorderSize = 0
$script:btnDeleteUsers.Cursor = [System.Windows.Forms.Cursors]::Hand
$script:btnDeleteUsers.Enabled = $false
$script:btnDeleteUsers.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$script:btnDeleteUsers.Add_Click({ Invoke-DeleteUsers })

$btnClearUsers = New-Object System.Windows.Forms.Button
$btnClearUsers.Text = "Clear All"
$btnClearUsers.Size = New-Object System.Drawing.Size(115, 36)
$btnClearUsers.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnClearUsers.BackColor = [System.Drawing.Color]::FromArgb(100, 110, 125)
$btnClearUsers.ForeColor = [System.Drawing.Color]::White
$btnClearUsers.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnClearUsers.FlatAppearance.BorderSize = 0
$btnClearUsers.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnClearUsers.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$btnClearUsers.Add_Click({
    $script:txtUserInput.Clear()
    $script:dgvUsers.Rows.Clear()
    $script:ProcessedUsers.Clear()
    $script:lblStatus.Text = "Ready"
    $script:progressBar.Value = 0
    $script:btnDisableUsers.Enabled = $false
    $script:btnEnableUsers.Enabled  = $false
    $script:btnDeleteUsers.Enabled  = $false
    Write-Log "User fields cleared." "INFO"
})

$btnExportUsers = New-Object System.Windows.Forms.Button
$btnExportUsers.Text = "Export Log"
$btnExportUsers.Size = New-Object System.Drawing.Size(115, 36)
$btnExportUsers.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnExportUsers.BackColor = [System.Drawing.Color]::FromArgb(55, 65, 81)
$btnExportUsers.ForeColor = [System.Drawing.Color]::White
$btnExportUsers.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnExportUsers.FlatAppearance.BorderSize = 0
$btnExportUsers.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnExportUsers.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$btnExportUsers.Add_Click({ Export-LogToFile })

$userButtonPanel.Controls.AddRange(@($btnImportUserCSV, $btnLookupUsers, $script:btnDisableUsers, $script:btnEnableUsers, $script:btnDeleteUsers, $btnClearUsers, $btnExportUsers))

$grpUserInput.Controls.Add($script:txtUserInput)
$grpUserInput.Controls.Add($lblUserHint)
$grpUserInput.Controls.Add($userButtonPanel)
$splitUsers.Panel1.Controls.Add($grpUserInput)

# --- User Results Grid ---
$grpUserResults = New-Object System.Windows.Forms.GroupBox
$grpUserResults.Text = " User Results "
$grpUserResults.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$grpUserResults.Dock = [System.Windows.Forms.DockStyle]::Fill
$grpUserResults.ForeColor = [System.Drawing.Color]::FromArgb(24, 42, 68)
$grpUserResults.Padding = New-Object System.Windows.Forms.Padding(10, 20, 10, 10)

$script:dgvUsers = New-Object System.Windows.Forms.DataGridView
$script:dgvUsers.Dock = [System.Windows.Forms.DockStyle]::Fill
$script:dgvUsers.AllowUserToAddRows = $false
$script:dgvUsers.AllowUserToDeleteRows = $false
$script:dgvUsers.ReadOnly = $true
$script:dgvUsers.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
$script:dgvUsers.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
$script:dgvUsers.BackgroundColor = [System.Drawing.Color]::White
$script:dgvUsers.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$script:dgvUsers.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(24, 42, 68)
$script:dgvUsers.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
$script:dgvUsers.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$script:dgvUsers.EnableHeadersVisualStyles = $false
$script:dgvUsers.ColumnHeadersHeight = 32
$script:dgvUsers.RowTemplate.Height = 26
$script:dgvUsers.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(248, 250, 252)
$script:dgvUsers.DefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$script:dgvUsers.GridColor = [System.Drawing.Color]::FromArgb(230, 233, 238)

[void]$script:dgvUsers.Columns.Add("SAM",         "SAMAccountName")
[void]$script:dgvUsers.Columns.Add("DisplayName",  "Display Name")
[void]$script:dgvUsers.Columns.Add("Status",       "Status")
[void]$script:dgvUsers.Columns.Add("OU",           "Organizational Unit")
[void]$script:dgvUsers.Columns.Add("Description",  "Description")
[void]$script:dgvUsers.Columns.Add("Action",       "Action")
[void]$script:dgvUsers.Columns.Add("Result",       "Result")
[void]$script:dgvUsers.Columns.Add("Timestamp",    "Timestamp")

$script:dgvUsers.Columns["SAM"].FillWeight         = 12
$script:dgvUsers.Columns["DisplayName"].FillWeight = 14
$script:dgvUsers.Columns["Status"].FillWeight      = 8
$script:dgvUsers.Columns["OU"].FillWeight          = 25
$script:dgvUsers.Columns["Description"].FillWeight = 18
$script:dgvUsers.Columns["Action"].FillWeight      = 8
$script:dgvUsers.Columns["Result"].FillWeight      = 8
$script:dgvUsers.Columns["Timestamp"].FillWeight   = 12

$grpUserResults.Controls.Add($script:dgvUsers)
$splitUsers.Panel2.Controls.Add($grpUserResults)
$tabUsers.Controls.Add($splitUsers)

# ============================================================
# COMPUTERS TAB LAYOUT
# ============================================================
$splitComputers = New-Object System.Windows.Forms.SplitContainer
$splitComputers.Dock = [System.Windows.Forms.DockStyle]::Fill
$splitComputers.SplitterDistance = 300
$splitComputers.SplitterWidth = 6
$splitComputers.BackColor = [System.Drawing.Color]::FromArgb(220, 225, 232)
$splitComputers.Panel1.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)
$splitComputers.Panel2.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)

# --- Computer Input group ---
$grpCompInput = New-Object System.Windows.Forms.GroupBox
$grpCompInput.Text = " Computer Names (one per line) or Import CSV "
$grpCompInput.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$grpCompInput.Dock = [System.Windows.Forms.DockStyle]::Fill
$grpCompInput.ForeColor = [System.Drawing.Color]::FromArgb(24, 42, 68)
$grpCompInput.Padding = New-Object System.Windows.Forms.Padding(10, 20, 10, 10)

$script:txtComputerInput = New-Object System.Windows.Forms.TextBox
$script:txtComputerInput.Multiline = $true
$script:txtComputerInput.ScrollBars = "Vertical"
$script:txtComputerInput.Font = New-Object System.Drawing.Font("Consolas", 10)
$script:txtComputerInput.Dock = [System.Windows.Forms.DockStyle]::Fill
$script:txtComputerInput.AcceptsReturn = $true
$script:txtComputerInput.WordWrap = $false
$script:txtComputerInput.BackColor = [System.Drawing.Color]::White
$script:txtComputerInput.ForeColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

$lblCompHint = New-Object System.Windows.Forms.Label
$lblCompHint.Text = "One computer name per line. Trailing `$` signs are stripped automatically. CSV column: ComputerName, Name, Computer, or Hostname."
$lblCompHint.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$lblCompHint.ForeColor = [System.Drawing.Color]::FromArgb(120, 130, 140)
$lblCompHint.Dock = [System.Windows.Forms.DockStyle]::Bottom
$lblCompHint.Height = 30

# Computer Button Panel
$compButtonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$compButtonPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
$compButtonPanel.Height = 120
$compButtonPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
$compButtonPanel.WrapContents = $true
$compButtonPanel.Padding = New-Object System.Windows.Forms.Padding(0, 5, 0, 5)

$btnImportCSV = New-Object System.Windows.Forms.Button
$btnImportCSV.Text = "Import CSV"
$btnImportCSV.Size = New-Object System.Drawing.Size(180, 36)
$btnImportCSV.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnImportCSV.BackColor = [System.Drawing.Color]::FromArgb(0, 150, 136)
$btnImportCSV.ForeColor = [System.Drawing.Color]::White
$btnImportCSV.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnImportCSV.FlatAppearance.BorderSize = 0
$btnImportCSV.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnImportCSV.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$btnImportCSV.Add_Click({ Import-ComputerCSV })

$btnLookupComputers = New-Object System.Windows.Forms.Button
$btnLookupComputers.Text = "Lookup Computers"
$btnLookupComputers.Size = New-Object System.Drawing.Size(220, 36)
$btnLookupComputers.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnLookupComputers.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnLookupComputers.ForeColor = [System.Drawing.Color]::White
$btnLookupComputers.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnLookupComputers.FlatAppearance.BorderSize = 0
$btnLookupComputers.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnLookupComputers.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$btnLookupComputers.Add_Click({ Lookup-Computers })

$script:btnDisableComputers = New-Object System.Windows.Forms.Button
$script:btnDisableComputers.Text = "Disable Computers"
$script:btnDisableComputers.Size = New-Object System.Drawing.Size(220, 36)
$script:btnDisableComputers.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$script:btnDisableComputers.BackColor = [System.Drawing.Color]::FromArgb(202, 131, 0)
$script:btnDisableComputers.ForeColor = [System.Drawing.Color]::White
$script:btnDisableComputers.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:btnDisableComputers.FlatAppearance.BorderSize = 0
$script:btnDisableComputers.Cursor = [System.Windows.Forms.Cursors]::Hand
$script:btnDisableComputers.Enabled = $false
$script:btnDisableComputers.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$script:btnDisableComputers.Add_Click({ Invoke-DisableComputers })

$script:btnEnableComputers = New-Object System.Windows.Forms.Button
$script:btnEnableComputers.Text = "Enable Computers"
$script:btnEnableComputers.Size = New-Object System.Drawing.Size(220, 36)
$script:btnEnableComputers.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$script:btnEnableComputers.BackColor = [System.Drawing.Color]::FromArgb(16, 137, 62)
$script:btnEnableComputers.ForeColor = [System.Drawing.Color]::White
$script:btnEnableComputers.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:btnEnableComputers.FlatAppearance.BorderSize = 0
$script:btnEnableComputers.Cursor = [System.Windows.Forms.Cursors]::Hand
$script:btnEnableComputers.Enabled = $false
$script:btnEnableComputers.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$script:btnEnableComputers.Add_Click({ Invoke-EnableComputers })

$script:btnDeleteComputers = New-Object System.Windows.Forms.Button
$script:btnDeleteComputers.Text = "DELETE Computers"
$script:btnDeleteComputers.Size = New-Object System.Drawing.Size(220, 36)
$script:btnDeleteComputers.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$script:btnDeleteComputers.BackColor = [System.Drawing.Color]::FromArgb(196, 43, 28)
$script:btnDeleteComputers.ForeColor = [System.Drawing.Color]::White
$script:btnDeleteComputers.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:btnDeleteComputers.FlatAppearance.BorderSize = 0
$script:btnDeleteComputers.Cursor = [System.Windows.Forms.Cursors]::Hand
$script:btnDeleteComputers.Enabled = $false
$script:btnDeleteComputers.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$script:btnDeleteComputers.Add_Click({ Invoke-DeleteComputers })

$btnClearComputers = New-Object System.Windows.Forms.Button
$btnClearComputers.Text = "Clear All"
$btnClearComputers.Size = New-Object System.Drawing.Size(115, 36)
$btnClearComputers.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnClearComputers.BackColor = [System.Drawing.Color]::FromArgb(100, 110, 125)
$btnClearComputers.ForeColor = [System.Drawing.Color]::White
$btnClearComputers.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnClearComputers.FlatAppearance.BorderSize = 0
$btnClearComputers.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnClearComputers.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$btnClearComputers.Add_Click({
    $script:txtComputerInput.Clear()
    $script:dgvComputers.Rows.Clear()
    $script:ProcessedComputers.Clear()
    $script:lblStatus.Text = "Ready"
    $script:progressBar.Value = 0
    $script:btnDisableComputers.Enabled = $false
    $script:btnEnableComputers.Enabled  = $false
    $script:btnDeleteComputers.Enabled  = $false
    Write-Log "Computer fields cleared." "INFO"
})

$btnExportComputers = New-Object System.Windows.Forms.Button
$btnExportComputers.Text = "Export Log"
$btnExportComputers.Size = New-Object System.Drawing.Size(115, 36)
$btnExportComputers.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnExportComputers.BackColor = [System.Drawing.Color]::FromArgb(55, 65, 81)
$btnExportComputers.ForeColor = [System.Drawing.Color]::White
$btnExportComputers.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnExportComputers.FlatAppearance.BorderSize = 0
$btnExportComputers.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnExportComputers.Margin = New-Object System.Windows.Forms.Padding(0, 0, 5, 5)
$btnExportComputers.Add_Click({ Export-LogToFile })

$compButtonPanel.Controls.AddRange(@($btnImportCSV, $btnLookupComputers, $script:btnDisableComputers, $script:btnEnableComputers, $script:btnDeleteComputers, $btnClearComputers, $btnExportComputers))

$grpCompInput.Controls.Add($script:txtComputerInput)
$grpCompInput.Controls.Add($lblCompHint)
$grpCompInput.Controls.Add($compButtonPanel)
$splitComputers.Panel1.Controls.Add($grpCompInput)

# --- Computer Results Grid ---
$grpCompResults = New-Object System.Windows.Forms.GroupBox
$grpCompResults.Text = " Computer Results "
$grpCompResults.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$grpCompResults.Dock = [System.Windows.Forms.DockStyle]::Fill
$grpCompResults.ForeColor = [System.Drawing.Color]::FromArgb(24, 42, 68)
$grpCompResults.Padding = New-Object System.Windows.Forms.Padding(10, 20, 10, 10)

$script:dgvComputers = New-Object System.Windows.Forms.DataGridView
$script:dgvComputers.Dock = [System.Windows.Forms.DockStyle]::Fill
$script:dgvComputers.AllowUserToAddRows = $false
$script:dgvComputers.AllowUserToDeleteRows = $false
$script:dgvComputers.ReadOnly = $true
$script:dgvComputers.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
$script:dgvComputers.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
$script:dgvComputers.BackgroundColor = [System.Drawing.Color]::White
$script:dgvComputers.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$script:dgvComputers.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(24, 42, 68)
$script:dgvComputers.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
$script:dgvComputers.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$script:dgvComputers.EnableHeadersVisualStyles = $false
$script:dgvComputers.ColumnHeadersHeight = 32
$script:dgvComputers.RowTemplate.Height = 26
$script:dgvComputers.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(248, 250, 252)
$script:dgvComputers.DefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$script:dgvComputers.GridColor = [System.Drawing.Color]::FromArgb(230, 233, 238)

[void]$script:dgvComputers.Columns.Add("Name",           "Computer Name")
[void]$script:dgvComputers.Columns.Add("DNSHostName",    "DNS Host Name")
[void]$script:dgvComputers.Columns.Add("OS",             "Operating System")
[void]$script:dgvComputers.Columns.Add("Status",         "Status")
[void]$script:dgvComputers.Columns.Add("OU",             "Organizational Unit")
[void]$script:dgvComputers.Columns.Add("Description",    "Description")
[void]$script:dgvComputers.Columns.Add("Action",         "Action")
[void]$script:dgvComputers.Columns.Add("Result",         "Result")
[void]$script:dgvComputers.Columns.Add("Timestamp",      "Timestamp")

$script:dgvComputers.Columns["Name"].FillWeight        = 12
$script:dgvComputers.Columns["DNSHostName"].FillWeight = 14
$script:dgvComputers.Columns["OS"].FillWeight          = 14
$script:dgvComputers.Columns["Status"].FillWeight      = 7
$script:dgvComputers.Columns["OU"].FillWeight          = 22
$script:dgvComputers.Columns["Description"].FillWeight = 14
$script:dgvComputers.Columns["Action"].FillWeight      = 7
$script:dgvComputers.Columns["Result"].FillWeight      = 7
$script:dgvComputers.Columns["Timestamp"].FillWeight   = 12

$grpCompResults.Controls.Add($script:dgvComputers)
$splitComputers.Panel2.Controls.Add($grpCompResults)
$tabComputers.Controls.Add($splitComputers)

$splitMain.Panel1.Controls.Add($tabControl)

# ============================================================
# BOTTOM: Verbose Log
# ============================================================
$grpLog = New-Object System.Windows.Forms.GroupBox
$grpLog.Text = " Verbose Activity Log "
$grpLog.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$grpLog.Dock = [System.Windows.Forms.DockStyle]::Fill
$grpLog.ForeColor = [System.Drawing.Color]::FromArgb(24, 42, 68)
$grpLog.Padding = New-Object System.Windows.Forms.Padding(10, 20, 10, 10)

$script:txtLog = New-Object System.Windows.Forms.TextBox
$script:txtLog.Multiline = $true
$script:txtLog.ScrollBars = "Both"
$script:txtLog.Font = New-Object System.Drawing.Font("Consolas", 9)
$script:txtLog.Dock = [System.Windows.Forms.DockStyle]::Fill
$script:txtLog.ReadOnly = $true
$script:txtLog.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 22)
$script:txtLog.ForeColor = [System.Drawing.Color]::FromArgb(0, 210, 106)
$script:txtLog.WordWrap = $false

$grpLog.Controls.Add($script:txtLog)
$splitMain.Panel2.Controls.Add($grpLog)

# --- Status Bar ---
$statusStrip = New-Object System.Windows.Forms.StatusStrip
$statusStrip.BackColor = [System.Drawing.Color]::FromArgb(24, 42, 68)

$script:lblStatus = New-Object System.Windows.Forms.ToolStripStatusLabel
$script:lblStatus.Text = "Ready - Enter a domain FQDN or click Connect to auto-detect"
$script:lblStatus.ForeColor = [System.Drawing.Color]::White
$script:lblStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$script:lblStatus.Spring = $true
$script:lblStatus.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft

$script:progressBar = New-Object System.Windows.Forms.ToolStripProgressBar
$script:progressBar.Size = New-Object System.Drawing.Size(250, 18)
$script:progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous

$statusStrip.Items.AddRange(@($script:lblStatus, $script:progressBar))

# --- Assemble Form ---
$form.Controls.Add($statusStrip)
$form.Controls.Add($splitMain)
$form.Controls.Add($domainPanel)
$form.Controls.Add($headerPanel)

# ============================================================
# INITIAL LOG
# ============================================================
Write-Log "AD Object Manager v$($script:AppVersion) initialized" "INFO"
Write-Log "Running as: $(whoami)" "INFO"
Write-Log "Domain targeting enabled - Enter a domain FQDN or click 'Connect & Discover PDC'" "INFO"
Write-Log "All AD operations will be performed against the PDC Emulator of the target domain" "INFO"
Write-Log "--- USER TAB: Paste SAMAccountNames OR use 'Import CSV' then Lookup / Disable / Enable / Delete ---" "INFO"
Write-Log "--- COMPUTER TAB: Paste computer names OR use 'Import CSV' then Lookup / Disable / Enable / Delete ---" "INFO"
Write-Log "User CSV accepted headers: SamAccountName, Username, User, LoginName (first column used as fallback)" "INFO"
Write-Log "Computer CSV accepted headers: ComputerName, Name, Computer, Hostname (first column used as fallback)" "INFO"
Write-Log "Ready." "INFO"

# Auto-connect
Resolve-TargetDomain

# ============================================================
# SHOW THE FORM
# ============================================================
[void]$form.ShowDialog()

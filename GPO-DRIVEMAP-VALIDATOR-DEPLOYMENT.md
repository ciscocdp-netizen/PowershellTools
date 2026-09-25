# GPO Drive Mapping Validator - Deployment Guide

## Overview

This guide covers enterprise deployment scenarios for the GPO Drive Mapping Validator tool.

## Deployment Options

### Option 1: Network Share Deployment (Recommended)

**Pros**: Centralized updates, easy access, no local installation
**Cons**: Requires network access

#### Steps

1. Create a shared folder on a file server:
   ```powershell
   # On file server
   New-Item -Path "D:\Shares\GPOTools" -ItemType Directory
   New-SmbShare -Name "GPOTools" -Path "D:\Shares\GPOTools" -ReadAccess "Domain Users"
   ```

2. Copy scripts to the share:
   ```powershell
   Copy-Item Test-GpoDriveMapTargeting.ps1 \\fileserver\GPOTools\
   Copy-Item GPO-DriveMap-Validator-GUI.ps1 \\fileserver\GPOTools\
   Copy-Item GPO-DRIVEMAP-VALIDATOR-*.md \\fileserver\GPOTools\Docs\
   ```

3. Create a desktop shortcut for users:
   ```powershell
   # GPO or logon script
   $WshShell = New-Object -ComObject WScript.Shell
   $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\GPO Validator.lnk")
   $Shortcut.TargetPath = "powershell.exe"
   $Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"\\fileserver\GPOTools\GPO-DriveMap-Validator-GUI.ps1`""
   $Shortcut.IconLocation = "shell32.dll,71"
   $Shortcut.Save()
   ```

4. Document the UNC path for CLI users:
   ```
   \\fileserver\GPOTools\Test-GpoDriveMapTargeting.ps1
   ```

---

### Option 2: Local Installation

**Pros**: Works offline, faster startup
**Cons**: Requires installation on each machine, updates are manual

#### Steps

1. Choose installation directory:
   ```powershell
   $installPath = "C:\Program Files\GPOTools"
   New-Item -Path $installPath -ItemType Directory -Force
   ```

2. Copy files:
   ```powershell
   Copy-Item *.ps1 "$installPath\"
   Copy-Item *.md "$installPath\Docs\"
   ```

3. Add to PATH (optional):
   ```powershell
   $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
   $newPath = "$currentPath;$installPath"
   [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
   ```

4. Create Start Menu shortcut:
   ```powershell
   $WshShell = New-Object -ComObject WScript.Shell
   $Shortcut = $WshShell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\GPO Drive Mapping Validator.lnk")
   $Shortcut.TargetPath = "powershell.exe"
   $Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$installPath\GPO-DriveMap-Validator-GUI.ps1`""
   $Shortcut.IconLocation = "shell32.dll,71"
   $Shortcut.Save()
   ```

---

### Option 3: Group Policy Deployment

**Pros**: Automated deployment, centralized management
**Cons**: More complex setup

#### Steps

1. **Create MSI Package** (using Advanced Installer, WiX, or similar):
   - Package the PowerShell scripts
   - Set installation path to `%ProgramFiles%\GPOTools`
   - Create Start Menu shortcuts
   - Set uninstall information

2. **Deploy via GPO**:
   - Open GPMC
   - Create/edit GPO: "Deploy GPO Validator Tool"
   - Computer Configuration → Policies → Software Settings → Software installation
   - Right-click → New → Package
   - Select the MSI file
   - Choose "Assigned" deployment method
   - Link to target OUs (e.g., IT Admin workstations)

3. **Verify deployment**:
   ```powershell
   # On client machine
   gpupdate /force
   # Check installation
   Test-Path "C:\Program Files\GPOTools\Test-GpoDriveMapTargeting.ps1"
   ```

---

### Option 4: PowerShell Gallery / Internal NuGet (Advanced)

**Pros**: Standard PowerShell module deployment
**Cons**: Requires packaging as a module

#### Steps

1. **Create module structure**:
   ```
   GPODriveMapValidator/
   ├── GPODriveMapValidator.psd1  (module manifest)
   ├── GPODriveMapValidator.psm1  (module script)
   ├── Functions/
   │   ├── Test-GpoDriveMapTargeting.ps1
   │   └── Show-GpoDriveMapValidatorGUI.ps1
   └── Docs/
       └── ...
   ```

2. **Publish to internal repository**:
   ```powershell
   # Set up internal NuGet feed
   Register-PSRepository -Name "Corporate" -SourceLocation "\\fileserver\PSRepository" -InstallationPolicy Trusted
   
   # Publish module
   Publish-Module -Path .\GPODriveMapValidator -Repository Corporate
   ```

3. **Install on client machines**:
   ```powershell
   Install-Module -Name GPODriveMapValidator -Repository Corporate
   
   # Usage
   Test-GpoDriveMapTargeting -GpoName "..." -TargetUsers alice
   Show-GpoDriveMapValidatorGUI
   ```

---

## RSAT Deployment

The tool requires RSAT PowerShell modules. Deploy via:

### Method 1: GPO (Windows 10/11)

1. Create GPO: "Install RSAT - AD and GP Tools"
2. Computer Configuration → Policies → Administrative Templates → System → Specify settings for optional component installation and component repair
   - Enable: "Download repair content and optional features directly from Windows Update"
3. Create a PowerShell startup script:

```powershell
# Install-RSAT.ps1
try {
    $ad = Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools*"
    if ($ad.State -ne "Installed") {
        Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    }
    
    $gp = Get-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools*"
    if ($gp.State -ne "Installed") {
        Add-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
    }
}
catch {
    Write-EventLog -LogName Application -Source "GPO Validator" -EventId 1001 -EntryType Warning -Message "RSAT installation failed: $_"
}
```

4. Add script to GPO:
   - Computer Configuration → Policies → Windows Settings → Scripts → Startup
   - Add Install-RSAT.ps1

### Method 2: SCCM / Intune

**SCCM**:
- Create application package for RSAT FOD
- Deploy to "IT Admins" collection

**Intune**:
- Devices → Windows → PowerShell scripts
- Upload Install-RSAT.ps1
- Assign to device group

### Method 3: Manual Installation Script

```powershell
# deploy-validator-with-rsat.ps1

Write-Host "Installing RSAT PowerShell modules..." -ForegroundColor Cyan

# Check OS version
$osVersion = [System.Environment]::OSVersion.Version

if ($osVersion.Major -eq 10 -and $osVersion.Build -ge 17763) {
    # Windows 10 1809+ / Windows 11
    Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    Add-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
}
elseif ($osVersion.Major -eq 10 -and $osVersion.Build -lt 17763) {
    # Windows 10 older versions
    Write-Host "Please install RSAT from: https://www.microsoft.com/download/details.aspx?id=45520" -ForegroundColor Yellow
    Start-Process "https://www.microsoft.com/download/details.aspx?id=45520"
    Read-Host "Press Enter after installing RSAT to continue"
}
else {
    # Windows Server
    Install-WindowsFeature RSAT-AD-PowerShell, RSAT-GP -IncludeManagementTools
}

Write-Host "Installing GPO Validator tool..." -ForegroundColor Cyan

$installPath = "C:\Program Files\GPOTools"
New-Item -Path $installPath -ItemType Directory -Force | Out-Null

# Download from network share or copy from current directory
Copy-Item "Test-GpoDriveMapTargeting.ps1" "$installPath\" -Force
Copy-Item "GPO-DriveMap-Validator-GUI.ps1" "$installPath\" -Force

Write-Host "Installation complete!" -ForegroundColor Green
Write-Host "Launch GUI: $installPath\GPO-DriveMap-Validator-GUI.ps1" -ForegroundColor Cyan
```

---

## Integration Scenarios

### Scenario 1: CI/CD Pipeline Integration

**Use case**: Validate GPO changes before merging to production.

**Architecture**:
```
Git Repo (GPO XML files)
    ↓
Pull Request Created
    ↓
CI Pipeline (Azure DevOps / Jenkins / GitHub Actions)
    ↓
Run Validation Script
    ↓
Post results as PR comment
    ↓
Block merge if conflicts detected
```

**Example: Azure DevOps Pipeline**

```yaml
# azure-pipelines.yml

trigger:
  branches:
    include:
      - main
      - feature/*
  paths:
    include:
      - GPO-Exports/**/*.xml

pool:
  vmImage: 'windows-latest'

steps:
- checkout: self

- powershell: |
    Import-Module ActiveDirectory
    Import-Module GroupPolicy
  displayName: 'Import AD Modules'

- powershell: |
    # Find all modified Drives.xml files
    $modifiedFiles = git diff --name-only HEAD~1 HEAD | Where-Object { $_ -like "*Drives.xml" }
    
    $allConflicts = @()
    
    foreach ($file in $modifiedFiles) {
        Write-Host "Validating: $file"
        
        # Extract GPO name from path (customize as needed)
        $gpoName = (Split-Path (Split-Path $file -Parent) -Leaf)
        
        # Run validation
        $result = .\Tools\Test-GpoDriveMapTargeting.ps1 `
            -DrivesXmlPath $file `
            -TargetOU "OU=AllUsers,DC=corp,DC=contoso,DC=com" `
            -ReturnObject
        
        if ($result.Conflicts -and $result.Conflicts.Count -gt 0) {
            Write-Host "##vso[task.logissue type=error]Conflicts detected in $file"
            $allConflicts += $result.Conflicts
        }
        
        if ($result.Warnings -and $result.Warnings.Count -gt 0) {
            foreach ($warning in $result.Warnings) {
                Write-Host "##vso[task.logissue type=warning]$warning"
            }
        }
    }
    
    if ($allConflicts.Count -gt 0) {
        Write-Host "##vso[task.complete result=Failed;]Validation failed with conflicts"
        exit 1
    }
  displayName: 'Validate GPO Drive Mappings'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: '$(Build.ArtifactStagingDirectory)'
    artifactName: 'ValidationResults'
  condition: always()
```

---

### Scenario 2: ServiceNow Integration

**Use case**: Validate GPOs before change management approval.

**Workflow**:
1. Change request created in ServiceNow
2. Workflow triggers validation script
3. Results posted to change record
4. Approvers review validation results
5. Change approved/rejected based on results

**Example: ServiceNow MID Server Script**

```powershell
# ServiceNow Orchestration Activity Script

param(
    [string]$GpoName,
    [string]$TargetOU,
    [string]$ChangeRequestNumber
)

$validationScript = "\\fileserver\GPOTools\Test-GpoDriveMapTargeting.ps1"

$result = & $validationScript `
    -GpoName $GpoName `
    -TargetOU $TargetOU `
    -ReturnObject

$output = @{
    ChangeRequest = $ChangeRequestNumber
    ValidationDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    TotalUsers = ($result.Results | Select-Object -Unique Subject).Count
    Conflicts = $result.Conflicts.Count
    Warnings = $result.Warnings.Count
    Status = if ($result.Conflicts.Count -eq 0) { "PASS" } else { "FAIL" }
    Details = $result | ConvertTo-Json -Depth 10
}

# Return to ServiceNow
return $output | ConvertTo-Json
```

---

### Scenario 3: Scheduled Auditing

**Use case**: Weekly automated audit of all GPOs.

**Setup**:

```powershell
# schedule-gpo-audit.ps1

# Configuration
$gpos = @(
    "Mapped Drives - Finance",
    "Mapped Drives - HR",
    "Mapped Drives - IT",
    "Mapped Drives - Sales"
)

$targetOUs = @{
    "Mapped Drives - Finance" = "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com"
    "Mapped Drives - HR"      = "OU=HR,OU=Users,DC=corp,DC=contoso,DC=com"
    "Mapped Drives - IT"      = "OU=IT,OU=Users,DC=corp,DC=contoso,DC=com"
    "Mapped Drives - Sales"   = "OU=Sales,OU=Users,DC=corp,DC=contoso,DC=com"
}

$outputPath = "\\fileserver\GPOAudits\Weekly"
$date = Get-Date -Format "yyyyMMdd"

foreach ($gpo in $gpos) {
    $ou = $targetOUs[$gpo]
    $csvFile = "$outputPath\$gpo-$date.csv"
    
    Write-Host "Auditing: $gpo" -ForegroundColor Cyan
    
    $result = .\Test-GpoDriveMapTargeting.ps1 `
        -GpoName $gpo `
        -TargetOU $ou `
        -ReturnObject
    
    # Export results
    $result.Results | Export-Csv -Path $csvFile -NoTypeInformation
    
    # Check for issues
    if ($result.Conflicts.Count -gt 0) {
        $conflictFile = "$outputPath\$gpo-$date-CONFLICTS.txt"
        $result.Conflicts | Out-File $conflictFile
        
        # Send alert email
        Send-MailMessage `
            -To "gpo-admins@corp.contoso.com" `
            -From "gpo-audit@corp.contoso.com" `
            -Subject "⚠ GPO Audit Alert: Conflicts in $gpo" `
            -Body "Conflicts detected in $gpo. See attached report." `
            -Attachments $conflictFile `
            -SmtpServer "smtp.corp.contoso.com"
    }
}

Write-Host "Audit complete. Results: $outputPath" -ForegroundColor Green
```

**Schedule via Task Scheduler**:

```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"C:\Scripts\schedule-gpo-audit.ps1`""
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$principal = New-ScheduledTaskPrincipal -UserId "CORP\svc-gpoaudit" -LogonType Password -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable

Register-ScheduledTask `
    -TaskName "GPO Drive Mapping Weekly Audit" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "Automated weekly audit of GPO drive mappings"
```

---

## Monitoring & Logging

### Event Log Integration

Add event logging to track validation runs:

```powershell
# Add to Test-GpoDriveMapTargeting.ps1 (near the end)

$eventSource = "GPO-Validator"

# Create event source if it doesn't exist
if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
    New-EventLog -LogName Application -Source $eventSource
}

# Log validation run
$eventMessage = @"
GPO Validation Completed

GPO: $GpoName
Users Tested: $($subjects.Count)
Total Evaluations: $($results.Count)
Conflicts: $(if ($conflicts) { $conflicts.Count } else { 0 })
Warnings: $(if ($script:UnverifiedFilterWarnings) { $script:UnverifiedFilterWarnings.Count } else { 0 })
"@

$eventType = if ($conflicts.Count -gt 0) { "Warning" } else { "Information" }
$eventId = if ($conflicts.Count -gt 0) { 2001 } else { 1001 }

Write-EventLog -LogName Application -Source $eventSource -EventId $eventId -EntryType $eventType -Message $eventMessage
```

### Splunk / ELK Integration

Forward event logs or export structured JSON:

```powershell
# Export validation results as JSON for log ingestion

$logData = [PSCustomObject]@{
    Timestamp = (Get-Date).ToUniversalTime().ToString("o")
    EventType = "GPOValidation"
    GpoName = $GpoName
    Domain = $Domain
    UserCount = $subjects.Count
    TotalEvaluations = $results.Count
    ConflictCount = $conflicts.Count
    WarningCount = $script:UnverifiedFilterWarnings.Count
    Results = $results
    Conflicts = $conflicts
    Warnings = $script:UnverifiedFilterWarnings
}

$logJson = $logData | ConvertTo-Json -Depth 10 -Compress

# Send to Splunk HTTP Event Collector
$splunkUrl = "https://splunk.corp.contoso.com:8088/services/collector/event"
$splunkToken = "YOUR-HEC-TOKEN"

Invoke-RestMethod -Uri $splunkUrl -Method Post -Headers @{ Authorization = "Splunk $splunkToken" } -Body $logJson -ContentType "application/json"
```

---

## Security Considerations

### Least Privilege

The tool requires:
- **Read access** to SYSVOL (via Domain Users)
- **Read access** to AD users, groups, OUs (via Domain Users)
- **No write access** required

**Service Account Recommendations**:
```powershell
# Create service account for automated validation
New-ADUser -Name "svc-gpovalidator" -SamAccountName "svc-gpovalidator" -UserPrincipalName "svc-gpovalidator@corp.contoso.com" -Description "Service account for GPO validation automation" -PasswordNeverExpires $true -CannotChangePassword $true

# Grant necessary permissions (default Domain Users is sufficient for read operations)
# No additional permissions required
```

### Credential Storage

For automated scenarios:

**Option 1: Group Managed Service Account (gMSA)** - Recommended
```powershell
# Create gMSA
New-ADServiceAccount -Name "gMSA-GPOValidator" -DNSHostName "gpovalidator.corp.contoso.com" -PrincipalsAllowedToRetrieveManagedPassword "GPOValidatorServers$"

# Use in scheduled task
$principal = New-ScheduledTaskPrincipal -UserId "CORP\gMSA-GPOValidator$" -LogonType Password
```

**Option 2: Credential Manager** - For interactive scenarios
```powershell
# Store credentials
cmdkey /add:GPOValidator /user:CORP\svc-gpovalidator /pass:P@ssw0rd

# Retrieve in script
$cred = Get-StoredCredential -Target "GPOValidator"
```

**Option 3: Azure Key Vault** - For cloud-integrated environments
```powershell
# Retrieve from Key Vault
$secret = Get-AzKeyVaultSecret -VaultName "CorpSecrets" -Name "GPOValidatorPassword"
$cred = New-Object PSCredential("CORP\svc-gpovalidator", $secret.SecretValue)
```

---

## Troubleshooting Deployments

### Issue: Users can't run scripts ("Execution Policy")

**Solution**: GPO to set execution policy

1. GPMC → Create/Edit GPO
2. Computer Configuration → Policies → Administrative Templates → Windows Components → Windows PowerShell
3. "Turn on Script Execution" → Enabled → "Allow local scripts and remote signed scripts"

### Issue: RSAT not installing via GPO

**Check**:
- Windows Update access (required for FOD installation)
- WSUS configuration (must allow optional features)
- Run `Get-WindowsCapability -Online -Name Rsat*` to see available packages

### Issue: Network share access denied

**Check**:
- SMB share permissions (Read for Domain Users)
- NTFS permissions (Read for Domain Users)
- Firewall (allow SMB ports 445)

---

## Maintenance & Updates

### Version Control

Keep scripts in Git:

```bash
git init GPOValidator
cd GPOValidator
git add *.ps1 *.md
git commit -m "Initial commit"
git remote add origin https://github.com/corp/gpovalidator
git push -u origin main
```

### Update Process

1. Test updates in development environment
2. Update version number in scripts
3. Deploy to test share
4. Notify pilot users
5. Collect feedback
6. Deploy to production share
7. Send update notification to all users

### Change Log

Maintain a CHANGELOG.md:

```markdown
# Changelog

## [2.0.0] - 2026-09-25
### Added
- Modern WPF GUI
- Simulated users support
- Enhanced error handling

### Fixed
- Primary group membership detection
- XML parsing for disabled drives
- Group membership matching logic

## [1.0.0] - 2025-01-15
### Initial Release
- Core validation engine
- CLI interface
- CSV export
```

---

## Support & Training

### User Training

Recommended training topics:
1. Introduction to GPP drive mappings
2. Understanding Item-Level Targeting
3. Using the GUI tool
4. Interpreting results
5. Resolving conflicts
6. Best practices

### Documentation

Distribute:
- README.md (overview)
- USER-GUIDE.md (detailed usage)
- DEPLOYMENT-GUIDE.md (this document)
- Quick Reference Card (1-page cheat sheet)

### Support Tiers

**Tier 1**: Basic usage questions
- Refer to User Guide
- Verify RSAT installation
- Check execution policy

**Tier 2**: Validation interpretation
- Analyze conflicts
- Explain filter logic
- Review warnings

**Tier 3**: Advanced scenarios
- Custom scripting
- CI/CD integration
- Module development

---

## Appendix: Example Deployment Script

Complete deployment script for enterprise rollout:

```powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enterprise deployment script for GPO Drive Mapping Validator
#>

param(
    [ValidateSet('Install', 'Uninstall', 'Update')]
    [string]$Action = 'Install',
    
    [ValidateSet('Local', 'NetworkShare')]
    [string]$DeploymentType = 'Local',
    
    [string]$NetworkSharePath = '\\fileserver\GPOTools'
)

$ErrorActionPreference = 'Stop'

# Logging
$logPath = "$env:TEMP\GPOValidator-Deployment.log"
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Host $logMessage
    Add-Content -Path $logPath -Value $logMessage
}

Write-Log "Starting deployment action: $Action, Type: $DeploymentType"

switch ($Action) {
    'Install' {
        Write-Log "Installing RSAT modules..."
        
        # Install RSAT
        try {
            $adModule = Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools*" | Where-Object { $_.State -ne "Installed" }
            if ($adModule) {
                Write-Log "Installing ActiveDirectory RSAT..."
                Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop
            }
            
            $gpModule = Get-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools*" | Where-Object { $_.State -ne "Installed" }
            if ($gpModule) {
                Write-Log "Installing GroupPolicy RSAT..."
                Add-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0" -ErrorAction Stop
            }
            
            Write-Log "RSAT modules installed successfully"
        }
        catch {
            Write-Log "ERROR: RSAT installation failed: $_"
            throw
        }
        
        if ($DeploymentType -eq 'Local') {
            Write-Log "Deploying to local installation..."
            
            $installPath = "$env:ProgramFiles\GPOTools"
            New-Item -Path $installPath -ItemType Directory -Force | Out-Null
            
            # Copy scripts
            Copy-Item "Test-GpoDriveMapTargeting.ps1" "$installPath\" -Force
            Copy-Item "GPO-DriveMap-Validator-GUI.ps1" "$installPath\" -Force
            
            # Create Start Menu shortcut
            $WshShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\GPO Drive Mapping Validator.lnk")
            $Shortcut.TargetPath = "powershell.exe"
            $Shortcut.Arguments = "-ExecutionPolicy Bypass -NoProfile -File `"$installPath\GPO-DriveMap-Validator-GUI.ps1`""
            $Shortcut.IconLocation = "shell32.dll,71"
            $Shortcut.Description = "Validate GPO Drive Mappings"
            $Shortcut.Save()
            
            Write-Log "Installation complete: $installPath"
        }
        else {
            Write-Log "Network share deployment - creating desktop shortcut..."
            
            # Create desktop shortcut pointing to network share
            $WshShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("$env:Public\Desktop\GPO Drive Mapping Validator.lnk")
            $Shortcut.TargetPath = "powershell.exe"
            $Shortcut.Arguments = "-ExecutionPolicy Bypass -NoProfile -File `"$NetworkSharePath\GPO-DriveMap-Validator-GUI.ps1`""
            $Shortcut.IconLocation = "shell32.dll,71"
            $Shortcut.Description = "Validate GPO Drive Mappings (Network)"
            $Shortcut.Save()
            
            Write-Log "Shortcut created on Public Desktop"
        }
        
        Write-Log "Deployment complete!"
    }
    
    'Uninstall' {
        Write-Log "Uninstalling GPO Validator..."
        
        if ($DeploymentType -eq 'Local') {
            $installPath = "$env:ProgramFiles\GPOTools"
            if (Test-Path $installPath) {
                Remove-Item $installPath -Recurse -Force
                Write-Log "Removed: $installPath"
            }
            
            $startMenuShortcut = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\GPO Drive Mapping Validator.lnk"
            if (Test-Path $startMenuShortcut) {
                Remove-Item $startMenuShortcut -Force
                Write-Log "Removed Start Menu shortcut"
            }
        }
        
        $desktopShortcut = "$env:Public\Desktop\GPO Drive Mapping Validator.lnk"
        if (Test-Path $desktopShortcut) {
            Remove-Item $desktopShortcut -Force
            Write-Log "Removed Desktop shortcut"
        }
        
        Write-Log "Uninstall complete"
    }
    
    'Update' {
        Write-Log "Updating GPO Validator..."
        
        if ($DeploymentType -eq 'Local') {
            $installPath = "$env:ProgramFiles\GPOTools"
            
            # Backup existing
            $backupPath = "$installPath\Backup-$(Get-Date -Format 'yyyyMMddHHmmss')"
            New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
            Copy-Item "$installPath\*.ps1" $backupPath -ErrorAction SilentlyContinue
            
            # Update scripts
            Copy-Item "Test-GpoDriveMapTargeting.ps1" "$installPath\" -Force
            Copy-Item "GPO-DriveMap-Validator-GUI.ps1" "$installPath\" -Force
            
            Write-Log "Update complete. Backup: $backupPath"
        }
        else {
            Write-Log "Network share deployment - files updated on share by admin"
        }
    }
}

Write-Log "Deployment action '$Action' completed successfully"
Write-Host "`nLog file: $logPath" -ForegroundColor Cyan
```

---

**Document Version**: 1.0  
**Last Updated**: 2026-09-25  
**Tool Version**: 2.0

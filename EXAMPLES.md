# GPO Drive Mapping Validator - Quick Examples

## Example 1: Interactive Quick Start

Run the quick start script for guided setup:

```powershell
.\Start-GPOValidator.ps1
```

This will:
- Check prerequisites (PowerShell version, RSAT modules)
- Offer to install missing components
- Present menu of options:
  1. Launch GUI
  2. Run CLI example
  3. View documentation
  4. Run demo with simulated users
  5. Exit

---

## Example 2: Basic Validation (CLI)

Test a GPO against specific users:

```powershell
# Simple validation
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetUsers alice, bob, charlie

# With domain specified explicitly
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -Domain "corp.contoso.com" `
    -TargetUsers alice, bob, charlie
```

**Expected Output:**
```
=================== SUMMARY: Who receives which drive ===================

alice:
  H:  \\fileserver\home\alice   (Home Drive)
  S:  \\fileserver\shared   (Shared)
  F:  \\fileserver\finance   (Finance Drive)

bob:
  H:  \\fileserver\home\bob   (Home Drive)
  S:  \\fileserver\shared   (Shared)

charlie:
  (no drives mapped)

=================== DRIVE-LETTER CONFLICTS ===================
None detected.

Validation complete.
```

---

## Example 3: Test Entire OU

Validate against all users in an organizational unit:

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetOU "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com" `
    -ExportCsvPath "C:\Reports\finance-validation-$(Get-Date -Format 'yyyyMMdd').csv"
```

This will:
- Query all users in the Finance OU recursively
- Validate each user against the GPO's drive mappings
- Export results to CSV with timestamp

---

## Example 4: Debug with Filter Trace

See step-by-step filter evaluation:

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetUsers alice `
    -ShowFilterTrace
```

**Expected Output:**
```
Drive H: (\\fileserver\home\alice) evaluated for 'alice':
  No item-level targeting filters present -> applies to ALL users.

Drive S: (\\fileserver\shared) evaluated for 'alice':
  No item-level targeting filters present -> applies to ALL users.

Drive F: (\\fileserver\finance) evaluated for 'alice':
  FilterGroup 'CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com' -> user-member:True computer-member:False
  FilterOrgUnit 'OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com' -> True (subject DN: CN=Alice Smith,OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com)
  FilterGroup 'CN=Contractors,OU=Groups,DC=corp,DC=contoso,DC=com' -> user-member:False computer-member:False
  (NOT applied -> True)
Final result: True

=================== SUMMARY: Who receives which drive ===================
alice:
  H:  \\fileserver\home\alice   (Home Drive)
  S:  \\fileserver\shared   (Shared)
  F:  \\fileserver\finance   (Finance Drive)
```

---

## Example 5: Simulated Users

Test hypothetical scenarios without creating AD accounts:

```powershell
# Define simulated users
$simulatedUsers = @(
    @{
        Name = "FutureEmployee"
        DistinguishedName = "CN=Future Employee,OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com"
        MemberOfGroups = @(
            "CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com",
            "CN=Domain Users,CN=Users,DC=corp,DC=contoso,DC=com"
        )
        ComputerName = "DESKTOP-FIN-NEW"
        Site = "HQ"
    },
    @{
        Name = "FutureContractor"
        DistinguishedName = "CN=Future Contractor,OU=Contractors,OU=Users,DC=corp,DC=contoso,DC=com"
        MemberOfGroups = @(
            "CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com",
            "CN=Contractors,OU=Groups,DC=corp,DC=contoso,DC=com",
            "CN=Domain Users,CN=Users,DC=corp,DC=contoso,DC=com"
        )
        ComputerName = "LAPTOP-CTR-NEW"
        Site = "Remote"
    }
)

# Run validation
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -SimulatedUsers $simulatedUsers `
    -ShowFilterTrace
```

**Use case**: Test how a planned OU restructure or new hire will be affected by existing GPOs.

---

## Example 6: Direct XML Path

Test without GPO name (useful for testing modified XML before importing):

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -DrivesXmlPath "\\corp.contoso.com\SysVol\corp.contoso.com\Policies\{12345678-1234-1234-1234-123456789ABC}\User\Preferences\Drives\Drives.xml" `
    -TargetUsers alice, bob
```

---

## Example 7: Computer Context

Test with specific computer assignments for computer-based filters:

```powershell
# Define computer assignments
$computerMapping = @{
    "alice" = "DESKTOP-FIN-01"
    "bob" = "LAPTOP-FIN-02"
    "charlie" = "DESKTOP-FIN-03"
}

# Run validation
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetUsers alice, bob, charlie `
    -ComputerNameOverride $computerMapping
```

This is important when GPO uses:
- FilterComputer (specific computer names)
- FilterGroup with computer groups

---

## Example 8: Automated Validation Script

Create a validation script for regular audits:

```powershell
# validate-all-gpos.ps1

$gpoMappings = @{
    "Mapped Drives - Finance" = "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com"
    "Mapped Drives - HR" = "OU=HR,OU=Users,DC=corp,DC=contoso,DC=com"
    "Mapped Drives - IT" = "OU=IT,OU=Users,DC=corp,DC=contoso,DC=com"
    "Mapped Drives - Sales" = "OU=Sales,OU=Users,DC=corp,DC=contoso,DC=com"
}

$outputDir = "C:\GPO-Audits\$(Get-Date -Format 'yyyy-MM-dd')"
New-Item -Path $outputDir -ItemType Directory -Force | Out-Null

foreach ($gpo in $gpoMappings.Keys) {
    $ou = $gpoMappings[$gpo]
    $csvPath = "$outputDir\$($gpo -replace ' ', '-').csv"
    
    Write-Host "Validating: $gpo" -ForegroundColor Cyan
    
    $result = .\Test-GpoDriveMapTargeting.ps1 `
        -GpoName $gpo `
        -TargetOU $ou `
        -ExportCsvPath $csvPath `
        -ReturnObject
    
    # Check for issues
    if ($result.Conflicts.Count -gt 0) {
        Write-Host "  ⚠ CONFLICTS DETECTED: $($result.Conflicts.Count)" -ForegroundColor Red
        $result.Conflicts | Out-File "$outputDir\$($gpo -replace ' ', '-')-CONFLICTS.txt"
    }
    
    if ($result.Warnings.Count -gt 0) {
        Write-Host "  ⚠ Warnings: $($result.Warnings.Count)" -ForegroundColor Yellow
    }
    
    Write-Host "  ✓ Complete: $csvPath" -ForegroundColor Green
}

Write-Host "`nAudit complete. Results: $outputDir" -ForegroundColor Green
```

**Schedule this via Task Scheduler for weekly audits.**

---

## Example 9: CI/CD Pipeline Integration

Validate GPO changes before merging to production:

```powershell
# ci-validate-gpo.ps1

param(
    [string]$GpoName,
    [string]$TargetOU
)

Write-Host "CI/CD Validation: $GpoName" -ForegroundColor Cyan

$result = .\Test-GpoDriveMapTargeting.ps1 `
    -GpoName $GpoName `
    -TargetOU $TargetOU `
    -ReturnObject

# Check for blocking issues
$exitCode = 0

if ($result.Conflicts.Count -gt 0) {
    Write-Host "❌ VALIDATION FAILED: Drive letter conflicts detected" -ForegroundColor Red
    foreach ($conflict in $result.Conflicts) {
        Write-Host "   $($conflict.Name): $($conflict.Count) conflicting mappings" -ForegroundColor Red
    }
    $exitCode = 1
}

if ($result.Warnings.Count -gt 0) {
    Write-Host "⚠ WARNING: Unverified filters detected" -ForegroundColor Yellow
    foreach ($warning in $result.Warnings) {
        Write-Host "   $warning" -ForegroundColor Yellow
    }
    # Warnings don't block deployment, but should be reviewed
}

if ($exitCode -eq 0) {
    Write-Host "✓ VALIDATION PASSED" -ForegroundColor Green
    
    # Export results for artifact storage
    $result.Results | Export-Csv -Path "validation-results.csv" -NoTypeInformation
}

exit $exitCode
```

**Use in Azure DevOps, Jenkins, GitHub Actions, etc.**

---

## Example 10: GUI Mode

Launch the graphical interface:

```powershell
.\GPO-DriveMap-Validator-GUI.ps1
```

Then:
1. Click "Auto-Detect" to populate domain
2. Click "Browse GPOs" to select a GPO
3. Enter usernames (comma-separated) or select "All Users in OU"
4. Click "Run Validation"
5. Review results in the tabs:
   - **Results**: See drive mappings per user
   - **Conflicts**: Identify drive letter conflicts
   - **Filter Trace**: Debug filter logic
   - **Warnings**: Review unverifiable filters
6. Click "Export to CSV" to save results

---

## Example 11: Pre-Migration Testing

Test how users will be affected by a planned OU migration:

```powershell
# Load users from current OU
$currentOU = "OU=OldDepartment,OU=Users,DC=corp,DC=contoso,DC=com"
$newOU = "OU=NewDepartment,OU=Users,DC=corp,DC=contoso,DC=com"

$users = Get-ADUser -SearchBase $currentOU -Filter * -Properties MemberOf

# Create simulated users in NEW OU
$simulatedUsers = @()
foreach ($user in $users) {
    $simulatedUsers += @{
        Name = $user.SamAccountName
        # Simulate in NEW location
        DistinguishedName = "CN=$($user.Name),$newOU"
        # Keep current group memberships
        MemberOfGroups = $user.MemberOf
    }
}

# Test against all drive mapping GPOs
$gpos = @("Mapped Drives - All Users", "Mapped Drives - Department Specific")

foreach ($gpo in $gpos) {
    Write-Host "`nTesting GPO: $gpo" -ForegroundColor Cyan
    
    .\Test-GpoDriveMapTargeting.ps1 `
        -GpoName $gpo `
        -SimulatedUsers $simulatedUsers `
        -ExportCsvPath "C:\Migration\$gpo-NewOU-Impact.csv"
}
```

---

## Example 12: Contractor vs Employee Verification

Verify contractors don't receive employee-only drives:

```powershell
# Get all contractors
$contractors = Get-ADUser -Filter {employeeType -eq "Contractor"} -Properties employeeType

# Test against employee-only GPO
$result = .\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Employees Only" `
    -TargetUsers $contractors.SamAccountName `
    -ReturnObject

# Check if any contractor receives drives (should be none)
$contractorsWithDrives = $result.Results | 
    Where-Object { $_.Applies -and -not $_.IsDisabled } |
    Select-Object -Unique Subject

if ($contractorsWithDrives) {
    Write-Host "❌ SECURITY ISSUE: Contractors receiving employee-only drives!" -ForegroundColor Red
    $contractorsWithDrives | ForEach-Object {
        Write-Host "   - $($_.Subject)" -ForegroundColor Red
    }
} else {
    Write-Host "✓ VERIFIED: No contractors receive employee-only drives" -ForegroundColor Green
}
```

---

## Example 13: Multi-GPO Aggregate Test

Test aggregate result when user receives drives from multiple GPOs:

```powershell
$user = "jsmith"
$gpos = @(
    "Mapped Drives - All Users",
    "Mapped Drives - Finance",
    "Mapped Drives - Managers"
)

$allDrives = @()

foreach ($gpo in $gpos) {
    $result = .\Test-GpoDriveMapTargeting.ps1 `
        -GpoName $gpo `
        -TargetUsers $user `
        -ReturnObject
    
    $allDrives += $result.Results | Where-Object { $_.Applies -and -not $_.IsDisabled }
}

# Check for conflicts across GPOs
$conflicts = $allDrives | Group-Object DriveLetter | Where-Object { $_.Count -gt 1 }

if ($conflicts) {
    Write-Host "❌ CROSS-GPO CONFLICTS for $user :" -ForegroundColor Red
    foreach ($conflict in $conflicts) {
        Write-Host "`n  Drive $($conflict.Name):" -ForegroundColor Red
        foreach ($item in $conflict.Group) {
            Write-Host "    $($item.Path) (from GPO context)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "✓ No conflicts across GPOs for $user" -ForegroundColor Green
    Write-Host "`nUser will receive:" -ForegroundColor Cyan
    $allDrives | Sort-Object DriveLetter -Unique | ForEach-Object {
        Write-Host "  $($_.DriveLetter)  $($_.Path)" -ForegroundColor Cyan
    }
}
```

---

## Tips & Best Practices

### 1. Always Test Before Deployment
```powershell
# Workflow
# 1. Create/modify GPO in test
# 2. Validate
# 3. Fix issues
# 4. Re-validate
# 5. Deploy to production
```

### 2. Use Filter Trace for Debugging
```powershell
# When a drive doesn't apply as expected, always use -ShowFilterTrace
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "..." `
    -TargetUsers problematic-user `
    -ShowFilterTrace
```

### 3. Export for Documentation
```powershell
# Always export results for audit trail
-ExportCsvPath "C:\Audit\$(Get-Date -Format 'yyyyMMdd-HHmmss')-validation.csv"
```

### 4. Test Representative Users
```powershell
# Include edge cases:
# - Standard employees
# - Contractors
# - Managers
# - Remote workers
# - Different OUs
```

### 5. Automate Regular Audits
```powershell
# Schedule weekly/monthly validations
# Keep historical exports
# Compare changes over time
```

---

## Need Help?

- **Documentation**: See `GPO-DRIVEMAP-VALIDATOR-USERGUIDE.md`
- **Deployment**: See `GPO-DRIVEMAP-VALIDATOR-DEPLOYMENT.md`
- **Troubleshooting**: Check the Troubleshooting section in the User Guide
- **Examples**: This file!

---

**Happy Validating! 🚀**

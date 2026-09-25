# GPO Drive Mapping Validator - User Guide

## Table of Contents

1. [Installation](#installation)
2. [GUI Walkthrough](#gui-walkthrough)
3. [Command-Line Usage](#command-line-usage)
4. [Common Scenarios](#common-scenarios)
5. [Understanding Results](#understanding-results)
6. [Troubleshooting](#troubleshooting)

---

## Installation

### Step 1: Prerequisites Check

Open PowerShell as Administrator and verify prerequisites:

```powershell
# Check PowerShell version (must be 5.1+)
$PSVersionTable.PSVersion

# Check for ActiveDirectory module
Get-Module -ListAvailable ActiveDirectory

# Check for GroupPolicy module
Get-Module -ListAvailable GroupPolicy
```

### Step 2: Install RSAT (if needed)

**Windows 10/11**:
```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
```

**Windows Server**:
```powershell
Install-WindowsFeature RSAT-AD-PowerShell, RSAT-GP
```

### Step 3: Download Scripts

Copy the following files to a directory (e.g., `C:\GPOTools`):
- `Test-GpoDriveMapTargeting.ps1` (backend validation engine)
- `GPO-DriveMap-Validator-GUI.ps1` (GUI application)

### Step 4: Unblock Files

```powershell
Unblock-File C:\GPOTools\*.ps1
```

### Step 5: Set Execution Policy (if needed)

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## GUI Walkthrough

### Launching the GUI

```powershell
cd C:\GPOTools
.\GPO-DriveMap-Validator-GUI.ps1
```

### Main Window Overview

The GUI is organized into 6 tabs:

1. **Configuration** - Set up validation parameters
2. **Results** - View drive mapping results per user
3. **Conflicts** - See drive letter conflicts
4. **Filter Trace** - Debug filter evaluation logic
5. **Warnings** - Review unverifiable filters
6. **Simulated Users** - Define test scenarios

---

### Tab 1: Configuration

#### Section A: GPO Selection

**Option 1: Select by GPO Name (Recommended)**

1. Click **Auto-Detect** to populate your domain
2. Enter the GPO display name in the "GPO Name" field
3. OR click **Browse GPOs** to see a searchable list

**Option 2: Direct XML Path**

1. Click **Browse...** next to "Or Drives.xml Path:"
2. Navigate to: `\\domain\SysVol\domain\Policies\{GPO-GUID}\User\Preferences\Drives\Drives.xml`

#### Section B: Test Subjects

**Option 1: Specific Users** ✓ (Default)

1. Select "Specific Users" radio button
2. Enter usernames separated by commas: `alice, bob, charlie`
3. OR click **Browse AD** to search and select users

**Option 2: All Users in OU**

1. Select "All Users in OU" radio button
2. Enter the OU Distinguished Name:
   ```
   OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com
   ```
3. OR click **Browse AD** to navigate the OU tree

**Option 3: Simulated Users**

1. Select "Simulated Users" radio button
2. Click **Configure** to switch to the Simulated Users tab
3. Add hypothetical users for testing (see Tab 6 below)

#### Section C: Options

- ☑ **Show detailed filter evaluation trace** - Check this to see step-by-step filter logic (useful for debugging)

#### Section D: Actions

- **▶ Run Validation** - Execute the validation (hotkey: Enter)
- **✖ Clear Results** - Clear all results and reset
- **📊 Export to CSV** - Save results to CSV file (enabled after validation)

---

### Tab 2: Results

After running validation, this tab displays:

#### Summary Cards (Top Row)

- **Total Mappings** - Number of drive mapping evaluations performed
- **Users Tested** - Number of unique users tested
- **Conflicts** - Number of drive letter conflicts detected
- **Warnings** - Number of filters that couldn't be verified

#### Results Grid

Columns:
- **User** - Username or label
- **Drive** - Drive letter (e.g., H:, S:)
- **Path** - UNC path (e.g., \\fileserver\share)
- **Label** - Drive label/description
- **Action** - GPP action (U=Update, C=Create, R=Replace, D=Delete)
- **Applies** - ✓ if this drive will be mapped for this user
- **Disabled** - ✓ if the drive is disabled in the GPO

**Interpreting Results**:
- ✓ Applies + ✗ Disabled = User is in the filter scope, but drive is disabled (won't be mapped)
- ✓ Applies + ✗ Disabled = Drive WILL be mapped
- ✗ Applies = Drive will NOT be mapped (filters didn't match)

**Sorting**: Click column headers to sort

---

### Tab 3: Conflicts

Shows drive letter conflicts where a single user would receive multiple mappings for the same drive letter.

#### Conflicts Grid

Columns:
- **User** - Username experiencing the conflict
- **Drive Letter** - The conflicting letter (e.g., T:)
- **Conflicting Paths** - All paths that evaluate to TRUE, separated by |
- **Count** - Number of conflicting mappings

**Example**:
```
User: alice
Drive Letter: T:
Conflicting Paths: \\fileserver\finance | \\fileserver\temp
Count: 2
```

**What happens in production?**
The actual mapped drive is **non-deterministic** - it depends on GPO processing order, which can vary between logons.

**How to fix**:
1. Use different drive letters
2. Add mutually exclusive filters (e.g., NOT in Group X)
3. Split into separate GPOs with security filtering
4. Disable one of the conflicting mappings

---

### Tab 4: Filter Trace

Debug individual filter evaluations step-by-step.

#### Controls

1. **Filter for:** (User dropdown) - Select a user
2. (Drive dropdown) - Select a drive letter
3. **Refresh** - Reload trace for selected user/drive

#### Trace Output (Console-style)

Example output:
```
Drive T: (\\fileserver\finance) evaluated for 'alice':
  No item-level targeting filters present -> applies to ALL users.
```

Or with filters:
```
Drive T: (\\fileserver\finance) evaluated for 'alice':
  FilterGroup 'CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com' -> user-member:True computer-member:False
  FilterOrgUnit 'OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com' -> True (subject DN: CN=Alice Smith,OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com)
  FilterGroup 'CN=Contractors,OU=Groups,DC=corp,DC=contoso,DC=com' -> user-member:False computer-member:False
  (NOT applied -> True)
```

**Reading the trace**:
- Each filter shows its evaluation (True/False)
- "(NOT applied -> X)" means the filter's result was inverted
- The final result determines if "Applies" is True or False

---

### Tab 5: Warnings

Lists filters that couldn't be fully evaluated offline.

#### Common Warnings

**"FilterComputer ... no ComputerName supplied"**
- **Cause**: User tested without specifying which computer they log on to
- **Fix**: 
  - Use simulated users with ComputerName property
  - OR provide `-ComputerNameOverride` in CLI mode
- **Impact**: Computer-based filters (computer groups, computer name matching) default to FALSE

**"FilterSite ... no Site supplied"**
- **Cause**: User tested without AD site information
- **Fix**: Use simulated users with Site property
- **Impact**: Site-based filters default to FALSE

**"FilterLdapQuery ... cannot be verified for simulated subjects"**
- **Cause**: LDAP queries require real AD objects
- **Fix**: Test with live AD users instead
- **Impact**: Query filters default to FALSE for simulated users

**"Unsupported filter type ... WMI/Battery/Date/etc"**
- **Cause**: These filter types require runtime evaluation on the actual client
- **Fix**: Manually test after GPO deployment
- **Impact**: Filter defaults to FALSE in validation (conservative approach)

⚠ **Important**: Any "Applies = True" result involving warned filters should be manually verified before production deployment.

---

### Tab 6: Simulated Users

Create hypothetical users for testing scenarios that don't exist in AD yet.

#### Grid Columns

- **Name** - Display label (e.g., "FutureContractor01")
- **Distinguished Name** - Where the user would live (e.g., OU=Contractors,DC=corp,DC=contoso,DC=com)
- **Member Of Groups** - Group DNs separated by semicolons
- **Computer** - Computer name for computer-based filters
- **Site** - AD site name

#### Actions

- **➕ Add User** - Add a new blank row
- **➖ Remove Selected** - Delete the selected user
- **📄 Load Template** - Load a predefined template (future feature)

#### Example Simulated User

```
Name: TestContractor
Distinguished Name: OU=Contractors,OU=Users,DC=corp,DC=contoso,DC=com
Member Of Groups: CN=VPN-Users,OU=Groups,DC=corp,DC=contoso,DC=com;CN=Contractors,OU=Groups,DC=corp,DC=contoso,DC=com
Computer: LAPTOP-CTR-01
Site: RemoteSite
```

**Use cases**:
- Test planned OU restructuring
- Verify contractor vs. employee differential access
- Test site-based filtering for remote offices
- Validate group membership scenarios before creating accounts

---

## Command-Line Usage

For automation, scripting, and CI/CD integration.

### Basic Syntax

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "<GPO Name>" `
    -Domain "<domain.com>" `
    -TargetUsers user1, user2, user3
```

### Parameters Reference

#### GPO Source (choose one)

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-GpoName` | GPO display name | `"Mapped Drives - Finance"` |
| `-DrivesXmlPath` | Direct path to Drives.xml | `"\\corp.contoso.com\SysVol\...\Drives.xml"` |
| `-Domain` | Domain FQDN (auto-detected if omitted) | `"corp.contoso.com"` |

#### Test Subjects (choose one)

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-TargetUsers` | Array of usernames | `alice, bob, charlie` |
| `-TargetOU` | OU Distinguished Name (recursive) | `"OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com"` |
| `-SimulatedUsers` | Array of hashtables (see below) | `@( @{Name="Test"; ...} )` |

#### Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-ComputerNameOverride` | Hashtable of user->computer | `@{}` |
| `-ExportCsvPath` | CSV export path | (no export) |
| `-ShowFilterTrace` | Show detailed trace | `$false` |
| `-ReturnObject` | Return results object (for automation) | `$false` |

### Example 1: Test Specific Users

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - All Users" `
    -TargetUsers alice, bob, charlie, david
```

### Example 2: Test Entire OU with Export

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetOU "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com" `
    -ExportCsvPath "C:\Reports\finance-validation-$(Get-Date -Format 'yyyyMMdd').csv"
```

### Example 3: Debug Filter Logic

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Complex" `
    -TargetUsers alice `
    -ShowFilterTrace
```

Output:
```
Drive T: (\\fileserver\finance) evaluated for 'alice':
  FilterGroup 'CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com' -> user-member:True computer-member:False
  FilterOrgUnit 'OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com' -> True (subject DN: CN=Alice Smith,OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com)
...
```

### Example 4: Simulated Users

```powershell
$simUsers = @(
    @{
        Name = "TestContractor"
        DistinguishedName = "OU=Contractors,OU=Users,DC=corp,DC=contoso,DC=com"
        MemberOfGroups = @(
            "CN=VPN-Users,OU=Groups,DC=corp,DC=contoso,DC=com",
            "CN=Contractors,OU=Groups,DC=corp,DC=contoso,DC=com"
        )
        ComputerName = "LAPTOP-CTR-01"
        Site = "RemoteSite"
    },
    @{
        Name = "TestEmployee"
        DistinguishedName = "OU=Employees,OU=Users,DC=corp,DC=contoso,DC=com"
        MemberOfGroups = @(
            "CN=Domain Users,CN=Users,DC=corp,DC=contoso,DC=com",
            "CN=Employees,OU=Groups,DC=corp,DC=contoso,DC=com"
        )
        ComputerName = "DESKTOP-EMP-01"
        Site = "HQ"
    }
)

.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - All Users" `
    -SimulatedUsers $simUsers `
    -ShowFilterTrace
```

### Example 5: Computer Context

```powershell
$computerMapping = @{
    "alice" = "DESKTOP-FIN-01"
    "bob" = "LAPTOP-FIN-02"
    "charlie" = "DESKTOP-FIN-03"
}

.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetUsers alice, bob, charlie `
    -ComputerNameOverride $computerMapping
```

### Example 6: Automated Validation Script

```powershell
# validation-pipeline.ps1

$gpoName = "Mapped Drives - Finance"
$targetOU = "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com"

Write-Host "Validating GPO: $gpoName" -ForegroundColor Cyan

$result = .\Test-GpoDriveMapTargeting.ps1 `
    -GpoName $gpoName `
    -TargetOU $targetOU `
    -ReturnObject

Write-Host "`nValidation Results:" -ForegroundColor Yellow
Write-Host "  Users Tested: $(($result.Results | Select-Object -Unique Subject).Count)"
Write-Host "  Total Evaluations: $($result.Results.Count)"
Write-Host "  Conflicts: $(if ($result.Conflicts) { $result.Conflicts.Count } else { 0 })"
Write-Host "  Warnings: $(if ($result.Warnings) { $result.Warnings.Count } else { 0 })"

if ($result.Conflicts -and $result.Conflicts.Count -gt 0) {
    Write-Host "`n❌ VALIDATION FAILED: Drive letter conflicts detected" -ForegroundColor Red
    foreach ($conflict in $result.Conflicts) {
        Write-Host "   $($conflict.Name): $($conflict.Count) conflicting mappings" -ForegroundColor Red
    }
    exit 1
}

if ($result.Warnings -and $result.Warnings.Count -gt 0) {
    Write-Host "`n⚠ WARNING: Some filters could not be fully verified" -ForegroundColor Yellow
    foreach ($warning in $result.Warnings) {
        Write-Host "   $warning" -ForegroundColor Yellow
    }
}

Write-Host "`n✓ VALIDATION PASSED" -ForegroundColor Green
exit 0
```

---

## Common Scenarios

### Scenario 1: Pre-Deployment Validation

**Goal**: Validate a new GPO before linking to production OUs.

**Steps**:
1. Create GPO with drive mappings and ILT filters
2. DO NOT link to any OUs yet
3. Run validation against representative users from target OU
4. Review conflicts and warnings
5. Fix issues and re-validate
6. Once clean, link GPO to production

**Command**:
```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "NEW - Mapped Drives - Sales" `
    -TargetOU "OU=Sales,OU=Users,DC=corp,DC=contoso,DC=com" `
    -ExportCsvPath "C:\Validation\sales-predeployment.csv"
```

---

### Scenario 2: Audit Existing GPO

**Goal**: Understand which users are receiving which drives from an existing GPO.

**Steps**:
1. Identify the GPO name
2. Identify the linked OUs
3. Run validation against all users in those OUs
4. Export results for documentation

**Command**:
```powershell
# Audit Finance GPO
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetOU "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com" `
    -ExportCsvPath "C:\Audit\finance-$(Get-Date -Format 'yyyyMMdd').csv"

# Audit HR GPO
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - HR" `
    -TargetOU "OU=HR,OU=Users,DC=corp,DC=contoso,DC=com" `
    -ExportCsvPath "C:\Audit\hr-$(Get-Date -Format 'yyyyMMdd').csv"
```

---

### Scenario 3: Troubleshoot User Complaint

**Goal**: User reports not receiving expected drive mapping (or receiving wrong one).

**Steps**:
1. Identify which GPO(s) apply to the user
2. Run validation for that specific user with `-ShowFilterTrace`
3. Review filter evaluation to see why drive didn't apply (or did apply)

**Command**:
```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetUsers jsmith `
    -ShowFilterTrace
```

**Analysis**:
- Check each filter's TRUE/FALSE evaluation
- Verify group memberships are correct
- Verify user's OU is expected
- Check for NOT operators that might be blocking

---

### Scenario 4: Plan OU Restructure

**Goal**: Test how drive mappings will be affected by moving users to new OUs.

**Steps**:
1. Create simulated users with the NEW OU paths (but existing group memberships)
2. Run validation against all relevant GPOs
3. Compare results to current state
4. Identify users who will lose or gain drives

**Command**:
```powershell
# Load current users from old OU
$currentUsers = Get-ADUser -SearchBase "OU=OldDept,OU=Users,DC=corp,DC=contoso,DC=com" -Filter * -Properties MemberOf

# Simulate them in new OU
$simulatedUsers = @()
foreach ($user in $currentUsers) {
    $simulatedUsers += @{
        Name = $user.SamAccountName
        DistinguishedName = "CN=$($user.Name),OU=NewDept,OU=Users,DC=corp,DC=contoso,DC=com"  # NEW OU
        MemberOfGroups = $user.MemberOf  # Keep current groups
    }
}

# Test all drive mapping GPOs
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - All Users" `
    -SimulatedUsers $simulatedUsers `
    -ExportCsvPath "C:\Migration\newou-impact-analysis.csv"
```

---

### Scenario 5: Contractor vs. Employee Differential

**Goal**: Verify contractors don't receive employee-only drives.

**Steps**:
1. Get list of all contractors
2. Run validation against "employee-only" GPOs
3. Expected result: All contractors show "Applies = False" for all drives (or only contractor-approved drives)

**Command**:
```powershell
# Get all contractors
$contractors = Get-ADUser -Filter {employeeType -eq "Contractor"} -Properties employeeType

# Test against employee GPO
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Employees Only" `
    -TargetUsers $contractors.SamAccountName `
    -ExportCsvPath "C:\Security\contractor-access-check.csv"
```

**Analysis**:
- If ANY contractor shows "Applies = True" for any employee-only drive, this is a security issue
- Review ILT filters and add explicit "NOT in Contractors group" filter

---

### Scenario 6: Multi-GPO Aggregate Testing

**Goal**: User receives drives from multiple GPOs - test aggregate result.

**Steps**:
1. Identify all GPOs that apply to the user
2. Run validation for each GPO separately
3. Combine results to see total drives
4. Check for conflicts across GPOs

**Command**:
```powershell
$user = "jsmith"
$gpos = @("Mapped Drives - All Users", "Mapped Drives - Finance", "Mapped Drives - Managers")

$allResults = @()

foreach ($gpo in $gpos) {
    $result = .\Test-GpoDriveMapTargeting.ps1 `
        -GpoName $gpo `
        -TargetUsers $user `
        -ReturnObject
    
    $allResults += $result.Results | Where-Object { $_.Applies -and -not $_.IsDisabled }
}

# Check for conflicts across GPOs
$conflicts = $allResults | Group-Object DriveLetter | Where-Object { $_.Count -gt 1 }

if ($conflicts) {
    Write-Host "❌ CONFLICTS DETECTED across multiple GPOs:" -ForegroundColor Red
    foreach ($conflict in $conflicts) {
        Write-Host "  Drive $($conflict.Name):" -ForegroundColor Red
        foreach ($item in $conflict.Group) {
            Write-Host "    $($item.Path)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "✓ No conflicts - user will receive:" -ForegroundColor Green
    $allResults | ForEach-Object {
        Write-Host "  $($_.DriveLetter)  $($_.Path)" -ForegroundColor Cyan
    }
}
```

---

## Understanding Results

### Output Sections

#### 1. Summary Section

```
=================== SUMMARY: Who receives which drive ===================

alice:
  H:  \\fileserver\home\alice   (Home Drive)
  S:  \\fileserver\shared   (Shared)
  T:  \\fileserver\finance   (Finance Share)

bob:
  H:  \\fileserver\home\bob   (Home Drive)
  S:  \\fileserver\shared   (Shared)

charlie:
  (no drives mapped)
```

**Interpretation**:
- **alice**: Will receive H:, S:, and T: drives
- **bob**: Will receive H: and S: drives only
- **charlie**: Will not receive any drives (filters didn't match)

#### 2. Conflicts Section

```
=================== DRIVE-LETTER CONFLICTS ===================

CONFLICT: alice, T: - multiple mappings evaluate TRUE simultaneously:
   -> \\fileserver\finance  [Finance Share]
   -> \\fileserver\temp  [Temporary Storage]
```

**Interpretation**:
- alice will receive BOTH mappings for T: drive
- The actual result is **unpredictable** - depends on GPO processing order
- This MUST be fixed before deployment

**Resolution Options**:
1. **Change drive letters**: Make one of them use a different letter (e.g., U:)
2. **Add exclusion filters**: Add "NOT in Finance group" to the Temp mapping
3. **Separate GPOs**: Move to different GPOs with security filtering
4. **Disable one**: If one is obsolete, disable it in the GPO

#### 3. Filter Verification Section

```
=================== FILTERS THAT COULD NOT BE FULLY VERIFIED ===================
  - FilterComputer 'LAPTOP-01' for subject 'alice': no ComputerName supplied - defaulting to NOT matched.
  - FilterLdapQuery '(department=Finance)' for subject 'TestUser': cannot be verified for simulated subjects.
  - Unsupported filter type '<FilterWMI>' encountered - not evaluated. Defaulting to NOT matched; verify manually.
```

**Interpretation**:
- Some filters require information not available in offline validation
- Results involving these filters may be **conservative** (defaulting to FALSE)
- Manual verification required after deployment

---

### CSV Export Format

Exported CSV contains one row per user/drive combination:

| Subject | DriveLetter | Path | Label | Action | Applies | IsDisabled |
|---------|-------------|------|-------|--------|---------|------------|
| alice | H: | \\fileserver\home\alice | Home Drive | U | TRUE | FALSE |
| alice | S: | \\fileserver\shared | Shared | U | TRUE | FALSE |
| alice | T: | \\fileserver\finance | Finance | U | TRUE | FALSE |
| bob | H: | \\fileserver\home\bob | Home Drive | U | TRUE | FALSE |
| bob | S: | \\fileserver\shared | Shared | U | TRUE | FALSE |
| bob | T: | \\fileserver\finance | Finance | U | FALSE | FALSE |

**Using in Excel**:
- Filter by "Applies = TRUE" to see actual mappings
- Pivot on User to see drives per user
- Pivot on DriveLetter to see all users receiving a specific drive
- Filter by "IsDisabled = TRUE" to find disabled mappings

---

## Troubleshooting

### Issue: "Module not found" errors

**Symptoms**:
```
ActiveDirectory module not found and no -SimulatedUsers supplied.
```

**Cause**: RSAT PowerShell modules not installed

**Solutions**:

1. **Install RSAT** (preferred):
   ```powershell
   # Windows 10/11
   Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
   Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
   ```

2. **Use Simulated Users** (workaround):
   ```powershell
   # Define users manually without AD lookups
   $simUsers = @( @{ Name="TestUser"; DistinguishedName="..."; MemberOfGroups=@(...) } )
   .\Test-GpoDriveMapTargeting.ps1 -DrivesXmlPath "..." -SimulatedUsers $simUsers
   ```

3. **Remote PS Session** (alternative):
   ```powershell
   # Run from a domain controller that has modules
   Enter-PSSession -ComputerName DC01
   ```

---

### Issue: GPO not found

**Symptoms**:
```
Failed to retrieve GPO 'Mapped Drives - Finance' from domain 'corp.contoso.com'
```

**Causes & Solutions**:

1. **Typo in GPO name**
   - GPO names are case-sensitive
   - Use exact display name as shown in GPMC
   - Click "Browse GPOs" in GUI to search

2. **Wrong domain**
   - Verify domain FQDN is correct
   - Use `-Domain` parameter explicitly

3. **Permissions**
   - You need read access to GPOs
   - Typically granted via Domain Users membership
   - Run PowerShell with domain credentials

4. **GPO doesn't exist**
   - Verify in GPMC (Group Policy Management Console)
   - Check spelling and domain

**Workaround**: Use `-DrivesXmlPath` to specify XML directly:
```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -DrivesXmlPath "\\corp.contoso.com\SysVol\corp.contoso.com\Policies\{GUID}\User\Preferences\Drives\Drives.xml" `
    -TargetUsers alice
```

---

### Issue: Access denied to Drives.xml

**Symptoms**:
```
Access to the path '\\corp.contoso.com\SysVol\...\Drives.xml' is denied.
```

**Causes & Solutions**:

1. **Not authenticated to domain**
   ```powershell
   # Verify domain authentication
   whoami /groups | findstr /i domain
   ```

2. **SYSVOL permissions**
   - Authenticated Users should have Read access to SYSVOL
   - Contact domain admins if access denied

3. **Network connectivity**
   ```powershell
   # Test SYSVOL access
   Test-Path "\\$env:USERDNSDOMAIN\SysVol"
   ```

4. **Wrong path**
   - Computer-side drive maps are rare: `Computer\Preferences\Drives\Drives.xml`
   - User-side is standard: `User\Preferences\Drives\Drives.xml`

---

### Issue: User not receiving expected drive

**Symptoms**: Validation shows "Applies = False" but user should be in scope

**Debug Steps**:

1. **Run with filter trace**:
   ```powershell
   .\Test-GpoDriveMapTargeting.ps1 -GpoName "..." -TargetUsers alice -ShowFilterTrace
   ```

2. **Check each filter's evaluation**:
   - Group membership: Does user belong to the group?
     ```powershell
     Get-ADUser alice -Properties MemberOf | Select -Expand MemberOf
     ```
   - OU location: Is user in the correct OU?
     ```powershell
     Get-ADUser alice -Properties DistinguishedName
     ```
   - NOT operators: Is user being excluded by a "not=1" filter?

3. **Primary group issue**:
   - Tool includes primary group (usually Domain Users)
   - Verify manually if needed:
     ```powershell
     $user = Get-ADUser alice -Properties primaryGroupID
     $domain = Get-ADDomain
     "$($domain.DomainSID)-$($user.primaryGroupID)"  # Primary group SID
     ```

4. **Disabled mapping**:
   - Check "IsDisabled" column in results
   - Mapping might be disabled in the GPO

---

### Issue: Unexpected conflict

**Symptoms**: Conflict detected but mappings seem mutually exclusive

**Debug Steps**:

1. **Review both filter sets**:
   ```powershell
   .\Test-GpoDriveMapTargeting.ps1 -GpoName "..." -TargetUsers alice -ShowFilterTrace
   ```

2. **Check for missing exclusions**:
   - Example: "Finance group" and "Finance OU" might both match
   - Need explicit "NOT in Finance group" on one mapping

3. **Verify filter logic**:
   - AND vs. OR confusion
   - NOT operators missing or incorrect

4. **Test in isolation**:
   ```powershell
   # Test each conflicting drive separately
   # Temporarily disable one in the GPO, validate, then swap
   ```

---

### Issue: "Unsupported filter type" warning

**Symptoms**:
```
Unsupported filter type '<FilterWMI>' encountered - not evaluated
```

**Cause**: Some ILT filters require runtime client evaluation:
- **WMI queries** (OS version, installed software)
- **Date/Time ranges**
- **Battery present** (laptops vs desktops)
- **Disk space** / **RAM amount**

**Impact**:
- These filters default to FALSE in validation
- If drive shows "Applies = True" and involves unsupported filters, the real result may differ

**Solution**:
- Manual testing on actual client machines
- Deploy to pilot OU first
- Use `gpresult /H report.html` on client to verify

---

### Issue: GUI not launching

**Symptoms**: Nothing happens when running `GPO-DriveMap-Validator-GUI.ps1`

**Causes & Solutions**:

1. **Execution policy**:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

2. **.NET Framework missing**:
   - GUI requires .NET Framework 4.5+
   - Verify:
     ```powershell
     Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' | Get-ItemPropertyValue -Name Version
     ```

3. **WPF assemblies missing**:
   - Should be present on Windows 10+
   - Try running from PowerShell 5.1 (not PowerShell 7):
     ```powershell
     powershell.exe -File GPO-DriveMap-Validator-GUI.ps1
     ```

4. **Error during load**:
   - Run from PowerShell console (not double-click)
   - Check for error messages

---

### Issue: Simulated users not working as expected

**Symptoms**: Simulated users show unexpected results

**Common Mistakes**:

1. **Group DN format**:
   - Use full DN: `CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com`
   - NOT just the name: `Finance-Users`

2. **Multiple groups**:
   - In GUI: Separate with semicolons: `Group1;Group2;Group3`
   - In CLI: Use array: `@("Group1", "Group2")`

3. **OU vs user DN**:
   - DistinguishedName should be user's full DN: `CN=User Name,OU=Dept,DC=...`
   - NOT just the OU: `OU=Dept,DC=...`

4. **LDAP queries**:
   - Cannot be evaluated for simulated users
   - Will default to FALSE with warning

**Example of correct simulated user**:
```powershell
@{
    Name = "SimulatedUser"
    DistinguishedName = "CN=Test User,OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com"
    MemberOfGroups = @(
        "CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com",
        "CN=Domain Users,CN=Users,DC=corp,DC=contoso,DC=com"
    )
    ComputerName = "DESKTOP-01"
    Site = "HQ"
}
```

---

## Best Practices

1. **Always validate before production deployment**
   - Create GPO
   - Configure drive maps and filters
   - Validate against representative users
   - Fix conflicts and issues
   - Re-validate
   - Deploy

2. **Use representative test users**
   - Include users from each target group
   - Include edge cases (contractors, temps, etc.)
   - Include users from different OUs

3. **Export and archive results**
   - Keep CSV exports for documentation
   - Timestamp exports for audit trail
   - Compare before/after when modifying GPOs

4. **Check for conflicts across multiple GPOs**
   - Users may receive drives from multiple GPOs
   - Validate each GPO separately
   - Manually check for cross-GPO conflicts

5. **Document unverifiable filters**
   - Note WMI/Date/Battery filters that require manual testing
   - Create test plan for these scenarios
   - Verify in pilot deployment

6. **Regularly audit existing GPOs**
   - Quarterly review recommended
   - Verify filters still match intended users
   - Remove obsolete mappings
   - Check for creeping complexity

---

## Additional Resources

- **Item-Level Targeting Reference**: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11)
- **GPP Drive Maps**: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581925(v=ws.11)
- **Group Policy Troubleshooting**: Use `gpresult /H report.html` on client machines

---

**Document Version**: 1.0  
**Last Updated**: 2026-09-25  
**Tool Version**: 2.0

# GPO Drive Mapping Validator & Manager - Quick Start Guide

## 🚀 5-Minute Setup

### Step 1: Verify Prerequisites

Open PowerShell as Administrator and run:

```powershell
# Check PowerShell version (need 5.1+)
$PSVersionTable.PSVersion

# Check for RSAT modules
Get-Module -ListAvailable ActiveDirectory, GroupPolicy

# If modules are missing, install RSAT:
# Windows Server:
Install-WindowsFeature RSAT-AD-PowerShell, RSAT-GP-PowerShell

# Windows 10/11:
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online
Get-WindowsCapability -Name RSAT.GroupPolicy* -Online | Add-WindowsCapability -Online
```

### Step 2: Download Files

Ensure you have both files in the same directory:
- `GPO-DriveMap-Manager-v2-FULL.ps1` (GUI application)
- `Test-GpoDriveMapTargeting.ps1` (validation engine)

### Step 3: Launch

```powershell
cd C:\path\to\scripts
.\GPO-DriveMap-Manager-v2-FULL.ps1
```

The dark-themed GUI window should appear within 2-3 seconds.

---

## 🎯 Common Tasks

### Task 1: View Drive Mappings in a GPO

1. **Select Domain** from toolbar dropdown
2. **Select GPO** from toolbar dropdown (only GPOs with drive mappings are listed)
3. Click **Load GPO**
4. View mappings in the grid (Drive Letter, Path, Label, Filters)

**Time**: 30 seconds

---

### Task 2: Test If a User Will Get a Specific Drive

1. Load your GPO (see Task 1)
2. Go to **👤 User Validation** tab
3. Leave mode as "Single User (sAMAccountName)"
4. Enter the user's login name (e.g., `jdoe`)
5. Click **▶ Validate**
6. View **Results Summary** sub-tab:
   - `Applies = True` means the user WILL get the drive
   - `Applies = False` means the user will NOT get the drive

**Time**: 1 minute

**Troubleshooting**:
- If a drive shows `Applies = False`, go to **Filter Trace** sub-tab
- Read the step-by-step evaluation to see which filter failed

---

### Task 3: Find Drive Letter Conflicts

1. Load your GPO
2. Go to **👤 User Validation** tab
3. Select mode: "User List (comma-separated sAMAccountNames)"
4. Enter test users: `jdoe, msmith, acontractor`
5. Click **▶ Validate**
6. Go to **Conflicts** sub-tab
   - Green "✓ No conflicts detected" = safe to deploy
   - Red "⚠ X conflict(s) detected" = fix required

**Time**: 2 minutes

**Example Conflict**:
```
User: jdoe
Drive Letter: H:
Conflicting Paths: \\server\home | \\server\finance
```
This means user `jdoe` would get TWO mappings for `H:`, causing unpredictable behavior.

---

### Task 4: Understand Complex Filters

1. Load your GPO
2. Go to **🔍 Filter Inspector** tab
3. Click on any drive mapping in the left grid
4. Right panel shows the filter tree structure:

```
Drive: S:
Path: \\server\shared

=== FILTER TREE ===

[Collection] (bool=AND)
  [Group] 'Finance-Users' (bool=AND)
  [OrgUnit] 'OU=Finance,DC=corp,DC=com' (bool=AND)
```

This means: User must be in `Finance-Users` group **AND** in the Finance OU.

**Time**: 1 minute

---

### Task 5: Compare Two GPOs

1. Load your primary GPO
2. Go to **⚖ GPO Comparison** tab
3. Select a second GPO from the dropdown
4. Click **Compare**
5. Review the status column:
   - `Same`: Both GPOs have identical mappings for this letter
   - `Different`: Both GPOs use the letter but for different paths (⚠ CONFLICT)
   - `Only in Current`: Drive only exists in primary GPO
   - `Only in Compare`: Drive only exists in comparison GPO

**Use Case**: Identify conflicts before merging GPOs or linking multiple GPOs to the same OU.

**Time**: 1 minute

---

### Task 6: Test Adding a New Drive Mapping

1. Load your GPO
2. Go to **➕ Add Mapping Simulator** tab
3. Fill in the form:
   - **Drive Letter**: `K:`
   - **UNC Path**: `\\server\knowledge`
   - **Label**: `Knowledge Base`
   - **Action**: `Create`
   - **Target Users**: `jdoe, msmith`
4. Click **Simulate & Test for Conflicts**
5. Review results in the lower panel

**Example Safe Result**:
```
✓ No conflicts detected for the specified users.
The new mapping can be safely added.
```

**Example Conflict Result**:
```
⚠ WARNING: Drive letter K: already exists in this GPO

⚠ POTENTIAL CONFLICTS DETECTED:
The following users already receive drive K: from existing mappings:
   - jdoe: \\server\kiosk
```

**Time**: 2 minutes

---

## 📊 Reading the Results

### User Validation Results Grid

| Column | Meaning |
|--------|---------|
| **Subject** | User's sAMAccountName |
| **Drive Letter** | Which drive (e.g., `H:`, `S:`) |
| **Path** | UNC path (e.g., `\\server\share`) |
| **Applies** | `True` = user gets this drive, `False` = user does NOT get this drive |
| **IsDisabled** | `True` = mapping is disabled in the GPO (no one gets it) |

### Filter Trace Example

```
Drive H: (\\server\home) evaluated for 'jdoe':
  FilterGroup 'Domain-Users' -> user-member:True computer-member:False
  FilterOrgUnit 'OU=Employees,DC=corp,DC=com' -> True (subject DN: CN=John Doe,OU=Employees,DC=corp,DC=com)
  Result: TRUE (all filters passed)
```

**Interpretation**: User `jdoe` is in the `Domain-Users` group ✅ and is located in the `Employees` OU ✅, so they receive the `H:` drive.

### Conflict Detection

A conflict means **two or more drive mappings** target the same user with the same drive letter.

**Example**:
- Mapping 1: `H:` → `\\server\home` (targets all Domain Users)
- Mapping 2: `H:` → `\\server\finance` (targets Finance Users)
- User `jdoe` is in BOTH groups → CONFLICT on `H:`

**Resolution**: Change one of the drive letters or adjust filters so they're mutually exclusive.

---

## 🛠️ Troubleshooting

### "GUI doesn't launch"

1. Check you're NOT on Windows Server Core (needs GUI)
2. Verify WPF assemblies:
   ```powershell
   Add-Type -AssemblyName PresentationFramework
   ```
3. Look for error messages in the PowerShell console

### "No GPOs listed in dropdown"

- The combo box only shows GPOs with `Drives.xml` files
- Create a test GPO with User Preferences → Drive Maps configured
- Check permissions to `\\domain\SysVol`

### "Validation script not found"

- Ensure `Test-GpoDriveMapTargeting.ps1` is in the same folder as the GUI script
- Check the **Action Log** tab for the exact error

### "FilterComputer unverified" warning

- This is expected: computer-based filters require knowing which machine the user logs on to
- The GUI focuses on user-based filters
- Document computer-specific mappings separately

---

## 🏆 Best Practices

### Before Deploying a New GPO

1. Load the GPO in the GUI
2. Test with 3-5 representative users from each target group/OU
3. Check for conflicts (Conflicts sub-tab)
4. Review warnings (Warnings sub-tab)
5. Export results for approval documentation

### Monthly Audit

1. Load production GPOs one by one
2. Use GPO Comparison to identify overlaps
3. Test critical users (executives, service accounts)
4. Document any new warnings

### Change Requests

Before modifying a GPO:
1. Use Add Mapping Simulator to preview the change
2. Test against affected users
3. Take a screenshot of the simulation results for the change ticket
4. Re-validate after making changes in GPMC

---

## 📚 Learn More

- **Full Documentation**: See `README-GUI.md` for detailed feature descriptions
- **Validation Logic**: See `Test-GpoDriveMapTargeting.ps1` script comments for ILT evaluation rules
- **Dark Theme Customization**: Edit the `<Window.Resources>` section in the XAML

---

## ✅ Quick Validation Checklist

Before linking a GPO to production:

- [ ] Loaded GPO in GUI and reviewed all mappings
- [ ] Tested with at least 3 representative users
- [ ] No conflicts detected (green checkmark in Conflicts tab)
- [ ] Reviewed and acknowledged all warnings
- [ ] Used GPO Comparison to check for overlaps with other linked GPOs
- [ ] Documented results in change request
- [ ] Tested in pilot OU first (if applicable)

---

## 🆘 Support

If you encounter issues:

1. Check the **📋 Action Log** tab for detailed error messages
2. Run with verbose output:
   ```powershell
   $VerbosePreference = 'Continue'
   .\GPO-DriveMap-Manager-v2-FULL.ps1
   ```
3. Review the **Troubleshooting** section in `README-GUI.md`
4. Check PowerShell console output for stack traces

---

**Happy validating! 🎉**

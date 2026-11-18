# GPO Drive Mapping Validator & Manager - GUI Documentation

## Overview

**GPO-DriveMap-Manager-v2-FULL.ps1** is a production-ready Windows Presentation Foundation (WPF) GUI application for validating, testing, and managing Group Policy Preference (GPP) drive mappings with comprehensive Item-Level Targeting (ILT) filter evaluation.

## Quick Start

### Prerequisites

1. **Operating System**: Windows Server 2016/2019/2022 or Windows 10/11
2. **PowerShell**: Version 5.1 or higher
3. **RSAT Tools**: 
   - ActiveDirectory PowerShell module
   - GroupPolicy PowerShell module
4. **Dependencies**: `Test-GpoDriveMapTargeting.ps1` in the same directory

### Installation

```powershell
# 1. Ensure RSAT tools are installed
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online

# 2. Verify modules are available
Get-Module -ListAvailable ActiveDirectory, GroupPolicy

# 3. Place both scripts in the same directory
# - GPO-DriveMap-Manager-v2-FULL.ps1
# - Test-GpoDriveMapTargeting.ps1

# 4. Launch the GUI
.\GPO-DriveMap-Manager-v2-FULL.ps1
```

## User Interface

### Layout

```
┌─────────────────────────────────────────────────────────────┐
│  GPO Drive Mapping Validator    [Domain] [GPO] [Load] [🔄] │  <- Toolbar
├─────────────────────────────────────────────────────────────┤
│ 📁Drive │👤User │🔍Filter │⚖GPO    │➕Add   │📋Action │     <- Tabs
│  Mappings│Valid │Inspector│Compare │Simulator│Log     │
│                                                             │
│                                                             │
│                    [Tab Content Area]                       │
│                                                             │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ Ready                                          12:34:56     │  <- Status Bar
└─────────────────────────────────────────────────────────────┘
```

### Color Scheme (Dark Theme)

| Element | Color | Hex Code |
|---------|-------|----------|
| Background Deep | Dark Gray | `#1A1D23` |
| Background Panel | Medium Gray | `#22262E` |
| Background Card | Light Gray | `#2A2F3A` |
| Accent (Primary) | Blue | `#2196F3` |
| Success | Green | `#4CAF50` |
| Warning | Orange | `#FF9800` |
| Danger | Red | `#F44336` |
| Text Primary | Off-White | `#E8EAF0` |
| Text Secondary | Gray | `#9AA3B2` |

## Features Guide

### 1. Drive Mappings Tab 📁

**Purpose**: View all drive mappings configured in the selected GPO.

**Workflow**:
1. Select domain from toolbar dropdown
2. Select GPO from toolbar dropdown (filtered to show only GPOs with drive mappings)
3. Click **Load GPO**
4. View mappings in grid:
   - Drive Letter (e.g., `H:`, `S:`)
   - Path (UNC path like `\\server\share`)
   - Label (description)
   - Action (`Create`, `Update`, `Replace`, `Delete`)
   - State (`Enabled` or `Disabled`)
   - Has Filters (`Yes` or `No`)
   - Filter Summary (brief description of ILT filters)

**Use Cases**:
- Audit existing drive mappings
- Identify disabled mappings
- Review filter assignments at a glance

---

### 2. User Validation Tab 👤

**Purpose**: Test which users will receive which drive mappings based on Item-Level Targeting filters.

**Validation Modes**:

#### Mode 1: Single User (sAMAccountName)
```
Test Mode: Single User (sAMAccountName)
Input: jdoe

Result: Shows all drives that user 'jdoe' will receive
```

#### Mode 2: All Users in OU (Distinguished Name)
```
Test Mode: All Users in OU (Distinguished Name)
Input: OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com

Result: Tests all users under the Finance OU recursively
```

#### Mode 3: User List (comma-separated sAMAccountNames)
```
Test Mode: User List (comma-separated sAMAccountNames)
Input: jdoe, msmith, acontractor

Result: Tests multiple specified users
```

**Sub-Tabs**:

#### Results Summary
Tabular view of all test results:
- **User**: sAMAccountName or display name
- **Drive Letter**: Which drive letter
- **Path**: UNC path
- **Label**: Drive label
- **Applies**: `True` (user gets the drive) or `False` (user does NOT get the drive)
- **Disabled**: Whether the mapping is disabled in the GPO

#### Filter Trace
Step-by-step evaluation log for audit trails:
```
Drive H: (\\server\finance) evaluated for 'jdoe':
  FilterGroup 'Finance-Users' -> user-member:True computer-member:False
  (NOT applied -> False)
  FilterOrgUnit 'OU=Finance,DC=corp,DC=contoso,DC=com' -> True (subject DN: CN=John Doe,OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com)
```

#### Conflicts
Detects drive letter conflicts (multiple mappings for same user/letter):
```
⚠ 2 conflict(s) detected!

User: jdoe, Drive Letter: H:, Conflicting Paths: \\server\finance | \\server\home
```

#### Warnings
Lists filters that could not be fully verified:
```
⚠ FilterComputer 'WS-FINANCE-01' for subject 'jdoe': no ComputerName supplied - defaulting to NOT matched.
⚠ FilterLdapQuery '(department=Finance)' for subject 'contractor01': cannot be verified for simulated subjects.
```

**Use Cases**:
- Pre-deployment validation ("Will this user get the correct drives?")
- Troubleshooting ("Why isn't this user getting the H: drive?")
- Conflict detection before linking GPO
- Compliance auditing

---

### 3. Filter Inspector Tab 🔍

**Purpose**: Deep-dive into Item-Level Targeting filter tree structure.

**Workflow**:
1. Select a drive mapping from the left grid
2. View detailed filter tree in the right panel

**Filter Tree Example**:
```
Drive: H:
Path: \\server\finance

=== FILTER TREE ===

[Collection] (bool=AND)
  [Group] 'CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com' (bool=AND)
  [OrgUnit] 'OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com' (bool=AND)
  [Collection] (bool=OR)
    [User] 'jdoe' (bool=OR)
    [User] 'msmith' (bool=OR)
```

**Filter Types Supported**:
- `FilterGroup`: AD security group membership (user or computer)
- `FilterUser`: Specific user SID/sAMAccountName
- `FilterComputer`: Specific computer name
- `FilterOrgUnit`: AD Organizational Unit (with recursive sub-OU matching)
- `FilterSite`: AD site name
- `FilterLdapQuery`: Custom LDAP filter
- `FilterCollection`: Nested AND/OR group (parentheses in boolean logic)

**Attributes**:
- `bool="AND"|"OR"`: How this filter combines with the running result
- `not="1"`: Negate this filter's result (logical NOT)

**Use Cases**:
- Understanding complex filter logic
- Documentation and knowledge transfer
- Debugging filter evaluation behavior

---

### 4. GPO Comparison Tab ⚖

**Purpose**: Compare drive mappings between two GPOs to identify conflicts or differences.

**Workflow**:
1. Load a GPO (becomes the "Current GPO")
2. Select another GPO from the comparison dropdown
3. Click **Compare**
4. View side-by-side comparison grid:
   - **Drive Letter**: Letter being compared
   - **Current GPO Path**: Path in the loaded GPO
   - **Compare GPO Path**: Path in the comparison GPO
   - **Status**: 
     - `Same`: Both GPOs map the same path
     - `Different`: Both GPOs have the letter but different paths
     - `Only in Current`: Drive exists only in loaded GPO
     - `Only in Compare`: Drive exists only in comparison GPO

**Example Output**:
```
Drive Letter | Current GPO Path    | Compare GPO Path     | Status
-------------|---------------------|----------------------|----------------
H:           | \\srv\home          | \\srv\home           | Same
S:           | \\srv\finance       | \\srv\accounting     | Different
P:           | \\srv\projects      | (null)               | Only in Current
T:           | (null)              | \\srv\temp           | Only in Compare
```

**Use Cases**:
- Merging GPOs (identify unique mappings)
- Detecting overlapping drive letter assignments
- GPO consolidation planning
- Change impact analysis

---

### 5. Add Mapping Simulator Tab ➕

**Purpose**: Simulate adding a new drive mapping to the current GPO and test for conflicts.

**Workflow**:
1. Enter new mapping details:
   - **Drive Letter**: e.g., `K:`
   - **UNC Path**: e.g., `\\server\newshare`
   - **Label**: e.g., `Knowledge Base`
   - **Action**: `Create`, `Update`, `Replace`, or `Delete`
   - **Target Users**: Comma-separated sAMAccountNames to test against
2. Click **Simulate & Test for Conflicts**
3. View simulation results in the lower panel

**Example Result**:
```
=== ADD MAPPING SIMULATION ===
Drive Letter: K:
Path: \\server\kb
Label: Knowledge Base
Action: Create

⚠ WARNING: Drive letter K: already exists in this GPO:
   Current Path: \\server\kiosk
   Current Label: Kiosk Files
   Current State: Enabled

=== CONFLICT TESTING ===
Testing against users: jdoe, msmith

⚠ POTENTIAL CONFLICTS DETECTED:
The following users already receive drive K: from existing mappings:
   - jdoe: \\server\kiosk
   - msmith: \\server\kiosk

Adding this new mapping will create a drive letter conflict!
```

**Use Cases**:
- Pre-change validation (test before modifying GPO)
- Impact analysis ("Who will be affected by this new mapping?")
- Conflict prevention
- Documentation for change requests

---

### 6. Action Log Tab 📋

**Purpose**: Real-time activity log with timestamped entries.

**Log Levels**:
- **INFO**: General informational messages (e.g., "Loading GPOs...")
- **SUCCESS**: Successful operations (e.g., "Loaded 12 drive mappings")
- **WARNING**: Non-critical issues (e.g., "No filters found")
- **ERROR**: Failures (e.g., "Failed to load GPO: Access denied")

**Features**:
- Auto-scroll to latest entry
- Color-coded severity levels
- Timestamp format: `yyyy-MM-dd HH:mm:ss`
- **Clear Log** button to reset

**Example Log**:
```
Timestamp            | Level   | Message
---------------------|---------|----------------------------------------
2026-09-25 14:32:15 | SUCCESS | Application started
2026-09-25 14:32:16 | INFO    | Loading available domains...
2026-09-25 14:32:17 | SUCCESS | Loaded 3 domain(s)
2026-09-25 14:32:18 | INFO    | Loading GPOs from domain: corp.contoso.com
2026-09-25 14:32:21 | SUCCESS | Loaded 8 GPO(s) with drive mappings
2026-09-25 14:32:35 | INFO    | Loading drive mappings from GPO: Mapped Drives - Finance
2026-09-25 14:32:36 | SUCCESS | Loaded 5 drive mapping(s) from GPO: Mapped Drives - Finance
```

**Use Cases**:
- Troubleshooting errors
- Auditing user actions
- Performance monitoring

---

## Status Bar

### Left Side
- **Status Message**: Current operation status
  - "Ready" (green) - idle
  - "Loading GPOs..." (orange) - in progress
  - "Validation complete" (green) - success
  - "Failed to load GPO" (red) - error

### Right Side
- **Clock**: Live clock in `HH:mm:ss` format (updates every second)

---

## Architecture Details

### Script Structure

```
GPO-DriveMap-Manager-v2-FULL.ps1
│
├─ [Assembly Loading]
│  └─ PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms
│
├─ [Module Validation]
│  ├─ Test-RequiredModules()
│  └─ Import ActiveDirectory and GroupPolicy modules
│
├─ [XAML Definition] (~400 lines)
│  ├─ Window resources (colors, styles)
│  ├─ Control templates (Button, TextBox, ComboBox, DataGrid, TabControl)
│  └─ Layout (Grid, StackPanel, Border)
│
├─ [Action Log Functions]
│  ├─ Write-ActionLog()
│  └─ Update-StatusBar()
│
├─ [Core GPO Functions]
│  ├─ Load-AvailableDomains()
│  ├─ Load-AvailableGpos()
│  ├─ Test-GpoHasDriveMappings()
│  ├─ Load-GpoDriveMappings()
│  ├─ Get-FilterSummary()
│  ├─ Update-GpoInfoDisplay()
│  └─ Load-ComparisonGpoList()
│
├─ [Validation Engine]
│  └─ Invoke-UserValidation() -> calls Test-GpoDriveMapTargeting.ps1 with -ReturnObject
│
├─ [GPO Comparison]
│  └─ Invoke-GpoComparison()
│
├─ [Add Mapping Simulator]
│  └─ Invoke-AddMappingSimulation()
│
├─ [Event Handlers]
│  ├─ Initialize-EventHandlers()
│  ├─ ComboDomain.SelectionChanged
│  ├─ BtnLoadGpo.Click
│  ├─ BtnRefresh.Click
│  ├─ BtnRunValidation.Click
│  ├─ BtnCompare.Click
│  ├─ BtnSimulateAdd.Click
│  ├─ BtnClearLog.Click
│  ├─ GridFilterInspectorDrives.SelectionChanged
│  └─ Format-FilterTreeRecursive()
│
└─ [Main Window Initialization]
   ├─ XamlReader.Load()
   ├─ Initialize-EventHandlers()
   ├─ Window.Loaded (startup logic)
   ├─ Window.Closing (cleanup)
   └─ Window.ShowDialog()
```

### Thread Safety

All UI updates use the **Dispatcher.Invoke** pattern:

```powershell
$script:Window.Dispatcher.Invoke([action]{
    # UI update code here
    $control.Text = "New Value"
    $collection.Add($item)
})
```

This ensures thread-safe execution and prevents cross-thread access violations.

### Data Binding

Uses **ObservableCollection** for automatic UI refresh:

```powershell
$script:MappingsData = New-Object System.Collections.ObjectModel.ObservableCollection[object]
$gridMappings.ItemsSource = $script:MappingsData

# Any changes to $script:MappingsData automatically update the DataGrid
$script:MappingsData.Add($newMapping)
```

### Integration with Test-GpoDriveMapTargeting.ps1

The validation engine is invoked via:

```powershell
$params = @{
    DrivesXmlPath = $script:LoadedGpo.XmlPath
    Domain = $script:LoadedGpo.Domain
    TargetUsers = @('jdoe', 'msmith')
    ReturnObject = $true
}

$result = & $scriptPath @params

# $result structure:
# - Results: array of per-user/per-drive evaluation results
# - Conflicts: grouped conflicts (multiple mappings for same user/letter)
# - Warnings: unverifiable filters
# - XmlPath: path to Drives.xml
```

---

## Troubleshooting

### Issue: GUI Does Not Launch

**Symptoms**: Script runs but no window appears, or hangs indefinitely.

**Solutions**:
1. Verify WPF assemblies load successfully:
   ```powershell
   Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
   ```
2. Check for XAML parsing errors:
   ```powershell
   [xml]$xaml = Get-Content .\xaml-fragment.xml -Raw
   ```
3. Ensure you're running in a **graphical session** (not Windows Server Core without GUI)
4. Check for module import failures in the console output

### Issue: "Required RSAT modules not found"

**Solution**:
```powershell
# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell, RSAT-GP-PowerShell

# Windows 10/11
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online
Get-WindowsCapability -Name RSAT.GroupPolicy* -Online | Add-WindowsCapability -Online
```

### Issue: "Validation script not found"

**Solution**:
Ensure `Test-GpoDriveMapTargeting.ps1` is in the same directory as `GPO-DriveMap-Manager-v2-FULL.ps1`.

```powershell
# Check script location
Get-ChildItem .\Test-GpoDriveMapTargeting.ps1

# If missing, download from repository
```

### Issue: No GPOs Listed

**Solution**:
The combo box only shows GPOs that have a `Drives.xml` file:
```
\\domain\SysVol\domain\Policies\{GUID}\User\Preferences\Drives\Drives.xml
```

If no GPOs appear:
1. Verify you have GPOs with User Preferences → Drive Maps configured
2. Check permissions to `\\domain\SysVol`
3. Try a different domain (if in multi-domain forest)

### Issue: Validation Returns "Access Denied"

**Solution**:
- Run as a user with AD read permissions
- Ensure you can query AD users/groups:
  ```powershell
  Get-ADUser -Identity jdoe
  Get-ADGroup -Identity "Finance-Users"
  ```

### Issue: Filter Trace Shows "FilterComputer unverified"

**Explanation**: Computer-based filters require knowing which computer the user is logging on to.

**Solution**:
This is expected behavior. The GUI tests user-based filters only. For computer-based filters:
1. Use the CLI version of `Test-GpoDriveMapTargeting.ps1` with `-ComputerNameOverride` parameter
2. Document computer-specific mappings separately

---

## Performance Considerations

### Large OU Queries
Testing "All Users in OU" for a large OU (thousands of users) can take several minutes.

**Mitigation**:
- Start with a small test OU
- Use "User List" mode for targeted testing
- Consider exporting results to CSV for batch analysis

### Forest with Many Domains
Domain enumeration queries the entire forest.

**Mitigation**:
- Manual domain selection (bypasses forest query)
- Edit the script to default to specific domains only

### GPO Enumeration
`Get-GPO -All` can be slow in large environments.

**Mitigation**:
- The script filters to only GPOs with `Drives.xml` (reduces list size)
- Results are cached until **Refresh** is clicked

---

## Customization

### Color Scheme
Edit the `<Window.Resources>` section in the XAML:

```xml
<SolidColorBrush x:Key="Accent" Color="#2196F3"/>  <!-- Blue -->
<!-- Change to: -->
<SolidColorBrush x:Key="Accent" Color="#9C27B0"/>  <!-- Purple -->
```

### Default Domain
Edit the script parameter:

```powershell
$script:CurrentDomain = "corp.contoso.com"  # Hardcode your domain
```

### Add Custom Tabs
1. Add a new `<TabItem>` in the XAML `<TabControl>`
2. Create corresponding event handlers in the `Initialize-EventHandlers` function
3. Implement backend logic in a new function

### Export Formats
Currently supports CSV export from the CLI script. To add Excel export:

```powershell
# Requires ImportExcel module
Install-Module ImportExcel -Scope CurrentUser

# In Invoke-UserValidation function:
$script:ValidationResults | Export-Excel -Path "C:\temp\report.xlsx" -AutoSize
```

---

## Security Notes

### Read-Only
This GUI is **READ-ONLY** by design. It never modifies:
- Active Directory objects
- Group Policy Objects
- `Drives.xml` files

### Credentials
Uses the current user's credentials (pass-through authentication to AD and SysVol).

### Audit Trail
All actions are logged in the Action Log tab with timestamps.

---

## Best Practices

### Pre-Deployment Workflow
1. Load GPO in **Drive Mappings** tab (review existing mappings)
2. Use **Filter Inspector** tab (understand filter logic)
3. Run **User Validation** tab with test users (verify targeting)
4. Check **Conflicts** sub-tab (resolve before linking)
5. Use **GPO Comparison** tab (check for overlaps with other GPOs)
6. Document results from **Action Log** tab

### Change Management
1. Before modifying a GPO, use **Add Mapping Simulator** tab
2. Test against representative users from each department/OU
3. Export validation results to CSV for approval workflow
4. Re-validate after making changes

### Troubleshooting Workflow
1. User reports "Missing drive letter"
   - Load the GPO in GUI
   - Use **User Validation** tab with their sAMAccountName
   - Check **Filter Trace** sub-tab for evaluation details
   - Review **Warnings** sub-tab for unverifiable filters

2. Multiple users report "Wrong drive path"
   - Use **GPO Comparison** tab to check for overlapping GPOs
   - Use **Conflicts** sub-tab to detect multiple mappings

---

## Version History

### v2.0 (2026-09-25)
- Initial production release
- Full WPF GUI with 6 tabs
- Dark theme with modern styling
- Integrated validation engine (`Test-GpoDriveMapTargeting.ps1`)
- Thread-safe dispatcher pattern
- Real-time action logging
- GPO comparison and add mapping simulation
- Windows Server 2022 compatibility validated

---

## Support

### Prerequisites Checklist
- [ ] PowerShell 5.1 or higher
- [ ] RSAT ActiveDirectory module installed
- [ ] RSAT GroupPolicy module installed
- [ ] Both scripts in the same directory
- [ ] Running as user with AD read permissions
- [ ] Graphical Windows environment (not Server Core)

### Debugging
Run with verbose output:
```powershell
$VerbosePreference = 'Continue'
.\GPO-DriveMap-Manager-v2-FULL.ps1
```

Check the console window for detailed error messages and stack traces.

---

## License

Same license as the parent repository. See `LICENSE` file.

---

## Credits

- **Architecture Reference**: `DHCP-Manager-v2-FULL.ps1` by Anthony Blake (proven WPF patterns for Windows Server 2022)
- **Validation Engine**: `Test-GpoDriveMapTargeting.ps1` (ILT filter evaluation with AD integration)

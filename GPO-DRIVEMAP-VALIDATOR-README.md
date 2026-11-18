# GPO Drive Mapping Validator

A modern, feature-rich PowerShell-based tool for validating Group Policy Preference (GPP) drive mappings and their Item-Level Targeting (ILT) filters **before** deployment to production.

## 🎯 Overview

Group Policy Preferences for drive mappings are powerful but complex. Item-Level Targeting filters can involve:
- AD Security Group membership (user and computer)
- Specific users or computers
- Organizational Units (with recursive sub-OU matching)
- AD Sites
- Custom LDAP queries
- Complex nested AND/OR logic with negation

**This tool validates your GPO drive mapping configuration against real AD data BEFORE you link or enable the GPO**, preventing production issues like:
- Users receiving wrong drive mappings
- Drive letter conflicts (multiple mappings to the same letter)
- Filters that never evaluate TRUE for anyone
- Unintended access to sensitive shares

## ✨ Features

### Core Validation Engine
- **Accurate ILT parsing**: Mirrors the GPP client-side extension's sequential left-to-right AND/OR evaluation logic
- **Live AD integration**: Tests against real user accounts, groups, and OUs
- **Simulated users**: Test hypothetical scenarios without creating test accounts
- **Comprehensive filter support**: Groups, Users, Computers, OUs, Sites, LDAP queries, nested collections
- **Conflict detection**: Identifies drive letter conflicts per user
- **Trace mode**: See step-by-step filter evaluation for debugging

### Modern GUI
- **WPF-based interface**: Professional, responsive design
- **Real-time validation**: Progress indicators and status updates
- **Multiple input modes**: Select GPO by name, browse SysVol, or load Drives.xml directly
- **Results dashboard**: Visual summary cards showing totals, conflicts, and warnings
- **Interactive data grids**: Sortable, filterable results with detailed views
- **Filter trace viewer**: Debug individual filter evaluations
- **CSV export**: Full results export for documentation and analysis
- **Simulated user designer**: Build and test hypothetical scenarios

### Enterprise-Ready
- **Read-only**: Never modifies GPOs, AD, or XML files
- **Comprehensive error handling**: Clear error messages and recovery
- **Module detection**: Graceful fallback when RSAT modules unavailable
- **Flexible deployment**: CLI script and GUI wrapper work independently

## 📋 Prerequisites

- **PowerShell 5.1** or later
- **.NET Framework 4.5+** (for GUI)
- **RSAT PowerShell Modules**:
  - `ActiveDirectory` (for live AD lookups)
  - `GroupPolicy` (for GPO browsing)
- **Permissions**:
  - Read access to SYSVOL (to load Drives.xml)
  - Read access to AD (to query users, groups, OUs)

### Installing RSAT (Windows 10/11)

```powershell
# Windows 10 1809+ / Windows 11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0

# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell, RSAT-GP
```

## 🚀 Quick Start

### Method 1: GUI Application

```powershell
# Launch the GUI
.\GPO-DriveMap-Validator-GUI.ps1
```

1. **Configure GPO Source**:
   - Click "Auto-Detect" to populate domain
   - Click "Browse GPOs" to select from available GPOs
   - OR browse to a Drives.xml file directly

2. **Select Test Subjects**:
   - Enter usernames (comma-separated)
   - OR select an OU to test all users within it
   - OR configure simulated users in the "Simulated Users" tab

3. **Run Validation**:
   - Click "Run Validation"
   - Review results in the "Results" tab
   - Check "Conflicts" tab for drive letter issues
   - Review "Warnings" tab for unverifiable filters
   - Use "Filter Trace" tab to debug specific filter evaluations

4. **Export Results**:
   - Click "Export to CSV" to save full results

### Method 2: Command Line

```powershell
# Test specific users
.\Test-GpoDriveMapTargeting.ps1 -GpoName "Mapped Drives - Finance" `
    -TargetUsers alice, bob, charlie

# Test entire OU
.\Test-GpoDriveMapTargeting.ps1 -GpoName "Mapped Drives - Finance" `
    -TargetOU "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com" `
    -ExportCsvPath C:\Reports\finance-drives.csv

# Test with filter trace for debugging
.\Test-GpoDriveMapTargeting.ps1 -GpoName "Mapped Drives - Finance" `
    -TargetUsers alice -ShowFilterTrace

# Test simulated users
$simulatedUsers = @(
    @{ 
        Name = "FutureContractor"
        DistinguishedName = "OU=Contractors,DC=corp,DC=contoso,DC=com"
        MemberOfGroups = @("CN=VPN-Users,OU=Groups,DC=corp,DC=contoso,DC=com")
        ComputerName = "LAPTOP-CTR-01"
        Site = "RemoteSite"
    }
)

.\Test-GpoDriveMapTargeting.ps1 -GpoName "Mapped Drives - Finance" `
    -SimulatedUsers $simulatedUsers
```

## 📊 Understanding Results

### Summary Output

```
=================== SUMMARY: Who receives which drive ===================

alice:
  H:  \\fileserver\home\alice   (Home Drive)
  S:  \\fileserver\shared   (Shared)
  T:  \\fileserver\finance   (Finance Share)

bob:
  H:  \\fileserver\home\bob   (Home Drive)
  S:  \\fileserver\shared   (Shared)

=================== DRIVE-LETTER CONFLICTS ===================

CONFLICT: alice, T: - multiple mappings evaluate TRUE simultaneously:
   -> \\fileserver\finance  [Finance Share]
   -> \\fileserver\temp  [Temporary]
```

### Conflict Types

**Drive Letter Conflicts** occur when multiple drive mappings for the same letter evaluate to TRUE for a single user. The actual drive that gets mapped is **non-deterministic** - it depends on GPO processing order.

**Resolution**:
1. Review ILT filters on conflicting drives
2. Add mutual exclusion (e.g., NOT in Group X for one mapping)
3. Use different drive letters
4. Split into separate GPOs with distinct security filtering

### Warnings

Warnings indicate filters that couldn't be fully evaluated:

- **FilterComputer**: No computer name provided for user
- **FilterSite**: No site information provided
- **FilterLdapQuery**: Cannot evaluate for simulated users
- **Unsupported filters**: WMI, Date/Time Range, Battery Present, etc.

These require **manual verification** before production deployment.

## 🛠️ Advanced Usage

### Computer Context Evaluation

Some filters check computer properties (computer groups, computer names). For live AD users, supply computer context:

```powershell
$computerMapping = @{
    "alice" = "DESKTOP-01"
    "bob" = "LAPTOP-02"
}

.\Test-GpoDriveMapTargeting.ps1 -GpoName "Mapped Drives - Finance" `
    -TargetUsers alice, bob `
    -ComputerNameOverride $computerMapping
```

### Direct XML Path

Test without GPO name (useful for testing modified XML before importing):

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -DrivesXmlPath "\\corp.contoso.com\SysVol\corp.contoso.com\Policies\{GUID}\User\Preferences\Drives\Drives.xml" `
    -TargetUsers alice
```

### Scripted Validation in CI/CD

```powershell
# Automated validation in deployment pipeline
$result = .\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetOU "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com" `
    -ReturnObject

if ($result.Conflicts.Count -gt 0) {
    Write-Error "Drive mapping conflicts detected - aborting deployment"
    exit 1
}

if ($result.Warnings.Count -gt 0) {
    Write-Warning "Unverified filters detected - manual review required"
}

Write-Output "Validation passed - safe to deploy"
```

## 📖 How Item-Level Targeting Works

GPP evaluates ILT filters **sequentially**, left-to-right, with a running boolean result:

```
Initial result = UNDEFINED
For each filter:
    Evaluate filter -> TRUE or FALSE
    Apply NOT if specified -> Invert result
    Combine with running result using bool operator (AND/OR)
    
If final result = TRUE -> Apply drive mapping
```

### Example Filter Logic

```xml
<Filters>
    <FilterGroup bool="AND" not="0" name="CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com"/>
    <FilterOrgUnit bool="AND" not="0" name="OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com"/>
    <FilterGroup bool="AND" not="1" name="CN=Contractors,OU=Groups,DC=corp,DC=contoso,DC=com"/>
</Filters>
```

**Evaluation**:
1. FilterGroup "Finance-Users" → TRUE (user is member)
2. FilterOrgUnit "Finance" → TRUE (user's OU is under Finance)
3. Result so far: TRUE AND TRUE = TRUE
4. FilterGroup "Contractors" with NOT=1 → TRUE (user IS contractor), inverted → FALSE
5. Final: TRUE AND FALSE = **FALSE** → Drive NOT mapped

**Translation**: "Apply if user is in Finance-Users group AND in Finance OU AND NOT in Contractors group"

## 🔍 Debugging Tips

### Issue: "No drives mapped" for expected user

1. Run with `-ShowFilterTrace`
2. Review each filter's evaluation in the "Filter Trace" tab (GUI)
3. Check for:
   - Group membership issues (remember: primary groups like Domain Users aren't in MemberOf by default - this tool includes them)
   - OU path mismatches (case-sensitive in XML, but evaluated case-insensitive)
   - Negated filters (NOT=1) that are incorrectly blocking

### Issue: Unexpected drive mappings

1. Check for missing filters (no filters = applies to EVERYONE)
2. Review disabled attribute on drive nodes
3. Verify AND/OR logic is as intended (common mistake: using AND when OR was intended)

### Issue: "Could not resolve computer"

Supply `-ComputerNameOverride` hashtable for live users, or add `ComputerName` property to simulated users.

## 🏢 Enterprise Scenarios

### Scenario 1: Department-Specific Drives

```powershell
# Validate all departments before rollout
$departments = @("Finance", "HR", "IT", "Sales")

foreach ($dept in $departments) {
    $ouPath = "OU=$dept,OU=Users,DC=corp,DC=contoso,DC=com"
    
    .\Test-GpoDriveMapTargeting.ps1 `
        -GpoName "Mapped Drives - $dept" `
        -TargetOU $ouPath `
        -ExportCsvPath "C:\Validation\$dept-validation.csv"
}
```

### Scenario 2: Pre-Migration Testing

```powershell
# Test how users will be affected by a planned OU move
$simulatedUsers = @()

# Load users from current OU
$users = Get-ADUser -SearchBase "OU=OldLocation,DC=corp,DC=contoso,DC=com" -Filter *

foreach ($user in $users) {
    $simulatedUsers += @{
        Name = $user.SamAccountName
        # Simulate them in NEW location
        DistinguishedName = "CN=$($user.Name),OU=NewLocation,DC=corp,DC=contoso,DC=com"
        MemberOfGroups = $user.MemberOf
    }
}

.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - All Users" `
    -SimulatedUsers $simulatedUsers
```

### Scenario 3: Contractor vs. Employee Differential

```powershell
# Verify contractors don't get employee-only drives
$contractors = Get-ADUser -Filter {employeeType -eq "Contractor"} -Properties MemberOf

.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Employees" `
    -TargetUsers $contractors.SamAccountName

# Expected: All contractors should show "no drives mapped"
```

## 📝 Script Architecture

### Component Overview

```
GPO-DriveMap-Validator-GUI.ps1    (WPF GUI wrapper)
    └─> Test-GpoDriveMapTargeting.ps1    (Core validation engine)
            ├─> Parse Drives.xml
            ├─> Resolve AD subjects (users, groups, OUs)
            ├─> Evaluate filter trees (recursive)
            ├─> Detect conflicts
            └─> Return results
```

### Key Functions

**Test-GpoDriveMapTargeting.ps1**:
- `Get-DrivesXmlPathFromGpoName`: Resolve GPO to SYSVOL path
- `Resolve-LiveAdUser`: Query AD for user, groups, and primary group
- `Test-DnUnderOu`: Check if DN is child of OU (recursive or direct)
- `Test-GroupMembership`: Match user's groups against filter
- `Invoke-FilterNode`: Evaluate single filter node
- `Invoke-FilterTree`: Recursively evaluate nested filter collections

**GPO-DriveMap-Validator-GUI.ps1**:
- `Show-Status`: Update status bar
- `Browse-Gpo`: Interactive GPO selection with search
- `Invoke-Validation`: Execute backend script with parameters
- `Update-ResultsDisplay`: Populate all result grids and summaries
- `Export-Results`: CSV export with timestamp

## 🐛 Troubleshooting

### Error: "ActiveDirectory module not found"

Install RSAT tools (see Prerequisites section).

**Workaround**: Use `-SimulatedUsers` parameter to test without AD module.

### Error: "GPO not found"

- Verify GPO name is **exact** (case-sensitive)
- Ensure you have read access to SYSVOL
- Check domain is correct
- Use `-DrivesXmlPath` to bypass GPO lookup

### Error: "Access denied to Drives.xml"

- You need read access to `\\domain\SysVol\domain\Policies\` (typically granted via Domain Users)
- Run PowerShell with domain credentials
- Check GPO has User-side drive mappings (not Computer-side)

### Warning: "Unsupported filter type"

Some ILT filters can't be evaluated offline:
- **WMI queries** (OS version, installed software)
- **Date/Time ranges**
- **Battery Present** (laptops vs. desktops)
- **RAM amount**

These will always evaluate to FALSE in validation. Mark these for manual testing.

## 🔐 Security Considerations

- **Read-only operations**: Never modifies GPOs or AD
- **Credential scope**: Runs with your current user credentials
- **No data exfiltration**: Results stay local unless you export CSV
- **SYSVOL access**: Only reads XML; never writes
- **Safe for production**: Can run against live GPOs without impact

## 📚 Additional Resources

- [Microsoft: Item-Level Targeting](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11))
- [GPP Drive Maps Reference](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581925(v=ws.11))
- [Group Policy Preferences Overview](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11))

## 📄 License

This tool is provided as-is for use in enterprise environments. Feel free to modify and adapt to your needs.

## 🤝 Contributing

Contributions welcome! Areas for enhancement:
- Support for Computer-side drive maps (currently User-side only)
- WMI filter evaluation
- Multi-GPO aggregate testing
- HTML report generation
- Integration with Group Policy reporting tools

## 📞 Support

For issues, questions, or feature requests, please:
1. Check the Troubleshooting section above
2. Review the example scenarios
3. Enable `-ShowFilterTrace` for detailed debugging output

---

**Version**: 2.0  
**Last Updated**: 2026-09-25  
**PowerShell Version**: 5.1+  
**Platform**: Windows Server 2012+, Windows 10+

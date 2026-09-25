# GPO Drive Mapping Validator

**A modern, enterprise-grade tool for validating Group Policy Preference drive mappings before deployment**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)

---

## 📖 Overview

Group Policy Preferences (GPP) drive mappings with Item-Level Targeting (ILT) are powerful but complex. A single misconfigured filter can result in:

- 🚫 Users not receiving required drives
- ⚠️ Drive letter conflicts (multiple mappings to same letter)
- 🔓 Unintended access to sensitive shares
- 🐛 Non-deterministic behavior in production

**This tool validates your GPO configuration BEFORE deployment** by:

1. Parsing the actual `Drives.xml` from SYSVOL
2. Evaluating ILT filter logic exactly as the GPP client-side extension does
3. Testing against real AD users, groups, and OUs
4. Detecting conflicts, issues, and unverifiable filters
5. Providing detailed reports and audit trails

### Why This Tool?

❌ **Without validation:**
- Deploy GPO → Users complain → Investigate → Fix → Repeat
- "Works for me" but fails for 10% of users with subtle filter issues
- Drive conflicts discovered in production
- Hours spent troubleshooting "why doesn't this filter work?"

✅ **With validation:**
- Test GPO → Fix issues → Deploy with confidence
- Know exactly which users receive which drives BEFORE rollout
- Catch conflicts before users do
- Debug filter logic with step-by-step traces

---

## ✨ Key Features

### 🎯 Accurate Validation
- **Real ILT logic**: Mirrors GPP client-side extension's sequential AND/OR evaluation
- **Comprehensive filter support**: Groups, Users, Computers, OUs, Sites, LDAP queries, nested collections
- **Primary group handling**: Includes primary groups (usually missed by naive `MemberOf` checks)
- **Disabled drive detection**: Identifies drives disabled in the GPO

### 🖥️ Modern GUI
- **WPF-based interface**: Clean, professional, responsive design
- **Interactive results**: Sortable grids, visual summary cards, tabbed navigation
- **Filter trace debugger**: Step-by-step evaluation viewer
- **GPO browser**: Search and select from available GPOs
- **CSV export**: Full results with timestamp for documentation

### 🔬 Testing Modes
1. **Live AD users**: Test against real accounts (queries AD)
2. **OU-based**: Test all users in an OU recursively
3. **Simulated users**: Test hypothetical scenarios without creating test accounts

### 🛡️ Enterprise-Ready
- **Read-only**: Never modifies GPOs, AD, or XML files
- **Comprehensive error handling**: Clear messages and recovery
- **Flexible deployment**: Network share, local install, or CI/CD integration
- **Audit trail**: Detailed logs, traces, and exports

---

## 🚀 Quick Start

### 1. Prerequisites

```powershell
# Check PowerShell version (5.1+ required)
$PSVersionTable.PSVersion

# Install RSAT tools (if not already installed)
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
```

### 2. Download

Clone or download this repository:

```powershell
git clone https://github.com/yourusername/gpo-drivemap-validator.git
cd gpo-drivemap-validator
```

Or download scripts directly:
- `Test-GpoDriveMapTargeting.ps1` (backend validation engine)
- `GPO-DriveMap-Validator-GUI.ps1` (GUI application)

### 3. Launch

**Option A: Interactive Quick Start**
```powershell
.\Start-GPOValidator.ps1
```

**Option B: GUI Directly**
```powershell
.\GPO-DriveMap-Validator-GUI.ps1
```

**Option C: Command Line**
```powershell
.\Test-GpoDriveMapTargeting.ps1 -GpoName "Your GPO Name" -TargetUsers alice, bob, charlie
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [README](GPO-DRIVEMAP-VALIDATOR-README.md) | Comprehensive feature overview and examples |
| [User Guide](GPO-DRIVEMAP-VALIDATOR-USERGUIDE.md) | Detailed usage instructions with screenshots |
| [Deployment Guide](GPO-DRIVEMAP-VALIDATOR-DEPLOYMENT.md) | Enterprise deployment scenarios and automation |
| [Adding to Existing GPO](ADDING-TO-EXISTING-GPO.md) | Guide for validating new drives in existing GPOs |
| [Examples](EXAMPLES.md) | 13 practical usage examples |

---

## 💡 Usage Examples

### Example 1: Validate existing GPO (with all current drive mappings)

```powershell
# Validates ALL drives in the GPO - existing and newly added
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Corporate Drives" `
    -TargetUsers alice, bob, charlie
```

**Use case**: You have an existing GPO with multiple drive mappings and want to add a new one. This validates the ENTIRE GPO state, detecting conflicts between existing and new mappings.

### Example 2: Test specific users

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetUsers alice, bob, charlie
```

**Output:**
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
```

**Note**: This evaluates ALL drive mappings in the GPO. Perfect for validating new additions to existing GPOs with multiple drives already configured.

### Example 3: Test entire OU with export

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetOU "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com" `
    -ExportCsvPath "C:\Reports\finance-validation.csv"
```

### Example 4: Debug filter logic

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Complex" `
    -TargetUsers alice `
    -ShowFilterTrace
```

**Output:**
```
Drive F: (\\fileserver\finance) evaluated for 'alice':
  FilterGroup 'CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com' -> user-member:True computer-member:False
  FilterOrgUnit 'OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com' -> True (subject DN: CN=Alice Smith,OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com)
  FilterGroup 'CN=Contractors,OU=Groups,DC=corp,DC=contoso,DC=com' -> user-member:False computer-member:False
  (NOT applied -> True)
Final result: True
```

### Example 5: Test simulated users

```powershell
$simulatedUsers = @(
    @{
        Name = "FutureContractor"
        DistinguishedName = "OU=Contractors,DC=corp,DC=contoso,DC=com"
        MemberOfGroups = @("CN=VPN-Users,OU=Groups,DC=corp,DC=contoso,DC=com")
    }
)

.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - All Users" `
    -SimulatedUsers $simulatedUsers
```

---

## 🎨 GUI Screenshots

### Configuration Tab
Configure GPO source, test subjects, and validation options.

### Results Tab
Visual dashboard with summary cards and detailed results grid.

### Conflicts Tab
Identify drive letter conflicts before they impact users.

### Filter Trace Tab
Debug filter evaluation logic step-by-step.

### Warnings Tab
Review filters that couldn't be fully verified offline.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│  GPO-DriveMap-Validator-GUI.ps1         │  Modern WPF interface
│  (User Interface Layer)                 │
└─────────────┬───────────────────────────┘
              │
              │ Invokes with parameters
              ▼
┌─────────────────────────────────────────┐
│  Test-GpoDriveMapTargeting.ps1          │  Validation engine
│  (Core Logic Layer)                     │
└─────────────┬───────────────────────────┘
              │
              ├─► Parse Drives.xml from SYSVOL
              ├─► Query AD (users, groups, OUs)
              ├─► Evaluate ILT filter trees
              ├─► Detect conflicts
              └─► Generate reports
```

### Key Components

**Test-GpoDriveMapTargeting.ps1** - Backend validation engine
- Resolves GPO to SYSVOL path
- Parses Drives.xml structure
- Queries Active Directory
- Evaluates filter logic recursively
- Detects conflicts and warnings

**GPO-DriveMap-Validator-GUI.ps1** - Frontend GUI wrapper
- Modern WPF interface
- Interactive data grids
- Real-time validation
- Results visualization
- CSV export

---

## 🔧 Advanced Features

### CI/CD Integration

```powershell
# Validate GPO in pipeline
$result = .\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetOU "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com" `
    -ReturnObject

if ($result.Conflicts.Count -gt 0) {
    Write-Error "Conflicts detected - aborting deployment"
    exit 1
}
```

### Scheduled Auditing

```powershell
# Weekly automated audit
$gpos = @("Mapped Drives - Finance", "Mapped Drives - HR", "Mapped Drives - IT")

foreach ($gpo in $gpos) {
    .\Test-GpoDriveMapTargeting.ps1 `
        -GpoName $gpo `
        -TargetOU "OU=Users,DC=corp,DC=contoso,DC=com" `
        -ExportCsvPath "\\fileserver\Audits\$gpo-$(Get-Date -Format 'yyyyMMdd').csv"
}
```

### Computer Context Testing

```powershell
# Test with specific computer assignments
$computerMapping = @{
    "alice" = "DESKTOP-FIN-01"
    "bob" = "LAPTOP-FIN-02"
}

.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetUsers alice, bob `
    -ComputerNameOverride $computerMapping
```

---

## 🛠️ Common Scenarios

### Scenario 1: Pre-Deployment Validation
**Goal**: Test a new GPO before linking to production OUs

1. Create GPO with drive mappings and ILT filters
2. DO NOT link to any OUs yet
3. Run validation against representative users
4. Fix conflicts and warnings
5. Once clean, link GPO to production

### Scenario 1.5: Adding to Existing GPO
**Goal**: Add a new drive mapping to an existing GPO with multiple drives already configured

1. Note current state: Validate existing GPO before changes
2. Add new drive mapping in GPMC (don't apply yet)
3. Validate again - tool checks ALL drives (existing + new)
4. Fix any conflicts between new and existing mappings
5. Deploy when validation is clean

**See [ADDING-TO-EXISTING-GPO.md](ADDING-TO-EXISTING-GPO.md) for detailed guide**

### Scenario 2: Troubleshoot User Issue
**Goal**: User reports not receiving expected drive

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetUsers jsmith `
    -ShowFilterTrace
```

Review the trace to see which filters evaluated FALSE.

### Scenario 3: Plan OU Restructure
**Goal**: Understand impact of moving users to new OUs

```powershell
# Create simulated users in NEW OU locations
$simulatedUsers = @(
    @{
        Name = "alice"
        DistinguishedName = "CN=Alice,OU=NewDept,DC=corp,DC=contoso,DC=com"
        MemberOfGroups = @("CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com")
    }
)

.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - All Users" `
    -SimulatedUsers $simulatedUsers
```

### Scenario 4: Audit Existing GPO
**Goal**: Document which users receive which drives

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetOU "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com" `
    -ExportCsvPath "C:\Audit\finance-$(Get-Date -Format 'yyyyMMdd').csv"
```

---

## ⚙️ Configuration

### Execution Policy

The scripts are not signed. Set execution policy:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Or bypass for a single run:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\GPO-DriveMap-Validator-GUI.ps1
```

### Network Deployment

Deploy to a network share for centralized access:

```powershell
# Copy to network share
Copy-Item *.ps1 \\fileserver\GPOTools\

# Create desktop shortcut for users
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\GPO Validator.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"\\fileserver\GPOTools\GPO-DriveMap-Validator-GUI.ps1`""
$Shortcut.Save()
```

---

## 🐛 Troubleshooting

### "Module not found" error

**Issue**: ActiveDirectory or GroupPolicy module not available

**Solution**: Install RSAT tools
```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
```

**Workaround**: Use simulated users instead of live AD

### "GPO not found" error

**Issue**: GPO name typo or wrong domain

**Solution**: 
- Use exact GPO display name (case-sensitive)
- Verify domain FQDN
- Use `-DrivesXmlPath` to specify XML directly

### "Access denied to Drives.xml"

**Issue**: No read access to SYSVOL

**Solution**: 
- Verify domain authentication: `whoami /groups | findstr /i domain`
- Check SYSVOL permissions (Authenticated Users should have Read)
- Use RunAs with domain credentials

### Unexpected validation results

**Issue**: Results don't match expectations

**Solution**: 
- Run with `-ShowFilterTrace` to see step-by-step evaluation
- Verify group memberships: `Get-ADUser alice -Properties MemberOf`
- Check for NOT operators inverting results
- Ensure primary groups are included (tool does this automatically)

---

## 📋 Version History

### Version 2.0 (2026-09-25)
- ✨ Modern WPF GUI with tabbed interface
- ✨ Simulated users support for hypothetical testing
- ✨ Enhanced filter trace debugger
- ✨ Visual summary dashboard with cards
- 🐛 Fixed primary group membership detection
- 🐛 Fixed XML parsing for disabled drives
- 🐛 Improved group membership matching logic
- 📚 Comprehensive documentation suite

### Version 1.0 (Initial Release)
- Core validation engine
- CLI interface
- CSV export
- Filter trace support

---

## 🤝 Contributing

Contributions welcome! Areas for enhancement:

- [ ] Support for Computer-side drive maps (currently User-side only)
- [ ] WMI filter evaluation
- [ ] Multi-GPO aggregate testing
- [ ] HTML report generation
- [ ] PowerShell Gallery module packaging
- [ ] Unit test suite

---

## 📜 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Microsoft Group Policy Preferences documentation
- PowerShell community for WPF examples
- Active Directory PowerShell module maintainers

---

## 📞 Support

- **Documentation**: See `GPO-DRIVEMAP-VALIDATOR-USERGUIDE.md` for detailed usage
- **Deployment**: See `GPO-DRIVEMAP-VALIDATOR-DEPLOYMENT.md` for enterprise deployment
- **Issues**: Use GitHub Issues for bug reports and feature requests

---

## 📊 Project Stats

- **PowerShell Version**: 5.1+
- **Platform**: Windows 10+, Windows Server 2012+
- **.NET Framework**: 4.5+
- **Dependencies**: RSAT (ActiveDirectory, GroupPolicy modules)

---

**Made with ❤️ for Active Directory administrators worldwide**

*Because nobody should have to debug GPP drive mappings in production.*

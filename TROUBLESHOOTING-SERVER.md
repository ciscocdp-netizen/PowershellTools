# Troubleshooting: GUI Hanging on Windows Server

## Problem

When running `GPO-DriveMap-Validator-GUI.ps1` on Windows Server 2022 (or other Server versions), the script hangs and the GUI window never appears.

## Root Cause

Windows Server environments, especially Server Core installations, may not have full WPF (Windows Presentation Foundation) support or may be running without a desktop environment.

## Quick Solution: Use CLI Instead

**The CLI version works perfectly on ALL Windows Server environments:**

```powershell
# Instead of the GUI, use this:
.\Test-GpoDriveMapTargeting.ps1 -GpoName "Your GPO Name" -TargetUsers alice, bob, charlie
```

or

```powershell
# Interactive CLI menu:
.\Start-GPOValidator-CLI.ps1
```

---

## Detailed Solutions

### Solution 1: Interactive CLI Launcher (Recommended for Server)

```powershell
.\Start-GPOValidator-CLI.ps1
```

This provides a text-based menu that works on ALL Windows versions, including Server Core.

**Features:**
- ✅ Works on Server Core
- ✅ Works via remote PowerShell
- ✅ No GUI dependencies
- ✅ Interactive prompts
- ✅ All validation features available

---

### Solution 2: Direct CLI Usage

For automation or quick validations:

```powershell
# Validate specific users
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -Domain "corp.contoso.com" `
    -TargetUsers alice, bob, charlie

# Validate entire OU
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetOU "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com" `
    -ExportCsvPath "C:\Validation\results.csv"

# Show detailed trace (for debugging)
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Mapped Drives - Finance" `
    -TargetUsers alice `
    -ShowFilterTrace
```

---

### Solution 3: Test WPF Compatibility

Before trying the GUI, test if your server supports it:

```powershell
.\Test-WPF-Compatibility.ps1
```

This will:
- Check if WPF assemblies can load
- Detect Server Core vs. Desktop Experience
- Provide specific recommendations
- Test if a simple WPF window can be created

---

### Solution 4: Enable Desktop Experience (If Needed)

**Only if you really need the GUI and have Desktop Experience installed:**

#### On Server 2016/2019/2022:

```powershell
# Check if GUI is installed
Get-WindowsFeature -Name "Server-Gui-Shell"

# If not installed and you want it:
Install-WindowsFeature -Name "Server-Gui-Shell" -IncludeManagementTools -Restart
```

**Note:** This requires:
- Significant disk space (~4GB)
- Server restart
- May not be allowed by your organization's policy
- **NOT recommended** - use CLI instead!

---

## Why the GUI Hangs

### Common Causes:

1. **Server Core Installation**
   - No Desktop Experience
   - WPF components not installed
   - Solution: Use CLI

2. **Remote PowerShell Session**
   - No GUI forwarding
   - Window cannot be displayed
   - Solution: Use CLI or run locally

3. **Missing .NET Framework Components**
   - WPF assemblies not available
   - Incomplete .NET installation
   - Solution: Use CLI (works with core .NET)

4. **User Session Type**
   - Service account
   - Non-interactive session
   - Solution: Use CLI

---

## Feature Comparison: GUI vs CLI

| Feature | GUI | CLI |
|---------|-----|-----|
| **Works on Server Core** | ❌ No | ✅ Yes |
| **Works via Remote PS** | ❌ No | ✅ Yes |
| **Validate GPO** | ✅ Yes | ✅ Yes |
| **Test specific users** | ✅ Yes | ✅ Yes |
| **Test entire OU** | ✅ Yes | ✅ Yes |
| **Conflict detection** | ✅ Yes | ✅ Yes |
| **Filter trace** | ✅ Yes | ✅ Yes |
| **CSV export** | ✅ Yes | ✅ Yes |
| **Simulated users** | ✅ Yes | ✅ Yes |
| **Visual dashboard** | ✅ Yes | ❌ No (text output) |
| **Point-and-click** | ✅ Yes | ❌ No (command-line) |
| **Automation-friendly** | ❌ No | ✅ Yes |

**Bottom line:** CLI has ALL the same validation capabilities, just without the visual interface.

---

## Recommended Workflow for Server Administrators

### For Daily Use:

```powershell
# Keep this shortcut handy
.\Start-GPOValidator-CLI.ps1
```

### For Automation:

```powershell
# Direct command in scripts
.\Test-GpoDriveMapTargeting.ps1 -GpoName "..." -TargetUsers ... -ExportCsvPath "..."
```

### For Remote Management:

```powershell
# Works perfectly via remote PS
Enter-PSSession -ComputerName DC01
cd C:\GPOTools
.\Test-GpoDriveMapTargeting.ps1 -GpoName "..." -TargetUsers ...
```

---

## Quick Reference Card

Save this for quick access:

```powershell
# ══════════════════════════════════════════════════════
#  GPO Drive Mapping Validator - Server Edition
# ══════════════════════════════════════════════════════

# Interactive menu (easiest)
.\Start-GPOValidator-CLI.ps1

# Quick validation
.\Test-GpoDriveMapTargeting.ps1 -GpoName "Your GPO" -TargetUsers alice,bob

# Validate entire department
.\Test-GpoDriveMapTargeting.ps1 -GpoName "Your GPO" -TargetOU "OU=Finance,DC=corp,DC=com"

# Debug why a drive doesn't apply
.\Test-GpoDriveMapTargeting.ps1 -GpoName "Your GPO" -TargetUsers alice -ShowFilterTrace

# Export for documentation
.\Test-GpoDriveMapTargeting.ps1 -GpoName "Your GPO" -TargetOU "OU=...,DC=..." -ExportCsvPath "C:\report.csv"

# Test if GUI would work (optional)
.\Test-WPF-Compatibility.ps1
```

---

## Examples for Your Environment

Based on your Windows Server 2022 environment:

### Example 1: Validate Against Finance Users

```powershell
# If your domain is "corp.contoso.com" and GPO is "Corporate Drives"
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Corporate Drives" `
    -Domain "corp.contoso.com" `
    -TargetUsers alice, bob, charlie, david
```

### Example 2: Validate Entire OU with Export

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Corporate Drives" `
    -TargetOU "OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com" `
    -ExportCsvPath "C:\GPO-Validation-Finance-$(Get-Date -Format 'yyyyMMdd').csv"
```

### Example 3: Debug Specific User Issue

```powershell
# User reports not getting expected drive
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Corporate Drives" `
    -TargetUsers john.smith `
    -ShowFilterTrace
```

Output will show exactly why each filter matched or didn't match.

---

## Still Need GUI?

If you absolutely need the visual interface:

### Option A: Use on a Desktop OS
- Install scripts on Windows 10/11 workstation
- Run GUI there
- Point to server's SYSVOL via UNC path

### Option B: Enable Desktop Experience on Server
1. Only if your organization allows it
2. Requires significant resources
3. Requires restart
4. **Not recommended** for production servers

```powershell
# Only if you must:
Install-WindowsFeature -Name "Server-Gui-Shell" -IncludeManagementTools -Restart
```

### Option C: Remote Desktop
- RDP to server with Desktop Experience
- Run GUI in RDP session

---

## Summary

### ✅ What Works on Server:
- `Test-GpoDriveMapTargeting.ps1` (CLI validation)
- `Start-GPOValidator-CLI.ps1` (interactive menu)
- All validation features
- All automation capabilities

### ❌ What May Not Work on Server:
- `GPO-DriveMap-Validator-GUI.ps1` (WPF GUI)
  - Especially on Server Core
  - Or via remote PowerShell

### 🎯 Recommended:
**Use the CLI version** - it's actually better for server administration:
- Works everywhere
- Faster
- Scriptable
- Same validation capabilities
- Better for automation

---

## Getting Help

If you still have issues:

1. **Run diagnostics:**
   ```powershell
   .\Test-WPF-Compatibility.ps1
   ```

2. **Check documentation:**
   - `EXAMPLES.md` - 13 CLI usage examples
   - `GPO-DRIVEMAP-VALIDATOR-USERGUIDE.md` - Full guide
   - `README.md` - Quick start

3. **Use interactive launcher:**
   ```powershell
   .\Start-GPOValidator-CLI.ps1
   ```

---

## Contact & Support

For issues specific to Windows Server environments:
- Review `EXAMPLES.md` for CLI patterns
- Check `GPO-DRIVEMAP-VALIDATOR-DEPLOYMENT.md` for server deployment
- Use `Start-GPOValidator-CLI.ps1` for best Server experience

**The CLI version provides 100% of the validation functionality without any GUI dependencies!**

# PowershellTools

PowerShell utilities for Windows administration.

## Get-LastLogonReport.ps1

Looks up Active Directory last-logon data from a CSV of `SamAccountName` values and writes a results CSV.

### Features

- GUI **Open** and **Save** file pickers (STA-safe) to choose the input CSV and where to place the report
- Save dialog prefers the same folder as the input CSV when available
- Exports **EmailAddress** (`mail`) and **EmployeeID** for each user
- Optional `-AccurateLastLogon` mode that queries reachable domain controllers

### Usage

```powershell
.\Get-LastLogonReport.ps1
.\Get-LastLogonReport.ps1 -AccurateLastLogon
.\Get-LastLogonReport.ps1 -InputCsv .\users.csv -OutputCsv .\LastLogonReport.csv
.\Get-LastLogonReport.ps1 -SelfTest
```

Requires the Active Directory PowerShell module (RSAT).

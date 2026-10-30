# Teams Call Report

Exports Microsoft Teams call records for one user and opens them in a Windows desktop window.

Graph keeps these records for 30 days, and a record is created only after the call ends. The app registration needs application permissions (admin consent), not delegated permissions:

- `CallRecords.Read.All`
- `User.Read.All`

## Desktop window

Double-click `Start-TeamsCallReport.cmd`, or from an existing Windows PowerShell window:

```powershell
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\TeamsCallReport.ps1 -StaReady
```

Sign in with a certificate thumbprint, a PFX, or a client secret. Choose Public, USGov, or USGovDoD. **Preview sample data** runs the same export against built-in records (try `alice@contoso.com`) so the grids, filters, and CSV files can be checked without a tenant.

An existing `Connect-MgGraph` session is visible only in this process. The `.cmd` launcher starts a new process, so use certificate or secret sign-in from the window. Settings are stored in `%APPDATA%\TeamsCallReport\settings.json`. Secrets and the PFX password are not saved.

The window lists calls, participants, and endpoints. Selecting a call filters the other two grids. The filter box searches the current text. Output is the folder you choose:

- `Calls.csv`
- `Participants.csv`
- `Endpoints.csv`
- `Summary.txt` and `TargetUser.json`
- `RawJson\<call-id>.json` (the Graph bodies, unmodified)

## Command line

```powershell
.\Get-TeamsUserCallDetails.ps1 -User alice@contoso.com -TenantId <tenant-guid> `
    -ClientId <app-guid> -CertificateThumbprint <thumbprint>

$secret = Read-Host -AsSecureString 'Client secret'
.\Get-TeamsUserCallDetails.ps1 -User alice@contoso.com -TenantId <tenant-guid> `
    -ClientId <app-guid> -ClientSecret $secret -StartDate (Get-Date).AddDays(-7)

.\Get-TeamsUserCallDetails.ps1 -User alice@contoso.com -TenantId <tenant-guid> `
    -ClientId <app-guid> -CertificatePath .\app.pfx -Cloud USGov

.\Get-TeamsUserCallDetails.ps1 -User alice@contoso.com -Sample
```

`-UseExistingConnection` reuses `Connect-MgGraph` in the same Windows PowerShell process. `-Cloud` accepts `Public`, `USGov`, and `USGovDoD`.

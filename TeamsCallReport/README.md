# Teams Call Report

Exports Microsoft Teams call records for one user and opens them in a Windows desktop window.

Graph keeps these records for 30 days, and a record is created only after the call ends. Microsoft does not let a signed-in user read call records directly. The first time you sign in with a Global Administrator or Privileged Role Administrator account, this tool creates an app named **Teams Call Report** and grants it:

- `CallRecords.Read.All`
- `User.Read.All`

The certificate private key stays in the Windows certificate store on this PC. Later runs reuse that grant and do not ask you to sign in again.

The window does not ask for a tenant id or a client id. Those boxes appear only after you choose certificate or client-secret sign-in for an app registration that already exists. If an older window saved certificate sign-in with both boxes empty, the next open returns to **Sign in with my account**.

## Desktop window

Keep `TeamsCallReport.ps1` and `TeamsCallReport.Core.ps1` in the same folder, then double-click `Start-TeamsCallReport.cmd`. Leave **Sign in with my account** selected, enter the person whose calls you want, and click **Run export**. A browser opens for the administrator sign-in and shows a device code.

**Preview sample data** runs the same export against built-in records (try `alice@contoso.com`) so the grids can be checked without a tenant.

Settings are stored in `%APPDATA%\TeamsCallReport\settings.json`. The app id and certificate thumbprint are stored in `%APPDATA%\TeamsCallReport\account.json`. Secrets are not saved. Certificate, PFX, and client-secret sign-in remain available in the sign-in list when an app registration already exists.

The window lists calls, participants, and endpoints. Selecting a call filters the other two grids. The filter box searches the current text. Output is the folder you choose:

- `Calls.csv`
- `Participants.csv`
- `Endpoints.csv`
- `Summary.txt` and `TargetUser.json`
- `RawJson\<call-id>.json` (the Graph bodies, unmodified)

## Command line

```powershell
.\Get-TeamsUserCallDetails.ps1 -User alice@contoso.com

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

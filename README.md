# PowershellTools

PowerShell utilities for Windows / Microsoft 365 administration.

## Report-MailboxQuotaCompliance.ps1

Reports Exchange Online mailbox storage quotas for users licensed with Office 365 or Microsoft 365 **E3 / E5**, and optionally remediates them to the standard 100 / 99 / 98 GB profile.

The script stays on **Windows PowerShell 5.1** (`#Requires -Version 5.1`). It does not use `ForEach-Object -Parallel` or other PowerShell 7-only features.

### Large tenants (~30,000 mailboxes) and one-hour tokens

A live `Get-EXOMailbox` / `Get-EXOMailboxStatistics` walk of ~31,000 mailboxes takes hours and outlives a typical delegated token. The default path avoids that:

1. **`GraphReports` (default)** — one Microsoft Graph download of `GET /reports/getMailboxUsageDetail(period='D7')`. That CSV already includes storage used and the three quota values. Join it in memory to E3/E5 licensed users. This is usually minutes, not hours, and finishes inside a one-hour token. The report can lag **24–48 hours**.
2. **`ExchangeLive`** — real-time `Get-EXOMailbox` in UPN-prefix shards. Use this only when you need current quotas. Tokens are refreshed about every 45 minutes (`-TokenRefreshMinutes`). Prefer **app-only certificate auth** so the job is not tied to an interactive MFA token.

Required Graph permission for the default path: **`Reports.Read.All`** (in addition to `User.Read.All` and `Organization.Read.All`).

### Features

- Default data source is the Graph mailbox usage report (one tenant CSV); `-DataSource ExchangeLive` is the real-time EXO path
- Reads licenses from Microsoft Graph and filters the user pull to E3/E5 SKUs when possible (`$top=999` paging)
- Joins Graph users to mailboxes by **Entra object ID** (`ExternalDirectoryObjectId`), then UPN
- Compares quotas with a byte tolerance so `99.99 GB` is not flagged as non-compliant
- Handles `ByteQuantifiedSize`, numeric REST sizes, Graph report byte columns, and `"99 GB (106,300,440,576 bytes)"` strings
- Treats Microsoft 365 E3/E5 (`SPE_E3` / `SPE_E5`) as well as Office 365 E3/E5 (`ENTERPRISEPACK` / `ENTERPRISEPREMIUM`)
- Writes CSV reports plus a self-contained HTML summary (includes the data source)
- `-Remediate` honors `-WhatIf` / `-Confirm` and only calls `Set-Mailbox` for mailboxes that need a quota fix
- Optional app-only auth: `-AppId`, `-CertificateThumbprint`, `-TenantId`, `-Organization`

### Usage

```powershell
# Fast path for ~30k mailboxes (default). Needs Reports.Read.All.
.\Report-MailboxQuotaCompliance.ps1 -OutputFolder C:\Reports

# Real-time Exchange Online quotas (slow). Skip per-mailbox statistics if you only care about the cap.
.\Report-MailboxQuotaCompliance.ps1 -DataSource ExchangeLive -SkipStatistics -OutputFolder C:\Reports

# Unattended / longer than one hour: app-only certificate (no interactive MFA token).
.\Report-MailboxQuotaCompliance.ps1 -AppId '<app-id>' -TenantId '<tenant-id>' `
    -CertificateThumbprint '<thumbprint>' -Organization contoso.onmicrosoft.com

.\Report-MailboxQuotaCompliance.ps1 -Identity jane@contoso.com
.\Report-MailboxQuotaCompliance.ps1 -Remediate -WhatIf
.\Report-MailboxQuotaCompliance.ps1 -Remediate -Confirm:$false
.\Report-MailboxQuotaCompliance.ps1 -SelfTest
.\Report-MailboxQuotaCompliance.ps1 -DemoReport -OutputFolder C:\Reports
```

Requires the `Microsoft.Graph.Authentication` module. `ExchangeOnlineManagement` is imported only for `-DataSource ExchangeLive` or `-Remediate`. Grant the signed-in account (or app) `User.Read.All`, `Organization.Read.All`, and `Reports.Read.All`. For `-Remediate`, the app also needs `Exchange.ManageAsApp` plus the Exchange Administrator role.

On **Windows PowerShell 5.1**, `Connect-ExchangeOnline` often fails with `An error occurred while sending the request` unless TLS 1.2 is enabled. The script does that automatically before the modules load. If it still fails, update the modules or run the script in PowerShell 7.

If you saved the script as `MailboxSize.ps1`, copy the latest `Report-MailboxQuotaCompliance.ps1` over it (or run the repo filename).

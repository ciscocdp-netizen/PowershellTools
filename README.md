# PowershellTools

PowerShell utilities for Windows / Microsoft 365 administration.

## Report-MailboxQuotaCompliance.ps1

Reports Exchange Online mailbox storage quotas for users licensed with Office 365 or Microsoft 365 **E3 / E5**, and optionally remediates them to the standard 100 / 99 / 98 GB profile.

### Features

- Reads licenses from Microsoft Graph (`User.Read.All`, `Organization.Read.All`) and mailbox quotas from Exchange Online
- Joins Graph users to mailboxes by **Entra object ID** (`ExternalDirectoryObjectId`), then UPN
- Pulls mailboxes in one `Get-EXOMailbox` query using **Minimum + Quota** property sets (not once per user)
- Compares quotas with a byte tolerance so `99.99 GB` is not flagged as non-compliant
- Handles `ByteQuantifiedSize`, numeric REST sizes, and `"99 GB (106,300,440,576 bytes)"` strings
- Treats Microsoft 365 E3/E5 (`SPE_E3` / `SPE_E5`) as well as Office 365 E3/E5 (`ENTERPRISEPACK` / `ENTERPRISEPREMIUM`)
- Writes CSV reports plus a self-contained HTML summary
- `-Remediate` honors `-WhatIf` / `-Confirm`

### Usage

```powershell
.\Report-MailboxQuotaCompliance.ps1 -OutputFolder C:\Reports
.\Report-MailboxQuotaCompliance.ps1 -Identity jane@contoso.com
.\Report-MailboxQuotaCompliance.ps1 -Remediate -WhatIf
.\Report-MailboxQuotaCompliance.ps1 -Remediate -Confirm:$false
.\Report-MailboxQuotaCompliance.ps1 -SelfTest
.\Report-MailboxQuotaCompliance.ps1 -DemoReport -OutputFolder C:\Reports
```

Requires the `ExchangeOnlineManagement` and `Microsoft.Graph.Authentication` modules (installed automatically for the current user if missing) and an account that can read mailboxes plus `User.Read.All` / `Organization.Read.All`.

On **Windows PowerShell 5.1**, `Connect-ExchangeOnline` often fails with `An error occurred while sending the request` unless TLS 1.2 is enabled. The script does that automatically before the modules load. If it still fails, update the modules or run the script in PowerShell 7.

If you saved the script as `MailboxSize.ps1`, copy the latest `Report-MailboxQuotaCompliance.ps1` over it (or run the repo filename). The Graph "property Count cannot be found" crash under `Set-StrictMode` is fixed in this revision.

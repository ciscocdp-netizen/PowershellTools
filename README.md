# PowershellTools

PowerShell utilities for Windows administration.

## Get-LitigationHoldReport.ps1

Reports Exchange Online mailboxes that have **Litigation Hold** enabled and exports the results to CSV.

### Features

- Connects with the Exchange Online V3 module (`ExchangeOnlineManagement`)
- Server-side filter on `LitigationHoldEnabled` (falls back to a full scan if the REST filter is rejected)
- Requests **Minimum + Hold + SoftDelete** property sets so identity fields are not blank
- Includes **inactive mailboxes** (deleted users that remain on hold) unless `-SkipInactiveMailboxes` is passed
- GUI **Save** file picker (STA-safe, owned by a TopMost form) or `-OutputCsv` for unattended runs
- Converts hold duration (`90.00:00:00`) to days; `Unlimited` stays Unlimited

### Usage

```powershell
.\Get-LitigationHoldReport.ps1
.\Get-LitigationHoldReport.ps1 -OutputCsv .\LitigationHoldReport.csv
.\Get-LitigationHoldReport.ps1 -UserPrincipalName admin@contoso.com
.\Get-LitigationHoldReport.ps1 -SkipInactiveMailboxes
.\Get-LitigationHoldReport.ps1 -SelfTest
```

Requires the ExchangeOnlineManagement module (installed automatically for the current user if missing) and an Exchange Online admin account that can run `Get-EXOMailbox`.

On **Windows PowerShell 5.1**, `Connect-ExchangeOnline` often fails with `An error occurred while sending the request` unless TLS 1.2 is enabled. The script does that automatically before the module loads. If it still fails, update the module (`Update-Module ExchangeOnlineManagement -Force`) or run the script in PowerShell 7.

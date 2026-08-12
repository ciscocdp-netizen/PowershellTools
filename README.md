# PowershellTools

Windows operations scripts for health, inventory, and Active Directory reporting.

## Invoke-SystemAnalysis.ps1

Comprehensive Windows Server health and performance collector. It samples CPU, memory, disk, and network counters, then adds Windows health, security, SQL Server, Hyper-V, certificates, and optional AD/Kerberos/BPA checks. Output is a self-contained HTML report plus a CSV export.

Requires an **elevated** Windows PowerShell 5.1+ session (PowerShell 7 on Windows also works).

```powershell
cd C:\Path\To\PowershellTools\scripts
.\Invoke-SystemAnalysis.ps1
```

```powershell
.\Invoke-SystemAnalysis.ps1 -OutputPath D:\Reports -SkipBpa -NoBrowser
.\Invoke-SystemAnalysis.ps1 -Sections CPU,Memory,Disk,Certificates
```

| Parameter | Default | Purpose |
| --- | --- | --- |
| `OutputPath` | Desktop, else `%TEMP%` | Directory for HTML/CSV (created if missing) |
| `SampleIntervalSeconds` | 5 | Seconds between counter samples |
| `SampleCount` | 3 | Samples per counter group |
| `EventLogHours` | 24 | Application/System lookback |
| `SkipBpa` | off | Skip Best Practices Analyzer (BPA can hang) |
| `SkipSoftware` | off | Skip Add/Remove Programs inventory |
| `IncludeRootCertificates` | off | Also scan Root/CA stores |
| `IncludeSecurityLog` | off | Include targeted Security event IDs |
| `NoBrowser` | off | Do not open the report at the end |
| `Sections` | `All` | Run a subset of collectors |

A static **UI preview** (sample data, not a live capture) is in [`examples/system-analysis-preview.html`](examples/system-analysis-preview.html).

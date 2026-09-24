# PowershellTools

Windows PowerShell utilities for Active Directory and DHCP administration.

## Active Directory Log Viewer

`AD-LogViewer-Modern.ps1` is a resizable WinForms viewer for the AD account-management logs you generate.

```powershell
powershell.exe -STA -ExecutionPolicy Bypass -File .\AD-LogViewer-Modern.ps1
```

- Streams the file instead of loading it with `Get-Content`
- Shows ingest progress (file, lines, matches, percent, lines/sec) and supports Cancel
- Parses Timestamp, Event, Account, Actor, and Host into a filterable grid
- Literal search by default (optional regex), plus export/copy/drag-and-drop
- Engine-only tests: `pwsh -File .\tests\Test-AdLogViewerEngine.ps1`

## Active Directory Object Manager

`AD-ObjectManager-Modern.ps1` manages user and computer objects in bulk.

## DHCP Manager

See `START-HERE.md` and `QUICK-START-GUIDE.md`.

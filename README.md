# PowershellTools

Collection of Windows administration scripts.

## Event Log XML Analyzer

`EventLogAnalyzer.ps1` is a WPF GUI (Windows) and headless analyzer for Event Viewer XML / `.evtx` exports. It clusters related failures and surfaces probable root causes (unexpected reboots, disk faults, service crashes, brute-force logons, log clearing, and more).

### Run the GUI (Windows)

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\EventLogAnalyzer.ps1
# or open a file immediately
.\EventLogAnalyzer.ps1 -Path C:\Temp\System.xml
```

Supports Event Viewer "Save All Events As... XML" (UTF-8 or UTF-16), `wevtutil qe /f:xml` fragments, native `.evtx`, drag-and-drop, and merging several logs in one pass.

### Headless / report

```powershell
.\EventLogAnalyzer.ps1 -Path .\samples\EventLog-Sample.xml -NoGui -ReportPath .\report.html
.\EventLogAnalyzer.ps1 -Path .\samples\EventLog-Sample.xml -NoGui -ReportPath .\report.json
```

### Self-test

```powershell
pwsh -File .\EventLogAnalyzer.ps1 -SelfTest
# or
pwsh -File .\tests\Test-EventLogAnalyzer.ps1
```

# PowershellTools

Windows PowerShell admin tools (WinForms) for Server 2012 / 2012 R2 and later.

## SMBv1 Traffic Analyzer

`SMBv1-TrafficAnalyzer.ps1` is a Wireshark-style live capture GUI that finds **SMBv1** on the wire (TCP 139/445), plus SMB2/SMB3 for contrast. No Npcap or Wireshark install is required. Targets **Windows Server 2012** (PowerShell 3.0), 2012 R2, and PowerShell 7 on Windows.

```powershell
# Server 2012 / 2012 R2 — elevated
powershell.exe -ExecutionPolicy Bypass -STA -File .\SMBv1-TrafficAnalyzer.ps1

# PowerShell 7+ on Windows
pwsh.exe -ExecutionPolicy Bypass -File .\SMBv1-TrafficAnalyzer.ps1

# Parser / PCAP round-trip check (no GUI)
powershell.exe -ExecutionPolicy Bypass -File .\SMBv1-TrafficAnalyzer.ps1 -SelfTest
```

Live capture needs Administrator. Offline PCAP review, the built-in **Demo** capture, server SMB config, and event-log scan do not.

Use **v1.5+**. On startup the console should print `SMBv1 Traffic Analyzer v1.5`. If that line is missing, the file on disk is still an older copy. The window reflows when resized: the toolbar and status bar wrap, the display-filter box stretches, the Info column fills leftover list width, and the three capture panes keep their split ratio.

Older copies fail with:
- `ScriptRequiresUnmatchedPSVersion` (a Requires-Version line)
- `Unexpected token` / incomplete hash literal (`-f` inside `@{ }`)
- `Exception setting ForeColor` / `FromArgb is not a valid value for Int32` (`FromArgb(r,g,b)` inside `@{ }` or as a command argument such as `-Color [Color]::FromArgb(...)`)

## Other tools

- `AD-ObjectManager-Modern.ps1` — Active Directory user/computer bulk enable, disable, delete
- DHCP Manager scripts — production DHCP GUI patches and templates

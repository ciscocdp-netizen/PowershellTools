# PowershellTools

Windows PowerShell 5.1 admin tools (WinForms) for Server 2012 R2 and older.

## SMBv1 Traffic Analyzer

`SMBv1-TrafficAnalyzer.ps1` is a Wireshark-style live capture GUI that finds **SMBv1** on the wire (TCP 139/445), plus SMB2/SMB3 for contrast. No Npcap or Wireshark install is required.

```powershell
# Windows PowerShell 5.1 (Server 2012 R2) — elevated
powershell.exe -ExecutionPolicy Bypass -STA -File .\SMBv1-TrafficAnalyzer.ps1

# PowerShell 7+ on Windows (pwsh) — also supported
pwsh.exe -ExecutionPolicy Bypass -File .\SMBv1-TrafficAnalyzer.ps1

# Parser / PCAP round-trip check (no GUI)
powershell.exe -ExecutionPolicy Bypass -File .\SMBv1-TrafficAnalyzer.ps1 -SelfTest
```

Live capture needs Administrator. Offline PCAP review, the built-in **Demo** capture, server SMB config, and event-log scan do not.

If you see `ScriptRequiresUnmatchedPSVersion` / "Windows PowerShell version 3.0", you are running an older copy that still had a `Requires -Version` line. That directive makes **PowerShell 7** refuse to start.

If you see `Unexpected token` / `The hash literal was incomplete` around `Get-CaptureInterfaces`, you are on a copy before v1.2. Re-download the current file.

## Other tools

- `AD-ObjectManager-Modern.ps1` — Active Directory user/computer bulk enable, disable, delete
- DHCP Manager scripts — production DHCP GUI patches and templates

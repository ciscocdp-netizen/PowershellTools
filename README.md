# PowershellTools

Windows PowerShell 5.1 admin tools (WinForms) for Server 2012 R2 and older.

## SMBv1 Traffic Analyzer

`SMBv1-TrafficAnalyzer.ps1` is a Wireshark-style live capture GUI that finds **SMBv1** on the wire (TCP 139/445), plus SMB2/SMB3 for contrast. No Npcap or Wireshark install is required.

```powershell
# Elevated session on the target server
powershell.exe -ExecutionPolicy Bypass -STA -File .\SMBv1-TrafficAnalyzer.ps1

# Parser / PCAP round-trip check (no GUI)
powershell.exe -ExecutionPolicy Bypass -File .\SMBv1-TrafficAnalyzer.ps1 -SelfTest
```

Live capture needs Administrator. Offline PCAP review, the built-in **Demo** capture, server SMB config, and event-log scan do not.

## Other tools

- `AD-ObjectManager-Modern.ps1` — Active Directory user/computer bulk enable, disable, delete
- DHCP Manager scripts — production DHCP GUI patches and templates

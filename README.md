# PowershellTools

Windows PowerShell admin tools (WinForms) for Server 2008 and later.

## SMBv1 Traffic Analyzer

`SMBv1-TrafficAnalyzer.ps1` is a Wireshark-style live capture GUI that finds **SMBv1** on the wire (TCP 139/445), plus SMB2/SMB3 for contrast. No Npcap or Wireshark install is required. Targets **Windows Server 2008 / 2008 R2** (PowerShell 2.0), Server 2012 (3.0), 2012 R2 (4.0), and PowerShell 7 on Windows.

```powershell
# Server 2008 / 2012 / 2012 R2 — elevated
powershell.exe -ExecutionPolicy Bypass -STA -File .\SMBv1-TrafficAnalyzer.ps1

# PowerShell 7+ on Windows
pwsh.exe -ExecutionPolicy Bypass -File .\SMBv1-TrafficAnalyzer.ps1

# Parser / PCAP round-trip check (no GUI)
powershell.exe -ExecutionPolicy Bypass -File .\SMBv1-TrafficAnalyzer.ps1 -SelfTest
```

Live capture needs Administrator. Offline PCAP review, the built-in **Demo** capture, server SMB config, and event-log scan do not.

Use **v1.16+**. On startup the console should print `SMBv1 Traffic Analyzer v1.16`. On Server 2008, live capture no longer sets `ReceiveTimeout` on the raw socket (that made every receive fail), tries several bind/header/`SIO_RCVALL` recipes, adds a Windows Firewall allow for this `powershell.exe`, and sends a UDP probe so **Wire** should rise even without SMB clients. Watch the status bar: Wire = 0 means the NIC is still blocked (firewall or 32-bit SysWOW64 PowerShell); rising Wire with 0 Packets means uncheck **SMB ports**. **Export CSV** / Save on PowerShell 2.0 enumerates host command maps by key (calling `.ToString()` on a raw hashtable enumerator threw `You cannot call a method on a null-valued expression`).

The window reflows when resized: the toolbar and status bar wrap, the display-filter box stretches, the Info column fills leftover list width, and the three capture panes keep their split ratio.

Older copies fail with:
- `Property 'IP' cannot be found` (PowerShell 2.0 `foreach ($x in $null)` runs once; StrictMode then rejects `$x.IP`)
- `Property 'Count' cannot be found` (PowerShell 2.0 unwraps an empty list return to `$null`; StrictMode then rejects `.Count`)
- `Value cannot be null. Parameter name: item` on `ComboBox.Items.Add` (PowerShell 2.0 unwraps an empty adapter list to `@($null)`)
- `Cannot find type [System.Collections.Generic.List[SmbPacket]]` (PowerShell 2.0 cannot construct generic lists of in-memory types)
- A second command window that opens and closes immediately (STA relaunch via `Start-Process`)
- `You must provide a value expression on the right-hand side of the '-' operator` (`-shl` / `-shr`; PowerShell 2.0 on Server 2008)
- `ScriptRequiresUnmatchedPSVersion` (a `#Requires -Version 5.1` line; PowerShell 2.0 and 4.0 cannot run it)
- `Unexpected token` / incomplete hash literal (`-f` inside `@{ }`)
- `Exception setting ForeColor` / `FromArgb is not a valid value for Int32` (`FromArgb(r,g,b)` inside `@{ }` or as a command argument such as `-Color [Color]::FromArgb(...)`)

## Other tools

- `AD-ObjectManager-Modern.ps1` — Active Directory user/computer bulk enable, disable, delete
- DHCP Manager scripts — production DHCP GUI patches and templates

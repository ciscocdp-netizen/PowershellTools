# PowershellTools

Windows PowerShell admin tools (WinForms) for Server 2008 and later.

## PowerShark

`PowerShark.ps1` is a Wireshark-style live capture GUI for **all IPv4** on the local server, with capture and display filters for **Active Directory** (LDAP, Kerberos, DNS, RPC, SYSVOL/SMB), **file server / file share** traffic (SMB1/2/3, NFS), and **domain collapse** leftovers (machine accounts, GPO, simple bind, DC locator, NTP, NTLM, WINS). No Npcap or Wireshark install is required. Same Server 2008 / PowerShell 2.0 bar as the SMBv1 analyzer.

```powershell
powershell.exe -ExecutionPolicy Bypass -STA -File .\PowerShark.ps1
pwsh.exe -ExecutionPolicy Bypass -File .\PowerShark.ps1
powershell.exe -ExecutionPolicy Bypass -File .\PowerShark.ps1 -SelfTest
```

On Start, **Capture** defaults to **All traffic**. Switch it to **Active Directory**, **File shares**, or **Domain collapse** to keep only those families on the sniffer thread. Before decommissioning a domain, use **Domain collapse** plus display filters such as `collapse`, `machine`, `kdc`, `gpo`, `simplebind`, `dclocator`, `ntp`, `domain:contoso`. Talkers tab can show All / AD / File shares / Domain collapse. Console must print `PowerShark v1.2`.

The window uses a Windows 8-style Metro chrome (charcoal hub header, teal accent, tile buttons). **CLOSE AFTER** keeps the app open for a chosen time, then writes the entire capture to the Desktop as `PowerShark-yyyyMMdd_HHmmss.pcap` and exits. **Save all** (or Ctrl+Shift+S) dumps the full buffer on demand. **Save view** (Ctrl+S) writes only the filtered list. Unattended: `.\PowerShark.ps1 -AutoCloseMinutes 60`.

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

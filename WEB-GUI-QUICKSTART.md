# Web GUI Quick Start (Windows Server 2022)

## ✅ This WORKS on Your Server!

Unlike the WPF GUI which hangs, this web-based GUI works perfectly on Windows Server 2022.

## 🚀 Launch It Now

```powershell
cd "C:\Users\Anthony.Blake.ark\Documents"
.\Start-WebGUI.ps1
```

**That's it!** 

The script will:
1. ✅ Start a web server on http://localhost:8080
2. ✅ Automatically open your default browser
3. ✅ Display a modern web interface
4. ✅ Work perfectly on Server 2022

## 🎨 What You'll See

A beautiful web interface with:
- Modern gradient design
- Easy-to-use form fields
- Real-time validation
- Summary cards with metrics
- Detailed output display

## 📋 How to Use

1. **Enter GPO Details:**
   - Domain: Leave blank to auto-detect or enter your domain
   - GPO Name: The exact name of your GPO

2. **Select Test Subjects:**
   - Choose "Specific Users" and enter usernames (comma-separated)
   - OR choose "Entire OU" and enter the OU Distinguished Name

3. **Click "Run Validation"**

4. **View Results:**
   - See summary cards (Users Tested, Drives Evaluated, Conflicts)
   - Read the detailed output
   - Conflicts are highlighted

## 🔧 Example

**For your environment on Server 2022:**

1. Launch:
   ```powershell
   .\Start-WebGUI.ps1
   ```

2. In the browser form:
   - Domain: `corp.contoso.com` (or leave blank)
   - GPO Name: `Corporate Drives`
   - Select: Specific Users
   - Enter: `alice, bob, charlie`

3. Click "Run Validation"

4. Results appear instantly!

## 🌐 Access From Another Computer

If you want to access from another machine on your network:

1. Note your server's IP address:
   ```powershell
   (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4" -and $_.IPAddress -notlike "127.*"}).IPAddress
   ```

2. Launch with network access:
   ```powershell
   # Edit Start-WebGUI.ps1 and change this line:
   # $HttpListener.Prefixes.Add("http://localhost:$Port/")
   # To:
   # $HttpListener.Prefixes.Add("http://+:$Port/")
   ```

3. Allow firewall (if needed):
   ```powershell
   New-NetFirewallRule -DisplayName "GPO Validator Web" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
   ```

4. Access from another machine:
   ```
   http://YOUR-SERVER-IP:8080
   ```

## 🛑 Stopping the Server

When done, press **Ctrl+C** in the PowerShell window to stop the web server.

## ⚡ Advantages Over Other Methods

| Feature | Web GUI | WPF GUI | CLI |
|---------|---------|---------|-----|
| Works on Server 2022 | ✅ Yes | ❌ No | ✅ Yes |
| Visual Interface | ✅ Yes | ✅ Yes | ❌ No |
| Works via Remote PS | ✅ Yes | ❌ No | ✅ Yes |
| Access from Browser | ✅ Yes | ❌ No | ❌ No |
| Modern Design | ✅ Yes | ✅ Yes | ❌ No |
| Point-and-Click | ✅ Yes | ✅ Yes | ❌ No |

**Best of both worlds**: Visual interface + Server compatibility!

## 🎯 Perfect For

- ✅ Windows Server 2022 (your situation!)
- ✅ Windows Server Core
- ✅ Remote PowerShell sessions
- ✅ Environments without WPF support
- ✅ Multi-user access (optional network mode)
- ✅ Anyone who wants a GUI that actually works on servers!

## 💡 Tips

- **Port in Use?** The script will automatically try port 8081, 8082, etc.
- **Slow Network?** The validation still runs locally (fast)
- **Security?** Only listens on localhost by default (safe)
- **No Browser?** Use CLI instead: `.\Test-GpoDriveMapTargeting.ps1`

---

**This is the solution you needed!** 🎉

No more hanging, no more waiting, just a working GUI on your Windows Server 2022 machine.

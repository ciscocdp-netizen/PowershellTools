# PowershellTools

Windows PowerShell utilities with interactive GUIs.

## PS2EXE Studio

`PS2EXE-GUI.ps1` is a full WinForms workbench for [PS2EXE](https://github.com/MScholtes/PS2EXE) — the compiler that turns a PowerShell script into a standalone Windows executable.

It exposes every `Invoke-ps2exe` switch from the engine you provided (v0.5.0.31) plus the later v0.5.0.34 additions (`-conHost`, `-embedFiles`):

- File pickers with drag-and-drop for `.ps1`, `.ico`, and saved profiles
- Live validation of compiler conflicts (STA/MTA, GUI vs conhost, admin vs virtualize, config file rules, version format, unique embed names)
- Live `Invoke-ps2exe` command preview you can copy
- Presets: Console EXE, Windows GUI, Admin GUI, High-DPI WinForms, Unicode console, Forced conhost, Debug build, x86 virtualized, Long-path console
- Metadata, culture/LCID, architecture, apartment, and embedded runtime files
- Compile log, profile save/load, last-session restore, recent files

### Run on Windows

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\PS2EXE-GUI.ps1
.\PS2EXE-GUI.ps1 -InputFile C:\Tools\Backup.ps1
```

Keyboard: **F5** compile, **Ctrl+O** open script, **Ctrl+L** copy command, **Ctrl+S** save profile.

The windowed UI requires Windows. On other platforms you can still print a command:

```powershell
pwsh -File .\PS2EXE-GUI.ps1 -CommandLineOnly -InputFile ./Backup.ps1
```

Headless tests (no WinForms):

```powershell
pwsh -File .\tests\PS2EXE-Studio.Tests.ps1
```

The bundled compiler is `ps2exe/Invoke-ps2exe.ps1` (Ingo Karstein / Markus Scholtes, Microsoft Public License). See `ps2exe/THIRD-PARTY-NOTICES.txt`.

## Other tools

| Tool | Script |
|------|--------|
| Active Directory Object Manager | `AD-ObjectManager-Modern.ps1` |
| DHCP Manager v2.0 | See `START-HERE.md` |

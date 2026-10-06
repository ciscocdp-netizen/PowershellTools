<#
.SYNOPSIS
    Event Log XML Analyzer - a WPF GUI for parsing Windows Event Log XML/EVTX exports
    and surfacing probable root causes.

.DESCRIPTION
    Ingests Windows event log data exported as XML (or native .evtx) and turns it
    into a readable, searchable and correlated view of what happened.

    Supported input formats:
      * Event Viewer  -> "Save All Events As..." -> XML (*.xml)  [UTF-8 or UTF-16]
      * wevtutil qe <log> /f:xml   (multiple <Event> elements without a root)
      * Get-WinEvent ... | ForEach-Object { $_.ToXml() }
      * Native .evtx files (Windows only)
      * Any XML file that contains <Event> elements using the standard schema
      * Multiple files merged in one analysis (System + Application + Security)

    Features:
      * Dashboard with KPIs, level breakdown, top providers / event IDs, timeline
      * Root-cause findings engine (crashes, unexpected shutdowns, service failures,
        disk/hardware faults, brute-force logons, log tampering, Defender, recurring errors, bursts)
      * Incident clustering: groups errors that happened close together and points
        at the earliest event as the probable trigger
      * Built-in knowledge base for common event IDs with explanation + fix
      * Decoding of NTSTATUS / HRESULT / Win32 codes, logon types, bug check codes
      * Full-text search and filtering, related-event correlation (+/- N minutes)
      * Export to a styled HTML report, JSON, or CSV
      * Drag-and-drop .xml / .evtx files onto the window
      * Headless / CI mode with -NoGui and -SelfTest

.PARAMETER Path
    Optional .xml or .evtx file(s) to load on start-up. Multiple paths are merged.

.PARAMETER NoGui
    Run headless: parse the file and print findings to the console.

.PARAMETER ReportPath
    With -NoGui (or together with -Path), write a report. Extension selects format:
    .html (default), .json, .csv

.PARAMETER CorrelationMinutes
    Window (in minutes) used for incident clustering and related events. Default 5.

.PARAMETER MaxEvents
    Maximum events to read from a .evtx file or a live capture. 0 = no limit for XML.
    Default 5000 for .evtx / live capture.

.PARAMETER SelfTest
    Generate fixture logs, parse them, and assert the analysis engine. Exit 0/1.

.EXAMPLE
    .\EventLogAnalyzer.ps1
.EXAMPLE
    .\EventLogAnalyzer.ps1 -Path C:\Temp\System.xml
.EXAMPLE
    .\EventLogAnalyzer.ps1 -Path C:\Temp\System.xml,C:\Temp\Application.xml -NoGui -ReportPath C:\Temp\report.html
.EXAMPLE
    .\EventLogAnalyzer.ps1 -SelfTest

.NOTES
    Version 1.2.0
    Requires Windows PowerShell 5.1 (or PowerShell 7+) on Windows for the GUI.
    Headless analysis (-NoGui / -SelfTest) also runs on PowerShell 7 on other OS.
    If script execution is blocked, run:
        powershell.exe -ExecutionPolicy Bypass -File .\EventLogAnalyzer.ps1
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]]$Path,

    [switch]$NoGui,

    [string]$ReportPath,

    [ValidateRange(1, 240)]
    [int]$CorrelationMinutes = 5,

    [ValidateRange(0, 1000000)]
    [int]$MaxEvents = 5000,

    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:AppName    = 'Event Log XML Analyzer'
$script:AppVersion = '1.2.0'
$script:IsWindowsOS = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT

function Get-HostExecutable {
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $pwsh = Join-Path $PSHOME 'pwsh.exe'
        if (Test-Path -LiteralPath $pwsh) { return $pwsh }
        return 'pwsh'
    }
    return 'powershell.exe'
}

# WPF requires a single-threaded apartment. Relaunch if needed.
# Do not extra-quote ArgumentList entries: Start-Process quotes values that contain spaces.
$script:NeedsGui = -not $NoGui -and -not $SelfTest -and -not ($ReportPath -and $Path)
if ($script:NeedsGui -and -not $script:IsWindowsOS) {
    Write-Warning 'The WPF GUI requires Windows. Falling back to headless mode. Pass -Path and -NoGui (and optionally -ReportPath).'
    if (-not $Path) {
        throw 'Specify -Path when running without a GUI (non-Windows host).'
    }
    $NoGui = $true
    $script:NeedsGui = $false
}

if ($script:NeedsGui -and
    [System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $argList = [System.Collections.Generic.List[string]]::new()
    [void]$argList.Add('-NoProfile')
    [void]$argList.Add('-ExecutionPolicy')
    [void]$argList.Add('Bypass')
    [void]$argList.Add('-STA')
    [void]$argList.Add('-File')
    [void]$argList.Add($PSCommandPath)
    foreach ($p in @($Path)) {
        if ($p) {
            [void]$argList.Add('-Path')
            [void]$argList.Add($p)
        }
    }
    [void]$argList.Add('-CorrelationMinutes')
    [void]$argList.Add("$CorrelationMinutes")
    [void]$argList.Add('-MaxEvents')
    [void]$argList.Add("$MaxEvents")
    $proc = Start-Process -FilePath (Get-HostExecutable) -ArgumentList $argList.ToArray() -PassThru
    if (-not $proc) { throw 'Failed to relaunch in STA mode for the WPF GUI.' }
    return
}

#region ======================= Reference data =======================

$script:LevelNames = @{
    0 = 'Information'   # LogAlways
    1 = 'Critical'
    2 = 'Error'
    3 = 'Warning'
    4 = 'Information'
    5 = 'Verbose'
}

$script:LevelRank = @{
    'Critical'      = 0
    'Error'         = 1
    'Audit Failure' = 2
    'Warning'       = 3
    'Information'   = 4
    'Audit Success' = 5
    'Verbose'       = 6
}

$script:LevelColors = @{
    'Critical'      = '#F43F5E'
    'Error'         = '#F97316'
    'Audit Failure' = '#E879F9'
    'Warning'       = '#FACC15'
    'Information'   = '#38BDF8'
    'Audit Success' = '#34D399'
    'Verbose'       = '#94A3B8'
}

$script:LogonTypes = @{
    '0'  = 'System'
    '2'  = 'Interactive (console)'
    '3'  = 'Network (e.g. SMB share, net use)'
    '4'  = 'Batch (scheduled task)'
    '5'  = 'Service'
    '7'  = 'Unlock'
    '8'  = 'NetworkCleartext (e.g. IIS basic auth)'
    '9'  = 'NewCredentials (RunAs /netonly)'
    '10' = 'RemoteInteractive (RDP)'
    '11' = 'CachedInteractive (cached domain creds)'
    '12' = 'CachedRemoteInteractive'
    '13' = 'CachedUnlock'
}

# NTSTATUS / HRESULT / exception codes frequently seen in event data.
$script:StatusCodes = @{
    '0XC000006A' = 'Wrong password (user name is correct)'
    '0XC0000064' = 'User name does not exist'
    '0XC000006D' = 'Bad user name or authentication information'
    '0XC000006E' = 'Account restriction (e.g. blank password, logon hours)'
    '0XC000006F' = 'Logon outside allowed hours'
    '0XC0000070' = 'Logon from unauthorized workstation'
    '0XC0000071' = 'Password expired'
    '0XC0000072' = 'Account disabled'
    '0XC0000193' = 'Account expired'
    '0XC0000224' = 'User must change password at next logon'
    '0XC0000234' = 'Account locked out'
    '0XC000015B' = 'Logon type not granted to this user'
    '0XC0000133' = 'Clock skew between DC and client is too large'
    '0XC0000192' = 'NetLogon service not started'
    '0XC0000413' = 'Authentication firewall: machine not allowed'
    '0XC0000005' = 'Access violation (invalid memory read/write)'
    '0XC0000374' = 'Heap corruption'
    '0XC0000409' = 'Stack buffer overrun / fail-fast (security check)'
    '0XC00000FD' = 'Stack overflow (often infinite recursion)'
    '0XC0000135' = 'Required DLL not found'
    '0XC0000142' = 'DLL initialization failed (often desktop heap exhaustion)'
    '0XC000001D' = 'Illegal instruction'
    '0XC0000094' = 'Integer divide by zero'
    '0XC0000006' = 'In-page error (I/O error reading paged memory - disk/network)'
    '0XC000009A' = 'Insufficient system resources'
    '0XC0000017' = 'Not enough virtual memory or paging file quota'
    '0XC0000022' = 'Access denied'
    '0XC0000034' = 'Object name not found'
    '0XC0000185' = 'I/O device error'
    '0XC000020C' = 'Connection disconnected'
    '0XC0000365' = 'Failed shim / missing component'
    '0XC06D007E' = 'Delay-load module not found'
    '0XE0434352' = '.NET (CLR) unhandled managed exception'
    '0XE0434F4D' = '.NET (CLR) exception (legacy)'
    '0XE06D7363' = 'Unhandled C++ exception'
    '0X80000003' = 'Breakpoint hit (debug break / assertion)'
    '0X80070005' = 'E_ACCESSDENIED - access is denied'
    '0X80070002' = 'File not found'
    '0X80070003' = 'Path not found'
    '0X80070057' = 'E_INVALIDARG - invalid parameter'
    '0X8007000E' = 'E_OUTOFMEMORY - out of memory'
    '0X80004005' = 'E_FAIL - unspecified error'
    '0X80070070' = 'Not enough disk space'
    '0X800705B4' = 'Operation timed out'
    '0X80072EE2' = 'WinHTTP timeout (network / proxy)'
    '0X80072EFD' = 'Cannot connect to server (network / firewall)'
    '0X80072F8F' = 'TLS/SSL secure channel error (clock or certificate)'
    '0X80240022' = 'Windows Update: all updates failed'
    '0X8024402C' = 'Windows Update: proxy / name resolution failure'
    '0X800F0922' = 'Update failed (reserved partition / VPN / .NET)'
    '0X800F081F' = 'Component store source files not found (run DISM)'
    '0X80073712' = 'Component store corrupted (run DISM /RestoreHealth)'
    '0X8007045B' = 'System shutdown in progress'
    '0X8007041D' = 'Service did not respond in time'
    '0X80070422' = 'Service is disabled'
    '0XC0000001' = 'STATUS_UNSUCCESSFUL'
    '0XC0000008' = 'Invalid handle'
    '0XC000000F' = 'No such file'
    '0XC0000035' = 'Object name collision'
    '0XC000007B' = 'Bad image / invalid executable format'
    '0XC0000102' = 'File corrupted'
    '0XC000012D' = 'Quota exceeded'
    '0X80070020' = 'File in use by another process'
    '0X80070490' = 'Element not found (often CBS/DISM)'
    '0X80240034' = 'Windows Update: download failed'
    '0X80072EE7' = 'WinHTTP name resolution failure'
}

$script:Win32Errors = @{
    '2'    = 'The system cannot find the file specified'
    '3'    = 'The system cannot find the path specified'
    '5'    = 'Access is denied'
    '87'   = 'The parameter is incorrect'
    '193'  = 'Not a valid Win32 application'
    '267'  = 'The directory name is invalid'
    '1053' = 'Service did not respond to the start/control request in time'
    '1058' = 'Service is disabled or has no enabled devices'
    '1067' = 'The process terminated unexpectedly'
    '1068' = 'Dependency service or group failed to start'
    '1069' = 'Service did not start due to a logon failure'
    '1075' = 'Dependency service does not exist or is marked for deletion'
    '1079' = 'Account for this service differs from others in the same process'
    '1275' = 'This driver has been blocked from loading'
    '1326' = 'Logon failure: unknown user name or bad password'
    '1385' = 'Logon failure: logon type not granted'
    '1722' = 'The RPC server is unavailable'
    '1727' = 'Remote procedure call failed and did not execute'
    '1818' = 'The remote procedure call was cancelled (RPC timeout)'
    '2147500037' = 'E_FAIL - unspecified error'
}

$script:BugChecks = @{
    '0x0000000a' = 'IRQL_NOT_LESS_OR_EQUAL - faulty driver or RAM'
    '0x0000001a' = 'MEMORY_MANAGEMENT - RAM or driver corruption'
    '0x0000001e' = 'KMODE_EXCEPTION_NOT_HANDLED - kernel driver fault'
    '0x0000003b' = 'SYSTEM_SERVICE_EXCEPTION - driver/system service fault'
    '0x00000050' = 'PAGE_FAULT_IN_NONPAGED_AREA - bad driver, RAM, or AV'
    '0x0000007e' = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED - driver fault'
    '0x0000007f' = 'UNEXPECTED_KERNEL_MODE_TRAP - hardware/overclock'
    '0x0000009f' = 'DRIVER_POWER_STATE_FAILURE - driver hung on sleep/wake'
    '0x000000d1' = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL - faulty driver'
    '0x000000ef' = 'CRITICAL_PROCESS_DIED - a critical system process exited'
    '0x00000133' = 'DPC_WATCHDOG_VIOLATION - driver/firmware (often storage)'
    '0x00000124' = 'WHEA_UNCORRECTABLE_ERROR - hardware failure (CPU/RAM/PSU)'
    '0x00000139' = 'KERNEL_SECURITY_CHECK_FAILURE - corrupted kernel structure'
    '0x0000013a' = 'KERNEL_MODE_HEAP_CORRUPTION - driver heap corruption'
    '0x00000116' = 'VIDEO_TDR_FAILURE - display driver reset failed'
    '0x00000119' = 'VIDEO_SCHEDULER_INTERNAL_ERROR - GPU driver'
    '0x000000f4' = 'CRITICAL_OBJECT_TERMINATION - critical process/thread died (disk?)'
    '0x0000007a' = 'KERNEL_DATA_INPAGE_ERROR - disk or paging file failure'
    '0x00000077' = 'KERNEL_STACK_INPAGE_ERROR - disk read failure'
    '0x000000c2' = 'BAD_POOL_CALLER - driver bug'
    '0x00000019' = 'BAD_POOL_HEADER - driver pool corruption'
    '0x0000009c' = 'MACHINE_CHECK_EXCEPTION - hardware failure'
    '0x00000101' = 'CLOCK_WATCHDOG_TIMEOUT - CPU hang (hardware/firmware)'
    '0x000001a8' = 'BUGCODE_NDIS_DRIVER_LIVE_DUMP'
    '0x0000000d' = 'WDF_VIOLATION - Kernel-mode driver framework fault'
    '0x0000014c' = 'PNP_DETECTED_FATAL_ERROR'
    '0x00000044' = 'MULTIPLE_IRP_COMPLETE_REQUESTS'
    '0x0000003d' = 'INTERRUPT_EXCEPTION_NOT_HANDLED'
}

# Knowledge base: key = "provider-fragment|EventID" (provider match is "contains", '*' = any).
$script:KnowledgeBase = [ordered]@{
    'Kernel-Power|41'           = @('Unexpected power loss / hard reboot', 'Power & Stability',
        'The system rebooted without cleanly shutting down first. This is a symptom, not a cause: it means the machine crashed, hung, lost power, or the power button was held.',
        'Check BugcheckCode in the event data (non-zero = blue screen). Look for WHEA, disk, or BugCheck 1001 events just before this one. If BugcheckCode is 0 suspect power supply, overheating, or a hard hang; update BIOS, chipset and storage drivers.')
    'EventLog|6008'             = @('Previous shutdown was unexpected', 'Power & Stability',
        'The Event Log service recorded that the previous system shutdown was not clean.',
        'Correlate with Kernel-Power 41 and BugCheck 1001 at the same time. Review events immediately before the reported shutdown time.')
    'EventLog|6005'             = @('Event Log service started (boot)', 'Power & Stability',
        'Marks a system boot. Useful as a timeline anchor.', 'Informational.')
    'EventLog|6006'             = @('Event Log service stopped (clean shutdown)', 'Power & Stability',
        'Marks a clean shutdown.', 'Informational.')
    'EventLog|6009'             = @('Operating system version at boot', 'Power & Stability',
        'Logged at boot with the OS version, build and service pack. Useful as a timeline anchor after a reboot.',
        'Informational.')
    'User32|1074'               = @('Shutdown/restart initiated by a process or user', 'Power & Stability',
        'A process or user requested a shutdown or restart. The event lists who and why.',
        'Inspect the process name, user and reason code to determine whether the restart was expected (Windows Update, admin, software installer).')
    'BugCheck|1001'             = @('System recovered from a blue screen (bug check)', 'Power & Stability',
        'Windows crashed with a stop error and created a memory dump.',
        'Decode the bug check code. Analyze the dump (C:\Windows\MEMORY.DMP or Minidump) with WinDbg !analyze -v to identify the faulting driver. Update or roll back that driver.')
    'WHEA-Logger|17'            = @('Corrected hardware error (PCIe)', 'Hardware',
        'A hardware component reported a corrected error, often a PCI Express link issue.',
        'Usually harmless if rare. If frequent, update chipset drivers/BIOS, reseat the device, or disable PCIe ASPM.')
    'WHEA-Logger|18'            = @('Fatal hardware error (CPU / machine check)', 'Hardware',
        'The processor reported a fatal machine check. The system typically blue-screens with WHEA_UNCORRECTABLE_ERROR.',
        'Remove overclocks/XMP, update BIOS, check CPU temperatures and power supply, run hardware diagnostics.')
    'WHEA-Logger|19'            = @('Corrected machine check (CPU / cache)', 'Hardware',
        'The CPU corrected an internal error.', 'Frequent occurrences indicate failing CPU, unstable overclock, or insufficient voltage.')
    'WHEA-Logger|47'            = @('Corrected memory error', 'Hardware',
        'A memory error was corrected by ECC.', 'Repeated events point at a failing DIMM. Run memory diagnostics and replace the module.')
    'disk|7'                    = @('Bad block on disk', 'Storage',
        'The disk reported an unreadable sector.', 'Back up data immediately. Check SMART status, run chkdsk /r and plan to replace the drive.')
    'disk|11'                   = @('Disk controller error', 'Storage',
        'The driver detected a controller error on the disk.', 'Check cables, controller/firmware updates, and SMART health. Common with failing disks or loose SATA cables.')
    'disk|51'                   = @('Error during paging operation', 'Storage',
        'An error was detected on a device during a paging operation.', 'Indicates disk or storage path issues. Check disk health, cabling, and storage drivers.')
    'disk|153'                  = @('Disk I/O retried', 'Storage',
        'An I/O operation was retried because the device did not respond in time.', 'Storage is slow or failing. Check disk latency, SAN/iSCSI paths, firmware and drivers.')
    'storport|129'              = @('Storage reset issued to the device', 'Storage',
        'The storage driver had to reset the device because a request timed out.', 'Update storage controller drivers/firmware; check for failing disks or overloaded SAN.')
    'Ntfs|55'                   = @('File system corruption detected', 'Storage',
        'NTFS detected a corrupt structure on the volume.', 'Run chkdsk /f on the affected volume. Investigate the underlying disk health.')
    'Ntfs|98'                   = @('Volume needs to be checked', 'Storage',
        'NTFS flagged the volume for a consistency check.', 'Schedule chkdsk. Check disk health.')
    'Ntfs|137'                  = @('Transaction resource manager error', 'Storage',
        'NTFS transactional resource manager failed.', 'Usually follows file system corruption; run chkdsk.')
    'volmgr|46'                 = @('Crash dump initialization failed', 'Storage',
        'Windows could not set up crash dump.', 'Ensure a page file exists on the system drive and is large enough for the configured dump type.')
    'Service Control Manager|7000' = @('Service failed to start', 'Services',
        'A service could not start. The event includes the service name and error.',
        'Decode the error, verify the service binary exists, the account credentials are valid, and dependencies are running.')
    'Service Control Manager|7001' = @('Service dependency failed', 'Services',
        'A service could not start because a service it depends on failed.', 'Fix the dependency first - look for the dependency''s own 7000/7009/7023 event.')
    'Service Control Manager|7009' = @('Service start timed out', 'Services',
        'The service did not respond within the start timeout (default 30 s).',
        'Commonly caused by slow disk, AV scanning, or the service waiting for network. Consider delayed start or ServicesPipeTimeout.')
    'Service Control Manager|7011' = @('Service response timeout', 'Services',
        'A service did not respond to a control request in time.', 'The service is hung or the system is resource starved. Check CPU/disk pressure.')
    'Service Control Manager|7023' = @('Service terminated with an error', 'Services',
        'A service stopped with an error code.', 'Decode the error code and check the service''s own log.')
    'Service Control Manager|7024' = @('Service terminated with a service-specific error', 'Services',
        'The service reported its own error code.', 'Consult the application-specific documentation/log for that code.')
    'Service Control Manager|7031' = @('Service crashed unexpectedly (recovery action taken)', 'Services',
        'The service terminated unexpectedly; recovery actions (restart) were applied.',
        'Look for Application Error 1000 for the service host at the same time to find the faulting module.')
    'Service Control Manager|7034' = @('Service crashed unexpectedly', 'Services',
        'The service terminated unexpectedly.', 'Find the matching Application Error 1000 / WER 1001 event to identify the faulting module.')
    'Service Control Manager|7045' = @('New service installed', 'Security',
        'A new service was installed on the system.', 'Verify the service is expected. Unexpected services are a common persistence technique for malware.')
    'Application Error|1000'    = @('Application crash', 'Applications',
        'A process crashed. The event lists the faulting application, faulting module and exception code.',
        'Decode the exception code. If the faulting module is a third-party DLL, update or remove it. If ntdll/KERNELBASE, look at the application itself.')
    'Application Hang|1002'     = @('Application hang', 'Applications',
        'A program stopped responding and was closed.', 'Check for resource contention, network shares, or plugins. Update the application.')
    'Windows Error Reporting|1001' = @('Windows Error Reporting bucket', 'Applications',
        'WER collected information about a crash or hang.', 'Use the event name and P1-P10 parameters to identify the failing component.')
    '.NET Runtime|1026'         = @('.NET unhandled exception', 'Applications',
        'A managed application terminated due to an unhandled exception. The stack trace is included.',
        'Read the exception type and top of stack in the message. Fix the code or configuration that throws.')
    'Application Popup|26'      = @('Application popup / system message', 'Applications',
        'A system-level popup message was displayed.', 'Read the message - often reports a driver or DLL failure.')
    'Resource-Exhaustion-Detector|2004' = @('Low virtual memory', 'Performance',
        'Windows detected low virtual memory and lists the top consuming processes.',
        'Identify the process consuming memory (likely a leak). Increase page file or RAM if usage is legitimate.')
    'Perflib|1008'              = @('Performance counter DLL failed', 'Performance',
        'A performance counter library failed to open.', 'Usually benign. Rebuild counters with lodctr /R if monitoring is affected.')
    'Display|4101'              = @('Display driver stopped responding and recovered', 'Hardware',
        'GPU timeout detection and recovery (TDR) reset the display driver.', 'Update the GPU driver, check GPU temperatures, remove overclocks.')
    'DistributedCOM|10016'      = @('DCOM permission error', 'Applications',
        'An app requested DCOM activation without permission. Very common and usually benign.', 'Can usually be ignored unless a specific feature is failing.')
    'DistributedCOM|10010'      = @('DCOM server did not register in time', 'Applications',
        'A COM server did not register with DCOM within the required timeout.', 'Usually benign; investigate if the related application misbehaves.')
    'DNS Client|1014'           = @('DNS name resolution timeout', 'Network',
        'No DNS server responded for a name lookup.', 'Verify DNS server reachability, network adapter, VPN or firewall rules.')
    'NETLOGON|5719'             = @('Cannot reach a domain controller', 'Network',
        'The computer could not set up a secure session with a domain controller.',
        'Check network connectivity at boot, DNS settings pointing to DCs, and NIC driver/link speed. Common at boot when the network is slow to initialize.')
    'NETLOGON|3210'             = @('Machine account authentication failed', 'Network',
        'The computer failed to authenticate with the domain (broken trust).', 'Reset the computer account or rejoin the domain (Test-ComputerSecureChannel -Repair).')
    'Tcpip|4199'                = @('IP address conflict', 'Network',
        'Another device on the network is using the same IP address.', 'Find the conflicting MAC address and fix the DHCP reservation or static assignment.')
    'Tcpip|4227'                = @('TCP ephemeral port exhaustion', 'Network',
        'TCP/IP could not reuse a local port because all ports are in use.', 'Find the process holding thousands of connections (netstat -ano) and fix the leak.')
    'Time-Service|36'           = @('Time not synchronized', 'Network',
        'The time service has not synchronized for a long time.', 'Check w32time configuration and access to the time source (UDP 123).')
    'Time-Service|129'          = @('NTP time source unreachable', 'Network',
        'The time provider could not reach its time source.', 'Verify DNS/firewall to the NTP server or DC.')
    'GroupPolicy|1129'          = @('Group Policy failed - no network connectivity', 'Group Policy',
        'Group Policy processing failed because there was no connectivity to a domain controller.', 'Check network at logon/boot and DC reachability.')
    'GroupPolicy|1085'          = @('Group Policy extension failed', 'Group Policy',
        'A client-side extension failed to apply settings.', 'Run gpresult /h and check the specific extension (drive maps, preferences, scripts).')
    'GroupPolicy|1053'          = @('Group Policy could not resolve user/computer', 'Group Policy',
        'Group Policy could not determine the user or computer name.', 'Check DC connectivity and DNS.')
    'User Profile Service|1511' = @('Temporary profile loaded', 'User Profiles',
        'Windows could not find the user''s profile and logged them on with a temporary one.', 'Check ProfileList registry key for .bak entries and profile folder permissions.')
    'User Profile Service|1515' = @('Backup profile used', 'User Profiles',
        'Windows logged the user on with a backup copy of the profile.', 'The primary profile may be corrupt; investigate disk and registry hive.')
    'User Profile Service|1530' = @('Registry file still in use by other apps', 'User Profiles',
        'Applications kept the user hive open at logoff.', 'Usually benign. Identify the application listed in the event details.')
    'VSS|8193'                  = @('Volume Shadow Copy error', 'Backup',
        'VSS encountered an unexpected error calling a routine.', 'Check VSS writers (vssadmin list writers) and permissions; backups may be failing.')
    'VSS|12289'                 = @('Volume Shadow Copy device error', 'Backup',
        'VSS could not access a volume.', 'Check for removed/offline volumes and storage health.')
    'WindowsUpdateClient|20'    = @('Windows Update installation failure', 'Updates',
        'An update failed to install. The event includes the update title and error code.', 'Decode the error code. Run DISM /Online /Cleanup-Image /RestoreHealth and sfc /scannow, then retry.')
    'Kernel-PnP|219'            = @('Driver failed to load for a device', 'Hardware',
        'A driver could not be loaded for a device (often WUDFRd).', 'Usually benign at boot. If a device is missing, reinstall its driver.')
    'Kernel-Boot|29'            = @('Windows failed fast startup', 'Power & Stability',
        'Fast startup (hybrid boot) failed and a full boot was performed.', 'Update chipset/storage drivers or disable Fast Startup.')
    'Schannel|36887'            = @('TLS fatal alert received', 'Security',
        'A fatal TLS alert was received from the remote endpoint.', 'Check TLS version/cipher compatibility and certificates with the remote server.')
    'Schannel|36874'            = @('TLS connection request with unsupported protocol', 'Security',
        'A client tried a TLS version not enabled on this server.', 'Align TLS protocol versions between client and server.')
    'Schannel|36888'            = @('TLS fatal alert generated', 'Security',
        'This machine generated a fatal TLS alert.', 'Check certificates, cipher suites and protocol versions.')
    'Security-Auditing|4625'    = @('Failed logon', 'Security',
        'An account failed to log on. The Status/SubStatus fields explain why.',
        'Decode SubStatus. Many failures for one account = wrong saved password or attack. Many accounts from one IP = password spraying.')
    'Security-Auditing|4624'    = @('Successful logon', 'Security', 'An account logged on successfully.', 'Informational. Check Logon Type and source IP.')
    'Security-Auditing|4634'    = @('Logoff', 'Security', 'An account logged off.', 'Informational.')
    'Security-Auditing|4648'    = @('Logon with explicit credentials', 'Security',
        'A process logged on using explicitly supplied credentials (RunAs, mapped drive).', 'Review if unexpected - used in lateral movement.')
    'Security-Auditing|4672'    = @('Special privileges assigned to new logon', 'Security', 'An administrator-equivalent logon occurred.', 'Review which accounts log on with admin privileges.')
    'Security-Auditing|4688'    = @('New process created', 'Security', 'A process was created.', 'Review command lines for suspicious activity.')
    'Security-Auditing|4697'    = @('Service installed (security log)', 'Security', 'A service was installed on the system.', 'Validate the service image path.')
    'Security-Auditing|4720'    = @('User account created', 'Security', 'A user account was created.', 'Verify the account creation was authorized.')
    'Security-Auditing|4726'    = @('User account deleted', 'Security', 'A user account was deleted.', 'Verify the deletion was authorized.')
    'Security-Auditing|4728'    = @('Member added to global security group', 'Security', 'A member was added to a security-enabled global group.', 'Verify group membership changes, especially for privileged groups.')
    'Security-Auditing|4732'    = @('Member added to local security group', 'Security', 'A member was added to a security-enabled local group (e.g. Administrators).', 'Verify this change was authorized.')
    'Security-Auditing|4740'    = @('Account locked out', 'Security',
        'A user account was locked out after too many failed attempts. Caller Computer Name shows the source.',
        'Check the source machine for stale credentials (mapped drives, services, scheduled tasks, phones) or attack activity.')
    'Security-Auditing|4767'    = @('Account unlocked', 'Security', 'A user account was unlocked.', 'Informational.')
    'Security-Auditing|4771'    = @('Kerberos pre-authentication failed', 'Security',
        'Kerberos pre-auth failed, typically a bad password (failure code 0x18).', 'Check the client address for stale credentials or attack activity.')
    'Security-Auditing|4776'    = @('NTLM credential validation', 'Security', 'The DC attempted to validate NTLM credentials.', 'A non-zero error code indicates failure; decode it.')
    'Security-Auditing|1102'    = @('Security audit log cleared', 'Security',
        'The Security log was cleared. This is a high-value indicator of tampering.', 'Confirm who cleared the log and why. Treat as a potential incident if unexpected.')
    'Eventlog|1102'             = @('Security audit log cleared', 'Security',
        'The Security log was cleared. This is a high-value indicator of tampering.', 'Confirm who cleared the log and why. Treat as a potential incident if unexpected.')
    'Eventlog|104'              = @('Event log cleared', 'Security',
        'An event log was cleared.', 'Confirm the clear was authorized.')
    'Security-Auditing|5152'    = @('Packet dropped by Windows Filtering Platform', 'Network', 'The firewall blocked a packet.', 'Review source/destination if connectivity is failing.')
    'Security-Auditing|5157'    = @('Connection blocked by Windows Filtering Platform', 'Network', 'The firewall blocked a connection.', 'Review the application, port and direction.')
    'Windows Defender|1116'     = @('Malware detected', 'Security', 'Microsoft Defender detected malware or potentially unwanted software.', 'Review the threat name and path; confirm remediation succeeded (1117).')
    'Windows Defender|1117'     = @('Malware remediated', 'Security', 'Microsoft Defender took action to protect the system.', 'Verify the source of the infection.')
    'Windows Defender|5001'     = @('Real-time protection disabled', 'Security', 'Real-time protection was turned off.', 'Re-enable unless intentionally disabled; may indicate tampering.')
    'TaskScheduler|101'         = @('Scheduled task failed to start', 'Applications', 'Task Scheduler failed to start a task.', 'Check task credentials and the action path.')
    'TaskScheduler|103'         = @('Scheduled task failed (action)', 'Applications', 'Task Scheduler failed to launch the action.', 'Verify the executable path and account permissions.')
    'TaskScheduler|203'         = @('Scheduled task action failed to launch', 'Applications', 'The task action failed to start.', 'Verify the executable path and account permissions.')
    'Winlogon|4005'             = @('Winlogon process terminated unexpectedly', 'Power & Stability', 'Windows logon process terminated unexpectedly.', 'Check for shell/credential provider issues and third-party login software.')
    'SideBySide|33'             = @('Side-by-side activation context failed', 'Applications', 'An app failed due to missing or mismatched Visual C++ runtime/manifests.', 'Install/repair the required Visual C++ Redistributable.')
    'MsiInstaller|11708'        = @('Product installation failed', 'Applications', 'A Windows Installer installation failed.', 'Run the installer with logging (msiexec /l*v) to find the failing action.')
    'MsiInstaller|1033'         = @('Installer completed', 'Applications', 'Windows Installer finished. A non-zero status indicates failure.', 'Check the status code (0 = success, 1603 = fatal error).')
    'iScsiPrt|20'               = @('iSCSI connection lost', 'Storage', 'Connection to an iSCSI target was lost.', 'Check SAN network path, MPIO and NIC.')
    'e1dexpress|27'             = @('Network link down', 'Network', 'The network adapter link was disconnected.', 'Check cable, switch port, NIC power management.')
    'Diagnostics-Performance|100' = @('Slow boot', 'Performance',
        'Windows measured a slow boot. The event contains boot duration in milliseconds.',
        'Check startup apps, disk health, missing drivers and updates. Use the BootTime field to quantify.')
    'Diagnostics-Performance|200' = @('Slow shutdown', 'Performance',
        'Windows measured a slow shutdown.', 'Identify the service or driver listed as the bottleneck and update or disable it.')
    'Kernel-General|1'          = @('System time changed', 'Security',
        'The system time was changed.', 'Unexpected time jumps break Kerberos and log correlation. Confirm the change was authorized.')
    'FilterManager|3'           = @('Filter driver failed to attach', 'Storage',
        'A mini-filter driver failed to attach to a volume.', 'Often AV/backup filter related. Update that product or check disk health.')
}

function Get-HashValue {
    param($Table, $Key, $Default = $null)
    if ($null -eq $Table -or $null -eq $Key) { return $Default }
    if ($Table -is [System.Collections.IDictionary] -and $Table.Contains($Key)) { return $Table[$Key] }
    return $Default
}

#endregion

#region ======================= Parsing =======================

function Get-LocalChild {
    param($Node, [string]$Name)
    if ($null -eq $Node) { return $null }
    foreach ($c in $Node.ChildNodes) {
        if ($c.NodeType -eq 'Element' -and $c.LocalName -eq $Name) { return $c }
    }
    return $null
}

function Get-NodeText {
    param($Node)
    if ($null -eq $Node) { return '' }
    return [string]$Node.InnerText
}

function Get-Attr {
    param($Node, [string]$Name)
    if ($null -eq $Node -or $null -eq $Node.Attributes) { return '' }
    $a = $Node.Attributes.GetNamedItem($Name)
    if ($a) { return [string]$a.Value }
    return ''
}

function Remove-InvalidXmlChars {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    return [regex]::Replace($Text, '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
}

function New-XmlReaderSettings {
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.IgnoreComments = $true
    $settings.CheckCharacters = $false
    $settings.ConformanceLevel = [System.Xml.ConformanceLevel]::Fragment
    $settings.MaxCharactersFromEntities = 1024
    $settings.MaxCharactersInDocument = 0
    return $settings
}

function Get-DetectedFileEncoding {
    param([Parameter(Mandatory)][string]$FilePath)
    $fs = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $buf = New-Object byte[] 4
        $n = $fs.Read($buf, 0, 4)
        if ($n -ge 3 -and $buf[0] -eq 0xEF -and $buf[1] -eq 0xBB -and $buf[2] -eq 0xBF) {
            return New-Object System.Text.UTF8Encoding $true
        }
        if ($n -ge 2 -and $buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) { return [System.Text.Encoding]::Unicode }
        if ($n -ge 2 -and $buf[0] -eq 0xFE -and $buf[1] -eq 0xFF) { return [System.Text.Encoding]::BigEndianUnicode }
        # UTF-16 LE without BOM: "<?xm" or "<Eve" with NULs on odd bytes.
        if ($n -ge 4 -and $buf[1] -eq 0 -and $buf[3] -eq 0 -and $buf[0] -ne 0) { return [System.Text.Encoding]::Unicode }
        if ($n -ge 4 -and $buf[0] -eq 0 -and $buf[2] -eq 0) { return [System.Text.Encoding]::BigEndianUnicode }
        return New-Object System.Text.UTF8Encoding $false
    }
    finally { $fs.Dispose() }
}

function Get-EventLogFileKind {
    param([Parameter(Mandatory)][string]$FilePath)
    $ext = [System.IO.Path]::GetExtension($FilePath)
    if ($ext -and $ext.ToLowerInvariant() -eq '.evtx') { return 'evtx' }
    $fs = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $buf = New-Object byte[] 8
        $n = $fs.Read($buf, 0, 8)
        if ($n -ge 7) {
            $sig = [System.Text.Encoding]::ASCII.GetString($buf, 0, 7)
            if ($sig -eq 'ElfFile') { return 'evtx' }
        }
    }
    finally { $fs.Dispose() }
    return 'xml'
}

function ConvertTo-UInt64Safe {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim()
    try {
        if ($v -match '^0x') { return [Convert]::ToUInt64($v.Substring(2), 16) }
        if ($v -match '^-?\d+$') {
            $n = [int64]$v
            if ($n -lt 0) { return [uint64]([uint32]($n -band 0xFFFFFFFF)) }
            return [uint64]$n
        }
    }
    catch { }
    return $null
}

function Resolve-KnowledgeEntry {
    param([string]$Provider, [string]$EventId)
    if ([string]::IsNullOrWhiteSpace($EventId)) { return $null }
    foreach ($key in $script:KnowledgeBase.Keys) {
        $parts = $key.Split('|')
        if ($parts.Count -lt 2) { continue }
        if ($parts[1] -ne $EventId) { continue }
        if ($parts[0] -eq '*' -or ($Provider -and $Provider -like "*$($parts[0])*")) {
            $v = $script:KnowledgeBase[$key]
            return [pscustomobject]@{ Title = $v[0]; Category = $v[1]; Explanation = $v[2]; Recommendation = $v[3] }
        }
    }
    return $null
}

function Get-CodeDescription {
    <# Returns a human description for a status / error code value, or $null. #>
    param([string]$Value, [string]$FieldName = '')
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim()
    if ($v -match '^%%(\d+)$') { $v = $Matches[1] }

    if ($FieldName -match '^LogonType$' -and $script:LogonTypes.ContainsKey($v)) { return $script:LogonTypes[$v] }

    if ($FieldName -match 'BugcheckCode') {
        if ($v -eq '0' -or $v -eq '0x0' -or $v -eq '0x00000000') {
            return 'No bug check (power loss, hard hang or forced power-off)'
        }
        try {
            $n = if ($v -match '^0x') { [Convert]::ToInt64($v.Substring(2), 16) } else { [Convert]::ToInt64($v) }
            $hex = '0x{0:x8}' -f $n
            $desc = Get-HashValue $script:BugChecks $hex
            if ($desc) { return "$hex $desc" }
            return "Stop code $hex"
        }
        catch { }
    }

    $num = ConvertTo-UInt64Safe $v
    if ($null -ne $num) {
        $norm = '0X{0:X8}' -f $num
        $st = Get-HashValue $script:StatusCodes $norm
        if ($st) { return $st }
        $bc = '0x{0:x8}' -f $num
        if ($FieldName -match '(?i)bug|stop|param') {
            $bd = Get-HashValue $script:BugChecks $bc
            if ($bd) { return $bd }
        }
        if ($v -match '^0x') {
            # fall through to Win32 low-word if HRESULT FACILITY_WIN32 (0x8007xxxx)
            if (($num -band 0xFFFF0000) -eq 0x80070000) {
                $win = [string]($num -band 0xFFFF)
                $wd = Get-HashValue $script:Win32Errors $win
                if ($wd) { return "Win32 $win - $wd" }
            }
        }
    }

    if ($v -match '^0x[0-9a-fA-F]+$') {
        # already handled via ConvertTo-UInt64Safe; keep for hex strings longer than 8 digits
    }

    if ($FieldName -match '(?i)error|status|code|result|param') {
        $wd = Get-HashValue $script:Win32Errors $v
        if ($wd) { return "Win32 $v - $wd" }
    }
    elseif ($script:Win32Errors.ContainsKey($v)) {
        return "Win32 $v - $($script:Win32Errors[$v])"
    }
    return $null
}

function ConvertTo-ParsedEvent {
    param($EventNode, [int]$Index)

    $sys = Get-LocalChild $EventNode 'System'
    $provNode = Get-LocalChild $sys 'Provider'
    $provider = Get-Attr $provNode 'Name'
    if (-not $provider) { $provider = Get-Attr $provNode 'EventSourceName' }

    $idNode = Get-LocalChild $sys 'EventID'
    $eventId = (Get-NodeText $idNode).Trim()

    $levelNum = 4
    $lvlText = (Get-NodeText (Get-LocalChild $sys 'Level')).Trim()
    if ($lvlText -match '^\d+$') { $levelNum = [int]$lvlText }
    $level = Get-HashValue $script:LevelNames $levelNum 'Information'

    $keywords = (Get-NodeText (Get-LocalChild $sys 'Keywords')).Trim()
    $kwNum = ConvertTo-UInt64Safe $keywords
    if ($null -ne $kwNum) {
        if (($kwNum -band [uint64]0x0010000000000000) -ne 0) { $level = 'Audit Failure' }
        elseif (($kwNum -band [uint64]0x0020000000000000) -ne 0) { $level = 'Audit Success' }
    }

    $timeNode = Get-LocalChild $sys 'TimeCreated'
    $timeRaw = Get-Attr $timeNode 'SystemTime'
    $time = [datetime]::MinValue
    if ($timeRaw) {
        $parsed = [datetime]::MinValue
        if ([datetime]::TryParse($timeRaw, [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
            $time = $parsed.ToLocalTime()
        }
    }

    $exec = Get-LocalChild $sys 'Execution'
    $sec  = Get-LocalChild $sys 'Security'

    $data = New-Object System.Collections.Generic.List[object]
    $ed = Get-LocalChild $EventNode 'EventData'
    if ($ed) {
        $i = 0
        foreach ($d in $ed.ChildNodes) {
            if ($d.NodeType -ne 'Element') { continue }
            $i++
            $name = Get-Attr $d 'Name'
            if (-not $name) { $name = if ($d.LocalName -eq 'Data') { "param$i" } else { $d.LocalName } }
            $data.Add([pscustomobject]@{ Name = $name; Value = [string]$d.InnerText })
        }
    }
    $ud = Get-LocalChild $EventNode 'UserData'
    if ($ud) {
        foreach ($wrapper in $ud.ChildNodes) {
            if ($wrapper.NodeType -ne 'Element') { continue }
            $leaves = @($wrapper.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })
            if ($leaves.Count -eq 0) { $data.Add([pscustomobject]@{ Name = $wrapper.LocalName; Value = [string]$wrapper.InnerText }) }
            foreach ($leaf in $leaves) { $data.Add([pscustomobject]@{ Name = $leaf.LocalName; Value = [string]$leaf.InnerText }) }
        }
    }

    $ri = Get-LocalChild $EventNode 'RenderingInfo'
    $message = ''
    $taskName = ''
    if ($ri) {
        $message = (Get-NodeText (Get-LocalChild $ri 'Message')).Trim()
        $taskName = (Get-NodeText (Get-LocalChild $ri 'Task')).Trim()
    }
    if (-not $taskName) {
        $t = (Get-NodeText (Get-LocalChild $sys 'Task')).Trim()
        if ($t -and $t -ne '0') { $taskName = "Task $t" }
    }

    $kb = Resolve-KnowledgeEntry -Provider $provider -EventId $eventId

    $decoded = New-Object System.Collections.Generic.List[object]
    $dataLookup = @{}
    foreach ($d in $data) {
        if (-not $dataLookup.ContainsKey($d.Name)) { $dataLookup[$d.Name] = $d.Value }
        $desc = Get-CodeDescription -Value $d.Value -FieldName $d.Name
        $decoded.Add([pscustomobject]@{ Name = $d.Name; Value = $d.Value; Meaning = $(if ($desc) { $desc } else { '' }) })
    }

    if (-not $message) {
        if ($data.Count -gt 0) {
            $message = ($data | Where-Object { $_.Value } | ForEach-Object { "$($_.Name): $($_.Value)" }) -join '; '
        }
    }
    $summary = if ($null -eq $message) { '' } else { [string]$message }
    if ($summary) { $summary = ($summary -replace '\s+', ' ').Trim() }
    if ($summary.Length -gt 220) { $summary = $summary.Substring(0, 217) + '...' }
    if (-not $summary -and $kb) { $summary = $kb.Title }

    $searchText = ("$provider $eventId $level $taskName $message " + (($data | ForEach-Object { $_.Value }) -join ' ')).ToLowerInvariant()

    $levelRank = Get-HashValue $script:LevelRank $level 4
    $levelColor = Get-HashValue $script:LevelColors $level '#94A3B8'
    $timeText = if ($time -ne [datetime]::MinValue) {
        $time.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    } else { '' }

    [pscustomobject]@{
        Index          = $Index
        Time           = $time
        TimeText       = $timeText
        Level          = $level
        LevelRank      = [int]$levelRank
        LevelColor     = $levelColor
        Provider       = $provider
        EventId        = $eventId
        Task           = $taskName
        Channel        = (Get-NodeText (Get-LocalChild $sys 'Channel')).Trim()
        Computer       = (Get-NodeText (Get-LocalChild $sys 'Computer')).Trim()
        RecordId       = (Get-NodeText (Get-LocalChild $sys 'EventRecordID')).Trim()
        ProcessId      = Get-Attr $exec 'ProcessID'
        ThreadId       = Get-Attr $exec 'ThreadID'
        UserSid        = Get-Attr $sec 'UserID'
        Keywords       = $keywords
        Message        = $message
        Summary        = $summary
        Data           = $data.ToArray()
        DataLookup     = $dataLookup
        Decoded        = $decoded.ToArray()
        KbTitle        = $(if ($kb) { $kb.Title } else { '' })
        KbCategory     = $(if ($kb) { $kb.Category } else { 'Other' })
        KbExplanation  = $(if ($kb) { $kb.Explanation } else { '' })
        KbAdvice       = $(if ($kb) { $kb.Recommendation } else { '' })
        SearchText     = $searchText
        RawXml         = $EventNode.OuterXml
    }
}

function Convert-EventXmlString {
    param([string]$Xml, [int]$Index, [string]$MessageOverride)
    $clean = Remove-InvalidXmlChars $Xml
    $doc = New-Object System.Xml.XmlDocument
    $doc.XmlResolver = $null
    $doc.LoadXml($clean)
    $evt = ConvertTo-ParsedEvent -EventNode $doc.DocumentElement -Index $Index
    if ($MessageOverride -and -not $evt.Message) {
        $evt.Message = $MessageOverride
        $sum = ($MessageOverride -replace '\s+', ' ').Trim()
        if ($sum.Length -gt 220) { $sum = $sum.Substring(0, 217) + '...' }
        $evt.Summary = $sum
        $evt.SearchText = ($evt.SearchText + ' ' + $MessageOverride.ToLowerInvariant())
    }
    return $evt
}

function Import-EventsFromXmlText {
    param([string]$Raw, [int]$StartIndex = 0, [scriptblock]$OnProgress)
    $clean = Remove-InvalidXmlChars $Raw
    $clean = [regex]::Replace($clean, '<\?xml[^>]*\?>', '')
    if ($clean -notmatch '(?s)<\s*[\w\-.]+:?EventLogAnalyzerRoot') {
        $clean = "<EventLogAnalyzerRoot>$clean</EventLogAnalyzerRoot>"
    }
    $settings = New-XmlReaderSettings
    $doc = New-Object System.Xml.XmlDocument
    $doc.XmlResolver = $null
    $reader = $null
    try {
        $reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($clean)), $settings)
        $doc.Load($reader)
    }
    finally {
        if ($reader) { $reader.Close() }
    }
    $nodes = $doc.SelectNodes("//*[local-name()='Event' and *[local-name()='System']]")
    $list = New-Object System.Collections.Generic.List[object]
    if ($null -eq $nodes) { return $list }
    $total = $nodes.Count
    $i = $StartIndex
    foreach ($n in $nodes) {
        $i++
        try { $list.Add((ConvertTo-ParsedEvent -EventNode $n -Index $i)) }
        catch { Write-Verbose "Skipping malformed event #$i : $($_.Exception.Message)" }
        if ($OnProgress -and ($i % 250 -eq 0 -or ($i - $StartIndex) -eq $total)) {
            & $OnProgress $i $total
        }
    }
    return $list
}

function Import-EventsFromXmlFile {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [int]$StartIndex = 0,
        [scriptblock]$OnProgress
    )
    $encoding = Get-DetectedFileEncoding -FilePath $FilePath
    $settings = New-XmlReaderSettings
    $list = New-Object System.Collections.Generic.List[object]
    $index = $StartIndex
    $fileLen = [math]::Max(1L, (Get-Item -LiteralPath $FilePath).Length)
    $stream = $null
    $xmlReader = $null
    try {
        $stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $reader = New-Object System.IO.StreamReader($stream, $encoding, $true, 65536, $true)
        $xmlReader = [System.Xml.XmlReader]::Create($reader, $settings)
        while ($xmlReader.Read()) {
            if ($xmlReader.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            if ($xmlReader.LocalName -ne 'Event') { continue }
            $outer = $xmlReader.ReadOuterXml()
            if ([string]::IsNullOrWhiteSpace($outer)) { continue }
            if ($outer.IndexOf('System', [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
            $index++
            try { $list.Add((Convert-EventXmlString -Xml $outer -Index $index)) }
            catch { Write-Verbose "Skipping malformed event #$index : $($_.Exception.Message)" }
            if ($OnProgress -and ($index % 200 -eq 0)) {
                $guess = [int][math]::Max($index, $index / [math]::Max(0.05, ($stream.Position / $fileLen)))
                & $OnProgress $index $guess
            }
        }
    }
    catch {
        Write-Verbose "Streaming XML parse failed, falling back to wrap: $($_.Exception.Message)"
        $raw = [System.IO.File]::ReadAllText($FilePath, $encoding)
        $list = Import-EventsFromXmlText -Raw $raw -StartIndex $StartIndex -OnProgress $OnProgress
    }
    finally {
        if ($xmlReader) { try { $xmlReader.Close() } catch { } }
        if ($stream) { try { $stream.Dispose() } catch { } }
    }
    if ($list.Count -eq 0) {
        $raw = [System.IO.File]::ReadAllText($FilePath, $encoding)
        $list = Import-EventsFromXmlText -Raw $raw -StartIndex $StartIndex -OnProgress $OnProgress
    }
    return $list
}

function Import-EventsFromEvtx {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [int]$StartIndex = 0,
        [int]$Limit = 0,
        [scriptblock]$OnProgress
    )
    if (-not $script:IsWindowsOS) {
        throw '.evtx import requires Windows (Get-WinEvent). Re-export the log as XML on a Windows host, or run this script there.'
    }
    $params = @{ Path = $FilePath; ErrorAction = 'Stop' }
    if ($Limit -gt 0) { $params.MaxEvents = $Limit }
    $records = @(Get-WinEvent @params)
    $list = New-Object System.Collections.Generic.List[object]
    $index = $StartIndex
    $total = $records.Count
    foreach ($r in $records) {
        $index++
        try {
            $xml = $r.ToXml()
            $msg = $null
            try { $msg = $r.FormatDescription() } catch { }
            if (-not $msg) { try { $msg = $r.Message } catch { } }
            $list.Add((Convert-EventXmlString -Xml $xml -Index $index -MessageOverride $msg))
        }
        catch { Write-Verbose "Skipping evtx record #$index : $($_.Exception.Message)" }
        if ($OnProgress -and ($index % 200 -eq 0 -or ($index - $StartIndex) -eq $total)) {
            & $OnProgress $index $total
        }
    }
    return $list
}

function Import-EventLogXml {
    param(
        [Parameter(Mandatory)][string[]]$FilePath,
        [scriptblock]$OnProgress,
        [int]$Limit = 0
    )
    $list = New-Object System.Collections.Generic.List[object]
    $index = 0
    foreach ($fp in @($FilePath)) {
        if ([string]::IsNullOrWhiteSpace($fp)) { continue }
        if (-not (Test-Path -LiteralPath $fp)) { throw "File not found: $fp" }
        $resolved = (Resolve-Path -LiteralPath $fp).ProviderPath
        $kind = Get-EventLogFileKind -FilePath $resolved
        $remaining = if ($Limit -gt 0) { [math]::Max(0, $Limit - $list.Count) } else { 0 }
        if ($kind -eq 'evtx') {
            $chunk = Import-EventsFromEvtx -FilePath $resolved -StartIndex $index -Limit $remaining -OnProgress $OnProgress
        }
        else {
            $chunk = Import-EventsFromXmlFile -FilePath $resolved -StartIndex $index -OnProgress $OnProgress
        }
        foreach ($e in $chunk) { $list.Add($e) }
        $index = $list.Count
        if ($Limit -gt 0 -and $list.Count -ge $Limit) { break }
    }
    if ($list.Count -eq 0) { throw 'No <Event> elements with a <System> section were found in this file.' }
    $sorted = @($list | Sort-Object -Property Time, Index)
    return ,$sorted
}

#endregion

#region ======================= Analysis =======================

function Get-DataValue {
    param($Evt, [string[]]$Names)
    if ($null -eq $Evt -or $null -eq $Evt.DataLookup) { return '' }
    foreach ($n in $Names) {
        if ($Evt.DataLookup.ContainsKey($n) -and $Evt.DataLookup[$n]) { return [string]$Evt.DataLookup[$n] }
    }
    return ''
}

function Merge-EventLists {
    param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Lists)
    $seen = @{}
    $r = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($Lists)) {
        foreach ($e in @($item)) {
            if ($null -eq $e) { continue }
            $ix = [int]$e.Index
            if ($seen.ContainsKey($ix)) { continue }
            $seen[$ix] = $true
            $r.Add($e)
        }
    }
    $sorted = @($r | Sort-Object Time, Index)
    return ,$sorted
}

function New-Finding {
    param(
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [string]$Category, [string]$Title, [string]$Detail, [string]$Recommendation,
        [object[]]$Events
    )
    $colors = @{ Critical = '#F43F5E'; High = '#F97316'; Medium = '#FACC15'; Low = '#38BDF8'; Info = '#94A3B8' }
    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $evs = @($Events | Where-Object { $_ })
    $first = ''; $last = ''
    if ($evs.Count -gt 0) {
        $first = ($evs | Select-Object -First 1).TimeText
        $last  = ($evs | Select-Object -Last 1).TimeText
    }
    [pscustomobject]@{
        Severity       = $Severity
        SeverityRank   = $rank[$Severity]
        SeverityColor  = $colors[$Severity]
        Category       = $Category
        Title          = $Title
        Detail         = $Detail
        Recommendation = $Recommendation
        Count          = $evs.Count
        CountText      = $(if ($evs.Count -eq 1) { '1 event' } else { "$($evs.Count) events" })
        FirstSeen      = $first
        LastSeen       = $last
        Window         = $(if ($first -and $first -ne $last) { "$first  ->  $last" } else { $first })
        EventIndexes   = @($evs | ForEach-Object { $_.Index })
    }
}

function Invoke-EventAnalysis {
    param([Parameter(Mandatory)][object[]]$Events, [int]$WindowMinutes = 5)

    $findings = New-Object System.Collections.Generic.List[object]
    $byKey = @{}
    foreach ($e in $Events) {
        $k = "$($e.Provider)|$($e.EventId)"
        if (-not $byKey.ContainsKey($k)) { $byKey[$k] = New-Object System.Collections.Generic.List[object] }
        $byKey[$k].Add($e)
    }
    function Get-ByIds([string]$prov, [string[]]$ids) {
        $r = New-Object System.Collections.Generic.List[object]
        foreach ($k in $byKey.Keys) {
            $pipe = $k.LastIndexOf('|')
            if ($pipe -lt 0) { continue }
            $pName = $k.Substring(0, $pipe)
            $eventIdPart = $k.Substring($pipe + 1)
            if (($pName -like "*$prov*") -and ($ids -contains $eventIdPart)) { foreach ($x in $byKey[$k]) { $r.Add($x) } }
        }
        return @($r | Sort-Object Time, Index)
    }

    $posByIndex = @{}
    for ($pi = 0; $pi -lt $Events.Count; $pi++) { $posByIndex[[int]$Events[$pi].Index] = $pi }

    function Get-PriorErrors {
        param($Anchor, [int]$Minutes = 30, [int]$Take = 3)
        $ix = [int]$Anchor.Index
        if (-not $posByIndex.ContainsKey($ix)) { return @() }
        $pos = [int]$posByIndex[$ix]
        if ($Anchor.Time -eq [datetime]::MinValue) { return @() }
        $lo = $Anchor.Time.AddMinutes(-$Minutes)
        $acc = New-Object System.Collections.Generic.List[object]
        for ($i = $pos - 1; $i -ge 0; $i--) {
            $prev = $Events[$i]
            if ($prev.Time -ne [datetime]::MinValue -and $prev.Time -lt $lo) { break }
            if ([int]$prev.LevelRank -le 1 -and [int]$prev.Index -ne $ix) {
                [void]$acc.Add($prev)
                if ($acc.Count -ge $Take) { break }
            }
        }
        return $acc.ToArray()
    }

    # ---- Unexpected shutdowns / blue screens
    $kp = @(Get-ByIds 'Kernel-Power' @('41'))
    $bsod = @(Get-ByIds 'BugCheck' @('1001'))
    $unexp = @(Get-ByIds 'EventLog' @('6008'))
    if ($kp.Count -gt 0 -or $unexp.Count -gt 0 -or $bsod.Count -gt 0) {
        $codes = @($kp | ForEach-Object { Get-DataValue $_ @('BugcheckCode') } | Where-Object { $_ -and $_ -ne '0' } | Select-Object -Unique)
        $detail = "Detected $($kp.Count) Kernel-Power 41, $($unexp.Count) unexpected shutdown (6008) and $($bsod.Count) BugCheck (1001) events."
        $rec = ''
        if ($bsod.Count -gt 0 -or $codes.Count -gt 0) {
            $decodedCodes = @($codes | ForEach-Object { Get-CodeDescription -Value $_ -FieldName 'BugcheckCode' } | Where-Object { $_ })
            if ($decodedCodes.Count -gt 0) { $detail += " Stop codes: " + ($decodedCodes -join '; ') + '.' }
            $rec = 'The system blue-screened. Analyze the memory dump with WinDbg (!analyze -v) to find the faulting driver, then update/roll back that driver. Check for WHEA hardware events around the same time.'
        } else {
            $rec = 'No bug check code was recorded - this points at power loss, a hard hang, or a forced power-off. Check PSU, UPS, temperatures, BIOS and storage/chipset drivers. Review the events right before each reboot in the Incidents tab.'
        }
        $pre = New-Object System.Collections.Generic.List[string]
        foreach ($k in $kp) {
            foreach ($p in (Get-PriorErrors $k 30 3)) { $pre.Add("$($p.Provider) $($p.EventId)") }
        }
        $preTop = @($pre | Group-Object | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name) (x$($_.Count))" })
        if ($preTop.Count -gt 0) { $detail += ' Errors seen in the 30 min before the reboot(s): ' + ($preTop -join ', ') + '.' }
        $findings.Add((New-Finding -Severity 'Critical' -Category 'Power & Stability' -Title 'Unexpected reboots / system crashes' -Detail $detail -Recommendation $rec -Events (Merge-EventLists $kp $unexp $bsod)))
    }

    $planned = @(Get-ByIds 'User32' @('1074'))
    if ($planned.Count -gt 0) {
        $who = @($planned | ForEach-Object { "$(Get-DataValue $_ @('param1','process')) by $(Get-DataValue $_ @('param7','param6','user'))" } | Where-Object { $_ -ne ' by ' } | Select-Object -Unique -First 5)
        $findings.Add((New-Finding -Severity 'Info' -Category 'Power & Stability' -Title 'Planned shutdowns / restarts' `
            -Detail ("$($planned.Count) initiated shutdown/restart event(s)." + $(if ($who.Count) { ' Sources: ' + ($who -join '; ') + '.' } else { '' })) `
            -Recommendation 'Use these as timeline anchors. A Kernel-Power 41 shortly after an initiated restart is still unexpected - the restart did not complete cleanly.' -Events $planned))
    }

    # ---- Hardware (WHEA)
    $whea = @(Get-ByIds 'WHEA' @('17', '18', '19', '20', '46', '47'))
    if ($whea.Count -gt 0) {
        $fatal = @($whea | Where-Object { $_.EventId -in @('18', '20', '46') })
        $sev = if ($fatal.Count -gt 0) { 'Critical' } elseif ($whea.Count -ge 10) { 'High' } else { 'Medium' }
        $findings.Add((New-Finding -Severity $sev -Category 'Hardware' -Title 'Hardware errors reported by WHEA' `
            -Detail "$($whea.Count) WHEA hardware error events ($($fatal.Count) fatal). These come directly from the CPU, memory controller or PCIe bus." `
            -Recommendation 'Update BIOS/firmware and chipset drivers, remove overclocks/XMP, check temperatures and PSU, run memory and CPU diagnostics. Fatal WHEA errors usually mean failing hardware.' -Events $whea))
    }

    # ---- Storage
    $disk = Merge-EventLists (Get-ByIds 'disk' @('7', '11', '51', '153')) (Get-ByIds 'storport' @('129')) (Get-ByIds 'Ntfs' @('55', '98', '137')) (Get-ByIds 'stornvme' @('11', '129')) (Get-ByIds 'iaStor' @('9', '129')) (Get-ByIds 'iScsiPrt' @('20', '39', '9')) (Get-ByIds 'FilterManager' @('3'))
    if ($disk.Count -gt 0) {
        $devices = @($disk | ForEach-Object { Get-DataValue $_ @('DeviceName', 'param1', 'DriveName') } | Where-Object { $_ } | Select-Object -Unique -First 5)
        $sev = if (@($disk | Where-Object { $_.EventId -in @('7', '55') }).Count -gt 0) { 'Critical' } else { 'High' }
        $findings.Add((New-Finding -Severity $sev -Category 'Storage' -Title 'Disk / storage subsystem errors' `
            -Detail ("$($disk.Count) storage-related errors (bad blocks, controller errors, timeouts or file system corruption)." + $(if ($devices.Count) { ' Devices: ' + ($devices -join ', ') + '.' } else { '' })) `
            -Recommendation 'Back up data now. Check SMART/health (Get-PhysicalDisk, vendor tools), replace suspect drives or cables, update storage controller firmware/drivers, then run chkdsk /r. Storage faults frequently cause application hangs, service timeouts and crashes downstream.' -Events $disk))
    }

    # ---- Application crashes
    $crashes = @(Get-ByIds 'Application Error' @('1000'))
    if ($crashes.Count -gt 0) {
        $groups = $crashes | Group-Object { "$(Get-DataValue $_ @('AppName','param1'))|$(Get-DataValue $_ @('ModuleName','param4'))|$(Get-DataValue $_ @('ExceptionCode','param7'))" } | Sort-Object Count -Descending
        foreach ($g in ($groups | Select-Object -First 6)) {
            $p = $g.Name.Split('|')
            $app = if ($p[0]) { $p[0] } else { 'Unknown application' }
            $mod = if ($p.Count -gt 1 -and $p[1]) { $p[1] } else { 'unknown module' }
            $code = if ($p.Count -gt 2) { $p[2] } else { '' }
            $codeForDecode = if ($code -and $code -notmatch '^0x' -and $code -match '^[0-9a-fA-F]+$') { "0x$code" } else { $code }
            $codeDesc = Get-CodeDescription -Value $codeForDecode -FieldName 'ExceptionCode'
            $detail = "$app crashed $($g.Count) time(s) in module $mod" + $(if ($code) { " with exception $code" } else { '' }) + $(if ($codeDesc) { " ($codeDesc)." } else { '.' })
            $rec = if ($mod -match '(?i)^(ntdll|kernelbase|kernel32|ucrtbase|msvcr|msvcp|vcruntime)') {
                "The fault surfaced in a core Windows/runtime library, so the bug is most likely in $app itself or a plugin it loads. Update or repair $app, check for .NET Runtime 1026 events with a stack trace, and repair the Visual C++ runtimes."
            } elseif ($mod -match '(?i)clr|coreclr|mscorwks') {
                'Managed (.NET) crash - look for the matching .NET Runtime 1026 event for the exception and stack trace.'
            } else {
                "The faulting module $mod is likely the root cause. Identify its vendor (file properties), update or remove it, and retest."
            }
            $sev = if ($g.Count -ge 5) { 'High' } else { 'Medium' }
            $findings.Add((New-Finding -Severity $sev -Category 'Applications' -Title "Application crash: $app" -Detail $detail -Recommendation $rec -Events @($g.Group)))
        }
    }
    $hangs = @(Get-ByIds 'Application Hang' @('1002'))
    if ($hangs.Count -gt 0) {
        $apps = @($hangs | Group-Object { Get-DataValue $_ @('param1', 'AppName') } | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) (x$($_.Count))" })
        $findings.Add((New-Finding -Severity 'Medium' -Category 'Applications' -Title 'Applications stopped responding' `
            -Detail ("$($hangs.Count) hang events. Top: " + ($apps -join ', ') + '.') `
            -Recommendation 'Hangs are usually caused by waiting on disk, network shares, or locks. Correlate with storage or network errors at the same time; update the application.' -Events $hangs))
    }
    $dotnet = @(Get-ByIds '.NET Runtime' @('1026'))
    if ($dotnet.Count -gt 0) {
        $types = @($dotnet | ForEach-Object { if ($_.Message -match 'Exception Info:\s*([\w\.]+)') { $Matches[1] } } | Group-Object | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name) (x$($_.Count))" })
        $findings.Add((New-Finding -Severity 'Medium' -Category 'Applications' -Title '.NET unhandled exceptions' `
            -Detail ("$($dotnet.Count) .NET applications terminated due to unhandled exceptions." + $(if ($types.Count) { ' Exception types: ' + ($types -join ', ') + '.' } else { '' })) `
            -Recommendation 'Open the event to read the full stack trace; the top frames that belong to the application point at the failing code or configuration.' -Events $dotnet))
    }

    # ---- Services
    $svc = @(Get-ByIds 'Service Control Manager' @('7000', '7001', '7009', '7011', '7022', '7023', '7024', '7031', '7034', '7038'))
    if ($svc.Count -gt 0) {
        $groups = $svc | Group-Object {
            $n = Get-DataValue $_ @('param1', 'ServiceName')
            if ($n -match '^\d+$') { $n = Get-DataValue $_ @('param2') }
            $n
        } | Sort-Object Count -Descending
        foreach ($g in ($groups | Select-Object -First 6)) {
            $name = if ($g.Name) { $g.Name } else { 'Unknown service' }
            $ids = @($g.Group | Select-Object -ExpandProperty EventId -Unique)
            $errs = @($g.Group | ForEach-Object { Get-DataValue $_ @('param2', 'param3') } | Where-Object { $_ -match '^\d+$|^%%\d+$' } | ForEach-Object { $_ -replace '%%', '' } | Select-Object -Unique)
            $errDesc = @($errs | ForEach-Object { $d = Get-HashValue $script:Win32Errors $_; if ($d) { "$_ ($d)" } else { $null } } | Where-Object { $_ })
            $kind = if ($ids -contains '7031' -or $ids -contains '7034') { 'crashed unexpectedly' }
                    elseif ($ids -contains '7009' -or $ids -contains '7011') { 'timed out' }
                    elseif ($ids -contains '7001') { 'could not start because a dependency failed' }
                    else { 'failed' }
            $rec = switch -Regex ($kind) {
                'crashed'    { "Find the Application Error 1000 event for the service's process at the same time to identify the faulting module. Check the service's own logs." }
                'timed out'  { 'Service start timeouts are usually caused by slow disk, AV scanning, or waiting on network/DC. Consider Automatic (Delayed Start) and check storage health.' }
                'dependency' { 'Fix the dependency first. Look for that service''s own 7000/7009/7023 events - it is the actual root cause.' }
                default      { 'Verify the service account credentials, binary path and dependencies (sc qc <name>). Decode the error code shown.' }
            }
            $sev = if ($g.Count -ge 5 -or $kind -eq 'crashed unexpectedly') { 'High' } else { 'Medium' }
            $findings.Add((New-Finding -Severity $sev -Category 'Services' -Title "Service $kind`: $name" `
                -Detail ("$name $kind $($g.Count) time(s) (event IDs: $($ids -join ', '))." + $(if ($errDesc.Count) { ' Error: ' + ($errDesc -join '; ') + '.' } else { '' })) `
                -Recommendation $rec -Events @($g.Group)))
        }
    }

    # ---- Security: failed logons
    $failedNtlm = @(Get-ByIds 'Security-Auditing' @('4776') | Where-Object { (Get-DataValue $_ @('Status')) -notin @('', '0x0', '0x00000000', '0') })
    $failed = Merge-EventLists (Get-ByIds 'Security-Auditing' @('4625', '4771')) $failedNtlm
    if ($failed.Count -gt 0) {
        $byAcct = $failed | Group-Object { Get-DataValue $_ @('TargetUserName') } | Sort-Object Count -Descending
        $byIp = $failed | Group-Object { Get-DataValue $_ @('IpAddress', 'Workstation', 'WorkstationName') } | Sort-Object Count -Descending
        $reasons = @($failed | ForEach-Object { $s = Get-DataValue $_ @('SubStatus', 'Status'); if ($s) { $d = Get-CodeDescription $s -FieldName 'Status'; if ($d) { $d } else { $s } } } | Group-Object | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name) (x$($_.Count))" })
        $topAcct = @($byAcct | Select-Object -First 3 | ForEach-Object { "$($_.Name) (x$($_.Count))" })
        $topIp = @($byIp | Where-Object { $_.Name -and $_.Name -ne '-' } | Select-Object -First 3 | ForEach-Object { "$($_.Name) (x$($_.Count))" })
        $spray = @($byIp | Where-Object { $_.Name -and $_.Name -ne '-' -and (@($_.Group | ForEach-Object { Get-DataValue $_ @('TargetUserName') } | Select-Object -Unique).Count -ge 5) })
        $sev = if ($spray.Count -gt 0 -or $failed.Count -ge 50) { 'High' } elseif ($failed.Count -ge 10) { 'Medium' } else { 'Low' }
        $title = if ($spray.Count -gt 0) { 'Possible password spraying / brute-force activity' } else { 'Failed logon attempts' }
        $detail = "$($failed.Count) failed authentications. Accounts: $($topAcct -join ', ')." + $(if ($topIp.Count) { " Sources: $($topIp -join ', ')." } else { '' }) + $(if ($reasons.Count) { " Reasons: $($reasons -join ', ')." } else { '' })
        $rec = if ($spray.Count -gt 0) { 'One source is trying many different accounts - treat as an attack. Block the source IP, enforce MFA/lockout policies, and review successful logons (4624) from that source.' }
               else { 'Repeated failures for one account usually mean stale saved credentials (mapped drives, services, scheduled tasks, mobile devices). Check the source workstation. Failures with "User name does not exist" across many names indicate enumeration.' }
        $findings.Add((New-Finding -Severity $sev -Category 'Security' -Title $title -Detail $detail -Recommendation $rec -Events $failed))
    }
    $lock = @(Get-ByIds 'Security-Auditing' @('4740'))
    if ($lock.Count -gt 0) {
        $who = @($lock | Group-Object { "$(Get-DataValue $_ @('TargetUserName')) from $(Get-DataValue $_ @('TargetDomainName','CallerComputerName'))" } | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) (x$($_.Count))" })
        $findings.Add((New-Finding -Severity 'High' -Category 'Security' -Title 'Account lockouts' -Detail ("$($lock.Count) lockouts: " + ($who -join ', ') + '. The "from" value is the caller computer that sent the bad passwords.') `
            -Recommendation 'Go to the caller computer and look for stale credentials (Credential Manager, mapped drives, services, scheduled tasks, RDP sessions, phones syncing mail).' -Events $lock))
    }
    $cleared = Merge-EventLists (Get-ByIds 'Eventlog' @('1102', '104')) (Get-ByIds 'Security-Auditing' @('1102'))
    if ($cleared.Count -gt 0) {
        $findings.Add((New-Finding -Severity 'Critical' -Category 'Security' -Title 'Event logs were cleared' -Detail "$($cleared.Count) log-clear events. Clearing logs destroys evidence and is a common anti-forensics step." `
            -Recommendation 'Identify the account that cleared the log (SubjectUserName) and confirm it was authorized. If not, treat the host as compromised.' -Events $cleared))
    }
    $newSvc = Merge-EventLists (Get-ByIds 'Service Control Manager' @('7045')) (Get-ByIds 'Security-Auditing' @('4697'))
    if ($newSvc.Count -gt 0) {
        $names = @($newSvc | ForEach-Object { "$(Get-DataValue $_ @('ServiceName','param1')) [$(Get-DataValue $_ @('ImagePath','ServiceFileName','param2'))]" } | Select-Object -Unique -First 5)
        $suspicious = @($newSvc | Where-Object { (Get-DataValue $_ @('ImagePath', 'ServiceFileName', 'param2')) -match '(?i)\\temp\\|\\appdata\\|\\users\\public|powershell|cmd\.exe|%comspec%|\-enc|frombase64|\\programdata\\[^\\]+\.exe' })
        $sev = if ($suspicious.Count -gt 0) { 'High' } else { 'Low' }
        $findings.Add((New-Finding -Severity $sev -Category 'Security' -Title $(if ($suspicious.Count) { 'Suspicious new service installed' } else { 'New services installed' }) `
            -Detail ("$($newSvc.Count) new service(s): " + ($names -join '; ') + $(if ($suspicious.Count) { ". $($suspicious.Count) with suspicious image path(s) (temp folders, script interpreters, encoded commands)." } else { '.' })) `
            -Recommendation 'Confirm each service belongs to legitimate software. Services launching PowerShell/cmd or binaries from user/temp folders are a classic persistence technique.' -Events $newSvc))
    }
    $groupAdd = @(Get-ByIds 'Security-Auditing' @('4728', '4732', '4756'))
    $privAdd = @($groupAdd | Where-Object { (Get-DataValue $_ @('TargetUserName')) -match '(?i)admin|domain admins|enterprise admins|remote desktop|backup operators' })
    if ($privAdd.Count -gt 0) {
        $findings.Add((New-Finding -Severity 'High' -Category 'Security' -Title 'Members added to privileged groups' `
            -Detail ("$($privAdd.Count) additions to privileged groups: " + (@($privAdd | ForEach-Object { "$(Get-DataValue $_ @('MemberName','MemberSid')) -> $(Get-DataValue $_ @('TargetUserName')) by $(Get-DataValue $_ @('SubjectUserName'))" } | Select-Object -First 5) -join '; ')) `
            -Recommendation 'Verify each change was authorized through change management.' -Events $privAdd))
    }

    $defender = @(Get-ByIds 'Windows Defender' @('1116', '1117', '5001'))
    if ($defender.Count -gt 0) {
        $malware = @($defender | Where-Object { $_.EventId -eq '1116' })
        $disabled = @($defender | Where-Object { $_.EventId -eq '5001' })
        $sev = if ($malware.Count -gt 0 -or $disabled.Count -gt 0) { 'High' } else { 'Medium' }
        $threats = @($defender | ForEach-Object { Get-DataValue $_ @('Threat Name','ThreatName','param1') } | Where-Object { $_ } | Select-Object -Unique -First 5)
        $findings.Add((New-Finding -Severity $sev -Category 'Security' -Title $(if ($disabled.Count) { 'Defender real-time protection disabled' } else { 'Microsoft Defender detections' }) `
            -Detail ("$($defender.Count) Defender events ($($malware.Count) detections, $($disabled.Count) RTP-disabled)." + $(if ($threats.Count) { ' Threats: ' + ($threats -join ', ') + '.' } else { '' })) `
            -Recommendation 'Confirm remediation (event 1117). If real-time protection was disabled unexpectedly, treat as possible tampering and re-enable it.' -Events $defender))
    }

    # ---- Network / domain
    $net = Merge-EventLists (Get-ByIds 'NETLOGON' @('5719', '3210', '5783')) (Get-ByIds 'DNS Client' @('1014')) (Get-ByIds 'GroupPolicy' @('1129', '1053', '1055')) (Get-ByIds 'Time-Service' @('36', '129', '134'))
    if ($net.Count -gt 0) {
        $sev = if ($net.Count -ge 20) { 'High' } else { 'Medium' }
        $kinds = @($net | Group-Object { "$($_.Provider) $($_.EventId)" } | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) (x$($_.Count))" })
        $findings.Add((New-Finding -Severity $sev -Category 'Network' -Title 'Domain controller / DNS connectivity problems' `
            -Detail ("$($net.Count) events indicate the machine could not reach a domain controller, DNS or time source: " + ($kinds -join ', ') + '.') `
            -Recommendation 'Verify the NIC has link at boot, DNS points only to internal DCs, and the DCs are reachable (nltest /dsgetdc:<domain>). If these appear only at boot, enable "Always wait for the network at computer startup and logon" or update the NIC driver.' -Events $net))
    }

    # ---- Updates
    $wu = @(Get-ByIds 'WindowsUpdateClient' @('20', '25', '31'))
    if ($wu.Count -gt 0) {
        $codes = @($wu | ForEach-Object { Get-DataValue $_ @('errorCode') } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { $d = Get-CodeDescription $_.Name; "$($_.Name)$(if ($d) { " ($d)" }) x$($_.Count)" })
        $findings.Add((New-Finding -Severity 'Medium' -Category 'Updates' -Title 'Windows Update failures' -Detail ("$($wu.Count) update failures." + $(if ($codes.Count) { ' Codes: ' + ($codes -join ', ') + '.' } else { '' })) `
            -Recommendation 'Run DISM /Online /Cleanup-Image /RestoreHealth and sfc /scannow, ensure free disk space, then reset Windows Update components and retry.' -Events $wu))
    }

    # ---- Memory
    $oomCrashes = @(Get-ByIds 'Application Error' @('1000') | Where-Object { (Get-DataValue $_ @('ExceptionCode', 'param7')) -match '(?i)c0000017|8007000e' })
    $mem = Merge-EventLists (Get-ByIds 'Resource-Exhaustion' @('2004')) $oomCrashes
    if ($mem.Count -gt 0) {
        $procs = @($mem | ForEach-Object { if ($_.Message -match '(?i)([\w\-. ]+\.exe)\s*\(\d+\)\s*consumed\s*(\d+)') { $Matches[1] } } | Group-Object | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { $_.Name })
        $findings.Add((New-Finding -Severity 'High' -Category 'Performance' -Title 'Low memory / resource exhaustion' `
            -Detail ("$($mem.Count) low-memory events." + $(if ($procs.Count) { ' Top consumers: ' + ($procs -join ', ') + '.' } else { '' })) `
            -Recommendation 'The top consuming process is the likely cause (memory leak). Monitor with Performance Monitor (Private Bytes), update/restart the application, and size the page file appropriately.' -Events $mem))
    }

    $slowBoot = @(Get-ByIds 'Diagnostics-Performance' @('100', '200'))
    if ($slowBoot.Count -gt 0) {
        $findings.Add((New-Finding -Severity 'Low' -Category 'Performance' -Title 'Slow boot or shutdown measured' `
            -Detail "$($slowBoot.Count) Diagnostics-Performance boot/shutdown traces. Open the event for duration and the slowest driver/service." `
            -Recommendation 'Review startup apps, disk latency and third-party filter drivers. A slow boot plus storage errors usually means the disk is the root cause.' -Events $slowBoot))
    }

    # ---- Recurring unknown errors (not already covered)
    $covered = @{}
    foreach ($f in $findings) { foreach ($ix in $f.EventIndexes) { $covered[$ix] = $true } }
    $other = @($Events | Where-Object { $_.LevelRank -le 1 -and -not $covered.ContainsKey($_.Index) })
    $recurring = $other | Group-Object { "$($_.Provider)|$($_.EventId)" } | Where-Object { $_.Count -ge 3 } | Sort-Object Count -Descending | Select-Object -First 8
    foreach ($g in $recurring) {
        $s = $g.Group[0]
        $title = if ($s.KbTitle) { $s.KbTitle } else { "$($s.Provider) event $($s.EventId)" }
        $sev = if ($g.Count -ge 25) { 'High' } elseif ($g.Count -ge 10) { 'Medium' } else { 'Low' }
        $detail = "$($s.Provider) logged event $($s.EventId) $($g.Count) times. Sample: $($s.Summary)"
        $rec = if ($s.KbAdvice) { $s.KbAdvice } else { "Search for '$($s.Provider) event $($s.EventId)' in vendor documentation. Recurring identical errors usually share one root cause - fix the first occurrence and see if the rest stop." }
        $findings.Add((New-Finding -Severity $sev -Category $s.KbCategory -Title "Recurring error: $title" -Detail $detail -Recommendation $rec -Events @($g.Group)))
    }

    # ---- Bursts (event storms)
    $timed = @($Events | Where-Object { $_.Time -ne [datetime]::MinValue -and $_.LevelRank -le 3 })
    if ($timed.Count -ge 20) {
        $perMinute = $timed | Group-Object { $_.Time.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) }
        $avg = [double]$timed.Count / [math]::Max(1, @($perMinute).Count)
        $threshold = [math]::Max(15, $avg * 5)
        $storms = @($perMinute | Where-Object { $_.Count -ge $threshold } | Sort-Object Count -Descending | Select-Object -First 3)
        foreach ($st in $storms) {
            $top = @($st.Group | Group-Object { "$($_.Provider) $($_.EventId)" } | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name) (x$($_.Count))" })
            $findings.Add((New-Finding -Severity 'Medium' -Category 'Timeline' -Title "Error storm at $($st.Name)" `
                -Detail ("$($st.Count) warnings/errors within one minute (normal rate: {0:N1}/min). Dominant: $($top -join ', ')." -f $avg) `
                -Recommendation 'Something changed at this exact minute. Check the Incidents tab for the earliest event in this burst - that is usually the trigger.' -Events @($st.Group | Sort-Object Time)))
        }
    }

    if ($findings.Count -eq 0) {
        $errCount = @($Events | Where-Object { $_.LevelRank -le 1 }).Count
        $findings.Add((New-Finding -Severity 'Info' -Category 'Summary' -Title 'No significant problems detected' `
            -Detail "Analyzed $($Events.Count) events; $errCount errors/critical events did not match any known problem pattern or recur." `
            -Recommendation 'Review individual errors on the Events tab. Use the search box and level filters to narrow down.' -Events @()))
    }

    # ---- Incidents: cluster errors that are close in time
    $incidents = New-Object System.Collections.Generic.List[object]
    $errs = @($Events | Where-Object { $_.LevelRank -le 2 -and $_.Time -ne [datetime]::MinValue } | Sort-Object Time, Index)
    $cluster = New-Object System.Collections.Generic.List[object]
    $flush = {
        if ($cluster.Count -ge 2) {
            $evs = $cluster.ToArray()
            $trigger = $evs[0]
            $last = $evs[-1]
            $crit = @($evs | Where-Object { $_.LevelRank -eq 0 }).Count
            $chain = @($evs | Group-Object { "$($_.Provider) $($_.EventId)" } | ForEach-Object { $_.Group[0] } | Sort-Object Time | Select-Object -First 8)
            $dur = $last.Time - $trigger.Time
            $chainLines = foreach ($c in $chain) {
                $clock = if ($c.TimeText -and $c.TimeText.Length -ge 19) { $c.TimeText.Substring(11) } else { $c.TimeText }
                $kbBit = if ($c.KbTitle) { ' - ' + $c.KbTitle } else { '' }
                "$clock  $($c.Provider) $($c.EventId)$kbBit"
            }
            $incidents.Add([pscustomobject]@{
                Start        = $trigger.TimeText
                Duration     = $(if ($dur.TotalMinutes -ge 1) { '{0:N0} min' -f $dur.TotalMinutes } else { '{0:N0} sec' -f $dur.TotalSeconds })
                Count        = $evs.Count
                Severity     = $(if ($crit -gt 0) { 'Critical' } else { 'Error' })
                SeverityColor = $(if ($crit -gt 0) { '#F43F5E' } else { '#F97316' })
                Trigger      = "$($trigger.Provider) $($trigger.EventId)"
                TriggerText  = $(if ($trigger.KbTitle) { $trigger.KbTitle } else { $trigger.Summary })
                Chain        = ($chainLines -join "`n")
                Providers    = (@($evs | Select-Object -ExpandProperty Provider -Unique) -join ', ')
                EventIndexes = @($evs | ForEach-Object { $_.Index })
            })
        }
        $cluster.Clear()
    }
    foreach ($e in $errs) {
        if ($cluster.Count -gt 0 -and ($e.Time - $cluster[$cluster.Count - 1].Time).TotalMinutes -gt $WindowMinutes) { & $flush }
        $cluster.Add($e)
    }
    & $flush

    # ---- Stats
    $timedAll = @($Events | Where-Object { $_.Time -ne [datetime]::MinValue })
    $start = if ($timedAll.Count) { $timedAll[0].Time } else { $null }
    $end = if ($timedAll.Count) { $timedAll[-1].Time } else { $null }
    $levels = @{}
    foreach ($l in $script:LevelRank.Keys) { $levels[$l] = 0 }
    foreach ($e in $Events) {
        if ($levels.ContainsKey($e.Level)) { $levels[$e.Level]++ }
        else { $levels[$e.Level] = 1 }
    }

    $topProv = @($Events | Where-Object { $_.LevelRank -le 3 } | Group-Object Provider | Sort-Object Count -Descending | Select-Object -First 8)
    $maxProv = [math]::Max(1, ($topProv | Measure-Object Count -Maximum).Maximum)
    $topIds = @($Events | Where-Object { $_.LevelRank -le 3 } | Group-Object { "$($_.Provider)|$($_.EventId)" } | Sort-Object Count -Descending | Select-Object -First 8)
    $maxIds = [math]::Max(1, ($topIds | Measure-Object Count -Maximum).Maximum)

    $buckets = New-Object System.Collections.Generic.List[object]
    if ($start -and $end) {
        $span = ($end - $start).TotalSeconds
        $n = 24
        $size = [math]::Max(1, $span / $n)
        $counts = New-Object 'int[]' $n
        $errCounts = New-Object 'int[]' $n
        foreach ($e in $timedAll) {
            $b = [math]::Min($n - 1, [int][math]::Floor(($e.Time - $start).TotalSeconds / $size))
            $counts[$b]++
            if ($e.LevelRank -le 2) { $errCounts[$b]++ }
        }
        $max = [math]::Max(1, ($counts | Measure-Object -Maximum).Maximum)
        for ($b = 0; $b -lt $n; $b++) {
            $bs = $start.AddSeconds($b * $size)
            $be = $start.AddSeconds(($b + 1) * $size)
            $buckets.Add([pscustomobject]@{
                Label     = $bs.ToString('MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
                StartTime = $bs
                EndTime   = $be
                Total     = $counts[$b]
                Errors    = $errCounts[$b]
                Height    = [math]::Round(140.0 * $counts[$b] / $max, 1)
                ErrHeight = [math]::Round(140.0 * $errCounts[$b] / $max, 1)
                Tip       = "$($bs.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture))  -  $($counts[$b]) events, $($errCounts[$b]) errors (click to filter)"
            })
        }
    }

    $healthScore = 100
    $deduct = @{ Critical = 25; High = 12; Medium = 5; Low = 2; Info = 0 }
    foreach ($f in $findings) {
        $d = Get-HashValue $deduct $f.Severity 0
        $healthScore -= $d
    }
    $healthScore = [math]::Max(0, $healthScore)

    [pscustomobject]@{
        Findings    = @($findings | Sort-Object SeverityRank, @{ Expression = 'Count'; Descending = $true })
        Incidents   = @($incidents | Sort-Object @{ Expression = { if ($_.Severity -eq 'Critical') { 0 } else { 1 } } }, @{ Expression = 'Count'; Descending = $true })
        Total       = $Events.Count
        Levels      = $levels
        Start       = $start
        End         = $end
        Computers   = @($Events | Select-Object -ExpandProperty Computer -Unique | Where-Object { $_ })
        Channels    = @($Events | Select-Object -ExpandProperty Channel -Unique | Where-Object { $_ })
        Providers   = @($Events | Select-Object -ExpandProperty Provider -Unique | Sort-Object)
        TopProviders = @($topProv | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Count = $_.Count; Width = [math]::Round(260.0 * $_.Count / $maxProv, 1) } })
        TopEventIds = @($topIds | ForEach-Object { $p = $_.Name.Split('|'); $idPart = if ($p.Count -gt 1) { $p[1] } else { '' }; $provPart = $p[0]; $kb = Resolve-KnowledgeEntry $provPart $idPart; [pscustomobject]@{ Name = "$idPart  $provPart"; Hint = $(if ($kb) { $kb.Title } else { '' }); Count = $_.Count; Width = [math]::Round(260.0 * $_.Count / $maxIds, 1) } })
        Timeline    = $buckets.ToArray()
        HealthScore = $healthScore
    }
}

#endregion

#region ======================= Reporting =======================

function ConvertTo-HtmlSafe([string]$s) {
    if ($null -eq $s) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($s)
}

function Write-ReportFile {
    param([string]$OutFile, [string]$Content)
    $dir = [System.IO.Path]::GetDirectoryName($OutFile)
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($OutFile, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

function Export-AnalysisHtml {
    param([object[]]$Events, $Analysis, [string]$OutFile, [string]$SourceFile)
    $sb = New-Object System.Text.StringBuilder
    $range = if ($Analysis.Start) { "$($Analysis.Start.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)) to $($Analysis.End.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture))" } else { 'n/a' }
    $critN = Get-HashValue $Analysis.Levels 'Critical' 0
    $errN = Get-HashValue $Analysis.Levels 'Error' 0
    $warnN = Get-HashValue $Analysis.Levels 'Warning' 0
    $afN = Get-HashValue $Analysis.Levels 'Audit Failure' 0
    [void]$sb.Append(@"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Event Log Analysis</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0B1120;color:#E2E8F0;margin:0;padding:32px;line-height:1.5}
h1{margin:0 0 4px;font-size:26px}h2{margin:32px 0 12px;font-size:18px;color:#F8FAFC}
.muted{color:#94A3B8}.grid{display:flex;flex-wrap:wrap;gap:12px;margin-top:16px}
.kpi{background:#111827;border:1px solid #1F2937;border-radius:12px;padding:14px 18px;min-width:130px}
.kpi b{display:block;font-size:24px}.card{background:#111827;border:1px solid #1F2937;border-left:4px solid var(--c);border-radius:10px;padding:14px 18px;margin-bottom:10px}
.pill{display:inline-block;padding:1px 10px;border-radius:999px;font-size:12px;font-weight:600;background:var(--c);color:#0B1120;margin-right:8px}
.rec{background:#0F172A;border-radius:8px;padding:8px 12px;margin-top:8px;color:#CBD5E1}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #1F2937;vertical-align:top}
th{color:#94A3B8;font-weight:600}pre{white-space:pre-wrap;margin:0;font-family:Consolas,monospace;font-size:12px}
@media print{body{background:#fff;color:#111} .card,.kpi{border-color:#ddd;background:#fff}}
</style></head><body>
<h1>Event Log Analysis Report</h1>
<div class="muted">Source: $(ConvertTo-HtmlSafe $SourceFile)<br>Range: $range<br>Computers: $(ConvertTo-HtmlSafe ($Analysis.Computers -join ', '))<br>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $script:AppName $script:AppVersion</div>
<div class="grid">
<div class="kpi"><span class="muted">Health score</span><b>$($Analysis.HealthScore)/100</b></div>
<div class="kpi"><span class="muted">Total events</span><b>$($Analysis.Total)</b></div>
<div class="kpi"><span class="muted">Critical</span><b style="color:#F43F5E">$critN</b></div>
<div class="kpi"><span class="muted">Error</span><b style="color:#F97316">$errN</b></div>
<div class="kpi"><span class="muted">Warning</span><b style="color:#FACC15">$warnN</b></div>
<div class="kpi"><span class="muted">Audit failure</span><b style="color:#E879F9">$afN</b></div>
</div>
<h2>Root-cause findings</h2>
"@)
    foreach ($f in $Analysis.Findings) {
        [void]$sb.Append("<div class='card' style='--c:$($f.SeverityColor)'><span class='pill' style='--c:$($f.SeverityColor)'>$($f.Severity)</span><span class='muted'>$(ConvertTo-HtmlSafe $f.Category) - $($f.CountText) - $(ConvertTo-HtmlSafe $f.Window)</span><h3 style='margin:6px 0'>$(ConvertTo-HtmlSafe $f.Title)</h3><div>$(ConvertTo-HtmlSafe $f.Detail)</div><div class='rec'><b>Recommended action:</b> $(ConvertTo-HtmlSafe $f.Recommendation)</div></div>")
    }
    [void]$sb.Append('<h2>Incidents (correlated error clusters)</h2>')
    if (@($Analysis.Incidents).Count -eq 0) { [void]$sb.Append("<p class='muted'>No clusters of related errors were found.</p>") }
    else {
        [void]$sb.Append('<table><tr><th>Start</th><th>Duration</th><th>Events</th><th>Probable trigger</th><th>Chain of events</th></tr>')
        foreach ($i in $Analysis.Incidents) {
            [void]$sb.Append("<tr><td>$($i.Start)</td><td>$($i.Duration)</td><td>$($i.Count)</td><td><b>$(ConvertTo-HtmlSafe $i.Trigger)</b><br><span class='muted'>$(ConvertTo-HtmlSafe $i.TriggerText)</span></td><td><pre>$(ConvertTo-HtmlSafe $i.Chain)</pre></td></tr>")
        }
        [void]$sb.Append('</table>')
    }
    [void]$sb.Append('<h2>Errors and warnings</h2><table><tr><th>Time</th><th>Level</th><th>Source</th><th>ID</th><th>Meaning</th><th>Message</th></tr>')
    foreach ($e in ($Events | Where-Object { $_.LevelRank -le 3 } | Select-Object -First 2000)) {
        [void]$sb.Append("<tr><td>$($e.TimeText)</td><td style='color:$($e.LevelColor)'>$($e.Level)</td><td>$(ConvertTo-HtmlSafe $e.Provider)</td><td>$($e.EventId)</td><td>$(ConvertTo-HtmlSafe $e.KbTitle)</td><td>$(ConvertTo-HtmlSafe $e.Summary)</td></tr>")
    }
    [void]$sb.Append('</table></body></html>')
    Write-ReportFile -OutFile $OutFile -Content $sb.ToString()
}

function Export-AnalysisJson {
    param([object[]]$Events, $Analysis, [string]$OutFile, [string]$SourceFile)
    $payload = [pscustomobject]@{
        Tool        = $script:AppName
        Version     = $script:AppVersion
        Source      = $SourceFile
        Generated   = (Get-Date).ToString('o')
        HealthScore = $Analysis.HealthScore
        Total       = $Analysis.Total
        Range       = @{ Start = $Analysis.Start; End = $Analysis.End }
        Computers   = @($Analysis.Computers)
        Channels    = @($Analysis.Channels)
        Levels      = $Analysis.Levels
        Findings    = @($Analysis.Findings | Select-Object Severity, Category, Title, Detail, Recommendation, Count, Window, EventIndexes)
        Incidents   = @($Analysis.Incidents | Select-Object Start, Duration, Count, Severity, Trigger, TriggerText, Chain, Providers, EventIndexes)
        TopProviders = $Analysis.TopProviders
        TopEventIds  = $Analysis.TopEventIds
    }
    $json = $payload | ConvertTo-Json -Depth 8
    Write-ReportFile -OutFile $OutFile -Content $json
}

function Export-EventsCsv {
    param([object[]]$Events, [string]$OutFile)
    $Events | Select-Object TimeText, Level, Provider, EventId, Task, Computer, Channel, RecordId, KbTitle, KbCategory, Message |
        Export-Csv -LiteralPath $OutFile -NoTypeInformation -Encoding UTF8
}

function Export-AnalysisReport {
    param([object[]]$Events, $Analysis, [string]$OutFile, [string]$SourceFile)
    $ext = [System.IO.Path]::GetExtension($OutFile).ToLowerInvariant()
    switch ($ext) {
        '.json' { Export-AnalysisJson -Events $Events -Analysis $Analysis -OutFile $OutFile -SourceFile $SourceFile }
        '.csv'  { Export-EventsCsv -Events $Events -OutFile $OutFile }
        default { Export-AnalysisHtml -Events $Events -Analysis $Analysis -OutFile $OutFile -SourceFile $SourceFile }
    }
}

#endregion

#region ======================= Sample fixtures & self-test =======================

function New-SampleEventXmlNode {
    param(
        [string]$Provider, [string]$EventId, [int]$Level = 2, [datetime]$Utc,
        [string]$Channel = 'System', [string]$Computer = 'TEST-PC',
        [hashtable]$Data, [string]$Message, [string]$Keywords = ''
    )
    $t = $Utc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.0000000Z')
    $kw = if ($Keywords) { "<Keywords>$Keywords</Keywords>" } else { '<Keywords>0x80000000000000</Keywords>' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="$Provider"/>
    <EventID>$EventId</EventID>
    <Level>$Level</Level>
    <Task>0</Task>
    $kw
    <TimeCreated SystemTime="$t"/>
    <EventRecordID>$([math]::Abs($Utc.Ticks % 100000))</EventRecordID>
    <Channel>$Channel</Channel>
    <Computer>$Computer</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
"@)
    if ($Data) {
        foreach ($k in $Data.Keys) {
            $val = [System.Security.SecurityElement]::Escape([string]$Data[$k])
            [void]$sb.Append("    <Data Name=`"$k`">$val</Data>`n")
        }
    }
    [void]$sb.Append("  </EventData>`n")
    if ($Message) {
        $m = [System.Security.SecurityElement]::Escape($Message)
        [void]$sb.Append("  <RenderingInfo Culture=`"en-US`"><Message>$m</Message></RenderingInfo>`n")
    }
    [void]$sb.Append("</Event>`n")
    return $sb.ToString()
}

function New-SampleEventLogXml {
    param([switch]$AsFragment, [switch]$WithInvalidChar)
    $base = [datetime]'2024-06-15T14:00:00Z'
    $nodes = New-Object System.Collections.Generic.List[string]
    $nodes.Add((New-SampleEventXmlNode -Provider 'disk' -EventId '7' -Level 2 -Utc $base.AddSeconds(1) -Data @{ DeviceName = '\Device\Harddisk0\DR0' } -Message 'The device, \Device\Harddisk0\DR0, has a bad block.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-Ntfs' -EventId '55' -Level 2 -Utc $base.AddSeconds(5) -Data @{ DriveName = 'C:' } -Message 'The file system structure on the disk is corrupt and unusable.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Application Error' -EventId '1000' -Level 2 -Utc $base.AddSeconds(20) -Channel 'Application' -Data @{
        AppName = 'sqlservr.exe'; ModuleName = 'ntdll.dll'; ExceptionCode = 'c0000005'; param1 = 'sqlservr.exe'; param4 = 'ntdll.dll'; param7 = 'c0000005'
    } -Message 'Faulting application name: sqlservr.exe, Faulting module name: ntdll.dll, Exception code: 0xc0000005'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Service Control Manager' -EventId '7034' -Level 2 -Utc $base.AddSeconds(21) -Data @{ param1 = 'SQL Server (MSSQLSERVER)' } -Message 'The SQL Server (MSSQLSERVER) service terminated unexpectedly.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-Kernel-Power' -EventId '41' -Level 1 -Utc $base.AddMinutes(2) -Data @{ BugcheckCode = '10'; BugcheckParameter1 = '0'; PowerButtonTimestamp = '0' } -Message 'The system has rebooted without cleanly shutting down first.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'EventLog' -EventId '6008' -Level 2 -Utc $base.AddMinutes(2).AddSeconds(5) -Message 'The previous system shutdown at 2:00:00 PM on 6/15/2024 was unexpected.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-WER-SystemErrorReporting' -EventId '1001' -Level 2 -Utc $base.AddMinutes(2).AddSeconds(8) -Data @{ param1 = '0x0000000a' } -Message 'The computer has rebooted from a bugcheck. The bugcheck was: 0x0000000a'))
    # Provider fragment 'BugCheck' is used by the findings engine
    $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-BugCheck' -EventId '1001' -Level 2 -Utc $base.AddMinutes(2).AddSeconds(9) -Data @{ BugcheckCode = '0x0000000a' } -Message 'The computer has rebooted from a bugcheck. The bugcheck was: 0x0000000a (IRQL_NOT_LESS_OR_EQUAL).'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'EventLog' -EventId '6005' -Level 4 -Utc $base.AddMinutes(2).AddSeconds(15) -Message 'The Event log service was started.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-WHEA-Logger' -EventId '18' -Level 1 -Utc $base.AddMinutes(1) -Message 'A fatal hardware error has occurred. Component: Processor.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'User32' -EventId '1074' -Level 4 -Utc $base.AddMinutes(-10) -Data @{ param1 = 'C:\Windows\System32\shutdown.exe'; param7 = 'TEST\admin' } -Message 'The process shutdown.exe has initiated the restart of computer TEST-PC.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Service Control Manager' -EventId '7000' -Level 2 -Utc $base.AddMinutes(3) -Data @{ param1 = 'Spooler'; param2 = '1053' } -Message 'The Print Spooler service failed to start due to the following error: The service did not respond to the start or control request in a timely fashion.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Service Control Manager' -EventId '7045' -Level 4 -Utc $base.AddMinutes(4) -Channel 'System' -Data @{ ServiceName = 'UpdHelper'; ImagePath = 'C:\Users\Public\upd.exe'; param1 = 'UpdHelper'; param2 = 'C:\Users\Public\upd.exe' } -Message 'A service was installed in the system.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-Windows Defender' -EventId '1116' -Level 3 -Utc $base.AddMinutes(5) -Channel 'Microsoft-Windows-Windows Defender/Operational' -Data @{ 'Threat Name' = 'Trojan:Win32/Test' } -Message 'Microsoft Defender Antivirus has detected malware or other potentially unwanted software.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-Resource-Exhaustion-Detector' -EventId '2004' -Level 3 -Utc $base.AddMinutes(6) -Message 'Windows successfully diagnosed a low virtual memory condition. sqlservr.exe (1234) consumed 8000 MB.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-WindowsUpdateClient' -EventId '20' -Level 2 -Utc $base.AddMinutes(7) -Data @{ errorCode = '0x80070070' } -Message 'Installation Failure: Windows failed to install the following update with error 0x80070070.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-Security-Auditing' -EventId '1102' -Level 4 -Utc $base.AddMinutes(8) -Channel 'Security' -Keywords '0x8010000000000000' -Data @{ SubjectUserName = 'badactor' } -Message 'The audit log was cleared.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-Security-Auditing' -EventId '4732' -Level 4 -Utc $base.AddMinutes(8).AddSeconds(10) -Channel 'Security' -Keywords '0x8020000000000000' -Data @{ MemberName = 'TEST\evil'; TargetUserName = 'Administrators'; SubjectUserName = 'badactor' } -Message 'A member was added to a security-enabled local group.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'NETLOGON' -EventId '5719' -Level 2 -Utc $base.AddMinutes(9) -Message 'This computer was not able to set up a secure session with a domain controller.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-DNS-Client' -EventId '1014' -Level 3 -Utc $base.AddMinutes(9).AddSeconds(2) -Message 'Name resolution for the name contoso.com timed out after none of the configured DNS servers responded.'))
    $nodes.Add((New-SampleEventXmlNode -Provider 'Application Hang' -EventId '1002' -Level 2 -Utc $base.AddSeconds(22) -Channel 'Application' -Data @{ param1 = 'outlook.exe'; AppName = 'outlook.exe' } -Message 'The program outlook.exe stopped interacting with Windows and was closed.'))
    $nodes.Add((New-SampleEventXmlNode -Provider '.NET Runtime' -EventId '1026' -Level 2 -Utc $base.AddSeconds(24) -Channel 'Application' -Message "Application: MyApp.exe`nException Info: System.NullReferenceException`nStack: at MyApp.Program.Main"))
    $i = 0
    foreach ($user in @('alice','bob','carol','dave','erin','frank')) {
        $i++
        $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-Security-Auditing' -EventId '4625' -Level 4 -Utc $base.AddMinutes(10).AddSeconds($i) -Channel 'Security' -Keywords '0x8010000000000000' -Data @{
            TargetUserName = $user; IpAddress = '203.0.113.50'; Status = '0xC000006D'; SubStatus = '0xC0000064'; LogonType = '3'
        } -Message "An account failed to log on. Account Name: $user Status: 0xC000006D"))
    }
    $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-Security-Auditing' -EventId '4740' -Level 4 -Utc $base.AddMinutes(11) -Channel 'Security' -Keywords '0x8010000000000000' -Data @{ TargetUserName = 'alice'; CallerComputerName = 'EVIL-PC' } -Message 'A user account was locked out.'))
    for ($b = 0; $b -lt 18; $b++) {
        $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-DistributedCOM' -EventId '10016' -Level 3 -Utc $base.AddMinutes(30).AddSeconds($b) -Message 'The application-specific permission settings do not grant Local Activation permission.'))
    }
    $nodes.Add((New-SampleEventXmlNode -Provider 'Microsoft-Windows-Winlogon' -EventId '4005' -Level 2 -Utc $base.AddMinutes(31) -Message 'The Windows logon process has unexpectedly terminated.'))
    if ($WithInvalidChar) {
        $bell = [char]7
        $soh = [char]1
        $badName = 'bad' + $bell + 'app.exe'
        $badMsg = 'Faulting application bad' + $soh + 'app.exe'
        $bad = New-SampleEventXmlNode -Provider 'Application Error' -EventId '1000' -Level 2 -Utc $base.AddMinutes(12) -Channel 'Application' -Data @{ AppName = $badName; ModuleName = 'foo.dll'; ExceptionCode = 'c0000005' } -Message $badMsg
        $nodes.Add($bad)
    }
    $body = $nodes -join "`n"
    if ($AsFragment) { return $body }
    return @"
<?xml version="1.0" encoding="utf-8"?>
<Events>
$body
</Events>
"@
}

function Invoke-AnalyzerSelfTest {
    $failed = New-Object System.Collections.Generic.List[string]
    function Assert-True($Cond, [string]$Name) {
        if ($Cond) { Write-Host "  PASS  $Name" -ForegroundColor Green }
        else { Write-Host "  FAIL  $Name" -ForegroundColor Red; $failed.Add($Name) }
    }

    Write-Host "`n$script:AppName $script:AppVersion self-test" -ForegroundColor Cyan
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("ela-selftest-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    try {
        $xmlPath = Join-Path $dir 'sample.xml'
        $fragPath = Join-Path $dir 'fragment.xml'
        $utf16Path = Join-Path $dir 'utf16.xml'
        $badPath = Join-Path $dir 'invalid-char.xml'
        $htmlPath = Join-Path $dir 'report.html'
        $jsonPath = Join-Path $dir 'report.json'

        [System.IO.File]::WriteAllText($xmlPath, (New-SampleEventLogXml), (New-Object System.Text.UTF8Encoding $false))
        [System.IO.File]::WriteAllText($fragPath, (New-SampleEventLogXml -AsFragment), (New-Object System.Text.UTF8Encoding $false))
        [System.IO.File]::WriteAllText($utf16Path, (New-SampleEventLogXml), [System.Text.Encoding]::Unicode)
        [System.IO.File]::WriteAllText($badPath, (New-SampleEventLogXml -WithInvalidChar), (New-Object System.Text.UTF8Encoding $false))

        $events = Import-EventLogXml -FilePath $xmlPath
        Assert-True ($events.Count -ge 30) "Parses sample XML ($($events.Count) events)"
        $kp = @($events | Where-Object { $_.EventId -eq '41' -and $_.Provider -like '*Kernel-Power*' })
        Assert-True ($kp.Count -eq 1) 'Kernel-Power 41 present'
        Assert-True ($kp[0].Level -eq 'Critical') 'Kernel-Power 41 is Critical'
        $decoded = @($kp[0].Decoded | Where-Object { $_.Name -eq 'BugcheckCode' -and $_.Meaning -match 'IRQL' })
        Assert-True ($decoded.Count -gt 0) 'BugcheckCode 10 decoded as IRQL_NOT_LESS_OR_EQUAL'
        $audit = @($events | Where-Object { $_.EventId -eq '4625' })
        Assert-True ($audit[0].Level -eq 'Audit Failure') 'Keywords map 4625 to Audit Failure'
        $desc = Get-CodeDescription -Value '0xC0000064' -FieldName 'SubStatus'
        Assert-True ($desc -match 'does not exist') 'NTSTATUS 0xC0000064 decoded'
        $desc2 = Get-CodeDescription -Value '%%1053' -FieldName 'param2'
        Assert-True ($desc2 -match 'did not respond') '%%1053 insertion string decoded as Win32 1053'
        $desc3 = Get-CodeDescription -Value '2147500037' -FieldName 'errorCode'
        Assert-True ($desc3 -match 'E_FAIL') 'Decimal HRESULT 2147500037 decoded'

        try {
            $analysis = Invoke-EventAnalysis -Events $events -WindowMinutes $CorrelationMinutes
        }
        catch {
            Write-Host "  FAIL  Invoke-EventAnalysis: $($_.Exception.GetType().FullName): $($_.Exception.Message)" -ForegroundColor Red
            Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
            if ($_.Exception.InnerException) { Write-Host $_.Exception.InnerException.ToString() -ForegroundColor DarkRed }
            $failed.Add("Invoke-EventAnalysis")
            throw
        }
        $titles = @($analysis.Findings | ForEach-Object { $_.Title })
        Assert-True ($analysis.HealthScore -lt 80) "Health score reflects problems ($($analysis.HealthScore))"
        Assert-True ($titles -match 'Unexpected reboot') 'Finding: unexpected reboots'
        Assert-True ($titles -match 'Disk / storage') 'Finding: storage errors'
        Assert-True ($titles -match 'sqlservr') 'Finding: application crash'
        Assert-True ($titles -match 'password spraying|Failed logon') 'Finding: failed logons'
        Assert-True ($titles -match 'Event logs were cleared') 'Finding: log cleared'
        Assert-True ($titles -match 'Suspicious new service') 'Finding: suspicious service'
        Assert-True ($titles -match 'WHEA') 'Finding: WHEA hardware'
        Assert-True ($titles -match 'Defender') 'Finding: Defender'
        Assert-True ($titles -match 'privileged groups') 'Finding: privileged group add'
        Assert-True (@($analysis.Incidents).Count -ge 1) "Incidents clustered ($((@($analysis.Incidents)).Count))"

        $frag = Import-EventLogXml -FilePath $fragPath
        Assert-True ($frag.Count -eq $events.Count) "wevtutil fragment (no root) parses ($($frag.Count))"
        $u16 = Import-EventLogXml -FilePath $utf16Path
        Assert-True ($u16.Count -eq $events.Count) "UTF-16 XML parses ($($u16.Count))"
        $bad = Import-EventLogXml -FilePath $badPath
        Assert-True ($bad.Count -ge $events.Count) "Invalid XML chars do not abort parse ($($bad.Count))"

        $merged = Import-EventLogXml -FilePath @($xmlPath, $fragPath)
        Assert-True ($merged.Count -eq ($events.Count * 2)) "Multiple files merge ($($merged.Count))"

        Export-AnalysisReport -Events $events -Analysis $analysis -OutFile $htmlPath -SourceFile $xmlPath
        Export-AnalysisReport -Events $events -Analysis $analysis -OutFile $jsonPath -SourceFile $xmlPath
        $html = [System.IO.File]::ReadAllText($htmlPath)
        $json = [System.IO.File]::ReadAllText($jsonPath)
        Assert-True ($html -match 'Root-cause findings' -and $html -match 'Unexpected') 'HTML report written'
        Assert-True ($html -notmatch '<script>alert') 'HTML encodes content'
        Assert-True ($json -match '"HealthScore"' -and $json -match 'Findings') 'JSON report written'

        $emptyPath = Join-Path $dir 'empty.xml'
        [System.IO.File]::WriteAllText($emptyPath, '<root><hello/></root>')
        $threw = $false
        try { [void](Import-EventLogXml -FilePath $emptyPath) } catch { $threw = $true }
        Assert-True $threw 'Empty/non-event XML throws a clear error'
    }
    finally {
        try { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }

    if ($failed.Count -gt 0) {
        Write-Host "`nSelf-test FAILED: $($failed.Count) assertion(s)" -ForegroundColor Red
        foreach ($f in $failed) { Write-Host "   - $f" -ForegroundColor Red }
        exit 1
    }
    Write-Host "`nSelf-test PASSED" -ForegroundColor Green
    exit 0
}

#endregion

#region ======================= Headless mode =======================

function Write-HeadlessAnalysis {
    param([object[]]$Events, $Analysis, [string]$Source)
    Write-Host ''
    Write-Host ("{0} events  |  Critical {1}  Error {2}  Warning {3}  AuditFail {4}  |  Health {5}/100" -f `
        $Analysis.Total, (Get-HashValue $Analysis.Levels 'Critical' 0), (Get-HashValue $Analysis.Levels 'Error' 0),
        (Get-HashValue $Analysis.Levels 'Warning' 0), (Get-HashValue $Analysis.Levels 'Audit Failure' 0), $Analysis.HealthScore) -ForegroundColor White
    Write-Host "Source: $Source" -ForegroundColor DarkGray
    Write-Host ''
    $sevColor = @{ Critical = 'Red'; High = 'DarkYellow'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }
    foreach ($f in $Analysis.Findings) {
        $col = Get-HashValue $sevColor $f.Severity 'White'
        Write-Host ("[{0}] {1}  ({2})" -f $f.Severity.ToUpper(), $f.Title, $f.CountText) -ForegroundColor $col
        Write-Host "    $($f.Detail)"
        Write-Host "    -> $($f.Recommendation)" -ForegroundColor DarkGray
        Write-Host ''
    }
    if (@($Analysis.Incidents).Count -gt 0) {
        Write-Host 'Incidents (probable trigger first):' -ForegroundColor White
        foreach ($inc in ($Analysis.Incidents | Select-Object -First 10)) {
            Write-Host ("  {0}  {1} events over {2}  trigger: {3}" -f $inc.Start, $inc.Count, $inc.Duration, $inc.Trigger)
        }
    }
}

if ($SelfTest) {
    Invoke-AnalyzerSelfTest
}

if ($NoGui -or ($ReportPath -and $Path)) {
    if (-not $Path) { throw 'Specify -Path when using -NoGui.' }
    Write-Host "Parsing $($Path -join ', ') ..." -ForegroundColor Cyan
    $events = Import-EventLogXml -FilePath $Path -OnProgress {
        param($i, $t)
        $pct = if ($t -gt 0) { [int](100 * $i / $t) } else { 0 }
        Write-Progress -Activity 'Parsing events' -Status "$i / $t" -PercentComplete $pct
    }
    Write-Progress -Activity 'Parsing events' -Completed
    $analysis = Invoke-EventAnalysis -Events $events -WindowMinutes $CorrelationMinutes
    Write-HeadlessAnalysis -Events $events -Analysis $analysis -Source ($Path -join ', ')
    if ($ReportPath) {
        Export-AnalysisReport -Events $events -Analysis $analysis -OutFile $ReportPath -SourceFile ($Path -join ', ')
        Write-Host "`nReport written to $ReportPath" -ForegroundColor Green
    }
    return
}

#endregion

#region ======================= GUI definition (XAML) =======================

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml
Add-Type -AssemblyName System.Windows.Forms

[xml]$script:Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="MainWindow" Title="Event Log XML Analyzer" Width="1440" Height="900" MinWidth="1100" MinHeight="680"
        WindowStartupLocation="CenterScreen" Background="#0B1120" Foreground="#E2E8F0"
        FontFamily="Segoe UI" FontSize="13" AllowDrop="True" UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <Window.Resources>
    <SolidColorBrush x:Key="BgBrush" Color="#0B1120"/>
    <SolidColorBrush x:Key="SurfaceBrush" Color="#111827"/>
    <SolidColorBrush x:Key="Surface2Brush" Color="#0F172A"/>
    <SolidColorBrush x:Key="BorderBrush" Color="#1F2937"/>
    <SolidColorBrush x:Key="TextBrush" Color="#E2E8F0"/>
    <SolidColorBrush x:Key="MutedBrush" Color="#94A3B8"/>
    <SolidColorBrush x:Key="AccentBrush" Color="#38BDF8"/>

    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="#111827"/>
      <Setter Property="BorderBrush" Value="#1F2937"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="12"/>
      <Setter Property="Padding" Value="18"/>
    </Style>
    <Style x:Key="Muted" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#94A3B8"/>
      <Setter Property="FontSize" Value="12"/>
    </Style>
    <Style x:Key="SectionTitle" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#F8FAFC"/>
      <Setter Property="FontSize" Value="15"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Margin" Value="0,0,0,12"/>
    </Style>
    <Style x:Key="Label" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#64748B"/>
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Margin" Value="0,12,0,4"/>
    </Style>

    <Style TargetType="Button">
      <Setter Property="Foreground" Value="#E2E8F0"/>
      <Setter Property="Background" Value="#1E293B"/>
      <Setter Property="BorderBrush" Value="#334155"/>
      <Setter Property="Padding" Value="14,7"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="1" CornerRadius="8" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="#38BDF8"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Bd" Property="Opacity" Value="0.8"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Bd" Property="Opacity" Value="0.4"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="PrimaryButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#38BDF8"/>
      <Setter Property="BorderBrush" Value="#38BDF8"/>
      <Setter Property="Foreground" Value="#0B1120"/>
    </Style>
    <Style x:Key="LinkButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderBrush" Value="#334155"/>
      <Setter Property="Padding" Value="10,4"/>
      <Setter Property="FontSize" Value="12"/>
    </Style>

    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#0F172A"/>
      <Setter Property="Foreground" Value="#E2E8F0"/>
      <Setter Property="BorderBrush" Value="#1F2937"/>
      <Setter Property="CaretBrush" Value="#38BDF8"/>
      <Setter Property="SelectionBrush" Value="#38BDF8"/>
      <Setter Property="Padding" Value="10,7"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="8">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsKeyboardFocused" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="#38BDF8"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Chip" TargetType="CheckBox">
      <Setter Property="Foreground" Value="#CBD5E1"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Margin" Value="0,0,6,0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <Border x:Name="Bd" Background="#0F172A" BorderBrush="#1F2937" BorderThickness="1" CornerRadius="14" Padding="10,5">
              <StackPanel Orientation="Horizontal">
                <Ellipse x:Name="Dot" Width="8" Height="8" Margin="0,0,7,0" VerticalAlignment="Center"
                         Fill="{Binding Tag, RelativeSource={RelativeSource TemplatedParent}}"/>
                <ContentPresenter VerticalAlignment="Center"/>
              </StackPanel>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#1E293B"/>
                <Setter TargetName="Bd" Property="BorderBrush" Value="#475569"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="False">
                <Setter TargetName="Dot" Property="Opacity" Value="0.25"/>
                <Setter Property="Foreground" Value="#64748B"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="#38BDF8"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="ComboBox">
      <Setter Property="Foreground" Value="#E2E8F0"/>
      <Setter Property="Height" Value="34"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBox">
            <Grid>
              <ToggleButton Focusable="False" ClickMode="Press"
                            IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}">
                <ToggleButton.Template>
                  <ControlTemplate TargetType="ToggleButton">
                    <Border x:Name="Bd" Background="#0F172A" BorderBrush="#1F2937" BorderThickness="1" CornerRadius="8">
                      <Path HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,12,0"
                            Data="M0,0 L4,4 L8,0" Stroke="#94A3B8" StrokeThickness="1.5"/>
                    </Border>
                    <ControlTemplate.Triggers>
                      <Trigger Property="IsMouseOver" Value="True">
                        <Setter TargetName="Bd" Property="BorderBrush" Value="#38BDF8"/>
                      </Trigger>
                    </ControlTemplate.Triggers>
                  </ControlTemplate>
                </ToggleButton.Template>
              </ToggleButton>
              <ContentPresenter IsHitTestVisible="False" Margin="12,0,30,0" VerticalAlignment="Center"
                                Content="{TemplateBinding SelectionBoxItem}"
                                ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                                TextElement.Foreground="#E2E8F0"/>
              <Popup IsOpen="{TemplateBinding IsDropDownOpen}" Placement="Bottom" AllowsTransparency="True" Focusable="False" PopupAnimation="Fade">
                <Border Background="#111827" BorderBrush="#334155" BorderThickness="1" CornerRadius="8" Margin="0,4,0,0" MaxHeight="380"
                        MinWidth="{Binding ActualWidth, RelativeSource={RelativeSource TemplatedParent}}">
                  <ScrollViewer Margin="4"><ItemsPresenter/></ScrollViewer>
                </Border>
              </Popup>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ComboBoxItem">
      <Setter Property="Foreground" Value="#E2E8F0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBoxItem">
            <Border x:Name="Bd" Padding="10,6" CornerRadius="6" Background="Transparent">
              <ContentPresenter/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsHighlighted" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#1E293B"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="ProgressBar">
      <Setter Property="Height" Value="6"/>
      <Setter Property="Foreground" Value="#38BDF8"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ProgressBar">
            <Grid>
              <Border x:Name="PART_Track" Background="#1E293B" CornerRadius="3"/>
              <Border x:Name="PART_Indicator" Background="{TemplateBinding Foreground}" CornerRadius="3" HorizontalAlignment="Left"/>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="TabControl">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabControl">
            <Grid>
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>
              <Border BorderBrush="#1F2937" BorderThickness="0,0,0,1" Padding="20,0">
                <TabPanel IsItemsHost="True"/>
              </Border>
              <ContentPresenter Grid.Row="1" ContentSource="SelectedContent"/>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="TabItem">
      <Setter Property="Foreground" Value="#94A3B8"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="Bd" BorderThickness="0,0,0,2" BorderBrush="Transparent" Padding="14,12" Margin="0,0,4,-1" Background="Transparent">
              <ContentPresenter ContentSource="Header" TextElement.FontWeight="SemiBold"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="#38BDF8"/>
                <Setter Property="Foreground" Value="#F8FAFC"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter Property="Foreground" Value="#F8FAFC"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#111827"/>
      <Setter Property="Foreground" Value="#94A3B8"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Padding" Value="10,9"/>
      <Setter Property="BorderBrush" Value="#1F2937"/>
      <Setter Property="BorderThickness" Value="0,0,0,1"/>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Padding="10,0" Background="Transparent">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="DataGridRow">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="#E2E8F0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="#162033"/>
        </Trigger>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="#1E3A5F"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style TargetType="ListBoxItem">
      <Setter Property="Foreground" Value="#E2E8F0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ListBoxItem">
            <Border x:Name="Bd" Padding="8,6" CornerRadius="6" Background="Transparent" Margin="0,1">
              <ContentPresenter/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#1E293B"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#1E3A5F"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <DataTemplate x:Key="BarRow">
      <Grid Margin="0,0,0,10">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel>
          <TextBlock Text="{Binding Name}" TextTrimming="CharacterEllipsis" Foreground="#E2E8F0"/>
          <Border Height="6" CornerRadius="3" Background="#38BDF8" HorizontalAlignment="Left" Margin="0,5,0,0" Width="{Binding Width}"/>
        </StackPanel>
        <TextBlock Grid.Column="1" Text="{Binding Count}" Foreground="#94A3B8" Margin="12,0,0,0" VerticalAlignment="Top" FontWeight="SemiBold"/>
      </Grid>
    </DataTemplate>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <Border Grid.Row="0" Background="#0B1120" BorderBrush="#1F2937" BorderThickness="0,0,0,1" Padding="20,14">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Border Width="38" Height="38" CornerRadius="10" Background="#0C4A6E" VerticalAlignment="Center">
          <TextBlock Text="&#xE9D9;" FontFamily="Segoe MDL2 Assets" FontSize="18" Foreground="#38BDF8" HorizontalAlignment="Center" VerticalAlignment="Center"/>
        </Border>
        <StackPanel Grid.Column="1" Margin="14,0,0,0" VerticalAlignment="Center">
          <TextBlock Text="Event Log XML Analyzer" FontSize="17" FontWeight="SemiBold" Foreground="#F8FAFC"/>
          <TextBlock x:Name="TxtFileName" Text="No file loaded - open or drop an .xml / .evtx export to begin" Style="{StaticResource Muted}" TextTrimming="CharacterEllipsis"/>
        </StackPanel>
        <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
          <Button x:Name="BtnLive" Margin="0,0,8,0" ToolTip="Capture events from this computer">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="&#xE7F4;" FontFamily="Segoe MDL2 Assets" Margin="0,0,8,0" VerticalAlignment="Center"/>
              <TextBlock Text="Capture local log"/>
            </StackPanel>
          </Button>
          <Button x:Name="BtnExportCsv" Margin="0,0,8,0" IsEnabled="False">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="&#xE9F9;" FontFamily="Segoe MDL2 Assets" Margin="0,0,8,0" VerticalAlignment="Center"/>
              <TextBlock Text="Export CSV"/>
            </StackPanel>
          </Button>
          <Button x:Name="BtnExportJson" Margin="0,0,8,0" IsEnabled="False">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="&#xE943;" FontFamily="Segoe MDL2 Assets" Margin="0,0,8,0" VerticalAlignment="Center"/>
              <TextBlock Text="Export JSON"/>
            </StackPanel>
          </Button>
          <Button x:Name="BtnExportHtml" Margin="0,0,8,0" IsEnabled="False">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="&#xE8A5;" FontFamily="Segoe MDL2 Assets" Margin="0,0,8,0" VerticalAlignment="Center"/>
              <TextBlock Text="HTML report"/>
            </StackPanel>
          </Button>
          <Button x:Name="BtnOpen" Style="{StaticResource PrimaryButton}" ToolTip="Open one or more .xml / .evtx files (Ctrl+O)">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="&#xE8E5;" FontFamily="Segoe MDL2 Assets" Margin="0,0,8,0" VerticalAlignment="Center"/>
              <TextBlock Text="Open log"/>
            </StackPanel>
          </Button>
        </StackPanel>
      </Grid>
    </Border>

    <TabControl x:Name="MainTabs" Grid.Row="1" Background="Transparent" BorderThickness="0" Visibility="Collapsed">
      <TabItem x:Name="TabDashboard" Header="Dashboard">
        <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="20">
          <StackPanel>
            <UniformGrid Rows="1" Columns="6">
              <Border x:Name="CardHealth" Style="{StaticResource Card}" Margin="0,0,10,0" Cursor="Hand" ToolTip="Open root-cause analysis">
                <StackPanel>
                  <TextBlock Text="HEALTH SCORE" Style="{StaticResource Label}" Margin="0,0,0,6"/>
                  <StackPanel Orientation="Horizontal">
                    <TextBlock x:Name="KpiHealth" Text="-" FontSize="30" FontWeight="Bold" Foreground="#F8FAFC"/>
                    <TextBlock Text=" / 100" Style="{StaticResource Muted}" VerticalAlignment="Bottom" Margin="2,0,0,7"/>
                  </StackPanel>
                  <ProgressBar x:Name="KpiHealthBar" Minimum="0" Maximum="100" Value="0" Margin="0,8,0,6"/>
                  <TextBlock x:Name="KpiHealthLabel" Text="" Style="{StaticResource Muted}"/>
                </StackPanel>
              </Border>
              <Border x:Name="CardTotal" Style="{StaticResource Card}" Margin="0,0,10,0" Cursor="Hand" ToolTip="Show all events">
                <StackPanel>
                  <TextBlock Text="TOTAL EVENTS" Style="{StaticResource Label}" Margin="0,0,0,6"/>
                  <TextBlock x:Name="KpiTotal" Text="-" FontSize="30" FontWeight="Bold" Foreground="#F8FAFC"/>
                  <TextBlock x:Name="KpiTotalSub" Text="" Style="{StaticResource Muted}" Margin="0,6,0,0" TextTrimming="CharacterEllipsis"/>
                </StackPanel>
              </Border>
              <Border x:Name="CardCritical" Style="{StaticResource Card}" Margin="0,0,10,0" BorderBrush="#4C1D2B" Cursor="Hand" ToolTip="Filter Critical events">
                <StackPanel>
                  <TextBlock Text="CRITICAL" Style="{StaticResource Label}" Margin="0,0,0,6" Foreground="#F43F5E"/>
                  <TextBlock x:Name="KpiCritical" Text="-" FontSize="30" FontWeight="Bold" Foreground="#F43F5E"/>
                  <TextBlock Text="System-level failures" Style="{StaticResource Muted}" Margin="0,6,0,0"/>
                </StackPanel>
              </Border>
              <Border x:Name="CardError" Style="{StaticResource Card}" Margin="0,0,10,0" BorderBrush="#4A2A12" Cursor="Hand" ToolTip="Filter Error events">
                <StackPanel>
                  <TextBlock Text="ERRORS" Style="{StaticResource Label}" Margin="0,0,0,6" Foreground="#F97316"/>
                  <TextBlock x:Name="KpiError" Text="-" FontSize="30" FontWeight="Bold" Foreground="#F97316"/>
                  <TextBlock Text="Failed operations" Style="{StaticResource Muted}" Margin="0,6,0,0"/>
                </StackPanel>
              </Border>
              <Border x:Name="CardWarning" Style="{StaticResource Card}" Margin="0,0,10,0" BorderBrush="#423A10" Cursor="Hand" ToolTip="Filter Warning events">
                <StackPanel>
                  <TextBlock Text="WARNINGS" Style="{StaticResource Label}" Margin="0,0,0,6" Foreground="#FACC15"/>
                  <TextBlock x:Name="KpiWarning" Text="-" FontSize="30" FontWeight="Bold" Foreground="#FACC15"/>
                  <TextBlock Text="Potential problems" Style="{StaticResource Muted}" Margin="0,6,0,0"/>
                </StackPanel>
              </Border>
              <Border x:Name="CardAudit" Style="{StaticResource Card}" BorderBrush="#3F1D47" Cursor="Hand" ToolTip="Filter Audit failure events">
                <StackPanel>
                  <TextBlock Text="AUDIT FAILURES" Style="{StaticResource Label}" Margin="0,0,0,6" Foreground="#E879F9"/>
                  <TextBlock x:Name="KpiAudit" Text="-" FontSize="30" FontWeight="Bold" Foreground="#E879F9"/>
                  <TextBlock Text="Security audit failures" Style="{StaticResource Muted}" Margin="0,6,0,0"/>
                </StackPanel>
              </Border>
            </UniformGrid>

            <Grid Margin="0,14,0,0">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="2*"/>
                <ColumnDefinition Width="*"/>
              </Grid.ColumnDefinitions>
              <Border Style="{StaticResource Card}" Margin="0,0,10,0">
                <StackPanel>
                  <Grid>
                    <TextBlock Text="Activity timeline (click a bar to filter that window)" Style="{StaticResource SectionTitle}"/>
                    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Top">
                      <Border Width="10" Height="10" CornerRadius="2" Background="#1E3A5F" Margin="0,0,6,0" VerticalAlignment="Center"/>
                      <TextBlock Text="All events" Style="{StaticResource Muted}" Margin="0,0,14,0"/>
                      <Border Width="10" Height="10" CornerRadius="2" Background="#F97316" Margin="0,0,6,0" VerticalAlignment="Center"/>
                      <TextBlock Text="Errors / critical / audit failures" Style="{StaticResource Muted}"/>
                    </StackPanel>
                  </Grid>
                  <ItemsControl x:Name="TimelineItems" Height="150">
                    <ItemsControl.ItemsPanel>
                      <ItemsPanelTemplate><UniformGrid Rows="1"/></ItemsPanelTemplate>
                    </ItemsControl.ItemsPanel>
                    <ItemsControl.ItemTemplate>
                      <DataTemplate>
                        <Grid Margin="2,0" Background="Transparent" ToolTip="{Binding Tip}" Cursor="Hand">
                          <Border VerticalAlignment="Bottom" Height="{Binding Height}" Background="#1E3A5F" CornerRadius="3,3,0,0"/>
                          <Border VerticalAlignment="Bottom" Height="{Binding ErrHeight}" Background="#F97316" CornerRadius="3,3,0,0"/>
                        </Grid>
                      </DataTemplate>
                    </ItemsControl.ItemTemplate>
                  </ItemsControl>
                  <Grid Margin="0,8,0,0">
                    <TextBlock x:Name="TxtTimelineStart" Style="{StaticResource Muted}"/>
                    <TextBlock x:Name="TxtTimelineEnd" Style="{StaticResource Muted}" HorizontalAlignment="Right"/>
                  </Grid>
                </StackPanel>
              </Border>
              <Border Grid.Column="1" Style="{StaticResource Card}">
                <StackPanel>
                  <TextBlock Text="Top problems" Style="{StaticResource SectionTitle}"/>
                  <ItemsControl x:Name="DashFindings">
                    <ItemsControl.ItemTemplate>
                      <DataTemplate>
                        <Grid Margin="0,0,0,12" Cursor="Hand">
                          <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                          </Grid.ColumnDefinitions>
                          <Border Width="4" CornerRadius="2" Background="{Binding SeverityColor}" Margin="0,2,10,2"/>
                          <StackPanel Grid.Column="1">
                            <TextBlock Text="{Binding Title}" Foreground="#F8FAFC" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
                            <TextBlock Style="{StaticResource Muted}">
                              <Run Text="{Binding Severity, Mode=OneWay}"/><Run Text="  -  "/><Run Text="{Binding CountText, Mode=OneWay}"/>
                            </TextBlock>
                          </StackPanel>
                        </Grid>
                      </DataTemplate>
                    </ItemsControl.ItemTemplate>
                  </ItemsControl>
                  <Button x:Name="BtnGoFindings" Content="View root-cause analysis" Style="{StaticResource LinkButton}" HorizontalAlignment="Left" Margin="0,4,0,0"/>
                </StackPanel>
              </Border>
            </Grid>

            <Grid Margin="0,14,0,0">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
              </Grid.ColumnDefinitions>
              <Border Style="{StaticResource Card}" Margin="0,0,10,0">
                <StackPanel>
                  <TextBlock Text="Noisiest sources (warnings and above)" Style="{StaticResource SectionTitle}"/>
                  <ItemsControl x:Name="TopProviders" ItemTemplate="{StaticResource BarRow}"/>
                </StackPanel>
              </Border>
              <Border Grid.Column="1" Style="{StaticResource Card}" Margin="0,0,10,0">
                <StackPanel>
                  <TextBlock Text="Most frequent event IDs" Style="{StaticResource SectionTitle}"/>
                  <ItemsControl x:Name="TopIds">
                    <ItemsControl.ItemTemplate>
                      <DataTemplate>
                        <Grid Margin="0,0,0,10">
                          <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                          </Grid.ColumnDefinitions>
                          <StackPanel>
                            <TextBlock Text="{Binding Name}" TextTrimming="CharacterEllipsis" Foreground="#E2E8F0"/>
                            <TextBlock Text="{Binding Hint}" Style="{StaticResource Muted}" TextTrimming="CharacterEllipsis"/>
                            <Border Height="6" CornerRadius="3" Background="#F97316" HorizontalAlignment="Left" Margin="0,5,0,0" Width="{Binding Width}"/>
                          </StackPanel>
                          <TextBlock Grid.Column="1" Text="{Binding Count}" Foreground="#94A3B8" Margin="12,0,0,0" FontWeight="SemiBold"/>
                        </Grid>
                      </DataTemplate>
                    </ItemsControl.ItemTemplate>
                  </ItemsControl>
                </StackPanel>
              </Border>
              <Border Grid.Column="2" Style="{StaticResource Card}">
                <StackPanel>
                  <TextBlock Text="Log information" Style="{StaticResource SectionTitle}"/>
                  <TextBlock Text="TIME RANGE" Style="{StaticResource Label}" Margin="0,0,0,4"/>
                  <TextBlock x:Name="InfoRange" TextWrapping="Wrap"/>
                  <TextBlock Text="DURATION" Style="{StaticResource Label}"/>
                  <TextBlock x:Name="InfoSpan"/>
                  <TextBlock Text="COMPUTERS" Style="{StaticResource Label}"/>
                  <TextBlock x:Name="InfoComputers" TextWrapping="Wrap"/>
                  <TextBlock Text="CHANNELS" Style="{StaticResource Label}"/>
                  <TextBlock x:Name="InfoChannels" TextWrapping="Wrap"/>
                  <TextBlock Text="DISTINCT SOURCES" Style="{StaticResource Label}"/>
                  <TextBlock x:Name="InfoProviders"/>
                  <TextBlock Text="INCIDENTS (CORRELATED ERROR CLUSTERS)" Style="{StaticResource Label}"/>
                  <TextBlock x:Name="InfoIncidents"/>
                </StackPanel>
              </Border>
            </Grid>
          </StackPanel>
        </ScrollViewer>
      </TabItem>

      <TabItem x:Name="TabFindings" Header="Root cause analysis">
        <Grid Margin="20">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Margin="0,0,0,14">
            <TextBlock Text="Findings" FontSize="20" FontWeight="SemiBold" Foreground="#F8FAFC"/>
            <TextBlock x:Name="TxtFindingsSummary" Style="{StaticResource Muted}" TextWrapping="Wrap" Margin="0,4,0,0"/>
          </StackPanel>
          <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
            <ItemsControl x:Name="FindingsList">
              <ItemsControl.ItemTemplate>
                <DataTemplate>
                  <Border Background="#111827" BorderBrush="#1F2937" BorderThickness="1" CornerRadius="12" Margin="0,0,0,12">
                    <Grid>
                      <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="5"/>
                        <ColumnDefinition Width="*"/>
                      </Grid.ColumnDefinitions>
                      <Border Background="{Binding SeverityColor}" CornerRadius="12,0,0,12"/>
                      <StackPanel Grid.Column="1" Margin="18,16">
                        <Grid>
                          <StackPanel Orientation="Horizontal">
                            <Border Background="{Binding SeverityColor}" CornerRadius="10" Padding="10,2" Margin="0,0,10,0">
                              <TextBlock Text="{Binding Severity}" Foreground="#0B1120" FontWeight="Bold" FontSize="11"/>
                            </Border>
                            <TextBlock Text="{Binding Category}" Style="{StaticResource Muted}" VerticalAlignment="Center"/>
                            <TextBlock Text="  |  " Style="{StaticResource Muted}" VerticalAlignment="Center"/>
                            <TextBlock Text="{Binding CountText}" Style="{StaticResource Muted}" VerticalAlignment="Center"/>
                            <TextBlock Text="  |  " Style="{StaticResource Muted}" VerticalAlignment="Center"/>
                            <TextBlock Text="{Binding Window}" Style="{StaticResource Muted}" VerticalAlignment="Center"/>
                          </StackPanel>
                          <Button Content="Show events" Tag="{Binding}" Style="{StaticResource LinkButton}" HorizontalAlignment="Right"/>
                        </Grid>
                        <TextBlock Text="{Binding Title}" FontSize="16" FontWeight="SemiBold" Foreground="#F8FAFC" Margin="0,10,0,6" TextWrapping="Wrap"/>
                        <TextBlock Text="{Binding Detail}" TextWrapping="Wrap" Foreground="#CBD5E1" LineHeight="20"/>
                        <Border Background="#0F172A" CornerRadius="8" Padding="12,10" Margin="0,12,0,0">
                          <Grid>
                            <Grid.ColumnDefinitions>
                              <ColumnDefinition Width="Auto"/>
                              <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Text="&#xE82F;" FontFamily="Segoe MDL2 Assets" Foreground="#38BDF8" Margin="0,2,10,0"/>
                            <StackPanel Grid.Column="1">
                              <TextBlock Text="RECOMMENDED ACTION" Foreground="#38BDF8" FontSize="11" FontWeight="Bold"/>
                              <TextBlock Text="{Binding Recommendation}" TextWrapping="Wrap" Foreground="#E2E8F0" Margin="0,4,0,0" LineHeight="20"/>
                            </StackPanel>
                          </Grid>
                        </Border>
                      </StackPanel>
                    </Grid>
                  </Border>
                </DataTemplate>
              </ItemsControl.ItemTemplate>
            </ItemsControl>
          </ScrollViewer>
        </Grid>
      </TabItem>

      <TabItem x:Name="TabIncidents" Header="Incidents">
        <Grid Margin="20">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Margin="0,0,0,14">
            <TextBlock Text="Correlated incidents" FontSize="20" FontWeight="SemiBold" Foreground="#F8FAFC"/>
            <TextBlock x:Name="TxtIncidentsSummary" Style="{StaticResource Muted}" TextWrapping="Wrap" Margin="0,4,0,0"/>
          </StackPanel>
          <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
            <ItemsControl x:Name="IncidentsList">
              <ItemsControl.ItemTemplate>
                <DataTemplate>
                  <Border Background="#111827" BorderBrush="#1F2937" BorderThickness="1" CornerRadius="12" Margin="0,0,0,12" Padding="18,16">
                    <Grid>
                      <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="300"/>
                        <ColumnDefinition Width="*"/>
                      </Grid.ColumnDefinitions>
                      <StackPanel Margin="0,0,20,0">
                        <Border Background="{Binding SeverityColor}" CornerRadius="10" Padding="10,2" HorizontalAlignment="Left">
                          <TextBlock Text="{Binding Severity}" Foreground="#0B1120" FontWeight="Bold" FontSize="11"/>
                        </Border>
                        <TextBlock Text="{Binding Start}" FontSize="16" FontWeight="SemiBold" Foreground="#F8FAFC" Margin="0,10,0,2"/>
                        <TextBlock Style="{StaticResource Muted}">
                          <Run Text="{Binding Count, Mode=OneWay}"/><Run Text=" events over "/><Run Text="{Binding Duration, Mode=OneWay}"/>
                        </TextBlock>
                        <TextBlock Text="PROBABLE TRIGGER (FIRST ERROR)" Style="{StaticResource Label}"/>
                        <TextBlock Text="{Binding Trigger}" Foreground="#F97316" FontWeight="SemiBold" TextWrapping="Wrap"/>
                        <TextBlock Text="{Binding TriggerText}" Foreground="#CBD5E1" TextWrapping="Wrap" Margin="0,2,0,0"/>
                        <Button Content="Show events" Tag="{Binding}" Style="{StaticResource LinkButton}" HorizontalAlignment="Left" Margin="0,12,0,0"/>
                      </StackPanel>
                      <Border Grid.Column="1" Background="#0F172A" CornerRadius="8" Padding="14,12">
                        <StackPanel>
                          <TextBlock Text="CHAIN OF EVENTS (FIRST OCCURRENCE OF EACH)" Foreground="#64748B" FontSize="11" FontWeight="SemiBold" Margin="0,0,0,8"/>
                          <TextBlock Text="{Binding Chain}" FontFamily="Consolas" FontSize="12" Foreground="#E2E8F0" TextWrapping="Wrap" LineHeight="20"/>
                          <TextBlock Style="{StaticResource Muted}" Margin="0,10,0,0" TextWrapping="Wrap">
                            <Run Text="Sources: "/><Run Text="{Binding Providers, Mode=OneWay}"/>
                          </TextBlock>
                        </StackPanel>
                      </Border>
                    </Grid>
                  </Border>
                </DataTemplate>
              </ItemsControl.ItemTemplate>
            </ItemsControl>
          </ScrollViewer>
        </Grid>
      </TabItem>

      <TabItem x:Name="TabEvents" Header="All events">
        <Grid Margin="20">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*" MinWidth="500"/>
            <ColumnDefinition Width="6"/>
            <ColumnDefinition Width="460" MinWidth="320"/>
          </Grid.ColumnDefinitions>

          <Grid Grid.ColumnSpan="3" Margin="0,0,0,10">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="200"/>
              <ColumnDefinition Width="180"/>
              <ColumnDefinition Width="110"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Grid>
              <TextBox x:Name="TxtSearch" Padding="34,7,10,7"/>
              <TextBlock Text="&#xE721;" FontFamily="Segoe MDL2 Assets" Foreground="#64748B" Margin="12,0,0,0" VerticalAlignment="Center" IsHitTestVisible="False"/>
              <TextBlock x:Name="TxtSearchHint" Text="Search messages, sources, IDs, users, IPs, file names...  (quotes for phrases)" Foreground="#64748B" Margin="36,0,0,0" VerticalAlignment="Center" IsHitTestVisible="False"/>
            </Grid>
            <ComboBox x:Name="CmbProvider" Grid.Column="1" Margin="8,0,0,0"/>
            <ComboBox x:Name="CmbComputer" Grid.Column="2" Margin="8,0,0,0"/>
            <Grid Grid.Column="3" Margin="8,0,0,0">
              <TextBox x:Name="TxtEventId"/>
              <TextBlock x:Name="TxtEventIdHint" Text="Event ID(s)" Foreground="#64748B" Margin="12,0,0,0" VerticalAlignment="Center" IsHitTestVisible="False"/>
            </Grid>
            <Button x:Name="BtnClearFilters" Grid.Column="4" Content="Reset" Margin="8,0,0,0"/>
          </Grid>

          <Grid Grid.Row="1" Grid.ColumnSpan="3" Margin="0,0,0,10">
            <WrapPanel VerticalAlignment="Center">
              <CheckBox x:Name="ChkCritical" Content="Critical" Tag="#F43F5E" Style="{StaticResource Chip}" IsChecked="True"/>
              <CheckBox x:Name="ChkError" Content="Error" Tag="#F97316" Style="{StaticResource Chip}" IsChecked="True"/>
              <CheckBox x:Name="ChkAuditFail" Content="Audit failure" Tag="#E879F9" Style="{StaticResource Chip}" IsChecked="True"/>
              <CheckBox x:Name="ChkWarning" Content="Warning" Tag="#FACC15" Style="{StaticResource Chip}" IsChecked="True"/>
              <CheckBox x:Name="ChkInfo" Content="Information" Tag="#38BDF8" Style="{StaticResource Chip}" IsChecked="True"/>
              <CheckBox x:Name="ChkAuditOk" Content="Audit success" Tag="#34D399" Style="{StaticResource Chip}" IsChecked="True"/>
              <CheckBox x:Name="ChkVerbose" Content="Verbose" Tag="#94A3B8" Style="{StaticResource Chip}" IsChecked="True"/>
              <Border x:Name="FilterBanner" Background="#0C4A6E" CornerRadius="14" Padding="12,4,4,4" Margin="8,0,0,0" Visibility="Collapsed">
                <StackPanel Orientation="Horizontal">
                  <TextBlock x:Name="TxtFilterBanner" Foreground="#E0F2FE" VerticalAlignment="Center" MaxWidth="420" TextTrimming="CharacterEllipsis"/>
                  <Button x:Name="BtnClearBanner" Content="Clear" Style="{StaticResource LinkButton}" Padding="8,2" Margin="8,0,0,0" BorderBrush="#38BDF8"/>
                </StackPanel>
              </Border>
            </WrapPanel>
            <TextBlock x:Name="TxtEventCount" Style="{StaticResource Muted}" HorizontalAlignment="Right" VerticalAlignment="Center"/>
          </Grid>

          <Border Grid.Row="2" Background="#111827" BorderBrush="#1F2937" BorderThickness="1" CornerRadius="12">
            <DataGrid x:Name="EventsGrid" AutoGenerateColumns="False" IsReadOnly="True" SelectionMode="Single"
                      Background="Transparent" BorderThickness="0" RowBackground="Transparent" AlternatingRowBackground="#0F1626"
                      GridLinesVisibility="Horizontal" HorizontalGridLinesBrush="#1A2333" HeadersVisibility="Column"
                      RowHeight="34" Foreground="#E2E8F0" CanUserResizeRows="False" CanUserAddRows="False"
                      EnableRowVirtualization="True" VirtualizingPanel.IsVirtualizing="True" VirtualizingPanel.VirtualizationMode="Recycling"
                      ClipboardCopyMode="IncludeHeader" Margin="1">
              <DataGrid.Columns>
                <DataGridTemplateColumn Header="Level" Width="120" SortMemberPath="LevelRank">
                  <DataGridTemplateColumn.CellTemplate>
                    <DataTemplate>
                      <StackPanel Orientation="Horizontal">
                        <Ellipse Width="8" Height="8" Fill="{Binding LevelColor}" Margin="0,0,8,0" VerticalAlignment="Center"/>
                        <TextBlock Text="{Binding Level}" Foreground="{Binding LevelColor}" FontWeight="SemiBold" VerticalAlignment="Center"/>
                      </StackPanel>
                    </DataTemplate>
                  </DataGridTemplateColumn.CellTemplate>
                </DataGridTemplateColumn>
                <DataGridTextColumn Header="Time" Binding="{Binding TimeText}" Width="140"/>
                <DataGridTextColumn Header="Source" Binding="{Binding Provider}" Width="190"/>
                <DataGridTextColumn Header="ID" Binding="{Binding EventId}" Width="60"/>
                <DataGridTextColumn Header="What it means" Binding="{Binding KbTitle}" Width="220"/>
                <DataGridTextColumn Header="Message" Binding="{Binding Summary}" Width="*"/>
              </DataGrid.Columns>
            </DataGrid>
          </Border>

          <GridSplitter Grid.Row="2" Grid.Column="1" Width="6" HorizontalAlignment="Stretch" Background="Transparent" Cursor="SizeWE"/>

          <Border Grid.Row="2" Grid.Column="2" Background="#111827" BorderBrush="#1F2937" BorderThickness="1" CornerRadius="12">
            <Grid>
              <StackPanel x:Name="DetailEmpty" VerticalAlignment="Center" HorizontalAlignment="Center" Margin="30">
                <TextBlock Text="&#xE8A5;" FontFamily="Segoe MDL2 Assets" FontSize="32" Foreground="#334155" HorizontalAlignment="Center"/>
                <TextBlock Text="Select an event to see its explanation, decoded fields and related events." Style="{StaticResource Muted}" TextWrapping="Wrap" TextAlignment="Center" Margin="0,10,0,0" MaxWidth="260"/>
              </StackPanel>
              <ScrollViewer x:Name="DetailPanel" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                <StackPanel Margin="20">
                  <StackPanel Orientation="Horizontal">
                    <Border x:Name="DLevelPill" CornerRadius="10" Padding="10,2" Background="#38BDF8">
                      <TextBlock x:Name="DLevel" Foreground="#0B1120" FontWeight="Bold" FontSize="11"/>
                    </Border>
                    <TextBlock x:Name="DId" Foreground="#94A3B8" Margin="10,0,0,0" VerticalAlignment="Center" FontWeight="SemiBold"/>
                  </StackPanel>
                  <TextBlock x:Name="DKbTitle" FontSize="17" FontWeight="SemiBold" Foreground="#F8FAFC" TextWrapping="Wrap" Margin="0,10,0,2"/>
                  <TextBlock x:Name="DProvider" Style="{StaticResource Muted}" TextWrapping="Wrap"/>
                  <TextBlock x:Name="DTime" Style="{StaticResource Muted}"/>

                  <StackPanel x:Name="DKbBox" Margin="0,12,0,0">
                    <TextBlock x:Name="DKbExplain" TextWrapping="Wrap" Foreground="#CBD5E1" LineHeight="20"/>
                    <Border Background="#0F172A" CornerRadius="8" Padding="12,10" Margin="0,10,0,0">
                      <StackPanel>
                        <TextBlock Text="HOW TO FIX / WHAT TO CHECK" Foreground="#38BDF8" FontSize="11" FontWeight="Bold"/>
                        <TextBlock x:Name="DKbAdvice" TextWrapping="Wrap" Foreground="#E2E8F0" Margin="0,4,0,0" LineHeight="20"/>
                      </StackPanel>
                    </Border>
                  </StackPanel>

                  <TextBlock Text="MESSAGE" Style="{StaticResource Label}" Margin="0,16,0,4"/>
                  <TextBox x:Name="DMessage" IsReadOnly="True" TextWrapping="Wrap" Background="#0F172A" BorderThickness="1" MaxHeight="220" VerticalScrollBarVisibility="Auto"/>

                  <TextBlock Text="EVENT DATA (DECODED)" Style="{StaticResource Label}" Margin="0,16,0,4"/>
                  <ItemsControl x:Name="DDataList">
                    <ItemsControl.ItemTemplate>
                      <DataTemplate>
                        <Border BorderBrush="#1F2937" BorderThickness="0,0,0,1" Padding="0,6">
                          <Grid>
                            <Grid.ColumnDefinitions>
                              <ColumnDefinition Width="150"/>
                              <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Text="{Binding Name}" Foreground="#94A3B8" TextTrimming="CharacterEllipsis" ToolTip="{Binding Name}"/>
                            <StackPanel Grid.Column="1">
                              <TextBox Text="{Binding Value, Mode=OneWay}" IsReadOnly="True" BorderThickness="0" Background="Transparent" Padding="0" TextWrapping="Wrap" FontFamily="Consolas" FontSize="12"/>
                              <TextBlock Text="{Binding Meaning}" Foreground="#34D399" FontSize="12" TextWrapping="Wrap"/>
                            </StackPanel>
                          </Grid>
                        </Border>
                      </DataTemplate>
                    </ItemsControl.ItemTemplate>
                  </ItemsControl>

                  <TextBlock Text="SYSTEM PROPERTIES" Style="{StaticResource Label}" Margin="0,16,0,4"/>
                  <Grid>
                    <Grid.ColumnDefinitions>
                      <ColumnDefinition Width="150"/>
                      <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    <Grid.RowDefinitions>
                      <RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/>
                    </Grid.RowDefinitions>
                    <TextBlock Grid.Row="0" Text="Computer" Foreground="#94A3B8" Margin="0,3"/>
                    <TextBlock Grid.Row="0" Grid.Column="1" x:Name="DComputer" TextWrapping="Wrap" Margin="0,3"/>
                    <TextBlock Grid.Row="1" Text="Channel" Foreground="#94A3B8" Margin="0,3"/>
                    <TextBlock Grid.Row="1" Grid.Column="1" x:Name="DChannel" Margin="0,3"/>
                    <TextBlock Grid.Row="2" Text="Task category" Foreground="#94A3B8" Margin="0,3"/>
                    <TextBlock Grid.Row="2" Grid.Column="1" x:Name="DTask" Margin="0,3"/>
                    <TextBlock Grid.Row="3" Text="Record ID" Foreground="#94A3B8" Margin="0,3"/>
                    <TextBlock Grid.Row="3" Grid.Column="1" x:Name="DRecord" Margin="0,3"/>
                    <TextBlock Grid.Row="4" Text="Process / Thread" Foreground="#94A3B8" Margin="0,3"/>
                    <TextBlock Grid.Row="4" Grid.Column="1" x:Name="DProcess" Margin="0,3"/>
                    <TextBlock Grid.Row="5" Text="User SID" Foreground="#94A3B8" Margin="0,3"/>
                    <TextBlock Grid.Row="5" Grid.Column="1" x:Name="DUser" TextWrapping="Wrap" Margin="0,3"/>
                    <TextBlock Grid.Row="6" Text="Keywords" Foreground="#94A3B8" Margin="0,3"/>
                    <TextBlock Grid.Row="6" Grid.Column="1" x:Name="DKeywords" Margin="0,3"/>
                  </Grid>

                  <TextBlock x:Name="DRelatedHeader" Text="RELATED EVENTS" Style="{StaticResource Label}" Margin="0,16,0,4"/>
                  <ListBox x:Name="DRelated" Background="Transparent" BorderThickness="0" MaxHeight="260"
                           ScrollViewer.HorizontalScrollBarVisibility="Disabled">
                    <ListBox.ItemTemplate>
                      <DataTemplate>
                        <Grid>
                          <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                          </Grid.ColumnDefinitions>
                          <Ellipse Width="8" Height="8" Fill="{Binding LevelColor}" Margin="0,5,8,0" VerticalAlignment="Top"/>
                          <StackPanel Grid.Column="1">
                            <TextBlock TextTrimming="CharacterEllipsis">
                              <Run Text="{Binding TimeText, Mode=OneWay}" Foreground="#94A3B8"/><Run Text="  "/><Run Text="{Binding Provider, Mode=OneWay}"/><Run Text=" "/><Run Text="{Binding EventId, Mode=OneWay}" FontWeight="SemiBold"/>
                            </TextBlock>
                            <TextBlock Text="{Binding Summary}" Foreground="#64748B" FontSize="12" TextTrimming="CharacterEllipsis"/>
                          </StackPanel>
                        </Grid>
                      </DataTemplate>
                    </ListBox.ItemTemplate>
                  </ListBox>

                  <Grid Margin="0,16,0,4">
                    <TextBlock Text="RAW XML" Style="{StaticResource Label}" Margin="0"/>
                    <Button x:Name="BtnCopyXml" Content="Copy" Style="{StaticResource LinkButton}" HorizontalAlignment="Right" Padding="8,2"/>
                  </Grid>
                  <TextBox x:Name="DRawXml" IsReadOnly="True" TextWrapping="Wrap" FontFamily="Consolas" FontSize="11" MaxHeight="260"
                           VerticalScrollBarVisibility="Auto" Foreground="#A5B4FC"/>
                </StackPanel>
              </ScrollViewer>
            </Grid>
          </Border>
        </Grid>
      </TabItem>
    </TabControl>

    <Grid x:Name="EmptyState" Grid.Row="1">
      <Border x:Name="DropZone" Width="640" Height="400" CornerRadius="20" Background="#0F172A" HorizontalAlignment="Center" VerticalAlignment="Center">
        <Grid>
          <Rectangle x:Name="DropZoneBorder" RadiusX="20" RadiusY="20" Stroke="#334155" StrokeThickness="2" StrokeDashArray="6 4"/>
          <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center" Margin="40">
            <Border Width="72" Height="72" CornerRadius="36" Background="#0C4A6E" HorizontalAlignment="Center">
              <TextBlock Text="&#xE896;" FontFamily="Segoe MDL2 Assets" FontSize="30" Foreground="#38BDF8" HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <TextBlock Text="Drop event log files here" FontSize="22" FontWeight="SemiBold" Foreground="#F8FAFC" HorizontalAlignment="Center" Margin="0,20,0,6"/>
            <TextBlock Style="{StaticResource Muted}" FontSize="13" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap" MaxWidth="480"
                       Text="Supports Event Viewer XML (UTF-8 or UTF-16), wevtutil qe /f:xml fragments, Get-WinEvent ToXml() exports, and native .evtx files. Drop several files to merge System + Application + Security."/>
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,24,0,0">
              <Button x:Name="BtnEmptyOpen" Content="Browse for a file" Style="{StaticResource PrimaryButton}" Padding="18,9" Margin="0,0,10,0"/>
              <Button x:Name="BtnEmptyLive" Content="Capture this PC's System log" Padding="18,9"/>
            </StackPanel>
            <TextBlock Style="{StaticResource Muted}" HorizontalAlignment="Center" Margin="0,18,0,0" TextWrapping="Wrap" TextAlignment="Center" MaxWidth="500"
                       Text="Tip: wevtutil qe System /c:5000 /rd:true /f:xml &gt; C:\Temp\System.xml"/>
          </StackPanel>
        </Grid>
      </Border>
    </Grid>

    <Grid x:Name="LoadingOverlay" Grid.Row="0" Grid.RowSpan="3" Background="#CC0B1120" Visibility="Collapsed">
      <Border Style="{StaticResource Card}" Width="420" HorizontalAlignment="Center" VerticalAlignment="Center" Padding="24">
        <StackPanel>
          <TextBlock x:Name="LoadingTitle" Text="Analyzing events..." FontSize="16" FontWeight="SemiBold" Foreground="#F8FAFC"/>
          <TextBlock x:Name="LoadingText" Text="" Style="{StaticResource Muted}" Margin="0,4,0,14"/>
          <ProgressBar x:Name="LoadingBar" Minimum="0" Maximum="100" Value="0"/>
        </StackPanel>
      </Border>
    </Grid>

    <Border Grid.Row="2" Background="#0B1120" BorderBrush="#1F2937" BorderThickness="0,1,0,0" Padding="20,6">
      <Grid>
        <TextBlock x:Name="TxtStatus" Text="Ready" Style="{StaticResource Muted}"/>
        <TextBlock x:Name="TxtStatusRight" Style="{StaticResource Muted}" HorizontalAlignment="Right"/>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

#endregion

#region ======================= GUI logic =======================

$reader = New-Object System.Xml.XmlNodeReader $script:Xaml
$script:Window = [Windows.Markup.XamlReader]::Load($reader)

$script:Ui = @{}
foreach ($node in $script:Xaml.SelectNodes("//*[@*[local-name()='Name']]")) {
    $name = $node.Attributes | Where-Object { $_.LocalName -eq 'Name' } | Select-Object -First 1 -ExpandProperty Value
    if ($name) { $script:Ui[$name] = $script:Window.FindName($name) }
}
$ui = $script:Ui

$script:State = @{
    Events      = @()
    Analysis    = $null
    File        = ''
    PosByIndex  = @{}
    ByIndex     = @{}
    IndexFilter = $null
    TimeLo      = $null
    TimeHi      = $null
    Filtered    = @()
}

$script:LevelChecks = [ordered]@{
    'Critical'      = 'ChkCritical'
    'Error'         = 'ChkError'
    'Audit Failure' = 'ChkAuditFail'
    'Warning'       = 'ChkWarning'
    'Information'   = 'ChkInfo'
    'Audit Success' = 'ChkAuditOk'
    'Verbose'       = 'ChkVerbose'
}

function Invoke-UiPump {
    $script:Window.Dispatcher.Invoke([Action] {}, [System.Windows.Threading.DispatcherPriority]::Background)
}

function Show-Error([string]$Title, [string]$Message) {
    [void][System.Windows.MessageBox]::Show($script:Window, $Message, $Title, 'OK', 'Error')
}

function Set-Status([string]$Text) { $ui.TxtStatus.Text = $Text }

function Show-Loading([string]$Title, [string]$Text, [double]$Value = 0) {
    $ui.LoadingTitle.Text = $Title
    $ui.LoadingText.Text = $Text
    $ui.LoadingBar.Value = $Value
    $ui.LoadingOverlay.Visibility = 'Visible'
    Invoke-UiPump
}

function Hide-Loading { $ui.LoadingOverlay.Visibility = 'Collapsed' }

function Get-HealthInfo([int]$Score) {
    if ($Score -ge 80) { return @{ Label = 'Healthy - no serious problems detected'; Color = '#34D399' } }
    if ($Score -ge 50) { return @{ Label = 'Needs attention'; Color = '#FACC15' } }
    return @{ Label = 'Unhealthy - investigate findings'; Color = '#F43F5E' }
}

function Format-Span([timespan]$Span) {
    if ($Span.TotalDays -ge 1) { return '{0:N0} d {1} h {2} min' -f [math]::Floor($Span.TotalDays), $Span.Hours, $Span.Minutes }
    if ($Span.TotalHours -ge 1) { return '{0} h {1} min' -f [math]::Floor($Span.TotalHours), $Span.Minutes }
    if ($Span.TotalMinutes -ge 1) { return '{0} min {1} sec' -f [math]::Floor($Span.TotalMinutes), $Span.Seconds }
    return '{0:N0} sec' -f $Span.TotalSeconds
}

function Get-SearchTerms([string]$Text) {
    $terms = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $rx = [regex]::Matches($Text.ToLowerInvariant(), '"([^"]+)"|(\S+)')
    foreach ($m in $rx) {
        $t = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
        if ($t) { [void]$terms.Add($t) }
    }
    return @($terms)
}

function Update-Dashboard {
    $a = $script:State.Analysis
    $health = Get-HealthInfo $a.HealthScore
    $brush = (New-Object System.Windows.Media.BrushConverter).ConvertFromString($health.Color)

    $ui.KpiHealth.Text = [string]$a.HealthScore
    $ui.KpiHealth.Foreground = $brush
    $ui.KpiHealthBar.Value = $a.HealthScore
    $ui.KpiHealthBar.Foreground = $brush
    $ui.KpiHealthLabel.Text = $health.Label
    $ui.KpiTotal.Text = '{0:N0}' -f $a.Total
    $ui.KpiTotalSub.Text = '{0:N0} information, {1:N0} audit success' -f (Get-HashValue $a.Levels 'Information' 0), (Get-HashValue $a.Levels 'Audit Success' 0)
    $ui.KpiCritical.Text = '{0:N0}' -f (Get-HashValue $a.Levels 'Critical' 0)
    $ui.KpiError.Text = '{0:N0}' -f (Get-HashValue $a.Levels 'Error' 0)
    $ui.KpiWarning.Text = '{0:N0}' -f (Get-HashValue $a.Levels 'Warning' 0)
    $ui.KpiAudit.Text = '{0:N0}' -f (Get-HashValue $a.Levels 'Audit Failure' 0)

    $ui.TimelineItems.ItemsSource = @($a.Timeline)
    if ($a.Start) {
        $ui.TxtTimelineStart.Text = $a.Start.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
        $ui.TxtTimelineEnd.Text = $a.End.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
        $ui.InfoRange.Text = "$($a.Start.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture))  to  $($a.End.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture))"
        $ui.InfoSpan.Text = Format-Span ($a.End - $a.Start)
    }
    else {
        $ui.TxtTimelineStart.Text = ''; $ui.TxtTimelineEnd.Text = ''
        $ui.InfoRange.Text = 'No timestamps found'; $ui.InfoSpan.Text = 'n/a'
    }

    $ui.DashFindings.ItemsSource = @($a.Findings | Select-Object -First 5)
    $ui.TopProviders.ItemsSource = @($a.TopProviders)
    $ui.TopIds.ItemsSource = @($a.TopEventIds)
    $ui.InfoComputers.Text = $(if (@($a.Computers).Count) { (@($a.Computers) | Select-Object -First 6) -join ', ' } else { 'n/a' })
    $ui.InfoChannels.Text = $(if (@($a.Channels).Count) { @($a.Channels) -join ', ' } else { 'n/a' })
    $ui.InfoProviders.Text = '{0:N0}' -f @($a.Providers).Count
    $ui.InfoIncidents.Text = '{0:N0}' -f @($a.Incidents).Count

    $findings = @($a.Findings)
    $ui.FindingsList.ItemsSource = $findings
    $crit = @($findings | Where-Object { $_.Severity -in @('Critical', 'High') }).Count
    $ui.TxtFindingsSummary.Text = "$($findings.Count) finding(s), $crit critical/high. Findings are ordered by severity. Fix the top items first, because later problems are often side effects of them. Click 'Show events' to see the evidence."
    $ui.TabFindings.Header = "Root cause analysis ($($findings.Count))"

    $incidents = @($a.Incidents)
    $ui.IncidentsList.ItemsSource = $incidents
    $ui.TxtIncidentsSummary.Text = "$($incidents.Count) incident(s). Errors that occur within $CorrelationMinutes minute(s) of each other are grouped. The first error in each group is usually the trigger, and the events after it are often consequences."
    $ui.TabIncidents.Header = "Incidents ($($incidents.Count))"
    $ui.TabEvents.Header = "All events ($($a.Total))"

    $ui.CmbProvider.Items.Clear()
    [void]$ui.CmbProvider.Items.Add('All sources')
    foreach ($p in @($a.Providers)) { if ($p) { [void]$ui.CmbProvider.Items.Add($p) } }
    $ui.CmbProvider.SelectedIndex = 0

    $ui.CmbComputer.Items.Clear()
    [void]$ui.CmbComputer.Items.Add('All computers')
    foreach ($c in @($a.Computers)) { if ($c) { [void]$ui.CmbComputer.Items.Add($c) } }
    $ui.CmbComputer.SelectedIndex = 0
}

function Update-EventFilter {
    $events = $script:State.Events
    if (-not $events -or $events.Count -eq 0) { return }

    $levels = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($k in $script:LevelChecks.Keys) { if ($ui[$script:LevelChecks[$k]].IsChecked) { [void]$levels.Add($k) } }

    $terms = @(Get-SearchTerms $ui.TxtSearch.Text)
    $provider = $null
    if ($ui.CmbProvider.SelectedIndex -gt 0) { $provider = [string]$ui.CmbProvider.SelectedItem }
    $computer = $null
    if ($ui.CmbComputer.SelectedIndex -gt 0) { $computer = [string]$ui.CmbComputer.SelectedItem }
    $ids = $null
    $idText = $ui.TxtEventId.Text.Trim()
    if ($idText) {
        $ids = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($t in ($idText -split '[,;\s]+')) { if ($t) { [void]$ids.Add($t) } }
    }
    $idx = $script:State.IndexFilter
    $timeLo = $script:State.TimeLo
    $timeHi = $script:State.TimeHi

    $result = New-Object System.Collections.Generic.List[object]
    foreach ($e in $events) {
        if (-not $levels.Contains($e.Level)) { continue }
        if ($null -ne $idx -and -not $idx.Contains([int]$e.Index)) { continue }
        if ($provider -and $e.Provider -ne $provider) { continue }
        if ($computer -and $e.Computer -ne $computer) { continue }
        if ($null -ne $ids -and -not $ids.Contains([string]$e.EventId)) { continue }
        if ($null -ne $timeLo -and $e.Time -ne [datetime]::MinValue -and $e.Time -lt $timeLo) { continue }
        if ($null -ne $timeHi -and $e.Time -ne [datetime]::MinValue -and $e.Time -ge $timeHi) { continue }
        $ok = $true
        foreach ($t in $terms) { if ($e.SearchText.IndexOf($t, [StringComparison]::Ordinal) -lt 0) { $ok = $false; break } }
        if (-not $ok) { continue }
        $result.Add($e)
    }
    $result.Reverse()
    $script:State.Filtered = $result.ToArray()
    $ui.EventsGrid.ItemsSource = $script:State.Filtered
    $ui.TxtEventCount.Text = '{0:N0} of {1:N0} events' -f $result.Count, $events.Count
}

function Reset-EventFilters {
    $script:State.IndexFilter = $null
    $script:State.TimeLo = $null
    $script:State.TimeHi = $null
    $ui.FilterBanner.Visibility = 'Collapsed'
    $ui.TxtSearch.Text = ''
    $ui.TxtEventId.Text = ''
    if ($ui.CmbProvider.Items.Count) { $ui.CmbProvider.SelectedIndex = 0 }
    if ($ui.CmbComputer.Items.Count) { $ui.CmbComputer.SelectedIndex = 0 }
    foreach ($c in $script:LevelChecks.Values) { $ui[$c].IsChecked = $true }
    Update-EventFilter
}

function Show-FilterBanner([string]$Text) {
    $ui.TxtFilterBanner.Text = $Text
    $ui.FilterBanner.Visibility = 'Visible'
}

function Show-EventSubset([string]$Label, [object[]]$Indexes) {
    $set = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($i in $Indexes) { [void]$set.Add([int]$i) }
    $script:State.IndexFilter = $set
    $script:State.TimeLo = $null
    $script:State.TimeHi = $null
    $ui.TxtSearch.Text = ''
    $ui.TxtEventId.Text = ''
    if ($ui.CmbProvider.Items.Count) { $ui.CmbProvider.SelectedIndex = 0 }
    if ($ui.CmbComputer.Items.Count) { $ui.CmbComputer.SelectedIndex = 0 }
    foreach ($c in $script:LevelChecks.Values) { $ui[$c].IsChecked = $true }
    Show-FilterBanner "Evidence for: $Label"
    $ui.MainTabs.SelectedItem = $ui.TabEvents
    Update-EventFilter
    if ($script:State.Filtered.Count -gt 0) {
        $ui.EventsGrid.SelectedIndex = 0
        $ui.EventsGrid.ScrollIntoView($ui.EventsGrid.SelectedItem)
    }
}

function Show-LevelFilter([string[]]$Keep) {
    $script:State.IndexFilter = $null
    $script:State.TimeLo = $null
    $script:State.TimeHi = $null
    foreach ($k in $script:LevelChecks.Keys) {
        $ui[$script:LevelChecks[$k]].IsChecked = ($Keep -contains $k)
    }
    Show-FilterBanner ("Level filter: " + ($Keep -join ', '))
    $ui.MainTabs.SelectedItem = $ui.TabEvents
    Update-EventFilter
}

function Get-RelatedEvents($Evt, [int]$Minutes = 5, [int]$Max = 40) {
    $events = $script:State.Events
    if ($Evt.Time -eq [datetime]::MinValue) { return @() }
    $pos = $script:State.PosByIndex[[int]$Evt.Index]
    if ($null -eq $pos) { return @() }
    $lo = $Evt.Time.AddMinutes(-$Minutes); $hi = $Evt.Time.AddMinutes($Minutes)
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = $pos - 1; $i -ge 0 -and $events[$i].Time -ge $lo; $i--) { if ($events[$i].LevelRank -le 3) { $out.Add($events[$i]) } }
    for ($i = $pos + 1; $i -lt $events.Count -and $events[$i].Time -le $hi; $i++) { if ($events[$i].LevelRank -le 3) { $out.Add($events[$i]) } }
    return @($out | Sort-Object Time | Select-Object -First $Max)
}

function Show-EventDetail($Evt) {
    if ($null -eq $Evt) {
        $ui.DetailPanel.Visibility = 'Collapsed'
        $ui.DetailEmpty.Visibility = 'Visible'
        return
    }
    $ui.DetailEmpty.Visibility = 'Collapsed'
    $ui.DetailPanel.Visibility = 'Visible'

    $ui.DLevel.Text = $Evt.Level.ToUpper()
    $ui.DLevelPill.Background = (New-Object System.Windows.Media.BrushConverter).ConvertFromString($Evt.LevelColor)
    $ui.DId.Text = "Event ID $($Evt.EventId)"
    $ui.DKbTitle.Text = $(if ($Evt.KbTitle) { $Evt.KbTitle } else { "$($Evt.Provider) event $($Evt.EventId)" })
    $ui.DProvider.Text = $Evt.Provider
    $ui.DTime.Text = $Evt.TimeText

    if ($Evt.KbExplanation) {
        $ui.DKbBox.Visibility = 'Visible'
        $ui.DKbExplain.Text = $Evt.KbExplanation
        $ui.DKbAdvice.Text = $Evt.KbAdvice
    }
    else { $ui.DKbBox.Visibility = 'Collapsed' }

    $ui.DMessage.Text = $(if ($Evt.Message) { $Evt.Message } else { '(No rendered message in the XML. See decoded event data below.)' })
    $ui.DDataList.ItemsSource = @($Evt.Decoded)
    $ui.DComputer.Text = $Evt.Computer
    $ui.DChannel.Text = $Evt.Channel
    $ui.DTask.Text = $Evt.Task
    $ui.DRecord.Text = $Evt.RecordId
    $ui.DProcess.Text = "$($Evt.ProcessId) / $($Evt.ThreadId)"
    $ui.DUser.Text = $Evt.UserSid
    $ui.DKeywords.Text = $Evt.Keywords

    $related = @(Get-RelatedEvents $Evt $CorrelationMinutes)
    $ui.DRelatedHeader.Text = "RELATED WARNINGS / ERRORS (+/- $CorrelationMinutes MIN)  -  $($related.Count)"
    $ui.DRelated.ItemsSource = $related
    $ui.DRawXml.Text = Format-XmlPretty $Evt.RawXml
}

function Format-XmlPretty([string]$Xml) {
    try {
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.LoadXml((Remove-InvalidXmlChars $Xml))
        $sw = New-Object System.IO.StringWriter
        $settings = New-Object System.Xml.XmlWriterSettings
        $settings.Indent = $true
        $settings.OmitXmlDeclaration = $true
        $w = [System.Xml.XmlWriter]::Create($sw, $settings)
        $doc.WriteTo($w); $w.Flush(); $w.Close()
        return $sw.ToString()
    }
    catch { return $Xml }
}

function Select-EventInGrid($Evt) {
    if ($script:State.Filtered -notcontains $Evt) { Reset-EventFilters }
    $ui.EventsGrid.SelectedItem = $Evt
    $ui.EventsGrid.ScrollIntoView($Evt)
}

function Complete-LoadedAnalysis {
    param([object[]]$Events, $Analysis, [string]$DisplayName, [string]$FilePath, [System.Diagnostics.Stopwatch]$Stopwatch)
    $pos = @{}; $byIdx = @{}
    for ($i = 0; $i -lt $Events.Count; $i++) { $pos[[int]$Events[$i].Index] = $i; $byIdx[[int]$Events[$i].Index] = $Events[$i] }

    $script:State.Events = $Events
    $script:State.Analysis = $Analysis
    $script:State.File = $FilePath
    $script:State.PosByIndex = $pos
    $script:State.ByIndex = $byIdx

    Show-Loading 'Rendering...' '' 96
    Update-Dashboard
    Reset-EventFilters
    Show-EventDetail $null

    $ui.EmptyState.Visibility = 'Collapsed'
    $ui.MainTabs.Visibility = 'Visible'
    $ui.MainTabs.SelectedItem = $ui.TabDashboard
    $ui.BtnExportHtml.IsEnabled = $true
    $ui.BtnExportCsv.IsEnabled = $true
    $ui.BtnExportJson.IsEnabled = $true
    $ui.TxtFileName.Text = $DisplayName
    $titleLeaf = [System.IO.Path]::GetFileName($DisplayName)
    $script:Window.Title = "$script:AppName - $titleLeaf"
    if ($Stopwatch) { $Stopwatch.Stop() }
    $secs = if ($Stopwatch) { $Stopwatch.Elapsed.TotalSeconds } else { 0 }
    Set-Status ('Loaded {0:N0} events, {1} finding(s), {2} incident(s) in {3:N1} s' -f $Events.Count, @($Analysis.Findings).Count, @($Analysis.Incidents).Count, $secs)
}

function Import-AndAnalyze {
    param([string[]]$FilePath, [string]$DisplayName)
    $files = @($FilePath | Where-Object { $_ })
    if ($files.Count -eq 0) { return }
    if (-not $DisplayName) {
        $DisplayName = if ($files.Count -eq 1) { $files[0] } else { '{0} files: {1}' -f $files.Count, (($files | ForEach-Object { [System.IO.Path]::GetFileName($_) }) -join ', ') }
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $size = 0L
        foreach ($f in $files) { $size += (Get-Item -LiteralPath $f).Length }
        Show-Loading 'Reading log...' ('{0}  ({1:N1} MB)' -f $DisplayName, ($size / 1MB)) 2
        $events = Import-EventLogXml -FilePath $files -OnProgress {
            param($i, $t)
            $ui.LoadingTitle.Text = 'Parsing events...'
            $ui.LoadingText.Text = '{0:N0} of {1:N0} events' -f $i, [math]::Max($i, $t)
            $ui.LoadingBar.Value = 5 + 80 * $i / [math]::Max(1, [math]::Max($i, $t))
            Invoke-UiPump
        }
        if (@($events).Count -eq 0) { throw 'The file contained no readable events.' }

        Show-Loading 'Analyzing...' 'Correlating events and detecting root causes' 88
        $analysis = Invoke-EventAnalysis -Events $events -WindowMinutes $CorrelationMinutes
        Complete-LoadedAnalysis -Events $events -Analysis $analysis -DisplayName $DisplayName -FilePath $files[0] -Stopwatch $sw
    }
    catch {
        Show-Error 'Could not load file' "Failed to parse '$DisplayName'.`n`n$($_.Exception.Message)"
        Set-Status 'Load failed'
    }
    finally { Hide-Loading }
}

function Open-XmlFile {
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Title = 'Open event log export'
    $dlg.Filter = 'Event logs (*.xml;*.evtx)|*.xml;*.evtx|XML (*.xml)|*.xml|Event Trace (.evtx)|*.evtx|All files (*.*)|*.*'
    $dlg.Multiselect = $true
    if ($dlg.ShowDialog($script:Window)) { Import-AndAnalyze @($dlg.FileNames) }
}

function Convert-WinEventRecords {
    param($Records, [scriptblock]$OnProgress)
    $list = New-Object System.Collections.Generic.List[object]
    $i = 0
    $total = @($Records).Count
    foreach ($r in @($Records)) {
        $i++
        try {
            $xml = $r.ToXml()
            $msg = $null
            try { $msg = $r.FormatDescription() } catch { }
            if (-not $msg) { try { $msg = $r.Message } catch { } }
            $list.Add((Convert-EventXmlString -Xml $xml -Index $i -MessageOverride $msg))
        }
        catch { Write-Verbose "Skipping live record #$i : $($_.Exception.Message)" }
        if ($OnProgress -and ($i % 150 -eq 0 -or $i -eq $total)) { & $OnProgress $i $total }
    }
    return @($list | Sort-Object Time, Index)
}

function Invoke-LocalCapture([string]$LogName, [int]$Count = 0) {
    if ($Count -le 0) { $Count = $MaxEvents }
    try {
        Show-Loading "Capturing $LogName log..." "Reading the newest $Count events from this computer" 2
        $records = @(Get-WinEvent -LogName $LogName -MaxEvents $Count -ErrorAction Stop)
        $events = Convert-WinEventRecords -Records $records -OnProgress {
            param($i, $t)
            $ui.LoadingText.Text = '{0:N0} of {1:N0} events captured' -f $i, $t
            $ui.LoadingBar.Value = 2 + 80 * $i / [math]::Max(1, $t)
            Invoke-UiPump
        }
        if (@($events).Count -eq 0) { throw 'No events were captured.' }
        Show-Loading 'Analyzing...' 'Correlating events and detecting root causes' 88
        $analysis = Invoke-EventAnalysis -Events $events -WindowMinutes $CorrelationMinutes
        $sw = [System.Diagnostics.Stopwatch]::StartNew(); $sw.Stop()
        Complete-LoadedAnalysis -Events $events -Analysis $analysis -DisplayName "Local $LogName log ($env:COMPUTERNAME)" -FilePath "live:$LogName" -Stopwatch $sw
    }
    catch {
        Hide-Loading
        $hint = if ($LogName -eq 'Security') { "`n`nThe Security log requires running PowerShell as Administrator." } else { '' }
        Show-Error 'Capture failed' "Could not read the $LogName log.`n`n$($_.Exception.Message)$hint"
    }
    finally { Hide-Loading }
}

function Export-Html {
    if (-not $script:State.Analysis) { return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'HTML report (*.html)|*.html'
    $base = if ($script:State.File -like 'live:*') { $script:State.File -replace '[:\\/]', '_' } else { [System.IO.Path]::GetFileNameWithoutExtension($script:State.File) }
    $dlg.FileName = '{0}-report.html' -f $base
    if ($dlg.ShowDialog($script:Window)) {
        try {
            Export-AnalysisHtml -Events $script:State.Events -Analysis $script:State.Analysis -OutFile $dlg.FileName -SourceFile $script:State.File
            Set-Status "HTML report saved to $($dlg.FileName)"
            Start-Process $dlg.FileName
        }
        catch { Show-Error 'Export failed' $_.Exception.Message }
    }
}

function Export-JsonGui {
    if (-not $script:State.Analysis) { return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'JSON (*.json)|*.json'
    $base = if ($script:State.File -like 'live:*') { $script:State.File -replace '[:\\/]', '_' } else { [System.IO.Path]::GetFileNameWithoutExtension($script:State.File) }
    $dlg.FileName = '{0}-analysis.json' -f $base
    if ($dlg.ShowDialog($script:Window)) {
        try {
            Export-AnalysisJson -Events $script:State.Events -Analysis $script:State.Analysis -OutFile $dlg.FileName -SourceFile $script:State.File
            Set-Status "JSON analysis saved to $($dlg.FileName)"
        }
        catch { Show-Error 'Export failed' $_.Exception.Message }
    }
}

function Export-FilteredEventCsv {
    if (-not $script:State.Analysis) { return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'CSV (*.csv)|*.csv'
    $base = if ($script:State.File -like 'live:*') { $script:State.File -replace '[:\\/]', '_' } else { [System.IO.Path]::GetFileNameWithoutExtension($script:State.File) }
    $dlg.FileName = '{0}-events.csv' -f $base
    if ($dlg.ShowDialog($script:Window)) {
        try {
            Export-EventsCsv -Events $script:State.Filtered -OutFile $dlg.FileName
            Set-Status ('Exported {0:N0} events (current filter) to {1}' -f $script:State.Filtered.Count, $dlg.FileName)
        }
        catch { Show-Error 'Export failed' $_.Exception.Message }
    }
}

function Find-Ancestor($Element, [type]$Type) {
    $cur = $Element
    while ($null -ne $cur -and -not ($cur -is $Type)) {
        if ($cur -is [System.Windows.Media.Visual] -or $cur -is [System.Windows.Media.Media3D.Visual3D]) {
            $cur = [System.Windows.Media.VisualTreeHelper]::GetParent($cur)
        }
        else { $cur = [System.Windows.LogicalTreeHelper]::GetParent($cur) }
    }
    return $cur
}

function Get-DataContextFromSource($Source) {
    $cur = $Source
    while ($null -ne $cur) {
        if ($cur -is [System.Windows.FrameworkElement] -and $null -ne $cur.DataContext) { return $cur.DataContext }
        if ($cur -is [System.Windows.Media.Visual] -or $cur -is [System.Windows.Media.Media3D.Visual3D]) {
            $cur = [System.Windows.Media.VisualTreeHelper]::GetParent($cur)
        }
        else { $cur = [System.Windows.LogicalTreeHelper]::GetParent($cur) }
    }
    return $null
}

# ---------------- Event wiring ----------------

$ui.BtnOpen.Add_Click({ Open-XmlFile })
$ui.BtnEmptyOpen.Add_Click({ Open-XmlFile })
$ui.BtnEmptyLive.Add_Click({ Invoke-LocalCapture 'System' })
$ui.BtnExportHtml.Add_Click({ Export-Html })
$ui.BtnExportCsv.Add_Click({ Export-FilteredEventCsv })
$ui.BtnExportJson.Add_Click({ Export-JsonGui })
$ui.BtnGoFindings.Add_Click({ $ui.MainTabs.SelectedItem = $ui.TabFindings })

$ui.CardHealth.Add_MouseLeftButtonUp({ $ui.MainTabs.SelectedItem = $ui.TabFindings })
$ui.CardTotal.Add_MouseLeftButtonUp({ $ui.MainTabs.SelectedItem = $ui.TabEvents; Reset-EventFilters })
$ui.CardCritical.Add_MouseLeftButtonUp({ Show-LevelFilter @('Critical') })
$ui.CardError.Add_MouseLeftButtonUp({ Show-LevelFilter @('Error') })
$ui.CardWarning.Add_MouseLeftButtonUp({ Show-LevelFilter @('Warning') })
$ui.CardAudit.Add_MouseLeftButtonUp({ Show-LevelFilter @('Audit Failure') })

$liveMenu = New-Object System.Windows.Controls.ContextMenu
foreach ($log in @('System', 'Application', 'Security', 'Setup', 'Microsoft-Windows-PowerShell/Operational')) {
    $mi = New-Object System.Windows.Controls.MenuItem
    $mi.Header = "$log log (newest $MaxEvents)"
    $mi.Tag = $log
    $mi.Add_Click({ param($s, $e) Invoke-LocalCapture ([string]$s.Tag) })
    [void]$liveMenu.Items.Add($mi)
}
$ui.BtnLive.ContextMenu = $liveMenu
$ui.BtnLive.Add_Click({
        $ui.BtnLive.ContextMenu.PlacementTarget = $ui.BtnLive
        $ui.BtnLive.ContextMenu.Placement = 'Bottom'
        $ui.BtnLive.ContextMenu.IsOpen = $true
    })

$showEventsHandler = [System.Windows.RoutedEventHandler] {
    param($sender, $e)
    $btn = Find-Ancestor $e.OriginalSource ([System.Windows.Controls.Button])
    if ($null -eq $btn -or $null -eq $btn.Tag) { return }
    $item = $btn.Tag
    $label = if ($item.PSObject.Properties['Title'] -and $item.Title) { $item.Title } else { "incident at $($item.Start) (trigger $($item.Trigger))" }
    Show-EventSubset $label @($item.EventIndexes)
}
$ui.FindingsList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, $showEventsHandler)
$ui.IncidentsList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, $showEventsHandler)

$ui.DashFindings.Add_PreviewMouseLeftButtonUp({
        param($s, $e)
        $ctx = Get-DataContextFromSource $e.OriginalSource
        if ($ctx -and $ctx.PSObject.Properties['EventIndexes']) {
            Show-EventSubset $ctx.Title @($ctx.EventIndexes)
            $e.Handled = $true
        }
    })

$ui.TimelineItems.Add_PreviewMouseLeftButtonUp({
        param($s, $e)
        $ctx = Get-DataContextFromSource $e.OriginalSource
        if ($ctx -and $ctx.PSObject.Properties['StartTime']) {
            $script:State.IndexFilter = $null
            $script:State.TimeLo = $ctx.StartTime
            $script:State.TimeHi = $ctx.EndTime
            Show-FilterBanner ("Time window: " + $ctx.Tip)
            $ui.MainTabs.SelectedItem = $ui.TabEvents
            Update-EventFilter
            $e.Handled = $true
        }
    })

$script:FilterTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:FilterTimer.Interval = [timespan]::FromMilliseconds(250)
$script:FilterTimer.Add_Tick({ $script:FilterTimer.Stop(); Update-EventFilter })
$queueFilter = { $script:FilterTimer.Stop(); $script:FilterTimer.Start() }

$ui.TxtSearch.Add_TextChanged({
        $ui.TxtSearchHint.Visibility = $(if ($ui.TxtSearch.Text) { 'Collapsed' } else { 'Visible' })
        & $queueFilter
    })
$ui.TxtEventId.Add_TextChanged({
        $ui.TxtEventIdHint.Visibility = $(if ($ui.TxtEventId.Text) { 'Collapsed' } else { 'Visible' })
        & $queueFilter
    })
$ui.CmbProvider.Add_SelectionChanged({ & $queueFilter })
$ui.CmbComputer.Add_SelectionChanged({ & $queueFilter })
foreach ($c in $script:LevelChecks.Values) {
    $ui[$c].Add_Checked({ & $queueFilter })
    $ui[$c].Add_Unchecked({ & $queueFilter })
}
$ui.BtnClearFilters.Add_Click({ Reset-EventFilters })
$ui.BtnClearBanner.Add_Click({
        $script:State.IndexFilter = $null
        $script:State.TimeLo = $null
        $script:State.TimeHi = $null
        $ui.FilterBanner.Visibility = 'Collapsed'
        Update-EventFilter
    })

$ui.EventsGrid.Add_SelectionChanged({
        try { Show-EventDetail $ui.EventsGrid.SelectedItem }
        catch { Set-Status "Could not display event: $($_.Exception.Message)" }
    })
$ui.DRelated.Add_MouseDoubleClick({
        $ev = $ui.DRelated.SelectedItem
        if ($ev) { Select-EventInGrid $ev }
    })
$ui.DRelated.ToolTip = 'Double-click to jump to this event'
$ui.BtnCopyXml.Add_Click({
        if ($ui.DRawXml.Text) {
            try { [System.Windows.Clipboard]::SetText($ui.DRawXml.Text); Set-Status 'Raw XML copied to clipboard' }
            catch { Show-Error 'Clipboard' $_.Exception.Message }
        }
    })

$script:Window.Add_DragOver({
        param($s, $e)
        if ($e.Data.GetDataPresent([System.Windows.DataFormats]::FileDrop)) {
            $e.Effects = [System.Windows.DragDropEffects]::Copy
            $ui.DropZoneBorder.Stroke = (New-Object System.Windows.Media.BrushConverter).ConvertFromString('#38BDF8')
        }
        else { $e.Effects = [System.Windows.DragDropEffects]::None }
        $e.Handled = $true
    })
$script:Window.Add_DragLeave({ $ui.DropZoneBorder.Stroke = (New-Object System.Windows.Media.BrushConverter).ConvertFromString('#334155') })
$script:Window.Add_Drop({
        param($s, $e)
        $ui.DropZoneBorder.Stroke = (New-Object System.Windows.Media.BrushConverter).ConvertFromString('#334155')
        $files = @($e.Data.GetData([System.Windows.DataFormats]::FileDrop))
        if ($files.Count -gt 0) { Import-AndAnalyze $files }
    })

$script:Window.Add_PreviewKeyDown({
        param($s, $e)
        $ctrl = ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control) -ne 0
        if ($ctrl -and $e.Key -eq 'O') { Open-XmlFile; $e.Handled = $true }
        elseif ($ctrl -and $e.Key -eq 'F' -and $script:State.Analysis) {
            $ui.MainTabs.SelectedItem = $ui.TabEvents
            $ui.TxtSearch.Focus() | Out-Null
            $e.Handled = $true
        }
        elseif ($ctrl -and $e.Key -eq 'S' -and $script:State.Analysis) { Export-Html; $e.Handled = $true }
        elseif ($e.Key -eq 'Escape' -and $ui.MainTabs.SelectedItem -eq $ui.TabEvents) { Reset-EventFilters; $e.Handled = $true }
    })

$script:Window.Add_Closed({
        try { if ($script:FilterTimer) { $script:FilterTimer.Stop() } } catch { }
    })

$ui.TxtStatusRight.Text = "v$script:AppVersion  |  Correlation window: $CorrelationMinutes min  |  Ctrl+O open  -  Ctrl+F search  -  Ctrl+S HTML  -  Esc reset filters"

$script:Window.Add_ContentRendered({
        if ($Path) {
            $missing = @($Path | Where-Object { -not (Test-Path -LiteralPath $_) })
            $ok = @($Path | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object { (Resolve-Path -LiteralPath $_).Path })
            if ($missing.Count) { Show-Error 'File not found' ("The file(s) do not exist:`n" + ($missing -join "`n")) }
            if ($ok.Count) { Import-AndAnalyze $ok }
        }
    })

[void]$script:Window.ShowDialog()

#endregion

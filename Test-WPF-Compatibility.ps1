#Requires -Version 5.1
<#
.SYNOPSIS
    Tests WPF compatibility and provides diagnostics for GUI issues.

.DESCRIPTION
    Checks if WPF assemblies can be loaded and provides detailed error information
    if the GUI cannot start on Windows Server or other environments.
#>

Write-Host "Testing WPF Compatibility..." -ForegroundColor Cyan
Write-Host ""

# System Info
Write-Host "System Information:" -ForegroundColor Yellow
Write-Host "  OS: $(([System.Environment]::OSVersion).VersionString)"
Write-Host "  PowerShell: $($PSVersionTable.PSVersion)"
Write-Host "  .NET Framework: $([System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription)"
Write-Host ""

# Test 1: Check if running as admin
Write-Host "Test 1: Administrator Check" -ForegroundColor Yellow
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "  ✓ Running as Administrator" -ForegroundColor Green
} else {
    Write-Host "  ⚠ NOT running as Administrator (may cause issues)" -ForegroundColor Yellow
}
Write-Host ""

# Test 2: Try to load WPF assemblies
Write-Host "Test 2: WPF Assembly Loading" -ForegroundColor Yellow

$assemblies = @(
    'PresentationFramework',
    'PresentationCore',
    'WindowsBase',
    'System.Xaml'
)

$allLoaded = $true
foreach ($assembly in $assemblies) {
    try {
        Add-Type -AssemblyName $assembly -ErrorAction Stop
        Write-Host "  ✓ $assembly loaded successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "  ✗ $assembly FAILED to load: $($_.Exception.Message)" -ForegroundColor Red
        $allLoaded = $false
    }
}
Write-Host ""

# Test 3: Check Desktop Experience feature (Server OS)
Write-Host "Test 3: Desktop Experience Check (Server OS)" -ForegroundColor Yellow
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
if ($osInfo.Caption -like "*Server*") {
    Write-Host "  Detected: $($osInfo.Caption)" -ForegroundColor Cyan
    
    try {
        $desktopExp = Get-WindowsFeature -Name "Desktop-Experience" -ErrorAction SilentlyContinue
        if ($desktopExp) {
            if ($desktopExp.Installed) {
                Write-Host "  ✓ Desktop Experience is installed" -ForegroundColor Green
            } else {
                Write-Host "  ⚠ Desktop Experience is NOT installed" -ForegroundColor Yellow
                Write-Host "    This may prevent GUI from working on Server Core" -ForegroundColor Yellow
            }
        } else {
            # Server 2016+ doesn't have Desktop Experience feature
            $serverGui = Get-WindowsFeature -Name "Server-Gui-Shell" -ErrorAction SilentlyContinue
            if ($serverGui -and $serverGui.Installed) {
                Write-Host "  ✓ Server GUI Shell is installed" -ForegroundColor Green
            } else {
                Write-Host "  ⚠ Server might be running Core (no GUI)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "  ⚠ Could not check Desktop Experience: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Detected: Desktop OS ($($osInfo.Caption))" -ForegroundColor Green
}
Write-Host ""

# Test 4: Try to create a simple WPF window
Write-Host "Test 4: WPF Window Creation Test" -ForegroundColor Yellow
if ($allLoaded) {
    try {
        [xml]$testXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="WPF Test" Height="100" Width="200">
    <TextBlock Text="Test" HorizontalAlignment="Center" VerticalAlignment="Center"/>
</Window>
"@
        $reader = New-Object System.Xml.XmlNodeReader $testXaml
        $testWindow = [Windows.Markup.XamlReader]::Load($reader)
        
        Write-Host "  ✓ WPF Window created successfully!" -ForegroundColor Green
        Write-Host "  Testing ShowDialog (this will briefly show a window)..." -ForegroundColor Cyan
        
        # Show for 2 seconds then close
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromSeconds(2)
        $timer.Add_Tick({
            $testWindow.Close()
            $timer.Stop()
        })
        $timer.Start()
        
        $testWindow.ShowDialog() | Out-Null
        Write-Host "  ✓ WPF Window displayed and closed successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "  ✗ WPF Window creation FAILED!" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Stack: $($_.Exception.StackTrace)" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  ⊘ Skipped (assemblies not loaded)" -ForegroundColor DarkGray
}
Write-Host ""

# Summary and recommendations
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "SUMMARY AND RECOMMENDATIONS" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if ($allLoaded -and $osInfo.Caption -notlike "*Server*") {
    Write-Host "✓ System appears compatible with WPF GUI" -ForegroundColor Green
    Write-Host ""
    Write-Host "You should be able to run:" -ForegroundColor Cyan
    Write-Host "  .\GPO-DriveMap-Validator-GUI.ps1" -ForegroundColor White
}
elseif ($allLoaded -and $osInfo.Caption -like "*Server*") {
    Write-Host "⚠ Running on Windows Server" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "The GUI may work if:" -ForegroundColor Yellow
    Write-Host "  • Server has Desktop Experience / GUI Shell installed" -ForegroundColor Yellow
    Write-Host "  • You're connected via RDP with GUI forwarding" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "RECOMMENDED: Use the CLI version instead:" -ForegroundColor Cyan
    Write-Host "  .\Test-GpoDriveMapTargeting.ps1 -GpoName `"Your GPO`" -TargetUsers alice,bob" -ForegroundColor White
    Write-Host ""
    Write-Host "Or use the interactive CLI launcher:" -ForegroundColor Cyan
    Write-Host "  .\Start-GPOValidator.ps1" -ForegroundColor White
}
else {
    Write-Host "✗ WPF assemblies could not be loaded" -ForegroundColor Red
    Write-Host ""
    Write-Host "This system cannot run the GUI. Use CLI version:" -ForegroundColor Red
    Write-Host "  .\Test-GpoDriveMapTargeting.ps1 -GpoName `"Your GPO`" -TargetUsers alice,bob" -ForegroundColor White
}

Write-Host ""
Write-Host "For detailed CLI examples, see:" -ForegroundColor Cyan
Write-Host "  EXAMPLES.md" -ForegroundColor White
Write-Host ""

#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnose why web GUI won't work
#>

Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Web GUI Diagnostics" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Test 1: PowerShell Version
Write-Host "1. PowerShell Version Check:" -ForegroundColor Yellow
Write-Host "   Version: $($PSVersionTable.PSVersion)" -ForegroundColor White
if ($PSVersionTable.PSVersion.Major -ge 5) {
    Write-Host "   ✓ OK" -ForegroundColor Green
} else {
    Write-Host "   ✗ Need 5.1+" -ForegroundColor Red
}
Write-Host ""

# Test 2: Can we create HTTP listener?
Write-Host "2. HTTP Listener Test:" -ForegroundColor Yellow
try {
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:8888/")
    $listener.Start()
    Write-Host "   ✓ Can create HTTP listener" -ForegroundColor Green
    $listener.Stop()
    $listener.Close()
} catch {
    Write-Host "   ✗ Cannot create HTTP listener" -ForegroundColor Red
    Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Test 3: Backend script exists?
Write-Host "3. Backend Script Check:" -ForegroundColor Yellow
$backend = Join-Path $PSScriptRoot "Test-GpoDriveMapTargeting.ps1"
if (Test-Path $backend) {
    Write-Host "   ✓ Found: $backend" -ForegroundColor Green
} else {
    Write-Host "   ✗ Not found: $backend" -ForegroundColor Red
}
Write-Host ""

# Test 4: Can we start a browser?
Write-Host "4. Browser Test:" -ForegroundColor Yellow
try {
    $ie = New-Object -ComObject InternetExplorer.Application
    $ie.Quit()
    Write-Host "   ✓ Can access browser COM object" -ForegroundColor Green
} catch {
    Write-Host "   ⚠ COM object failed, but Start-Process may still work" -ForegroundColor Yellow
}
Write-Host ""

# Test 5: Firewall/Admin
Write-Host "5. Permission Check:" -ForegroundColor Yellow
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "   ✓ Running as Administrator" -ForegroundColor Green
} else {
    Write-Host "   ⚠ Not running as Administrator" -ForegroundColor Yellow
    Write-Host "   HTTP listener may require admin rights" -ForegroundColor Yellow
}
Write-Host ""

# Test 6: Try minimal HTTP server
Write-Host "6. Minimal HTTP Server Test:" -ForegroundColor Yellow
Write-Host "   Starting test server on http://localhost:8889..." -ForegroundColor White

try {
    $http = [System.Net.HttpListener]::new()
    $http.Prefixes.Add("http://localhost:8889/")
    $http.Start()
    
    Write-Host "   ✓ Server started!" -ForegroundColor Green
    Write-Host "   Opening browser..." -ForegroundColor White
    
    Start-Process "http://localhost:8889/"
    Start-Sleep -Seconds 2
    
    Write-Host "   Waiting for request (10 seconds)..." -ForegroundColor White
    $task = $http.GetContextAsync()
    $timeout = [System.Threading.Tasks.Task]::WaitAny(@($task), 10000)
    
    if ($timeout -eq 0) {
        Write-Host "   ✓ Browser connected successfully!" -ForegroundColor Green
        $context = $task.Result
        $response = $context.Response
        $html = "<html><body><h1>Success!</h1><p>Web server is working.</p></body></html>"
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.Close()
    } else {
        Write-Host "   ⚠ No browser connection received" -ForegroundColor Yellow
        Write-Host "   Browser may not have opened or connected" -ForegroundColor Yellow
    }
    
    $http.Stop()
    $http.Close()
} catch {
    Write-Host "   ✗ Test failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Summary
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host ""
Write-Host "If all tests passed, the web GUI should work." -ForegroundColor White
Write-Host "If any tests failed, try the CLI version instead:" -ForegroundColor White
Write-Host ""
Write-Host "  .\Start-GPOValidator-CLI.ps1" -ForegroundColor Yellow
Write-Host ""
Write-Host "Or direct command:" -ForegroundColor White
Write-Host "  .\Test-GpoDriveMapTargeting.ps1 -GpoName `"...`" -TargetUsers alice" -ForegroundColor Yellow
Write-Host ""

Read-Host "Press Enter to exit"

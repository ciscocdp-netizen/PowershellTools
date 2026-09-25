#Requires -Version 5.1
<#
.SYNOPSIS
    Web-based GUI for GPO Drive Mapping Validator (Server-compatible)

.DESCRIPTION
    Launches a web server with an HTML/JavaScript interface that works on
    ANY Windows version, including Server Core. Access via browser.

.NOTES
    This works where WPF GUI cannot:
    - Windows Server Core
    - Remote PowerShell sessions
    - Any machine with a web browser
#>

$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  GPO Drive Mapping Validator - Web Interface" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Configuration
$Port = 8080
$BackendScript = Join-Path $PSScriptRoot "Test-GpoDriveMapTargeting.ps1"

# Check if backend exists
if (-not (Test-Path $BackendScript)) {
    Write-Host "✗ Backend script not found: $BackendScript" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✓ Backend script found" -ForegroundColor Green
Write-Host ""

# Find available port
$PortFound = $false
$PortAttempts = 0
$OriginalPort = $Port

while (-not $PortFound -and $PortAttempts -lt 10) {
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        $listener.Stop()
        $PortFound = $true
        Write-Host "✓ Port $Port is available" -ForegroundColor Green
    }
    catch {
        Write-Host "⚠ Port $Port in use, trying $($Port + 1)..." -ForegroundColor Yellow
        $Port++
        $PortAttempts++
    }
}

if (-not $PortFound) {
    Write-Host "✗ Could not find available port" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$Url = "http://localhost:$Port/"

Write-Host ""
Write-Host "Starting web server on $Url" -ForegroundColor Cyan
Write-Host ""
Write-Host "The web interface will open automatically in your default browser." -ForegroundColor White
Write-Host "If it doesn't open, manually navigate to: $Url" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C to stop the server when done." -ForegroundColor Yellow
Write-Host ""

# HTML Interface
$Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GPO Drive Mapping Validator</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #0078D4 0%, #106EBE 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 32px;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .content {
            padding: 30px;
        }
        
        .form-section {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
        }
        
        .form-section h2 {
            color: #333;
            margin-bottom: 20px;
            font-size: 20px;
            border-bottom: 2px solid #0078D4;
            padding-bottom: 10px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 600;
            font-size: 14px;
        }
        
        .form-group input[type="text"],
        .form-group textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            font-family: 'Segoe UI', sans-serif;
            transition: border-color 0.3s;
        }
        
        .form-group input[type="text"]:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #0078D4;
        }
        
        .form-group textarea {
            resize: vertical;
            min-height: 80px;
        }
        
        .form-group small {
            display: block;
            margin-top: 5px;
            color: #777;
            font-size: 12px;
        }
        
        .radio-group {
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
        }
        
        .radio-group label {
            display: flex;
            align-items: center;
            cursor: pointer;
            font-weight: normal;
        }
        
        .radio-group input[type="radio"] {
            margin-right: 8px;
            cursor: pointer;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            margin: 15px 0;
        }
        
        .checkbox-group input[type="checkbox"] {
            margin-right: 10px;
            cursor: pointer;
            width: 18px;
            height: 18px;
        }
        
        .checkbox-group label {
            cursor: pointer;
            margin: 0;
            font-weight: normal;
        }
        
        .button-group {
            display: flex;
            gap: 15px;
            justify-content: center;
            margin-top: 30px;
        }
        
        button {
            padding: 14px 32px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #0078D4 0%, #106EBE 100%);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0, 120, 212, 0.3);
        }
        
        .btn-primary:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
        }
        
        .btn-secondary {
            background: #6c757d;
            color: white;
        }
        
        .btn-secondary:hover {
            background: #5a6268;
        }
        
        #results {
            margin-top: 30px;
            display: none;
        }
        
        .result-section {
            background: white;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .result-section h3 {
            color: #0078D4;
            margin-bottom: 15px;
            font-size: 18px;
        }
        
        pre {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.6;
            max-height: 600px;
            overflow-y: auto;
        }
        
        .status-bar {
            background: #f0f0f0;
            padding: 15px 30px;
            border-top: 1px solid #ddd;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .status-message {
            color: #666;
            font-size: 14px;
        }
        
        .loader {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #0078D4;
            border-radius: 50%;
            width: 24px;
            height: 24px;
            animation: spin 1s linear infinite;
            display: none;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .alert {
            padding: 15px 20px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        
        .alert-info {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
        }
        
        .alert-success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .alert-warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
        }
        
        .alert-error {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .hidden {
            display: none !important;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .summary-card h4 {
            font-size: 14px;
            opacity: 0.9;
            margin-bottom: 10px;
        }
        
        .summary-card .value {
            font-size: 32px;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🗂️ GPO Drive Mapping Validator</h1>
            <p>Web Interface - Works on ALL Windows Versions including Server Core</p>
        </div>
        
        <div class="content">
            <div class="alert alert-info">
                <strong>ℹ️ Server-Friendly:</strong> This web interface works perfectly on Windows Server 2022, Server Core, and any environment where the WPF GUI cannot run.
            </div>
            
            <!-- Configuration Form -->
            <div class="form-section">
                <h2>📋 Configuration</h2>
                
                <div class="form-group">
                    <label for="domain">Domain (FQDN)</label>
                    <input type="text" id="domain" placeholder="corp.contoso.com">
                    <small>Leave blank to auto-detect</small>
                </div>
                
                <div class="form-group">
                    <label for="gpoName">GPO Name</label>
                    <input type="text" id="gpoName" placeholder="Mapped Drives - Finance" required>
                </div>
            </div>
            
            <!-- Test Subjects -->
            <div class="form-section">
                <h2>👥 Test Subjects</h2>
                
                <div class="radio-group">
                    <label>
                        <input type="radio" name="targetType" value="users" checked>
                        Specific Users
                    </label>
                    <label>
                        <input type="radio" name="targetType" value="ou">
                        Entire OU
                    </label>
                </div>
                
                <div class="form-group" id="usersGroup">
                    <label for="targetUsers">Target Users (comma-separated)</label>
                    <input type="text" id="targetUsers" placeholder="alice, bob, charlie">
                    <small>Enter sAMAccountNames separated by commas</small>
                </div>
                
                <div class="form-group hidden" id="ouGroup">
                    <label for="targetOU">Target OU (Distinguished Name)</label>
                    <input type="text" id="targetOU" placeholder="OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com">
                    <small>Enter the full Distinguished Name of the OU</small>
                </div>
            </div>
            
            <!-- Options -->
            <div class="form-section">
                <h2>⚙️ Options</h2>
                
                <div class="checkbox-group">
                    <input type="checkbox" id="showTrace">
                    <label for="showTrace">Show detailed filter evaluation trace (verbose)</label>
                </div>
            </div>
            
            <!-- Actions -->
            <div class="button-group">
                <button class="btn-primary" id="btnValidate">▶️ Run Validation</button>
                <button class="btn-secondary" id="btnClear">🗑️ Clear Results</button>
            </div>
            
            <!-- Results -->
            <div id="results" class="hidden">
                <div class="form-section">
                    <h2>📊 Results</h2>
                    <div id="resultContent"></div>
                </div>
            </div>
        </div>
        
        <div class="status-bar">
            <div class="status-message" id="statusMessage">Ready</div>
            <div class="loader" id="loader"></div>
        </div>
    </div>
    
    <script>
        // Handle radio button change
        document.querySelectorAll('input[name="targetType"]').forEach(radio => {
            radio.addEventListener('change', function() {
                if (this.value === 'users') {
                    document.getElementById('usersGroup').classList.remove('hidden');
                    document.getElementById('ouGroup').classList.add('hidden');
                } else {
                    document.getElementById('usersGroup').classList.add('hidden');
                    document.getElementById('ouGroup').classList.remove('hidden');
                }
            });
        });
        
        // Validate button
        document.getElementById('btnValidate').addEventListener('click', async function() {
            const domain = document.getElementById('domain').value.trim();
            const gpoName = document.getElementById('gpoName').value.trim();
            const targetType = document.querySelector('input[name="targetType"]:checked').value;
            const targetUsers = document.getElementById('targetUsers').value.trim();
            const targetOU = document.getElementById('targetOU').value.trim();
            const showTrace = document.getElementById('showTrace').checked;
            
            // Validation
            if (!gpoName) {
                alert('Please enter a GPO name');
                return;
            }
            
            if (targetType === 'users' && !targetUsers) {
                alert('Please enter at least one user');
                return;
            }
            
            if (targetType === 'ou' && !targetOU) {
                alert('Please enter an OU Distinguished Name');
                return;
            }
            
            // Build query string
            const params = new URLSearchParams();
            if (domain) params.append('domain', domain);
            params.append('gpoName', gpoName);
            if (targetType === 'users') {
                params.append('targetUsers', targetUsers);
            } else {
                params.append('targetOU', targetOU);
            }
            params.append('showTrace', showTrace);
            
            // Show loading
            document.getElementById('statusMessage').textContent = 'Running validation...';
            document.getElementById('loader').style.display = 'block';
            document.getElementById('btnValidate').disabled = true;
            document.getElementById('results').classList.add('hidden');
            
            try {
                const response = await fetch('/validate?' + params.toString());
                const data = await response.json();
                
                if (data.success) {
                    displayResults(data);
                    document.getElementById('statusMessage').textContent = 'Validation complete ✓';
                } else {
                    displayError(data.error);
                    document.getElementById('statusMessage').textContent = 'Validation failed ✗';
                }
            } catch (error) {
                displayError(error.message);
                document.getElementById('statusMessage').textContent = 'Error occurred ✗';
            } finally {
                document.getElementById('loader').style.display = 'none';
                document.getElementById('btnValidate').disabled = false;
            }
        });
        
        // Clear button
        document.getElementById('btnClear').addEventListener('click', function() {
            document.getElementById('results').classList.add('hidden');
            document.getElementById('statusMessage').textContent = 'Ready';
        });
        
        function displayResults(data) {
            const resultDiv = document.getElementById('resultContent');
            resultDiv.innerHTML = '';
            
            // Summary cards
            const summaryHtml = '<div class="summary-cards">' +
                '<div class="summary-card"><h4>Users Tested</h4><div class="value">' + (data.userCount || 0) + '</div></div>' +
                '<div class="summary-card"><h4>Drives Evaluated</h4><div class="value">' + (data.driveCount || 0) + '</div></div>' +
                '<div class="summary-card"><h4>Conflicts</h4><div class="value">' + (data.conflictCount || 0) + '</div></div>' +
                '</div>';
            resultDiv.innerHTML += summaryHtml;
            
            // Output
            if (data.output) {
                resultDiv.innerHTML += '<div class="result-section"><h3>📄 Validation Output</h3><pre>' + 
                    escapeHtml(data.output) + '</pre></div>';
            }
            
            // Show results section
            document.getElementById('results').classList.remove('hidden');
            
            // Scroll to results
            document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
        }
        
        function displayError(error) {
            const resultDiv = document.getElementById('resultContent');
            resultDiv.innerHTML = '<div class="alert alert-error"><strong>Error:</strong> ' + 
                escapeHtml(error) + '</div>';
            document.getElementById('results').classList.remove('hidden');
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
"@

# Create HTTP listener
$HttpListener = New-Object System.Net.HttpListener
$HttpListener.Prefixes.Add($Url)
$HttpListener.Start()

# Open browser
Start-Sleep -Seconds 1
Start-Process $Url

Write-Host "✓ Web server started successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Access the validator at: $Url" -ForegroundColor Cyan
Write-Host ""

# Main server loop
try {
    while ($HttpListener.IsListening) {
        $context = $HttpListener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $responseString = ""
        $statusCode = 200
        $contentType = "text/html"
        
        try {
            if ($request.Url.AbsolutePath -eq "/") {
                # Serve HTML
                $responseString = $Html
            }
            elseif ($request.Url.AbsolutePath -eq "/validate") {
                # Handle validation request
                $contentType = "application/json"
                
                $query = $request.Url.Query.TrimStart('?')
                $params = @{}
                foreach ($pair in $query.Split('&')) {
                    if ($pair) {
                        $kv = $pair.Split('=')
                        $params[[System.Web.HttpUtility]::UrlDecode($kv[0])] = [System.Web.HttpUtility]::UrlDecode($kv[1])
                    }
                }
                
                # Build backend command
                $backendParams = @{}
                $backendParams.GpoName = $params['gpoName']
                
                if ($params['domain']) {
                    $backendParams.Domain = $params['domain']
                }
                
                if ($params['targetUsers']) {
                    $users = $params['targetUsers'] -split ',' | ForEach-Object { $_.Trim() }
                    $backendParams.TargetUsers = $users
                }
                elseif ($params['targetOU']) {
                    $backendParams.TargetOU = $params['targetOU']
                }
                
                if ($params['showTrace'] -eq 'true') {
                    $backendParams.ShowFilterTrace = $true
                }
                
                # Execute validation
                try {
                    $output = & $BackendScript @backendParams 2>&1 | Out-String
                    
                    # Parse results
                    $userCount = if ($output -match 'Users Tested:\s+(\d+)') { $matches[1] } else { "?" }
                    $driveCount = if ($output -match 'Total Evaluations:\s+(\d+)') { $matches[1] } else { "?" }
                    $conflictCount = if ($output -match 'Conflicts:\s+(\d+)') { $matches[1] } else { 0 }
                    
                    $result = @{
                        success = $true
                        output = $output
                        userCount = $userCount
                        driveCount = $driveCount
                        conflictCount = $conflictCount
                    }
                    
                    $responseString = $result | ConvertTo-Json
                }
                catch {
                    $result = @{
                        success = $false
                        error = $_.Exception.Message
                    }
                    $responseString = $result | ConvertTo-Json
                }
            }
            else {
                $statusCode = 404
                $responseString = "Not Found"
            }
        }
        catch {
            $statusCode = 500
            $contentType = "application/json"
            $result = @{
                success = $false
                error = $_.Exception.Message
            }
            $responseString = $result | ConvertTo-Json
        }
        
        # Send response
        $response.StatusCode = $statusCode
        $response.ContentType = $contentType
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseString)
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.OutputStream.Close()
        
        # Log request
        $timestamp = Get-Date -Format "HH:mm:ss"
        Write-Host "[$timestamp] $($request.HttpMethod) $($request.Url.AbsolutePath) - $statusCode" -ForegroundColor Gray
    }
}
finally {
    $HttpListener.Stop()
    $HttpListener.Close()
    Write-Host ""
    Write-Host "Web server stopped." -ForegroundColor Yellow
}

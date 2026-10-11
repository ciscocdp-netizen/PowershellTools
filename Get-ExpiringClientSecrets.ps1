#Requires -Version 5.1
<#
================================================================================
 SCRIPT : Get-ExpiringClientSecrets.ps1
 PURPOSE: Scan Microsoft Entra ID App Registrations for expiring CLIENT SECRETS
          only (SAML / OIDC signing certificates are intentionally excluded),
          resolve application owners, export workbooks, and email an elaborate
          HTML report branded with the Owens & Minor logo.
 AUTHOR : Anthony Blake
 UPDATED: 2026-10-11
 COMPAT : Windows PowerShell 5.1 (Graph REST API, manual pagination)
================================================================================

.SYNOPSIS
    Scans Entra ID App Registrations for expiring client secrets and emails a branded report.

.DESCRIPTION
    Designed to run as a Windows Scheduled Task.

    This version ONLY evaluates password credentials (client secrets) on
    Application objects. It does NOT scan servicePrincipal keyCredentials, so
    SAML verification certificates and OIDC signing certificates are ignored.

    The HTML email prefers Get-ExpiringClientSecrets.EmailTemplate.html and
    assets\owens-minor-logo.png when those files sit next to the script. If they
    are missing (for example the .ps1 was copied alone into a home folder), the
    same branded template and Owens & Minor logo are loaded from built-in
    copies so the email still sends. The logo is attached as cid:om-logo.

    Credentials are resolved in this order:
        1. -TenantId / -ClientId / -ClientSecret parameters
        2. ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_CLIENT_SECRET environment variables
        3. Values in the CONFIGURATION region below

    Exit Codes:
        0 = Success (report generated; email sent unless -SkipEmail)
        1 = Authentication / configuration failure
        2 = Graph API query failure
        3 = Report export failure (Excel/CSV)
        4 = Email send failure
        5 = General/unexpected error

.PARAMETER RenderSampleEmail
    Skip Graph entirely and write a sample HTML preview (and optional dummy
    workbooks) so the branded message can be reviewed locally.

.PARAMETER SkipEmail
    Generate reports but do not send SMTP mail.

.PARAMETER WriteHtmlPreview
    Also write the generated HTML body next to the workbooks.

.NOTES
    Graph application permissions required:
        Application.Read.All
        Directory.Read.All   (for application owners)

    Ensure the service account running this has write access to the output directory.
    Do not commit a real client secret to the script; use environment variables
    or Task Scheduler secret storage.
#>

[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret,
    [int]$DaysThreshold = 35,
    [bool]$IncludeExpired = $true,
    [string]$OutputDir,
    [string]$SmtpServer,
    [string]$FromEmail,
    [string[]]$ToEmail,
    [string]$Subject = "Expiring Client Secrets Report",
    [string]$LogoPath,
    [string]$TemplatePath,
    [int]$PreviewRowCount = 12,
    [int]$ReportRetentionDays = 90,
    [switch]$SkipEmail,
    [switch]$WriteHtmlPreview,
    [switch]$RenderSampleEmail
)

#region ### 1. CONFIGURATION ###################################################

# --- Azure AD App Registration (used by THIS script to authenticate) ---
# Leave as hashes and inject real values via parameters or environment variables.
$DefaultTenantId     = "################################################"
$DefaultClientId     = "################################"
$DefaultClientSecret = "#################################"

# --- Output (use a consistent location accessible by the service account) ---
$DefaultOutputDir = "C:\Scripts\ExpiringSecretsReports"

# --- Email ---
$DefaultSmtpServer = "relay.owens-minor.com"
$DefaultFromEmail  = "EnterpriseAppAdmin@owens-minor.com"
$DefaultToEmail    = @("Anthony.Blake@Owens-minor.com")

# --- Brand ---
$BrandBurgundy = "#92232E"
$BrandNavy     = "#1B2A4A"

#endregion

#region ### 2. CORE HELPERS ####################################################

function Resolve-ConfigString {
    param(
        [string]$ParamValue,
        [string]$EnvironmentName,
        [string]$Fallback
    )
    if (-not [string]::IsNullOrWhiteSpace($ParamValue) -and $ParamValue -notmatch '^#+$') {
        return $ParamValue
    }
    $envValue = [Environment]::GetEnvironmentVariable($EnvironmentName)
    if (-not [string]::IsNullOrWhiteSpace($envValue)) {
        return $envValue
    }
    return $Fallback
}

function Test-PlaceholderSecret {
    param([string]$Value)
    return [string]::IsNullOrWhiteSpace($Value) -or ($Value -match '^[#]+$')
}

function Get-ScriptRootPath {
    param([string]$InvocationPath)
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { return $PSScriptRoot }
    if (-not [string]::IsNullOrWhiteSpace($InvocationPath)) { return (Split-Path -Parent $InvocationPath) }
    return (Get-Location).Path
}

function ConvertTo-UtcDateTime {
    param($Value)
    if ($null -eq $Value -or $Value -eq "") { return $null }
    if ($Value -is [datetime]) {
        $dt = [datetime]$Value
        if ($dt.Kind -eq [DateTimeKind]::Utc) { return $dt }
        if ($dt.Kind -eq [DateTimeKind]::Local) { return $dt.ToUniversalTime() }
        return [datetime]::SpecifyKind($dt, [DateTimeKind]::Utc)
    }
    $parsed = [datetime]::Parse(
        $Value.ToString(),
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind
    )
    if ($parsed.Kind -eq [DateTimeKind]::Local) { return $parsed.ToUniversalTime() }
    if ($parsed.Kind -eq [DateTimeKind]::Unspecified) {
        return [datetime]::SpecifyKind($parsed, [DateTimeKind]::Utc)
    }
    return $parsed
}

function ConvertTo-HtmlSafe {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Get-SecretSeverity {
    param([int]$DaysRemaining)
    if ($DaysRemaining -lt 0) { return "Critical" }
    if ($DaysRemaining -le 7) { return "Urgent" }
    if ($DaysRemaining -le 14) { return "Warning" }
    return "Watch"
}

function Get-LocalTimeZoneLabel {
    param([datetime]$At)
    try {
        $tz = [System.TimeZoneInfo]::Local
        if ($tz.IsDaylightSavingTime($At)) {
            $label = $tz.DaylightName
        } else {
            $label = $tz.StandardName
        }
        $utcOffset  = $tz.GetUtcOffset($At)
        $offsetSign = if ($utcOffset.Ticks -lt 0) { "-" } else { "+" }
        return "{0} (UTC{1}{2:hh\:mm})" -f $label, $offsetSign, $utcOffset.Duration()
    } catch {
        return [System.TimeZoneInfo]::Local.StandardName
    }
}

function Get-EntraCredentialsUrl {
    param([string]$AppId)
    if ([string]::IsNullOrWhiteSpace($AppId)) { return "" }
    return "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/$AppId/isMSAApp~/false"
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG")][string]$Level = "INFO"
    )
    $timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    if ($Level -ne "DEBUG") {
        switch ($Level) {
            "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
            "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
            default   { Write-Host $logMessage }
        }
    }

    if ([string]::IsNullOrWhiteSpace($script:LogFile)) { return }
    try {
        Add-Content -Path $script:LogFile -Value $logMessage -ErrorAction Stop
    } catch {
        Write-Host "Failed to write to log file: $_" -ForegroundColor Red
    }
}

function Set-TemplateToken {
    param(
        [Parameter(Mandatory = $true)][string]$Template,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][string]$Value
    )
    if ($null -eq $Value) { $Value = "" }
    return $Template.Replace("{{" + $Name + "}}", $Value)
}

#endregion

#region ### 3. GRAPH HELPERS ###################################################

function Get-HttpStatusCode {
    param($ErrorRecord)
    try {
        $response = $ErrorRecord.Exception.Response
        if ($response -and $response.StatusCode) {
            return [int]$response.StatusCode
        }
    } catch {}
    return 0
}

function Get-GraphErrorDetail {
    param([Parameter(Mandatory = $true)]$ErrorRecord)
    try {
        $resp = $ErrorRecord.Exception.Response
        if ($resp -and $resp.GetResponseStream) {
            $stream = $resp.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                $body   = $reader.ReadToEnd()
                if ($body) { return $body }
            }
        }
    } catch {}
    return $ErrorRecord.Exception.Message
}

function Invoke-GraphRequestWithRetry {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][hashtable]$Headers,
        [string]$Method = "GET",
        [int]$MaxRetries = 5
    )
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method -ErrorAction Stop
        } catch {
            $status    = Get-HttpStatusCode -ErrorRecord $_
            $retryable = ($status -eq 429 -or $status -eq 503 -or $status -eq 504)
            if (-not $retryable -or $attempt -ge $MaxRetries) {
                $detail = Get-GraphErrorDetail -ErrorRecord $_
                throw "Graph $Method failed (HTTP $status): $detail`nURI: $Uri"
            }
            $delay = [int][math]::Min(60, [math]::Pow(2, $attempt))
            try {
                $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                if ($retryAfter) { $delay = [int]$retryAfter }
            } catch {}
            Write-Log "Graph returned HTTP $status — retry $attempt/$MaxRetries in $delay sec" -Level WARNING
            Start-Sleep -Seconds $delay
        }
    }
}

function Get-AllGraphItems {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][hashtable]$Headers
    )
    $results = New-Object System.Collections.ArrayList
    do {
        $response = Invoke-GraphRequestWithRetry -Uri $Uri -Headers $Headers -Method GET
        if ($response.value) {
            foreach ($item in @($response.value)) {
                [void]$results.Add($item)
            }
        }
        $Uri = $response."@odata.nextLink"
    } while ($Uri)
    return ,$results.ToArray()
}

#endregion

#region ### 4. OWNER RESOLUTION ################################################

$script:OwnerCache = @{}

function Get-ApplicationOwners {
    param(
        [Parameter(Mandatory = $true)][string]$AppObjectId,
        [Parameter(Mandatory = $true)][hashtable]$Headers
    )

    if ($script:OwnerCache.ContainsKey($AppObjectId)) {
        return $script:OwnerCache[$AppObjectId]
    }

    $ownersUri = "https://graph.microsoft.com/v1.0/applications/$AppObjectId/owners?`$select=displayName,mail,userPrincipalName"
    try {
        $rawOwners = Get-AllGraphItems -Uri $ownersUri -Headers $Headers
        $owners = @(
            $rawOwners | ForEach-Object {
                $name  = $_.displayName
                $email = if ([string]::IsNullOrWhiteSpace($_.mail)) { $_.userPrincipalName } else { $_.mail }
                if ($name -or $email) {
                    [PSCustomObject]@{ Name = $name; Email = $email }
                }
            }
        )
        $script:OwnerCache[$AppObjectId] = $owners
        return $owners
    } catch {
        Write-Log "Owner lookup failed for application $($AppObjectId): $($_.Exception.Message)" -Level WARNING
        $script:OwnerCache[$AppObjectId] = @()
        return @()
    }
}

#endregion

#region ### 5. EXCEL / CSV EXPORT ##############################################

$script:ExcelAvailable = $false

function Initialize-ExcelModule {
    try {
        if (Get-Module -ListAvailable -Name ImportExcel) {
            Import-Module ImportExcel -ErrorAction Stop
            $script:ExcelAvailable = $true
            Write-Log "ImportExcel module loaded - reports will be generated as .xlsx" -Level INFO
        } else {
            Write-Log "ImportExcel module not found - falling back to .csv output. (Install with: Install-Module ImportExcel -Scope AllUsers)" -Level WARNING
        }
    } catch {
        Write-Log "Failed to load ImportExcel module: $($_.Exception.Message). Falling back to .csv output." -Level WARNING
        $script:ExcelAvailable = $false
    }
}

function Export-SecretReport {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Items,
        [Parameter(Mandatory = $true)][string]$XlsxPath,
        [Parameter(Mandatory = $true)][string]$CsvPath,
        [Parameter(Mandatory = $true)][string]$WorksheetName
    )

    $rows = @($Items)
    if ($script:ExcelAvailable) {
        try {
            $tableName = ($WorksheetName -replace "[^A-Za-z0-9]", "")
            if ([string]::IsNullOrWhiteSpace($tableName)) { $tableName = "Secrets" }
            $rows | Export-Excel -Path $XlsxPath `
                -WorksheetName $WorksheetName `
                -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter `
                -TableName $tableName `
                -TableStyle "Medium2" `
                -ErrorAction Stop
            return $XlsxPath
        } catch {
            Write-Log "Export-Excel failed, falling back to CSV: $($_.Exception.Message)" -Level WARNING
        }
    }

    $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Force -ErrorAction Stop
    return $CsvPath
}

function Remove-OldReports {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [int]$RetentionDays
    )
    if ($RetentionDays -le 0) { return }
    if (-not (Test-Path -LiteralPath $Directory)) { return }
    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    $stale = @(
        Get-ChildItem -LiteralPath $Directory -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.LastWriteTime -lt $cutoff -and
                $_.Name -match "^(ClientSecrets_|ExpiringClientSecrets_)"
            }
    )
    foreach ($file in $stale) {
        try {
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            Write-Log "Removed stale report: $($file.Name)" -Level INFO
        } catch {
            Write-Log "Could not remove stale report $($file.Name): $($_.Exception.Message)" -Level WARNING
        }
    }
}

#endregion

#region ### 6. HTML EMAIL BUILDER ##############################################

function New-HtmlAlert {
    param(
        [string]$BorderColor,
        [string]$BackgroundColor,
        [string]$TextColor,
        [string]$HtmlMessage
    )
    return @"
                            <tr>
                                <td style="padding:8px 32px 4px 32px;">
                                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-left:4px solid $BorderColor;background-color:$BackgroundColor;border-radius:6px;">
                                        <tr><td style="padding:14px 16px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:14px;line-height:20px;color:$TextColor;">
                                            $HtmlMessage
                                        </td></tr>
                                    </table>
                                </td>
                            </tr>
"@
}

function New-HtmlPreviewTable {
    param(
        [AllowEmptyCollection()][object[]]$Items,
        [int]$MaxRows = 12
    )

    $rows = @($Items)
    if ($rows.Count -eq 0) {
        return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eee8e4;border-radius:8px;"><tr><td style="padding:16px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:13px;color:#6d6e71;">No client secrets are currently inside the reporting window.</td></tr></table>'
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eee8e4;border-collapse:collapse;">')
    [void]$sb.Append('<tr style="background-color:#1b2a4a;">')
    foreach ($header in @("Application", "Secret", "Expiry", "Days", "Severity", "Owners")) {
        [void]$sb.Append('<th align="left" style="padding:8px 7px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:11px;color:#ffffff;font-weight:700;">' + $header + '</th>')
    }
    [void]$sb.Append("</tr>")

    $shown = 0
    foreach ($row in $rows) {
        if ($shown -ge $MaxRows) { break }
        $shown++
        $bg = if ($shown % 2 -eq 0) { "#faf8f6" } else { "#ffffff" }

        switch ($row.Severity) {
            "Critical" { $sevColor = "#92232E"; $sevBg = "#fdecec" }
            "Urgent"   { $sevColor = "#c05621"; $sevBg = "#fff1e8" }
            "Warning"  { $sevColor = "#8a6d1b"; $sevBg = "#fff8e8" }
            default    { $sevColor = "#1b2a4a"; $sevBg = "#eef2f6" }
        }

        $nameSafe   = ConvertTo-HtmlSafe $row.Name
        $secretSafe = ConvertTo-HtmlSafe $(if ($row.SecretName) { $row.SecretName } else { "(unnamed)" })
        $hintSafe   = ConvertTo-HtmlSafe $row.SecretHint
        $secretCell = $secretSafe
        if ($hintSafe) { $secretCell = "$secretSafe<br /><span style=`"color:#6d6e71;font-size:10px;`">hint $hintSafe</span>" }

        $daysNum = 0
        [void][int]::TryParse([string]$row.DaysRemaining, [ref]$daysNum)
        if ($daysNum -lt 0) {
            $daysLabel = ("{0}d ago" -f [math]::Abs($daysNum))
            $daysColor = "#92232E"
        } else {
            $daysLabel = [string]$daysNum
            $daysColor = $sevColor
        }

        $ownerSafe = ConvertTo-HtmlSafe $row.OwnerNames
        if ([string]::IsNullOrWhiteSpace($ownerSafe)) {
            $ownerSafe = '<span style="color:#8a6d1b;font-weight:600;">Unassigned</span>'
        }

        $appCell = $nameSafe
        if ($row.PortalUrl) {
            $urlSafe = ConvertTo-HtmlSafe $row.PortalUrl
            $appCell = '<a href="' + $urlSafe + '" style="color:#1b2a4a;font-weight:600;text-decoration:underline;">' + $nameSafe + '</a>'
        }

        [void]$sb.Append('<tr style="background-color:' + $bg + ';">')
        [void]$sb.Append('<td style="padding:8px 7px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#2f3337;border-top:1px solid #eee8e4;">' + $appCell + '</td>')
        [void]$sb.Append('<td style="padding:8px 7px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#2f3337;border-top:1px solid #eee8e4;">' + $secretCell + '</td>')
        [void]$sb.Append('<td style="padding:8px 7px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#2f3337;border-top:1px solid #eee8e4;white-space:nowrap;">' + (ConvertTo-HtmlSafe $row.ExpiryDate) + '</td>')
        [void]$sb.Append('<td style="padding:8px 7px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;color:' + $daysColor + ';border-top:1px solid #eee8e4;white-space:nowrap;">' + $daysLabel + '</td>')
        [void]$sb.Append('<td style="padding:8px 7px;border-top:1px solid #eee8e4;"><span style="display:inline-block;padding:2px 8px;border-radius:10px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:11px;font-weight:700;color:' + $sevColor + ';background-color:' + $sevBg + ';">' + (ConvertTo-HtmlSafe $row.Severity) + '</span></td>')
        [void]$sb.Append('<td style="padding:8px 7px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#2f3337;border-top:1px solid #eee8e4;">' + $ownerSafe + '</td>')
        [void]$sb.Append("</tr>")
    }
    [void]$sb.Append("</table>")

    if ($rows.Count -gt $MaxRows) {
        [void]$sb.Append('<div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#6d6e71;padding-top:8px;">Showing ' + $MaxRows + " of " + $rows.Count + " reportable secrets. Remaining rows are in the attached workbooks.</div>")
    }

    return $sb.ToString()
}

function New-HtmlAttachmentList {
    param([string[]]$Paths, [hashtable]$Counts)
    $items = @($Paths | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($items.Count -eq 0) {
        return '<div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:13px;color:#6d6e71;">No workbook was attached (preview-only run).</div>'
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eee8e4;border-radius:8px;">')
    $i = 0
    foreach ($path in $items) {
        $i++
        $name  = [System.IO.Path]::GetFileName($path)
        $ext   = [System.IO.Path]::GetExtension($path).TrimStart(".").ToUpperInvariant()
        $label = "Workbook"
        if ($name -match "Expired") { $label = "Expired secrets" }
        elseif ($name -match "Expiring") { $label = "Expiring secrets" }
        $countText = ""
        if ($Counts -and $Counts.ContainsKey($path)) {
            $countText = " &nbsp;&bull;&nbsp; " + $Counts[$path] + " row(s)"
        }
        $border = if ($i -gt 1) { "border-top:1px solid #eee8e4;" } else { "" }
        [void]$sb.Append('<tr><td style="padding:10px 14px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:13px;color:#2f3337;' + $border + '"><strong>' + (ConvertTo-HtmlSafe $label) + "</strong> &mdash; " + (ConvertTo-HtmlSafe $name) + ' <span style="color:#6d6e71;">(' + $ext + $countText + ")</span></td></tr>")
    }
    [void]$sb.Append("</table>")
    return $sb.ToString()
}

function New-HtmlNextSteps {
    param(
        [int]$ExpiredCount,
        [int]$UnownedCount,
        [int]$UrgentCount,
        [int]$DaysThreshold
    )
    $steps = New-Object System.Collections.Generic.List[string]
    if ($ExpiredCount -gt 0) {
        [void]$steps.Add("<strong>Rotate expired secrets now.</strong> Applications with an expired client secret will fail client-credential flows. Create a new secret, update the consuming application, then delete the expired key.")
    }
    if ($UrgentCount -gt 0) {
        [void]$steps.Add("<strong>Treat 0–7 day expirations as a change window this week.</strong> Prefer overlapping secrets (add the new one first) so production traffic never sees a gap.")
    }
    [void]$steps.Add("<strong>Notify listed owners</strong> using the OwnerEmails column. Ask them to confirm the secret is still required and to complete rotation before the expiry date.")
    if ($UnownedCount -gt 0) {
        [void]$steps.Add("<strong>Assign owners on unowned app registrations</strong> in Entra admin center. Secrets with no owner are the most common cause of missed rotations.")
    }
    [void]$steps.Add("<strong>Plan the rest of the $DaysThreshold-day window</strong> from the Expiring workbook. Use PortalUrl to open Certificates &amp; secrets directly.")
    [void]$steps.Add("When rotation is complete, keep at least one valid secret and remove unused keys so the next scan stays accurate.")

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<ol style=`"margin:0;padding-left:20px;`">")
    foreach ($step in $steps) {
        [void]$sb.Append("<li style=`"padding-bottom:6px;`">$step</li>")
    }
    [void]$sb.Append("</ol>")
    return $sb.ToString()
}

function New-ExpirationReportHtml {
    param(
        [string]$TemplateFile,
        [string]$TemplateText,
        [Parameter(Mandatory = $true)][string]$LogoSrc,
        [datetime]$GeneratedAt,
        [string]$TimeZoneLabel,
        [int]$DaysThreshold,
        [bool]$IncludeExpired,
        [int]$AppsScanned,
        [int]$AppsWithSecrets,
        [int]$SecretsEvaluated,
        [int]$ExpiringCount,
        [int]$ExpiredCount,
        [int]$UnownedCount,
        [int]$SecretsWithOwners,
        [int]$SeverityExpired,
        [int]$SeverityUrgent,
        [int]$SeverityWarning,
        [int]$SeverityWatch,
        [object[]]$PreviewItems,
        [int]$PreviewRowCount,
        [string[]]$AttachmentPaths,
        [hashtable]$AttachmentCounts,
        [string]$ComputerName
    )

    if ([string]::IsNullOrWhiteSpace($TemplateText)) {
        if ($TemplateFile -and (Test-Path -LiteralPath $TemplateFile)) {
            $TemplateText = [System.IO.File]::ReadAllText($TemplateFile, [System.Text.Encoding]::UTF8)
        } else {
            Write-Log "Sidecar email template not found at '$TemplateFile'. Using the built-in template." -Level WARNING
            $TemplateText = Get-EmbeddedEmailTemplate
        }
    }

    $html = $TemplateText

    $headerColor = $BrandNavy
    $headerLabel = "INFORMATIONAL"
    if ($ExpiredCount -gt 0) {
        $headerColor = $BrandBurgundy
        $headerLabel = "ACTION REQUIRED"
    } elseif ($SeverityUrgent -gt 0) {
        $headerColor = "#c05621"
        $headerLabel = "ACTION THIS WEEK"
    }

    $alerts = New-Object System.Text.StringBuilder
    if ($ExpiredCount -gt 0) {
        [void]$alerts.Append((New-HtmlAlert -BorderColor $BrandBurgundy -BackgroundColor "#fdecec" -TextColor "#8a1a1a" -HtmlMessage ("<strong>Action needed:</strong> " + $ExpiredCount + " client secret(s) have already expired and should be rotated immediately. Details are in the attached <strong>Expired</strong> workbook.")))
    }
    if ($SeverityUrgent -gt 0) {
        [void]$alerts.Append((New-HtmlAlert -BorderColor "#c05621" -BackgroundColor "#fff1e8" -TextColor "#7a3b12" -HtmlMessage ("<strong>This week:</strong> " + $SeverityUrgent + " secret(s) expire within 7 days. Add a replacement secret before cutting over so the application does not lose access.")))
    }
    if ($UnownedCount -gt 0) {
        [void]$alerts.Append((New-HtmlAlert -BorderColor "#c5a035" -BackgroundColor "#fff8e8" -TextColor "#8a6d1b" -HtmlMessage ("<strong>Ownership gap:</strong> " + $UnownedCount + " reportable secret(s) have no application owner in Entra ID. Assign an owner so the next rotation is not missed.")))
    }

    $previewIntro = "The table below is sorted by urgency (oldest / soonest first). Application names link to the Certificates &amp; secrets blade in Entra admin center."
    if ((@($PreviewItems)).Count -eq 0) {
        $previewIntro = "No client secrets are inside the current reporting window. The attached Expiring workbook was still generated so the scheduled job has a consistent artifact."
    }

    $includeLabel = ""
    if ($IncludeExpired) { $includeLabel = ", including secrets that have already expired" }

    $generatedAtText = $GeneratedAt.ToString("dddd, MMMM d, yyyy 'at' h:mm tt")
    $preheader = if ($ExpiredCount -gt 0) {
        "ACTION REQUIRED: $ExpiredCount expired, $ExpiringCount expiring within $DaysThreshold days — Owens & Minor Entra ID client secrets"
    } else {
        "$ExpiringCount client secret(s) expiring within $DaysThreshold days — Owens & Minor Entra ID"
    }

    $replacements = @{
        PREHEADER              = (ConvertTo-HtmlSafe $preheader)
        LOGO_SRC               = $LogoSrc
        HEADER_COLOR           = $headerColor
        HEADER_LABEL           = $headerLabel
        APPS_SCANNED           = [string]$AppsScanned
        APPS_WITH_SECRETS      = [string]$AppsWithSecrets
        EXPIRING_COUNT         = [string]$ExpiringCount
        EXPIRED_COUNT          = [string]$ExpiredCount
        UNOWNED_COUNT          = [string]$UnownedCount
        DAYS_THRESHOLD         = [string]$DaysThreshold
        SEVERITY_EXPIRED       = [string]$SeverityExpired
        SEVERITY_URGENT        = [string]$SeverityUrgent
        SEVERITY_WARNING       = [string]$SeverityWarning
        SEVERITY_WATCH         = [string]$SeverityWatch
        ALERT_SECTION          = $alerts.ToString()
        PREVIEW_INTRO          = $previewIntro
        PREVIEW_TABLE          = (New-HtmlPreviewTable -Items $PreviewItems -MaxRows $PreviewRowCount)
        NEXT_STEPS             = (New-HtmlNextSteps -ExpiredCount $ExpiredCount -UnownedCount $UnownedCount -UrgentCount $SeverityUrgent -DaysThreshold $DaysThreshold)
        ATTACHMENT_LIST        = (New-HtmlAttachmentList -Paths $AttachmentPaths -Counts $AttachmentCounts)
        GENERATED_AT           = (ConvertTo-HtmlSafe $generatedAtText)
        TIME_ZONE              = (ConvertTo-HtmlSafe $TimeZoneLabel)
        INCLUDE_EXPIRED_LABEL  = (ConvertTo-HtmlSafe $includeLabel)
        SECRETS_EVALUATED      = [string]$SecretsEvaluated
        SECRETS_WITH_OWNERS    = [string]$SecretsWithOwners
        COMPUTER_NAME          = (ConvertTo-HtmlSafe $ComputerName)
    }

    foreach ($key in $replacements.Keys) {
        $html = Set-TemplateToken -Template $html -Name $key -Value $replacements[$key]
    }

    return $html
}

function Send-HtmlReportEmail {
    param(
        [Parameter(Mandatory = $true)][string]$SmtpHost,
        [Parameter(Mandatory = $true)][string]$From,
        [Parameter(Mandatory = $true)][string[]]$To,
        [Parameter(Mandatory = $true)][string]$EmailSubject,
        [Parameter(Mandatory = $true)][string]$HtmlBody,
        [string[]]$Attachments,
        [string]$InlineLogoPath,
        [string]$InlineLogoContentId = "om-logo"
    )

    $mail = $null
    $smtp = $null
    try {
        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = New-Object System.Net.Mail.MailAddress($From, "Owens & Minor Enterprise Application Team")
        foreach ($recipient in @($To)) {
            if (-not [string]::IsNullOrWhiteSpace($recipient)) {
                [void]$mail.To.Add($recipient)
            }
        }
        if ($mail.To.Count -eq 0) { throw "No email recipients were configured." }

        $mail.Subject = $EmailSubject
        $mail.SubjectEncoding = [System.Text.Encoding]::UTF8
        $mail.BodyEncoding = [System.Text.Encoding]::UTF8
        $mail.IsBodyHtml = $true

        $alternate = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString(
            $HtmlBody,
            [System.Text.Encoding]::UTF8,
            "text/html"
        )

        if ($InlineLogoPath -and (Test-Path -LiteralPath $InlineLogoPath)) {
            $contentType = "image/png"
            $ext = [System.IO.Path]::GetExtension($InlineLogoPath).ToLowerInvariant()
            if ($ext -eq ".jpg" -or $ext -eq ".jpeg") { $contentType = "image/jpeg" }
            elseif ($ext -eq ".gif") { $contentType = "image/gif" }

            $logo = New-Object System.Net.Mail.LinkedResource($InlineLogoPath, $contentType)
            $logo.ContentId = $InlineLogoContentId
            $logo.TransferEncoding = [System.Net.Mime.TransferEncoding]::Base64
            $logo.ContentType.MediaType = $contentType
            $logo.ContentType.Name = [System.IO.Path]::GetFileName($InlineLogoPath)
            [void]$alternate.LinkedResources.Add($logo)
            Write-Log "Embedded company logo as cid:$InlineLogoContentId ($([System.IO.Path]::GetFileName($InlineLogoPath)))" -Level INFO
        } else {
            Write-Log "Logo file not found - email will render without the inline image ($InlineLogoPath)" -Level WARNING
        }

        [void]$mail.AlternateViews.Add($alternate)

        foreach ($path in @($Attachments)) {
            if ($path -and (Test-Path -LiteralPath $path)) {
                [void]$mail.Attachments.Add((New-Object System.Net.Mail.Attachment($path)))
            }
        }

        $smtp = New-Object System.Net.Mail.SmtpClient($SmtpHost)
        $smtp.Timeout = 120000
        $smtp.Send($mail)
    } finally {
        if ($mail) { $mail.Dispose() }
        if ($smtp) { $smtp.Dispose() }
    }
}

#endregion

#region ### 7. SAMPLE DATA (preview / demo) ####################################

function New-SampleSecretRows {
    param([datetime]$NowUtc)

    $samples = @(
        @{ Name = "ServiceNow-Integration";     Secret = "prod-client-secret";     Days = -12; Owners = "Cloud Ops";           Emails = "cloudops@owens-minor.com";     Hint = "8f2" }
        @{ Name = "Workday-HR-Connector";       Secret = "workday-prod";           Days = -3;  Owners = "HRIS Platform";       Emails = "hris@owens-minor.com";        Hint = "b91" }
        @{ Name = "PowerBI-Enterprise-Refresh"; Secret = "pbi-refresh-2024";       Days = 2;   Owners = "BI Engineering";      Emails = "bi-eng@owens-minor.com";      Hint = "c3a" }
        @{ Name = "ServiceDesk-Automation";     Secret = "snow-midserver";         Days = 6;   Owners = "";                    Emails = "";                            Hint = "e77" }
        @{ Name = "Apria-Order-API";            Secret = "order-api-prod";         Days = 11;  Owners = "Patient Direct IT";   Emails = "pd-it@owens-minor.com";        Hint = "11d" }
        @{ Name = "Halyard-Supplier-Portal";    Secret = "supplier-oidc-secret";   Days = 18;  Owners = "Product Engineering"; Emails = "product@owens-minor.com";      Hint = "aa0" }
        @{ Name = "Byram-Patient-Notify";       Secret = "notify-prod";            Days = 27;  Owners = "";                    Emails = "";                            Hint = "44c" }
        @{ Name = "Inventory-Sync-Batch";       Secret = "(unnamed)";              Days = 33;  Owners = "Supply Chain Apps";   Emails = "sc-apps@owens-minor.com";      Hint = "9de" }
    )

    $list = New-Object System.Collections.ArrayList
    foreach ($s in $samples) {
        $expiry = $NowUtc.AddDays([int]$s.Days)
        $status = if ([int]$s.Days -lt 0) { "EXPIRED" } else { "Expiring" }
        $appId  = [guid]::NewGuid().ToString()
        [void]$list.Add([PSCustomObject]@{
            Name          = $s.Name
            Type          = "Client Secret"
            Status        = $status
            Severity      = Get-SecretSeverity -DaysRemaining ([int]$s.Days)
            AppId         = $appId
            SecretName    = $s.Secret
            SecretHint    = $s.Hint
            KeyId         = [guid]::NewGuid().ToString()
            CreatedDate   = $NowUtc.AddMonths(-18).ToString("yyyy-MM-dd")
            ExpiryDate    = $expiry.ToString("yyyy-MM-dd")
            DaysRemaining = [int]$s.Days
            OwnerNames    = $s.Owners
            OwnerEmails   = $s.Emails
            PortalUrl     = Get-EntraCredentialsUrl -AppId $appId
        })
    }
    return ,$list.ToArray()
}

#endregion


#region ### 7b. BUILT-IN TEMPLATE + LOGO (single-file fallback) ##############

# The sidecar HTML file and assets\ logo are optional. If the operator copies
# only this .ps1 (common for a quick run from a home directory), we still have
# a complete branded email. Prefer a file on disk when one is present.

function Get-EmbeddedEmailTemplate {
    return @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <title>Owens &amp; Minor — Client Secret Expiration Report</title>
    <!--[if mso]>
    <style type="text/css">
        table, td, div, span, p { font-family: Arial, Helvetica, sans-serif !important; }
    </style>
    <![endif]-->
</head>
<body style="margin:0;padding:0;background-color:#f4f1ef;">
    <!-- Inbox preheader (hidden) -->
    <div style="display:none;max-height:0;overflow:hidden;mso-hide:all;font-size:1px;line-height:1px;color:#f4f1ef;opacity:0;">
        {{PREHEADER}}
    </div>

    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f1ef;padding:28px 0 36px 0;">
        <tr>
            <td align="center" style="padding:0 12px;">
                <table role="presentation" width="680" cellpadding="0" cellspacing="0" style="max-width:680px;width:100%;background-color:#ffffff;border-radius:10px;overflow:hidden;border:1px solid #e6e0dc;">

                    <!-- Brand header: company logo + purpose -->
                    <tr>
                        <td style="background-color:#ffffff;padding:28px 32px 18px 32px;border-bottom:1px solid #eee8e4;">
                            <img src="{{LOGO_SRC}}" width="300" alt="Owens &amp; Minor — Life Takes Care" style="display:block;border:0;outline:none;text-decoration:none;max-width:300px;height:auto;" />
                        </td>
                    </tr>

                    <!-- Status ribbon -->
                    <tr>
                        <td style="background-color:{{HEADER_COLOR}};padding:22px 32px 20px 32px;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td>
                                        <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#ffffff;font-weight:700;opacity:.9;">{{HEADER_LABEL}}</div>
                                        <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:24px;line-height:30px;font-weight:700;color:#ffffff;padding-top:6px;">Client Secret Expiration Report</div>
                                        <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:13px;line-height:19px;color:#ffffff;padding-top:6px;opacity:.92;">Microsoft Entra ID &nbsp;&bull;&nbsp; App Registrations &nbsp;&bull;&nbsp; Password credentials only</div>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Greeting / executive summary -->
                    <tr>
                        <td style="padding:26px 32px 8px 32px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:15px;line-height:23px;color:#2f3337;">
                            Hello,
                            <br /><br />
                            The Enterprise Application Team completed the scheduled Entra ID client-secret scan.
                            This message summarizes what needs attention, lists the most urgent secrets inline,
                            and attaches full workbooks for triage. SAML and OIDC signing certificates are
                            <strong>intentionally excluded</strong> — only application <strong>client secrets</strong>
                            (password credentials) are in scope.
                        </td>
                    </tr>

                    <!-- KPI cards (2x2 so Outlook keeps readable columns) -->
                    <tr>
                        <td style="padding:16px 26px 4px 26px;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td width="50%" valign="top" style="padding:6px;">
                                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #ddd6d0;border-radius:8px;background-color:#faf8f6;">
                                            <tr><td style="padding:16px 18px;">
                                                <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:#6d6e71;font-weight:700;">Apps scanned</div>
                                                <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:32px;line-height:38px;font-weight:700;color:#1b2a4a;padding-top:4px;">{{APPS_SCANNED}}</div>
                                                <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#6d6e71;padding-top:2px;">{{APPS_WITH_SECRETS}} registrations have at least one secret</div>
                                            </td></tr>
                                        </table>
                                    </td>
                                    <td width="50%" valign="top" style="padding:6px;">
                                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #d5e3f2;border-radius:8px;background-color:#eef5fc;">
                                            <tr><td style="padding:16px 18px;">
                                                <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:#0f4c81;font-weight:700;">Expiring soon</div>
                                                <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:32px;line-height:38px;font-weight:700;color:#0f4c81;padding-top:4px;">{{EXPIRING_COUNT}}</div>
                                                <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#3b6a99;padding-top:2px;">Still valid, due within {{DAYS_THRESHOLD}} days</div>
                                            </td></tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr>
                                    <td width="50%" valign="top" style="padding:6px;">
                                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #f3c2c2;border-radius:8px;background-color:#fdecec;">
                                            <tr><td style="padding:16px 18px;">
                                                <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:#92232e;font-weight:700;">Already expired</div>
                                                <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:32px;line-height:38px;font-weight:700;color:#92232e;padding-top:4px;">{{EXPIRED_COUNT}}</div>
                                                <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#8a1a1a;padding-top:2px;">Rotate immediately — auth will fail</div>
                                            </td></tr>
                                        </table>
                                    </td>
                                    <td width="50%" valign="top" style="padding:6px;">
                                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #ead9a8;border-radius:8px;background-color:#fff8e8;">
                                            <tr><td style="padding:16px 18px;">
                                                <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:#8a6d1b;font-weight:700;">No owner assigned</div>
                                                <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:32px;line-height:38px;font-weight:700;color:#8a6d1b;padding-top:4px;">{{UNOWNED_COUNT}}</div>
                                                <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#8a6d1b;padding-top:2px;">Assign an owner before the next rotation</div>
                                            </td></tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Severity breakdown -->
                    <tr>
                        <td style="padding:8px 32px 4px 32px;">
                            <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:13px;font-weight:700;color:#1b2a4a;padding:8px 0 10px 0;">Severity breakdown</div>
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eee8e4;border-radius:8px;">
                                <tr>
                                    <td width="25%" style="padding:12px 10px;border-right:1px solid #eee8e4;font-family:Segoe UI,Arial,Helvetica,sans-serif;">
                                        <div style="font-size:11px;color:#92232e;font-weight:700;text-transform:uppercase;letter-spacing:.4px;">Critical</div>
                                        <div style="font-size:20px;font-weight:700;color:#92232e;padding-top:2px;">{{SEVERITY_EXPIRED}}</div>
                                        <div style="font-size:11px;color:#6d6e71;">Already expired</div>
                                    </td>
                                    <td width="25%" style="padding:12px 10px;border-right:1px solid #eee8e4;font-family:Segoe UI,Arial,Helvetica,sans-serif;">
                                        <div style="font-size:11px;color:#c05621;font-weight:700;text-transform:uppercase;letter-spacing:.4px;">Urgent</div>
                                        <div style="font-size:20px;font-weight:700;color:#c05621;padding-top:2px;">{{SEVERITY_URGENT}}</div>
                                        <div style="font-size:11px;color:#6d6e71;">Expires in 0–7 days</div>
                                    </td>
                                    <td width="25%" style="padding:12px 10px;border-right:1px solid #eee8e4;font-family:Segoe UI,Arial,Helvetica,sans-serif;">
                                        <div style="font-size:11px;color:#b8860b;font-weight:700;text-transform:uppercase;letter-spacing:.4px;">Warning</div>
                                        <div style="font-size:20px;font-weight:700;color:#b8860b;padding-top:2px;">{{SEVERITY_WARNING}}</div>
                                        <div style="font-size:11px;color:#6d6e71;">Expires in 8–14 days</div>
                                    </td>
                                    <td width="25%" style="padding:12px 10px;font-family:Segoe UI,Arial,Helvetica,sans-serif;">
                                        <div style="font-size:11px;color:#1b2a4a;font-weight:700;text-transform:uppercase;letter-spacing:.4px;">Watch</div>
                                        <div style="font-size:20px;font-weight:700;color:#1b2a4a;padding-top:2px;">{{SEVERITY_WATCH}}</div>
                                        <div style="font-size:11px;color:#6d6e71;">Expires in 15–{{DAYS_THRESHOLD}} days</div>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    {{ALERT_SECTION}}

                    <!-- Priority preview table -->
                    <tr>
                        <td style="padding:18px 32px 8px 32px;">
                            <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:13px;font-weight:700;color:#1b2a4a;padding-bottom:6px;">Highest-priority secrets</div>
                            <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;line-height:18px;color:#5c5f62;padding-bottom:10px;">
                                {{PREVIEW_INTRO}}
                            </div>
                            {{PREVIEW_TABLE}}
                        </td>
                    </tr>

                    <!-- Recommended actions -->
                    <tr>
                        <td style="padding:16px 32px 8px 32px;">
                            <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:13px;font-weight:700;color:#1b2a4a;padding-bottom:8px;">Recommended actions</div>
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eee8e4;border-radius:8px;background-color:#faf8f6;">
                                <tr>
                                    <td style="padding:14px 18px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:13px;line-height:20px;color:#2f3337;">
                                        {{NEXT_STEPS}}
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Attachments -->
                    <tr>
                        <td style="padding:16px 32px 8px 32px;">
                            <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:13px;font-weight:700;color:#1b2a4a;padding-bottom:8px;">Attachments in this message</div>
                            {{ATTACHMENT_LIST}}
                        </td>
                    </tr>

                    <!-- Scan metadata -->
                    <tr>
                        <td style="padding:12px 32px 4px 32px;">
                            <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:13px;font-weight:700;color:#1b2a4a;padding-bottom:8px;">Scan details</div>
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #eee8e4;border-bottom:1px solid #eee8e4;">
                                <tr>
                                    <td style="padding:9px 0;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#6d6e71;width:42%;">Generated</td>
                                    <td style="padding:9px 0;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#2f3337;font-weight:600;">{{GENERATED_AT}} ({{TIME_ZONE}})</td>
                                </tr>
                                <tr>
                                    <td style="padding:9px 0;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#6d6e71;border-top:1px solid #f4f1ef;">Reporting window</td>
                                    <td style="padding:9px 0;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#2f3337;font-weight:600;border-top:1px solid #f4f1ef;">Secrets expiring within {{DAYS_THRESHOLD}} days{{INCLUDE_EXPIRED_LABEL}}</td>
                                </tr>
                                <tr>
                                    <td style="padding:9px 0;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#6d6e71;border-top:1px solid #f4f1ef;">Client secrets evaluated</td>
                                    <td style="padding:9px 0;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#2f3337;font-weight:600;border-top:1px solid #f4f1ef;">{{SECRETS_EVALUATED}} across {{APPS_WITH_SECRETS}} applications</td>
                                </tr>
                                <tr>
                                    <td style="padding:9px 0;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#6d6e71;border-top:1px solid #f4f1ef;">Owner coverage</td>
                                    <td style="padding:9px 0;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#2f3337;font-weight:600;border-top:1px solid #f4f1ef;">{{SECRETS_WITH_OWNERS}} with owners &nbsp;&bull;&nbsp; {{UNOWNED_COUNT}} with none assigned</td>
                                </tr>
                                <tr>
                                    <td style="padding:9px 0;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#6d6e71;border-top:1px solid #f4f1ef;">Source host</td>
                                    <td style="padding:9px 0;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;color:#2f3337;font-weight:600;border-top:1px solid #f4f1ef;">{{COMPUTER_NAME}}</td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Methodology -->
                    <tr>
                        <td style="padding:16px 32px 4px 32px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:12px;line-height:18px;color:#6d6e71;">
                            <strong style="color:#1b2a4a;">How to use the workbooks:</strong>
                            Open the <em>Expiring</em> attachment for secrets that still have remaining life inside the
                            {{DAYS_THRESHOLD}}-day window. When expired secrets are present they are exported to a
                            <em>separate</em> Expired workbook so they can be routed independently. Use the
                            <strong>PortalUrl</strong> column to jump straight to the app’s Certificates &amp; secrets blade
                            in Entra admin center. Days remaining are calculated from UTC to avoid daylight-saving drift.
                        </td>
                    </tr>

                    <!-- Sign-off -->
                    <tr>
                        <td style="padding:20px 32px 24px 32px;font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:15px;line-height:22px;color:#2f3337;">
                            Best regards,<br />
                            <strong>Enterprise Application Team</strong><br />
                            <span style="font-size:12px;color:#6d6e71;">Owens &amp; Minor &nbsp;|&nbsp; Identity &amp; Access</span>
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="background-color:#1b2a4a;padding:18px 32px 16px 32px;">
                            <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:11px;letter-spacing:1.6px;text-transform:uppercase;color:#ffffff;font-weight:700;">
                                <span style="color:#ffffff;">Life Takes</span> <span style="color:#e8b3b8;">Care</span>
                            </div>
                            <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:11px;line-height:16px;color:#c5ccd6;padding-top:8px;">
                                This is an automated, confidential message generated from <strong style="color:#ffffff;">{{COMPUTER_NAME}}</strong>.
                                Do not reply to this mailbox. If you believe you received this report in error, contact the
                                Enterprise Application Team.
                            </div>
                        </td>
                    </tr>

                </table>
            </td>
        </tr>
    </table>
</body>
</html>
'@
}

function Get-EmbeddedLogoBytes {
    $b64 = @'
iVBORw0KGgoAAAANSUhEUgAAAyAAAAE6CAIAAABhwKHrAADg+UlEQVR42uz9d3xcyXodilbYsTNy
zokACWZOzvHMSZIlW87hOocn+977rOdr++efbb33nJ+vbEtXupIsycfHsiRb4ZwzM2ciZzgc5gSA
RM6pG92N0Hn3DlX1/qjuZhNEaIAA0SD3EjUHBLt3qF27atWq71sfZIwBGzZs2LBhw4YNG3sHZDeB
DRs2bNiwYcOGTbBs2LBhw4YNGzZsgmXDhg0bNmzYsGETLBs2bNiwYcOGDRs2wbJhw4YNGzZs2LAJ
lg0bNmzYsGHDhk2wbNiwYcOGDRs2bNgEy4YNGzZs2LBhwyZYNmzYsGHDhg0bNsGyYcOGDRs2bNiw
YRMsGzZs2LBhw4YNm2DZsGHDhg0bNmzYBMuGDRs2bNiwYcMmWDZs2LBhw4YNGzZsgmXDhg0bNmzY
sGETLBs2bNiwYcOGDZtg2bBhw4YNGzZs2LAJlg0bNmzYsGHDhk2wbNiwYcOGDRs2bIJlw4YNGzZs
2LBhwyZYNmzYsGHDhg0bNsGyYcOGDRs2bNiwCZYNGzZs2LBhw4YNm2DZsGHDhg0bNmzYBMuGDRs2
bNiwYcMmWDZs2LBhw4YNGzbBsmHDhg0bNmzYsGETLBs2bNiwYcOGDZtg2bBhw4YNGzZs2ATLhg0b
NmzYsGHDhk2wbNiwYcOGDRs2bIJlw4YNGzZs2LBhEywbNmzYsGHDhg0bNsGyYcOGDRs2bNiwCZYN
GzZs2LBhw8ZhhWA3wR6AMZb9AQAA0QO01UgktNWIHo0ZiURqdTW5FNRW14x4XI/F09G4paUBAJam
McYgQlhRIISCJMper+RxK26XXFLiqq50lpWKLpfs9aglPtnrWX92xgCAAAIIAIDQfiA2bNiwYcPG
wQLmuIGNHdMqShllEMF1jEqPxVfHJ1YnZyLTM7FFfyoYSgTDqeWVdCRCDBNhDBDkABBl6FCOFTEG
AGAAAMoYo4wxQBklBAlY9nod5WWuqkpnZYWrpspdW+NrbirravfU162nW4Q+fFWHgJ4WySvxBDHU
Imlam/fbsGHDJlg2CqVWgDGIMf+rmdLSkUh4eCxw45b/1p24P2DEE3osbsQTAEEsikgUkSAgjCGE
LMuiQN4PLH8qAg9SLgghAAwAZlnUsohlUdOkFhEURXa7ZK9HLSurOn607pkz1adPOCvKJZfrgYtE
yJ7bbNiwYcOGDZtgFTGpenD7L+4PhO8NBwfuLVy7Gey/a6Y0/kGIEMICFDDCOKMi8F28R2zqjOjF
GRdklFJCmGVRQgCEgAEsSxU9R+qfPVt96kRFzxFfS9MWF188IKZJDZOrHEXwmJnoUJ8YSmrpOrPI
gd4O3zTHgiIX+wv+4Ou5hZBZ+Cdt2LBhEywb21ArxhjK6lV6JDp94eupT78I3xtam5o2kinRoQqy
nBlnIQAMPCBT7ePTgzB7Rj7uE8MwUxqWpZKWptLO9sYXn2t583Vfc+N9mpUnvBXDnAYg7PvN79/7
nf8pquqBd0WIoJFIPvOzf6Pru99ijB3eiZNffNwf+OBv/W8AsANkrhAAyzBqz515/ef/MX/cxdZQ
vK0e8VlTSvnbaJMtGzZs5GAHuW89+gKuSEEAEsFQqP/uyA8+WLhyLR2Nm8kkFiVBlUWHg1HKSVh2
xf54F915ZxQUWXQ4GKPRucXV8amZzy9c/T9/qebMqe6f+m7N6ZOehjqQVdT4bFAMzRxbWFy8flNy
urjMdqAEC5mp1ODv/EHXd7916GdKxqY/vzD39WVROUjmCiE005qyLi2jCN5skFGEM9TKsqx0Wk+n
0+l0Oh5PJFOptK7r6bRlEUIs/mFBEDFGgii6HA6X2+VyuWRJUlXV4VBRVhvOHdkePm3YsGETrI3G
36zSwwUi/8074x98PHvh6/DwCEIYSSLCWPZ6M+tfyyqmK2eMWpxpCarCKDVT2vT5CxM//rS0vbXp
1Rdb33qj5c1XObUqkn1DQZIkt0tyOA+cYAEIBUUODtyLLyy6H0wdOFyAjAGEJj7+THK6RFU5WIIF
RSyoarHxKv6LYCgcDi+vrq5FItFYPB6Px3Vdz30g+7HMh7MHAXzLHwKgKIrX6ynx+UpKfKVlZXU1
1Wr2TjNrM5tp2bBhEywbuTGYUsp3A81kaurzLwb/++8H7w0mlkKiqsgeD2CM8wBGSLFzxKwqIyqK
6HDE/YE7v/694f/5g4pj3T1/4o91fPNdxecFAFBCIEIHOBPwtEeuAhYBN4FGPD752Zcn/9KfZYQU
0XbqTh49RCgyM7s8PAohvK+tHlB78odbJNQKAGAYRnh5ZWJiMrC0lEymUqmUZVkYY4wxQkjdyVY1
pXR5eWVpKcgYUBTZ6XRWlpe3tbXU1dU5HCoAkAEGmC1o2bBhE6ynnVkxnnOHMI77A9OffXnvd39/
qf8uBACLoqOslFFa5KRqq1sjBEuioJQS0/TfuOO/cfvGL/1a75/+E+3ffKektTlLcwBET/tMABGy
0vrcxcsn/+KfKYqg+90SrNkLXyeDYdGhPOVBlvkhVsFgaG5+fnxicnV1jTcLwlgURUmS7nN9Lj1t
Esb+cGMKgiCKIidbsVgsGo1OTE05HGpXR0dLa0ttTTWA9r6hDRs2wXqKx+CMagVhanml/3u/PfqD
D5aHRgVVkRwOPqrSYtoH3O28yxi1IEKiQwWMxf2BC//8Xw58/3fa3n3z5P/y533NjRAevJp18KAU
K/Ly0EhkZtbX0szJyuHqzBBjSsji1ZtE1yWXg1nkaX2t79Oa+YWFoaGR+YWFRCIhihLGONfJIYQ0
C8bA+u3BLOviRI0LXTkels/JONniv0un9eu3bt8bGq6rqz12rKe5sTFzPTbJsmHDJlhP0ShMKVet
kqHw8O//YOC//k5kZg5hrJaVMkqKYtNqz6cdvnYXBLWsNO5fuvWrvzX6gw96fuanTvyFP+Opr821
yVM7K4uKsjY17b9xx9fSzCiDh4xfMYhQZH5h8cZtyeVklD21z5GTmaWl4K3bfXPz86ZpCoKgqo58
SmRZlmlakiQ6nU5Flt1ut9frUWRJVhRJkhhjlmUZhhmPx9bWoqlUKpFMplIphBAXvdYJWrm/Qggd
qkopnZqamp9faGlpOnPqVEVFef6F2bBhwyZYTzi1gghR07z72//jzm98b2V0XFRUyeUEADwBktW2
UxC1LEGRBUXWY/Hr//FXRv/o/RN/8c/0/pmfUUp8TznNAhDOXb565Ke/iw5hDBZgLHhnIDo7r5T5
nkL5KidcxWLx2319w8OjlmUJWOCUiFKaSxtklJWVl9XV1tTUVFeUl3u9HrRlhzdNcykYCoXC8wuL
iwsLhDJBwAihDTdhKaUAAEmSGWNjYxMzs/PHe4+eOX1KliSbY9mwYROsJxmUED53Tn702Y1f/jX/
rT4EoeL10scfag3XO2zmlzV8DCwTAAARkr2eZGj5q5//16N/9MGZv/1Xu777TYTxIY3yftS+Qano
cMxeuKStrDgrKw/XdMg58eQn57EsgqdPvso9rNHRsWs3bq6tRSRJEkUxp1pBCE3TxBjX1daeOH6s
urrK4XCsI2ebQRTFhvq6hvq6E8ePhcPLwyOjE5NT6XRaFEUINzYU5L+UJIlReuPGrcWFxRdfeL62
tsbmWDZs2ATriR2CEcarE1PX/9OvjP3gA2JZPNaK7lMMezaoI0ebMn5ZPNubEJAXV5up2Azh/Vio
vGiR+2P2XtMvRgiWRCxLy6NjH/3sz43+4fsv/oO/V3G0BzyFUhZjfMt48cbtzm9949Bdvra8snD5
Gpakpy28nb/aWjp95cq1oeERAICiKDSbRMljrQzDqKutPX36ZGtLc+5buUD4bUkP/7AgCDU11TU1
1b3Hjt7p65+cnLIIEQRhswbnv5dleSkY/uH7Hz77zLlTJ48De7vQhg2bYD1JAzAPZmeE3P71/3L7
V38rtuiX3S4kSfuiWkGIEAIQUsuyTDOzWXO/zDMEEIqqKns9WBCQKCJJBABQ06SGSS1Lj8WNVApk
y+zwqs8AAChgLIpIEPjt7CHT4o0gKDIAcOqz84Hbfaf+yl84+7f+iqAovHr0U1XTEEI4/sHHnd/6
xoEaoe/4CUKEps9/lY5GeQ95ep4XpRQhFA4vf3HhYiCwJEkiZ1T8XxFClmUJgnD27OmTx3vzI6h2
ZOOe+zD/bkVF+TtvvznT0X7pyrWVlRVpS1LLGBNFgVJ68evLsXjspRee5/HyNseyYcMmWId/dQsA
wjg8OPzV//vfzH71NRYlxeuhWQFpjydnhBgh6WiMWpZa4nPXVMs+r6+hoaSj1VNX666tdlZVKD4f
liQkCBBBCNF9gYpRnrdIDFOPRBNLwbh/Kb4YWJ2cjM7Op6MxbXkltbyCBCy5XBBjtsc0iwHAJLfb
TCUv/ZtfmL3w9Sv/5B/UnDn5tC24IYJLfQOplVVHWWkR1njZ+NkBAAGYOv+lpRvyPi0biphdzc3N
f/7FhXgioSgyzXP/ghAahuF2uV5/7ZWmpkbwoHfDrl/xHM1qbm6qqqr8+tKV4ZExURQ22y7kn0cI
SRLq67ubSCTffvP1nEOEDRs2bIJ1iAUJAMCd//y9a//hl9ORiOL1MAAYoXsaY8QAgIBSYppWOq2U
lra9+2z1yeMV3UfKe7q8jQ27OKK7prq8uyv/N9H5heXBkfDw6FLfwOKN29rKiqiqWBQBQntadY5h
SRZkJXC7/w//wl8/+7f+ytm/+VeQIOzTo4EYQ4z3l8TsiINCKChKKry8cOlq53e/mfOeLWp2RSlC
KO5fWhkZE2SpSHZ1IYQQo329GM5aJienPj//pWlZkijSPGbJ2VVFefnbb71RXl62t5ZUOZqlqurb
b73h8/muX7+JMNr6agEAiixNTExZpvnuO28pimLrWDZs2ATrUIKPaKvjExf+6b8c+/BjUZaRKKYj
sX2oGggZYBDh0vbWnj/+k61vv17S2oxzK9S85PAck4Db8bV15ABC6G2o9zbUt33jLWKYa9Mz85eu
3vvt/7E8MkoJgbmyz3t3RwBBbWX183/4z6Y++/L1f/aPKnuP8l3OPTyHpet6NAYIZXT/Ut52vL+J
BCG1sjL5yecd33nvUEx9WX/Ri8H+e5LLqcfiRUKwzLRmado+HZ9rVxOTU59+dp4xxjfd8s9uWZbP
53v3nbdKS0v2icfkJKtzZ0+rqnLx68vbXzZjsizNzs2f/+LC22+9wa1KbdiwYROsQ8auIISxRf/1
//SrWiTS/t7bgFJG2X5E1UAIiEkbX37+zN/4y5Izk5pELSsTuLFzA0+Yf+j78yhjjALGsCSWd3WU
d3X0/uk/futXf2v2wtdQwHu/3cnt3SEy4okbv/xrL/zc/1ra3rq3W2a+5qamV17c35J5DBDT3Oms
aek6AECPxhSft/g1Bq7Faqtr1aeOKz4fLY6qAxAAyzBKOzv26e1GCM3NzX1+/kv+87ouRCmVFfnt
t94oLS3hVGz/eCS/nmNHezBCX1y4WEi8vCRJ4xNToiS9+fqrj7hlacOGjWIclp+GVCMrpQGEBEXe
23ClhyZxkGNRmcI7cD8Dw7kkljcuU0L262QQQgiJaVLTEp2Ovb4Pyv0w9296YQAQw9ihuscggIwx
rMiHyA3L1DTIQDG90gwAABEWFHk/1k6hUPj9Dz/SNG2ddgUyjgzWm2+82tN95LHxY36iO339X1+6
KorCtqMrBNAwjZdfeuHUyRP7SgFt2LDx+PFUxGAJjkyJ+32NBeHjNyMUYrS/1CqP9GSGdUohRPvN
A7Ak4X2IyYUQwX0mMBAApKpPQ1cXn47b5DwmmUp9/sWFZDLJna7yP4AQ0nW9u/vI42RXIGsGcerk
iUQyeft2vyLLlG2dasAEQbh6/WZ5WXlDQ50djGXDxpOEJ3DBdMCaHIKPuT5J5n7hU9naNp5WMMa+
/vpyKBR6mF0BAEzLcrvdz547+/gvjIdkPfvMuYaGOsM00JaEiQGAECKEXLh4MZVK2ezKho0nCU+a
gsWXgAeWoM4AxAhAQC2L1+HZ75tlhCBBAAd3yxChR1x2s/vu+fDBiQoUiTkCROhQODXwjenivLY9
fBd4fxu4Ozg2Ni7L8sPsCkLAKO091uPxuB+/JsQJliSKr73y0h/+4P20rm/DsRgTMF5ZWb1+89Zr
r7xsi1g2bNgEq0hnF4jQyB++3/+938aC8PinGkZpyxuvHP2Zn3ZUlGUvKUMb7pu5P+pNZle+AEAE
oSDosfjIH70//v5HjFEA4WMLwIEIUNM6+jM/ffRP/TQjBOw8ip+zlr7f/P7d3/4fokNZp/wJsgwF
fLDxRBBBM6W1f+Otc3/nrxetoz2vaDT92Zc3/q9fO/AWe5huEEOvPXPylX/yf+yJiwjnHysrqzdu
3MTCxlvLhDCfz3e8t/egyArnWKWlpWfPnLrw1deFuOqLojQ6OtbR1lZXV2tzLBs2bIJVXPSKr5IH
/ut//+Kf/H+oRSA6mBFq/vK10R982Pmdb7S9+1ZZZ/u6GYURkolMv8+34Aazzv2COtnCOBAijPPK
5gAAQHRufvKT82Pvf+S/cSsTX/9Ybccho2TpzoAej5/+a39p13uF8UAgOHBPcjnXi3B59PQAdRcj
kSS6fuIv/BnJ5SxmHWvsg4+nz3+plpQUSf5gjmqYWlpyOLPdGj7aW84AAISQ6zdvJZJJRZbpQ70O
Iajr+tGeI5IkHuD+NedY3UeOTExMLfr925q8Y4x0Xb9x83ZVVaXt8G7Dhk2wiohdMQAghDd/+dcv
/ot/h0VJdMrggLbMBFUNDw0H7w72/eb3S9paGl96oe7ZsyVtLZLLKaoqxLigUTOvAHT+5620biQS
0bl5//XbsxcvrYxOxANLgLHM3H8Q0wgj5MLP/ysjmXzuf/07jNJdRPcjLAiyJBSn8ziEaokYmZ0L
3O5vevXFXI3wIur7lEKME0uhYP+A7PViSULF1IycZ/AyUHt1wLn5hYmJSXkjdgUhtCzi83rbWluL
4fYlSTx37kzowzDlr8bmoJRKkjQ/vzA7N9/W2mKHNh7+GQnYFNmG8CR0ZcYAQpf/3X+8+n/+oqiq
EEJ2gIt4QkSHA0Cora4lQ+GFKzcAYI6K8rL2Nm9rk6+p0VVZqZT6FJ9XcjpFhyo4VIQFLElc1GKM
UdOgFjE1zUxpZjKZjsbSq5FkOBydnV+bmV0dn0wuBbmshbAgOR3gAO+XMYCxoCiX/+1/MFPay//o
7zNKd7oZyijLoQi7FxKEZHh58fqNpldfLMYRkzEAQOje4PLImOR20f00InmkN3SP2BWl9NbtO5sp
YRBC0zTr6+u9Xs+Bi0CcXDY21Dc21E9NzwgFFEKACPb3321tbgL23PwIzGazx/F4LmB3lmYHfuWF
XInNGp86gsXjrq7+wi9d+ff/SXI6YRHktXElBosilkS+0adHY/NXrs9+dYmYJoBQ9rhlt0tQVUFR
BEVGGCNRzLg8AEBNk1FqpdNWWrc0TY8n9FicEYIkEYsiFiVBUQAA3Lb94FUfSgGEktNx4xd/FSH8
4v/xv4Ed+rgyVtQl8xilksMx99Xls3/7r0lOZ7Ht3XB/0ZkvLjJCc3zrSZ07IYRj45NLSyFRxBu+
5lwHamyoB6CItnNPnDg+MzO7RY3C3A1ijJdCwZm5+ZbmJnuXcCeDEAUAoO3CQPnH9snTNUetLMua
X1hwqI6qqsptv5L71haXlP+x/Xu5Mot2iArxyN1FoXSbYB3CEZcyiNGtX/nPV/7df5QcDlBMrgGZ
CPfsLCg6BAgdfMinhBiJpB6LZxLoGFhX3wNAwJMQIUIQY0d52f1+nVN6WDE9CAAkp+Paf/oVJInP
/+//D0YIROjJWIUzSgVFDvTfXZ2YrD5xvLjCsBgAEBiJxMz5C6JDfcz+II9fEDIM8+69QcooAPjh
FwBCQAh1uVwNjfVFs9SGjLGa6qqmpsap6Rlpu2h3hFA6nR4dG2vaVenSHUkO+zFUFjI37+GRc9M8
N2hljGmaZhgGIZQQQhlDCGKMMcKyLKuqnPNx3dstvPyjzc7OXbtxMxxelmX5O996r6qqckOivI6g
UEK0tG4YBiGEUMoYRQhjjCRRUhRZFMX84uJ727HvXwnI7DwYhmEYpmmaFrEoZbzIqSAIgiBIkihJ
0joia++HPokEK8uu7vzG9776//5bQVG2XSAe8NU+yKEQxkDA21cjZIDxejvF/jgAgEByqFf//S8K
spTJuSv0lSt+WgAZIVOfflF94nhRsUbGKARw8fqteGAJCcITL1/Nzy8EAkubR69DSml5eZlaNOWT
IQSUMoxxR0fbzOxcIUqMIIh+/1I8kfB6PPtNWA+EJe+tXAQA0HV9bn4hFArHYrFINJpKaZZpmpZF
KcUYi6IoCoLT6XR7XB63p6KivK6mxulyPjo54IN6jm2srK729Q2MjI4xxkRRjMXisXj8YYKVf+Xx
eHxxMRAMh+OxWDyeSCZTpmVaFqGUCIIgCqKiKh63y+v1VlZW1tfVeL3e/IPsDa+CEACgaenA0tLK
yupaJJJIJFIpLZ1Oc6pKKcEYS5IkS7LDqTpUh9PpcDhUt9vt8/lKS3yyLAMbTxjB4uxq6H/+4Mt/
+i+wJBU1u9qsd7NDwS12ck8QCop86d/8guLz9v7ZP8ksCxYQdwLoIbg5hPH0p188///8u8W1UGMM
IDTx40+JaeHizBLY04l5fGJi21emvq6uCK+8oaHe5/NGIlFBELYTsaCmaZ98+nlpSYmqKoqiyLIs
SZIkiaIgAgAQxhghAAChlBJCGTUMU9d1wzB03dAzMCzLhBDV19WePNH7cGaGYRj3BoeWloKUUVEU
VVmRFVmWFUkSJVGUJFEQRAAAxjgnDlmWBQAglPDTmaaZTqfTaV3T0haxBCyUlHiPdHV6vRsU7uS/
WVtb6797L5FIYoQURXW5nA6HqsiyrMgYYUHAAECLWJZFNE1LpVKJRDKRTJqGIcvyiRO9VZUZspI7
fjAUunt3MLAUjMfjaV3HCGGMMcYQQl4/mzFGCLEsK5FKBZaWKKWKojhUtays7GjPkbr6Oin7sR29
1/nshDG2tha5e29oYnIykUhIkpRRm8D6oFKufUMILUIWF/337g2Gw8uplKYbOn+mnKuJosDnZUJJ
PB6PRKJkdk4UBJfTWVtb09t7tKa6Or8Rdk1PAQCGaS4u+kdGRsPLK6lUKq2lAcw8dH539y+GkEQy
EYvHKKV8p1USJVmRZVku9fkaGhuamxo9HrfNqJ4EgsUohRjNXbx8/h//cyxKCONDMLXA/MzAnb4Y
GSkr85oWMcmCCCGML/z8v3ZVVbW89Vph3lHFzjIZAEgQoguLgVt9tWdPFYshFmMQYz0eX7rT/zTI
85FIdGZubkPf9nw2U1NTXWwEizHmUB11tbVra5FCvoIQCgZDS0vB/Bl0qxidvGGBPbhsm52bc7mc
nZ0dlDKEILhfLXHg0pWrUl5j5h1/m4k7/xT5X7csa9Ef+M633uPkZl0jUEqvXrsxPDImyZmVQPY0
G5wu504DAIMQptM6ZfQb77zNRSkIoT8QGLg7OD09Y1kWhFAQBJfTyRjLcE7AAAAIQk4UEIQYISAK
XOOMJxKxeHxmdrasrLT32NHOzg7eDltHQeVfaFZ/SgRDoYmJqZnZWdM0EULc9nazPUH+y6npmdt3
+peWlhhjECJBQA6HI3u/DDy4i5rlixJjLJlKjY6NT0xOdXa2nzl9qsTnexR2ZRjG2PjE3XuDy8sr
/I4EAatONRevkv9fTrYyF5OdvxijhmGk0+lINDo1M3tVls6dPXPq5HE7dvBwEyxuqxi6O/jR3/t/
Wem0IMvFmd6fUV8hBBAwShmh/P3nBacZY4AyBrIJVnkMKm/cgSB7EIjg/agsPrvzgxRZ8h2jFAmC
lU5/8nP/+I/911+rPNbDKNvak4xRVvwW6UgQtJW1mS8uFA/BooQgQVi4fD0yMyeoSpHnCjyiOAoh
HB4ZNQ1zM4LFp3CXy+ne62Lke4XOjo6h4ZEC39b8lMMCv5K/gsuNQMlU0jDNLA2DueElGosKGMuy
TB5MQC58MFl3Ou7dpaU0y7LETfgKoRQhKEtidtxi26XOMQgRYIyIpMRXwpMAdN24cfPWvcEhXTdk
WeLxSYQQTnFUVfV5PaIoMUZTmhaLxU3TJJQKGCOE+DvC25YxtrKyev6LC8Mjo2dOnWptbX5YyqKM
gbxNQI5oNOb3Bxb8i8FgeGV1BQIoimJOMNukA1MIUSwWv3L12sTkFCFUyhqXMMa2eHPzWQ7nNwCA
wcGR+fmFl196sb1tN14kEMLZ2bnrN275AwGMsSgKvLOYpsmYldOu+MKAg0tWgiAghPLzlDm1zWmi
N2/dOtpzRNqHerU2wXqsq/a4f+mjv/cPkqFl0almkqeKRKCCGdd2ahJiGsS0qGUxQgRFEVRFUGQs
K4IiY1FEAkaiiAQBIQQghBjnXmFqkcxrZ1nEtBixiGmRtG7puqXrZkqzNA0wBkUBCyJPLQQQAsby
130Hy7FERU6Fl3/8s3//p//7b7qqq7ZmJOxQ7JNCCADw3+wztbSoKsUQ6s472+L1m9paxFlRfggC
9R7hXimlc3PzW3+IEFJSUipKEiiykFt+MZWV5W63O5FIbHVtWSvWXayacsISH4l0w6CUtDQ3tbQ0
5zcI5xAd7W3j41OpVErabXzF/dNBSClNp9MOVT116oSqqhtuESKEuo90BYPBZDJlESJgzCfszUkJ
47tplJCe7iOnTh6HEAZDoS++/CoYDEuSqCgydxczDENRlK7Oju4jXWXlZQLGmchxSg3DXPT7x8cn
5xcWdF3nSQa5M3JysLQU/PHHn5w43vvMuTP8A7kNOAQhgNCyrEQyGYlEFhcDC4v+WCxmmqZpmhhj
WZLBQxG2D98IQnhx0f/FhYsrKyuyLHMyuotlBv9BUeRUUvv4k88iz5w7e+bUjhQjSumt2303b902
TYvHTmWnGqustLShoa6urq6kpERVFQiAZZF0WltdjQTDoUBgaXV1LZ1OS5LEZ5t1V4UQQghrmmYT
rMNKsPiTJLp+/h/9s+WRUdntPnjTagghQoBSahFKCKOEEgIYcFZWeBu7XLXVzvJyR0WFs7xULvEp
Xo/kcSsej+BQBVkWHSresi9SyzI1jeiGqWlGLKHHYno8no5EteWVZHglFQ4ngqHo3GLC77cMEwkY
YQxx5r+AsQMU9iihktO5PDL22T/4J9/6lf+AZRlsMQqwg/ZrL4w1Si5nsG9gZXSs+uRxSukBO45S
CjFORyJzX1+RnM4nOPqK720tBcPxRGLrmYkQWuLzFmI3dTBDrSDU1dUMDg5vlUu4F++BRSlgrKG+
rr2ttaurUxLFXPGIHNNqaW7+ie9+c2h4dHZ2jk+Ku5jyObUyTdPtdh872nPkSGdlRcWG7Jb/pq21
pbS0ZGFhMRqNRaOxUDgUjyce3k/MfYUQIsvy8889e7TnCABgYnLqywtfaZquKBJjgLMrXTca6ute
eOHZ6qqqdUfguW8d7W0d7W3zC4s3bt5aWFjMv1P+A9fbbt2+EwqF3nzjNa/XSynlFbjnFxYDS0vh
UDgUXk4mk5kNR4QghDl2si0rwhhPTEx9fv5Li1iKotBHflUppVjEjLIrV68DAArhWPw6KSVfXbzc
P3BPliWeKcKpJMb47JlTx3uPKdwAKA8ul7O8vLyzs50xNjs3Pzo2PjkxSQAQNnoTCSHptO71AnuX
8HAqWJRChG784q9OfXpeKfExQtHBDqYQUMPU43EsybLb5aqprj7ZW33qeHlXl1pWIvu8sseFsLD9
qoQBkK8SZ83QkSDIbjfYPHDQSCTSkVg6Eo1Mzyz1DwRu9kdmZvVYTI8nBFkSHQe8V6KWlsyc/+rm
L//68//7z26hq0GEkCAgQShyloAEnFpZXbo9UH3yOIQHvEXIOena5MzKyBivMlScdRIhhEgQ4COR
UQYADAQCyWRyi/kJQkgpcbmcfAZCRdYafMqprakZGLhXoGLEP7OFxrNhI1iWVV5e/sJzz9TU1Iii
kCe/rl/U1NfV1dfVRdYifQN3B4eGd9FihBBRFM+dPdPV2cEDnLeNZCrx+XjwECEkmUxOTE5fv3GT
MfowtSSEKIry3jferq2pAQAMj4ye/+ICAEAUBUozyplhGB0dbW+/+booipQxuBG3463XUF9XXVV5
+cq1/oG76ygd/4AsywuL/h+9/+O3336zqrJi0e//+tLVtbU1TdMwxoIgZHPlsiY5hTxByiCEk1NT
n5//wiIEY5zrvZtdZ8HrPcajpq5eu+5yuY50dWzLaSCEl69c7x+4qyoKzUpulFKM0RuvvdLR0X7/
GvIOlB9j19zU2NzUONXedvny1dW1NVmW81/GnJBpk6pDSbAYYxChge/9969+/l9jSUiGlne6F7bX
QSqQUeqqrGh/9636559tfv3lsq6ODZWPLG+AEGaHuvvxC/yXAAC86RALsrt+uR1ABiCCEGPJ5ZJc
Lk99beWx7s7vvAcASAbDcxcvzV++7r91Jzw0Agg5wPgmCCAD4MI/+5dqScnJ/+XPbTYEGLFEMhSW
XE5KSRF3QAghJLo+8P3f6f2zfwIfeGYyhACAe7/9PxKhsOxM0WINwEIQGZqmR6K7PwJClNKlpeC2
9rUIIYfDUcyDWFlZqcvlsgrYzGWMybIEIdS0dIE7Spxd+bzeb37jHU53tiCaEGbIkK/E99qrL6uK
ev3WTVHYQfVGSqnD4fjGO2/W1NSAwvwOcmE9PGLa4/GcPnUCIfjVxcvrrDf4bP3i889xdjU2Nv7F
l19x9Sh3ItM06+pq33zjNVEUt7zTTGi/KIqvvvISQvBO38DDih1jTJbltUjko48//fY3373TN7Cw
sOByOnkE+m7qTDAmikIymTx//gJnVznFiOc23j9mJsIW5UwTdsS/L168VFrqq6yo2GyA5b+/Nzh0
p69fURT6YF7CqVMnOjrauRy4mfSY05IhBK0tzRXlZZ+fvzA3P7+uGSmlmk2wDinBghAyQhkEr/7z
f4hFkVG6Ez2dQYQEWdnTnSgGMS7v6qx//pmHFKn764D7Mem7u+cHV6BwA/UrLzQeQmdVRfcf/8nu
P/6TsYXF+UtX9Vj8AIUNXiCSGIbkcvLUhA1ZwpGf+k5JZxsWhSKPxco4HSNUDH6emeT/l58v7Wov
tvKID0kRlo/bZu6qfgiEMJlMhpeXRXErgwNKqSzLqqrs7kSPB26Xy+N2h5eXtzVroJQKgsDj4nVd
L1DHopTW1NZ4PG5OOLYWpfLn8nPnTkeikdGx8cL3ChljJ0/01tTUbDY3b7pMyX6Sf7G9vX3g7mA8
Hs/xSIRgWjcaG+rb21sBAAsLC1y7ymdXlFJFll99+UVZkgoRLHOq4fPPPxeJxmZmZh/OlqCUiqIY
i8U+/vRzCIEgCCR7a/zUO+JYEMK0rn918VJK07j6xQ0O+Paiz+t1OB2iIDAAKCHJVCoajWlamjEK
ERIKDtLCGKf09JUr1957711REDY3yIhcu35z3e45p8injh8v0CY+l4Xqdrvf+8bbP/740/n5eVGU
cg+FbxECUFxmzDbBKrjLInjiz//pItTWKKWQZ5rk+eE+pjl23bkYY5QxwDz1dUf/5E8XVStt9i8N
Lz7X8OJz9qu4Cxz5yW8/DbeZTKZi0Zi4+dzPZ1xJkvhMVoRjO39ZVVV1uV1LwaAoCltPoBjjeDxR
U1Oladrde4M78HLcoXNmpho3Qi+++PxSMJTYLtAtN8yIolBTU/MoJVwgQhAARZF9Pm8kEsHZdQK3
Zu3q7BAEIRqNfvHlRYvSfM4BITRM49TJE+Xl5fziC79TAeOXX3ohFArrur7hPp0gCGtrEbfbXVNd
nUgmuakYpUQUxW1pcT53URTl+o1bPCocAGAYhsPpbG5q6GxvL68oFwUBZ4PxAQCEENOyVpZXJiYn
Z2bno9FogaHilFJZFGdn5ycmJnu6j2x4eQyAvv7+RCKRv8PO5aua6ipZkXf0+HgzyrL8zltv/OCH
H6ysruaahTKW1tO5xbU9Ph8SgpVNE4UP5mvs6AHui6knBJCvE4tHQoAQYggB4IYwRaIJQQhzTg0P
l9ChhDBCiu6FhJv+mt/CwcY8McYApZuuqotMC4QIPkq45PLyKi1gyhcwFoXiHdC40OLxeFimH21T
M0fT0vF44vjxY/eGhgvXTmKx+E6fPp8yXU7nM2fPfHr+C1zYaMYYYJQ8isMzf8NwVrDJ5aZRSku8
3va2NkrZxUtX1iKRdboa3wntPtK105mcX63P6z3ee+zSlauqItON1GiMcSwW6zx9uru7a3l5OZ5I
RiKRQGApvLy8WUj+hudKplJ82880zfa21nPnzlSUl288DQuCIAj19XX19XWxWPxOX//g0DAPPy+k
ebGA7/T1t7e3SqL0sHy1sro6NTWzoWLndrt3QY4z1m4Ox2uvvfzDH31Is0U7KCGaZm8RHjqCxQvL
7JxUPY55jpAizJhglDLGcMFjwcECYQyKe5OrKN8JCLjp3xN/mwCEl8PbqhSMMUHEYhH3eX4vpSU+
URALTCWLxxO9x8pqqqqCoVAh8gnGmLtoejzuHY1L/JOdne3DI6OLfv/Wbq5Z/YOEl1d4ANZuFwkA
QkAotQgnapkjE0KOHOmSJHFwaPjhAo5ceqmqqvT5vIwxtKuxt7299d7gUCqV2pDBcFXsTn9/U3Nj
W9ZrKplK3b07eOv2ncKzAXLs6uTJ4y8+/1z+FuemqyYAPB73q6+8VF1d9dXFr03T2nZ3mF/t6ura
2NjEsaM9Dz/3ufn5WCLB60c9pCGiXXdmxlhNdfWZM6cuX76a86/Xdd0enA8VwWLM0o2lvn5qWuuU
DyQIEKEDWa1DACkhjvKy0o62+29GjgI+fr6Vy0aEGYkFAhCZnk0sBRHGRWI0BQFklFad7BX4fke2
lSIzs4lAEV0nV4CQwN0uNhhZiGl66mpdtdUHI4QzBiDU1iJrE1N4k4mQWhajtBiWIxBASqni85Yf
6XwEBWulEK7AC/sW+XjmdrkEARNKt70fhCDPyTrS3VUI6eGCRzQWWwou7ZRg5b7ee6xn0e8vZH4l
lCwu+o/3Hnuk1wxAQ9dTKS0/MMvpcnZ3dyUSyRs3buGHGAAPV991MWzODEp8vvq6uuGRkc06DMZI
143Ll69+9zvf5J9xOhzPPXsuGouOjU1s+yxy5zJNs621lbOrbWPF8qPiujo7RFH45NPzBZ4IADA6
Nt7T3ZWf4Mxvdn5+YUNll6dQPOK0c6L32Nzs3KI/IMsSgNA0TWAXfj4sBItHRvf/l/92/h/9cyRL
D+zzMYAlESJ0IJMyhIBS6qys6PjmO0f+2HerTx2H6wQkSu+bsO95b8tuDHEn94y9e56+F7o7OPqD
D8be/yi+GEAYFYnTO0TISKZe+Sc/98zP/k3GGMxyhdu/9lt3fu17ostRLJ6xAADAkCBsWEgRYZSO
xrp/8jvv/MK/woJ4UPpl3298//K//QW1tGRDKzhqmkWy6woRNLV061uv/bHv//ruYl8JIYlkctut
KMYYQBAVpVdFPlSHihDims32JIYQAEBzY2NZWVk0un0dQwghsazFRX9He/tOuyX/fFNTU1Vl5VIw
uG20u4BxKLwcjca8Xs+jvAWJZGptbY3fGkJI07TeY0cdqnrx68uRaFRV1XVqHw+Taqivf8SJvLGh
fnxiYrN7pJRJkrTo909MTncf6eRu5gihzvb2ycnpAkkPIcThcLzw/DNchSo8VozfZmtLy7lzZy5d
urp5dfMHyPHKymogEKyrq81ncoZhBIPhh2UwxhjGKLC0ZFlWfjTYTqmqKIrPPvvMD374PmMAY2yZ
pmVZwkbh9jbBKjJ2RSlEeGV88tb//Ruyx4Nlab1dCmMH5VrOABAgTC2v3PrV3xr6/R+Wd7W3vPl6
wwvPeBrqFZ83K609xLceELdg7lbgQwd/4B6zv80JPCj7PuS+SHQjHY1GZucWr96YPv/V2sRUcnlZ
kCRBVRhjxTLnQCC5nTd/+ddb3ny9oqcrw7EAQFjAkohFkeEi8hrgudQbzPeUCrI8e/FyIrDkbWwA
9PEmzDAGILS09OQnn2FZoqa5cd0YjIskLhBCSAmBjxAalUppxLIKU7BgMY/p/NqcTifGGBgGKMAZ
khBCCHG7XU2NDX39a4V0WkkU5+YXNS3tcKg7neQoZZIkNjc1BkOhbU8kCEIkEln0Lz4iwVoOL+u6
oSoyA4AQ4nQ6u490xuPxoeGRdU5LuVM7HKrT6XzEB1FTXY0xJpszXc5a+vr6OzvaMc4Mom63q3Bn
Mkppe1urz+fbXfswxk709s7MzC0uLm7LdzHGyWRq0R+oq6vNfR1CGI3GrE1eH4RQNBqdnJru6uzY
3RXyr9TV1pw6deLa9ZuAMS2dtggRhENZ4/gpU7AgBJBd/YVfivuXFK9n40ogBzeeMkqxJGJZtlKp
xRu3F6/fAgD6mpsqjx3xtbWWtjS56mqcFRXOinLZ69lRQDTc5AZh3qlT4eXU8koyFI4v+tem59am
psNDI/GFRW5SigVB9ngyZu4QFsvGG2VYEPRo7PK/+YVv/+p/QIKQuTvGGDdbLbbut9lYJorJUNh/
s8/b0HAQPQ8sD4+ujI4Lssw214SKpzF3Xb6JD/qJZJIUFrHE5eJiV7AURcC4kPbgwUZ8Wj1ypGtk
dNSyyLaG3QjjaDQaDIVampt21+Xb2lvv9A+Q7TU27qI5e6Sra3fCYbb48TTGmDLGJZ/mpqby8vLz
X1wwDOPhnTiumpSWlj66VOlyO1VFiW9ZuQghtBaJTE5NdXa0Z4rnIAxAQU7lXLLq6urc7fADKaWC
gI8f6wkGgwVQuvuKVD6/icZim10tT/+8eu1GdVWl1+tlO8w/zV8JnD19SkulFxYWWlqa5Wy5IZtd
FS/B4s7Ukx9/PvH+R9IWJXEOdPeLUQYAgYIgZrgCiy0srE5OEUPHgqiWlcpej+L1KF6P7PWo5eWO
8lJnWZnodkoul+R0Sk6noCoAAEFVIMK5OdHU0oBSYlpmMmGkNCOeMJMpLRLRlle0lVVtbU2PJfRo
VI/F09FYem0NAIglSZAl0enMKV331ZdiKgVNCREcjqnPv5j4+POu77xHCckILVyMZOxQvDOMUiwK
Ex9+3P1T33nMlu6MMYjg2IefUELwYWmxR7vIRCJBKSlgvIaUUlL0JYMyVVbi8QLy72Dudiorymtq
ajZ0b9rgawiNj0+0NDftbpewrLS0pKQktF1YPd9EW1hYWF1dKy8v20XIF4QwEokuBpa4PsQAQAid
PHk8Hk/Mzs1vRqEoZQ5V3ZMHoTrU2JYPgpvFj09Mdna079TLgFLi8XhKS0rAbrcyeQu0trb4bt1Z
zXND2KxZBFFcDq8kkymuKWZmE9PYwoAUYxyPx3/0wY9ffeUlvuvKdm7zAQAQRfGN119JJpMOh9Nm
VkVPsBgDEJop7fov/gqlFMPinkfyDD+xKGJZhtADGLN03fQHYvMLvHgzxBhihDCGEEEEAfft5eYF
OQ+D+8djjIFMHj6ljDJGCSOUUsIoRQhDASOMkSA4yssBN6mn7FAUpOMv5M1f+tXmV16UPe7D+M4w
ACAWArf7kuFlZ0X5Y7XVg5AY5sLlq5mTHhJK+ihIa2lejnBb9YWxw/EKCGKBu7eMu3vzvxzt6Z6Z
mS1kNEIQLi4uJpPJXe+j1VRXBYPBQj5pmtbo2Hh5ednuTjQ6OmbouiAIEELTsmprqmtrqu/09cdi
MZkLtBvdorhH5YQL2ckSBCEcXl5di5SW+HZ0cMuipSUlgvBIO/WcA7U0N62srGxPyCBMJJOxeNzr
9eQ/oK2PLwhCNBp7/4OPThzv7T7SVVLi2wXN4niUfdsnFcUYE8oohRAO/u7vB271i6p6iArZ8sAd
almUEIgQlmXR4ZC9HtnnlVxOUVGQKEKMMkHyhBDTIqZFdN3K+0NMk5hWJhEsU6oPC7IsOh2y2634
fJLbJaoqFkUAIbUsalmMUHZ45B/J4VjqGxj8vT84rHa/jCEBa2uRmfMXAAD0cfVPSgiE0H/zdmR2
Hu+qOu9hhEWsAtURSikhh4FgYaGwXgZwHsGqr6urqqy0LLMAx22U1LSJqelddE7eqcpKSwr5It8F
m56e4cn5hWcB87Ok0/r0zGxuIqeEnOg9Rimdmp7d2rxUQCiz6tzVH5Y1VjR0Y2sdkfObSDQaDod3
uoyklPp83h2VktwMTU0NhZ93ZWWZ/8h/s21eLb9HAMCNm7f+8Ac/unT56srqan7RnsKv/ykZkQ43
wWKUQYSSofCd3/geEg6zPVJGfKKMEEYI96a6LznAPPA0wNyfLPL5B8s/Gv/h8OypPTwRCqp65z//
11R4mWdCHr7XBmMzmZq7eBk89lS9havXk8EQlqQnXr5iGYJVUIVKHrHEs8SLHFgQtn1yPDgxl95F
KZUksa2tlRBaUPqhRebm5grPXFsHRVUL7FsYo2g8PjMzCyEsvB4mZ8zz8/M5607TNCsrK5ubm9bW
1paWliRJ2oLhWYQgBBHc5R9e+kbX9XgiXkBjAsBAaIcECwDAGHU696YypsftdjochVBeCMHaWhTk
RZAW4gyXK3etadrNW7f/8I9+9P6HH3PevKPyiHbc1QaLgaK7IggAhEO/94cr41Oq10MJOaxNm5/o
l9/zYN7sscGEAjdukwdzC++vFg/jLMsYFsXo3Fzfb/32Cz/3dxmhh/AOmKDIwbtDsYVFT30dDxnc
d9kMYzOZXLhyA8sSYBQ88WAMQEiygd6FECzDMA6DgoW3X1NAyBiQZCk7aUEAQEd76917g8lkEm/n
vSKKIncer6yooDt34yxcikAI6en01PRsx06ilLgp1PjEJKX36x93tLcKgjA1NcuNAzandHgx4J9f
WIC7XdowACzLGh+b0HWjAANbgDFeXY0Qi+CdLPhZYVuQhUAUJY/Xk1wKigX4dERj8Qe4slxoJRwu
ZWGMdV2fnp6enp4uKy1tb2utr6+rra3JHcQOYD/EBIsxBgFMhsL93/vvkqrQw7M5mOd6xeNBAJea
KNeyGeWhVDkLKwi5JWiuivP94YLlWTNkP8+yilc2fgshCBHECAmYny7zyV1UfT+wdbw4/Ad/dPzP
/YzoUCk9ZDSaUSqo6sroeLDvrqe+Lmc5sb+vBoSrkzOBW7dFh4MS+pSMUJZFCimNByG0SEbBKvI5
oMBro4zKkgwAoIwhBBljHo+nob52aHgUY7xFnigXrlIpbX5+obKiYodNAQEAsVi8QE5GKZVEcWFh
cW1traysrMD0OgDAysrKzNy8LEuMMUKIx+3u7j4CAJhbmN/i7vithUPL73/4EXwE7Zj7XxTo+48Q
TCYTJrGwsBMzZMY4wXqU3si/KEmix+NZXAxAcZsNTQBAKpnM/67P5+N0tpBryBbbRpzgrkUil65c
czrVqsrKxsbGrs4Oh0PNSarF7zlnE6yNBkoE+//Lf4stLEouZ/FGX+UsrXK8nhDLNKlp8aAogJDk
dIhOhyArgixhRRZkWVBkJAhIEJEkSQ4VK4qoKhm2IYpIlgBjjBIrbXBdipqmqaXNlGal0/ywxDBI
Om2ldUs3LD1tpjQ9kqSWBTFGgoBEAYvi/aJvuXex+CgXo1RwqGsT06M//BBhfBgLg3LdfP7S1fZv
vfs4xhoIAQDzFy+bKU32eJ6ecIcC5yYIoa7r3Pq8yFFgqiMvqZtT8vgvj/Z0j45NFPL0RVEcH588
cfz4juKs+Xlm5+YLT4/FGCVTyZnZubKysoLPAgeHRizLkkSR0522tlanw5HStLW1SK5szhYCWL6I
v5vVHcYFlvnj9Mg0rZ2+cSybBrgnKyuHs8AtQqgbRj77cTodqqomkkm4w5PyVnI4BMsiM7Pz8wv+
O339zU2NXZ0dVdVVAi7UrsImWEU06SKE4v6l0R98UKTRV9kSv9SymGUxSrk0BRhQy0pLO9rctTXO
qgpHWZlaVqqWliglPtntEl1OyemS3E7J5XzErH4zpZmJhJ5IGPGkkUymI1FtZUVbXUstr6bCy3H/
UnxxMbEUYoxCiACCECGebAghzIRtFQ0oIaLLcff7v1tx9IggHr6QbUqJ6FSnvrjwYiwuez37nUvI
B7Lxjz7FkvzUsCsIABAEsZBBHEJICE2mUqDoY0EIIYVcoCSIanYBlrupqqqq2tqa+fkFQRQB20bE
WlldDSwtNXCFtTABA0K4uOgPBAIYF26nyURRHB0bP3nieCEh1dzbbHpmhpfB4Tyyp/sIAMDvD5im
WQgv2RPuUli/ApZFBFFAD3o7P75pEQAIgIiFAgklY8w0zQw1BwBjXFtbMzw8sou0GL51CyHkQmM6
nb43ODQ0PNLQ0NDe2tLR0S5Jok2zDpOCBQCY/OSz1YlptayUWdaB1gBe3595YogejQHAZK9HLinx
NtRXHe+pONZT1tWh+LySyyW5XVuXWGaMgbwC7rCAtyt3doiQ6FBFh+qorNjgk4QYiaSRSOjR+Nrs
bPjeUHBgcG1yOh2J6dEIMS3J6cSyyGgRzc1YkuOBpXQ0imX5MJoOIBEnl8JLd/qbXnt5X8sS8iFs
eWQsMjWDZQkeHnEeQggxhrs0ogQAAJ7DX9DjQDCRTB0Gar69FEEIkWTJ5XLl8wDeDXq6j8zOziMI
tn6V+Xg1MjrWUF9X+MNijN3p7zdNU9rJfIwQWluLLCwsNjU1bj3d8n8dHR1PJJKiKHLdsaenu7S0
BACwsrxqWVYhXl/pdJrf4P53YGSaZkNDfTag6gDqzAIIRVEocHjkiez5rd3W0jw0NPyI4w/vHpIk
AQBmZ2fn5uYH7t473nu0q6vTLoxzGAgWYxAhbW3t1q/8BjXN9OrawS7T13cXCKlpyl5P06svVZ04
WvfM2dqzpxWfd8MboZSCXGn4XHBVJjoLAowL74lw3ZuW/U92fZH5GSIMMZa9HtnrcdeB8p6ujvfe
AQAQwwgO3Fu4fD04cM9/605sfhFLYnEl7UFoJJKH9OWECBqadu/3/qDptZf3VcFihEIBD//BD2OL
ftHhOETGJRBCM62Zj8B7BEEA23tyZjSbRDxe/NEhhqFv22iUUlmWXI4NjIUa6usqK8uXl1e2JSIQ
wqWlYCqVcji2T2fjc+Ts7Nzs7EIuOKkAN9TMxwilw6NjTU2N21Ix3TCmp6f56SilkiR1dWYC5CPR
aGGcCfb2HnOoimGYj6EHM0qPdHUebB1xXJj7/4YMvqamuqqqMhxe3jo3s3CmxWnWyurq+S+/Ghwe
eebc2eamRlvKOgQKlra82vTqS61vv84YO8hStRAQLX1/GoOQEeKoqGh585WaM6fua1Trgpyy1Qb3
qwzc/aAvuCH9ytKt+xeDJan27Onas6cBAOHB4ZkLl1bHJyCCxcaxDqvjAEJE1921NdS09nVTG2IE
APDUVp/6q39RcqiUHprmghAS0yjnBUN2NfjKkogKVbDQ2lrEMAxFUYp5rE+nDbBdph6lVJJkl9uZ
v9jjdEdV1ZampnB4edu5kJcLnJmd6+k+UgjvJIT09Q8QQgQhMxMbhikIBVUCxggtLS1FIlGfz7uF
dTiE0L/oDwSC3EfUsqyG+rq62loAACE0mUxsfS5eTqeiovyN1155ymbqwmP671cdy3WYkydOfPb5
+b3SLPhxuKQXDIY//PHHx44dffbcWVmW7OD3YiVYEAIAStpa3vrXP1/kTUYti7tV5Y98RTGVZTjX
g7yLUl42u+Jod8XRbrvH74/E9DgCsE78pT/3FDat0+VCCNHt8jRznpC6biiKUrS3Y1mEEAIKSLVz
uZzSJmXdujo77g0NG4axLR2hlM7NLXQf2aZcID/L9PTM/MKiJImcXTHGGurrVlZXdd3Y2kk/S+Zi
M7OzJ33Htyh+BwAYHhkF8H58T3f3ES4OaZqW1vVtp2dKmdPpZI83XRpCeFhVdggZY0e6OkLh4J07
d2VF2qsoEd7+oigwxm7f7ltaCr715mulJSW2jlWkClamMnGxbH88tGKgjAEGEUKHqlQ4Ny8FjDFC
GbC7/v6sDfj0v39te3jcN7boh7ujlR63G2NMTRMUYLBpWdZaZC2/VEixIZ1OU0q3JYsIoYry8s3a
pKS0pL6udnxicutdQr4BNzs/H4lES0p8W898pmne7uvPqvDQNM3m5sbvfOubt/v6L1++CsC2Ai3D
GE1NzRw72rOh/1MmjnBlZW5+gUftUEpLS0vaWlv5PxmGbhhGAfoHEwXh8DKeA1oAsheffz6t6cMj
o5IkFbjzWzjNUlVlaSn4/gc/fu/ddyoqym2OVYwEKzMEF+2DwRAQ8lgLz+3hCwYAY/RwUcNDxrH2
fwX9dDaty+XEGG+r1uQQDIabm5qKc5KDECaSCcuyCnFjr6qs3OI4x471jE9OFdJx0po2MztXsnkp
Pb6tMzY+EQqGhCxjE0Xx2WfOMcaO9XQP3huKxeNbUx+eS+gPBMLh5Zqa6s2m2MHBYdM0RVGEEOi6
ebS7WxAwd2lKp41ta9fY2N3gAQDAGL/5xmsul+tOXz9n3nuYIsBDBqPR2Meffvadb3/T6/HYHKu4
CBajNBkKE8MAEIEDCRFiAGGENqtiwRgSBUfO6CVX4BnC/ZUuHmVZkYsM4xAEM6WlwmGI8GGsTlO8
4xcAjFJHRYXoUPfpFETXE8EwOKTjFWOCojg3Sn0taF2DscvlSqW0Aj/vDwSKuTGSiWQhro+CIFRU
lIPNrQSqqyrraqsXFgKStE2ou4Dx2PjEieO9G27zMQYQQmldv3t3kOU4WVo/fvxoZUUFY0ySpK6u
jitXb8gyLiTVYGR0tKamemNymUjMzs3zOzJNUlpS0tbakhuuLGIV6BBGLGIPO7t7lV54/tmKirKb
t+6EQmFRFFHWKWNPOJYoiqura19dvPyt996xI7GKhWDx0s4roxPv//W/CzHMRWk//gvhllGbDBwA
YVR5tLvt3bcaXnlBVJQHXEYpzRRm5gUEH7PekN0/ylQnhBDxRMW8a1gZm5j48aezX15MraxCBO0l
4h4CIWSkUr1/9k8++3f/5r68HQgN/t4f3vi/fk2QD58DFoTQ0vWGF5595//3L3at/lZWVgSDQQi3
meD5zlokEk1pKYfqKLY1NL+eWCJhWZawec0TvtFZXV3ldDo3+wClVBDEjvb2hQX/tuWKIUJra2uB
paW62pqH24T/bWxsPBgKy7LEZ0qn09l79CjXpTCGnR3tfX33LGJuXbqYt//s3HwqpTkc6sPnmpqe
WVtb4xFyhJC2thaX25X7GKWUUrqt/yeEMG3otkCy607Y0d5eX1d3997g4OBwPJHEOOPb/uhjC7c0
m56eHhoePnb0qP2MioJgcVIy+sMPQoNDstfDCDm4/MFNI10ggIzRwJ3+0R9+6Kgsrzp+rOnlFyuP
H3WUlSklXkFR1oWY8NrMMPPVBwezB24Pgod+BR6gmOyh/2H5MhUEEGIE15ngMaZFonoksjY1u3D1
+sLla9G5+dRqBFCKJO5PaI9Ne9mDiWGM/MEPn/nbfxXuxyYsYyN/9KO1iWnRqTJ6+AiWmdZKWpsf
hZRUV1X09RVU2ISLMYFAkEsjRYhIJLq11RMEwDStpsZGXh5ni2jxluamvhJfNBoTtixRhxAyDGNi
YnJDggUASOt6X/9dQcCZikMW6e5u4ZE0GCMAgM/na21tujc0rCrK1tMwQiiRSE5OTvb2HssfZXhQ
1/j4JBc2CCFOh9rFc0vvSyCEE6ztSWosbk/eu34feV7hM+fO9vR0Dw0Nj46Nr61FAWDcfOERaRYn
2f0D9zra23NmpzbBOuBnbqZS4+9/pPi8SBBAYfWhDgQShNSyYgv+6OzC6A8+gAh5GurKOtp9zY3u
ulpXdZWrptpVVamU+GSPGz6KWQNc/1Pe/6z/N2KY2upqamU1sRRM+JcSgaXo/MLq5PTaxJQeiyOM
IUYQY8npOMSGCMUNLImJQMB/q6/umTNs75zEuXy1PDwamZqV3C5UsNlgcQ3ogOFHe6lLS0sLMZ/k
E7ymaX5/oK21pdjmYF4SLh6Pb31VDABZEqurKredJl0uV2Njw8DAvQKeAvL7A1pKUx/cxeZN1D9w
NxqN8hZmjKmqcurkiTzeQxFCbW2tYxOT20btcDI3PTPb03MEIZx/lqWloH9piZ+FENLQ2lKerV2Y
KYEHUYGW/bqup1Kay+W0R55dcywAgMvpfObc2d7eY+NjE2MTE37/EkIQIfQo+4Y8n3R1LTI5OdXT
0227NhwwweL7gzNfXowt+CFGRe6gyO1ssSTlNuASS6Ho7DwxTEap5HIqXq/scYtOh+h0yF6vq6pS
LfUpXp9c4lN9HsXrFZ1OQVVEhyqqKhKzNUAe3FJkgAHKAASAMWIRoutGIsn/aySS6UgkHY2m1yLp
SDQZXtGWl41kykwmjUQyHY3pkSglBIsiliUsSbLHndO6DpE75eEbsxDS48mpT8/XPXuWEQL3yAiN
E6y5ry7Hl4KKx0XJIQw92YsaTW6Xq6ysNLy8Im4p1WQX0HhpKZhO64oiFw/H4leSSmmJRHKLXTAI
oWEYNTXVZWWl206TAIBjPT3Dw6NbB3UxxkRRDC8vLwYC7W2tuTmPX1I0GhsZGeVfRxBqun6895jP
e9/Lim8LNjbUV5aVBYLBAvIWZX9gKRReqamu4gfhx7l7bzD/fentPbZuQVlgfUBuhRUOh10up61j
7Zpj5fqGqijHjx87cqTTHwjcvTu46A8YhoExFgRhd1HwEEJiWXMLi93dR+ynIxz4wAMQmvrsSzOt
yW734SABeSHkWBCwJPFuxAgxksl0NMYoYYQyxiBGECEIEUQwY53FA00RhABiUUSSCABAgoAlKdc/
qWUSw+DuppaWzkRXMQYYY5QxRgGl/IfcWRDCECMkCGpZCciZzDBqk6rHRyMYC9zqs3RdkOW9STVl
DGFMTWvh+k1AKXgqh6rcjkZ1ddXSUlDaTsdijEmSGF4Or66t1tbUFNvtxGKxaCSydQAWAKC+vk6W
5UJW/2VlpQ11dVMzM9spfAwAMD0909basu6YQ8PDa5GoqiiMUYtQj8d9bCO3PIxxZ1fHUihUgFAH
NU2bmZmtqa7K0bjV1dVFf4AXHzQMo7m5qaqyAoAHcoQQxlzk27ZLmKYZCAZbWprtgWdH/H6z94un
MjQ3NTU3Nfn9gcGh4fmFxVgsLkni1lF3mxN6KRQKJRIJt9v9lJPggyRYjFKIcTIUDvbfRRgfSvsD
xgAhOd/cDcLk8xP6AOCFCBkFAABimiDJAIAMsAe2fvL9Sx8wbocQQQgwEIT7wxLMBmUxxgCgdn7N
AfVkyaGGR0aD/XfrnjlLKX10N39GGcQoMjOzeP2m6HJS8pRyZT5A19fVDQ2NFLKkhhAahjU7O19b
U1M8Izun3OHl5bSuOxyOzSYtQoiqqh3tbaCAesa50oST0zMFzHnizOxcIpl0u1y50nLRaPTe4DDP
2EcQEkK6uzq93vVW7Pznjo72W7f7NE3bulV5NtnY+MSZ0yf5kSGEwyOjmqbxKB8IIa88QynLT2yU
RFEURU3TttWxGGNLS0uEEISxLWIV0km2aCL+r7kuUVtbU1tbs7KyOj4+OTg8kkwmuLIICt405KF7
kWgskUy63e6nvP0Pcn+UR+wu3RlYHZ88XBXWNu1ZjPGMwvt/2HrydN83AWMoCFDASBCwKOb+IEGA
/A/GmXcjy7Q2OBHZ5EQ2Hu+jR6KYCi37b9wGexWDBQEAYPHG7UQwhAThqX24vDHr6mo8HjchZNu2
pZSKojA2PmEYRhGNswgyxvz+wNbyFaG0srKiPGcHUwBq62qqq6tM09zO1R2k0+mp6en8X97pG9A0
jVcisihxu929x47mzGfWQVWUzo52wzC3fQQIoXg8Pjs3z1ediURienoWIcTFp8qqSl6ycN1hHA6H
sl0QfUYVEISVlbXw8rJNrAp5fUzTTKZS234ssw/DGGOsrKz0uefO/cwf/2Pnzp5xOh26rhfiLbLu
NYxGY3b7HyTBgggCAIID98xkiruNH/q+zIEQRIiHlkOMM3/diCcBSvkfRjNg2d+AXMXodcwsc3AM
efR69uBw3cFtPF5QSgWHOvPFRUvX96Qz87zUyR9/JvI9x6d4hmCMqYpaW1NT4BoaY5xIJGamZ8Ee
efzsCTQtvegPbCPPMHbsaE+Bl52tCS23tTQX8HkIAJicmMppFcFgaHRsnO8tIoQs0zp2tMflcm1o
k8O/1dHepqpKIWFSjLHRsXE+bk1NTa+srnJmCSFsb2uVs8pW/rWpqqIoMtku0JDXREokkzMzs/aw
s3VDAQBCofCP3v/wd3/v92fm5grpVzlBizHmdruef+6Zn/6pnzx75rQoidzst0CahSBMJJL2U0AH
+PwhQlY6vXD1+iGVrzjd4duCSBAgAJRSYppWOm0mU3osrkeieiRqxBNmMmWm08QwqGlSQu6H/SLE
/2SOgzHM/gbwDQJeUYIQaprEMPiRjXhCj0T1SESPxc1kytLSxDQpIRAAfiX8OLZy/pgZlqAogdt9
ET6v78XgGJtfDNzpQ6L4lMfS8Z7c23tM2C7IPQdCyMjYGNi7jM5Hf5qzs3PpdHqz6+FKQ21tbXNT
Q+GXzbcROzraXS7X1vIe5yWra5Hw8goAgBJy49ZtXdf5lGlZVklJydGe7q05U3l5WUN93bYFbfi5
Fhf9/kAgndbv9N/lxXO4w9bR7iPgwQ1QCDO5ii6nq8DFjCSKY2OTmpa2nd+37nW37vTNzi0kk8kb
N25tpk1uLWi5Xa4XX3jup37iu12dHZZFrAJUZA5d14vkBTxAHFgMFndJSSyFQgODWJYOwRQC4QNe
CYwR06KmSS2LWCZgQHI5JZdLdDokh0N0OkSHA8uy5HRIHpfs8Ugul+R0CrIkqIogy1hRsCQK3CmE
MYgxlmUIgaXrzMrUgrV0nZqmldattG6l01ZaN1MpIx7X4wk9GjNTKUvXzWTKTGlmKmWmUkYiqa+s
AgCQKPBtx2yiYsa5/YFoMBt73kEAsAxj+vyF8iOd4NG8xnh44tSn5/V4AosSsJ33ASgvK21qahwf
n1QUebtgLCaK4qI/MDc339jYUCRhOhNTU5QxYQtCAEHv0W6MhR0ltzPGPB53U2PD0PDI1iZSCKFU
KjUyMlr58otDo+PT0zO8mDRCyLKs3mM9G7qD5p8IIdTe3jYzO1eIX4Npmp9//qUgColEgt+OaZon
TxzfsBQ3P2lVZcX4xESBImUkGhkcGj575pT9amwxXyUTSUEQRFFYXl6ZmZ1paW7e0euQ469lZaXv
vvNWQ8PotWvXE8nk9rYpEBJiBwQfYJA7AwCC8L0hSzdEVSnqVQiEEABiWcS0GKUAMMAYFARPfZ2v
qdFVU+WurnJWVarlZWpJiex1Kx6P7PVIbtdjuDQjkdBj8XQ0ZsTi2tpaank1GQwmlkKJpaXozHx0
foFkgjMgRBAJAuKORDbN2o9ugiDEaPr8V+f+9l97xAmd7w/OfX2ZmRZyqOzQRrhnNrUfmd/wWaH7
SOfk5DRjbGtDt0z5l3R6aGikvr6OTxIHxbE4WwqHl4PB0Gb7g1y+qqmpbmlp5jxmp2c5erR7ZHRs
2zYUBGFsbJxQMj0zy8/CT11eXtZ9pGtrvYF/vqWl2efzrq1Ftt7r5CJWLJEAjGGMeA60qqpHOjvA
Rklt/K/VNdWCIBQSacePf+/eYGdHu8fjtkPdN+xUlFLKGAAMIZRKaePjk01NTRDsbPWXk7IghD3d
XdVVlV98ecEfCIqisPVmt10t50AJFmAAwLnLV610GkJQzASLWhYlRC0tcVZWlLQ21549VdHTXdLW
ong9ksslqMqmYwDfCryfCQgf6tcbObmzDX5aL0DxkjgISS6X5HK5a9dnpFu6bsQTejQamZkPDQ4t
3e5bGZ9KR6LaygqAEBexm+uhHtKoRcL3hkN3Byt7j3IXq13KVwitjI77b/UzxixNO3QG7vmjs6Wl
iWHuyXK8qbGxualxemZGkrZR9Xhw0uT0dGApyB3MD1ZIGBsbTyQSqqpuqP0wBjBCp0+dLNBP9eHj
V5SXN9TXz8zOclFqiw8bptnff1eSpFwGPmPsaE8PDzDfxgSVMVEQjnR2fn35Ci4gTxZBCCDM8d2j
R3tKSku2OEtFeZnL5YpEIoWwJQHjaCx+9fqNd956Y/8IFssWIjuMdIHH9fIhRZLEufmFyFqktLSE
7dxHJkezSktLvv2t9z748ONFv3/r7ipJ9ixzgAQLQgCAHomWdbYLqlKkUwgEjDK1xFd79mTDC8/V
nDklbWQfvL4WYbY/Ql4TcOcnBRvQro1+lfXHyv4MAGAQIoiRIMuCLDvKy0raWlvefBUAYGnppb67
85ev+m/cTobCAEF732nPgRA0Ulp4cKSy9yijDO5qTGaMQQBWJ6ZEVa3s7TnUBg28FqG7fg8sqbi0
c/bMqUW/v0AWQim7dv3Gd7/zTQEfzEDHJ/54PD4+MbkZ9UEIptPGka6O1pbm3REFLud0drbPzM4W
8kRUVc3xBkppaWnp0Z4joOBwmY6Otjv9/bpuFH6phBBZlrs6O7isstkXEUId7a1Xr90oxHGUMibL
0tjYeH1dbU/3kT3nWDmDg8OrjZFssC/LZn5Mz8yWlpY8oiomy/Jbb73+B3/0w0Q8sVlYJANAkRWw
uQWXTbAex8LulX/6DxkhRZ3+Rpni84jZwquZzpSpO5+hOzyV78Aa8eESh9mXKnedAABBVeqfP1f/
/Dmi66nlVYBsRX0/CDmkxJKcTgAAEnZphcU9tBpfev5P/M/vIYwPPQ1mLBNr+GivOYSQMVBTU93V
2XH33uDWUk1GbhGFhYXFwcGRE8ePHWDVjv6Be9FYTN6oVjev/efxuJ595twj9TsAmpoaysvLV1ZW
t9m7ASCnokEIiUVOnzzBpYhtJ8JciZ72trY7ff2bCXIb3aNVU1NdV1e7xQYov4CW5uZbt/sYKNRy
CSF06fLVstKSqqqqPXzEOY+uQCB4b/Ce0+l89plzeI8qNDxOBYtl6SylVJKkoeHh3mM90n1f612s
IRGl1ON2n+jtvfj1pU0fDWU+n9eeEQ7Yyd21ZcmtIuqplnXfDQEUfa3k3KbkgzuP3Nsdy7K7rsbu
+kUO2euRvR67HR6aUsHZs6fnFxZisXghSYUY4zt9/c2NjV6f5zEvpvnpQuHwvcGhLeggpfS5Z57x
+by7vjyehacqaktT48rKSuGElQd+tbY2F74vyTlNa1vL8MgoydSz3/5LAIDeoz1oy4w/zt7Kykqb
mxrHxic25KMbzve6rn/0yWff/uZ7ZWWle/KIGWMIwVQqdfPmnaGREV03GKPt7W2VFRWHK2OREkLz
LhhCGIlEh4ZHTp44/igNxZ9UU2PDHZdL0zQeY7euAVVVsYtFgoP1wco8iiIGYIwRQi2L21kdbqMp
CLgZBA8pK/KWP9TI1xF391IchpdjZ+/RHiq2bpfr5RdfzMVobz26YIxjsdjFS5cecyVH3g9M07xy
5fpmLqCcHBw72tPd3fWIzIC3Rnf3EV5jp/D2PHa0m1OZwo0hGGO11dXV1VWWZRUgegHLohUV5c3N
TYU8L4RQT88RSZQK9w0XBCEWi3/40SfBYCjn4bTruYhf5OTk9B/+4P07/f2MMUWRJEnmdX7uh4Ic
BhDCQF5n4HEroyNj6bQOHsEijgsNHo9blmVK10fMIwQty6qsKHe53OCpt2k4YIJV5MsBxhjEGAkC
hJBaFiP0sObfcT8tywIQcqMs2zxmf2WWRylHCCFgwH5AW6yeW1qaTp44zp0Pt30WsixPTc1cv3Ub
QkgfV6syxhCEff0DM7NzG8YCQwh1XW9saHjxhef2ah7y+bzNTY2F8R5oWlZVVWVXVyfYeQQ3xrir
owMV4EEFIbIsq6f7SCFyY7awdENTU8O23vT5TS2KYjQaff/Dj8YnJvn0v9NCxTwyDEKYSCQ/P//l
R598ura2JssyhDCtG83NDSUlJQAA07IKfDFh3lbsQc2plFokjzozxiRJCIaXxycm+Ib7I8ljlDJG
N6xwSAiprq6SJJE+9cVwD84Hi9Jb//dvBG73FbHLKGSUumuqml57ufbsKeFB+5YH1uW5jcMDJ+vr
Sh/e39PMuMAT0wzcvDN74VJ0fgEiZBss7dNDwILw0j/8+86qip2lRDMGINRWVy//m/+oR6NQFJ6A
8gbEMKt6e879nb++txzr3LkzK6urU1MzslxAMJYk3r7dX15a2t7e9hg2CrkSMzk1fePmbUkSNwm9
skpKfK+/9grfPdw7J4uu0bEJWMiLzcCpkyc4p9nR2fmH29pab9y6HY/HtyBnEELDMMvKSltbWnZ0
/OeefWbRH9gRxxIEQdf1Tz793O8PnD590u1y5Y+IGx4n/58QQrpuDI+O9vX1x2JxURL5aE4IcToc
z547x29TS6cLXDpBCDVNe8wSDn81TDOTtEvoejGPMYAxun2nv6Wl2eV07jqpAkKYTqeJRR4e3Qgh
DoejpbnZlq8OkmDpkdjYDz+cv3JdcrlY0TqSQUhM485vfr/q+LGKnq7ac6frzp5219eB/ITBvG7H
LAoYA/DB8PMHQ9H3kkLlfmZ8BxBDtPG54oEl/83bgRt3wsMjwYF72soaliTbDWvfug2gllVz9tTx
P/enGCWw4NhYSigS8OyFS33/5b9lQugOf/koM51Or0XO/Z2//kiq3kMQBeHtN9/4UfrHgUBg630x
Ph9QSs5/eVFR1fq62n0NeOcHn5ub//z8lyDPqnEdu3I6nd949+1HCb3akPfU1FTX19XMLyzKskTp
pkUPTdOsr69rLWDbbrMmlSTxSFfn5StXVUXZUhekrc1NLlehczlvrtLSknNnT1/46mtFUQpUQXJJ
f/0Dd+cXFo52d/f0HOES1P3xOe86UZ49m24YIyNjo2NjgaWggHEmYA5mJKjXXn25rKyUP9ZoNEYp
FQS09djJGMNYCCwtnQLHH/25AgAsyyxk+Q4htAiNx5O+khKYZ9PwABPFOBqNXrl6/e03X38UKr8a
iWi6zotsrutazU1N1dVVtjnZQRIsLRrR4wm1tBRLImPFKiQyAJGLErp49cbC5Wv3fvcPJFV1VJSX
93SVd3WWH+lw19ZKbpfkdskuFxIFuEXi2PpglI0csB46e/7/gGzBwY0zB/lgZllGIsnd3hOB4PLo
2PLI2PLwaDIYNlMpI5EAEEpOp6O8lFEG7DzCfWIVCOux2OyXF4//uT+1s0aGEDA2f+kqo1QtL6Wm
ddifEYQQSoLoUPdjpa4o8jtvv/H+Bz9eWVndOqmQB2OZpvHRx5++89abjY31uS2h/dCuZufnP/v8
vGmaD9sN5LGrtyrKy/d2EqKUCoLQ2toyv+DfygMSAITQieO9CONH4ZrtbS0DA3dN09yMN/PQ+57N
K/Bs8XBPnjgeCi8PD48UGO2egyzLkUj00pWrA3fvtba2tLQ0+bw+1aFghNc1taalY/HY9PTc+MR4
NBpjjMmSxHlYxqWTstdfe7m9rTVHU4KhEKUEALz10odnsM7MzAUCwZqa6kdpZL5kXl5ewXj7DQcI
oWEaS6FgY2M9AIBS8rDlFWVMkqTR0bHamuqjPd277oEBf0DTNMeDmaR8R/7sWdte/6AJVjoaTYRC
ECNqWcXcQIwCAKHkcQMAGCF6IpGOxlbGxkcoZYRiUXRWVbpqqpxVlc7yMrnEp5b41NISpcQnu92i
0ym5nJLLKTmdgqrsyUiaKUeYSBrJZMbGPRLVVtf0tagW4U7uocRSMBEIEkPPlprGECOEsez1AgAY
pdSyixjsLy9HghAeHovMzvmaGgt0HGWUIowS/iX/rTuCLNNM2YDDTjYhI3Q/boRPw16P55vvvfvJ
p58Hg0FZVrbWsTDG6XT6o08+feXll450bWwpvmtexQDgacaDQ8MXL12mhD7MrhBChmGU+Lzvvvv2
nrMrkCtN2N7W1383EU8gjDaZg83mxsbGhga2W7tt3vi+El9jU+PQ8IiqyA+rZZxKNna0lZT4dqeT
vfzSC7F43L/o31HkPmeZAIBEMtnXP3Cnr7+kxFdS4nO73Iosi5LIGDB0PZFMrq6uLa+sEEIwxhjj
nNbI6/xgjN9845XuI/fzD5KJZCgcKrDFOEX74sLFb7/3rsfrAZn9hp01Q64MwPTsnCRtKkmCvFU7
BGBqauZ471FFVkyLcFO9DbvK15euetzuhob6HfVD3mdSqdTE5LQkPhBlxe1kn3/uWZ5uactXB0mw
9Ghcj8ZVn5cWf8UixnKbmEgQgJC1QYAQMKatriVDIWJalBBmWRAh0aEKqoplGUuiIElYlrAkIVFE
GGNJEhRZVB2CqkCMsCAgReaylqgoACIrrfGuSXSDmCaj1NLSZkqz9DQ1TEoIMQximMQwiGEQ3bB0
3dLSpqYxQng8PhIFLAiCKgsOFTB2P1kk7y5s7DMpp6KirE1O+2/cLpxg8W4QGhxaHh5TvB5qP6wC
5jAAQInP951vvffxp5/Nzi4oirxFdgCP1LEs6/z5L1dWlp85dy5nGfUokwGfBSEAKU27dv3G4OAw
Qijnk55/qel0urGx4a03XnO796u6C2PM4XC0NDf1DdzFcINcFr5JdOJEryA8aqYLgqijvW1ycopS
uqEUjxDqPXp0F0SWh2CrivLu229+/PGni/5A4XuFWSoDEELcuSoWi6+tRQihlFEIMwbLCCMBY0EQ
cjw41xN03XC7na+/+kpzc1PunxBC94aHI2vRLfZeHyb0q6urP/rwo5dfer6xoSHnR1WgdMpPahjG
ha8umqYpFmCJRxkTRTEUCl2/ceuVl17EEBJCwUMJg/zIpml+8tnnb7/5Bq/XuaO34HZf/+rqWn74
I0IoraXbO1rPnD5ps6uDJ1ip0PKhfAL3I6CyHUvASBREx/2QLEYpI9RMJo04ZYwByhijjGb3B2Gu
J6+z1IIA5sWns/yxImu8ByFEEEIIuCkXQhBCQZVFpyMTr5Nzl6AMAHuGPsDJHzBKFy5f7/6p7xQY
g8VJ2PT5ryCEdnDcTinFt977xlcXLw2PjPJpdTPqwKcWxtit231+/9Jzzz3TUF8H8spQFTbzZb6R
i482THNycurGzVvRaEwUBQDWB6YQQvi21wvPPyuK4r4GgTHGjvZ0Dw2NbBhcbxhma0tT0yPXwObf
bW5sKCsrDYXC65IEuZjR1tpaWVHOdnl8wBhzu1zvvvPW5+e/nJmbV2QZ7NBcgH84J1BtoDs++JgY
Y7quNzc3vfziC6WlJTkyxI0b+voGBEGkdAeeYYIgRCKRDz78uLWlpae7q7a2JudWunX783/VUtqn
n38RWAoWXkOJ51T299+VRKmkxAc3Cd1ijIkiTqf1jz757KUXnu/pOZLfthu2FcjmSg0ODvf1383f
lIcQptN6Q2P9G6++iu0U9WIgWHx/8Al4EhlC8/DiDmDA36VtRrEHGdWWdXLWjfH8S4wyRi27KxcV
KKGSyzl74evU8qqzsgDBnDEAoRFPTH9+QVBkW2vcodrBJEl6683Xa2qqL1+5pqXTkiCATUwE+C8l
SVoKBn/0wY/bWpuP9XTX1dWBDaKhMw/toeDo+6+nruvDI2MTk5OBwBKEMDsR3l/WU0p1Xff5fC88
/2xHe1uO5O2rqldaWtLU2Dg+ObEuNI1P+adPn9yroQ8i1H3kyNJS6GFVD2Ohs7MDY0wZQ7s0UIWM
Mbfb/d433rly5drdwWGEoCBgusO6avkC1cZSHEKUUtM0ZVl+4flnT508IQhCjgSn0+n+u/f6+gYI
IeuEyQJ1LMbYyOjY5NRUTXV1XV1tR3trSUnJtuwqGAp98eXFUCi0bdGCDeZ1Qbhx85bT6QSAbR4h
xzDGlmV98eWF+YXFc+dOl5aUPMw+8+sFMcZu3rp949ZtniHAWI6VGi2tTe+88YaiKrZ8VRQEK72y
CuGTW237wVFtJ1/c4Ccbh7EDIEGILy35b93p+MY7Bc1VAMxfuZYMhZAg2O23C1bBGDja011ZUXHp
8tX5hQVOdzbbV+ILfcbYyMjYzMxcZUV5V2dHXV2dw6GKorhuhlj3V8Mw0ul0MBSemppeCgbj8QSv
Q/KwBpDWdVmSjvcee+bcGWc2K36/px/ODDo62yamJtbRiHQ6faSrs7amBuxdCn1ba8vNW7c1Tcsd
kKeSVVRWtLY0gWyY9qOwZ1mWX3vtlcqqyus3bkUiUVkWIdybxTm/Zl3XBUFobW5+9tlz5eVl4H6k
kTZw797o6FgsFscY75Rd5U8FfDdtfmFhfmFx4O696qrKM2dO12yUasd/Mzw6dunSFU3TdsGuOERR
TKfTWz/nTIfEeHRsbH5+vrm5sbu72+v1OFQ1P8uSUppKaUtLwTv9/UvBEM7ugPOYelEQz5099dyz
zyCEOOWyR6SDJ1h6LA6esCfxoDUDyGXZr7NUeEiC2vhgeYfd8Pgw9/Xs8R/4q40i4FgQoYn3P+54
753t2TJjAKHJH39KTBOLUvHm1Rb1+wcYYxUV5T/5E98eGh7p6x8Ih5c5W4IbqVnZmU8mhCz6A/ML
i4osV1RWlJWWetxu1aHKsowQQgCYxDIM0zTNVEqLxWKRaGwtspZKaQhChBAPqc6PYqGUWpYFAOxo
az1+7Gh9Qz14jFVv+Vnq62orKip4C/BrI4QoitLbeyxHwvZCOwSqqrS3tty605dfmhBC2N3VyfcN
4R7UoGQAgJ7uI7W1tX19/aNj45wS5W5hRxQknzdwU9ampsbeoz2trS35zzGZTP7ghx+El5dFURRF
cUOq/cAgvV0BRQghz4g0TXNmdm7RH/jud75ZU13NHvQChRCOT0x+8cWXAEBJkuiW3vFwy0kEIcRv
aLMtvxwkSTJMc3hkbGh4zOt1V1RUuF0uWZYBYLpuJFOp4FIwGoshjCVR5H2Je0A01NedPnWyqakR
PPV1nYuLYBnxBETw8LKBjA9WxjoBMEIZIYRSRgiPwWKUMkoBgghhiBGPlwIQ3Q+iAgBAeH95xylZ
XpmUbLwXYzQ/lovmjg8QRNkkQYgQxBhhnIn4yQVj2XzrADsJQv5bfdrqmlpassXowwsGpJZXlvrv
8e5ky5ePMhlDCHu6jzQ3NQ6PjA4ODsficUqpKIp82f1wwC+EkJMkQunCwuLs7BxlTBREURS43EQo
tQghFqGUcCUDYyxnJSt+BH5w0zS54tLU1Hi891h9XW3ukh7b3MPz1xRFaWpoCIXCuV9altXa0lxb
U72ne5QMQtja2jI4PMIjlnjNCKfT2dXZsVc6WW5/yuf1vPbqyz093XfvDs7MzmqaRggRBAELGGbj
3jYc8bKLU8gYI4RYFkEIybLU3Nx07GhPXW1NLnIox+cW/YHAUtDtdnIuAfJ2zfL/N7uszYzh8IEz
5vvqPLDRhhBKJpNra5Ga6uqHr3N4ZNQiVMnLnaSUPliLi+Uv2PNPlX+i3F42pbwsIeWn5n04dzE5
NsZ7RSKRjEZjhFBuBoYgRAiLoqAoCiFE1w0AgSgI1dXVJ4/3NjU18kyRx9nDbYK1PdKJxCFSsO7X
eGaZFQMxLWqZ1LKoRSghoqrKbpfsckoOh+hySg6H4FAFWRadTtnjktxuyekUFFlQFEFVBEkSVIV7
KAiqkomuRQhCmMsds3SDczUrnbbSBkmnLT1taTq3s9JjcSOesHTd1NJmKmUmk0YiZaZSRjxhJBMQ
IiQIUMBYEJEowHwOxzL/Z2PfBSwAsCimwuG5i5e7fuJbgFCwiU0aIwQKgv/G7bXpGVFVbU786K8q
pdThcJw5far32NGR0bHx8clQOJxKpURRzI93Zoyt+0EURSmPOeX4kygIUlbGeDgy2rKIaZqiKJSX
l9XX1R3p6qyoKM8ncAfSCN09RwaHhw3D5BeJMD7ee2wfGC2ora2pqa2enZmTJAkhpGna8d5jyoOl
L/aKPQMAKivK33zj1UQiMTo2vrCwuLoWicViPOoL8TVn3mTPnyChlFFqWQQh6PZ4Skt8tTXVnR0d
Pp83y2AYX/Pm4PF4vB6PRSy+RoYI8WB5AWOEMcZIwHyvLHO6HLmjlAIGCCWUUEII/w+xiEUIz3Xg
klhnRwfXzB5GfV3t/PyCbujZ+rGZbEdBwJn/E4TcqQEDlFHOGoll8bMQy+ISE48IRAiXlZXV1lTH
E/FoJJZIJbWUZllW9iC5m+AbhljIRilkWo8QwzAopQ6no6q0sqqqoqO9va625gB7uE2wtgE1TYQw
RKjIRSyIEKOUGCYlFsiKrVAQ3HU13uZGd3WVs7rSVV3lKCtTfF7Z45bdbtnjltyuxxNJwyjlfItT
Lu6JlbHCWgrF5ucjs/NWOp1bYyGMkSggQWDU3oTadyBB0FbXFq5c6/qJbwEEN7YyZ4znDy5cvWEm
kmJ5GbUsgJ6QAQvm8l4fc8tnw2UkSTree+xoT/eiP+APLM3OzoaXV7i4my0fhR5cfGdje7N5nevk
Lo7s1JURDMrLSxsa6murq2tqqnPE4gCX9RmfKq+3taX57r0hh8ORTqcbGupraqrBXhcwYYwhBHuO
dM3PzedCptrbW/dj6s2JLhBCl8t15vSpM6dPLa+srK6srq6trayuJRKJRCKZTqfzg+EkSXK7XC63
s6yktKy8tKSktKK8bJ2Emc+u+Fmqqyp/8ie/nUppCCHOpDizyVIcLArCFqlIOamMsx4rCwaYgAVV
Vbxe7wOr9zycPNFbUVFhGDqEiFM6URSxgLmqKghCbssyH6ZlWaZlWaZpWZxoUcIoowAwjHGJz6eq
KgBAS2nRWCyRSMQTiWQylUwlU6lUMqml02l+hfntIMuyw+Fwu5w+r7e0tNRX4qusKBcfXGnY7KoY
CZaZSFmGTllxl09mzNLSWJGd5eVKia+ss6361InSzvaSlmbZ4xadDkGWt6A+WRID86Tjh7Nm4QM/
bhbkzjb4f4gQREj2eGSP5+ELIIZpaSkjkYzOLqxMTIQGhsKDQ8nlFW11LbW8Iihy4SVcbOyanQMI
5i9fTywFXdVVjNINgiEAgAhpq2vTn1/AsmTp+pPEfSGExDAPxEw4X8PAGDc21Dc21J8+eTwSjfr9
gaWl4MrqWjqdNk2Tz0q5DfvsF++HUPK9FQYAn+pEUZREUXWopSUlNTXVNTXVTodTlqWsFkLzt2kO
dPRiZ06fWvQHwuFlQRRPnOjN7VfuKZeFAID2trapjpmhoRGLkNMnT1ZVVu6fsPGgAAnLy8rKy8pA
NqbKsixCKKc1CGNREHicnCBgnDfi5S5vi4ssLysDZVu3cHY4fijQie87C4IAgLzZ09ns1Ahh7h6y
9cPNjB7Z04mCIAoCAJsKh7xnqg5VdagAVK0ngpyOUWpZJmWMNxqnd/yHdcex9wSLmmC5qipKWlqQ
gIs23oQxgEWxrKuj7pnTdWdPl3Z3IoS3IlI8fCY7QnP2s/PBYyPitTEdy3/PWN7am/FTY0nEklf2
et11tfUvPMM/Hp2dC9zqX7x5KzQwqMfidr3nfZ/lETRTWnRmzlVdtfFagjEA4drklBGPexsanrTw
dghJWldKSw6W5AEAKGUQAkmSKisqKisqwAlAKV1ZWU0kEvFEMplMplIp0zQppaZlcYGKb5cgCPm+
oSSJDofD5XQ5nU6fz+NwOB4Wt7gkViTUljHm9Xq/+Y13h4ZHqqsqW5p2WXmwECYHIXz91Vd4nn/v
saNwE4+M/Xiy+S0vSRLf4d3sOnOyYoFWn1vUz8xFOoEti0lvsKDaRLh6kAzdN/t4+JMw/9xbny4X
pJU1+s/FcGXmq/tEcBvQ7PqwSHr44Rj/DirgIxkMFXuRHAAQxq7qqnwulf+2wY0VqWJiiA/UM2T5
Baq11TUzlYLQJlj7/opRYqmlpZLLucWH+N5uhu8+SQ8EQkap6FDz36MD13XA5jMcA4xYPBwYQJgp
CbzhjPKwUbuNonq+G4peNnbUbnbTHVaCdYi6HSNkl3JUcd4OpRAAe3/Qho11NVK2mEvo/Urt8EGn
lP2d3nZCZTfNUeVbaWj/A/t41luBCsej3PIWN2tzAhs2wQKZbbUipncMAEAptz940uYVShkhIM9K
zsY+v2f3TRg3nRYoA0/k02AAQHCI1if5yu8hekHsZK6HDaXsgcfGU0qwDtN7SwjLLXAP80vLGON7
+8iWr2zYKJ63EoDbd/qnp2dcLqeqqqqqKIoiiSIWBO6KzgPxDcM0DMO0LNMwDMOglPG0f5fLefbM
6fLyssN11wN3701OTTPKBFGQJUnN3LmsKgoAQDfMVCqlpTVN0w09bRFCKRWwoKryka4u7mz5MLsK
h5dD4XBra4uq2DVbbBw8DizI/eYv/3p0dk5QVCjgItWxICxrb6t95kxJazN8eEzMXXO+wXrxDNj3
mzTjeJf5CWMIQDIYWrhxK3i739Q0iJAdhbW/QJAYhru6+szf/CuiQ71v1sAYgFCPxu/85/+SWAoi
SQT0iXsSEFDTKjvSeeov/3m7I2wmugSDoVu376TT6ay7xAbE4EFHy/xRCtIADSwFf+K73yotKSl+
VsGvsL//3pdffbWuRPS6G2cP3i9f4pqWtbyy2tjY8EAuIYQQwrv3hi5fuZpO62V9/W++8do6k3Qb
Np4igjX1yfmZC19jUSzSpHQIGGUI45K2lvLurvLurppTx6tPnVBLfGAjKSuTS8hTRB6uabO3L/kD
mYP8/7I7GgjBrEf8ui8Rw1gZnwjc7PPfvB0eGlkZnbDSaYixHeS+/0QdcSvaumfPNrz4HKWUK4j8
h9C9oa//1b8HCMIn0QEWQmhq6bZ33jz1l/882CIj6+lGzh1+i+KJWzdyLBa7evX6N955GyJYzKyC
929d1+/eu8dNXwtaoSDEGLUsQilDEDY1Nq7zm4AA3Lx959Llq6IgKIq8thb50fs/fvedt5oaG2yO
ZeNpJFjuuhrZ6xEVuUj3KFmmtlls0b82OT358WeiqopOh7epoayzo6yzo7Sj1VFWKns8ktslu11I
FLeOMtkrHgkhWkfa4EMn0uNxI57QY/H0WmRtamZlbGJldGxtetZMJEwtbWlpJIqiQ5VcTrtw4eMB
EoRkKLx47WbDi8898CgBWLhyDULoKCulFnkSySUUlPTWGZRPN/mGjLHy8rLTJ0/cuHU75zUPdhID
zhiTJGl6embR729oqC/mqA9GKUJodHQ8GosKgrjtpfKyP5qWFkTB5/V4PJ6OtrYjR7rAg6ajd/oH
Ll++JkkiBJCXRTJN8+NPPvv2N9+rrbV1LBtPH8ESHA5qmrRoFazcdcqyoCjcjk2PxpbuDARu9lFC
GCGiy+GsrHRWlDsqyx2lpbLPq/h8aolXLfHJXq/odspOp+h0Si6n6HTuYZCvmdKMZMKIJ81kykgm
9WhMW4uk19bSkagejWmrq8nQcmp5ORkMp6MxXvsA4Uy9QiSKsiwDXt/QNnN/fBMLw7I0d+nqmb/x
l0WngzEGAYAIkrQ+8cnngqpYhvlEkl1e/cnuaVs3EQDg9OmTNTXVU9PT09OzK2trGCFe0qdAtgQh
pIwN3BtsaKgvXvmKMQihrusjY2OUsq3vjv+rYRhut+toT3d1dXVNTZXH7X74gBMTU1euXBNFIVcF
jFvLGobx6efnf+K73/J5vTbHsvF0ESxHWemhiK+/PzdkHdlAxk8UMkqToXB8MUAti1oWIwQKmBMy
LMtYErEoIlHM/IAxkiRBVURZFlRVUBUsiYwyLAjoITt4ahjENCGCxLRIOm2meCHCNDEMSgg1TGKa
xDSpaRLDJIZhpdNWWqemybkUL4aDBEEt8eW8qO//QIjd7x8zKKWiqgZu3Vmbmak82pPLcQoODq2N
TyFBsKXEp56BM24Kf+rkiUV/YGDgbmApyJ1OCxknGWOCIMzNzQdDoX11UX90NjkzOxsIBBVF2mIz
FEJICIEQnj518sSJXrfLlbvNddpVOLz85VcXeQ3j/IbiJf+i0ejn57/87re/KQiC3cdsPEUEy1VT
BQg9ZDEZecFP/FXGgoBFMROSBQFgjFHGKLU0zUylQKYCOs1YArOcL+k6e9ING4Hl/28uPgdCCDLF
01D2ByjIsqiqudBpXuCTMUBtLlVMcwsxzJnzFyuP9gAIAaUA4/H3PyaWKQqKncxr61i8Dzgcjo72
to72tsGh4WvXb6RS2kOR4JsewTDMu3cHq96sLNp7JIQODAxijLa+IUopRvj111/p6uwADzqwr7vf
C19dTGmaJG6w20gplSRpcdF/7cbNl1543haxbDxFBMtdVUUphYc8xJrlxKF1AwnGKO+v2/KnjUaj
LekXY/nfZrYudRj6ChLw5MefPfOzf4PXmzBT2uLVG5liHDbBsjlWVpjhPx/t6a6srPjxR5/GYrFC
OBZjDGM0Oze/urpWWlp06YT8eqanZ4Kh0NayHJevnn3uXFdnx2YesPxo12/eWlgMqIpMNzka17H6
++/W19U2NzXZHMvGY8aBuf8pZaWi0/FkBmdw1pUDpRv9YZk/myH3gQ2/ngXIN4ywUcydAgCEcWR6
NnRvCEAIIAzc7lubnhVk2ZavbOTTi2zxRFpRXv7uO2/KslxgaqEgCPF4fHRsrDjXrZTSu4OD27Ic
Qkh5ednJE8cfVq3y2dXCgv/evUFZluiWrw+XBq9eu5HW9cdTIdGGjYMnWGpZibu2mpgmfCIrR+YK
inLfBIQgxpkAKf5HwEgQkJD3m3UfwOs/wI9w/4Do0BufPmUMiyFRTEci0599yX+xcPmatryMRdGm
yDY2GJoRYoxVVVaePXPKMq1C6s/wTbHRsfFEMlVUZILXCZ6dnfP7l7YOh+Ly1ZGuzvw9gIdhWVbf
wICuG9vW/+EiVjAYGhkZszuVjceMA9sidJaXe2rrIjNz+KEQ70NHpbggkbNO4Bt2lMtUjGYtshij
LBuMlQmTAgBuxi8ZY4BRztRyzlvZAKwswcpQN8QT/h+IZLfn7KLsK4SQxes3GaVmKjX39RWsyHaG
nY2t+UH3ka7R0fHwyopYwEYhxjgWi4+NTZw+daKoyCIhdHB4xLJMeWvJljGMcV1d7RYNAiEML6/M
zs7JskQL8OallAqCMDg4dLz32GMoyGjDxsETLMntctVVE12Hbvfh4AL57lPZEYJRSk2LEosbNzBC
KaWCLHNrBkGRBUURFEVQZCxJWBKRIGBRRKKABBFCCAUsKHJGzueZifzAEBDDpIYJAKOmRSyLmiYx
LZ42aKU1K63zzEErnTbiCUtL53QyhDEUMMICxDkHdwAAfMjh3cYBLOQlpzPYfy8yM0ctK3C7X1RV
mwrb2GLIoZQqitLU3BgKhwskZBjj4eGR3mM9oigWCUeEEAZDodnZua3ZFZev3G6XqqhbH5OXDCow
/D/zFdOklCJkVwmz8RQQLABAWUcbwkKRTzB8mw8AQCyLWBa1rExYAEIAQNnpdDZXuqqrXNXVjopS
taRELSuVXC7Z4xJVh6DKgqIKqiIqCpYlLEmPsh/KGKOGSQzD1DQrnTa1NNHSpqYZ8YSeSGira9rq
mraymlhaSgRCiaUlPRZnjAGuojGW2XMURQihbYJ1UDMNFsX40pL/2i0tGqGmCRwqsB+Eje2Wda3N
TXfvDlqWtW2MNidYa5HI6NjEsaPdlFJ00DEY/Jrv9PVTSre1bqeUOp1OURIB2Dg9iB+tuqqyproq
FAqL4vZupQghwzA72lsFAdtx7jaeFoJVdaLXUVFODKOYfYCIaZqxOGNMLfG5Kisc5WW+1ubS9rbS
9taStha1tESQZU6eCp1j7wenb+LPcP/D2cI7WWBZwrIkuV1bXzDRDaLrejS2OjWzNjG1OjG5Njmd
CIfTqxFtdZVaRHI6sKLYw8yBzDay2z3+40/igYDkckGEnuzhHkKIMH4y4ywfIzspr6hQFCUejxfY
WyilY+PjXV0d4kH7P3FC4w8szc8vFOjphTFGOeV9k2PKsnzieO+nn31RSANaluVyuXqPHbO7k42n
hmAxVnXiGJbE2PyCoCqsKMvcMsY89TXNb7xac+p4+ZHOsiOdni2DAzKBViBrdJUbDfPGC7i7KIB8
P4jcIMVyllwsZ4uFRRGLInA51bJSX2szeOs1/tlkeHllZGx5dCw8OBK43bcyOmGLWAfSpwCAEz/+
hDH2NNAOCKGpaUYiYT/4RwFGqLysLBqNFsJReOUcvz+wML/Q0tJ84JoNY2xwcEjXdbmAhFnGAM/f
2bpTMca6OjumpmcmJia3zbKklJ49c8rr9djylY2nhmBBKLvd7/3iv9NWI0jARZhWzBgVFMXb1FDS
0pybCxllIOv4+cAaKxeHjvarue6fDm7pkfWgRVbur86KcmdFeePLLwAA4v7A6uS0kUhAYA83B8Gw
MoF8T0HrQ0AJcVZWruu3NnYKr9ezY1ozNNLU3IQOrtlzZuvTMzOF7OXxPkILydGBEALw4gvPhUKh
ZDK1Ge9ECOm63t7WeuxYt82ubDxNBAsAwFjDC88dimbioVcAIYggKPJpcV0R6OxfGWOAUsYYxNhd
W+OurbF7vw0bh4CRMwYhdDochYdR8Mo5s3NzwaVgTU01O9Axa3B4WNN0RSko4w8AYBErl5CzGSPi
VTO8Hs9rr7z8wY8/5k20jmNBCE3TLPH5Xn7pRYywnU1i4ykjWBAyQimxiper8NQ8CNHhL2UFIQQY
Z2wksmanh9xI38Yh6XsIIbsY3KNBdag7elt5BuLA3cGamuqtqMo+88JINDo+PiFJYoHsCkJILZLd
8tuKGXJG1dzc9Pxzz166fGVdyiS/fUmS3njjNbfbZctXNp4+ggUAxAhjqZgbiJfzeyCg6rAvhxlj
jNkTng0bhwjb5t89DITQ/MJCKLxcWVF+UAxjYOCepqUlSSpYQIKEkAI/zDnW6VMnEolEX/9A7iyc
XTEAXnn5xbraGptd2XhKCZa2ujZz/iskCEUmpUDGKBbFqhO9noa6B/gJpdnlIISwuFlXnu9oLkQs
V4lDW13z37xjJpIQoadYx4K2hrf/SxTqqq5sePE5uykesafu9O0XBJxIJsfGxisryh/72AMghLFo
bHJqekfUEEJgEUJ3sp3HGHvxhecty7p7b1CSJAghoRQy8MrLLxzp6rTZlY2nkWDxfm8mkp/83D+2
0mmIUDE5NUDAGBIFb1NDzemTjS+/WP/sGVdNNRKEdZlfjFJGaM5MIbOqOgg1PtN6GYt4BhGEfEMw
72IYoamVlcDtvtkLl/w3b69OTluahiBiTyPJgAAwQBl4WpydYWbDhVEAeIWlx/HQIURmWmt9642G
F587kI2qJ+gB7rjpKGWSKI6PTxw/cczjcj9eqsEAgEMjo9FoTFUVWnDCMvca3dHneZXrV195yeF0
3Lp1hxCqqsrLL9nsysZTTLB4r3fVVDW98uLMF1+JTgcjxeQaAAFgIDo7vzYxPfbDDwVZ9rU2VZ86
UdbVWdLa7KysUEtLZK8Hi+KGyfYPOSDAXa5D1w1ZD/0EeKBYXlFCeF85IHosll6NpJZXItMzy2MT
wb57K6OjZlq3NA0iJKiq7PE8jd7uEDJKFa8XMKrH4qC4yP1+vm8MSG6nldLo43rXIIRQxKJDtYfa
R15E7eaRIYTiicT46PiZM6cf8+I5kUiOjo2L4g6spPknCSE7cu3hFApj/Nwz5yrLy/3+QHfPkbLS
Uptd2Xh6CRaf5JAo1pw+Ofb+R6LDUYS2TIKiAAUwSi3DCA2OLPXdo6YJMXJVV7lqa5zlZY6Kcmdl
hau6ylFeppaWqCU+paxULS1BeB8KMmxmzsCAtraqraxpaxFtbU1bWU0EgolQKBVa0ZaX44Fg3B8g
hsEL9XARTnK5QLZm4tMpBlDLEh1q7TNnh37vDwRZeuIzjCCClm6UNDd5mxrmr1x/fIQSQkbssgF7
AGLt5lXlxu5Dw2PHjh2VZfnxaIic1oyOjUciEUXZgXwFdq5grUNra0tra0uO5NndxsbTSrD4OwBA
ZW+P4nZTQgCExSYk5CYGiJCAMZBlCCEDQI/FUyur1LSoZQIGBIcqyLKgyFiSBUXGsiTIsuz1yB63
4vVIHq/idYsOBy9KKKiKICuCqgAARIfKBzyEsKDIAEBi6MTKpFVaKY0BQDI1BzVTS1tp3dI0PRZP
R2N6LGZEY+lo1EqnLd0gumHpOtENK62bmgYoRaLAa+NILieErrwi08Ce8BilCOO2t98Y+r3fL8KO
tw9zHjKTyaoTR911dVOffSk5HU9n1jrP8MgGImb+mq3YXtTzsWXtMtsaIRSJRkfHxo/3HgPgMTk2
6Lp+b3BIEIRdUCXLIrvunNkv3o/T2CemZRO4/X5Pc0zdJliPtNCpPnm8tLMtPDQiOp3FLKiwPC91
XtcPOjIbc9z1wExpRiLJKGOMPjhhw3zVaeebhVm39gd+kf87CBGCCPK9QkGWRIeSqe6cMZendiD3
+r4HIDHNsiPtlb09oYEhQVWebNLJGENYqD131tI0allPA6fccDrMUSvAAAP3mdbWI3sxzKZkt2Mj
hJAxOjY2ceRI12OonMPbamh4JB6P76gYc+5qLcukjO76ZtddyZ4/uN0ddrN2KAYOsfUzesxXuIvm
zV1/ERKyAyVYCDFC1NKSiqPdwYHBQzTi55Ot+90Q4/s7g7kg4v27p/sxVyz/VIwxZj2VG387W9dD
ouueutqGF59buHpTdDqeZIIFITUtpbSk5a3XBn/nf+7L/nVxUys+8sbjiYWFxVAoFE8kTdNkgGGM
JVH0+XwVFeW1NdUOh+O+sgUAynpXFsPAbRHy8KrsYXfNDVtAkqTA0tLs7FxHe9u+kkV+MZqmjY6N
519YIdeZA6WUPNpKO/fUCCHBYMjlcnk87j3sS7phrKyslJaUKoq87VcYY2jLkqOUMl7r7HH2snwp
d+v+8NhU3txTY4wtBUOyJJWWlmzbVfLbtgh1r4M2Q4IQMNb86sujf/TB4Z7h2IM602Mgi+t1LBs7
F3UEof65Z9WS/0otE8AnNtQdAkCIVd7W5a6pJob59KTy5cjEwqL/3r3B+YUF07Qsy2IM8IqgfO7A
GGGMRUGoqqpqb2+tranxej0wb02cSCRVVcEHSkwty3pY9SaEoMIqWjLAhoZH2tpa0T7PkQihmZnZ
YDAsyzlXqh1cJ291stslYv4UO7+wcO36zaWlYFlp6U9899uOR8i0yJ/7Jyambty6tby80tra/I13
3xawsMXnc/QlnU7rukEoIYQyxjBCCCNJlFRVRghz6sy4ucX+i1X5F0Yp1XXdMExCCaWUUgohRAhj
hERRlCRRFMXHwGByr2ooHL527ebc/LzL5fzWe98oLy/bdEnAGEKIUhqNRi1CnA6Hw+EARbZ7e9BG
owgBAJpee0mtKEuFl5+qtbWNA9awEDaTyfpnz3ibGldGx0XHkxuWBCG1rI5vvA0yxTSfInYVjyeu
Xb85OjZOiCWKIkKI163LTRWcaVFKDdOcm5+fnJr2+TxNTY1NjY1NTY2Gbty6fWdicuqZc2d7urv4
ivmxPz0IALAsAh/6fYnPF43FCmkKSZQWFhYDgUBdbe3+zUAIIcuy+u8OYoxybxMhzOv1plIpixcc
K2DRbe4w4Iw/T4QypGFtLdI/cHdweIRRihCKJ5ORaMThUHd64+sOuxQM3ukbmJiYQggihFdW11LJ
lMfzQA3pfMVUNwy/PxAMhiKRSDyRSCaTpmmZlsUoFTAWRNGhqm6Py+f1VVVVNtTXKYqyTyQmn1cB
AAil4XA4FAqvrkaSyUQimUylNMuyCLEsiyIEBUHAAlYVxaE6nE5HSYmvtKSkorLC7XI9TIkeUUXj
LxSEMJlKDQzcG7h7zzAMQRCSydTa6uqGBIsyhiAEEE5MTg0Pj4bCId0wSny+5qbGI0e6Sny+4qFZ
RWHnrfi8La+9PPD938Eulx1/beOxTVzEtBSft/bM6ZXR8SdYC2SMCYrS9NrLGS3jqWFXS8HQ5+e/
CC+vyJKEscQYs0yrsrKivb2trLRUFAXLsqKx+FIw6PcHEokEY8zhUJPJVF//3dHRcY/HQwiJRCKm
Za2urh7sHZG8kmK8yl5VZcU7b7/5xYWLCwuLhZRSppQODNyrq63d1zafnJoOh8OCIORdZ+U333vn
gx9/HAotF+jaQAojWFkrZb4HBwAAa5HIvcGhiYnJWCwuSRIUBEop3GEYan5MD4SAUrq8snL37uDU
9IymadzL1LIs8NBhc5P68vLK4NDw3Px8MpnStDSPH0EI8102hDFlTNd1TdNCy8uUEFmW3W5Xa0vz
saM9Xq93b/lB7lCWZa2srI6OTSwsLqRSWiqVIoQghDFGOZYjCJgxRgixLEtLact0hacpKLKsOtTS
0tKW5uampka3ywkfYQN93c5pPJEcHRkdGhmNRCKCIPDOzBggG3UVxhiCUNO0ry9dGR0bJ4SIogQh
XFlZDQbDI6PjJ44fO3niOEKoGDjWwRMsRimEsOPb3xj4/u/Yk76Nx60NMNbx7W8M/t7vP6nyFcTI
TKQaX37O19wEnojEnAJnlHB4+aOPPonFE6qiUEp5sseZM6eePXcW4QdUqN5jPYZujIyN3RscXl5e
liTJIQiU0pWVFQihLEmMMXrQ3cPKC0uCEBBKXW6Xz+c7fuzY/PxCIUkLGOP5RX8wGKqqqtwnKc4i
1t27g1wp4ZMoxvi5Z59xuVwlJSWhULjQ42xCsHKBGLmUhZz4EQwGJyampmdmDcNACMmynNMpd8So
8t+RtbVIKBQen5iYm18ghGCMZXnjktU54WplZeX2nf6JySku12GM+dZkjgvm/osQQggJ2cI+0Vj8
1u2+4ZGxE8d7j/ce4xusjy4RcZZoGObU9Mzg4NBSMMhDvjDGsizzbpPfUPnpIDnWxdl5PJ6IxeIz
M3OqqnS0t3W0t9XW1oDCElPXUTHeVpqmhULhmdm5iYnJlKZBCCVJAlsG3fPLW15e+fTz8+HwsiSK
oihyCsiZWSqlfX3pyuKi/+WXX/R5vQfOsYpAwYIQQFh57Ghl77Hw0LCoqraIZeNx9r2aMyc9jfWx
uUUsCk8ezYIQWel0/QvPSS5n5pafAt6c0rTPPv8inkhIksjJRDqtHzva/fxzzzCwQYKKJEvHe4+1
tbVev37z7r1BSRIhhLx+MAOAUmoddILzg2FJEDAmYIEx1tBQX1tb4/cHZEmiW85MGONUMjUyOl5V
Vbnnsw5v5Onp2WAoxDdhuXzV2dHe2FjPGHM6HDsiaptpHvmz+Vok4vcH/P6l5eXl5ZUVXt0589QK
e5F5yNG63MPl5VV/wO/3B8Lh5dW1NYSwKAqiKIJNlDB+YQyw27f77vT1J5Op/MvYzKgin9MAAASM
AcaGYVy6fHVubv7VV18qLyt7FB6c4xZDwyN37w0FgyEIgSAIGEOIILGIbhgIwnVx7ly+opQJAsYY
85VJhitkU1BN07zT1z88PNrS2nzq5AleiGlDKrNhjH8ikfQHAot+fzAYWl5esQjhPGnbp0YpQwgu
LPo/+eSzZErjpSdzbCFD6BHEWJqemV2LRN564/Xa2poD2dYvIoIFIaSEqKW+1rdfW7rTLzmdNsGy
8bg6HwAASE5H65uv3/ilX8UlPvCEOa9CSEzTVVNV/+y5p+SR8oH+xs1bwVA4V6SFEOJ0OnqPHeWf
2JBeUEqdDsfrr73icrmuXb+BsZATSxhjdLc2VHsoDj1wmwBgLEAIJUlsb28LBJZYAS0jisLE5OSJ
E8f2fHGPECKUDg+PEEIEAVPKAAOiKJ4+dYq3IZ9BC1awyMPTBGdsiWRydWXNH/AvLgbiibhhWKZl
8ohsAEDhqlXusgEAuq4nk6nw8vKiP+D3B1KplGGalmWJgqCqKstii4Ok0+kvv7o4OjYhYEHJKqY7
V5sAhFBVFX8g8MMfffjO22/W1+0mYI5lO/nKyuqVq9dnZmcZY5Ik5nhIOqU7nY7ampq6upry8nKP
xy1JkoCxYZjxRCIUCs3NL4ZDoZSmcSFwHSMEAKiqSikdGR2bnZ3rPdpz5swpTnc2tMkghCQSyWg0
6g8EFhb8kWjUNE0uNIqiKIoCpayQZFiE4Ozc/Ceffq7r+mZ7zfzeJUmKxeIffvTJu2+/0dDQcIA6
llAk0wAAoOO9d+5+/3f1aAyJArOdm2w8Dn6VeeuaXnnh9q//JngC5Stoalrl0SNVJ44xQuCTnkTC
V6vh5eWxsQmuXWUawbTKy91bZSQBwIM2AADnzp6GEFy+co3PGQAwBKFpmger/xGLPHDljGEB8Ymn
q6N9YOBePB7feqXORax4IjE2NvHMuTN7TmoXFxfnFxZFUaSUcc5xtKe7rCxTskbYgQUXNM31BGtu
fmFx0R8MhkLhsKZpXBRBCCEEFVkuXLLKv2BK6dT0TCCwFAyFwuFlPuXzI2OERFnm4uW2rCiRSHz0
yWeLi35ZlsF2XymkD0uSlEqlPvrks2+++3Ztbc2O+EHmwxAODY1cunJN0zROrfjvCaEQwt5jR3t6
jtRUV637rqqqXq+nvq729KmTfn9gcGh4bGwCQMAlyXUXCQCQJcmyrOs3by34/S+/9EJ1VVX+pUII
l5aC8wuLS8FgKBROJJI8pwQiiCCSs0+tkOfG3+uFhcWPP/nUMMxt/dUYY4Ig6Lr+yafnv/3t96oq
K59eBSsztFFacbS7+tSJqU/PI1G03QdsPE5UHuup6OkODw4XZ8mmR5n6IMZ1zz4jKArRdfykEyw+
uE9NzSSSSYeq5k11zKGqOQq19dcZY2fPnI7FYvcGh2VZYgwAhAzDONi9hnWJdYwB/jQppaqqdna0
X79x6+GJcAMRSxCHR0aO9x7lOWt72OwDA/copRhjABghRFGU7u4uhCDfhhMlsUAKBCGwiJk3ubIL
X301PDJmGAbCWBQE+UFGtYttfQhhOp3+5LPz8/MLPGdNeOiwdHtNBWCMTNP85NPzfn8gJ/asC+TK
XeSOnMBEUdRS2mfnv/jut7/l8+1AbuTE8eKlKwMDdzHGkiTmu4KpqvLqKy+3ZasJPfgAH2jM2tqa
2tqaxsaGi19fTqfTG3IaflWKoiwtBX/0/oevvvJyZ0d77nRXr9/s7x/QtDREUBQEWZbyT7GTCpUA
YxQILH30yWeFsKt8jpVMaRe++vo733pPVQ+mHCoqqvGx98/+SbjdIGjjydORDlj2IMRRUV596gQx
TIieqBAlxhiWpPb33ubrmCe/K0FomubC4qK4bhSGcKfk8tlnnikvLzNNi29zGKbJRayDGp0e8t5k
GN2/o57uLlVVConERwjGYvHhkdG9uhd+kEW/f35hMTv5QUJIfV1tXW1tbkNW2smymWcR8iP7/f6R
0XEAoMPhkCUpFz7/iBc8OTU9MzOLMXY6ndKuDosAgBBdvnJ1bn6eR2fnkvV0XU+ltGQylUymUqmU
pmmcoIOCs0wopZIoRCLRry9dZrQgdsUv3jDMTz49f+dOHzclyWNXlqIq3/zGu22tLetcRvOPnfsV
/0xXZ8e3v/UNr9e7hcUGp4OGYX762fk7/QP8Y5FodGho2DRNp9OhyDK/kt09OIzR2lrk408/T6fT
hWTL5l+YLEuBQHB4ZOzAxKOiGRkRAKD5lRdrzpyy0mm7zNPTA0YOWDHiXa359Zdlr4ea1hMTBg4B
oKZV2tZaeawHPAX5g3zk1XV9eXkF4QfXaYxp6XThLI0x5nQ6zp09w39GCOm6oevGAd5dNsg9l++G
MEa5q3W73V2dHYZubKux8W4wNj6R1vU94Vj8gHfvDpqmme1jDCF04vhxAADL9rodxWBxNsmPpiiy
LEmmaeqGYZrmw2Hpu4PDoWKMTdPUdd2yLEppzu+qwM6GBKH/7t2h4VEufRFCeAvU1FSfPNH78ksv
vPP2G+++88Ybb7z2/HPPdHd1ud1u/hlW2MtIGZNleWp6dnB4eNsnxQmTrhuffv75yNhYLnTs/tUi
9Pqrr1RXV3G6tu0F5GhWdVXVN997x+1yEUI2+xbffYYQXrp0pa//LoRQEkVZli2L6Lq+66fGrz8e
//+3995xdhxV3ndVdbhx5k66k5MmaqJyGOWc5QC2sV/gAcw+LLCEJeyDDXiBJSws2GZtsBcWWFiD
MWDAWU4KVrRl5TQajUaanPPNHareP2rm6mrCnZ4gTTpff6xP3zt9O1RXd/36nFPnuF9/8y2XyyVJ
oy5tyRgTiDCJOVbEqfJ0xIjpOpGl4vvvqT/6HrZZod7LrLBeYRyZmd5TUzeZwz/Pdrt6hS0hvreu
XpDlGdK4gqD29mZt2SDI0uypPOjx+lR1oB8BY+Lz+fwBv9lkNuJt4UNLbk72xUvl9fUNhBB/wO/3
+yek4srY4EHuwRET32yTwxjn5uaUX67QKcUjDTmSJLW0tNbU1Obn5fKRbzyiFmPc1NxcU1sXzH2l
KGpmZnpKShLqq+Q1aoHF/aH8KsTFxW3ZvPHCpfLurh5FDQQCitfr5fHRY1OH/HwzMzI2b9pwpfKq
q9elqIrfH/D7/IIoGPFAcT3hdrvPnbvQZ+BUFLs9omBuXsHcfLvdNkTAGUMBJdDa2nbh0qXq6lpN
04zuiJCTp87Mycy02awMMTy8wZ8x9s7BQ5WVVZabnOP8iiilJcVZczJH6+bmlyA2Jmbzpg2vvPq6
pmuE4CGPOpgy9PCRoyaTXDA3f/PG9ecvXGjv6FICgYCieH0+Hn5uPHeGIAi6rr+9d39be4csSWOr
qcsQtY5mBusMFVgIIYwZY1mb1sXPK26/eFm2WSlMJ5zB0ooQxePJ2rDWkZlxprJKspgna2YDj7uR
rNb0lWXn//AcnjEBgIyKFkv6imUIodkzM1dRAkNJTeJ2eVpa2jLSRzelaH5pSX19gyAIfp+fm3wm
TWCFvHAyhjBGoQKLMZaYEJ+amny1qtokj6w8MMbl5ZdzcrKFcTuOGWPl5Vd8fj/PN8YDmUuKivjY
jG9YsMTRnKwWKoZSU1NSU1MQQm63p6e3p62tvbLqWnNTsziO2tUY47zcnLzcHEaZy+3u6u5ua2u7
XFHZ1dVtMBtq0MumKGp6etqa1StjoqND/8qTdvEGwBibTKa0tNS0tNTqmtojR491dnRKI6kNxpgg
Ct3dPRfLy5cuXoTo0D4nfiRHj71bXnFlgLpCfHqszbZw4QI0JjM2D+pKTk5aumTRoSNHCRnW1RvU
WIcOHYmOikpMTNi4YT1CyOv19fT2tre3X7teU1dXZ9BZTwimun7k2Ls1tbVms3nMplZGWexINQ1v
4cv7lBpxEaWW2JjCe+5CGKLcZwGMzfv4R8zcMTepoVj87s3dtZVROjNchFgQFI8vobQ4rjC/30o3
S9zueMhXYa/PV1/fYHyM4aulpCQnJSZqqqqqGncyTkoMFmOM0pscNIQQob8KXjCqurCgQBIFI3YR
SZLqGxobGhrHc0Z8XO/q7rlSedUky5RSgrGiKCkpyenpqQOaOrSk3YhtP2AWYdDbZbfbUpKT588r
vWPn9pzsLIO1d8IcP2MMExwZGZGRnrZ40cI779gZ73Qa3ywhWFGUzMz0ndu3xURHD6hvTfikuZuz
TDHKMjPSd+/akZSUFOJUDYcgkMrKq16vFxM8XKT5lcqqU6fPyv1ZN0P7iaIo+fm5kRH2MWcr4BFU
paXFmRkZ4Y+Z32sBRdl34KDX6+XpKqxWS1JiQklx0c7tW0tKisO4Ggds59SZcxcuXApNFTF6achs
NqvTGQcCq19jMVbywL0xOVm6oiCIxJrB5iu3O31VWdqq5YrXO/mh5RgjhOKLCmLzcnRFmQHhShgj
qqpJC+eZo6KogSfajEEeysPL8wBdrapyu93BEh8jwqN309PTdEoJwV63B01SKJuuD4xf59VXBsjB
zIz0eGecbiyXG2Ps/Pnz4z+2c+fOKf23DGVMEISigrk8R+VNIw0mgiAwAy/OGCNdUwecbHCCJ8+E
aTKZli9bYrGMy8sxaLM0wm5ftmyxQdGJMdY0PTIycu3qlTw8yFBgE8GU0siIiM2bNkRFOUa8WHw2
XEd7Z2Nj03Aat6en59ixY0MGOVFKTSZTRnr6+N8NCCHLli2WxBHiDfhd09bWfur0WW7QYv35S0VR
WL50Ca9AFb6tuNmsq6trQPL3wYTvSKqqJCUn8epDILD6vIRyhH3BJz+m+f1kFsx7mq2mKyaYTPM/
/hHRZKLGXuNucb/DjFJzdFTGmpWKyz3t80VhTBXNHO1IX7MShaT7mg1YLebB0S38hbi7u4fPnhuV
ESszI91usyGE3ZMnsDRdCz0j7osRb+6lfKzlFgJizEJQ39DU1NxsXHEOYb7q6q66Vi0KpD/Nkh4X
F5udnYX6c3iGDs+iaDTB4XB58/mYyrNRREdH22wWfSJeHvo3SxhjCQlOg3FCvIBSSXGRw+EYVWwT
IYRS6nBErlq5wmCPwgRXVl0bcmXG2HvHT3T39A7u9jwDXGxsTEJC/OArMuonJGPOuLiCgny/ooyY
cU2WpQsXLzU2NvNyZPyq8Wl90dFRBmWxEFKrR1VV7Wb4N2FkFmNMEMSc7OxJTE8z9RQMxoyxvDt2
JC2cr7g9WACNNQPNV5rXm1q2NHv7ZoTQFFEzfHJNyvIlcoSd6fq0tp5ihHRNtScmpK1YhhCaJTcR
f86aTKaoqKjB4y63BFy4eMnr9Y5uUHHGxSfEuz1uVZ+0ZO66pqNBY2e/i/Cm00xPS42Pj1cMOLkE
QfD7/eXlV8Y2AYKP5RcvlbvdHqE/FopSVlpSPGQ6Li6wjApKY3nzJUme8C5EMJGNTXNhjFktloKC
/GDs0aisQYyxOZkZOdnZgUAg/MXiarixscl/80xYLmrr6hquVFaZTPKQqoUxGhMdPdh1OOb2KSws
sNmsRkxQiqKcPnNmgNsUIcQTwxpq4f70XYyxzIyMLZs33P+hez764fs/dO8Htm3dXFpaHBXlUFWV
Z08dfACqqiUnJ+Vkz5nEhxKZgk9JRqnZEbnwUx/nHkNQJDPSfLXsC5+ZUn4rQjBCKHX50uisOarP
N91daoyytBVlksUy27LKybKclJQ4ZBiNIAhut+fEydNolO6SlWXL16xeWVJciCYpBkvXNTboOckz
uQfPkntVLBZLbk6WkdGUR2Jdu369s7t7tEYsLil6e11Xr1aJIq88iDRNi3fGDTeeEYJ5cjIjd702
5aeQ84E/NSXZarGM7TnGG7ygIF82NilBURTuJQxdWdO090+eClNwWRTFeKcTTYTltd+IFZuWmqoZ
eNmQJKmuvr6+oQFjPLYJTBghSqkoCmvXrNq9a3tebm5cbKzD4XA6nTnZWWtXr7r3g3eXLV9qMkkD
IsP4oYqiuHzpYjKpmTWn4qstEQRGae6OremryxSPF4OjcAZBRDHQ01vwgTtSli6mU6rwHyFM1y0x
0YnzShBj0zskHCPEaO6OLX2vgbMGPpE7PTVtyDn83BJw8VJ5Q2OjQUnBn9rR0VGrV65wxsWh2+4i
5Aep6TpjNDRWmpCgBWvg0ebn5zkMhLlwkeR2uyuuVI72vPjKlyuu9PT2Bks767peUJAvSfKQKooQ
oxkQEEKqqk31OwwjXdfj451j1tzc6JWSnBQfHz9itDvGWNO0lpZW1J+qg4d8Xa+uaW5uHq5heWL9
mImeQ1dYMFcUpRHnP/IK65WVVWiswfUMI0rp8mXLigoL2FCYTKbFixbu3LGNm7KCdkSMcSAQWLRw
wWgLDc0KgcWbSJDlZV/8rGSxQO3nGQPGWPMHIlNTFv3jg1MxZzrGiLGc7ZuJJE3fXocx1hU1OifL
WVzQJ7ZmUQdDjLHk5MT4eKc61GQFQoimacfePa6OpngzY2wM5XsnUjjq+sAgd4QHZ1joSzpqt2dm
phs0YsmyfLn8it/nH+0heX3+S+WXuZDlqQpiY2NzcrKHayVCsGg0FRamVJ/yhleMEIqKihrf+wAV
BCExIcHgyu2dHaHXmlJ6tbIq/JxHQkhkZOREvRj0Zc1ISY6KjByxg/H4+uvVNR6vd2xpATRNT0lJ
Li0pujnvPA5NN08pTUpM3LF9a1SUIxAI8FKSXp+3uKhw8aIFk6uupq7AwgQzSlOWLS75yP0Bl5vM
9Bpqs2cA1BVlwSc/GpObzXS974WDTZ1eRxDGqWVLbYnxU8u6NrpXE6K4PRlrV5mjHGx8aSSnqb40
mWSHwzFk3RjuF2toaDz+/gnjfjFeV3gSW1LT9QGHSggRRGG4IbC0uMhgHk5CiNvjPn/pknFLDF/t
0qVLLpc7NPYoPy/XZrUOHsv5R0KIZKyKHFfJuj6ljVhcPVitlnH2VYRQYmKCZCCLJiHE6/Wrqhos
79je3l5dUyPL8nBah/d2m20i02xy01Rubo6RZBYYY6/XW1Nbx3852sahOp1XUhxmL/zG5KlQd+3Y
5nTG+f1+XdcWLpi/bu3qqTBJbkp73xhji/7xE7F5OarPB47CaT/yEaJ6vEmL5i948P8wxqbsTD05
wp61Ya3m80/LLocx06lktaQuWzrm0Idpra78fv+RY+/V1tYNNxeMm23Onj1/vbqGmwGm/nlp2g2B
hfujm0Vh2JjxmJiY7Kw5iuGEI1crqwL+gBHFyXft9XorrlwNbptSarfbi4sKwlhKCCGCMYHF96Jp
2hTuZrxsthhaDnJsW0IIxURH8wrZIwosv9/Pp7LyyLua2npleN8iv5p2u/1WzKFLT0sVDE9ZqKmp
HcONrOt6dJTD6XQaWZnPKr37zt3btmy6687da1evCtYVAIE17HjMKI1ISlz2hc8wShlkHp3mQx+j
VDSbVj70JdFivultZipZWHhhxMwNayei3Nmk3DVI8/mjc7JTli5ECM2w2tXhbSoMocuXK57/2wsn
T57yer28NvOwL8eUHjp8xNXrItOhuvxN2ZL6U4OTYSaHcsk4d26+ESMWN3K0d3RUXb9u3Ih1tepa
e0dHiH9QKSoqsFgs4fWBKBof6Zk2pU3IGCEkiOI4XSv8SkZERMiSoTh3VVUDSiAosquuXR9xYqbF
bL4V5+9wRMY74zTVkBGro7NrDClhNU2LjY01WOWGayyz2Zyfn5eSnDx1OsqUfkcngsAYK/jgHfl3
7FTdHgyOwumrrwhR3O7Sj/1/aSuWD8x7OaVGN55xtLgwriBP9U5DIxbDVNcTigutzjhG6Wyw+1LG
MMYul2vP62+8ve9AR0enyWTKyc4qKS4aTjzxGUbd3T17D7wzqkf/gGRUPARkSAasOV6BpekD8lgS
QoazYPGzTk5KTElONpgrnDF0+XKFqmrh5WawovDFS5cJvpH7yuFw5Ofmhj9TjLEkitRQTAymlOma
hiZpzqbBnkAIJhPxEiaKgn2kNOv8r6qq8orjGOP2jo7u7m6MR7hesmniM1lwKZMQH69qqpGJFD6f
r7W1bVRXE2Os69ThiBQEYrBcZmjOWBBYxjsywoSs/vpXI9NSdb8fHIXTU11h1euNLy5a9oVPc6/5
lM0yhQlmum5PTEheslD1Tz/HNDcTZm1eP0vymzDGCMb19Q0vvPRKVdV1hFByctLundu3b9uyft2a
FcuXDpcpm09BqqmtO3z0GGPIeDAW6s/SxMNsyTD0ZTanlE5EGNyAWfGMDczkPhhBEObOzRsyJdUQ
w7AsNTQ2NTQ2GjmY69XVbW3tvGAfn92Wk5PlcESGkQj8EERRRMZisBBCmj6L5jYZybzFtWzQc9rU
1KzreviexUaTdGpUNx1CyOmMM5KRlU+A6O3tHe0uBIHYRl+kGU8x14M4xXseJpjpNCI1eeXXvvTG
F7+GwFE47dQVxowyyWxe92/fMEdFDfEUnmJai2doSFtRdun5F6mm8YCLaSM4dN0SG5O+ZgWapj7O
0V4pjCsqruw/eEjXdIxxelralk0bzBYzf0YXFxfV1jVcu359SGcZpVSW5QsXLkU5HPPnlRoxIXR1
dx8/fkLVNFEURVEQBUkUBR7jIggCIYQnRdR1TVE1VVVVVWWMLZw/b5zTxflmQ37OCCF8v0Nuk3+Z
nZ116tSZzq4ug9G+586dz8xIH3GMP3vufNDQpeu63WYrLixEI8S7MISwwbh7fmk0TZ09D0mDLUMp
DU6+aWlp03V9BAHN2HjqYYd/zXDGxZnNZr/fH/4YCCGBgL/X5UajtEcKgmAw4+tURpz6h4gJYTqd
e9euxuMnz/z2D2ZH5PSd4TU7BZbf5Vr10JfTVixjOh0iq/gUUy98NMpYt8qeEN9b3yCaTNNFXmFC
VJ8vbVWZefJqb91O2xXGuOJK5d7972CMEcIOR+SGDevMFjOvW8KHgRUrljU2NQ3rKWNMEISjx96z
22052dkjaqC21vZTp89KskT65xVybyBjiBCM+mYVsL6icwRrms4YTUtNTU5OGs/J6toAgcUtWEL4
9hEFoaio4MA7h0a0Y/XlCm9qbmhsTElOHrIdKGWE4KtVVW1tHdx4xp1WBXPzo6OjRpKnCGMkiqLx
EXbq5xqdSIFlQAb1Ta6kFCGkalpPb49BC8UtElixsTEWi9nr9Y4YRM8Y9Xi8aDQh57w7kelfgmI6
nABGvC75qoe/krSgVPF4wFE4bdSVIAQ8nqwN6xZ96hOMUjQtYq55kIEjMmXJwuk1Cw9jTFUte/MG
xNDMzh7Hn79NTc3vHDyM+qKO6KJF8+02Kw2pW8IYi46KWrhgnhp2shVCaO/+d3j20fCTCufMydy8
aUN+Xm5KSrLVZkUImUwmu90eEWG3Wq1Wi8Vms9psNpvNarVaZFlOS03esnljUdjpdSNa6RBP0zDQ
dIcEAzHj2VlZDofDSPlnQkggECgvrxhOivFc7ZfKK/T+BCt8PmZpSZHB8xBF0eDrFGN9MViz5y3U
0EDI+trP6/X6/YoRwyS9NZ5WHlzFM2wZObuxzQmdATZ4Ml06IKPU5Ihc/71/NTkiqaaDxpoWBhUt
EIhMTd3wg29JVuu0c1rl7t7OGJ0uiTp5a0dnZybMK575yUUx9vsDBw4eCgQCgiBomuaIjMzLyUEI
kUEVM0pKilNTUobTWHyoUBX1zbf2trW1E0KGzEjEfytJ4uJFC3bv3L5zx7bdO3ds3rQxKSlRURRN
0wZEuKuq5nTG7d61o7SkWBzP7BzGEE80SkNMRIwRQggm4QcnxpjNZs3Ly9E0zUj5Z0mSrlfXdHR2
Ds7XECx711DfwMveEUICASUvNycmJsag91MUBYPRyoxN8VmEk/dqgRhCyOf1BQL+EQUWNzHeuoOJ
i40zeEF5VrNRPv9nwlNs2sgUTAjV9aRF89d88//pgQDcadPAmqLrBJON338kKjN9Oma8TFwwz5Ge
StXpUfgZE6x4vClLFkemJM/s/KKMMYzQqdNn2traeZgtpTQtLXW4cBNZktasXmk2m8LkYxRF0ePx
7nnjra6ubkLCpYPiG7HbbEmJCYUF+Xfs3rlm9arBk+8opYWFBRaLRZ8IE4KuawNsPxj1zZka8bd5
uTl2u10z0CUIIV6vt6KicjjRc/7CheD+dEotFvPcufkYY4NmXkEQMSFGjFiMMR0E1vD4/H5FMZS3
bEB96IklNibKQCfsi9Vjs7Ks8HSyA/GsDcUP3LvoHx8M9PZCevcprrA0n3/5Vz8/Z9N6pofPFzDl
Cv9hjBFjluiozHVrAm73tAgFYDqVLOaU5Yu5uRfNUIHF5/l3dnaWX74sCAKXO7pOY2Njh3zW91Wo
dcaVlS0LU56Pa6yenp49r7/Z09MbZugKesc4AiGlJUVLly4asHGMWFxsLJ/MP/6zVnU6IDG9keyR
/CxiY2LS01KNxK1yI1bFlUqPxxPaAnyhvqGxrr5RFG9MHkxLS01KSuQTOY2chSiJAhGMjLMgsMLK
FaRpqqbpRnJQebzeWzdHxxHlMPDoxgghIpDZVlJi+gks1J9gbeVDX87Zusnf64LMWFNWCgdc7qIH
7ln86U8yXR8p0BJPwcmhVKeYkLSyZaJJZpRNcb2CMdYUxZ6YkL56JUJoBt8X/DJUXLnqcnlCkjUz
q8UcXmcUFxbOnz/PHwiE0ViSJHV0db22543u7p7w5oHQamh84wnx8cG02pRSq9VqsZgnalDRNW3A
MClKo5ifVFpaLIiCwco5Ho/nYvnlwX86e/Z8UETyCPrSkuJRnZ4kCIJgKK0r97HCg3Q4NJ4XbaQ2
xBh73B52ax44CCGbzSYZ6IeMMZ6zbRaasKZbJBPGiDFBEjf8+7cTS4tUj4dAMNZUu0SC4O91pa9c
tu7bDxMioJGzXrEp6G7nojB56aKYnCzN55vqr18YM53GFeQ70lJmsH+Qjxk+n+/ates8D1OwA434
HGCMrVi+NC8nm1eEHW4dWRLbOzpe2/NGd0+PERcMX0eW5bS0FJ5Bl+dIjHREykZrGxuR+9qAAzEY
19U3o97pTE9LM5h0FGNcWXnV7/cHxSLGuL6hsaGhMZiKXdP01NSU1JRkNJrAGlEUjTyuMbpRi5BB
Wp4hnpZ9+dWQAQtWQAm4PZ5bdCiiINqs1hGLTTHWb3CdfZdz+qkTTAhjLCI5aduTP4lMSVYDAQh4
n0L9SRBUt8dZkLf9yZ+YIiKm72DPKzXZE+PjS4ro1J/QxBhCKHf7lr6XkBlNR2dXZ2dXMPVAn+oK
G2vCO6EgCBvXr0tPTwsEAsN57ihlkiR1dHa+/Oqejo5OI8UK+cajo2N42V3+k8jISJ7FZ0L6v6bT
AYHkxivBcRdeYUFB+KD4G8YGUezo6Ky8WhVUV5TS8vLLwYxHGGOE0bzSEoRGl6BVEAVDhYl4kHtf
mgZQWIP1Z386TQPqX9dpT3cPujU58QkhFquF0hGmOGDMzGYTmsJ5+UFgDTH4xeblbHn8R7LNqisK
FkBjTYHrIhDV641ISdzx1OP2pETGmLHrgqfuY5SxrE0bRLN5imc9YIyZIu3pa1bMhtGlvqFhgMWT
YNzV3R1ezXBTk8ls2rRxfWJCQiCghLFjSZLU3dX96p432js6DRYrtFktQc2n63pMdNQEVpLWB20n
TKXnIc8oLTWZT3g0aMSqqKhUVJXn+urs7Kq6dl029cnHQEBJT01NGX1mL1EUgwm0RjzgAcnrgQEt
SQTByENT1/X2jo5bdBiCQMxmc/inN2NMEES73T5LLQ7T9UFLCNP1tBVLtz/5Y0GWqaqBHWuy1ZWg
+QOWmJjtP3ssbm4e1fXp7qjChCCMM9atssTGTOXctoQIqteXtmqFLd6J0ExO0cA7VHt7x4CuRQhp
bmo2ohsYYxF2+9Ytm5ISE0bwFcpSb2/vq6/taWtvN+Ir5Jnc+8SuSY6JiZnAE6c6HXAzCYYLJ/OD
lyQpNyfbiFjkKzc1N9XX1fNvTp0+oyjqjegrUSiYmyeK4mirAImCSIihUDCGkK5BkHu4lhSNzXLQ
NK29oxPdMguWJIoj5rCVJMlus6EZkddqtggsPqIzSudsXL/5J99HCFENNNYkjvFEDyiyzbr18R+m
LF3EKB3NHE82lVWB2RGZvnqFHlCmbu8iSFeUzDUriSgyXZ/xLsLurm6EbprjRgjp6Ozq6uoecSDh
asPhiNyxfWtKSrLf7w/jKxRF0eVyv/LKnrq6+hE1lqppjFFeTMZut8fGxkzIiNIfCKUPuEek0ZRA
4covf25eZGSkEaMaYwxjcuLUaV3Xr12vruqPeONn53TGZWdnoZCErkZlgcSD3EeW0YxSTQML1pCt
gxBCFos56I8esTW7u7s1TTNoiB211JPE8HNBeEGq6OioG0cPAmsa2RioruffsWPzj7+HGNNBY03S
VdAURTDJWx/7UeaGNVSfOWlgGaWIoewtGxmdogY5jLEWUKIy0pMWzZ8NnU1VVVXVBlazxDigKJVV
14xbdGw22/atm9PT0/xhfYWiKHp9vj1vvFVRURmcMzj4/QAh5PV6+cx5ndKICLvDETkxr+wYIYR0
SjEOjRHGY6gxZ5Llgrn5umaoJwuC0N7e8bcXXnrn4KHQgZwxVlpcJBjzTw2yu0gYG8mDhcGCFbY7
IKvVajabjWhlSRB7e13cgX4rGNFVTSmzWi3R0dFo5keHzjiBxV/OGKUFH7xz20//gwgCaKzb3f6C
oAcCktW67fEfZm/bOErb1dR/nmGEUcK84picbM0/FadTYEI0ry+uMD8mN4dROuMTlyiKQhkdQjNR
du3aNZ5W0eDUP6vVun3r5qzMTF//jLkhNRbPFP/Wvv2nTp8NpmYYsBJCqKurm0c4EYxTU1IwwhNi
MMAII8YopVx2BHulMMoLzQ8mPy/HZrcZdO1hjFtaWn0+Pzd+cH+TMy4uOztrbNqRF8Y22Cw6BYE1
zBMJIbvdZrGYDUzfY0QgvS5XR0cHmmgvId+a1J8XLcya8U4nmpUR7jNBYCGMMSFUp3l37tjy6A8E
QdAVBTTWbWp7gag+nxwZue2J/8jZsWUm2a6CwxujNCIpMWXpIsU7FYtgMkoFk5y2YjkRhZn9COPn
puv6YBMID5lqa2u/dq3aSLxUUB+Yzebt2zYXFxYEAkq4UYoQgZCjx949fPgoVychDkpECNE0jZfZ
4YJsTmbGBJ64TimldLDRbrSPScZYZGRkbm52wFioO0JIFMXgmhhjTdeLigolSRptT+MbEUVRMHYH
4f64/tmZnTJ8yyCEBEHgNiGDNDQ0McQmNqVRMIvHSI4/lp6eNnsNEDPFjkKYruffsWPXL56QIyI0
f4DAvMJb3eaioHq8tvj43b98ImvTeqbrY7RdTWVVgBHPMpq6Yplss03BUHeq67Ldlr1lA+JR+TN9
aJEkKUzZ5jPnzgUUxfhAwp2AmzauX7pkEU8dPly9Qj6qnTpz9vU33nLflOicIYTaOzobm5pkWdY0
LT7eGRcXOyHigO+CUjpUyV42tq3l5eTYrFaDedKDQgpjrChKvNOZnT1nzDpeEERiIAYr2LHhGRuG
5MREcaQA8753D0mqrav3+25JzRxV1zEe1jpFKbXZbMlJSbP2Ms2cJzKPec/csOau3z4dkZqseDxQ
S+dWqisx0OuOzsq843+eTi1bOoOdU1ypZ6xZGZGcqAeUKfVKjTGmmuYsLIjOnjNLXvfNZvOQFhQu
ldrb28+cOdv/Ym3UrsMYK1u+dO3qVdwLFqYZZVm+WnXtpZdfa2xsCs6qQwiVl19WFEUQiKZpc/Pz
DFrRjGpoSumgEMAxbJ4b2BIS4lNSkvVRTvINehitFsvYehpjrN+zyQysicPoXQAhlJKSLBszJRJC
3G53XX0jugV+On34+4UQoqhqRka6xWKetZdyZjl0CKGalrRowR2/+nlCaUmgtxfsWLdkVBeIv7sn
Zemiu57574SSwvF6BvFUP19GqS3eGV9aMuVq/BGi+wO52zejWRPigDGOckQN+bxmjImidPrM+cam
ZuNzpoJhVSUlRVs2b7RarWGSRTHGTCZTR0fHq6+9fv78RUoZIaShsfFyxRWTyeT3B2JjYzMy0if2
lCmllN50LqxvXuEYG7CkqMhgyZrQE4+MiCgsnDvOkRIbvS5Y1ymd2snnJhFKaUSEPSUlWdeNZsq4
fLliwg9D13WfzzfcI5FSKolSdtacCUwIBwJr8i0rTNedhfl3/u4Xubu2+bt7McYQkjWBEhYxprjc
c+/efcevfx6Vkc50OvMthRgjhPJ2bkWITZ1qDxghpuumKEdq2dIx2jSmG3xsTkpOHO55TQhRVfXg
wSNen29UZiS+ctaczDvv2JmUmMA11pBDF6VUkiRV0w4cPPTW23svX6k8dPgINwgxxubm59ptthFz
W492GNPpzdk3GPN4vGNTVwihtLSUhIQE40YsjLGqqkWFBRazZcw6nv9OCgnqCvvigFVVVVUVzdbg
aCM3Qm5ujpH5CjwusKW1tbW1bWJtq5qm9fT2CkOJZt5nkpMTU1OSGWOztqLdDDxtLAiMMZszbsdT
jy/53Kc0n4+qKmisCWlYPaDoqlr25c9v/9lPLLExhnO1zwRSy5ba4uPp1Ek0JQiqx5O8ZGHUnIyg
CpwNpKWkhE3CLra2tR46fHS0thY+9sTGxNx5x665c/NVVR1uehT/XpLEiiuV+/Yd6OzsFkVRVdWY
6OjS4iKuDybwfLnUIDcfiWesBeb4wRcXFRoUWNxbFxkZmZ+fNxF91mgJRUVVFVWFp+7wr1coNSU5
MSHeSHZ+QRC8Xu+l8oqJeg3jm1E1zeVyDXkzclFVWDB3DPlEQGBNfYsDZpQJkrTmka9tefyHpshI
1e3BgoDAoz/mBhWI4vaYoh3bn/hx2Ve/QARhwuoMTvkXVB5rY4mJzly/SvF4p4hYxwhRnaYsXSxa
LDRs5NAMIyYmOjkpiRdyGfLJLstyRUXl0WPv8Y+jtWPJsrxl04aysmWMsTAqhDEky3LQ0MUYKykp
NpnNE25xURRl8CDq8fr0cYSBZ6SnJSQkKAYmBHBTRF5ebkSEfcQJ+SPdRUYlLyHE5/P5fD549A5z
URCl1Gw2z52bZygzPmOSJFVWVXV2dU+QEYshhLo6uzSNDtlnNE1LTU3Jy81BY/IpY4wZo/r0n+gw
Y80PmGDEGKO08N677/79fycunBfo6UEzfabVrWlJghgK9PSmLl9y759+m3/nTsYYYmwWtSTGVKeY
kPRVK/HUEDIYY11R7Anx6auWo1kTQBqs+pKTk8UoHW6c4HasEydPnzh5ejhPX/hdIIQWL1ywbetm
i8WiqmqYkKybP1I0oS4tvim3x+v1+EKLWxNC/H5/d/dYBkseEGM2m3Ozs0ZUn3ykjIyIKJybN/6T
QQjpusYMnLUgCG632+VyoclwEU4LpyRXxgVz8+OdTk1Tw3dy3me8Hu/ps+cm8Bjq6up59YLBuxNF
cdnSxeMRc7quK8q0N2HO6DESY16yML6k6IPP/Xbhpx6kqqr5/RhmFxrvH4Kg+f1UUxd/5h8+8Mx/
x+b3FxmcZbZATDBCKHnxgpicLNXnn3xxibGuqI7MtMQFpbPwtSEnJzsuLi78jD9JEo+9+957x98f
7agZTPCTNSfzjt07E/tDskYc8E6fOd/T2zuBNUn4Ttvb29nNZl5BEHw+X2tb+9jUAB/28vJzIyMj
RjQS8HaIjo4el/mq/1wC/oBxi3Vra9vtf3ngZstpcRdwa+vyZUswJshAvgaTSb58+UpdXd34jVi8
YkFtfcOQf1IUtbSkOCkxccg+YzBNHaV0zH5wEFi3cSQSBKZT2W5b/2/f2PHzRyNTk5VeF8JgyhrZ
cIUx9vf0RGdl7vrlE2u/9bBotcyKkPZhWoNRGpmWklBapCuBSdeXDCGMccaalZgIU25u4y1+aWKM
WS2W+fNLRnxSi6J4/PjJ/QcOcivUqKYycZ0UFxuza8f2/Pw8RVGMGF32vP5WV79hafwyi8c/Xa+u
kSQp9OC5266urn5A1tNRaZ0Iuz07a074aWiUMVmW580rGb/QwRgHAoGAohgJUOMzCa5dr9EmwvdN
GTOeVUvX9TA2y1CDkKpqmn5bCyZSRmnIteaXPjMzo2DuXIPp3xijR44d577XMfdP3hVramq6uroG
5OIiBCuKkpaavHjxwuEUuUH9SojQ2dml6/otqqIIAmsCNRbh7sLcndvu++uzRR/6AFU1ze+HRFlh
DFeq16urasmH77vnL89kb9nIKEWzKaR9yIcTQihj7WrRbGGT/o5LKZbEnG2b+YN2doldjBFChXPn
ZmfNURQFhx2wJVk8f+HiK6+93tXVzUeg0YZkWSzmzZs2LF68UNO0ML/lfsm2traXX3mttraOuybH
Mzud76umtra9o2PA2EkpNZlM1TW1XV3d49EfxUVFsiwPd1IYY1VRcnOyR5U0PMy5dHR2ut0eg9Vy
CCFdXV3VNbVofD47jLGm6UZqKPU5ZN0eI1eNEOLxeNxuz4SM/IbzviK/PzD4+xUrliYlJQZGytLH
GJNEsaWl5eix4+M0RlJKL166PECJ8qa22+1r16wyyfJwu/AaCK2jlMqy1NDY2NHRCRasafJUJoTp
uj0pYetPf7TjqcdicrP9Xd3cOAHB7ze1EmP+7h5n4dxtT/x4y6P/bnPG9WW6ukWtNF3eTgQBITRn
41pLTBTV9clM34WxrqrxhQWxeTloFlao758Kt3LFcocjUlPDGTkYQyaTqb6+4W8vvHThUjn/IevH
oMbCCK1YvqysbNkAkTeUxpJ6e12v7nnjyNF33W5PUNKF7szI3vlxBgKB90+cQmyI3WGM/YHAiZOn
+Kcx3OiMoagoR07OnOGMH4wxs8nEc1/R8d2k/GTr6xvcHo/xiYQIoZOnTnPb4ZDNZSQZGCFEUZR2
w+N0a1sbM9oDSUXFlQm5+7jV08ATSGjv6AjNesD7p9lkXr9uTUSEfUSDH2XMJMuXystPnjw9Njsr
75lXKiurq2tC1Tm3toqiuGXzxtjY2CE3y0P6vF6fwemriqqeO38BBNY0MmUJvEvl7tj6gWd/s+xL
nyWSpLg9GCEIzCKCgBhTPB7RZFr+pc994Nnf5N+xgzfXrTX1TRN1ixFCDFnjYlOWLqaqhjGZxCul
erxzNq0TTCbG2Cx8PeBjg8Ph2LRxvSxJ4TMOcH+T3+8/cODgS6/sqW9owP3wHJ5DDga859OQinhz
8/NMJlPQ5DCcxuLz0k+ePPXiS6+cPXeej3mhkfbBvYc5YH5shw4fbW1tG7IiChdzV65WnTl3nm9p
tNYyPlLm5+WaTfLgdEo8kiYzMyPe6WSMkXH0MUopIcTlcl8qvyzLssHj5C3Z2tp29Nh7wYvVH+aP
GEOqqgb8ASNZoGRZulp1zePxEELC7L3PZFhTx4wll5Ik8WrVtUvll0Oq8o1FdzY0NHZ2do3oCKOU
SpJYU1vrdrvRzVWMGGPOuLgtmzaYzWbuUwu/X1EUj7773qnTZ4YuXh72GDDGLa1tR4++F2qJ5OpK
EMXNG9fzxFfDhV61tLT6fD4jeW4ZYyZJulxx5cLFS8EWnnauQuHb3/72bHs0Y4yZrpsiItJXr8hc
t8rX2dlZWaV6faLFNDsNWZhnYXC5CRGyt2zY+vgP5969W7Jama7zSKxbuu/qfQebT58TZOn2mbIw
ZpTKNtu8//OAYJKNizzGKJ+RX/HCK6LFPDm2N4wRY4JJXvr5TzvSUhmlBqMJGWWYkLoj7za8d0KQ
5dtz8LyYT/SczLl3755YMR2sXhwTG3O9ukZVtfCmEUIIIaSzs7Oq6lprW7vZbDabzZIkhuZZGPyg
4Hg83tq6ugMHDrrdHm4/MJvNPr9PFIbN8SOJotvjqa2rv1p1TdM1s8ksSqJACKVUUZTeXldPr8tk
kgccMx+ZMMZen++dg4cvV1yRJDHMhSKE1NXVC4KYkBAf6gA1aCFACEVGRDQ2NXd2dg1uPUEUV60s
czgcaKwBWH2vZ4SoqvrW3v0trW3SKLMiEUKam1t8fl9SYiIvQ0kpRYgRQiqvVlVcqTQSeEQI8Xq9
Pb2ujPR0SRKHbCWuApubW06cOm38fDHGtTV1gig642J5AxqfCsDXVFT17b37e3tdRvJFEUICAX8g
oGRlzemzrWJ8070QE1NXV+f3K6IohL+/CSE1NXWBQCAp6UZNw7CWYIYwJhg3Nze/+da+UEskjwi0
WCxbN2+Yk5nJKBvstec9AWN86syZ+voGSZINqjpCSG1tnSAQpzNOEIRg3cPpMm961gmsvj5BCKMU
MWRPiM+/Y0dsbk6gt7ezsopRRgQBCwKaJYVHBAEhpAcUze9PX1m25l8fWv7lz9mccbxxbkfEFcbV
Bw41nz47LQQWT04h2axXX39LdXsmZZ4EEQTF7U5cMG/xZ/5BNMnGZ3TOMIEVHFeio6MSE+IbGht8
Pr8gCOGfvKIoUsY6OjsvV1xpamru7e1VNU0ggslkwjfj8/laW9tqamvLyyveP3Hq/PkLfn9A13Wr
1bp+3Zr5pcWdnd3d3d2iOPQeGUL8YPx+f3V1TUXl1cam5pqausrKqxcuXjpx6vSp02eio6K4fSg4
WPKxqqKi8sA7h+rq6iVZGvEqYYxramo7OjslSYpyRIXaxkYc7PkKgkCuX68ZHEyTnpa6ZPFCNPbK
g300N7fs23+grq7eYO28wUNsU1NzQ0OjIAg2m02WJYxxXX39ocNHA4oiGLsHBUHo6OhoaGySJDEy
MiK0n/C0+/yK7913oLunx0gR5VCqa2paW9sIIdExUaTfsB2+8flf/X7/W3v319c3SIZbRhDE1rY2
n8/PhVGoWGSMRUdFpaQkNzU3c8UW/sIRQhobm5qaWyIiIhyOyNCV+w7mZrMr0+n5ixf3Hzzkdnsk
SQxeYkVRnHFxW7duTklOZmxodcXXrLp2/fjxk0Qgo3341FTXtLa1E0IiIuyh5zXOma23gdmbZRX3
v/BhhHJ3bp2zcd3V19868fSv2i9foV6vHGFHDLGZW0GJn77qcmNRcBYVLPrUg9lbN0rWvlIYMMUy
zIgekZyUtmL5hWf/bImNoZp2m4+BIcYoS1o4zxRhZ7o+y13b/Iqkpqbcfecd+985VFdXRwgRRXE4
f01/EnYJIdTY1FRbV2exWKxWq9lsMpnMZrNMCAkEFL/P5w8oPNclpYwbuhDCc+ZkrihbFhsTgxDa
vWv70WPvXbh4CSE0YJZf6ChFCDGZTFTXa2vqGKMIYUEkGOHIiIh4pzM4ivGB6tLlivLyio72DoSR
JBsddCVJqqq6VldXHxMTnZiYkJaaGh/vtFmtI449fIXsOXNiY2LaOzpCzR4Yo/nzS8c8hnGfUVNT
84WL5fX19V6fX5alMceqy7Lc0tr69r790VFR0THRiLH6hkZFUYwrIe5RbW5ubm1tjYmOTkxKyEhP
T05KNJvNhGDGWFNzy+Ejx1paWqTRq0BJkqpra+sbGs6cPZeenpaXmxMdFTWiuurs7Np34GBjY6NJ
lo27vvh81XPnLzY2Nc+fV5I1J5O7rVn/vZAQH3/n7l0HDx+pqroW/l7gDdvQ0Pha+xvpaakFc/OT
kpK4fg09eF3XvV7f9erqiorK5pYWQghXVwRjRdMwwsVFhSvKlpnN5uG6Cg+9On/h0omTJ3VdEwgZ
bT+QZLmmpra+viEqyhEbG5OWmpqSnGS326d+mngMlZ4QQlTTiSgghHRVvfy3ly8893zD8ROIIclm
xZiPaTOklfoMHowpHg8mJHnJwoIP3ll0z92C2YQQorp+W2dWMoYwPvDI907/5hnJZr19chZjqmn2
+PiPvv2SHGFHowljoppGRPHCH//y5r88Ilstt1+C85C43b/6WcbqFWw06V55Jz/yo8ff+8+nZbvt
9hw5xlj1++dsWHvX736Bblm4WNAIdO78hTNnz3V1dcuyHHQehZklx11Ouq5TyhC6aXjgLkU+NiCM
EhMSS4oL8/Ny0c0OpiuVV4+/f7Kjo0PunzYVfnfcRkUI2bRhfW5udvCvdfUN77xzsKu7B2McapkY
ldDUNI0fuSRJmRnpK8qW2e12A7cgunDh4t5975gtZu4pCwQCmZnpO7Zt5QpmDAKrrr7+2LvH29ra
dUpFQRj/THt+DJqm8brXojiWbQ5oJYvFUliQn5iYWH654np1DdX10dquBm+ZX77k5OSSosI5c9IH
zz/g7XntWvU7hw653R7jQWmDJQsPQ8zJzsrLzYmLix1g1Dl3/uLJU6d7e3vD98zgLUAIsVqt8U6n
IyqSG3Q1RfV4fV3dXR0dnbxyFH8zQQhRSlVVTYiPX7BgXvCmGC4pw9Wqa6fPnG1raxfG0RMGXDtC
SHRUVG5uTklxoSzLYMGa0hBR4NnJBUkq+tAH8u/cUfXW/kt/+mvtkfeoqmBREE1mhBCbzpn7iSAw
hDS/n+m6IIpZmzYU3nv3nE1rJYsFIcTjOiFvhUHLX9qqMkdaiquhUTSbb6fGwhjrqupITUldthhh
jGH2a8jDF2M8r7QkMyPjytWrFy9ecrncvH34Y/2mAYYxFhIXIklin/MSYx7Y3hf7ruuSJOXmZOfm
ZqenpYmiyH8YOlzl5eYkJyWdPXfh4qVLgUCAEMLdT/17QKFRMpqm6brucDjWr12dnp7GA7Yxxl6v
99DhI51d3ea+SjuMMTSq+rg81ImPNDw4/8LFS7Isr1u7emSTKMIZmRlR0VEej4d73DDG+Xl5oihS
ykZVV5G3Z2+va9/+gz09PSaTSRwU8DSqThu8ZHzhJotFyIjOm3io3930mf/LVQJjzO/3H3//JD8k
URT5xgcG+6Mh/dpDiISgZRQxVlNbU11Ts2HdmuKiwsHtU3Xt+ptv7qWMhho+B08yGG5vvN/yo3W7
3e+fOHnh4qUdO7amJieHuptLS4rS01LPXbhYXl6uKCo/x8EzB4M2XcaYz+e7dv16cDIBD7riXVqS
JIyRrlMucSIjI4uLCgsL51r6a0MNd1nfP3Hq2LvvybIp2OwT0MIIMcY6OjubDh2murZkyeIp6ysE
gXWzaQchpuui2Zy/e3vOtk2tZy+e+/1ztUeOueoaEMay3YYIZpRNpwgtPgwz5u/tRQg70lJTy5bM
++gDCfNLCH9R1nUsCJPsE8QY4duYb2Ac++LRe460VOfc/N66+v4nxO06boyZpmesWy2YTGM3CN3O
1sa3aZZocJ6RwxG5ZNHC4qLC2tq6ysqq9o5Ov9/r9flwiFEq1AnChxOuqXRKBUGwmM12u83hiMrK
zMjISLPb7UFFNWAyIP/SbretXLGscG7emXPna2pre3tdlFJRFPm++JY1TScE2+32nOysJYsXWiyW
vrEQIYSQoqg+n59Spqpq37RGxhhDjBvPQ+Zq9T2jKOPF4G6cS////WthxlCvyzXiwMOPMMJuL5ib
f+jwUZvV4vP50lJTs7Oy0FirVquqqgQClLLQzGEDzqhf8Aw6NT5FkI/tfeeHuKsrVNey4CRPxhhl
/UWK+u+S/pZBIf/faJ0QNRC07oQ0O7tpF3y5b+u4r6LijUPmm72xzK+pLEkul7uxsWlIgXX+wkVF
U61ms96fJzZ4Kn2t1C+yg1ZVPAi+KUKIzWrt7Opubm5JTU6+qWdSGhXlWLNqRWlx4fkLl65fr+5x
uXRNkyQpdEJDqPQkGBNJGtxhKKUBRaG6brFY4p3OnJzswoJ8C38zD1sQ3ePxVlZWybIsSWLwBPsn
A7JBLdwn94PN3N+nb+7c/a0hSZKu64GpXU4HBNagJw6ffUqpIElJi+cnLZ7fU1NX+frbtQcO1b37
nubzi2YzFgTCS0cPXxBtksUiIYgxqutM0zR/QLSYM9aszFy/Jnf7FkdGWt9twycJTrbVilFKNY1q
+u11EerjtEfm7Nh89Y29VNXYbaxWjTFhVMvesgH1W1+meGvzIPfbdmWDDgiL2Zyfl5ufl+t2e1rb
WtvbO3p6XV6P1+P1KIqqaZqua5QyQRAEQTCZTGazyWqxRERERERGxERHxzvjzGbzjQGGMTzMO3qf
sQqj6Jjo9evWuFyuqmvVLS2tnZ2dHp9XVzXJZDKbTTHR0fHx8dnZcxyRkaHDEv83KsqxdMmiiopK
XdclSRTEPiRRFERBEkVCBNQfNY8Q0nWdD1Sqxv/TNE3TVFXV+Pc6xsRqsSxYMC90rll4bTqvtNjl
ctfU1sbHO1etXCGKwhg6GF8/NjZm5cqyK5VXlYDCD5UIRBRFURBEURT4eQkC/4cb6rj2RQhRqnNl
pt5A8wf83EuF+lL1ESIIZpPJZJJlSZZlSZJlgQhEIH09nFJN1zVVVfuaR1dVVdNUSpmm6YwxXdcE
gciSjDFRlABCWBAIIUSSJUmU+ptdkiSJCEQQBIyQIAhciSOEdEoZpZqm67qmajpv+uA1EEUiinJO
TvaC+fOGlCCpKcnVNTUerzdolZEkSZYkSZJESZIlUZIkwg+IYF2nfDeKqmiqqqh9O+OqnW8/LTU1
Mz19iFdBxjDGUVFRq1etWLhwXnV1bUNjU3NzS3dPN6Ns8MtGv45EoVqTUma1WuLjnYmJiWkpyamp
qVx2G5l4KEmiMy62q7uLMYYRFkQiiryNRVGUJEkQBUkQBEIwIQRhLBCiU4r6X3g0Xdd1ndt9dV3X
dUp1ve8D1RVFccY7S0uKp7ScgBisEczT/WEums/fdrH82tsHqt7a21tbr3i9jFLJYhF4srUpoLS4
ruJlgDWfH2Es26wRKck52zZlbdnoLMgT+72BwReBSW9hhPGh7/7HuWf+KN7+GCyn8/6X/yzbbaM2
BTGGMPa0tT2360Oq14sIvl1HTfRAIDp7zl3/+0tLzKhrw/EYrHcf//mJp34l2a23TWBp/kDG2pW7
fvEEur0puwYPAJqmBQIKH5z4+zQf10VRlCRRlqRQO+5oZ4MPWN/j8SqKQinl7hWbzRr6Zj+c4UdV
NR5dFBQcRi8upXzYQYhRyjBG3MAwWnp6ei0WiyxL429/nVJux+JPGu6oFQgZVRwCPy9V1dweN093
zgUBwUSS+nWaKAS9wMFG7m8QXaeU6pQPyVwu8PEbEywKIiZY07T+wmBYIFxycwkncEU7+EIELTHB
Zg/+p+uUECwKYmRkpDDMLGxd1zs6OhRFJYJACOY7EoWbCN0pN65qusbF1k3nghDBOCLCHvo+EL5n
ulwul8vd2tbW1tbhcrlcLpeiaUFDaV/zEmK32yIjHY7IiIQEp8MRFWG3BUOdRvXk8fsDvb29DPXZ
2wghoiAQIggC6WtoQsigqdChLRwCC/mH6ZRGRkZYx9TPQWBNJaFFKaOU9Lv/qao1njhV9ebelnPn
O69WuxoaiSiIZjORpBsRAezG28CtdYpgFDSg6Kqq+f1U0yJSkqPnZCbOL8nauil58UJB6j9yTcOE
TLUZgprPryvK7Vd7mPt8x7Ff1eOltzksjzFBlkWLeeyt7Q/ogdtbS5EhLAmy1TpZb0nBUKcRR4WQ
tKJjjOgIZn4acuNhjiFMbsYwj+gBDi8j2zR4FuOMaBkhSUGfqxAhFO7UplRUzRjaZEoFBvX1zEFS
hoerq6rGDYRctkqSJBBhQBQBF+639IymeyODwBrfCzG/lsHoDU1rOXex7WJ506kzzafPdV2vYVTn
jw0sCEQQiUgwEYK/DT4vx6qlcDCumVGdapTpWt8AjzHGOCozI2nhvKSF853FBfHFhUJwbgV/O4GY
aGC238IjjOgTbj8b1cZZSI4EfFv2aMTsN4GNgMaaUsvgA3IMPxzDZiekO4U/tqGkdrh9odGbWo3/
ZLTrj/NMbxbiIw+XU3xQA4E1pgcHpYwyntmBdyJ/T4+rsaXp5Knm0+faL1/xdnQGXC7F5da8PoSx
IElEFLEoEB681XevhI3eCfHhUV1nuk51naoa1TRKdcliNUXYZbvdEhcTNzcvcf68pMXzI5OTzNFR
N144NJ1PApkODTorK+pNVkPd5taGiwsA0+P1A6rygsCaSl2Su8EHRxW4m5o7Kqt6aupcDY3u5hZ3
S6uvs8vf1e3r6lZ6XQgxhAkmfTNQUJ+rL1TzM8RY33RFjGS73exwmGOibc5Ya1ysLT7ekZEWlZEW
NSczMi1lwK6prmOoYA0AAAAAILBmgtIKvqyjIZxxisejuNyKyx1wuRWXK9DbG+hx+Xt6Ay4XVVVd
Uaiq9tmsCBHMJlGW5YgIOcJuirBb42Ikm0222eTICLMjUhoQy9Lv/uu7nPAOAgAAAAAgsAAAAAAA
AGYeUHIOAAAAAAAABBYAAAAAAAAILAAAAAAAABBYAAAAAAAAAAgsAAAAAAAAEFgAAAAAAAAgsAAA
AAAAAAAQWAAAAAAAACCwAAAAAAAAQGABAAAAAAAAILAAAAAAAABAYAEAAAAAAIDAAgAAAAAAAIEF
AAAAAAAAgMACAAAAAAAAgQUAAAAAAAACCwAAAAAAAACBBQAAAAAAAAILAAAAAAAABBYAAAAAAAAA
AgsAAAAAAAAEFgAAAAAAAAgsAAAAAAAAAAQWAAAAAAAACCwAAAAAAAAQWAAAAAAAACCwAAAAAAAA
ABBYAAAAAAAAUxFxEvdd19BStuVBvuyMjTp98A9j/kno9yNy7vAfY6IjR/UThFD1uZdEQRjyT5/8
/Hff2Peu8U2VFuW89uf/DP3m57/6y78//tvgx11bV/3XYw+Pp906Onvue/Dhisoa/nHlsnm/fepb
FrNp/GddW9/y91f2H3v/fNX1+p5ed0BRTLIcG+PIykxZuWzevXdtcsZGjaobMJ1ee2tfzcEjzWfO
eds7Ar0uQZLMMVExOdnpq5bn37HTEhsTfgsn/+s3R39yoz1ztm/Z/uSPh1yzt77xd+u2D7cdTIhk
s9oTExLnl+TfuSt1+RLjvx3MP1WcIsN0GAAAAAAEFnA7+OtL+0I/vrn/vV6XJzLCNrattXd23/eJ
r1+52qeu1q5Y+OsnHzGb5XEeJGPsx08+89Sv/6ppWuj3Xp/f2+Cva2h558ipx576ww//9XP33LnR
4DZrDx3d/8j3eusbQr+kmqY2+FwNTTXvHD722M8Wf+YfFn/6k5gMa229/MLLoR+v7z0Q6HWZIiNG
fYKUKi53p8vdWVl16S8vZG1av+WxH0hWK/RPAAAAYLSAi3DyOXvhypWq2tBvFEV9ac/BsW2traP7
vo8/HFRXG9cu+Z+f/+v41RVC6PGn//jEL/4UVFcY4yhHRFJCnMl0Y+N+v/Llbz5+7P3zRjZ47vfP
vfTJfxqgrgag+fzvPvazN7/6DcTYkCu0nLvYefVa6De6olS++sb4z/fa2/v3fO6r0D8BAACAMTAD
LVgx0ZGv/umnYVaIckSM9icIIXF4d8+PvvP5bz/0qdBvnvnTa0/9+nm+/KG7N//zZx4I/atJlkI/
Pv/ivuBhlBblHjh8EiH0/It7P3Lf9tGee1t7170ff+jq9Xr+cdvGsqcffUiSxLE1VOhZe33+p/vP
CGP8lc99+GP374qOikAIMcaOn7z49e89xT2SlLKf/Oz3f/3dj8JvueG9Ewe/+yNGKf8o221F930g
tWyZLT4u0Ovquna9/K8vtpy7yP965aXXkhaUln70gcHbufz3PvOVJToqvqSo5uAR/mXxA/eEPwBL
dNR9f/9j6Deq19tTW3fumefqjvQ5fGsOHqk7+l7aimUj/naIdxfwDwIAAIDAmkkIhKSlJNzqn4QS
FxM14BtHpD24bLdbw2xc07QX97zDl7duWL5ofgEXWCfOlFfXNmamJxs/jNa2zns/8XBVv7ravW31
k//xL2F04ajO+uLlaz5/gC8vW1z8z5++oXUwxssWFz/7y+9tvOuz8XHRaakJGWlJlDJCcJgNHvr+
j5nep65i83Pv/J+nbfHO4F9Ty5aWfPhDZ/7nmUM/eJTbro4/+Yui+z4gmEyhG6GaVvnKHr48Z9P6
pIXzucBqOnWmp6bWkZEe5gCwIESmDmze2LycORvW/vWBTzSdPNOnsQ4cGiywhvwtAAAAAMxkgTW9
ePud9zu7evsl0ZrSopyHvvNz7oZ7/sV9X/38Rwxup6W1895PPHStus/ddveu9T/9wZcFYcJcwD5f
ILjMhvLWJcTHXDj6nMGtNb5/qu3S5T6dJ0k7n3osVF0Fmf+Jj7ZXXO2qrEotW5q6YhkeJBar9x/0
dXXz5bydW53Fhfsf+S7VNIRQ+d9fXv7P/zSGM8WEZG3eEBRY7pZW6KUAAADAaIEYrEnm+Rf38oW4
mKiVy+ZFOSLWrlzAv/nry/vYMIFHA2hqaf/gx74WVFf33bXpP//9KxOorhBCczJuGGzeO3Hh0Z/9
PmjQGgN1R29MuszeujGMqWnTD79z719/X/bVL6StWEbEge8D5X/r9w/GxqSWLTNHOdJXl/FvKl54
BRlrvcFQVb3xCnKzzQwAAAAAQGBNdbq6XXsPvs+Xd29bzSXRXTvW9qmQhpb3TlwYcSONzW33fOyh
6tpG/vHD92579Hv/HN49NwbSUhI2rr2RtuDxp/84f/WHP/7Z7zz16+ffff+81+cf1dZaL5YHl1MH
OeAM4u/urjlwiC/n7tiKBYIQytvVF7jWW9/Y8P7JsagrTbv62pvBj/ElhdBRAQAAgNEyA12EbR3d
qUU7h/vrkgWFf//9j0f1E4TQG399smhu1oQf6guvHVDVvkl5d+1cxxe2biyzmE3cPvT8S/uWLykJ
swWfP3DPxx6qrW8OfpOTlYYxHn9DDT7r73/zs7V1/1p5rY5/9Hh9b79z/O13jiOEBIEUF+RsWL3o
njs3ZqQljayNOrqCy470tLG13pWX9+j9pqb8O/p0VdaWDaLFrPn8CKHLf385Zeni4X7OdL23vjH0
G83v775effrX/9tWXsG/MUVG5O3eMfi33vaOJ3PmhTm2+1/+s7MgH54vAAAAILCASSA4fzA9NWHR
/Ll82Woxb9mw7MXXDiKEXn3z8Pe+8ZkwSRbcHp/b4wv95ns/+fXc3MzVZfMn/GhTk+Nffu7xXz/z
4u+ee7W1rTP0T7pOz164cvbClSd++acHPrj121/7VPjEEKrvxjGLFvPYjic4fzAyNSVxQZ/ckSyW
rI3rrrzyOkLo6p631n7r66J5aB+fr6s7fOJQQZY3/+T75igHdFQAAABgtICLcNK4er3+7IUrfPnO
HetC/xS0Zrnc3tf3Hh1xU3k5GffdtSmodT7zlR/W1DXdimO22yxf/PT9J/b97yvPPf6Nrzy4bWNZ
QnzMAKX1+z/v+eLDj4bfjhxxY5al6nKP4Ui6qq4Hkzjk7b5JJ+Xd0WdzUtyea2/uHduZJs4ruet3
v5izYS10VAAAAGAMzLo8WGaTPNqfIIQS42Mn/Dj/8sLbweUnf/mnJ3/5p6FXe3FvUG8NyX13bfr+
I5+VJamxuf3wu2cQQt09rgc//92Xnn3UZrWMuaHCnDUheH5J3vySPP6xvrF1/6ETv/n9S0Hv4atv
Hj59rmJB6bA+Mqsz7oZUqq5JW1U22tYr//tLweUTT//qxNO/Gma1l4N6yzhzNqzd9csnwqwwYh4s
W4ITHi4AAAAgsGYUtz8P1higlP3t5f1G1jz87pnWts5459D1+JyxUY99/0t8+amffG37vV9oaGpD
CFVU1nzx4Uf/+6ffCBOPNVFnnZoc/9EP7bj/A1s+/KlHjh4/x788ePR0GIGVOL+06vU+fVlz8Ejp
R+4f1R4ZpRUvvGpkzbqj73pa223xcUOIvLjYT757o0KRp7Xt91vvUlxuhND1fe9U7z+UuX71cJuF
PFgAAABAeMBFODkcee9sU0u7kTV1nf7VmBSLiY781ROPBAvXvP72scefeva2nZEkiXfvWh/82NMb
zvGXuXZVcLnmwOG2kEmFA7jw7F/+uPu+93/+y66q68Ev648ddze3GJJiOq148RUja9rinSv/35eC
H/d94zuBXhd0VAAAAGBsQJD75PCXF2/4B//36W+vXDZwSlpPr3vpxo9ruo4Qev6lvZ958INGNltS
mP3Db33uS19/jH98/Ok/FuZnbdtUNs6j9Xh9j/382eraxuu1TT29rtf/8oQzLnrwauVXbmigAbFZ
A7VgbnbmutXVBw4hhBilr/3TV+787X9FZQ7MhnV974FD//4TzedvL6949/Gf3/v8M4nzSxFC5X+7
4R/c/aufpZUtHfBDf4/rt6u3UF1HCF3++8sL/+/HjZxm8f0frHjp1cb3TyGEPK1tB7/7o80//h70
VQAAAGAaCyyd0rqGcDaJ+Lhok0merL0jhCLs1sFFDMesV15/+xhfjo1xrFm5cHBBm3hnzKqy+bxs
TkVlzYXyquKCbCMbv/fOjecuVP7Psy8jhBhjX3z40ZcyHs3PzRjPWduslsPvnrl4ua+m8rZ7v/C5
f7hvxdLSeGeM3Wbx+vxV1+v/9vL+3z3X57bDGG9YsyT8lld9/auNJ04pbg9CqLe+4dmd9xTec2f6
6hX2xATNH+itq6987Y3qA4eDyULzdm3j6kr1eq+92efas8REp69eMbjqny3elLZyOS+b03Hlatul
y87CuSO3HcYbvv+tP+66V1cUrsxyt2/J3LBm8IqDUzwMRrbbYAYiAAAACKxJprOrt2zLg2FW+Mtv
f1gWNiPULd07QujjD+z63jc/MyG7e/XNI8HMnDs2rxyuXOAd29dwgYUQ+suLew0KLITQt772Dxcv
Xzt+6iIXc5/43L+99uefDlaHozrrH3378/d+/CGenaultfORH/xXmF994sO7c7NGyG4VnZW57Ykf
7/mnr/CUDXogcP4Pfz7/hz8PuXLSovkbfvAtvnx1z1vBLA/Z2zYNV1M5d+dWLrAQQuV/e8mQwEIo
OitzyWf/77s//Tn/uO+b3/nwnr+bHJEDVhsxxQNCqPQj96/99sPwiAEAAJidQAzWJBAsj4MQunP7
muFW276xTJYlvvziq+9wd6Eh1SyKv3j84aCTrra++dNf/qHeX1l5bMwvyfvTb36QPSc1/GqyLP3z
px/4zkOfMrLNjDUr7/vbH7hdatgOKgjzPv7hu373S8lq5d8E018hhPJ2bRvuh9lbNgpyn8nzyst7
qOHWW/TpB2Pzcviyp7X94Hd/BD0WAAAAAIE11Wloajv2/nm+nBAfs3RR8XBrRkTY1q9axJfbO7uD
1iwjOOOi//un35CkPgvl4XfP/NuPfzXOI184b+7+l/7rt09966Mf2jGvOC82xiHLkiAQu82Snpq4
ce2SR/7lk0de/9VXP/8Rg6nkEUIxudn3Pv/MB5799fxPfDShtMjqjBMkSZBlW7wzbeXysq9+4WMH
Xlvzzf8XTBbqamyqf+8EX7bFO5MXLxxW6kXYM9as5Mu+js7ad44YvSVEccMPvoVJ361x+YVXru89
AP0WAAAAGBWYjbUgLgAAAAAAADD06zo0AQAAAAAAAAgsAAAAAAAAEFgAAAAAAAAgsAAAAAAAAAAQ
WAAAAAAAACCwAAAAAAAAQGABAAAAAAAAILAAAAAAAABAYAEAAAAAAIDAAgAAAAAAAEBgAQAAAAAA
gMACAAAAAAAAgQUAAAAAAAACCwAAAAAAAACBBQAAAAAAAAILAAAAAAAABBYAAAAAAAAAAgsAAAAA
AAAEFgAAAAAAAAgsAAAAAAAAAAQWAAAAAAAACCwAAAAAAAAQWAAAAAAAAAAILAAAAAAAABBYAAAA
AAAAILAAAAAAAABAYAEAAAAAAAAgsAAAAAAAAEBgAQAAAAAAgMACAAAAAAAAQGABAAAAAACAwAIA
AAAAAACBBQAAAAAAAIDAAgAAAAAAAIEFAAAAAAAAAgsAAAAAAAAAgQUAAAAAAAACCwAAAAAAAAQW
AAAAAAAACCwAAAAAAAAABBYAAAAAAAAILAAAAAAAABBYAAAAAAAAAAgsAAAAAAAAEFgAAAAAAAAz
hf8f94wkcVF5+f8AAAAASUVORK5CYII=
'@
    $compact = ($b64 -replace '\s','')
    return [System.Convert]::FromBase64String($compact)
}

function Find-FirstExistingPath {
    param([string[]]$Candidates)
    foreach ($candidate in $Candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) {
            return (Get-Item -LiteralPath $candidate).FullName
        }
    }
    return $null
}

function Initialize-ReportAssets {
    param(
        [string]$PreferredTemplatePath,
        [string]$PreferredLogoPath,
        [string]$ScriptRoot,
        [string]$DestinationDir
    )

    $templateCandidates = @(
        $PreferredTemplatePath
        (Join-Path $ScriptRoot "Get-ExpiringClientSecrets.EmailTemplate.html")
        (Join-Path $DestinationDir "Get-ExpiringClientSecrets.EmailTemplate.html")
        "C:\Scripts\ExpiringSecretsReports\Get-ExpiringClientSecrets.EmailTemplate.html"
        "C:\Scripts\Get-ExpiringClientSecrets.EmailTemplate.html"
    )
    $foundTemplate = Find-FirstExistingPath -Candidates $templateCandidates
    if ($foundTemplate) {
        $script:TemplatePath = $foundTemplate
        $script:TemplateText = [System.IO.File]::ReadAllText($foundTemplate, [System.Text.Encoding]::UTF8)
        Write-Log "Using email template: $foundTemplate" -Level INFO
    } else {
        $script:TemplateText = Get-EmbeddedEmailTemplate
        $script:TemplatePath = Join-Path $DestinationDir "Get-ExpiringClientSecrets.EmailTemplate.html"
        [System.IO.File]::WriteAllText($script:TemplatePath, $script:TemplateText, [System.Text.UTF8Encoding]::new($false))
        Write-Log "Sidecar HTML template was not next to the script (looked for Get-ExpiringClientSecrets.EmailTemplate.html). Using the built-in template and writing a copy to $($script:TemplatePath)." -Level WARNING
    }

    $logoCandidates = @(
        $PreferredLogoPath
        (Join-Path $ScriptRoot (Join-Path "assets" "owens-minor-logo.png"))
        (Join-Path $ScriptRoot "owens-minor-logo.png")
        (Join-Path $DestinationDir "owens-minor-logo.png")
        "C:\Scripts\ExpiringSecretsReports\assets\owens-minor-logo.png"
        "C:\Scripts\ExpiringSecretsReports\owens-minor-logo.png"
        "C:\Scripts\owens-minor-logo.png"
    )
    $foundLogo = Find-FirstExistingPath -Candidates $logoCandidates
    if ($foundLogo) {
        $script:LogoPath = $foundLogo
        Write-Log "Using company logo: $foundLogo" -Level INFO
    } else {
        $script:LogoPath = Join-Path $DestinationDir "owens-minor-logo.png"
        [System.IO.File]::WriteAllBytes($script:LogoPath, (Get-EmbeddedLogoBytes))
        Write-Log "Logo file was not next to the script. Extracted the built-in Owens & Minor logo to $($script:LogoPath)." -Level WARNING
    }
}

#endregion

#region ### 8. INITIALIZE ######################################################

$script:ScriptRoot = Get-ScriptRootPath -InvocationPath $MyInvocation.MyCommand.Path

$TenantId     = Resolve-ConfigString -ParamValue $TenantId     -EnvironmentName "ENTRA_TENANT_ID"     -Fallback $DefaultTenantId
$ClientId     = Resolve-ConfigString -ParamValue $ClientId     -EnvironmentName "ENTRA_CLIENT_ID"     -Fallback $DefaultClientId
$ClientSecret = Resolve-ConfigString -ParamValue $ClientSecret -EnvironmentName "ENTRA_CLIENT_SECRET" -Fallback $DefaultClientSecret
$SmtpServer   = Resolve-ConfigString -ParamValue $SmtpServer   -EnvironmentName "ENTRA_SMTP_SERVER"   -Fallback $DefaultSmtpServer
$FromEmail    = Resolve-ConfigString -ParamValue $FromEmail    -EnvironmentName "ENTRA_FROM_EMAIL"    -Fallback $DefaultFromEmail

if (-not $ToEmail -or @($ToEmail).Count -eq 0) { $ToEmail = $DefaultToEmail }
if ([string]::IsNullOrWhiteSpace($OutputDir)) { $OutputDir = $DefaultOutputDir }

$PreferredLogoPath     = $LogoPath
$PreferredTemplatePath = $TemplatePath

$CurrentDate   = Get-Date
$CurrentUtc    = [datetime]::UtcNow
$TimeZoneLabel = Get-LocalTimeZoneLabel -At $CurrentDate
$strTime       = $CurrentDate.ToString("yyyyMMdd_HHmmss")

try {
    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }
} catch {
    Write-Host "Failed to create output directory '$OutputDir': $($_.Exception.Message)" -ForegroundColor Red
    exit 5
}

$script:LogFile     = Join-Path $OutputDir "ExpiringClientSecrets_$strTime.log"
$OutputExpiringXlsx = Join-Path $OutputDir "ClientSecrets_Expiring_$strTime.xlsx"
$OutputExpiredXlsx  = Join-Path $OutputDir "ClientSecrets_Expired_$strTime.xlsx"
$OutputExpiringCsv  = Join-Path $OutputDir "ClientSecrets_Expiring_$strTime.csv"
$OutputExpiredCsv   = Join-Path $OutputDir "ClientSecrets_Expired_$strTime.csv"
$HtmlPreviewPath    = Join-Path $OutputDir "ClientSecrets_EmailPreview_$strTime.html"

try {
    Write-Log "Script started (Client Secrets ONLY mode)" -Level INFO
    Write-Log "Output directory: $OutputDir" -Level INFO
    Write-Log "Script root: $script:ScriptRoot" -Level INFO
    Initialize-ReportAssets -PreferredTemplatePath $PreferredTemplatePath -PreferredLogoPath $PreferredLogoPath -ScriptRoot $script:ScriptRoot -DestinationDir $OutputDir
    $TemplatePath = $script:TemplatePath
    $LogoPath     = $script:LogoPath
    Write-Log "Logo path: $LogoPath (exists=$(Test-Path -LiteralPath $LogoPath))" -Level INFO
    Write-Log "Template path: $TemplatePath (exists=$(Test-Path -LiteralPath $TemplatePath))" -Level INFO

    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Write-Log "TLS 1.2 enforced" -Level INFO

    Initialize-ExcelModule
    Remove-OldReports -Directory $OutputDir -RetentionDays $ReportRetentionDays
} catch {
    Write-Log "Initialization failed: $($_.Exception.Message)" -Level ERROR
    exit 5
}

#endregion

#region ### 9. COLLECT SECRETS #################################################

$ExpiringItems     = New-Object System.Collections.ArrayList
$appsScanned       = 0
$appsWithSecrets   = 0
$secretsEvaluated  = 0
$secretsExpiring   = 0
$secretsExpired    = 0
$secretsWithOwners = 0
$secretsNoOwners   = 0

if ($RenderSampleEmail) {
    Write-Log "RenderSampleEmail specified - generating branded preview from sample data (Graph is not called)." -Level WARNING
    $sampleRows = New-SampleSecretRows -NowUtc $CurrentUtc
    foreach ($row in $sampleRows) {
        [void]$ExpiringItems.Add($row)
        $secretsEvaluated++
        if ($row.DaysRemaining -lt 0) { $secretsExpired++ } else { $secretsExpiring++ }
        if ([string]::IsNullOrWhiteSpace($row.OwnerNames)) { $secretsNoOwners++ } else { $secretsWithOwners++ }
    }
    $appsScanned     = 48
    $appsWithSecrets = 22
} else {
    if ((Test-PlaceholderSecret $TenantId) -or (Test-PlaceholderSecret $ClientId) -or (Test-PlaceholderSecret $ClientSecret)) {
        Write-Log "TenantId / ClientId / ClientSecret are not configured. Set them via parameters or ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET. Do not store a real secret in the script file." -Level ERROR
        exit 1
    }

    try {
        Write-Log "Acquiring access token..." -Level INFO
        $tokenBody = @{
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = "https://graph.microsoft.com/.default"
            grant_type    = "client_credentials"
        }
        $tokenResponse = Invoke-RestMethod `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -Method Post -Body $tokenBody -ErrorAction Stop
        $AccessToken = $tokenResponse.access_token
        if ([string]::IsNullOrWhiteSpace($AccessToken)) { throw "Access token is null or empty" }
        $Headers = @{
            Authorization = "Bearer $AccessToken"
            "Content-Type" = "application/json"
            "User-Agent"  = "OwensMinor-ExpiringClientSecrets/2.0"
        }
        Write-Log "Access token acquired successfully" -Level INFO
    } catch {
        Write-Log "Authentication failed: $($_.Exception.Message)" -Level ERROR
        exit 1
    }

    try {
        Write-Log "Fetching App Registrations from Graph API..." -Level INFO
        $appUri = "https://graph.microsoft.com/v1.0/applications?`$select=id,displayName,appId,passwordCredentials&`$top=999"
        $Apps   = Get-AllGraphItems -Uri $appUri -Headers $Headers
        $appsScanned = @($Apps).Count
        Write-Log "Retrieved $appsScanned App Registrations" -Level INFO
    } catch {
        Write-Log "Failed to fetch data from Graph API: $($_.Exception.Message)" -Level ERROR
        exit 2
    }

    try {
        Write-Log "Scanning App Registrations for expiring client secrets..." -Level INFO
        foreach ($App in @($Apps)) {
            if (-not $App.passwordCredentials) { continue }
            $appsWithSecrets++

            foreach ($Secret in @($App.passwordCredentials)) {
                if (-not $Secret.endDateTime) { continue }
                $secretsEvaluated++

                $ExpiryUtc = ConvertTo-UtcDateTime -Value $Secret.endDateTime
                if ($null -eq $ExpiryUtc) { continue }
                $DaysRemaining = [int][math]::Floor(($ExpiryUtc - $CurrentUtc).TotalDays)

                if ($DaysRemaining -gt $DaysThreshold) { continue }
                if ($DaysRemaining -lt 0 -and -not $IncludeExpired) { continue }

                if ($DaysRemaining -lt 0) { $secretsExpired++ } else { $secretsExpiring++ }

                $owners      = Get-ApplicationOwners -AppObjectId $App.id -Headers $Headers
                $ownerNames  = (($owners | Select-Object -ExpandProperty Name  | Where-Object { $_ }) -join "; ")
                $ownerEmails = (($owners | Select-Object -ExpandProperty Email | Where-Object { $_ }) -join "; ")
                if (@($owners).Count -gt 0) { $secretsWithOwners++ } else { $secretsNoOwners++ }

                $secretName = $Secret.displayName
                if ([string]::IsNullOrWhiteSpace($secretName)) { $secretName = "(unnamed)" }

                $createdUtc = ConvertTo-UtcDateTime -Value $Secret.startDateTime
                $createdStr = if ($createdUtc) { $createdUtc.ToString("yyyy-MM-dd") } else { "" }

                [void]$ExpiringItems.Add([PSCustomObject]@{
                    Name          = $App.displayName
                    Type          = "Client Secret"
                    Status        = $(if ($DaysRemaining -lt 0) { "EXPIRED" } else { "Expiring" })
                    Severity      = Get-SecretSeverity -DaysRemaining $DaysRemaining
                    AppId         = $App.appId
                    SecretName    = $secretName
                    SecretHint    = $Secret.hint
                    KeyId         = $Secret.keyId
                    CreatedDate   = $createdStr
                    ExpiryDate    = $ExpiryUtc.ToString("yyyy-MM-dd")
                    DaysRemaining = $DaysRemaining
                    OwnerNames    = $ownerNames
                    OwnerEmails   = $ownerEmails
                    PortalUrl     = Get-EntraCredentialsUrl -AppId $App.appId
                })
            }
        }
    } catch {
        Write-Log "Error scanning client secrets: $($_.Exception.Message)" -Level ERROR
        exit 2
    }
}

Write-Log "Applications scanned             : $appsScanned" -Level INFO
Write-Log "Applications containing secrets  : $appsWithSecrets" -Level INFO
Write-Log "Client secrets evaluated         : $secretsEvaluated" -Level INFO
Write-Log "Reportable secrets (expiring)    : $secretsExpiring" -Level INFO
Write-Log "Reportable secrets (expired)     : $secretsExpired" -Level INFO
Write-Log "  - With owners assigned         : $secretsWithOwners" -Level INFO
Write-Log "  - With NO owners assigned      : $secretsNoOwners" -Level INFO

#endregion

#region ### 10. DEDUPE, SPLIT & EXPORT ########################################

$ExpiringReportPath = $null
$ExpiredReportPath  = $null
$ExpiringCount      = 0
$ExpiredCount       = 0
$ExpiredList        = @()
$ExpiringList       = @()
$AllReportable      = @()

try {
    Write-Log "Deduplicating and splitting results..." -Level INFO

    $unique = @($ExpiringItems.ToArray())
    if ($unique.Count -gt 0) {
        $unique = @(
            $unique |
                Group-Object AppId, KeyId, ExpiryDate |
                ForEach-Object { $_.Group[0] } |
                Sort-Object { $_.DaysRemaining }, { $_.Name }
        )
    }

    $ExpiredList   = @($unique | Where-Object { $_.Status -eq "EXPIRED" })
    $ExpiringList  = @($unique | Where-Object { $_.Status -eq "Expiring" })
    $AllReportable = @($unique)
    $ExpiredCount  = $ExpiredList.Count
    $ExpiringCount = $ExpiringList.Count

    if ($ExpiringCount -gt 0) {
        $ExpiringReportPath = Export-SecretReport -Items $ExpiringList -XlsxPath $OutputExpiringXlsx -CsvPath $OutputExpiringCsv -WorksheetName "Expiring Secrets"
        Write-Log "Exported $ExpiringCount EXPIRING client secrets to $ExpiringReportPath" -Level INFO
    } else {
        Write-Log "No expiring (not-yet-expired) client secrets found within $DaysThreshold days." -Level INFO
        $emptyItem = [PSCustomObject]@{
            Name = "No expiring client secrets found within $DaysThreshold days"
            Type = ""; Status = ""; Severity = ""; AppId = ""; SecretName = ""
            SecretHint = ""; KeyId = ""; CreatedDate = ""; ExpiryDate = ""; DaysRemaining = ""
            OwnerNames = ""; OwnerEmails = ""; PortalUrl = ""
        }
        $ExpiringReportPath = Export-SecretReport -Items @($emptyItem) -XlsxPath $OutputExpiringXlsx -CsvPath $OutputExpiringCsv -WorksheetName "Expiring Secrets"
        Write-Log "Created empty EXPIRING report at $ExpiringReportPath" -Level INFO
    }

    if ($ExpiredCount -gt 0) {
        $ExpiredReportPath = Export-SecretReport -Items $ExpiredList -XlsxPath $OutputExpiredXlsx -CsvPath $OutputExpiredCsv -WorksheetName "Expired Secrets"
        Write-Log "Exported $ExpiredCount EXPIRED client secrets to $ExpiredReportPath" -Level INFO
    } else {
        Write-Log "No expired client secrets found - expired workbook was not generated." -Level INFO
    }
} catch {
    Write-Log "Failed to export report(s): $($_.Exception.GetType().FullName): $($_.Exception.Message)" -Level ERROR
    if ($_.Exception.InnerException) {
        Write-Log "Inner: $($_.Exception.InnerException.Message)" -Level ERROR
    }
    Write-Log "At: $($_.InvocationInfo.PositionMessage)" -Level ERROR
    Write-Log "$($_.ScriptStackTrace)" -Level ERROR
    exit 3
}

#endregion

#region ### 11. EMAIL REPORT ###################################################

try {
    Write-Log "Preparing email report..." -Level INFO

    $Attachments = @()
    if ($ExpiringReportPath -and (Test-Path -LiteralPath $ExpiringReportPath)) { $Attachments += $ExpiringReportPath }
    if ($ExpiredReportPath  -and (Test-Path -LiteralPath $ExpiredReportPath))  { $Attachments += $ExpiredReportPath }

    if (-not $RenderSampleEmail -and $Attachments.Count -eq 0) {
        throw "No report files were found to attach."
    }

    $severityExpired = @($AllReportable | Where-Object { $_.Severity -eq "Critical" }).Count
    $severityUrgent  = @($AllReportable | Where-Object { $_.Severity -eq "Urgent" }).Count
    $severityWarning = @($AllReportable | Where-Object { $_.Severity -eq "Warning" }).Count
    $severityWatch   = @($AllReportable | Where-Object { $_.Severity -eq "Watch" }).Count

    $attachmentCounts = @{}
    if ($ExpiringReportPath) { $attachmentCounts[$ExpiringReportPath] = $ExpiringCount }
    if ($ExpiredReportPath)  { $attachmentCounts[$ExpiredReportPath]  = $ExpiredCount }

    $emailLogoSrc = "cid:om-logo"
    if ($WriteHtmlPreview -or $RenderSampleEmail) {
        if (Test-Path -LiteralPath $LogoPath) {
            $logoFull = (Get-Item -LiteralPath $LogoPath).FullName
            $emailLogoSrc = ([System.Uri]::new($logoFull)).AbsoluteUri
        }
    }
    if ([string]::IsNullOrWhiteSpace($emailLogoSrc)) { $emailLogoSrc = "cid:om-logo" }

    $EmailBody = New-ExpirationReportHtml `
        -TemplateText $script:TemplateText `
        -LogoSrc $emailLogoSrc `
        -GeneratedAt $CurrentDate `
        -TimeZoneLabel $TimeZoneLabel `
        -DaysThreshold $DaysThreshold `
        -IncludeExpired $IncludeExpired `
        -AppsScanned $appsScanned `
        -AppsWithSecrets $appsWithSecrets `
        -SecretsEvaluated $secretsEvaluated `
        -ExpiringCount $ExpiringCount `
        -ExpiredCount $ExpiredCount `
        -UnownedCount $secretsNoOwners `
        -SecretsWithOwners $secretsWithOwners `
        -SeverityExpired $severityExpired `
        -SeverityUrgent $severityUrgent `
        -SeverityWarning $severityWarning `
        -SeverityWatch $severityWatch `
        -PreviewItems $AllReportable `
        -PreviewRowCount $PreviewRowCount `
        -AttachmentPaths $Attachments `
        -AttachmentCounts $attachmentCounts `
        -ComputerName $env:COMPUTERNAME

    if ($WriteHtmlPreview -or $RenderSampleEmail) {
        [System.IO.File]::WriteAllText($HtmlPreviewPath, $EmailBody, [System.Text.UTF8Encoding]::new($false))
        Write-Log "Wrote HTML preview: $HtmlPreviewPath" -Level INFO
    }

    # When actually mailing, rebuild with cid: so Outlook uses the LinkedResource.
    if (-not $SkipEmail -and -not $RenderSampleEmail) {
        $EmailBody = New-ExpirationReportHtml `
            -TemplateText $script:TemplateText `
            -LogoSrc "cid:om-logo" `
            -GeneratedAt $CurrentDate `
            -TimeZoneLabel $TimeZoneLabel `
            -DaysThreshold $DaysThreshold `
            -IncludeExpired $IncludeExpired `
            -AppsScanned $appsScanned `
            -AppsWithSecrets $appsWithSecrets `
            -SecretsEvaluated $secretsEvaluated `
            -ExpiringCount $ExpiringCount `
            -ExpiredCount $ExpiredCount `
            -UnownedCount $secretsNoOwners `
            -SecretsWithOwners $secretsWithOwners `
            -SeverityExpired $severityExpired `
            -SeverityUrgent $severityUrgent `
            -SeverityWarning $severityWarning `
            -SeverityWatch $severityWatch `
            -PreviewItems $AllReportable `
            -PreviewRowCount $PreviewRowCount `
            -AttachmentPaths $Attachments `
            -AttachmentCounts $attachmentCounts `
            -ComputerName $env:COMPUTERNAME
    }

    $EmailSubject = $Subject
    if ($ExpiredCount -gt 0) {
        $EmailSubject = "$Subject - ACTION REQUIRED ($ExpiredCount expired)"
    } elseif ($severityUrgent -gt 0) {
        $EmailSubject = "$Subject - $severityUrgent expire within 7 days"
    }

    if ($SkipEmail -or $RenderSampleEmail) {
        Write-Log "Email send skipped (SkipEmail=$SkipEmail, RenderSampleEmail=$RenderSampleEmail). Subject would be: $EmailSubject" -Level INFO
    } else {
        Write-Log "Sending email with $($Attachments.Count) attachment(s)..." -Level INFO
        Send-HtmlReportEmail `
            -SmtpHost $SmtpServer `
            -From $FromEmail `
            -To $ToEmail `
            -EmailSubject $EmailSubject `
            -HtmlBody $EmailBody `
            -Attachments $Attachments `
            -InlineLogoPath $LogoPath `
            -InlineLogoContentId "om-logo"
        Write-Log "Email sent successfully to $($ToEmail -join ', ')" -Level INFO
    }
} catch {
    Write-Log "Failed to send email: $($_.Exception.Message)" -Level ERROR
    exit 4
}

#endregion

#region ### 12. SUCCESS ########################################################

Write-Log "Script completed successfully" -Level INFO
exit 0

#endregion

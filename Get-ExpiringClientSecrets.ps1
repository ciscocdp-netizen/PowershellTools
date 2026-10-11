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

    The HTML email is built from Get-ExpiringClientSecrets.EmailTemplate.html
    and embeds assets\owens-minor-logo.png as an inline CID image (Outlook-safe).

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
        [Parameter(Mandatory = $true)][string]$TemplateFile,
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

    if (-not (Test-Path -LiteralPath $TemplateFile)) {
        throw "Email template not found: $TemplateFile"
    }

    $html = [System.IO.File]::ReadAllText($TemplateFile, [System.Text.Encoding]::UTF8)

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

#region ### 8. INITIALIZE ######################################################

$script:ScriptRoot = Get-ScriptRootPath -InvocationPath $MyInvocation.MyCommand.Path

$TenantId     = Resolve-ConfigString -ParamValue $TenantId     -EnvironmentName "ENTRA_TENANT_ID"     -Fallback $DefaultTenantId
$ClientId     = Resolve-ConfigString -ParamValue $ClientId     -EnvironmentName "ENTRA_CLIENT_ID"     -Fallback $DefaultClientId
$ClientSecret = Resolve-ConfigString -ParamValue $ClientSecret -EnvironmentName "ENTRA_CLIENT_SECRET" -Fallback $DefaultClientSecret
$SmtpServer   = Resolve-ConfigString -ParamValue $SmtpServer   -EnvironmentName "ENTRA_SMTP_SERVER"   -Fallback $DefaultSmtpServer
$FromEmail    = Resolve-ConfigString -ParamValue $FromEmail    -EnvironmentName "ENTRA_FROM_EMAIL"    -Fallback $DefaultFromEmail

if (-not $ToEmail -or @($ToEmail).Count -eq 0) { $ToEmail = $DefaultToEmail }
if ([string]::IsNullOrWhiteSpace($OutputDir)) { $OutputDir = $DefaultOutputDir }

if ([string]::IsNullOrWhiteSpace($LogoPath)) {
    $LogoPath = Join-Path $script:ScriptRoot (Join-Path "assets" "owens-minor-logo.png")
}
if ([string]::IsNullOrWhiteSpace($TemplatePath)) {
    $TemplatePath = Join-Path $script:ScriptRoot "Get-ExpiringClientSecrets.EmailTemplate.html"
}

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
        -TemplateFile $TemplatePath `
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
            -TemplateFile $TemplatePath `
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

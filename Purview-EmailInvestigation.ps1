#Requires -Version 5.1

<#
.SYNOPSIS
    Microsoft Purview eDiscovery email investigation tool.

.DESCRIPTION
    Searches Exchange Online mailbox content for messages sent by one user
    to selected recipient domains. It creates a compliance search, monitors
    progress, and writes search statistics.     When the search finds messages,
    it also writes a spreadsheet with one row per message, including the
    subject line. It does not delete, move, or modify email messages, and it
    does not download message bodies. Microsoft 365 no longer accepts the old
    preview command, so the subject list comes from a Purview item report and
    may ask for a second sign-in. No hold is placed.

    Run the script on Windows to open the GUI. The search runs on a background
    runspace so the window stays responsive while Microsoft sign-in and the
    compliance search are in progress.

.NOTES
    Requires Windows PowerShell 5.1 or PowerShell 7 on Windows.
    Requires ExchangeOnlineManagement 3.9.0 or later.
    The connection uses Connect-IPPSSession -EnableSearchOnlySession, which
    current Security & Compliance PowerShell requires for these cmdlets.
    The signed-in account needs eDiscovery or Compliance Search permissions.

    The end date is inclusive. KeyQL receives an exclusive upper bound of the
    next calendar day because a date-only sent<= bound is midnight.
#>

$script:AppVersion = '2.2'

function ConvertTo-KqlPhrase {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    return (($Value -replace '\\', '\\') -replace '"', '\"')
}

function Test-EmailAddress {
    param([AllowEmptyString()][string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    $candidate = $Address.Trim()
    if ($candidate.Length -gt 320) { return $false }
    return $candidate -match '^[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
}

function Test-RecipientDomain {
    param([AllowEmptyString()][string]$Domain)
    if ([string]::IsNullOrWhiteSpace($Domain)) { return $false }
    if ($Domain.Length -gt 253) { return $false }
    return $Domain -match '^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
}

function ConvertTo-RecipientDomainList {
    param([AllowEmptyString()][string]$InputText)
    $tokens = @(
        $InputText -split '[,;\s]+' |
            ForEach-Object { $_.Trim().TrimStart('@').TrimEnd('.').ToLowerInvariant() } |
            Where-Object { $_ }
    )
    if ($tokens.Count -eq 0) {
        throw 'At least one recipient domain is required.'
    }

    $unique = New-Object System.Collections.Generic.List[string]
    foreach ($token in $tokens) {
        if (-not (Test-RecipientDomain $token)) {
            throw "Invalid recipient domain: $token"
        }
        if (-not $unique.Contains($token)) {
            $unique.Add($token)
        }
    }

    return ,$unique.ToArray()
}

function Test-ParenthesesBalanced {
    param([AllowEmptyString()][string]$Text)
    $depth = 0
    $inQuote = $false
    $escaped = $false
    foreach ($ch in $Text.ToCharArray()) {
        if ($escaped) {
            $escaped = $false
            continue
        }
        if ($ch -eq '\') {
            $escaped = $true
            continue
        }
        if ($ch -eq '"') {
            $inQuote = -not $inQuote
            continue
        }
        if ($inQuote) { continue }
        if ($ch -eq '(') {
            $depth++
        }
        elseif ($ch -eq ')') {
            $depth--
            if ($depth -lt 0) { return $false }
        }
    }
    return ((-not $inQuote) -and ($depth -eq 0))
}

function New-InvestigationQuery {
    param(
        [Parameter(Mandatory)][string]$Sender,
        [Parameter(Mandatory)][string[]]$Domains,
        [Parameter(Mandatory)][datetime]$Start,
        [Parameter(Mandatory)][datetime]$End,
        [AllowEmptyString()][string]$AdditionalQuery
    )

    $senderText = $Sender.Trim()
    if ([string]::IsNullOrWhiteSpace($senderText)) {
        throw 'Sender is required.'
    }
    if ($Start.Date -gt $End.Date) {
        throw 'Start date cannot be after end date.'
    }

    $cleanDomains = New-Object System.Collections.Generic.List[string]
    foreach ($domain in @($Domains)) {
        if (-not [string]::IsNullOrWhiteSpace($domain)) {
            $cleanDomains.Add($domain.Trim())
        }
    }
    if ($cleanDomains.Count -eq 0) {
        throw 'At least one recipient domain is required.'
    }

    $recipientParts = New-Object System.Collections.Generic.List[string]
    foreach ($domain in $cleanDomains) {
        $recipientParts.Add(('recipients:"{0}"' -f (ConvertTo-KqlPhrase $domain)))
    }
    $recipientQuery = $recipientParts -join ' OR '
    $query = 'kind:email AND from:"{0}" AND ({1}) AND sent>={2} AND sent<{3}' -f `
        (ConvertTo-KqlPhrase $senderText),
        $recipientQuery,
        $Start.Date.ToString('yyyy-MM-dd'),
        $End.Date.AddDays(1).ToString('yyyy-MM-dd')

    if (-not [string]::IsNullOrWhiteSpace($AdditionalQuery)) {
        $extra = ($AdditionalQuery -replace '\s+', ' ').Trim()
        if (-not (Test-ParenthesesBalanced $extra)) {
            throw 'Additional query has unbalanced parentheses or quotes.'
        }
        $query = '{0} AND ({1})' -f $query, $extra
    }

    if ($query.Length -gt 8000) {
        throw "The search query is too long ($($query.Length) characters)."
    }
    return $query
}

function Test-SearchName {
    param([AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name.Length -gt 180) { return $false }
    return $Name -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$'
}

function New-InvestigationSearchName {
    param(
        [AllowEmptyString()][string]$Sender,
        [AllowEmptyString()][string]$Timestamp
    )

    $local = $Sender
    if ($Sender -and $Sender.Contains('@')) {
        $local = $Sender.Split('@')[0]
    }
    $alias = ($local -replace '[^A-Za-z0-9._-]', '_').Trim('._-')
    if ([string]::IsNullOrWhiteSpace($alias)) { $alias = 'sender' }

    $stamp = ($Timestamp -replace '[^A-Za-z0-9._-]', '_')
    if ([string]::IsNullOrWhiteSpace($stamp)) {
        $stamp = (Get-Date).ToString('yyyyMMddHHmmssfff')
    }

    $name = "EmailInvestigation_${alias}_${stamp}"
    if ($name.Length -gt 180) {
        $name = $name.Substring(0, 180).TrimEnd('._-')
    }
    if (-not (Test-SearchName $name)) {
        $name = 'EmailInvestigation_sender_' + (Get-Date).ToString('yyyyMMddHHmmssfff')
    }
    return $name
}

function Get-ExchangeSearchLocation {
    param(
        [Parameter(Mandatory)][string]$Sender,
        [Parameter(Mandatory)][ValidateSet('Sender', 'All')][string]$Scope,
        [bool]$AllowNotFound = $false
    )

    if ($Scope -eq 'All') { return 'All' }
    $smtp = $Sender.Trim()
    if ($AllowNotFound) { return ".$smtp" }
    return $smtp
}

function New-InvestigationDescription {
    param(
        [AllowEmptyString()][string]$Sender,
        [string[]]$Domains,
        [datetime]$Start,
        [datetime]$End
    )

    $who = if ([string]::IsNullOrWhiteSpace($Sender)) { 'the specified sender' } else { $Sender.Trim() }
    $domainList = @($Domains | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $domainText = if ($domainList.Count -gt 0) { $domainList -join ', ' } else { 'the specified domains' }
    $text = "Read-only investigation of messages sent by $who to $domainText from $($Start.ToString('yyyy-MM-dd')) through $($End.ToString('yyyy-MM-dd'))."
    if ($text.Length -gt 1000) { $text = $text.Substring(0, 1000) }
    return $text
}

function ConvertTo-SettingDate {
    param(
        [AllowEmptyString()][string]$Text,
        [datetime]$Fallback
    )
    try {
        return [datetime]::ParseExact($Text, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        return $Fallback.Date
    }
}

function Test-InvestigationRequest {
    param(
        [AllowEmptyString()][string]$AdminUpn,
        [AllowEmptyString()][string]$Sender,
        [AllowEmptyString()][string]$DomainText,
        [AllowEmptyString()][string]$CaseName,
        [AllowEmptyString()][string]$Scope,
        [bool]$AllowNotFound = $false,
        [bool]$NotifyAdmin = $false,
        [datetime]$Start,
        [datetime]$End,
        [AllowEmptyString()][string]$AdditionalQuery,
        [AllowEmptyString()][string]$SearchName,
        [AllowEmptyString()][string]$OutputFolder,
        [int]$TimeoutMinutes,
        [AllowEmptyString()][string]$Description
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $admin = $AdminUpn.Trim()
    $senderText = $Sender.Trim()
    $case = $CaseName.Trim()
    $name = $SearchName.Trim()

    if (-not (Test-EmailAddress $admin)) { $errors.Add('Enter a valid administrative UPN.') }
    if (-not (Test-EmailAddress $senderText)) { $errors.Add('Enter a valid sender email address.') }
    if ($Scope -notin @('Sender', 'All')) { $errors.Add('Select a mailbox scope.') }
    if ($Start.Date -gt $End.Date) { $errors.Add('Start date cannot be after end date.') }
    if ($TimeoutMinutes -lt 1 -or $TimeoutMinutes -gt 720) { $errors.Add('Timeout must be between 1 and 720 minutes.') }
    if (-not (Test-SearchName $name)) {
        $errors.Add('Search name must be 1-180 characters and use only letters, numbers, periods, underscores, and hyphens.')
    }
    if (-not [string]::IsNullOrWhiteSpace($case) -and $case.Length -gt 200) {
        $errors.Add('Case name must be 200 characters or fewer.')
    }

    $fullOutput = ''
    if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
        $errors.Add('Choose an output folder.')
    }
    elseif (-not [System.IO.Path]::IsPathRooted($OutputFolder.Trim())) {
        $errors.Add('Output folder must be a full path.')
    }
    else {
        try {
            $fullOutput = [System.IO.Path]::GetFullPath($OutputFolder.Trim())
        }
        catch {
            $errors.Add('Output folder path is not valid.')
        }
    }

    $domains = @()
    try {
        $domains = ConvertTo-RecipientDomainList $DomainText
    }
    catch {
        $errors.Add($_.Exception.Message)
    }

    $descriptionText = $Description.Trim()
    if ([string]::IsNullOrWhiteSpace($descriptionText)) {
        $descriptionText = New-InvestigationDescription -Sender $senderText -Domains $domains -Start $Start -End $End
    }
    if ($descriptionText.Length -gt 1000) {
        $errors.Add('Description must be 1000 characters or fewer.')
    }

    $query = $null
    $location = $null
    if ($errors.Count -eq 0) {
        try {
            $query = New-InvestigationQuery -Sender $senderText -Domains $domains -Start $Start -End $End -AdditionalQuery $AdditionalQuery
            $location = Get-ExchangeSearchLocation -Sender $senderText -Scope $Scope -AllowNotFound $AllowNotFound
        }
        catch {
            $errors.Add($_.Exception.Message)
        }
    }

    return [pscustomobject]@{
        IsValid          = ($errors.Count -eq 0)
        Errors           = $errors.ToArray()
        AdminUpn         = $admin
        Sender           = $senderText
        Domains          = $domains
        CaseName         = $case
        Scope            = $Scope
        AllowNotFound    = [bool]$AllowNotFound
        NotifyAdmin      = [bool]$NotifyAdmin
        Start            = $Start.Date
        End              = $End.Date
        AdditionalQuery  = (($AdditionalQuery -replace '\s+', ' ').Trim())
        SearchName       = $name
        OutputFolder     = $fullOutput
        TimeoutMinutes   = $TimeoutMinutes
        Description      = $descriptionText
        Query            = $query
        ExchangeLocation = $location
    }
}

function ConvertTo-ByteCount {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) { return $null }

    $toBytes = $Value.PSObject.Methods['ToBytes']
    if ($toBytes) {
        try { return [int64]$toBytes.Invoke() } catch { }
    }

    if ($Value -is [ValueType] -and $Value -isnot [bool] -and $Value -isnot [datetime] -and $Value -isnot [char]) {
        try { return [int64]$Value } catch { }
    }

    $text = [string]$Value
    if ($text -match '\(([0-9,]+)\s+bytes\)') {
        return [int64]($Matches[1] -replace ',', '')
    }
    if ($text -match '^\d+$') {
        return [int64]$text
    }
    return $null
}

function Format-ByteSize {
    param($Bytes)
    $count = ConvertTo-ByteCount $Bytes
    if ($null -eq $count) {
        if ($null -eq $Bytes) { return '' }
        return [string]$Bytes
    }
    if ($count -ge 1GB) { return ('{0:N2} GB' -f ($count / 1GB)) }
    if ($count -ge 1MB) { return ('{0:N2} MB' -f ($count / 1MB)) }
    if ($count -ge 1KB) { return ('{0:N2} KB' -f ($count / 1KB)) }
    return "$count bytes"
}

function ConvertTo-LocationStatistic {
    param([AllowEmptyString()][string]$SuccessResults)
    $list = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($SuccessResults)) {
        return ,$list.ToArray()
    }

    $pattern = '(?i)Location:\s*(?<Location>[^,]+?),\s*Item count:\s*(?<ItemCount>\d+),\s*Total size:\s*(?<Size>.*?)(?=\s*}|\s*$)'
    foreach ($match in [regex]::Matches($SuccessResults, $pattern)) {
        $location = $match.Groups['Location'].Value.Trim()
        if ([string]::IsNullOrWhiteSpace($location)) { continue }
        $sizeText = $match.Groups['Size'].Value.Trim().TrimEnd(',')
        $bytes = ConvertTo-ByteCount $sizeText
        if ($null -eq $bytes) { $bytes = [int64]0 }
        $display = Format-ByteSize -Bytes $sizeText
        if ([string]::IsNullOrWhiteSpace($display)) { $display = $sizeText }
        $list.Add([pscustomobject]@{
            Location    = $location
            ItemCount   = [int64]$match.Groups['ItemCount'].Value
            SizeBytes   = [int64]$bytes
            SizeDisplay = $display
        })
    }
    return ,$list.ToArray()
}

function Get-LabeledPreviewValue {
    param(
        [AllowEmptyString()][string]$Chunk,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$NextPattern
    )

    $labelPattern = [regex]::Escape($Label).Replace('\ ', '\s+')
    $match = [regex]::Match($Chunk, "(?is)$labelPattern\s*:\s*(?<Value>.*?)(?=$NextPattern)")
    if (-not $match.Success) { return '' }
    $value = $match.Groups['Value'].Value.Trim()
    return $value.TrimEnd('}', ' ').Trim()
}

function ConvertTo-PreviewItem {
    param([AllowEmptyString()][string]$Results)
    $list = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($Results)) {
        return ,$list.ToArray()
    }

    $records = [regex]::Split($Results, '(?i)(?=Location\s*:)')
    foreach ($chunk in $records) {
        if ($chunk -notmatch '(?i)Sender\s*:') { continue }
        $location = Get-LabeledPreviewValue $chunk 'Location' '(?:;|,)\s*Sender\s*:'
        $location = $location.TrimStart('{').Trim()
        if ([string]::IsNullOrWhiteSpace($location)) { continue }
        $list.Add([pscustomobject]@{
            Location    = $location
            Sender      = (Get-LabeledPreviewValue $chunk 'Sender' '(?:;|,)\s*Subject\s*:')
            Subject     = (Get-LabeledPreviewValue $chunk 'Subject' '(?:;|,)\s*Type\s*:')
            Type        = (Get-LabeledPreviewValue $chunk 'Type' '(?:;|,)\s*Size\s*:')
            Size        = (Get-LabeledPreviewValue $chunk 'Size' '(?:;|,)\s*Received\s+Time\s*:')
            Received    = (Get-LabeledPreviewValue $chunk 'Received Time' '(?:;|,)\s*Data\s+Link\s*:|\z')
            PreviewLink = (Get-LabeledPreviewValue $chunk 'Data Link' '\z')
        })
    }
    return ,$list.ToArray()
}

function ConvertTo-SpreadsheetText {
    param([AllowEmptyString()][string]$Value)
    $text = [string]$Value
    if ([string]::IsNullOrEmpty($text)) { return '' }
    $text = [regex]::Replace($text, '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
    return [System.Security.SecurityElement]::Escape($text)
}

function ConvertTo-ColumnName {
    param([Parameter(Mandatory)][int]$Index)
    $name = ''
    $number = $Index
    while ($number -gt 0) {
        $number--
        $name = [char](65 + ($number % 26)) + $name
        $number = [math]::Floor($number / 26)
    }
    return $name
}

function Add-ZipTextEntry {
    param(
        [Parameter(Mandatory)]$Archive,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content
    )

    $entry = $Archive.CreateEntry($Name, [System.IO.Compression.CompressionLevel]::Optimal)
    $stream = $entry.Open()
    try {
        $bytes = (New-Object System.Text.UTF8Encoding $false).GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally {
        $stream.Dispose()
    }
}

function New-FindingsWorksheetXml {
    param(
        [Parameter(Mandatory)][string[]]$Headers,
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$Rows,
        [int[]]$Widths
    )

    $lastColumn = ConvertTo-ColumnName $Headers.Count
    $lastRow = $Rows.Count + 1
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    [void]$builder.AppendLine('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
    [void]$builder.AppendLine('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>')
    if ($Widths -and $Widths.Count -gt 0) {
        [void]$builder.AppendLine('<cols>')
        for ($i = 0; $i -lt $Widths.Count; $i++) {
            $column = $i + 1
            [void]$builder.AppendLine("<col min=`"$column`" max=`"$column`" width=`"$($Widths[$i])`" customWidth=`"1`"/>")
        }
        [void]$builder.AppendLine('</cols>')
    }
    [void]$builder.AppendLine('<sheetData>')
    [void]$builder.AppendLine('<row r="1">')
    for ($i = 0; $i -lt $Headers.Count; $i++) {
        $cell = (ConvertTo-ColumnName ($i + 1)) + '1'
        $text = ConvertTo-SpreadsheetText $Headers[$i]
        [void]$builder.AppendLine("<c r=`"$cell`" t=`"inlineStr`" s=`"1`"><is><t>$text</t></is></c>")
    }
    [void]$builder.AppendLine('</row>')
    for ($r = 0; $r -lt $Rows.Count; $r++) {
        $rowNumber = $r + 2
        $values = @($Rows[$r])
        [void]$builder.AppendLine("<row r=`"$rowNumber`">")
        for ($c = 0; $c -lt $Headers.Count; $c++) {
            $cell = (ConvertTo-ColumnName ($c + 1)) + $rowNumber
            $raw = ''
            if ($c -lt $values.Count -and $null -ne $values[$c]) { $raw = [string]$values[$c] }
            if ($c -eq 0 -and $raw -match '^\d+$') {
                [void]$builder.AppendLine("<c r=`"$cell`" t=`"n`"><v>$raw</v></c>")
            }
            else {
                $text = ConvertTo-SpreadsheetText $raw
                [void]$builder.AppendLine("<c r=`"$cell`" t=`"inlineStr`"><is><t xml:space=`"preserve`">$text</t></is></c>")
            }
        }
        [void]$builder.AppendLine('</row>')
    }
    [void]$builder.AppendLine('</sheetData>')
    if ($Headers.Count -gt 0) {
        [void]$builder.AppendLine("<autoFilter ref=`"A1:${lastColumn}${lastRow}`"/>")
    }
    [void]$builder.AppendLine('</worksheet>')
    return $builder.ToString()
}

function Export-FindingsSpreadsheet {
    param(
        $Items,
        [Parameter(Mandatory)][string]$OutputFolder,
        [AllowEmptyString()][string]$SearchName,
        [int]$ReportedItemCount = -1
    )

    if (-not (Test-Path -LiteralPath $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }

    $table = New-Object System.Collections.Generic.List[object]
    $sheetRows = New-Object System.Collections.Generic.List[object]
    $number = 0
    foreach ($item in $Items) {
        if ($null -eq $item) { continue }
        $number++
        $table.Add([pscustomobject]@{
            Item       = $number
            Subject    = [string]$item.Subject
            Sender     = [string]$item.Sender
            Received   = [string]$item.Received
            Mailbox    = [string]$item.Location
            Type       = [string]$item.Type
            Size       = [string]$item.Size
            SearchName = [string]$SearchName
        })
        $sheetRows.Add(@(
            [string]$number,
            [string]$item.Subject,
            [string]$item.Sender,
            [string]$item.Received,
            [string]$item.Location,
            [string]$item.Type,
            [string]$item.Size,
            [string]$SearchName
        ))
    }

    $csvPath = Join-Path $OutputFolder 'MessageFindings.csv'
    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    if ($table.Count -gt 0) {
        $csvLines = @($table | ConvertTo-Csv -NoTypeInformation)
        [System.IO.File]::WriteAllLines($csvPath, $csvLines, $utf8Bom)
    }
    else {
        $header = 'Item,Subject,Sender,Received,Mailbox,Type,Size,SearchName'
        [System.IO.File]::WriteAllLines($csvPath, @($header), $utf8Bom)
    }

    $headers = @('Item', 'Subject', 'Sender', 'Received', 'Mailbox', 'Type', 'Size', 'Search name')
    $widths = @(8, 56, 36, 24, 36, 16, 14, 42)
    $findingsXml = New-FindingsWorksheetXml -Headers $headers -Rows $sheetRows -Widths $widths

    $reportedText = if ($ReportedItemCount -ge 0) { [string]$ReportedItemCount } else { 'Not supplied' }
    $complete = ($ReportedItemCount -lt 0) -or ($table.Count -eq $ReportedItemCount)
    $coverage = if ($complete) {
        'Every message reported by the search has a row in this workbook.'
    }
    else {
        'This workbook has fewer rows than the search count. The item report did not include a subject for every match. The search count remains the total.'
    }
    $noteRows = New-Object System.Collections.Generic.List[object]
    foreach ($line in @(
        "Search name: $SearchName",
        "Messages reported by the search: $reportedText",
        "Rows in this spreadsheet: $($table.Count)",
        'Each row is one matching message and includes its subject line.',
        $coverage,
        'Subject and sender text from the item report can be shortened to 255 characters.',
        'Message bodies were not downloaded. Mailbox messages were not changed.'
    )) {
        $noteRows.Add(@($line))
    }
    $notesXml = New-FindingsWorksheetXml -Headers @('Note') -Rows $noteRows -Widths @(120)

    $styles = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2">
    <font><sz val="11"/><name val="Calibri"/></font>
    <font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
  </fonts>
  <fills count="3">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF182A44"/></patternFill></fill>
  </fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="2">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>
  </cellXfs>
</styleSheet>
'@
    $workbook = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Findings" sheetId="1" r:id="rId1"/>
    <sheet name="Notes" sheetId="2" r:id="rId2"/>
  </sheets>
</workbook>
'@
    $workbookRels = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>
'@
    $packageRels = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>
'@
    $contentTypes = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>
'@

    $workbookPath = Join-Path $OutputFolder 'MessageFindings.xlsx'
    if (Test-Path -LiteralPath $workbookPath) {
        Remove-Item -LiteralPath $workbookPath -Force
    }
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
    try { Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop } catch { }
    $archive = [System.IO.Compression.ZipFile]::Open($workbookPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        Add-ZipTextEntry -Archive $archive -Name '[Content_Types].xml' -Content $contentTypes
        Add-ZipTextEntry -Archive $archive -Name '_rels/.rels' -Content $packageRels
        Add-ZipTextEntry -Archive $archive -Name 'xl/workbook.xml' -Content $workbook
        Add-ZipTextEntry -Archive $archive -Name 'xl/_rels/workbook.xml.rels' -Content $workbookRels
        Add-ZipTextEntry -Archive $archive -Name 'xl/styles.xml' -Content $styles
        Add-ZipTextEntry -Archive $archive -Name 'xl/worksheets/sheet1.xml' -Content $findingsXml
        Add-ZipTextEntry -Archive $archive -Name 'xl/worksheets/sheet2.xml' -Content $notesXml
    }
    finally {
        $archive.Dispose()
    }

    return [pscustomobject]@{
        Count             = $table.Count
        CsvPath           = $csvPath
        WorkbookPath      = $workbookPath
        ReportedItemCount = $ReportedItemCount
        IsComplete        = [bool]$complete
    }
}

function Test-TerminalSearchStatus {
    param([AllowEmptyString()][string]$Status)
    if ([string]::IsNullOrWhiteSpace($Status)) { return $false }
    $known = @(
        'Completed', 'Failed', 'Stopped', 'PartiallySucceeded',
        'CompletedWithErrors', 'Succeeded', 'Canceled', 'Cancelled'
    )
    if ($known -contains $Status) { return $true }
    return $Status -match '^(Completed|Failed|Stopped|Succeeded|Cancelled|Canceled)'
}

function Format-Duration {
    param([TimeSpan]$Elapsed)
    $hours = [math]::Floor($Elapsed.TotalHours)
    return '{0:00}:{1:00}:{2:00}' -f $hours, $Elapsed.Minutes, $Elapsed.Seconds
}

function Add-Utf8Line {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Line
    )
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::AppendAllText($Path, $Line + [Environment]::NewLine, $utf8)
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content
    )
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $Content, $utf8)
}

function Format-PropertyValue {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string] -or $Value -is [ValueType]) { return [string]$Value }

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($item in $Value) {
        if ($null -ne $item) { $parts.Add([string]$item) }
    }
    return ($parts -join ([Environment]::NewLine + '    '))
}

function ConvertTo-PropertyDump {
    param($Object)
    $builder = New-Object System.Text.StringBuilder
    if ($null -eq $Object) { return '' }
    foreach ($prop in $Object.PSObject.Properties) {
        $rendered = ''
        try {
            $rendered = Format-PropertyValue $prop.Value
        }
        catch {
            $rendered = "<unavailable: $($_.Exception.Message)>"
        }
        [void]$builder.AppendLine("$($prop.Name): $rendered")
        [void]$builder.AppendLine()
    }
    return $builder.ToString()
}

function ConvertTo-FlatErrorText {
    param($Errors)
    if ($null -eq $Errors) { return '' }
    if ($Errors -is [string]) { return $Errors.Trim() }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($item in $Errors) {
        if ($null -eq $item) { continue }
        $text = [string]$item
        if (-not [string]::IsNullOrWhiteSpace($text)) { $parts.Add($text.Trim()) }
    }
    return ($parts -join '; ')
}

function ConvertTo-ResultText {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($item in $Value) {
        if ($null -ne $item) { $parts.Add([string]$item) }
    }
    return ($parts -join [Environment]::NewLine)
}

function Export-InvestigationReport {
    param(
        [Parameter(Mandatory)]$Search,
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][hashtable]$Context
    )

    if (-not (Test-Path -LiteralPath $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }

    $sizeBytesValue = ConvertTo-ByteCount $Search.Size
    $unindexedBytesValue = ConvertTo-ByteCount $Search.UnindexedSize
    $locations = ConvertTo-LocationStatistic (ConvertTo-ResultText $Search.SuccessResults)
    $itemsText = ''
    if ($null -ne $Search.Items -and -not [string]::IsNullOrWhiteSpace([string]$Search.Items)) {
        $itemsText = [string]$Search.Items
    }

    $summary = [pscustomobject]@{
        SearchName       = [string]$Context.SearchName
        CaseName         = [string]$Context.CaseName
        Administrator    = [string]$Context.Administrator
        ConnectedAs      = [string]$Context.ConnectedAs
        Sender           = [string]$Context.Sender
        RecipientDomains = [string]$Context.RecipientDomains
        StartDate        = [string]$Context.StartDate
        EndDate          = [string]$Context.EndDate
        SearchScope      = [string]$Context.SearchScope
        ExchangeLocation = [string]$Context.ExchangeLocation
        SearchStatus     = [string]$Search.Status
        MatchingItems    = $itemsText
        TotalSize        = Format-ByteSize $Search.Size
        TotalSizeBytes   = $(if ($null -eq $sizeBytesValue) { '' } else { $sizeBytesValue })
        UnindexedItems   = $(if ($null -eq $Search.UnindexedItems) { '' } else { [string]$Search.UnindexedItems })
        UnindexedSize    = Format-ByteSize $Search.UnindexedSize
        UnindexedBytes   = $(if ($null -eq $unindexedBytesValue) { '' } else { $unindexedBytesValue })
        SearchErrors     = ConvertTo-FlatErrorText $Search.Errors
        SearchQuery      = [string]$Context.SearchQuery
        ExecutionTime    = [string]$Context.ExecutionTime
        JobStartTime     = $(if ($Search.JobStartTime) { [string]$Search.JobStartTime } else { '' })
        JobEndTime       = $(if ($Search.JobEndTime) { [string]$Search.JobEndTime } else { '' })
        TimedOut         = [bool]$Context.TimedOut
        ModuleVersion    = [string]$Context.ModuleVersion
        ReportGenerated  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        OutputFolder     = $OutputFolder
    }

    $summary | Export-Csv -Path (Join-Path $OutputFolder 'SearchSummary.csv') -NoTypeInformation -Encoding UTF8

    $locationRows = New-Object System.Collections.Generic.List[object]
    foreach ($row in $locations) {
        if ($null -eq $row) { continue }
        $locationRows.Add([pscustomobject]@{
            SearchName  = $summary.SearchName
            Location    = $row.Location
            ItemCount   = $row.ItemCount
            SizeBytes   = $row.SizeBytes
            SizeDisplay = $row.SizeDisplay
        })
    }
    $locationPath = Join-Path $OutputFolder 'LocationStatistics.csv'
    if ($locationRows.Count -gt 0) {
        $locationRows | Export-Csv -Path $locationPath -NoTypeInformation -Encoding UTF8
    }
    else {
        Write-Utf8File -Path $locationPath -Content "SearchName,Location,ItemCount,SizeBytes,SizeDisplay$([Environment]::NewLine)"
    }

    $details = New-Object System.Text.StringBuilder
    [void]$details.AppendLine('Compliance search property dump')
    [void]$details.AppendLine("Generated: $($summary.ReportGenerated)")
    [void]$details.AppendLine()
    [void]$details.Append((ConvertTo-PropertyDump $Search))
    Write-Utf8File -Path (Join-Path $OutputFolder 'SearchDetails.txt') -Content $details.ToString()
    Write-Utf8File -Path (Join-Path $OutputFolder 'SearchQuery.txt') -Content ($summary.SearchQuery + [Environment]::NewLine)

    $locationArray = $locationRows.ToArray()
    $manifest = [ordered]@{
        Summary   = $summary
        Locations = $locationArray
    }
    Write-Utf8File -Path (Join-Path $OutputFolder 'RunManifest.json') -Content ($manifest | ConvertTo-Json -Depth 6)

    return [pscustomobject]@{
        Summary   = $summary
        Locations = $locationArray
    }
}

function Export-PreviewResults {
    param(
        [AllowEmptyString()][string]$RawResults,
        [Parameter(Mandatory)][string]$OutputFolder,
        [AllowEmptyString()][string]$SearchName,
        [int]$ReportedItemCount = -1
    )

    if (-not (Test-Path -LiteralPath $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }

    Write-Utf8File -Path (Join-Path $OutputFolder 'PreviewResults.txt') -Content ([string]$RawResults + [Environment]::NewLine)
    $items = ConvertTo-PreviewItem $RawResults
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($item in $items) {
        if ($null -eq $item) { continue }
        $rows.Add([pscustomobject]@{
            SearchName = $SearchName
            Received   = $item.Received
            Sender     = $item.Sender
            Subject    = $item.Subject
            Type       = $item.Type
            Size       = $item.Size
            Location   = $item.Location
        })
    }
    if ($rows.Count -gt 0) {
        $rows | Export-Csv -Path (Join-Path $OutputFolder 'PreviewResults.csv') -NoTypeInformation -Encoding UTF8
    }
    $saved = Export-FindingsSpreadsheet -Items $items -OutputFolder $OutputFolder -SearchName $SearchName -ReportedItemCount $ReportedItemCount
    return [pscustomobject]@{
        Rows = $rows.ToArray()
        File = $saved
    }
}

function New-InvestigationOutputFolder {
    param([Parameter(Mandatory)][string]$Root)
    if ([string]::IsNullOrWhiteSpace($Root)) {
        throw 'Output folder is required.'
    }
    if (-not (Test-Path -LiteralPath $Root)) {
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
    }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
    $path = Join-Path $Root $stamp
    $suffix = 1
    while (Test-Path -LiteralPath $path) {
        $path = Join-Path $Root ('{0}_{1}' -f $stamp, $suffix)
        $suffix++
        if ($suffix -gt 50) {
            throw "Unable to create a unique folder under $Root"
        }
    }
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    return $path
}

function Get-DefaultInvestigationSettings {
    $documents = [Environment]::GetFolderPath('MyDocuments')
    if ([string]::IsNullOrWhiteSpace($documents)) {
        $homeRoot = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
        $documents = Join-Path $homeRoot 'Documents'
    }
    return [pscustomobject]@{
        AdminUpn        = ''
        Sender          = ''
        Domains         = 'acpao.org, allencounty.in.gov'
        CaseName        = ''
        Scope           = 'Sender'
        AllowNotFound   = $false
        NotifyAdmin     = $false
        OutputFolder    = (Join-Path $documents 'Purview_Email_Investigation')
        TimeoutMinutes  = 120
        AdditionalQuery = ''
        StartDate       = '2025-07-10'
        EndDate         = (Get-Date).ToString('yyyy-MM-dd')
    }
}

function Get-InvestigationSettingsPath {
    $root = [Environment]::GetFolderPath('ApplicationData')
    if ([string]::IsNullOrWhiteSpace($root)) { return $null }
    return (Join-Path (Join-Path $root 'PurviewEmailInvestigation') 'settings.json')
}

function Read-InvestigationSettings {
    $path = Get-InvestigationSettingsPath
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { return $null }
    try {
        return ([System.IO.File]::ReadAllText($path) | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Save-InvestigationSettings {
    param([Parameter(Mandatory)][hashtable]$Settings)
    $path = Get-InvestigationSettingsPath
    if ([string]::IsNullOrWhiteSpace($path)) { return }
    $directory = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Write-Utf8File -Path $path -Content ($Settings | ConvertTo-Json -Depth 4)
}

function Resolve-ExchangeOnlineModule {
    param([switch]$Refresh)
    $params = @{
        ListAvailable = $true
        Name          = 'ExchangeOnlineManagement'
        ErrorAction   = 'SilentlyContinue'
    }
    $candidates = @()
    try {
        if ($Refresh) { $params.Refresh = $true }
        $candidates = @(Get-Module @params)
    }
    catch {
        $params.Remove('Refresh')
        $candidates = @(Get-Module @params)
    }

    $suitable = $candidates |
        Where-Object { $_.Version -ge [version]'3.9.0' } |
        Sort-Object Version -Descending |
        Select-Object -First 1
    $newest = $candidates | Sort-Object Version -Descending | Select-Object -First 1
    return [pscustomobject]@{
        Suitable       = $suitable
        Newest         = $newest
        InstalledCount = $candidates.Count
    }
}

function ConvertTo-GraphJson {
    param($Value)

    $escape = {
        param([AllowEmptyString()][string]$Text)
        if ($null -eq $Text) { return '' }
        $builder = New-Object System.Text.StringBuilder
        foreach ($ch in $Text.ToCharArray()) {
            $code = [int]$ch
            if ($ch -eq '"') { [void]$builder.Append('\"') }
            elseif ($ch -eq '\') { [void]$builder.Append('\\') }
            elseif ($ch -eq "`b") { [void]$builder.Append('\b') }
            elseif ($ch -eq "`f") { [void]$builder.Append('\f') }
            elseif ($ch -eq "`n") { [void]$builder.Append('\n') }
            elseif ($ch -eq "`r") { [void]$builder.Append('\r') }
            elseif ($ch -eq "`t") { [void]$builder.Append('\t') }
            elseif ($code -lt 32) { [void]$builder.Append(('\u{0:x4}' -f $code)) }
            else { [void]$builder.Append($ch) }
        }
        return $builder.ToString()
    }

    $write = {
        param($Node)
        if ($null -eq $Node) { return 'null' }
        if ($Node -is [bool]) {
            if ($Node) { return 'true' }
            return 'false'
        }
        if ($Node -is [string] -or $Node -is [char]) {
            return '"' + (& $escape ([string]$Node)) + '"'
        }
        if ($Node -is [datetime]) {
            return '"' + $Node.ToUniversalTime().ToString('o') + '"'
        }
        if ($Node -is [System.Collections.IDictionary]) {
            $pairs = New-Object System.Collections.Generic.List[string]
            foreach ($key in $Node.Keys) {
                $encodedKey = & $escape ([string]$key)
                $encodedValue = & $write $Node[$key]
                $pairs.Add(('"' + $encodedKey + '":' + $encodedValue))
            }
            return '{' + ($pairs -join ',') + '}'
        }
        if ($Node -is [System.Collections.IEnumerable]) {
            $items = New-Object System.Collections.Generic.List[string]
            foreach ($item in $Node) {
                $items.Add((& $write $item))
            }
            return '[' + ($items -join ',') + ']'
        }
        $isNumber = $Node -is [byte] -or $Node -is [int16] -or $Node -is [int] -or $Node -is [long] -or $Node -is [decimal] -or $Node -is [single] -or $Node -is [double]
        if ($isNumber) {
            return $Node.ToString([System.Globalization.CultureInfo]::InvariantCulture)
        }
        return '"' + (& $escape ([string]$Node)) + '"'
    }

    return (& $write $Value)
}

function ConvertTo-FindingsFromReportCsv {
    param([AllowEmptyString()][string]$CsvText)
    $rows = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($CsvText)) {
        return ,$rows.ToArray()
    }

    $parsed = @()
    try {
        $parsed = @($CsvText | ConvertFrom-Csv)
    }
    catch {
        return ,$rows.ToArray()
    }

    foreach ($item in $parsed) {
        if ($null -eq $item) { continue }
        $map = @{}
        foreach ($prop in $item.PSObject.Properties) {
            $map[$prop.Name.Trim().ToLowerInvariant()] = [string]$prop.Value
        }
        $subject = ''
        $sender = ''
        $received = ''
        $location = ''
        $typeName = ''
        $size = ''
        foreach ($name in @('subject/title', 'subject', 'doc subject', 'conversation topic', 'email subject', 'title')) {
            if ($map.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace($map[$name])) {
                $subject = $map[$name].Trim()
                break
            }
        }
        foreach ($name in @('sender/author', 'sender', 'author', 'from', 'sender or author')) {
            if ($map.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace($map[$name])) {
                $sender = $map[$name].Trim()
                break
            }
        }
        foreach ($name in @('date', 'received', 'email date sent', 'sent', 'date sent', 'last modified date')) {
            if ($map.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace($map[$name])) {
                $received = $map[$name].Trim()
                break
            }
        }
        foreach ($name in @('location', 'location name', 'custodian', 'compound path', 'mailbox')) {
            if ($map.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace($map[$name])) {
                $location = $map[$name].Trim()
                break
            }
        }
        foreach ($name in @('file class', 'item class', 'file type', 'type')) {
            if ($map.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace($map[$name])) {
                $typeName = $map[$name].Trim()
                break
            }
        }
        foreach ($name in @('size', 'file size')) {
            if ($map.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace($map[$name])) {
                $size = $map[$name].Trim()
                break
            }
        }
        if ([string]::IsNullOrWhiteSpace($subject) -and [string]::IsNullOrWhiteSpace($sender)) { continue }
        $rows.Add([pscustomobject]@{
            Subject  = $subject
            Sender   = $sender
            Received = $received
            Location = $location
            Type     = $typeName
            Size     = $size
        })
    }
    return ,$rows.ToArray()
}

function Get-InvestigationRunspaceFunctionNames {
    return @(
        'ConvertTo-KqlPhrase'
        'ConvertTo-ByteCount'
        'Format-ByteSize'
        'ConvertTo-LocationStatistic'
        'ConvertTo-PreviewItem'
        'Get-LabeledPreviewValue'
        'ConvertTo-SpreadsheetText'
        'ConvertTo-ColumnName'
        'Add-ZipTextEntry'
        'New-FindingsWorksheetXml'
        'Export-FindingsSpreadsheet'
        'ConvertTo-GraphJson'
        'ConvertTo-FindingsFromReportCsv'
        'Test-TerminalSearchStatus'
        'Format-Duration'
        'Add-Utf8Line'
        'Write-Utf8File'
        'Format-PropertyValue'
        'ConvertTo-PropertyDump'
        'ConvertTo-FlatErrorText'
        'ConvertTo-ResultText'
        'Export-InvestigationReport'
        'Export-PreviewResults'
        'Invoke-PurviewSearchJob'
    )
}

function New-InvestigationRunspace {
    $initial = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($name in (Get-InvestigationRunspaceFunctionNames)) {
        $command = Get-Command -Name $name -CommandType Function -ErrorAction Stop
        $entry = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry(
            $name,
            $command.ScriptBlock.ToString())
        [void]$initial.Commands.Add($entry)
    }

    $runspace = [RunspaceFactory]::CreateRunspace($initial)
    $runspace.ApartmentState = [System.Threading.ApartmentState]::STA
    $runspace.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $runspace.Open()
    return $runspace
}

function Invoke-PurviewSearchJob {
    param([Parameter(Mandatory)][hashtable]$Job)

    function Write-JobLog {
        param([string]$Message, [string]$Level = 'INFO')
        $entry = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
        try { $Job.Sync.LogQueue.Enqueue($entry) } catch { }
        if (-not [string]::IsNullOrWhiteSpace($Job.LogFile)) {
            try { Add-Utf8Line -Path $Job.LogFile -Line $entry } catch { }
        }
    }

    function Get-ErrorText {
        param($Record)
        $message = [string]$Record.Exception.Message
        if ($Record.ErrorDetails -and $Record.ErrorDetails.Message) {
            $detail = [string]$Record.ErrorDetails.Message
            if ($detail -and $message -notlike "*$detail*") {
                $message = "$message $detail"
            }
        }
        return $message.Trim()
    }

    function Connect-PurviewWorker {
        if ($script:IppsConnected) {
            Write-JobLog 'Already connected.' 'SUCCESS'
            $Job.Sync.Connected = $true
            $Job.Sync.Phase = 'Connected'
            if ([string]::IsNullOrWhiteSpace([string]$Job.Sync.ConnectedUpn)) {
                $Job.Sync.ConnectedUpn = [string]$Job.AdminUPN
            }
            $Job.Sync.StatusText = "Connected as $($Job.Sync.ConnectedUpn)"
            return
        }
        if ([string]::IsNullOrWhiteSpace([string]$Job.ModulePath)) {
            throw 'ExchangeOnlineManagement 3.9.0 or later is not installed.'
        }

        Write-JobLog "Loading $($Job.ModulePath)"
        Remove-Module ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue
        Import-Module -Name $Job.ModulePath -Force
        $loaded = @(Get-Module ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1)
        if ($loaded.Count -eq 0 -or $loaded[0].Version -lt [version]'3.9.0') {
            $found = if ($loaded.Count -eq 0) { 'none' } else { [string]$loaded[0].Version }
            throw "ExchangeOnlineManagement 3.9.0 or later is required. Loaded: $found"
        }

        $Job.Sync.ModuleVersion = [string]$loaded[0].Version
        Write-JobLog "Module version: $($loaded[0].Version)"
        if ($Job.Sync.CancelRequested) {
            $Job.Sync.Phase = 'Cancelled'
            $Job.Sync.StatusText = 'Cancelled before sign-in.'
            Write-JobLog $Job.Sync.StatusText 'WARNING'
            return
        }

        $Job.Sync.Phase = 'Connecting'
        $Job.Sync.StatusText = 'Waiting for Microsoft sign-in. Check the taskbar if the window is hidden.'
        Write-JobLog $Job.Sync.StatusText
        Connect-IPPSSession -UserPrincipalName $Job.AdminUPN -EnableSearchOnlySession

        $script:IppsConnected = $true
        $Job.Sync.Connected = $true
        $Job.Sync.ConnectedUpn = [string]$Job.AdminUPN
        try {
            $info = @(Get-ConnectionInformation -ErrorAction SilentlyContinue |
                Where-Object { $_.State -eq 'Connected' -and $_.UserPrincipalName } |
                Select-Object -First 1)
            if ($info.Count -eq 1) {
                $Job.Sync.ConnectedUpn = [string]$info[0].UserPrincipalName
            }
        }
        catch { }

        $Job.Sync.Phase = 'Connected'
        $Job.Sync.StatusText = "Connected as $($Job.Sync.ConnectedUpn)"
        Write-JobLog $Job.Sync.StatusText 'SUCCESS'
    }

    function Disconnect-PurviewWorker {
        if (-not $script:IppsConnected) {
            $Job.Sync.Connected = $false
            $Job.Sync.Phase = 'Disconnected'
            $Job.Sync.StatusText = 'Disconnected'
            Write-JobLog 'Not connected.'
            return
        }
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        $script:IppsConnected = $false
        $script:GraphAccessToken = $null
        $script:GraphTokenExpires = $null
        $Job.Sync.Connected = $false
        $Job.Sync.ConnectedUpn = ''
        $Job.Sync.Phase = 'Disconnected'
        $Job.Sync.StatusText = 'Disconnected'
        Write-JobLog 'Disconnected from Purview.' 'SUCCESS'
    }

    function Get-SearchWithRetry {
        param([string]$Identity)
        $attempt = 0
        while ($true) {
            try {
                return (Get-ComplianceSearch -Identity $Identity)
            }
            catch {
                $attempt++
                if ($attempt -ge 3) { throw }
                Write-JobLog "Status check failed (attempt $attempt): $(Get-ErrorText $_)" 'WARNING'
                Start-Sleep -Seconds 5
            }
        }
    }

    function Wait-ForComplianceSearch {
        $timeout = 120.0
        try { $timeout = [double]$Job.TimeoutMinutes } catch { $timeout = 120.0 }
        if ($timeout -le 0) { $timeout = 120.0 }

        $watch = [Diagnostics.Stopwatch]::StartNew()
        $lastLog = [datetime]::MinValue
        $lastKey = ''
        $search = $null

        while ($true) {
            if ($Job.Sync.CancelRequested -and -not $Job.Sync.StopSent) {
                $Job.Sync.StopSent = $true
                Write-JobLog 'Stop requested. Sending stop to the compliance search.' 'WARNING'
                try {
                    Stop-ComplianceSearch -Identity $Job.SearchName -Confirm:$false
                }
                catch {
                    Write-JobLog "Stop request failed: $(Get-ErrorText $_)" 'WARNING'
                }
            }

            $search = Get-SearchWithRetry -Identity $Job.SearchName
            $status = [string]$search.Status
            $progress = 0
            if ($null -ne $search.JobProgress) {
                try { $progress = [int]$search.JobProgress } catch { $progress = 0 }
            }

            $Job.Sync.SearchStatus = $status
            $Job.Sync.Items = $search.Items
            $Job.Sync.Progress = $progress
            $Job.Sync.Phase = 'Running'
            $Job.Sync.StatusText = "Status: $status | Items: $($search.Items) | Progress: $progress%"

            $key = "$status|$($search.Items)|$progress"
            $now = Get-Date
            if ($key -ne $lastKey -or ($now - $lastLog).TotalSeconds -ge 60) {
                Write-JobLog $Job.Sync.StatusText
                $lastKey = $key
                $lastLog = $now
            }

            if (Test-TerminalSearchStatus $status) { break }
            if ($watch.Elapsed.TotalMinutes -ge $timeout) {
                $Job.Sync.TimedOut = $true
                Write-JobLog "Monitoring timed out after $timeout minutes. The search may still be running in Purview as $($Job.SearchName)." 'WARNING'
                break
            }

            $slept = 0
            while ($slept -lt 5) {
                if ($Job.Sync.CancelRequested) { break }
                Start-Sleep -Seconds 1
                $slept++
            }
        }

        $watch.Stop()
        $Job.Sync.ExecutionSeconds = [int]$watch.Elapsed.TotalSeconds
        try {
            $finalSearch = Get-ComplianceSearch -Identity $Job.SearchName
            if ($finalSearch) { $search = $finalSearch }
        }
        catch { }
        return $search
    }

    function Publish-SearchWorkerResult {
        param($Search)
        if ($null -eq $Search) { return }
        if ($null -eq $Job.Context) { $Job.Context = @{} }
        $Job.Context.ConnectedAs = [string]$Job.Sync.ConnectedUpn
        $Job.Context.ModuleVersion = [string]$Job.Sync.ModuleVersion
        $Job.Context.TimedOut = [bool]$Job.Sync.TimedOut
        $seconds = 0
        try { $seconds = [int]$Job.Sync.ExecutionSeconds } catch { $seconds = 0 }
        $Job.Context.ExecutionTime = Format-Duration ([TimeSpan]::FromSeconds($seconds))

        try {
            $exported = Export-InvestigationReport -Search $Search -OutputFolder $Job.OutputFolder -Context $Job.Context
            $Job.Sync.Result = $exported
            Write-JobLog "Reports saved to $($Job.OutputFolder)" 'SUCCESS'
        }
        catch {
            $Job.Sync.ErrorMessage = Get-ErrorText $_
            Write-JobLog "Search finished but saving reports failed: $($Job.Sync.ErrorMessage)" 'ERROR'
        }

        $status = [string]$Search.Status
        $Job.Sync.SearchStatus = $status
        if ($status -eq 'Completed') { $Job.Sync.Progress = 100 }
        if ($Job.Sync.TimedOut) { $Job.Sync.Phase = 'TimedOut' }
        elseif ($Job.Sync.CancelRequested) { $Job.Sync.Phase = 'Cancelled' }
        elseif ($status -eq 'Completed') { $Job.Sync.Phase = 'Completed' }
        else { $Job.Sync.Phase = 'Finished' }
        $Job.Sync.StatusText = "Finished: $status | Items: $($Search.Items)"
    }

    function Start-SearchWorker {
        if (-not $script:IppsConnected) { throw 'Not connected to Purview.' }
        if ($Job.Sync.CancelRequested) {
            $Job.Sync.Phase = 'Cancelled'
            $Job.Sync.StatusText = 'Cancelled before the search was created.'
            Write-JobLog $Job.Sync.StatusText 'WARNING'
            return
        }

        $Job.Sync.Phase = 'Creating'
        $Job.Sync.StatusText = "Creating search $($Job.SearchName)"
        Write-JobLog "Creating compliance search $($Job.SearchName)."
        Write-JobLog "Query: $($Job.Query)"
        Write-JobLog "Exchange location: $($Job.ExchangeLocation)"

        $params = @{
            Name              = [string]$Job.SearchName
            ExchangeLocation  = [string]$Job.ExchangeLocation
            ContentMatchQuery = [string]$Job.Query
            Description       = [string]$Job.Description
            Force             = $true
        }
        if ($Job.AllowNotFound) {
            $params['AllowNotFoundExchangeLocationsEnabled'] = $true
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$Job.CaseName)) {
            $params['Case'] = [string]$Job.CaseName
        }
        if ($Job.NotifyAdmin -and -not [string]::IsNullOrWhiteSpace([string]$Job.AdminUPN)) {
            $params['StatusMailRecipients'] = @([string]$Job.AdminUPN)
        }

        New-ComplianceSearch @params | Out-Null
        $Job.Sync.SearchCreated = $true
        $Job.Sync.ActiveSearchName = [string]$Job.SearchName
        Write-JobLog 'Compliance search created. No messages were changed.' 'SUCCESS'

        if ($Job.Sync.CancelRequested) {
            Write-JobLog 'Cancelled after the search was created. It was not started.' 'WARNING'
            $Job.Sync.Phase = 'Cancelled'
            $Job.Sync.StatusText = 'Cancelled before the search started.'
            return
        }

        Start-ComplianceSearch -Identity $Job.SearchName -Confirm:$false
        Write-JobLog 'Compliance search started.' 'SUCCESS'
        $search = Wait-ForComplianceSearch
        Publish-SearchWorkerResult -Search $search

        $finalStatus = [string]$Job.Sync.SearchStatus
        if ($finalStatus -eq 'Completed') {
            Write-JobLog 'Search completed.' 'SUCCESS'
        }
        elseif ($Job.Sync.TimedOut) {
            Write-JobLog "Monitoring timed out. Review search $($Job.SearchName) in Purview." 'WARNING'
        }
        else {
            Write-JobLog "Search requires review: $finalStatus" 'WARNING'
        }

        $itemCount = 0
        if ($search -and $null -ne $search.Items -and -not [string]::IsNullOrWhiteSpace([string]$search.Items)) {
            try { $itemCount = [int]$search.Items } catch { $itemCount = 0 }
        }
        $Job.ReportedItemCount = $itemCount
        $canCollect = ($finalStatus -in @('Completed', 'PartiallySucceeded')) -and -not $Job.Sync.CancelRequested -and -not $Job.Sync.TimedOut
        if ($canCollect -and $itemCount -le 0 -and $Job.OutputFolder -and (Test-Path -LiteralPath $Job.OutputFolder)) {
            $saved = Export-FindingsSpreadsheet -Items $null -OutputFolder $Job.OutputFolder -SearchName $Job.SearchName -ReportedItemCount 0
            $Job.Sync.FindingsCount = 0
            $Job.Sync.FindingsReported = 0
            $Job.Sync.FindingsPath = [string]$saved.WorkbookPath
            Write-JobLog "No matching messages. Wrote $($saved.WorkbookPath)"
        }
        elseif ($canCollect -and $itemCount -gt 0) {
            try {
                $Job.Sync.StatusText = "Collecting subject lines for $itemCount messages"
                Write-JobLog "Collecting subject lines for $itemCount matching messages. Message bodies are not downloaded."
                Start-PreviewWorker
            }
            catch {
                $message = Get-ErrorText $_
                $Job.Sync.FindingsError = $message
                Write-JobLog "The findings spreadsheet was not created: $message" 'WARNING'
                if ($finalStatus -eq 'Completed') { $Job.Sync.Phase = 'Completed' }
                else { $Job.Sync.Phase = 'Finished' }
            }
            $Job.Sync.SearchStatus = $finalStatus
        }
    }

    function Wait-ForComplianceAction {
        param([string]$ActionName)
        $timeout = 30.0
        try {
            if ($Job.TimeoutMinutes) { $timeout = [Math]::Min(30, [double]$Job.TimeoutMinutes) }
        }
        catch { $timeout = 30.0 }
        if ($timeout -lt 1) { $timeout = 1 }

        $watch = [Diagnostics.Stopwatch]::StartNew()
        $action = $null
        while ($true) {
            if ($Job.Sync.CancelRequested) {
                Write-JobLog 'Stopped waiting. The action may still be running in Purview.' 'WARNING'
                $Job.Sync.Phase = 'Cancelled'
                break
            }
            try {
                $action = Get-ComplianceSearchAction -Identity $ActionName
            }
            catch {
                Write-JobLog "Action status check failed: $(Get-ErrorText $_)" 'WARNING'
            }
            if ($null -eq $action) {
                if ($watch.Elapsed.TotalMinutes -ge $timeout) {
                    $Job.Sync.TimedOut = $true
                    Write-JobLog 'Action monitoring timed out. It may still be running in Purview.' 'WARNING'
                    break
                }
                Start-Sleep -Seconds 5
                continue
            }
            $status = [string]$action.Status
            $progress = 0
            if ($action -and $null -ne $action.JobProgress) {
                try { $progress = [int]$action.JobProgress } catch { $progress = 0 }
            }
            $Job.Sync.SearchStatus = $status
            $Job.Sync.Progress = $progress
            $Job.Sync.StatusText = "Action ${ActionName}: $status ($progress%)"
            Write-JobLog $Job.Sync.StatusText
            if (Test-TerminalSearchStatus $status) { break }
            if ($watch.Elapsed.TotalMinutes -ge $timeout) {
                $Job.Sync.TimedOut = $true
                Write-JobLog 'Action monitoring timed out. It may still be running in Purview.' 'WARNING'
                break
            }
            $slept = 0
            while ($slept -lt 5 -and -not $Job.Sync.CancelRequested) {
                Start-Sleep -Seconds 1
                $slept++
            }
        }
        return $action
    }

    function Get-ActionResultText {
        param($Action)
        if ($null -eq $Action) { return '' }
        $raw = ConvertTo-ResultText $Action.Results
        if ([string]::IsNullOrWhiteSpace($raw) -and $Action.PSObject.Properties['ActionResults']) {
            $raw = ConvertTo-ResultText $Action.ActionResults
        }
        return $raw
    }

    function Hide-SecretAddress {
        param([AllowEmptyString()][string]$Text)
        if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
        $cleaned = [regex]::Replace($Text, 'https?://\S+', '[address omitted]')
        if ($cleaned.Length -gt 800) { return $cleaned.Substring(0, 800) }
        return $cleaned
    }

    function Get-HttpErrorBody {
        param($Record)
        $body = ''
        if ($Record.ErrorDetails -and $Record.ErrorDetails.Message) {
            $body = [string]$Record.ErrorDetails.Message
        }
        if ([string]::IsNullOrWhiteSpace($body)) {
            try {
                $response = $Record.Exception.Response
                if ($response -and $response.GetResponseStream) {
                    $stream = $response.GetResponseStream()
                    if ($stream) {
                        $reader = New-Object System.IO.StreamReader($stream)
                        $body = $reader.ReadToEnd()
                        $reader.Dispose()
                    }
                }
            }
            catch { }
        }
        return (Hide-SecretAddress $body)
    }

    function Invoke-PurviewGraph {
        param(
            [string]$Method,
            [string]$Uri,
            [AllowEmptyString()][string]$JsonBody,
            [string]$Token
        )
        $headers = @{
            Authorization = "Bearer $Token"
            Accept        = 'application/json'
        }
        $params = @{
            Method          = $Method
            Uri             = $Uri
            Headers         = $headers
            UseBasicParsing = $true
        }
        if (-not [string]::IsNullOrWhiteSpace($JsonBody)) {
            $params.Body = [System.Text.Encoding]::UTF8.GetBytes($JsonBody)
            $params.ContentType = 'application/json; charset=utf-8'
        }
        try {
            $response = Invoke-WebRequest @params
        }
        catch {
            $body = Get-HttpErrorBody $_
            if ([string]::IsNullOrWhiteSpace($body)) { $body = Hide-SecretAddress (Get-ErrorText $_) }
            $status = 0
            try {
                if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                    $status = [int]$_.Exception.Response.StatusCode
                }
            }
            catch { }
            return [pscustomobject]@{
                Ok         = $false
                StatusCode = $status
                Location   = ''
                Json       = $null
                Error      = $body
            }
        }

        $location = ''
        if ($response.Headers) {
            $loc = $null
            try { if ($response.Headers['Location']) { $loc = $response.Headers['Location'] } } catch { }
            if ($null -eq $loc) {
                try { $loc = $response.Headers.Location } catch { }
            }
            if ($loc -is [System.Array]) {
                if ($loc.Length -gt 0) { $location = [string]$loc[0] }
            }
            elseif ($null -ne $loc) {
                $location = [string]$loc
            }
        }
        if ($location.StartsWith('/')) { $location = 'https://graph.microsoft.com' + $location }

        $parsed = $null
        if ($response.Content) {
            try { $parsed = ([string]$response.Content) | ConvertFrom-Json } catch { $parsed = $null }
        }
        return [pscustomobject]@{
            Ok         = $true
            StatusCode = [int]$response.StatusCode
            Location   = $location
            Json       = $parsed
            Error      = ''
        }
    }

    function Get-GraphFailure {
        param($Result, [string]$Action)
        $detail = ''
        if ($Result) { $detail = Hide-SecretAddress ([string]$Result.Error) }
        return "$Action $detail".Trim()
    }

    function Wait-PurviewGraphOperation {
        param([string]$Location, [string]$Token, [string]$Label)
        $timeout = 120.0
        try {
            if ($Job.TimeoutMinutes) { $timeout = [double]$Job.TimeoutMinutes }
        }
        catch { $timeout = 120.0 }
        if ($timeout -lt 1) { $timeout = 1 }

        $watch = [Diagnostics.Stopwatch]::StartNew()
        $last = ''
        while ($true) {
            if ($Job.Sync.CancelRequested) { throw "Cancelled while waiting for the $Label." }
            if ($watch.Elapsed.TotalMinutes -ge $timeout) {
                throw "The $Label is still running after $timeout minutes. Open the eDiscovery case in Purview and download the item report from Process manager. Message files are not required."
            }
            $slept = 0
            while ($slept -lt 10 -and -not $Job.Sync.CancelRequested) {
                Start-Sleep -Seconds 1
                $slept++
            }
            if ($Job.Sync.CancelRequested) { throw "Cancelled while waiting for the $Label." }

            $result = Invoke-PurviewGraph -Method Get -Uri $Location -Token $Token
            if (-not $result.Ok) { throw (Get-GraphFailure $result "The $Label status could not be read.") }
            $status = ''
            if ($result.Json -and $result.Json.status) { $status = [string]$result.Json.status }
            if ($status -and $status -ne $last) {
                Write-JobLog "$Label status: $status"
                $Job.Sync.StatusText = "$Label status: $status"
                $last = $status
            }
            if ($status -in @('succeeded', 'partiallySucceeded', 'completed')) { return $result.Json }
            if ($status -in @('failed', 'cancelled', 'canceled')) {
                $detail = ''
                if ($result.Json.statusDetail) { $detail = Hide-SecretAddress ([string]$result.Json.statusDetail) }
                throw "The $Label failed ($status). $detail"
            }
        }
    }

    function Get-GraphAccessToken {
        if ($script:GraphAccessToken -and $script:GraphTokenExpires) {
            if (($script:GraphTokenExpires - [datetime]::UtcNow).TotalMinutes -gt 5) {
                return [string]$script:GraphAccessToken
            }
        }

        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
        $clientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
        $scope = 'https://graph.microsoft.com/eDiscovery.ReadWrite.All'
        $deviceUri = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode'
        $tokenUri = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
        $deviceBody = 'client_id=' + [uri]::EscapeDataString($clientId) + '&scope=' + [uri]::EscapeDataString($scope)
        try {
            $deviceResponse = Invoke-WebRequest -Method Post -Uri $deviceUri -Body $deviceBody -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing
        }
        catch {
            $detail = Get-HttpErrorBody $_
            if (-not $detail) { $detail = Hide-SecretAddress (Get-ErrorText $_) }
            throw "Microsoft sign-in for the item report could not start. $detail"
        }

        $device = $null
        try { $device = ([string]$deviceResponse.Content) | ConvertFrom-Json }
        catch { throw 'Microsoft sign-in for the item report returned a response that could not be read.' }
        if ($null -eq $device -or [string]::IsNullOrWhiteSpace([string]$device.user_code) -or [string]::IsNullOrWhiteSpace([string]$device.device_code)) {
            throw 'Microsoft sign-in for the item report did not return a sign-in code.'
        }

        $userCode = [string]$device.user_code
        $signInUrl = [string]$device.verification_uri
        if ([string]::IsNullOrWhiteSpace($signInUrl)) { $signInUrl = [string]$device.verification_url }
        if ([string]::IsNullOrWhiteSpace($signInUrl)) { $signInUrl = 'https://microsoft.com/devicelogin' }
        $interval = 5
        if ($device.interval) {
            try { $interval = [int]$device.interval } catch { $interval = 5 }
        }
        if ($interval -lt 5) { $interval = 5 }
        $expiresIn = 900
        if ($device.expires_in) {
            try { $expiresIn = [int]$device.expires_in } catch { $expiresIn = 900 }
        }

        $Job.Sync.GraphSignInUrl = $signInUrl
        $Job.Sync.GraphUserCode = $userCode
        $Job.Sync.StatusText = "Sign in at $signInUrl and enter code $userCode"
        Write-JobLog "A second Microsoft sign-in is required for the subject list. Open $signInUrl and enter $userCode. Use an eDiscovery Manager or eDiscovery Administrator account. Message files are not downloaded and no hold is placed." 'WARNING'

        $watch = [Diagnostics.Stopwatch]::StartNew()
        $token = $null
        while ($true) {
            if ($Job.Sync.CancelRequested) { throw 'Cancelled before the item-report sign-in finished.' }
            if ($watch.Elapsed.TotalSeconds -ge $expiresIn) {
                throw "The sign-in code expired. Start the findings list again and complete sign-in at $signInUrl."
            }
            $slept = 0
            while ($slept -lt $interval -and -not $Job.Sync.CancelRequested) {
                Start-Sleep -Seconds 1
                $slept++
            }
            if ($Job.Sync.CancelRequested) { throw 'Cancelled before the item-report sign-in finished.' }

            $tokenBody = 'grant_type=' + [uri]::EscapeDataString('urn:ietf:params:oauth:grant-type:device_code') + '&client_id=' + [uri]::EscapeDataString($clientId) + '&device_code=' + [uri]::EscapeDataString([string]$device.device_code)
            try {
                $tokenResponse = Invoke-WebRequest -Method Post -Uri $tokenUri -Body $tokenBody -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing
                $token = ([string]$tokenResponse.Content) | ConvertFrom-Json
                break
            }
            catch {
                $detail = Get-HttpErrorBody $_
                if (-not $detail) { $detail = Hide-SecretAddress (Get-ErrorText $_) }
                if ($detail -match 'authorization_pending') { continue }
                if ($detail -match 'slow_down') {
                    $interval += 5
                    continue
                }
                if ($detail -match 'expired_token' -or $detail -match 'code has expired') {
                    throw "The sign-in code expired. Start the findings list again and complete sign-in at $signInUrl."
                }
                if ($detail -match 'authorization_declined' -or $detail -match 'access_denied') {
                    throw 'The item-report sign-in was declined.'
                }
                throw "Microsoft sign-in for the item report failed. $detail Sign in with an eDiscovery Manager or eDiscovery Administrator. If the tenant blocks Microsoft Graph Command Line Tools, an administrator must consent to eDiscovery.ReadWrite.All. Microsoft 365 China (21Vianet) does not support this report."
            }
        }

        if (-not $token -or [string]::IsNullOrWhiteSpace([string]$token.access_token)) {
            throw 'Microsoft sign-in finished without an access token for the item report.'
        }
        $script:GraphAccessToken = [string]$token.access_token
        $lifetime = 3600
        if ($token.expires_in) {
            try { $lifetime = [int]$token.expires_in } catch { $lifetime = 3600 }
        }
        $script:GraphTokenExpires = [datetime]::UtcNow.AddSeconds($lifetime)
        $Job.Sync.GraphUserCode = ''
        Write-JobLog 'Signed in for the item report. No hold was placed and message files are not downloaded.' 'SUCCESS'
        return [string]$script:GraphAccessToken
    }

    function Get-FindingsFromReportOperation {
        param($Operation)
        $files = @()
        if ($Operation -and $Operation.exportFileMetadata) { $files = @($Operation.exportFileMetadata) }
        if ($files.Count -eq 0) { throw 'The item report finished without any files.' }

        $folder = [string]$Job.OutputFolder
        if ([string]::IsNullOrWhiteSpace($folder) -or -not (Test-Path -LiteralPath $folder)) {
            $folder = [System.IO.Path]::GetTempPath()
        }
        $work = Join-Path $folder 'ItemReportFiles'
        if (-not (Test-Path -LiteralPath $work)) {
            New-Item -ItemType Directory -Path $work -Force | Out-Null
        }

        $csvPaths = New-Object System.Collections.Generic.List[string]
        $ignoredContent = $false
        foreach ($file in $files) {
            if ($null -eq $file) { continue }
            $name = 'report.bin'
            if ($file.fileName -and -not [string]::IsNullOrWhiteSpace([string]$file.fileName)) {
                $name = [System.IO.Path]::GetFileName([string]$file.fileName)
            }
            $lower = $name.ToLowerInvariant()
            if ($lower.EndsWith('.pst') -or $lower.EndsWith('.msg') -or $lower.EndsWith('.eml')) {
                $ignoredContent = $true
                continue
            }
            $url = ''
            if ($file.downloadUrl) { $url = [string]$file.downloadUrl }
            if ([string]::IsNullOrWhiteSpace($url)) { continue }
            $safe = ($name -replace '[\\/:*?"<>|]', '_')
            if ([string]::IsNullOrWhiteSpace($safe)) { $safe = 'report.bin' }
            $dest = Join-Path $work $safe
            try {
                Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing | Out-Null
            }
            catch {
                throw 'The item report file could not be downloaded. The download address was not saved.'
            }

            $isCsv = $lower.EndsWith('.csv')
            $isZip = $lower.EndsWith('.zip')
            if (-not $isZip) {
                try {
                    $probe = [System.IO.File]::ReadAllBytes($dest)
                    if ($probe.Length -ge 2 -and $probe[0] -eq 80 -and $probe[1] -eq 75) { $isZip = $true }
                }
                catch { }
            }
            if ($isCsv -and -not $isZip) {
                $csvPaths.Add($dest)
                continue
            }
            if (-not $isZip) { continue }

            $extract = Join-Path $work ([System.IO.Path]::GetFileNameWithoutExtension($safe))
            if (-not (Test-Path -LiteralPath $extract)) {
                New-Item -ItemType Directory -Path $extract -Force | Out-Null
            }
            try {
                Expand-Archive -LiteralPath $dest -DestinationPath $extract -Force
            }
            catch {
                try {
                    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($dest, $extract)
                }
                catch {
                    throw 'The item report archive could not be opened.'
                }
            }
            try { Remove-Item -LiteralPath $dest -Force } catch { }
            $extractedFiles = Get-ChildItem -LiteralPath $extract -Recurse -File -ErrorAction SilentlyContinue
            foreach ($extracted in $extractedFiles) {
                $ext = $extracted.Extension.ToLowerInvariant()
                if ($ext -eq '.csv') { $csvPaths.Add($extracted.FullName) }
                elseif ($ext -eq '.pst' -or $ext -eq '.msg' -or $ext -eq '.eml') {
                    $ignoredContent = $true
                    try { Remove-Item -LiteralPath $extracted.FullName -Force } catch { }
                }
            }
        }
        if ($ignoredContent) {
            Write-JobLog 'A message file was listed with the report and was not downloaded. Only the item report is used.' 'WARNING'
        }
        if ($csvPaths.Count -eq 0) { throw 'The item report did not include a CSV of message subjects.' }

        $best = $null
        $bestScore = -1
        $bestPath = ''
        foreach ($csvPath in $csvPaths) {
            $text = [System.IO.File]::ReadAllText($csvPath)
            $parsed = ConvertTo-FindingsFromReportCsv -CsvText $text
            $score = 0
            foreach ($row in $parsed) {
                if ($null -ne $row -and (-not [string]::IsNullOrWhiteSpace([string]$row.Subject) -or -not [string]::IsNullOrWhiteSpace([string]$row.Sender))) {
                    $score++
                }
            }
            if ($score -gt $bestScore) {
                $best = $parsed
                $bestScore = $score
                $bestPath = $csvPath
            }
        }
        if ($bestScore -le 0 -or $null -eq $best) {
            throw 'The item report finished, but none of its files included message subjects.'
        }
        if (-not [string]::IsNullOrWhiteSpace($bestPath) -and $Job.OutputFolder -and (Test-Path -LiteralPath $Job.OutputFolder)) {
            try { [System.IO.File]::Copy($bestPath, (Join-Path $Job.OutputFolder 'PurviewItemReport.csv'), $true) } catch { }
        }
        Write-JobLog "Item report contained $bestScore messages with subject or sender values."
        return ,$best
    }

    function Request-GraphFindingItems {
        param(
            [AllowEmptyString()][string]$ContentQuery,
            [AllowEmptyString()][string]$ExchangeLocation
        )
        if ([string]::IsNullOrWhiteSpace($ContentQuery)) {
            throw 'The completed search has no query, so the item report cannot be created.'
        }
        $token = Get-GraphAccessToken
        $base = 'https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases'
        $caseName = 'Purview Email Investigation'
        if (-not [string]::IsNullOrWhiteSpace([string]$Job.CaseName)) { $caseName = ([string]$Job.CaseName).Trim() }

        $caseId = $null
        $next = $base + '?$top=50'
        $pages = 0
        while ($next -and -not $caseId -and $pages -lt 20) {
            $pages++
            $page = Invoke-PurviewGraph -Method Get -Uri $next -Token $token
            if (-not $page.Ok) {
                throw ((Get-GraphFailure $page 'The eDiscovery case list could not be read.') + ' The account needs eDiscovery Manager or eDiscovery Administrator, and the Microsoft Graph eDiscovery.ReadWrite.All permission.')
            }
            if ($page.Json -and $page.Json.value) {
                foreach ($case in $page.Json.value) {
                    if ($case.displayName -and ([string]$case.displayName).ToLowerInvariant() -eq $caseName.ToLowerInvariant()) {
                        $caseId = [string]$case.id
                        break
                    }
                }
            }
            $next = ''
            if (-not $caseId -and $page.Json -and $page.Json.'@odata.nextLink') {
                $next = [string]$page.Json.'@odata.nextLink'
            }
        }

        if (-not $caseId) {
            Write-JobLog "Creating eDiscovery case '$caseName'. No hold is placed."
            $created = Invoke-PurviewGraph -Method Post -Uri $base -Token $token -JsonBody (ConvertTo-GraphJson @{
                displayName = $caseName
                description = 'Read-only case used by Purview Email Investigation to list message subjects. No hold is placed and message files are not downloaded.'
            })
            if (-not $created.Ok -or -not $created.Json -or -not $created.Json.id) {
                throw (Get-GraphFailure $created 'The eDiscovery case could not be created.')
            }
            $caseId = [string]$created.Json.id
        }
        else {
            Write-JobLog "Using existing eDiscovery case '$caseName'. No hold is placed."
        }

        $location = ''
        if (-not [string]::IsNullOrWhiteSpace($ExchangeLocation)) {
            $location = (($ExchangeLocation -split '\r?\n')[0]).Trim()
        }
        $allMailboxes = ($location -eq 'All')
        $mailbox = ''
        if (-not $allMailboxes) {
            $mailbox = $location.TrimStart('.')
            if ($mailbox -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
                if ($ContentQuery -match 'from:"([^"]+)"') { $mailbox = $Matches[1] }
            }
            if ($mailbox -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
                throw "The search location '$location' is not a mailbox address, so the item report cannot be limited to one mailbox."
            }
        }

        $searchBody = @{
            displayName = ''
            description = 'Read-only item report for message subjects. Message files are not downloaded. No hold is placed.'
            contentQuery = $ContentQuery
        }
        if ($allMailboxes) {
            $searchBody['dataSourceScopes'] = 'allTenantMailboxes'
            Write-JobLog 'The item report uses the same query across all tenant mailboxes. Message files are not downloaded.'
        }
        else {
            $custodianId = $null
            $custodianUri = $base + '/' + $caseId + '/custodians?$top=100'
            $custodianPage = Invoke-PurviewGraph -Method Get -Uri $custodianUri -Token $token
            if ($custodianPage.Ok -and $custodianPage.Json -and $custodianPage.Json.value) {
                foreach ($custodian in $custodianPage.Json.value) {
                    if ($custodian.email -and ([string]$custodian.email).ToLowerInvariant() -eq $mailbox.ToLowerInvariant()) {
                        $custodianId = [string]$custodian.id
                        break
                    }
                }
            }
            if (-not $custodianId) {
                Write-JobLog "Adding mailbox $mailbox to the case. The mailbox is not placed on hold."
                $added = Invoke-PurviewGraph -Method Post -Uri ($base + '/' + $caseId + '/custodians') -Token $token -JsonBody (ConvertTo-GraphJson @{ email = $mailbox })
                if (-not $added.Ok -or -not $added.Json -or -not $added.Json.id) {
                    throw (Get-GraphFailure $added "The mailbox $mailbox could not be added to the case.")
                }
                $custodianId = [string]$added.Json.id
            }

            $sourceId = $null
            $sources = Invoke-PurviewGraph -Method Get -Uri ($base + '/' + $caseId + '/custodians/' + $custodianId + '/userSources') -Token $token
            if ($sources.Ok -and $sources.Json -and $sources.Json.value) {
                foreach ($source in $sources.Json.value) {
                    $included = [string]$source.includedSources
                    if ($included -match 'mailbox') {
                        $sourceId = [string]$source.id
                        break
                    }
                }
            }
            if (-not $sourceId) {
                $createdSource = Invoke-PurviewGraph -Method Post -Uri ($base + '/' + $caseId + '/custodians/' + $custodianId + '/userSources') -Token $token -JsonBody (ConvertTo-GraphJson @{
                    email            = $mailbox
                    includedSources  = 'mailbox'
                })
                if (-not $createdSource.Ok -or -not $createdSource.Json -or -not $createdSource.Json.id) {
                    throw (Get-GraphFailure $createdSource "The mailbox source for $mailbox could not be added.")
                }
                $sourceId = [string]$createdSource.Json.id
            }
            $searchBody['custodianSources@odata.bind'] = @($base + '/' + $caseId + '/custodians/' + $custodianId + '/userSources/' + $sourceId)
            Write-JobLog "The item report is limited to mailbox $mailbox."
        }

        $suffix = '_S' + (Get-Date -Format 'HHmmss')
        $baseName = [string]$Job.SearchName
        if ([string]::IsNullOrWhiteSpace($baseName)) { $baseName = 'EmailInvestigation' }
        if (($baseName.Length + $suffix.Length) -gt 180) {
            $baseName = $baseName.Substring(0, 180 - $suffix.Length)
        }
        $graphSearchName = $baseName + $suffix
        $searchBody['displayName'] = $graphSearchName
        Write-JobLog "Creating the item-report search $graphSearchName."
        $Job.Sync.StatusText = 'Creating the item report'
        $search = Invoke-PurviewGraph -Method Post -Uri ($base + '/' + $caseId + '/searches') -Token $token -JsonBody (ConvertTo-GraphJson $searchBody)
        if (-not $search.Ok -or -not $search.Json -or -not $search.Json.id) {
            throw (Get-GraphFailure $search 'The item-report search could not be created.')
        }
        $searchId = [string]$search.Json.id

        Write-JobLog 'Estimating the item-report search.'
        $Job.Sync.StatusText = 'Estimating the item report'
        $estimateUri = $base + '/' + $caseId + '/searches/' + $searchId + '/estimateStatistics'
        $estimate = Invoke-PurviewGraph -Method Post -Uri $estimateUri -Token $token -JsonBody (ConvertTo-GraphJson @{ statisticsOptions = 'includeQueryStats' })
        if (-not $estimate.Ok -and $estimate.StatusCode -eq 400) {
            $estimate = Invoke-PurviewGraph -Method Post -Uri $estimateUri -Token $token -JsonBody '{}'
        }
        if (-not $estimate.Ok) { throw (Get-GraphFailure $estimate 'The item-report estimate could not start.') }
        $estimateUrl = [string]$estimate.Location
        if ([string]::IsNullOrWhiteSpace($estimateUrl) -and $estimate.Json -and $estimate.Json.id) {
            $estimateUrl = $base + '/' + $caseId + '/operations/' + [string]$estimate.Json.id
        }
        if ([string]::IsNullOrWhiteSpace($estimateUrl)) {
            throw 'Microsoft Graph did not return an operation address for the item-report estimate.'
        }
        Wait-PurviewGraphOperation -Location $estimateUrl -Token $token -Label 'Estimate' | Out-Null

        Write-JobLog 'Requesting the item report. Message files are not downloaded.'
        $Job.Sync.StatusText = 'Requesting the item report'
        $export = Invoke-PurviewGraph -Method Post -Uri ($base + '/' + $caseId + '/searches/' + $searchId + '/exportReport') -Token $token -JsonBody (ConvertTo-GraphJson @{
            displayName        = ($graphSearchName + ' report')
            description        = 'Item report only. Message files are not downloaded.'
            exportCriteria     = 'searchHits'
            additionalOptions  = 'none'
        })
        if (-not $export.Ok) { throw (Get-GraphFailure $export 'The item report could not start.') }
        $exportUrl = [string]$export.Location
        if ([string]::IsNullOrWhiteSpace($exportUrl) -and $export.Json -and $export.Json.id) {
            $exportUrl = $base + '/' + $caseId + '/operations/' + [string]$export.Json.id
        }
        if ([string]::IsNullOrWhiteSpace($exportUrl)) {
            throw 'Microsoft Graph did not return an operation address for the item report.'
        }
        $operation = Wait-PurviewGraphOperation -Location $exportUrl -Token $token -Label 'Item report'
        $items = Get-FindingsFromReportOperation -Operation $operation
        return ,$items
    }

    function Publish-FindingRows {
        param($Items)
        $reported = -1
        if ($null -ne $Job.ReportedItemCount) {
            try { $reported = [int]$Job.ReportedItemCount } catch { $reported = -1 }
        }
        $count = 0
        foreach ($row in $Items) {
            if ($null -ne $row) { $count++ }
        }
        if ($Job.OutputFolder -and (Test-Path -LiteralPath $Job.OutputFolder)) {
            $saved = Export-FindingsSpreadsheet -Items $Items -OutputFolder $Job.OutputFolder -SearchName $Job.SearchName -ReportedItemCount $reported
            $Job.Sync.FindingsCount = $count
            $Job.Sync.FindingsReported = $reported
            $Job.Sync.FindingsPath = [string]$saved.WorkbookPath
            if ($reported -gt $count) {
                Write-JobLog "MessageFindings.xlsx has $count subject lines. The search reported $reported matches. The item report did not include a subject for every match." 'WARNING'
            }
            else {
                Write-JobLog "Findings spreadsheet saved with $count subject lines: $($Job.Sync.FindingsPath)" 'SUCCESS'
            }
        }
        else {
            $Job.Sync.FindingsCount = $count
            Write-JobLog 'Subject lines will be shown in the window. No output folder was available for the spreadsheet.' 'WARNING'
        }
        $Job.Sync.Preview = $Items
        if ($Job.Sync.Phase -ne 'Cancelled') {
            $Job.Sync.Phase = 'PreviewReady'
            $Job.Sync.StatusText = "Findings spreadsheet ready ($count subject lines)"
            $Job.Sync.Progress = 100
        }
    }

    function Start-PreviewWorker {
        if (-not $script:IppsConnected) { throw 'Connect to Purview before loading a preview.' }
        if ([string]::IsNullOrWhiteSpace([string]$Job.SearchName)) { throw 'There is no search to preview.' }

        $existing = Get-ComplianceSearch -Identity $Job.SearchName
        $existingStatus = [string]$existing.Status
        if ($existingStatus -notin @('Completed', 'PartiallySucceeded')) {
            throw "A findings list is available after the search completes. Current status: $existingStatus"
        }
        if (($null -eq $Job.ReportedItemCount -or [int]$Job.ReportedItemCount -lt 0) -and $null -ne $existing.Items -and -not [string]::IsNullOrWhiteSpace([string]$existing.Items)) {
            try { $Job.ReportedItemCount = [int]$existing.Items } catch { }
        }

        $supportsPreview = $false
        try {
            $actionCommand = Get-Command -Name New-ComplianceSearchAction -ErrorAction Stop
            $supportsPreview = [bool]$actionCommand.Parameters.ContainsKey('Preview')
        }
        catch {
            $supportsPreview = $false
        }
        if (-not $supportsPreview) {
            Write-JobLog 'This Microsoft 365 connection does not accept New-ComplianceSearchAction -Preview. Requesting an item report that lists each subject. Message files are not downloaded.'
            $queryText = ConvertTo-ResultText $existing.ContentMatchQuery
            $locationText = ConvertTo-ResultText $existing.ExchangeLocation
            $items = Request-GraphFindingItems -ContentQuery $queryText -ExchangeLocation $locationText
            Publish-FindingRows -Items $items
            return
        }

        $actionName = "$($Job.SearchName)_Preview"
        $action = $null
        try {
            $action = Get-ComplianceSearchAction -Identity $actionName -ErrorAction SilentlyContinue
        }
        catch { $action = $null }

        if ($action -and (Test-TerminalSearchStatus ([string]$action.Status))) {
            Write-JobLog "Using the existing preview action $actionName."
        }
        else {
            Write-JobLog 'Requesting message subjects from Purview. Message bodies are not downloaded.'
            $created = New-ComplianceSearchAction -SearchName $Job.SearchName -Preview -Confirm:$false
            if ($created -and $created.Name) { $actionName = [string]$created.Name }
            $Job.Sync.Phase = 'Running'
            $action = Wait-ForComplianceAction -ActionName $actionName
        }

        $reported = -1
        if ($null -ne $Job.ReportedItemCount) {
            try { $reported = [int]$Job.ReportedItemCount } catch { $reported = -1 }
        }
        $actionStatus = if ($action) { [string]$action.Status } else { '' }
        $raw = "Action: $actionName$([Environment]::NewLine)Status: $actionStatus$([Environment]::NewLine)$([Environment]::NewLine)$(Get-ActionResultText $action)"
        $items = @()
        if ($Job.OutputFolder -and (Test-Path -LiteralPath $Job.OutputFolder)) {
            $exported = Export-PreviewResults -RawResults $raw -OutputFolder $Job.OutputFolder -SearchName $Job.SearchName -ReportedItemCount $reported
            if ($exported) { $items = $exported.Rows }
            $count = 0
            foreach ($row in $items) { if ($null -ne $row) { $count++ } }
            $Job.Sync.FindingsCount = $count
            $Job.Sync.FindingsReported = $reported
            if ($exported -and $exported.File) { $Job.Sync.FindingsPath = [string]$exported.File.WorkbookPath }
            if ($reported -gt $count) {
                Write-JobLog "MessageFindings.xlsx has $count subject lines. The search reported $reported matches. Purview did not return a subject for every match." 'WARNING'
            }
            else {
                Write-JobLog "Findings spreadsheet saved with $count subject lines: $($Job.Sync.FindingsPath)" 'SUCCESS'
            }
        }
        else {
            $items = ConvertTo-PreviewItem $raw
            $count = 0
            foreach ($row in $items) { if ($null -ne $row) { $count++ } }
            $Job.Sync.FindingsCount = $count
            Write-JobLog 'Subject lines will be shown in the window. No output folder was available for the spreadsheet.' 'WARNING'
        }
        $Job.Sync.Preview = $items
        if ($Job.Sync.Phase -ne 'Cancelled') {
            $Job.Sync.Phase = 'PreviewReady'
            $countText = [string]$Job.Sync.FindingsCount
            $Job.Sync.StatusText = "Findings spreadsheet ready ($countText subject lines)"
            $Job.Sync.Progress = 100
        }
    }

    function Start-ReportWorker {
        if (-not $script:IppsConnected) { throw 'Connect to Purview before creating a statistics report.' }
        if ([string]::IsNullOrWhiteSpace([string]$Job.SearchName)) { throw 'There is no search to report on.' }

        $existing = Get-ComplianceSearch -Identity $Job.SearchName
        if ([string]$existing.Status -notin @('Completed', 'PartiallySucceeded')) {
            throw "A statistics report is available after the search completes. Current status: $($existing.Status)"
        }

        $supportsReport = $false
        try {
            $reportCommand = Get-Command -Name New-ComplianceSearchAction -ErrorAction Stop
            $supportsReport = [bool]$reportCommand.Parameters.ContainsKey('Report')
        }
        catch {
            $supportsReport = $false
        }
        if (-not $supportsReport) {
            throw 'Microsoft 365 no longer accepts New-ComplianceSearchAction -Report. Mailbox totals are already in the search summary, and the findings spreadsheet lists each subject.'
        }

        Write-JobLog 'Creating a statistics report action. Message content is not exported.'
        $created = New-ComplianceSearchAction -SearchName $Job.SearchName -Report -Confirm:$false
        $actionName = "$($Job.SearchName)_Report"
        if ($created -and $created.Name) { $actionName = [string]$created.Name }
        $Job.Sync.Phase = 'Running'
        $action = Wait-ForComplianceAction -ActionName $actionName
        $actionStatus = if ($action) { [string]$action.Status } else { '' }
        $raw = "Action: $actionName$([Environment]::NewLine)Status: $actionStatus$([Environment]::NewLine)$([Environment]::NewLine)$(Get-ActionResultText $action)"
        $Job.Sync.ReportNote = $raw
        if ($Job.OutputFolder -and (Test-Path -LiteralPath $Job.OutputFolder)) {
            Write-Utf8File -Path (Join-Path $Job.OutputFolder 'StatisticsReport.txt') -Content ($raw + [Environment]::NewLine)
            Write-JobLog "Statistics report saved to $($Job.OutputFolder)" 'SUCCESS'
        }
        if ($Job.Sync.Phase -ne 'Cancelled') {
            $Job.Sync.Phase = 'ReportReady'
            $Job.Sync.StatusText = 'Statistics report ready'
            $Job.Sync.Progress = 100
        }
    }

    function Remove-SearchWorker {
        if (-not $script:IppsConnected) { throw 'Connect to Purview before removing a search definition.' }
        if ([string]::IsNullOrWhiteSpace([string]$Job.SearchName)) { throw 'There is no search definition to remove.' }

        Write-JobLog "Removing search definition $($Job.SearchName). Mailbox messages are not modified." 'WARNING'
        foreach ($suffix in @('Preview', 'Preview1', 'Report', 'Report1')) {
            $actionName = "$($Job.SearchName)_$suffix"
            try {
                Remove-ComplianceSearchAction -Identity $actionName -Confirm:$false -ErrorAction SilentlyContinue
            }
            catch { }
        }
        Remove-ComplianceSearch -Identity $Job.SearchName -Confirm:$false
        $Job.Sync.SearchCreated = $false
        $Job.Sync.Phase = 'Removed'
        $Job.Sync.StatusText = 'Search definition removed'
        Write-JobLog 'Search definition removed. Mailbox messages were not modified.' 'SUCCESS'
    }

    function Install-ModuleWorker {
        $Job.Sync.Phase = 'Installing'
        $Job.Sync.StatusText = 'Installing ExchangeOnlineManagement for the current user'
        Write-JobLog $Job.Sync.StatusText
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
        catch { }

        $provider = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue -Force
        if (-not $provider -or $provider.Version -lt [version]'2.8.5.201') {
            Write-JobLog 'Installing the NuGet package provider.'
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
        }
        $repository = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($repository -and $repository.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            Write-JobLog 'Trusted the PowerShell Gallery for the current user.'
        }
        Install-Module -Name ExchangeOnlineManagement -MinimumVersion 3.9.0 -Scope CurrentUser -Force -AllowClobber
        $Job.Sync.Phase = 'Installed'
        $Job.Sync.StatusText = 'ExchangeOnlineManagement installed'
        $Job.Sync.Progress = 100
        Write-JobLog 'Module install finished.' 'SUCCESS'
    }

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $ConfirmPreference = 'None'
    $WarningPreference = 'SilentlyContinue'

    try {
        if ($null -eq $Job.Sync) { throw 'Search job is missing its status channel.' }
        $Job.Sync.Busy = $true
        switch ([string]$Job.Mode) {
            'Connect' { Connect-PurviewWorker }
            'Disconnect' { Disconnect-PurviewWorker }
            'ConnectAndSearch' {
                Connect-PurviewWorker
                if ($Job.Sync.CancelRequested) {
                    $Job.Sync.Phase = 'Cancelled'
                    $Job.Sync.StatusText = 'Cancelled before the search was created.'
                    Write-JobLog $Job.Sync.StatusText 'WARNING'
                }
                else {
                    Start-SearchWorker
                }
            }
            'Search' { Start-SearchWorker }
            'Preview' { Start-PreviewWorker }
            'Report' { Start-ReportWorker }
            'Remove' { Remove-SearchWorker }
            'InstallModule' { Install-ModuleWorker }
            default { throw "Unknown job mode: $($Job.Mode)" }
        }
    }
    catch {
        $message = Get-ErrorText $_
        if ($Job -and $Job.Sync) {
            $Job.Sync.Phase = 'Failed'
            $Job.Sync.ErrorMessage = $message
            $Job.Sync.StatusText = $message
        }
        Write-JobLog $message 'ERROR'
        if ($_.ScriptStackTrace) { Write-JobLog $_.ScriptStackTrace 'ERROR' }
    }
    finally {
        if ($Job -and $Job.Sync) {
            $Job.Sync.Busy = $false
            $Job.Sync.Done = $true
        }
    }
}

function New-UiButton {
    param(
        [string]$Text,
        [int]$Width = 120,
        $BackColor,
        $ForeColor,
        [switch]$Outline
    )

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Width = $Width
    $button.Height = 34
    $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $button.Cursor = [System.Windows.Forms.Cursors]::Hand
    $button.UseVisualStyleBackColor = $false
    $button.Margin = New-Object System.Windows.Forms.Padding(4, 4, 4, 4)
    if ($Outline) {
        $button.FlatAppearance.BorderSize = 1
        $button.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(186, 195, 206)
        $BackColor = [System.Drawing.Color]::White
        $ForeColor = $script:ColorNavy
    }
    else {
        $button.FlatAppearance.BorderSize = 0
    }
    $button.BackColor = $BackColor
    $button.ForeColor = $ForeColor
    $button.Tag = @{ Back = $BackColor; Fore = $ForeColor }
    $button.Add_EnabledChanged({
        param($sender, $eventArgs)
        if ($sender.Enabled) {
            $sender.BackColor = $sender.Tag.Back
            $sender.ForeColor = $sender.Tag.Fore
        }
        else {
            $sender.BackColor = [System.Drawing.Color]::FromArgb(214, 218, 224)
            $sender.ForeColor = [System.Drawing.Color]::FromArgb(120, 126, 135)
        }
    })
    return $button
}

function New-UiTextBox {
    param([switch]$Multiline, [int]$Height = 28)
    $box = New-Object System.Windows.Forms.TextBox
    $box.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $box.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    if ($Multiline) {
        $box.Multiline = $true
        $box.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
        $box.Height = $Height
        $box.AcceptsReturn = $true
        $box.WordWrap = $true
    }
    return $box
}

function New-ResultGrid {
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = [System.Windows.Forms.DockStyle]::Fill
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToResizeRows = $false
    $grid.RowHeadersVisible = $false
    $grid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $grid.MultiSelect = $false
    $grid.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
    $grid.BackgroundColor = [System.Drawing.Color]::White
    $grid.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $grid.EnableHeadersVisualStyles = $false
    $grid.ColumnHeadersHeight = 32
    $grid.RowTemplate.Height = 26
    $grid.ColumnHeadersDefaultCellStyle.BackColor = $script:ColorNavy
    $grid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $grid.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $grid.DefaultCellStyle.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $grid.DefaultCellStyle.SelectionBackColor = $script:ColorAccent
    $grid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $grid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(236, 242, 248)
    $grid.ClipboardCopyMode = [System.Windows.Forms.DataGridViewClipboardCopyMode]::EnableWithAutoHeaderText
    return $grid
}

function Add-GridColumn {
    param($Grid, [string]$Name, [string]$Header, [int]$FillWeight, [type]$ValueType)
    $column = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $column.Name = $Name
    $column.HeaderText = $Header
    $column.FillWeight = $FillWeight
    $column.MinimumWidth = 70
    if ($ValueType) { $column.ValueType = $ValueType }
    [void]$Grid.Columns.Add($column)
}

function Ensure-Sync {
    if ($script:Sync) { return }
    $script:Sync = [hashtable]::Synchronized(@{
        LogQueue         = New-Object System.Collections.Concurrent.ConcurrentQueue[string]
        Phase            = 'Idle'
        StatusText       = 'Ready'
        Progress         = 0
        SearchStatus     = ''
        Items            = $null
        ErrorMessage     = $null
        Done             = $false
        CancelRequested  = $false
        Connected        = $false
        ConnectedUpn     = ''
        TimedOut         = $false
        Result           = $null
        Preview          = $null
        ReportNote       = ''
        Busy             = $false
        SearchCreated    = $false
        ActiveSearchName = ''
        ModuleVersion    = ''
        ExecutionSeconds = 0
        StopSent         = $false
    })
}

function Reset-CommandSignals {
    Ensure-Sync
    $script:Sync.Done = $false
    $script:Sync.CancelRequested = $false
    $script:Sync.ErrorMessage = $null
    $script:Sync.TimedOut = $false
    $script:Sync.StopSent = $false
    $script:Sync.Busy = $true
    $script:Sync.Phase = 'Starting'
    $script:Sync.Progress = 0
    $script:Sync.StatusText = 'Starting'
    $script:Sync.GraphUserCode = ''
    $script:Sync.GraphSignInUrl = ''
    $script:GraphCodeShown = $false
}

function Ensure-Runspace {
    $opened = $script:Runspace -and $script:Runspace.RunspaceStateInfo.State -eq [System.Management.Automation.Runspaces.RunspaceState]::Opened
    if ($opened -and $script:PsHost) { return }
    if ($script:PsHost) {
        try { $script:PsHost.Dispose() } catch { }
        $script:PsHost = $null
    }
    if ($script:Runspace) {
        try { $script:Runspace.Close() } catch { }
        try { $script:Runspace.Dispose() } catch { }
        $script:Runspace = $null
    }
    $script:Runspace = New-InvestigationRunspace
    $script:PsHost = [powershell]::Create()
    $script:PsHost.Runspace = $script:Runspace
}

function Append-LogLine {
    param([string]$Entry)
    if (-not $script:txtLog -or $script:txtLog.IsDisposed) { return }
    $color = [System.Drawing.Color]::FromArgb(190, 205, 220)
    if ($Entry -match '\[ERROR\]') { $color = [System.Drawing.Color]::FromArgb(255, 140, 130) }
    elseif ($Entry -match '\[WARNING\]') { $color = [System.Drawing.Color]::FromArgb(240, 190, 90) }
    elseif ($Entry -match '\[SUCCESS\]') { $color = [System.Drawing.Color]::FromArgb(120, 210, 150) }
    if ($script:txtLog.TextLength -gt 300000) {
        $script:txtLog.Select(0, 100000)
        $script:txtLog.SelectedText = ''
    }
    $script:txtLog.SelectionStart = $script:txtLog.TextLength
    $script:txtLog.SelectionLength = 0
    $script:txtLog.SelectionColor = $color
    $script:txtLog.AppendText($Entry + [Environment]::NewLine)
    $script:txtLog.ScrollToCaret()
}

function Add-UiLog {
    param([string]$Message, [string]$Level = 'INFO')
    $entry = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Append-LogLine $entry
    if ($script:CurrentLogFile -and -not $script:CommandRunning) {
        try { Add-Utf8Line -Path $script:CurrentLogFile -Line $entry } catch { }
    }
}

function Drain-LogQueue {
    if (-not $script:Sync -or -not $script:Sync.LogQueue) { return }
    $line = [string]$null
    $count = 0
    while ($count -lt 200 -and $script:Sync.LogQueue.TryDequeue([ref]$line)) {
        Append-LogLine $line
        $count++
    }
}

function Show-UiMessage {
    param([string]$Message, [string]$Title, [string]$Icon = 'Information')
    $iconValue = [System.Windows.Forms.MessageBoxIcon]::Information
    try { $iconValue = [System.Windows.Forms.MessageBoxIcon]::$Icon } catch { }
    $owner = $script:form
    if ($owner -and -not $owner.IsDisposed) {
        [void][System.Windows.Forms.MessageBox]::Show($owner, $Message, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, $iconValue)
    }
    else {
        [void][System.Windows.Forms.MessageBox]::Show($Message, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, $iconValue)
    }
}

function Update-Chrome {
    if (-not $script:btnStart) { return }
    $busy = [bool]$script:CommandRunning
    $connected = [bool]($script:Sync -and $script:Sync.Connected)
    $created = [bool]($script:Sync -and $script:Sync.SearchCreated)
    $previewable = $script:LastStatus -in @('Completed', 'PartiallySucceeded')
    $namedSearch = ($script:Sync -and $script:Sync.SearchCreated) -or $script:SearchNameDirty

    $script:btnConnect.Enabled = -not $busy
    $script:btnConnect.Text = if ($connected) { 'Disconnect' } else { 'Connect' }
    $script:btnStart.Enabled = (-not $busy) -and [bool]$script:FormValid
    $script:btnStop.Enabled = $busy
    $script:btnPreview.Enabled = (-not $busy) -and $connected -and $namedSearch -and ($previewable -or $script:SearchNameDirty)
    $script:btnReport.Enabled = (-not $busy) -and $connected -and $previewable
    $script:btnRemove.Enabled = (-not $busy) -and $connected -and $created
    $folderReady = $script:CurrentOutputFolder -and (Test-Path -LiteralPath $script:CurrentOutputFolder)
    $script:btnOpenFolder.Enabled = [bool]$folderReady
    $script:btnCopyQuery.Enabled = -not [string]::IsNullOrWhiteSpace($script:txtQuery.Text)
    $script:btnCopyName.Enabled = $script:txtSearchName -and -not [string]::IsNullOrWhiteSpace($script:txtSearchName.Text)
    if ($script:btnInstall) { $script:btnInstall.Enabled = (-not $busy) -and (-not $connected) }
}

function Update-ProgressChrome {
    if (-not $script:lblStatus) { return }
    $phase = [string]$script:Sync.Phase
    $text = [string]$script:Sync.StatusText
    if ([string]::IsNullOrWhiteSpace($text)) { $text = 'Ready' }
    $script:lblStatus.Text = $text

    $progressValue = 0
    try { $progressValue = [int]$script:Sync.Progress } catch { $progressValue = 0 }
    if ($progressValue -lt 0) { $progressValue = 0 }
    if ($progressValue -gt 100) { $progressValue = 100 }
    $marquee = $script:CommandRunning -and $progressValue -le 0 -and ($phase -in @('Starting', 'Connecting', 'Creating', 'Running', 'Installing'))
    if ($marquee) {
        if ($script:progress.Style -ne [System.Windows.Forms.ProgressBarStyle]::Marquee) {
            $script:progress.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
        }
    }
    else {
        if ($script:progress.Style -ne [System.Windows.Forms.ProgressBarStyle]::Continuous) {
            $script:progress.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
        }
        if ($script:progress.Value -ne $progressValue) { $script:progress.Value = $progressValue }
    }

    $color = $script:ColorNavy
    if ($phase -eq 'Failed') { $color = $script:ColorDanger }
    elseif ($phase -in @('Completed', 'Connected', 'PreviewReady', 'ReportReady', 'Installed')) { $color = $script:ColorSuccess }
    elseif ($phase -in @('TimedOut', 'Cancelled', 'Finished', 'Removed')) { $color = $script:ColorWarning }
    $script:lblStatus.ForeColor = $color

    if ($script:CurrentMode -in @('Search', 'ConnectAndSearch')) {
        if ($script:SummaryValues -and $script:SummaryValues.Contains('Status')) {
            $status = [string]$script:Sync.SearchStatus
            if (-not [string]::IsNullOrWhiteSpace($status)) { $script:SummaryValues['Status'].Text = $status }
        }
        if ($script:SummaryValues -and $null -ne $script:Sync.Items -and "$($script:Sync.Items)" -ne '') {
            $script:SummaryValues['Items'].Text = [string]$script:Sync.Items
        }
    }
}

function Get-FormRequest {
    $scope = if ($script:radAll.Checked) { 'All' } else { 'Sender' }
    return Test-InvestigationRequest `
        -AdminUpn $script:txtAdmin.Text `
        -Sender $script:txtSender.Text `
        -DomainText $script:txtDomains.Text `
        -CaseName $script:txtCase.Text `
        -Scope $scope `
        -AllowNotFound $script:chkInactive.Checked `
        -NotifyAdmin $script:chkNotify.Checked `
        -Start $script:dtStart.Value `
        -End $script:dtEnd.Value `
        -AdditionalQuery $script:txtExtra.Text `
        -SearchName $script:txtSearchName.Text `
        -OutputFolder $script:txtOutput.Text `
        -TimeoutMinutes ([int]$script:numTimeout.Value) `
        -Description $script:txtDescription.Text
}

function Update-InactiveCaption {
    if (-not $script:chkInactive) { return }
    if ($script:radAll.Checked) {
        $script:chkInactive.Text = 'Include inactive and other non-user mailboxes'
    }
    else {
        $script:chkInactive.Text = 'Sender mailbox is inactive'
    }
}

function Update-QueryPreview {
    if ($script:InPreview) { return }
    if (-not $script:txtSender) { return }
    $script:InPreview = $true
    try {
        if (-not $script:SearchNameDirty) {
            $generatedName = New-InvestigationSearchName -Sender $script:txtSender.Text -Timestamp $script:SessionStamp
            if ($script:txtSearchName.Text -ne $generatedName) {
                $script:UpdatingName = $true
                $script:txtSearchName.Text = $generatedName
                $script:UpdatingName = $false
            }
        }

        $request = Get-FormRequest
        if (-not $script:DescriptionDirty -and $request.Description -and $script:txtDescription.Text -ne $request.Description) {
            $script:UpdatingDescription = $true
            $script:txtDescription.Text = $request.Description
            $script:UpdatingDescription = $false
            $request = Get-FormRequest
        }

        $script:LastRequest = $request
        $script:FormValid = [bool]$request.IsValid
        if ($request.IsValid) {
            $script:txtQuery.Text = [string]$request.Query
            $script:lblValidation.Text = 'Ready to search. The end date is inclusive.'
            $script:lblValidation.ForeColor = $script:ColorSuccess
        }
        else {
            $script:txtQuery.Text = ''
            $message = 'Check the form.'
            if ($request.Errors -and $request.Errors.Count -gt 0) { $message = $request.Errors -join ' ' }
            $script:lblValidation.Text = $message
            $script:lblValidation.ForeColor = $script:ColorDanger
        }
    }
    catch {
        $script:FormValid = $false
        if ($script:lblValidation) {
            $script:lblValidation.Text = $_.Exception.Message
            $script:lblValidation.ForeColor = $script:ColorDanger
        }
    }
    finally {
        $script:InPreview = $false
        Update-Chrome
    }
}

function Update-ModuleStatus {
    param([switch]$Refresh)
    $report = Resolve-ExchangeOnlineModule -Refresh:$Refresh
    $script:ModuleReport = $report
    if ($report.Suitable) {
        $script:ModulePath = [string]$report.Suitable.Path
        $script:lblModule.Text = "ExchangeOnlineManagement $($report.Suitable.Version) is ready."
        $script:lblModule.ForeColor = $script:ColorSuccess
        $script:btnInstall.Visible = $false
    }
    else {
        $script:ModulePath = $null
        $found = if ($report.Newest) { " Installed version: $($report.Newest.Version)." } else { ' It is not installed.' }
        $script:lblModule.Text = "ExchangeOnlineManagement 3.9.0 or later is required.$found"
        $script:lblModule.ForeColor = $script:ColorDanger
        $script:btnInstall.Visible = $true
    }
}

function Apply-SavedSettings {
    $saved = Read-InvestigationSettings
    if (-not $saved) { return }
    if ($saved.AdminUpn) { $script:txtAdmin.Text = [string]$saved.AdminUpn }
    if ($saved.Sender) { $script:txtSender.Text = [string]$saved.Sender }
    if ($saved.Domains) { $script:txtDomains.Text = [string]$saved.Domains }
    if ($saved.PSObject.Properties['CaseName']) { $script:txtCase.Text = [string]$saved.CaseName }
    if ([string]$saved.Scope -eq 'All') { $script:radAll.Checked = $true } else { $script:radSender.Checked = $true }
    if ($saved.PSObject.Properties['AllowNotFound']) { $script:chkInactive.Checked = [bool]$saved.AllowNotFound }
    if ($saved.PSObject.Properties['NotifyAdmin']) { $script:chkNotify.Checked = [bool]$saved.NotifyAdmin }
    if ($saved.OutputFolder) { $script:txtOutput.Text = [string]$saved.OutputFolder }
    $timeout = 120
    try { $timeout = [int]$saved.TimeoutMinutes } catch { $timeout = 120 }
    if ($timeout -lt 1) { $timeout = 1 }
    if ($timeout -gt 720) { $timeout = 720 }
    $script:numTimeout.Value = $timeout
    if ($saved.AdditionalQuery) { $script:txtExtra.Text = [string]$saved.AdditionalQuery }
    if ($saved.StartDate) { $script:dtStart.Value = ConvertTo-SettingDate ([string]$saved.StartDate) $script:dtStart.Value }
    if ($saved.EndDate) { $script:dtEnd.Value = ConvertTo-SettingDate ([string]$saved.EndDate) $script:dtEnd.Value }
}

function Save-SettingsFromUi {
    if (-not $script:txtAdmin) { return }
    $scope = if ($script:radAll.Checked) { 'All' } else { 'Sender' }
    Save-InvestigationSettings @{
        AdminUpn        = $script:txtAdmin.Text
        Sender          = $script:txtSender.Text
        Domains         = $script:txtDomains.Text
        CaseName        = $script:txtCase.Text
        Scope           = $scope
        AllowNotFound   = [bool]$script:chkInactive.Checked
        NotifyAdmin     = [bool]$script:chkNotify.Checked
        OutputFolder    = $script:txtOutput.Text
        TimeoutMinutes  = [int]$script:numTimeout.Value
        AdditionalQuery = $script:txtExtra.Text
        StartDate       = $script:dtStart.Value.ToString('yyyy-MM-dd')
        EndDate         = $script:dtEnd.Value.ToString('yyyy-MM-dd')
    }
}

function Clear-ResultView {
    if ($script:gridLocations) { $script:gridLocations.Rows.Clear() }
    if ($script:gridPreview) { $script:gridPreview.Rows.Clear() }
    if ($script:lblEmptyLocations) { $script:lblEmptyLocations.Visible = $true }
    if ($script:lblEmptyPreview) { $script:lblEmptyPreview.Visible = $true }
    if (-not $script:SummaryValues) { return }
    foreach ($key in @('Status', 'Items', 'Size', 'Unindexed', 'Duration', 'Scope', 'Search', 'Output')) {
        if ($script:SummaryValues.Contains($key)) { $script:SummaryValues[$key].Text = '-' }
    }
}

function Fill-LocationGrid {
    param($Locations)
    if (-not $script:gridLocations) { return }
    $script:gridLocations.Rows.Clear()
    foreach ($row in $Locations) {
        if ($null -eq $row) { continue }
        [void]$script:gridLocations.Rows.Add([string]$row.Location, [int64]$row.ItemCount, [string]$row.SizeDisplay, [int64]$row.SizeBytes)
    }
    $script:lblEmptyLocations.Visible = ($script:gridLocations.Rows.Count -eq 0)
}

function Fill-PreviewGrid {
    param($Items)
    if (-not $script:gridPreview) { return }
    $script:gridPreview.Rows.Clear()
    foreach ($row in $Items) {
        if ($null -eq $row) { continue }
        [void]$script:gridPreview.Rows.Add([string]$row.Received, [string]$row.Sender, [string]$row.Subject, [string]$row.Type, [string]$row.Size, [string]$row.Location)
    }
    $script:lblEmptyPreview.Visible = ($script:gridPreview.Rows.Count -eq 0)
}

function Update-ResultsFromSync {
    if (-not $script:Sync -or -not $script:SummaryValues) { return }
    if ($script:Sync.SearchStatus) {
        $script:LastStatus = [string]$script:Sync.SearchStatus
        $script:SummaryValues['Status'].Text = $script:LastStatus
    }
    if ($script:Sync.ActiveSearchName) {
        $script:ActiveSearchName = [string]$script:Sync.ActiveSearchName
        $script:SummaryValues['Search'].Text = $script:ActiveSearchName
    }
    $result = $script:Sync.Result
    if ($result -and $result.Summary) {
        $summary = $result.Summary
        $script:SummaryValues['Status'].Text = $(if ($summary.SearchStatus) { [string]$summary.SearchStatus } else { '-' })
        $script:SummaryValues['Items'].Text = $(if ($summary.MatchingItems) { [string]$summary.MatchingItems } else { '0' })
        $script:SummaryValues['Size'].Text = $(if ($summary.TotalSize) { [string]$summary.TotalSize } else { '-' })
        $script:SummaryValues['Unindexed'].Text = $(if ("$($summary.UnindexedItems)" -ne '') { [string]$summary.UnindexedItems } else { '0' })
        $script:SummaryValues['Duration'].Text = $(if ($summary.ExecutionTime) { [string]$summary.ExecutionTime } else { '-' })
        $script:SummaryValues['Scope'].Text = $(if ($summary.SearchScope) { [string]$summary.SearchScope } else { '-' })
        $script:SummaryValues['Search'].Text = [string]$summary.SearchName
        $script:SummaryValues['Output'].Text = [string]$summary.OutputFolder
        if ($script:toolTip) { $script:toolTip.SetToolTip($script:SummaryValues['Output'], [string]$summary.OutputFolder) }
        $script:LastStatus = [string]$summary.SearchStatus
        $script:ActiveSearchName = [string]$summary.SearchName
        Fill-LocationGrid $result.Locations
    }
    if ($script:Sync.Preview) { Fill-PreviewGrid $script:Sync.Preview }
}

function Show-SearchFinishedDialog {
    $phase = [string]$script:Sync.Phase
    $summary = $null
    if ($script:Sync.Result) { $summary = $script:Sync.Result.Summary }
    $name = $script:ActiveSearchName
    $status = $script:LastStatus
    $items = if ($summary) { $summary.MatchingItems } else { $script:Sync.Items }
    $size = if ($summary -and $summary.TotalSize) { $summary.TotalSize } else { '-' }
    $folder = $script:CurrentOutputFolder
    $icon = 'Information'
    $title = 'Search finished'
    $lead = "Search $name finished with status $status."
    if ($phase -eq 'TimedOut') {
        $icon = 'Warning'
        $title = 'Search still running'
        $lead = "Monitoring timed out. The search may still be running in Purview as $name."
    }
    elseif ($phase -eq 'Cancelled') {
        $icon = 'Warning'
        $title = 'Search stopped'
        $lead = "Stop was requested for $name. Status: $status."
    }
    elseif ($status -and $status -ne 'Completed') {
        $icon = 'Warning'
        $title = 'Search needs review'
    }

    $findingsLine = ''
    if ($script:Sync.FindingsPath) {
        $rowCount = 0
        try { $rowCount = [int]$script:Sync.FindingsCount } catch { $rowCount = 0 }
        $findingsLine = "Findings spreadsheet: MessageFindings.xlsx ($rowCount subject lines)`r`n$($script:Sync.FindingsPath)"
        $reportedCount = 0
        $hasReported = $false
        if ($null -ne $script:Sync.FindingsReported) {
            try {
                $reportedCount = [int]$script:Sync.FindingsReported
                $hasReported = $true
            }
            catch { $hasReported = $false }
        }
        if ($hasReported -and $reportedCount -gt $rowCount) {
            $findingsLine += "`r`nThe search reported $reportedCount matches. Purview did not return a subject for every match."
        }
    }
    elseif ($script:Sync.FindingsError) {
        $findingsLine = "Findings spreadsheet was not created: $($script:Sync.FindingsError)"
    }

    $text = @"
$lead

Matching items: $items
Size: $size
Reports: $folder
$findingsLine

MessageFindings.xlsx has one row per message, including the subject line. Message bodies are not downloaded.
"@
    if ($script:Sync.ErrorMessage) { $text += "`r`n`r`n$($script:Sync.ErrorMessage)" }
    Show-UiMessage $text $title $icon
    if ($script:Sync.FindingsCount -gt 0 -and $script:tabs -and $script:tabPreview) {
        $script:tabs.SelectedTab = $script:tabPreview
    }
    elseif ($script:tabs -and $script:tabStats) {
        $script:tabs.SelectedTab = $script:tabStats
    }
}

function Show-CompletionDialog {
    $phase = [string]$script:Sync.Phase
    $mode = [string]$script:CurrentMode
    $errorText = [string]$script:Sync.ErrorMessage
    if ($phase -eq 'Failed') {
        $message = if ($errorText) { $errorText } else { 'The operation failed.' }
        Show-UiMessage $message 'Purview investigation' 'Error'
        return
    }

    switch ($mode) {
        'ConnectAndSearch' { Show-SearchFinishedDialog }
        'Search' { Show-SearchFinishedDialog }
        'Preview' {
            if ($phase -eq 'PreviewReady') {
                if ($script:tabs -and $script:tabPreview) { $script:tabs.SelectedTab = $script:tabPreview }
                $rowCount = 0
                try { $rowCount = [int]$script:Sync.FindingsCount } catch { $rowCount = 0 }
                $path = [string]$script:Sync.FindingsPath
                if ($rowCount -le 0) {
                    Show-UiMessage "The findings request finished, but no subject lines were recognized. The raw result was saved when an output folder was available.`r`n`r`n$path" 'Findings spreadsheet' 'Information'
                }
                else {
                    Show-UiMessage "MessageFindings.xlsx lists $rowCount messages, including each subject line.`r`n`r`n$path" 'Findings spreadsheet' 'Information'
                }
            }
            elseif ($phase -eq 'Cancelled') {
                Show-UiMessage 'Stopped waiting for the preview. It may still be running in Purview.' 'Preview' 'Warning'
            }
        }
        'Report' {
            if ($phase -eq 'ReportReady') {
                $note = [string]$script:Sync.ReportNote
                if ($note.Length -gt 1500) { $note = $note.Substring(0, 1500) + '...' }
                Show-UiMessage "Statistics report finished.`r`n`r`n$note" 'Statistics report' 'Information'
            }
        }
        'Remove' {
            if ($phase -eq 'Removed') {
                Show-UiMessage 'The search definition was removed. Mailbox messages were not modified.' 'Search removed' 'Information'
            }
        }
        'InstallModule' {
            if ($phase -eq 'Installed') {
                Update-ModuleStatus -Refresh
                Show-UiMessage 'ExchangeOnlineManagement was installed for the current user. You can connect now.' 'Module installed' 'Information'
            }
        }
    }
}

function Complete-CurrentCommand {
    $invocationError = $null
    try {
        if ($script:AsyncHandle) { [void]$script:PsHost.EndInvoke($script:AsyncHandle) }
    }
    catch {
        $invocationError = $_.Exception.Message
    }

    $streamErrors = New-Object System.Collections.Generic.List[string]
    if ($script:PsHost) {
        foreach ($err in $script:PsHost.Streams.Error) {
            if ($err -and $err.Exception -and $err.Exception.Message) { $streamErrors.Add([string]$err.Exception.Message) }
        }
        try { $script:PsHost.Commands.Clear() } catch { }
        try { $script:PsHost.Streams.ClearStreams() } catch { }
    }
    $script:AsyncHandle = $null
    Drain-LogQueue
    if ($invocationError -and -not $script:Sync.ErrorMessage) {
        $script:Sync.ErrorMessage = $invocationError
        $script:Sync.Phase = 'Failed'
        Add-UiLog $invocationError 'ERROR'
    }
    foreach ($streamMessage in $streamErrors) {
        if ($streamMessage -and $streamMessage -ne [string]$script:Sync.ErrorMessage) { Add-UiLog $streamMessage 'ERROR' }
    }
    Update-ResultsFromSync
    Update-ProgressChrome
    Update-Chrome
    Show-CompletionDialog
    Update-Chrome
}

function Update-InvestigationUi {
    if ($script:InTimer) { return }
    $script:InTimer = $true
    try {
        Drain-LogQueue
        Update-ProgressChrome
        if ($script:Sync -and $script:Sync.GraphUserCode -and -not $script:GraphCodeShown) {
            $script:GraphCodeShown = $true
            $code = [string]$script:Sync.GraphUserCode
            $url = [string]$script:Sync.GraphSignInUrl
            if ([string]::IsNullOrWhiteSpace($url)) { $url = 'https://microsoft.com/devicelogin' }
            try { [System.Windows.Forms.Clipboard]::SetText($code) } catch { }
            Show-UiMessage "Microsoft 365 no longer returns message subjects from the old preview command.`r`n`r`nSign in once so the tool can download an item report. Message files are not included and no hold is placed.`r`n`r`nOpen $url`r`nEnter this code: $code`r`n`r`nThe code was copied to the clipboard. It is also in the activity log." 'Sign in for the findings report' 'Information'
        }
        if ($script:CommandRunning -and $script:AsyncHandle -and $script:AsyncHandle.IsCompleted) {
            $script:CommandRunning = $false
            Complete-CurrentCommand
        }
    }
    catch {
        try { Add-UiLog $_.Exception.Message 'ERROR' } catch { }
    }
    finally {
        $script:InTimer = $false
    }
}

function Start-InvestigationCommand {
    param([hashtable]$Job)
    if ($script:CommandRunning) { return }
    Ensure-Runspace
    Reset-CommandSignals
    $script:CurrentMode = [string]$Job.Mode
    $script:CommandRunning = $true
    Update-Chrome
    $script:PsHost.Commands.Clear()
    $script:PsHost.Streams.ClearStreams()
    [void]$script:PsHost.AddCommand('Invoke-PurviewSearchJob').AddParameter('Job', $Job)
    $script:AsyncHandle = $script:PsHost.BeginInvoke()
}

function Connect-FromUi {
    if ($script:CommandRunning) { return }
    Ensure-Sync
    if ($script:Sync.Connected) {
        $answer = [System.Windows.Forms.MessageBox]::Show($script:form, 'Disconnect from Purview?', 'Disconnect', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        Start-InvestigationCommand @{
            Mode     = 'Disconnect'
            Sync     = $script:Sync
            LogFile  = $script:CurrentLogFile
            AdminUPN = $script:txtAdmin.Text.Trim()
        }
        return
    }
    if (-not (Test-EmailAddress $script:txtAdmin.Text)) {
        Show-UiMessage 'Enter a valid administrative UPN before connecting.' 'Administrator' 'Warning'
        return
    }
    Update-ModuleStatus
    if (-not $script:ModulePath) {
        Show-UiMessage 'Install ExchangeOnlineManagement 3.9.0 or later, then connect.' 'Module required' 'Warning'
        return
    }
    Start-InvestigationCommand @{
        Mode       = 'Connect'
        Sync       = $script:Sync
        LogFile    = $script:CurrentLogFile
        ModulePath = $script:ModulePath
        AdminUPN   = $script:txtAdmin.Text.Trim()
    }
}

function Show-InvestigationConfirm {
    param($Request)
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'Confirm compliance search'
    $dialog.Size = New-Object System.Drawing.Size(700, 560)
    $dialog.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
    $dialog.MinimizeBox = $false
    $dialog.MaximizeBox = $false
    $dialog.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $dialog.BackColor = $script:ColorPage

    $summary = New-Object System.Text.StringBuilder
    [void]$summary.AppendLine('This creates a compliance search estimate.')
    [void]$summary.AppendLine('It does not delete, move, or modify messages, and it does not download message bodies.')
    [void]$summary.AppendLine('If messages match, a second sign-in collects the subject lines. No hold is placed.')
    [void]$summary.AppendLine()
    [void]$summary.AppendLine("Search name : $($Request.SearchName)")
    [void]$summary.AppendLine("Sender      : $($Request.Sender)")
    [void]$summary.AppendLine("Domains     : $($Request.Domains -join ', ')")
    [void]$summary.AppendLine("Dates       : $($Request.Start.ToString('yyyy-MM-dd')) through $($Request.End.ToString('yyyy-MM-dd')) (end date is inclusive)")
    [void]$summary.AppendLine("Scope       : $($Request.Scope)")
    [void]$summary.AppendLine("Location    : $($Request.ExchangeLocation)")
    [void]$summary.AppendLine("Case        : $(if ($Request.CaseName) { $Request.CaseName } else { '(none)' })")
    [void]$summary.AppendLine("Output      : $($Request.OutputFolder)")
    [void]$summary.AppendLine()
    [void]$summary.AppendLine('KeyQL:')
    [void]$summary.AppendLine($Request.Query)
    if ($Request.Scope -eq 'All') {
        [void]$summary.AppendLine()
        [void]$summary.AppendLine('All mailboxes searches every mailbox you can access and can take a long time.')
    }
    if (-not $script:Sync.Connected) {
        [void]$summary.AppendLine()
        [void]$summary.AppendLine('A Microsoft sign-in window will open. Check the taskbar if you do not see it.')
    }

    $details = New-Object System.Windows.Forms.TextBox
    $details.Multiline = $true
    $details.ReadOnly = $true
    $details.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
    $details.Font = New-Object System.Drawing.Font('Consolas', 9)
    $details.Dock = [System.Windows.Forms.DockStyle]::Fill
    $details.Text = $summary.ToString()
    $details.BackColor = [System.Drawing.Color]::White

    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttons.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $buttons.Height = 52
    $buttons.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
    $buttons.Padding = New-Object System.Windows.Forms.Padding(8)
    $go = New-UiButton 'Start search' 140 $script:ColorAccent ([System.Drawing.Color]::White)
    $go.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $cancel = New-UiButton 'Cancel' 110 ([System.Drawing.Color]::White) $script:ColorNavy -Outline
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $buttons.Controls.Add($go)
    $buttons.Controls.Add($cancel)
    $dialog.AcceptButton = $go
    $dialog.CancelButton = $cancel
    $dialog.Controls.Add($details)
    $dialog.Controls.Add($buttons)

    $accepted = $dialog.ShowDialog($script:form) -eq [System.Windows.Forms.DialogResult]::OK
    $dialog.Dispose()
    return $accepted
}

function Start-SearchFromUi {
    if ($script:CommandRunning) { return }
    Ensure-Sync
    if (-not $script:SearchNameDirty) {
        $script:SessionStamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
    }
    Update-QueryPreview
    $request = $script:LastRequest
    if (-not $request -or -not $request.IsValid) {
        Show-UiMessage $script:lblValidation.Text 'Check the form' 'Warning'
        return
    }
    if (-not $script:Sync.Connected) {
        Update-ModuleStatus
        if (-not $script:ModulePath) {
            Show-UiMessage 'Install ExchangeOnlineManagement 3.9.0 or later before starting a search.' 'Module required' 'Warning'
            return
        }
    }
    if (-not (Show-InvestigationConfirm $request)) {
        Add-UiLog 'Search cancelled.' 'WARNING'
        return
    }

    try {
        $folder = New-InvestigationOutputFolder -Root $request.OutputFolder
    }
    catch {
        Show-UiMessage $_.Exception.Message 'Output folder' 'Error'
        return
    }

    $configLines = @(
        "Search name: $($request.SearchName)"
        "Administrator: $($request.AdminUpn)"
        "Sender: $($request.Sender)"
        "Domains: $($request.Domains -join ', ')"
        "Start: $($request.Start.ToString('yyyy-MM-dd'))"
        "End: $($request.End.ToString('yyyy-MM-dd')) (inclusive)"
        "Scope: $($request.Scope)"
        "Exchange location: $($request.ExchangeLocation)"
        "Case: $($request.CaseName)"
        'Query:'
        $request.Query
    )
    Write-Utf8File -Path (Join-Path $folder 'SearchConfiguration.txt') -Content (($configLines -join [Environment]::NewLine) + [Environment]::NewLine)

    $script:CurrentOutputFolder = $folder
    $script:CurrentLogFile = Join-Path $folder 'Investigation.log'
    $script:ActiveSearchName = $request.SearchName
    $script:Sync.ActiveSearchName = $request.SearchName
    $script:Sync.SearchCreated = $false
    $script:Sync.Result = $null
    $script:Sync.Preview = $null
    $script:LastStatus = ''
    Clear-ResultView
    $script:SummaryValues['Search'].Text = $request.SearchName
    $script:SummaryValues['Scope'].Text = $request.Scope
    $script:SummaryValues['Output'].Text = $folder
    Add-UiLog "Investigation folder: $folder"
    Add-UiLog "Search name: $($request.SearchName)"
    Add-UiLog "Query: $($request.Query)"
    try { Save-SettingsFromUi } catch { }

    $context = @{
        SearchName       = $request.SearchName
        CaseName         = $request.CaseName
        Administrator    = $request.AdminUpn
        ConnectedAs      = [string]$script:Sync.ConnectedUpn
        Sender           = $request.Sender
        RecipientDomains = ($request.Domains -join '; ')
        StartDate        = $request.Start.ToString('yyyy-MM-dd')
        EndDate          = $request.End.ToString('yyyy-MM-dd')
        SearchScope      = $request.Scope
        ExchangeLocation = $request.ExchangeLocation
        SearchQuery      = $request.Query
        ExecutionTime    = ''
        TimedOut         = $false
        ModuleVersion    = [string]$script:Sync.ModuleVersion
    }
    Start-InvestigationCommand @{
        Mode             = $(if ($script:Sync.Connected) { 'Search' } else { 'ConnectAndSearch' })
        Sync             = $script:Sync
        LogFile          = $script:CurrentLogFile
        ModulePath       = $script:ModulePath
        AdminUPN         = $request.AdminUpn
        SearchName       = $request.SearchName
        ExchangeLocation = $request.ExchangeLocation
        AllowNotFound    = [bool]$request.AllowNotFound
        Query            = $request.Query
        CaseName         = $request.CaseName
        Description      = $request.Description
        NotifyAdmin      = [bool]$request.NotifyAdmin
        TimeoutMinutes   = $request.TimeoutMinutes
        OutputFolder     = $folder
        Context          = $context
    }
}

function Start-PreviewFromUi {
    if ($script:CommandRunning -or -not $script:Sync.Connected) { return }
    $searchName = $script:txtSearchName.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($searchName)) { $searchName = $script:ActiveSearchName }
    if ([string]::IsNullOrWhiteSpace($searchName)) { return }
    if (-not $script:CurrentOutputFolder -or -not (Test-Path -LiteralPath $script:CurrentOutputFolder)) {
        try {
            $script:CurrentOutputFolder = New-InvestigationOutputFolder -Root $script:txtOutput.Text.Trim()
            $script:CurrentLogFile = Join-Path $script:CurrentOutputFolder 'Investigation.log'
        }
        catch {
            Show-UiMessage $_.Exception.Message 'Output folder' 'Error'
            return
        }
    }
    $script:ActiveSearchName = $searchName
    $script:Sync.ActiveSearchName = $searchName
    $reported = -1
    $sameSearch = $script:Sync.Result -and $script:Sync.Result.Summary -and [string]$script:Sync.Result.Summary.SearchName -eq $searchName
    if ($sameSearch -and -not [string]::IsNullOrWhiteSpace([string]$script:Sync.Result.Summary.MatchingItems)) {
        try { $reported = [int]$script:Sync.Result.Summary.MatchingItems } catch { $reported = -1 }
    }
    elseif ($sameSearch -and $null -ne $script:Sync.Items -and -not [string]::IsNullOrWhiteSpace([string]$script:Sync.Items)) {
        try { $reported = [int]$script:Sync.Items } catch { $reported = -1 }
    }
    Start-InvestigationCommand @{
        Mode              = 'Preview'
        Sync              = $script:Sync
        LogFile           = $script:CurrentLogFile
        SearchName        = $script:ActiveSearchName
        OutputFolder      = $script:CurrentOutputFolder
        TimeoutMinutes    = [int]$script:numTimeout.Value
        ReportedItemCount = $reported
        CaseName          = $script:txtCase.Text.Trim()
    }
}

function Start-ReportFromUi {
    if ($script:CommandRunning -or -not $script:Sync.Connected) { return }
    if ([string]::IsNullOrWhiteSpace($script:ActiveSearchName)) { return }
    Start-InvestigationCommand @{
        Mode           = 'Report'
        Sync           = $script:Sync
        LogFile        = $script:CurrentLogFile
        SearchName     = $script:ActiveSearchName
        OutputFolder   = $script:CurrentOutputFolder
        TimeoutMinutes = [int]$script:numTimeout.Value
    }
}

function Remove-SearchFromUi {
    if ($script:CommandRunning -or -not $script:Sync.Connected) { return }
    if ([string]::IsNullOrWhiteSpace($script:ActiveSearchName)) { return }
    $answer = [System.Windows.Forms.MessageBox]::Show(
        $script:form,
        "Remove the search definition '$($script:ActiveSearchName)' from Purview?`r`n`r`nMailbox messages are not deleted or modified.",
        'Remove search definition',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    Start-InvestigationCommand @{
        Mode         = 'Remove'
        Sync         = $script:Sync
        LogFile      = $script:CurrentLogFile
        SearchName   = $script:ActiveSearchName
        OutputFolder = $script:CurrentOutputFolder
    }
}

function Install-ModuleFromUi {
    if ($script:CommandRunning) { return }
    $answer = [System.Windows.Forms.MessageBox]::Show(
        $script:form,
        'Install ExchangeOnlineManagement 3.9.0 or later for the current user from the PowerShell Gallery?',
        'Install module',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question)
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    Ensure-Sync
    Start-InvestigationCommand @{
        Mode    = 'InstallModule'
        Sync    = $script:Sync
        LogFile = $script:CurrentLogFile
    }
}

function Copy-UiText {
    param([string]$Text, [string]$Label)
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    [System.Windows.Forms.Clipboard]::SetText($Text)
    Add-UiLog "$Label copied to the clipboard."
}

function Open-OutputFolder {
    $path = $script:CurrentOutputFolder
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { $path = $script:txtOutput.Text }
    if ($path -and (Test-Path -LiteralPath $path)) { Invoke-Item -LiteralPath $path }
}

function Open-PurviewPortal {
    Start-Process 'https://purview.microsoft.com/ediscovery'
}

function Export-ActivityLog {
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = 'Log files (*.log)|*.log|Text files (*.txt)|*.txt'
    $dialog.FileName = 'PurviewInvestigation_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log'
    if ($dialog.ShowDialog($script:form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
    if ($script:CurrentLogFile -and (Test-Path -LiteralPath $script:CurrentLogFile)) {
        [System.IO.File]::Copy($script:CurrentLogFile, $dialog.FileName, $true)
    }
    else {
        Write-Utf8File -Path $dialog.FileName -Content $script:txtLog.Text
    }
    Add-UiLog "Log exported to $($dialog.FileName)" 'SUCCESS'
}

function Browse-OutputFolder {
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Choose where investigation reports are saved'
    $dialog.ShowNewFolderButton = $true
    if ($script:txtOutput.Text -and (Test-Path -LiteralPath $script:txtOutput.Text)) {
        $dialog.SelectedPath = $script:txtOutput.Text
    }
    if ($dialog.ShowDialog($script:form) -eq [System.Windows.Forms.DialogResult]::OK) {
        $script:txtOutput.Text = $dialog.SelectedPath
    }
}

function Show-ToolHelp {
    $text = @"
Purview Email Investigation creates a read-only compliance search for mail sent by one user to the domains you list.

It does not delete, move, or modify messages, and it does not download message bodies.

Requirements
- Windows PowerShell 5.1 or PowerShell 7 on Windows
- ExchangeOnlineManagement 3.9.0 or later
- An account with eDiscovery or Compliance Search permission
- Connect-IPPSSession -EnableSearchOnlySession, which this tool uses

The end date is inclusive. KeyQL uses the next day as an exclusive bound so mail sent later that day is included.

Sender mailbox searches that person's mailbox, including Sent Items. All mailboxes searches every mailbox the account can access and can take much longer.

When messages match, MessageFindings.xlsx lists each one with its subject line. Message bodies are not downloaded.

Microsoft 365 no longer accepts the old preview command. The subject list comes from a Purview item report. That step asks for a second sign-in at https://microsoft.com/devicelogin. Use an eDiscovery Manager or eDiscovery Administrator account. No hold is placed.
"@
    Show-UiMessage $text "Purview Email Investigation v$($script:AppVersion)" 'Information'
}

function Stop-FromUi {
    if (-not $script:CommandRunning -or -not $script:Sync) { return }
    $script:Sync.CancelRequested = $true
    $script:Sync.StatusText = 'Stop requested. Waiting for the service to acknowledge it.'
    Add-UiLog 'Stop requested.' 'WARNING'
}

function Close-InvestigationSession {
    if ($script:SessionClosed) { return }
    $script:SessionClosed = $true
    try {
        if ($script:UiTimer) {
            $script:UiTimer.Stop()
            $script:UiTimer.Dispose()
            $script:UiTimer = $null
        }
    }
    catch { }
    try {
        if ($script:PsHost) {
            if ($script:CommandRunning) {
                try { $script:PsHost.Stop() } catch { }
            }
            elseif ($script:Sync -and $script:Sync.Connected) {
                try {
                    $script:PsHost.Commands.Clear()
                    [void]$script:PsHost.AddScript('Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue')
                    [void]$script:PsHost.Invoke()
                }
                catch { }
            }
            $script:PsHost.Dispose()
            $script:PsHost = $null
        }
    }
    catch { }
    try {
        if ($script:Runspace) {
            $script:Runspace.Close()
            $script:Runspace.Dispose()
            $script:Runspace = $null
        }
    }
    catch { }
}

function Start-PurviewInvestigationGui {
    if ($env:OS -ne 'Windows_NT') {
        throw 'Purview Email Investigation requires Windows.'
    }
    if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        if ($env:PURVIEW_TOOL_STA_RELAUNCH -eq '1') {
            throw 'The GUI could not be started in STA mode.'
        }
        if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
            throw 'Save the script and run it as a file so the GUI can relaunch in STA mode.'
        }
        $hostPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (-not (Test-Path -LiteralPath $hostPath)) {
            $hostPath = [Diagnostics.Process]::GetCurrentProcess().Path
        }
        $env:PURVIEW_TOOL_STA_RELAUNCH = '1'
        Start-Process -FilePath $hostPath -ArgumentList @(
            '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath
        ) | Out-Null
        return
    }

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch { }
    try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }

    $script:ColorNavy = [System.Drawing.Color]::FromArgb(24, 42, 68)
    $script:ColorPage = [System.Drawing.Color]::FromArgb(245, 247, 250)
    $script:ColorAccent = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $script:ColorSuccess = [System.Drawing.Color]::FromArgb(16, 124, 65)
    $script:ColorDanger = [System.Drawing.Color]::FromArgb(196, 43, 28)
    $script:ColorWarning = [System.Drawing.Color]::FromArgb(140, 90, 0)
    $script:ColorMuted = [System.Drawing.Color]::FromArgb(96, 110, 128)
    $script:ColorQuery = [System.Drawing.Color]::FromArgb(236, 242, 248)
    $script:SessionStamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
    $script:FormValid = $false
    $script:CommandRunning = $false
    $script:SessionClosed = $false
    $script:SearchNameDirty = $false
    $script:DescriptionDirty = $false
    $script:InPreview = $false
    $script:UpdatingName = $false
    $script:UpdatingDescription = $false
    $script:InTimer = $false
    $script:ActiveSearchName = ''
    $script:CurrentOutputFolder = ''
    $script:CurrentLogFile = ''
    $script:LastStatus = ''
    $script:ModulePath = $null
    Ensure-Sync
    $defaults = Get-DefaultInvestigationSettings

    $script:form = New-Object System.Windows.Forms.Form
    $script:form.Text = "Purview Email Investigation v$($script:AppVersion)"
    $script:form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $script:form.Size = New-Object System.Drawing.Size(1360, 920)
    $script:form.MinimumSize = New-Object System.Drawing.Size(1180, 780)
    $script:form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $script:form.BackColor = $script:ColorPage
    $script:form.Icon = [System.Drawing.SystemIcons]::Shield
    $script:toolTip = New-Object System.Windows.Forms.ToolTip

    $header = New-Object System.Windows.Forms.Panel
    $header.Dock = [System.Windows.Forms.DockStyle]::Top
    $header.Height = 72
    $header.BackColor = $script:ColorNavy
    $helpHost = New-Object System.Windows.Forms.Panel
    $helpHost.Dock = [System.Windows.Forms.DockStyle]::Right
    $helpHost.Width = 110
    $helpHost.BackColor = $script:ColorNavy
    $script:btnHelp = New-UiButton 'Help' 86 ([System.Drawing.Color]::White) $script:ColorNavy -Outline
    $script:btnHelp.Location = New-Object System.Drawing.Point(12, 18)
    $script:btnHelp.Add_Click({ Show-ToolHelp })
    $helpHost.Controls.Add($script:btnHelp)
    $title = New-Object System.Windows.Forms.Label
    $title.Text = 'Purview Email Investigation'
    $title.Font = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
    $title.ForeColor = [System.Drawing.Color]::White
    $title.AutoSize = $true
    $title.Location = New-Object System.Drawing.Point(16, 10)
    $subtitle = New-Object System.Windows.Forms.Label
    $subtitle.Text = 'Read-only compliance search. Does not delete, move, or modify messages.'
    $subtitle.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $subtitle.ForeColor = [System.Drawing.Color]::FromArgb(168, 190, 214)
    $subtitle.AutoSize = $true
    $subtitle.Location = New-Object System.Drawing.Point(18, 42)
    $header.Controls.Add($title)
    $header.Controls.Add($subtitle)
    $header.Controls.Add($helpHost)

    $status = New-Object System.Windows.Forms.Panel
    $status.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $status.Height = 48
    $status.BackColor = [System.Drawing.Color]::White
    $script:progress = New-Object System.Windows.Forms.ProgressBar
    $script:progress.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $script:progress.Height = 16
    $script:progress.Minimum = 0
    $script:progress.Maximum = 100
    $script:lblStatus = New-Object System.Windows.Forms.Label
    $script:lblStatus.Dock = [System.Windows.Forms.DockStyle]::Fill
    $script:lblStatus.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $script:lblStatus.Padding = New-Object System.Windows.Forms.Padding(12, 0, 12, 0)
    $script:lblStatus.Text = 'Ready'
    $script:lblStatus.ForeColor = $script:ColorNavy
    $status.Controls.Add($script:lblStatus)
    $status.Controls.Add($script:progress)

    $logHost = New-Object System.Windows.Forms.Panel
    $logHost.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $logHost.Height = 180
    $logHost.Padding = New-Object System.Windows.Forms.Padding(12, 0, 12, 8)
    $logHost.BackColor = $script:ColorPage
    $logCaption = New-Object System.Windows.Forms.Label
    $logCaption.Text = 'Activity log'
    $logCaption.Dock = [System.Windows.Forms.DockStyle]::Top
    $logCaption.Height = 22
    $logCaption.Font = New-Object System.Drawing.Font('Segoe UI', 8.5, [System.Drawing.FontStyle]::Bold)
    $logCaption.ForeColor = $script:ColorNavy
    $script:txtLog = New-Object System.Windows.Forms.RichTextBox
    $script:txtLog.Dock = [System.Windows.Forms.DockStyle]::Fill
    $script:txtLog.ReadOnly = $true
    $script:txtLog.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $script:txtLog.BackColor = [System.Drawing.Color]::FromArgb(18, 22, 28)
    $script:txtLog.ForeColor = [System.Drawing.Color]::FromArgb(220, 228, 236)
    $script:txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
    $script:txtLog.DetectUrls = $false
    $logHost.Controls.Add($script:txtLog)
    $logHost.Controls.Add($logCaption)

    $table = New-Object System.Windows.Forms.TableLayoutPanel
    $table.Dock = [System.Windows.Forms.DockStyle]::Fill
    $table.ColumnCount = 2
    $table.RowCount = 1
    $table.Padding = New-Object System.Windows.Forms.Padding(8, 8, 8, 4)
    $table.BackColor = $script:ColorPage
    $table.ColumnStyles.Clear()
    $table.RowStyles.Clear()
    [void]$table.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 46)))
    [void]$table.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 54)))
    [void]$table.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $script:leftScroll = New-Object System.Windows.Forms.Panel
    $script:leftScroll.Dock = [System.Windows.Forms.DockStyle]::Fill
    $script:leftScroll.AutoScroll = $true
    $script:leftScroll.BackColor = $script:ColorPage
    $script:leftBody = New-Object System.Windows.Forms.Panel
    $script:leftBody.Location = New-Object System.Drawing.Point(0, 0)
    $script:leftBody.Width = 640
    $script:leftBody.Height = 1100
    $script:leftBody.BackColor = $script:ColorPage
    $script:leftScroll.Controls.Add($script:leftBody)
    $script:leftScroll.Add_Resize({
        $width = $script:leftScroll.ClientSize.Width - 4
        if ($width -lt 360) { $width = 360 }
        if ($script:leftBody.Width -ne $width) { $script:leftBody.Width = $width }
    })

    $script:LayoutY = 8
    function Add-FieldLabel([string]$Text) {
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $Text
        $label.AutoSize = $true
        $label.Font = New-Object System.Drawing.Font('Segoe UI', 8.5, [System.Drawing.FontStyle]::Bold)
        $label.ForeColor = $script:ColorNavy
        $label.Location = New-Object System.Drawing.Point(12, $script:LayoutY)
        $script:leftBody.Controls.Add($label)
        $script:LayoutY += 20
    }
    function Add-FullWidthControl($Control, [int]$Height, [int]$Gap = 8) {
        $y = $script:LayoutY
        $Control.Location = New-Object System.Drawing.Point(12, $y)
        $Control.Size = New-Object System.Drawing.Size(($script:leftBody.Width - 24), $Height)
        if ($Control -is [System.Windows.Forms.Label]) { $Control.AutoSize = $false }
        $Control.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $script:leftBody.Controls.Add($Control)
        $script:LayoutY = $y + $Height + $Gap
    }
    function Add-Hint([string]$Text, [int]$Height = 32) {
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $Text
        $label.Font = New-Object System.Drawing.Font('Segoe UI', 8)
        $label.ForeColor = $script:ColorMuted
        Add-FullWidthControl $label $Height 6
    }

    Add-FieldLabel 'Administrator UPN'
    $adminRow = New-Object System.Windows.Forms.Panel
    Add-FullWidthControl $adminRow 34
    $script:txtAdmin = New-UiTextBox
    $script:txtAdmin.Dock = [System.Windows.Forms.DockStyle]::Fill
    $script:btnConnect = New-UiButton 'Connect' 120 $script:ColorAccent ([System.Drawing.Color]::White)
    $script:btnConnect.Dock = [System.Windows.Forms.DockStyle]::Right
    $adminGap = New-Object System.Windows.Forms.Panel
    $adminGap.Dock = [System.Windows.Forms.DockStyle]::Right
    $adminGap.Width = 8
    $adminRow.Controls.Add($script:txtAdmin)
    $adminRow.Controls.Add($adminGap)
    $adminRow.Controls.Add($script:btnConnect)

    $moduleRow = New-Object System.Windows.Forms.Panel
    Add-FullWidthControl $moduleRow 36 4
    $script:lblModule = New-Object System.Windows.Forms.Label
    $script:lblModule.Text = 'Checking ExchangeOnlineManagement...'
    $script:lblModule.Dock = [System.Windows.Forms.DockStyle]::Fill
    $script:lblModule.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $script:lblModule.AutoEllipsis = $true
    $script:lblModule.ForeColor = $script:ColorMuted
    $script:btnInstall = New-UiButton 'Install module' 140 $script:ColorWarning ([System.Drawing.Color]::White)
    $script:btnInstall.Dock = [System.Windows.Forms.DockStyle]::Right
    $script:btnInstall.Visible = $false
    $moduleRow.Controls.Add($script:lblModule)
    $moduleRow.Controls.Add($script:btnInstall)

    Add-FieldLabel 'Sender'
    $script:txtSender = New-UiTextBox
    Add-FullWidthControl $script:txtSender 28
    Add-FieldLabel 'Recipient domains'
    $script:txtDomains = New-UiTextBox -Multiline -Height 68
    $script:txtDomains.Text = $defaults.Domains
    Add-FullWidthControl $script:txtDomains 68
    Add-Hint 'Separate domains with commas, semicolons, or new lines. A leading @ is optional.' 28

    Add-FieldLabel 'Start date and end date'
    $dateRow = New-Object System.Windows.Forms.Panel
    Add-FullWidthControl $dateRow 32
    $script:dtStart = New-Object System.Windows.Forms.DateTimePicker
    $script:dtStart.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom
    $script:dtStart.CustomFormat = 'yyyy-MM-dd'
    $script:dtStart.Width = 160
    $script:dtStart.Location = New-Object System.Drawing.Point(0, 2)
    $script:dtStart.Value = ConvertTo-SettingDate $defaults.StartDate (Get-Date).Date
    $dateCaption = New-Object System.Windows.Forms.Label
    $dateCaption.Text = 'through'
    $dateCaption.AutoSize = $true
    $dateCaption.Location = New-Object System.Drawing.Point(172, 6)
    $script:dtEnd = New-Object System.Windows.Forms.DateTimePicker
    $script:dtEnd.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom
    $script:dtEnd.CustomFormat = 'yyyy-MM-dd'
    $script:dtEnd.Width = 160
    $script:dtEnd.Location = New-Object System.Drawing.Point(230, 2)
    $script:dtEnd.Value = (Get-Date).Date
    $dateRow.Controls.Add($script:dtStart)
    $dateRow.Controls.Add($dateCaption)
    $dateRow.Controls.Add($script:dtEnd)

    Add-FieldLabel 'eDiscovery case (optional)'
    $script:txtCase = New-UiTextBox
    Add-FullWidthControl $script:txtCase 28
    Add-Hint 'Leave blank for a standalone content search. The case must already exist.' 28
    Add-FieldLabel 'Mailbox scope'
    $scopeRow = New-Object System.Windows.Forms.Panel
    Add-FullWidthControl $scopeRow 48
    $script:radSender = New-Object System.Windows.Forms.RadioButton
    $script:radSender.Text = 'Sender mailbox only (recommended)'
    $script:radSender.Checked = $true
    $script:radSender.AutoSize = $true
    $script:radSender.Location = New-Object System.Drawing.Point(0, 0)
    $script:radAll = New-Object System.Windows.Forms.RadioButton
    $script:radAll.Text = 'All accessible mailboxes'
    $script:radAll.AutoSize = $true
    $script:radAll.Location = New-Object System.Drawing.Point(0, 24)
    $scopeRow.Controls.Add($script:radSender)
    $scopeRow.Controls.Add($script:radAll)
    Add-Hint 'Sender mailbox includes Sent Items. All mailboxes can take much longer. Neither option changes mail.' 32
    $script:chkInactive = New-Object System.Windows.Forms.CheckBox
    $script:chkInactive.Text = 'Sender mailbox is inactive'
    $script:chkInactive.AutoSize = $true
    Add-FullWidthControl $script:chkInactive 24
    $script:chkNotify = New-Object System.Windows.Forms.CheckBox
    $script:chkNotify.Text = 'Email me when the search finishes'
    $script:chkNotify.AutoSize = $true
    Add-FullWidthControl $script:chkNotify 24

    Add-FieldLabel 'Search name'
    $script:txtSearchName = New-UiTextBox
    $script:txtSearchName.Font = New-Object System.Drawing.Font('Consolas', 9)
    Add-FullWidthControl $script:txtSearchName 28
    Add-FieldLabel 'Output folder'
    $outputRow = New-Object System.Windows.Forms.Panel
    Add-FullWidthControl $outputRow 34
    $script:txtOutput = New-UiTextBox
    $script:txtOutput.Dock = [System.Windows.Forms.DockStyle]::Fill
    $script:txtOutput.Text = $defaults.OutputFolder
    $script:btnBrowse = New-UiButton 'Browse' 100 ([System.Drawing.Color]::White) $script:ColorNavy -Outline
    $script:btnBrowse.Dock = [System.Windows.Forms.DockStyle]::Right
    $outputGap = New-Object System.Windows.Forms.Panel
    $outputGap.Dock = [System.Windows.Forms.DockStyle]::Right
    $outputGap.Width = 8
    $outputRow.Controls.Add($script:txtOutput)
    $outputRow.Controls.Add($outputGap)
    $outputRow.Controls.Add($script:btnBrowse)

    Add-FieldLabel 'Timeout (minutes)'
    $timeoutRow = New-Object System.Windows.Forms.Panel
    Add-FullWidthControl $timeoutRow 32
    $script:numTimeout = New-Object System.Windows.Forms.NumericUpDown
    $script:numTimeout.Minimum = 1
    $script:numTimeout.Maximum = 720
    $script:numTimeout.Value = 120
    $script:numTimeout.Width = 90
    $script:numTimeout.Location = New-Object System.Drawing.Point(0, 2)
    $timeoutHint = New-Object System.Windows.Forms.Label
    $timeoutHint.Text = 'Stop watching after this long. The search keeps running in Purview.'
    $timeoutHint.AutoSize = $true
    $timeoutHint.ForeColor = $script:ColorMuted
    $timeoutHint.Location = New-Object System.Drawing.Point(100, 6)
    $timeoutRow.Controls.Add($script:numTimeout)
    $timeoutRow.Controls.Add($timeoutHint)

    Add-FieldLabel 'Additional KeyQL (optional)'
    $script:txtExtra = New-UiTextBox -Multiline -Height 44
    Add-FullWidthControl $script:txtExtra 44
    Add-Hint 'Combined with AND, so it cannot remove the sender, domain, or date conditions.' 28
    Add-FieldLabel 'Description'
    $script:txtDescription = New-UiTextBox -Multiline -Height 52
    Add-FullWidthControl $script:txtDescription 52
    $script:leftBody.Height = $script:LayoutY + 12

    $leftColumn = New-Object System.Windows.Forms.Panel
    $leftColumn.Dock = [System.Windows.Forms.DockStyle]::Fill
    $leftColumn.BackColor = $script:ColorPage

    $footer = New-Object System.Windows.Forms.Panel
    $footer.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $footer.Height = 176
    $footer.BackColor = [System.Drawing.Color]::White

    $script:lblValidation = New-Object System.Windows.Forms.Label
    $script:lblValidation.Text = 'Checking the form...'
    $script:lblValidation.ForeColor = $script:ColorMuted
    $script:lblValidation.Location = New-Object System.Drawing.Point(12, 6)
    $script:lblValidation.Size = New-Object System.Drawing.Size(600, 32)
    $script:lblValidation.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

    $queryCaption = New-Object System.Windows.Forms.Label
    $queryCaption.Text = 'KeyQL query'
    $queryCaption.AutoSize = $true
    $queryCaption.Font = New-Object System.Drawing.Font('Segoe UI', 8.5, [System.Drawing.FontStyle]::Bold)
    $queryCaption.ForeColor = $script:ColorNavy
    $queryCaption.Location = New-Object System.Drawing.Point(12, 40)

    $script:txtQuery = New-UiTextBox -Multiline -Height 68
    $script:txtQuery.ReadOnly = $true
    $script:txtQuery.Font = New-Object System.Drawing.Font('Consolas', 9)
    $script:txtQuery.BackColor = $script:ColorQuery
    $script:txtQuery.Location = New-Object System.Drawing.Point(12, 60)
    $script:txtQuery.Size = New-Object System.Drawing.Size(600, 68)
    $script:txtQuery.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

    $script:btnStart = New-UiButton 'Start search' 160 $script:ColorAccent ([System.Drawing.Color]::White)
    $script:btnStart.Location = New-Object System.Drawing.Point(12, 136)
    $script:btnStop = New-UiButton 'Stop' 100 $script:ColorDanger ([System.Drawing.Color]::White)
    $script:btnStop.Location = New-Object System.Drawing.Point(180, 136)
    $script:btnStop.Enabled = $false
    $footer.Controls.Add($script:lblValidation)
    $footer.Controls.Add($queryCaption)
    $footer.Controls.Add($script:txtQuery)
    $footer.Controls.Add($script:btnStart)
    $footer.Controls.Add($script:btnStop)
    $leftColumn.Controls.Add($script:leftScroll)
    $leftColumn.Controls.Add($footer)

    $right = New-Object System.Windows.Forms.Panel
    $right.Dock = [System.Windows.Forms.DockStyle]::Fill
    $right.BackColor = $script:ColorPage
    $right.Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
    $summaryPanel = New-Object System.Windows.Forms.Panel
    $summaryPanel.Dock = [System.Windows.Forms.DockStyle]::Top
    $summaryPanel.Height = 128
    $summaryPanel.BackColor = [System.Drawing.Color]::White
    $summaryPanel.Padding = New-Object System.Windows.Forms.Padding(8)
    $summaryGrid = New-Object System.Windows.Forms.TableLayoutPanel
    $summaryGrid.Dock = [System.Windows.Forms.DockStyle]::Fill
    $summaryGrid.ColumnCount = 2
    $summaryGrid.RowCount = 4
    $summaryGrid.ColumnStyles.Clear()
    $summaryGrid.RowStyles.Clear()
    [void]$summaryGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
    [void]$summaryGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
    for ($rowStyle = 0; $rowStyle -lt 4; $rowStyle++) {
        [void]$summaryGrid.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 25)))
    }
    $summaryGrid.BackColor = [System.Drawing.Color]::White
    $script:SummaryValues = @{}
    $summaryFields = @(
        @('Status', 'Status'),
        @('Items', 'Matching items'),
        @('Size', 'Total size'),
        @('Unindexed', 'Unindexed items'),
        @('Duration', 'Duration'),
        @('Scope', 'Scope'),
        @('Search', 'Search name'),
        @('Output', 'Output')
    )
    for ($i = 0; $i -lt $summaryFields.Count; $i++) {
        $column = $i % 2
        $rowIndex = [int][math]::Floor($i / 2)
        $cell = New-Object System.Windows.Forms.Panel
        $cell.Dock = [System.Windows.Forms.DockStyle]::Fill
        $cell.Margin = New-Object System.Windows.Forms.Padding(4, 1, 4, 1)
        $cell.BackColor = [System.Drawing.Color]::White
        $caption = New-Object System.Windows.Forms.Label
        $caption.Text = $summaryFields[$i][1]
        $caption.Dock = [System.Windows.Forms.DockStyle]::Left
        $caption.Width = 118
        $caption.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $caption.ForeColor = $script:ColorMuted
        $value = New-Object System.Windows.Forms.Label
        $value.Text = '-'
        $value.Dock = [System.Windows.Forms.DockStyle]::Fill
        $value.AutoEllipsis = $true
        $value.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $value.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
        $value.ForeColor = $script:ColorNavy
        $cell.Controls.Add($value)
        $cell.Controls.Add($caption)
        $summaryGrid.Controls.Add($cell, $column, $rowIndex)
        $script:SummaryValues[$summaryFields[$i][0]] = $value
    }
    $summaryPanel.Controls.Add($summaryGrid)

    $actions = New-Object System.Windows.Forms.FlowLayoutPanel
    $actions.Dock = [System.Windows.Forms.DockStyle]::Top
    $actions.Height = 120
    $actions.WrapContents = $true
    $actions.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
    $actions.Padding = New-Object System.Windows.Forms.Padding(0, 6, 0, 0)
    $actions.BackColor = $script:ColorPage
    $script:btnPreview = New-UiButton 'Findings list' 140 $script:ColorNavy ([System.Drawing.Color]::White)
    $script:btnReport = New-UiButton 'Statistics report' 160 $script:ColorNavy ([System.Drawing.Color]::White)
    $script:btnOpenFolder = New-UiButton 'Open folder' 120 ([System.Drawing.Color]::White) $script:ColorNavy -Outline
    $script:btnPurview = New-UiButton 'Open Purview' 130 ([System.Drawing.Color]::White) $script:ColorNavy -Outline
    $script:btnCopyQuery = New-UiButton 'Copy query' 110 ([System.Drawing.Color]::White) $script:ColorNavy -Outline
    $script:btnCopyName = New-UiButton 'Copy name' 110 ([System.Drawing.Color]::White) $script:ColorNavy -Outline
    $script:btnRemove = New-UiButton 'Remove search' 140 $script:ColorDanger ([System.Drawing.Color]::White)
    $script:btnExportLog = New-UiButton 'Export log' 110 ([System.Drawing.Color]::White) $script:ColorNavy -Outline
    foreach ($button in @($script:btnPreview, $script:btnReport, $script:btnOpenFolder, $script:btnPurview, $script:btnCopyQuery, $script:btnCopyName, $script:btnRemove, $script:btnExportLog)) {
        $actions.Controls.Add($button)
    }

    $script:tabs = New-Object System.Windows.Forms.TabControl
    $script:tabs.Dock = [System.Windows.Forms.DockStyle]::Fill
    $script:tabStats = New-Object System.Windows.Forms.TabPage
    $script:tabStats.Text = 'Mailbox statistics'
    $script:tabStats.Padding = New-Object System.Windows.Forms.Padding(8)
    $script:tabStats.BackColor = $script:ColorPage
    $script:tabPreview = New-Object System.Windows.Forms.TabPage
    $script:tabPreview.Text = 'Message findings'
    $script:tabPreview.Padding = New-Object System.Windows.Forms.Padding(8)
    $script:tabPreview.BackColor = $script:ColorPage
    $script:tabs.TabPages.Add($script:tabStats)
    $script:tabs.TabPages.Add($script:tabPreview)

    $script:gridLocations = New-ResultGrid
    Add-GridColumn $script:gridLocations 'Location' 'Mailbox' 40
    Add-GridColumn $script:gridLocations 'Items' 'Items' 15 ([int64])
    Add-GridColumn $script:gridLocations 'Size' 'Size' 20
    Add-GridColumn $script:gridLocations 'Bytes' 'Bytes' 15 ([int64])
    $script:lblEmptyLocations = New-Object System.Windows.Forms.Label
    $script:lblEmptyLocations.Text = 'Run a search to list matching mailboxes.'
    $script:lblEmptyLocations.Dock = [System.Windows.Forms.DockStyle]::Top
    $script:lblEmptyLocations.Height = 24
    $script:lblEmptyLocations.ForeColor = $script:ColorMuted
    $script:tabStats.Controls.Add($script:gridLocations)
    $script:tabStats.Controls.Add($script:lblEmptyLocations)

    $script:gridPreview = New-ResultGrid
    Add-GridColumn $script:gridPreview 'Received' 'Received' 18
    Add-GridColumn $script:gridPreview 'Sender' 'Sender' 20
    Add-GridColumn $script:gridPreview 'Subject' 'Subject' 28
    Add-GridColumn $script:gridPreview 'Type' 'Type' 12
    Add-GridColumn $script:gridPreview 'Size' 'Size' 10
    Add-GridColumn $script:gridPreview 'Location' 'Mailbox' 18
    $script:lblEmptyPreview = New-Object System.Windows.Forms.Label
    $script:lblEmptyPreview.Text = 'Each matching message is listed here with its subject line. Message bodies are not downloaded.'
    $script:lblEmptyPreview.Dock = [System.Windows.Forms.DockStyle]::Top
    $script:lblEmptyPreview.Height = 36
    $script:lblEmptyPreview.ForeColor = $script:ColorMuted
    $script:tabPreview.Controls.Add($script:gridPreview)
    $script:tabPreview.Controls.Add($script:lblEmptyPreview)

    $right.Controls.Add($script:tabs)
    $right.Controls.Add($actions)
    $right.Controls.Add($summaryPanel)
    $table.Controls.Add($leftColumn, 0, 0)
    $table.Controls.Add($right, 1, 0)

    $script:form.Controls.Add($table)
    $script:form.Controls.Add($logHost)
    $script:form.Controls.Add($status)
    $script:form.Controls.Add($header)

    Apply-SavedSettings
    $script:txtAdmin.Add_TextChanged({ Update-QueryPreview })
    $script:txtSender.Add_TextChanged({ Update-QueryPreview })
    $script:txtDomains.Add_TextChanged({ Update-QueryPreview })
    $script:txtCase.Add_TextChanged({ Update-QueryPreview })
    $script:txtExtra.Add_TextChanged({ Update-QueryPreview })
    $script:txtOutput.Add_TextChanged({ Update-QueryPreview })
    $script:txtSearchName.Add_TextChanged({
        if (-not $script:UpdatingName) { $script:SearchNameDirty = $true }
        Update-QueryPreview
    })
    $script:txtDescription.Add_TextChanged({
        if (-not $script:UpdatingDescription) { $script:DescriptionDirty = $true }
        Update-QueryPreview
    })
    $script:dtStart.Add_ValueChanged({ Update-QueryPreview })
    $script:dtEnd.Add_ValueChanged({ Update-QueryPreview })
    $script:numTimeout.Add_ValueChanged({ Update-QueryPreview })
    $script:radSender.Add_CheckedChanged({ Update-InactiveCaption; Update-QueryPreview })
    $script:radAll.Add_CheckedChanged({ Update-InactiveCaption; Update-QueryPreview })
    $script:chkInactive.Add_CheckedChanged({ Update-QueryPreview })
    $script:chkNotify.Add_CheckedChanged({ Update-QueryPreview })
    $script:btnConnect.Add_Click({ Connect-FromUi })
    $script:btnInstall.Add_Click({ Install-ModuleFromUi })
    $script:btnBrowse.Add_Click({ Browse-OutputFolder })
    $script:btnStart.Add_Click({ Start-SearchFromUi })
    $script:btnStop.Add_Click({ Stop-FromUi })
    $script:btnPreview.Add_Click({ Start-PreviewFromUi })
    $script:btnReport.Add_Click({ Start-ReportFromUi })
    $script:btnOpenFolder.Add_Click({ Open-OutputFolder })
    $script:btnPurview.Add_Click({ Open-PurviewPortal })
    $script:btnCopyQuery.Add_Click({ Copy-UiText $script:txtQuery.Text 'Query' })
    $script:btnCopyName.Add_Click({ Copy-UiText $script:txtSearchName.Text 'Search name' })
    $script:btnRemove.Add_Click({ Remove-SearchFromUi })
    $script:btnExportLog.Add_Click({ Export-ActivityLog })
    $script:form.Add_FormClosing({
        param($sender, $eventArgs)
        if ($script:CommandRunning) {
            $answer = [System.Windows.Forms.MessageBox]::Show(
                $script:form,
                "A Purview operation is still running.`r`n`r`nClose the window anyway? A search that already started keeps running in Purview.",
                'Operation in progress',
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) {
                $eventArgs.Cancel = $true
                return
            }
            $script:Sync.CancelRequested = $true
        }
        try { Save-SettingsFromUi } catch { }
    })

    $script:toolTip.SetToolTip($script:btnStart, 'Create and start a read-only compliance search.')
    $script:toolTip.SetToolTip($script:btnPreview, 'Save MessageFindings.xlsx with one row per message, including the subject line. Does not download message bodies. Microsoft 365 asks for a second sign-in because the old preview command is no longer accepted.')
    $script:toolTip.SetToolTip($script:btnRemove, 'Remove the search definition from Purview. Does not modify messages.')
    $script:toolTip.SetToolTip($script:chkInactive, 'For one mailbox, the address is prefixed with a period so an inactive mailbox can be searched.')

    Update-InactiveCaption
    Update-ModuleStatus
    Update-QueryPreview
    Add-UiLog "Purview Email Investigation v$($script:AppVersion) ready. Sign in with an account that can run compliance searches."

    $script:UiTimer = New-Object System.Windows.Forms.Timer
    $script:UiTimer.Interval = 400
    $script:UiTimer.Add_Tick({ Update-InvestigationUi })
    $script:UiTimer.Start()

    try {
        [void]$script:form.ShowDialog()
    }
    finally {
        Close-InvestigationSession
        if ($script:form -and -not $script:form.IsDisposed) { $script:form.Dispose() }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Start-PurviewInvestigationGui
}

$ErrorActionPreference = 'Stop'
$tool = Join-Path (Split-Path -Parent $PSScriptRoot) 'Purview-EmailInvestigation.ps1'
. $tool

$script:Failures = 0

function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        Write-Host "PASS $Name"
    }
    else {
        Write-Host "FAIL $Name"
        $script:Failures++
    }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Name)
    if ($Actual -eq $Expected) {
        Write-Host "PASS $Name"
    }
    else {
        Write-Host "FAIL $Name"
        Write-Host "  actual:   [$Actual]"
        Write-Host "  expected: [$Expected]"
        $script:Failures++
    }
}

function Assert-Throws {
    param([scriptblock]$Script, [string]$Name, [string]$Pattern)
    $threw = $false
    $message = ''
    try {
        & $Script | Out-Null
    }
    catch {
        $threw = $true
        $message = $_.Exception.Message
    }
    if (-not $threw) {
        Write-Host "FAIL $Name (no exception)"
        $script:Failures++
        return
    }
    if ($Pattern -and $message -notmatch $Pattern) {
        Write-Host "FAIL $Name"
        Write-Host "  message: $message"
        $script:Failures++
        return
    }
    Write-Host "PASS $Name"
}

$parseErrors = $null
$parseTokens = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($tool, [ref]$parseTokens, [ref]$parseErrors)
Assert-Equal $parseErrors.Count 0 'script parses'

Assert-True (Test-EmailAddress 'user.name+tag@contoso.com') 'accepts a normal email'
Assert-True (Test-EmailAddress 'admin@contoso.onmicrosoft.com') 'accepts an onmicrosoft UPN'
Assert-True (-not (Test-EmailAddress 'not-an-email')) 'rejects an address without a domain'
Assert-True (-not (Test-EmailAddress 'user@domain')) 'rejects a single-label domain'
Assert-True (-not (Test-EmailAddress 'user@domain..com')) 'rejects a double-dot domain'
Assert-True (-not (Test-EmailAddress 'bad address@contoso.com')) 'rejects an address with a space'
Assert-True (-not (Test-EmailAddress '')) 'rejects an empty address'

$domains = ConvertTo-RecipientDomainList " @ACPAO.org, allencounty.in.gov;acpao.org`nallencounty.in.gov "
Assert-Equal $domains.Count 2 'domain list collapses case and duplicates'
Assert-Equal $domains[0] 'acpao.org' 'domain order keeps the first domain'
Assert-Equal $domains[1] 'allencounty.in.gov' 'domain order keeps the second domain'
Assert-Throws { ConvertTo-RecipientDomainList '   ' } 'empty domains throw' 'At least one recipient domain'
Assert-Throws { ConvertTo-RecipientDomainList 'not a domain, acpao.org' } 'invalid domain throws' 'Invalid recipient domain: not'
Assert-Throws { ConvertTo-RecipientDomainList '-bad.com' } 'leading hyphen throws' 'Invalid recipient domain'
Assert-True (-not (Test-RecipientDomain 'ab-.com')) 'trailing hyphen in a label is rejected'

Assert-True (Test-ParenthesesBalanced 'subject:"foo (bar)"') 'parentheses inside quotes are ignored'
Assert-True (-not (Test-ParenthesesBalanced ('subject:"foo (bar'))) 'an open quote is unbalanced'
Assert-True (-not (Test-ParenthesesBalanced 'subject:(foo')) 'a missing close parenthesis is rejected'

$start = [datetime]::ParseExact('2025-07-10', 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
$end = $start
$query = New-InvestigationQuery -Sender 'user@contoso.com' -Domains $domains -Start $start -End $end
$expected = 'kind:email AND from:"user@contoso.com" AND (recipients:"acpao.org" OR recipients:"allencounty.in.gov") AND sent>=2025-07-10 AND sent<2025-07-11'
Assert-Equal $query $expected 'query groups recipients and includes the whole end date'

$singleDay = New-InvestigationQuery -Sender 'user@contoso.com' -Domains @('acpao.org') -Start $start -End $end
Assert-True ($singleDay.Contains('AND (recipients:"acpao.org") AND')) 'one domain stays grouped'
Assert-True ($singleDay -notmatch 'sent<=2025-07-10') 'end date is not a midnight inclusive bound'

$leapStart = [datetime]::ParseExact('2024-02-28', 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
$leapEnd = [datetime]::ParseExact('2024-02-29', 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
$leapQuery = New-InvestigationQuery -Sender 'user@contoso.com' -Domains @('acpao.org') -Start $leapStart -End $leapEnd
Assert-True ($leapQuery.Contains('sent>=2024-02-28 AND sent<2024-03-01')) 'leap-day end date rolls to March'

$narrowed = New-InvestigationQuery -Sender 'user@contoso.com' -Domains @('acpao.org') -Start $start -End $end -AdditionalQuery "subject:`"budget`" OR from:`"other@contoso.com`""
Assert-True ($narrowed.EndsWith('AND (subject:"budget" OR from:"other@contoso.com")')) 'additional query can only narrow the search'
Assert-True ($narrowed.Contains('from:"user@contoso.com"')) 'additional query keeps the required sender'
Assert-Throws {
    New-InvestigationQuery -Sender 'user@contoso.com' -Domains @('acpao.org') -Start $start.AddDays(1) -End $start
} 'start after end throws' 'Start date cannot be after end date'
Assert-Throws {
    New-InvestigationQuery -Sender 'user@contoso.com' -Domains @('acpao.org') -Start $start -End $end -AdditionalQuery 'subject:(foo'
} 'unbalanced additional query throws' 'unbalanced'

$quoted = New-InvestigationQuery -Sender 'user"name@contoso.com' -Domains @('acpao.org') -Start $start -End $end
Assert-True ($quoted.Contains('from:"user\"name@contoso.com"')) 'quotes in a sender are escaped'

$longSender = ('a' * 250) + '@contoso.com'
$longName = New-InvestigationSearchName -Sender $longSender -Timestamp '2025-07-10 12:00'
Assert-True (Test-SearchName $longName) 'long sender still produces a valid search name'
Assert-True ($longName.Length -le 180) 'search name stays within 180 characters'
Assert-True ($longName -notmatch '\s') 'search name has no spaces'
$safeName = New-InvestigationSearchName -Sender 'first last@contoso.com' -Timestamp '20250710_120000_001'
Assert-Equal $safeName 'EmailInvestigation_first_last_20250710_120000_001' 'unsafe characters in the alias are replaced'

Assert-Equal (Get-ExchangeSearchLocation -Sender 'user@contoso.com' -Scope 'Sender') 'user@contoso.com' 'sender scope uses the mailbox'
Assert-Equal (Get-ExchangeSearchLocation -Sender 'user@contoso.com' -Scope 'Sender' -AllowNotFound $true) '.user@contoso.com' 'inactive mailbox is prefixed'
Assert-Equal (Get-ExchangeSearchLocation -Sender 'user@contoso.com' -Scope 'All' -AllowNotFound $true) 'All' 'all-mailbox scope stays All'

Assert-Equal (Format-ByteSize 0) '0 bytes' 'zero bytes'
Assert-Equal (Format-ByteSize 1023) '1023 bytes' 'bytes below 1 KB'
Assert-Equal (Format-ByteSize 1024) '1.00 KB' 'one kilobyte'
Assert-Equal (Format-ByteSize 1536) '1.50 KB' 'fractional kilobytes'
Assert-Equal (Format-ByteSize '1.5 KB (1,536 bytes)') '1.50 KB' 'Exchange size text is parsed'
Assert-Equal (Format-ByteSize $null) '' 'null size is blank'
Assert-Equal (Format-Duration ([TimeSpan]::FromSeconds(90))) '00:01:30' 'duration under an hour'
Assert-Equal (Format-Duration ([TimeSpan]::FromHours(26))) '26:00:00' 'duration over a day'

$stats = ConvertTo-LocationStatistic '{Location: a@b.com, Item count: 2, Total size: 1000}; {Location: c@d.com, Item count: 1, Total size: 536}'
Assert-Equal $stats.Count 2 'two mailbox statistics are parsed'
Assert-Equal $stats[0].Location 'a@b.com' 'first mailbox location'
Assert-Equal $stats[0].ItemCount 2 'first mailbox count'
Assert-Equal $stats[0].SizeDisplay '1000 bytes' 'size under 1 KB stays in bytes'
Assert-Equal $stats[1].SizeBytes 536 'second mailbox byte count'
$sized = ConvertTo-LocationStatistic '{Location: a@b.com, Item count: 2, Total size: 1.5 KB (1,536 bytes)}'
Assert-Equal $sized[0].SizeBytes 1536 'mailbox size text uses the byte count'
Assert-Equal $sized[0].SizeDisplay '1.50 KB' 'mailbox size text is displayed in kilobytes'
Assert-Equal (ConvertTo-LocationStatistic '').Count 0 'empty statistics return no rows'
Assert-Equal (ConvertTo-LocationStatistic $null).Count 0 'null statistics return no rows'

$previewRaw = '{Location: box@contoso.com; Sender: sender@contoso.com; Subject: Hello; world; Type: IPM.Note; Size: 45678; Received Time: 7/11/2025 3:14:22 PM; Data Link: abc}, {Location: box2@contoso.com; Sender: other@contoso.com; Subject: Next; Type: IPM.Note; Size: 10; Received Time: 7/12/2025 1:00:00 AM; Data Link: def}'
$preview = ConvertTo-PreviewItem $previewRaw
Assert-Equal $preview.Count 2 'two preview items are parsed'
Assert-Equal $preview[0].Subject 'Hello; world' 'preview subject can contain a semicolon'
Assert-Equal $preview[1].Sender 'other@contoso.com' 'second preview sender'
Assert-Equal (ConvertTo-PreviewItem '').Count 0 'empty preview returns no rows'

Assert-True (Test-TerminalSearchStatus 'Completed') 'completed is terminal'
Assert-True (Test-TerminalSearchStatus 'failed') 'failed is terminal regardless of case'
Assert-True (Test-TerminalSearchStatus 'PartiallySucceeded') 'partial success is terminal'
Assert-True (-not (Test-TerminalSearchStatus 'InProgress')) 'in progress is not terminal'
Assert-True (-not (Test-TerminalSearchStatus 'Stopping')) 'stopping is not terminal'
Assert-True (-not (Test-TerminalSearchStatus 'Starting')) 'starting is not terminal'

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('PurviewToolTests_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    $folderA = New-InvestigationOutputFolder -Root $tempRoot
    $folderB = New-InvestigationOutputFolder -Root $tempRoot
    Assert-True (Test-Path -LiteralPath $folderA) 'output folder is created'
    Assert-True ($folderA -ne $folderB) 'two runs get different folders'
    Assert-True ($folderA.StartsWith($tempRoot)) 'output folder stays under the selected root'

    $longQuery = 'Q' * 500
    $search = [pscustomobject]@{
        Status          = 'Completed'
        Items           = 3
        Size            = '1.5 KB (1,536 bytes)'
        UnindexedItems  = 1
        UnindexedSize   = '100'
        Errors          = @('mailbox one failed')
        SuccessResults  = '{Location: a@b.com, Item count: 2, Total size: 1000}; {Location: c@d.com, Item count: 1, Total size: 536}'
        JobStartTime    = '2025-07-10T00:00:00Z'
        JobEndTime      = '2025-07-10T00:02:00Z'
        ContentMatchQuery = $longQuery
    }
    $context = @{
        SearchName       = 'EmailInvestigation_user_20250710'
        CaseName         = 'Litigation Hold 2025'
        Administrator    = 'admin@contoso.com'
        ConnectedAs      = 'admin@contoso.com'
        Sender           = 'user@contoso.com'
        RecipientDomains = 'acpao.org; allencounty.in.gov'
        StartDate        = '2025-07-10'
        EndDate          = '2025-07-10'
        SearchScope      = 'Sender'
        ExchangeLocation = 'user@contoso.com'
        SearchQuery      = $expected
        ExecutionTime    = '00:02:00'
        TimedOut         = $false
        ModuleVersion    = '3.9.0'
    }
    $report = Export-InvestigationReport -Search $search -OutputFolder $folderA -Context $context
    Assert-Equal $report.Summary.MatchingItems '3' 'summary item count'
    Assert-Equal $report.Summary.TotalSize '1.50 KB' 'summary size'
    Assert-Equal $report.Summary.TotalSizeBytes 1536 'summary byte count'
    Assert-Equal $report.Summary.SearchErrors 'mailbox one failed' 'errors are flattened'
    Assert-Equal $report.Locations.Count 2 'location rows are exported'
    $details = [System.IO.File]::ReadAllText((Join-Path $folderA 'SearchDetails.txt'))
    Assert-True ($details.Contains($longQuery)) 'details keep the full query text'
    $savedQuery = [System.IO.File]::ReadAllText((Join-Path $folderA 'SearchQuery.txt')).Trim()
    Assert-Equal $savedQuery $expected 'query file matches the KeyQL'
    Assert-True (Test-Path -LiteralPath (Join-Path $folderA 'SearchSummary.csv')) 'summary CSV exists'
    Assert-True (Test-Path -LiteralPath (Join-Path $folderA 'LocationStatistics.csv')) 'location CSV exists'
    Assert-True (Test-Path -LiteralPath (Join-Path $folderA 'RunManifest.json')) 'manifest exists'

    $previewItems = Export-PreviewResults -RawResults $previewRaw -OutputFolder $folderA -SearchName 'EmailInvestigation_user_20250710'
    Assert-Equal $previewItems.Rows.Count 2 'preview export returns both rows'
    Assert-True (Test-Path -LiteralPath (Join-Path $folderA 'PreviewResults.csv')) 'preview CSV exists'
    Assert-True (Test-Path -LiteralPath (Join-Path $folderA 'MessageFindings.csv')) 'findings CSV exists'
    Assert-True (Test-Path -LiteralPath (Join-Path $folderA 'MessageFindings.xlsx')) 'findings workbook exists'
    $previewText = [System.IO.File]::ReadAllText((Join-Path $folderA 'PreviewResults.txt'))
    Assert-True ($previewText.Contains('Hello; world')) 'preview text keeps the subject'

    $noLink = ConvertTo-PreviewItem 'Location: box@contoso.com; Sender: a@contoso.com; Subject: No link; Type: IPM.Note; Size: 10; Received Time: 7/11/2025 1:00:00 PM'
    Assert-Equal $noLink.Count 1 'a record without a data link is kept'
    Assert-Equal $noLink[0].Subject 'No link' 'subject is read without a data link'
    $quoted = ConvertTo-PreviewItem 'Location: box@contoso.com; Sender: a@contoso.com; Subject: Say "hello", friend; Type: IPM.Note; Size: 12; Received Time: 7/11/2025 1:00:00 PM; Data Link: abc'
    Assert-Equal $quoted[0].Subject 'Say "hello", friend' 'subject keeps quotes and commas'

    $many = New-Object System.Text.StringBuilder
    for ($i = 1; $i -le 90; $i++) {
        if ($i -gt 1) { [void]$many.Append(', ') }
        [void]$many.Append("Location: box@contoso.com; Sender: user@contoso.com; Subject: Finding $i; Type: IPM.Note; Size: 100; Received Time: 7/11/2025 1:00:00 PM; Data Link: link$i")
    }
    $parsed = ConvertTo-PreviewItem $many.ToString()
    Assert-Equal $parsed.Count 90 'ninety preview records are parsed'
    Assert-Equal $parsed[0].Subject 'Finding 1' 'first finding subject'
    Assert-Equal $parsed[89].Subject 'Finding 90' 'ninetieth finding subject'
    $saved = Export-FindingsSpreadsheet -Items $parsed -OutputFolder $folderA -SearchName 'EmailInvestigation_user_20250710' -ReportedItemCount 90
    Assert-Equal $saved.Count 90 'findings spreadsheet has ninety rows'
    Assert-True $saved.IsComplete 'ninety rows cover the reported count'
    $findingsCsv = [System.IO.File]::ReadAllText($saved.CsvPath)
    Assert-True ($findingsCsv.Contains('Finding 1')) 'findings CSV contains the first subject'
    Assert-True ($findingsCsv.Contains('Finding 90')) 'findings CSV contains the last subject'
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zip = [System.IO.Compression.ZipFile]::OpenRead($saved.WorkbookPath)
    try {
        $entry = $zip.GetEntry('xl/worksheets/sheet1.xml')
        $reader = New-Object System.IO.StreamReader($entry.Open())
        try { $sheetXml = $reader.ReadToEnd() } finally { $reader.Dispose() }
    }
    finally { $zip.Dispose() }
    Assert-True ($sheetXml.Contains('Finding 1')) 'workbook contains the first subject'
    Assert-True ($sheetXml.Contains('Finding 90')) 'workbook contains the ninetieth subject'
    $partial = Export-FindingsSpreadsheet -Items $quoted -OutputFolder $folderA -SearchName 'EmailInvestigation_user_20250710' -ReportedItemCount 90
    Assert-True (-not $partial.IsComplete) 'a short subject list does not cover ninety matches'
    $quoteCsv = [System.IO.File]::ReadAllText($partial.CsvPath)
    Assert-True ($quoteCsv.Contains('Say "hello", friend') -or $quoteCsv.Contains('Say ""hello"", friend')) 'quoted subject is saved in the CSV'

    $logPath = Join-Path $folderA 'Investigation.log'
    Add-Utf8Line -Path $logPath -Line 'one'
    Add-Utf8Line -Path $logPath -Line 'two'
    $logBytes = [System.IO.File]::ReadAllBytes($logPath)
    $bom = ($logBytes.Length -ge 3 -and $logBytes[0] -eq 0xEF -and $logBytes[1] -eq 0xBB -and $logBytes[2] -eq 0xBF)
    Assert-True (-not $bom) 'log file does not start with a BOM'
    $bomInside = $false
    for ($i = 1; $i -lt ($logBytes.Length - 2); $i++) {
        if ($logBytes[$i] -eq 0xEF -and $logBytes[$i + 1] -eq 0xBB -and $logBytes[$i + 2] -eq 0xBF) { $bomInside = $true }
    }
    Assert-True (-not $bomInside) 'appended log lines do not insert a BOM'
    Assert-Equal ([System.IO.File]::ReadAllText($logPath).Trim()) "one$([Environment]::NewLine)two" 'log lines are both present'

    $request = Test-InvestigationRequest `
        -AdminUpn 'admin@contoso.com' `
        -Sender 'user@contoso.com' `
        -DomainText 'acpao.org, allencounty.in.gov' `
        -CaseName 'Litigation Hold 2025' `
        -Scope 'Sender' `
        -AllowNotFound $false `
        -NotifyAdmin $false `
        -Start $start `
        -End $end `
        -AdditionalQuery '' `
        -SearchName 'EmailInvestigation_user_20250710_120000' `
        -OutputFolder $tempRoot `
        -TimeoutMinutes 120 `
        -Description ''
    Assert-True $request.IsValid 'a complete request is valid'
    Assert-Equal $request.Query $expected 'request builds the same query'
    Assert-Equal $request.ExchangeLocation 'user@contoso.com' 'request location'
    Assert-True ($request.Description.Contains('user@contoso.com')) 'empty description is generated'
    Assert-Equal $request.CaseName 'Litigation Hold 2025' 'case names may contain spaces'

    $badName = Test-InvestigationRequest `
        -AdminUpn 'admin@contoso.com' `
        -Sender 'user@contoso.com' `
        -DomainText 'acpao.org' `
        -CaseName '' `
        -Scope 'All' `
        -AllowNotFound $false `
        -NotifyAdmin $false `
        -Start $start `
        -End $end `
        -AdditionalQuery '' `
        -SearchName 'Has Spaces' `
        -OutputFolder $tempRoot `
        -TimeoutMinutes 120 `
        -Description 'x'
    Assert-True (-not $badName.IsValid) 'a search name with spaces is rejected'

    $relative = Test-InvestigationRequest `
        -AdminUpn 'admin@contoso.com' `
        -Sender 'user@contoso.com' `
        -DomainText 'acpao.org' `
        -CaseName '' `
        -Scope 'Sender' `
        -AllowNotFound $false `
        -NotifyAdmin $false `
        -Start $start `
        -End $end `
        -AdditionalQuery '' `
        -SearchName 'EmailInvestigation_user_20250710' `
        -OutputFolder 'reports' `
        -TimeoutMinutes 120 `
        -Description 'x'
    Assert-True (-not $relative.IsValid) 'a relative output folder is rejected'

    $inactive = Test-InvestigationRequest `
        -AdminUpn 'admin@contoso.com' `
        -Sender 'user@contoso.com' `
        -DomainText '@allencounty.in.gov' `
        -CaseName '' `
        -Scope 'Sender' `
        -AllowNotFound $true `
        -NotifyAdmin $true `
        -Start $start `
        -End $end `
        -AdditionalQuery '' `
        -SearchName 'EmailInvestigation_user_20250710' `
        -OutputFolder $tempRoot `
        -TimeoutMinutes 120 `
        -Description 'x'
    Assert-True $inactive.IsValid 'inactive mailbox request is valid'
    Assert-Equal $inactive.ExchangeLocation '.user@contoso.com' 'inactive request prefixes the mailbox'
    Assert-Equal $inactive.Domains[0] 'allencounty.in.gov' 'leading @ is removed'
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$runspace = $null
$powershell = $null
try {
    $runspace = New-InvestigationRunspace
    $powershell = [powershell]::Create()
    $powershell.Runspace = $runspace
    foreach ($name in (Get-InvestigationRunspaceFunctionNames)) {
        $powershell.Commands.Clear()
        $powershell.Streams.ClearStreams()
        [void]$powershell.AddScript("Get-Command -Name '$name' -ErrorAction Stop | Select-Object -ExpandProperty Name")
        $found = @($powershell.Invoke())
        Assert-Equal ($found -join ',') $name "runspace defines $name"
        Assert-Equal $powershell.Streams.Error.Count 0 "runspace lookup of $name has no errors"
    }

    $sync = [hashtable]::Synchronized(@{
        LogQueue          = New-Object System.Collections.Concurrent.ConcurrentQueue[string]
        Phase             = ''
        StatusText        = ''
        Progress          = 0
        ErrorMessage      = $null
        Done              = $false
        CancelRequested   = $false
        Connected         = $false
        ConnectedUpn      = ''
        Busy              = $false
        SearchCreated     = $false
    })
    $job = @{
        Mode       = 'Nope'
        Sync       = $sync
        LogFile    = $null
        ModulePath = ''
        AdminUPN   = 'admin@contoso.com'
    }
    $powershell.Commands.Clear()
    $powershell.Streams.ClearStreams()
    [void]$powershell.AddCommand('Invoke-PurviewSearchJob').AddParameter('Job', $job)
    [void]$powershell.Invoke()
    Assert-Equal $powershell.Streams.Error.Count 0 'unknown mode is handled inside the job'
    Assert-Equal $sync.Phase 'Failed' 'unknown mode fails the job'
    Assert-Equal $sync.Done $true 'unknown mode marks the job done'
    Assert-True ($sync.ErrorMessage -match 'Unknown job mode') 'unknown mode explains the failure'
    $logged = $null
    $sawError = $false
    while ($sync.LogQueue.TryDequeue([ref]$logged)) {
        if ($logged -match '\[ERROR\].*Unknown job mode') { $sawError = $true }
    }
    Assert-True $sawError 'unknown mode is written to the log queue'

    $sync.Done = $false
    $sync.Phase = ''
    $sync.ErrorMessage = $null
    $job.Mode = 'Connect'
    $powershell.Commands.Clear()
    $powershell.Streams.ClearStreams()
    [void]$powershell.AddCommand('Invoke-PurviewSearchJob').AddParameter('Job', $job)
    [void]$powershell.Invoke()
    Assert-Equal $sync.Phase 'Failed' 'connect without a module fails'
    Assert-True ($sync.ErrorMessage -match '3\.9\.0') 'connect without a module names the required version'
    Assert-Equal $sync.Connected $false 'failed connect does not mark the session connected'
}
finally {
    if ($powershell) { $powershell.Dispose() }
    if ($runspace) { $runspace.Close(); $runspace.Dispose() }
}

$source = [System.IO.File]::ReadAllText($tool)
Assert-True ($source -notmatch '(?i)-Purge\b') 'the tool does not expose a purge switch'
Assert-True ($source -match 'EnableSearchOnlySession') 'the connection uses a search-only session'
Assert-True ($source -match 'sent<\{3\}') 'the query template uses an exclusive end bound'

Assert-Throws { Start-PurviewInvestigationGui } 'GUI requires Windows' 'requires Windows'
Assert-True ($source -match 'Start-PurviewInvestigationGui') 'the script launches the GUI'
Assert-True ($source -match 'New-ComplianceSearch') 'the search is still created with New-ComplianceSearch'
Assert-True ($source -match 'MessageFindings.xlsx') 'the tool writes a findings workbook'
Assert-True ($source -notmatch 'New-ComplianceSearchAction[^\r\n]*-Export') 'findings do not use the retired export switch'
$previewGuard = $source.IndexOf("ContainsKey('Preview')")
$previewCall = $source.IndexOf('New-ComplianceSearchAction -SearchName $Job.SearchName -Preview')
Assert-True ($previewGuard -ge 0 -and $previewCall -gt $previewGuard) 'preview is used only when the cmdlet still has that parameter'
$reportGuard = $source.IndexOf("ContainsKey('Report')")
$reportCall = $source.IndexOf('New-ComplianceSearchAction -SearchName $Job.SearchName -Report')
Assert-True ($reportGuard -ge 0 -and $reportCall -gt $reportGuard) 'the statistics report switch is used only when the cmdlet still has it'
Assert-True ($source -match 'exportReport') 'findings use the item report when preview is unavailable'
Assert-True ($source -match 'eDiscovery.ReadWrite.All') 'the item report requests the eDiscovery permission'

$graphJson = ConvertTo-GraphJson @{
    name = 'a "b"'
    'custodianSources@odata.bind' = @('https://example.test/source')
}
Assert-True ($graphJson -match '"custodianSources@odata.bind":\["https://example.test/source"\]') 'graph json keeps a one-element array'
$graphParsed = $graphJson | ConvertFrom-Json
Assert-Equal $graphParsed.name 'a "b"' 'graph json keeps a quoted value'
Assert-Equal @($graphParsed.'custodianSources@odata.bind').Count 1 'graph json parses the bind array'

$reportCsv = @"
Subject/Title,Sender,Date,Location,File class,Size
Budget update,alice@contoso.com,2025-07-11,box@contoso.com,IPM.Note,1024
"Quote, please",bob@contoso.com,2025-07-12,box@contoso.com,IPM.Note,2048
"@
$reportRows = ConvertTo-FindingsFromReportCsv -CsvText $reportCsv
Assert-Equal $reportRows.Count 2 'report csv reads two subject rows'
Assert-Equal $reportRows[0].Subject 'Budget update' 'report csv reads Subject/Title'
Assert-Equal $reportRows[0].Sender 'alice@contoso.com' 'report csv reads the sender'
Assert-Equal $reportRows[1].Subject 'Quote, please' 'report csv keeps a comma inside the subject'
$summaryCsv = "Search name,Item count`r`nEmailInvestigation,90"
$summaryRows = ConvertTo-FindingsFromReportCsv -CsvText $summaryCsv
Assert-Equal $summaryRows.Count 0 'summary csv is not treated as message rows'
$emptyRows = ConvertTo-FindingsFromReportCsv -CsvText ''
Assert-Equal $emptyRows.Count 0 'empty report csv returns no rows'
Assert-True ($source -notmatch 'Remove-ComplianceSearchAction -Purge') 'cleanup does not purge messages'

if ($script:Failures -gt 0) {
    Write-Host "$($script:Failures) test(s) failed."
    exit 1
}
Write-Host 'All tests passed.'
exit 0

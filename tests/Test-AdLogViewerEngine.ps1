#Requires -Version 5.1
<#
.SYNOPSIS
    Engine tests for AD-LogViewer-Modern.ps1 (no GUI).
#>
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$viewer = Join-Path $root 'AD-LogViewer-Modern.ps1'
$sample = Join-Path $PSScriptRoot 'sample-ad-log.txt'
$failed = 0
$passed = 0

function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        $script:passed++
        Write-Host "PASS  $Name"
    } else {
        $script:failed++
        Write-Host "FAIL  $Name"
    }
}

. $viewer -SkipGui

$added = '09/03/2026 12:39:08 == The AD user called: Y22686, was ADDED TO A UNIVERSAL (SECURITY) GROUP by ablake4.S in DFOMIPV22'
$removed = '09/03/2026 12:42:35 == The AD user called: Y22686, was REMOVED FROM A UNIVERSAL (SECURITY) GROUP by ablake4.S in DFOMIPV22'
$modified = '09/10/2026 08:45:37 == Account ablake4.SA was MODIFIED by SVC_DELINEADA in DFOMIPV2202'
$attrChange = '09/03/2026 12:42:38 == The user ablake4.S modified the primaryGroupID of user Y22686 (CN=Y22686,OU=San Pedro Sula)'
$noTs = 'This line has no timestamp and should sort last'

$ts = Get-AdLogTimestamp -Line $added
Assert-True ($null -ne $ts -and $ts.Year -eq 2026 -and $ts.Month -eq 9 -and $ts.Day -eq 3) 'Parse timestamp from leading MM/dd/yyyy HH:mm:ss'
Assert-True ($null -eq (Get-AdLogTimestamp -Line $noTs)) 'Reject lines without a timestamp'

Assert-True ((Get-AdLogEventKind -Line $added) -eq 'Added') 'Classify Added'
Assert-True ((Get-AdLogEventKind -Line $removed) -eq 'Removed') 'Classify Removed'
Assert-True ((Get-AdLogEventKind -Line $modified) -eq 'Modified') 'Classify Modified'
Assert-True ((Get-AdLogEventKind -Line $attrChange) -eq 'Modified') 'Classify attribute-change as Modified'

Assert-True ((Get-AdLogAccount -Line $added) -eq 'Y22686') 'Extract account from "AD user called"'
Assert-True ((Get-AdLogAccount -Line $modified) -eq 'ablake4.SA') 'Extract account from "Account ... was"'
Assert-True ((Get-AdLogAccount -Line $attrChange) -eq 'Y22686') 'Extract account from "of user"'

Assert-True ((Get-AdLogActor -Line $added) -eq 'ablake4.S') 'Extract actor from "by ... in"'
Assert-True ((Get-AdLogActor -Line $attrChange) -eq 'ablake4.S') 'Extract actor from "The user ... modified"'
Assert-True ((Get-AdLogHostName -Line $added) -eq 'DFOMIPV22') 'Extract host'
Assert-True ((Get-AdLogHostName -Line $modified) -eq 'DFOMIPV2202') 'Extract longer host'

Assert-True (Test-AdLogLineMatch -Line $added -SearchTerm 'ablake4.s' -CaseInsensitive $true -UseRegex $false) 'Literal case-insensitive match'
Assert-True (-not (Test-AdLogLineMatch -Line $added -SearchTerm 'ablake4.s' -CaseInsensitive $false -UseRegex $false)) 'Literal case-sensitive miss'
Assert-True (Test-AdLogLineMatch -Line $added -SearchTerm 'Y22686' -CaseInsensitive $false -UseRegex $false) 'Literal exact token match'
Assert-True (Test-AdLogLineMatch -Line $added -SearchTerm '' -CaseInsensitive $true -UseRegex $false) 'Blank term matches every line'

$compiled = [regex]::new('ablake4\.S', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
Assert-True (Test-AdLogLineMatch -Line $added -SearchTerm 'ablake4\.S' -CaseInsensitive $true -UseRegex $true -CompiledRegex $compiled) 'Regex match with escaped dot'
$compiledLoose = [regex]::new('ablake4.S')
Assert-True (Test-AdLogLineMatch -Line 'nope ablake4XS here' -SearchTerm 'ablake4.S' -CaseInsensitive $false -UseRegex $true -CompiledRegex $compiledLoose) 'Regex dot matches any character'
Assert-True (-not (Test-AdLogLineMatch -Line 'nope ablake4XS here' -SearchTerm 'ablake4.S' -CaseInsensitive $false -UseRegex $false)) 'Literal mode does not treat dot as wildcard'

$progressHits = New-Object System.Collections.Generic.List[hashtable]
$results = Search-AdLogFiles -Path $sample -SearchTerm 'ablake4.s' -IsFolder $false -Recursive $false -CaseInsensitive $true -UseRegex $false -ProgressCallback {
    param($info)
    $progressHits.Add($info)
}

Assert-True ($results.Count -eq 13) 'Sample search for ablake4.s returns 13 lines'
Assert-True ($progressHits.Count -ge 1) 'Ingest reports at least one progress callback'
Assert-True (@($results | Where-Object { $_.Event -eq 'Added' }).Count -eq 3) 'Parsed 3 Added events for ablake4.s'
Assert-True (@($results | Where-Object { $_.Account -eq 'ablake4.SA' }).Count -ge 1) 'Parsed ablake4.SA account field'

$all = Search-AdLogFiles -Path $sample -SearchTerm '' -IsFolder $false -Recursive $false -CaseInsensitive $true -UseRegex $false
Assert-True ($all.Count -eq 15) 'Blank search ingests every sample line'

$sorted = Sort-AdLogEntries -Entries $all -Descending $false
Assert-True ($sorted[0].Account -eq 'jsmith') 'Oldest-first sort puts 09/01 first'
Assert-True ($sorted[$sorted.Count - 1].Text.StartsWith('This line has no timestamp')) 'Undated lines stay at the bottom'

$newest = Sort-AdLogEntries -Entries $all -Descending $true
Assert-True ($newest[0].TimestampText.StartsWith('09/10/2026')) 'Newest-first sort starts in September 10'

$filtered = Select-AdLogEntries -Entries $all -FilterText 'Y22686' -EventKind 'Added'
Assert-True ($filtered.Count -eq 1) 'Filter + event kind narrows to one Added Y22686 row'

$folder = Search-AdLogFiles -Path $PSScriptRoot -SearchTerm 'jsmith' -IsFolder $true -Recursive $false -CaseInsensitive $true -UseRegex $false
Assert-True ($folder.Count -eq 1) 'Folder ingest finds the jsmith line in *.txt files'

$large = Join-Path $PSScriptRoot 'large-ad-log.txt'
try {
    $seed = Get-Content -LiteralPath $sample
    $writer = [System.IO.StreamWriter]::new($large, $false, [System.Text.UTF8Encoding]::new($false))
    try {
        for ($i = 0; $i -lt 2500; $i++) {
            foreach ($line in $seed) { $writer.WriteLine($line) }
        }
    } finally {
        $writer.Dispose()
    }

    $ticks = New-Object System.Collections.Generic.List[int]
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $big = Search-AdLogFiles -Path $large -SearchTerm 'ablake4.s' -IsFolder $false -Recursive $false -CaseInsensitive $true -UseRegex $false -ProgressCallback {
        param($info)
        $ticks.Add([int]$info.Percent)
    }
    $sw.Stop()
    Assert-True ($big.Count -eq (13 * 2500)) 'Large-file ingest match count is exact'
    Assert-True ($ticks.Count -ge 2) 'Large-file ingest emits multiple progress updates'
    Assert-True ($sw.Elapsed.TotalSeconds -lt 20) ("Large-file ingest finishes quickly ({0:N2}s)" -f $sw.Elapsed.TotalSeconds)
} finally {
    if (Test-Path -LiteralPath $large) { Remove-Item -LiteralPath $large -Force }
}

Write-Host ""
Write-Host "Passed: $passed   Failed: $failed"
if ($failed -gt 0) { exit 1 }
exit 0

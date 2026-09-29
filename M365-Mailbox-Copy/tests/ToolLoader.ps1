<#
.SYNOPSIS
    Loads the copy tool's functions without running its bootstrap or GUI.

.DESCRIPTION
    Parses M365-Mailbox-Copy-Tool.ps1 (the real file, so tests cannot drift from
    it) and keeps only function definitions and $script:-scoped assignments. The
    module installs, the Connect-MgGraph call and the form never execute.

    Dot-source this file, then dot-source the script block it returns:

        . "$PSScriptRoot/ToolLoader.ps1"
        . ([scriptblock]::Create((Import-ToolDefinitions -Path $ToolPath)))
#>

function Import-ToolDefinitions {
    param([Parameter(Mandatory = $true)][string]$Path)

    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
    if ($errors) {
        throw "$Path has $($errors.Count) parse error(s); first: $($errors[0].Message)"
    }

    $wanted = New-Object System.Collections.Generic.List[string]
    foreach ($statement in $ast.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            $wanted.Add($statement.Extent.Text)
            continue
        }
        # $script:-scoped state the functions rely on (GraphBase, MAPI property
        # set guids, well-known folder names, FolderScanIncomplete, Ui, Prog).
        if ($statement -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $statement.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $statement.Left.VariablePath.UserPath -like 'script:*') {
            $wanted.Add($statement.Extent.Text)
        }
    }

    return ($wanted -join "`r`n")
}

function Assert-ToolFunctionsPresent {
    param(
        [Parameter(Mandatory = $true)][string[]]$Names,
        [Parameter(Mandatory = $true)][string]$ToolPath
    )
    foreach ($name in $Names) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            throw "$name was not found in $ToolPath"
        }
    }
}

function Get-DefaultToolPath {
    return (Join-Path (Split-Path $PSScriptRoot -Parent) 'M365-Mailbox-Copy-Tool.ps1')
}

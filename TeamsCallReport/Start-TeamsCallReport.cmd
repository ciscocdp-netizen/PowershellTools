@echo off
REM Starts the Teams Call Report window in Windows PowerShell (STA, required by WinForms).
set "SCRIPT=%~dp0TeamsCallReport.ps1"
if not exist "%SCRIPT%" (
    echo Could not find "%SCRIPT%"
    exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%SCRIPT%" -StaReady
exit /b %ERRORLEVEL%

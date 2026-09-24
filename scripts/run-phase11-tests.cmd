@echo off
setlocal
cd /d "%~dp0.."
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-phase11-tests.ps1" -Release %*
set EXITCODE=%ERRORLEVEL%
echo.
if %EXITCODE% EQU 0 (
  echo Phase 11 validation completed successfully.
) else (
  echo Phase 11 validation failed. Run from an elevated PowerShell and review test-logs.
)
echo.
pause
exit /b %EXITCODE%

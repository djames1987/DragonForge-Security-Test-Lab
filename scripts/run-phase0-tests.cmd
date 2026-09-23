@echo off
setlocal
cd /d "%~dp0.."
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-phase0-tests.ps1" %*
set EXITCODE=%ERRORLEVEL%
echo.
if %EXITCODE% EQU 0 (
  echo Phase 0 validation completed successfully.
) else (
  echo Phase 0 validation failed. Review the generated log in test-logs.
)
echo.
pause
exit /b %EXITCODE%

@echo off
setlocal
cd /d "%~dp0.."
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-phase1-tests.ps1" -Release %*
set EXITCODE=%ERRORLEVEL%
echo.
if %EXITCODE% EQU 0 (
  echo Phase 1 validation completed successfully.
) else (
  echo Phase 1 validation failed. Review the generated log in test-logs.
)
echo.
pause
exit /b %EXITCODE%

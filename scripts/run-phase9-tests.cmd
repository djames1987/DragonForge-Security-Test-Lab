@echo off
setlocal
cd /d "%~dp0.."
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-phase9-tests.ps1" -Release %*
set EXITCODE=%ERRORLEVEL%
echo.
if %EXITCODE% EQU 0 (
  echo Phase 9 validation completed successfully.
) else (
  echo Phase 9 validation failed. Review the generated log in test-logs.
)
echo.
pause
exit /b %EXITCODE%

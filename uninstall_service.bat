@echo off
setlocal enabledelayedexpansion

REM ============================================================
REM  MKDSS VMS Server - Windows Service Uninstaller
REM ============================================================
REM  Stops and removes the "MKDSS VMS Server" Windows service.
REM  This does NOT delete your data (vms_accounts.db is untouched) -
REM  it only removes the auto-start service registration. You can
REM  always run install_service.bat again later to re-add it.
REM ============================================================

set SERVICE_NAME=VMSServer
set SCRIPT_DIR=%~dp0

echo.
echo === MKDSS VMS Server - Service Uninstaller ===
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator.
    echo Right-click this file and choose "Run as administrator", then try again.
    pause
    exit /b 1
)

set NSSM_CMD=
if exist "%SCRIPT_DIR%nssm.exe" (
    set NSSM_CMD=%SCRIPT_DIR%nssm.exe
) else (
    where nssm >nul 2>nul
    if !errorlevel! equ 0 (
        set NSSM_CMD=nssm
    )
)
if "%NSSM_CMD%"=="" (
    echo ERROR: nssm.exe not found. It should be in this same folder.
    pause
    exit /b 1
)

"%NSSM_CMD%" status %SERVICE_NAME% >nul 2>&1
if %errorlevel% neq 0 (
    echo No "%SERVICE_NAME%" service is currently installed. Nothing to do.
    pause
    exit /b 0
)

echo Stopping the service...
"%NSSM_CMD%" stop %SERVICE_NAME%

echo Removing the service...
"%NSSM_CMD%" remove %SERVICE_NAME% confirm

echo.
echo Done. The service has been removed.
echo Your data (vms_accounts.db) has NOT been touched.
echo You can run install_service.bat again any time to re-add the service.
pause

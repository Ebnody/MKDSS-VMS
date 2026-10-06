@echo off
setlocal enabledelayedexpansion

REM ============================================================
REM  MKDSS VMS Server - Restart Service
REM ============================================================
REM  Use this after updating vms_server.py, so the running service
REM  picks up the new code (it doesn't reload automatically).
REM ============================================================

set SERVICE_NAME=VMSServer
set SCRIPT_DIR=%~dp0

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator.
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

echo Restarting "%SERVICE_NAME%"...
"%NSSM_CMD%" restart %SERVICE_NAME%
echo Done.
pause

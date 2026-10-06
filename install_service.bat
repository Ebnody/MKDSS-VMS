@echo off
setlocal enabledelayedexpansion

REM ============================================================
REM  MKDSS VMS Server - Windows Service Installer
REM ============================================================
REM  This makes vms_server.py run as a real Windows Service:
REM    - Starts automatically when this PC boots
REM    - Keeps running even if nobody is logged in
REM    - Restarts itself automatically if it ever crashes
REM
REM  PREREQUISITE (one-time, manual):
REM    1. Download NSSM from https://nssm.cc/download
REM    2. Unzip it
REM    3. Copy nssm.exe from the "win64" folder into THIS SAME FOLDER
REM       (the one this .bat file is in)
REM    4. Then run this script (right-click -> Run as administrator)
REM ============================================================

set SERVICE_NAME=VMSServer
set SCRIPT_DIR=%~dp0
set SERVER_SCRIPT=%SCRIPT_DIR%vms_server.py

echo.
echo === MKDSS VMS Server - Service Installer ===
echo.

REM --- Check for admin rights ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator.
    echo Right-click this file and choose "Run as administrator", then try again.
    pause
    exit /b 1
)

REM --- Check for nssm.exe ---
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
    echo ERROR: nssm.exe not found.
    echo.
    echo Download it from https://nssm.cc/download, unzip it, and copy
    echo nssm.exe from the win64 folder into this same folder:
    echo   %SCRIPT_DIR%
    echo Then run this script again.
    pause
    exit /b 1
)

REM --- Check for Python ---
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: python.exe not found on PATH.
    echo Make sure Python is installed and added to PATH, then try again.
    pause
    exit /b 1
)
for /f "delims=" %%i in ('where python') do (
    set "PYTHON_PATH=%%i"
    goto :python_path_found
)
:python_path_found

REM --- Check the server script actually exists here ---
if not exist "%SERVER_SCRIPT%" (
    echo ERROR: Could not find vms_server.py in this folder:
    echo   %SCRIPT_DIR%
    echo Make sure this .bat file is in the same folder as vms_server.py.
    pause
    exit /b 1
)

echo Using Python: %PYTHON_PATH%
echo Using NSSM:   %NSSM_CMD%
echo Server file:  %SERVER_SCRIPT%
echo.

REM --- If the service already exists, stop/remove it first (safe re-install) ---
"%NSSM_CMD%" status %SERVICE_NAME% >nul 2>&1
if %errorlevel% equ 0 (
    echo An existing "%SERVICE_NAME%" service was found - removing it first...
    "%NSSM_CMD%" stop %SERVICE_NAME% >nul 2>&1
    "%NSSM_CMD%" remove %SERVICE_NAME% confirm >nul 2>&1
)

echo Installing the service...
"%NSSM_CMD%" install %SERVICE_NAME% "%PYTHON_PATH%" "-u" "%SERVER_SCRIPT%"
"%NSSM_CMD%" set %SERVICE_NAME% AppDirectory "%SCRIPT_DIR%"
"%NSSM_CMD%" set %SERVICE_NAME% DisplayName "MKDSS VMS Server"
"%NSSM_CMD%" set %SERVICE_NAME% Description "Central server for the MKDSS Smart Card Factory Visitor Management System. Do not stop unless instructed by IT."
"%NSSM_CMD%" set %SERVICE_NAME% Start SERVICE_AUTO_START
"%NSSM_CMD%" set %SERVICE_NAME% AppStdout "%SCRIPT_DIR%vms_server_output.log"
"%NSSM_CMD%" set %SERVICE_NAME% AppStderr "%SCRIPT_DIR%vms_server_error.log"
"%NSSM_CMD%" set %SERVICE_NAME% AppRotateFiles 1
"%NSSM_CMD%" set %SERVICE_NAME% AppRotateBytes 1048576
"%NSSM_CMD%" set %SERVICE_NAME% AppExit Default Restart
"%NSSM_CMD%" set %SERVICE_NAME% AppRestartDelay 5000

echo.
echo Starting the service...
"%NSSM_CMD%" start %SERVICE_NAME%

echo.
echo ============================================================
echo  Done. The VMS server is now running as a Windows service.
echo ============================================================
echo  - It will start automatically when this PC boots
echo  - It will restart automatically if it crashes
echo  - It keeps running even if nobody is logged into this PC
echo.
echo  Logs (useful if something looks wrong):
echo    %SCRIPT_DIR%vms_server_output.log
echo    %SCRIPT_DIR%vms_server_error.log
echo.
echo  To check on it: open services.msc and look for "MKDSS VMS Server"
echo  To stop/start/remove it: use uninstall_service.bat, or services.msc
echo ============================================================
pause

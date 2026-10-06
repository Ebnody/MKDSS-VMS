@echo off
setlocal
REM ============================================================
REM  MKDSS VMS - Create Desktop Shortcut
REM ============================================================
REM  Run this ONCE on each PC (Admin, Officer, each Host) after
REM  you've copied VMS_App.exe onto that PC. It creates a
REM  "VMS App" icon on the Desktop, just like a normal installed
REM  app, with the MKDSS logo as its icon.
REM
REM  Put this file in the SAME folder as VMS_App.exe, then
REM  double-click it. That's it - one time only, per PC.
REM ============================================================
set SCRIPT_DIR=%~dp0

if not exist "%SCRIPT_DIR%VMS_App.exe" (
    echo ERROR: VMS_App.exe not found in this folder:
    echo   %SCRIPT_DIR%
    echo Put this .bat file in the same folder as VMS_App.exe and try again.
    pause
    exit /b 1
)

echo Creating Desktop shortcut...
powershell -NoProfile -Command ^
    "$s = (New-Object -COMObject WScript.Shell).CreateShortcut([System.IO.Path]::Combine([Environment]::GetFolderPath('Desktop'), 'VMS App.lnk'));" ^
    "$s.TargetPath = '%SCRIPT_DIR%VMS_App.exe';" ^
    "$s.WorkingDirectory = '%SCRIPT_DIR%';" ^
    "$s.IconLocation = '%SCRIPT_DIR%VMS_App.exe,0';" ^
    "$s.Description = 'MKDSS Visitor Management System';" ^
    "$s.Save()"

if %errorlevel% equ 0 (
    echo.
    echo Done - "VMS App" now appears on this PC's Desktop with the MKDSS logo.
) else (
    echo.
    echo Something went wrong creating the shortcut. You can still just
    echo double-click VMS_App.exe directly in this folder.
)
pause

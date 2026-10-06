@echo off
setlocal

REM MKDSS VMS Client - Build Standalone exe
REM Packages VMS_App.pyw into VMS_App.exe so it runs on any Windows PC
REM without needing Python installed.
REM Run this on a PC that has Python plus whichever client packages that
REM PC needs already installed - Officer PCs need more than Admin/Host PCs
REM since Officer PCs do ID scanning.
REM Only bundles cv2/pyzbar if they are actually installed on THIS PC, so
REM the build no longer fails on Admin/Host PCs that do not have them.

set SCRIPT_DIR=%~dp0

echo.
echo === MKDSS VMS Client - Build .exe ===
echo.

where python >nul 2>nul
if errorlevel 1 goto no_python

if not exist "%SCRIPT_DIR%VMS_App.pyw" goto no_pyw

if exist "%SCRIPT_DIR%mkdss_logo_transparent.png" goto have_logo
echo ERROR: mkdss_logo_transparent.png not found in this folder.
echo The app will still build without it, but the logo will not show.
echo Press any key to continue anyway, or close this window to stop.
pause
:have_logo

set ICON_ARG=
if not exist "%SCRIPT_DIR%mkdss_icon.ico" goto no_icon
set ICON_ARG=--icon "%SCRIPT_DIR%mkdss_icon.ico"
goto icon_done
:no_icon
echo WARNING: mkdss_icon.ico not found - the .exe will use the default
echo blank Python icon instead of the MKDSS logo. Put mkdss_icon.ico in
echo this same folder to fix that.
:icon_done

set CV2_ARG=
python -c "import cv2" >nul 2>nul
if errorlevel 1 goto no_cv2
set CV2_ARG=--collect-all cv2
goto cv2_done
:no_cv2
echo NOTE: cv2 - opencv-python - is not installed on this PC, so webcam
echo scanning will be skipped in this build. That is fine unless this
echo is meant to be the Officer PC build.
:cv2_done

set PYZBAR_ARG=
python -c "import pyzbar" >nul 2>nul
if errorlevel 1 goto no_pyzbar
set PYZBAR_ARG=--collect-all pyzbar
goto pyzbar_done
:no_pyzbar
echo NOTE: pyzbar is not installed on this PC, so QR/barcode decoding
echo will be skipped in this build. That is fine unless this is meant
echo to be the Officer PC build.
:pyzbar_done

echo Installing/upgrading PyInstaller...
python -m pip install --upgrade pyinstaller

echo.
echo Building VMS_App.exe - this can take a few minutes...
echo.

python -m PyInstaller --onefile --windowed --name VMS_App %ICON_ARG% --add-data "%SCRIPT_DIR%mkdss_logo_transparent.png;." --hidden-import PIL._tkinter_finder %PYZBAR_ARG% %CV2_ARG% --exclude-module matplotlib --exclude-module scipy --exclude-module pandas "%SCRIPT_DIR%VMS_App.pyw"

if not exist "%SCRIPT_DIR%dist\VMS_App.exe" goto build_failed

echo.
echo ============================================================
echo  SUCCESS: %SCRIPT_DIR%dist\VMS_App.exe
echo ============================================================
echo  This ONE file is now everything you need to copy to other
echo  PCs - they do NOT need Python installed to run it.
echo.
echo  If this PC has opencv/pytesseract/pywin32/pyzbar installed
echo  - i.e. this is your Officer PC - those scanning features are
echo  now baked into this .exe automatically. Tesseract itself
echo  still needs to be installed separately either way.
echo ============================================================
echo.
echo Creating Desktop shortcut on this PC...

powershell -NoProfile -Command "$s = (New-Object -COMObject WScript.Shell).CreateShortcut([System.IO.Path]::Combine([Environment]::GetFolderPath('Desktop'), 'VMS App.lnk')); $s.TargetPath = '%SCRIPT_DIR%dist\VMS_App.exe'; $s.WorkingDirectory = '%SCRIPT_DIR%dist'; $s.IconLocation = '%SCRIPT_DIR%dist\VMS_App.exe,0'; $s.Description = 'MKDSS Visitor Management System'; $s.Save()"

if errorlevel 1 goto shortcut_failed
echo Desktop shortcut created: VMS App on this PC's Desktop.
goto end

:shortcut_failed
echo Could not auto-create the Desktop shortcut. You can still just
echo double-click dist\VMS_App.exe directly.
goto end

:no_python
echo ERROR: python.exe not found on PATH.
pause
exit /b 1

:no_pyw
echo ERROR: VMS_App.pyw not found in this folder:
echo   %SCRIPT_DIR%
echo Make sure this .bat file is in the same folder as VMS_App.pyw.
pause
exit /b 1

:build_failed
echo.
echo ============================================================
echo  BUILD FAILED - VMS_App.exe was not created.
echo  Scroll up to see the actual error from PyInstaller.
echo ============================================================
pause
exit /b 1

:end
echo ============================================================
pause

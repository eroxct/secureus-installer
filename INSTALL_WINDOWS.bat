@echo off
setlocal enabledelayedexpansion
title SecureUS Installer

echo.
echo  =============================================
echo   SecureUS Network Monitor  Windows Installer
echo  =============================================
echo.

:: Find the wheel in dist\ next to this script
set "SCRIPT_DIR=%~dp0"
set "WHL="
for %%f in ("%SCRIPT_DIR%dist\secureus-*.whl") do set "WHL=%%f"

if not defined WHL (
    echo  [!] Could not find the SecureUS package in dist\
    echo  Make sure you extracted the full zip before running this.
    pause
    exit /b 1
)

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [!] Python not found. Opening the Python download page...
    start https://www.python.org/downloads/
    echo.
    echo  Install Python 3.9 or later.
    echo  Tick "Add Python to PATH", then run this again.
    echo.
    pause
    exit /b 1
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  [OK] Python %PYVER% found.

python -m pip --version >nul 2>&1
if errorlevel 1 ( python -m ensurepip --upgrade >nul 2>&1 )
echo  [OK] pip is ready.

echo  [..] Updating pip...
python -m pip install --upgrade pip --quiet

echo  [..] Installing SecureUS Monitor...
echo       (This may take a few minutes on first install)
echo.
python -m pip install "%WHL%" --quiet --progress-bar on

if errorlevel 1 (
    echo  [!] Retrying with full output...
    python -m pip install "%WHL%"
    if errorlevel 1 (
        echo  [ERROR] Installation failed. Visit https://secureus.com/support
        pause
        exit /b 1
    )
)
echo  [OK] SecureUS installed!

echo  [..] Creating shortcuts...
:: Find where pip installed the secureus-monitor script
for /f "delims=" %%P in ('python -c "import sys; print(sys.prefix)" 2^>nul') do set "PYPREFIX=%%P"
set "MONITOR_EXE=%PYPREFIX%\Scripts\secureus-monitor.exe"
if not exist "%MONITOR_EXE%" set "MONITOR_EXE=%PYPREFIX%\Scripts\secureus-monitor"

:: Create a proper .lnk shortcut so the window shows normally
set "LNK=%USERPROFILE%\Desktop\SecureUS Monitor.lnk"
set "SM=%APPDATA%\Microsoft\Windows\Start Menu\Programs\SecureUS"
if not exist "%SM%" mkdir "%SM%"

:: Use PowerShell to create the .lnk (avoids the hidden-window VBS bug)
powershell -NoProfile -Command ^
  "$s=(New-Object -COM WScript.Shell).CreateShortcut('%LNK%');" ^
  "$s.TargetPath='%MONITOR_EXE%';" ^
  "$s.WorkingDirectory='%USERPROFILE%';" ^
  "$s.WindowStyle=1;" ^
  "$s.Description='SecureUS Network Monitor';" ^
  "$s.Save()"

powershell -NoProfile -Command ^
  "$s=(New-Object -COM WScript.Shell).CreateShortcut('%SM%\SecureUS Monitor.lnk');" ^
  "$s.TargetPath='%MONITOR_EXE%';" ^
  "$s.WorkingDirectory='%USERPROFILE%';" ^
  "$s.WindowStyle=1;" ^
  "$s.Description='SecureUS Network Monitor';" ^
  "$s.Save()"
echo  [OK] Desktop and Start Menu shortcuts created.

echo.
echo  =============================================
echo   Done! SecureUS Monitor is installed.
echo  =============================================
echo.
echo  Double-click "SecureUS Monitor" on your Desktop to open the app.
echo  It scans your network, shows all devices, and flags any threats.
echo.
set /p LAUNCH="  Launch SecureUS Monitor now? (Y/N): "
if /i "!LAUNCH!"=="Y" ( start "" "%MONITOR_EXE%" )

echo.
pause

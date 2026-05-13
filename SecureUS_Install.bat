@echo off
setlocal enabledelayedexpansion
title SecureUS Installer
echo.
echo  =============================================
echo   SecureUS Network Monitor  Windows Installer
echo  =============================================
echo.
python --version >nul 2>&1
if errorlevel 1 (
    echo  [!] Python not found. Opening the Python download page...
    start https://www.python.org/downloads/
    echo.
    echo  Install Python 3.9 or later.
    echo  On the first screen tick Add Python to PATH.
    echo  Then double-click this installer again.
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
echo  [..] Installing dependencies...
echo       This may take a few minutes on first install
echo.
python -m pip install flask werkzeug numpy pandas scikit-learn xgboost shap lime PyQt5 --quiet
if errorlevel 1 (
    echo  [ERROR] Failed to install dependencies.
    echo  Please visit https://secureus-yv9w.onrender.com/support
    pause
    exit /b 1
)
echo  [OK] Dependencies installed.
echo  [..] Installing SecureUS app...
python -m pip uninstall secureus -y >nul 2>&1
python -m pip cache purge >nul 2>&1
python -m pip install --no-cache-dir https://github.com/eroxct/secureus-installer/archive/refs/heads/release.zip --quiet
if errorlevel 1 (
    echo  [ERROR] Could not install SecureUS app.
    echo  Please visit https://secureus-yv9w.onrender.com/support
    pause
    exit /b 1
)
echo  [OK] SecureUS installed successfully!
echo  [..] Verifying installation...
python -m pip show secureus | findstr /i "version location"
echo  [..] Creating desktop shortcut...
for /f "tokens=2 delims= " %%p in ('python -c "import sys; print(sys.executable)"') do set PYEXE=%%p
for /f %%p in ('python -c "import sys,os; print(os.path.join(os.path.dirname(sys.executable), 'Scripts', 'secureus-monitor.exe'))"') do set MONITOR_EXE=%%p
set VBS=%USERPROFILE%\Desktop\SecureUS Monitor.vbs
(
echo Set WshShell = CreateObject^("WScript.Shell"^)
echo WshShell.Run "%MONITOR_EXE%", 1, False
) > "%VBS%"
set SM=%APPDATA%\Microsoft\Windows\Start Menu\Programs\SecureUS
if not exist "%SM%" mkdir "%SM%"
copy "%VBS%" "%SM%\SecureUS Monitor.vbs" >nul 2>&1
echo  [OK] Shortcuts created ^(pointing to %MONITOR_EXE%^)
echo.
echo  =============================================
echo   Done! SecureUS Monitor is installed.
echo  =============================================
echo.
echo  Double-click SecureUS Monitor on your Desktop to open the app.
echo.
set /p LAUNCH=  Launch SecureUS Monitor now? (Y/N): 
if /i "!LAUNCH!"=="Y" ( start "" secureus-monitor )
echo.
pause

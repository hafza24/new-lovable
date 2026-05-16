@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo [Sentinel Net] Cleaning previous build output...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
mkdir dist\assets dist\config dist\logs dist\drivers

echo [Sentinel Net] Installing build dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo [Sentinel Net] Building SentinelAgent.exe...
pyinstaller --noconfirm --clean --onefile --name SentinelAgent --hidden-import win32timezone --collect-submodules sentinel_net agent.py

echo [Sentinel Net] Building SentinelTray.exe...
pyinstaller --noconfirm --clean --onefile --windowed --name SentinelTray --collect-submodules sentinel_net tray.py

echo [Sentinel Net] Building SentinelWatchdog.exe...
pyinstaller --noconfirm --clean --onefile --name SentinelWatchdog --hidden-import win32timezone --collect-submodules sentinel_net watchdog.py

echo [Sentinel Net] Building SentinelInstaller.exe...
pyinstaller --noconfirm --clean --onefile --uac-admin --name SentinelInstaller --collect-submodules sentinel_net installer.py

echo [Sentinel Net] Bundling assets and configuration...
xcopy /E /I /Y sentinel_net\assets dist\assets >nul
xcopy /E /I /Y sentinel_net\config dist\config >nul
xcopy /E /I /Y sentinel_net\drivers dist\drivers >nul
copy /Y requirements.txt dist\requirements.txt >nul

echo [Sentinel Net] Final output:
dir dist

echo [Sentinel Net] Build complete.
endlocal

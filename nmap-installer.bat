@echo off
setlocal

REM Detect OS
if "%OS%"=="Windows_NT" (
    echo Operating System: Windows
) else (
    echo This script is only supported on Windows.
    pause
    exit /b 1
)

REM Define Nmap download URL
set NMAP_URL=https://nmap.org/dist/nmap-7.91-setup.exe
set NMAP_INSTALLER=nmap-7.91-setup.exe

REM Download Nmap
echo Downloading Nmap...
powershell -Command "Invoke-WebRequest -Uri %NMAP_URL% -OutFile %NMAP_INSTALLER%"
if %ERRORLEVEL% neq 0 (
    echo Failed to download Nmap.
    pause
    exit /b 1
)

REM Install Nmap
echo Installing Nmap...
start /wait %NMAP_INSTALLER% /S
if %ERRORLEVEL% neq 0 (
    echo Failed to install Nmap.
    pause
    exit /b 1
)

REM Cleanup installer
del %NMAP_INSTALLER%

REM Launch Nmap
echo Launching Nmap...
start nmap

echo Nmap has been successfully installed and launched.
pause

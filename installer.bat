@echo off
echo Installing required packages...

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed. Please install Python and run this script again.
    pause
    exit /b
)

echo Upgrading pip...
python -m pip install --upgrade pip

echo Installing Python packages...
pip install nmap
pip install requests
pip install pystyle
pip install colorama

where nmap >nul 2>&1
if %errorlevel% neq 0 (
    echo Nmap is not installed. Please install Nmap and run this script again.
    pause
    exit /b
)

echo All required packages have been installed.
pause

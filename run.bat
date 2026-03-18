@echo off
REM Advanced Threat Intelligence Dashboard - Launch Script

echo.
echo   ^|^^| THREAT INTELLIGENCE DASHBOARD ||
echo   Glassmorphism OSINT Command Center v2.0
echo.

REM Check if .env file exists
if not exist .env (
    echo [!] WARNING: .env file not found!
    echo [*] Copying .env.example to .env
    copy .env.example .env
    echo [*] Please edit .env with your API keys
    echo.
)

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [X] Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

REM Install/Update dependencies
echo [*] Installing/updating dependencies...
python -m pip install -q flask requests python-dotenv flask-cors sqlalchemy
if errorlevel 1 (
    echo [X] Failed to install dependencies
    pause
    exit /b 1
)

echo [✓] Dependencies ready
echo.
echo [*] Starting Threat Intelligence Dashboard...
echo [*] Open browser: http://localhost:5001
echo [*] Press Ctrl+C to stop the server
echo.

python app.py

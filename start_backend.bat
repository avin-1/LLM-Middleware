@echo off
echo ======================================================================
echo 🚀 SENTINEL Backend - Quick Start
echo ======================================================================
echo.

REM Check if virtual environment exists
if not exist ".venv\Scripts\activate.bat" (
    echo ❌ Virtual environment not found!
    echo.
    echo Creating virtual environment...
    python -m venv .venv
    echo ✅ Virtual environment created
    echo.
)

echo Activating virtual environment...
call .venv\Scripts\activate.bat

echo.
echo Checking dependencies...
pip show fastapi >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
    echo ✅ Dependencies installed
) else (
    echo ✅ Dependencies already installed
)

echo.
echo ======================================================================
echo 🔄 Stopping any existing server on port 8000...
echo ======================================================================

for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000') do (
    echo Killing process: %%a
    taskkill /F /PID %%a 2>nul
)

echo.
echo ======================================================================
echo ✅ Starting SENTINEL Brain API...
echo ======================================================================
echo.
echo Server will be available at:
echo   - API: http://localhost:8000
echo   - Docs: http://localhost:8000/docs
echo   - Health: http://localhost:8000/health
echo.
echo Press Ctrl+C to stop the server
echo ======================================================================
echo.

python -m uvicorn src.brain.api.main:app --host 0.0.0.0 --port 8000 --reload

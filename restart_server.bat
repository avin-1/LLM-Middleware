@echo off
echo ======================================================================
echo 🔄 SENTINEL - Server Restart Script
echo ======================================================================
echo.

echo Step 1: Stopping old server...
echo.

REM Find and kill process on port 8000
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000') do (
    echo Found process: %%a
    taskkill /F /PID %%a 2>nul
    if errorlevel 1 (
        echo No process found on port 8000
    ) else (
        echo ✅ Process killed successfully
    )
)

echo.
echo Step 2: Waiting 2 seconds...
timeout /t 2 /nobreak >nul

echo.
echo Step 3: Starting fresh server...
echo.
echo ⚠️  Server will start in a NEW window
echo ⚠️  Keep that window open!
echo.

REM Start server in new window
start "SENTINEL Brain API" cmd /k "cd /d %~dp0 && .venv\Scripts\activate && python -m uvicorn src.brain.api.main:app --host 0.0.0.0 --port 8000"

echo.
echo ✅ Server starting in new window...
echo.
echo Wait for: "Uvicorn running on http://0.0.0.0:8000"
echo.
echo Then run: python test_real_datasets.py
echo.
echo ======================================================================
pause

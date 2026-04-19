@echo off
echo ======================================================================
echo 🔄 FORCE RESTART - Killing old backend and starting fresh
echo ======================================================================
echo.

echo Killing all Python processes on port 8000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000') do (
    taskkill /F /PID %%a 2>nul
)

echo.
echo Waiting 2 seconds...
timeout /t 2 /nobreak >nul

echo.
echo ======================================================================
echo ✅ Starting Fresh Backend with .env loaded
echo ======================================================================
echo.
echo Look for these lines:
echo   "LLM Service initialized with model: gpt2"
echo   "API Key configured: hf_hgNp..."
echo.
echo If you see "without API key", something is wrong!
echo.
echo ======================================================================
echo.

python -m uvicorn src.brain.api.main:app --host 0.0.0.0 --port 8000 --reload

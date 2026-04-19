@echo off
echo ======================================================================
echo 📦 Installing OpenAI SDK
echo ======================================================================
echo.

echo Activating virtual environment...
call .venv\Scripts\activate.bat

echo.
echo Installing openai package...
pip install openai

echo.
echo ======================================================================
echo ✅ Installation Complete!
echo ======================================================================
echo.
echo Next steps:
echo 1. Restart backend: force_restart.bat
echo 2. Test in frontend: http://localhost:3000
echo.
echo ======================================================================
pause

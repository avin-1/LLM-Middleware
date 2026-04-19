@echo off
echo ======================================================================
echo 🤖 SENTINEL Brain - LLM Setup
echo ======================================================================
echo.

REM Check if .env exists
if exist ".env" (
    echo ✅ .env file found
) else (
    echo Creating .env from .env.example...
    copy .env.example .env
    echo ✅ .env file created
)

echo.
echo ======================================================================
echo Configuration Steps:
echo ======================================================================
echo.
echo 1. Get your Hugging Face API key:
echo    👉 https://huggingface.co/settings/tokens
echo.
echo 2. Open .env file and add:
echo    HUGGINGFACE_API_KEY=hf_your_token_here
echo.
echo 3. Choose a model (optional, default is gpt2):
echo    LLM_MODEL=gpt2
echo.
echo 4. Save the file
echo.
echo ======================================================================
echo.

set /p OPEN_ENV="Open .env file now? (y/n): "
if /i "%OPEN_ENV%"=="y" (
    notepad .env
)

echo.
echo ======================================================================
echo Next Steps:
echo ======================================================================
echo.
echo 1. Configure your API key in .env
echo 2. Run: start_backend.bat
echo 3. Run: cd front ^&^& npm run dev
echo 4. Open: http://localhost:3000
echo.
echo ======================================================================
pause

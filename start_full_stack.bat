@echo off
echo Starting SENTINEL Brain Full Stack...
echo.

echo Starting Backend API on port 8000...
start "SENTINEL Backend" cmd /k "python -m uvicorn src.brain.api.main:app --reload --port 8000"

timeout /t 3 /nobreak > nul

echo Starting Frontend on port 3000...
start "SENTINEL Frontend" cmd /k "cd front && npm run dev"

echo.
echo Full stack started!
echo Backend: http://localhost:8000
echo Frontend: http://localhost:3000
echo.
echo Press any key to exit this window (servers will keep running)...
pause > nul

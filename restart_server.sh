#!/bin/bash
# Bash script to restart SENTINEL Brain API server

echo "Stopping any existing server on port 8000..."

# Find and kill process on port 8000
PID=$(netstat -ano | findstr :8000 | awk '{print $5}' | head -1)
if [ ! -z "$PID" ]; then
    taskkill //F //PID $PID
    echo "Stopped process $PID"
    sleep 2
else
    echo "No process found on port 8000"
fi

echo ""
echo "Starting SENTINEL Brain API server..."
echo "Server will be available at: http://localhost:8000"
echo "API Documentation: http://localhost:8000/docs"
echo ""
echo "Press CTRL+C to stop the server"
echo ""

# Start the server
python -m uvicorn src.brain.api.main:app --host 0.0.0.0 --port 8000

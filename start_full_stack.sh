#!/bin/bash

echo "Starting SENTINEL Brain Full Stack..."
echo ""

echo "Starting Backend API on port 8000..."
python -m uvicorn src.brain.api.main:app --reload --port 8000 &
BACKEND_PID=$!

sleep 3

echo "Starting Frontend on port 3000..."
cd front && npm run dev &
FRONTEND_PID=$!

echo ""
echo "Full stack started!"
echo "Backend: http://localhost:8000"
echo "Frontend: http://localhost:3000"
echo ""
echo "Press Ctrl+C to stop both servers"

# Wait for Ctrl+C
trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT
wait

#!/bin/bash

echo "======================================================================"
echo "🚀 SENTINEL Backend - Quick Start"
echo "======================================================================"
echo ""

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "❌ Virtual environment not found!"
    echo ""
    echo "Creating virtual environment..."
    python3 -m venv .venv
    echo "✅ Virtual environment created"
    echo ""
fi

echo "Activating virtual environment..."
source .venv/bin/activate

echo ""
echo "Checking dependencies..."
if ! pip show fastapi > /dev/null 2>&1; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
    echo "✅ Dependencies installed"
else
    echo "✅ Dependencies already installed"
fi

echo ""
echo "======================================================================"
echo "🔄 Stopping any existing server on port 8000..."
echo "======================================================================"

# Kill any process on port 8000
lsof -ti:8000 | xargs kill -9 2>/dev/null || echo "No existing server found"

echo ""
echo "======================================================================"
echo "✅ Starting SENTINEL Brain API..."
echo "======================================================================"
echo ""
echo "Server will be available at:"
echo "  - API: http://localhost:8000"
echo "  - Docs: http://localhost:8000/docs"
echo "  - Health: http://localhost:8000/health"
echo ""
echo "Press Ctrl+C to stop the server"
echo "======================================================================"
echo ""

python -m uvicorn src.brain.api.main:app --host 0.0.0.0 --port 8000 --reload

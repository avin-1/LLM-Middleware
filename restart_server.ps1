# SENTINEL Brain API - Server Restart Script
# This script stops the current server and starts a fresh one

Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 69) -ForegroundColor Cyan
Write-Host "SENTINEL Brain API - Server Restart" -ForegroundColor Yellow
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 69) -ForegroundColor Cyan
Write-Host ""

# Step 1: Find and kill existing server
Write-Host "Step 1: Stopping existing server..." -ForegroundColor Yellow
$port = 8000
$connections = netstat -ano | Select-String ":$port"

if ($connections) {
    $connections | ForEach-Object {
        $line = $_.Line
        if ($line -match "\s+(\d+)\s*$") {
            $pid = $matches[1]
            Write-Host "  Found server on PID: $pid" -ForegroundColor Cyan
            try {
                Stop-Process -Id $pid -Force -ErrorAction Stop
                Write-Host "  ✓ Server stopped successfully" -ForegroundColor Green
                Start-Sleep -Seconds 2
            } catch {
                Write-Host "  ✗ Failed to stop server: $_" -ForegroundColor Red
            }
        }
    }
} else {
    Write-Host "  No server running on port $port" -ForegroundColor Gray
}

Write-Host ""

# Step 2: Start new server
Write-Host "Step 2: Starting server with latest code..." -ForegroundColor Yellow
Write-Host "  Server will start on: http://localhost:8000" -ForegroundColor Cyan
Write-Host "  API endpoint: http://localhost:8000/api/v1/analyze" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Press Ctrl+C to stop the server" -ForegroundColor Gray
Write-Host ""
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 69) -ForegroundColor Cyan
Write-Host ""

# Start server
python -m uvicorn src.brain.api.main:app --host 0.0.0.0 --port 8000

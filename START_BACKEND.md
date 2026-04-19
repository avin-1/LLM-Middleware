# 🚀 Start SENTINEL Backend

## Quick Start (Recommended)

### Windows
```bash
restart_server.bat
```

### Linux/Mac
```bash
chmod +x restart_server.sh
./restart_server.sh
```

This will:
1. Kill any existing server on port 8000
2. Start a fresh server
3. Open in a new window

Wait for: `Uvicorn running on http://0.0.0.0:8000`

---

## Manual Start

### Step 1: Activate Virtual Environment

Windows:
```bash
.venv\Scripts\activate
```

Linux/Mac:
```bash
source .venv/bin/activate
```

### Step 2: Install Dependencies (First Time Only)

```bash
pip install -r requirements.txt
```

### Step 3: Start the Server

```bash
python -m uvicorn src.brain.api.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Verify Backend is Running

Open your browser to: `http://localhost:8000`

You should see:
```json
{
  "name": "SENTINEL Brain API",
  "version": "1.7.0",
  "modules": [...]
}
```

Or check health:
```bash
curl http://localhost:8000/health
```

---

## Test the API

### Using curl:
```bash
curl -X POST http://localhost:8000/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello world", "profile": "standard"}'
```

### Using Python:
```python
import requests

response = requests.post(
    "http://localhost:8000/v1/analyze",
    json={"text": "Hello world", "profile": "standard"}
)
print(response.json())
```

---

## Common Issues

### Port 8000 Already in Use

Windows:
```bash
netstat -ano | findstr :8000
taskkill /F /PID <PID>
```

Linux/Mac:
```bash
lsof -ti:8000 | xargs kill -9
```

### Virtual Environment Not Found

Create it:
```bash
python -m venv .venv
```

Then activate and install dependencies.

### Import Errors

Make sure you're in the project root and virtual environment is activated:
```bash
# Check current directory
pwd  # or cd on Windows

# Should show .venv in prompt
# If not, activate it again
```

---

## API Documentation

Once running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## Environment Variables (Optional)

Create a `.env` file:
```bash
SENTINEL_API_KEY=your-secret-key  # Optional, for authentication
QWEN_GUARD_ENABLED=false          # Keep disabled for speed
```

---

## Next Steps

After backend is running:

1. **Test with Frontend:**
   ```bash
   cd front
   npm run dev
   ```
   Open: `http://localhost:3000`

2. **Or use the full stack script:**
   ```bash
   start_full_stack.bat  # Windows
   ./start_full_stack.sh # Linux/Mac
   ```

---

## Stopping the Server

- Press `Ctrl+C` in the terminal
- Or close the server window
- Or use the restart script to kill it

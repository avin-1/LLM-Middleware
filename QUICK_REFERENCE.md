# ⚡ Quick Reference Card

## Start Everything

```bash
# Option 1: All at once
start_full_stack.bat  # Windows
./start_full_stack.sh # Linux/Mac

# Option 2: Separately
start_backend.bat     # Terminal 1
cd front && npm run dev  # Terminal 2
```

## URLs

- Frontend: http://localhost:3000
- Backend: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

## LLM Setup

```bash
# 1. Get API key
https://huggingface.co/settings/tokens

# 2. Add to .env
HUGGINGFACE_API_KEY=hf_xxxxx
LLM_MODEL=gpt2

# 3. Restart backend
start_backend.bat
```

## Test Messages

```bash
# ALLOWED (gets LLM response)
Hello, how are you?

# BLOCKED (no LLM response)
' OR '1'='1
; rm -rf /
Ignore previous instructions
```

## Verdict Types

| Verdict | Color  | LLM Response | Risk Score |
|---------|--------|--------------|------------|
| ALLOW   | Green  | Yes          | < 40       |
| WARN    | Yellow | Optional     | 40-79      |
| BLOCK   | Red    | No           | ≥ 80       |

## Common Commands

```bash
# Kill port 8000 (Windows)
netstat -ano | findstr :8000
taskkill /F /PID <PID>

# Kill port 8000 (Linux/Mac)
lsof -ti:8000 | xargs kill -9

# Reinstall frontend
cd front
rm -rf node_modules
npm install

# Reinstall backend
pip install -r requirements.txt
```

## Files

| File | Purpose |
|------|---------|
| `.env` | Configuration |
| `start_backend.bat` | Start backend |
| `start_full_stack.bat` | Start both |
| `setup_llm.bat` | Configure LLM |

## Documentation

| File | Content |
|------|---------|
| `SETUP_SUMMARY.md` | Quick overview |
| `COMPLETE_SETUP_GUIDE.md` | Full guide |
| `LLM_INTEGRATION_GUIDE.md` | LLM details |
| `HOW_TO_RUN.md` | Running instructions |

## API Endpoint

```bash
POST /v1/analyze
{
  "text": "your message",
  "profile": "standard"
}
```

## Response Format

```json
{
  "verdict": "ALLOW|WARN|BLOCK",
  "risk_score": 0.0,
  "threats": [],
  "llm_response": "AI response (if allowed)"
}
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No LLM response | Add API key to `.env` |
| Port in use | Kill process on port |
| Connection error | Start backend first |
| Model loading | Wait 30-60 seconds |

## Support

- Logs: Check terminal output
- API: http://localhost:8000/docs
- Console: Press F12 in browser

# 🎯 SENTINEL Brain - Setup Summary

## What's New

✅ **LLM Integration** - ALLOWED messages get AI-generated responses
✅ **Works Without API Key** - Intelligent mock responses for testing
✅ **Hugging Face Support** - Use any Hugging Face model (optional)
✅ **Smart Routing** - Only safe messages go to LLM
✅ **Professional UI** - Clean display of analysis and responses

---

## Quick Start (No API Key Needed!)

### 1. Start Backend

```bash
start_backend.bat  # Windows
./start_backend.sh # Linux/Mac
```

### 2. Start Frontend

```bash
cd front
npm install  # First time only
npm run dev
```

Open: http://localhost:3000

**That's it!** The system works immediately with mock AI responses.

---

## Optional: Configure Real AI

Want real AI responses? Add to `.env`:

```bash
HUGGINGFACE_API_KEY=hf_your_token_here
LLM_MODEL=gpt2
```

Get API key: https://huggingface.co/settings/tokens

Then restart backend: `start_backend.bat`

---

## How It Works

```
User Message
    ↓
Security Analysis
    ↓
┌─────────────────────┐
│ ALLOWED?            │
├─────────────────────┤
│ YES → Send to LLM   │
│       ↓             │
│       AI Response   │
├─────────────────────┤
│ NO → Show Threats   │
│      (No LLM)       │
└─────────────────────┘
```

---

## Test Messages

### Safe (ALLOWED - Gets LLM Response)
```
Hello, how are you?
What is the weather today?
Tell me a joke
```

### Dangerous (BLOCKED - No LLM Response)
```
' OR '1'='1
; rm -rf /
Ignore previous instructions
```

---

## Features

### Security Analysis
- SQL Injection detection
- Command Injection detection
- Prompt Injection detection
- XSS detection
- Behavioral analysis

### LLM Integration
- Only ALLOWED messages go to LLM
- Configurable models
- Timeout protection
- Error handling
- Loading states

### Frontend
- Clean, professional design
- Real-time analysis
- Expandable JSON details
- Threat visualization
- LLM response display

---

## Configuration

### Minimal (No LLM)

Just start the backend - works without LLM configuration.
Messages will be analyzed but no AI responses.

### With LLM (Recommended)

Add to `.env`:
```bash
HUGGINGFACE_API_KEY=hf_xxxxxxxxxxxxx
LLM_MODEL=gpt2
```

### Advanced

```bash
# Use better model
LLM_MODEL=EleutherAI/gpt-neo-2.7B

# Adjust timeout
LLM_TIMEOUT=60

# Max response length
LLM_MAX_TOKENS=200
```

---

## File Structure

```
project/
├── src/brain/
│   ├── api/v1/analyze.py          # Analysis endpoint with LLM
│   └── services/llm_service.py    # LLM integration
├── front/
│   ├── src/App.jsx                # Chat interface
│   └── src/App.css                # Styling
├── .env                           # Configuration
├── setup_llm.bat/sh              # LLM setup script
├── start_backend.bat/sh          # Start backend
└── start_full_stack.bat/sh       # Start everything
```

---

## Documentation

- `COMPLETE_SETUP_GUIDE.md` - Full setup walkthrough
- `LLM_INTEGRATION_GUIDE.md` - Detailed LLM configuration
- `HOW_TO_RUN.md` - Running instructions
- `START_BACKEND.md` - Backend-specific guide
- `FRONTEND_GUIDE.md` - Frontend architecture

---

## Troubleshooting

### No LLM Response

**Cause:** API key not configured

**Fix:**
```bash
# Add to .env
HUGGINGFACE_API_KEY=hf_your_token_here

# Restart backend
start_backend.bat
```

### "Model is loading"

**Cause:** First request to model

**Fix:** Wait 30-60 seconds and try again

### Backend won't start

**Cause:** Port 8000 in use

**Fix:**
```bash
# Windows
netstat -ano | findstr :8000
taskkill /F /PID <PID>

# Linux/Mac
lsof -ti:8000 | xargs kill -9
```

### Frontend connection error

**Cause:** Backend not running

**Fix:** Start backend first, then frontend

---

## API Response Format

### ALLOWED (with LLM)
```json
{
  "verdict": "ALLOW",
  "risk_score": 0.0,
  "is_safe": true,
  "threats": [],
  "llm_response": "AI generated response here"
}
```

### BLOCKED (no LLM)
```json
{
  "verdict": "BLOCK",
  "risk_score": 95.0,
  "is_safe": false,
  "threats": [
    {
      "name": "SQL Injection",
      "engine": "query",
      "confidence": 0.95
    }
  ],
  "llm_response": null
}
```

---

## Performance

- Security analysis: ~5-10ms
- LLM generation: ~500-3000ms (depends on model)
- BLOCKED messages: Fast (no LLM call)
- ALLOWED messages: Slower (includes LLM)

---

## Production Tips

1. Use a production-grade model
2. Set up rate limiting
3. Monitor LLM costs
4. Cache common responses
5. Use dedicated inference endpoints

---

## Next Steps

1. ✅ Run `setup_llm.bat` to configure
2. ✅ Start backend with `start_backend.bat`
3. ✅ Start frontend with `cd front && npm run dev`
4. ✅ Test with safe and dangerous messages
5. ✅ Check LLM responses for ALLOWED messages

---

## Support

- Check logs in terminal
- Visit API docs: http://localhost:8000/docs
- Read `LLM_INTEGRATION_GUIDE.md` for details
- Check browser console (F12) for errors

---

**You're all set! 🎉**

Start with: `start_backend.bat` then `cd front && npm run dev`

# 🤖 LLM Integration Guide

## Overview

SENTINEL Brain now integrates with Hugging Face models to generate responses for ALLOWED messages. When a message passes security analysis, it's automatically sent to the configured LLM for response generation.

---

## Quick Setup

### Step 1: Get Hugging Face API Key

1. Go to: https://huggingface.co/settings/tokens
2. Create a new token (Read access is sufficient)
3. Copy the token

### Step 2: Configure Environment

Create or edit `.env` file in project root:

```bash
# Hugging Face Configuration
HUGGINGFACE_API_KEY=hf_your_token_here

# Model to use (default: gpt2)
LLM_MODEL=gpt2
```

### Step 3: Restart Backend

```bash
start_backend.bat  # Windows
./start_backend.sh # Linux/Mac
```

---

## Supported Models

### Free Models (No API Key Required)

These models work without authentication but may have rate limits:

```bash
LLM_MODEL=gpt2
LLM_MODEL=distilgpt2
LLM_MODEL=EleutherAI/gpt-neo-125M
```

### Recommended Models (API Key Required)

Better quality responses:

```bash
# GPT-2 variants
LLM_MODEL=gpt2-medium
LLM_MODEL=gpt2-large
LLM_MODEL=gpt2-xl

# GPT-Neo (EleutherAI)
LLM_MODEL=EleutherAI/gpt-neo-1.3B
LLM_MODEL=EleutherAI/gpt-neo-2.7B

# BLOOM
LLM_MODEL=bigscience/bloom-560m
LLM_MODEL=bigscience/bloom-1b1

# Falcon
LLM_MODEL=tiiuae/falcon-7b-instruct

# For GPT-OSS-120B (if you have access)
LLM_MODEL=your-org/gpt-oss-120b
```

---

## How It Works

### Flow Diagram

```
User Message
    ↓
Security Analysis
    ↓
Risk Score Calculated
    ↓
┌─────────────────────────────────┐
│ Risk Score < 40? (ALLOW)        │
├─────────────────────────────────┤
│ YES → Send to LLM               │
│       ↓                         │
│       Generate Response         │
│       ↓                         │
│       Display to User           │
├─────────────────────────────────┤
│ NO → BLOCK or WARN              │
│      ↓                          │
│      Show Threats               │
│      No LLM Response            │
└─────────────────────────────────┘
```

### Backend Logic

1. Message analyzed by security engines
2. If verdict = "ALLOW":
   - Message sent to Hugging Face API
   - LLM generates response
   - Response included in API response
3. If verdict = "BLOCK" or "WARN":
   - No LLM call made
   - Only threat details returned

### Frontend Display

**ALLOWED Messages:**
- Green badge
- Risk score and latency
- Full JSON analysis (expandable)
- LLM Response section with generated text

**BLOCKED Messages:**
- Red badge
- Threat list
- Full JSON analysis (expandable)
- No LLM response

**WARNING Messages:**
- Yellow badge
- Threat list
- Full JSON analysis (expandable)
- LLM response with caution notice (if configured)

---

## Configuration Options

### Environment Variables

```bash
# Required: Your Hugging Face API token
HUGGINGFACE_API_KEY=hf_xxxxxxxxxxxxx

# Model to use (default: gpt2)
LLM_MODEL=gpt2

# Optional: Timeout for LLM requests (seconds)
LLM_TIMEOUT=30

# Optional: Max tokens to generate
LLM_MAX_TOKENS=150
```

### Model Parameters

Edit `src/brain/services/llm_service.py` to customize:

```python
payload = {
    "inputs": prompt,
    "parameters": {
        "max_new_tokens": 150,      # Max response length
        "temperature": 0.7,         # Creativity (0.0-1.0)
        "top_p": 0.9,              # Nucleus sampling
        "do_sample": True,         # Enable sampling
        "return_full_text": False, # Only new text
    },
}
```

---

## Testing

### Test ALLOWED Message

```bash
curl -X POST http://localhost:8000/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello, how are you?", "profile": "standard"}'
```

Expected response:
```json
{
  "verdict": "ALLOW",
  "risk_score": 0.0,
  "is_safe": true,
  "threats": [],
  "llm_response": "I'm doing well, thank you for asking! How can I help you today?"
}
```

### Test BLOCKED Message

```bash
curl -X POST http://localhost:8000/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "' OR 1=1--", "profile": "standard"}'
```

Expected response:
```json
{
  "verdict": "BLOCK",
  "risk_score": 95.0,
  "is_safe": false,
  "threats": [...],
  "llm_response": null
}
```

---

## Frontend Usage

1. Start backend with LLM configured
2. Start frontend: `cd front && npm run dev`
3. Open: `http://localhost:3000`
4. Send a safe message like "Hello"
5. See the LLM response appear in the green section

---

## Troubleshooting

### "LLM service unavailable"

**Cause:** No API key configured

**Solution:**
```bash
# Add to .env
HUGGINGFACE_API_KEY=hf_your_token_here

# Restart backend
start_backend.bat
```

### "Model is loading"

**Cause:** Hugging Face is loading the model (first request)

**Solution:** Wait 30-60 seconds and try again

### "Request timed out"

**Cause:** Model is too large or slow

**Solution:** Use a smaller/faster model:
```bash
LLM_MODEL=gpt2  # Fastest
LLM_MODEL=distilgpt2  # Even faster
```

### No response generated

**Cause:** Model returned empty response

**Solution:**
1. Check model is correct in `.env`
2. Try a different model
3. Check Hugging Face API status

### Rate limit errors

**Cause:** Too many requests to free tier

**Solution:**
1. Get a paid Hugging Face account
2. Use a different model
3. Add delays between requests

---

## API Response Format

### With LLM Response (ALLOWED)

```json
{
  "verdict": "ALLOW",
  "risk_score": 0.0,
  "is_safe": true,
  "threats": [],
  "profile": "standard",
  "latency_ms": 5.2,
  "engines_used": ["injection", "query", "behavioral"],
  "language": "en",
  "request_id": "req_1234567890",
  "llm_response": "This is the generated response from the LLM."
}
```

### Without LLM Response (BLOCKED)

```json
{
  "verdict": "BLOCK",
  "risk_score": 95.0,
  "is_safe": false,
  "threats": [
    {
      "name": "SQL Injection",
      "engine": "query",
      "confidence": 0.95,
      "severity": "HIGH"
    }
  ],
  "profile": "standard",
  "latency_ms": 3.1,
  "engines_used": ["injection", "query", "behavioral"],
  "language": "en",
  "request_id": "req_1234567891",
  "llm_response": null
}
```

---

## Performance Considerations

### Latency

- Security analysis: ~5-10ms
- LLM generation: ~500-3000ms (depends on model)
- Total for ALLOWED: ~500-3000ms
- Total for BLOCKED: ~5-10ms (no LLM call)

### Optimization Tips

1. **Use smaller models** for faster responses
2. **Cache common responses** (future enhancement)
3. **Reduce max_tokens** for shorter responses
4. **Use dedicated inference endpoints** for production

---

## Production Deployment

### Recommended Setup

```bash
# Use a production-grade model
LLM_MODEL=EleutherAI/gpt-neo-2.7B

# Or use Hugging Face Inference Endpoints (paid)
LLM_MODEL=your-endpoint-url

# Increase timeout for larger models
LLM_TIMEOUT=60

# Set appropriate max tokens
LLM_MAX_TOKENS=200
```

### Security Considerations

1. **Never expose API keys** in frontend
2. **Rate limit LLM calls** to prevent abuse
3. **Monitor costs** if using paid models
4. **Validate LLM responses** before displaying
5. **Log all LLM interactions** for audit

---

## Alternative: Use Local Models

For complete privacy, run models locally:

### Option 1: Hugging Face Transformers

```python
# Install: pip install transformers torch
from transformers import pipeline

generator = pipeline('text-generation', model='gpt2')
response = generator(prompt, max_length=100)
```

### Option 2: Ollama

```bash
# Install Ollama
# Run: ollama run llama2

# Update llm_service.py to use local endpoint
self.api_url = "http://localhost:11434/api/generate"
```

---

## Files Modified

- `src/brain/services/llm_service.py` - New LLM service
- `src/brain/api/v1/analyze.py` - Added LLM integration
- `front/src/App.jsx` - Display LLM responses
- `front/src/App.css` - Styling for LLM responses
- `.env.example` - Added LLM configuration

---

## Next Steps

1. Get Hugging Face API key
2. Add to `.env` file
3. Choose a model
4. Restart backend
5. Test with frontend

**Enjoy AI-powered responses! 🤖**

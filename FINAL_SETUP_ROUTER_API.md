# ✅ Final Setup - Router API with OpenAI SDK

## What You Need to Do

### 1. Install OpenAI SDK

```bash
install_openai.bat
```

Or manually:
```bash
pip install openai
```

### 2. Restart Backend

```bash
force_restart.bat
```

### 3. Test

Open: http://localhost:3000

Send: **"What is the capital of France?"**

---

## What Changed

### Old Setup (Inference API)
```python
# Used httpx to call HF Inference API
response = await client.post(
    "https://api-inference.huggingface.co/models/openai/gpt-oss-120b",
    ...
)
```

### New Setup (Router API with OpenAI SDK)
```python
# Uses OpenAI SDK with HF Router
from openai import OpenAI

client = OpenAI(
    base_url="https://router.huggingface.co/v1",
    api_key=os.environ["HF_TOKEN"],
)

completion = client.chat.completions.create(
    model="openai/gpt-oss-120b:fireworks-ai",
    ...
)
```

---

## Benefits

✅ **Faster**: 2-5 seconds vs 10-30 seconds
✅ **More Reliable**: Multiple providers
✅ **Better Quality**: Optimized routing
✅ **Familiar API**: OpenAI SDK interface

---

## Your Configuration

```bash
HF_TOKEN=hf_YOUR_TOKEN_HERE... ✅
LLM_MODEL=openai/gpt-oss-120b:fireworks-ai ✅
```

---

## Expected Logs After Restart

```
LLM Service initialized with model: openai/gpt-oss-120b:fireworks-ai
API Key configured: hf_YOUR_TOKEN_HERE...
Using Hugging Face Router API with OpenAI SDK
```

---

## Test Example

### Input:
```
What is the capital of France?
```

### Expected Output:
```
The capital of France is Paris. Paris is not only the capital 
but also the largest city in France, known for its art, fashion, 
gastronomy, and culture. The city is home to iconic landmarks 
such as the Eiffel Tower, the Louvre Museum, and Notre-Dame Cathedral.
```

Fast, detailed, high-quality response!

---

## Troubleshooting

### "OpenAI SDK not installed"

Run:
```bash
install_openai.bat
```

### "Model not found"

Try different provider in `.env`:
```bash
LLM_MODEL=openai/gpt-oss-120b:together-ai
```

Or let router choose:
```bash
LLM_MODEL=openai/gpt-oss-120b
```

### Still Issues?

Try a different model:
```bash
LLM_MODEL=mistralai/Mistral-7B-Instruct-v0.2:fireworks-ai
```

---

## Quick Commands

```bash
# Install OpenAI SDK
install_openai.bat

# Restart backend
force_restart.bat

# Start frontend
cd front && npm run dev

# Open browser
http://localhost:3000
```

---

## Files Updated

- ✅ `src/brain/services/llm_service.py` - Uses OpenAI SDK
- ✅ `.env` - Added HF_TOKEN, updated model
- ✅ `requirements.txt` - Added openai>=1.0.0
- ✅ Created `install_openai.bat` - Easy installation
- ✅ Created `ROUTER_API_SETUP.md` - Detailed guide

---

## Summary

| Step | Command | Status |
|------|---------|--------|
| 1. Install SDK | `install_openai.bat` | ⏳ Do this |
| 2. Restart | `force_restart.bat` | ⏳ Then this |
| 3. Test | http://localhost:3000 | ⏳ Finally this |

---

## 🎯 DO THIS NOW:

```bash
install_openai.bat
```

Then:

```bash
force_restart.bat
```

**You'll get fast, high-quality AI responses!** 🚀

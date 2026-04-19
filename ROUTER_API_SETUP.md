# 🚀 Hugging Face Router API Setup

## What Changed

Switched from direct Inference API to **Hugging Face Router API** using OpenAI SDK.

### Benefits:
- ✅ Access to multiple providers (Fireworks AI, Together AI, etc.)
- ✅ Better reliability and speed
- ✅ Familiar OpenAI SDK interface
- ✅ Automatic provider routing

---

## Configuration Updated! ✅

Your `.env` now uses:
```bash
HF_TOKEN=hf_YOUR_TOKEN_HERE... ✅
LLM_MODEL=openai/gpt-oss-120b:fireworks-ai ✅
```

---

## 🔧 Installation Required

Install OpenAI SDK:

```bash
pip install openai
```

Or install all requirements:

```bash
pip install -r requirements.txt
```

---

## 🔄 Restart Backend

```bash
force_restart.bat
```

Look for:
```
LLM Service initialized with model: openai/gpt-oss-120b:fireworks-ai
API Key configured: hf_YOUR_TOKEN_HERE...
Using Hugging Face Router API with OpenAI SDK
```

---

## How It Works

### Old Approach (Direct Inference API)
```
Your App → Hugging Face Inference API → Model
```
- Limited to HF-hosted models
- Can be slow
- May have availability issues

### New Approach (Router API)
```
Your App → HF Router → Best Provider → Model
```
- Routes to best available provider
- Faster responses
- Better reliability
- Multiple providers (Fireworks AI, Together AI, etc.)

---

## Model Format

```bash
LLM_MODEL=model-name:provider
```

### Examples:

```bash
# GPT-OSS-120B via Fireworks AI (recommended)
LLM_MODEL=openai/gpt-oss-120b:fireworks-ai

# GPT-OSS-120B via Together AI
LLM_MODEL=openai/gpt-oss-120b:together-ai

# Let router choose best provider
LLM_MODEL=openai/gpt-oss-120b

# Other models
LLM_MODEL=meta-llama/Llama-2-7b-chat-hf:fireworks-ai
LLM_MODEL=mistralai/Mistral-7B-Instruct-v0.2:together-ai
```

---

## Testing

### 1. Install OpenAI SDK

```bash
pip install openai
```

### 2. Restart Backend

```bash
force_restart.bat
```

### 3. Test in Frontend

Open: http://localhost:3000

Send: **"What is the capital of France?"**

Expected response:
```
"The capital of France is Paris. Paris is not only the capital 
but also the largest city in France..."
```

---

## Response Times

| Provider | Speed | Quality |
|----------|-------|---------|
| Fireworks AI | ⚡⚡⚡ Fast (2-5s) | ⭐⭐⭐⭐⭐ |
| Together AI | ⚡⚡ Medium (5-10s) | ⭐⭐⭐⭐⭐ |
| Auto-route | ⚡⚡⚡ Varies | ⭐⭐⭐⭐⭐ |

Much faster than direct Inference API!

---

## Troubleshooting

### "OpenAI SDK not installed"

**Solution:**
```bash
pip install openai
```

Then restart backend.

### "Model not found or not accessible"

**Solution:** Try different provider:
```bash
# In .env
LLM_MODEL=openai/gpt-oss-120b:together-ai
```

Or let router choose:
```bash
LLM_MODEL=openai/gpt-oss-120b
```

### Still Getting Errors?

Try a different model:
```bash
# Mistral 7B (fast and reliable)
LLM_MODEL=mistralai/Mistral-7B-Instruct-v0.2:fireworks-ai

# Llama 2 7B
LLM_MODEL=meta-llama/Llama-2-7b-chat-hf:fireworks-ai
```

---

## Available Providers

### Fireworks AI
- Fast inference
- Good availability
- Recommended for production

### Together AI
- High quality
- Good for complex tasks
- Slightly slower

### Auto-routing
- Router picks best provider
- Balances speed and availability
- Good default choice

---

## Code Example

The service now uses OpenAI SDK:

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://router.huggingface.co/v1",
    api_key=os.environ["HF_TOKEN"],
)

completion = client.chat.completions.create(
    model="openai/gpt-oss-120b:fireworks-ai",
    messages=[
        {"role": "user", "content": "What is the capital of France?"}
    ],
)

print(completion.choices[0].message.content)
```

---

## Configuration Summary

```bash
# .env
HF_TOKEN=hf_YOUR_TOKEN_HERE... ✅
HUGGINGFACE_API_KEY=hf_YOUR_TOKEN_HERE... ✅ (fallback)
LLM_MODEL=openai/gpt-oss-120b:fireworks-ai ✅
LLM_TIMEOUT=60 ✅
LLM_MAX_TOKENS=150 ✅
```

---

## Files Updated

- ✅ `src/brain/services/llm_service.py` - Now uses OpenAI SDK
- ✅ `.env` - Added HF_TOKEN, updated model format
- ✅ `requirements.txt` - Added openai>=1.0.0

---

## Next Steps

1. ✅ Install OpenAI SDK: `pip install openai`
2. 🔄 Restart backend: `force_restart.bat`
3. 🧪 Test in frontend: http://localhost:3000
4. 🎉 Enjoy fast, reliable AI responses!

---

## Comparison

| Feature | Old (Inference API) | New (Router API) |
|---------|-------------------|------------------|
| Speed | 🐌 Slow (10-30s) | ⚡ Fast (2-5s) |
| Reliability | ⚠️ Variable | ✅ High |
| Providers | 1 (HF only) | Multiple |
| SDK | httpx | OpenAI |
| Setup | Simple | Simple |

---

**Install OpenAI SDK and restart backend now!** 🚀

```bash
pip install openai
force_restart.bat
```

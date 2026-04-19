# 🤖 Model Selection Guide

## Your API Key is Configured! ✅

Your Hugging Face API key is set up: `hf_YOUR_TOKEN_HERE...`

---

## Quick Model Options

### Fast & Free (Recommended to Start)

```bash
# In .env
LLM_MODEL=gpt2
```
- ✅ Works immediately
- ✅ Fast responses (~1-2s)
- ✅ No approval needed
- ⚠️ Basic quality

### Better Quality

```bash
# In .env
LLM_MODEL=gpt2-medium
```
- ✅ Better responses
- ✅ Still fast (~2-3s)
- ✅ No approval needed

```bash
LLM_MODEL=gpt2-large
```
- ✅ Even better quality
- ⚠️ Slower (~3-5s)

### Advanced Models

```bash
LLM_MODEL=EleutherAI/gpt-neo-1.3B
```
- ✅ Good quality
- ⚠️ Slower (~5-10s)
- ⚠️ May need to wait for model loading

```bash
LLM_MODEL=EleutherAI/gpt-neo-2.7B
```
- ✅ Better quality
- ⚠️ Much slower (~10-20s)
- ⚠️ May timeout

### Instruction-Tuned Models

```bash
LLM_MODEL=tiiuae/falcon-7b-instruct
```
- ✅ Follows instructions well
- ⚠️ Slower
- ⚠️ May require approval

```bash
LLM_MODEL=meta-llama/Llama-2-7b-chat-hf
```
- ✅ Excellent quality
- ⚠️ Requires approval from Meta
- ⚠️ Slower

---

## About GPT-OSS-120B

The model `gpt-oss-120b` is not available on Hugging Face's free inference API. Options:

### Option 1: Use Similar Free Models

```bash
# Good alternatives
LLM_MODEL=EleutherAI/gpt-neo-2.7B
LLM_MODEL=EleutherAI/gpt-j-6B
```

### Option 2: Use Dedicated Inference Endpoint

If you have access to a dedicated endpoint:

```bash
# In .env
LLM_MODEL=your-endpoint-name
# Or use custom URL in llm_service.py
```

### Option 3: Use OpenAI-Compatible API

If you have an OpenAI-compatible endpoint:

```bash
OPENAI_API_BASE=https://your-endpoint-url
OPENAI_API_KEY=your-key
```

---

## Testing Your Configuration

### 1. Check Current Settings

Your `.env` is now configured with:
```bash
HUGGINGFACE_API_KEY=hf_YOUR_TOKEN_HERE... ✅
LLM_MODEL=gpt2 ✅
LLM_USE_MOCK=false ✅
```

### 2. Restart Backend

```bash
# Stop current backend (Ctrl+C)
# Then restart
start_backend.bat
```

### 3. Test in Frontend

```bash
cd front
npm run dev
```

Open: http://localhost:3000

Try: "Hello, how are you?"

---

## Expected Behavior

### With gpt2 (Current)

```
Input: "Hello, how are you?"
Output: "I'm doing well, thank you! [continues with GPT-2 style response]"
```

Response time: ~1-3 seconds

### First Request

The first request may take 10-30 seconds while the model loads:
```
"The AI model is currently loading. Please try again in a moment."
```

Just wait and try again!

---

## Troubleshooting

### "Model is loading"

**Normal!** First request loads the model. Wait 30 seconds and try again.

### "Model not found"

**Solution:** Use a different model from the list above.

### Timeout

**Solution:** 
1. Use a smaller model (gpt2)
2. Increase timeout in .env:
   ```bash
   LLM_TIMEOUT=60
   ```

### Empty responses

**Solution:**
1. Check model name is correct
2. Try gpt2 first to verify API key works
3. Check logs in backend terminal

---

## Recommended Setup

For best experience:

```bash
# .env
HUGGINGFACE_API_KEY=hf_YOUR_TOKEN_HERE
LLM_MODEL=gpt2-medium
LLM_USE_MOCK=false
LLM_TIMEOUT=30
LLM_MAX_TOKENS=150
```

This gives you:
- ✅ Good quality responses
- ✅ Reasonable speed
- ✅ Reliable availability

---

## Model Comparison

| Model | Quality | Speed | Availability |
|-------|---------|-------|--------------|
| gpt2 | ⭐⭐ | ⚡⚡⚡ | ✅ Always |
| gpt2-medium | ⭐⭐⭐ | ⚡⚡ | ✅ Always |
| gpt2-large | ⭐⭐⭐⭐ | ⚡ | ✅ Always |
| gpt-neo-1.3B | ⭐⭐⭐⭐ | ⚡ | ✅ Usually |
| gpt-neo-2.7B | ⭐⭐⭐⭐⭐ | 🐌 | ⚠️ Sometimes |
| falcon-7b | ⭐⭐⭐⭐⭐ | 🐌 | ⚠️ May need approval |

---

## Next Steps

1. ✅ Your API key is configured
2. ✅ Mock mode is disabled
3. ✅ Model is set to gpt2
4. 🔄 Restart backend: `start_backend.bat`
5. 🧪 Test in frontend: `cd front && npm run dev`

**You're ready to use real AI! 🎉**

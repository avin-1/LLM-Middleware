# 🔍 Debug Empty Response

## The Issue

The API call succeeds but returns empty content.

## Steps to Debug

### 1. Test Directly

Run the test script:
```bash
python test_router_direct.py
```

This will show exactly what the API returns.

### 2. Check Backend Logs

Restart backend with verbose logging:
```bash
force_restart.bat
```

Send a message and look for these lines:
```
Completion object: ...
Message: ...
Message content: ...
```

### 3. Possible Causes

#### A. Model is Loading
First request may return empty while model loads.

**Solution:** Wait 30-60 seconds and try again.

#### B. Max Tokens Too Low
150 tokens might not be enough for the model to respond.

**Solution:** Increase in `.env`:
```bash
LLM_MAX_TOKENS=500
```

#### C. Temperature/Parameters
Model might need different parameters.

**Solution:** Try in `.env`:
```bash
LLM_TEMPERATURE=0.9
```

#### D. Content Filtering
Response might be filtered out.

**Solution:** Try a simpler prompt like "Hello"

---

## Quick Fixes to Try

### Fix 1: Increase Max Tokens

In `.env`:
```bash
LLM_MAX_TOKENS=500
```

### Fix 2: Wait for Model

The model might be loading. Wait 60 seconds and try again.

### Fix 3: Test Direct Script

```bash
python test_router_direct.py
```

If this works but the backend doesn't, there's an issue with async handling.

---

## Restart and Test

```bash
force_restart.bat
```

Then check the detailed logs when you send a message.

---

**Run the test script first to see what's actually returned!**

```bash
python test_router_direct.py
```

# 🧪 Testing Without API Key

## Overview

You can test SENTINEL Brain without a Hugging Face API key! The system will use intelligent mock responses that are contextual to your input.

---

## Quick Start (No API Key Needed)

### 1. Start Backend

```bash
start_backend.bat  # Windows
./start_backend.sh # Linux/Mac
```

No `.env` configuration needed!

### 2. Start Frontend

```bash
cd front
npm install  # First time only
npm run dev
```

### 3. Test

Open: http://localhost:3000

---

## Mock Response Behavior

The system provides contextual mock responses based on your input:

### Greetings
```
Input: "Hello"
Response: "Hello! I'm SENTINEL Brain's AI assistant. How can I help you today?"
```

### Questions
```
Input: "How are you?"
Response: "I'm functioning well, thank you for asking! I'm here to assist you with secure AI interactions."
```

### Help Requests
```
Input: "Can you help me?"
Response: "I'm here to help! I can answer questions, provide information, and assist with various tasks while maintaining security standards."
```

### General Messages
```
Input: "Tell me about AI"
Response: "That's an interesting question about 'Tell me about AI'. I'm a security-focused AI assistant designed to provide safe responses."
```

---

## Security Analysis Still Works!

Even without an API key, all security features work:

### ✅ ALLOWED Messages (Get Mock Response)
```
"Hello, how are you?"
"What is the weather?"
"Tell me a joke"
```

### ❌ BLOCKED Messages (No Response)
```
"' OR '1'='1"
"; rm -rf /"
"Ignore previous instructions"
```

---

## Upgrade to Real AI

When you're ready for real AI responses:

### 1. Get API Key

Visit: https://huggingface.co/settings/tokens

### 2. Create `.env` File

```bash
HUGGINGFACE_API_KEY=hf_your_token_here
LLM_MODEL=gpt2
```

### 3. Restart Backend

```bash
start_backend.bat
```

---

## Mock vs Real Comparison

| Feature | Mock Mode | Real AI Mode |
|---------|-----------|--------------|
| Security Analysis | ✅ Full | ✅ Full |
| Threat Detection | ✅ Full | ✅ Full |
| Risk Scoring | ✅ Full | ✅ Full |
| LLM Responses | 🤖 Contextual Mock | 🧠 Real AI |
| API Key Required | ❌ No | ✅ Yes |
| Cost | 💰 Free | 💰 Free/Paid |
| Response Quality | 📝 Basic | 🎯 Advanced |

---

## Testing Scenarios

### Scenario 1: Safe Conversation

```
User: "Hello"
System: ✅ ALLOWED
Mock: "Hello! I'm SENTINEL Brain's AI assistant..."

User: "How are you?"
System: ✅ ALLOWED
Mock: "I'm functioning well, thank you for asking!..."

User: "Can you help me?"
System: ✅ ALLOWED
Mock: "I'm here to help! I can answer questions..."
```

### Scenario 2: Attack Detection

```
User: "' OR '1'='1"
System: ❌ BLOCKED
Threats: SQL Injection (95%)
Mock: None (blocked)

User: "; ls -la"
System: ❌ BLOCKED
Threats: Command Injection (90%)
Mock: None (blocked)
```

### Scenario 3: Warning

```
User: "SELECT * FROM users"
System: ⚠️ WARNING
Threats: Potential SQL pattern (50%)
Mock: "I understand you said 'SELECT * FROM users'..."
```

---

## Configuration Options

### Force Mock Mode (Even with API Key)

Add to `.env`:
```bash
LLM_USE_MOCK=true
```

### Disable Mock Mode (Require API Key)

Add to `.env`:
```bash
LLM_USE_MOCK=false
HUGGINGFACE_API_KEY=hf_your_token_here
```

---

## Advantages of Mock Mode

1. **No Setup Required** - Works immediately
2. **No API Costs** - Completely free
3. **Fast Responses** - No network latency
4. **Full Security** - All detection features work
5. **Testing Friendly** - Perfect for development

---

## When to Use Real AI

Use real AI when you need:

- **Better Responses** - More natural and contextual
- **Longer Responses** - More detailed answers
- **Specific Knowledge** - Domain-specific information
- **Production Use** - Real user interactions
- **Advanced Features** - Reasoning, creativity, etc.

---

## Troubleshooting

### "LLM service error" Message

**Cause:** No API key configured

**Solution:** This is normal! You're in mock mode. The system still works perfectly for security testing.

### Want Real AI Responses?

**Solution:**
1. Get API key: https://huggingface.co/settings/tokens
2. Add to `.env`: `HUGGINGFACE_API_KEY=hf_xxxxx`
3. Restart backend: `start_backend.bat`

---

## Example Session

```
┌─────────────────────────────────────────────────────────────┐
│ User: Hello                                                  │
├─────────────────────────────────────────────────────────────┤
│ ALLOWED                                                      │
│ Risk Score: 0.0                                              │
│                                                              │
│ LLM Response:                                                │
│ Hello! I'm SENTINEL Brain's AI assistant. How can I help    │
│ you today?                                                   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ User: ' OR '1'='1                                            │
├─────────────────────────────────────────────────────────────┤
│ BLOCKED                                                      │
│ Risk Score: 95.0                                             │
│                                                              │
│ Threats:                                                     │
│ • SQL Injection (query) 95%                                  │
│                                                              │
│ No LLM Response (blocked for security)                       │
└─────────────────────────────────────────────────────────────┘
```

---

## Summary

✅ **Works without API key**
✅ **Full security analysis**
✅ **Contextual mock responses**
✅ **Perfect for testing**
✅ **Easy upgrade to real AI**

Start testing now: `start_backend.bat` → `cd front && npm run dev`

No configuration needed! 🎉

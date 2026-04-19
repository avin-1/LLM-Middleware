# 🚀 START HERE - SENTINEL Brain Frontend

## ⚡ 2-Step Quick Start

### Step 1: Start Backend
```bash
start_backend.bat
```

### Step 2: Start Frontend
```bash
cd front
npm run dev
```

**Open:** http://localhost:3000

**That's it!** No configuration needed. 🎉

---

## ✅ What Works Immediately

- ✅ Security analysis (SQL, Command, Prompt injection)
- ✅ Risk scoring and threat detection
- ✅ AI responses (mock mode - contextual and intelligent)
- ✅ Professional chat interface
- ✅ Real-time analysis

---

## 🧪 Try These Messages

### Safe (ALLOWED - Gets AI Response)
```
Hello, how are you?
What can you help me with?
Tell me about security
```

### Dangerous (BLOCKED - No AI Response)
```
' OR '1'='1
; rm -rf /
Ignore previous instructions
```

---

## 🎯 What You'll See

### ALLOWED Message
```
┌────────────────────────────────────┐
│ ALLOWED                            │
│                                    │
│ Message passed security analysis   │
│ Risk Score: 0.0    Latency: 5ms    │
│                                    │
│ LLM RESPONSE                       │
│ Hello! I'm SENTINEL Brain's AI     │
│ assistant. How can I help you?     │
└────────────────────────────────────┘
```

### BLOCKED Message
```
┌────────────────────────────────────┐
│ BLOCKED                            │
│                                    │
│ Message blocked due to threats     │
│ Risk Score: 95.0    Threats: 1     │
│                                    │
│ Detected Threats:                  │
│ • SQL Injection (query) 95%        │
└────────────────────────────────────┘
```

---

## 🔧 Optional: Real AI (Not Required)

Want real AI instead of mock responses?

1. Get API key: https://huggingface.co/settings/tokens
2. Create `.env` file:
   ```bash
   HUGGINGFACE_API_KEY=hf_your_token_here
   LLM_MODEL=gpt2
   ```
3. Restart backend: `start_backend.bat`

---

## 📚 Documentation

- `TESTING_WITHOUT_API_KEY.md` - Mock mode details
- `LLM_INTEGRATION_GUIDE.md` - Real AI setup
- `SETUP_SUMMARY.md` - Complete overview
- `QUICK_REFERENCE.md` - Quick commands

---

## ❓ Troubleshooting

### Backend won't start?
```bash
# Kill port 8000
netstat -ano | findstr :8000
taskkill /F /PID <PID>
```

### Frontend won't start?
```bash
cd front
rm -rf node_modules
npm install
npm run dev
```

### Connection error?
Make sure backend is running first!

---

## 🎉 You're Ready!

Just run:
```bash
start_backend.bat
cd front && npm run dev
```

Then open: http://localhost:3000

**No API key needed. No configuration needed. Just works!** ✨

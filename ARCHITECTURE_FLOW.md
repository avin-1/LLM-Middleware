# 🏗️ Architecture Flow

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      SENTINEL Brain                          │
│                   Security + AI Platform                     │
└─────────────────────────────────────────────────────────────┘
```

## Component Architecture

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Frontend   │────────▶│   Backend    │────────▶│  Hugging     │
│   (React)    │         │   (FastAPI)  │         │  Face API    │
│              │◀────────│              │◀────────│              │
│  Port 3000   │         │  Port 8000   │         │  (LLM)       │
└──────────────┘         └──────────────┘         └──────────────┘
      │                         │
      │                         │
      ▼                         ▼
  User Input            Security Engines
                        ┌──────────────┐
                        │  Injection   │
                        │  Query       │
                        │  Behavioral  │
                        └──────────────┘
```

## Request Flow

### 1. User Sends Message

```
User types: "Hello, how are you?"
    ↓
Frontend (App.jsx)
    ↓
POST /v1/analyze
    ↓
Backend receives request
```

### 2. Security Analysis

```
Backend (analyze.py)
    ↓
┌─────────────────────────────────┐
│  Run Security Engines           │
├─────────────────────────────────┤
│  1. Injection Engine            │
│     - Check for SQL injection   │
│     - Check for command inject  │
│     - Check for prompt inject   │
│                                 │
│  2. Query Engine                │
│     - Validate SQL patterns     │
│     - Check for malicious code  │
│                                 │
│  3. Behavioral Engine           │
│     - Analyze behavior patterns │
│     - Check for anomalies       │
└─────────────────────────────────┘
    ↓
Calculate Risk Score
    ↓
Determine Verdict
```

### 3. Verdict Decision

```
Risk Score Calculated
    ↓
┌─────────────────────────────────┐
│  Risk Score < 40?               │
├─────────────────────────────────┤
│  YES → ALLOW                    │
│  40-79 → WARN                   │
│  ≥ 80 → BLOCK                   │
└─────────────────────────────────┘
```

### 4. LLM Integration (ALLOW only)

```
Verdict = ALLOW?
    ↓
   YES
    ↓
┌─────────────────────────────────┐
│  LLM Service (llm_service.py)   │
├─────────────────────────────────┤
│  1. Check API key configured    │
│  2. Prepare request payload     │
│  3. Call Hugging Face API       │
│  4. Wait for response           │
│  5. Extract generated text      │
│  6. Return to analyze endpoint  │
└─────────────────────────────────┘
    ↓
LLM Response Generated
```

### 5. Response to Frontend

```
Backend Response
    ↓
{
  "verdict": "ALLOW",
  "risk_score": 0.0,
  "threats": [],
  "llm_response": "I'm doing well, thank you!"
}
    ↓
Frontend receives response
    ↓
Display in UI
```

## Frontend Display Logic

```
Receive Analysis Result
    ↓
┌─────────────────────────────────┐
│  Check Verdict                  │
├─────────────────────────────────┤
│  ALLOW?                         │
│    ↓                            │
│    Show green badge             │
│    Show risk score              │
│    Show LLM response            │
│    Expandable JSON              │
├─────────────────────────────────┤
│  BLOCK?                         │
│    ↓                            │
│    Show red badge               │
│    Show threat list             │
│    Show threat details          │
│    Expandable JSON              │
│    NO LLM response              │
├─────────────────────────────────┤
│  WARN?                          │
│    ↓                            │
│    Show yellow badge            │
│    Show threat list             │
│    Show LLM response (caution)  │
│    Expandable JSON              │
└─────────────────────────────────┘
```

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        User Input                            │
│                  "Hello, how are you?"                       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   Security Analysis                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │Injection │  │  Query   │  │Behavioral│                  │
│  │ Engine   │  │  Engine  │  │  Engine  │                  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                  │
│       │             │             │                          │
│       └─────────────┴─────────────┘                          │
│                     │                                        │
│                     ▼                                        │
│              Risk Score: 0.0                                 │
│              Verdict: ALLOW                                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    LLM Generation                            │
│                                                              │
│  Input: "Hello, how are you?"                               │
│         ↓                                                    │
│  Hugging Face API                                           │
│         ↓                                                    │
│  Output: "I'm doing well, thank you for asking!"            │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    Frontend Display                          │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │ ALLOWED                                            │    │
│  │                                                    │    │
│  │ Message passed security analysis                  │    │
│  │ Risk Score: 0.0    Latency: 5ms                   │    │
│  │                                                    │    │
│  │ ▶ View Full Analysis                              │    │
│  │                                                    │    │
│  │ LLM RESPONSE                                       │    │
│  │ I'm doing well, thank you for asking!             │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Security Flow (BLOCKED)

```
User Input: "' OR '1'='1"
    ↓
Security Analysis
    ↓
SQL Injection Detected!
    ↓
Risk Score: 95.0
    ↓
Verdict: BLOCK
    ↓
❌ NO LLM CALL
    ↓
Response:
{
  "verdict": "BLOCK",
  "risk_score": 95.0,
  "threats": [
    {
      "name": "SQL Injection",
      "engine": "query",
      "confidence": 0.95
    }
  ],
  "llm_response": null
}
    ↓
Frontend Display:
┌────────────────────────────────┐
│ BLOCKED                        │
│                                │
│ Message blocked due to         │
│ security threats               │
│                                │
│ Detected Threats:              │
│ • SQL Injection (query) 95%    │
│                                │
│ ▶ View Full Analysis           │
└────────────────────────────────┘
```

## Technology Stack

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend                              │
├─────────────────────────────────────────────────────────────┤
│  • React 19                                                  │
│  • Vite (build tool)                                         │
│  • CSS (no frameworks)                                       │
│  • Fetch API (HTTP client)                                   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                        Backend                               │
├─────────────────────────────────────────────────────────────┤
│  • FastAPI (web framework)                                   │
│  • Pydantic (validation)                                     │
│  • httpx (async HTTP)                                        │
│  • Custom security engines                                   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      External Services                       │
├─────────────────────────────────────────────────────────────┤
│  • Hugging Face Inference API                                │
│  • Models: gpt2, gpt-neo, bloom, etc.                        │
└─────────────────────────────────────────────────────────────┘
```

## File Structure

```
project/
├── src/brain/
│   ├── api/
│   │   ├── main.py              # FastAPI app
│   │   └── v1/
│   │       └── analyze.py       # Analysis endpoint
│   ├── engines/
│   │   ├── injection.py         # Injection detection
│   │   ├── query.py             # SQL detection
│   │   └── behavioral.py        # Behavior analysis
│   └── services/
│       └── llm_service.py       # LLM integration
│
├── front/
│   ├── src/
│   │   ├── App.jsx              # Main component
│   │   ├── App.css              # Styling
│   │   └── main.jsx             # Entry point
│   └── vite.config.js           # Vite config
│
├── .env                         # Configuration
└── requirements.txt             # Python deps
```

## Configuration Flow

```
.env file
    ↓
Environment Variables
    ↓
┌─────────────────────────────────┐
│  HUGGINGFACE_API_KEY            │
│  LLM_MODEL                      │
│  LLM_TIMEOUT                    │
│  LLM_MAX_TOKENS                 │
└─────────────────────────────────┘
    ↓
LLM Service (llm_service.py)
    ↓
Used by analyze endpoint
```

## Performance Metrics

```
┌─────────────────────────────────────────────────────────────┐
│                    Latency Breakdown                         │
├─────────────────────────────────────────────────────────────┤
│  Security Analysis:        5-10ms                            │
│  LLM Generation:           500-3000ms                        │
│  Network Overhead:         10-50ms                           │
│  ─────────────────────────────────────────                  │
│  Total (ALLOW):            515-3060ms                        │
│  Total (BLOCK):            5-10ms (no LLM)                   │
└─────────────────────────────────────────────────────────────┘
```

## Error Handling

```
Request
    ↓
Try Security Analysis
    ↓
  Error?
    ↓
   YES → Log error, return 500
    ↓
   NO → Continue
    ↓
Try LLM Generation (if ALLOW)
    ↓
  Error?
    ↓
   YES → Log warning, return without LLM response
    ↓
   NO → Return with LLM response
```

## Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Production Setup                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐         ┌──────────────┐                 │
│  │   Nginx      │────────▶│   Backend    │                 │
│  │  (Reverse    │         │   (Uvicorn)  │                 │
│  │   Proxy)     │         │   Port 8000  │                 │
│  │  Port 80/443 │         └──────────────┘                 │
│  └──────────────┘                 │                         │
│         │                         │                         │
│         │                         ▼                         │
│         │                 ┌──────────────┐                 │
│         │                 │  Hugging     │                 │
│         │                 │  Face API    │                 │
│         │                 └──────────────┘                 │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐                                          │
│  │   Frontend   │                                          │
│  │   (Static)   │                                          │
│  │   /dist      │                                          │
│  └──────────────┘                                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

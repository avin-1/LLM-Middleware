# Edge Cases & System Failsafes

Examiners *love* to ask about edge cases: "What happens when things go wrong?"
This project handles failure brilliantly. Focus on these points.

---

## Edge Case 1: The Rust Engine Crashes or Fails to Load
*   **The Examiner's Trap:** "You integrated a compiled Rust binary into Python. What if the environment doesn't support it or the binary corrupts? Does your whole security system go down?"
*   **Our Solution (Graceful Degradation):** No. We implemented a fail-safe mechanism (`rust_bridge.py`). At runtime, the system attempts to import the Rust engine. If it fails, it logs an error and automatically routes all traffic to the pure Python heuristic engines. 
*   **🌟 The Positive:** Zero downtime. The system degrades in performance slightly but remains 100% functional and secure.

## Edge Case 2: False Positives (Blocking legitimate users)
*   **The Examiner's Trap:** "What if a cyber security student legitimately asks the AI to explain how an SQL injection works? Will your system block them, ruining the user experience?"
*   **Our Solution (Contextual Scoring):** We use a Risk Scoring System (0-100). The word "SQL Injection" alone might add +20 points, but it won't cross the blocking threshold of 80. The system analyzes the *intent*. Furthermore, borderline scores (60-79) are flagged as "WARNING" rather than outright blocked.
*   **🌟 The Positive:** High usability. We protect the AI without crippling its ability to discuss sensitive topics.

## Edge Case 3: A Zero-Day Attack (Completely Unseen Prompt)
*   **The Examiner's Trap:** "What if an attacker uses a brand new jailbreak methodology that isn't in your Rust signatures or your ChromaDB vector database?"
*   **Our Solution (Behavioral Heuristics & LLM Alignment):** 
    1.  Our Tier 2 Python Heuristics look for structural anomalies (excessive urgency, strange role-playing commands). Even if the words are new, the *shape* of the attack is often recognizable.
    2.  **The Ultimate Backstop:** If the middleware misses it (Risk Score < 60), the prompt is sent to the LLM. Modern LLMs have built-in ethical alignment. Even if our middleware allows it, the LLM itself will likely refuse a malicious task.
*   **🌟 The Positive:** We add immense security on top of the LLM, but we still leverage the LLM's own safety training as a final safety net.

## Edge Case 4: High Traffic Loads (DDoS on the API)
*   **Our Solution:** The Tier 0 Rust engine drops malicious requests in under 5 milliseconds. By terminating bad requests immediately at the gateway, we prevent computationally expensive operations (like Vector Database lookups or LLM generation) from executing, effectively mitigating resource exhaustion attacks.

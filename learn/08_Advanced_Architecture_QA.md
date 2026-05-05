# 🧠 Advanced Architectural & Design QA

This document covers high-level, complex questions that an examiner might ask to test if you truly understand the "Why" and "How" of the system's design. These questions move beyond basic features into architectural trade-offs and engineering decisions.

---

### Q1: Why build a separate middleware instead of just using "System Prompts" to tell the LLM to be safe?
**A:** System prompts (Instructional Defense) are notoriously easy to bypass via **Prompt Injection**. Attackers use "Jailbreaks" to trick the LLM into ignoring its system prompt. By placing a **Deterministic Middleware** (SENTINEL) outside the LLM's "brain," we create a boundary that the attacker cannot talk their way out of. We filter the input *before* the LLM even sees it, ensuring that malicious commands never reach the inference engine.

### Q2: You mentioned Aho-Corasick in the Rust Core. Why not just use Python's `re` (Regex) library?
**A:** Python's `re` library is powerful, but it evaluates patterns one after another (Linear Time). If you have 500 attack signatures, Python will scan the text 500 times. 
**Aho-Corasick** builds a **Finite State Automaton** (a tree-like structure). It scans the user's prompt **exactly once**, and in that single pass, it finds every single matching signature simultaneously. This reduces our Tier-0 latency from ~50ms to ~1ms, which is critical for high-traffic enterprise gateways.

### Q3: Why did you choose ChromaDB (Vector Database) for the Semantic Layer instead of a simple keyword list?
**A:** Keywords are fragile. An attacker can say "disregard previous guidelines" instead of "ignore instructions." 
ChromaDB allows us to perform **Semantic Search**. We convert the prompt into a 768-dimensional vector (using `sentence-transformers`). Even if the words are completely different, if the **mathematical intent** is close to a known attack, the vector distance will be small. This makes our system "intelligent" enough to catch paraphrased attacks that keywords would miss.

### Q4: Explain the "Max-Pooling" vs "Additive" scoring logic in your analyzer.
**A:** We use **Max-Pooling** for explicit threats (SQLi, Jailbreak signatures). If we find a 95% certain SQL injection, that should be our baseline risk score—we don't want to "average" it down with safe parts of the text.
However, we use **Additive Modifiers** for behavioral anomalies (like excessive urgency or roleplay). One behavioral anomaly might be a mistake; three anomalies together suggest a coordinated attack. By adding these modifiers to the maximum detected threat, we get a nuanced score that reflects both specific evidence and overall "suspiciousness."

### Q5: How does the system handle "False Positives" in a developer-heavy environment (where users *need* to send code)?
**A:** This is a classic trade-off. We handle this through **Contextual Engines**. For example, our `code_security` and `query` engines don't just block any code—they look for **malicious patterns** within that code (like dropping tables or exfiltrating keys). Additionally, by setting the block threshold at 80, we allow "borderline" inputs (scored 40-79) to pass through with a warning, rather than breaking the user's workflow.

### Q6: Your Rust code contains "Strange Math" engines like Spectral Decomposition and TDA. What is the ideation behind these?
**A:** These represent the **next generation of AI security**. Traditional security looks at text. These engines look at the **internal structure of the prompt's representation**. 
- **Spectral Analysis** looks at the "frequency" of tokens to detect repetitive bot-like behavior.
- **TDA (Topological Data Analysis)** looks at the "shape" of the data in high-dimensional space.
These are currently in an "R&D/Experimental" state in our codebase, showing that the project is designed to be future-proof against advanced, multi-turn AI attacks.

### Q7: If you were to scale this to 1 million requests per second, what would be the bottleneck?
**A:** The bottleneck would be **Tier 1 (Semantic Embeddings)** because generating vectors requires a GPU-intensive model (`sentence-transformers`). 
**To solve this:**
1.  **Horizontal Scaling:** Deploying multiple Semantic nodes.
2.  **Tier 0 Caching:** If the Rust Core (Tier 0) catches an attack, we never even send it to the embedding model, saving 90% of our compute power for legitimate traffic.
3.  **Vector Caching:** We cache the scores of common prompts so we don't have to re-embed them.

### Q8: How did you ensure the "Fail-Safe" nature of the system?
**A:** We used a **Safe-Failure Design Pattern**. The `rust_bridge.py` is wrapped in a `try-except` block. If the Rust binary is missing, corrupted, or crashes, the system doesn't stop. It logs the error and falls back to the Python-based heuristic engines. This ensures that a security software failure never becomes a Denial of Service (DoS) for the user.

### Q9: How do you prevent "Adversarial Drifting" (where attackers slowly learn how to bypass your scores)?
**A:** We implement **Noise Injection** in our `collective_immunity` module. By adding a small amount of "Laplace Noise" to our risk scores before they are reported in logs, we prevent attackers from using "Hill-Climbing" techniques to find the exact boundary of our filters. This is a principle of **Differential Privacy** applied to security scoring.

### Q10: What is the "Lethal Trifecta" engine mentioned in your Rust source?
**A:** The "Lethal Trifecta" is a high-level detection logic that looks for three specific conditions occurring simultaneously:
1.  **Data Access:** The prompt asks for sensitive info.
2.  **Untrusted Input:** The prompt comes from an external/anonymous user.
3.  **Exfiltration Vector:** The prompt contains a way to send that data out (like an URL or a file write).
Individually, these might be safe. Together, they represent a critical security breach. This engine demonstrates our **Context-Aware** approach to security.

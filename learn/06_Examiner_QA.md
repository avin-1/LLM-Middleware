# 🎓 Examiner Q&A (Viva Preparation)

This file contains the most likely questions the examiner will ask, along with the perfect, confident answers to secure high marks.

---

### Q1: Why did you call this "Middleware"?
**A:** Because it sits right in the middle between the user's application and the Large Language Model. Instead of modifying the LLM itself (which is difficult and expensive), SENTINEL intercepts the traffic in real-time, cleans it, and only forwards safe requests. It acts as an API gateway.

### Q2: Why did you use Rust? Why not just write the whole thing in Python?
**A:** Python is excellent for data science and AI, but it is slow for concurrent, real-time string parsing due to the Global Interpreter Lock (GIL). By building the Tier-0 Core Engine in Rust, we achieved sub-5ms latency and memory safety. We offload the heavy lifting to Rust, so the Python backend never becomes a bottleneck.

### Q3: What is "Defense-in-Depth"?
**A:** It means not relying on a single security mechanism. If an attacker bypasses our Tier 0 Rust keyword checks, they still have to beat our Tier 1 Semantic Vector database. If they beat that, they face the Tier 2 behavioral heuristics. Multiple layers of security drastically reduce the chance of a successful attack.

### Q4: How does the Vector Database (ChromaDB) actually stop attacks?
**A:** Attackers often try to obfuscate their attacks by changing words (e.g., instead of "ignore instructions", they say "disregard previous guidelines"). Regular expressions fail here. ChromaDB converts text into high-dimensional mathematical vectors (Embeddings). Even if the words are different, the mathematical "distance" between the two sentences is very close. We block based on semantic intent, not just exact keywords.

### Q5: What happens if your Rust engine crashes? Does the application go offline?
**A:** Absolutely not. We designed the system with "Graceful Degradation." We have a `rust_bridge.py` module. If the Rust binary fails to load or crashes, the system catches the exception and automatically reroutes all security checks to our pure Python fallback engines. The user experiences zero downtime.

### Q6: Can a legitimate user get blocked by accident (False Positive)?
**A:** We minimize this by using a Risk Scoring System rather than a binary "Allow/Deny". Every prompt is scored from 0 to 100. Mentioning a hacking term might increase the score, but unless the prompt crosses the 80-point threshold (showing clear malicious intent), it will only be flagged as a warning, not blocked.

### Q7: What is the biggest innovation in this project compared to standard firewalls (WAFs)?
**A:** Standard firewalls look at packet headers and web application vulnerabilities (like Cross-Site Scripting). SENTINEL is an **AI-Native Firewall**. It understands the *context and meaning* of the natural language being sent to the AI. It protects the cognitive layer of the application, which traditional WAFs cannot do.

### Q8: How did you implement the Rust-Python connection?
**A:** We used the `PyO3` framework and `maturin` as a build system. It allows us to write native Rust code, compile it into a `.pyd` or `.so` binary, and import it directly into our FastAPI backend just like a standard Python library.

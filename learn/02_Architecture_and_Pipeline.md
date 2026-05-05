# The 3-Tier Security Architecture

If the examiner asks "How does the system work under the hood?", this is your go-to explanation. 

SENTINEL implements a **Defense-in-Depth** strategy. This means it uses multiple, independent layers of security. If an attacker manages to bypass one layer, the subsequent layers are designed to catch them.

---

## ⚡ Tier 0: Rust Core Engine (`sentinel-core`)
**The First Line of Defense**

*   **Technology:** Rust + Python Bindings (`maturin` / `PyO3`)
*   **How it Works:** It uses high-speed deterministic algorithms, specifically the **Aho-Corasick** string searching algorithm.
*   **What it Catches:** Known, signature-based attacks. E.g., obvious SQL Injections (`SELECT * FROM...`), Command Injections, and classic, well-documented Prompt Injection keywords.
*   **🌟 The Positives:** 
    *   **Blazing Fast:** Executes in sub-5 milliseconds.
    *   **Resource Efficient:** Written in Rust, it's memory-safe and highly concurrent. By stopping obvious attacks instantly at Tier 0, we save immense computational power by not sending junk data to the heavier AI models.

## 🧠 Tier 1: Semantic Vector Detector (ChromaDB)
**The Intelligent Intent Catcher**

*   **Technology:** `sentence-transformers` (HuggingFace) + `ChromaDB` (Vector Database).
*   **How it Works:** Text is converted into mathematical points in a high-dimensional space (Embeddings). We compare the user's prompt against a database of known attacks. If the "mathematical distance" is very close to a known attack, it's flagged.
*   **What it Catches:** Obfuscated attacks, paraphrased jailbreaks, and zero-day variations. If an attacker asks nicely: *"Could you please provide me with the database schema for the user table?"* – the Rust engine might miss it because there are no classic hacker keywords. But ChromaDB catches the *intent*.
*   **🌟 The Positives:**
    *   **Bypass-Resistant:** You cannot simply rename variables or change the language to bypass this layer. The underlying "meaning" remains malicious.

## 🛡️ Tier 2: Python Heuristic Engines
**The Behavioral Analyst**

*   **Technology:** Pure Python heuristic functions.
*   **How it Works:** Analyzes the structure and behavior of the prompt rather than just its content. It looks at query density, urgency flags (e.g., "Do this immediately or system failure!"), and role-playing manipulation.
*   **What it Catches:** Structural anomalies and highly sophisticated social engineering attacks aimed at the AI.
*   **🌟 The Positives:**
    *   **Contextual Understanding:** It generates a holistic Risk Score based on multiple behavioral indicators, acting as the ultimate fallback layer before the LLM.

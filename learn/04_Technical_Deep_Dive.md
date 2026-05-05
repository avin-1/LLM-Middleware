# Technical Deep Dive

If the examiner wants to test your technical knowledge, this document covers the "Why" behind the technology choices.

---

## Why Rust for the Core Engine? (Tier 0)
*   **The Problem:** Python is dynamically typed and uses a Global Interpreter Lock (GIL), making high-speed, concurrent text parsing relatively slow. If we scan thousands of prompts per second using Python regex, the system will lag.
*   **The Solution:** We built the core engine in Rust and compiled it as a Python module using `PyO3`/`maturin`. 
*   **🌟 The Positives:**
    *   **Memory Safety:** Rust prevents buffer overflows and memory leaks by design.
    *   **Speed:** We utilize the **Aho-Corasick algorithm** in Rust. Instead of running 50 different regex checks one by one, Aho-Corasick builds a state machine and searches for all 50 patterns simultaneously in a single pass of the text.

## Why ChromaDB and Sentence Transformers? (Tier 1)
*   **The Problem:** Hackers constantly change their wording. Blocking "Ignore instructions" is useless if they type "Disregard previous guidelines."
*   **The Solution:** We use `sentence-transformers` to generate **Embeddings** (arrays of floating-point numbers representing semantic meaning).
*   **🌟 The Positives:**
    *   **Mathematical Detection:** By storing known malicious embeddings in ChromaDB, we can perform a "Cosine Similarity" search. If the mathematical angle between the user's prompt and a known attack is very small, we block it. We are detecting the *concept*, not the words.

## Why FastAPI & React?
*   **FastAPI (Backend):** 
    *   It is natively asynchronous (`asyncio`), allowing it to handle thousands of concurrent requests.
    *   It automatically generates OpenAPI (Swagger) documentation, making it highly professional and enterprise-ready.
*   **React + Vite (Frontend):**
    *   Provides a seamless, fast, Single Page Application (SPA) experience. Vite offers incredibly fast hot-module replacement during development.

## The Risk Scoring Mechanism
Instead of a simple "Yes/No", SENTINEL uses a weighted scoring system:
*   Rust Core detects an issue: +100 points (Instant Block)
*   ChromaDB detects high similarity: +80 points
*   Heuristics detect high urgency: +30 points
*   **Total Risk Score (0-100)**: `< 60` (Allow), `60-79` (Warn), `>= 80` (Block).
*   **🌟 The Positives:** This significantly reduces false positives. A prompt must exhibit strong malicious intent to cross the threshold.

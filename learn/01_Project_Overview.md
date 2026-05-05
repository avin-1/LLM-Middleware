# SENTINEL: Project Overview & Core Philosophy

## What is SENTINEL?
**SENTINEL** is an advanced, high-performance **Defense-in-Depth AI Security Gateway**. It acts as an intelligent middleware layer sitting directly between users and Large Language Models (LLMs). 

Before a user's prompt ever reaches the AI, SENTINEL analyzes it for security threats, injections, data exfiltration attempts, and semantic manipulations. 

## Why was this built? (The Cyber Security Problem)
In the modern landscape, LLMs are incredibly powerful but fundamentally gullible. They are susceptible to:
- **Prompt Injection:** Tricking the AI into ignoring its original instructions.
- **Jailbreaks:** Bypassing ethical and safety guardrails.
- **Classic Injections:** Using the AI as an attack vector against backend systems (e.g., generating malicious SQL queries).

Standard keyword filters are easily bypassed by attackers who paraphrase or obfuscate their intent. SENTINEL solves this by combining deterministic high-speed checks with advanced AI-driven semantic analysis.

## 🌟 Key Positives & Project Strengths
*Focus heavily on these during your presentation to impress the examiner!*

1. **Enterprise-Grade Architecture:** This isn't just a simple script; it's a 3-tier pipeline designed for high scalability and low latency.
2. **Defense-in-Depth:** We never rely on a single point of failure. If one layer misses an attack, the next layer catches it.
3. **High Performance:** By offloading the initial checks to a Rust-based core engine, we ensure sub-5ms latency, meaning the security layer doesn't slow down the user experience.
4. **Graceful Degradation:** Built-in failsafes ensure that if the Rust engine goes offline, the system falls back to Python seamlessly without crashing.
5. **Intent-Based Detection:** We don't just look at *what* the user typed; we use Vector Databases (ChromaDB) to understand the *mathematical meaning* (semantics) to catch obfuscated attacks.

## Target Audience
This system is designed for enterprises, healthcare providers, and financial institutions that want to deploy LLMs internally or externally but need strict, verifiable guarantees that their AI will not be compromised or leak sensitive data.

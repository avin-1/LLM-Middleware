# Detailed Report: Risk Score Calculation

During your presentation, the examiner might ask exactly *how* a prompt is evaluated and how the final decision is made. This document explains the mathematical and logical process behind the `risk_score`.

---

## The Risk Score Thresholds (The Verdict)
Every incoming prompt starts with a `risk_score` of `0.0`. As it passes through the pipeline, the score is adjusted. At the end of the pipeline, the final verdict is determined by these thresholds:

*   **`>= 80`**: **BLOCK** (The prompt is highly malicious and is blocked from reaching the LLM).
*   **`40 to 79`**: **WARN** (The prompt has suspicious elements and is flagged, but might still be passed depending on system configuration). *(Note: Your README mentions the warning threshold as 60, but the `analyzer.py` code actually triggers warnings at 40. It's good to be aware of this in case they look at the code!)*
*   **`< 40`**: **ALLOW** (The prompt is safe).

---

## How the Score is Calculated (Step-by-Step)

The calculation uses a "Highest Threat Wins" approach for structural checks (`max()`), combined with an "Additive" approach for behavioral anomalies (`+`).

### Step 1: Tier 0 - Rust Core Engine
The prompt is scanned by the high-speed Rust engine using the Aho-Corasick algorithm.
*   **Action:** If Rust detects a known malicious signature, it assigns a score based on the severity of that signature.
*   **Short-Circuit:** If Rust assigns a score `>= 70`, it doesn't even bother checking the rest of the pipeline. It **immediately blocks** the request to save compute resources.
*   **Calculation:** If the score is `< 70`, the pipeline continues, and the current `risk_score` becomes `max(0, rust_score)`.

### Step 2: Tier 1 - Semantic Detection (Vector Embeddings)
The prompt is converted into a mathematical vector and compared to known attacks in ChromaDB using "Cosine Similarity".
*   **Action:** If the mathematical similarity to an attack is high, a score is generated. For example, a 95% similarity might translate to a score of 95.
*   **Short-Circuit:** If the semantic score is `>= 80`, it **immediately blocks** the request.
*   **Calculation:** The current risk score is updated to take the highest threat found so far: `risk_score = max(current_risk_score, semantic_score)`.

### Step 3: Tier 2 - Python Heuristic Engines
If the prompt survives Tier 0 and Tier 1, it undergoes deeper inspection by Python engines.

#### A. Query Engine (SQL Injection)
If the prompt contains database keywords (like `select`, `drop`, `union`), it is scanned against specific patterns.
*   *Examples of hardcoded scores:*
    *   Classic SQL Injection (`OR 1=1`): **Score 90**
    *   `DROP TABLE` command: **Score 95**
    *   Boolean Blind Injection (`AND 1=1`): **Score 70**
*   **Calculation:** `risk_score = max(current_risk_score, query_score)`.

#### B. Injection Engine
Scans for standard prompt injection tactics (e.g., "ignore previous instructions").
*   **Calculation:** `risk_score = max(current_risk_score, injection_score)`.

#### C. Behavioral Engine (The Additive Modifier)
Unlike the other engines which take the *maximum* score, the behavioral engine looks for subtle anomalies (like unnatural urgency, strange roles, high keyword density) and generates a `risk_modifier`.
*   **Calculation:** This modifier is *added* to the total score.
*   `risk_score = min(100.0, current_risk_score + risk_modifier)`
*   *Why?* Because a prompt might not have any single severe keyword, but a combination of "Urgency" + "Complex Roleplay" + "Density" adds up to a high risk. The `min(100.0, ...)` ensures the score never mathematically exceeds 100.

---

## Summary of the Logic
1.  **Start at 0.**
2.  Take the **Maximum (Highest)** score out of Rust, Semantic Vector, SQL Query, and Prompt Injection checks.
3.  **Add** any Behavioral modifiers to that maximum score.
4.  If the total hits **80**, **BLOCK**. If it hits **40**, **WARN**.

**Why this is a positive (Examiner Answer):**
*"We don't use a simple binary allow/deny system because it causes too many false positives. By using a weighted score that takes the maximum explicit threat and adds behavioral context, we create a highly nuanced security layer that understands context, much like a human security analyst."*

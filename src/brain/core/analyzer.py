"""
Sentinel Analyzer - Main Analysis Pipeline (Optimized for Course Project)

Tiered Architecture:
- Tier 0: Rust Core Engine (Aho-Corasick + Regex) - <5ms
- Tier 1: Semantic Detection (ChromaDB Vector Embeddings)
- Tier 2: Python Fallback Engines (Injection, Query, Behavioral)
"""

import logging
import asyncio
import time
from functools import cached_property

# Import the bridge and specific engines
from .rust_bridge import get_rust_bridge

logger = logging.getLogger("SentinelAnalyzer")

class SentinelAnalyzer:
    def __init__(self):
        logger.info("SentinelAnalyzer initializing...")
        
        # Load Rust bridge
        self._rust_bridge = get_rust_bridge()
        if self._rust_bridge.available:
            logger.info("✓ Rust fast path enabled")
        else:
            logger.warning("✗ Rust fast path disabled, using Python only")

        # Load Python heuristic engines
        from ..engines.injection import InjectionEngine
        from ..engines.query import QueryEngine
        from ..engines.behavioral import BehavioralEngine
        
        self.injection_engine = InjectionEngine()
        self.query_engine = QueryEngine()
        self.behavioral_engine = BehavioralEngine()
        
        logger.info("Python engines initialized")

    @cached_property
    def semantic_detector(self):
        """Lazy load ChromaDB to save memory until needed"""
        logger.info("Lazy loading Semantic Detector...")
        from ..engines.semantic_detector import get_semantic_detector
        return get_semantic_detector()

    async def analyze(self, prompt: str, context: dict) -> dict:
        """
        Main ingress analysis pipeline.
        Tiered execution for high performance.
        """
        start_time = time.perf_counter()
        logger.info("Running optimized analysis pipeline...")
        
        user_id = context.get("user_id", "anonymous")
        
        risk_score = 0.0
        allowed = True
        threats = []
        engines_used = []

        # =====================================================================
        # TIER 0: Rust Fast Path (~1-5ms)
        # =====================================================================
        if self._rust_bridge.available:
            rust_result = self._rust_bridge.quick_scan(prompt)
            engines_used.append("rust_core")
            if rust_result and rust_result["detected"]:
                logger.info(f"Rust fast path threat detected: risk={rust_result['risk_score']}")
                if rust_result["risk_score"] >= 70:
                    elapsed = (time.perf_counter() - start_time) * 1000
                    threats.extend(rust_result.get("threats", ["Rust Core Detection"]))
                    return {
                        "verdict": "BLOCK",
                        "risk_score": rust_result["risk_score"],
                        "is_safe": False,
                        "threats": threats,
                        "latency_ms": elapsed,
                        "engines_used": engines_used
                    }
                else:
                    risk_score = max(risk_score, rust_result["risk_score"])
                    threats.extend(rust_result.get("threats", ["Rust Core Warning"]))

        # =====================================================================
        # TIER 1: Semantic Detection (Vector Embeddings)
        # =====================================================================
        semantic_result = self.semantic_detector.scan(prompt)
        engines_used.append("semantic")
        if not semantic_result.is_safe:
            risk_score = max(risk_score, semantic_result.risk_score)
            for threat_cat in semantic_result.threats:
                threats.append(f"Semantic match: {threat_cat}")
            
            # If highly confident, we can block early
            if risk_score >= 80:
                elapsed = (time.perf_counter() - start_time) * 1000
                return {
                    "verdict": "BLOCK",
                    "risk_score": risk_score,
                    "is_safe": False,
                    "threats": threats,
                    "latency_ms": elapsed,
                    "engines_used": engines_used
                }

        # =====================================================================
        # TIER 2: Python Fallback Heuristics
        # =====================================================================
        
        # Injection Scan
        injection_result = self.injection_engine.scan(prompt)
        engines_used.append("injection")
        if not getattr(injection_result, 'is_safe', True):
            risk_score = max(risk_score, getattr(injection_result, 'risk_score', 0))
            if hasattr(injection_result, 'threats'):
                threats.extend(injection_result.threats)

        # Query Scan (SQL Injection)
        if "select" in prompt.lower() or "drop" in prompt.lower() or "union" in prompt.lower() or "or" in prompt.lower():
            query_result = self.query_engine.scan_sql(prompt)
            engines_used.append("query")
            if not query_result.get("is_safe", True):
                risk_score = max(risk_score, query_result.get("risk_score", 0))
                threats.extend(query_result.get("threats", []))

        # Behavioral Analysis
        behavior_result = self.behavioral_engine.analyze(prompt, {})
        engines_used.append("behavioral")
        if isinstance(behavior_result, dict):
            risk_modifier = behavior_result.get("risk_modifier", 0)
            if risk_modifier > 0:
                risk_score = min(100.0, risk_score + risk_modifier)
                behavior_type = behavior_result.get("behavior_type", "unknown")
                threats.append(f"Behavioral anomaly: {behavior_type}")

        # Final Decision
        if risk_score >= 80:
            allowed = False
            verdict = "BLOCK"
        elif risk_score >= 40:
            allowed = False
            verdict = "WARN"
        else:
            allowed = True
            verdict = "ALLOW"

        elapsed = (time.perf_counter() - start_time) * 1000
        logger.info(f"Pipeline completed in {elapsed:.1f}ms - Verdict: {verdict}")

        return {
            "verdict": verdict,
            "risk_score": risk_score,
            "is_safe": allowed,
            "threats": threats,
            "latency_ms": elapsed,
            "engines_used": engines_used
        }

    async def analyze_response(self, prompt: str, response: str, context: dict) -> dict:
        """Egress pipeline - simple pass-through for now"""
        return {
            "allowed": True,
            "risk_score": 0.0,
            "detected_threats": [],
            "sanitized_response": response
        }

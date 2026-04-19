"""
SENTINEL Community Edition - AI Security Platform

Open source protection for LLM applications.

Engines:
- 15 detection engines for prompt injection, PII, VLM, RAG, and more
"""

__version__ = "1.0.0"
__author__ = "Dmitry Labintsev"
__license__ = "Apache-2.0"

# Re-export SentinelAnalyzer from core for backward compatibility
from .core.analyzer import SentinelAnalyzer

# Import available engines
from .engines import (
    InjectionEngine,
    QueryEngine,
    BehavioralEngine,
)

__all__ = [
    "SentinelAnalyzer",
    "InjectionEngine",
    "QueryEngine",
    "BehavioralEngine",
]

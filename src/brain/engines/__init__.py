"""
SENTINEL Engines Package — Shim Layer.
Provides compatibility between SentinelAnalyzer and sentinel_core.
"""

from .injection import InjectionEngine
from .query import QueryEngine
from .behavioral import BehavioralEngine

__all__ = [
    "InjectionEngine",
    "QueryEngine",
    "BehavioralEngine",
]

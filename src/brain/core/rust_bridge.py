"""
Rust Bridge - Optional high-performance detection
Falls back to Python if Rust not available
"""
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("RustBridge")

# Try to import Rust module
try:
    from sentinel_core import quick_scan, SentinelEngine
    RUST_AVAILABLE = True
    logger.info("✓ Rust engines available (sentinel_core)")
except ImportError as e:
    RUST_AVAILABLE = False
    logger.warning(f"✗ Rust engines not available, using Python fallback. Error: {e}")


class RustBridge:
    """Bridge to Rust detection engines"""
    
    def __init__(self):
        self.available = RUST_AVAILABLE
        self._engine = None
    
    @property
    def engine(self):
        """Lazy load Rust engine"""
        if not self.available:
            return None
        if self._engine is None:
            self._engine = SentinelEngine()
        return self._engine
    
    def quick_scan(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Fast Rust scan (1-5ms)
        Returns None if Rust not available
        """
        if not self.available:
            return None
        
        try:
            result = quick_scan(text)
            return {
                "detected": result.detected,
                "risk_score": result.risk_score,
                "threats": [str(m.pattern) for m in result.matches] if hasattr(result, 'matches') and result.matches else [],
                "engine": "rust_fast_path"
            }
        except Exception as e:
            logger.error(f"Rust quick_scan failed: {e}")
            return None
    
    def full_analysis(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Full Rust analysis with all engines
        Returns None if Rust not available
        """
        if not self.available or not self.engine:
            return None
        
        try:
            result = self.engine.analyze(text)
            return {
                "detected": result.detected,
                "risk_score": result.risk_score,
                "matches": [
                    {
                        "engine": m.engine,
                        "pattern": m.pattern,
                        "confidence": m.confidence,
                        "severity": m.severity
                    }
                    for m in result.matches
                ],
                "engine": "rust_full_analysis"
            }
        except Exception as e:
            logger.error(f"Rust full_analysis failed: {e}")
            return None


# Global instance
_rust_bridge = None

def get_rust_bridge() -> RustBridge:
    """Get global Rust bridge instance"""
    global _rust_bridge
    if _rust_bridge is None:
        _rust_bridge = RustBridge()
    return _rust_bridge

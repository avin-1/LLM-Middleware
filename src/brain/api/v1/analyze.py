"""
SENTINEL Brain API v1 - Analyze Endpoints

Uses SentinelAnalyzer for full multi-engine analysis.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import List, Optional
import time
import logging

router = APIRouter(prefix="/analyze", tags=["analyze"])
logger = logging.getLogger("AnalyzeAPI")


class AnalyzeRequest(BaseModel):
    """Request model for text analysis."""

    text: str = Field(..., min_length=1, max_length=100000)
    profile: str = Field(default="standard", pattern="^(lite|standard|enterprise)$")
    session_id: Optional[str] = None
    engines: Optional[List[str]] = None


class ThreatInfo(BaseModel):
    """Detected threat information."""

    name: str
    engine: str
    confidence: float
    severity: str = "MEDIUM"
    details: Optional[str] = None


class AnalyzeResponse(BaseModel):
    """Response model for text analysis."""

    verdict: str  # ALLOW, WARN, BLOCK
    risk_score: float
    is_safe: bool
    threats: List[ThreatInfo]
    profile: str
    latency_ms: float
    engines_used: List[str]
    language: Optional[str] = None
    request_id: str = ""
    llm_response: Optional[str] = None  # LLM response for allowed messages


@router.post("", response_model=AnalyzeResponse)
async def analyze_text(request: AnalyzeRequest):
    """
    Analyze text using available engines.

    Currently available engines:
    - InjectionEngine: Regex pattern matching
    - QueryEngine: SQL injection detection
    - BehavioralEngine: Behavioral analysis
    """
    start_time = time.time()

    try:
        # Import only the engines that exist
        from ...engines.injection import InjectionEngine
        from ...engines.query import QueryEngine
        from ...engines.behavioral import BehavioralEngine

        # Create engine instances
        injection_engine = InjectionEngine()
        query_engine = QueryEngine()
        behavioral_engine = BehavioralEngine()

        # Run analysis with available engines
        threats = []
        risk_score = 0.0

        # 1. Injection detection
        try:
            injection_result = injection_engine.scan(request.text)
            if hasattr(injection_result, 'is_safe') and not injection_result.is_safe:
                risk_score = max(risk_score, injection_result.risk_score)
                if hasattr(injection_result, 'threats'):
                    for threat in injection_result.threats:
                        threats.append(
                            ThreatInfo(
                                name=threat,
                                engine="injection",
                                confidence=injection_result.risk_score / 100.0,
                                severity="HIGH" if injection_result.risk_score >= 70 else "MEDIUM",
                            )
                        )
        except Exception as e:
            logger.warning(f"Injection engine error: {e}")

        # 2. Query validation (SQL injection)
        try:
            query_result = query_engine.scan_sql(request.text)
            if isinstance(query_result, dict):
                if not query_result.get("is_safe", True):
                    query_risk = query_result.get("risk_score", 0)
                    risk_score = max(risk_score, query_risk)
                    for threat in query_result.get("threats", []):
                        threats.append(
                            ThreatInfo(
                                name=threat,
                                engine="query",
                                confidence=query_risk / 100.0,
                                severity="MEDIUM",
                            )
                        )
        except Exception as e:
            logger.warning(f"Query engine error: {e}")

        # 3. Behavioral analysis
        try:
            behavioral_result = behavioral_engine.analyze(request.text, {})
            if isinstance(behavioral_result, dict):
                risk_modifier = behavioral_result.get("risk_modifier", 0)
                if risk_modifier > 0:
                    risk_score = min(100, risk_score + risk_modifier)
                    behavior_type = behavioral_result.get("behavior_type", "unknown")
                    threats.append(
                        ThreatInfo(
                            name=f"Behavioral anomaly: {behavior_type}",
                            engine="behavioral",
                            confidence=risk_modifier / 100.0,
                            severity="MEDIUM",
                        )
                    )
        except Exception as e:
            logger.warning(f"Behavioral engine error: {e}")

        latency = (time.time() - start_time) * 1000

        # Determine verdict
        if risk_score >= 80:
            verdict = "BLOCK"
            is_safe = False
        elif risk_score >= 40:
            verdict = "WARN"
            is_safe = False
        else:
            verdict = "ALLOW"
            is_safe = True

        # If ALLOWED, get LLM response
        llm_response = None
        if verdict == "ALLOW":
            try:
                from ...services.llm_service import get_llm_service
                llm_service = get_llm_service()
                llm_response = await llm_service.generate_response(request.text)
                if llm_response:
                    logger.info(f"LLM response generated for allowed message")
                else:
                    logger.warning(f"No LLM response generated")
                    llm_response = "LLM service is not responding. Please check configuration."
            except Exception as e:
                logger.warning(f"LLM generation failed: {e}")
                llm_response = "LLM service error. Configure HUGGINGFACE_API_KEY in .env for AI responses."

        logger.info(
            f"Analysis: verdict={verdict}, score={risk_score:.1f}, "
            f"threats={len(threats)}, latency={latency:.0f}ms"
        )

        return AnalyzeResponse(
            verdict=verdict,
            risk_score=risk_score,
            is_safe=is_safe,
            threats=threats,
            profile=request.profile,
            latency_ms=latency,
            engines_used=["injection", "query", "behavioral"],
            language="en",
            request_id=f"req_{int(start_time * 1000)}",
            llm_response=llm_response,
        )

    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stream")
async def analyze_stream(request: AnalyzeRequest):
    """Stream analysis with real-time progress (SSE)."""
    try:
        from ..streaming import (
            StreamingAnalyzer,
            create_streaming_response,
        )
        from ...core.analyzer import SentinelAnalyzer

        analyzer = SentinelAnalyzer()
        streamer = StreamingAnalyzer(analyzer)

        generator = streamer.analyze_stream(
            request.text,
            profile=request.profile,
        )

        return create_streaming_response(generator)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/batch")
async def analyze_batch(
    texts: List[str] = Query(..., max_length=100),
    profile: str = "standard",
):
    """Analyze multiple texts in batch."""
    if len(texts) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 texts per batch")

    results = []
    for text in texts:
        req = AnalyzeRequest(text=text, profile=profile)
        result = await analyze_text(req)
        results.append(result)

    return {"results": results, "count": len(results)}

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
    Analyze text using the advanced SentinelAnalyzer pipeline.
    
    Features:
    - Tier 0: Rust Core Engine (Aho-Corasick + Regex)
    - Tier 1: Semantic Detection (ChromaDB Vector Embeddings)
    - Tier 2: Python Fallback Heuristics
    """
    start_time = time.time()

    try:
        from ...core.analyzer import SentinelAnalyzer
        
        # Instantiate the advanced analyzer
        analyzer = SentinelAnalyzer()
        
        # Run analysis pipeline
        context = {"user_id": request.session_id or "anonymous"}
        result = await analyzer.analyze(request.text, context)

        verdict = result["verdict"]
        risk_score = result["risk_score"]
        is_safe = result["is_safe"]
        threats_list = result["threats"]
        latency = result["latency_ms"]
        engines_used = result.get("engines_used", [])

        # Format threats for API
        formatted_threats = []
        for t in threats_list:
            formatted_threats.append(
                ThreatInfo(
                    name=t,
                    engine="sentinel_pipeline",
                    confidence=1.0,
                    severity="HIGH" if risk_score >= 70 else "MEDIUM",
                )
            )

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
            f"threats={len(formatted_threats)}, latency={latency:.0f}ms"
        )

        return AnalyzeResponse(
            verdict=verdict,
            risk_score=risk_score,
            is_safe=is_safe,
            threats=formatted_threats,
            profile=request.profile,
            latency_ms=latency,
            engines_used=engines_used,
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

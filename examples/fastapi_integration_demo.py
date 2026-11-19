"""AlertSense FastAPI Integration Reference Server for Member 2.

Demonstrates how Member 2 can host AlertSense AI & Multi-Agent orchestration
within their FastAPI application shell.

Endpoints:
- POST /api/v1/incidents/analyze -> Full LangGraph multi-agent analysis
- POST /api/v1/alerts/correlate  -> Fast pure-Python correlation
- GET  /api/v1/health            -> System and AI engine health status

Run standalone:
    python examples/fastapi_integration_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from backend.services.ai_service import (
    AnalyzeAlertsRequest,
    AnalyzeAlertsResponse,
    CorrelateAlertsRequest,
    run_full_incident_analysis,
    run_fast_correlation
)

app = FastAPI(
    title="AlertSense AI Engine API",
    description="Multi-Agent Alert Storm Correlation and Root Cause Analysis Engine (Member 1)",
    version="1.0.0"
)

# Enable CORS for Member 2's React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/v1/health", tags=["Monitoring"])
def health_check():
    """Health check endpoint confirming AI engine readiness."""
    return {
        "status": "healthy",
        "service": "AlertSense-AI-Orchestrator",
        "agent_pipeline": ["CorrelationAgent", "RootCauseAgent", "SeverityAgent", "ReportingAgent"],
        "orchestrator": "LangGraph StateGraph"
    }


@app.post(
    "/api/v1/incidents/analyze",
    response_model=AnalyzeAlertsResponse,
    tags=["Incident Analysis"],
    status_code=status.HTTP_200_OK
)
def analyze_incident_storm(payload: AnalyzeAlertsRequest):
    """Full Multi-Agent Pipeline.
    
    1. Preprocesses & normalizes alerts.
    2. Correlates alerts into candidate incident clusters.
    3. Performs topological & Gemini-grounded root cause analysis.
    4. Evaluates P1-P4 severity and blast radius using deterministic rules.
    5. Assembles structured incident report and actionable recommendations.
    """
    try:
        result = run_full_incident_analysis(
            alerts=payload.alerts,
            service_dependencies=payload.service_dependencies,
            config=payload.config
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AlertSense workflow error: {e}"
        )


@app.post(
    "/api/v1/alerts/correlate",
    tags=["Fast Correlation"],
    status_code=status.HTTP_200_OK
)
def correlate_alert_stream(payload: CorrelateAlertsRequest):
    """Fast Pure-Python Correlation Endpoint.
    
    Bypasses LLM reasoning for high-frequency alert ingestion.
    Returns candidate incident clusters, deduplication summary, and noise reduction ratio.
    """
    try:
        corr_result = run_fast_correlation(
            alerts=payload.alerts,
            service_dependencies=payload.service_dependencies,
            time_window_seconds=payload.time_window_seconds,
            correlation_threshold=payload.correlation_threshold
        )
        return corr_result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Correlation error: {e}"
        )


if __name__ == "__main__":
    import uvicorn
    print("\n[*] Starting AlertSense FastAPI Integration Reference Server...")
    print("[*] Documentation available at: http://127.0.0.1:8000/docs")
    uvicorn.run("fastapi_integration_demo:app", host="127.0.0.1", port=8000, reload=False)

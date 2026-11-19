"""AlertSense AI Service Interface for Member 2 (Backend Integration).

This module exposes clean, typed, FastAPI-compatible interfaces and Pydantic
request/response models so Member 2 can seamlessly integrate AlertSense into
FastAPI endpoints, background worker queues, and PostgreSQL persistence.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.services.correlation_engine import NormalizedAlert, correlate_alerts
from orchestrator.workflow import analyze_alerts


# ---------------------------------------------------------------------------
# FastAPI Request & Response Models for Member 2
# ---------------------------------------------------------------------------

class ServiceDependencyEntry(BaseModel):
    """A service and its upstream dependencies."""
    service: str = Field(..., description="Downstream service name")
    depends_on: List[str] = Field(default_factory=list, description="Upstream services this service relies on")


class ServiceDependenciesPayload(BaseModel):
    """Dependency graph payload."""
    services: List[ServiceDependencyEntry] = Field(default_factory=list)


class AnalyzeAlertsRequest(BaseModel):
    """Payload for full multi-agent analysis endpoint: POST /api/v1/incidents/analyze."""
    alerts: List[Dict[str, Any]] = Field(..., description="List of raw or normalized monitoring alerts")
    service_dependencies: Dict[str, Any] = Field(..., description="Service topology graph dictionary")
    config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Optional overrides (threshold, model, etc.)")


class CorrelateAlertsRequest(BaseModel):
    """Payload for lightweight pure-Python correlation: POST /api/v1/alerts/correlate."""
    alerts: List[Dict[str, Any]] = Field(..., description="List of normalized alerts")
    service_dependencies: Dict[str, Any] = Field(..., description="Service topology graph")
    time_window_seconds: int = Field(300, description="Sliding correlation window in seconds")
    correlation_threshold: float = Field(0.55, description="Similarity threshold (0.0 - 1.0)")


class AnalyzeAlertsResponse(BaseModel):
    """Full multi-agent response returned to Member 2."""
    workflow_status: str = Field(..., description="completed, completed_with_fallback, requires_human_review, or error")
    needs_human_review: bool
    candidate_incidents: List[Dict[str, Any]]
    root_cause_findings: List[Dict[str, Any]]
    severity_assessments: List[Dict[str, Any]]
    incident_report: Dict[str, Any]
    correlation_metadata: Optional[Dict[str, Any]] = None
    errors: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Direct Python Callables for Member 2 Backend
# ---------------------------------------------------------------------------

def run_full_incident_analysis(
    alerts: List[Dict[str, Any]],
    service_dependencies: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Execute complete multi-agent workflow (Correlation + RCA + Severity + Reporting).
    
    Callable directly by Member 2 in FastAPI route handlers or Celery workers:
        result = run_full_incident_analysis(alerts, dependencies)
    """
    return analyze_alerts(
        alerts=alerts,
        service_dependencies=service_dependencies,
        config=config
    )


def run_fast_correlation(
    alerts: List[Dict[str, Any]],
    service_dependencies: Dict[str, Any],
    time_window_seconds: int = 300,
    correlation_threshold: float = 0.55
) -> Dict[str, Any]:
    """Execute fast pure-Python correlation without running LLM agents.
    
    Useful for high-frequency alert ingestion pipelines:
        corr_result = run_fast_correlation(alerts, dependencies)
    """
    return correlate_alerts(
        alerts=alerts,
        service_dependencies=service_dependencies,
        time_window_seconds=time_window_seconds,
        correlation_threshold=correlation_threshold
    )

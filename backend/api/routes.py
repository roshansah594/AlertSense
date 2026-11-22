"""AlertSense API Routes.

Connects the FastAPI backend shell directly to the LangGraph AI multi-agent
orchestrator and SQLite persistence layer with authentication and RBAC.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.api.auth import get_current_user, require_admin
from backend.services.ingestion import (
    process_alerts,
    load_default_dependencies,
    load_sample_alerts
)
from backend.services.ai_service import run_full_incident_analysis
from backend.database.models import (
    save_alerts,
    get_all_alerts,
    save_incident_analysis,
    get_all_incidents,
    get_incident_by_id,
    get_analytics_summary,
    clear_all_data
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/alerts",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_current_user)]
)
def receive_alerts(alerts: List[Dict[str, Any]]):
    """Ingest a batch of normalized monitoring alerts into the platform.
    
    Requires valid authentication token.
    """
    if not isinstance(alerts, list) or not alerts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Alerts payload must be a non-empty list of alert objects."
        )

    try:
        processed = process_alerts(alerts)
        inserted_count = save_alerts(processed)

        return {
            "message": "Alerts processed and stored successfully",
            "received": len(alerts),
            "stored": inserted_count,
            "total_active_alerts": len(get_all_alerts())
        }
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    except Exception as e:
        logger.error(f"Error ingesting alerts: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest alerts: {e}"
        )


@router.get(
    "/alerts",
    dependencies=[Depends(get_current_user)]
)
def fetch_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    service: Optional[str] = Query(None, description="Filter by service name")
):
    """Retrieve all ingested alerts with optional severity and service filters.
    
    Requires valid authentication token.
    """
    sev = severity if isinstance(severity, str) else None
    svc = service if isinstance(service, str) else None
    return get_all_alerts(severity=sev, service=svc)


@router.post(
    "/alerts/load-sample",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_current_user)]
)
def load_sample_alerts_endpoint():
    """Load benchmark synthetic alerts (16 alerts across 6 scenarios) into the platform.
    
    Requires valid authentication token.
    """
    samples = load_sample_alerts()
    if not samples:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="datasets/sample_alerts.json not found."
        )

    processed = process_alerts(samples)
    inserted = save_alerts(processed)

    return {
        "message": f"Successfully loaded {len(processed)} benchmark sample alerts ({inserted} new).",
        "total_alerts": len(get_all_alerts())
    }


@router.post(
    "/incidents/analyze",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_current_user)]
)
def analyze_incidents(payload: Optional[Dict[str, Any]] = None):
    """Execute LangGraph Multi-Agent Investigation.
    
    Traverses: Preprocessing -> Correlation -> Root Cause -> Severity -> Reporting.
    Persists resulting incidents and returns executive report.
    Requires valid authentication token.
    """
    if payload is not None and not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Analysis payload must be a JSON object."
        )

    # Use alerts from payload if provided; otherwise load all alerts from DB
    if payload and payload.get("alerts"):
        raw_alerts = payload["alerts"]
        if not isinstance(raw_alerts, list):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="'alerts' field in payload must be a list."
            )
    else:
        raw_alerts = get_all_alerts()

    if not raw_alerts:
        return {
            "message": "No alerts available. Submit alerts or load sample alerts to run investigation.",
            "alert_count": 0,
            "incidents": [],
            "integration_status": "Idle"
        }

    # Load service topology
    dependencies = (
        payload.get("service_dependencies")
        if payload and payload.get("service_dependencies")
        else load_default_dependencies()
    )

    config = payload.get("config", {}) if payload else {}

    try:
        # Run complete multi-agent LangGraph workflow
        analysis_result = run_full_incident_analysis(
            alerts=raw_alerts,
            service_dependencies=dependencies,
            config=config
        )

        # Persist candidate incidents, root causes, severity scores, and actions
        save_incident_analysis(analysis_result)

        stored_incidents = get_all_incidents()
        candidate_count = len(analysis_result.get("candidate_incidents", []))
        noise_red = analysis_result.get("correlation_metadata", {}).get("noise_reduction_ratio", 0.0)

        return {
            "message": f"Investigation complete. Consolidated {len(raw_alerts)} alerts into {candidate_count} incident(s).",
            "workflow_status": analysis_result.get("workflow_status"),
            "needs_human_review": analysis_result.get("needs_human_review", False),
            "alert_count": len(raw_alerts),
            "incidents_count": len(stored_incidents),
            "noise_reduction_ratio": noise_red,
            "incidents": stored_incidents,
            "incident_report": analysis_result.get("incident_report", {}),
            "integration_status": "Active (LangGraph StateGraph + Gemini AI)"
        }
    except Exception as e:
        logger.error(f"Error during incident analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Multi-agent investigation failed: {e}"
        )


@router.get(
    "/incidents",
    dependencies=[Depends(get_current_user)]
)
def fetch_incidents():
    """Retrieve all investigated incidents with root cause, severity, and timeline.
    
    Requires valid authentication token.
    """
    return get_all_incidents()


@router.get(
    "/incidents/{incident_id}",
    dependencies=[Depends(get_current_user)]
)
def fetch_incident_details(incident_id: str):
    """Retrieve deep forensic investigation details for a specific incident.
    
    Requires valid authentication token.
    """
    inc = get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found."
        )
    return inc


@router.get(
    "/analytics",
    dependencies=[Depends(get_current_user)]
)
def fetch_analytics():
    """Retrieve aggregated platform analytics, noise reduction, and severity distribution.
    
    Requires valid authentication token.
    """
    return get_analytics_summary()


@router.post(
    "/reset",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_admin)]
)
def reset_platform():
    """Reset all alerts and incidents.
    
    STRICT: Requires Administrator privileges (admin role).
    """
    clear_all_data()
    return {"message": "All alerts and incidents cleared successfully."}

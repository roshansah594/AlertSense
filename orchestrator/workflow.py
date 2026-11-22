"""AlertSense LangGraph Workflow Orchestrator.

Constructs and compiles the supervisor-controlled sequential StateGraph:
START -> preprocessing -> correlation -> root_cause -> severity -> reporting -> finalize -> END

Provides the primary integration interface for Member 2:
    analyze_alerts(alerts, service_dependencies, config=None) -> dict
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from langgraph.graph import StateGraph, START, END

from orchestrator.state import AlertSenseState
from backend.services.correlation_engine import NormalizedAlert
from ai_agents.correlation_agent import correlation_agent_node
from ai_agents.root_cause_agent import root_cause_agent_node
from ai_agents.severity_agent import severity_agent_node
from ai_agents.reporting_agent import reporting_agent_node

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Preprocessing Node (Bug 1 Fix: Malformed Alert Handling)
# ---------------------------------------------------------------------------

def preprocessing_node(state: AlertSenseState) -> Dict[str, Any]:
    """Validate, sanitize, and sort incoming alert payloads.
    
    Robustly handles malformed items (None, strings, numbers, lists, empty dicts,
    or missing fields) without crashing the workflow.
    """
    raw_alerts = state.get("alerts")
    if not isinstance(raw_alerts, list):
        raw_alerts = []

    valid_alerts: List[Dict[str, Any]] = []
    errors = list(state.get("errors", []))

    for alert in raw_alerts:
        # Check if alert is a dictionary
        if not isinstance(alert, dict):
            logger.warning(f"Malformed alert (expected dict, got {type(alert).__name__}): {alert}")
            errors.append({
                "stage": "preprocessing",
                "alert_id": "unknown",
                "error": f"Malformed alert payload: expected dict, got {type(alert).__name__} ({repr(alert)})"
            })
            continue

        # Extract alert_id safely
        aid = alert.get("alert_id")
        alert_id_str = str(aid).strip() if (aid is not None and str(aid).strip()) else "unknown"

        try:
            norm = NormalizedAlert(**alert)
            valid_alerts.append(norm.model_dump())
        except Exception as e:
            logger.warning(f"Validation error for alert '{alert_id_str}': {e}")
            errors.append({
                "stage": "preprocessing",
                "alert_id": alert_id_str,
                "error": str(e)
            })

    return {
        "preprocessed_alerts": valid_alerts,
        "alerts": valid_alerts,  # normalized alerts replace raw alerts
        "errors": errors
    }


def route_after_preprocessing(state: AlertSenseState) -> str:
    """Route to correlation if valid alerts exist; otherwise finalize."""
    valid_alerts = state.get("preprocessed_alerts", [])
    if not valid_alerts:
        return "finalize"
    return "correlation"


# ---------------------------------------------------------------------------
# Workflow Finalization & Status Node
# ---------------------------------------------------------------------------

def finalize_workflow_node(state: AlertSenseState) -> Dict[str, Any]:
    """Evaluate overall workflow status, audit errors, and set review flags."""
    errors = state.get("errors", [])
    needs_review = state.get("needs_human_review", False)
    root_cause_findings = state.get("root_cause_findings", [])
    valid_alerts = state.get("preprocessed_alerts", [])
    incident_report = state.get("incident_report")

    # Check if no valid alerts were processed
    if not valid_alerts:
        status_code = "completed" if not errors else "completed_with_errors"
        return {
            "workflow_status": status_code,
            "needs_human_review": bool(errors),
            "incident_report": {
                "total_incidents_reported": 0,
                "high_severity_incidents_count": 0,
                "incidents": [],
                "workflow_status": status_code
            }
        }

    # Determine status
    if any(e.get("stage") in {"correlation_agent", "graph_runtime"} for e in errors):
        status = "error"
        needs_review = True
    elif needs_review:
        status = "requires_human_review"
    elif any(f.get("status") == "completed_with_fallback" for f in root_cause_findings if isinstance(f, dict)):
        status = "completed_with_fallback"
    else:
        status = "completed"

    # Ensure incident report has the final workflow status
    if isinstance(incident_report, dict):
        incident_report["workflow_status"] = status

    return {
        "workflow_status": status,
        "needs_human_review": needs_review,
        "incident_report": incident_report or {
            "total_incidents_reported": 0,
            "high_severity_incidents_count": 0,
            "incidents": [],
            "workflow_status": status
        }
    }


# ---------------------------------------------------------------------------
# Graph Builder
# ---------------------------------------------------------------------------

def create_alert_sense_workflow() -> Any:
    """Build and compile the LangGraph StateGraph workflow."""
    builder = StateGraph(AlertSenseState)

    # Register Nodes
    builder.add_node("preprocessing", preprocessing_node)
    builder.add_node("correlation", correlation_agent_node)
    builder.add_node("root_cause", root_cause_agent_node)
    builder.add_node("severity", severity_agent_node)
    builder.add_node("reporting", reporting_agent_node)
    builder.add_node("finalize", finalize_workflow_node)

    # Register Edges
    builder.add_edge(START, "preprocessing")

    # Conditional branching from preprocessing
    builder.add_conditional_edges(
        "preprocessing",
        route_after_preprocessing,
        {
            "correlation": "correlation",
            "finalize": "finalize"
        }
    )

    # Sequential Agent Flow
    builder.add_edge("correlation", "root_cause")
    builder.add_edge("root_cause", "severity")
    builder.add_edge("severity", "reporting")
    builder.add_edge("reporting", "finalize")
    builder.add_edge("finalize", END)

    return builder.compile()


# ---------------------------------------------------------------------------
# Primary Integration Interface (Callable by Member 2)
# ---------------------------------------------------------------------------

_COMPILED_WORKFLOW = None


def get_compiled_workflow():
    """Singleton getter for compiled LangGraph workflow."""
    global _COMPILED_WORKFLOW
    if _COMPILED_WORKFLOW is None:
        _COMPILED_WORKFLOW = create_alert_sense_workflow()
    return _COMPILED_WORKFLOW


def analyze_alerts(
    alerts: List[Dict[str, Any]],
    service_dependencies: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Execute complete end-to-end AlertSense multi-agent workflow.

    This function serves as the agreed integration contract with Member 2's backend.

    Args:
        alerts: List of raw/normalized alert dictionaries.
        service_dependencies: Service dependency topology.
        config: Optional runtime overrides (thresholds, Gemini model, etc.).

    Returns:
        Structured dictionary conforming to the incident response data contract.
    """
    initial_state: AlertSenseState = {
        "alerts": alerts if isinstance(alerts, list) else [],
        "service_dependencies": service_dependencies if isinstance(service_dependencies, (dict, list)) else {},
        "config": config or {},
        "errors": [],
        "needs_human_review": False,
        "workflow_status": "processing"
    }

    workflow = get_compiled_workflow()

    try:
        final_state: Dict[str, Any] = workflow.invoke(initial_state)
        return final_state
    except Exception as e:
        logger.error(f"AlertSense workflow execution failed: {e}", exc_info=True)
        return {
            "workflow_status": "error",
            "error_message": str(e),
            "errors": [{"stage": "graph_runtime", "error": str(e)}],
            "needs_human_review": True,
            "incident_report": {"incidents": [], "total_incidents_reported": 0}
        }

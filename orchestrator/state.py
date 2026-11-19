"""LangGraph Shared Workflow State Definition.

Defines the centralized state contract shared across all agent nodes
in the AlertSense sequential supervisor workflow.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from typing_extensions import TypedDict


class AlertSenseState(TypedDict, total=False):
    """Centralized shared state for the AlertSense multi-agent workflow.

    Conforms to the data contracts agreed upon with Member 2.
    """
    # Inputs
    alerts: List[Dict[str, Any]]
    service_dependencies: Dict[str, Any]
    config: Dict[str, Any]

    # Preprocessing Stage
    preprocessed_alerts: List[Dict[str, Any]]

    # Correlation Agent Stage
    correlation_groups: List[Dict[str, Any]]
    candidate_incidents: List[Dict[str, Any]]
    ungrouped_alert_ids: List[str]
    correlation_metadata: Dict[str, Any]

    # Root Cause Agent Stage
    root_cause_findings: List[Dict[str, Any]]

    # Severity Agent Stage
    severity_assessments: List[Dict[str, Any]]
    is_high_severity_incident: bool

    # Incident Reporting Agent Stage
    incident_report: Dict[str, Any]

    # Supervision & Governance
    errors: List[Dict[str, Any]]
    needs_human_review: bool
    workflow_status: str  # "completed", "completed_with_fallback", "insufficient_evidence", "error"

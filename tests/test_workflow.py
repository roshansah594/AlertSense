"""End-to-End Tests for AlertSense LangGraph Workflow Orchestrator.

Verifies:
1. Full end-to-end multi-agent execution via analyze_alerts.
2. Graph compilation, node registration, and conditional routing.
3. Preprocessing and error containment for malformed alerts.
4. Empty alerts edge case handling.
5. Deterministic fallback behavior when offline.
"""

import json
from pathlib import Path
import pytest

from orchestrator.workflow import (
    create_alert_sense_workflow,
    analyze_alerts
)

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"


@pytest.fixture
def sample_data():
    """Load sample alerts and service dependencies."""
    with open(DATASETS_DIR / "sample_alerts.json", "r", encoding="utf-8") as f:
        alerts = json.load(f)
    with open(DATASETS_DIR / "service_dependencies.json", "r", encoding="utf-8") as f:
        dependencies = json.load(f)
    return alerts, dependencies


def test_workflow_graph_compilation_and_nodes():
    """Verify LangGraph StateGraph builds and contains all expected agent nodes."""
    workflow = create_alert_sense_workflow()
    assert workflow is not None

    # Check registered nodes in the compiled graph
    node_keys = set(workflow.nodes.keys())
    expected_nodes = {
        "preprocessing",
        "correlation",
        "root_cause",
        "severity",
        "reporting",
        "finalize"
    }
    for node in expected_nodes:
        assert node in node_keys, f"Node '{node}' must be present in workflow graph"


def test_end_to_end_analyze_alerts(sample_data):
    """Primary integration test: analyze_alerts runs through all 5 agent nodes successfully."""
    alerts, dependencies = sample_data
    result = analyze_alerts(
        alerts=alerts,
        service_dependencies=dependencies,
        config={"correlation_threshold": 0.55}
    )

    # 1. Workflow Status
    assert result["workflow_status"] in {"completed", "completed_with_fallback", "requires_human_review"}

    # 2. Stage 1: Preprocessing
    assert "preprocessed_alerts" in result
    assert len(result["preprocessed_alerts"]) == len(alerts)

    # 3. Stage 2: Correlation
    assert "correlation_groups" in result
    assert "candidate_incidents" in result
    assert len(result["candidate_incidents"]) >= 2
    assert "correlation_metadata" in result
    assert result["correlation_metadata"]["noise_reduction_ratio"] > 0.50

    # 4. Stage 3: Root Cause Analysis
    assert "root_cause_findings" in result
    assert len(result["root_cause_findings"]) == len(result["candidate_incidents"])
    db_rca = next(
        f for f in result["root_cause_findings"]
        if f["primary_hypothesis"]["root_cause_service"] == "database"
    )
    assert db_rca is not None
    assert "ALT-001" in db_rca["primary_hypothesis"]["evidence_alert_ids"]

    # 5. Stage 4: Severity Assessment
    assert "severity_assessments" in result
    assert result["is_high_severity_incident"] is True
    p1_assessment = next(
        s for s in result["severity_assessments"]
        if s["severity_level"] == "P1_CRITICAL"
    )
    assert p1_assessment is not None

    # 6. Stage 5: Incident Reporting
    assert "incident_report" in result
    report = result["incident_report"]
    assert report["total_incidents_reported"] == len(result["candidate_incidents"])
    assert report["high_severity_incidents_count"] >= 1
    assert len(report["incidents"]) == len(result["candidate_incidents"])

    # Ensure no unhandled fatal errors
    critical_errors = [e for e in result["errors"] if e.get("stage") in {"correlation_agent", "graph_runtime"}]
    assert len(critical_errors) == 0


def test_workflow_empty_alerts():
    """Empty alerts input must bypass downstream agents and finalize cleanly."""
    result = analyze_alerts(
        alerts=[],
        service_dependencies={"services": []}
    )

    assert result["workflow_status"] == "completed"
    assert result["incident_report"]["total_incidents_reported"] == 0
    assert result["incident_report"]["incidents"] == []


def test_workflow_malformed_alert_containment():
    """Malformed alerts must be caught in preprocessing while valid alerts proceed."""
    mixed_alerts = [
        {
            # Malformed alert: missing alert_type and service
            "alert_id": "ALT-BAD",
            "message": "Malformed alert without required fields",
            "severity": "critical",
            "timestamp": "2026-11-19T10:00:00Z"
        },
        {
            # Valid alert
            "alert_id": "ALT-VALID",
            "service": "database",
            "alert_type": "high_cpu",
            "message": "Valid CPU alert",
            "severity": "high",
            "timestamp": "2026-11-19T10:00:00Z"
        }
    ]

    result = analyze_alerts(
        alerts=mixed_alerts,
        service_dependencies={"services": []}
    )

    assert len(result["preprocessed_alerts"]) == 1
    assert result["preprocessed_alerts"][0]["alert_id"] == "ALT-VALID"
    # Check that error was safely captured in preprocessing
    assert any(e.get("stage") == "preprocessing" for e in result["errors"])
    assert result["incident_report"]["total_incidents_reported"] == 1


def test_workflow_deterministic_offline_execution(sample_data):
    """When api_key is None, workflow executes seamlessly using deterministic fallbacks."""
    alerts, dependencies = sample_data
    result = analyze_alerts(
        alerts=alerts,
        service_dependencies=dependencies,
        config={"gemini_api_key": None}
    )

    assert result["workflow_status"] in {"completed", "completed_with_fallback", "requires_human_review"}
    assert len(result["incident_report"]["incidents"]) > 0
    # Confirm fallback was recorded
    assert any(
        f.get("status") == "completed_with_fallback"
        for f in result["root_cause_findings"]
    )

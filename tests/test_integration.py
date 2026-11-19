"""Integration Tests for Member 2 Interface and FastAPI Endpoints.

Verifies:
1. Direct Python callables (run_full_incident_analysis, run_fast_correlation).
2. Pydantic request and response schemas (AnalyzeAlertsRequest, AnalyzeAlertsResponse).
3. FastAPI endpoint handlers for both reference demo server and unified backend.
4. Database persistence and end-to-end incident analysis flow.
"""

import json
from pathlib import Path
import pytest

from backend.services.ai_service import (
    AnalyzeAlertsRequest,
    AnalyzeAlertsResponse,
    CorrelateAlertsRequest,
    run_full_incident_analysis,
    run_fast_correlation
)
from examples.fastapi_integration_demo import (
    health_check as demo_health_check,
    analyze_incident_storm as demo_analyze_endpoint,
    correlate_alert_stream as demo_correlate_endpoint
)
from backend.api.routes import (
    load_sample_alerts_endpoint,
    fetch_alerts,
    analyze_incidents,
    fetch_incidents,
    fetch_analytics,
    reset_platform
)

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"


@pytest.fixture
def sample_data():
    with open(DATASETS_DIR / "sample_alerts.json", "r", encoding="utf-8") as f:
        alerts = json.load(f)
    with open(DATASETS_DIR / "service_dependencies.json", "r", encoding="utf-8") as f:
        dependencies = json.load(f)
    return alerts, dependencies


def test_run_full_incident_analysis_callable(sample_data):
    """Direct callable run_full_incident_analysis must execute LangGraph workflow cleanly."""
    alerts, dependencies = sample_data
    result = run_full_incident_analysis(alerts, dependencies)

    assert result["workflow_status"] in {"completed", "completed_with_fallback", "requires_human_review"}
    assert "candidate_incidents" in result
    assert "root_cause_findings" in result
    assert "severity_assessments" in result
    assert "incident_report" in result


def test_run_fast_correlation_callable(sample_data):
    """Direct callable run_fast_correlation must return deterministic clustering result."""
    alerts, dependencies = sample_data
    corr_result = run_fast_correlation(alerts, dependencies, correlation_threshold=0.55)

    assert "groups" in corr_result
    assert corr_result["total_input_alerts"] == len(alerts)
    assert corr_result["noise_reduction_ratio"] > 0.50


def test_fastapi_analyze_endpoint(sample_data):
    """FastAPI analyze handler must validate request model and return structured result."""
    alerts, dependencies = sample_data

    payload = AnalyzeAlertsRequest(
        alerts=alerts,
        service_dependencies=dependencies,
        config={"correlation_threshold": 0.55}
    )

    result = demo_analyze_endpoint(payload)
    assert "workflow_status" in result
    assert "candidate_incidents" in result
    assert "incident_report" in result
    assert len(result["candidate_incidents"]) > 0

    # Ensure response model validates without error
    validated = AnalyzeAlertsResponse(**result)
    assert validated.workflow_status in {"completed", "completed_with_fallback", "requires_human_review"}


def test_fastapi_correlate_endpoint(sample_data):
    """FastAPI correlate handler must validate payload and return candidate incident clusters."""
    alerts, dependencies = sample_data

    payload = CorrelateAlertsRequest(
        alerts=alerts,
        service_dependencies=dependencies,
        time_window_seconds=300,
        correlation_threshold=0.55
    )

    data = demo_correlate_endpoint(payload)
    assert "groups" in data
    assert "candidate_incidents_count" in data
    assert data["candidate_incidents_count"] > 0


def test_fastapi_health_check():
    """FastAPI health handler must return healthy status."""
    data = demo_health_check()
    assert data["status"] == "healthy"
    assert "agent_pipeline" in data


def test_unified_backend_full_flow():
    """Test unified backend API routes with database persistence and LangGraph."""
    # 1. Reset platform
    reset_res = reset_platform()
    assert "cleared" in reset_res["message"]

    # 2. Ingest benchmark sample alerts
    load_res = load_sample_alerts_endpoint()
    assert load_res["total_alerts"] == 16

    # 3. Fetch alerts
    all_alerts = fetch_alerts()
    assert len(all_alerts) == 16

    # 4. Trigger AI investigation through unified API
    analysis_res = analyze_incidents()
    assert analysis_res["alert_count"] == 16
    assert analysis_res["incidents_count"] > 0
    assert analysis_res["noise_reduction_ratio"] > 0.5

    # 5. Fetch persisted incidents
    stored_incidents = fetch_incidents()
    assert len(stored_incidents) == analysis_res["incidents_count"]

    # Verify first incident structure
    first_inc = stored_incidents[0]
    assert "incident_id" in first_inc
    assert "title" in first_inc
    assert "severity_level" in first_inc
    assert "root_cause_service" in first_inc
    assert len(first_inc.get("recommended_actions", [])) > 0

    # 6. Fetch analytics summary
    analytics = fetch_analytics()
    assert analytics["total_alerts"] == 16
    assert analytics["total_incidents"] == len(stored_incidents)
    assert analytics["noise_reduction_ratio"] > 0.5

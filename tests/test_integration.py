"""Integration Tests for Member 2 Interface and FastAPI Endpoints.

Verifies:
1. Direct Python callables (run_full_incident_analysis, run_fast_correlation).
2. Pydantic request and response schemas (AnalyzeAlertsRequest, AnalyzeAlertsResponse).
3. Live FastAPI endpoint execution via TestClient.
"""

import json
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from backend.services.ai_service import (
    AnalyzeAlertsRequest,
    AnalyzeAlertsResponse,
    CorrelateAlertsRequest,
    run_full_incident_analysis,
    run_fast_correlation
)
from examples.fastapi_integration_demo import app

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
    """FastAPI POST /api/v1/incidents/analyze must validate request and return 200 OK."""
    alerts, dependencies = sample_data
    client = TestClient(app)

    payload = {
        "alerts": alerts,
        "service_dependencies": dependencies,
        "config": {"correlation_threshold": 0.55}
    }

    response = client.post("/api/v1/incidents/analyze", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "workflow_status" in data
    assert "candidate_incidents" in data
    assert "incident_report" in data
    assert len(data["candidate_incidents"]) > 0


def test_fastapi_correlate_endpoint(sample_data):
    """FastAPI POST /api/v1/alerts/correlate must return 200 OK."""
    alerts, dependencies = sample_data
    client = TestClient(app)

    payload = {
        "alerts": alerts,
        "service_dependencies": dependencies,
        "time_window_seconds": 300,
        "correlation_threshold": 0.55
    }

    response = client.post("/api/v1/alerts/correlate", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "groups" in data
    assert "candidate_incidents_count" in data


def test_fastapi_health_check():
    """FastAPI GET /api/v1/health must return healthy status."""
    client = TestClient(app)
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

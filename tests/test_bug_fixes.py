"""Comprehensive Test Suite for AlertSense Bug Fixes and Reliability Improvements.

Verifies all 18 required scenarios:
1. Valid alert submission.
2. Invalid alert submission.
3. Missing alert fields.
4. Invalid timestamps.
5. Duplicate alerts.
6. Multiple unrelated incidents.
7. Missing service dependencies.
8. Gemini API unavailable.
9. Gemini returns malformed JSON.
10. Root cause fallback execution.
11. Severity calculation.
12. Incident report generation.
13. Database connection failure.
14. Unauthorized API requests.
15. Unauthorized reset attempts.
16. Authorized administrator reset.
17. Empty analytics response.
18. Frontend API failures / error handling.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.correlation_engine import (
    NormalizedAlert,
    parse_iso_timestamp,
    deduplicate_alerts,
    correlate_alerts,
    CorrelationEngine
)
from backend.services.preprocessing import normalize_alert
from orchestrator.workflow import analyze_alerts, preprocessing_node
from orchestrator.state import AlertSenseState
from ai_agents.gemini_service import GeminiService
from ai_agents.root_cause_agent import RootCauseAgent
from ai_agents.severity_agent import SeverityAgent
from ai_agents.reporting_agent import ReportingAgent
from backend.database.connection import check_db_health
from backend.database.models import (
    get_analytics_summary,
    clear_all_data,
    save_alerts,
    get_all_alerts
)

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"

ADMIN_HEADERS = {"Authorization": "Bearer alertsense-admin-dev-key"}
USER_HEADERS = {"Authorization": "Bearer alertsense-user-dev-key"}
INVALID_HEADERS = {"Authorization": "Bearer invalid-token-xyz"}


@pytest.fixture
def client():
    """FastAPI TestClient fixture."""
    return TestClient(app)


@pytest.fixture
def sample_data():
    """Load benchmark alerts and dependencies."""
    with open(DATASETS_DIR / "sample_alerts.json", "r", encoding="utf-8") as f:
        alerts = json.load(f)
    with open(DATASETS_DIR / "service_dependencies.json", "r", encoding="utf-8") as f:
        dependencies = json.load(f)
    return alerts, dependencies


# ---------------------------------------------------------------------------
# Scenario 1: Valid alert submission
# ---------------------------------------------------------------------------
def test_scenario_01_valid_alert_submission(client):
    """Scenario 1: Valid alert submission with proper authentication."""
    valid_alerts = [
        {
            "alert_id": "ALT-TEST-VALID-1",
            "service": "database",
            "alert_type": "high_cpu",
            "message": "Database CPU exceeded 95%",
            "severity": "critical",
            "timestamp": "2026-11-20T10:00:00Z",
            "host": "db-node-01"
        }
    ]
    response = client.post("/api/alerts", json=valid_alerts, headers=USER_HEADERS)
    assert response.status_code == 201
    data = response.json()
    assert data["received"] == 1
    assert "stored" in data


# ---------------------------------------------------------------------------
# Scenario 2: Invalid alert submission
# ---------------------------------------------------------------------------
def test_scenario_02_invalid_alert_submission(client):
    """Scenario 2: Reject non-list or empty alert submissions."""
    # Empty list
    res_empty = client.post("/api/alerts", json=[], headers=USER_HEADERS)
    assert res_empty.status_code == 400

    # Non-list payload (e.g. dict or string)
    res_dict = client.post("/api/alerts", json={"alert_id": "foo"}, headers=USER_HEADERS)
    assert res_dict.status_code in {400, 422}


# ---------------------------------------------------------------------------
# Scenario 3: Missing alert fields & malformed alert handling
# ---------------------------------------------------------------------------
def test_scenario_03_missing_alert_fields_and_malformed():
    """Scenario 3: Preprocessing handles None, string, int, empty dict, missing fields."""
    # Test NormalizedAlert rejects missing fields
    with pytest.raises(Exception):
        NormalizedAlert(
            alert_id="ALT-BAD",
            service="database"
            # Missing alert_type, message, severity, timestamp
        )

    # Test workflow preprocessing node with malformed elements
    state: AlertSenseState = {
        "alerts": [
            None,                           # None
            "malformed string alert",       # String
            12345,                          # Integer
            [],                             # List
            {},                             # Empty dict
            {                               # Missing required fields
                "alert_id": "ALT-INCOMPLETE",
                "service": "api"
            },
            {                               # Valid alert
                "alert_id": "ALT-GOOD-1",
                "service": "database",
                "alert_type": "high_cpu",
                "message": "High CPU utilization",
                "severity": "high",
                "timestamp": "2026-11-20T10:00:00Z"
            }
        ],
        "errors": []
    }

    result = preprocessing_node(state)
    assert len(result["preprocessed_alerts"]) == 1
    assert result["preprocessed_alerts"][0]["alert_id"] == "ALT-GOOD-1"
    # Errors recorded for malformed alerts without crashing
    assert len(result["errors"]) >= 5


# ---------------------------------------------------------------------------
# Scenario 4: Timestamp validation & timezone normalization
# ---------------------------------------------------------------------------
def test_scenario_04_timestamp_validation():
    """Scenario 4: Proper ISO 8601 parsing, UTC normalization, and rejection of invalid timestamps."""
    # Invalid timestamps that must raise ValueError
    invalid_ts = [
        "hello123",
        "",
        "   ",
        None,
        "2024-02-31T00:00:00Z",  # Non-existent date
        "not-a-date",
        12345
    ]
    for ts in invalid_ts:
        with pytest.raises(ValueError):
            parse_iso_timestamp(ts)

    # Valid timestamps from different time zones must parse and normalize consistently to UTC
    ts_utc = "2026-11-20T10:00:00Z"
    ts_offset = "2026-11-20T15:30:00+05:30"  # Equivalent to 10:00:00 UTC
    ts_naive = "2026-11-20T10:00:00"

    dt_utc = parse_iso_timestamp(ts_utc)
    dt_offset = parse_iso_timestamp(ts_offset)
    dt_naive = parse_iso_timestamp(ts_naive)

    assert dt_utc.tzinfo == timezone.utc
    assert dt_offset.tzinfo == timezone.utc
    assert dt_utc == dt_offset  # Timezone-aware equality
    assert dt_utc == dt_naive


# ---------------------------------------------------------------------------
# Scenario 5: Duplicate alerts
# ---------------------------------------------------------------------------
def test_scenario_05_duplicate_alerts():
    """Scenario 5: Alerts within duplicate window are mapped to canonical alert."""
    alerts = [
        NormalizedAlert(
            alert_id="ALT-DUP-1",
            service="payment",
            alert_type="high_latency",
            message="Payment latency high",
            severity="high",
            timestamp="2026-11-20T12:00:00Z",
            host="pay-01"
        ),
        NormalizedAlert(
            alert_id="ALT-DUP-2",
            service="payment",
            alert_type="high_latency",
            message="Payment latency high",
            severity="high",
            timestamp="2026-11-20T12:00:30Z",  # 30s later (within 60s window)
            host="pay-01"
        )
    ]

    canonical, dup_map = deduplicate_alerts(alerts, duplicate_window_seconds=60)
    assert len(canonical) == 1
    assert canonical[0].alert_id == "ALT-DUP-1"
    assert "ALT-DUP-2" in dup_map["ALT-DUP-1"]


# ---------------------------------------------------------------------------
# Scenario 6: Multiple unrelated incidents
# ---------------------------------------------------------------------------
def test_scenario_06_multiple_unrelated_incidents():
    """Scenario 6: Simultaneous alerts on disconnected services form separate incidents."""
    unrelated_alerts = [
        {
            "alert_id": "ALT-DB-1",
            "service": "database",
            "alert_type": "high_cpu",
            "message": "Database CPU critical",
            "severity": "critical",
            "timestamp": "2026-11-20T14:00:00Z"
        },
        {
            "alert_id": "ALT-CMS-1",
            "service": "marketing-cms",
            "alert_type": "disk_space_warning",
            "message": "CMS disk space low",
            "severity": "low",
            "timestamp": "2026-11-20T14:00:05Z"
        }
    ]
    # No dependency between database and marketing-cms
    deps = {
        "services": [
            {"service": "api", "depends_on": ["database"]}
        ]
    }

    result = correlate_alerts(unrelated_alerts, deps, correlation_threshold=0.55)
    assert result["candidate_incidents_count"] == 2
    groups = result["groups"]
    group_services = [g["affected_services"] for g in groups]
    assert ["database"] in group_services
    assert ["marketing-cms"] in group_services


# ---------------------------------------------------------------------------
# Scenario 7: Missing service dependencies
# ---------------------------------------------------------------------------
def test_scenario_07_missing_service_dependencies():
    """Scenario 7: Correlation and workflow run cleanly when dependencies are missing or None."""
    alerts = [
        {
            "alert_id": "ALT-TEST-1",
            "service": "unknown-service-a",
            "alert_type": "high_cpu",
            "message": "High CPU",
            "severity": "high",
            "timestamp": "2026-11-20T10:00:00Z"
        }
    ]

    # Test None dependency
    res_none = correlate_alerts(alerts, None)
    assert res_none["candidate_incidents_count"] == 1

    # Test empty dict dependency
    res_empty = correlate_alerts(alerts, {})
    assert res_empty["candidate_incidents_count"] == 1


# ---------------------------------------------------------------------------
# Scenario 8: Gemini API unavailable
# ---------------------------------------------------------------------------
def test_scenario_08_gemini_api_unavailable(sample_data):
    """Scenario 8: Workflow runs to completion using fallback when Gemini is unavailable."""
    alerts, dependencies = sample_data
    result = analyze_alerts(
        alerts=alerts,
        service_dependencies=dependencies,
        config={"gemini_api_key": ""}  # Empty key
    )
    assert result["workflow_status"] in {"completed", "completed_with_fallback", "requires_human_review"}
    assert len(result["candidate_incidents"]) > 0
    assert len(result["root_cause_findings"]) > 0


# ---------------------------------------------------------------------------
# Scenario 9: Gemini returns malformed JSON
# ---------------------------------------------------------------------------
def test_scenario_09_gemini_returns_malformed_json():
    """Scenario 9: GeminiService handles malformed JSON without crashing and reports error."""
    service = GeminiService(api_key="AIzaSyFakeKeyForTest123456789")
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "This is definitely not valid JSON! { broken json ..."
    mock_client.models.generate_content.return_value = mock_resp
    service._client = mock_client

    data, telemetry = service.generate_json("system instruction", "user prompt")
    assert data is None
    assert telemetry["success"] is False
    assert "malformed_json" in telemetry["error"]


# ---------------------------------------------------------------------------
# Scenario 10: Root cause fallback execution
# ---------------------------------------------------------------------------
def test_scenario_10_root_cause_fallback_execution(sample_data):
    """Scenario 10: Topological fallback identifies upstream failure origin."""
    alerts, dependencies = sample_data
    agent = RootCauseAgent(api_key=None)  # None forces fallback

    candidate = {
        "group_id": "GRP-TEST",
        "alert_ids": ["ALT-001", "ALT-004", "ALT-005"],
        "duplicate_alert_ids": [],
        "affected_services": ["database", "api"],
        "reasons": []
    }

    rca = agent.analyze_incident(candidate, alerts, dependencies)
    assert rca.status == "completed_with_fallback"
    assert rca.primary_hypothesis is not None
    assert rca.primary_hypothesis.root_cause_service == "database"
    assert "ALT-001" in rca.primary_hypothesis.evidence_alert_ids


# ---------------------------------------------------------------------------
# Scenario 11: Severity calculation
# ---------------------------------------------------------------------------
def test_scenario_11_severity_calculation():
    """Scenario 11: Deterministic severity scoring adheres to bounds and rules."""
    agent = SeverityAgent()

    # P1: Critical alert on Tier-1 service cascading to multiple services
    p1_incident = {
        "group_id": "GRP-P1",
        "alert_ids": ["ALT-1", "ALT-2", "ALT-3"],
        "affected_services": ["database", "api", "payment"]
    }
    p1_alerts = [
        {"alert_id": "ALT-1", "service": "database", "severity": "critical"},
        {"alert_id": "ALT-2", "service": "api", "severity": "high"},
        {"alert_id": "ALT-3", "service": "payment", "severity": "high"}
    ]
    p1_assessment = agent.assess_incident(p1_incident, p1_alerts)
    assert p1_assessment.severity_level == "P1_CRITICAL"
    assert p1_assessment.urgency == "IMMEDIATE"
    assert 0.0 <= p1_assessment.severity_score <= 100.0

    # P4: Low alert on Tier-3 service
    p4_incident = {
        "group_id": "GRP-P4",
        "alert_ids": ["ALT-4"],
        "affected_services": ["marketing-cms"]
    }
    p4_alerts = [{"alert_id": "ALT-4", "service": "marketing-cms", "severity": "low"}]
    p4_assessment = agent.assess_incident(p4_incident, p4_alerts)
    assert p4_assessment.severity_level == "P4_LOW"


# ---------------------------------------------------------------------------
# Scenario 12: Incident report generation
# ---------------------------------------------------------------------------
def test_scenario_12_incident_report_generation():
    """Scenario 12: ReportingAgent builds timeline, summaries, and actions."""
    agent = ReportingAgent(api_key=None)
    candidate = {
        "group_id": "GRP-REP",
        "alert_ids": ["ALT-R1", "ALT-R2"],
        "duplicate_alert_ids": [],
        "affected_services": ["database", "api"]
    }
    alerts = [
        {
            "alert_id": "ALT-R1",
            "service": "database",
            "alert_type": "high_cpu",
            "severity": "critical",
            "message": "DB saturated",
            "timestamp": "2026-11-20T10:00:00Z"
        },
        {
            "alert_id": "ALT-R2",
            "service": "api",
            "alert_type": "query_timeout",
            "severity": "high",
            "message": "API timeout",
            "timestamp": "2026-11-20T10:01:00Z"
        }
    ]
    report = agent.generate_incident_report(
        candidate_incident=candidate,
        all_alerts=alerts,
        root_cause_analysis={"primary_hypothesis": {"root_cause_service": "database", "title": "DB issue"}},
        severity_assessment={"severity_level": "P1_CRITICAL", "severity_score": 85.0}
    )

    assert report.incident_id == "GRP-REP"
    assert len(report.timeline) == 2
    assert len(report.recommended_actions) > 0
    assert report.status == "completed_with_fallback"


# ---------------------------------------------------------------------------
# Scenario 13: Database connection failure
# ---------------------------------------------------------------------------
def test_scenario_13_database_connection_failure(client):
    """Scenario 13: /health returns HTTP 503 when database is inaccessible."""
    with patch("backend.main.check_db_health", return_value=(False, {"error": "Connection refused"})):
        res = client.get("/health")
        assert res.status_code == 503
        data = res.json()
        assert data["status"] == "unhealthy"
        assert data["database"] == "disconnected"


# ---------------------------------------------------------------------------
# Scenario 14: Unauthorized API requests
# ---------------------------------------------------------------------------
def test_scenario_14_unauthorized_api_requests(client):
    """Scenario 14: Sensitive endpoints reject unauthenticated or invalid tokens with 401."""
    protected_endpoints = [
        ("POST", "/api/alerts", [{"alert_id": "1", "service": "api", "alert_type": "t", "message": "m", "severity": "low", "timestamp": "2026-11-20T10:00:00Z"}]),
        ("GET", "/api/alerts", None),
        ("POST", "/api/incidents/analyze", {}),
        ("GET", "/api/incidents", None),
        ("GET", "/api/analytics", None),
        ("POST", "/api/reset", None),
    ]

    for method, endpoint, payload in protected_endpoints:
        # Without headers
        if method == "POST":
            res_no_auth = client.post(endpoint, json=payload)
        else:
            res_no_auth = client.get(endpoint)
        assert res_no_auth.status_code == 401, f"{method} {endpoint} must return 401 without auth"

        # With invalid header
        if method == "POST":
            res_bad_auth = client.post(endpoint, json=payload, headers=INVALID_HEADERS)
        else:
            res_bad_auth = client.get(endpoint, headers=INVALID_HEADERS)
        assert res_bad_auth.status_code == 401, f"{method} {endpoint} must return 401 with invalid token"


# ---------------------------------------------------------------------------
# Scenario 15: Unauthorized reset attempts
# ---------------------------------------------------------------------------
def test_scenario_15_unauthorized_reset_attempts(client):
    """Scenario 15: Non-admin users are rejected from /api/reset with 403 Forbidden."""
    res = client.post("/api/reset", headers=USER_HEADERS)
    assert res.status_code == 403
    assert "Forbidden" in res.json().get("detail", "")


# ---------------------------------------------------------------------------
# Scenario 16: Authorized administrator reset
# ---------------------------------------------------------------------------
def test_scenario_16_authorized_administrator_reset(client):
    """Scenario 16: Admin token successfully clears all platform data."""
    # Seed alert
    save_alerts([{
        "alert_id": "ALT-TO-RESET",
        "service": "database",
        "alert_type": "high_cpu",
        "message": "CPU 90%",
        "severity": "critical",
        "timestamp": "2026-11-20T10:00:00Z"
    }])
    assert len(get_all_alerts()) > 0

    # Execute authorized reset
    res = client.post("/api/reset", headers=ADMIN_HEADERS)
    assert res.status_code == 200
    assert "cleared" in res.json()["message"]
    assert len(get_all_alerts()) == 0


# ---------------------------------------------------------------------------
# Scenario 17: Empty analytics response
# ---------------------------------------------------------------------------
def test_scenario_17_empty_analytics_response():
    """Scenario 17: get_analytics_summary handles 0 alerts cleanly without division by zero."""
    clear_all_data()
    analytics = get_analytics_summary()
    assert analytics["total_alerts"] == 0
    assert analytics["total_incidents"] == 0
    assert analytics["noise_reduction_ratio"] == 0.0
    assert analytics["severity_distribution"] == {}
    assert analytics["incident_severity_distribution"] == {}


# ---------------------------------------------------------------------------
# Scenario 18: Frontend API failures / client handling
# ---------------------------------------------------------------------------
def test_scenario_18_frontend_api_error_handling(client):
    """Scenario 18: Client properly handles 404 for non-existent incident."""
    res = client.get("/api/incidents/NON_EXISTENT_ID", headers=USER_HEADERS)
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()

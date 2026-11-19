"""Unit tests for AlertSense Correlation Engine.

Verifies:
1. Related cascade grouping (database -> api -> auth -> frontend).
2. Unrelated simultaneous alerts isolation (safeguard against time-only merges).
3. Duplicate alert deduplication and traceability.
4. Out-of-order timestamp handling.
5. Missing dependency topology handling.
6. Missing optional fields (null host/source).
7. Single alert and empty alerts edge cases.
"""

import json
from pathlib import Path
import pytest

from backend.services.correlation_engine import (
    CorrelationEngine,
    correlate_alerts,
    deduplicate_alerts,
    NormalizedAlert,
    build_dependency_graph,
    calculate_pairwise_correlation,
    parse_iso_timestamp
)

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"


@pytest.fixture
def sample_data():
    """Load sample alerts and service dependencies from datasets/."""
    with open(DATASETS_DIR / "sample_alerts.json", "r", encoding="utf-8") as f:
        alerts = json.load(f)
    with open(DATASETS_DIR / "service_dependencies.json", "r", encoding="utf-8") as f:
        dependencies = json.load(f)
    return alerts, dependencies


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_empty_alerts_handling():
    """Engine should handle empty alerts without error."""
    result = correlate_alerts([], {"services": []})
    assert result["total_input_alerts"] == 0
    assert result["candidate_incidents_count"] == 0
    assert result["groups"] == []


def test_single_alert_handling():
    """Single alert should produce exactly one singleton incident."""
    alert = {
        "alert_id": "ALT-SINGLE",
        "service": "database",
        "alert_type": "high_cpu",
        "message": "CPU reached 99%",
        "severity": "critical",
        "timestamp": "2026-11-19T10:00:00Z"
    }
    result = correlate_alerts([alert], {"services": []})
    assert result["total_input_alerts"] == 1
    assert result["candidate_incidents_count"] == 1
    assert result["groups"][0]["is_singleton"] is True
    assert result["groups"][0]["alert_ids"] == ["ALT-SINGLE"]


def test_deduplication_traceability(sample_data):
    """Verify exact duplicate alerts are deduplicated and tracked."""
    alerts, _ = sample_data
    # ALT-001 and ALT-010 have identical attributes
    norm_alerts = [NormalizedAlert(**a) for a in alerts]
    canonical, dup_map = deduplicate_alerts(norm_alerts, duplicate_window_seconds=60)

    # Total alerts in sample is 16
    assert len(canonical) < len(norm_alerts)
    # Check that ALT-010 was tracked as a duplicate of ALT-001
    assert "ALT-010" in dup_map.get("ALT-001", [])


def test_related_cascade_grouping(sample_data):
    """Related database failure cascade must be grouped together."""
    alerts, dependencies = sample_data
    result = correlate_alerts(alerts, dependencies, correlation_threshold=0.55)

    groups = result["groups"]
    assert len(groups) > 0

    # Locate the primary cascade group containing the database alert
    db_cascade_group = next(
        (g for g in groups if "ALT-001" in g["alert_ids"]),
        None
    )
    assert db_cascade_group is not None, "Database primary alert ALT-001 must be in a group"
    
    # Check services in cascade
    services = set(db_cascade_group["affected_services"])
    assert "database" in services
    assert "api" in services
    assert "authentication" in services

    # Verify downstream API alerts are included
    alert_ids = set(db_cascade_group["alert_ids"])
    assert "ALT-004" in alert_ids  # API query timeout
    assert "ALT-005" in alert_ids  # API http 500 spike
    assert "ALT-006" in alert_ids  # Auth dependency timeout

    # Verify reasons explain dependencies and causal symptoms
    assert len(db_cascade_group["reasons"]) > 0
    reasons_text = " ".join(db_cascade_group["reasons"]).lower()
    assert "dependency" in reasons_text or "service" in reasons_text


def test_unrelated_simultaneous_alerts_safeguard(sample_data):
    """Billing and Marketing CMS alerts occurring at 10:01 must NOT merge with DB cascade."""
    alerts, dependencies = sample_data
    result = correlate_alerts(alerts, dependencies, correlation_threshold=0.55)

    groups = result["groups"]
    db_group = next(g for g in groups if "ALT-001" in g["alert_ids"])

    # ALT-008 is billing-service (cron_execution_delayed at 10:01:10)
    # ALT-009 is marketing-cms (media_upload_warning at 10:01:30)
    assert "ALT-008" not in db_group["alert_ids"], "Unrelated billing alert must not merge into DB cascade"
    assert "ALT-009" not in db_group["alert_ids"], "Unrelated CMS alert must not merge into DB cascade"

    # Both should be in separate groups or singletons
    billing_group = next((g for g in groups if "ALT-008" in g["alert_ids"]), None)
    assert billing_group is not None
    assert "database" not in billing_group["affected_services"]


def test_network_outage_scenario(sample_data):
    """Network failure on gw-switch-az1 affecting payment, order-service, notification must cluster."""
    alerts, dependencies = sample_data
    result = correlate_alerts(alerts, dependencies, correlation_threshold=0.55)

    groups = result["groups"]
    # ALT-011 is payment network_packet_loss at 10:15:00
    net_group = next((g for g in groups if "ALT-011" in g["alert_ids"]), None)
    assert net_group is not None, "Network incident group must be created"

    # ALT-013 (connection refused on payment), ALT-012 (dns resolution on order-service)
    # ALT-014 (notification socket reset on gw-switch-az1)
    net_alerts = set(net_group["alert_ids"])
    assert "ALT-013" in net_alerts or "ALT-014" in net_alerts


def test_missing_dependency_graph():
    """Engine must gracefully correlate or isolate when dependency info is missing."""
    alert_a = {
        "alert_id": "A1",
        "service": "unknown-service-1",
        "alert_type": "high_cpu",
        "message": "CPU 99%",
        "severity": "critical",
        "timestamp": "2026-11-19T10:00:00Z"
    }
    alert_b = {
        "alert_id": "B1",
        "service": "unknown-service-2",
        "alert_type": "http_latency",
        "message": "High latency 5000ms",
        "severity": "high",
        "timestamp": "2026-11-19T10:00:30Z"
    }
    # With empty dependencies, without shared host or known link, safeguard prevents merge
    result = correlate_alerts([alert_a, alert_b], service_dependencies={"services": []})
    assert result["candidate_incidents_count"] == 2
    assert result["groups"][0]["is_singleton"] is True
    assert result["groups"][1]["is_singleton"] is True


def test_out_of_order_timestamps():
    """Alerts passed out of chronological order must be correctly parsed and ordered."""
    alerts = [
        {
            "alert_id": "LATER",
            "service": "api",
            "alert_type": "http_500_spike",
            "message": "HTTP 500 errors",
            "severity": "critical",
            "timestamp": "2026-11-19T10:02:00Z"
        },
        {
            "alert_id": "EARLIER",
            "service": "database",
            "alert_type": "high_cpu",
            "message": "Database CPU 95%",
            "severity": "critical",
            "timestamp": "2026-11-19T10:00:00Z"
        }
    ]
    deps = {"services": [{"service": "api", "depends_on": ["database"]}]}
    result = correlate_alerts(alerts, deps, time_window_seconds=300)
    assert result["candidate_incidents_count"] == 1
    grp = result["groups"][0]
    assert grp["time_range"]["start_time"] == "2026-11-19T10:00:00+00:00"
    assert grp["time_range"]["end_time"] == "2026-11-19T10:02:00+00:00"
    assert grp["time_range"]["duration_seconds"] == 120


def test_missing_optional_fields():
    """Alerts without host or source should still be processed without errors."""
    alerts = [
        {
            "alert_id": "A-NOHOST",
            "service": "api",
            "alert_type": "http_500_spike",
            "message": "Internal error",
            "severity": "critical",
            "timestamp": "2026-11-19T10:00:00Z",
            "host": None,
            "source": None
        },
        {
            "alert_id": "B-NOHOST",
            "service": "api",
            "alert_type": "query_timeout",
            "message": "Timeout occurred",
            "severity": "high",
            "timestamp": "2026-11-19T10:00:20Z",
            "host": None,
            "source": None
        }
    ]
    result = correlate_alerts(alerts, {"services": []})
    assert result["candidate_incidents_count"] == 1
    assert "A-NOHOST" in result["groups"][0]["alert_ids"]
    assert "B-NOHOST" in result["groups"][0]["alert_ids"]


def test_noise_reduction_calculation(sample_data):
    """Noise reduction ratio should accurately reflect reduction from raw alerts to incidents."""
    alerts, dependencies = sample_data
    result = correlate_alerts(alerts, dependencies)
    raw_count = len(alerts)
    incidents_count = result["candidate_incidents_count"]
    expected_ratio = round((raw_count - incidents_count) / raw_count, 3)
    assert result["noise_reduction_ratio"] == expected_ratio
    assert result["noise_reduction_ratio"] > 0.50  # Over 50% noise reduction expected

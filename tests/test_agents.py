"""Unit tests for AlertSense Agents.

Currently verifies Stage 4: CorrelationAgent and its LangGraph node adapter.
"""

import json
from pathlib import Path
import pytest

from ai_agents.correlation_agent import CorrelationAgent, correlation_agent_node

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"


@pytest.fixture
def sample_data():
    """Load sample alerts and service dependencies."""
    with open(DATASETS_DIR / "sample_alerts.json", "r", encoding="utf-8") as f:
        alerts = json.load(f)
    with open(DATASETS_DIR / "service_dependencies.json", "r", encoding="utf-8") as f:
        dependencies = json.load(f)
    return alerts, dependencies


def test_correlation_agent_direct_run(sample_data):
    """CorrelationAgent.run should return candidate incidents and explainable metadata."""
    alerts, dependencies = sample_data
    agent = CorrelationAgent(correlation_threshold=0.55)
    result = agent.run(alerts, dependencies)

    assert result["metadata"]["status"] == "success"
    assert result["metadata"]["agent"] == "CorrelationAgent"
    assert result["metadata"]["total_input_alerts"] == len(alerts)
    assert len(result["candidate_incidents"]) > 0

    # Ensure every group has causality disclaimer
    for group in result["correlation_groups"]:
        assert "causality_disclaimer" in group
        assert "uncertainty_notes" in group
        assert "score" in group
        assert "reasons" in group


def test_correlation_agent_node_langgraph_contract(sample_data):
    """LangGraph node function must accept state dict and return updated fields."""
    alerts, dependencies = sample_data
    initial_state = {
        "alerts": alerts,
        "service_dependencies": dependencies,
        "config": {"correlation_threshold": 0.55},
        "errors": []
    }

    state_update = correlation_agent_node(initial_state)

    assert "correlation_groups" in state_update
    assert "candidate_incidents" in state_update
    assert "ungrouped_alert_ids" in state_update
    assert "correlation_metadata" in state_update
    assert "errors" in state_update
    assert len(state_update["errors"]) == 0

    # Verify initial state was not mutated
    assert "correlation_groups" not in initial_state


def test_correlation_agent_uncertainty_flagging(sample_data):
    """Services not present in the dependency graph should be explicitly flagged with uncertainty."""
    _, dependencies = sample_data
    unmapped_alerts = [
        {
            "alert_id": "ALT-UNMAPPED-1",
            "service": "shadow-legacy-service",
            "alert_type": "high_cpu",
            "message": "Shadow service CPU spike",
            "severity": "critical",
            "timestamp": "2026-11-19T10:00:00Z",
            "host": "shadow-01"
        },
        {
            "alert_id": "ALT-UNMAPPED-2",
            "service": "shadow-legacy-service",
            "alert_type": "high_cpu",
            "message": "Shadow service CPU spike",
            "severity": "critical",
            "timestamp": "2026-11-19T10:02:00Z",
            "host": "shadow-01"
        }
    ]

    agent = CorrelationAgent(correlation_threshold=0.50)
    result = agent.run(unmapped_alerts, dependencies)

    assert len(result["candidate_incidents"]) == 1
    inc = result["candidate_incidents"][0]
    assert any("Dependency topology missing" in note for note in inc["uncertainty_notes"])


def test_correlation_agent_empty_alerts():
    """Agent must handle empty alerts gracefully."""
    agent = CorrelationAgent()
    result = agent.run([], {"services": []})

    assert result["metadata"]["status"] == "success"
    assert result["metadata"]["total_input_alerts"] == 0
    assert result["candidate_incidents"] == []
    assert result["ungrouped_alert_ids"] == []


def test_correlation_agent_runtime_config_override(sample_data):
    """Runtime config override in agent.run should change correlation threshold."""
    alerts, dependencies = sample_data
    agent = CorrelationAgent(correlation_threshold=0.55)

    # With very high threshold, fewer multi-alert clustered incidents should form
    strict_result = agent.run(alerts, dependencies, config={"correlation_threshold": 0.95})
    assert strict_result["metadata"]["correlation_threshold"] == 0.95
    assert len(strict_result["multi_alert_incidents"]) < len(agent.run(alerts, dependencies)["multi_alert_incidents"])


# ---------------------------------------------------------------------------
# Stage 5: Root Cause Agent Tests
# ---------------------------------------------------------------------------

from ai_agents.root_cause_agent import (
    RootCauseAgent,
    root_cause_agent_node,
    IncidentRootCauseAnalysis,
    Hypothesis
)


def test_root_cause_agent_deterministic_baseline(sample_data):
    """Deterministic fallback must identify upstream database as root cause in cascade."""
    alerts, dependencies = sample_data
    # First obtain correlated candidate incidents
    corr_agent = CorrelationAgent(correlation_threshold=0.55)
    corr_result = corr_agent.run(alerts, dependencies)
    db_incident = next(
        inc for inc in corr_result["candidate_incidents"]
        if "database" in inc["affected_services"] and len(inc["alert_ids"]) > 2
    )

    rca_agent = RootCauseAgent(api_key=None)  # API key None triggers deterministic fallback
    analysis = rca_agent.analyze_incident(
        candidate_incident=db_incident,
        all_alerts=alerts,
        service_dependencies=dependencies
    )

    assert analysis.status == "completed_with_fallback"
    assert analysis.primary_hypothesis is not None
    assert analysis.primary_hypothesis.root_cause_service == "database"
    assert "ALT-001" in analysis.primary_hypothesis.evidence_alert_ids
    assert len(analysis.missing_evidence) > 0
    assert len(analysis.recommended_investigation_checks) > 0
    assert analysis.evidence_validation_passed is True


def test_root_cause_evidence_validation_rejects_hallucination():
    """Anti-hallucination guard must strip citations not in the incident."""
    agent = RootCauseAgent(api_key=None)
    fake_analysis = IncidentRootCauseAnalysis(
        incident_id="GRP-TEST",
        status="completed",
        primary_hypothesis=Hypothesis(
            rank=1,
            root_cause_service="database",
            title="Database failure",
            explanation="Explanation",
            evidence_alert_ids=["ALT-001", "ALT-FAKE-999"],
            supporting_dependency_edges=["api -> database"],
            confidence_label="high",
            confidence_rationale="Rationale"
        ),
        alternative_hypotheses=[]
    )

    validated = agent._validate_and_sanitize_evidence(
        analysis=fake_analysis,
        valid_alert_ids={"ALT-001", "ALT-002"},
        affected_services={"database", "api"}
    )

    # ALT-FAKE-999 must be removed
    assert "ALT-FAKE-999" not in validated.primary_hypothesis.evidence_alert_ids
    assert "ALT-001" in validated.primary_hypothesis.evidence_alert_ids
    assert any("ALT-FAKE-999" in note for note in validated.validation_notes)


def test_root_cause_singleton_analysis():
    """Singleton alert must produce a single isolated investigation."""
    agent = RootCauseAgent(api_key=None)
    single_incident = {
        "group_id": "GRP-SINGLE",
        "alert_ids": ["ALT-SOLO"],
        "duplicate_alert_ids": [],
        "affected_services": ["cache"]
    }
    solo_alert = [{
        "alert_id": "ALT-SOLO",
        "service": "cache",
        "alert_type": "oom_eviction",
        "message": "Redis key eviction spike",
        "severity": "medium",
        "timestamp": "2026-11-19T10:00:00Z"
    }]

    analysis = agent.analyze_incident(single_incident, solo_alert, {"services": []})
    assert analysis.primary_hypothesis.root_cause_service == "cache"
    assert analysis.primary_hypothesis.confidence_label == "low"
    assert "ALT-SOLO" in analysis.primary_hypothesis.evidence_alert_ids


def test_root_cause_agent_node_workflow(sample_data):
    """LangGraph node function must populate root_cause_findings for all candidate incidents."""
    alerts, dependencies = sample_data
    corr_agent = CorrelationAgent(correlation_threshold=0.55)
    corr_res = corr_agent.run(alerts, dependencies)

    state = {
        "candidate_incidents": corr_res["candidate_incidents"],
        "alerts": alerts,
        "service_dependencies": dependencies,
        "errors": []
    }

    state_update = root_cause_agent_node(state)

    assert "root_cause_findings" in state_update
    assert len(state_update["root_cause_findings"]) == len(corr_res["candidate_incidents"])
    assert "needs_human_review" in state_update

    # Check structure of the findings
    first_finding = state_update["root_cause_findings"][0]
    assert "primary_hypothesis" in first_finding
    assert "missing_evidence" in first_finding
    assert "recommended_investigation_checks" in first_finding


# ---------------------------------------------------------------------------
# Stage 6: Severity Agent Tests
# ---------------------------------------------------------------------------

from ai_agents.severity_agent import (
    SeverityAgent,
    severity_agent_node,
    IncidentSeverityAssessment
)


def test_severity_agent_critical_cascade(sample_data):
    """Database cascade affecting Tier-1 services must be assessed as P1_CRITICAL."""
    alerts, dependencies = sample_data
    corr_agent = CorrelationAgent(correlation_threshold=0.55)
    corr_res = corr_agent.run(alerts, dependencies)
    db_incident = next(
        inc for inc in corr_res["candidate_incidents"]
        if "database" in inc["affected_services"]
    )

    sev_agent = SeverityAgent()
    assessment = sev_agent.assess_incident(db_incident, alerts)

    assert assessment.severity_level == "P1_CRITICAL"
    assert assessment.urgency == "IMMEDIATE"
    assert assessment.severity_score >= 75.0
    assert "database" in assessment.affected_tier1_services
    assert assessment.blast_radius_services_count >= 3
    assert len(assessment.rationale) >= 3
    assert len(assessment.missing_impact_data) > 0

    # Verify score arithmetic
    breakdown = assessment.score_breakdown
    expected_total = round(
        breakdown.alert_severity_score + breakdown.service_tier_score + breakdown.blast_radius_score,
        2
    )
    assert breakdown.total_score == expected_total


def test_severity_agent_low_tier3_incident():
    """Single low-severity alert on Tier-3 service must yield low priority."""
    sev_agent = SeverityAgent()
    minor_incident = {
        "group_id": "GRP-MINOR",
        "alert_ids": ["ALT-CRON"],
        "duplicate_alert_ids": [],
        "affected_services": ["billing-service"]
    }
    minor_alert = [{
        "alert_id": "ALT-CRON",
        "service": "billing-service",
        "alert_type": "cron_delayed",
        "message": "Cron delayed 2 mins",
        "severity": "low",
        "timestamp": "2026-11-19T10:00:00Z"
    }]

    assessment = sev_agent.assess_incident(minor_incident, minor_alert)

    assert assessment.severity_level in {"P3_MEDIUM", "P4_LOW"}
    assert assessment.urgency in {"MODERATE", "LOW"}
    assert assessment.severity_score < 50.0
    assert len(assessment.affected_tier1_services) == 0


def test_severity_agent_node_workflow(sample_data):
    """severity_agent_node must populate severity_assessments in LangGraph state."""
    alerts, dependencies = sample_data
    corr_agent = CorrelationAgent(correlation_threshold=0.55)
    corr_res = corr_agent.run(alerts, dependencies)

    rca_agent = RootCauseAgent(api_key=None)
    rca_findings = [
        rca_agent.analyze_incident(inc, alerts, dependencies).model_dump()
        for inc in corr_res["candidate_incidents"]
    ]

    state = {
        "candidate_incidents": corr_res["candidate_incidents"],
        "alerts": alerts,
        "root_cause_findings": rca_findings,
        "errors": []
    }

    state_update = severity_agent_node(state)

    assert "severity_assessments" in state_update
    assert len(state_update["severity_assessments"]) == len(corr_res["candidate_incidents"])
    assert "is_high_severity_incident" in state_update
    assert state_update["is_high_severity_incident"] is True  # DB cascade is P1


# ---------------------------------------------------------------------------
# Stage 7: Reporting Agent Tests
# ---------------------------------------------------------------------------

from ai_agents.reporting_agent import (
    ReportingAgent,
    reporting_agent_node,
    IncidentReport,
    ComprehensiveIncidentReport
)


def test_reporting_agent_deterministic_report(sample_data):
    """ReportingAgent must build verified executive report and timeline without hallucinated facts."""
    alerts, dependencies = sample_data
    corr_agent = CorrelationAgent(correlation_threshold=0.55)
    corr_res = corr_agent.run(alerts, dependencies)
    db_incident = next(
        inc for inc in corr_res["candidate_incidents"]
        if "database" in inc["affected_services"]
    )

    rca_agent = RootCauseAgent(api_key=None)
    rca = rca_agent.analyze_incident(db_incident, alerts, dependencies).model_dump()

    sev_agent = SeverityAgent()
    sev = sev_agent.assess_incident(db_incident, alerts, rca).model_dump()

    rep_agent = ReportingAgent(api_key=None)
    report = rep_agent.generate_incident_report(
        candidate_incident=db_incident,
        all_alerts=alerts,
        root_cause_analysis=rca,
        severity_assessment=sev
    )

    assert report.incident_id == db_incident["group_id"]
    assert "P1_CRITICAL" in report.title
    assert "database" in report.executive_summary
    assert len(report.timeline) >= 4

    # Verify timeline chronological sorting
    for i in range(len(report.timeline) - 1):
        t1 = report.timeline[i].timestamp
        t2 = report.timeline[i + 1].timestamp
        assert t1 <= t2

    # Check categorized recommendations
    categories = {a.category for a in report.recommended_actions}
    assert "Immediate Mitigation" in categories
    assert "Diagnostic Investigation" in categories
    assert "Post-Incident Prevention" in categories

    assert len(report.evidence_summary) > 0
    assert len(report.uncertainty_and_gaps) > 0
    assert report.status == "completed_with_fallback"


def test_reporting_agent_comprehensive_report(sample_data):
    """Comprehensive report must aggregate all candidate incidents."""
    alerts, dependencies = sample_data
    corr_agent = CorrelationAgent(correlation_threshold=0.55)
    corr_res = corr_agent.run(alerts, dependencies)

    rca_agent = RootCauseAgent(api_key=None)
    rca_findings = [
        rca_agent.analyze_incident(inc, alerts, dependencies).model_dump()
        for inc in corr_res["candidate_incidents"]
    ]

    sev_agent = SeverityAgent()
    sev_findings = [
        sev_agent.assess_incident(inc, alerts, rca_findings[i]).model_dump()
        for i, inc in enumerate(corr_res["candidate_incidents"])
    ]

    rep_agent = ReportingAgent(api_key=None)
    comp_report = rep_agent.generate_comprehensive_report(
        candidate_incidents=corr_res["candidate_incidents"],
        all_alerts=alerts,
        root_cause_findings=rca_findings,
        severity_assessments=sev_findings
    )

    assert comp_report.total_incidents_reported == len(corr_res["candidate_incidents"])
    assert comp_report.high_severity_incidents_count >= 1
    assert comp_report.workflow_status == "completed"
    assert len(comp_report.incidents) == len(corr_res["candidate_incidents"])


def test_reporting_agent_node_workflow(sample_data):
    """reporting_agent_node must output incident_report in LangGraph state."""
    alerts, dependencies = sample_data
    corr_agent = CorrelationAgent(correlation_threshold=0.55)
    corr_res = corr_agent.run(alerts, dependencies)

    rca_agent = RootCauseAgent(api_key=None)
    rca_findings = [
        rca_agent.analyze_incident(inc, alerts, dependencies).model_dump()
        for inc in corr_res["candidate_incidents"]
    ]

    sev_agent = SeverityAgent()
    sev_findings = [
        sev_agent.assess_incident(inc, alerts, rca_findings[i]).model_dump()
        for i, inc in enumerate(corr_res["candidate_incidents"])
    ]

    state = {
        "candidate_incidents": corr_res["candidate_incidents"],
        "alerts": alerts,
        "root_cause_findings": rca_findings,
        "severity_assessments": sev_findings,
        "errors": []
    }

    state_update = reporting_agent_node(state)

    assert "incident_report" in state_update
    assert state_update["incident_report"]["total_incidents_reported"] == len(corr_res["candidate_incidents"])
    assert len(state_update["incident_report"]["incidents"]) == len(corr_res["candidate_incidents"])


# ---------------------------------------------------------------------------
# Stage 9: Gemini Service Resilience & Error Handling Tests
# ---------------------------------------------------------------------------

from unittest.mock import MagicMock, patch
from ai_agents.gemini_service import GeminiService


def test_gemini_service_not_configured():
    """GeminiService should safely report unconfigured status when key is absent."""
    service = GeminiService(api_key="")
    assert service.is_configured() is False

    data, telemetry = service.generate_json("System", "User")
    assert data is None
    assert telemetry["success"] is False
    assert telemetry["error"] == "api_key_not_configured"


def test_gemini_service_sanitize_markdown():
    """Markdown code fences should be cleanly stripped from JSON output."""
    raw_markdown_json = "```json\n{\"incident_id\": \"GRP-001\", \"status\": \"ok\"}\n```"
    sanitized = GeminiService._sanitize_json_markdown(raw_markdown_json)
    assert sanitized == '{"incident_id": "GRP-001", "status": "ok"}'


def test_gemini_service_retry_on_rate_limit():
    """GeminiService must retry with exponential backoff on 429 rate limits."""
    service = GeminiService(
        api_key="AIzaSyFakeKey1234567890",
        max_retries=1,
        initial_backoff_seconds=0.01
    )

    mock_client = MagicMock()
    # First attempt raises 429 rate limit error, second succeeds
    mock_response = MagicMock()
    mock_response.text = '{"status": "recovered_after_retry"}'
    mock_client.models.generate_content.side_effect = [
        Exception("429 Resource Exhausted: Rate limit reached"),
        mock_response
    ]
    service._client = mock_client

    data, telemetry = service.generate_json("System", "User")

    assert telemetry["success"] is True
    assert telemetry["retries"] == 1
    assert data == {"status": "recovered_after_retry"}





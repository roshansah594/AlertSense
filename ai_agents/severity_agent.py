"""Severity Assessment Agent Module.

Acts as Agent Stage 3 in the AlertSense multi-agent architecture.
Performs deterministic, transparent incident priority scoring and business impact evaluation.

Key Principles:
- 100% deterministic rules as the primary decision mechanism.
- Never allows an LLM to silently override operational priority rules.
- Transparent score breakdown: Alert Severity + Service Tier + Blast Radius.
- Flags missing business impact and SLO telemetry.
- Provides step-by-step human-readable justification for incident commanders.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Service Criticality Tiers (Configurable operational defaults)
# ---------------------------------------------------------------------------

DEFAULT_SERVICE_TIERS: Dict[str, int] = {
    # Tier 1: Core infrastructure, databases, authentication, core API & payments
    "database": 1,
    "payment": 1,
    "authentication": 1,
    "api": 1,
    "order-service": 1,

    # Tier 2: Customer-facing caching, frontend UI, search
    "cache": 2,
    "frontend": 2,
    "search-service": 2,

    # Tier 3: Asynchronous processing, batch jobs, marketing, notifications
    "billing-service": 3,
    "notification-service": 3,
    "marketing-cms": 3
}

SEVERITY_WEIGHTS = {
    "critical": 30.0,
    "high": 20.0,
    "medium": 10.0,
    "low": 5.0,
    "info": 0.0
}


# ---------------------------------------------------------------------------
# Structured Schemas
# ---------------------------------------------------------------------------

class SeverityScoreBreakdown(BaseModel):
    """Component scores contributing to total incident severity."""
    alert_severity_score: float = Field(..., ge=0.0, le=40.0)
    service_tier_score: float = Field(..., ge=0.0, le=35.0)
    blast_radius_score: float = Field(..., ge=0.0, le=25.0)
    total_score: float = Field(..., ge=0.0, le=100.0)


class IncidentSeverityAssessment(BaseModel):
    """Complete severity evaluation for an incident cluster."""
    incident_id: str
    severity_level: str = Field(..., description="P1_CRITICAL, P2_HIGH, P3_MEDIUM, or P4_LOW")
    urgency: str = Field(..., description="IMMEDIATE, HIGH, MODERATE, or LOW")
    severity_score: float = Field(..., ge=0.0, le=100.0)
    score_breakdown: SeverityScoreBreakdown
    rationale: List[str] = Field(default_factory=list)
    affected_tier1_services: List[str] = Field(default_factory=list)
    blast_radius_services_count: int = Field(..., ge=1)
    missing_impact_data: List[str] = Field(default_factory=list)
    assessment_metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity_level", mode="before")
    @classmethod
    def validate_level(cls, v: Any) -> str:
        allowed = {"P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW"}
        v_clean = str(v).strip().upper()
        return v_clean if v_clean in allowed else "P3_MEDIUM"


# ---------------------------------------------------------------------------
# Severity Agent Implementation
# ---------------------------------------------------------------------------

class SeverityAgent:
    """Evaluates incident severity using deterministic, auditable rules."""

    def __init__(
        self,
        service_tiers: Optional[Dict[str, int]] = None
    ):
        self.service_tiers = service_tiers or DEFAULT_SERVICE_TIERS

    def get_service_tier(self, service_name: str) -> int:
        """Retrieve tier for a service (defaults to Tier 2 for unmapped services)."""
        return self.service_tiers.get(service_name.lower().strip(), 2)

    def assess_incident(
        self,
        candidate_incident: Dict[str, Any],
        all_alerts: List[Dict[str, Any]],
        root_cause_analysis: Optional[Dict[str, Any]] = None
    ) -> IncidentSeverityAssessment:
        """Assess severity level, priority, and rationale for a candidate incident cluster.
        
        Scoring Model (Total: 0 - 100):
        1. Alert Severity & Volume (max 40 pts)
        2. Affected Service Criticality Tier (max 35 pts)
        3. Cascade Blast Radius (max 25 pts)
        """
        incident_id = candidate_incident.get("group_id", "UNKNOWN-INCIDENT")
        incident_alert_ids = set(candidate_incident.get("alert_ids", []))
        for dup in candidate_incident.get("duplicate_alert_ids", []):
            incident_alert_ids.add(dup)

        alerts_in_incident = [
            a for a in all_alerts if a.get("alert_id") in incident_alert_ids
        ]

        affected_services = list(candidate_incident.get("affected_services", []))
        rationale: List[str] = []

        # -------------------------------------------------------------------
        # 1. Alert Severity & Volume Component (0 - 40 pts)
        # -------------------------------------------------------------------
        severities = [a.get("severity", "medium").lower() for a in alerts_in_incident]
        if not severities:
            severities = ["medium"]

        # Base score from highest alert severity
        if "critical" in severities:
            base_alert_score = 30.0
            highest_sev = "critical"
        elif "high" in severities:
            base_alert_score = 20.0
            highest_sev = "high"
        elif "medium" in severities:
            base_alert_score = 10.0
            highest_sev = "medium"
        elif "low" in severities:
            base_alert_score = 5.0
            highest_sev = "low"
        else:
            base_alert_score = 0.0
            highest_sev = "info"

        # Volume bonus
        alert_count = len(alerts_in_incident)
        if alert_count >= 5:
            volume_bonus = 10.0
            vol_reason = f"Alert density high ({alert_count} active/duplicate alerts; +10 pts)."
        elif alert_count >= 3:
            volume_bonus = 5.0
            vol_reason = f"Multiple corroborating alerts ({alert_count} alerts; +5 pts)."
        else:
            volume_bonus = 0.0
            vol_reason = f"Localized alert count ({alert_count} alert(s); +0 pts)."

        alert_score = min(40.0, base_alert_score + volume_bonus)
        rationale.append(f"Highest alert severity is '{highest_sev}' (+{base_alert_score} pts); {vol_reason}")

        # -------------------------------------------------------------------
        # 2. Service Tier Component (0 - 35 pts)
        # -------------------------------------------------------------------
        service_tier_map = {svc: self.get_service_tier(svc) for svc in affected_services}
        highest_tier = min(service_tier_map.values()) if service_tier_map else 2
        tier1_services = [svc for svc, tier in service_tier_map.items() if tier == 1]

        if highest_tier == 1:
            tier_score = 35.0
            rationale.append(
                f"Impacts Tier-1 mission-critical services: {', '.join(sorted(tier1_services))} (+35 pts)."
            )
        elif highest_tier == 2:
            tier_score = 20.0
            tier2_services = [svc for svc, tier in service_tier_map.items() if tier == 2]
            rationale.append(
                f"Impacts Tier-2 operational services: {', '.join(sorted(tier2_services))} (+20 pts)."
            )
        else:
            tier_score = 10.0
            rationale.append(f"Impacts internal/batch Tier-3 services (+10 pts).")

        # -------------------------------------------------------------------
        # 3. Blast Radius Component (0 - 25 pts)
        # -------------------------------------------------------------------
        distinct_service_count = len(affected_services)
        if distinct_service_count >= 3:
            blast_score = 25.0
            rationale.append(
                f"Wide architectural blast radius spanning {distinct_service_count} services "
                f"({', '.join(sorted(affected_services))}; +25 pts)."
            )
        elif distinct_service_count == 2:
            blast_score = 15.0
            rationale.append(
                f"Cross-service cascade between 2 services "
                f"({', '.join(sorted(affected_services))}; +15 pts)."
            )
        else:
            blast_score = 5.0
            rationale.append(f"Contained single-service blast radius ({affected_services[0] if affected_services else 'unknown'}; +5 pts).")

        # -------------------------------------------------------------------
        # Composite Score & Priority Classification
        # -------------------------------------------------------------------
        total_score = round(min(100.0, alert_score + tier_score + blast_score), 2)

        # Explicit Threshold Rules
        # P1_CRITICAL: total >= 75 OR (critical alert AND tier 1 affected AND multi-service cascade)
        if total_score >= 75.0 or (highest_sev == "critical" and highest_tier == 1 and distinct_service_count >= 2):
            severity_level = "P1_CRITICAL"
            urgency = "IMMEDIATE"
            rationale.append(
                "Triggered P1 (Critical) criteria: high composite score or critical impact on Tier-1 multi-service topology."
            )
        elif total_score >= 50.0 or (highest_sev in {"critical", "high"} and highest_tier == 1):
            severity_level = "P2_HIGH"
            urgency = "HIGH"
            rationale.append(
                "Triggered P2 (High) criteria: substantial impact on critical infrastructure or elevated cross-service degradation."
            )
        elif total_score >= 25.0:
            severity_level = "P3_MEDIUM"
            urgency = "MODERATE"
            rationale.append("Triggered P3 (Medium) criteria: localized operational impairment without core infrastructure failure.")
        else:
            severity_level = "P4_LOW"
            urgency = "LOW"
            rationale.append("Triggered P4 (Low) criteria: minor or informational warning with minimal blast radius.")

        # -------------------------------------------------------------------
        # Missing Business Impact Audit
        # -------------------------------------------------------------------
        missing_impact = [
            "Customer-facing SLO/error budget burn rate metric not supplied.",
            "Active session count / transaction volume financial impact telemetry absent.",
            "Geographic or multi-availability zone blast radius details absent."
        ]

        return IncidentSeverityAssessment(
            incident_id=incident_id,
            severity_level=severity_level,
            urgency=urgency,
            severity_score=total_score,
            score_breakdown=SeverityScoreBreakdown(
                alert_severity_score=alert_score,
                service_tier_score=tier_score,
                blast_radius_score=blast_score,
                total_score=total_score
            ),
            rationale=rationale,
            affected_tier1_services=sorted(tier1_services),
            blast_radius_services_count=distinct_service_count,
            missing_impact_data=missing_impact,
            assessment_metadata={
                "agent": "SeverityAgent",
                "rules_version": "1.0.0",
                "algorithm": "deterministic_weighted_tier_blast",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )


# ---------------------------------------------------------------------------
# LangGraph Node Entrypoint
# ---------------------------------------------------------------------------

def severity_agent_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """LangGraph node execution function for Severity Agent."""
    candidate_incidents = state.get("candidate_incidents", [])
    all_alerts = state.get("alerts", [])
    root_cause_findings = state.get("root_cause_findings", [])
    rca_by_id = {f.get("incident_id"): f for f in root_cause_findings}

    agent = SeverityAgent()
    severity_assessments: List[Dict[str, Any]] = []
    errors = list(state.get("errors", []))
    has_p1 = False

    for inc in candidate_incidents:
        try:
            rca = rca_by_id.get(inc.get("group_id"))
            assessment = agent.assess_incident(
                candidate_incident=inc,
                all_alerts=all_alerts,
                root_cause_analysis=rca
            )
            assessment_dict = assessment.model_dump()
            severity_assessments.append(assessment_dict)

            if assessment.severity_level == "P1_CRITICAL":
                has_p1 = True

        except Exception as e:
            logger.error(f"Severity assessment failed for {inc.get('group_id')}: {e}", exc_info=True)
            errors.append({
                "stage": "severity_agent",
                "incident_id": inc.get("group_id"),
                "message": str(e)
            })

    return {
        "severity_assessments": severity_assessments,
        "is_high_severity_incident": has_p1,
        "errors": errors
    }

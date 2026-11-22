"""Incident Reporting Agent Module.

Acts as Agent Stage 4 in the AlertSense multi-agent architecture.
Synthesizes verified outputs from Correlation, Root Cause Analysis, and Severity
into comprehensive, executive-ready, schema-validated incident reports.

Key Principles:
- Strictly grounded in verified workflow outputs; does NOT invent facts.
- Produces chronological incident timeline of alerts and cascades.
- Categorizes actionable recommendations (Mitigation, Diagnostics, Prevention).
- Never claims recommendations were executed.
- Supports Gemini LLM synthesis with robust deterministic structured fallback.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

from backend.services.correlation_engine import parse_iso_timestamp
from ai_agents.prompts.reporting_prompt import (
    PROMPT_VERSION,
    REPORTING_SYSTEM_PROMPT,
    build_reporting_user_prompt
)

from ai_agents.gemini_service import GeminiService

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Structured Schemas for Incident Report
# ---------------------------------------------------------------------------

class TimelineEvent(BaseModel):
    """An event in the incident timeline."""
    timestamp: str
    service: str
    alert_type: str
    severity: str
    host: Optional[str] = None
    message: str
    alert_id: str


class RecommendedAction(BaseModel):
    """A prioritized investigation or remediation step for operators."""
    action: str
    category: str = Field(..., description="Immediate Mitigation, Diagnostic Investigation, or Post-Incident Prevention")
    is_safe_readonly: bool = True


class IncidentReport(BaseModel):
    """Comprehensive structured incident report for a single incident cluster."""
    incident_id: str
    title: str
    executive_summary: str
    severity_assessment: Dict[str, Any]
    affected_services: List[str]
    timeline: List[TimelineEvent] = Field(default_factory=list)
    root_cause_summary: Dict[str, Any] = Field(default_factory=dict)
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    evidence_summary: List[str] = Field(default_factory=list)
    uncertainty_and_gaps: List[str] = Field(default_factory=list)
    status: str = Field(..., description="completed, completed_with_fallback, or error")
    report_metadata: Dict[str, Any] = Field(default_factory=dict)


class ComprehensiveIncidentReport(BaseModel):
    """Top-level report containing all investigated incidents from the workflow run."""
    generated_at: str
    total_incidents_reported: int
    high_severity_incidents_count: int
    incidents: List[IncidentReport]
    workflow_status: str


# ---------------------------------------------------------------------------
# Reporting Agent Implementation
# ---------------------------------------------------------------------------

class ReportingAgent:
    """Synthesizes analysis outputs into structured incident reports."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None
    ):
        if api_key is not None:
            self.api_key = api_key.strip()
        else:
            self.api_key = (os.getenv("GEMINI_API_KEY") or "").strip()

        if model_name is not None:
            self.model_name = model_name.strip()
        else:
            self.model_name = (os.getenv("GEMINI_MODEL") or "gemini-2.5-flash").strip()

        self.gemini_service = GeminiService(api_key=self.api_key, model_name=self.model_name)

    def build_timeline(
        self,
        candidate_incident: Dict[str, Any],
        all_alerts: List[Dict[str, Any]]
    ) -> List[TimelineEvent]:
        """Build sorted, chronological timeline of all alerts involved in the incident."""
        incident_alert_ids = set(candidate_incident.get("alert_ids", []))
        for dup in candidate_incident.get("duplicate_alert_ids", []):
            incident_alert_ids.add(dup)

        alerts_in_incident = [
            a for a in all_alerts if a.get("alert_id") in incident_alert_ids
        ]

        # Sort chronologically
        sorted_alerts = sorted(
            alerts_in_incident,
            key=lambda a: parse_iso_timestamp(a["timestamp"])
        )

        timeline = []
        for a in sorted_alerts:
            timeline.append(TimelineEvent(
                timestamp=a.get("timestamp", ""),
                service=a.get("service", ""),
                alert_type=a.get("alert_type", ""),
                severity=a.get("severity", ""),
                host=a.get("host"),
                message=a.get("message", ""),
                alert_id=a.get("alert_id", "")
            ))
        return timeline

    def generate_incident_report(
        self,
        candidate_incident: Dict[str, Any],
        all_alerts: List[Dict[str, Any]],
        root_cause_analysis: Optional[Dict[str, Any]],
        severity_assessment: Optional[Dict[str, Any]]
    ) -> IncidentReport:
        """Generate structured incident report for a candidate incident cluster."""
        incident_id = candidate_incident.get("group_id", "UNKNOWN-INCIDENT")
        affected_services = sorted(candidate_incident.get("affected_services", []))
        timeline = self.build_timeline(candidate_incident, all_alerts)

        # Extract severity facts
        sev_level = severity_assessment.get("severity_level", "P3_MEDIUM") if severity_assessment else "P3_MEDIUM"
        urgency = severity_assessment.get("urgency", "MODERATE") if severity_assessment else "MODERATE"
        sev_score = severity_assessment.get("severity_score", 50.0) if severity_assessment else 50.0

        # Extract RCA facts
        primary_hyp = root_cause_analysis.get("primary_hypothesis", {}) if root_cause_analysis else {}
        suspected_service = primary_hyp.get("root_cause_service", affected_services[0] if affected_services else "unknown")
        rca_explanation = primary_hyp.get("explanation", "Investigation pending.")
        rca_title = primary_hyp.get("title", f"Incident on {suspected_service}")
        evidence_ids = primary_hyp.get("evidence_alert_ids", [])
        dep_edges = primary_hyp.get("supporting_dependency_edges", [])
        missing_evidence = root_cause_analysis.get("missing_evidence", []) if root_cause_analysis else []
        safe_checks = root_cause_analysis.get("recommended_investigation_checks", []) if root_cause_analysis else []

        # Attempt Gemini LLM report generation if service is configured
        if self.gemini_service.is_configured():
            try:
                llm_report = self._call_gemini_reporting(
                    incident_id=incident_id,
                    sev_level=sev_level,
                    urgency=urgency,
                    affected_services=affected_services,
                    primary_hyp=primary_hyp,
                    timeline=timeline,
                    missing_evidence=missing_evidence,
                    safe_checks=safe_checks
                )
                if llm_report:
                    llm_report.severity_assessment = severity_assessment or {}
                    llm_report.affected_services = affected_services
                    llm_report.timeline = timeline
                    llm_report.root_cause_summary = primary_hyp
                    llm_report.uncertainty_and_gaps = missing_evidence + (
                        severity_assessment.get("missing_impact_data", []) if severity_assessment else []
                    )
                    return llm_report
            except Exception as e:
                logger.warning(f"Gemini reporting call failed for {incident_id}: {e}. Engaging deterministic builder.")

        # Deterministic Structured Report Builder (Fallback)
        return self._deterministic_report_builder(
            incident_id=incident_id,
            candidate_incident=candidate_incident,
            severity_assessment=severity_assessment,
            root_cause_analysis=root_cause_analysis,
            timeline=timeline,
            affected_services=affected_services,
            suspected_service=suspected_service,
            rca_title=rca_title,
            rca_explanation=rca_explanation,
            evidence_ids=evidence_ids,
            dep_edges=dep_edges,
            missing_evidence=missing_evidence,
            safe_checks=safe_checks,
            sev_level=sev_level,
            urgency=urgency,
            sev_score=sev_score
        )

    def _call_gemini_reporting(
        self,
        incident_id: str,
        sev_level: str,
        urgency: str,
        affected_services: List[str],
        primary_hyp: Dict[str, Any],
        timeline: List[TimelineEvent],
        missing_evidence: List[str],
        safe_checks: List[str]
    ) -> Optional[IncidentReport]:
        """Invoke Gemini API to generate executive report wording."""
        context = {
            "incident_id": incident_id,
            "severity_level": sev_level,
            "urgency": urgency,
            "affected_services": affected_services,
            "primary_hypothesis": primary_hyp,
            "timeline": [t.model_dump() for t in timeline],
            "missing_evidence": missing_evidence,
            "preliminary_safe_checks": safe_checks
        }

        user_prompt = build_reporting_user_prompt(context)

        data, telemetry = self.gemini_service.generate_json(
            system_instruction=REPORTING_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.1
        )

        if not data:
            return None

        actions = []
        for a in data.get("recommended_actions", []):
            try:
                actions.append(RecommendedAction(**a))
            except Exception:
                pass

        return IncidentReport(
            incident_id=incident_id,
            title=data.get("title", f"{sev_level}: Incident on {', '.join(affected_services)}"),
            executive_summary=data.get("executive_summary", "Incident summary generated."),
            severity_assessment={},
            affected_services=affected_services,
            timeline=timeline,
            root_cause_summary=primary_hyp,
            recommended_actions=actions,
            evidence_summary=data.get("evidence_summary", []),
            uncertainty_and_gaps=[],
            status="completed",
            report_metadata={
                "agent": "ReportingAgent",
                "method": "gemini_llm",
                "model_name": self.model_name,
                "prompt_version": PROMPT_VERSION,
                "telemetry": telemetry,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

    def _deterministic_report_builder(
        self,
        incident_id: str,
        candidate_incident: Dict[str, Any],
        severity_assessment: Optional[Dict[str, Any]],
        root_cause_analysis: Optional[Dict[str, Any]],
        timeline: List[TimelineEvent],
        affected_services: List[str],
        suspected_service: str,
        rca_title: str,
        rca_explanation: str,
        evidence_ids: List[str],
        dep_edges: List[str],
        missing_evidence: List[str],
        safe_checks: List[str],
        sev_level: str,
        urgency: str,
        sev_score: float
    ) -> IncidentReport:
        """Deterministic structured incident report generator."""
        # 1. Headline Title
        services_str = ", ".join(affected_services)
        title = f"[{sev_level}] Incident {incident_id}: Suspected failure on '{suspected_service}' impacting {len(affected_services)} service(s)"

        # 2. Executive Summary
        earliest_time = timeline[0].timestamp if timeline else "unknown time"
        latest_time = timeline[-1].timestamp if timeline else "unknown time"
        total_alerts = len(timeline)
        exec_summary = (
            f"{sev_level} incident detected across {len(affected_services)} service(s) ({services_str}) "
            f"comprising {total_alerts} active/correlated alert events between {earliest_time} and {latest_time}. "
            f"Severity score is {sev_score}/100 with {urgency} urgency. "
            f"Initial investigation points to '{suspected_service}' as the originating failure root."
        )

        # 3. Categorized Actionable Recommendations
        recs: List[RecommendedAction] = []

        # Immediate Mitigation
        if sev_level in {"P1_CRITICAL", "P2_HIGH"}:
            recs.append(RecommendedAction(
                action=f"Initiate operational bridge and verify health status of core service '{suspected_service}'.",
                category="Immediate Mitigation",
                is_safe_readonly=True
            ))
            if "database" in affected_services:
                recs.append(RecommendedAction(
                    action="Check active database connection pools and terminate hung or slow transactions if saturated.",
                    category="Immediate Mitigation",
                    is_safe_readonly=False
                ))

        # Diagnostic Investigation
        for check in safe_checks:
            recs.append(RecommendedAction(
                action=check,
                category="Diagnostic Investigation",
                is_safe_readonly=True
            ))

        # Post-Incident Prevention
        recs.append(RecommendedAction(
            action=f"Review dependency resilience, circuit breaking, and timeouts between dependent services and '{suspected_service}'.",
            category="Post-Incident Prevention",
            is_safe_readonly=True
        ))

        # 4. Evidence Summary
        evidence_summary = [
            f"Earliest triggered alert occurred on '{timeline[0].service}' ({timeline[0].alert_type}) at {timeline[0].timestamp} (Alert ID: {timeline[0].alert_id})." if timeline else "No alert timeline available.",
            f"Correlation Engine established cluster based on time proximity and dependency graph links.",
            f"Root cause hypothesis cited alert evidence: {', '.join(evidence_ids) if evidence_ids else 'None'}."
        ]
        if dep_edges:
            evidence_summary.append(f"Architectural propagation supported by dependency links: {'; '.join(dep_edges)}.")

        # 5. Uncertainty & Gaps
        uncertainties = list(missing_evidence)
        if severity_assessment:
            uncertainties.extend(severity_assessment.get("missing_impact_data", []))
        if candidate_incident.get("uncertainty_notes"):
            uncertainties.extend(candidate_incident.get("uncertainty_notes", []))

        return IncidentReport(
            incident_id=incident_id,
            title=title,
            executive_summary=exec_summary,
            severity_assessment=severity_assessment or {},
            affected_services=affected_services,
            timeline=timeline,
            root_cause_summary=root_cause_analysis.get("primary_hypothesis", {}) if root_cause_analysis else {},
            recommended_actions=recs,
            evidence_summary=evidence_summary,
            uncertainty_and_gaps=uncertainties,
            status="completed_with_fallback",
            report_metadata={
                "agent": "ReportingAgent",
                "method": "deterministic_structured_builder",
                "prompt_version": PROMPT_VERSION,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

    def generate_comprehensive_report(
        self,
        candidate_incidents: List[Dict[str, Any]],
        all_alerts: List[Dict[str, Any]],
        root_cause_findings: List[Dict[str, Any]],
        severity_assessments: List[Dict[str, Any]]
    ) -> ComprehensiveIncidentReport:
        """Generate top-level multi-incident report across the complete workflow."""
        rca_by_id = {f.get("incident_id"): f for f in root_cause_findings}
        sev_by_id = {s.get("incident_id"): s for s in severity_assessments}

        reports: List[IncidentReport] = []
        high_sev_count = 0

        for inc in candidate_incidents:
            iid = inc.get("group_id")
            rca = rca_by_id.get(iid)
            sev = sev_by_id.get(iid)

            rep = self.generate_incident_report(
                candidate_incident=inc,
                all_alerts=all_alerts,
                root_cause_analysis=rca,
                severity_assessment=sev
            )
            reports.append(rep)
            if rep.severity_assessment.get("severity_level") in {"P1_CRITICAL", "P2_HIGH"}:
                high_sev_count += 1

        return ComprehensiveIncidentReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_incidents_reported=len(reports),
            high_severity_incidents_count=high_sev_count,
            incidents=reports,
            workflow_status="completed"
        )


# ---------------------------------------------------------------------------
# LangGraph Node Entrypoint
# ---------------------------------------------------------------------------

def reporting_agent_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """LangGraph node execution function for Incident Reporting Agent."""
    candidate_incidents = state.get("candidate_incidents", [])
    all_alerts = state.get("alerts", [])
    root_cause_findings = state.get("root_cause_findings", [])
    severity_assessments = state.get("severity_assessments", [])
    config = state.get("config", {})

    agent = ReportingAgent(
        api_key=config.get("gemini_api_key"),
        model_name=config.get("gemini_model")
    )

    errors = list(state.get("errors", []))
    try:
        comp_report = agent.generate_comprehensive_report(
            candidate_incidents=candidate_incidents,
            all_alerts=all_alerts,
            root_cause_findings=root_cause_findings,
            severity_assessments=severity_assessments
        )
        report_dict = comp_report.model_dump()
    except Exception as e:
        logger.error(f"ReportingAgent failed: {e}", exc_info=True)
        errors.append({
            "stage": "reporting_agent",
            "message": str(e)
        })
        report_dict = {
            "workflow_status": "error",
            "error_message": str(e),
            "incidents": []
        }

    return {
        "incident_report": report_dict,
        "errors": errors
    }

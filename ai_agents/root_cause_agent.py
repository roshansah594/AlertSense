"""Root Cause Analysis Agent Module.

Acts as Agent Stage 2 in the AlertSense multi-agent architecture.
Performs evidence-grounded root cause investigation on correlated candidate incidents.

Key Principles:
- Grounded in supplied alerts, topology, and timestamps; NEVER invents logs/metrics.
- Uses Gemini API for contextual language reasoning when available.
- Graceful, fully deterministic topological fallback when Gemini API is unavailable or unconfigured.
- Rigorous validation: rejects or flags unsupported alert citations.
- Prepares structured hypothesis rankings, missing evidence, and safe investigation steps.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import networkx as nx
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv

# Load local environment variables from .env if present
load_dotenv()

from backend.services.correlation_engine import (
    build_dependency_graph,
    parse_iso_timestamp
)
from ai_agents.prompts.root_cause_prompt import (
    PROMPT_VERSION,
    ROOT_CAUSE_SYSTEM_PROMPT,
    build_root_cause_user_prompt
)

from ai_agents.gemini_service import GeminiService

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Structured Schemas for Root Cause Analysis
# ---------------------------------------------------------------------------

class Hypothesis(BaseModel):
    """An evidence-grounded root cause hypothesis."""
    rank: int = Field(..., ge=1, description="Ranking of plausibility (1 = most plausible)")
    root_cause_service: str = Field(..., description="Service identified as origin of failure")
    title: str = Field(..., description="Concise descriptive title of hypothesis")
    explanation: str = Field(..., description="Detailed causal narrative explaining failure propagation")
    evidence_alert_ids: List[str] = Field(default_factory=list, description="IDs of supplied alerts supporting this hypothesis")
    supporting_dependency_edges: List[str] = Field(default_factory=list, description="Dependency graph edges supporting this hypothesis")
    confidence_label: str = Field("medium", description="Qualitative confidence: high, medium, low, unconfirmed")
    confidence_rationale: str = Field(..., description="Why this confidence level was assigned")

    @field_validator("confidence_label", mode="before")
    @classmethod
    def normalize_confidence(cls, v: Any) -> str:
        if not isinstance(v, str):
            return "medium"
        v_clean = v.strip().lower()
        if v_clean not in {"high", "medium", "low", "unconfirmed"}:
            return "medium"
        return v_clean


class IncidentRootCauseAnalysis(BaseModel):
    """Complete root cause investigation for a candidate incident cluster."""
    incident_id: str
    status: str = Field(..., description="completed, completed_with_fallback, insufficient_evidence, api_unavailable, or error")
    primary_hypothesis: Optional[Hypothesis] = None
    alternative_hypotheses: List[Hypothesis] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    recommended_investigation_checks: List[str] = Field(default_factory=list)
    evidence_validation_passed: bool = True
    validation_notes: List[str] = Field(default_factory=list)
    investigation_metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Root Cause Agent Implementation
# ---------------------------------------------------------------------------

class RootCauseAgent:
    """Investigates candidate incidents to determine probable root causes."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout_seconds: int = 20
    ):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = model_name or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self.timeout_seconds = timeout_seconds
        self.gemini_service = GeminiService(api_key=self.api_key, model_name=self.model_name)

    def analyze_incident(
        self,
        candidate_incident: Dict[str, Any],
        all_alerts: List[Dict[str, Any]],
        service_dependencies: Any
    ) -> IncidentRootCauseAnalysis:
        """Run root cause analysis on a single candidate incident."""
        incident_id = candidate_incident.get("group_id", "UNKNOWN-INCIDENT")
        incident_alert_ids = set(candidate_incident.get("alert_ids", []))
        
        # Include duplicates in valid alert references
        for dup in candidate_incident.get("duplicate_alert_ids", []):
            incident_alert_ids.add(dup)

        alerts_in_incident = [
            a for a in all_alerts if a.get("alert_id") in incident_alert_ids
        ]

        # Edge case: no alerts found in incident
        if not alerts_in_incident:
            return IncidentRootCauseAnalysis(
                incident_id=incident_id,
                status="insufficient_evidence",
                evidence_validation_passed=False,
                validation_notes=["Incident contains no resolvable alert data."],
                investigation_metadata={"agent": "RootCauseAgent", "method": "none"}
            )

        # Singleton alert case: single isolated alert
        if len(candidate_incident.get("alert_ids", [])) == 1:
            return self._analyze_singleton_incident(candidate_incident, alerts_in_incident[0])

        # Attempt LLM reasoning if Gemini client is active
        # Attempt LLM reasoning if Gemini service is configured
        if self.gemini_service.is_configured():
            try:
                llm_analysis = self._call_gemini_rca(
                    candidate_incident=candidate_incident,
                    alerts_in_incident=alerts_in_incident,
                    service_dependencies=service_dependencies
                )
                if llm_analysis:
                    validated = self._validate_and_sanitize_evidence(
                        llm_analysis,
                        valid_alert_ids=incident_alert_ids,
                        affected_services=set(candidate_incident.get("affected_services", []))
                    )
                    return validated
            except Exception as e:
                logger.warning(f"Gemini API call failed for incident {incident_id}: {e}. Engaging deterministic fallback.")

        # Deterministic Fallback: Rule & topology based
        fallback_analysis = self._deterministic_root_cause_fallback(
            candidate_incident=candidate_incident,
            alerts_in_incident=alerts_in_incident,
            service_dependencies=service_dependencies,
            reason="api_unavailable" if not self.gemini_service.is_configured() else "api_call_failed"
        )
        return fallback_analysis

    def _call_gemini_rca(
        self,
        candidate_incident: Dict[str, Any],
        alerts_in_incident: List[Dict[str, Any]],
        service_dependencies: Any
    ) -> Optional[IncidentRootCauseAnalysis]:
        """Invoke Gemini API with structured prompt and extract validated JSON."""
        user_prompt = build_root_cause_user_prompt(
            candidate_incident=candidate_incident,
            alerts_in_incident=alerts_in_incident,
            service_dependencies=service_dependencies
        )

        data, telemetry = self.gemini_service.generate_json(
            system_instruction=ROOT_CAUSE_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.1
        )

        if not data:
            return None

        # Parse hypotheses
        primary_raw = data.get("primary_hypothesis")
        primary_hyp = Hypothesis(**primary_raw) if primary_raw else None

        alt_hyps = []
        for raw_h in data.get("alternative_hypotheses", []):
            try:
                alt_hyps.append(Hypothesis(**raw_h))
            except Exception:
                pass

        return IncidentRootCauseAnalysis(
            incident_id=candidate_incident.get("group_id", "UNKNOWN"),
            status="completed",
            primary_hypothesis=primary_hyp,
            alternative_hypotheses=alt_hyps,
            missing_evidence=data.get("missing_evidence", []),
            recommended_investigation_checks=data.get("recommended_investigation_checks", []),
            evidence_validation_passed=True,
            validation_notes=[],
            investigation_metadata={
                "agent": "RootCauseAgent",
                "method": "gemini_llm",
                "model_name": self.model_name,
                "prompt_version": PROMPT_VERSION,
                "telemetry": telemetry,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

    def _deterministic_root_cause_fallback(
        self,
        candidate_incident: Dict[str, Any],
        alerts_in_incident: List[Dict[str, Any]],
        service_dependencies: Any,
        reason: str
    ) -> IncidentRootCauseAnalysis:
        """Topological and chronological deterministic root cause fallback.
        
        Evaluates:
        1. Dependency Graph: Identifies root upstream services with in-degree 0 in the incident subgraph.
        2. Earliest Alert: Identifies the root service with the earliest timestamp.
        3. Cascading Edges: Identifies downstream dependent services.
        """
        incident_id = candidate_incident.get("group_id", "UNKNOWN")
        affected_services = set(candidate_incident.get("affected_services", []))
        dep_graph = build_dependency_graph(service_dependencies)

        # Sort alerts chronologically
        sorted_alerts = sorted(
            alerts_in_incident,
            key=lambda a: parse_iso_timestamp(a["timestamp"])
        )
        earliest_alert = sorted_alerts[0]

        # Analyze subgraph of affected services
        subgraph = nx.DiGraph()
        for svc in affected_services:
            subgraph.add_node(svc)

        # Add edges where u depends on v
        for u in affected_services:
            for v in affected_services:
                if u != v and dep_graph.has_edge(u, v):
                    subgraph.add_edge(u, v)

        # Root services in dependency orientation (services that do not depend on other incident services)
        # In our graph, edge is (downstream -> upstream), so out_degree == 0 means it has no upstream in incident
        upstream_roots = [node for node in subgraph.nodes if subgraph.out_degree(node) == 0]

        # Suspected root cause service: upstream root that had earliest alert
        suspected_service = earliest_alert.get("service")
        if upstream_roots:
            # Check if any upstream root had an alert
            root_alerts = [a for a in sorted_alerts if a.get("service") in upstream_roots]
            if root_alerts:
                suspected_service = root_alerts[0].get("service")
            else:
                suspected_service = upstream_roots[0]

        # Gather supporting alerts for the suspected origin
        origin_alerts = [a for a in sorted_alerts if a.get("service") == suspected_service]
        downstream_alerts = [a for a in sorted_alerts if a.get("service") != suspected_service]

        evidence_ids = [a.get("alert_id") for a in origin_alerts]
        for a in downstream_alerts[:2]:
            evidence_ids.append(a.get("alert_id"))

        # Dependency edges supporting propagation
        edges = []
        for downstream in affected_services:
            if (
                downstream != suspected_service
                and dep_graph.has_node(downstream)
                and dep_graph.has_node(suspected_service)
                and nx.has_path(dep_graph, downstream, suspected_service)
            ):
                edges.append(f"{downstream} depends_on {suspected_service}")

        # Construct primary hypothesis
        earliest_type = origin_alerts[0].get("alert_type") if origin_alerts else earliest_alert.get("alert_type")
        primary_title = f"Originating failure on upstream service '{suspected_service}' ({earliest_type})"
        
        downstream_str = ", ".join(sorted(list(affected_services - {suspected_service})))
        explanation = (
            f"Chronological and topological evidence indicates '{suspected_service}' as the failure origin. "
            f"The earliest incident alert ({origin_alerts[0].get('alert_id') if origin_alerts else earliest_alert.get('alert_id')}) "
            f"occurred on '{suspected_service}' with '{earliest_type}', subsequently cascading to downstream "
            f"dependent services ({downstream_str or 'none'})."
        )

        primary_hyp = Hypothesis(
            rank=1,
            root_cause_service=suspected_service,
            title=primary_title,
            explanation=explanation,
            evidence_alert_ids=evidence_ids,
            supporting_dependency_edges=edges,
            confidence_label="medium",
            confidence_rationale="Inferred deterministically from service dependency direction and earliest alert timestamp without LLM log analysis."
        )

        # Alternative hypothesis: network/shared host or independent simultaneous degradation
        shared_hosts = {a.get("host") for a in alerts_in_incident if a.get("host")}
        alt_hyps = []
        if len(shared_hosts) == 1 and None not in shared_hosts:
            host_name = list(shared_hosts)[0]
            alt_hyps.append(Hypothesis(
                rank=2,
                root_cause_service="infrastructure-host",
                title=f"Shared hardware/hypervisor degradation on host '{host_name}'",
                explanation=f"All affected services share common host '{host_name}'. Host-level resource contention or hardware fault could be driving simultaneous alerts.",
                evidence_alert_ids=[a.get("alert_id") for a in alerts_in_incident[:3]],
                supporting_dependency_edges=[],
                confidence_label="low",
                confidence_rationale="Shared host context observed, but specific host hypervisor metrics are absent."
            ))
        elif downstream_alerts:
            first_downstream = downstream_alerts[0]
            alt_hyps.append(Hypothesis(
                rank=2,
                root_cause_service=first_downstream.get("service"),
                title=f"Independent failure originating in downstream service '{first_downstream.get('service')}'",
                explanation=f"Downstream service '{first_downstream.get('service')}' may have experienced an autonomous defect triggering downstream retries that saturated upstream '{suspected_service}'.",
                evidence_alert_ids=[first_downstream.get("alert_id")],
                supporting_dependency_edges=[],
                confidence_label="low",
                confidence_rationale="Reverse retry storm is architecturally plausible but lacks application retry telemetry."
            ))

        missing_evidence = [
            f"Detailed transaction and error logs for '{suspected_service}'.",
            "Network packet capture or latency traces between services.",
            "Host-level memory, thread pool, and I/O wait metrics."
        ]

        safe_checks = [
            f"Inspect recent error logs and active thread count on '{suspected_service}'.",
            f"Verify network connectivity and connection pool saturation on '{suspected_service}'.",
            "Confirm whether any scheduled cron job or deployment occurred immediately prior to incident start."
        ]

        status_code = "completed_with_fallback" if reason == "api_unavailable" else "completed_with_fallback"

        return IncidentRootCauseAnalysis(
            incident_id=incident_id,
            status=status_code,
            primary_hypothesis=primary_hyp,
            alternative_hypotheses=alt_hyps,
            missing_evidence=missing_evidence,
            recommended_investigation_checks=safe_checks,
            evidence_validation_passed=True,
            validation_notes=[
                f"Deterministic baseline analysis used (Reason: {reason}). "
                "Reliant on topological upstream analysis and timestamp ordering."
            ],
            investigation_metadata={
                "agent": "RootCauseAgent",
                "method": "deterministic_topological_baseline",
                "prompt_version": PROMPT_VERSION,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

    def _analyze_singleton_incident(
        self,
        candidate_incident: Dict[str, Any],
        alert: Dict[str, Any]
    ) -> IncidentRootCauseAnalysis:
        """Analyze isolated singleton alert."""
        service = alert.get("service", "unknown")
        aid = alert.get("alert_id", "unknown")
        atype = alert.get("alert_type", "unknown")

        hyp = Hypothesis(
            rank=1,
            root_cause_service=service,
            title=f"Isolated anomaly on '{service}' ({atype})",
            explanation=f"Alert {aid} fired on '{service}' with no related cascade or correlated anomalies detected across other services.",
            evidence_alert_ids=[aid],
            supporting_dependency_edges=[],
            confidence_label="low",
            confidence_rationale="Single isolated alert without corroborating multi-service telemetry."
        )

        return IncidentRootCauseAnalysis(
            incident_id=candidate_incident.get("group_id", "UNKNOWN"),
            status="completed",
            primary_hypothesis=hyp,
            alternative_hypotheses=[],
            missing_evidence=[f"Service health check history and logs for '{service}'."],
            recommended_investigation_checks=[f"Check '{service}' dashboard to verify if anomaly auto-resolved."],
            evidence_validation_passed=True,
            validation_notes=["Singleton alert; no cascading dependencies identified."],
            investigation_metadata={
                "agent": "RootCauseAgent",
                "method": "singleton_baseline",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

    def _validate_and_sanitize_evidence(
        self,
        analysis: IncidentRootCauseAnalysis,
        valid_alert_ids: Set[str],
        affected_services: Set[str]
    ) -> IncidentRootCauseAnalysis:
        """Anti-hallucination guard: validates citations and flags unsupported claims."""
        notes = list(analysis.validation_notes)
        validation_passed = True

        def sanitize_hypothesis(hyp: Hypothesis) -> Hypothesis:
            nonlocal validation_passed
            sanitized_ids = []
            for aid in hyp.evidence_alert_ids:
                if aid in valid_alert_ids:
                    sanitized_ids.append(aid)
                else:
                    validation_passed = False
                    notes.append(f"Rejected unsupported alert citation '{aid}' in hypothesis '{hyp.title}'.")

            hyp.evidence_alert_ids = sanitized_ids
            if not sanitized_ids:
                hyp.confidence_label = "low"
                notes.append(f"Hypothesis '{hyp.title}' has no valid evidence alert citations.")
            return hyp

        if analysis.primary_hypothesis:
            analysis.primary_hypothesis = sanitize_hypothesis(analysis.primary_hypothesis)

        sanitized_alts = []
        for alt in analysis.alternative_hypotheses:
            sanitized_alts.append(sanitize_hypothesis(alt))
        analysis.alternative_hypotheses = sanitized_alts

        analysis.validation_notes = notes
        analysis.evidence_validation_passed = validation_passed
        if not validation_passed:
            analysis.status = "insufficient_evidence"

        return analysis


# ---------------------------------------------------------------------------
# LangGraph Node Entrypoint
# ---------------------------------------------------------------------------

def root_cause_agent_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """LangGraph node execution function for Root Cause Agent."""
    candidate_incidents = state.get("candidate_incidents", [])
    all_alerts = state.get("alerts", [])
    service_dependencies = state.get("service_dependencies", {})
    config = state.get("config", {})

    agent = RootCauseAgent(
        api_key=config.get("gemini_api_key"),
        model_name=config.get("gemini_model")
    )

    root_cause_findings: List[Dict[str, Any]] = []
    needs_review = state.get("needs_human_review", False)
    errors = list(state.get("errors", []))

    for inc in candidate_incidents:
        try:
            analysis = agent.analyze_incident(
                candidate_incident=inc,
                all_alerts=all_alerts,
                service_dependencies=service_dependencies
            )
            analysis_dict = analysis.model_dump()
            root_cause_findings.append(analysis_dict)

            # Trigger human review flag if confidence is low or evidence was insufficient
            if analysis.status in {"insufficient_evidence", "error"}:
                needs_review = True
            elif analysis.primary_hypothesis and analysis.primary_hypothesis.confidence_label in {"low", "unconfirmed"}:
                needs_review = True

        except Exception as e:
            logger.error(f"Root cause analysis failed for incident {inc.get('group_id')}: {e}", exc_info=True)
            errors.append({
                "stage": "root_cause_agent",
                "incident_id": inc.get("group_id"),
                "message": str(e)
            })
            needs_review = True

    return {
        "root_cause_findings": root_cause_findings,
        "needs_human_review": needs_review,
        "errors": errors
    }

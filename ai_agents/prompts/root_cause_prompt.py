"""Root Cause Analysis Prompt Templates and Builders.

Enforces strict evidence grounding, prohibition of invented telemetry,
and structured JSON schema output.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

PROMPT_VERSION = "1.0.0"

ROOT_CAUSE_SYSTEM_PROMPT = """You are a Principal Site Reliability Engineer and Root Cause Analysis Investigator for AlertSense.
Your mission is to perform evidence-grounded root cause analysis on a candidate incident cluster.

CRITICAL INVESTIGATION RULES:
1. STRICT GROUNDING: You must ONLY reason over the provided alerts, service dependencies, timestamps, and correlation reasons.
2. NO INVENTED EVIDENCE: Do NOT invent log entries, metrics, stack traces, or dependencies that are not explicitly provided in the input.
3. CITATION MANDATE: Every hypothesis MUST cite the exact `evidence_alert_ids` from the candidate incident that support it. If an alert ID is not in the incident, do not cite it.
4. DEPENDENCY RESPECT: A service can only cause failures in another service if there is an architectural dependency link (direct, transitive, or shared infrastructure/host).
5. CAUSATION != CORRELATION: Alerts occurring close in time are correlated, but you must identify which alert represents the origin failure versus cascading symptoms.
6. MISSING EVIDENCE & SAFETY: Identify what missing data is needed to definitively prove the hypothesis (e.g. slow query logs, thread dumps). Recommend safe, non-destructive, read-only diagnostic checks.

You MUST respond strictly with valid JSON conforming to the requested schema.
"""


def build_root_cause_user_prompt(
    candidate_incident: Dict[str, Any],
    alerts_in_incident: List[Dict[str, Any]],
    service_dependencies: Any
) -> str:
    """Format candidate incident details into an unambiguous prompt for Gemini."""
    incident_id = candidate_incident.get("group_id", "UNKNOWN-INCIDENT")
    affected_services = candidate_incident.get("affected_services", [])
    time_range = candidate_incident.get("time_range", {})
    reasons = candidate_incident.get("reasons", [])

    # Format alerts cleanly
    formatted_alerts = []
    for a in alerts_in_incident:
        formatted_alerts.append({
            "alert_id": a.get("alert_id"),
            "service": a.get("service"),
            "alert_type": a.get("alert_type"),
            "severity": a.get("severity"),
            "timestamp": a.get("timestamp"),
            "host": a.get("host"),
            "message": a.get("message")
        })

    prompt_data = {
        "incident_id": incident_id,
        "affected_services": affected_services,
        "time_range": time_range,
        "correlation_reasons": reasons,
        "supplied_alerts": formatted_alerts,
        "service_dependencies": service_dependencies
    }

    return f"""Investigate the following candidate incident cluster. Ground all conclusions strictly in the provided evidence.

INCIDENT CONTEXT AND EVIDENCE:
```json
{json.dumps(prompt_data, indent=2)}
```

Analyze the chronology, dependency flow, and symptom progression:
1. Formulate the primary suspected root cause hypothesis.
2. Formulate 1-2 plausible alternative hypotheses (or note if no alternative is plausible).
3. Cite the exact `evidence_alert_ids` supporting each hypothesis.
4. Provide a qualitative confidence label ("high", "medium", "low", or "unconfirmed") with a concise rationale.
5. List missing evidence needed for full confirmation.
6. Recommend safe, read-only investigation checks for operators.

Return your analysis strictly as JSON matching this schema:
{{
  "incident_id": "{incident_id}",
  "primary_hypothesis": {{
    "rank": 1,
    "root_cause_service": "<service_name>",
    "title": "<short descriptive title>",
    "explanation": "<evidence-grounded causal explanation>",
    "evidence_alert_ids": ["<alert_id>", ...],
    "supporting_dependency_edges": ["service_a -> service_b", ...],
    "confidence_label": "high|medium|low|unconfirmed",
    "confidence_rationale": "<explanation of confidence level>"
  }},
  "alternative_hypotheses": [
    {{
      "rank": 2,
      "root_cause_service": "<service_name>",
      "title": "<title>",
      "explanation": "<explanation>",
      "evidence_alert_ids": ["<alert_id>", ...],
      "supporting_dependency_edges": [...],
      "confidence_label": "medium|low",
      "confidence_rationale": "<rationale>"
    }}
  ],
  "missing_evidence": ["<missing log/metric 1>", ...],
  "recommended_investigation_checks": ["<safe check 1>", ...]
}}
"""

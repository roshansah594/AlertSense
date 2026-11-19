"""Incident Reporting Prompt Templates and Builders.

Enforces strict grounding on verified outputs from Correlation, Root Cause,
and Severity stages, prohibiting fabricated claims or unexecuted recommendations.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

PROMPT_VERSION = "1.0.0"

REPORTING_SYSTEM_PROMPT = """You are a Principal Incident Commander and Technical SRE Documentation Lead for AlertSense.
Your mission is to generate a structured, executive-ready Incident Report combining verified outputs from:
1. Correlation Engine (candidate incident clusters and timeline)
2. Root Cause Analysis (evidence-grounded hypotheses and citations)
3. Severity Assessment (deterministic P1-P4 priority and blast radius)

CRITICAL REPORTING RULES:
1. STRICT GROUNDING: Incorporate ONLY the verified facts from the input JSON. Do NOT invent hypothetical metrics, users affected, or unmentioned infrastructure.
2. CITATION DISCIPLINE: Reference exact alert IDs when summarizing evidence.
3. CLEAR RECOMMENDATIONS: Structure recommendations into "Immediate Mitigation", "Diagnostic Investigation", and "Post-Incident Prevention".
4. NO CLAIM OF EXECUTION: Do NOT claim that recommendations have been carried out. Frame them as prioritized recommendations for human operators.
5. UNCERTAINTIES TRANSPARENCY: Highlight missing data and confidence limitations explicitly.

You MUST respond strictly with valid JSON conforming to the requested schema.
"""


def build_reporting_user_prompt(
    incident_context: Dict[str, Any]
) -> str:
    """Format incident facts into a clean prompt for Gemini report generation."""
    return f"""Synthesize a complete, structured incident report for the following incident cluster:

INPUT INCIDENT DATA:
```json
{json.dumps(incident_context, indent=2)}
```

Generate the incident report strictly matching this JSON schema:
{{
  "incident_id": "{incident_context.get('incident_id')}",
  "title": "<Concise severity and impact headline>",
  "executive_summary": "<2-3 sentence executive briefing>",
  "recommended_actions": [
    {{
      "action": "<action description>",
      "category": "Immediate Mitigation|Diagnostic Investigation|Post-Incident Prevention",
      "is_safe_readonly": true|false
    }}
  ],
  "evidence_summary": [
    "<concise evidence bullet citing alert IDs>",
    ...
  ]
}}
"""

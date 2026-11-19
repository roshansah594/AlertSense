# AlertSense – Member 2 Backend & Platform Integration Guide

**Author:** Member 1 (AI, Correlation & Multi-Agent Architecture)  
**Target Audience:** Member 2 (FastAPI Application Shell, PostgreSQL Persistence, React Frontend)  
**Version:** 1.0.0

---

## 1. Division of Responsibilities

| Responsibility | Owner | Module / Location |
| :--- | :--- | :--- |
| **Alert Normalization & Preprocessing** | Member 1 | `orchestrator/workflow.py` (`preprocessing_node`) |
| **Deterministic Correlation Engine** | Member 1 | `backend/services/correlation_engine.py` |
| **Root Cause Analysis Agent (Gemini + Fallback)** | Member 1 | `ai_agents/root_cause_agent.py` |
| **Deterministic Severity Agent (P1-P4)** | Member 1 | `ai_agents/severity_agent.py` |
| **Incident Reporting Agent** | Member 1 | `ai_agents/reporting_agent.py` |
| **LangGraph Orchestrator** | Member 1 | `orchestrator/workflow.py`, `orchestrator/state.py` |
| **FastAPI REST API Routes** | **Member 2** | `app/api/...` |
| **PostgreSQL Database & SQLAlchemy Models** | **Member 2** | `app/db/...` |
| **React Dashboard & Visualizations** | **Member 2** | `frontend/...` |
| **Alert Ingestion Webhooks** | **Member 2** | `app/webhooks/...` |

---

## 2. Callable Python Interfaces

Member 1 exposes two functions ready for direct import:

```python
from backend.services.ai_service import run_full_incident_analysis, run_fast_correlation

# Or directly from the orchestrator:
from orchestrator.workflow import analyze_alerts
```

### Option A: Full Multi-Agent Pipeline (`analyze_alerts`)
Executes the full 5-stage LangGraph workflow:
```python
result = analyze_alerts(
    alerts=raw_alerts_list,
    service_dependencies=service_topology_dict,
    config={"correlation_threshold": 0.55}  # optional runtime config
)
```

### Option B: Fast Pure-Python Correlation (`run_fast_correlation`)
Bypasses LLM reasoning for high-frequency alert streams (sub-millisecond latency):
```python
corr_result = run_fast_correlation(
    alerts=raw_alerts_list,
    service_dependencies=service_topology_dict,
    time_window_seconds=300,
    correlation_threshold=0.55
)
```

---

## 3. Data Contracts

### 3.1 Input Contract: Normalized Alert Schema

Each alert dictionary passed to `analyze_alerts` should follow this structure:

```json
{
  "alert_id": "ALT-001",
  "service": "database",
  "alert_type": "high_cpu",
  "message": "Database CPU usage reached 96% on primary instance",
  "severity": "critical",
  "timestamp": "2026-11-19T10:00:00Z",
  "source": "prometheus",
  "host": "db-primary-01",
  "metadata": {}
}
```

- **`alert_id`** (str, required): Unique identifier from your database or monitoring tool.
- **`service`** (str, required): Affected microservice or infrastructure component (case-insensitive).
- **`alert_type`** (str, required): E.g., `high_cpu`, `query_timeout`, `http_500_spike`, `network_packet_loss`.
- **`message`** (str, required): Human-readable notification text.
- **`severity`** (str, required): `"critical"`, `"high"`, `"medium"`, `"low"`, or `"info"`.
- **`timestamp`** (str, required): ISO 8601 string (with or without timezone offset).
- **`source`** (str, optional): Monitoring tool (e.g. `"prometheus"`, `"datadog"`).
- **`host`** (str, optional): Hardware node or VM identifier.

### 3.2 Input Contract: Service Dependencies Schema

Directed dependency topology where `service` is the downstream caller and `depends_on` lists upstream callees/infrastructure:

```json
{
  "services": [
    {"service": "api", "depends_on": ["database", "cache"]},
    {"service": "authentication", "depends_on": ["api", "database"]},
    {"service": "database", "depends_on": []}
  ]
}
```

---

## 4. Output Contract: Incident Response Schema

`analyze_alerts(...)` returns a comprehensive dictionary with this structure:

```json
{
  "workflow_status": "completed",
  "needs_human_review": false,
  "is_high_severity_incident": true,
  "candidate_incidents": [
    {
      "group_id": "GRP-001",
      "alert_ids": ["ALT-001", "ALT-002", "ALT-004", "ALT-005", "ALT-006"],
      "duplicate_alert_ids": ["ALT-010"],
      "score": 0.703,
      "time_range": {
        "start_time": "2026-11-19T10:00:00+00:00",
        "end_time": "2026-11-19T10:01:45+00:00",
        "duration_seconds": 105
      },
      "affected_services": ["api", "authentication", "database"],
      "reasons": [
        "Direct dependency: 'api' depends directly on 'database'.",
        "Causal symptom match: 'resource_exhaustion' propagates into 'latency_timeout' across connected services."
      ]
    }
  ],
  "root_cause_findings": [
    {
      "incident_id": "GRP-001",
      "status": "completed",
      "primary_hypothesis": {
        "rank": 1,
        "root_cause_service": "database",
        "title": "Originating failure on upstream service 'database' (high_cpu)",
        "explanation": "Chronological and topological evidence indicates 'database' as failure origin...",
        "evidence_alert_ids": ["ALT-001", "ALT-002", "ALT-004"],
        "supporting_dependency_edges": ["api depends_on database", "authentication depends_on database"],
        "confidence_label": "high",
        "confidence_rationale": "Direct topological precedence and matching causal symptom propagation."
      },
      "missing_evidence": ["Detailed transaction and error logs for 'database'."],
      "recommended_investigation_checks": ["Inspect active connections and lock contention on database."]
    }
  ],
  "severity_assessments": [
    {
      "incident_id": "GRP-001",
      "severity_level": "P1_CRITICAL",
      "urgency": "IMMEDIATE",
      "severity_score": 95.0,
      "score_breakdown": {
        "alert_severity_score": 40.0,
        "service_tier_score": 35.0,
        "blast_radius_score": 20.0,
        "total_score": 95.0
      },
      "rationale": [
        "Highest alert severity is 'critical' (+30 pts); Alert density high (+10 pts).",
        "Impacts Tier-1 mission-critical services: database, api, authentication (+35 pts).",
        "Cross-service cascade across 3 services (+20 pts)."
      ]
    }
  ],
  "incident_report": {
    "total_incidents_reported": 1,
    "high_severity_incidents_count": 1,
    "incidents": [
      {
        "incident_id": "GRP-001",
        "title": "[P1_CRITICAL] Incident GRP-001: Suspected failure on 'database' impacting 3 service(s)",
        "executive_summary": "P1_CRITICAL incident detected across 3 service(s)...",
        "timeline": [
          {
            "timestamp": "2026-11-19T10:00:00Z",
            "service": "database",
            "alert_type": "high_cpu",
            "severity": "critical",
            "message": "Database CPU usage reached 96%",
            "alert_id": "ALT-001"
          }
        ],
        "recommended_actions": [
          {
            "action": "Initiate operational bridge and verify health status of core service 'database'.",
            "category": "Immediate Mitigation",
            "is_safe_readonly": true
          }
        ]
      }
    ]
  },
  "errors": []
}
```

---

## 5. Ready-to-Copy FastAPI Route Snippet

Member 2 can create an endpoint in their FastAPI application:

```python
from fastapi import APIRouter, HTTPException, status
from backend.services.ai_service import (
    AnalyzeAlertsRequest,
    AnalyzeAlertsResponse,
    run_full_incident_analysis
)

router = APIRouter(prefix="/api/v1/incidents", tags=["Incidents"])

@router.post("/analyze", response_model=AnalyzeAlertsResponse)
def analyze_alerts_endpoint(payload: AnalyzeAlertsRequest):
    try:
        results = run_full_incident_analysis(
            alerts=payload.alerts,
            service_dependencies=payload.service_dependencies,
            config=payload.config
        )
        return results
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AlertSense AI Orchestration failed: {str(e)}"
        )
```

---

## 6. Recommended PostgreSQL Schema (Member 2 Persistence)

Below is the recommended relational design for storing AlertSense outputs in PostgreSQL:

```sql
-- 1. Candidate Incidents Table
CREATE TABLE incidents (
    id VARCHAR(64) PRIMARY KEY, -- e.g. 'GRP-001'
    title TEXT NOT NULL,
    severity_level VARCHAR(20) NOT NULL, -- 'P1_CRITICAL', 'P2_HIGH', etc.
    severity_score NUMERIC(5, 2) NOT NULL,
    urgency VARCHAR(20) NOT NULL,
    root_cause_service VARCHAR(100),
    confidence_label VARCHAR(20),
    executive_summary TEXT,
    workflow_status VARCHAR(50) NOT NULL,
    needs_human_review BOOLEAN DEFAULT FALSE,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. Raw / Ingested Alerts Table
CREATE TABLE alerts (
    id VARCHAR(64) PRIMARY KEY, -- 'ALT-001'
    service VARCHAR(100) NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    source VARCHAR(50),
    host VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. Incident-to-Alert Association (Many-to-Many / Join Table)
CREATE TABLE incident_alerts (
    incident_id VARCHAR(64) REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id VARCHAR(64) REFERENCES alerts(id) ON DELETE CASCADE,
    is_duplicate BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (incident_id, alert_id)
);

-- 4. Recommended Actions Table
CREATE TABLE incident_actions (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(64) REFERENCES incidents(id) ON DELETE CASCADE,
    action_text TEXT NOT NULL,
    category VARCHAR(50) NOT NULL, -- 'Immediate Mitigation', 'Diagnostic', 'Post-Incident'
    is_safe_readonly BOOLEAN DEFAULT TRUE
);
```

---

## 7. Status Codes & Error Handling Conventions

| Workflow Status | Meaning | Recommended Member 2 Action |
| :--- | :--- | :--- |
| **`completed`** | Full multi-agent workflow succeeded with high confidence. | Persist incident to DB; notify on-call via Webhook/Pager. |
| **`completed_with_fallback`** | Deterministic algorithms succeeded; Gemini API was offline. | Persist incident; note that topological fallback was used. |
| **`requires_human_review`** | Insufficient telemetry, low confidence, or missing dependencies. | Persist incident; display visual "Human Review Required" badge in UI. |
| **`error`** | Fatal error in ingestion or execution. | Log in alert error queue; surface error details to operator. |

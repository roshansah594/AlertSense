# AlertSense – Alert Storm Correlation & Root Cause Analysis Platform

An AI-powered multi-agent incident intelligence platform that ingests raw telemetry alert storms, clusters related failures using multi-signal correlation and service dependency graphs, determines probable root causes using Google Gemini AI and topological algorithms, calculates deterministic severity priorities, and synthesizes executive incident reports to eliminate alert fatigue.

---

## Architecture Overview

```
                      Raw Monitoring Alerts (Prometheus, Datadog, Logs)
                                              │
                                              ▼
                             [1. Preprocessing & Normalization]
                                              │
                                              ▼
                         [2. Multi-Signal Correlation Agent]
                       (Temporal + Topology + Causal Symptoms)
                                              │
                                              ▼
                             [3. Root Cause Analysis Agent]
                          (Gemini 2.5 Flash + Topological Fallback)
                                              │
                                              ▼
                                 [4. Severity Agent]
                        (Deterministic P1-P4 Impact Scoring)
                                              │
                                              ▼
                             [5. Incident Reporting Agent]
                       (Actionable Structured JSON Reports)
                                              │
                                              ▼
                 FastAPI Backend (:8000) ─── SQLite3 (alertsense.db)
                                              │
                                              ▼
                        React 19 + TypeScript Dashboard (:5173)
```

---

## Key Features

1. **Deterministic Multi-Signal Correlation:**
   - Multi-factor scoring formula: $C = 0.30T + 0.30D + 0.25S + 0.15A$.
   - NetworkX topology-aware shortest path graph distance.
   - Causal symptom relationship propagation (e.g., `resource_exhaustion` $\to$ `latency_timeout` $\to$ `error_rate`).
   - Anti-merge safeguards preventing grouping solely based on time proximity or severity.

2. **Evidence-Grounded Root Cause Analysis:**
   - Powered by Google Gemini (`gemini-2.5-flash`) via the `google-genai` SDK.
   - Strict anti-hallucination citation validation: rejects ungrounded alert IDs.
   - Autonomous, zero-latency topological fallback when operating offline.

3. **Deterministic Severity & Priority Scoring:**
   - Transparent, auditable P1–P4 classification:
     - **P1 - CRITICAL:** Core Tier-1 services impacted across multiple nodes.
     - **P2 - HIGH:** Substantial degradation on critical components.
     - **P3 - MEDIUM:** Localized operational impairment.
     - **P4 - LOW:** Minor or informational warning.

4. **Modern Web Interface (React 19 + TypeScript + Vite):**
   - **System Overview:** Noise reduction metrics, active pipeline diagram, severity distributions.
   - **Live Alerts:** Real-time alert storm table with full-text search, severity filtering, and service filtering.
   - **Candidate Incidents:** Collapsible chronological alert cascade timelines, blast radius tags.
   - **Root Cause Analysis:** Suspected origin, primary hypothesis narrative, grounded citations, and categorized action plans (`SAFE READONLY` badges).

---

## Benchmark Performance & Evaluation

Tested against 16 synthetic benchmark alerts across 6 production failure scenarios:

- **Noise Reduction Ratio:** **62.5%** (16 alerts consolidated into 6 incidents)
- **Pairwise Correlation Precision:** **100.00%**
- **Pairwise Correlation Recall:** **100.00%**
- **F1-Score:** **1.0000**
- **False Merge Rate:** **0.00%** (0 false groupings)
- **Evidence Grounding Ratio:** **100.0%** (0 hallucinated citations)
- **Execution Latency:** **~17 ms** (offline pipeline)

---

## Quickstart Guide

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 2. Environment Setup
```bash
# Clone the repository
git clone git@github.com:roshansah594/AlertSense.git
cd AlertSense

# Install Python dependencies
pip install -r requirements.txt

# (Optional) Configure Gemini API for live LLM reasoning
copy .env.example .env
# Edit .env and insert your GEMINI_API_KEY
```

### 3. Run the Backend Server
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Base URL: `http://127.0.0.1:8000`
- Swagger Documentation: `http://127.0.0.1:8000/docs`

### 4. Run the React Frontend
In a new terminal:
```bash
cd frontend
npm install
npm run dev
```
- Open `http://localhost:5173` in your browser.
- Click **"Load Sample Data"** to load the 16 benchmark alerts.
- Click **"Run AI Investigation"** to execute the multi-agent correlation pipeline.

---

## Running Tests & Diagnostics

```bash
# Run complete pytest test suite (41 tests)
python -m pytest tests/ -v

# Run quantitative evaluation benchmark
python scripts/evaluate_system.py

# Run Gemini connection health check
python scripts/verify_gemini_connection.py

# Verify frontend build
cd frontend
npm run build
```

---

## Repository Structure

```
AlertSense/
├── ai_agents/                    # Autonomous AI Agents
│   ├── correlation_agent.py      # Stage 1: Clustering node & uncertainty tagging
│   ├── root_cause_agent.py       # Stage 2: Evidence grounding & hypothesis ranking
│   ├── severity_agent.py         # Stage 3: Deterministic P1-P4 scoring
│   ├── reporting_agent.py        # Stage 4: Executive synthesis & timelines
│   ├── gemini_service.py         # Resilient Google GenAI wrapper with 429 backoff
│   └── prompts/                  # System and user prompts
├── orchestrator/                 # LangGraph Multi-Agent Orchestrator
│   ├── workflow.py               # StateGraph compilation & supervisor logic
│   └── state.py                  # AlertSenseState TypedDict contract
├── backend/                      # Unified FastAPI Application Shell
│   ├── main.py                   # FastAPI server entrypoint & DB lifespan
│   ├── api/routes.py             # REST endpoints (/alerts, /incidents, /analytics)
│   ├── database/                 # SQLite persistence layer (WAL mode)
│   │   ├── connection.py         # Auto-initializing connection pool
│   │   └── models.py             # Schema & CRUD operations
│   └── services/                 # Core domain services
│       ├── correlation_engine.py # Deterministic multi-signal correlation
│       ├── ingestion.py          # Alert batch ingestion & sample loader
│       ├── preprocessing.py      # Normalization & timestamp sanitization
│       └── ai_service.py         # Direct Python callables for Member 2
├── datasets/                     # Synthetic Benchmark Telemetry
│   ├── sample_alerts.json        # 16 multi-scenario alerts
│   └── service_dependencies.json # 11-service directed graph
├── frontend/                     # React 19 + TypeScript + Vite Dashboard
│   ├── src/App.tsx               # 4-tab dashboard UI
│   ├── src/App.css               # Modern SRE platform styles
│   └── package.json
└── tests/                        # Comprehensive Pytest Suite
    ├── test_correlation.py       # Deterministic correlation tests
    ├── test_agents.py            # AI agent unit tests
    ├── test_workflow.py          # LangGraph state machine tests
    ├── test_evaluation_metrics.py# Precision, recall, false merge rate assertions
    └── test_integration.py       # FastAPI & end-to-end integration tests
```

---

## License
MIT License © 2026 AlertSense Team.

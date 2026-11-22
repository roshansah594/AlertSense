"""AlertSense Backend API Application Shell.

Combines the FastAPI REST API, database persistence, and LangGraph
AI multi-agent orchestration into a single runnable service.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import List
from fastapi import FastAPI, Response, status
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

from backend.database.connection import init_db, check_db_health
from backend.api.routes import router
from orchestrator.workflow import get_compiled_workflow

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AlertSense")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager to initialize DB on startup."""
    logger.info("Initializing AlertSense database...")
    init_db()
    # Pre-compile LangGraph workflow
    get_compiled_workflow()
    logger.info("AlertSense AI & Multi-Agent Platform ready.")
    yield


app = FastAPI(
    title="AlertSense API",
    description="Intelligent Alert Storm Correlation, Root Cause Analysis & Severity Assessment Platform",
    version="1.0.0",
    lifespan=lifespan
)

# ---------------------------------------------------------------------------
# CORS Configuration (Security Hardened)
# ---------------------------------------------------------------------------
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower().strip()
raw_origins = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()

if raw_origins:
    allowed_origins = [orig.strip() for orig in raw_origins.split(",") if orig.strip()]
elif ENVIRONMENT == "production":
    # Production strictly forbids wildcard origins with credentials
    logger.warning("CORS_ALLOWED_ORIGINS not set in production. Defaulting to strict empty origin list.")
    allowed_origins = []
else:
    # Development defaults to standard local dev servers
    allowed_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Mount primary API router under /api
app.include_router(router, prefix="/api")


@app.get("/")
def root():
    return {
        "project": "AlertSense",
        "version": "1.0.0",
        "environment": ENVIRONMENT,
        "status": "Running",
        "description": "Alert Storm Correlation & Root Cause Analysis Platform",
        "documentation": "/docs"
    }


@app.get("/health")
def health(response: Response):
    """Comprehensive health check verifying DB connectivity and application readiness.
    
    Returns HTTP 503 if critical dependencies (database or orchestrator) are unavailable.
    """
    db_healthy, db_details = check_db_health()
    orchestrator_ready = False

    try:
        wf = get_compiled_workflow()
        orchestrator_ready = wf is not None
    except Exception as e:
        logger.error(f"Orchestrator health check failed: {e}")

    is_healthy = db_healthy and orchestrator_ready

    if not is_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "healthy" if is_healthy else "unhealthy",
        "database": "connected" if db_healthy else "disconnected",
        "database_details": db_details,
        "orchestrator": "LangGraph StateGraph" if orchestrator_ready else "unavailable",
        "ai_agents": [
            "CorrelationAgent",
            "RootCauseAgent",
            "SeverityAgent",
            "ReportingAgent"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    print("\n" + "=" * 65)
    print("  Starting AlertSense Unified Backend API Server")
    print("  Swagger UI: http://127.0.0.1:8000/docs")
    print("=" * 65 + "\n")
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False)

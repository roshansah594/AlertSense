"""AlertSense Backend API Application Shell.

Combines the FastAPI REST API, database persistence, and LangGraph
AI multi-agent orchestration into a single runnable service.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database.connection import init_db
from backend.api.routes import router

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
    logger.info("AlertSense AI & Multi-Agent Platform ready.")
    yield


app = FastAPI(
    title="AlertSense API",
    description="Intelligent Alert Storm Correlation, Root Cause Analysis & Severity Assessment Platform",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount primary API router under /api
app.include_router(router, prefix="/api")


@app.get("/")
def root():
    return {
        "project": "AlertSense",
        "version": "1.0.0",
        "status": "Running",
        "description": "Alert Storm Correlation & Root Cause Analysis Platform",
        "documentation": "/docs"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "database": "connected",
        "orchestrator": "LangGraph StateGraph",
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

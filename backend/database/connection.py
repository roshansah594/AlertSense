"""AlertSense Database Connection Manager.

Provides a thread-safe SQLite persistence layer that stores ingested alerts,
correlated incidents, and investigation results with indexes and health verification.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, Tuple

logger = logging.getLogger(__name__)

DEFAULT_DB_FILE = Path(__file__).resolve().parent.parent.parent / "alertsense.db"
_DB_INITIALIZED = False


def get_db_path() -> Path:
    """Return the resolved database file path from environment or default."""
    env_path = os.getenv("ALERT_SENSE_DB_PATH") or os.getenv("DB_PATH")
    if env_path:
        return Path(env_path).resolve()
    return DEFAULT_DB_FILE


def _init_tables(conn: sqlite3.Connection) -> None:
    """Create database tables and performance indexes if they do not exist."""
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                service TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source TEXT,
                host TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity_level TEXT NOT NULL,
                severity_score REAL NOT NULL,
                severity_reasoning TEXT,
                urgency TEXT,
                root_cause_service TEXT,
                root_cause_hypothesis TEXT,
                confidence_score REAL DEFAULT 0.85,
                confidence_label TEXT DEFAULT 'medium',
                summary TEXT,
                executive_summary TEXT,
                workflow_status TEXT DEFAULT 'completed',
                needs_human_review BOOLEAN DEFAULT 0,
                start_time TEXT,
                end_time TEXT,
                affected_services TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS incident_alerts (
                incident_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                is_duplicate BOOLEAN DEFAULT 0,
                PRIMARY KEY (incident_id, alert_id),
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE,
                FOREIGN KEY (alert_id) REFERENCES alerts (alert_id) ON DELETE CASCADE
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS incident_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                action_text TEXT NOT NULL,
                category TEXT,
                is_safe_readonly BOOLEAN DEFAULT 1,
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
            );
        """)

        # Performance Indexes for frequent queries and filtering
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_service ON alerts(service);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity_level);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_alerts_inc_id ON incident_alerts(incident_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_alerts_alt_id ON incident_alerts(alert_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_actions_inc_id ON incident_actions(incident_id);")


def get_connection() -> sqlite3.Connection:
    """Return a configured sqlite3 connection with dict-like row access."""
    global _DB_INITIALIZED
    db_file = get_db_path()
    db_file.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_file), timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 15000;")
    if not _DB_INITIALIZED:
        _init_tables(conn)
        _DB_INITIALIZED = True
    return conn


def init_db() -> None:
    """Explicitly initialize database tables and indexes."""
    conn = get_connection()
    _init_tables(conn)
    conn.close()


def check_db_health() -> Tuple[bool, Dict[str, Any]]:
    """Execute a real connection and query check against the SQLite database.
    
    Returns:
        (is_healthy, status_details)
    """
    try:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1;")
            cur.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name IN ('alerts', 'incidents', 'incident_alerts', 'incident_actions');
            """)
            tables = [row["name"] for row in cur.fetchall()]
            required_tables = {"alerts", "incidents", "incident_alerts", "incident_actions"}
            missing = required_tables - set(tables)

            if missing:
                return False, {
                    "database_file": str(get_db_path()),
                    "error": f"Missing required database tables: {', '.join(sorted(missing))}"
                }

            return True, {
                "database_file": str(get_db_path()),
                "tables_verified": sorted(tables),
                "journal_mode": "WAL"
            }
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Database health verification failed: {e}", exc_info=True)
        return False, {
            "database_file": str(get_db_path()),
            "error": str(e)
        }

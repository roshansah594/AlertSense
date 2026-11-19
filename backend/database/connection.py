"""AlertSense Database Connection Manager.

Provides a thread-safe, zero-dependency SQLite persistence layer
that stores ingested alerts, correlated incidents, and investigation results.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

DB_FILE = Path(__file__).resolve().parent.parent.parent / "alertsense.db"
_DB_INITIALIZED = False


def _init_tables(conn: sqlite3.Connection) -> None:
    """Create database tables if they do not exist."""
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


def get_connection() -> sqlite3.Connection:
    """Return a configured sqlite3 connection with dict-like row access."""
    global _DB_INITIALIZED
    conn = sqlite3.connect(str(DB_FILE), timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    if not _DB_INITIALIZED:
        _init_tables(conn)
        _DB_INITIALIZED = True
    return conn


def init_db() -> None:
    """Explicitly initialize database tables."""
    conn = get_connection()
    _init_tables(conn)
    conn.close()

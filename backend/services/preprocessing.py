"""Alert Preprocessing Service.

Validates and normalizes raw alert dictionaries to ensure schema conformity
before correlation and persistence.
"""

from __future__ import annotations

from typing import Any, Dict
from backend.services.correlation_engine import parse_iso_timestamp


def normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and normalize a single raw monitoring alert.
    
    Raises ValueError if alert is not a dictionary, required fields are missing,
    or the timestamp cannot be parsed as a valid ISO 8601 string.
    """
    if not isinstance(alert, dict):
        raise ValueError(f"Alert must be a dictionary, got {type(alert).__name__}")

    required = ["alert_id", "service", "alert_type", "message", "severity", "timestamp"]

    for field in required:
        if field not in alert or alert[field] is None:
            raise ValueError(f"Missing required field: '{field}'")
        if isinstance(alert[field], str) and not alert[field].strip():
            raise ValueError(f"Required field '{field}' cannot be empty")

    result = dict(alert)
    result["alert_id"] = str(result["alert_id"]).strip()
    result["service"] = str(result["service"]).strip().lower()
    result["alert_type"] = str(result["alert_type"]).strip().lower()
    result["severity"] = str(result["severity"]).strip().lower()
    result["message"] = str(result["message"]).strip()

    # Validate allowed severity
    allowed_sevs = {"critical", "high", "medium", "low", "info"}
    if result["severity"] not in allowed_sevs:
        result["severity"] = "medium"

    # Validate and normalize ISO timestamp
    dt = parse_iso_timestamp(result["timestamp"])
    result["timestamp"] = dt.isoformat()

    # Optional fields
    result["source"] = str(result["source"]).strip() if result.get("source") else None
    result["host"] = str(result["host"]).strip() if result.get("host") else None
    result["metadata"] = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}

    return result

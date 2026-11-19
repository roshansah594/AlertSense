"""Alert Preprocessing Service.

Validates and normalizes raw alert dictionaries to ensure schema conformity
before correlation and persistence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict


def normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and normalize a single raw monitoring alert.
    
    Raises ValueError if required fields are missing or timestamp is invalid.
    """
    required = ["alert_id", "service", "alert_type", "message", "severity", "timestamp"]

    for field in required:
        if field not in alert or alert[field] is None:
            raise ValueError(f"Missing required field: {field}")

    result = dict(alert)
    result["alert_id"] = str(result["alert_id"]).strip()
    result["service"] = str(result["service"]).strip().lower()
    result["alert_type"] = str(result["alert_type"]).strip().lower()
    result["severity"] = str(result["severity"]).strip().lower()
    result["message"] = str(result["message"]).strip()

    # Validate allowed severity
    if result["severity"] not in {"critical", "high", "medium", "low", "info"}:
        result["severity"] = "medium"

    # Validate ISO timestamp
    ts_str = str(result["timestamp"]).strip()
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        result["timestamp"] = dt.isoformat()
    except Exception as e:
        raise ValueError(f"Invalid timestamp format '{result['timestamp']}': {e}")

    # Optional fields
    result["source"] = str(result["source"]).strip() if result.get("source") else None
    result["host"] = str(result["host"]).strip() if result.get("host") else None
    result["metadata"] = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}

    return result

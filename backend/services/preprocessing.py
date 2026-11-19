
from datetime import datetime, timezone

def normalize_alert(alert: dict) -> dict:
    required = ["alert_id", "service", "alert_type", "message", "severity", "timestamp"]

    for field in required:
        if field not in alert:
            raise ValueError(f"Missing required field: {field}")

    result = alert.copy()
    result["service"] = str(result["service"]).strip().lower()
    result["severity"] = str(result["severity"]).strip().lower()

    datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))

    return result

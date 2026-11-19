
from backend.services.preprocessing import normalize_alert

def process_alerts(alerts: list):
    processed = []
    seen = set()

    for alert in alerts:
        clean_alert = normalize_alert(alert)

        if clean_alert["alert_id"] not in seen:
            processed.append(clean_alert)
            seen.add(clean_alert["alert_id"])

    return processed

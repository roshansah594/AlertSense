
from fastapi import APIRouter, HTTPException
from backend.services.ingestion import process_alerts

router = APIRouter()

alerts_store = []
incidents_store = []

@router.post("/alerts")
def receive_alerts(alerts: list[dict]):
    try:
        processed = process_alerts(alerts)

        existing_ids = {a["alert_id"] for a in alerts_store}
        new_alerts = [
            a for a in processed
            if a["alert_id"] not in existing_ids
        ]

        alerts_store.extend(new_alerts)

        return {
            "message": "Alerts processed successfully",
            "received": len(alerts),
            "stored": len(new_alerts)
        }
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

@router.get("/alerts")
def get_alerts():
    return alerts_store

@router.post("/incidents/analyze")
def analyze_incidents():
    if not alerts_store:
        return {"message": "No alerts available", "incidents": []}

    return {
        "message": "Alerts are ready for agent investigation",
        "alert_count": len(alerts_store),
        "incidents": incidents_store,
        "integration_status": "Pending LangGraph agent integration"
    }

@router.get("/incidents")
def get_incidents():
    return incidents_store

@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    for incident in incidents_store:
        if incident["incident_id"] == incident_id:
            return incident

    raise HTTPException(status_code=404, detail="Incident not found")

@router.get("/analytics")
def get_analytics():
    severity_counts = {}

    for alert in alerts_store:
        severity = alert["severity"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return {
        "total_alerts": len(alerts_store),
        "total_incidents": len(incidents_store),
        "severity_distribution": severity_counts
    }

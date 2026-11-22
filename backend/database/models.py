"""AlertSense Database Models & Query Operations.

Provides data access and persistence functions for Alerts, Incidents,
Actions, and Analytics with parameterized queries and transaction guarantees.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from backend.database.connection import get_connection

logger = logging.getLogger(__name__)


def save_alerts(alerts: List[Dict[str, Any]]) -> int:
    """Insert or ignore a list of normalized alerts into the database.
    
    Returns the count of newly inserted alerts.
    """
    if not alerts or not isinstance(alerts, list):
        return 0

    conn = get_connection()
    inserted_count = 0
    try:
        with conn:
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                aid = alert.get("alert_id")
                if not aid:
                    continue
                
                metadata = alert.get("metadata")
                meta_str = json.dumps(metadata) if isinstance(metadata, dict) else "{}"
                cur = conn.execute("""
                    INSERT OR IGNORE INTO alerts (
                        alert_id, service, alert_type, message, severity, timestamp, source, host, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(aid).strip(),
                    str(alert.get("service", "")).lower().strip(),
                    str(alert.get("alert_type", "")).lower().strip(),
                    str(alert.get("message", "")).strip(),
                    str(alert.get("severity", "medium")).lower().strip(),
                    str(alert.get("timestamp", "")).strip(),
                    str(alert.get("source")).strip() if alert.get("source") else None,
                    str(alert.get("host")).strip() if alert.get("host") else None,
                    meta_str
                ))
                if cur.rowcount > 0:
                    inserted_count += 1
        return inserted_count
    finally:
        conn.close()


def get_all_alerts(
    severity: Optional[str] = None,
    service: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve all alerts from the database, sorted chronologically."""
    conn = get_connection()
    try:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: List[Any] = []
        if severity and isinstance(severity, str) and severity.lower() != "all":
            query += " AND LOWER(severity) = ?"
            params.append(severity.lower().strip())
        if service and isinstance(service, str) and service.lower() != "all":
            query += " AND LOWER(service) = ?"
            params.append(service.lower().strip())
        query += " ORDER BY timestamp ASC"

        rows = conn.execute(query, params).fetchall()
        alerts = []
        for r in rows:
            alert_dict = dict(r)
            if alert_dict.get("metadata"):
                try:
                    alert_dict["metadata"] = json.loads(alert_dict["metadata"])
                except Exception:
                    pass
            alerts.append(alert_dict)
        return alerts
    finally:
        conn.close()


def save_incident_analysis(analysis_result: Dict[str, Any]) -> None:
    """Persist analyzed incidents, associated alerts, and recommendations."""
    if not analysis_result or not isinstance(analysis_result, dict):
        return

    # Ensure all alerts from the analysis are persisted before linking
    if analysis_result.get("alerts"):
        save_alerts(analysis_result["alerts"])

    candidate_incidents = analysis_result.get("candidate_incidents", [])
    rca_findings = {f.get("incident_id"): f for f in analysis_result.get("root_cause_findings", []) if isinstance(f, dict)}
    sev_assessments = {s.get("incident_id"): s for s in analysis_result.get("severity_assessments", []) if isinstance(s, dict)}
    incident_report = analysis_result.get("incident_report", {})
    if not isinstance(incident_report, dict):
        incident_report = {}
    reports_by_id = {rep.get("incident_id"): rep for rep in incident_report.get("incidents", []) if isinstance(rep, dict)}
    workflow_status = analysis_result.get("workflow_status", "completed")
    needs_review = 1 if analysis_result.get("needs_human_review") else 0

    conn = get_connection()
    try:
        with conn:
            for grp in candidate_incidents:
                if not isinstance(grp, dict):
                    continue
                iid = grp.get("group_id")
                if not iid:
                    continue

                rca = rca_findings.get(iid, {})
                primary_hyp = rca.get("primary_hypothesis", {}) if isinstance(rca, dict) else {}
                if not isinstance(primary_hyp, dict):
                    primary_hyp = {}
                sev = sev_assessments.get(iid, {}) if isinstance(sev_assessments, dict) else {}
                if not isinstance(sev, dict):
                    sev = {}
                rep = reports_by_id.get(iid, {}) if isinstance(reports_by_id, dict) else {}
                if not isinstance(rep, dict):
                    rep = {}

                title = rep.get("title") or f"Incident on {', '.join(grp.get('affected_services', []))}"
                raw_sev = str(sev.get("severity_level", "P3")).upper()
                if "P1" in raw_sev:
                    sev_level = "P1"
                elif "P2" in raw_sev:
                    sev_level = "P2"
                elif "P3" in raw_sev:
                    sev_level = "P3"
                elif "P4" in raw_sev:
                    sev_level = "P4"
                else:
                    sev_level = "P3"

                try:
                    sev_score = float(sev.get("severity_score", 5.0))
                except (ValueError, TypeError):
                    sev_score = 5.0

                rationale_list = sev.get("rationale", [])
                if isinstance(rationale_list, list):
                    sev_reasoning = " ".join(str(r) for r in rationale_list)
                else:
                    sev_reasoning = str(rationale_list or "")
                urgency = sev.get("urgency", "MODERATE")
                root_cause_service = primary_hyp.get("root_cause_service") or (grp.get("affected_services", ["unknown"])[0])
                root_cause_hyp = primary_hyp.get("explanation") or primary_hyp.get("title", "")
                confidence_label = primary_hyp.get("confidence_label", "medium")
                conf_score_map = {"high": 0.90, "medium": 0.75, "low": 0.50, "unconfirmed": 0.30}
                confidence_score = conf_score_map.get(str(confidence_label).lower(), 0.75)
                exec_summary = rep.get("executive_summary") or primary_hyp.get("explanation", "")
                summary = exec_summary
                
                time_range = grp.get("time_range", {}) if isinstance(grp.get("time_range"), dict) else {}
                start_time = time_range.get("start_time", "")
                end_time = time_range.get("end_time", "")
                affected_svcs_str = json.dumps(grp.get("affected_services", []))

                # Upsert incident
                conn.execute("""
                    INSERT INTO incidents (
                        incident_id, title, severity_level, severity_score, severity_reasoning,
                        urgency, root_cause_service, root_cause_hypothesis, confidence_score,
                        confidence_label, summary, executive_summary,
                        workflow_status, needs_human_review, start_time, end_time, affected_services
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(incident_id) DO UPDATE SET
                        title = excluded.title,
                        severity_level = excluded.severity_level,
                        severity_score = excluded.severity_score,
                        severity_reasoning = excluded.severity_reasoning,
                        urgency = excluded.urgency,
                        root_cause_service = excluded.root_cause_service,
                        root_cause_hypothesis = excluded.root_cause_hypothesis,
                        confidence_score = excluded.confidence_score,
                        confidence_label = excluded.confidence_label,
                        summary = excluded.summary,
                        executive_summary = excluded.executive_summary,
                        workflow_status = excluded.workflow_status,
                        needs_human_review = excluded.needs_human_review,
                        start_time = excluded.start_time,
                        end_time = excluded.end_time,
                        affected_services = excluded.affected_services
                """, (
                    iid, title, sev_level, sev_score, sev_reasoning,
                    urgency, root_cause_service, root_cause_hyp, confidence_score,
                    confidence_label, summary, exec_summary,
                    workflow_status, needs_review, start_time, end_time, affected_svcs_str
                ))

                # Refresh linked alerts for this incident to avoid stale/duplicate associations
                conn.execute("DELETE FROM incident_alerts WHERE incident_id = ?", (iid,))

                for aid in grp.get("alert_ids", []):
                    if aid:
                        conn.execute("""
                            INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, is_duplicate)
                            VALUES (?, ?, 0)
                        """, (iid, aid))

                for dup_id in grp.get("duplicate_alert_ids", []):
                    if dup_id:
                        conn.execute("""
                            INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, is_duplicate)
                            VALUES (?, ?, 1)
                        """, (iid, dup_id))

                # Actions
                conn.execute("DELETE FROM incident_actions WHERE incident_id = ?", (iid,))
                actions = rep.get("recommended_actions", [])
                if isinstance(actions, list):
                    for act in actions:
                        if isinstance(act, dict):
                            conn.execute("""
                                INSERT INTO incident_actions (incident_id, action_text, category, is_safe_readonly)
                                VALUES (?, ?, ?, ?)
                            """, (
                                iid,
                                act.get("action", ""),
                                act.get("category", "Diagnostic Investigation"),
                                1 if act.get("is_safe_readonly", True) else 0
                            ))
    finally:
        conn.close()


def get_all_incidents() -> List[Dict[str, Any]]:
    """Retrieve all recorded incidents with their linked alerts and actions."""
    conn = get_connection()
    try:
        inc_rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
        incidents = []
        for r in inc_rows:
            inc = dict(r)
            iid = inc["incident_id"]

            # Parse affected services
            try:
                inc["affected_services"] = json.loads(inc["affected_services"])
            except Exception:
                inc["affected_services"] = []

            # Retrieve associated alerts
            alert_rows = conn.execute("""
                SELECT a.*, ia.is_duplicate 
                FROM alerts a
                JOIN incident_alerts ia ON a.alert_id = ia.alert_id
                WHERE ia.incident_id = ?
                ORDER BY a.timestamp ASC
            """, (iid,)).fetchall()
            inc_alerts = []
            for ar in alert_rows:
                ad = dict(ar)
                if ad.get("metadata") and isinstance(ad["metadata"], str):
                    try:
                        ad["metadata"] = json.loads(ad["metadata"])
                    except Exception:
                        pass
                inc_alerts.append(ad)
            inc["alerts"] = inc_alerts
            inc["alert_ids"] = [ar["alert_id"] for ar in alert_rows if not ar["is_duplicate"]]
            inc["duplicate_alert_ids"] = [ar["alert_id"] for ar in alert_rows if ar["is_duplicate"]]

            # Retrieve actions
            action_rows = conn.execute("""
                SELECT action_text, category, is_safe_readonly
                FROM incident_actions
                WHERE incident_id = ?
            """, (iid,)).fetchall()
            inc["recommended_actions"] = [
                {
                    "action": ar["action_text"],
                    "category": ar["category"],
                    "is_safe_readonly": bool(ar["is_safe_readonly"])
                }
                for ar in action_rows
            ]

            incidents.append(inc)
        return incidents
    finally:
        conn.close()


def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full details of a specific incident."""
    all_inc = get_all_incidents()
    for inc in all_inc:
        if inc["incident_id"] == incident_id:
            return inc
    return None


def get_analytics_summary() -> Dict[str, Any]:
    """Calculate aggregated analytics across all stored alerts and incidents."""
    conn = get_connection()
    try:
        total_alerts_row = conn.execute("SELECT COUNT(*) as cnt FROM alerts").fetchone()
        total_alerts = total_alerts_row["cnt"] if total_alerts_row else 0

        total_incidents_row = conn.execute("SELECT COUNT(*) as cnt FROM incidents").fetchone()
        total_incidents = total_incidents_row["cnt"] if total_incidents_row else 0

        # Severity distribution of alerts
        sev_rows = conn.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM alerts
            GROUP BY severity
        """).fetchall()
        severity_dist = {r["severity"]: r["cnt"] for r in sev_rows}

        # Incident severity distribution
        inc_sev_rows = conn.execute("""
            SELECT severity_level, COUNT(*) as cnt
            FROM incidents
            GROUP BY severity_level
        """).fetchall()
        inc_sev_dist = {r["severity_level"]: r["cnt"] for r in inc_sev_rows}

        # Noise reduction ratio
        noise_red = round((total_alerts - total_incidents) / total_alerts, 3) if total_alerts > 0 else 0.0

        return {
            "total_alerts": total_alerts,
            "total_incidents": total_incidents,
            "noise_reduction_ratio": noise_red,
            "severity_distribution": severity_dist,
            "incident_severity_distribution": inc_sev_dist
        }
    finally:
        conn.close()


def clear_all_data() -> None:
    """Clear all alerts and incidents (for resetting testing state)."""
    conn = get_connection()
    try:
        with conn:
            conn.execute("DELETE FROM incident_actions;")
            conn.execute("DELETE FROM incident_alerts;")
            conn.execute("DELETE FROM incidents;")
            conn.execute("DELETE FROM alerts;")
    finally:
        conn.close()

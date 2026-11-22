"""Alert Ingestion Service.

Processes, sanitizes, and deduplicates inbound streams of monitoring alerts.
Also provides utility to load benchmark synthetic alerts from datasets/.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from backend.services.preprocessing import normalize_alert

logger = logging.getLogger(__name__)
DATASETS_DIR = Path(__file__).resolve().parent.parent.parent / "datasets"


def process_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Process and normalize a list of raw alerts, deduplicating identical alert IDs."""
    if not isinstance(alerts, list):
        raise ValueError(f"Alerts payload must be a list, got {type(alerts).__name__}")

    processed = []
    seen = set()

    for alert in alerts:
        clean_alert = normalize_alert(alert)
        aid = clean_alert["alert_id"]

        if aid not in seen:
            processed.append(clean_alert)
            seen.add(aid)

    return processed


def load_default_dependencies() -> Dict[str, Any]:
    """Load default service dependencies topology from datasets/service_dependencies.json."""
    dep_file = DATASETS_DIR / "service_dependencies.json"
    if dep_file.exists():
        with open(dep_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"services": []}


def load_sample_alerts() -> List[Dict[str, Any]]:
    """Load benchmark synthetic alerts from datasets/sample_alerts.json."""
    alerts_file = DATASETS_DIR / "sample_alerts.json"
    if alerts_file.exists():
        with open(alerts_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

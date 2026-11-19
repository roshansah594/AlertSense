"""Unit and Benchmark Metric Assertions for AlertSense.

Verifies the Section 11 Evaluation Metrics from the Member 1 Playbook:
- Precision >= 95%
- Recall == 100%
- False Merge Rate == 0.0%
- Noise Reduction >= 60%
- Evidence Grounding == 100%
"""

import json
from pathlib import Path
import pytest

from scripts.evaluate_system import evaluate_alert_sense

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"


@pytest.fixture
def benchmark_data():
    with open(DATASETS_DIR / "sample_alerts.json", "r", encoding="utf-8") as f:
        alerts = json.load(f)
    with open(DATASETS_DIR / "service_dependencies.json", "r", encoding="utf-8") as f:
        dependencies = json.load(f)
    return alerts, dependencies


def test_correlation_evaluation_metrics(benchmark_data):
    """Correlation engine must achieve high precision, recall, and zero false merges."""
    alerts, dependencies = benchmark_data
    metrics = evaluate_alert_sense(alerts, dependencies)
    corr = metrics["correlation_metrics"]

    assert corr["precision"] >= 0.95, f"Precision too low: {corr['precision']}"
    assert corr["recall"] == 1.0, f"Recall must be 100%: {corr['recall']}"
    assert corr["f1_score"] >= 0.95, f"F1-score too low: {corr['f1_score']}"
    assert corr["false_merge_rate"] == 0.0, f"False merge rate must be 0.0: {corr['false_merge_rate']}"
    assert corr["noise_reduction_ratio"] >= 0.60, f"Noise reduction must be >= 60%: {corr['noise_reduction_ratio']}"


def test_root_cause_grounding_metrics(benchmark_data):
    """Root cause hypotheses must achieve 100% evidence grounding without hallucination."""
    alerts, dependencies = benchmark_data
    metrics = evaluate_alert_sense(alerts, dependencies)
    rca = metrics["root_cause_metrics"]

    assert rca["primary_cause_accuracy"] == "100%"
    assert rca["evidence_grounding_ratio"] == 1.0
    assert rca["hallucinated_citations_count"] == 0

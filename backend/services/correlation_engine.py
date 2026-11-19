"""AlertSense Correlation Engine.

Deterministic, explainable alert correlation module for infrastructure monitoring.
Implements multi-signal scoring:
    C = 0.30 * Time + 0.30 * Dependency + 0.25 * Symptom + 0.15 * Context/Severity

Features:
- ISO 8601 timestamp parsing with timezone support and out-of-order handling.
- Deterministic deduplication with original alert traceability.
- NetworkX topology-aware dependency distance calculation.
- Causal symptom relationship and taxonomy matching.
- Critical safeguards: prevents merging solely on time proximity or severity.
- Explainable reasons for every correlation decision.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Models / Data Contracts (Shared with Member 2)
# ---------------------------------------------------------------------------

class NormalizedAlert(BaseModel):
    """Data contract for a normalized monitoring alert."""
    alert_id: str = Field(..., description="Unique alert identifier")
    service: str = Field(..., description="Affected service name (lowercase)")
    alert_type: str = Field(..., description="Alert classification type (e.g., high_cpu, query_timeout)")
    message: str = Field(..., description="Human-readable alert message")
    severity: str = Field(..., description="Severity level: critical, high, medium, low, or info")
    timestamp: str = Field(..., description="ISO 8601 formatted timestamp string")
    source: Optional[str] = Field(None, description="Monitoring origin (e.g., prometheus, datadog)")
    host: Optional[str] = Field(None, description="Host / node / instance name")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Arbitrary extra telemetry")

    @field_validator("service", "alert_type", mode="before")
    @classmethod
    def normalize_strings(cls, v: Any) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("service and alert_type must be non-empty strings")
        return v.strip().lower()

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: Any) -> str:
        if not isinstance(v, str):
            raise ValueError("severity must be a string")
        v_clean = v.strip().lower()
        allowed = {"critical", "high", "medium", "low", "info"}
        if v_clean not in allowed:
            # Default to medium if non-standard
            return "medium"
        return v_clean

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_timestamp(cls, v: Any) -> str:
        if isinstance(v, datetime):
            return v.isoformat()
        if not isinstance(v, str) or not v.strip():
            raise ValueError("timestamp must be a valid ISO 8601 string or datetime")
        return v.strip()


class PairwiseScoreBreakdown(BaseModel):
    """Detailed score breakdown for correlation between two alerts."""
    alert_id_a: str
    alert_id_b: str
    time_score: float = Field(..., ge=0.0, le=1.0)
    dependency_score: float = Field(..., ge=0.0, le=1.0)
    symptom_score: float = Field(..., ge=0.0, le=1.0)
    context_score: float = Field(..., ge=0.0, le=1.0)
    total_score: float = Field(..., ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)


class CorrelationGroup(BaseModel):
    """A candidate incident cluster formed by correlated alerts."""
    group_id: str
    alert_ids: List[str]
    duplicate_alert_ids: List[str] = Field(default_factory=list)
    score: float = Field(..., ge=0.0, le=1.0)
    threshold: float
    time_range: Dict[str, Any]
    affected_services: List[str]
    reasons: List[str]
    pairwise_correlations: List[PairwiseScoreBreakdown] = Field(default_factory=list)
    is_singleton: bool = False


class CorrelationResult(BaseModel):
    """Complete output of the correlation engine."""
    groups: List[CorrelationGroup]
    total_input_alerts: int
    deduplicated_alerts_count: int
    candidate_incidents_count: int
    noise_reduction_ratio: float


# ---------------------------------------------------------------------------
# Symptom Taxonomy & Causal Patterns
# ---------------------------------------------------------------------------

SYMPTOM_TAXONOMY: Dict[str, Set[str]] = {
    "resource_exhaustion": {
        "high_cpu", "cpu_spike", "high_memory", "memory_leak", "oom", "out_of_memory",
        "connection_pool_exhausted", "thread_pool_exhausted", "max_connections_reached",
        "resource_limit"
    },
    "latency_timeout": {
        "query_timeout", "timeout", "slow_query", "http_latency", "latency_spike",
        "response_time_high", "service_degradation", "dependency_timeout"
    },
    "error_rate": {
        "http_500_spike", "http_5xx", "500_internal_error", "crash", "unhandled_exception",
        "service_unavailable", "http_502_bad_gateway", "http_503_service_unavailable",
        "http_504_gateway_timeout"
    },
    "network_infra": {
        "network_packet_loss", "packet_loss", "connection_refused", "dns_resolution_failed",
        "socket_error", "network_unreachable", "socket_closed", "tcp_timeout"
    },
    "storage": {
        "disk_space_warning", "disk_full", "read_only_filesystem", "io_saturation",
        "disk_io_high", "storage_failure"
    }
}

# Cross-category causal patterns: Upstream cause -> Downstream symptom
CAUSAL_SYMPTOM_PAIRS: Set[Tuple[str, str]] = {
    ("resource_exhaustion", "latency_timeout"),
    ("resource_exhaustion", "error_rate"),
    ("network_infra", "latency_timeout"),
    ("network_infra", "error_rate"),
    ("storage", "error_rate"),
    ("storage", "latency_timeout")
}


def classify_symptom(alert_type: str, message: str) -> str:
    """Classify an alert into a canonical symptom category based on type and text."""
    clean_type = alert_type.lower()
    clean_msg = message.lower()

    for category, keywords in SYMPTOM_TAXONOMY.items():
        for kw in keywords:
            if kw in clean_type or kw.replace("_", " ") in clean_msg:
                return category

    # Fallback keyword checks in message
    if any(k in clean_msg for k in ["cpu", "memory", "ram", "pool", "threads"]):
        return "resource_exhaustion"
    if any(k in clean_msg for k in ["timeout", "slow", "latency", "delay"]):
        return "latency_timeout"
    if any(k in clean_msg for k in ["500", "502", "503", "504", "exception", "error rate"]):
        return "error_rate"
    if any(k in clean_msg for k in ["network", "packet", "dns", "refused", "reset by peer"]):
        return "network_infra"
    if any(k in clean_msg for k in ["disk", "storage", "mount", "filesystem"]):
        return "storage"

    return "general"


# ---------------------------------------------------------------------------
# Timestamp Normalization & Parsing
# ---------------------------------------------------------------------------

def parse_iso_timestamp(ts: str) -> datetime:
    """Parse an ISO 8601 timestamp string into a UTC datetime.
    
    Handles strings ending with 'Z', offset notation (+00:00), or naive timestamps.
    """
    ts_clean = ts.strip()
    if ts_clean.endswith("Z"):
        ts_clean = ts_clean[:-1] + "+00:00"
    
    dt = datetime.fromisoformat(ts_clean)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate_alerts(
    alerts: List[NormalizedAlert],
    duplicate_window_seconds: int = 60
) -> Tuple[List[NormalizedAlert], Dict[str, List[str]]]:
    """Identify duplicate alerts within a short window.
    
    Deduplication rules:
    - Same service, alert_type, and host (if present) within duplicate_window_seconds
    - Or exact duplicate alert_id
    
    Returns:
        (canonical_alerts, mapping_of_canonical_id_to_duplicate_ids)
    """
    sorted_alerts = sorted(alerts, key=lambda a: parse_iso_timestamp(a.timestamp))
    canonical_alerts: List[NormalizedAlert] = []
    duplicate_map: Dict[str, List[str]] = {}
    seen_ids: Set[str] = set()

    for alert in sorted_alerts:
        if alert.alert_id in seen_ids:
            continue

        alert_dt = parse_iso_timestamp(alert.timestamp)
        matched_canonical: Optional[NormalizedAlert] = None

        for canonical in canonical_alerts:
            canon_dt = parse_iso_timestamp(canonical.timestamp)
            delta_sec = abs((alert_dt - canon_dt).total_seconds())

            # Check if alert is an identical symptom on the same service/host within the window
            if delta_sec <= duplicate_window_seconds:
                same_service = alert.service == canonical.service
                same_type = alert.alert_type == canonical.alert_type
                same_host = (alert.host == canonical.host) if (alert.host and canonical.host) else True

                if same_service and same_type and same_host:
                    matched_canonical = canonical
                    break

        if matched_canonical:
            duplicate_map[matched_canonical.alert_id].append(alert.alert_id)
            seen_ids.add(alert.alert_id)
        else:
            canonical_alerts.append(alert)
            duplicate_map[alert.alert_id] = []
            seen_ids.add(alert.alert_id)

    return canonical_alerts, duplicate_map


# ---------------------------------------------------------------------------
# Dependency Graph Analysis (NetworkX)
# ---------------------------------------------------------------------------

def build_dependency_graph(dependencies_data: Any) -> nx.DiGraph:
    """Build a directed graph from the service dependencies contract.
    
    Contract format:
    {
      "services": [
        {"service": "api", "depends_on": ["database", "cache"]}
      ]
    }
    An edge (u, v) indicates that u depends on v (u is downstream, v is upstream).
    """
    graph = nx.DiGraph()

    if not dependencies_data:
        return graph

    services_list = []
    if isinstance(dependencies_data, dict):
        services_list = dependencies_data.get("services", [])
    elif isinstance(dependencies_data, list):
        services_list = dependencies_data

    for entry in services_list:
        if not isinstance(entry, dict):
            continue
        service = str(entry.get("service", "")).strip().lower()
        if not service:
            continue
        graph.add_node(service)
        depends_on = entry.get("depends_on", [])
        for upstream in depends_on:
            upstream_svc = str(upstream).strip().lower()
            if upstream_svc:
                graph.add_node(upstream_svc)
                # Edge: service -> upstream
                graph.add_edge(service, upstream_svc)

    return graph


def calculate_dependency_similarity(
    graph: nx.DiGraph,
    service_a: str,
    service_b: str
) -> Tuple[float, Optional[str]]:
    """Calculate dependency similarity score between two services.
    
    Returns:
        (score, explanation_str)
    """
    if service_a == service_b:
        return 1.0, f"Both alerts originate from the exact same service '{service_a}'."

    if not graph.has_node(service_a) or not graph.has_node(service_b):
        return 0.0, None

    # Check direct or transitive dependency: a depends on b
    if nx.has_path(graph, service_a, service_b):
        dist = nx.shortest_path_length(graph, service_a, service_b)
        if dist == 1:
            return 1.0, f"Direct dependency: '{service_a}' depends directly on '{service_b}'."
        elif dist == 2:
            return 0.7, f"Transitive dependency (2 hops): '{service_a}' depends on '{service_b}'."
        else:
            return 0.4, f"Multi-hop dependency ({dist} hops) from '{service_a}' to '{service_b}'."

    # Check reverse dependency: b depends on a
    if nx.has_path(graph, service_b, service_a):
        dist = nx.shortest_path_length(graph, service_b, service_a)
        if dist == 1:
            return 1.0, f"Direct dependency: '{service_b}' depends directly on '{service_a}'."
        elif dist == 2:
            return 0.7, f"Transitive dependency (2 hops): '{service_b}' depends on '{service_a}'."
        else:
            return 0.4, f"Multi-hop dependency ({dist} hops) from '{service_b}' to '{service_a}'."

    # Sibling check: both services depend on a common upstream service
    a_successors = set(graph.successors(service_a))
    b_successors = set(graph.successors(service_b))
    shared_deps = a_successors.intersection(b_successors)
    if shared_deps:
        common = ", ".join(sorted(shared_deps))
        return 0.35, f"Architecture siblings: both '{service_a}' and '{service_b}' depend on '{common}'."

    return 0.0, None


# ---------------------------------------------------------------------------
# Signal Scoring Algorithms
# ---------------------------------------------------------------------------

def calculate_time_similarity(
    t1: datetime,
    t2: datetime,
    window_seconds: int = 300
) -> Tuple[float, Optional[str]]:
    """Compute normalized time proximity score in [0.0, 1.0]."""
    delta_seconds = abs((t1 - t2).total_seconds())
    if delta_seconds > window_seconds:
        return 0.0, None

    score = max(0.0, 1.0 - (delta_seconds / window_seconds))
    explanation = f"Alerts occurred within {int(delta_seconds)}s of each other (window: {window_seconds}s)."
    return round(score, 3), explanation


def calculate_symptom_similarity(
    alert_a: NormalizedAlert,
    alert_b: NormalizedAlert,
    dep_score: float
) -> Tuple[float, Optional[str]]:
    """Calculate symptom similarity based on alert types, messages, and causal patterns."""
    cat_a = classify_symptom(alert_a.alert_type, alert_a.message)
    cat_b = classify_symptom(alert_b.alert_type, alert_b.message)

    # Identical alert type
    if alert_a.alert_type == alert_b.alert_type:
        return 1.0, f"Identical alert type '{alert_a.alert_type}' across both alerts."

    # Same symptom category
    if cat_a == cat_b and cat_a != "general":
        return 0.85, f"Shared symptom classification '{cat_a}' ({alert_a.alert_type} & {alert_b.alert_type})."

    # Known causal propagation pattern across connected services
    # Requires direct dependency connection (dep_score >= 0.7) or shared infrastructure host
    has_direct_conn = (dep_score >= 0.7) or bool(alert_a.host and alert_b.host and alert_a.host == alert_b.host)
    if has_direct_conn and ((cat_a, cat_b) in CAUSAL_SYMPTOM_PAIRS or (cat_b, cat_a) in CAUSAL_SYMPTOM_PAIRS):
        return 0.75, f"Causal symptom match: '{cat_a}' propagates into '{cat_b}' across connected services."

    # Jaccard keyword overlap on messages
    words_a = set(re.findall(r"\w+", alert_a.message.lower())) - {"the", "a", "an", "is", "on", "in", "to", "for", "of"}
    words_b = set(re.findall(r"\w+", alert_b.message.lower())) - {"the", "a", "an", "is", "on", "in", "to", "for", "of"}
    intersection = words_a.intersection(words_b)
    union = words_a.union(words_b)

    if union:
        jaccard = len(intersection) / len(union)
        if jaccard >= 0.25:
            shared_terms = ", ".join(list(intersection)[:3])
            return round(min(0.65, jaccard + 0.3), 3), f"Corroborating text/token similarity ({shared_terms})."

    return 0.0, None


def calculate_context_similarity(
    alert_a: NormalizedAlert,
    alert_b: NormalizedAlert
) -> Tuple[float, Optional[str]]:
    """Calculate context similarity (shared host, monitoring source, severity alignment)."""
    score = 0.0
    reasons = []

    # Shared Host / Infrastructure node
    if alert_a.host and alert_b.host and alert_a.host == alert_b.host:
        score += 0.60
        reasons.append(f"Shared infrastructure host '{alert_a.host}'.")

    # Shared Monitoring Source
    if alert_a.source and alert_b.source and alert_a.source == alert_b.source:
        score += 0.20
        reasons.append(f"Common telemetry source '{alert_a.source}'.")

    # Severity compatibility
    high_sevs = {"critical", "high"}
    if alert_a.severity in high_sevs and alert_b.severity in high_sevs:
        score += 0.20
        reasons.append(f"Aligned high severity levels ({alert_a.severity}/{alert_b.severity}).")
    elif alert_a.severity == alert_b.severity:
        score += 0.10

    score = min(1.0, score)
    explanation = "; ".join(reasons) if reasons else None
    return round(score, 3), explanation


# ---------------------------------------------------------------------------
# Pairwise Scoring & Safeguard Enforcement
# ---------------------------------------------------------------------------

def calculate_pairwise_correlation(
    alert_a: NormalizedAlert,
    alert_b: NormalizedAlert,
    dep_graph: nx.DiGraph,
    time_window_seconds: int = 300,
    weights: Optional[Dict[str, float]] = None
) -> PairwiseScoreBreakdown:
    """Calculate overall correlation between two alerts using weighted signals.
    
    Formula:
        C = 0.30T + 0.30D + 0.25S + 0.15A
    
    Safeguards:
    - Time proximity alone MUST NOT merge alerts if there is NO dependency connection,
      NO symptom relationship, and NO shared infrastructure context.
    - Severity alone MUST NOT merge alerts.
    """
    if weights is None:
        weights = {"time": 0.30, "dependency": 0.30, "symptom": 0.25, "context": 0.15}

    t1 = parse_iso_timestamp(alert_a.timestamp)
    t2 = parse_iso_timestamp(alert_b.timestamp)

    # 1. Time proximity
    t_score, t_reason = calculate_time_similarity(t1, t2, time_window_seconds)

    # 2. Service dependency
    d_score, d_reason = calculate_dependency_similarity(dep_graph, alert_a.service, alert_b.service)

    # 3. Symptom similarity
    s_score, s_reason = calculate_symptom_similarity(alert_a, alert_b, d_score)

    # 4. Context similarity
    a_score, a_reason = calculate_context_similarity(alert_a, alert_b)

    reasons: List[str] = []
    if t_reason:
        reasons.append(t_reason)
    if d_reason:
        reasons.append(d_reason)
    if s_reason:
        reasons.append(s_reason)
    if a_reason:
        reasons.append(a_reason)

    # CRITICAL SAFEGUARD:
    # If no structural dependency (d_score == 0) AND no symptom similarity (s_score == 0)
    # AND no shared host, time proximity alone or high severity alone must NOT cause a link.
    shared_host = bool(alert_a.host and alert_b.host and alert_a.host == alert_b.host)
    if d_score == 0.0 and s_score == 0.0 and not shared_host:
        total_score = 0.0
        reasons = ["Safeguard: Alerts occurred around the same time but lack architectural, symptom, or host links."]
    else:
        # Renormalization if dependency graph has no nodes for both services
        w_t = weights["time"]
        w_d = weights["dependency"]
        w_s = weights["symptom"]
        w_a = weights["context"]

        total_score = (w_t * t_score) + (w_d * d_score) + (w_s * s_score) + (w_a * a_score)

    total_score = round(min(1.0, max(0.0, total_score)), 3)

    return PairwiseScoreBreakdown(
        alert_id_a=alert_a.alert_id,
        alert_id_b=alert_b.alert_id,
        time_score=t_score,
        dependency_score=d_score,
        symptom_score=s_score,
        context_score=a_score,
        total_score=total_score,
        reasons=reasons
    )


# ---------------------------------------------------------------------------
# Correlation Engine Main API
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Production-grade deterministic alert correlation engine."""

    def __init__(
        self,
        time_window_seconds: int = 300,
        correlation_threshold: float = 0.55,
        duplicate_window_seconds: int = 60
    ):
        self.time_window_seconds = time_window_seconds
        self.correlation_threshold = correlation_threshold
        self.duplicate_window_seconds = duplicate_window_seconds

    def correlate(
        self,
        alerts_data: List[Dict[str, Any]],
        service_dependencies: Any
    ) -> CorrelationResult:
        """Execute deterministic correlation on normalized alerts.
        
        Args:
            alerts_data: List of raw/normalized alert dictionaries.
            service_dependencies: Dependency topology dictionary or list.
            
        Returns:
            CorrelationResult with candidate incident groups, deduplication, and metrics.
        """
        if not alerts_data:
            return CorrelationResult(
                groups=[],
                total_input_alerts=0,
                deduplicated_alerts_count=0,
                candidate_incidents_count=0,
                noise_reduction_ratio=0.0
            )

        # 1. Validate & Normalize Alerts
        normalized_alerts: List[NormalizedAlert] = []
        for raw in alerts_data:
            try:
                normalized_alerts.append(NormalizedAlert(**raw))
            except Exception as e:
                logger.warning(f"Skipping malformed alert: {raw}. Error: {e}")

        total_input_count = len(normalized_alerts)
        if total_input_count == 0:
            return CorrelationResult(
                groups=[],
                total_input_alerts=0,
                deduplicated_alerts_count=0,
                candidate_incidents_count=0,
                noise_reduction_ratio=0.0
            )

        # 2. Deduplicate
        canonical_alerts, duplicate_map = deduplicate_alerts(
            normalized_alerts,
            duplicate_window_seconds=self.duplicate_window_seconds
        )
        dedup_count = len(canonical_alerts)

        # 3. Build Dependency Graph
        dep_graph = build_dependency_graph(service_dependencies)

        # 4. Handle Single Alert Case
        if dedup_count == 1:
            only_alert = canonical_alerts[0]
            dt = parse_iso_timestamp(only_alert.timestamp)
            dups = duplicate_map.get(only_alert.alert_id, [])
            group = CorrelationGroup(
                group_id="GRP-001",
                alert_ids=[only_alert.alert_id],
                duplicate_alert_ids=dups,
                score=1.0,
                threshold=self.correlation_threshold,
                time_range={
                    "start_time": dt.isoformat(),
                    "end_time": dt.isoformat(),
                    "duration_seconds": 0
                },
                affected_services=[only_alert.service],
                reasons=[f"Isolated alert on service '{only_alert.service}' with no related active alerts."],
                pairwise_correlations=[],
                is_singleton=True
            )
            return CorrelationResult(
                groups=[group],
                total_input_alerts=total_input_count,
                deduplicated_alerts_count=dedup_count,
                candidate_incidents_count=1,
                noise_reduction_ratio=round((total_input_count - 1) / total_input_count, 3)
            )

        # 5. Pairwise Scoring & Graph Construction
        cluster_graph = nx.Graph()
        for alert in canonical_alerts:
            cluster_graph.add_node(alert.alert_id, alert=alert)

        all_pairwise_scores: Dict[Tuple[str, str], PairwiseScoreBreakdown] = {}

        for i in range(dedup_count):
            for j in range(i + 1, dedup_count):
                alert_a = canonical_alerts[i]
                alert_b = canonical_alerts[j]

                breakdown = calculate_pairwise_correlation(
                    alert_a=alert_a,
                    alert_b=alert_b,
                    dep_graph=dep_graph,
                    time_window_seconds=self.time_window_seconds
                )
                all_pairwise_scores[(alert_a.alert_id, alert_b.alert_id)] = breakdown
                all_pairwise_scores[(alert_b.alert_id, alert_a.alert_id)] = breakdown

                if breakdown.total_score >= self.correlation_threshold:
                    cluster_graph.add_edge(
                        alert_a.alert_id,
                        alert_b.alert_id,
                        weight=breakdown.total_score,
                        breakdown=breakdown
                    )

        # 6. Extract Connected Components as Candidate Incidents
        groups: List[CorrelationGroup] = []
        alert_lookup = {a.alert_id: a for a in canonical_alerts}
        group_idx = 1

        # Sort connected components by earliest alert timestamp
        components = list(nx.connected_components(cluster_graph))
        
        def component_earliest_dt(comp: Set[str]) -> datetime:
            return min(parse_iso_timestamp(alert_lookup[aid].timestamp) for aid in comp)

        components.sort(key=component_earliest_dt)

        for comp in components:
            comp_alert_ids = sorted(list(comp))
            comp_alerts = [alert_lookup[aid] for aid in comp_alert_ids]
            
            # Aggregate duplicate IDs
            comp_duplicates: List[str] = []
            for aid in comp_alert_ids:
                comp_duplicates.extend(duplicate_map.get(aid, []))

            # Timestamps
            dts = [parse_iso_timestamp(a.timestamp) for a in comp_alerts]
            start_dt = min(dts)
            end_dt = max(dts)
            duration_sec = int((end_dt - start_dt).total_seconds())

            # Affected services
            affected_services = sorted(list({a.service for a in comp_alerts}))

            # Pairwise scores & reasons within this component
            comp_pairwise: List[PairwiseScoreBreakdown] = []
            group_reasons_set: Set[str] = set()
            scores_list: List[float] = []

            for i in range(len(comp_alert_ids)):
                for j in range(i + 1, len(comp_alert_ids)):
                    aid_a = comp_alert_ids[i]
                    aid_b = comp_alert_ids[j]
                    if (aid_a, aid_b) in all_pairwise_scores:
                        pw = all_pairwise_scores[(aid_a, aid_b)]
                        if pw.total_score >= self.correlation_threshold:
                            comp_pairwise.append(pw)
                            scores_list.append(pw.total_score)
                            for r in pw.reasons:
                                group_reasons_set.add(r)

            is_singleton = len(comp_alert_ids) == 1
            if is_singleton:
                group_score = 1.0
                group_reasons = [f"Isolated alert on service '{affected_services[0]}'; no correlation criteria met."]
            else:
                group_score = round(sum(scores_list) / len(scores_list), 3) if scores_list else self.correlation_threshold
                group_reasons = sorted(list(group_reasons_set))

            group = CorrelationGroup(
                group_id=f"GRP-{group_idx:03d}",
                alert_ids=comp_alert_ids,
                duplicate_alert_ids=comp_duplicates,
                score=group_score,
                threshold=self.correlation_threshold,
                time_range={
                    "start_time": start_dt.isoformat(),
                    "end_time": end_dt.isoformat(),
                    "duration_seconds": duration_sec
                },
                affected_services=affected_services,
                reasons=group_reasons,
                pairwise_correlations=comp_pairwise,
                is_singleton=is_singleton
            )
            groups.append(group)
            group_idx += 1

        incident_count = len(groups)
        noise_reduction = round((total_input_count - incident_count) / total_input_count, 3) if total_input_count > 0 else 0.0

        return CorrelationResult(
            groups=groups,
            total_input_alerts=total_input_count,
            deduplicated_alerts_count=dedup_count,
            candidate_incidents_count=incident_count,
            noise_reduction_ratio=noise_reduction
        )


# ---------------------------------------------------------------------------
# Functional Entrypoint
# ---------------------------------------------------------------------------

def correlate_alerts(
    alerts: List[Dict[str, Any]],
    service_dependencies: Any,
    time_window_seconds: int = 300,
    correlation_threshold: float = 0.55,
    duplicate_window_seconds: int = 60
) -> Dict[str, Any]:
    """Pure-Python functional entrypoint for AlertSense alert correlation.
    
    Can be directly called by Member 2 or wrapped by the Correlation Agent.
    """
    engine = CorrelationEngine(
        time_window_seconds=time_window_seconds,
        correlation_threshold=correlation_threshold,
        duplicate_window_seconds=duplicate_window_seconds
    )
    result = engine.correlate(alerts, service_dependencies)
    return result.model_dump()

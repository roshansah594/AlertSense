"""Correlation Agent Module.

Acts as Agent Stage 1 in the AlertSense multi-agent architecture.
Wraps the deterministic correlation engine into a structured, validated agent
that can be invoked independently or as a LangGraph node.

Responsibilities:
- Accepts normalized monitoring alerts and service dependency topology.
- Executes multi-signal correlation and deduplication.
- Identifies candidate incident clusters and flags ungrouped/singleton alerts.
- Computes group-level uncertainty and explainability metadata.
- Prepares state updates for downstream Root Cause and Severity agents.
- Enforces core principle: groups are candidate incidents, NOT proven causes.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from backend.services.correlation_engine import (
    CorrelationEngine,
    CorrelationResult,
    CorrelationGroup,
    build_dependency_graph
)

logger = logging.getLogger(__name__)


class CorrelationAgent:
    """Agent responsible for clustering normalized alerts into candidate incidents."""

    def __init__(
        self,
        time_window_seconds: int = 300,
        correlation_threshold: float = 0.55,
        duplicate_window_seconds: int = 60
    ):
        self.time_window_seconds = time_window_seconds
        self.correlation_threshold = correlation_threshold
        self.duplicate_window_seconds = duplicate_window_seconds
        self.engine = CorrelationEngine(
            time_window_seconds=self.time_window_seconds,
            correlation_threshold=self.correlation_threshold,
            duplicate_window_seconds=self.duplicate_window_seconds
        )

    def run(
        self,
        alerts: List[Dict[str, Any]],
        service_dependencies: Any,
        config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute correlation agent analysis.

        Args:
            alerts: List of normalized alert dictionaries.
            service_dependencies: Service dependency definition.
            config: Optional override configuration.

        Returns:
            Structured dictionary with correlation_groups, ungrouped_alerts,
            and execution metadata.
        """
        # Apply runtime config overrides if provided
        time_window = self.time_window_seconds
        threshold = self.correlation_threshold
        dup_window = self.duplicate_window_seconds

        if config:
            time_window = config.get("time_window_seconds", time_window)
            threshold = config.get("correlation_threshold", threshold)
            dup_window = config.get("duplicate_window_seconds", dup_window)

        # Update engine parameters if overridden
        engine = CorrelationEngine(
            time_window_seconds=time_window,
            correlation_threshold=threshold,
            duplicate_window_seconds=dup_window
        )

        try:
            raw_result: CorrelationResult = engine.correlate(alerts, service_dependencies)
        except Exception as e:
            logger.error(f"CorrelationEngine failed during execution: {e}", exc_info=True)
            return {
                "correlation_groups": [],
                "ungrouped_alerts": [a.get("alert_id", "unknown") for a in alerts] if alerts else [],
                "metadata": {
                    "agent": "CorrelationAgent",
                    "status": "error",
                    "error_message": str(e),
                    "total_input_alerts": len(alerts) if alerts else 0,
                    "candidate_incidents_count": 0,
                    "noise_reduction_ratio": 0.0
                }
            }

        # Check known services in dependency graph for uncertainty assessment
        dep_graph = build_dependency_graph(service_dependencies)
        known_services = set(dep_graph.nodes)

        formatted_groups: List[Dict[str, Any]] = []
        ungrouped_alert_ids: List[str] = []

        for group in raw_result.groups:
            group_dict = group.model_dump()

            # Assess uncertainties for this group
            uncertainties: List[str] = []
            unmapped = [s for s in group.affected_services if s not in known_services]
            if unmapped:
                uncertainties.append(
                    f"Dependency topology missing for services: {', '.join(unmapped)}. "
                    "Correlation relied primarily on time, symptoms, and host context."
                )

            if group.score < (threshold + 0.10) and not group.is_singleton:
                uncertainties.append(
                    f"Correlation score ({group.score:.3f}) is close to threshold ({threshold:.2f}); "
                    "loose relationship requires operational verification."
                )

            group_dict["uncertainty_notes"] = uncertainties
            # Explicit safeguard statement: candidate cluster, not causal proof
            group_dict["causality_disclaimer"] = (
                "Candidate incident cluster based on temporal, architectural, and symptom correlation. "
                "Causation is not proven at this stage and must be evaluated by Root Cause Analysis."
            )

            if group.is_singleton:
                ungrouped_alert_ids.extend(group.alert_ids)
                group_dict["is_candidate_incident"] = False
            else:
                group_dict["is_candidate_incident"] = True

            formatted_groups.append(group_dict)

        # Every group (clustered or singleton) is a candidate incident for investigation
        candidate_incidents = formatted_groups
        multi_alert_incidents = [g for g in formatted_groups if not g["is_singleton"]]

        return {
            "correlation_groups": formatted_groups,
            "candidate_incidents": candidate_incidents,
            "multi_alert_incidents": multi_alert_incidents,
            "ungrouped_alert_ids": ungrouped_alert_ids,
            "metadata": {
                "agent": "CorrelationAgent",
                "status": "success",
                "total_input_alerts": raw_result.total_input_alerts,
                "deduplicated_alerts_count": raw_result.deduplicated_alerts_count,
                "candidate_incidents_count": len(candidate_incidents),
                "multi_alert_incidents_count": len(multi_alert_incidents),
                "total_groups_count": len(formatted_groups),
                "noise_reduction_ratio": raw_result.noise_reduction_ratio,
                "time_window_seconds": time_window,
                "correlation_threshold": threshold
            }
        }


# ---------------------------------------------------------------------------
# LangGraph Node Entrypoint
# ---------------------------------------------------------------------------

def correlation_agent_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """LangGraph node execution function.
    
    Accepts workflow state and returns updated correlation fields.
    Does NOT mutate previous state fields.
    """
    alerts = state.get("alerts", [])
    service_dependencies = state.get("service_dependencies", {})
    config = state.get("config", {})

    agent = CorrelationAgent(
        time_window_seconds=config.get("time_window_seconds", 300),
        correlation_threshold=config.get("correlation_threshold", 0.55),
        duplicate_window_seconds=config.get("duplicate_window_seconds", 60)
    )

    result = agent.run(alerts, service_dependencies, config=config)

    errors = list(state.get("errors", []))
    if result["metadata"]["status"] == "error":
        errors.append({
            "stage": "correlation_agent",
            "message": result["metadata"].get("error_message", "Unknown correlation error")
        })

    return {
        "correlation_groups": result["correlation_groups"],
        "candidate_incidents": result["candidate_incidents"],
        "ungrouped_alert_ids": result["ungrouped_alert_ids"],
        "correlation_metadata": result["metadata"],
        "errors": errors
    }

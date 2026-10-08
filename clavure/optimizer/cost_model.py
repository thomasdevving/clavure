"""Optimization objectives.

The cost model ONLY ranks candidates that already satisfy every hard
constraint. It is never used to trade a security violation against
convenience: an invalid candidate is rejected regardless of its cost.

All weights are explicit and reported with each result so that "optimal" is
always qualified by "within this action space and this cost model".
"""

from __future__ import annotations

from pydantic import BaseModel

WEIGHTS: dict[str, float] = {
    # Minimize policy changes.
    "policy_objects_changed": 10.0,
    "rule_edits": 2.0,
    # Minimize affected workloads (rollout blast radius and behaviour change).
    "workloads_reconfigured": 2.0,
    "workloads_connectivity_changed": 3.0,
    # Minimize unnecessary connectivity removal / business disruption.
    "connectivity_removed": 8.0,
    "business_disruption": 5.0,
    # Minimize operational complexity.
    "complexity": 1.0,
    # Prefer enforcement at the protected resource: a destination-side
    # control protects the asset against every current and future source,
    # a source-side control only constrains one source.
    "source_side_only_blocks": 4.0,
}

CRITICALITY_WEIGHT = {"high": 3.0, "medium": 2.0, "low": 1.0}


class CostBreakdown(BaseModel):
    policy_objects_changed: int = 0
    rule_edits: int = 0
    workloads_reconfigured: int = 0
    workloads_connectivity_changed: int = 0
    connectivity_removed: int = 0
    business_disruption: float = 0.0
    complexity: int = 0
    source_side_only_blocks: int = 0
    total: float = 0.0

    def compute_total(self) -> CostBreakdown:
        self.total = round(sum(WEIGHTS[k] * float(getattr(self, k)) for k in WEIGHTS), 3)
        return self

"""Bounded, deterministic remediation search.

Algorithm
---------
1. Generate candidate actions from evidence (:mod:`clavure.optimizer.candidates`).
2. Enumerate every conflict-free combination of 1..k actions (k from the
   requirements file, default 3), in a fixed order.
3. For each combination, build the resulting policy set and re-run the *full*
   reachability model, then check the hard constraints:

   H1 every forbidden constraint is SATISFIED (blocked on every port)
   H2 every required constraint is SATISFIED (every backend reachable)
   H3 every generated/modified NetworkPolicy is structurally valid
   H4 no constraint connection is UNKNOWN/UNSUPPORTED (no silent acceptance)
   H5 no new connectivity: nothing that was not ALLOWED becomes possibly
      allowed, except connections that are explicitly required
   H6 no reliance on contradicted model predictions (runtime evidence)

4. Valid candidates are ranked by the cost model; ties are broken by the
   number of actions and then lexicographically by action keys.

Because the enumeration is exhaustive within the bound, the selected plan is
optimal *within the generated action space, the bound k and the cost model*.
It is not claimed to be globally optimal over all possible policy rewrites.
"""

from __future__ import annotations

import time
from itertools import combinations

from pydantic import BaseModel, Field

from clavure.core.analysis import Analysis, analyze_inventory
from clavure.core.constraints import ConstraintStatus
from clavure.core.models import Inventory, Verdict
from clavure.core.policy_parser import validate_policy_document
from clavure.core.security_graph import EdgeClass, classify_connections
from clavure.optimizer.actions import Action, ActionError, PlanState, conflicts
from clavure.optimizer.candidates import generate_actions
from clavure.optimizer.cost_model import CRITICALITY_WEIGHT, WEIGHTS, CostBreakdown

EdgeKey = tuple[str, str, int, str]


class HardConstraintResult(BaseModel):
    name: str
    passed: bool
    detail: str = ""


class PolicyChange(BaseModel):
    policy: str
    change: str  # added | modified | deleted
    origin: str  # manifest | live-cluster | generated
    source: str | None = None
    manifest: dict | None = None


class CandidatePlan(BaseModel):
    id: str = ""
    actions: list[dict]
    action_keys: list[str]
    coarse: bool
    valid: bool
    minimal: bool = False
    hard_constraints: list[HardConstraintResult]
    rejection_reasons: list[str]
    cost: CostBreakdown
    constraint_status: dict[str, str]
    connectivity_removed: list[str]
    connectivity_added: list[str]
    changes: list[PolicyChange]
    out_of_band: list[str] = Field(default_factory=list)

    def summary(self) -> str:
        return " + ".join(a["description"] for a in self.actions)


class Evidence(BaseModel):
    """Runtime evidence the optimizer must respect (H6).

    ``contradicted`` holds connections that the model predicted as BLOCKED
    but that runtime verification observed as ALLOWED, and that re-ingestion
    of the live state did not explain. The model's BLOCKED verdict for those
    edges is not trusted, whatever the candidate.
    """

    contradicted: list[EdgeKey] = Field(default_factory=list)


class OptimizationResult(BaseModel):
    selected: CandidatePlan | None
    candidates: list[CandidatePlan]
    actions_generated: list[dict]
    stats: dict
    weights: dict[str, float]
    limitations: list[str]


LIMITATIONS = [
    "Optimality holds only within the generated action space, the combination bound and the "
    "declared cost model; other rewrites of the policies are not considered.",
    "Connectivity is modelled at L3/L4 for TCP; application-level authorization is not modelled.",
    "Costs for business disruption are estimates derived from declared workload criticality, "
    "not from observed traffic.",
    "Selectors are generated from the labels of workloads present in the analysed manifests; "
    "future pods with matching labels will also match.",
]


def _edge_str(k: EdgeKey) -> str:
    return f"{k[0]} -> {k[1]}:{k[2]}/{k[3]}"


def _changes(base: Inventory, policies: dict) -> list[PolicyChange]:
    out = []
    for pid in sorted(set(base.policies) | set(policies)):
        before, after = base.policies.get(pid), policies.get(pid)
        if before is None:
            out.append(
                PolicyChange(
                    policy=pid, change="added", origin="generated", manifest=after.to_k8s()
                )
            )
        elif after is None:
            out.append(
                PolicyChange(
                    policy=pid,
                    change="deleted",
                    origin=before.source.origin,
                    source=before.source.describe(),
                )
            )
        elif before.to_k8s() != after.to_k8s():
            out.append(
                PolicyChange(
                    policy=pid,
                    change="modified",
                    origin=before.source.origin,
                    source=before.source.describe(),
                    manifest=after.to_k8s(),
                )
            )
    return out


def evaluate_plan(
    baseline: Analysis, actions: list[Action], evidence: Evidence | None = None
) -> tuple[CandidatePlan, Analysis | None]:
    base_inv = baseline.inventory
    st = PlanState.of(base_inv)
    try:
        for act in actions:
            act.apply(st)
    except (ActionError, KeyError, IndexError) as exc:
        return _invalid(actions, [f"action not applicable: {exc}"]), None
    policies = st.result()
    changes = _changes(base_inv, policies)
    hard: list[HardConstraintResult] = []

    # H3 — structural validity of every generated or modified object.
    errors = []
    for ch in changes:
        if ch.manifest is not None:
            errors += [f"{ch.policy}: {e}" for e in validate_policy_document(ch.manifest)]
    hard.append(
        HardConstraintResult(
            name="H3 valid configuration", passed=not errors, detail="; ".join(errors)
        )
    )
    if errors:
        return _finish(
            actions, hard, CostBreakdown().compute_total(), {}, [], [], changes, st
        ), None

    after = analyze_inventory(base_inv.with_policies(policies), baseline.scenario)
    contradicted = set(map(tuple, (evidence.contradicted if evidence else [])))

    status = {e.constraint_id: str(e.status) for e in after.evaluations}
    h6_hits = []
    for ev in after.evaluations:
        if ev.kind == "forbidden":
            for c in ev.connections:
                if c.key in contradicted and c.verdict == Verdict.BLOCKED:
                    h6_hits.append(_edge_str(c.key))
                    status[ev.constraint_id] = str(ConstraintStatus.UNDECIDED)

    kinds = {e.constraint_id: e.kind for e in after.evaluations}
    unsatisfied = [cid for cid, s in status.items() if s != ConstraintStatus.SATISFIED]
    forb_bad = [cid for cid in unsatisfied if kinds[cid] == "forbidden"]
    req_bad = [cid for cid in unsatisfied if kinds[cid] == "required"]
    hard.append(
        HardConstraintResult(
            name="H1 forbidden connections blocked",
            passed=not forb_bad,
            detail=", ".join(f"{c}={status[c]}" for c in forb_bad),
        )
    )
    hard.append(
        HardConstraintResult(
            name="H2 required connections preserved",
            passed=not req_bad,
            detail=", ".join(f"{c}={status[c]}" for c in req_bad),
        )
    )
    undecided = [cid for cid, s in status.items() if s == ConstraintStatus.UNDECIDED]
    hard.append(
        HardConstraintResult(
            name="H4 no undecidable constraint", passed=not undecided, detail=", ".join(undecided)
        )
    )

    # H5 — monotonicity: nothing new becomes (possibly) reachable, except
    # explicitly required connections.
    before_v = {c.key: c.verdict for c in baseline.matrix}
    required_keys = {
        k
        for k, (cls, _) in classify_connections(after.evaluations).items()
        if cls == EdgeClass.REQUIRED
    }
    added, removed = [], []
    for c in after.matrix:
        prev = before_v.get(c.key, Verdict.BLOCKED)
        newly_possible = prev == Verdict.BLOCKED and c.verdict != Verdict.BLOCKED
        newly_definite = (
            prev in (Verdict.UNKNOWN, Verdict.UNSUPPORTED) and c.verdict == Verdict.ALLOWED
        )
        if (newly_possible or newly_definite) and c.key not in required_keys:
            added.append(c.key)
        if prev == Verdict.ALLOWED and c.verdict != Verdict.ALLOWED:
            removed.append(c.key)
    hard.append(
        HardConstraintResult(
            name="H5 no new connectivity",
            passed=not added,
            detail=", ".join(_edge_str(k) for k in added),
        )
    )
    hard.append(
        HardConstraintResult(
            name="H6 consistent with runtime evidence",
            passed=not h6_hits,
            detail=("model BLOCKED contradicted at runtime: " + ", ".join(h6_hits))
            if h6_hits
            else "",
        )
    )

    cost = _cost(baseline, after, st, changes, removed)
    return _finish(actions, hard, cost, status, removed, added, changes, st), after


def _cost(baseline: Analysis, after: Analysis, st: PlanState, changes, removed) -> CostBreakdown:
    inv = baseline.inventory
    scenario = baseline.scenario
    classes = classify_connections(baseline.evaluations)
    reconfigured: set[str] = set()
    for ch in changes:
        for pol in (inv.policies.get(ch.policy), st.result().get(ch.policy)):
            if pol is None:
                continue
            for w in inv.workloads.values():
                if w.namespace == pol.namespace and pol.pod_selector.matches(w.labels_dict()):
                    reconfigured.add(w.id)
    before_allowed = {c.key for c in baseline.matrix if c.verdict == Verdict.ALLOWED}
    after_allowed = {c.key for c in after.matrix if c.verdict == Verdict.ALLOWED}
    changed_edges = before_allowed ^ after_allowed
    conn_changed = {k[0] for k in changed_edges} | {k[1] for k in changed_edges}
    collateral = [
        k for k in removed if classes.get(k, (EdgeClass.UNDECLARED, []))[0] != EdgeClass.FORBIDDEN
    ]
    disruption = 0.0
    for k in collateral:
        crit = max(
            CRITICALITY_WEIGHT[scenario.criticality(k[0])],
            CRITICALITY_WEIGHT[scenario.criticality(k[1])],
        )
        required = classes.get(k, (EdgeClass.UNDECLARED, []))[0] == EdgeClass.REQUIRED
        disruption += crit * (10.0 if required else 1.0)
    source_only = 0
    after_by_key = {c.key: c for c in after.matrix}
    for c in baseline.matrix:
        if classes.get(c.key, (None,))[0] == EdgeClass.FORBIDDEN and c.verdict == Verdict.ALLOWED:
            a = after_by_key.get(c.key)
            if (
                a is not None
                and a.verdict == Verdict.BLOCKED
                and a.ingress.verdict == Verdict.ALLOWED
            ):
                source_only += 1
    complexity = st.complexity + 5 * sum(1 for ch in changes if ch.origin == "live-cluster")
    return CostBreakdown(
        policy_objects_changed=len(changes),
        rule_edits=st.edits,
        workloads_reconfigured=len(reconfigured),
        workloads_connectivity_changed=len(conn_changed),
        connectivity_removed=len(collateral),
        business_disruption=disruption,
        complexity=complexity,
        source_side_only_blocks=source_only,
    ).compute_total()


def _invalid(actions: list[Action], reasons: list[str]) -> CandidatePlan:
    return CandidatePlan(
        actions=[a.record() for a in actions],
        action_keys=[a.key() for a in actions],
        coarse=any(a.coarse for a in actions),
        valid=False,
        hard_constraints=[
            HardConstraintResult(name="applicable", passed=False, detail="; ".join(reasons))
        ],
        rejection_reasons=reasons,
        cost=CostBreakdown().compute_total(),
        constraint_status={},
        connectivity_removed=[],
        connectivity_added=[],
        changes=[],
    )


def _finish(actions, hard, cost, status, removed, added, changes, st) -> CandidatePlan:
    reasons = [f"{h.name}: {h.detail}" if h.detail else h.name for h in hard if not h.passed]
    return CandidatePlan(
        actions=[a.record() for a in actions],
        action_keys=[a.key() for a in actions],
        coarse=any(a.coarse for a in actions),
        valid=not reasons,
        hard_constraints=hard,
        rejection_reasons=reasons,
        cost=cost,
        constraint_status=status,
        connectivity_removed=[_edge_str(k) for k in removed],
        connectivity_added=[_edge_str(k) for k in added],
        changes=changes,
        out_of_band=[
            f"{ch.change} {ch.policy} (exists only in the live cluster)"
            for ch in changes
            if ch.origin == "live-cluster"
        ],
    )


def optimize(
    baseline: Analysis,
    *,
    max_actions: int | None = None,
    evidence: Evidence | None = None,
    budget: int = 20000,
) -> OptimizationResult:
    t0 = time.monotonic()
    k = max_actions or baseline.scenario.max_actions_per_plan
    actions = generate_actions(baseline)
    plans: list[CandidatePlan] = []
    evaluated = skipped_conflicts = 0
    exhausted = False
    valid_sets: list[frozenset[str]] = []
    for size in range(1, k + 1):
        for combo in combinations(actions, size):
            if any(conflicts(a, b) for a, b in combinations(combo, 2)):
                skipped_conflicts += 1
                continue
            if evaluated >= budget:
                exhausted = True
                break
            plan, _ = evaluate_plan(baseline, list(combo), evidence)
            evaluated += 1
            keys = frozenset(plan.action_keys)
            if plan.valid:
                plan.minimal = not any(v < keys for v in valid_sets)
                valid_sets.append(keys)
            plans.append(plan)
        if exhausted:
            break

    valid = sorted(
        (p for p in plans if p.valid), key=lambda p: (p.cost.total, len(p.actions), p.action_keys)
    )
    invalid = sorted(
        (p for p in plans if not p.valid), key=lambda p: (len(p.actions), p.action_keys)
    )
    ordered = valid + invalid
    for i, p in enumerate(ordered, start=1):
        p.id = f"P-{i:03d}"
    limitations = list(LIMITATIONS)
    if exhausted:
        limitations.insert(
            0, f"Search budget of {budget} evaluations exhausted; optimality is NOT guaranteed."
        )
    if not actions:
        limitations.insert(0, "No candidate actions could be derived from the evidence.")
    return OptimizationResult(
        selected=valid[0] if valid else None,
        candidates=ordered,
        actions_generated=[a.record() for a in actions],
        stats={
            "actions_generated": len(actions),
            "max_actions_per_plan": k,
            "combinations_evaluated": evaluated,
            "combinations_skipped_conflicting": skipped_conflicts,
            "valid_plans": len(valid),
            "invalid_plans": len(invalid),
            "budget_exhausted": exhausted,
            "search_seconds": round(time.monotonic() - t0, 3),
        },
        weights=dict(WEIGHTS),
        limitations=limitations,
    )

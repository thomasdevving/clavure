"""Milestone 2 acceptance and optimizer behaviour."""

from __future__ import annotations

import shutil

import yaml

from clavure.core.analysis import analyze, analyze_inventory
from clavure.core.constraints import ConstraintStatus
from clavure.core.drift import ingest_live_policies
from clavure.core.models import Direction, PolicyPeer, PolicyRule
from clavure.core.policy_parser import parse_manifests
from clavure.optimizer.actions import (
    BlockAllIngress,
    DeletePolicy,
    PlanState,
    QuarantineWorkload,
    RuleDraft,
)
from clavure.optimizer.solver import Evidence, evaluate_plan, optimize
from tests.conftest import BASE, CHANGE, DRIFT


def vulnerable(scenario):
    return analyze([BASE, CHANGE], scenario)


def test_selected_plan_blocks_forbidden_and_preserves_required(scenario):
    a = vulnerable(scenario)
    r = optimize(a)
    assert r.selected is not None and r.selected.valid
    assert all(h.passed for h in r.selected.hard_constraints)
    assert all(s == ConstraintStatus.SATISFIED for s in r.selected.constraint_status.values())
    assert r.selected.connectivity_added == []
    assert r.selected.connectivity_removed == [
        "clavure-analytics/reporting -> clavure-data/finance-db:5432/TCP"
    ]
    assert r.selected.minimal


def test_coarse_candidates_are_computed_and_rejected(scenario):
    r = optimize(vulnerable(scenario))
    single = {p.action_keys[0].split("(")[0]: p for p in r.candidates if len(p.actions) == 1}
    quarantine = single[QuarantineWorkload.kind]
    block_ingress = single[BlockAllIngress.kind]
    assert not quarantine.valid and not block_ingress.valid
    # Security objective met, business objective violated.
    assert quarantine.constraint_status["FORBID-REPORTING-FINANCEDB"] == "SATISFIED"
    assert quarantine.constraint_status["REQ-REPORTING-ORDERS"] == "VIOLATED"
    assert block_ingress.constraint_status["FORBID-REPORTING-FINANCEDB"] == "SATISFIED"
    assert block_ingress.constraint_status["REQ-PAYMENT-FINANCEDB"] == "VIOLATED"
    assert any(r.startswith("H2") for r in block_ingress.rejection_reasons)
    # Cost is still reported for rejected plans, but never makes them valid.
    assert block_ingress.cost.total > 0


def test_valid_plans_ranked_by_cost_and_deterministic(scenario):
    r1 = optimize(vulnerable(scenario))
    r2 = optimize(vulnerable(scenario))
    assert [p.action_keys for p in r1.candidates] == [p.action_keys for p in r2.candidates]
    valid = [p for p in r1.candidates if p.valid]
    assert len(valid) >= 2
    assert [p.cost.total for p in valid] == sorted(p.cost.total for p in valid)
    assert r1.stats["budget_exhausted"] is False


def test_new_connectivity_is_a_hard_violation(scenario):
    a = vulnerable(scenario)
    # Deleting the data namespace default-deny removes egress isolation of the
    # databases: new connectivity appears, so the plan must be rejected (H5).
    plan, _ = evaluate_plan(a, [DeletePolicy(policy="clavure-data/default-deny-all")])
    assert not plan.valid
    h5 = next(h for h in plan.hard_constraints if h.name.startswith("H5"))
    assert not h5.passed and "clavure-data/finance-db" in h5.detail


def test_removing_last_peer_drops_rule_instead_of_allowing_all():
    rd = RuleDraft.of(PolicyRule(peers=(PolicyPeer(),)))
    rd.peers[0] = None
    assert rd.finalize() is None


def test_runtime_contradiction_makes_constraint_undecidable(scenario):
    a = vulnerable(scenario)
    key = ("clavure-analytics/reporting", "clavure-data/finance-db", 5432, "TCP")
    r = optimize(a, evidence=Evidence(contradicted=[key]))
    assert r.selected is None
    assert all(
        any(h.name.startswith("H6") and not h.passed for h in p.hard_constraints)
        for p in r.candidates
        if p.hard_constraints
        and len(p.hard_constraints) > 1
        and p.constraint_status.get("FORBID-REPORTING-FINANCEDB") != "VIOLATED"
    )


def test_drift_changes_the_selected_plan(scenario):
    inv = parse_manifests([BASE, CHANGE])
    clean = optimize(analyze_inventory(inv, scenario)).selected
    live = [p.to_k8s() for p in inv.policies.values()]
    live.append(yaml.safe_load((DRIFT / "legacy-finance-export.yaml").read_text()))
    inv2, drift = ingest_live_policies(inv, live, scenario.test_namespaces)
    assert [f.policies for f in drift] == [["clavure-data/legacy-finance-export"]]
    a2 = analyze_inventory(inv2, scenario)
    replanned = optimize(a2)
    assert replanned.selected is not None
    assert replanned.selected.action_keys != clean.action_keys
    # The plan that was best without drift is now invalid.
    old = next(p for p in replanned.candidates if p.action_keys == clean.action_keys)
    assert not old.valid and old.constraint_status["FORBID-REPORTING-FINANCEDB"] == "VIOLATED"


def test_optimizer_handles_unisolated_side(scenario, tmp_path):
    """Variant: the analytics namespace has no egress isolation at all."""
    shutil.copytree(BASE, tmp_path / "base")
    f = tmp_path / "base" / "22-analytics-policies.yaml"
    f.write_text(
        f.read_text().replace('policyTypes: ["Ingress", "Egress"]', 'policyTypes: ["Ingress"]')
    )
    a = analyze([tmp_path / "base", CHANGE], scenario)
    reporting = a.inventory.workloads["clavure-analytics/reporting"]
    assert a.engine.selecting_policies(
        reporting, Direction.EGRESS
    )  # still selected by change policy
    r = optimize(a)
    assert r.selected is not None and r.selected.valid


def test_budget_exhaustion_is_reported(scenario):
    r = optimize(vulnerable(scenario), budget=3)
    assert r.stats["budget_exhausted"] is True
    assert "NOT guaranteed" in r.limitations[0]


def test_plan_state_tracks_edits(scenario):
    inv = parse_manifests([BASE, CHANGE])
    st = PlanState.of(inv)
    DeletePolicy(policy="clavure-data/allow-analytics-to-data-tier").apply(st)
    assert "clavure-data/allow-analytics-to-data-tier" not in st.result()
    assert st.edits == 1

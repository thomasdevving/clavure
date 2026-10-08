"""Independent model verifier and plan rendering tests."""

from __future__ import annotations

import shutil
from pathlib import Path

from clavure.core.analysis import analyze
from clavure.optimizer.remediation import GENERATED_FILE, render_plan
from clavure.optimizer.solver import evaluate_plan, optimize
from clavure.verification.model_verifier import FAIL, PASS, cross_check, verify
from tests.conftest import BASE, CHANGE, SCENARIO


def outcomes(rep):
    return {c.constraint_id: c.outcome for c in rep.checks}


def test_verifier_detects_exposure_and_missing_feature():
    vuln = verify([BASE, CHANGE], SCENARIO)
    assert vuln.outcome == FAIL
    assert outcomes(vuln)["FORBID-REPORTING-FINANCEDB"] == FAIL
    assert outcomes(vuln)["REQ-REPORTING-ORDERS"] == PASS
    base = verify([BASE], SCENARIO)
    assert outcomes(base)["REQ-REPORTING-ORDERS"] == FAIL
    assert outcomes(base)["FORBID-REPORTING-FINANCEDB"] == PASS


def test_rendered_remediation_passes_independent_verification(scenario, tmp_path):
    a = analyze([BASE, CHANGE], scenario)
    plan = optimize(a).selected
    res = render_plan(plan, [BASE, CHANGE], output_dir=tmp_path / "out")
    assert res.out_of_band == []
    roots = sorted((tmp_path / "out").iterdir())
    rep = verify(roots, SCENARIO, baseline_paths=[BASE, CHANGE])
    a2 = analyze(roots, scenario)
    cross_check(rep, {(c.source, c.destination, c.port): str(c.verdict) for c in a2.matrix})
    assert rep.outcome == PASS, rep.to_dict()
    assert rep.baseline_compared and rep.new_connectivity == []
    assert rep.engine_disagreements == []
    # Originals untouched; comments preserved in the patched copy.
    assert "tier: data" in (CHANGE / "30-reporting-data-access.yaml").read_text()
    patched = next(p for p in res.files_changed if p.endswith("30-reporting-data-access.yaml"))
    text = Path(patched).read_text()
    assert "DELIBERATE, DOCUMENTED MISCONFIGURATION" in text
    assert "# Remediated by Clavure:" in text


def test_in_place_render_with_added_policy(scenario, tmp_path):
    shutil.copytree(BASE, tmp_path / "base")
    shutil.copytree(CHANGE, tmp_path / "change")
    a = analyze([tmp_path / "base", tmp_path / "change"], scenario)
    quarantine = next(
        p
        for p in optimize(a).candidates
        if p.coarse and len(p.actions) == 1 and p.actions[0]["kind"] == "quarantine-workload"
    )
    res = render_plan(quarantine, [tmp_path / "base", tmp_path / "change"])
    assert any(f.endswith(GENERATED_FILE) for f in res.files_changed)
    rep = verify([tmp_path / "base", tmp_path / "change"], SCENARIO)
    assert outcomes(rep)["REQ-REPORTING-ORDERS"] == FAIL  # the verifier agrees it breaks business


def test_cross_check_fails_closed_on_disagreement():
    rep = verify([BASE, CHANGE], SCENARIO)
    a_verdicts = {}
    for c in rep.checks:
        for o in c.observations:
            a_verdicts[(o["source"], o["destination"], o["port"])] = "BLOCKED"
    cross_check(rep, a_verdicts)
    assert rep.engine_disagreements and rep.outcome == FAIL


def test_structural_errors_fail_verification(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: Bad_Name, namespace: x}\n"
        "spec: {podSelector: {}, ingress: [{ports: [{port: 99999}]}]}\n"
    )
    rep = verify([BASE, CHANGE, bad], SCENARIO)
    assert rep.outcome == FAIL
    assert any("out of range" in e for e in rep.structural_errors)


def test_plan_change_records_source_for_patching(scenario):
    a = analyze([BASE, CHANGE], scenario)
    plan = optimize(a).selected
    plan2, _ = evaluate_plan(a, [])
    assert plan2.changes == []
    ch = plan.changes[0]
    assert ch.change == "modified" and ch.origin == "manifest"
    assert ch.source.endswith("30-reporting-data-access.yaml#0")

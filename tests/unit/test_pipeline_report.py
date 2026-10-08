"""Model-only pipeline and report generation (no cluster)."""

from __future__ import annotations

import json

from clavure.pipeline import PipelineOptions, run_pipeline
from tests.conftest import BASE, CHANGE, SCENARIO

EXPECTED = {
    "topology.json",
    "reachability.json",
    "security-findings.json",
    "permission-diff.json",
    "remediation-plan.json",
    "verification-report.json",
    "adversarial-results.json",
    "clavure-report.html",
}


def run(tmp_path):
    return run_pipeline(
        PipelineOptions(scenario=SCENARIO, baseline=[BASE], proposed=[BASE, CHANGE], out=tmp_path)
    )


def test_model_only_pipeline_never_claims_runtime_success(tmp_path):
    report = run(tmp_path)
    assert report["final_verdict"] == "MODEL_VERIFIED_ONLY"
    assert report["runtime"] == []
    assert report["success_criteria"]["runtime_connectivity_checks_pass"] is None
    statuses = {s["stage"]: s["status"] for s in report["stages"]}
    assert statuses["runtime-baseline"] == "SKIPPED"
    assert statuses["model-verify#1"] == "EXECUTED"
    assert {p.name for p in tmp_path.iterdir()} >= EXPECTED


def test_adversarial_artifact_is_honest(tmp_path):
    run(tmp_path)
    adv = json.loads((tmp_path / "adversarial-results.json").read_text())
    assert adv["status"] == "NOT_IMPLEMENTED" and adv["results"] == []


def test_report_reflects_artifacts(tmp_path):
    run(tmp_path)
    html = (tmp_path / "clavure-report.html").read_text()
    assert "MODEL_VERIFIED_ONLY" in html
    assert "Forbidden connectivity permitted" in html
    assert "not executed" in html.lower()
    assert "NOT_IMPLEMENTED" in html
    assert "<script" not in html  # standalone, no external or inline scripts
    plan = json.loads((tmp_path / "remediation-plan.json").read_text())
    assert plan["selected"]["id"] in html
    for c in plan["candidates"]:
        if not c["valid"] and len(c["actions"]) == 1:
            assert c["id"] in html


def test_no_violation_short_circuits(tmp_path, scenario):
    report = run_pipeline(
        PipelineOptions(scenario=SCENARIO, baseline=[BASE], proposed=[BASE], out=tmp_path)
    )
    # The baseline lacks the reporting feature (a required connection is
    # broken), so there is still something to plan for: a missing allow.
    assert report["final_verdict"] in ("MODEL_VERIFIED_ONLY", "NO_VALID_REMEDIATION")
    plan = json.loads((tmp_path / "remediation-plan.json").read_text())
    if plan["selected"]:
        kinds = {a["kind"] for a in plan["selected"]["actions"]}
        assert kinds == {"allow-required"}
        assert plan["selected"]["connectivity_added"] == []  # required edges are not "new"

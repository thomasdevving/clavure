"""Milestone 1 acceptance: the forbidden connection is derived from real manifests."""

from __future__ import annotations

import shutil

from clavure.core.analysis import analyze, write_analysis_artifacts
from clavure.core.constraints import ConstraintStatus
from clavure.core.diff import diff_analyses, expansion_findings
from clavure.core.findings import FindingCategory, Severity
from clavure.core.models import Verdict
from clavure.core.security_graph import EdgeClass
from tests.conftest import BASE, CHANGE


def test_change_introduces_forbidden_reporting_to_finance(scenario):
    a = analyze([BASE, CHANGE], scenario)
    ev = a.evaluation("FORBID-REPORTING-FINANCEDB")
    assert ev.status == ConstraintStatus.VIOLATED
    allowed = [c for c in ev.connections if c.verdict == Verdict.ALLOWED]
    assert [c.port for c in allowed] == [5432]  # metrics port 9187 stays blocked
    conn = allowed[0]
    assert [r.policy for r in conn.egress.permitting] == ["clavure-analytics/reporting-egress-data"]
    assert [r.policy for r in conn.ingress.permitting] == [
        "clavure-data/allow-analytics-to-data-tier"
    ]
    for cid in (
        "REQ-STOREFRONT-ORDERS",
        "REQ-ORDERS-ORDERSDB",
        "REQ-ORDERS-PAYMENT",
        "REQ-PAYMENT-FINANCEDB",
        "REQ-REPORTING-ORDERS",
    ):
        assert a.evaluation(cid).status == ConstraintStatus.SATISFIED
    critical = [f for f in a.findings if f.severity == Severity.CRITICAL]
    assert [f.constraint_id for f in critical] == ["FORBID-REPORTING-FINANCEDB"]
    assert any("allow-analytics-to-data-tier" in r for r in critical[0].permitting_rules)
    assert a.consistency_issues == []


def test_baseline_has_no_exposure_but_lacks_feature(scenario):
    a = analyze([BASE], scenario)
    assert all(
        e.status == ConstraintStatus.SATISFIED for e in a.evaluations if e.kind == "forbidden"
    )
    assert a.evaluation("REQ-REPORTING-ORDERS").status == ConstraintStatus.VIOLATED


def test_result_is_derived_not_hardcoded(scenario, tmp_path):
    """Fixing the selector in a copy of the change removes the finding."""
    shutil.copytree(CHANGE, tmp_path / "change")
    f = tmp_path / "change" / "30-reporting-data-access.yaml"
    f.write_text(f.read_text().replace("      tier: data", "      app: orders-db"))
    a = analyze([BASE, tmp_path / "change"], scenario)
    assert a.evaluation("FORBID-REPORTING-FINANCEDB").status == ConstraintStatus.SATISFIED
    assert a.evaluation("REQ-REPORTING-ORDERS").status == ConstraintStatus.SATISFIED


def test_service_port_maps_to_named_target_port(scenario):
    a = analyze([BASE, CHANGE], scenario)
    ev = a.evaluation("REQ-ORDERS-PAYMENT")  # service port 80 -> targetPort http -> 8080
    assert [c.port for c in ev.connections] == [8080]
    assert ev.connections[0].port_name == "http"


def test_permission_diff_attributes_expansion(scenario):
    before = analyze([BASE], scenario)
    after = analyze([BASE, CHANGE], scenario)
    diff = diff_analyses(before, after)
    assert diff.added_policies == [
        "clavure-analytics/reporting-egress-data",
        "clavure-data/allow-analytics-to-data-tier",
    ]
    exp = {(c.source, c.destination, c.port): c for c in diff.expansions}
    assert (
        exp[("clavure-analytics/reporting", "clavure-data/finance-db", 5432)].classification
        == EdgeClass.FORBIDDEN
    )
    assert (
        exp[("clavure-analytics/reporting", "clavure-data/orders-db", 5432)].classification
        == EdgeClass.REQUIRED
    )
    assert len(exp) == 2
    findings = expansion_findings(diff, after)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(crit) == 1 and crit[0].category == FindingCategory.PERMISSION_EXPANSION
    assert any("allow-analytics-to-data-tier" in r for r in crit[0].permitting_rules)


def test_artifacts_written(scenario, tmp_path):
    a = analyze([BASE, CHANGE], scenario)
    paths = write_analysis_artifacts(a, tmp_path)
    import json

    topo = json.loads(paths["topology"].read_text())
    reach = json.loads(paths["reachability"].read_text())
    fnd = json.loads(paths["findings"].read_text())
    assert reach["summary"]["connections_evaluated"] == len(a.matrix)
    assert fnd["summary"]["constraints_violated"] == 1
    forb = [
        e
        for e in topo["edges"]
        if e.get("classification") == "FORBIDDEN" and e["verdict"] == "ALLOWED"
    ]
    assert len(forb) == 1 and forb[0]["port"] == 5432
    assert topo["requirements_fingerprint"].startswith("sha256:")

"""Runtime verification against a real disposable k3d cluster.

Skipped unless CLAVURE_RUNTIME_TESTS=1. These tests are never replaced by
mocks: if the cluster is unavailable they are reported as skipped, not passed.
"""

from __future__ import annotations

import os

import pytest

from clavure.core.analysis import analyze
from clavure.optimizer.actions import action_from_record
from clavure.optimizer.solver import evaluate_plan, optimize
from clavure.runtime.cluster import ClusterController
from clavure.runtime.environment import TestEnvironment
from clavure.verification.evidence import Observed, Outcome
from clavure.verification.runtime_verifier import RuntimeVerifier
from tests.conftest import BASE, CHANGE

pytestmark = [
    pytest.mark.runtime,
    pytest.mark.skipif(
        os.environ.get("CLAVURE_RUNTIME_TESTS") != "1", reason="set CLAVURE_RUNTIME_TESTS=1"
    ),
]


@pytest.fixture(scope="module")
def env(scenario):
    ctl = ClusterController.from_env(name=os.environ.get("CLAVURE_IT_CLUSTER", "clavure-it"))
    ctl.create()
    e = TestEnvironment(ctl, scenario)
    e.deploy([BASE, CHANGE])
    yield e
    if os.environ.get("CLAVURE_KEEP_CLUSTER") != "1":
        ctl.delete()


def test_exposure_reproduced_then_remediated(env, scenario):
    a = analyze([BASE, CHANGE], scenario)
    rv = RuntimeVerifier(env, scenario)
    pf = rv.preflight()
    assert pf["enforcement_confirmed"], pf["canary"]

    before = rv.verify("baseline", a)
    assert before.check("FORBID-REPORTING-FINANCEDB").observed == Observed.ALLOWED
    assert before.check("FORBID-REPORTING-FINANCEDB").outcome == Outcome.FAIL
    assert before.mismatches == []

    plan = optimize(a).selected
    env.apply_plan(plan)
    try:
        _, model_after = evaluate_plan(a, [action_from_record(x) for x in plan.actions])
        after = rv.verify("remediated", model_after)
        assert after.outcome == Outcome.PASS, [c.model_dump() for c in after.checks]
        assert all(w.outcome == Outcome.PASS for w in after.workflows)
        assert after.mismatches == []
    finally:
        env.revert_plan(plan)

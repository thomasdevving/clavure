"""Trusted-file guard, security gate, and target-branch verification (local git)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from clavure.cli import main as cli
from clavure.verification.gate import evaluate_gate
from clavure.verification.guard import check_trusted_files
from clavure.verification.trusted_ci import run as trusted_run
from tests.conftest import CHANGE, ROOT


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


@pytest.fixture
def repo(tmp_path) -> Path:
    """A throwaway repo: main = baseline (no change); branch dev = with the change."""
    r = tmp_path / "repo"
    r.mkdir()
    for item in (".clavure.yaml", "demo", "clavure", "requirements.lock", "pyproject.toml"):
        src = ROOT / item
        (shutil.copytree if src.is_dir() else shutil.copy2)(src, r / item)
    # The baseline never contains the demo change, even when these tests run on
    # the demonstration branch that adds it.
    shutil.rmtree(r / "demo" / "manifests" / "analytics-access", ignore_errors=True)
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@example.com")
    git(r, "config", "user.name", "t")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "baseline")
    git(r, "checkout", "-q", "-b", "dev")
    # Same layout as the demonstration MR (branch demo/unsafe-networkpolicy).
    shutil.copytree(CHANGE, r / "demo" / "manifests" / "analytics-access")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "reporting data access")
    return r


def test_guard_blocks_automated_change_to_trusted_files():
    files = ["demo/scenario.yaml", "demo/manifests/analytics-access/30-reporting-data-access.yaml"]
    bot = check_trusted_files(
        "x", repo=ROOT, actor="ai-clavure-remediation-acme", branch="feature", files=files
    )
    assert not bot["ok"] and bot["trusted_files_touched"] == ["demo/scenario.yaml"]
    branch = check_trusted_files(
        "x", repo=ROOT, actor="alice", branch="clavure/remediation-7", files=files
    )
    assert not branch["ok"]
    human = check_trusted_files("x", repo=ROOT, actor="alice", branch="feature", files=files)
    assert human["ok"] and human["decision"].startswith("REVIEW")
    manifests_only = check_trusted_files(
        "x",
        repo=ROOT,
        actor="ai-clavure-remediation-acme",
        branch="clavure/remediation-7",
        files=files[1:],
    )
    assert manifests_only["ok"]
    verifier = check_trusted_files(
        "x", repo=ROOT, actor="ai-x", branch="b", files=["clavure/verification/model_verifier.py"]
    )
    assert not verifier["ok"]


def test_flow_sequence_on_local_git(repo, monkeypatch):
    """mr-check -> apply-remediation --verify -> commit -> guard, as the Duo flow does."""
    monkeypatch.chdir(repo)
    assert cli(["mr-check", "--target-ref", "main", "--out", "artifacts/duo"]) == 0
    summary = (repo / "artifacts/duo/summary.md").read_text()
    assert "REMEDIATION_AVAILABLE" in summary
    gate = evaluate_gate(repo / "artifacts/duo")
    assert not gate["pass"]  # the developer's change is blocked
    assert "forbidden connectivity" in gate["blocking_reasons"][0]

    assert (
        cli(["apply-remediation", "--plan", "artifacts/duo/remediation-plan.json", "--verify"]) == 0
    )
    git(repo, "checkout", "-q", "-b", "clavure/remediation-1")
    git(repo, "add", "demo/manifests")
    git(repo, "commit", "-q", "-m", "Clavure remediation")
    g = check_trusted_files(
        "dev", repo=repo, actor="ai-clavure-remediation-acme", branch="clavure/remediation-1"
    )
    assert g["ok"], g
    assert g["changed_files"] == ["demo/manifests/analytics-access/30-reporting-data-access.yaml"]
    # Re-check the remediated branch against the developer branch: clean.
    assert cli(["mr-check", "--target-ref", "dev", "--out", "artifacts/after"]) == 0
    assert evaluate_gate(repo / "artifacts/after")["pass"]


def test_agent_tampering_with_requirements_is_blocked(repo):
    git(repo, "checkout", "-q", "-b", "clavure/remediation-2")
    scen = repo / "demo/scenario.yaml"
    scen.write_text(scen.read_text().replace("FORBID-REPORTING-FINANCEDB", "REMOVED-BY-AGENT"))
    git(repo, "commit", "-q", "-am", "make it pass")
    g = check_trusted_files(
        "dev", repo=repo, actor="ai-clavure-remediation-acme", branch="clavure/remediation-2"
    )
    assert not g["ok"] and g["trusted_files_touched"] == ["demo/scenario.yaml"]


def test_target_branch_verifier_cannot_be_weakened_by_the_mr(repo, tmp_path):
    """The MR replaces the verifier with one that always passes; CI still fails it."""
    git(repo, "checkout", "-q", "dev")
    mv = repo / "clavure/verification/model_verifier.py"
    mv.write_text(
        mv.read_text().replace(
            "    @property\n    def outcome(self) -> str:\n",
            "    @property\n    def outcome(self) -> str:\n        return PASS\n",
        )
    )
    git(repo, "commit", "-q", "-am", "simplify verifier")
    trusted = tmp_path / "trusted"
    git(repo, "worktree", "add", "-q", "--detach", str(trusted), "main")
    # The verdict comes from the trusted tree's requirements and manifest list.
    doc = trusted_run(trusted, repo, tmp_path / "out")
    assert doc["outcome"] == "FAIL"
    fails = {c["constraint_id"] for c in doc["checks"] if c["outcome"] == "FAIL"}
    assert "FORBID-REPORTING-FINANCEDB" in fails
    gate = evaluate_gate(tmp_path / "out")
    assert not gate["pass"]


def test_gate_passes_clean_artifacts(tmp_path):
    (tmp_path / "security-findings.json").write_text(json.dumps({"findings": []}))
    (tmp_path / "guard.json").write_text(json.dumps({"ok": True}))
    assert evaluate_gate(tmp_path)["pass"]
    (tmp_path / "guard.json").write_text(json.dumps({"ok": False, "decision": "BLOCK"}))
    assert not evaluate_gate(tmp_path)["pass"]


def test_apply_remediation_rolls_back_on_failed_verification(tmp_path, monkeypatch, scenario):
    from clavure.core.analysis import analyze
    from clavure.optimizer.solver import optimize
    from clavure.reporting.artifacts import plan_document

    work = tmp_path / "w"
    shutil.copytree(ROOT / "demo", work / "demo")
    shutil.copy2(ROOT / ".clavure.yaml", work / ".clavure.yaml")
    shutil.copytree(CHANGE, work / "demo" / "manifests" / "analytics-access", dirs_exist_ok=True)
    monkeypatch.chdir(work)
    a = analyze([Path("demo/manifests")], scenario)
    r = optimize(a)
    quarantine = next(
        p for p in r.candidates if p.coarse and p.actions[0]["kind"] == "quarantine-workload"
    )
    r.selected = quarantine  # force an invalid plan through the CLI path
    Path("plan.json").write_text(json.dumps(plan_document(a, r), default=str))
    before = {p: p.read_text() for p in Path("demo/manifests").rglob("*.yaml")}
    assert cli(["apply-remediation", "--plan", "plan.json", "--verify"]) == 1
    after = {p: p.read_text() for p in Path("demo/manifests").rglob("*.yaml")}
    assert after == before  # rolled back, including no stray generated file


def test_preexisting_unmet_requirement_does_not_block(repo, tmp_path):
    """On the clean baseline, REQ-REPORTING-ORDERS is not yet implemented."""
    git(repo, "checkout", "-q", "main")
    trusted = tmp_path / "trusted"
    git(repo, "worktree", "add", "-q", "--detach", str(trusted), "main")
    doc = trusted_run(trusted, repo, tmp_path / "out")
    assert doc["outcome"] == "FAIL"  # the verifier still reports the unmet requirement
    assert doc["gate_outcome"] == "PASS"
    assert doc["preexisting_required_failures"] == ["REQ-REPORTING-ORDERS"]
    gate = evaluate_gate(tmp_path / "out")
    assert gate["pass"], gate
    assert any("REQ-REPORTING-ORDERS" in n for n in gate["notes"])


def test_required_regression_blocks(repo, tmp_path):
    """Breaking checkout (a required connection that worked before) is blocked."""
    git(repo, "checkout", "-q", "-b", "break-payments", "main")
    pol = repo / "demo/manifests/base/21-data-policies.yaml"
    pol.write_text(pol.read_text().replace("app: payment-service", "app: nobody"))
    git(repo, "commit", "-q", "-am", "oops")
    trusted = tmp_path / "trusted"
    git(repo, "worktree", "add", "-q", "--detach", str(trusted), "main")
    doc = trusted_run(trusted, repo, tmp_path / "out", baseline_root=trusted)
    assert doc["gate_outcome"] == "FAIL"
    assert doc["required_regressions"] == ["REQ-PAYMENT-FINANCEDB"]


def test_mr_into_unprotected_branch_is_judged_by_default_branch(repo, tmp_path):
    """The target branch can be weakened first; the default branch decides."""
    git(repo, "checkout", "-q", "-b", "weakened", "dev")
    scen = repo / "demo/scenario.yaml"
    before = scen.read_text()
    scen.write_text(
        scen.read_text().replace(
            "port: any\n      description: Analytics", "port: 9187\n      description: Analytics"
        )
    )
    assert scen.read_text() != before
    git(repo, "commit", "-q", "-am", "relax requirement on an unprotected branch")
    trusted = tmp_path / "trusted"
    git(repo, "worktree", "add", "-q", "--detach", str(trusted), "main")
    target = tmp_path / "target"
    git(repo, "worktree", "add", "-q", "--detach", str(target), "weakened")
    doc = trusted_run(trusted, repo, tmp_path / "out", baseline_root=target)
    assert doc["requirements"].startswith(str(trusted))
    assert "FORBID-REPORTING-FINANCEDB" in doc["forbidden_failures"]
    assert doc["gate_outcome"] == "FAIL"

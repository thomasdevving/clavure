"""Verify a merge request with verifier code and requirements from the default branch.

Usage (inside CI, from an installation built from the protected DEFAULT branch):

    python -m clavure.verification.trusted_ci --trusted-root /tmp/trusted \
        --baseline-root /tmp/target --mr-root "$CI_PROJECT_DIR" --out artifacts

Everything that decides the outcome (this module, the independent verifier,
the requirements file, the list of manifest roots) is loaded from
``--trusted-root``: a worktree of the protected default branch. It is NOT the
MR's target branch, which may be unprotected. ``--baseline-root`` (the
target branch) is only the state the change is compared with for the
no-new-connectivity check. Only the manifests under test come from the merge
request, so a merge request cannot make itself pass by editing requirements
or verification code.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from clavure.core.analysis import analyze, write_analysis_artifacts
from clavure.core.constraints import load_scenario
from clavure.verification.guard import load_config
from clavure.verification.model_verifier import FAIL, PASS, cross_check, verify


def run(trusted_root: Path, mr_root: Path, out: Path, baseline_root: Path | None = None) -> dict:
    cfg = load_config(trusted_root / ".clavure.yaml")
    scenario_path = trusted_root / cfg["scenario"]
    base_root = baseline_root or trusted_root
    manifests = [mr_root / p for p in cfg["manifests"] if (mr_root / p).exists()]
    baseline = [base_root / p for p in cfg["manifests"] if (base_root / p).exists()]
    rep = verify(manifests, scenario_path, baseline_paths=baseline)
    a = analyze(manifests, load_scenario(scenario_path))
    cross_check(rep, {(c.source, c.destination, c.port): str(c.verdict) for c in a.matrix})
    base_rep = verify(baseline, scenario_path)
    before = {c.constraint_id: c.outcome for c in base_rep.checks}
    forbidden_failures = [
        c.constraint_id for c in rep.checks if c.kind == "forbidden" and c.outcome != PASS
    ]
    required_regressions = [
        c.constraint_id
        for c in rep.checks
        if c.kind == "required" and c.outcome != PASS and before.get(c.constraint_id) == PASS
    ]
    preexisting = [
        c.constraint_id
        for c in rep.checks
        if c.kind == "required" and c.outcome != PASS and before.get(c.constraint_id) != PASS
    ]
    blocking = bool(
        forbidden_failures
        or required_regressions
        or rep.structural_errors
        or rep.new_connectivity
        or rep.engine_disagreements
    )
    doc = {
        "artifact": "trusted-model-verification",
        "trusted_root": str(trusted_root),
        "baseline_root": str(base_root),
        "requirements": str(scenario_path),
        **rep.to_dict(),
        # The security gate blocks forbidden connectivity and regressions; a
        # required connection that was already unmet before the change is
        # reported but does not block unrelated changes.
        "gate_outcome": FAIL if blocking else PASS,
        "forbidden_failures": forbidden_failures,
        "required_regressions": required_regressions,
        "preexisting_required_failures": preexisting,
        "baseline_checks": before,
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "trusted-model-verification.json").write_text(json.dumps(doc, indent=2) + "\n")
    # Findings for the gate and the report, produced by the trusted engine.
    write_analysis_artifacts(a, out)
    return doc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--trusted-root", required=True, type=Path)
    p.add_argument("--mr-root", required=True, type=Path)
    p.add_argument(
        "--baseline-root", type=Path, help="target branch worktree (default: trusted root)"
    )
    p.add_argument("--out", default=Path("artifacts"), type=Path)
    args = p.parse_args(argv)
    doc = run(args.trusted_root, args.mr_root, args.out, args.baseline_root)
    for c in doc["checks"]:
        print(f"  {c['outcome']:13} {c['constraint_id']}")
    for e in doc["structural_errors"] + doc["new_connectivity"] + doc["engine_disagreements"]:
        print(f"  FAIL {e}")
    for cid in doc["preexisting_required_failures"]:
        print(f"  NOTE {cid} was already unmet before this change (not blocking)")
    print(f"TRUSTED MODEL VERIFICATION: {doc['outcome']}; SECURITY GATE: {doc['gate_outcome']}")
    return 0 if doc["gate_outcome"] == PASS else 1


if __name__ == "__main__":
    sys.exit(main())

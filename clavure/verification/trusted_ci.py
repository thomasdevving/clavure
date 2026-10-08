"""Verify a merge request with verifier code and requirements from the target branch.

Usage (inside CI, from an installation built from the *target* branch):

    python -m clavure.verification.trusted_ci \
        --trusted-root /tmp/trusted --mr-root "$CI_PROJECT_DIR" --out artifacts

Everything that decides the outcome — this module, the independent verifier,
the requirements file, the list of manifest roots — is loaded from
``--trusted-root`` (a worktree of the protected target branch). Only the
manifests under test come from the merge request. A merge request therefore
cannot make itself pass by editing requirements or verification code.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from clavure.core.analysis import analyze
from clavure.core.constraints import load_scenario
from clavure.verification.guard import load_config
from clavure.verification.model_verifier import cross_check, verify


def run(trusted_root: Path, mr_root: Path, out: Path) -> dict:
    cfg = load_config(trusted_root / ".clavure.yaml")
    scenario_path = trusted_root / cfg["scenario"]
    manifests = [mr_root / p for p in cfg["manifests"] if (mr_root / p).exists()]
    baseline = [trusted_root / p for p in cfg["manifests"] if (trusted_root / p).exists()]
    rep = verify(manifests, scenario_path, baseline_paths=baseline)
    a = analyze(manifests, load_scenario(scenario_path))
    cross_check(rep, {(c.source, c.destination, c.port): str(c.verdict) for c in a.matrix})
    doc = {
        "artifact": "trusted-model-verification",
        "trusted_root": str(trusted_root),
        "requirements": str(scenario_path),
        **rep.to_dict(),
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "trusted-model-verification.json").write_text(json.dumps(doc, indent=2) + "\n")
    return doc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--trusted-root", required=True, type=Path)
    p.add_argument("--mr-root", required=True, type=Path)
    p.add_argument("--out", default=Path("artifacts"), type=Path)
    args = p.parse_args(argv)
    doc = run(args.trusted_root, args.mr_root, args.out)
    for c in doc["checks"]:
        print(f"  {c['outcome']:13} {c['constraint_id']}")
    for e in doc["structural_errors"] + doc["new_connectivity"] + doc["engine_disagreements"]:
        print(f"  FAIL {e}")
    print(f"TRUSTED MODEL VERIFICATION: {doc['outcome']}")
    return 0 if doc["outcome"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())

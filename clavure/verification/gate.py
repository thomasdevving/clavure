"""CI security gate (trusted component).

Mandatory failures that block the pipeline:

* a forbidden connection is permitted (CRITICAL/HIGH finding) and no
  verified remediation exists in this pipeline,
* the independent model verifier did not PASS,
* a runtime phase that was executed ended in FAIL after remediation,
* the trusted-file guard blocked the change.

A passing gate never authorizes deployment by itself; deployment jobs are
manual and protected (see .gitlab-ci.yml).
"""

from __future__ import annotations

import json
from pathlib import Path


def _load(d: Path, name: str) -> dict | None:
    p = d / name
    return json.loads(p.read_text()) if p.exists() else None


def evaluate_gate(artifacts: Path) -> dict:
    reasons: list[str] = []
    notes: list[str] = []
    findings = _load(artifacts, "security-findings.json")
    ver = _load(artifacts, "verification-report.json")
    guard = _load(artifacts, "guard.json")
    if findings is None:
        reasons.append("security-findings.json missing: analysis did not run")
    else:
        blocking = [
            f["title"]
            for f in findings["findings"]
            if f["category"] == "FORBIDDEN_CONNECTIVITY" and f["severity"] in ("CRITICAL", "HIGH")
        ]
        undecided = [
            f["title"] for f in findings["findings"] if f["category"] == "UNDECIDABLE_CONSTRAINT"
        ]
        if blocking:
            reasons.extend(f"forbidden connectivity in this change: {t}" for t in blocking)
        if undecided:
            reasons.extend(f"undecidable constraint: {t}" for t in undecided)
    if ver is not None:
        mv = ver.get("model_verification")
        if mv and mv.get("outcome") != "PASS":
            reasons.append(
                f"independent model verification of the proposed remediation: {mv.get('outcome')}"
            )
        runtime = ver.get("runtime") or []
        if len(runtime) > 1 and runtime[-1]["outcome"] == "FAIL":
            reasons.append("runtime verification after remediation FAILED")
        if not runtime:
            notes.append("runtime verification not executed in this pipeline")
        if ver.get("final_verdict") in ("MODEL_VERIFIED_ONLY", "REMEDIATION_VERIFIED"):
            notes.append(
                f"a remediation is available ({ver['final_verdict']}); it must be merged as its own reviewed change"
            )
    trusted = _load(artifacts, "trusted-model-verification.json")
    if trusted is not None:
        outcome = trusted.get("gate_outcome", trusted.get("outcome"))
        if outcome != "PASS":
            keys = (
                "forbidden_failures",
                "required_regressions",
                "new_connectivity",
                "structural_errors",
                "engine_disagreements",
            )
            detail = {k: trusted[k] for k in keys if trusted.get(k)}
            reasons.append(
                f"trusted verification (default-branch verifier and requirements): {outcome} {detail}"
            )
        for cid in trusted.get("preexisting_required_failures", []):
            notes.append(f"{cid} was already unmet before this change (not blocking)")
    if guard is not None and not guard.get("ok", True):
        reasons.append(f"trusted-file guard: {guard.get('decision')}")
    return {"pass": not reasons, "blocking_reasons": reasons, "notes": notes}

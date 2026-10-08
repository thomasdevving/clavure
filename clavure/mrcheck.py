"""Merge-request check: one deterministic command for CI and the Duo flow.

1. Materialize the target branch's manifests (``git archive``) as the baseline.
2. Run the model pipeline (analyze, permission diff, optimize, render,
   independent model verification) on the working tree.
3. Write ``summary.md`` and ``mr-description.md`` (evidence for reviewers)
   and print a single routing line ``CLAVURE_RESULT=<token>``.

The tokens are what the GitLab Duo flow routes on; the agent never decides
the security outcome itself.
"""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path

from clavure.pipeline import PipelineOptions, run_pipeline
from clavure.verification.guard import load_config

RESULT_TOKENS = {
    "NO_VIOLATION": "NO_VIOLATION",
    "MODEL_VERIFIED_ONLY": "REMEDIATION_AVAILABLE",
    "REMEDIATION_VERIFIED": "REMEDIATION_AVAILABLE",
    "NO_VALID_REMEDIATION": "NO_VALID_REMEDIATION",
    "VERIFICATION_FAILED": "VERIFICATION_FAILED",
    "INCONCLUSIVE": "VERIFICATION_FAILED",
}


def materialize_ref(ref: str, paths: list[str], dest: Path, repo: Path = Path(".")) -> list[Path]:
    """Extract ``paths`` as they exist at ``ref`` into ``dest``."""
    verify = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        capture_output=True,
        timeout=30,
    )
    if verify.returncode != 0:
        raise ValueError(f"git ref {ref!r} does not resolve to a commit")
    out = []
    for p in paths:
        exists = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "-e", f"{ref}:{p}"],
            capture_output=True,
            timeout=30,
        )
        target = dest / p
        if exists.returncode != 0:
            target.mkdir(parents=True, exist_ok=True)  # absent at ref: empty baseline
            out.append(target)
            continue
        proc = subprocess.run(
            ["git", "-C", str(repo), "archive", "--format=tar", ref, "--", p],
            capture_output=True,
            timeout=120,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"git archive {ref} {p} failed: {proc.stderr.decode()[-500:]}")
        with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tar:
            tar.extractall(dest, filter="data")
        out.append(target)
    return out


def _md_table(rows: list[list[str]], header: list[str]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(lines)


def write_summaries(out: Path, ref: str) -> tuple[str, str]:
    ver = json.loads((out / "verification-report.json").read_text())
    plan = (
        json.loads((out / "remediation-plan.json").read_text())
        if (out / "remediation-plan.json").exists()
        else None
    )
    findings = json.loads((out / "security-findings.json").read_text())
    diff = json.loads((out / "permission-diff.json").read_text())
    verdict = ver["final_verdict"]
    token = RESULT_TOKENS.get(verdict, "VERIFICATION_FAILED")

    f_rows = [[f["severity"], f["category"], f["title"]] for f in findings["findings"]]
    d_rows = [
        [
            f"`{x['source']}` → `{x['destination']}:{x['port']}`",
            x["classification"],
            "<br>".join(f"`{r}`" for r in x["introduced_by"]),
        ]
        for x in diff["expansions"]
    ]
    summary = [
        f"# Clavure merge-request check (baseline `{ref}`)",
        "",
        f"**Result:** `{token}` (pipeline verdict `{verdict}`)",
        "",
        "## Findings",
        _md_table(f_rows, ["Severity", "Category", "Finding"]) if f_rows else "No findings.",
        "",
        "## Connectivity newly permitted by this change",
        _md_table(d_rows, ["Connection", "Declared as", "Introduced by"]) if d_rows else "None.",
    ]
    desc = []
    if plan and plan.get("selected"):
        sel = plan["selected"]
        rejected = [c for c in plan["candidates"] if not c["valid"] and len(c["actions"]) == 1]
        r_rows = [
            [
                c["id"],
                " + ".join(a["description"] for a in c["actions"]),
                "; ".join(c["rejection_reasons"]),
            ]
            for c in rejected
        ]
        v_rows = []
        mv = ver.get("model_verification") or {}
        for c in mv.get("checks", []):
            v_rows.append([f"`{c['constraint_id']}`", c["expected"], c["outcome"]])
        summary += [
            "",
            "## Selected remediation",
            f"`{sel['id']}` (cost {sel['cost']['total']}): "
            + " + ".join(a["description"] for a in sel["actions"]),
            "",
            plan["selection_rationale"],
        ]
        desc = [
            "## Clavure remediation",
            "",
            "This merge request was prepared from Clavure's deterministic analysis. The optimizer, "
            "not the agent, selected the change; CI re-verifies it independently.",
            "",
            "### Exposure",
            *[
                f"- **{f['severity']}** {f['title']}"
                for f in findings["findings"]
                if f["severity"] in ("CRITICAL", "HIGH")
            ],
            "",
            "### Selected change",
            f"`{sel['id']}` — " + " + ".join(a["description"] for a in sel["actions"]),
            f"- Connectivity removed: {', '.join(f'`{x}`' for x in sel['connectivity_removed']) or 'none'}",
            f"- Connectivity added: {', '.join(f'`{x}`' for x in sel['connectivity_added']) or 'none'}",
            f"- Hard constraints: {', '.join(h['name'] for h in sel['hard_constraints'] if h['passed'])} — all passed",
            "",
            "### Rejected alternatives",
            _md_table(r_rows, ["Plan", "Change", "Why rejected"]) if r_rows else "None.",
            "",
            "### Independent model verification",
            f"Outcome **{mv.get('outcome', 'NOT EXECUTED')}**; cross-checked against engine: "
            f"{mv.get('cross_checked_against_engine')}; disagreements: {len(mv.get('engine_disagreements', []))}.",
            "",
            _md_table(v_rows, ["Constraint", "Expected", "Outcome"]) if v_rows else "",
            "",
            "### Still to be demonstrated by CI",
            "- `verify:model` re-runs the verifier from the target branch (trusted code and requirements).",
            "- `runtime:k3d` deploys to a disposable cluster and re-runs connectivity probes and business "
            "workflows (only on runners that support it; otherwise reported as not executed).",
            "",
            "### Limitations",
            *[f"- {x}" for x in plan.get("limitations", [])],
        ]
    (out / "summary.md").write_text("\n".join(summary) + "\n")
    (out / "mr-description.md").write_text(
        "\n".join(desc) + "\n" if desc else "No remediation proposed.\n"
    )
    return token, verdict


def run_mr_check(
    target_ref: str,
    config: Path,
    out: Path,
    *,
    fetch: bool = False,
    runtime: bool = False,
    cluster_name: str = "clavure-ci",
) -> tuple[str, dict]:
    cfg = load_config(config)
    if fetch and target_ref.startswith("origin/"):
        subprocess.run(
            ["git", "fetch", "--depth=200", "origin", target_ref.split("/", 1)[1]],
            capture_output=True,
            timeout=180,
            check=False,
        )
    with tempfile.TemporaryDirectory(prefix="clavure-baseline-") as tmp:
        baseline = materialize_ref(target_ref, cfg["manifests"], Path(tmp))
        report = run_pipeline(
            PipelineOptions(
                scenario=Path(cfg["scenario"]),
                baseline=baseline,
                proposed=[Path(p) for p in cfg["manifests"]],
                out=out,
                runtime=runtime,
                cluster_name=cluster_name,
            )
        )
    token, _ = write_summaries(out, target_ref)
    return token, report

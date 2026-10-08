"""Clavure command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from clavure.core.analysis import (
    analyze,
    artifact_header,
    write_analysis_artifacts,
    write_json,
)
from clavure.core.constraints import load_scenario


def _paths(values: list[str]) -> list[Path]:
    return [Path(v) for v in values]


def cmd_analyze(args) -> int:
    scenario = load_scenario(args.scenario)
    a = analyze(_paths(args.manifests), scenario)
    paths = write_analysis_artifacts(a, args.out)
    for f in a.findings:
        print(f"[{f.severity}] {f.title}")
    if a.consistency_issues:
        print("Graph consistency issues:", *a.consistency_issues, sep="\n  ")
    print(f"Artifacts: {', '.join(str(p) for p in paths.values())}")
    violated = [e for e in a.violations]
    return 1 if (violated and args.fail_on_violation) or a.consistency_issues else 0


def cmd_diff(args) -> int:
    from clavure.core.diff import diff_analyses, diff_document, expansion_findings

    scenario = load_scenario(args.scenario)
    before = analyze(_paths(args.before), scenario)
    after = analyze(_paths(args.after), scenario)
    d = diff_analyses(before, after)
    findings = expansion_findings(d, after)
    doc = {
        **artifact_header("permission-diff", scenario, after.inventory),
        "before_sources": [str(p) for p in args.before],
        **diff_document(d),
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    write_json(args.out, doc)
    for f in findings:
        print(f"[{f.severity}] {f.title}")
    print(f"Wrote {args.out}")
    critical = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    return 1 if critical and args.fail_on_violation else 0


def cmd_optimize(args) -> int:
    from clavure.optimizer.remediation import render_plan
    from clavure.optimizer.solver import optimize
    from clavure.reporting.artifacts import plan_document

    scenario = load_scenario(args.scenario)
    a = analyze(_paths(args.manifests), scenario)
    result = optimize(a, max_actions=args.max_actions)
    rendered = None
    if result.selected and args.render_dir:
        rendered = render_plan(result.selected, _paths(args.manifests), output_dir=args.render_dir)
    doc = plan_document(a, result, rendered)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    write_json(args.out, doc)
    print(json.dumps(result.stats))
    if result.selected:
        print(
            f"Selected {result.selected.id} (cost {result.selected.cost.total}): {result.selected.summary()}"
        )
    else:
        print("No valid remediation found within the supported model and action space.")
    for p in result.candidates[: args.show]:
        status = "VALID   " if p.valid else "REJECTED"
        print(f"  {p.id} {status} cost={p.cost.total:<7} {p.summary()}")
        if not p.valid:
            print(f"           reason: {'; '.join(p.rejection_reasons)}")
    if rendered:
        print(f"Rendered remediated manifests under {args.render_dir}")
    return 0 if result.selected or not a.violations else 2


def cmd_apply(args) -> int:
    """Apply the selected plan from a remediation-plan.json to the manifests in place."""
    from clavure.optimizer.remediation import render_plan
    from clavure.optimizer.solver import CandidatePlan

    doc = json.loads(Path(args.plan).read_text())
    if not doc.get("selected"):
        print("Plan has no selected remediation; nothing to apply.", file=sys.stderr)
        return 2
    plan = CandidatePlan.model_validate(doc["selected"])
    res = render_plan(plan, _paths(args.manifests))
    print(res.diff or "(no file changes)")
    for oob in res.out_of_band:
        print(f"OUT-OF-BAND (manual, not applied): {oob}")
    return 0


def cmd_verify_model(args) -> int:
    from clavure.verification.model_verifier import cross_check, verify

    scenario = load_scenario(args.scenario)
    rep = verify(
        _paths(args.manifests),
        args.scenario,
        baseline_paths=_paths(args.baseline) if args.baseline else None,
    )
    a = analyze(_paths(args.manifests), scenario)
    cross_check(rep, {(c.source, c.destination, c.port): str(c.verdict) for c in a.matrix})
    doc = {**artifact_header("model-verification", scenario, a.inventory), **rep.to_dict()}
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        write_json(args.out, doc)
    for c in rep.checks:
        print(f"  {c.outcome:13} {c.constraint_id} (expected {c.expected})")
    for e in rep.structural_errors + rep.new_connectivity + rep.engine_disagreements:
        print(f"  FAIL {e}")
    print(f"MODEL VERIFICATION: {rep.outcome}")
    return 0 if rep.outcome == "PASS" else 1


def cmd_guard(args) -> int:
    from clavure.verification.guard import check_trusted_files

    result = check_trusted_files(args.base_ref, args.manifest, repo=args.repo)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def cmd_report(args) -> int:
    from clavure.reporting.generator import generate_report

    out = generate_report(Path(args.artifacts), Path(args.out) if args.out else None)
    print(f"Wrote {out}")
    return 0


def cmd_cluster(args) -> int:
    from clavure.runtime.cluster import ClusterController

    ctl = ClusterController.from_env(name=args.name)
    if args.action == "up":
        ctl.create()
    elif args.action == "down":
        ctl.delete()
    print(json.dumps(ctl.status(), indent=2))
    return 0


def cmd_pipeline(args) -> int:
    from clavure.pipeline import PipelineOptions, run_pipeline

    opts = PipelineOptions(
        scenario=Path(args.scenario),
        baseline=_paths(args.baseline),
        proposed=_paths(args.proposed),
        out=Path(args.out),
        runtime=args.runtime,
        cluster_name=args.cluster_name,
        inject_drift=Path(args.inject_drift) if args.inject_drift else None,
        adversarial_budget=args.adversarial_budget,
        max_repair_attempts=args.max_repair_attempts,
        keep_cluster=args.keep_cluster,
    )
    result = run_pipeline(opts)
    print(f"FINAL VERDICT: {result['final_verdict']}")
    return 0 if result["final_verdict"] in ("REMEDIATION_VERIFIED", "NO_VIOLATION") else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="clavure", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="build the security graph and findings")
    a.add_argument("--manifests", nargs="+", required=True)
    a.add_argument("--scenario", required=True)
    a.add_argument("--out", default="artifacts")
    a.add_argument("--fail-on-violation", action="store_true")
    a.set_defaults(func=cmd_analyze)

    d = sub.add_parser("diff", help="permission-change analysis between two manifest sets")
    d.add_argument("--before", nargs="+", required=True)
    d.add_argument("--after", nargs="+", required=True)
    d.add_argument("--scenario", required=True)
    d.add_argument("--out", default="artifacts/permission-diff.json")
    d.add_argument("--fail-on-violation", action="store_true")
    d.set_defaults(func=cmd_diff)

    o = sub.add_parser("optimize", help="compute least-disruptive remediation candidates")
    o.add_argument("--manifests", nargs="+", required=True)
    o.add_argument("--scenario", required=True)
    o.add_argument("--out", default="artifacts/remediation-plan.json")
    o.add_argument("--render-dir", help="write a patched copy of the manifests here")
    o.add_argument("--max-actions", type=int)
    o.add_argument("--show", type=int, default=12)
    o.set_defaults(func=cmd_optimize)

    ap = sub.add_parser("apply-remediation", help="apply the selected plan to manifests in place")
    ap.add_argument("--plan", required=True)
    ap.add_argument("--manifests", nargs="+", required=True)
    ap.set_defaults(func=cmd_apply)

    v = sub.add_parser("verify-model", help="independent deterministic model verification")
    v.add_argument("--manifests", nargs="+", required=True)
    v.add_argument("--scenario", required=True)
    v.add_argument(
        "--baseline", nargs="+", help="manifests before the change (no-new-connectivity check)"
    )
    v.add_argument("--out")
    v.set_defaults(func=cmd_verify_model)

    g = sub.add_parser("guard", help="fail if trusted files differ from the base ref")
    g.add_argument("--base-ref", required=True)
    g.add_argument("--manifest", default=".clavure-trusted.yaml")
    g.add_argument("--repo", default=".")
    g.set_defaults(func=cmd_guard)

    r = sub.add_parser("report", help="render clavure-report.html from artifacts")
    r.add_argument("--artifacts", default="artifacts")
    r.add_argument("--out")
    r.set_defaults(func=cmd_report)

    c = sub.add_parser("cluster", help="manage the dedicated disposable k3d test cluster")
    c.add_argument("action", choices=["up", "down", "status"])
    c.add_argument("--name", default="clavure-test")
    c.set_defaults(func=cmd_cluster)

    pl = sub.add_parser(
        "pipeline", help="run the closed-loop verification and remediation pipeline"
    )
    pl.add_argument("--scenario", required=True)
    pl.add_argument("--baseline", nargs="+", required=True, help="manifests before the change")
    pl.add_argument("--proposed", nargs="+", required=True, help="manifests including the change")
    pl.add_argument("--out", default="artifacts")
    pl.add_argument(
        "--runtime", action="store_true", help="run runtime + adversarial stages on k3d"
    )
    pl.add_argument("--cluster-name", default="clavure-test")
    pl.add_argument("--inject-drift", help="FAULT INJECTION: apply this manifest out-of-band")
    pl.add_argument("--adversarial-budget", type=int, default=12)
    pl.add_argument("--max-repair-attempts", type=int, default=3)
    pl.add_argument("--keep-cluster", action="store_true")
    pl.set_defaults(func=cmd_pipeline)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

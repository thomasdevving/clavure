"""Closed-loop verification and remediation pipeline.

Stages (each recorded with status EXECUTED / SKIPPED / FAILED and a reason):

  1. analyze          security graph, reachability, findings (proposed state)
  2. permission-diff  what the change newly permits vs. the baseline
  3. runtime-baseline deploy proposed state in the disposable cluster, verify
  4. optimize         least-disruptive remediation within the action space
  5. render           patched copy of the manifests
  6. model-verify     independent verifier on the rendered files (+ cross-check)
  7. runtime-verify   apply plan, re-run probes and business workflows
  8. feedback         on MODEL MISMATCH: read live policies, report drift,
                      re-optimize with runtime evidence, bounded attempts

Final verdicts:

  NO_VIOLATION            nothing to remediate
  REMEDIATION_VERIFIED    model checks, runtime checks and workflows all PASS
  MODEL_VERIFIED_ONLY     model checks PASS; runtime stages not executed
  NO_VALID_REMEDIATION    no candidate satisfies every hard constraint
  VERIFICATION_FAILED     a verifier rejected the selected remediation
  INCONCLUSIVE            runtime evidence could not decide
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from clavure.core.analysis import (
    analyze,
    analyze_inventory,
    artifact_header,
    write_analysis_artifacts,
    write_json,
)
from clavure.core.constraints import load_scenario
from clavure.core.diff import diff_analyses, diff_document, expansion_findings
from clavure.core.drift import ingest_live_policies
from clavure.core.findings import Finding, FindingCategory, Severity
from clavure.core.policy_parser import parse_manifests
from clavure.optimizer.remediation import render_plan
from clavure.optimizer.solver import Evidence, optimize
from clavure.reporting.artifacts import plan_document
from clavure.verification.evidence import Outcome, now
from clavure.verification.model_verifier import cross_check, verify


@dataclass
class PipelineOptions:
    scenario: Path
    baseline: list[Path]
    proposed: list[Path]
    out: Path
    runtime: bool = False
    cluster_name: str = "clavure-test"
    inject_drift: Path | None = None
    adversarial_budget: int = 12  # accepted for CLI compatibility; extension not implemented
    max_repair_attempts: int = 3
    keep_cluster: bool = False


class StageLog:
    def __init__(self):
        self.stages: list[dict] = []

    def add(self, name: str, status: str, detail: str = "", **extra) -> None:
        self.stages.append(
            {"stage": name, "status": status, "timestamp": now(), "detail": detail, **extra}
        )


def _model_verify(
    paths: list[Path],
    scenario_path: Path,
    baseline: list[Path],
    scenario,
    extra_docs=None,
    baseline_extra=None,
) -> dict:
    rep = verify(
        paths,
        scenario_path,
        baseline_paths=baseline,
        extra_docs=extra_docs,
        baseline_extra_docs=baseline_extra,
    )
    a = analyze(paths, scenario)
    cross_check(rep, {(c.source, c.destination, c.port): str(c.verdict) for c in a.matrix})
    return rep.to_dict()


def run_pipeline(opts: PipelineOptions) -> dict:
    out = opts.out
    out.mkdir(parents=True, exist_ok=True)
    log = StageLog()
    scenario = load_scenario(opts.scenario)
    report: dict = {
        "pipeline": "clavure closed-loop verification",
        "started_at": now(),
        "scenario": scenario.name,
        "requirements_fingerprint": scenario.fingerprint,
        "baseline_sources": [str(p) for p in opts.baseline],
        "proposed_sources": [str(p) for p in opts.proposed],
        "separation_of_concerns": {
            "declared_requirements": str(opts.scenario),
            "modelled_reachability": "reachability.json",
            "observed_runtime_behaviour": "verification-report.json#runtime",
            "verified_violations": "verification-report.json#verified_violations",
            "proposed_remediations": "remediation-plan.json",
        },
        "adversarial_extension": {
            "status": "NOT_IMPLEMENTED",
            "detail": "The adversarial agent extension is not part of this build; no adversarial "
            "results exist and none are reported.",
        },
    }

    # 1. analyze --------------------------------------------------------
    proposed = analyze(opts.proposed, scenario)
    write_analysis_artifacts(proposed, out)
    log.add(
        "analyze",
        "EXECUTED",
        f"{len(proposed.violations)} constraint(s) not satisfied",
        consistency_issues=proposed.consistency_issues,
    )

    # 2. permission diff -----------------------------------------------
    before = analyze(opts.baseline, scenario)
    diff = diff_analyses(before, proposed)
    exp = expansion_findings(diff, proposed)
    write_json(
        out / "permission-diff.json",
        {
            **artifact_header("permission-diff", scenario, proposed.inventory),
            **diff_document(diff),
            "findings": [f.model_dump(mode="json") for f in exp],
        },
    )
    log.add("permission-diff", "EXECUTED", f"{len(diff.expansions)} newly permitted connection(s)")

    env = verifier = None
    runtime_reports: list[dict] = []
    drift_findings: list[Finding] = []
    verified_violations: list[dict] = []

    # 3. runtime baseline ----------------------------------------------
    if opts.runtime:
        try:
            from clavure.runtime.cluster import ClusterController
            from clavure.runtime.environment import TestEnvironment
            from clavure.verification.runtime_verifier import RuntimeVerifier

            ctl = ClusterController.from_env(name=opts.cluster_name)
            ctl.create()
            env = TestEnvironment(ctl, scenario)
            env.deploy(opts.proposed)
            if opts.inject_drift:
                env.inject_drift(opts.inject_drift)
            verifier = RuntimeVerifier(env, scenario)
            verifier.preflight()
            base_rt = verifier.verify("baseline (proposed change deployed)", proposed)
            runtime_reports.append(base_rt.model_dump(mode="json"))
            for c in base_rt.checks:
                if c.kind == "forbidden" and c.outcome == Outcome.FAIL:
                    verified_violations.append(
                        {
                            "constraint_id": c.constraint_id,
                            "phase": base_rt.phase,
                            "observed": str(c.observed),
                            "probe_ids": c.probe_ids,
                        }
                    )
            log.add(
                "runtime-baseline",
                "EXECUTED",
                f"outcome={base_rt.outcome}",
                enforcement_confirmed=verifier.enforcement_confirmed,
            )
        except Exception as exc:
            log.add("runtime-baseline", "FAILED", f"{type(exc).__name__}: {exc}")
            env = verifier = None
    else:
        log.add("runtime-baseline", "SKIPPED", "runtime stages not requested (--runtime)")

    # 4-8. optimize / verify / feedback loop ----------------------------
    analysis = proposed
    evidence = Evidence()
    attempts: list[dict] = []
    final_verdict = "NO_VIOLATION" if not proposed.violations else None
    result = None
    selected = None
    model_report: dict | None = None

    attempt = 0
    while final_verdict is None and attempt < opts.max_repair_attempts:
        attempt += 1
        result = optimize(analysis, evidence=evidence)
        selected = result.selected
        rec: dict = {
            "attempt": attempt,
            "selected": selected.id if selected else None,
            "summary": selected.summary() if selected else None,
            "stats": result.stats,
        }
        if selected is None:
            log.add(
                f"optimize#{attempt}", "EXECUTED", "no valid remediation within the supported model"
            )
            final_verdict = "NO_VALID_REMEDIATION"
            attempts.append(rec)
            break
        log.add(f"optimize#{attempt}", "EXECUTED", f"selected {selected.id}: {selected.summary()}")

        render_dir = out / "remediated-manifests"
        rendered = render_plan(selected, opts.proposed, output_dir=render_dir)
        write_json(out / "remediation-plan.json", plan_document(analysis, result, rendered))
        log.add(
            f"render#{attempt}",
            "EXECUTED",
            f"{len(rendered.files_changed)} file(s) changed",
            out_of_band=rendered.out_of_band,
        )

        roots = sorted(p for p in render_dir.iterdir())
        # Objects that exist only in the live cluster are not in git and
        # out-of-band changes are never applied automatically, so they are
        # part of the state the verifier must check, before and after.
        live_only = [
            p.to_k8s()
            for p in analysis.inventory.policies.values()
            if p.source.origin == "live-cluster"
        ]
        model_report = _model_verify(
            roots,
            opts.scenario,
            opts.proposed,
            scenario,
            extra_docs=live_only,
            baseline_extra=live_only,
        )
        rec["model_verification"] = model_report["outcome"]
        log.add(f"model-verify#{attempt}", "EXECUTED", f"outcome={model_report['outcome']}")
        if model_report["outcome"] != "PASS":
            final_verdict = "VERIFICATION_FAILED"
            attempts.append(rec)
            break

        if verifier is None:
            final_verdict = "MODEL_VERIFIED_ONLY"
            log.add(f"runtime-verify#{attempt}", "SKIPPED", "no runtime environment")
            attempts.append(rec)
            break

        skipped = env.apply_plan(selected)
        model_after = analyze_inventory(
            analysis.inventory.with_policies(_policies_after(analysis, selected)), scenario
        )
        rt = verifier.verify(f"remediation attempt {attempt}", model_after)
        runtime_reports.append(rt.model_dump(mode="json"))
        rec.update(
            runtime_outcome=str(rt.outcome),
            mismatches=len(rt.mismatches),
            out_of_band_skipped=skipped,
        )
        log.add(
            f"runtime-verify#{attempt}",
            "EXECUTED",
            f"outcome={rt.outcome}; mismatches={len(rt.mismatches)}",
        )
        attempts.append(rec)

        if rt.outcome == Outcome.PASS and not rt.mismatches:
            final_verdict = "REMEDIATION_VERIFIED"
            break

        # Feedback: never trust either side blindly. Revert, re-read what the
        # cluster actually enforces (read-only), and re-plan with evidence.
        env.revert_plan(selected)
        live = env.live_policies()
        inv, drift = ingest_live_policies(
            parse_manifests(opts.proposed), live, scenario.test_namespaces
        )
        drift_findings.extend(d for d in drift if d.id not in {x.id for x in drift_findings})
        refreshed = analyze_inventory(inv, scenario)
        unexplained = []
        refreshed_after = (
            analyze_inventory(inv.with_policies(_policies_after(refreshed, selected)), scenario)
            if _plan_applies(refreshed, selected)
            else None
        )
        for m in rt.mismatches:
            key = (m.source, m.destination, m.port, "TCP")
            explained = False
            if refreshed_after is not None:
                c = next((x for x in refreshed_after.matrix if x.key == key), None)
                explained = c is not None and str(c.verdict) == str(m.observed)
            if not explained:
                unexplained.append(key)
        evidence = Evidence(contradicted=sorted(set(evidence.contradicted) | set(unexplained)))
        log.add(
            f"feedback#{attempt}",
            "EXECUTED",
            f"{len(drift)} drift finding(s); {len(unexplained)} unexplained mismatch(es)",
            drift=[d.title for d in drift],
        )
        analysis = refreshed

    if final_verdict is None:
        final_verdict = "VERIFICATION_FAILED" if attempts else "INCONCLUSIVE"
        log.add(
            "repair-loop",
            "EXECUTED",
            f"stopped after {attempt} attempt(s) without verified remediation",
        )

    if env is not None and not opts.keep_cluster:
        try:
            env.controller.delete()
            log.add("teardown", "EXECUTED", "disposable cluster deleted")
        except Exception as exc:
            log.add("teardown", "FAILED", str(exc))

    findings = list(proposed.findings) + exp + drift_findings
    for rt in runtime_reports:
        for m in rt["mismatches"]:
            findings.append(
                Finding(
                    id=f"MODEL_MISMATCH:{m['source']}->{m['destination']}:{m['port']}:{rt['phase']}",
                    category=FindingCategory.MODEL_MISMATCH,
                    severity=Severity.HIGH,
                    provenance="runtime",
                    title=f"Model/runtime disagreement during '{rt['phase']}'",
                    source=m["source"],
                    destination=m["destination"],
                    ports=[m["port"]],
                    evidence=[m["explanation"]],
                )
            )
    report.update(
        {
            "finished_at": now(),
            "final_verdict": final_verdict,
            "stages": log.stages,
            "repair_attempts": attempts,
            "model_verification": model_report,
            "runtime": runtime_reports,
            "verified_violations": verified_violations,
            "drift_findings": [d.model_dump(mode="json") for d in drift_findings],
            "all_findings": [f.model_dump(mode="json") for f in findings],
            "events": env.events if env is not None else [],
            "success_criteria": {
                "model_constraints_satisfied": bool(
                    model_report and model_report["outcome"] == "PASS"
                ),
                "runtime_connectivity_checks_pass": _last_runtime(runtime_reports, "checks"),
                "business_workflows_pass": _last_runtime(runtime_reports, "workflows"),
            },
        }
    )
    write_json(out / "verification-report.json", report)
    write_json(
        out / "adversarial-results.json",
        {
            "artifact": "adversarial-results",
            "status": "NOT_IMPLEMENTED",
            "results": [],
            "detail": report["adversarial_extension"]["detail"],
        },
    )
    if not (out / "remediation-plan.json").exists() and result is not None:
        write_json(out / "remediation-plan.json", plan_document(analysis, result))
    try:
        from clavure.reporting.generator import generate_report

        generate_report(out, out / "clavure-report.html")
    except ImportError:
        pass
    return report


def _policies_after(analysis, plan):
    from clavure.optimizer.actions import PlanState, action_from_record

    st = PlanState.of(analysis.inventory)
    for rec in plan.actions:
        action_from_record(rec).apply(st)
    return st.result()


def _plan_applies(analysis, plan) -> bool:
    try:
        _policies_after(analysis, plan)
        return True
    except Exception:
        return False


def _last_runtime(reports: list[dict], key: str) -> bool | None:
    if len(reports) < 2:
        return None
    items = reports[-1][key]
    return all(i["outcome"] == "PASS" for i in items)

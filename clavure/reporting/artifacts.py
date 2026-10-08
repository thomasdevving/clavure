"""Serialization of optimizer results into remediation-plan.json."""

from __future__ import annotations

from clavure.core.analysis import Analysis, artifact_header
from clavure.optimizer.remediation import RenderResult
from clavure.optimizer.solver import OptimizationResult


def plan_document(
    a: Analysis, result: OptimizationResult, rendered: RenderResult | None = None
) -> dict:
    selected = result.selected
    return {
        **artifact_header("remediation-plan", a.scenario, a.inventory),
        "question": (
            "What is the least disruptive security change that eliminates the identified "
            "exposure while preserving essential business functionality?"
        ),
        "violations_addressed": [
            {
                "constraint_id": e.constraint_id,
                "kind": e.kind,
                "status": str(e.status),
                "detail": e.detail,
            }
            for e in a.violations
        ],
        "selected": selected.model_dump(mode="json") if selected else None,
        "selection_rationale": _rationale(result),
        "stats": result.stats,
        "cost_weights": result.weights,
        "actions_generated": result.actions_generated,
        "candidates": [p.model_dump(mode="json") for p in result.candidates],
        "rendered": (
            {
                "files_changed": rendered.files_changed,
                "out_of_band": rendered.out_of_band,
                "diff": rendered.diff,
            }
            if rendered
            else None
        ),
        "limitations": result.limitations,
    }


def _rationale(result: OptimizationResult) -> str:
    sel = result.selected
    if sel is None:
        return (
            "No candidate satisfied every hard constraint within the generated action space "
            f"({result.stats['combinations_evaluated']} combinations of up to "
            f"{result.stats['max_actions_per_plan']} actions). No remediation is proposed."
        )
    valid = [p for p in result.candidates if p.valid]
    runner = valid[1] if len(valid) > 1 else None
    text = (
        f"{sel.id} satisfies all hard constraints and has the lowest cost ({sel.cost.total}) of "
        f"{len(valid)} valid plans among {result.stats['combinations_evaluated']} evaluated combinations."
    )
    if runner is not None:
        text += f" Next best: {runner.id} (cost {runner.cost.total}): {runner.summary()}."
    rejected = [p for p in result.candidates if not p.valid and len(p.actions) == 1]
    if rejected:
        text += f" {len(rejected)} single-action candidates were rejected by hard constraints."
    return text

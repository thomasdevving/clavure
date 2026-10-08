"""Permission-change analysis: compare effective connectivity before/after a change.

Used for merge requests: the "before" manifests come from the target branch and
the "after" manifests from the MR head. Any connection whose verdict becomes
ALLOWED (or becomes undecidable) is a permission expansion and is attributed to
the rules that now permit it.
"""

from __future__ import annotations

from pydantic import BaseModel

from clavure.core.analysis import Analysis
from clavure.core.findings import Finding, FindingCategory, Severity
from clavure.core.models import Verdict
from clavure.core.security_graph import EdgeClass, classify_connections


class VerdictChange(BaseModel):
    source: str
    destination: str
    port: int
    protocol: str
    before: Verdict
    after: Verdict
    classification: EdgeClass
    constraints: list[str]
    introduced_by: list[str]

    @property
    def is_expansion(self) -> bool:
        return self.before == Verdict.BLOCKED and self.after != Verdict.BLOCKED


class PermissionDiff(BaseModel):
    added_policies: list[str]
    removed_policies: list[str]
    modified_policies: list[str]
    changes: list[VerdictChange]

    @property
    def expansions(self) -> list[VerdictChange]:
        return [c for c in self.changes if c.is_expansion]

    @property
    def reductions(self) -> list[VerdictChange]:
        return [
            c for c in self.changes if c.before == Verdict.ALLOWED and c.after == Verdict.BLOCKED
        ]


def diff_analyses(before: Analysis, after: Analysis) -> PermissionDiff:
    b_pol, a_pol = before.inventory.policies, after.inventory.policies
    modified = sorted(
        pid for pid in set(b_pol) & set(a_pol) if b_pol[pid].to_k8s() != a_pol[pid].to_k8s()
    )
    before_by_key = {c.key: c for c in before.matrix}
    classes = classify_connections(after.evaluations)
    changes = []
    for conn in after.matrix:
        prev = before_by_key.get(conn.key)
        prev_verdict = prev.verdict if prev else Verdict.BLOCKED
        if prev_verdict == conn.verdict:
            continue
        cls, cids = classes.get(conn.key, (EdgeClass.UNDECLARED, []))
        prev_rules = set()
        if prev:
            prev_rules = {r.describe() for s in (prev.egress, prev.ingress) for r in s.permitting}
        introduced = [
            r.describe()
            for s in (conn.egress, conn.ingress)
            for r in s.permitting
            if r.describe() not in prev_rules
        ]
        changes.append(
            VerdictChange(
                source=conn.source,
                destination=conn.destination,
                port=conn.port,
                protocol=conn.protocol,
                before=prev_verdict,
                after=conn.verdict,
                classification=cls,
                constraints=cids,
                introduced_by=introduced,
            )
        )
    return PermissionDiff(
        added_policies=sorted(set(a_pol) - set(b_pol)),
        removed_policies=sorted(set(b_pol) - set(a_pol)),
        modified_policies=modified,
        changes=changes,
    )


def expansion_findings(diff: PermissionDiff, after: Analysis) -> list[Finding]:
    protected = after.scenario.protected_workloads()
    out = []
    for ch in diff.expansions:
        forbidden = ch.classification == EdgeClass.FORBIDDEN
        if forbidden:
            sev = Severity.CRITICAL if ch.destination in protected else Severity.HIGH
        elif ch.classification == EdgeClass.REQUIRED:
            sev = Severity.INFO
        else:
            sev = Severity.MEDIUM
        out.append(
            Finding(
                id=f"PERMISSION_EXPANSION:{ch.source}->{ch.destination}:{ch.port}",
                category=FindingCategory.PERMISSION_EXPANSION,
                severity=sev,
                provenance="diff",
                title=(
                    f"Change newly permits {ch.source} -> {ch.destination}:{ch.port}/{ch.protocol}"
                    f" ({ch.classification.value.lower()} connection)"
                ),
                constraint_id=ch.constraints[0] if ch.constraints else None,
                source=ch.source,
                destination=ch.destination,
                ports=[ch.port],
                verdict=ch.after,
                evidence=[f"verdict changed {ch.before} -> {ch.after}"]
                + [f"newly permitting rule: {r}" for r in ch.introduced_by],
                permitting_rules=ch.introduced_by,
            )
        )
    return out


def diff_document(diff: PermissionDiff) -> dict:
    return {
        "added_policies": diff.added_policies,
        "removed_policies": diff.removed_policies,
        "modified_policies": diff.modified_policies,
        "expansions": [c.model_dump(mode="json") for c in diff.expansions],
        "reductions": [c.model_dump(mode="json") for c in diff.reductions],
        "all_changes": [c.model_dump(mode="json") for c in diff.changes],
    }

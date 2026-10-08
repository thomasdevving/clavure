"""Security findings with human-readable evidence."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from clavure.core.constraints import ConstraintEvaluation, ConstraintStatus, Scenario
from clavure.core.models import Inventory, Verdict

L4_SCOPE_NOTE = (
    "Network reachability (L3/L4) only: this shows that a TCP connection is permitted by the "
    "NetworkPolicy model, not that the application authorizes the request or that the "
    "resource is exploitable."
)


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(StrEnum):
    FORBIDDEN_CONNECTIVITY = "FORBIDDEN_CONNECTIVITY"
    REQUIRED_CONNECTIVITY_BROKEN = "REQUIRED_CONNECTIVITY_BROKEN"
    UNDECIDABLE_CONSTRAINT = "UNDECIDABLE_CONSTRAINT"
    UNSUPPORTED_FEATURE = "UNSUPPORTED_FEATURE"
    PERMISSION_EXPANSION = "PERMISSION_EXPANSION"
    MODEL_MISMATCH = "MODEL_MISMATCH"
    CONFIGURATION_DRIFT = "CONFIGURATION_DRIFT"


class Finding(BaseModel):
    id: str
    category: FindingCategory
    severity: Severity
    title: str
    provenance: str = "model"  # model | runtime | adversarial | diff
    constraint_id: str | None = None
    source: str | None = None
    destination: str | None = None
    ports: list[int] = Field(default_factory=list)
    verdict: Verdict | None = None
    evidence: list[str] = Field(default_factory=list)
    policies: list[str] = Field(default_factory=list)
    permitting_rules: list[str] = Field(default_factory=list)
    scope_note: str = L4_SCOPE_NOTE


def findings_from_evaluations(
    scenario: Scenario, evaluations: list[ConstraintEvaluation], inv: Inventory
) -> list[Finding]:
    findings: list[Finding] = []
    protected = scenario.protected_workloads()
    for ev in evaluations:
        if ev.status == ConstraintStatus.SATISFIED:
            continue
        src_id = scenario.workload_id(ev.source)
        dst_id = scenario.workload_id(ev.destination)
        evidence: list[str] = [ev.detail]
        rules: list[str] = []
        policies: list[str] = []
        for conn in ev.connections:
            if ev.kind == "forbidden" and conn.verdict == Verdict.BLOCKED:
                continue
            if ev.kind == "required" and conn.verdict == Verdict.ALLOWED:
                continue
            evidence.append(
                f"{conn.source} -> {conn.destination}:{conn.port}/{conn.protocol} = {conn.verdict}"
            )
            evidence.extend(conn.explanation())
            for side in (conn.egress, conn.ingress):
                rules.extend(r.describe() for r in side.permitting)
                rules.extend(r.describe() + f" [uncertain: {r.note}]" for r in side.uncertain)
            for p in conn.policies():
                if p not in policies:
                    policies.append(p)
        ports = (
            sorted({c.port for c in ev.connections if c.verdict != Verdict.BLOCKED})
            if ev.kind == "forbidden"
            else ev.ports()
        )
        if ev.status == ConstraintStatus.UNDECIDED:
            category, severity = FindingCategory.UNDECIDABLE_CONSTRAINT, Severity.MEDIUM
            title = f"Cannot decide {ev.constraint_id} ({ev.source} -> {ev.destination}) within the supported model"
        elif ev.kind == "forbidden":
            category = FindingCategory.FORBIDDEN_CONNECTIVITY
            severity = Severity.CRITICAL if dst_id in protected else Severity.HIGH
            title = (
                f"Forbidden connectivity permitted: {ev.source} -> {ev.destination} (ports {ports})"
            )
        else:
            category, severity = FindingCategory.REQUIRED_CONNECTIVITY_BROKEN, Severity.HIGH
            title = f"Required connectivity blocked: {ev.source} -> {ev.destination}"
        findings.append(
            Finding(
                id=f"{category.value}:{ev.constraint_id}",
                category=category,
                severity=severity,
                title=title,
                constraint_id=ev.constraint_id,
                source=src_id,
                destination=dst_id,
                ports=ports,
                verdict=_aggregate(ev),
                evidence=_dedupe(evidence),
                policies=policies,
                permitting_rules=_dedupe(rules),
            )
        )
    for i, feat in enumerate(inv.unsupported):
        findings.append(
            Finding(
                id=f"UNSUPPORTED_FEATURE:{i:03d}",
                category=FindingCategory.UNSUPPORTED_FEATURE,
                severity=Severity.MEDIUM if feat.affected_namespaces else Severity.INFO,
                title=f"Unsupported: {feat.feature} in {feat.object_ref}",
                evidence=[feat.detail, f"source: {feat.source.describe()}"]
                + (
                    [f"affects verdicts in namespaces: {list(feat.affected_namespaces)}"]
                    if feat.affected_namespaces
                    else []
                ),
            )
        )
    order = list(Severity)
    findings.sort(key=lambda f: (order.index(f.severity), f.id))
    return findings


def _aggregate(ev: ConstraintEvaluation) -> Verdict | None:
    """The verdict that best explains why the constraint is not satisfied."""
    verdicts = {c.verdict for c in ev.connections}
    if not verdicts:
        return None
    # Forbidden: any ALLOWED port is the problem. Required: any BLOCKED backend.
    worst = Verdict.ALLOWED if ev.kind == "forbidden" else Verdict.BLOCKED
    for v in (worst, Verdict.UNSUPPORTED, Verdict.UNKNOWN):
        if v in verdicts:
            return v
    return next(iter(verdicts))


def _dedupe(items: list[str]) -> list[str]:
    seen: list[str] = []
    for i in items:
        if i and i not in seen:
            seen.append(i)
    return seen

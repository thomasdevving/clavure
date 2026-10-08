"""Declared security requirements and their evaluation against the model.

The requirements file is a *trusted input*: it is read, fingerprinted and
evaluated, but nothing in Clavure ever writes it. Agent observations can never
be promoted into requirements (see docs/security-model.md).
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from clavure.core.models import Inventory, Verdict, Workload
from clavure.core.reachability import Connection, ReachabilityEngine


class WorkloadRef(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    namespace: str
    deployment: str
    service: str | None = None
    criticality: Literal["high", "medium", "low"] = "medium"
    protected: bool = False

    @property
    def workload_id(self) -> str:
        return f"{self.namespace}/{self.deployment}"

    @property
    def service_id(self) -> str | None:
        return f"{self.namespace}/{self.service}" if self.service else None


class RequiredConnection(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    id: str
    source: str
    destination: str
    port: int
    via_service: bool = Field(default=True, alias="viaService")
    protocol: Literal["TCP"] = "TCP"
    description: str = ""


class ForbiddenConnection(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    id: str
    source: str
    destination: str
    # A destination *pod* port, or "any" for every TCP port the pod exposes.
    port: int | Literal["any"] = "any"
    protocol: Literal["TCP"] = "TCP"
    description: str = ""


class Entrypoint(BaseModel):
    workload: str
    method: Literal["GET", "POST"]
    path: str


class StateCheck(BaseModel):
    workload: str
    table: str
    expect: str


class BusinessWorkflow(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    description: str = ""
    entrypoint: Entrypoint
    depends_on: list[str] = Field(default_factory=list, alias="dependsOn")
    state_checks: list[StateCheck] = Field(default_factory=list, alias="stateChecks")


class Scenario(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    test_namespaces: list[str]
    required_namespace_label: str = "clavure.io/test-env=true"
    workloads: dict[str, WorkloadRef]
    required: list[RequiredConnection] = Field(default_factory=list)
    forbidden: list[ForbiddenConnection] = Field(default_factory=list)
    workflows: list[BusinessWorkflow] = Field(default_factory=list)
    max_actions_per_plan: int = 3
    fingerprint: str = ""
    path: str | None = None

    @model_validator(mode="after")
    def _check_refs(self) -> Scenario:
        ids = [c.id for c in self.required] + [c.id for c in self.forbidden]
        if len(ids) != len(set(ids)):
            raise ValueError("constraint ids must be unique")
        for c in [*self.required, *self.forbidden]:
            for ref in (c.source, c.destination):
                if ref not in self.workloads:
                    raise ValueError(f"{c.id}: unknown logical workload {ref!r}")
        req_ids = {c.id for c in self.required}
        for wf in self.workflows:
            if wf.entrypoint.workload not in self.workloads:
                raise ValueError(f"{wf.id}: unknown entrypoint workload")
            missing = set(wf.depends_on) - req_ids
            if missing:
                raise ValueError(f"{wf.id}: depends on unknown requirements {sorted(missing)}")
        # A pair that is both required and forbidden on every port can never be
        # satisfied. (Port-specific overlaps are detected during evaluation,
        # because forbidden ports are pod ports and required ports may be
        # Service ports.)
        for c in self.forbidden:
            for r in self.required:
                if (r.source, r.destination) == (c.source, c.destination) and c.port == "any":
                    raise ValueError(f"{c.id} contradicts required connection {r.id}")
        return self

    def workload_id(self, logical: str) -> str:
        return self.workloads[logical].workload_id

    def logical_name(self, workload_id: str) -> str | None:
        for name, ref in self.workloads.items():
            if ref.workload_id == workload_id:
                return name
        return None

    def protected_workloads(self) -> set[str]:
        return {r.workload_id for r in self.workloads.values() if r.protected}

    def criticality(self, workload_id: str) -> str:
        name = self.logical_name(workload_id)
        return self.workloads[name].criticality if name else "low"


def load_scenario(path: str | Path) -> Scenario:
    raw_text = Path(path).read_text()
    doc = yaml.safe_load(raw_text)
    if doc.get("kind") != "SecurityRequirements" or doc.get("apiVersion") != "clavure.io/v1alpha1":
        raise ValueError(f"{path}: not a clavure.io/v1alpha1 SecurityRequirements document")
    spec = doc.get("spec") or {}
    env = spec.get("testEnvironment") or {}
    scenario = Scenario(
        name=(doc.get("metadata") or {}).get("name", "unnamed"),
        test_namespaces=list(env.get("namespaces") or []),
        required_namespace_label=env.get("requiredNamespaceLabel", "clavure.io/test-env=true"),
        workloads={k: WorkloadRef(**v) for k, v in (spec.get("workloads") or {}).items()},
        required=[RequiredConnection(**c) for c in spec.get("required") or []],
        forbidden=[ForbiddenConnection(**c) for c in spec.get("forbidden") or []],
        workflows=[BusinessWorkflow(**w) for w in spec.get("businessWorkflows") or []],
        max_actions_per_plan=int((spec.get("optimization") or {}).get("maxActionsPerPlan", 3)),
        path=str(path),
    )
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    scenario.fingerprint = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    return scenario


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------


class ConstraintStatus(StrEnum):
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    # The model cannot decide (UNKNOWN / UNSUPPORTED verdicts involved).
    UNDECIDED = "UNDECIDED"


class ConstraintEvaluation(BaseModel):
    constraint_id: str
    kind: Literal["required", "forbidden"]
    source: str
    destination: str
    status: ConstraintStatus
    connections: list[Connection]
    detail: str

    def ports(self) -> list[int]:
        return sorted({c.port for c in self.connections})


class ResolutionError(ValueError):
    pass


def _workload(inv: Inventory, scenario: Scenario, logical: str) -> Workload:
    wid = scenario.workload_id(logical)
    w = inv.workloads.get(wid)
    if w is None:
        raise ResolutionError(f"logical workload {logical!r} ({wid}) not found in manifests")
    return w


def required_connections(
    c: RequiredConnection, scenario: Scenario, inv: Inventory, engine: ReachabilityEngine
) -> tuple[list[Connection], str | None]:
    """Concrete pod-level connections that must all be ALLOWED for ``c``."""
    src = _workload(inv, scenario, c.source)
    dst_ref = scenario.workloads[c.destination]
    if not c.via_service:
        dst = _workload(inv, scenario, c.destination)
        return [engine.evaluate(src, dst, c.port, c.protocol)], None
    svc = inv.services.get(dst_ref.service_id or "")
    if svc is None:
        return [], f"service {dst_ref.service_id} not found"
    targets = engine.resolve_service_port(svc, c.port)
    if not targets:
        return [], f"service {svc.id} has no backends for port {c.port}"
    conns = []
    for backend, target in targets:
        if target is None:
            return [], f"named targetPort of {svc.id}:{c.port} does not resolve on {backend.id}"
        conns.append(engine.evaluate(src, backend, target, c.protocol))
    return conns, None


def forbidden_connections(
    c: ForbiddenConnection, scenario: Scenario, inv: Inventory, engine: ReachabilityEngine
) -> list[Connection]:
    src = _workload(inv, scenario, c.source)
    dst = _workload(inv, scenario, c.destination)
    ports = dst.tcp_ports() if c.port == "any" else [c.port]
    return [engine.evaluate(src, dst, p, c.protocol) for p in ports]


def evaluate_constraints(
    scenario: Scenario, inv: Inventory, engine: ReachabilityEngine | None = None
) -> list[ConstraintEvaluation]:
    engine = engine or ReachabilityEngine(inv)
    out: list[ConstraintEvaluation] = []
    for c in scenario.required:
        conns, problem = required_connections(c, scenario, inv, engine)
        verdicts = {x.verdict for x in conns}
        if problem:
            status, detail = ConstraintStatus.VIOLATED, problem
        elif verdicts == {Verdict.ALLOWED}:
            status, detail = ConstraintStatus.SATISFIED, "all backends reachable"
        elif Verdict.BLOCKED in verdicts:
            status, detail = ConstraintStatus.VIOLATED, "at least one backend is blocked"
        else:
            status, detail = ConstraintStatus.UNDECIDED, f"verdicts {sorted(verdicts)}"
        out.append(
            ConstraintEvaluation(
                constraint_id=c.id,
                kind="required",
                source=c.source,
                destination=c.destination,
                status=status,
                connections=conns,
                detail=detail,
            )
        )
    for c in scenario.forbidden:
        conns = forbidden_connections(c, scenario, inv, engine)
        verdicts = {x.verdict for x in conns}
        if Verdict.ALLOWED in verdicts:
            allowed = sorted(x.port for x in conns if x.verdict == Verdict.ALLOWED)
            status, detail = ConstraintStatus.VIOLATED, f"allowed on port(s) {allowed}"
        elif verdicts <= {Verdict.BLOCKED}:
            status, detail = ConstraintStatus.SATISFIED, "blocked on every port"
        else:
            status, detail = ConstraintStatus.UNDECIDED, f"verdicts {sorted(verdicts)}"
        out.append(
            ConstraintEvaluation(
                constraint_id=c.id,
                kind="forbidden",
                source=c.source,
                destination=c.destination,
                status=status,
                connections=conns,
                detail=detail,
            )
        )
    return out

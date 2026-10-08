"""One-call analysis facade and JSON artifact writers."""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import networkx as nx

from clavure import __version__
from clavure.core.constraints import (
    ConstraintEvaluation,
    ConstraintStatus,
    Scenario,
    evaluate_constraints,
)
from clavure.core.findings import Finding, findings_from_evaluations
from clavure.core.models import Inventory, Verdict
from clavure.core.policy_parser import iter_manifest_files, parse_manifests
from clavure.core.reachability import Connection, ReachabilityEngine
from clavure.core.security_graph import build_graph, check_consistency, topology_document


@dataclass
class Analysis:
    inventory: Inventory
    scenario: Scenario
    engine: ReachabilityEngine
    matrix: list[Connection]
    evaluations: list[ConstraintEvaluation]
    findings: list[Finding]
    graph: nx.MultiDiGraph
    consistency_issues: list[str]

    @property
    def violations(self) -> list[ConstraintEvaluation]:
        return [e for e in self.evaluations if e.status != ConstraintStatus.SATISFIED]

    def evaluation(self, constraint_id: str) -> ConstraintEvaluation:
        return next(e for e in self.evaluations if e.constraint_id == constraint_id)


def analyze_inventory(inv: Inventory, scenario: Scenario) -> Analysis:
    engine = ReachabilityEngine(inv)
    matrix = engine.matrix()
    evaluations = evaluate_constraints(scenario, inv, engine)
    findings = findings_from_evaluations(scenario, evaluations, inv)
    graph = build_graph(inv, scenario, engine, matrix, evaluations)
    issues = check_consistency(graph, inv, scenario, evaluations)
    return Analysis(inv, scenario, engine, matrix, evaluations, findings, graph, issues)


def analyze(manifest_paths: list[str | Path], scenario: Scenario) -> Analysis:
    return analyze_inventory(parse_manifests(manifest_paths), scenario)


def inputs_digest(manifest_paths: list[str | Path]) -> str:
    h = hashlib.sha256()
    for f in iter_manifest_files(manifest_paths):
        h.update(str(f).encode())
        h.update(b"\0")
        h.update(f.read_bytes())
        h.update(b"\0")
    return "sha256:" + h.hexdigest()


def artifact_header(kind: str, scenario: Scenario, inv: Inventory) -> dict[str, Any]:
    return {
        "artifact": kind,
        "clavure_version": __version__,
        "generated_at": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
        "scenario": scenario.name,
        "requirements_fingerprint": scenario.fingerprint,
        "manifest_sources": inv.sources,
        "inputs_digest": inputs_digest(inv.sources) if inv.sources else None,
    }


def connection_dict(conn: Connection) -> dict[str, Any]:
    return {
        "source": conn.source,
        "destination": conn.destination,
        "port": conn.port,
        "port_name": conn.port_name,
        "protocol": conn.protocol,
        "verdict": str(conn.verdict),
        "egress": _side(conn.egress),
        "ingress": _side(conn.ingress),
        "unsupported": list(conn.unsupported),
    }


def _side(side) -> dict[str, Any]:
    return {
        "workload": side.workload,
        "isolated": side.isolated,
        "verdict": str(side.verdict),
        "selecting_policies": list(side.selecting_policies),
        "permitting_rules": [r.describe() for r in side.permitting],
        "uncertain_rules": [f"{r.describe()} ({r.note})" for r in side.uncertain],
        "explanation": side.explanation,
    }


def evaluation_dict(ev: ConstraintEvaluation) -> dict[str, Any]:
    return {
        "constraint_id": ev.constraint_id,
        "kind": ev.kind,
        "source": ev.source,
        "destination": ev.destination,
        "status": str(ev.status),
        "detail": ev.detail,
        "connections": [
            {
                "source": c.source,
                "destination": c.destination,
                "port": c.port,
                "verdict": str(c.verdict),
            }
            for c in ev.connections
        ],
    }


def write_analysis_artifacts(a: Analysis, out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    header = lambda kind: artifact_header(kind, a.scenario, a.inventory)  # noqa: E731
    topo = {
        **header("topology"),
        **topology_document(a.graph),
        "unsupported_features": [f.model_dump(mode="json") for f in a.inventory.unsupported],
        "ignored_kinds": a.inventory.ignored_kinds,
        "consistency_issues": a.consistency_issues,
    }
    counts: dict[str, int] = {}
    for c in a.matrix:
        counts[str(c.verdict)] = counts.get(str(c.verdict), 0) + 1
    reach = {
        **header("reachability"),
        "semantics": "Kubernetes networking.k8s.io/v1 NetworkPolicy, TCP, pod-to-pod after Service DNAT",
        "summary": {"connections_evaluated": len(a.matrix), "by_verdict": counts},
        "connections": [connection_dict(c) for c in a.matrix],
        "constraints": [evaluation_dict(e) for e in a.evaluations],
    }
    findings = {
        **header("security-findings"),
        "summary": {
            "total": len(a.findings),
            "by_severity": _count(f.severity for f in a.findings),
            "constraints_violated": sum(
                1 for e in a.evaluations if e.status == ConstraintStatus.VIOLATED
            ),
            "constraints_undecided": sum(
                1 for e in a.evaluations if e.status == ConstraintStatus.UNDECIDED
            ),
            "constraints_satisfied": sum(
                1 for e in a.evaluations if e.status == ConstraintStatus.SATISFIED
            ),
        },
        "findings": [f.model_dump(mode="json") for f in a.findings],
    }
    paths = {
        "topology": out / "topology.json",
        "reachability": out / "reachability.json",
        "findings": out / "security-findings.json",
    }
    for key, doc in (("topology", topo), ("reachability", reach), ("findings", findings)):
        write_json(paths[key], doc)
    return paths


def _count(items) -> dict[str, int]:
    out: dict[str, int] = {}
    for i in items:
        out[str(i)] = out.get(str(i), 0) + 1
    return out


def write_json(path: str | Path, doc: Any) -> None:
    Path(path).write_text(json.dumps(doc, indent=2, sort_keys=False, default=str) + "\n")


def allowed_set(matrix: list[Connection]) -> set[tuple[str, str, int, str]]:
    return {c.key for c in matrix if c.verdict == Verdict.ALLOWED}

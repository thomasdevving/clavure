"""Security graph: workloads, services, namespaces, policies and connectivity.

Built with NetworkX (MultiDiGraph). Structural edges (membership, Service
routing, policy selection) are kept separate from connectivity edges, which
carry the verdict, policies, evidence and the constraint classification.
"""

from __future__ import annotations

from enum import StrEnum

import networkx as nx

from clavure.core.constraints import ConstraintEvaluation, Scenario
from clavure.core.models import Direction, Inventory, Verdict
from clavure.core.reachability import Connection, ReachabilityEngine


class EdgeClass(StrEnum):
    REQUIRED = "REQUIRED"
    FORBIDDEN = "FORBIDDEN"
    UNDECLARED = "UNDECLARED"
    CONFLICT = "CONFLICT"


def wl_node(workload_id: str) -> str:
    return f"wl:{workload_id}"


def classify_connections(
    evaluations: list[ConstraintEvaluation],
) -> dict[tuple[str, str, int, str], tuple[EdgeClass, list[str]]]:
    out: dict[tuple[str, str, int, str], tuple[EdgeClass, list[str]]] = {}
    for ev in evaluations:
        cls = EdgeClass.REQUIRED if ev.kind == "required" else EdgeClass.FORBIDDEN
        for conn in ev.connections:
            prev = out.get(conn.key)
            if prev is None:
                out[conn.key] = (cls, [ev.constraint_id])
            else:
                merged = prev[0] if prev[0] == cls else EdgeClass.CONFLICT
                out[conn.key] = (merged, [*prev[1], ev.constraint_id])
    return out


def build_graph(
    inv: Inventory,
    scenario: Scenario,
    engine: ReachabilityEngine,
    matrix: list[Connection],
    evaluations: list[ConstraintEvaluation],
) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    protected = scenario.protected_workloads()
    for ns in inv.namespaces.values():
        g.add_node(
            f"ns:{ns.name}",
            type="namespace",
            name=ns.name,
            labels=dict(ns.labels),
            labels_known=ns.labels_known,
        )
    for w in inv.workloads.values():
        g.add_node(
            wl_node(w.id),
            type="workload",
            id=w.id,
            kind=w.kind,
            name=w.name,
            namespace=w.namespace,
            logical_name=scenario.logical_name(w.id),
            labels=w.labels_dict(),
            ports=[
                {"name": p.name, "port": p.container_port, "protocol": p.protocol} for p in w.ports
            ],
            criticality=scenario.criticality(w.id),
            protected=w.id in protected,
            ingress_isolated=bool(engine.selecting_policies(w, Direction.INGRESS)),
            egress_isolated=bool(engine.selecting_policies(w, Direction.EGRESS)),
            source=w.source.describe(),
        )
        g.add_edge(wl_node(w.id), f"ns:{w.namespace}", kind="member_of")
    for s in inv.services.values():
        g.add_node(
            f"svc:{s.id}",
            type="service",
            id=s.id,
            name=s.name,
            namespace=s.namespace,
            ports=[
                {"port": p.port, "targetPort": p.target_port, "protocol": p.protocol}
                for p in s.ports
            ],
        )
        for b in inv.backends(s):
            g.add_edge(f"svc:{s.id}", wl_node(b.id), kind="routes_to")
    for p in inv.policies.values():
        g.add_node(
            f"np:{p.id}",
            type="policy",
            id=p.id,
            name=p.name,
            namespace=p.namespace,
            pod_selector=p.pod_selector.describe(),
            policy_types=[str(t) for t in p.policy_types],
            origin=p.source.origin,
            source=p.source.describe(),
        )
        for w in inv.workloads.values():
            dirs = [str(d) for d in p.policy_types if p in engine.selecting_policies(w, d)]
            if dirs:
                g.add_edge(f"np:{p.id}", wl_node(w.id), kind="selects", directions=dirs)

    classes = classify_connections(evaluations)
    for conn in matrix:
        cls, constraint_ids = classes.get(conn.key, (EdgeClass.UNDECLARED, []))
        g.add_edge(
            wl_node(conn.source),
            wl_node(conn.destination),
            key=f"{conn.protocol}/{conn.port}",
            kind="connectivity",
            source=conn.source,
            destination=conn.destination,
            port=conn.port,
            port_name=conn.port_name,
            protocol=conn.protocol,
            verdict=str(conn.verdict),
            classification=str(cls),
            constraints=constraint_ids,
            policies=conn.policies(),
            permitting_rules=[
                r.describe() for s in (conn.egress, conn.ingress) for r in s.permitting
            ],
            evidence=conn.explanation(),
        )
    return g


def topology_document(g: nx.MultiDiGraph) -> dict:
    """Readable topology: structural edges plus connectivity that matters.

    Connectivity edges are included when they are allowed/undecidable or when
    a declared constraint refers to them. The full matrix is in
    reachability.json.
    """
    nodes = [{"id": n, **attrs} for n, attrs in sorted(g.nodes(data=True))]
    edges = []
    for u, v, attrs in g.edges(data=True):
        if (
            attrs["kind"] == "connectivity"
            and attrs["verdict"] == Verdict.BLOCKED
            and attrs["classification"] == EdgeClass.UNDECLARED
        ):
            continue
        edges.append({"from": u, "to": v, **attrs})
    edges.sort(key=lambda e: (e["kind"], e["from"], e["to"], str(e.get("port", ""))))
    return {"nodes": nodes, "edges": edges}


def check_consistency(
    g: nx.MultiDiGraph, inv: Inventory, scenario: Scenario, evaluations: list[ConstraintEvaluation]
) -> list[str]:
    """Structural self-checks; an empty list means the graph is consistent."""
    issues: list[str] = []
    for u, v, attrs in g.edges(data=True):
        for n in (u, v):
            if n not in g:
                issues.append(f"edge {u}->{v} references missing node {n}")
        if attrs["kind"] == "connectivity":
            if attrs["classification"] == EdgeClass.CONFLICT:
                issues.append(f"{u}->{v}:{attrs['port']} is both required and forbidden")
            for pol in attrs["policies"]:
                if f"np:{pol}" not in g:
                    issues.append(f"{u}->{v} cites unknown policy {pol}")
            if attrs["verdict"] not in {v.value for v in Verdict}:
                issues.append(f"{u}->{v} has invalid verdict {attrs['verdict']}")
    for name, ref in scenario.workloads.items():
        if wl_node(ref.workload_id) not in g:
            issues.append(f"scenario workload {name} ({ref.workload_id}) not in graph")
        if ref.service_id and f"svc:{ref.service_id}" not in g:
            issues.append(f"scenario service {ref.service_id} not in graph")
        elif ref.service_id and not list(g.successors(f"svc:{ref.service_id}")):
            issues.append(f"service {ref.service_id} has no backends")
    edge_verdicts = {
        (a["source"], a["destination"], a["port"], a["protocol"]): a["verdict"]
        for _, _, a in g.edges(data=True)
        if a["kind"] == "connectivity"
    }
    for ev in evaluations:
        for conn in ev.connections:
            if edge_verdicts.get(conn.key) != conn.verdict:
                issues.append(
                    f"{ev.constraint_id}: constraint verdict {conn.verdict} for {conn.key} "
                    f"disagrees with matrix verdict {edge_verdicts.get(conn.key)}"
                )
    return issues

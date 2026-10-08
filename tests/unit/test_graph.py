"""Security graph consistency tests."""

from __future__ import annotations

from clavure.core.analysis import analyze
from clavure.core.security_graph import check_consistency, topology_document, wl_node
from tests.conftest import BASE, CHANGE


def test_graph_structure(scenario):
    a = analyze([BASE, CHANGE], scenario)
    g = a.graph
    fin = g.nodes[wl_node("clavure-data/finance-db")]
    assert fin["protected"] is True
    assert fin["ingress_isolated"] and fin["egress_isolated"]
    # The misconfigured policy selects both databases.
    selected = {
        v
        for _, v, d in g.out_edges("np:clavure-data/allow-analytics-to-data-tier", data=True)
        if d["kind"] == "selects"
    }
    assert selected == {wl_node("clavure-data/finance-db"), wl_node("clavure-data/orders-db")}
    routes = {
        v
        for _, v, d in g.out_edges("svc:clavure-data/finance-db", data=True)
        if d["kind"] == "routes_to"
    }
    assert routes == {wl_node("clavure-data/finance-db")}


def test_connectivity_edges_carry_evidence(scenario):
    a = analyze([BASE, CHANGE], scenario)
    edges = [d for _, _, d in a.graph.edges(data=True) if d["kind"] == "connectivity"]
    assert len(edges) == len(a.matrix)
    for e in edges:
        assert {
            "source",
            "destination",
            "protocol",
            "port",
            "policies",
            "evidence",
            "classification",
            "verdict",
        } <= set(e)
        assert e["evidence"]


def test_consistency_detects_injected_problem(scenario):
    a = analyze([BASE, CHANGE], scenario)
    assert a.consistency_issues == []
    u, v, k, d = next(
        (u, v, k, d)
        for u, v, k, d in a.graph.edges(keys=True, data=True)
        if d["kind"] == "connectivity"
    )
    a.graph.edges[u, v, k]["policies"] = [*d["policies"], "ghost/policy"]
    issues = check_consistency(a.graph, a.inventory, scenario, a.evaluations)
    assert any("ghost/policy" in i for i in issues)


def test_topology_document_filters_irrelevant_blocked_edges(scenario):
    a = analyze([BASE, CHANGE], scenario)
    doc = topology_document(a.graph)
    conn = [e for e in doc["edges"] if e["kind"] == "connectivity"]
    assert all(e["verdict"] != "BLOCKED" or e["classification"] != "UNDECLARED" for e in conn)
    assert len(conn) < len(a.matrix)

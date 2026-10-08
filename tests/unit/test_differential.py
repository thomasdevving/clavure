"""Differential test: reachability engine vs. independent model verifier.

Both implement Kubernetes NetworkPolicy semantics with different algorithms
and no shared code. On randomly generated worlds they must agree on every
(source, destination, port) verdict.
"""

from __future__ import annotations

import random

import pytest
import yaml

from clavure.core.models import SourceRef
from clavure.core.policy_parser import parse_documents
from clavure.core.reachability import ReachabilityEngine
from clavure.verification.model_verifier import (
    ALLOW,
    DENY,
    MAYBE,
    UNSUP,
    compile_world,
    load_world,
    query,
)

MAP = {"ALLOWED": ALLOW, "BLOCKED": DENY, "UNKNOWN": MAYBE, "UNSUPPORTED": UNSUP}
KEYS = ["app", "tier", "team"]
VALUES = ["a", "b", "c"]


def rand_selector(rng: random.Random, allow_empty=True) -> dict:
    sel: dict = {}
    if rng.random() < 0.6:
        sel["matchLabels"] = {
            rng.choice(KEYS): rng.choice(VALUES) for _ in range(rng.randint(1, 2))
        }
    if rng.random() < 0.3:
        op = rng.choice(["In", "NotIn", "Exists", "DoesNotExist"])
        expr = {"key": rng.choice(KEYS), "operator": op}
        if op in ("In", "NotIn"):
            expr["values"] = rng.sample(VALUES, rng.randint(1, 2))
        sel["matchExpressions"] = [expr]
    if not sel and not allow_empty:
        sel["matchLabels"] = {"app": rng.choice(VALUES)}
    return sel


def rand_ns_selector(rng, namespaces) -> dict:
    r = rng.random()
    if r < 0.3:
        return {}
    if r < 0.6:
        return {"matchLabels": {"kubernetes.io/metadata.name": rng.choice([*namespaces, "ghost"])}}
    return {"matchLabels": {"env": rng.choice(["prod", "dev"])}}


def rand_peer(rng, namespaces) -> dict:
    r = rng.random()
    if r < 0.08:
        return {"ipBlock": {"cidr": "10.0.0.0/8"}}
    if r < 0.4:
        return {"podSelector": rand_selector(rng)}
    if r < 0.7:
        return {"namespaceSelector": rand_ns_selector(rng, namespaces)}
    return {
        "namespaceSelector": rand_ns_selector(rng, namespaces),
        "podSelector": rand_selector(rng),
    }


def rand_ports(rng) -> list:
    out = []
    for _ in range(rng.randint(1, 2)):
        r = rng.random()
        if r < 0.35:
            out.append({"protocol": "TCP", "port": rng.choice([80, 8080, 5432])})
        elif r < 0.55:
            out.append({"port": rng.choice(["http", "db", "nope"])})
        elif r < 0.7:
            out.append({"port": 1000, "endPort": rng.choice([6000, 9000])})
        elif r < 0.85:
            out.append({"protocol": "UDP", "port": 8080})
        else:
            out.append({"protocol": "TCP"})
    return out


def rand_world(seed: int) -> list[dict]:
    rng = random.Random(seed)
    namespaces = ["n1", "n2", "n3"]
    docs: list[dict] = []
    for ns in namespaces[:2]:  # n3 stays undeclared: labels unknown
        docs.append(
            {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": ns, "labels": {"env": rng.choice(["prod", "dev"])}},
            }
        )
    for i in range(5):
        ns = rng.choice(namespaces)
        labels = {k: rng.choice(VALUES) for k in KEYS if rng.random() < 0.7}
        ports = [{"name": "http", "containerPort": 8080}]
        if rng.random() < 0.5:
            ports.append({"name": "db", "containerPort": 5432})
        if rng.random() < 0.3:
            ports.append({"containerPort": 80})
        docs.append(
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": f"p{i}", "namespace": ns, "labels": labels},
                "spec": {"containers": [{"name": "c", "image": "x", "ports": ports}]},
            }
        )
    for j in range(rng.randint(0, 5)):
        ns = rng.choice(namespaces)
        spec: dict = {"podSelector": rand_selector(rng)}
        r = rng.random()
        if r < 0.3:
            spec["policyTypes"] = ["Ingress"]
        elif r < 0.55:
            spec["policyTypes"] = ["Egress"]
        elif r < 0.8:
            spec["policyTypes"] = ["Ingress", "Egress"]
        for field, peer_key in (("ingress", "from"), ("egress", "to")):
            if rng.random() < 0.7:
                rules = []
                for _ in range(rng.randint(0, 2)):
                    rule: dict = {}
                    if rng.random() < 0.8:
                        rule[peer_key] = [
                            rand_peer(rng, namespaces) for _ in range(rng.randint(1, 2))
                        ]
                    if rng.random() < 0.6:
                        rule["ports"] = rand_ports(rng)
                    rules.append(rule)
                spec[field] = rules
        if "policyTypes" in spec:
            for field, t in (("ingress", "Ingress"), ("egress", "Egress")):
                if t not in spec["policyTypes"]:
                    spec.pop(field, None)
        docs.append(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": f"np{j}", "namespace": ns},
                "spec": spec,
            }
        )
    return docs


@pytest.mark.parametrize("seed", range(400))
def test_engine_and_verifier_agree(seed, tmp_path):
    docs = rand_world(seed)
    inv = parse_documents([(d, SourceRef(path="rand", document=i)) for i, d in enumerate(docs)])
    engine = ReachabilityEngine(inv)
    path = tmp_path / "w.yaml"
    path.write_text(yaml.safe_dump_all(docs))
    world = load_world([path])
    comp = compile_world(world)
    pods = {p.id: p for p in world.pods}
    for src in inv.workloads.values():
        for dst in inv.workloads.values():
            if src.id == dst.id:
                continue
            for port in dst.tcp_ports():
                e = engine.evaluate(src, dst, port).verdict
                v = query(world, comp, pods[src.id], pods[dst.id], port)
                assert MAP[str(e)] == v, (
                    f"seed={seed} {src.id}->{dst.id}:{port} engine={e} verifier={v}"
                )

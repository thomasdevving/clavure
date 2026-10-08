"""Policy parsing and validation tests."""

from __future__ import annotations

import pytest

from clavure.core.models import Direction
from clavure.core.policy_parser import ManifestError, parse_manifests, validate_policy_document
from tests.conftest import BASE, CHANGE, docs, inv_from_yaml, ns, pod


def np_doc(spec: str, name: str = "p", namespace: str = "a") -> str:
    return f"""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {{name: {name}, namespace: {namespace}}}
spec:
{spec}
"""


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ("  podSelector: {}\n  ingress: [{ports: [{port: 70000}]}]", "out of range"),
        (
            "  podSelector: {}\n  ingress: [{ports: [{port: http, endPort: 90}]}]",
            "endPort requires",
        ),
        ("  podSelector: {}\n  ingress: [{ports: [{port: 100, endPort: 90}]}]", "endPort must be"),
        (
            "  podSelector: {}\n  ingress: [{from: [{podSelector: {}, bogus: 1}]}]",
            "unknown peer fields",
        ),
        ("  podSelector: {matchExpressions: [{key: a, operator: Has}]}", "invalid operator"),
        ("  podSelector: {matchExpressions: [{key: a, operator: In}]}", "requires values"),
        ("  podSelector: {}\n  policyTypes: [Sideways]", "invalid policyType"),
        (
            "  podSelector: {}\n  ingress: [{from: [{ipBlock: {cidr: 10.0.0.0/8}, podSelector: {}}]}]",
            "ipBlock cannot",
        ),
        (
            "  podSelector: {}\n  policyTypes: [Egress]\n  egress: [{from: [{podSelector: {}}]}]",
            "not valid",
        ),
        ("  podSelector: {matchLabels: {'bad key!': x}}", "invalid label key"),
        ("  ingress: []", "podSelector is required"),
        ("  podSelector: {}\n  ingress: [{from: [{}]}]", "must set podSelector"),
    ],
)
def test_invalid_policies_are_rejected(spec, message):
    with pytest.raises(ManifestError, match=message):
        inv_from_yaml(docs(np_doc(spec)))


def test_duplicate_objects_rejected():
    with pytest.raises(ManifestError, match="duplicate"):
        inv_from_yaml(docs(np_doc("  podSelector: {}"), np_doc("  podSelector: {}")))


def test_rules_without_policy_type_are_reported():
    inv = inv_from_yaml(docs(np_doc("  podSelector: {}\n  policyTypes: [Ingress]\n  egress: [{}]")))
    p = inv.policies["a/p"]
    assert p.egress == ()
    assert any("without policyType" in f.feature for f in inv.unsupported)


def test_unknown_spec_field_is_unsupported_not_ignored():
    inv = inv_from_yaml(docs(np_doc("  podSelector: {}\n  futureField: true")))
    assert any(
        f.feature == "spec.futureField" and f.affected_namespaces == ("a",) for f in inv.unsupported
    )


def test_deployment_selector_must_match_template():
    bad = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: d, namespace: a}
spec:
  selector: {matchLabels: {app: x}}
  template:
    metadata: {labels: {app: y}}
    spec: {containers: [{name: c, image: i}]}
"""
    with pytest.raises(ManifestError, match="does not match"):
        inv_from_yaml(docs(bad))


def test_implicit_namespace_has_unknown_labels():
    inv = inv_from_yaml(docs(pod("p", "undeclared", {"app": "p"})))
    assert inv.namespaces["undeclared"].labels_known is False
    assert inv.namespaces["undeclared"].labels_dict() == {
        "kubernetes.io/metadata.name": "undeclared"
    }


def test_namespace_gets_metadata_name_label():
    inv = inv_from_yaml(docs(ns("a", {"zone": "z"})))
    assert inv.namespaces["a"].labels_dict()["kubernetes.io/metadata.name"] == "a"


def test_round_trip_generated_documents_validate():
    inv = parse_manifests([BASE, CHANGE])
    for p in inv.policies.values():
        assert validate_policy_document(p.to_k8s()) == []


def test_demo_manifests_parse_completely():
    inv = parse_manifests([BASE, CHANGE])
    assert len(inv.workloads) == 6
    assert len(inv.services) == 6
    assert len(inv.policies) == 15
    assert inv.unsupported == []
    pay = inv.policies["clavure-shop/payment-service-ingress"]
    assert pay.ingress[0].ports[0].port == "http"  # named port preserved
    assert inv.policies["clavure-shop/default-deny-all"].policy_types == (
        Direction.INGRESS,
        Direction.EGRESS,
    )


def test_list_documents_are_expanded():
    lst = """
apiVersion: v1
kind: List
items:
  - apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata: {name: one, namespace: a}
    spec: {podSelector: {}}
"""
    assert "a/one" in inv_from_yaml(docs(lst)).policies

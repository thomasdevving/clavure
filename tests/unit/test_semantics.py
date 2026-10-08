"""Kubernetes NetworkPolicy semantics tests for the reachability engine."""

from __future__ import annotations

import pytest

from clavure.core.models import Verdict
from clavure.core.reachability import ReachabilityEngine
from tests.conftest import docs, inv_from_yaml, ns, pod


def verdict(inv, src: str, dst: str, port: int, protocol: str = "TCP") -> Verdict:
    e = ReachabilityEngine(inv)
    return e.evaluate(inv.workloads[src], inv.workloads[dst], port, protocol).verdict


TWO_PODS = [
    ns("a", {"team": "x"}),
    pod("client", "a", {"app": "client"}),
    pod("server", "a", {"app": "server"}),
]


def np(name, namespace, body):
    return f"""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {{name: {name}, namespace: {namespace}}}
spec:
{body}
"""


DENY_ALL_A = np("deny", "a", "  podSelector: {}\n  policyTypes: [Ingress, Egress]")


def test_non_isolated_pods_allow_everything():
    inv = inv_from_yaml(docs(*TWO_PODS))
    assert verdict(inv, "a/client", "a/server", 8080) == Verdict.ALLOWED


def test_default_deny_ingress_blocks():
    inv = inv_from_yaml(
        docs(*TWO_PODS, np("deny", "a", "  podSelector: {}\n  policyTypes: [Ingress]"))
    )
    assert verdict(inv, "a/client", "a/server", 8080) == Verdict.BLOCKED


def test_policies_are_additive_restrictive_policy_does_not_revoke():
    allow = np(
        "allow",
        "a",
        """  podSelector: {matchLabels: {app: server}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {app: client}}}]""",
    )
    # A second, "more restrictive" policy selecting the same pod with no
    # matching rule does NOT override the first one.
    restrictive = np(
        "restrict",
        "a",
        """  podSelector: {matchLabels: {app: server}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {app: nobody}}}]""",
    )
    inv = inv_from_yaml(
        docs(
            *TWO_PODS,
            np("deny", "a", "  podSelector: {}\n  policyTypes: [Ingress]"),
            allow,
            restrictive,
        )
    )
    assert verdict(inv, "a/client", "a/server", 8080) == Verdict.ALLOWED


def test_egress_isolation_blocks_even_if_destination_allows():
    inv = inv_from_yaml(
        docs(
            *TWO_PODS,
            np(
                "deny-eg",
                "a",
                "  podSelector: {matchLabels: {app: client}}\n  policyTypes: [Egress]",
            ),
        )
    )
    assert verdict(inv, "a/client", "a/server", 8080) == Verdict.BLOCKED


def test_both_directions_required():
    ingress_ok = np(
        "in",
        "a",
        """  podSelector: {matchLabels: {app: server}}
  ingress: [{from: [{podSelector: {matchLabels: {app: client}}}]}]""",
    )
    egress_ok = np(
        "out",
        "a",
        """  podSelector: {matchLabels: {app: client}}
  policyTypes: [Egress]
  egress: [{to: [{podSelector: {matchLabels: {app: server}}}]}]""",
    )
    only_ingress = inv_from_yaml(docs(*TWO_PODS, DENY_ALL_A, ingress_ok))
    assert verdict(only_ingress, "a/client", "a/server", 8080) == Verdict.BLOCKED
    both = inv_from_yaml(docs(*TWO_PODS, DENY_ALL_A, ingress_ok, egress_ok))
    assert verdict(both, "a/client", "a/server", 8080) == Verdict.ALLOWED


def test_policy_types_default_inference():
    # No policyTypes and no egress rules -> Ingress only: egress stays open.
    inv = inv_from_yaml(
        docs(*TWO_PODS, np("p", "a", "  podSelector: {matchLabels: {app: client}}\n  ingress: []"))
    )
    p = inv.policies["a/p"]
    assert [str(t) for t in p.policy_types] == ["Ingress"]
    assert verdict(inv, "a/client", "a/server", 8080) == Verdict.ALLOWED
    # No policyTypes but egress rules present -> Ingress and Egress.
    inv2 = inv_from_yaml(
        docs(
            *TWO_PODS,
            np(
                "p",
                "a",
                "  podSelector: {matchLabels: {app: client}}\n  egress: [{to: [{podSelector: {matchLabels: {app: other}}}]}]",
            ),
        )
    )
    assert [str(t) for t in inv2.policies["a/p"].policy_types] == ["Ingress", "Egress"]
    assert verdict(inv2, "a/client", "a/server", 8080) == Verdict.BLOCKED


def test_empty_rule_allows_all_peers_and_ports():
    inv = inv_from_yaml(
        docs(
            *TWO_PODS,
            DENY_ALL_A,
            np(
                "in",
                "a",
                "  podSelector: {}\n  policyTypes: [Ingress, Egress]\n  ingress: [{}]\n  egress: [{}]",
            ),
        )
    )
    assert verdict(inv, "a/client", "a/server", 8080) == Verdict.ALLOWED


def test_pod_selector_peer_is_namespace_local():
    pods = [
        ns("a"),
        ns("b"),
        pod("client", "b", {"app": "client"}),
        pod("server", "a", {"app": "server"}),
    ]
    rule = np(
        "in",
        "a",
        """  podSelector: {matchLabels: {app: server}}
  ingress: [{from: [{podSelector: {matchLabels: {app: client}}}]}]""",
    )
    inv = inv_from_yaml(docs(*pods, rule))
    # Same labels, but different namespace: podSelector-only peers do not match.
    assert verdict(inv, "b/client", "a/server", 8080) == Verdict.BLOCKED


def test_namespace_selector_and_vs_or():
    base = [
        ns("a"),
        ns("b", {"env": "prod"}),
        pod("client", "b", {"app": "client"}),
        pod("other", "b", {"app": "other"}),
        pod("server", "a", {"app": "server"}),
    ]
    and_rule = np(
        "in",
        "a",
        """  podSelector: {matchLabels: {app: server}}
  ingress:
    - from:
        - namespaceSelector: {matchLabels: {env: prod}}
          podSelector: {matchLabels: {app: client}}""",
    )
    or_rule = np(
        "in",
        "a",
        """  podSelector: {matchLabels: {app: server}}
  ingress:
    - from:
        - namespaceSelector: {matchLabels: {env: prod}}
        - podSelector: {matchLabels: {app: client}}""",
    )
    inv_and = inv_from_yaml(docs(*base, and_rule))
    assert verdict(inv_and, "b/client", "a/server", 8080) == Verdict.ALLOWED
    assert verdict(inv_and, "b/other", "a/server", 8080) == Verdict.BLOCKED
    inv_or = inv_from_yaml(docs(*base, or_rule))
    # OR form: every pod in env=prod namespaces is allowed.
    assert verdict(inv_or, "b/other", "a/server", 8080) == Verdict.ALLOWED


def test_empty_namespace_selector_matches_all_namespaces():
    base = [
        ns("a"),
        ns("b"),
        pod("client", "b", {"app": "client"}),
        pod("server", "a", {"app": "server"}),
    ]
    rule = np("in", "a", "  podSelector: {}\n  ingress: [{from: [{namespaceSelector: {}}]}]")
    assert (
        verdict(inv_from_yaml(docs(*base, rule)), "b/client", "a/server", 8080) == Verdict.ALLOWED
    )


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ("{key: app, operator: In, values: [client, x]}", Verdict.ALLOWED),
        ("{key: app, operator: NotIn, values: [client]}", Verdict.BLOCKED),
        ("{key: app, operator: Exists}", Verdict.ALLOWED),
        ("{key: app, operator: DoesNotExist}", Verdict.BLOCKED),
        ("{key: missing, operator: DoesNotExist}", Verdict.ALLOWED),
        ("{key: missing, operator: NotIn, values: [y]}", Verdict.ALLOWED),
    ],
)
def test_match_expressions(expr, expected):
    rule = np(
        "in",
        "a",
        f"""  podSelector: {{matchLabels: {{app: server}}}}
  ingress: [{{from: [{{podSelector: {{matchExpressions: [{expr}]}}}}]}}]""",
    )
    assert verdict(inv_from_yaml(docs(*TWO_PODS, rule)), "a/client", "a/server", 8080) == expected


def test_ports_numeric_named_range_and_protocol():
    server = pod(
        "server", "a", {"app": "server"}, [("http", 8080), ("metrics", 9090), (None, 7000)]
    )
    base = [ns("a"), pod("client", "a", {"app": "client"}), server]

    def with_ports(ports_yaml):
        return inv_from_yaml(
            docs(
                *base,
                np(
                    "in",
                    "a",
                    f"""  podSelector: {{matchLabels: {{app: server}}}}
  ingress: [{{ports: {ports_yaml}}}]""",
                ),
            )
        )

    named = with_ports("[{port: http}]")
    assert verdict(named, "a/client", "a/server", 8080) == Verdict.ALLOWED
    assert verdict(named, "a/client", "a/server", 9090) == Verdict.BLOCKED
    ranged = with_ports("[{port: 7000, endPort: 9000}]")
    assert verdict(ranged, "a/client", "a/server", 8080) == Verdict.ALLOWED
    assert verdict(ranged, "a/client", "a/server", 9090) == Verdict.BLOCKED
    udp = with_ports("[{protocol: UDP, port: 8080}]")
    assert verdict(udp, "a/client", "a/server", 8080) == Verdict.BLOCKED
    proto_only = with_ports("[{protocol: TCP}]")
    assert verdict(proto_only, "a/client", "a/server", 9090) == Verdict.ALLOWED
    missing_name = with_ports("[{port: grpc}]")
    assert verdict(missing_name, "a/client", "a/server", 8080) == Verdict.BLOCKED


def test_named_port_in_egress_resolves_on_destination():
    server = pod("server", "a", {"app": "server"}, [("web", 8443)])
    rule = np(
        "out",
        "a",
        """  podSelector: {matchLabels: {app: client}}
  policyTypes: [Egress]
  egress: [{ports: [{port: web}]}]""",
    )
    inv = inv_from_yaml(
        docs(ns("a"), pod("client", "a", {"app": "client"}, [("web", 1111)]), server, rule)
    )
    assert verdict(inv, "a/client", "a/server", 8443) == Verdict.ALLOWED


def test_ip_block_is_unknown_not_blocked():
    rule = np(
        "in",
        "a",
        """  podSelector: {matchLabels: {app: server}}
  ingress: [{from: [{ipBlock: {cidr: 10.0.0.0/8}}]}]""",
    )
    inv = inv_from_yaml(docs(*TWO_PODS, rule))
    assert verdict(inv, "a/client", "a/server", 8080) == Verdict.UNKNOWN
    # A definite block on the other side still decides the connection.
    inv2 = inv_from_yaml(
        docs(
            *TWO_PODS,
            rule,
            np(
                "deny-eg",
                "a",
                "  podSelector: {matchLabels: {app: client}}\n  policyTypes: [Egress]",
            ),
        )
    )
    assert verdict(inv2, "a/client", "a/server", 8080) == Verdict.BLOCKED
    # A definite allow from another rule wins over the unknown one.
    allow = np(
        "allow",
        "a",
        "  podSelector: {matchLabels: {app: server}}\n  ingress: [{from: [{podSelector: {}}]}]",
    )
    inv3 = inv_from_yaml(docs(*TWO_PODS, rule, allow))
    assert verdict(inv3, "a/client", "a/server", 8080) == Verdict.ALLOWED


def test_undeclared_namespace_labels_are_unknown():
    base = [
        ns("a"),
        pod("client", "ghost", {"app": "client"}),
        pod("server", "a", {"app": "server"}),
    ]
    by_label = np(
        "in",
        "a",
        "  podSelector: {}\n  ingress: [{from: [{namespaceSelector: {matchLabels: {env: prod}}}]}]",
    )
    assert (
        verdict(inv_from_yaml(docs(*base, by_label)), "ghost/client", "a/server", 8080)
        == Verdict.UNKNOWN
    )
    by_name = np(
        "in",
        "a",
        "  podSelector: {}\n  ingress: [{from: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: ghost}}}]}]",
    )
    assert (
        verdict(inv_from_yaml(docs(*base, by_name)), "ghost/client", "a/server", 8080)
        == Verdict.ALLOWED
    )


def test_foreign_policy_kind_makes_verdicts_unsupported():
    cilium = """
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: c, namespace: a}
spec: {}
"""
    inv = inv_from_yaml(docs(*TWO_PODS, DENY_ALL_A, cilium))
    assert verdict(inv, "a/client", "a/server", 8080) == Verdict.UNSUPPORTED
    assert any("CiliumNetworkPolicy" in f.feature for f in inv.unsupported)


def test_host_network_is_unsupported():
    inv = inv_from_yaml(
        docs(
            ns("a"),
            pod("client", "a", {"app": "client"}, host_network=True),
            pod("server", "a", {"app": "server"}),
        )
    )
    assert verdict(inv, "a/client", "a/server", 8080) == Verdict.UNSUPPORTED


def test_policy_in_other_namespace_does_not_select():
    inv = inv_from_yaml(
        docs(*TWO_PODS, ns("b"), np("deny", "b", "  podSelector: {}\n  policyTypes: [Ingress]"))
    )
    assert verdict(inv, "a/client", "a/server", 8080) == Verdict.ALLOWED


def test_evidence_names_permitting_rule():
    rule = np(
        "in",
        "a",
        """  podSelector: {matchLabels: {app: server}}
  ingress: [{from: [{podSelector: {matchLabels: {app: client}}}], ports: [{port: 8080}]}]""",
    )
    inv = inv_from_yaml(docs(*TWO_PODS, rule))
    conn = ReachabilityEngine(inv).evaluate(
        inv.workloads["a/client"], inv.workloads["a/server"], 8080
    )
    assert conn.ingress.permitting[0].policy == "a/in"
    assert conn.ingress.permitting[0].rule_index == 0
    assert "a/in ingress[0]" in conn.ingress.explanation
    assert not conn.egress.isolated

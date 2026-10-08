"""Effective L4 reachability under Kubernetes NetworkPolicy semantics.

Semantics implemented (networking.k8s.io/v1):

* A pod is *isolated* for a direction iff at least one NetworkPolicy in its
  namespace selects it (``spec.podSelector``) and lists that direction in its
  effective ``policyTypes``. Non-isolated pods allow all traffic in that
  direction.
* Policies are purely additive allow-lists: traffic is allowed for an isolated
  pod iff *any* rule of *any* selecting policy matches. There are no deny
  rules, so adding a policy can never revoke what another policy allows.
* A connection needs BOTH the source's egress side and the destination's
  ingress side to allow it.
* Rule peers: ``podSelector`` alone = pods in the policy's namespace;
  ``namespaceSelector`` alone = all pods in matching namespaces; both = pods
  matching the pod selector inside matching namespaces. Empty ``from``/``to``
  matches all peers; empty ``ports`` matches all ports.
* Ports are evaluated against the destination *pod* port (after Service DNAT).
  Named ports resolve against the destination pod's container ports.
* ``ipBlock`` matching of pod IPs is implementation-defined → UNKNOWN.

Three-valued logic (True / False / None=unknown) is used throughout so that
UNKNOWN is never collapsed into BLOCKED.
"""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict

from clavure.core.models import (
    Direction,
    Inventory,
    LabelSelector,
    NetworkPolicy,
    PolicyPeer,
    PolicyPort,
    PolicyRule,
    Service,
    Verdict,
    Workload,
)

Tri = bool | None


def tri_and(a: Tri, b: Tri) -> Tri:
    if a is False or b is False:
        return False
    if a is None or b is None:
        return None
    return True


def tri_any(values: Iterable[Tri]) -> Tri:
    result: Tri = False
    for v in values:
        if v is True:
            return True
        if v is None:
            result = None
    return result


class RuleRef(BaseModel):
    """A specific rule that permits (or may permit) a connection."""

    model_config = ConfigDict(frozen=True)

    policy: str
    direction: Direction
    rule_index: int
    # Indexes of the peers that matched; empty when the rule has no peers
    # (i.e. it matches every peer).
    peer_indexes: tuple[int, ...] = ()
    matched_ports: str = "all ports"
    note: str | None = None

    def describe(self) -> str:
        field = "ingress" if self.direction == Direction.INGRESS else "egress"
        peers = f" peers{list(self.peer_indexes)}" if self.peer_indexes else " (all peers)"
        return f"{self.policy} {field}[{self.rule_index}]{peers} on {self.matched_ports}"


class SideDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    direction: Direction
    workload: str
    isolated: bool
    selecting_policies: tuple[str, ...]
    verdict: Verdict
    permitting: tuple[RuleRef, ...] = ()
    uncertain: tuple[RuleRef, ...] = ()
    explanation: str = ""


class Connection(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: str
    destination: str
    port: int
    protocol: str
    port_name: str | None
    verdict: Verdict
    egress: SideDecision
    ingress: SideDecision
    unsupported: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, str, int, str]:
        return (self.source, self.destination, self.port, self.protocol)

    def policies(self) -> list[str]:
        seen: list[str] = []
        for side in (self.egress, self.ingress):
            for p in side.selecting_policies:
                if p not in seen:
                    seen.append(p)
        return seen

    def explanation(self) -> list[str]:
        lines = [self.egress.explanation, self.ingress.explanation]
        lines.extend(f"Unsupported: {u}" for u in self.unsupported)
        return lines


def port_matches(spec: PolicyPort, port: int, protocol: str, destination: Workload) -> bool:
    if spec.protocol != protocol:
        return False
    if spec.port is None:
        return True
    if isinstance(spec.port, int):
        if spec.end_port is not None:
            return spec.port <= port <= spec.end_port
        return spec.port == port
    resolved = destination.resolve_named_port(spec.port, protocol)
    return resolved is not None and resolved == port


def namespace_selector_matches(selector: LabelSelector, inv: Inventory, namespace: str) -> Tri:
    ns = inv.namespace(namespace)
    if selector.is_empty:
        return True
    if ns.labels_known or selector.referenced_keys() <= {"kubernetes.io/metadata.name"}:
        return selector.matches(ns.labels_dict())
    return None


def peer_matches(
    peer: PolicyPeer, policy: NetworkPolicy, remote: Workload, inv: Inventory
) -> tuple[Tri, str | None]:
    if peer.ip_block is not None:
        return None, (
            f"ipBlock {peer.ip_block.cidr}: whether pod IPs match ipBlock peers is "
            "implementation-defined"
        )
    if peer.namespace_selector is None:
        ns_ok: Tri = remote.namespace == policy.namespace
        note = None
    else:
        ns_ok = namespace_selector_matches(peer.namespace_selector, inv, remote.namespace)
        note = (
            f"labels of namespace {remote.namespace} are unknown (not declared in manifests)"
            if ns_ok is None
            else None
        )
    pod_ok: Tri = (
        True if peer.pod_selector is None else peer.pod_selector.matches(remote.labels_dict())
    )
    return tri_and(ns_ok, pod_ok), note


class ReachabilityEngine:
    """Evaluates connectivity between workloads for one :class:`Inventory`."""

    def __init__(self, inventory: Inventory):
        self.inv = inventory
        self._selecting: dict[tuple[str, Direction], list[NetworkPolicy]] = {}
        for w in inventory.workloads.values():
            labels = w.labels_dict()
            for d in (Direction.INGRESS, Direction.EGRESS):
                self._selecting[(w.id, d)] = sorted(
                    (
                        p
                        for p in inventory.policies.values()
                        if p.namespace == w.namespace
                        and p.applies_to(d)
                        and p.pod_selector.matches(labels)
                    ),
                    key=lambda p: p.id,
                )

    # ------------------------------------------------------------------
    def selecting_policies(self, workload: Workload, direction: Direction) -> list[NetworkPolicy]:
        return self._selecting.get((workload.id, direction), [])

    def _rule_match(
        self,
        policy: NetworkPolicy,
        rule: PolicyRule,
        direction: Direction,
        remote: Workload,
        destination: Workload,
        port: int,
        protocol: str,
    ) -> tuple[Tri, tuple[int, ...], str, str | None]:
        notes: list[str] = []
        if rule.peers:
            results = []
            matched = []
            for i, peer in enumerate(rule.peers):
                r, note = peer_matches(peer, policy, remote, self.inv)
                results.append(r)
                if r is not False:
                    matched.append(i)
                if note and r is None:
                    notes.append(note)
            peer_ok = tri_any(results)
        else:
            peer_ok, matched = True, []
        if rule.ports:
            hits = [p for p in rule.ports if port_matches(p, port, protocol, destination)]
            port_ok: Tri = bool(hits)
            port_desc = ", ".join(p.describe() for p in hits) if hits else "no matching port"
        else:
            port_ok, port_desc = True, "all ports"
        return tri_and(peer_ok, port_ok), tuple(matched), port_desc, "; ".join(notes) or None

    def side(
        self,
        direction: Direction,
        local: Workload,
        remote: Workload,
        destination: Workload,
        port: int,
        protocol: str = "TCP",
    ) -> SideDecision:
        selecting = self.selecting_policies(local, direction)
        verb = "Ingress to" if direction == Direction.INGRESS else "Egress from"
        if not selecting:
            return SideDecision(
                direction=direction,
                workload=local.id,
                isolated=False,
                selecting_policies=(),
                verdict=Verdict.ALLOWED,
                explanation=(
                    f"{verb} {local.id}: no NetworkPolicy selects it for {direction}, "
                    "so it is not isolated and all traffic is allowed in this direction."
                ),
            )
        permitting: list[RuleRef] = []
        uncertain: list[RuleRef] = []
        for policy in selecting:
            for idx, rule in enumerate(policy.rules(direction)):
                result, peers, port_desc, note = self._rule_match(
                    policy, rule, direction, remote, destination, port, protocol
                )
                if result is False:
                    continue
                ref = RuleRef(
                    policy=policy.id,
                    direction=direction,
                    rule_index=idx,
                    peer_indexes=peers,
                    matched_ports=port_desc,
                    note=note,
                )
                (permitting if result is True else uncertain).append(ref)
        names = ", ".join(p.id for p in selecting)
        if permitting:
            verdict = Verdict.ALLOWED
            why = "permitted by " + "; ".join(r.describe() for r in permitting)
        elif uncertain:
            verdict = Verdict.UNKNOWN
            why = "possibly permitted by " + "; ".join(
                f"{r.describe()} ({r.note})" for r in uncertain
            )
        else:
            verdict = Verdict.BLOCKED
            why = "no rule of any selecting policy matches (policies are allow-lists)"
        return SideDecision(
            direction=direction,
            workload=local.id,
            isolated=True,
            selecting_policies=tuple(p.id for p in selecting),
            verdict=verdict,
            permitting=tuple(permitting),
            uncertain=tuple(uncertain),
            explanation=f"{verb} {local.id}: isolated by [{names}]; {why}.",
        )

    def _unsupported_reasons(self, src: Workload, dst: Workload) -> list[str]:
        reasons = []
        for w in (src, dst):
            if w.host_network:
                reasons.append(f"{w.id} uses hostNetwork")
        for feat in self.inv.unsupported:
            scope = set(feat.affected_namespaces)
            if "*" in scope or src.namespace in scope or dst.namespace in scope:
                reasons.append(f"{feat.object_ref}: {feat.feature}")
        return reasons

    def evaluate(
        self, src: Workload, dst: Workload, port: int, protocol: str = "TCP"
    ) -> Connection:
        egress = self.side(Direction.EGRESS, src, dst, dst, port, protocol)
        ingress = self.side(Direction.INGRESS, dst, src, dst, port, protocol)
        unsupported = self._unsupported_reasons(src, dst)
        if unsupported:
            verdict = Verdict.UNSUPPORTED
        elif Verdict.BLOCKED in (egress.verdict, ingress.verdict):
            verdict = Verdict.BLOCKED
        elif egress.verdict == ingress.verdict == Verdict.ALLOWED:
            verdict = Verdict.ALLOWED
        else:
            verdict = Verdict.UNKNOWN
        return Connection(
            source=src.id,
            destination=dst.id,
            port=port,
            protocol=protocol,
            port_name=dst.port_name(port, protocol),
            verdict=verdict,
            egress=egress,
            ingress=ingress,
            unsupported=tuple(unsupported),
        )

    def matrix(self) -> list[Connection]:
        """All ordered workload pairs, for every TCP port the destination exposes."""
        out = []
        workloads = sorted(self.inv.workloads.values(), key=lambda w: w.id)
        for src in workloads:
            for dst in workloads:
                if src.id == dst.id:
                    continue
                for port in dst.tcp_ports():
                    out.append(self.evaluate(src, dst, port))
        return out

    # ------------------------------------------------------------------
    def resolve_service_port(
        self, service: Service, service_port: int
    ) -> list[tuple[Workload, int | None]]:
        """Map a Service port to (backend workload, target pod port) pairs.

        Returns ``None`` as the port when a named targetPort does not exist on
        a backend (Kubernetes would not create an endpoint for that pod).
        """
        sp = next((p for p in service.ports if p.port == service_port), None)
        if sp is None:
            return []
        out: list[tuple[Workload, int | None]] = []
        for backend in sorted(self.inv.backends(service), key=lambda w: w.id):
            if isinstance(sp.target_port, int):
                out.append((backend, sp.target_port))
            elif isinstance(sp.target_port, str) and sp.target_port.isdigit():
                out.append((backend, int(sp.target_port)))
            else:
                out.append((backend, backend.resolve_named_port(str(sp.target_port), sp.protocol)))
        return out

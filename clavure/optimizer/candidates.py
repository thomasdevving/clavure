"""Generate candidate remediation actions from analysis evidence.

Nothing here knows about the demo. Actions are derived from:

* the permitting rules recorded for every ALLOWED forbidden connection
  (on both the egress and the ingress side), and
* which required connections depend on each policy / rule / peer, so that
  narrowing actions keep exactly the required counterparts.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from clavure.core.analysis import Analysis
from clavure.core.constraints import ConstraintStatus
from clavure.core.models import Direction, Verdict
from clavure.core.reachability import Connection
from clavure.optimizer.actions import (
    Action,
    AllowRequired,
    BlockAllIngress,
    DeletePolicy,
    ExcludeFromPolicy,
    IsolateWithRequiredAllows,
    NarrowPeer,
    NarrowPolicyTargets,
    QuarantineWorkload,
    RemovePeer,
    RemoveRule,
    RestrictRulePorts,
    macro_for,
)


@dataclass
class RequiredUsage:
    """Which required (remote, port) pairs flow through each policy element."""

    by_rule: dict[tuple[str, Direction, int], set[tuple[str, int]]] = field(
        default_factory=lambda: defaultdict(set)
    )
    by_peer: dict[tuple[str, Direction, int, int], set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    by_policy: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    # workload -> direction -> required (remote, port)
    by_local: dict[tuple[str, Direction], set[tuple[str, int]]] = field(
        default_factory=lambda: defaultdict(set)
    )


def required_usage(a: Analysis) -> RequiredUsage:
    u = RequiredUsage()
    for ev in a.evaluations:
        if ev.kind != "required":
            continue
        for conn in ev.connections:
            u.by_local[(conn.source, Direction.EGRESS)].add((conn.destination, conn.port))
            u.by_local[(conn.destination, Direction.INGRESS)].add((conn.source, conn.port))
            if conn.verdict != Verdict.ALLOWED:
                continue
            for side, remote in ((conn.egress, conn.destination), (conn.ingress, conn.source)):
                for ref in side.permitting:
                    u.by_rule[(ref.policy, ref.direction, ref.rule_index)].add((remote, conn.port))
                    for pi in ref.peer_indexes:
                        u.by_peer[(ref.policy, ref.direction, ref.rule_index, pi)].add(remote)
                    u.by_policy[ref.policy].add(side.workload)
    return u


def forbidden_allowed(a: Analysis) -> list[Connection]:
    out = []
    for ev in a.evaluations:
        if ev.kind == "forbidden" and ev.status == ConstraintStatus.VIOLATED:
            out.extend(c for c in ev.connections if c.verdict == Verdict.ALLOWED)
    return out


def generate_actions(a: Analysis) -> list[Action]:
    inv = a.inventory
    usage = required_usage(a)
    actions: dict[str, Action] = {}

    def add(action: Action) -> None:
        actions.setdefault(action.key(), action)

    for conn in forbidden_allowed(a):
        for side, remote in ((conn.egress, conn.destination), (conn.ingress, conn.source)):
            local = side.workload
            if not side.isolated:
                allows = tuple(sorted(usage.by_local.get((local, side.direction), set())))
                add(
                    IsolateWithRequiredAllows(
                        workload=local, direction=side.direction, allows=allows
                    )
                )
                continue
            for ref in side.permitting:
                pol = inv.policies[ref.policy]
                rule = pol.rules(ref.direction)[ref.rule_index]
                rkey = (ref.policy, ref.direction, ref.rule_index)
                add(RemoveRule(policy=ref.policy, direction=ref.direction, rule=ref.rule_index))
                for pi in ref.peer_indexes:
                    if len(rule.peers) > 1:
                        add(
                            RemovePeer(
                                policy=ref.policy,
                                direction=ref.direction,
                                rule=ref.rule_index,
                                peer=pi,
                            )
                        )
                    keep = sorted(usage.by_peer.get((*rkey, pi), set()) - {remote})
                    if keep and rule.peers[pi].ip_block is None:
                        add(
                            NarrowPeer(
                                policy=ref.policy,
                                direction=ref.direction,
                                rule=ref.rule_index,
                                peer=pi,
                                keep=tuple(keep),
                            )
                        )
                needed_ports = sorted({p for _, p in usage.by_rule.get(rkey, set())})
                if needed_ports and conn.port not in needed_ports:
                    add(
                        RestrictRulePorts(
                            policy=ref.policy,
                            direction=ref.direction,
                            rule=ref.rule_index,
                            ports=tuple(needed_ports),
                        )
                    )
                selected = [
                    w.id
                    for w in inv.workloads.values()
                    if w.namespace == pol.namespace and pol.pod_selector.matches(w.labels_dict())
                ]
                keep_targets = sorted(usage.by_policy.get(ref.policy, set()) - {local})
                if keep_targets and set(keep_targets) != set(selected):
                    add(NarrowPolicyTargets(policy=ref.policy, keep=tuple(keep_targets)))
                if len(selected) > 1:
                    add(ExcludeFromPolicy(policy=ref.policy, workload=local))
                add(DeletePolicy(policy=ref.policy))

        # Coarse "obvious" fixes: evaluated exactly like the fine-grained ones,
        # so their rejection is computed rather than asserted.
        src, dst = inv.workloads[conn.source], inv.workloads[conn.destination]
        selecting = {d: a.engine.selecting_policies(src, d) for d in Direction}
        add(macro_for(QuarantineWorkload, src, inv, selecting))
        selecting_dst = {d: a.engine.selecting_policies(dst, d) for d in Direction}
        add(macro_for(BlockAllIngress, dst, inv, selecting_dst))

    # Broken requirements: propose the narrowest allow rules.
    req_by_id = {r.id: r for r in a.scenario.required}
    for ev in a.evaluations:
        if ev.kind != "required" or ev.status != ConstraintStatus.VIOLATED:
            continue
        for conn in ev.connections:
            if conn.verdict != Verdict.BLOCKED:
                continue
            sides = tuple(
                s.direction for s in (conn.egress, conn.ingress) if s.verdict == Verdict.BLOCKED
            )
            add(
                AllowRequired(
                    constraint=req_by_id[ev.constraint_id].id,
                    source=conn.source,
                    destination=conn.destination,
                    port=conn.port,
                    sides=sides,
                )
            )

    return sorted(actions.values(), key=lambda x: (x.coarse, x.kind, x.key()))

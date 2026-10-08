"""Remediation actions over a NetworkPolicy set.

Every action is a deterministic, structural transformation with a precise
meaning. Actions never encode a desired *outcome*; whether a combination of
actions blocks the forbidden traffic and preserves required traffic is decided
by re-evaluating the full model (and later by the independent verifiers).

Actions edit a :class:`PlanState` made of drafts that keep the *original*
rule/peer indexes, so combinations of actions never suffer from index shifts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from clavure.core.models import (
    Direction,
    Inventory,
    LabelSelector,
    NetworkPolicy,
    PolicyPeer,
    PolicyPort,
    PolicyRule,
    SourceRef,
    Workload,
)
from clavure.optimizer.selectors import (
    distinguishing_labels,
    exclude_selector,
    narrow_peer,
    peer_for,
    selector_for,
)

GENERATED_BY = (("clavure.io/generated-by", "clavure-optimizer"),)


# --------------------------------------------------------------------------
# Drafts
# --------------------------------------------------------------------------


@dataclass
class RuleDraft:
    # Per original peer: list of replacement peers; None = peer removed.
    peers: list[list[PolicyPeer] | None]
    ports: tuple[PolicyPort, ...]
    removed: bool = False

    @classmethod
    def of(cls, rule: PolicyRule) -> RuleDraft:
        return cls(peers=[[p] for p in rule.peers], ports=rule.ports)

    def finalize(self) -> PolicyRule | None:
        if self.removed:
            return None
        flat = [p for group in self.peers if group is not None for p in group]
        if self.peers and not flat:
            # Removing every peer must NOT turn the rule into "match all
            # peers" (empty `from`/`to`); the rule is dropped instead.
            return None
        return PolicyRule(peers=tuple(flat), ports=self.ports)


@dataclass
class PolicyDraft:
    original: NetworkPolicy | None
    name: str
    namespace: str
    pod_selector: LabelSelector
    policy_types: tuple[Direction, ...]
    rules: dict[Direction, list[RuleDraft]]
    labels: tuple[tuple[str, str], ...] = ()
    annotations: tuple[tuple[str, str], ...] = ()
    source: SourceRef = field(default_factory=SourceRef)
    deleted: bool = False

    @classmethod
    def of(cls, p: NetworkPolicy) -> PolicyDraft:
        return cls(
            original=p,
            name=p.name,
            namespace=p.namespace,
            pod_selector=p.pod_selector,
            policy_types=p.policy_types,
            rules={d: [RuleDraft.of(r) for r in p.rules(d)] for d in Direction},
            labels=p.labels,
            annotations=p.annotations,
            source=p.source,
        )

    @property
    def id(self) -> str:
        return f"{self.namespace}/{self.name}"

    def finalize(self) -> NetworkPolicy | None:
        if self.deleted:
            return None
        rules = {
            d: tuple(r for r in (rd.finalize() for rd in self.rules[d]) if r is not None)
            for d in Direction
        }
        return NetworkPolicy(
            name=self.name,
            namespace=self.namespace,
            pod_selector=self.pod_selector,
            policy_types=self.policy_types,
            ingress=rules[Direction.INGRESS] if Direction.INGRESS in self.policy_types else (),
            egress=rules[Direction.EGRESS] if Direction.EGRESS in self.policy_types else (),
            labels=self.labels,
            annotations=self.annotations,
            source=self.source,
        )


@dataclass
class PlanState:
    inv: Inventory
    drafts: dict[str, PolicyDraft]
    edits: int = 0
    complexity: int = 0
    notes: list[str] = field(default_factory=list)

    @classmethod
    def of(cls, inv: Inventory) -> PlanState:
        return cls(inv=inv, drafts={pid: PolicyDraft.of(p) for pid, p in inv.policies.items()})

    def draft(self, policy_id: str) -> PolicyDraft:
        d = self.drafts.get(policy_id)
        if d is None or d.deleted:
            raise ActionError(f"policy {policy_id} does not exist")
        return d

    def add_policy(self, policy: NetworkPolicy) -> None:
        if policy.id in self.drafts and not self.drafts[policy.id].deleted:
            raise ActionError(f"policy {policy.id} already exists")
        d = PolicyDraft.of(policy)
        d.original = None
        self.drafts[policy.id] = d
        self.edits += 1 + len(policy.ingress) + len(policy.egress)
        self.complexity += 2

    def workload(self, wid: str) -> Workload:
        return self.inv.workloads[wid]

    def result(self) -> dict[str, NetworkPolicy]:
        out = {}
        for pid, d in self.drafts.items():
            p = d.finalize()
            if p is not None:
                out[pid] = p
        return out


class ActionError(ValueError):
    """An action cannot be applied to the current state."""


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------


class Action(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: ClassVar[str] = "abstract"
    # Coarse actions are generated to document the trade-off space; they are
    # evaluated exactly like any other action.
    coarse: ClassVar[bool] = False

    def key(self) -> str:
        fields = ",".join(f"{k}={v}" for k, v in self.model_dump(mode="json").items())
        return f"{self.kind}({fields})"

    def touches(self) -> set[tuple]:
        raise NotImplementedError

    def describe(self) -> str:
        raise NotImplementedError

    def apply(self, st: PlanState) -> None:
        raise NotImplementedError

    def record(self) -> dict:
        return {
            "kind": self.kind,
            "description": self.describe(),
            "params": self.model_dump(mode="json"),
        }


def _dir_word(d: Direction) -> str:
    return "ingress" if d == Direction.INGRESS else "egress"


class RemoveRule(Action):
    kind: ClassVar[str] = "remove-rule"
    policy: str
    direction: Direction
    rule: int

    def touches(self):
        return {(self.policy, self.direction, self.rule)}

    def describe(self):
        return f"Remove {_dir_word(self.direction)} rule #{self.rule} from {self.policy}"

    def apply(self, st):
        d = st.draft(self.policy)
        d.rules[self.direction][self.rule].removed = True
        st.edits += 1


class RemovePeer(Action):
    kind: ClassVar[str] = "remove-peer"
    policy: str
    direction: Direction
    rule: int
    peer: int

    def touches(self):
        return {(self.policy, self.direction, self.rule, "peers", self.peer)}

    def describe(self):
        return f"Remove peer #{self.peer} from {_dir_word(self.direction)} rule #{self.rule} of {self.policy}"

    def apply(self, st):
        st.draft(self.policy).rules[self.direction][self.rule].peers[self.peer] = None
        st.edits += 1


class NarrowPeer(Action):
    """Restrict one peer to the required counterpart workloads it serves."""

    kind: ClassVar[str] = "narrow-peer"
    policy: str
    direction: Direction
    rule: int
    peer: int
    keep: tuple[str, ...]  # workload ids that must stay matched

    def touches(self):
        return {(self.policy, self.direction, self.rule, "peers", self.peer)}

    def describe(self):
        return (
            f"Narrow peer #{self.peer} of {_dir_word(self.direction)} rule #{self.rule} in "
            f"{self.policy} to only {', '.join(self.keep)}"
        )

    def apply(self, st):
        rd = st.draft(self.policy).rules[self.direction][self.rule]
        group = rd.peers[self.peer]
        if group is None or len(group) != 1:
            raise ActionError("peer already changed")
        original = group[0]
        if original.ip_block is not None:
            raise ActionError("ipBlock peers cannot be narrowed by labels")
        rd.peers[self.peer] = [narrow_peer(original, st.workload(w), st.inv) for w in self.keep]
        st.edits += 1
        st.complexity += len(self.keep)


class RestrictRulePorts(Action):
    kind: ClassVar[str] = "restrict-ports"
    policy: str
    direction: Direction
    rule: int
    ports: tuple[int, ...]

    def touches(self):
        return {(self.policy, self.direction, self.rule, "ports")}

    def describe(self):
        return (
            f"Restrict {_dir_word(self.direction)} rule #{self.rule} of {self.policy} to TCP ports "
            f"{list(self.ports)}"
        )

    def apply(self, st):
        rd = st.draft(self.policy).rules[self.direction][self.rule]
        rd.ports = tuple(PolicyPort(protocol="TCP", port=p) for p in self.ports)
        st.edits += 1


class NarrowPolicyTargets(Action):
    """Replace a policy's podSelector so it selects only the given workloads."""

    kind: ClassVar[str] = "narrow-targets"
    policy: str
    keep: tuple[str, ...]

    def touches(self):
        return {(self.policy, "podSelector")}

    def describe(self):
        return f"Narrow {self.policy} podSelector to select only {', '.join(self.keep)}"

    def apply(self, st):
        d = st.draft(self.policy)
        workloads = [st.workload(w) for w in self.keep]
        if any(w.namespace != d.namespace for w in workloads):
            raise ActionError("policy can only select workloads in its own namespace")
        d.pod_selector = selector_for(workloads, st.inv)
        st.edits += 1


class ExcludeFromPolicy(Action):
    kind: ClassVar[str] = "exclude-target"
    policy: str
    workload: str

    def touches(self):
        return {(self.policy, "podSelector")}

    def describe(self):
        return f"Exclude {self.workload} from {self.policy} (podSelector NotIn)"

    def apply(self, st):
        d = st.draft(self.policy)
        d.pod_selector = exclude_selector(d.pod_selector, st.workload(self.workload), st.inv)
        st.edits += 1
        st.complexity += 3  # NotIn exclusions silently include future pods


class DeletePolicy(Action):
    kind: ClassVar[str] = "delete-policy"
    policy: str

    def touches(self):
        return {(self.policy,)}

    def describe(self):
        return f"Delete NetworkPolicy {self.policy}"

    def apply(self, st):
        st.draft(self.policy).deleted = True
        st.edits += 1


def _new_name(prefix: str, workload: Workload) -> str:
    return f"{prefix}-{workload.name}"[:253].rstrip("-.")


def _rule_to(remote: Workload, local_ns: str, port: int, inv: Inventory) -> PolicyRule:
    return PolicyRule(
        peers=(peer_for(remote, local_ns, inv),),
        ports=(PolicyPort(protocol="TCP", port=port),),
    )


class IsolateWithRequiredAllows(Action):
    """Isolate a non-isolated workload, allowing only its required traffic."""

    kind: ClassVar[str] = "isolate"
    workload: str
    direction: Direction
    allows: tuple[tuple[str, int], ...]  # (remote workload id, destination port)

    def touches(self):
        return {("new", _dir_word(self.direction), self.workload)}

    def describe(self):
        allowed = ", ".join(f"{w}:{p}" for w, p in self.allows) or "nothing"
        return f"Isolate {self.workload} for {_dir_word(self.direction)}; allow only required: {allowed}"

    def apply(self, st):
        w = st.workload(self.workload)
        rules = tuple(_rule_to(st.workload(r), w.namespace, p, st.inv) for r, p in self.allows)
        st.add_policy(
            NetworkPolicy(
                name=_new_name(f"clavure-isolate-{_dir_word(self.direction)}", w),
                namespace=w.namespace,
                pod_selector=LabelSelector.of(distinguishing_labels(w, st.inv)),
                policy_types=(self.direction,),
                ingress=rules if self.direction == Direction.INGRESS else (),
                egress=rules if self.direction == Direction.EGRESS else (),
                labels=GENERATED_BY,
                source=SourceRef(origin="generated"),
            )
        )


class AllowRequired(Action):
    """Add the narrowest allow rules for a blocked *required* connection."""

    kind: ClassVar[str] = "allow-required"
    constraint: str
    source: str
    destination: str
    port: int
    sides: tuple[Direction, ...]

    def touches(self):
        return {("new", "allow", self.constraint)}

    def describe(self):
        sides = " and ".join(_dir_word(s) for s in self.sides)
        return f"Allow required {self.constraint}: {self.source} -> {self.destination}:{self.port} ({sides})"

    def apply(self, st):
        src, dst = st.workload(self.source), st.workload(self.destination)
        tag = self.constraint.lower()
        for side in self.sides:
            local, remote = (dst, src) if side == Direction.INGRESS else (src, dst)
            rule = _rule_to(remote, local.namespace, self.port, st.inv)
            st.add_policy(
                NetworkPolicy(
                    name=f"clavure-allow-{tag}-{_dir_word(side)}"[:253],
                    namespace=local.namespace,
                    pod_selector=LabelSelector.of(distinguishing_labels(local, st.inv)),
                    policy_types=(side,),
                    ingress=(rule,) if side == Direction.INGRESS else (),
                    egress=(rule,) if side == Direction.EGRESS else (),
                    labels=GENERATED_BY,
                    source=SourceRef(origin="generated"),
                )
            )


class _WorkloadMacro(Action):
    """Base for coarse macros that cut a workload off in some direction."""

    coarse: ClassVar[bool] = True
    directions: ClassVar[tuple[Direction, ...]] = ()
    prefix: ClassVar[str] = ""
    workload: str
    # Precomputed from the baseline so the macro is deterministic.
    excluded_from: tuple[str, ...] = ()
    stripped: tuple[str, ...] = ()

    def touches(self):
        t = {(p, "podSelector") for p in self.excluded_from}
        t |= {(p, d) for p in self.stripped for d in self.directions}
        t.add(("new", self.prefix, self.workload))
        return t

    def apply(self, st):
        w = st.workload(self.workload)
        for pid in self.excluded_from:
            ExcludeFromPolicy(policy=pid, workload=self.workload).apply(st)
        for pid in self.stripped:
            d = st.draft(pid)
            for direction in self.directions:
                for rd in d.rules[direction]:
                    rd.removed = True
            st.edits += 1
        st.add_policy(
            NetworkPolicy(
                name=_new_name(self.prefix, w),
                namespace=w.namespace,
                pod_selector=LabelSelector.of(distinguishing_labels(w, st.inv)),
                policy_types=self.directions,
                labels=GENERATED_BY,
                source=SourceRef(origin="generated"),
            )
        )


class QuarantineWorkload(_WorkloadMacro):
    """Coarse: cut off ALL ingress and egress of a workload."""

    kind: ClassVar[str] = "quarantine-workload"
    directions: ClassVar[tuple[Direction, ...]] = (Direction.INGRESS, Direction.EGRESS)
    prefix: ClassVar[str] = "clavure-quarantine"

    def describe(self):
        return f"Disable all connectivity of {self.workload} (deny all ingress and egress)"


class BlockAllIngress(_WorkloadMacro):
    """Coarse: block every inbound connection to a workload."""

    kind: ClassVar[str] = "block-all-ingress"
    directions: ClassVar[tuple[Direction, ...]] = (Direction.INGRESS,)
    prefix: ClassVar[str] = "clavure-deny-ingress"

    def describe(self):
        return f"Block all ingress to {self.workload}"


def macro_for(
    cls: type[_WorkloadMacro],
    workload: Workload,
    inv: Inventory,
    selecting: dict[Direction, list[NetworkPolicy]],
) -> _WorkloadMacro:
    """Plan which policies a macro must modify so that no allow rule remains."""
    excluded, stripped = [], []
    for pol in sorted(
        {p.id: p for d in cls.directions for p in selecting[d]}.values(), key=lambda p: p.id
    ):
        has_rules = any(pol.rules(d) for d in cls.directions if d in pol.policy_types)
        if not has_rules:
            continue
        only_this = all(
            w.id == workload.id
            for w in inv.workloads.values()
            if w.namespace == pol.namespace and pol.pod_selector.matches(w.labels_dict())
        )
        (stripped if only_this else excluded).append(pol.id)
    return cls(workload=workload.id, excluded_from=tuple(excluded), stripped=tuple(stripped))


ACTION_TYPES: dict[str, type[Action]] = {
    c.kind: c
    for c in (
        RemoveRule,
        RemovePeer,
        NarrowPeer,
        RestrictRulePorts,
        NarrowPolicyTargets,
        ExcludeFromPolicy,
        DeletePolicy,
        IsolateWithRequiredAllows,
        AllowRequired,
        QuarantineWorkload,
        BlockAllIngress,
    )
}


def conflicts(a: Action, b: Action) -> bool:
    """Two actions conflict if one touches a prefix of what the other touches."""
    for x in a.touches():
        for y in b.touches():
            n = min(len(x), len(y))
            if x[:n] == y[:n]:
                return True
    return False

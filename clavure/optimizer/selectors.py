"""Selector construction helpers used by remediation actions."""

from __future__ import annotations

from itertools import combinations

from clavure.core.models import (
    Inventory,
    LabelSelector,
    LabelSelectorRequirement,
    PolicyPeer,
    Workload,
)

# Preferred keys when looking for a label that identifies a workload.
_PREFERRED_KEYS = ("app", "app.kubernetes.io/name", "name", "component")


def distinguishing_labels(workload: Workload, inv: Inventory) -> dict[str, str]:
    """Smallest label subset selecting ``workload`` and no other workload in its namespace.

    Falls back to the full label set when no subset is unique (identically
    labelled workloads cannot be told apart by any selector).
    """
    labels = workload.labels_dict()
    peers = [
        w
        for w in inv.workloads.values()
        if w.namespace == workload.namespace and w.id != workload.id
    ]
    keys = sorted(labels, key=lambda k: (k not in _PREFERRED_KEYS, _rank(k), k))
    for size in range(1, len(keys) + 1):
        for subset in combinations(keys, size):
            cand = {k: labels[k] for k in subset}
            if not any(all(p.labels_dict().get(k) == v for k, v in cand.items()) for p in peers):
                return cand
    return labels


def _rank(key: str) -> int:
    return _PREFERRED_KEYS.index(key) if key in _PREFERRED_KEYS else len(_PREFERRED_KEYS)


def selector_for(workloads: list[Workload], inv: Inventory) -> LabelSelector:
    """A selector matching exactly the given workloads (same namespace)."""
    if len(workloads) == 1:
        return LabelSelector.of(distinguishing_labels(workloads[0], inv))
    dist = [distinguishing_labels(w, inv) for w in workloads]
    shared_keys = set(dist[0])
    for d in dist[1:]:
        shared_keys &= set(d)
    if len(shared_keys) == 1:
        key = next(iter(shared_keys))
        values = tuple(sorted({d[key] for d in dist}))
        return LabelSelector.of(
            {}, [LabelSelectorRequirement(key=key, operator="In", values=values)]
        )
    # Common labels of all workloads (may over-select; the verifier decides).
    common = dict(workloads[0].labels)
    for w in workloads[1:]:
        common = {k: v for k, v in common.items() if w.labels_dict().get(k) == v}
    return LabelSelector.of(common)


def merge_selectors(a: LabelSelector | None, b: LabelSelector) -> LabelSelector:
    """Logical AND of two selectors (result selects a subset of each)."""
    if a is None:
        return b
    labels = a.labels_dict()
    for k, v in b.match_labels:
        if k in labels and labels[k] != v:
            # Contradiction: nothing can match. Keep both so that it is visible.
            return LabelSelector.of(
                labels,
                [*a.match_expressions, LabelSelectorRequirement(key=k, operator="In", values=(v,))],
            )
        labels[k] = v
    exprs = list(a.match_expressions)
    for e in b.match_expressions:
        if e not in exprs:
            exprs.append(e)
    return LabelSelector.of(labels, exprs)


def exclude_selector(sel: LabelSelector, workload: Workload, inv: Inventory) -> LabelSelector:
    """Add a NotIn requirement so that ``sel`` no longer matches ``workload``."""
    dist = distinguishing_labels(workload, inv)
    key = next(iter(sorted(dist, key=lambda k: (k not in _PREFERRED_KEYS, _rank(k), k))))
    req = LabelSelectorRequirement(key=key, operator="NotIn", values=(dist[key],))
    return LabelSelector.of(sel.labels_dict(), [*sel.match_expressions, req])


def peer_for(workload: Workload, policy_namespace: str, inv: Inventory) -> PolicyPeer:
    """A peer matching exactly ``workload`` from a policy in ``policy_namespace``."""
    pod = LabelSelector.of(distinguishing_labels(workload, inv))
    if workload.namespace == policy_namespace:
        return PolicyPeer(pod_selector=pod)
    return PolicyPeer(
        namespace_selector=LabelSelector.of({"kubernetes.io/metadata.name": workload.namespace}),
        pod_selector=pod,
    )


def narrow_peer(original: PolicyPeer, workload: Workload, inv: Inventory) -> PolicyPeer:
    """Keep the original peer's scope but restrict it to ``workload``.

    The result is the AND of the original peer and the workload's
    distinguishing labels, so it is never broader than the original.
    """
    dist = LabelSelector.of(distinguishing_labels(workload, inv))
    return PolicyPeer(
        pod_selector=merge_selectors(original.pod_selector, dist),
        namespace_selector=original.namespace_selector,
        ip_block=original.ip_block,
    )
